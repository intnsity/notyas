// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The store's lifecycle, driven through the public API only.
//!
//! Every test here is a sentence from ESP-SEAL.md or OPEN-QUESTIONS Q5 turned into an
//! assertion. Nothing reaches into the crate's internals, so the suite doubles as the
//! usage documentation and a refactor cannot quietly change observable behaviour.

use notyas_wallet::fuzz::{fuzz_config, geometry_for, v1_config};
use notyas_wallet::sim::{SimFlash, SoftMac, VecScratch};
use notyas_wallet::{
    Config, Identity, KeyProvenance, MountError, Occupancy, Pin, Policy, PolicyRefusal,
    PolicyRequest, Session, SlotClass, SlotId, SlotState, StorageError, StoreState, TamperKind,
    UnlockError, Vault, WIPE_AFTER_MAX,
};

type V = Vault<SimFlash, SoftMac>;

fn pin(s: &str) -> Pin {
    Pin::from_normalized_utf8(s).expect("test PIN is 1..=64 bytes")
}

fn blank(cfg: &Config) -> V {
    let flash = SimFlash::new(geometry_for(&cfg.layout));
    Vault::mount(flash, SoftMac::new(), cfg).expect("a blank store mounts")
}

fn scratch(cfg: &Config) -> VecScratch {
    VecScratch::for_params(&cfg.kdf)
}

/// Format, then hand back the store and its session.
fn formatted(cfg: &Config) -> (V, Session) {
    let mut v = blank(cfg);
    let mut s = scratch(cfg);
    let session = v.format(&pin("135790"), b"primary", s.scratch()).expect("format");
    (v, session)
}

fn remount(v: V, cfg: &Config) -> V {
    let (flash, mac) = v.into_parts();
    Vault::mount(flash, mac, cfg).expect("remount")
}

fn payload(cfg: &Config, i: u8) -> SlotId {
    SlotId::new(SlotClass::Payload, i, &cfg.layout).expect("payload slot exists")
}

fn registry(cfg: &Config, i: u8) -> SlotId {
    SlotId::new(SlotClass::Registry, i, &cfg.layout).expect("registry slot exists")
}

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

#[test]
fn a_blank_store_is_blank_and_writes_nothing() {
    let cfg = fuzz_config();
    let flash = SimFlash::new(geometry_for(&cfg.layout));
    let v = Vault::mount(flash, SoftMac::new(), &cfg).expect("mount");
    assert_eq!(v.state(), StoreState::Blank);
    let (flash, _) = v.into_parts();
    assert_eq!(
        flash.erase_count(),
        0,
        "mounting a blank store must not touch the flash: a device that has never saved a \
         wallet is behaviourally a 0.1.0 device"
    );
    assert_eq!(flash.program_count(), 0);
}

#[test]
fn format_then_unlock_returns_the_same_identity() {
    let cfg = fuzz_config();
    let (v, session) = formatted(&cfg);
    assert_eq!(session.identity(), Identity(0));
    assert!(matches!(
        v.state(),
        StoreState::Formatted {
            identities_present: 1,
            ..
        }
    ));
    let mut v = remount(v, &cfg);
    let mut s = scratch(&cfg);
    let session = v.unlock(&pin("135790"), s.scratch()).expect("unlock");
    assert_eq!(session.identity(), Identity(0));
}

#[test]
fn a_second_format_is_refused() {
    let cfg = fuzz_config();
    let (mut v, _s) = formatted(&cfg);
    let mut s = scratch(&cfg);
    assert!(v.format(&pin("999999"), b"second", s.scratch()).is_err());
}

#[test]
fn an_unprovisioned_board_reports_a_state_rather_than_a_fault() {
    let cfg = fuzz_config();
    let flash = SimFlash::new(geometry_for(&cfg.layout));
    let mac = SoftMac::new().with_provenance(KeyProvenance::Absent);
    let v = Vault::mount(flash, mac, &cfg).expect("mount reports the state, it does not refuse");
    assert_eq!(v.state(), StoreState::Unprovisioned);
    assert_eq!(v.key_provenance(), KeyProvenance::Absent);
}

#[test]
fn a_provenance_the_product_will_not_accept_refuses_to_mount() {
    let cfg = fuzz_config();
    let flash = SimFlash::new(geometry_for(&cfg.layout));
    let mac = SoftMac::new().with_provenance(KeyProvenance::EfuseReadable);
    match Vault::mount(flash, mac, &cfg) {
        Err(MountError::Provenance(KeyProvenance::EfuseReadable)) => {}
        other => panic!("expected a provenance refusal, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

#[test]
fn a_record_survives_a_power_cycle_byte_for_byte() {
    let cfg = fuzz_config();
    let (mut v, session) = formatted(&cfg);
    let secret = b"the wallet record, whatever it happens to be";
    v.write(&session, payload(&cfg, 0), secret).expect("write");
    drop(session);

    let mut v = remount(v, &cfg);
    let mut s = scratch(&cfg);
    let session = v.unlock(&pin("135790"), s.scratch()).expect("unlock");
    let mut out = vec![0u8; 4096];
    let n = v.read(&session, payload(&cfg, 0), &mut out).expect("read");
    assert_eq!(&out[..n], secret);
}

#[test]
fn a_registry_slot_holds_twice_the_payload_slot() {
    let cfg = fuzz_config();
    let (mut v, session) = formatted(&cfg);
    let big = vec![0x5au8; 6000];
    v.write(&session, registry(&cfg, 0), &big)
        .expect("a registry side is two sectors");
    let mut out = vec![0u8; 9000];
    let n = v.read(&session, registry(&cfg, 0), &mut out).expect("read");
    assert_eq!(&out[..n], &big[..]);

    assert!(
        v.write(&session, payload(&cfg, 0), &big).is_err(),
        "the same payload must not fit a one-sector slot"
    );
}

#[test]
fn overwriting_a_record_leaves_exactly_one_committed_side() {
    let cfg = fuzz_config();
    let (mut v, session) = formatted(&cfg);
    let slot = payload(&cfg, 0);
    v.write(&session, slot, b"first").expect("write");
    v.write(&session, slot, b"second").expect("overwrite");
    v.write(&session, slot, b"third").expect("overwrite again");
    let mut out = vec![0u8; 4096];
    let n = v.read(&session, slot, &mut out).expect("read");
    assert_eq!(&out[..n], b"third");
}

#[test]
fn always_filled_hides_occupancy_from_a_pre_pin_reader() {
    let cfg = fuzz_config();
    assert_eq!(cfg.occupancy, Occupancy::AlwaysFilled);
    let (mut v, session) = formatted(&cfg);
    assert_eq!(
        v.occupancy().count(),
        0,
        "a freshly formatted store holds no records"
    );
    v.write(&session, payload(&cfg, 0), b"one wallet").expect("write");
    drop(session);
    let mut v = remount(v, &cfg);
    assert_eq!(v.occupancy().count(), 1);

    // The point of the mode: the erased-flash signature is absent from every slot, so a
    // flash dump cannot count the wallets.
    let (flash, _) = v.into_parts();
    let records = flash.raw(notyas_wallet::Region::Records);
    let erased_sectors = records
        .chunks(4096)
        .filter(|s| s.iter().all(|b| *b == 0xff))
        .count();
    assert_eq!(
        erased_sectors,
        records.len() / 4096 - 1 - 4 - 2 - 4,
        "exactly the stale B side of every occupied slot pair is erased and nothing else"
    );
}

#[test]
fn clear_under_always_filled_writes_filler_rather_than_erasing() {
    let cfg = fuzz_config();
    let (mut v, session) = formatted(&cfg);
    let slot = payload(&cfg, 0);
    v.write(&session, slot, b"a wallet").expect("write");
    assert!(matches!(
        v.slot_state(&session, slot),
        Ok(SlotState::Occupied { .. })
    ));
    v.clear(&session, slot).expect("clear");
    assert!(matches!(v.slot_state(&session, slot), Ok(SlotState::Empty)));
    assert_eq!(v.occupancy().count(), 0);
}

// ---------------------------------------------------------------------------
// The attempt counter
// ---------------------------------------------------------------------------

#[test]
fn a_wrong_pin_costs_an_attempt_and_the_cost_survives_a_reboot() {
    let cfg = fuzz_config();
    let (v, _s) = formatted(&cfg);
    let mut v = remount(v, &cfg);
    let before = v.attempts_remaining().expect("wipe is on by default");
    let mut s = scratch(&cfg);
    match v.unlock(&pin("000000"), s.scratch()) {
        Err(UnlockError::WrongPin { attempts_remaining }) => {
            assert_eq!(attempts_remaining, Some(before - 1));
        }
        other => panic!("expected WrongPin, got {other:?}"),
    }
    let v = remount(v, &cfg);
    assert_eq!(v.attempts_remaining(), Some(before - 1));
    assert_eq!(v.failures(), 1);
}

#[test]
fn a_correct_pin_clears_the_streak() {
    let cfg = fuzz_config();
    let (v, _s) = formatted(&cfg);
    let mut v = remount(v, &cfg);
    for _ in 0..3 {
        let mut s = scratch(&cfg);
        let _ = v.unlock(&pin("000000"), s.scratch());
    }
    assert_eq!(v.failures(), 3);
    let mut s = scratch(&cfg);
    v.unlock(&pin("135790"), s.scratch()).expect("unlock");
    assert_eq!(v.failures(), 0);
    let v = remount(v, &cfg);
    assert_eq!(v.failures(), 0);
}

#[test]
fn the_limit_destroys_every_record_and_bumps_the_epoch() {
    let cfg = fuzz_config();
    let (mut v, session) = formatted(&cfg);
    v.write(&session, payload(&cfg, 0), b"about to be destroyed")
        .expect("write");
    drop(session);
    let mut v = remount(v, &cfg);
    assert_eq!(v.wipe_epoch(), 0);

    let limit = v.policy().wipe_after;
    let mut wiped = false;
    for _ in 0..limit {
        let mut s = scratch(&cfg);
        if let Err(UnlockError::Wiped { epoch }) = v.unlock(&pin("000000"), s.scratch()) {
            assert_eq!(epoch, 1);
            wiped = true;
        }
    }
    assert!(wiped, "the {limit}th consecutive failure must wipe");
    let mut v = remount(v, &cfg);
    assert!(matches!(v.state(), StoreState::Wiped { epoch: 1 }));

    // The correct PIN no longer opens anything, because every record's epoch is stale.
    let mut s = scratch(&cfg);
    assert!(v.unlock(&pin("135790"), s.scratch()).is_err());
}

#[test]
fn a_wipe_is_one_way_and_a_reformat_does_not_reset_the_epoch() {
    let cfg = fuzz_config();
    let (mut v, _s) = formatted(&cfg);
    v.wipe().expect("wipe");
    assert_eq!(v.wipe_epoch(), 1);
    let mut v = remount(v, &cfg);
    let mut s = scratch(&cfg);
    v.format(&pin("246802"), b"again", s.scratch())
        .expect("a wiped store can be formatted again");
    assert_eq!(
        v.wipe_epoch(),
        1,
        "the epoch is a one-way counter: resetting it at format would let a post-wipe \
         re-save collide with a pre-wipe flash snapshot's keystream"
    );
    let v = remount(v, &cfg);
    assert_eq!(v.wipe_epoch(), 1);
}

// ---------------------------------------------------------------------------
// PIN change
// ---------------------------------------------------------------------------

#[test]
fn a_pin_change_moves_every_record_and_retires_the_old_key() {
    let cfg = fuzz_config();
    let (mut v, session) = formatted(&cfg);
    v.write(&session, payload(&cfg, 0), b"wallet one").expect("write");
    v.write(&session, payload(&cfg, 1), b"wallet two").expect("write");
    v.write(&session, registry(&cfg, 0), b"a registration")
        .expect("write");

    let mut s = scratch(&cfg);
    let session = v
        .change_pin(session, &pin("246802"), s.scratch())
        .expect("change_pin");

    let mut out = vec![0u8; 9000];
    let n = v.read(&session, payload(&cfg, 0), &mut out).expect("read");
    assert_eq!(&out[..n], b"wallet one");
    let n = v.read(&session, registry(&cfg, 0), &mut out).expect("read");
    assert_eq!(&out[..n], b"a registration");
    drop(session);

    let mut v = remount(v, &cfg);
    let mut s = scratch(&cfg);
    assert!(
        v.unlock(&pin("135790"), s.scratch()).is_err(),
        "the retired PIN must not open the store"
    );
    let mut s = scratch(&cfg);
    v.unlock(&pin("246802"), s.scratch())
        .expect("the new PIN opens it");
}

#[test]
fn no_ciphertext_anywhere_opens_under_a_retired_pin() {
    let cfg = fuzz_config();
    let (mut v, session) = formatted(&cfg);
    v.write(&session, payload(&cfg, 0), b"wallet one").expect("write");
    let mut s = scratch(&cfg);
    let session = v
        .change_pin(session, &pin("246802"), s.scratch())
        .expect("change_pin");
    drop(session);

    let mut v = remount(v, &cfg);
    let mut s = scratch(&cfg);
    let stale = v
        .open_any_side(&pin("135790"), s.scratch())
        .expect("the scan itself works");
    assert!(
        stale.is_empty(),
        "sides still holding old-PIN ciphertext: {stale:?}"
    );
}

#[test]
fn a_session_from_before_a_pin_change_cannot_write() {
    let cfg = fuzz_config();
    let (mut v, old_session) = formatted(&cfg);
    let mut s = scratch(&cfg);
    // A second session over the same PIN, so the first is still held when the change lands.
    let stale = v.unlock(&pin("135790"), s.scratch()).expect("unlock");
    let mut s = scratch(&cfg);
    let _new = v
        .change_pin(old_session, &pin("246802"), s.scratch())
        .expect("change_pin");
    assert!(
        v.write(&stale, payload(&cfg, 0), b"too late").is_err(),
        "a session whose generation is no longer current must not be able to write a \
         record nobody could read"
    );
}

// ---------------------------------------------------------------------------
// The settable policy
// ---------------------------------------------------------------------------

#[test]
fn set_policy_needs_the_pin_and_the_ledger_is_the_authority() {
    let cfg = fuzz_config();
    let (mut v, session) = formatted(&cfg);
    assert_eq!(v.policy().wipe_after, 15);

    let mut s = scratch(&cfg);
    assert!(matches!(
        v.set_policy(
            &session,
            PolicyRequest { wipe_after: 5, min_pin_len: 4 },
            &pin("000000"),
            s.scratch()
        ),
        Err(StorageError::PinMismatch)
    ));

    let mut s = scratch(&cfg);
    let now = v
        .set_policy(
            &session,
            PolicyRequest { wipe_after: 5, min_pin_len: 4 },
            &pin("135790"),
            s.scratch(),
        )
        .expect("set_policy");
    assert_eq!(now.wipe_after, 5);
    assert_eq!(now.policy_gen, 1);
    drop(session);

    let v = remount(v, &cfg);
    assert_eq!(v.policy().wipe_after, 5);
    assert_eq!(v.attempts_remaining(), Some(5));
}

#[test]
fn the_wipe_can_be_turned_off_and_back_on() {
    let cfg = fuzz_config();
    let (mut v, session) = formatted(&cfg);
    let mut s = scratch(&cfg);
    v.set_policy(
        &session,
        PolicyRequest { wipe_after: 0, min_pin_len: 4 },
        &pin("135790"),
        s.scratch(),
    )
    .expect("disable");
    assert!(!v.policy().wipe_enabled());
    assert_eq!(
        v.attempts_remaining(),
        None,
        "with the wipe off there is no attempt count, and rendering one would be a lie"
    );
    drop(session);

    let mut v = remount(v, &cfg);
    assert!(!v.policy().wipe_enabled());
    // Far more failures than the old limit, and nothing is destroyed.
    for _ in 0..40 {
        let mut s = scratch(&cfg);
        let _ = v.unlock(&pin("000000"), s.scratch());
    }
    let mut s = scratch(&cfg);
    let session = v
        .unlock(&pin("135790"), s.scratch())
        .expect("the store is still there");

    let mut s = scratch(&cfg);
    v.set_policy(
        &session,
        PolicyRequest { wipe_after: 8, min_pin_len: 4 },
        &pin("135790"),
        s.scratch(),
    )
    .expect("re-enable");
    assert_eq!(v.policy().wipe_after, 8);
}

#[test]
fn a_wipe_disabled_device_survives_more_failures_than_the_attempt_log_holds() {
    let cfg = fuzz_config();
    let (mut v, session) = formatted(&cfg);
    let mut s = scratch(&cfg);
    v.set_policy(
        &session,
        PolicyRequest { wipe_after: 0, min_pin_len: 4 },
        &pin("135790"),
        s.scratch(),
    )
    .expect("disable");
    drop(session);
    let mut v = remount(v, &cfg);

    // The attempt log holds 128 cells. Without `failures_base` the 129th failure would
    // have nowhere to go, and refusing further attempts would be a permanent lockout that
    // is worse than the wipe the user just turned off.
    for _ in 0..300 {
        let mut s = scratch(&cfg);
        let _ = v.unlock(&pin("000000"), s.scratch());
    }
    assert_eq!(v.failures(), 300);
    let v2 = remount(v, &cfg);
    assert_eq!(
        v2.failures(),
        300,
        "rotation carries the count forward; it is not a counter reset"
    );
    let mut v = v2;
    let mut s = scratch(&cfg);
    v.unlock(&pin("135790"), s.scratch())
        .expect("the correct PIN still opens it");
    assert_eq!(v.failures(), 0);
}

#[test]
fn on_a_wipe_enabled_device_failures_base_is_always_zero() {
    // The differential property MILESTONES m3 demands: behaviour on a wipe-enabled device
    // is byte-for-byte what it was before the settable policy landed.
    let cfg = fuzz_config();
    let (v, _s) = formatted(&cfg);
    let mut v = remount(v, &cfg);
    for _ in 0..(WIPE_AFTER_MAX as usize) {
        let mut s = scratch(&cfg);
        let _ = v.unlock(&pin("000000"), s.scratch());
        let mut s = scratch(&cfg);
        if v.unlock(&pin("135790"), s.scratch()).is_ok() {
            assert_eq!(v.failures(), 0);
        }
    }
    assert_eq!(v.failures(), 0);
}

#[test]
fn a_policy_may_not_be_lowered_below_the_failures_already_accumulated() {
    let cfg = fuzz_config();
    let (v, _s) = formatted(&cfg);
    let mut v = remount(v, &cfg);
    for _ in 0..6 {
        let mut s = scratch(&cfg);
        let _ = v.unlock(&pin("000000"), s.scratch());
    }
    let mut s = scratch(&cfg);
    let session = v.unlock(&pin("135790"), s.scratch()).expect("unlock");
    // The successful unlock cleared the streak, so build it again while holding a session.
    drop(session);
    for _ in 0..6 {
        let mut s = scratch(&cfg);
        let _ = v.unlock(&pin("000000"), s.scratch());
    }
    let mut s = scratch(&cfg);
    let session = v.unlock(&pin("135790"), s.scratch()).expect("unlock");
    let _ = session;

    // With the streak cleared, 3 is legal.
    let mut s = scratch(&cfg);
    let session2 = v.unlock(&pin("135790"), s.scratch()).expect("unlock");
    let mut s = scratch(&cfg);
    assert!(v
        .set_policy(
            &session2,
            PolicyRequest { wipe_after: 3, min_pin_len: 4 },
            &pin("135790"),
            s.scratch()
        )
        .is_ok());
}

#[test]
fn an_out_of_range_limit_is_refused() {
    let cfg = fuzz_config();
    let (mut v, session) = formatted(&cfg);
    for bad in [1u8, 2, 26, 200] {
        let mut s = scratch(&cfg);
        assert!(
            matches!(
                v.set_policy(
                    &session,
                    PolicyRequest { wipe_after: bad, min_pin_len: 4 },
                    &pin("135790"),
                    s.scratch()
                ),
                Err(StorageError::Policy(PolicyRefusal::OutOfRange))
            ),
            "wipe_after = {bad} must be refused"
        );
    }
}

#[test]
fn a_pin_length_floor_on_disabling_the_wipe_is_expressible() {
    // The ratified answer is "no floor" (Q62 b), and the check is a parameter rather than
    // a constant so revisiting it is a value change and not a code change.
    let cfg = Config {
        disable_wipe_min_pin_len: Some(12),
        ..fuzz_config()
    };
    let (mut v, session) = formatted(&cfg);
    let mut s = scratch(&cfg);
    assert!(matches!(
        v.set_policy(
            &session,
            PolicyRequest { wipe_after: 0, min_pin_len: 4 },
            &pin("135790"),
            s.scratch()
        ),
        Err(StorageError::Policy(
            PolicyRefusal::PinTooShortToDisableWipe { min_len: 12 }
        ))
    ));
}

#[test]
fn remove_pin_destroys_everything_and_names_what_it_destroyed() {
    let cfg = fuzz_config();
    let (mut v, session) = formatted(&cfg);
    v.write(&session, payload(&cfg, 0), b"wallet one").expect("write");
    v.write(&session, payload(&cfg, 1), b"wallet two").expect("write");
    v.write(&session, registry(&cfg, 0), b"a registration")
        .expect("write");

    let mut s = scratch(&cfg);
    let destroyed = v
        .remove_pin(&session, &pin("135790"), s.scratch())
        .expect("remove_pin");
    assert_eq!(destroyed.wallets, 2);
    assert_eq!(destroyed.registrations, 1);
    assert_eq!(destroyed.identities, 1);
    assert_eq!(destroyed.epoch, 1);

    let v = remount(v, &cfg);
    assert!(matches!(v.state(), StoreState::Wiped { epoch: 1 }));
    let (flash, _) = v.into_parts();
    let records = flash.raw(notyas_wallet::Region::Records);
    assert!(
        records.iter().all(|b| *b == 0xff),
        "turning the PIN off returns the device to storing nothing at all"
    );
}

// ---------------------------------------------------------------------------
// Tamper
// ---------------------------------------------------------------------------

#[test]
fn an_erased_ledger_beside_live_records_is_refused() {
    let cfg = fuzz_config();
    let (mut v, session) = formatted(&cfg);
    v.write(&session, payload(&cfg, 0), b"a wallet").expect("write");
    drop(session);
    let (mut flash, mac) = v.into_parts();
    // The cheap counter-reset attack: erase the counters, keep the wallets.
    let ledger_len = flash.raw(notyas_wallet::Region::Ledger).len();
    flash.poke(notyas_wallet::Region::Ledger, 0, &vec![0xffu8; ledger_len]);

    let v = Vault::mount(flash, mac, &cfg).expect("mount reports rather than refuses");
    assert_eq!(
        v.state(),
        StoreState::Inconsistent(TamperKind::LedgerMissing)
    );
    assert!(v.tamper_flags().contains(TamperKind::LedgerMissing));
}

#[test]
fn a_forged_policy_cell_resolves_to_the_strict_default() {
    let cfg = fuzz_config();
    let (mut v, session) = formatted(&cfg);
    let mut s = scratch(&cfg);
    v.set_policy(
        &session,
        PolicyRequest { wipe_after: 0, min_pin_len: 4 },
        &pin("135790"),
        s.scratch(),
    )
    .expect("disable the wipe");
    drop(session);
    assert!(!v.policy().wipe_enabled());

    let (mut flash, mac) = v.into_parts();
    // Corrupt the guard of the policy cell. An attacker with a programmer can write any
    // bytes they like into the plaintext ledger and cannot make them verify.
    flash.poke(notyas_wallet::Region::Ledger, 0x0f88, &[0x00; 8]);
    let v = Vault::mount(flash, mac, &cfg).expect("mount");
    assert!(
        v.policy().wipe_enabled(),
        "a malformed policy cell must force the strict default, which always has the \
         wipe ON: glitching a cell must never be able to preserve an off policy"
    );
    assert!(v.tamper_flags().contains(TamperKind::GuardMismatch));
}

#[test]
fn an_erased_policy_log_falls_back_to_the_format_time_policy() {
    let cfg = fuzz_config();
    let (mut v, session) = formatted(&cfg);
    let mut s = scratch(&cfg);
    v.set_policy(
        &session,
        PolicyRequest { wipe_after: 0, min_pin_len: 4 },
        &pin("135790"),
        s.scratch(),
    )
    .expect("disable the wipe");
    drop(session);

    let (mut flash, mac) = v.into_parts();
    flash.poke(notyas_wallet::Region::Ledger, 0x0f80, &[0xff; 128]);
    let v = Vault::mount(flash, mac, &cfg).expect("mount");
    assert!(
        v.policy().wipe_enabled(),
        "there is no erase that produces a permissive state"
    );
    assert_eq!(v.policy().wipe_after, 15);
}

#[test]
fn a_superblock_only_rollback_cannot_weaken_the_policy() {
    let cfg = fuzz_config();
    let (mut v, session) = formatted(&cfg);
    let mut s = scratch(&cfg);
    v.set_policy(
        &session,
        PolicyRequest { wipe_after: 5, min_pin_len: 4 },
        &pin("135790"),
        s.scratch(),
    )
    .expect("tighten");
    drop(session);
    let v = remount(v, &cfg);
    assert_eq!(v.policy().wipe_after, 5);

    // Roll the RECORDS region back to the tighter policy while keeping the newer ledger.
    // That is exactly what a superblock-only restore looks like from a programmer, and it
    // must not be able to loosen anything.
    let (flash, mac) = v.into_parts();
    let tight = flash.snapshot();
    let mut v = Vault::mount(flash, mac, &cfg).expect("mount");
    let mut s = scratch(&cfg);
    let session = v.unlock(&pin("135790"), s.scratch()).expect("unlock");
    let mut s = scratch(&cfg);
    v.set_policy(
        &session,
        PolicyRequest { wipe_after: 25, min_pin_len: 4 },
        &pin("135790"),
        s.scratch(),
    )
    .expect("loosen");
    drop(session);
    let (flash, mac) = v.into_parts();
    let loose_ledger = flash.raw(notyas_wallet::Region::Ledger).to_vec();

    let mut rolled = SimFlash::new(geometry_for(&cfg.layout));
    rolled.restore(&tight);
    rolled.poke(notyas_wallet::Region::Ledger, 0, &loose_ledger);
    let v = Vault::mount(rolled, mac, &cfg).expect("mount");
    assert_eq!(
        v.policy().wipe_after,
        25,
        "the ledger is the authority; the superblock mirror is never it"
    );
}

#[test]
fn flash_from_another_board_is_named_as_foreign() {
    let cfg = fuzz_config();
    let (v, _s) = formatted(&cfg);
    let (flash, _) = v.into_parts();
    match Vault::mount(flash, SoftMac::other_board(), &cfg) {
        Err(MountError::Foreign) => {}
        other => panic!("expected Foreign, got {other:?}"),
    }
}

#[test]
fn a_record_sealed_at_one_provenance_cannot_be_opened_at_another() {
    // Not "should not": cannot. The provenance byte is inside `RecordInfo` and the flag is
    // inside the AEAD's associated data.
    let cfg = Config {
        accept_provenance: &[KeyProvenance::EfuseReadProtected, KeyProvenance::Emulated],
        ..fuzz_config()
    };
    let flash = SimFlash::new(geometry_for(&cfg.layout));
    let mut v = Vault::mount(flash, SoftMac::new(), &cfg).expect("mount");
    let mut s = scratch(&cfg);
    v.format(&pin("135790"), b"prod", s.scratch()).expect("format");
    let (flash, _) = v.into_parts();

    let mac = SoftMac::new().with_provenance(KeyProvenance::Emulated);
    let mut v = Vault::mount(flash, mac, &cfg).expect("mount");
    let mut s = scratch(&cfg);
    assert!(
        v.unlock(&pin("135790"), s.scratch()).is_err(),
        "a development-mode build must not be able to open a production record"
    );
}

// ---------------------------------------------------------------------------
// Encrypted partitions and the shipped geometry
// ---------------------------------------------------------------------------

#[test]
fn the_whole_lifecycle_works_on_an_encrypted_records_partition() {
    // On a release unit an erased sector DECRYPTS to pseudorandom bytes, so any erasure
    // test built on `read` works on a dev board and fails in the field. This is the test
    // that would catch it.
    let cfg = fuzz_config();
    let flash = SimFlash::new(geometry_for(&cfg.layout)).encrypted(true);
    let mut v = Vault::mount(flash, SoftMac::new(), &cfg).expect("mount");
    let mut s = scratch(&cfg);
    let session = v.format(&pin("135790"), b"enc", s.scratch()).expect("format");
    v.write(&session, payload(&cfg, 0), b"encrypted at rest twice over")
        .expect("write");
    drop(session);
    let mut v = remount(v, &cfg);
    let mut s = scratch(&cfg);
    let session = v.unlock(&pin("135790"), s.scratch()).expect("unlock");
    let mut out = vec![0u8; 4096];
    let n = v.read(&session, payload(&cfg, 0), &mut out).expect("read");
    assert_eq!(&out[..n], b"encrypted at rest twice over");
}

#[test]
fn the_shipped_v1_geometry_round_trips() {
    let cfg = v1_config();
    let flash = SimFlash::v1();
    let mut v = Vault::mount(flash, SoftMac::new(), &cfg).expect("mount");
    let mut s = scratch(&cfg);
    let session = v.format(&pin("135790"), b"v1", s.scratch()).expect("format");
    assert!(matches!(
        v.state(),
        StoreState::Formatted { identities_present: 1, occupied_slots: 0 }
    ));
    for i in 0..8u8 {
        v.write(&session, payload(&cfg, i), &[i; 100])
            .expect("write every payload slot");
    }
    drop(session);
    let mut v = remount(v, &cfg);
    assert_eq!(v.occupancy().count(), 8);
    let mut s = scratch(&cfg);
    let session = v.unlock(&pin("135790"), s.scratch()).expect("unlock");
    let mut out = vec![0u8; 9000];
    for i in 0..8u8 {
        let n = v.read(&session, payload(&cfg, i), &mut out).expect("read");
        assert_eq!(&out[..n], &vec![i; 100][..]);
    }
}

// ---------------------------------------------------------------------------
// Sessions and duress identities
// ---------------------------------------------------------------------------

#[test]
fn a_second_identity_opens_only_its_own_canary() {
    let cfg = fuzz_config();
    let (mut v, session) = formatted(&cfg);
    let mut s = scratch(&cfg);
    v.add_identity(
        &session,
        Identity(1),
        &pin("909090"),
        notyas_wallet::SlotMap::from_bits(0b01),
        s.scratch(),
    )
    .expect("add_identity");
    drop(session);

    let mut v = remount(v, &cfg);
    let mut s = scratch(&cfg);
    let duress = v.unlock(&pin("909090"), s.scratch()).expect("unlock duress");
    assert_eq!(duress.identity(), Identity(1));
    assert_eq!(duress.visible_slots().bits(), 0b01);
    drop(duress);
    let mut s = scratch(&cfg);
    let primary = v.unlock(&pin("135790"), s.scratch()).expect("unlock primary");
    assert_eq!(primary.identity(), Identity(0));
}

#[test]
fn changing_one_identitys_pin_leaves_the_others_records_intact() {
    // The hole the format's own candidate rule would have had: with every identity on
    // generation 0, one PIN change would leave the retired generation still current.
    let cfg = fuzz_config();
    let (mut v, session) = formatted(&cfg);
    let mut s = scratch(&cfg);
    v.add_identity(
        &session,
        Identity(1),
        &pin("909090"),
        notyas_wallet::SlotMap::ALL,
        s.scratch(),
    )
    .expect("add_identity");
    v.write(&session, payload(&cfg, 0), b"identity zero's wallet")
        .expect("write");
    let mut s = scratch(&cfg);
    let session = v
        .change_pin(session, &pin("246802"), s.scratch())
        .expect("change_pin");
    drop(session);

    let mut v = remount(v, &cfg);
    let mut s = scratch(&cfg);
    assert!(v.unlock(&pin("135790"), s.scratch()).is_err());
    let mut s = scratch(&cfg);
    let duress = v.unlock(&pin("909090"), s.scratch());
    assert!(
        duress.is_ok(),
        "the second identity's canary must survive the first identity's PIN change"
    );
    let mut s = scratch(&cfg);
    let primary = v.unlock(&pin("246802"), s.scratch()).expect("new PIN");
    let mut out = vec![0u8; 4096];
    let n = v.read(&primary, payload(&cfg, 0), &mut out).expect("read");
    assert_eq!(&out[..n], b"identity zero's wallet");
}

#[test]
fn confirm_pin_costs_nothing_and_verify_pin_costs_an_attempt() {
    let cfg = fuzz_config();
    let (v, _s) = formatted(&cfg);
    let mut v = remount(v, &cfg);
    let mut s = scratch(&cfg);
    let session = v.unlock(&pin("135790"), s.scratch()).expect("unlock");

    let before = v.failures();
    for _ in 0..5 {
        let mut s = scratch(&cfg);
        assert!(v.confirm_pin(&session, &pin("135790"), s.scratch()).unwrap());
        let mut s = scratch(&cfg);
        assert!(!v.confirm_pin(&session, &pin("000000"), s.scratch()).unwrap());
    }
    assert_eq!(
        v.failures(),
        before,
        "confirm_pin touches no flash and consumes no attempt"
    );
    drop(session);

    let mut s = scratch(&cfg);
    let _ = v.verify_pin(&pin("000000"), s.scratch());
    assert_eq!(
        v.failures(),
        before + 1,
        "verify_pin on a locked store is a guess and must cost one"
    );
}

#[test]
fn the_boot_log_counts_and_survives_a_power_cycle() {
    let cfg = fuzz_config();
    let (mut v, _s) = formatted(&cfg);
    assert_eq!(v.record_boot().expect("record_boot"), 1);
    assert_eq!(v.record_boot().expect("record_boot"), 2);
    let v = remount(v, &cfg);
    assert_eq!(v.boot_count(), 2);
}

#[test]
fn the_policy_encoding_orders_strictness_the_way_the_fuzzer_assumes() {
    let strict = Policy {
        wipe_after: 3,
        occupancy: Occupancy::AlwaysFilled,
        min_pin_len: 4,
        policy_gen: 0,
    };
    let loose = Policy { wipe_after: 25, ..strict };
    let off = Policy { wipe_after: 0, ..strict };
    assert!(strict.at_least_as_strict_as(&loose));
    assert!(!loose.at_least_as_strict_as(&strict));
    assert!(loose.at_least_as_strict_as(&off));
    assert!(!off.at_least_as_strict_as(&loose));
    assert!(off.at_least_as_strict_as(&off));
}

// ---------------------------------------------------------------------------
// Sparse occupancy, the mode notyas does not ship but the layer supports
// ---------------------------------------------------------------------------

#[test]
fn sparse_leaves_unoccupied_slots_erased_and_the_format_is_otherwise_identical() {
    // Q2 pins AlwaysFilled for the product, and the mode switch is still built because the
    // sealing layer is general. The property that makes that safe is that the ON-FLASH
    // FORMAT is byte-identical between the two modes: only the content of an unoccupied
    // slot differs, so the choice can be made after the format is frozen.
    let cfg = Config {
        occupancy: Occupancy::Sparse,
        ..fuzz_config()
    };
    let (mut v, session) = formatted(&cfg);
    v.write(&session, payload(&cfg, 0), b"the only record")
        .expect("write");
    drop(session);
    let mut v = remount(v, &cfg);
    assert_eq!(v.occupancy().count(), 1);

    let mut s = scratch(&cfg);
    let session = v.unlock(&pin("135790"), s.scratch()).expect("unlock");
    let mut out = vec![0u8; 4096];
    let n = v.read(&session, payload(&cfg, 0), &mut out).expect("read");
    assert_eq!(&out[..n], b"the only record");
    // The unoccupied slots really are erased, which is the whole difference and the whole
    // leak: a flash dump now counts the wallets.
    v.clear(&session, payload(&cfg, 0)).expect("clear");
    drop(session);
    let v = remount(v, &cfg);
    let (flash, _) = v.into_parts();
    let records = flash.raw(notyas_wallet::Region::Records);
    let payload_pair = &records[10 * 4096..12 * 4096];
    assert!(
        payload_pair.iter().all(|b| *b == 0xff),
        "under Sparse a cleared slot is erased on both sides"
    );
}

// ---------------------------------------------------------------------------
// The device-bound derivation the product builds anti-phishing words on
// ---------------------------------------------------------------------------

#[test]
fn device_derive_is_device_bound_label_separated_and_needs_no_pin() {
    let cfg = fuzz_config();
    let mut v = blank(&cfg);
    let mut words = [0u8; 32];
    v.device_derive(b"antiphishing", b"12", &mut words)
        .expect("no PIN required");

    let mut same = [0u8; 32];
    v.device_derive(b"antiphishing", b"12", &mut same)
        .expect("derive");
    assert_eq!(words, same, "the derivation is a pure function of its inputs");

    let mut other_label = [0u8; 32];
    v.device_derive(b"lockscreen", b"12", &mut other_label)
        .expect("derive");
    assert_ne!(words, other_label);

    let mut other_data = [0u8; 32];
    v.device_derive(b"antiphishing", b"13", &mut other_data)
        .expect("derive");
    assert_ne!(words, other_data);

    // The separation that matters: the label and the data are length-prefixed, so moving a
    // byte from one to the other cannot produce the same message. Without this an attacker
    // choosing the input to an embedder-facing derivation could steer it.
    let mut shifted = [0u8; 32];
    v.device_derive(b"antiphishing1", b"2", &mut shifted)
        .expect("derive");
    assert_ne!(
        words, shifted,
        "concatenation without a length prefix would make these two calls identical"
    );

    let flash = SimFlash::new(geometry_for(&cfg.layout));
    let mut other_board = Vault::mount(flash, SoftMac::other_board(), &cfg).expect("mount");
    let mut elsewhere = [0u8; 32];
    other_board
        .device_derive(b"antiphishing", b"12", &mut elsewhere)
        .expect("derive");
    assert_ne!(
        words, elsewhere,
        "the words must be different on a different board or they defend nothing"
    );
}

// ---------------------------------------------------------------------------
// Caller-supplied working memory
// ---------------------------------------------------------------------------

#[test]
fn a_scratch_buffer_that_is_too_small_is_named_rather_than_guessed_at() {
    let cfg = fuzz_config();
    let (v, _s) = formatted(&cfg);
    let mut v = remount(v, &cfg);
    let mut tiny = VecScratch::with_blocks(1);
    match v.unlock(&pin("135790"), tiny.scratch()) {
        Err(UnlockError::Scratch { required_blocks }) => {
            assert_eq!(required_blocks, cfg.kdf.scratch_blocks());
        }
        other => panic!("expected a Scratch refusal naming the size, got {other:?}"),
    }
    assert_eq!(
        v.failures(),
        0,
        "a refusal before the counted region must not cost the user an attempt"
    );
}

#[test]
fn the_pin_entropy_estimate_is_advisory_and_monotonic() {
    let four_digits = pin("1234").estimated_bits();
    let six_digits = pin("123456").estimated_bits();
    let mixed = pin("Tr0ub4dor").estimated_bits();
    assert!(six_digits > four_digits);
    assert!(mixed > six_digits);
    assert_eq!(
        pin("1").estimated_bits(),
        3,
        "one digit out of ten is log2(10) rounded down, and the number is an upper bound          on a keyspace rather than a claim about what the user chose"
    );
}

#[test]
fn an_oversized_derivation_input_is_refused_rather_than_truncated() {
    // The failure this guards against is subtle and was real: a fixed staging buffer that
    // silently dropped everything past its end would let two inputs differing only past
    // the cut derive the same value, which is exactly the collision the length prefix in
    // front of them exists to prevent.
    let cfg = fuzz_config();
    let mut v = blank(&cfg);
    let mut out = [0u8; 32];

    assert!(v.device_derive(&[b'x'; 64], &[b'y'; 256], &mut out).is_ok());
    assert!(
        matches!(
            v.device_derive(&[b'x'; 65], b"", &mut out),
            Err(StorageError::Capacity)
        ),
        "an over-long label must be refused"
    );
    assert!(
        matches!(
            v.device_derive(b"", &[b'y'; 257], &mut out),
            Err(StorageError::Capacity)
        ),
        "over-long data must be refused"
    );

    // And the pair that would have collided under truncation stays distinct.
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    v.device_derive(b"label", &[b'z'; 200], &mut a).expect("derive");
    let mut longer = vec![b'z'; 200];
    longer.push(b'z');
    v.device_derive(b"label", &longer, &mut b).expect("derive");
    assert_ne!(a, b);
}
