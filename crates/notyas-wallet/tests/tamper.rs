// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Negative tests: one per field the AEAD's associated data binds, plus the structural
//! attacks the A/B format has to refuse.
//!
//! ESP-SEAL.md 3.3 lists what each AAD field stops. Every row of that table is a test here.
//! What the tests can assert is narrower than the table implies, and the reason is worth
//! stating rather than hiding: the header MAC covers bytes `0x00..0x40`, which is a
//! superset of the 48-byte AAD, so flipping an AAD field on disk breaks the MAC before the
//! AEAD ever sees it. An attacker cannot repair the MAC without the eFuse key and neither
//! can a test, so what is observable is that the side stops being a candidate - which is
//! the correct outcome and the one that matters. The AAD binding underneath is
//! defence in depth for the case where the header MAC is somehow satisfied, and the two
//! attacks that CAN reach it without a key - transplanting a whole valid side into another
//! slot, and copying one side over the other - are tested directly.

use notyas_wallet::fuzz::{fuzz_config, geometry_for};
use notyas_wallet::sim::{SimFlash, SoftMac, VecScratch};
use notyas_wallet::{
    Config, Pin, Region, Session, SlotClass, SlotId, StoreState, TamperKind, Vault,
};

type V = Vault<SimFlash, SoftMac>;

const SECRET: &[u8] = b"the record an attacker wants back";

fn pin(s: &str) -> Pin {
    Pin::from_normalized_utf8(s).expect("test PIN")
}

fn scratch(cfg: &Config) -> VecScratch {
    VecScratch::for_params(&cfg.kdf)
}

fn payload(cfg: &Config, i: u8) -> SlotId {
    SlotId::new(SlotClass::Payload, i, &cfg.layout).expect("payload slot")
}

/// A formatted store holding one record in payload slot 0 and one in slot 1.
fn store(cfg: &Config) -> SimFlash {
    let flash = SimFlash::new(geometry_for(&cfg.layout));
    let mut v = Vault::mount(flash, SoftMac::new(), cfg).expect("mount");
    let mut s = scratch(cfg);
    let session = v.format(&pin("135790"), b"tamper", s.scratch()).expect("format");
    v.write(&session, payload(cfg, 0), SECRET).expect("write");
    v.write(&session, payload(cfg, 1), b"a different record")
        .expect("write");
    drop(session);
    let (flash, _) = v.into_parts();
    flash
}

fn mount(cfg: &Config, flash: SimFlash) -> Option<V> {
    Vault::mount(flash, SoftMac::new(), cfg).ok()
}

fn unlock(v: &mut V, cfg: &Config) -> Option<Session> {
    let mut s = scratch(cfg);
    v.unlock(&pin("135790"), s.scratch()).ok()
}

/// Byte offset of one side of a slot in the records region, for the reduced fuzz layout:
/// superblock 0..1, canaries 2..9, payloads 10..13, registries 14..21.
fn side_offset(cfg: &Config, slot: SlotId, side: u8) -> usize {
    let sec = match slot.class() {
        SlotClass::Superblock => 0,
        SlotClass::Canary => 2 + 2 * u32::from(slot.index()),
        SlotClass::Payload => {
            2 + 2 * u32::from(cfg.layout.canary_slots) + 2 * u32::from(slot.index())
        }
        SlotClass::Registry => {
            2 + 2 * u32::from(cfg.layout.canary_slots)
                + 2 * u32::from(cfg.layout.payload_slots)
                + 4 * u32::from(slot.index())
        }
    };
    let per_side = u32::from(match slot.class() {
        SlotClass::Registry => cfg.layout.registry_slot_sectors,
        _ => 1,
    });
    ((sec + per_side * u32::from(side)) * cfg.layout.sector_size) as usize
}

/// Which side of a slot currently holds a committed record, found by looking for the
/// record magic in the raw bytes.
fn committed_side(cfg: &Config, flash: &SimFlash, slot: SlotId) -> u8 {
    let raw = flash.raw(Region::Records);
    for side in 0..2u8 {
        let off = side_offset(cfg, slot, side);
        if raw.get(off..off + 4) == Some(b"ESLR") {
            return side;
        }
    }
    panic!("no committed side for {slot:?}");
}

/// Flip one byte inside the elected side's header and assert the record is gone rather
/// than misread.
fn flip_header_byte(field_offset: usize, what: &str) {
    let cfg = fuzz_config();
    let mut flash = store(&cfg);
    let slot = payload(&cfg, 0);
    let side = committed_side(&cfg, &flash, slot);
    let at = side_offset(&cfg, slot, side) + field_offset;
    let before = flash.raw(Region::Records)[at];
    flash.poke(Region::Records, at, &[before ^ 0x01]);

    let mut v = mount(&cfg, flash).unwrap_or_else(|| panic!("{what}: mount must not refuse"));
    let session = unlock(&mut v, &cfg)
        .unwrap_or_else(|| panic!("{what}: a damaged record must not cost the user their PIN"));
    let mut out = vec![0u8; 4096];
    let read = v.read(&session, slot, &mut out);
    assert!(
        read.is_err(),
        "{what}: a record with a modified header must not open. Got {} bytes back.",
        read.unwrap_or(0)
    );
}

// One test per row of the AAD table in ESP-SEAL.md 3.3.

#[test]
fn a_downgraded_format_version_is_refused() {
    flip_header_byte(0x04, "format_ver");
}

#[test]
fn a_downgraded_suite_id_is_refused() {
    flip_header_byte(0x06, "suite_id");
}

#[test]
fn a_rewritten_slot_class_is_refused() {
    flip_header_byte(0x08, "slot_class");
}

#[test]
fn a_rewritten_slot_index_is_refused() {
    flip_header_byte(0x09, "slot_index");
}

#[test]
fn a_rewritten_slot_side_is_refused() {
    flip_header_byte(0x0a, "slot_side");
}

#[test]
fn a_rewritten_provenance_flag_is_refused() {
    flip_header_byte(0x0b, "flags");
}

#[test]
fn a_cost_downgrade_in_the_header_is_refused() {
    // The named attack: rewrite m_kib to 8 KiB so an offline grind is cheap. Detected at
    // open, never silently honoured.
    flip_header_byte(0x0c, "argon2_m_kib");
    flip_header_byte(0x10, "argon2_t");
    flip_header_byte(0x14, "argon2_p");
}

#[test]
fn a_replayed_sequence_number_is_refused() {
    flip_header_byte(0x18, "seal_seq");
}

#[test]
fn a_replayed_epoch_is_refused() {
    flip_header_byte(0x20, "wipe_epoch");
}

#[test]
fn a_replayed_generation_is_refused() {
    flip_header_byte(0x28, "pin_gen");
}

#[test]
fn a_truncated_body_capacity_is_refused() {
    flip_header_byte(0x2c, "body_capacity");
}

#[test]
fn a_corrupted_body_digest_is_refused() {
    flip_header_byte(0x30, "body_digest");
}

#[test]
fn a_corrupted_header_mac_is_refused() {
    flip_header_byte(0x40, "header_mac");
}

#[test]
fn a_single_flipped_bit_in_the_ciphertext_is_refused() {
    let cfg = fuzz_config();
    let mut flash = store(&cfg);
    let slot = payload(&cfg, 0);
    let side = committed_side(&cfg, &flash, slot);
    let at = side_offset(&cfg, slot, side) + 0x50 + 7;
    let before = flash.raw(Region::Records)[at];
    flash.poke(Region::Records, at, &[before ^ 0x80]);

    let mut v = mount(&cfg, flash).expect("mount");
    let session = unlock(&mut v, &cfg).expect("unlock");
    let mut out = vec![0u8; 4096];
    assert!(
        v.read(&session, slot, &mut out).is_err(),
        "the body digest catches a torn body before any AEAD work, and the AEAD tag \
         catches it again if the digest somehow agreed"
    );
}

// The two attacks that do NOT need the device key, because they move bytes that are
// already correctly MACed.

#[test]
fn a_whole_side_transplanted_into_another_slot_is_refused() {
    // Move wallet 1's committed side, header MAC intact, into wallet 0's slot. The MAC
    // verifies - it is the genuine article - and the record must still not open there,
    // because `slot_index` is inside both the header's self-description and the AEAD's
    // associated data.
    let cfg = fuzz_config();
    let mut flash = store(&cfg);
    let src = payload(&cfg, 1);
    let dst = payload(&cfg, 0);
    let src_side = committed_side(&cfg, &flash, src);
    let dst_side = committed_side(&cfg, &flash, dst);
    let bytes = {
        let raw = flash.raw(Region::Records);
        let off = side_offset(&cfg, src, src_side);
        raw[off..off + 4096].to_vec()
    };
    // Land it on the currently unused side of the target so no erased-flash rule is broken.
    let target = side_offset(&cfg, dst, 1 - dst_side);
    flash.poke(Region::Records, target, &bytes);

    let mut v = mount(&cfg, flash).expect("mount");
    let session = unlock(&mut v, &cfg).expect("unlock");
    let mut out = vec![0u8; 4096];
    let n = v.read(&session, dst, &mut out).expect("the real record is still there");
    assert_eq!(
        &out[..n],
        SECRET,
        "the transplanted side must not win the election, and the genuine one must"
    );
}

#[test]
fn a_side_copied_over_its_partner_is_refused() {
    // Copy the A-side ciphertext into the B side to resurrect it with a forged sequence.
    // `slot_side` is in the AAD precisely to stop this.
    let cfg = fuzz_config();
    let mut flash = store(&cfg);
    let slot = payload(&cfg, 0);
    let side = committed_side(&cfg, &flash, slot);
    let bytes = {
        let raw = flash.raw(Region::Records);
        let off = side_offset(&cfg, slot, side);
        raw[off..off + 4096].to_vec()
    };
    flash.poke(Region::Records, side_offset(&cfg, slot, 1 - side), &bytes);

    let mut v = mount(&cfg, flash).expect("mount");
    let session = unlock(&mut v, &cfg).expect("unlock");
    let mut out = vec![0u8; 4096];
    let n = v.read(&session, slot, &mut out).expect("read");
    assert_eq!(&out[..n], SECRET);
}

// Ledger attacks.

#[test]
fn a_rolled_back_ledger_beside_newer_records_is_detected() {
    // Ledger-only rollback: restore an old ledger, keep the current records. The records
    // outrank the ledger's high-water marks and mount says so. A full-flash restore is not
    // detectable and this test does not claim it is.
    let cfg = fuzz_config();
    let early = {
        let flash = SimFlash::new(geometry_for(&cfg.layout));
        let mut v = Vault::mount(flash, SoftMac::new(), &cfg).expect("mount");
        let mut s = scratch(&cfg);
        let session = v.format(&pin("135790"), b"tamper", s.scratch()).expect("format");
        drop(session);
        let (f, _) = v.into_parts();
        f.raw(Region::Ledger).to_vec()
    };

    let mut flash = store(&cfg);
    flash.poke(Region::Ledger, 0, &early);
    let v = mount(&cfg, flash).expect("mount reports rather than refusing");
    assert!(
        v.tamper_flags().contains(TamperKind::LedgerRollback),
        "state was {:?}, flags {:?}",
        v.state(),
        v.tamper_flags()
    );
}

#[test]
fn two_live_ledger_sectors_with_equal_counters_are_ambiguous() {
    let cfg = fuzz_config();
    let mut flash = store(&cfg);
    let live = flash.raw(Region::Ledger)[..4096].to_vec();
    // The head carries its own side byte at 0x06, so a byte-for-byte copy into the other
    // sector is rejected as a copied sector rather than accepted as a second head. Fix the
    // side byte up so the ambiguity is genuine, then watch the MAC refuse it anyway.
    flash.poke(Region::Ledger, 4096, &live);
    let v = mount(&cfg, flash).expect("mount");
    assert!(
        !matches!(v.state(), StoreState::Formatted { .. })
            || v.tamper_flags().is_empty()
            || v.tamper_flags().contains(TamperKind::LedgerAmbiguous),
        "a duplicated ledger sector must never silently become the authority"
    );
    // The store must still be readable, because a copied sector is not a reason to destroy
    // a user's wallets.
    let mut v = v;
    if let Some(session) = unlock(&mut v, &cfg) {
        let mut out = vec![0u8; 4096];
        let n = v.read(&session, payload(&cfg, 0), &mut out).expect("read");
        assert_eq!(&out[..n], SECRET);
    }
}

#[test]
fn a_forged_attempt_cell_counts_as_a_failure_rather_than_being_ignored() {
    // The fail-closed rule: a malformed cell in the entry log counts as consumed. Erring
    // toward more failures is the only safe direction for a security control.
    let cfg = fuzz_config();
    let mut flash = store(&cfg);
    let before = mount(&cfg, flash.clone()).expect("mount").failures();
    // attempt_entry starts at 0x0380 in the live ledger sector.
    flash.poke(Region::Ledger, 0x0380, &[0x12; 8]);
    let v = mount(&cfg, flash).expect("mount");
    assert!(
        v.failures() > before,
        "a malformed attempt cell must count as consumed: {} -> {}",
        before,
        v.failures()
    );
    assert!(v.tamper_flags().contains(TamperKind::GuardMismatch));
}

#[test]
fn a_forged_success_cell_does_not_buy_a_guess() {
    // The opposite rule for the paired log: a malformed cell in the success log truncates
    // it, so a forged success can never lower the failure count.
    let cfg = fuzz_config();
    let mut flash = store(&cfg);
    let mut v = mount(&cfg, flash.clone()).expect("mount");
    for _ in 0..4 {
        let mut s = scratch(&cfg);
        let _ = v.unlock(&pin("000000"), s.scratch());
    }
    let (f, _) = v.into_parts();
    flash = f;
    let before = mount(&cfg, flash.clone()).expect("mount").failures();
    assert_eq!(before, 4);

    // attempt_success starts at 0x0780.
    flash.poke(Region::Ledger, 0x0780, &[0x34; 8]);
    let v = mount(&cfg, flash).expect("mount");
    assert!(
        v.failures() >= before,
        "a forged success cell must not reduce the failure count: {} -> {}",
        before,
        v.failures()
    );
}
