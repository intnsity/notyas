// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Turning "remember this wallet's passphrase" OFF destroys the passphrase.
//!
//! The record half of that claim is in `wallet_record.rs`: the body a forget writes does
//! not contain the passphrase, anywhere in it. This is the other half, and it is the one
//! that is actually load-bearing - a record with no passphrase in it is worth nothing if
//! the PREVIOUS record, which had one, is still sitting in the other half of the slot pair
//! waiting for anyone who can read flash and knows the PIN.
//!
//! # What is proven, and what "gone" means here
//!
//! Records are sealed, so the passphrase is never plaintext on flash in the first place -
//! scanning the image for the bytes proves nothing about a device that is working
//! correctly. The property that MATTERS is that no surviving ciphertext anywhere on the
//! flash decrypts, under this store's own key, to a record carrying the passphrase. That
//! is exactly what `Vault::open_any_side` answers: it walks every (slot, side) pair
//! including the ones no election will ever reach, and reports which ones open. After a
//! re-seal there must be one, and reading it must give a record with no passphrase in it.
//!
//! Both scans are run anyway, because the cheap one guards a future in which the mode
//! changes: a plaintext-bytes scan of the raw image costs nothing and would catch an
//! unsealed write immediately.
//!
//! The mechanism under the guarantee is the vault's own: `Vault::write` seals into the
//! INACTIVE side and erases the stale side before it returns (`seal_into` ->
//! `StaleSide::EraseNow`). A cut inside that window leaves the stale side for the next
//! mount's cleanup, which is the same guarantee every other record write on this device
//! has and is covered by that crate's power-loss harness rather than restated here.

use notyas_core::bitcoin::Network;
use notyas_firmware_hostcheck::record::{SealedWallet, StoredPassphrase, WalletRecord};
use notyas_wallet::fuzz::{fuzz_config, geometry_for};
use notyas_wallet::sim::{SimFlash, SoftMac, VecScratch};
use notyas_wallet::{
    Config, Pin, Region, Session, SlotClass, SlotId, Vault,
};

type V = Vault<SimFlash, SoftMac>;

/// The published vector, as everywhere else in this suite: these words derive b4e3f5ed
/// under the passphrase TREZOR.
const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon about";
const PASSPHRASE: &str = "TREZOR";
const CONFIRMED: &str = "b4e3f5ed";
const LABEL: &str = "tz";
const PIN: &str = "135790";

fn pin() -> Pin {
    Pin::from_normalized_utf8(PIN).expect("a test PIN")
}

fn formatted(cfg: &Config) -> (V, Session) {
    let flash = SimFlash::new(geometry_for(&cfg.layout));
    let mut v = Vault::mount(flash, SoftMac::new(), cfg).expect("a blank store mounts");
    let mut scratch = VecScratch::for_params(&cfg.kdf);
    let session = v
        .format(&pin(), b"notyas", scratch.scratch())
        .expect("format");
    (v, session)
}

fn slot(cfg: &Config) -> SlotId {
    SlotId::new(SlotClass::Payload, 0, &cfg.layout).expect("payload slot 0 exists")
}

/// The record as it reads back out of the slot.
fn read_back(v: &mut V, session: &Session, slot: SlotId) -> WalletRecord {
    let mut buf = vec![0u8; 4096];
    let n = v.read(session, slot, &mut buf).expect("the slot reads");
    WalletRecord::decode(&buf[..n]).expect("it is a wallet record")
}

/// Every (slot, side) on the whole flash that opens under this PIN. The stale-ciphertext
/// question, asked the way `notyas-wallet` asks it of a PIN change.
fn sides_that_open(v: &mut V, cfg: &Config) -> Vec<(SlotId, notyas_wallet::Side)> {
    let mut scratch = VecScratch::for_params(&cfg.kdf);
    v.open_any_side(&pin(), scratch.scratch())
        .expect("the scan itself works")
}

#[test]
fn forgetting_a_stored_passphrase_leaves_no_side_that_still_holds_it() {
    let cfg = fuzz_config();
    let (mut v, session) = formatted(&cfg);
    let slot = slot(&cfg);

    // 1. The wallet, with the passphrase stored on it, sealed into the slot.
    let remembered = SealedWallet::confirmed(
        LABEL,
        Network::Bitcoin,
        PHRASE,
        CONFIRMED,
        StoredPassphrase::Stored(zeroize::Zeroizing::new(String::from(PASSPHRASE))),
    )
    .expect("the stored passphrase derives the identity it claims");
    let with = remembered.body(4096).expect("it encodes");
    v.write(&session, slot, &with).expect("the record seals");
    assert_eq!(
        read_back(&mut v, &session, slot).passphrase.stored(),
        Some(PASSPHRASE),
        "the test is meaningless unless the passphrase really was stored"
    );

    // 2. Turn it off: the same record, minus the passphrase, into the same slot. This is
    //    what `Wallet::set_passphrase_storage` writes; the store call it makes is this one.
    let forgotten = SealedWallet::confirmed(
        LABEL,
        Network::Bitcoin,
        PHRASE,
        CONFIRMED,
        StoredPassphrase::Applied,
    )
    .expect("a wallet that still has a passphrase, unremembered");
    let without = forgotten.body(4096).expect("it encodes");
    v.write(&session, slot, &without).expect("the record re-seals");

    // 3. What the device now reads: the wallet, still a passphrase wallet, with no
    //    passphrase in it.
    let back = read_back(&mut v, &session, slot);
    assert_eq!(back.passphrase, StoredPassphrase::Applied);
    assert_eq!(back.passphrase.stored(), None);
    assert_eq!(back.phrase.as_str(), PHRASE, "the words are untouched");
    assert_eq!(back.label, LABEL);
    assert_eq!(back.fingerprint.to_string(), CONFIRMED);

    // 4. The claim itself: exactly ONE side of that slot still opens, and it is the one
    //    just written. A stale side holding the passphrase-bearing ciphertext would show
    //    up here as a second entry, and it is unreachable through `read` - which is
    //    precisely why the scan exists.
    let open: Vec<_> = sides_that_open(&mut v, &cfg)
        .into_iter()
        .filter(|(s, _)| *s == slot)
        .collect();
    assert_eq!(
        open.len(),
        1,
        "sides of the wallet slot that still open: {open:?} - one of them holds the \
         passphrase this device was told to forget"
    );

    // 5. And the cheap scan, which guards a future where records stop being sealed: the
    //    passphrase appears nowhere in the raw image.
    let (flash, _) = v.into_parts();
    for region in [Region::Records, Region::Ledger] {
        let raw = flash.raw(region);
        assert!(
            !raw.windows(PASSPHRASE.len())
                .any(|w| w == PASSPHRASE.as_bytes()),
            "{region:?} holds the passphrase in the clear"
        );
    }
}

/// The same property across a power cycle: what a remount elects is the record with no
/// passphrase, and the stale side does not come back.
#[test]
fn a_remount_after_forgetting_still_finds_no_passphrase() {
    let cfg = fuzz_config();
    let (mut v, session) = formatted(&cfg);
    let slot = slot(&cfg);

    let remembered = SealedWallet::confirmed(
        LABEL,
        Network::Bitcoin,
        PHRASE,
        CONFIRMED,
        StoredPassphrase::Stored(zeroize::Zeroizing::new(String::from(PASSPHRASE))),
    )
    .unwrap();
    v.write(&session, slot, &remembered.body(4096).unwrap()).unwrap();
    let forgotten = remembered.forgetting();
    v.write(&session, slot, &forgotten.body(4096).unwrap()).unwrap();
    drop(session);

    let (flash, mac) = v.into_parts();
    let mut v = Vault::mount(flash, mac, &cfg).expect("remount");
    let mut scratch = VecScratch::for_params(&cfg.kdf);
    let session = v.unlock(&pin(), scratch.scratch()).expect("unlock");

    assert_eq!(read_back(&mut v, &session, slot).passphrase, StoredPassphrase::Applied);
    let open: Vec<_> = sides_that_open(&mut v, &cfg)
        .into_iter()
        .filter(|(s, _)| *s == slot)
        .collect();
    assert_eq!(open.len(), 1, "a stale side came back across the remount: {open:?}");
}
