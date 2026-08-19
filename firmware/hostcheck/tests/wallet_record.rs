// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! What a save made from the touchscreen puts into a wallet slot.
//!
//! Two properties are the whole point of this file, and until 0.2.0 the firmware had
//! neither. A wallet saved through the panel must come back as a WALLET - the save wrote
//! the user's raw mnemonic bytes into the slot, which `WalletRecord::decode` refuses, so
//! the device could not read back the wallet it had just told the user it had saved. And
//! the identity in the record must be the identity that was ON the panel - the fingerprint
//! the user compared and approved, derived with the passphrase they typed - because a
//! record sealed under the empty-passphrase identity of a passphrased wallet inverts the
//! guarantee the fingerprint field exists for.
//!
//! The vector is the one the hardware run used (docs/clause2-evidence.md), so the numbers
//! asserted here are numbers a device reported and an independent implementation agreed
//! with, rather than numbers this suite computed for itself.

use notyas_core::bitcoin::Network;
use notyas_core::{bip39, derive};
use notyas_firmware_hostcheck::record::{
    RecordError, SealedWallet, WalletRecord, MAX_LABEL_BYTES,
};

/// trezor/python-mnemonic english[0], which is what `tools/psbtgen generate` seeds with.
const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon about";
/// The passphrase that vector is published with, and the one the clause 2 run used.
const PASSPHRASE: &str = "TREZOR";
/// The identity the panel would show for that pair: "Device reported b4e3f5ed for the
/// published vector under passphrase TREZOR. psbtgen derived the same value
/// independently." (docs/clause2-evidence.md).
const CONFIRMED: &str = "b4e3f5ed";
/// The identity the SAME words derive with no passphrase. A different wallet, and the one
/// a save that re-derived instead of storing what it was given would seal.
const WITHOUT_PASSPHRASE: &str = "73c5da0a";

const LABEL: &str = "tz";

/// Any capacity these records fit in. The device passes `Store::max_payload_bytes()`,
/// which is a const over an ESP partition layout and unreachable from a host test; the
/// capacity refusal is exercised against a measured length instead (see below).
const CAPACITY: usize = 1024;

fn confirmed_draft() -> SealedWallet<'static> {
    SealedWallet::confirmed(LABEL, Network::Bitcoin, PHRASE, CONFIRMED, true)
        .expect("the fingerprint the panel rendered parses back")
}

/// Guards every other assertion here: if these two constants were equal, or were not the
/// values the hardware reported, this file would be proving nothing.
#[test]
fn the_published_vector_derives_the_pair_the_hardware_run_reported() {
    let with = derive::master_fingerprint(&bip39::seed(PHRASE, PASSPHRASE), Network::Bitcoin);
    let without = derive::master_fingerprint(&bip39::seed(PHRASE, ""), Network::Bitcoin);
    assert_eq!(with.to_string(), CONFIRMED);
    assert_eq!(without.to_string(), WITHOUT_PASSPHRASE);
    assert_ne!(with, without, "a passphrase makes a different wallet");
}

#[test]
fn a_saved_wallet_is_a_record_the_device_reads_back() {
    let body = confirmed_draft().body(CAPACITY).expect("the record encodes");
    assert_eq!(&body[..4], b"NYW1", "the body must carry the format magic");

    let back = WalletRecord::decode(&body).expect("the slot decodes as a wallet");
    assert_eq!(back.label, LABEL);
    assert_eq!(back.network, Network::Bitcoin);
    assert_eq!(back.phrase.as_str(), PHRASE);
}

#[test]
fn the_record_carries_the_identity_the_panel_confirmed() {
    let back = WalletRecord::decode(&confirmed_draft().body(CAPACITY).unwrap()).unwrap();
    assert_eq!(back.fingerprint.to_string(), CONFIRMED);
    assert_ne!(back.fingerprint.to_string(), WITHOUT_PASSPHRASE);

    // What `Wallet::open` does with the record, run here: the passphrase the user typed
    // reproduces the stored fingerprint and opens the wallet, and the empty one does not.
    let typed = derive::master_fingerprint(&bip39::seed(&back.phrase, PASSPHRASE), back.network);
    assert_eq!(typed, back.fingerprint, "the user's passphrase must open it");
    let empty = derive::master_fingerprint(&bip39::seed(&back.phrase, ""), back.network);
    assert_ne!(empty, back.fingerprint, "and an empty one must not");
}

/// The defect itself, pinned: raw mnemonic bytes in a payload slot are not a wallet, and a
/// device that wrote them has lost the wallet it reported saving.
#[test]
fn the_bare_phrase_is_not_a_wallet_record() {
    assert!(matches!(
        WalletRecord::decode(PHRASE.as_bytes()),
        Err(RecordError::NotThisKind)
    ));
}

#[test]
fn a_fingerprint_that_will_not_parse_refuses_the_save() {
    // Empty, a character short, a character long, not hex, and two of them.
    for text in ["", "b4e3f5e", "b4e3f5ed0", "not hex!", "b4e3f5edb4e3f5ed"] {
        assert!(
            matches!(
                SealedWallet::confirmed(LABEL, Network::Bitcoin, PHRASE, text, true),
                Err(RecordError::UnreadableFingerprint)
            ),
            "{text:?} must not become a wallet identity"
        );
    }
}

#[test]
fn the_phrase_is_normalized_before_it_is_sealed() {
    let words: Vec<&str> = PHRASE.split(' ').collect();
    let messy = format!("  {}\n", words.join("\t \t"));

    let back = WalletRecord::decode(
        &SealedWallet::confirmed(LABEL, Network::Bitcoin, &messy, CONFIRMED, true)
            .unwrap()
            .body(CAPACITY)
            .unwrap(),
    )
    .unwrap();

    // The stored bytes ARE the PBKDF2 password, which is what makes the stored fingerprint
    // checkable at all.
    assert_eq!(back.phrase.as_str(), PHRASE);
    let typed = derive::master_fingerprint(&bip39::seed(&back.phrase, PASSPHRASE), back.network);
    assert_eq!(typed.to_string(), CONFIRMED);
}

#[test]
fn every_network_survives_the_round_trip() {
    for network in [
        Network::Bitcoin,
        Network::Testnet,
        Network::Signet,
        Network::Regtest,
    ] {
        let draft = SealedWallet::confirmed(LABEL, network, PHRASE, CONFIRMED, true).unwrap();
        let back = WalletRecord::decode(&draft.body(CAPACITY).unwrap()).unwrap();
        assert_eq!(back.network, network, "the record names the device's network");
    }
}

#[test]
fn a_record_too_big_for_the_slot_is_refused_rather_than_truncated() {
    let exact = confirmed_draft().body(CAPACITY).unwrap().len();
    assert!(confirmed_draft().body(exact).is_ok());
    assert!(matches!(
        confirmed_draft().body(exact - 1),
        Err(RecordError::TooLarge { bytes, max }) if bytes == exact && max == exact - 1
    ));
}

#[test]
fn a_label_past_the_limit_is_refused() {
    let long = "x".repeat(MAX_LABEL_BYTES + 1);
    let draft = SealedWallet::confirmed(&long, Network::Bitcoin, PHRASE, CONFIRMED, true).unwrap();
    assert!(matches!(
        draft.body(CAPACITY),
        Err(RecordError::LabelTooLong { bytes, max })
            if bytes == MAX_LABEL_BYTES + 1 && max == MAX_LABEL_BYTES
    ));
}

/// A record may not claim an identity its own words do not produce.
///
/// This is the failure the touch-UI save path is one bug away from at all times: the
/// fingerprint is HANDED to the sealer (Q22 keeps the passphrase off the draft), so nothing
/// but this check stands between a wrong fingerprint and a wallet that is refused forever.
/// The refusal reads exactly like a forgotten passphrase, so it would be diagnosed as user
/// error rather than as the storage bug it is.
///
/// The two vectors are the real ones off the bench: the same words derive b4e3f5ed under
/// the passphrase TREZOR and 73c5da0a under none.
#[test]
fn a_record_cannot_claim_an_identity_its_words_do_not_derive() {
    // No passphrase claimed and the bare identity given: derivable, checked, accepted.
    SealedWallet::confirmed(LABEL, Network::Bitcoin, PHRASE, WITHOUT_PASSPHRASE, false)
        .expect("the identity these words derive with no passphrase is sealable");

    // No passphrase claimed but the PASSPHRASE identity given: the check has everything it
    // needs to know this is wrong, and refuses instead of sealing a dead wallet.
    let err = SealedWallet::confirmed(LABEL, Network::Bitcoin, PHRASE, CONFIRMED, false)
        .expect_err("a fingerprint these words cannot derive must be refused");
    assert!(
        matches!(err, RecordError::FingerprintNotFromPhrase),
        "wrong refusal: {err:?}"
    );

    // A passphrase IS claimed, so the difference is explained and the device cannot check
    // it without the passphrase it deliberately never received. Accepted, and that
    // asymmetry is the honest cost of Q22 rather than an oversight.
    SealedWallet::confirmed(LABEL, Network::Bitcoin, PHRASE, CONFIRMED, true)
        .expect("a passphrase wallet's identity cannot be re-derived here");
}
