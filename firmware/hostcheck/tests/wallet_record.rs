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
    RecordError, SealedWallet, StoredPassphrase, WalletRecord, FLAG_PASSPHRASE_APPLIED,
    FLAG_PASSPHRASE_STORED, MAX_LABEL_BYTES, MAX_PASSPHRASE_BYTES,
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

/// The same wallet with the passphrase stored on it, which is what the storage opt-in
/// seals. Built through `confirmed`, like every other record: that is where the check
/// lives that a stored passphrase actually opens the identity it is stored against.
fn remembered_draft() -> SealedWallet<'static> {
    SealedWallet::confirmed(
        LABEL,
        Network::Bitcoin,
        PHRASE,
        CONFIRMED,
        StoredPassphrase::Stored(zeroize::Zeroizing::new(String::from(PASSPHRASE))),
    )
    .expect("the stored passphrase derives the identity it claims")
}

fn confirmed_draft() -> SealedWallet<'static> {
    SealedWallet::confirmed(LABEL, Network::Bitcoin, PHRASE, CONFIRMED, StoredPassphrase::Applied)
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
    assert_eq!(&body[..4], b"NYW2", "the body must carry the format magic");

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
                SealedWallet::confirmed(LABEL, Network::Bitcoin, PHRASE, text, StoredPassphrase::Applied),
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
        &SealedWallet::confirmed(LABEL, Network::Bitcoin, &messy, CONFIRMED, StoredPassphrase::Applied)
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
        let draft = SealedWallet::confirmed(LABEL, network, PHRASE, CONFIRMED, StoredPassphrase::Applied).unwrap();
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
    let draft = SealedWallet::confirmed(&long, Network::Bitcoin, PHRASE, CONFIRMED, StoredPassphrase::Applied).unwrap();
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
    SealedWallet::confirmed(LABEL, Network::Bitcoin, PHRASE, WITHOUT_PASSPHRASE, StoredPassphrase::None)
        .expect("the identity these words derive with no passphrase is sealable");

    // No passphrase claimed but the PASSPHRASE identity given: the check has everything it
    // needs to know this is wrong, and refuses instead of sealing a dead wallet.
    let err = SealedWallet::confirmed(LABEL, Network::Bitcoin, PHRASE, CONFIRMED, StoredPassphrase::None)
        .expect_err("a fingerprint these words cannot derive must be refused");
    assert!(
        matches!(err, RecordError::FingerprintNotFromPhrase),
        "wrong refusal: {err:?}"
    );

    // A passphrase IS claimed, so the difference is explained and the device cannot check
    // it without the passphrase it deliberately never received. Accepted, and that
    // asymmetry is the honest cost of Q22 rather than an oversight.
    SealedWallet::confirmed(LABEL, Network::Bitcoin, PHRASE, CONFIRMED, StoredPassphrase::Applied)
        .expect("a passphrase wallet's identity cannot be re-derived here");
}


// ---------------------------------------------------------------------------------------
// Format 2: the flags byte, the stored passphrase, and the format 1 records already on
// devices (Q22 amendment, 2026-08-19)
// ---------------------------------------------------------------------------------------

/// A format 1 body, built by hand, so that "the reader still accepts NYW1" is proven
/// against the bytes the old encoder wrote rather than against today's encoder with a
/// different magic pasted on.
///
/// The layout is the frozen one: magic, network code, reserved zero, fingerprint, two
/// little-endian lengths, label, phrase.
fn nyw1_body(label: &str, network: u8, fingerprint: &str, phrase: &str) -> Vec<u8> {
    let fp = u32::from_str_radix(fingerprint, 16).expect("eight hex characters");
    let mut out = Vec::new();
    out.extend_from_slice(b"NYW1");
    out.push(network);
    out.push(0); // reserved
    out.extend_from_slice(&fp.to_be_bytes());
    out.extend_from_slice(&(label.len() as u16).to_le_bytes());
    out.extend_from_slice(&(phrase.len() as u16).to_le_bytes());
    out.extend_from_slice(label.as_bytes());
    out.extend_from_slice(phrase.as_bytes());
    out
}

/// The owner's own wallet, in the format his device wrote it in: a passphrase wallet whose
/// record predates the flag that would say so.
///
/// It must still decode - refusing it would make the wallet in that slot unopenable, which
/// is the failure a format bump exists to avoid rather than to cause - and it must decode
/// as `None`, because a format 1 record makes no statement about a passphrase at all. What
/// turns that into the right behaviour is the open path, which tries the empty passphrase,
/// finds the mismatch, and asks (never showing what the words derive without one).
#[test]
fn a_format_1_record_still_opens_and_says_nothing_about_a_passphrase() {
    let body = nyw1_body(LABEL, 0, CONFIRMED, PHRASE);
    let back = WalletRecord::decode(&body).expect("a format 1 record still decodes");
    assert_eq!(back.label, LABEL);
    assert_eq!(back.network, Network::Bitcoin);
    assert_eq!(back.phrase.as_str(), PHRASE);
    assert_eq!(back.fingerprint.to_string(), CONFIRMED);
    assert_eq!(back.passphrase, StoredPassphrase::None);
    assert!(!back.passphrase.applied());
    assert_eq!(back.passphrase.stored(), None);

    // And the thing that makes it openable: the words plus the passphrase reproduce the
    // stored fingerprint, so the prompt path has something to check an answer against.
    let typed = derive::master_fingerprint(&bip39::seed(&back.phrase, PASSPHRASE), back.network);
    assert_eq!(typed, back.fingerprint);
}

/// Format 1 kept byte 5 as a reserved zero and refused anything else. Format 2 spends that
/// byte, so the old refusal has to survive for old records: a format 1 body with a flag set
/// is a body from somewhere else.
#[test]
fn a_format_1_record_with_a_flag_set_is_still_refused() {
    let mut body = nyw1_body(LABEL, 0, CONFIRMED, PHRASE);
    body[5] = FLAG_PASSPHRASE_APPLIED;
    assert!(matches!(
        WalletRecord::decode(&body),
        Err(RecordError::ReservedNotZero)
    ));
}

#[test]
fn the_three_passphrase_states_survive_the_round_trip() {
    for (state, flags) in [
        (StoredPassphrase::None, 0u8),
        (StoredPassphrase::Applied, FLAG_PASSPHRASE_APPLIED),
        (
            StoredPassphrase::Stored(zeroize::Zeroizing::new(String::from(PASSPHRASE))),
            FLAG_PASSPHRASE_APPLIED | FLAG_PASSPHRASE_STORED,
        ),
    ] {
        let fingerprint = if state.applied() { CONFIRMED } else { WITHOUT_PASSPHRASE };
        let draft =
            SealedWallet::confirmed(LABEL, Network::Bitcoin, PHRASE, fingerprint, state.clone())
                .expect("the identity is the one these words derive");
        let body = draft.body(CAPACITY).expect("the record encodes");
        assert_eq!(&body[..4], b"NYW2", "every write is format 2");
        assert_eq!(body[5], flags, "the flags byte states the passphrase state");

        let back = WalletRecord::decode(&body).expect("it decodes");
        assert_eq!(back.passphrase, state);
        assert_eq!(back.passphrase.stored(), state.stored());
        // The stored passphrase is present exactly when bit 1 is set, and it is the one
        // that opens this wallet.
        if let Some(stored) = back.passphrase.stored() {
            let seed = bip39::seed(&back.phrase, stored);
            assert_eq!(
                derive::master_fingerprint(&seed, back.network),
                back.fingerprint,
                "a stored passphrase that does not open its own record is worse than none"
            );
        }
    }
}

/// A stored passphrase is proven at seal time. The device HAS the passphrase in that case,
/// so there is no excuse for writing a record it cannot open - and the one wallet whose
/// identity cannot be checked here is the one where the passphrase was deliberately not
/// kept.
#[test]
fn a_stored_passphrase_that_does_not_derive_the_identity_is_refused() {
    let wrong = StoredPassphrase::Stored(zeroize::Zeroizing::new(String::from("not it")));
    let err = SealedWallet::confirmed(LABEL, Network::Bitcoin, PHRASE, CONFIRMED, wrong)
        .expect_err("a stored passphrase is checked against the identity it claims");
    assert!(
        matches!(err, RecordError::FingerprintNotFromPhrase),
        "wrong refusal: {err:?}"
    );
}

/// Turning storage OFF destroys the passphrase, in the bytes the device seals.
///
/// This is the record half of the guarantee: the body that gets written carries no
/// passphrase, anywhere in it, and still says the wallet HAS one - dropping to "no
/// passphrase" would make the next open try an empty one and report a mismatch about a
/// wallet that never changed. The flash half - that no earlier body survives beside it -
/// is `passphrase_forget.rs`.
#[test]
fn forgetting_the_passphrase_writes_a_body_that_does_not_contain_it() {
    let remembered = remembered_draft();
    let with = remembered.body(CAPACITY).expect("the record encodes");
    assert!(
        with.windows(PASSPHRASE.len()).any(|w| w == PASSPHRASE.as_bytes()),
        "the test is meaningless unless the stored body really does carry the passphrase"
    );

    let without = confirmed_draft()
        .remembering(PASSPHRASE)
        .expect("the stored passphrase derives the identity it claims")
        .forgetting()
        .body(CAPACITY)
        .expect("the record encodes");
    assert!(
        !without.windows(PASSPHRASE.len()).any(|w| w == PASSPHRASE.as_bytes()),
        "the passphrase is still in the body a forget writes"
    );

    let back = WalletRecord::decode(&without).expect("it decodes");
    assert_eq!(back.passphrase, StoredPassphrase::Applied);
    assert_eq!(back.passphrase.stored(), None);
    assert!(
        back.passphrase.applied(),
        "forgetting the passphrase must not claim the wallet no longer has one"
    );
}

/// The tail is exactly as long as the field says. A record is its declared contents, and a
/// reader that skipped a byte is a reader that can be fed one.
#[test]
fn a_trailing_byte_is_still_refused_with_a_stored_passphrase() {
    let mut body = confirmed_draft()
        .remembering(PASSPHRASE)
        .expect("the stored passphrase derives the identity it claims")
        .body(CAPACITY)
        .unwrap()
        .to_vec();
    body.push(0);
    assert!(matches!(
        WalletRecord::decode(&body),
        Err(RecordError::TrailingBytes { extra: 1 })
    ));
}

/// A flag this build does not implement is a record written by a firmware that knows
/// something this one does not. Refused, on the format 1 rule.
#[test]
fn an_unknown_flag_bit_is_refused() {
    for bit in 2..8u8 {
        let mut body = confirmed_draft().body(CAPACITY).unwrap().to_vec();
        body[5] |= 1 << bit;
        assert!(
            matches!(WalletRecord::decode(&body), Err(RecordError::ReservedNotZero)),
            "bit {bit} must not be readable as a feature"
        );
    }
}

/// Stored-without-applied is not a wallet anything could open. The enum makes it
/// unrepresentable in memory; this is the flash side of the same rule.
#[test]
fn a_stored_flag_without_the_applied_flag_is_refused() {
    let mut body = confirmed_draft()
        .remembering(PASSPHRASE)
        .expect("the stored passphrase derives the identity it claims")
        .body(CAPACITY)
        .unwrap()
        .to_vec();
    body[5] = FLAG_PASSPHRASE_STORED;
    assert!(matches!(
        WalletRecord::decode(&body),
        Err(RecordError::FlagsInconsistent { .. })
    ));
}

/// The one bound this format puts on a passphrase, and the screen that types one keeps the
/// same number. Two constants that must be equal is a drift waiting to happen, so it is
/// asserted rather than commented.
#[test]
fn the_stored_passphrase_cap_is_the_one_the_entry_screen_enforces() {
    assert_eq!(MAX_PASSPHRASE_BYTES, notyas_ui::PASS_MAX);

    let long = "x".repeat(MAX_PASSPHRASE_BYTES + 1);
    let draft = SealedWallet {
        label: LABEL,
        network: Network::Bitcoin,
        phrase: PHRASE,
        fingerprint: confirmed_draft().fingerprint,
        passphrase: StoredPassphrase::Stored(zeroize::Zeroizing::new(long)),
    };
    assert!(matches!(
        draft.body(CAPACITY),
        Err(RecordError::PassphraseTooLong { bytes, max })
            if bytes == MAX_PASSPHRASE_BYTES + 1 && max == MAX_PASSPHRASE_BYTES
    ));
}

/// The whole of what a slot has to hold at once: the longest label, the longest passphrase
/// and a 24-word phrase. Measured rather than assumed, because the number that decides
/// whether some passphrases cannot be stored is this one.
#[test]
fn the_largest_record_this_format_can_produce_is_measured() {
    let phrase = ["abandon"; 24].join(" ");
    let label = "x".repeat(MAX_LABEL_BYTES);
    let draft = SealedWallet {
        label: &label,
        network: Network::Bitcoin,
        phrase: &phrase,
        fingerprint: confirmed_draft().fingerprint,
        passphrase: StoredPassphrase::Stored(zeroize::Zeroizing::new(
            "x".repeat(MAX_PASSPHRASE_BYTES),
        )),
    };
    let len = draft.body(CAPACITY).expect("it fits a 1 KiB slot").len();
    // 14 header + 64 label + 24 words + 2 length prefix + 256 passphrase.
    assert_eq!(len, 14 + MAX_LABEL_BYTES + phrase.len() + 2 + MAX_PASSPHRASE_BYTES);
    // The measurement, written down: 527 bytes. A payload slot on the shipped layout is
    // one 4096-byte sector a side, less the 80-byte record header, the 16-byte AEAD tag
    // and the 4-byte length prefix, i.e. 3996 - so every passphrase this device can type
    // fits with room to spare. That is the question this test exists to answer before the
    // format is frozen; the encoder still refuses safely if a future layout shrinks.
    assert_eq!(len, 527, "the largest wallet record has changed size");
    assert!(len <= 3996, "the largest wallet record no longer fits a payload slot");
}

/// A capacity refusal happens BEFORE anything is written, and it names the passphrase-sized
/// difference rather than reporting a storage error.
#[test]
fn a_stored_passphrase_that_does_not_fit_is_refused_before_the_write() {
    let plain = confirmed_draft().body(CAPACITY).unwrap().len();
    let draft = remembered_draft();
    assert!(matches!(
        draft.body(plain),
        Err(RecordError::TooLarge { bytes, max })
            if bytes == plain + 2 + PASSPHRASE.len() && max == plain
    ));
}
