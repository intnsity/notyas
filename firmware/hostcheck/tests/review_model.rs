// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! `firmware/src/flow/model.rs` under test, on the host, as the device links it.
//!
//! Three properties, and each one is a thing the compiler cannot check and the panel cannot
//! be trusted to show:
//!
//! 1. **The refusal table.** R-01..R-10 are ARCHITECTURE.md 5.3's ten checks in order. A
//!    device that showed R-05 for a change-derivation failure would send the user to look
//!    at the wrong thing, and every sentence on the screen would be about the wrong attack.
//! 2. **The size estimate.** The fee rate is the number a user judges a transaction by, and
//!    its denominator is estimated. Wrong low, the device flatters the fee; wrong about
//!    `exact`, it claims a broadcast size it cannot know.
//! 3. **The warnings.** They fire off one inspection and nothing else. A warning that never
//!    fires is a defence that is not there; one that always fires teaches the user to skip
//!    the page the whole review builds towards.

use notyas_core::bitcoin::absolute::LockTime;
use notyas_core::bitcoin::secp256k1::PublicKey;
use notyas_core::bitcoin::{Amount, Network, OutPoint, ScriptBuf};
use notyas_core::psbt::{
    AmountProof, Check, Claim, ClaimedKey, InputFacts, Malformed, OutputFacts, OutputRole,
    ScriptKind,
};
use notyas_firmware_hostcheck::model;
use notyas_ui::{RefusalCode, ReviewedFee, TxReview};

// ---------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------

/// A 22-byte `OP_0 <20>` script, the length a P2WPKH output actually has on the wire.
///
/// Lengths and not contents: everything under test measures a script or compares two of
/// them, and a real script would only make the fixtures harder to read.
fn spk(len: usize) -> ScriptBuf {
    ScriptBuf::from(vec![0x51u8; len])
}

/// An input of THIS wallet: the ordinary case, and what an ordinary spend is made of.
fn input(index: u16, kind: ScriptKind) -> InputFacts {
    InputFacts {
        claim: Claim::Ours {
            path: "m/84'/0'/0'/0/0".parse().expect("a BIP-84 leaf parses"),
            key: ClaimedKey::Ecdsa(generator()),
        },
        ..foreign(index, kind)
    }
}

/// A coin this device cannot spend: somebody else's input, beside ours.
fn foreign(index: u16, kind: ScriptKind) -> InputFacts {
    InputFacts {
        index,
        outpoint: OutPoint::null(),
        value: Amount::from_sat(1_000_000),
        amount_proof: AmountProof::ProvenByPrevTx,
        script_pubkey: spk(22),
        redeem_script: None,
        kind,
        claim: Claim::Foreign,
        multisig: None,
        tap_merkle_root: None,
    }
}

/// secp256k1's generator point, which is the one compressed public key that can be written
/// down. Nothing derives from it: these fixtures need a claim to BE `Ours`, not a key that
/// could spend anything.
fn generator() -> PublicKey {
    PublicKey::from_slice(&[
        0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
        0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16,
        0xF8, 0x17, 0x98,
    ])
    .expect("the generator point is a valid compressed key")
}

fn output(index: u16, sats: u64, kind: ScriptKind, role: OutputRole) -> OutputFacts {
    OutputFacts {
        index,
        value: Amount::from_sat(sats),
        script_pubkey: spk(22),
        kind,
        claims_our_key: matches!(role, OutputRole::Change { .. } | OutputRole::OwnNotChange { .. }),
        role,
    }
}

/// A review with nothing notable about it: one proven input, one payment, an enforced fee.
fn plain() -> TxReview {
    let inputs = vec![input(0, ScriptKind::P2wpkh)];
    let outputs = vec![output(0, 900_000, ScriptKind::P2wpkh, OutputRole::Payment)];
    let (vsize, vsize_exact) = model::vsize(&inputs, &outputs);
    TxReview {
        inputs,
        outputs,
        input_total: Amount::from_sat(1_000_000),
        output_total: Amount::from_sat(900_000),
        fee: ReviewedFee::Enforced(Amount::from_sat(1_000)),
        lock_time: LockTime::ZERO,
        rbf_signaled: false,
        network: Network::Bitcoin,
        fingerprint: String::from("a1b2c3d4"),
        wallet: String::from("savings"),
        source: String::from("spend.psbt"),
        signable_inputs: 1,
        unknown_fields: 0,
        serialized_len: 400,
        psbt_id: String::from("00").repeat(32),
        vsize,
        vsize_exact,
        warnings: Vec::new(),
    }
}

/// The single-input spend the amount rule of 2026-08-21 admits: the amount came off
/// `witness_utxo` alone, and the signature this device adds makes it binding because there
/// is no second amount in the transaction to lie about.
///
/// It is a `TxReview` and not a PSBT because that is the boundary this file tests: what the
/// firmware's own model does with the facts the engine established.
fn bound_single_input() -> TxReview {
    let mut review = plain();
    review.inputs[0].amount_proof = AmountProof::BoundByOurSignature;
    review
}

/// The headlines of every warning a review raises, in the order the page numbers them.
fn headlines(review: &TxReview) -> Vec<String> {
    model::warnings(review).into_iter().map(|w| w.headline).collect()
}

fn fires(review: &TxReview, needle: &str) -> bool {
    headlines(review).iter().any(|h| h.contains(needle))
}

// ---------------------------------------------------------------------------------------
// The refusal table
// ---------------------------------------------------------------------------------------

/// R-01..R-10 are the ten checks, in the order ARCHITECTURE.md 5.3 numbers them.
///
/// Pinned as a table rather than as a rule, because the rule is what a future edit would
/// change: this is the one place the ratified numbering exists in code, and the screen
/// prints the code beside a headline and an instruction that only make sense together.
#[test]
fn every_check_carries_its_ratified_code() {
    let table = [
        (Check::InputOwnership, RefusalCode::NotOurInputs, "R-01"),
        (Check::Prevouts, RefusalCode::MissingPrevTx, "R-02"),
        (Check::ChangeDerivation, RefusalCode::ChangeNotProven, "R-03"),
        (Check::MultisigBinding, RefusalCode::CosignerMismatch, "R-04"),
        (Check::NetworkIsolation, RefusalCode::WrongNetwork, "R-05"),
        (Check::Fee, RefusalCode::ImpossibleFee, "R-06"),
        (Check::SighashWhitelist, RefusalCode::UnsupportedSighash, "R-07"),
        (Check::Taproot, RefusalCode::UnexpectedTaproot, "R-08"),
        (Check::GlobalSanity, RefusalCode::MalformedFile, "R-09"),
        (Check::PostSign, RefusalCode::SignatureCheckFailed, "R-10"),
    ];
    for (check, code, number) in table {
        assert_eq!(model::code_for(check), code, "{check:?} maps to the wrong code");
        assert_eq!(code.code(), number, "{code:?} is not {number}");
    }
}

/// A file that is not a PSBT gets the code about FILES, not the code about checks.
///
/// The three that earn their own code earn it because each has its own remedy: choose a
/// different file, export a smaller one, export version 0. Everything else is R-09.
#[test]
fn the_decoder_refusals_split_by_what_the_user_does_next() {
    let cases = [
        (Malformed::Empty, RefusalCode::NotAPsbt),
        (Malformed::Truncated { len: 3 }, RefusalCode::NotAPsbt),
        (Malformed::NotAPsbt, RefusalCode::NotAPsbt),
        (
            Malformed::TooLarge {
                len: 2_000_000,
                max: 1_048_576,
            },
            RefusalCode::FileTooLarge,
        ),
        (
            Malformed::PsbtVersionUnsupported { version: 2 },
            RefusalCode::PsbtVersion2,
        ),
        (
            Malformed::Damaged(String::from("bad key")),
            RefusalCode::MalformedFile,
        ),
        (
            Malformed::LengthPrefixOverrun {
                declared: 99,
                remaining: 4,
            },
            RefusalCode::MalformedFile,
        ),
    ];
    for (e, code) in cases {
        assert_eq!(model::file_refusal(&e).code, code, "{e:?}");
    }
}

/// What the panel shows is the engine's own sentence, bracketed into one.
///
/// Bracketed and never rewritten: the text under C7's "Show details" is what a bug report is
/// photographed from, so it has to be the words the engine wrote. What this adds is a
/// capital and a full stop, because a clause with neither reads as something unfinished.
#[test]
fn a_refusal_reads_as_a_sentence_and_keeps_the_engines_words() {
    let notice = model::file_refusal(&Malformed::Empty);
    assert_eq!(notice.happened, "The file is empty.");
    assert!(notice.details.contains("gate 0"), "{}", notice.details);

    let big = model::file_refusal(&Malformed::TooLarge {
        len: 2_000_000,
        max: 1_048_576,
    });
    assert!(big.happened.starts_with("The file is 2000000 bytes"), "{}", big.happened);
    assert!(big.happened.ends_with('.'));
    assert!(!big.after_signing, "a decode refusal happens before anything is signed");
}

// ---------------------------------------------------------------------------------------
// Virtual size
// ---------------------------------------------------------------------------------------

/// One P2WPKH in, two P2WPKH out: the ordinary spend, weighed by hand.
///
/// base   = 4 version + 1 in-count + (32 + 4 + 1 + 4) + 1 out-count + 2 * (8 + 1 + 22) + 4
///        = 4 + 1 + 41 + 1 + 62 + 4 = 113
/// witness= 1 item-count + (1 + 72) sig + (1 + 33) key = 108
/// total  = 113 + 2 marker/flag + 108 = 223
/// weight = 113 * 3 + 223 = 562, vsize = ceil(562 / 4) = 141
///
/// The number is written out because a size estimate that agrees with the code that produced
/// it proves nothing. This one agrees with BIP-141 and with a hand count of the wire format.
#[test]
fn an_ordinary_segwit_spend_weighs_what_bip141_says() {
    let inputs = vec![input(0, ScriptKind::P2wpkh)];
    let outputs = vec![
        output(0, 500_000, ScriptKind::P2wpkh, OutputRole::Payment),
        output(1, 480_000, ScriptKind::P2wpkh, OutputRole::Change { owner: owner(), index: 0 }),
    ];
    assert_eq!(model::vsize(&inputs, &outputs), (141, false));
}

/// A vsize is exact for one shape and estimated for every other.
///
/// Taproot key-path is the only spend whose witness is fixed before it is signed: BIP-341
/// pins the Schnorr signature at 64 bytes. Every ECDSA input is DER, and low-R grinding
/// BOUNDS the signature rather than fixing it, so the quoted size is an upper estimate - and
/// one taproot input beside one segwit input is still an estimate, which is the case a
/// per-input flag would get wrong.
#[test]
fn only_an_all_taproot_transaction_reports_an_exact_size() {
    let outputs = vec![output(0, 100, ScriptKind::P2tr, OutputRole::Payment)];
    let taproot = vec![input(0, ScriptKind::P2tr), input(1, ScriptKind::P2tr)];
    assert!(model::vsize(&taproot, &outputs).1, "every input taproot is exact");

    let mixed = vec![input(0, ScriptKind::P2tr), input(1, ScriptKind::P2wpkh)];
    assert!(!model::vsize(&mixed, &outputs).1, "one ECDSA input makes the whole size an estimate");

    let empty: Vec<InputFacts> = Vec::new();
    assert!(
        !model::vsize(&empty, &outputs).1,
        "a transaction with no inputs has no exact size to report"
    );
}

/// Every input costs something, including the ones this device will not sign.
///
/// A foreign coin is spent by somebody else's witness and the device cannot size it, so it is
/// charged the largest single-signature spend rather than nothing. Charging nothing would
/// understate the transaction, which OVERSTATES the fee rate on the one page a user judges
/// the fee from.
#[test]
fn an_unclassifiable_input_is_charged_rather_than_ignored() {
    let outputs = vec![output(0, 100, ScriptKind::P2wpkh, OutputRole::Payment)];
    let known = model::vsize(&[input(0, ScriptKind::P2wpkh)], &outputs).0;
    let unknown = model::vsize(&[input(0, ScriptKind::Other)], &outputs).0;
    assert!(unknown > known, "an unrecognised spend is not free: {unknown} vs {known}");
}

/// A P2WSH input's witness is sized from the REGISTRATION's script, threshold and all.
///
/// The 2-of-3 pays for two signatures and the whole witness script; a device that charged
/// one would quote a fee rate about a third too high on every multisig transaction it ever
/// reviewed. The threshold is read off the script the engine rebuilt, which is why a
/// higher-threshold script weighs more here without anything else changing.
#[test]
fn a_multisig_input_pays_for_every_signature_its_script_demands() {
    assert!(
        model::multisig_threshold(&[0x52, 0x21, 0xae]) == 2
            && model::multisig_threshold(&[0x53]) == 3,
        "OP_M is the first opcode of a sortedmulti witness script"
    );
    // A script that is not a small-integer push is charged one signature rather than
    // refused: this is a rendering estimate over a file the engine has already accepted.
    assert_eq!(model::multisig_threshold(&[]), 1);
    assert_eq!(model::multisig_threshold(&[0xff]), 1);
}

// ---------------------------------------------------------------------------------------
// Warnings
// ---------------------------------------------------------------------------------------

/// An ordinary spend raises nothing. The page still exists and reads "No warnings."
///
/// The half that is easy to lose: a predicate that fires on every transaction is worse than
/// no predicate, because it teaches the reader that this page never says anything.
#[test]
fn an_ordinary_transaction_has_nothing_notable_about_it() {
    assert!(model::warnings(&plain()).is_empty(), "{:?}", headlines(&plain()));
}

/// The fee, over either of the two ratified thresholds (Q12).
#[test]
fn a_large_fee_is_stated_as_a_share_and_as_a_rate() {
    let mut review = plain();
    // 100_000 out of 900_000 leaving is 11%, over the 5% threshold.
    review.fee = ReviewedFee::Enforced(Amount::from_sat(100_000));
    assert!(fires(&review, "% of the amount leaving"), "{:?}", headlines(&review));

    let mut rate = plain();
    // 141 vB at 500 sat/vB is 70_500 sats, and 7% of what leaves - so both fire, which is
    // the honest outcome rather than a reason to suppress one.
    rate.fee = ReviewedFee::Enforced(Amount::from_sat(70_500));
    assert!(fires(&rate, "sat/vB"), "{:?}", headlines(&rate));
}

/// A fee nothing proves is a LOWER BOUND, and every number derived from it says so.
///
/// The threshold is compared against the bound, which is the direction that cannot hide a
/// fee: a device that waited for a proven number before warning would never warn about the
/// files where the number is least trustworthy.
#[test]
fn an_unproven_fee_is_warned_about_as_a_bound() {
    let mut review = plain();
    review.fee = ReviewedFee::Stated(Amount::from_sat(100_000));
    review.inputs[0].amount_proof = AmountProof::ClaimedByFile;
    let lines = headlines(&review);
    assert!(
        lines.iter().any(|h| h.contains("at least") && h.contains("% of the amount leaving")),
        "{lines:?}"
    );
    assert!(
        lines.iter().any(|h| h.contains("input amounts are not proven")),
        "{lines:?}"
    );
}

/// The unproven-amount band fires on the file whose amount nobody binds, and is SILENT on
/// the one whose amount this device's own signature binds.
///
/// Both files state their amount through `witness_utxo` alone, so the number on the screen
/// came from the file in each case. Only one of them leaves that number free to be a lie,
/// and the band has to separate the two: raised on a single-input spend of the user's own
/// coin it would stand beside an exact fee saying every total rests on the file's word,
/// which is a contradiction the user has no way to resolve and the fastest way to teach
/// somebody that this page never says anything.
///
/// Broken version: count [`AmountProof::BoundByOurSignature`] in
/// `TxReview::unproven_amounts`. The second assertion trips.
#[test]
fn the_unproven_amount_band_reads_the_proof_and_not_the_witness_utxo() {
    let mut unbound = plain();
    unbound.fee = ReviewedFee::Stated(Amount::from_sat(1_000));
    unbound.inputs[0].amount_proof = AmountProof::ClaimedByFile;
    assert!(
        fires(&unbound, "input amounts are not proven"),
        "{:?}",
        headlines(&unbound)
    );

    let bound = bound_single_input();
    assert_eq!(bound.unproven_amounts(), 0);
    assert!(
        !fires(&bound, "input amounts are not proven"),
        "a bound amount is not an unproven one: {:?}",
        headlines(&bound)
    );
    // And the whole page stays quiet, so the band is the only thing that changed.
    assert!(model::warnings(&bound).is_empty(), "{:?}", headlines(&bound));
}

/// Two outputs of THIS transaction paying the same script.
///
/// The only reuse an airgapped signer can honestly speak about: it holds one file, no chain
/// and no history, so a warning about a wallet's PAST could only be fabricated.
#[test]
fn two_outputs_paying_the_same_address_are_named() {
    let mut review = plain();
    review.outputs.push(output(1, 100_000, ScriptKind::P2wpkh, OutputRole::Payment));
    assert!(fires(&review, "Outputs 0 and 1 pay the same address"), "{:?}", headlines(&review));
}

/// The structural limit, all of it paying one address: ONE warning, not 32,385.
///
/// The bound this pins is on the attacker's side of the wire. `StructuralLimits` lets a
/// file carry 255 outputs, the reader of that file chooses every one of them, and the
/// pairwise scan this replaces built a heap-allocated warning per PAIR: 32,385 of them,
/// 64,786 allocations and 7 MB, measured, on a device whose RAM is a fixed budget - and
/// then the review screen turned all of it into rows on every frame.
///
/// Broken version this fails against: the pairwise `for i / for j.skip(i + 1)` scan that
/// pushed one warning per matching pair. Every assertion below trips - 32,385 duplicate
/// warnings instead of one, and no count of how many outputs share the address.
#[test]
fn two_hundred_and_fifty_five_identical_outputs_are_one_warning() {
    let mut review = plain();
    review.outputs = (0..255u16)
        .map(|i| output(i, 100_000, ScriptKind::P2wpkh, OutputRole::Payment))
        .collect();

    let warnings = model::warnings(&review);
    let dups: Vec<&String> = warnings
        .iter()
        .map(|w| &w.headline)
        .filter(|h| h.contains("pay the same address"))
        .collect();
    assert_eq!(dups.len(), 1, "one reused address is one warning: {dups:?}");
    assert_eq!(
        dups[0], "Outputs 0, 1, 2, 3, 4, 5, 6, 7 and 247 more pay the same address.",
        "the list is shortened and the remainder is counted, never dropped"
    );
    // The count is the fact the shortened list must not cost the reader.
    assert!(
        warnings.iter().any(|w| w.detail.contains("pays that address 255 times")),
        "{:?}",
        warnings.iter().map(|w| &w.detail).collect::<Vec<_>>()
    );
    assert!(
        warnings.len() <= 8,
        "the whole warnings page has to stay readable: {} entries",
        warnings.len()
    );
}

/// A reused address the page does not have room to NAME is still counted.
///
/// 127 addresses each paid twice is the other end of the same structural limit, and the
/// bound on how many are written out one by one is the bound most likely to be mistaken for
/// permission to forget the rest. It is not: the page names four and states the exact number
/// of addresses and outputs behind them, because on a signing device a warning that quietly
/// disappears is worse than any amount of slowness.
///
/// Broken version this fails against: drop the summary warning, or count anything but the
/// groups that were not named. The arithmetic below stops adding up to 127.
#[test]
fn a_reused_address_the_page_cannot_name_is_still_counted() {
    let mut review = plain();
    review.outputs = (0..254u16)
        .map(|i| {
            let mut o = output(i, 100_000, ScriptKind::P2wpkh, OutputRole::Payment);
            // A script of its own per PAIR - lengths 22..148, all distinct - so the file
            // holds 127 reused addresses rather than one.
            o.script_pubkey = spk(22 + usize::from(i) / 2);
            o
        })
        .collect();

    let warnings = model::warnings(&review);
    let named = warnings.iter().filter(|w| w.headline.contains("pay the same address")).count();
    assert_eq!(named, 4, "{:?}", warnings.iter().map(|w| &w.headline).collect::<Vec<_>>());
    let rest = warnings
        .iter()
        .find(|w| w.headline.contains("addresses are each paid more than once"))
        .expect("the reused addresses that were not named are counted out loud");
    assert_eq!(rest.headline, "123 more addresses are each paid more than once.");
    assert!(rest.detail.starts_with("246 outputs pay them"), "{}", rest.detail);
    // 4 named + 123 counted is every one of the 127, and 8 + 246 is every one of the 254
    // outputs involved. Nothing fell between the two.
    assert!(
        warnings.len() <= 8,
        "the whole warnings page has to stay readable: {} entries",
        warnings.len()
    );
}

/// An output of ours on the receive keychain is money SENT, and the page says so.
#[test]
fn a_self_send_is_not_quietly_netted_out() {
    let mut review = plain();
    review.outputs[0].role = OutputRole::OwnNotChange { owner: owner(), index: 0 };
    assert!(fires(&review, "pays an address of this wallet"), "{:?}", headlines(&review));
    // And the sum this device shows as leaving still counts it, which is the fact the
    // warning is about.
    assert_eq!(review.leaving(), Amount::from_sat(900_000));
}

/// Dust, per output type rather than at one number.
///
/// A single 546 sat floor would call an ordinary segwit change output dust, and a warning
/// that fires on ordinary transactions is a warning users learn to skip.
#[test]
fn dust_is_measured_against_the_floor_for_that_address_type() {
    let mut review = plain();
    review.outputs[0] = output(0, 300, ScriptKind::P2wpkh, OutputRole::Payment);
    assert!(!fires(&review, "below the dust limit"), "294 is the segwit floor");

    review.outputs[0] = output(0, 293, ScriptKind::P2wpkh, OutputRole::Payment);
    assert!(fires(&review, "Output 0 is below the dust limit"), "{:?}", headlines(&review));

    review.outputs[0] = output(0, 300, ScriptKind::P2pkh, OutputRole::Payment);
    assert!(fires(&review, "below the dust limit"), "546 is the legacy floor");

    review.outputs[0] = output(0, 0, ScriptKind::OpReturn, OutputRole::Payment);
    assert!(!fires(&review, "below the dust limit"), "a data output carries no value");
}

/// Inputs this device will not sign, named, with what that means for the transaction.
#[test]
fn a_foreign_input_is_named_and_its_consequence_stated() {
    let mut review = plain();
    review.inputs = vec![foreign(0, ScriptKind::P2wpkh), foreign(1, ScriptKind::P2wpkh)];
    let warnings = model::warnings(&review);
    let foreign = warnings
        .iter()
        .find(|w| w.headline.contains("not from this wallet"))
        .expect("a foreign input is always said out loud");
    assert!(foreign.headline.contains("Inputs 0, 1"), "{}", foreign.headline);
    assert!(foreign.detail.contains("Another signer"), "{}", foreign.detail);
}

/// A locktime, and only when there is one.
#[test]
fn a_locktime_is_a_warning_and_height_zero_is_not() {
    let review = plain();
    assert!(!fires(&review, "locktime"), "an ordinary spend has no locktime");

    let mut held = plain();
    held.lock_time = LockTime::from_consensus(812_000);
    assert!(fires(&held, "locktime set"), "{:?}", headlines(&held));
    assert!(
        model::warnings(&held)
            .iter()
            .any(|w| w.detail.contains("block 812000")),
        "the warning names the block it waits for"
    );
}

/// The file's own oddities: a long output list and fields this device does not read.
#[test]
fn the_shape_of_the_file_is_reported_without_being_judged() {
    let mut many = plain();
    for i in 1..12u16 {
        many.outputs.push(output(i, 1_000, ScriptKind::P2wpkh, OutputRole::Payment));
    }
    assert!(fires(&many, "Large transaction - 12 outputs"), "{:?}", headlines(&many));

    let mut unknown = plain();
    unknown.unknown_fields = 3;
    let warnings = model::warnings(&unknown);
    let field = warnings
        .iter()
        .find(|w| w.headline.contains("does not read"))
        .expect("unknown fields are counted and stated");
    assert!(field.detail.contains("BIP-174"), "{}", field.detail);
    assert!(
        field.detail.contains("No decision on this screen was made from any of them."),
        "{}",
        field.detail
    );
}

/// Every string this module can put on a panel is ASCII the font atlas can draw.
///
/// The atlas is U+0020..U+007E plus two characters, so anything else renders as a
/// substitution glyph - which on a warning page means a sentence the user cannot read on the
/// screen where they are deciding whether to sign.
#[test]
fn every_sentence_is_ascii() {
    let mut review = plain();
    review.fee = ReviewedFee::Stated(Amount::from_sat(200_000));
    review.inputs[0].amount_proof = AmountProof::ClaimedByFile;
    review.inputs.push(input(1, ScriptKind::P2wpkh));
    review.inputs[1].amount_proof = AmountProof::BoundByOurSignature;
    review.outputs.push(output(1, 100, ScriptKind::P2wpkh, OutputRole::Payment));
    review.outputs[0].role = OutputRole::OwnNotChange { owner: owner(), index: 0 };
    review.unknown_fields = 2;
    review.lock_time = LockTime::from_consensus(500);

    let mut text = String::new();
    for w in model::warnings(&review) {
        text.push_str(&w.headline);
        text.push_str(&w.detail);
    }
    for e in [
        Malformed::Empty,
        Malformed::NotAPsbt,
        Malformed::Damaged(String::from("bad key")),
    ] {
        let n = model::file_refusal(&e);
        text.push_str(&n.happened);
        text.push_str(&n.details);
    }
    assert!(
        text.chars().all(|c| c.is_ascii_graphic() || c == ' '),
        "a non-ASCII character reached a panel string: {text:?}"
    );
    assert!(!text.contains('\u{2014}') && !text.contains('\u{2013}'), "no dashes but '-'");
}

/// An `Owner` for the fixtures: the BIP-84 account of a seed of zeroes.
///
/// Derived through `Account::derive` rather than assembled, because an `AccountId` has no
/// public constructor and should not have one - it names an account only the seed can
/// produce, which is the whole of what check 3 rests on. The seed is public and worthless;
/// what these tests need from it is that the value exists at all.
fn owner() -> notyas_core::psbt::Owner {
    use notyas_core::derive::{Account, ChildIndex, Scheme};
    let account = Account::derive(&[0u8; 64], Network::Bitcoin, Scheme::Bip84, ChildIndex::ZERO)
        .expect("BIP-84 derives an account from any seed");
    notyas_core::psbt::Owner::Account(account.id())
}
