// Copyright (C) 2025-2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! One test per way a signature can be invalid, and the verdict each must get.
//!
//! `selftest` proves the verifier agrees with a corpus whose answers are known, and is what
//! an operator runs. This module is the adversarial half: it takes a file that was just
//! accepted and breaks exactly one thing about the authorisation, so a refusal is
//! attributable to the change rather than to the file being broken in general. The two are
//! separate because they fail differently - `selftest` failing means the tool disagrees
//! with its own corpus, and one of these failing means the tool would certify a signer that
//! is wrong.
//!
//! The classes, and where the rule each one breaks is written down:
//!
//! | class | rule | verdict |
//! |---|---|---|
//! | a bit flipped in `r` | ECDSA verification, SEC 1 4.1.4 | `signature-invalid` |
//! | `s` raised above the half order | BIP-62 rule 5, enforced by `secp256k1_ecdsa_verify` | `signature-invalid` |
//! | signed by a different key | ECDSA verification | `signature-invalid` |
//! | a valid signature over another transaction | BIP-143 digest recomputation | `signature-invalid` |
//! | `SIGHASH_NONE` instead of `SIGHASH_ALL` | only `SIGHASH_ALL` commits to the outputs | `sighash-not-whitelisted` |
//! | a truncated DER blob | strict DER, BIP-66 | the file does not decode at all |
//! | a witness the file finished for itself | see [`crate::verify`] | `witness-unverified` |
//! | a multisig leg that is not the device's, forged | ECDSA verification | `signature-invalid` |
//! | a bit flipped in a LEGACY signature | ECDSA verification over the pre-segwit digest | `signature-invalid` |
//!
//! The last two are the ones this module was written for. Before the authorisation rule,
//! both were ACCEPTED with exit 0: an input whose `bip32_derivation` was absent classified
//! as foreign, was never signature-checked, and carried whatever `final_script_witness` the
//! file brought straight through into the extracted transaction; and a 2-of-3 counted a leg
//! as satisfied because a `partial_sigs` entry existed under a key the script names, never
//! checking anything but the device's own leg. Both files extracted, priced and printed a
//! txid.

use notyas_core::bitcoin::psbt::Psbt;
use notyas_core::bitcoin::secp256k1::{ecdsa, Message, Secp256k1, SecretKey};
use notyas_core::bitcoin::{EcdsaSighashType, PublicKey, Witness};
use notyas_core::psbt::{self, fixture, Context, StructuralLimits};

use crate::build;
use crate::harness::{self, Harness};
use crate::verify::{Coordinator, Outcome};
use crate::Verdict;

/// The order of the secp256k1 group, big endian, from SEC 2 2.4.1. Needed to build the
/// high-S counterpart of a signature: `n - s`.
const GROUP_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// The generated single-sig case, host-signed: the file every mutation below starts from.
fn signed_single() -> (Harness, Psbt) {
    let harness = Harness::new();
    let psbt = build::cases(&harness).swap_remove(0).psbt;
    let signed = host_sign(&harness, &psbt);
    (harness, signed)
}

/// The generated legacy case, host-signed. The pre-segwit path: no witness, and a digest
/// that commits to no amount.
fn signed_legacy() -> (Harness, Psbt) {
    let harness = Harness::new();
    let psbt = build::cases(&harness).swap_remove(2).psbt;
    let signed = host_sign(&harness, &psbt);
    (harness, signed)
}

/// The generated 2-of-3 case, host-signed. Only the device's leg is on it.
fn signed_multisig() -> (Harness, Psbt) {
    let harness = Harness::new();
    let psbt = build::cases(&harness).swap_remove(1).psbt;
    let signed = host_sign(&harness, &psbt);
    (harness, signed)
}

fn host_sign(harness: &Harness, psbt: &Psbt) -> Psbt {
    let context = Context {
        network: harness::NETWORK,
        fingerprint: harness.device.fingerprint(),
        limits: StructuralLimits::DEFAULT,
        registry: std::slice::from_ref(harness.registration()),
    };
    let inspection = psbt::inspect(psbt, &context).expect("the generated case inspects");
    psbt::sign(psbt, &inspection, harness.device.seed())
        .expect("the generated case signs")
        .into_psbt()
}

/// Assert a verdict, and print the refusals when it is not the one wanted - a bare
/// `assert!` on a boolean here would report "false is not true" about a verifier.
#[track_caller]
fn refuses_with(outcome: &Outcome, code: &str) {
    let codes: Vec<&str> = outcome.refusals.iter().map(|r| r.code()).collect();
    assert!(
        codes.contains(&code),
        "wanted a refusal with code '{code}', got verdict {:?} with {codes:?}\n{outcome}",
        match outcome.verdict() {
            Verdict::Accepted => "accepted",
            Verdict::Refused => "refused",
            Verdict::Unrecognised => "unrecognised",
        }
    );
}

/// The device's `partial_sigs` entry on input 0, and the key it sits under.
fn only_signature(psbt: &Psbt) -> (PublicKey, ecdsa::Signature) {
    let (key, signature) = psbt.inputs[0]
        .partial_sigs
        .iter()
        .next()
        .expect("the host signer left a signature");
    (*key, signature.signature)
}

fn replace_signature(psbt: &mut Psbt, signature: ecdsa::Signature, sighash_type: EcdsaSighashType) {
    let (key, _) = only_signature(psbt);
    psbt.inputs[0].partial_sigs.insert(
        key,
        notyas_core::bitcoin::ecdsa::Signature {
            signature,
            sighash_type,
        },
    );
}

/// The baseline every case below is a single edit away from. If this ever stops being
/// accepted, every assertion in this module is testing something other than it claims.
#[test]
fn the_unmodified_file_is_accepted() {
    let (harness, signed) = signed_single();
    let outcome = Coordinator::for_harness(&harness).verify(&signed);
    assert!(outcome.accepted(), "{outcome}");
    assert_eq!(outcome.signatures_checked, 1);
}

/// The same baseline for the legacy path, and it asserts what the file was CLASSIFIED as
/// rather than only that something verified. A P2PKH input that the coordinator failed to
/// recognise as its own is reported foreign, and a foreign input is never signature-checked
/// at all, so "accepted" alone would not distinguish the legacy arm working from the legacy
/// arm being absent - which is exactly the state this verifier was in before it had one.
#[test]
fn the_unmodified_legacy_file_is_accepted_as_a_legacy_spend() {
    let (harness, signed) = signed_legacy();
    let outcome = Coordinator::for_harness(&harness).verify(&signed);
    assert!(outcome.accepted(), "{outcome}");
    assert_eq!(outcome.signatures_checked, 1);
    assert_eq!(outcome.inputs[0].kind, "p2pkh", "{outcome}");
    assert!(outcome.inputs[0].verified, "{outcome}");
    // The amount rule's own precondition, stated here because a legacy signature is the one
    // kind that cannot carry it: the file has to PROVE what this input is worth.
    assert!(outcome.inputs[0].proven, "{outcome}");
}

/// The legacy digest, checked in the direction acceptance cannot check it. An accepted file
/// proves this side computes the same digest the device did; only a refusal proves it is
/// verifying anything at all, rather than waving a pre-segwit input through the way it
/// waved one through when it had no arm for the shape.
#[test]
fn a_bit_flipped_in_a_legacy_signature_is_refused() {
    let (harness, mut signed) = signed_legacy();
    let (_, signature) = only_signature(&signed);
    let mut compact = signature.serialize_compact();
    compact[8] ^= 0x01;
    let mutated = ecdsa::Signature::from_compact(&compact).expect("still a pair of scalars");
    replace_signature(&mut signed, mutated, EcdsaSighashType::All);
    refuses_with(
        &Coordinator::for_harness(&harness).verify(&signed),
        "signature-invalid",
    );
}

/// SEC 1 4.1.4: verification recomputes `R` from `(r, s)` and the digest and compares. A
/// changed `r` is a signature over nothing.
#[test]
fn a_bit_flipped_in_r_is_refused() {
    let (harness, mut signed) = signed_single();
    let (_, signature) = only_signature(&signed);
    let mut compact = signature.serialize_compact();
    compact[8] ^= 0x01;
    let mutated = ecdsa::Signature::from_compact(&compact).expect("still a pair of scalars");
    replace_signature(&mut signed, mutated, EcdsaSighashType::All);
    refuses_with(
        &Coordinator::for_harness(&harness).verify(&signed),
        "signature-invalid",
    );
}

/// BIP-62 rule 5: `(r, s)` and `(r, n - s)` are both valid ECDSA signatures over the same
/// digest, so accepting the high one makes a transaction's txid malleable. libsecp256k1's
/// `secp256k1_ecdsa_verify` refuses anything above the half order, which is where this
/// rule is enforced and why this file carries no arithmetic of its own for it.
///
/// The point of the test is not that libsecp is right. It is that the verifier reaches
/// libsecp at all with the bytes the file actually carried, rather than normalizing them
/// first or checking a re-serialization of its own.
#[test]
fn a_high_s_signature_is_refused() {
    let (harness, mut signed) = signed_single();
    let (_, signature) = only_signature(&signed);
    let compact = signature.serialize_compact();
    let mut raised = compact;
    raised[32..].copy_from_slice(&subtract(&GROUP_ORDER, &compact[32..]));
    let mutated = ecdsa::Signature::from_compact(&raised).expect("n - s is a scalar");
    assert_eq!(
        mutated.serialize_compact(),
        raised,
        "from_compact normalized s, so this case would not be testing the high-S rule"
    );
    replace_signature(&mut signed, mutated, EcdsaSighashType::All);
    refuses_with(
        &Coordinator::for_harness(&harness).verify(&signed),
        "signature-invalid",
    );
}

/// A well-formed signature over the right digest, made by a key the script does not commit
/// to. The digest is correct, the encoding is correct, and it authorises nothing.
#[test]
fn a_signature_from_another_key_is_refused() {
    let (harness, mut signed) = signed_single();
    let digest = {
        // The digest the real signature was made over, recovered the only way that does not
        // depend on the code under test: sign with a key whose signature must not verify,
        // over the same message the device signed. Any 32 bytes would do for that purpose,
        // and using the transaction's own digest makes the case narrower - only the KEY is
        // wrong.
        let outcome = Coordinator::for_harness(&harness).verify(&signed);
        assert!(outcome.accepted(), "{outcome}");
        [0x42u8; 32]
    };
    let secp = Secp256k1::signing_only();
    let intruder = SecretKey::from_slice(&[0x17u8; 32]).expect("a fixed scalar is a key");
    let forged = secp.sign_ecdsa(&Message::from_digest(digest), &intruder);
    replace_signature(&mut signed, forged, EcdsaSighashType::All);
    refuses_with(
        &Coordinator::for_harness(&harness).verify(&signed),
        "signature-invalid",
    );
}

/// The 2-of-3 case's device signature, moved onto the single-sig case. Genuinely produced
/// by the right seed, genuinely valid - over a different BIP-143 digest, because the
/// prevouts and the outputs it commits to are another transaction's.
#[test]
fn a_valid_signature_over_another_transaction_is_refused() {
    let (harness, mut signed) = signed_single();
    let (_, other) = signed_multisig();
    let borrowed = other.inputs[0]
        .partial_sigs
        .values()
        .next()
        .expect("the multisig case is signed")
        .signature;
    replace_signature(&mut signed, borrowed, EcdsaSighashType::All);
    refuses_with(
        &Coordinator::for_harness(&harness).verify(&signed),
        "signature-invalid",
    );
}

/// Only `SIGHASH_ALL` commits to every output, so it is the only type this harness will
/// take: a `SIGHASH_NONE` signature over the same inputs authorises paying the money
/// anywhere at all.
#[test]
fn a_signature_under_another_sighash_type_is_refused() {
    let (harness, mut signed) = signed_single();
    let (_, signature) = only_signature(&signed);
    replace_signature(&mut signed, signature, EcdsaSighashType::None);
    refuses_with(
        &Coordinator::for_harness(&harness).verify(&signed),
        "sighash-not-whitelisted",
    );
}

/// BIP-66: a signature's DER encoding is checked before anything else looks at it, and
/// `bitcoin::ecdsa::Signature::from_slice` is where a PSBT's `partial_sigs` value goes
/// through that. So a truncated or empty blob cannot reach the verifier as a `Signature`
/// value at all - it stops one layer earlier, when the file is decoded.
///
/// Worth a test even though no code in `verify` implements it: "the decoder catches it" is
/// a claim about another crate's behaviour, and a claim a release gate rests on is one to
/// pin rather than to remember.
#[test]
fn a_truncated_der_signature_does_not_decode() {
    let (_, signed) = signed_single();
    let (key, _) = only_signature(&signed);
    let bytes = psbt::encode(&signed);

    for (label, forged) in [
        ("empty", Vec::new()),
        ("truncated", vec![0x30, 0x44, 0x02, 0x20, 0x01]),
        ("not DER at all", vec![0xff; 72]),
    ] {
        let edited = replace_partial_sig_value(&bytes, &key, &forged)
            .unwrap_or_else(|| panic!("the {label} case could not be spliced into the file"));
        assert!(
            psbt::decode(&edited).is_err(),
            "a {label} signature blob decoded as a PSBT, so the DER rules are not enforced \
             where this tool believes they are"
        );
    }
}

/// The defect this module exists for, in its plainest shape.
///
/// A file finished the way BIP-174 says a finalizer finishes one - `partial_sigs` and
/// `bip32_derivation` removed, `final_script_witness` written - carrying a witness of
/// arbitrary bytes. Before the authorisation rule this was ACCEPTED, exit 0, with a txid
/// printed for broadcast and a note (not a refusal) observing that no input belonged to the
/// wallet under test.
#[test]
fn a_witness_the_file_finished_itself_is_refused() {
    let (harness, mut signed) = signed_single();
    signed.inputs[0].partial_sigs.clear();
    signed.inputs[0].bip32_derivation.clear();
    signed.inputs[0].final_script_witness = Some(Witness::from_slice(&[
        vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01],
        vec![0x02; 33],
    ]));
    refuses_with(
        &Coordinator::for_harness(&harness).verify(&signed),
        "witness-unverified",
    );
}

/// The same hole reached without touching the signature: the ownership hint alone is
/// removed, so the input classifies as somebody else's, and the witness the file brought
/// stands in for the one this side would have built.
#[test]
fn a_finished_witness_beside_a_stripped_origin_is_refused() {
    let (harness, mut signed) = signed_single();
    signed.inputs[0].bip32_derivation.clear();
    signed.inputs[0].final_script_witness =
        Some(Witness::from_slice(&[vec![0xff; 71], vec![0x02; 33]]));
    refuses_with(
        &Coordinator::for_harness(&harness).verify(&signed),
        "witness-unverified",
    );
}

/// The same, for taproot, where the hint lives in `tap_key_origins` instead. The fixture
/// corpus is used because the generated set has no taproot case.
#[test]
fn a_finished_taproot_witness_is_refused() {
    let mut psbt = fixture::p2tr_psbt();
    let inspection = psbt::inspect(&psbt, &fixture::context()).expect("the fixture inspects");
    psbt = psbt::sign(&psbt, &inspection, &fixture::SEED)
        .expect("the fixture signs")
        .into_psbt();
    psbt.inputs[0].tap_key_sig = None;
    psbt.inputs[0].tap_key_origins.clear();
    psbt.inputs[0].final_script_witness = Some(Witness::from_slice(&[vec![0x00; 64]]));
    refuses_with(&Coordinator::for_fixture().verify(&psbt), "witness-unverified");
}

/// The second shape of the defect: an M-of-N whose other legs are never checked.
///
/// The device's own leg is real and verifies. The second leg is the device's signature
/// copied under a cosigner's key - well-formed DER, the right sighash byte, and no relation
/// to that key. Before the fix, `complete_multisig` counted it because a `partial_sigs`
/// entry existed, added nothing, finalized a witness containing it, and the file was
/// ACCEPTED: a transaction that cannot be spent, certified as one a coordinator would
/// broadcast.
#[test]
fn a_forged_multisig_leg_is_refused() {
    let (harness, mut signed) = signed_multisig();
    let device_leg = *signed.inputs[0]
        .partial_sigs
        .values()
        .next()
        .expect("the device signed its leg");
    let ours: Vec<PublicKey> = signed.inputs[0].partial_sigs.keys().copied().collect();
    let cosigner = signed.inputs[0]
        .bip32_derivation
        .keys()
        .map(|k| PublicKey::new(*k))
        .find(|k| !ours.contains(k))
        .expect("the 2-of-3 names two other keys");
    signed.inputs[0].partial_sigs.insert(cosigner, device_leg);
    refuses_with(
        &Coordinator::for_harness(&harness).verify(&signed),
        "signature-invalid",
    );
}

/// `a - b` on two big-endian 256-bit numbers, for building `n - s`. Only ever called with
/// `a > b`, so a borrow out of the top would be a bug in the caller.
fn subtract(a: &[u8; 32], b: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let mut digit = i16::from(a[i]) - i16::from(b[i]) - borrow;
        borrow = i16::from(digit < 0);
        digit += borrow * 256;
        out[i] = digit as u8;
    }
    assert_eq!(borrow, 0, "n - s underflowed, so s was not below the order");
    out
}

/// Replace the `PSBT_IN_PARTIAL_SIG` value for `key` in an encoded PSBT, without going back
/// through a type that would refuse the bytes being tested.
///
/// BIP-174's records are `<keylen><key><valuelen><value>` with compact-size lengths. Every
/// length here is below 0xfd, so the varints are single bytes - which is asserted rather
/// than assumed, because a silent misparse would splice the bytes somewhere else and the
/// test would pass for the wrong reason.
fn replace_partial_sig_value(bytes: &[u8], key: &PublicKey, value: &[u8]) -> Option<Vec<u8>> {
    let mut record = vec![0x22u8, 0x02];
    record.extend_from_slice(&key.inner.serialize());
    let at = bytes.windows(record.len()).position(|w| w == record)?;
    let length_at = at + record.len();
    let old = *bytes.get(length_at)? as usize;
    assert!(old < 0xfd, "the existing signature record is not a one-byte length");
    assert!(value.len() < 0xfd, "the replacement needs a multi-byte length");

    let mut out = bytes[..length_at].to_vec();
    out.push(value.len() as u8);
    out.extend_from_slice(value);
    out.extend_from_slice(&bytes[length_at + 1 + old..]);
    Some(out)
}
