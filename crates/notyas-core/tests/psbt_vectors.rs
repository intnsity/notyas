// Copyright (C) 2025-2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! End-to-end known-answer tests for the PSBT engine (0.2.0-m6).
//!
//! Every case here starts from the BIP-39 test mnemonic
//! ("abandon abandon ... about", empty passphrase) and drives only the crate's public API:
//! `psbt::inspect`, `psbt::sign`, `psbt::encode`, `psbt::decode`. No test-only fixture is
//! reachable from here, which is the point - this is the surface notyas-wallet will use.
//!
//! # What anchors these numbers
//!
//! Two independent things, and the distinction matters:
//!
//! - The DERIVATION is anchored externally. Each case asserts that the address its key
//!   produces is the first receiving address the published reference for that scheme names,
//!   read out of `tests/vectors/fuzz_vectors.json`'s `reference_checks.first_addresses` -
//!   the same values iancoleman/bip39 and python bip-utils agree on for this mnemonic. A
//!   wrong key therefore fails before any signature is compared.
//!
//! - The SIGNATURES are pinned regression values, produced by this engine. They are not
//!   published bytes and must not be described as such. What makes them worth pinning is
//!   determinism: RFC 6979 with low-R grinding and Schnorr with no auxiliary randomness
//!   (ARCHITECTURE.md 2.4, ratified at Q3) mean that any change to the digest, the key, the
//!   sighash flag or the grinding policy moves them. `tests/signing_vectors.rs` is where
//!   the published BIP-143, BIP-340 and BIP-341 bytes are checked; this file checks that
//!   the PSBT layer feeds that machinery the right inputs.
//!
//! Every signature is additionally verified here against a sighash this file computes with
//! `SighashCache` directly, so a pinned value that happened to be wrong could not pass.

use bitcoin::bip32::DerivationPath;
use bitcoin::hashes::Hash;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::Message;
use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::{
    absolute, transaction, Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Witness,
};
use notyas_core::derive::{master_fingerprint, secp};
use notyas_core::psbt::{self, Claim, Context, ScriptKind, StructuralLimits};
use notyas_core::sign::{derive_path, SecretSigningKey, MAX_ECDSA_SIGNATURE_LEN};
use serde_json::Value;

const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon about";
const REFERENCE: &str = include_str!("vectors/fuzz_vectors.json");

const NETWORK: Network = Network::Bitcoin;
const PREVOUT_SAT: u64 = 200_000;
const OUTPUT_SAT: u64 = 150_000;
const FEE_SAT: u64 = PREVOUT_SAT - OUTPUT_SAT;

fn seed() -> [u8; 64] {
    *notyas_core::bip39::seed(MNEMONIC, "")
}

/// The published first receiving address for `scheme`, from the reference block the fuzz
/// corpus already carries.
fn published_address(scheme: &str) -> String {
    let v: Value = serde_json::from_str(REFERENCE).expect("vector file is valid JSON");
    v["reference_checks"]["first_addresses"][scheme]
        .as_str()
        .expect("published address")
        .to_owned()
}

fn key_at(path: &str) -> (SecretSigningKey, DerivationPath) {
    let path: DerivationPath = path.parse().expect("path");
    let key = derive_path(&seed(), NETWORK, &path).expect("derivation");
    (key, path)
}

/// The single-sig context these vectors run under: no multisig wallet registered, which
/// is what keeps them a test of the single-sig path alone.
fn context() -> Context<'static> {
    Context {
        network: NETWORK,
        fingerprint: master_fingerprint(&seed(), NETWORK),
        limits: StructuralLimits::DEFAULT,
        registry: &[],
    }
}

/// Where every case sends its money: a P2WPKH script from a fixed byte string, with no
/// derivation information, so it classifies as somebody else's address.
fn destination() -> ScriptBuf {
    ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([0x11; 20]))
}

/// A one-output transaction paying `spk`, whose txid the spend then references.
fn funding(spk: &ScriptBuf) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(PREVOUT_SAT),
            script_pubkey: spk.clone(),
        }],
    }
}

/// The unsigned spend of that funding output.
fn spend(funding_txid: bitcoin::Txid) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: funding_txid,
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(OUTPUT_SAT),
            script_pubkey: destination(),
        }],
    }
}

fn prevout(spk: &ScriptBuf) -> TxOut {
    TxOut {
        value: Amount::from_sat(PREVOUT_SAT),
        script_pubkey: spk.clone(),
    }
}

/// The engine's whole contract in one call: parse what it emitted, and get the same bytes
/// back. Run on every signed result below, because a signed PSBT that cannot be re-read is
/// not a delivered signature.
fn survives_a_round_trip(signed: &Psbt) {
    let bytes = psbt::encode(signed);
    assert_eq!(psbt::encode(&psbt::decode(&bytes).expect("re-parse")), bytes);
}

// ---------------------------------------------------------------------------------------
// BIP84 - native segwit
// ---------------------------------------------------------------------------------------

/// The pinned low-R ECDSA signature over the BIP84 case, DER plus the SIGHASH_ALL byte.
const BIP84_SIGNATURE: &str = "3044022004b600c233275280a1df76d6b28ccd1aa1a428e1b93040e061459eabe7fcaa1602203094d35926629c9e4afac0f4c86c072681d3ad93d70fcb1c87069b06746c879001";

#[test]
fn bip84_p2wpkh_signs_end_to_end() {
    let (key, path) = key_at("m/84'/0'/0'/0/0");
    let spk = ScriptBuf::new_p2wpkh(&key.public_key().wpubkey_hash());
    assert_eq!(
        Address::from_script(&spk, NETWORK).unwrap().to_string(),
        published_address("bip84"),
        "the derived key is not the one the published vector names"
    );

    let funding = funding(&spk);
    let mut unsigned = Psbt::from_unsigned_tx(spend(funding.compute_txid())).unwrap();
    unsigned.inputs[0].non_witness_utxo = Some(funding);
    unsigned.inputs[0].witness_utxo = Some(prevout(&spk));
    unsigned.inputs[0]
        .bip32_derivation
        .insert(key.public_key().0, (context().fingerprint, path));

    let inspection = psbt::inspect(&unsigned, &context()).unwrap();
    assert_eq!(inspection.inputs[0].kind, ScriptKind::P2wpkh);
    assert!(matches!(inspection.inputs[0].claim, Claim::Ours { .. }));
    assert_eq!(inspection.fee, Amount::from_sat(FEE_SAT));

    let signed = psbt::sign(&unsigned, &inspection, &seed()).unwrap();
    assert_eq!(signed.report().signatures_added, 1);
    assert_eq!(signed.report().signatures_verified, 1);

    let signature = *signed.psbt().inputs[0]
        .partial_sigs
        .get(&bitcoin::PublicKey::from(key.public_key()))
        .expect("a signature under our own public key");
    assert_eq!(hex::encode(signature.serialize()), BIP84_SIGNATURE);
    assert!(signature.serialize().len() <= MAX_ECDSA_SIGNATURE_LEN);

    // Independent of the engine: recompute the BIP-143 digest here and verify.
    let tx = signed.psbt().unsigned_tx.clone();
    let mut cache = SighashCache::new(&tx);
    let hash = cache
        .p2wpkh_signature_hash(0, &spk, Amount::from_sat(PREVOUT_SAT), EcdsaSighashType::All)
        .unwrap();
    secp()
        .verify_ecdsa(
            &Message::from_digest(hash.to_byte_array()),
            &signature.signature,
            &key.public_key().0,
        )
        .expect("the pinned signature must verify against an independently taken digest");

    survives_a_round_trip(signed.psbt());
}

// ---------------------------------------------------------------------------------------
// BIP49 - wrapped segwit
// ---------------------------------------------------------------------------------------

const BIP49_SIGNATURE: &str = "3044022035688a432e0aaef711449beb2864d495ac47b2dcc305f6b5d4565b38292398df022077182ebed7e5a11e8f4aa12f5499d46afb1145b030bbe8f393e3c897324de62e01";

#[test]
fn bip49_p2sh_p2wpkh_signs_end_to_end() {
    let (key, path) = key_at("m/49'/0'/0'/0/0");
    let redeem = ScriptBuf::new_p2wpkh(&key.public_key().wpubkey_hash());
    let spk = ScriptBuf::new_p2sh(&redeem.script_hash());
    assert_eq!(
        Address::from_script(&spk, NETWORK).unwrap().to_string(),
        published_address("bip49"),
        "the derived key is not the one the published vector names"
    );

    let funding = funding(&spk);
    let mut unsigned = Psbt::from_unsigned_tx(spend(funding.compute_txid())).unwrap();
    unsigned.inputs[0].non_witness_utxo = Some(funding);
    unsigned.inputs[0].witness_utxo = Some(prevout(&spk));
    unsigned.inputs[0].redeem_script = Some(redeem.clone());
    unsigned.inputs[0]
        .bip32_derivation
        .insert(key.public_key().0, (context().fingerprint, path));

    let inspection = psbt::inspect(&unsigned, &context()).unwrap();
    assert_eq!(inspection.inputs[0].kind, ScriptKind::P2shP2wpkh);

    let signed = psbt::sign(&unsigned, &inspection, &seed()).unwrap();
    let signature = *signed.psbt().inputs[0]
        .partial_sigs
        .get(&bitcoin::PublicKey::from(key.public_key()))
        .expect("a signature under our own public key");
    assert_eq!(hex::encode(signature.serialize()), BIP49_SIGNATURE);

    // The digest is BIP-143 over the REDEEM script, never the P2SH scriptPubKey: getting
    // that wrong is the classic wrapped-segwit bug, and this line is what would catch it.
    let tx = signed.psbt().unsigned_tx.clone();
    let mut cache = SighashCache::new(&tx);
    let hash = cache
        .p2wpkh_signature_hash(
            0,
            &redeem,
            Amount::from_sat(PREVOUT_SAT),
            EcdsaSighashType::All,
        )
        .unwrap();
    secp()
        .verify_ecdsa(
            &Message::from_digest(hash.to_byte_array()),
            &signature.signature,
            &key.public_key().0,
        )
        .expect("the pinned signature must verify against an independently taken digest");

    survives_a_round_trip(signed.psbt());
}

// ---------------------------------------------------------------------------------------
// BIP86 - taproot key path
// ---------------------------------------------------------------------------------------

const BIP86_SIGNATURE: &str = "7f856d1f0556b4a3c3c3a788b56fb8dd0f0d8b9cd0645d6708dc49974fd129c86d89ad9fce52fd4e8a86376557f132d32df2648559969af712581694549cc25c";

#[test]
fn bip86_p2tr_key_path_signs_end_to_end() {
    let (key, path) = key_at("m/86'/0'/0'/0/0");
    let spk = ScriptBuf::new_p2tr_tweaked(key.output_key(None));
    assert_eq!(
        Address::from_script(&spk, NETWORK).unwrap().to_string(),
        published_address("bip86"),
        "the derived key is not the one the published vector names"
    );

    // Taproot needs no previous transaction: BIP-341 commits to every prevout, so the
    // amount cannot be lied about without changing the digest.
    let funding = funding(&spk);
    let mut unsigned = Psbt::from_unsigned_tx(spend(funding.compute_txid())).unwrap();
    unsigned.inputs[0].witness_utxo = Some(prevout(&spk));
    unsigned.inputs[0].tap_internal_key = Some(key.internal_key());
    unsigned.inputs[0]
        .tap_key_origins
        .insert(key.internal_key(), (vec![], (context().fingerprint, path)));

    let inspection = psbt::inspect(&unsigned, &context()).unwrap();
    assert_eq!(inspection.inputs[0].kind, ScriptKind::P2tr);

    let signed = psbt::sign(&unsigned, &inspection, &seed()).unwrap();
    let signature = signed.psbt().inputs[0]
        .tap_key_sig
        .expect("a taproot key-path signature");
    assert_eq!(hex::encode(signature.serialize()), BIP86_SIGNATURE);
    // SIGHASH_DEFAULT is the only whitelisted taproot flag and it omits the flag byte.
    assert_eq!(signature.serialize().len(), 64);
    assert!(signed.psbt().inputs[0].partial_sigs.is_empty());

    let tx = signed.psbt().unsigned_tx.clone();
    let prevouts = vec![prevout(&spk)];
    let mut cache = SighashCache::new(&tx);
    let hash = cache
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default)
        .unwrap();
    secp()
        .verify_schnorr(
            &signature.signature,
            &Message::from_digest(hash.to_byte_array()),
            &key.output_key(None).to_x_only_public_key(),
        )
        .expect("the pinned signature must verify against an independently taken digest");

    survives_a_round_trip(signed.psbt());
}

// ---------------------------------------------------------------------------------------
// Properties that hold across all three
// ---------------------------------------------------------------------------------------

/// The same seed and the same file produce the same bytes on every run. This is what makes
/// the pins above meaningful and what ARCHITECTURE.md 2.4's determinism claim rests on.
#[test]
fn signing_the_same_psbt_twice_gives_the_same_bytes() {
    let (key, path) = key_at("m/84'/0'/0'/0/0");
    let spk = ScriptBuf::new_p2wpkh(&key.public_key().wpubkey_hash());
    let funding = funding(&spk);
    let mut unsigned = Psbt::from_unsigned_tx(spend(funding.compute_txid())).unwrap();
    unsigned.inputs[0].non_witness_utxo = Some(funding);
    unsigned.inputs[0].witness_utxo = Some(prevout(&spk));
    unsigned.inputs[0]
        .bip32_derivation
        .insert(key.public_key().0, (context().fingerprint, path));

    let inspection = psbt::inspect(&unsigned, &context()).unwrap();
    let first = psbt::sign(&unsigned, &inspection, &seed()).unwrap();
    let second = psbt::sign(&unsigned, &inspection, &seed()).unwrap();
    assert_eq!(psbt::encode(first.psbt()), psbt::encode(second.psbt()));
}
