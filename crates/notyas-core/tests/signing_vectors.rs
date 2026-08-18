// Copyright (C) 2025-2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Known-answer tests for the signing path (0.2.0-m2).
//!
//! Every expected value in `tests/vectors/signing_vectors.json` comes from one of four
//! upstream artefacts, recorded per section in the file's own `source` fields:
//!
//!   BIP-143  https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
//!            the "Native P2WPKH" and "P2SH-P2WPKH" worked examples: the unsigned
//!            transaction, the sighash, and the signature the BIP publishes for it.
//!   BIP-340  https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
//!            the signing vectors (index 0 has aux_rand = 32 zero bytes, which is what
//!            libsecp256k1's no-aux-rand path computes).
//!   BIP-341  https://github.com/bitcoin/bips/blob/master/bip-0341/wallet-test-vectors.json
//!            `keyPathSpending[0]`: nine spent outputs, seven key-path inputs covering
//!            every sighash flag, each with its internal key, tweak, tweaked key, sighash
//!            and expected witness.
//!   Bitcoin Core
//!            https://github.com/bitcoin/bitcoin/blob/master/src/test/key_tests.cpp
//!            `key_test1`'s two published deterministic-signature vectors, and the key and
//!            message family of `key_signature_tests`, which is Core's own low-R corpus.
//!
//! # The low-R vectors and what makes them independent
//!
//! Core's `key_signature_tests` asserts only a *property* over its corpus (every signature
//! is at most 70 DER bytes), so there are no published bytes to pin. The `low_r` section's
//! expected bytes were therefore produced by a pure-Python RFC 6979 + secp256k1
//! implementation written from RFC 6979 section 3.2 and libsecp256k1's documented
//! `nonce_function_rfc6979` keydata layout - no C library, no Rust crate, no shared code
//! with what it checks. That implementation reproduces Core's two *published* signatures
//! and both of BIP-143's byte for byte, which is what earns it the right to be the
//! reference for the seven grinding cases Core never published.
//!
//! Seven of the twelve low-R cases need one or more grind rounds, so a build that quietly
//! called `sign_ecdsa` instead of `sign_ecdsa_low_r` fails this file. Neither BIP-143
//! vector would catch that on its own: both are naturally low-R at counter 0.

use bitcoin::bip32::DerivationPath;
use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::sighash::{
    EcdsaSighashType, Prevouts, SegwitV0Sighash, SighashCache, TapSighashType,
};
use bitcoin::taproot::TapNodeHash;
use bitcoin::{Amount, Network, ScriptBuf, Transaction, TxOut};
use notyas_core::sign::{
    self, SecretSigningKey, SignHash, Signature, SpendKind, MAX_ECDSA_SIGNATURE_LEN,
};
use serde_json::Value;

const VECTORS: &str = include_str!("vectors/signing_vectors.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("vector file is valid JSON")
}

fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex string")).expect("valid hex")
}

fn array32(v: &Value) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes(v));
    out
}

fn key(v: &Value) -> SecretSigningKey {
    SecretSigningKey::from_secret_bytes(&array32(v), Network::Bitcoin).expect("vector scalar")
}

fn tx(v: &Value) -> Transaction {
    deserialize(&bytes(v)).expect("vector transaction")
}

// =======================================================================================
// BIP-143 - segwit v0 digests and the ECDSA signatures over them
// =======================================================================================

/// The digest and the signature, both byte for byte against the BIP's own worked example,
/// for each of the two input types 0.2.0 signs with ECDSA.
#[test]
fn bip143_sighash_and_signature() {
    let doc = vectors();
    let cases = doc["bip143"].as_array().expect("bip143 array");
    assert_eq!(cases.len(), 2, "vector file lost a BIP-143 case");

    for case in cases {
        let name = case["name"].as_str().unwrap();
        let transaction = tx(&case["unsigned_tx"]);
        let script = ScriptBuf::from_hex(case["script"].as_str().unwrap()).unwrap();
        let value = Amount::from_sat(case["value_sat"].as_u64().unwrap());
        let sighash_type =
            EcdsaSighashType::from_consensus(case["sighash_type"].as_u64().unwrap() as u32);
        let index = case["input_index"].as_u64().unwrap() as usize;

        let spend = match case["spend"].as_str().unwrap() {
            "p2wpkh" => SpendKind::P2wpkh {
                script_pubkey: &script,
                value,
                sighash_type,
            },
            "p2sh_p2wpkh" => SpendKind::P2shP2wpkh {
                redeem_script: &script,
                value,
                sighash_type,
            },
            other => panic!("{name}: unknown spend kind {other}"),
        };

        let mut cache = SighashCache::new(&transaction);
        let hash = spend.sign_hash(&mut cache, index).expect("digest");
        assert_eq!(
            hex::encode(hash.to_byte_array()),
            case["sighash"].as_str().unwrap(),
            "{name}: sighash"
        );

        let signing_key = key(&case["privkey"]);
        assert_eq!(
            signing_key.public_key().to_string(),
            case["pubkey"].as_str().unwrap(),
            "{name}: public key"
        );

        let sig = signing_key.sign(&hash);
        assert_eq!(
            hex::encode(sig.serialize()),
            case["signature"].as_str().unwrap(),
            "{name}: signature bytes"
        );
        assert!(signing_key.verify(&hash, &sig), "{name}: self-verify");
        assert!(
            sig.serialize().len() <= MAX_ECDSA_SIGNATURE_LEN,
            "{name}: {} bytes",
            sig.serialize().len()
        );
    }
}

/// P2SH-P2WPKH hashes the REDEEM script, not the P2SH scriptPubKey. Passing the wrong one
/// is the classic wrapped-segwit bug, so prove the digest actually depends on which.
#[test]
fn bip143_p2sh_p2wpkh_uses_the_redeem_script() {
    let doc = vectors();
    let case = &doc["bip143"][1];
    assert_eq!(case["spend"].as_str().unwrap(), "p2sh_p2wpkh");
    let transaction = tx(&case["unsigned_tx"]);
    let redeem = ScriptBuf::from_hex(case["script"].as_str().unwrap()).unwrap();
    // The scriptPubKey of that input, from the same BIP-143 section.
    let script_pubkey =
        ScriptBuf::from_hex("a9144733f37cf4db86fbc2efed2500b4f4e49f31202387").unwrap();

    let mut cache = SighashCache::new(&transaction);
    let good = SpendKind::P2shP2wpkh {
        redeem_script: &redeem,
        value: Amount::from_sat(case["value_sat"].as_u64().unwrap()),
        sighash_type: EcdsaSighashType::All,
    }
    .sign_hash(&mut cache, 0)
    .unwrap();
    assert_eq!(
        hex::encode(good.to_byte_array()),
        case["sighash"].as_str().unwrap()
    );

    // A P2SH scriptPubKey is not a witness program, so rust-bitcoin refuses it outright
    // rather than producing a plausible wrong digest - which is the better failure.
    let mut cache = SighashCache::new(&transaction);
    assert!(SpendKind::P2shP2wpkh {
        redeem_script: &script_pubkey,
        value: Amount::from_sat(case["value_sat"].as_u64().unwrap()),
        sighash_type: EcdsaSighashType::All,
    }
    .sign_hash(&mut cache, 0)
    .is_err());
}

// =======================================================================================
// BIP-341 - taproot key-path digests and the Schnorr signatures over them
// =======================================================================================

fn bip341_prevouts(doc: &Value) -> Vec<TxOut> {
    doc["bip341_keypath"]["utxos_spent"]
        .as_array()
        .expect("utxos")
        .iter()
        .map(|u| TxOut {
            value: Amount::from_sat(u["value_sat"].as_u64().unwrap()),
            script_pubkey: ScriptBuf::from_hex(u["script_pubkey"].as_str().unwrap()).unwrap(),
        })
        .collect()
}

fn merkle_root(v: &Value) -> Option<TapNodeHash> {
    v.as_str()
        .map(|s| TapNodeHash::from_slice(&hex::decode(s).unwrap()).unwrap())
}

/// All seven key-path inputs: the digest, the tweaked output key, and the witness the BIP
/// publishes - which is a `sign_schnorr_no_aux_rand` signature, byte for byte.
#[test]
fn bip341_key_path_sighash_and_signature() {
    let doc = vectors();
    let transaction = tx(&doc["bip341_keypath"]["unsigned_tx"]);
    let spent = bip341_prevouts(&doc);
    let prevouts = Prevouts::All(&spent);
    let cases = doc["bip341_keypath"]["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 7, "vector file lost a BIP-341 case");

    let mut cache = SighashCache::new(&transaction);
    let mut seen_default = 0;
    let mut seen_no_root = 0;
    for case in cases {
        let index = case["input_index"].as_u64().unwrap() as usize;
        let root = merkle_root(&case["merkle_root"]);
        let sighash_type =
            TapSighashType::from_consensus_u8(case["hash_type"].as_u64().unwrap() as u8).unwrap();
        seen_default += u32::from(sighash_type == TapSighashType::Default);
        seen_no_root += u32::from(root.is_none());

        let hash = SpendKind::P2trKeyPath {
            prevouts: &prevouts,
            merkle_root: root,
            sighash_type,
        }
        .sign_hash(&mut cache, index)
        .expect("digest");
        assert_eq!(
            hex::encode(hash.to_byte_array()),
            case["sighash"].as_str().unwrap(),
            "input {index}: sighash"
        );

        let signing_key = key(&case["internal_privkey"]);
        assert_eq!(
            hex::encode(signing_key.internal_key().serialize()),
            case["internal_pubkey"].as_str().unwrap(),
            "input {index}: internal key"
        );
        // The output key must be the one derived from the vector's own tweaked private
        // key, which is what proves our tweak is BIP-341's and not merely self-consistent.
        let tweaked = key(&case["tweaked_privkey"]);
        assert_eq!(
            signing_key.output_key(root).to_x_only_public_key(),
            tweaked.internal_key(),
            "input {index}: output key"
        );

        let sig = signing_key.sign(&hash);
        assert_eq!(
            hex::encode(sig.serialize()),
            case["signature"].as_str().unwrap(),
            "input {index}: witness"
        );
        assert!(signing_key.verify(&hash, &sig), "input {index}: self-verify");
        assert_eq!(
            sig.serialize().len(),
            if sighash_type == TapSighashType::Default {
                64
            } else {
                65
            },
            "input {index}: witness length"
        );
    }
    assert!(seen_default >= 1, "no SIGHASH_DEFAULT case exercised");
    assert!(seen_no_root >= 1, "no key-path-only (BIP86 shaped) case exercised");
}

/// `Prevouts::One` is the ANYONECANPAY shape, where the signer has only the one spent
/// output. It must produce the same digest as the full set for the same input.
#[test]
fn bip341_anyonecanpay_needs_only_its_own_prevout() {
    let doc = vectors();
    let transaction = tx(&doc["bip341_keypath"]["unsigned_tx"]);
    let spent = bip341_prevouts(&doc);
    let cases = doc["bip341_keypath"]["cases"].as_array().unwrap();

    let mut checked = 0;
    for case in cases {
        let flag = case["hash_type"].as_u64().unwrap() as u8;
        if flag & 0x80 == 0 {
            continue;
        }
        let index = case["input_index"].as_u64().unwrap() as usize;
        let sighash_type = TapSighashType::from_consensus_u8(flag).unwrap();
        let one = Prevouts::One(index, spent[index].clone());
        let mut cache = SighashCache::new(&transaction);
        let hash = SpendKind::P2trKeyPath {
            prevouts: &one,
            merkle_root: merkle_root(&case["merkle_root"]),
            sighash_type,
        }
        .sign_hash(&mut cache, index)
        .expect("digest");
        assert_eq!(
            hex::encode(hash.to_byte_array()),
            case["sighash"].as_str().unwrap(),
            "input {index}: ANYONECANPAY digest from a single prevout"
        );
        checked += 1;
    }
    assert_eq!(checked, 3, "the corpus should hold three ANYONECANPAY cases");
}

// =======================================================================================
// BIP-340 - Schnorr, and the no-auxiliary-randomness claim
// =======================================================================================

/// BIP-340's vectors sign a bare message with a bare key, so they are checked against the
/// Schnorr primitive itself rather than through [`SecretSigningKey::sign`], which always
/// applies the BIP-341 tweak. What they establish is the aux-rand question, and only that.
///
/// Vector 0's aux_rand is 32 zero bytes, and libsecp256k1's no-aux-rand path is defined to
/// use its precomputed `TaggedHash("BIP0340/aux", 0^32)` mask - so the two must agree byte
/// for byte. That equality is the evidence behind the no-RNG invariant on the Schnorr
/// side: a property of the function actually called, not of a comment. The remaining
/// signing vectors use a non-zero aux_rand, so the same call must NOT reproduce their
/// published signature; if it did, aux_rand would be being ignored rather than absent and
/// the equality above would prove nothing.
///
/// That the SIGNING PATH reaches this same entry point is proved by
/// `bip341_key_path_sighash_and_signature`, whose expected witnesses are BIP-341's own and
/// are matched through [`SecretSigningKey::sign`].
#[test]
fn bip340_no_aux_rand_matches_the_zero_aux_vector() {
    use bitcoin::secp256k1::{Keypair, Message, SecretKey};

    let secp = notyas_core::derive::secp();
    let doc = vectors();
    let cases = doc["bip340"].as_array().expect("bip340 array");
    assert!(cases.len() >= 4, "vector file lost BIP-340 cases");

    let mut matched_zero_aux = 0;
    let mut differed_on_nonzero_aux = 0;
    for case in cases {
        let index = &case["index"];
        let keypair =
            Keypair::from_secret_key(secp, &SecretKey::from_slice(&array32(&case["secret_key"]))
                .expect("vector scalar"));
        assert_eq!(
            hex::encode(keypair.x_only_public_key().0.serialize()),
            case["public_key"].as_str().unwrap(),
            "vector {index}: public key"
        );

        let message = Message::from_digest(array32(&case["message"]));
        let sig = secp.sign_schnorr_no_aux_rand(&message, &keypair);
        assert!(
            secp.verify_schnorr(&sig, &message, &keypair.x_only_public_key().0)
                .is_ok(),
            "vector {index}: does not verify"
        );

        let want = case["signature"].as_str().unwrap();
        if case["aux_rand"].as_str().unwrap() == "0".repeat(64) {
            assert_eq!(hex::encode(sig.serialize()), want, "vector {index}");
            matched_zero_aux += 1;
        } else {
            assert_ne!(hex::encode(sig.serialize()), want, "vector {index}");
            differed_on_nonzero_aux += 1;
        }
    }
    assert!(matched_zero_aux >= 1, "no zero-aux vector in the corpus");
    assert!(
        differed_on_nonzero_aux >= 1,
        "no non-zero-aux vector in the corpus"
    );
}

// =======================================================================================
// Low-R grinding
// =======================================================================================

/// The ECDSA path must be Bitcoin Core's, not libsecp's stock loop.
///
/// Three claims, all over the same corpus: the bytes are exactly what an independent
/// RFC 6979 implementation says low-R grinding produces; they differ from the stock
/// signature wherever grinding was needed; and every one of them serializes to at most
/// 71 bytes with the sighash byte, which is the number the fee display stands on.
#[test]
fn low_r_grinding_matches_and_bounds_the_signature() {
    let doc = vectors();
    let block = &doc["low_r"];
    let signing_key = key(&block["privkey"]);
    let cases = block["cases"].as_array().expect("low_r cases");
    assert!(cases.len() >= 12, "vector file lost low-R cases");

    let mut ground = 0;
    for case in cases {
        let hash = SignHash::SegwitV0 {
            hash: SegwitV0Sighash::from_byte_array(array32(&case["digest"])),
            sighash_type: EcdsaSighashType::All,
        };
        let sig = signing_key.sign(&hash);
        let Signature::Ecdsa(inner) = sig else {
            panic!("a segwit v0 digest must produce an ECDSA signature");
        };
        let der = hex::encode(inner.signature.serialize_der());
        assert_eq!(
            der,
            case["low_r_der"].as_str().unwrap(),
            "case {}: low-R bytes",
            case["index"]
        );
        assert!(signing_key.verify(&hash, &sig), "case {}", case["index"]);

        let counter = case["grind_counter"].as_u64().unwrap();
        if counter > 0 {
            ground += 1;
            assert_ne!(
                der,
                case["stock_der"].as_str().unwrap(),
                "case {}: grinding produced the stock signature",
                case["index"]
            );
        } else {
            assert_eq!(der, case["stock_der"].as_str().unwrap(), "case {}", case["index"]);
        }

        // Low R means a 32-byte R with the top bit clear, so DER never pads it: the
        // length byte at offset 3 is at most 32 and the whole thing fits in 71 bytes.
        let raw = inner.signature.serialize_der();
        assert!(raw[3] <= 32, "case {}: R is {} bytes", case["index"], raw[3]);
        assert!(
            sig.serialize().len() <= MAX_ECDSA_SIGNATURE_LEN,
            "case {}: {} bytes",
            case["index"],
            sig.serialize().len()
        );
    }
    assert!(
        ground >= 5,
        "only {ground} grinding cases: the corpus no longer discriminates low-R from stock"
    );
}

/// Byte-identical to Bitcoin Core, on the two signatures Core itself publishes.
#[test]
fn matches_bitcoin_core_deterministic_signatures() {
    let doc = vectors();
    let cases = doc["core_detsig"].as_array().expect("core_detsig array");
    assert_eq!(cases.len(), 2);
    for case in cases {
        let signing_key = key(&case["privkey"]);
        let hash = SignHash::SegwitV0 {
            hash: SegwitV0Sighash::from_byte_array(array32(&case["digest"])),
            sighash_type: EcdsaSighashType::All,
        };
        let Signature::Ecdsa(inner) = signing_key.sign(&hash) else {
            unreachable!()
        };
        assert_eq!(
            hex::encode(inner.signature.serialize_der()),
            case["der"].as_str().unwrap(),
            "{}",
            case["wif"].as_str().unwrap()
        );
    }
}

// =======================================================================================
// BIP-32 - derive_path over an arbitrary chain
// =======================================================================================

/// BIP-32 test vector 2 (bitcoin/bips, bip-0032.mediawiki), 64-byte seed. Only the chains
/// that mix hardened and normal steps at depth are transcribed here; the account-shaped
/// chains are already covered by `spec_vectors.rs` through the report path.
const BIP32_V2_SEED: &str = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542";
const BIP32_V2_CHAINS: [(&str, &str); 3] = [
    ("m/0/2147483647h",
     "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9"),
    ("m/0/2147483647h/1/2147483646h",
     "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc"),
    ("m/0/2147483647h/1/2147483646h/2",
     "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j"),
];

/// `derive_path` must reach the exact scalar BIP-32 publishes for chains of arbitrary
/// depth with hardened and normal steps interleaved - the shape a PSBT can name and
/// `derive::derive`'s fixed BIP-43 walk cannot express.
#[test]
fn derive_path_matches_bip32_arbitrary_chains() {
    let mut seed = [0u8; 64];
    seed.copy_from_slice(&hex::decode(BIP32_V2_SEED).unwrap());

    for (chain, want_xprv) in BIP32_V2_CHAINS {
        let path: DerivationPath = chain.parse().expect("chain parses");
        let derived = sign::derive_path(&seed, Network::Bitcoin, &path).expect("derivation");
        // Bytes 46..78 of a serialized xprv are the 0x00 prefix and the 32-byte scalar.
        let raw = bitcoin::base58::decode_check(want_xprv).expect("official vector");
        assert_eq!(raw.len(), 78);
        assert_eq!(raw[45], 0x00, "{chain}: not a private extended key");
        assert_eq!(
            hex::encode(derived.to_private_key().inner.secret_bytes()),
            hex::encode(&raw[46..78]),
            "{chain}: scalar"
        );
    }
}
