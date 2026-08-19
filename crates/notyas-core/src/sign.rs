// Copyright (C) 2025-2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Signing: a key for one derivation path, the digest one input commits to, and the
//! signature over it.
//!
//! Three types carry the whole module and they compose in one direction:
//!
//! ```text
//!   seed + path        -> [`derive_path`]         -> [`SecretSigningKey`]
//!   tx + input + spend -> [`SpendKind::sign_hash`] -> [`SignHash`]
//!   key + hash         -> [`SecretSigningKey::sign`] -> [`Signature`]
//! ```
//!
//! The split matters: a [`SignHash`] is produced with no key material in scope, and a
//! [`SecretSigningKey`] cannot be asked to sign anything but a digest this module built.
//! Which signature scheme runs is decided by the [`SignHash`] variant, not by the caller,
//! so an ECDSA key can never be handed a taproot digest and a taproot spend can never be
//! signed with the untweaked key: those states are unrepresentable rather than checked.
//!
//! # What this module is not
//!
//! It has no policy. It signs what it is told, for any derivation path of any depth and
//! any sighash flag rust-bitcoin will compute. Deciding whether a spend *should* be
//! signed - the sighash whitelist, change verification, fee sanity, multisig
//! registration - is notyas-wallet's job (WALLET-API.md section 3), and keeping the two
//! apart is what lets the validation pipeline run with no key in scope at all.
//!
//! # Crypto provenance
//!
//! Nothing here is hand-rolled. The BIP-143 and BIP-341 digests come from rust-bitcoin's
//! [`SighashCache`]; the signatures come from libsecp256k1 through the same `bitcoin`
//! pin the rest of the crate uses. This module decides which of their entry points each
//! input type calls, wipes the secrets afterwards, and nothing else.
//!
//! Two of those entry points are chosen deliberately and are load-bearing claims:
//!
//! - **ECDSA is low-R ground**
//!   ([`bitcoin::secp256k1::Secp256k1::sign_ecdsa_low_r`]), which is what Bitcoin
//!   Core's `CKey::Sign` does. It buys byte-identical signatures against Core, a DER
//!   encoding of at most 70 bytes, and therefore a signature of at most 71 bytes once
//!   the sighash byte is appended - so the vsize a fee is quoted against is exact rather
//!   than an upper bound. Seven of the twelve low-R vectors in the KAT corpus need
//!   grinding (up to four rounds), so a build that silently reverted to the stock nonce
//!   would fail them.
//! - **Schnorr uses no auxiliary randomness**
//!   ([`bitcoin::secp256k1::Secp256k1::sign_schnorr_no_aux_rand`]), which passes a null
//!   `ndata` pointer and makes libsecp256k1 use its precomputed
//!   `TaggedHash("BIP0340/aux", 0^32)` mask. That is byte-identical to signing with 32
//!   zero bytes of auxiliary randomness, which is what BIP-340 test vector 0 specifies,
//!   and it is the only Schnorr entry point the crate can reach:
//!   `sign_schnorr` and `sign_schnorr_with_rng` are behind secp256k1's `rand`/`rand-std`
//!   features, which the workspace's build-graph check bans outright (SECURITY.md
//!   invariant 1, no RNG in the image).
//!
//! # Secret hygiene
//!
//! [`SecretSigningKey`] wipes its scalar on drop and redacts itself in `Debug`, the same
//! discipline the private `derive::SecretXpriv` applies to extended keys. The wipe is
//! best effort in the same sense: it overwrites the copy this value owns and cannot
//! follow copies the compiler put in registers. The one deliberate hole is
//! [`SecretSigningKey::to_private_key`], which hands out a `bitcoin::PrivateKey` that
//! nothing wipes; it exists because rust-bitcoin's `psbt::GetKey` trait is defined to
//! return one, and its contract is that the caller owns the wipe.

use core::borrow::Borrow;
use core::fmt;

use alloc::vec::Vec;

use bitcoin::bip32::{DerivationPath, KeySource, Xpub};
use bitcoin::hashes::Hash;
use bitcoin::key::{CompressedPublicKey, TapTweak, TweakedPublicKey, UntweakedKeypair};
use bitcoin::secp256k1::{Message, SecretKey, XOnlyPublicKey};
use bitcoin::sighash::{
    EcdsaSighashType, P2wpkhError, Prevouts, SegwitV0Sighash, SighashCache, TapSighash,
    TapSighashType, TaprootError,
};
use bitcoin::taproot::TapNodeHash;
use bitcoin::{Amount, Network, PrivateKey, Script, Transaction};

use crate::derive::{master, secp, SecretXpriv};

/// The largest a low-R ground signature can be once the sighash byte is appended: a
/// 70-byte DER encoding (two 32-byte integers, neither needing a leading zero) plus one.
///
/// This is the number a fee estimate stands on. Grinding is what makes it a maximum that
/// is also the common case, rather than 72 with a one-in-two chance of 71.
pub const MAX_ECDSA_SIGNATURE_LEN: usize = 71;

// ---------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------

/// Why a derivation or a digest could not be produced.
///
/// Signing itself is infallible once a [`SecretSigningKey`] and a [`SignHash`] exist,
/// which is the point of building both through constructors that can fail: every
/// rejection happens before any key is in scope.
#[derive(Debug)]
pub enum SignError {
    /// BIP32 refused a step of the path: a child scalar off the curve order, or a depth
    /// past 255. Unreachable for the paths this device builds itself, but a path can
    /// arrive inside a PSBT, and untrusted input must not be able to panic the signer.
    Derivation(bitcoin::bip32::Error),
    /// The BIP-143 digest could not be taken: the input index is not in the transaction,
    /// or - for the two key-hash spends - the script handed in is not a P2WPKH program.
    ///
    /// One variant for all three segwit-v0 spends, including P2WSH, whose only failure is
    /// the index. `P2wpkhError` names P2WPKH because it is rust-bitcoin's type for the
    /// spend that has the second failure mode; splitting our own error in two to mirror
    /// that would put a dependency's type layout in this crate's API for no gain.
    SegwitV0(P2wpkhError),
    /// The BIP-341 digest could not be taken: a prevout set that does not cover the
    /// input, an index out of range, an invalid sighash flag, or SIGHASH_SINGLE with no
    /// output at the same index.
    Taproot(TaprootError),
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignError::Derivation(e) => write!(f, "BIP32 derivation failed: {e}"),
            SignError::SegwitV0(e) => write!(f, "BIP-143 sighash failed: {e}"),
            SignError::Taproot(e) => write!(f, "BIP-341 sighash failed: {e}"),
        }
    }
}

impl core::error::Error for SignError {}

// ---------------------------------------------------------------------------------------
// Derivation
// ---------------------------------------------------------------------------------------

/// Derive the signing key at `path` from a BIP39 seed.
///
/// Any depth, any mix of hardened and normal steps: bounding what a path is *allowed* to
/// be belongs to the policy engine, not here (WALLET-API.md section 3, gate 7).
///
/// The returned key carries its [`KeySource`] - the master fingerprint and the path
/// walked - so a caller can prove after the fact that the key it signed with is the key
/// its plan named, which is exactly the tuple a PSBT's `bip32_derivation` field states.
/// Computing the fingerprint costs one extra point multiplication per call; a caller
/// signing many inputs is expected to derive once per distinct path, not once per use.
///
/// Every intermediate node is wiped: `master` and the derived child both live in
/// `SecretXpriv`, and only the final scalar survives the call.
pub fn derive_path(
    seed: &[u8; 64],
    network: Network,
    path: &DerivationPath,
) -> Result<SecretSigningKey, SignError> {
    let secp = secp();
    let root = master(seed, network);
    let fingerprint = Xpub::from_priv(secp, root.key()).fingerprint();
    let child = SecretXpriv::new(
        root.key()
            .derive_priv(secp, path)
            .map_err(SignError::Derivation)?,
    );
    Ok(SecretSigningKey {
        secret: child.key().private_key,
        origin: Some((fingerprint, path.clone())),
        network,
    })
}

// ---------------------------------------------------------------------------------------
// The key
// ---------------------------------------------------------------------------------------

/// A single secp256k1 scalar with spending authority, plus the public facts that say
/// which key it is.
///
/// Only [`derive_path`] and [`SecretSigningKey::from_secret_bytes`] construct one, and
/// the scalar never leaves except through [`SecretSigningKey::to_private_key`].
pub struct SecretSigningKey {
    secret: SecretKey,
    /// `None` for a key built from a raw scalar. A vector's private key genuinely has no
    /// BIP32 origin, and inventing one would put a lie in the type that a later
    /// derive-and-compare check would trust.
    origin: Option<KeySource>,
    network: Network,
}

impl SecretSigningKey {
    /// A key from a raw 32-byte scalar, with no BIP32 origin.
    ///
    /// The device's own keys always come from [`derive_path`]. This exists because the
    /// published signing vectors (BIP-143, BIP-340, BIP-341) state a private key rather
    /// than a seed, and the boot self-test has to be able to run them. `None` if the
    /// scalar is zero or at/above the curve order.
    pub fn from_secret_bytes(secret: &[u8; 32], network: Network) -> Option<SecretSigningKey> {
        Some(SecretSigningKey {
            secret: SecretKey::from_slice(secret).ok()?,
            origin: None,
            network,
        })
    }

    /// Master fingerprint and full path, for a key that has one.
    pub fn origin(&self) -> Option<&KeySource> {
        self.origin.as_ref()
    }

    pub fn network(&self) -> Network {
        self.network
    }

    /// The 33-byte compressed public key: what a P2WPKH or P2SH-P2WPKH input commits to
    /// and what goes in the witness beside the signature.
    pub fn public_key(&self) -> CompressedPublicKey {
        CompressedPublicKey(self.secret.public_key(secp()))
    }

    /// The x-only INTERNAL key of a taproot output, before any tweak. This is the value a
    /// PSBT's `tap_internal_key` field carries; it is not what the scriptPubKey holds.
    pub fn internal_key(&self) -> XOnlyPublicKey {
        self.secret.x_only_public_key(secp()).0
    }

    /// The x-only OUTPUT key: the internal key tweaked with `merkle_root`, which is what
    /// the scriptPubKey holds and what a Schnorr signature must verify against. `None`
    /// for a BIP86 key-path-only output.
    pub fn output_key(&self, merkle_root: Option<TapNodeHash>) -> TweakedPublicKey {
        self.internal_key().tap_tweak(secp(), merkle_root).0
    }

    /// The scalar as rust-bitcoin's `PrivateKey`, for a `psbt::GetKey` adapter.
    ///
    /// `GetKey::get_key` is defined to return `Option<PrivateKey>`, a type with no
    /// `Drop`, so this hands out a copy nothing wipes. **The caller owns the wipe**
    /// (`PrivateKey::inner::non_secure_erase`). Signing through [`SecretSigningKey::sign`]
    /// needs no copy and is the path the device uses; this is the seam for the one
    /// rust-bitcoin API that cannot be fed anything else.
    pub fn to_private_key(&self) -> PrivateKey {
        PrivateKey::new(self.secret, self.network)
    }

    /// Sign a digest this module produced.
    ///
    /// The digest's variant selects the scheme and, for taproot, the tweak, so there is
    /// no way to sign a segwit v0 digest with Schnorr, or a taproot digest with an
    /// untweaked key. Infallible: both underlying calls are total for a valid scalar and
    /// a 32-byte message.
    pub fn sign(&self, hash: &SignHash) -> Signature {
        let secp = secp();
        match *hash {
            SignHash::SegwitV0 {
                hash,
                sighash_type,
            } => Signature::Ecdsa(bitcoin::ecdsa::Signature {
                signature: secp.sign_ecdsa_low_r(&message(hash.to_byte_array()), &self.secret),
                sighash_type,
            }),
            SignHash::Taproot {
                hash,
                sighash_type,
                merkle_root,
            } => {
                let mut untweaked = UntweakedKeypair::from_secret_key(secp, &self.secret);
                let mut tweaked = untweaked.tap_tweak(secp, merkle_root).to_keypair();
                let signature =
                    secp.sign_schnorr_no_aux_rand(&message(hash.to_byte_array()), &tweaked);
                // Both keypairs hold the scalar (the tweaked one holds a different
                // scalar, which is just as spendable); neither has a Drop of its own.
                tweaked.non_secure_erase();
                untweaked.non_secure_erase();
                Signature::Schnorr(bitcoin::taproot::Signature {
                    signature,
                    sighash_type,
                })
            }
        }
    }

    /// Check a signature against this key and the digest it was meant for.
    ///
    /// The device runs this on its own output. A deterministic nonce makes a faulted
    /// signature a key-recovery event rather than an invalid transaction
    /// (ARCHITECTURE.md 2.4), so verifying what we just produced is a fault check, not a
    /// formality. It is deliberately NOT the wallet's post-sign gate: that one recomputes
    /// the digest by a separate path and verifies against the pubkey the PSBT declares,
    /// and sharing an implementation with the signer would defeat it.
    pub fn verify(&self, hash: &SignHash, signature: &Signature) -> bool {
        let secp = secp();
        match (hash, signature) {
            (
                SignHash::SegwitV0 {
                    hash,
                    sighash_type,
                },
                Signature::Ecdsa(sig),
            ) => {
                sig.sighash_type == *sighash_type
                    && secp
                        .verify_ecdsa(
                            &message(hash.to_byte_array()),
                            &sig.signature,
                            &self.public_key().0,
                        )
                        .is_ok()
            }
            (
                SignHash::Taproot {
                    hash,
                    sighash_type,
                    merkle_root,
                },
                Signature::Schnorr(sig),
            ) => {
                sig.sighash_type == *sighash_type
                    && secp
                        .verify_schnorr(
                            &sig.signature,
                            &message(hash.to_byte_array()),
                            &self.output_key(*merkle_root).to_x_only_public_key(),
                        )
                        .is_ok()
            }
            // A scheme mismatch is not a verification failure to report, it is a caller
            // bug; either way the answer is no.
            _ => false,
        }
    }
}

impl Drop for SecretSigningKey {
    fn drop(&mut self) {
        self.secret.non_secure_erase();
    }
}

impl fmt::Debug for SecretSigningKey {
    /// Hand written rather than derived: the whole value is spending authority, and a
    /// `{:?}` in a log line is how a seed leaves a device.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretSigningKey")
            .field("secret", &"<redacted>")
            .field("origin", &self.origin)
            .field("network", &self.network)
            .finish()
    }
}

/// A 32-byte digest as a secp256k1 message. Named so the two call sites read the same and
/// neither has to spell out that a sighash is already a digest and is not hashed again.
fn message(digest: [u8; 32]) -> Message {
    Message::from_digest(digest)
}

// ---------------------------------------------------------------------------------------
// Digests
// ---------------------------------------------------------------------------------------

/// The per-input facts a sighash needs beyond the transaction itself.
///
/// One variant per input type 0.2.0 signs. A further input type is a further variant and a
/// further arm of [`SpendKind::sign_hash`]; nothing else in the module changes, which is
/// the property that let m7 add P2WSH multisig here without touching a digest.
#[derive(Debug)]
pub enum SpendKind<'a> {
    /// BIP84 native segwit v0. `script_pubkey` is the input's own `0014{keyhash}`
    /// program; BIP-143 expands it into the P2PKH script code internally.
    P2wpkh {
        script_pubkey: &'a Script,
        value: Amount,
        sighash_type: EcdsaSighashType,
    },
    /// BIP49 wrapped segwit. The digest is BIP-143 over exactly the same script code as
    /// the native case - the P2SH wrapper is invisible to it - so what is passed here is
    /// the `0014{keyhash}` REDEEM script, never the `a914{scripthash}87` scriptPubKey.
    /// Naming the field `redeem_script` is the only guard against that confusion, and it
    /// is why this is a separate variant rather than an alias of the one above.
    P2shP2wpkh {
        redeem_script: &'a Script,
        value: Amount,
        sighash_type: EcdsaSighashType,
    },
    /// BIP48 native segwit multisig (m7). BIP-143 hashes the WITNESS script verbatim - it
    /// is not expanded the way a P2WPKH program is - so what is passed here is the
    /// `OP_M ... OP_N OP_CHECKMULTISIG` script itself, and never the `0020{hash}`
    /// scriptPubKey that commits to it. The caller is expected to have rebuilt that script
    /// from a verified registration rather than read it out of the PSBT
    /// ([`crate::multisig::Registration::locate`]); this variant carries no way to tell the
    /// difference, which is why the check lives one layer up in `psbt::inspect`.
    P2wsh {
        witness_script: &'a Script,
        value: Amount,
        sighash_type: EcdsaSighashType,
    },
    /// BIP86 taproot key-path spend. BIP-341 commits to every spent output, so the whole
    /// prevout set is required unless the flag is ANYONECANPAY - which is what
    /// `Prevouts::One` expresses. `merkle_root` is `None` for a key-path-only output
    /// (BIP86) and `Some` when the output also commits to a script tree.
    P2trKeyPath {
        prevouts: &'a Prevouts<'a, bitcoin::TxOut>,
        merkle_root: Option<TapNodeHash>,
        sighash_type: TapSighashType,
    },
}

impl SpendKind<'_> {
    /// The digest input `input_index` of `cache`'s transaction must sign.
    ///
    /// Takes the cache rather than the transaction so the midstate hashes BIP-143 and
    /// BIP-341 share are computed once per transaction instead of once per input: a fresh
    /// cache per input would make signing quadratic in the input count, which on a
    /// 400 MHz target is the difference between a pause and a hang.
    pub fn sign_hash<T: Borrow<Transaction>>(
        &self,
        cache: &mut SighashCache<T>,
        input_index: usize,
    ) -> Result<SignHash, SignError> {
        match *self {
            SpendKind::P2wpkh {
                script_pubkey,
                value,
                sighash_type,
            } => Ok(SignHash::SegwitV0 {
                hash: cache
                    .p2wpkh_signature_hash(input_index, script_pubkey, value, sighash_type)
                    .map_err(SignError::SegwitV0)?,
                sighash_type,
            }),
            SpendKind::P2shP2wpkh {
                redeem_script,
                value,
                sighash_type,
            } => Ok(SignHash::SegwitV0 {
                hash: cache
                    .p2wpkh_signature_hash(input_index, redeem_script, value, sighash_type)
                    .map_err(SignError::SegwitV0)?,
                sighash_type,
            }),
            SpendKind::P2wsh {
                witness_script,
                value,
                sighash_type,
            } => Ok(SignHash::SegwitV0 {
                hash: cache
                    .p2wsh_signature_hash(input_index, witness_script, value, sighash_type)
                    .map_err(|e| SignError::SegwitV0(P2wpkhError::Sighash(e)))?,
                sighash_type,
            }),
            SpendKind::P2trKeyPath {
                prevouts,
                merkle_root,
                sighash_type,
            } => Ok(SignHash::Taproot {
                hash: cache
                    .taproot_key_spend_signature_hash(input_index, prevouts, sighash_type)
                    .map_err(SignError::Taproot)?,
                sighash_type,
                merkle_root,
            }),
        }
    }
}

/// The digest one input's signature commits to, tagged with everything the signature
/// depends on besides the key.
///
/// Carrying the sighash flag and the taproot merkle root here rather than passing them to
/// [`SecretSigningKey::sign`] separately is deliberate: the flag is part of what the
/// digest committed to and the merkle root decides which key the verifier will use, so a
/// signature can never be produced under a flag or a tweak the digest did not assume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignHash {
    /// BIP-143, for P2WPKH and P2SH-P2WPKH. Signed with ECDSA.
    SegwitV0 {
        hash: SegwitV0Sighash,
        sighash_type: EcdsaSighashType,
    },
    /// BIP-341, for a taproot key-path spend. Signed with Schnorr under the tweaked key.
    Taproot {
        hash: TapSighash,
        sighash_type: TapSighashType,
        merkle_root: Option<TapNodeHash>,
    },
}

impl SignHash {
    /// The 32 raw digest bytes, for display and for an independent recomputation to
    /// compare against.
    pub fn to_byte_array(self) -> [u8; 32] {
        match self {
            SignHash::SegwitV0 { hash, .. } => hash.to_byte_array(),
            SignHash::Taproot { hash, .. } => hash.to_byte_array(),
        }
    }
}

// ---------------------------------------------------------------------------------------
// Signatures
// ---------------------------------------------------------------------------------------

/// A finished signature, in the shape the PSBT field and the witness want.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signature {
    /// Goes in `psbt::Input::partial_sigs`. At most [`MAX_ECDSA_SIGNATURE_LEN`] bytes
    /// serialized, because the R value is ground low.
    Ecdsa(bitcoin::ecdsa::Signature),
    /// Goes in `psbt::Input::tap_key_sig`. 64 bytes under SIGHASH_DEFAULT, 65 under any
    /// other flag - BIP-341 omits the flag byte precisely when it is the default.
    Schnorr(bitcoin::taproot::Signature),
}

impl Signature {
    /// Exactly the bytes that go on the wire: DER plus the sighash byte for ECDSA, the
    /// 64-byte Schnorr signature plus the flag byte unless it is SIGHASH_DEFAULT.
    ///
    /// This is the length a fee quote is computed from, so producing it here - rather
    /// than leaving each caller to re-derive the encoding rules - is what keeps the
    /// quoted vsize and the broadcast vsize the same number.
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            Signature::Ecdsa(sig) => sig.serialize().to_vec(),
            Signature::Schnorr(sig) => sig.serialize().to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;
    use bitcoin::consensus::deserialize;
    use bitcoin::TxOut;
    use std::vec::Vec as StdVec;

    /// The BIP-143 native P2WPKH example, as an already-built spend description.
    fn bip143_native() -> (Transaction, SecretSigningKey, [u8; 32]) {
        let raw = hex::decode(
            "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000\
             000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a\
             010000000 0ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac\
             7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac\
             11000000"
                .replace(' ', ""),
        )
        .unwrap();
        let tx: Transaction = deserialize(&raw).unwrap();
        let mut sk = [0u8; 32];
        sk.copy_from_slice(
            &hex::decode("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9")
                .unwrap(),
        );
        let key = SecretSigningKey::from_secret_bytes(&sk, Network::Bitcoin).unwrap();
        let mut want = [0u8; 32];
        want.copy_from_slice(
            &hex::decode("c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670")
                .unwrap(),
        );
        (tx, key, want)
    }

    fn native_spend<'a>(script: &'a Script) -> SpendKind<'a> {
        SpendKind::P2wpkh {
            script_pubkey: script,
            value: Amount::from_sat(600_000_000),
            sighash_type: EcdsaSighashType::All,
        }
    }

    fn native_script() -> bitcoin::ScriptBuf {
        bitcoin::ScriptBuf::from_hex("00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1").unwrap()
    }

    /// The digest is BIP-143's, and the signature over it is BIP-143's, byte for byte.
    #[test]
    fn bip143_native_p2wpkh_round_trip() {
        let (tx, key, want_hash) = bip143_native();
        let script = native_script();
        let mut cache = SighashCache::new(&tx);
        let hash = native_spend(&script).sign_hash(&mut cache, 1).unwrap();
        assert_eq!(hash.to_byte_array(), want_hash);

        let sig = key.sign(&hash);
        assert_eq!(
            hex::encode(sig.serialize()),
            "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220\
             573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01"
                .replace(' ', "")
        );
        assert!(key.verify(&hash, &sig));
        assert!(sig.serialize().len() <= MAX_ECDSA_SIGNATURE_LEN);
    }

    /// The key's own public key must be the one BIP-143 names, or the digest above
    /// happens to match for a key that could not spend the output.
    #[test]
    fn public_key_matches_the_vector() {
        let (_, key, _) = bip143_native();
        assert_eq!(
            key.public_key().to_string(),
            "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357"
        );
    }

    /// An out-of-range input index is an error, never a panic and never a digest over
    /// some other input: the index reaches here from a PSBT.
    #[test]
    fn a_bad_input_index_is_an_error() {
        let (tx, _, _) = bip143_native();
        let script = native_script();
        let mut cache = SighashCache::new(&tx);
        let err = native_spend(&script).sign_hash(&mut cache, 7).unwrap_err();
        assert!(matches!(err, SignError::SegwitV0(_)));
        assert!(!err.to_string().is_empty());
    }

    /// Same for a taproot prevout set that does not cover the input.
    #[test]
    fn a_short_taproot_prevout_set_is_an_error() {
        let (tx, _, _) = bip143_native();
        let prevouts: StdVec<TxOut> = vec![];
        let prevouts = Prevouts::All(&prevouts);
        let mut cache = SighashCache::new(&tx);
        let err = SpendKind::P2trKeyPath {
            prevouts: &prevouts,
            merkle_root: None,
            sighash_type: TapSighashType::Default,
        }
        .sign_hash(&mut cache, 0)
        .unwrap_err();
        assert!(matches!(err, SignError::Taproot(_)));
        assert!(!err.to_string().is_empty());
    }

    /// `Debug` must never print the scalar; the origin and the network are public facts
    /// and are worth keeping, because a redacted struct nobody can identify is useless.
    #[test]
    fn debug_redacts_the_secret_but_keeps_the_origin() {
        let seed = [7u8; 64];
        let path: DerivationPath = "m/84'/0'/0'/0/0".parse().unwrap();
        let key = derive_path(&seed, Network::Bitcoin, &path).unwrap();
        let shown = format!("{key:?}");
        assert!(shown.contains("<redacted>"), "{shown}");
        assert!(shown.contains("84'/0'/0'/0/0"), "{shown}");
        let raw = hex::encode(key.to_private_key().inner.secret_bytes());
        assert!(!shown.contains(&raw), "the scalar leaked into Debug");
    }

    /// A key from a raw scalar has no origin, and says so rather than inventing one.
    #[test]
    fn a_raw_scalar_key_has_no_origin() {
        let (_, key, _) = bip143_native();
        assert!(key.origin().is_none());
        assert!(SecretSigningKey::from_secret_bytes(&[0u8; 32], Network::Bitcoin).is_none());
        assert!(SecretSigningKey::from_secret_bytes(&[0xffu8; 32], Network::Bitcoin).is_none());
    }

    /// `derive_path` must reach the same key as the report path for a path the report
    /// also walks. These are two different call shapes into rust-bitcoin (one path in one
    /// call versus a fixed account node plus two normal steps) and a divergence between
    /// them would sign with a key the user never saw an address for.
    #[test]
    fn derive_path_agrees_with_the_report_derivation() {
        let seed = [0x2au8; 64];
        let report = crate::derive::derive(
            &seed,
            Network::Bitcoin,
            crate::derive::Scheme::Bip84,
            crate::derive::ChildIndex::ZERO,
            crate::derive::ChildIndex::ZERO,
            3,
            0,
        );
        for (i, row) in report.rows.iter().enumerate() {
            let path: DerivationPath = format!("m/84'/0'/0'/0/{i}").parse().unwrap();
            let key = derive_path(&seed, Network::Bitcoin, &path).unwrap();
            assert_eq!(key.public_key().to_string(), row.pubkey, "row {i} pubkey");
            assert_eq!(key.to_private_key().to_wif(), row.wif, "row {i} wif");
            assert_eq!(key.origin().unwrap().1, path, "row {i} path");
        }
    }

    /// The origin's fingerprint is the seed's master fingerprint, not the child's.
    #[test]
    fn the_origin_fingerprint_is_the_master_fingerprint() {
        let seed = [0x5cu8; 64];
        let want = crate::derive::master_fingerprint(&seed, Network::Bitcoin);
        for spec in ["m", "m/0", "m/84'/0'/0'", "m/48'/0'/0'/2'/1/9"] {
            let path: DerivationPath = spec.parse().unwrap();
            let key = derive_path(&seed, Network::Bitcoin, &path).unwrap();
            assert_eq!(key.origin().unwrap().0, want, "{spec}");
        }
    }

    /// Arbitrary depth and arbitrary mixing: this module refuses nothing structural, and
    /// the empty path is the master key itself.
    #[test]
    fn arbitrary_paths_derive() {
        let seed = [0x11u8; 64];
        let master_key = derive_path(&seed, Network::Bitcoin, &DerivationPath::master()).unwrap();
        let deep: DerivationPath = "m/1'/2/3'/4/5'/6/7'/8/9'/10".parse().unwrap();
        let deep_key = derive_path(&seed, Network::Bitcoin, &deep).unwrap();
        assert_ne!(
            master_key.public_key().to_string(),
            deep_key.public_key().to_string()
        );
        assert_eq!(deep_key.origin().unwrap().1.len(), 10);
    }

    /// The tweak must actually be applied: a taproot signature verifies against the
    /// output key and not against the internal key, and two different merkle roots give
    /// two different output keys.
    #[test]
    fn the_taproot_tweak_changes_the_output_key() {
        let seed = [0x99u8; 64];
        let path: DerivationPath = "m/86'/0'/0'/0/0".parse().unwrap();
        let key = derive_path(&seed, Network::Bitcoin, &path).unwrap();
        let root = TapNodeHash::from_byte_array([0x33u8; 32]);
        let bare = key.output_key(None).to_x_only_public_key();
        let with_root = key.output_key(Some(root)).to_x_only_public_key();
        assert_ne!(bare, with_root);
        assert_ne!(bare, key.internal_key());
    }

    /// A signature made under one tweak must not verify under another, and a digest of
    /// the wrong scheme must not verify at all.
    #[test]
    fn verify_rejects_a_mismatched_tweak_or_scheme() {
        let seed = [0x99u8; 64];
        let path: DerivationPath = "m/86'/0'/0'/0/0".parse().unwrap();
        let key = derive_path(&seed, Network::Bitcoin, &path).unwrap();
        let root = TapNodeHash::from_byte_array([0x33u8; 32]);
        let digest = TapSighash::from_byte_array([0x77u8; 32]);

        let bare = SignHash::Taproot {
            hash: digest,
            sighash_type: TapSighashType::Default,
            merkle_root: None,
        };
        let rooted = SignHash::Taproot {
            hash: digest,
            sighash_type: TapSighashType::Default,
            merkle_root: Some(root),
        };
        let sig = key.sign(&bare);
        assert!(key.verify(&bare, &sig));
        assert!(!key.verify(&rooted, &sig));

        let ecdsa = SignHash::SegwitV0 {
            hash: SegwitV0Sighash::from_byte_array([0x77u8; 32]),
            sighash_type: EcdsaSighashType::All,
        };
        assert!(!key.verify(&ecdsa, &sig));
        assert!(!key.verify(&bare, &key.sign(&ecdsa)));
    }

    /// The sighash flag is part of the signature, so a signature made under one flag must
    /// not verify under another even when the digest bytes are identical.
    #[test]
    fn verify_rejects_a_swapped_sighash_flag() {
        let (_, key, _) = bip143_native();
        let digest = SegwitV0Sighash::from_byte_array([0x42u8; 32]);
        let all = SignHash::SegwitV0 {
            hash: digest,
            sighash_type: EcdsaSighashType::All,
        };
        let single = SignHash::SegwitV0 {
            hash: digest,
            sighash_type: EcdsaSighashType::Single,
        };
        let sig = key.sign(&all);
        assert!(key.verify(&all, &sig));
        assert!(!key.verify(&single, &sig));
        // ... and the serialized form differs by exactly the trailing flag byte.
        let other = key.sign(&single);
        assert_eq!(
            &sig.serialize()[..sig.serialize().len() - 1],
            &other.serialize()[..other.serialize().len() - 1]
        );
        assert_ne!(sig.serialize().last(), other.serialize().last());
    }

    /// No RNG anywhere on this path: the same inputs must give the same bytes, forever,
    /// on both schemes. This is SECURITY.md invariant 1 expressed as a test rather than
    /// as a promise about which function was called.
    #[test]
    fn signing_is_deterministic_on_both_schemes() {
        let seed = [0x64u8; 64];
        let path: DerivationPath = "m/86'/0'/0'/0/0".parse().unwrap();
        let key = derive_path(&seed, Network::Bitcoin, &path).unwrap();
        let taproot = SignHash::Taproot {
            hash: TapSighash::from_byte_array([0x21u8; 32]),
            sighash_type: TapSighashType::Default,
            merkle_root: None,
        };
        let ecdsa = SignHash::SegwitV0 {
            hash: SegwitV0Sighash::from_byte_array([0x21u8; 32]),
            sighash_type: EcdsaSighashType::All,
        };
        for hash in [taproot, ecdsa] {
            let first = key.sign(&hash).serialize();
            for _ in 0..4 {
                assert_eq!(key.sign(&hash).serialize(), first);
            }
        }
    }

    /// SIGHASH_DEFAULT omits the flag byte and every other taproot flag appends it; the
    /// 64/65 split is what a witness size estimate is built on.
    #[test]
    fn schnorr_serialization_length_tracks_the_flag() {
        let seed = [0x64u8; 64];
        let path: DerivationPath = "m/86'/0'/0'/0/0".parse().unwrap();
        let key = derive_path(&seed, Network::Bitcoin, &path).unwrap();
        let digest = TapSighash::from_byte_array([0x21u8; 32]);
        for (flag, len) in [
            (TapSighashType::Default, 64),
            (TapSighashType::All, 65),
            (TapSighashType::None, 65),
            (TapSighashType::Single, 65),
            (TapSighashType::AllPlusAnyoneCanPay, 65),
        ] {
            let hash = SignHash::Taproot {
                hash: digest,
                sighash_type: flag,
                merkle_root: None,
            };
            assert_eq!(key.sign(&hash).serialize().len(), len, "{flag:?}");
        }
    }
}
