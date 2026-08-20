// Copyright (C) 2025-2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Message signing: the classic Bitcoin Signed Message digest, encoded per BIP-137.
//!
//! One entry point, [`sign`], and one thing it produces: the 65 bytes every wallet in
//! the field calls a signed message, base64 encoded.
//!
//! > The serialization format of a Bitcoin signature is as follows:
//! >
//! > [1 byte of header data][32 bytes for r value][32 bytes for s value]
//!
//! (BIP-137, "Conventions with signatures used in Bitcoin".)
//!
//! The r and s are an ordinary ECDSA signature over an ordinary 32-byte digest, so the
//! whole of what BIP-137 contributes is the header byte, and the whole of what the header
//! byte contributes is telling a verifier which of the four address types the signer is
//! claiming:
//!
//! > The header is the recId plus a constant which indicates what type of Bitcoin address
//! > this is. For P2PKH address using an uncompressed public key this value is 27. For
//! > P2PKH address using compressed public key this value is 31. For P2SH-P2WPKH this
//! > value is 35 and for P2WPKH (version 0 witness) address this value is 39. So, you have
//! > the following ranges:
//! > * 27-30: P2PKH uncompressed
//! > * 31-34: P2PKH compressed
//! > * 35-38: Segwit P2SH
//! > * 39-42: Segwit Bech32
//!
//! (BIP-137, "Procedure for signing/verifying a signature".) [`AddressKind`] is those four
//! constants and nothing else, and a [`MessageSignature`] stores the kind and the recovery
//! id rather than the sum, so a header outside the sixteen legal values cannot be built.
//!
//! # The digest BIP-137 does not specify
//!
//! BIP-137 says only `Sha256Hash messageHash = Sha256Hash.twiceOf(messageBytes);` and
//! leaves `formatMessageForSigning` to the implementation it was extracted from. The
//! normative text for that half is Bitcoin Core's `src/util/message.cpp`:
//!
//! ```text
//! const std::string MESSAGE_MAGIC = "Bitcoin Signed Message:\n";
//!
//! uint256 MessageHash(const std::string& message)
//! {
//!     HashWriter hasher{};
//!     hasher << MESSAGE_MAGIC << message;
//!     return hasher.GetHash();
//! }
//! ```
//!
//! Serializing a `std::string` writes a CompactSize length and then the bytes, and
//! `GetHash` is SHA-256 applied twice, so the preimage is
//! `0x18 || "Bitcoin Signed Message:\n" || CompactSize(len) || message`. Both length
//! prefixes are load-bearing: without them a signature over a chosen message could be
//! replayed as a signature over a different message that happens to share the
//! concatenation, and any verifier in the field will simply reject a digest built any
//! other way. [`hash`] is that preimage and nothing else.
//!
//! The message is hashed exactly as handed in. No Unicode normalization, no trailing
//! newline, no case folding: Core hashes the bytes of the string it was given, and a
//! device that quietly normalized would produce a signature that does not verify against
//! the text the user actually read. Callers that want normalization must do it before
//! they call, and must show the normalized text.
//!
//! # What this module is not
//!
//! It is not BIP-322. That standard signs a message by building a pair of virtual
//! transactions, which is a second signing surface with its own script evaluation and its
//! own review problem; it is deliberately out of 0.2.0 (COMPETITIVE.md section 8). BIP-137
//! is here instead because its entire reviewable content is one message, one address and
//! one address type - one screen.
//!
//! It has no policy, in the same sense [`crate::sign`] has none: it signs the bytes it is
//! given under the key it is given. Deciding that a message is safe to sign, and showing
//! the user what they are about to attest to, is the front end's job.
//!
//! It signs no taproot address. BIP-137 assigns no header constant to a v1 witness
//! program, so there is no interoperable answer to give; [`AddressKind::for_scheme`]
//! returns `None` for BIP86 rather than inventing a range no verifier implements.
//!
//! # Determinism
//!
//! The nonce is RFC 6979 through libsecp256k1's default nonce function, which is what
//! `secp256k1_ecdsa_sign_recoverable(..., secp256k1_nonce_function_rfc6979, nullptr)`
//! gives Bitcoin Core's `CKey::SignCompact`. Nothing here reads an RNG, because the crate
//! has no way to (SECURITY.md invariant 3).
//!
//! Note that this is the one signature in the crate that is deliberately NOT low-R ground:
//! [`crate::sign::SecretSigningKey::sign`] grinds because a transaction's vsize depends on
//! the DER length, and a message signature has no DER and no vsize. Grinding here would
//! move r away from the value Core, Electrum and every other signer produces for the same
//! key and message, and message signatures are compared byte for byte far more often than
//! transactions are.

use alloc::string::String;

use bitcoin::hashes::{sha256d, Hash, HashEngine};
use bitcoin::secp256k1::{ecdsa, Message, PublicKey, Scalar};

use crate::derive::{secp, Scheme};
use crate::sign::SecretSigningKey;

/// The prefix that makes a signed message unmistakably not a transaction.
///
/// Verbatim from Bitcoin Core's `MESSAGE_MAGIC`, including the trailing newline. Its
/// length, 24, is the first byte of every preimage [`hash`] builds.
pub const MESSAGE_MAGIC: &str = "Bitcoin Signed Message:\n";

/// Header plus r plus s: the fixed size of every BIP-137 signature.
pub const SIGNATURE_LEN: usize = 65;

/// The base64 encoding of [`SIGNATURE_LEN`] bytes, which is fixed because the length is:
/// 21 full three-byte groups and a two-byte tail padded with one `=`.
pub const SIGNATURE_BASE64_LEN: usize = 88;

/// The SEC 2 generator point of secp256k1, compressed.
///
/// Only used to turn the message digest into the point `eG` while checking the recovery
/// id (see [`recovery_id`]); it is public data, so naming it as a constant rather than
/// deriving it through a `SecretKey` keeps a public value out of the secret-typed API. The
/// `generator_constant_is_the_curve_generator` test pins it against libsecp256k1's own
/// answer for the scalar 1, so a transcription error cannot survive a test run.
const GENERATOR: [u8; 33] = [
    0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
    0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17,
    0x98,
];

// ---------------------------------------------------------------------------------------
// Address kinds
// ---------------------------------------------------------------------------------------

/// Which of BIP-137's four address types a signature claims.
///
/// This is the only thing the header byte says beyond the recovery id, and it is a claim,
/// not a proof: the same r and s serve all four, and a verifier that recovers the public
/// key still has to build the address of this kind and compare it with the one it was
/// given. That is exactly why the kind has to be carried - without it a verifier holding a
/// bech32 address cannot tell whether a header of 32 means "wrong signer" or "signer that
/// did not know about segwit".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressKind {
    /// A `1...` address over the 65-byte uncompressed public key. Present for
    /// interoperability with signatures made before compressed keys were universal; this
    /// device derives no uncompressed keys itself.
    P2pkhUncompressed,
    /// A `1...` address over the 33-byte compressed public key (BIP44).
    P2pkhCompressed,
    /// A `3...` address wrapping a v0 witness program (BIP49).
    P2shP2wpkh,
    /// A `bc1q...` v0 witness program (BIP84).
    P2wpkh,
}

impl AddressKind {
    /// The header byte for recovery id 0. Adding the recovery id, which BIP-137 states is
    /// "a number between 0 and 3 inclusive", gives the four-value range of this kind.
    pub const fn header_base(self) -> u8 {
        match self {
            AddressKind::P2pkhUncompressed => 27,
            AddressKind::P2pkhCompressed => 31,
            AddressKind::P2shP2wpkh => 35,
            AddressKind::P2wpkh => 39,
        }
    }

    /// Whether the address this kind names is built from the compressed public key.
    ///
    /// Only [`AddressKind::P2pkhUncompressed`] is not: a witness program is defined over
    /// the compressed key, so the two segwit kinds have no uncompressed form at all.
    pub const fn compressed(self) -> bool {
        !matches!(self, AddressKind::P2pkhUncompressed)
    }

    /// The kind a derivation scheme's addresses have, for the caller that has an account
    /// scheme in hand and must not have to restate the mapping.
    ///
    /// `None` where BIP-137 has nothing to say: BIP86 because the standard assigns no
    /// header constant to a v1 witness program, and BIP48 because a multisig address is
    /// not derived from one key and so no single-key signature can attest to it.
    pub fn for_scheme(scheme: Scheme) -> Option<AddressKind> {
        match scheme {
            Scheme::Bip44 => Some(AddressKind::P2pkhCompressed),
            Scheme::Bip49 => Some(AddressKind::P2shP2wpkh),
            Scheme::Bip84 => Some(AddressKind::P2wpkh),
            Scheme::Bip86 | Scheme::Bip48 => None,
        }
    }
}

// ---------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------

/// Why a message could not be signed.
///
/// Every variant is a state that a correct libsecp256k1 and a well-formed key cannot
/// reach; they exist because the alternative is a panic on a device with no console, and
/// because a signature that silently carried the wrong recovery id would be rejected by
/// every verifier with no clue as to why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageError {
    /// The digest is zero or is at or above the curve order, so it is not a scalar the
    /// recovery-id check can multiply the generator by. A double SHA-256 lands there with
    /// probability around 2^-128; there is no message to reach it with, only a fault.
    DigestNotAScalar,
    /// No recovery id fits the signature. Reachable in theory when the signature's r is
    /// the x coordinate of a point that had to be reduced modulo the curve order - the
    /// case BIP-137's recovery ids 2 and 3 exist for, at probability around 2^-128 - and
    /// in practice only if the signature or the public key was corrupted between being
    /// produced and being checked.
    NoRecoveryId,
    /// The finished signature did not verify against the key that made it. Under the
    /// deterministic nonce this crate is built on (SECURITY.md invariant 3) a faulted
    /// signature is a key-recovery event and not merely a rejected message: two signatures
    /// over the same digest with the same nonce and different s reveal the scalar. That is
    /// why the bytes are checked before they leave, and why this firing is a hardware
    /// fault rather than a condition to retry.
    FaultCheck,
}

impl core::fmt::Display for MessageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MessageError::DigestNotAScalar => write!(f, "message digest is not a valid scalar"),
            MessageError::NoRecoveryId => write!(f, "no recovery id fits the signature"),
            MessageError::FaultCheck => write!(f, "signature failed its own verification"),
        }
    }
}

impl core::error::Error for MessageError {}

// ---------------------------------------------------------------------------------------
// The digest
// ---------------------------------------------------------------------------------------

/// The 32 bytes a Bitcoin Signed Message signature commits to.
///
/// `SHA256d(0x18 || MESSAGE_MAGIC || CompactSize(message.len()) || message)`, which is
/// Core's `MessageHash` written out. Takes bytes rather than `&str` because that is what
/// is hashed: a caller holding text passes `s.as_bytes()` and thereby states that the
/// UTF-8 bytes it displayed are the bytes it signed.
///
/// Streams into the hash engine instead of building the preimage in a buffer, so a long
/// message is never copied. On a device whose whole heap is smaller than a page of some
/// desktop wallets that is the difference between signing a 10 KB message and failing to.
pub fn hash(message: &[u8]) -> [u8; 32] {
    let mut engine = sha256d::Hash::engine();

    // The magic is written the way Core writes it, as a length-prefixed string; its length
    // is 24, so the prefix is the single byte 0x18 that every implementation hardcodes.
    let mut prefix = [0u8; 9];
    engine.input(compact_size(MESSAGE_MAGIC.len() as u64, &mut prefix));
    engine.input(MESSAGE_MAGIC.as_bytes());

    let mut length = [0u8; 9];
    engine.input(compact_size(message.len() as u64, &mut length));
    engine.input(message);

    sha256d::Hash::from_engine(engine).to_byte_array()
}

/// Bitcoin's CompactSize, written into `buf` and returned as the bytes that were used.
///
/// Borrowed rather than allocated because [`hash`] runs it twice per call and the whole
/// point of streaming the message is to touch the allocator zero times.
fn compact_size(value: u64, buf: &mut [u8; 9]) -> &[u8] {
    if value < 253 {
        buf[0] = value as u8;
        &buf[..1]
    } else if value <= u16::MAX as u64 {
        buf[0] = 0xfd;
        buf[1..3].copy_from_slice(&(value as u16).to_le_bytes());
        &buf[..3]
    } else if value <= u32::MAX as u64 {
        buf[0] = 0xfe;
        buf[1..5].copy_from_slice(&(value as u32).to_le_bytes());
        &buf[..5]
    } else {
        buf[0] = 0xff;
        buf[1..9].copy_from_slice(&value.to_le_bytes());
        &buf[..9]
    }
}

// ---------------------------------------------------------------------------------------
// The signature
// ---------------------------------------------------------------------------------------

/// A finished BIP-137 signature.
///
/// Stores the address kind and the recovery id rather than the header byte they add up to.
/// The sum is derivable and the parts are not, so keeping the parts makes every header
/// outside the four legal ranges unrepresentable, and lets a caller ask which address type
/// a signature claims without decoding anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageSignature {
    kind: AddressKind,
    /// Always 0 or 1 in practice. See [`MessageSignature::recovery_id`].
    recovery: u8,
    /// r then s, 32 big-endian bytes each, with s already in the low half of the range -
    /// libsecp256k1 normalizes before it returns.
    compact: [u8; 64],
}

impl MessageSignature {
    /// The address type this signature claims.
    pub fn address_kind(&self) -> AddressKind {
        self.kind
    }

    /// The recovery id, 0 to 3, that a verifier uses to rebuild the public key.
    ///
    /// BIP-137 allows all four values. Only 0 and 1 - the parity of the nonce point's y
    /// coordinate - are reachable here: 2 and 3 say that the point's x coordinate exceeded
    /// the curve order and was reduced, which happens with probability around 2^-128 and
    /// which [`sign`] reports as [`MessageError::NoRecoveryId`] rather than guessing at.
    pub fn recovery_id(&self) -> u8 {
        self.recovery
    }

    /// The header byte: the kind's constant plus the recovery id.
    pub fn header(&self) -> u8 {
        self.kind.header_base() + self.recovery
    }

    /// The 65 bytes on the wire: `[header][r][s]`.
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LEN] {
        let mut out = [0u8; SIGNATURE_LEN];
        out[0] = self.header();
        out[1..].copy_from_slice(&self.compact);
        out
    }

    /// The signature as wallets exchange it: standard base64 of [`MessageSignature::to_bytes`].
    ///
    /// Always [`SIGNATURE_BASE64_LEN`] characters, which is what lets a front end lay the
    /// string out before it has one.
    pub fn to_base64(&self) -> String {
        base64_encode(&self.to_bytes())
    }

    /// Check this signature against the public key it claims to come from.
    ///
    /// Two independent things have to hold: the r and s verify as ECDSA over the digest of
    /// `message`, and the recovery id in the header is the one that rebuilds this exact
    /// key. The second is what a verifier will actually do - it has no public key until it
    /// recovers one - so checking only the first would let a signature ship with a header
    /// no verifier can use.
    ///
    /// Takes the public key rather than the signing key: verification needs no secret, and
    /// the device's post-sign check is stronger for running with none in scope.
    pub fn verify(&self, pubkey: &PublicKey, message: &[u8]) -> bool {
        let digest = hash(message);
        let Ok(signature) = ecdsa::Signature::from_compact(&self.compact) else {
            return false;
        };
        if recovery_id(pubkey, &digest, &self.compact) != Ok(self.recovery) {
            return false;
        }
        secp()
            .verify_ecdsa(&Message::from_digest(digest), &signature, pubkey)
            .is_ok()
    }
}

// ---------------------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------------------

/// Sign `message` with `key`, claiming an address of type `kind`.
///
/// `kind` does not change the signature, only the header byte in front of it, which is the
/// property BIP-137 rests on and the reason a caller must state it: nothing in the key or
/// the message says which of the four addresses derived from this key the user meant. A
/// caller that has a [`Scheme`] should get the kind from
/// [`AddressKind::for_scheme`] rather than choosing one.
///
/// The returned signature has already verified against its own public key; see
/// [`MessageError::FaultCheck`].
pub fn sign(
    key: &SecretSigningKey,
    kind: AddressKind,
    message: &[u8],
) -> Result<MessageSignature, MessageError> {
    let secp = secp();
    let digest = hash(message);

    // `to_private_key` hands out a copy of the scalar that nothing wipes, and its contract
    // is that the caller owns the wipe. This is the whole extent of that ownership: the
    // copy exists for one call and is erased before anything else can run.
    //
    // The plain `sign_ecdsa` rather than the crate's usual `sign_ecdsa_low_r`: see the
    // determinism note in the module docs. Both use the same RFC 6979 nonce; low-R
    // additionally grinds the nonce until r is short, which no message-signing
    // implementation in the field does, so grinding would break byte comparison against
    // every one of them for no gain here.
    let mut private = key.to_private_key();
    let signature = secp.sign_ecdsa(&Message::from_digest(digest), &private.inner);
    private.inner.non_secure_erase();

    let pubkey = key.public_key().0;
    let compact = signature.serialize_compact();
    let signed = MessageSignature {
        kind,
        recovery: recovery_id(&pubkey, &digest, &compact)?,
        compact,
    };

    // The recovery-id search already proved the verification equation for this key (see
    // [`recovery_id`]); running libsecp256k1's own verifier as well means a fault has to
    // corrupt two unrelated computations the same way to escape. That is the same reason
    // Core's `CKey::SignCompact` recovers and compares before it returns.
    if !signed.verify(&pubkey, message) {
        return Err(MessageError::FaultCheck);
    }
    Ok(signed)
}

/// Which recovery id rebuilds `pubkey` from this signature.
///
/// libsecp256k1 knows the answer while it signs and its recovery module returns it, but
/// that module is not in this build: `bitcoin` is pinned with `default-features = false`,
/// which drops `secp-recovery`, and the dependency surface of the firmware image is not
/// something a display feature gets to widen.
///
/// It does not have to be. The recovery id is the parity of the nonce point R, and R is
/// pinned down by the signature: a verifier accepts (r, s) for a key P and a digest e
/// exactly when
///
/// ```text
///   R = (e/s)G + (r/s)P    and    R.x = r
/// ```
///
/// Multiplying through by s gives `sR = eG + rP`, which needs no modular inversion and no
/// arithmetic this module has to implement - just three scalar multiplications and one
/// addition, all of them libsecp256k1's. There are only two candidate R with x coordinate
/// r, one per parity, and they are negatives of each other, so at most one can satisfy an
/// equation whose other side is fixed. Testing them is therefore a decision, not a search.
///
/// Two things fall out of this shape and are worth stating, because the code reads as if
/// it only did one job:
///
/// - Finding an id **is** verifying the signature. The equation above is the verification
///   equation; a corrupted r, s or P leaves both parities failing it.
/// - It is correct across libsecp256k1's low-s normalization for free. Negating s negates
///   R, so a signature whose s was flipped has the opposite parity, and this function is
///   told about it by the only thing that decides: the equation.
///
/// All inputs are public, so nothing here needs to be constant time.
fn recovery_id(
    pubkey: &PublicKey,
    digest: &[u8; 32],
    compact: &[u8; 64],
) -> Result<u8, MessageError> {
    let secp = secp();

    // r and s come from a signature libsecp256k1 has just produced or parsed, so both are
    // already reduced into [1, n-1]; a rejection here would be a broken library rather
    // than bad input, and NoRecoveryId is the honest thing to say about it either way.
    let r_bytes: [u8; 32] = compact[..32].try_into().expect("32 of 64 bytes");
    let s_bytes: [u8; 32] = compact[32..].try_into().expect("32 of 64 bytes");
    let r = Scalar::from_be_bytes(r_bytes).map_err(|_| MessageError::NoRecoveryId)?;
    let s = Scalar::from_be_bytes(s_bytes).map_err(|_| MessageError::NoRecoveryId)?;
    let e = Scalar::from_be_bytes(*digest).map_err(|_| MessageError::DigestNotAScalar)?;

    let generator = PublicKey::from_slice(&GENERATOR).expect("SEC 2 generator point");
    // eG + rP. `combine` refuses the point at infinity, which is the case P = -(e/r)G: a
    // key that only a signature could have chosen, at probability around 2^-256.
    let expected = pubkey
        .mul_tweak(secp, &r)
        .and_then(|r_p| generator.mul_tweak(secp, &e).and_then(|e_g| r_p.combine(&e_g)))
        .map_err(|_| MessageError::NoRecoveryId)?;

    let mut candidate = [0u8; 33];
    candidate[1..].copy_from_slice(&r_bytes);
    for prefix in [2u8, 3u8] {
        candidate[0] = prefix;
        // A prefix that names no point means r is not the x coordinate of any curve point,
        // which is the reduced case NoRecoveryId is for; the other parity cannot rescue it
        // but trying it keeps the loop one shape.
        let Ok(point) = PublicKey::from_slice(&candidate) else {
            continue;
        };
        let scaled = point.mul_tweak(secp, &s).map_err(|_| MessageError::NoRecoveryId)?;
        if scaled == expected {
            // Compressed prefix 2 is an even y, which is recovery id 0.
            return Ok(prefix - 2);
        }
    }
    Err(MessageError::NoRecoveryId)
}

// ---------------------------------------------------------------------------------------
// Base64
// ---------------------------------------------------------------------------------------

/// The standard base64 alphabet, RFC 4648 section 4. Not the URL-safe one: signed messages
/// are pasted into wallets that decode the standard alphabet, and 62 and 63 are where the
/// two differ.
const BASE64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Base64 with padding.
///
/// Hand written rather than pulled in: it is twenty lines against a new dependency in a
/// crate whose dependency list is itself a security claim.
///
/// `pub(crate)` for its second caller, [`crate::psbt_qr`], which needs the same standard
/// alphabet for the same reason this one does - the string is pasted or scanned into a
/// wallet that decodes RFC 4648 section 4. One encoder rather than two: the vectors below
/// are the only place either of them is pinned.
pub(crate) fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        // Missing tail bytes contribute zero bits, which is what the padding then hides.
        let group = (chunk[0] as u32) << 16
            | (*chunk.get(1).unwrap_or(&0) as u32) << 8
            | (*chunk.get(2).unwrap_or(&0) as u32);
        out.push(BASE64_ALPHABET[(group >> 18) as usize & 0x3f] as char);
        out.push(BASE64_ALPHABET[(group >> 12) as usize & 0x3f] as char);
        out.push(if chunk.len() > 1 {
            BASE64_ALPHABET[(group >> 6) as usize & 0x3f] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            BASE64_ALPHABET[group as usize & 0x3f] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec::Vec;
    use bitcoin::bip32::DerivationPath;
    use bitcoin::secp256k1::SecretKey;
    use bitcoin::{Address, Network};
    use core::str::FromStr;

    use crate::bip39;
    use crate::sign::derive_path;

    /// The mnemonic Trezor's device tests are seeded with (trezor-firmware
    /// `tests/conftest.py`: `mnemonic: str = " ".join(["all"] * 12)`), with no passphrase.
    /// Every Trezor vector below is signed by a key derived from this and nothing else,
    /// which is why each one also pins the address: if the seed were wrong the address
    /// would say so before the signature did.
    const TREZOR_MNEMONIC: &str = "all all all all all all all all all all all all";

    fn trezor_key(path: &str, network: Network) -> SecretSigningKey {
        let seed = bip39::seed(TREZOR_MNEMONIC, "");
        derive_path(&seed, network, &DerivationPath::from_str(path).unwrap()).unwrap()
    }

    fn key_from_hex(hex_scalar: &str, network: Network) -> SecretSigningKey {
        let bytes: [u8; 32] = hex::decode(hex_scalar).unwrap().try_into().unwrap();
        SecretSigningKey::from_secret_bytes(&bytes, network).unwrap()
    }

    /// The address a signature of `kind` is claiming, built here from rust-bitcoin
    /// directly so that a vector's address is checked against the `bitcoin` pin rather
    /// than against another notyas module that could drift with it.
    fn address_of(key: &SecretSigningKey, kind: AddressKind, network: Network) -> String {
        let compressed = key.public_key();
        match kind {
            AddressKind::P2pkhUncompressed => {
                let uncompressed = bitcoin::PublicKey {
                    compressed: false,
                    inner: compressed.0,
                };
                Address::p2pkh(uncompressed, network).to_string()
            }
            AddressKind::P2pkhCompressed => Address::p2pkh(compressed, network).to_string(),
            AddressKind::P2shP2wpkh => Address::p2shwpkh(&compressed, network).to_string(),
            AddressKind::P2wpkh => Address::p2wpkh(&compressed, network).to_string(),
        }
    }

    // -----------------------------------------------------------------------------------
    // The header byte
    // -----------------------------------------------------------------------------------

    /// BIP-137, "Procedure for signing/verifying a signature": the four constants and the
    /// four ranges they open. This is the whole of what the BIP adds to an ECDSA
    /// signature, so it is pinned on its own rather than only through the vectors.
    #[test]
    fn bip137_header_ranges() {
        let ranges = [
            (AddressKind::P2pkhUncompressed, 27u8, 30u8),
            (AddressKind::P2pkhCompressed, 31, 34),
            (AddressKind::P2shP2wpkh, 35, 38),
            (AddressKind::P2wpkh, 39, 42),
        ];
        for (kind, first, last) in ranges {
            assert_eq!(kind.header_base(), first, "{kind:?} base");
            // "The recId is a number between 0 and 3 inclusive."
            assert_eq!(kind.header_base() + 3, last, "{kind:?} top of range");
        }
        // The ranges are contiguous and cover 27..=42 with no gap and no overlap, which is
        // what lets a verifier subtract a constant chosen by range test alone.
        assert_eq!(
            AddressKind::P2pkhUncompressed.header_base() + 12,
            AddressKind::P2wpkh.header_base()
        );
    }

    #[test]
    fn scheme_mapping_covers_exactly_the_single_key_segwit_v0_schemes() {
        assert_eq!(
            AddressKind::for_scheme(Scheme::Bip44),
            Some(AddressKind::P2pkhCompressed)
        );
        assert_eq!(
            AddressKind::for_scheme(Scheme::Bip49),
            Some(AddressKind::P2shP2wpkh)
        );
        assert_eq!(
            AddressKind::for_scheme(Scheme::Bip84),
            Some(AddressKind::P2wpkh)
        );
        // BIP-137 assigns no header to a v1 witness program and a multisig address is not
        // one key's to attest to; neither may be silently mapped onto a range that means
        // something else.
        assert_eq!(AddressKind::for_scheme(Scheme::Bip86), None);
        assert_eq!(AddressKind::for_scheme(Scheme::Bip48), None);
    }

    // -----------------------------------------------------------------------------------
    // The digest
    // -----------------------------------------------------------------------------------

    #[test]
    fn magic_is_the_string_core_prefixes_with_its_own_length() {
        assert_eq!(MESSAGE_MAGIC, "Bitcoin Signed Message:\n");
        assert_eq!(MESSAGE_MAGIC.len(), 24);
        // 24 is 0x18, the byte every implementation writes at the front of the preimage.
        let mut buf = [0u8; 9];
        assert_eq!(compact_size(MESSAGE_MAGIC.len() as u64, &mut buf), [0x18]);
    }

    /// Published vectors: bitcoinjs-message `test/fixtures.json`, `valid.magicHash`.
    ///
    /// These pin the preimage without involving a key at all, which is what makes them
    /// worth having beside the signature vectors: a wrong magic string, a missing length
    /// prefix or a normalized message all fail here first, and fail readably.
    #[test]
    fn magic_hash_vectors() {
        // bitcoinjs-message fixtures.json, valid.magicHash[0], network "bitcoin", message "".
        assert_eq!(
            hex::encode(hash(b"")),
            "80e795d4a4caadd7047af389d9f7f220562feb6196032e2131e10563352c4bcc"
        );
        // valid.magicHash[1], message "Vires is Numeris".
        assert_eq!(
            hex::encode(hash(b"Vires is Numeris")),
            "f8a5affbef4a3241b19067aa694562f64f513310817297089a8929a930f4f933"
        );
        // valid.magicHash[2], message "Vir\u{e8}s is Num\u{e9}ris". Spelled as bytes
        // because the fixture is UTF-8 and precomposed, and because the point of the
        // vector is that those exact bytes are hashed: no normalization, no re-encoding.
        let accented = b"Vir\xc3\xa8s is Num\xc3\xa9ris";
        assert_eq!(
            hex::encode(hash(accented)),
            "af3d51b82a6694d76af5b49401d6f824d66cfce6f96213e606e7da95fe675f25"
        );
    }

    /// A message long enough to need a three-byte CompactSize is hashed with one, and the
    /// boundary is where Core's serializer puts it: 253 is the first length that is not
    /// its own prefix.
    #[test]
    fn compact_size_boundaries() {
        let mut buf = [0u8; 9];
        assert_eq!(compact_size(0, &mut buf), [0x00]);
        assert_eq!(compact_size(252, &mut buf), [0xfc]);
        assert_eq!(compact_size(253, &mut buf), [0xfd, 0xfd, 0x00]);
        assert_eq!(compact_size(0xffff, &mut buf), [0xfd, 0xff, 0xff]);
        assert_eq!(compact_size(0x1_0000, &mut buf), [0xfe, 0x00, 0x00, 0x01, 0x00]);
        assert_eq!(
            compact_size(0xffff_ffff, &mut buf),
            [0xfe, 0xff, 0xff, 0xff, 0xff]
        );
        assert_eq!(
            compact_size(0x1_0000_0000, &mut buf),
            [0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]
        );
    }

    /// The length prefix is what stops one message's signature from being read as another
    /// message's. Two messages whose concatenation with a plausible neighbour is identical
    /// must not hash the same.
    #[test]
    fn length_prefix_separates_messages_that_share_a_concatenation() {
        assert_ne!(hash(b"ab"), hash(b"a\x00b"));
        assert_ne!(hash(b"aab"), hash(b"aa"));
    }

    // -----------------------------------------------------------------------------------
    // Base64
    // -----------------------------------------------------------------------------------

    /// RFC 4648 section 10, "Test Vectors". Pinned because the padding rules are the part
    /// a hand written encoder gets wrong, and a signature is always a padded tail.
    #[test]
    fn rfc4648_test_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        // The high two alphabet entries, which are where the URL-safe alphabet differs.
        assert_eq!(base64_encode(&[0xfb, 0xef, 0xbe]), "++++");
        assert_eq!(base64_encode(&[0xff, 0xff, 0xff]), "////");
    }

    // -----------------------------------------------------------------------------------
    // The curve constant
    // -----------------------------------------------------------------------------------

    /// The generator this module hardcodes is the generator libsecp256k1 uses, checked by
    /// asking it for the public key of the scalar 1.
    #[test]
    fn generator_constant_is_the_curve_generator() {
        let mut one = [0u8; 32];
        one[31] = 1;
        let from_library = PublicKey::from_secret_key(secp(), &SecretKey::from_slice(&one).unwrap());
        assert_eq!(from_library.serialize(), GENERATOR);
    }

    // -----------------------------------------------------------------------------------
    // Published signing vectors
    // -----------------------------------------------------------------------------------

    /// Published vector: Bitcoin Core `src/test/util_tests.cpp`, `BOOST_AUTO_TEST_CASE
    /// (message_sign)`. The private key and expected base64 are verbatim from that test,
    /// as is the address in its comment ("derived address from this private key").
    ///
    /// This is the reference implementation signing a message with a compressed key, so it
    /// is what pins the digest, the RFC 6979 nonce and the 31-range header together.
    #[test]
    fn bitcoin_core_message_sign_vector() {
        let key = key_from_hex(
            "d97f5108f11cda6eeebaaa420fef0726b1f898060b98489fa3098463c0032866",
            Network::Bitcoin,
        );
        assert_eq!(
            address_of(&key, AddressKind::P2pkhCompressed, Network::Bitcoin),
            "15CRxFdyRpGZLW9w8HnHvVduizdL5jKNbs"
        );

        let signed = sign(&key, AddressKind::P2pkhCompressed, b"Trust no one").unwrap();
        assert_eq!(
            signed.to_base64(),
            "IPojfrX2dfPnH26UegfbGQQLrdK844DlHq5157/P6h57WyuS/Qsl+h/WSVGDF4MUi4rWSswW38oimDYfNNUBUOk="
        );
        // 0x20: the compressed P2PKH constant, 31, plus recovery id 1.
        assert_eq!(signed.header(), 32);
        assert_eq!(signed.recovery_id(), 1);
    }

    /// Published vectors: bitcoinjs-message `test/fixtures.json`, `valid.sign[0]`,
    /// "gives equal r, s values irrespective of point compression or segwit type".
    /// Private key d = 1 (the fixture's `"d": "1"` is a decimal `BigInteger`), message
    /// "vires is numeris".
    ///
    /// One key and one message across all four header ranges is the vector this module
    /// most needs: it shows that the ranges are the only thing that varies, which is the
    /// claim BIP-137 makes and the thing an implementation gets wrong.
    #[test]
    fn bitcoinjs_all_four_address_kinds() {
        let key = key_from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
            Network::Bitcoin,
        );
        let message = b"vires is numeris";

        let cases = [
            // valid.sign[0].signature, header 0x1c = 27 + 1.
            (
                AddressKind::P2pkhUncompressed,
                "HF8nHqFr3K2UKYahhX3soVeoW8W1ECNbr0wfck7lzyXjCS5Q16Ek45zyBuy1Fiy9sTPKVgsqqOuPvbycuVSSVl8=",
                28u8,
            ),
            // valid.sign[0].compressed.signature, header 0x20 = 31 + 1.
            (
                AddressKind::P2pkhCompressed,
                "IF8nHqFr3K2UKYahhX3soVeoW8W1ECNbr0wfck7lzyXjCS5Q16Ek45zyBuy1Fiy9sTPKVgsqqOuPvbycuVSSVl8=",
                32,
            ),
            // valid.sign[0].segwit.P2SH_P2WPKH.signature, header 0x24 = 35 + 1.
            (
                AddressKind::P2shP2wpkh,
                "JF8nHqFr3K2UKYahhX3soVeoW8W1ECNbr0wfck7lzyXjCS5Q16Ek45zyBuy1Fiy9sTPKVgsqqOuPvbycuVSSVl8=",
                36,
            ),
            // valid.sign[0].segwit.P2WPKH.signature, header 0x28 = 39 + 1.
            (
                AddressKind::P2wpkh,
                "KF8nHqFr3K2UKYahhX3soVeoW8W1ECNbr0wfck7lzyXjCS5Q16Ek45zyBuy1Fiy9sTPKVgsqqOuPvbycuVSSVl8=",
                40,
            ),
        ];

        let mut bodies = Vec::new();
        for (kind, expected, header) in cases {
            let signed = sign(&key, kind, message).unwrap();
            assert_eq!(signed.to_base64(), expected, "{kind:?}");
            assert_eq!(signed.header(), header, "{kind:?}");
            assert_eq!(signed.recovery_id(), 1, "{kind:?}");
            assert_eq!(signed.to_base64().len(), SIGNATURE_BASE64_LEN);
            bodies.push(signed.to_bytes()[1..].to_vec());
        }
        // The fixture's own description, restated as an assertion: only the header moves.
        assert!(bodies.windows(2).all(|pair| pair[0] == pair[1]));

        // The addresses those last two headers claim, from the same fixture file
        // (`valid.verify[0].segwit.*.address`, which reuses this key). The bech32 one is
        // also BIP-173's own P2WPKH example, since the public key of the scalar 1 is the
        // generator that example is built on.
        assert_eq!(
            address_of(&key, AddressKind::P2shP2wpkh, Network::Bitcoin),
            "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN"
        );
        assert_eq!(
            address_of(&key, AddressKind::P2wpkh, Network::Bitcoin),
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        );
        // The two P2PKH ranges exist because one key has two P2PKH addresses, and a
        // verifier told only "P2PKH" cannot tell which of them to build.
        assert_ne!(
            address_of(&key, AddressKind::P2pkhUncompressed, Network::Bitcoin),
            address_of(&key, AddressKind::P2pkhCompressed, Network::Bitcoin)
        );
    }

    /// Published vectors: trezor-firmware `tests/device_tests/bitcoin/test_signmessage.py`,
    /// `VECTORS`. Each tuple there is (case, coin, path, script type, no_script_type,
    /// address, message, signature); the signatures are hex of the full 65 bytes.
    ///
    /// An independent implementation, an independent key derivation and the segwit ranges
    /// exercised end to end from a mnemonic, which is the path this device actually walks.
    #[test]
    fn trezor_bitcoin_vectors() {
        let message = b"This is an example of a signed message.";
        let cases = [
            // case "p2pkh", Bitcoin, m/44h/0h/0h/0/0.
            (
                "m/44'/0'/0'/0/0",
                AddressKind::P2pkhCompressed,
                "1JAd7XCBzGudGpJQSDSfpmJhiygtLQWaGL",
                "20fd8f2f7db5238fcdd077d5204c3e6949c261d700269cefc1d9d2dcef6b95023630ee617f6c8acf9eb40c8edd704c9ca74ea4afc393f43f35b4e8958324cbdd1c",
            ),
            // case "segwit-p2sh", Bitcoin, m/49h/0h/0h/0/0.
            (
                "m/49'/0'/0'/0/0",
                AddressKind::P2shP2wpkh,
                "3L6TyTisPBmrDAj6RoKmDzNnj4eQi54gD2",
                "23744de4516fac5c140808015664516a32fead94de89775cec7e24dbc24fe133075ac09301c4cc8e197bea4b6481661d5b8e9bf19d8b7b8a382ecdb53c2ee0750d",
            ),
            // case "segwit-native", Bitcoin, m/84h/0h/0h/0/0.
            (
                "m/84'/0'/0'/0/0",
                AddressKind::P2wpkh,
                "bc1qannfxke2tfd4l7vhepehpvt05y83v3qsf6nfkk",
                "28b55d7600d9e9a7e2a49155ddf3cfdb8e796c207faab833010fa41fb7828889bc47cf62348a7aaa0923c0832a589fab541e8f12eb54fb711c90e2307f0f66b194",
            ),
        ];

        for (path, kind, address, expected) in cases {
            let key = trezor_key(path, Network::Bitcoin);
            assert_eq!(address_of(&key, kind, Network::Bitcoin), address, "{path}");
            let signed = sign(&key, kind, message).unwrap();
            assert_eq!(hex::encode(signed.to_bytes()), expected, "{path}");
        }
    }

    /// Published vectors: the Testnet cases of the same Trezor `VECTORS` table. The network
    /// changes the address and nothing about the signature, which is the point: the digest
    /// has no network in it, so a testnet key and a mainnet key sign identically and only
    /// the address the signature claims differs.
    #[test]
    fn trezor_testnet_vectors() {
        let message = b"This is an example of a signed message.";
        let cases = [
            (
                "m/44'/1'/0'/0/0",
                AddressKind::P2pkhCompressed,
                "mvbu1Gdy8SUjTenqerxUaZyYjmveZvt33q",
                "2030cd7f116c0481d1936cfef48137fd23ee56aaf00787bfa08a94837466ec9909390c3efacfc56bae5782f1db4cf49ae05f242b5f62a47f871ec46bf1a3253e7f",
            ),
            (
                "m/49'/1'/0'/0/0",
                AddressKind::P2shP2wpkh,
                "2N4Q5FhU2497BryFfUgbqkAJE87aKHUhXMp",
                "23ef39fd388c3425d6aaa04274dcd5c7dd4c283a411b616443474fbcde5dd966050d91bc7c57e9578f28efdd84c9a9bcba415f93c5727b5d3f2bf3de46d7084896",
            ),
            (
                "m/84'/1'/0'/0/0",
                AddressKind::P2wpkh,
                "tb1qkvwu9g3k2pdxewfqr7syz89r3gj557l3uuf9r9",
                "27758b3393396ad9fe48f6ce81f63410145e7b2b69a5dfc1d48b5e6e623e91e08e3afb60bda1546f9c6f9fb5bd0a41887b784c266036dd4b4015a0abc1137daa1d",
            ),
        ];

        for (path, kind, address, expected) in cases {
            let key = trezor_key(path, Network::Testnet);
            assert_eq!(address_of(&key, kind, Network::Testnet), address, "{path}");
            let signed = sign(&key, kind, message).unwrap();
            assert_eq!(hex::encode(signed.to_bytes()), expected, "{path}");
        }
    }

    /// Published vectors: the `no_script_type=True` rows of the same Trezor table, which
    /// sign the identical messages with the identical keys but ask for the legacy header.
    ///
    /// They are the cleanest available proof that the header offset is the only thing an
    /// address type changes: Trezor's own corpus states the same r and s twice, once under
    /// 0x23/0x28 and once under 0x1f/0x20.
    #[test]
    fn trezor_legacy_headers_over_segwit_keys() {
        let message = b"This is an example of a signed message.";
        let cases = [
            // case "segwit-p2sh", no_script_type=True: header 0x1f = 31 + 0.
            (
                "m/49'/0'/0'/0/0",
                "1f744de4516fac5c140808015664516a32fead94de89775cec7e24dbc24fe133075ac09301c4cc8e197bea4b6481661d5b8e9bf19d8b7b8a382ecdb53c2ee0750d",
                "23744de4516fac5c140808015664516a32fead94de89775cec7e24dbc24fe133075ac09301c4cc8e197bea4b6481661d5b8e9bf19d8b7b8a382ecdb53c2ee0750d",
            ),
            // case "segwit-native", no_script_type=True: header 0x20 = 31 + 1.
            (
                "m/84'/0'/0'/0/0",
                "20b55d7600d9e9a7e2a49155ddf3cfdb8e796c207faab833010fa41fb7828889bc47cf62348a7aaa0923c0832a589fab541e8f12eb54fb711c90e2307f0f66b194",
                "28b55d7600d9e9a7e2a49155ddf3cfdb8e796c207faab833010fa41fb7828889bc47cf62348a7aaa0923c0832a589fab541e8f12eb54fb711c90e2307f0f66b194",
            ),
        ];

        for (path, legacy, segwit) in cases {
            let key = trezor_key(path, Network::Bitcoin);
            let signed = sign(&key, AddressKind::P2pkhCompressed, message).unwrap();
            assert_eq!(hex::encode(signed.to_bytes()), legacy, "{path}");
            // Same 64 bytes under the segwit header, one byte apart at the front.
            assert_eq!(&hex::encode(signed.to_bytes())[2..], &segwit[2..], "{path}");
        }
    }

    /// Published vector: the "t1 firmware path" case of the same Trezor table,
    /// m/10026h/826421588h/2h/0h over a 32-byte non-text message.
    ///
    /// Two things this pins that the other vectors do not: an arbitrary hardened path of a
    /// depth the address schemes never produce, and a message that is bytes rather than
    /// text, which is what [`hash`] takes and why it takes it.
    #[test]
    fn trezor_arbitrary_path_and_byte_message() {
        let key = trezor_key("m/10026'/826421588'/2'/0'", Network::Bitcoin);
        assert_eq!(
            address_of(&key, AddressKind::P2pkhCompressed, Network::Bitcoin),
            "1FoHjQT6bAEu2FQGzTgqj4PBneoiCAk4ZN"
        );
        let signed = sign(
            &key,
            AddressKind::P2pkhCompressed,
            b"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        )
        .unwrap();
        assert_eq!(
            hex::encode(signed.to_bytes()),
            "1f40ae58dd68480a2f39eecf4decfe79ceacde3f865502db67c083b8465b33535c0750d5377b7ac62e534f71c922cd029f659761f8ac99e859df36322c5b320eff"
        );
    }

    // -----------------------------------------------------------------------------------
    // Properties
    // -----------------------------------------------------------------------------------

    /// No RNG anywhere means the same key and message always produce the same bytes, which
    /// is what makes a signature reproducible off the device (SECURITY.md invariant 3).
    #[test]
    fn signing_is_deterministic() {
        let key = trezor_key("m/84'/0'/0'/0/0", Network::Bitcoin);
        let first = sign(&key, AddressKind::P2wpkh, b"repeat me").unwrap();
        let second = sign(&key, AddressKind::P2wpkh, b"repeat me").unwrap();
        assert_eq!(first, second);
    }

    /// A signature verifies against its own key and message and nothing else. The middle
    /// case is the one worth having: a signature that has had its recovery id nudged still
    /// carries valid ECDSA, so only the recovery half of the check can reject it.
    #[test]
    fn verify_accepts_only_its_own_message_and_recovery_id() {
        let key = trezor_key("m/44'/0'/0'/0/0", Network::Bitcoin);
        let pubkey = key.public_key().0;
        let signed = sign(&key, AddressKind::P2pkhCompressed, b"attested").unwrap();

        assert!(signed.verify(&pubkey, b"attested"));
        assert!(!signed.verify(&pubkey, b"attested "));

        let mut wrong_recovery = signed;
        wrong_recovery.recovery = 1 - signed.recovery_id();
        assert!(!wrong_recovery.verify(&pubkey, b"attested"));

        let other = trezor_key("m/44'/0'/0'/0/1", Network::Bitcoin);
        assert!(!signed.verify(&other.public_key().0, b"attested"));
    }

    /// A single flipped bit anywhere in r or s is rejected. This is the fault case
    /// [`MessageError::FaultCheck`] exists for, exercised on the check rather than by
    /// faulting the signer.
    #[test]
    fn verify_rejects_a_corrupted_body() {
        let key = trezor_key("m/84'/0'/0'/0/0", Network::Bitcoin);
        let pubkey = key.public_key().0;
        let signed = sign(&key, AddressKind::P2wpkh, b"attested").unwrap();

        for byte in [0usize, 31, 32, 63] {
            let mut corrupted = signed;
            corrupted.compact[byte] ^= 0x01;
            assert!(
                !corrupted.verify(&pubkey, b"attested"),
                "flipped bit in byte {byte} accepted"
            );
        }
    }

    /// The empty message is a message. It has a CompactSize of zero and a digest like any
    /// other, and refusing it here would only push the special case into the caller.
    #[test]
    fn empty_message_signs_and_verifies() {
        let key = trezor_key("m/44'/0'/0'/0/0", Network::Bitcoin);
        let signed = sign(&key, AddressKind::P2pkhCompressed, b"").unwrap();
        assert!(signed.verify(&key.public_key().0, b""));
        assert_eq!(signed.to_bytes().len(), SIGNATURE_LEN);
    }

    /// A message long enough that its length needs two bytes of CompactSize round-trips,
    /// so the boundary tested on `compact_size` above is also reached through `hash`.
    #[test]
    fn long_message_crosses_the_compact_size_boundary() {
        let key = trezor_key("m/44'/0'/0'/0/0", Network::Bitcoin);
        let pubkey = key.public_key().0;
        let long = alloc::vec![b'x'; 1000];
        let signed = sign(&key, AddressKind::P2pkhCompressed, &long).unwrap();
        assert!(signed.verify(&pubkey, &long));
        // One byte shorter is a different message, and the length prefix says so.
        assert!(!signed.verify(&pubkey, &long[..999]));
    }

    #[test]
    fn header_is_the_kind_plus_the_recovery_id_for_every_kind() {
        let key = trezor_key("m/44'/0'/0'/0/0", Network::Bitcoin);
        for kind in [
            AddressKind::P2pkhUncompressed,
            AddressKind::P2pkhCompressed,
            AddressKind::P2shP2wpkh,
            AddressKind::P2wpkh,
        ] {
            let signed = sign(&key, kind, b"header check").unwrap();
            assert_eq!(signed.address_kind(), kind);
            assert_eq!(signed.header(), kind.header_base() + signed.recovery_id());
            assert!((27..=42).contains(&signed.header()));
            assert_eq!(signed.to_bytes()[0], signed.header());
        }
    }

    #[test]
    fn error_display_is_the_sentence_a_screen_shows() {
        assert_eq!(
            MessageError::NoRecoveryId.to_string(),
            "no recovery id fits the signature"
        );
        assert_eq!(
            MessageError::FaultCheck.to_string(),
            "signature failed its own verification"
        );
        assert_eq!(
            MessageError::DigestNotAScalar.to_string(),
            "message digest is not a valid scalar"
        );
    }
}
