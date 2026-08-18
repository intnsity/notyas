// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The key ladder, byte-exact per ESP-SEAL.md 4.1.
//!
//! ```text
//! hmac_efuse(tag, msg) = HMAC-SHA256_{eFuse key}( tag || msg )      // tag is one byte
//!
//! device_binding = hmac_efuse(0x01, domain_tag)
//! guard_key      = HKDF(device_binding, salt=domain_tag, info=b"esp-seal/guard/v1")
//! hdr_key        = HKDF(device_binding, salt=domain_tag, info=b"esp-seal/hdr/v1")
//! filler_root    = HKDF(device_binding, salt=domain_tag, info=b"esp-seal/filler/v1")
//! kdf_salt       = SHA256(domain_tag || b"esp-seal/salt/v1" || device_binding)
//! prestretch     = Argon2id(pin, kdf_salt, m, t, p=1, 32)
//! bound          = hmac_efuse(0x02, prestretch)
//! okm            = HKDF(bound, salt=kdf_salt, info=RecordInfo)      // 44 bytes
//! key, nonce     = okm[0..32], okm[32..44]
//! ```
//!
//! Two rules about the eFuse-keyed MAC are load-bearing rather than tidy. First, every
//! internal call carries a fixed one-byte tag followed by a FIXED-LENGTH payload.
//! Second, every embedder-facing derivation goes through [`device_derive`], which uses
//! tag `0x7f` and length-prefixes its inputs. Together those mean an attacker who can
//! choose the input to an embedder-facing derivation (the anti-phishing words take a
//! partial PIN) can never steer it into colliding with `0x02 || prestretch`.
//!
//! `user_root` from ESP-SEAL.md 4.1 is deliberately absent: nothing in the design ever
//! consumes it, and an unused key in a ladder is a liability rather than an asset.

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::hal::{DeviceMac, KeyProvenance, Scratch};
use crate::{FORMAT_VERSION, SUITE_ID};

type HmacSha256 = Hmac<Sha256>;

/// Domain-separation tags for the eFuse-keyed MAC. Internal tags are 0x01..0x0f and are
/// always followed by a fixed-length payload.
const TAG_DEVICE_BINDING: u8 = 0x01;
const TAG_BOUND: u8 = 0x02;
/// Every embedder-facing derivation, with length-prefixed inputs.
const TAG_DEVICE_DERIVE: u8 = 0x7f;

const INFO_GUARD: &[u8] = b"esp-seal/guard/v1";
const INFO_HDR: &[u8] = b"esp-seal/hdr/v1";
const INFO_FILLER: &[u8] = b"esp-seal/filler/v1";
const SALT_LABEL: &[u8] = b"esp-seal/salt/v1";

/// Everything derivable from the device alone, computed once at mount.
///
/// None of it depends on a PIN, which is exactly why mount can validate headers, scan
/// the guarded ledger and identify filler with no secret from the user.
pub(crate) struct DeviceKeys {
    pub guard_key: Zeroizing<[u8; 32]>,
    pub hdr_key: Zeroizing<[u8; 32]>,
    pub filler_root: Zeroizing<[u8; 32]>,
    pub kdf_salt: [u8; 32],
    /// Stable 8-byte device fingerprint written into the superblock, so "this flash came
    /// from another board" is distinguishable from "this flash is corrupt".
    pub device_tag: [u8; 8],
    pub provenance: KeyProvenance,
}

/// The post-Argon2, post-HMAC session secret. PIN-equivalent for this device while it
/// lives, which is why the session owns exactly this and nothing else.
pub struct Bound(Zeroizing<[u8; 32]>);

impl Bound {
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Constant-time equality, for `confirm_pin`.
    pub(crate) fn ct_eq(&self, other: &Bound) -> bool {
        self.0.as_slice().ct_eq(other.0.as_slice()).into()
    }
}

impl core::fmt::Debug for Bound {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Bound(<redacted>)")
    }
}

/// HMAC-SHA256 under the read-protected eFuse key, with a one-byte domain tag.
///
/// The payload length is a const generic rather than a slice length, and the buffer is
/// sized from it, so an internal message that outgrew its staging buffer is a compile
/// error. That matters more than it looks: silently truncating the message would make two
/// different internal derivations collide, and the whole reason for the tag byte is that
/// two derivations must never collide.
fn hmac_efuse<M: DeviceMac, const N: usize>(
    mac: &mut M,
    tag: u8,
    msg: &[u8; N],
) -> Result<Zeroizing<[u8; 32]>, M::Error> {
    let mut out = Zeroizing::new([0u8; 32]);
    let mut buf = Zeroizing::new([0u8; N]);
    buf.copy_from_slice(msg);
    let mut framed = Zeroizing::new(alloc::vec::Vec::with_capacity(N.saturating_add(1)));
    framed.push(tag);
    framed.extend_from_slice(buf.as_slice());
    mac.hmac(framed.as_slice(), &mut out)?;
    Ok(out)
}

/// HKDF-SHA256 into a fixed-size output.
pub(crate) fn hkdf<const N: usize>(ikm: &[u8], salt: &[u8], info: &[u8]) -> Zeroizing<[u8; N]> {
    let mut out = Zeroizing::new([0u8; N]);
    let h = Hkdf::<Sha256>::new(Some(salt), ikm);
    // `expand` fails only for N > 255*32; every call site is a compile-time constant far
    // below that, so a failure here is a bug and it leaves the output zeroed rather than
    // panicking on a secret path.
    let _ = h.expand(info, out.as_mut_slice());
    out
}

/// Keyed MAC over a sequence of parts, truncated to 16 bytes. Used for `header_mac`,
/// `body_digest` and every guarded ledger cell.
///
/// Taking the parts as a slice rather than concatenating into a buffer is not a
/// convenience: it removes the possibility of a heap or stack buffer sized for the
/// biggest caller and silently truncating a smaller one.
pub(crate) fn mac16(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 16] {
    let full = mac32(key, parts);
    let mut out = [0u8; 16];
    if let Some(src) = full.get(..16) {
        out.copy_from_slice(src);
    }
    out
}

pub(crate) fn mac8(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 8] {
    let full = mac32(key, parts);
    let mut out = [0u8; 8];
    if let Some(src) = full.get(..8) {
        out.copy_from_slice(src);
    }
    out
}

pub(crate) fn mac32(key: &[u8; 32], parts: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    // A 32-byte key is always a valid HMAC key length, so this cannot fail; the branch
    // exists so that the impossible case returns zeros rather than unwinding.
    if let Ok(mut h) = HmacSha256::new_from_slice(key.as_slice()) {
        for p in parts {
            h.update(p);
        }
        out.copy_from_slice(&h.finalize().into_bytes());
    }
    out
}

/// Derive everything that depends only on the device.
pub(crate) fn device_keys<M: DeviceMac>(
    mac: &mut M,
    domain_tag: &[u8; 16],
) -> Result<DeviceKeys, M::Error> {
    let device_binding = hmac_efuse(mac, TAG_DEVICE_BINDING, domain_tag)?;

    let guard_key = hkdf::<32>(device_binding.as_slice(), domain_tag, INFO_GUARD);
    let hdr_key = hkdf::<32>(device_binding.as_slice(), domain_tag, INFO_HDR);
    let filler_root = hkdf::<32>(device_binding.as_slice(), domain_tag, INFO_FILLER);

    let mut hasher = Sha256::new();
    hasher.update(domain_tag);
    hasher.update(SALT_LABEL);
    hasher.update(device_binding.as_slice());
    let mut kdf_salt = [0u8; 32];
    kdf_salt.copy_from_slice(&hasher.finalize());

    let mut device_tag = [0u8; 8];
    if let Some(src) = device_binding.get(..8) {
        device_tag.copy_from_slice(src);
    }

    Ok(DeviceKeys {
        guard_key,
        hdr_key,
        filler_root,
        kdf_salt,
        device_tag,
        provenance: mac.provenance(),
    })
}

/// Argon2id over the PIN into the caller's working memory.
///
/// The scratch buffer is zeroized on every path out of here, including the error paths:
/// it is the largest secret-bearing region in the system.
pub(crate) fn prestretch(
    pin: &[u8],
    kdf_salt: &[u8; 32],
    params: &crate::config::KdfParams,
    scratch: &mut Scratch<'_>,
) -> Option<Zeroizing<[u8; 32]>> {
    let p = params.params()?;
    let hasher = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, p);
    let mut out = Zeroizing::new([0u8; 32]);
    let result = hasher.hash_password_into_with_memory(
        pin,
        kdf_salt.as_slice(),
        out.as_mut_slice(),
        scratch.blocks_mut(),
    );
    scratch.wipe();
    result.ok().map(|()| out)
}

/// The second wall: bind the memory-hard result to this physical board.
pub(crate) fn bind<M: DeviceMac>(
    mac: &mut M,
    prestretch: &[u8; 32],
) -> Result<Bound, M::Error> {
    Ok(Bound(hmac_efuse(mac, TAG_BOUND, prestretch)?))
}

/// Longest label and longest data [`device_derive`] will accept.
///
/// Generous for what the embedder actually does with it - a fixed word-list label and a
/// partial PIN - and bounded because the framing has to be, see below.
pub(crate) const DERIVE_MAX_LABEL: usize = 64;
pub(crate) const DERIVE_MAX_DATA: usize = 256;

/// Embedder-facing device-bound derivation: anti-phishing words, the PIN-pad permutation,
/// lock-screen words.
///
/// Tag `0x7f` and length-prefixed inputs, so it can never collide with an internal
/// message, whose payloads are fixed-length and whose tags are `0x01..0x0f`. That
/// separation is load-bearing: the anti-phishing words are derived from a partial PIN,
/// i.e. from attacker-chosen input to the same eFuse key that produces `bound`, and
/// without it a chosen-prefix query could be steered to collide with `0x02 || prestretch`.
///
/// Oversized inputs are REFUSED rather than truncated. An earlier version silently dropped
/// everything past a 96-byte staging buffer, which would have let `(label, data)` pairs
/// that differ only past the cut produce the same words - the exact collision the length
/// prefix exists to prevent, reintroduced by the buffer behind it.
pub(crate) fn device_derive<M: DeviceMac>(
    mac: &mut M,
    label: &[u8],
    data: &[u8],
    out: &mut [u8],
) -> Result<bool, M::Error> {
    if label.len() > DERIVE_MAX_LABEL || data.len() > DERIVE_MAX_DATA {
        return Ok(false);
    }
    // Lengths are bounded above by the constants just checked, so both casts are exact.
    let llen = (label.len() as u16).to_le_bytes();
    let dlen = (data.len() as u16).to_le_bytes();
    let mut msg = Zeroizing::new(alloc::vec::Vec::with_capacity(
        DERIVE_MAX_LABEL
            .saturating_add(DERIVE_MAX_DATA)
            .saturating_add(5),
    ));
    msg.push(TAG_DEVICE_DERIVE);
    msg.extend_from_slice(&llen);
    msg.extend_from_slice(label);
    msg.extend_from_slice(&dlen);
    msg.extend_from_slice(data);

    let mut root = Zeroizing::new([0u8; 32]);
    mac.hmac(msg.as_slice(), &mut root)?;

    // HKDF over the MAC so the caller can ask for any output size without the framing
    // changing, and so an output length is never itself a domain separator by accident.
    let h = Hkdf::<Sha256>::new(None, root.as_slice());
    let _ = h.expand(b"esp-seal/device-derive/v1", out);
    Ok(true)
}

/// The 40-byte HKDF `info` that separates every record key from every other one.
///
/// Fixed-width little-endian throughout, never a concatenation of variable-length
/// pieces: a length-ambiguous info string is how two different records end up with one
/// key.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct RecordInfo {
    pub slot_class: u8,
    pub slot_index: u8,
    pub slot_side: u8,
    pub provenance: u8,
    pub wipe_epoch: u64,
    pub pin_gen: u32,
    pub seal_seq: u64,
    pub domain_prefix: [u8; 8],
}

impl RecordInfo {
    pub const LEN: usize = 40;

    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut b = [0u8; Self::LEN];
        let _ = crate::bytes::wr(&mut b, 0, b"ESL1");
        let _ = crate::bytes::wr_u16(&mut b, 4, SUITE_ID);
        let _ = crate::bytes::wr_u16(&mut b, 6, FORMAT_VERSION);
        let _ = crate::bytes::wr_u8(&mut b, 8, self.slot_class);
        let _ = crate::bytes::wr_u8(&mut b, 9, self.slot_index);
        let _ = crate::bytes::wr_u8(&mut b, 10, self.slot_side);
        let _ = crate::bytes::wr_u8(&mut b, 11, self.provenance);
        let _ = crate::bytes::wr_u64(&mut b, 12, self.wipe_epoch);
        let _ = crate::bytes::wr_u32(&mut b, 20, self.pin_gen);
        let _ = crate::bytes::wr_u64(&mut b, 24, self.seal_seq);
        let _ = crate::bytes::wr(&mut b, 32, &self.domain_prefix);
        b
    }
}

/// A record key and its nonce. Never `Clone`; zeroized on drop.
pub(crate) struct Okm(Zeroizing<[u8; 44]>);

impl Okm {
    pub fn key(&self) -> [u8; 32] {
        let mut k = [0u8; 32];
        if let Some(src) = self.0.get(..32) {
            k.copy_from_slice(src);
        }
        k
    }

    pub fn nonce(&self) -> [u8; 12] {
        let mut n = [0u8; 12];
        if let Some(src) = self.0.get(32..44) {
            n.copy_from_slice(src);
        }
        n
    }

    pub fn ct_eq(&self, other: &Okm) -> bool {
        self.0.as_slice().ct_eq(other.0.as_slice()).into()
    }
}

/// `okm = HKDF-SHA256(ikm = key_source, salt = kdf_salt, info = RecordInfo)`.
///
/// `key_source` is `bound` for a PIN-sealed record and `filler_root` for filler. Nothing
/// else in the crate produces a record key.
pub(crate) fn record_okm(key_source: &[u8; 32], kdf_salt: &[u8; 32], info: &RecordInfo) -> Okm {
    Okm(hkdf::<44>(key_source, kdf_salt, &info.encode()))
}

/// ChaCha20-Poly1305 seal in place. Returns the 16-byte tag.
pub(crate) fn aead_seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
) -> Option<[u8; 16]> {
    use chacha20poly1305::{AeadInOut, ChaCha20Poly1305, KeyInit};
    // The one place an encryption happens, and therefore the one place the fuzzer has to
    // watch to assert that no (key, nonce) pair is ever used twice (ESP-SEAL.md 8.1 I6).
    #[cfg(feature = "testkit")]
    crate::probe::note_seal(key, nonce);
    let cipher = ChaCha20Poly1305::new(&(*key).into());
    let tag = cipher
        .encrypt_inout_detached(&(*nonce).into(), aad, buf.into())
        .ok()?;
    let mut out = [0u8; 16];
    out.copy_from_slice(tag.as_slice());
    Some(out)
}

/// ChaCha20-Poly1305 open in place. `false` means the tag did not verify, and the buffer
/// must be treated as garbage by the caller (it is overwritten either way).
pub(crate) fn aead_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8; 16],
) -> bool {
    use chacha20poly1305::{AeadInOut, ChaCha20Poly1305, KeyInit};
    let cipher = ChaCha20Poly1305::new(&(*key).into());
    cipher
        .decrypt_inout_detached(&(*nonce).into(), aad, buf.into(), &(*tag).into())
        .is_ok()
}

/// Constant-time byte comparison, for every secret and every MAC.
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}
