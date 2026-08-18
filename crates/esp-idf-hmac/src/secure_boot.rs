// SPDX-FileCopyrightText: 2026 intnsity
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Secure Boot v2 state: whether it is on, and whose keys it trusts.
//!
//! The second half is the interesting one. "Secure boot enabled" is a
//! checkbox; the SHA-256 digests of the enrolled public keys say **which**
//! signing key the boot ROM will accept, and that is comparable off-device
//! against `espsecure.py digest_sbv2_public_key` run on a published key.
//!
//! Those digests are readable by design, not by oversight. ESP-IDF's
//! `esp_efuse_write_key()` read-protects a block for the XTS, ECDSA, HMAC and
//! Key Manager purposes and deliberately does not for the three
//! `SECURE_BOOT_DIGEST` purposes, and the Secure Boot v2 documentation states
//! the requirement in words: the key must be readable so software can access
//! it, write-protected but not read-protected. A digest of a public key is not
//! a secret.
//!
//! One trap this module closes. `esp_efuse_read_block()` performs no `RD_DIS`
//! check: a read-protected block returns `ESP_OK` and a row of zeros, and
//! `esp_secure_boot_read_key_digests()` hands back a pointer into the same read
//! registers with the same result. Thirty-two zero bytes rendered as a digest
//! would be the single worst value a verification readout could show, so the
//! read protection is checked first and the slot reports
//! [`DigestSlot::ReadProtected`] instead.

use crate::key_block::{KeyBlock, KeyPurpose};

/// ESP32-P4's `SOC_EFUSE_SECURE_BOOT_KEY_DIGESTS`. Other parts with Secure Boot
/// v2 use the same number; parts with none do not build this crate's readers.
pub const DIGEST_SLOTS: usize = 3;

/// What one of the three secure-boot digest slots holds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DigestSlot {
    /// No key block carries this slot's purpose. The ordinary state of a device
    /// that has never been through secure-boot provisioning.
    NotBurned,
    /// The slot's revocation bit is set: the boot ROM no longer trusts whatever
    /// digest is in it. The bytes may still be present and are not shown,
    /// because a revoked digest is not a trusted key and displaying it as one
    /// would invite exactly the wrong comparison.
    Revoked,
    /// The digest's key block is read-protected, so its value cannot be read.
    /// Unexpected for a secure-boot digest and therefore worth its own state
    /// rather than being flattened into "not burned".
    ReadProtected,
    /// The SHA-256 digest of an enrolled RSA-3072 public key, and the block it
    /// lives in.
    Burned {
        /// The key block carrying the digest.
        block: KeyBlock,
        /// The 32-byte digest, exactly as `espsecure.py digest_sbv2_public_key`
        /// produces it.
        digest: [u8; 32],
    },
}

impl DigestSlot {
    /// The purpose that carries slot `index`.
    pub const fn purpose(index: usize) -> Option<KeyPurpose> {
        match index {
            0 => Some(KeyPurpose::SecureBootDigest0),
            1 => Some(KeyPurpose::SecureBootDigest1),
            2 => Some(KeyPurpose::SecureBootDigest2),
            _ => None,
        }
    }
}

/// The whole secure-boot posture, read in one pass.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SecureBoot {
    /// `SECURE_BOOT_EN`. The one guarantee on a verification readout that the
    /// application cannot forge - on a burned device an unsigned application
    /// does not run, so there is nothing left to print a reassuring value.
    pub enabled: bool,
    /// `SECURE_BOOT_AGGRESSIVE_REVOKE`: whether one failed verification revokes
    /// a digest.
    pub aggressive_revoke: bool,
    /// The three digest slots, in slot order.
    pub digests: [DigestSlot; DIGEST_SLOTS],
    /// Per slot, whether the revocation bit is itself write-protected.
    pub revoke_write_protected: [bool; DIGEST_SLOTS],
}

#[cfg(target_os = "espidf")]
mod imp {
    use super::*;
    use crate::key_block;
    use esp_idf_sys as sys;

    /// Read the secure-boot posture from eFuse.
    ///
    /// Cost: memory-mapped register reads, microseconds. Cannot fail: every
    /// component is a bit or a block that is either present or is not, and
    /// "not present" is a reportable answer rather than an error.
    pub fn read() -> SecureBoot {
        let mut digests = [DigestSlot::NotBurned; DIGEST_SLOTS];
        let mut revoke_write_protected = [false; DIGEST_SLOTS];

        for (slot, out) in digests.iter_mut().enumerate() {
            // SAFETY: `slot` is 0..DIGEST_SLOTS, the range the C API documents.
            revoke_write_protected[slot] =
                unsafe { sys::esp_efuse_get_write_protect_of_digest_revoke(slot as u32) };

            // SAFETY: same.
            if unsafe { sys::esp_efuse_get_digest_revoke(slot as u32) } {
                *out = DigestSlot::Revoked;
                continue;
            }

            let Some(purpose) = DigestSlot::purpose(slot) else {
                continue;
            };
            let Some(block) = key_block::find(purpose) else {
                continue;
            };

            // The RD_DIS check that esp_efuse_read_block() does not do. Without
            // it a read-protected block renders as 32 zero bytes.
            if key_block::state(block).read_protected {
                *out = DigestSlot::ReadProtected;
                continue;
            }

            let mut digest = [0u8; 32];
            // SAFETY: reads the first 256 bits of a 256-bit key block into a
            // 32-byte buffer. `block` came from esp_efuse_find_purpose, so it
            // is in EFUSE_BLK_KEY0..KEY_MAX.
            let err = unsafe {
                sys::esp_efuse_read_block(
                    block.as_sys(),
                    digest.as_mut_ptr().cast(),
                    0,
                    32 * 8,
                )
            };
            if err == sys::ESP_OK {
                *out = DigestSlot::Burned { block, digest };
            }
            // A non-OK read leaves the slot at NotBurned, which understates
            // rather than invents. There is no honest value to show here and a
            // readout that guesses is worse than one that says nothing.
        }

        SecureBoot {
            enabled: crate::efuse_bit(core::ptr::addr_of_mut!(sys::ESP_EFUSE_SECURE_BOOT_EN)),
            aggressive_revoke: crate::efuse_bit(core::ptr::addr_of_mut!(
                sys::ESP_EFUSE_SECURE_BOOT_AGGRESSIVE_REVOKE
            )),
            digests,
            revoke_write_protected,
        }
    }
}

#[cfg(target_os = "espidf")]
pub use imp::read;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_purposes_are_the_three_digest_purposes() {
        assert_eq!(DigestSlot::purpose(0), Some(KeyPurpose::SecureBootDigest0));
        assert_eq!(DigestSlot::purpose(1), Some(KeyPurpose::SecureBootDigest1));
        assert_eq!(DigestSlot::purpose(2), Some(KeyPurpose::SecureBootDigest2));
        assert_eq!(DigestSlot::purpose(DIGEST_SLOTS), None);
    }

    /// Four distinct states, and no way to conflate a read-protected slot with
    /// an empty one. That distinction is the whole point of the type.
    #[test]
    fn the_four_slot_states_are_distinct() {
        let burned = DigestSlot::Burned {
            block: KeyBlock::Key0,
            digest: [0u8; 32],
        };
        assert_ne!(burned, DigestSlot::NotBurned);
        assert_ne!(DigestSlot::ReadProtected, DigestSlot::NotBurned);
        assert_ne!(DigestSlot::Revoked, DigestSlot::NotBurned);
        assert_ne!(DigestSlot::ReadProtected, DigestSlot::Revoked);
    }
}
