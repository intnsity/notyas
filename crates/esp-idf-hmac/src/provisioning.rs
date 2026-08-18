// SPDX-FileCopyrightText: 2026 intnsity
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Burning a key into eFuse. Off by default, and fenced three ways.
//!
//! # Read this before enabling the feature
//!
//! Everything in this module is permanent. There is no undo, no erase, no
//! recovery and no support path. A part has six key blocks and no seventh. The
//! irreversibility ladder, in the order `burn_hmac_up_key` climbs it:
//!
//! 1. **The key bits are programmed.** One of six blocks is spent, forever.
//! 2. **`WR_DIS` is set.** The block's contents can never change again.
//! 3. **`RD_DIS` is set.** The key value is gone from every perspective that
//!    is not the HMAC peripheral itself, including JTAG and including a
//!    debugger with full bus access. If the value was not backed up before this
//!    step, it does not exist any more. **This is the point of no return.**
//! 4. **`KEY_PURPOSE` is set and write-protected.** The block can never serve
//!    another purpose.
//!
//! ESP-IDF performs all four inside one batched write, so a caller cannot stop
//! between them and there is no partial state to reason about.
//!
//! One ordering constraint that is not obvious and that this module cannot
//! enforce: on a part where Secure Boot v2 is subsequently enabled, the
//! bootloader's own first-boot sequence sets `WR_DIS_RD_DIS`, which
//! write-disables the read-protection register itself. **After secure boot is
//! enabled, no key block can ever be read-protected again.** Any key that must
//! be read-protected has to be burned and protected before that happens.
//!
//! # The three fences
//!
//! 1. **A non-default Cargo feature**, `provisioning`. Necessary, and not
//!    sufficient: Cargo unifies features across a dependency graph, so a
//!    transitive dependency can turn one on without the application author
//!    noticing.
//! 2. **A build-script refusal.** `build.rs` fails the build when this feature
//!    is on, the ESP-IDF configuration does not virtualise eFuses, and
//!    `ESP_IDF_HMAC_ALLOW_REAL_EFUSE_BURN=1` is not set in the environment. A
//!    dependency can set a feature; it cannot set an environment variable in
//!    the operator's shell.
//! 3. **A witness argument.** Every function here takes an [`Irreversible`],
//!    whose only constructor is spelled out in full at the call site. It exists
//!    so that a burn is visible in a code review of the caller, not only in the
//!    manifest of a crate three levels down.
//!
//! # Consider not using this at all
//!
//! Provisioning from the host with `espefuse.py` is the better default for most
//! projects and is what this crate's own author uses. The host tool prompts for
//! confirmation before every irreversible operation, it runs against a device
//! in ROM download mode where no application code is involved, and it leaves an
//! auditable command line. An on-device burn helper is for the case where the
//! device must provision itself in the field. If that is not the case, do not
//! enable the feature.

/// Proof that the caller knows an eFuse write cannot be undone.
///
/// Carries no data. Its whole job is to make the constructor's name appear,
/// verbatim, at every site that programs a fuse.
#[derive(Clone, Copy, Debug)]
pub struct Irreversible(());

impl Irreversible {
    /// The only way to make one.
    ///
    /// Named the way it is so that a reviewer scanning a diff cannot miss it
    /// and an author cannot type it absent-mindedly.
    #[allow(clippy::new_without_default)]
    pub const fn i_understand_this_permanently_consumes_an_efuse_block() -> Self {
        Irreversible(())
    }
}

#[cfg(target_os = "espidf")]
mod imp {
    use super::*;
    use crate::error::{Error, Result};
    use crate::key_block::{self, KeyBlock, KeyPurpose};
    use esp_idf_sys as sys;

    /// Burn a 256-bit key into `block` with purpose `HMAC_UP`, and protect it.
    ///
    /// Wraps `esp_efuse_write_key()`, which performs the full ladder from this
    /// module's header inside one batched write: key bits, `WR_DIS`, `RD_DIS`
    /// (it applies read protection for `HMAC_UP` automatically and by design),
    /// `KEY_PURPOSE`, and the purpose field's own `WR_DIS`.
    ///
    /// After this returns `Ok`, the value in `key` exists nowhere on the device
    /// that software can reach. **Zeroise the caller's copy** - this crate
    /// never copies it and never stores it, so the caller's buffer is the only
    /// remaining copy and its lifetime is entirely the caller's business.
    ///
    /// Fails with [`Error::Esp`] carrying `ESP_ERR_INVALID_STATE` if the block
    /// is not unused; ESP-IDF checks that before it programs anything, so a
    /// mistargeted call costs nothing.
    pub fn burn_hmac_up_key(
        block: KeyBlock,
        key: &[u8; 32],
        _witness: Irreversible,
    ) -> Result<()> {
        burn_key(block, KeyPurpose::HmacUp, key, _witness)
    }

    /// Burn a 256-bit key into `block` with an arbitrary purpose.
    ///
    /// The general form, for embedders whose key is not an HMAC key. Whether
    /// ESP-IDF read-protects the block is a function of the purpose and is
    /// ESP-IDF's decision, not this crate's: it read-protects the XTS, ECDSA,
    /// HMAC and Key Manager purposes and deliberately does not read-protect the
    /// `SECURE_BOOT_DIGEST` purposes, because a secure-boot digest must stay
    /// readable for software to check it. Call `key_block::state` afterwards
    /// to see what actually happened rather than assuming.
    pub fn burn_key(
        block: KeyBlock,
        purpose: KeyPurpose,
        key: &[u8; 32],
        _witness: Irreversible,
    ) -> Result<()> {
        // Refuse before the peripheral is touched. ESP-IDF checks this too and
        // returns ESP_ERR_INVALID_STATE; checking here means the error names
        // the block and what it is already committed to, which is what an
        // operator staring at a half-provisioned unit needs to know.
        let state = key_block::state(block);
        if !state.unused {
            return Err(Error::BlockInUse {
                block,
                purpose: state.purpose,
            });
        }

        // SAFETY: `block` is EFUSE_BLK_KEY0..KEY5 by construction, `purpose` is
        // below ESP_EFUSE_KEY_PURPOSE_MAX for every variant this crate can
        // produce from hardware, and `key` is exactly the 32 bytes declared.
        let err = unsafe {
            sys::esp_efuse_write_key(
                block.as_sys(),
                purpose.raw() as sys::esp_efuse_purpose_t,
                key.as_ptr().cast(),
                32,
            )
        };
        match err {
            sys::ESP_OK => Ok(()),
            sys::ESP_ERR_INVALID_ARG => Err(Error::InvalidArgument),
            other => Err(Error::Esp(other)),
        }
    }
}

#[cfg(target_os = "espidf")]
pub use imp::{burn_hmac_up_key, burn_key};

#[cfg(test)]
mod tests {
    use super::*;

    /// The witness is a marker. If it ever grows a field, the argument that it
    /// costs nothing but a visible name at the call site stops holding.
    #[test]
    fn the_witness_is_free_and_explicit() {
        assert_eq!(core::mem::size_of::<Irreversible>(), 0);
        let _ = Irreversible::i_understand_this_permanently_consumes_an_efuse_block();
    }
}
