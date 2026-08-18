// SPDX-FileCopyrightText: 2026 intnsity
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The HMAC peripheral in upstream mode: HMAC-SHA256 under a key held in eFuse.
//!
//! # What this buys you
//!
//! The key is written into an eFuse block once and the block is read-protected.
//! From then on the value is unreachable - not by the CPU, not by JTAG, not by
//! a debugger, not by firmware that has been replaced. The HMAC peripheral
//! still reads it, because the peripheral is wired to the eFuse block directly,
//! so the device can still prove it is itself. The consequence for a caller is
//! the property this whole crate exists to provide:
//!
//! > A device-bound MAC is available to software; the key behind it is not.
//!
//! [`HmacKey`] is the API shape that makes that property hard to lose. It holds
//! a block identifier and nothing else - no key, no buffer, no cached state -
//! so there is no key material for a caller to leak, log, serialise or forget
//! to zeroise, and no `Drop` obligation. Consult `HmacKey::state` to see
//! whether the block really is read-protected; a burned-but-readable key still
//! computes correct MACs and is a materially weaker device, and this crate
//! reports the difference rather than deciding what it means.
//!
//! # What it does not buy you
//!
//! The purpose check that makes upstream mode safe is performed *in hardware*,
//! against the real eFuse block, by the peripheral. `CONFIG_EFUSE_VIRTUAL`
//! cannot forge it: an eFuse API call will happily report a virtual key block
//! with purpose `HMAC_UP`, and the peripheral will still refuse the block and
//! return [`Error::PeripheralRefused`]. That is a feature - virtual eFuses are
//! a way to exercise code, never a way to simulate the silicon - but it means
//! no amount of virtualisation substitutes for one real burned block when the
//! time comes to verify the ladder end to end.

use crate::key_block::KeyBlock;

/// A handle to an eFuse key block committed to `HMAC_UP`.
///
/// Holds a block index. Deliberately `Copy`: there is nothing to own and
/// nothing to drop, and making that visible in the type is part of the
/// argument that no key material passes through this API.
///
/// `Send` and `Sync` because ESP-IDF's `esp_hmac_calculate()` takes the
/// peripheral's own crypto lock for the duration of the call, so concurrent
/// callers serialise inside the driver rather than corrupting each other.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HmacKey {
    block: KeyBlock,
}

impl HmacKey {
    /// The eFuse block this handle addresses.
    pub const fn block(self) -> KeyBlock {
        self.block
    }
}

#[cfg(target_os = "espidf")]
mod imp {
    use super::*;
    use crate::error::{Error, Result};
    use crate::key_block::{self, KeyBlockState, KeyPurpose};
    use esp_idf_sys as sys;

    impl HmacKey {
        /// Bind to `block`, requiring that its purpose is already `HMAC_UP`.
        ///
        /// Fails with [`Error::WrongPurpose`] otherwise. The check is not
        /// defensive politeness: a key block's purpose is write-once, so a
        /// block that reports a different purpose will never serve this one,
        /// and the failure is permanent information rather than a transient.
        pub fn bind(block: KeyBlock) -> Result<Self> {
            let found = key_block::state(block).purpose;
            if found == KeyPurpose::HmacUp {
                Ok(Self { block })
            } else {
                Err(Error::WrongPurpose {
                    block,
                    found,
                    expected: KeyPurpose::HmacUp,
                })
            }
        }

        /// Bind to whichever block carries `HMAC_UP`.
        ///
        /// Returns [`Error::PurposeNotFound`] on a device where no block does,
        /// which is the ordinary state of an unprovisioned part and is a fact
        /// about the device rather than a fault in the caller.
        pub fn find() -> Result<Self> {
            key_block::require(KeyPurpose::HmacUp).map(|block| Self { block })
        }

        /// The full eFuse state of this handle's block, so a caller can see
        /// whether the key is still software-readable.
        pub fn state(self) -> KeyBlockState {
            key_block::state(self.block)
        }

        /// HMAC-SHA256 of `message` under the eFuse key, into a caller-owned
        /// buffer.
        ///
        /// The peripheral streams the message in 512-bit blocks and applies the
        /// SHA-256 padding, so `message` may be any length including zero. Time
        /// taken is a function of the message length only; nothing here
        /// branches on message content or on the key, which the caller could
        /// not observe in any case.
        ///
        /// `out` is written only on success. On any failure it is left
        /// untouched rather than zeroed, so a caller cannot mistake a failed
        /// MAC for a MAC of zero.
        pub fn mac_into(self, message: &[u8], out: &mut [u8; 32]) -> Result<()> {
            let mut scratch = [0u8; 32];
            // SAFETY: key id is 0..5 by construction; `message` is a valid
            // readable range of `message.len()` bytes (a possibly-dangling but
            // aligned pointer for the empty slice, which the driver never
            // dereferences because it copies `message_len` bytes); `scratch` is
            // a writeable 32-byte buffer as the C contract requires.
            let err = unsafe {
                sys::esp_hmac_calculate(
                    self.block.index() as sys::hmac_key_id_t,
                    message.as_ptr().cast(),
                    message.len(),
                    scratch.as_mut_ptr(),
                )
            };
            match err {
                sys::ESP_OK => {
                    *out = scratch;
                    Ok(())
                }
                // ESP_FAIL is the peripheral's own configuration error - on
                // this path it means the hardware read the block's real
                // KEY_PURPOSE and disagreed with the eFuse API.
                sys::ESP_FAIL => Err(Error::PeripheralRefused),
                sys::ESP_ERR_INVALID_ARG => Err(Error::InvalidArgument),
                other => Err(Error::Esp(other)),
            }
        }

        /// HMAC-SHA256 of `message` under the eFuse key.
        ///
        /// Convenience over [`HmacKey::mac_into`] for callers that want an
        /// owned digest. A MAC is not secret in the way a key is, but it is
        /// authentication material: a caller deriving further keys from it
        /// should zeroise its copy, which is why the by-reference form exists
        /// alongside this one.
        pub fn mac(self, message: &[u8]) -> Result<[u8; 32]> {
            let mut out = [0u8; 32];
            self.mac_into(message, &mut out)?;
            Ok(out)
        }
    }

    /// HMAC downstream mode: JTAG re-enable.
    ///
    /// Separate from [`HmacKey`] on purpose. Downstream mode never returns a
    /// value to software - the peripheral feeds its result to another block of
    /// silicon - so it is a different operation with a different key purpose
    /// (`HMAC_DOWN_JTAG` or `HMAC_DOWN_ALL`), and folding it into the upstream
    /// handle would suggest the two are interchangeable.
    ///
    /// This only matters on a device whose JTAG is *soft*-disabled
    /// (`SOFT_DIS_JTAG`). `DIS_PAD_JTAG` and `DIS_USB_JTAG` are permanent and
    /// no token re-opens them.
    pub mod jtag {
        use super::*;

        /// Present the JTAG re-enable token to the peripheral.
        ///
        /// `token` is HMAC-SHA256 of 32 zero bytes under the key in `block`,
        /// computed off-device by whoever holds that key. It is the caller's
        /// secret and never touches this crate's state.
        ///
        /// ESP-IDF returns `ESP_OK` when the key purpose matched, **whether or
        /// not the token was correct** - JTAG is re-enabled only on a match,
        /// and the return value is not a report on that. Nothing here can
        /// improve on it, so nothing here pretends to: `Ok(())` means the
        /// request was accepted, not that JTAG is open.
        pub fn enable(block: KeyBlock, token: &[u8; 32]) -> Result<()> {
            // SAFETY: key id is 0..5 by construction, `token` is a valid
            // 32-byte readable buffer for the duration of the call.
            let err = unsafe {
                sys::esp_hmac_jtag_enable(block.index() as sys::hmac_key_id_t, token.as_ptr())
            };
            match err {
                sys::ESP_OK => Ok(()),
                sys::ESP_FAIL => Err(Error::WrongPurpose {
                    block,
                    found: key_block::state(block).purpose,
                    expected: KeyPurpose::HmacDownJtag,
                }),
                sys::ESP_ERR_INVALID_ARG => Err(Error::InvalidArgument),
                other => Err(Error::Esp(other)),
            }
        }

        /// Clear the result of a previous [`enable`], closing JTAG again.
        pub fn disable() -> Result<()> {
            // SAFETY: no arguments, no aliasing; writes one peripheral register.
            match unsafe { sys::esp_hmac_jtag_disable() } {
                sys::ESP_OK => Ok(()),
                other => Err(Error::Esp(other)),
            }
        }
    }
}

#[cfg(target_os = "espidf")]
pub use imp::jtag;

#[cfg(test)]
mod tests {
    use super::*;

    /// A handle is a block index and nothing else. If this ever grows a field,
    /// the claim that no key material passes through the API needs re-arguing.
    #[test]
    fn the_handle_carries_no_material() {
        assert_eq!(
            core::mem::size_of::<HmacKey>(),
            core::mem::size_of::<KeyBlock>()
        );
        assert!(!core::mem::needs_drop::<HmacKey>());
    }
}
