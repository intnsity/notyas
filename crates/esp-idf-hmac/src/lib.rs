// SPDX-FileCopyrightText: 2026 intnsity
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Safe Rust over the ESP32 HMAC peripheral and the eFuse state it depends on.
//!
//! Two things live here, and they are one thing viewed from two sides.
//!
//! **A device-bound MAC.** [`HmacKey`] computes HMAC-SHA256 under a key that
//! lives in an eFuse block and that software cannot read. The handle holds a
//! block index and nothing else: no key, no buffer, no cached state. A caller
//! can therefore obtain a MAC that only this physical part can produce without
//! any key material ever crossing the API - which is the point, and which is
//! why there is deliberately no function anywhere in this crate that returns
//! the contents of a key block.
//!
//! **The eFuse state that says whether that means anything.** A key in a block
//! that was never read-protected computes exactly the same MACs and is a
//! materially weaker device. So the crate also reads out the surrounding
//! configuration - key-block purposes and their protection, Secure Boot v2 and
//! its enrolled public-key digests, flash encryption and its mode, the download
//! and JTAG fields, anti-rollback, and the factory identity in eFuse - as raw
//! values.
//!
//! # Two things this crate will not do
//!
//! **It holds no secret.** Nothing is compiled in, nothing is cached, nothing
//! needs zeroising on drop. Key material appears in exactly one signature, the
//! provisioning burn, where the caller supplies it and this crate passes the
//! pointer straight to ESP-IDF without copying it.
//!
//! **It makes no policy decision.** Every readout is a value as read. There is
//! no `is_secure()`, no verdict, no threshold and no default that stands in for
//! a value the hardware did not supply. ESP-IDF's own
//! `esp_flash_encryption_cfg_verify_release_mode()` exists for callers who want
//! a judgement and is the right reference for which fields matter; this crate
//! reports the fields it checks, individually, and leaves the judgement to the
//! caller who knows their threat model.
//!
//! Both constraints have a licensing consequence as well as a design one. This
//! crate is MIT OR Apache-2.0 and depends on nothing but `esp-idf-sys`, so any
//! project can adopt it; a crate that encoded one product's policy, or pulled
//! that product's dependencies, would be a crate only that product could use.
//!
//! # Portability
//!
//! The types, the enumerator tables and their renderings are pure `core` and
//! compile everywhere, which is where the host test suite exercises them. The
//! readers are `#[cfg(target_os = "espidf")]`. The download / JTAG / ROM-log /
//! flash-encryption field group in [`posture`] is additionally ESP32-P4 only
//! for now, because that field set genuinely differs between parts and a
//! wrapper that guessed would be worse than one that is honest about its
//! coverage. [`hmac`], [`key_block`], [`secure_boot`] and [`identity`] use only
//! target-generic ESP-IDF APIs.
//!
//! # Example
//!
//! ```no_run
//! # #[cfg(target_os = "espidf")]
//! # fn main() -> Result<(), esp_idf_hmac::Error> {
//! use esp_idf_hmac::{HmacKey, KeyBlock};
//!
//! // Report what the six key blocks are committed to, as read.
//! for state in esp_idf_hmac::key_block::all_states() {
//!     println!(
//!         "{}  {}  rd_dis {}  wr_dis {}",
//!         state.block.name(),
//!         state.purpose,
//!         state.read_protected as u8,
//!         state.write_protected as u8,
//!     );
//! }
//!
//! // Bind to the HMAC_UP block, if the device has one, and MAC a message.
//! match HmacKey::find() {
//!     Ok(key) => {
//!         let tag = key.mac(b"context||counter")?;
//!         println!("device MAC: {:02x?}", &tag[..4]);
//!     }
//!     Err(e) => println!("no device-bound key: {e}"),
//! }
//! # let _ = KeyBlock::Key0;
//! # Ok(())
//! # }
//! # #[cfg(not(target_os = "espidf"))]
//! # fn main() {}
//! ```

#![cfg_attr(not(test), no_std)]
#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod error;
pub mod hmac;
pub mod identity;
pub mod key_block;
pub mod posture;
pub mod secure_boot;

#[cfg(feature = "provisioning")]
pub mod provisioning;

pub use error::{Error, Result};
pub use hmac::HmacKey;
pub use identity::{ChipRevision, DieUniqueId};
pub use key_block::{KeyBlock, KeyBlockState, KeyPurpose};
pub use secure_boot::{DigestSlot, SecureBoot};

/// Whether this build's eFuse API is backed by a RAM copy
/// (`CONFIG_EFUSE_VIRTUAL`) rather than by the fuses.
///
/// Exposed as a constant because a caller that reports eFuse state to a human
/// must be able to say so. Under virtualisation, reads still reflect the real
/// fuses - ESP-IDF copies them into RAM at startup - but writes go nowhere, and
/// a value that *looks* burned may only be burned in RAM. A release build
/// should assert this is `false`; a development build that forgets to say it is
/// `true` is showing a reader a fiction.
///
/// Note what it does not cover: the HMAC peripheral reads the real eFuse block
/// regardless, so a virtual key block does not produce a working MAC. See
/// [`hmac`] for why that is a feature.
pub const EFUSE_VIRTUAL: bool = cfg!(esp_idf_efuse_virtual);

/// Read a one-bit eFuse field through its generated descriptor table entry.
///
/// The `addr_of_mut!` dance is not decoration. bindgen renders each `ESP_EFUSE_*`
/// descriptor table as a `static mut` array, and taking a reference to one is
/// the `static_mut_refs` footgun; the raw-pointer cast never creates a
/// reference. The `*mut` is only because ESP-IDF's prototypes are not
/// const-qualified - a field read never writes through the pointer.
#[cfg(target_os = "espidf")]
pub(crate) fn efuse_bit<const N: usize>(
    field: *mut [*const esp_idf_sys::esp_efuse_desc_t; N],
) -> bool {
    // SAFETY: `field` points at one of the generated descriptor tables, which
    // are static for the life of the program and are what this API expects.
    unsafe { esp_idf_sys::esp_efuse_read_field_bit(field.cast()) }
}

/// Count the programmed bits of a multi-bit eFuse field.
///
/// The right read for the thermometer-encoded fields - `SPI_BOOT_CRYPT_CNT`,
/// `SOFT_DIS_JTAG` - where the count *is* the value and reading the raw bits
/// would invite an off-by-one against the odd/even rule. Returns 0 if the read
/// fails, which cannot happen for a BLK0 field on a non-virtual build (they are
/// memory-mapped register reads) and which understates rather than invents.
#[cfg(target_os = "espidf")]
pub(crate) fn efuse_cnt<const N: usize>(
    field: *mut [*const esp_idf_sys::esp_efuse_desc_t; N],
) -> u8 {
    let mut count: usize = 0;
    // SAFETY: as above, plus a valid out-pointer for the duration of the call.
    let err = unsafe { esp_idf_sys::esp_efuse_read_field_cnt(field.cast(), &mut count) };
    if err == esp_idf_sys::ESP_OK {
        count.min(u8::MAX as usize) as u8
    } else {
        0
    }
}
