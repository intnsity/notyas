// SPDX-FileCopyrightText: 2026 intnsity
// SPDX-License-Identifier: MIT OR Apache-2.0

//! One error type for the whole crate.
//!
//! Every variant names a distinguishable physical situation, because the
//! caller's correct response differs for each: a missing key block is a
//! provisioning problem, a refused peripheral is a silicon-level purpose
//! mismatch, and a raw `esp_err_t` is something this crate did not anticipate
//! and will not pretend to have understood.

use core::fmt;

use crate::key_block::{KeyBlock, KeyPurpose};

/// The result of every fallible operation in this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// What went wrong.
///
/// `#[non_exhaustive]`: this maps onto silicon whose feature set differs by
/// part and by revision, so new variants are expected and must not be
/// breaking changes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Error {
    /// No eFuse key block carries the purpose asked for. On an unprovisioned
    /// device this is the normal answer, not a fault.
    PurposeNotFound(KeyPurpose),

    /// The named block exists but is committed to a different purpose. Key
    /// purposes are write-once, so this condition is permanent for that block.
    WrongPurpose {
        /// The block that was asked about.
        block: KeyBlock,
        /// What its `KEY_PURPOSE` field actually says.
        found: KeyPurpose,
        /// What the operation required.
        expected: KeyPurpose,
    },

    /// The block is already in use, so it cannot be provisioned. Distinct from
    /// [`Error::WrongPurpose`] because the two call for different responses and
    /// because a block committed to the purpose you wanted is still a block you
    /// must not burn again: `found == expected` would have read as agreement.
    BlockInUse {
        /// The block that is already spent.
        block: KeyBlock,
        /// What it is committed to. `USER` here means the block is not
        /// purpose-committed but is protected or non-empty.
        purpose: KeyPurpose,
    },

    /// The HMAC peripheral rejected the configuration. The purpose check is
    /// performed by hardware against the real eFuse block, so this is what a
    /// virtualised or unburned key block produces however convincing the eFuse
    /// API's answer looked (`hmac_ll_config_error()` is a register read).
    PeripheralRefused,

    /// A field, peripheral or table entry this crate can name does not exist in
    /// the ESP-IDF build it was compiled against.
    Unsupported,

    /// Arguments rejected before the peripheral was touched.
    InvalidArgument,

    /// An `esp_err_t` this crate does not model. The code is reported verbatim
    /// rather than being folded into a nearby variant, because guessing at a
    /// hardware error's meaning is how a readout starts lying.
    Esp(i32),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::PurposeNotFound(p) => {
                write!(f, "no eFuse key block has purpose {}", p.idf_name())
            }
            Error::WrongPurpose {
                block,
                found,
                expected,
            } => write!(
                f,
                "{} has purpose {}, not {}",
                block.name(),
                found.idf_name(),
                expected.idf_name()
            ),
            Error::BlockInUse { block, purpose } => write!(
                f,
                "{} is already in use (purpose {}) and must not be burned again",
                block.name(),
                purpose.idf_name()
            ),
            Error::PeripheralRefused => {
                f.write_str("the HMAC peripheral refused the key block (hardware purpose check)")
            }
            Error::Unsupported => f.write_str("not supported by this ESP-IDF build"),
            Error::InvalidArgument => f.write_str("invalid argument"),
            Error::Esp(code) => write!(f, "esp_err_t 0x{code:x}"),
        }
    }
}

impl core::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    /// These strings end up in a serial log with no other context around them,
    /// so each one names the block and both purposes rather than a bare code.
    #[test]
    fn display_is_self_describing() {
        assert_eq!(
            Error::WrongPurpose {
                block: KeyBlock::Key2,
                found: KeyPurpose::XtsAes128Key,
                expected: KeyPurpose::HmacUp,
            }
            .to_string(),
            "KEY2 has purpose XTS_AES_128_KEY, not HMAC_UP"
        );
        assert_eq!(
            Error::PurposeNotFound(KeyPurpose::HmacUp).to_string(),
            "no eFuse key block has purpose HMAC_UP"
        );
        assert_eq!(Error::Esp(0x102).to_string(), "esp_err_t 0x102");
        assert_eq!(
            Error::BlockInUse {
                block: KeyBlock::Key2,
                purpose: KeyPurpose::HmacUp,
            }
            .to_string(),
            "KEY2 is already in use (purpose HMAC_UP) and must not be burned again"
        );
        assert_eq!(
            Error::PeripheralRefused.to_string(),
            "the HMAC peripheral refused the key block (hardware purpose check)"
        );
    }
}
