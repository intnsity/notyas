// SPDX-FileCopyrightText: 2026 intnsity
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The factory-programmed identity that lives in eFuse: silicon revision, MAC
//! address, and the optional per-die unique ID.
//!
//! These are in this crate because they are eFuse reads and because the eFuse
//! table they come from is revision-family dependent in a way that is easy to
//! get wrong by hand. They are not secrets. The MAC is in BLK1, which any
//! `esptool` invocation over the same USB port returns, and the die ID is a
//! label rather than a key; treating either as confidential would be theatre
//! that costs the owner a check and costs an attacker nothing.

/// Silicon revision, as `major.minor`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct ChipRevision {
    /// Wafer major version.
    pub major: u32,
    /// Wafer minor version.
    pub minor: u32,
}

impl ChipRevision {
    /// `major * 100 + minor`, ESP-IDF's `efuse_hal_chip_revision()` encoding.
    /// Revision v1.3 is 103.
    pub const fn composite(self) -> u32 {
        self.major * 100 + self.minor
    }

    /// Decompose ESP-IDF's composite encoding.
    pub const fn from_composite(composite: u32) -> ChipRevision {
        ChipRevision {
            major: composite / 100,
            minor: composite % 100,
        }
    }
}

impl core::fmt::Display for ChipRevision {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "v{}.{}", self.major, self.minor)
    }
}

/// `OPTIONAL_UNIQUE_ID`, eFuse BLK2 bits 0..128.
///
/// Named *optional* by Espressif, and no ESP-IDF code path reads it. Whether it
/// is programmed on a given part is a bench question, so this type keeps the
/// two answers apart: sixteen zero bytes rendered as an identity would be a
/// value the device never read.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DieUniqueId {
    /// Not a single bit of the field is programmed.
    NotBurned,
    /// The 128-bit factory value.
    Burned([u8; 16]),
}

#[cfg(target_os = "espidf")]
mod imp {
    use super::*;
    use crate::error::{Error, Result};
    use esp_idf_sys as sys;

    /// Read the silicon revision.
    ///
    /// Goes through the HAL rather than the eFuse table on purpose: on the
    /// pre-v3.0 ESP32-P4 table the wafer major version is split into a 2-bit LO
    /// field and a 1-bit HI field, and `efuse_hal_chip_revision()` is what
    /// composes `(HI << 2) | LO`. Reading the CSV fields directly gets the
    /// major version wrong on exactly the silicon this matters on.
    pub fn chip_revision() -> ChipRevision {
        // SAFETY: no arguments; reads eFuse read registers through the HAL.
        unsafe {
            ChipRevision {
                major: sys::efuse_hal_get_major_chip_version(),
                minor: sys::efuse_hal_get_minor_chip_version(),
            }
        }
    }

    /// The factory base MAC, eFuse BLK1.
    ///
    /// `ESP_MAC_BASE` is the only universally valid type on a part with no
    /// radio: most of `esp_mac_type_t`'s enumerators exist unconditionally but
    /// return `ESP_ERR_NOT_SUPPORTED` at run time where the interface does not.
    pub fn mac() -> Result<[u8; 6]> {
        let mut mac = [0u8; 6];
        // SAFETY: `mac` is a writeable 6-byte buffer, which is the length the
        // C API documents for every MAC type it accepts.
        let err = unsafe { sys::esp_read_mac(mac.as_mut_ptr(), sys::esp_mac_type_t_ESP_MAC_BASE) };
        match err {
            sys::ESP_OK => Ok(mac),
            sys::ESP_ERR_NOT_SUPPORTED => Err(Error::Unsupported),
            sys::ESP_ERR_INVALID_ARG => Err(Error::InvalidArgument),
            other => Err(Error::Esp(other)),
        }
    }

    /// The 128-bit per-die unique ID, or [`DieUniqueId::NotBurned`].
    ///
    /// Emptiness is tested with `esp_efuse_read_field_cnt()`, which counts
    /// programmed bits, rather than by reading the blob and comparing it
    /// against zero. Both give the same answer here, but the count is the
    /// question actually being asked and it does not require materialising a
    /// value in order to decide it is not one.
    pub fn die_unique_id() -> DieUniqueId {
        let field = core::ptr::addr_of_mut!(sys::ESP_EFUSE_OPTIONAL_UNIQUE_ID).cast();
        let mut programmed_bits: usize = 0;
        // SAFETY: the descriptor pointer is the generated table's own; the
        // out-parameter is a valid `usize` for the duration of the call.
        let err = unsafe { sys::esp_efuse_read_field_cnt(field, &mut programmed_bits) };
        if err != sys::ESP_OK || programmed_bits == 0 {
            return DieUniqueId::NotBurned;
        }

        let mut id = [0u8; 16];
        // SAFETY: 128 bits into a 16-byte buffer; the API clamps to the
        // smaller of the field width and the requested size.
        let err = unsafe { sys::esp_efuse_read_field_blob(field, id.as_mut_ptr().cast(), 128) };
        if err == sys::ESP_OK {
            DieUniqueId::Burned(id)
        } else {
            DieUniqueId::NotBurned
        }
    }
}

#[cfg(target_os = "espidf")]
pub use imp::{chip_revision, die_unique_id, mac};

#[cfg(test)]
mod tests {
    use super::*;

    /// 103 is the revision on this project's bench silicon, and the composite
    /// encoding is the one place a `/100` and a `%100` can be transposed
    /// without anything failing loudly.
    #[test]
    fn revision_composite_round_trips() {
        let rev = ChipRevision::from_composite(103);
        assert_eq!((rev.major, rev.minor), (1, 3));
        assert_eq!(rev.composite(), 103);
        assert_eq!(rev.to_string(), "v1.3");

        for composite in [0u32, 1, 100, 199, 300, 301, 1099] {
            assert_eq!(
                ChipRevision::from_composite(composite).composite(),
                composite
            );
        }
    }

    #[test]
    fn an_unburned_die_id_is_not_sixteen_zero_bytes() {
        assert_ne!(DieUniqueId::NotBurned, DieUniqueId::Burned([0u8; 16]));
    }
}
