// SPDX-FileCopyrightText: 2026 intnsity
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The one-way chip configuration: download modes, JTAG, ROM logging, flash
//! encryption, anti-rollback.
//!
//! Every value here is a raw eFuse field, reported as it reads. There are no
//! verdicts in this module and there will not be any: a single `bool` summary
//! of "is this device secure" is a judgement, it depends on a threat model this
//! crate does not know, and it hides the four genuinely different postures a
//! chip's download configuration can be in behind one word.
//!
//! ESP-IDF ships `esp_flash_encryption_cfg_verify_release_mode()` and
//! `esp_secure_boot_cfg_verify_release_mode()`, which audit exactly the right
//! `SOC_*`-gated field set for the part they are compiled for. They are the
//! right *reference* for which fields matter and the wrong thing to call here,
//! because each collapses to one boolean. The field set below is theirs,
//! itemised.
//!
//! # Target coverage
//!
//! The reader is written for ESP32-P4. The field *names* in ESP-IDF's generated
//! eFuse tables are mostly common across parts, but the set is not: several
//! fields that generic Espressif documentation lists for "the ESP32 family"
//! have no ESP32-P4 equivalent at all, and one field's name and meaning change
//! between the two P4 silicon families. Both cases are handled explicitly below
//! rather than by hoping a symbol resolves.

/// ROM download modes and the boot paths adjacent to them.
///
/// Field names are ESP-IDF's, and the polarity is ESP-IDF's too: most of these
/// fuses are named for what they *disable*, so `true` generally means a path is
/// closed. The one exception is called out on its own field.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Download {
    /// `DIS_DOWNLOAD_MODE` (BLK0 bit 128). ROM download mode is closed
    /// entirely.
    pub uart_download_disabled: bool,
    /// `ENABLE_SECURITY_DOWNLOAD` (bit 133). **Positive polarity**: `true`
    /// means download mode is restricted to the secure subset, not that
    /// anything is disabled.
    pub secure_download_enabled: bool,
    /// `DIS_USB_SERIAL_JTAG_DOWNLOAD_MODE` (bit 132).
    pub usb_serial_jtag_download_disabled: bool,
    /// `DIS_USB_OTG_DOWNLOAD_MODE` (bit 123).
    pub usb_otg_download_disabled: bool,
    /// `DIS_FORCE_DOWNLOAD` (bit 44): the software path that forces the chip
    /// into download mode.
    pub force_download_disabled: bool,
    /// `DIS_DIRECT_BOOT` (bit 129): the ROM's jump-straight-to-flash path.
    pub direct_boot_disabled: bool,
}

/// Debug-port state.
///
/// Three separate fields, deliberately not collapsed into one. `SOFT_DIS_JTAG`
/// is reversible at run time by presenting an HMAC token to a key block with
/// purpose `HMAC_DOWN_JTAG` or `HMAC_DOWN_ALL` (see the `hmac::jtag` module);
/// `DIS_PAD_JTAG` and `DIS_USB_JTAG` are permanent. Reporting "JTAG: disabled"
/// over the top of that difference would hide the case that matters.
///
/// **`HARD_DIS_JTAG` does not exist on ESP32-P4.** It is present on the S2 and
/// S3 and it appears in cross-target Espressif documentation, but the P4 eFuse
/// table has no such field and `SOC_EFUSE_HARD_DIS_JTAG` is undefined - ESP-IDF
/// itself substitutes `DIS_PAD_JTAG` for it on this part. P4's permanent JTAG
/// lock is `DIS_PAD_JTAG` and `DIS_USB_JTAG` together.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Jtag {
    /// `DIS_PAD_JTAG` (bit 51). Permanent.
    pub pad_disabled: bool,
    /// `DIS_USB_JTAG` (bit 41). Permanent.
    pub usb_disabled: bool,
    /// `SOFT_DIS_JTAG` (bit 48, **3 bits**) as a raw programmed-bit count.
    /// The field is odd/even: an odd count disables, an even count enables.
    /// Reported as the count rather than as a verdict; ESP-IDF treats the
    /// soft-disable as complete when the count reaches the field width.
    pub soft_disable_count: u8,
    /// The width of `SOFT_DIS_JTAG` in bits, so the count above can be read
    /// without a table. 3 on ESP32-P4.
    pub soft_disable_width: u8,
    /// `JTAG_SEL_ENABLE` (bit 47): whether strapping GPIO15 selects between the
    /// pad and USB JTAG paths when both are still enabled.
    pub select_enabled: bool,
}

/// Whether the boot ROM prints.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RomLog {
    /// `UART_PRINT_CONTROL` (bit 134, **2 bits**), raw. `0` force on,
    /// `1` on when GPIO8 is low at reset, `2` on when high, `3` force off.
    ///
    /// `None` if the field read failed. It cannot fail for a BLK0 field on a
    /// non-virtual build - the eFuse controller auto-loads BLK0 into read
    /// registers at reset, so this is a `REG_READ` - but `0` is a meaningful
    /// value of this field ("force enable printing"), so a failed read must
    /// not be able to look like one.
    pub uart_print_control: Option<u8>,
    /// `DIS_USB_SERIAL_JTAG_ROM_PRINT` (bit 130).
    pub usb_serial_jtag_print_disabled: bool,
}

/// The XTS-AES flash encryption posture.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FlashEncryption {
    /// `esp_flash_encryption_enabled()`: the odd parity of `SPI_BOOT_CRYPT_CNT`.
    pub enabled: bool,
    /// `esp_get_flash_encryption_mode()`. The row that "enabled" alone cannot
    /// give you: a Development-mode board is re-flashable and a Release-mode
    /// unit is not.
    pub mode: EncryptionMode,
    /// `SPI_BOOT_CRYPT_CNT` (bit 82, 3 bits) as a raw programmed-bit count,
    /// 0 to 3. The CSV's mapping is `{0: disable, 1: enable, 3: disable,
    /// 7: enable}` over the raw field value, which is why the count is shown
    /// beside [`FlashEncryption::enabled`] rather than instead of it.
    pub crypt_count: u8,
    /// The pre-v3 P4 table's `XTS_KEY_LENGTH_256` (bit 78).
    ///
    /// `None` on v3.0 silicon, where the field at that bit is renamed
    /// `KM_XTS_KEY_LENGTH_256` and changes meaning (it selects xts-512 versus
    /// xts-256 for the Key Manager, not 128 versus 256 for flash encryption).
    /// The two are not the same field with a new name, so this crate reports
    /// the one that exists and `None` for the one that does not, rather than
    /// silently showing a bit whose meaning has moved.
    pub xts_key_length_256: Option<bool>,
    /// `DIS_DOWNLOAD_MANUAL_ENCRYPT` (bit 52).
    pub manual_encrypt_disabled: bool,
    /// `SPI_DOWNLOAD_MSPI_DIS` (bit 45).
    pub mspi_download_disabled: bool,
    /// The key block holding the XTS key, if one of the three XTS purposes is
    /// committed anywhere.
    pub key_block: Option<crate::KeyBlock>,
    /// Whether that block is read-protected. `None` when there is no key block.
    /// A burned but software-readable XTS key is not flash encryption in any
    /// useful sense, and this is the field that says so.
    pub key_read_protected: Option<bool>,
}

/// `esp_get_flash_encryption_mode()`'s three states.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EncryptionMode {
    /// `ESP_FLASH_ENC_MODE_DISABLED`.
    Disabled,
    /// `ESP_FLASH_ENC_MODE_DEVELOPMENT`: re-flashable over UART.
    Development,
    /// `ESP_FLASH_ENC_MODE_RELEASE`.
    Release,
    /// A value ESP-IDF did not document at the version this was built against.
    Unknown(u32),
}

impl EncryptionMode {
    /// ESP-IDF's own enumerator spelling, minus the `ESP_FLASH_ENC_MODE_`
    /// prefix.
    pub const fn idf_name(self) -> &'static str {
        match self {
            EncryptionMode::Disabled => "DISABLED",
            EncryptionMode::Development => "DEVELOPMENT",
            EncryptionMode::Release => "RELEASE",
            EncryptionMode::Unknown(_) => "UNKNOWN",
        }
    }

    /// Classify a raw `esp_flash_enc_mode_t`.
    pub const fn from_raw(raw: u32) -> EncryptionMode {
        match raw {
            0 => EncryptionMode::Disabled,
            1 => EncryptionMode::Development,
            2 => EncryptionMode::Release,
            other => EncryptionMode::Unknown(other),
        }
    }
}

impl core::fmt::Display for EncryptionMode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            EncryptionMode::Unknown(v) => write!(f, "UNKNOWN({v})"),
            other => f.write_str(other.idf_name()),
        }
    }
}

#[cfg(all(target_os = "espidf", esp_idf_idf_target_esp32p4))]
mod imp {
    use super::*;
    use crate::key_block::{self, KeyPurpose};
    use crate::{efuse_bit, efuse_cnt};
    use esp_idf_sys as sys;

    /// Read the download-mode field group.
    pub fn download() -> Download {
        Download {
            uart_download_disabled: efuse_bit(core::ptr::addr_of_mut!(
                sys::ESP_EFUSE_DIS_DOWNLOAD_MODE
            )),
            secure_download_enabled: efuse_bit(core::ptr::addr_of_mut!(
                sys::ESP_EFUSE_ENABLE_SECURITY_DOWNLOAD
            )),
            usb_serial_jtag_download_disabled: efuse_bit(core::ptr::addr_of_mut!(
                sys::ESP_EFUSE_DIS_USB_SERIAL_JTAG_DOWNLOAD_MODE
            )),
            usb_otg_download_disabled: efuse_bit(core::ptr::addr_of_mut!(
                sys::ESP_EFUSE_DIS_USB_OTG_DOWNLOAD_MODE
            )),
            force_download_disabled: efuse_bit(core::ptr::addr_of_mut!(
                sys::ESP_EFUSE_DIS_FORCE_DOWNLOAD
            )),
            direct_boot_disabled: efuse_bit(core::ptr::addr_of_mut!(
                sys::ESP_EFUSE_DIS_DIRECT_BOOT
            )),
        }
    }

    /// Read the three JTAG fields and the strapping selector.
    pub fn jtag() -> Jtag {
        Jtag {
            pad_disabled: efuse_bit(core::ptr::addr_of_mut!(sys::ESP_EFUSE_DIS_PAD_JTAG)),
            usb_disabled: efuse_bit(core::ptr::addr_of_mut!(sys::ESP_EFUSE_DIS_USB_JTAG)),
            soft_disable_count: efuse_cnt(core::ptr::addr_of_mut!(sys::ESP_EFUSE_SOFT_DIS_JTAG)),
            soft_disable_width: 3,
            select_enabled: efuse_bit(core::ptr::addr_of_mut!(sys::ESP_EFUSE_JTAG_SEL_ENABLE)),
        }
    }

    /// Read the ROM logging configuration.
    pub fn rom_log() -> RomLog {
        RomLog {
            uart_print_control: crate::efuse_blob_u8(
                core::ptr::addr_of_mut!(sys::ESP_EFUSE_UART_PRINT_CONTROL),
                2,
            ),
            usb_serial_jtag_print_disabled: efuse_bit(core::ptr::addr_of_mut!(
                sys::ESP_EFUSE_DIS_USB_SERIAL_JTAG_ROM_PRINT
            )),
        }
    }

    /// Read the flash encryption posture.
    pub fn flash_encryption() -> FlashEncryption {
        // The XTS key can be under any of the three XTS purposes. Look for all
        // three rather than assuming the one this project happens to budget.
        let key_block = key_block::find(KeyPurpose::XtsAes128Key)
            .or_else(|| key_block::find(KeyPurpose::XtsAes256Key1))
            .or_else(|| key_block::find(KeyPurpose::XtsAes256Key2));

        FlashEncryption {
            // SAFETY: no arguments, reads eFuse read registers.
            enabled: unsafe { sys::esp_flash_encryption_enabled() },
            // SAFETY: same.
            mode: EncryptionMode::from_raw(unsafe { sys::esp_get_flash_encryption_mode() }),
            crypt_count: efuse_cnt(core::ptr::addr_of_mut!(sys::ESP_EFUSE_SPI_BOOT_CRYPT_CNT)),
            xts_key_length_256: xts_key_length_256(),
            manual_encrypt_disabled: efuse_bit(core::ptr::addr_of_mut!(
                sys::ESP_EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT
            )),
            mspi_download_disabled: efuse_bit(core::ptr::addr_of_mut!(
                sys::ESP_EFUSE_SPI_DOWNLOAD_MSPI_DIS
            )),
            key_block,
            key_read_protected: key_block.map(|b| key_block::state(b).read_protected),
        }
    }

    /// Present only on the pre-v3.0 P4 eFuse table. See
    /// [`FlashEncryption::xts_key_length_256`] for why this is `Option` rather
    /// than a bit read from whichever symbol happens to resolve.
    #[cfg(esp_idf_esp32p4_selects_rev_less_v3)]
    fn xts_key_length_256() -> Option<bool> {
        Some(efuse_bit(core::ptr::addr_of_mut!(
            sys::ESP_EFUSE_XTS_KEY_LENGTH_256
        )))
    }

    #[cfg(not(esp_idf_esp32p4_selects_rev_less_v3))]
    fn xts_key_length_256() -> Option<bool> {
        None
    }
}

#[cfg(all(target_os = "espidf", esp_idf_idf_target_esp32p4))]
pub use imp::{download, flash_encryption, jtag, rom_log};

/// The anti-rollback floor burned into eFuse.
///
/// `esp_efuse_read_secure_version()` takes no out-parameter and returns a
/// `__builtin_popcount()` of a thermometer-encoded field, so the return value
/// is the version number itself.
///
/// Trap, and the reason a caller should print this next to the image's own
/// `secure_version` rather than alone: with
/// `CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK` unset, ESP-IDF falls back to a 4-bit
/// field width, so an application built without anti-rollback reports a capped
/// value. One number hides whether the pair agrees; two do not.
#[cfg(target_os = "espidf")]
pub fn efuse_secure_version() -> u32 {
    // SAFETY: no arguments, reads eFuse read registers.
    unsafe { esp_idf_sys::esp_efuse_read_secure_version() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encryption_modes_round_trip_and_keep_idfs_spelling() {
        for (raw, name) in [(0u32, "DISABLED"), (1, "DEVELOPMENT"), (2, "RELEASE")] {
            assert_eq!(EncryptionMode::from_raw(raw).idf_name(), name);
        }
        assert_eq!(EncryptionMode::from_raw(9), EncryptionMode::Unknown(9));
        assert_eq!(EncryptionMode::from_raw(9).to_string(), "UNKNOWN(9)");
        assert_eq!(EncryptionMode::Release.to_string(), "RELEASE");
    }
}
