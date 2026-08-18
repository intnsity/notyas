// SPDX-FileCopyrightText: 2026 intnsity
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The six eFuse key blocks: which purpose each is committed to, and whether
//! software may still read or write it.
//!
//! Nothing here reads a key block's CONTENTS, and there is deliberately no API
//! that could. The whole value of an eFuse-held key is that the only thing
//! which ever sees it is the peripheral, so a wrapper that offered to hand it
//! back would be undoing the property it exists to expose. What this module
//! reports is metadata: purpose, protection, occupancy. That is exactly the
//! information a caller needs in order to decide whether the device is
//! provisioned the way it expects, and none of the information an attacker
//! would want.

/// One of the six eFuse key blocks.
///
/// ESP-IDF spells the same block two ways depending on which API is being
/// called: `EFUSE_BLK_KEY0` (which is `EFUSE_BLK4`, because blocks 0 to 3 are
/// system data) for the eFuse API, and `HMAC_KEY0` (which is 0) for the HMAC
/// peripheral. Getting the two confused silently addresses the wrong block, so
/// the conversion lives here, once, and is unit-tested.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum KeyBlock {
    /// `EFUSE_BLK_KEY0` / `HMAC_KEY0`.
    Key0,
    /// `EFUSE_BLK_KEY1` / `HMAC_KEY1`.
    Key1,
    /// `EFUSE_BLK_KEY2` / `HMAC_KEY2`.
    Key2,
    /// `EFUSE_BLK_KEY3` / `HMAC_KEY3`.
    Key3,
    /// `EFUSE_BLK_KEY4` / `HMAC_KEY4`.
    Key4,
    /// `EFUSE_BLK_KEY5` / `HMAC_KEY5`.
    Key5,
}

impl KeyBlock {
    /// Every key block, low to high. The iteration order of every readout in
    /// this crate, so two devices' readouts line up row for row.
    pub const ALL: [KeyBlock; 6] = [
        KeyBlock::Key0,
        KeyBlock::Key1,
        KeyBlock::Key2,
        KeyBlock::Key3,
        KeyBlock::Key4,
        KeyBlock::Key5,
    ];

    /// `0` to `5`: the index within the key-block range, and the value the HMAC
    /// peripheral's `hmac_key_id_t` uses.
    pub const fn index(self) -> u8 {
        self as u8
    }

    /// The eFuse API's block number. `EFUSE_BLK_KEY0` is block 4, not block 0.
    pub const fn efuse_block(self) -> u8 {
        self as u8 + 4
    }

    /// `KEY0` .. `KEY5`, spelled as `espefuse.py summary` spells them so a
    /// device readout can be compared against host tooling without translation.
    pub const fn name(self) -> &'static str {
        match self {
            KeyBlock::Key0 => "KEY0",
            KeyBlock::Key1 => "KEY1",
            KeyBlock::Key2 => "KEY2",
            KeyBlock::Key3 => "KEY3",
            KeyBlock::Key4 => "KEY4",
            KeyBlock::Key5 => "KEY5",
        }
    }

    /// Inverse of [`KeyBlock::index`].
    pub const fn from_index(index: u8) -> Option<KeyBlock> {
        match index {
            0 => Some(KeyBlock::Key0),
            1 => Some(KeyBlock::Key1),
            2 => Some(KeyBlock::Key2),
            3 => Some(KeyBlock::Key3),
            4 => Some(KeyBlock::Key4),
            5 => Some(KeyBlock::Key5),
            _ => None,
        }
    }

    /// Inverse of [`KeyBlock::efuse_block`]. `None` for a block outside the key
    /// range (BLK0 to BLK3 and BLK10 are system data, not key blocks).
    pub const fn from_efuse_block(block: u8) -> Option<KeyBlock> {
        if block < 4 {
            None
        } else {
            KeyBlock::from_index(block - 4)
        }
    }
}

/// What a key block is committed to.
///
/// The `KEY_PURPOSE` field is write-once: a block that has been set to one of
/// these can never serve another purpose, which is why this crate reports the
/// purpose rather than only reporting "in use".
///
/// The values are ESP32-P4's (`components/efuse/esp32p4/include/esp_efuse_chip.h`).
/// Other parts assign the same names to the same numbers where the purpose
/// exists at all; a number this enum does not know becomes
/// [`KeyPurpose::Unknown`] rather than an error, because a newer part gaining a
/// purpose must not turn an existing readout into a failure.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyPurpose {
    /// Software-only use. Also the value of an unburned block.
    User,
    /// ECDSA private key.
    EcdsaKey,
    /// Flash / PSRAM encryption, first half of an XTS-AES-256 key.
    XtsAes256Key1,
    /// Flash / PSRAM encryption, second half of an XTS-AES-256 key.
    XtsAes256Key2,
    /// Flash / PSRAM encryption, XTS-AES-128 key.
    XtsAes128Key,
    /// HMAC downstream mode, any downstream consumer.
    HmacDownAll,
    /// HMAC downstream mode, JTAG soft-enable token only.
    HmacDownJtag,
    /// HMAC downstream mode, Digital Signature peripheral only.
    HmacDownDigitalSignature,
    /// HMAC upstream mode: the only purpose whose result comes back to
    /// software, and therefore the only one [`crate::HmacKey`] will bind to.
    HmacUp,
    /// Secure Boot v2 public-key digest, slot 0.
    SecureBootDigest0,
    /// Secure Boot v2 public-key digest, slot 1.
    SecureBootDigest1,
    /// Secure Boot v2 public-key digest, slot 2.
    SecureBootDigest2,
    /// Key Manager initialisation key.
    KmInitKey,
    /// A purpose value this crate does not know. Reported verbatim.
    Unknown(u32),
}

impl KeyPurpose {
    /// The raw `esp_efuse_purpose_t` value.
    pub const fn raw(self) -> u32 {
        match self {
            KeyPurpose::User => 0,
            KeyPurpose::EcdsaKey => 1,
            KeyPurpose::XtsAes256Key1 => 2,
            KeyPurpose::XtsAes256Key2 => 3,
            KeyPurpose::XtsAes128Key => 4,
            KeyPurpose::HmacDownAll => 5,
            KeyPurpose::HmacDownJtag => 6,
            KeyPurpose::HmacDownDigitalSignature => 7,
            KeyPurpose::HmacUp => 8,
            KeyPurpose::SecureBootDigest0 => 9,
            KeyPurpose::SecureBootDigest1 => 10,
            KeyPurpose::SecureBootDigest2 => 11,
            KeyPurpose::KmInitKey => 12,
            KeyPurpose::Unknown(v) => v,
        }
    }

    /// Classify a raw `esp_efuse_purpose_t`.
    pub const fn from_raw(raw: u32) -> KeyPurpose {
        match raw {
            0 => KeyPurpose::User,
            1 => KeyPurpose::EcdsaKey,
            2 => KeyPurpose::XtsAes256Key1,
            3 => KeyPurpose::XtsAes256Key2,
            4 => KeyPurpose::XtsAes128Key,
            5 => KeyPurpose::HmacDownAll,
            6 => KeyPurpose::HmacDownJtag,
            7 => KeyPurpose::HmacDownDigitalSignature,
            8 => KeyPurpose::HmacUp,
            9 => KeyPurpose::SecureBootDigest0,
            10 => KeyPurpose::SecureBootDigest1,
            11 => KeyPurpose::SecureBootDigest2,
            12 => KeyPurpose::KmInitKey,
            other => KeyPurpose::Unknown(other),
        }
    }

    /// ESP-IDF's own enumerator spelling, minus the `ESP_EFUSE_KEY_PURPOSE_`
    /// prefix: `HMAC_UP`, `XTS_AES_128_KEY`, `SECURE_BOOT_DIGEST0`.
    ///
    /// Not a translation and not a description. A reader comparing a device
    /// against `espefuse.py summary` output or against a burn runbook is
    /// comparing this exact string, so prettifying it would destroy the only
    /// property that makes the row useful. [`KeyPurpose::Unknown`] renders as
    /// `UNKNOWN`; callers that must show the number use [`KeyPurpose::raw`].
    pub const fn idf_name(self) -> &'static str {
        match self {
            KeyPurpose::User => "USER",
            KeyPurpose::EcdsaKey => "ECDSA_KEY",
            KeyPurpose::XtsAes256Key1 => "XTS_AES_256_KEY_1",
            KeyPurpose::XtsAes256Key2 => "XTS_AES_256_KEY_2",
            KeyPurpose::XtsAes128Key => "XTS_AES_128_KEY",
            KeyPurpose::HmacDownAll => "HMAC_DOWN_ALL",
            KeyPurpose::HmacDownJtag => "HMAC_DOWN_JTAG",
            KeyPurpose::HmacDownDigitalSignature => "HMAC_DOWN_DIGITAL_SIGNATURE",
            KeyPurpose::HmacUp => "HMAC_UP",
            KeyPurpose::SecureBootDigest0 => "SECURE_BOOT_DIGEST0",
            KeyPurpose::SecureBootDigest1 => "SECURE_BOOT_DIGEST1",
            KeyPurpose::SecureBootDigest2 => "SECURE_BOOT_DIGEST2",
            KeyPurpose::KmInitKey => "KM_INIT_KEY",
            KeyPurpose::Unknown(_) => "UNKNOWN",
        }
    }
}

impl core::fmt::Display for KeyPurpose {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            KeyPurpose::Unknown(v) => write!(f, "UNKNOWN({v})"),
            other => f.write_str(other.idf_name()),
        }
    }
}

/// Everything the eFuse controller will say about one key block.
///
/// Read as a snapshot rather than field by field, because the fields are only
/// meaningful together: `purpose == HMAC_UP` with `read_protected == false` is
/// a key the CPU can still read, which is a materially different device from
/// one where the same purpose is read-protected.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct KeyBlockState {
    /// Which block this describes.
    pub block: KeyBlock,
    /// The block's write-once `KEY_PURPOSE`.
    pub purpose: KeyPurpose,
    /// `RD_DIS` for this block: software can no longer read its contents.
    pub read_protected: bool,
    /// `WR_DIS` for this block: its contents can no longer be changed.
    pub write_protected: bool,
    /// `WR_DIS` for this block's `KEY_PURPOSE` field: the block can no longer
    /// be repurposed even if it could still be written.
    pub purpose_write_protected: bool,
    /// ESP-IDF's `esp_efuse_key_block_unused()`: purpose `USER`, neither
    /// protection set, and all bits still zero. A block that is free to use.
    pub unused: bool,
}

impl KeyBlockState {
    /// True when this block is an HMAC upstream key that software can no longer
    /// read - the state the sealing use case requires.
    ///
    /// This is a statement of fact about three eFuse bits, not a judgement:
    /// what a caller does about a key block that is not in this state is the
    /// caller's policy, and this crate has none.
    pub const fn is_sealed_hmac_up(&self) -> bool {
        matches!(self.purpose, KeyPurpose::HmacUp) && self.read_protected
    }
}

// ---------------------------------------------------------------------------
// The eFuse controller. Everything above is pure data and is tested on the host.
// ---------------------------------------------------------------------------

#[cfg(target_os = "espidf")]
mod imp {
    use super::*;
    use crate::error::{Error, Result};
    use esp_idf_sys as sys;

    impl KeyBlock {
        pub(crate) const fn as_sys(self) -> sys::esp_efuse_block_t {
            self.efuse_block() as sys::esp_efuse_block_t
        }
    }

    /// Read one key block's state from the eFuse controller.
    ///
    /// Cost: a handful of memory-mapped register reads. The eFuse controller
    /// auto-loads BLK0 into read registers at reset, so none of this is an
    /// eFuse transaction and none of it can fail.
    pub fn state(block: KeyBlock) -> KeyBlockState {
        let blk = block.as_sys();
        // SAFETY: every one of these takes a block number by value and returns
        // a bool or an enum. `blk` is in range by construction (KeyBlock has
        // exactly six inhabitants and maps to EFUSE_BLK4..BLK9).
        unsafe {
            KeyBlockState {
                block,
                purpose: KeyPurpose::from_raw(sys::esp_efuse_get_key_purpose(blk) as u32),
                read_protected: sys::esp_efuse_get_key_dis_read(blk),
                write_protected: sys::esp_efuse_get_key_dis_write(blk),
                purpose_write_protected: sys::esp_efuse_get_keypurpose_dis_write(blk),
                unused: sys::esp_efuse_key_block_unused(blk),
            }
        }
    }

    /// Every key block's state, in [`KeyBlock::ALL`] order.
    pub fn all_states() -> [KeyBlockState; 6] {
        KeyBlock::ALL.map(state)
    }

    /// The block committed to `purpose`, if any.
    ///
    /// Purposes other than the three `SECURE_BOOT_DIGEST*` slots are unique by
    /// construction, so for those this is an unambiguous lookup; ESP-IDF's own
    /// `esp_efuse_find_purpose()` returns the lowest matching block either way.
    pub fn find(purpose: KeyPurpose) -> Option<KeyBlock> {
        let mut blk: sys::esp_efuse_block_t = 0;
        // SAFETY: `blk` is a valid out-pointer for the duration of the call.
        let found = unsafe { sys::esp_efuse_find_purpose(purpose.raw(), &mut blk) };
        if found {
            KeyBlock::from_efuse_block(blk as u8)
        } else {
            None
        }
    }

    /// The block committed to `purpose`, as an error rather than an `Option`.
    pub fn require(purpose: KeyPurpose) -> Result<KeyBlock> {
        find(purpose).ok_or(Error::PurposeNotFound(purpose))
    }
}

#[cfg(target_os = "espidf")]
pub use imp::{all_states, find, require, state};

#[cfg(test)]
mod tests {
    use super::*;

    /// The single most damaging bug this crate could have: addressing
    /// `EFUSE_BLK4` when the caller meant `HMAC_KEY0`, or the reverse. The two
    /// numbering schemes differ by exactly four and both are plain integers at
    /// the FFI boundary, so nothing but this test stands between them.
    #[test]
    fn the_two_numbering_schemes_do_not_drift() {
        assert_eq!(KeyBlock::Key0.index(), 0);
        assert_eq!(KeyBlock::Key0.efuse_block(), 4);
        assert_eq!(KeyBlock::Key5.index(), 5);
        assert_eq!(KeyBlock::Key5.efuse_block(), 9);

        for (i, block) in KeyBlock::ALL.iter().copied().enumerate() {
            assert_eq!(block.index() as usize, i);
            assert_eq!(block.efuse_block(), block.index() + 4);
            assert_eq!(KeyBlock::from_index(block.index()), Some(block));
            assert_eq!(KeyBlock::from_efuse_block(block.efuse_block()), Some(block));
        }

        // BLK0..BLK3 are system data and BLK10 is SYS_DATA_PART2; none is a key
        // block, and mapping one into this type would address the wrong fuses.
        for not_a_key_block in [0u8, 1, 2, 3, 10, 11, 255] {
            assert_eq!(KeyBlock::from_efuse_block(not_a_key_block), None);
        }
        assert_eq!(KeyBlock::from_index(6), None);
    }

    /// Names are compared character for character against `espefuse.py summary`
    /// and against the burn runbook, so a typo here is a silent mis-compare
    /// rather than a visible failure.
    #[test]
    fn purpose_names_are_idfs_own_spelling() {
        let expected = [
            (0u32, "USER"),
            (1, "ECDSA_KEY"),
            (2, "XTS_AES_256_KEY_1"),
            (3, "XTS_AES_256_KEY_2"),
            (4, "XTS_AES_128_KEY"),
            (5, "HMAC_DOWN_ALL"),
            (6, "HMAC_DOWN_JTAG"),
            (7, "HMAC_DOWN_DIGITAL_SIGNATURE"),
            (8, "HMAC_UP"),
            (9, "SECURE_BOOT_DIGEST0"),
            (10, "SECURE_BOOT_DIGEST1"),
            (11, "SECURE_BOOT_DIGEST2"),
            (12, "KM_INIT_KEY"),
        ];
        for (raw, name) in expected {
            let purpose = KeyPurpose::from_raw(raw);
            assert_eq!(purpose.raw(), raw, "round trip for {name}");
            assert_eq!(purpose.idf_name(), name);
        }
        // The longest enumerator is 27 characters. VERIFY.md 11.1 sizes the
        // Verify screen's key-block table around exactly that, so a longer name
        // arriving from a future part is a layout change, not a wrap.
        assert_eq!(KeyPurpose::HmacDownDigitalSignature.idf_name().len(), 27);
    }

    /// An unrecognised purpose must survive as a number. A future part that
    /// adds purpose 13 must not turn a readout into an error or, worse, into a
    /// plausible-looking wrong name.
    #[test]
    fn unknown_purposes_are_reported_not_guessed() {
        let p = KeyPurpose::from_raw(13);
        assert_eq!(p, KeyPurpose::Unknown(13));
        assert_eq!(p.raw(), 13);
        assert_eq!(p.idf_name(), "UNKNOWN");
        assert_eq!(p.to_string(), "UNKNOWN(13)");
    }

    #[test]
    fn sealed_means_hmac_up_and_read_protected() {
        let mut st = KeyBlockState {
            block: KeyBlock::Key0,
            purpose: KeyPurpose::HmacUp,
            read_protected: true,
            write_protected: true,
            purpose_write_protected: true,
            unused: false,
        };
        assert!(st.is_sealed_hmac_up());

        // A burned but still software-readable key is NOT sealed. This is the
        // distinction the whole readout exists to make visible.
        st.read_protected = false;
        assert!(!st.is_sealed_hmac_up());

        st.read_protected = true;
        st.purpose = KeyPurpose::HmacDownAll;
        assert!(!st.is_sealed_hmac_up());
    }
}
