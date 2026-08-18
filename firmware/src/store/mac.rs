// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! [`notyas_wallet::DeviceMac`] over the ESP32-P4 HMAC peripheral, with an honest
//! unprovisioned state and a fenced development substitute.
//!
//! # Why there are three arms and not two
//!
//! The device-binding key is supposed to live in a read-protected eFuse block that
//! software cannot read and the HMAC peripheral can. Getting one there is the factory
//! ceremony of ESP-SEAL.md 4.3, performed by the HOST with `espefuse.py`; release
//! firmware contains no eFuse-burn code at all, so this file cannot create the key it
//! needs. A board that has not been through that ceremony is therefore a real, expected,
//! permanent state - `KeyProvenance::Absent`, surfaced as `StoreState::Unprovisioned` -
//! and not a hardware fault. "Your board was never provisioned" and "your board is
//! broken" are different sentences to show a person (ratified Q45).
//!
//! # Why the emulated arm exists at all, and how it is fenced
//!
//! Both development boards are irreversibly eFuse-virgin by owner instruction and there
//! is no third board, so the peripheral path cannot be exercised here: the peripheral's
//! key-purpose check is performed by hardware against the REAL block and `CONFIG_EFUSE_VIRTUAL`
//! cannot fool it (see `src/hmac_check.rs`). Storage logic still has to run on real
//! silicon, against real flash, at the real Argon2 cost. That is what the emulated arm
//! buys, and ESP-SEAL.md 6.4's five fences are what keep it from ever meaning anything
//! else:
//!
//! 1. a non-default cargo feature with a deliberately ugly name;
//! 2. `build.rs` fails the build outright when it is on in a release profile;
//! 3. the provenance byte is inside every AEAD's associated data, so a record sealed
//!    under this key **cannot** be opened by a production build, nor the reverse;
//! 4. `Config::accept_provenance` on a product build lists only `EfuseReadProtected`, so
//!    a release image that somehow acquired this backend refuses at `mount()`;
//! 5. the true provenance is displayed, never a constant - see `provenance_label`.

use notyas_wallet::{DeviceMac, KeyProvenance};

use esp_idf_hmac::key_block::{self, KeyPurpose};
use esp_idf_hmac::{Error as HmacError, HmacKey};

/// Failure of the device-binding MAC. Never a silent substitution: the engine treats
/// this as a hardware fault and refuses the whole operation, which is the only correct
/// response to "the key that binds records to this board did not answer".
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MacError {
    /// No key of any kind. Only reachable when the store has already been reported
    /// `Unprovisioned`; a defensive arm, not an expected path.
    Unprovisioned,
    /// The peripheral refused or faulted. Carries the crate's typed reason.
    Peripheral(HmacError),
}

impl core::fmt::Display for MacError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MacError::Unprovisioned => f.write_str("no device-binding key on this board"),
            MacError::Peripheral(e) => write!(f, "HMAC peripheral: {e}"),
        }
    }
}

/// The compiled-in development key. Visibly fake by construction: it is a counting
/// pattern, so a hex dump of anything derived from it is recognisable at a glance and
/// nobody can mistake a development store for a provisioned one.
///
/// It is deliberately NOT the host test key `[0x5a; 32]`. The known-answer vectors use
/// that one, and a device whose ordinary store shared a key with the KAT would let a
/// published vector open a developer's records.
#[cfg(feature = "unsafe-emulated-key")]
const DEV_KEY: [u8; 32] = [
    0x6e, 0x6f, 0x74, 0x79, 0x61, 0x73, 0x2d, 0x64, 0x65, 0x76, 0x2d, 0x6b, 0x65, 0x79, 0x2d, 0x6e,
    0x6f, 0x74, 0x2d, 0x73, 0x65, 0x63, 0x75, 0x72, 0x65, 0x2d, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31,
];

/// The device-binding MAC, in whichever form this board can actually offer.
pub enum DeviceHmac {
    /// A real eFuse key block with purpose `HMAC_UP`. `provenance` distinguishes a
    /// properly sealed block from one whose read protection was never applied.
    Peripheral { key: HmacKey, provenance: KeyProvenance },
    /// A software HMAC-SHA256 under [`DEV_KEY`]. See the module docs.
    #[cfg(feature = "unsafe-emulated-key")]
    Emulated,
    /// No key. Every operation refuses and the store reports `Unprovisioned`.
    Absent,
}

impl core::fmt::Debug for DeviceHmac {
    /// The arm and the provenance. Never the key, and never anything derived from it.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "DeviceHmac({})", self.label())
    }
}

impl DeviceHmac {
    /// Read the eFuse key blocks and pick the strongest arm this board can honestly
    /// offer. Never burns, never writes, never guesses: the only calls are reads.
    pub fn detect() -> DeviceHmac {
        match HmacKey::find() {
            Ok(key) => {
                let st = key_block::state(key.block());
                // A block whose purpose is HMAC_UP but whose value software can still
                // read is a real and reachable state: it is what a provisioning run cut
                // between ESP-SEAL 4.3's P2 and P3 leaves behind. It is a weaker tier, it
                // is a different tier inside the AEAD, and the product must say so.
                let provenance = if st.read_protected {
                    KeyProvenance::EfuseReadProtected
                } else {
                    KeyProvenance::EfuseReadable
                };
                DeviceHmac::Peripheral { key, provenance }
            }
            Err(HmacError::PurposeNotFound(KeyPurpose::HmacUp)) => DeviceHmac::unprovisioned(),
            // Any other error means the eFuse readout itself did not work. Falling back
            // to the development key here would be the exact failure this crate's
            // `fd90a4c` fix existed to prevent - a failed read must not be able to look
            // like a usable state - so it resolves to Absent, which refuses everything.
            Err(_) => DeviceHmac::Absent,
        }
    }

    #[cfg(feature = "unsafe-emulated-key")]
    fn unprovisioned() -> DeviceHmac {
        DeviceHmac::Emulated
    }

    #[cfg(not(feature = "unsafe-emulated-key"))]
    fn unprovisioned() -> DeviceHmac {
        DeviceHmac::Absent
    }

    /// One-line rendering for the log and for the Verify screen. This is fence 5: the
    /// product displays what it READ, never a constant, and an emulated build says so in
    /// words a user cannot miss.
    pub fn label(&self) -> &'static str {
        match self {
            DeviceHmac::Peripheral {
                provenance: KeyProvenance::EfuseReadProtected,
                ..
            } => "eFuse HMAC_UP key, read-protected",
            DeviceHmac::Peripheral { .. } => {
                "eFuse HMAC_UP key, SOFTWARE-READABLE (provisioning incomplete)"
            }
            #[cfg(feature = "unsafe-emulated-key")]
            DeviceHmac::Emulated => "EMULATED KEY - development build, NOT SECURE",
            DeviceHmac::Absent => "not provisioned",
        }
    }
}

impl DeviceMac for DeviceHmac {
    type Error = MacError;

    fn hmac(&mut self, msg: &[u8], out: &mut [u8; 32]) -> Result<(), MacError> {
        match self {
            DeviceHmac::Peripheral { key, .. } => {
                key.mac_into(msg, out).map_err(MacError::Peripheral)
            }
            #[cfg(feature = "unsafe-emulated-key")]
            DeviceHmac::Emulated => {
                out.copy_from_slice(&soft_hmac(&DEV_KEY, msg));
                Ok(())
            }
            DeviceHmac::Absent => Err(MacError::Unprovisioned),
        }
    }

    fn provenance(&self) -> KeyProvenance {
        match self {
            DeviceHmac::Peripheral { provenance, .. } => *provenance,
            #[cfg(feature = "unsafe-emulated-key")]
            DeviceHmac::Emulated => KeyProvenance::Emulated,
            DeviceHmac::Absent => KeyProvenance::Absent,
        }
    }
}

// -------------------------------------------------------------------------------------
// Software HMAC - development and known-answer testing only
// -------------------------------------------------------------------------------------

/// HMAC-SHA256 in software. Present only in a development or test-console build; a
/// product image has no compiled-in key for it to use and does not link it.
#[cfg(any(feature = "unsafe-emulated-key", feature = "hil-console"))]
pub fn soft_hmac(key: &[u8; 32], msg: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, KeyInit, Mac};
    let mut h = <Hmac<sha2::Sha256>>::new_from_slice(key)
        .expect("HMAC-SHA256 accepts any key length, so a 32-byte key cannot be rejected");
    h.update(msg);
    h.finalize().into_bytes().into()
}

/// A [`DeviceMac`] under a caller-supplied constant key, reporting a caller-supplied
/// provenance.
///
/// This is `notyas_wallet::sim::SoftMac` reimplemented in the firmware, and it has to be
/// reimplemented rather than imported: `sim` lives behind the wallet crate's `testkit`
/// feature, which the build-graph check forbids in a firmware image because enabling it
/// would also pull the power-loss simulator into the product's dependency graph.
///
/// Its only caller is the known-answer test in `src/hil.rs`, whose entire purpose is to
/// prove that the real `esp_partition` driver, on real silicon, at the pinned Argon2
/// cost, produces the SAME flash image as the host simulator that the power-loss fuzzer
/// proved. That comparison is only meaningful if the MAC is byte-identical to the host's,
/// which is why the key is a parameter and the published vector's `[0x5a; 32]` is not
/// hardcoded here.
#[cfg(feature = "hil-console")]
pub struct FixedKeyMac {
    key: [u8; 32],
    provenance: KeyProvenance,
}

#[cfg(feature = "hil-console")]
impl core::fmt::Debug for FixedKeyMac {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FixedKeyMac")
            .field("provenance", &self.provenance)
            .field("key", &"<redacted>")
            .finish()
    }
}

#[cfg(feature = "hil-console")]
impl FixedKeyMac {
    pub fn new(key: [u8; 32], provenance: KeyProvenance) -> FixedKeyMac {
        FixedKeyMac { key, provenance }
    }
}

#[cfg(feature = "hil-console")]
impl DeviceMac for FixedKeyMac {
    type Error = MacError;

    fn hmac(&mut self, msg: &[u8], out: &mut [u8; 32]) -> Result<(), MacError> {
        if self.provenance == KeyProvenance::Absent {
            return Err(MacError::Unprovisioned);
        }
        out.copy_from_slice(&soft_hmac(&self.key, msg));
        Ok(())
    }

    fn provenance(&self) -> KeyProvenance {
        self.provenance
    }
}
