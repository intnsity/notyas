// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The `settings` partition, as four `esp_partition_*` calls and no decisions.
//!
//! Every rule about the format - the A/B election, the CRC, the strict parse, the write
//! order that makes a torn write unreadable - lives in `notyas_wallet::settings`, where a
//! host test can reach it. This file is the part that cannot be host-tested, so it is kept
//! to the part that has nothing to get wrong: find the partition, read bytes, program
//! bytes, erase a sector.
//!
//! # Why it opens per call rather than living for the life of the device
//!
//! Because a save is a human tapping Save, once, and a load is one read at boot. Holding a
//! handle would mean threading it through `answer_request` and its recursive calls for a
//! resource whose lookup costs a table scan of four entries. `esp_partition_find_first` is
//! the whole of the state, so there is no state to hold.
//!
//! # What happens on a device whose table does not have this partition
//!
//! Nothing at all: [`load`] returns the defaults and [`save`] reports that there was
//! nowhere to write. That is the state of every device flashed before the 0.2.0 table, and
//! it must boot exactly as it did then - unnamed, on mainnet, with no error on the panel.

use core::ffi::{c_void, CStr};

use esp_idf_svc::sys;
use notyas_ui::Network;
use notyas_wallet::settings::{SettingsFlash, SettingsRegion, SECTOR_BYTES};
use notyas_wallet::{Settings, SettingsNetwork};

/// The partition label, frozen alongside `firmware/partitions.csv`. Looked up by label,
/// like the two sealing regions, because all three carry subtype `undefined` and the label
/// IS the identity.
const LABEL: &CStr = c"settings";

/// Bounce-buffer size. Every transfer goes through an internal-RAM buffer on the stack for
/// the reason `store/flash.rs` documents at length: handing `esp_partition_*` a
/// PSRAM-resident buffer makes IDF allocate one of its own at the moment of the call. 256
/// bytes rather than a sector because the largest single transfer this module makes is a
/// 4 KiB slot read and sixteen memcpys of 256 bytes cost nothing a user can perceive.
const BOUNCE: usize = 256;

/// What went wrong, and where. The ESP error code rather than a prose summary, for the
/// same reason the store's driver keeps it: a number can be looked up.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SettingsError {
    op: &'static str,
    offset: u32,
    len: u32,
    code: sys::esp_err_t,
}

impl core::fmt::Debug for SettingsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "SettingsError({} off=0x{:x} len={} esp_err=0x{:x})",
            self.op, self.offset, self.len, self.code
        )
    }
}

/// The partition, and the internal buffer every transfer bounces through.
struct PartitionSettings {
    part: *const sys::esp_partition_t,
    sectors: u32,
    bounce: [u8; BOUNCE],
}

impl PartitionSettings {
    /// Adopt the partition, or `None` if this device's table has no usable one.
    ///
    /// Three refusals, all of them build- or flash-time mistakes rather than anything a
    /// user can cause: the partition is absent (a pre-0.2.0 table, and the only one of the
    /// three that is not a defect), it is marked `encrypted` - which would make a region
    /// that must be readable before any key exists depend on a key - or its erase
    /// granularity is not the 4 KiB the format assumes. The two that are defects are
    /// logged, so a technician reads them off the boot log. Whether the region is big
    /// enough for two slots is `SettingsRegion::open`'s check, because it is the format's
    /// rule and not this partition's.
    fn open() -> Option<PartitionSettings> {
        // SAFETY: a plain lookup; the returned pointer is either null or valid for the
        // lifetime of the application (IDF contract).
        let part = unsafe {
            sys::esp_partition_find_first(
                sys::esp_partition_type_t_ESP_PARTITION_TYPE_DATA,
                sys::esp_partition_subtype_t_ESP_PARTITION_SUBTYPE_DATA_UNDEFINED,
                LABEL.as_ptr(),
            )
        };
        if part.is_null() {
            return None;
        }
        // SAFETY: non-null, therefore a live partition descriptor.
        let (size, erase, encrypted) = unsafe { ((*part).size, (*part).erase_size, (*part).encrypted) };
        if encrypted {
            log::error!(
                "settings: partition is marked encrypted - it must be readable before any \
                 key exists; settings will not persist"
            );
            return None;
        }
        if erase != SECTOR_BYTES {
            log::error!("settings: erase size {erase} is not the {SECTOR_BYTES} the format assumes");
            return None;
        }
        Some(PartitionSettings {
            part,
            sectors: size / SECTOR_BYTES,
            bounce: [0u8; BOUNCE],
        })
    }

    fn err(&self, op: &'static str, offset: u32, len: u32, code: sys::esp_err_t) -> SettingsError {
        SettingsError { op, offset, len, code }
    }
}

impl SettingsFlash for PartitionSettings {
    type Error = SettingsError;

    fn sectors(&self) -> u32 {
        self.sectors
    }

    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), SettingsError> {
        let mut done = 0usize;
        while done < buf.len() {
            let n = core::cmp::min(BOUNCE, buf.len() - done);
            let at = offset.saturating_add(done as u32);
            // SAFETY: `bounce` owns BOUNCE bytes and n <= BOUNCE; `part` is a live IDF
            // partition; IDF bounds-checks the range against the partition size.
            let code = unsafe {
                sys::esp_partition_read(
                    self.part,
                    at as usize,
                    self.bounce.as_mut_ptr() as *mut c_void,
                    n,
                )
            };
            if code != sys::ESP_OK {
                return Err(self.err("read", at, n as u32, code));
            }
            buf[done..done + n].copy_from_slice(&self.bounce[..n]);
            done += n;
        }
        Ok(())
    }

    fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), SettingsError> {
        let mut done = 0usize;
        while done < data.len() {
            let n = core::cmp::min(BOUNCE, data.len() - done);
            let at = offset.saturating_add(done as u32);
            self.bounce[..n].copy_from_slice(&data[done..done + n]);
            // SAFETY: the source is our own internal-RAM buffer of exactly n bytes and
            // `part` is live; IDF bounds-checks the destination range.
            let code = unsafe {
                sys::esp_partition_write(
                    self.part,
                    at as usize,
                    self.bounce.as_ptr() as *const c_void,
                    n,
                )
            };
            if code != sys::ESP_OK {
                return Err(self.err("write", at, n as u32, code));
            }
            done += n;
        }
        Ok(())
    }

    fn erase_sector(&mut self, sector: u32) -> Result<(), SettingsError> {
        let at = sector.saturating_mul(SECTOR_BYTES);
        // SAFETY: `part` is live; IDF checks alignment and bounds and returns an error
        // rather than erasing outside the partition.
        let code = unsafe {
            sys::esp_partition_erase_range(self.part, at as usize, SECTOR_BYTES as usize)
        };
        if code != sys::ESP_OK {
            return Err(self.err("erase", at, SECTOR_BYTES, code));
        }
        Ok(())
    }
}

fn region() -> Option<SettingsRegion<PartitionSettings>> {
    let part = PartitionSettings::open()?;
    match SettingsRegion::open(part) {
        Ok(r) => Some(r),
        Err(e) => {
            log::error!("settings: region unusable: {e:?} - settings will not persist");
            None
        }
    }
}

/// Whether this device has somewhere to keep its settings.
///
/// Asked so that a failed save can be reported to the user as a failure only when it IS
/// one. On a device whose table predates this region there is nothing to report and
/// nothing broken; the name still works for the life of the power-up, exactly as it did
/// before the region existed.
pub fn available() -> bool {
    PartitionSettings::open().is_some()
}

/// What this device has saved, or the defaults.
///
/// Never fails and never blocks a boot: an absent partition, a blank region, a torn write
/// and a corrupted record all arrive at the defaults, because "no valid slot" is one
/// condition and not four.
pub fn load() -> Settings {
    let Some(mut r) = region() else {
        log::info!("settings: no settings partition - device name and network are session-only");
        return Settings::new();
    };
    match r.load() {
        Ok(s) => s,
        Err(e) => {
            log::error!("settings: unreadable ({e:?}) - using defaults");
            Settings::new()
        }
    }
}

/// Persist `settings`, reporting whether they will survive the next power cycle.
///
/// `false` means exactly that and nothing more: the value is still in force for this
/// power-up, because the UI holds it, and the caller decides whether the user needs to be
/// told (see `answer_set_device_name`).
pub fn save(settings: &Settings) -> bool {
    let Some(mut r) = region() else {
        return false;
    };
    match r.save(settings) {
        Ok(()) => true,
        Err(e) => {
            log::error!("settings: save failed: {e:?}");
            false
        }
    }
}

/// Read, change one value, write back.
///
/// Load-modify-save rather than a cached copy, because the settings record is one small
/// object written by two unrelated user actions (naming the device, toggling the network)
/// and a cached copy is how one of them silently reverts the other.
pub fn update(change: impl FnOnce(&mut Settings)) -> bool {
    let mut s = load();
    change(&mut s);
    save(&s)
}

/// Erase both slots. For the one caller entitled to it: an operation that destroys what
/// the device holds must not leave the previous owner's device name on the lock screen.
#[allow(dead_code)] // The destructive flow that will call it is refused in this build.
pub fn clear() -> bool {
    let Some(mut r) = region() else {
        return false;
    };
    match r.clear() {
        Ok(()) => true,
        Err(e) => {
            log::error!("settings: clear failed: {e:?}");
            false
        }
    }
}

/// The pipeline's four-way network as the two-way one the settings record defines.
///
/// `None` for signet and regtest: they are reachable only from the test console, which is
/// not a user preference, and writing "nearest neighbour" into a persistent record is how a
/// device comes back up on a chain nobody chose.
pub fn network_tag(network: Network) -> Option<SettingsNetwork> {
    match network {
        Network::Bitcoin => Some(SettingsNetwork::Mainnet),
        Network::Testnet => Some(SettingsNetwork::Testnet),
        _ => None,
    }
}

/// The stored network as the pipeline's.
pub fn network_from(tag: SettingsNetwork) -> Network {
    match tag {
        SettingsNetwork::Mainnet => Network::Bitcoin,
        SettingsNetwork::Testnet => Network::Testnet,
    }
}
