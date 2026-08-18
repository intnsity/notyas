// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! [`notyas_wallet::Flash`] over two `esp_partition_*` regions.
//!
//! The whole driver is thirty lines of real logic wrapped in the care that the two
//! regions' physically different write rules demand (ESP-SEAL.md 2.2). Three decisions
//! carry the weight:
//!
//! **`is_erased` reads RAW.** On a release unit `wallets` is XTS-encrypted, so
//! `esp_partition_read` returns *decrypted* bytes and an erased sector decrypts to
//! pseudorandom noise, never `0xff`. An erasure test built on the logical view passes on
//! every dev board and fails on every shipped one. `esp_partition_read_raw` is the only
//! call in this file that bypasses the cipher, and it exists solely for that question.
//!
//! **`cipher_block` is 16 whether or not this board encrypts.** It is a statement about
//! the format's write discipline, not about this silicon: the engine must lay records out
//! so that they are legal on an encrypted partition, because the same bytes have to be
//! readable when the same firmware runs on a unit that has flash encryption burned. It
//! also makes the device's write pattern identical to `SimFlash::v1`'s, which is what lets
//! the known-answer vectors compare a device image against a host image byte for byte.
//!
//! **Every transfer bounces through internal DMA-capable RAM.** `esp_flash_*` has to
//! handle a PSRAM-resident buffer by allocating a bounce buffer of its own, at the
//! moment of the call, on a path that is already committed to a flash program. Owning one
//! buffer for the life of the driver turns "may allocate under the commit point" into
//! "allocated at mount or the mount failed", and the failure is then diagnosable at boot
//! rather than at a user's PIN entry.

use core::ffi::{c_void, CStr};

use esp_idf_svc::sys;
use notyas_wallet::{Flash, Geometry, Region};

/// Sector size on every ESP32 part, and the unit `Layout::V1` is frozen against.
pub const SECTOR_BYTES: u32 = 4096;
const SECTOR: u32 = SECTOR_BYTES;
/// Bounce-buffer size. One sector: the largest single access the engine makes is a
/// two-sector registry side, and chunking that into two passes costs one extra memcpy.
const BOUNCE: usize = SECTOR as usize;
/// See the module docs. Not `geometry.write_gran`, deliberately.
const CIPHER_BLOCK: u32 = 16;
/// ESP-IDF's program granularity on a plaintext partition.
const WRITE_GRAN: u32 = 4;

/// Partition labels, frozen alongside `firmware/partitions.csv`. Looked up by label
/// rather than by subtype because both regions carry subtype `undefined`: the label IS
/// the identity, and a table that lost one of them must fail loudly at boot.
const RECORDS_LABEL: &CStr = c"wallets";
const LEDGER_LABEL: &CStr = c"counters";

/// What went wrong, and where. Carries the ESP error code rather than a prose summary:
/// the engine surfaces this verbatim into `HardwareFault`, and a number that can be
/// looked up beats an adjective.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FlashError {
    pub op: &'static str,
    pub region: Region,
    pub offset: u32,
    pub len: u32,
    pub code: sys::esp_err_t,
}

impl core::fmt::Debug for FlashError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "FlashError({} {:?} off=0x{:x} len={} esp_err=0x{:x})",
            self.op, self.region, self.offset, self.len, self.code
        )
    }
}

impl core::fmt::Display for FlashError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(self, f)
    }
}

/// Why the two partitions could not be adopted. Distinct from [`FlashError`] because
/// these are all build/flash-time mistakes a user cannot cause and a technician must be
/// able to read off a boot log.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OpenError {
    /// No partition with that label in the table at 0x8000.
    Missing(&'static str),
    /// Found, but not the size `Layout::V1` freezes. Refused rather than clamped: a
    /// smaller region would silently truncate the slot map, and a larger one would leave
    /// a tail the engine never scrubs.
    WrongSize {
        label: &'static str,
        want: u32,
        got: u32,
    },
    /// The partition's erase granularity is not the 4 KiB the format assumes.
    WrongEraseSize { label: &'static str, got: u32 },
    /// `counters` is marked encrypted. The guarded bit-log advances by clearing bits in
    /// an already-programmed cell, which an encrypted partition cannot express; a table
    /// that says otherwise would corrupt the ledger on the first attempt.
    LedgerEncrypted,
    /// The bounce buffer could not be allocated from internal RAM.
    NoBounce,
}

/// Two raw partitions, the internal bounce buffer they share, and nothing else.
pub struct PartitionFlash {
    records: *const sys::esp_partition_t,
    ledger: *const sys::esp_partition_t,
    geometry: Geometry,
    /// Internal, DMA-capable. Owned for the driver's life; see the module docs.
    bounce: *mut u8,
}

impl core::fmt::Debug for PartitionFlash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PartitionFlash")
            .field("geometry", &self.geometry)
            .finish()
    }
}

impl PartitionFlash {
    /// Adopt the two frozen partitions, or say exactly why not.
    ///
    /// `records_bytes` and `ledger_bytes` are the sizes the caller's `Layout` demands.
    /// They are passed in rather than hardcoded so that the one place the numbers live is
    /// `notyas_wallet::Layout::V1`, and a layout change becomes a compile-time-visible
    /// mismatch here instead of a silent acceptance of the wrong table.
    pub fn open(records_bytes: u32, ledger_bytes: u32) -> Result<PartitionFlash, OpenError> {
        let records = find(RECORDS_LABEL, "wallets", records_bytes)?;
        let ledger = find(LEDGER_LABEL, "counters", ledger_bytes)?;

        // SAFETY: both pointers came from esp_partition_find_first and are valid for the
        // lifetime of the application (IDF contract).
        if unsafe { (*ledger).encrypted } {
            return Err(OpenError::LedgerEncrypted);
        }

        let bounce = unsafe {
            sys::heap_caps_malloc(
                BOUNCE,
                sys::MALLOC_CAP_INTERNAL | sys::MALLOC_CAP_DMA | sys::MALLOC_CAP_8BIT,
            )
        } as *mut u8;
        if bounce.is_null() {
            return Err(OpenError::NoBounce);
        }

        Ok(PartitionFlash {
            records,
            ledger,
            geometry: Geometry {
                sector_size: SECTOR,
                records_sectors: records_bytes / SECTOR,
                ledger_sectors: ledger_bytes / SECTOR,
                cipher_block: CIPHER_BLOCK,
                write_gran: WRITE_GRAN,
            },
            bounce,
        })
    }

    /// Absolute flash address of a region's byte 0. Diagnostics only - nothing in the
    /// engine ever names an absolute address, which is the property that makes a
    /// repartition unable to silently move a record.
    pub fn base(&self, region: Region) -> u32 {
        // SAFETY: as in `open`.
        unsafe { (*self.part(region)).address }
    }

    fn part(&self, region: Region) -> *const sys::esp_partition_t {
        match region {
            Region::Records => self.records,
            Region::Ledger => self.ledger,
        }
    }

    fn err(&self, op: &'static str, region: Region, offset: u32, len: u32, code: sys::esp_err_t) -> FlashError {
        FlashError { op, region, offset, len, code }
    }

    /// Read through the bounce buffer, `f` seeing one internal-RAM chunk at a time.
    ///
    /// `raw` selects `esp_partition_read_raw` over `esp_partition_read`; the only caller
    /// that passes `true` is [`Flash::is_erased`], and the module docs say why.
    fn read_chunked(
        &mut self,
        region: Region,
        offset: u32,
        len: u32,
        raw: bool,
        mut f: impl FnMut(&[u8]),
    ) -> Result<(), FlashError> {
        let part = self.part(region);
        let mut done = 0u32;
        while done < len {
            let n = core::cmp::min(BOUNCE as u32, len - done);
            let at = offset + done;
            // SAFETY: `bounce` owns BOUNCE bytes and n <= BOUNCE; `part` is a live IDF
            // partition; the range is bounds-checked by IDF against the partition size.
            let code = unsafe {
                let dst = self.bounce as *mut c_void;
                if raw {
                    sys::esp_partition_read_raw(part, at as usize, dst, n as usize)
                } else {
                    sys::esp_partition_read(part, at as usize, dst, n as usize)
                }
            };
            if code != sys::ESP_OK {
                let op = if raw { "read_raw" } else { "read" };
                return Err(self.err(op, region, at, n, code));
            }
            // SAFETY: the call above initialized exactly n bytes of the buffer.
            f(unsafe { core::slice::from_raw_parts(self.bounce, n as usize) });
            done += n;
        }
        Ok(())
    }

    /// Read the region's RAW bytes - the undecrypted, uninterpreted view.
    ///
    /// This is what `SimFlash::raw` returns on the host, and it is therefore the only
    /// view a device-versus-host image comparison may use. On a dev unit with flash
    /// encryption off it is identical to [`Flash::read`]; on a release unit it is not,
    /// and a comparison built on the logical view would silently compare plaintexts
    /// while claiming to compare images.
    pub fn read_raw(
        &mut self,
        region: Region,
        offset: u32,
        buf: &mut [u8],
    ) -> Result<(), FlashError> {
        let len = buf.len() as u32;
        let mut written = 0usize;
        self.read_chunked(region, offset, len, true, |chunk| {
            buf[written..written + chunk.len()].copy_from_slice(chunk);
            written += chunk.len();
        })
    }

    /// Stream the region's RAW bytes to `f` a sector at a time, so a caller can hash or
    /// scan 256 KiB without a 256 KiB buffer.
    pub fn scan_raw(
        &mut self,
        region: Region,
        f: impl FnMut(&[u8]),
    ) -> Result<(), FlashError> {
        let len = match region {
            Region::Records => self.geometry.records_sectors,
            Region::Ledger => self.geometry.ledger_sectors,
        } * SECTOR;
        self.read_chunked(region, 0, len, true, f)
    }

    /// Erase the whole region. Not part of the engine's `Flash` contract - the engine
    /// only ever erases one sector at a time and only ones it owns - and used by nothing
    /// but the test console, which needs to return a board to factory-blank.
    pub fn erase_all(&mut self, region: Region) -> Result<(), FlashError> {
        let sectors = match region {
            Region::Records => self.geometry.records_sectors,
            Region::Ledger => self.geometry.ledger_sectors,
        };
        for s in 0..sectors {
            self.erase_sector(region, s)?;
        }
        Ok(())
    }
}

impl Drop for PartitionFlash {
    fn drop(&mut self) {
        if !self.bounce.is_null() {
            // SAFETY: allocated by heap_caps_malloc in `open` and not freed elsewhere.
            unsafe { sys::heap_caps_free(self.bounce as *mut c_void) };
        }
    }
}

fn find(
    label: &'static CStr,
    name: &'static str,
    want: u32,
) -> Result<*const sys::esp_partition_t, OpenError> {
    // SAFETY: a plain lookup; the returned pointer is either null or valid for the
    // lifetime of the application.
    let p = unsafe {
        sys::esp_partition_find_first(
            sys::esp_partition_type_t_ESP_PARTITION_TYPE_DATA,
            sys::esp_partition_subtype_t_ESP_PARTITION_SUBTYPE_DATA_UNDEFINED,
            label.as_ptr(),
        )
    };
    if p.is_null() {
        return Err(OpenError::Missing(name));
    }
    // SAFETY: non-null, therefore a live partition descriptor.
    let (size, erase) = unsafe { ((*p).size, (*p).erase_size) };
    if size != want {
        return Err(OpenError::WrongSize { label: name, want, got: size });
    }
    if erase != SECTOR {
        return Err(OpenError::WrongEraseSize { label: name, got: erase });
    }
    Ok(p)
}

impl Flash for PartitionFlash {
    type Error = FlashError;

    fn geometry(&self) -> Geometry {
        self.geometry
    }

    fn read(&mut self, region: Region, offset: u32, buf: &mut [u8]) -> Result<(), Self::Error> {
        let len = buf.len() as u32;
        let mut written = 0usize;
        self.read_chunked(region, offset, len, false, |chunk| {
            buf[written..written + chunk.len()].copy_from_slice(chunk);
            written += chunk.len();
        })
    }

    fn write(&mut self, region: Region, offset: u32, data: &[u8]) -> Result<(), Self::Error> {
        let part = self.part(region);
        let mut done = 0usize;
        while done < data.len() {
            let n = core::cmp::min(BOUNCE, data.len() - done);
            let at = offset + done as u32;
            // SAFETY: `bounce` owns BOUNCE bytes and n <= BOUNCE.
            unsafe { core::ptr::copy_nonoverlapping(data.as_ptr().add(done), self.bounce, n) };
            // SAFETY: `part` is live, the source is our own internal buffer, and IDF
            // bounds-checks the destination range against the partition size.
            let code = unsafe {
                sys::esp_partition_write(part, at as usize, self.bounce as *const c_void, n)
            };
            if code != sys::ESP_OK {
                return Err(self.err("write", region, at, n as u32, code));
            }
            done += n;
        }
        Ok(())
    }

    fn erase_sector(&mut self, region: Region, sector: u32) -> Result<(), Self::Error> {
        let at = sector * SECTOR;
        // SAFETY: `part` is live; IDF checks alignment and bounds and returns an error
        // rather than erasing outside the partition.
        let code = unsafe {
            sys::esp_partition_erase_range(self.part(region), at as usize, SECTOR as usize)
        };
        if code != sys::ESP_OK {
            return Err(self.err("erase", region, at, SECTOR, code));
        }
        Ok(())
    }

    fn is_erased(&mut self, region: Region, offset: u32, len: u32) -> Result<bool, Self::Error> {
        // Accumulate rather than early-return: the answer is the AND of every byte, the
        // cost does not depend on the content, and a scan whose duration leaks where the
        // first non-erased byte sits is a side channel for free.
        let mut acc = 0xffu8;
        self.read_chunked(region, offset, len, true, |chunk| {
            for b in chunk {
                acc &= *b;
            }
        })?;
        Ok(acc == 0xff)
    }
}
