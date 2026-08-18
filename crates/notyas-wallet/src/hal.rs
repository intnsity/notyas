// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The entire hardware surface of the sealing engine: two traits and a borrowed buffer.
//!
//! ESP-SEAL.md 2.2 is normative here. The whole point of keeping it this narrow is that
//! the engine above it is a pure function of `(flash bytes, MAC responses, caller
//! inputs)`, which is what makes the power-loss fuzzer possible with no silicon at all.
//!
//! ## Why `Flash` and not WALLET-API.md's `Storage`
//!
//! WALLET-API.md 2.2 sketches a `Storage` trait with `read`/`write`/`erase` and a
//! `write_granularity`. It is missing the one method that cannot be emulated above the
//! driver: [`Flash::is_erased`]. On an XTS-encrypted ESP-IDF partition `read()` returns
//! DECRYPTED bytes, so an erased sector reads back as pseudorandom noise, not `0xff`.
//! Any erasure test built on `read()` works perfectly on a plaintext dev board and fails
//! on every release unit. MILESTONES.md m3 makes ESP-SEAL.md authoritative for the
//! platform-trait contracts for exactly this class of reason, so the ESP-SEAL shape is
//! what is implemented.

use crate::config::KdfParams;

/// Which of the two raw partitions an access targets.
///
/// They are separate regions rather than one address space because their write rules are
/// physically different, and conflating them is the mistake that the red-team pass caught
/// (ARCHITECTURE.md 2.5): progressive bit clearing is legal in [`Region::Ledger`] and
/// impossible in [`Region::Records`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Region {
    /// Sealed records. `encrypted` on release units, therefore write-once per cipher
    /// block between erases.
    Records,
    /// Guarded bit-log counters. Plaintext by necessity; advanced by clearing bits in a
    /// previously erased cell.
    Ledger,
}

/// Physical parameters of the two regions, read from the backend and checked against the
/// compile-time [`crate::config::Layout`] at mount.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Geometry {
    /// 4096 on every ESP32 part.
    pub sector_size: u32,
    pub records_sectors: u32,
    pub ledger_sectors: u32,
    /// 16 when `Records` is XTS-encrypted, else the write granularity.
    pub cipher_block: u32,
    /// Write granularity of the plaintext ledger region. 4 on ESP-IDF.
    pub write_gran: u32,
}

/// Byte-addressable NOR flash, split into the two regions the engine owns.
///
/// Offsets are relative to the start of the region, so the engine never names a
/// partition address and a repartition cannot silently move a record.
pub trait Flash {
    type Error: core::fmt::Debug;

    fn geometry(&self) -> Geometry;

    /// Logical read. On an ESP-IDF encrypted partition this is `esp_partition_read`,
    /// i.e. it returns DECRYPTED bytes.
    fn read(&mut self, region: Region, offset: u32, buf: &mut [u8]) -> Result<(), Self::Error>;

    /// Logical write.
    ///
    /// On an encrypted partition, `offset` and `data.len()` must both be multiples of
    /// `geometry().cipher_block`, and any given cipher block may be written AT MOST ONCE
    /// between erases. The engine never violates either rule; the simulation backend
    /// fails the test rather than emulating the garbage real XTS hardware would produce.
    fn write(&mut self, region: Region, offset: u32, data: &[u8]) -> Result<(), Self::Error>;

    fn erase_sector(&mut self, region: Region, sector: u32) -> Result<(), Self::Error>;

    /// True iff every RAW flash byte in the range is `0xff`.
    ///
    /// MUST be implemented against the raw, undecrypted view. This is not a convenience
    /// method: see the module docs.
    fn is_erased(&mut self, region: Region, offset: u32, len: u32) -> Result<bool, Self::Error>;
}

/// HMAC-SHA256 under a key that software cannot read.
///
/// One method, because one method is the whole of what the ESP32 HMAC peripheral in
/// `HMAC_UP` mode offers and anything richer would be an abstraction over a capability
/// the silicon does not have.
pub trait DeviceMac {
    type Error: core::fmt::Debug;

    /// MUST be constant-time with respect to `msg`.
    /// MUST fail rather than silently substitute a key if the eFuse block is unset.
    fn hmac(&mut self, msg: &[u8], out: &mut [u8; 32]) -> Result<(), Self::Error>;

    /// Reported to the caller and mixed into every derivation. Never a constant.
    fn provenance(&self) -> KeyProvenance;
}

/// Where the device-binding key came from, and therefore which guarantee tier the store
/// is actually running at.
///
/// This is mixed into `RecordInfo` and flagged inside the AEAD's associated data, so a
/// record sealed at one provenance cannot be opened at another. Not "should not": cannot.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyProvenance {
    /// eFuse key block burned, purpose `HMAC_UP`, read-protected AND write-protected.
    EfuseReadProtected = 0,
    /// eFuse key present but software-readable. Weaker tier; the product must say so.
    EfuseReadable = 1,
    /// Compiled-in development key. NOT SECURE.
    Emulated = 2,
    /// No key at all: the factory provisioning ceremony (ESP-SEAL.md 4.3) has not been
    /// run on this board. Every operation refuses, and the store reports
    /// [`crate::StoreState::Unprovisioned`] rather than a generic hardware fault.
    ///
    /// Added here because the ratified Q45 requires a real unprovisioned state and
    /// ESP-SEAL.md 2.2's enum could not express one.
    Absent = 3,
}

impl KeyProvenance {
    pub(crate) fn tag(self) -> u8 {
        self as u8
    }

    /// Header `flags` bits, bound into the AEAD associated data (ESP-SEAL.md 3.3).
    pub(crate) fn flags(self) -> u8 {
        match self {
            KeyProvenance::Emulated => 0b0000_0001,
            KeyProvenance::EfuseReadable => 0b0000_0010,
            KeyProvenance::EfuseReadProtected | KeyProvenance::Absent => 0,
        }
    }
}

/// One Argon2id memory block, 1 KiB. Re-exported so the embedder can allocate the
/// working set with the alignment Argon2 needs without this crate performing the
/// allocation or reaching for `unsafe` to re-type a `&mut [u64]`.
///
/// ESP-SEAL.md 2.1 specifies `Scratch<'a>(&'a mut [u64])`. That signature cannot be
/// implemented under `#![forbid(unsafe_code)]`: turning `&mut [u64]` into the
/// `&mut [argon2::Block]` the hasher wants is a transmute. Exposing the block type is
/// the honest alternative and costs one line in the embedder.
pub use argon2::Block as ScratchBlock;

/// Borrowed Argon2id working memory.
///
/// The buffer belongs to the caller because 16 MiB is a board decision, not a library
/// decision: on the P4 it must land in PSRAM and only the firmware knows how to put it
/// there. The engine zeroizes it on every return path, success or failure.
pub struct Scratch<'a> {
    blocks: &'a mut [ScratchBlock],
}

impl core::fmt::Debug for Scratch<'_> {
    /// Reports the size and nothing else. The contents are Argon2id state, which is the
    /// largest secret-bearing region in the system and must never reach a log.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Scratch")
            .field("blocks", &self.blocks.len())
            .finish()
    }
}

impl<'a> Scratch<'a> {
    pub fn new(blocks: &'a mut [ScratchBlock]) -> Self {
        Scratch { blocks }
    }

    /// Number of 1 KiB blocks available.
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// True iff this buffer can serve those parameters.
    pub fn fits(&self, params: &KdfParams) -> bool {
        self.blocks.len() >= params.scratch_blocks()
    }

    pub(crate) fn blocks_mut(&mut self) -> &mut [ScratchBlock] {
        self.blocks
    }

    /// Overwrite the whole working set. Called on every return path from the ladder,
    /// including error paths: this is the largest secret-bearing region in the system
    /// and leaving Argon2 state in PSRAM after an unlock hands a cold-boot attacker the
    /// intermediate values the ladder exists to protect (ESP-SEAL.md 5.5).
    pub(crate) fn wipe(&mut self) {
        for block in self.blocks.iter_mut() {
            *block = ScratchBlock::default();
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}
