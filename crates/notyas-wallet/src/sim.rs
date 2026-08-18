// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Host simulation backends: a NOR-accurate [`Flash`], a software [`DeviceMac`], and a
//! heap-allocated [`Scratch`].
//!
//! ESP-SEAL.md 2.3 (points 1, 2 and 6) and 3.1 are normative for everything in this file.
//! The engine above [`Flash`] is a pure function of `(flash bytes, MAC responses, caller
//! inputs)`, so a faithful backend is the whole of what host testing needs - and an
//! *unfaithful* one is worse than no backend at all, because it certifies code that will
//! only fail on release silicon.
//!
//! Three properties are therefore non-negotiable here:
//!
//! - **NOR rules are enforced, not emulated.** Programming can only clear bits, a
//!   `Records` cipher block may be written at most once between erases, and offsets and
//!   lengths must be aligned. A violation is a bug in the engine, not a condition the
//!   engine could have handled, so this backend panics instead of returning an error. Real
//!   XTS hardware answers a double program with garbage; a test that could depend on that
//!   garbage is a test that lies.
//! - **Erasure is only ever visible through the raw view.** With [`SimFlash::encrypted`]
//!   turned on, [`Flash::read`] returns `raw XOR keystream(offset)`, so an erased sector
//!   decrypts to non-`0xff` noise exactly as it does on an ESP-IDF encrypted partition.
//!   Any code that tests erasure through `read` fails here rather than in the field.
//! - **Power loss is a counter, not a thread.** One armed budget, one mangled step, and
//!   every access after it fails. No concurrency, no flakiness, and enumerating the budget
//!   over `0..steps(op)` is exhaustive coverage of every step boundary of that operation.
//!
//! The public surface is deliberately small: [`SimFlash`], [`SoftMac`], [`VecScratch`].
//!
//! ```ignore
//! let mut flash = SimFlash::v1().encrypted(true);
//! let mut mac = SoftMac::new();
//! let mut scratch = VecScratch::for_params(&KdfParams::TEST_ONLY);
//! flash.arm(17, CutMode::PartialPrefix);
//! ```

// A simulator's job is to fail loudly at the exact instruction that broke an invariant,
// with the offset in the message, because the reader is someone bisecting a fuzzer seed at
// 2 a.m. Returning a `Result` for a condition the engine is forbidden to produce would
// bury that. Indexing and plain arithmetic are likewise the clearest way to express a
// byte-for-byte flash model, and every index in this file is range-checked by an explicit
// panic with a better message than the one the slice would give.
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::integer_division_remainder_used
)]

use alloc::{vec, vec::Vec};
use core::fmt;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::config::KdfParams;
use crate::hal::{DeviceMac, Flash, Geometry, KeyProvenance, Region, Scratch, ScratchBlock};

/// SPI NOR program page. The partial-program limit of measurement M6 is specified per page
/// of this size, so the counters are kept at this granularity and nowhere else.
const PAGE_SIZE: u32 = 256;

/// Default partial programs per page between erases (ESP-SEAL.md 3.1 point 6). The ledger
/// design programs 8- and 16-byte cells inside 256-byte pages, i.e. up to 32 per page, and
/// that number is exactly the budget the format is allowed to spend.
const DEFAULT_PAGE_PROGRAM_LIMIT: u32 = 32;

/// Byte positions inside a bit-rotted program unit that fail to take. Deterministic
/// because a fuzzer failure has to replay identically from its seed.
const BITROT_WRITE_STRIDE: usize = 8;
const BITROT_WRITE_PHASE: usize = 3;

/// Byte positions inside a bit-rotted erase that keep their old value.
const BITROT_ERASE_STRIDE: u32 = 64;

// ---------------------------------------------------------------------------
// Power-cut model
// ---------------------------------------------------------------------------

/// How a power cut mangles the operation it lands on.
///
/// These are the three shapes a half-finished NOR operation actually takes: nothing
/// happened, some of it happened, or all of it happened but the charge pump gave out
/// before every bit settled. An engine that survives all three at every step boundary is
/// an engine that survives the rail dropping.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum CutMode {
    /// The operation does not happen at all.
    #[default]
    Clean,
    /// A prefix of the bytes is applied; the rest is left as it was.
    PartialPrefix,
    /// All bytes are applied but a deterministic subset of bits fails to clear.
    BitRot,
}

impl CutMode {
    /// Every mode, in a fixed order so a fuzzer case id means the same thing every run.
    pub const ALL: &'static [CutMode] = &[CutMode::Clean, CutMode::PartialPrefix, CutMode::BitRot];
}

/// The only way a [`SimFlash`] access can fail.
///
/// There is exactly one variant because there is exactly one thing a correct engine driving
/// a correct backend can encounter: the rail went away. Everything else the engine could do
/// wrong is a panic, not an error.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SimFault {
    /// The rail went away. Every access after the cut fails with this.
    PowerCut,
}

/// [`Flash::Error`] for [`SimFlash`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SimError(pub SimFault);

impl fmt::Display for SimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            SimFault::PowerCut => f.write_str("simulated power cut"),
        }
    }
}

/// What the step machine decided about one erase or one program unit.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Step {
    Normal,
    Mangled(CutMode),
}

/// An armed but not yet fired cut.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Armed {
    /// Steps that still apply normally before the mangled one.
    remaining: u32,
    mode: CutMode,
}

/// What a cut decided about a multi-unit write, resolved before a single byte moves.
///
/// Separating the decision from the application is not style: the step machine mutates the
/// simulator's own counters and the application mutates a region image borrowed out of the
/// same struct, and doing them in one pass would mean interleaving two mutable borrows.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct WritePlan {
    /// Number of leading units that reach the store.
    applied: usize,
    /// Index of the unit that is applied with holes, if the cut mode is [`CutMode::BitRot`].
    bitrot: Option<usize>,
    cut: bool,
}

/// What a cut decided about one sector erase.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ErasePlan {
    /// The whole sector returns to `0xff`.
    Full,
    /// The first `n` bytes return to `0xff`; the tail keeps its old content.
    Prefix(u32),
    /// The whole sector is erased except for the bytes that fail to lift.
    BitRot,
    /// Nothing happens at all.
    Skip,
}

// ---------------------------------------------------------------------------
// Backing store
// ---------------------------------------------------------------------------

/// One region's bytes plus the bookkeeping that makes the NOR rules checkable.
///
/// `unit` is the region's program granularity: `cipher_block` for [`Region::Records`],
/// `write_gran` for [`Region::Ledger`]. It is also the step granularity of the power-cut
/// model, because a step is precisely one unit of hardware work.
#[derive(Clone, Debug)]
struct RegionImage {
    bytes: Vec<u8>,
    /// One flag per `unit`: has this unit been programmed since the sector holding it was
    /// last erased? Only [`Region::Records`] treats a set flag as fatal, but the flag is
    /// kept for both so a single code path maintains it and snapshots stay uniform.
    programmed: Vec<bool>,
    /// One counter per [`PAGE_SIZE`] bytes: partial programs since the last erase.
    pages: Vec<u32>,
    unit: u32,
    sector_size: u32,
    sectors: u32,
}

impl RegionImage {
    fn new(sector_size: u32, sectors: u32, unit: u32) -> RegionImage {
        assert!(
            sector_size > 0,
            "SimFlash geometry: sector_size must be nonzero"
        );
        assert!(unit > 0, "SimFlash geometry: program unit must be nonzero");
        assert!(
            sector_size % unit == 0,
            "SimFlash geometry: sector_size {sector_size} is not a multiple of the program unit {unit}; \
             a unit would straddle an erase boundary and the write-once bitmap could not be reset"
        );
        let len = (sector_size as usize) * (sectors as usize);
        RegionImage {
            bytes: vec![0xff; len],
            programmed: vec![false; len / (unit as usize).max(1)],
            pages: vec![0; (len as u32).div_ceil(PAGE_SIZE) as usize],
            unit,
            sector_size,
            sectors,
        }
    }

    fn len(&self) -> u32 {
        self.bytes.len() as u32
    }

    /// Forget the program history of every unit and page that lies *entirely* inside
    /// `[start, end)`.
    ///
    /// "Entirely" matters for a partially completed erase: a unit that is only half erased
    /// still holds programmed bits, so pretending it is fresh would let the next write
    /// through the bitmap check and hide the corruption the cut caused.
    fn clear_bookkeeping(&mut self, start: u32, end: u32) {
        let first_unit = (start.div_ceil(self.unit) as usize).min(self.programmed.len());
        let last_unit = ((end / self.unit) as usize).min(self.programmed.len());
        for u in first_unit..last_unit {
            self.programmed[u] = false;
        }
        let first_page = (start.div_ceil(PAGE_SIZE) as usize).min(self.pages.len());
        let last_page = ((end / PAGE_SIZE) as usize).min(self.pages.len());
        for p in first_page..last_page {
            self.pages[p] = 0;
        }
    }
}

/// A byte-for-byte copy of both regions plus the write-once bookkeeping.
///
/// Deliberately does NOT carry the cut state or the step counter: the fuzzer's inner loop
/// is "save a known-good device image, replay one operation under budget `n`, restore,
/// increment `n`", and a snapshot that dragged the cut along would poison the replay.
#[derive(Clone, Debug)]
pub struct SimImage {
    geometry: Geometry,
    records: RegionImage,
    ledger: RegionImage,
}

// ---------------------------------------------------------------------------
// SimFlash
// ---------------------------------------------------------------------------

/// A NOR-accurate host [`Flash`] with injectable power cuts.
#[derive(Clone, Debug)]
pub struct SimFlash {
    geometry: Geometry,
    records: RegionImage,
    ledger: RegionImage,
    /// Model [`Region::Records`] as an XTS-encrypted partition. See [`SimFlash::encrypted`].
    encrypted: bool,
    page_program_limit: u32,
    armed: Option<Armed>,
    cut_fired: bool,
    steps: u32,
    erases: u64,
    programs: u64,
}

impl SimFlash {
    /// All bytes `0xff`, no cut armed, plaintext (unencrypted) Records region.
    ///
    /// Plaintext is the default because it is the weaker model of the two and a test that
    /// wants the release-silicon behaviour should have to say so, not inherit it.
    pub fn new(geometry: Geometry) -> SimFlash {
        SimFlash {
            geometry,
            records: RegionImage::new(
                geometry.sector_size,
                geometry.records_sectors,
                geometry.cipher_block,
            ),
            ledger: RegionImage::new(
                geometry.sector_size,
                geometry.ledger_sectors,
                geometry.write_gran,
            ),
            encrypted: false,
            page_program_limit: DEFAULT_PAGE_PROGRAM_LIMIT,
            armed: None,
            cut_fired: false,
            steps: 0,
            erases: 0,
            programs: 0,
        }
    }

    /// The frozen 0.2.0 geometry: 4096-byte sectors, 64 records sectors, 4 ledger sectors,
    /// cipher_block 16, write_gran 4.
    ///
    /// Mirrors [`crate::config::Layout::V1`] rather than deriving from it, because the two
    /// are different facts: the layout is what the format claims and the geometry is what
    /// the part provides. A mount checks one against the other, and a test that built the
    /// geometry from the layout could not exercise that check.
    pub fn v1() -> SimFlash {
        SimFlash::new(Geometry {
            sector_size: 4096,
            records_sectors: 64,
            ledger_sectors: 4,
            cipher_block: 16,
            write_gran: 4,
        })
    }

    /// Turn on the XTS model for [`Region::Records`].
    ///
    /// [`Flash::read`] then returns `raw XOR keystream(offset)`, so an erased sector
    /// decrypts to non-`0xff` garbage exactly as it does on release silicon, and any code
    /// that tests erasure through `read` fails here instead of in the field.
    ///
    /// The NOR rules and the write-once bitmap keep applying to the RAW bytes, which is the
    /// physically correct place for them: a write to an erased (raw `0xff`) block is always
    /// legal whatever the ciphertext looks like, and the second program of a block is
    /// caught by the bitmap rather than by the bit rule.
    #[must_use]
    pub fn encrypted(mut self, on: bool) -> SimFlash {
        self.encrypted = on;
        self
    }

    /// Maximum partial-page programs per 256-byte page between erases (measurement M6).
    /// Default 32. Exceeding it panics the test.
    #[must_use]
    pub fn with_page_program_limit(mut self, limit: u32) -> SimFlash {
        self.page_program_limit = limit;
        self
    }

    /// Arm a power cut: the `after`-th step from now is the one that gets mangled, and
    /// every access after it fails. `after == 0` cuts the very next step.
    ///
    /// The mangled operation itself returns `Ok`. That is not an oversight: on real
    /// hardware the CPU stops with the flash controller mid-op and no return value is ever
    /// observed, so the engine only ever learns about the cut from the *next* access. The
    /// fuzzer's job is to check that it learns in time.
    ///
    /// Arming while already cut is legal; the fresh budget starts counting once
    /// [`SimFlash::power_on`] clears the cut.
    pub fn arm(&mut self, after: u32, mode: CutMode) {
        self.armed = Some(Armed {
            remaining: after,
            mode,
        });
    }

    /// Disarm and clear the cut flag, so the image can be re-mounted after a cut.
    /// Does NOT touch the flash contents.
    ///
    /// Firing a cut consumes its budget, so after a cut this really is a disarm. An `arm`
    /// issued *after* the cut survives, which is what makes
    /// `arm(a); ...; arm(b); power_on()` mean "reboot, then cut again at `b`" - the shape
    /// the fuzzer's multi-reboot cases need. The step counter is untouched; use
    /// [`SimFlash::reset_steps`] for that.
    pub fn power_on(&mut self) {
        self.cut_fired = false;
    }

    /// True once the armed cut has fired.
    pub fn is_cut(&self) -> bool {
        self.cut_fired
    }

    /// Steps consumed since the last [`SimFlash::reset_steps`]. A step is one sector erase
    /// or one write of one `cipher_block` (Records) / `write_gran` (Ledger) unit.
    ///
    /// Measuring an operation's step count is how the fuzzer knows the upper bound to
    /// enumerate cut budgets over: run it once clean, read this, then replay `0..steps`.
    pub fn steps(&self) -> u32 {
        self.steps
    }

    pub fn reset_steps(&mut self) {
        self.steps = 0;
    }

    /// Total sector erases, for wear assertions.
    ///
    /// Counts erases that reached the store, so a [`CutMode::Clean`] cut on an erase does
    /// not count and a partial or bit-rotted one does.
    pub fn erase_count(&self) -> u64 {
        self.erases
    }

    /// Total program units that reached the store, for wear assertions. Units a cut
    /// prevented from ever being reached are not counted.
    pub fn program_count(&self) -> u64 {
        self.programs
    }

    /// The RAW (undecrypted) bytes of a region, for readback assertions.
    ///
    /// Not gated by the cut flag: this is the harness looking at the die with the board
    /// powered down, not the device performing an access.
    pub fn raw(&self, region: Region) -> &[u8] {
        &self.image(region).bytes
    }

    /// Overwrite raw bytes, for the tamper and rollback tests. Bypasses every NOR rule on
    /// purpose: it models an attacker with a programmer, not the device.
    ///
    /// Consumes no steps, ignores the cut flag, and leaves the write-once bitmap and the
    /// page counters alone - an attacker's bench programmer is not part of the device's
    /// program history, and the bytes it leaves behind are exactly what the device will
    /// find next boot.
    pub fn poke(&mut self, region: Region, offset: usize, bytes: &[u8]) {
        let region_len = self.image(region).bytes.len();
        let end = offset.saturating_add(bytes.len());
        assert!(
            end <= region_len,
            "SimFlash::poke out of range: {} offset {offset} len {} ends at {end}, region \
             length is {region_len}",
            region_name(region),
            bytes.len()
        );
        let img = self.image_mut(region);
        for (i, b) in bytes.iter().enumerate() {
            img.bytes[offset + i] = *b;
        }
    }

    /// Copy both regions and their bookkeeping. Cheap enough to call in a fuzzer's inner
    /// loop; see [`SimImage`] for what is deliberately left out.
    pub fn snapshot(&self) -> SimImage {
        SimImage {
            geometry: self.geometry,
            records: self.records.clone(),
            ledger: self.ledger.clone(),
        }
    }

    /// Put the device back to the state a [`SimImage`] recorded.
    ///
    /// The cut flag, the step counter and the lifetime wear counters are NOT restored: the
    /// first two describe the *current* power episode and the last two are what the harness
    /// is usually trying to measure across replays.
    pub fn restore(&mut self, image: &SimImage) {
        assert!(
            image.geometry == self.geometry,
            "SimFlash::restore geometry mismatch: image is {:?}, device is {:?}",
            image.geometry,
            self.geometry
        );
        self.records = image.records.clone();
        self.ledger = image.ledger.clone();
    }

    // -- internals ----------------------------------------------------------

    fn image(&self, region: Region) -> &RegionImage {
        match region {
            Region::Records => &self.records,
            Region::Ledger => &self.ledger,
        }
    }

    fn image_mut(&mut self, region: Region) -> &mut RegionImage {
        match region {
            Region::Records => &mut self.records,
            Region::Ledger => &mut self.ledger,
        }
    }

    /// True iff reads and writes of this region go through the keystream.
    fn ciphered(&self, region: Region) -> bool {
        self.encrypted && region == Region::Records
    }

    /// Consume one step and say whether the cut lands on it.
    fn take_step(&mut self) -> Step {
        self.steps = self.steps.saturating_add(1);
        match self.armed {
            Some(armed) if armed.remaining == 0 => {
                // Spent: a fired cut must not fire again, so that an `arm` issued while
                // cut is the only thing `power_on` can re-enable.
                self.armed = None;
                Step::Mangled(armed.mode)
            }
            Some(mut armed) => {
                armed.remaining -= 1;
                self.armed = Some(armed);
                Step::Normal
            }
            None => Step::Normal,
        }
    }

    fn plan_write(&mut self, units: usize) -> WritePlan {
        let mut applied = 0usize;
        let mut bitrot = None;
        let mut cut = false;
        while applied < units {
            match self.take_step() {
                Step::Normal => applied += 1,
                Step::Mangled(mode) => {
                    match mode {
                        CutMode::Clean => {}
                        // Half of what is LEFT, not half of the whole write: the cut lands
                        // where it lands, and the units before it already went in.
                        CutMode::PartialPrefix => applied += (units - applied) / 2,
                        CutMode::BitRot => {
                            bitrot = Some(applied);
                            applied += 1;
                        }
                    }
                    cut = true;
                    break;
                }
            }
        }
        WritePlan {
            applied,
            bitrot,
            cut,
        }
    }

    fn plan_erase(&mut self) -> (ErasePlan, bool) {
        match self.take_step() {
            Step::Normal => (ErasePlan::Full, false),
            Step::Mangled(CutMode::Clean) => (ErasePlan::Skip, true),
            Step::Mangled(CutMode::PartialPrefix) => {
                (ErasePlan::Prefix(self.geometry.sector_size / 2), true)
            }
            Step::Mangled(CutMode::BitRot) => (ErasePlan::BitRot, true),
        }
    }

    /// Charge one partial program to every page the applied byte range touched, and fail
    /// the test if a page has now been programmed more times than the part allows.
    fn charge_pages(&mut self, region: Region, start: u32, end: u32) {
        if start >= end {
            return;
        }
        let limit = self.page_program_limit;
        let enforce = region == Region::Ledger;
        let img = self.image_mut(region);
        let first = (start / PAGE_SIZE) as usize;
        let last = ((end - 1) / PAGE_SIZE) as usize;
        for p in first..=last.min(img.pages.len().saturating_sub(1)) {
            img.pages[p] = img.pages[p].saturating_add(1);
            let count = img.pages[p];
            // Records cannot realistically trip this - write-once caps a 256-byte page at
            // 16 programs - so the limit is only enforced where the format actually spends
            // the budget, and a low limit set for a ledger test does not spuriously fail a
            // records write.
            assert!(
                !enforce || count <= limit,
                "M6 PARTIAL-PAGE LIMIT violated: {} page {p} (bytes {}..{}) has now been \
                 programmed {count} times since its last erase, limit is {limit}",
                region_name(region),
                (p as u32) * PAGE_SIZE,
                (p as u32) * PAGE_SIZE + PAGE_SIZE
            );
        }
    }
}

/// Deterministic per-offset keystream byte.
///
/// This is NOT cryptography and must never be mistaken for it: it is a cheap offset mixer
/// whose only jobs are to be deterministic, to depend on the offset, and never to be zero -
/// the last of which is what guarantees that an erased (`0xff`) byte decrypts to something
/// other than `0xff`, which is the entire point of the encrypted model.
fn keystream_byte(offset: u32) -> u8 {
    let off = offset as u64;
    let mixed = off.wrapping_mul(0x9e37) ^ (off >> 3) ^ 0xa5;
    let folded = (mixed ^ (mixed >> 8) ^ (mixed >> 16)) as u8;
    if folded == 0 {
        // Any fixed nonzero value will do; the property that matters is "never 0".
        0x5b
    } else {
        folded
    }
}

const fn region_name(region: Region) -> &'static str {
    match region {
        Region::Records => "Records",
        Region::Ledger => "Ledger",
    }
}

/// The name of the format-wide invariant (ESP-SEAL.md 3.1) that governs a region.
const fn invariant_name(region: Region) -> &'static str {
    match region {
        Region::Records => "RECORDS INVARIANT",
        Region::Ledger => "LEDGER INVARIANT",
    }
}

impl Flash for SimFlash {
    type Error = SimError;

    fn geometry(&self) -> Geometry {
        self.geometry
    }

    fn read(&mut self, region: Region, offset: u32, buf: &mut [u8]) -> Result<(), SimError> {
        if self.cut_fired {
            return Err(SimError(SimFault::PowerCut));
        }
        let len = buf.len() as u32;
        self.check_range(region, offset, len, "read");
        let ciphered = self.ciphered(region);
        let img = self.image(region);
        for (i, out) in buf.iter_mut().enumerate() {
            let abs = offset + i as u32;
            let raw = img.bytes[abs as usize];
            *out = if ciphered {
                raw ^ keystream_byte(abs)
            } else {
                raw
            };
        }
        Ok(())
    }

    fn write(&mut self, region: Region, offset: u32, data: &[u8]) -> Result<(), SimError> {
        if self.cut_fired {
            return Err(SimError(SimFault::PowerCut));
        }
        let unit = self.image(region).unit;
        assert!(
            offset % unit == 0,
            "{} violated: {} write offset {offset} is not a multiple of the {unit}-byte \
             program unit",
            invariant_name(region),
            region_name(region)
        );
        assert!(
            data.len() % (unit as usize) == 0,
            "{} violated: {} write length {} at offset {offset} is not a multiple of the \
             {unit}-byte program unit",
            invariant_name(region),
            region_name(region),
            data.len()
        );
        self.check_range(region, offset, data.len() as u32, "write");
        if data.is_empty() {
            return Ok(());
        }

        // What the die will actually hold. Every NOR rule below is checked against these
        // bytes, never against the caller's plaintext.
        let ciphered = self.ciphered(region);
        let mut raw_new = Vec::with_capacity(data.len());
        for (i, b) in data.iter().enumerate() {
            let abs = offset + i as u32;
            raw_new.push(if ciphered {
                b ^ keystream_byte(abs)
            } else {
                *b
            });
        }

        // Validate the WHOLE request before a cut gets the chance to truncate it. The
        // engine asked for all of it, so a violation anywhere in it is the engine's bug
        // whether or not the rail happened to drop first.
        let units = data.len() / (unit as usize);
        let first_unit = (offset / unit) as usize;
        if region == Region::Records {
            let img = self.image(region);
            for u in first_unit..(first_unit + units) {
                assert!(
                    !img.programmed[u],
                    "RECORDS INVARIANT violated: cipher block at Records offset {} is being \
                     programmed a second time since its last erase. On XTS hardware the \
                     address-derived tweak makes that produce garbage, not an update, so no \
                     test is allowed to depend on it.",
                    (u as u32) * unit
                );
            }
        }
        {
            let img = self.image(region);
            for (i, new) in raw_new.iter().enumerate() {
                let abs = offset + i as u32;
                let old = img.bytes[abs as usize];
                let set = new & !old;
                assert!(
                    set == 0,
                    "{} violated: {} offset {abs} would SET bit(s) 0x{set:02x} (raw old \
                     0x{old:02x}, raw new 0x{new:02x}). Programming can only clear bits; \
                     the cell must be erased first.",
                    invariant_name(region),
                    region_name(region)
                );
            }
        }

        let plan = self.plan_write(units);
        let unit_sz = unit as usize;
        let base = offset as usize;
        {
            let img = self.image_mut(region);
            for u in 0..plan.applied {
                let rot = plan.bitrot == Some(u);
                for k in 0..unit_sz {
                    // A bit-rotted unit reaches the die with a fixed subset of its bytes
                    // never having taken; those cells keep whatever they held before.
                    if rot && k % BITROT_WRITE_STRIDE == BITROT_WRITE_PHASE {
                        continue;
                    }
                    let idx = u * unit_sz + k;
                    img.bytes[base + idx] = raw_new[idx];
                }
                img.programmed[first_unit + u] = true;
            }
        }
        self.programs = self.programs.saturating_add(plan.applied as u64);
        let applied_bytes = (plan.applied * unit_sz) as u32;
        self.charge_pages(region, offset, offset + applied_bytes);
        if plan.cut {
            self.cut_fired = true;
        }
        Ok(())
    }

    fn erase_sector(&mut self, region: Region, sector: u32) -> Result<(), SimError> {
        if self.cut_fired {
            return Err(SimError(SimFault::PowerCut));
        }
        let (sector_size, sectors) = {
            let img = self.image(region);
            (img.sector_size, img.sectors)
        };
        assert!(
            sector < sectors,
            "SimFlash::erase_sector out of range: {} sector {sector} but the region has \
             {sectors} sectors",
            region_name(region)
        );
        let start = sector * sector_size;
        let end = start + sector_size;

        let (plan, cut) = self.plan_erase();
        {
            let img = self.image_mut(region);
            match plan {
                ErasePlan::Skip => {}
                ErasePlan::Full => {
                    for b in start..end {
                        img.bytes[b as usize] = 0xff;
                    }
                    img.clear_bookkeeping(start, end);
                }
                ErasePlan::Prefix(n) => {
                    let stop = start + n.min(sector_size);
                    for b in start..stop {
                        img.bytes[b as usize] = 0xff;
                    }
                    // The tail never lifted, so only the prefix forgets its history.
                    img.clear_bookkeeping(start, stop);
                }
                ErasePlan::BitRot => {
                    for b in start..end {
                        if (b - start) % BITROT_ERASE_STRIDE == 0 {
                            continue;
                        }
                        img.bytes[b as usize] = 0xff;
                    }
                    // The erase pulse happened across the whole sector, so the history is
                    // gone even where a cell failed to lift. A later write to a stuck bit
                    // is then caught by the bit-clear rule, which is what the hardware
                    // would do to it as well.
                    img.clear_bookkeeping(start, end);
                }
            }
        }
        if plan != ErasePlan::Skip {
            self.erases = self.erases.saturating_add(1);
        }
        if cut {
            self.cut_fired = true;
        }
        Ok(())
    }

    fn is_erased(&mut self, region: Region, offset: u32, len: u32) -> Result<bool, SimError> {
        if self.cut_fired {
            return Err(SimError(SimFault::PowerCut));
        }
        self.check_range(region, offset, len, "is_erased");
        let img = self.image(region);
        // Deliberately the raw view, never the decrypted one: ESP-SEAL.md 3.1 point 4.
        for b in offset..(offset + len) {
            if img.bytes[b as usize] != 0xff {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

impl SimFlash {
    /// Shared range check. An out-of-range access is an engine bug and never a runtime
    /// condition, so it panics with the region and the arithmetic spelled out.
    fn check_range(&self, region: Region, offset: u32, len: u32, what: &str) {
        let region_len = self.image(region).len();
        let end = (offset as u64) + (len as u64);
        assert!(
            end <= region_len as u64,
            "SimFlash::{what} out of range: {} offset {offset} len {len} ends at {end}, \
             region length is {region_len}",
            region_name(region)
        );
    }
}

// ---------------------------------------------------------------------------
// SoftMac
// ---------------------------------------------------------------------------

/// [`DeviceMac::Error`] for [`SoftMac`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MacError {
    /// The eFuse key block is unset. The trait requires a failure here rather than a
    /// substituted key, because a substituted key silently downgrades every derivation in
    /// the ladder to something an attacker can reproduce off-board.
    Unprovisioned,
}

impl fmt::Display for MacError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MacError::Unprovisioned => f.write_str("device MAC key is not provisioned"),
        }
    }
}

/// HMAC-SHA256 under a fixed test key.
///
/// Fixed, not random: every derivation in the crate is then a deterministic function of the
/// test vectors, which is the only thing that makes known-answer testing of the ladder
/// possible at all (ESP-SEAL.md 2.3 point 3).
#[derive(Clone, Debug)]
pub struct SoftMac {
    key: [u8; 32],
    provenance: KeyProvenance,
    calls: u64,
}

impl SoftMac {
    /// The standard host test key: `[0x5a; 32]`, provenance
    /// [`KeyProvenance::EfuseReadProtected`].
    pub fn new() -> SoftMac {
        SoftMac::with_key([0x5a; 32])
    }

    pub fn with_key(key: [u8; 32]) -> SoftMac {
        SoftMac {
            key,
            provenance: KeyProvenance::EfuseReadProtected,
            calls: 0,
        }
    }

    #[must_use]
    pub fn with_provenance(mut self, p: KeyProvenance) -> SoftMac {
        self.provenance = p;
        self
    }

    /// A second board: a different key, same provenance. For the foreign-flash test.
    pub fn other_board() -> SoftMac {
        SoftMac::with_key([0xa5; 32])
    }

    /// Count of MAC invocations, so a test can assert mount's cost.
    ///
    /// Counts attempts, including ones refused for [`KeyProvenance::Absent`]: the question
    /// a test asks of this number is "how many times did the engine reach for the
    /// peripheral", and a refusal is still a reach.
    pub fn calls(&self) -> u64 {
        self.calls
    }
}

impl Default for SoftMac {
    fn default() -> SoftMac {
        SoftMac::new()
    }
}

impl DeviceMac for SoftMac {
    type Error = MacError;

    fn hmac(&mut self, msg: &[u8], out: &mut [u8; 32]) -> Result<(), MacError> {
        self.calls = self.calls.saturating_add(1);
        if self.provenance == KeyProvenance::Absent {
            return Err(MacError::Unprovisioned);
        }
        let mut h = Hmac::<Sha256>::new_from_slice(self.key.as_slice())
            .expect("HMAC-SHA256 accepts any key length, so a 32-byte key cannot be rejected");
        h.update(msg);
        out.copy_from_slice(&h.finalize().into_bytes());
        Ok(())
    }

    fn provenance(&self) -> KeyProvenance {
        self.provenance
    }
}

// ---------------------------------------------------------------------------
// VecScratch
// ---------------------------------------------------------------------------

/// Heap-allocated Argon2id working memory.
///
/// The engine borrows its working set rather than allocating it, because on the target
/// board 16 MiB has to land in PSRAM and only the firmware knows how to put it there. On a
/// host, the heap is that answer, and this is the one line it costs:
///
/// ```ignore
/// let mut s = VecScratch::for_params(&KdfParams::TEST_ONLY);
/// vault.unlock(&pin, s.scratch())
/// ```
#[derive(Debug)]
pub struct VecScratch {
    blocks: Vec<ScratchBlock>,
}

impl VecScratch {
    /// Exactly the blocks those parameters need, and no more, so that a test which
    /// under-provisions on purpose is not accidentally rescued by slack.
    pub fn for_params(params: &KdfParams) -> VecScratch {
        VecScratch::with_blocks(params.scratch_blocks())
    }

    pub fn with_blocks(n: usize) -> VecScratch {
        VecScratch {
            blocks: vec![ScratchBlock::default(); n],
        }
    }

    /// Borrow the working set. The engine zeroizes it on every return path, so the same
    /// `VecScratch` may be reused across calls.
    pub fn scratch(&mut self) -> Scratch<'_> {
        Scratch::new(&mut self.blocks)
    }
}

// ---------------------------------------------------------------------------
// Tests of the simulator itself
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::boxed::Box;
    use std::panic::{catch_unwind, set_hook, take_hook, AssertUnwindSafe};

    /// Assert that the simulator refuses an illegal operation by panicking.
    ///
    /// The panic hook is muted around the call so that a passing test does not print a
    /// backtrace that looks like a failure. That hook is process-global, so this is the one
    /// place in the file where a parallel test could lose a message it wanted to print.
    fn assert_panics(what: &str, f: impl FnOnce()) {
        let prev = take_hook();
        set_hook(Box::new(|_| {}));
        let outcome = catch_unwind(AssertUnwindSafe(f));
        set_hook(prev);
        assert!(
            outcome.is_err(),
            "expected a panic from the simulator: {what}"
        );
    }

    fn read_raw(flash: &SimFlash, region: Region, offset: usize, len: usize) -> Vec<u8> {
        flash.raw(region)[offset..offset + len].to_vec()
    }

    #[test]
    fn fresh_regions_are_all_ff() {
        let mut f = SimFlash::v1();
        assert_eq!(f.raw(Region::Records).len(), 64 * 4096);
        assert_eq!(f.raw(Region::Ledger).len(), 4 * 4096);
        assert!(f.raw(Region::Records).iter().all(|b| *b == 0xff));
        assert!(f.raw(Region::Ledger).iter().all(|b| *b == 0xff));
        assert_eq!(f.is_erased(Region::Records, 0, 4096), Ok(true));
        assert_eq!(f.is_erased(Region::Ledger, 0, 4096), Ok(true));
    }

    #[test]
    fn erase_returns_the_sector_to_ff_and_nothing_else() {
        let mut f = SimFlash::v1();
        f.write(Region::Records, 0, &[0x00; 32]).unwrap();
        f.write(Region::Records, 4096, &[0x00; 32]).unwrap();
        f.erase_sector(Region::Records, 0).unwrap();
        assert_eq!(read_raw(&f, Region::Records, 0, 32), vec![0xff; 32]);
        assert_eq!(read_raw(&f, Region::Records, 4096, 32), vec![0x00; 32]);
        assert_eq!(f.erase_count(), 1);
    }

    #[test]
    fn programming_clears_bits() {
        let mut f = SimFlash::v1();
        f.write(Region::Records, 0, &[0x0f; 16]).unwrap();
        assert_eq!(read_raw(&f, Region::Records, 0, 16), vec![0x0f; 16]);
        assert_eq!(f.program_count(), 1);
    }

    #[test]
    fn ledger_allows_progressive_bit_clearing() {
        let mut f = SimFlash::v1();
        // The whole point of the plaintext ledger: a cell is advanced by clearing more bits
        // in place, which the Records region cannot do.
        f.write(Region::Ledger, 0, &[0xf0; 4]).unwrap();
        f.write(Region::Ledger, 0, &[0x30; 4]).unwrap();
        f.write(Region::Ledger, 0, &[0x10; 4]).unwrap();
        assert_eq!(read_raw(&f, Region::Ledger, 0, 4), vec![0x10; 4]);
    }

    #[test]
    fn setting_a_bit_is_rejected() {
        assert_panics("ledger write that sets a bit", || {
            let mut f = SimFlash::v1();
            f.write(Region::Ledger, 0, &[0x00; 4]).unwrap();
            let _ = f.write(Region::Ledger, 0, &[0xff; 4]);
        });
    }

    #[test]
    fn setting_a_bit_is_rejected_even_for_one_bit() {
        assert_panics("ledger write that sets exactly one bit", || {
            let mut f = SimFlash::v1();
            f.write(Region::Ledger, 0, &[0xfe, 0xff, 0xff, 0xff])
                .unwrap();
            let _ = f.write(Region::Ledger, 0, &[0xff, 0xff, 0xff, 0xfd]);
        });
    }

    #[test]
    fn records_refuses_a_second_program_of_a_cipher_block() {
        assert_panics("second program of a Records cipher block", || {
            let mut f = SimFlash::v1();
            f.write(Region::Records, 0, &[0xf0; 16]).unwrap();
            // Legal by the bit rule (it only clears further) and still forbidden, because
            // XTS re-encrypts the whole block under an address-derived tweak.
            let _ = f.write(Region::Records, 0, &[0x30; 16]);
        });
    }

    #[test]
    fn records_write_once_is_per_block_and_survives_a_multi_block_write() {
        assert_panics(
            "second program of the middle block of a 3-block write",
            || {
                let mut f = SimFlash::v1();
                f.write(Region::Records, 0, &[0x00; 48]).unwrap();
                let _ = f.write(Region::Records, 16, &[0x00; 16]);
            },
        );
    }

    #[test]
    fn erase_reopens_a_records_block_for_programming() {
        let mut f = SimFlash::v1();
        f.write(Region::Records, 0, &[0x00; 16]).unwrap();
        f.erase_sector(Region::Records, 0).unwrap();
        f.write(Region::Records, 0, &[0x0f; 16]).unwrap();
        assert_eq!(read_raw(&f, Region::Records, 0, 16), vec![0x0f; 16]);
    }

    #[test]
    fn records_rejects_an_unaligned_offset() {
        assert_panics("Records write at offset 8", || {
            let mut f = SimFlash::v1();
            let _ = f.write(Region::Records, 8, &[0x00; 16]);
        });
    }

    #[test]
    fn records_rejects_an_unaligned_length() {
        assert_panics("Records write of 24 bytes", || {
            let mut f = SimFlash::v1();
            let _ = f.write(Region::Records, 0, &[0x00; 24]);
        });
    }

    #[test]
    fn ledger_rejects_an_unaligned_offset() {
        assert_panics("Ledger write at offset 2", || {
            let mut f = SimFlash::v1();
            let _ = f.write(Region::Ledger, 2, &[0x00; 4]);
        });
    }

    #[test]
    fn out_of_range_accesses_are_rejected() {
        assert_panics("write past the end of Ledger", || {
            let mut f = SimFlash::v1();
            let _ = f.write(Region::Ledger, 4 * 4096 - 4, &[0x00; 8]);
        });
        assert_panics("read past the end of Records", || {
            let mut f = SimFlash::v1();
            let mut buf = [0u8; 32];
            let _ = f.read(Region::Records, 64 * 4096 - 16, &mut buf);
        });
        assert_panics("erase a sector that does not exist", || {
            let mut f = SimFlash::v1();
            let _ = f.erase_sector(Region::Ledger, 4);
        });
    }

    #[test]
    fn an_encrypted_erased_sector_does_not_read_back_as_ff() {
        let mut f = SimFlash::v1().encrypted(true);
        let mut buf = [0u8; 256];
        f.read(Region::Records, 0, &mut buf).unwrap();
        // Not one byte, anywhere: the keystream is nonzero by construction precisely so
        // that no code can get away with an `== 0xff` erasure probe through `read`.
        assert!(buf.iter().all(|b| *b != 0xff));
        // The Ledger partition is not covered by flash encryption (ESP-SEAL.md 3.1 point 5).
        let mut led = [0u8; 256];
        f.read(Region::Ledger, 0, &mut led).unwrap();
        assert!(led.iter().all(|b| *b == 0xff));
    }

    #[test]
    fn an_encrypted_write_reads_back_as_written_but_is_not_stored_that_way() {
        let mut f = SimFlash::v1().encrypted(true);
        let payload: Vec<u8> = (0u8..16).collect();
        f.write(Region::Records, 32, &payload).unwrap();
        let mut buf = [0u8; 16];
        f.read(Region::Records, 32, &mut buf).unwrap();
        assert_eq!(&buf[..], &payload[..]);
        assert_ne!(read_raw(&f, Region::Records, 32, 16), payload);
    }

    #[test]
    fn is_erased_uses_the_raw_view_under_encryption() {
        let mut f = SimFlash::v1().encrypted(true);
        assert_eq!(f.is_erased(Region::Records, 0, 4096), Ok(true));
        f.write(Region::Records, 0, &[0xff; 16]).unwrap();
        // Writing all-ones plaintext still stores ciphertext, so the sector is no longer
        // erased even though the caller "wrote nothing".
        assert_eq!(f.is_erased(Region::Records, 0, 16), Ok(false));
        assert_eq!(f.is_erased(Region::Records, 16, 4080), Ok(true));
    }

    #[test]
    fn steps_count_erases_and_program_units() {
        let mut f = SimFlash::v1();
        f.reset_steps();
        f.write(Region::Records, 0, &[0x00; 64]).unwrap();
        assert_eq!(f.steps(), 4);
        f.erase_sector(Region::Records, 1).unwrap();
        assert_eq!(f.steps(), 5);
        f.write(Region::Ledger, 0, &[0x00; 16]).unwrap();
        assert_eq!(f.steps(), 9);
        f.reset_steps();
        assert_eq!(f.steps(), 0);
        assert_eq!(f.program_count(), 8);
        assert_eq!(f.erase_count(), 1);
    }

    #[test]
    fn cut_clean_leaves_the_target_unit_untouched() {
        let mut f = SimFlash::v1();
        f.arm(2, CutMode::Clean);
        f.write(Region::Records, 0, &[0x00; 64]).unwrap();
        assert_eq!(read_raw(&f, Region::Records, 0, 32), vec![0x00; 32]);
        assert_eq!(read_raw(&f, Region::Records, 32, 32), vec![0xff; 32]);
        assert!(f.is_cut());
        assert_eq!(f.program_count(), 2);
    }

    #[test]
    fn cut_partial_prefix_applies_half_the_remaining_units() {
        let mut f = SimFlash::v1();
        f.arm(2, CutMode::PartialPrefix);
        // 8 units; 2 go in normally, the cut lands with 6 left and applies 3 of them.
        f.write(Region::Records, 0, &[0x00; 128]).unwrap();
        assert_eq!(read_raw(&f, Region::Records, 0, 80), vec![0x00; 80]);
        assert_eq!(read_raw(&f, Region::Records, 80, 48), vec![0xff; 48]);
        assert!(f.is_cut());
        assert_eq!(f.program_count(), 5);
    }

    #[test]
    fn cut_bit_rot_leaves_a_fixed_subset_of_bytes_unprogrammed() {
        let mut f = SimFlash::v1();
        f.arm(0, CutMode::BitRot);
        f.write(Region::Records, 0, &[0x00; 32]).unwrap();
        let got = read_raw(&f, Region::Records, 0, 32);
        for (i, b) in got.iter().enumerate().take(16) {
            let want = if i % 8 == 3 { 0xff } else { 0x00 };
            assert_eq!(*b, want, "bit-rotted byte {i}");
        }
        // The unit after the mangled one was never reached.
        assert_eq!(&got[16..], &[0xff; 16]);
        assert!(f.is_cut());
    }

    #[test]
    fn cut_partial_prefix_on_an_erase_lifts_half_the_sector() {
        let mut f = SimFlash::v1();
        f.write(Region::Records, 0, &[0x00; 4096]).unwrap();
        f.arm(0, CutMode::PartialPrefix);
        f.erase_sector(Region::Records, 0).unwrap();
        assert_eq!(read_raw(&f, Region::Records, 0, 2048), vec![0xff; 2048]);
        assert_eq!(read_raw(&f, Region::Records, 2048, 2048), vec![0x00; 2048]);
        assert!(f.is_cut());
        assert_eq!(f.erase_count(), 1);
    }

    #[test]
    fn cut_bit_rot_on_an_erase_leaves_stuck_cells() {
        let mut f = SimFlash::v1();
        f.write(Region::Ledger, 0, &[0x00; 4096]).unwrap();
        f.arm(0, CutMode::BitRot);
        f.erase_sector(Region::Ledger, 0).unwrap();
        let got = read_raw(&f, Region::Ledger, 0, 256);
        for (i, b) in got.iter().enumerate() {
            let want = if i % 64 == 0 { 0x00 } else { 0xff };
            assert_eq!(*b, want, "bit-rotted erase byte {i}");
        }
    }

    #[test]
    fn cut_clean_on_an_erase_does_not_count_as_wear() {
        let mut f = SimFlash::v1();
        f.write(Region::Ledger, 0, &[0x00; 4]).unwrap();
        f.arm(0, CutMode::Clean);
        f.erase_sector(Region::Ledger, 0).unwrap();
        assert_eq!(read_raw(&f, Region::Ledger, 0, 4), vec![0x00; 4]);
        assert_eq!(f.erase_count(), 0);
        assert!(f.is_cut());
    }

    #[test]
    fn every_access_after_a_cut_fails() {
        let mut f = SimFlash::v1();
        f.arm(0, CutMode::Clean);
        f.erase_sector(Region::Ledger, 0).unwrap();
        let cut = Err(SimError(SimFault::PowerCut));
        let mut buf = [0u8; 4];
        // Reads fail too. After the rail drops the CPU is not running either, and modelling
        // it any other way lets the engine assume a read path that cannot fail.
        assert_eq!(f.read(Region::Ledger, 0, &mut buf), cut);
        assert_eq!(f.write(Region::Ledger, 0, &[0x00; 4]), cut);
        assert_eq!(f.erase_sector(Region::Ledger, 0), cut);
        assert_eq!(
            f.is_erased(Region::Ledger, 0, 4),
            Err(SimError(SimFault::PowerCut))
        );
    }

    #[test]
    fn power_on_clears_the_cut_without_touching_the_bytes() {
        let mut f = SimFlash::v1();
        f.write(Region::Ledger, 0, &[0x0f; 4]).unwrap();
        f.arm(0, CutMode::Clean);
        f.write(Region::Ledger, 4, &[0x00; 4]).unwrap();
        assert!(f.is_cut());
        f.power_on();
        assert!(!f.is_cut());
        assert_eq!(
            read_raw(&f, Region::Ledger, 0, 8),
            vec![0x0f, 0x0f, 0x0f, 0x0f, 0xff, 0xff, 0xff, 0xff]
        );
        f.write(Region::Ledger, 4, &[0x00; 4]).unwrap();
        assert_eq!(read_raw(&f, Region::Ledger, 4, 4), vec![0x00; 4]);
    }

    #[test]
    fn arming_while_cut_takes_effect_after_power_on() {
        let mut f = SimFlash::v1();
        f.arm(0, CutMode::Clean);
        f.erase_sector(Region::Ledger, 0).unwrap();
        assert!(f.is_cut());
        f.arm(2, CutMode::Clean);
        assert!(f.erase_sector(Region::Ledger, 0).is_err());
        f.power_on();
        f.erase_sector(Region::Ledger, 0).unwrap();
        f.erase_sector(Region::Ledger, 1).unwrap();
        assert!(!f.is_cut());
        f.erase_sector(Region::Ledger, 2).unwrap();
        assert!(f.is_cut());
    }

    #[test]
    fn snapshot_restore_round_trips_bytes_and_the_write_once_bitmap() {
        let mut f = SimFlash::v1();
        f.write(Region::Records, 0, &[0xaa; 16]).unwrap();
        f.write(Region::Ledger, 0, &[0x0f; 4]).unwrap();
        let img = f.snapshot();

        f.erase_sector(Region::Records, 0).unwrap();
        f.write(Region::Records, 0, &[0x55; 16]).unwrap();
        f.write(Region::Ledger, 0, &[0x00; 4]).unwrap();
        assert_ne!(read_raw(&f, Region::Records, 0, 16), vec![0xaa; 16]);

        f.restore(&img);
        assert_eq!(read_raw(&f, Region::Records, 0, 16), vec![0xaa; 16]);
        assert_eq!(read_raw(&f, Region::Ledger, 0, 4), vec![0x0f; 4]);
        assert_panics("restored Records block is programmed again", || {
            let _ = f.write(Region::Records, 0, &[0x00; 16]);
        });
    }

    #[test]
    fn snapshot_restore_leaves_the_cut_state_and_the_step_counter_alone() {
        let mut f = SimFlash::v1();
        let img = f.snapshot();
        f.reset_steps();
        f.arm(0, CutMode::Clean);
        f.erase_sector(Region::Ledger, 0).unwrap();
        assert!(f.is_cut());
        assert_eq!(f.steps(), 1);
        f.restore(&img);
        assert!(
            f.is_cut(),
            "restore must not silently power the board back on"
        );
        assert_eq!(f.steps(), 1);
    }

    #[test]
    fn poke_bypasses_every_nor_rule() {
        let mut f = SimFlash::v1();
        f.write(Region::Records, 0, &[0x00; 16]).unwrap();
        // An attacker with a programmer can set bits the device physically cannot, at an
        // offset the device would refuse, without spending a step.
        f.reset_steps();
        f.poke(Region::Records, 3, &[0xff, 0xff]);
        assert_eq!(f.steps(), 0);
        assert_eq!(
            read_raw(&f, Region::Records, 0, 6),
            vec![0x00, 0x00, 0x00, 0xff, 0xff, 0x00]
        );
    }

    #[test]
    fn the_page_program_limit_is_enforced_on_the_ledger() {
        assert_panics(
            "a fourth program of ledger page 0 under a limit of 3",
            || {
                let mut f = SimFlash::v1().with_page_program_limit(3);
                f.write(Region::Ledger, 0, &[0xfe; 4]).unwrap();
                f.write(Region::Ledger, 4, &[0xfe; 4]).unwrap();
                f.write(Region::Ledger, 8, &[0xfe; 4]).unwrap();
                let _ = f.write(Region::Ledger, 12, &[0xfe; 4]);
            },
        );
    }

    #[test]
    fn erasing_resets_the_page_program_counters() {
        let mut f = SimFlash::v1().with_page_program_limit(2);
        f.write(Region::Ledger, 0, &[0xfe; 4]).unwrap();
        f.write(Region::Ledger, 4, &[0xfe; 4]).unwrap();
        f.erase_sector(Region::Ledger, 0).unwrap();
        f.write(Region::Ledger, 0, &[0xfe; 4]).unwrap();
        f.write(Region::Ledger, 4, &[0xfe; 4]).unwrap();
        assert_eq!(read_raw(&f, Region::Ledger, 0, 8), vec![0xfe; 8]);
    }

    #[test]
    fn softmac_is_deterministic_and_counts_its_calls() {
        let mut a = SoftMac::new();
        let mut b = SoftMac::new();
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        a.hmac(b"notyas", &mut x).unwrap();
        b.hmac(b"notyas", &mut y).unwrap();
        assert_eq!(x, y);
        assert_ne!(x, [0u8; 32]);
        a.hmac(b"notyas-other", &mut y).unwrap();
        assert_ne!(x, y);
        assert_eq!(a.calls(), 2);
        assert_eq!(b.calls(), 1);
        assert_eq!(a.provenance(), KeyProvenance::EfuseReadProtected);
    }

    #[test]
    fn a_second_board_produces_different_macs_at_the_same_provenance() {
        let mut a = SoftMac::new();
        let mut b = SoftMac::other_board();
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        a.hmac(b"same message", &mut x).unwrap();
        b.hmac(b"same message", &mut y).unwrap();
        assert_ne!(x, y);
        assert_eq!(a.provenance(), b.provenance());
    }

    #[test]
    fn an_absent_key_refuses_rather_than_substituting_one() {
        let mut m = SoftMac::new().with_provenance(KeyProvenance::Absent);
        let mut out = [0u8; 32];
        assert_eq!(m.hmac(b"anything", &mut out), Err(MacError::Unprovisioned));
        assert_eq!(out, [0u8; 32]);
        assert_eq!(m.calls(), 1);
    }

    #[test]
    fn vec_scratch_sizes_itself_from_the_parameters() {
        let mut s = VecScratch::for_params(&KdfParams::TEST_ONLY);
        assert_eq!(s.scratch().len(), KdfParams::TEST_ONLY.scratch_blocks());
        assert!(s.scratch().fits(&KdfParams::TEST_ONLY));
        let mut small = VecScratch::with_blocks(1);
        assert!(!small.scratch().fits(&KdfParams::TEST_ONLY));
    }
}
