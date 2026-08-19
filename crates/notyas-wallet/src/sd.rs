// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The card layer: everything about a removable FAT volume that can be decided without a
//! card in a slot.
//!
//! A microSD card is one of the two ways bytes enter this device from outside the airgap
//! (the camera is the other). Everything on it - the file names, the entry count, the
//! sizes in the directory entries, the bytes in the files - was written by something the
//! device has no reason to trust, and a signer that treats any of it as a fact is a
//! signer that can be steered. This module is where that distrust is spelled out once, in
//! pure code, so that the firmware's driver does not have to be trusted to remember it.
//!
//! # Where the seam is, and why it is not the block device
//!
//! [`Flash`](crate::Flash) abstracts a byte-addressable NOR partition because the sealing
//! engine above it implements the whole record format itself. The obvious symmetry here
//! would be a trait over 512-byte SD blocks with FAT implemented in this crate, and it is
//! the wrong shape: it would put a second, hand-written FAT parser on the untrusted
//! ingress path in order to make that parser testable, which costs more than the coverage
//! is worth. ESP-IDF vendors FatFs, the firmware already builds it, and it is the one
//! component in this subsystem with two decades of other people's cards behind it.
//!
//! So the seam is one level up. [`Volume`] is the filesystem, and everything this module
//! owns lives above it:
//!
//! ```text
//!   FAT bytes on the card  ->  vendored FatFs        (not ours, not modelled here)
//!   directory entries      ->  Volume::walk          (the trait the firmware implements)
//!   entries -> a catalog   ->  Catalog::scan         (bounded, validated, ordered)
//!   a name  -> a path      ->  Location              (cannot express a traversal)
//!   a file  -> bytes       ->  read                  (bounded before it allocates)
//!   bytes   -> a file      ->  deliver               (staged, verified, then renamed)
//! ```
//!
//! Everything in the second half of that list is a pure function of `(what the volume
//! returned, caller inputs)`, which is what lets the tests below run a hostile card - a
//! name with a path separator in it, a directory entry that claims four gigabytes, a
//! volume that fails half way through a write, a card that hands back different bytes
//! than it accepted - with no silicon at all.
//!
//! # The rule this module exists to enforce
//!
//! **No length, count or offset that came off a card may reach an allocation before it
//! has been bounded.** The PSBT engine learned this one layer down, where an 82-byte file
//! forced a 16 MB reservation through a nested length prefix. The same shape is available
//! here: a directory entry is free to claim `u64::MAX` bytes, and a directory is free to
//! contain a million of them. So [`Bounds`] is a required argument rather than a default,
//! [`Catalog::scan`] stops walking at [`Bounds::max_entries`] instead of growing, and
//! [`read`] hands the cap DOWN to the backend so the bound is applied by the code doing
//! the transfer rather than checked afterwards by the code that asked for it.
//!
//! # The durability guarantee, stated exactly
//!
//! FAT has no journal and FatFs has no transaction. This device is power-cut by design,
//! so the guarantee has to be named rather than implied.
//!
//! [`deliver`] writes to a staging name, reads the staged bytes back and compares them,
//! and only then renames the staging file onto its final name. What that buys, under a
//! power cut at any instant, is:
//!
//! - the card holds the previous state, or a `.part` file holding some prefix of the new
//!   bytes, or the complete new file under its final name;
//! - **the final name never appears carrying a partial body**, which is the failure mode
//!   that matters: a truncated `-signed.psbt` that a coordinator reads as complete;
//! - a `.part` file is never offered by [`Catalog::scan`] and is cleared by the next
//!   [`deliver`] to the same name, so a cut leaves litter rather than a trap.
//!
//! What it does not buy, and what no amount of code above FAT could:
//!
//! - **atomicity of the rename itself.** It updates directory entries, and FAT does not
//!   make that update atomic. A cut inside it leaves a directory that needs a repair -
//!   which a filesystem check reports - rather than a plausible-looking wrong file.
//! - **durability of anything after the call returns.** The card's own controller may
//!   still be holding writes in a cache it claimed to have flushed. The read-back catches
//!   a card that returns wrong bytes; it cannot catch one that forgets them later.
//! - **crash-safe replacement.** [`OnCollision::Replace`] removes the old file before the
//!   rename, so a cut between those two steps leaves neither name, with the `.part` file
//!   still holding the new bytes. Nothing is lost that the device cannot produce again.
//!
//! The reason a guarantee this narrow is acceptable at all is stated in SECURITY.md and
//! holds for every byte this module writes: **nothing secret is ever written to a card**,
//! and every artifact on one is re-creatable from the device plus its input.
//!
//! # DEVIATION from MILESTONES.md m5
//!
//! m5's "Crates / areas" names firmware and notyas-ui, not this crate. The pure half of
//! the subsystem is put here anyway because a card is untrusted ingress and untrusted
//! ingress needs a host test suite: inside the firmware crate none of this can be
//! exercised without the ESP toolchain and a card in a slot, which is exactly the
//! coverage this milestone's risk profile cannot afford to skip. Nothing here depends on
//! the sealing engine and nothing in the sealing engine depends on it.

use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::fmt;

// ---------------------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------------------

/// Everything a card is allowed to cost this device.
///
/// Passed in rather than defaulted, and deliberately without a `Default`. The file-size
/// cap belongs to whatever is going to parse the file - for a PSBT it is
/// `notyas_core::psbt::StructuralLimits::max_psbt_bytes`, the number check 9 re-enforces
/// against the serialized length - and a second copy of a safety limit is a second limit.
/// This type carries the caller's number; it does not invent one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Bounds {
    /// Largest file [`read`] will return, in bytes. The directory entry's claim is checked
    /// against it before any allocation, and the backend is handed the same number so that
    /// a lying directory entry cannot buy a larger transfer.
    pub max_file_bytes: u32,
    /// Largest number of rows [`Catalog::scan`] will build. Reaching it sets
    /// [`Catalog::truncated`] rather than failing: a card holding ten thousand files is a
    /// nuisance, not an attack, and the user still has to be able to pick the one file
    /// they came for.
    pub max_entries: u16,
}

impl Bounds {
    /// A listing bound that comfortably exceeds any card a human curates by hand while
    /// still being a bound. At the FAT long-name maximum a row costs at most
    /// [`Name::MAX_BYTES`] plus a fixed overhead, so this is a few hundred kilobytes of
    /// PSRAM in the worst case and a few kilobytes in every real one.
    pub const MAX_ENTRIES: u16 = 512;

    /// Bounds for a flow that will read files of at most `max_file_bytes`.
    pub const fn new(max_file_bytes: u32) -> Self {
        Bounds {
            max_file_bytes,
            max_entries: Self::MAX_ENTRIES,
        }
    }
}

// ---------------------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------------------

/// Why a byte string from a card is not a usable file name.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NameError {
    /// Zero bytes, or more than [`Name::MAX_BYTES`].
    Length { len: usize },
    /// A byte outside printable ASCII: a control character, `NUL`, `DEL`, or the high half
    /// of whatever code page the volume is using. See [`Name::new`].
    NotAscii { at: usize },
    /// One of the characters FAT reserves, including both path separators.
    Illegal { at: usize, byte: u8 },
    /// `.` or `..`. Not merely illegal: these two are the traversal.
    DotEntry,
    /// A name the user's computer could not open: a reserved device name such as `NUL`, or
    /// a trailing space or dot. Only ever refused on the WRITE side - see
    /// [`Name::portable`].
    NotPortable,
}

impl fmt::Display for NameError {
    /// Why a name was refused, in the words a refusal screen puts on the panel.
    ///
    /// A sentence rather than a variant name, because these reach the user: a picker that
    /// dropped a row, or a delivery that would not name its file, has to say what about the
    /// name was wrong. The offending byte is given as a POSITION and never echoed - a name
    /// this layer refused is by definition one the device cannot render, and printing part
    /// of it is how the unrenderable byte reaches the glass anyway.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NameError::Length { len } if *len == 0 => f.write_str("the name is empty"),
            NameError::Length { len } => write!(
                f,
                "the name is {len} bytes and the limit is {}",
                Name::MAX_BYTES
            ),
            NameError::NotAscii { at } => write!(
                f,
                "byte {at} of the name is not a character this device can display"
            ),
            NameError::Illegal { at, .. } => {
                write!(f, "byte {at} of the name is a character FAT reserves")
            }
            NameError::DotEntry => f.write_str("a name of dots is not a file"),
            NameError::NotPortable => f.write_str(
                "the name is one a computer could not open: a reserved device name, or a                  trailing space or dot",
            ),
        }
    }
}

/// A validated single path component.
///
/// The invariant is the point of the type: a `Name` holds no path separator, no `.` and no
/// `..`, so a [`Location`] built from one cannot address anything outside the directory it
/// was built for. Traversal is not checked for at the point of use; it is unsayable.
///
/// Validation follows the character rules in the Microsoft Extensible Firmware Initiative
/// FAT32 File System Specification 1.03 (2000-12-06), which is the published source for
/// the reserved set, and the reserved device names in Microsoft's "Naming Files, Paths,
/// and Namespaces". Both are named again at the sites that implement them.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Name(String);

impl fmt::Debug for Name {
    /// Quoted, always. A name off a card is attacker-chosen text that ends up in logs, and
    /// the `String` formatter escapes the newline that would otherwise forge a second log
    /// line.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Name {
    /// The FAT long-name maximum. Nothing legal on a card is longer, so bounding here
    /// refuses no file a user could have put there while still being a bound.
    pub const MAX_BYTES: usize = 255;

    /// Characters FAT reserves in a long name, plus `\` and `/`.
    ///
    /// Source: FAT32 File System Specification 1.03, long-name character rules. The two
    /// separators are the security-relevant members: a name containing either would let a
    /// directory entry address a second directory once it was concatenated into a path.
    const ILLEGAL: &'static [u8] = b"\"*/:<>?\\|";

    /// Validate one component exactly as the volume handed it over.
    ///
    /// Takes bytes rather than `&str` because that is what a FAT directory entry is. Under
    /// `CONFIG_FATFS_API_ENCODING_ANSI_OEM` - the ESP-IDF default - names come back in an
    /// OEM code page, so a file named on a Mac can arrive as bytes that are not UTF-8 at
    /// all. Those are refused here and counted by [`Catalog::rejected`] rather than being
    /// lossily transliterated into a name that would then open the wrong file.
    pub fn new(bytes: &[u8]) -> Result<Self, NameError> {
        if bytes.is_empty() || bytes.len() > Self::MAX_BYTES {
            return Err(NameError::Length { len: bytes.len() });
        }
        for (at, byte) in bytes.iter().enumerate() {
            // 0x20..=0x7e. Below is a control character (0x00 included), 0x7f is DEL, and
            // above is code-page dependent.
            if *byte < 0x20 || *byte > 0x7e {
                return Err(NameError::NotAscii { at });
            }
            if Self::ILLEGAL.contains(byte) {
                return Err(NameError::Illegal { at, byte: *byte });
            }
        }
        // Printable ASCII is valid UTF-8 by construction, so this cannot fail; it is
        // written as a fallible conversion anyway because the crate does not unwrap.
        let text = core::str::from_utf8(bytes).map_err(|_| NameError::NotAscii { at: 0 })?;
        if text == "." || text == ".." {
            return Err(NameError::DotEntry);
        }
        let mut owned = String::new();
        owned.push_str(text);
        Ok(Name(owned))
    }

    /// The same validation, applied to text this device produced itself.
    pub fn parse(text: &str) -> Result<Self, NameError> {
        Self::new(text.as_bytes())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The part before the final `.`, or the whole name if it has none.
    ///
    /// A leading dot is not an extension separator: `.hidden` has stem `.hidden` and no
    /// extension, which is what every other tool does and what stops a delivered name from
    /// collapsing to a bare `-signed.psbt`.
    pub fn stem(&self) -> &str {
        match self.0.rfind('.') {
            Some(0) | None => &self.0,
            Some(at) => self.0.get(..at).unwrap_or(&self.0),
        }
    }

    /// True if the name's extension is `want`, compared case-insensitively.
    fn extension_eq(&self, want: &str) -> bool {
        let ext = match self.0.rfind('.') {
            Some(0) | None => return false,
            Some(at) => match at.checked_add(1).and_then(|start| self.0.get(start..)) {
                Some(ext) => ext,
                None => return false,
            },
        };
        ext.len() == want.len()
            && ext
                .bytes()
                .map(|b| b.to_ascii_lowercase())
                .eq(want.bytes().map(|b| b.to_ascii_lowercase()))
    }

    /// `Ok` if a Windows or macOS host could open a file of this name.
    ///
    /// Checked only before this device CREATES a name, never before it reads one. A card
    /// that already holds a file called `NUL` is the user's business and FatFs opens it
    /// without complaint; a signed transaction this device writes under a name the user's
    /// laptop cannot open is this device's business.
    ///
    /// Source for the device names: Microsoft, "Naming Files, Paths, and Namespaces". They
    /// are reserved with any extension, so the check is against the stem.
    pub fn portable(&self) -> Result<(), NameError> {
        // A trailing space or dot is storable in a FAT long name and unopenable on
        // Windows, which silently strips both.
        let last = self.0.as_bytes().last().copied().unwrap_or(b'x');
        if last == b' ' || last == b'.' {
            return Err(NameError::NotPortable);
        }
        let stem = self.stem();
        const DEVICES: [&str; 4] = ["con", "prn", "aux", "nul"];
        let matches_device = DEVICES.iter().any(|d| {
            d.len() == stem.len() && stem.bytes().map(|b| b.to_ascii_lowercase()).eq(d.bytes())
        });
        // COM1..COM9 and LPT1..LPT9. COM0 and LPT0 are not reserved.
        let bytes = stem.as_bytes();
        let matches_port = match (bytes.first(), bytes.get(1), bytes.get(2), bytes.get(3)) {
            (Some(a), Some(b), Some(c), Some(d)) if bytes.len() == 4 => {
                let head = (
                    a.to_ascii_lowercase(),
                    b.to_ascii_lowercase(),
                    c.to_ascii_lowercase(),
                );
                (head == (b'c', b'o', b'm') || head == (b'l', b'p', b't'))
                    && d.is_ascii_digit()
                    && *d != b'0'
            }
            _ => false,
        };
        if matches_device || matches_port {
            return Err(NameError::NotPortable);
        }
        Ok(())
    }

    /// Deterministically fold arbitrary user text into a usable name.
    ///
    /// Wallet labels reach file names (UX-SCREENS S-27 writes `savings-84-a1b2c3d4.json`)
    /// and a label is whatever the user typed. The mapping is total and has no randomness
    /// in it, which is not a stylistic choice: this device has no RNG, and a name that
    /// varied between two calls would break the "this writes to the card: `<name>`" notice
    /// that SECURITY invariant 2b requires to be shown BEFORE the write happens - the
    /// notice and the writer each derive the name for themselves.
    ///
    /// Every byte outside `[A-Za-z0-9._-]` becomes `-`, runs of `-` collapse, leading and
    /// trailing `-` and `.` are dropped, the result is truncated to `max` bytes, and
    /// anything that comes out empty or unportable becomes `fallback`.
    pub fn sanitize(text: &str, max: usize, fallback: &str) -> Result<Self, NameError> {
        let cap = max.min(Self::MAX_BYTES);
        let mut out = String::new();
        let mut pending_dash = false;
        for byte in text.bytes() {
            let keep = byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'_';
            if keep {
                if pending_dash && !out.is_empty() {
                    out.push('-');
                }
                pending_dash = false;
                out.push(char::from(byte));
            } else {
                pending_dash = true;
            }
            if out.len() >= cap {
                break;
            }
        }
        let trimmed = out.trim_matches(|c| c == '-' || c == '.');
        let candidate = if trimmed.is_empty() { fallback } else { trimmed };
        let name = Name::parse(candidate)?;
        match name.portable() {
            Ok(()) => Ok(name),
            Err(_) => Name::parse(fallback),
        }
    }
}

// ---------------------------------------------------------------------------------------
// Locations
// ---------------------------------------------------------------------------------------

/// A file, addressed relative to the volume root.
///
/// `dir` is `None` for the card root and `Some` for one level below it, and there is no
/// third case: UX-SCREENS S-28 fixed the picker at the root plus one level of directories
/// because a deeper tree on a five-row list is a navigation trap, and expressing that
/// depth limit in the type is cheaper than remembering to enforce it at each use.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Location<'a> {
    pub dir: Option<&'a Name>,
    pub file: &'a Name,
}

impl<'a> Location<'a> {
    pub fn root(file: &'a Name) -> Self {
        Location { dir: None, file }
    }

    pub fn under(dir: &'a Name, file: &'a Name) -> Self {
        Location {
            dir: Some(dir),
            file,
        }
    }

    /// Render an absolute path under `mount`, e.g. `/sd/psbt/spend.psbt`.
    ///
    /// The one place in the subsystem that joins path components, so it is the one place a
    /// join bug could live, and it is host-tested. A backend that builds its own paths out
    /// of `Name`s reintroduces that bug site for no gain.
    pub fn render(&self, mount: &str) -> String {
        let mut out = String::new();
        out.push_str(mount);
        if let Some(dir) = self.dir {
            out.push('/');
            out.push_str(dir.as_str());
        }
        out.push('/');
        out.push_str(self.file.as_str());
        out
    }
}

// ---------------------------------------------------------------------------------------
// Timestamps
// ---------------------------------------------------------------------------------------

/// A wall-clock instant off a directory entry, to the minute.
///
/// Deliberately not a duration, an epoch offset, or anything else that implies a time
/// zone. FAT stores local wall-clock with no zone at all; ESP-IDF's VFS converts it with
/// `mktime` on a device that has no zone set; and the picker shows it "as-is with no
/// timezone claim" (UX-SCREENS S-28). Reading the seconds back as UTC therefore recovers
/// exactly the digits the card recorded, which is the only honest thing to display.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Timestamp {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
}

impl Timestamp {
    /// 1980-01-01T00:00:00Z, the base year of the FAT directory entry's date field (FAT32
    /// File System Specification 1.03, `DIR_WrtDate`). Nothing on a FAT volume can
    /// legitimately be older.
    pub const FAT_EPOCH_SECONDS: i64 = 315_532_800;

    /// 2107-12-31T23:59:59Z, the last instant the seven-bit FAT year field can express.
    pub const FAT_LAST_SECONDS: i64 = 4_354_819_199;

    /// Convert seconds since the POSIX epoch into civil date and time, or `None` if the
    /// value is outside what a FAT directory entry can hold.
    ///
    /// The range check is not tidiness. A directory entry whose date field is all zeroes -
    /// which is what a device with no clock writes - normalizes through `mktime` into a
    /// nonsense instant, and a picker row reading "1979-11-30" is worse than a row reading
    /// nothing at all. Out of range means "no timestamp", and the row says so.
    ///
    /// The conversion is Howard Hinnant's `civil_from_days`
    /// (howardhinnant.github.io/date_algorithms.html, public domain), exact for every
    /// proleptic Gregorian date and needing no table. The accepted range is entirely
    /// positive, so the algorithm's negative-era branch is unreachable here and is not
    /// written.
    #[allow(
        clippy::integer_division_remainder_used,
        clippy::arithmetic_side_effects
    )]
    // Both crate-wide lints are waived for this function alone, and only because the
    // arithmetic is bounded by the range check above rather than by an argument about
    // typical inputs. Every divisor is a nonzero literal. `days` is at most 50,400 and `z`
    // at most 769,868, so `era` is at most 5, `doe` is below 146,097 by construction, and
    // the largest intermediate (`153 * mp`) is under 1,700 - four orders of magnitude
    // inside `u64`. A checked-arithmetic rendering of a calendar is materially harder to
    // read and would hide, not surface, an error in the algorithm itself.
    pub fn from_epoch_seconds(seconds: i64) -> Option<Self> {
        if !(Self::FAT_EPOCH_SECONDS..=Self::FAT_LAST_SECONDS).contains(&seconds) {
            return None;
        }
        let seconds = u64::try_from(seconds).ok()?;
        let days = seconds / 86_400;
        let secs_of_day = seconds % 86_400;

        // Shift the epoch to 0000-03-01 so the leap day is the last day of the "year" and
        // every era is 400 years of exactly 146,097 days.
        let z = days + 719_468;
        let era = z / 146_097;
        let doe = z % 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = if mp < 10 { mp + 3 } else { mp - 9 };
        let year = yoe + era * 400 + u64::from(month <= 2);

        Some(Timestamp {
            year: u16::try_from(year).ok()?,
            month: u8::try_from(month).ok()?,
            day: u8::try_from(day).ok()?,
            hour: u8::try_from(secs_of_day / 3600).ok()?,
            minute: u8::try_from((secs_of_day % 3600) / 60).ok()?,
        })
    }
}

impl fmt::Display for Timestamp {
    /// `2026-08-17 14:02`. Big-endian and unambiguous; the picker is free to arrange the
    /// same fields differently, but anything that reaches a log goes out in this form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:04}-{:02}-{:02} {:02}:{:02}",
            self.year, self.month, self.day, self.hour, self.minute
        )
    }
}

// ---------------------------------------------------------------------------------------
// The volume
// ---------------------------------------------------------------------------------------

/// Whether [`Volume::walk`] should keep going.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Walk {
    Continue,
    Stop,
}

/// What [`Volume::read`] found.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReadOutcome {
    /// The whole file fitted inside the limit and is in the buffer.
    Complete,
    /// The file is longer than the limit. The buffer holds the limit's worth and the
    /// caller must discard it: a prefix of an untrusted file is not a shorter file.
    OverLimit,
}

/// One directory entry, exactly as the filesystem reported it and not yet believed.
///
/// Everything here is a claim. `name` may not be UTF-8, may contain a path separator and
/// may be 255 bytes of punctuation; `len` may be any `u64` the entry can hold; `modified`
/// may be any instant, including one before FAT existed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Raw<'a> {
    pub name: &'a [u8],
    pub is_dir: bool,
    /// Size from the directory entry. A claim, not a measurement: [`read`] bounds the
    /// actual transfer separately and does not trust this.
    pub len: u64,
    /// Modification time in seconds since the POSIX epoch, or `None` if the backend could
    /// not read one.
    pub modified: Option<i64>,
}

/// A mounted FAT volume.
///
/// Six operations, no handles and no cursor: a file is opened, transferred and closed
/// inside one call, so no code above this trait can hold a descriptor across a card
/// removal. The firmware implements it over ESP-IDF's VFS; [`sim::SimVolume`] implements
/// it over a map for the tests.
///
/// Implementors carry three obligations the pure layer cannot check for them, each
/// restated at its method:
///
/// 1. `read` stops at the limit it is given and does not allocate past it.
/// 2. `create_exclusive` fails if the target exists, and does not return until the bytes
///    have been flushed towards the medium.
/// 3. paths are built with [`Location::render`] and nowhere else.
pub trait Volume {
    type Error: fmt::Debug;

    /// Visit every entry of `dir` (the volume root when `None`), stopping early if the
    /// visitor says to.
    ///
    /// The borrowed name in [`Raw`] lets the backend lend the visitor its own directory
    /// buffer instead of allocating one string per entry - which matters on a card holding
    /// thousands of files, where the allocation, not the read, is the cost.
    fn walk(
        &mut self,
        dir: Option<&Name>,
        visit: &mut dyn FnMut(Raw<'_>) -> Walk,
    ) -> Result<(), Self::Error>;

    /// Read up to `limit` bytes of `at` into `out`, which is cleared first.
    ///
    /// The limit is handed DOWN rather than checked afterwards so that the bound is applied
    /// by the code performing the transfer. An implementation MUST NOT reserve capacity
    /// from the file's claimed size, MUST stop after `limit` bytes, and MUST return
    /// [`ReadOutcome::OverLimit`] when at least one byte remained.
    fn read(
        &mut self,
        at: Location<'_>,
        limit: u32,
        out: &mut Vec<u8>,
    ) -> Result<ReadOutcome, Self::Error>;

    /// Create `at`, write all of `data`, flush it, and close it.
    ///
    /// MUST fail rather than truncate if `at` already exists: the existence check
    /// [`deliver`] performs first is advisory, because the card can be swapped between the
    /// check and the write, and exclusive creation is what makes that race harmless.
    fn create_exclusive(&mut self, at: Location<'_>, data: &[u8]) -> Result<(), Self::Error>;

    /// Rename within the volume. Both locations are always in the same directory.
    fn rename(&mut self, from: Location<'_>, to: Location<'_>) -> Result<(), Self::Error>;

    /// Delete a file. Deleting something that is not there is an error, not a no-op: the
    /// only caller checks first, and silence would hide a card lying about its own
    /// directory.
    fn remove(&mut self, at: Location<'_>) -> Result<(), Self::Error>;

    fn exists(&mut self, at: Location<'_>) -> Result<bool, Self::Error>;
}

// ---------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------

/// Why a card operation did not produce what was asked for.
///
/// Generic over the backend's error so a driver failure stays distinguishable from a
/// refusal this layer decided. That is the distinction [`crate::error`] draws and it
/// matters for the same reason: "the card is broken" and "that file is too big" are
/// different sentences on different screens.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SdError<E> {
    /// The driver failed. Card removed, bus error, filesystem damage.
    Backend(E),
    /// A name this device was asked to use is not one it can use.
    Name(NameError),
    /// The file is larger than the caller's cap. Carries the cap, which is the number the
    /// refusal quotes ("too large (max N)").
    TooLarge { max: u32 },
    /// The target name is already on the card and the caller said not to replace it.
    Collision,
    /// The bytes read back after the staged write are not the bytes handed in. The card
    /// accepted the write and returned something else; nothing was renamed, and the
    /// staging file is left in place as the evidence.
    ReadBackMismatch { wrote: usize, read: usize },
}

impl<E> From<NameError> for SdError<E> {
    fn from(e: NameError) -> Self {
        SdError::Name(e)
    }
}

// ---------------------------------------------------------------------------------------
// Cataloguing
// ---------------------------------------------------------------------------------------

/// What a listed entry is, decided from its extension alone.
///
/// **Extension only, never content.** m5 builds the picker chrome and m6 builds the
/// PSBT-specific behaviour (MILESTONES.md R15), and the split is worth keeping for a
/// reason beyond the schedule: deciding "this is a PSBT" belongs to the code that parses
/// PSBTs, where the magic check already exists and already produces the sentence a user
/// acts on. A sniff here would be a second, weaker answer to a question that already has
/// an authority, and giving it would mean opening every file on the card to draw a list.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Directory,
    /// `.psbt`
    Psbt,
    /// `.txn`, the finalized-transaction file (ratified Q26).
    Txn,
    /// `.txt`, which is how the Coldcard dialect ships multisig descriptors.
    Text,
    /// `.json`, the coordinator export bodies.
    Json,
    Other,
}

impl Kind {
    fn of(name: &Name, is_dir: bool) -> Self {
        if is_dir {
            Kind::Directory
        } else if name.extension_eq(PSBT_EXT) {
            Kind::Psbt
        } else if name.extension_eq(TXN_EXT) {
            Kind::Txn
        } else if name.extension_eq("txt") {
            Kind::Text
        } else if name.extension_eq("json") {
            Kind::Json
        } else {
            Kind::Other
        }
    }
}

/// The picker's two tabs (UX-SCREENS S-28).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Filter {
    /// Everything the card holds, minus what is never listed at all.
    All,
    /// `.psbt` files, plus directories so the tab can still be navigated.
    PsbtOnly,
}

impl Filter {
    fn admits(self, kind: Kind) -> bool {
        match self {
            Filter::All => true,
            Filter::PsbtOnly => matches!(kind, Kind::Psbt | Kind::Directory),
        }
    }
}

/// One row of the picker.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Entry {
    pub name: Name,
    pub kind: Kind,
    /// Size as the directory entry claims it, saturated into `u32`. For rendering only:
    /// the transfer is bounded by [`Bounds::max_file_bytes`] regardless of what this says.
    pub len: u32,
    pub modified: Option<Timestamp>,
    /// The directory entry claims more than [`Bounds::max_file_bytes`]. The row is still
    /// shown - hiding it would leave a user hunting for a file that is plainly on the card
    /// - but it is not selectable, and the refusal states the cap.
    pub oversize: bool,
}

impl Entry {
    pub fn is_dir(&self) -> bool {
        matches!(self.kind, Kind::Directory)
    }
}

/// A bounded, validated, deterministically ordered view of one directory.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Catalog {
    entries: Vec<Entry>,
    truncated: bool,
    rejected: u16,
}

impl Catalog {
    /// List one directory: the volume root when `dir` is `None`, one level below it
    /// otherwise.
    ///
    /// Four things happen here and each one is a bound on untrusted input:
    ///
    /// - the walk stops at [`Bounds::max_entries`] and records that it did, so a card with
    ///   a million files costs a fixed amount of PSRAM;
    /// - every name goes through [`Name::new`], and one that fails is counted rather than
    ///   transliterated, so nothing unopenable ever reaches a row;
    /// - staging files and nested directories are dropped, the first because a `.part` is
    ///   a half-written artifact and the second because the depth limit is the design
    ///   (UX-SCREENS S-28);
    /// - the result is sorted, because FAT returns entries in whatever order the volume
    ///   happens to hold them - which is an order the person who wrote the card chose. The
    ///   row a user taps has to be a function of what they were shown, not of a layout an
    ///   attacker picked.
    pub fn scan<V: Volume>(
        volume: &mut V,
        dir: Option<&Name>,
        filter: Filter,
        bounds: &Bounds,
    ) -> Result<Self, SdError<V::Error>> {
        let mut entries: Vec<Entry> = Vec::new();
        let mut truncated = false;
        let mut rejected: u16 = 0;
        let nested = dir.is_some();
        let limit = usize::from(bounds.max_entries);

        volume
            .walk(dir, &mut |raw: Raw<'_>| {
                if entries.len() >= limit {
                    truncated = true;
                    return Walk::Stop;
                }
                // A directory inside a directory is where the depth limit is applied.
                // Dropping it here rather than refusing to descend later is what makes
                // "root plus one level" true of what the user can SEE, not merely of what
                // the code would agree to open.
                if raw.is_dir && nested {
                    return Walk::Continue;
                }
                let name = match Name::new(raw.name) {
                    Ok(name) => name,
                    Err(_) => {
                        rejected = rejected.saturating_add(1);
                        return Walk::Continue;
                    }
                };
                // Staging files are this device's own litter from an interrupted write.
                // Never offered, never counted as rejected, never a Kind.
                if !raw.is_dir && name.extension_eq(STAGING_EXT) {
                    return Walk::Continue;
                }
                let kind = Kind::of(&name, raw.is_dir);
                if !filter.admits(kind) {
                    return Walk::Continue;
                }
                entries.push(Entry {
                    name,
                    kind,
                    len: u32::try_from(raw.len).unwrap_or(u32::MAX),
                    modified: raw.modified.and_then(Timestamp::from_epoch_seconds),
                    oversize: !raw.is_dir && raw.len > u64::from(bounds.max_file_bytes),
                });
                Walk::Continue
            })
            .map_err(SdError::Backend)?;

        entries.sort_by(order);
        Ok(Catalog {
            entries,
            truncated,
            rejected,
        })
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// True if the directory held more entries than [`Bounds::max_entries`]. The picker
    /// says so rather than implying the card holds only what is on screen.
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    /// How many entries were dropped because their names were not usable. Surfaced for the
    /// same reason: a user who can see a file on their laptop and not on the device
    /// deserves to be told the device could not read its name, rather than left to
    /// conclude the card is empty.
    pub fn rejected(&self) -> u16 {
        self.rejected
    }
}

/// Directories first, then case-insensitive by name, with an exact-byte tiebreak.
///
/// The tiebreak is what makes the order total: without it `README` and `readme` compare
/// equal and their relative position falls back to whatever the volume returned, which is
/// the attacker-chosen order this function exists to remove.
fn order(a: &Entry, b: &Entry) -> Ordering {
    b.is_dir()
        .cmp(&a.is_dir())
        .then_with(|| {
            a.name
                .as_str()
                .bytes()
                .map(|c| c.to_ascii_lowercase())
                .cmp(b.name.as_str().bytes().map(|c| c.to_ascii_lowercase()))
        })
        .then_with(|| a.name.as_str().cmp(b.name.as_str()))
}

// ---------------------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------------------

/// Read a whole file, bounded.
///
/// The cap is enforced twice on purpose. It is passed to the backend, which is the only
/// code that can stop a transfer part way; and the result is re-checked here, because a
/// backend that got it wrong would otherwise hand a truncated file to a parser with no way
/// to know it was truncated. A prefix of a PSBT is not a smaller PSBT.
pub fn read<V: Volume>(
    volume: &mut V,
    at: Location<'_>,
    bounds: &Bounds,
) -> Result<Vec<u8>, SdError<V::Error>> {
    let mut out = Vec::new();
    let outcome = volume
        .read(at, bounds.max_file_bytes, &mut out)
        .map_err(SdError::Backend)?;
    if outcome == ReadOutcome::OverLimit || out.len() > usize_of(bounds.max_file_bytes) {
        return Err(SdError::TooLarge {
            max: bounds.max_file_bytes,
        });
    }
    Ok(out)
}

/// `u32` into `usize`, on a 32-bit target and on a 64-bit host, without a cast.
fn usize_of(value: u32) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

// ---------------------------------------------------------------------------------------
// Naming what goes back out
// ---------------------------------------------------------------------------------------

/// `psbt`, the extension of both the file that arrives and the file that leaves.
pub const PSBT_EXT: &str = "psbt";
/// `txn`, the finalized raw transaction (ARCHITECTURE.md 5.4, ratified Q26).
pub const TXN_EXT: &str = "txn";
/// `part`, the staging extension. Never listed, never delivered under this name.
pub const STAGING_EXT: &str = "part";
/// The infix Coldcard established for a file a signer has added signatures to.
pub const SIGNED_INFIX: &str = "-signed";
/// The infix for a transaction that needs no further signatures.
pub const FINAL_INFIX: &str = "-final";

/// The names one signing flow will write, decided before anything is written.
///
/// Built up front because SECURITY invariant 2b requires every write to a card to be
/// announced on screen before it happens (UX-SCREENS S-38 shows exactly these two lines),
/// and an announcement is only worth something if the announced name is the value the
/// writer is later handed. [`deliver`] takes a `Name`, and this is where that `Name` comes
/// from.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct WritePlan {
    /// `<stem>-signed.psbt`.
    pub signed: Name,
    /// `<stem>-final.txn`, present only when the transaction is complete. A partially
    /// signed multisig has no finalized form, and S-38 omits the line rather than naming a
    /// file it will not write.
    pub finalized: Option<Name>,
}

/// Derive the output names from the input file's name.
///
/// The convention is Coldcard's and is ratified in ARCHITECTURE.md 5.4: `<name>-signed.psbt`
/// alongside the input, plus `-final.txn` when the transaction can be finalized. A user
/// with the card in front of them can see which file came from which, which is the whole
/// value of DERIVING a name rather than generating one - and generating one is not
/// available anyway, on a device with no RNG and no clock it trusts.
///
/// The case this deliberately does not special-case: signing `spend-signed.psbt` yields
/// `spend-signed-signed.psbt`. It is visible, it is harmless, and stripping a trailing
/// `-signed` would make the output name equal to the input name and overwrite the file
/// being signed FROM.
pub fn plan(source: &Name, finalized: bool) -> Result<WritePlan, NameError> {
    let signed = derive(source.stem(), SIGNED_INFIX, PSBT_EXT)?;
    let final_name = if finalized {
        Some(derive(source.stem(), FINAL_INFIX, TXN_EXT)?)
    } else {
        None
    };
    Ok(WritePlan {
        signed,
        finalized: final_name,
    })
}

/// `<stem><infix>.<ext>`, with the stem truncated from the right if the whole will not fit
/// in a FAT long name.
///
/// The stem is what gets shortened because the infix and the extension are the parts that
/// carry meaning to whatever reads the card: a coordinator looking for the signed file
/// needs `-signed.psbt` intact, while a user looking at a shortened stem still recognises
/// their own file name.
fn derive(stem: &str, infix: &str, ext: &str) -> Result<Name, NameError> {
    // Saturating, because the alternative is an error path for a case that cannot arise:
    // `infix` and `ext` are compile-time constants of a dozen bytes between them, and a
    // room of zero would produce a name consisting of the suffix alone, which is still a
    // valid name.
    let fixed = infix.len().saturating_add(1).saturating_add(ext.len());
    let room = Name::MAX_BYTES.saturating_sub(fixed);
    let mut out = String::new();
    // Byte truncation is character truncation here: `Name` admits printable ASCII only, so
    // there is no multi-byte sequence to split.
    out.push_str(stem.get(..room.min(stem.len())).unwrap_or(""));
    out.push_str(infix);
    out.push('.');
    out.push_str(ext);
    let name = Name::parse(&out)?;
    name.portable()?;
    Ok(name)
}

/// The staging name for a delivery: the final name with `.part` appended.
///
/// Appended rather than substituted, so that two deliveries in one directory can never
/// stage into the same file and so that the staging name of `x.psbt` cannot collide with a
/// real `x.part` the user put there.
fn staging(target: &Name) -> Result<Name, NameError> {
    let suffix = STAGING_EXT.len().saturating_add(1);
    let room = Name::MAX_BYTES.saturating_sub(suffix);
    let base = target.as_str();
    let mut out = String::new();
    out.push_str(base.get(..room.min(base.len())).unwrap_or(""));
    out.push('.');
    out.push_str(STAGING_EXT);
    Name::parse(&out)
}

// ---------------------------------------------------------------------------------------
// Delivery
// ---------------------------------------------------------------------------------------

/// What to do when the target name is already on the card.
///
/// No third option, and no automatic renaming to `-1`. UX-SCREENS S-38 puts an overwrite
/// behind an explicit yellow-card confirmation, so the decision belongs to the person
/// looking at the screen; and a device with no RNG that silently invented a second name
/// would falsify the "this writes to the card: `<name>`" notice it showed a moment before.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OnCollision {
    Refuse,
    Replace,
}

/// What a completed delivery wrote.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Delivered {
    pub name: Name,
    pub bytes: usize,
    /// True if an existing file of the same name was removed to make room.
    pub replaced: bool,
}

/// Write `data` to `dir/name`, staged and verified.
///
/// The sequence:
///
/// 1. clear any stale staging file - litter from a previous interrupted delivery;
/// 2. create the staging file exclusively, write it whole, flush it;
/// 3. read it back and compare it byte for byte with what was handed in;
/// 4. remove the target if it exists and the caller allowed a replacement;
/// 5. rename staging onto the target.
///
/// Step 3 is the one that is not obvious. An SD card can acknowledge a write and return
/// different bytes - a worn card, a counterfeit card, a bad contact - and this is the last
/// moment at which noticing that is cheap: before the bytes acquire the name a coordinator
/// will trust. It costs one extra read of a file that is normally a few kilobytes, and it
/// means the final name is never given to bytes the card has not already proven it can
/// hand back.
///
/// The peak allocation is therefore twice the payload. On a device whose PSBT cap is
/// measured against PSRAM that also holds a framebuffer and the Argon2 arena, that is a
/// number the caller's cap has to accommodate, and it is stated here rather than
/// discovered there.
///
/// The module docs hold the power-loss guarantee this sequence composes into, including
/// the two places it stops short.
pub fn deliver<V: Volume>(
    volume: &mut V,
    dir: Option<&Name>,
    name: &Name,
    data: &[u8],
    on_collision: OnCollision,
) -> Result<Delivered, SdError<V::Error>> {
    name.portable()?;
    let stage = staging(name)?;
    let target = at(dir, name);
    let staged = at(dir, &stage);

    let occupied = volume.exists(target).map_err(SdError::Backend)?;
    if occupied && on_collision == OnCollision::Refuse {
        return Err(SdError::Collision);
    }
    if volume.exists(staged).map_err(SdError::Backend)? {
        volume.remove(staged).map_err(SdError::Backend)?;
    }

    volume
        .create_exclusive(staged, data)
        .map_err(SdError::Backend)?;

    let mut back = Vec::new();
    let limit = u32::try_from(data.len()).unwrap_or(u32::MAX);
    let outcome = volume
        .read(staged, limit, &mut back)
        .map_err(SdError::Backend)?;
    if outcome != ReadOutcome::Complete || back.as_slice() != data {
        // The staging file is deliberately left where it is. It is the evidence, it cannot
        // be mistaken for a delivered artifact, and removing it would need a second write
        // to a card that has just demonstrated it cannot be trusted with one.
        return Err(SdError::ReadBackMismatch {
            wrote: data.len(),
            read: back.len(),
        });
    }

    if occupied {
        volume.remove(target).map_err(SdError::Backend)?;
    }
    volume.rename(staged, target).map_err(SdError::Backend)?;

    Ok(Delivered {
        name: name.clone(),
        bytes: data.len(),
        replaced: occupied,
    })
}

fn at<'a>(dir: Option<&'a Name>, file: &'a Name) -> Location<'a> {
    Location { dir, file }
}

// ---------------------------------------------------------------------------------------
// Simulation backend
// ---------------------------------------------------------------------------------------

/// An in-memory [`Volume`], and the faults a real card commits.
///
/// Behind `testkit` for the same reason [`crate::sim`] is: it is host code, harnesses
/// outside this crate's unit tests need it, and a feature is greppable in
/// `tools/build-graph-check.sh` where a `cfg(test)` is not. It must never be enabled in a
/// firmware build.
#[cfg(feature = "testkit")]
pub mod sim {
    use super::{Location, Name, Raw, ReadOutcome, Volume, Walk};
    use alloc::collections::{BTreeMap, BTreeSet};
    use alloc::string::String;
    use alloc::vec::Vec;

    /// Why a simulated operation failed.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum SimError {
        NotFound,
        AlreadyExists,
        /// The injected fault fired.
        Cut,
    }

    /// Where the power goes out, or where the card misbehaves.
    ///
    /// One variant per step of [`super::deliver`] that can fail, so a test can walk the
    /// whole sequence and assert the same invariant after each: the target name never
    /// holds anything but the complete intended bytes.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum Fault {
        None,
        /// The write stops after `n` bytes and reports failure, leaving a short staging
        /// file behind. A card pulled mid-write.
        DuringWrite(usize),
        /// The rename fails. Indistinguishable, from the card's side, from a cut in the
        /// instant before it.
        DuringRename,
        /// Any delete fails, which is what strands the previous file in the replace path.
        DuringRemove,
        /// The write is accepted and the card hands back different bytes.
        CorruptOnReadBack,
    }

    /// The mount point the simulation renders paths against. Any constant would do; this
    /// one matches the firmware so a rendered path reads the same in both places.
    pub const MOUNT: &str = "/sd";

    /// A FAT-like volume held in maps: keys are the strings [`Location::render`] produces.
    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct SimVolume {
        files: BTreeMap<String, Vec<u8>>,
        dirs: BTreeSet<String>,
        times: BTreeMap<String, i64>,
        /// Names returned by `walk` verbatim, bypassing `Name`'s rules, so a test can put a
        /// path separator or a non-UTF-8 byte in a directory entry.
        raw_names: BTreeMap<String, Vec<u8>>,
        /// Directory-entry sizes that disagree with the file's real length, for the case
        /// where the card lies about what it holds.
        claims: BTreeMap<String, u64>,
        fault: Fault,
    }

    impl Default for SimVolume {
        fn default() -> Self {
            Self::new()
        }
    }

    impl SimVolume {
        pub fn new() -> Self {
            SimVolume {
                files: BTreeMap::new(),
                dirs: BTreeSet::new(),
                times: BTreeMap::new(),
                raw_names: BTreeMap::new(),
                claims: BTreeMap::new(),
                fault: Fault::None,
            }
        }

        /// Put a file at the root.
        pub fn put(&mut self, name: &str, data: &[u8]) -> &mut Self {
            let path = Self::join(None, name);
            self.files.insert(path.clone(), data.to_vec());
            self.raw_names.insert(path, name.as_bytes().to_vec());
            self
        }

        /// Put a file whose directory entry carries `entry_name`, which need not be a name
        /// this device would accept.
        pub fn put_raw(&mut self, key: &str, entry_name: &[u8], data: &[u8]) -> &mut Self {
            let path = Self::join(None, key);
            self.files.insert(path.clone(), data.to_vec());
            self.raw_names.insert(path, entry_name.to_vec());
            self
        }

        pub fn put_in(&mut self, dir: &str, name: &str, data: &[u8]) -> &mut Self {
            self.mkdir(dir);
            let path = Self::join(Some(dir), name);
            self.files.insert(path.clone(), data.to_vec());
            self.raw_names.insert(path, name.as_bytes().to_vec());
            self
        }

        pub fn mkdir(&mut self, name: &str) -> &mut Self {
            let path = Self::join(None, name);
            self.dirs.insert(path.clone());
            self.raw_names.insert(path, name.as_bytes().to_vec());
            self
        }

        /// A directory two levels down, which the picker must never show.
        pub fn mkdir_in(&mut self, dir: &str, name: &str) -> &mut Self {
            self.mkdir(dir);
            let path = Self::join(Some(dir), name);
            self.dirs.insert(path.clone());
            self.raw_names.insert(path, name.as_bytes().to_vec());
            self
        }

        pub fn touch(&mut self, name: &str, epoch: i64) -> &mut Self {
            self.times.insert(Self::join(None, name), epoch);
            self
        }

        /// Make a directory entry claim a size the file does not have.
        pub fn claim(&mut self, name: &str, len: u64) -> &mut Self {
            self.claims.insert(Self::join(None, name), len);
            self
        }

        pub fn fault(&mut self, fault: Fault) -> &mut Self {
            self.fault = fault;
            self
        }

        pub fn get(&self, name: &str) -> Option<&[u8]> {
            self.files.get(&Self::join(None, name)).map(Vec::as_slice)
        }

        pub fn contains(&self, name: &str) -> bool {
            self.files.contains_key(&Self::join(None, name))
        }

        pub fn file_count(&self) -> usize {
            self.files.len()
        }

        fn join(dir: Option<&str>, name: &str) -> String {
            let mut out = String::new();
            out.push_str(MOUNT);
            if let Some(dir) = dir {
                out.push('/');
                out.push_str(dir);
            }
            out.push('/');
            out.push_str(name);
            out
        }

        fn prefix(dir: Option<&Name>) -> String {
            let mut out = String::new();
            out.push_str(MOUNT);
            if let Some(dir) = dir {
                out.push('/');
                out.push_str(dir.as_str());
            }
            out.push('/');
            out
        }

        fn immediate(path: &str, prefix: &str) -> bool {
            path.starts_with(prefix)
                && path
                    .get(prefix.len()..)
                    .is_some_and(|rest| !rest.is_empty() && !rest.contains('/'))
        }
    }

    impl Volume for SimVolume {
        type Error = SimError;

        fn walk(
            &mut self,
            dir: Option<&Name>,
            visit: &mut dyn FnMut(Raw<'_>) -> Walk,
        ) -> Result<(), Self::Error> {
            let prefix = Self::prefix(dir);
            let mut listing: Vec<(String, bool)> = Vec::new();
            for path in self.files.keys() {
                if Self::immediate(path, &prefix) {
                    listing.push((path.clone(), false));
                }
            }
            for path in self.dirs.iter() {
                if Self::immediate(path, &prefix) {
                    listing.push((path.clone(), true));
                }
            }
            for (path, is_dir) in listing {
                let fallback = path.get(prefix.len()..).unwrap_or("").as_bytes().to_vec();
                let name = self.raw_names.get(&path).cloned().unwrap_or(fallback);
                let len = match self.claims.get(&path) {
                    Some(claim) => *claim,
                    None => self
                        .files
                        .get(&path)
                        .map(|f| u64::try_from(f.len()).unwrap_or(u64::MAX))
                        .unwrap_or(0),
                };
                let raw = Raw {
                    name: &name,
                    is_dir,
                    len,
                    modified: self.times.get(&path).copied(),
                };
                if visit(raw) == Walk::Stop {
                    break;
                }
            }
            Ok(())
        }

        fn read(
            &mut self,
            at: Location<'_>,
            limit: u32,
            out: &mut Vec<u8>,
        ) -> Result<ReadOutcome, Self::Error> {
            out.clear();
            let path = at.render(MOUNT);
            let data = self.files.get(&path).ok_or(SimError::NotFound)?;
            let limit = usize::try_from(limit).unwrap_or(usize::MAX);
            let take = limit.min(data.len());
            out.extend_from_slice(data.get(..take).unwrap_or(&[]));
            if self.fault == Fault::CorruptOnReadBack {
                if let Some(first) = out.first_mut() {
                    *first ^= 0xff;
                }
            }
            if data.len() > limit {
                Ok(ReadOutcome::OverLimit)
            } else {
                Ok(ReadOutcome::Complete)
            }
        }

        fn create_exclusive(&mut self, at: Location<'_>, data: &[u8]) -> Result<(), Self::Error> {
            let path = at.render(MOUNT);
            if self.files.contains_key(&path) {
                return Err(SimError::AlreadyExists);
            }
            if let Fault::DuringWrite(n) = self.fault {
                let take = n.min(data.len());
                self.files
                    .insert(path, data.get(..take).unwrap_or(&[]).to_vec());
                return Err(SimError::Cut);
            }
            self.files.insert(path, data.to_vec());
            Ok(())
        }

        fn rename(&mut self, from: Location<'_>, to: Location<'_>) -> Result<(), Self::Error> {
            if self.fault == Fault::DuringRename {
                return Err(SimError::Cut);
            }
            let from = from.render(MOUNT);
            let to = to.render(MOUNT);
            let data = self.files.remove(&from).ok_or(SimError::NotFound)?;
            self.files.insert(to, data);
            Ok(())
        }

        fn remove(&mut self, at: Location<'_>) -> Result<(), Self::Error> {
            if self.fault == Fault::DuringRemove {
                return Err(SimError::Cut);
            }
            let path = at.render(MOUNT);
            self.files
                .remove(&path)
                .map(|_| ())
                .ok_or(SimError::NotFound)
        }

        fn exists(&mut self, at: Location<'_>) -> Result<bool, Self::Error> {
            Ok(self.files.contains_key(&at.render(MOUNT)))
        }
    }
}

#[cfg(test)]
mod tests {
    // Test code, not card code; the same exemption hal.rs and sim.rs take, and for the
    // same reason: a test that cannot index or unwrap is a test written around its lint
    // set rather than around the property it is asserting.
    #![allow(
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::arithmetic_side_effects
    )]

    use super::sim::{Fault, SimError, SimVolume, MOUNT};
    use super::*;

    fn name(text: &str) -> Name {
        Name::parse(text).expect("valid test name")
    }

    fn bounds() -> Bounds {
        Bounds::new(1024 * 1024)
    }

    fn listed(cat: &Catalog) -> Vec<&str> {
        cat.entries().iter().map(|e| e.name.as_str()).collect()
    }

    // -----------------------------------------------------------------------------------
    // Names: the traversal, and everything else a directory entry may claim to be called
    // -----------------------------------------------------------------------------------

    /// The reason `Name` exists. Every one of these is a directory entry a hostile card can
    /// legally contain, and none of them may become a path component.
    ///
    /// The reserved set is the FAT32 File System Specification 1.03 long-name character
    /// rules; `.` and `..` are the two entries every FAT directory holds by definition.
    #[test]
    fn a_directory_entry_cannot_smuggle_a_path() {
        for hostile in [
            "../secrets",
            "..",
            ".",
            "a/b",
            "a\\b",
            "C:file",
            "a<b",
            "a>b",
            "a|b",
            "a?b",
            "a*b",
            "a\"b",
        ] {
            assert!(
                Name::parse(hostile).is_err(),
                "{hostile:?} must not become a Name"
            );
        }
    }

    #[test]
    fn control_bytes_and_non_ascii_are_refused() {
        assert_eq!(Name::new(b"a\nb"), Err(NameError::NotAscii { at: 1 }));
        assert_eq!(Name::new(b"a\0b"), Err(NameError::NotAscii { at: 1 }));
        assert_eq!(Name::new(b"a\x7fb"), Err(NameError::NotAscii { at: 1 }));
        // An OEM code page hands back bytes above 0x7f; they are not transliterated.
        assert_eq!(Name::new(&[b'a', 0xe9]), Err(NameError::NotAscii { at: 1 }));
        assert_eq!(Name::new(b""), Err(NameError::Length { len: 0 }));
        assert!(Name::new(&[b'a'; 256]).is_err());
        assert!(Name::new(&[b'a'; 255]).is_ok());
    }

    /// Reading one is fine; writing one is not. Source for the device names: Microsoft,
    /// "Naming Files, Paths, and Namespaces".
    #[test]
    fn reserved_device_names_are_readable_but_never_written() {
        for reserved in ["NUL", "nul.txt", "CON", "aux", "COM1", "lpt9", "trailing "] {
            let n = Name::parse(reserved).expect("a card may hold this");
            assert_eq!(
                n.portable(),
                Err(NameError::NotPortable),
                "{reserved:?} must not be a name this device creates"
            );
        }
        // COM0 and LPT0 are not reserved, and a stem that merely begins with one is not
        // either.
        for ok in ["COM0", "lpt0", "common.psbt", "console"] {
            Name::parse(ok).unwrap().portable().expect("not reserved");
        }
    }

    #[test]
    fn stems_and_extensions_follow_the_last_dot_and_ignore_a_leading_one() {
        assert_eq!(name("spend.psbt").stem(), "spend");
        assert_eq!(name("a.b.psbt").stem(), "a.b");
        assert_eq!(name("noext").stem(), "noext");
        assert_eq!(name(".hidden").stem(), ".hidden");
        assert!(name("SPEND.PSBT").extension_eq("psbt"));
        assert!(!name(".psbt").extension_eq("psbt"));
    }

    #[test]
    fn sanitize_is_total_deterministic_and_bounded() {
        assert_eq!(
            Name::sanitize("My Savings / 2026", 32, "wallet")
                .unwrap()
                .as_str(),
            "My-Savings-2026"
        );
        assert_eq!(
            Name::sanitize("///", 32, "wallet").unwrap().as_str(),
            "wallet"
        );
        assert_eq!(
            Name::sanitize("NUL", 32, "wallet").unwrap().as_str(),
            "wallet"
        );
        assert_eq!(Name::sanitize("--a--b--", 32, "w").unwrap().as_str(), "a-b");
        assert_eq!(Name::sanitize("abcdefghij", 4, "w").unwrap().as_str(), "abcd");
        // Determinism is a requirement, not an observation: the announced name and the
        // written name are produced by two separate calls (SECURITY invariant 2b).
        assert_eq!(
            Name::sanitize("a b c", 16, "w").unwrap(),
            Name::sanitize("a b c", 16, "w").unwrap()
        );
    }

    // -----------------------------------------------------------------------------------
    // Locations
    // -----------------------------------------------------------------------------------

    #[test]
    fn rendering_a_location_cannot_leave_the_mount_point() {
        let dir = name("psbt");
        let file = name("spend.psbt");
        assert_eq!(Location::root(&file).render("/sd"), "/sd/spend.psbt");
        assert_eq!(
            Location::under(&dir, &file).render("/sd"),
            "/sd/psbt/spend.psbt"
        );
    }

    // -----------------------------------------------------------------------------------
    // Timestamps
    // -----------------------------------------------------------------------------------

    /// Vectors, and where each one comes from.
    ///
    /// The epoch and the signed 32-bit maximum are POSIX (IEEE Std 1003.1, "Seconds Since
    /// the Epoch", and the published 2038-01-19T03:14:07Z rollover instant). 1980-01-01 is
    /// the FAT directory entry's year base (FAT32 File System Specification 1.03,
    /// `DIR_WrtDate`). 2000-02-29 is the century leap day the divisible-by-400 rule admits
    /// and the divisible-by-100 rule alone would not - the single case a naive calendar
    /// gets wrong. The two round numbers are the widely published 1_000_000_000 and
    /// 1_234_567_890 instants. Every pair was cross-checked against an independent
    /// implementation before it was written down.
    #[test]
    fn epoch_seconds_become_the_civil_date_published_for_them() {
        const fn at(
            year: u16,
            month: u8,
            day: u8,
            hour: u8,
            minute: u8,
        ) -> Timestamp {
            Timestamp {
                year,
                month,
                day,
                hour,
                minute,
            }
        }
        let cases = [
            (315_532_800i64, at(1980, 1, 1, 0, 0)),
            (951_782_400, at(2000, 2, 29, 0, 0)),
            (1_000_000_000, at(2001, 9, 9, 1, 46)),
            (1_234_567_890, at(2009, 2, 13, 23, 31)),
            (2_147_483_647, at(2038, 1, 19, 3, 14)),
            (4_354_819_199, at(2107, 12, 31, 23, 59)),
        ];
        for (seconds, expected) in cases {
            let ts = Timestamp::from_epoch_seconds(seconds)
                .unwrap_or_else(|| panic!("{seconds} is inside the FAT range"));
            assert_eq!(ts, expected, "epoch {seconds}");
        }
    }

    #[test]
    fn a_directory_entry_outside_the_fat_range_has_no_timestamp() {
        // The POSIX epoch itself predates FAT's year base, and an all-zero date field
        // normalizes to somewhere near it. "No timestamp" beats a wrong one.
        assert_eq!(Timestamp::from_epoch_seconds(0), None);
        assert_eq!(Timestamp::from_epoch_seconds(-1), None);
        assert_eq!(Timestamp::from_epoch_seconds(315_532_799), None);
        assert_eq!(Timestamp::from_epoch_seconds(4_354_819_200), None);
        assert_eq!(Timestamp::from_epoch_seconds(i64::MAX), None);
    }

    #[test]
    fn timestamps_render_big_endian() {
        // 2026-08-17T14:02:00Z, the instant UX-SCREENS S-28 uses in its wireframe.
        let ts = Timestamp::from_epoch_seconds(1_786_975_320).unwrap();
        assert_eq!(alloc::format!("{ts}"), "2026-08-17 14:02");
    }

    // -----------------------------------------------------------------------------------
    // Cataloguing
    // -----------------------------------------------------------------------------------

    #[test]
    fn a_catalog_is_bounded_validated_and_ordered() {
        let mut vol = SimVolume::new();
        vol.put("zeta.psbt", b"z")
            .put("Alpha.psbt", b"a")
            .put("alpha.psbt", b"a")
            .put("notes.txt", b"n")
            .mkdir("archive");
        let cat = Catalog::scan(&mut vol, None, Filter::All, &bounds()).expect("scan");
        // Directory first; then case-insensitive, with the exact-byte tiebreak deciding
        // Alpha before alpha rather than the volume's own order deciding it.
        assert_eq!(
            listed(&cat),
            ["archive", "Alpha.psbt", "alpha.psbt", "notes.txt", "zeta.psbt"]
        );
        assert!(!cat.truncated());
        assert_eq!(cat.rejected(), 0);
    }

    #[test]
    fn the_psbt_tab_shows_psbts_and_directories_and_nothing_else() {
        let mut vol = SimVolume::new();
        vol.put("spend.PSBT", b"p")
            .put("notes.txt", b"n")
            .put("wallet.json", b"j")
            .put("tx.txn", b"t")
            .mkdir("archive");
        let cat = Catalog::scan(&mut vol, None, Filter::PsbtOnly, &bounds()).expect("scan");
        assert_eq!(listed(&cat), ["archive", "spend.PSBT"]);
        assert_eq!(cat.entries()[1].kind, Kind::Psbt);

        let all = Catalog::scan(&mut vol, None, Filter::All, &bounds()).expect("scan");
        assert_eq!(
            listed(&all),
            ["archive", "notes.txt", "spend.PSBT", "tx.txn", "wallet.json"]
        );
        assert_eq!(all.entries()[1].kind, Kind::Text);
        assert_eq!(all.entries()[3].kind, Kind::Txn);
        assert_eq!(all.entries()[4].kind, Kind::Json);
    }

    #[test]
    fn a_name_the_device_cannot_use_is_counted_not_shown() {
        let mut vol = SimVolume::new();
        vol.put("good.psbt", b"g");
        vol.put_raw("bad1", b"../escape.psbt", b"x");
        vol.put_raw("bad2", &[b'c', 0xe9, b'.', b'p', b's', b'b', b't'], b"x");
        let cat = Catalog::scan(&mut vol, None, Filter::All, &bounds()).expect("scan");
        assert_eq!(listed(&cat), ["good.psbt"]);
        assert_eq!(cat.rejected(), 2);
    }

    #[test]
    fn staging_litter_is_never_offered() {
        let mut vol = SimVolume::new();
        vol.put("spend-signed.psbt.part", b"half")
            .put("spend.psbt", b"whole");
        let cat = Catalog::scan(&mut vol, None, Filter::All, &bounds()).expect("scan");
        assert_eq!(listed(&cat), ["spend.psbt"]);
        // Dropped, not rejected: it is the device's own file, not an unreadable one.
        assert_eq!(cat.rejected(), 0);
    }

    #[test]
    fn a_card_with_more_files_than_the_bound_is_truncated_not_refused() {
        let mut vol = SimVolume::new();
        for i in 0..40u16 {
            vol.put(&alloc::format!("f{i:03}.psbt"), b"x");
        }
        let mut b = bounds();
        b.max_entries = 10;
        let cat = Catalog::scan(&mut vol, None, Filter::All, &b).expect("scan");
        assert_eq!(cat.entries().len(), 10);
        assert!(cat.truncated());
    }

    #[test]
    fn the_picker_never_descends_past_one_level() {
        let mut vol = SimVolume::new();
        vol.put_in("archive", "old.psbt", b"o");
        vol.mkdir_in("archive", "deeper");
        // The root shows the directory ...
        let root = Catalog::scan(&mut vol, None, Filter::All, &bounds()).expect("scan");
        assert_eq!(listed(&root), ["archive"]);
        // ... and one level down, the nested directory is not offered at all.
        let dir = name("archive");
        let cat = Catalog::scan(&mut vol, Some(&dir), Filter::All, &bounds()).expect("scan");
        assert_eq!(listed(&cat), ["old.psbt"]);
    }

    /// A lying directory entry cannot buy an allocation, and it cannot hide the file
    /// either: the row is listed and marked, which is what S-28 renders as `Disabled` plus
    /// "too large".
    #[test]
    fn a_directory_entry_claiming_four_gigabytes_is_marked_not_believed() {
        let mut vol = SimVolume::new();
        vol.put("huge.psbt", b"actually tiny")
            .claim("huge.psbt", u64::MAX);
        let cat = Catalog::scan(&mut vol, None, Filter::All, &bounds()).expect("scan");
        let entry = &cat.entries()[0];
        assert!(entry.oversize);
        assert_eq!(entry.len, u32::MAX);
    }

    #[test]
    fn a_timestamp_reaches_the_row_and_a_nonsense_one_does_not() {
        let mut vol = SimVolume::new();
        vol.put("dated.psbt", b"d").touch("dated.psbt", 1_786_975_320);
        vol.put("undated.psbt", b"u").touch("undated.psbt", 0);
        let cat = Catalog::scan(&mut vol, None, Filter::All, &bounds()).expect("scan");
        assert_eq!(
            cat.entries()[0].modified.map(|t| alloc::format!("{t}")),
            Some(alloc::string::String::from("2026-08-17 14:02"))
        );
        assert_eq!(cat.entries()[1].modified, None);
    }

    // -----------------------------------------------------------------------------------
    // Reading
    // -----------------------------------------------------------------------------------

    #[test]
    fn reading_stops_at_the_cap_and_refuses_the_prefix() {
        let mut vol = SimVolume::new();
        vol.put("big.psbt", &[7u8; 4096]);
        let file = name("big.psbt");
        let small = Bounds::new(1024);
        assert_eq!(
            read(&mut vol, Location::root(&file), &small),
            Err(SdError::TooLarge { max: 1024 })
        );
        let exact = Bounds::new(4096);
        assert_eq!(
            read(&mut vol, Location::root(&file), &exact)
                .expect("fits")
                .len(),
            4096
        );
    }

    #[test]
    fn a_missing_file_is_a_backend_error_not_an_empty_read() {
        let mut vol = SimVolume::new();
        let file = name("absent.psbt");
        assert_eq!(
            read(&mut vol, Location::root(&file), &bounds()),
            Err(SdError::Backend(SimError::NotFound))
        );
    }

    // -----------------------------------------------------------------------------------
    // Naming what goes back out
    // -----------------------------------------------------------------------------------

    #[test]
    fn the_write_plan_follows_the_coldcard_convention() {
        let source = name("psbt-2026-08-17.psbt");
        let planned = plan(&source, true).expect("plan");
        assert_eq!(planned.signed.as_str(), "psbt-2026-08-17-signed.psbt");
        assert_eq!(
            planned.finalized.as_ref().map(Name::as_str),
            Some("psbt-2026-08-17-final.txn")
        );
        // A partially signed multisig has no finalized form, so the line is absent rather
        // than naming a file that will not be written.
        assert!(plan(&source, false).expect("plan").finalized.is_none());
    }

    #[test]
    fn a_long_source_name_loses_stem_not_suffix() {
        let source = Name::parse(&"a".repeat(255)).expect("at the FAT maximum");
        let planned = plan(&source, true).expect("plan");
        assert!(planned.signed.len() <= Name::MAX_BYTES);
        assert!(planned.signed.as_str().ends_with("-signed.psbt"));
        let finalized = planned.finalized.expect("finalized");
        assert!(finalized.len() <= Name::MAX_BYTES);
        assert!(finalized.as_str().ends_with("-final.txn"));
    }

    /// Documented behaviour, not an oversight: stripping a trailing `-signed` would make
    /// the output name equal to the input name and overwrite the file being signed.
    #[test]
    fn signing_a_signed_file_appends_rather_than_replacing() {
        let source = name("spend-signed.psbt");
        assert_eq!(
            plan(&source, false).expect("plan").signed.as_str(),
            "spend-signed-signed.psbt"
        );
    }

    // -----------------------------------------------------------------------------------
    // Delivery, and every point a power cut can land on
    // -----------------------------------------------------------------------------------

    #[test]
    fn a_delivery_stages_verifies_and_renames() {
        let mut vol = SimVolume::new();
        let target = name("spend-signed.psbt");
        let out =
            deliver(&mut vol, None, &target, b"psbt bytes", OnCollision::Refuse).expect("delivered");
        assert_eq!(out.bytes, 10);
        assert!(!out.replaced);
        assert_eq!(vol.get("spend-signed.psbt"), Some(&b"psbt bytes"[..]));
        // Nothing else is left behind.
        assert_eq!(vol.file_count(), 1);
    }

    /// The property the whole staging sequence exists for, asserted at every point of it
    /// that can fail: after a cut, the target name either does not exist or holds exactly
    /// the bytes handed in. It never holds a prefix.
    #[test]
    fn no_power_cut_leaves_the_target_name_holding_a_partial_body() {
        let payload = b"the complete signed transaction".as_slice();
        for fault in [
            Fault::DuringWrite(0),
            Fault::DuringWrite(1),
            Fault::DuringWrite(7),
            Fault::DuringWrite(30),
            Fault::DuringRename,
            Fault::CorruptOnReadBack,
        ] {
            let mut vol = SimVolume::new();
            vol.fault(fault);
            let target = name("spend-signed.psbt");
            let outcome = deliver(&mut vol, None, &target, payload, OnCollision::Refuse);
            assert!(outcome.is_err(), "{fault:?} must not report success");
            if let Some(found) = vol.get("spend-signed.psbt") {
                panic!("{fault:?} left the target name holding {found:?}");
            }
        }
    }

    /// The replace path has one extra failure point, and it is the window the module docs
    /// admit to: the old file is gone and the new name has not arrived. What must still
    /// hold is that the new name never carries a partial body, and that the bytes are
    /// still on the card under the staging name.
    #[test]
    fn a_cut_while_replacing_loses_the_old_file_but_never_forges_the_new_one() {
        let mut vol = SimVolume::new();
        vol.put("spend-signed.psbt", b"older");
        let target = name("spend-signed.psbt");
        vol.fault(Fault::DuringRename);
        let outcome = deliver(&mut vol, None, &target, b"newer", OnCollision::Replace);
        assert_eq!(outcome, Err(SdError::Backend(SimError::Cut)));
        assert!(!vol.contains("spend-signed.psbt"));
        assert_eq!(vol.get("spend-signed.psbt.part"), Some(&b"newer"[..]));
    }

    /// The other failure point in the replace path. A delete that does not happen leaves
    /// the previous file exactly as it was, which is the outcome to prefer: the delivery
    /// is reported as failed and nothing the user had is gone.
    #[test]
    fn a_failed_delete_leaves_the_previous_file_untouched() {
        let mut vol = SimVolume::new();
        vol.put("spend-signed.psbt", b"older");
        vol.fault(Fault::DuringRemove);
        let target = name("spend-signed.psbt");
        assert_eq!(
            deliver(&mut vol, None, &target, b"newer", OnCollision::Replace),
            Err(SdError::Backend(SimError::Cut))
        );
        assert_eq!(vol.get("spend-signed.psbt"), Some(&b"older"[..]));
        assert_eq!(vol.get("spend-signed.psbt.part"), Some(&b"newer"[..]));
    }

    #[test]
    fn a_stale_staging_file_is_cleared_by_the_next_delivery() {
        let mut vol = SimVolume::new();
        vol.put("spend-signed.psbt.part", b"litter from a cut");
        let target = name("spend-signed.psbt");
        deliver(&mut vol, None, &target, b"fresh", OnCollision::Refuse).expect("delivered");
        assert_eq!(vol.get("spend-signed.psbt"), Some(&b"fresh"[..]));
        assert!(!vol.contains("spend-signed.psbt.part"));
        assert_eq!(vol.file_count(), 1);
    }

    #[test]
    fn a_card_that_returns_different_bytes_never_gets_to_name_them() {
        let mut vol = SimVolume::new();
        vol.fault(Fault::CorruptOnReadBack);
        let target = name("spend-signed.psbt");
        let err = deliver(&mut vol, None, &target, b"abcdef", OnCollision::Refuse)
            .expect_err("the read-back must fail");
        assert_eq!(err, SdError::ReadBackMismatch { wrote: 6, read: 6 });
        assert!(!vol.contains("spend-signed.psbt"));
        // The staging file survives as the evidence.
        assert!(vol.contains("spend-signed.psbt.part"));
    }

    #[test]
    fn an_existing_target_is_refused_unless_the_caller_allowed_a_replacement() {
        let mut vol = SimVolume::new();
        vol.put("spend-signed.psbt", b"older");
        let target = name("spend-signed.psbt");
        assert_eq!(
            deliver(&mut vol, None, &target, b"newer", OnCollision::Refuse),
            Err(SdError::Collision)
        );
        assert_eq!(vol.get("spend-signed.psbt"), Some(&b"older"[..]));
        let out = deliver(&mut vol, None, &target, b"newer", OnCollision::Replace)
            .expect("replaced");
        assert!(out.replaced);
        assert_eq!(vol.get("spend-signed.psbt"), Some(&b"newer"[..]));
        assert_eq!(vol.file_count(), 1);
    }

    #[test]
    fn a_name_the_users_computer_cannot_open_is_never_delivered() {
        let mut vol = SimVolume::new();
        let target = name("NUL.psbt");
        assert_eq!(
            deliver(&mut vol, None, &target, b"x", OnCollision::Refuse),
            Err(SdError::Name(NameError::NotPortable))
        );
        assert_eq!(vol.file_count(), 0);
    }

    #[test]
    fn delivery_into_a_subdirectory_stays_in_it() {
        let mut vol = SimVolume::new();
        vol.put_in("psbt", "seed.psbt", b"s");
        let dir = name("psbt");
        let target = name("spend-signed.psbt");
        deliver(&mut vol, Some(&dir), &target, b"body", OnCollision::Refuse).expect("delivered");
        assert_eq!(
            Location::under(&dir, &target).render(MOUNT),
            "/sd/psbt/spend-signed.psbt"
        );
        // Present one level down ...
        let cat = Catalog::scan(&mut vol, Some(&dir), Filter::All, &bounds()).expect("scan");
        assert_eq!(listed(&cat), ["seed.psbt", "spend-signed.psbt"]);
        // ... and not at the root, which holds only the directory itself.
        let root = Catalog::scan(&mut vol, None, Filter::All, &bounds()).expect("scan");
        assert_eq!(listed(&root), ["psbt"]);
    }
}
