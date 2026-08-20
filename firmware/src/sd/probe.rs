// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! What sector 0 of a card says, and whether writing a filesystem into it could help.
//!
//! This is the whole of the format decision, and it is pure: bytes in, a verdict out, no
//! driver, no ESP-IDF, no allocation off a card-supplied length. `firmware/hostcheck`
//! compiles this exact file for the host and drives it against hand-built sectors, which
//! is the only way any of it gets tested at all - the module that calls it cannot be
//! built without silicon.
//!
//! # Why the decision lives here and not next to `f_mkfs`
//!
//! `notyas_wallet::sd`'s seam rule says every judgement belongs in pure, host-tested code
//! and the firmware side is calls with no logic. The judgement here is the most
//! consequential one this device makes about a card: it decides whether the user is
//! offered a button that erases everything they own on it. A branch of that reached only
//! on a bench, with a real card, is a branch nobody has checked.
//!
//! # The rule, stated once
//!
//! **A format is offered only where it repairs the fault, and never where it would erase
//! something this device cannot read back.** That collapses to four questions about one
//! sector:
//!
//! 1. Is there a partition table at all? A card whose filesystem starts at LBA 0 (a
//!    "superfloppy") has none. Its intended layout is something this device does not know
//!    and must not invent - the standing instruction is not to touch partitions, and
//!    creating a table where there was none is the largest partition change there is.
//! 2. Is it an MBR? A GPT-partitioned card is refused: this build's FatFs has `FF_LBA64`
//!    at 0 (`ffconf.h`), so it cannot address a GPT volume, and a format would not make
//!    the card readable even if it succeeded.
//! 3. Is there exactly one partition? Two or more and the device would be choosing which
//!    of somebody's volumes to destroy. It does not get to choose.
//! 4. Does that partition fit inside the card, and is it big enough for FatFs to build a
//!    volume in? A table that describes more sectors than the card has is corrupt, and
//!    corrupt is the state in which writing is worst.
//!
//! Anything that survives all four is a card where `f_mkfs` into the EXISTING partition
//! entry is a repair: the geometry the table describes is left exactly as it is, and the
//! only byte of the table that changes is that entry's filesystem-type byte, which FatFs
//! rewrites to match what it just built (ff.c, "Update system ID in the partition
//! table"). The screen says so, in those words; see `notyas_ui::screens::format`.
//!
//! # What this module deliberately cannot tell you
//!
//! Whether the card is FAILING. A sector that reads is a sector that reads; a card with a
//! dying controller can hand back a perfect MBR and then fail on the first write. The
//! caller answers that half by whether the read SUCCEEDED at all, and the copy on the
//! screen never promises the format will work - only that nothing on the device is at
//! risk if it does not.

use std::fmt;

/// Bytes in an SD block. Fixed for every SD card this device can address, and the number
/// FatFs is compiled against (`ffconf.h`: `FF_MIN_SS` and `FF_MAX_SS` are both
/// `FF_SS_SDCARD`).
pub const SECTOR_BYTES: usize = 512;

/// Offset of the first partition entry in an MBR, and the size of one entry.
const TABLE_OFFSET: usize = 446;
const ENTRY_BYTES: usize = 16;
/// Where in an entry the type byte, the first LBA and the sector count sit.
const ENTRY_TYPE: usize = 4;
const ENTRY_START: usize = 8;
const ENTRY_SECTORS: usize = 12;

/// MBR type byte of a GPT protective partition. Its presence means the real table is a
/// GPT and this MBR is a decoy that exists precisely to stop tools like this one writing.
const TYPE_GPT_PROTECTIVE: u8 = 0xEE;
/// The extended-partition containers. What is inside one is a chain this device does not
/// walk, so a card carrying one holds an unknown number of volumes.
const TYPE_EXTENDED: [u8; 3] = [0x05, 0x0F, 0x85];

/// Smallest partition this device will build a filesystem in, in sectors: 64 KiB.
///
/// FatFs's own floor is `MIN_FAT12_SEC_VOL` (4 sectors), which it enforces by ABORTING
/// part-way through the call. This floor is far above it and exists so that the refusal
/// happens here, as a sentence, rather than there, as an `FRESULT` after the driver has
/// been brought up. Nothing anyone would call a card is smaller.
const MIN_SECTORS: u32 = 128;

/// One MBR partition entry, as this device reads it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Slot {
    /// 1..=4. The number FatFs wants in `VolToPart[vol].pt`, and the number the screen
    /// prints, so the partition consent was given for is the partition written.
    pub index: u8,
    /// The filesystem-type byte as it stands now. Reported to the user - "this partition
    /// says it holds exFAT" - and trusted for nothing else: it is one byte somebody else
    /// wrote.
    pub kind: u8,
    pub start_lba: u32,
    pub sectors: u32,
}

impl Slot {
    /// One past the last sector this partition claims. `u64` because a table is free to
    /// claim numbers whose sum a `u32` cannot hold, and that overflow is a case to REPORT
    /// rather than a case to wrap.
    pub fn end_lba(&self) -> u64 {
        u64::from(self.start_lba) + u64::from(self.sectors)
    }
}

/// Why this card must not be formatted here.
///
/// One variant per REMEDY, which is the whole reason they are separate: "there is no
/// partition table" and "there are three partitions" are both refusals, and they send the
/// user to do two different things. A single `Refused` with a string would have collapsed
/// them the way ESP-IDF collapses every `FRESULT` into `ESP_FAIL`, which is the defect
/// this whole module exists to undo.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refusal {
    /// Sector 0 is not a partition table: either it is a filesystem's own boot sector, or
    /// it carries no signature at all.
    NoTable,
    /// Sector 0 is a GPT protective MBR.
    Gpt,
    /// A valid table with no partitions in it.
    NoPartitions,
    /// More than one primary partition.
    Several,
    /// One entry, and it is an extended container: a CHAIN of further partitions this
    /// device does not walk. Separate from [`Refusal::Several`] because the honest
    /// sentence is different - the count is not two, it is unknown, and a refusal that
    /// stated a number here would be the device claiming to know something it does not.
    Extended,
    /// The partition runs past the end of the card, or names no filesystem at all.
    Damaged,
    /// The partition is too small for a filesystem.
    TooSmall,
}

// The SENTENCES for these live in `notyas_ui::FormatRefusal`, not here. What a device says
// about somebody's card is product copy - frozen, asserted by CI, and measured against
// both panels before it ships - and this module's job is the judgement, not the wording.
// `super::format` maps one to the other, in the one place that already depends on both.

/// What sector 0 of a card means for a format.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verdict {
    /// One partition, inside the card, large enough. Writing a filesystem into THIS entry
    /// changes no geometry.
    Format(Slot),
    /// The partition count travels beside the reason so a caller can render the sentence
    /// without walking the table a second time.
    Refuse(Refusal, u8),
}

/// Read the partition table out of sector 0 and decide.
///
/// `card_sectors` is the card's own capacity, taken from its CSD - the one number here
/// that did not come off the medium's CONTENTS, and therefore the only one that can catch
/// a table claiming more card than exists.
///
/// Returns [`Verdict::Refuse`] for anything at all it is not certain about. There is no
/// benefit-of-the-doubt branch: a wrong "yes" costs somebody their only copy of
/// something, and a wrong "no" costs them a sentence telling them to use a computer.
pub fn read_table(sector0: &[u8], card_sectors: u64) -> Verdict {
    if sector0.len() < SECTOR_BYTES {
        return Verdict::Refuse(Refusal::NoTable, 0);
    }
    // The signature is necessary and nowhere near sufficient: a FAT boot sector carries
    // the same two bytes, which is exactly how a superfloppy card gets mistaken for a
    // partitioned one and 64 bytes of its boot code get read as a partition table.
    if !has_signature(sector0) || is_boot_sector(sector0) {
        return Verdict::Refuse(Refusal::NoTable, 0);
    }

    let entries: [Slot; 4] = core::array::from_fn(|i| entry(sector0, i));
    if entries.iter().any(|e| e.kind == TYPE_GPT_PROTECTIVE) {
        return Verdict::Refuse(Refusal::Gpt, 0);
    }

    // "Used" is EITHER field, not both: a type byte with no sectors and sectors with no
    // type byte are each a half-written entry, and counting them as partitions is the
    // direction that refuses. FatFs itself aborts on `pte[PTE_System] == 0`, so an entry
    // like that could not be formatted anyway.
    let used: Vec<Slot> = entries
        .iter()
        .copied()
        .filter(|e| e.kind != 0 || e.sectors != 0)
        .collect();
    let count = used.len() as u8;
    match used.as_slice() {
        [] => Verdict::Refuse(Refusal::NoPartitions, 0),
        // An extended container holds a chain this device does not walk, so how many
        // volumes are on the card is a question it cannot answer.
        [one] if TYPE_EXTENDED.contains(&one.kind) => Verdict::Refuse(Refusal::Extended, 1),
        [one] => {
            if one.kind == 0 || one.sectors == 0 || one.end_lba() > card_sectors {
                Verdict::Refuse(Refusal::Damaged, count)
            } else if one.sectors < MIN_SECTORS {
                Verdict::Refuse(Refusal::TooSmall, count)
            } else {
                Verdict::Format(*one)
            }
        }
        _ => Verdict::Refuse(Refusal::Several, count),
    }
}

/// The two-byte boot signature at the end of the sector.
fn has_signature(s: &[u8]) -> bool {
    s[510] == 0x55 && s[511] == 0xAA
}

/// True if sector 0 is a filesystem's own boot record rather than a partition table.
///
/// Mirrors FatFs's `check_fs` (ff.c), and mirrors it deliberately: the question is "would
/// FatFs mount this sector as a volume", and answering it under different rules than
/// FatFs uses would let the two disagree about the same card.
fn is_boot_sector(s: &[u8]) -> bool {
    // exFAT states itself in the jump instruction and the OEM name. This build's FatFs
    // cannot mount it (`FF_FS_EXFAT` is 0), but it is still a filesystem occupying the
    // whole card with no table above it, which is the case being detected.
    if s[..11] == *b"\xEB\x76\x90EXFAT   " {
        return true;
    }
    // A partition table's first byte is boot code or zero; a FAT VBR's is a jump.
    if !matches!(s[0], 0xEB | 0xE9 | 0xE8) {
        return false;
    }
    if s[82..90] == *b"FAT32   " {
        return true;
    }
    // Early-DOS volumes carry neither signature, so the BPB is judged on its own
    // plausibility - the same properties FatFs checks, in the same order.
    let bytes_per_sector = word(s, 11);
    let sectors_per_cluster = s[13];
    let reserved = word(s, 14);
    let fats = s[16];
    let root_entries = word(s, 17);
    let total16 = word(s, 19);
    let total32 = dword(s, 32);
    let fat_size16 = word(s, 22);
    bytes_per_sector as usize == SECTOR_BYTES
        && sectors_per_cluster != 0
        && sectors_per_cluster.is_power_of_two()
        && reserved != 0
        && (fats == 1 || fats == 2)
        && root_entries != 0
        && (u32::from(total16) >= 4 || total32 >= 0x10000)
        && fat_size16 != 0
}

/// Partition entry `i` (0-based), as bytes on the card.
fn entry(s: &[u8], i: usize) -> Slot {
    let at = TABLE_OFFSET + i * ENTRY_BYTES;
    Slot {
        index: i as u8 + 1,
        kind: s[at + ENTRY_TYPE],
        start_lba: dword(s, at + ENTRY_START),
        sectors: dword(s, at + ENTRY_SECTORS),
    }
}

fn word(s: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([s[at], s[at + 1]])
}

fn dword(s: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([s[at], s[at + 1], s[at + 2], s[at + 3]])
}

/// What a partition-type byte is usually used for, in words rather than in hex.
///
/// Hedged everywhere on purpose: this is one byte somebody else wrote and nothing checks
/// it against the volume's contents. It is on the screen so that the user recognises
/// their own card, not so the device can reason about it - which is why the copy around
/// it says, in the same breath, that the device cannot tell what is on the card.
pub fn kind_label(kind: u8) -> &'static str {
    match kind {
        0x00 => "nothing",
        0x01 => "a FAT12 filesystem",
        0x04 | 0x06 | 0x0E => "a FAT16 filesystem",
        0x0B | 0x0C => "a FAT32 filesystem",
        0x07 => "an exFAT or NTFS filesystem",
        0x83 => "a Linux filesystem",
        0xAF => "a Mac filesystem",
        _ => "an unrecognised filesystem",
    }
}

/// A capacity, split into the number and the unit the card's own label uses.
///
/// Decimal units, and that is the deliberate choice: a card sold as 32 GB reports about
/// 31.9 x 10^9 bytes, and the user is being asked to recognise the card in their hand.
/// Binary units would print "29 GB" on a card whose sticker says 32, which is the one
/// rendering that could make somebody erase the wrong card.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Capacity {
    pub value: u64,
    pub unit: &'static str,
}

impl Capacity {
    /// From a sector count, rounded to the nearest whole unit.
    pub fn of(sectors: u64) -> Capacity {
        const MB: u64 = 1_000_000;
        const GB: u64 = 1_000_000_000;
        // Saturating throughout. A capacity comes from the card's own CSD, which is a
        // value this device did not choose, and a rounding step that panicked on an absurd
        // one would take the whole screen down instead of printing an absurd number.
        let bytes = sectors.saturating_mul(SECTOR_BYTES as u64);
        if bytes >= GB {
            Capacity { value: bytes.saturating_add(GB / 2) / GB, unit: "GB" }
        } else {
            Capacity { value: (bytes + MB / 2) / MB, unit: "MB" }
        }
    }

    /// The word the user types back to consent, which is this capacity with the space
    /// taken out.
    ///
    /// Built from the SAME two fields the label is built from, so the string on the screen
    /// and the string that has to be typed cannot drift apart - which they would the
    /// moment either was a second `format!` somewhere else. Every character is a digit or
    /// an uppercase letter, so it can be typed without leaving the keyboard's letter and
    /// digit pages.
    pub fn word(&self) -> String {
        format!("{}{}", self.value, self.unit)
    }
}

/// "32 GB". The reading form; [`Capacity::word`] is the typing form.
impl fmt::Display for Capacity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.value, self.unit)
    }
}
