// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The gate in front of the only operation this device performs on data it does not own.
//!
//! `firmware/src/sd/probe.rs` decides, from 512 bytes and a capacity, whether the user is
//! offered a button that erases their card. Everything else in that flow - two consent
//! sheets, a typed word, a re-read of the table before the write - is downstream of this
//! answer, so a wrong `Format` here is not caught by any of it.
//!
//! The tests are written as REFUSALS wherever possible, because that is the shape of the
//! rule: exactly one arrangement of sector 0 is formattable and every other arrangement,
//! including every damaged and every ambiguous one, is not. A test suite that only proved
//! the happy path would prove the least important half.

use notyas_firmware_hostcheck::probe::{
    kind_label, read_table, Capacity, Refusal, Verdict, SECTOR_BYTES,
};

/// A 32 GB card, in 512-byte sectors.
const CARD_32GB: u64 = 62_500_000;

/// An MBR with the boot signature and nothing else.
fn blank_mbr() -> [u8; SECTOR_BYTES] {
    let mut s = [0u8; SECTOR_BYTES];
    s[510] = 0x55;
    s[511] = 0xAA;
    s
}

/// Write partition entry `index` (1..=4).
fn put(s: &mut [u8; SECTOR_BYTES], index: usize, kind: u8, start: u32, sectors: u32) {
    let at = 446 + (index - 1) * 16;
    s[at + 4] = kind;
    s[at + 8..at + 12].copy_from_slice(&start.to_le_bytes());
    s[at + 12..at + 16].copy_from_slice(&sectors.to_le_bytes());
}

/// The ordinary case this feature exists for: one factory-shipped SDXC card, exFAT, which
/// this build's FatFs cannot mount.
fn one_exfat_partition() -> [u8; SECTOR_BYTES] {
    let mut s = blank_mbr();
    put(&mut s, 1, 0x07, 8192, 62_490_000);
    s
}

fn refusal(sector: &[u8; SECTOR_BYTES], card: u64) -> Refusal {
    match read_table(sector, card) {
        Verdict::Refuse(why, _) => why,
        Verdict::Format(slot) => panic!("expected a refusal, got a plan to format {slot:?}"),
    }
}

// ---------------------------------------------------------------------------------------
// The one card that may be formatted
// ---------------------------------------------------------------------------------------

/// The single accepted shape, and it is accepted with the geometry ALREADY ON THE CARD.
///
/// The start sector and the length are what `f_mkfs` is told to build inside, so a bug
/// that returned anything else here would move somebody's partition while claiming not to.
#[test]
fn one_partition_inside_the_card_is_formattable_where_it_already_is() {
    match read_table(&one_exfat_partition(), CARD_32GB) {
        Verdict::Format(slot) => {
            assert_eq!(slot.index, 1, "the partition index f_mkfs is given");
            assert_eq!(slot.start_lba, 8192, "the start sector must be the card's own");
            assert_eq!(slot.sectors, 62_490_000, "and so must the length");
            assert_eq!(slot.kind, 0x07, "the type byte is reported, never invented");
        }
        Verdict::Refuse(why, n) => panic!("a plain exFAT card must be formattable: {why:?} {n}"),
    }
}

/// The partition need not be the first entry, and the index reported has to be the one it
/// actually occupies: `f_mkfs` addresses partitions by that number, so an off-by-one here
/// formats a different partition than the screen named.
#[test]
fn the_partition_index_is_the_entry_it_occupies() {
    for index in 1..=4usize {
        let mut s = blank_mbr();
        put(&mut s, index, 0x0C, 2048, 1_000_000);
        match read_table(&s, CARD_32GB) {
            Verdict::Format(slot) => assert_eq!(slot.index, index as u8),
            Verdict::Refuse(why, _) => panic!("entry {index}: {why:?}"),
        }
    }
}

/// A card that already holds FAT is still formattable BY THIS FUNCTION. That is correct
/// and deliberate: this module answers "would writing a filesystem here be safe and
/// well-defined", not "should it be offered". Whether the card is readable at all is
/// answered one level up, by trying to mount it, and a card that mounts never reaches
/// here. Splitting the two is what lets each be checked on its own.
#[test]
fn a_fat_partition_is_a_well_defined_target_too() {
    let mut s = blank_mbr();
    put(&mut s, 1, 0x0C, 2048, 62_490_000);
    assert!(matches!(read_table(&s, CARD_32GB), Verdict::Format(_)));
}

// ---------------------------------------------------------------------------------------
// Refusals: no partition table
// ---------------------------------------------------------------------------------------

/// The requirement stated plainly: a card with no partition table is REFUSED, never
/// repaired by inventing one.
#[test]
fn a_sector_with_no_signature_is_not_a_partition_table() {
    assert_eq!(refusal(&[0u8; SECTOR_BYTES], CARD_32GB), Refusal::NoTable);
}

/// The trap this check exists for. A FAT volume written directly to LBA 0 - a
/// "superfloppy", which is how some cameras and some card readers format - carries the
/// SAME 0x55AA signature an MBR does. Reading its boot code as a partition table produces
/// four entries of nonsense, and one of them can look formattable.
#[test]
fn a_filesystem_at_lba_zero_is_not_a_partition_table() {
    // A FAT16 VBR: jump, an OEM name, and a BPB that passes FatFs's own plausibility
    // check - which is exactly what makes it dangerous to treat as a table.
    let mut s = blank_mbr();
    s[0] = 0xEB;
    s[1] = 0x3C;
    s[2] = 0x90;
    s[11..13].copy_from_slice(&512u16.to_le_bytes()); // bytes per sector
    s[13] = 64; // sectors per cluster
    s[14..16].copy_from_slice(&1u16.to_le_bytes()); // reserved sectors
    s[16] = 2; // FATs
    s[17..19].copy_from_slice(&512u16.to_le_bytes()); // root entries
    s[19..21].copy_from_slice(&0u16.to_le_bytes()); // total sectors (16-bit)
    s[22..24].copy_from_slice(&244u16.to_le_bytes()); // FAT size
    s[32..36].copy_from_slice(&1_000_000u32.to_le_bytes()); // total sectors (32-bit)
    // Boot code where the partition table would be, plausible enough to parse as one.
    put(&mut s, 1, 0x0C, 2048, 900_000);
    assert_eq!(
        refusal(&s, CARD_32GB),
        Refusal::NoTable,
        "a volume boot record must never be read as a partition table"
    );
}

/// The same, for a whole-card exFAT volume, which is what a 64 GB+ card looks like when
/// somebody formats it without a table.
#[test]
fn an_exfat_volume_at_lba_zero_is_not_a_partition_table() {
    let mut s = blank_mbr();
    s[..11].copy_from_slice(b"\xEB\x76\x90EXFAT   ");
    put(&mut s, 1, 0x07, 2048, 900_000);
    assert_eq!(refusal(&s, CARD_32GB), Refusal::NoTable);
}

/// A FAT32 VBR states itself in its filesystem-type field rather than in its BPB.
#[test]
fn a_fat32_volume_at_lba_zero_is_not_a_partition_table() {
    let mut s = blank_mbr();
    s[0] = 0xE9;
    s[82..90].copy_from_slice(b"FAT32   ");
    put(&mut s, 1, 0x0C, 2048, 900_000);
    assert_eq!(refusal(&s, CARD_32GB), Refusal::NoTable);
}

/// An MBR's first byte is boot code or zero, never a jump. A table whose boot code happens
/// to start with a jump but whose BPB is nonsense is still a table, and must not be
/// mistaken for a filesystem - the check has to be wrong in neither direction.
#[test]
fn a_table_whose_boot_code_starts_with_a_jump_is_still_a_table() {
    let mut s = one_exfat_partition();
    s[0] = 0xEB;
    assert!(
        matches!(read_table(&s, CARD_32GB), Verdict::Format(_)),
        "an implausible BPB behind a jump byte is boot code, not a filesystem"
    );
}

// ---------------------------------------------------------------------------------------
// Refusals: tables this device will not choose within, or trust
// ---------------------------------------------------------------------------------------

/// A GPT card. This build's FatFs has `FF_LBA64` at 0 and cannot address a GPT volume at
/// all, so formatting one repairs nothing even if it succeeds.
#[test]
fn a_gpt_protective_mbr_is_refused() {
    let mut s = blank_mbr();
    put(&mut s, 1, 0xEE, 1, 0xFFFF_FFFF);
    assert_eq!(refusal(&s, CARD_32GB), Refusal::Gpt);
}

/// ...including where the protective entry is not the first one, which is unusual but
/// legal, and where a formattable-looking entry sits beside it. The GPT check has to run
/// before the counting, or this card gets offered as "two partitions" or worse.
#[test]
fn a_gpt_entry_anywhere_in_the_table_is_refused() {
    let mut s = blank_mbr();
    put(&mut s, 1, 0x0C, 2048, 900_000);
    put(&mut s, 4, 0xEE, 1, 0xFFFF_FFFF);
    assert_eq!(refusal(&s, CARD_32GB), Refusal::Gpt);
}

/// An empty table. This device formats a partition that exists and never creates one, so
/// there is nothing here for it to write into.
#[test]
fn an_empty_table_is_refused() {
    assert_eq!(refusal(&blank_mbr(), CARD_32GB), Refusal::NoPartitions);
}

/// Two partitions: the device does not get to choose which of somebody's volumes to
/// destroy. This is the case a Raspberry Pi card is in, and it is a card whose owner would
/// be very surprised to lose it.
#[test]
fn two_partitions_are_refused_and_the_count_is_reported() {
    let mut s = blank_mbr();
    put(&mut s, 1, 0x0C, 8192, 500_000);
    put(&mut s, 2, 0x83, 600_000, 1_000_000);
    match read_table(&s, CARD_32GB) {
        Verdict::Refuse(Refusal::Several, n) => assert_eq!(n, 2, "the sentence states the count"),
        other => panic!("{other:?}"),
    }
}

/// An extended container is a CHAIN of further partitions this device does not walk, so a
/// card carrying one holds an unknown number of volumes even though the table shows one
/// entry. Counting it as a single formattable partition would erase all of them.
#[test]
fn an_extended_container_is_refused_even_when_it_is_the_only_entry() {
    for kind in [0x05u8, 0x0F, 0x85] {
        let mut s = blank_mbr();
        put(&mut s, 1, kind, 2048, 62_490_000);
        assert_eq!(
            refusal(&s, CARD_32GB),
            Refusal::Extended,
            "an extended container (0x{kind:02x}) hides an unknown number of volumes"
        );
    }
}

/// A half-written entry - a type byte with no length, or a length with no type - counts as
/// a partition rather than as empty space. Counting the other way would let a damaged
/// table look like a clean single-partition card.
#[test]
fn a_half_written_entry_counts_as_a_partition() {
    let mut s = blank_mbr();
    put(&mut s, 1, 0x0C, 8192, 500_000);
    put(&mut s, 2, 0x83, 0, 0); // a type with no extent
    assert_eq!(refusal(&s, CARD_32GB), Refusal::Several);

    let mut s = blank_mbr();
    put(&mut s, 1, 0x0C, 8192, 500_000);
    put(&mut s, 2, 0x00, 600_000, 1_000); // an extent with no type
    assert_eq!(refusal(&s, CARD_32GB), Refusal::Several);
}

// ---------------------------------------------------------------------------------------
// Refusals: tables that do not describe this card
// ---------------------------------------------------------------------------------------

/// A table claiming more card than exists is damaged. Writing on the strength of it is
/// how data that a recovery tool could still have read stops being readable.
#[test]
fn a_partition_that_runs_past_the_end_of_the_card_is_refused() {
    let mut s = blank_mbr();
    put(&mut s, 1, 0x0C, 2048, u32::MAX);
    assert_eq!(refusal(&s, CARD_32GB), Refusal::Damaged);
}

/// The arithmetic must not wrap. `start + sectors` overflows a `u32` here, and a
/// 32-bit sum would come out small and INSIDE the card - the one bug in this file that
/// would turn a refusal into a format.
#[test]
fn a_partition_whose_extent_overflows_thirty_two_bits_is_refused() {
    let mut s = blank_mbr();
    put(&mut s, 1, 0x0C, 0xFFFF_F000, 0x0000_2000);
    assert_eq!(
        refusal(&s, CARD_32GB),
        Refusal::Damaged,
        "start + length must be computed in 64 bits"
    );
}

/// A partition too small for FatFs to build anything in. Refused here, with a sentence,
/// rather than inside `f_mkfs`, which aborts part-way through after the driver is up.
#[test]
fn a_partition_too_small_for_a_filesystem_is_refused() {
    let mut s = blank_mbr();
    put(&mut s, 1, 0x0C, 2048, 8);
    assert_eq!(refusal(&s, CARD_32GB), Refusal::TooSmall);
}

/// A short read is not a partition table. The caller hands 512 bytes, but the check is
/// here rather than in a `debug_assert`: the alternative is indexing past the end of a
/// buffer while deciding whether to erase a card.
#[test]
fn a_short_sector_is_refused_rather_than_indexed_past() {
    assert_eq!(refusal_of_slice(&[0u8; 64]), Refusal::NoTable);
    assert_eq!(refusal_of_slice(&[]), Refusal::NoTable);
}

fn refusal_of_slice(s: &[u8]) -> Refusal {
    match read_table(s, CARD_32GB) {
        Verdict::Refuse(why, _) => why,
        Verdict::Format(slot) => panic!("expected a refusal, got {slot:?}"),
    }
}

// ---------------------------------------------------------------------------------------
// What the user reads
// ---------------------------------------------------------------------------------------

/// The typed word and the label on the screen are the SAME two fields rendered twice.
///
/// This is what the whole consent gate rests on: the user reads "32 GB card" off the panel
/// and types "32GB". If those could ever disagree, the sheet would be asking for a word
/// that is not on the screen, and the only way through it would be to guess.
#[test]
fn the_word_and_the_label_cannot_disagree() {
    for sectors in [1u64, 1_000, 62_500_000, 125_000_000, 250_000_000] {
        let c = Capacity::of(sectors);
        assert_eq!(c.word(), c.to_string().replace(' ', ""));
        assert!(
            c.word().chars().all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit()),
            "{} must be typable without leaving the letter and digit pages",
            c.word()
        );
    }
}

/// Decimal units, because the user is being asked to recognise the card in their hand and
/// the card's own sticker is decimal. Binary units would print "29 GB" on a card sold as
/// 32 GB, which is the one rendering that could make somebody erase the wrong card.
#[test]
fn a_capacity_reads_the_way_the_card_is_labelled() {
    assert_eq!(Capacity::of(62_500_000).to_string(), "32 GB");
    assert_eq!(Capacity::of(124_735_488).to_string(), "64 GB");
    assert_eq!(Capacity::of(3_842_048).to_string(), "2 GB");
    assert_eq!(Capacity::of(1_000_000).to_string(), "512 MB");
    // No panic and no wrap at the edges of the type.
    assert_eq!(Capacity::of(0).to_string(), "0 MB");
    assert!(Capacity::of(u64::MAX).value > 0);
}

/// The type byte is described in words, hedged, and never as a claim about the CONTENTS.
/// It is one byte somebody else wrote; it is on the screen so the user recognises their
/// own card, and for nothing else.
#[test]
fn a_partition_type_is_described_and_never_asserted() {
    assert_eq!(kind_label(0x07), "an exFAT or NTFS filesystem");
    assert_eq!(kind_label(0x0C), "a FAT32 filesystem");
    assert_eq!(kind_label(0x83), "a Linux filesystem");
    assert_eq!(kind_label(0x42), "an unrecognised filesystem");
    // Every byte renders, so no card can produce a blank line where a description belongs.
    for kind in 0..=u8::MAX {
        assert!(!kind_label(kind).is_empty());
    }
}
