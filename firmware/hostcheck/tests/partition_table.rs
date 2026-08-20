// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! `firmware/partitions.csv` as a tested artifact rather than a reviewed one.
//!
//! The table is flashed verbatim by `tools/flash.ps1`, so nothing in the build ever
//! type-checks it, and the failures it can cause are the expensive kind: a moved offset
//! destroys every sealed record on the devices that already have one, an overlap corrupts
//! two regions at once, and a region that does not fit the smaller board bricks one of the
//! two boards this firmware ships for.
//!
//! What is asserted here is exactly what the design rests on and nothing decorative:
//! the frozen offsets, that no two regions overlap, the alignments ESP-IDF requires, the
//! fit at BOTH flash sizes, and that the `settings` region matches the format the sealing
//! crate defines for it. The comments say why each one matters, because a bare number
//! would just be re-derived by whoever next wants to move something.

use std::fs;
use std::path::PathBuf;

/// Both boards this firmware ships for, and the rule from `docs/BOARDS.md`: one shared
/// table, sized within the SMALLER part. The larger board's extra flash is unusable by
/// construction, which is a decision and not an oversight.
const FLASH_SIZES: [(u32, &str); 2] = [(16 * 1024 * 1024, "Elecrow-5, 16 MB"), (32 * 1024 * 1024, "Waveshare-4b, 32 MB")];

#[derive(Debug, Clone, PartialEq, Eq)]
struct Row {
    name: String,
    kind: String,
    subtype: String,
    offset: u32,
    size: u32,
    encrypted: bool,
}

impl Row {
    fn end(&self) -> u32 {
        self.offset + self.size
    }
}

fn table() -> Vec<Row> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../partitions.csv");
    let text = fs::read_to_string(&path).expect("firmware/partitions.csv is readable");
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let f: Vec<&str> = l.split(',').map(str::trim).collect();
            assert!(f.len() >= 5, "malformed row: {l}");
            Row {
                name: f[0].to_string(),
                kind: f[1].to_string(),
                subtype: f[2].to_string(),
                offset: number(f[3]),
                size: number(f[4]),
                encrypted: f.get(5).is_some_and(|flags| flags.contains("encrypted")),
            }
        })
        .collect()
}

fn number(raw: &str) -> u32 {
    if let Some(hex) = raw.strip_prefix("0x") {
        return u32::from_str_radix(hex, 16).expect("hex");
    }
    if let Some(k) = raw.strip_suffix('K') {
        return k.parse::<u32>().expect("K size") * 1024;
    }
    if let Some(m) = raw.strip_suffix('M') {
        return m.parse::<u32>().expect("M size") * 1024 * 1024;
    }
    raw.parse().expect("decimal size")
}

/// The offsets, spelled out. Not a restatement of the file for its own sake: three of
/// these four have been on a user's device, every superblock records the geometry it was
/// formatted against, and a mismatch is a hard mount refusal - so moving one of them is
/// data loss, not a repartition. This test is where that becomes a red build instead of a
/// support ticket.
#[test]
fn the_frozen_offsets_have_not_moved() {
    let rows = table();
    let want = [
        ("factory", 0x0001_0000u32, 4 * 1024 * 1024u32, false),
        ("wallets", 0x0041_0000, 256 * 1024, true),
        ("counters", 0x0045_0000, 16 * 1024, false),
        ("settings", 0x0046_0000, 64 * 1024, false),
    ];
    assert_eq!(rows.len(), want.len(), "row count changed: {rows:#?}");
    for (row, (name, offset, size, encrypted)) in rows.iter().zip(want) {
        assert_eq!(row.name, name);
        assert_eq!(row.offset, offset, "{name} moved");
        assert_eq!(row.size, size, "{name} resized");
        assert_eq!(row.encrypted, encrypted, "{name} encrypted flag");
    }
}

/// Ascending and non-overlapping. An overlap is not caught by espflash for every case and
/// would be discovered as two regions corrupting each other on a live device.
#[test]
fn no_two_regions_overlap() {
    let rows = table();
    for pair in rows.windows(2) {
        let (a, b) = (&pair[0], &pair[1]);
        assert!(
            b.offset >= a.end(),
            "{} (ends 0x{:X}) overlaps {} (starts 0x{:X})",
            a.name,
            a.end(),
            b.name,
            b.offset
        );
    }
    // Everything is above the app offset's own floor: the partition table lives at 0x8000
    // and ESP-IDF requires no partition below table_offset + 0x1000. The 0.3.0 bootloader
    // move to 0xC000 raises that floor to 0xD000, which every row here still clears.
    assert!(rows.iter().all(|r| r.offset >= 0x1_0000), "{rows:#?}");
}

/// The alignments ESP-IDF actually enforces: 64 KiB for an app partition (and for anything
/// that may become one), 4 KiB for data. The `settings` region is placed so that the NEXT
/// free offset is 64 KiB aligned too, which is what lets 0.3.0's `otadata` and second app
/// slot be appended without moving a byte of what has shipped (SECUREBOOT.md 7, 8.2).
#[test]
fn the_alignments_hold_and_the_tail_stays_appendable() {
    let rows = table();
    for r in &rows {
        let align = if r.kind == "app" { 0x1_0000 } else { 0x1000 };
        assert_eq!(r.offset % align, 0, "{} is not {align:#x}-aligned", r.name);
        assert_eq!(r.size % 0x1000, 0, "{} is not a whole number of sectors", r.name);
    }
    let end = rows.last().expect("a non-empty table").end();
    assert_eq!(
        end % 0x1_0000,
        0,
        "the table must END 64 KiB-aligned so the next region can be APPENDED; \
         it ends at 0x{end:X}"
    );
}

/// The shared-table rule: one CSV, sized within the smaller board. Checked at both sizes
/// because "it fits" is a different statement on each, and the 32 MB board's extra space
/// is deliberately unusable rather than accidentally unused.
#[test]
fn the_table_fits_both_boards() {
    let end = table().last().expect("a non-empty table").end();
    for (size, board) in FLASH_SIZES {
        assert!(end <= size, "the table ends past the end of flash on {board}");
        let free = size - end;
        assert!(
            free > 8 * 1024 * 1024,
            "{board} has only {free} bytes free, which is not the headroom this design \
             assumed when it chose to append rather than insert"
        );
    }
}

/// The `settings` region against the format that reads it. Two slots is the floor - a
/// single-slot region would make every save a window in which the only copy on the device
/// is half-written - and the rest of the sectors are the reserve that lets a 0.3.0 format
/// revision happen with no table change at all.
#[test]
fn the_settings_region_matches_the_format_that_reads_it() {
    use notyas_wallet::settings::{SECTOR_BYTES, SLOTS};

    let settings = table()
        .into_iter()
        .find(|r| r.name == "settings")
        .expect("the settings region");
    assert_eq!(settings.size % SECTOR_BYTES, 0);
    let sectors = settings.size / SECTOR_BYTES;
    assert!(sectors >= SLOTS, "{sectors} sectors cannot hold {SLOTS} slots");
    assert_eq!(sectors, 16, "the reserve is 14 sectors beyond the two slots");
    // It must NOT be encrypted. The region is read before any PIN exists, so a key-bearing
    // region could not answer at the one moment it is asked; and XTS's write-once per
    // 16-byte cipher block is the wrong physics for a record rewritten on every Save.
    assert!(!settings.encrypted, "the settings region must be plaintext");
    // Label, not subtype, is the identity - all three data regions carry `undefined`
    // because esp-idf-part 0.6 panics on a numeric user-range data subtype.
    assert_eq!(settings.subtype, "undefined");
}
