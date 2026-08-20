// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The settings region, fed everything a power cut and a hostile programmer can produce.
//!
//! The firmware cannot be host-tested, so the whole of the settings logic lives in
//! `notyas_wallet::settings` and the firmware's backend is four `esp_partition_*` calls.
//! This file is what that arrangement buys: the parser a torn write reaches, exercised on
//! a host at every cut position, plus the images no writer of ours would ever produce -
//! all-`0xff`, all-`0x00`, truncated, bit-flipped, and a record carrying a name the
//! keyboard could not have typed.
//!
//! The rule every test below is a restatement of: **the reader returns a record the writer
//! completed, or it returns the defaults. It never returns anything else.**

use std::cell::RefCell;
use std::rc::Rc;

use notyas_wallet::settings::{Network, Settings, SettingsFlash, SettingsRegion, SECTOR_BYTES};

const REGION_SECTORS: usize = 16;

/// The image and the power supply, shared between the test and the backend the region
/// owns, so the test can cut the power mid-save and read the damage afterwards without the
/// library growing a test-only accessor.
#[derive(Debug)]
struct Image {
    data: Vec<u8>,
    /// Bytes of effect the region is still allowed to have. `None` is a healthy supply.
    /// This is what makes the harness a power-loss harness rather than a mock: when it
    /// runs out mid-erase or mid-program the operation stops exactly there and reports a
    /// failure, which is what a flash chip losing its supply actually leaves behind - a
    /// half-erased sector or a half-programmed page, never a clean rollback.
    budget: Option<usize>,
}

#[derive(Clone, Debug)]
struct Bench(Rc<RefCell<Image>>);

/// The backend as the region sees it: a handle onto the shared image, and nothing else.
#[derive(Debug)]
struct MemFlash(Bench);

#[derive(Debug, PartialEq, Eq)]
struct Cut;

impl Bench {
    fn blank() -> Bench {
        Bench::of(vec![0xff; REGION_SECTORS * SECTOR_BYTES as usize])
    }

    /// The state a factory-fresh part is NOT in, and one a programmer can leave for free.
    fn zeroed() -> Bench {
        Bench::of(vec![0x00; REGION_SECTORS * SECTOR_BYTES as usize])
    }

    fn of(data: Vec<u8>) -> Bench {
        Bench(Rc::new(RefCell::new(Image { data, budget: None })))
    }

    fn region(&self) -> SettingsRegion<MemFlash> {
        SettingsRegion::open(MemFlash(self.clone())).expect("16 sectors is two slots and a tail")
    }

    /// Cut the power after `bytes` more bytes of effect.
    fn cut_after(&self, bytes: usize) {
        self.0.borrow_mut().budget = Some(bytes);
    }

    fn restore_power(&self) {
        self.0.borrow_mut().budget = None;
    }

    fn bytes(&self) -> Vec<u8> {
        self.0.borrow().data.clone()
    }

    fn settings(&self) -> Settings {
        self.region().load().expect("a read never fails on a live supply")
    }
}

impl SettingsFlash for MemFlash {
    type Error = Cut;

    fn sectors(&self) -> u32 {
        self.0 .0.borrow().data.len() as u32 / SECTOR_BYTES
    }

    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), Cut> {
        let image = self.0 .0.borrow();
        let at = offset as usize;
        buf.copy_from_slice(&image.data[at..at + buf.len()]);
        Ok(())
    }

    /// NOR programming: a write clears bits and never sets them. Modelled honestly, so a
    /// write into an un-erased slot cannot silently produce a clean record.
    fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), Cut> {
        let mut image = self.0 .0.borrow_mut();
        let allowed = spend(&mut image, data.len());
        let at = offset as usize;
        for (i, b) in data.iter().enumerate().take(allowed) {
            image.data[at + i] &= *b;
        }
        if allowed < data.len() {
            return Err(Cut);
        }
        Ok(())
    }

    fn erase_sector(&mut self, sector: u32) -> Result<(), Cut> {
        let mut image = self.0 .0.borrow_mut();
        let len = SECTOR_BYTES as usize;
        let allowed = spend(&mut image, len);
        let at = sector as usize * SECTOR_BYTES as usize;
        for b in image.data[at..at + allowed].iter_mut() {
            *b = 0xff;
        }
        if allowed < len {
            return Err(Cut);
        }
        Ok(())
    }
}

fn spend(image: &mut Image, want: usize) -> usize {
    match &mut image.budget {
        None => want,
        Some(left) => {
            let take = want.min(*left);
            *left -= take;
            take
        }
    }
}

fn named(name: &str, network: Network) -> Settings {
    let mut s = Settings::new();
    s.set_device_name(name).expect("the test's own name is legal");
    s.set_network(network);
    s
}

// --- the three states a device can be in without ever having saved -------------------

#[test]
fn a_blank_region_is_the_defaults_and_not_an_error() {
    let s = Bench::blank().settings();
    assert_eq!(s, Settings::new());
    assert_eq!(s.device_name(), "");
    assert_eq!(s.network(), Network::Mainnet);
}

/// All zeros is not a state our writer produces, which is exactly why it is worth a test:
/// it is what a programmer, a failed bulk erase or a mis-flashed image leaves behind, and
/// the magic check is what has to catch it.
#[test]
fn an_all_zero_region_is_the_defaults_and_not_an_error() {
    assert_eq!(Bench::zeroed().settings(), Settings::new());
}

#[test]
fn a_region_smaller_than_two_slots_is_refused_rather_than_run_single_copy() {
    let bench = Bench::of(vec![0xff; SECTOR_BYTES as usize]);
    assert!(SettingsRegion::open(MemFlash(bench)).is_err());
}

// --- the ordinary life of the region --------------------------------------------------

#[test]
fn a_saved_name_reads_back() {
    let bench = Bench::blank();
    let want = named("kitchen-desk", Network::Testnet);
    bench.region().save(&want).unwrap();
    assert_eq!(bench.settings(), want);
}

#[test]
fn an_empty_name_is_a_state_and_not_an_absence_of_one() {
    let bench = Bench::blank();
    bench.region().save(&named("kitchen-desk", Network::Mainnet)).unwrap();
    let mut cleared = Settings::new();
    cleared.set_device_name("").unwrap();
    bench.region().save(&cleared).unwrap();
    assert_eq!(bench.settings().device_name(), "");
}

/// Wear is the reason the sides alternate, and a reader that took the wrong side would
/// pass every single-save test above.
#[test]
fn saves_alternate_sides_and_the_newest_always_wins() {
    let bench = Bench::blank();
    let mut region = bench.region();
    for i in 0..25u32 {
        let want = named(&format!("bench-{i}"), Network::Mainnet);
        region.save(&want).unwrap();
        assert_eq!(region.load().unwrap(), want, "after save {i}");
    }
    // Both slots hold a record, so every save after the first has had a complete previous
    // copy standing beside it.
    let data = bench.bytes();
    let b = SECTOR_BYTES as usize;
    assert_ne!(&data[0..8], &[0xff; 8], "slot A was never written");
    assert_ne!(&data[b..b + 8], &[0xff; 8], "slot B was never written");
}

#[test]
fn the_reserved_sectors_are_never_touched() {
    let bench = Bench::blank();
    let mut region = bench.region();
    for i in 0..8u32 {
        region.save(&named(&format!("n{i}"), Network::Testnet)).unwrap();
    }
    let data = bench.bytes();
    let tail = 2 * SECTOR_BYTES as usize;
    assert!(
        data[tail..].iter().all(|b| *b == 0xff),
        "sectors 2-15 are the 0.3.0 reserve and this module must not write there"
    );
}

#[test]
fn clear_returns_the_region_to_the_defaults() {
    let bench = Bench::blank();
    let mut region = bench.region();
    region.save(&named("kitchen-desk", Network::Testnet)).unwrap();
    region.save(&named("kitchen-desk-2", Network::Testnet)).unwrap();
    region.clear().unwrap();
    assert_eq!(region.load().unwrap(), Settings::new());
    assert_eq!(bench.settings(), Settings::new());
}

// --- torn writes ----------------------------------------------------------------------

/// The gate. A cut at EVERY byte of the save - anywhere in the erase, anywhere in the
/// payload program, anywhere in the header page - must leave the reader with the record
/// that was there before, or (for the very first save a device ever makes) the defaults.
///
/// Byte granularity rather than step granularity on purpose: a header page torn halfway
/// through is the one state that could plausibly promote a stale sequence number onto a
/// fresh payload, and only a byte-level cut produces it.
#[test]
fn no_cut_anywhere_in_a_save_can_produce_a_readable_wrong_record() {
    let first = named("first-name", Network::Mainnet);
    let second = named("second-name-longer", Network::Testnet);

    // A save costs one 4096-byte erase, the padded payload, and the 64-byte header page.
    let span = SECTOR_BYTES as usize + 64 + 64;
    for cut in 0..span {
        // Case 1: the cut lands on the device's FIRST ever save. There is no previous
        // record, so the only acceptable outcomes are the defaults or the new record.
        let bench = Bench::blank();
        bench.cut_after(cut);
        let _ = bench.region().save(&first);
        bench.restore_power();
        let got = bench.settings();
        assert!(
            got == Settings::new() || got == first,
            "cut {cut} on the first save produced {got:?}"
        );

        // Case 2: the cut lands on a REWRITE. The previous record must survive intact -
        // this is the case a user actually experiences, and the one the winner-untouched
        // rule exists for.
        let bench = Bench::blank();
        bench.region().save(&first).unwrap();
        bench.cut_after(cut);
        let _ = bench.region().save(&second);
        bench.restore_power();
        let got = bench.settings();
        assert!(
            got == first || got == second,
            "cut {cut} on a rewrite produced {got:?}, which is neither record"
        );
    }
}

/// Repeated brownouts: a device that keeps losing power part-way through a save must not
/// converge on a pair of unreadable slots, and must still accept a save afterwards.
#[test]
fn repeated_cuts_leave_the_region_readable_and_writable() {
    let a = named("alpha", Network::Mainnet);
    let b = named("bravo", Network::Testnet);
    for cut in (0..SECTOR_BYTES as usize + 200).step_by(37) {
        let bench = Bench::blank();
        bench.region().save(&a).unwrap();
        bench.cut_after(cut);
        let _ = bench.region().save(&b);
        let _ = bench.region().save(&b);
        bench.restore_power();
        let got = bench.settings();
        assert!(got == a || got == b, "cut {cut} produced {got:?}");
        bench.region().save(&b).unwrap();
        assert_eq!(bench.settings(), b, "cut {cut} left the region unwritable");
    }
}

// --- hostile and damaged images -------------------------------------------------------

/// Single-bit corruption of the only record on the device. Every flip must be caught: the
/// device falls back to the defaults rather than drawing a name nobody typed.
#[test]
fn any_single_bit_flip_in_the_only_record_falls_back_to_the_defaults() {
    let want = named("kitchen-desk", Network::Testnet);
    let bench = Bench::blank();
    bench.region().save(&want).unwrap();
    let good = bench.bytes();

    // The header page plus the payload it describes: every byte the record occupies, read
    // from the header rather than guessed, so the sweep cannot silently stop short.
    let payload_len =
        u32::from_le_bytes([good[12], good[13], good[14], good[15]]) as usize;
    let record_span = 64 + payload_len;
    for byte in 0..record_span {
        for bit in 0..8u8 {
            let mut data = good.clone();
            data[byte] ^= 1 << bit;
            let got = Bench::of(data).settings();
            assert_eq!(
                got,
                Settings::new(),
                "byte {byte} bit {bit} was corrupted and still read as a record"
            );
        }
    }

    // The bytes just past the record are the program-granularity pad. They are outside
    // `payload_len` and covered by no CRC, so damage there must NOT invalidate the record:
    // that is the difference between a checksum over the record and a checksum over the
    // slot, and it is deliberate.
    let mut data = good.clone();
    data[record_span] ^= 0x01;
    assert_eq!(Bench::of(data).settings(), want);
}

/// A corrupt NEW record must not beat an intact old one: the election runs on validity
/// first and sequence second.
#[test]
fn a_corrupt_higher_sequence_slot_loses_to_an_intact_lower_one() {
    let old = named("old-name", Network::Mainnet);
    let new = named("new-name", Network::Testnet);
    let bench = Bench::blank();
    let mut region = bench.region();
    region.save(&old).unwrap();
    region.save(&new).unwrap();
    let mut data = bench.bytes();
    // Slot B holds the newer record (the second save alternates onto it). Break its CRC.
    let b = SECTOR_BYTES as usize;
    data[b + 16] ^= 0x01;
    assert_eq!(
        Bench::of(data).settings(),
        old,
        "the intact older record is what the device must show"
    );
}

/// The reason the name alphabet is re-checked on READ. These records are internally
/// perfect - right magic, right length, right CRC - and carry names the on-screen keyboard
/// cannot produce. They must be rejected, not drawn.
#[test]
fn a_valid_record_carrying_an_illegal_name_is_rejected() {
    for smuggled in ["kitchen\ndesk", "kitchen/desk", "  padded", "caf\u{e9}", ""] {
        let payload = name_payload(smuggled.as_bytes());
        let got = Bench::of(image(1, &payload)).settings();
        assert_eq!(got, Settings::new(), "{smuggled:?} reached the lock screen");
    }
}

#[test]
fn a_length_that_runs_past_the_payload_is_rejected() {
    // A name TLV claiming 300 bytes inside a 10-byte payload.
    let mut payload = vec![0x01u8];
    payload.extend_from_slice(&300u16.to_le_bytes());
    payload.extend_from_slice(b"kitchen");
    assert_eq!(Bench::of(image(1, &payload)).settings(), Settings::new());
}

#[test]
fn a_payload_length_larger_than_a_slot_is_rejected() {
    let mut data = image(1, &name_payload(b"kitchen"));
    data[12..16].copy_from_slice(&5000u32.to_le_bytes());
    assert_eq!(Bench::of(data).settings(), Settings::new());
}

#[test]
fn a_zero_length_payload_is_rejected() {
    let mut data = image(1, &name_payload(b"kitchen"));
    data[12..16].copy_from_slice(&0u32.to_le_bytes());
    assert_eq!(Bench::of(data).settings(), Settings::new());
}

#[test]
fn a_nonzero_reserved_header_byte_is_rejected() {
    let mut data = image(1, &name_payload(b"kitchen"));
    data[63] = 0x01;
    assert_eq!(Bench::of(data).settings(), Settings::new());
}

#[test]
fn a_truncated_record_is_rejected() {
    let payload = name_payload(b"kitchen-desk");
    let mut data = image(1, &payload);
    // The payload's last four bytes never made it to flash.
    let end = 64 + payload.len();
    data[end - 4..end].copy_from_slice(&[0xff; 4]);
    assert_eq!(Bench::of(data).settings(), Settings::new());
}

#[test]
fn a_record_with_an_erased_or_zero_sequence_number_is_rejected() {
    let payload = name_payload(b"kitchen");
    for seq in [0u32, u32::MAX] {
        // The CRC is recomputed for that sequence number, so the sequence number is the
        // ONLY thing wrong with the record.
        let data = image(seq, &payload);
        assert_eq!(
            Bench::of(data).settings(),
            Settings::new(),
            "seq {seq:#x} was accepted"
        );
    }
}

#[test]
fn a_wrong_magic_is_rejected_even_when_everything_else_is_perfect() {
    let mut data = image(1, &name_payload(b"kitchen"));
    data[0..8].copy_from_slice(b"NYSETT2\0");
    assert_eq!(Bench::of(data).settings(), Settings::new());
}

/// Forward compatibility, which is the whole reason each entry carries its length: a tag a
/// 0.3.0 firmware writes must be stepped over by this one, with the values it does know
/// still read.
#[test]
fn an_unknown_tag_is_skipped_and_the_known_values_survive() {
    let mut payload = vec![0x7fu8];
    payload.extend_from_slice(&5u16.to_le_bytes());
    payload.extend_from_slice(b"hello");
    payload.extend_from_slice(&name_payload(b"kitchen-desk"));
    payload.push(0x02);
    payload.extend_from_slice(&1u16.to_le_bytes());
    payload.push(1);
    let got = Bench::of(image(1, &payload)).settings();
    assert_eq!(got.device_name(), "kitchen-desk");
    assert_eq!(got.network(), Network::Testnet);
}

#[test]
fn a_repeated_tag_is_rejected() {
    let mut payload = name_payload(b"one");
    payload.extend_from_slice(&name_payload(b"two"));
    assert_eq!(Bench::of(image(1, &payload)).settings(), Settings::new());
}

/// An undefined network byte cannot land the device on a chain the user did not choose:
/// the record is rejected whole and the default is mainnet.
#[test]
fn an_undefined_network_byte_is_rejected() {
    let mut payload = name_payload(b"kitchen");
    payload.push(0x02);
    payload.extend_from_slice(&1u16.to_le_bytes());
    payload.push(9);
    let got = Bench::of(image(1, &payload)).settings();
    assert_eq!(got, Settings::new());
    assert_eq!(got.network(), Network::Mainnet);
}

// --- what the setters refuse ----------------------------------------------------------

#[test]
fn the_setter_refuses_what_the_reader_would_have_to_reject() {
    let mut s = Settings::new();
    assert!(s.set_device_name("kitchen-desk 2").is_ok());
    assert!(s.set_device_name("kitchen/desk").is_err());
    assert!(s.set_device_name(" padded ").is_err());
    assert!(s.set_device_name(&"x".repeat(257)).is_err());
    assert_eq!(
        s.device_name(),
        "kitchen-desk 2",
        "a refused name must not have half-landed"
    );
}

/// The longest name the format accepts still fits a slot with room to spare, which is the
/// arithmetic the 4 KiB slot was chosen against.
#[test]
fn the_longest_accepted_name_round_trips() {
    let bench = Bench::blank();
    let want = named(&"n".repeat(256), Network::Testnet);
    bench.region().save(&want).unwrap();
    assert_eq!(bench.settings(), want);
}

// --- helpers: images this crate's writer would never produce --------------------------

fn name_payload(name: &[u8]) -> Vec<u8> {
    let mut out = vec![0x01u8];
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(name);
    out
}

/// CRC-32/ISO-HDLC over `seq || payload_len || payload`, written out here rather than
/// imported so that a test image is a statement about the FORMAT and not an echo of the
/// code under test.
fn crc_of(seq: u32, payload: &[u8]) -> u32 {
    let mut framed = Vec::new();
    framed.extend_from_slice(&seq.to_le_bytes());
    framed.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    framed.extend_from_slice(payload);
    let mut crc = u32::MAX;
    for byte in framed {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

/// A whole region image holding one hand-built record in slot A.
fn image(seq: u32, payload: &[u8]) -> Vec<u8> {
    let mut data = vec![0xff; REGION_SECTORS * SECTOR_BYTES as usize];
    data[0..8].copy_from_slice(b"NYSETT1\0");
    data[8..12].copy_from_slice(&seq.to_le_bytes());
    data[12..16].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    data[16..20].copy_from_slice(&crc_of(seq, payload).to_le_bytes());
    for b in data[20..64].iter_mut() {
        *b = 0;
    }
    data[64..64 + payload.len()].copy_from_slice(payload);
    data
}
