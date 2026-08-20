// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The public settings region: the handful of user-set values a device must be able to
//! read BEFORE anyone has typed a PIN.
//!
//! # Why this is not in the sealed store
//!
//! The lock screen draws the device name. The sealed store is unreadable until an unlock,
//! and the unlock is the screen the name is drawn on, so a name kept in the store could
//! never be shown where it is needed. Until 0.2.0 the name therefore lived in RAM and did
//! not survive a power cycle, because there was nowhere on this device to put it: the
//! partition table carries an app image and the two raw regions the sealing engine owns
//! and nothing else. This module is the third region, and it is deliberately the smallest,
//! dumbest thing that answers the question.
//!
//! # What may live here, and what may never
//!
//! The region is UNAUTHENTICATED PLAINTEXT. Anyone holding the device reads it; anyone
//! with a programmer rewrites it; a MAC would not change that, because the same programmer
//! erases a MAC'd region just as easily. So the admission rule is one sentence, and every
//! future tag is measured against it:
//!
//! > A value may live here only if "an attacker sets this to any value of their choosing"
//! > is an acceptable outcome.
//!
//! The device name passes: an attacker learns it by picking the device up and it was never
//! evidence of anything (the anti-swap evidence is the S-04 word pair a counterfeit cannot
//! compute). The network choice passes: every sealed wallet record carries its own network
//! and every signing surface states the network in force, so a flip is a visible annoyance
//! and not a redirection of funds.
//!
//! These do NOT pass, and none of them may ever be added:
//!
//! - the wipe policy, attempts-left or `min_pin_len` - the sealed ledger owns those with a
//!   `policy_gen` and a strictness rule, and a plaintext copy is an attacker-writable knob
//!   that relaxes the guess budget;
//! - the boot counter or any acknowledgement timestamp - a counter an attacker can reset
//!   is a counter that no longer reveals an unattended power-up;
//! - wallet count, occupancy, labels or fingerprints - the pre-PIN Verify sheet withholds
//!   these on purpose, and a plaintext file that volunteers them undoes that;
//! - anything secret or secret-derived: the device words, digests of sealed content, key
//!   material of any provenance;
//! - provisioning state and anti-rollback version - those are eFuse facts, read from the
//!   silicon at every boot, and flash may never be trusted for either.
//!
//! # On-flash format
//!
//! Two single-sector slots, A at region offset 0 and B at 0x1000. Each slot is a 64-byte
//! header page followed by its payload:
//!
//! ```text
//! off len field
//! 0     8  magic        ASCII "NYSETT1\0" - version-bearing, so a format revision is a
//!                       different magic and an old reader rejects it rather than guessing
//! 8     4  seq          u32 LE, strictly increasing across saves for the device's life
//! 12    4  payload_len  u32 LE, 1..=4032
//! 16    4  crc32        u32 LE (ISO-HDLC) over seq || payload_len || payload
//! 20   44  MBZ          reserved, must be zero
//! 64    n  payload      TLV
//! ```
//!
//! Payload TLV entries are `tag: u8, len: u16 LE, value: len bytes`, packed, with no
//! trailing bytes. Unknown tags are SKIPPED by their length, which is what lets a 0.3.0
//! firmware add a tag that a 0.2.0 firmware reads past instead of rejecting.
//!
//! # Why a CRC and not a MAC
//!
//! The CRC is here to catch a torn write and a bit rot, which is the entire class of
//! damage this region can suffer that anybody could plausibly defend against. It makes no
//! authenticity claim and no part of the product may make one on its behalf.
//!
//! # Why two slots
//!
//! So that a write is never the only copy. The writer erases the LOSING side, programs the
//! payload, and programs the header page LAST; the winning side is untouched from the
//! first byte to the last. A cut anywhere therefore leaves either the new record complete
//! or the old record complete, and the reader's validity test (exact magic, in-range
//! length, matching CRC) rejects every partial state a cut can produce. It is the same
//! never-only-copy discipline the sealing engine's A/B slots use, at toy scale.
//!
//! # Where the logic lives
//!
//! All of it is here, over a four-method [`SettingsFlash`], so that the parser a hostile
//! flash image reaches is host-testable. The firmware's implementation of that trait is
//! four `esp_partition_*` calls and no decisions.

use alloc::string::String;
use alloc::vec::Vec;

use crate::transport::checksum::crc32;

/// Magic, and the format revision. A revision is a NEW magic, never a version byte inside
/// this one: an old reader must reject a newer layout outright rather than parse a header
/// whose fields it would mis-assign.
const MAGIC: [u8; 8] = *b"NYSETT1\0";

/// The header page. A whole 64 bytes for 20 bytes of fields because the payload then
/// starts on a round offset and a future revision can spend the remainder without moving
/// anything.
pub const HEADER_BYTES: usize = 64;
/// Fields actually defined in the header; everything from here to [`HEADER_BYTES`] is
/// reserved and must read back as zero.
const HEADER_USED: usize = 20;
/// Flash sector, and the size of one slot.
pub const SECTOR_BYTES: u32 = 4096;
/// Slots in the region. Two: see the module docs.
pub const SLOTS: u32 = 2;
/// Largest payload a slot can hold.
pub const MAX_PAYLOAD: usize = 4032;
/// Longest device name the format accepts. Far above what any shipped panel can draw -
/// the UI's own width rule is the binding limit - so this bound exists to keep a hostile
/// image from claiming a name that does not fit in a slot, not to constrain a user.
pub const MAX_NAME_BYTES: usize = 256;
/// Program granularity of a plaintext ESP-IDF partition. The payload is padded up to it
/// with `0xff`, which clears no bits and so leaves the pad indistinguishable from erased.
const WRITE_GRAN: usize = 4;

const TAG_DEVICE_NAME: u8 = 0x01;
const TAG_NETWORK: u8 = 0x02;

/// The chain this device's next derivation runs on.
///
/// This crate's own two-value enum rather than the pipeline's `Network`: the sealing crate
/// does not depend on the Bitcoin layer, and the settings region has never had a use for
/// the four-way one. The firmware maps between them, and refuses to persist a network this
/// enum cannot name rather than silently writing a nearby one.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Network {
    #[default]
    Mainnet = 0,
    Testnet = 1,
}

impl Network {
    fn tag(self) -> u8 {
        self as u8
    }

    /// Any byte the encoding does not define is INVALID, not "probably mainnet". The
    /// record it came from is rejected whole, and the reader falls back to defaults - so a
    /// corrupted network byte can only ever land the device on mainnet, never on a chain
    /// the user did not pick.
    fn from_tag(raw: u8) -> Option<Network> {
        match raw {
            0 => Some(Network::Mainnet),
            1 => Some(Network::Testnet),
            _ => None,
        }
    }
}

/// Everything the region holds. Public state, no secrets, nothing zeroized: there is
/// nothing here an attacker does not already have by holding the device.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Settings {
    /// Private, with a checked setter, so a `Settings` that cannot be written back is
    /// unrepresentable. The reader applies the same rule to what it finds on flash.
    device_name: String,
    network: Network,
}

/// Why a name was refused. The UI has its own, richer refusals (a PIN-shaped name, a seed
/// word, a name too wide for the narrowest panel); this is only the part the FORMAT can
/// answer for, and it is checked again on read.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NameRefusal {
    /// A character outside letters, digits, space, `-` and `_`.
    Charset,
    /// Longer than [`MAX_NAME_BYTES`].
    TooLong,
    /// Leading or trailing whitespace. The UI stores names trimmed and the lock screen
    /// draws them quoted, so a name that is not its own trimmed form would render as
    /// something the user did not type.
    Untrimmed,
}

impl Settings {
    /// The state of a device that has never saved - and, byte for byte, the state a blank
    /// region reads back as, with no special case anywhere.
    pub fn new() -> Settings {
        Settings::default()
    }

    pub fn device_name(&self) -> &str {
        &self.device_name
    }

    pub fn network(&self) -> Network {
        self.network
    }

    /// Set the name, or say why not. An empty name is accepted and means the device is
    /// unnamed, which is a state the lock screen draws.
    pub fn set_device_name(&mut self, name: &str) -> Result<(), NameRefusal> {
        check_name(name)?;
        self.device_name.clear();
        self.device_name.push_str(name);
        Ok(())
    }

    pub fn set_network(&mut self, network: Network) {
        self.network = network;
    }

    /// The payload, as it goes to flash. Never empty: the network tag is always written,
    /// so `payload_len == 0` stays an invalid encoding the reader can reject outright.
    fn encode_payload(&self) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        if !self.device_name.is_empty() {
            let len = u16::try_from(self.device_name.len()).ok()?;
            out.push(TAG_DEVICE_NAME);
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(self.device_name.as_bytes());
        }
        out.push(TAG_NETWORK);
        out.extend_from_slice(&1u16.to_le_bytes());
        out.push(self.network.tag());
        if out.len() > MAX_PAYLOAD {
            return None;
        }
        Some(out)
    }

    /// Parse a payload, rejecting anything the encoding does not define and skipping any
    /// tag this firmware does not know.
    fn decode_payload(payload: &[u8]) -> Option<Settings> {
        let mut out = Settings::new();
        let mut seen_name = false;
        let mut seen_network = false;
        let mut at = 0usize;
        while at < payload.len() {
            let tag = *take(payload, &mut at, 1)?.first()?;
            let len_bytes = take(payload, &mut at, 2)?;
            let len = usize::from(u16::from_le_bytes([
                *len_bytes.first()?,
                *len_bytes.get(1)?,
            ]));
            let value = take(payload, &mut at, len)?;
            match tag {
                TAG_DEVICE_NAME => {
                    // A repeated tag is a malformed record, not a last-one-wins merge:
                    // two answers to one question is exactly the ambiguity a strict
                    // parser exists to refuse.
                    if seen_name {
                        return None;
                    }
                    seen_name = true;
                    let name = core::str::from_utf8(value).ok()?;
                    // An empty name is the ABSENCE of the tag, so the two spellings of
                    // "unnamed" cannot both exist on flash.
                    if name.is_empty() {
                        return None;
                    }
                    // Re-checked on READ, not merely on write. Flash is not a trusted
                    // input: without this, an image with a control character or a
                    // non-ASCII byte in the name would reach the one screen a user reads
                    // to recognise their own device.
                    out.set_device_name(name).ok()?;
                }
                TAG_NETWORK => {
                    if seen_network {
                        return None;
                    }
                    seen_network = true;
                    if value.len() != 1 {
                        return None;
                    }
                    out.set_network(Network::from_tag(*value.first()?)?);
                }
                // Forward compatibility, and the whole reason the entries carry a length:
                // a 0.3.0 tag is stepped over, and the 0.2.0 values in the same record
                // are still read.
                _ => {}
            }
        }
        // Exactly consumed: `at` can only stop on a tag boundary, and `take` already
        // refused a value that ran past the end.
        Some(out)
    }
}

/// Whether `c` may appear in a device name. The same alphabet the on-screen keyboard
/// offers, restated here because this is the boundary a flash image crosses and it must
/// not be able to smuggle a character the keyboard would never have produced.
fn name_char_ok(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == ' ' || c == '-' || c == '_'
}

fn check_name(name: &str) -> Result<(), NameRefusal> {
    if name.len() > MAX_NAME_BYTES {
        return Err(NameRefusal::TooLong);
    }
    if !name.chars().all(name_char_ok) {
        return Err(NameRefusal::Charset);
    }
    if name.trim() != name {
        return Err(NameRefusal::Untrimmed);
    }
    Ok(())
}

/// Advance `at` by `n` and return the bytes stepped over, or `None` if they run past the
/// end. The one bounds check in the parser, so there is one place to get it right.
fn take<'a>(buf: &'a [u8], at: &mut usize, n: usize) -> Option<&'a [u8]> {
    let end = at.checked_add(n)?;
    let out = buf.get(*at..end)?;
    *at = end;
    Some(out)
}

/// A slot header, once it has been found structurally sound. Holding one proves the magic
/// matched and the length is in range; it does NOT prove the payload is intact, which only
/// the CRC over the bytes actually read can say.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Header {
    seq: u32,
    payload_len: u32,
    crc: u32,
}

impl Header {
    fn parse(raw: &[u8]) -> Option<Header> {
        let magic = raw.get(0..8)?;
        if magic != MAGIC {
            return None;
        }
        let seq = le_u32(raw, 8)?;
        // 0xffffffff is what an erased header reads as, and 0 is what a zeroed one reads
        // as. Neither is a sequence number, so a slot that has been erased or zeroed can
        // never win an election even if the rest of the page somehow validated.
        if seq == u32::MAX || seq == 0 {
            return None;
        }
        let payload_len = le_u32(raw, 12)?;
        if payload_len == 0 || payload_len as usize > MAX_PAYLOAD {
            return None;
        }
        let crc = le_u32(raw, 16)?;
        // Reserved bytes are MBZ, checked rather than ignored: it costs nothing and it
        // means a future revision can spend them knowing that no shipped writer ever put
        // anything there.
        if raw.get(HEADER_USED..HEADER_BYTES)?.iter().any(|b| *b != 0) {
            return None;
        }
        Some(Header {
            seq,
            payload_len,
            crc,
        })
    }

    /// The CRC as it must read for `payload` to belong to this header. Covers the sequence
    /// number and the length as well as the bytes, so no tear can promote a stale length
    /// or a stale sequence onto an intact payload.
    fn expected_crc(&self, payload: &[u8]) -> u32 {
        let mut framed = Vec::with_capacity(payload.len().saturating_add(8));
        framed.extend_from_slice(&self.seq.to_le_bytes());
        framed.extend_from_slice(&self.payload_len.to_le_bytes());
        framed.extend_from_slice(payload);
        crc32(&framed)
    }
}

fn le_u32(raw: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    let b = raw.get(at..end)?;
    Some(u32::from_le_bytes([
        *b.first()?,
        *b.get(1)?,
        *b.get(2)?,
        *b.get(3)?,
    ]))
}

/// The plaintext settings region, as four calls.
///
/// Deliberately NOT [`crate::Flash`]: that trait describes the two regions the sealing
/// engine owns, with an `is_erased` that must read past a cipher and a geometry the
/// superblock is checked against. This region is plaintext by requirement, is not
/// described by any `Layout`, and must stay outside everything the power-loss fuzzer
/// reasons about. Offsets are relative to the start of the region, for the same reason the
/// engine's are: nothing here may name an absolute flash address.
pub trait SettingsFlash {
    type Error: core::fmt::Debug;

    /// Sectors in the region. Must be at least [`SLOTS`]; the extra ones are reserved and
    /// this module never touches them.
    fn sectors(&self) -> u32;

    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), Self::Error>;

    /// Program `data` at `offset`. Both are multiples of the 4-byte program granularity.
    fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), Self::Error>;

    fn erase_sector(&mut self, sector: u32) -> Result<(), Self::Error>;
}

/// Which of the two slots a record lives in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Side {
    A,
    B,
}

impl Side {
    fn other(self) -> Side {
        match self {
            Side::A => Side::B,
            Side::B => Side::A,
        }
    }

    fn offset(self) -> u32 {
        match self {
            Side::A => 0,
            Side::B => SECTOR_BYTES,
        }
    }

    fn sector(self) -> u32 {
        match self {
            Side::A => 0,
            Side::B => 1,
        }
    }
}

/// Why a save could not be made.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SaveError<E> {
    /// The backend refused a read, a write or an erase. The region is unchanged or holds a
    /// partial record on the LOSING side; either way the previous record is still readable.
    Flash(E),
    /// The settings do not fit a slot. Unreachable through the checked setters; kept as a
    /// value so the encoder has no reason to panic.
    TooLarge,
    /// 4,294,967,294 saves. Not reachable by a human tapping Save; refused rather than
    /// wrapped, because a wrapped sequence number silently resurrects an older record.
    SequenceExhausted,
}

/// Why a region could not be adopted.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OpenError {
    /// Fewer than [`SLOTS`] sectors: there is no room for a second copy, and a
    /// single-copy region would make every save a window in which the only record on the
    /// device is half-written. Refused rather than degraded.
    TooSmall { sectors: u32 },
}

/// The region opened, and every operation on it.
#[derive(Debug)]
pub struct SettingsRegion<F> {
    flash: F,
}

impl<F: SettingsFlash> SettingsRegion<F> {
    pub fn open(flash: F) -> Result<SettingsRegion<F>, OpenError> {
        let sectors = flash.sectors();
        if sectors < SLOTS {
            return Err(OpenError::TooSmall { sectors });
        }
        Ok(SettingsRegion { flash })
    }

    /// What this device has saved, or the defaults.
    ///
    /// A blank region, a wiped region, a torn write and a corrupted record all arrive at
    /// the same place - the defaults - because "no valid slot" is one condition and not
    /// four. The only failure this can report is the backend failing to read at all.
    pub fn load(&mut self) -> Result<Settings, F::Error> {
        Ok(self
            .load_current()?
            .map_or_else(Settings::new, |c| c.settings))
    }

    /// Save, then leave. The winning side is not touched, so the device is never without a
    /// complete record - see the module docs for the cut analysis.
    pub fn save(&mut self, settings: &Settings) -> Result<(), SaveError<F::Error>> {
        let payload = settings.encode_payload().ok_or(SaveError::TooLarge)?;
        let current = self.load_current().map_err(SaveError::Flash)?;
        let (target, seq) = match &current {
            Some(c) => (
                c.side.other(),
                c.seq.checked_add(1).ok_or(SaveError::SequenceExhausted)?,
            ),
            None => (Side::A, 1),
        };
        // The one sequence number the header rejects. Refused here rather than written and
        // discovered unreadable at the next boot.
        if seq == u32::MAX {
            return Err(SaveError::SequenceExhausted);
        }

        let len = u32::try_from(payload.len()).map_err(|_| SaveError::TooLarge)?;
        let crc = Header {
            seq,
            payload_len: len,
            crc: 0,
        }
        .expected_crc(&payload);
        let mut header = [0u8; HEADER_BYTES];
        write_at(&mut header, 0, &MAGIC).ok_or(SaveError::TooLarge)?;
        write_at(&mut header, 8, &seq.to_le_bytes()).ok_or(SaveError::TooLarge)?;
        write_at(&mut header, 12, &len.to_le_bytes()).ok_or(SaveError::TooLarge)?;
        write_at(&mut header, 16, &crc.to_le_bytes()).ok_or(SaveError::TooLarge)?;

        // Pad up to the program granularity with 0xff: those bytes clear no bits, so the
        // pad is indistinguishable from erased flash and a later reader has nothing extra
        // to explain. They sit outside `payload_len` and are covered by no CRC.
        let mut body = payload;
        body.resize(padded(body.len()), 0xff);

        let base = target.offset();
        // Order is the whole guarantee. Erase the loser; program the payload; program the
        // header page LAST, because the header is what makes a slot claimable at all.
        self.flash
            .erase_sector(target.sector())
            .map_err(SaveError::Flash)?;
        let payload_at = base.saturating_add(HEADER_BYTES as u32);
        self.flash
            .write(payload_at, &body)
            .map_err(SaveError::Flash)?;
        self.flash.write(base, &header).map_err(SaveError::Flash)?;
        Ok(())
    }

    /// Erase both slots, returning the region to the state a factory-blank device is in.
    ///
    /// For the one caller that is entitled to it: an operation that destroys what the
    /// device holds must not leave the previous owner's device name on the lock screen.
    pub fn clear(&mut self) -> Result<(), F::Error> {
        self.flash.erase_sector(Side::A.sector())?;
        self.flash.erase_sector(Side::B.sector())?;
        Ok(())
    }

    /// The winning record and where it lives, or `None` when neither side is valid.
    fn load_current(&mut self) -> Result<Option<Current>, F::Error> {
        let a = self.read_side(Side::A)?;
        let b = self.read_side(Side::B)?;
        // Highest sequence number wins, and a side that fails ANY check is not a
        // candidate - so a torn new record does not beat an intact old one.
        Ok(match (a, b) {
            (Some(a), Some(b)) => Some(if b.seq > a.seq { b } else { a }),
            (Some(a), None) => Some(a),
            (None, b) => b,
        })
    }

    /// One side, fully validated: header, then the payload the header claims, then the CRC
    /// over both, then the TLV structure. Anything short of all four is `None`.
    fn read_side(&mut self, side: Side) -> Result<Option<Current>, F::Error> {
        let base = side.offset();
        let mut header = [0u8; HEADER_BYTES];
        self.flash.read(base, &mut header)?;
        let Some(h) = Header::parse(&header) else {
            return Ok(None);
        };
        let mut payload = alloc::vec![0u8; h.payload_len as usize];
        self.flash
            .read(base.saturating_add(HEADER_BYTES as u32), &mut payload)?;
        if h.expected_crc(&payload) != h.crc {
            return Ok(None);
        }
        Ok(Settings::decode_payload(&payload).map(|settings| Current {
            side,
            seq: h.seq,
            settings,
        }))
    }
}

/// A validated record and the slot it came from.
#[derive(Clone, PartialEq, Eq, Debug)]
struct Current {
    side: Side,
    seq: u32,
    settings: Settings,
}

/// Round up to the program granularity. `wrapping_neg() & 3` is the round-up, written
/// without a division the crate bans and without an addition that could overflow.
fn padded(len: usize) -> usize {
    len.saturating_add(len.wrapping_neg() & (WRITE_GRAN.saturating_sub(1)))
}

/// Copy `src` into `dst` at `at`, or `None` if it does not fit. The crate forbids
/// indexing, and a header field written to the wrong offset is exactly the bug that
/// forbidding it is meant to prevent.
fn write_at(dst: &mut [u8], at: usize, src: &[u8]) -> Option<()> {
    let end = at.checked_add(src.len())?;
    dst.get_mut(at..end)?.copy_from_slice(src);
    Some(())
}
