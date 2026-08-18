// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The on-flash format, byte for byte.
//!
//! ESP-SEAL.md 3.3-3.7 is normative, extended by OPEN-QUESTIONS Q5.1 (the policy log,
//! the two superblock fields, the canary witness) and Q5.4 (`failures_base`), both of
//! which land inside this freeze. Nothing in this module performs I/O; it is pure
//! encoding, which is what makes the negative tests possible - every AAD-bound field can
//! be flipped on a byte buffer and the resulting error asserted.
//!
//! Two invariants shape everything here:
//!
//! > **RECORDS INVARIANT.** Every byte of the records region is programmed at most once
//! > between erases. No in-place updates, ever.
//! >
//! > **LEDGER INVARIANT.** The ledger region is only ever advanced by programming a
//! > previously erased cell, or reset by erasing a whole sector. No cell is ever
//! > reprogrammed.

use crate::bytes as by;
use crate::config::{KdfParams, Layout, Occupancy, Policy};
use crate::crypto::{mac16, mac8};
use crate::error::Corruption;
use crate::slot::{Identity, SlotMap};
use crate::{FORMAT_VERSION, SUITE_ID};

pub(crate) const HEADER_LEN: usize = 80;
/// The AEAD associated data is header bytes 0x00..0x30, exactly 48 bytes.
pub(crate) const AAD_LEN: usize = 48;
pub(crate) const TAG_LEN: usize = 16;
/// Offset of the header MAC inside the header. It is the LAST 16 bytes, and writing it
/// is the commit point of every single-record operation.
pub(crate) const HEADER_MAC_OFF: usize = 0x40;

const MAGIC_RECORD: &[u8; 4] = b"ESLR";
const MAGIC_SUPERBLOCK: &[u8; 4] = b"ESLS";
const MAGIC_CANARY: &[u8; 4] = b"ESLK";
const MAGIC_LEDGER: &[u8; 4] = b"ESLC";
const MAGIC_AUX: &[u8; 4] = b"ESLA";

const FLAG_EMULATED_KEY: u8 = 0b0000_0001;
const FLAG_READABLE_KEY: u8 = 0b0000_0010;
const FLAG_MASK: u8 = FLAG_EMULATED_KEY | FLAG_READABLE_KEY;

// ---------------------------------------------------------------------------
// Record header
// ---------------------------------------------------------------------------

/// The 80-byte header every slot side of every class begins with.
///
/// ```text
/// off  len  field
/// 0x00   4  magic b"ESLR"
/// 0x04   2  format_ver
/// 0x06   2  suite_id
/// 0x08   1  slot_class
/// 0x09   1  slot_index
/// 0x0A   1  slot_side
/// 0x0B   1  flags        bit0 EMULATED_KEY, bit1 READABLE_KEY, bits2-7 MBZ
/// 0x0C   4  argon2_m_kib
/// 0x10   4  argon2_t
/// 0x14   1  argon2_p
/// 0x15   3  MBZ
/// 0x18   8  seal_seq
/// 0x20   8  wipe_epoch
/// 0x28   4  pin_gen
/// 0x2C   4  body_capacity
/// ---- 0x30: end of the AEAD associated data (48 bytes) ----
/// 0x30  16  body_digest
/// 0x40  16  header_mac
/// 0x50 ---  body
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct RecordHeader {
    pub slot_class: u8,
    pub slot_index: u8,
    pub slot_side: u8,
    pub flags: u8,
    pub kdf: KdfParams,
    pub seal_seq: u64,
    pub wipe_epoch: u64,
    pub pin_gen: u32,
    pub body_capacity: u32,
}

impl RecordHeader {
    /// The 48 bytes the AEAD authenticates. Each field in here stops a specific attack
    /// (ESP-SEAL.md 3.3): parameter downgrade, slot transplant, side copy, sequence
    /// replay, post-wipe key reuse, generation mixing, truncation.
    pub fn aad(&self) -> [u8; AAD_LEN] {
        let mut b = [0u8; AAD_LEN];
        let _ = by::wr(&mut b, 0x00, MAGIC_RECORD);
        let _ = by::wr_u16(&mut b, 0x04, FORMAT_VERSION);
        let _ = by::wr_u16(&mut b, 0x06, SUITE_ID);
        let _ = by::wr_u8(&mut b, 0x08, self.slot_class);
        let _ = by::wr_u8(&mut b, 0x09, self.slot_index);
        let _ = by::wr_u8(&mut b, 0x0a, self.slot_side);
        let _ = by::wr_u8(&mut b, 0x0b, self.flags);
        let _ = by::wr_u32(&mut b, 0x0c, self.kdf.m_kib);
        let _ = by::wr_u32(&mut b, 0x10, self.kdf.t);
        let _ = by::wr_u8(&mut b, 0x14, self.kdf.p);
        let _ = by::wr_u64(&mut b, 0x18, self.seal_seq);
        let _ = by::wr_u64(&mut b, 0x20, self.wipe_epoch);
        let _ = by::wr_u32(&mut b, 0x28, self.pin_gen);
        let _ = by::wr_u32(&mut b, 0x2c, self.body_capacity);
        b
    }

    /// The whole 80-byte header, MACs included.
    pub fn encode(&self, hdr_key: &[u8; 32], body: &[u8]) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        let _ = by::wr(&mut b, 0, &self.aad());
        let digest = self.body_digest(hdr_key, body);
        let _ = by::wr(&mut b, 0x30, &digest);
        let mac = mac16(hdr_key, &[b"ESLH", by::rd(&b, 0, 0x40).unwrap_or(&[])]);
        let _ = by::wr(&mut b, HEADER_MAC_OFF, &mac);
        b
    }

    /// `HMAC(hdr_key, b"ESLB" || class || index || side || body_region)[0..16]`.
    ///
    /// Deliberately outside the AAD: it is a function of the ciphertext, which is a
    /// function of the AAD, so putting it inside would be circular. Its job is torn-write
    /// and glitch detection before an Argon2 spend, not confidentiality.
    pub fn body_digest(&self, hdr_key: &[u8; 32], body: &[u8]) -> [u8; 16] {
        mac16(
            hdr_key,
            &[
                b"ESLB",
                &[self.slot_class, self.slot_index, self.slot_side],
                body,
            ],
        )
    }

    /// Parse and structurally validate a header. Returns the parsed header only if the
    /// magic, versions and every MBZ field are what this firmware wrote.
    pub fn decode(raw: &[u8]) -> Result<RecordHeader, Corruption> {
        let magic = by::rd(raw, 0, 4).ok_or(Corruption::Geometry)?;
        if magic != MAGIC_RECORD {
            return Err(Corruption::Magic);
        }
        if by::rd_u16(raw, 0x04) != Some(FORMAT_VERSION) || by::rd_u16(raw, 0x06) != Some(SUITE_ID)
        {
            return Err(Corruption::Version);
        }
        let flags = by::rd_u8(raw, 0x0b).ok_or(Corruption::Geometry)?;
        if flags & !FLAG_MASK != 0 {
            return Err(Corruption::Version);
        }
        if !by::all_zero(by::rd(raw, 0x15, 3).ok_or(Corruption::Geometry)?) {
            return Err(Corruption::Version);
        }
        Ok(RecordHeader {
            slot_class: by::rd_u8(raw, 0x08).ok_or(Corruption::Geometry)?,
            slot_index: by::rd_u8(raw, 0x09).ok_or(Corruption::Geometry)?,
            slot_side: by::rd_u8(raw, 0x0a).ok_or(Corruption::Geometry)?,
            flags,
            kdf: KdfParams {
                m_kib: by::rd_u32(raw, 0x0c).ok_or(Corruption::Geometry)?,
                t: by::rd_u32(raw, 0x10).ok_or(Corruption::Geometry)?,
                p: by::rd_u8(raw, 0x14).ok_or(Corruption::Geometry)?,
            },
            seal_seq: by::rd_u64(raw, 0x18).ok_or(Corruption::Geometry)?,
            wipe_epoch: by::rd_u64(raw, 0x20).ok_or(Corruption::Geometry)?,
            pin_gen: by::rd_u32(raw, 0x28).ok_or(Corruption::Geometry)?,
            body_capacity: by::rd_u32(raw, 0x2c).ok_or(Corruption::Geometry)?,
        })
    }

    /// Verify the header MAC over the parsed bytes. A side is COMMITTED if and only if
    /// this returns true: the header is written last, so a valid MAC proves the body was
    /// fully written. That one sentence is the whole power-loss story for SEAL.
    pub fn verify_mac(raw: &[u8], hdr_key: &[u8; 32]) -> bool {
        let (Some(covered), Some(stored)) = (by::rd(raw, 0, 0x40), by::rd(raw, HEADER_MAC_OFF, 16))
        else {
            return false;
        };
        crate::crypto::ct_eq(&mac16(hdr_key, &[b"ESLH", covered]), stored)
    }

    pub fn flags_for(provenance: crate::hal::KeyProvenance) -> u8 {
        provenance.flags()
    }
}

// ---------------------------------------------------------------------------
// Superblock body (plaintext - there is no PIN at mount time)
// ---------------------------------------------------------------------------

/// ```text
/// off  len  field
/// 0x00   4  magic b"ESLS"
/// 0x04   2  layout_ver
/// 0x06   2  MBZ
/// 0x08  16  domain_tag
/// 0x18   8  device_tag
/// 0x20   1  n_canary_slots
/// 0x21   1  n_payload_slots
/// 0x22   1  n_registry_slots
/// 0x23   1  payload_slot_sectors
/// 0x24   1  registry_slot_sectors
/// 0x25   1  identities
/// 0x26   1  wipe_after            format-time policy mirror
/// 0x27   1  occupancy
/// 0x28   4  argon2_m_kib
/// 0x2C   4  argon2_t
/// 0x30   1  argon2_p
/// 0x31   1  suite_id
/// 0x32   4  policy_gen            of the FORMAT-TIME policy, i.e. always 0
/// 0x36   1  min_pin_len           format-time
/// 0x37   1  MBZ
/// 0x38   8  formatted_at_epoch
/// 0x40   8  policy_mirror         the CURRENT policy, rewritten by SET-POLICY Y6
/// 0x48 ...  MBZ to body_capacity
/// ```
///
/// **The two policy copies here are not the same copy, and OPEN-QUESTIONS Q5.1 conflates
/// them.** Q5.1 asks the superblock fields at 0x26/0x27/0x32/0x36 to be a MIRROR that
/// SET-POLICY rewrites (Y6), and separately defines the strict default that every
/// fail-closed path resolves to as "the superblock's FORMAT-TIME value". Those cannot be
/// one field: rewriting the mirror destroys the format-time value, and after one
/// "disable the wipe" the strict default would itself be "wipe off" - the exact inversion
/// the fail-closed rule exists to prevent. So the format-time policy stays where Q5.1 put
/// it and is written exactly once, and the fast-read mirror gets eight bytes of its own
/// at 0x40, inside the same `body_digest` and `header_mac` cover.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Superblock {
    pub domain_tag: [u8; 16],
    pub device_tag: [u8; 8],
    pub layout: Layout,
    pub kdf: KdfParams,
    /// Written once, at FORMAT. The strict default resolves here.
    pub format_policy: Policy,
    /// The policy believed current when this superblock side was written. Never the
    /// authority: if it disagrees with the ledger, the ledger wins.
    pub policy_mirror: Policy,
    pub formatted_at_epoch: u64,
}

impl Superblock {
    pub fn encode(&self, out: &mut [u8]) -> Option<()> {
        by::wr(out, 0x00, MAGIC_SUPERBLOCK)?;
        by::wr_u16(out, 0x04, FORMAT_VERSION)?;
        by::wr(out, 0x08, &self.domain_tag)?;
        by::wr(out, 0x18, &self.device_tag)?;
        by::wr_u8(out, 0x20, self.layout.canary_slots)?;
        by::wr_u8(out, 0x21, self.layout.payload_slots)?;
        by::wr_u8(out, 0x22, self.layout.registry_slots)?;
        by::wr_u8(out, 0x23, self.layout.payload_slot_sectors)?;
        by::wr_u8(out, 0x24, self.layout.registry_slot_sectors)?;
        by::wr_u8(out, 0x25, self.layout.identities)?;
        by::wr_u8(out, 0x26, self.format_policy.wipe_after)?;
        by::wr_u8(out, 0x27, self.format_policy.occupancy as u8)?;
        by::wr_u32(out, 0x28, self.kdf.m_kib)?;
        by::wr_u32(out, 0x2c, self.kdf.t)?;
        by::wr_u8(out, 0x30, self.kdf.p)?;
        by::wr_u8(out, 0x31, SUITE_ID.to_le_bytes()[0])?;
        by::wr_u32(out, 0x32, self.format_policy.policy_gen)?;
        by::wr_u8(out, 0x36, self.format_policy.min_pin_len)?;
        by::wr_u64(out, 0x38, self.formatted_at_epoch)?;
        by::wr(out, 0x40, &self.policy_mirror.encode())?;
        Some(())
    }

    pub fn decode(raw: &[u8], sector_size: u32, ledger_sectors: u32) -> Result<Superblock, Corruption> {
        if by::rd(raw, 0, 4).ok_or(Corruption::Geometry)? != MAGIC_SUPERBLOCK {
            return Err(Corruption::Magic);
        }
        if by::rd_u16(raw, 0x04) != Some(FORMAT_VERSION) {
            return Err(Corruption::Version);
        }
        if by::rd_u8(raw, 0x31) != Some(SUITE_ID.to_le_bytes()[0]) {
            return Err(Corruption::Version);
        }
        if by::rd_u8(raw, 0x37) != Some(0) {
            return Err(Corruption::Version);
        }
        let occupancy = match by::rd_u8(raw, 0x27) {
            Some(0) => Occupancy::Sparse,
            Some(1) => Occupancy::AlwaysFilled,
            _ => return Err(Corruption::Body),
        };
        let format_policy = Policy {
            wipe_after: by::rd_u8(raw, 0x26).ok_or(Corruption::Geometry)?,
            occupancy,
            min_pin_len: by::rd_u8(raw, 0x36).ok_or(Corruption::Geometry)?,
            policy_gen: by::rd_u32(raw, 0x32).ok_or(Corruption::Geometry)?,
        };
        // The format-time policy is the strict default. If it does not decode, or if it
        // says "wipe disabled", the store's fail-closed direction has been inverted on
        // flash and there is no safe reading of it.
        if Policy::decode(&format_policy.encode()).is_none() || !format_policy.wipe_enabled() {
            return Err(Corruption::Body);
        }
        let mirror_raw = by::rd_arr::<8>(raw, 0x40).ok_or(Corruption::Geometry)?;
        let policy_mirror = Policy::decode(&mirror_raw).ok_or(Corruption::Body)?;
        Ok(Superblock {
            domain_tag: by::rd_arr::<16>(raw, 0x08).ok_or(Corruption::Geometry)?,
            device_tag: by::rd_arr::<8>(raw, 0x18).ok_or(Corruption::Geometry)?,
            layout: Layout {
                sector_size,
                // The records-sector count is implied by the slot map rather than stored:
                // storing it twice would create a disagreement that has no right answer.
                records_sectors: 0,
                ledger_sectors,
                canary_slots: by::rd_u8(raw, 0x20).ok_or(Corruption::Geometry)?,
                payload_slots: by::rd_u8(raw, 0x21).ok_or(Corruption::Geometry)?,
                registry_slots: by::rd_u8(raw, 0x22).ok_or(Corruption::Geometry)?,
                payload_slot_sectors: by::rd_u8(raw, 0x23).ok_or(Corruption::Geometry)?,
                registry_slot_sectors: by::rd_u8(raw, 0x24).ok_or(Corruption::Geometry)?,
                identities: by::rd_u8(raw, 0x25).ok_or(Corruption::Geometry)?,
            },
            kdf: KdfParams {
                m_kib: by::rd_u32(raw, 0x28).ok_or(Corruption::Geometry)?,
                t: by::rd_u32(raw, 0x2c).ok_or(Corruption::Geometry)?,
                p: by::rd_u8(raw, 0x30).ok_or(Corruption::Geometry)?,
            },
            format_policy,
            policy_mirror,
            formatted_at_epoch: by::rd_u64(raw, 0x38).ok_or(Corruption::Geometry)?,
        })
    }

    /// The device fingerprint out of a superblock body that has NOT been authenticated.
    ///
    /// Used for one thing only: telling a user whose flash came from another board that
    /// this is what happened, instead of showing them a generic corruption message. It
    /// cannot be used for anything else, and the reason is worth stating because it is a
    /// limit of the design rather than of this function. The superblock's integrity comes
    /// from `header_mac` under the device-bound `hdr_key`, so on a foreign board the MAC
    /// fails first and no superblock is ever elected - which means the authenticated
    /// `device_tag` comparison ESP-SEAL.md 3.5 describes can never actually run. The
    /// fingerprint read here is therefore unauthenticated by necessity, is forgeable by
    /// anyone with a programmer, and is allowed to influence exactly one thing: which
    /// refusal message is shown. It never grants access.
    pub fn peek_fingerprint(raw: &[u8]) -> Option<([u8; 16], [u8; 8])> {
        if by::rd(raw, 0, 4)? != MAGIC_SUPERBLOCK {
            return None;
        }
        Some((by::rd_arr::<16>(raw, 0x08)?, by::rd_arr::<8>(raw, 0x18)?))
    }

    /// Does the recorded map describe the same slots the running firmware expects?
    /// Only the fields that move a slot are compared; `records_sectors` is not stored.
    pub fn layout_matches(&self, want: &Layout) -> bool {
        let l = &self.layout;
        l.sector_size == want.sector_size
            && l.ledger_sectors == want.ledger_sectors
            && l.canary_slots == want.canary_slots
            && l.payload_slots == want.payload_slots
            && l.registry_slots == want.registry_slots
            && l.payload_slot_sectors == want.payload_slot_sectors
            && l.registry_slot_sectors == want.registry_slot_sectors
            && l.identities == want.identities
    }
}

// ---------------------------------------------------------------------------
// Canary body (inside the AEAD)
// ---------------------------------------------------------------------------

/// The fixed 64-byte canary plaintext.
///
/// ```text
/// b"ESLK"(4) | identity u8 | MBZ u8 | visible_slot_mask u16 | created_epoch u64
///            | label[16] | policy_bytes[8] | MBZ[24]
/// ```
///
/// The trailing MBZ[32] of ESP-SEAL.md 4.4 gives up its first eight bytes to the policy
/// witness of Q5.1: the copy that proves a human who knew the PIN authorised the policy
/// in force.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Canary {
    pub identity: Identity,
    pub visible: SlotMap,
    pub created_epoch: u64,
    pub label: [u8; 16],
    pub policy: Policy,
}

impl Canary {
    pub const LEN: usize = 64;

    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut b = [0u8; Self::LEN];
        let _ = by::wr(&mut b, 0, MAGIC_CANARY);
        let _ = by::wr_u8(&mut b, 4, self.identity.0);
        let _ = by::wr_u16(&mut b, 6, self.visible.bits());
        let _ = by::wr_u64(&mut b, 8, self.created_epoch);
        let _ = by::wr(&mut b, 16, &self.label);
        let _ = by::wr(&mut b, 32, &self.policy.encode());
        b
    }

    pub fn decode(raw: &[u8]) -> Result<Canary, Corruption> {
        if raw.len() < Self::LEN {
            return Err(Corruption::Body);
        }
        if by::rd(raw, 0, 4).ok_or(Corruption::Body)? != MAGIC_CANARY {
            return Err(Corruption::Magic);
        }
        if by::rd_u8(raw, 5) != Some(0) {
            return Err(Corruption::Body);
        }
        if !by::all_zero(by::rd(raw, 40, 24).ok_or(Corruption::Body)?) {
            return Err(Corruption::Body);
        }
        let policy_raw = by::rd_arr::<8>(raw, 32).ok_or(Corruption::Body)?;
        let policy = Policy::decode(&policy_raw).ok_or(Corruption::Body)?;
        Ok(Canary {
            identity: Identity(by::rd_u8(raw, 4).ok_or(Corruption::Body)?),
            visible: SlotMap::from_bits(by::rd_u16(raw, 6).ok_or(Corruption::Body)?),
            created_epoch: by::rd_u64(raw, 8).ok_or(Corruption::Body)?,
            label: by::rd_arr::<16>(raw, 16).ok_or(Corruption::Body)?,
            policy,
        })
    }
}

// ---------------------------------------------------------------------------
// Ledger
// ---------------------------------------------------------------------------

/// The guarded bit-log arrays of the live ledger sector, and the boot log of the
/// auxiliary sector.
///
/// The `log_id` discriminants are on-flash values (they are MACed into every cell) and
/// are frozen.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum LogId {
    Epoch = 1,
    Seq = 2,
    AttemptEntry = 3,
    AttemptSuccess = 4,
    PinGen = 5,
    Policy = 6,
    Boot = 7,
}

/// Where one log lives inside its sector.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LogSpec {
    pub id: LogId,
    pub offset: u32,
    pub cell_len: u32,
    pub cells: u32,
}

impl LogSpec {
    pub fn cell_offset(&self, index: u32) -> Option<u32> {
        if index >= self.cells {
            return None;
        }
        self.offset.checked_add(self.cell_len.checked_mul(index)?)
    }
}

/// The live ledger sector map (4096 bytes).
///
/// ESP-SEAL.md 3.7 with its 128-byte reserved tail spent on the `policy_log` that
/// OPEN-QUESTIONS Q5.1 requires. Every array keeps its documented size: the tail reserve
/// that makes `wipe_after <= 25` a frozen constant is untouched, which is the property
/// m3 must not break.
pub(crate) const LEDGER_HEAD_LEN: u32 = 128;
pub(crate) const EPOCH_LOG: LogSpec = LogSpec {
    id: LogId::Epoch,
    offset: 0x0080,
    cell_len: 8,
    cells: 32,
};
pub(crate) const SEQ_LOG: LogSpec = LogSpec {
    id: LogId::Seq,
    offset: 0x0180,
    cell_len: 8,
    cells: 64,
};
pub(crate) const ATTEMPT_ENTRY_LOG: LogSpec = LogSpec {
    id: LogId::AttemptEntry,
    offset: 0x0380,
    cell_len: 8,
    cells: 128,
};
pub(crate) const ATTEMPT_SUCCESS_LOG: LogSpec = LogSpec {
    id: LogId::AttemptSuccess,
    offset: 0x0780,
    cell_len: 8,
    cells: 128,
};
pub(crate) const PIN_GEN_LOG: LogSpec = LogSpec {
    id: LogId::PinGen,
    offset: 0x0b80,
    cell_len: 16,
    cells: 64,
};
pub(crate) const POLICY_LOG: LogSpec = LogSpec {
    id: LogId::Policy,
    offset: 0x0f80,
    cell_len: 16,
    cells: 8,
};

/// The auxiliary sector map (4096 bytes): head plus the boot log of Q53.
pub(crate) const BOOT_LOG: LogSpec = LogSpec {
    id: LogId::Boot,
    offset: 0x0080,
    cell_len: 8,
    cells: 496,
};

/// Sequence numbers are reserved 256 at a time so that advancing the high-water mark
/// does not burn a log cell per seal.
pub(crate) const SEQ_RESERVE: u64 = 256;

/// Rotation fires on the first successful unlock at which the attempt log has fewer than
/// this many cells left. The reserve is the maximum permitted `wipe_after`, so a failure
/// streak long enough to reach the end of the log would have triggered a wipe first.
pub(crate) const ATTEMPT_TAIL_RESERVE: u32 = crate::config::WIPE_AFTER_MAX as u32;

/// The 128-byte ledger head.
///
/// ```text
/// off  len  field
/// 0x00   4  magic b"ESLC"
/// 0x04   2  format_ver
/// 0x06   1  side
/// 0x07   1  MBZ
/// 0x08   4  rotation_ctr
/// 0x0C   4  MBZ
/// 0x10   8  epoch_base
/// 0x18   8  seq_base            in units of SEQ_RESERVE
/// 0x20  32  pin_gen_current[4]
/// 0x40   4  failures_base       Q5.4
/// 0x44   4  policy_gen_base
/// 0x48   8  policy_current      the 8 policy bytes in force at rotation
/// 0x50  32  MBZ
/// 0x70  16  head_mac
/// ```
///
/// `policy_gen_base` and `policy_current` are not in ESP-SEAL.md or Q5.1 and are required
/// by them: Q5.1 defines `policy_gen` as "the cell's index plus one", which restarts at
/// every rotation and would let a rotation silently roll the policy generation backwards.
/// Carrying a base in the head keeps the generation device-global and monotonic, and the
/// cell still carries its own generation so the array stays self-describing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct LedgerHead {
    pub side: u8,
    pub rotation_ctr: u32,
    pub epoch_base: u64,
    pub seq_base: u64,
    pub pin_gen_current: [u64; 4],
    pub failures_base: u32,
    pub policy_gen_base: u32,
    pub policy_current: [u8; 8],
}

impl LedgerHead {
    pub fn encode(&self, guard_key: &[u8; 32]) -> [u8; LEDGER_HEAD_LEN as usize] {
        let mut b = [0u8; LEDGER_HEAD_LEN as usize];
        let _ = by::wr(&mut b, 0x00, MAGIC_LEDGER);
        let _ = by::wr_u16(&mut b, 0x04, FORMAT_VERSION);
        let _ = by::wr_u8(&mut b, 0x06, self.side);
        let _ = by::wr_u32(&mut b, 0x08, self.rotation_ctr);
        let _ = by::wr_u64(&mut b, 0x10, self.epoch_base);
        let _ = by::wr_u64(&mut b, 0x18, self.seq_base);
        for (i, g) in self.pin_gen_current.iter().enumerate() {
            let off = 0x20usize.saturating_add(i.saturating_mul(8));
            let _ = by::wr_u64(&mut b, off, *g);
        }
        let _ = by::wr_u32(&mut b, 0x40, self.failures_base);
        let _ = by::wr_u32(&mut b, 0x44, self.policy_gen_base);
        let _ = by::wr(&mut b, 0x48, &self.policy_current);
        let mac = mac16(guard_key, &[b"ESLC", by::rd(&b, 0, 0x70).unwrap_or(&[])]);
        let _ = by::wr(&mut b, 0x70, &mac);
        b
    }

    pub fn decode(raw: &[u8], guard_key: &[u8; 32]) -> Option<LedgerHead> {
        if by::rd(raw, 0, 4)? != MAGIC_LEDGER {
            return None;
        }
        if by::rd_u16(raw, 0x04)? != FORMAT_VERSION {
            return None;
        }
        let covered = by::rd(raw, 0, 0x70)?;
        let stored = by::rd(raw, 0x70, 16)?;
        if !crate::crypto::ct_eq(&mac16(guard_key, &[b"ESLC", covered]), stored) {
            return None;
        }
        let mut pin_gen_current = [0u64; 4];
        for (i, g) in pin_gen_current.iter_mut().enumerate() {
            *g = by::rd_u64(raw, 0x20usize.saturating_add(i.saturating_mul(8)))?;
        }
        Some(LedgerHead {
            side: by::rd_u8(raw, 0x06)?,
            rotation_ctr: by::rd_u32(raw, 0x08)?,
            epoch_base: by::rd_u64(raw, 0x10)?,
            seq_base: by::rd_u64(raw, 0x18)?,
            pin_gen_current,
            failures_base: by::rd_u32(raw, 0x40)?,
            policy_gen_base: by::rd_u32(raw, 0x44)?,
            policy_current: by::rd_arr::<8>(raw, 0x48)?,
        })
    }
}

/// The auxiliary sector head, carrying the boot log's base and Q53's `acknowledged_at`.
///
/// ```text
/// 0x00   4  magic b"ESLA"
/// 0x04   2  format_ver
/// 0x06   1  side
/// 0x07   1  log_id            the boot log's id, so a future second array is unambiguous
/// 0x08   4  rotation_ctr
/// 0x10   8  boot_base
/// 0x18   8  acknowledged_at
/// 0x70  16  head_mac
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct AuxHead {
    pub side: u8,
    pub rotation_ctr: u32,
    pub boot_base: u64,
    pub acknowledged_at: u64,
}

impl AuxHead {
    pub fn encode(&self, guard_key: &[u8; 32]) -> [u8; LEDGER_HEAD_LEN as usize] {
        let mut b = [0u8; LEDGER_HEAD_LEN as usize];
        let _ = by::wr(&mut b, 0x00, MAGIC_AUX);
        let _ = by::wr_u16(&mut b, 0x04, FORMAT_VERSION);
        let _ = by::wr_u8(&mut b, 0x06, self.side);
        let _ = by::wr_u8(&mut b, 0x07, LogId::Boot as u8);
        let _ = by::wr_u32(&mut b, 0x08, self.rotation_ctr);
        let _ = by::wr_u64(&mut b, 0x10, self.boot_base);
        let _ = by::wr_u64(&mut b, 0x18, self.acknowledged_at);
        let mac = mac16(guard_key, &[b"ESLA", by::rd(&b, 0, 0x70).unwrap_or(&[])]);
        let _ = by::wr(&mut b, 0x70, &mac);
        b
    }

    pub fn decode(raw: &[u8], guard_key: &[u8; 32]) -> Option<AuxHead> {
        if by::rd(raw, 0, 4)? != MAGIC_AUX {
            return None;
        }
        if by::rd_u16(raw, 0x04)? != FORMAT_VERSION || by::rd_u8(raw, 0x07)? != LogId::Boot as u8 {
            return None;
        }
        let covered = by::rd(raw, 0, 0x70)?;
        let stored = by::rd(raw, 0x70, 16)?;
        if !crate::crypto::ct_eq(&mac16(guard_key, &[b"ESLA", covered]), stored) {
            return None;
        }
        Some(AuxHead {
            side: by::rd_u8(raw, 0x06)?,
            rotation_ctr: by::rd_u32(raw, 0x08)?,
            boot_base: by::rd_u64(raw, 0x10)?,
            acknowledged_at: by::rd_u64(raw, 0x18)?,
        })
    }
}

// ---------------------------------------------------------------------------
// Guarded cells
// ---------------------------------------------------------------------------

/// The guard value of a plain 8-byte tick cell:
/// `HMAC(guard_key, b"ESLG" || side || rotation_ctr || log_id || u16_le(i))[0..8]`.
///
/// Erased flash is all ones and the guard has roughly half its bits clear, so a program
/// interrupted mid-cell leaves a value matching neither. A single fault would have to
/// corrupt data and guard consistently, and it cannot: the guard is keyed by a key the
/// attacker cannot read.
pub(crate) fn tick_cell(guard_key: &[u8; 32], side: u8, rotation: u32, log: LogId, i: u32) -> [u8; 8] {
    let idx = (i.min(u16::MAX as u32) as u16).to_le_bytes();
    mac8(
        guard_key,
        &[
            b"ESLG",
            &[side],
            &rotation.to_le_bytes(),
            &[log as u8],
            &idx,
        ],
    )
}

/// A 16-byte `pin_gen_log` cell: `identity | MBZ[3] | new_gen u32 | guard[8]`.
pub(crate) fn pin_gen_cell(
    guard_key: &[u8; 32],
    side: u8,
    rotation: u32,
    i: u32,
    identity: u8,
    new_gen: u32,
) -> [u8; 16] {
    let mut cell = [0u8; 16];
    let _ = by::wr_u8(&mut cell, 0, identity);
    let _ = by::wr_u32(&mut cell, 4, new_gen);
    let idx = (i.min(u16::MAX as u32) as u16).to_le_bytes();
    let guard = mac8(
        guard_key,
        &[
            b"ESLP",
            &[side],
            &rotation.to_le_bytes(),
            &idx,
            &[identity],
            &new_gen.to_le_bytes(),
        ],
    );
    let _ = by::wr(&mut cell, 8, &guard);
    cell
}

/// Parse a `pin_gen_log` cell, verifying its guard.
pub(crate) fn parse_pin_gen_cell(
    raw: &[u8],
    guard_key: &[u8; 32],
    side: u8,
    rotation: u32,
    i: u32,
) -> Option<(u8, u32)> {
    let identity = by::rd_u8(raw, 0)?;
    if !by::all_zero(by::rd(raw, 1, 3)?) {
        return None;
    }
    let new_gen = by::rd_u32(raw, 4)?;
    let want = pin_gen_cell(guard_key, side, rotation, i, identity, new_gen);
    if crate::crypto::ct_eq(&want, by::rd(raw, 0, 16)?) {
        Some((identity, new_gen))
    } else {
        None
    }
}

/// A 16-byte `policy_log` cell: `policy_bytes[8] | guard[8]`, guard tag `b"ESLY"`.
pub(crate) fn policy_cell(
    guard_key: &[u8; 32],
    side: u8,
    rotation: u32,
    i: u32,
    policy: &[u8; 8],
) -> [u8; 16] {
    let mut cell = [0u8; 16];
    let _ = by::wr(&mut cell, 0, policy);
    let idx = (i.min(u16::MAX as u32) as u16).to_le_bytes();
    let guard = mac8(
        guard_key,
        &[b"ESLY", &[side], &rotation.to_le_bytes(), &idx, policy],
    );
    let _ = by::wr(&mut cell, 8, &guard);
    cell
}

/// Parse a `policy_log` cell, verifying its guard AND that the policy it carries is a
/// value this format defines. A cell that verifies but decodes to nonsense is malformed,
/// which resolves to the strict default.
pub(crate) fn parse_policy_cell(
    raw: &[u8],
    guard_key: &[u8; 32],
    side: u8,
    rotation: u32,
    i: u32,
) -> Option<Policy> {
    let policy_raw = by::rd_arr::<8>(raw, 0)?;
    let want = policy_cell(guard_key, side, rotation, i, &policy_raw);
    if !crate::crypto::ct_eq(&want, by::rd(raw, 0, 16)?) {
        return None;
    }
    Policy::decode(&policy_raw)
}

/// Body framing: `plaintext = u32_le(true_len) || payload || zero_pad`.
///
/// Every record is padded to the full slot capacity and the true length lives inside the
/// AEAD. The sector is erased and rewritten wholesale anyway, so padding is free, and a
/// plaintext length in the header would leak label lengths, cosigner counts, and which
/// slots hold filler.
pub(crate) fn frame_plaintext(payload: &[u8], out: &mut [u8]) -> Option<()> {
    let len = u32::try_from(payload.len()).ok()?;
    for b in out.iter_mut() {
        *b = 0;
    }
    by::wr_u32(out, 0, len)?;
    by::wr(out, 4, payload)?;
    Some(())
}

/// Inverse of [`frame_plaintext`], with the pad check the format requires.
pub(crate) fn unframe_plaintext(buf: &[u8]) -> Result<&[u8], Corruption> {
    let len = by::rd_u32(buf, 0).ok_or(Corruption::LengthPrefix)? as usize;
    let body = by::rd(buf, 4, len).ok_or(Corruption::LengthPrefix)?;
    let pad_off = 4usize.checked_add(len).ok_or(Corruption::LengthPrefix)?;
    let pad = buf.get(pad_off..).ok_or(Corruption::LengthPrefix)?;
    if !by::all_zero(pad) {
        return Err(Corruption::Padding);
    }
    Ok(body)
}
