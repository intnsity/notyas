// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Slot identity and the fixed geometry of the records region.
//!
//! ESP-SEAL.md 3.2 is normative. Every slot in every class is an A/B pair of the same
//! shape; that uniformity is deliberate and it is what keeps the election, cleanup and
//! filler paths free of per-class special cases.

use crate::config::Layout;

/// The four record classes. The discriminants are on-flash values and are frozen.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum SlotClass {
    /// Store-wide plaintext descriptor. One slot, no AEAD (there is no PIN at mount).
    Superblock = 0,
    /// One per PIN identity. Opening it is what proves a PIN.
    Canary = 1,
    /// Wallet records.
    Payload = 2,
    /// Multisig registration records. Two sectors per side.
    Registry = 3,
}

impl SlotClass {
    pub(crate) const ALL: [SlotClass; 4] = [
        SlotClass::Superblock,
        SlotClass::Canary,
        SlotClass::Payload,
        SlotClass::Registry,
    ];

    /// Sectors occupied by ONE side of a slot in this class.
    pub const fn side_sectors(self, layout: &Layout) -> u32 {
        match self {
            SlotClass::Superblock | SlotClass::Canary => 1,
            SlotClass::Payload => layout.payload_slot_sectors as u32,
            SlotClass::Registry => layout.registry_slot_sectors as u32,
        }
    }

    /// Number of slots of this class.
    pub const fn count(self, layout: &Layout) -> u8 {
        match self {
            SlotClass::Superblock => 1,
            SlotClass::Canary => layout.canary_slots,
            SlotClass::Payload => layout.payload_slots,
            SlotClass::Registry => layout.registry_slots,
        }
    }

    /// Bytes in one side, header included.
    ///
    /// Saturating throughout this block rather than wrapping. A layout whose arithmetic
    /// overflows is refused by `Config::validate` long before a record is written, and
    /// until then every consumer of these numbers treats them as an upper bound, so
    /// clamping is the reading that stays safe.
    pub const fn side_bytes(self, layout: &Layout) -> u32 {
        self.side_sectors(layout).saturating_mul(layout.sector_size)
    }

    /// Bytes available to the body after the 80-byte header.
    pub const fn body_capacity(self, layout: &Layout) -> u32 {
        self.side_bytes(layout)
            .saturating_sub(crate::format::HEADER_LEN as u32)
    }

    /// Largest plaintext this class can hold: body minus the AEAD tag and the in-AEAD
    /// length prefix.
    pub const fn max_payload(self, layout: &Layout) -> u32 {
        self.body_capacity(layout)
            .saturating_sub(crate::format::TAG_LEN as u32)
            .saturating_sub(4)
    }
}

/// A slot, identified by class and index. Constructed only through [`SlotId::new`],
/// which is the only place a range check exists.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct SlotId {
    class: SlotClass,
    index: u8,
}

impl SlotId {
    pub fn new(class: SlotClass, index: u8, layout: &Layout) -> Option<SlotId> {
        if index < class.count(layout) {
            Some(SlotId { class, index })
        } else {
            None
        }
    }

    /// The superblock, which is the one slot whose index is structurally zero.
    pub const fn superblock() -> SlotId {
        SlotId {
            class: SlotClass::Superblock,
            index: 0,
        }
    }

    pub const fn class(self) -> SlotClass {
        self.class
    }

    pub const fn index(self) -> u8 {
        self.index
    }

    /// Byte offset of one side within the records region.
    ///
    /// The map is the frozen one from ESP-SEAL.md 3.2: superblock 0..1, canaries 2..9,
    /// payloads 10..25, registries 26..57, and 58..63 reserved and erased.
    pub(crate) fn side_offset(self, side: Side, layout: &Layout) -> Option<u32> {
        let sector = self.first_sector(layout)?;
        let per_side = self.class.side_sectors(layout);
        let side_sector = sector.checked_add(per_side.checked_mul(side as u32)?)?;
        side_sector.checked_mul(layout.sector_size)
    }

    /// First sector of the A side of this slot.
    fn first_sector(self, layout: &Layout) -> Option<u32> {
        let per_slot = self.class.side_sectors(layout).checked_mul(2)?;
        let sectors_of = |class: SlotClass| -> u32 {
            (class.count(layout) as u32)
                .saturating_mul(class.side_sectors(layout))
                .saturating_mul(2)
        };
        let base = match self.class {
            SlotClass::Superblock => 0,
            SlotClass::Canary => sectors_of(SlotClass::Superblock),
            SlotClass::Payload => {
                sectors_of(SlotClass::Superblock).saturating_add(sectors_of(SlotClass::Canary))
            }
            SlotClass::Registry => sectors_of(SlotClass::Superblock)
                .saturating_add(sectors_of(SlotClass::Canary))
                .saturating_add(sectors_of(SlotClass::Payload)),
        };
        base.checked_add(per_slot.checked_mul(self.index as u32)?)
    }
}

/// Which half of an A/B pair.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Side {
    A = 0,
    B = 1,
}

impl Side {
    pub(crate) const BOTH: [Side; 2] = [Side::A, Side::B];

    pub(crate) fn other(self) -> Side {
        match self {
            Side::A => Side::B,
            Side::B => Side::A,
        }
    }
}

/// A PIN identity. Index 0 is the primary; 1..=3 are reserved for the duress case that
/// the format supports and the product may or may not expose.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Identity(pub u8);

/// A set of payload and registry slots, as a bit mask.
///
/// Bits 0..8 are payload slots, bits 8..16 registry slots. This is the same encoding as
/// the canary's `visible_slot_mask`, so the UI-facing value and the on-flash value are
/// one type rather than two that must be kept in step.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct SlotMap(u16);

impl SlotMap {
    pub const EMPTY: SlotMap = SlotMap(0);
    pub const ALL: SlotMap = SlotMap(u16::MAX);

    pub const fn bits(self) -> u16 {
        self.0
    }

    pub const fn from_bits(bits: u16) -> SlotMap {
        SlotMap(bits)
    }

    pub fn contains(self, slot: SlotId) -> bool {
        match Self::bit(slot) {
            Some(b) => self.0 & (1u16 << b) != 0,
            None => false,
        }
    }

    pub fn with(mut self, slot: SlotId) -> SlotMap {
        if let Some(b) = Self::bit(slot) {
            self.0 |= 1u16 << b;
        }
        self
    }

    pub fn without(mut self, slot: SlotId) -> SlotMap {
        if let Some(b) = Self::bit(slot) {
            self.0 &= !(1u16 << b);
        }
        self
    }

    pub fn count(self) -> u32 {
        self.0.count_ones()
    }

    fn bit(slot: SlotId) -> Option<u32> {
        match slot.class() {
            SlotClass::Payload if slot.index() < 8 => Some(slot.index() as u32),
            SlotClass::Registry if slot.index() < 8 => Some((slot.index() as u32).saturating_add(8)),
            _ => None,
        }
    }
}

/// What a slot holds, as reported without opening a payload.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SlotState {
    /// Erased, or holding a device-derived filler record.
    Empty,
    /// A real record, sealed under a PIN.
    Occupied { len: u16 },
    /// Present but not openable with the current session's key: another identity's
    /// record, or a corrupt one.
    Opaque,
}
