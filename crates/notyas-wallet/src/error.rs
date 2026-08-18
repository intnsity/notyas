// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The error taxonomy.
//!
//! The central requirement (ESP-SEAL.md 5.4) is that **wrong PIN, corrupt record and
//! hardware fault are three different things**, because they lead to three different
//! product behaviours: try again, restore from backup, stop trusting this board. Every
//! type here exists to keep those three from collapsing into one.

use crate::config::ConfigError;
use crate::hal::KeyProvenance;
use crate::slot::SlotId;

/// Why a record could not be parsed or accepted. Each variant is a distinct thing that
/// went wrong on flash, and each maps to different user-facing copy.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Corruption {
    /// Header torn, forged, or written by another device.
    HeaderMac,
    /// Body torn or bit-rotted. Detected BEFORE any Argon2 spend.
    BodyDigest,
    /// The AEAD tag did not verify for a record that was expected to open.
    Tag,
    /// Non-zero pad inside the AEAD.
    Padding,
    /// In-AEAD length exceeds capacity.
    LengthPrefix,
    /// `wipe_epoch` is not the current one: superseded by a wipe.
    EpochStale,
    /// `pin_gen` is not in the current set: superseded by a PIN change.
    PinGenStale,
    /// Record KDF parameters disagree with the superblock.
    ParamMismatch,
    Magic,
    Version,
    Geometry,
    /// The plaintext body of a superblock or canary did not have the shape its magic
    /// promised.
    Body,
}

/// Structural evidence of interference. A signal for the product to display, not an
/// automatic wipe: a genuine mid-program power cut produces several of these, and
/// destroying a user's wallet because the battery died is a worse failure than counting
/// one extra attempt.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TamperKind {
    /// Records present, ledger blank: the cheap counter-reset attack.
    LedgerMissing,
    /// Two live ledger sectors with equal rotation counters.
    LedgerAmbiguous,
    /// Records outrank the ledger's high-water marks (MOUNT M7).
    LedgerRollback,
    /// A bit-log cell failed its keyed guard.
    GuardMismatch,
    /// A non-erased cell after the first erased one.
    LogHole,
    /// `device_tag` mismatch: this flash came from another board.
    ForeignDevice,
    /// The canary's in-AEAD policy witness disagrees with the ledger at the same
    /// generation, which is impossible without forgery (OPEN-QUESTIONS Q5.1).
    PolicyMismatch,
}

impl TamperKind {
    const ALL: [TamperKind; 7] = [
        TamperKind::LedgerMissing,
        TamperKind::LedgerAmbiguous,
        TamperKind::LedgerRollback,
        TamperKind::GuardMismatch,
        TamperKind::LogHole,
        TamperKind::ForeignDevice,
        TamperKind::PolicyMismatch,
    ];

    fn bit(self) -> u16 {
        1u16 << (self as u16)
    }
}

/// A set of [`TamperKind`]s. Mount accumulates them rather than returning the first,
/// because "the ledger has a hole AND the policy witness disagrees" is a different
/// situation from either alone and the product deserves to see both.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct TamperFlags(u16);

impl TamperFlags {
    pub const NONE: TamperFlags = TamperFlags(0);

    pub fn insert(&mut self, kind: TamperKind) {
        self.0 |= kind.bit();
    }

    pub fn contains(self, kind: TamperKind) -> bool {
        self.0 & kind.bit() != 0
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The kinds present, in enum order. Fixed order so a UI listing them is stable.
    pub fn iter(self) -> impl Iterator<Item = TamperKind> {
        TamperKind::ALL.into_iter().filter(move |k| self.contains(*k))
    }

    /// The first kind present, for the state that can only carry one.
    pub fn first(self) -> Option<TamperKind> {
        self.iter().next()
    }
}

/// The backend or the silicon misbehaved. Never a statement about the PIN.
#[derive(Debug)]
pub enum HardwareFault<FE, ME> {
    Flash(FE),
    Mac(ME),
    /// The two independent `okm` derivations disagreed (SEAL S3). Glitch suspected.
    DerivationMismatch,
    /// The record read back from flash did not match what was written (SEAL S8).
    WriteVerify,
    /// A ledger cell read back differently from what was programmed.
    CellVerify,
}

/// Why SET-POLICY refused. Separated from the storage errors because none of these is a
/// failure: they are the policy engine declining, and the UI shows them as sentences.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PolicyRefusal {
    /// `wipe_after` outside 3..=25 and not the 0 sentinel.
    OutOfRange,
    /// Lowering N below the failures already accumulated would wipe on commit.
    BelowAccumulatedFailures { failures: u32 },
    /// Occupancy is not settable in 0.2.0.
    OccupancyNotSettable,
    /// Disabling the wipe requires a PIN of at least this many characters under the
    /// product's configuration. Not the shipped answer (Q62(b)), but expressible.
    PinTooShortToDisableWipe { min_len: u8 },
    /// The policy log is full and could not be rotated.
    LogFull,
}

/// The general failure type for operations that are not the unlock.
#[derive(Debug)]
pub enum StorageError<FE, ME> {
    Hardware(HardwareFault<FE, ME>),
    Corrupt {
        slot: SlotId,
        detail: Corruption,
    },
    Tamper(TamperKind),
    /// The store has never been formatted.
    NotFormatted,
    /// The store is at its attempt limit and awaiting its wipe.
    Locked,
    /// The operation is not legal in the store's current state.
    WrongState,
    /// The payload is larger than the slot class can hold, or a log is exhausted.
    Capacity,
    Policy(PolicyRefusal),
    /// A `confirm_pin` did not match the live session.
    PinMismatch,
    /// `Scratch` too small for the store's parameters.
    Scratch {
        required_blocks: usize,
    },
    /// An internal invariant did not hold. This is a bug in this crate, reported with a
    /// stable code the user can quote rather than a panic that loses the context.
    Invariant(&'static str),
}

/// Mount is the only operation that can decide the store is unusable rather than merely
/// in a bad state, so it has its own type.
#[derive(Debug)]
pub enum MountError<FE, ME> {
    Hardware(HardwareFault<FE, ME>),
    /// The backend's geometry does not match the compile-time layout.
    Geometry,
    /// The superblock's recorded layout does not match the compile-time layout. Refusing
    /// is the point: a future firmware with a different map must not misread this one.
    LayoutMismatch,
    /// `device_tag` says this flash was formatted by a different board.
    Foreign,
    /// Format or suite version this firmware does not implement.
    Version,
    /// The factory HMAC key was never burned (ESP-SEAL.md 4.3, ratified Q45).
    Unprovisioned,
    /// The backend's provenance is not in `Config::accept_provenance`.
    Provenance(KeyProvenance),
    Config(ConfigError),
    Invariant(&'static str),
}

/// The unlock path, where the difference between "an attempt was consumed" and "no
/// attempt was consumed" is the whole security property.
#[derive(Debug)]
pub enum UnlockError<FE, ME> {
    /// The AEAD tag did not verify for any identity. AN ATTEMPT WAS CONSUMED.
    /// `attempts_remaining` is `None` when the wipe is disabled.
    WrongPin { attempts_remaining: Option<u8> },
    /// This attempt was the last one; every record has been destroyed and the epoch
    /// bumped. AN ATTEMPT WAS CONSUMED.
    Wiped { epoch: u64 },
    /// No canary could be parsed. NO ATTEMPT CONSUMED - this is not a guess.
    Corrupt { slot: SlotId, detail: Corruption },
    /// Structural evidence of interference. NO ATTEMPT CONSUMED. Fail closed: refuse.
    Tamper(TamperKind),
    NotFormatted,
    /// Already at zero attempts and awaiting its wipe.
    Locked,
    Scratch { required_blocks: usize },
    Provenance(KeyProvenance),
    /// May or may not have consumed an attempt; `attempt_consumed` says which, and it is
    /// never a guess about the PIN.
    Hardware {
        source: HardwareFault<FE, ME>,
        attempt_consumed: bool,
    },
    Invariant(&'static str),
}

/// FORMAT's failures. Distinct from [`StorageError`] mostly so that "this store already
/// has a PIN" cannot be confused with "this write failed".
#[derive(Debug)]
pub enum FormatError<FE, ME> {
    /// The store is neither blank nor wiped.
    AlreadyFormatted,
    Scratch { required_blocks: usize },
    Provenance(KeyProvenance),
    Tamper(TamperKind),
    Policy(PolicyRefusal),
    Hardware(HardwareFault<FE, ME>),
    Invariant(&'static str),
}

/// CHANGE-PIN consumes the session, so its error must say whether the old PIN still
/// works. It always does before the commit point and never does after it, and
/// `old_pin_still_valid` is that fact rather than an inference the caller has to make.
#[derive(Debug)]
pub struct ChangePinError<FE, ME> {
    pub source: StorageError<FE, ME>,
    pub old_pin_still_valid: bool,
}

impl<FE, ME> From<HardwareFault<FE, ME>> for StorageError<FE, ME> {
    fn from(f: HardwareFault<FE, ME>) -> Self {
        StorageError::Hardware(f)
    }
}

impl<FE, ME> From<HardwareFault<FE, ME>> for MountError<FE, ME> {
    fn from(f: HardwareFault<FE, ME>) -> Self {
        MountError::Hardware(f)
    }
}

impl<FE, ME> From<HardwareFault<FE, ME>> for FormatError<FE, ME> {
    fn from(f: HardwareFault<FE, ME>) -> Self {
        FormatError::Hardware(f)
    }
}

impl<FE, ME> From<StorageError<FE, ME>> for FormatError<FE, ME> {
    fn from(e: StorageError<FE, ME>) -> Self {
        match e {
            StorageError::Hardware(h) => FormatError::Hardware(h),
            StorageError::Tamper(t) => FormatError::Tamper(t),
            StorageError::Policy(p) => FormatError::Policy(p),
            StorageError::Scratch { required_blocks } => FormatError::Scratch { required_blocks },
            StorageError::Invariant(m) => FormatError::Invariant(m),
            _ => FormatError::AlreadyFormatted,
        }
    }
}

impl<FE, ME> From<StorageError<FE, ME>> for UnlockError<FE, ME> {
    /// Used only on paths BEFORE the counted region, which is why `attempt_consumed` is
    /// false here. Anything inside the counted region constructs its error explicitly.
    fn from(e: StorageError<FE, ME>) -> Self {
        match e {
            StorageError::Hardware(h) => UnlockError::Hardware {
                source: h,
                attempt_consumed: false,
            },
            StorageError::Corrupt { slot, detail } => UnlockError::Corrupt { slot, detail },
            StorageError::Tamper(t) => UnlockError::Tamper(t),
            StorageError::NotFormatted | StorageError::WrongState => UnlockError::NotFormatted,
            StorageError::Locked => UnlockError::Locked,
            StorageError::Scratch { required_blocks } => UnlockError::Scratch { required_blocks },
            StorageError::Capacity => UnlockError::Invariant("capacity on unlock path"),
            StorageError::Policy(_) => UnlockError::Invariant("policy refusal on unlock path"),
            StorageError::PinMismatch => UnlockError::Invariant("pin mismatch on unlock path"),
            StorageError::Invariant(m) => UnlockError::Invariant(m),
        }
    }
}
