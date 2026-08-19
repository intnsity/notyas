// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The unlocked-device capability.
//!
//! A [`Session`] owns exactly one secret: the 32-byte `bound` value that every record key
//! descends from. It is PIN-equivalent for this device while it lives, which is why it is
//! the only thing in the crate that outlives a single call, why it has no `Clone`, and why
//! its `Drop` is a wipe point rather than a formality.
//!
//! Every vault operation on sealed data takes `&Session`, so "you must be unlocked" is a
//! type rule and not a runtime check the caller could forget.
//!
//! The session is deliberately a value the caller holds rather than a borrow of the vault.
//! ESP-SEAL.md 5.3 sketches `Session<'s, F, M>` borrowing the store, which cannot express
//! `Vault::set_policy(&mut self, session: &Session)` at all: the session would already
//! hold the unique borrow. WALLET-API.md 2.5's standalone `Session` is the shape that
//! works, and it is the one the ratified `Vault::set_policy` and `Vault::remove_pin`
//! signatures require.

use crate::crypto::Bound;
use crate::slot::{Identity, SlotMap};

/// How long an idle session lives before the product should drop it. Fed by the caller;
/// the crate has no clock of its own.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Liveness {
    Live { idle_ms: u32 },
    Expired,
}

/// Proof that a PIN was known, plus the key material that proof bought.
pub struct Session {
    bound: Bound,
    identity: Identity,
    visible: SlotMap,
    /// The generation this identity's records carried when the session opened. A session
    /// is invalidated by anything that moves it, which is what makes a stale session
    /// unable to write a record nobody can read.
    pin_gen: u32,
    /// The one-way epoch at unlock. A wipe bumps it and every session in existence dies
    /// with it, which is the property that keeps a pre-wipe session from writing a record
    /// into a post-wipe store.
    epoch: u64,
    idle_ms: u32,
    auto_lock_ms: u32,
}

/// Default idle timeout. A product overrides it; the crate needs a value that is not zero
/// so a caller that never calls [`Session::set_auto_lock_ms`] still gets a timeout.
pub const DEFAULT_AUTO_LOCK_MS: u32 = 120_000;

impl Session {
    pub(crate) fn new(
        bound: Bound,
        identity: Identity,
        visible: SlotMap,
        pin_gen: u32,
        epoch: u64,
    ) -> Session {
        Session {
            bound,
            identity,
            visible,
            pin_gen,
            epoch,
            idle_ms: 0,
            auto_lock_ms: DEFAULT_AUTO_LOCK_MS,
        }
    }

    pub fn identity(&self) -> Identity {
        self.identity
    }

    /// The slots this identity should be shown. A UI aid for the duress case, not a
    /// security control: cryptography decides what an identity can open, the mask only
    /// decides what the product should bother displaying.
    pub fn visible_slots(&self) -> SlotMap {
        self.visible
    }

    pub(crate) fn bound(&self) -> &Bound {
        &self.bound
    }

    pub(crate) fn pin_gen(&self) -> u32 {
        self.pin_gen
    }

    pub(crate) fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Fed by the firmware main loop. The only notion of time anywhere in the crate, and
    /// it arrives from outside so the crate stays a pure function of its inputs.
    pub fn tick(&mut self, elapsed_ms: u32) -> Liveness {
        self.idle_ms = self.idle_ms.saturating_add(elapsed_ms);
        self.liveness()
    }

    pub fn liveness(&self) -> Liveness {
        if self.idle_ms >= self.auto_lock_ms {
            Liveness::Expired
        } else {
            Liveness::Live {
                idle_ms: self.idle_ms,
            }
        }
    }

    /// User activity resets the idle timer.
    pub fn touch(&mut self) {
        self.idle_ms = 0;
    }

    pub fn auto_lock_ms(&self) -> u32 {
        self.auto_lock_ms
    }

    /// Milliseconds of idle left before [`Session::tick`] would report `Expired`.
    ///
    /// Here rather than in the product because the timeout and the elapsed time are both
    /// this type's state: a caller recomputing it from `auto_lock_ms` and a `Liveness` is
    /// a second copy of one subtraction, and the two drift the moment `set_auto_lock_ms`
    /// is called from a settings screen.
    pub fn remaining_ms(&self) -> u32 {
        self.auto_lock_ms.saturating_sub(self.idle_ms)
    }

    pub fn set_auto_lock_ms(&mut self, ms: u32) {
        self.auto_lock_ms = ms;
    }

    /// Explicit lock. `Drop` performs the same wipe, so forgetting to call this is safe
    /// and calling it is documentation at the site where the decision was made.
    pub fn lock(self) {}
}

impl core::fmt::Debug for Session {
    /// Prints the identity and the idle time. Never the key, never the epoch's effect on
    /// it, and never anything that would let a log reconstruct a secret.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Session")
            .field("identity", &self.identity)
            .field("idle_ms", &self.idle_ms)
            .field("bound", &"<redacted>")
            .finish()
    }
}
