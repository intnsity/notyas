// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Seal observation, for the one invariant an argument on paper cannot guarantee.
//!
//! ESP-SEAL.md 8.1's invariant I6 is that **no `(key, nonce)` pair is ever derived twice
//! over the entire life of the device**, across every power cut, wipe and PIN change. The
//! argument for it is short - the nonce is a pure function of `RecordInfo`, which carries
//! a strictly increasing `seal_seq` bounded below by a one-way flash high-water mark
//! advanced before use, plus a one-way `wipe_epoch` - and the argument is exactly the kind
//! that is right until an off-by-one in the reserve-ahead makes it wrong. So the fuzzer
//! observes the real thing instead of trusting the reasoning.
//!
//! What is observed is the SEAL side only. Re-deriving the same pair to *open* a record is
//! not merely harmless, it is the normal case: [`crate::records`] derives twice before a
//! write as a fault-injection countermeasure and a third time from the flash-resident
//! header afterwards. Two-time pad requires two *encryptions*, so an encryption is what
//! gets counted.
//!
//! The log is thread-local and is installed by an RAII guard, so a test that wants it pays
//! for it and tests running in parallel cannot pollute each other. With the `testkit`
//! feature off, none of this exists and the call site in [`crate::crypto`] compiles away.

use alloc::vec::Vec;
use core::cell::RefCell;

/// One AEAD encryption, as the harness sees it.
///
/// The key is held in the clear here. That is acceptable exactly once: this type only
/// exists in a host test build, where the MAC key is a compile-time constant anyway.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SealRecord {
    pub key: [u8; 32],
    pub nonce: [u8; 12],
}

std::thread_local! {
    static SEALS: RefCell<Option<Vec<SealRecord>>> = const { RefCell::new(None) };
}

/// Called from the AEAD seal path. A no-op unless a [`DerivationLog`] is live on this
/// thread, so the cost outside the fuzzer is one thread-local read.
pub(crate) fn note_seal(key: &[u8; 32], nonce: &[u8; 12]) {
    SEALS.with(|cell| {
        if let Ok(mut slot) = cell.try_borrow_mut() {
            if let Some(log) = slot.as_mut() {
                log.push(SealRecord {
                    key: *key,
                    nonce: *nonce,
                });
            }
        }
    });
}

/// Records every AEAD encryption performed on this thread while it is alive.
///
/// One guard is one simulated device's lifetime. The fuzzer creates it before it builds
/// the store and drops it after the final assertion, so "twice over the life of the
/// device" is exactly the scope the guard covers.
#[derive(Debug)]
pub struct DerivationLog {
    /// Not `()` so the type cannot be constructed by a caller outside this module.
    _seal: (),
}

impl DerivationLog {
    /// Install a fresh log on this thread, discarding any previous one.
    pub fn start() -> DerivationLog {
        SEALS.with(|cell| {
            if let Ok(mut slot) = cell.try_borrow_mut() {
                *slot = Some(Vec::new());
            }
        });
        DerivationLog { _seal: () }
    }

    /// Every seal recorded so far, in order.
    pub fn seals(&self) -> Vec<SealRecord> {
        SEALS.with(|cell| {
            cell.try_borrow()
                .ok()
                .and_then(|slot| slot.clone())
                .unwrap_or_default()
        })
    }

    /// How many encryptions have happened.
    pub fn len(&self) -> usize {
        SEALS.with(|cell| {
            cell.try_borrow()
                .ok()
                .and_then(|slot| slot.as_ref().map(Vec::len))
                .unwrap_or(0)
        })
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The first `(key, nonce)` pair used to encrypt twice, if any. This returning `Some`
    /// is a two-time pad and is the most serious failure the fuzzer can report.
    pub fn duplicate(&self) -> Option<SealRecord> {
        let seals = self.seals();
        let mut seen: Vec<SealRecord> = Vec::with_capacity(seals.len());
        for s in seals {
            if seen.iter().any(|p| p.key == s.key && p.nonce == s.nonce) {
                return Some(s);
            }
            seen.push(s);
        }
        None
    }

    /// Distinct nonces observed. Equal to `len()` in a healthy run; a smaller number means
    /// one nonce served two keys, which is legal but worth seeing in a report.
    pub fn distinct_nonces(&self) -> usize {
        let mut seen: Vec<[u8; 12]> = Vec::new();
        for s in self.seals() {
            if !seen.contains(&s.nonce) {
                seen.push(s.nonce);
            }
        }
        seen.len()
    }
}

impl Drop for DerivationLog {
    fn drop(&mut self) {
        SEALS.with(|cell| {
            if let Ok(mut slot) = cell.try_borrow_mut() {
                *slot = None;
            }
        });
    }
}
