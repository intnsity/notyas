// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! notyas sealed storage: the PIN key ladder, the A/B record format, the guarded counter
//! ledger and the settable wipe policy.
//!
//! # What this crate is
//!
//! One question, answered for one device: *how do I keep a secret in flash that only
//! comes back when the user types the right PIN on this specific board?*
//!
//! - **Seal and unseal an opaque byte payload under a PIN.** The crate knows nothing
//!   about BIP39, descriptors or wallets; it stores bytes.
//! - **Device binding that costs the attacker the physical board.** Every PIN guess runs
//!   through an HMAC peripheral keyed by a read-protected eFuse block.
//! - **A memory-hard first wall.** Argon2id over the PIN before the HMAC step.
//! - **A fault-hardened attempt counter with erase-at-zero**, and a wipe policy the user
//!   can change - or switch off - from an unlocked session.
//! - **Power-loss-safe storage.** One single-write commit point per operation.
//!
//! `docs/plan-0.2.0/ESP-SEAL.md` is normative for the byte format, the operation-level
//! power-loss analysis and the attack analysis. `OPEN-QUESTIONS.md` Q5 is normative for
//! the settable policy. Where this implementation had to make a call those documents did
//! not settle, the call is marked with a `DEVIATION` comment at the site.
//!
//! # What it is not
//!
//! It is not a secure element. It has no key store hardened against fault injection, no
//! monotonic counter the CPU cannot reach, and no rate limit enforced outside the
//! attacker-controllable processor. The attempt counter converts "unlimited guesses" into
//! "`wipe_after` guesses per full-flash snapshot-and-restore cycle", which is a real
//! slowdown and not a wall. It does not protect RAM after an unseal, it is not a backup,
//! and it cannot defend a weak PIN against an attacker who has extracted the eFuse key.
//!
//! # Shape
//!
//! Two traits are the whole hardware surface ([`Flash`] and [`DeviceMac`]), and one
//! borrowed buffer is the whole allocation policy ([`Scratch`]). Everything above them is
//! a pure function of `(flash bytes, MAC responses, caller inputs)` - no clock, no RNG,
//! no interrupt - which is what makes the host power-loss fuzzer possible with no silicon.
//!
//! ```ignore
//! let mut vault = Vault::mount(flash, mac, &CONFIG)?;
//! let session = vault.unlock(&pin, Scratch::new(&mut blocks))?;
//! let n = vault.read(&session, slot, &mut out)?;
//! ```

#![no_std]
#![forbid(unsafe_code)]
// A panic inside a sealing operation is not merely a crash: it unwinds past the point
// where the caller could have been told what happened, on a device whose whole job is to
// explain refusals, and it skips the drop glue that zeroizes the secrets on the stack.
// So the crate does not panic, and the compiler is asked to prove it.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::integer_division_remainder_used
)]
#![deny(missing_debug_implementations)]

extern crate alloc;

// The simulation backends and the power-loss harness are host code and use `std` freely.
// They are behind a non-default feature that must never be enabled in a firmware build,
// and `tools/build-graph-check.sh` asserts that.
#[cfg(feature = "testkit")]
extern crate std;

mod bytes;
pub mod config;
mod crypto;
pub mod error;
mod format;
pub mod hal;
mod ledger;
mod pin;
#[cfg(feature = "testkit")]
mod probe;
mod records;
mod session;
mod slot;
mod vault;

#[cfg(feature = "testkit")]
pub mod fuzz;
#[cfg(feature = "testkit")]
pub mod sim;

pub use config::{
    Config, ConfigError, KdfParams, Layout, Occupancy, Policy, PolicyRequest, WIPE_AFTER_MAX,
    WIPE_AFTER_MIN,
};
pub use error::{
    ChangePinError, Corruption, FormatError, HardwareFault, MountError, PolicyRefusal,
    StorageError, TamperFlags, TamperKind, UnlockError,
};
pub use hal::{DeviceMac, Flash, Geometry, KeyProvenance, Region, Scratch, ScratchBlock};
pub use pin::{Pin, PinError};
pub use session::{Liveness, Session, DEFAULT_AUTO_LOCK_MS};
pub use slot::{Identity, Side, SlotClass, SlotId, SlotMap, SlotState};
pub use vault::{Destroyed, StoreState, Vault};

/// On-flash format revision. Bound into every AEAD's associated data, so a store written
/// by a different revision refuses rather than being reinterpreted.
pub const FORMAT_VERSION: u16 = 1;

/// The cipher suite: argon2id + hmac-efuse + hkdf-sha256 + chacha20poly1305.
pub const SUITE_ID: u16 = 1;

/// PIN identities the format supports. Frozen: a build-time K would make the on-flash map
/// depend on a constant, which is how a firmware update becomes silent data loss.
pub const MAX_IDENTITIES: u8 = 4;

/// Sequence numbers are reserved in blocks of this size, so advancing the high-water mark
/// does not burn one ledger cell per seal.
pub const SEQ_RESERVE: u64 = format::SEQ_RESERVE;

/// The `probe` module records every AEAD seal so the fuzzer can assert globally that no
/// `(key, nonce)` pair is ever used twice. Re-exported for the harness and for embedder
/// tests; it does not exist without the `testkit` feature.
#[cfg(feature = "testkit")]
pub use probe::{DerivationLog, SealRecord};
