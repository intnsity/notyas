// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The microSD subsystem (0.2.0-m5): the board's slot, mounted only inside a flow, behind
//! the one trait the bounded half of the card layer is written against.
//!
//! A card is one of the two ways bytes reach this device from outside the airgap. The
//! design that follows from that is a split, and the split is the whole of the
//! architecture here:
//!
//! ```text
//!   notyas_wallet::sd    every decision - names, bounds, ordering, staging, verification
//!         ^              (no_std, no I/O, host-tested against a hostile simulated card)
//!         | Volume
//!   firmware::sd::fs     six filesystem calls and no logic
//!   firmware::sd::mount  the slot, the lifetime, and the airgap cross-check
//!   firmware::sd::pins   which GPIOs, per board, proven disjoint from the C6's at compile time
//! ```
//!
//! Read `notyas_wallet::sd`'s module documentation first: it carries the trust model, the
//! bounding rule and the exact statement of what the delivery sequence does and does not
//! guarantee under a power cut. Nothing in this directory restates those, because a
//! guarantee written down twice is a guarantee that can disagree with itself.
//!
//! # What this module is for
//!
//! Three flows, and `crate::flow` drives the first two today:
//!
//! - **load a PSBT** (m6, screens 9-11): [`psbt_bounds`] is the cap, `Catalog::scan` is the
//!   picker's model, `read` produces the bytes, and `notyas_core::psbt::decode` decides
//!   whether they are a transaction. This module deliberately never looks inside a file.
//! - **deliver a signed PSBT** (m6, screen S-38): `plan` names the output file before the
//!   screen announces it, and `deliver` writes it. ONE file in 0.2.0: nothing in this
//!   workspace finalizes a PSBT, so `plan` is called with `finalized: false` and no screen
//!   ever prints a `.txn` name.
//! - **export and verify** (m10, screens S-27 and 8): the same `deliver` and `read` with
//!   [`text_bounds`].
//!
//! And one operation that is not a flow, because it does not go through [`Volume`] at all:
//! [`probe_format`] and [`format_card`] reach the card at BLOCK level, below FatFs, to
//! repair a card that has no filesystem this device can mount. It is the only destructive
//! thing this directory does and the only thing here the user has to type a word to reach;
//! `format` carries the whole argument, and `probe` carries the decision that gates it.
//!
//! # Who calls it
//!
//! `crate::flow`, which is where the card requests the screens raise are answered:
//! `Catalog::scan` behind `UiRequest::ListCard`, `read` behind `LoadPsbt` and
//! `ImportRegistration`, `plan` and `deliver` behind `WriteSigned`. Until 0.2.0-m6 wired
//! those screens this whole directory was compiled and unreferenced behind a crate-level
//! dead-code allow; the allow is gone, which is the form of "it is called now" that a
//! compiler checks.

mod format;
mod fs;
mod mount;
mod pins;
mod probe;

// What the rest of the firmware may name. Trimmed to the items that have callers:
// `LONG_NAMES`, `MOUNT_POINT` and the wiring note are read inside this directory and by
// nothing outside it, and a re-export nothing names is a public surface nobody asked for.
pub use fs::FsError;
pub use mount::{is_mounted, mounts, Card, CardError};

use notyas_ui::{FormatOffer, FormatOutcome};
use notyas_wallet::sd::Bounds;

/// Look at the card in the slot and decide whether formatting it could repair it.
///
/// Reads one sector and writes nothing, on any path. See [`format`] for the whole
/// argument; the short version is that this is the gate, and it refuses far more cards
/// than it accepts - a card that mounts, an empty slot, a card that will not return its
/// first sector, a card with two partitions and a card with no partition table are all
/// refusals, and only one fault is repaired by writing a filesystem.
pub fn probe_format() -> FormatOffer {
    format::probe()
}

/// Write a fresh FAT filesystem into `partition`, on the card whose capacity renders as
/// `word`.
///
/// Both arguments are re-derived from the card in the slot and compared before anything is
/// written, so a card swapped between the consent sheet and the tap is refused rather than
/// erased. **This is the only function in this subsystem that destroys data**, and the
/// only one in the firmware that destroys data the device never held.
pub fn format_card(partition: u8, word: &str) -> FormatOutcome {
    format::format(partition, word)
}

/// Bounds for reading a PSBT off a card.
///
/// The file cap is `notyas_core`'s, not this module's. It is the number ARCHITECTURE.md
/// 5.3 check 9 re-enforces against the serialized length and the one the PSBT decoder
/// applies to the bytes as they arrive, and a card layer with a cap of its own would be a
/// second limit that could drift below or above it. Read once, here, so the picker's "too
/// large" row and the decoder's refusal quote the same figure.
pub fn psbt_bounds() -> Bounds {
    let max = notyas_core::psbt::StructuralLimits::DEFAULT.max_psbt_bytes;
    Bounds::new(u32::try_from(max).unwrap_or(u32::MAX))
}

/// Bounds for the small text artifacts: descriptors, coordinator exports, an address to
/// check.
///
/// 64 KiB, and it is this module's own number because nothing else owns one. The largest
/// thing in the class is a coordinator export of a multisig wallet, which is a few
/// kilobytes; the cap exists to stop a hostile card from feeding a megabyte of text into a
/// screen that renders it, not to accommodate a plausible file.
pub fn text_bounds() -> Bounds {
    Bounds::new(64 * 1024)
}

/// Run one SD flow: mount, do the work, unmount.
///
/// The unmount happens on the way out of this function whatever `f` did - returned,
/// propagated an error, or panicked - because [`Card`]'s `Drop` is what performs it. That
/// is the mechanism behind MILESTONES.md m5's "the mount is never held outside an SD
/// flow": a caller that wants to keep the card mounted has to keep the guard, and keeping
/// the guard is a visible thing to do.
///
/// `f` returns whatever it likes, including its own `Result`. This function's error is
/// only about getting a card at all.
pub fn with_card<T>(f: impl FnOnce(&mut Card) -> T) -> Result<T, CardError> {
    let mut card = Card::mount()?;
    Ok(f(&mut card))
}

/// Panics in a debug build if a card is mounted.
///
/// For the main loop's idle path, which is the one place that can observe the property
/// MILESTONES.md m5 asks to be "asserted in code": an idle device holds no mount, so a
/// card removed at any idle moment costs nothing. A release build logs instead of
/// aborting, because a stuck mount is a bug worth a loud line and not worth bricking a
/// device that is otherwise working.
pub fn assert_idle() {
    if is_mounted() {
        debug_assert!(false, "a microSD card is mounted while the device is idle");
        log::error!(
            "microSD: a card is still mounted at idle - some flow returned without \
             dropping its Card guard"
        );
    }
}
