// Copyright (C) 2025-2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The cryptographic core of BigDice, ported to no_std for the notyas device.
//!
//! This crate is the desktop BigDice library (github.com/intnsity/BigDice) minus its
//! front ends: the same SPEC (the desktop crate's `docs/SPEC.md` is normative, and every
//! "SPEC step N" below refers to it), the same vectors, the same output bytes.
//! Divergence from desktop BigDice output on identical input is a release-blocking bug.
//! PORTING.md lists the few places the port differs from the desktop modules.
//!
//! # Module map
//!
//! The pipeline is a straight line and each stage lives in exactly one module:
//!
//!   raw dice text -> [`entropy::parse_dice`]      (SPEC steps 1-3)
//!                 -> [`bip39::mnemonic_from_dice`] (SPEC steps 4-7)
//!                 -> [`bip39::seed`]               (SPEC step 8)
//!                 -> [`derive::derive`]            (SPEC step 9)
//!
//! A phrase the user already has joins that line at step 8, which is the whole of what the
//! two inputs share:
//!
//!   typed phrase  -> [`bip39::normalize_phrase`] (+ [`bip39::check_phrase`], advisory)
//!                 -> [`bip39::seed`]               (SPEC step 8)
//!                 -> [`derive::derive`]            (SPEC step 9)
//!
//! [`report::Report::build`] is the one caller of the first sequence and
//! [`report::Report::from_phrase`] of the second; the firmware UI renders what either
//! produces and `qr` draws one value out of it.
//!
//! Invariant for the whole crate: the keys come from what the user supplied and from
//! nothing else - the dice on one path, the phrase on the other, plus the passphrase.
//! Nothing here reads an RNG, a clock, a file or a peripheral; the crate has no way to,
//! because it is `no_std` and imports no I/O. Any change that puts randomness, a clock or
//! I/O on the derivation path is a defect, not a feature.

#![no_std]

// alloc is the one runtime the core needs: strings, vectors and the secp context live on
// the heap the firmware provides. `#[macro_use]` keeps `format!` and `vec!` available
// crate-wide, as they are under std.
#[macro_use]
extern crate alloc;

// The unit tests run on the host under the ordinary test harness, which is a std program;
// the library itself never links std.
#[cfg(test)]
extern crate std;

pub mod bip39;
pub mod derive;
pub mod entropy;
/// QR symbols for the values [`report`] shows. Generation only; see the module docs.
/// Feature-gated because the `qrcode` crate needs std; the firmware (std on ESP-IDF)
/// keeps the default on.
#[cfg(feature = "qr")]
pub mod qr;
pub mod report;
