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
//! Signing hangs off step 9 rather than extending the line, because it starts from a
//! transaction the pipeline knows nothing about:
//!
//!   seed + path   -> [`sign::derive_path`]         -> a key
//!   tx  + input   -> [`sign::SpendKind::sign_hash`] -> a digest (no key in scope)
//!   key + digest  -> [`sign::SecretSigningKey::sign`]
//!
//! `psbt` is the one caller of that sequence that a transaction actually arrives through,
//! and it keeps the same split: [`psbt::inspect`] decides whether a file may be signed
//! with no seed in scope at all, and [`psbt::sign`] acts only on what an inspection named.
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

/// The `bitcoin` crate this core is built against, re-exported so front ends (notyas-ui,
/// the firmware) name the pipeline's own exact pin for the few types they need
/// (`Network`), instead of carrying a second `bitcoin` dependency whose version or
/// feature set could drift from the one the derivation path actually runs on.
pub use bitcoin;

// Addresses (0.2.0-m10): the one scheme-to-address rendering the whole crate uses, a
// wallet's receive and change addresses derived watch-only from account xpubs and
// multisig registrations, and the bounded ownership search behind "is this address
// mine?". Hangs off step 9 rather than extending the line above: it starts from an
// address someone else supplied. The module's own docs are the summary, and this comment
// is deliberately not a doc comment - see the note on `sign` below for why an outer one
// here would break the module's intra-doc links.
pub mod address;
pub mod bip39;
pub mod bip85;
pub mod derive;
pub mod entropy;
/// Watch-only export rendering: BIP-380 descriptors and the named coordinator export
/// bodies (0.2.0-m10). See the module docs for what each format is and where it comes
/// from.
pub mod export;
pub mod health;
pub mod message;
pub mod mnemonic_tools;
/// Multisig (0.2.0-m7): P2WSH `sortedmulti` registration, script derivation and the change
/// proof the policy engine's check 4 rests on. Off the derivation pipeline above and off
/// the signing one too: it decides which multi-party scripts this device has been told it
/// is a member of, and `psbt` is its only caller inside this crate.
pub mod multisig;
// The PSBT engine (0.2.0-m6): decode a BIP-174 file, decide whether it may be signed,
// sign it, encode it again. Off the derivation pipeline above for the same reason `sign`
// is: it starts from a file the pipeline knows nothing about. The module's own docs are
// the summary, and this comment is deliberately not a doc comment - see the note on
// `sign` below for why an outer one here would break the module's intra-doc links.
pub mod psbt;
/// QR symbols for the values [`report`] shows. Generation only; see the module docs.
/// Feature-gated because the `qrcode` crate needs std; the firmware (std on ESP-IDF)
/// keeps the default on.
#[cfg(feature = "qr")]
pub mod qr;
/// The signed transaction as a QR payload (0.2.0): the one string a camera is meant to
/// read, and the panel-derived limit on how large a transaction may be to have one. Not
/// feature-gated - it produces a string, and `qr` is what turns a string into modules.
pub mod psbt_qr;
pub mod report;
pub mod seedqr;
// Signing (0.2.0-m2). The module's own docs are the summary; an outer doc comment here
// would make rustdoc resolve the module's intra-doc links in THIS file's scope, which is
// why `qr` and `selftest` have unresolved links today.
pub mod sign;
/// Boot self-test (SECURITY.md invariant 5): a curated vector subset the firmware runs
/// at every boot and renders on the Verify screen. Off the derivation pipeline above -
/// it only exercises it.
pub mod selftest;
