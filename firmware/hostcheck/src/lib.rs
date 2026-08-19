// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The firmware's pure wallet code, compiled for the host so it can be tested.
//!
//! One `#[path]` module and nothing else. There is deliberately no code of this package's
//! own: anything written here would be a second implementation of something the device
//! runs, and the whole value of this package is that what it tests is the file the device
//! actually links (see Cargo.toml for why that matters and what it already cost).
//!
//! What is NOT covered, and cannot be from here: everything that touches `Store`. The slot
//! walk, the occupancy gate and the write itself live in `firmware/src/wallet/mod.rs`
//! against a type that is an ESP-IDF partition, and the honest statement is that they are
//! covered by review and by the HIL console (`wallet persist`, `wallet open`) rather than
//! by this suite.

/// `firmware/src/wallet/record.rs`, verbatim.
#[path = "../../src/wallet/record.rs"]
pub mod record;

/// `firmware/src/flow/model.rs`, verbatim.
///
/// The other half of the firmware that is pure by construction: no store, no card, no
/// ESP-IDF, and therefore testable here. What it holds is the three judgements a review
/// screen rests on and no engine owns - which refusal code a failure is, what a transaction
/// will weigh, and which warnings fire - and every one of them is wrong in a way no compiler
/// can see.
#[path = "../../src/flow/model.rs"]
pub mod model;
