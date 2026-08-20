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

/// `firmware/src/unseal.rs`, verbatim.
///
/// The guess / not-a-guess judgement on an unlock refusal. Pure for the same reason the
/// modules above are, and worth covering for the reason they are: the compiler cannot see
/// the difference between telling an owner their correct PIN was wrong and telling them
/// the store could not be read, and neither can a panel photograph.
#[path = "../../src/unseal.rs"]
pub mod unseal;

/// `firmware/src/session.rs`, verbatim.
///
/// What an unlocked session remembers between screens, and the one property worth proving
/// about it: clearing it WIPES the passphrases rather than merely dropping the references.
/// Pure by construction - no store, no logger, no ESP-IDF - and untestable on the device,
/// because the evidence is a freed heap buffer that no panel and no log line can show.
#[path = "../../src/session.rs"]
pub mod session;

/// `firmware/src/wallet/erase.rs`, verbatim.
///
/// The delete-wallet ordering rule. Pure by construction for the reason `replace.rs` is - a
/// trait with five methods and one function that sequences them - and worth covering for a
/// sharper reason than either: the failure it guards against is a registry record left
/// naming a payload slot that has been freed, which the NEXT wallet stored on the device
/// would then inherit. No compiler can see that, and neither can a panel photograph.
#[path = "../../src/wallet/erase.rs"]
pub mod erase;

/// `firmware/src/flow/replace.rs`, verbatim.
///
/// The registry-replacement ordering rule. It is storage-agnostic by construction - a trait
/// with four methods and one function that sequences them - which is the only reason any of
/// it can be exercised here: the real implementation of that trait is a `Store`, an ESP-IDF
/// flash partition, and the rollback path is by definition the path a working store never
/// takes. Behind the trait it is a registry that can be told to fail on demand, and the
/// sequencing under test is the device's own.
#[path = "../../src/flow/replace.rs"]
pub mod replace;

/// `firmware/src/sd/probe.rs`, verbatim.
///
/// The gate that decides whether the device offers to ERASE somebody's card. Pure by
/// construction - 512 bytes and a capacity in, a verdict out, no driver and no allocation
/// off anything the card said - and the single most consequential judgement in this tree
/// that a compiler cannot check: every branch of it is a decision about data the device
/// has never seen and cannot get back.
///
/// On silicon it is reachable only with a real card in a real slot, in states nobody can
/// produce on a bench (a GPT card, a superfloppy card, a table claiming more sectors than
/// the card has). Here every one of them is 512 bytes in an array.
#[path = "../../src/sd/probe.rs"]
pub mod probe;
