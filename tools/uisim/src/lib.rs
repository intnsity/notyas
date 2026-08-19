// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! uisim - the host-side render of notyas-ui, and the gate that regression-tests it.
//!
//! One crate with three consumers and one catalogue, which is the point. The docs
//! pictures, the gate in `tests/gate.rs` and the `render`/`diff` commands all drive the
//! SAME [`catalog::CATALOG`] through the SAME [`drive`] helpers with the SAME
//! [`fixtures`] sample data. A second crate holding a second copy of `dummy_wallets`
//! would drift, and the committed pictures would quietly stop being evidence about the
//! thing under gate.
//!
//! # Module map
//!
//! - [`panel`] - the render target. Records what a display would discard, so bounds
//!   overflow survives to be measured instead of being destroyed at the target.
//! - [`fixtures`] - the DUMMY sample data. Public test vectors only; nothing here was
//!   read off a device and nothing here is a usable seed.
//! - [`drive`] - tapping region centres. No screen is reached any way a finger could not.
//! - [`catalog`] - the render set as DATA, plus the per-screen state obligations.
//! - [`gate`] - the three tiers, the manifest format, and the approval policy.
//!
//! The simulator plays the firmware's role in the QR round trip: notyas-ui only ever
//! renders a precomputed matrix (it stays no_std), so the request returned by `Ui::touch`
//! is answered here with notyas-core's std-side encoder, exactly as the firmware does.

pub mod catalog;
pub mod drive;
pub mod fixtures;
pub mod gate;
pub mod panel;
