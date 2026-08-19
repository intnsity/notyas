// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The graphics regression gate.
//!
//! READ-ONLY, deliberately and completely: nothing in this file writes into the
//! repository. Writing is `cargo run -p uisim -- approve`, which runs the two
//! unapprovable tiers first and refuses if either fails. That split is what stops a
//! failing gate from being silenced by the act of running it, and it is why the commit
//! carrying a goldens.txt diff is a record of a decision somebody made.
//!
//! The matrix is rendered ONCE into a `OnceLock` and shared by every test here: it is a
//! few hundred frames, and rendering it per test would be the difference between a gate
//! that runs on every `cargo test` and one that gets ignored.

use std::sync::OnceLock;

use notyas_ui::layout::PANELS;
use notyas_ui::theme::PALETTE;

use uisim::gate::{self, Rendered};
use uisim::panel::SENTINEL;

fn matrix() -> &'static [Rendered] {
    static MATRIX: OnceLock<Vec<Rendered>> = OnceLock::new();
    MATRIX.get_or_init(gate::render_all)
}

fn report(what: &str, failures: Vec<String>) {
    if failures.is_empty() {
        return;
    }
    let shown: Vec<String> = failures.iter().take(25).cloned().collect();
    let more = failures.len().saturating_sub(shown.len());
    panic!(
        "{what} - {} failures:\n  {}{}",
        failures.len(),
        shown.join("\n  "),
        if more > 0 { format!("\n  ... and {more} more") } else { String::new() }
    );
}

/// Tier (a), first half. A pixel drawn off the panel is invisible on the device and
/// unrecoverable from a screenshot, which is exactly why the old framebuffer's silent
/// discard let an 800x480 panel ship with text drawn through other text.
#[test]
fn no_frame_draws_outside_its_panel() {
    report("frames drew off their panel", gate::escape_failures(matrix()));
}

/// Tier (a), second half. Every screen fills the panel with paper before it draws, so a
/// pixel left at the sentinel colour is a screen that failed to paint - the uninitialised
/// framebuffer showing through, which is the signature of a panel rendering garbage.
#[test]
fn no_frame_leaves_the_panel_unpainted() {
    report("frames left panel pixels unpainted", gate::hole_failures(matrix()));
}

/// Tier (b). Every screen, in every state the catalogue declares it has, on every panel
/// the firmware ships - and nothing claiming a state that was never declared.
#[test]
fn every_screen_and_state_renders_on_every_shipped_panel() {
    report("screen states are not covered", gate::coverage_failures(matrix()));
}

/// Tier (c). The approvable one: a difference here is a layout change, and the way to
/// accept it is `cargo run -p uisim -- approve` plus a commit.
#[test]
fn frames_match_the_approved_goldens() {
    let path = gate::goldens_path();
    let committed = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!("{}: {e}\nRun `cargo run -p uisim -- approve` to create it.", path.display())
    });
    let current = gate::manifest(matrix());
    let deltas = gate::golden_failures(&current, &committed);
    if deltas.is_empty() {
        assert_eq!(current, committed, "goldens.txt differs byte for byte");
        return;
    }
    let shown: Vec<String> = deltas.iter().take(25).cloned().collect();
    let more = deltas.len().saturating_sub(shown.len());
    panic!(
        "{} frames differ from {}:\n  {}{}\n\n\
         If the layout change was intended, approve it deliberately:\n\
         \x20   cargo run -p uisim -- approve\n\
         \x20   git add tools/uisim/goldens.txt docs/screenshots/ui\n\
         The approve path re-runs the bounds and coverage gates first and refuses to write\n\
         if either fails, so a frame drawing off the panel can never be blessed this way.\n\
         To see the pixels for a docs-tier frame: cargo run -p uisim -- diff",
        deltas.len(),
        path.display(),
        shown.join("\n  "),
        if more > 0 { format!("\n  ... and {more} more") } else { String::new() }
    );
}

/// The instrument's blind spot, checked rather than assumed: the hole detector reads a
/// magenta pixel as "nothing painted here", which is only sound while nothing in the
/// palette IS that magenta.
#[test]
fn the_sentinel_cannot_be_produced_by_the_palette() {
    for (i, c) in PALETTE.iter().enumerate() {
        assert_ne!(*c, SENTINEL, "palette entry {i} is the sentinel colour");
    }
}

/// `layout::PANELS` and the boards that ship must be one list.
///
/// notyas-ui cannot depend on the firmware crate - different target, different toolchain -
/// so nothing but this scan can marry them. Without it the two drift silently, which is
/// how three of the five shipped geometries came to have never been rendered by anything:
/// ten board features select five distinct panels, and the UI tests named two.
#[test]
fn the_shipped_panels_match_the_firmware_board_files() {
    let from_boards = gate::board_panels();
    let mut declared: Vec<(u32, u32)> = PANELS.to_vec();
    declared.sort_unstable();
    assert_eq!(
        from_boards,
        declared,
        "firmware/src/board/*.rs ships {from_boards:?}, notyas_ui::layout::PANELS declares \
         {declared:?}. Add the panel to both in the same commit, then \
         `cargo run -p uisim -- approve`."
    );
}
