// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The power-loss fuzzer, driven to convergence.
//!
//! A cut at every step boundary of every operation, in three flavours, with eleven
//! invariants asserted after each one.
//!
//! # How this suite is split, and why
//!
//! The exhaustive corpus is the milestone's exit gate and it takes about three and a half
//! minutes in release and over half an hour in debug, because it is quadratic by
//! construction: each of tens of thousands of cases re-runs a whole operation. Leaving
//! that in the default `cargo test` path would put half an hour on every developer's
//! inner loop, which is how a gate stops being run at all. So the exhaustive runs are
//! `#[ignore]`d and invoked explicitly:
//!
//! ```text
//! cargo test -p notyas-wallet --release -- --ignored --nocapture
//! ```
//!
//! What runs by default is a small subset chosen for sharpness rather than coverage: the
//! four operations whose commit points a regression is most likely to break, including the
//! repeated-seal case that is the only one able to expose a broken reserve-ahead. It costs
//! a few seconds and it would have caught both defects this module found while it was
//! being written.
//!
//! The case count is printed rather than asserted against a number. The number moves
//! whenever an operation gains or loses a write, and pinning it would only produce a test
//! that fails for the wrong reason.

use notyas_wallet::fuzz::{self, fuzz_config, v1_config, Op};
use notyas_wallet::sim::CutMode;

fn report(report: &fuzz::Report) {
    println!("{}", report.summary());
    for line in report.grouped() {
        println!("  {line}");
    }
    assert!(
        report.is_clean(),
        "{} invariant failure(s). If one of these is genuinely unreachable on hardware, \
         say so in the design document; do not weaken the assertion to make it pass.",
        report.findings.len()
    );
    assert!(
        report.cuts_fired > 0,
        "no cut ever fired, so this run proved nothing"
    );
    assert!(
        report.seals_observed > 0,
        "no seal was observed, so invariant I6 was not actually checked"
    );
}

/// The default-path subset: four operations whose commit points carry the most weight.
#[test]
fn the_sharp_subset_holds() {
    report(&fuzz::run_ops(
        &fuzz_config(),
        &[
            Op::SealRepeated,
            Op::Wipe,
            Op::UnlockToWipe,
            Op::PolicyDisable,
        ],
        CutMode::ALL,
    ));
}

/// THE EXIT GATE. The full corpus on the reduced slot map: every operation, every step
/// boundary, every cut mode.
#[test]
#[ignore = "the milestone exit gate; minutes long, run with --release -- --ignored"]
fn the_full_corpus_holds() {
    report(&fuzz::run(&fuzz_config()));
}

/// THE EXIT GATE, second half. The shipped 8+8 slot map, on the operations whose behaviour
/// depends on how many records there are. The reduced map covers the same code paths far
/// faster; this is the check that the geometry itself is not the thing making them pass.
#[test]
#[ignore = "the milestone exit gate; minutes long, run with --release -- --ignored"]
fn the_shipped_geometry_holds_on_the_operations_that_scale_with_it() {
    report(&fuzz::run_ops(
        &v1_config(),
        &[
            Op::SealNew,
            Op::SealOverwrite,
            Op::SealRepeated,
            Op::ChangePin { records: 4 },
            Op::Wipe,
            Op::PolicyDisable,
        ],
        CutMode::ALL,
    ));
}
