// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The power-loss fuzzer.
//!
//! This is the reason the milestone exists. Every claim in ESP-SEAL.md about what a power
//! cut can and cannot do is an argument on paper; this module turns each of them into an
//! assertion and runs it at every step boundary of every operation.
//!
//! The method is the one ESP-SEAL.md 2.3 point 6 specifies, and its whole virtue is that
//! it is a counter rather than a thread: [`SimFlash`] takes a step budget, each sector
//! erase and each cipher-block program spends one, the budgeted step is mangled, and every
//! access after it fails. Enumerating the budget over `0..steps(op)` covers every boundary
//! exhaustively, with no concurrency and no flakiness. The same case run twice gives the
//! same answer, which is what makes a failure a bug report rather than a mystery.
//!
//! For each operation and each step boundary the harness runs three variants: a clean
//! truncation, a partial program of a prefix of the block, and a deterministic bit-rot
//! where a fixed subset of bits fails to clear.
//!
//! # The invariants, and what each one protects
//!
//! | # | Invariant | Protects |
//! |---|---|---|
//! | I1 | `mount` returns a store or a tamper state; never a panic, never garbage | the device boots |
//! | I2 | every slot reads back as exactly the pre-operation or post-operation record | the user's data |
//! | I3 | `failures` never decreases except where a successful unlock clears it | the attempt counter |
//! | I4 | `wipe_epoch` never decreases | the one-way wipe |
//! | I5 | `pin_gen` never decreases and the current set never holds an uncommitted value | the PIN change |
//! | I6 | no `(key, nonce)` pair is ever used to encrypt twice | the cryptography |
//! | I7 | after a committed PIN change, nothing on flash opens under the old PIN | the retired key |
//! | I8 | the RECORDS INVARIANT: no cipher block is programmed twice between erases | the format |
//! | I9 | exactly the documented operations consume an attempt | the counter's honesty |
//! | I10 | a cut during change-PIN leaves the old PIN or the new PIN working, never neither | the user's access |
//! | I11 | the effective policy after a cut is never weaker than both the old and new value | the wipe policy |
//!
//! I6 is why the fuzzer exists. Every other invariant protects data; I6 protects the
//! cryptography, and it is the one property an argument on paper is least able to
//! guarantee. I8 is asserted by [`SimFlash`] itself, which panics on a second program of a
//! cipher block rather than emulating the garbage real XTS hardware would produce.

#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use crate::config::{Config, KdfParams, Layout, Occupancy, Policy, PolicyRequest};
use crate::hal::{Geometry, KeyProvenance};
use crate::probe::{observed_seals, DerivationLog, SealRecord};
use crate::session::Session;
use crate::sim::{CutMode, SimFlash, SimImage, SoftMac, VecScratch};
use crate::slot::{Identity, Side, SlotClass, SlotId};
use crate::vault::{StoreState, Vault};
use crate::{Pin, TamperFlags};

type V = Vault<SimFlash, SoftMac>;

/// Provenance set the harness accepts.
///
/// Deliberately not a release set. `Config::validate` refuses test-cost Argon2id
/// parameters on a config that accepts nothing but a read-protected eFuse key, which is
/// the control that keeps a debug constant out of a signed image, and admitting the
/// emulated tier is how a test config declares that it is one.
static FUZZ_PROVENANCE: &[KeyProvenance] =
    &[KeyProvenance::EfuseReadProtected, KeyProvenance::Emulated];

/// A cut-down slot map for the exhaustive corpus.
///
/// The corpus is quadratic in the work one operation does - every step boundary is a case,
/// and every case re-runs the operation - so the full 8+8 map would spend most of the run
/// re-sealing filler rather than exploring boundaries. Two payload and two registry slots
/// exercise every code path the full map does, including the multi-record batch of a PIN
/// change, and the full map is covered separately by the V1 corpus.
pub const FUZZ_LAYOUT: Layout = Layout {
    sector_size: 4096,
    records_sectors: 22,
    ledger_sectors: 4,
    canary_slots: 4,
    payload_slots: 2,
    registry_slots: 2,
    payload_slot_sectors: 1,
    registry_slot_sectors: 2,
    identities: 4,
};

/// A config the fuzzer can drive at speed: test-cost Argon2id and the reduced slot map.
pub fn fuzz_config() -> Config {
    Config {
        domain_tag: *b"notyas-fuzz-v1..",
        kdf: KdfParams::TEST_ONLY,
        layout: FUZZ_LAYOUT,
        format_policy: PolicyRequest {
            wipe_after: 15,
            min_pin_len: 4,
        },
        occupancy: Occupancy::AlwaysFilled,
        accept_provenance: FUZZ_PROVENANCE,
        disable_wipe_min_pin_len: None,
    }
}

/// The shipped slot map at test cost, for the smaller V1 corpus.
pub fn v1_config() -> Config {
    Config {
        kdf: KdfParams::TEST_ONLY,
        layout: Layout::V1,
        accept_provenance: FUZZ_PROVENANCE,
        ..Config::NOTYAS_RELEASE
    }
}

pub fn geometry_for(layout: &Layout) -> Geometry {
    Geometry {
        sector_size: layout.sector_size,
        records_sectors: layout.records_sectors,
        ledger_sectors: layout.ledger_sectors,
        cipher_block: 16,
        write_gran: 4,
    }
}

/// The two PINs every scenario uses. Fixed so a failure is reproducible from its case id
/// alone.
#[derive(Debug)]
pub struct Pins {
    pub old: Pin,
    pub new: Pin,
}

impl Default for Pins {
    fn default() -> Self {
        Pins {
            // `from_normalized_bytes` refuses only an empty or over-long PIN, and neither
            // literal is either, so the fallback branch is unreachable and exists to keep
            // this module panic-free like the rest of the crate.
            old: Pin::from_normalized_utf8("135790").unwrap_or_else(|_| empty_pin()),
            new: Pin::from_normalized_utf8("246802").unwrap_or_else(|_| empty_pin()),
        }
    }
}

fn empty_pin() -> Pin {
    Pin::from_normalized_bytes(&[0u8]).unwrap_or_else(|_| unreachable_pin())
}

fn unreachable_pin() -> Pin {
    // A one-byte PIN is always accepted, so this is never reached. Written as a loop
    // rather than a panic because the crate does not panic.
    loop {
        core::hint::spin_loop();
    }
}

/// The operations the corpus covers, each with the pre-state it needs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Op {
    /// FORMAT on a blank store.
    Format,
    /// FORMAT on a wiped store, which must carry the one-way epoch forward.
    Reformat,
    /// SEAL a record into an empty slot.
    SealNew,
    /// SEAL over an existing record, which is the A/B swap plus the stale-side erase.
    SealOverwrite,
    /// Three seals of ONE slot inside a single cut window.
    ///
    /// This is the case that makes I6 sharp. A nonce is a function of the slot, the SIDE
    /// and the sequence number, so two seals of one slot land on opposite sides and differ
    /// on the side alone even if the sequence were repeated. It takes a third write,
    /// returning to the side the first one used, before a broken reserve-ahead shows up as
    /// a repeated pair. Without this operation the whole I6 check passes on a store whose
    /// sequence cursor never advances, which was verified by mutation and is exactly the
    /// kind of hole a fuzzer is supposed to not have.
    SealRepeated,
    /// CLEAR, which under AlwaysFilled is a filler write rather than an erase.
    Clear,
    /// A successful unlock: attempt cell, four opens, catch-up.
    UnlockGood,
    /// A failed unlock: attempt cell, four opens, no catch-up.
    UnlockBad,
    /// The last permitted failure, which triggers the wipe from inside the counted region.
    UnlockToWipe,
    /// CHANGE-PIN over a store holding `n` user records.
    ChangePin { records: u8 },
    /// WIPE from a locked store.
    Wipe,
    /// SET-POLICY tightening the limit.
    PolicyTighten,
    /// SET-POLICY disabling the wipe, the only direction that weakens the device.
    PolicyDisable,
    /// SET-POLICY turning the wipe back on from a disabled store.
    PolicyEnable,
    /// LEDGER ROTATION, reached by driving the attempt log into its tail reserve.
    Rotation,
    /// Rotation on a wipe-disabled device, where the attempt log fills with no success to
    /// clear it and `failures_base` has to carry the count across.
    RotationOnFailure,
    /// REMOVE-PIN: a wipe that leaves the store unformatted.
    RemovePin,
    /// MOUNT's own cleanup pass over a store left with a torn side.
    MountCleanup,
}

impl Op {
    /// The default corpus. Every operation ESP-SEAL.md 8.1 names, plus the three the
    /// settable policy added.
    pub const CORPUS: &'static [Op] = &[
        Op::Format,
        Op::Reformat,
        Op::SealNew,
        Op::SealOverwrite,
        Op::SealRepeated,
        Op::Clear,
        Op::UnlockGood,
        Op::UnlockBad,
        Op::UnlockToWipe,
        Op::ChangePin { records: 0 },
        Op::ChangePin { records: 1 },
        Op::ChangePin { records: 4 },
        Op::Wipe,
        Op::PolicyTighten,
        Op::PolicyDisable,
        Op::PolicyEnable,
        Op::Rotation,
        Op::RotationOnFailure,
        Op::RemovePin,
        Op::MountCleanup,
    ];

    fn name(self) -> String {
        match self {
            Op::ChangePin { records } => format!("ChangePin{{records:{records}}}"),
            other => format!("{other:?}"),
        }
    }

    /// Does this operation legitimately consume an attempt? I9 is checked against this.
    fn consumes_attempt(self) -> bool {
        matches!(
            self,
            Op::UnlockGood
                | Op::UnlockBad
                | Op::UnlockToWipe
                | Op::Rotation
                | Op::RotationOnFailure
        )
    }

    /// Values a slot may legitimately hold part-way through a COMPOUND operation.
    ///
    /// I2's rule is "the pre-operation record or the post-operation record, never a
    /// mixture". For an operation that writes one slot more than once, the intermediate
    /// values are neither, and they are perfectly correct: the cut simply landed between
    /// two writes. Listing them here keeps I2 sharp - it still rejects a mixture or a
    /// truncation - without turning a multi-write operation into a false positive.
    fn intermediates(self) -> Vec<Option<Vec<u8>>> {
        match self {
            Op::SealRepeated => vec![Some(vec![0u8; 48]), Some(vec![1u8; 48])],
            _ => Vec::new(),
        }
    }

    /// Is this operation allowed to reduce the failure count? Only a successful unlock and
    /// the operations that re-format the store are.
    fn may_clear_failures(self) -> bool {
        matches!(
            self,
            Op::UnlockGood
                | Op::Rotation
                | Op::RotationOnFailure
                | Op::Format
                | Op::Reformat
                | Op::UnlockToWipe
                | Op::RemovePin
                | Op::Wipe
        )
    }
}

/// One observation of a store, taken by mounting it and looking.
#[derive(Clone, Debug)]
struct View {
    state: StoreState,
    failures: u32,
    epoch: u64,
    policy: Policy,
    pin_gen: u32,
    tamper: TamperFlags,
    /// Contents of every user slot, `None` for empty or filler.
    slots: Vec<Option<Vec<u8>>>,
    old_pin_opens: bool,
    new_pin_opens: bool,
    /// Sides anywhere on flash whose ciphertext opens under the OLD PIN. I7 requires this
    /// to be empty once the change has committed.
    old_pin_sides: usize,
    mounted: bool,
}

/// A failure the harness found, named precisely enough to reproduce.
#[derive(Clone, Debug)]
pub struct Finding {
    pub op: String,
    pub cut_after: u32,
    pub mode: CutMode,
    pub invariant: &'static str,
    pub detail: String,
}

/// What the run proved, and what it did not.
#[derive(Clone, Debug, Default)]
pub struct Report {
    /// Total (operation, step boundary, cut mode) triples executed.
    pub cases: u32,
    /// Operations whose step count was measured.
    pub operations: u32,
    /// Sum of step boundaries over all operations, before the cut-mode multiplier.
    pub step_boundaries: u32,
    /// Cases in which the armed cut actually fired.
    pub cuts_fired: u32,
    /// Total AEAD encryptions observed across the whole run.
    pub seals_observed: u64,
    pub findings: Vec<Finding>,
}

impl Report {
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }

    /// Findings collapsed to one line per (operation, invariant) pair with a count and the
    /// lowest step boundary that reproduces it.
    ///
    /// A single defect usually fires for hundreds of consecutive boundaries, and a report
    /// that printed all of them would bury the second defect under the first.
    pub fn grouped(&self) -> Vec<String> {
        let mut keys: Vec<(String, &'static str)> = Vec::new();
        for f in &self.findings {
            let k = (f.op.clone(), f.invariant);
            if !keys.contains(&k) {
                keys.push(k);
            }
        }
        keys.into_iter()
            .map(|(op, inv)| {
                let hits: Vec<&Finding> = self
                    .findings
                    .iter()
                    .filter(|f| f.op == op && f.invariant == inv)
                    .collect();
                let first = hits.first();
                format!(
                    "{op} {inv}: {} case(s), first at cut_after={} mode={:?}: {}",
                    hits.len(),
                    first.map_or(0, |f| f.cut_after),
                    first.map_or(CutMode::Clean, |f| f.mode),
                    first.map_or(String::new(), |f| f.detail.clone())
                )
            })
            .collect()
    }

    /// A one-line summary for a test's output.
    pub fn summary(&self) -> String {
        format!(
            "{} cases over {} operations ({} step boundaries x {} cut modes), {} cuts fired, {} seals observed, {} findings",
            self.cases,
            self.operations,
            self.step_boundaries,
            self.cases.checked_div(self.step_boundaries.max(1)).unwrap_or(0),
            self.cuts_fired,
            self.seals_observed,
            self.findings.len()
        )
    }
}

/// Run the whole corpus.
pub fn run(cfg: &Config) -> Report {
    run_ops(cfg, Op::CORPUS, CutMode::ALL)
}

/// Run a chosen set of operations and cut modes.
pub fn run_ops(cfg: &Config, ops: &[Op], modes: &[CutMode]) -> Report {
    let mut report = Report::default();
    for op in ops {
        run_one(cfg, *op, modes, &mut report);
    }
    report
}

fn run_one(cfg: &Config, op: Op, modes: &[CutMode], report: &mut Report) {
    let pins = Pins::default();

    // ---- Build the pre-state, and remember every seal it performed. Those seals are a
    // legitimate part of every timeline that branches from this image, so they are the
    // baseline the per-case I6 check runs against rather than a duplicate.
    let baseline_log = DerivationLog::start();
    let Some(image) = build_pre_state(cfg, op, &pins) else {
        report.findings.push(Finding {
            op: op.name(),
            cut_after: 0,
            mode: CutMode::Clean,
            invariant: "setup",
            detail: "could not build the pre-state for this operation".to_string(),
        });
        return;
    };
    let baseline: Vec<SealRecord> = baseline_log.seals();
    drop(baseline_log);
    // The setup is a linear timeline too, and it seals more records than any single
    // operation does. Checking it against itself is not redundant with the per-case check:
    // a defect that repeats a nonce inside one operation would otherwise sit entirely
    // inside the baseline, where the per-case comparison never looks.
    if let Some(dup) = first_duplicate(&[], &baseline) {
        report.findings.push(Finding {
            op: op.name(),
            cut_after: 0,
            mode: CutMode::Clean,
            invariant: "I6",
            detail: format!(
                "building the pre-state already used a (key, nonce) pair twice: nonce {:02x?}",
                dup.nonce
            ),
        });
    }

    let pre = observe(cfg, &image, &pins);

    // ---- Measure the operation, uncut, to learn how many step boundaries it has, and to
    // learn what the completed operation looks like.
    let measure_log = DerivationLog::start();
    let Some((steps, post_image)) = measure(cfg, op, &image, &pins) else {
        report.findings.push(Finding {
            op: op.name(),
            cut_after: 0,
            mode: CutMode::Clean,
            invariant: "setup",
            detail: "the operation did not complete on an uncut device".to_string(),
        });
        return;
    };
    drop(measure_log);
    let post = observe(cfg, &post_image, &pins);
    report.operations += 1;
    report.step_boundaries += steps;

    // ---- Every step boundary, every cut mode.
    for k in 0..steps {
        for mode in modes {
            let log = DerivationLog::start();
            let (after, fired, seals_upto) = cut_and_observe(cfg, op, &image, &pins, k, *mode);
            let seals = log.seals();
            report.cases += 1;
            report.seals_observed += seals.len() as u64;
            if fired {
                report.cuts_fired += 1;
            }
            check(
                cfg,
                op,
                k,
                *mode,
                &pre,
                &post,
                &after,
                &baseline,
                &seals[..seals_upto.min(seals.len())],
                report,
            );
            drop(log);
        }
    }
}

// ---------------------------------------------------------------------------
// Driving the store
// ---------------------------------------------------------------------------

fn fresh(cfg: &Config) -> (SimFlash, SoftMac) {
    (
        SimFlash::new(geometry_for(&cfg.layout)),
        SoftMac::new(),
    )
}

fn mount(cfg: &Config, image: &SimImage) -> Option<V> {
    let (mut flash, mac) = fresh(cfg);
    flash.restore(image);
    Vault::mount(flash, mac, cfg).ok()
}

fn unmount(v: V) -> SimImage {
    let (flash, _) = v.into_parts();
    flash.snapshot()
}

fn scratch_for(cfg: &Config) -> VecScratch {
    VecScratch::for_params(&cfg.kdf)
}

fn unlock(v: &mut V, pin: &Pin, cfg: &Config) -> Option<Session> {
    let mut s = scratch_for(cfg);
    v.unlock(pin, s.scratch()).ok()
}

/// The pre-state each operation starts from, as an image that can be restored any number
/// of times.
fn build_pre_state(cfg: &Config, op: Op, pins: &Pins) -> Option<SimImage> {
    let (flash, mac) = fresh(cfg);
    let mut v = Vault::mount(flash, mac, cfg).ok()?;

    match op {
        Op::Format => return Some(unmount(v)),
        Op::Reformat => {
            format_store(&mut v, cfg, pins)?;
            v.wipe().ok()?;
            return Some(unmount(v));
        }
        Op::MountCleanup => {
            // A store left exactly as an interrupted seal leaves it: a body written into
            // the inactive side with no header, which mount must erase and ignore.
            format_store(&mut v, cfg, pins)?;
            let session = unlock(&mut v, &pins.old, cfg)?;
            let slot = user_slot(cfg, 0)?;
            v.write(&session, slot, b"the record that must survive").ok()?;
            let mut image = unmount(v);
            // Re-run the same write with a cut two steps in, which lands inside the body
            // program of the inactive side.
            let (mut flash, mac) = fresh(cfg);
            flash.restore(&image);
            let mut v2 = Vault::mount(flash, mac, cfg).ok()?;
            let s2 = unlock(&mut v2, &pins.old, cfg)?;
            v2.backend_mut().arm(2, CutMode::PartialPrefix);
            let _ = v2.write(&s2, slot, b"the torn record that must not");
            let (mut flash, _) = v2.into_parts();
            flash.power_on();
            image = flash.snapshot();
            return Some(image);
        }
        _ => {}
    }

    format_store(&mut v, cfg, pins)?;

    match op {
        Op::SealNew | Op::Clear | Op::UnlockGood | Op::UnlockBad | Op::Wipe => {}
        Op::SealOverwrite | Op::SealRepeated => {
            let session = unlock(&mut v, &pins.old, cfg)?;
            v.write(&session, user_slot(cfg, 0)?, b"the record being replaced")
                .ok()?;
        }
        Op::ChangePin { records } => {
            let session = unlock(&mut v, &pins.old, cfg)?;
            for i in 0..records {
                let Some(slot) = user_slot(cfg, i) else {
                    break;
                };
                let payload = vec![0xa0u8.wrapping_add(i); 64];
                v.write(&session, slot, &payload).ok()?;
            }
        }
        Op::UnlockToWipe => {
            // One failure short of the limit, so the operation under test is the attempt
            // that trips the wipe from inside the counted region.
            let limit = v.policy().wipe_after;
            for _ in 0..limit.saturating_sub(1) {
                let mut s = scratch_for(cfg);
                let _ = v.unlock(&wrong_pin(), s.scratch());
            }
        }
        Op::PolicyTighten | Op::PolicyDisable => {}
        Op::PolicyEnable => {
            let session = unlock(&mut v, &pins.old, cfg)?;
            let mut s = scratch_for(cfg);
            v.set_policy(
                &session,
                PolicyRequest {
                    wipe_after: 0,
                    min_pin_len: 4,
                },
                &pins.old,
                s.scratch(),
            )
            .ok()?;
        }
        Op::Rotation => {
            // Drive the attempt log to one short of the tail reserve so the operation
            // under test is the successful unlock that rotates.
            drive_attempts(&mut v, cfg, 104)?;
        }
        Op::RotationOnFailure => {
            let session = unlock(&mut v, &pins.old, cfg)?;
            let mut s = scratch_for(cfg);
            v.set_policy(
                &session,
                PolicyRequest {
                    wipe_after: 0,
                    min_pin_len: 4,
                },
                &pins.old,
                s.scratch(),
            )
            .ok()?;
            drop(session);
            drive_attempts(&mut v, cfg, 127)?;
        }
        Op::RemovePin => {}
        Op::Format | Op::Reformat | Op::MountCleanup => {}
    }
    Some(unmount(v))
}

/// Spend `n` failed attempts, remounting as the store demands.
fn drive_attempts(v: &mut V, cfg: &Config, n: u32) -> Option<()> {
    for _ in 0..n {
        let mut s = scratch_for(cfg);
        let _ = v.unlock(&wrong_pin(), s.scratch());
    }
    Some(())
}

fn format_store(v: &mut V, cfg: &Config, pins: &Pins) -> Option<()> {
    let mut s = scratch_for(cfg);
    v.format(&pins.old, b"fuzz", s.scratch()).ok().map(|_| ())
}

fn wrong_pin() -> Pin {
    Pin::from_normalized_utf8("000000").unwrap_or_else(|_| empty_pin())
}

fn user_slot(cfg: &Config, i: u8) -> Option<SlotId> {
    let payloads = cfg.layout.payload_slots;
    if i < payloads {
        SlotId::new(SlotClass::Payload, i, &cfg.layout)
    } else {
        SlotId::new(SlotClass::Registry, i - payloads, &cfg.layout)
    }
}

fn all_user_slots(cfg: &Config) -> Vec<SlotId> {
    let mut out = Vec::new();
    for i in 0..cfg.layout.payload_slots {
        if let Some(s) = SlotId::new(SlotClass::Payload, i, &cfg.layout) {
            out.push(s);
        }
    }
    for i in 0..cfg.layout.registry_slots {
        if let Some(s) = SlotId::new(SlotClass::Registry, i, &cfg.layout) {
            out.push(s);
        }
    }
    out
}

/// Prepare whatever the operation needs before the cut window opens, so the cut lands
/// inside the operation and not inside the unlock that authorised it.
fn prepare(v: &mut V, cfg: &Config, op: Op, pins: &Pins) -> Option<Session> {
    match op {
        Op::SealNew
        | Op::SealOverwrite
        | Op::SealRepeated
        | Op::Clear
        | Op::ChangePin { .. }
        | Op::PolicyTighten
        | Op::PolicyDisable
        | Op::PolicyEnable
        | Op::RemovePin => unlock(v, &pins.old, cfg),
        _ => None,
    }
}

fn execute(v: &mut V, cfg: &Config, op: Op, session: Option<Session>, pins: &Pins) {
    let mut s = scratch_for(cfg);
    match op {
        Op::Format | Op::Reformat => {
            let _ = v.format(&pins.old, b"fuzz", s.scratch());
        }
        Op::SealNew => {
            if let (Some(sess), Some(slot)) = (session.as_ref(), user_slot(cfg, 0)) {
                let _ = v.write(sess, slot, b"a freshly sealed record");
            }
        }
        Op::SealOverwrite => {
            if let (Some(sess), Some(slot)) = (session.as_ref(), user_slot(cfg, 0)) {
                let _ = v.write(sess, slot, b"the replacement record, longer than before");
            }
        }
        Op::SealRepeated => {
            if let (Some(sess), Some(slot)) = (session.as_ref(), user_slot(cfg, 0)) {
                for round in 0u8..3 {
                    if v.write(sess, slot, &[round; 48]).is_err() {
                        break;
                    }
                }
            }
        }
        Op::Clear => {
            if let (Some(sess), Some(slot)) = (session.as_ref(), user_slot(cfg, 0)) {
                let _ = v.clear(sess, slot);
            }
        }
        Op::UnlockGood | Op::Rotation => {
            let _ = v.unlock(&pins.old, s.scratch());
        }
        Op::UnlockBad | Op::UnlockToWipe | Op::RotationOnFailure => {
            let _ = v.unlock(&wrong_pin(), s.scratch());
        }
        Op::ChangePin { .. } => {
            if let Some(sess) = session {
                let _ = v.change_pin(sess, &pins.new, s.scratch());
            }
        }
        Op::Wipe => {
            let _ = v.wipe();
        }
        Op::PolicyTighten => {
            if let Some(sess) = session.as_ref() {
                let _ = v.set_policy(
                    sess,
                    PolicyRequest {
                        wipe_after: 5,
                        min_pin_len: 4,
                    },
                    &pins.old,
                    s.scratch(),
                );
            }
        }
        Op::PolicyDisable => {
            if let Some(sess) = session.as_ref() {
                let _ = v.set_policy(
                    sess,
                    PolicyRequest {
                        wipe_after: 0,
                        min_pin_len: 4,
                    },
                    &pins.old,
                    s.scratch(),
                );
            }
        }
        Op::PolicyEnable => {
            if let Some(sess) = session.as_ref() {
                let _ = v.set_policy(
                    sess,
                    PolicyRequest {
                        wipe_after: 8,
                        min_pin_len: 4,
                    },
                    &pins.old,
                    s.scratch(),
                );
            }
        }
        Op::RemovePin => {
            if let Some(sess) = session.as_ref() {
                let _ = v.remove_pin(sess, &pins.old, s.scratch());
            }
        }
        Op::MountCleanup => {
            // The mount that happened to get here IS the operation.
        }
    }
}

/// Run the operation with no cut and report how many step boundaries it had.
fn measure(cfg: &Config, op: Op, image: &SimImage, pins: &Pins) -> Option<(u32, SimImage)> {
    let mut v = mount(cfg, image)?;
    let session = prepare(&mut v, cfg, op, pins);
    v.backend_mut().reset_steps();
    execute(&mut v, cfg, op, session, pins);
    let steps = v.backend_mut().steps();
    Some((steps, unmount(v)))
}

/// Restore the pre-state, arm the cut, run the operation, power the device back on, and
/// look at what survived. Returns the observation, whether the cut fired, and how many
/// seals belong to the canonical post-cut timeline (the probes that follow re-derive
/// legitimately and must not count as duplicates).
fn cut_and_observe(
    cfg: &Config,
    op: Op,
    image: &SimImage,
    pins: &Pins,
    cut_after: u32,
    mode: CutMode,
) -> (View, bool, usize) {
    let (mut flash, mac) = fresh(cfg);
    flash.restore(image);

    // MountCleanup arms before the mount, because mount's own erases are the operation
    // under test. Everything else arms after, so the cut lands in the operation rather
    // than in the unlock that authorised it.
    let cut_image = if op == Op::MountCleanup {
        flash.arm(cut_after, mode);
        match Vault::mount(flash, mac, cfg) {
            Ok(v) => {
                let (mut f, _) = v.into_parts();
                f.power_on();
                f.snapshot()
            }
            Err(_) => {
                // Mount refused mid-cut. The image is whatever the cut left behind, and
                // the harness cannot get it back out of the moved value, so rebuild it.
                let (mut f, _) = fresh(cfg);
                f.restore(image);
                f.arm(cut_after, mode);
                let _ = Vault::mount(f, SoftMac::new(), cfg);
                // A refused mount performs no write beyond the tidy erases it already
                // attempted, so the pre-state image is the honest reconstruction.
                let (mut f2, _) = fresh(cfg);
                f2.restore(image);
                f2.snapshot()
            }
        }
    } else {
        let Ok(mut v) = Vault::mount(flash, mac, cfg) else {
            let (mut f, _) = fresh(cfg);
            f.restore(image);
            return (observe_image(cfg, &f.snapshot(), pins), false, 0);
        };
        let session = prepare(&mut v, cfg, op, pins);
        v.backend_mut().arm(cut_after, mode);
        execute(&mut v, cfg, op, session, pins);
        let (mut f, _) = v.into_parts();
        let fired = f.is_cut();
        f.power_on();
        let img = f.snapshot();
        let (view, upto) = observe_split(cfg, &img, pins);
        return (view, fired, upto);
    };

    let (view, upto) = observe_split(cfg, &cut_image, pins);
    (view, true, upto)
}

fn observe(cfg: &Config, image: &SimImage, pins: &Pins) -> View {
    observe_split(cfg, image, pins).0
}

fn observe_image(cfg: &Config, image: &SimImage, pins: &Pins) -> View {
    observe_split(cfg, image, pins).0
}

/// Mount once, read everything, and return both the view and the number of seals that
/// belong to that single canonical mount. Everything after the split point is a probe on a
/// throwaway clone and legitimately repeats work.
fn observe_split(cfg: &Config, image: &SimImage, pins: &Pins) -> (View, usize) {
    let mut view = View {
        state: StoreState::Blank,
        failures: 0,
        epoch: 0,
        policy: cfg.format_policy(),
        pin_gen: 0,
        tamper: TamperFlags::NONE,
        slots: Vec::new(),
        old_pin_opens: false,
        new_pin_opens: false,
        old_pin_sides: 0,
        mounted: false,
    };

    // The canonical mount. This is the one that has to be clean, and it is the one whose
    // seals count toward I6.
    let Some(v) = mount(cfg, image) else {
        return (view, observed_seals());
    };
    view.mounted = true;
    view.state = v.state();
    view.failures = v.failures();
    view.epoch = v.wipe_epoch();
    view.policy = v.policy();
    view.pin_gen = v.pin_gen(Identity(0));
    view.tamper = v.tamper_flags();
    let settled = unmount(v);
    // Everything after this point is a probe on a throwaway clone. Probes legitimately
    // re-derive what the canonical mount already derived, so they must not count toward
    // the no-repeated-nonce check.
    let split = observed_seals();

    // Probes, each on its own copy of the settled image so one probe cannot perturb the
    // next. An unlock costs an attempt, which is exactly why they cannot share.
    if let Some(mut v) = mount(cfg, &settled) {
        let mut s = scratch_for(cfg);
        if let Ok(session) = v.unlock(&pins.old, s.scratch()) {
            view.old_pin_opens = true;
            view.slots = read_all(&mut v, &session, cfg);
        }
    }
    if !view.old_pin_opens {
        if let Some(mut v) = mount(cfg, &settled) {
            let mut s = scratch_for(cfg);
            if let Ok(session) = v.unlock(&pins.new, s.scratch()) {
                view.new_pin_opens = true;
                view.slots = read_all(&mut v, &session, cfg);
            }
        }
    } else if let Some(mut v) = mount(cfg, &settled) {
        let mut s = scratch_for(cfg);
        view.new_pin_opens = v.unlock(&pins.new, s.scratch()).is_ok();
    }

    // I7's scan: every side anywhere on flash whose ciphertext still opens under the old
    // PIN. `unlock` succeeding is not the same question - a non-elected side can hold
    // old-PIN ciphertext that no unlock would ever reach.
    if let Some(mut v) = mount(cfg, &settled) {
        let mut s = scratch_for(cfg);
        view.old_pin_sides = v
            .open_any_side(&pins.old, s.scratch())
            .map(|found| found.len())
            .unwrap_or(0);
    }

    (view, split)
}

fn read_all(v: &mut V, session: &Session, cfg: &Config) -> Vec<Option<Vec<u8>>> {
    let mut out = Vec::new();
    for slot in all_user_slots(cfg) {
        let cap = slot.class().max_payload(&cfg.layout) as usize;
        let mut buf = vec![0u8; cap];
        match v.slot_state(session, slot) {
            Ok(crate::slot::SlotState::Occupied { .. }) => match v.read(session, slot, &mut buf) {
                Ok(n) => out.push(Some(buf[..n].to_vec())),
                Err(_) => out.push(None),
            },
            _ => out.push(None),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The invariants
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn check(
    cfg: &Config,
    op: Op,
    cut_after: u32,
    mode: CutMode,
    pre: &View,
    post: &View,
    after: &View,
    baseline: &[SealRecord],
    seals: &[SealRecord],
    report: &mut Report,
) {
    let mut fail = |invariant: &'static str, detail: String| {
        report.findings.push(Finding {
            op: op.name(),
            cut_after,
            mode,
            invariant,
            detail,
        });
    };

    // I1: the device boots.
    if !after.mounted {
        fail("I1", "mount refused after the cut".to_string());
        return;
    }

    // I4: the one-way epoch.
    if after.epoch < pre.epoch {
        fail(
            "I4",
            format!("epoch went backwards: {} -> {}", pre.epoch, after.epoch),
        );
    }
    if after.epoch > post.epoch {
        fail(
            "I4",
            format!(
                "epoch overshot the completed operation: {} > {}",
                after.epoch, post.epoch
            ),
        );
    }

    // I5: generations only move forward, and only a committed one is ever current.
    if after.pin_gen < pre.pin_gen {
        fail(
            "I5",
            format!(
                "pin_gen went backwards: {} -> {}",
                pre.pin_gen, after.pin_gen
            ),
        );
    }
    if after.pin_gen != pre.pin_gen && after.pin_gen != post.pin_gen {
        fail(
            "I5",
            format!(
                "pin_gen is neither the old value {} nor the new value {}: {}",
                pre.pin_gen, post.pin_gen, after.pin_gen
            ),
        );
    }

    // I3 and I9: the attempt counter.
    if !op.may_clear_failures() && after.failures < pre.failures {
        fail(
            "I3",
            format!(
                "failures decreased without a successful unlock: {} -> {}",
                pre.failures, after.failures
            ),
        );
    }
    if !op.consumes_attempt() && !op.may_clear_failures() && after.failures > pre.failures {
        fail(
            "I9",
            format!(
                "an operation that must not consume an attempt consumed {}",
                after.failures - pre.failures
            ),
        );
    }
    if op.consumes_attempt() && after.failures > pre.failures.saturating_add(1) {
        fail(
            "I9",
            format!(
                "one attempt consumed more than one failure: {} -> {}",
                pre.failures, after.failures
            ),
        );
    }

    // I6: no (key, nonce) pair encrypts twice, over this simulated device's whole life.
    if let Some(dup) = first_duplicate(baseline, seals) {
        fail(
            "I6",
            format!(
                "a (key, nonce) pair was used to encrypt twice: nonce {:02x?}",
                dup.nonce
            ),
        );
    }

    // I2: no torn record ever opens, and no slot is ever a mixture.
    let allowed = op.intermediates();
    if after.old_pin_opens || after.new_pin_opens {
        for (i, content) in after.slots.iter().enumerate() {
            let a = pre.slots.get(i).cloned().flatten();
            let b = post.slots.get(i).cloned().flatten();
            if *content != a && *content != b && !allowed.contains(content) {
                fail(
                    "I2",
                    format!(
                        "slot {i} is neither the pre-operation record ({:?} bytes) nor the post-operation one ({:?} bytes): {:?} bytes",
                        a.as_ref().map(Vec::len),
                        b.as_ref().map(Vec::len),
                        content.as_ref().map(Vec::len)
                    ),
                );
            }
        }
    }

    // I10: a cut during CHANGE-PIN always leaves one PIN working.
    if matches!(op, Op::ChangePin { .. }) {
        if !after.old_pin_opens && !after.new_pin_opens {
            fail(
                "I10",
                "neither the old PIN nor the new PIN opens the store".to_string(),
            );
        }
        if after.old_pin_opens && after.new_pin_opens {
            fail(
                "I10",
                "both PINs open the store, so the change is neither committed nor rolled back"
                    .to_string(),
            );
        }
        // I7: once the change has committed, no old-PIN ciphertext survives anywhere.
        if after.new_pin_opens && after.old_pin_sides != 0 {
            fail(
                "I7",
                format!(
                    "{} side(s) still hold ciphertext that opens under the retired PIN",
                    after.old_pin_sides
                ),
            );
        }
    }

    // I11: the policy is never weaker than both the old value and the new one.
    let weaker_than_pre = !after.policy.at_least_as_strict_as(&pre.policy);
    let weaker_than_post = !after.policy.at_least_as_strict_as(&post.policy);
    if weaker_than_pre && weaker_than_post {
        fail(
            "I11",
            format!(
                "effective policy {:?} is weaker than both the old {:?} and the new {:?}",
                after.policy.wipe_after, pre.policy.wipe_after, post.policy.wipe_after
            ),
        );
    }

    // A store that reports a tamper kind must say which; an empty kind with a tamper state
    // would be a refusal the product could not explain.
    if let StoreState::Inconsistent(_) = after.state {
        if after.tamper.is_empty() {
            fail(
                "I1",
                "store is Inconsistent but reports no tamper kind".to_string(),
            );
        }
    }

    let _ = cfg;
}

fn first_duplicate(baseline: &[SealRecord], seals: &[SealRecord]) -> Option<SealRecord> {
    let mut seen: Vec<&SealRecord> = baseline.iter().collect();
    for s in seals {
        if seen.iter().any(|p| p.key == s.key && p.nonce == s.nonce) {
            return Some(*s);
        }
        seen.push(s);
    }
    None
}

/// Sides are enumerated in a fixed order so a finding names the same side every run.
const _: () = assert!(Side::A as u8 == 0 && Side::B as u8 == 1);
