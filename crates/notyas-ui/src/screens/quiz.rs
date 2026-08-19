// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! S-17 Backup check (UX 5): the mandatory gate between a new seed and a usable wallet.
//!
//! Commandment 3 - no backup exists until it is verified. Every word position, five
//! candidates, no skipping and no sampling: it takes about two minutes and it is the only
//! moment the device can catch a transcription error while the words are still on the
//! table. A wrong answer re-poses THAT word with a fresh candidate set rather than
//! restarting the quiz (BitBox02's behaviour), because a full restart punishes a fat
//! finger with twenty-four re-taps and teaches people to rush.
//!
//! # Where the candidates come from, and why not from an HMAC
//!
//! UX-SCREENS S-17 specifies distractors weighted toward confusables and derived, without
//! an RNG, from `HMAC_efuse(quiz_domain || word_index || mnemonic_position)`. This crate
//! has neither an RNG (SECURITY.md invariant 3) nor a path to the eFuse, and asking the
//! std side per word would mean handing the CORRECT WORD across the boundary to get a
//! candidate set back - a worse trade than the one the derivation was protecting.
//!
//! So the derivation is a pure function of (position, attempt) over the public wordlist,
//! and it delivers what the specified one was specified FOR:
//!
//! - **Maximum confusability.** The candidates are the correct word's neighbours in the
//!   sorted BIP-39 list, which are exactly the words sharing its longest prefix - the real
//!   transcription risk, and precisely the set S-17's own wireframe draws (crouch, crowd,
//!   cruel, crumble, crunch are consecutive entries). Note the spec's "same 4-letter
//!   prefix" cannot be it: BIP-39 guarantees the first four letters are UNIQUE, so that
//!   set is always empty.
//! - **A fresh set on a re-pose.** The wrong-answer counter is mixed in, so re-posing a
//!   word moves both the window and the correct answer's slot. Without this a user who
//!   failed once could answer the retry by position.
//! - **A uniform correct slot.** Asserted over the whole wordlist below, which is the
//!   property that stops the quiz from having a tell.

use alloc::string::String;
use alloc::vec::Vec;

use embedded_graphics::draw_target::{DrawTarget, DrawTargetExt};
use embedded_graphics::pixelcolor::Rgb565;

use crate::canvas::{fill, frame, text, text_centered, wrap_words, BODY, HEADING, MONO};
use crate::components::{back_rect, draw_bar, LINE, SMALL_LINE};
use crate::layout::{Rect, LIST_ROW_MIN};
use crate::screens::fork::ForkState;
use crate::screens::{Ctx, Env, Nav, Outcome, Screen, State};
use crate::theme::*;
use crate::{BackupState, QuizView, Region, RegionId};
use notyas_core::bip39::wordlist;
use notyas_core::report::Report;

/// Candidates offered per word. Five, per S-17; the layout below is written against this
/// constant rather than against the number 5.
const CHOICES: usize = 5;

pub(crate) struct QuizState {
    /// The finished wallet, parked here until the fork takes it.
    ///
    /// `Option` because the next screen MOVES it out of a `&mut self`, which is the only
    /// way a screen can hand a non-`Clone` secret forward; the state it is taken from is
    /// dropped on the same transition.
    pub report: Option<Report>,
    /// Word position under test, 0-based.
    at: usize,
    /// Wrong answers on the CURRENT word. Mixed into the candidate derivation, so a
    /// re-pose is a genuinely fresh set rather than the same five in the same order.
    attempt: u32,
    /// The last tap was wrong and the line saying so is showing. Cleared by the next tap.
    wrong: bool,
}

impl QuizState {
    pub fn new(report: Report) -> QuizState {
        QuizState { report: Some(report), at: 0, attempt: 0, wrong: false }
    }

    /// The mnemonic being checked. Empty only if the report has already been handed on,
    /// which cannot happen while this screen is the live one.
    fn words(&self) -> &[String] {
        self.report.as_ref().map_or(&[], |r| &r.words)
    }

    /// The candidates for the word under test, in the order they are drawn.
    ///
    /// Returned by reference into the wordlist and the report, so the correct word is
    /// never copied onto the heap for the sake of being displayed.
    fn choices(&self) -> Vec<&str> {
        let list = wordlist();
        let n = list.len() as u64;
        let Some(word) = self.words().get(self.at) else { return Vec::new() };
        // Where in the list the answer sits. A word outside the list cannot occur on this
        // path (the quiz runs on a mnemonic this device derived), and index 0 is the
        // harmless fallback rather than a panic in the draw path.
        let idx = list.binary_search(&word.as_str()).unwrap_or(0) as u64;
        let slot = self.slot() as u64;
        // Wrapping rather than clamping: clamping would pin the correct answer to a fixed
        // slot for the first and last few words of the list, which is exactly the tell
        // the uniform distribution exists to prevent.
        let start = (idx + n - slot) % n;
        (0..CHOICES as u64)
            .map(|k| {
                if k == slot {
                    word.as_str()
                } else {
                    list[((start + k) % n) as usize]
                }
            })
            .collect()
    }
}

impl QuizState {
    /// Which slot the correct word occupies, for the attempt in progress.
    ///
    /// Derived one attempt at a time rather than in one shot, for a property one shot
    /// cannot have: each attempt lands in a slot the previous attempt did NOT use. A
    /// straight hash of (position, attempt) collides one time in five, and a re-pose that
    /// shows the same five words in the same order is not the fresh candidate set S-17
    /// asks for - it is a retry the user can answer by position. The loop is over the
    /// wrong answers the user has actually given, so it is as short as their patience.
    fn slot(&self) -> usize {
        let n = CHOICES as u64;
        let mut slot = mix(self.at as u64, 0) % n;
        for attempt in 1..=self.attempt {
            // `1 + r` for r in 0..n-1 covers every slot except the current one, so the
            // step is unpredictable and never zero.
            slot = (slot + 1 + mix(self.at as u64, attempt as u64) % (n - 1)) % n;
        }
        slot as usize
    }
}

/// A deterministic 64-bit mix of the two inputs a candidate set derives from.
///
/// SplitMix64's finalizer: three multiply-xorshift rounds, chosen because it is a few
/// lines of integer arithmetic with a known avalanche and no state - this crate has no
/// RNG and must never grow one (invariant 3). It is a display permutation, not key
/// material, and nothing here is or claims to be cryptographic.
fn mix(position: u64, attempt: u64) -> u64 {
    let mut z = (position << 32 ^ attempt).wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

pub(crate) struct Layout {
    question: Rect,
    /// The five candidate rows, in draw and hit-test order.
    choices: [Rect; CHOICES],
    status: Rect,
}

impl Screen for QuizState {
    type Layout = Layout;

    /// Question across the top, candidates below it, one status line at the foot.
    ///
    /// The portrait panel stacks all five candidates; the short panel puts them in two
    /// columns of two plus one full-width row, because five stacked rows at the
    /// `LIST_ROW_MIN` floor do not fit in 377 px of body and the floor outranks the
    /// arrangement (reflow rule 2's reasoning, applied to rows).
    fn layout(&self, ctx: &Ctx) -> Layout {
        let m = &ctx.m;
        let body = m.body();
        let g = m.gap;
        let question = Rect::new(body.x, body.y, body.w, LINE);
        let status = Rect::new(body.x, body.bottom() - LINE, body.w, LINE);
        let grid = Rect::new(
            body.x,
            question.bottom() + g,
            body.w,
            status.y - g - (question.bottom() + g),
        );

        let mut choices = [Rect::new(0, 0, 0, 0); CHOICES];
        if m.landscape() {
            // Three rows: two pairs and a full-width fifth.
            let row_h = ((grid.h - 2 * ROW_GAP) / 3).max(LIST_ROW_MIN);
            let half = (grid.w - ROW_GAP) / 2;
            for (i, r) in choices.iter_mut().enumerate() {
                let (col, row) = (i as i32 % 2, i as i32 / 2);
                let y = grid.y + row * (row_h + ROW_GAP);
                *r = if i == CHOICES - 1 {
                    Rect::new(grid.x, y, grid.w, row_h)
                } else {
                    Rect::new(grid.x + col * (half + ROW_GAP), y, half, row_h)
                };
            }
        } else {
            let row_h = ((grid.h - (CHOICES as i32 - 1) * ROW_GAP) / CHOICES as i32)
                .max(LIST_ROW_MIN);
            for (i, r) in choices.iter_mut().enumerate() {
                *r = Rect::new(grid.x, grid.y + i as i32 * (row_h + ROW_GAP), grid.w, row_h);
            }
        }
        Layout { question, choices, status }
    }

    fn regions(&self, ctx: &Ctx, out: &mut Vec<Region>) {
        let l = self.layout(ctx);
        out.push(Region { id: RegionId::Back, rect: back_rect(&ctx.m) });
        for (i, r) in l.choices.iter().enumerate() {
            out.push(Region { id: RegionId::QuizChoice(i as u8), rect: *r });
        }
    }

    fn draw<D: DrawTarget<Color = Rgb565>>(&self, t: &mut D, ctx: &Ctx) -> Result<(), D::Error> {
        let m = &ctx.m;
        let words = self.words().len();
        // The progress counter rides the bar, exactly as C1's right slot specifies, which
        // is what buys the body the height its five rows need.
        draw_bar(t, m, &format!("Check your backup - {} of {words}", self.at + 1))?;
        let l = self.layout(ctx);

        let q = format!("Which word did you write down as word {}?", self.at + 1);
        text(t, &q, l.question.x, l.question.y, HEADING, INK_PRIMARY, PAPER_1)?;

        // Every candidate is drawn identically: same fill, same ink, same face, same
        // height. The correct one carries no rendering artifact at all, which is the
        // pixel-level property S-17 asks for - swapping which candidate is correct must
        // permute rows and change nothing else.
        for (r, word) in l.choices.iter().zip(self.choices()) {
            fill(t, *r, PAPER_2)?;
            frame(t, *r, BORDER_STRONG)?;
            let mut clip = t.clipped(&r.to_eg());
            text_centered(&mut clip, word, *r, MONO, INK_PRIMARY, PAPER_2)?;
        }

        // One status row, carrying whichever of the two things is true. They are mutually
        // exclusive by construction - a wrong answer is the newest fact on the screen -
        // and two rows would cost a candidate its floor on the short panel.
        let (line, ink) = if self.wrong {
            (
                format!("That is not word {}. Read your backup again.", self.at + 1),
                DANGER,
            )
        } else {
            (format!("{} of {words} words checked", self.at), INK_SECONDARY)
        };
        for (i, wrapped) in wrap_words(&line, l.status.w, BODY).into_iter().enumerate() {
            text(
                t,
                &wrapped,
                l.status.x,
                l.status.y + i as i32 * SMALL_LINE,
                BODY,
                ink,
                PAPER_1,
            )?;
        }
        Ok(())
    }

    fn activate(&mut self, id: RegionId, _env: &mut Env) -> Outcome {
        let RegionId::QuizChoice(i) = id else { return Outcome::stay() };
        // Judged through the same list `choices` built and `regions` hit-tested, so slot
        // `i` can never resolve to a different word than the one under the finger. The
        // block is what releases the borrow before `self` is mutated.
        let correct = {
            let choices = self.choices();
            let Some(&picked) = choices.get(i as usize) else { return Outcome::stay() };
            self.words().get(self.at).is_some_and(|w| w.as_str() == picked)
        };
        if !correct {
            self.wrong = true;
            self.attempt = self.attempt.saturating_add(1);
            return Outcome::stay();
        }
        self.wrong = false;
        self.attempt = 0;
        self.at += 1;
        if self.at < self.words().len() {
            return Outcome::stay();
        }
        // Every word checked: the backup now exists, and the fork is what it exists for.
        // Entered rather than pushed - the quiz has handed its report on and there is
        // nothing behind it worth returning to.
        match self.report.take() {
            Some(report) => Outcome::enter(State::Fork(ForkState::new(
                report,
                BackupState::Verified(String::new()),
            ))),
            None => Outcome::stay(),
        }
    }

    /// The words are still in memory and the user is part way through proving they wrote
    /// them down: Back asks first.
    fn back(&self) -> Nav {
        Nav::ConfirmExit
    }
}

/// Gap between candidate rows. Tighter than `Metrics::gap`, because the rows' own
/// `LIST_ROW_MIN` floor is what the height budget has to spend on.
const ROW_GAP: i32 = 8;

impl QuizState {
    /// What the screen is asking, for a host driver that has no other way to read the
    /// panel. See [`QuizView`] for why this discloses nothing the screen does not.
    pub fn view(&self) -> QuizView {
        QuizView {
            word: self.at as u8 + 1,
            words: self.words().len() as u8,
            done: self.at as u8,
            choices: self.choices().into_iter().map(String::from).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::screens::testing::{Fixture, GEOMETRIES};

    /// The correct answer lands in every slot about equally often over the whole wordlist.
    ///
    /// This is the security-relevant property of the candidate derivation: a quiz whose
    /// answer is usually third teaches people to tap third. The bound is generous because
    /// the point is the absence of a bias, not a claim about a hash.
    #[test]
    fn the_correct_answer_is_uniform_across_the_five_slots() {
        let mut counts = [0usize; CHOICES];
        for position in 0..wordlist().len() {
            let state = QuizState { report: None, at: position, attempt: 0, wrong: false };
            counts[state.slot()] += 1;
        }
        let expect = wordlist().len() / CHOICES;
        for (slot, &c) in counts.iter().enumerate() {
            let drift = c.abs_diff(expect);
            assert!(
                drift * 10 < expect,
                "slot {slot} holds the answer {c} times against {expect} expected: {counts:?}"
            );
        }
    }

    /// A re-posed word ALWAYS lands somewhere else. Not usually, always: a retry that
    /// happens to repeat the last arrangement is one the user can answer from muscle
    /// memory, and one time in five is often enough to matter over twenty-four words.
    #[test]
    fn a_wrong_answer_never_re_poses_the_same_arrangement() {
        for at in 0..24usize {
            let mut previous = None;
            for attempt in 0..8u32 {
                let s = QuizState { report: None, at, attempt, wrong: false }.slot();
                assert!(s < CHOICES, "slot {s} is off the pad");
                assert_ne!(Some(s), previous, "word {at} attempt {attempt} repeated a slot");
                previous = Some(s);
            }
        }
    }

    /// Every candidate row keeps the list floor and stays inside the body on both panels,
    /// which is the constraint that forces the two arrangements.
    #[test]
    fn five_candidates_keep_their_floor_on_both_panels() {
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            let ctx = f.ctx();
            let state = QuizState { report: None, at: 0, attempt: 0, wrong: false };
            let l = state.layout(&ctx);
            let body = f.m.body();
            for (i, r) in l.choices.iter().enumerate() {
                assert!(
                    r.h >= LIST_ROW_MIN,
                    "{w}x{h}: candidate {i} is {} px tall, below {LIST_ROW_MIN}",
                    r.h
                );
                assert!(
                    r.x >= body.x && r.right() <= body.right() && r.bottom() <= l.status.y,
                    "{w}x{h}: candidate {i} at {r:?} escapes the grid"
                );
            }
            for (i, a) in l.choices.iter().enumerate() {
                for b in &l.choices[i + 1..] {
                    assert!(!a.overlaps(b), "{w}x{h}: candidate {i} overlaps a sibling");
                }
            }
        }
    }
}
