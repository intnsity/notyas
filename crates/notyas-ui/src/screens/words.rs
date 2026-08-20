// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! S-04a: what the two device words are, and when to look at them.
//!
//! # Why an explainer earns a screen here, when it would not anywhere else
//!
//! The anti-phishing words are the strongest thing this device does about substitution,
//! and they are worth exactly nothing unless the user knows two facts: that a counterfeit
//! cannot compute them, and that the moment to check them is BEFORE the rest of the PIN is
//! typed. A user who reads them afterwards has already handed the whole PIN to whatever is
//! in their hand. That is the entire failure mode, it is a knowledge failure rather than a
//! mechanism failure, and no amount of cryptography closes it.
//!
//! It replaces something weaker. Until 2026-08-19 the lock screen carried a user-chosen
//! "lock word" whose panel claimed it let the user tell this device from a fake; the claim
//! was false, because a string shown before authentication is readable by whoever would
//! build the counterfeit. The claim was not merely deleted - it moved to the mechanism that
//! can keep it, and this screen is where the user is told so.
//!
//! # Shown twice at most, and skippable both times
//!
//! At the two moments the user can act on it: when a PIN has just been set, and the first
//! time the words are about to be shown. Never again - `Ui` holds the flag, because it
//! outlives both screens. One button, no gate, no acknowledgement to tick: an explainer
//! that has to be dismissed twice is an explainer people learn to dismiss without reading,
//! which would cost the words the one thing this screen exists to give them.

use alloc::string::String;
use alloc::vec::Vec;

use embedded_graphics::draw_target::{DrawTarget, DrawTargetExt};
use embedded_graphics::pixelcolor::Rgb565;

use crate::canvas::{button, text, wrap_words, ButtonKind, BODY, HEADING};
use crate::components::{draw_bar_no_back, LINE};
use crate::layout::Rect;
use crate::screens::{Ctx, Env, Nav, Outcome, Screen};
use crate::theme::*;
use crate::{Region, RegionId, PIN_WORDS_AT};

/// The one explainer in the product, held as a unit struct because it has nothing to
/// remember: it is read and dismissed, and whether it has been read is the `Ui`'s to know.
pub(crate) struct WordsInfoState;

const HEADING_LINE: &str = "The two device words";
const DISMISS: &str = "Got it";

/// The copy, in the order the facts are needed.
///
/// Two short paragraphs and no more, and the length is a constraint rather than a taste:
/// the 800x480 body leaves this screen five lines between its heading and its button, and
/// a sixth would be clipped away silently. The test below is what holds the line.
///
/// The first paragraph says what the words are and specifically that the device COMPUTES
/// them - a user who believes they are stored will not understand why a copy cannot show
/// them. The second carries the property and the instruction together, in that order,
/// because an instruction only lands after the reason for it; it is also the only
/// paragraph drawn in primary ink, which is the whole point of the screen.
fn paragraphs() -> [String; 2] {
    [
        alloc::format!(
            "Type the first {PIN_WORDS_AT} digits of your PIN and this device shows two \
             words. It works them out from those digits and a secret only it holds."
        ),
        String::from(
            "No copy of this device can work them out. Check them BEFORE you type the \
             rest of your PIN.",
        ),
    ]
}

pub(crate) struct Layout {
    heading: Rect,
    body: Rect,
    dismiss: Rect,
}

impl Screen for WordsInfoState {
    type Layout = Layout;

    fn layout(&self, ctx: &Ctx) -> Layout {
        let m = &ctx.m;
        let body = m.body();
        let g = m.gap;
        let heading = Rect::new(body.x, body.y, body.w, HEADING.line_height as i32);
        // The button is anchored to the foot and the prose takes what is left, rather than
        // the prose flowing and the button following it: this screen is dismissed by
        // habit after the first read, and a button that moved with the copy would be a
        // button in a different place on the two panels for no reason a user could see.
        let dismiss_w = (body.w * 2 / 5).max(260).min(body.w);
        let dismiss = Rect::new(body.right() - dismiss_w, body.bottom() - m.btn, dismiss_w, m.btn);
        let top = heading.bottom() + g;
        Layout { heading, body: Rect::new(body.x, top, body.w, (dismiss.y - g - top).max(0)), dismiss }
    }

    fn regions(&self, ctx: &Ctx, out: &mut Vec<Region>) {
        let l = self.layout(ctx);
        // No Back. This screen has one way out and it is the button, so that dismissing it
        // is one deliberate act rather than two rectangles that mean the same thing - and
        // so the bar cannot offer a route back to a PIN pad that is mid-entry.
        out.push(Region { id: RegionId::WordsUnderstood, rect: l.dismiss });
    }

    fn draw<D: DrawTarget<Color = Rgb565>>(&self, t: &mut D, ctx: &Ctx) -> Result<(), D::Error> {
        let m = &ctx.m;
        draw_bar_no_back(t, m, "Before you type your PIN")?;
        let l = self.layout(ctx);
        text(t, HEADING_LINE, l.heading.x, l.heading.y, HEADING, INK_PRIMARY, PAPER_1)?;

        let mut y = l.body.y;
        let mut clip = t.clipped(&l.body.to_eg());
        let block = paragraphs();
        let n = block.len();
        for (i, para) in block.iter().enumerate() {
            // The instruction is the last paragraph and the only one in primary ink. A
            // screen where everything is emphasised has emphasised nothing.
            let ink = if i + 1 == n { INK_PRIMARY } else { INK_SECONDARY };
            if i > 0 {
                y += m.gap;
            }
            for line in wrap_words(para, l.body.w, BODY) {
                text(&mut clip, &line, l.body.x, y, BODY, ink, PAPER_1)?;
                y += LINE;
            }
        }
        button(t, l.dismiss, DISMISS, ButtonKind::Primary, PAPER_1)?;
        Ok(())
    }

    fn activate(&mut self, id: RegionId, _env: &mut Env) -> Outcome {
        match id {
            RegionId::WordsUnderstood => Outcome { nav: Nav::Back, request: None },
            _ => Outcome::stay(),
        }
    }

    /// Back is whatever raised it - PIN entry with its prefix still typed, or the flow the
    /// new PIN interrupted. The screen is an interstitial and owns nothing, so returning
    /// costs nothing.
    fn back(&self) -> Nav {
        Nav::Back
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::screens::testing::{rows_are_clear_on, Fixture, GEOMETRIES};

    /// The three blocks stay clear of each other and on the panel, at both geometries.
    #[test]
    fn no_two_blocks_of_the_explainer_overlap() {
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            let l = WordsInfoState.layout(&f.ctx());
            rows_are_clear_on(
                &f.m,
                &format!("{w}x{h}"),
                Rect::new(0, f.m.bar, f.m.w, f.m.h - f.m.bar),
                &[("heading", l.heading), ("copy", l.body), ("dismiss", l.dismiss)],
            );
        }
    }

    /// All three paragraphs fit the block they are drawn in, on both panels.
    ///
    /// `draw` clips to that block, so copy that overran would not overlap anything - it
    /// would simply be gone, and the sentence most likely to go is the last one, which is
    /// the instruction the whole screen exists to deliver.
    #[test]
    fn the_whole_explanation_fits_on_both_panels() {
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            let l = WordsInfoState.layout(&f.ctx());
            let lines: i32 = paragraphs()
                .iter()
                .map(|p| wrap_words(p, l.body.w, BODY).len() as i32)
                .sum();
            let need = lines * LINE + (paragraphs().len() as i32 - 1) * f.m.gap;
            assert!(
                need <= l.body.h,
                "{w}x{h}: the explanation needs {need} px in a {} px block",
                l.body.h
            );
            assert!(
                HEADING.text_width(HEADING_LINE) as i32 <= l.heading.w,
                "{w}x{h}: the heading does not fit its row"
            );
        }
    }

    /// The explanation actually contains the three things it is required to say.
    ///
    /// Worded over the copy rather than over the layout because this is a REQUIREMENT about
    /// content: the words are derived rather than stored, a counterfeit cannot produce
    /// them, and the check happens before the rest of the PIN. A rewrite that dropped any
    /// of the three would leave a screen that reads fine and teaches nothing.
    #[test]
    fn the_explanation_says_the_three_things_it_exists_to_say() {
        let all = paragraphs().join(" ").to_lowercase();
        assert!(all.contains("works them out"), "it does not say the device derives them");
        assert!(all.contains("secret only it holds"), "it does not say what else from");
        assert!(all.contains("no copy of this device can work them out"), "a copy is not ruled out");
        assert!(all.contains("before you type the rest"), "it does not say when to check");
        // The threshold is formatted from the constant the PIN screen guards on, never a
        // literal: an explainer that promised the words at a different digit than the one
        // that unlocks the button is a screen teaching the user something false.
        assert!(
            all.contains(&alloc::format!("first {PIN_WORDS_AT} digits")),
            "the threshold is not the one S-04 enforces"
        );
    }
}
