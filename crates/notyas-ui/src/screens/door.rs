// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The dice door: the pre-PIN way into the dice-only flow from S-03
//! (docs/plan-0.2.0/SIMPLE-MODE.md).
//!
//! 0.1.0 was a dice seed generator that stored nothing. 0.2.0 put a PIN in front of the
//! store, and on a device that has saved one wallet that PIN ends up in front of the dice
//! flow too - even though nothing on that flow reads the store, writes it, or derives
//! anything from the PIN. The door removes that precondition and nothing else: one card
//! on the lock screen that pushes S-12.
//!
//! # What the door is, stated as invariants
//!
//! - **It records nothing.** There is no preference, no flag, no mode. A persistent
//!   toggle would be stored state, and SECURITY.md invariant 2a says a device with no
//!   stored wallet writes nothing to flash - so the setting meant to make the dice-only
//!   product easy to reach could exist only on devices that have already left it. That is
//!   why this module has no state type: there is nothing for one to hold.
//! - **It opens no store.** No mount, no unseal, no attempt-counter tick. [`open`]
//!   returns a navigation and no [`crate::UiRequest`] at all, which is that rule made
//!   mechanical rather than editorial.
//! - **It is pushed, not entered.** S-03 is the floor of a locked device and the door has
//!   to be able to return to it. See the note on `Ui::floor` in
//!   docs/plan-0.2.0/SIMPLE-MODE.md section 9.
//! - **It assumes no anti-phishing words** (R20). The card states nothing about this
//!   unit at all: no wallet count, no word, no name. So it renders identically on a
//!   device with one wallet and a device with eight, and it says nothing that would be
//!   false on a device whose device-key derivations do not exist yet.
//!
//! # Why the whole S-03 arrangement lives here
//!
//! [`place`] returns every rectangle the lock screen has, not just the card's. The card
//! is the reason the arrangement had to change: S-03 already overflowed at 800x480 before
//! any of this (the unlock hint was drawn across the footer), and the fix is a genuine
//! two-column rearrangement rather than a compression. Keeping the arrangement beside the
//! thing that forced it means the fit is testable as one unit at both geometries, which
//! is what the tests at the bottom of this file do - the overflow class was invisible to
//! CI precisely because it was measured text rather than regions.

// The call sites are S-03's `layout`, `regions` and `draw` in `screens/lock.rs`, and they
// land with the layout change this module exists to make possible. Until they do, nothing
// in the crate calls any of this. The allow is scoped to this module and comes off with
// the first call site.
#![allow(dead_code)]

use embedded_graphics::draw_target::{DrawTarget, DrawTargetExt};
use embedded_graphics::pixelcolor::Rgb565;

use crate::canvas::{fill, frame, text, wrap_words, BODY, HEADING};
use crate::components::{LINE, SMALL_LINE};
use crate::layout::{Metrics, Rect};
use crate::screens::dice::DiceState;
use crate::screens::{Outcome, State};
use crate::theme::*;
use crate::RegionId;

// ---------------------------------------------------------------------------------------
// Copy
// ---------------------------------------------------------------------------------------

/// The card's heading, reused verbatim from the stateless home's first button.
///
/// One label per concept across the product (UX-SCREENS.md 3.1): the concept is identical
/// and so is the destination, so a second wording for it would fork the vocabulary for
/// nothing. The parenthetical is not decoration - it is what keeps the label accurate for
/// a card that goes straight to S-12 and skips S-11's method fork, which a dice-only door
/// has no reason to show.
pub(crate) const CARD_HEADING: &str = "New seed (dice)";

/// The card's body: three mechanical facts, in the order the two audiences need them.
///
/// "Nothing is written." is deliberately the same claim in the same words as S-19's
/// use-once card and S-40's notice, so it reads as a property of the device rather than
/// as per-screen boilerplate. "Your stored wallets stay locked." answers the wallet
/// owner's only question in the sentence the dice user reads for the opposite reason, and
/// it does so without stating a count (Q2(a)).
///
/// No adjective appears here, and none may: not "simple", not "easy", not "safe". The
/// moment one path is called simple the other becomes the real one, and the product has
/// told the user that the configuration PIN-MODES.md calls the safest state the hardware
/// can be in is the one for people who cannot manage the rest.
pub(crate) const CARD_BODY: &str = "No PIN. Nothing is written. Your stored wallets stay locked.";

/// S-03's unlock hint, corrected by the door.
///
/// "Touch anywhere to unlock" stops being true the moment the body carries a second
/// affordance. A near-true line is worse than a shorter true one (UX-REVISION.md A9), and
/// this is the shorter true one.
pub(crate) const UNLOCK_HINT: &str = "Touch to unlock";

/// What a tap on the card means. Reused rather than a new variant: a region names the
/// MEANING of the tap, never the widget or its position (UX-SCREENS.md 4), and the
/// meaning here is exactly the stateless home's - start a dice seed run. A
/// `LockDiceDoor` would grow the enum by one variant per entry point, which is that
/// rule's opposite.
pub(crate) const REGION: RegionId = RegionId::HomeNewSeed;

// ---------------------------------------------------------------------------------------
// Navigation
// ---------------------------------------------------------------------------------------

/// What the door does when tapped.
///
/// `push`, not `enter`: the lock screen is the floor of a locked device, and the door has
/// to be able to hand it back. It carries no [`crate::UiRequest`], and that absence is
/// the point - the door path issues nothing that could reach the store, so "the store is
/// never opened on the door path" is checkable by looking at what this function returns.
pub(crate) fn open() -> Outcome {
    Outcome::push(State::Dice(DiceState::new()))
}

// ---------------------------------------------------------------------------------------
// Geometry
// ---------------------------------------------------------------------------------------

/// Every rectangle S-03 has, arranged around the door card.
///
/// One struct rather than four functions because the parts constrain each other: the card
/// is anchored above the footer, and what is left over is what the identity block and the
/// status lines have to fit into. Splitting that into independent queries is how the two
/// halves drift apart and one of them ends up drawn across the other, which is the defect
/// this arrangement fixes.
pub(crate) struct Placement {
    /// Where the identity block goes: the title, the nickname, the lock-word panel,
    /// stacked from the top of this rectangle.
    pub identity: Rect,
    /// Where "Locked" and [`UNLOCK_HINT`] go, when the arrangement gives them a column
    /// of their own.
    ///
    /// `None` on the portrait panel, where they simply continue the single column under
    /// the identity block. An `Option` rather than a rectangle equal to `identity`
    /// because the two cases differ in KIND, not in coordinates: a caller that flows on
    /// from the lock-word panel and a caller that starts a fresh column are different
    /// code, and making the difference representable is what stops one of them running
    /// silently in the other's arrangement.
    pub status: Option<Rect>,
    /// The door card.
    pub card: Rect,
    /// The body with the card subtracted: what stays tappable as
    /// [`RegionId::LockWake`].
    ///
    /// One rectangle in portrait, two in the landscape arrangement, because the region
    /// test forbids ANY overlap between returned rectangles - so the wake area has to be
    /// computed to exclude the card rather than rely on hit-test order. Two rectangles
    /// carrying one `RegionId` is deliberate and costs nothing: the region-parity test
    /// compares `RegionId` sets, and the two sets are equal. Without the second one the
    /// lock word - the element the user is meant to read before typing - would sit in a
    /// dead zone on the landscape panel.
    pub wake: (Rect, Option<Rect>),
    /// The version and storage-word band, full width on both panels.
    pub footer: Rect,
}

impl Placement {
    /// The wake rectangles, in the order `regions` should push them.
    pub fn wake_rects(&self) -> impl Iterator<Item = Rect> + '_ {
        core::iter::once(self.wake.0).chain(self.wake.1)
    }
}

/// Height the card needs for a `w`-wide slot, measured with the same wrap the drawing
/// uses. Never guessed: the body wraps to two lines on the tall panel and three in a
/// landscape column, and a constant would be wrong on one of them.
pub(crate) fn card_height(w: i32, gap: i32) -> i32 {
    let inner = w - 2 * gap;
    let lines = wrap_words(CARD_BODY, inner, BODY).len() as i32;
    // The body ADVANCES `SMALL_LINE` per line but each line's glyph box is a full BODY
    // line, so the last one is measured at its real height rather than at the advance.
    // Without that the card's own clip cuts the descenders off the closing sentence -
    // the one that tells a wallet owner their wallets stay locked.
    2 * gap + LINE + (lines - 1) * SMALL_LINE + BODY.line_height as i32
}

/// Arrange S-03 around the door, at whatever geometry this panel is.
///
/// Portrait keeps the shipped single column and only moves the identity block up, from
/// `body.h / 8` to `body.h / 16`, to pay for the card. Landscape is a rearrangement
/// rather than a compression (UX-SCREENS.md reflow rule 3): identity on the left, status
/// and card on the right. That is not cosmetic - laid out top-down in one column, the
/// 800x480 lock screen already drew its unlock hint across the footer band, and no
/// amount of tightening a single column recovers 42 px of it.
pub(crate) fn place(m: &Metrics) -> Placement {
    let body = m.body();
    let gap = m.gap;
    let footer = Rect::new(0, m.h - m.pad - LINE, m.w, LINE);
    // Everything else stops one gap above the footer band. The band is full width on both
    // panels (reflow rule 5), so this is the one bound both arrangements share.
    let content_bottom = footer.y - gap;

    if m.landscape() {
        // Two columns of equal width, anchored to the two edges so an odd body width
        // loses its remainder to the gutter rather than to one column.
        let half = (body.w - gap) / 2;
        let left = Rect::new(body.x, body.y, half, content_bottom - body.y);
        let right = Rect::new(body.right() - half, body.y, half, content_bottom - body.y);

        let card_h = card_height(right.w, gap);
        // Bottom-anchored: the card is the last thing on the screen in reading order, and
        // anchoring it means a longer status line above never pushes it into the footer.
        let card = Rect::new(right.x, content_bottom - card_h, right.w, card_h);
        let status = Some(Rect::new(right.x, right.y, right.w, card.y - gap - right.y));

        // The split runs down the middle of the gutter, so a finger that lands between
        // the columns wakes the device rather than landing on nothing.
        let split = left.right() + gap / 2;
        let wake_left = Rect::new(0, m.bar, split, content_bottom + gap - m.bar);
        let wake_right = Rect::new(split, m.bar, m.w - split, card.y - gap - m.bar);
        Placement {
            identity: left,
            status,
            card,
            wake: (wake_left, Some(wake_right)),
            footer,
        }
    } else {
        let card_h = card_height(body.w, gap);
        let card = Rect::new(body.x, content_bottom - card_h, body.w, card_h);
        // The identity block starts a sixteenth of the way down rather than an eighth:
        // the whole delta the card costs the portrait arrangement, and the only change to
        // it. If a future string or font makes this stop fitting, collapse the lock-word
        // panel to one row first and drop this offset to `gap` second. Never drop content
        // and never shrink the card (reflow rule 4).
        let top = body.y + body.h / 16;
        let identity = Rect::new(body.x, top, body.w, card.y - gap - top);
        Placement {
            identity,
            // Portrait stacks the status lines under the identity block in the same
            // column, so there is no second rectangle to hand out.
            status: None,
            card,
            wake: (Rect::new(0, m.bar, m.w, card.y - gap - m.bar), None),
            footer,
        }
    }
}

// ---------------------------------------------------------------------------------------
// Drawing
// ---------------------------------------------------------------------------------------

/// The door card: a heading and the mechanism line, in the same card grammar as S-19's
/// two halves, clipped to its own rectangle so a longer body can never bleed onto the
/// footer.
pub(crate) fn draw_card<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    r: Rect,
    gap: i32,
) -> Result<(), D::Error> {
    fill(t, r, PAPER_2)?;
    frame(t, r, BORDER_STRONG)?;
    let inner = r.inset(gap);
    let mut clip = t.clipped(&inner.to_eg());
    text(&mut clip, CARD_HEADING, inner.x, inner.y, HEADING, INK_PRIMARY, PAPER_2)?;
    let mut y = inner.y + LINE;
    for line in wrap_words(CARD_BODY, inner.w, BODY) {
        text(&mut clip, &line, inner.x, y, BODY, INK_SECONDARY, PAPER_2)?;
        y += SMALL_LINE;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canvas::TITLE;
    use crate::layout::TOUCH_MIN;
    use crate::screens::testing::GEOMETRIES;

    /// What the identity column has to hold: the product title and the device name.
    ///
    /// It used to have a third block, the lock-word panel, and this constant tracked its
    /// height. The word went on 2026-08-19 (`screens/lock.rs`), so the budget this file
    /// checks against is smaller by exactly that panel - which can only make the door fit
    /// more easily, never less.
    fn identity_h(m: &Metrics) -> i32 {
        TITLE.line_height as i32 + m.gap + LINE
    }

    /// What the status block has to hold: "Locked" and the unlock hint.
    fn status_h(m: &Metrics) -> i32 {
        LINE + m.gap + LINE
    }

    /// The whole point of the arrangement: everything S-03 draws fits above the footer
    /// band, on both panels.
    ///
    /// This is the assertion the crate did not have. The 800x480 overflow that prompted
    /// it was invisible to CI because the unlock hint and the footer are measured text
    /// rather than regions, and the region checks only ever see regions - so a screen
    /// could draw one line across another and every test in the suite would pass.
    #[test]
    fn nothing_is_drawn_across_the_footer() {
        for (w, h) in GEOMETRIES {
            let m = Metrics::new(w, h);
            let p = place(&m);
            assert!(
                p.card.bottom() <= p.footer.y,
                "{w}x{h}: the door card runs into the footer band"
            );
            assert!(p.footer.bottom() <= m.h, "{w}x{h}: the footer runs off the panel");

            if m.landscape() {
                assert!(
                    identity_h(&m) <= p.identity.h,
                    "{w}x{h}: the identity column does not fit ({} needed, {} available)",
                    identity_h(&m),
                    p.identity.h
                );
                let status = p.status.expect("the landscape arrangement has a status column");
                assert!(
                    status_h(&m) <= status.h,
                    "{w}x{h}: the status block does not fit ({} needed, {} available)",
                    status_h(&m),
                    status.h
                );
            } else {
                assert!(p.status.is_none(), "{w}x{h}: portrait must not split the body");
                // One column: identity and status stack in the same rectangle.
                let needed = identity_h(&m) + m.gap + status_h(&m);
                assert!(
                    needed <= p.identity.h,
                    "{w}x{h}: the portrait column does not fit ({needed} needed, {} available)",
                    p.identity.h
                );
            }
        }
    }

    /// The card's height is measured from the copy, so it is right on a panel where the
    /// body wraps to two lines and on one where the same string wraps to three.
    #[test]
    fn the_card_is_as_tall_as_its_copy() {
        for (w, h) in GEOMETRIES {
            let m = Metrics::new(w, h);
            let p = place(&m);
            let lines = wrap_words(CARD_BODY, p.card.w - 2 * m.gap, BODY).len() as i32;
            assert_eq!(
                p.card.h,
                2 * m.gap + LINE + (lines - 1) * SMALL_LINE + BODY.line_height as i32,
                "{w}x{h}: the card is not the height of the copy it holds"
            );
            // The clip must not cut the last line: this is the assertion the render
            // failed before the last line was measured at its full height.
            assert!(
                LINE + (lines - 1) * SMALL_LINE + BODY.line_height as i32
                    <= p.card.inset(m.gap).h,
                "{w}x{h}: the card clips its own closing line"
            );
            assert!(lines >= 1, "{w}x{h}: the card body wrapped to nothing");
            assert!(p.card.h >= TOUCH_MIN, "{w}x{h}: the card is below the touch floor");
            assert!(p.card.w >= TOUCH_MIN, "{w}x{h}: the card is below the touch floor");
        }
    }

    /// The wake area excludes the card, at both geometries.
    ///
    /// Not a taste question: the region test in this crate forbids any overlap between
    /// returned rectangles, so a wake rectangle that merely LOSES to the card on hit
    /// order would fail CI. It would also be a real bug - a finger landing on the card
    /// must not be one pixel of layout drift away from opening the PIN pad.
    #[test]
    fn the_wake_area_has_a_hole_where_the_card_is() {
        for (w, h) in GEOMETRIES {
            let m = Metrics::new(w, h);
            let p = place(&m);
            let wake: alloc::vec::Vec<Rect> = p.wake_rects().collect();
            assert_eq!(
                wake.len(),
                if m.landscape() { 2 } else { 1 },
                "{w}x{h}: unexpected number of wake rectangles"
            );
            for r in &wake {
                assert!(!r.overlaps(&p.card), "{w}x{h}: the wake area covers the card");
                assert!(r.y >= m.bar, "{w}x{h}: the wake area covers the top bar");
                assert!(r.w >= TOUCH_MIN && r.h >= TOUCH_MIN, "{w}x{h}: wake rect too small");
                assert!(
                    r.x >= 0 && r.right() <= m.w && r.bottom() <= m.h,
                    "{w}x{h}: wake rect off the panel"
                );
            }
            if let [a, b] = wake[..] {
                assert!(!a.overlaps(&b), "{w}x{h}: the two wake rectangles overlap");
            }
        }
    }

    /// The device name stays tappable on the landscape panel.
    ///
    /// The reason the second wake rectangle exists. A user who reads the identity block and
    /// then touches it to start typing must not find that half of the screen inert. It was
    /// written about the lock word, which is gone; the row it protects is now the name, and
    /// the name is the row a finger goes for on that panel for the same reason.
    #[test]
    fn the_device_name_wakes_the_device() {
        let m = Metrics::new(800, 480);
        let p = place(&m);
        // Where `lock.rs` puts the name: directly under the title, in the identity column.
        let name_y = p.identity.y + TITLE.line_height as i32 + m.gap + LINE / 2;
        let name_x = p.identity.x + p.identity.w / 2;
        assert!(
            p.wake_rects().any(|r| r.contains(name_x, name_y)),
            "the device name sits in a dead zone on the landscape panel"
        );
        // NOT asserted here: that every accepted device name fits this column. The name
        // limit is measured against the narrowest BODY any panel has
        // (`screens/devicename.rs`), and the door's landscape identity column is half of
        // one - so a legal name can be wider than it. That is a real constraint on wiring
        // the door up, recorded here rather than papered over with a weaker assertion:
        // whoever lands `place` in `lock.rs` owes either a narrower name limit or a
        // column measured to the limit that exists.
    }



    /// The copy is what SIMPLE-MODE.md 5.2 specified, and carries no banned word.
    ///
    /// The banned list is the failure mode this feature invites: the moment a string
    /// calls one path "simple", the other becomes the real one.
    #[test]
    fn the_copy_says_only_what_it_may() {
        const BANNED: [&str; 9] = [
            "simple", "beginner", "basic", "advanced", "easy", "expert mode", "full mode",
            "wallet mode", "dice mode",
        ];
        for s in [CARD_HEADING, CARD_BODY, UNLOCK_HINT] {
            assert!(s.is_ascii(), "non-ASCII in on-screen copy: {s}");
            let lower = s.to_lowercase();
            for banned in BANNED {
                assert!(!lower.contains(banned), "banned word {banned:?} in {s:?}");
            }
        }
        assert_eq!(CARD_HEADING, "New seed (dice)");
        assert_eq!(CARD_BODY, "No PIN. Nothing is written. Your stored wallets stay locked.");
        assert_eq!(UNLOCK_HINT, "Touch to unlock");
    }

    /// The door pushes S-12 and asks the embedder for nothing.
    ///
    /// The request half is the load-bearing assertion: the door path must not open the
    /// store, and a `None` here is that rule checked rather than described.
    #[test]
    fn the_door_pushes_the_dice_screen_and_asks_for_nothing() {
        let o = open();
        assert!(o.request.is_none(), "the door asked the embedder for something");
        match o.nav {
            crate::screens::Nav::Push(State::Dice(_)) => {}
            _ => panic!("the door must PUSH the dice screen, so S-03 is still behind it"),
        }
    }
}
