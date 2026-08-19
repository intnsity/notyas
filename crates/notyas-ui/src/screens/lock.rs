// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! S-03 Lock (UX 16): the device says which device it is, before the user gives it a PIN.
//!
//! Reachable only with a PIN set (`Ui::lock` refuses otherwise), which is what keeps R20
//! true here: the device-word panel cannot appear on a device whose words do not exist,
//! because they are derived from a key that has not been burned.

use alloc::string::String;
use alloc::vec::Vec;

use embedded_graphics::draw_target::DrawTarget;
use embedded_graphics::pixelcolor::Rgb565;

use crate::canvas::{
    button, fill, panel, text_centered, wrap_words, ButtonKind, BODY, HEADING, MONO, TITLE,
};
use crate::components::LINE;
use crate::layout::{Metrics, Rect};
use crate::screens::pin::PinState;
use crate::screens::verify::VerifyState;
use crate::screens::{Ctx, Env, Nav, Outcome, Screen, State};
use crate::theme::*;
use crate::{LockInfo, Region, RegionId, StoreStatus, VERSION};

/// The lock screen holds nothing: everything it shows is device state the embedder
/// installed, and a locked device has no session to remember.
pub(crate) struct LockState;

/// The device-identity panel's internal padding. Its HEIGHT is measured from whatever it
/// is holding (see [`word_panel`]) rather than fixed at two rows: the panel shows a
/// caption and a word when one is set and a wrapped sentence when one is not, and a
/// constant is right for exactly one of those two - it cut the other off at the border.
const PANEL_PAD: i32 = 12;

/// Narrowest the word panel may get. It is the element this screen exists to make
/// readable across a room, so it keeps its floor even where that costs the column beside
/// it some width.
const PANEL_MIN_W: i32 = 320;

/// The copy this screen owns, named rather than written inline because the LAYOUT MEASURES
/// it: the identity column is sized to the touch hint, and the tests assert every line fits
/// the rectangle it is centred in. A copy edit therefore moves the geometry with it instead
/// of quietly overrunning it.
const LOCKED: &str = "Locked";
const TOUCH_HINT: &str = "Touch anywhere to unlock";
const NO_WORD: &str = "no word set - set one in Settings so you can tell this device from a fake.";

/// Every rectangle this screen draws into, tappable or not.
///
/// The text rows are here for the same reason the two regions are: this screen is a column
/// of MEASURED text over a fixed footer, and until 0.2.0 it was placed by running a pen
/// down the screen and hoping - which on the 800x480 panel put the touch hint 42 px on top
/// of the row below it, invisibly, because nothing but a region was ever checked for
/// overlap. A rectangle a test can see is the whole point.
pub(crate) struct Layout {
    /// Everything below the bar. "Touch anywhere to unlock" means anywhere that is not
    /// the one other affordance on the screen: overlapping the two would make the Verify
    /// chip unreachable, since hit testing takes the first region that contains the
    /// point.
    wake: Rect,
    verify_chip: Rect,
    /// The product name, the nickname under it, and the device-word panel: what the user
    /// reads to decide this is their device before typing anything into it.
    title: Rect,
    nickname: Rect,
    panel: Rect,
    /// The state and what to do about it.
    locked: Rect,
    hint: Rect,
    /// The one footer row: the build, and the storage word Q2(a) permits. Nothing here
    /// states capacity or contents - see [`Screen::draw`].
    version: Rect,
}

/// The word panel's (width, height) inside a column `avail` px wide.
///
/// Both are measured. The width is three fifths of the display, never under
/// [`PANEL_MIN_W`] and never wider than the column it sits in; the height is the rows its
/// CONTENT actually takes at that width - two for a word that is set, and however many the
/// edge-state sentence wraps to for one that is not, which at every shipped panel width is
/// more than two.
fn word_panel(m: &Metrics, lock: &LockInfo, avail: i32) -> (i32, i32) {
    let w = (m.w * 3 / 5).max(PANEL_MIN_W).min(avail);
    let rows = if lock.lock_word.is_empty() {
        wrap_words(NO_WORD, w - 2 * PANEL_PAD, BODY).len() as i32
    } else {
        // The caption and the word itself.
        2
    };
    (w, rows * LINE + 2 * PANEL_PAD)
}

impl Screen for LockState {
    type Layout = Layout;

    /// One column on a panel with the height for it, two beside each other on one without.
    ///
    /// The arrangement is chosen by whether the stack FITS, not by which board is plugged
    /// in: the copy, the fonts and the footer decide how much room the identity needs, and
    /// a predicate over the panel's aspect ratio would only be a guess at the same
    /// question. The 720x720 panel takes the first branch and is laid out to the pixel as
    /// it was in 0.1.0; the 800x480 panel takes the second, where before it ran the touch
    /// hint straight through the footer.
    fn layout(&self, ctx: &Ctx) -> Layout {
        let m = &ctx.m;
        let g = m.gap;
        let body = m.body();

        let wake = Rect::new(0, m.bar, m.w, m.h - m.bar);
        let cw = (m.w / 3).clamp(200, 260);
        let verify_chip = Rect::new(m.w - g - cw, g / 2, cw, m.bar - g);

        // The footer is placed first, against the bottom padding, in both arrangements: it
        // is the last thing read and the one row on this screen whose position does not
        // depend on how tall anything above it turned out to be.
        let version = Rect::new(0, m.h - m.pad - LINE, m.w, LINE);
        // What is left for the identity, and a hard boundary rather than a starting point.
        let room = Rect::new(body.x, body.y, body.w, version.y - g - body.y);

        let title_h = TITLE.line_height as i32;
        let (pw, ph) = word_panel(m, ctx.lock, room.w);
        // Title, nickname, panel, "Locked", the hint, and the four gaps between them.
        let stacked_h = title_h + LINE + ph + 2 * LINE + 4 * g;

        if stacked_h <= room.h {
            // The leading is the panel's own proportion of itself, but never more room
            // than is actually spare: this branch was taken BECAUSE the stack fits, so its
            // whitespace must not be the thing that pushes it back out.
            let mut y = room.y + (body.h / 8).min(room.h - stacked_h);
            // Centred across the whole display, not across the body: these lines are the
            // device's identity and they read as centred on the panel itself.
            let row = |y: i32, h: i32| Rect::new(0, y, m.w, h);
            let title = row(y, title_h);
            y += title_h + g;
            let nickname = row(y, LINE);
            y += LINE + g;
            let panel = Rect::new((m.w - pw) / 2, y, pw, ph);
            y = panel.bottom() + g;
            let locked = row(y, LINE);
            y += LINE + g;
            let hint = row(y, LINE);
            Layout { wake, verify_chip, title, nickname, panel, locked, hint, version }
        } else {
            // Not enough height for one column, so the panel moves BESIDE the identity
            // rather than any of it being compressed or dropped. Nothing here is optional:
            // the word is what proves the device, and the hint is the only instruction on
            // the screen.
            //
            // The identity column is sized to the touch hint, the widest fixed line it
            // carries, and the word panel takes what is left down to its own floor. Sized
            // to the text rather than to half the room because half of the 800x480 body is
            // 12 px short of that sentence, and a cropped instruction on a screen whose
            // whole job is "here is how to get in" is the worst line on it to lose. The
            // nickname is deliberately not measured: it is user data of any length, no
            // column can promise to hold it, and it is centred rather than load-bearing.
            let ident_w = BODY.text_width(TOUCH_HINT) as i32;
            let (pw, ph) = word_panel(m, ctx.lock, (room.w - g - ident_w).max(PANEL_MIN_W));
            let col = room.w - g - pw;
            let ident_h = title_h + 3 * LINE + 3 * g;
            let mut y = room.y + (room.h - ident_h).max(0) / 2;
            let left = |y: i32, h: i32| Rect::new(room.x, y, col, h);
            let title = left(y, title_h);
            y += title_h + g;
            let nickname = left(y, LINE);
            y += LINE + g;
            let locked = left(y, LINE);
            y += LINE + g;
            let hint = left(y, LINE);
            let panel =
                Rect::new(room.right() - pw, room.y + (room.h - ph).max(0) / 2, pw, ph);
            Layout { wake, verify_chip, title, nickname, panel, locked, hint, version }
        }
    }

    fn regions(&self, ctx: &Ctx, out: &mut Vec<Region>) {
        let l = self.layout(ctx);
        // The chip first: the wake area covers it, and the first region containing the
        // point wins.
        out.push(Region { id: RegionId::HomeVerifyDevice, rect: l.verify_chip });
        out.push(Region { id: RegionId::LockWake, rect: l.wake });
    }

    fn draw<D: DrawTarget<Color = Rgb565>>(&self, t: &mut D, ctx: &Ctx) -> Result<(), D::Error> {
        let m = &ctx.m;
        let lock = ctx.lock;
        let l = self.layout(ctx);
        fill(t, Rect::new(0, 0, m.w, m.bar), PAPER_2)?;
        fill(t, Rect::new(0, m.bar - 1, m.w, 1), BORDER)?;
        // Pre-PIN and deliberate (commandment 4): a user who suspects a swapped device
        // must be able to check the firmware hash without typing a digit into it.
        button(t, l.verify_chip, "Verify device", ButtonKind::Ghost, PAPER_2)?;

        text_centered(t, "notyas", l.title, TITLE, INK_PRIMARY, PAPER_1)?;

        // The nickname is a user-chosen label, shown in quotes so it reads as a name
        // rather than as a device claim about itself.
        let nickname = if lock.nickname.is_empty() {
            String::from("no name set")
        } else {
            format!("\"{}\"", lock.nickname)
        };
        text_centered(t, &nickname, l.nickname, MONO, INK_SECONDARY, PAPER_1)?;

        // The word panel keeps its width on the shorter panel: it is the
        // security-relevant element, and it is the thing the user is meant to read before
        // typing. What gives instead is the arrangement around it.
        panel(t, l.panel, PAPER_3, BORDER_STRONG)?;
        if lock.lock_word.is_empty() {
            // The edge state says what to do and does not pretend a word exists. It is
            // taller than the two-row form, which is why the panel is measured.
            let inner = l.panel.inset(PANEL_PAD);
            let mut ly = inner.y;
            for line in wrap_words(NO_WORD, inner.w, BODY) {
                let row = Rect::new(inner.x, ly, inner.w, LINE);
                text_centered(t, &line, row, BODY, INK_MUTED, PAPER_3)?;
                ly += LINE;
            }
        } else {
            let word = lock.lock_word.to_uppercase();
            text_centered(
                t,
                "your word",
                Rect::new(l.panel.x, l.panel.y + PANEL_PAD, l.panel.w, LINE),
                BODY,
                INK_SECONDARY,
                PAPER_3,
            )?;
            text_centered(
                t,
                &word,
                Rect::new(l.panel.x, l.panel.y + PANEL_PAD + LINE, l.panel.w, LINE),
                MONO,
                INK_PRIMARY,
                PAPER_3,
            )?;
        }

        text_centered(t, LOCKED, l.locked, HEADING, INK_PRIMARY, PAPER_1)?;
        text_centered(t, TOUCH_HINT, l.hint, BODY, INK_SECONDARY, PAPER_1)?;

        // Q2(a), and stricter than the ratified answer. Q2(a) permitted the static
        // maximum here and forbade only the count in use; the owner has since ruled that
        // no pre-PIN surface volunteers capacity or contents at all, so the
        // "holds up to N wallets" row is gone (2026-08-19). That STRENGTHENS the property
        // Q2(a) exists for rather than reopening it: the row it removes was the one a
        // coercer could read off a locked device, and saying nothing is strictly less than
        // saying a maximum. What remains is the occupancy WORD - `present` or `blank`,
        // permanently and for all users - which the design still requires so an owner can
        // tell a formatted device from a blank one without unlocking it, and which is a
        // binary state rather than a number.
        text_centered(t, &footer_line(lock.status), l.version, BODY, INK_MUTED, PAPER_1)?;
        Ok(())
    }

    fn activate(&mut self, id: RegionId, _env: &mut Env) -> Outcome {
        match id {
            // Touch anywhere wakes into PIN entry, which needs nothing from the std side
            // to draw itself: the pad is fixed (Q35, reversed 2026-08-19) and the
            // anti-phishing words are asked for only when the user asks for them.
            // Entered rather than pushed: the lock screen is the floor of a locked
            // device, and PIN entry returns to it through Back, not through the stack.
            RegionId::LockWake => Outcome::enter(State::Pin(PinState::new())),
            // Verify device is reachable BEFORE the PIN, deliberately: a user who
            // suspects a swapped device must be able to check the firmware hash without
            // typing a digit into it (UX-SCREENS.md S-03). Pushed, so Back returns here.
            RegionId::HomeVerifyDevice => Outcome::push(State::Verify(VerifyState::new())),
            _ => Outcome::stay(),
        }
    }

    /// There is nothing behind the lock screen: it is the floor of a locked device.
    fn back(&self) -> Nav {
        Nav::Stay
    }
}

/// The whole of the pre-PIN footer, as one named string.
///
/// Named so the copy test below reads exactly what `draw` paints rather than a
/// reconstruction of it. This line is the ONLY thing the lock screen says about storage,
/// and it says it as a binary state.
fn footer_line(status: StoreStatus) -> String {
    format!("version {VERSION} - {}", storage_word(status))
}

/// Storage occupancy at the only granularity any pre-PIN surface may state (Q2(a)).
fn storage_word(status: StoreStatus) -> &'static str {
    match status {
        StoreStatus::NotProvisioned => "internal store not set up",
        StoreStatus::Blank => "internal store blank",
        StoreStatus::Locked | StoreStatus::Unlocked => "internal store present",
        StoreStatus::Unreadable => "internal store unreadable",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canvas::BODY;
    use crate::screens::testing::{rows_are_clear, Fixture, GEOMETRIES};

    /// The screen, laid out at `w` x `h` with `word` as the lock word.
    fn laid_out(w: u32, h: u32, word: &str) -> (Fixture, Layout) {
        let mut f = Fixture::new(w, h);
        // The lock screen only exists on a device with a PIN (R20), so that is the only
        // state worth laying it out in.
        f.lock.status = StoreStatus::Locked;
        f.lock.nickname = String::from("kitchen drawer");
        f.lock.lock_word = String::from(word);
        let l = LockState.layout(&f.ctx());
        (f, l)
    }

    /// No two rows of S-03 land on each other, on either panel, with and without a word.
    ///
    /// This is the check this suite did not have. Every rectangle on this screen but two is
    /// MEASURED TEXT, the region tests only inspect regions, and so at 800x480 the unlock
    /// hint was drawn 42 px on top of the footer for a whole release with every test
    /// passing. The no-word edge state is here for the same reason: its panel holds a
    /// wrapped sentence, which is taller than the two rows the panel used to reserve for
    /// it - at 720x720 by exactly one line.
    #[test]
    fn no_two_rows_of_the_lock_screen_overlap() {
        for (w, h) in GEOMETRIES {
            for word in ["anvil", ""] {
                let (f, l) = laid_out(w, h, word);
                let m = &f.m;
                rows_are_clear(
                    &format!("{w}x{h} lock_word={word:?}"),
                    // Below the bar: the bar is painted over, and the Verify chip rides in
                    // it.
                    Rect::new(0, m.bar, m.w, m.h - m.bar),
                    &[
                        ("title", l.title),
                        ("nickname", l.nickname),
                        ("word panel", l.panel),
                        ("Locked", l.locked),
                        ("unlock hint", l.hint),
                        ("version", l.version),
                    ],
                );
            }
        }
    }

    /// Every fixed line fits the row it is centred in.
    ///
    /// `text_centered` will happily centre a string wider than its rectangle and lose both
    /// ends of it, so a row that is too narrow does not wrap - it crops. On the shorter
    /// panel the identity is a COLUMN, sized to the widest of these lines, which is the one
    /// arrangement where being 12 px out would cost the user the only instruction on the
    /// screen.
    #[test]
    fn every_fixed_line_fits_the_row_it_is_centred_in() {
        for (w, h) in GEOMETRIES {
            for word in ["anvil", ""] {
                let (_, l) = laid_out(w, h, word);
                for (line, need, have) in [
                    ("notyas", TITLE.text_width("notyas") as i32, l.title.w),
                    (LOCKED, HEADING.text_width(LOCKED) as i32, l.locked.w),
                    (TOUCH_HINT, BODY.text_width(TOUCH_HINT) as i32, l.hint.w),
                    ("your word", BODY.text_width("your word") as i32, l.panel.w),
                ] {
                    assert!(
                        need <= have,
                        "{w}x{h} lock_word={word:?}: {line:?} needs {need} px in a {have} px row"
                    );
                }
            }
        }
    }

    /// The word panel holds what is drawn inside it.
    ///
    /// The panel is a box of a measured height, and the sentence inside it is wrapped
    /// AGAIN by the drawing code: the two have to agree, or the line that tells a user
    /// this device cannot prove itself is the one that runs out of the bottom of the box.
    /// It did - the panel reserved two rows for a sentence that wraps to three at 720x720
    /// and to four in the shorter panel's column.
    #[test]
    fn the_word_panel_holds_what_is_drawn_in_it() {
        for (w, h) in GEOMETRIES {
            for word in ["anvil", ""] {
                let (_, l) = laid_out(w, h, word);
                // Exactly what `draw` does: inset by the padding, one LINE per row.
                let inner = l.panel.inset(PANEL_PAD);
                let rows = if word.is_empty() {
                    wrap_words(NO_WORD, inner.w, BODY).len() as i32
                } else {
                    2
                };
                assert!(
                    inner.y + rows * LINE <= l.panel.bottom(),
                    "{w}x{h} lock_word={word:?}: {rows} rows do not fit a {} px panel",
                    l.panel.h
                );
            }
        }
    }

    /// The footer line fits the panel it is centred on, at both geometries.
    ///
    /// It is the pre-PIN storage statement, and it is neither wrapped nor clipped by the
    /// code that draws it - `text_centered` will happily centre a string wider than the
    /// panel and lose both ends of it. A copy edit that overran fails here rather than
    /// shipping a storage word with its ends cut off.
    #[test]
    fn the_pre_pin_footer_line_fits_the_panel() {
        for (w, h) in GEOMETRIES {
            let m = crate::layout::Metrics::new(w, h);
            let widest = [
                StoreStatus::NotProvisioned,
                StoreStatus::Blank,
                StoreStatus::Locked,
                StoreStatus::Unreadable,
            ]
            .into_iter()
            .map(|s| format!("version {VERSION} - {}", storage_word(s)))
            .map(|line| BODY.text_width(&line) as i32)
            .max()
            .unwrap_or(0);
            assert!(
                widest <= m.content().w,
                "{w}x{h}: the widest footer line is {widest} px in a {} px body",
                m.content().w
            );
        }
    }

    /// Q2(a), tightened 2026-08-19: nothing this screen says states capacity or contents.
    ///
    /// Worded over the screen's own copy rather than over its rectangles, because the row
    /// this asserts the absence of no longer HAS a rectangle - a test that walked the
    /// layout would pass again the moment the sentence was drawn into one of the rows that
    /// remain. What it covers is every fixed string S-03 can paint; what it cannot cover is
    /// a literal a future edit writes inline, which is why the copy is named up top in the
    /// first place. The nickname is excluded because it is user data, and the user may
    /// call their device whatever they like.
    ///
    /// The last assertion is what makes this a statement about the footer's CONTENT and
    /// not about a screen that stopped saying anything: the storage word the design still
    /// requires is checked to be there.
    #[test]
    fn nothing_this_screen_says_states_capacity_or_contents() {
        let mut copy = alloc::vec![
            String::from("notyas"),
            String::from(LOCKED),
            String::from(TOUCH_HINT),
            String::from(NO_WORD),
            String::from("your word"),
            String::from("Verify device"),
        ];
        copy.extend(
            [
                StoreStatus::NotProvisioned,
                StoreStatus::Blank,
                StoreStatus::Locked,
                StoreStatus::Unlocked,
                StoreStatus::Unreadable,
            ]
            .into_iter()
            .map(footer_line),
        );
        let slots = format!("{}", crate::WALLET_SLOTS);
        for line in &copy {
            let l = line.to_lowercase();
            for banned in ["holds up to", "wallet", "slot", "capacity", slots.as_str()] {
                assert!(
                    !l.contains(banned),
                    "a pre-PIN line volunteers capacity or contents ({banned:?}): {line:?}"
                );
            }
        }
        assert!(
            copy.iter().any(|line| line.contains("internal store present")),
            "the storage word the design still requires is gone"
        );
    }
}
