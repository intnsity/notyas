// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! S-03 Lock (UX 16): the device says which device it is, before the user gives it a PIN.
//!
//! Reachable only with a PIN set (`Ui::lock` refuses otherwise).
//!
//! # One pre-PIN string, and it makes no security claim
//!
//! Until 2026-08-19 this screen showed TWO user-set strings before any authentication: a
//! nickname, and a "lock word" in a panel whose own copy told the user it let them tell
//! this device from a fake. They were the same mechanism - a string the owner chose,
//! displayed to the owner before the PIN - and only one of them claimed to be a security
//! feature. The claim did not survive inspection: anything drawn here is readable by
//! anyone who picks the device up, including whoever would build the counterfeit, so the
//! word caught a careless swap and never a targeted one. It was a bank sitekey.
//!
//! So there is one string now, it is the device NAME, and nothing on this screen says it
//! proves anything. The real anti-swap evidence on this device is elsewhere and is
//! genuinely strong: after a PIN prefix is typed, S-04 shows two words DERIVED from that
//! prefix and a device-held secret (`Store::anti_phishing_words`), which a counterfeit
//! cannot compute. Any sentence in this product about telling a real device from a fake
//! belongs to those words. The other pre-PIN affordance here, the Verify chip, is the
//! same idea one level down: it shows a measurement, not a string somebody chose.
//!
//! Do not re-add a second string. The reasoning above is the whole of why it went.

use alloc::string::String;
use alloc::vec::Vec;

use embedded_graphics::draw_target::DrawTarget;
use embedded_graphics::pixelcolor::Rgb565;

use crate::canvas::{button, fill, text_centered, ButtonKind, BODY, HEADING, MONO, TITLE};
use crate::components::LINE;
use crate::layout::Rect;
use crate::screens::pin::PinState;
use crate::screens::verify::VerifyState;
use crate::screens::{Ctx, Env, Nav, Outcome, Screen, State};
use crate::theme::*;
use crate::{Region, RegionId, StoreStatus, VERSION};

/// The lock screen holds nothing: everything it shows is device state the embedder
/// installed, and a locked device has no session to remember.
pub(crate) struct LockState;

/// The copy this screen owns, named rather than written inline because the LAYOUT MEASURES
/// it and the tests assert every line fits the rectangle it is centred in. A copy edit
/// therefore moves the geometry with it instead of quietly overrunning it.
///
/// Read these as a set before adding to them: none of them says this screen proves which
/// device you are holding, and none of them may.
const LOCKED: &str = "Locked";
const TOUCH_HINT: &str = "Touch anywhere to unlock";
/// The unnamed state. A statement of fact with no instruction attached: an unnamed device
/// is not a degraded one, and the edge state this replaces - "set one in Settings so you
/// can tell this device from a fake" - was an instruction wrapped around a false promise.
const NO_NAME: &str = "no name set";

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
    /// The product name and the device name under it: what the user reads to recognise
    /// their own device. Recognise, not verify - see the module header.
    title: Rect,
    name: Rect,
    /// The state and what to do about it.
    locked: Rect,
    hint: Rect,
    /// The one footer row: the build, and the storage word Q2(a) permits. Nothing here
    /// states capacity or contents - see [`Screen::draw`].
    version: Rect,
}

impl Screen for LockState {
    type Layout = Layout;

    /// One centred column, on every shipped panel.
    ///
    /// It was two arrangements while the lock-word panel existed: 320 px of panel plus a
    /// wrapped edge-state sentence did not fit above the footer at 800x480, so the panel
    /// moved beside the identity and the screen carried a second geometry to test. With the
    /// panel gone the column is four rows and three gaps - 221 px at 800x480, in 322 px of
    /// room - so the branch it needed goes with it. Deleting a layout because the element
    /// that forced it was deleted is the cheapest complexity this file will ever shed. The
    /// fit is still ASSERTED rather than assumed: `stacked_h` bounds the leading here, and
    /// the tests check every row on both panels.
    fn layout(&self, ctx: &Ctx) -> Layout {
        let m = &ctx.m;
        let g = m.gap;
        let body = m.body();

        let wake = Rect::new(0, m.bar, m.w, m.h - m.bar);
        let cw = (m.w / 3).clamp(200, 260);
        let verify_chip = Rect::new(m.w - g - cw, g / 2, cw, m.bar - g);

        // The footer is placed first, against the bottom padding: it is the last thing
        // read and the one row on this screen whose position does not depend on how tall
        // anything above it turned out to be.
        let version = Rect::new(0, m.h - m.pad - LINE, m.w, LINE);
        // What is left for the identity, and a hard boundary rather than a starting point.
        let room = Rect::new(body.x, body.y, body.w, version.y - g - body.y);

        let title_h = TITLE.line_height as i32;
        // Title, name, "Locked", the hint, and the three gaps between them.
        let stacked_h = title_h + 3 * LINE + 3 * g;
        // The leading is the body's own proportion of itself, but never more room than is
        // actually spare, so whitespace can never be the thing that pushes the column off
        // the bottom.
        let mut y = room.y + (body.h / 8).min((room.h - stacked_h).max(0));
        // Centred across the whole display, not across the body: these lines are the
        // device's identity and they read as centred on the panel itself.
        let row = |y: i32, h: i32| Rect::new(0, y, m.w, h);
        let title = row(y, title_h);
        y += title_h + g;
        let name = row(y, LINE);
        y += LINE + g;
        let locked = row(y, LINE);
        y += LINE + g;
        let hint = row(y, LINE);
        Layout { wake, verify_chip, title, name, locked, hint, version }
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
        // must be able to check the firmware hash without typing a digit into it. This is
        // the affordance that answers "is this my device", and it answers with a
        // measurement rather than with a string somebody chose.
        button(t, l.verify_chip, "Verify device", ButtonKind::Ghost, PAPER_2)?;

        text_centered(t, "notyas", l.title, TITLE, INK_PRIMARY, PAPER_1)?;

        // Quoted so it reads as a name the owner gave the device rather than as a claim
        // the device makes about itself, and drawn in INK_SECONDARY for the same reason:
        // it is a label, not evidence.
        //
        // Its length is bounded where it is TYPED (screens/devicename.rs), against the
        // narrowest body any shipped panel has, so this row can centre it whole. That
        // bound is the only reason it is safe to centre user data in a fixed row at all.
        let name = if lock.device_name.is_empty() {
            String::from(NO_NAME)
        } else {
            format!("\"{}\"", lock.device_name)
        };
        text_centered(t, &name, l.name, MONO, INK_SECONDARY, PAPER_1)?;

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
    use crate::screens::devicename::name_refusal;
    use crate::screens::testing::{fits, rows_are_clear_on, Fixture, GEOMETRIES};

    /// The screen, laid out at `w` x `h` with `name` as the device name.
    fn laid_out(w: u32, h: u32, name: &str) -> (Fixture, Layout) {
        let mut f = Fixture::new(w, h);
        // The lock screen only exists on a device with a PIN (R20), so that is the only
        // state worth laying it out in.
        f.lock.status = StoreStatus::Locked;
        f.lock.device_name = String::from(name);
        let l = LockState.layout(&f.ctx());
        (f, l)
    }

    /// The two states of the one pre-PIN string: named, and not.
    const NAMES: [&str; 2] = ["kitchen drawer", ""];

    /// No two rows of S-03 land on each other, on either panel, named or not.
    ///
    /// This is the check this suite did not have. Every rectangle on this screen but two is
    /// MEASURED TEXT, the region tests only inspect regions, and so at 800x480 the unlock
    /// hint was drawn 42 px on top of the footer for a whole release with every test
    /// passing.
    #[test]
    fn no_two_rows_of_the_lock_screen_overlap() {
        for (w, h) in GEOMETRIES {
            for name in NAMES {
                let (f, l) = laid_out(w, h, name);
                let m = &f.m;
                rows_are_clear_on(
                    m,
                    &format!("{w}x{h} device_name={name:?}"),
                    // Below the bar: the bar is painted over, and the Verify chip rides in
                    // it.
                    Rect::new(0, m.bar, m.w, m.h - m.bar),
                    &[
                        ("title", l.title),
                        ("device name", l.name),
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
    /// ends of it, so a row that is too narrow does not wrap - it crops, silently.
    #[test]
    fn every_fixed_line_fits_the_row_it_is_centred_in() {
        for (w, h) in GEOMETRIES {
            for name in NAMES {
                let (_, l) = laid_out(w, h, name);
                let what = format!("{w}x{h} device_name={name:?}");
                fits(&what, "notyas", TITLE.text_width("notyas") as i32, l.title);
                fits(&what, LOCKED, HEADING.text_width(LOCKED) as i32, l.locked);
                fits(&what, TOUCH_HINT, BODY.text_width(TOUCH_HINT) as i32, l.hint);
                fits(&what, NO_NAME, MONO.text_width(NO_NAME) as i32, l.name);
            }
        }
    }

    /// The longest name the device will ACCEPT still fits the row that shows it, quotes
    /// and all, on every panel this file lays out for.
    ///
    /// The two halves of that sentence live in different files - the refusal is in
    /// `screens/devicename.rs`, the row is here - and this is the joint between them. A
    /// name is the one piece of user data drawn unwrapped in a fixed row on a screen shown
    /// before authentication, so the entry screen is the only place a length can be
    /// refused, and a limit that did not match this row would crop a user's device name
    /// with no error raised anywhere.
    #[test]
    fn the_longest_accepted_name_fits_the_row_that_shows_it() {
        // Grown a character at a time and stopped at the first refusal, so the string under
        // test is exactly the boundary the entry screen enforces rather than a number
        // restated here. `W` is the widest glyph the mono face has in its ASCII range,
        // which makes this the worst case rather than an average one.
        let mut longest = String::new();
        loop {
            let mut next = longest.clone();
            next.push('W');
            if name_refusal(&next).is_some() {
                break;
            }
            longest = next;
        }
        assert!(!longest.is_empty(), "no name of any length is accepted");
        let quoted = format!("\"{longest}\"");
        for (w, h) in GEOMETRIES {
            let (_, l) = laid_out(w, h, &longest);
            fits(
                &format!("{w}x{h} longest accepted name"),
                &quoted,
                MONO.text_width(&quoted) as i32,
                l.name,
            );
        }
    }

    /// The footer line fits the panel it is centred on, at both geometries.
    ///
    /// It is the pre-PIN storage statement, and it is neither wrapped nor clipped by the
    /// code that draws it. A copy edit that overran fails here rather than shipping a
    /// storage word with its ends cut off.
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
            .map(footer_line)
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
    /// first place. The device name is excluded because it is user data, and the user may
    /// call their device whatever they like.
    ///
    /// The last assertion is what makes this a statement about the footer's CONTENT and
    /// not about a screen that stopped saying anything: the storage word the design still
    /// requires is checked to be there.
    #[test]
    fn nothing_this_screen_says_states_capacity_or_contents() {
        let slots = format!("{}", crate::WALLET_SLOTS);
        for line in &copy() {
            let l = line.to_lowercase();
            for banned in ["holds up to", "wallet", "slot", "capacity", slots.as_str()] {
                assert!(
                    !l.contains(banned),
                    "a pre-PIN line volunteers capacity or contents ({banned:?}): {line:?}"
                );
            }
        }
        assert!(
            copy().iter().any(|line| line.contains("internal store present")),
            "the storage word the design still requires is gone"
        );
    }

    /// Nothing this screen says claims the device name proves which device this is.
    ///
    /// The defect this replaces was one sentence: "no word set - set one in Settings so
    /// you can tell this device from a fake." It was drawn before any authentication, about
    /// a string anyone holding the device could read and anyone building a counterfeit
    /// could copy. The words that carry that promise honestly are S-04's derived pair, and
    /// this test is what stops the promise wandering back onto the screen that cannot keep
    /// it - including onto the Verify chip's label, which is why the chip is in the list.
    #[test]
    fn no_pre_pin_line_claims_the_name_proves_the_device() {
        for line in &copy() {
            let l = line.to_lowercase();
            for banned in ["fake", "counterfeit", "genuine", "authentic", "prove", "swap"] {
                assert!(
                    !l.contains(banned),
                    "S-03 makes an anti-swap claim it cannot keep ({banned:?}): {line:?}"
                );
            }
        }
    }

    /// Every fixed string S-03 can paint, in one place, so the two copy tests above cannot
    /// drift apart or quietly stop covering a line.
    fn copy() -> Vec<String> {
        let mut copy = alloc::vec![
            String::from("notyas"),
            String::from(LOCKED),
            String::from(TOUCH_HINT),
            String::from(NO_NAME),
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
        copy
    }
}
