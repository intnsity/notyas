// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! S-19 Keep or save: the fork that keeps statelessness first-class (commandment 6).
//!
//! This is the product's central choice and the screen is built so that it reads as one.
//! The two cards are EQUAL - same width, same height, same fill, same ink, same border,
//! neither drawn as the primary and neither as an escape hatch from the other - and the
//! layout computes them from one rectangle so they cannot drift apart. A device that
//! nudged here would be teaching that storing is the normal thing and keeping nothing is
//! the exception, which is the opposite of what this device is.
//!
//! It is also placement (ii) of the three the ratified Q22 requires: the post-check backup
//! screen states, in plain words, that the passphrase is not stored. It appears here
//! exactly when the wallet has one, which is when the fact can cost the user their coins.

use alloc::string::String;
use alloc::vec::Vec;

use embedded_graphics::draw_target::{DrawTarget, DrawTargetExt};
use embedded_graphics::pixelcolor::Rgb565;

use crate::canvas::{fill, frame, text, wrap_words, BODY, HEADING};
use crate::components::{back_rect, draw_bar, LINE, SMALL_LINE};
use crate::layout::{Rect, LIST_ROW_MIN};
use crate::screens::name::NameState;
use crate::screens::setpin::SetPinState;
use crate::screens::wallet::WalletState;
use crate::screens::{Ctx, Env, Nav, Outcome, Screen, State};
use crate::theme::*;
use crate::{
    BackupState, PassphraseState, Region, RegionId, WalletInfo, WalletKind,
    PASSPHRASE_NOT_STORED,
};
use notyas_core::report::Report;
use zeroize::Zeroizing;

pub(crate) struct ForkState {
    /// The finished wallet. `Option` because the stateless leg MOVES it into the wallet
    /// home out of a `&mut self`; the storing leg leaves it here, because Back from the
    /// naming screen has to find this screen intact.
    pub report: Option<Report>,
    /// How the backup behind this wallet was proved: the quiz on the create path, the
    /// word entry itself on the restore path.
    backup: BackupState,
    /// The PUBLIC facts this screen shows or is shaped by, copied once at construction.
    /// Kept here rather than read back through the report because the geometry depends on
    /// one of them - the Q22 block is on the screen exactly when there is a passphrase -
    /// and a layout that can only be computed with a live derivation in hand is a layout
    /// that cannot be tested.
    ///
    /// The word count and the network are deliberately NOT among them: this screen is a
    /// save-or-discard decision and neither changes it, the bar carries the fingerprint
    /// that does, and the wallet home one tap later states both in full. What the body
    /// buys with the line they would have taken is two cards that fit their own titles at
    /// 800x480.
    fingerprint: String,
    /// The passphrase this wallet was derived with, empty where none was applied.
    ///
    /// Two things read it and neither renders it: the layout, which puts the Q22 block on
    /// the screen exactly when there is a passphrase, and the naming screen this one hands
    /// it to. `Zeroizing`, and named in the parent module's drop-equals-zeroize check.
    pub(super) passphrase: Zeroizing<String>,
}

impl ForkState {
    pub fn new(
        report: Report,
        backup: BackupState,
        passphrase: Zeroizing<String>,
    ) -> ForkState {
        // The two must agree: `has_passphrase` is the report's own record of whether the
        // pipeline was given one, and this screen decides what to warn about from the
        // value it is holding. A disagreement means a caller lost the passphrase between
        // the derivation and here, and the wallet would be saved with a flag that does not
        // describe it.
        debug_assert_eq!(
            report.has_passphrase,
            !passphrase.is_empty(),
            "the carried passphrase and the derivation must describe the same wallet"
        );
        ForkState {
            backup,
            fingerprint: report.root_fingerprint.clone(),
            passphrase,
            report: Some(report),
        }
    }

    /// Whether a passphrase is part of this wallet. The layout's question, and the only
    /// thing this screen asks of the value it carries.
    fn has_passphrase(&self) -> bool {
        !self.passphrase.is_empty()
    }

    /// The bar title. The fingerprint rides it rather than the body, exactly as S-19's
    /// reflow note asks: it is how a user notices a passphrase typo (commandment 8), so it
    /// must be legible on both panels, and the body below has to hold two equal cards and
    /// a warning before it has room for anything else.
    fn title(&self) -> String {
        format!("Backup checked - {}", self.fingerprint)
    }

    /// Where the storing leg goes once the device is able to store: the naming screen, built
    /// from the report this screen is holding.
    ///
    /// ONE definition of "forward from Save", called by the tap and by [`Ui::pin_created`]
    /// after the PIN step. The alternative was for the `Ui` to know how to rebuild this
    /// screen's next state, which would have put the fork's knowledge in two places and let
    /// the post-PIN route drift from the direct one.
    ///
    /// `None` only where the report has already been moved out down the stateless leg, which
    /// is a screen that can no longer offer either choice.
    pub fn save_target(&self) -> Option<State> {
        self.report
            .as_ref()
            .map(|r| State::Name(NameState::new(r, &self.passphrase)))
    }
}

/// The two cards' copy: a title and one mechanism line each. Stated once and at the same
/// length, so the two halves of the choice are written in the same voice - a card with
/// three lines against a card with one is a nudge whatever the pixels do.
///
/// Terse because the cards must be EQUAL and must both fit beside the Q22 warning on the
/// 800x480 panel, where each card is half a body wide. What the terse line leaves out -
/// that a session wallet is gone at the next power-off until the words are retyped - is
/// said in full one screen later, on the wallet home band, which is the screen where it
/// starts being true.
const SAVE_CARD: [&str; 2] =
    ["Save to this device", "Stored encrypted. The PIN is the key."];
/// The same choice on a device that has no PIN yet, where the tap sets one first (S-06/S-07).
///
/// A separate line rather than one that covers both cases: this screen is a decision, and a
/// card that did not say a two-step PIN flow was behind it would be springing the flow on a
/// user who thought they had tapped the last button. Same length as the line it replaces, so
/// the two cards stay the pair they are drawn as.
const SAVE_CARD_NEW_PIN: [&str; 2] =
    ["Save to this device", "Sets a PIN first. The PIN is the key."];
const ONCE_CARD: [&str; 2] =
    ["Use once, keep nothing", "Nothing is written to this device."];

/// The sentence that is true down both legs, and the reason neither is a trap.
const EITHER_WAY: &str = "Either way, your dice rolls or seed words are the backup.";

/// Tallest a card may grow on a panel with room to spare. A card is a choice, not a
/// billboard: past this the two cards stop reading as a pair of options and start reading
/// as two pages.
const CARD_MAX_H: i32 = 220;

/// The height a card `card_w` px wide needs to show its copy IN FULL: the title line, the
/// lines its mechanism sentence wraps to at that width, and the card's own padding.
///
/// Measured rather than assumed, and measured over EVERY copy either card can carry - both
/// forms of the save card and the use-once card - with the tallest requirement winning. The
/// two cards are the same size by construction, so sizing to the shorter copy would crop the
/// other one, which is the same nudge as drawing them unequal; measuring over both save
/// variants additionally keeps the height independent of the store status, so the fork does
/// not reflow between a device that has a PIN and one that has not. This is the
/// floor the layout gives a card, and the same function the layout test measures against,
/// so the screen and its gate can never be reading different arithmetic.
fn card_copy_h(card_w: i32, gap: i32) -> i32 {
    let inner = card_w - 2 * gap;
    let text: i32 = [&SAVE_CARD, &SAVE_CARD_NEW_PIN, &ONCE_CARD]
        .into_iter()
        .map(|copy| LINE + wrap_words(copy[1], inner, BODY).len() as i32 * SMALL_LINE)
        .max()
        .unwrap_or(LINE);
    text + 2 * gap
}

pub(crate) struct Layout {
    save: Rect,
    once: Rect,
    /// The Q22 block, present exactly when the wallet has a passphrase.
    warning: Option<Rect>,
    footer: Option<Rect>,
}

impl Screen for ForkState {
    type Layout = Layout;

    /// Cards stacked on the tall panel, side by side on the short one (S-19's reflow),
    /// and equal in both. The warning and the footer take their height from the copy;
    /// whatever is left is split evenly between the two cards, which is what makes
    /// "equally weighted" a property of the arithmetic rather than of the wording.
    fn layout(&self, ctx: &Ctx) -> Layout {
        let m = &ctx.m;
        let body = m.body();
        let g = m.gap;

        let footer_h = wrap_words(EITHER_WAY, body.w, BODY).len() as i32 * LINE;
        let footer = Rect::new(body.x, body.bottom() - footer_h, body.w, footer_h);

        // The Q22 block and the "either way" footer are alternatives, not neighbours.
        // On a passphrase wallet the footer would be the WEAKER of two claims about the
        // same thing - the seed words are the backup, except that here they are not
        // enough - so the accurate one takes the space rather than sitting under it.
        let (warning, footer) = if self.has_passphrase() {
            let lines: i32 = PASSPHRASE_NOT_STORED
                .iter()
                .map(|p| wrap_words(p, body.w, BODY).len() as i32)
                .sum();
            let h = lines * LINE;
            (Some(Rect::new(body.x, body.bottom() - h, body.w, h)), None)
        } else {
            (None, Some(footer))
        };

        let top = body.y;
        let bottom = warning.or(footer).map_or(body.bottom(), |r| r.y) - g;
        // Stacked and full width on BOTH panels, and equal by construction. Side by side
        // is what the S-19 reflow note suggests for the shorter panel, and it does not
        // survive contact with the copy: half of 736 px does not hold "Use once, keep
        // nothing" at heading size, and a choice with one of its two names cropped is not
        // the equally-weighted fork this screen exists to be. Full width costs the
        // identity line instead, which the bar and the next screen both carry.
        //
        // What the copy needs comes FIRST and the leftover second. The cards split whatever
        // the block below leaves them, but never fall below their own words: the touch
        // floor alone would not catch that, because a card's sentence needs more pixels
        // than a finger does, and a card cropped to fit is one half of this screen's choice
        // with its reasoning missing. `min` then `max` rather than `clamp` so the copy also
        // outranks the cosmetic ceiling instead of panicking against it.
        let needed = card_copy_h(body.w, g).max(LIST_ROW_MIN);
        let card_h = ((bottom - top - g) / 2).min(CARD_MAX_H).max(needed);
        let save = Rect::new(body.x, top, body.w, card_h);
        let once = Rect::new(body.x, top + card_h + g, body.w, card_h);
        Layout { save, once, warning, footer }
    }

    fn regions(&self, ctx: &Ctx, out: &mut Vec<Region>) {
        let l = self.layout(ctx);
        out.push(Region { id: RegionId::Back, rect: back_rect(&ctx.m) });
        out.push(Region { id: RegionId::SaveToDevice, rect: l.save });
        out.push(Region { id: RegionId::UseOnce, rect: l.once });
    }

    fn draw<D: DrawTarget<Color = Rgb565>>(&self, t: &mut D, ctx: &Ctx) -> Result<(), D::Error> {
        let m = &ctx.m;
        draw_bar(t, m, &self.title())?;
        let l = self.layout(ctx);

        // The two halves of the choice, drawn by one function so a difference between them
        // would have to be written deliberately.
        let save_copy =
            if ctx.lock.status.has_pin() { &SAVE_CARD } else { &SAVE_CARD_NEW_PIN };
        card(t, l.save, save_copy, m.gap)?;
        card(t, l.once, &ONCE_CARD, m.gap)?;

        // Q22 placement (ii). Warning ink, because this is the fact that decides whether a
        // seed backup is enough to recover the wallet being saved.
        if let Some(r) = l.warning {
            let mut y = r.y;
            for para in PASSPHRASE_NOT_STORED {
                for line in wrap_words(para, r.w, BODY) {
                    text(t, &line, r.x, y, BODY, WARNING, PAPER_1)?;
                    y += LINE;
                }
            }
        }

        if let Some(r) = l.footer {
            let mut y = r.y;
            for line in wrap_words(EITHER_WAY, r.w, BODY) {
                text(t, &line, r.x, y, BODY, INK_SECONDARY, PAPER_1)?;
                y += LINE;
            }
        }
        Ok(())
    }

    fn activate(&mut self, id: RegionId, env: &mut Env) -> Outcome {
        match id {
            // A device with no PIN has nothing to seal WITH - the sealing key IS the PIN -
            // so the first save is where one is set. PIN-MODES.md puts the moment here in as
            // many words: "The PIN is introduced at the moment the user first chooses to
            // save a wallet, not at first boot." Until 0.2.0 this arm went straight on and
            // the device had no route to a PIN at all outside the test console, which a
            // product build compiles out.
            //
            // The report stays here across the PIN step, exactly as it stays across naming:
            // the create screen is pushed, so Back from it finds this screen still able to
            // offer both legs, and a PIN that was set on the way through does not consume
            // the wallet that occasioned it.
            RegionId::SaveToDevice if !env.lock.status.has_pin() && self.report.is_some() => {
                Outcome::push(State::SetPin(SetPinState::new()))
            }
            // The storing leg keeps the report here: naming is a step the user can back
            // out of, and Back has to find this screen able to offer both legs again.
            RegionId::SaveToDevice => match self.save_target() {
                Some(next) => Outcome::push(next),
                None => Outcome::stay(),
            },
            // The stateless leg moves it: nothing is written, the session wallet IS this
            // derivation, and leaving this screen must not leave a second copy behind.
            RegionId::UseOnce => match self.report.take() {
                Some(report) => {
                    let info = WalletInfo {
                        slot: 0,
                        name: String::from("Session wallet"),
                        fingerprint: report.root_fingerprint.clone(),
                        path: String::from("m"),
                        script_type: String::from("every scheme"),
                        kind: WalletKind::SingleSig,
                        backup: self.backup.clone(),
                        network: *env.network,
                        registrations: 0,
                        stored: false,
                        // A session wallet is never `Stored`: nothing is written, so
                        // there is nothing for a device to remember it in.
                        passphrase: if report.has_passphrase {
                            PassphraseState::Required
                        } else {
                            PassphraseState::None
                        },
                    };
                    Outcome::enter(State::Wallet(WalletState::new(info, Some(report))))
                }
                None => Outcome::stay(),
            },
            _ => Outcome::stay(),
        }
    }

    /// The derived keys are still in memory: Back asks first, so an accidental tap cannot
    /// silently discard a wallet the user has just proved they can restore.
    fn back(&self) -> Nav {
        Nav::ConfirmExit
    }
}

/// One half of the choice. Both cards are drawn through this, at the rectangle the layout
/// computed, with no parameter that could make one of them louder than the other.
fn card<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    r: Rect,
    copy: &[&str; 2],
    gap: i32,
) -> Result<(), D::Error> {
    fill(t, r, PAPER_2)?;
    frame(t, r, BORDER_STRONG)?;
    let inner = r.inset(gap);
    let mut clip = t.clipped(&inner.to_eg());
    let mut y = inner.y;
    text(&mut clip, copy[0], inner.x, y, HEADING, INK_PRIMARY, PAPER_2)?;
    y += LINE;
    for para in &copy[1..] {
        for line in wrap_words(para, inner.w, BODY) {
            text(&mut clip, &line, inner.x, y, BODY, INK_SECONDARY, PAPER_2)?;
            y += SMALL_LINE;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::TOUCH_MIN;
    use crate::screens::testing::{Fixture, GEOMETRIES};

    fn state(passphrase: bool) -> ForkState {
        ForkState {
            report: None,
            backup: BackupState::Verified(String::new()),
            fingerprint: String::from("a1b2c3d4"),
            passphrase: Zeroizing::new(String::from(if passphrase { "x" } else { "" })),
        }
    }

    /// The two halves of the choice are the same size, on both panels, whether or not the
    /// Q22 block is on the screen. This is the acceptance criterion made mechanical: a
    /// later edit that grew one card would fail here rather than ship a nudge.
    #[test]
    fn the_two_cards_are_the_same_size() {
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            for passphrase in [false, true] {
                let l = state(passphrase).layout(&f.ctx());
                assert_eq!(
                    (l.save.w, l.save.h),
                    (l.once.w, l.once.h),
                    "{w}x{h} passphrase={passphrase}: the cards differ in size"
                );
                assert!(l.save.h >= TOUCH_MIN, "{w}x{h}: cards below the touch floor");
                assert!(!l.save.overlaps(&l.once), "{w}x{h}: the cards overlap");
                let body = f.m.body();
                for r in [Some(l.save), Some(l.once), l.footer, l.warning].into_iter().flatten() {
                    assert!(
                        r.x >= body.x && r.right() <= body.right() && r.bottom() <= body.bottom(),
                        "{w}x{h}: {r:?} escapes the body"
                    );
                }
                // The copy must FIT the card it is written on. Both cards are the same
                // size, so both are measured against the taller requirement: a card whose
                // last line is cut off is one half of the product's central choice with
                // its reasoning missing.
                let needed = card_copy_h(l.save.w, f.m.gap);
                assert!(
                    needed <= l.save.h,
                    "{w}x{h} passphrase={passphrase}: a card needs {needed} px and has {}",
                    l.save.h
                );
                // ... and the cards must clear whatever is under them. The block below is
                // placed against the body's BOTTOM while the cards are placed against its
                // top, so nothing in the arithmetic stops them meeting in the middle when
                // the copy on either side grows. Two overlapping paragraphs is the same
                // defect as a cropped card arriving from the other direction, and until
                // this line nothing in the suite could see it.
                if let Some(below) = l.warning.or(l.footer) {
                    let (end, start) = (l.once.bottom(), below.y);
                    assert!(
                        end <= start,
                        "{w}x{h} passphrase={passphrase}: the cards end at {end} and the \
                         block below them starts at {start}"
                    );
                }
            }
        }
    }
}
