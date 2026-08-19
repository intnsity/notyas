// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Passphrase entry: the explicit opt-in, the two fields, and the byte counter.
//!
//! Typed INPUT masking (one bullet per character) rather than the fixed run a derived
//! secret gets: the user already knows what they typed, the counter beside the field
//! discloses the length anyway, and a Show toggle exists because an unseen typo silently
//! derives a different wallet, which is the worse failure.
//!
//! # The Q22 warning, and why it is on the OFF state
//!
//! This screen is placement (i) AND (iii) of the ratified Q22: it is the passphrase entry
//! of the create flow and the passphrase entry of every restore flow, which are two of the
//! three placements the answer requires. The warning is drawn in the OFF state - the state
//! this screen opens in, and the one a user has to pass through to turn a passphrase on -
//! rather than beside the fields, for a reason that is measured rather than editorial:
//! with the keyboard up, the 800x480 body has seventeen pixels left after the toggle, the
//! two fields, the status row and the keyboard floor, and reflow rule 4 forbids a warning
//! that exists on one panel and not the other. Read before typing is also the better
//! order.

use alloc::string::String;
use alloc::vec::Vec;

use embedded_graphics::draw_target::{DrawTarget, DrawTargetExt};
use embedded_graphics::pixelcolor::Rgb565;
use zeroize::{Zeroize, Zeroizing};

use crate::canvas::{self, button, text, toggle, wrap_words, ButtonKind, BODY, HEADING, MONO_SMALL};
use crate::components::{back_rect, draw_bar, draw_keyboard, keyboard, LINE, SMALL_LINE};
use crate::layout::Rect;
use crate::screens::deriving::{DerivingState, SeedSource};
use crate::screens::{Ctx, Env, Nav, Outcome, Screen, State};
use crate::theme::*;
use crate::{secret_buf, Page, Region, RegionId, PASSPHRASE_NOT_STORED, PASS_MAX};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PassFocus {
    Entry,
    Confirm,
}

pub(crate) struct PassState {
    pub source: SeedSource,
    /// The desktop's explicit opt-in: off means the seed derives with an empty
    /// passphrase, and the screen says so.
    enabled: bool,
    pub entry: Zeroizing<String>,
    pub confirm: Zeroizing<String>,
    focus: PassFocus,
    page: Page,
    /// Show/Hide toggle (default hidden). When true the passphrase fields render
    /// unmasked so the user can verify what they typed - an unseen typo silently
    /// derives a different wallet, which is the worse failure.
    show: bool,
}

impl PassState {
    pub fn new(source: SeedSource) -> PassState {
        PassState {
            source,
            enabled: false,
            entry: secret_buf(PASS_MAX),
            confirm: secret_buf(PASS_MAX),
            focus: PassFocus::Entry,
            page: Page::Lower,
            show: false,
        }
    }

    /// Append/remove one character on whichever field has focus.
    fn edit(&mut self, c: Option<char>) {
        if !self.enabled {
            return;
        }
        let buf = match self.focus {
            PassFocus::Entry => &mut self.entry,
            PassFocus::Confirm => &mut self.confirm,
        };
        match c {
            Some(c) if buf.len() < PASS_MAX => buf.push(c),
            Some(_) => {}
            None => {
                buf.pop();
            }
        }
    }
}

/// Width floor of the Show/Hide button. The measured widths of "Show" and "Hide" set the
/// real floor (see [`Screen::layout`]); this keeps it a comfortable target rather than a
/// label with a border round it.
const SHOW_LABEL_W: i32 = 120;

pub(crate) struct Layout {
    toggle_label_y: i32,
    toggle: Rect,
    show_btn: Rect,
    entry: Rect,
    confirm: Rect,
    status_y: i32,
    kb: Rect,
    continue_btn: Rect,
    hint_y: i32,
}

impl Screen for PassState {
    type Layout = Layout;

    fn layout(&self, ctx: &Ctx) -> Layout {
        let m = &ctx.m;
        let body = m.body();
        let g = m.gap;
        let toggle_h = 48;
        let toggle_w = (body.w / 3).max(200);
        let toggle = Rect::new(body.right() - toggle_w, body.y, toggle_w, toggle_h);
        // Header row, right to left: the Off/On toggle is right-anchored, the Show/Hide
        // button sits immediately left of it, and the "Use passphrase" label takes the
        // remaining space from the left edge. Anchoring Show to the LEFT edge instead put
        // it straight on top of that label on both shipped geometries.
        let show_w = SHOW_LABEL_W.max(HEADING.text_width("Hide") as i32 + 2 * m.gap);
        let show_btn = Rect::new(toggle.x - m.gap - show_w, body.y, show_w, toggle_h);
        let fields_y = body.y + toggle_h + g;
        let (entry, confirm, status_y) = if m.landscape() {
            let fw = (body.w - g) / 2;
            let e = Rect::new(body.x, fields_y, fw, 52);
            let c = Rect::new(body.x + fw + g, fields_y, body.w - fw - g, 52);
            (e, c, e.bottom() + g / 2)
        } else {
            let e = Rect::new(body.x, fields_y, body.w, 56);
            let c = Rect::new(body.x, e.bottom() + g, body.w, 56);
            (e, c, c.bottom() + g / 2)
        };
        let kb_top = status_y + SMALL_LINE + g;
        Layout {
            toggle_label_y: body.y + (toggle_h - LINE) / 2,
            toggle,
            show_btn,
            entry,
            confirm,
            status_y,
            kb: Rect::new(body.x, kb_top, body.w, body.bottom() - kb_top),
            continue_btn: Rect::new(body.x, body.bottom() - m.btn, body.w, m.btn),
            // Where the OFF state copy starts: the fields row, because in that state
            // there are no fields and the room they would take is what the Q22 warning
            // needs on the short panel.
            hint_y: fields_y,
        }
    }

    fn regions(&self, ctx: &Ctx, out: &mut Vec<Region>) {
        let l = self.layout(ctx);
        out.push(Region { id: RegionId::Back, rect: back_rect(&ctx.m) });
        out.push(Region { id: RegionId::PassShow, rect: l.show_btn });
        out.push(Region { id: RegionId::PassToggle, rect: l.toggle });
        if self.enabled {
            out.push(Region { id: RegionId::PassEntry, rect: l.entry });
            // The confirm field appears once there is something to confirm.
            if !self.entry.is_empty() {
                out.push(Region { id: RegionId::PassConfirm, rect: l.confirm });
            }
            for k in keyboard(l.kb, self.page) {
                out.push(Region { id: k.id, rect: k.rect });
            }
        } else {
            out.push(Region { id: RegionId::KeyDone, rect: l.continue_btn });
        }
    }

    fn draw<D: DrawTarget<Color = Rgb565>>(&self, t: &mut D, ctx: &Ctx) -> Result<(), D::Error> {
        let m = &ctx.m;
        draw_bar(t, m, "Passphrase")?;
        let l = self.layout(ctx);
        let body = m.body();

        // Clipped to the space the header row leaves it: the label is the only element
        // here that can grow with wording, so it is the one that must crop rather than
        // run under the Show button. The header-row test pins that it never has to.
        let label = Rect::new(body.x, l.toggle_label_y, l.show_btn.x - m.gap - body.x, LINE);
        let mut clip = t.clipped(&label.to_eg());
        text(&mut clip, "Use passphrase", label.x, label.y, BODY, INK_PRIMARY, PAPER_1)?;
        toggle(t, l.toggle, ["Off", "On"], usize::from(self.enabled))?;
        // Show/Hide the passphrase fields (default Hidden): an unseen typo silently
        // derives a different wallet, which is the worse failure. Plain button, no
        // confirm.
        let show_label = if self.show { "Hide" } else { "Show" };
        button(t, l.show_btn, show_label, ButtonKind::Secondary, PAPER_1)?;

        if !self.enabled {
            // Desktop wording for the off state, then the warning that matters before
            // opting in.
            // Q22, in the plain words the ratified answer requires, and the whole of
            // what this state has room to say on the short panel: 800x480 leaves five
            // lines between the toggle and the button, and the acceptance criterion is
            // what gets them. Warning ink, because this is the fact that decides whether
            // a seed backup is enough to bring the wallet back - and the one thing on
            // this screen a user cannot discover later by looking.
            let mut y = l.hint_y;
            for para in PASSPHRASE_NOT_STORED {
                for line in wrap_words(para, body.w, BODY) {
                    text(t, &line, body.x, y, BODY, WARNING, PAPER_1)?;
                    y += LINE;
                }
                y += m.gap;
            }
            button(t, l.continue_btn, "Continue", ButtonKind::Primary, PAPER_1)?;
            return Ok(());
        }

        // Entry and confirm fields. Masked one bullet per typed character (the INPUT rule
        // - see `canvas::field`), or literal with spaces marked while Show is on.
        canvas::field(t, l.entry, &self.entry, !self.show, self.focus == PassFocus::Entry)?;
        if self.entry.is_empty() {
            let y = l.entry.y + (l.entry.h - LINE) / 2;
            text(t, "passphrase", l.entry.x + 12, y, BODY, INK_MUTED, PAPER_3)?;
        } else {
            // The opt-in confirm field appears once there is something to confirm.
            canvas::field(
                t,
                l.confirm,
                &self.confirm,
                !self.show,
                self.focus == PassFocus::Confirm,
            )?;
            if self.confirm.is_empty() {
                let y = l.confirm.y + (l.confirm.h - LINE) / 2;
                text(t, "repeat passphrase", l.confirm.x + 12, y, BODY, INK_MUTED, PAPER_3)?;
            }
        }

        // `differ` is the exact predicate the Done handler blocks on; the drawn state must
        // never disagree with it. The status row carries ONE line (two would overlap on the
        // 720-wide panel): the mismatch warning once a confirm attempt exists, otherwise the
        // byte counter - extended with the reason Done is still disabled while the confirm
        // field is untouched (a disabled control always says why).
        //
        // The counter reports NFKD BYTES, the desktop's counter semantics: BIP39 feeds
        // PBKDF2 the NFKD byte string, and byte length is what external passphrase limits
        // (e.g. other wallets' 256-byte caps) are stated in. The on-screen keyboard emits
        // ASCII only (test-asserted), for which NFKD is the identity and every char is one
        // byte - so `len()` IS the NFKD byte count, with no normalization pass over the
        // secret here in the draw path.
        let bytes = self.entry.len();
        let differ = *self.entry != *self.confirm;
        if differ && !self.confirm.is_empty() {
            let msg = "The two passphrases are different.";
            text(t, msg, body.x, l.status_y, MONO_SMALL, DANGER, PAPER_1)?;
        } else if differ {
            let msg = format!("{bytes} bytes (NFKD) - repeat to continue");
            text(t, &msg, body.x, l.status_y, MONO_SMALL, INK_MUTED, PAPER_1)?;
        } else {
            let msg = format!("{bytes} bytes (NFKD)");
            text(t, &msg, body.x, l.status_y, MONO_SMALL, INK_MUTED, PAPER_1)?;
        }

        draw_keyboard(t, l.kb, self.page, !differ)?;
        Ok(())
    }

    fn activate(&mut self, id: RegionId, _env: &mut Env) -> Outcome {
        match id {
            RegionId::PassToggle => {
                self.enabled = !self.enabled;
                if !self.enabled {
                    // Off wipes what was typed: an abandoned passphrase must not linger.
                    self.entry.zeroize();
                    self.confirm.zeroize();
                    self.focus = PassFocus::Entry;
                }
                Outcome::stay()
            }
            RegionId::PassShow => {
                self.show = !self.show;
                Outcome::stay()
            }
            RegionId::PassEntry => {
                self.focus = PassFocus::Entry;
                Outcome::stay()
            }
            RegionId::PassConfirm => {
                self.focus = PassFocus::Confirm;
                Outcome::stay()
            }
            RegionId::Key(c) => {
                self.edit(Some(c));
                Outcome::stay()
            }
            RegionId::Space => {
                self.edit(Some(' '));
                Outcome::stay()
            }
            RegionId::KeyBackspace => {
                self.edit(None);
                Outcome::stay()
            }
            RegionId::Shift => {
                self.page = if self.page == Page::Lower { Page::Upper } else { Page::Lower };
                Outcome::stay()
            }
            RegionId::PageDigits => {
                self.page = Page::Digits;
                Outcome::stay()
            }
            RegionId::PageLetters => {
                self.page = Page::Lower;
                Outcome::stay()
            }
            RegionId::PageSymbols => {
                self.page = Page::Symbols;
                Outcome::stay()
            }
            // Done on the passphrase screen does NOT derive. It parks the seed material
            // in the Deriving state and returns, so the embedder's next draw puts the
            // interstitial on the panel BEFORE `Ui::tick` spends several seconds in
            // PBKDF2. Deriving inline here is what made this transition feel like a
            // freeze: the last passphrase keypress stayed on screen for the whole stretch.
            RegionId::KeyDone => {
                if self.enabled && *self.entry != *self.confirm {
                    // Mismatch shown in danger ink; Done is drawn disabled.
                    return Outcome::stay();
                }
                let mut passphrase = secret_buf(PASS_MAX);
                if self.enabled {
                    passphrase.push_str(&self.entry);
                }
                // A duplicate, not a move: Back must restore this screen intact, so the
                // seed material the interstitial works from is its own copy.
                let source = self.source.duplicate();
                Outcome::push(State::Deriving(DerivingState { source, passphrase }))
            }
            _ => Outcome::stay(),
        }
    }

    /// A derived secret is on this screen: Back asks first.
    fn back(&self) -> Nav {
        Nav::ConfirmExit
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::screens::deriving::SeedSource;
    use crate::screens::testing::{Fixture, GEOMETRIES};
    use zeroize::Zeroizing;

    /// Every line the OFF state draws fits above the Continue button, on both panels.
    ///
    /// The Q22 warning has no scroll and no ellipsis behind it, so a copy edit that pushed
    /// it under the button would silently drop an acceptance criterion. This is the same
    /// discipline the PIN screen fixed blocks keep, and it is why the wording above is
    /// measured rather than eyeballed.
    #[test]
    fn the_off_state_warning_fits_above_the_button() {
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            let ctx = f.ctx();
            let state = PassState::new(SeedSource::Phrase(Zeroizing::new(String::new())));
            let l = state.layout(&ctx);
            let body = f.m.body();
            let mut y = l.hint_y;
            for para in PASSPHRASE_NOT_STORED {
                y += wrap_words(para, body.w, BODY).len() as i32 * LINE + f.m.gap;
            }
            assert!(
                y <= l.continue_btn.y,
                "{w}x{h}: the off-state copy ends at {y} and the button starts at {}",
                l.continue_btn.y
            );
        }
    }
}
