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

use crate::canvas::{
    self, button, panel, text, text_centered, toggle, wrap_words, ButtonKind, BODY, HEADING,
    MONO_SMALL,
};
use crate::components::{
    back_rect, draw_bar, draw_bar_no_back, draw_keyboard, keyboard, LINE, SMALL_LINE,
};
use crate::layout::Rect;
use crate::screens::deriving::{DerivingState, SeedSource};
use crate::screens::{Ctx, Env, Nav, Outcome, Screen, State};
use crate::theme::*;
use crate::{
    secret_buf, Page, Region, RegionId, ScreenId, Secret, UiRequest, PASSPHRASE_NOT_STORED,
    PASS_MAX,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PassFocus {
    Entry,
    Confirm,
}

/// Why this screen is up, which is the one thing that changes what its first page says
/// and what the toggle means.
pub(crate) enum PassPurpose {
    /// The create and restore flows. A passphrase is OPTIONAL here: off is a real answer
    /// and means this seed derives its own wallet, so the toggle is a control and the
    /// first page is the Q22 warning the user passes through to reach it.
    Create,
    /// Deriving a SECOND wallet from the words of one that is already stored. Off is not
    /// an answer here - it would re-derive the wallet the user is looking at - so there is
    /// no toggle, and the first page is the explanation of what this makes instead.
    ///
    /// Carries the name of the wallet the words came from, because every sentence on that
    /// page is about what does NOT happen to it.
    Derive(String),
}

pub(crate) struct PassState {
    pub source: SeedSource,
    purpose: PassPurpose,
    /// The desktop's explicit opt-in: off means the seed derives with an empty
    /// passphrase, and the screen says so.
    ///
    /// In [`PassPurpose::Derive`] it is not an opt-in at all: it separates the
    /// explanation page from the entry page, and the entry page is the only way on.
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
        PassState::with_purpose(source, PassPurpose::Create)
    }

    /// The entry point from an open wallet's home: derive a SECOND wallet from the words
    /// this one is made of.
    ///
    /// It takes a copy of the phrase rather than the wallet's own buffer, because the
    /// screen it is opened from is dropped by the transition that opens this one - which
    /// is what keeps exactly one copy of the words alive. Exact capacity, so the copy
    /// cannot grow and strand a partial phrase outside the `Zeroizing` wrapper.
    pub fn deriving_from(phrase: &str, name: &str) -> PassState {
        let mut copy = secret_buf(crate::PHRASE_MAX);
        copy.push_str(phrase);
        PassState::with_purpose(
            SeedSource::Phrase(copy),
            PassPurpose::Derive(String::from(name)),
        )
    }

    fn with_purpose(source: SeedSource, purpose: PassPurpose) -> PassState {
        PassState {
            source,
            purpose,
            enabled: false,
            entry: secret_buf(PASS_MAX),
            confirm: secret_buf(PASS_MAX),
            focus: PassFocus::Entry,
            page: Page::Lower,
            show: false,
        }
    }

    /// Whether a passphrase is optional on this visit. False in the derive purpose, where
    /// a wallet with no passphrase is the wallet the user already has.
    fn optional(&self) -> bool {
        matches!(self.purpose, PassPurpose::Create)
    }

    /// The first page: what this screen has to say before anything is typed.
    ///
    /// In the create purpose it is the ratified Q22 warning, which is placement (i) and
    /// the state a user passes through to turn a passphrase on. In the derive purpose it
    /// is what the action actually does - the BIP-39 fact that decides whether the user
    /// understands what they are about to make - and Q22 is not repeated here: the fork
    /// screen states it two screens later (placement ii) and the save is GATED on the
    /// acknowledgement (placement iii), both of which this flow passes through.
    fn intro(&self) -> Vec<String> {
        match &self.purpose {
            PassPurpose::Create => {
                PASSPHRASE_NOT_STORED.iter().map(|s| String::from(*s)).collect()
            }
            // ONE paragraph, and every word of it measured: the first page has three
            // BODY lines on the 800x480 panel above the Continue button, and there is no
            // scroll behind it. What has to survive that budget is the BIP-39 fact - a
            // passphrase makes a DIFFERENT wallet - and the promise that the wallet the
            // user came from is untouched. The copy gate asserts both clauses are here.
            PassPurpose::Derive(name) => alloc::vec![format!(
                "This does not change \"{name}\": these words plus a passphrase are a \
                 different wallet, with its own fingerprint and addresses."
            )],
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
        // No toggle where a passphrase is not optional: the control that is not drawn is
        // the control that cannot be tapped, and off is not an answer in the derive
        // purpose - it is the wallet the user already has.
        if self.optional() {
            out.push(Region { id: RegionId::PassToggle, rect: l.toggle });
        }
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
        let heading = match &self.purpose {
            PassPurpose::Create => "Use passphrase",
            PassPurpose::Derive(_) => "Add a passphrase",
        };
        let mut clip = t.clipped(&label.to_eg());
        text(&mut clip, heading, label.x, label.y, BODY, INK_PRIMARY, PAPER_1)?;
        if self.optional() {
            toggle(t, l.toggle, ["Off", "On"], usize::from(self.enabled))?;
        }
        // Show/Hide the passphrase fields (default Hidden): an unseen typo silently
        // derives a different wallet, which is the worse failure. Plain button, no
        // confirm.
        let show_label = if self.show { "Hide" } else { "Show" };
        button(t, l.show_btn, show_label, ButtonKind::Secondary, PAPER_1)?;

        if !self.enabled {
            // The first page. In the create purpose it is Q22 in the plain words the
            // ratified answer requires, and the whole of what this state has room to say
            // on the short panel: 800x480 leaves five lines between the toggle and the
            // button, and the acceptance criterion is what gets them. Warning ink, because
            // this is the fact that decides whether a seed backup is enough to bring the
            // wallet back - and the one thing on this screen a user cannot discover later
            // by looking.
            //
            // In the derive purpose it is what this action makes, in the same ink for the
            // same reason: a user who reads it as "change the passphrase of this wallet"
            // will be looking for a wallet that does not exist.
            let mut y = l.hint_y;
            for para in self.intro() {
                for line in wrap_words(&para, body.w, BODY) {
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
            // Continue on the first page of the derive purpose. It is the same region as
            // the keyboard's Done because it is the same button in the same place - what
            // differs is that there is nothing to commit yet, so it opens the fields.
            RegionId::KeyDone if !self.enabled && !self.optional() => {
                self.enabled = true;
                Outcome::stay()
            }
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

// ---------------------------------------------------------------------------------------
// S-21b: the passphrase of a wallet that already exists
// ---------------------------------------------------------------------------------------

/// What is on the panel. Three phases, and every one of them has a way out.
///
/// A phase rather than three screens because they are one exchange: type, wait, read what
/// happened. What makes them phases and not a mode flag is that each one draws a DIFFERENT
/// set of regions and the dispatcher hit-tests exactly what is drawn, so a control that
/// belongs to another phase cannot be tapped.
#[derive(Debug, Clone, PartialEq, Eq)]
enum UnlockPhase {
    /// The field and the keyboard.
    Typing,
    /// The C3 Busy frame, published BEFORE the derivation starts (see
    /// `firmware/src/main.rs`'s `publish_before_answering`). Nothing is tappable and Back
    /// is absent, because the work is synchronous and cannot be cancelled - a Back here
    /// would be a button that lies.
    ///
    /// It cannot wedge: the dispatch is synchronous, every request in this vocabulary is
    /// answered, and BOTH answers leave this phase.
    Busy,
    /// What happened, in derivation facts. See [`crate::PassphraseRefusal`] for what this
    /// screen may and may not say.
    Refused(String),
}

/// S-21b. The passphrase of a STORED wallet, asked for at open time.
///
/// # One field and no confirm
///
/// The create screen has two fields because nothing there can check the answer: a typo in
/// a passphrase that has never been used silently derives a different wallet, so the
/// second field is the only check available. Here the record itself is the check - it
/// carries the fingerprint the seed has to produce - so a typo is caught by the device
/// rather than by retyping, and a second field would be friction that buys nothing.
///
/// # What it may never do
///
/// It never says "wrong", "incorrect" or "invalid": BIP-39 has no invalid passphrases,
/// only different wallets, and the copy gate asserts those words appear in no frame of it.
/// It never renders what the words derive with an EMPTY passphrase either - that value is
/// an existence proof for a hidden wallet, and the embedder discards it rather than
/// sending it here.
pub(crate) struct PassUnlockState {
    /// The slot the wallet list raised [`crate::UiRequest::OpenWallet`] for. Carried so
    /// the answer and the retry gate are about ONE wallet.
    slot: u8,
    /// What the user called it. Every sentence on the screen names it.
    name: String,
    pub(super) entry: Zeroizing<String>,
    show: bool,
    page: Page,
    phase: UnlockPhase,
}

impl PassUnlockState {
    pub(crate) fn new(slot: u8, name: &str) -> PassUnlockState {
        PassUnlockState {
            slot,
            name: String::from(name),
            entry: secret_buf(PASS_MAX),
            show: false,
            page: Page::Lower,
            phase: UnlockPhase::Typing,
        }
    }

    pub(crate) fn slot(&self) -> u8 {
        self.slot
    }

    /// The screen an embedder sees. A Busy frame has no Back and nothing tappable, so it
    /// IS a different screen to an embedder rather than a mode of the one underneath it -
    /// the rule `State::Verify`, `State::Erase` and the card screens already keep.
    pub(crate) fn id(&self) -> ScreenId {
        match self.phase {
            UnlockPhase::Busy => ScreenId::Working,
            _ => ScreenId::PassphraseUnlock,
        }
    }

    /// The refusal arrived: leave the Busy phase and say what happened.
    ///
    /// The typed passphrase is WIPED here rather than left in the field. It derived some
    /// other wallet, so it is not the answer; keeping it would leave a secret on a screen
    /// whose next tap is "try again", and the user has to retype it anyway to change it.
    pub(crate) fn refused(&mut self, sentence: String) {
        self.entry.zeroize();
        self.page = Page::Lower;
        self.show = false;
        self.phase = UnlockPhase::Refused(sentence);
    }

    /// Whether the derivation this screen asked for is still running.
    pub(crate) fn busy(&self) -> bool {
        self.phase == UnlockPhase::Busy
    }
}

pub(crate) struct UnlockLayout {
    /// The prose block: the refusal, or the line that says what this screen wants.
    prose: Rect,
    field: Rect,
    show_btn: Rect,
    status_y: i32,
    hint_y: i32,
    kb: Rect,
    /// Unlock, or Try again in the refused phase.
    action: Rect,
}

impl Screen for PassUnlockState {
    type Layout = UnlockLayout;

    fn layout(&self, ctx: &Ctx) -> UnlockLayout {
        let m = &ctx.m;
        let body = m.body();
        let g = m.gap;
        let show_w = SHOW_LABEL_W.max(HEADING.text_width("Hide") as i32 + 2 * g);
        let field_h = 56;
        let action = Rect::new(body.x, body.bottom() - m.btn, body.w, m.btn);
        match &self.phase {
            // Typing: field and Show on one row, the counter under it, one line of Q22,
            // then the keyboard fills what is left. The action button is the keyboard's
            // Done, so there is no separate button row to pay for.
            UnlockPhase::Typing => {
                let field = Rect::new(body.x, body.y, body.w - show_w - g, field_h);
                let show_btn = Rect::new(field.right() + g, body.y, show_w, field_h);
                let status_y = field.bottom() + g / 2;
                let hint_y = status_y + SMALL_LINE;
                let kb_top = hint_y + SMALL_LINE + g;
                UnlockLayout {
                    prose: Rect::new(body.x, body.y, body.w, 0),
                    field,
                    show_btn,
                    status_y,
                    hint_y,
                    kb: Rect::new(body.x, kb_top, body.w, body.bottom() - kb_top),
                    action,
                }
            }
            // The other two phases have no keyboard, so the prose gets the panel. The
            // refusal is the longest copy in this crate that is not a review page, and it
            // is the one the user has to read.
            _ => UnlockLayout {
                prose: Rect::new(body.x, body.y, body.w, action.y - g - body.y),
                field: Rect::new(body.x, body.y, 0, 0),
                show_btn: Rect::new(body.x, body.y, 0, 0),
                status_y: action.y - g - SMALL_LINE,
                hint_y: action.y - g,
                kb: Rect::new(body.x, body.y, 0, 0),
                action,
            },
        }
    }

    fn regions(&self, ctx: &Ctx, out: &mut Vec<Region>) {
        let l = self.layout(ctx);
        // No Back and nothing else while the derivation runs. The panel is showing a frame
        // that says the device is working, and it is.
        if self.phase == UnlockPhase::Busy {
            return;
        }
        out.push(Region { id: RegionId::Back, rect: back_rect(&ctx.m) });
        match &self.phase {
            UnlockPhase::Typing => {
                out.push(Region { id: RegionId::PassShow, rect: l.show_btn });
                out.push(Region { id: RegionId::PassEntry, rect: l.field });
                for k in keyboard(l.kb, self.page) {
                    out.push(Region { id: k.id, rect: k.rect });
                }
            }
            // Try again, and only where the wait has run out: a disabled control is drawn
            // and not hit-tested, so a tap during the wait does nothing at all.
            UnlockPhase::Refused(_) => {
                if ctx.gate.wait_ms(self.slot) == 0 {
                    out.push(Region { id: RegionId::PassUnlock, rect: l.action });
                }
            }
            UnlockPhase::Busy => {}
        }
    }

    fn draw<D: DrawTarget<Color = Rgb565>>(&self, t: &mut D, ctx: &Ctx) -> Result<(), D::Error> {
        let m = &ctx.m;
        let l = self.layout(ctx);
        let body = m.body();
        match &self.phase {
            UnlockPhase::Busy => {
                // C3, and the same words the create interstitial uses, because it is the
                // same work: one BIP-39 stretch and every scheme.
                draw_bar_no_back(t, m, &format!("Opening {}", self.name))?;
                let card_h = 3 * LINE + 4 * m.gap;
                let card = Rect::new(body.x, body.y + (body.h - card_h) / 2, body.w, card_h);
                panel(t, card, PAPER_2, BORDER_STRONG)?;
                let mut y = card.y + m.gap;
                text_centered(
                    t,
                    "Opening this wallet...",
                    Rect::new(card.x, y, card.w, LINE),
                    HEADING,
                    INK_PRIMARY,
                    PAPER_2,
                )?;
                y += LINE + m.gap;
                for line in [
                    "Deriving keys from your words and passphrase.",
                    "This takes a few seconds. Do not power off.",
                ] {
                    text_centered(
                        t,
                        line,
                        Rect::new(card.x, y, card.w, LINE),
                        BODY,
                        INK_SECONDARY,
                        PAPER_2,
                    )?;
                    y += LINE;
                }
                return Ok(());
            }
            UnlockPhase::Refused(why) => {
                draw_bar(t, m, &self.name)?;
                let mut y = l.prose.y;
                for line in wrap_words(why, l.prose.w, BODY) {
                    text(t, &line, l.prose.x, y, BODY, WARNING, PAPER_1)?;
                    y += LINE;
                }
                // A disabled control says why it is disabled, in the C4d grammar: the
                // number beside it is the whole reason.
                let wait = ctx.gate.wait_ms(self.slot);
                if wait > 0 {
                    let secs = wait.div_ceil(1000);
                    let msg = format!("Wait {secs}s before the next try.");
                    text(t, &msg, body.x, l.status_y, MONO_SMALL, INK_MUTED, PAPER_1)?;
                }
                button(
                    t,
                    l.action,
                    "Try again",
                    if wait > 0 { ButtonKind::Disabled } else { ButtonKind::Primary },
                    PAPER_1,
                )?;
                return Ok(());
            }
            UnlockPhase::Typing => {}
        }

        draw_bar(t, m, &self.name)?;
        // Typed INPUT masking, one bullet per character, exactly as the create screen
        // masks it - and the same Show button, for the same reason: an unseen typo is a
        // wallet that does not open, and the counter beside the field discloses the length
        // anyway.
        canvas::field(t, l.field, &self.entry, !self.show, true)?;
        if self.entry.is_empty() {
            let y = l.field.y + (l.field.h - LINE) / 2;
            text(t, "passphrase", l.field.x + 12, y, BODY, INK_MUTED, PAPER_3)?;
        }
        button(
            t,
            l.show_btn,
            if self.show { "Hide" } else { "Show" },
            ButtonKind::Secondary,
            PAPER_1,
        )?;
        // The byte counter, in the create screen's own words, and the two fixed lines
        // beside it. Both are measured by `the_unlock_lines_fit_the_panel` - `text` does
        // not wrap, so a line wider than the body is drawn off the panel.
        let bytes = self.entry.len();
        let counter = format!("{bytes} bytes (NFKD) - {}", UNLOCK_LINES[0]);
        text(t, &counter, body.x, l.status_y, MONO_SMALL, INK_MUTED, PAPER_1)?;
        // Q22, in the one line this phase has room for. The full statement is on the entry
        // screen of every flow that CREATES a wallet; what a user needs here is the fact
        // that decides whether they can get this wallet back without the device.
        text(t, UNLOCK_LINES[1], body.x, l.hint_y, MONO_SMALL, INK_MUTED, PAPER_1)?;
        draw_keyboard(t, l.kb, self.page, !self.entry.is_empty())?;
        Ok(())
    }

    fn activate(&mut self, id: RegionId, env: &mut Env) -> Outcome {
        match &self.phase {
            // Nothing is tappable while the work runs; `regions` returns none, and this is
            // the same answer for a caller that did not consult it.
            UnlockPhase::Busy => return Outcome::stay(),
            UnlockPhase::Refused(_) => {
                // The gate is checked here as well as in `regions`, and against the same
                // clock: the two are read a frame apart, and a tap that arrived while the
                // countdown was still running must not be honoured by the pass that
                // finishes it.
                if id == RegionId::PassUnlock && env.gate.wait_ms(self.slot) == 0 {
                    self.phase = UnlockPhase::Typing;
                }
                return Outcome::stay();
            }
            UnlockPhase::Typing => {}
        }
        match id {
            RegionId::PassShow => {
                self.show = !self.show;
                Outcome::stay()
            }
            RegionId::PassEntry => Outcome::stay(),
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
            // The commit. The Busy phase is entered BEFORE the request is returned, so the
            // frame the embedder publishes on its way to answering is the one that says
            // the device is working - which is the whole of C3 and the reason this screen
            // has a phase rather than a spinner it cannot animate.
            //
            // An empty passphrase is not offered: this wallet did not open with one (that
            // is why the screen is up), so Done is drawn disabled until something is typed.
            RegionId::KeyDone if !self.entry.is_empty() => {
                let passphrase = Secret::passphrase(&self.entry);
                self.phase = UnlockPhase::Busy;
                Outcome::ask(UiRequest::UnlockWallet { slot: self.slot, passphrase })
            }
            _ => Outcome::stay(),
        }
    }

    /// Back is the wallet list, with nothing opened and nothing spent. The typed
    /// passphrase goes with this screen when it is dropped.
    ///
    /// No confirmation modal, unlike the create flow's passphrase screen: there is nothing
    /// here that cannot be retyped in ten seconds, and no derivation that would be lost.
    fn back(&self) -> Nav {
        match self.phase {
            // Unreachable - the Busy phase draws no Back and hit-tests none - and stated
            // rather than defaulted, because "the panel cannot move while the device is
            // deriving" is the property, not an accident of which regions got pushed.
            UnlockPhase::Busy => Nav::Stay,
            _ => Nav::Back,
        }
    }
}

impl PassUnlockState {
    /// Append or remove one character. The buffer is exact-capacity, so this can never
    /// reallocate and strand a partial passphrase outside the `Zeroizing` wrapper.
    fn edit(&mut self, c: Option<char>) {
        match c {
            Some(c) if self.entry.len() < PASS_MAX => self.entry.push(c),
            Some(_) => {}
            None => {
                self.entry.pop();
            }
        }
    }
}

/// The two fixed lines the unlock screen draws under its field, so that a copy edit that
/// overran the panel fails here rather than on the glass.
///
/// The second is Q22 at this placement, in the words the row has room for and no weaker
/// than the truth: this screen is only ever up for a wallet whose passphrase this device
/// does NOT hold - a stored one opens with no prompt at all - so the sentence is
/// unconditional here, where the fuller statement on the create and save screens has to
/// carry the opt-in.
///
/// `text` does not wrap and a line wider than the body is drawn straight off the panel -
/// which is exactly what the graphics gate caught the first time this screen was written.
/// The measurement is the same one the draw makes.
pub(crate) const UNLOCK_LINES: [&str; 2] = ["Done opens it", "Not stored on this device."];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::screens::deriving::SeedSource;
    use crate::screens::testing::{fits, Fixture, GEOMETRIES};
    use zeroize::Zeroizing;

    /// THE COPY GATE, for the two pages this module writes about a passphrase.
    ///
    /// The derive page is the one that has to be right: a user who reads it as "change the
    /// passphrase of this wallet" will go looking for a wallet that does not exist and
    /// conclude the device ate it. What makes that impossible to misread is the BIP-39
    /// fact stated as a fact - these words plus a passphrase ARE a different wallet - next
    /// to the promise that the wallet they came from is untouched.
    ///
    /// Asserted over the copy and not the pixels, because a framebuffer cannot be searched
    /// for a word.
    #[test]
    fn the_derive_page_says_what_it_makes_and_what_it_leaves_alone() {
        let derive = PassState::deriving_from("", "savings");
        let page = derive.intro().join(" ");
        assert!(page.contains("does not change"), "{page}");
        assert!(page.contains("different wallet"), "{page}");
        assert!(page.contains("savings"), "the page names the wallet it leaves alone: {page}");
        // Not a toggle of the wallet the user came from, in any wording.
        for banned in ["passphrase ON", "passphrase off", "change the passphrase"] {
            assert!(!page.contains(banned), "{page}");
        }

        // And the create page is the ratified Q22 statement, unparaphrased.
        let create = PassState::new(SeedSource::Phrase(Zeroizing::new(String::new())));
        assert_eq!(create.intro(), PASSPHRASE_NOT_STORED.to_vec());
        let q22 = create.intro().join(" ");
        assert!(q22.contains("Not stored here unless you choose to store it"), "{q22}");
        assert!(q22.contains("DIFFERENT wallet"), "{q22}");
    }

    /// The unlock screen never says a passphrase is wrong, in any of its own fixed copy.
    /// The refusal it renders comes from [`crate::PassphraseRefusal`], which has its own
    /// gate in `tests/passphrase_open.rs`.
    #[test]
    fn the_unlock_screen_never_delivers_a_verdict() {
        for line in UNLOCK_LINES {
            for verdict in ["wrong", "Wrong", "incorrect", "invalid", "Invalid"] {
                assert!(!line.contains(verdict), "{line}");
            }
        }
    }

    /// Both fixed lines of the unlock screen fit the body they are drawn in, on both
    /// panels, with the widest counter in front of one of them.
    #[test]
    fn the_unlock_lines_fit_the_panel() {
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            let body = f.m.body();
            let counter = format!("{PASS_MAX} bytes (NFKD) - {}", UNLOCK_LINES[0]);
            for line in [counter.as_str(), UNLOCK_LINES[1]] {
                fits(
                    &format!("{w}x{h} unlock"),
                    line,
                    MONO_SMALL.text_width(line) as i32,
                    Rect::new(body.x, 0, body.w, 0),
                );
            }
        }
    }

    /// A tap that arrives while the retry gate is still counting down does nothing, and
    /// the same tap works the moment it reaches zero.
    ///
    /// `regions` already withholds `PassUnlock` during the wait, so this cannot be reached
    /// through the integration harness at all - `tap()` refuses an undrawn region, which
    /// is the right behaviour for a test of what a finger can hit and the wrong instrument
    /// for this. `activate` is called DIRECTLY here, because the re-check inside it is
    /// defence against a different thing: `regions` and `activate` read the gate a frame
    /// apart, and a tap dispatched from the region list of the frame before the countdown
    /// started must not be honoured by the pass that finishes it. Without that second
    /// read the schedule has a one-frame hole in it on every single wait.
    ///
    /// Broken version: delete the `env.gate.wait_ms(self.slot) == 0` condition in
    /// `activate`'s `Refused` arm. The screen returns to Typing on the first call and the
    /// third assertion trips.
    #[test]
    fn a_tap_during_the_wait_is_not_honoured() {
        let mut f = Fixture::new(720, 720);
        let mut s = PassUnlockState::new(2, "savings");

        // Three refusals is where the schedule stops being free: five seconds.
        for _ in 0..3 {
            f.gate.refused(2);
        }
        s.refused(String::from("That passphrase opens a different wallet."));
        assert_eq!(f.gate.wait_ms(2), 5_000);
        assert!(!matches!(s.phase, UnlockPhase::Typing), "the screen is in its refused state");

        // The disabled control is not even offered...
        let mut out = Vec::new();
        s.regions(&f.ctx(), &mut out);
        assert!(
            !out.iter().any(|r| r.id == RegionId::PassUnlock),
            "a control that cannot be used is not hit-tested"
        );

        // ...and a tap that reaches `activate` anyway is refused there too.
        s.activate(RegionId::PassUnlock, &mut f.env());
        assert!(
            !matches!(s.phase, UnlockPhase::Typing),
            "a tap during the wait returned the screen to the keyboard"
        );

        // The wait runs out, and the identical tap works.
        f.gate.tick(5_000, Some(2));
        assert_eq!(f.gate.wait_ms(2), 0);
        s.activate(RegionId::PassUnlock, &mut f.env());
        assert!(
            matches!(s.phase, UnlockPhase::Typing),
            "once the wait is over Try again has to work"
        );

        // And the gate has NOT forgiven the attempts: the next refusal is the fourth, so
        // the wait doubles rather than restarting at five seconds.
        assert_eq!(f.gate.refused(2), 10_000);
    }

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
            // Both purposes: the create flow's Q22 warning and the derive action's
            // explanation are drawn in the same place by the same code, so both have to
            // fit, and the second one is the longer.
            for state in [
                PassState::new(SeedSource::Phrase(Zeroizing::new(String::new()))),
                PassState::deriving_from("", "a wallet with a fairly long name"),
            ] {
                let l = state.layout(&ctx);
                let body = f.m.body();
                let mut y = l.hint_y;
                for para in state.intro() {
                    y += wrap_words(&para, body.w, BODY).len() as i32 * LINE + f.m.gap;
                }
                assert!(
                    y <= l.continue_btn.y,
                    "{w}x{h}: the first-page copy ends at {y} and the button starts at {}",
                    l.continue_btn.y
                );
            }
        }
    }
}
