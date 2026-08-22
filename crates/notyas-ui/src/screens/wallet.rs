// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! S-21 Wallet home (UX 7): the per-wallet hub. Identity first, then what can be done
//! with it.
//!
//! The identity card is the point of the screen. An airgapped device has no chain view,
//! so there are no balances here and never will be - a stale balance is worse than none -
//! and what identifies a wallet is the fingerprint, which is also how a user notices that
//! a passphrase typo has given them a DIFFERENT wallet (commandment 8). Everything on the
//! card is public: a name, eight hex characters, a path, a network.
//!
//! # Which actions exist
//!
//! Only the ones that lead somewhere. The 0.1.0 rule about never drawing an affordance
//! nothing hit-tests decides what this screen carries: a card appears when the screen
//! behind it exists AND this wallet can reach it, and a card that opened nothing would be
//! a worse introduction to the wallet than a shorter list. Multisig is here because S-41
//! is, and it is offered on a STORED wallet only - a registration is a record in a registry
//! slot that names a wallet slot, so a session wallet has nowhere to put one and nothing to
//! list. Sign is here because S-27 is, and it is offered on a STORED wallet holding its
//! derivation - both halves, for the reason on the card itself.
//!
//! Export is offered exactly when this UI holds the derivation, and that is a property of
//! the CALLER rather than of the wallet: a "Use once, keep nothing" session hands it over
//! because the keys ARE this screen's state, and the embedder hands it over for a stored
//! wallet it has just unsealed ([`crate::Ui::wallet_opened_with_keys`]). Without it the
//! card is absent - the UI owns no key ladder and cannot re-derive what it was not given.
//! Export is also the route to the receive addresses: S-26 carries the per-scheme address
//! list, so one card reaches the xpub, the descriptor, the QR codes and the addresses.

use alloc::string::String;
use alloc::vec::Vec;

use embedded_graphics::draw_target::{DrawTarget, DrawTargetExt};
use embedded_graphics::pixelcolor::Rgb565;

use crate::canvas::{
    button, fill, frame, text, wrap_words, ButtonKind, BODY, CAPTION, HEADING, MONO_SMALL,
};
use notyas_fonts::Atlas;
use crate::components::{back_rect, draw_bar, LINE, SMALL_LINE};
use crate::danger::{Danger, DangerGrade, DangerOutcome};
use crate::layout::{Rect, LIST_ROW_MIN, TOUCH_MIN};
use crate::screens::multisig::MultisigListState;
use crate::screens::review::marker;
use crate::screens::wallets::chip;
use crate::screens::passphrase::PassState;
use crate::screens::schemes::{Origin as SchemesOrigin, SchemesState};
use crate::screens::erase::EraseState;
use crate::screens::{Answer, Ctx, Env, Nav, Outcome, Screen, State};
use crate::theme::*;
use crate::{
    PassphraseState, Region, RegionId, StorageOutcome, StoreStatus, UiRequest, WordsOutcome,
    WalletInfo,
};
use notyas_core::bitcoin::Network;
use notyas_core::report::Report;

pub(crate) struct WalletState {
    pub info: WalletInfo,
    /// The derivation behind this wallet, when the caller had one to give: a session
    /// wallet, because nothing was written and this state IS the wallet, or a stored one
    /// the embedder unsealed and handed over. `None` where the keys stayed sealed on the
    /// std side - this crate owns no key ladder and can derive nothing back.
    ///
    /// `Option` because Export moves it into the schemes screen out of a `&mut self`.
    pub report: Option<Report>,
    /// The open danger sheet, and what consenting to it does.
    ///
    /// One field for every step of every sequence on this screen: the sheet knows its own
    /// grade, so "the consequence has been read" and "the name has been typed" are the
    /// same `Confirmed` answer asked of two different sheets, and there is no second flag
    /// to disagree with it. The [`Consent`] beside it says which ACTION the answer belongs
    /// to, which is the one thing a grade cannot say - two actions on this screen open a
    /// C4b sheet, and a screen that inferred the action from the grade would eventually
    /// run the wrong one.
    danger: Option<(Consent, Danger)>,
    /// How far the body has been dragged up, in pixels.
    ///
    /// The screen scrolls because it has to: a stored wallet with its keys, a passphrase
    /// and a registry offers five actions, and 190 px under the identity card on the
    /// 800x480 panel holds two of them at the touch floor. What gives way is neither the
    /// floor nor the number of actions - it is the assumption that a wallet home is one
    /// screenful. The identity card scrolls with the actions rather than pinning: it is
    /// the content a reader starts on, not a header, and pinning it would spend the 116 px
    /// that make the last card reachable.
    scroll: i32,
    /// What the last thing this screen asked the embedder for did, when it did not change
    /// the screen. Cleared by the next tap, because a band is about ONE action.
    ///
    /// The storage toggle needs it and the delete does not: a delete leaves this screen
    /// for the list, which carries its own band, while a toggle that was refused leaves
    /// the user looking at exactly what they were looking at before.
    notice: Option<String>,
}

/// What consenting to the open sheet does. Never inferred from the sheet's grade - see
/// [`WalletState::danger`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Consent {
    /// The C4b consequence of a delete has been read; the typed-name sheet follows.
    Delete,
    /// View this wallet's recovery words (C4b: reveals the seed to anyone watching).
    ViewWords,
    /// Store this wallet's passphrase on this device (C4b: destructive of a security
    /// property, and undone by turning it off again).
    StorePassphrase,
    /// Forget the stored passphrase (C4c: this device can never show it back, so what it
    /// forgets is gone, and a tap must not be able to cause that).
    ForgetPassphrase,
}

impl WalletState {
    /// This wallet, with the derivation behind it if the caller has one.
    ///
    /// ONE constructor over the one axis that matters, rather than a pair named after the
    /// two situations it was first used in: whether the store holds the wallet
    /// (`info.stored`) and whether this screen holds its keys (`report`) are INDEPENDENT
    /// facts, and a constructor per situation made the four combinations look like two.
    /// The one that was missing is the one the product needs most - a STORED wallet the
    /// embedder has just unsealed, which is both - and its absence is why a wallet behind
    /// the PIN could be deleted and nothing else.
    pub fn new(info: WalletInfo, report: Option<Report>) -> WalletState {
        WalletState { info, report, danger: None, notice: None, scroll: 0 }
    }

    /// This card's copy, on this wallet.
    ///
    /// Every card but one takes its words from the [`action_copy`] table; the storage row
    /// is the exception because it is one control with two directions, and which one it is
    /// in is a fact about the wallet rather than about the region. One accessor, so the
    /// drawing, the measuring and the fit test cannot read different tables.
    fn card_copy(&self, id: RegionId) -> (&'static str, &'static str, Rgb565) {
        match id {
            RegionId::ActPassphraseStore => storage_copy(self.info.passphrase),
            other => action_copy(other),
        }
    }

    /// The sheet that offers to store the passphrase (C4b).
    ///
    /// Grade by consequence, per `danger.rs`: this destroys a security property - the
    /// passphrase stops being a second factor for anyone who has the PIN - and it is
    /// recoverable, because turning it off again is a control on this same screen. The
    /// two dangers it names are the two that are true whichever way the toggle goes: what
    /// the PIN then buys an attacker, and the fact that a device is not a backup.
    fn store_sheet(&self) -> Danger {
        Danger::confirm("Store the passphrase on this device?", &STORE_DANGERS, "Store it")
    }

    /// The C4b sheet for revealing recovery words: a warning that the seed
    /// will be visible, with a confirm that raises RecoveryWords.
    fn words_sheet(&self) -> Danger {
        Danger::confirm(
            "Reveal recovery words?",
            &[
                "Anyone who sees these words can steal every coin in this wallet.",
                "Do not reveal them where a camera can see the screen.",
            ],
            "Reveal words",
        )
    }

    /// The first sheet of the forget sequence (C4b): what forgetting costs, on a sheet
    /// with room to say it.
    ///
    /// Two sheets and not one, on the delete sequence's own precedent two functions up: the
    /// grade that this action EARNS is the hold, and a hold bar takes 120 px, which leaves
    /// 64 px of prose on the 800x480 panel - two lines, for a consequence that needs five.
    /// So the consequence is read first and the hold is taken second, with the sentence
    /// that matters restated on it.
    fn forget_sheet(&self) -> Danger {
        let lines = forget_consequence(&self.info.name);
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        Danger::confirm("Forget the passphrase?", &refs, "Continue")
    }

    /// The second sheet (C4c): the consent itself.
    ///
    /// A hold and not a tap. The effect is irreversible the moment the session ends - this
    /// device destroys a secret it can never re-display - so a user who has not written the
    /// passphrase down and taps this by accident has lost the wallet.
    fn forget_hold_sheet(&self) -> Danger {
        Danger::hold("Forget the passphrase?", &[FORGET_HOLD], "Forget it")
    }

    /// What deleting this wallet destroys, and what the way back is.
    ///
    /// Read off the wallet in hand rather than written as a constant: the registration
    /// count is runtime state, and Q14 deferred encrypted backup to 0.3.0, so a
    /// registration really has no recovery path on this device and the sentence that says
    /// so has to be here rather than in a manual. The closing line is the product one
    /// backup sentence, word for word (copy decision 8).
    fn consequence(&self) -> Vec<String> {
        let slot = match self.info.registrations {
            0 => String::from("This erases the stored wallet slot."),
            1 => String::from(
                "This erases the stored wallet slot and its 1 multisig registration.",
            ),
            n => format!(
                "This erases the stored wallet slot and its {n} multisig registrations."
            ),
        };
        let mut lines = alloc::vec![slot];
        if self.info.registrations > 0 {
            lines.push(String::from(
                "A registration cannot be re-derived from your seed. Import it again from \
                 your other devices.",
            ));
        }
        lines.push(String::from("Your dice rolls or seed words are the only way back."));
        lines
    }

    /// The first sheet: what deleting this wallet destroys, on a sheet with room to say
    /// it. The typed step follows and has a keyboard where this prose would be.
    fn read_sheet(&self) -> Danger {
        let lines = self.consequence();
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        Danger::confirm("Delete this wallet?", &refs, "Continue")
    }

    /// The second sheet: the consent itself.
    ///
    /// The required word is the wallet's own name. A user who cannot type it is not
    /// certain which wallet they are looking at, which is exactly when the device should
    /// not proceed.
    fn type_sheet(&self) -> Danger {
        let lines = self.consequence();
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        Danger::typed(
            &format!("Delete \"{}\"", self.info.name),
            &refs[..1],
            "Delete wallet",
            &self.info.name,
        )
    }
}

/// Height of the identity card: the name, then three rows of paired facts, and its own
/// padding. Four rows rather than three because every row here is a PAIR - a caption on
/// the left and a value on the right - and three rows meant three values sharing a line
/// with a fourth, which is how a fingerprint ends up with its tail under a badge.
const CARD_H: i32 = LINE + 3 * SMALL_LINE + 24;

pub(crate) struct Layout {
    card: Rect,
    /// The action cards that exist on this wallet, in draw and hit-test order. Already
    /// offset by the scroll, so `draw` and `regions` cannot disagree about where a card is.
    actions: Vec<(RegionId, Rect)>,
    lock_chip: Rect,
    /// The band above the actions: the session warning, or the refusal of something this
    /// screen asked for. Present when either has something to say.
    session: Option<Rect>,
    /// How far past the bottom of the body the content runs. Zero on a panel that holds
    /// everything, which is every geometry with fewer than five actions.
    overflow: i32,
}

impl Screen for WalletState {
    type Layout = Layout;

    fn layout(&self, ctx: &Ctx) -> Layout {
        let m = &ctx.m;
        let body = m.body();
        let g = m.gap;
        // Everything below is laid out in CONTENT coordinates - as if the panel were tall
        // enough - and shifted up by the scroll at the end. One computation, one shift, so
        // no rectangle can be drawn at one place and hit-tested at another.
        let card = Rect::new(body.x, body.y, body.w, CARD_H);

        // The band that says nothing was written, or - on a stored wallet - the refusal of
        // a store or forget this screen asked for. It is above the actions, not below
        // them, because either sentence changes what every one of them means.
        //
        // Allocated for EITHER, and that is the whole of this fix. It used to be allocated
        // only for the session case, so a `StorageOutcome::Refused` set `self.notice`,
        // `draw` duly preferred it over the session copy, and the rectangle it would have
        // been drawn in did not exist on the one kind of wallet a storage toggle can be
        // refused for. The user was left looking at a switch that had silently not moved,
        // which is precisely the "toggle that lies" this screen is written against.
        let session = if self.info.stored && self.notice.is_none() {
            None
        } else {
            Some(Rect::new(body.x, card.bottom() + g, body.w, 2 * LINE))
        };
        let top = session.map_or(card.bottom(), |s| s.bottom()) + g;

        let mut ids = Vec::new();
        // Sign leads, because it is what the device is for. It needs BOTH facts, and the
        // second one is the surprising half: signing runs on the std side's seed, and the
        // only seed the std side ever holds is the one it unsealed out of a slot. A "use
        // once, keep nothing" session hands this screen a derivation without ever handing
        // the embedder a seed, so a Sign card there would raise a request that could only
        // be refused - which is the affordance-that-leads-nowhere this screen's whole
        // action list is written against. That is a real gap in 0.2.0 and it is stated
        // here rather than papered over: a stateless signing entry (S-40) is what closes
        // it, and it does not exist yet.
        if self.info.stored && self.report.is_some() {
            ids.push(RegionId::ActSign);
        }
        // Export needs only the derivation, because the keys ARE this screen's state.
        if self.report.is_some() {
            ids.push(RegionId::ActExport);
            ids.push(RegionId::ActReceive);
        }
        if self.info.stored {
            ids.push(RegionId::ActMultisig);
            ids.push(RegionId::ActWords);
        }
        // The storage toggle exists for a STORED wallet that HAS a passphrase, and only
        // while this screen holds the keys - which is the same thing as saying the
        // embedder has the passphrase in hand for this session. Storing what is not in
        // hand would mean asking the user to type it again and storing something nothing
        // has checked; this way what gets written is byte-for-byte what just opened the
        // wallet.
        if self.info.stored && self.info.passphrase.applied() && self.report.is_some() {
            ids.push(RegionId::ActPassphraseStore);
        }
        // Deriving a second wallet is offered on a wallet with NO passphrase, because on
        // one that has a passphrase the same action reads as changing it - and a
        // passphrase is not a setting that can be changed. It needs the keys for the
        // literal reason: the words it derives from are in the report.
        if self.info.stored
            && self.info.passphrase == PassphraseState::None
            && self.report.is_some()
        {
            ids.push(RegionId::ActPassphraseDerive);
        }
        if self.info.stored {
            ids.push(RegionId::WalletDelete);
        }
        let mut actions =
            action_grid(ids, Rect::new(body.x, top, body.w, body.bottom() - top), g);

        // What the panel cannot show, measured from the content rather than assumed from
        // the count: the same five cards fit on the 720x720 panel and do not on the
        // 800x480 one, and neither number belongs in this file.
        let bottom = actions.iter().map(|(_, r)| r.bottom()).max().unwrap_or(body.bottom());
        let overflow = (bottom - body.bottom()).max(0);
        let scroll = self.scroll.clamp(0, overflow);
        let card = card.translated(0, -scroll);
        let session = session.map(|r| r.translated(0, -scroll));
        for (_, r) in &mut actions {
            *r = r.translated(0, -scroll);
        }

        Layout { card, actions, lock_chip: chip(m), session, overflow }
    }

    fn regions(&self, ctx: &Ctx, out: &mut Vec<Region>) {
        // While a sheet is open it is the only thing on the panel: the wallet beneath is
        // as inert to a finger as it is invisible.
        if let Some((_, d)) = &self.danger {
            d.regions(&ctx.m, out);
            return;
        }
        let l = self.layout(ctx);
        let body = ctx.m.body();
        out.push(Region { id: RegionId::Back, rect: back_rect(&ctx.m) });
        if ctx.lock.status == StoreStatus::Unlocked {
            out.push(Region { id: RegionId::Lock, rect: l.lock_chip });
        }
        for (id, rect) in l.actions {
            // Clipped to the body, exactly as the draw is: a card scrolled off the panel
            // is not drawn, so it must not be tappable either, and one that is half on the
            // panel is tappable over the half a finger can see. A rectangle with nothing
            // left of it is no region at all.
            if let Some(visible) = rect.intersection(&body) {
                if visible.h >= TOUCH_MIN {
                    out.push(Region { id, rect: visible });
                }
            }
        }
    }

    fn draw<D: DrawTarget<Color = Rgb565>>(&self, t: &mut D, ctx: &Ctx) -> Result<(), D::Error> {
        let m = &ctx.m;
        if let Some((_, d)) = &self.danger {
            return d.draw(t, m, ctx.press, ctx.hold_released);
        }
        draw_bar(t, m, &self.info.name)?;
        let l = self.layout(ctx);
        if ctx.lock.status == StoreStatus::Unlocked {
            button(t, l.lock_chip, "Lock device", ButtonKind::Secondary, PAPER_2)?;
        }
        // The body scrolls, so everything in it is drawn through the body's own clip: a
        // card dragged past the top or the bottom is cut off at the edge of the content
        // area instead of over the bar. `regions` clips to the same rectangle, which is
        // what keeps "drawn where it can be tapped" true while the content moves.
        let t = &mut t.clipped(&m.body().to_eg());

        // Identity card. Mono for everything a user compares against another device, and
        // every row is a PAIR drawn into its own half, so a long name or a long path
        // crops rather than running under the value beside it.
        fill(t, l.card, PAPER_2)?;
        frame(t, l.card, BORDER_STRONG)?;
        let inner = l.card.inset(m.gap);
        {
            // Scoped: the clip belongs to the card, and the band below it is not part
            // of the card.
            let mut clip = t.clipped(&inner.to_eg());
            pair(
                &mut clip,
                Rect::new(inner.x, inner.y, inner.w, LINE),
                (&self.info.name, HEADING, INK_PRIMARY),
                (self.info.kind.badge(), HEADING, INK_SECONDARY),
                m.gap,
            )?;
            let network =
                if self.info.network == Network::Bitcoin { "mainnet" } else { "TESTNET" };
            // One of exactly three strings, and none of them says ON or off. The row
            // states what a passphrase HAS TO DO with this wallet, which is a property of
            // which wallet this is; the only switch in the vocabulary is whether this
            // device remembers it, and "passphrase stored" is the state that names it.
            // The old row rendered "passphrase off" for a wallet that demonstrably had
            // one, because `false` was the closest the vocabulary came to "not measured".
            let passphrase = self.info.passphrase.row();
            let fingerprint = format!("fingerprint {}", self.info.fingerprint);
            let rows: [(&str, Rgb565, &str); 3] = [
                (&fingerprint, INK_PRIMARY, &self.info.path),
                (&self.info.script_type, INK_SECONDARY, passphrase),
                ("network", INK_SECONDARY, network),
            ];
            for (i, (left, ink, right)) in rows.into_iter().enumerate() {
                let row =
                    Rect::new(inner.x, inner.y + LINE + i as i32 * SMALL_LINE, inner.w, SMALL_LINE);
                pair(
                    &mut clip,
                    row,
                    (left, MONO_SMALL, ink),
                    (right, MONO_SMALL, INK_SECONDARY),
                    m.gap,
                )?;
        }
        }

        // The honest statement about a session wallet, in the words S-21 specifies - or,
        // where something this screen asked for did not happen, what did not happen.
        //
        // The two share ONE band because they are mutually exclusive: a session wallet has
        // no stored record for a storage toggle to refuse, so a notice only ever exists on
        // a stored wallet and the session copy only ever on an unstored one. The refusal
        // wins the band whenever it is present, because it is the newer fact and it is the
        // one the user is waiting for an answer to. `layout` allocates for both, and it
        // has to: this preference is a silent no-op otherwise.
        if let Some(r) = l.session {
            let mut y = r.y;
            let (copy, ink) = match &self.notice {
                Some(why) => (why.as_str(), DANGER),
                None => (
                    "Not stored. Locking or powering off loses this wallet until you \
                     retype the words.",
                    WARNING,
                ),
            };
            for line in wrap_words(copy, r.w, BODY) {
                if y + LINE > r.bottom() {
                    break;
                }
                text(t, &line, r.x, y, BODY, ink, PAPER_1)?;
                y += LINE;
            }
        }

        for (id, rect) in &l.actions {
            let (title, detail, ink) = self.card_copy(*id);
            fill(t, *rect, if ink == DANGER { DANGER_TINT } else { PAPER_2 })?;
            frame(t, *rect, if ink == DANGER { DANGER } else { BORDER_STRONG })?;
            let inner = rect.inset(m.gap);
            let mut clip = t.clipped(&inner.to_eg());
            // BOTH lines at CAPTION, separated by INK rather than by size. A card is a
            // control, not a page: its height is set by the finger and the panel - four
            // cards under the identity card on an 800x480 leaves 88 px each and 62 px
            // inside - and the page has no more room to give it. HEADING over BODY is 84 px
            // of type in that 62 px, so the second line, the one that says what the tap
            // costs, could not be drawn at all. At 24 px the pair is 62 px exactly and both
            // lines are there on every panel. INK_PRIMARY over INK_SECONDARY is what makes
            // the title read as the title, which is the distinction the type scale already
            // draws for hints.
            //
            // The clip is why nobody saw the old overflow: a label wider or taller than its
            // card is truncated INSIDE the card, so it never draws off-panel and the bounds
            // gate stays green. Only the measured fit test below sees it.
            //
            // Advance by the FONT'S own line height, not by LINE/SMALL_LINE. Those two are
            // the page rhythm - the spacing between rows of a screen - and a card sets its
            // own leading from the glyphs it actually draws.
            text(&mut clip, title, inner.x, inner.y, CAPTION, ink, PAPER_2)?;
            let mut y = inner.y + CAPTION.line_height as i32;
            for line in wrap_words(detail, inner.w, CAPTION) {
                // A FLOOR, not the mechanism. Nothing is expected to trip this any more -
                // every card at every shipped geometry holds its whole detail line at
                // CAPTION, and `every_action_card_holds_the_copy_it_draws` asserts that
                // NOTHING is omitted. It stays because a truncated descriptor is worse than
                // an absent one: 'load a PSBT from the ca' reads as a rendering fault and
                // teaches the user to distrust the screen, so if a future panel or a longer
                // string ever does overrun, the card must lose the line cleanly and the test
                // must be the thing that shouts.
                if y + CAPTION.line_height as i32 > inner.bottom() {
                    break;
                }
                text(&mut clip, &line, inner.x, y, CAPTION, INK_SECONDARY, PAPER_2)?;
                y += CAPTION.line_height as i32;
            }
        }

        // C2: a drag with nothing marking it is undiscoverable, so a wallet whose actions
        // run past the panel says so, in the same chip S-30, S-38, S-42 and C7 use. Both
        // edges, because the identity card scrolls too and a screen that can be scrolled
        // BACK has to say that as well.
        let body = m.body();
        if l.overflow > 0 {
            if self.scroll < l.overflow {
                marker(t, "more below", body, false)?;
            }
            if self.scroll > 0 {
                marker(t, "more above", body, true)?;
            }
        }
        Ok(())
    }

    fn activate(&mut self, id: RegionId, _env: &mut Env) -> Outcome {
        // A sheet, while open, answers for the whole screen.
        if let Some((consent, d)) = &mut self.danger {
            let consent = *consent;
            // A CONSEQUENCE that has been read, as distinct from consent that has been
            // given: two of the three sequences here have a second sheet behind the first,
            // and the grade is what says which step this is.
            let reading = d.grade() == DangerGrade::Confirm;
            let outcome = d.activate(id);
            // Storing is one step: the sheet states what it costs and the confirm IS the
            // answer, because turning it off again is a control on this same screen.
            if let (DangerOutcome::Confirmed, Consent::StorePassphrase) = (outcome, consent) {
                self.danger = None;
                self.notice = None;
                return Outcome::ask(UiRequest::StorePassphrase(self.info.slot));
            }
            if let (DangerOutcome::Confirmed, Consent::ViewWords) = (outcome, consent) {
                self.danger = None;
                return Outcome::ask(UiRequest::RecoveryWords(self.info.slot));
            }
            // Forgetting is two: the consequence, then the hold that performs it.
            if let (DangerOutcome::Confirmed, Consent::ForgetPassphrase, false) =
                (outcome, consent, reading)
            {
                self.danger = None;
                self.notice = None;
                return Outcome::ask(UiRequest::ForgetPassphrase(self.info.slot));
            }
            return match outcome {
                DangerOutcome::Open | DangerOutcome::Alternative => Outcome::stay(),
                DangerOutcome::Cancelled => {
                    self.danger = None;
                    Outcome::stay()
                }
                // The consequence has been read; what follows is the consent, at the grade
                // this action earns - a typed name for a delete, a hold for a forget.
                DangerOutcome::Confirmed if reading && consent == Consent::ForgetPassphrase => {
                    self.danger = Some((consent, self.forget_hold_sheet()));
                    Outcome::stay()
                }
                DangerOutcome::Confirmed if reading => {
                    self.danger = Some((Consent::Delete, self.type_sheet()));
                    Outcome::stay()
                }
                // Consent is complete and the erase does NOT happen here. S-47b comes
                // next: the last moment these words exist on the device, and the offer to
                // read them once more before they do not. Nothing is written until a card
                // over there is tapped, and that screen announces what the write is.
                //
                // ENTERED, not pushed, and that is a wipe rather than a routing
                // preference: entering REPLACES this screen, so the derivation it may be
                // holding is dropped here - at the moment the user commits to the
                // last-words step - instead of sitting in the back stack behind the erase
                // of the very wallet it belongs to. Back from the offer is then the wallet
                // list, which is where a delete ends anyway.
                //
                // It also puts the destructive answer in the BODY of a screen rather than
                // at the coordinates this sheet's confirm occupied a frame earlier: a
                // second tap on an armed confirm is precisely how somebody answers a
                // device that appeared to do nothing, which is the report this whole flow
                // exists to answer.
                DangerOutcome::Confirmed => Outcome::enter(State::Erase(EraseState::new(
                    self.info.slot,
                    &self.info.name,
                    self.info.registrations,
                ))),
            };
        }
        match id {
            // One call returns the whole Outcome - the push AND the card read that ends
            // the Busy frame it lands on - so the two cannot be got wrong separately.
            RegionId::ActSign => crate::screens::sdcard::SignSourceState::open(),
            // Export moves the derivation on: the schemes screen becomes the owner of the
            // keys, and this screen must not keep a second copy of them. It is handed this
            // wallet's identity with them, which is what lets its Back rebuild this screen
            // WITH its keys - a wallet returned to without them has lost Export and Sign.
            RegionId::ActExport => match self.report.take() {
                Some(report) => Outcome::enter(State::Schemes(SchemesState::new(
                    report,
                    SchemesOrigin::Wallet(self.info.clone()),
                ))),
                None => Outcome::stay(),
            },
            // Pushed, so Back from the registry returns to the wallet it belongs to
            // rather than to whatever the stack happened to hold.
            RegionId::ActMultisig => {
                Outcome::push(State::MultisigList(MultisigListState::new(&self.info)))
            }
            RegionId::ActReceive => match &self.report {
                Some(r) => match super::receive::ReceiveState::new(r) {
                    Some(rs) => Outcome::push(State::Receive(rs)),
                    None => Outcome::stay(),
                },
                None => Outcome::stay(),
            },
            RegionId::ActWords => {
                self.notice = None;
                self.danger = Some((Consent::ViewWords, self.words_sheet()));
                Outcome::stay()
            }
            RegionId::WalletDelete => {
                self.notice = None;
                self.danger = Some((Consent::Delete, self.read_sheet()));
                Outcome::stay()
            }
            // One row, two directions, and the state of the wallet decides which sheet
            // opens. Storing is a C4b confirm; forgetting is a C4c hold.
            RegionId::ActPassphraseStore => {
                self.notice = None;
                self.danger = Some(match self.info.passphrase {
                    PassphraseState::Stored => (Consent::ForgetPassphrase, self.forget_sheet()),
                    _ => (Consent::StorePassphrase, self.store_sheet()),
                });
                Outcome::stay()
            }
            // A creation, never a modification. This wallet is not touched: the words go
            // into the same passphrase entry the create flow uses, and what comes out the
            // far end is a NEW record in a NEW slot with its own label and its own
            // fingerprint. Entered rather than pushed, so this screen and the derivation
            // it holds are dropped here - the passphrase screen gets its own copy of the
            // words and there is no second one behind it.
            RegionId::ActPassphraseDerive => match &self.report {
                Some(report) => Outcome::enter(State::Passphrase(PassState::deriving_from(
                    &report.phrase,
                    &self.info.name,
                ))),
                None => Outcome::stay(),
            },
            RegionId::Lock => Outcome::ask(UiRequest::LockSession),
            _ => Outcome::stay(),
        }
    }

    /// What became of a change to whether this device remembers the passphrase.
    ///
    /// The row re-renders from the state the embedder READ BACK out of the record, never
    /// from what the user asked for: this is the one control on the screen whose whole
    /// subject is what the flash says, and a toggle that showed the intent would be a
    /// switch that lies about it. A refusal changes nothing and says so in the band.
    fn answered(&mut self, answer: Answer, _env: &mut Env) -> Outcome {
        match answer {
            Answer::PassphraseStorage(StorageOutcome::Now(state)) => {
                self.info.passphrase = state;
                self.notice = None;
            }
            Answer::PassphraseStorage(StorageOutcome::Refused(why)) => self.notice = Some(why),
            Answer::RecoveryWords(WordsOutcome::Words(_)) => {
                // The words were shown on the mnemonic screen opened by the firmware.
                // Nothing more to do here - the user has seen them and we stay.
            }
            Answer::RecoveryWords(WordsOutcome::Refused(why)) => {
                self.notice = Some(why);
            }
            _ => {}
        }
        Outcome::stay()
    }

    fn scroll_mut(&mut self) -> Option<&mut i32> {
        // Frozen under a sheet: the sheet is modal, and a screen that scrolled behind one
        // would move the content the consequence is about.
        if self.danger.is_some() {
            return None;
        }
        Some(&mut self.scroll)
    }

    /// Measured from the same layout that paints, so the clamp cannot drift from the
    /// rendering - and zero on every panel and every wallet that fits, which is most of
    /// them.
    ///
    /// `overflow` is computed from the content BEFORE the scroll is applied to it, which
    /// is what stops the limit chasing the offset.
    fn scroll_limit(&self, ctx: &Ctx) -> i32 {
        self.layout(ctx).overflow
    }

    /// A session wallet's keys live ONLY on this screen, so Back asks first: leaving
    /// discards the one copy of a wallet that was never written to a slot. A stored
    /// wallet's keys are not at risk the same way - the record survives in flash whether
    /// or not this screen is holding a derivation of it - so Back moves straight to the
    /// list, the same distinction the schemes screen's `Origin` draws between an Export
    /// that returns to a wallet still on the device and one with nothing behind it.
    ///
    /// `report.is_some()` alone used to decide this, which reads as "does this screen
    /// hold keys" rather than "would leaving lose something" - and the embedder hands a
    /// stored wallet its derivation too (`Ui::wallet_opened_with_keys`), so opening ANY
    /// stored wallet with its keys already unsealed raised the same "clear work?" modal a
    /// truly unstored session earns, over a record that was never at risk.
    fn back(&self) -> Nav {
        if self.report.is_some() && !self.info.stored {
            Nav::ConfirmExit
        } else {
            Nav::Back
        }
    }
}

/// Lay the action cards out in `room`, in one column while that fits and in two when it
/// does not.
///
/// A card is a TARGET with two lines of copy in it, so the thing that may not give way is
/// its height: [`LIST_ROW_MIN`] is the floor, and a card squeezed under it is a control
/// whose second line - the one saying what the tap costs - is cut off. What gives way is
/// the number of COLUMNS. The 800x480 panel has 190 px under the identity card, which holds
/// two cards and not three, and a wallet that is both stored and unsealed has three.
///
/// A row holding one card takes the full width. That is not only tidiness: the odd card out
/// is the last one, the last one is Delete, and a full-width danger card alone on the
/// bottom row is the shape the rest of the product gives a destructive action.
fn action_grid(ids: Vec<RegionId>, room: Rect, g: i32) -> Vec<(RegionId, Rect)> {
    let n = ids.len().max(1) as i32;
    let single = n * LIST_ROW_MIN + (n - 1) * g <= room.h;
    let cols = if single { 1 } else { 2 };
    let rows = (n + cols - 1) / cols;
    let row_h = ((room.h - (rows - 1) * g) / rows).clamp(LIST_ROW_MIN, 140);
    let col_w = (room.w - (cols - 1) * g) / cols;
    let last_row_len = n - (rows - 1) * cols;
    ids.into_iter()
        .enumerate()
        .map(|(i, id)| {
            let (row, col) = (i as i32 / cols, i as i32 % cols);
            let alone = row == rows - 1 && last_row_len == 1;
            let w = if alone { room.w } else { col_w };
            (id, Rect::new(room.x + col * (col_w + g), room.y + row * (row_h + g), w, row_h))
        })
        .collect()
}

/// One row of the identity card: a value on the left, a value on the right, each clipped
/// to the half the other one leaves it.
///
/// The right value is measured first and the left gets what remains, so the pair can never
/// overlap however long a user names a wallet or however wide a path runs. Cropping the
/// left is the right way round: what a reader compares against another device - the
/// fingerprint, the badge, the network - is on the side that keeps its full width.
fn pair<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    row: Rect,
    left: (&str, &'static Atlas, Rgb565),
    right: (&str, &'static Atlas, Rgb565),
    gap: i32,
) -> Result<(), D::Error> {
    let rw = right.1.text_width(right.0) as i32;
    text(t, right.0, row.right() - rw, row.y, right.1, right.2, PAPER_2)?;
    let room = Rect::new(row.x, row.y, (row.w - rw - gap).max(0), row.h);
    let mut clip = t.clipped(&room.to_eg());
    text(&mut clip, left.0, room.x, room.y, left.1, left.2, PAPER_2)?;
    Ok(())
}

/// Title, secondary line and ink for an action card. One table, so a card cannot be drawn
/// with copy that disagrees with what its region does - and the secondary line says what
/// the tap COSTS, which is the part a user cannot see from the title.
///
/// The budget is ONE [`CAPTION`] line inside the card, which is 341 px on the narrowest
/// panel. That makes every entry here a fragment rather than a sentence, and it is a
/// budget to write to rather than one to escape: a second line does not fit at any size
/// worth reading, so copy that overruns gets shortened instead. "registered wallets,
/// import a descriptor" (413 px) became "registrations, import one" (266 px) for exactly
/// that reason - it names the same two things, which is all the card ever promised.
fn action_copy(id: RegionId) -> (&'static str, &'static str, Rgb565) {
    match id {
        RegionId::ActSign => ("Sign a transaction", "load a PSBT from the card", INK_PRIMARY),
        RegionId::ActExport => ("Export public keys", "xpub, descriptor, QR", INK_PRIMARY),
        RegionId::ActReceive => ("Receive", "next address + QR", INK_PRIMARY),
        RegionId::ActMultisig => ("Multisig", "registrations, import one", INK_PRIMARY),
        RegionId::ActPassphraseDerive => (
            "Add a passphrase",
            "makes a different wallet",
            INK_PRIMARY,
        ),
        RegionId::ActWords => ("View recovery words", "reveal the seed phrase", INK_PRIMARY),
        RegionId::WalletDelete => ("Delete this wallet", "type the name to confirm", DANGER),
        _ => ("", "", INK_PRIMARY),
    }
}

/// What storing the passphrase costs, on the C4b sheet that offers it.
///
/// Two dangers, and they are the two that are true whichever way the toggle goes. The
/// first is what the owner asked to have said: anyone with the PIN then has the
/// passphrase, so it stops being a second factor. The second is the one that actually
/// loses coins and is easiest to misread from a device that says it remembers something -
/// remembered HERE is not backed up here.
///
/// A named constant so the copy gate can read it: what a sheet says at the moment of
/// consent is the security property, and it is not checkable from a framebuffer.
const STORE_DANGERS: [&str; 2] = [
    "Anyone who knows this device's PIN can then spend from this wallet. The passphrase \
     stops being a second lock.",
    "If this device is lost, your seed words alone restore a DIFFERENT wallet. Write the \
     passphrase down and keep it apart from the words.",
];

/// What forgetting it costs, on the C4c sheet that offers that.
///
/// Named after the wallet, because "you must type it to open THIS" is the sentence that
/// makes the consequence concrete, and because the device can never show the passphrase
/// back - which is what makes this a hold rather than a tap.
/// The one line the hold sheet has room for.
///
/// ONE line, and it is measured rather than chosen: the C4c bar has a 120 px physical
/// minimum, and what is left of the 800x480 sheet after the title, the bar and the cancel
/// is 64 px - a single line at the body face. The consequence in full was read on the
/// sheet before this one, which is why this can be the shortest true sentence rather than
/// a summary of it.
const FORGET_HOLD: &str = "This cannot be undone.";

fn forget_consequence(name: &str) -> Vec<String> {
    alloc::vec![
        format!(
            "This device will forget the passphrase and will never show it to you. From \
             the next unlock you must type it to open \"{name}\"."
        ),
        String::from("If it is not written down, do not do this."),
    ]
}

/// The storage row's copy, which is the one card on this screen whose words depend on the
/// state it is in. Kept beside [`action_copy`] rather than inside it because that table's
/// contract is that a region has ONE label - a lookup that could return two would let a
/// card be drawn in the state it is not in.
fn storage_copy(state: PassphraseState) -> (&'static str, &'static str, Rgb565) {
    match state {
        // The destructive direction gets the danger ink: this device forgets a secret it
        // can never show back.
        PassphraseState::Stored => (
            "Forget the passphrase",
            "type it at each unlock",
            DANGER,
        ),
        _ => (
            "Remember the passphrase",
            "this device stores it",
            INK_PRIMARY,
        ),
    }
}

#[cfg(test)]
mod tests {
    use crate::UnlockGate;
    use super::*;
    use crate::screens::testing::{Fixture, GEOMETRIES};
    use crate::WalletKind;
    use crate::BackupState;

    /// THE COPY GATE. What this screen may say about a passphrase, and what it may never
    /// say.
    ///
    /// Asserted over the copy rather than over the pixels, because a framebuffer cannot be
    /// searched for a word - and every one of these is a security property rather than a
    /// preference:
    ///
    /// - The identity row is exactly one of three strings, and none of them is a switch.
    ///   "off" implies a passphrase this wallet could be given, and a passphrase is not a
    ///   setting of a wallet: the same words under a different passphrase are a DIFFERENT
    ///   wallet. The row this replaces read `passphrase off` for a wallet that
    ///   demonstrably had one.
    /// - The one control that IS a switch names STORAGE, never the passphrase.
    /// - The derive action says what it makes, in the words that stop it reading as a
    ///   change to the wallet the user is looking at.
    /// - Both consent sheets carry the dangers the owner asked for AND the one that
    ///   actually loses coins: a device is not a backup.
    #[test]
    fn the_copy_can_never_read_as_a_passphrase_toggle_of_this_wallet() {
        const STATES: [PassphraseState; 3] =
            [PassphraseState::None, PassphraseState::Required, PassphraseState::Stored];

        // 1. The identity row.
        for state in STATES {
            let row = state.row();
            assert!(
                ["no passphrase", "passphrase required", "passphrase stored"].contains(&row),
                "{state:?} renders {row:?}, which is not one of the three"
            );
        }

        // 2. Nothing this screen draws about a passphrase reads as ON or off.
        let mut copy: Vec<String> = Vec::new();
        for state in STATES {
            copy.push(String::from(state.row()));
            let (title, detail, _) = storage_copy(state);
            copy.push(String::from(title));
            copy.push(String::from(detail));
        }
        for id in [
            RegionId::ActSign,
            RegionId::ActExport,
            RegionId::ActMultisig,
            RegionId::ActWords,
            RegionId::ActPassphraseDerive,
            RegionId::WalletDelete,
        ] {
            let (title, detail, _) = action_copy(id);
            copy.push(String::from(title));
            copy.push(String::from(detail));
        }
        copy.extend(STORE_DANGERS.iter().map(|s| String::from(*s)));
        copy.extend(forget_consequence("savings"));
        for line in &copy {
            for banned in ["passphrase ON", "passphrase off", "Passphrase ON", "passphrase: on"]
            {
                assert!(!line.contains(banned), "{line:?} reads as an on/off toggle");
            }
        }

        // 3. The switch names storage, and the derive action names what it makes.
        assert!(storage_copy(PassphraseState::Required).0.contains("Remember"));
        assert!(storage_copy(PassphraseState::Stored).0.contains("Forget"));
        let (_, derive, _) = action_copy(RegionId::ActPassphraseDerive);
        assert!(derive.contains("different wallet"), "{derive:?}");

        // 4. The sheets. Danger (a) is the owner's first, (c) is the one that loses coins.
        let store = STORE_DANGERS.join(" ");
        assert!(store.contains("PIN can then spend"), "danger (a) is missing: {store}");
        assert!(store.contains("second lock"), "{store}");
        assert!(store.contains("DIFFERENT wallet"), "danger (c) is missing: {store}");
        assert!(store.contains("keep it apart from the words"), "{store}");
        let forget = forget_consequence("savings").join(" ");
        assert!(forget.contains("never show it to you"), "danger (b) is missing: {forget}");
        assert!(forget.contains("\"savings\""), "the sheet names the wallet: {forget}");
        assert!(forget.contains("If it is not written down"), "{forget}");
    }

    /// Both consent sheets fit the panel they are drawn on, on both geometries.
    ///
    /// `danger.rs` puts this obligation on the caller in as many words: there is no scroll
    /// and no ellipsis behind a consequence, so the prose either fits or it is silently cut
    /// off at the one moment the product most needs it read.
    #[test]
    fn the_passphrase_sheets_fit_both_panels() {
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            let mut info = info(true);
            info.name = String::from("a wallet with a long name");
            for state in [PassphraseState::Required, PassphraseState::Stored] {
                info.passphrase = state;
                let s = WalletState::new(info.clone(), Some(report()));
                for sheet in [s.store_sheet(), s.forget_sheet(), s.forget_hold_sheet()] {
                    let (used, have) = sheet.text_budget(&f.m);
                    assert!(
                        sheet.fits(&f.m),
                        "{w}x{h}: a {state:?} sheet needs {used} px and has {have}"
                    );
                }
                let sheet = match state {
                    PassphraseState::Stored => s.forget_sheet(),
                    _ => s.store_sheet(),
                };
                let (used, have) = sheet.text_budget(&f.m);
                assert!(
                    sheet.fits(&f.m),
                    "{w}x{h}: the {state:?} sheet needs {used} px and has {have}"
                );
            }
        }
    }

    /// Every action card holds the copy it draws, at every shipped geometry - and draws
    /// ALL of it.
    ///
    /// The card draws through a CLIP (`t.clipped(&inner.to_eg())` in `draw`), so a label
    /// wider or taller than its card is not an overflow the graphics gate can see - it is
    /// silently truncated inside the card's own rectangle, on the glass, where only a
    /// person looking at the device finds it. That is exactly how this shipped: the bounds
    /// gate was green the whole time. `lock.rs` has carried the same assertion since the
    /// 800x480 lock screen lost its unlock hint; the action cards never got one.
    ///
    /// Two properties, and the second is the one the CAPTION face was added to buy: what
    /// is drawn fits, AND nothing is left undrawn. The omit-rule in `draw` is a floor under
    /// a future mistake, so this test has to fail if it ever becomes the mechanism again.
    #[test]
    fn every_action_card_holds_the_copy_it_draws() {
        // Collected rather than asserted per line: one assert per card reports the first
        // offender and hides the rest, and the point of this test is to see the whole
        // screen at once on a panel nobody is holding.
        let mut bad: Vec<String> = Vec::new();
        // Cards that would drop a detail line. Asserted EMPTY: a card silently losing the
        // line that says what the tap costs is the defect this screen was fixed for.
        let mut omitted: Vec<String> = Vec::new();
        for (w, h) in GEOMETRIES {
            let mut f = Fixture::new(w, h);
            f.wallets.clear();
            let s = WalletState::new(info(true), Some(report()));
            let l = s.layout(&f.ctx());
            for (id, rect) in &l.actions {
                let inner = rect.inset(f.m.gap);
                let (title, detail, _) = s.card_copy(*id);
                let tw = CAPTION.text_width(title) as i32;
                if tw > inner.w {
                    bad.push(format!(
                        "{w}x{h} {id:?} title: {title:?} needs {tw} px in {} px",
                        inner.w
                    ));
                }
                // The detail wraps, so width alone is not the question: every wrapped line
                // must fit the width AND the wrapped block must fit the height under the
                // title. A card that clips vertically hides its last line just as quietly
                // as one that clipped horizontally did.
                let lines = wrap_words(detail, inner.w, CAPTION);
                for line in &lines {
                    let lw = CAPTION.text_width(line) as i32;
                    if lw > inner.w {
                        bad.push(format!(
                            "{w}x{h} {id:?} detail line: {line:?} needs {lw} px in {} px",
                            inner.w
                        ));
                    }
                }
                // Mirror the draw rule: count the lines that actually get drawn, and assert
                // the title itself fits. A card too short even for its TITLE is a defect the
                // omit-rule cannot rescue, and that is what this catches.
                let mut drawn = 0usize;
                let mut y = CAPTION.line_height as i32;
                for _ in &lines {
                    if y + CAPTION.line_height as i32 > inner.h {
                        break;
                    }
                    drawn += 1;
                    y += CAPTION.line_height as i32;
                }
                if CAPTION.line_height as i32 > inner.h {
                    bad.push(format!(
                        "{w}x{h} {id:?}: the title alone needs {} px in a {} px card",
                        CAPTION.line_height,
                        inner.h
                    ));
                }
                if drawn < lines.len() {
                    omitted.push(format!(
                        "{w}x{h} {id:?}: {detail:?} wraps to {} line(s) and {drawn} fit a {} \
                         px card",
                        lines.len(),
                        inner.h
                    ));
                }
            }
        }
        assert!(
            bad.is_empty(),
            "action card copy does not fit:\n  {}",
            bad.join("\n  ")
        );
        assert!(
            omitted.is_empty(),
            "action cards would drop copy - shorten the copy, do not shrink the face:\n  \
             {}",
            omitted.join("\n  ")
        );
    }
    fn info(stored: bool) -> WalletInfo {
        WalletInfo {
            slot: 3,
            name: String::from("savings"),
            fingerprint: String::from("a1b2c3d4"),
            path: String::from("m/84'/0'/0'"),
            script_type: String::from("native segwit"),
            kind: WalletKind::SingleSig,
            backup: BackupState::Verified(String::new()),
            network: Network::Bitcoin,
            registrations: 0,
            stored,
            passphrase: PassphraseState::None,
        }
    }

    /// The 12-word all-`abandon` vector, so a test can hold a real derivation without
    /// inventing one. Public knowledge and worthless by construction.
    const TEST_PHRASE: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon about";

    /// A derivation, for the cases that turn on this screen holding one.
    fn report() -> Report {
        use notyas_core::derive::{ChildIndex, Scheme};
        use notyas_core::bip39::MnemonicMode;
        use notyas_core::report::Parameters;
        Report::from_phrase(
            TEST_PHRASE,
            &Parameters {
                mode: MnemonicMode::Raw,
                passphrase: "",
                network: Network::Bitcoin,
                schemes: &Scheme::ALL,
                account: ChildIndex::ZERO,
                change: ChildIndex::ZERO,
                count: crate::ADDRESS_ROWS,
                script_type: 2,
            },
        )
        .expect("a phrase with words in it derives")
    }

    /// Every action card is a full-width target on its floor, below the identity card,
    /// clear of the session band that changes what it means - and REACHABLE.
    ///
    /// All four combinations of the two INDEPENDENT facts this screen lays out from:
    /// whether the store holds the wallet, and whether the embedder handed over its keys.
    /// The one that used to be unreachable - a stored wallet with keys, which is what the
    /// PIN protects - is also the one carrying the most cards, and therefore the tightest
    /// fit.
    ///
    /// Reachability is the property that replaced "everything is on one screenful", and it
    /// is checked the way a finger would: through `regions`, which clips to the body, at
    /// the top of the scroll and at the bottom of it. A card that no offset makes tappable
    /// is a control that does not exist, and that is what this refuses - not the existence
    /// of an offset.
    #[test]
    fn every_action_card_is_reachable_and_clear_of_the_identity_card() {
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            let ctx = f.ctx();
            for stored in [false, true] {
                for keys in [false, true] {
                    for passphrase in
                        [PassphraseState::None, PassphraseState::Required, PassphraseState::Stored]
                    {
                        let mut i = info(stored);
                        i.passphrase = passphrase;
                        let mut s = WalletState::new(i, keys.then(report));
                        let what = format!(
                            "{w}x{h} stored={stored} keys={keys} passphrase={passphrase:?}"
                        );
                        let l = s.layout(&ctx);
                        let body = f.m.body();
                        for (id, r) in &l.actions {
                            assert!(
                                r.h >= LIST_ROW_MIN && r.w >= TOUCH_MIN,
                                "{what}: {id:?} is {}x{}",
                                r.w,
                                r.h
                            );
                            assert!(
                                r.y >= l.card.bottom(),
                                "{what}: {id:?} at {r:?} is over the identity card"
                            );
                            if let Some(band) = l.session {
                                assert!(
                                    !r.overlaps(&band),
                                    "{what}: {id:?} overlaps the session band"
                                );
                            }
                        }
                        for (i, (_, a)) in l.actions.iter().enumerate() {
                            for (_, b) in &l.actions[i + 1..] {
                                assert!(!a.overlaps(b), "{what}: {a:?} overlaps {b:?}");
                            }
                        }

                        // Every card is tappable at one of the two ends of the scroll, and
                        // every region that IS offered is on the panel.
                        let wanted: Vec<RegionId> = l.actions.iter().map(|(id, _)| *id).collect();
                        let limit = s.scroll_limit(&ctx);
                        let mut reachable: Vec<RegionId> = Vec::new();
                        for offset in [0, limit] {
                            s.scroll = offset;
                            let mut out = Vec::new();
                            s.regions(&ctx, &mut out);
                            for region in out {
                                assert!(
                                    region.rect.y >= 0
                                        && region.rect.bottom() <= f.m.h
                                        && region.rect.x >= 0
                                        && region.rect.right() <= f.m.w,
                                    "{what}: {:?} at {:?} is off the panel",
                                    region.id,
                                    region.rect
                                );
                                if wanted.contains(&region.id) {
                                    assert!(
                                        region.rect.bottom() <= body.bottom()
                                            && region.rect.y >= body.y,
                                        "{what}: {:?} at {:?} escapes the body",
                                        region.id,
                                        region.rect
                                    );
                                    reachable.push(region.id);
                                }
                            }
                        }
                        for id in wanted {
                            assert!(
                                reachable.contains(&id),
                                "{what}: {id:?} is drawn and no scroll offset makes it \
                                 tappable"
                            );
                        }
                        s.scroll = 0;
                    }
                }
            }
        }
    }

    /// A wallet the PIN protects can do more than be deleted - as long as the embedder
    /// hands its keys over.
    ///
    /// This is the whole of the stored-wallet gap in one assertion. The UI owns no key
    /// ladder, so what a stored wallet can DO is decided entirely by whether the answer to
    /// [`crate::UiRequest::OpenWallet`] carried a derivation: without one the identical
    /// wallet offers Delete and nothing else, and everything S-26 reaches - the account
    /// xpub, the descriptor, the receive addresses, their QR codes - is behind the card
    /// this proves appears.
    #[test]
    fn a_stored_wallet_exports_exactly_when_its_keys_were_handed_over() {
        let f = Fixture::new(720, 720);
        let ctx = f.ctx();
        let offered = |s: &WalletState| {
            let mut out = Vec::new();
            s.regions(&ctx, &mut out);
            out.iter().map(|r| r.id).collect::<Vec<_>>()
        };
        let bare = offered(&WalletState::new(info(true), None));
        assert!(!bare.contains(&RegionId::ActExport), "no keys, no export");
        assert!(bare.contains(&RegionId::WalletDelete));

        let opened = offered(&WalletState::new(info(true), Some(report())));
        assert!(opened.contains(&RegionId::ActExport), "an unsealed wallet can export");
        assert!(opened.contains(&RegionId::WalletDelete), "and is still deletable");
    }

    /// Sign is the ingress path, and it is offered on exactly the same evidence Export is:
    /// the embedder handed this screen a derivation, which is the only proof the UI has
    /// that the std side is still holding the seed the review engine needs.
    ///
    /// The tap must produce BOTH halves of the outcome. A push with no request behind it
    /// lands the user on a Busy frame nothing will ever answer, which is the exact defect
    /// the 0.2.0 request/answer vocabulary exists to make impossible.
    #[test]
    fn signing_is_offered_with_the_keys_and_asks_for_the_card() {
        let f = Fixture::new(720, 720);
        let ctx = f.ctx();
        let offered = |s: &WalletState| {
            let mut out = Vec::new();
            s.regions(&ctx, &mut out);
            out.iter().any(|r| r.id == RegionId::ActSign)
        };
        assert!(!offered(&WalletState::new(info(true), None)), "no keys, no signing");
        assert!(offered(&WalletState::new(info(true), Some(report()))));
        assert!(
            !offered(&WalletState::new(info(false), Some(report()))),
            "a session wallet's seed never reached the embedder, so it cannot sign"
        );

        let mut network = Network::Bitcoin;
        let mut env = Env {
            network: &mut network,
            lock: &f.lock,
            wallets: &f.wallets,
            gate: &mut UnlockGate::default(),
        };
        let mut s = WalletState::new(info(true), Some(report()));
        let outcome = s.activate(RegionId::ActSign, &mut env);
        assert!(matches!(outcome.nav, Nav::Push(State::SignSource(_))), "Sign opens S-27");
        assert!(
            matches!(outcome.request, Some(UiRequest::ListCard { .. })),
            "S-27 must arrive with the card read that ends its Busy frame"
        );
        assert!(s.report.is_some(), "signing needs the seed on the std side, not the report");
    }

    /// Export hands the derivation ON rather than copying it: the wallet home must not
    /// keep a second copy of the keys once the schemes screen owns them.
    #[test]
    fn exporting_moves_the_keys_out_of_this_screen() {
        let f = Fixture::new(720, 720);
        let mut network = Network::Bitcoin;
        let mut env = Env {
            network: &mut network,
            lock: &f.lock,
            wallets: &f.wallets,
            gate: &mut UnlockGate::default(),
        };
        let mut s = WalletState::new(info(true), Some(report()));
        let outcome = s.activate(RegionId::ActExport, &mut env);
        assert!(matches!(outcome.nav, Nav::Enter(State::Schemes(_))), "export opens S-26");
        assert!(s.report.is_none(), "the wallet home kept a second copy of the keys");
    }

    /// Delete is offered for a stored wallet and for nothing else: there is no slot to
    /// erase behind a session wallet, and a button that erased nothing would be a lie
    /// about what the device just did.
    #[test]
    fn only_a_stored_wallet_can_be_deleted() {
        let f = Fixture::new(720, 720);
        let ctx = f.ctx();
        let has = |s: &WalletState| {
            let mut out = Vec::new();
            s.regions(&ctx, &mut out);
            out.iter().any(|r| r.id == RegionId::WalletDelete)
        };
        assert!(has(&WalletState::new(info(true), None)));
        assert!(!has(&WalletState::new(info(false), None)));
    }

    /// A stored wallet whose passphrase storage was REFUSED, ready to lay out. The two
    /// things that put the band on the panel, in one place, so the geometry assertions
    /// below cannot drift from the flow assertions above them.
    fn refused_wallet(why: &str) -> WalletState {
        let mut i = info(true);
        i.passphrase = PassphraseState::Required;
        let mut s = WalletState::new(i, Some(report()));
        s.notice = Some(String::from(why));
        s
    }

    /// The identity row renders what the FLASH said, and a refusal is visible.
    ///
    /// Two halves of one property, and the second is the one that shipped broken. The row
    /// moves only for `Now`, because the record read back is the only evidence the device
    /// has about its own storage; and a `Refused` has to reach the glass, because a
    /// refused write that says nothing leaves a user in front of a switch that did not
    /// move, with no way to tell a refusal from a device that ignored the tap.
    ///
    /// Broken version: the code as it stood before 2026-08-19 - `layout` allocating the
    /// band only for `!self.info.stored`. Everything down to the band assertion passes,
    /// `draw` still prefers the notice, and the notice is drawn into a rectangle that does
    /// not exist. That is the failure this test is the pin for.
    #[test]
    fn the_row_reads_the_flash_not_the_intent() {
        for (w, h) in GEOMETRIES {
            let mut f = Fixture::new(w, h);
            let what = format!("{w}x{h}");

            // A write that landed moves the row to what the record now says, and clears
            // any refusal still on the panel.
            let mut i = info(true);
            i.passphrase = PassphraseState::Required;
            let mut s = WalletState::new(i, Some(report()));
            s.notice = Some(String::from("an older refusal"));
            s.answered(
                Answer::PassphraseStorage(StorageOutcome::Now(PassphraseState::Stored)),
                &mut f.env(),
            );
            assert_eq!(s.info.passphrase, PassphraseState::Stored, "{what}");
            assert!(s.notice.is_none(), "{what}: a success leaves no refusal on the panel");
            assert!(s.layout(&f.ctx()).session.is_none(), "{what}: and no band either");

            // A refusal moves NOTHING about the wallet, and says so.
            let why = "The record could not be re-sealed. Nothing was changed.";
            let mut s = WalletState::new(
                {
                    let mut i = info(true);
                    i.passphrase = PassphraseState::Required;
                    i
                },
                Some(report()),
            );
            s.answered(
                Answer::PassphraseStorage(StorageOutcome::Refused(String::from(why))),
                &mut f.env(),
            );
            assert_eq!(
                s.info.passphrase,
                PassphraseState::Required,
                "{what}: a refusal must not move the row"
            );
            assert_eq!(s.notice.as_deref(), Some(why), "{what}");

            // ...on the panel. The band exists, it is inside the body, and no action card
            // is drawn over it.
            let ctx = f.ctx();
            let l = s.layout(&ctx);
            let band = l.session.unwrap_or_else(|| {
                panic!("{what}: a refused store has nowhere to be said")
            });
            let body = f.m.body();
            assert!(
                band.y >= body.y && band.bottom() <= body.bottom() && band.w == body.w,
                "{what}: the band is {band:?} in a {body:?} body"
            );
            assert!(band.y >= l.card.bottom(), "{what}: the band is over the identity card");
            for (id, r) in &l.actions {
                assert!(!r.overlaps(&band), "{what}: {id:?} is drawn over the refusal");
            }
            // And the sentence fits the two lines the band reserves, at both geometries.
            let lines = wrap_words(why, band.w, BODY).len() as i32;
            assert!(
                lines * LINE <= band.h,
                "{what}: the refusal wraps to {lines} line(s) in a {} px band",
                band.h
            );
        }
    }

    /// The band belongs to the wallet it can happen to, and to no other.
    ///
    /// A session wallet's band is the "not stored" warning and it is unconditional; a
    /// stored wallet has one only while something it asked for has been refused. Stated as
    /// a test because the two share one rectangle, and a change to either condition that
    /// made them overlap would put a refusal and a session warning in the same pixels.
    #[test]
    fn the_band_is_the_session_warning_or_a_refusal_and_never_both() {
        let f = Fixture::new(720, 720);
        let ctx = f.ctx();
        let session = WalletState::new(info(false), Some(report()));
        assert!(session.layout(&ctx).session.is_some(), "an unstored wallet always says so");
        assert!(session.notice.is_none(), "and has no record to refuse anything about");

        let quiet = WalletState::new(info(true), Some(report()));
        assert!(
            quiet.layout(&ctx).session.is_none(),
            "a stored wallet with nothing to report gives the space to its actions"
        );
        assert!(refused_wallet("nope").layout(&ctx).session.is_some());
    }

    /// Storing the passphrase is ONE consent, and the confirm IS the answer.
    ///
    /// C4b and not C4c: what it costs is stated on the sheet, and the mistake is
    /// recoverable on this same screen by forgetting again - which is the test C4 applies
    /// to decide a grade. The request carries the SLOT and nothing else; the passphrase
    /// the embedder writes is the one already in its hand, so nothing here can substitute
    /// a retyped one.
    ///
    /// Broken version: raise the request from the first `DangerOutcome::Confirmed` without
    /// checking `consent`, and a delete's consequence sheet stores a passphrase instead.
    #[test]
    fn storing_is_one_confirm() {
        let mut f = Fixture::new(720, 720);
        let mut i = info(true);
        i.passphrase = PassphraseState::Required;
        let mut s = WalletState::new(i.clone(), Some(report()));

        assert!(
            s.activate(RegionId::ActPassphraseStore, &mut f.env()).request.is_none(),
            "opening the sheet asks for nothing"
        );
        let out = s.activate(RegionId::DangerConfirm, &mut f.env());
        assert_eq!(
            out.request,
            Some(UiRequest::StorePassphrase(3)),
            "the confirm is the answer, and it names the slot"
        );
        assert!(s.danger.is_none(), "the sheet closes behind it");
        assert_eq!(
            s.info.passphrase,
            PassphraseState::Required,
            "and nothing on the screen moves until the flash answers"
        );

        // Cancel closes the sheet and writes nothing.
        let mut s = WalletState::new(i, Some(report()));
        s.activate(RegionId::ActPassphraseStore, &mut f.env());
        let out = s.activate(RegionId::DangerCancel, &mut f.env());
        assert!(out.request.is_none(), "a cancelled store asks for nothing");
        assert!(s.danger.is_none());
    }

    /// Forgetting takes a consequence AND a hold, and neither one alone writes anything.
    ///
    /// C4c, because this is the one direction the device cannot undo: it can never show a
    /// stored passphrase back, so a user who tapped by accident and had not written the
    /// passphrase down has lost the wallet. The first sheet is the consequence; the second
    /// is the hold that performs it, and the request exists only on the far side of the
    /// second.
    ///
    /// Broken version: drop the `reading` guard in `activate`. The first assertion below
    /// trips, because the consequence sheet's confirm raises the request on its own.
    #[test]
    fn forgetting_takes_a_consequence_and_a_hold() {
        let mut f = Fixture::new(720, 720);
        let mut i = info(true);
        i.passphrase = PassphraseState::Stored;

        let mut s = WalletState::new(i.clone(), Some(report()));
        assert!(s.activate(RegionId::ActPassphraseStore, &mut f.env()).request.is_none());
        let read = s.activate(RegionId::DangerConfirm, &mut f.env());
        assert!(read.request.is_none(), "reading the consequence must not forget anything");
        assert!(s.danger.is_some(), "the hold sheet is up behind it");
        let done = s.activate(RegionId::HoldConfirm, &mut f.env());
        assert_eq!(
            done.request,
            Some(UiRequest::ForgetPassphrase(3)),
            "only the completed hold performs it"
        );
        assert!(s.danger.is_none());
        assert_eq!(
            s.info.passphrase,
            PassphraseState::Stored,
            "the row still reads the flash, which has not answered yet"
        );

        // Cancel at either step leaves the stored passphrase exactly where it was.
        for cancel_at_step in [1u8, 2] {
            let mut s = WalletState::new(i.clone(), Some(report()));
            s.activate(RegionId::ActPassphraseStore, &mut f.env());
            if cancel_at_step == 2 {
                s.activate(RegionId::DangerConfirm, &mut f.env());
            }
            let out = s.activate(RegionId::DangerCancel, &mut f.env());
            assert!(out.request.is_none(), "cancelled at step {cancel_at_step}");
            assert!(s.danger.is_none(), "the sheet closes at step {cancel_at_step}");
            assert_eq!(s.info.passphrase, PassphraseState::Stored);
        }
    }
}
