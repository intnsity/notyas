// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! S-38: get the signed transaction off the device, so no flow ends with one stranded in
//! RAM.
//!
//! # Why this screen has no Back
//!
//! Back from a signed but undelivered transaction is exactly the loss this screen exists to
//! prevent: the bytes live on the std side and nowhere else, and leaving drops them. So
//! [`Screen::back`] is [`Nav::Stay`], `Done` appears only once a delivery has succeeded, and
//! the only other way out is the C4 override that appears after two failed attempts - for a
//! user with a dead card slot, who will otherwise pull the power, which is the same outcome
//! without the informed consent.
//!
//! # Invariant 2b: the names before the write
//!
//! The C12 band above `Write to card` lists the files the write will create, from
//! [`SignedTx::artifacts`], which the signer computed before this screen existed. The
//! announcement therefore carries the value the writer is later handed rather than a
//! plausible reconstruction of it.
//!
//! # Every answer has an arm
//!
//! [`crate::WriteOutcome`] has four variants because four different things happen: a
//! collision is a QUESTION for the user, a missing card is a remedy they can perform
//! standing there, a part-written file is a mess they have to clean up, and a success is the
//! end. A handler that logged and returned on any of them would freeze the panel holding
//! the only copy of a signed transaction, which is the defect the answer vocabulary exists
//! to stop.
//!
//! # The second exit, and what makes it honest
//!
//! `Show as QR` opens S-39 over this screen with the transaction as one static symbol. It
//! is offered only while `notyas_core::psbt_qr::fits` says the transaction can be drawn at
//! a density a phone can resolve on the shortest panel this firmware ships; over that, the
//! control is drawn DISABLED with the size and the limit beside it and is not hit-tested,
//! because a control that refuses on tap teaches nothing and the card is the remedy for
//! exactly that case.
//!
//! The symbol arrives as an ANSWER and lives in this screen's own state, so it is the one
//! extra rendering of the transaction that exists and it dies with the screen. What the
//! user does with it comes back as [`deliverqr::Exit`]: `My wallet has it` sets the same
//! delivered flag a successful card write sets, because the panel cannot see the camera
//! and a claim by the person holding the device is the only evidence that exists.
//!
//! Nothing here is secret: the artifact names, the counts and the digest of the reviewed
//! bytes are all public, and the signed bytes themselves never cross into this crate.

use alloc::string::String;
use alloc::vec::Vec;
use alloc::{format, vec};

use embedded_graphics::draw_target::{DrawTarget, DrawTargetExt};
use embedded_graphics::pixelcolor::Rgb565;

use crate::canvas::{
    button, panel, text, text_centered, wrap_words, ButtonKind, BODY, CAPTION, HEADING,
    MONO_SMALL,
};
use crate::components::{draw_bar_no_back, write_notice, write_notice_h, LINE, SMALL_LINE};
use crate::danger::{Danger, DangerOutcome};
use crate::layout::{Metrics, Rect, TOUCH_MIN};
use crate::screens::deliverqr::{self, SignedQr};
use crate::screens::review::marker;
use crate::screens::{Answer, Ctx, Env, Nav, Outcome, Screen};
use crate::theme::*;
use crate::{
    Artifact, Region, RegionId, ScreenId, SignedQrOutcome, SignedTx, UiRequest, WriteOutcome,
};
use notyas_core::psbt_qr;

/// Inner padding of the status card.
const CARD_PAD: i32 = 12;

/// How much of the reviewed file's digest the card prints: 20 hex characters, 80 bits.
///
/// A fixed prefix rather than a fitted one, so the two panels print the SAME characters
/// and a user tying a written file back to what was on the glass is comparing the same
/// string whichever device they hold. 20 is what the narrower card holds with its
/// continuation marker (629 px of 648).
const DIGEST_CHARS: usize = 20;

/// Height of the status card: what was signed, whether it is finished, the gate's own
/// result, and the digest of the bytes that were reviewed. Four facts, four rows.
const CARD_H: i32 = 2 * LINE + 2 * SMALL_LINE + 2 * CARD_PAD;

/// Failures after which the C4 escape hatch appears. Two, per S-38's ratified decision: one
/// failure is a card to reseat, two is a slot that does not work.
const FAILURES_BEFORE_OVERRIDE: u8 = 2;

/// The confidentiality half of the C12 band. Fixed copy: it is a claim about the artifact,
/// and a claim that varied per build would be a claim nobody could check.
const NOTHING_SECRET: &str = "Nothing secret is written.";

/// What the last delivery attempt said, as a band under the actions.
///
/// A BAND rather than a screen for every one of these, because the only place the
/// transaction can be delivered from is this screen: a refusal screen would take the user
/// away from the sole remaining copy of it.
enum Band {
    /// Nothing has been attempted yet.
    None,
    Written(Vec<Artifact>),
    /// R-23. The transaction is still signed and still deliverable.
    NoCard,
    /// R-25. The sentence names how far the write got, because the file on the card is
    /// incomplete and has to be deleted before the name is reused.
    Failed(String),
    /// The std side refused to destroy the signed transaction. Stated rather than swallowed:
    /// the alternative is a user who believes it is gone.
    NotDiscarded,
    /// The user closed S-39 saying their wallet has the transaction. A delivery, recorded
    /// because they said so and worded so that whose claim it is stays visible.
    Claimed,
    /// The encoder refused what this screen offered. A disagreement between the two sides
    /// of the size rule, or bytes that are not a BIP-174 file; either way it is a defect,
    /// and a defect that says nothing is a button that does nothing.
    NotShown(String),
}

/// Which sheet is open, so that one `Confirmed` can mean two different things.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Ask {
    /// C4: these names already exist on the card. Confirm re-raises the write with
    /// `overwrite`.
    Overwrite,
    /// C4: throw the signed transaction away undelivered.
    Discard,
}

/// A request in flight, and therefore a C3 Busy frame.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Busy {
    Writing,
    Discarding,
}

impl Busy {
    /// The gerund heading and the one mechanical line beneath it (C3 contents 1 and 2).
    fn copy(self) -> (&'static str, &'static str) {
        match self {
            Busy::Writing => ("Writing to card", "Writing the signed transaction to the card."),
            Busy::Discarding => (
                "Discarding",
                "Erasing the signed transaction from this device's memory.",
            ),
        }
    }

    /// C3 contents 4: exactly one trailing line, and only the true one. "Do not remove the
    /// card" belongs to a write in flight and to nothing else.
    fn trailing(self) -> &'static str {
        match self {
            Busy::Writing => "Do not remove the card.",
            Busy::Discarding => "This cannot be cancelled.",
        }
    }
}

pub(crate) struct DeliverState {
    signed: SignedTx,
    band: Band,
    /// Unsuccessful write attempts. A missing card counts: a dead slot reports R-23 forever,
    /// and a user held on this screen by a card reader that does not work is exactly who the
    /// override exists for.
    failures: u8,
    /// At least one delivery has landed, so leaving is safe.
    delivered: bool,
    ask: Option<(Ask, Danger)>,
    busy: Option<Busy>,
    /// S-39, while it is open over this screen.
    ///
    /// The ONE extra rendering of the signed transaction that exists on this device, held
    /// here rather than beside the `Ui` so that it cannot outlive the delivery it belongs
    /// to: dropping this screen drops the symbol, and there is no path that keeps one
    /// after the transaction it draws has been discarded.
    qr: Option<SignedQr>,
    scroll: i32,
}

impl DeliverState {
    /// A signed transaction, waiting to be delivered.
    pub(crate) fn new(signed: SignedTx) -> DeliverState {
        DeliverState {
            signed,
            band: Band::None,
            failures: 0,
            delivered: false,
            ask: None,
            busy: None,
            qr: None,
            scroll: 0,
        }
    }

    /// The size of the signed transaction itself, in bytes, or `None` when this build
    /// produced no file to deliver at all.
    ///
    /// The FIRST artifact, by the contract [`crate::SignedTx::artifacts`] states: it is
    /// the files a write will create, in the order the notice lists them, and the first
    /// thing a delivery of a signed transaction writes IS the signed transaction. Anything
    /// a later build adds is derived from those bytes and is listed after them.
    fn qr_bytes(&self) -> Option<usize> {
        self.signed.artifacts.first().map(|a| a.bytes as usize)
    }

    /// Why the transaction cannot go on the glass, or `None` when it can. `None` too when
    /// there is nothing to show, because then the exit does not exist to be refused.
    ///
    /// The rule is asked for BY NAME from the module that owns it rather than restated
    /// here. A screen carrying its own threshold would eventually draw a control the
    /// encoder refuses, which is precisely the failure a disabled-with-a-reason button
    /// exists to prevent - and the sentence carries both numbers for the same reason S-28
    /// prints sizes: a limit without the measurement beside it is not something a user can
    /// act on.
    /// A MONO_SMALL machine-fact row and not `psbt_qr::Refused`'s own sentence, which is
    /// the one thing here that was not free to choose. That sentence is 1071 px of
    /// MONO_SMALL and wraps to two lines on both shipped panels, and the second line does
    /// not exist to be spent: in this screen's worst state - two failed writes, so the C4
    /// override has taken a full-width row - the 800x480 foot has 54 px of slack over the
    /// one line of scrolling sheet S-38 guarantees. So the numbers come from the module
    /// that owns them and the words are cut to the row's budget, which is the same trade
    /// the status card's gate line already made. The full sentence still reaches the panel
    /// on the path where the ENCODER refuses ([`Band::NotShown`]), where it is BODY text
    /// in the scrolling half and has room to wrap.
    ///
    /// One line at every geometry for every `u32` size, by construction rather than by
    /// hope: the fixed text is 18 characters and the two numbers are at most fourteen,
    /// which is 558 px of the 672 the narrower body has.
    fn qr_refusal(&self) -> Option<String> {
        let bytes = self.qr_bytes()?;
        (!psbt_qr::fits(bytes))
            .then(|| format!("{bytes} bytes; QR limit {}.", psbt_qr::MAX_PSBT_BYTES))
    }

    /// The public name of what is on the panel right now. A request in flight is C3's Busy
    /// screen, which is a different screen to an embedder and to the region checks - not a
    /// mode of the sheet beneath it.
    pub(crate) fn id(&self) -> ScreenId {
        match self.busy {
            None => ScreenId::Deliver,
            Some(_) => ScreenId::Working,
        }
    }

    /// The status card's two lines: what was signed, and whether it is finished.
    fn status(&self) -> (String, String) {
        let s = &self.signed;
        let headline = format!("Signed - {} of {} inputs", s.signed_inputs, s.signable_inputs);
        let detail = if s.complete {
            String::from("This transaction is complete and ready to broadcast.")
        } else {
            String::from("This transaction still needs another cosigner.")
        };
        (headline, detail)
    }

    /// The gate's own result, shown because a gate whose result nobody can see is a gate
    /// nobody can tell has stopped running.
    ///
    /// The COUNT is the claim, and the count is what this line is cut down to. The sentence
    /// this replaced ("Every signature was re-checked against a hash recomputed from the
    /// file: 3 of 3.") was 1343 px of MONO_SMALL drawn into 648 px of card, so what a user
    /// actually read was half a sentence and no result at all - the mechanism it described
    /// is in `psbt::checks`, but "3 of 3" is the part only the running device can tell you.
    /// Shortened rather than shrunk: this row sits with the digest below it as one block of
    /// machine facts, and mono is what makes two counts line up under each other.
    fn gate_line(&self) -> String {
        format!(
            "Signatures re-checked: {} of {}.",
            self.signed.verified_inputs, self.signed.signed_inputs
        )
    }

    /// The digest of the bytes that were reviewed, as its leading [`DIGEST_CHARS`]
    /// characters.
    ///
    /// A PREFIX by construction rather than by accident. The card draws through a clip, so
    /// printing all 64 characters did not print all 64: it printed however many the panel
    /// happened to hold, cut mid-character, and a different number on each panel.
    /// [`crate::SignedTx::psbt_id`] describes this line as the digest's leading bytes and
    /// that is now what it is. The remainder is not shown anywhere on this screen, and the
    /// trailing marker says so rather than letting a prefix pass for a whole digest.
    fn reviewed_line(&self) -> String {
        let id = &self.signed.psbt_id;
        match id.char_indices().nth(DIGEST_CHARS) {
            Some((cut, _)) => format!("reviewed file {}...", &id[..cut]),
            None => format!("reviewed file {id}"),
        }
    }

    /// The C12 band's first half: the files this write will create, named before it runs.
    ///
    /// NAMES and not sizes. Invariant 2b is about the name - it is what a user checks
    /// against the card afterwards and what a collision is about - and the two lines the
    /// sizes cost are two lines of body on the short panel. What was written, with its
    /// sizes, is what the band says once the write has happened.
    fn write_what(&self) -> String {
        if self.signed.artifacts.is_empty() {
            return String::from("This build has no file to write.");
        }
        let names: Vec<&str> = self.signed.artifacts.iter().map(|a| a.name.as_str()).collect();
        format!("This writes to the card: {}", names.join(", "))
    }

    /// Whether the escape hatch is offered. Only after the second failure, and never once a
    /// delivery has landed - a delivered transaction is left through `Done`.
    fn override_offered(&self) -> bool {
        !self.delivered && self.failures >= FAILURES_BEFORE_OVERRIDE
    }

    /// The band's sentence and its ink, or `None` while nothing has been attempted.
    fn band_copy(&self) -> Option<(String, Rgb565)> {
        match &self.band {
            Band::None => None,
            Band::Written(a) if a.is_empty() => {
                Some((String::from("Written. Remove the card."), SUCCESS))
            }
            Band::Written(a) => Some((
                format!(
                    "Written. Remove the card. {}",
                    a.iter()
                        .map(|x| format!("{} ({})", x.name, kb(x.bytes)))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                SUCCESS,
            )),
            Band::NoCard => Some((
                String::from(
                    "No card detected. Insert a FAT32-formatted card and try again. The \
                     transaction is still signed and still held on this device.",
                ),
                WARNING,
            )),
            Band::Failed(msg) => Some((
                format!(
                    "Card write failed. {msg} The file on the card is incomplete - delete it \
                     before reusing the name.",
                ),
                DANGER,
            )),
            Band::NotDiscarded => Some((
                String::from(
                    "The signed transaction was NOT discarded. It is still held on this \
                     device.",
                ),
                DANGER,
            )),
            // Whose claim it is stays in the sentence. This device saw a symbol drawn and
            // a button pressed; it did not see a camera, and a band that said "delivered"
            // flatly would be the device asserting something only the user can know.
            Band::Claimed => Some((
                String::from(
                    "You said your wallet has this transaction. Nothing was written to the \
                     card, and scanning it does not broadcast it.",
                ),
                SUCCESS,
            )),
            Band::NotShown(why) => Some((
                format!(
                    "The signed transaction was not shown as a QR code. {why}. It is still \
                     signed and still held on this device."
                ),
                DANGER,
            )),
        }
    }

    /// The C4 sheet for a name that is already on the card.
    fn overwrite_sheet(names: &[String]) -> Danger {
        let taken = format!("These files are already on the card: {}.", names.join(", "));
        Danger::confirm(
            "Overwrite on the card?",
            &[
                &taken,
                "Overwriting replaces them. If one of them is a transaction you have not                  broadcast, it is gone.",
            ],
            "Overwrite",
        )
    }

    /// The C4 sheet for leaving without delivering.
    fn discard_sheet() -> Danger {
        Danger::confirm(
            "Discard the signed transaction?",
            &[
                "This device holds the only copy. Discarding it erases the signature and \
                 nothing has been written to the card.",
                "The transaction can be built and signed again from the same file.",
            ],
            "Discard signed transaction",
        )
    }

    /// Record an unsuccessful attempt. The count is what unlocks the escape hatch.
    fn failed(&mut self, band: Band) {
        self.band = band;
        self.failures = self.failures.saturating_add(1);
    }
}

/// A size in kB with one decimal, which is how S-28 and the C12 band both print one.
fn kb(bytes: u32) -> String {
    let tenths = (bytes as u64 * 10).div_ceil(1024);
    format!("{}.{} kB", tenths / 10, tenths % 10)
}

pub(crate) struct Layout {
    /// The scrolling half: the result band, then the status card.
    viewport: Rect,
    /// The band the last answer produced, at the TOP of the scrolling half so that the
    /// newest thing the device has said is the thing visible at rest.
    band: Option<Rect>,
    card: Rect,
    /// The sentence beside a disabled `Show as QR`, or `None` while the exit is live.
    ///
    /// ABOVE the C12 announcement rather than between it and the exits: invariant 2b puts
    /// nothing between the band that names the files and the button that writes them, and
    /// a reason for a different control is exactly the sort of thing that would drift in
    /// there.
    qr_note: Option<Rect>,
    /// The C12 announcement and the exits, PINNED to the foot of the body.
    ///
    /// Pinned rather than scrolled, and pinned TOGETHER, for the two reasons that decide
    /// this screen's shape. The announcement has to sit directly above the button that
    /// performs the write (invariant 2b), and nothing may come between them - so they are
    /// one block. And the way OUT of a screen holding the only copy of a signed transaction
    /// may never be below the fold: a control a user has to discover by dragging is a
    /// control a user with a signed transaction and a failing card will not find.
    notice: Rect,
    actions: Vec<(RegionId, Rect)>,
    limit: i32,
}

/// The label on each exit. One table, so a control cannot be drawn with copy that disagrees
/// with what its region does.
fn action_label(id: RegionId, no_card: bool) -> &'static str {
    match id {
        RegionId::DeliverSd => "Write to card",
        RegionId::DeliverQr => "Show as QR",
        RegionId::DeliverRetry if no_card => "Check again",
        RegionId::DeliverRetry => "Retry",
        RegionId::DeliverDone => "Done",
        RegionId::DeliverDiscard => "Discard signed transaction",
        _ => "",
    }
}

impl Screen for DeliverState {
    type Layout = Layout;

    fn layout(&self, ctx: &Ctx) -> Layout {
        let m = &ctx.m;
        let body = m.body();
        let g = m.gap;

        // The pinned foot, measured from the bottom up: the C12 band and the exits.
        //
        // Two to a row, because the exits are short verbs and the short panel has no
        // vertical room to spare - except the C4 override, which always gets a full-width
        // row of its own. It is the destructive answer and it is the one control here a
        // finger must not find by accident while reaching for the write.
        let mut ids = vec![RegionId::DeliverSd];
        // The second exit sits beside the first, because they are the two ways a signed
        // transaction leaves this device and neither is a fallback for the other. Drawn
        // even when it is refused - see `qr_refusal` - so that a user whose transaction is
        // too large learns the fact instead of wondering where the QR option went.
        if self.qr_bytes().is_some() {
            ids.push(RegionId::DeliverQr);
        }
        if matches!(self.band, Band::NoCard | Band::Failed(_)) {
            ids.push(RegionId::DeliverRetry);
        }
        if self.delivered {
            ids.push(RegionId::DeliverDone);
        }
        let rows: Vec<Vec<RegionId>> = if self.override_offered() {
            vec![ids, vec![RegionId::DeliverDiscard]]
        } else {
            ids.chunks(2).map(|c| c.to_vec()).collect()
        };

        let btn_h = m.btn.max(TOUCH_MIN);
        let notice_h = write_notice_h(body.w, &self.write_what(), NOTHING_SECRET);
        let actions_h = rows.len() as i32 * btn_h + (rows.len() as i32 - 1) * g;
        // A disabled control says why it is disabled, in the grammar the unlock screen's
        // countdown uses: the sentence beside it IS the whole reason, and it is measured
        // from the same wrap the painter walks so a copy change cannot outgrow its block.
        let refusal = self.qr_refusal();
        let note_h = refusal
            .as_ref()
            .map_or(0, |why| wrap_words(why, body.w, MONO_SMALL).len() as i32 * SMALL_LINE + g);
        let foot_h = note_h + notice_h + g + actions_h;
        let foot_y = body.bottom() - foot_h;
        let qr_note = refusal.map(|_| Rect::new(body.x, foot_y, body.w, note_h - g));
        let notice = Rect::new(body.x, foot_y + note_h, body.w, notice_h);

        let mut actions = Vec::new();
        let mut y = notice.bottom() + g;
        for row in &rows {
            let w = (body.w - (row.len() as i32 - 1) * g) / row.len() as i32;
            for (i, id) in row.iter().enumerate() {
                actions.push((*id, Rect::new(body.x + i as i32 * (w + g), y, w, btn_h)));
            }
            y += btn_h + g;
        }

        // What is left scrolls: the band the last answer produced, then the status card.
        let viewport = Rect::new(body.x, body.y, body.w, (notice.y - g - body.y).max(0));
        let band = self.band_copy().map(|(copy, _)| {
            let h = wrap_words(&copy, body.w, BODY).len() as i32 * LINE;
            Rect::new(body.x, viewport.y, body.w, h)
        });
        let card_y = band.map_or(viewport.y, |b| b.bottom() + g);
        let card = Rect::new(body.x, card_y, body.w, CARD_H);
        let limit = (card.bottom() - viewport.bottom()).max(0);

        Layout { viewport, band, card, qr_note, notice, actions, limit }
    }

    fn regions(&self, ctx: &Ctx, out: &mut Vec<Region>) {
        // C3: a Busy screen offers nothing. A write is a single blocking call on the std
        // side and a live control here would be a lie about what the loop can do.
        if self.busy.is_some() {
            return;
        }
        // S-39 is hit-tested INSTEAD of this screen, like the sheets: it covers the panel,
        // and a control still live underneath it would be a control nobody can see.
        if let Some(qr) = &self.qr {
            qr.regions(&ctx.m, out);
            return;
        }
        if let Some((_, sheet)) = &self.ask {
            sheet.regions(&ctx.m, out);
            return;
        }
        // No Back, ever - see the module docs. Not even in the bar: `draw_bar_no_back` is
        // what makes that visible rather than merely true.
        //
        // A refused `Show as QR` is DRAWN and not pushed. That is the house rule for a
        // disabled control - the passphrase unlock screen's Try again keeps it too - and
        // it is what stops a tap being answered by a refusal the user has already read
        // above the button.
        let refused = self.qr_refusal().is_some();
        for (id, rect) in self.layout(ctx).actions {
            if id == RegionId::DeliverQr && refused {
                continue;
            }
            out.push(Region { id, rect });
        }
    }

    fn draw<D: DrawTarget<Color = Rgb565>>(&self, t: &mut D, ctx: &Ctx) -> Result<(), D::Error> {
        let m = &ctx.m;
        if let Some(busy) = self.busy {
            return draw_busy(t, m, busy);
        }
        if let Some(qr) = &self.qr {
            return qr.draw(t, m);
        }
        if let Some((_, sheet)) = &self.ask {
            return sheet.draw(t, m, ctx.press, ctx.hold_released);
        }
        let l = self.layout(ctx);
        // No Back, and the bar says so by not drawing one: a screen holding the only copy
        // of a signed transaction may not offer an affordance that would drop it.
        draw_bar_no_back(t, m, "Signed")?;

        let scroll = self.scroll.clamp(0, l.limit);
        {
            let mut clip = t.clipped(&l.viewport.to_eg());
            if let (Some(r), Some((copy, ink))) = (l.band, self.band_copy()) {
                let r = r.translated(0, -scroll);
                let mut y = r.y;
                for line in wrap_words(&copy, r.w, BODY) {
                    text(&mut clip, &line, r.x, y, BODY, ink, PAPER_1)?;
                    y += LINE;
                }
            }
            let card = l.card.translated(0, -scroll);
            panel(&mut clip, card, PAPER_2, BORDER_STRONG)?;
            let inner = card.inset(CARD_PAD);
            let (headline, detail) = self.status();
            let ink = if self.signed.complete { SUCCESS } else { WARNING };
            text(&mut clip, &headline, inner.x, inner.y, HEADING, ink, PAPER_2)?;
            // CAPTION, not BODY. The card's height is a constant - four facts, four rows -
            // so this line cannot have a second one, and at BODY the finished-transaction
            // sentence is 758 px drawn into 648 px of card on the 720x720 panel. The words
            // are left exactly as they are: UX-SCREENS S-38 parks this sentence OPEN until
            // the finalizer decision, and a truncation is not a reason to pre-empt that.
            text(&mut clip, &detail, inner.x, inner.y + LINE, CAPTION, INK_SECONDARY, PAPER_2)?;
            text(
                &mut clip,
                &self.gate_line(),
                inner.x,
                inner.y + 2 * LINE,
                MONO_SMALL,
                INK_SECONDARY,
                PAPER_2,
            )?;
            text(
                &mut clip,
                &self.reviewed_line(),
                inner.x,
                inner.y + 2 * LINE + SMALL_LINE,
                MONO_SMALL,
                INK_MUTED,
                PAPER_2,
            )?;
        }
        // C6's markers.
        if scroll > 0 {
            marker(t, "more above", l.viewport, true)?;
        }
        if scroll < l.limit {
            marker(t, "more below", l.viewport, false)?;
        }

        let refusal = self.qr_refusal();
        if let (Some(r), Some(why)) = (l.qr_note, &refusal) {
            let mut y = r.y;
            for line in wrap_words(why, r.w, MONO_SMALL) {
                text(t, &line, r.x, y, MONO_SMALL, INK_MUTED, PAPER_1)?;
                y += SMALL_LINE;
            }
        }
        write_notice(t, l.notice, &self.write_what(), NOTHING_SECRET)?;
        let no_card = matches!(self.band, Band::NoCard);
        for (id, rect) in &l.actions {
            let kind = match id {
                RegionId::DeliverSd => ButtonKind::Primary,
                RegionId::DeliverDone => ButtonKind::Primary,
                RegionId::DeliverDiscard => ButtonKind::Danger,
                // Drawn disabled rather than dropped, with the reason above it. The exit
                // stays where a user who has been told about it expects to find it, and
                // `regions` does not hit-test it.
                RegionId::DeliverQr if refusal.is_some() => ButtonKind::Disabled,
                _ => ButtonKind::Secondary,
            };
            // Pixel-clipped to its own key for the reason the keyboard's control row is:
            // a label wider than the button it names must crop rather than bleed into the
            // button beside it, where it would make both unreadable.
            let mut clip = t.clipped(&rect.to_eg());
            button(&mut clip, *rect, action_label(*id, no_card), kind, PAPER_1)?;
        }
        Ok(())
    }

    fn activate(&mut self, id: RegionId, _env: &mut Env) -> Outcome {
        if self.busy.is_some() {
            return Outcome::stay();
        }
        // S-39's two answers, which are answers THIS screen records. The symbol is dropped
        // either way: it is the one extra rendering of the transaction that exists, and
        // there is no state in which it should outlive the surface that showed it.
        if let Some(qr) = &self.qr {
            match qr.activate(id) {
                deliverqr::Exit::Stay => {}
                // The panel cannot see the camera, so this claim is the user's and the
                // band says whose it is. It ungates `Done` exactly as a card write does,
                // because "delivered" is the same fact however it was reached.
                deliverqr::Exit::Delivered => {
                    self.qr = None;
                    self.delivered = true;
                    self.scroll = 0;
                    self.band = Band::Claimed;
                }
                deliverqr::Exit::Closed => self.qr = None,
            }
            return Outcome::stay();
        }
        if let Some((ask, sheet)) = &mut self.ask {
            let which = *ask;
            return match sheet.activate(id) {
                DangerOutcome::Open | DangerOutcome::Alternative => Outcome::stay(),
                DangerOutcome::Cancelled => {
                    self.ask = None;
                    Outcome::stay()
                }
                DangerOutcome::Confirmed => {
                    self.ask = None;
                    match which {
                        Ask::Overwrite => {
                            self.busy = Some(Busy::Writing);
                            Outcome::ask(UiRequest::WriteSigned { overwrite: true })
                        }
                        Ask::Discard => {
                            self.busy = Some(Busy::Discarding);
                            Outcome::ask(UiRequest::DiscardSigned)
                        }
                    }
                }
            };
        }
        match id {
            // C3's law: the transition chooses the frame that says what is happening, and
            // the embedder publishes it before answering.
            RegionId::DeliverSd | RegionId::DeliverRetry => {
                self.busy = Some(Busy::Writing);
                Outcome::ask(UiRequest::WriteSigned { overwrite: false })
            }
            // No Busy frame, unlike every other request this screen raises: framing a
            // 1.4 kB base64 string and laying out a version-31 symbol is arithmetic, not
            // a flash write, and it lands well inside C3's 150 ms. The guard repeats the
            // size rule `regions` applied, so a tap dispatched from a stale region list
            // cannot reach the encoder with a transaction it refuses.
            RegionId::DeliverQr if self.qr_bytes().is_some() && self.qr_refusal().is_none() => {
                Outcome::ask(UiRequest::ShowSignedQr)
            }
            // Leaving is a REQUEST, not a screen change: the bytes are on the std side, so
            // the only way this screen can know they are gone is to be told.
            RegionId::DeliverDone if self.delivered => {
                self.busy = Some(Busy::Discarding);
                Outcome::ask(UiRequest::DiscardSigned)
            }
            RegionId::DeliverDiscard if self.override_offered() => {
                self.ask = Some((Ask::Discard, DeliverState::discard_sheet()));
                Outcome::stay()
            }
            _ => Outcome::stay(),
        }
    }

    fn answered(&mut self, answer: Answer, _env: &mut Env) -> Outcome {
        match answer {
            Answer::Write(outcome) => {
                self.busy = None;
                self.scroll = 0;
                match outcome {
                    WriteOutcome::Written(files) => {
                        self.delivered = true;
                        self.failures = 0;
                        self.band = Band::Written(files);
                    }
                    // A question, not a failure: the count is untouched, because a name that
                    // is already taken says nothing about whether the slot works.
                    WriteOutcome::Collision(names) => {
                        self.ask = Some((Ask::Overwrite, DeliverState::overwrite_sheet(&names)));
                    }
                    WriteOutcome::NoCard => self.failed(Band::NoCard),
                    WriteOutcome::Failed(msg) => self.failed(Band::Failed(msg)),
                }
                Outcome::stay()
            }
            Answer::SignedQr(SignedQrOutcome::Symbol(data)) => {
                self.qr = Some(SignedQr::new(data));
                Outcome::stay()
            }
            // The encoder disagreed with the rule this screen offered the exit under, or
            // was handed something that is not a BIP-174 file. Either is a defect on this
            // device; what must not happen is that it arrives as a button that did
            // nothing, so it arrives as a band instead.
            Answer::SignedQr(SignedQrOutcome::Refused(why)) => {
                self.scroll = 0;
                self.band = Band::NotShown(why);
                Outcome::stay()
            }
            Answer::Discard(gone) => {
                self.busy = None;
                if gone {
                    Outcome { nav: Nav::Back, request: None }
                } else {
                    // Stated, never swallowed. A user who believes a signed transaction is
                    // gone will not go looking for it.
                    self.band = Band::NotDiscarded;
                    Outcome::stay()
                }
            }
            _ => Outcome::stay(),
        }
    }

    /// There is no Back from a signed transaction that has not been delivered. `Done` and
    /// the C4 override are the two ways out and both of them destroy it deliberately.
    fn back(&self) -> Nav {
        Nav::Stay
    }

    fn scroll_mut(&mut self) -> Option<&mut i32> {
        if self.busy.is_some() || self.ask.is_some() || self.qr.is_some() {
            return None;
        }
        Some(&mut self.scroll)
    }

    fn scroll_limit(&self, ctx: &Ctx) -> i32 {
        self.layout(ctx).limit
    }
}

/// The C3 frame for a request this screen raised.
///
/// Indeterminate and honest about it: this vocabulary carries no progress report for a
/// card write, so the frame states what is happening and what not to do, and shows no
/// meter. C3 forbids the alternative outright.
fn draw_busy<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    m: &Metrics,
    busy: Busy,
) -> Result<(), D::Error> {
    let (heading, mechanical) = busy.copy();
    draw_bar_no_back(t, m, heading)?;
    let body = m.body();
    let card_h = 3 * LINE + 4 * m.gap;
    let card = Rect::new(body.x, body.y + (body.h - card_h).max(0) / 2, body.w, card_h);
    panel(t, card, PAPER_2, BORDER_STRONG)?;
    let line = |y: i32| Rect::new(card.x, y, card.w, LINE);
    let mut y = card.y + m.gap;
    text_centered(t, heading, line(y), HEADING, INK_PRIMARY, PAPER_2)?;
    y += LINE + m.gap;
    text_centered(t, mechanical, line(y), BODY, INK_SECONDARY, PAPER_2)?;
    y += LINE + m.gap;
    text_centered(t, busy.trailing(), line(y), BODY, INK_SECONDARY, PAPER_2)
}

#[cfg(test)]
mod tests {
    use crate::UnlockGate;
    use super::*;
    use crate::screens::testing::{rows_are_clear_on, Fixture, GEOMETRIES};
    use notyas_fonts::Atlas;

    fn signed(complete: bool) -> SignedTx {
        SignedTx {
            signed_inputs: 3,
            verified_inputs: 3,
            signable_inputs: 3,
            complete,
            artifacts: vec![
                Artifact { name: String::from("psbt-2026-08-17-signed.psbt"), bytes: 2600 },
                Artifact { name: String::from("psbt-2026-08-17-final.txn"), bytes: 400 },
            ],
            psbt_id: String::from(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            ),
        }
    }

    fn ids(s: &DeliverState, f: &Fixture) -> Vec<RegionId> {
        let mut out = Vec::new();
        s.regions(&f.ctx(), &mut out);
        out.into_iter().map(|r| r.id).collect()
    }

    fn drive(s: &mut DeliverState, f: &Fixture, id: RegionId) -> Option<UiRequest> {
        let mut net = crate::Network::Bitcoin;
        let mut e = Env {
            network: &mut net,
            lock: &f.lock,
            wallets: &f.wallets,
            gate: &mut UnlockGate::default(),
        };
        s.activate(id, &mut e).request
    }

    fn answer(s: &mut DeliverState, f: &Fixture, a: Answer) -> Nav {
        let mut net = crate::Network::Bitcoin;
        let mut e = Env {
            network: &mut net,
            lock: &f.lock,
            wallets: &f.wallets,
            gate: &mut UnlockGate::default(),
        };
        s.answered(a, &mut e).nav
    }

    /// Every one of the four write answers has an arm that leaves the panel usable. A
    /// handler that logged and returned would freeze the screen holding the only copy of a
    /// signed transaction.
    ///
    /// Broken version: delete the `WriteOutcome::NoCard` arm of `answered` (or let it fall
    /// through the `_` arm). `busy` is never cleared, `regions` stays empty and the first
    /// assertion of that case trips.
    #[test]
    fn every_write_answer_leaves_the_panel_usable() {
        let f = Fixture::new(720, 720);
        let outcomes = [
            WriteOutcome::Written(vec![Artifact { name: String::from("a.psbt"), bytes: 10 }]),
            WriteOutcome::Collision(vec![String::from("a.psbt")]),
            WriteOutcome::NoCard,
            WriteOutcome::Failed(String::from("Writing stopped after 1.2 kB.")),
        ];
        for outcome in outcomes {
            let mut s = DeliverState::new(signed(true));
            assert!(drive(&mut s, &f, RegionId::DeliverSd).is_some());
            assert_eq!(s.id(), ScreenId::Working, "the write must publish a Busy frame");
            assert!(ids(&s, &f).is_empty(), "a Busy screen offers nothing");
            answer(&mut s, &f, Answer::Write(outcome));
            assert_eq!(s.id(), ScreenId::Deliver, "the answer must end the Busy frame");
            assert!(!ids(&s, &f).is_empty(), "the panel is frozen with no control");
            assert!(
                ids(&s, &f).contains(&RegionId::DeliverSd)
                    || ids(&s, &f).contains(&RegionId::DangerConfirm),
                "there is always a way to deliver or to answer the question"
            );
        }
    }

    /// Done exists only once something has landed, and leaving is a request rather than a
    /// screen change.
    ///
    /// Broken version: push `DeliverDone` unconditionally in `layout`. The first assertion
    /// trips, and with it the property that no flow ends with a stranded transaction.
    #[test]
    fn done_appears_only_after_a_delivery() {
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            let mut s = DeliverState::new(signed(true));
            assert!(!ids(&s, &f).contains(&RegionId::DeliverDone), "{w}x{h}");
            assert!(matches!(s.back(), Nav::Stay), "{w}x{h}: S-38 has no Back");
            assert!(drive(&mut s, &f, RegionId::DeliverDone).is_none(), "{w}x{h}");

            drive(&mut s, &f, RegionId::DeliverSd);
            answer(&mut s, &f, Answer::Write(WriteOutcome::Written(Vec::new())));
            assert!(ids(&s, &f).contains(&RegionId::DeliverDone), "{w}x{h}");
            assert!(
                matches!(drive(&mut s, &f, RegionId::DeliverDone), Some(UiRequest::DiscardSigned)),
                "{w}x{h}: leaving must ask the std side to destroy the bytes"
            );
            assert_eq!(answer_nav(&mut s, &f, true), "back");
        }
    }

    fn answer_nav(s: &mut DeliverState, f: &Fixture, gone: bool) -> &'static str {
        match answer(s, f, Answer::Discard(gone)) {
            Nav::Back => "back",
            _ => "stay",
        }
    }

    /// A refused discard is stated on the panel, never swallowed.
    #[test]
    fn a_refused_discard_says_so() {
        let f = Fixture::new(800, 480);
        let mut s = DeliverState::new(signed(true));
        drive(&mut s, &f, RegionId::DeliverSd);
        answer(&mut s, &f, Answer::Write(WriteOutcome::Written(Vec::new())));
        drive(&mut s, &f, RegionId::DeliverDone);
        assert_eq!(answer_nav(&mut s, &f, false), "stay");
        let (copy, _) = s.band_copy().expect("a refusal is a band");
        assert!(copy.contains("NOT discarded"), "{copy}");
        assert!(ids(&s, &f).contains(&RegionId::DeliverDone), "the way out is still offered");
    }

    /// The escape hatch appears after two failures and not before, and it is behind a C4
    /// sheet naming what is destroyed.
    ///
    /// Broken version: change `FAILURES_BEFORE_OVERRIDE` to 1. The first assertion trips.
    #[test]
    fn the_override_appears_only_after_two_failures() {
        let f = Fixture::new(720, 720);
        let mut s = DeliverState::new(signed(true));
        drive(&mut s, &f, RegionId::DeliverSd);
        answer(&mut s, &f, Answer::Write(WriteOutcome::NoCard));
        assert!(!ids(&s, &f).contains(&RegionId::DeliverDiscard), "one failure is a card to reseat");
        assert!(ids(&s, &f).contains(&RegionId::DeliverRetry));
        drive(&mut s, &f, RegionId::DeliverRetry);
        answer(&mut s, &f, Answer::Write(WriteOutcome::Failed(String::from("Stopped."))));
        assert!(ids(&s, &f).contains(&RegionId::DeliverDiscard), "two is a slot that does not work");

        drive(&mut s, &f, RegionId::DeliverDiscard);
        assert_eq!(
            ids(&s, &f),
            vec![RegionId::DangerCancel, RegionId::DangerConfirm],
            "the sheet is modal"
        );
        assert!(matches!(
            drive(&mut s, &f, RegionId::DangerConfirm),
            Some(UiRequest::DiscardSigned)
        ));
    }

    /// A collision is a question, not a failure: it must not count toward the override and
    /// its confirm re-raises the write with `overwrite` set.
    #[test]
    fn a_collision_asks_and_then_overwrites() {
        let f = Fixture::new(720, 720);
        let mut s = DeliverState::new(signed(true));
        drive(&mut s, &f, RegionId::DeliverSd);
        answer(
            &mut s,
            &f,
            Answer::Write(WriteOutcome::Collision(vec![String::from("psbt-signed.psbt")])),
        );
        assert_eq!(s.failures, 0, "a taken name says nothing about the slot");
        assert_eq!(ids(&s, &f), vec![RegionId::DangerCancel, RegionId::DangerConfirm]);
        assert!(matches!(
            drive(&mut s, &f, RegionId::DangerConfirm),
            Some(UiRequest::WriteSigned { overwrite: true })
        ));
        // ...and cancelling leaves the transaction exactly where it was.
        let mut s = DeliverState::new(signed(true));
        drive(&mut s, &f, RegionId::DeliverSd);
        answer(&mut s, &f, Answer::Write(WriteOutcome::Collision(vec![String::from("a")])));
        drive(&mut s, &f, RegionId::DangerCancel);
        assert!(ids(&s, &f).contains(&RegionId::DeliverSd));
    }

    /// Invariant 2b: the C12 band names the files BEFORE the write, and the band sits
    /// directly above the button that performs it with nothing between them.
    #[test]
    fn the_write_is_announced_before_it_runs() {
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            let s = DeliverState::new(signed(true));
            let what = s.write_what();
            assert!(what.contains("psbt-2026-08-17-signed.psbt"), "{what}");
            assert!(what.contains("psbt-2026-08-17-final.txn"), "{what}");
            let l = s.layout(&f.ctx());
            let (_, write) = l
                .actions
                .iter()
                .find(|(id, _)| *id == RegionId::DeliverSd)
                .expect("the write action exists");
            assert!(
                write.y >= l.notice.bottom(),
                "{w}x{h}: the button is above its own announcement"
            );
            for (id, r) in &l.actions {
                if *id != RegionId::DeliverSd {
                    assert!(
                        !(r.y < write.y && r.bottom() > l.notice.bottom()),
                        "{w}x{h}: {id:?} sits between the notice and the write"
                    );
                }
            }
            // ...and what LANDED, with its sizes, is what the band says afterwards.
            let mut s = s;
            drive(&mut s, &f, RegionId::DeliverSd);
            answer(
                &mut s,
                &f,
                Answer::Write(WriteOutcome::Written(vec![Artifact {
                    name: String::from("psbt-2026-08-17-signed.psbt"),
                    bytes: 2600,
                }])),
            );
            let (band, _) = s.band_copy().expect("a landed write says so");
            assert!(band.contains("Written. Remove the card."), "{band}");
            assert!(band.contains("2.6 kB"), "{band}");
        }
    }

    /// The whole screen lays out on both panels in every state it has, with every control
    /// tappable and nothing overlapping.
    #[test]
    fn every_state_lays_out_on_both_panels() {
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            for complete in [false, true] {
                let mut s = DeliverState::new(signed(complete));
                // Walk to the busiest state this screen has: delivered, failed twice, with
                // the override and a band on screen.
                drive(&mut s, &f, RegionId::DeliverSd);
                answer(&mut s, &f, Answer::Write(WriteOutcome::NoCard));
                drive(&mut s, &f, RegionId::DeliverRetry);
                answer(&mut s, &f, Answer::Write(WriteOutcome::Failed(String::from("Stopped."))));
                let l = s.layout(&f.ctx());
                let what = format!("{w}x{h} complete={complete}");
                // The pinned half is on the panel and disjoint from the scrolling half.
                let mut rects = vec![("viewport", l.viewport), ("notice", l.notice)];
                for (id, r) in &l.actions {
                    rects.push((label_of(*id), *r));
                }
                rows_are_clear_on(&f.m, &what, f.m.screen(), &rects);
                for (name, r) in &rects[2..] {
                    assert!(r.w >= TOUCH_MIN && r.h >= TOUCH_MIN, "{what}: {name} is {}x{}", r.w, r.h);
                }
                // The scrolling half starts inside its viewport, so the newest thing the
                // device has said is the first line on the panel at rest and everything
                // else is one drag away with `more below` marking it. One line is the
                // floor: in the state this walk reaches - two failed writes, so the C4
                // override has taken a full-width row of the foot - 800x480 has exactly
                // that much left, and what it spends the room on is the announcement and
                // the way out, which are the two things a user with a failing card slot
                // must not have to go looking for.
                assert!(l.viewport.h >= LINE, "{what}: the sheet has {} px", l.viewport.h);
                let top = l.band.unwrap_or(l.card);
                assert_eq!(top.y, l.viewport.y, "{what}: the sheet does not start at the top");
                assert!(l.card.y >= l.viewport.y, "{what}: the card starts above the sheet");
                assert!(
                    l.limit >= l.card.bottom() - l.viewport.bottom(),
                    "{what}: the sheet cannot be scrolled to its end"
                );
            }
        }
    }

    /// The status card holds every line it draws, at both shipped geometries.
    ///
    /// The card draws through the viewport clip, so a line wider than the card is truncated
    /// INSIDE the panel: the bounds gate cannot see it and only a person holding the device
    /// can. That is how the gate line shipped 619 px too wide on the 800x480 panel, and how
    /// the digest line shipped cut mid-character on both. Measured against the WIDEST value
    /// each line can carry - a four-digit input count and a full 64-character digest - so a
    /// larger transaction cannot quietly bring it back.
    #[test]
    fn the_status_card_holds_every_line_it_draws() {
        let mut bad: Vec<String> = Vec::new();
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            for complete in [false, true] {
                let mut tx = signed(complete);
                tx.signed_inputs = 1000;
                tx.verified_inputs = 1000;
                tx.signable_inputs = 1000;
                let s = DeliverState::new(tx);
                let inner = s.layout(&f.ctx()).card.inset(CARD_PAD);
                let (headline, detail) = s.status();
                let gate = s.gate_line();
                let reviewed = s.reviewed_line();
                let rows: [(&str, &'static Atlas); 4] = [
                    (&headline, HEADING),
                    (&detail, CAPTION),
                    (&gate, MONO_SMALL),
                    (&reviewed, MONO_SMALL),
                ];
                for (line, font) in rows {
                    let lw = font.text_width(line) as i32;
                    if lw > inner.w {
                        bad.push(format!(
                            "{w}x{h} complete={complete}: {line:?} needs {lw} px in {} px",
                            inner.w
                        ));
                    }
                }
            }
        }
        assert!(
            bad.is_empty(),
            "the status card truncates its own copy:\n  {}",
            bad.join("\n  ")
        );
    }

    /// The digest line is a deliberate prefix, the same on every panel, and says that it
    /// is one. A digest silently cut by a clip reads as a whole digest.
    #[test]
    fn the_digest_line_is_a_marked_prefix() {
        let s = DeliverState::new(signed(true));
        let line = s.reviewed_line();
        assert_eq!(line, "reviewed file 0123456789abcdef0123...");
        assert!(s.signed.psbt_id.starts_with("0123456789abcdef0123"), "prefix of the digest");
        // A digest shorter than the cap is printed whole, with no marker claiming more.
        let mut short = signed(true);
        short.psbt_id = String::from("00");
        assert_eq!(DeliverState::new(short).reviewed_line(), "reviewed file 00");
    }

    fn label_of(id: RegionId) -> &'static str {
        action_label(id, false)
    }

    /// The same region set at both geometries in every state. Reflow rule 4.
    #[test]
    fn the_region_set_is_the_same_on_both_panels() {
        let a = Fixture::new(GEOMETRIES[0].0, GEOMETRIES[0].1);
        let b = Fixture::new(GEOMETRIES[1].0, GEOMETRIES[1].1);
        let mut sa = DeliverState::new(signed(true));
        let mut sb = DeliverState::new(signed(true));
        assert_eq!(ids(&sa, &a), ids(&sb, &b));
        for outcome in [WriteOutcome::NoCard, WriteOutcome::Failed(String::from("x."))] {
            drive(&mut sa, &a, RegionId::DeliverSd);
            drive(&mut sb, &b, RegionId::DeliverSd);
            answer(&mut sa, &a, Answer::Write(outcome.clone()));
            answer(&mut sb, &b, Answer::Write(outcome));
            assert_eq!(ids(&sa, &a), ids(&sb, &b));
        }
    }

    /// A partly signed multisig says so, and its status never claims to be broadcastable.
    #[test]
    fn a_partial_signature_says_it_needs_another_cosigner() {
        let mut tx = signed(false);
        tx.signed_inputs = 1;
        tx.verified_inputs = 1;
        tx.signable_inputs = 2;
        let s = DeliverState::new(tx);
        let (headline, detail) = s.status();
        assert_eq!(headline, "Signed - 1 of 2 inputs");
        assert!(detail.contains("still needs another cosigner"), "{detail}");
        assert!(!detail.contains("ready to broadcast"));
        assert!(s.gate_line().contains("1 of 1"), "the gate result is always shown");
        assert!(s.gate_line().starts_with("Signatures re-checked"), "{}", s.gate_line());
    }

    /// Every string this screen can put on the panel is ASCII and free of reassurance.
    #[test]
    fn the_copy_is_ascii_and_states_facts() {
        let f = Fixture::new(720, 720);
        let mut text = String::new();
        for band in [
            Band::Written(vec![Artifact { name: String::from("a.psbt"), bytes: 2600 }]),
            Band::NoCard,
            Band::Failed(String::from("Writing stopped after 1.2 kB.")),
            Band::NotDiscarded,
        ] {
            let mut s = DeliverState::new(signed(true));
            s.band = band;
            if let Some((copy, _)) = s.band_copy() {
                text.push_str(&copy);
                text.push('\n');
            }
            let (a, b) = s.status();
            text.push_str(&a);
            text.push_str(&b);
            text.push_str(&s.gate_line());
            text.push_str(&s.write_what());
            text.push_str(NOTHING_SECRET);
            for (id, _) in s.layout(&f.ctx()).actions {
                text.push_str(action_label(id, true));
                text.push_str(action_label(id, false));
            }
        }
        for busy in [Busy::Writing, Busy::Discarding] {
            let (a, b) = busy.copy();
            text.push_str(a);
            text.push_str(b);
            text.push_str(busy.trailing());
        }
        assert!(text.is_ascii(), "{text}");
        assert!(!text.contains('\u{2013}') && !text.contains('\u{2014}'));
        let lower = text.to_lowercase();
        for word in ["secure", "safe", "simply", "please", "sorry", "successfully", "oops"] {
            assert!(!lower.contains(word), "the copy says {word:?}");
        }
        assert!(text.contains(NOTHING_SECRET));
    }

    /// "Do not remove the card" belongs to a write in flight and to nothing else (C3).
    #[test]
    fn the_busy_frame_says_only_what_is_true() {
        assert_eq!(Busy::Writing.trailing(), "Do not remove the card.");
        assert_eq!(Busy::Discarding.trailing(), "This cannot be cancelled.");
    }



    /// Sizes read as S-28 prints them.
    #[test]
    fn sizes_are_kilobytes_with_one_decimal() {
        assert_eq!(kb(2600), "2.6 kB");
        assert_eq!(kb(400), "0.4 kB");
        assert_eq!(kb(0), "0.0 kB");
    }
}
