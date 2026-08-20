// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! S-49 Format card: make an unreadable card usable, and refuse in every case where that
//! would not be what happened.
//!
//! This is the most destructive thing the product offers. Every other destruction on this
//! device destroys something the device itself holds and can therefore describe - this one
//! erases a card whose contents the device has never seen and the user may not remember.
//! Three properties follow, and the whole screen is built out of them.
//!
//! # 1. The offer is not the screen's to make
//!
//! Nothing here decides that a format would help. The embedder probes the card
//! ([`UiRequest::ProbeCardFormat`]) and answers with either a [`FormatTarget`] or a
//! [`FormatRefusal`], and the destructive control exists ONLY in the first case - it is
//! not drawn, not hit-tested and not reachable in the second. That is deliberate placement
//! of the judgement: whether a card is blank, foreign, healthy, failing, absent, or fine
//! all along is a question about hardware and a partition table, and a screen that guessed
//! at it would be guessing with somebody's data.
//!
//! The refusals it renders are the point of the feature as much as the offer is. A card
//! that mounts perfectly, a slot with nothing in it, a card whose first sector will not
//! read, a card with two partitions, a card with no partition table: all of them arrive
//! here as a headline, a reason and a remedy, and none of them can be formatted from this
//! device at all.
//!
//! # 2. Consent is at the strongest grade this codebase has, and it is given twice
//!
//! C4d, reached through the ratified two-sheet sequence (`danger`): a Confirm sheet that
//! STATES the consequence, replaced by a Typed sheet that takes a word. Typed is defined
//! as "unrecoverable on this device", and erasing a card whose contents the device never
//! held is strictly worse than the three existing uses of it.
//!
//! The word is the CARD'S OWN IDENTITY - its capacity, "32GB" - on the precedent that
//! deleting a multisig registration types that registration's name. A fixed word would be
//! a ritual; this one can only be typed by somebody who has looked at what is on the panel,
//! and what is on the panel is the size of the card in their hand. The mistake that
//! actually happens is the wrong card in the slot, and this is the one gate that catches
//! it. The embedder checks the same word again against the card at write time, so a card
//! swapped between the sheet and the tap is refused rather than erased.
//!
//! # 3. Every state says what is true of the card RIGHT NOW
//!
//! Including the one nobody wants to write: a format that failed part-way leaves the card
//! in a state neither the device nor the user can describe, and [`FormatOutcome::Failed`]
//! carries `wrote` precisely so this screen can say that instead of reporting a generic
//! failure over it. Write protect is invisible to this firmware, so a locked card fails
//! exactly there - which makes that state common enough to be worth its own sentence
//! rather than rare enough to fold into another.
//!
//! # What is measured, and why the copy is short
//!
//! The well has no scroll and no pager: on the 800x480 panel the body holds one action
//! button and six lines above it, and half a warning drawn is worse than none. So the copy
//! is budgeted rather than written and hoped for - `the_copy_fits_every_state_on_both_panels`
//! measures every state's block, and the two sheets, against both shipped geometries at
//! the longest values the embedder can produce.

use alloc::string::String;
use alloc::vec::Vec;

use embedded_graphics::draw_target::DrawTarget;
use embedded_graphics::pixelcolor::Rgb565;

use crate::canvas::{button, panel, ButtonKind};
use crate::components::{back_rect, draw_bar};
use crate::danger::{Danger, DangerGrade, DangerOutcome};
use crate::layout::Rect;
use crate::screens::sdcard::{
    block_h, draw_block, draw_busy, fit_block, push_head, push_prose, push_untrusted, Line,
    WELL_PAD,
};
use crate::screens::{Answer, Ctx, Env, Nav, Outcome, Screen};
use crate::theme::*;
use crate::{
    FormatOffer, FormatOutcome, FormatRefusal, FormatTarget, Region, RegionId, ScreenId,
    UiRequest,
};

/// The heading of the C3 frame while the card is being looked at. It writes nothing, and
/// the frame under it says only that the panel will not move.
const READING: &str = "Reading card";
/// The heading of the C3 frame while the card is being ERASED. A different sentence
/// because it is a different promise: the frame's own "Do not remove the card" line stops
/// being advice here and becomes the difference between a formatted card and a brick.
const WRITING: &str = "Formatting the card";

/// The destructive button, and the sheet's. A verb naming the act, never "Confirm"
/// (3.3 decision 2), so a photograph of the moment of consent describes itself.
const ERASE: &str = "Erase this card";

/// Where the user is in the one flow this screen has.
///
/// A closed set with no "idle": the screen cannot exist without a probe in flight behind
/// it (see [`FormatCardState::open`]), because a panel showing a card's state with nothing
/// having looked at the card is a panel stating something it does not know.
enum Stage {
    /// [`UiRequest::ProbeCardFormat`] is in flight. C3 Busy.
    Probing,
    /// The card can be repaired, and this is what is in the slot.
    Ready(FormatTarget),
    /// It cannot, and this is why. No destructive control exists in this state.
    ///
    /// The code carries the frozen copy; the note is the embedder's machine detail and
    /// may be empty.
    Refused { why: FormatRefusal, note: String },
    /// [`UiRequest::FormatCard`] is in flight. C3 Busy, and the one frame in the product
    /// during which the user's own data is being overwritten.
    ///
    /// Carries NOTHING, deliberately. The obvious thing to keep here is the target the
    /// write was raised for, and it would be a second answer to "which card was erased" -
    /// one the screen remembered, sitting beside the one the embedder reports, free to
    /// disagree with it after a card swap. The sentence that lands names the card that was
    /// actually written, and that is the only one this screen shows.
    Writing,
    /// It worked. The sentence is the embedder's: it names the card and the partition it
    /// actually wrote, not the ones this screen asked for.
    Done(String),
    /// It did not. `wrote` is whether the card may already have been altered.
    Failed { why: String, wrote: bool },
}

impl Stage {
    /// True while a request is in flight: nothing is tappable and nothing moves until an
    /// answer lands.
    fn busy(&self) -> bool {
        matches!(self, Stage::Probing | Stage::Writing)
    }

    fn busy_heading(&self) -> &'static str {
        match self {
            Stage::Writing => WRITING,
            _ => READING,
        }
    }
}

pub(crate) struct FormatCardState {
    stage: Stage,
    /// The open consent sheet, if any. Two in sequence: the consequence, then the word.
    danger: Option<Danger>,
}

impl FormatCardState {
    /// Enter S-49 from Settings, with the probe that ends its Busy frame.
    ///
    /// The state and the request are built together and cannot be had apart, on S-27's
    /// rule: a Busy frame with no request behind it is a panel that never moves again, and
    /// this is the one call that opens the screen.
    pub(crate) fn open() -> Outcome {
        Outcome {
            nav: Nav::Push(crate::screens::State::FormatCard(FormatCardState {
                stage: Stage::Probing,
                danger: None,
            })),
            request: Some(UiRequest::ProbeCardFormat),
        }
    }

    pub(crate) fn id(&self) -> ScreenId {
        if self.stage.busy() {
            ScreenId::Working
        } else {
            ScreenId::FormatCard
        }
    }

    /// The card this screen would erase, if it is in a state where that means anything.
    fn target(&self) -> Option<&FormatTarget> {
        match &self.stage {
            Stage::Ready(t) => Some(t),
            _ => None,
        }
    }

    /// The stacked actions, top to bottom. Never empty at rest: a state with no way out is
    /// a trap, and every one of these states is reachable by accident.
    fn actions(&self) -> Vec<(RegionId, &'static str)> {
        match &self.stage {
            Stage::Probing | Stage::Writing => Vec::new(),
            // The ONE place a destructive control exists on this screen.
            Stage::Ready(_) => vec![(RegionId::CardFormat, ERASE)],
            // Everywhere else the only action is to look again - which is also the right
            // action after a successful format, because it comes back saying the card is
            // readable now, from the device rather than from this screen's own optimism.
            Stage::Refused { .. } | Stage::Done(_) | Stage::Failed { .. } => {
                vec![(RegionId::FileRefresh, "Check again")]
            }
        }
    }

    /// The well's copy, wrapped to `w`.
    ///
    /// Ordered headline, then what is true, then what would happen, then the machine
    /// detail - which is the order [`fit_block`] trims backwards through, so the only
    /// thing a panel this crate has never seen can cost is the last line.
    fn block(&self, w: i32) -> Vec<Line> {
        let mut out = Vec::new();
        match &self.stage {
            // Painted by `draw_busy`, never out of a well.
            Stage::Probing | Stage::Writing => {}
            Stage::Ready(t) => {
                push_head(&mut out, "This card cannot be read.", w);
                out.push(Line::detail(
                    format!("{} card, partition {}, {}", t.capacity, t.partition, t.volume),
                    INK_SECONDARY,
                ));
                // What the card SAYS it holds, from a byte somebody else wrote. Untrusted
                // for the same reason a file name is: it is rendered only if the atlas can
                // render it faithfully.
                push_untrusted(&mut out, &format!("It holds {}.", t.holds), w);
                // ONE sentence carrying three things, because the 800x480 well holds six
                // lines and each of the three has to be one of them: what is destroyed,
                // what is WRITTEN - invariant 2b, named before it happens - and that the
                // partition is not the thing being replaced. "into the partition it
                // already has" is the whole no-repartitioning claim, and it is the claim
                // `f_mkfs` is actually called in a way that keeps; see
                // `firmware::sd::format` for the single byte of the table that does change.
                push_prose(
                    &mut out,
                    "Formatting erases the card and writes an empty FAT filesystem into \
                     the partition it already has.",
                    w,
                );
                // The line a frightened reader is looking for, and it is on THIS screen
                // rather than only on the sheet one tap later. A user in front of a
                // full-panel erase warning who cannot tell whether their seed is what is
                // about to go has one safe-looking action left, and it is pulling the
                // power out.
                push_prose(&mut out, "No wallet or key on this device is affected.", w);
            }
            Stage::Refused { why, note } => {
                // Frozen copy first, in the crate's own voice and typography; the
                // embedder's machine detail last, where trimming can only cost a hex code.
                push_head(&mut out, why.headline(), w);
                push_prose(&mut out, &why.detail(), w);
                push_prose(&mut out, why.remedy(), w);
                push_untrusted(&mut out, note, w);
            }
            Stage::Done(sentence) => {
                push_head(&mut out, "The card was formatted.", w);
                push_untrusted(&mut out, sentence, w);
                push_prose(
                    &mut out,
                    "Everything that was on it is gone. Check again to confirm this device \
                     can now read it.",
                    w,
                );
            }
            Stage::Failed { why, wrote } => {
                push_head(&mut out, "The card was not formatted.", w);
                // The sentence that has to be there, and it is frozen here rather than
                // left to the embedder because it is the one line on this screen that
                // tells a user what to DO next. `wrote` is the difference between a user
                // who can carry on and a user who has to stop trusting the card; it is not
                // a shade of the same message, so it is not a shade of the same sentence.
                push_prose(
                    &mut out,
                    if *wrote {
                        "Part of it may already have been overwritten. Do not rely on \
                         anything that was on it, and format it on a computer before using \
                         it again."
                    } else {
                        "Nothing on the card was changed."
                    },
                    w,
                );
                push_untrusted(&mut out, why, w);
            }
        }
        out
    }

    /// The well's paper and hairline. Danger ink is worn by the two states that have
    /// earned it - the one offering to erase, and the one reporting that an erase was left
    /// half done - and by nothing else, so it keeps meaning something.
    fn well_colors(&self) -> (Rgb565, Rgb565) {
        match &self.stage {
            Stage::Ready(_) | Stage::Failed { wrote: true, .. } => (DANGER_TINT, DANGER),
            _ => (PAPER_2, BORDER_STRONG),
        }
    }

    /// C4b: the consequence, stated in full, with the answer that is not "yes".
    ///
    /// Four things have to survive any edit of this copy, and they are the four a user
    /// standing in front of it needs: everything on the card goes, the device cannot tell
    /// them what that is, it cannot be undone, and NOTHING on the device is at risk. The
    /// last is not reassurance for its own sake - a user faced with a full-panel erase
    /// warning has to know their seed is not what is being erased, or the only safe-looking
    /// action is to pull the power.
    fn review_sheet(t: &FormatTarget) -> Danger {
        Danger::confirm(
            "Erase everything on this card?",
            &[
                &format!(
                    "Everything on the {} card is destroyed. This device cannot see what \
                     is on it, so it cannot tell you what you would lose.",
                    t.capacity
                ),
                "This cannot be undone. No wallet, key or setting on this device is \
                 affected.",
            ],
            "Continue",
        )
    }

    /// C4d: the word, with the card restated so consent is given against what is in the
    /// slot rather than against a remembered sentence.
    ///
    /// One short line and nothing else: after its keyboard, its field and its action row
    /// the landscape sheet has three lines left, and the identity of the card is what
    /// earns them. What a format does was read on the sheet before this one.
    fn type_sheet(t: &FormatTarget) -> Danger {
        Danger::typed(
            "Erase everything on this card",
            &[&format!("Erasing the {} card in the slot.", t.capacity)],
            ERASE,
            &t.word,
        )
    }
}

pub(crate) struct Layout {
    well: Rect,
    lines: Vec<Line>,
    actions: Vec<(RegionId, &'static str, Rect)>,
}

impl Screen for FormatCardState {
    type Layout = Layout;

    fn layout(&self, ctx: &Ctx) -> Layout {
        let m = &ctx.m;
        let body = m.body();
        let actions = self.actions();
        let n = actions.len() as i32;
        let actions_h = if n == 0 { 0 } else { n * m.btn + (n - 1) * m.gap };
        // The well takes what the actions leave, and the copy is fitted to that rather
        // than the other way round: an action this screen cannot reach is worse than a
        // sentence this screen had to trim.
        let room = (body.h - actions_h - m.gap).max(0);
        let lines = fit_block(self.block(body.w - 2 * WELL_PAD), room);
        let well = Rect::new(body.x, body.y, body.w, block_h(&lines).min(room));

        let mut y = body.bottom() - actions_h;
        let mut laid = Vec::with_capacity(actions.len());
        for (id, label) in actions {
            laid.push((id, label, Rect::new(body.x, y, body.w, m.btn)));
            y += m.btn + m.gap;
        }
        Layout { well, lines, actions: laid }
    }

    fn regions(&self, ctx: &Ctx, out: &mut Vec<Region>) {
        // A sheet is MODAL: while one is open it is the only thing on the panel a finger
        // can reach, so the screen below it is as inert as it looks.
        if let Some(d) = &self.danger {
            d.regions(&ctx.m, out);
            return;
        }
        // C3: a Busy frame offers nothing, not even Back. Both operations behind it are
        // single blocking calls on the std side and neither can be cancelled, so a live
        // control would be a lie about what the loop can do - and during a format it would
        // be a lie with a half-written card behind it.
        if self.stage.busy() {
            return;
        }
        let l = self.layout(ctx);
        out.push(Region { id: RegionId::Back, rect: back_rect(&ctx.m) });
        for (id, _, rect) in l.actions {
            out.push(Region { id, rect });
        }
    }

    fn draw<D: DrawTarget<Color = Rgb565>>(&self, t: &mut D, ctx: &Ctx) -> Result<(), D::Error> {
        let m = &ctx.m;
        if let Some(d) = &self.danger {
            return d.draw(t, m, ctx.press, ctx.hold_released);
        }
        if self.stage.busy() {
            return draw_busy(t, m, self.stage.busy_heading());
        }
        draw_bar(t, m, "Format card")?;
        let l = self.layout(ctx);
        let (paper, edge) = self.well_colors();
        panel(t, l.well, paper, edge)?;
        draw_block(t, l.well, &l.lines, paper)?;
        for (id, label, rect) in &l.actions {
            let kind = if *id == RegionId::CardFormat {
                ButtonKind::Danger
            } else {
                ButtonKind::Primary
            };
            button(t, *rect, label, kind, PAPER_1)?;
        }
        Ok(())
    }

    fn activate(&mut self, id: RegionId, _env: &mut Env) -> Outcome {
        // The sheet, while open, answers for the whole screen.
        if let Some(d) = &mut self.danger {
            let outcome = d.activate(id);
            let grade = d.grade();
            return match outcome {
                // This sheet offers no third answer, so the region is never emitted and
                // the arm cannot be reached from a tap. There is no honest alternative to
                // offer: the one thing that would remove the reason for this warning is
                // done on another machine, and a button that only closed the sheet while
                // claiming to do it would be the worst kind of lie on the worst kind of
                // screen. The remedy is said in words instead, on every refusal.
                DangerOutcome::Open | DangerOutcome::Alternative => Outcome::stay(),
                DangerOutcome::Cancelled => {
                    self.danger = None;
                    Outcome::stay()
                }
                DangerOutcome::Confirmed => match grade {
                    // The consequence has been read; the word is next. NEVER the write:
                    // this is the arm that would turn a two-sheet consent into a one-tap
                    // erase if it were ever written as anything else.
                    DangerGrade::Confirm => {
                        self.danger = self.target().map(FormatCardState::type_sheet);
                        Outcome::stay()
                    }
                    // Consent complete. Everything below is ordered so that the panel is
                    // already on the Busy frame, and the sheet already gone, before the
                    // request leaves - a tap arriving behind a sheet that had not closed
                    // could otherwise ask for the same destruction twice.
                    _ => {
                        // Not reachable with `None`: a typed sheet only ever exists over
                        // `Ready`. It is written as a refusal rather than an `unwrap`
                        // because the one thing worse than this screen doing nothing is
                        // this screen erasing a card it had lost track of.
                        let Some(target) = self.target() else {
                            self.danger = None;
                            return Outcome::stay();
                        };
                        let request = UiRequest::FormatCard {
                            partition: target.partition,
                            card: target.word.clone(),
                        };
                        self.danger = None;
                        self.stage = Stage::Writing;
                        Outcome::ask(request)
                    }
                },
            };
        }
        match id {
            // Opens the first of the two sheets, and only where there is something to
            // erase. `actions` does not emit this region in any other state, so this is
            // the second of two independent reasons the write is unreachable from them.
            RegionId::CardFormat => {
                let Some(target) = self.target() else { return Outcome::stay() };
                self.danger = Some(FormatCardState::review_sheet(target));
                Outcome::stay()
            }
            RegionId::FileRefresh => {
                self.stage = Stage::Probing;
                Outcome::ask(UiRequest::ProbeCardFormat)
            }
            _ => Outcome::stay(),
        }
    }

    fn answered(&mut self, answer: Answer, _env: &mut Env) -> Outcome {
        match answer {
            // An answer that arrives while this screen is not waiting for one belongs to a
            // tap the user has moved on from, and must not move the panel back.
            Answer::FormatOffer(offer) if matches!(self.stage, Stage::Probing) => {
                self.stage = match offer {
                    FormatOffer::Ready(target) => Stage::Ready(target),
                    FormatOffer::Refused { why, note } => Stage::Refused { why, note },
                };
                Outcome::stay()
            }
            Answer::Formatted(outcome) if matches!(self.stage, Stage::Writing) => {
                self.stage = match outcome {
                    FormatOutcome::Done(sentence) => Stage::Done(sentence),
                    FormatOutcome::Failed { why, wrote } => Stage::Failed { why, wrote },
                };
                Outcome::stay()
            }
            _ => Outcome::stay(),
        }
    }

    /// Back is Settings. Frozen while a request is in flight - `regions` emits no Back
    /// there, so this cannot be reached from a tap either, and both halves say the same
    /// thing rather than one relying on the other.
    fn back(&self) -> Nav {
        if self.stage.busy() {
            Nav::Stay
        } else {
            Nav::Back
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::UnlockGate;
    use super::*;
    use crate::layout::Metrics;
    use crate::screens::testing::{rows_are_clear_on, Fixture, GEOMETRIES};
    use crate::screens::State;

    /// The longest values the embedder can hand this screen, so the copy is measured
    /// against the worst case rather than against a pleasant one.
    ///
    /// `holds` is the longest string `firmware::sd::probe::kind_label` produces and
    /// `capacity` the widest a card renders as; the refusal is the longest of the six
    /// `firmware::sd::probe::Refusal` renderings plus the mount-time ones around them.
    fn worst_target() -> FormatTarget {
        FormatTarget {
            partition: 4,
            capacity: String::from("1024 GB"),
            word: String::from("1024GB"),
            holds: String::from("an unrecognised filesystem"),
            volume: String::from("1024 GB"),
        }
    }

    /// The refusal whose three frozen sentences are the longest, with the longest note an
    /// embedder can hang off it.
    ///
    /// Picked by MEASUREMENT rather than by eye - see
    /// `the_copy_fits_every_state_on_both_panels`, which walks `FormatRefusal::ALL` and
    /// would fail on any of them.
    fn worst_refusal() -> Stage {
        Stage::Refused {
            why: FormatRefusal::Hardware,
            note: String::from("esp_err=0x105"),
        }
    }

    fn at(stage: Stage) -> FormatCardState {
        FormatCardState { stage, danger: None }
    }

    /// Walk the whole consent sequence, tapping exactly what a finger can reach.
    ///
    /// Returns every request the screen raised, in order, which is what the gate tests
    /// below assert about: the write is a request, so "the write did not happen" is
    /// "no `FormatCard` request was raised".
    fn drive(state: &mut FormatCardState, taps: &[RegionId]) -> Vec<UiRequest> {
        let mut network = notyas_core::bitcoin::Network::Bitcoin;
        let lock = crate::LockInfo::default();
        let wallets: Vec<crate::WalletRow> = Vec::new();
        let mut env = Env {
            network: &mut network,
            lock: &lock,
            wallets: &wallets,
            gate: &mut UnlockGate::default(),
        };
        let mut out = Vec::new();
        for id in taps {
            if let Some(r) = state.activate(*id, &mut env).request {
                out.push(r);
            }
        }
        out
    }

    fn typed_word(word: &str) -> Vec<RegionId> {
        word.chars().map(RegionId::Key).collect()
    }

    // --- the gate ------------------------------------------------------------------------

    /// THE property this screen exists for: a card is never erased without the C4d word.
    ///
    /// Every intermediate tap is checked too, because "the last tap did not do it" is not
    /// the claim - the claim is that no prefix of this sequence writes anything.
    #[test]
    fn the_write_is_unreachable_until_the_card_is_typed_back() {
        let target = worst_target();
        let mut s = at(Stage::Ready(target.clone()));

        // Opening the first sheet asks for nothing.
        assert!(drive(&mut s, &[RegionId::CardFormat]).is_empty());
        // Reading the consequence asks for nothing: it opens the SECOND sheet.
        assert!(drive(&mut s, &[RegionId::DangerConfirm]).is_empty());
        assert_eq!(
            s.danger.as_ref().map(Danger::grade),
            Some(DangerGrade::Typed),
            "the confirm sheet must lead to the typed sheet and never to the write"
        );
        // The confirm is drawn disabled until the word matches, and a tap on it does
        // nothing - before anything is typed, and after the WRONG thing is typed.
        assert!(drive(&mut s, &[RegionId::DangerConfirm]).is_empty());
        let mut wrong = typed_word("1024TB");
        wrong.push(RegionId::DangerConfirm);
        assert!(
            drive(&mut s, &wrong).is_empty(),
            "a card that was not the one on the panel must not be erasable"
        );
        // ...and the keyboard's own Done is the same control, so it is gated the same way.
        assert!(drive(&mut s, &[RegionId::KeyDone]).is_empty());

        // Clear the wrong word and type the right one.
        let mut right: Vec<RegionId> = (0..6).map(|_| RegionId::KeyBackspace).collect();
        right.extend(typed_word(&target.word));
        assert!(drive(&mut s, &right).is_empty(), "typing alone must not write");
        let raised = drive(&mut s, &[RegionId::DangerConfirm]);
        assert_eq!(
            raised,
            vec![UiRequest::FormatCard { partition: 4, card: String::from("1024GB") }],
            "the write must name the partition and the card consent was given for"
        );
        assert!(s.danger.is_none(), "the sheet closes before the request goes out");
        assert!(matches!(s.stage, Stage::Writing), "the panel must already be on the frame");

        // And a second tap on the same region cannot ask for it again.
        assert!(drive(&mut s, &[RegionId::DangerConfirm]).is_empty());
    }

    /// Cancelling either sheet leaves the card alone and the screen where it was.
    #[test]
    fn cancelling_either_sheet_writes_nothing() {
        for after in [Vec::new(), vec![RegionId::DangerConfirm]] {
            let mut s = at(Stage::Ready(worst_target()));
            let mut taps = vec![RegionId::CardFormat];
            taps.extend(after);
            taps.push(RegionId::DangerCancel);
            assert!(drive(&mut s, &taps).is_empty());
            assert!(s.danger.is_none());
            assert!(matches!(s.stage, Stage::Ready(_)), "cancel must not change the card");
        }
    }

    /// The states where a format would not help offer no way to start one - not as a
    /// region, and not as a tap that arrives some other way.
    ///
    /// Both halves are asserted because they are independent defences: `actions` decides
    /// what is drawn and hit-tested, `activate` decides what a `RegionId` means. A screen
    /// that relied on the first alone would be one mis-routed tap from an erase.
    #[test]
    fn no_state_but_ready_can_start_a_format() {
        let f = Fixture::new(720, 720);
        let ctx = f.ctx();
        let states = [
            Stage::Probing,
            worst_refusal(),
            Stage::Writing,
            Stage::Done(String::from("The 32 GB card now holds one empty FAT filesystem.")),
            Stage::Failed { why: String::from("The card refused the write."), wrote: false },
            Stage::Failed { why: String::from("The card refused the write."), wrote: true },
        ];
        for stage in states {
            let mut s = at(stage);
            let mut out = Vec::new();
            s.regions(&ctx, &mut out);
            assert!(
                !out.iter().any(|r| r.id == RegionId::CardFormat),
                "a state that cannot be formatted must not offer the control"
            );
            assert!(
                drive(&mut s, &[RegionId::CardFormat]).is_empty(),
                "and must not act on it if the tap arrives anyway"
            );
            assert!(s.danger.is_none(), "no consent sheet may open over it");
        }
    }

    /// A Busy frame is inert, Back included. The format is a single blocking call that
    /// cannot be cancelled, and a Back that appeared to cancel it would be the one control
    /// on this device that lies about a write in flight.
    #[test]
    fn the_busy_frames_offer_nothing() {
        let f = Fixture::new(800, 480);
        let ctx = f.ctx();
        for stage in [Stage::Probing, Stage::Writing] {
            let s = at(stage);
            let mut out = Vec::new();
            s.regions(&ctx, &mut out);
            assert!(out.is_empty(), "a C3 frame offers nothing");
            assert!(matches!(s.back(), Nav::Stay));
            assert_eq!(s.id(), ScreenId::Working);
        }
    }

    /// An answer that belongs to a tap the user has moved on from is dropped, and - the
    /// half that matters - a format answer can never install itself over a state that
    /// never asked for a format.
    #[test]
    fn a_late_answer_cannot_move_the_panel() {
        let mut network = notyas_core::bitcoin::Network::Bitcoin;
        let lock = crate::LockInfo::default();
        let wallets: Vec<crate::WalletRow> = Vec::new();
        let mut env = Env {
            network: &mut network,
            lock: &lock,
            wallets: &wallets,
            gate: &mut UnlockGate::default(),
        };

        let mut s = at(Stage::Ready(worst_target()));
        s.answered(Answer::Formatted(FormatOutcome::Done(String::from("done"))), &mut env);
        assert!(matches!(s.stage, Stage::Ready(_)), "a format nobody asked for is dropped");

        let mut s = at(worst_refusal());
        s.answered(
            Answer::FormatOffer(FormatOffer::Ready(worst_target())),
            &mut env,
        );
        assert!(
            matches!(s.stage, Stage::Refused { .. }),
            "a stale offer must not arm the screen"
        );
    }

    /// Opening the screen and raising its probe are one act.
    #[test]
    fn opening_the_screen_asks_the_card() {
        let out = FormatCardState::open();
        assert!(matches!(out.request, Some(UiRequest::ProbeCardFormat)));
        match out.nav {
            Nav::Push(State::FormatCard(s)) => assert!(matches!(s.stage, Stage::Probing)),
            _ => panic!("S-49 is pushed over Settings"),
        }
    }

    // --- geometry ------------------------------------------------------------------------

    /// The copy FITS, in every state, on both shipped panels, at the longest values the
    /// embedder can produce.
    ///
    /// There is no scroll and no pager behind this well. A block that overflows is trimmed
    /// with a visible ellipsis, which is the right behaviour for a panel this crate has
    /// never seen and the wrong outcome for one it ships on: half a warning about erasing
    /// somebody's card is worse than none.
    #[test]
    fn the_copy_fits_every_state_on_both_panels() {
        for (w, h) in GEOMETRIES {
            let m = Metrics::new(w, h);
            // Every refusal, not the one that looked longest: the copy is frozen in this
            // crate, so this is a complete check of it rather than a sample.
            for why in FormatRefusal::ALL {
                let s = at(Stage::Refused { why, note: String::from("esp_err=0x105") });
                let actions = s.actions().len() as i32;
                let actions_h = actions * m.btn + (actions - 1).max(0) * m.gap;
                let room = m.body().h - actions_h - m.gap;
                // The note is allowed to be trimmed and the three sentences are not, so the
                // three are what is measured.
                let mut fixed = Vec::new();
                push_head(&mut fixed, why.headline(), m.body().w - 2 * WELL_PAD);
                push_prose(&mut fixed, &why.detail(), m.body().w - 2 * WELL_PAD);
                push_prose(&mut fixed, why.remedy(), m.body().w - 2 * WELL_PAD);
                let need = block_h(&fixed);
                assert!(need <= room, "{w}x{h} {why:?}: the refusal needs {need} px of {room}");
            }
            let states = [
                ("ready", Stage::Ready(worst_target())),
                (
                    "done",
                    Stage::Done(String::from(
                        "The 1024 GB card now holds one empty FAT filesystem in partition 4. \
                         Its partition layout is unchanged.",
                    )),
                ),
                (
                    "failed",
                    Stage::Failed {
                        // The longest sentence `firmware::sd::format` produces on the path
                        // that sets `wrote`, which is also the worst case: it is the state
                        // with the most fixed copy above it.
                        why: String::from(
                            "The card refused the write (FatFs error 1). A write-protect \
                             switch on the card or its adapter fails like this.",
                        ),
                        wrote: true,
                    },
                ),
            ];
            for (name, stage) in states {
                let s = at(stage);
                let actions = s.actions().len() as i32;
                let actions_h = actions * m.btn + (actions - 1).max(0) * m.gap;
                let room = m.body().h - actions_h - m.gap;
                let need = block_h(&s.block(m.body().w - 2 * WELL_PAD));
                assert!(
                    need <= room,
                    "{w}x{h} {name}: the copy needs {need} px of {room}"
                );
            }
        }
    }

    /// Both consent sheets fit too, at both geometries. The sheet has no scroll either,
    /// and it is the surface carrying the four statements this feature is not allowed to
    /// ship without.
    #[test]
    fn both_consent_sheets_fit_on_both_panels() {
        for (w, h) in GEOMETRIES {
            let m = Metrics::new(w, h);
            let t = worst_target();
            for (name, sheet) in [
                ("confirm", FormatCardState::review_sheet(&t)),
                ("typed", FormatCardState::type_sheet(&t)),
            ] {
                let (used, have) = sheet.text_budget(&m);
                assert!(used <= have, "{w}x{h} {name}: the consequence needs {used} px of {have}");
            }
        }
    }

    /// Nothing this screen measures escapes the panel or lands on anything else, in any
    /// state - the class of defect a region check cannot see, because a well and a button
    /// that overlap are still two perfectly valid rectangles.
    #[test]
    fn the_furniture_is_clear_in_every_state_on_both_panels() {
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            let ctx = f.ctx();
            for (name, stage) in [
                ("ready", Stage::Ready(worst_target())),
                ("refused", worst_refusal()),
                ("done", Stage::Done(String::from("Formatted."))),
                (
                    "failed",
                    Stage::Failed { why: String::from("It did not work."), wrote: true },
                ),
            ] {
                let s = at(stage);
                let l = s.layout(&ctx);
                let mut rows = vec![("well", l.well)];
                for (_, label, rect) in &l.actions {
                    rows.push((*label, *rect));
                }
                rows_are_clear_on(&ctx.m, &format!("{w}x{h} {name}"), ctx.m.body(), &rows);
            }
        }
    }

    /// Every action is a real touch target, and the destructive one is not smaller or
    /// easier to hit than the way out.
    #[test]
    fn every_action_clears_the_touch_floor() {
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            let ctx = f.ctx();
            for stage in [
                Stage::Ready(worst_target()),
                worst_refusal(),
                Stage::Done(String::from("Formatted.")),
            ] {
                let s = at(stage);
                for (_, label, rect) in s.layout(&ctx).actions {
                    assert!(
                        rect.h >= crate::layout::TOUCH_MIN && rect.w >= crate::layout::TOUCH_MIN,
                        "{w}x{h}: {label:?} is {}x{}",
                        rect.w,
                        rect.h
                    );
                }
            }
        }
    }
}
