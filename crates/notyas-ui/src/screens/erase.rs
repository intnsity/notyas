// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! S-47b: the last moment the words exist on this device.
//!
//! # Why this is a screen and not a fourth danger sheet
//!
//! Consent has already been given. The user tapped Delete, read the C4b consequence, and
//! typed the wallet's own name into the C4d sheet. This screen asks for nothing more; it
//! OFFERS something - one last look at the recovery words - and then does what was
//! consented to. The product's grammar for "here are two legitimate choices" is a pair of
//! equal cards (S-19's fork), not a danger sheet, and using the sheet here would say the
//! wrong thing twice over: it would re-ask a question already answered, and it would put
//! the destructive answer at the same coordinates the typed sheet's confirm occupied a
//! frame earlier. That last point is not cosmetic. A user who has just been told nothing
//! happened is a user who taps twice, and a second tap landing on an armed confirm is the
//! whole failure this release exists to fix arriving from the opposite direction.
//!
//! # The choice is balanced by construction
//!
//! The two cards are the same size, in the same row, drawn by one function with no
//! parameter that could make either louder - the arithmetic is S-19's, for the same
//! reason. Neither is pre-selected, neither costs an extra gesture, neither is tinted as
//! the danger. What separates them is a FACT ABOUT THE READER, stated on each card in the
//! same voice and at the same length: one is for somebody whose backup is written down and
//! checked, the other for somebody who wants to check it. A user with a backup is not
//! nagged, and a user without one is not led past the offer, because the device never
//! guesses which of the two they are - it prints both conditions and lets them recognise
//! their own.
//!
//! # What it announces before it writes
//!
//! Invariant 2b: the write is on the panel before it happens, naming what is written -
//! filler over a numbered wallet slot and over its registrations. The C3 busy frame names
//! it again while it runs, and the answer lands on the wallet list, which is the evidence
//! either way.

use alloc::string::String;
use alloc::vec::Vec;

use embedded_graphics::draw_target::{DrawTarget, DrawTargetExt};
use embedded_graphics::pixelcolor::Rgb565;

use crate::canvas::{fill, frame, text, wrap_words, BODY, HEADING};
use crate::components::{back_rect, draw_bar, draw_bar_no_back, LINE, SMALL_LINE};
use crate::layout::{Metrics, Rect, LIST_ROW_MIN};
use crate::screens::mnemonic::MnemonicState;
use crate::screens::wallets::WalletsState;
use crate::screens::{Answer, Ctx, Env, Nav, Outcome, Screen, State};
use crate::theme::*;
use crate::{Region, RegionId, ScreenId, UiRequest, WordsOutcome};

/// What this screen is doing right now.
///
/// One enum rather than a pair of flags: the two are mutually exclusive by construction and
/// `regions` returns exactly the controls the current one has. A busy frame with a live
/// Erase card under it is a second erase one tap away from the first.
pub(crate) enum Mode {
    /// The choice is on the panel.
    Choose,
    /// A request is in flight. The string is what the frame says it is doing.
    Busy(&'static str),
}

pub(crate) struct EraseState {
    slot: u8,
    name: String,
    registrations: u8,
    mode: Mode,
    /// Why the words could not be shown, when they could not.
    ///
    /// Rendered here rather than bounced to the wallet list, because a failure to READ the
    /// words changes nothing about the wallet and the user is still mid-decision. A failure
    /// of the ERASE is the opposite and leaves this screen entirely - see [`Screen::answered`].
    notice: Option<String>,
}

impl EraseState {
    pub(crate) fn new(slot: u8, name: &str, registrations: u8) -> EraseState {
        EraseState {
            slot,
            name: String::from(name),
            registrations,
            mode: Mode::Choose,
            notice: None,
        }
    }

    pub(crate) fn id(&self) -> ScreenId {
        match self.mode {
            Mode::Busy(_) => ScreenId::Working,
            Mode::Choose => ScreenId::EraseWallet,
        }
    }

    /// Which slot this step is about.
    ///
    /// Read by the `Ui` when the erase is answered, because a slot that has stopped
    /// holding a wallet is a slot the passphrase retry gate has to forget - and the
    /// answer itself ([`crate::DeleteOutcome`]) carries what happened rather than which
    /// record it happened to. This screen is the only thing on the device that still
    /// knows.
    pub(crate) fn slot(&self) -> u8 {
        self.slot
    }

    /// Invariant 2b, in one sentence: what is written, and where.
    ///
    /// "Filler" rather than "erases" because that is what happens - `Vault::clear` under
    /// `Occupancy::AlwaysFilled` rewrites the slot with device-derived filler, and a device
    /// that said "erases" would be describing the mode it deliberately does not run in.
    fn announcement(&self) -> String {
        match self.registrations {
            0 => format!("Writes device filler over wallet slot {}.", self.slot),
            1 => format!(
                "Writes device filler over wallet slot {} and its 1 registration.",
                self.slot
            ),
            n => format!(
                "Writes device filler over wallet slot {} and its {n} registrations.",
                self.slot
            ),
        }
    }

    /// The prose above the cards, in the order it is read.
    ///
    /// Three paragraphs at most, and the Q22 line is the one that gives way: it is a fact
    /// about the completeness of the backup the user is about to be SHOWN, so on a frame
    /// where the words could not be read it has no subject, and its space goes to the
    /// sentence saying why they could not.
    fn prose(&self) -> Vec<String> {
        let mut out = alloc::vec![self.announcement(), String::from(AFTERWARDS)];
        match &self.notice {
            Some(n) => out.push(n.clone()),
            None => out.push(String::from(PASSPHRASE)),
        }
        out
    }
}

/// The consequence, stated once. Named, not asked about (UX-SCREENS 0.4: never "Are you
/// sure?").
const AFTERWARDS: &str =
    "After this the device cannot show these words again and cannot recover this wallet.";

/// Q22's fourth placement. Unconditional, because it has to be: a stored wallet's row
/// carries `passphrase: false` whether or not one was applied - the record holds no such
/// flag and cannot (Q22 keeps the passphrase out of storage entirely) - so a conditional
/// line here would be a line that is wrong exactly when it matters.
const PASSPHRASE: &str =
    "A BIP-39 passphrase is never stored here. If this wallet has one, these words alone \
     will not open it.";

/// The two halves of the offer: a title and the one condition that selects it.
///
/// Same shape, same length, same voice, and neither carries an adjective. See the module
/// docs for why that is the whole answer to "which of these is the default".
const SHOW_CARD: [&str; 2] = ["Show the words", "check your backup"];
const ERASE_CARD: [&str; 2] = ["Erase now", "backup is checked"];

/// What the C3 frame says while the erase runs. `&'static` so the busy state cannot carry a
/// sentence assembled from something that changed under it.
const BUSY_ERASING: &str = "Erasing wallet slot";
const BUSY_READING: &str = "Reading the recovery words";

/// Longest failure sentence this screen wraps. The embedder's text is unbounded, and a
/// wrap over an unbounded string is work this layout does not get to choose the size of, so
/// it is cut before the wrap - the wallet list's rule. What survives the wrap is then cut
/// again, to the lines the panel actually has (see [`Layout`]).
const NOTICE_MAX: usize = 160;

/// The cut marker. The same three characters the wallet list uses, for the same reason: a
/// sentence that was shortened has to say so, or the user reads a truncation as the whole
/// message.
const CUT: &str = "...";

/// The height a card `w` px wide needs for its copy in full: the title, whatever the
/// condition line wraps to, and the card's own padding.
///
/// Measured over BOTH cards with the taller winning, so the pair cannot be sized to the
/// shorter copy - which would crop the other one, and a cropped card is the same nudge as
/// an unequal one drawn deliberately.
fn card_copy_h(w: i32, gap: i32) -> i32 {
    let inner = w - 2 * gap;
    let text: i32 = [&SHOW_CARD, &ERASE_CARD]
        .into_iter()
        .map(|c| LINE + wrap_words(c[1], inner, BODY).len() as i32 * SMALL_LINE)
        .max()
        .unwrap_or(LINE);
    text + 2 * gap
}

pub(crate) struct Layout {
    /// Where the prose is drawn, and the paragraphs already wrapped to the width they will
    /// be drawn at - one `Vec<String>` per paragraph, because the space BETWEEN paragraphs
    /// is a gap and not a blank line. On the 800x480 panel the difference is two of the
    /// five lines this screen has room for.
    prose: (Rect, Vec<Vec<String>>),
    show: Rect,
    erase: Rect,
}

/// Pixels a wrapped prose block occupies.
///
/// Lines ADVANCE by [`SMALL_LINE`] and the last line of each paragraph is measured at its
/// full glyph box, which is the wallet list's arithmetic and is here for the same reason:
/// measured at the advance, the paragraph below crosses the descenders of the one above.
/// The advance is the tight one because the 800x480 body is 377 px and this screen has six
/// lines of consequence to fit above two cards - at [`LINE`] it does not, and a consequence
/// that does not fit is a consequence that is not read.
fn para_h(lines: usize) -> i32 {
    (lines as i32 - 1).max(0) * SMALL_LINE + BODY.line_height as i32
}

fn prose_h(paras: &[Vec<String>], gap: i32) -> i32 {
    let text: i32 = paras.iter().map(|p| para_h(p.len())).sum();
    text + (paras.len() as i32 - 1).max(0) * gap
}

/// How many lines a paragraph may have in `room` pixels. At least one: a failure sentence
/// cut to nothing is the defect this whole route exists to fix.
fn lines_in(room: i32) -> i32 {
    ((room - BODY.line_height as i32) / SMALL_LINE + 1).max(1)
}

/// The two cards' rectangles, and the height they share.
///
/// Returns `(show, erase, h)`. Side by side rather than stacked because the 800x480 body is
/// 377 px and two stacked cards plus the consequence do not fit in it - and because one row
/// of two makes "these are the same size" a thing the eye checks rather than a thing the
/// code claims. The titles are short enough to survive half a body at heading size on both
/// shipped panels, which is asserted rather than assumed.
///
/// # Why the ERASE is on the left
///
/// Because the frame before this one was the C4d sheet, whose confirm sits in the BOTTOM
/// RIGHT of the body - and these cards are bottom-anchored, so whichever of them is on the
/// right stands where that confirm stood a moment ago. A user who has just been told
/// nothing happened taps twice; a user typing a name into a sheet may double-tap the button
/// that ends it. The right-hand card is therefore the harmless one: a second tap in the
/// same place opens the masked words screen, which shows nothing without S-13's gate and
/// comes straight back.
///
/// This is not a weighting. In this product's grammar weight is SIZE, TINT and GESTURE
/// COST, all three of which are identical here and asserted to be - and the one other
/// deliberately equal pair, S-19's fork, likewise puts the more consequential half first.
fn cards(body: &Rect, m: &Metrics) -> (Rect, Rect, i32) {
    let g = m.gap;
    let w = (body.w - g) / 2;
    let h = card_copy_h(w, g).max(LIST_ROW_MIN);
    let y = body.bottom() - h;
    (
        Rect::new(body.right() - w, y, w, h),
        Rect::new(body.x, y, w, h),
        h,
    )
}

impl Screen for EraseState {
    type Layout = Layout;

    fn layout(&self, ctx: &Ctx) -> Layout {
        let m = &ctx.m;
        let body = m.body();
        let (show, erase, h) = cards(&body, m);
        let area = Rect::new(body.x, body.y, body.w, body.h - h - m.gap);
        let mut paras: Vec<Vec<String>> = self
            .prose()
            .iter()
            .map(|p| wrap_words(p, area.w, BODY))
            .collect();
        // The announcement and the consequence are never cut: one is invariant 2b and the
        // other is the whole reason this screen exists. What gives way is the LAST
        // paragraph, which is the embedder's failure sentence when there is one and the
        // Q22 line when there is not - and the Q22 line is a constant this crate measures,
        // so in practice only an embedder's sentence is ever shortened here.
        if let Some(last) = paras.pop() {
            let room = area.h - prose_h(&paras, m.gap) - m.gap;
            paras.push(trim_lines(last, lines_in(room)));
        }
        Layout { prose: (area, paras), show, erase }
    }

    fn regions(&self, ctx: &Ctx, out: &mut Vec<Region>) {
        // A C3 frame has nothing tappable, Back included: the erase is running and there is
        // nothing to go back to until it answers.
        if matches!(self.mode, Mode::Busy(_)) {
            return;
        }
        let l = self.layout(ctx);
        out.push(Region { id: RegionId::Back, rect: back_rect(&ctx.m) });
        out.push(Region { id: RegionId::EraseShowWords, rect: l.show });
        out.push(Region { id: RegionId::EraseNow, rect: l.erase });
    }

    fn draw<D: DrawTarget<Color = Rgb565>>(&self, t: &mut D, ctx: &Ctx) -> Result<(), D::Error> {
        let m = &ctx.m;
        if let Mode::Busy(what) = self.mode {
            // The write is named again WHILE it happens, with the slot in it, so a
            // photograph of this frame says which slot was being written. The read has its
            // own pair of lines and says the opposite in as many words: a frame that
            // announced a write during a read would be announcing one that is not
            // happening, which is the same defect as not announcing one that is.
            let (title, line) = if what == BUSY_ERASING {
                (format!("{what} {}", self.slot), self.announcement())
            } else {
                (
                    String::from(what),
                    format!("Reading wallet slot {}. Nothing is written.", self.slot),
                )
            };
            draw_bar_no_back(t, m, &title)?;
            let body = m.body();
            let mut y = body.y;
            for line in wrap_words(&line, body.w, BODY) {
                text(t, &line, body.x, y, BODY, INK_SECONDARY, PAPER_1)?;
                y += LINE;
            }
            return Ok(());
        }

        draw_bar(t, m, "Before the erase")?;
        let l = self.layout(ctx);

        // The prose. The failure sentence, when there is one, is the LAST paragraph and is
        // drawn in warning ink - nothing has been destroyed at that point, and danger ink
        // would say otherwise.
        let (area, paras) = &l.prose;
        let mut clip = t.clipped(&area.to_eg());
        let mut y = area.y;
        let last = paras.len().saturating_sub(1);
        for (i, para) in paras.iter().enumerate() {
            let ink = if self.notice.is_some() && i == last { WARNING } else { INK_PRIMARY };
            for line in para {
                text(&mut clip, line, area.x, y, BODY, ink, PAPER_1)?;
                y += SMALL_LINE;
            }
            // Back off the last line's advance and add its full box, so the paragraph ends
            // where `para_h` says it does.
            y += BODY.line_height as i32 - SMALL_LINE + m.gap;
        }

        card(t, l.show, &SHOW_CARD, m.gap)?;
        card(t, l.erase, &ERASE_CARD, m.gap)?;
        Ok(())
    }

    fn activate(&mut self, id: RegionId, _env: &mut Env) -> Outcome {
        if matches!(self.mode, Mode::Busy(_)) {
            return Outcome::stay();
        }
        match id {
            // The UI holds no flash and no key ladder, so it cannot read a record: it asks,
            // and the answer either carries the words or says why not.
            RegionId::EraseShowWords => {
                self.notice = None;
                self.mode = Mode::Busy(BUSY_READING);
                Outcome::ask(UiRequest::RecoveryWords(self.slot))
            }
            RegionId::EraseNow => {
                self.mode = Mode::Busy(BUSY_ERASING);
                Outcome::ask(UiRequest::DeleteWallet(self.slot))
            }
            _ => Outcome::stay(),
        }
    }

    fn answered(&mut self, answer: Answer, _env: &mut Env) -> Outcome {
        match answer {
            // Pushed, so Done on the words screen comes back here and the choice is still
            // open: reading the words is not consent to anything and must not advance the
            // flow by itself.
            Answer::RecoveryWords(WordsOutcome::Words(phrase)) => {
                self.mode = Mode::Choose;
                Outcome::push(State::Mnemonic(MnemonicState::stored(phrase)))
            }
            Answer::RecoveryWords(WordsOutcome::Refused(why)) => {
                self.mode = Mode::Choose;
                self.notice = Some(cut(&why));
                Outcome::stay()
            }
            // Every ending lands on the wallet list, which is re-read from the flash after
            // the write and is therefore the evidence either way: the wallet is gone from
            // it, or it is still there with a sentence saying why.
            Answer::DeleteWallet(outcome) => Outcome {
                nav: Nav::Enter(State::Wallets(WalletsState::after_delete(
                    &self.name, outcome,
                ))),
                request: None,
            },
            _ => Outcome::stay(),
        }
    }

    /// Back is a cancel: nothing has been written yet. It pops to the wallet list, because
    /// this screen REPLACED the wallet home rather than being pushed over it - which is
    /// what drops that screen's derivation instead of parking it behind the erase of the
    /// wallet it belongs to.
    ///
    /// No confirmation, because there is nothing on this screen to lose: the words are not
    /// here, they are on the flash, and the list is one tap from the wallet again.
    fn back(&self) -> Nav {
        match self.mode {
            Mode::Busy(_) => Nav::Stay,
            Mode::Choose => Nav::Back,
        }
    }
}

/// Cut an embedder's sentence to a bounded length before it is wrapped, marking the cut.
fn cut(s: &str) -> String {
    if s.chars().count() <= NOTICE_MAX {
        return String::from(s);
    }
    let mut out: String = s.chars().take(NOTICE_MAX).collect();
    out.push_str(CUT);
    out
}

/// Keep at most `max` wrapped lines, marking the cut on the last one that survives.
///
/// A cut sentence on this screen is still worth drawing: it names the wallet and says the
/// words could not be read, which is what the user acts on. What is not acceptable is a
/// sentence that runs under the cards, so the cut is made here rather than left to a clip.
fn trim_lines(mut lines: Vec<String>, max: i32) -> Vec<String> {
    let max = max.max(1) as usize;
    if lines.len() <= max {
        return lines;
    }
    lines.truncate(max);
    if let Some(last) = lines.last_mut() {
        last.push_str(CUT);
    }
    lines
}

/// One half of the offer. Both cards are drawn through this, at the rectangle the layout
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
    text(&mut clip, copy[0], inner.x, inner.y, HEADING, INK_PRIMARY, PAPER_2)?;
    let mut y = inner.y + LINE;
    for line in wrap_words(copy[1], inner.w, BODY) {
        text(&mut clip, &line, inner.x, y, BODY, INK_SECONDARY, PAPER_2)?;
        y += SMALL_LINE;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::TOUCH_MIN;
    use crate::screens::testing::{Fixture, GEOMETRIES};

    fn state(registrations: u8, notice: Option<&str>) -> EraseState {
        EraseState {
            slot: 3,
            name: String::from("savings"),
            registrations,
            mode: Mode::Choose,
            notice: notice.map(String::from),
        }
    }

    /// The offer is balanced in the arithmetic, not only in the wording: same width, same
    /// height, same row, both above the touch floor, on both shipped panels. A later edit
    /// that grew one of them fails here rather than shipping a nudge at the one moment a
    /// user is deciding whether their backup exists.
    #[test]
    fn the_two_cards_are_the_same_size() {
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            for regs in [0u8, 1, 4] {
                let l = state(regs, None).layout(&f.ctx());
                assert_eq!(
                    (l.show.w, l.show.h),
                    (l.erase.w, l.erase.h),
                    "{w}x{h}: the cards differ in size"
                );
                assert_eq!(l.show.y, l.erase.y, "{w}x{h}: the cards are not in one row");
                assert!(l.show.h >= TOUCH_MIN, "{w}x{h}: a card is under the touch floor");
                assert!(!l.show.overlaps(&l.erase), "{w}x{h}: the cards overlap");
                // Both titles have to survive half a body at heading size, or the card
                // whose name is cropped is the quieter one whatever the rectangles say.
                for copy in [&SHOW_CARD, &ERASE_CARD] {
                    let title = HEADING.text_width(copy[0]) as i32;
                    assert!(
                        title <= l.show.w - 2 * f.m.gap,
                        "{w}x{h}: \"{}\" needs {title} px and the card gives {}",
                        copy[0],
                        l.show.w - 2 * f.m.gap
                    );
                }
                let needed = card_copy_h(l.show.w, f.m.gap);
                assert!(
                    needed <= l.show.h,
                    "{w}x{h}: a card needs {needed} px and has {}",
                    l.show.h
                );
            }
        }
    }

    /// Nothing this screen draws leaves the panel, and the prose never runs into the cards -
    /// including on the frame where a failure sentence has taken the Q22 line's place, which
    /// is the state with the most to say and the least room to say it.
    #[test]
    fn the_prose_fits_above_the_cards_on_both_panels() {
        let long = "The recovery words could not be read from wallet slot 3: the record \
                    did not come back from flash intact.";
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            let body = f.m.body();
            for regs in [0u8, 1, 12] {
                for notice in [None, Some(long)] {
                    let s = state(regs, notice);
                    let l = s.layout(&f.ctx());
                    let (area, paras) = &l.prose;
                    let used = prose_h(paras, f.m.gap);
                    assert!(
                        used <= area.h,
                        "{w}x{h} regs={regs} notice={}: the prose needs {used} px and has {}",
                        notice.is_some(),
                        area.h
                    );
                    // The announcement and the consequence are never the ones cut, and
                    // whatever is last still gets at least one line - a failure with
                    // nothing drawn is the defect this whole change is about.
                    assert_eq!(paras.len(), 3, "{w}x{h}: a paragraph went missing");
                    assert!(
                        paras.iter().all(|p| !p.is_empty()),
                        "{w}x{h}: a paragraph was cut to nothing"
                    );
                    assert_eq!(
                        paras[0],
                        wrap_words(&s.announcement(), area.w, BODY),
                        "{w}x{h}: the announcement was shortened"
                    );
                    assert_eq!(
                        paras[1],
                        wrap_words(AFTERWARDS, area.w, BODY),
                        "{w}x{h}: the consequence was shortened"
                    );
                    // Q22's sentence is a constant this crate measures, so it is never the
                    // one that gets cut: a truncated "a passphrase is not stored..." would
                    // hand somebody a backup they believe is complete.
                    if notice.is_none() {
                        assert_eq!(
                            paras[2],
                            wrap_words(PASSPHRASE, area.w, BODY),
                            "{w}x{h} regs={regs}: the Q22 sentence was cut"
                        );
                    } else {
                        assert!(
                            !paras[2].is_empty(),
                            "{w}x{h}: the failure sentence was cut to nothing"
                        );
                    }
                    for r in [*area, l.show, l.erase] {
                        assert!(
                            r.x >= body.x
                                && r.right() <= body.right()
                                && r.y >= body.y
                                && r.bottom() <= body.bottom(),
                            "{w}x{h}: {r:?} escapes the body {body:?}"
                        );
                    }
                    assert!(
                        area.bottom() <= l.show.y,
                        "{w}x{h}: the prose runs into the cards"
                    );
                }
            }
        }
    }

    /// The write is named before it happens, and named again while it runs. Invariant 2b is
    /// a property of the copy, so it is asserted over the copy rather than over a rectangle.
    #[test]
    fn the_write_is_announced_before_it_happens() {
        for regs in [0u8, 1, 4] {
            let s = state(regs, None);
            let announced = s.announcement();
            assert!(announced.contains("filler"), "{announced}");
            assert!(announced.contains("slot 3"), "{announced}");
            assert!(
                s.prose().first() == Some(&announced),
                "the announcement is the first thing read"
            );
            if regs > 0 {
                assert!(announced.contains(&format!("{regs}")), "{announced}");
            }
        }
    }

    /// The Q22 sentence is on the screen whenever the words can be offered, and steps aside
    /// only for a sentence saying they cannot - the one state where it has no subject.
    #[test]
    fn the_passphrase_warning_is_present_unless_the_words_could_not_be_read() {
        let s = state(1, None);
        assert!(s.prose().iter().any(|p| p == PASSPHRASE));
        let s = state(1, Some("no"));
        assert!(!s.prose().iter().any(|p| p == PASSPHRASE));
        assert!(s.prose().iter().any(|p| p == "no"));
    }

    /// Neither card is louder than the other in the words either: same number of lines, and
    /// no adjective on either condition. The lengths are held close so that one card cannot
    /// drift into being the explained option and the other the unexplained one.
    #[test]
    fn the_two_conditions_are_written_in_the_same_voice() {
        let (a, b) = (SHOW_CARD[1], ERASE_CARD[1]);
        assert!(a.is_ascii() && b.is_ascii());
        for word in ["recommended", "safer", "just", "simply", "only", "sure"] {
            for line in [SHOW_CARD[0], SHOW_CARD[1], ERASE_CARD[0], ERASE_CARD[1]] {
                assert!(
                    !line.to_lowercase().contains(word),
                    "\"{line}\" nudges with \"{word}\""
                );
            }
        }
        let (la, lb) = (a.chars().count() as i32, b.chars().count() as i32);
        assert!((la - lb).abs() <= 12, "the conditions differ in length: {la} vs {lb}");
    }


    /// A busy frame has nothing tappable and no way back, on both panels. The erase is
    /// running; a Back that appeared to cancel it would be a button that lies.
    #[test]
    fn the_busy_frame_offers_nothing() {
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            let mut s = state(1, None);
            s.mode = Mode::Busy(BUSY_ERASING);
            let mut out = Vec::new();
            s.regions(&f.ctx(), &mut out);
            assert!(out.is_empty(), "{w}x{h}: the busy frame is tappable");
            assert!(matches!(s.back(), Nav::Stay));
            assert_eq!(s.id(), ScreenId::Working);
        }
    }
}
