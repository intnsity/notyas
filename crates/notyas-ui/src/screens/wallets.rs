// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! S-10 Wallet list (UX 3): the device's real home once anything is stored.
//!
//! # The one place a wallet COUNT is allowed to exist
//!
//! Ratified Q2(a) is an acceptance criterion, not a preference, and it cuts in two
//! directions that are easy to get backwards. No pre-PIN surface and no row of the Verify
//! screen may ever state how many wallets a device holds: that number is what a coercer
//! learns for free from a device they cannot open, and those surfaces say `present` or
//! `blank` and, where it helps, the STATIC MAXIMUM - a constant is the same on every unit
//! and therefore not a leak. This screen is different in kind: it exists only after a
//! successful unlock, so its reader has already proved the PIN and can see the wallets
//! themselves. Showing "3 of 8 slots used" here discloses nothing the rows above it do
//! not, and hiding it would cost the user the one number they need before creating
//! another wallet.
//!
//! # No balances, ever
//!
//! An airgapped device has no chain view. A balance here could only be stale, and a stale
//! balance is worse than none. The fingerprint is the identity surface (commandment 8);
//! names are the user's own labels and are drawn in mono, so lookalike characters in a
//! name the user did not choose are visible.

use alloc::string::String;
use alloc::vec::Vec;

use embedded_graphics::draw_target::{DrawTarget, DrawTargetExt};
use embedded_graphics::pixelcolor::Rgb565;

use crate::canvas::{button, fill, frame, text, wrap_words, ButtonKind, BODY, HEADING, MONO_SMALL};
use crate::components::{draw_bar_no_back, LINE, SMALL_LINE};
use crate::layout::{Metrics, Rect, TOUCH_MIN};
use crate::screens::dice::DiceState;
use crate::screens::phrase::PhraseState;
use crate::screens::review::marker;
use crate::screens::settings::SettingsState;
use crate::screens::{Ctx, Env, Nav, Outcome, Screen, State};
use crate::theme::*;
use crate::{BackupState, DeleteOutcome, Region, RegionId, UiRequest, WalletRow, WALLET_SLOTS};
use notyas_core::bitcoin::Network;

/// The list holds only its scroll offset. Every wallet it shows belongs to the `Ui`,
/// installed by the embedder after it unsealed the store; this screen computes no part of
/// it and remembers none of it.
pub(crate) struct WalletsState {
    scroll: i32,
    /// Why the last wallet this screen was asked to open did not open.
    ///
    /// A tap on a row raises [`UiRequest::OpenWallet`] and the answer is normally a screen
    /// change; a wallet the embedder cannot unseal produces no screen change at all, and
    /// without this the row would look like a control that does nothing. `Ui::wallet_opened`
    /// is the success channel and [`WalletsState::report_failure`] is the other one, on the
    /// same precedent as `Ui::pin_removed(false)`.
    ///
    /// Cleared by the next tap, because the band is about ONE attempt: leaving it up while
    /// the user opens a different wallet would attach a failure to a row it is not about.
    notice: Option<(String, Tone)>,
}

/// What a band is about, which is the only thing that varies about how it is drawn.
///
/// Two tones and not a colour parameter: a caller that could pass any colour is a caller
/// that can eventually paint a completed delete in danger ink, and the one thing this band
/// must never do is make "it is done" and "it did not happen" look alike.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tone {
    /// Something the user asked for did not happen, or did not fully happen.
    Refused,
    /// Something the user asked for happened. S-47's status band.
    Done,
}

impl WalletsState {
    pub fn new() -> WalletsState {
        WalletsState { scroll: 0, notice: None }
    }

    /// The list as it reads after a delete, with a band naming what happened to it.
    ///
    /// S-47 ratifies both halves: the user lands here, and the band says `Deleted "savings"`.
    /// The band is not decoration - it is the only thing that distinguishes a wallet that is
    /// gone from a list the user is not sure they are reading correctly, which is exactly
    /// the doubt the previous build left them in.
    pub(crate) fn after_delete(name: &str, outcome: DeleteOutcome) -> WalletsState {
        let notice = match outcome {
            // The count is the one that actually happened. Named because the consequence
            // sheet named a number a minute ago and the user is owed the real one.
            DeleteOutcome::Gone { registrations: 0 } => {
                (format!("Deleted \"{name}\"."), Tone::Done)
            }
            DeleteOutcome::Gone { registrations: 1 } => (
                format!("Deleted \"{name}\" and its 1 multisig registration."),
                Tone::Done,
            ),
            DeleteOutcome::Gone { registrations: n } => (
                format!("Deleted \"{name}\" and its {n} multisig registrations."),
                Tone::Done,
            ),
            DeleteOutcome::Refused(why) | DeleteOutcome::Damaged(why) => (why, Tone::Refused),
        };
        WalletsState { scroll: 0, notice: Some(notice) }
    }

    /// State that a wallet did not open, in the embedder's own words.
    pub(crate) fn report_failure(&mut self, reason: String) {
        self.notice = Some((reason, Tone::Refused));
    }
}

/// Longest failure sentence this screen will render.
///
/// The text is the embedder's, which makes it untrusted input in the sense that matters
/// here: it is not attacker-chosen, but it is unbounded, and a wrap over an unbounded string
/// is work this screen does not get to choose the size of. Cut before the wrap, never after.
const NOTICE_MAX: usize = 240;

/// Padding inside the failure band.
const NOTICE_PAD: i32 = 12;

/// One wallet row: a heading line, a mono line under it, and its own padding.
///
/// Derived from the two lines it has to hold rather than from the `LIST_ROW_MIN` floor,
/// because the floor is a TOUCH minimum and clearing it says nothing about whether the
/// text fits. A row sized to the floor clips the descenders off its second line, which is
/// how a fingerprint loses its tail on the one screen a user reads fingerprints from.
const ROW_H: i32 = LINE + SMALL_LINE + 2 * ROW_PAD;
/// Padding inside a row. Fixed rather than `Metrics::gap`, so the row is the same shape
/// on both panels and its height can be a constant the layout reasons about.
const ROW_PAD: i32 = 12;
const ROW_GAP: i32 = 6;

// A row derived from its own two lines is taller than the touch floor, which is the right
// way round: clearing `LIST_ROW_MIN` is necessary and never sufficient.
const _: () = assert!(ROW_H >= crate::layout::LIST_ROW_MIN);

/// Padding inside the empty-state well.
const EMPTY_PAD: i32 = 12;

/// The empty state's copy. Constants because the well is SIZED from them: the words and
/// the box that holds them have to be measured from the same string or one of the two is
/// a guess.
const EMPTY_HEAD: &str = "No wallets stored.";
const EMPTY_BODY: &str = "Create one from dice, or restore from your seed words.";

/// The empty-state well, and its copy already wrapped to the width it will be drawn at.
struct Empty {
    well: Rect,
    /// The well minus its padding: where both the heading and the wrapped body start.
    inner: Rect,
    /// [`EMPTY_BODY`], wrapped. The drawing iterates exactly what the well was sized from.
    lines: Vec<String>,
}

/// Lay the empty state out in `viewport`, measuring the copy instead of assuming it.
///
/// The rows below this well have always been given a width and clipped to it; the empty
/// state was not. Its second line is a sentence of prose, and a sentence is wider than a
/// 720 px panel's list column - drawn as one run from the well's left edge it reached
/// 797 px into a 648 px well and finished 111 px past the right edge of the glass, where
/// there is no display to paint it on. Nothing at the layout tier could see that: no
/// `Region` names a line of text, so every rectangle check on this screen passed while a
/// third of the sentence was off the device.
///
/// So the wrap belongs to the layout, not to the string: the body is wrapped to the width
/// it is drawn in, and the well takes the height that wrap produced rather than the two
/// lines it was assumed to need. That holds at a panel width this file has never seen,
/// which a hand-broken string would not.
fn empty_state(viewport: &Rect) -> Empty {
    let lines = wrap_words(EMPTY_BODY, viewport.w - 2 * EMPTY_PAD, BODY);
    // Each body line ADVANCES `SMALL_LINE`, but the last line's glyph box is a full BODY
    // line, so the well is sized to the box and not to the advance - measured at the
    // advance, the well's own border crosses the descenders of the closing sentence.
    let h = 2 * EMPTY_PAD + LINE + (lines.len() as i32 - 1) * SMALL_LINE + BODY.line_height as i32;
    let well = Rect::new(viewport.x, viewport.y, viewport.w, h);
    Empty { well, inner: well.inset(EMPTY_PAD), lines }
}

pub(crate) struct Layout {
    /// The failure band, present exactly when the last open did not happen. Above the
    /// rows and inside the body, so it takes room from the list rather than covering it.
    notice: Option<(Rect, Vec<String>, Tone)>,
    viewport: Rect,
    capacity: Rect,
    new: Rect,
    restore: Rect,
    lock_chip: Rect,
    /// Settings, immediately left of Lock. Both are session affordances and this is the
    /// screen a session lives on: S-44's rows configure stored wallets, and this is the
    /// only place an unlocked device can be reached from (UX-SCREENS S-10, "Settings ->
    /// S-44").
    settings_chip: Rect,
}

impl Screen for WalletsState {
    type Layout = Layout;

    fn layout(&self, ctx: &Ctx) -> Layout {
        let m = &ctx.m;
        let body = m.body();
        let g = m.gap;
        let action_y = body.bottom() - m.btn;
        let capacity = Rect::new(body.x, action_y - g - SMALL_LINE, body.w, SMALL_LINE);
        let half = (body.w - g) / 2;
        // Measured from the copy, like the empty state below it: a band sized to a constant
        // is a band that cuts its own last line off on the narrower panel. Then bounded by
        // what the LIST can spare, which is the half a measurement alone gets wrong - a
        // three-line sentence takes the whole body of the 800x480 panel, and a screen whose
        // failure band hides every wallet has replaced one dead end with another.
        let room = capacity.y - g - body.y;
        let notice = self.notice.as_ref().map(|(text, tone)| {
            let lines = trimmed(
                wrap_words(clipped(text), body.w - 2 * NOTICE_PAD, BODY),
                (room - ROW_H - g - 2 * NOTICE_PAD) / LINE,
            );
            let h = 2 * NOTICE_PAD + lines.len() as i32 * LINE;
            (Rect::new(body.x, body.y, body.w, h), lines, *tone)
        });
        let top = notice.as_ref().map_or(body.y, |(r, _, _)| r.bottom() + g);
        Layout {
            notice,
            viewport: Rect::new(body.x, top, body.w, whole_rows(capacity.y - g - top)),
            capacity,
            new: Rect::new(body.x, action_y, half, m.btn),
            restore: Rect::new(body.right() - half, action_y, half, m.btn),
            lock_chip: chip(m),
            settings_chip: settings_chip(m),
        }
    }

    fn regions(&self, ctx: &Ctx, out: &mut Vec<Region>) {
        let l = self.layout(ctx);
        out.push(Region { id: RegionId::Lock, rect: l.lock_chip });
        out.push(Region { id: RegionId::OpenSettings, rect: l.settings_chip });
        // Rows ride the scrolled content: a row that is only partly in the viewport draws
        // but does not tap, which is the honest reading of half a row. That rule is about
        // a row the user has scrolled halfway off, and it is only safe because the
        // viewport is a WHOLE number of rows (`whole_rows`) and the scroll extent is an
        // exact multiple of the row pitch (`scroll_limit`): at either end of the travel
        // the list is at rest showing complete rows, so the rule can never fire on a row
        // nobody moved. An unreadable slot emits nothing - there is no wallet behind it to
        // open, and the row already says so in full rather than pretending to be an
        // action.
        for (i, entry) in ctx.wallets.iter().enumerate() {
            let WalletRow::Wallet(w) = entry else { continue };
            let r = row_rect(&l.viewport, i, self.scroll);
            if r.y >= l.viewport.y && r.bottom() <= l.viewport.bottom() {
                out.push(Region { id: RegionId::ListRow(w.slot), rect: r });
            }
        }
        // Offered only while there is a slot to put a wallet in. At capacity both are still
        // DRAWN, `Disabled` and with the reason beside them, and neither is hit-tested -
        // the same shape as the review screen's disabled hold: a control that is not
        // available is not a control. Painting them keeps the reason attached to the thing
        // it is about; withholding the regions is what makes the paint true.
        if has_free_slot(ctx.wallets) {
            out.push(Region { id: RegionId::WalletNew, rect: l.new });
            out.push(Region { id: RegionId::WalletRestore, rect: l.restore });
        }
    }

    fn draw<D: DrawTarget<Color = Rgb565>>(&self, t: &mut D, ctx: &Ctx) -> Result<(), D::Error> {
        let m = &ctx.m;
        // No Back: this screen is the floor of an unlocked device, and a drawn button
        // that leads nowhere is a button that lies.
        draw_bar_no_back(t, m, "Wallets")?;
        let l = self.layout(ctx);
        // "Lock device", not "Lock": the bare verb reads as a state badge next to a title,
        // and this is the control that ends a session - the one chip whose purpose has to
        // be legible without being tried. Words rather than a padlock glyph, because the
        // chips on this device are labelled with words, not icons (UX-SCREENS C1/S-42),
        // and the font atlas carries no padlock to draw one with. Both chips keep the
        // HEADING label and the `chip` geometry, so the pair still reads as a pair.
        button(t, l.lock_chip, "Lock device", ButtonKind::Secondary, PAPER_2)?;
        button(t, l.settings_chip, "Settings", ButtonKind::Secondary, PAPER_2)?;

        // The band first: it changes what the rows under it mean, and on the short panel
        // it is the difference between a tap that did nothing and a tap that was refused.
        if let Some((rect, lines, tone)) = &l.notice {
            // A completed delete is not a failure and must not be painted as one: the band
            // that says a wallet is gone is the same shape in success ink, so a user
            // glancing at the panel can tell the two apart before reading a word.
            let (ink, tint) = match tone {
                Tone::Refused => (DANGER, DANGER_TINT),
                Tone::Done => (SUCCESS, PAPER_0),
            };
            fill(t, *rect, tint)?;
            frame(t, *rect, ink)?;
            let mut y = rect.y + NOTICE_PAD;
            for line in lines {
                text(t, line, rect.x + NOTICE_PAD, y, BODY, ink, tint)?;
                y += LINE;
            }
        }

        if ctx.wallets.is_empty() {
            // The empty state is a first-class row, never a blank panel.
            let e = empty_state(&l.viewport);
            fill(t, e.well, PAPER_0)?;
            frame(t, e.well, BORDER)?;
            text(t, EMPTY_HEAD, e.inner.x, e.inner.y, HEADING, INK_PRIMARY, PAPER_0)?;
            let mut y = e.inner.y + LINE;
            for line in &e.lines {
                text(t, line, e.inner.x, y, BODY, INK_SECONDARY, PAPER_0)?;
                y += SMALL_LINE;
            }
        } else {
            {
                let mut clip = t.clipped(&l.viewport.to_eg());
                for (i, entry) in ctx.wallets.iter().enumerate() {
                    row(&mut clip, row_rect(&l.viewport, i, self.scroll), entry, m.gap)?;
                }
            }
            // A row below the fold is invisible, not clipped - the viewport is a whole
            // number of rows (`whole_rows`) so a row that does not fully fit is not drawn
            // at all. On the short panel two rows fit and a third stored wallet is common,
            // so the capacity line's word count is not what tells a reader there is more:
            // it is this mark, over the one edge that still has content past it. Same
            // mechanism as the review flow's C6 markers (`marker`), so a scroll affordance
            // does not look like a different control from one screen to the next.
            let limit = self.scroll_limit(ctx);
            if self.scroll > 0 {
                marker(t, "more above", l.viewport, true)?;
            }
            if self.scroll < limit {
                marker(t, "more below", l.viewport, false)?;
            }
        }

        // The count in use. Post-PIN, and the only surface in the product that states it.
        let used = ctx.wallets.len();
        text(
            t,
            &format!("{used} of {WALLET_SLOTS} slots used"),
            l.capacity.x,
            l.capacity.y,
            MONO_SMALL,
            INK_SECONDARY,
            PAPER_1,
        )?;

        let free = has_free_slot(ctx.wallets);
        let kind = if free { ButtonKind::Primary } else { ButtonKind::Disabled };
        let second = if free { ButtonKind::Secondary } else { ButtonKind::Disabled };
        button(t, l.new, "New wallet", kind, PAPER_1)?;
        button(t, l.restore, "Restore from words", second, PAPER_1)?;
        if !free {
            // A disabled control always carries its reason.
            text(
                t,
                &format!("All {WALLET_SLOTS} slots are used. Delete a wallet to free one."),
                l.capacity.x,
                l.capacity.y - SMALL_LINE,
                BODY,
                WARNING,
                PAPER_1,
            )?;
        }
        Ok(())
    }

    fn activate(&mut self, id: RegionId, env: &mut Env) -> Outcome {
        match id {
            // The UI cannot unseal a record - it owns no key - so it asks. The slot
            // travels in the region id, which is why `activate` can name it without
            // reading the list back. The answer arrives through `Ui::wallet_opened`.
            RegionId::ListRow(slot) => {
                // The band is about the previous attempt. This is a new one.
                self.notice = None;
                Outcome::ask(UiRequest::OpenWallet(slot))
            }
            // Guarded here as well as in `regions`, and against the store rather than
            // against anything this screen remembers: the two are read a frame apart, and
            // the wallet that fills the last slot can land in between. A caller that
            // reaches `activate` without consulting `regions` gets the same answer.
            RegionId::WalletNew if has_free_slot(env.wallets) => {
                Outcome::push(State::Dice(DiceState::new()))
            }
            RegionId::WalletRestore if has_free_slot(env.wallets) => {
                Outcome::push(State::Phrase(PhraseState::new()))
            }
            RegionId::Lock => Outcome::ask(UiRequest::LockSession),
            // Pushed, so Back from settings returns to the list rather than to an empty
            // stack that happens to look like it.
            RegionId::OpenSettings => Outcome::push(State::Settings(SettingsState::new())),
            _ => Outcome::stay(),
        }
    }

    /// There is nothing behind the wallet list: it is where a successful unlock lands.
    fn back(&self) -> Nav {
        Nav::Stay
    }

    fn scroll_mut(&mut self) -> Option<&mut i32> {
        Some(&mut self.scroll)
    }

    fn scroll_limit(&self, ctx: &Ctx) -> i32 {
        let l = self.layout(ctx);
        // The content ends at the BOTTOM OF THE LAST ROW, not a gap past it. A trailing
        // `ROW_GAP` in the extent would let the list travel six pixels further than it has
        // content, which parks the topmost visible row six pixels above the viewport -
        // painted through the clip, and by the fit rule in `regions` untappable, on a list
        // the user has stopped scrolling. Measured without it, and against a viewport that
        // is itself a whole number of rows, the limit is an exact multiple of the row
        // pitch: the list comes to rest at both ends showing complete rows only.
        let content = row_extent(ctx.wallets.len() as i32);
        (content - l.viewport.h).max(0)
    }
}

/// Whether a new wallet has anywhere to go.
///
/// One predicate for the three places that have to agree about capacity - `draw` paints
/// from it, `regions` hit-tests from it, `activate` refuses from it. They disagreed: the
/// pair was painted `Disabled` at eight wallets and offered and honoured anyway, so the
/// user could roll a seed the terminal save would then refuse.
///
/// A slot holding a record this device cannot read back counts as occupied. The store
/// cannot put a wallet where bytes already are, whatever those bytes turn out to be, so
/// counting rows is the same question as counting slots.
fn has_free_slot(wallets: &[WalletRow]) -> bool {
    wallets.len() < usize::from(WALLET_SLOTS)
}

/// The Lock chip in the top bar, shared by the two screens a session is read from.
///
/// Sized against `TOUCH_MIN` rather than against the bar: the bar is 64 px on the short
/// panel, and a chip inset from it by `Metrics::gap` would be 51 px tall - under the
/// physical floor, on the one control that ends a session.
pub(crate) fn chip(m: &Metrics) -> Rect {
    let h = (m.bar - m.gap).clamp(TOUCH_MIN, m.bar - 2);
    let w = 200.min(m.w / 3);
    Rect::new(m.w - m.gap - w, (m.bar - h) / 2, w, h)
}

/// The Settings chip, sized like the Lock chip it sits beside so the pair reads as one
/// group rather than as two unrelated controls that happen to share a bar.
fn settings_chip(m: &Metrics) -> Rect {
    let lock = chip(m);
    let w = 200.min(m.w / 4);
    Rect::new(lock.x - m.gap - w, lock.y, w, lock.h)
}

/// The wrapped band, cut to the lines the list can spare, with the cut marked.
///
/// The head survives and the tail is what goes, because the head is the part that says what
/// happened; the marker is a line of its own so that no sentence ends mid-word with nothing
/// to say it was shortened. One line is the floor: a panel with no room even for that is a
/// panel that cannot show the list either, and the band is still the more useful of the two.
fn trimmed(mut lines: Vec<String>, budget: i32) -> Vec<String> {
    let budget = usize::try_from(budget.max(1)).unwrap_or(1);
    if lines.len() <= budget {
        return lines;
    }
    lines.truncate(budget);
    if budget > 1 {
        lines.truncate(budget - 1);
        lines.push(String::from("..."));
    }
    lines
}

/// An embedder sentence bounded before it is wrapped, on a character boundary.
///
/// Cut rather than elided with a marker: what is lost is the tail of a diagnostic, the head
/// carries what happened, and a band that spent a line on an ellipsis would be spending it
/// on the part with no information in it.
fn clipped(text: &str) -> &str {
    match text.char_indices().nth(NOTICE_MAX) {
        Some((at, _)) => text.get(..at).unwrap_or(text),
        None => text,
    }
}

/// How tall `n` stacked rows are: `n` rows and the `n - 1` gaps BETWEEN them.
///
/// There is no gap after the last row. Every measurement of list content goes through
/// here so that the viewport and the scroll extent cannot disagree about where the content
/// ends, which is the disagreement that leaves a row painted six pixels out of reach.
fn row_extent(n: i32) -> i32 {
    (n * (ROW_H + ROW_GAP) - ROW_GAP).max(0)
}

/// The tallest viewport that is a whole number of rows, out of `room` px of body.
///
/// # Invariant: at rest, every row that is painted is tappable
///
/// `draw` paints the rows through a clip on the viewport, so a row reaching even one pixel
/// into it leaves ink; `regions` emits a row only when it fits ENTIRELY. A viewport whose
/// height is not a whole number of rows therefore ends inside a row and paints a sliver of
/// it that no finger can reach - a control the user can see and cannot use, which is the
/// defect class this screen must not ship (it is the same shape as an enable predicate
/// stricter than the thing it guards). The fit rule itself is right and stays: a row
/// scrolled halfway off the top genuinely should not tap. What was wrong was a viewport
/// that could not hold the rows it was expected to show at rest, so the viewport is what
/// gives way - it takes the largest whole-row height that fits and leaves the remainder
/// blank above the capacity line.
///
/// Zero when not even one row fits. That is a panel the wallet list cannot serve at all,
/// and painting a row it cannot offer would be the same lie in a worse place; a test
/// asserts both shipped panels clear it by a wide margin.
fn whole_rows(room: i32) -> i32 {
    row_extent((room + ROW_GAP) / (ROW_H + ROW_GAP))
}

/// Where row `i` sits at the current scroll offset. The single source of that arithmetic:
/// `regions` hit-tests it and `draw` paints it, so a row can never be drawn where it
/// cannot be tapped.
fn row_rect(viewport: &Rect, i: usize, scroll: i32) -> Rect {
    Rect::new(viewport.x, viewport.y + i as i32 * (ROW_H + ROW_GAP) - scroll, viewport.w, ROW_H)
}

/// One row. Two lines: what the wallet is called and what kind it is, then the values a
/// user compares against another device.
fn row<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    r: Rect,
    entry: &WalletRow,
    gap: i32,
) -> Result<(), D::Error> {
    let unreadable = matches!(entry, WalletRow::Unreadable { .. });
    fill(t, r, PAPER_2)?;
    frame(t, r, if unreadable { DANGER } else { BORDER_STRONG })?;
    let inner = r.inset(ROW_PAD);
    let mut clip = t.clipped(&inner.to_eg());

    match entry {
        // A slot this device cannot read back as a wallet has no name, no fingerprint and
        // no path. Inventing blanks for them would be the device claiming to have read
        // something it could not; the row says what happened instead (R-32).
        WalletRow::Unreadable { slot } => {
            let head = format!("slot {slot} - unreadable");
            text(&mut clip, &head, inner.x, inner.y, HEADING, DANGER, PAPER_2)?;
            // The line must be true of EVERY way this row is reached, and "does not decrypt
            // with this PIN" was true of only one of them. `wallet_row` also lands here for
            // an opaque slot belonging to another identity, for a length fault, and - the
            // case that actually reaches owners - for a body that decrypted PERFECTLY and
            // simply is not a wallet record, which is what a diagnostic or soak payload in a
            // slot looks like. Blaming the PIN there sends the owner hunting for a second
            // PIN that does not exist, which is the one wrong conclusion this row can cause.
            //
            // One line, because a row is one line tall. The full account belongs to R-32,
            // which is a screen with room for three sections; a row that tried to carry it
            // would be a row with its last words cut off.
            text(
                &mut clip,
                "Not readable as a wallet.",
                inner.x,
                inner.y + LINE,
                MONO_SMALL,
                INK_SECONDARY,
                PAPER_2,
            )?;
        }
        WalletRow::Wallet(w) => {
            // The badges are drawn first and the name gets what they leave, because the
            // name is the only value here whose length is the user's business. TESTNET
            // rides the type badge rather than the identity line below it: signing on the
            // wrong network is a real error class (S-10), so it belongs on the line a
            // reader takes in first, not at the end of a string that can be cropped.
            let badge = w.kind.badge();
            let bw = HEADING.text_width(badge) as i32;
            text(&mut clip, badge, inner.right() - bw, inner.y, HEADING, INK_SECONDARY, PAPER_2)?;
            let net_w = if w.network == Network::Bitcoin {
                0
            } else {
                let net = "TESTNET";
                let nw = HEADING.text_width(net) as i32;
                let x = inner.right() - bw - ROW_PAD - nw;
                text(&mut clip, net, x, inner.y, HEADING, WARNING, PAPER_2)?;
                nw + ROW_PAD
            };
            let name_room =
                Rect::new(inner.x, inner.y, (inner.w - bw - net_w - ROW_PAD).max(0), LINE);
            {
                let mut name_clip = clip.clipped(&name_room.to_eg());
                text(&mut name_clip, &w.name, inner.x, inner.y, HEADING, INK_PRIMARY, PAPER_2)?;
            }

            // Uppercase is reserved for states that should stop a reader (copy
            // decision 3), and the badge is drawn FIRST so the identity line can be given
            // exactly the width it leaves. A wallet name and a testnet marker are both
            // user-visible truth; overlapping them would make neither readable.
            let (status, ink) = match &w.backup {
                BackupState::Verified(_) => (String::from("backup verified"), SUCCESS),
                BackupState::Unchecked => (String::from("BACKUP UNCHECKED"), WARNING),
            };
            let sw = MONO_SMALL.text_width(&status) as i32;
            let sy = inner.y + LINE;
            text(&mut clip, &status, inner.right() - sw, sy, MONO_SMALL, ink, PAPER_2)?;

            let left = format!("{}  {}", w.fingerprint, w.path);
            let room = Rect::new(inner.x, sy, inner.w - sw - gap, SMALL_LINE);
            let mut left_clip = clip.clipped(&room.to_eg());
            text(&mut left_clip, &left, room.x, room.y, MONO_SMALL, INK_SECONDARY, PAPER_2)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::UnlockGate;
    use super::*;
    use crate::layout::{PANELS, TOUCH_MIN};
    use crate::screens::testing::{fits, rows_are_clear_on, Fixture, GEOMETRIES};
    use crate::{PassphraseState, WalletInfo, WalletKind};

    fn wallet(n: u8) -> WalletRow {
        WalletRow::Wallet(WalletInfo {
            slot: n,
            name: format!("wallet {n}"),
            fingerprint: String::from("a1b2c3d4"),
            path: String::from("m/84'/0'/0'"),
            script_type: String::from("native segwit"),
            kind: WalletKind::SingleSig,
            backup: BackupState::Verified(String::new()),
            network: Network::Bitcoin,
            registrations: 0,
            stored: true,
            passphrase: PassphraseState::None,
        })
    }

    /// The empty state fits the well it is drawn in, on EVERY shipped panel.
    ///
    /// The rest of this suite measures RECTANGLES, and the empty state has only one; the
    /// defect was in the line of prose inside it, which no `Region` names and no rectangle
    /// check can see. Measured against the panel as well as the well, because a well that
    /// is itself off the glass measures perfectly clear against its own copy.
    ///
    /// Driven over the whole of `PANELS` rather than `GEOMETRIES`: nothing here depends on
    /// the eight-slot overflow assumption that keeps the other tests to two panels, and the
    /// line was too wide on four of the five.
    #[test]
    fn the_empty_state_copy_fits_its_well() {
        for (w, h) in PANELS {
            let f = Fixture::new(w, h);
            let ctx = f.ctx();
            let l = WalletsState::new().layout(&ctx);
            let e = empty_state(&l.viewport);
            let what = format!("{w}x{h} empty wallet list");
            rows_are_clear_on(&f.m, &what, l.viewport, &[("well", e.well)]);
            fits(&what, EMPTY_HEAD, HEADING.text_width(EMPTY_HEAD) as i32, e.inner);
            for line in &e.lines {
                fits(&what, line, BODY.text_width(line) as i32, e.inner);
            }
            // The well is as tall as the copy it was given, so the frame cannot cross the
            // last line's descenders and the wrap cannot outgrow the box.
            let used = LINE + (e.lines.len() as i32 - 1) * SMALL_LINE + BODY.line_height as i32;
            assert_eq!(e.well.h, used + 2 * EMPTY_PAD, "{what}: the well is not its copy's height");
        }
    }

    /// Rows keep the list floor, the action pair keeps the touch floor, and nothing
    /// escapes the body - at both geometries and at the full eight slots.
    #[test]
    fn a_full_list_lays_out_on_both_panels() {
        for (w, h) in GEOMETRIES {
            let mut f = Fixture::new(w, h);
            f.wallets = (0..WALLET_SLOTS).map(wallet).collect();
            let ctx = f.ctx();
            let s = WalletsState::new();
            let l = s.layout(&ctx);
            let body = f.m.body();
            let mut out = Vec::new();
            s.regions(&ctx, &mut out);
            for r in &out {
                assert!(
                    r.rect.w >= TOUCH_MIN && r.rect.h >= TOUCH_MIN,
                    "{w}x{h}: {:?} is {}x{}",
                    r.id,
                    r.rect.w,
                    r.rect.h
                );
                assert!(
                    r.rect.x >= 0 && r.rect.bottom() <= body.bottom(),
                    "{w}x{h}: {:?} at {:?} escapes the body",
                    r.id,
                    r.rect
                );
            }
            assert!(l.new.w >= TOUCH_MIN && l.restore.w >= TOUCH_MIN);
            assert!(!l.new.overlaps(&l.restore));
            // Eight rows do not fit either panel, so the list must be able to reach them.
            assert!(s.scroll_limit(&ctx) > 0, "{w}x{h}: a full list must scroll");
        }
    }

    /// Every row is reachable by scrolling: the last row's top must come inside the
    /// viewport at the limit, or a stored wallet would be invisible on the one screen
    /// that lists them.
    #[test]
    fn scrolling_reaches_the_last_wallet() {
        for (w, h) in GEOMETRIES {
            let mut f = Fixture::new(w, h);
            f.wallets = (0..WALLET_SLOTS).map(wallet).collect();
            let ctx = f.ctx();
            let mut s = WalletsState::new();
            let limit = s.scroll_limit(&ctx);
            *s.scroll_mut().unwrap() = limit;
            let l = s.layout(&ctx);
            let last = row_rect(&l.viewport, WALLET_SLOTS as usize - 1, limit);
            assert!(
                last.bottom() <= l.viewport.bottom() && last.y >= l.viewport.y,
                "{w}x{h}: the last row is at {last:?} in a viewport of {:?}",
                l.viewport
            );
        }
    }

    /// THE INVARIANT: at rest, every row that is PAINTED is TAPPABLE.
    ///
    /// `draw` paints each row through a clip on the viewport, so any overlap at all leaves
    /// ink - a row fills its whole rect before it draws a word. `regions` emits a row only
    /// when it fits entirely. The two sets have to be the SAME set wherever the list is
    /// standing still, or the screen shows a control that does nothing, which is how a row
    /// reached the owner's hands looking tappable and refusing to open.
    ///
    /// Checked at both resting offsets: no scroll, and the scroll limit. Mid-drag is
    /// deliberately excluded - a row scrolled halfway off the top is half a row and must
    /// not tap - and the two ends of the travel are exactly where "the user let go" is
    /// indistinguishable from "the list arrived like this".
    #[test]
    fn every_painted_row_at_rest_is_tappable() {
        for (w, h) in GEOMETRIES {
            for n in [1u8, 2, 3, WALLET_SLOTS] {
                let mut f = Fixture::new(w, h);
                f.wallets = (0..n).map(wallet).collect();
                let ctx = f.ctx();
                let mut s = WalletsState::new();
                for offset in [0, s.scroll_limit(&ctx)] {
                    *s.scroll_mut().unwrap() = offset;
                    let l = s.layout(&ctx);
                    let mut out = Vec::new();
                    s.regions(&ctx, &mut out);
                    for i in 0..n as usize {
                        let r = row_rect(&l.viewport, i, offset);
                        let painted = r.y < l.viewport.bottom() && r.bottom() > l.viewport.y;
                        let tappable = out
                            .iter()
                            .any(|g| g.id == RegionId::ListRow(i as u8) && g.rect == r);
                        assert_eq!(
                            painted, tappable,
                            "{w}x{h}, {n} wallets at scroll {offset}: row {i} at {r:?} is \
                             painted={painted} but tappable={tappable} in viewport {:?}",
                            l.viewport
                        );
                    }
                }
            }
        }
    }

    /// A wallet that would not open leaves a sentence on this screen, and the list under it
    /// still works.
    ///
    /// The band is the whole answer to a tap that cannot produce a screen change. Three
    /// things have to hold at once for it to be worth having: the sentence has to FIT the
    /// panel it is drawn on, the rows below it have to stay tappable rather than being
    /// pushed under the capacity line, and the next tap has to clear it - a failure band
    /// left standing over a different wallet is a lie about that wallet.
    #[test]
    fn a_refused_open_is_stated_and_does_not_break_the_list() {
        let long = "Wallet slot 3 did not open with no passphrase: its words derive wallet                     9f8e7d6c and the record was sealed for a1b2c3d4, so either it has a                     BIP-39 passphrase or the record did not come back intact.";
        for (w, h) in PANELS {
            let mut f = Fixture::new(w, h);
            f.wallets = vec![wallet(0), wallet(1), wallet(2)];
            let ctx = f.ctx();
            let mut s = WalletsState::new();
            s.report_failure(String::from(long));
            let l = s.layout(&ctx);
            let (rect, lines, _) = l.notice.as_ref().expect("a reported failure is drawn");
            let body = f.m.body();
            assert!(
                rect.y >= body.y && rect.bottom() <= l.viewport.y,
                "{w}x{h}: the band at {rect:?} runs into the list at {:?}",
                l.viewport
            );
            let room = Rect::new(rect.x + NOTICE_PAD, rect.y, rect.w - 2 * NOTICE_PAD, LINE);
            for line in lines {
                fits(&format!("{w}x{h} band"), line, BODY.text_width(line) as i32, room);
            }
            assert!(
                l.viewport.h >= ROW_H,
                "{w}x{h}: the band left no room for a wallet row"
            );
            assert!(
                lines[0].starts_with("Wallet slot 3 did not open"),
                "{w}x{h}: the head of the sentence is what must survive a trim: {:?}",
                lines[0]
            );
            if lines.len() > 1 {
                assert!(
                    lines.last().is_some_and(|l| l == "..." || long.contains(l.trim())),
                    "{w}x{h}: a shortened band has to say it was shortened"
                );
            }
            let mut regions = Vec::new();
            s.regions(&ctx, &mut regions);
            assert!(
                regions.iter().any(|r| r.id == RegionId::ListRow(0)),
                "{w}x{h}: the first wallet is still tappable under the band"
            );
        }

        let mut f = Fixture::new(720, 720);
        f.wallets = vec![wallet(0)];
        let mut network = Network::Bitcoin;
        let mut env = Env {
            network: &mut network,
            lock: &f.lock,
            wallets: &f.wallets,
            gate: &mut UnlockGate::default(),
        };
        let mut s = WalletsState::new();
        s.report_failure(String::from("Wallet slot 0 did not open."));
        let out = s.activate(RegionId::ListRow(0), &mut env);
        assert_eq!(out.request, Some(UiRequest::OpenWallet(0)));
        assert!(s.notice.is_none(), "a new attempt clears the band about the last one");
    }

    /// The pair that creates a wallet is offered only while there is a slot to put one in.
    ///
    /// At capacity both buttons are still PAINTED, `Disabled` and with the reason beside
    /// them, and neither is a region and neither acts. The half that was missing is the
    /// acting half: the buttons drew grey and started the flow anyway, and that flow ends
    /// at a save the device refuses, several minutes and one dice seed later. `activate`
    /// is driven directly as well as through `regions`, because the guard has to hold for
    /// a caller that never asked what was tappable.
    #[test]
    fn creating_a_wallet_is_refused_at_capacity() {
        let pair = [RegionId::WalletNew, RegionId::WalletRestore];
        for (w, h) in GEOMETRIES {
            let mut f = Fixture::new(w, h);
            f.wallets = (0..WALLET_SLOTS).map(wallet).collect();
            let mut s = WalletsState::new();
            let mut out = Vec::new();
            s.regions(&f.ctx(), &mut out);
            for id in pair {
                assert!(
                    !out.iter().any(|r| r.id == id),
                    "{w}x{h}: {id:?} is hit-tested on a device with no free slot"
                );
            }
            let mut network = Network::Bitcoin;
            let mut env = Env {
            network: &mut network,
            lock: &f.lock,
            wallets: &f.wallets,
            gate: &mut UnlockGate::default(),
        };
            for id in pair {
                let outcome = s.activate(id, &mut env);
                assert!(
                    matches!(outcome.nav, Nav::Stay) && outcome.request.is_none(),
                    "{w}x{h}: {id:?} started a flow at capacity"
                );
            }

            // ...and the same screen one slot short offers both and opens both, so the
            // guard is capacity and not a control that has been switched off.
            let mut f = Fixture::new(w, h);
            f.wallets = (0..WALLET_SLOTS - 1).map(wallet).collect();
            let mut out = Vec::new();
            s.regions(&f.ctx(), &mut out);
            for id in pair {
                assert!(out.iter().any(|r| r.id == id), "{w}x{h}: {id:?} is gone with a free slot");
            }
            let mut network = Network::Bitcoin;
            let mut env = Env {
            network: &mut network,
            lock: &f.lock,
            wallets: &f.wallets,
            gate: &mut UnlockGate::default(),
        };
            assert!(
                matches!(s.activate(RegionId::WalletNew, &mut env).nav, Nav::Push(State::Dice(_))),
                "{w}x{h}: New wallet did not open the dice flow"
            );
            assert!(
                matches!(
                    s.activate(RegionId::WalletRestore, &mut env).nav,
                    Nav::Push(State::Phrase(_))
                ),
                "{w}x{h}: Restore did not open the words flow"
            );
        }
    }

    /// The viewport is a whole number of rows, and both shipped panels hold at least two.
    ///
    /// The first half is what makes the invariant above hold by construction rather than
    /// by luck. The second is the floor that keeps `whole_rows`' degenerate answer - a
    /// zero-height viewport, which paints no wallet at all - off the hardware: a panel
    /// that cannot show two rows of a list cannot show a wallet list.
    #[test]
    fn the_viewport_is_whole_rows_and_holds_at_least_two() {
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            let ctx = f.ctx();
            let l = WalletsState::new().layout(&ctx);
            let rows = (l.viewport.h + ROW_GAP) / (ROW_H + ROW_GAP);
            assert!(rows >= 2, "{w}x{h}: the list viewport holds {rows} rows");
            assert_eq!(
                l.viewport.h,
                row_extent(rows),
                "{w}x{h}: the viewport ends inside row {rows}"
            );
            // And it still sits above the capacity line it was carved out of.
            assert!(l.viewport.bottom() <= l.capacity.y, "{w}x{h}: the list runs into capacity");
        }
    }
}
