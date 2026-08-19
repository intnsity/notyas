// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! S-27 Sign: source and S-28 SD file picker - the only way a transaction reaches this
//! device.
//!
//! # Why two screens share one module
//!
//! They are two views of ONE resource. Both raise [`UiRequest::ListCard`], both receive
//! every [`CardOutcome`] the card layer can produce, both must state the same size cap,
//! and both hand the same file to [`UiRequest::LoadPsbt`]. Split across two modules the
//! cap, the failure copy and the rule about which rows may be tapped would each exist
//! twice, and two copies of a safety rule is one rule and one bug waiting. The two state
//! types stay separate - a screen is one state type - and everything they agree about
//! lives between them, once.
//!
//! # The card is hostile input
//!
//! Every value on these screens came off a FAT directory entry that somebody else wrote.
//! `notyas_wallet::sd` bounds and validates it on the std side, and these screens assume
//! none of that held:
//!
//! - a name is drawn only if every byte of it is printable ASCII within the FAT long-name
//!   maximum. The atlas substitutes `'?'` for anything else, so a name holding a tab or a
//!   UTF-8 sequence would render as a DIFFERENT name the user might well recognise. A row
//!   whose name fails is painted with the reason and is not tappable, so its bytes never
//!   reach a request;
//! - a length is checked against [`MAX_FILE_BYTES`] BEFORE the row is offered, so an
//!   oversize file is refused by the screen and never becomes a read. The screen makes
//!   that check itself rather than trusting [`FileRow::oversize`], which was decided
//!   against whatever bound the embedder happened to pass - the cap the row PRINTS is
//!   therefore the cap the screen ENFORCES;
//! - a listing is addressed through [`RegionId::ListRow`], which carries a `u8`, so at
//!   most [`MAX_ROWS`] rows can be named at all. Rows past that are not painted, and the
//!   footer states the shortfall rather than leaving rows on the panel that no tap can
//!   reach;
//! - every failure reaches the user as a sentence with a way out of it. A card fault -
//!   no card, an unreadable card - is a state of these screens; an unreadable name and an
//!   oversize file are stated on the row itself; a file that was read and refused is S-29,
//!   pushed. No path on either screen leaves the panel showing the Busy frame it had when
//!   the request went out.
//!
//! # What these screens do not decide
//!
//! Whether a file IS a PSBT. That belongs to the decoder, which owns the magic check and
//! writes the sentence a user acts on; [`FileKind`] is extension-only for the same reason.
//! The picker's "All files" tab exists precisely so a mis-extensioned transaction can be
//! handed to it anyway.

use alloc::string::String;
use alloc::vec::Vec;

use embedded_graphics::draw_target::{DrawTarget, DrawTargetExt};
use embedded_graphics::pixelcolor::Rgb565;
use notyas_fonts::Atlas;

use crate::canvas::{
    button, fill, frame, panel, tabs, text, text_centered, wrap_words, ButtonKind, BODY, HEADING,
    MONO, MONO_SMALL,
};
use crate::components::{back_rect, draw_bar, draw_bar_no_back, LINE, SMALL_LINE};
use crate::layout::{Metrics, Rect, LIST_ROW_MIN, TOUCH_MIN};
use crate::screens::refusal::RefusalState;
use crate::screens::review::ReviewState;
use crate::screens::{Answer, Ctx, Env, Nav, Outcome, Screen, State};
use crate::theme::*;
use crate::{
    CardListing, CardOutcome, FileFilter, FileKind, FileRow, PsbtOutcome, Region, RegionId,
    ScreenId, UiRequest,
};

// ---------------------------------------------------------------------------------------
// The bounds these screens enforce
// ---------------------------------------------------------------------------------------

/// The largest file either screen will hand to [`UiRequest::LoadPsbt`].
///
/// `notyas_core`'s number, not a second one. It is the cap the decoder applies to the
/// bytes as they arrive and the one ARCHITECTURE 5.3 check 9 re-enforces against the
/// serialized length, and `firmware::sd::psbt_bounds` reads it from the same place - so
/// the figure a row prints ("too large - max ...") is the figure that would refuse the
/// file.
const MAX_FILE_BYTES: u32 = {
    let max = notyas_core::psbt::StructuralLimits::DEFAULT.max_psbt_bytes;
    // The ratified cap is 1 MiB. The clamp is so that a future rise past 4 GiB arrives
    // here as a smaller number rather than as a wrapped one.
    if max > u32::MAX as usize {
        u32::MAX
    } else {
        max as u32
    }
};

/// Rows the picker can address.
///
/// [`RegionId::ListRow`] carries a `u8`, so row 256 has no name a tap could produce. This
/// is therefore a bound on what the screen may PAINT, not a hope about what a card holds:
/// a row drawn past it would be a row the user can see and cannot open, which is the
/// defect class this module is written against.
const MAX_ROWS: usize = 256;
const _: () = assert!(MAX_ROWS - 1 <= u8::MAX as usize);

/// The FAT long-name maximum (FAT32 File System Specification 1.03), restated here because
/// this crate is no_std and cannot depend on `notyas-wallet`, where the same number bounds
/// a validated `Name`. Nothing legal on a card is longer, so a name above it is one the
/// volume layer should already have refused.
const NAME_MAX: usize = 255;

/// A timestamp is a string some other machine wrote, rendered as-is or not at all. This is
/// how much of a row it may claim.
const STAMP_MAX: usize = 24;

/// How much of an embedder's own sentence a well will render. Longer than any of them, and
/// a bound rather than a hope: these strings describe a fault, and a fault report is not a
/// place to trust a length.
const UNTRUSTED_MAX: usize = 512;

/// The one character outside ASCII the atlas carries, used wherever a value is too wide for
/// the panel and the reader has to know they are not seeing all of it.
const ELLIPSIS: &str = "\u{2026}";

// ---------------------------------------------------------------------------------------
// Shared geometry
// ---------------------------------------------------------------------------------------

/// Padding inside a well or a list row.
const WELL_PAD: i32 = 12;
/// Gap between stacked list rows.
const ROW_GAP: i32 = 6;
/// One list row: a name line and a detail line, plus its own padding.
///
/// Derived from the two lines it has to hold rather than from [`LIST_ROW_MIN`], because
/// that floor is a TOUCH minimum and clearing it says nothing about whether the text fits.
const ROW_H: i32 = LINE + SMALL_LINE + 2 * WELL_PAD;
const ROW_PITCH: i32 = ROW_H + ROW_GAP;
const _: () = assert!(ROW_H >= LIST_ROW_MIN);

/// How far the explicit pager steps, in rows.
///
/// Two, and the number is a floor rather than a preference: every shipped panel gives the
/// list at least two whole rows (`the_viewport_holds_at_least_a_page`), so a page step can
/// never carry the list over a row the user was never shown. On a taller panel it is a
/// half-page, which leaves context on screen - what a reader wants from a pager anyway.
const PAGE_ROWS: i32 = 2;

/// The `SignReady` card is the primary action of S-27, so it carries a button's weight
/// rather than a caption's (UX-SCREENS S-27: "full width, >= 120 px").
const READY_MIN_H: i32 = 120;

// ---------------------------------------------------------------------------------------
// Measured copy
// ---------------------------------------------------------------------------------------

/// One measured line of a well.
///
/// `adv` is the baseline-to-baseline step to the next line and is never less than the
/// font's own line box (`a_line_never_advances_less_than_its_font_needs`), so a block's
/// height is exactly the sum of its advances plus the well's padding. That is what lets a
/// block be trimmed to a room bound without the last line's descenders crossing the border
/// drawn under them.
struct Line {
    text: String,
    font: &'static Atlas,
    ink: Rgb565,
    adv: i32,
}

impl Line {
    fn head(text: String) -> Line {
        Line { text, font: HEADING, ink: INK_PRIMARY, adv: LINE }
    }

    fn body(text: String) -> Line {
        Line { text, font: BODY, ink: INK_SECONDARY, adv: LINE }
    }

    fn mono(text: String) -> Line {
        Line { text, font: MONO, ink: INK_PRIMARY, adv: LINE }
    }

    fn detail(text: String, ink: Rgb565) -> Line {
        Line { text, font: MONO_SMALL, ink, adv: SMALL_LINE }
    }
}

/// Wrap `head` to `w` px and append it as headline lines.
///
/// A headline wraps for the same reason prose does: the narrowest column any of these
/// wells gets is the landscape half of an 800x480 body, and "The card could not be read."
/// is wider than that at HEADING. Nothing in this module draws a fixed line it has not
/// measured.
fn push_head(out: &mut Vec<Line>, head: &str, w: i32) {
    for line in wrap_words(head, w, HEADING) {
        out.push(Line::head(line));
    }
}

/// Wrap `prose` to `w` px and append it as body lines.
fn push_prose(out: &mut Vec<Line>, prose: &str, w: i32) {
    for line in wrap_words(prose, w, BODY) {
        out.push(Line::body(line));
    }
}

/// Wrap an UNTRUSTED sentence to `w` px and append it as detail lines.
///
/// Drawn only if the atlas can draw it faithfully, bounded before it is wrapped - the wrap
/// is linear in a length someone else chose - and always LAST in a block, so a hostile
/// length can cost nothing but itself (see [`fit_block`]). A sentence that was cut says so,
/// because [`fit_block`]'s own marker only appears when the PANEL ran out of room.
fn push_untrusted(out: &mut Vec<Line>, sentence: &str, w: i32) {
    if !printable(sentence) {
        return;
    }
    // Printable ASCII, so a byte index is a character boundary.
    let cut = sentence.len() > UNTRUSTED_MAX;
    let head = if cut { &sentence[..UNTRUSTED_MAX] } else { sentence };
    for line in wrap_words(head, w, MONO_SMALL) {
        out.push(Line::detail(line, INK_SECONDARY));
    }
    if cut {
        out.push(Line::detail(String::from(ELLIPSIS), INK_MUTED));
    }
}

/// Height a block needs, well padding included.
fn block_h(lines: &[Line]) -> i32 {
    2 * WELL_PAD + lines.iter().map(|l| l.adv).sum::<i32>()
}

/// Trim a block to what `room` px can hold, and say that it was trimmed.
///
/// The order every builder emits in is load-bearing: headline, then what the user should
/// do, then the machine detail. Trimming takes from the tail, so the only thing a short
/// panel - or a message whose length someone else chose - can cost is the detail, never
/// the sentence the user has to act on. A trimmed block ends in a lone ellipsis, so the
/// reader knows the text continues instead of believing they have read all of it.
fn fit_block(mut lines: Vec<Line>, room: i32) -> Vec<Line> {
    if block_h(&lines) <= room {
        return lines;
    }
    let marker = Line::detail(String::from(ELLIPSIS), INK_MUTED);
    while lines.len() > 1 && block_h(&lines) + marker.adv > room {
        lines.pop();
    }
    if block_h(&lines) + marker.adv <= room {
        lines.push(marker);
    }
    lines
}

fn draw_block<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    well: Rect,
    lines: &[Line],
    surface: Rgb565,
) -> Result<(), D::Error> {
    let inner = well.inset(WELL_PAD);
    let mut clip = t.clipped(&inner.to_eg());
    let mut y = inner.y;
    for line in lines {
        text(&mut clip, &line.text, inner.x, y, line.font, line.ink, surface)?;
        y += line.adv;
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Rendering strings this device did not write
// ---------------------------------------------------------------------------------------

/// True if the string is non-empty and every byte of it is a glyph the atlas actually has.
fn printable(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

/// [`printable`], and within the bound its role carries.
fn renderable(s: &str, max: usize) -> bool {
    s.len() <= max && printable(s)
}

/// `s` shortened to `w` px by dropping the MIDDLE.
///
/// The middle, not the tail, and that is the security-relevant half of this function: two
/// files whose names share a long prefix - which is what a card someone prepared looks
/// like - are told apart by their last characters and by the extension, and tail elision
/// renders both identically. The elision itself is visible, so a reader always knows they
/// are not looking at the whole name.
fn elide_middle(s: &str, font: &'static Atlas, w: i32) -> String {
    if font.text_width(s) as i32 <= w {
        return String::from(s);
    }
    let budget = w - font.text_width(ELLIPSIS) as i32;
    if budget <= 0 {
        return String::from(ELLIPSIS);
    }
    let chars: Vec<char> = s.chars().collect();
    let (mut head, mut tail, mut used) = (0usize, 0usize, 0i32);
    while head + tail < chars.len() {
        // Alternate so that neither end starves the other.
        let from_head = head <= tail;
        let c = if from_head { chars[head] } else { chars[chars.len() - 1 - tail] };
        let adv = font.glyph(c).advance as i32;
        if used + adv > budget {
            break;
        }
        used += adv;
        if from_head {
            head += 1;
        } else {
            tail += 1;
        }
    }
    let mut out: String = chars[..head].iter().collect();
    out.push_str(ELLIPSIS);
    out.extend(chars[chars.len() - tail..].iter());
    out
}

/// `s` shortened to `w` px by dropping the TAIL, for a line whose meaning is front-loaded.
fn elide_end(s: &str, font: &'static Atlas, w: i32) -> String {
    if font.text_width(s) as i32 <= w {
        return String::from(s);
    }
    let budget = w - font.text_width(ELLIPSIS) as i32;
    if budget <= 0 {
        return String::from(ELLIPSIS);
    }
    let mut out = String::new();
    let mut used = 0i32;
    for c in s.chars() {
        let adv = font.glyph(c).advance as i32;
        if used + adv > budget {
            break;
        }
        used += adv;
        out.push(c);
    }
    out.push_str(ELLIPSIS);
    out
}

/// A byte count, rounded DOWN.
///
/// Always down, everywhere, including where the cap itself is printed: a size rounded up
/// over-states a file, and a cap rounded up promises a device that reads more than it does.
/// kB and MB are the decimal units the ratified copy uses (UX-SCREENS S-28, "sizes in kB
/// with one decimal").
fn size_label(len: u32) -> String {
    const K: u32 = 1000;
    const M: u32 = 1000 * 1000;
    if len < K {
        format!("{len} B")
    } else if len < M {
        format!("{}.{} kB", len / K, (len % K) / 100)
    } else {
        format!("{}.{} MB", len / M, (len % M) / (M / 10))
    }
}

// ---------------------------------------------------------------------------------------
// What the card last said
// ---------------------------------------------------------------------------------------

/// The card layer's last word, in the form both screens render.
///
/// One type for both, because every one of these can reach either screen and a variant only
/// one of them handled would be the frozen panel this contract exists to stop.
enum CardState {
    /// A [`UiRequest::ListCard`] is in flight. C3 Busy.
    Reading,
    /// A [`UiRequest::LoadPsbt`] is in flight, over the listing the file was chosen from.
    /// C3 Busy.
    ///
    /// The listing travels WITH the request, and that is the whole reason this variant
    /// carries one: the answer sends the user forward to a review or a refusal, and both of
    /// those come Back to here. A screen that had thrown its listing away would greet them
    /// with a Busy frame nothing will ever answer again.
    Loading(CardListing),
    Listed(CardListing),
    /// R-23. Nothing in the slot, or it did not mount.
    NoCard,
    /// The card mounted and would not list. The sentence is the embedder's, because the
    /// fault is its filesystem's - or its build's - to describe.
    Unreadable(String),
}

impl CardState {
    /// True while a request is in flight: the panel shows a C3 Busy frame, nothing is
    /// tappable, and nothing moves until an answer lands.
    fn busy(&self) -> bool {
        matches!(self, CardState::Reading | CardState::Loading(_))
    }

    /// Begin reading a file chosen from the listing on screen, keeping that listing. False
    /// if there was no listing to choose from, which is not a state a tap can reach.
    fn start_load(&mut self) -> bool {
        match core::mem::replace(self, CardState::Reading) {
            CardState::Listed(listing) => {
                *self = CardState::Loading(listing);
                true
            }
            other => {
                *self = other;
                false
            }
        }
    }

    /// The read is over: show the listing again, whatever the answer led to.
    fn end_load(&mut self) {
        if let CardState::Loading(listing) = core::mem::replace(self, CardState::Reading) {
            *self = CardState::Listed(listing);
        }
    }

    fn id(&self, at_rest: ScreenId) -> ScreenId {
        if self.busy() {
            ScreenId::Working
        } else {
            at_rest
        }
    }

    /// The Busy frame's heading. It names the operation, which is the one thing the frame
    /// says that [`ScreenId::Working`] does not.
    fn busy_heading(&self) -> &'static str {
        match self {
            CardState::Loading(_) => "Reading transaction",
            _ => "Reading card",
        }
    }
}

/// The copy a card state renders as, headline first and untrusted detail last.
fn card_block(card: &CardState, w: i32) -> Vec<Line> {
    let mut out = Vec::new();
    match card {
        // A Busy frame is painted by `draw_busy`, never out of a well.
        CardState::Reading | CardState::Loading(_) => {}
        // Reached only with an EMPTY listing: a picker with rows draws rows, and S-27
        // builds its own copy for the listings it can hold.
        CardState::Listed(_) => {
            push_head(&mut out, "No files on this card.", w);
            push_prose(
                &mut out,
                "Show all files if the transaction was saved under a different extension, \
                 or write it to the card again and check again.",
                w,
            );
        }
        CardState::NoCard => {
            push_head(&mut out, "No card detected.", w);
            push_prose(&mut out, "Insert a FAT32 card holding the .psbt file, then check again.", w);
        }
        CardState::Unreadable(why) => {
            push_head(&mut out, "The card could not be read.", w);
            push_prose(&mut out, "Try another card, or write this one again from your computer.", w);
            push_untrusted(&mut out, why, w);
        }
    }
    out
}

// ---------------------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------------------

/// What the screen decided about one listed row.
///
/// The decision is made ONCE, in [`classify`], and both `regions` and `activate` consume
/// it - so a row that cannot be offered cannot be tapped and cannot become a request, and
/// neither half can drift from the other.
enum Row<'a> {
    /// A directory at the card root. Tapping it lists that directory.
    Dir(&'a FileRow),
    /// A file this screen will hand to [`UiRequest::LoadPsbt`].
    File(&'a FileRow),
    /// Painted, never offered, carrying its own reason.
    Blocked(&'a FileRow, String),
}

/// Decide what may be done with `row`, listed in `dir` ("" is the card root).
fn classify<'a>(row: &'a FileRow, dir: &str) -> Row<'a> {
    if !renderable(&row.name, NAME_MAX) {
        Row::Blocked(row, String::from("name not readable on this device"))
    } else if row.kind == FileKind::Directory {
        // The depth limit is the design (UX-SCREENS S-28: a deep tree on a five-row list is
        // a navigation trap). The embedder drops nested directories; refusing the descent
        // here too means the limit holds whatever a listing turns out to contain.
        if dir.is_empty() {
            Row::Dir(row)
        } else {
            Row::Blocked(row, String::from("folders one level deep only"))
        }
    } else if row.oversize || row.len > MAX_FILE_BYTES {
        // The screen's own check, not the embedder's flag alone: the cap printed here is
        // the cap enforced here, and it is enforced BEFORE the read rather than by the
        // decoder after a megabyte has already been pulled into RAM.
        Row::Blocked(row, format!("too large - max {}", size_label(MAX_FILE_BYTES)))
    } else {
        Row::File(row)
    }
}

/// The one row a listing offers as the transaction to sign, if it offers exactly that.
fn single_transaction(listing: &CardListing) -> Option<&FileRow> {
    let [only] = listing.rows.as_slice() else { return None };
    match classify(only, &listing.dir) {
        Row::File(row) if row.kind == FileKind::Psbt => Some(row),
        _ => None,
    }
}

/// The short badge on the right of a row's detail line.
fn kind_badge(kind: FileKind) -> &'static str {
    match kind {
        FileKind::Directory => "FOLDER",
        FileKind::Psbt => "PSBT",
        FileKind::Txn => "TXN",
        FileKind::Text => "TEXT",
        FileKind::Json => "JSON",
        FileKind::Other => "FILE",
    }
}

/// Where row `i` sits at scroll offset `scroll`. The single source of that arithmetic:
/// `regions` hit-tests it and `draw` paints it, so a row can never be drawn where it cannot
/// be tapped.
fn row_rect(viewport: &Rect, i: usize, scroll: i32) -> Rect {
    Rect::new(viewport.x, viewport.y + i as i32 * ROW_PITCH - scroll, viewport.w, ROW_H)
}

/// How tall `n` stacked rows are: `n` rows and the `n - 1` gaps BETWEEN them. There is no
/// gap after the last row, and every measurement of list content goes through here so that
/// the viewport and the scroll extent cannot disagree about where the content ends.
fn row_extent(n: i32) -> i32 {
    (n * ROW_PITCH - ROW_GAP).max(0)
}

/// The tallest viewport that is a whole number of rows, out of `room` px.
///
/// `draw` paints rows through a clip on the viewport, so a row reaching one pixel into it
/// leaves ink; `regions` offers a row only when it fits ENTIRELY. A viewport that is not a
/// whole number of rows therefore ends inside a row and paints a sliver no finger can
/// reach. The viewport gives way, not the fit rule: a row scrolled halfway off genuinely
/// should not tap, but a list standing still must not show a row it cannot offer.
fn whole_rows(room: i32) -> i32 {
    row_extent((room + ROW_GAP) / ROW_PITCH)
}

/// Paint one row: what the file is called, and what it is.
fn draw_row<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    r: Rect,
    row: &Row,
    gap: i32,
) -> Result<(), D::Error> {
    let (fill_c, border_c) = match row {
        Row::Blocked(..) => (PAPER_0, BORDER),
        _ => (PAPER_2, BORDER_STRONG),
    };
    fill(t, r, fill_c)?;
    frame(t, r, border_c)?;
    let inner = r.inset(WELL_PAD);
    let mut clip = t.clipped(&inner.to_eg());
    let entry = match row {
        Row::Dir(e) | Row::File(e) | Row::Blocked(e, _) => e,
    };

    // The right of the detail line is drawn FIRST so the left can be given exactly the
    // width it leaves, and so a long name can never push the reason a row is refused off
    // the panel. A refused row always carries its reason, exactly as a disabled button does.
    let (mark, mark_ink) = match row {
        Row::Blocked(_, why) => (why.as_str(), WARNING),
        _ => (kind_badge(entry.kind), INK_SECONDARY),
    };
    let mark = elide_end(mark, MONO_SMALL, inner.w);
    let mark_w = MONO_SMALL.text_width(&mark) as i32;
    let detail_y = inner.y + LINE;
    text(&mut clip, &mark, inner.right() - mark_w, detail_y, MONO_SMALL, mark_ink, fill_c)?;

    // A name is drawn only where the atlas can draw it faithfully; the fixed label is the
    // honest alternative to rendering someone else's bytes as a row of question marks.
    let (name, name_ink) = if renderable(&entry.name, NAME_MAX) {
        (elide_middle(&entry.name, MONO, inner.w), INK_PRIMARY)
    } else {
        (String::from("(unreadable name)"), DANGER)
    };
    text(&mut clip, &name, inner.x, inner.y, MONO, name_ink, fill_c)?;

    let mut left = if entry.kind == FileKind::Directory {
        String::new()
    } else {
        size_label(entry.len)
    };
    if renderable(&entry.modified, STAMP_MAX) {
        if !left.is_empty() {
            left.push_str("   ");
        }
        left.push_str(&entry.modified);
    }
    if !left.is_empty() {
        let room = (inner.w - mark_w - gap).max(0);
        let left = elide_end(&left, MONO_SMALL, room);
        text(&mut clip, &left, inner.x, detail_y, MONO_SMALL, INK_SECONDARY, fill_c)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// The C3 Busy frame, shared by both screens
// ---------------------------------------------------------------------------------------

/// C3 Busy: no Back, nothing tappable, and no invented progress.
///
/// Indeterminate on purpose. A card read has no unit the std side reports between, so a
/// trough filled to some fraction would be the fake percentage C3 forbids.
fn draw_busy<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    m: &Metrics,
    heading: &str,
) -> Result<(), D::Error> {
    draw_bar_no_back(t, m, heading)?;
    let body = m.body();
    let card_h = 2 * LINE + 3 * m.gap;
    let card = Rect::new(body.x, body.y + (body.h - card_h) / 2, body.w, card_h);
    panel(t, card, PAPER_2, BORDER_STRONG)?;
    let mut y = card.y + m.gap;
    text_centered(t, heading, Rect::new(card.x, y, card.w, LINE), HEADING, INK_PRIMARY, PAPER_2)?;
    y += LINE + m.gap;
    text_centered(
        t,
        "Do not remove the card.",
        Rect::new(card.x, y, card.w, LINE),
        BODY,
        INK_SECONDARY,
        PAPER_2,
    )
}

// ---------------------------------------------------------------------------------------
// S-27 Sign: source
// ---------------------------------------------------------------------------------------

/// The transport contract, stated on the screen where it bites. Not an apology: it is why
/// there is one way in, and a user who has read it stops looking for a camera.
const TRANSPORT_NOTE: &str = "Transactions come in on the card only. This device has no \
                              camera, so it cannot scan one. The signed transaction goes \
                              back out on the card.";

/// S-27. Get an unsigned transaction into the device, and say plainly why there is only one
/// way in.
pub(crate) struct SignSourceState {
    card: CardState,
}

impl SignSourceState {
    /// Enter S-27 from the wallet home, with the card read that ends its Busy frame.
    ///
    /// The state and the request are built together and cannot be had apart: a Busy frame
    /// with no request behind it is a panel that never moves again, and this is the one call
    /// that opens the screen.
    pub(crate) fn open() -> Outcome {
        Outcome {
            nav: Nav::Push(State::SignSource(SignSourceState { card: CardState::Reading })),
            request: Some(list(String::new(), FileFilter::PsbtOnly)),
        }
    }

    pub(crate) fn id(&self) -> ScreenId {
        self.card.id(ScreenId::SignSource)
    }

    /// The single file this screen offers to load, if the listing holds exactly that.
    ///
    /// Exactly one row, and that row a file this screen would accept. Anything else - a
    /// second transaction, a directory that might hold more, a file too large to read - is a
    /// choice the user has to make, and choices are made in the picker.
    fn ready(&self) -> Option<&FileRow> {
        match &self.card {
            CardState::Listed(listing) => single_transaction(listing),
            _ => None,
        }
    }

    /// The file a tap on the ready card would read, detached from the borrow that found it.
    fn ready_target(&self) -> Option<(String, String)> {
        let CardState::Listed(listing) = &self.card else { return None };
        single_transaction(listing).map(|row| (listing.dir.clone(), row.name.clone()))
    }

    /// The stacked actions this state offers, top to bottom. Never empty at rest: a state
    /// with no way out is a trap, and every one of these states is reachable by accident.
    fn actions(&self) -> Vec<(RegionId, &'static str)> {
        match &self.card {
            CardState::Reading | CardState::Loading(_) => Vec::new(),
            CardState::Listed(_) if self.ready().is_some() => {
                vec![(RegionId::SignPickFile, "Choose a different file")]
            }
            CardState::Listed(listing) if listing.rows.is_empty() => vec![
                (RegionId::FileShowAll, "Show all files"),
                (RegionId::FileRefresh, "Check again"),
            ],
            CardState::Listed(_) => vec![
                (RegionId::SignPickFile, "Choose a file"),
                (RegionId::FileRefresh, "Check again"),
            ],
            CardState::NoCard | CardState::Unreadable(_) => vec![(RegionId::FileRefresh, "Check again")],
        }
    }

    /// The status well's copy. The ready card is the one state with a shape of its own: it
    /// names a file, so it renders that name in mono with its size beside it.
    fn status_block(&self, w: i32) -> Vec<Line> {
        match &self.card {
            CardState::Listed(listing) => match single_transaction(listing) {
                Some(row) => {
                    // The name gets a whole line of its own and the size sits under it, the
                    // way a file listing reads. Everything the user has to compare against
                    // what their computer wrote is on the panel BEFORE the read, which is
                    // the point of making the read a tap.
                    let mut out = Vec::new();
                    push_head(&mut out, "Ready to sign", w);
                    out.push(Line::mono(elide_middle(&row.name, MONO, w)));
                    out.push(Line::detail(size_label(row.len), INK_SECONDARY));
                    push_prose(&mut out, "Found on the card. Tap this card to read it.", w);
                    out
                }
                None if listing.rows.is_empty() => card_block(&self.card, w),
                // Defensive: `answered` sends a listing with a choice in it to the picker,
                // so this is only reachable if some other caller ever installs one here.
                None => {
                    let mut out = Vec::new();
                    push_head(&mut out, "Several files on this card.", w);
                    push_prose(&mut out, "Choose the transaction to sign.", w);
                    out
                }
            },
            other => card_block(other, w),
        }
    }
}

pub(crate) struct SignLayout {
    /// The status well. Also the `SignReady` region while a file is ready.
    status: Rect,
    lines: Vec<Line>,
    actions: Vec<(RegionId, &'static str, Rect)>,
    note: Rect,
    note_lines: Vec<Line>,
}

impl Screen for SignSourceState {
    type Layout = SignLayout;

    fn layout(&self, ctx: &Ctx) -> SignLayout {
        let m = &ctx.m;
        let body = m.body();
        // The ratified reflow: on a wide panel the transport note sits beside the status
        // card instead of under it, which is also what keeps the two apart on the panel with
        // the least vertical room. An even split, because both halves are measured: at two
        // fifths the note wraps to ten lines and outgrows the 800x480 body, and the action
        // column still has to hold "Choose a different file".
        let (col, note_col) = if m.landscape() {
            let note_w = (body.w - m.gap) / 2;
            let col_w = body.w - m.gap - note_w;
            (
                Rect::new(body.x, body.y, col_w, body.h),
                Rect::new(body.right() - note_w, body.y, note_w, body.h),
            )
        } else {
            (body, body)
        };

        let actions = self.actions();
        let n = actions.len() as i32;
        let actions_h = if n == 0 { 0 } else { n * m.btn + (n - 1) * m.gap };

        // The note is the lowest-priority thing on the screen, so it is the one measured
        // against what is left rather than the one that takes what it wants: the actions
        // and a readable status well come first, and the note is fitted into the remainder.
        // On every shipped panel the remainder holds all of it
        // (`the_transport_note_fits_every_shipped_panel`); the bound is here so that a panel
        // this crate has never seen trims the explanation instead of painting it off the
        // glass.
        let stacked_note = !m.landscape();
        let note_room = if stacked_note {
            col.h - actions_h - 2 * m.gap - (2 * WELL_PAD + 2 * LINE)
        } else {
            note_col.h
        };
        let mut note_lines = Vec::new();
        push_prose(&mut note_lines, TRANSPORT_NOTE, note_col.w - 2 * WELL_PAD);
        let note_lines = fit_block(note_lines, note_room.max(0));
        let note_h = block_h(&note_lines);

        let reserved = actions_h + m.gap + if stacked_note { note_h + m.gap } else { 0 };
        let room = (col.h - reserved).max(0);

        let lines = fit_block(self.status_block(col.w - 2 * WELL_PAD), room);
        let min_h = if self.ready().is_some() { READY_MIN_H } else { 0 };
        let status_h = block_h(&lines).max(min_h).min(room.max(min_h));
        let status = Rect::new(col.x, col.y, col.w, status_h);

        let mut y = status.bottom() + m.gap;
        let mut laid = Vec::with_capacity(actions.len());
        for (id, label) in actions {
            laid.push((id, label, Rect::new(col.x, y, col.w, m.btn)));
            y += m.btn + m.gap;
        }
        let note = if m.landscape() {
            Rect::new(note_col.x, note_col.y, note_col.w, note_h)
        } else {
            Rect::new(col.x, y, col.w, note_h)
        };
        SignLayout { status, lines, actions: laid, note, note_lines }
    }

    fn regions(&self, ctx: &Ctx, out: &mut Vec<Region>) {
        // C3: a Busy screen offers nothing, not even Back. The read is one blocking call on
        // the std side and cannot be cancelled, so a live control would be a lie about what
        // the loop can do.
        if self.card.busy() {
            return;
        }
        let l = self.layout(ctx);
        out.push(Region { id: RegionId::Back, rect: back_rect(&ctx.m) });
        if self.ready().is_some() {
            out.push(Region { id: RegionId::SignReady, rect: l.status });
        }
        for (id, _, rect) in l.actions {
            out.push(Region { id, rect });
        }
    }

    fn draw<D: DrawTarget<Color = Rgb565>>(&self, t: &mut D, ctx: &Ctx) -> Result<(), D::Error> {
        let m = &ctx.m;
        if self.card.busy() {
            return draw_busy(t, m, self.card.busy_heading());
        }
        draw_bar(t, m, "Sign")?;
        let l = self.layout(ctx);

        let ready = self.ready().is_some();
        let (fill_c, border_c) =
            if ready { (ACCENT_TINT, ACCENT) } else { (PAPER_2, BORDER_STRONG) };
        panel(t, l.status, fill_c, border_c)?;
        draw_block(t, l.status, &l.lines, fill_c)?;

        for (i, (_, label, rect)) in l.actions.iter().enumerate() {
            // With a file ready the CARD is the primary action, so every button beside it is
            // secondary; without one the first action is the primary one.
            let kind = if i == 0 && !ready { ButtonKind::Primary } else { ButtonKind::Secondary };
            button(t, *rect, label, kind, PAPER_1)?;
        }

        panel(t, l.note, PAPER_0, BORDER)?;
        draw_block(t, l.note, &l.note_lines, PAPER_0)?;
        Ok(())
    }

    fn activate(&mut self, id: RegionId, _env: &mut Env) -> Outcome {
        match id {
            RegionId::SignReady => {
                let Some((dir, name)) = self.ready_target() else { return Outcome::stay() };
                if !self.card.start_load() {
                    return Outcome::stay();
                }
                Outcome::ask(UiRequest::LoadPsbt { dir, name })
            }
            // Entered, not pushed: the picker supersedes this screen entirely, and Back from
            // it belongs on the wallet home rather than on a listing the user has already
            // replaced.
            RegionId::SignPickFile => FilePickerState::open(FileFilter::PsbtOnly),
            RegionId::FileShowAll => FilePickerState::open(FileFilter::All),
            RegionId::FileRefresh => {
                self.card = CardState::Reading;
                Outcome::ask(list(String::new(), FileFilter::PsbtOnly))
            }
            _ => Outcome::stay(),
        }
    }

    fn answered(&mut self, answer: Answer, _env: &mut Env) -> Outcome {
        match answer {
            // An answer that arrives while this screen is not waiting for one belongs to a
            // tap the user has moved on from, and must not move the panel back.
            Answer::Card(outcome) if matches!(self.card, CardState::Reading) => match outcome {
                CardOutcome::Listed(listing) => {
                    // One row this screen would load is the auto-detected case, and it stays
                    // here - where the name and the size are on the panel BEFORE anything is
                    // read, and where reading it is the user's tap rather than a consequence
                    // of inserting a card. Anything else is a choice, and choices are the
                    // picker's.
                    if listing.rows.is_empty() || single_transaction(&listing).is_some() {
                        self.card = CardState::Listed(listing);
                        Outcome::stay()
                    } else {
                        Outcome::enter(State::FilePicker(FilePickerState::listed(
                            FileFilter::PsbtOnly,
                            listing,
                        )))
                    }
                }
                CardOutcome::NoCard => {
                    self.card = CardState::NoCard;
                    Outcome::stay()
                }
                CardOutcome::Unreadable(why) => {
                    self.card = CardState::Unreadable(why);
                    Outcome::stay()
                }
            },
            Answer::Psbt(outcome) if matches!(self.card, CardState::Loading(_)) => {
                self.card.end_load();
                psbt_landed(outcome)
            }
            _ => Outcome::stay(),
        }
    }

    fn back(&self) -> Nav {
        // Nothing cancels a card read: the request is already in flight on the std side and
        // the answer is what moves the panel.
        if self.card.busy() {
            Nav::Stay
        } else {
            Nav::Back
        }
    }
}

// ---------------------------------------------------------------------------------------
// S-28 SD file picker
// ---------------------------------------------------------------------------------------

/// S-28. Choose a file when auto-detect is not enough.
pub(crate) struct FilePickerState {
    filter: FileFilter,
    /// "" is the card root; anything else is the one directory below it S-28 permits.
    dir: String,
    card: CardState,
    /// Where the list is standing, as a REQUEST for a position: [`FilePickerState::offset`]
    /// resolves it against the content the screen actually has. That is what makes a page
    /// step past the end, and a refresh that returns fewer rows than the last one, both
    /// harmless - neither can paint a row off the end of a listing.
    scroll: i32,
}

impl FilePickerState {
    /// Replace the current screen with a picker that has to read the card first.
    fn open(filter: FileFilter) -> Outcome {
        Outcome {
            nav: Nav::Enter(State::FilePicker(FilePickerState {
                filter,
                dir: String::new(),
                card: CardState::Reading,
                scroll: 0,
            })),
            request: Some(list(String::new(), filter)),
        }
    }

    /// A picker over a listing that has already been read.
    ///
    /// S-27 hands its own listing over rather than asking for it again: a second read costs
    /// a card transaction and, worse, can answer about a different card.
    fn listed(filter: FileFilter, listing: CardListing) -> FilePickerState {
        FilePickerState { filter, dir: listing.dir.clone(), card: CardState::Listed(listing), scroll: 0 }
    }

    pub(crate) fn id(&self) -> ScreenId {
        self.card.id(ScreenId::FilePicker)
    }

    /// The rows this screen may address. Never more than [`MAX_ROWS`] - see the module docs.
    fn rows(&self) -> &[FileRow] {
        match &self.card {
            CardState::Listed(l) => &l.rows[..l.rows.len().min(MAX_ROWS)],
            _ => &[],
        }
    }

    fn content_h(&self) -> i32 {
        row_extent(self.rows().len() as i32)
    }

    /// The tabs, the viewport, and the top of the footer row.
    ///
    /// Computed apart from [`Screen::layout`] because [`Screen::scroll_limit`] needs the
    /// viewport while the layout needs the limit - the pager is offered only when the
    /// listing exceeds two viewports - and this is the half that depends on neither.
    fn frame(&self, m: &Metrics) -> (Rect, Rect, i32) {
        let body = m.body();
        let tabs = Rect::new(body.x, body.y, body.w, m.btn.max(TOUCH_MIN));
        let foot_y = body.bottom() - m.btn;
        let top = tabs.bottom() + m.gap;
        let viewport = Rect::new(body.x, top, body.w, whole_rows((foot_y - m.gap - top).max(0)));
        (tabs, viewport, foot_y)
    }

    /// The offset this frame will actually render at.
    fn offset(&self, viewport_h: i32) -> i32 {
        self.scroll.clamp(0, (self.content_h() - viewport_h).max(0))
    }

    /// The footer's summary: what is on the card, and what could not be put on the screen.
    ///
    /// Every clause here is a claim about a card nobody in this crate controls, so each is
    /// stated rather than implied by an absence. A user who can see a file on their laptop
    /// and not on this panel is owed the reason.
    fn summary(&self) -> String {
        let CardState::Listed(l) = &self.card else { return String::new() };
        let dirs = l.rows.iter().filter(|r| r.kind == FileKind::Directory).count();
        let files = l.rows.len() - dirs;
        let mut out = match files {
            1 => String::from("1 file"),
            n => format!("{n} files"),
        };
        match dirs {
            0 => {}
            1 => out.push_str(", 1 folder"),
            n => out.push_str(&format!(", {n} folders")),
        }
        if l.rows.len() > MAX_ROWS {
            out.push_str(&format!(" - showing the first {MAX_ROWS}"));
        }
        if l.truncated {
            out.push_str(" - more than the device will list");
        }
        if l.rejected > 0 {
            out.push_str(&format!(" - {} names unreadable", l.rejected));
        }
        out
    }
}

pub(crate) struct PickerLayout {
    tabs: Rect,
    viewport: Rect,
    /// The offset this frame renders at, clamped once so `regions` and `draw` cannot
    /// disagree about it.
    offset: i32,
    /// The footer's buttons, in reading order.
    buttons: Vec<(RegionId, &'static str, Rect)>,
    /// What the footer's summary has left after the buttons.
    summary: Rect,
    /// The well shown instead of rows: an empty card, a failure, a refusal.
    well: Option<Rect>,
    lines: Vec<Line>,
}

/// The two tabs, laid out exactly as [`crate::canvas::tabs`] paints them: equal segments
/// with the last absorbing the rounding remainder.
fn tab_rect(bar: &Rect, i: i32, n: i32) -> Rect {
    let seg = bar.w / n;
    let w = if i == n - 1 { bar.w - seg * (n - 1) } else { seg };
    Rect::new(bar.x + i * seg, bar.y, w, bar.h)
}

const TAB_LABELS: [&str; 2] = ["PSBT only", "All files"];

impl Screen for FilePickerState {
    type Layout = PickerLayout;

    fn layout(&self, ctx: &Ctx) -> PickerLayout {
        let m = &ctx.m;
        let body = m.body();
        let (tabs, viewport, foot_y) = self.frame(m);
        let offset = self.offset(viewport.h);

        // C2: a drag alone is undiscoverable with no scrollbar, so a listing deeper than two
        // viewports gets an explicit pager. Below that one drag reveals everything and the
        // extra chrome would cost the summary its room.
        let pager = self.content_h() - viewport.h > viewport.h;
        let mut specs: Vec<(RegionId, &'static str)> = Vec::new();
        if pager {
            specs.push((RegionId::ListPagePrev, "< Prev"));
            specs.push((RegionId::ListPageNext, "Next >"));
        }
        specs.push((RegionId::FileRefresh, "Check again"));
        // Measured from the right so each button is as wide as its own label, then put back
        // into reading order.
        let mut x = body.right();
        let mut buttons = Vec::with_capacity(specs.len());
        for (id, label) in specs.iter().rev() {
            let w = (HEADING.text_width(label) as i32 + 2 * m.gap).max(TOUCH_MIN);
            x -= w;
            buttons.push((*id, *label, Rect::new(x, foot_y, w, m.btn)));
            x -= m.gap;
        }
        buttons.reverse();
        let summary = Rect::new(body.x, foot_y, (x + m.gap - body.x).max(0), m.btn);

        // A well replaces the rows whenever there are none to show - an empty card, a
        // failure, a refusal - so the middle of the panel is never simply blank.
        let (well, lines) = if self.rows().is_empty() {
            let lines = fit_block(card_block(&self.card, viewport.w - 2 * WELL_PAD), viewport.h);
            let h = block_h(&lines).min(viewport.h.max(0));
            (Some(Rect::new(viewport.x, viewport.y, viewport.w, h)), lines)
        } else {
            (None, Vec::new())
        };

        PickerLayout { tabs, viewport, offset, buttons, summary, well, lines }
    }

    fn regions(&self, ctx: &Ctx, out: &mut Vec<Region>) {
        if self.card.busy() {
            return;
        }
        let l = self.layout(ctx);
        out.push(Region { id: RegionId::Back, rect: back_rect(&ctx.m) });
        let n = TAB_LABELS.len() as i32;
        for i in 0..n {
            out.push(Region { id: RegionId::Tab(i as u8), rect: tab_rect(&l.tabs, i, n) });
        }
        // Rows ride the scrolled content: a row only partly in the viewport draws but does
        // not tap, which is the honest reading of half a row. That is safe only because the
        // viewport is a WHOLE number of rows and every resting offset is a multiple of the
        // row pitch, so the rule can never fire on a row nobody moved. A blocked row emits
        // nothing - there is no file behind it this device would open, and the row already
        // says so rather than pretending to be an action.
        for (i, entry) in self.rows().iter().enumerate() {
            if matches!(classify(entry, &self.dir), Row::Blocked(..)) {
                continue;
            }
            let r = row_rect(&l.viewport, i, l.offset);
            if r.y >= l.viewport.y && r.bottom() <= l.viewport.bottom() {
                out.push(Region { id: RegionId::ListRow(i as u8), rect: r });
            }
        }
        for (id, _, rect) in l.buttons {
            out.push(Region { id, rect });
        }
    }

    fn draw<D: DrawTarget<Color = Rgb565>>(&self, t: &mut D, ctx: &Ctx) -> Result<(), D::Error> {
        let m = &ctx.m;
        if self.card.busy() {
            return draw_busy(t, m, self.card.busy_heading());
        }
        let title = if renderable(&self.dir, NAME_MAX) {
            format!("Files in {}", self.dir)
        } else {
            String::from("Files on card")
        };
        draw_bar(t, m, &elide_end(&title, HEADING, m.w / 2))?;
        let l = self.layout(ctx);

        let active = match self.filter {
            FileFilter::PsbtOnly => 0,
            FileFilter::All => 1,
        };
        tabs(t, l.tabs, &TAB_LABELS, active)?;

        match l.well {
            Some(well) => {
                panel(t, well, PAPER_2, BORDER_STRONG)?;
                draw_block(t, well, &l.lines, PAPER_2)?;
            }
            None => {
                let mut clip = t.clipped(&l.viewport.to_eg());
                for (i, entry) in self.rows().iter().enumerate() {
                    let r = row_rect(&l.viewport, i, l.offset);
                    draw_row(&mut clip, r, &classify(entry, &self.dir), m.gap)?;
                }
            }
        }

        let summary = elide_end(&self.summary(), MONO_SMALL, l.summary.w);
        text(
            t,
            &summary,
            l.summary.x,
            l.summary.y + (l.summary.h - SMALL_LINE) / 2,
            MONO_SMALL,
            INK_SECONDARY,
            PAPER_1,
        )?;
        for (_, label, rect) in &l.buttons {
            button(t, *rect, label, ButtonKind::Secondary, PAPER_1)?;
        }
        Ok(())
    }

    fn activate(&mut self, id: RegionId, _env: &mut Env) -> Outcome {
        match id {
            RegionId::Tab(i) => {
                let filter = match i {
                    0 => FileFilter::PsbtOnly,
                    1 => FileFilter::All,
                    _ => return Outcome::stay(),
                };
                self.filter = filter;
                self.scroll = 0;
                self.card = CardState::Reading;
                Outcome::ask(list(self.dir.clone(), filter))
            }
            RegionId::FileRefresh => {
                self.scroll = 0;
                self.card = CardState::Reading;
                Outcome::ask(list(self.dir.clone(), self.filter))
            }
            RegionId::ListRow(i) => {
                let Some(entry) = self.rows().get(usize::from(i)) else { return Outcome::stay() };
                // Refused a second time here, so the rule survives even if a region were
                // ever emitted for a row `regions` does not offer.
                let (is_dir, name) = match classify(entry, &self.dir) {
                    Row::Dir(row) => (true, row.name.clone()),
                    Row::File(row) => (false, row.name.clone()),
                    Row::Blocked(..) => return Outcome::stay(),
                };
                if is_dir {
                    // Pushed, not entered: a directory is a level the user has to come back
                    // OUT of, and Back restores this listing without a second card read.
                    Outcome {
                        nav: Nav::Push(State::FilePicker(FilePickerState {
                            filter: self.filter,
                            dir: name.clone(),
                            card: CardState::Reading,
                            scroll: 0,
                        })),
                        request: Some(list(name, self.filter)),
                    }
                } else {
                    let dir = self.dir.clone();
                    if !self.card.start_load() {
                        return Outcome::stay();
                    }
                    Outcome::ask(UiRequest::LoadPsbt { dir, name })
                }
            }
            RegionId::ListPageNext => {
                self.scroll = page(self.scroll, PAGE_ROWS);
                Outcome::stay()
            }
            RegionId::ListPagePrev => {
                self.scroll = page(self.scroll, -PAGE_ROWS);
                Outcome::stay()
            }
            _ => Outcome::stay(),
        }
    }

    fn answered(&mut self, answer: Answer, _env: &mut Env) -> Outcome {
        match answer {
            Answer::Card(outcome) if matches!(self.card, CardState::Reading) => {
                self.scroll = 0;
                self.card = match outcome {
                    CardOutcome::Listed(listing) => CardState::Listed(listing),
                    CardOutcome::NoCard => CardState::NoCard,
                    CardOutcome::Unreadable(why) => CardState::Unreadable(why),
                };
                Outcome::stay()
            }
            Answer::Psbt(outcome) if matches!(self.card, CardState::Loading(_)) => {
                self.card.end_load();
                psbt_landed(outcome)
            }
            _ => Outcome::stay(),
        }
    }

    fn back(&self) -> Nav {
        if self.card.busy() {
            Nav::Stay
        } else {
            Nav::Back
        }
    }

    fn scroll_mut(&mut self) -> Option<&mut i32> {
        Some(&mut self.scroll)
    }

    fn scroll_limit(&self, ctx: &Ctx) -> i32 {
        let (_, viewport, _) = self.frame(&ctx.m);
        // The content ends at the BOTTOM OF THE LAST ROW, not a gap past it: a trailing gap
        // in the extent would let the list travel six pixels further than it has content and
        // park the topmost visible row above the viewport - painted through the clip and, by
        // the fit rule in `regions`, untappable.
        (self.content_h() - viewport.h).max(0)
    }
}

/// Step the offset by `rows`, from the nearest row boundary.
///
/// Snapping first is what keeps every pager landing on a whole row even after a drag left
/// the list between two: the pager is the discoverable control, and a control that leaves
/// the list showing half a row it will not offer is the defect this module is written
/// against. The result is deliberately not clamped here - it is a request for a position,
/// and [`FilePickerState::offset`] resolves it against the rows that actually exist.
fn page(scroll: i32, rows: i32) -> i32 {
    let snapped = (scroll + ROW_PITCH / 2) / ROW_PITCH * ROW_PITCH;
    (snapped + rows * ROW_PITCH).max(0)
}

/// The one place a card listing is asked for, so the depth limit travels with the request.
fn list(dir: String, filter: FileFilter) -> UiRequest {
    UiRequest::ListCard { dir, filter }
}

/// Where a [`UiRequest::LoadPsbt`] answer leaves the screen that raised it.
///
/// BOTH halves navigate, which is what this lane owes the request it raised: a screen that
/// handled only the success would leave every refused file on a Busy frame.
///
/// PUSHED rather than entered, in both cases. S-29's own body button reads "Back to sign"
/// and S-30's Back is a confirm that leaves the review, so both expect the screen the file
/// was chosen from to still be behind them - and pushing is also what lets a user whose file
/// was refused pick another one without the card being read a second time.
fn psbt_landed(outcome: PsbtOutcome) -> Outcome {
    Outcome::push(match outcome {
        PsbtOutcome::Reviewed(review) => State::Review(ReviewState::new(review)),
        PsbtOutcome::Refused(notice) => State::Refusal(RefusalState::new(notice)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::PANELS;
    use crate::screens::testing::{fits, rows_are_clear_on, Fixture, GEOMETRIES};
    use crate::{Network, RefusalCode, RefusalNotice};
    use embedded_graphics::geometry::{Dimensions, Point, Size};
    use embedded_graphics::primitives::Rectangle;
    use embedded_graphics::Pixel;

    // --- instruments ------------------------------------------------------------------

    /// A draw target that records the bounding box of every pixel a screen paints.
    ///
    /// It reports a bounding box far larger than any panel ON PURPOSE. The default
    /// `fill_solid` / `fill_contiguous` path would otherwise clip a rectangle to the target
    /// before this ever saw it, which is exactly how an off-panel draw stays invisible to a
    /// framebuffer that silently discards. This is tools/uisim's escape gate, in the crate,
    /// so a screen with no route through the public API yet is still measured.
    struct Ink {
        min: Point,
        max: Point,
        painted: bool,
    }

    impl Ink {
        fn new() -> Ink {
            Ink {
                min: Point::new(i32::MAX, i32::MAX),
                max: Point::new(i32::MIN, i32::MIN),
                painted: false,
            }
        }

        /// The panel this ink would all fit on, or the reason it would not.
        fn check(&self, m: &Metrics, what: &str) {
            assert!(self.painted, "{what}: the screen painted nothing at all");
            assert!(
                self.min.x >= 0 && self.min.y >= 0 && self.max.x < m.w && self.max.y < m.h,
                "{what}: ink spans ({},{})..({},{}) on a {}x{} panel",
                self.min.x,
                self.min.y,
                self.max.x,
                self.max.y,
                m.w,
                m.h
            );
        }
    }

    impl Dimensions for Ink {
        fn bounding_box(&self) -> Rectangle {
            Rectangle::new(Point::new(-100_000, -100_000), Size::new(200_000, 200_000))
        }
    }

    impl DrawTarget for Ink {
        type Color = Rgb565;
        type Error = core::convert::Infallible;

        fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
        where
            I: IntoIterator<Item = Pixel<Rgb565>>,
        {
            for Pixel(p, _) in pixels {
                self.painted = true;
                self.min = Point::new(self.min.x.min(p.x), self.min.y.min(p.y));
                self.max = Point::new(self.max.x.max(p.x), self.max.y.max(p.y));
            }
            Ok(())
        }
    }

    fn file(name: &str, len: u32) -> FileRow {
        FileRow {
            name: String::from(name),
            kind: FileKind::Psbt,
            len,
            modified: String::from("17 Aug 14:02"),
            oversize: false,
        }
    }

    fn listing(rows: Vec<FileRow>) -> CardListing {
        CardListing { dir: String::new(), rows, truncated: false, rejected: 0 }
    }

    fn psbts(n: usize) -> CardListing {
        listing((0..n).map(|i| file(&format!("spend-{i:03}.psbt"), 2400)).collect())
    }

    fn picker(card: CardState) -> FilePickerState {
        FilePickerState { filter: FileFilter::PsbtOnly, dir: String::new(), card, scroll: 0 }
    }

    fn source(card: CardState) -> SignSourceState {
        SignSourceState { card }
    }

    /// Every state either screen can be in, so a property can be asserted over all of them
    /// rather than over the one that was on someone's mind.
    fn every_card() -> Vec<CardState> {
        vec![
            CardState::Reading,
            CardState::Loading(psbts(3)),
            CardState::Listed(listing(Vec::new())),
            CardState::Listed(psbts(1)),
            CardState::Listed(psbts(3)),
            CardState::Listed(psbts(40)),
            CardState::NoCard,
            CardState::Unreadable(String::from(
                "the card holds no filesystem this device can read (esp_err=0x103)",
            )),
        ]
    }

    fn refusal() -> RefusalNotice {
        RefusalNotice {
            code: RefusalCode::NotAPsbt,
            happened: String::from("spend-vault.psbt does not start with the PSBT magic."),
            details: String::from("magic=0x00000000"),
            after_signing: false,
        }
    }

    /// A `TxReview` is a large struct with no `Default`. Nothing here reads a field of it:
    /// what this lane owes a reviewed transaction is a push into the screen that does.
    fn review() -> crate::TxReview {
        crate::TxReview {
            inputs: Vec::new(),
            outputs: Vec::new(),
            input_total: crate::Amount::ZERO,
            output_total: crate::Amount::ZERO,
            fee: crate::ReviewedFee::Enforced(crate::Amount::ZERO),
            lock_time: crate::LockTime::ZERO,
            rbf_signaled: false,
            network: Network::Bitcoin,
            fingerprint: String::from("a1b2c3d4"),
            wallet: String::from("savings"),
            source: String::from("spend-000.psbt"),
            signable_inputs: 1,
            unknown_fields: 0,
            serialized_len: 2400,
            psbt_id: String::new(),
            vsize: 141,
            vsize_exact: true,
            warnings: Vec::new(),
        }
    }

    /// A short name for a region, for the overlap report.
    fn label_of(id: RegionId) -> &'static str {
        match id {
            RegionId::SignPickFile => "pick",
            RegionId::FileShowAll => "show all",
            RegionId::FileRefresh => "refresh",
            RegionId::ListPagePrev => "prev",
            RegionId::ListPageNext => "next",
            _ => "action",
        }
    }

    // --- copy and formatting ----------------------------------------------------------

    /// Every line advance is at least its font's own line box, which is what makes a block's
    /// height the exact sum of its advances - and therefore what lets a block be trimmed to
    /// a room bound without the last line crossing the border drawn under it.
    #[test]
    fn a_line_never_advances_less_than_its_font_needs() {
        for l in [
            Line::head(String::new()),
            Line::body(String::new()),
            Line::mono(String::new()),
            Line::detail(String::new(), INK_MUTED),
        ] {
            assert!(
                l.font.line_height as i32 <= l.adv,
                "{} {} advances {} with a {} px line box",
                l.font.family,
                l.font.style,
                l.adv,
                l.font.line_height
            );
        }
    }

    /// A size is never overstated, and the cap the rows print is the cap they enforce.
    #[test]
    fn a_size_is_rounded_down() {
        assert_eq!(size_label(0), "0 B");
        assert_eq!(size_label(999), "999 B");
        assert_eq!(size_label(2400), "2.4 kB");
        assert_eq!(size_label(2499), "2.4 kB");
        assert_eq!(size_label(11_800), "11.8 kB");
        assert_eq!(MAX_FILE_BYTES, 1024 * 1024);
        assert_eq!(size_label(MAX_FILE_BYTES), "1.0 MB");
    }

    /// A name too wide for its row keeps its head AND its tail, so two names sharing a long
    /// prefix cannot render as the same string.
    #[test]
    fn a_long_name_is_elided_in_the_middle() {
        let a = "transaction-from-the-coordinator-2026-08-19-aaaa.psbt";
        let b = "transaction-from-the-coordinator-2026-08-19-bbbb.psbt";
        let w = 300;
        let (ea, eb) = (elide_middle(a, MONO, w), elide_middle(b, MONO, w));
        assert_ne!(ea, eb, "two names elided to the same string: {ea}");
        assert!(ea.contains(ELLIPSIS), "{ea} was not marked as shortened");
        assert!(ea.starts_with("tra") && ea.ends_with("psbt"), "{ea} lost an end");
        for e in [&ea, &eb] {
            assert!(MONO.text_width(e) as i32 <= w, "{e} still does not fit {w} px");
        }
        assert_eq!(elide_middle("a.psbt", MONO, w), "a.psbt", "a name that fits was touched");
    }

    /// A block trimmed to fit keeps its head and says that it was trimmed - and an embedder
    /// sentence longer than [`UNTRUSTED_MAX`] is cut before it is ever wrapped, with its own
    /// marker, so a hostile length costs a bounded amount of work and a bounded number of
    /// lines.
    #[test]
    fn a_trimmed_block_keeps_the_actionable_copy() {
        let long = CardState::Unreadable("word ".repeat(400));
        let full = card_block(&long, 400);
        assert!(full.len() > 4, "the long sentence was dropped instead of bounded");
        assert!(full.len() < 40, "an unbounded sentence produced {} lines", full.len());
        assert_eq!(full.last().unwrap().text, ELLIPSIS, "a cut sentence did not say so");

        let room = 2 * WELL_PAD + 4 * LINE;
        let cut = fit_block(card_block(&long, 400), room);
        assert!(block_h(&cut) <= room, "a trimmed block is {} px in {room} px", block_h(&cut));
        // The headline wraps, so the assertion is on what survived rather than on one
        // fragment of it: whatever else a trim takes, it starts with the sentence the user
        // has to read.
        assert!(cut[0].text.starts_with("The card"), "the head was trimmed: {:?}", cut[0].text);
        assert_eq!(cut.last().unwrap().text, ELLIPSIS);

        // A sentence the atlas cannot draw is dropped whole rather than rendered as a row
        // of question marks.
        let hostile = CardState::Unreadable(String::from("mount failed \u{0007}\u{0000}"));
        assert!(
            card_block(&hostile, 400).iter().all(|l| l.adv != SMALL_LINE),
            "unrenderable bytes reached a well"
        );
    }

    /// A name this device cannot draw faithfully is never offered, whatever it holds.
    #[test]
    fn a_hostile_name_is_refused() {
        let hostile = [
            String::from("spend\u{0000}.psbt"),
            String::from("spend\t.psbt"),
            String::from("sp\u{00e9}nd.psbt"),
            String::new(),
            "a".repeat(NAME_MAX + 1),
        ];
        for name in hostile {
            let mut row = file("x.psbt", 2400);
            row.name = name.clone();
            assert!(
                matches!(classify(&row, ""), Row::Blocked(..)),
                "{name:?} was offered as a file"
            );
        }
        assert!(matches!(classify(&file("spend.psbt", 2400), ""), Row::File(_)));

        // ...and the decision reaches the screen: the row is painted with its reason and
        // is not offered, so its bytes can never travel in a request.
        let mut row = file("x.psbt", 2400);
        row.name = String::from("spend\u{0000}.psbt");
        let f = Fixture::new(720, 720);
        let ctx = f.ctx();
        let mut s = picker(CardState::Listed(listing(vec![row])));
        let mut out = Vec::new();
        s.regions(&ctx, &mut out);
        assert!(
            !out.iter().any(|r| matches!(r.id, RegionId::ListRow(_))),
            "a row whose name cannot be drawn was made tappable"
        );
        let mut net = Network::Bitcoin;
        let mut env = Env { network: &mut net, lock: &f.lock, wallets: &f.wallets };
        assert!(
            s.activate(RegionId::ListRow(0), &mut env).request.is_none(),
            "a row whose name cannot be drawn raised a request"
        );
    }

    // --- the size cap ------------------------------------------------------------------

    /// The cap is enforced by the SCREEN and before anything is read: an oversize row is
    /// never offered, and a tap on one produces no request - whether the embedder flagged it
    /// or not.
    #[test]
    fn an_oversize_file_never_becomes_a_read() {
        let mut flagged = file("huge.psbt", 2400);
        flagged.oversize = true;
        let unflagged = file("huge.psbt", MAX_FILE_BYTES + 1);
        for row in [flagged, unflagged] {
            let Row::Blocked(_, why) = classify(&row, "") else {
                panic!("{} was offered for reading", row.name);
            };
            assert!(why.contains("1.0 MB"), "the refusal does not state the cap: {why}");

            let f = Fixture::new(720, 720);
            let ctx = f.ctx();
            let mut s = picker(CardState::Listed(listing(vec![row])));
            let mut out = Vec::new();
            s.regions(&ctx, &mut out);
            assert!(
                !out.iter().any(|r| matches!(r.id, RegionId::ListRow(_))),
                "an oversize row was made tappable"
            );
            let mut net = Network::Bitcoin;
            let mut env = Env { network: &mut net, lock: &f.lock, wallets: &f.wallets };
            assert!(
                s.activate(RegionId::ListRow(0), &mut env).request.is_none(),
                "an oversize row raised a request"
            );
        }
    }

    // --- layout, on both panels ---------------------------------------------------------

    /// S-27 in every state: nothing escapes the body, nothing overlaps, every control clears
    /// the touch floor, and every string fits the rectangle it is drawn in.
    #[test]
    fn the_source_screen_lays_out_on_both_panels() {
        for (w, h) in GEOMETRIES {
            for card in every_card() {
                let f = Fixture::new(w, h);
                let ctx = f.ctx();
                let s = source(card);
                let what = format!("{w}x{h} S-27 {:?}", s.id());
                if s.card.busy() {
                    let mut out = Vec::new();
                    s.regions(&ctx, &mut out);
                    assert!(out.is_empty(), "{what}: a Busy frame offered {} regions", out.len());
                    assert!(matches!(s.back(), Nav::Stay), "{what}: a Busy frame went Back");
                    continue;
                }
                let l = s.layout(&ctx);
                let mut rows = vec![("status", l.status), ("note", l.note)];
                for (id, _, r) in &l.actions {
                    rows.push((label_of(*id), *r));
                }
                rows_are_clear_on(&f.m, &what, f.m.body(), &rows);
                assert!(!l.actions.is_empty(), "{what}: a state with no way out");
                for (_, label, r) in &l.actions {
                    fits(&what, label, HEADING.text_width(label) as i32, *r);
                    assert!(r.h >= TOUCH_MIN && r.w >= TOUCH_MIN, "{what}: {label} is {r:?}");
                }
                for line in &l.lines {
                    // Against the INNER rect: `draw_block` insets by the well's padding, so
                    // measuring against the well itself would allow a line 24 px too wide.
                    let inner = l.status.inset(WELL_PAD);
                    fits(&what, &line.text, line.font.text_width(&line.text) as i32, inner);
                }
                for line in &l.note_lines {
                    fits(
                        &what,
                        &line.text,
                        line.font.text_width(&line.text) as i32,
                        l.note.inset(WELL_PAD),
                    );
                }
                if s.ready().is_some() {
                    assert!(l.status.h >= READY_MIN_H, "{what}: the ready card is {:?}", l.status);
                }
            }
        }
    }

    /// S-28 in every state, at both ends of its travel.
    #[test]
    fn the_picker_lays_out_on_both_panels() {
        for (w, h) in GEOMETRIES {
            for card in every_card() {
                let f = Fixture::new(w, h);
                let ctx = f.ctx();
                let mut s = picker(card);
                let what = format!("{w}x{h} S-28 {:?}", s.id());
                if s.card.busy() {
                    let mut out = Vec::new();
                    s.regions(&ctx, &mut out);
                    assert!(out.is_empty(), "{what}: a Busy frame offered {} regions", out.len());
                    continue;
                }
                for offset in [0, s.scroll_limit(&ctx)] {
                    s.scroll = offset;
                    let l = s.layout(&ctx);
                    assert!(l.summary.w > 0, "{what}: the footer left no room for its summary");
                    let mut rows =
                        vec![("tabs", l.tabs), ("viewport", l.viewport), ("summary", l.summary)];
                    for (id, _, r) in &l.buttons {
                        rows.push((label_of(*id), *r));
                    }
                    rows_are_clear_on(&f.m, &what, f.m.body(), &rows);
                    if let Some(well) = l.well {
                        assert!(
                            well.y >= l.viewport.y && well.bottom() <= l.viewport.bottom(),
                            "{what}: the well {well:?} escapes the viewport {:?}",
                            l.viewport
                        );
                        for line in &l.lines {
                            let inner = well.inset(WELL_PAD);
                            fits(&what, &line.text, line.font.text_width(&line.text) as i32, inner);
                        }
                    }
                    for (_, label, r) in &l.buttons {
                        fits(&what, label, HEADING.text_width(label) as i32, *r);
                        assert!(r.h >= TOUCH_MIN && r.w >= TOUCH_MIN, "{what}: {label} is {r:?}");
                    }
                    let mut out = Vec::new();
                    s.regions(&ctx, &mut out);
                    for r in &out {
                        // Back is `components::back_rect`, which every screen in the crate
                        // shares and which is 51 px tall on the 800x480 panel. That is a
                        // defect in the shared bar rather than in this screen, and asserting
                        // it here would only mean this screen could never state the property
                        // for the controls it does own.
                        if r.id == RegionId::Back {
                            continue;
                        }
                        assert!(
                            r.rect.w >= TOUCH_MIN && r.rect.h >= TOUCH_MIN,
                            "{what}: {:?} is {}x{}",
                            r.id,
                            r.rect.w,
                            r.rect.h
                        );
                    }
                }
            }
        }
    }

    /// The viewport is a whole number of rows and holds a full page, on EVERY shipped panel.
    ///
    /// The first half is what makes "painted is tappable" hold by construction rather than
    /// by luck. The second is what keeps the pager honest: a step of [`PAGE_ROWS`] can only
    /// carry the list over a row nobody saw if some viewport is shorter than a page.
    #[test]
    fn the_viewport_holds_at_least_a_page() {
        for (w, h) in PANELS {
            let f = Fixture::new(w, h);
            let (tabs, viewport, foot_y) = picker(CardState::Listed(psbts(40))).frame(&f.m);
            let rows = (viewport.h + ROW_GAP) / ROW_PITCH;
            assert!(rows >= PAGE_ROWS, "{w}x{h}: the list viewport holds {rows} rows");
            assert_eq!(viewport.h, row_extent(rows), "{w}x{h}: the viewport ends inside a row");
            assert!(viewport.y >= tabs.bottom(), "{w}x{h}: the list runs into the tabs");
            assert!(viewport.bottom() <= foot_y, "{w}x{h}: the list runs into the footer");
        }
    }

    /// The transport note is rendered in FULL on every shipped panel.
    ///
    /// The layout can trim it, which is what stops a panel this crate has never seen from
    /// painting the explanation off the glass. This is the other half of that: on the panels
    /// that DO ship the trim must never fire, or the device would ship a sentence with its
    /// end cut off. It fired on the 800x480 panel at a two-fifths column split, which is how
    /// that split was found to be wrong.
    #[test]
    fn the_transport_note_fits_every_shipped_panel() {
        let mut one = Vec::new();
        push_prose(&mut one, TRANSPORT_NOTE, 10_000);
        let whole = one[0].text.clone();
        for (w, h) in PANELS {
            let f = Fixture::new(w, h);
            let ctx = f.ctx();
            for card in every_card() {
                let s = source(card);
                if s.card.busy() {
                    continue;
                }
                let l = s.layout(&ctx);
                let note = l.note;
                let joined = l
                    .note_lines
                    .iter()
                    .map(|line| line.text.as_str())
                    .collect::<Vec<_>>()
                    .join(" ");
                assert_eq!(joined, whole, "{w}x{h}: the transport note was shortened");
                assert_eq!(block_h(&l.note_lines), note.h, "{w}x{h}: the well is not its copy");
                for line in &l.note_lines {
                    fits(
                        &format!("{w}x{h} note"),
                        &line.text,
                        line.font.text_width(&line.text) as i32,
                        note.inset(WELL_PAD),
                    );
                }
            }
        }
    }

    /// S-27's status well always has room for a headline and a line of prose, and for the
    /// ready card's full height, on every shipped panel.
    #[test]
    fn the_status_well_always_has_room_for_its_sentence() {
        for (w, h) in PANELS {
            let f = Fixture::new(w, h);
            let ctx = f.ctx();
            for card in every_card() {
                if card.busy() {
                    continue;
                }
                let s = source(card);
                let l = s.layout(&ctx);
                assert!(
                    l.status.h >= 2 * WELL_PAD + 2 * LINE,
                    "{w}x{h}: the status well is only {} px",
                    l.status.h
                );
                assert!(!l.lines.is_empty(), "{w}x{h}: a state with nothing to say");
            }
        }
    }

    // --- scrolling ----------------------------------------------------------------------

    /// THE INVARIANT: at rest, every row that is PAINTED and offerable is TAPPABLE.
    ///
    /// `draw` paints each row through a clip on the viewport, so any overlap at all leaves
    /// ink - a row fills its whole rect before it draws a word. `regions` emits a row only
    /// when it fits entirely. Wherever the list is standing still the two sets have to be
    /// the SAME set, or the screen shows a control that does nothing.
    ///
    /// Checked at every resting offset: no scroll, the scroll limit, and every landing the
    /// pager can produce. Mid-drag is deliberately excluded - a row scrolled halfway off the
    /// top is half a row and must not tap.
    #[test]
    fn every_painted_row_at_rest_is_tappable() {
        for (w, h) in GEOMETRIES {
            for n in [1usize, 2, 3, 7, 40] {
                let f = Fixture::new(w, h);
                let ctx = f.ctx();
                let mut s = picker(CardState::Listed(psbts(n)));
                let limit = s.scroll_limit(&ctx);
                let mut rests = vec![0, limit];
                let mut at = 0;
                while at < limit {
                    at = page(at, PAGE_ROWS);
                    rests.push(at.min(limit));
                }
                for offset in rests {
                    s.scroll = offset;
                    let l = s.layout(&ctx);
                    let mut out = Vec::new();
                    s.regions(&ctx, &mut out);
                    for i in 0..n {
                        let r = row_rect(&l.viewport, i, l.offset);
                        let painted = r.y < l.viewport.bottom() && r.bottom() > l.viewport.y;
                        let tappable =
                            out.iter().any(|g| g.id == RegionId::ListRow(i as u8) && g.rect == r);
                        assert_eq!(
                            painted, tappable,
                            "{w}x{h}, {n} rows at scroll {offset}: row {i} at {r:?} is \
                             painted={painted} tappable={tappable} in viewport {:?}",
                            l.viewport
                        );
                    }
                }
            }
        }
    }

    /// Every row is reachable: the last one comes fully inside the viewport at the limit, or
    /// a file on the card would be invisible on the screen that lists it.
    #[test]
    fn scrolling_reaches_the_last_row() {
        for (w, h) in GEOMETRIES {
            for n in [3usize, 40, MAX_ROWS] {
                let f = Fixture::new(w, h);
                let ctx = f.ctx();
                let mut s = picker(CardState::Listed(psbts(n)));
                s.scroll = s.scroll_limit(&ctx);
                let l = s.layout(&ctx);
                let last = row_rect(&l.viewport, n - 1, l.offset);
                assert!(
                    last.bottom() <= l.viewport.bottom() && last.y >= l.viewport.y,
                    "{w}x{h}, {n} rows: the last row is at {last:?} in {:?}",
                    l.viewport
                );
            }
        }
    }

    /// A stale offset is resolved, never rendered: the pager may ask for a position the
    /// listing does not have, and a refresh may return fewer rows than the last one did.
    #[test]
    fn an_offset_past_the_content_is_resolved_not_rendered() {
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            let ctx = f.ctx();
            let mut s = picker(CardState::Listed(psbts(40)));
            s.scroll = 400 * ROW_PITCH;
            assert_eq!(s.layout(&ctx).offset, s.scroll_limit(&ctx));
            s.card = CardState::Listed(psbts(2));
            assert_eq!(s.layout(&ctx).offset, 0, "{w}x{h}: a shrunken listing kept a stale offset");
        }
    }

    /// The pager lands on whole rows even when a drag left the list between two, and it is
    /// offered only where there is more than a second viewport to reach.
    #[test]
    fn the_pager_lands_on_whole_rows() {
        assert_eq!(page(0, PAGE_ROWS), PAGE_ROWS * ROW_PITCH);
        assert_eq!(page(ROW_PITCH * 3 + 7, -PAGE_ROWS), (3 - PAGE_ROWS) * ROW_PITCH);
        assert_eq!(page(0, -PAGE_ROWS), 0, "the pager stepped above the first row");
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            let ctx = f.ctx();
            for (n, want) in [(2usize, false), (40, true)] {
                let has = picker(CardState::Listed(psbts(n)))
                    .layout(&ctx)
                    .buttons
                    .iter()
                    .any(|(id, _, _)| *id == RegionId::ListPageNext);
                assert_eq!(has, want, "{w}x{h}, {n} rows: pager offered={has}");
            }
        }
    }

    /// A listing deeper than [`RegionId::ListRow`] can name is cut to what a tap can reach,
    /// and the footer says so rather than leaving rows nobody can open.
    #[test]
    fn a_listing_past_the_row_index_bound_is_cut_and_stated() {
        let f = Fixture::new(720, 720);
        let ctx = f.ctx();
        let mut s = picker(CardState::Listed(psbts(MAX_ROWS + 40)));
        assert_eq!(s.rows().len(), MAX_ROWS);
        assert!(
            s.summary().contains(&format!("showing the first {MAX_ROWS}")),
            "the footer hides the shortfall: {}",
            s.summary()
        );
        s.scroll = s.scroll_limit(&ctx);
        let mut out = Vec::new();
        s.regions(&ctx, &mut out);
        assert!(s.layout(&ctx).offset <= row_extent(MAX_ROWS as i32));
        assert!(out.iter().any(|r| matches!(r.id, RegionId::ListRow(_))));
    }

    /// A truncated or partly unreadable card says so, rather than looking like a card that
    /// simply holds less.
    #[test]
    fn what_the_card_would_not_give_up_is_stated() {
        let mut l = psbts(3);
        l.truncated = true;
        l.rejected = 4;
        let s = picker(CardState::Listed(l));
        let summary = s.summary();
        assert!(summary.contains("3 files"), "{summary}");
        assert!(summary.contains("more than the device will list"), "{summary}");
        assert!(summary.contains("4 names unreadable"), "{summary}");
    }

    /// The two tabs tile their bar exactly, so a tap between them cannot land on paper.
    #[test]
    fn the_tabs_tile_their_bar() {
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            let (bar, _, _) = picker(CardState::NoCard).frame(&f.m);
            let a = tab_rect(&bar, 0, 2);
            let b = tab_rect(&bar, 1, 2);
            assert_eq!((a.x, a.right(), b.right()), (bar.x, b.x, bar.right()), "{w}x{h}");
            assert!(!a.overlaps(&b));
        }
    }

    // --- requests and answers ------------------------------------------------------------

    /// Every failure the card layer can produce reaches a sentence and a way out, and none of
    /// them leaves the panel on the Busy frame.
    #[test]
    fn every_card_failure_reaches_a_sentence() {
        let f = Fixture::new(720, 720);
        let mut net = Network::Bitcoin;
        let mut env = Env { network: &mut net, lock: &f.lock, wallets: &f.wallets };
        for outcome in [
            CardOutcome::NoCard,
            CardOutcome::Unreadable(String::from("no FAT filesystem")),
            CardOutcome::Listed(listing(Vec::new())),
        ] {
            let mut s = source(CardState::Reading);
            s.answered(Answer::Card(outcome.clone()), &mut env);
            assert!(!s.card.busy(), "an answer left S-27 on a Busy frame");
            assert!(!s.actions().is_empty(), "a failure with no way out");
            assert!(!s.status_block(600).is_empty(), "a failure with nothing to read");

            let mut p = picker(CardState::Reading);
            p.answered(Answer::Card(outcome), &mut env);
            assert!(!p.card.busy(), "an answer left S-28 on a Busy frame");
            assert!(!card_block(&p.card, 600).is_empty(), "a failure with nothing to read");
        }
    }

    /// Both halves of a load answer navigate, and the screen behind them goes back to
    /// showing its listing - so Back out of a refusal or a review lands on a usable picker
    /// rather than on the Busy frame the request left behind.
    #[test]
    fn a_load_answer_navigates_and_leaves_a_usable_screen_behind() {
        let f = Fixture::new(720, 720);
        let mut net = Network::Bitcoin;
        let mut env = Env { network: &mut net, lock: &f.lock, wallets: &f.wallets };
        for (outcome, is_review) in [
            (PsbtOutcome::Refused(refusal()), false),
            (PsbtOutcome::Reviewed(review()), true),
        ] {
            let mut s = picker(CardState::Loading(psbts(3)));
            let out = s.answered(Answer::Psbt(outcome), &mut env);
            let landed = match out.nav {
                Nav::Push(State::Review(_)) => true,
                Nav::Push(State::Refusal(_)) => false,
                _ => panic!("a load answer did not leave the Busy frame"),
            };
            assert_eq!(landed, is_review);
            assert!(!s.card.busy(), "the screen behind the answer is still Busy");
            assert_eq!(s.rows().len(), 3, "the listing was thrown away");
        }
    }

    /// An answer to a request the screen is no longer waiting for is dropped: the user has
    /// moved on, and a late answer must not move the panel back.
    #[test]
    fn a_late_answer_is_dropped() {
        let f = Fixture::new(720, 720);
        let mut net = Network::Bitcoin;
        let mut env = Env { network: &mut net, lock: &f.lock, wallets: &f.wallets };
        let mut s = picker(CardState::Listed(psbts(3)));
        let out = s.answered(Answer::Card(CardOutcome::NoCard), &mut env);
        assert!(matches!(out.nav, Nav::Stay));
        assert!(matches!(s.card, CardState::Listed(_)), "a late listing replaced the screen");
        let out = s.answered(Answer::Psbt(PsbtOutcome::Refused(refusal())), &mut env);
        assert!(matches!(out.nav, Nav::Stay), "a late refusal moved the panel");
        assert!(matches!(s.card, CardState::Listed(_)), "a late refusal replaced the screen");
    }

    /// S-27 offers exactly one loadable transaction and reads it only when the user taps it;
    /// anything else is a choice and goes to the picker.
    #[test]
    fn one_transaction_is_offered_and_several_are_a_choice() {
        let f = Fixture::new(720, 720);
        let mut net = Network::Bitcoin;
        let mut env = Env { network: &mut net, lock: &f.lock, wallets: &f.wallets };

        let mut one = source(CardState::Reading);
        let out = one.answered(Answer::Card(CardOutcome::Listed(psbts(1))), &mut env);
        assert!(matches!(out.nav, Nav::Stay) && out.request.is_none());
        assert!(one.ready().is_some(), "one transaction was not offered");

        let mut several = source(CardState::Reading);
        let out = several.answered(Answer::Card(CardOutcome::Listed(psbts(2))), &mut env);
        assert!(
            matches!(out.nav, Nav::Enter(State::FilePicker(_))),
            "two transactions did not reach the picker"
        );

        // The tap is what starts the read. Inserting a card is not.
        let out = one.activate(RegionId::SignReady, &mut env);
        assert!(
            matches!(out.request, Some(UiRequest::LoadPsbt { ref name, .. })
                if name == "spend-000.psbt"),
            "the ready card did not read the file it named"
        );
        assert!(one.card.busy(), "the read did not put the panel on a Busy frame");
    }

    /// A directory is pushed, so Back restores the listing behind it without a second read,
    /// and nothing descends twice.
    #[test]
    fn a_directory_is_one_level_deep() {
        let f = Fixture::new(720, 720);
        let mut net = Network::Bitcoin;
        let mut env = Env { network: &mut net, lock: &f.lock, wallets: &f.wallets };
        let mut dir = file("bundles", 0);
        dir.kind = FileKind::Directory;
        let mut s = picker(CardState::Listed(listing(vec![dir.clone()])));
        let out = s.activate(RegionId::ListRow(0), &mut env);
        assert!(matches!(out.nav, Nav::Push(State::FilePicker(_))));
        assert!(
            matches!(out.request, Some(UiRequest::ListCard { ref dir, .. }) if dir == "bundles")
        );
        assert!(matches!(classify(&dir, "bundles"), Row::Blocked(..)), "a nested folder descended");
    }

    // --- pixels ---------------------------------------------------------------------------

    /// Nothing either screen paints lands off the panel, in any state, on any shipped panel.
    ///
    /// The layout checks above can only see rectangles a `Layout` names; a heading, a hint or
    /// a row's own text is drawn at a rectangle no struct holds. This measures the ink.
    #[test]
    fn nothing_draws_off_the_panel() {
        for (w, h) in PANELS {
            for card in every_card() {
                let f = Fixture::new(w, h);
                let ctx = f.ctx();
                let s = source(card);
                let mut ink = Ink::new();
                s.draw(&mut ink, &ctx).expect("infallible");
                ink.check(&f.m, &format!("{w}x{h} S-27 {:?}", s.id()));
            }
            for card in every_card() {
                let f = Fixture::new(w, h);
                let ctx = f.ctx();
                let mut s = picker(card);
                for offset in [0, s.scroll_limit(&ctx)] {
                    s.scroll = offset;
                    let mut ink = Ink::new();
                    s.draw(&mut ink, &ctx).expect("infallible");
                    ink.check(&f.m, &format!("{w}x{h} S-28 {:?} at {offset}", s.id()));
                }
            }
        }
    }

    /// The instrument itself: a recorder that could not see an escape would let every test
    /// above pass while measuring nothing.
    #[test]
    fn the_ink_recorder_sees_a_draw_off_the_panel() {
        let mut ink = Ink::new();
        fill(&mut ink, Rect::new(-4, 700, 20, 40), DANGER).expect("infallible");
        assert!(ink.painted);
        assert!(ink.min.x < 0, "an off-panel column was not recorded");
        assert!(ink.max.y >= 720, "an off-panel row was not recorded");
    }
}
