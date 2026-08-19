// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! S-41 / S-42 / S-43: the multisig registry, the import review, and the detail screen.
//!
//! # What a registration is, and why these three screens are one module
//!
//! A multisig registration is a claim by an OUTSIDE party about which keys control money.
//! It arrives as text on a card that anybody could have written. Accepting a wrong one
//! does not merely inconvenience the user: it tells this device, for the life of the
//! wallet, which outputs count as change and which cosigner is us - so a substituted
//! cosigner key turns "coming back to you" into "leaving forever", and a quorum the user
//! did not agree to turns a 2-of-3 into a 1-of-1 somebody else holds.
//!
//! The three screens are one module because they are one act: the registry offers the
//! import, the review IS the consent, and the detail screen is the cross-check that
//! finishes it. They hand each other whole values rather than re-reading a list - S-42
//! hands its [`RegistrationReview`] to S-43, which is the only reason S-43 can show the
//! first address at all - and they share one vocabulary for facts, prose and rows.
//!
//! # The four things this module refuses to do
//!
//! 1. **Approve a wallet this device is not provably in.** [`Blocked`] is computed once at
//!    construction and consulted by `regions`, so [`RegionId::MsApprove`] cannot be
//!    emitted while it says no. A review whose `ours` index disagrees with the cosigner
//!    row that claims to be ours is the 2021 xpub-substitution attack arriving with a
//!    forged label on it. The engine already refuses that; the screen refuses it again,
//!    because a screen that CAN draw an approve button over an answer it did not
//!    understand is a screen that will eventually be handed one.
//! 2. **Approve a policy that cannot exist.** 0 of 3, 4 of 3, no cosigners, more than
//!    [`MAX_COSIGNERS`]. Rendering one as an ordinary review would teach the reader that
//!    the shape is normal.
//! 3. **Render attacker text as it arrived.** Every string that came off a card goes
//!    through [`printable`] first: the font atlas is U+0020..U+007E plus U+2022 and
//!    U+2026, so anything outside it draws as nothing at all - which is a free
//!    impersonation of any wallet the user already trusts. Names are additionally capped,
//!    and a cap that fired is STATED on the page rather than applied silently.
//! 4. **Write to flash without saying so first.** The last page of S-42 carries the C12
//!    notice naming the registration, its policy and its descriptor checksum, directly
//!    above the only control that can store it (ratified invariant 2b), and outside the
//!    scrolled content - an announcement you can scroll away from was not made.
//!
//! # The first-address cross-check
//!
//! The membership proof establishes that OUR key is in the set. It cannot establish that
//! the OTHER keys are the ones the user's other signers hold - nothing on an airgapped
//! device can, because the only evidence is the file itself. What closes that gap is
//! comparing the wallet's first receive address on a second device: substitute any
//! cosigner key and the sorted key set changes, so the witness script changes, so the
//! address changes. S-42's last page and S-43 both show that address in full and say why,
//! and S-43 opens with it already disclosed when it was reached by approving an import,
//! because that is the moment the comparison is worth something.
//!
//! # One departure from the screen contract, and why
//!
//! The contract says an unreadable registration row is not tappable to detail. The intent
//! behind that - never present an unproven registration as usable - is kept: S-43 renders
//! it in DANGER, shows no cosigners because it has none, and offers exactly one action.
//! What the literal rule would cost is the remedy the row itself states, because deleting
//! a registration is an S-43 control: a slot nothing can erase stays until the registry is
//! full, and then the user is refused an import they have no way to act on.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use embedded_graphics::draw_target::{DrawTarget, DrawTargetExt};
use embedded_graphics::pixelcolor::Rgb565;
use notyas_fonts::Atlas;

use crate::canvas::{button, fill, frame, text, wrap_words, ButtonKind, BODY, HEADING, MONO_SMALL};
use crate::components::{
    back_rect, draw_bar, draw_bar_no_back, write_notice, write_notice_h, LINE, SMALL_LINE,
};
use crate::danger::{Danger, DangerGrade, DangerOutcome};
use crate::layout::{Metrics, Rect, LIST_ROW_MIN};
use crate::screens::refusal::RefusalState;
use crate::screens::review::marker;
use crate::screens::wallets::chip;
use crate::screens::{Answer, Ctx, Env, Nav, Outcome, Screen, State};
use crate::theme::*;
use crate::{
    CardListing, CardOutcome, FileFilter, FileKind, FileRow, ImportOutcome, Region, RegionId,
    RegistrationInfo, RegistrationOutcome, RegistrationReview, ScreenId, StoreStatus, UiRequest,
    WalletInfo, WalletRow,
};

// ---------------------------------------------------------------------------------------
// Bounds on what a card may put on this panel
// ---------------------------------------------------------------------------------------

/// The largest cosigner set 0.2.0 stores, mirrored from `notyas_core::multisig`.
///
/// Restated rather than imported so this crate stays a renderer with no opinion about the
/// engine's internals, and asserted equal to the engine's constant in this module's tests
/// - which is the part that makes restating it safe rather than a second source of truth.
const MAX_COSIGNERS: usize = 15;

/// The longest descriptor this module will measure or draw.
///
/// Fifteen cosigners at roughly 170 characters each - a 111-character xpub, a
/// `[fingerprint/48h/0h/0h/2h]` origin and a `/<0;1>/*` tail - plus the wrapper, is about
/// 2600. Three thousand is that with room to spare, and it is a bound the UI can STATE
/// instead of discover: a descriptor longer than any wallet this device can hold did not
/// come from a wallet this device can hold, so wrapping and measuring it would be work
/// performed on behalf of a file that is already refused. The store bounds the WRITE;
/// this bounds the RENDER, which happens first.
const MAX_DESCRIPTOR_CHARS: usize = 3000;

/// The longest label this module prints, in characters.
///
/// A name is the one field on a registration with no structure to check it against, and it
/// is drawn beside the values the user is meant to compare. Capping it stops a hostile file
/// from pushing those values off the bottom of a scroll. The cap is announced on the page
/// rather than applied silently: a name this device shortened no longer matches what the
/// other device shows, and the user has to know that before they compare the two.
const MAX_NAME_CHARS: usize = 48;

/// The longest name a C4d sheet will ask to be typed back.
///
/// Past this the sheet asks for the SLOT NUMBER instead. A confirmation nobody can complete
/// is not friction, it is a dead end, and a 200-character name out of a hostile file would
/// be exactly that on a screen keyboard.
const MAX_TYPED_NAME: usize = 24;

/// The longest name the C12 write notice prints. See [`MultisigImportState::notice_copy`].
const NOTICE_NAME_CHARS: usize = 24;

/// The most file rows the import picker will offer.
///
/// [`RegionId::ListRow`] carries a `u8`, so a row past 255 could not be named by a tap even
/// if it were drawn. The embedder bounds the listing long before this; the bound is
/// restated because "the region vocabulary cannot express it" is a reason that survives the
/// embedder changing its mind.
const MAX_PICK_ROWS: usize = 256;

const ELLIPSIS: char = '\u{2026}';

/// Characters this device's font atlas can draw: printable ASCII, the bullet, the ellipsis.
/// Everything else is replaced rather than drawn.
fn in_atlas(c: char) -> bool {
    matches!(c, ' '..='~') || c == BULLET || c == ELLIPSIS
}

/// Text from a card, made safe to put on this panel.
///
/// Two jobs, both about the same failure. A character the atlas cannot draw renders as
/// nothing at all, so a name written in glyphs this device does not have would appear
/// SHORTER, different, possibly empty - a free impersonation of any wallet the user already
/// trusts. Replacing with `?` makes the substitution visible instead of invisible. The cap
/// then bounds what one field can do to a layout, and the `bool` says whether it fired so
/// that every caller can state it.
fn printable(s: &str, cap: usize) -> (String, bool) {
    let mut out = String::new();
    let mut cut = false;
    for c in s.chars() {
        if out.chars().count() >= cap {
            cut = true;
            break;
        }
        out.push(if in_atlas(c) { c } else { '?' });
    }
    if cut {
        out.push(ELLIPSIS);
    }
    (out, cut)
}

/// [`printable`] with no cap, for values whose length their FORMAT bounds: an xpub, a
/// fingerprint, a derivation path, an address.
///
/// These are exactly what a user compares against another device, so shortening one would
/// defeat the comparison that is the only reason it is on the screen.
fn compared(s: &str) -> String {
    s.chars().map(|c| if in_atlas(c) { c } else { '?' }).collect()
}

/// A string trimmed to fit `w` pixels, with an ellipsis where it was cut.
///
/// For the top bar only, which draws its title as one unclipped run: a title wider than the
/// bar paints over the chip beside it and then off the glass, and a registration's name is
/// a value a file supplied. Nothing else in this module truncates - everything else wraps.
fn clamp_to_width(s: &str, w: i32, font: &'static Atlas) -> String {
    if font.text_width(s) as i32 <= w {
        return String::from(s);
    }
    let chars: Vec<char> = s.chars().collect();
    let mut keep = chars.len();
    while keep > 0 {
        keep -= 1;
        let mut candidate: String = chars[..keep].iter().collect();
        candidate.push(ELLIPSIS);
        if font.text_width(&candidate) as i32 <= w {
            return candidate;
        }
    }
    String::new()
}

/// The BIP-380 checksum at the end of a canonical descriptor: eight characters after a
/// `#`, and the value two devices holding one wallet compare in a single glance.
///
/// `None` for a descriptor carrying none, which the screen then says rather than inventing
/// one.
fn descriptor_checksum(descriptor: &str) -> Option<&str> {
    let (_, tail) = descriptor.rsplit_once('#')?;
    (tail.len() == 8 && tail.chars().all(|c| c.is_ascii_graphic())).then_some(tail)
}

/// A long value split into groups, so a reader compares a chunk at a time instead of
/// tracking 111 characters with a fingertip.
fn chunked(s: &str, per: usize) -> String {
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && i % per == 0 {
            out.push(' ');
        }
        out.push(c);
    }
    out
}

/// The word a C4d sheet asks to be typed back for one registration.
///
/// The name when it is short enough to type, the slot number otherwise. Both are on the
/// screen above the keyboard, so either way the user is copying something they can see -
/// which is the point of the grade: someone who cannot identify what they are erasing
/// should not be able to erase it. Every character [`printable`] can produce is on the
/// keyboard, so a sanitised name is always typeable; only its LENGTH can make it useless.
fn typed_word(name: &str, slot: u8) -> String {
    let (clean, cut) = printable(name, MAX_TYPED_NAME);
    if cut || clean.trim().is_empty() {
        slot.to_string()
    } else {
        clean
    }
}

// ---------------------------------------------------------------------------------------
// A measured column of prose
// ---------------------------------------------------------------------------------------

/// One drawn line: its text, the font it is in, and how far the pen moves after it.
struct Line {
    text: String,
    font: &'static Atlas,
    ink: Rgb565,
    advance: i32,
}

/// A block of prose, WRAPPED AT THE WIDTH IT WILL BE DRAWN AT and therefore measurable
/// before it is drawn.
///
/// Every long-form surface in this module is built through this: the empty states, the
/// cosigner pages, the address panel, the blocked-import statement. It exists rather than
/// each screen wrapping its own strings because of the defect class it removes - a screen
/// that measures a paragraph as two lines and draws three has no rectangle wrong, no region
/// misplaced and nothing any layout assertion can see, and the third line lands on whatever
/// is under it. Here the height IS the wrap, so the two cannot disagree.
struct Column {
    width: i32,
    lines: Vec<Line>,
}

impl Column {
    fn new(width: i32) -> Column {
        Column { width: width.max(1), lines: Vec::new() }
    }

    fn heading(&mut self, s: &str, ink: Rgb565) {
        self.wrapped(s, HEADING, ink, LINE);
    }

    fn body(&mut self, s: &str, ink: Rgb565) {
        self.wrapped(s, BODY, ink, SMALL_LINE);
    }

    /// A value with no word structure - an xpub, an address, a descriptor - wrapped by
    /// character count, so nothing is lost at a space that is not there.
    fn mono(&mut self, s: &str, ink: Rgb565) {
        let advance_px = MONO_SMALL.glyph('m').advance as i32;
        let per_line = (self.width / advance_px).max(1) as usize;
        let chars: Vec<char> = s.chars().collect();
        for chunk in chars.chunks(per_line) {
            self.lines.push(Line {
                text: chunk.iter().collect(),
                font: MONO_SMALL,
                ink,
                advance: SMALL_LINE,
            });
        }
    }

    /// Blank vertical space, so a paragraph break is part of the measurement.
    fn space(&mut self, h: i32) {
        self.lines.push(Line {
            text: String::new(),
            font: MONO_SMALL,
            ink: INK_PRIMARY,
            advance: h,
        });
    }

    fn wrapped(&mut self, s: &str, font: &'static Atlas, ink: Rgb565, advance: i32) {
        for line in wrap_words(s, self.width, font) {
            self.lines.push(Line { text: line, font, ink, advance });
        }
    }

    /// The pixels this column occupies.
    ///
    /// The advances, plus whatever the LAST line's glyph box overhangs its own advance.
    /// Measured at the box rather than at the advance because a frame drawn at the advance
    /// crosses the descenders of the closing sentence - the same correction the wallet
    /// list's empty-state well carries.
    fn height(&self) -> i32 {
        let mut h: i32 = self.lines.iter().map(|l| l.advance).sum();
        if let Some(last) = self.lines.last() {
            h += (last.font.line_height as i32 - last.advance).max(0);
        }
        h
    }

    /// Every drawn line, as (text, width in pixels). What the layout tests measure: a line
    /// wider than the frame it is drawn in does not wrap, it crops, silently.
    #[cfg(test)]
    fn measured(&self) -> Vec<(String, i32)> {
        self.lines
            .iter()
            .filter(|l| !l.text.is_empty())
            .map(|l| (l.text.clone(), l.font.text_width(&l.text) as i32))
            .collect()
    }

    /// Every drawn line's text, joined with nothing between them.
    ///
    /// The reading for a MONO value: `mono` wraps mid-token, so the characters either side
    /// of a break belong together and a separator would be a character the panel does not
    /// show. Lets a test assert that a value the user compares reached the panel in full.
    #[cfg(test)]
    fn joined(&self) -> String {
        self.lines.iter().map(|l| l.text.as_str()).collect()
    }

    /// Every drawn line's text, joined with a space.
    ///
    /// The reading for PROSE: `wrapped` breaks at spaces, so the space is what the reader
    /// sees at the break and the sentence only reads back with it restored.
    #[cfg(test)]
    fn prose(&self) -> String {
        let mut out = String::new();
        for line in self.lines.iter().filter(|l| !l.text.is_empty()) {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(&line.text);
        }
        out
    }

    fn draw<D: DrawTarget<Color = Rgb565>>(
        &self,
        t: &mut D,
        x: i32,
        y: i32,
        bg: Rgb565,
    ) -> Result<(), D::Error> {
        let mut pen = y;
        for line in &self.lines {
            if !line.text.is_empty() {
                text(t, &line.text, x, pen, line.font, line.ink, bg)?;
            }
            pen += line.advance;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------
// The facts card
// ---------------------------------------------------------------------------------------

/// One caption/value row of the facts card.
struct Fact {
    caption: &'static str,
    value: String,
    ink: Rgb565,
}

const CARD_PAD: i32 = 12;

/// The facts card, laid out: the caption column's width, each row's height, and the
/// rectangle the whole thing occupies.
///
/// The caption column takes the widest caption it actually has, so the card reflows for a
/// panel this file has never seen and for a fact list that grows. Values WRAP into what is
/// left rather than crop, because every one of them - the policy, the derivation, this
/// device's own fingerprint - is a value the user is being asked to check.
struct FactsCard {
    rect: Rect,
    caption_w: i32,
    rows: Vec<(Fact, i32)>,
}

fn facts_card(at: Rect, facts: Vec<Fact>) -> FactsCard {
    let inner_w = at.w - 2 * CARD_PAD;
    let caption_w = facts.iter().map(|f| BODY.text_width(f.caption) as i32).max().unwrap_or(0);
    let value_w = (inner_w - caption_w - CARD_PAD).max(1);
    let mut rows = Vec::new();
    let mut h = 2 * CARD_PAD;
    for fact in facts {
        let mut col = Column::new(value_w);
        col.mono(&fact.value, fact.ink);
        let row_h = col.height().max(SMALL_LINE);
        rows.push((fact, row_h));
        h += row_h;
    }
    FactsCard { rect: Rect::new(at.x, at.y, at.w, h), caption_w, rows }
}

impl FactsCard {
    /// Where the value column starts, and how wide it is.
    fn value_column(&self) -> Rect {
        let inner = self.rect.inset(CARD_PAD);
        let x = inner.x + self.caption_w + CARD_PAD;
        Rect::new(x, inner.y, (inner.right() - x).max(1), inner.h)
    }

    fn draw<D: DrawTarget<Color = Rgb565>>(&self, t: &mut D) -> Result<(), D::Error> {
        fill(t, self.rect, PAPER_2)?;
        frame(t, self.rect, BORDER_STRONG)?;
        let inner = self.rect.inset(CARD_PAD);
        let value = self.value_column();
        let mut y = inner.y;
        for (fact, h) in &self.rows {
            text(t, fact.caption, inner.x, y, BODY, INK_SECONDARY, PAPER_2)?;
            let mut col = Column::new(value.w);
            col.mono(&fact.value, fact.ink);
            col.draw(t, value.x, y, PAPER_2)?;
            y += h;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------------------

/// One list row: a heading line, a mono line under it, and its own padding.
///
/// Sized from the two lines it holds rather than from [`LIST_ROW_MIN`], which is a TOUCH
/// floor and says nothing about whether the text fits. A row at the floor clips the
/// descenders off its second line, and on this screen that is the line carrying the
/// fingerprint.
const ROW_H: i32 = LINE + SMALL_LINE + 2 * ROW_PAD;
const ROW_PAD: i32 = 12;
const ROW_GAP: i32 = 6;

const _: () = assert!(ROW_H >= LIST_ROW_MIN);

/// How tall `n` stacked rows are: `n` rows and the `n - 1` gaps between them, and no gap
/// after the last. Every measurement of list content goes through here so the viewport and
/// the scroll extent cannot disagree about where the content ends.
fn row_extent(n: i32) -> i32 {
    (n * (ROW_H + ROW_GAP) - ROW_GAP).max(0)
}

/// The tallest viewport that is a whole number of rows.
///
/// A viewport ending inside a row paints a sliver of it - `draw` clips, so any overlap
/// leaves ink - that `regions` will not offer, because a row taps only when it fits
/// entirely. A control the user can see and cannot use is the defect this arithmetic exists
/// to make impossible.
fn whole_rows(room: i32) -> i32 {
    row_extent((room + ROW_GAP) / (ROW_H + ROW_GAP))
}

fn row_rect(viewport: &Rect, i: usize, scroll: i32) -> Rect {
    Rect::new(viewport.x, viewport.y + i as i32 * (ROW_H + ROW_GAP) - scroll, viewport.w, ROW_H)
}

/// A row's two halves: a value on the right that keeps its full width, and a left value
/// clipped to what is left. The right half is what a reader compares.
fn row_pair<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    row: Rect,
    left: (&str, &'static Atlas, Rgb565),
    right: (&str, &'static Atlas, Rgb565),
    bg: Rgb565,
    gap: i32,
) -> Result<(), D::Error> {
    let rw = right.1.text_width(right.0) as i32;
    text(t, right.0, row.right() - rw, row.y, right.1, right.2, bg)?;
    let room = Rect::new(row.x, row.y, (row.w - rw - gap).max(0), row.h);
    let mut clip = t.clipped(&room.to_eg());
    text(&mut clip, left.0, room.x, room.y, left.1, left.2, bg)?;
    Ok(())
}

/// One registry row. Two lines: what the wallet is called and what its policy is, then the
/// values a user compares against another device.
fn registry_row<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    r: Rect,
    info: &RegistrationInfo,
    gap: i32,
) -> Result<(), D::Error> {
    let bg = if info.proven { PAPER_2 } else { DANGER_TINT };
    fill(t, r, bg)?;
    frame(t, r, if info.proven { BORDER_STRONG } else { DANGER })?;
    let inner = r.inset(ROW_PAD);
    let mut clip = t.clipped(&inner.to_eg());

    let (name, _) = printable(&info.name, MAX_NAME_CHARS);
    let policy = format!("{} of {}  {}", info.threshold, info.cosigners, compared(&info.script));
    row_pair(
        &mut clip,
        Rect::new(inner.x, inner.y, inner.w, LINE),
        (&name, HEADING, if info.proven { INK_PRIMARY } else { DANGER }),
        (&policy, HEADING, INK_SECONDARY),
        bg,
        gap,
    )?;

    let second = Rect::new(inner.x, inner.y + LINE, inner.w, SMALL_LINE);
    if info.proven {
        let ours = format!("this device: {}", compared(&info.fingerprint));
        row_pair(
            &mut clip,
            second,
            (&compared(&info.derivation), MONO_SMALL, INK_SECONDARY),
            (&ours, MONO_SMALL, INK_SECONDARY),
            bg,
            gap,
        )?;
    } else {
        // No fingerprint, no derivation and no policy this device could prove. Saying what
        // the row IS beats printing fields nothing verified.
        text(
            &mut clip,
            "unreadable - open to erase this slot and import again",
            second.x,
            second.y,
            MONO_SMALL,
            DANGER,
            bg,
        )?;
    }
    Ok(())
}

/// What kind of file a picker row is, in a word. The atlas has no icons and this device
/// labels its controls with words.
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

/// A byte count in a form a person reads. No decimal places: this is a size beside a file
/// name, not a measurement anybody acts on.
fn size_of(bytes: u32) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{} KB", bytes / 1024)
    } else {
        format!("{} MB", bytes / (1024 * 1024))
    }
}

/// One picker row. The name is MONO, so a lookalike character in a name somebody else wrote
/// is visible rather than plausible.
fn file_row<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    r: Rect,
    row: &FileRow,
    gap: i32,
) -> Result<(), D::Error> {
    let bg = if row.oversize { PAPER_0 } else { PAPER_2 };
    fill(t, r, bg)?;
    frame(t, r, if row.oversize { BORDER } else { BORDER_STRONG })?;
    let inner = r.inset(ROW_PAD);
    let mut clip = t.clipped(&inner.to_eg());
    let ink = if row.oversize { INK_MUTED } else { INK_PRIMARY };
    let (name, _) = printable(&row.name, 128);
    row_pair(
        &mut clip,
        Rect::new(inner.x, inner.y, inner.w, LINE),
        (&name, MONO_SMALL, ink),
        (kind_badge(row.kind), HEADING, INK_SECONDARY),
        bg,
        gap,
    )?;
    let second = Rect::new(inner.x, inner.y + LINE, inner.w, SMALL_LINE);
    if row.oversize {
        text(
            &mut clip,
            "too large for this device to read",
            second.x,
            second.y,
            MONO_SMALL,
            WARNING,
            bg,
        )?;
    } else {
        let (modified, _) = printable(&row.modified, 32);
        let left = if row.kind == FileKind::Directory {
            String::from("folder")
        } else {
            size_of(row.len)
        };
        row_pair(
            &mut clip,
            second,
            (&left, MONO_SMALL, INK_SECONDARY),
            (&modified, MONO_SMALL, INK_SECONDARY),
            bg,
            gap,
        )?;
    }
    Ok(())
}

/// C6's edge markers over a scrolled viewport.
///
/// A page that silently has more below is a page the user believes they have read, and on
/// these screens what is below the fold is a cosigner key or a receive address - the values
/// the whole flow exists to have compared. Both ends are drawn from one call so a screen
/// cannot state one and forget the other, and the marker itself is the review flow's, so a
/// scroll affordance does not look like a different mechanism from one screen to the next.
fn edges<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    viewport: Rect,
    scroll: i32,
    limit: i32,
) -> Result<(), D::Error> {
    if scroll > 0 {
        marker(t, "more above", viewport, true)?;
    }
    if scroll < limit {
        marker(t, "more below", viewport, false)?;
    }
    Ok(())
}

/// The C3 Busy frame every screen in this module shows while a request is in flight.
///
/// No Back and nothing tappable, which is exactly what [`ScreenId::Working`] says. The
/// heading names the operation, because the id deliberately does not.
fn draw_busy<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    m: &Metrics,
    what: &str,
) -> Result<(), D::Error> {
    draw_bar_no_back(t, m, what)?;
    let body = m.body();
    let mut col = Column::new(body.w);
    col.heading(what, INK_PRIMARY);
    col.body("The device is working. Do not remove the card.", INK_SECONDARY);
    col.draw(t, body.x, body.y, PAPER_1)
}

// ---------------------------------------------------------------------------------------
// S-41 The registry
// ---------------------------------------------------------------------------------------

/// What the registry screen is doing right now.
///
/// One enum rather than a set of flags: the three are mutually exclusive by construction,
/// and `regions` returns exactly the controls the current one has. A screen carrying "busy"
/// as a bool beside a listing could offer a row while a request was in flight, which is the
/// frozen-panel defect one step before it happens.
enum ListMode {
    /// The registry itself, plus the sentence the card left behind if it went wrong.
    ///
    /// `Some` is always about the CARD, which is why it also decides whether "Check again"
    /// is offered: there is exactly one remedy for an empty slot, and it is worth nothing
    /// if the user has to navigate away to reach it.
    Registry(Option<String>),
    /// C3. A request is in flight; the string is the heading that names it.
    Busy(&'static str),
    /// The card's files, so the user can choose which one to import.
    Pick(Picking),
}

/// The listing being chosen from.
struct Picking {
    listing: CardListing,
    /// Rows dropped because the listing was longer than a `u8` row handle can address.
    /// Stated on screen: a file the user can see on the card must never silently not be on
    /// the list.
    hidden: usize,
}

pub(crate) struct MultisigListState {
    /// The open wallet's name, for the bar.
    wallet: String,
    /// Which stored wallet this registry belongs to.
    ///
    /// The SLOT rather than the claimed count, so the count is read out of the wallet row
    /// on every frame instead of being cached here. A cached one goes stale the moment the
    /// user erases a slot, and a stale claim renders as a DANGER card about registrations
    /// that are gone - which is a device shouting about a fault it invented.
    slot: u8,
    mode: ListMode,
    scroll: i32,
}

impl MultisigListState {
    pub(crate) fn new(wallet: &WalletInfo) -> MultisigListState {
        MultisigListState {
            wallet: wallet.name.clone(),
            slot: wallet.slot,
            mode: ListMode::Registry(None),
            scroll: 0,
        }
    }

    /// [`ScreenId::Working`] while a request is in flight, and the registry otherwise.
    ///
    /// A C3 frame is a different screen to an embedder and to anything logging where the
    /// panel is: nothing is tappable, there is no Back, and the panel will not move until an
    /// answer lands.
    pub(crate) fn id(&self) -> ScreenId {
        match self.mode {
            ListMode::Busy(_) => ScreenId::Working,
            _ => ScreenId::MultisigList,
        }
    }

    /// How many registrations the WALLET RECORD says this wallet has.
    ///
    /// Zero where the row cannot be found, which is the honest answer: with nothing to
    /// compare against, this screen has no claim to check and says nothing about one.
    ///
    /// The embedder re-installs the wallet rows and the registry together after anything
    /// that changes either, exactly as it does after an unlock - see `Ui::set_wallets` and
    /// `Ui::set_registrations`.
    fn claimed(&self, ctx: &Ctx) -> usize {
        ctx.wallets
            .iter()
            .find_map(|row| match row {
                WalletRow::Wallet(info) if info.slot == self.slot => {
                    Some(usize::from(info.registrations))
                }
                _ => None,
            })
            .unwrap_or(0)
    }

    /// Registrations the wallet record claims that the embedder could not prove.
    fn unreadable(&self, ctx: &Ctx) -> usize {
        self.claimed(ctx).saturating_sub(ctx.registrations.len())
    }

    fn enter_mode(&mut self, mode: ListMode) {
        self.mode = mode;
        self.scroll = 0;
    }

    /// Ask for the card's files, from the root.
    fn read_card(&mut self) -> Outcome {
        self.enter_mode(ListMode::Busy("Reading card"));
        Outcome::ask(UiRequest::ListCard { dir: String::new(), filter: FileFilter::All })
    }

    /// The rows the picker is offering, in listing order.
    fn pick_rows<'a>(&self, p: &'a Picking) -> &'a [FileRow] {
        &p.listing.rows[..p.listing.rows.len().min(MAX_PICK_ROWS)]
    }

    /// Leave the busy frame before handing the panel to another screen.
    ///
    /// The screen a `Nav::Push` remembers is this one AS IT IS, and a C3 frame has no way
    /// out by construction - so a push taken straight out of `Busy` would leave a frozen
    /// screen on the back stack for Back to restore.
    fn park(&mut self) {
        self.enter_mode(ListMode::Registry(None));
    }
}

const EMPTY_HEAD: &str = "No multisig registrations.";
const EMPTY_BODY: &str = "Import a descriptor or a Coldcard multisig file from the card. A \
                          registration is what lets this device tell change from a payment in \
                          a multisig transaction, so nothing multisig works without one.";

pub(crate) struct ListLayout {
    /// The DANGER card above the list when the wallet claims registrations this device could
    /// not read. Absent when the two agree.
    fault: Option<(Rect, Column)>,
    /// The picker's heading and its notes about what the listing left out.
    pick_head: Option<(Rect, Column)>,
    viewport: Rect,
    /// The empty-state well, when there is nothing to list.
    empty: Option<(Rect, Column)>,
    band: Option<(Rect, Column)>,
    /// The registry's "N proven on this wallet" line. Absent in the picker, whose count
    /// belongs in its heading - on the 800x480 panel those 36 pixels are the difference
    /// between a list that shows one file and a list that shows two.
    capacity: Option<Rect>,
    /// The primary action: Import on the registry, Cancel in the picker.
    action: Rect,
    /// "Check again", beside the action whenever the card is in play.
    refresh: Option<Rect>,
    /// The session affordance, on the bar. Offered only while a session is open, like the
    /// wallet list's and the wallet home's - it is the same control in the same place.
    lock_chip: Option<Rect>,
}

impl Screen for MultisigListState {
    type Layout = ListLayout;

    fn layout(&self, ctx: &Ctx) -> ListLayout {
        let m = &ctx.m;
        let body = m.body();
        let g = m.gap;

        let action_y = body.bottom() - m.btn;
        let picking = matches!(self.mode, ListMode::Pick(_));
        let capacity = (!picking)
            .then(|| Rect::new(body.x, action_y - g - SMALL_LINE, body.w, SMALL_LINE));

        // Two buttons whenever the card is in play, so "insert it and try again" - the whole
        // remedy for an empty slot - is one tap away instead of a navigation the user will
        // power-cycle instead of finding.
        let card_in_play = matches!(self.mode, ListMode::Pick(_))
            || matches!(self.mode, ListMode::Registry(Some(_)));
        let (action, refresh) = if card_in_play {
            let half = (body.w - g) / 2;
            (
                Rect::new(body.right() - half, action_y, half, m.btn),
                Some(Rect::new(body.x, action_y, half, m.btn)),
            )
        } else {
            (Rect::new(body.x, action_y, body.w, m.btn), None)
        };

        let mut top = body.y;
        let mut fault = None;
        let claims = self.claimed(ctx);
        let missing = self.unreadable(ctx);
        if missing > 0 {
            let mut col = Column::new(body.w - 2 * CARD_PAD);
            col.heading("Registrations this device cannot read", DANGER);
            col.body(
                &format!(
                    "This wallet's record claims {claims} registration{}, and {missing} of \
                     them did not prove out against its seed. Open the row and erase the \
                     slot, then import it again - until you do, a transaction from that \
                     wallet is refused.",
                    if claims == 1 { "" } else { "s" }
                ),
                INK_PRIMARY,
            );
            let h = col.height() + 2 * CARD_PAD;
            fault = Some((Rect::new(body.x, top, body.w, h), col));
            top += h + g;
        }

        let mut pick_head = None;
        if let ListMode::Pick(p) = &self.mode {
            let mut col = Column::new(body.w);
            let n = self.pick_rows(p).len();
            col.heading(
                &format!("Choose a file - {n} on the card"),
                INK_PRIMARY,
            );
            // A second line only when there is something exceptional to say. It costs a row
            // of the list on the short panel, so it is spent on a claim about the card that
            // the user could not otherwise make - never on restating the heading.
            let (dir, _) = printable(&p.listing.dir, 64);
            let mut notes = Vec::new();
            if !dir.is_empty() {
                notes.push(format!("in {dir}"));
            }
            if p.listing.truncated {
                notes.push(String::from("the card holds more files than this list shows"));
            }
            if p.listing.rejected > 0 {
                notes.push(format!(
                    "{} name{} could not be read and are not shown",
                    p.listing.rejected,
                    if p.listing.rejected == 1 { "" } else { "s" }
                ));
            }
            if p.hidden > 0 {
                notes.push(format!("{} more are past this screen's limit", p.hidden));
            }
            if !notes.is_empty() {
                col.body(&format!("{}.", notes.join("; ")), INK_SECONDARY);
            }
            let h = col.height();
            pick_head = Some((Rect::new(body.x, top, body.w, h), col));
            top += h + g;
        }

        let mut band = None;
        let mut floor = capacity.map_or(action_y, |c| c.y) - g;
        if let ListMode::Registry(Some(s)) = &self.mode {
            let mut col = Column::new(body.w);
            let (line, _) = printable(s, 300);
            col.body(&line, WARNING);
            let h = col.height();
            floor -= h + g;
            band = Some((Rect::new(body.x, floor + g, body.w, h), col));
        }

        let viewport = Rect::new(body.x, top, body.w, whole_rows((floor - top).max(0)));

        // Not while `fault` is up: "no multisig registrations" is precisely the wrong
        // conclusion for a wallet that HAS them and could not prove them, and it is the one
        // that sends the user away instead of to the row they have to erase.
        let empty = if matches!(self.mode, ListMode::Registry(_))
            && ctx.registrations.is_empty()
            && missing == 0
        {
            let mut col = Column::new(viewport.w - 2 * CARD_PAD);
            col.heading(EMPTY_HEAD, INK_PRIMARY);
            col.body(EMPTY_BODY, INK_SECONDARY);
            let h = col.height() + 2 * CARD_PAD;
            Some((Rect::new(viewport.x, viewport.y, viewport.w, h), col))
        } else {
            None
        };

        let lock_chip = (ctx.lock.status == StoreStatus::Unlocked).then(|| chip(m));

        ListLayout {
            fault,
            pick_head,
            viewport,
            empty,
            band,
            capacity,
            action,
            refresh,
            lock_chip,
        }
    }

    fn regions(&self, ctx: &Ctx, out: &mut Vec<Region>) {
        let l = self.layout(ctx);
        match &self.mode {
            // C3: nothing tappable, no Back. The panel does not move until an answer lands,
            // and the frame says so.
            ListMode::Busy(_) => {}
            ListMode::Registry(_) => {
                out.push(Region { id: RegionId::Back, rect: back_rect(&ctx.m) });
                if let Some(r) = l.lock_chip {
                    out.push(Region { id: RegionId::Lock, rect: r });
                }
                // Rows ride the scrolled content: a row only partly in the viewport draws
                // and does not tap, which is the honest reading of half a row, and is only
                // safe because the viewport is a whole number of rows and the extent is an
                // exact multiple of the pitch - at rest the list shows complete rows only.
                for (i, r) in ctx.registrations.iter().enumerate() {
                    let rect = row_rect(&l.viewport, i, self.scroll);
                    if rect.y >= l.viewport.y && rect.bottom() <= l.viewport.bottom() {
                        out.push(Region { id: RegionId::ListRow(r.slot), rect });
                    }
                }
                if let Some(r) = l.refresh {
                    out.push(Region { id: RegionId::FileRefresh, rect: r });
                }
                out.push(Region { id: RegionId::MsImport, rect: l.action });
            }
            ListMode::Pick(p) => {
                out.push(Region { id: RegionId::Back, rect: back_rect(&ctx.m) });
                for (i, row) in self.pick_rows(p).iter().enumerate() {
                    // An oversize row is drawn and not offered: the transfer cap already
                    // refused it, and a control whose only outcome is a dead end lies.
                    if row.oversize {
                        continue;
                    }
                    let rect = row_rect(&l.viewport, i, self.scroll);
                    if rect.y >= l.viewport.y && rect.bottom() <= l.viewport.bottom() {
                        out.push(Region { id: RegionId::ListRow(i as u8), rect });
                    }
                }
                if let Some(r) = l.refresh {
                    out.push(Region { id: RegionId::FileRefresh, rect: r });
                }
                out.push(Region { id: RegionId::MsReject, rect: l.action });
            }
        }
    }

    fn draw<D: DrawTarget<Color = Rgb565>>(&self, t: &mut D, ctx: &Ctx) -> Result<(), D::Error> {
        let m = &ctx.m;
        if let ListMode::Busy(what) = self.mode {
            return draw_busy(t, m, what);
        }
        let l = self.layout(ctx);
        draw_bar(t, m, &self.title(m, l.lock_chip))?;
        if let Some(r) = l.lock_chip {
            button(t, r, "Lock device", ButtonKind::Secondary, PAPER_2)?;
        }

        if let Some((rect, col)) = &l.fault {
            fill(t, *rect, DANGER_TINT)?;
            frame(t, *rect, DANGER)?;
            col.draw(t, rect.x + CARD_PAD, rect.y + CARD_PAD, DANGER_TINT)?;
        }
        if let Some((rect, col)) = &l.pick_head {
            col.draw(t, rect.x, rect.y, PAPER_1)?;
        }

        match &self.mode {
            ListMode::Pick(p) => {
                let rows = self.pick_rows(p);
                let mut clip = t.clipped(&l.viewport.to_eg());
                for (i, row) in rows.iter().enumerate() {
                    file_row(&mut clip, row_rect(&l.viewport, i, self.scroll), row, m.gap)?;
                }
                if rows.is_empty() {
                    let mut col = Column::new(l.viewport.w);
                    col.heading("This card holds no files.", INK_PRIMARY);
                    col.body(
                        "Copy the descriptor or the Coldcard multisig file onto the card and \
                         check again.",
                        INK_SECONDARY,
                    );
                    col.draw(&mut clip, l.viewport.x, l.viewport.y, PAPER_1)?;
                }
            }
            _ => match &l.empty {
                Some((rect, col)) => {
                    let mut clip = t.clipped(&l.viewport.to_eg());
                    fill(&mut clip, *rect, PAPER_0)?;
                    frame(&mut clip, *rect, BORDER)?;
                    col.draw(&mut clip, rect.x + CARD_PAD, rect.y + CARD_PAD, PAPER_0)?;
                }
                None => {
                    let mut clip = t.clipped(&l.viewport.to_eg());
                    for (i, r) in ctx.registrations.iter().enumerate() {
                        registry_row(&mut clip, row_rect(&l.viewport, i, self.scroll), r, m.gap)?;
                    }
                }
            },
        }

        edges(t, l.viewport, self.scroll, self.limit(&l, ctx))?;

        if let Some((rect, col)) = &l.band {
            col.draw(t, rect.x, rect.y, PAPER_1)?;
        }

        if let Some(c) = l.capacity {
            let held = ctx.registrations.len();
            text(
                t,
                &format!(
                    "{held} registration{} proven on this wallet",
                    if held == 1 { "" } else { "s" }
                ),
                c.x,
                c.y,
                MONO_SMALL,
                INK_SECONDARY,
                PAPER_1,
            )?;
        }
        match &self.mode {
            ListMode::Pick(_) => button(t, l.action, "Cancel", ButtonKind::Secondary, PAPER_1)?,
            _ => button(t, l.action, "Import from card", ButtonKind::Primary, PAPER_1)?,
        }
        if let Some(r) = l.refresh {
            button(t, r, "Check again", ButtonKind::Secondary, PAPER_1)?;
        }
        Ok(())
    }

    fn activate(&mut self, id: RegionId, _env: &mut Env) -> Outcome {
        match (&self.mode, id) {
            (ListMode::Registry(_), RegionId::MsImport | RegionId::FileRefresh) => self.read_card(),
            (ListMode::Registry(_), RegionId::Lock) => Outcome::ask(UiRequest::LockSession),
            // The slot travels in the region id, which is why `activate` can name it without
            // reading the list back - and why `Env` does not carry the registry. The detail
            // screen reads the row itself, so it is also the one place that decides what an
            // unproven slot may do.
            (ListMode::Registry(_), RegionId::ListRow(slot)) => {
                Outcome::push(State::MultisigDetail(MultisigDetailState::stored(slot)))
            }
            (ListMode::Pick(_), RegionId::FileRefresh) => self.read_card(),
            (ListMode::Pick(_), RegionId::MsReject) => {
                self.enter_mode(ListMode::Registry(None));
                Outcome::stay()
            }
            (ListMode::Pick(p), RegionId::ListRow(i)) => {
                let Some(row) = self.pick_rows(p).get(usize::from(i)) else {
                    return Outcome::stay();
                };
                let (dir, name) = (p.listing.dir.clone(), row.name.clone());
                if row.kind == FileKind::Directory {
                    // One level below the root, which is the depth the picker permits.
                    self.enter_mode(ListMode::Busy("Reading card"));
                    Outcome::ask(UiRequest::ListCard { dir: name, filter: FileFilter::All })
                } else {
                    // Read AND decide in one request: the user does nothing between the two,
                    // and both halves fail into the same refusal.
                    self.enter_mode(ListMode::Busy("Reading registration"));
                    Outcome::ask(UiRequest::ImportRegistration { dir, name })
                }
            }
            _ => Outcome::stay(),
        }
    }

    fn answered(&mut self, answer: Answer, _env: &mut Env) -> Outcome {
        match answer {
            Answer::Card(CardOutcome::Listed(listing)) => {
                let hidden = listing.rows.len().saturating_sub(MAX_PICK_ROWS);
                self.enter_mode(ListMode::Pick(Picking { listing, hidden }));
                Outcome::stay()
            }
            Answer::Card(CardOutcome::NoCard) => {
                self.enter_mode(ListMode::Registry(Some(String::from(
                    "No card detected. Insert a FAT32-formatted card and check again.",
                ))));
                Outcome::stay()
            }
            Answer::Card(CardOutcome::Unreadable(why)) => {
                let (why, _) = printable(&why, 300);
                self.enter_mode(ListMode::Registry(Some(why)));
                Outcome::stay()
            }
            // Pushed rather than entered, so Back from the review - and from the refusal -
            // is the registry the user started in, which is what S-42 specifies.
            Answer::Import(ImportOutcome::Pending(review)) => {
                self.park();
                Outcome::push(State::MultisigImport(MultisigImportState::new(review)))
            }
            Answer::Import(ImportOutcome::Refused(notice)) => {
                self.park();
                Outcome::push(State::Refusal(RefusalState::new(notice)))
            }
            // Every other answer belongs to a request this screen did not raise: a late
            // answer belongs to a tap the user has moved on from.
            _ => Outcome::stay(),
        }
    }

    fn scroll_mut(&mut self) -> Option<&mut i32> {
        if matches!(self.mode, ListMode::Busy(_)) {
            return None;
        }
        Some(&mut self.scroll)
    }

    fn scroll_limit(&self, ctx: &Ctx) -> i32 {
        self.limit(&self.layout(ctx), ctx)
    }
}

impl MultisigListState {
    /// The scroll bound for a layout already in hand.
    ///
    /// Taken as a parameter rather than recomputed, because `draw` needs both and this
    /// screen's layout measures every column it holds: asking twice would wrap the same
    /// prose twice on every repaint, and this device repaints in full.
    fn limit(&self, l: &ListLayout, ctx: &Ctx) -> i32 {
        let content = match &self.mode {
            ListMode::Pick(p) => row_extent(self.pick_rows(p).len() as i32),
            ListMode::Registry(_) if l.empty.is_some() => 0,
            ListMode::Registry(_) => row_extent(ctx.registrations.len() as i32),
            ListMode::Busy(_) => 0,
        };
        (content - l.viewport.h).max(0)
    }
}

impl MultisigListState {
    /// The bar title, trimmed to the room the bar actually has.
    ///
    /// The bar draws its title as one unclipped run, and the wallet name in it is the user's
    /// own label - which on a restored wallet came off another machine. The chip beside it
    /// is part of the measurement: a title that ran under it would paint over the one
    /// control that ends a session.
    fn title(&self, m: &Metrics, chip: Option<Rect>) -> String {
        let (name, _) = printable(&self.wallet, MAX_NAME_CHARS);
        let right = chip.map_or(m.w, |c| c.x);
        clamp_to_width(&format!("Multisig - {name}"), right - back_rect(m).right() - 2 * m.gap, HEADING)
    }
}

// ---------------------------------------------------------------------------------------
// S-42 The import review
// ---------------------------------------------------------------------------------------

/// Why this registration cannot be approved, whatever the user does.
///
/// Computed once at construction from the review alone and consulted by `regions`, so
/// [`RegionId::MsApprove`] is not merely hidden - it cannot be produced. Each variant is a
/// claim the engine already refuses; the screen refuses it again because the screen is what
/// draws the button, and a renderer that trusts every field it is handed is one mistake in
/// the embedder away from offering consent to a wallet nobody proved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Blocked {
    /// The set does not identify this device: `ours` is out of range, or the cosigner it
    /// points at does not claim to be ours, or more than one row does. This is the most
    /// important refusal on the screen - importing a wallet you cannot sign for is how a
    /// substituted key gets accepted (R-04).
    NotAMember,
    /// A quorum that cannot exist: no cosigners, more than [`MAX_COSIGNERS`], a threshold of
    /// zero, or a threshold larger than the set.
    ImpossiblePolicy,
    /// A descriptor longer than any wallet this device can hold. Refused before it is
    /// wrapped, measured or drawn.
    DescriptorTooLong,
}

impl Blocked {
    fn headline(self) -> &'static str {
        match self {
            Blocked::NotAMember => "This device is not one of the cosigners",
            Blocked::ImpossiblePolicy => "This is not a policy this device can hold",
            Blocked::DescriptorTooLong => "This descriptor is too long to be a wallet",
        }
    }

    fn matters(self) -> &'static str {
        match self {
            Blocked::NotAMember => {
                "Importing a wallet you cannot sign for is how a substituted key gets \
                 accepted. This device could not find its own key in the set, so it cannot \
                 tell you which of these cosigners is you - and it would have no way to tell \
                 change from a payment for this wallet."
            }
            Blocked::ImpossiblePolicy => {
                "A quorum that cannot exist was not written by a wallet, or was altered on \
                 the way here. Storing it would give every later transaction a rule with \
                 nothing behind it."
            }
            Blocked::DescriptorTooLong => {
                "The largest wallet this device holds is 15 cosigners. Anything longer did \
                 not come from a wallet it can be a member of, and it is refused before it \
                 is read any further."
            }
        }
    }

    fn todo(self) -> &'static str {
        match self {
            Blocked::NotAMember => {
                "Check you opened the right wallet, then export this device's xpub to your \
                 coordinator and build the wallet again."
            }
            Blocked::ImpossiblePolicy | Blocked::DescriptorTooLong => {
                "Re-export the wallet from your coordinator and import it again."
            }
        }
    }
}

/// Everything about a review that decides whether it may be stored.
///
/// Separated from the rendering so the security decision is one readable function with one
/// caller, testable without a panel: given a review, may this be approved?
fn blocked_by(review: &RegistrationReview) -> Option<Blocked> {
    let n = review.cosigners.len();
    if n == 0 || n > MAX_COSIGNERS {
        return Some(Blocked::ImpossiblePolicy);
    }
    if review.threshold == 0 || usize::from(review.threshold) > n {
        return Some(Blocked::ImpossiblePolicy);
    }
    if review.descriptor.chars().count() > MAX_DESCRIPTOR_CHARS {
        return Some(Blocked::DescriptorTooLong);
    }
    // Three ways the membership claim can be inconsistent, and all three are the same
    // attack: `ours` is a POSITION, `CosignerRow::ours` is a FLAG, and a file that moves one
    // without the other is asking this device to point at somebody else's key and call it
    // its own.
    let claimed = review.cosigners.iter().filter(|c| c.ours).count();
    let position = usize::from(review.ours);
    if claimed != 1 || position == 0 || position > n || !review.cosigners[position - 1].ours {
        return Some(Blocked::NotAMember);
    }
    None
}

enum ImportMode {
    Review,
    Busy(&'static str),
}

pub(crate) struct MultisigImportState {
    review: RegistrationReview,
    blocked: Option<Blocked>,
    page: usize,
    /// Which pages have been on the panel. C5's enforced traversal, held as a SET rather
    /// than as a high-water index: paging back and forth is fine, skipping is not.
    visited: Vec<bool>,
    scroll: i32,
    /// The C4a "already stored - replace it?" sheet.
    danger: Option<Danger>,
    mode: ImportMode,
}

impl MultisigImportState {
    pub(crate) fn new(review: RegistrationReview) -> MultisigImportState {
        let blocked = blocked_by(&review);
        let pages = MultisigImportState::pages_for(&review);
        let mut visited = alloc::vec![false; pages];
        visited[0] = true;
        MultisigImportState {
            review,
            blocked,
            page: 0,
            visited,
            scroll: 0,
            danger: None,
            mode: ImportMode::Review,
        }
    }

    pub(crate) fn id(&self) -> ScreenId {
        match self.mode {
            ImportMode::Busy(_) => ScreenId::Working,
            _ => ScreenId::MultisigImport,
        }
    }

    /// The overview, one page per cosigner, and the address page that carries the write.
    ///
    /// The ONE definition of the count: the `[ i / n ]` counter, the visited set and the
    /// Next target all read it, so they cannot disagree by one.
    fn pages_for(review: &RegistrationReview) -> usize {
        2 + review.cosigners.len()
    }

    fn pages(&self) -> usize {
        MultisigImportState::pages_for(&self.review)
    }

    fn last(&self) -> usize {
        self.pages() - 1
    }

    fn unseen(&self) -> usize {
        self.visited.iter().filter(|v| !**v).count()
    }

    /// Approval is live only on the last page, only after every page has been seen, and only
    /// while nothing blocks it.
    fn may_approve(&self) -> bool {
        self.blocked.is_none() && self.page == self.last() && self.unseen() == 0
    }

    fn go(&mut self, page: usize) {
        self.page = page.min(self.last());
        self.visited[self.page] = true;
        self.scroll = 0;
    }

    /// The C4a sheet for a registration that is already stored.
    fn replace_sheet(&self) -> Danger {
        let (name, _) = printable(&self.review.name, MAX_NAME_CHARS);
        Danger::confirm(
            "This registration is already stored",
            &[
                "Replacing it stores this descriptor in place of the one on the device.",
                "If the two differ, the addresses this wallet verifies change with them. \
                 Compare the first receive address on your other signers afterwards.",
            ],
            &format!("Replace \"{name}\""),
        )
    }

    /// What the C12 notice says, and what it promises about confidentiality.
    ///
    /// The name is capped SHORTER here than anywhere else on the screen. The notice is
    /// pinned outside the scroll, so every line it grows is a line the page it announces
    /// loses - and on the 800x480 panel that page is the one carrying the first receive
    /// address. The full name is on the facts card one page turn away; what this line has
    /// to carry is enough to identify the artifact, which is the name, the quorum and the
    /// checksum.
    fn notice_copy(&self) -> (String, &'static str) {
        let (name, _) = printable(&self.review.name, NOTICE_NAME_CHARS);
        let checksum = descriptor_checksum(&self.review.descriptor)
            .map(compared)
            .unwrap_or_else(|| String::from("none"));
        (
            format!(
                "Writes: registration \"{name}\", {} of {}, checksum {checksum}.",
                self.review.threshold,
                self.review.cosigners.len()
            ),
            "Public keys only - no private key, no seed.",
        )
    }

    /// The membership statement: the one block on this screen that says what was PROVEN.
    fn membership(&self, width: i32) -> Column {
        let mut col = Column::new(width - 2 * CARD_PAD);
        match self.blocked {
            Some(reason) => {
                col.heading(reason.headline(), DANGER);
                col.body(reason.matters(), INK_PRIMARY);
            }
            None => {
                let ours = &self.review.cosigners[usize::from(self.review.ours) - 1];
                col.heading(
                    &format!(
                        "This device is cosigner {} of {} ({}).",
                        self.review.ours,
                        self.review.cosigners.len(),
                        compared(&ours.fingerprint)
                    ),
                    SUCCESS,
                );
                col.body(
                    "Checked: the key at this path on this device really is in the set. The \
                     other keys are the file's word - compare the first receive address on \
                     your other signers before you use this wallet.",
                    INK_PRIMARY,
                );
            }
        }
        col
    }
}

/// A page's content, already measured: an optional facts card, an optional bordered
/// STATEMENT card (page 1's membership verdict, which has to read as a verdict and not as
/// prose), and the prose under them.
struct PageBody {
    card: Option<FactsCard>,
    note: Option<(Rect, Column)>,
    col: Column,
    col_y: i32,
    height: i32,
}

pub(crate) struct ImportLayout {
    pager: Rect,
    viewport: Rect,
    body: PageBody,
    notice: Option<Rect>,
    /// Why the approve button is disabled, drawn as a measured line rather than as a label:
    /// a sentence that long inside a half-width button crops on the short panel, and this
    /// one has to be read.
    reason: Option<(Rect, Column)>,
    prev: Rect,
    next: Rect,
    reject_chip: Rect,
}

impl MultisigImportState {
    fn page_body(&self, at: Rect) -> PageBody {
        let g = SMALL_LINE / 2;
        if let Some(reason) = self.blocked {
            // A blocked review is not a paged review. One statement, in DANGER, with nothing
            // on the panel that looks like a step towards approving it.
            let mut col = Column::new(at.w);
            col.heading("What to do", INK_PRIMARY);
            col.body(reason.todo(), INK_SECONDARY);
            col.space(g);
            col.heading("What the file said", INK_PRIMARY);
            let (name, cut) = printable(&self.review.name, MAX_NAME_CHARS);
            col.mono(&format!("name        {name}"), INK_SECONDARY);
            col.mono(
                &format!(
                    "policy      {} of {}",
                    self.review.threshold,
                    self.review.cosigners.len()
                ),
                INK_SECONDARY,
            );
            col.mono(&format!("script      {}", compared(&self.review.script)), INK_SECONDARY);
            col.mono(
                &format!("descriptor  {} characters", self.review.descriptor.chars().count()),
                INK_SECONDARY,
            );
            if cut {
                col.body(
                    "The name was shortened to fit this screen, so it is not the name your \
                     other device shows.",
                    WARNING,
                );
            }
            let note = self.membership(at.w);
            let note_rect = Rect::new(at.x, at.y, at.w, note.height() + 2 * CARD_PAD);
            let col_y = note_rect.bottom() + g;
            let height = col_y + col.height() - at.y;
            return PageBody { card: None, note: Some((note_rect, note)), col, col_y, height };
        }

        match self.page {
            0 => {
                let (name, cut) = printable(&self.review.name, MAX_NAME_CHARS);
                let card = facts_card(
                    at,
                    alloc::vec![
                        Fact { caption: "Name", value: name, ink: INK_PRIMARY },
                        Fact {
                            caption: "Policy",
                            value: format!(
                                "{} of {}   {}",
                                self.review.threshold,
                                self.review.cosigners.len(),
                                compared(&self.review.policy)
                            ),
                            ink: INK_PRIMARY,
                        },
                        Fact {
                            caption: "Script",
                            value: compared(&self.review.script),
                            ink: INK_PRIMARY,
                        },
                        Fact {
                            caption: "Derivation",
                            value: compared(&self.review.derivation),
                            ink: INK_PRIMARY,
                        },
                        Fact {
                            caption: "Network",
                            value: self.review.network.to_string(),
                            ink: if self.review.network == notyas_core::bitcoin::Network::Bitcoin {
                                INK_PRIMARY
                            } else {
                                WARNING
                            },
                        },
                    ],
                );
                let note = self.membership(at.w);
                let note_rect =
                    Rect::new(at.x, card.rect.bottom() + g, at.w, note.height() + 2 * CARD_PAD);

                let mut col = Column::new(at.w);
                if cut {
                    col.body(
                        "This device shortened the name to fit the screen, so it will not \
                         match the name your other device shows.",
                        WARNING,
                    );
                }
                if self.review.converted {
                    col.body(
                        "Imported from a Coldcard multisig file and converted to a descriptor. \
                         The descriptor on the last page is what gets stored.",
                        INK_SECONDARY,
                    );
                }
                if self.review.duplicate {
                    col.body(
                        "A registration for this wallet is already on this device. Approving \
                         replaces it.",
                        WARNING,
                    );
                }
                col.body(
                    &format!(
                        "You will see each of the {} cosigner keys in full on the next pages.",
                        self.review.cosigners.len()
                    ),
                    INK_SECONDARY,
                );
                let col_y = note_rect.bottom() + g;
                let height = col_y + col.height() - at.y;
                PageBody { card: Some(card), note: Some((note_rect, note)), col, col_y, height }
            }
            p if p <= self.review.cosigners.len() => {
                let c = &self.review.cosigners[p - 1];
                let mut col = Column::new(at.w);
                col.heading(
                    &format!("Cosigner {} of {}", p, self.review.cosigners.len()),
                    INK_PRIMARY,
                );
                if c.ours {
                    col.heading("THIS DEVICE", SUCCESS);
                }
                col.space(g);
                col.body("Master fingerprint", INK_SECONDARY);
                col.mono(&compared(&c.fingerprint), INK_PRIMARY);
                col.space(g);
                col.body("Derivation path", INK_SECONDARY);
                col.mono(&compared(&c.path), INK_PRIMARY);
                col.space(g);
                col.body("Account xpub", INK_SECONDARY);
                col.mono(&chunked(&compared(&c.xpub), 8), INK_PRIMARY);
                col.space(g);
                col.body(
                    "Compare this key with the device that holds it. A key that is not the one \
                     you expect is a wallet somebody else can spend from.",
                    INK_SECONDARY,
                );
                let height = col.height();
                PageBody { card: None, note: None, col, col_y: at.y, height }
            }
            _ => {
                let mut col = Column::new(at.w);
                col.heading("First receive address", INK_PRIMARY);
                col.space(g);
                col.mono(&chunked(&compared(&self.review.first_address), 4), INK_PRIMARY);
                col.space(g);
                col.body(
                    "Compare this address on your other signing devices before you use this \
                     wallet. Every cosigner key goes into it, so if any one of them was \
                     substituted on the way here this address will differ - and that is the \
                     only check on this device that can catch it.",
                    INK_PRIMARY,
                );
                col.space(g);
                col.heading("Descriptor checksum", INK_PRIMARY);
                match descriptor_checksum(&self.review.descriptor) {
                    Some(sum) => col.mono(&compared(sum), INK_PRIMARY),
                    None => col.body(
                        "This descriptor carries no checksum, so there is no short value to \
                         compare between devices.",
                        WARNING,
                    ),
                }
                col.space(g);
                col.heading("Descriptor", INK_PRIMARY);
                col.mono(&compared(&self.review.descriptor), INK_SECONDARY);
                let height = col.height();
                PageBody { card: None, note: None, col, col_y: at.y, height }
            }
        }
    }
}

impl Screen for MultisigImportState {
    type Layout = ImportLayout;

    fn layout(&self, ctx: &Ctx) -> ImportLayout {
        let m = &ctx.m;
        let body = m.body();
        let g = m.gap;
        let reject_chip = chip(m);
        let row = Rect::new(body.x, body.bottom() - m.btn, body.w, m.btn);
        let half = (row.w - g) / 2;
        let (prev, next) = (
            Rect::new(row.x, row.y, half, row.h),
            Rect::new(row.right() - half, row.y, half, row.h),
        );

        let pager = Rect::new(body.x, body.y, body.w, SMALL_LINE);
        let mut floor = row.y - g;

        // The C12 notice sits OUTSIDE the scrolled content, directly above the button that
        // performs the write: an announcement the user can scroll away from is one that was
        // not made.
        let mut notice = None;
        if self.blocked.is_none() && self.page == self.last() {
            let (what, confidentiality) = self.notice_copy();
            let h = write_notice_h(body.w, &what, confidentiality);
            floor -= h + g;
            notice = Some(Rect::new(body.x, floor + g, body.w, h));
        }

        let mut reason = None;
        if self.blocked.is_none() && self.page == self.last() && self.unseen() > 0 {
            let mut col = Column::new(body.w);
            col.body(
                &format!(
                    "Review all {} pages first - {} not yet seen.",
                    self.pages(),
                    self.unseen()
                ),
                WARNING,
            );
            let h = col.height();
            floor -= h + g;
            reason = Some((Rect::new(body.x, floor + g, body.w, h), col));
        }

        let viewport =
            Rect::new(body.x, pager.bottom() + g, body.w, (floor - pager.bottom() - g).max(0));
        let body_at = Rect::new(viewport.x, viewport.y - self.scroll, viewport.w, viewport.h);
        let page = self.page_body(body_at);

        ImportLayout { pager, viewport, body: page, notice, reason, prev, next, reject_chip }
    }

    fn regions(&self, ctx: &Ctx, out: &mut Vec<Region>) {
        if let Some(d) = &self.danger {
            d.regions(&ctx.m, out);
            return;
        }
        if matches!(self.mode, ImportMode::Busy(_)) {
            return;
        }
        let l = self.layout(ctx);
        out.push(Region { id: RegionId::Back, rect: back_rect(&ctx.m) });
        // Refusing needs no traversal, so it is offered on every page.
        out.push(Region { id: RegionId::MsReject, rect: l.reject_chip });
        if self.blocked.is_some() {
            // Nothing to page through and nothing to approve. The only ways off this screen
            // are the two that change nothing.
            return;
        }
        if self.page > 0 {
            out.push(Region { id: RegionId::ReviewPrev, rect: l.prev });
        }
        if self.page < self.last() {
            out.push(Region { id: RegionId::ReviewNext, rect: l.next });
        } else if self.may_approve() {
            out.push(Region { id: RegionId::MsApprove, rect: l.next });
        }
    }

    fn draw<D: DrawTarget<Color = Rgb565>>(&self, t: &mut D, ctx: &Ctx) -> Result<(), D::Error> {
        let m = &ctx.m;
        if let Some(d) = &self.danger {
            return d.draw(t, m, ctx.press, ctx.hold_released);
        }
        if let ImportMode::Busy(what) = self.mode {
            return draw_busy(t, m, what);
        }
        draw_bar(t, m, "Import multisig")?;
        let l = self.layout(ctx);
        button(t, l.reject_chip, "Reject", ButtonKind::Secondary, PAPER_2)?;

        if self.blocked.is_none() {
            let counter = format!("[ {} / {} ]", self.page + 1, self.pages());
            let cw = MONO_SMALL.text_width(&counter) as i32;
            text(t, &counter, l.pager.right() - cw, l.pager.y, MONO_SMALL, INK_SECONDARY, PAPER_1)?;
            let seen = self.pages() - self.unseen();
            text(
                t,
                &format!("{seen} of {} pages seen", self.pages()),
                l.pager.x,
                l.pager.y,
                MONO_SMALL,
                INK_SECONDARY,
                PAPER_1,
            )?;
        }

        {
            let mut clip = t.clipped(&l.viewport.to_eg());
            if let Some(card) = &l.body.card {
                card.draw(&mut clip)?;
            }
            if let Some((rect, col)) = &l.body.note {
                let (bg, border) = match self.blocked {
                    Some(_) => (DANGER_TINT, DANGER),
                    None => (ACCENT_TINT, ACCENT),
                };
                fill(&mut clip, *rect, bg)?;
                frame(&mut clip, *rect, border)?;
                col.draw(&mut clip, rect.x + CARD_PAD, rect.y + CARD_PAD, bg)?;
            }
            l.body.col.draw(&mut clip, l.viewport.x, l.body.col_y, PAPER_1)?;
        }
        edges(t, l.viewport, self.scroll, (l.body.height - l.viewport.h).max(0))?;

        if let Some((rect, col)) = &l.reason {
            col.draw(t, rect.x, rect.y, PAPER_1)?;
        }
        if let Some(r) = l.notice {
            let (what, confidentiality) = self.notice_copy();
            write_notice(t, r, &what, confidentiality)?;
        }

        if self.blocked.is_some() {
            return Ok(());
        }
        let prev_kind = if self.page > 0 { ButtonKind::Secondary } else { ButtonKind::Disabled };
        button(t, l.prev, "< Previous", prev_kind, PAPER_1)?;
        if self.page < self.last() {
            button(t, l.next, "Next >", ButtonKind::Primary, PAPER_1)?;
        } else if self.may_approve() {
            button(t, l.next, "Approve", ButtonKind::Primary, PAPER_1)?;
        } else {
            button(t, l.next, "Approve", ButtonKind::Disabled, PAPER_1)?;
        }
        Ok(())
    }

    fn activate(&mut self, id: RegionId, _env: &mut Env) -> Outcome {
        if let Some(d) = &mut self.danger {
            return match d.activate(id) {
                DangerOutcome::Open | DangerOutcome::Alternative => Outcome::stay(),
                DangerOutcome::Cancelled => {
                    self.danger = None;
                    Outcome::stay()
                }
                DangerOutcome::Confirmed => {
                    self.danger = None;
                    self.mode = ImportMode::Busy("Saving registration");
                    Outcome::ask(UiRequest::ApproveRegistration { replace: true })
                }
            };
        }
        match (&self.mode, id) {
            (ImportMode::Review, RegionId::ReviewPrev) => {
                self.go(self.page.saturating_sub(1));
                Outcome::stay()
            }
            (ImportMode::Review, RegionId::ReviewNext) => {
                self.go(self.page + 1);
                Outcome::stay()
            }
            (ImportMode::Review, RegionId::MsApprove) if self.may_approve() => {
                if self.review.duplicate {
                    self.danger = Some(self.replace_sheet());
                    Outcome::stay()
                } else {
                    self.mode = ImportMode::Busy("Saving registration");
                    Outcome::ask(UiRequest::ApproveRegistration { replace: false })
                }
            }
            (ImportMode::Review, RegionId::MsReject) => Outcome { nav: Nav::Back, request: None },
            _ => Outcome::stay(),
        }
    }

    fn answered(&mut self, answer: Answer, _env: &mut Env) -> Outcome {
        match answer {
            Answer::Register(RegistrationOutcome::Saved(info)) => {
                let review = core::mem::replace(&mut self.review, blank_review());
                Outcome::enter(State::MultisigDetail(MultisigDetailState::saved(info, review)))
            }
            // Entered rather than pushed: the approval is spent, and the way on from a
            // refused save is the registry - which is what lies under this screen.
            Answer::Register(RegistrationOutcome::Refused(notice)) => {
                self.mode = ImportMode::Review;
                Outcome::enter(State::Refusal(RefusalState::new(notice)))
            }
            _ => Outcome::stay(),
        }
    }

    fn scroll_mut(&mut self) -> Option<&mut i32> {
        if self.danger.is_some() || matches!(self.mode, ImportMode::Busy(_)) {
            return None;
        }
        Some(&mut self.scroll)
    }

    fn scroll_limit(&self, ctx: &Ctx) -> i32 {
        let l = self.layout(ctx);
        (l.body.height - l.viewport.h).max(0)
    }
}

/// A review with nothing in it, to move the real one out of a `&mut self`.
///
/// Nothing renders it: the only place it is installed is the instant before this screen is
/// replaced by S-43. It exists because a `RegistrationReview` is not `Copy`, and handing the
/// real one forward is what stops two screens holding the same registration.
fn blank_review() -> RegistrationReview {
    RegistrationReview {
        name: String::new(),
        threshold: 0,
        policy: String::new(),
        script: String::new(),
        derivation: String::new(),
        network: notyas_core::bitcoin::Network::Bitcoin,
        cosigners: Vec::new(),
        ours: 0,
        first_address: String::new(),
        descriptor: String::new(),
        converted: false,
        duplicate: false,
    }
}

// ---------------------------------------------------------------------------------------
// S-43 The detail screen
// ---------------------------------------------------------------------------------------

enum DetailMode {
    /// The screen itself, plus the sentence the last answer left behind.
    Detail(Option<(String, Rgb565)>),
    Busy(&'static str),
}

pub(crate) struct MultisigDetailState {
    /// The registry SLOT, not a position in the list. The screen reads its own row out of
    /// [`Ctx::registrations`] every frame, so a registration that is erased, or that a lock
    /// cleared, stops being rendered rather than being rendered from a stale copy.
    slot: u8,
    /// The review this registration was approved from, when it was reached that way.
    ///
    /// [`RegistrationInfo`] carries a policy and a fingerprint and no keys, so a detail
    /// screen opened from a row genuinely cannot show the cosigners or the first address -
    /// and says so, rather than drawing two controls that would open nothing.
    review: Option<RegistrationReview>,
    /// The registration's label as it was when this screen was opened, for the C4d sheet.
    ///
    /// Cached rather than read from the registry, because `activate` cannot reach `Ctx` -
    /// and empty for a screen opened from a row, where the sheet asks for the SLOT instead.
    /// Either way the required word is a value the facts card above the sheet prints.
    name: String,
    show_cosigners: bool,
    show_address: bool,
    scroll: i32,
    danger: Option<Danger>,
    mode: DetailMode,
}

impl MultisigDetailState {
    /// Opened from a registry row.
    pub(crate) fn stored(slot: u8) -> MultisigDetailState {
        MultisigDetailState {
            slot,
            review: None,
            name: String::new(),
            show_cosigners: false,
            show_address: false,
            scroll: 0,
            danger: None,
            mode: DetailMode::Detail(None),
        }
    }

    /// Reached by approving an import.
    ///
    /// The address is disclosed straight away: this is the one moment the cross-check is
    /// worth something, and a user who has to find a button to see it is a user who will not
    /// compare it at all.
    pub(crate) fn saved(info: RegistrationInfo, review: RegistrationReview) -> MultisigDetailState {
        let slot = info.slot;
        MultisigDetailState {
            slot,
            name: info.name,
            review: Some(review),
            show_cosigners: false,
            show_address: true,
            scroll: 0,
            danger: None,
            mode: DetailMode::Detail(Some((
                String::from(
                    "Saved. Compare the first receive address on your other signers before \
                     you use this wallet.",
                ),
                SUCCESS,
            ))),
        }
    }

    pub(crate) fn id(&self) -> ScreenId {
        match self.mode {
            DetailMode::Busy(_) => ScreenId::Working,
            _ => ScreenId::MultisigDetail,
        }
    }

    fn info<'a>(&self, ctx: &'a Ctx) -> Option<&'a RegistrationInfo> {
        ctx.registrations.iter().find(|r| r.slot == self.slot)
    }

    /// What the sheets call this registration, and what the C4d step asks to be typed
    /// back: the name where it can be typed, the slot number where it cannot. Both are on
    /// the facts card above the sheet, so either way the user copies something they can see.
    fn names(&self) -> (String, String) {
        let (shown, _) = printable(&self.name, MAX_NAME_CHARS);
        let title = if shown.trim().is_empty() {
            format!("Delete the registration in slot {}?", self.slot)
        } else {
            format!("Delete registration \"{shown}\"?")
        };
        (title, typed_word(&self.name, self.slot))
    }

    /// The first sheet: what deleting this registration costs, on a sheet with room to say
    /// it. The typed step follows and has a keyboard where this prose would be - the same
    /// two-step sequence the wallet delete uses, and for the same reason.
    fn read_sheet(&self) -> Danger {
        let (title, _) = self.names();
        Danger::confirm(
            &title,
            &[
                "This wallet stops verifying change and addresses for it until you import it \
                 again. Your keys are not affected.",
                "A registration cannot be re-derived from your seed. Import it again from \
                 your coordinator or another signer.",
            ],
            "Continue",
        )
    }

    /// The second sheet: the consent itself.
    fn type_sheet(&self) -> Danger {
        let (title, word) = self.names();
        Danger::typed(
            &title,
            &["Your keys are not affected."],
            "Delete registration",
            &word,
        )
    }

    fn content_column(&self, width: i32, info: Option<&RegistrationInfo>) -> Column {
        let g = SMALL_LINE / 2;
        let mut col = Column::new(width);
        let Some(info) = info else {
            col.heading("This registration is no longer on the device.", INK_PRIMARY);
            col.body(
                "It was erased, or the session that proved it was closed. Open the registry \
                 again to see what this wallet holds.",
                INK_SECONDARY,
            );
            return col;
        };
        if !info.proven {
            col.heading("This slot did not prove out", DANGER);
            col.body(
                "The record in this slot could not be turned back into a registration this \
                 wallet's seed is a member of. Nothing on this device can use it: a \
                 transaction from that wallet is refused, and no address it produces can be \
                 verified.",
                INK_PRIMARY,
            );
            col.space(g);
            col.heading("What to do", INK_PRIMARY);
            col.body(
                "Erase the slot and import the descriptor again from your coordinator or \
                 another signer. Your keys are not affected.",
                INK_SECONDARY,
            );
            return col;
        }
        let Some(review) = &self.review else {
            col.heading("Cosigner keys are not in memory", INK_PRIMARY);
            col.body(
                "This device stores a registration as its descriptor and re-proves it from the \
                 seed when the wallet is opened. The cosigner keys and the first receive \
                 address are shown while you import it, not while you list it - import the \
                 descriptor again to review them.",
                INK_SECONDARY,
            );
            return col;
        };
        if self.show_address {
            col.heading("First receive address", INK_PRIMARY);
            col.mono(&chunked(&compared(&review.first_address), 4), INK_PRIMARY);
            col.space(g);
            col.body(
                "Compare this address on your other signing devices. Every cosigner key goes \
                 into it, so a substituted key changes it - which is the only check on this \
                 device that can catch one.",
                INK_SECONDARY,
            );
            col.space(g);
            match descriptor_checksum(&review.descriptor) {
                Some(sum) => {
                    col.body("Descriptor checksum", INK_SECONDARY);
                    col.mono(&compared(sum), INK_PRIMARY);
                }
                None => col.body("This descriptor carries no checksum.", WARNING),
            }
            col.space(g);
        }
        if self.show_cosigners {
            for (i, c) in review.cosigners.iter().enumerate() {
                col.heading(
                    &format!("Cosigner {} of {}", i + 1, review.cosigners.len()),
                    INK_PRIMARY,
                );
                if c.ours {
                    col.heading("THIS DEVICE", SUCCESS);
                }
                col.mono(&compared(&c.fingerprint), INK_PRIMARY);
                col.mono(&compared(&c.path), INK_SECONDARY);
                col.mono(&chunked(&compared(&c.xpub), 8), INK_PRIMARY);
                col.space(g);
            }
        }
        if !self.show_address && !self.show_cosigners {
            col.body(
                "Show the first receive address to cross-check this wallet against another \
                 signer, or show every cosigner key in full.",
                INK_SECONDARY,
            );
        }
        col
    }
}

pub(crate) struct DetailLayout {
    address_toggle: Option<Rect>,
    cosigner_toggle: Option<Rect>,
    /// What scrolls. The facts card is INSIDE it rather than pinned above it: six rows of
    /// facts, two toggles and a delete button do not fit a 377 px body, and the facts are
    /// the part a reader scrolls past once - where the toggles and the delete are controls
    /// that have to stay where the finger left them.
    viewport: Rect,
    card: Option<FactsCard>,
    /// The DANGER card shown instead of the facts when the slot did not prove out, or when
    /// the registration is no longer on the device.
    fault: Option<(Rect, Column)>,
    content: Column,
    content_y: i32,
    /// The scrolled content's full height, for the scroll bound.
    height: i32,
    band: Option<(Rect, Column)>,
    delete: Option<Rect>,
}

impl Screen for MultisigDetailState {
    type Layout = DetailLayout;

    fn layout(&self, ctx: &Ctx) -> DetailLayout {
        let m = &ctx.m;
        let body = m.body();
        let g = m.gap;
        let info = self.info(ctx);

        // Pinned first, from the outside in: the toggles at the top, the delete at the
        // bottom, the band above it. Whatever is left is what scrolls.
        let mut top = body.y;
        let (mut address_toggle, mut cosigner_toggle) = (None, None);
        if self.review.is_some() && info.is_some_and(|i| i.proven) {
            let half = (body.w - g) / 2;
            address_toggle = Some(Rect::new(body.x, top, half, m.btn));
            cosigner_toggle = Some(Rect::new(body.right() - half, top, half, m.btn));
            top += m.btn + g;
        }

        // Delete is offered for any slot that is actually there, proven or not: erasing an
        // unreadable slot is the whole remedy its row states.
        let delete = info.map(|_| Rect::new(body.x, body.bottom() - m.btn, body.w, m.btn));
        let mut floor = delete.map_or(body.bottom(), |d| d.y - g);

        let mut band = None;
        if let DetailMode::Detail(Some((sentence, ink))) = &self.mode {
            let mut col = Column::new(body.w);
            col.body(sentence, *ink);
            let h = col.height();
            floor -= h + g;
            band = Some((Rect::new(body.x, floor + g, body.w, h), col));
        }

        let viewport = Rect::new(body.x, top, body.w, (floor - top).max(0));
        let at = viewport.y - self.scroll;

        let mut card = None;
        let mut fault = None;
        let content_y;
        match info {
            Some(i) if i.proven => {
                let (name, _) = printable(&i.name, MAX_NAME_CHARS);
                let c = facts_card(
                    Rect::new(viewport.x, at, viewport.w, 0),
                    alloc::vec![
                        Fact { caption: "Name", value: name, ink: INK_PRIMARY },
                        // The slot is on the card because it is the word the C4d sheet falls
                        // back to, and a sheet may only ask for a value the screen shows.
                        Fact {
                            caption: "Slot",
                            value: i.slot.to_string(),
                            ink: INK_SECONDARY,
                        },
                        Fact {
                            caption: "Policy",
                            value: format!(
                                "{} of {}   {}",
                                i.threshold,
                                i.cosigners,
                                compared(&i.script)
                            ),
                            ink: INK_PRIMARY,
                        },
                        Fact {
                            caption: "Derivation",
                            value: compared(&i.derivation),
                            ink: INK_PRIMARY,
                        },
                        Fact {
                            caption: "This device",
                            value: compared(&i.fingerprint),
                            ink: INK_PRIMARY,
                        },
                        Fact {
                            caption: "Network",
                            value: i.network.to_string(),
                            ink: if i.network == notyas_core::bitcoin::Network::Bitcoin {
                                INK_PRIMARY
                            } else {
                                WARNING
                            },
                        },
                    ],
                );
                content_y = c.rect.bottom() + g;
                card = Some(c);
            }
            _ => {
                let mut col = Column::new(viewport.w - 2 * CARD_PAD);
                col.heading(
                    match info {
                        None => "Registration not found",
                        Some(_) => "Unreadable registration",
                    },
                    DANGER,
                );
                col.body(&format!("Registry slot {}.", self.slot), INK_PRIMARY);
                let h = col.height() + 2 * CARD_PAD;
                fault = Some((Rect::new(viewport.x, at, viewport.w, h), col));
                content_y = at + h + g;
            }
        }

        let content = self.content_column(viewport.w, info);
        let height = content_y + content.height() - at;

        DetailLayout {
            address_toggle,
            cosigner_toggle,
            viewport,
            card,
            fault,
            content,
            content_y,
            height,
            band,
            delete,
        }
    }

    fn regions(&self, ctx: &Ctx, out: &mut Vec<Region>) {
        if let Some(d) = &self.danger {
            d.regions(&ctx.m, out);
            return;
        }
        if matches!(self.mode, DetailMode::Busy(_)) {
            return;
        }
        let l = self.layout(ctx);
        out.push(Region { id: RegionId::Back, rect: back_rect(&ctx.m) });
        if let Some(r) = l.address_toggle {
            out.push(Region { id: RegionId::MsFirstAddress, rect: r });
        }
        if let Some(r) = l.cosigner_toggle {
            out.push(Region { id: RegionId::MsCosigners, rect: r });
        }
        if let Some(r) = l.delete {
            out.push(Region { id: RegionId::MsDelete, rect: r });
        }
    }

    fn draw<D: DrawTarget<Color = Rgb565>>(&self, t: &mut D, ctx: &Ctx) -> Result<(), D::Error> {
        let m = &ctx.m;
        if let Some(d) = &self.danger {
            return d.draw(t, m, ctx.press, ctx.hold_released);
        }
        if let DetailMode::Busy(what) = self.mode {
            return draw_busy(t, m, what);
        }
        let info = self.info(ctx);
        let title = match info {
            Some(i) => clamp_to_width(
                &printable(&i.name, MAX_NAME_CHARS).0,
                m.w - back_rect(m).right() - 2 * m.gap,
                HEADING,
            ),
            None => String::from("Registration"),
        };
        draw_bar(t, m, &title)?;
        let l = self.layout(ctx);

        {
            let mut clip = t.clipped(&l.viewport.to_eg());
            if let Some(card) = &l.card {
                card.draw(&mut clip)?;
            }
            if let Some((rect, col)) = &l.fault {
                fill(&mut clip, *rect, DANGER_TINT)?;
                frame(&mut clip, *rect, DANGER)?;
                col.draw(&mut clip, rect.x + CARD_PAD, rect.y + CARD_PAD, DANGER_TINT)?;
            }
            l.content.draw(&mut clip, l.viewport.x, l.content_y, PAPER_1)?;
        }
        edges(t, l.viewport, self.scroll, (l.height - l.viewport.h).max(0))?;
        if let Some(r) = l.address_toggle {
            let label = if self.show_address { "Hide address" } else { "Show first address" };
            button(t, r, label, ButtonKind::Secondary, PAPER_1)?;
        }
        if let Some(r) = l.cosigner_toggle {
            let label = if self.show_cosigners { "Hide cosigners" } else { "Show all cosigners" };
            button(t, r, label, ButtonKind::Secondary, PAPER_1)?;
        }
        if let Some((rect, col)) = &l.band {
            col.draw(t, rect.x, rect.y, PAPER_1)?;
        }
        if let Some(r) = l.delete {
            button(t, r, "Delete registration", ButtonKind::Danger, PAPER_1)?;
        }
        Ok(())
    }

    fn activate(&mut self, id: RegionId, _env: &mut Env) -> Outcome {
        if let Some(d) = &mut self.danger {
            // One field for both steps: the sheet knows its own grade, so "the consequence
            // has been read" and "the name has been typed" are the same `Confirmed` answer
            // asked of two different sheets, and there is no second flag to disagree with it.
            let reading = d.grade() == DangerGrade::Confirm;
            return match d.activate(id) {
                DangerOutcome::Open | DangerOutcome::Alternative => Outcome::stay(),
                DangerOutcome::Cancelled => {
                    self.danger = None;
                    Outcome::stay()
                }
                DangerOutcome::Confirmed if reading => {
                    self.danger = Some(self.type_sheet());
                    Outcome::stay()
                }
                // The UI owns no flash. It names what it is doing and asks; the answer says
                // whether the slot is gone, and the screen states it either way.
                DangerOutcome::Confirmed => {
                    self.danger = None;
                    self.mode = DetailMode::Busy("Erasing registration");
                    Outcome::ask(UiRequest::DeleteRegistration(self.slot))
                }
            };
        }
        match id {
            RegionId::MsFirstAddress => {
                self.show_address = !self.show_address;
                self.scroll = 0;
                Outcome::stay()
            }
            RegionId::MsCosigners => {
                self.show_cosigners = !self.show_cosigners;
                self.scroll = 0;
                Outcome::stay()
            }
            // The name the sheet asks for comes from the review this screen was handed,
            // because `activate` cannot reach the registry. Without one the slot number is
            // the word - which is the value the fault card above the sheet prints.
            RegionId::MsDelete => {
                let sheet = self.read_sheet();
                self.danger = Some(sheet);
                Outcome::stay()
            }
            _ => Outcome::stay(),
        }
    }

    fn answered(&mut self, answer: Answer, _env: &mut Env) -> Outcome {
        match answer {
            // The registry is the evidence either way: the embedder re-installs it, and this
            // screen reads its own row out of it. `true` means the row is gone, so going
            // back to the list is going back to the truth.
            Answer::DeleteRegistration(true) => Outcome { nav: Nav::Back, request: None },
            Answer::DeleteRegistration(false) => {
                self.mode = DetailMode::Detail(Some((
                    String::from("The registration was NOT erased. It is still on this device."),
                    DANGER,
                )));
                Outcome::stay()
            }
            _ => Outcome::stay(),
        }
    }

    fn scroll_mut(&mut self) -> Option<&mut i32> {
        if self.danger.is_some() || matches!(self.mode, DetailMode::Busy(_)) {
            return None;
        }
        Some(&mut self.scroll)
    }

    fn scroll_limit(&self, ctx: &Ctx) -> i32 {
        let l = self.layout(ctx);
        (l.height - l.viewport.h).max(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::danger::DangerGrade;
    use crate::layout::TOUCH_MIN;
    use crate::screens::testing::{fits, rows_are_clear_on, Fixture, GEOMETRIES};
    use crate::{BackupState, CosignerRow, NullTarget, RefusalCode, RefusalNotice, WalletKind};
    use notyas_core::bitcoin::Network;

    // -----------------------------------------------------------------------------------
    // Sample data
    //
    // Real BIP-32 test-vector xpubs and the BIP-173 P2WSH example address: public,
    // published, worthless as keys, and exactly the right LENGTH - which is what these
    // tests turn on, because a 111-character value that wraps to four mono lines either
    // fits the panel or does not.
    // -----------------------------------------------------------------------------------

    const XPUBS: [&str; 3] = [
        "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
        "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
        "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
    ];
    const ADDRESS: &str = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";
    const PATH: &str = "m/48'/0'/0'/2'";

    fn cosigner(i: usize, ours: bool) -> CosignerRow {
        CosignerRow {
            fingerprint: format!("a1b2c3{i:02x}"),
            path: String::from(PATH),
            xpub: String::from(XPUBS[i % XPUBS.len()]),
            ours,
        }
    }

    /// A descriptor of the shape and roughly the length a real one has, so the pages that
    /// render it are measured against a realistic value rather than a token.
    fn descriptor_for(n: usize) -> String {
        let keys: Vec<String> = (0..n)
            .map(|i| format!("[a1b2c3{:02x}/48h/0h/0h/2h]{}/<0;1>/*", i, XPUBS[i % XPUBS.len()]))
            .collect();
        format!("wsh(sortedmulti(2,{}))#8zl0zxma", keys.join(","))
    }

    /// A well-formed review of `n` cosigners in which cosigner `ours` (1-based) is us.
    fn review(n: usize, ours: u8) -> RegistrationReview {
        RegistrationReview {
            name: String::from("vault 2of3"),
            threshold: 2,
            policy: String::from("sortedmulti"),
            script: String::from("P2WSH (native segwit)"),
            derivation: String::from(PATH),
            network: Network::Bitcoin,
            cosigners: (0..n).map(|i| cosigner(i, i + 1 == usize::from(ours))).collect(),
            ours,
            first_address: String::from(ADDRESS),
            descriptor: descriptor_for(n),
            converted: false,
            duplicate: false,
        }
    }

    fn info(slot: u8, proven: bool) -> RegistrationInfo {
        RegistrationInfo {
            slot,
            name: format!("vault {slot}"),
            threshold: 2,
            cosigners: 3,
            script: String::from("P2WSH"),
            derivation: String::from(PATH),
            fingerprint: String::from("a1b2c3d4"),
            network: Network::Bitcoin,
            proven,
        }
    }

    fn wallet(registrations: u8) -> WalletInfo {
        WalletInfo {
            slot: 0,
            name: String::from("savings"),
            fingerprint: String::from("a1b2c3d4"),
            path: String::from("m/84'/0'/0'"),
            script_type: String::from("native segwit"),
            kind: WalletKind::Multisig,
            backup: BackupState::Verified(String::new()),
            network: Network::Bitcoin,
            registrations,
            stored: true,
            passphrase: false,
        }
    }

    fn file(name: &str, kind: FileKind, oversize: bool) -> FileRow {
        FileRow {
            name: String::from(name),
            kind,
            len: 512,
            modified: String::from("17 Aug 14:02"),
            oversize,
        }
    }

    fn listing(rows: Vec<FileRow>) -> CardListing {
        CardListing { dir: String::new(), rows, truncated: false, rejected: 0 }
    }

    fn notice() -> RefusalNotice {
        RefusalNotice {
            code: RefusalCode::CosignerMismatch,
            happened: String::from("cosigner 2 claims this device's key"),
            details: String::from("at=1"),
            after_signing: false,
        }
    }

    fn regions_of<S: Screen>(s: &S, ctx: &Ctx) -> Vec<Region> {
        let mut out = Vec::new();
        s.regions(ctx, &mut out);
        out
    }

    fn has<S: Screen>(s: &S, ctx: &Ctx, id: RegionId) -> bool {
        regions_of(s, ctx).iter().any(|r| r.id == id)
    }

    /// Drive a tap the way the dispatcher does, with a throwaway `Env`.
    fn tap<S: Screen>(s: &mut S, f: &Fixture, id: RegionId) -> Outcome {
        let mut network = Network::Bitcoin;
        let mut env = Env { network: &mut network, lock: &f.lock, wallets: &f.wallets };
        s.activate(id, &mut env)
    }

    fn answer<S: Screen>(s: &mut S, f: &Fixture, a: Answer) -> Outcome {
        let mut network = Network::Bitcoin;
        let mut env = Env { network: &mut network, lock: &f.lock, wallets: &f.wallets };
        s.answered(a, &mut env)
    }

    /// Every region is a reachable target on the panel.
    ///
    /// The bar's Back is exempt from the size floor and only from that: its rectangle is
    /// `components::back_rect`, shared by every screen in the crate, and it is 51 px tall on
    /// the 800x480 panel. That is the bar's business to fix, not this screen's to assert
    /// about - but where it LANDS is still checked here.
    fn targets_are_reachable(what: &str, m: &Metrics, out: &[Region]) {
        let panel = m.screen();
        for r in out {
            if r.id != RegionId::Back {
                assert!(
                    r.rect.w >= TOUCH_MIN && r.rect.h >= TOUCH_MIN,
                    "{what}: {:?} is {}x{}, under the {TOUCH_MIN} px floor",
                    r.id,
                    r.rect.w,
                    r.rect.h
                );
            }
            assert!(
                r.rect.x >= 0
                    && r.rect.y >= 0
                    && r.rect.right() <= panel.right()
                    && r.rect.bottom() <= panel.bottom(),
                "{what}: {:?} at {:?} escapes the {}x{} panel",
                r.id,
                r.rect,
                m.w,
                m.h
            );
        }
    }

    /// Every measured line of a column fits the frame it is drawn in.
    ///
    /// The rectangle checks can only see what a screen makes TAPPABLE; a line of prose has
    /// no `Region`, so a line 200 px too wide passes every other assertion in this file and
    /// crops silently on the glass.
    fn column_fits(what: &str, col: &Column, frame: Rect) {
        for (line, need) in col.measured() {
            fits(what, &line, need, frame);
        }
    }

    // -----------------------------------------------------------------------------------
    // The security core
    // -----------------------------------------------------------------------------------

    /// THE most important refusal on this screen: a descriptor that does not contain this
    /// device's key can never be stored.
    ///
    /// Five ways a file can lie about it, and all five are the 2021 xpub-substitution
    /// attack: point `ours` past the end of the set, point it at nothing, point it at a
    /// cosigner that does not claim to be us, claim to be us twice, or claim it nowhere.
    /// Every one has to reach the same place - no `MsApprove` region on any page at any
    /// traversal state, and an `MsApprove` fed in by hand raising nothing.
    #[test]
    fn a_review_that_does_not_name_this_device_can_never_be_approved() {
        let mut broken: Vec<(&str, RegistrationReview)> = Vec::new();

        let mut out_of_range = review(3, 1);
        out_of_range.ours = 4;
        broken.push(("ours points past the set", out_of_range));

        let mut zero = review(3, 1);
        zero.ours = 0;
        broken.push(("ours points at nothing", zero));

        let mut mislabelled = review(3, 1);
        mislabelled.ours = 2; // the flag is still on cosigner 1
        broken.push(("ours points at a cosigner that is not flagged", mislabelled));

        let mut twice = review(3, 1);
        twice.cosigners[2].ours = true;
        broken.push(("two cosigners both claim to be this device", twice));

        let mut none = review(3, 1);
        none.cosigners[0].ours = false;
        broken.push(("no cosigner claims to be this device", none));

        for (what, r) in broken {
            assert_eq!(
                blocked_by(&r),
                Some(Blocked::NotAMember),
                "{what}: the screen did not refuse it"
            );
            for (w, h) in GEOMETRIES {
                let f = Fixture::new(w, h);
                let ctx = f.ctx();
                let mut s = MultisigImportState::new(r.clone());
                // Walk every page there is, marking them all seen, and check every one.
                for page in 0..s.pages() {
                    s.go(page);
                    assert!(
                        !has(&s, &ctx, RegionId::MsApprove),
                        "{w}x{h} {what}: page {page} offered MsApprove"
                    );
                }
                assert!(!s.may_approve(), "{w}x{h} {what}: may_approve said yes");
                // And a region fed in by hand - a stale tap, a mis-wired embedder - raises no
                // request either.
                let outcome = tap(&mut s, &f, RegionId::MsApprove);
                assert!(outcome.request.is_none(), "{w}x{h} {what}: MsApprove raised a request");
                // The screen says what it refused and why, and offers the two ways out.
                let l = s.layout(&ctx);
                let (_, said) = l.body.note.as_ref().expect("a blocked review states its verdict");
                assert!(
                    said.prose().contains("not one of the cosigners"),
                    "{w}x{h} {what}: the refusal is not on the panel"
                );
                assert!(has(&s, &ctx, RegionId::MsReject), "{w}x{h} {what}: no way to reject");
                s.draw(&mut NullTarget, &ctx).expect("the blocked page renders");
            }
        }
    }

    /// A quorum that cannot exist is refused rather than rendered as an ordinary review.
    #[test]
    fn an_impossible_policy_can_never_be_approved() {
        let mut cases: Vec<(&str, RegistrationReview)> = Vec::new();

        let mut zero_of_three = review(3, 1);
        zero_of_three.threshold = 0;
        cases.push(("0 of 3", zero_of_three));

        let mut four_of_three = review(3, 1);
        four_of_three.threshold = 4;
        cases.push(("4 of 3", four_of_three));

        let mut none = review(3, 1);
        none.cosigners.clear();
        cases.push(("no cosigners at all", none));

        cases.push(("16 cosigners", review(MAX_COSIGNERS + 1, 1)));

        for (what, r) in cases {
            assert_eq!(
                blocked_by(&r),
                Some(Blocked::ImpossiblePolicy),
                "{what}: the screen did not refuse it"
            );
            for (w, h) in GEOMETRIES {
                let f = Fixture::new(w, h);
                let ctx = f.ctx();
                let mut s = MultisigImportState::new(r.clone());
                for page in 0..s.pages() {
                    s.go(page);
                    assert!(
                        !has(&s, &ctx, RegionId::MsApprove),
                        "{w}x{h} {what}: page {page} offered MsApprove"
                    );
                }
                s.draw(&mut NullTarget, &ctx).expect("the blocked page renders");
            }
        }
    }

    /// A descriptor longer than any wallet this device can hold is refused BEFORE it is
    /// wrapped and measured, and the page that says so is a bounded size.
    ///
    /// The bound is the point. Without it a 200 KB string out of a file goes through
    /// `Column::mono`, which allocates one `String` per rendered line - thousands of them -
    /// every single time the panel repaints.
    #[test]
    fn an_over_long_descriptor_is_refused_before_it_is_measured() {
        let mut r = review(3, 1);
        r.descriptor = core::iter::repeat_n('x', MAX_DESCRIPTOR_CHARS + 1).collect();
        assert_eq!(blocked_by(&r), Some(Blocked::DescriptorTooLong));

        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            let ctx = f.ctx();
            let s = MultisigImportState::new(r.clone());
            let l = s.layout(&ctx);
            assert!(!has(&s, &ctx, RegionId::MsApprove), "{w}x{h}: a refused descriptor approved");
            // The refusal page states the LENGTH; it never draws the value. A page that
            // wrapped it would be an order of magnitude taller than the panel.
            assert!(
                l.body.height < 4 * f.m.h,
                "{w}x{h}: the refusal page is {} px tall - the descriptor was wrapped",
                l.body.height
            );
            assert!(
                !l.body.col.joined().contains("xxxxxxxxxx"),
                "{w}x{h}: the refused descriptor reached the panel"
            );
            assert!(
                l.body.col.prose().contains(&format!("{} characters", MAX_DESCRIPTOR_CHARS + 1)),
                "{w}x{h}: the page does not state how long it was"
            );
            s.draw(&mut NullTarget, &ctx).expect("the refusal renders");
        }
    }

    /// C5's enforced traversal: approval is offered only on the last page and only after
    /// every page has been on the panel.
    #[test]
    fn approval_waits_for_the_whole_traversal() {
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            let ctx = f.ctx();
            let mut s = MultisigImportState::new(review(3, 1));
            assert_eq!(s.pages(), 5, "the overview, three cosigners, and the address page");

            // Jump straight to the last page: the pages between were never seen.
            s.go(s.last());
            assert!(!has(&s, &ctx, RegionId::MsApprove), "{w}x{h}: a skipped review approved");
            let l = s.layout(&ctx);
            let (rect, col) = l.reason.as_ref().expect("a disabled approve carries its reason");
            assert!(col.prose().contains("not yet seen"), "{w}x{h}: the reason is not stated");
            column_fits(&format!("{w}x{h} approve reason"), col, *rect);

            // Now walk it the way a finger does.
            s.go(0);
            while s.page < s.last() {
                assert!(has(&s, &ctx, RegionId::ReviewNext), "{w}x{h}: the pager stopped");
                tap(&mut s, &f, RegionId::ReviewNext);
            }
            assert_eq!(s.unseen(), 0);
            assert!(has(&s, &ctx, RegionId::MsApprove), "{w}x{h}: a full traversal cannot approve");
            assert!(s.layout(&ctx).reason.is_none(), "{w}x{h}: a live approve still has a reason");

            // Paging back and forth is fine; the set does not un-see a page.
            tap(&mut s, &f, RegionId::ReviewPrev);
            tap(&mut s, &f, RegionId::ReviewNext);
            assert!(has(&s, &ctx, RegionId::MsApprove));
        }
    }

    /// Ratified invariant 2b: the flash write is announced, naming what it writes, and the
    /// announcement is pinned above the button that performs it.
    #[test]
    fn the_flash_write_is_announced_above_the_button_that_performs_it() {
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            let ctx = f.ctx();
            let mut s = MultisigImportState::new(review(3, 1));

            for page in 0..s.last() {
                s.go(page);
                assert!(
                    s.layout(&ctx).notice.is_none(),
                    "{w}x{h}: page {page} announces a write it cannot perform"
                );
            }

            s.go(s.last());
            let l = s.layout(&ctx);
            let notice = l.notice.expect("the write page carries the C12 notice");
            assert!(
                notice.bottom() <= l.next.y,
                "{w}x{h}: the notice at {notice:?} is not above the approve button {:?}",
                l.next
            );
            assert!(
                notice.y >= l.viewport.bottom(),
                "{w}x{h}: the notice is inside the scrolled content and can be scrolled away"
            );

            // What it says: the artifact, its quorum, and the value another device compares.
            let (what, confidentiality) = s.notice_copy();
            assert!(what.contains("vault 2of3"), "the notice does not name the registration");
            assert!(what.contains("2 of 3"), "the notice does not name the quorum");
            assert!(what.contains("8zl0zxma"), "the notice does not name the checksum");
            assert!(confidentiality.contains("no private key"));
        }
    }

    /// A registration that is already stored is replaced only through the C4a sheet, and
    /// the request that goes out says `replace`.
    #[test]
    fn a_duplicate_registration_is_replaced_only_through_the_danger_sheet() {
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            let ctx = f.ctx();
            let mut r = review(3, 1);
            r.duplicate = true;
            let mut s = MultisigImportState::new(r);
            for _ in 0..s.last() {
                tap(&mut s, &f, RegionId::ReviewNext);
            }
            let outcome = tap(&mut s, &f, RegionId::MsApprove);
            assert!(outcome.request.is_none(), "{w}x{h}: a duplicate wrote without a confirm");
            let d = s.danger.as_ref().expect("no sheet opened");
            assert!(d.fits(&f.m), "{w}x{h}: the replace sheet's copy does not fit");
            // While the sheet is open it is the only thing on the panel.
            let sheet: Vec<RegionId> = regions_of(&s, &ctx).iter().map(|r| r.id).collect();
            assert!(
                !sheet.contains(&RegionId::MsApprove) && !sheet.contains(&RegionId::ReviewPrev),
                "{w}x{h}: the review is still tappable under the sheet"
            );
            let outcome = tap(&mut s, &f, RegionId::DangerConfirm);
            assert_eq!(
                outcome.request,
                Some(UiRequest::ApproveRegistration { replace: true }),
                "{w}x{h}: the confirmed sheet did not ask for a replace"
            );
            assert_eq!(s.id(), ScreenId::Working, "{w}x{h}: the write is not on a Busy frame");
            assert!(regions_of(&s, &ctx).is_empty(), "{w}x{h}: a Busy frame is tappable");
        }
    }

    /// A first import never asks to replace anything. The flag is not a formality: it
    /// decides whether a stored record is destroyed.
    #[test]
    fn a_first_import_never_asks_to_replace_anything() {
        let f = Fixture::new(720, 720);
        let mut s = MultisigImportState::new(review(2, 2));
        for _ in 0..s.last() {
            tap(&mut s, &f, RegionId::ReviewNext);
        }
        let outcome = tap(&mut s, &f, RegionId::MsApprove);
        assert_eq!(outcome.request, Some(UiRequest::ApproveRegistration { replace: false }));
    }

    // -----------------------------------------------------------------------------------
    // Attacker-supplied text
    // -----------------------------------------------------------------------------------

    /// Text off a card is reduced to glyphs this device actually has, and a cap that fires
    /// is visible.
    ///
    /// The atlas is ASCII plus the bullet and the ellipsis. A character outside it draws as
    /// NOTHING, so a name of twelve such code points would render as an empty string beside
    /// a policy - a free impersonation of any wallet the user trusts.
    #[test]
    fn text_from_a_card_is_reduced_to_glyphs_this_device_has() {
        let (out, cut) = printable("vault", 48);
        assert_eq!((out.as_str(), cut), ("vault", false), "plain ASCII passes through");

        let (out, _) = printable("va\u{0448}lt\u{202e}", 48);
        assert_eq!(out, "va?lt?", "a glyph the atlas lacks must be visible, not absent");

        let (out, _) = printable("a\nb\tc", 48);
        assert_eq!(out, "a?b?c", "control characters are not drawn");

        let long: String = core::iter::repeat_n('x', 200).collect();
        let (out, cut) = printable(&long, MAX_NAME_CHARS);
        assert!(cut, "the cap must report that it fired");
        assert_eq!(out.chars().count(), MAX_NAME_CHARS + 1, "the cap plus its ellipsis");
        assert!(out.ends_with(ELLIPSIS));

        // Every character it can produce is drawable, and every one is on the keyboard - so
        // a C4d sheet built from a sanitised name is always completable.
        for c in ' '..='~' {
            let (out, _) = printable(&c.to_string(), 8);
            assert_eq!(out, c.to_string(), "printable ASCII must survive verbatim");
            assert!(in_atlas(c));
        }
    }

    /// A value the user COMPARES is sanitised and never shortened. Shortening one would
    /// defeat the only reason it is on the screen.
    #[test]
    fn a_compared_value_is_never_shortened() {
        for xpub in XPUBS {
            assert_eq!(compared(xpub), xpub);
        }
        assert_eq!(compared(ADDRESS), ADDRESS);
        assert_eq!(compared(PATH), PATH);
        assert_eq!(compared("a1b2\u{0448}3d4"), "a1b2?3d4", "and it is still sanitised");
    }

    /// A hostile name cannot push the bar title over the panel edge.
    ///
    /// The bar draws its title as one unclipped run, so a long enough name paints straight
    /// off the glass - which the pixel gate catches and no rectangle check would.
    #[test]
    fn a_hostile_name_cannot_push_the_bar_title_off_the_panel() {
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            let mut info = wallet(0);
            info.name = core::iter::repeat_n('W', 400).collect();
            let s = MultisigListState::new(&info);
            let title = s.title(&f.m, None);
            let room = f.m.w - back_rect(&f.m).right() - 2 * f.m.gap;
            fits(
                &format!("{w}x{h} registry bar"),
                &title,
                HEADING.text_width(&title) as i32,
                Rect::new(0, 0, room, f.m.bar),
            );
        }
    }

    /// The cap this module states has to be the engine's cap, or a 15-cosigner wallet the
    /// device really can hold would be refused by its own screen.
    #[test]
    fn the_cosigner_cap_matches_the_engine() {
        assert_eq!(
            MAX_COSIGNERS,
            usize::from(notyas_core::multisig::MAX_COSIGNERS),
            "the screen's cap and the engine's have drifted"
        );
    }

    // -----------------------------------------------------------------------------------
    // S-41 the registry
    // -----------------------------------------------------------------------------------

    /// The registry lays out on both panels, empty and full.
    #[test]
    fn the_registry_lays_out_on_both_panels() {
        for (w, h) in GEOMETRIES {
            for n in [0usize, 1, 3, 8] {
                let mut f = Fixture::new(w, h);
                f.registrations = (0..n as u8).map(|i| info(i, true)).collect();
                let ctx = f.ctx();
                let s = MultisigListState::new(&wallet(n as u8));
                let l = s.layout(&ctx);
                let what = format!("{w}x{h} registry with {n}");

                let capacity = l.capacity.expect("the registry states what it holds");
                rows_are_clear_on(
                    &f.m,
                    &what,
                    f.m.body(),
                    &[("viewport", l.viewport), ("capacity", capacity), ("action", l.action)],
                );
                targets_are_reachable(&what, &f.m, &regions_of(&s, &ctx));
                assert_eq!(
                    l.viewport.h,
                    whole_rows(l.viewport.h),
                    "{what}: the viewport ends inside a row"
                );
                assert!(
                    l.viewport.h >= row_extent(2),
                    "{what}: the registry viewport holds fewer than two rows"
                );
                match &l.empty {
                    Some((rect, col)) => {
                        assert_eq!(n, 0, "{what}: an empty state over a list that has rows");
                        rows_are_clear_on(&f.m, &what, f.m.body(), &[("well", *rect)]);
                        column_fits(&what, col, rect.inset(CARD_PAD));
                    }
                    None => assert_ne!(n, 0, "{what}: an empty list drew no empty state"),
                }
                s.draw(&mut NullTarget, &ctx).expect("the registry renders");
            }
        }
    }

    /// At rest, every row that is painted is tappable.
    ///
    /// `draw` paints rows through a clip, so any overlap at all leaves ink; `regions` emits
    /// a row only when it fits entirely. The two have to be the same set wherever the list
    /// is standing still, or the screen shows a control that does nothing.
    #[test]
    fn every_painted_registry_row_at_rest_is_tappable() {
        for (w, h) in GEOMETRIES {
            for n in [1u8, 2, 8] {
                let mut f = Fixture::new(w, h);
                f.registrations = (0..n).map(|i| info(i, true)).collect();
                let ctx = f.ctx();
                let mut s = MultisigListState::new(&wallet(n));
                for offset in [0, s.scroll_limit(&ctx)] {
                    *s.scroll_mut().unwrap() = offset;
                    let l = s.layout(&ctx);
                    let out = regions_of(&s, &ctx);
                    for i in 0..n as usize {
                        let r = row_rect(&l.viewport, i, offset);
                        let painted = r.y < l.viewport.bottom() && r.bottom() > l.viewport.y;
                        let tappable =
                            out.iter().any(|g| g.id == RegionId::ListRow(i as u8) && g.rect == r);
                        assert_eq!(
                            painted, tappable,
                            "{w}x{h}, {n} rows at scroll {offset}: row {i} at {r:?} is \
                             painted={painted} tappable={tappable}"
                        );
                    }
                }
                // ...and the last row is reachable.
                let limit = s.scroll_limit(&ctx);
                *s.scroll_mut().unwrap() = limit;
                let l = s.layout(&ctx);
                let last = row_rect(&l.viewport, n as usize - 1, limit);
                assert!(
                    last.bottom() <= l.viewport.bottom() && last.y >= l.viewport.y,
                    "{w}x{h}: the last of {n} rows is unreachable at {last:?}"
                );
            }
        }
    }

    /// A wallet that claims registrations this device could not prove says exactly that,
    /// and does NOT render the empty state.
    ///
    /// "No multisig registrations" would be a lie with consequences here: the user concludes
    /// the wallet has none, and the next multisig PSBT is refused with nothing to explain
    /// it. The row that has to be erased is the thing they need to be sent to.
    #[test]
    fn the_registry_says_when_a_wallet_claims_more_than_it_can_prove() {
        for (w, h) in GEOMETRIES {
            let mut f = Fixture::new(w, h);
            f.wallets = alloc::vec![WalletRow::Wallet(wallet(3))];
            let ctx = f.ctx();
            let s = MultisigListState::new(&wallet(3));
            let l = s.layout(&ctx);
            let (rect, col) = l.fault.as_ref().expect("a claimed-but-unproven count is a fault");
            assert!(l.empty.is_none(), "{w}x{h}: it claimed there are none");
            let joined = col.prose();
            assert!(joined.contains("claims 3 registration"), "the card does not state the claim");
            assert!(joined.contains("3 of them did not prove out"), "or what went wrong");
            assert!(joined.contains("erase the slot"), "or what to do about it");
            rows_are_clear_on(
                &f.m,
                &format!("{w}x{h} registry fault"),
                f.m.body(),
                &[("fault", *rect), ("viewport", l.viewport), ("action", l.action)],
            );
            column_fits(&format!("{w}x{h} registry fault"), col, rect.inset(CARD_PAD));
            s.draw(&mut NullTarget, &ctx).expect("the fault card renders");
        }
    }

    /// Erasing a registration does not leave the registry shouting about a fault it made up.
    ///
    /// The claim is read off the wallet row every frame rather than cached when the screen
    /// is built. A cached one still says "2" after the user erases one of the two, and a
    /// DANGER card about registrations that are gone teaches the reader to ignore the card
    /// that means something.
    #[test]
    fn the_fault_card_follows_the_wallet_row_rather_than_a_cached_count() {
        for (w, h) in GEOMETRIES {
            let mut f = Fixture::new(w, h);
            f.wallets = alloc::vec![WalletRow::Wallet(wallet(2))];
            f.registrations = alloc::vec![info(0, true), info(1, true)];
            let s = MultisigListState::new(&wallet(2));
            assert!(
                s.layout(&f.ctx()).fault.is_none(),
                "{w}x{h}: two claimed and two proven is not a fault"
            );

            // The user erases one, and the embedder re-installs both lists.
            f.wallets = alloc::vec![WalletRow::Wallet(wallet(1))];
            f.registrations = alloc::vec![info(0, true)];
            assert!(
                s.layout(&f.ctx()).fault.is_none(),
                "{w}x{h}: an erased slot was rendered as an unreadable one"
            );

            // ...and a wallet row this screen cannot find makes no claim at all.
            f.wallets = Vec::new();
            assert!(s.layout(&f.ctx()).fault.is_none(), "{w}x{h}: a claim was invented");
        }
    }

    /// The picker: rows are reachable, an oversize row is drawn and not offered, a folder
    /// walks one level, and a file reads and decides in one request.
    #[test]
    fn the_picker_lays_out_and_offers_only_what_can_be_read() {
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            let ctx = f.ctx();
            let mut s = MultisigListState::new(&wallet(0));
            let outcome = tap(&mut s, &f, RegionId::MsImport);
            assert_eq!(
                outcome.request,
                Some(UiRequest::ListCard { dir: String::new(), filter: FileFilter::All })
            );
            assert_eq!(s.id(), ScreenId::Working, "{w}x{h}: reading a card is a Busy frame");
            assert!(regions_of(&s, &ctx).is_empty(), "{w}x{h}: a Busy frame is tappable");

            answer(
                &mut s,
                &f,
                Answer::Card(CardOutcome::Listed(listing(alloc::vec![
                    file("vault.txt", FileKind::Text, false),
                    file("huge.json", FileKind::Json, true),
                    file("wallets", FileKind::Directory, false),
                ]))),
            );
            assert_eq!(s.id(), ScreenId::MultisigList);
            let what = format!("{w}x{h} picker");
            targets_are_reachable(&what, &f.m, &regions_of(&s, &ctx));
            let l = s.layout(&ctx);
            let (head_rect, head) = l.pick_head.as_ref().expect("the picker names what it wants");
            assert!(head.prose().contains("3 on the card"), "the picker states the count");
            column_fits(&what, head, *head_rect);
            assert!(
                l.viewport.h >= row_extent(2),
                "{what}: the picker shows {} px of rows",
                l.viewport.h
            );
            s.draw(&mut NullTarget, &ctx).expect("the picker renders");

            // Every readable row is reachable by scrolling to it, which is how a finger
            // gets there; the oversize row is reachable and never offered.
            let limit = s.scroll_limit(&ctx);
            for (i, offered) in [(0u8, true), (1, false), (2, true)] {
                let to = (i as i32 * (ROW_H + ROW_GAP)).min(limit);
                *s.scroll_mut().unwrap() = to;
                assert_eq!(
                    has(&s, &ctx, RegionId::ListRow(i)),
                    offered,
                    "{what}: row {i} offered={} at scroll {to}",
                    !offered
                );
            }

            // A folder walks one level.
            assert_eq!(
                tap(&mut s, &f, RegionId::ListRow(2)).request,
                Some(UiRequest::ListCard {
                    dir: String::from("wallets"),
                    filter: FileFilter::All
                })
            );

            // A file reads AND decides in one request.
            let mut pick = MultisigListState::new(&wallet(0));
            tap(&mut pick, &f, RegionId::MsImport);
            answer(
                &mut pick,
                &f,
                Answer::Card(CardOutcome::Listed(listing(alloc::vec![file(
                    "vault.txt",
                    FileKind::Text,
                    false
                )]))),
            );
            assert_eq!(
                tap(&mut pick, &f, RegionId::ListRow(0)).request,
                Some(UiRequest::ImportRegistration {
                    dir: String::new(),
                    name: String::from("vault.txt")
                })
            );
            assert_eq!(pick.id(), ScreenId::Working);
        }
    }

    /// Every answer this screen can be handed takes it off the Busy frame and leaves
    /// something to do. A request answered by silence is a frozen panel, and that is the
    /// defect the whole request/answer contract exists to stop.
    #[test]
    fn every_answer_the_registry_can_receive_leaves_the_busy_frame() {
        type Case = (&'static str, fn() -> Answer);
        let cases: [Case; 5] = [
            ("listed", || Answer::Card(CardOutcome::Listed(listing(alloc::vec![])))),
            ("no card", || Answer::Card(CardOutcome::NoCard)),
            ("unreadable", || {
                Answer::Card(CardOutcome::Unreadable(String::from("the card is not FAT32")))
            }),
            ("pending", || Answer::Import(ImportOutcome::Pending(review(3, 1)))),
            ("refused", || Answer::Import(ImportOutcome::Refused(notice()))),
        ];
        for (what, make) in cases {
            for (w, h) in GEOMETRIES {
                let f = Fixture::new(w, h);
                let ctx = f.ctx();
                let mut s = MultisigListState::new(&wallet(0));
                tap(&mut s, &f, RegionId::MsImport);
                assert_eq!(s.id(), ScreenId::Working);
                let outcome = answer(&mut s, &f, make());
                let moved_on = !matches!(outcome.nav, Nav::Stay);
                assert!(
                    moved_on || !regions_of(&s, &ctx).is_empty(),
                    "{w}x{h} {what}: the panel is frozen - no screen change and nothing tappable"
                );
                // Whether it moved on or not, the screen it leaves behind is never a Busy
                // frame: that is the state a `Nav::Push` would remember and `Back` restore.
                assert_eq!(s.id(), ScreenId::MultisigList, "{w}x{h} {what}: still Busy");
                s.draw(&mut NullTarget, &ctx).expect("it renders");
            }
        }
    }

    /// A card band offers "Check again" beside the import: inserting the card is the whole
    /// remedy, and a user who has to navigate away to reach it will power-cycle instead.
    #[test]
    fn a_missing_card_offers_the_retry_beside_the_import() {
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            let ctx = f.ctx();
            let mut s = MultisigListState::new(&wallet(0));
            tap(&mut s, &f, RegionId::MsImport);
            answer(&mut s, &f, Answer::Card(CardOutcome::NoCard));
            let l = s.layout(&ctx);
            let refresh = l.refresh.expect("a card band offers Check again");
            let (rect, col) = l.band.as_ref().expect("and states what happened");
            assert!(col.prose().contains("No card detected"));
            rows_are_clear_on(
                &f.m,
                &format!("{w}x{h} no card"),
                f.m.body(),
                &[
                    ("viewport", l.viewport),
                    ("band", *rect),
                    ("capacity", l.capacity.expect("the registry states what it holds")),
                    ("refresh", refresh),
                    ("action", l.action),
                ],
            );
            column_fits(&format!("{w}x{h} no card"), col, *rect);
            assert!(has(&s, &ctx, RegionId::FileRefresh));
            assert_eq!(
                tap(&mut s, &f, RegionId::FileRefresh).request,
                Some(UiRequest::ListCard { dir: String::new(), filter: FileFilter::All })
            );
        }
    }

    // -----------------------------------------------------------------------------------
    // S-42 the import review
    // -----------------------------------------------------------------------------------

    /// Every page of the review lays out on both panels, at two cosigners and at the fifteen
    /// the device can hold, with every measured line inside the frame it is drawn in and
    /// every page reachable by scrolling.
    #[test]
    fn every_review_page_lays_out_on_both_panels() {
        for (w, h) in GEOMETRIES {
            for n in [2usize, 3, MAX_COSIGNERS] {
                let f = Fixture::new(w, h);
                let ctx = f.ctx();
                let mut s = MultisigImportState::new(review(n, 1));
                for page in 0..s.pages() {
                    s.go(page);
                    let l = s.layout(&ctx);
                    let what = format!("{w}x{h} review page {page} of {n} cosigners");

                    let mut rows = alloc::vec![
                        ("pager", l.pager),
                        ("viewport", l.viewport),
                        ("prev", l.prev),
                        ("next", l.next),
                    ];
                    if let Some(r) = l.notice {
                        rows.push(("notice", r));
                    }
                    if let Some((r, _)) = &l.reason {
                        rows.push(("reason", *r));
                    }
                    rows_are_clear_on(&f.m, &what, f.m.body(), &rows);
                    targets_are_reachable(&what, &f.m, &regions_of(&s, &ctx));
                    // Three mono lines is the floor for a screen whose job is to be READ.
                    assert!(
                        l.viewport.h >= 3 * SMALL_LINE,
                        "{what}: the content viewport is only {} px",
                        l.viewport.h
                    );

                    column_fits(&what, &l.body.col, l.viewport);
                    if let Some((rect, col)) = &l.body.note {
                        column_fits(&what, col, rect.inset(CARD_PAD));
                    }
                    if let Some(card) = &l.body.card {
                        let value = card.value_column();
                        for (fact, _) in &card.rows {
                            let mut col = Column::new(value.w);
                            col.mono(&fact.value, fact.ink);
                            column_fits(&what, &col, value);
                            fits(
                                &what,
                                fact.caption,
                                BODY.text_width(fact.caption) as i32,
                                card.rect,
                            );
                        }
                    }
                    assert!(
                        s.scroll_limit(&ctx) + l.viewport.h >= l.body.height,
                        "{what}: {} px of content in a {} px viewport with a {} px scroll",
                        l.body.height,
                        l.viewport.h,
                        s.scroll_limit(&ctx)
                    );
                    s.draw(&mut NullTarget, &ctx).expect("the page renders");
                }
            }
        }
    }

    /// Every cosigner key reaches the panel in full, and the one that is ours is marked as
    /// ours. Comparing these against the devices that hold them is the whole defence against
    /// a substituted key, so a value that arrives shortened defeats the screen.
    #[test]
    fn the_cosigner_pages_show_every_key_in_full() {
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            let ctx = f.ctx();
            let mut s = MultisigImportState::new(review(3, 2));
            for i in 0..3usize {
                s.go(i + 1);
                let l = s.layout(&ctx);
                let drawn: String = l.body.col.joined().chars().filter(|c| *c != ' ').collect();
                let c = &s.review.cosigners[i];
                assert!(drawn.contains(&c.xpub), "{w}x{h}: cosigner {i} xpub is not shown in full");
                assert!(drawn.contains(&c.fingerprint), "{w}x{h}: cosigner {i} fingerprint");
                assert!(drawn.contains(PATH), "{w}x{h}: cosigner {i} derivation path");
                let marked = l.body.col.prose().contains("THIS DEVICE");
                assert_eq!(marked, c.ours, "{w}x{h}: cosigner {i} is marked wrongly");
            }
            // ...and the address page shows the address in full, with the reason it matters.
            s.go(s.last());
            let l = s.layout(&ctx);
            let drawn: String = l.body.col.joined().chars().filter(|c| *c != ' ').collect();
            assert!(drawn.contains(ADDRESS), "{w}x{h}: the first address is not shown in full");
            assert!(
                l.body.col.prose().contains("Compare this address on your other signing devices"),
                "{w}x{h}: the address page does not say why the comparison matters"
            );
            assert!(drawn.contains("8zl0zxma"), "{w}x{h}: the descriptor checksum is not shown");
        }
    }

    /// Page one states which cosigner this device is, and names the fingerprint that makes
    /// the claim checkable.
    #[test]
    fn page_one_states_which_cosigner_this_device_is() {
        let f = Fixture::new(720, 720);
        let ctx = f.ctx();
        let s = MultisigImportState::new(review(3, 2));
        let l = s.layout(&ctx);
        let (_, note) = l.body.note.as_ref().expect("page one carries the membership card");
        let said = note.prose();
        assert!(said.contains("This device is cosigner 2 of 3"), "got {said:?}");
        assert!(said.contains("a1b2c301"), "the card does not name our fingerprint: {said:?}");
        assert!(said.contains("compare the first receive address"), "got {said:?}");
    }

    // -----------------------------------------------------------------------------------
    // S-43 the detail screen
    // -----------------------------------------------------------------------------------

    /// The detail screen lays out on both panels in every state it has.
    #[test]
    fn the_detail_screen_lays_out_on_both_panels() {
        for (w, h) in GEOMETRIES {
            for proven in [true, false] {
                for held in [true, false] {
                    let mut f = Fixture::new(w, h);
                    f.registrations = alloc::vec![info(2, proven)];
                    let ctx = f.ctx();
                    let mut s = if held {
                        MultisigDetailState::saved(info(2, proven), review(3, 1))
                    } else {
                        MultisigDetailState::stored(2)
                    };
                    for shown in [false, true] {
                        s.show_cosigners = shown;
                        let l = s.layout(&ctx);
                        let what =
                            format!("{w}x{h} detail proven={proven} held={held} all={shown}");
                        // The facts card and the fault card ride the scroll INSIDE the
                        // viewport, so they are measured against it rather than against the
                        // pinned rectangles they are allowed to pass under.
                        if let Some(c) = &l.card {
                            assert_eq!(c.rect.w, l.viewport.w, "{what}: the card is not the column");
                            let value = c.value_column();
                            for (fact, _) in &c.rows {
                                let mut col = Column::new(value.w);
                                col.mono(&fact.value, fact.ink);
                                column_fits(&what, &col, value);
                            }
                        }
                        if let Some((r, col)) = &l.fault {
                            assert_eq!(r.w, l.viewport.w);
                            column_fits(&what, col, r.inset(CARD_PAD));
                        }
                        let mut rows = alloc::vec![("viewport", l.viewport)];
                        if let Some(r) = l.address_toggle {
                            rows.push(("address toggle", r));
                        }
                        if let Some(r) = l.cosigner_toggle {
                            rows.push(("cosigner toggle", r));
                        }
                        if let Some((r, _)) = &l.band {
                            rows.push(("band", *r));
                        }
                        if let Some(r) = l.delete {
                            rows.push(("delete", r));
                        }
                        rows_are_clear_on(&f.m, &what, f.m.body(), &rows);
                        targets_are_reachable(&what, &f.m, &regions_of(&s, &ctx));
                        column_fits(&what, &l.content, l.viewport);
                        if let Some((rect, col)) = &l.band {
                            column_fits(&what, col, *rect);
                        }
                        assert!(
                            l.viewport.h >= 3 * SMALL_LINE,
                            "{what}: the viewport is only {} px",
                            l.viewport.h
                        );
                        assert!(
                            s.scroll_limit(&ctx) + l.viewport.h >= l.height,
                            "{what}: the content cannot be scrolled to its end"
                        );
                        s.draw(&mut NullTarget, &ctx).expect("the detail screen renders");
                    }
                }
            }
        }
    }

    /// Approving an import lands on the detail screen with the first address ALREADY
    /// showing, because that is the moment the cross-check is worth something.
    #[test]
    fn a_saved_registration_opens_on_its_first_address() {
        let mut f = Fixture::new(720, 720);
        f.registrations = alloc::vec![info(2, true)];
        let ctx = f.ctx();
        let mut s = MultisigImportState::new(review(3, 1));
        for _ in 0..s.last() {
            tap(&mut s, &f, RegionId::ReviewNext);
        }
        tap(&mut s, &f, RegionId::MsApprove);
        let outcome =
            answer(&mut s, &f, Answer::Register(RegistrationOutcome::Saved(info(2, true))));
        let Nav::Enter(State::MultisigDetail(detail)) = outcome.nav else {
            panic!("a saved registration must open its detail screen");
        };
        assert!(detail.show_address, "the cross-check is not on screen");
        let l = detail.layout(&ctx);
        let shown = l.content.prose();
        let compact: String = l.content.joined().chars().filter(|c| *c != ' ').collect();
        assert!(compact.contains(ADDRESS), "the first address is not shown in full");
        assert!(shown.contains("Compare this address"), "and does not say why it matters");
        assert!(
            detail
                .layout(&ctx)
                .band
                .map(|(_, c)| c.prose().contains("Compare the first receive address"))
                .unwrap_or(false),
            "the save is not confirmed with the instruction that follows it"
        );
    }

    /// An unreadable slot is drawn as one, offers exactly one action, and that action is the
    /// remedy its own row states.
    #[test]
    fn an_unreadable_slot_offers_only_the_delete() {
        for (w, h) in GEOMETRIES {
            let mut f = Fixture::new(w, h);
            f.registrations = alloc::vec![info(5, false)];
            let ctx = f.ctx();
            let mut s = MultisigDetailState::stored(5);
            let ids: Vec<RegionId> = regions_of(&s, &ctx).iter().map(|r| r.id).collect();
            assert!(
                ids.contains(&RegionId::MsDelete),
                "{w}x{h}: an unreadable slot cannot be erased"
            );
            assert!(!ids.contains(&RegionId::MsCosigners), "{w}x{h}: it has no cosigners to show");
            assert!(
                !ids.contains(&RegionId::MsFirstAddress),
                "{w}x{h}: it has no address to derive"
            );
            let l = s.layout(&ctx);
            assert!(l.fault.is_some(), "{w}x{h}: an unreadable slot renders as a normal one");
            assert!(l.content.prose().contains("did not prove out"));

            // The sheet is C4d, and the word is one the user can read off this screen.
            tap(&mut s, &f, RegionId::MsDelete);
            let d = s.danger.as_ref().expect("delete opens a sheet");
            assert_eq!(d.grade(), DangerGrade::Confirm, "{w}x{h}: the consequence comes first");
            assert!(d.fits(&f.m), "{w}x{h}: the consequence sheet's copy does not fit");
            tap(&mut s, &f, RegionId::DangerConfirm);
            let d = s.danger.as_ref().expect("and then the typed step");
            assert_eq!(d.grade(), DangerGrade::Typed, "{w}x{h}: delete is not a typed-name sheet");
            assert!(d.fits(&f.m), "{w}x{h}: the typed sheet's copy does not fit");
            // While it is open, nothing else on the panel is.
            let sheet: Vec<RegionId> = regions_of(&s, &ctx).iter().map(|r| r.id).collect();
            assert!(
                !sheet.contains(&RegionId::MsDelete),
                "{w}x{h}: the screen is live under the sheet"
            );
        }
    }

    /// A registration the registry no longer holds says so instead of rendering a stale
    /// copy. The screen reads its row out of the registry every frame, so a delete that
    /// landed - or a lock that cleared the session - is visible immediately.
    #[test]
    fn a_registration_that_is_gone_says_so() {
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            let ctx = f.ctx();
            let s = MultisigDetailState::saved(info(2, true), review(3, 1));
            let l = s.layout(&ctx);
            assert!(l.card.is_none(), "{w}x{h}: facts drawn for a registration that is not there");
            assert!(l.fault.is_some(), "{w}x{h}: and it says so");
            assert!(l.delete.is_none(), "{w}x{h}: a delete offered for nothing");
            assert!(l.content.prose().contains("no longer on the device"));
            let ids: Vec<RegionId> = regions_of(&s, &ctx).iter().map(|r| r.id).collect();
            assert_eq!(ids, alloc::vec![RegionId::Back], "{w}x{h}: the only way out is Back");
            s.draw(&mut NullTarget, &ctx).expect("it renders");
        }
    }

    /// A delete that did not happen is stated, not swallowed. The alternative is a user who
    /// believes a registration is gone while the device still holds it.
    #[test]
    fn a_refused_delete_is_stated_and_an_erased_slot_returns_to_the_registry() {
        let mut f = Fixture::new(720, 720);
        f.registrations = alloc::vec![info(2, true)];
        let ctx = f.ctx();
        let mut s = MultisigDetailState::saved(info(2, true), review(3, 1));
        // C4b first - the consequence, on a sheet with room for it - then C4d.
        tap(&mut s, &f, RegionId::MsDelete);
        assert_eq!(s.danger.as_ref().map(Danger::grade), Some(DangerGrade::Confirm));
        assert!(s.danger.as_ref().unwrap().fits(&f.m), "the consequence sheet does not fit");
        let outcome = tap(&mut s, &f, RegionId::DangerConfirm);
        assert!(outcome.request.is_none(), "reading the consequence must not erase anything");
        assert_eq!(s.danger.as_ref().map(Danger::grade), Some(DangerGrade::Typed));
        // Type the name back, which is what arms a C4d sheet.
        for c in "vault 2".chars() {
            if c == ' ' {
                tap(&mut s, &f, RegionId::Space);
            } else {
                tap(&mut s, &f, RegionId::Key(c));
            }
        }
        let outcome = tap(&mut s, &f, RegionId::DangerConfirm);
        assert_eq!(outcome.request, Some(UiRequest::DeleteRegistration(2)));
        assert_eq!(s.id(), ScreenId::Working);
        assert!(regions_of(&s, &ctx).is_empty(), "a Busy frame is tappable");

        let outcome = answer(&mut s, &f, Answer::DeleteRegistration(false));
        assert!(matches!(outcome.nav, Nav::Stay), "a refused delete must not leave the screen");
        assert_eq!(s.id(), ScreenId::MultisigDetail, "and must leave the Busy frame");
        assert!(
            s.layout(&ctx).band.map(|(_, c)| c.prose().contains("NOT erased")).unwrap_or(false),
            "and must say so"
        );

        // ...and a delete that DID happen goes back to the registry.
        let outcome = answer(&mut s, &f, Answer::DeleteRegistration(true));
        assert!(matches!(outcome.nav, Nav::Back), "an erased slot returns to the registry");
    }

    /// The two disclosures are toggles, and they show what they promise.
    #[test]
    fn the_detail_disclosures_show_what_their_labels_promise() {
        let mut f = Fixture::new(800, 480);
        f.registrations = alloc::vec![info(2, true)];
        let ctx = f.ctx();
        let s = MultisigDetailState::stored(2);
        // Without the review there is nothing to disclose, and no control claims otherwise.
        assert!(!has(&s, &ctx, RegionId::MsCosigners));
        assert!(s.layout(&ctx).content.prose().contains("not in memory"));

        let mut s = MultisigDetailState::saved(info(2, true), review(3, 2));
        tap(&mut s, &f, RegionId::MsCosigners);
        let l = s.layout(&ctx);
        let compact: String = l.content.joined().chars().filter(|c| *c != ' ').collect();
        for xpub in XPUBS {
            assert!(compact.contains(xpub), "a disclosed cosigner list must be complete");
        }
        assert!(l.content.prose().contains("THIS DEVICE"), "and must mark this device's own key");
        tap(&mut s, &f, RegionId::MsCosigners);
        assert!(!s.layout(&ctx).content.prose().contains("THIS DEVICE"), "the toggle toggles");
    }

    /// The C4d sheet asks for something the user can actually type.
    ///
    /// A name from a file can be 200 characters of anything. The sheet caps the typed field
    /// at the length of the word it requires, so a word nobody can finish typing is a
    /// registration nobody can delete - which fills the registry with slots that cannot be
    /// cleared, and then refuses the next import for want of a free one.
    #[test]
    fn the_delete_sheet_asks_for_something_the_user_can_type() {
        assert_eq!(typed_word("vault 2of3", 3), "vault 2of3");
        assert_eq!(typed_word("", 3), "3", "a blank name falls back to the slot");
        assert_eq!(typed_word("   ", 3), "3", "and so does whitespace");
        let long: String = core::iter::repeat_n('v', 200).collect();
        assert_eq!(typed_word(&long, 7), "7", "an untypeable name falls back to the slot");
        for c in typed_word("vault \u{0448}", 1).chars() {
            assert!(in_atlas(c), "the required word must be drawable and typeable");
        }
    }

    // -----------------------------------------------------------------------------------
    // Small pieces
    // -----------------------------------------------------------------------------------

    #[test]
    fn a_descriptor_checksum_is_read_only_when_it_is_one() {
        assert_eq!(descriptor_checksum("wsh(sortedmulti(2,a,b))#8zl0zxma"), Some("8zl0zxma"));
        assert_eq!(descriptor_checksum("wsh(sortedmulti(2,a,b))"), None);
        assert_eq!(descriptor_checksum("wsh(...)#short"), None);
        assert_eq!(descriptor_checksum("wsh(...)#with spc"), None);
    }

    #[test]
    fn chunking_groups_without_losing_a_character() {
        let grouped = chunked(ADDRESS, 4);
        let back: String = grouped.chars().filter(|c| *c != ' ').collect();
        assert_eq!(back, ADDRESS, "chunking must not lose or add a character");
        assert!(grouped.contains(' '), "and must actually group");
    }

    /// A column's height is the wrap it will actually draw, measured at the last line's
    /// glyph box rather than at its advance - a box drawn at the advance crosses the
    /// descenders of the closing sentence.
    #[test]
    fn a_column_measures_what_it_draws() {
        let mut col = Column::new(300);
        col.heading("A heading that is long enough to wrap onto a second line", INK_PRIMARY);
        col.body("And a body sentence under it.", INK_SECONDARY);
        let drawn = col.measured();
        assert!(drawn.len() >= 3, "the sample must actually wrap");
        let advances: i32 = col.lines.iter().map(|l| l.advance).sum();
        assert!(col.height() >= advances, "the box must cover the last line's descenders");
        for (line, need) in drawn {
            assert!(need <= 300, "{line:?} is {need} px in a 300 px column");
        }
    }
}
