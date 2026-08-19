// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! S-14 word entry: typing a seed the user already has.
//!
//! The keyboard, the well showing what has been typed, the completion strip and the
//! checksum verdict. This is the restore flow's front door and the only seed-import path
//! 0.2.0 needs (R26); the same screen serves "verify an existing seed", because typing
//! twelve words and checking them is the same act either way.
//!
//! # Three things the screen does that a plain text field would not
//!
//! - **It counts.** The status line says which word is being typed and how many the seed
//!   will have, so a user copying from paper knows where they are without counting the
//!   well.
//!
//! - **It finishes the phrase.** At 11, 14, 17, 20 or 23 words the last word is almost
//!   entirely determined - it carries a few entropy bits and the whole checksum - so the
//!   strip stops offering prefix completions and starts offering the words that would
//!   actually CHECK ([`bip39::valid_last_words`]). A user whose backup has one smudged
//!   word gets a short list instead of a 2048-word search. Where the list is longer than
//!   the strip, [`RegionId::SuggestMore`] opens all of it.
//!
//! - **It refuses.** The checksum is ENFORCED here rather than reported: Done stays
//!   disabled until the words are a real seed, and the reason says which failure it is -
//!   an unknown word, a word count that no seed has, or a checksum that does not hold.
//!   "Invalid" alone would send a user hunting through twelve correct words. This is the
//!   one deliberate departure from the desktop's advisory-only rule, and it is a
//!   departure the desktop's own reasoning supports: the desktop derives from anything
//!   because a researcher may want to, and this device is being handed a backup to
//!   restore.
//!
//! The typed phrase is shown UNMASKED. It is the user's own input, arriving from their
//! eyes and fingers, and an unseen typo silently restores a different wallet - the worse
//! failure, and the same reasoning as the passphrase reveal toggle. The completion strip
//! offers only public wordlist entries against what the user is typing, which is why it
//! can exist here and nowhere near a derived value.

use alloc::string::String;
use alloc::vec::Vec;

use embedded_graphics::draw_target::{DrawTarget, DrawTargetExt};
use embedded_graphics::pixelcolor::Rgb565;
use zeroize::{Zeroize, Zeroizing};

use crate::canvas::{button, fill, frame, panel, text, text_centered, ButtonKind, BODY, MONO_SMALL};
use crate::components::{
    back_rect, draw_bar, draw_bar_no_back, draw_keyboard, keyboard, keyboard_min_h, LINE,
    SMALL_LINE,
};
use crate::layout::Rect;
use crate::screens::deriving::SeedSource;
use crate::screens::passphrase::PassState;
use crate::screens::{Ctx, Env, Outcome, Screen, State};
use crate::theme::*;
use crate::{secret_buf, Page, Region, RegionId, PHRASE_MAX};
use notyas_core::bip39::{
    self, current_word_fragment, valid_last_words, words_with_prefix, Checksum, FIXED_WORD_COUNTS,
};

pub(crate) struct PhraseState {
    pub text: Zeroizing<String>,
    page: Page,
    /// The full candidate list is open over the screen, and how far it is scrolled.
    ///
    /// `Option<i32>` rather than a bool plus an offset: a scroll position that exists
    /// while the sheet is closed is a state with no meaning, and reopening the sheet
    /// should always start at the top of the list.
    more: Option<i32>,
}

impl PhraseState {
    pub fn new() -> PhraseState {
        PhraseState { text: secret_buf(PHRASE_MAX), page: Page::Lower, more: None }
    }
}

pub(crate) struct Layout {
    /// Tail view of the typed phrase. The FLEXIBLE element of this screen: everything
    /// below it is a physical minimum, so the well absorbs whatever the panel has left
    /// (three lines at 720x720, one at 800x480).
    well: Rect,
    status_y: i32,
    /// Always-reserved band for the completion chips, so the keyboard cannot jump under a
    /// finger when suggestions appear or disappear. It doubles as the hint row: when there
    /// is nothing to offer there is usually something to say, and saying it here costs no
    /// layout.
    strip: Rect,
    kb: Rect,
}

/// Height of the suggestion strip, and therefore of a completion chip. A physical floor
/// like [`crate::layout::DICE_KEY_MIN`] - fingers do not scale with the panel; 60 px is
/// ~6.7 mm on the 229 PPI primary panel.
const SUGGEST_H: i32 = 60;
/// Gap between chips (tighter than `Metrics::gap` so four chips keep their width on the
/// narrower body).
const SUGGEST_GAP: i32 = 8;
/// Chips the strip shows at once. The strip is ONE row, not a stack: five stacked 60 px
/// rows (300 px) do not exist on the 800x480 panel, whose whole body is 377 px and whose
/// keyboard alone needs 184. Four is what fits side by side at the 8-character worst case
/// of the wordlist on the narrower of the two shipped geometries.
const MAX_SUGGEST: usize = 4;
/// Vertical padding inside the phrase well (8 px above and below the text lines).
const WELL_PAD: i32 = 16;

/// The candidates the strip is offering, in the order it offers them.
///
/// TWO different lists, and which one this is depends on how much has been typed:
///
/// - one word short of a supported seed length, the checksum pins the last word to a small
///   set (128 words for a 12-word seed, 8 for a 24-word one), so the strip offers THAT set
///   narrowed by whatever prefix has been typed. This is the final-word helper.
/// - otherwise, plain wordlist completions of the word in progress.
///
/// Single source of truth for the strip and the sheet behind it - `regions` hit-tests it,
/// `draw` paints it, and `activate` indexes it - so a chip can never resolve to a
/// different word than the one under the finger.
///
/// Empty while no word is in progress and nothing is determined, and empty when the
/// fragment is already the only word it can be: there is nothing left to complete, and the
/// strip yields the row to the verdict.
fn candidates(text: &str) -> Vec<&'static str> {
    let fragment = current_word_fragment(text);
    let head = &text[..text.len() - fragment.len()];
    let determined = valid_last_words(head);
    if !determined.is_empty() {
        return determined.into_iter().filter(|w| starts_with_folded(w, fragment)).collect();
    }
    let words = words_with_prefix(fragment, MAX_SUGGEST);
    if words.len() == 1 && words[0] == fragment {
        return Vec::new();
    }
    words
}

/// Case-insensitive prefix test that allocates nothing.
///
/// The prefix is a slice of the user's phrase; a lowercase heap copy of part of a phrase
/// would be one more buffer to wipe. Folding the PREFIX rather than the word is exact
/// because every wordlist entry is ASCII a-z (build.rs verifies the list) - the same
/// reasoning `bip39::words_with_prefix` uses.
fn starts_with_folded(word: &str, prefix: &str) -> bool {
    word.len() >= prefix.len()
        && word.bytes().zip(prefix.bytes()).all(|(w, p)| w == p.to_ascii_lowercase())
}

/// Chip `i` of the strip. Chips keep a fixed width whatever the match count is, so the row
/// does not reflow letter by letter as the user types.
fn suggest_chip(strip: Rect, i: usize) -> Rect {
    let n = MAX_SUGGEST as i32;
    let w = (strip.w - (n - 1) * SUGGEST_GAP) / n;
    Rect::new(strip.x + i as i32 * (w + SUGGEST_GAP), strip.y, w, strip.h)
}

/// How many of the candidates the strip itself shows.
///
/// One slot goes to the "+N more" affordance whenever there are more than fit, so the
/// count is always honest about what is being withheld - a strip that silently showed the
/// first four of 128 would be a worse helper than none.
fn chips_shown(total: usize) -> usize {
    if total > MAX_SUGGEST {
        MAX_SUGGEST - 1
    } else {
        total
    }
}

/// Lines of the phrase the well can show at the height it was given.
fn well_lines(well: Rect) -> usize {
    ((well.h - WELL_PAD) / SMALL_LINE).max(1) as usize
}

/// Where the user is: which word they are typing, and how long the seed will be.
///
/// `None` for a phrase already past the longest seed there is - there is no target left to
/// count towards, and the screen says so instead of naming one.
fn position(text: &str) -> (usize, Option<usize>) {
    let typed = text.split_whitespace().count();
    // A fragment in progress IS the word being typed; with none, the next word is next.
    let at = if current_word_fragment(text).is_empty() { typed + 1 } else { typed };
    (at, FIXED_WORD_COUNTS.iter().copied().find(|&n| n >= at))
}

/// The verdict on what has been typed, as the status line states it and as Done reads it.
///
/// One enum rather than a bag of booleans, so "Done is enabled" and "the line says it is
/// fine" cannot disagree: both are this value.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// Nothing typed yet.
    Empty,
    /// Still being typed: word `at` of `of`.
    Typing { at: usize, of: usize },
    /// Words the list does not have. `unknown` of `words`.
    Unknown { words: usize, unknown: usize },
    /// A word count no seed has, and nothing in progress to make it one.
    BadCount { words: usize },
    /// Every word known, the count right, and the checksum wrong.
    BadChecksum { words: usize },
    /// A real seed.
    Valid { words: usize },
}

impl Verdict {
    fn of(text: &str) -> Verdict {
        // Read twice, because "is that word wrong" and "is this phrase a seed" are asked
        // of different strings. A word still under the finger is not a wrong word - it is
        // three keystrokes from a right one - so the UNKNOWN complaint is judged on the
        // completed words only. The checksum is judged on everything typed, because the
        // last word of a finished phrase is not usually followed by a space.
        let fragment = current_word_fragment(text);
        let head = &text[..text.len() - fragment.len()];
        let completed = bip39::check_phrase(&bip39::normalize_phrase(head));
        let all = bip39::check_phrase(&bip39::normalize_phrase(text));

        if !completed.unknown_words.is_empty() {
            return Verdict::Unknown {
                words: completed.word_count,
                unknown: completed.unknown_words.len(),
            };
        }
        if all.unknown_words.is_empty() && FIXED_WORD_COUNTS.contains(&all.word_count) {
            return match all.checksum {
                Checksum::Valid => Verdict::Valid { words: all.word_count },
                _ => Verdict::BadChecksum { words: all.word_count },
            };
        }
        if all.word_count == 0 {
            return Verdict::Empty;
        }
        // Past the shortest seed there is, an unsupported count with nothing in progress
        // is far more likely a finished phrase that is wrong than a phrase still growing,
        // so it is reported as the error rather than counted towards a length the user may
        // not be heading for.
        let settled = fragment.is_empty() && all.word_count >= FIXED_WORD_COUNTS[0];
        let (at, of) = position(text);
        match of {
            Some(of) if !settled => Verdict::Typing { at, of },
            _ => Verdict::BadCount { words: all.word_count },
        }
    }

    /// Whether this phrase may be handed on. The checksum gate, in one place.
    fn done(self) -> bool {
        matches!(self, Verdict::Valid { .. })
    }

    /// The status line under the well: where the user is, or what is wrong. One line by
    /// construction - the layout reserves exactly one and the copy test holds it there.
    fn line(self) -> (String, Rgb565) {
        match self {
            Verdict::Empty => (String::from("Type your seed words"), INK_MUTED),
            Verdict::Typing { at, of } if at == of => {
                (format!("word {at} of {of} - last word"), INK_SECONDARY)
            }
            Verdict::Typing { at, of } => (format!("word {at} of {of}"), INK_SECONDARY),
            Verdict::Unknown { words, unknown } => {
                (format!("{unknown} of {words} words are not in the list"), WARNING)
            }
            Verdict::BadCount { .. } => {
                (String::from("A seed is 12, 15, 18, 21 or 24 words."), WARNING)
            }
            Verdict::BadChecksum { words } => {
                (format!("These {words} words do not form a valid seed."), DANGER)
            }
            Verdict::Valid { words } => (format!("{words} words - checksum valid"), SUCCESS),
        }
    }

    /// What to do about it, shown in the strip row when there are no chips to put there.
    /// Kept separate from the line above because the two are read at different moments:
    /// one says what happened, the other says what to try.
    fn hint(self) -> Option<String> {
        match self {
            Verdict::BadCount { words } => Some(format!("You have {words}.")),
            Verdict::BadChecksum { .. } => {
                Some(String::from("Check the last word and each spelling."))
            }
            _ => None,
        }
    }
}

impl Screen for PhraseState {
    type Layout = Layout;

    /// Laid out from the bottom up. The keyboard floor and the chip height are physical
    /// minimums; the status line is one line; the well takes what remains, capped at the
    /// three lines it wants and floored at one. On the 800x480 panel this budget is exact
    /// to a few pixels, which is why the well - not the keyboard - is the part that gives
    /// (the layout tests pin both ends of it).
    fn layout(&self, ctx: &Ctx) -> Layout {
        let m = &ctx.m;
        let body = m.body();
        let g = m.gap;
        let spare = body.h - keyboard_min_h() - SUGGEST_H - LINE - 3 * g;
        let well_h = spare.clamp(SMALL_LINE + WELL_PAD, 3 * SMALL_LINE + WELL_PAD);
        let well = Rect::new(body.x, body.y, body.w, well_h);
        let status_y = well.bottom() + g;
        let strip = Rect::new(body.x, status_y + LINE + g, body.w, SUGGEST_H);
        let kb_top = strip.bottom() + g;
        Layout {
            well,
            status_y,
            strip,
            kb: Rect::new(body.x, kb_top, body.w, body.bottom() - kb_top),
        }
    }

    fn regions(&self, ctx: &Ctx, out: &mut Vec<Region>) {
        let all = candidates(&self.text);
        // The full-list sheet is modal: while it is open it is the only thing on the panel
        // a finger can reach, exactly as it is the only thing visible.
        if let Some(scroll) = self.more {
            let sheet = sheet_layout(ctx, all.len());
            out.push(Region { id: RegionId::SuggestClose, rect: sheet.close });
            for (i, rect) in sheet.visible(scroll) {
                out.push(Region { id: RegionId::Suggest(i as u8), rect });
            }
            return;
        }
        let l = self.layout(ctx);
        out.push(Region { id: RegionId::Back, rect: back_rect(&ctx.m) });
        let shown = chips_shown(all.len());
        for i in 0..shown {
            out.push(Region { id: RegionId::Suggest(i as u8), rect: suggest_chip(l.strip, i) });
        }
        if all.len() > MAX_SUGGEST {
            out.push(Region { id: RegionId::SuggestMore, rect: suggest_chip(l.strip, shown) });
        }
        for k in keyboard(l.kb, self.page) {
            out.push(Region { id: k.id, rect: k.rect });
        }
    }

    fn draw<D: DrawTarget<Color = Rgb565>>(&self, t: &mut D, ctx: &Ctx) -> Result<(), D::Error> {
        let m = &ctx.m;
        let all = candidates(&self.text);
        if let Some(scroll) = self.more {
            return draw_sheet(t, ctx, &all, scroll);
        }
        draw_bar(t, m, "Seed words")?;
        let l = self.layout(ctx);

        // The typed phrase, UNMASKED (see the module docs), word by word so that a word the
        // list does not have can be inked `DANGER` where the user can see WHICH one it is.
        panel(t, l.well, PAPER_3, BORDER_STRONG)?;
        let inner = l.well.inset(8);
        let adv = MONO_SMALL.glyph('m').advance as i32;
        let columns = (inner.w / adv).max(1) as usize;
        // The phrase is shown unmasked by design, but its per-frame heap copies still obey
        // the hygiene rule: the drop guard wipes them on every exit path, including the `?`
        // returns inside the draw loop below.
        let tmp = WellTemps { lines: wrap_words_in_columns(&self.text, columns) };
        let visible = tmp.lines.len().min(well_lines(l.well));
        let mut caret = (inner.x, inner.y);
        for (row, line) in tmp.lines[tmp.lines.len() - visible..].iter().enumerate() {
            let y = inner.y + row as i32 * SMALL_LINE;
            let mut pen = inner.x;
            for word in line {
                let ink = if word.known { INK_PRIMARY } else { DANGER };
                pen = text(t, &word.text, pen, y, MONO_SMALL, ink, PAPER_3)?;
            }
            caret = (pen, y);
        }

        // Caret: a short bar after the last character, so it is obvious where the next
        // keypress lands. Static, not blinking - the panel repaints on input only, and a
        // caret that needed a timer would be a lie about how this screen works.
        fill(t, Rect::new(caret.0, caret.1 + SMALL_LINE - 4, 2, 3), ACCENT)?;
        drop(tmp);

        let verdict = Verdict::of(&self.text);
        let (line, ink) = verdict.line();
        text(t, &line, l.well.x, l.status_y, BODY, ink, PAPER_1)?;

        // The strip: chips if there is anything to offer, otherwise whatever the verdict
        // wants said. Cobalt-on-tint, the crate's "interactive" grammar, so the chips read
        // as buttons rather than as part of the phrase; each label is pixel-clipped to its
        // chip for the same reason the masked field is - a wide word must crop, never bleed
        // into the neighbouring target.
        let shown = chips_shown(all.len());
        for (i, word) in all.iter().take(shown).enumerate() {
            draw_chip(t, suggest_chip(l.strip, i), word)?;
        }
        if all.len() > MAX_SUGGEST {
            let label = format!("+{} more", all.len() - shown);
            button(t, suggest_chip(l.strip, shown), &label, ButtonKind::Secondary, PAPER_1)?;
        } else if shown == 0 {
            if let Some(hint) = verdict.hint() {
                text(t, &hint, l.strip.x, l.strip.y + 8, BODY, INK_SECONDARY, PAPER_1)?;
            } else if !current_word_fragment(&self.text).is_empty() {
                // A fragment nothing in the list starts with. Said plainly, and said here
                // rather than in the status line, which is busy counting words.
                text(t, "Not a BIP-39 word.", l.strip.x, l.strip.y + 8, BODY, WARNING, PAPER_1)?;
            }
        }

        draw_keyboard(t, l.kb, self.page, verdict.done())?;
        Ok(())
    }

    fn activate(&mut self, id: RegionId, _env: &mut Env) -> Outcome {
        match id {
            RegionId::Key(c) => {
                if self.text.len() < PHRASE_MAX {
                    self.text.push(c);
                }
                Outcome::stay()
            }
            RegionId::Space => {
                if self.text.len() < PHRASE_MAX {
                    self.text.push(' ');
                }
                Outcome::stay()
            }
            RegionId::KeyBackspace => {
                self.text.pop();
                Outcome::stay()
            }
            // Completing a word: replace the fragment being typed with the chosen word and
            // append the separating space, so the next word can be typed straight away.
            // The list comes from `candidates` - the same call the strip drew and `regions`
            // hit-tested - so index `i` cannot resolve to a different word than the one
            // under the finger.
            RegionId::Suggest(i) => {
                if let Some(word) = candidates(&self.text).get(i as usize) {
                    let keep = self.text.len() - current_word_fragment(&self.text).len();
                    self.text.truncate(keep);
                    // The truncate freed at least one byte per fragment character, so this
                    // only declines at a phrase that was already at the cap. (`+ 1` is the
                    // separating space, folded into the comparison.)
                    if self.text.len() + word.len() < PHRASE_MAX {
                        self.text.push_str(word);
                        self.text.push(' ');
                    }
                }
                // Choosing from the sheet closes it: the user came for one word and has it.
                self.more = None;
                Outcome::stay()
            }
            RegionId::SuggestMore => {
                self.more = Some(0);
                Outcome::stay()
            }
            RegionId::SuggestClose => {
                self.more = None;
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
            // The checksum gate. Done is drawn disabled until the words are a real seed and
            // the status line says which failure is in the way, so this is the interlock
            // rather than the message.
            RegionId::KeyDone if Verdict::of(&self.text).done() => {
                let normalized = bip39::normalize_phrase(&self.text);
                Outcome::push(State::Passphrase(PassState::new(SeedSource::Phrase(normalized))))
            }
            _ => Outcome::stay(),
        }
    }

    fn scroll_mut(&mut self) -> Option<&mut i32> {
        self.more.as_mut()
    }

    fn scroll_limit(&self, ctx: &Ctx) -> i32 {
        match self.more {
            Some(_) => sheet_layout(ctx, candidates(&self.text).len()).scroll_limit(),
            None => 0,
        }
    }
}

// ---------------------------------------------------------------------------------------
// The well
// ---------------------------------------------------------------------------------------

/// One word as the well draws it: the characters, and whether the list has it.
struct WellWord {
    text: String,
    known: bool,
}

/// Wrap the typed phrase into lines of at most `columns` mono cells, word by word.
///
/// The well shows the phrase whitespace-NORMALIZED - single spaces, no leading run -
/// because that is the string the seed is actually derived from
/// ([`bip39::normalize_phrase`]), so nothing the user can see is discarded by showing it
/// this way. A word longer than a line is hard-split rather than clipped: the user needs
/// to see every character they typed, especially the ones that made it too long.
fn wrap_words_in_columns(text: &str, columns: usize) -> Vec<Vec<WellWord>> {
    let list = bip39::wordlist();
    let mut lines: Vec<Vec<WellWord>> = Vec::new();
    let mut line: Vec<WellWord> = Vec::new();
    let mut used = 0usize;
    for (i, word) in text.split_whitespace().enumerate() {
        let known = list
            .binary_search_by(|probe| {
                let mut probe = probe.bytes();
                let mut w = word.bytes().map(|b| b.to_ascii_lowercase());
                loop {
                    match (probe.next(), w.next()) {
                        (Some(a), Some(b)) if a == b => continue,
                        (Some(a), Some(b)) => return a.cmp(&b),
                        (rest, other) => return rest.is_some().cmp(&other.is_some()),
                    }
                }
            })
            .is_ok();
        let lead = usize::from(i > 0 && !line.is_empty());
        if used + lead + word.chars().count() > columns && !line.is_empty() {
            lines.push(core::mem::take(&mut line));
            used = 0;
        }
        let mut text = String::with_capacity(word.len() + 1);
        if !line.is_empty() {
            text.push(' ');
        }
        text.push_str(word);
        used += text.chars().count();
        line.push(WellWord { text, known });
    }
    // A trailing space is a word boundary the user typed and the caret sits after it.
    if text.ends_with(char::is_whitespace) && !text.is_empty() {
        if used + 1 > columns {
            lines.push(core::mem::take(&mut line));
        }
        line.push(WellWord { text: String::from(" "), known: true });
    }
    lines.push(line);
    lines
}

/// Per-frame copies of the typed phrase, wiped on drop. `draw` can leave early through `?`
/// on any draw error; owning the temporaries in a drop guard means no exit path - early or
/// normal - strands unwiped secret bytes in freed allocations.
struct WellTemps {
    lines: Vec<Vec<WellWord>>,
}

impl Drop for WellTemps {
    fn drop(&mut self) {
        for line in &mut self.lines {
            for word in line {
                word.text.zeroize();
            }
        }
    }
}

// ---------------------------------------------------------------------------------------
// The full-candidate sheet
// ---------------------------------------------------------------------------------------

/// Geometry of the "+N more" sheet: a scrolling grid of every candidate.
///
/// It exists because the final-word helper can offer 128 words and the strip has four
/// slots. A list that silently showed the first four would be a worse helper than none -
/// the word the user is missing is as likely to be the ninetieth as the first.
struct Sheet {
    grid: Rect,
    close: Rect,
    columns: usize,
    cell_w: i32,
    total: usize,
}

const SHEET_GAP: i32 = 8;

fn sheet_layout(ctx: &Ctx, total: usize) -> Sheet {
    let m = &ctx.m;
    let body = m.body();
    let close = Rect::new(body.right() - 200.min(body.w), body.bottom() - m.btn, 200.min(body.w), m.btn);
    let grid = Rect::new(body.x, body.y, body.w, close.y - m.gap - body.y);
    // Wide enough for the longest wordlist entry in the mono face, and never fewer than
    // two columns: a one-column list of 128 words is a scroll, not a list.
    let min_w = MONO_SMALL.glyph('m').advance as i32 * 10;
    let columns = ((grid.w + SHEET_GAP) / (min_w + SHEET_GAP)).clamp(2, 6) as usize;
    let cell_w = (grid.w - (columns as i32 - 1) * SHEET_GAP) / columns as i32;
    Sheet { grid, close, columns, cell_w, total }
}

impl Sheet {
    fn row_h(&self) -> i32 {
        SUGGEST_H + SHEET_GAP
    }

    fn rows(&self) -> usize {
        self.total.div_ceil(self.columns.max(1))
    }

    fn scroll_limit(&self) -> i32 {
        (self.rows() as i32 * self.row_h() - self.grid.h).max(0)
    }

    /// Cell `i` at scroll offset `scroll`, in panel coordinates.
    fn cell(&self, i: usize, scroll: i32) -> Rect {
        let (row, col) = (i / self.columns, i % self.columns);
        Rect::new(
            self.grid.x + col as i32 * (self.cell_w + SHEET_GAP),
            self.grid.y + row as i32 * self.row_h() - scroll,
            self.cell_w,
            SUGGEST_H,
        )
    }

    /// The cells wholly inside the viewport. A chip half off the top is not offered: a
    /// target the user cannot see all of is a target they cannot judge.
    fn visible(&self, scroll: i32) -> Vec<(usize, Rect)> {
        (0..self.total)
            .map(|i| (i, self.cell(i, scroll)))
            .filter(|(_, r)| r.y >= self.grid.y && r.bottom() <= self.grid.bottom())
            .collect()
    }
}

fn draw_chip<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    chip: Rect,
    word: &str,
) -> Result<(), D::Error> {
    fill(t, chip, ACCENT_TINT)?;
    frame(t, chip, ACCENT)?;
    let mut clip = t.clipped(&chip.to_eg());
    text_centered(&mut clip, word, chip, MONO_SMALL, ACCENT, ACCENT_TINT)
}

fn draw_sheet<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    ctx: &Ctx,
    all: &[&'static str],
    scroll: i32,
) -> Result<(), D::Error> {
    let m = &ctx.m;
    let sheet = sheet_layout(ctx, all.len());
    // No Back: while the sheet is open the only ways out are Close and choosing a
    // word, and a drawn button that nothing hit-tests is a button that lies.
    draw_bar_no_back(t, m, &format!("{} words fit here", all.len()))?;
    let mut clip = t.clipped(&sheet.grid.to_eg());
    for (i, rect) in sheet.visible(scroll) {
        draw_chip(&mut clip, rect, all[i])?;
    }
    button(t, sheet.close, "Close", ButtonKind::Secondary, PAPER_1)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canvas::wrap_words;
    use crate::screens::testing::{Fixture, GEOMETRIES};

    const ELEVEN: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                          abandon abandon abandon";
    const VECTOR: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                          abandon abandon abandon about";

    /// The status line is a FIXED single line in the layout, so every string it can render
    /// has to fit one on both panels. A copy change that wrapped would draw over the strip
    /// below it - which is where the actionable half of the message lives.
    #[test]
    fn every_status_line_fits_one_line_on_both_panels() {
        let verdicts = [
            Verdict::Empty,
            Verdict::Typing { at: 1, of: 12 },
            Verdict::Typing { at: 24, of: 24 },
            Verdict::Unknown { words: 24, unknown: 12 },
            Verdict::BadCount { words: 13 },
            Verdict::BadChecksum { words: 24 },
            Verdict::Valid { words: 24 },
        ];
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            let l = PhraseState::new().layout(&f.ctx());
            for v in verdicts {
                let (line, _) = v.line();
                assert_eq!(
                    wrap_words(&line, l.well.w, BODY).len(),
                    1,
                    "{w}x{h}: status line wraps: {line}"
                );
                if let Some(hint) = v.hint() {
                    assert_eq!(
                        wrap_words(&hint, l.strip.w, BODY).len(),
                        1,
                        "{w}x{h}: hint wraps: {hint}"
                    );
                }
            }
        }
    }

    /// The checksum gate, which is the whole difference between this screen and a text
    /// field. Each refusal is a DIFFERENT verdict, because "invalid" alone would send a
    /// user hunting through twelve correct words.
    #[test]
    fn done_opens_only_for_a_real_seed_and_says_which_failure_is_in_the_way() {
        assert!(matches!(Verdict::of(""), Verdict::Empty));
        assert!(matches!(Verdict::of("aband"), Verdict::Typing { at: 1, of: 12 }));
        // Eleven words with the eleventh still under the finger, then finished: the
        // counter moves on only when the word does.
        assert!(matches!(Verdict::of(ELEVEN), Verdict::Typing { at: 11, of: 12 }));
        assert!(matches!(
            Verdict::of(&format!("{ELEVEN} ")),
            Verdict::Typing { at: 12, of: 12 }
        ));
        // A word the list does not have is reported as that, not as a checksum failure.
        assert!(matches!(
            Verdict::of("abandon notaword abandon "),
            Verdict::Unknown { words: 3, unknown: 1 }
        ));
        // Three words is a phrase still growing, and the counter says where it is going.
        assert!(matches!(Verdict::of("zoo zoo zoo "), Verdict::Typing { at: 4, of: 12 }));
        // Thirteen is past the shortest seed there is, so it is an error rather than
        // progress towards fifteen - which is the edge state S-14 names.
        let thirteen = format!("{ELEVEN} about zoo ");
        assert!(matches!(Verdict::of(&thirteen), Verdict::BadCount { words: 13 }));
        // Every word known, the count right, the checksum wrong: the vector with its last
        // word replaced by another real word. Judged without a trailing space, because a
        // finished phrase does not usually get one.
        assert!(matches!(
            Verdict::of(&VECTOR.replace("about", "zoo")),
            Verdict::BadChecksum { words: 12 }
        ));
        assert!(matches!(Verdict::of(VECTOR), Verdict::Valid { words: 12 }));
        assert!(matches!(Verdict::of(&format!("{VECTOR} ")), Verdict::Valid { words: 12 }));
        // A twelfth word half typed is neither wrong nor finished.
        assert!(matches!(
            Verdict::of(&format!("{ELEVEN} abo")),
            Verdict::Typing { at: 12, of: 12 }
        ));

        for (v, ok) in [
            (Verdict::of(""), false),
            (Verdict::of(ELEVEN), false),
            (Verdict::of(&VECTOR.replace("about", "zoo")), false),
            (Verdict::of(VECTOR), true),
        ] {
            assert_eq!(v.done(), ok);
        }
    }

    /// The final-word helper: one word short of a seed, the strip stops guessing prefixes
    /// and starts offering words that would actually check.
    #[test]
    fn the_strip_switches_to_checksum_valid_last_words() {
        // Eleven words and nothing in progress: every valid twelfth.
        let all = candidates(&format!("{ELEVEN} "));
        assert_eq!(all.len(), 128);
        assert!(all.contains(&"about"));
        // ...narrowed by whatever prefix is typed, case-insensitively.
        let narrowed = candidates(&format!("{ELEVEN} abo"));
        assert!(!narrowed.is_empty() && narrowed.len() < all.len());
        assert!(narrowed.iter().all(|w| w.starts_with("abo")));
        assert_eq!(candidates(&format!("{ELEVEN} ABO")), narrowed);
        // A prefix no valid last word has offers nothing, rather than falling back to
        // wordlist completions that could not complete this seed.
        assert!(candidates(&format!("{ELEVEN} zoo")).is_empty());
        // Ten words is not one short of anything, so the plain completions are back.
        let ten = ELEVEN.rsplit_once(' ').unwrap().0;
        assert_eq!(candidates(&format!("{ten} ab")).len(), MAX_SUGGEST);
    }

    /// The strip never hides how much it is not showing: past four candidates one slot
    /// becomes the count of the rest, and the sheet behind it holds all of them.
    #[test]
    fn the_overflow_slot_accounts_for_every_candidate() {
        assert_eq!(chips_shown(0), 0);
        assert_eq!(chips_shown(4), 4);
        assert_eq!(chips_shown(5), 3);
        assert_eq!(chips_shown(128), 3);
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            let sheet = sheet_layout(&f.ctx(), 128);
            assert!(sheet.columns >= 2, "{w}x{h}: the sheet must not be one column");
            assert!(sheet.cell_w >= 60, "{w}x{h}: sheet cell {} px wide", sheet.cell_w);
            // Every candidate is reachable: scrolled to the bottom, the last one is drawn.
            let last = sheet.total - 1;
            let at_end = sheet.cell(last, sheet.scroll_limit());
            assert!(
                at_end.bottom() <= sheet.grid.bottom() && at_end.y >= sheet.grid.y,
                "{w}x{h}: the last candidate is unreachable: {at_end:?}"
            );
        }
    }

    /// The well shows the phrase word by word so an unknown word can be inked where the
    /// user can see WHICH one it is, and it never loses a character to wrapping.
    #[test]
    fn the_well_marks_the_word_the_list_does_not_have() {
        let lines = wrap_words_in_columns("abandon notaword ABOUT", 40);
        let words: Vec<(&str, bool)> =
            lines.iter().flatten().map(|w| (w.text.trim(), w.known)).collect();
        assert_eq!(words, vec![("abandon", true), ("notaword", false), ("ABOUT", true)]);

        // Wrapping keeps every word intact and every character present, and no line
        // overruns the well it was measured against.
        let lines = wrap_words_in_columns(ELEVEN, 20);
        assert!(lines.len() > 1, "eleven words must wrap into 20 columns");
        assert_eq!(lines.iter().flatten().count(), 11, "a word was lost in the wrap");
        for line in &lines {
            let width: usize = line.iter().map(|w| w.text.chars().count()).sum();
            assert!(width <= 20, "a line overruns the well: {width} columns");
            for word in line {
                assert_eq!(word.text.trim(), "abandon", "a word was split");
            }
        }
    }
}
