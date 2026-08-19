// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! S-04 PIN entry (UX 2): the fixed phone-order pad, the anti-phishing words, and the
//! attempt policy stated as a sentence over runtime state.
//!
//! The typed PIN is the only secret here and it never leaves this module except as a
//! [`Secret`], which wipes on drop. The pad is the constant [`PIN_PAD`]: the per-attempt
//! shuffle C10 specified was reversed by the project owner on 2026-08-19
//! (docs/plan-0.2.0/OPEN-QUESTIONS.md Q35), so nothing this screen draws depends on a
//! value the embedder derives.

use alloc::string::String;
use alloc::vec::Vec;

use embedded_graphics::draw_target::DrawTarget;
use embedded_graphics::pixelcolor::Rgb565;
use zeroize::Zeroize;
use zeroize::Zeroizing;

use crate::canvas::{
    button, fill, frame, panel, text, text_centered, wrap_words, ButtonKind, BODY, MONO,
};
use crate::components::{back_rect, draw_bar, LINE};
use crate::layout::{Rect, KEYPAD_KEY_MIN};
use crate::screens::lock::LockState;
use crate::screens::{Ctx, Env, Nav, Outcome, Screen, State};
use crate::theme::*;
use crate::{
    pin_floor, secret_buf, LockInfo, Region, RegionId, Secret, UiRequest, PIN_MAX, PIN_PAD,
    PIN_WORDS_AT,
};

/// S-04's state. The typed PIN is the only secret here, and it is now nearly all of the
/// state: the pad became a constant on 2026-08-19, so what is left beside the entry is the
/// words the embedder answered with and one flag about the last attempt.
pub(crate) struct PinState {
    /// What the user typed. Self-wiping, pre-reserved to `PIN_MAX` so a push can never
    /// reallocate and strand a partial PIN outside the `Zeroizing` wrapper's reach.
    pub entry: Zeroizing<String>,
    /// The anti-phishing words, once the user asked and the embedder answered. `None`
    /// means not asked; the screen never invents them (R20).
    words: Option<[String; 2]>,
    /// A wrong PIN was entered and the danger line is showing. Cleared by the next key.
    wrong: bool,
}

impl PinState {
    pub fn new() -> PinState {
        PinState { entry: secret_buf(PIN_MAX), words: None, wrong: false }
    }

    /// Answer to [`UiRequest::DeviceWords`].
    pub fn install_words(&mut self, words: [String; 2]) {
        self.words = Some(words);
    }

    /// The PIN was wrong: the entry goes NOW rather than on the next keystroke - a wrong
    /// PIN left in the buffer is a secret kept for no reason - and the words go with it,
    /// because they belonged to a prefix that no longer exists.
    pub fn reject(&mut self) {
        self.entry.zeroize();
        self.wrong = true;
        self.words = None;
    }
}

/// The digit printed on pad position `i`, or `None` for a position off the pad. A free
/// function rather than a method, so nothing suggests a per-screen pad that no longer
/// exists: every S-04 on every device prints the same digit on position `i`.
fn digit(i: u8) -> Option<u8> {
    PIN_PAD.get(i as usize).copied()
}

/// Dot-row height: one masked run of MONO bullets, vertically centered.
const PIN_DOTS_H: i32 = 36;

/// Device-words panel height: the word pair, then the two lines the "wrong words"
/// sentence wraps to at the narrowest shipped width. Fixed, and fixed at the SHOWN
/// state's size rather than the button state's, so the pad below does not move under the
/// finger the moment the words arrive - which is the mistap C10 exists to prevent.
const PIN_WORDS_H: i32 = 3 * LINE;

// The attempt block has no constant: it is whatever is left of its column under the
// words panel, and nothing is drawn below it on either panel. It used to be a fixed
// three lines because the pad sat under it and a block that grew when a warning arrived
// would slide the keys out from under a finger; the pad is beside it now, so the honest
// height is the remaining one. What has to hold is that the worst-case policy sentence
// and the disabled-button reason both fit STACKED - a wrong PIN clears the entry, so the
// low-attempts warning and "A PIN is at least N characters." land on the same frame, and
// one drawn over the other is how a warning stops being read. The layout test asserts
// that at both shipped widths.

/// Width of `s` in the mono face, for the one place a string's fit decides a layout
/// rather than a wrap: the device-words line, which is drawn whole or not at all.
fn mono_width(s: &str) -> i32 {
    s.chars().map(|c| MONO.glyph(c).advance as i32).sum()
}

/// Pad internal gap, matching the dice keypad's.
const PIN_PAD_GAP: i32 = 10;

/// The pad's shape, and the same shape on every panel: three across, four down, the way
/// an ATM and a phone have laid out ten digits for fifty years.
///
/// This is the one part of the screen that must NOT be clever, and now that the digits
/// have stopped moving it is no longer the only part: frame and glyphs teach the same
/// thing, which is the whole of what the reversal bought. That purchase is only delivered
/// if the shape is the one every phone and cash machine has already put in the user's
/// hands - a novel grid would spend it and hand back nothing.
const PIN_COLS: i32 = 3;
const PIN_ROWS: i32 = 4;

/// The control keys' labels, as short as a keypad key is wide.
///
/// "Backspace" is what S-04's region table calls it and it needs 160 px in the button
/// face; the key is 80 px on the narrower panel, so the full word cannot be drawn in a
/// cell and the choice is a shorter word or a wider key that starves the sentence beside
/// it. "Back" is not available - the bar owns that word and the copy vocabulary gives it
/// exactly one meaning - and "Del" is the form numeric keypads have always used. The
/// layout test asserts both labels fit the key at both geometries, so a longer word
/// fails there rather than clipping on a device.
const PIN_BACKSPACE_LABEL: &str = "Del";
/// The commit key. "Unlock" needs 102 px and fits no key either panel can afford; "OK" is
/// the ATM's own word for this key, and the bar title "Enter PIN" plus the dot row above
/// it carry the rest of the sentence.
const PIN_SUBMIT_LABEL: &str = "OK";

pub(crate) struct Layout {
    dots: Rect,
    /// The device-words panel, and the button that lives inside it before the words do.
    words: Rect,
    words_btn: Rect,
    words_hint: Rect,
    /// The ten digit positions in reading order. The first nine fill the pad's first
    /// three rows; the tenth is the bottom-CENTRE cell, where every keypad ever built
    /// puts its 0, rather than the first cell of the last row that reading order alone
    /// would give it.
    keys: [Rect; 10],
    /// The two cells flanking the tenth digit. Nothing on this pad moves any more, so
    /// what these two need is not stability but SEPARATION: one of them spends an attempt
    /// when it is hit, so it must not sit where a finger aiming for a digit lands, and
    /// the last row is the only row with cells to spare.
    backspace: Rect,
    /// The attempt line's block; the text wraps into it, and it owns the rest of its
    /// column so a wrap that grows has somewhere to grow into.
    attempt: Rect,
    submit: Rect,
}

impl Screen for PinState {
    type Layout = Layout;

    /// One pad shape on both panels ([`PIN_COLS`] x [`PIN_ROWS`]); what differs is where
    /// it sits, because the two panels run out of different things.
    ///
    /// Landscape has width and no height: the pad is a right-hand rail sized at exactly
    /// [`KEYPAD_KEY_MIN`], and the dot row, the words panel and the attempt block stack
    /// in the column beside it. Every pixel the rail takes past the floor comes out of
    /// the column that has to hold three wrapped sentences, so it takes none.
    ///
    /// Portrait cannot stack the pad under everything else, and the arithmetic is worth
    /// keeping because it is what the old 5x2 pad was justified by. The 720x720 body is
    /// 672x604; the dot row (36), the words panel (126), a three-line attempt block and
    /// three gaps leave 280 px, and four rows at the 80 px floor need 350. Neither block
    /// above can give the 70 px back: the words panel is 126 because its shown state is a
    /// word pair over a sentence that wraps to two lines at 648 px, and the attempt block
    /// needs three because the widest policy sentence wraps to two with the
    /// disabled-button reason under it. So reflow rule 2 decides this panel too - keypads
    /// move beside, never shrink - and the pad moves as little as it has to. The dot row
    /// and the words panel keep the full width above it, because the words panel needs
    /// 466 px to hold its hint on one line and the widest word pair unclipped; only the
    /// attempt block, the one block that reads perfectly well narrow, goes beside the pad.
    fn layout(&self, ctx: &Ctx) -> Layout {
        let m = &ctx.m;
        let body = m.body();
        let landscape = m.landscape();

        // The rail is exactly as wide as `KEYPAD_KEY_MIN` demands and the column beside
        // it is the rest. Portrait keeps the whole width down to the words panel and
        // narrows only below it, where the pad and the attempt block share a band.
        let rail_w = PIN_COLS * KEYPAD_KEY_MIN + (PIN_COLS - 1) * PIN_PAD_GAP;
        let (col_w, g) =
            if landscape { (body.w - rail_w - m.gap, m.gap / 2) } else { (body.w, m.gap) };
        let col = Rect::new(body.x, body.y, col_w, body.h);

        let dots = Rect::new(col.x, col.y, col.w, PIN_DOTS_H);
        let words = Rect::new(col.x, dots.bottom() + g, col.w, PIN_WORDS_H);
        // The button takes the panel's first two lines; the hint sits under it, so the
        // hint's own wrap decides nothing about where the pad starts.
        let btn_h = m.btn.min(2 * LINE - 16);
        let words_btn = Rect::new(words.x + 12, words.y + 8, (words.w - 24).min(360), btn_h);
        let words_hint = Rect::new(words.x + 12, words_btn.bottom() + 8, words.w - 24, LINE);

        // Everything below the words panel: the pad, and the attempt block beside it or
        // under it. The key is SQUARE on both panels - the grid is the shape the hand is
        // being asked to learn, and a stretched cell reads as a different control.
        let below = words.bottom() + g;
        let (key, pad_x, pad_y) = if landscape {
            (KEYPAD_KEY_MIN, body.right() - rail_w, body.y)
        } else {
            // Sized from the height it actually has, and capped at half the band so a
            // taller panel can never grow the keys into the sentence beside them.
            let key = ((body.bottom() - below - (PIN_ROWS - 1) * PIN_PAD_GAP) / PIN_ROWS)
                .min((body.w / 2 - (PIN_COLS - 1) * PIN_PAD_GAP) / PIN_COLS);
            (key, body.right() - (PIN_COLS * key + (PIN_COLS - 1) * PIN_PAD_GAP), below)
        };
        let pad = Rect::new(
            pad_x,
            pad_y,
            PIN_COLS * key + (PIN_COLS - 1) * PIN_PAD_GAP,
            PIN_ROWS * key + (PIN_ROWS - 1) * PIN_PAD_GAP,
        );
        // The attempt block owns the rest of its column. Nothing is drawn below it on
        // either panel now, so a sentence that wraps one line further pushes nothing.
        let attempt = Rect::new(
            col.x,
            below,
            if landscape { col.w } else { col.w - pad.w - m.gap },
            body.bottom() - below,
        );

        let cell = |c: i32, r: i32| {
            Rect::new(pad.x + c * (key + PIN_PAD_GAP), pad.y + r * (key + PIN_PAD_GAP), key, key)
        };
        // Reading order fills the first three rows, and then the tenth position steps to
        // the middle of the last row - the 0 slot on every keypad - rather than the cell
        // reading order alone would give it. The two cells that frees are the actions, so
        // the row has no dead cell. Note what is NOT happening here: nothing looks at
        // which digit a slot carries. Geometry is decided here and the order in
        // `PIN_PAD`; keeping them apart is what lets the shape be tested against the
        // keypad and the digits against the owner's decision, one obligation each.
        let mut keys = [Rect::new(0, 0, 0, 0); 10];
        for (i, k) in keys.iter_mut().enumerate() {
            let i = i as i32;
            *k = if i == PIN_COLS * (PIN_ROWS - 1) {
                cell(PIN_COLS / 2, PIN_ROWS - 1)
            } else {
                cell(i % PIN_COLS, i / PIN_COLS)
            };
        }
        // Backspace keeps the bottom-RIGHT cell it has held since the 0.1.0 rail, which
        // is the slot S-04 froze it to; Unlock takes the bottom-left cell, the one the
        // spec reserved for `PinAlpha` and that 0.2.0 does not emit. That also puts the
        // forgiving key in the corner a thumb falls into and leaves the key that spends
        // an attempt a deliberate reach away.
        let backspace = cell(PIN_COLS - 1, PIN_ROWS - 1);
        let submit = cell(0, PIN_ROWS - 1);

        Layout { dots, words, words_btn, words_hint, keys, backspace, attempt, submit }
    }

    fn regions(&self, ctx: &Ctx, out: &mut Vec<Region>) {
        let l = self.layout(ctx);
        out.push(Region { id: RegionId::Back, rect: back_rect(&ctx.m) });
        out.push(Region { id: RegionId::PinShowWords, rect: l.words_btn });
        out.push(Region { id: RegionId::PinSubmit, rect: l.submit });
        out.push(Region { id: RegionId::PinBackspace, rect: l.backspace });
        for (i, k) in l.keys.iter().enumerate() {
            out.push(Region { id: RegionId::PinKey(i as u8), rect: *k });
        }
    }

    fn draw<D: DrawTarget<Color = Rgb565>>(&self, t: &mut D, ctx: &Ctx) -> Result<(), D::Error> {
        let m = &ctx.m;
        draw_bar(t, m, "Enter PIN")?;
        let l = self.layout(ctx);
        let n = self.entry.chars().count();

        // Typed input masks one bullet per character (0.6). No length counter and no
        // reveal toggle: a shoulder surfer learns the LENGTH from the run, which every
        // hardware wallet accepts because hiding your own progress from yourself causes
        // far more entry errors than the length leak costs. What the mask can no longer
        // lean on is the pad: with fixed digits anyone who can watch the hand has the
        // PIN, which is the trade the owner took on 2026-08-19. So the mask's job is the
        // narrower one it always did - stop the SCREEN being a second, readable copy of
        // what was typed - and it is not asked to stand in for what the shuffle did.
        let temps = PinTemps { dots: core::iter::repeat_n(BULLET, n).collect::<String>() };
        if self.wrong {
            text_centered(t, "Wrong PIN.", l.dots, BODY, DANGER, PAPER_1)?;
        } else {
            text_centered(t, &temps.dots, l.dots, MONO, INK_PRIMARY, PAPER_1)?;
        }

        panel(t, l.words, PAPER_3, BORDER_STRONG)?;
        match &self.words {
            Some([a, b]) => {
                // Labelled when the label fits, bare when it does not. The 800x480 info
                // column cannot hold "Device words: " plus the widest pair the BIP39 list
                // can produce, and a clipped anti-phishing word is worse than an
                // unlabelled one - the sentence below the pair says what it is either
                // way.
                let pair = format!("{} {}", a.to_uppercase(), b.to_uppercase());
                let labelled = format!("Device words: {pair}");
                let line1 = if mono_width(&labelled) <= l.words.w - 24 { &labelled } else { &pair };
                let mut y = l.words.y + 4;
                text_centered(
                    t,
                    line1,
                    Rect::new(l.words.x, y, l.words.w, LINE),
                    MONO,
                    INK_PRIMARY,
                    PAPER_3,
                )?;
                y += LINE;
                for line in wrap_words(
                    "Wrong words? Stop. This may not be your device.",
                    l.words.w - 24,
                    BODY,
                ) {
                    text_centered(
                        t,
                        &line,
                        Rect::new(l.words.x, y, l.words.w, LINE),
                        BODY,
                        INK_SECONDARY,
                        PAPER_3,
                    )?;
                    y += LINE;
                }
            }
            None => {
                // Disabled carries its reason beside it, never a silent dead button.
                let ready = n >= PIN_WORDS_AT;
                let kind = if ready { ButtonKind::Secondary } else { ButtonKind::Disabled };
                button(t, l.words_btn, "Show device words", kind, PAPER_3)?;
                // Formatted from the same constant the guard at `activate` reads, never a
                // literal: a hint and a guard that state the threshold separately are two
                // places for one number, and the screen would keep promising the old one.
                let waiting = alloc::format!("Available after {PIN_WORDS_AT} digits.");
                let hint = if ready { "Seeing them costs no attempt." } else { &waiting };
                text(t, hint, l.words_hint.x, l.words_hint.y, BODY, INK_MUTED, PAPER_3)?;
            }
        }

        // C10: the pressed state is drawn on the DOT ROW, never on the key, and it keeps
        // its place now that the pad is fixed - on a different argument, because the old
        // one died with the shuffle. A highlight can no longer betray a permutation there
        // is none of; what it would betray instead is worse. On a fixed pad a lit cell IS
        // the digit, and a lit 80 px cell is legible from across a room, in a window
        // reflection, and in a camera frame where the hand covers the glyph but not the
        // border around it. The finger already hands the digit to anyone standing over
        // the user - that much the reversal conceded - but the concession was to the
        // owner's convenience, not to indirect observers, and the screen does not have to
        // repeat it at higher contrast. So the key still gets no local press feedback,
        // the one control in the product without it, and the bullet arriving on the dot
        // row is the acknowledgement the finger gets.
        for (i, k) in l.keys.iter().enumerate() {
            let digit = PIN_PAD.get(i).copied().unwrap_or(0);
            fill(t, *k, PAPER_3)?;
            frame(t, *k, BORDER_STRONG)?;
            let mut buf = [0u8; 4];
            let label = char::from(b'0' + digit).encode_utf8(&mut buf);
            text_centered(t, label, *k, MONO, INK_PRIMARY, PAPER_3)?;
        }
        // The two cells flanking the tenth digit are drawn as BUTTONS rather than as
        // keys. A control that looks like a digit is a mistap waiting to happen, and one
        // of these two spends an attempt when it is hit by accident.
        let bs_kind = if n > 0 { ButtonKind::Secondary } else { ButtonKind::Disabled };
        button(t, l.backspace, PIN_BACKSPACE_LABEL, bs_kind, PAPER_1)?;

        let (line, ink) = attempt_line(ctx.lock);
        let mut ay = l.attempt.y;
        for wrapped in wrap_words(&line, l.attempt.w, BODY) {
            text(t, &wrapped, l.attempt.x, ay, BODY, ink, PAPER_1)?;
            ay += LINE;
        }
        // The floor comes from the device, and the sentence and the button are both
        // written from that one value. A literal here is the defect that reached
        // hardware: the screen said 6 while the store accepted 4, so Unlock never
        // enabled and the reason under it named a number nothing enforced.
        let floor = pin_floor(ctx.lock);
        let reason = if n >= PIN_MAX {
            Some((String::from("Maximum length reached."), WARNING))
        } else if n < floor {
            Some((format!("A PIN is at least {floor} characters."), INK_MUTED))
        } else {
            None
        };
        // Directly under whatever the policy sentence wrapped to, not at a fixed offset:
        // the sentence is one to three lines depending on the policy and the panel, and a
        // fixed offset draws the reason over the warning in exactly the state that
        // matters most. Wrapped rather than placed, because the block is a column beside
        // the pad on the portrait panel and the sentence is wider than that column.
        if let Some((why, ink)) = reason {
            for wrapped in wrap_words(&why, l.attempt.w, BODY) {
                text(t, &wrapped, l.attempt.x, ay, BODY, ink, PAPER_1)?;
                ay += LINE;
            }
        }

        let kind = if n >= floor { ButtonKind::Primary } else { ButtonKind::Disabled };
        button(t, l.submit, PIN_SUBMIT_LABEL, kind, PAPER_1)?;
        Ok(())
    }

    fn activate(&mut self, id: RegionId, env: &mut Env) -> Outcome {
        match id {
            RegionId::PinKey(i) => {
                self.wrong = false;
                if let Some(d) = digit(i) {
                    if self.entry.len() < PIN_MAX {
                        self.entry.push((b'0' + d) as char);
                    }
                }
                Outcome::stay()
            }
            RegionId::PinBackspace => {
                self.wrong = false;
                self.entry.pop();
                Outcome::stay()
            }
            // Showing the words is not a guess and costs no attempt (ARCHITECTURE.md 3).
            // The prefix is handed over exactly as typed, including one that is not any
            // real prefix: refusing to answer would turn the words into an oracle for
            // prefix correctness, which is the failure the feature exists to prevent.
            RegionId::PinShowWords if self.entry.len() >= PIN_WORDS_AT => {
                Outcome::ask(UiRequest::DeviceWords(Secret::new(&self.entry)))
            }
            // The same floor the button was DRAWN from, read from the same place: a guard
            // that could disagree with the paint is a button that lies either way round.
            RegionId::PinSubmit if self.entry.len() >= pin_floor(env.lock) => {
                Outcome::ask(UiRequest::UnsealWallet(Secret::new(&self.entry)))
            }
            // Both are drawn disabled, with the reason beside them; a tap does nothing.
            _ => Outcome::stay(),
        }
    }

    /// Back is the lock screen, not the stack: popping from PIN entry would land on
    /// whatever was open before the auto-lock fired.
    fn back(&self) -> Nav {
        Nav::Enter(State::Lock(LockState))
    }
}

/// The attempt line, as a sentence over the runtime policy rather than a literal (Q37).
///
/// The wipe threshold is always shown, because it tells the user the consequence of their
/// next mistake and leaks nothing a coercer cannot get by trying one wrong PIN. The full
/// disclosure - that an interrupted verification also costs an attempt, and what exactly
/// a wipe destroys - belongs to m4b's S-44 policy screen, which is the surface the
/// ratified Q5 gives it to; repeating all of it here would not fit either shipped panel.
fn attempt_line(lock: &LockInfo) -> (String, Rgb565) {
    match (lock.attempts_left, lock.wipe_after) {
        (Some(n), _) if n <= 3 => (
            format!("{n} tries left. At 0 the device erases its stored wallets."),
            WARNING,
        ),
        (Some(n), Some(total)) => (format!("{n} of {total} tries left"), INK_SECONDARY),
        (Some(n), None) => (format!("{n} tries left"), INK_SECONDARY),
        (None, _) => (
            String::from("Tries are not limited. This device does not erase on wrong PINs."),
            INK_SECONDARY,
        ),
    }
}

/// Per-frame heap copy of the masked dot run, wiped on every exit path.
struct PinTemps {
    dots: String,
}

impl Drop for PinTemps {
    fn drop(&mut self) {
        self.dots.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canvas::{wrap_words, HEADING};
    use crate::screens::testing::{Fixture, GEOMETRIES};
    use crate::Network;

    /// Every string the PIN screen's two information blocks can render must wrap inside
    /// their fixed heights at both shipped geometries.
    ///
    /// This is the assertion the layout rests on: the blocks are a FIXED height so the
    /// pad below them does not move when a hint, a word pair or a warning arrives, and a
    /// fixed height is only honest if the copy provably fits it. A copy change that
    /// overflows fails here rather than clipping a warning on a device.
    #[test]
    fn the_pin_information_blocks_hold_every_string_they_can_show() {
        let words_lines = PIN_WORDS_H / LINE;
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            let l = PinState::new().layout(&f.ctx());

            // The attempt block, over the cross product of every policy state and every
            // floor a store can be formatted with. The two are drawn TOGETHER - a wrong
            // PIN clears the entry, so the low-attempts warning and the disabled-button
            // reason land on the same frame - so what has to fit is both wraps stacked,
            // in whatever height the panel left the block. The reason is a format string
            // over a device value, which is why the widest number the clamp admits is
            // exercised rather than the one the wireframe happened to draw.
            for lock in [
                LockInfo { attempts_left: Some(9), wipe_after: Some(15), ..LockInfo::default() },
                LockInfo { attempts_left: Some(3), wipe_after: Some(15), ..LockInfo::default() },
                LockInfo { attempts_left: Some(1), wipe_after: None, ..LockInfo::default() },
                LockInfo { attempts_left: None, wipe_after: None, ..LockInfo::default() },
            ] {
                let (line, _) = attempt_line(&lock);
                let policy = wrap_words(&line, l.attempt.w, BODY).len() as i32;
                let mut reasons = alloc::vec![String::from("Maximum length reached.")];
                for floor in [1, 9, 10, PIN_MAX] {
                    reasons.push(format!("A PIN is at least {floor} characters."));
                }
                for why in reasons {
                    let n = policy + wrap_words(&why, l.attempt.w, BODY).len() as i32;
                    assert!(
                        n * LINE <= l.attempt.h,
                        "{w}x{h}: the attempt block needs {n} lines in the {} it has, at \
                         {} px wide: {line:?} over {why:?}",
                        l.attempt.h / LINE,
                        l.attempt.w
                    );
                }
            }

            // The words panel in its shown state: the word pair takes one line and the
            // "wrong words" sentence takes the rest.
            let warn = wrap_words(
                "Wrong words? Stop. This may not be your device.",
                l.words.w - 24,
                BODY,
            )
            .len() as i32;
            // The pair plus the sentence.
            assert!(
                warn < words_lines,
                "{w}x{h}: words panel needs {} lines in {words_lines}",
                warn + 1
            );
            // The widest word pair the BIP39 list can produce, unclipped. Two eight-letter
            // words and a space is the ceiling; nothing longer exists.
            assert!(
                mono_width("ABANDONED ABANDONED") <= l.words.w - 24,
                "{w}x{h}: the widest word pair overflows the panel"
            );

            // And in its button state: the button plus one hint line.
            let waiting = alloc::format!("Available after {PIN_WORDS_AT} digits.");
            for hint in [waiting.as_str(), "Seeing them costs no attempt."] {
                assert_eq!(
                    wrap_words(hint, l.words_hint.w, BODY).len(),
                    1,
                    "{w}x{h}: hint must be one line: {hint}"
                );
            }
            assert!(
                l.words_hint.bottom() <= l.words.bottom(),
                "{w}x{h}: the hint escapes its panel"
            );
            assert!(
                l.words_btn.bottom() <= l.words_hint.y,
                "{w}x{h}: the button overlaps its own hint"
            );
        }
    }

    /// The pad is the conventional keypad on BOTH panels, and every cell in it keeps
    /// `KEYPAD_KEY_MIN`.
    ///
    /// This is the assertion the owner instruction rests on. It checks the SHAPE rather
    /// than the arithmetic that produces it: three columns of three digits, the tenth
    /// digit centred under them, and the two controls in the cells beside it - which is
    /// what a hand recognises without reading. It says nothing about which digit lands
    /// where; that is the other half of the keypad and it is pinned separately, because a
    /// screen can hold the shape and print the wrong order, or the reverse, and one test
    /// that failed for either reason would name neither.
    #[test]
    fn the_pin_pad_is_a_keypad_at_both_geometries() {
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            let l = PinState::new().layout(&f.ctx());
            let body = f.m.body();

            // Every cell is the same square, at or above the floor. Same square matters
            // as much as the floor does: the tenth key is the 0, and a 0 drawn to a
            // different size would read as a different kind of control on the one row
            // that genuinely holds two of them.
            let cells: [Rect; 12] = core::array::from_fn(|i| match i {
                0..=9 => l.keys[i],
                10 => l.backspace,
                _ => l.submit,
            });
            let key = l.keys[0];
            for (i, c) in cells.iter().enumerate() {
                assert!(
                    c.w >= KEYPAD_KEY_MIN && c.h >= KEYPAD_KEY_MIN,
                    "{w}x{h}: cell {i} is {}x{} below the {KEYPAD_KEY_MIN} px floor",
                    c.w,
                    c.h
                );
                assert!(
                    c.w == key.w && c.h == key.h,
                    "{w}x{h}: cell {i} is {}x{}, not the {}x{} every other cell is",
                    c.w, c.h, key.w, key.h
                );
                assert!(
                    c.x >= body.x && c.y >= body.y && c.right() <= body.right()
                        && c.bottom() <= body.bottom(),
                    "{w}x{h}: cell {i} {c:?} escapes the body {body:?}"
                );
            }

            // Three columns, four rows, and nothing overlapping anything.
            let cols: Vec<i32> = {
                let mut xs: Vec<i32> = cells.iter().map(|c| c.x).collect();
                xs.sort_unstable();
                xs.dedup();
                xs
            };
            let rows: Vec<i32> = {
                let mut ys: Vec<i32> = cells.iter().map(|c| c.y).collect();
                ys.sort_unstable();
                ys.dedup();
                ys
            };
            assert_eq!(cols.len(), PIN_COLS as usize, "{w}x{h}: {} columns", cols.len());
            assert_eq!(rows.len(), PIN_ROWS as usize, "{w}x{h}: {} rows", rows.len());
            for (i, a) in cells.iter().enumerate() {
                for b in cells.iter().skip(i + 1) {
                    assert!(!a.overlaps(b), "{w}x{h}: {a:?} overlaps {b:?}");
                }
            }

            // The slots read left to right, top to bottom over the first three rows,
            // and the tenth is centred on the last - the frame a hand already knows,
            // whatever is printed in it.
            for (i, k) in l.keys.iter().take(9).enumerate() {
                assert_eq!(k.x, cols[i % 3], "{w}x{h}: key {i} is in the wrong column");
                assert_eq!(k.y, rows[i / 3], "{w}x{h}: key {i} is in the wrong row");
            }
            assert_eq!(l.keys[9].x, cols[1], "{w}x{h}: the tenth digit is not centred");
            assert_eq!(l.keys[9].y, rows[3], "{w}x{h}: the tenth digit is not on the last row");

            // The two controls flank it, and they do not move between attempts: their
            // cells are a function of the grid alone.
            assert_eq!((l.submit.x, l.submit.y), (cols[0], rows[3]), "{w}x{h}: submit slot");
            assert_eq!(
                (l.backspace.x, l.backspace.y),
                (cols[2], rows[3]),
                "{w}x{h}: backspace slot"
            );

            // Their labels have to fit the cell they are drawn in. `button` centres the
            // label in `HEADING` and neither wraps nor clips, so a longer word fails here
            // rather than running over the border on a device. The margin is the frame
            // plus enough space for the label to read as a label.
            for label in [PIN_SUBMIT_LABEL, PIN_BACKSPACE_LABEL] {
                let need = HEADING.text_width(label) as i32;
                assert!(
                    need <= key.w - 16,
                    "{w}x{h}: {label:?} needs {need} px in a {} px key",
                    key.w
                );
            }

            for r in [l.dots, l.words, l.attempt] {
                assert!(
                    r.x >= body.x && r.y >= body.y && r.right() <= body.right()
                        && r.bottom() <= body.bottom(),
                    "{w}x{h}: {r:?} escapes the body {body:?}"
                );
                assert!(!r.overlaps(&l.keys[0]), "{w}x{h}: {r:?} runs under the pad");
                assert!(!r.overlaps(&l.keys[9]), "{w}x{h}: {r:?} runs under the pad");
            }
        }
    }

    /// The pad is phone order - 1-2-3 / 4-5-6 / 7-8-9 with 0 centred under them - on both
    /// panels, and a tap types the digit that is drawn on the cell it hit.
    ///
    /// This is the owner's 2026-08-19 decision (Q35, reversed) held in one place, and it
    /// is asserted through `activate` rather than against `PIN_PAD` alone because the pad
    /// the user has is the product of TWO independent things: the slot -> digit order and
    /// the slot -> rectangle layout. Either one alone can be right while the pad on the
    /// panel is wrong, so what is pinned here is the pair - which cell, and what typing it
    /// yields - at both shipped geometries.
    ///
    /// The screen is built with `PinState::new()` and the embedder is never consulted,
    /// which is the second property: the pad is correct with no embedder in the picture at
    /// all. There is no longer a setter that could make it otherwise - the pad is a `const`
    /// and the whole `PinPad` request path was deleted with the shuffle.
    #[test]
    fn the_pad_is_phone_order_at_both_geometries() {
        // Slot -> (column, row, digit). The tenth slot is the centre of the last row.
        let expect: [(i32, i32, u8); 10] = [
            (0, 0, 1),
            (1, 0, 2),
            (2, 0, 3),
            (0, 1, 4),
            (1, 1, 5),
            (2, 1, 6),
            (0, 2, 7),
            (1, 2, 8),
            (2, 2, 9),
            (1, 3, 0),
        ];
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            let mut network = Network::Bitcoin;
            let mut s = PinState::new();
            let l = s.layout(&f.ctx());
            // The step is read off the grid rather than recomputed from the constants, so
            // this test fails on the cell a slot LANDS in and not on the arithmetic.
            let step = l.keys[1].x - l.keys[0].x;
            let (x0, y0) = (l.keys[0].x, l.keys[0].y);

            for (i, (c, r, digit)) in expect.iter().enumerate() {
                let k = l.keys[i];
                assert_eq!(
                    (k.x, k.y),
                    (x0 + c * step, y0 + r * step),
                    "{w}x{h}: slot {i} (the {digit} key) is not at column {c}, row {r}"
                );
                let mut env =
                    Env { network: &mut network, lock: &f.lock, wallets: &f.wallets };
                s.activate(RegionId::PinKey(i as u8), &mut env);
                assert_eq!(
                    s.entry.chars().last(),
                    Some(char::from(b'0' + digit)),
                    "{w}x{h}: slot {i} typed something other than {digit}"
                );
            }
            assert_eq!(&*s.entry, "1234567890", "{w}x{h}: the pad is not phone order");
        }
    }
}
