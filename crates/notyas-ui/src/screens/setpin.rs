// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! S-06 / S-07 PIN create and confirm: the only surface that can put a PIN on this device.
//!
//! Before this screen existed the store could be given its first PIN over the test console
//! and nowhere else, and the test console is compiled out of a product build - so a release
//! image could not format itself, and a device that cannot format itself cannot save a
//! wallet. That is the whole reason this module is here, and it is why the commit path is
//! written to reach the user on every outcome rather than to look right on the happy one.
//!
//! Two spec screens, one state, one `ScreenId`: S-07 is S-06 with a different heading line
//! and a different button label, over the same bar, the same pad and the same rectangles.
//! The step is carried in [`Step`] and shows in the bar.
//!
//! The pad is [`PIN_PAD`] - fixed phone order, the same slots S-04 uses, on both panels and
//! on every device (Q35, reversed by the owner on 2026-08-19). A create screen that shuffled
//! while the unlock screen did not would teach one layout and then ask for the PIN on
//! another, which is a mistyped PIN on a device that erases after enough of them.
//!
//! Three properties this module owes, and where each is kept:
//!
//! 1. **The floor is the STORE's.** Every enable rule and every sentence about length is
//!    written from [`crate::pin_floor`], which reads [`LockInfo::min_pin_len`] - the value
//!    the device was formatted with, or will be. A second constant here would be the 0.2.0
//!    defect exactly, and worse on this screen than on S-04: a create screen that refuses a
//!    PIN the store would have accepted is a device nobody can ever unlock, rather than one
//!    nobody can unlock today.
//! 2. **Both entries are masked and neither is compared visibly.** The panel says only
//!    whether the two matched; see [`entries_match`] for the loop that keeps it that way.
//! 3. **Nothing is typed anywhere but into a `Zeroizing` buffer**, both buffers are wiped
//!    the moment one is handed over, and leaving the screen drops them.

use alloc::string::String;
use alloc::vec::Vec;

use embedded_graphics::draw_target::DrawTarget;
use embedded_graphics::pixelcolor::Rgb565;
use zeroize::{Zeroize, Zeroizing};

use crate::canvas::{button, fill, frame, text, text_centered, wrap_words, ButtonKind, BODY, MONO};
use crate::components::{back_rect, draw_bar, SMALL_LINE};
use crate::layout::{Rect, KEYPAD_KEY_MIN};
use crate::screens::{Ctx, Env, Nav, Outcome, Screen};
use crate::theme::*;
use crate::{
    pin_floor, secret_buf, LockInfo, Region, RegionId, Secret, StoreStatus, UiRequest, PIN_MAX,
    PIN_PAD,
};

/// What the copy block is carrying: the explanation, or the reason there is nothing to
/// explain.
enum BodyCopy {
    Explanation([String; 3]),
    Refusal(&'static str),
}

/// Which of the two entries the pad is typing into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Enter,
    Confirm,
}

/// The news the screen owes the user, as distinct from the standing reason a disabled
/// button owes. Cleared by the next key, the way S-04 clears its wrong-PIN line: a warning
/// that outlived the state it described would be read as a warning about the new one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Note {
    None,
    /// The two entries differed.
    Mismatch,
    /// The embedder refused [`UiRequest::SetPin`]. NOT a silent return: a failed write that
    /// left the screen looking exactly like an unstarted one is the defect pattern this
    /// codebase names at the top of the firmware's `answer_request`.
    Refused,
}

/// S-06/S-07's state. Two secrets; everything else is device state or a step counter.
pub(crate) struct SetPinState {
    /// The first entry. Self-wiping and pre-reserved to [`PIN_MAX`], so a push can never
    /// reallocate and strand a partial PIN outside the wrapper's reach.
    pub entry: Zeroizing<String>,
    /// The second entry, typed on step 2 and never shown beside the first.
    pub confirm: Zeroizing<String>,
    step: Step,
    note: Note,
}

impl SetPinState {
    pub fn new() -> SetPinState {
        SetPinState {
            entry: secret_buf(PIN_MAX),
            confirm: secret_buf(PIN_MAX),
            step: Step::Enter,
            note: Note::None,
        }
    }

    /// Answer to a refused [`UiRequest::SetPin`].
    ///
    /// The buffers were already wiped when the request was raised, so there is nothing left
    /// to clear here and nothing of the refused PIN survives in this crate. What this
    /// installs is the sentence the user is owed.
    pub fn report_failure(&mut self) {
        self.note = Note::Refused;
        self.step = Step::Enter;
    }

    /// The buffer the pad types into.
    fn active(&mut self) -> &mut Zeroizing<String> {
        match self.step {
            Step::Enter => &mut self.entry,
            Step::Confirm => &mut self.confirm,
        }
    }

    /// How many characters are in the entry being typed.
    fn typed(&self) -> usize {
        match self.step {
            Step::Enter => self.entry.chars().count(),
            Step::Confirm => self.confirm.chars().count(),
        }
    }

    /// Forget both entries and return to step 1. Called wherever an entry stops being the
    /// one on screen - a mismatch, and the handover to the embedder - so that at no point
    /// does a PIN sit in this state longer than the screen is showing it.
    fn forget(&mut self) {
        self.entry.zeroize();
        self.confirm.zeroize();
        self.step = Step::Enter;
    }

    /// The commit region for the step showing, and its label.
    fn commit(&self) -> (RegionId, &'static str) {
        match self.step {
            Step::Enter => (RegionId::PinNext, NEXT_LABEL),
            Step::Confirm => (RegionId::PinConfirm, SET_LABEL),
        }
    }

    /// Whether the commit is live: a store that can be formatted at all, and an entry at or
    /// above THIS DEVICE's floor.
    ///
    /// ONE rule, read by the paint and by the tap. A guard that could disagree with the
    /// button it draws is a button that lies either way round.
    fn ready(&self, lock: &LockInfo) -> bool {
        refusal(lock.status).is_none() && self.typed() >= pin_floor(lock)
    }

    /// The one sentence this screen owes right now, and the ink it is owed in.
    ///
    /// The news outranks the standing reason: after a mismatch the entry is empty, so the
    /// floor sentence is true as well, and the user needs to be told what just happened
    /// before being told what to type. The next key clears the news and the floor sentence
    /// takes the line back.
    fn advice(&self, lock: &LockInfo) -> Option<(String, Rgb565)> {
        match self.note {
            Note::Mismatch => return Some((String::from(MISMATCH), DANGER)),
            Note::Refused => return Some((String::from(REFUSED), DANGER)),
            Note::None => {}
        }
        let n = self.typed();
        let floor = pin_floor(lock);
        if n >= PIN_MAX {
            Some((String::from(AT_CAP), WARNING))
        } else if n < floor {
            Some((format!("A PIN is at least {floor} characters."), INK_MUTED))
        } else {
            None
        }
    }

    /// The bar title, carrying the step the way S-06's wireframe carries its `1 / 2`.
    fn title(&self) -> &'static str {
        match self.step {
            Step::Enter => "Set a PIN - 1 of 2",
            Step::Confirm => "Set a PIN - 2 of 2",
        }
    }

    /// What the copy block says on this frame.
    ///
    /// A refusal REPLACES the explanation rather than sitting under it: on a device that
    /// cannot store anything, "this PIN encrypts what you save here" is not a sentence about
    /// that device, and the reason it cannot is the only thing on the screen worth reading.
    /// It is also what keeps the block below this one to one line, which is what lets the
    /// ratified copy fit the 800x480 column at all.
    fn body_copy(&self, lock: &LockInfo) -> BodyCopy {
        match refusal(lock.status) {
            Some(why) => BodyCopy::Refusal(why),
            None => BodyCopy::Explanation(copy_for(self.step, lock)),
        }
    }
}

// ---------------------------------------------------------------------------------------
// Copy
// ---------------------------------------------------------------------------------------

/// What the PIN is, and what nothing can undo. First, because it is the fact that makes the
/// next tap irreversible.
const LEAD_ENTER: &str = "This PIN encrypts what you save here. There is no reset.";
/// S-07's heading line, replacing the lead.
const LEAD_CONFIRM: &str = "Type the same PIN again.";
/// The ratified honesty line (Q4), in the ratified words. It is on this screen rather than
/// S-04 because this is where the length is CHOSEN, and it is not a bit count on purpose: a
/// bit count for a human-chosen PIN would be a lie.
///
/// What the ratified copy pairs it with - that letters and symbols make offline guessing
/// far harder - is deliberately absent: this build's pad has ten keys and no alphanumeric
/// page (`RegionId::PinAlpha` is declared and unemitted), so the sentence would advertise a
/// control the user cannot reach.
const CLASS: &str = "A digits-only PIN protects against theft, not against a funded lab.";

/// The two failure lines, and both are one line long at both shipped widths on purpose.
///
/// The ratified copy ends them "Start again." and "Nothing was written."; the screen itself
/// says both of those things - a mismatch returns to step 1 with an empty dot row, and a PIN
/// that was not set is a device that was not written to - and the column carrying them also
/// has to carry the three sentences above, which are facts the user cannot infer from
/// anything on the panel. The clause that the screen already states is the one that gives
/// way.
const MISMATCH: &str = "Those did not match.";
const REFUSED: &str = "The PIN was not set.";
const AT_CAP: &str = "Maximum length reached.";

/// The commit key labels. Short because the key is [`KEYPAD_KEY_MIN`] wide on the narrower
/// panel and a cropped label on the one control that writes to flash is not an option; the
/// bar's step counter and the heading above it carry the rest of the sentence, which is the
/// same trade S-04 makes for its OK key.
const NEXT_LABEL: &str = "Next";
const SET_LABEL: &str = "Set";
/// S-04's word for the same key, and frozen to it: the two PIN pads must be one object to
/// the hand.
const BACKSPACE_LABEL: &str = "Del";

/// The wipe consequence, as a sentence over the policy the device actually carries (Q37).
///
/// Never a literal: a blank store reports the policy its format will be written with, so the
/// number here is the one that will be in force the moment this screen commits, and a device
/// configured differently states its own.
fn wipe_line(lock: &LockInfo) -> String {
    match lock.wipe_after {
        Some(n) => format!("After {n} wrong PINs the device erases its stored wallets."),
        None => String::from("Tries are not limited. This device does not erase on wrong PINs."),
    }
}

/// Why this device cannot be given a PIN at all, or `None` when it can.
///
/// Exhaustive over the status rather than a test for the good one: every state has an
/// answer, and a tap that did nothing because the store was in one of the others would be
/// exactly the dead button this screen exists to remove.
fn refusal(status: StoreStatus) -> Option<&'static str> {
    match status {
        // Nothing sealed and a device key present: the state this screen is for.
        StoreStatus::Blank => None,
        StoreStatus::NotProvisioned => {
            Some("This device has no device key, so it cannot store anything.")
        }
        StoreStatus::Unreadable => {
            Some("This device cannot read its own store, so nothing can be saved to it.")
        }
        // Unreachable through the fork, which sends a device that already has a PIN straight
        // on - but a screen that answered an impossible state with silence would be one
        // refusal short of the rule above.
        StoreStatus::Locked | StoreStatus::Unlocked => Some("This device already has a PIN."),
    }
}

fn copy_for(step: Step, lock: &LockInfo) -> [String; 3] {
    let lead = match step {
        Step::Enter => LEAD_ENTER,
        Step::Confirm => LEAD_CONFIRM,
    };
    [String::from(lead), String::from(CLASS), wipe_line(lock)]
}

// ---------------------------------------------------------------------------------------
// Geometry
// ---------------------------------------------------------------------------------------

/// Dot-row height: one masked run, vertically centred. S-04's value, because the two PIN
/// screens must not read as different objects.
const DOTS_H: i32 = 36;
/// Pad internal gap, matching S-04's and the dice keypad's.
const PAD_GAP: i32 = 10;
/// Three across, four down: the shape a hand has known since the first cash machine, and
/// S-04's shape exactly. The digits on it are fixed too now (Q35, reversed 2026-08-19), so
/// what a user learns here is what they will be asked for at every later unlock.
const COLS: i32 = 3;
const ROWS: i32 = 4;
/// Space between the copy paragraphs, so three stacked sentences read as three.
const PARA_GAP: i32 = 8;

/// Height of `paras` wrapped at `w`.
fn paragraph_h(paras: &[String; 3], w: i32) -> i32 {
    let lines: i32 = paras.iter().map(|p| wrap_words(p, w, BODY).len() as i32).sum();
    lines * SMALL_LINE + (paras.len() as i32 - 1) * PARA_GAP
}

/// The copy block's height at `w`: the taller of the two steps.
///
/// Sized for BOTH steps rather than for the one showing, so advancing to the confirm step
/// moves nothing under it. The pad is placed independently of this block, but the advice
/// line is not, and a sentence that jumped up the screen as the step changed would be read
/// as a different sentence.
fn copy_block_h(w: i32, lock: &LockInfo) -> i32 {
    [Step::Enter, Step::Confirm]
        .into_iter()
        .map(|s| paragraph_h(&copy_for(s, lock), w))
        .max()
        .unwrap_or(0)
}

/// The advice line's reserve at `w`: the worst case of every sentence it can carry.
///
/// Reserved rather than measured per frame for the same reason the copy block is sized for
/// both steps, and for a stronger one here: this block is the LAST thing in its column, so a
/// sentence longer than its reserve would not push anything - it would run off the bottom of
/// the panel, where nothing but the pixel gate can see it.
fn advice_block_h(w: i32, lock: &LockInfo) -> i32 {
    let floor = pin_floor(lock);
    let mut lines = 1;
    let worst = [
        String::from(MISMATCH),
        String::from(REFUSED),
        String::from(AT_CAP),
        // The floor is a runtime value, so the reserve is measured at the widest sentence it
        // can produce rather than at the one this device happens to state.
        format!("A PIN is at least {} characters.", PIN_MAX),
        format!("A PIN is at least {floor} characters."),
    ];
    for s in worst {
        lines = lines.max(wrap_words(&s, w, BODY).len() as i32);
    }
    lines * SMALL_LINE
}

pub(crate) struct Layout {
    dots: Rect,
    copy: Rect,
    advice: Rect,
    /// The ten digit positions in reading order; the tenth is the bottom-CENTRE cell, where
    /// every keypad ever built puts its zero.
    keys: [Rect; 10],
    /// The two cells flanking it, and never a digit: the key that discards an entry must
    /// not sit where a finger aims for a digit.
    backspace: Rect,
    commit: Rect,
}

impl Screen for SetPinState {
    type Layout = Layout;

    /// One pad shape on both panels, and the copy in the column beside it.
    ///
    /// Landscape has width and no height, so the pad is a right-hand rail at exactly
    /// [`KEYPAD_KEY_MIN`] and everything else stacks in the column beside it - S-04's
    /// arrangement, arrived at the same way.
    ///
    /// Portrait cannot stack three sentences AND four rows of keys: 604 px of body minus a
    /// 350 px pad at the key floor leaves four lines of body copy for a screen that owes the
    /// user seven. So the dot row keeps the full width, and below it the pad takes the right
    /// of the band with the copy in the column beside it - reflow rule 2 (keypads move
    /// beside, never shrink) applied to the block that reads perfectly well narrow.
    fn layout(&self, ctx: &Ctx) -> Layout {
        let m = &ctx.m;
        let body = m.body();
        let landscape = m.landscape();
        let rail_w = COLS * KEYPAD_KEY_MIN + (COLS - 1) * PAD_GAP;
        let g = if landscape { m.gap / 2 } else { m.gap };

        // Where the pad goes, and how big its keys are. The key is SQUARE on both panels:
        // the grid is the shape the hand is being asked to learn, and a stretched cell reads
        // as a different control.
        let (key, pad_x, pad_y, dots) = if landscape {
            let dots = Rect::new(body.x, body.y, body.w - rail_w - m.gap, DOTS_H);
            (KEYPAD_KEY_MIN, body.right() - rail_w, body.y, dots)
        } else {
            let dots = Rect::new(body.x, body.y, body.w, DOTS_H);
            let top = dots.bottom() + g;
            // Sized from the height the band actually has, and capped at half the body so
            // the pad can never grow into the sentences beside it on a taller panel.
            let key = ((body.bottom() - top - (ROWS - 1) * PAD_GAP) / ROWS)
                .min((body.w / 2 - (COLS - 1) * PAD_GAP) / COLS);
            (key, body.right() - (COLS * key + (COLS - 1) * PAD_GAP), top, dots)
        };
        let pad = Rect::new(
            pad_x,
            pad_y,
            COLS * key + (COLS - 1) * PAD_GAP,
            ROWS * key + (ROWS - 1) * PAD_GAP,
        );

        // The column is everything the pad does not take. In landscape it starts at the top
        // and the dot row is its first block; in portrait the dot row spans the whole body
        // above the band and the column starts beside the pad.
        let col = Rect::new(body.x, pad_y, pad.x - m.gap - body.x, body.bottom() - pad_y);
        let copy_top = if landscape { dots.bottom() + g } else { col.y };
        let copy = Rect::new(col.x, copy_top, col.w, copy_block_h(col.w, ctx.lock));
        let advice = Rect::new(col.x, copy.bottom() + g, col.w, advice_block_h(col.w, ctx.lock));

        let cell = |c: i32, r: i32| {
            Rect::new(pad.x + c * (key + PAD_GAP), pad.y + r * (key + PAD_GAP), key, key)
        };
        // Reading order fills the first three rows; the tenth POSITION steps to the middle
        // of the last row rather than to the cell reading order alone would give it, which
        // is what puts the zero under the 8. The grid is deliberately blind to what is
        // printed on a cell, so its shape can be tested apart from the pad it carries.
        let mut keys = [Rect::new(0, 0, 0, 0); 10];
        for (i, k) in keys.iter_mut().enumerate() {
            let i = i as i32;
            *k = if i == COLS * (ROWS - 1) {
                cell(COLS / 2, ROWS - 1)
            } else {
                cell(i % COLS, i / COLS)
            };
        }
        // Backspace keeps the bottom-right cell S-04 froze it to, and the commit takes the
        // bottom-left one. That puts the forgiving key where a thumb falls and leaves the key
        // that writes to flash a deliberate reach away.
        Layout {
            dots,
            copy,
            advice,
            keys,
            backspace: cell(COLS - 1, ROWS - 1),
            commit: cell(0, ROWS - 1),
        }
    }

    fn regions(&self, ctx: &Ctx, out: &mut Vec<Region>) {
        let l = self.layout(ctx);
        out.push(Region { id: RegionId::Back, rect: back_rect(&ctx.m) });
        out.push(Region { id: self.commit().0, rect: l.commit });
        out.push(Region { id: RegionId::PinBackspace, rect: l.backspace });
        for (i, k) in l.keys.iter().enumerate() {
            out.push(Region { id: RegionId::PinKey(i as u8), rect: *k });
        }
    }

    fn draw<D: DrawTarget<Color = Rgb565>>(&self, t: &mut D, ctx: &Ctx) -> Result<(), D::Error> {
        let m = &ctx.m;
        draw_bar(t, m, self.title())?;
        let l = self.layout(ctx);

        // One bullet per character, and the run is the only feedback either entry gives. No
        // reveal toggle and no counter: the confirm step is what catches the typo a reveal
        // would have caught, and it catches it without ever putting the PIN on a panel
        // somebody else may be looking at.
        text_centered(t, &mask_run(self.typed(), l.dots), l.dots, MONO, INK_PRIMARY, PAPER_1)?;

        match self.body_copy(ctx.lock) {
            BodyCopy::Explanation(paras) => {
                let mut y = l.copy.y;
                for para in paras {
                    for line in wrap_words(&para, l.copy.w, BODY) {
                        text(t, &line, l.copy.x, y, BODY, INK_SECONDARY, PAPER_1)?;
                        y += SMALL_LINE;
                    }
                    y += PARA_GAP;
                }
            }
            BodyCopy::Refusal(why) => {
                let mut y = l.copy.y;
                for line in wrap_words(why, l.copy.w, BODY) {
                    text(t, &line, l.copy.x, y, BODY, WARNING, PAPER_1)?;
                    y += SMALL_LINE;
                }
            }
        }

        if let Some((sentence, ink)) = self.advice(ctx.lock) {
            let mut y = l.advice.y;
            for line in wrap_words(&sentence, l.advice.w, BODY) {
                text(t, &line, l.advice.x, y, BODY, ink, PAPER_1)?;
                y += SMALL_LINE;
            }
        }

        // No pressed state on a key, which is the half of C10 the 2026-08-19 reversal kept
        // and gave a stronger reason: on a FIXED pad a lit key is the digit itself, and an
        // 80 px cell lighting up is legible from across a room where a fingertip is not. The
        // press is confirmed on the dot row instead.
        for (i, k) in l.keys.iter().enumerate() {
            let digit = PIN_PAD.get(i).copied().unwrap_or(0);
            fill(t, *k, PAPER_3)?;
            frame(t, *k, BORDER_STRONG)?;
            let mut buf = [0u8; 4];
            let label = char::from(b'0' + digit).encode_utf8(&mut buf);
            text_centered(t, label, *k, MONO, INK_PRIMARY, PAPER_3)?;
        }
        // The two cells flanking the zero are drawn as BUTTONS, never as keys: a control
        // that looks like a digit is a mistap waiting to happen, and one of these two
        // formats the device.
        let bs = if self.typed() > 0 { ButtonKind::Secondary } else { ButtonKind::Disabled };
        button(t, l.backspace, BACKSPACE_LABEL, bs, PAPER_1)?;
        let (_, label) = self.commit();
        let kind = if self.ready(ctx.lock) { ButtonKind::Primary } else { ButtonKind::Disabled };
        button(t, l.commit, label, kind, PAPER_1)
    }

    fn activate(&mut self, id: RegionId, env: &mut Env) -> Outcome {
        match id {
            RegionId::PinKey(i) => {
                self.note = Note::None;
                if let Some(d) = PIN_PAD.get(i as usize).copied() {
                    let buf = self.active();
                    if buf.len() < PIN_MAX {
                        buf.push((b'0' + d) as char);
                    }
                }
                Outcome::stay()
            }
            RegionId::PinBackspace => {
                self.note = Note::None;
                self.active().pop();
                Outcome::stay()
            }
            // Step 1 -> step 2. Nothing is written and nothing leaves this screen: the
            // first entry stays in its buffer because the second one has to be compared
            // against it, and the confirm buffer is cleared in case this is a second pass.
            RegionId::PinNext if self.ready(env.lock) => {
                self.step = Step::Confirm;
                self.confirm.zeroize();
                Outcome::stay()
            }
            RegionId::PinConfirm if self.ready(env.lock) => {
                if !entries_match(&self.entry, &self.confirm) {
                    // Both entries go NOW rather than on the next keystroke: a rejected PIN
                    // left in a buffer is a secret kept for no reason, and returning to step
                    // 1 with step 1 intact would let a shoulder surfer resume somebody
                    // else's half-typed PIN.
                    self.forget();
                    self.note = Note::Mismatch;
                    return Outcome::stay();
                }
                // The PIN leaves as a `Secret` and this screen forgets it in the same
                // breath: from here until the embedder answers, the only copy in the process
                // is the one in flight.
                let pin = Secret::new(&self.entry);
                self.forget();
                self.note = Note::None;
                Outcome::ask(UiRequest::SetPin(pin))
            }
            // Both commits are drawn disabled with their reason on the line above; a tap
            // does nothing, which is what the paint already said.
            _ => Outcome::stay(),
        }
    }

    /// Back leaves the screen, and dropping it wipes both entries - which is S-07's "Back
    /// from step 2 clears both entries" kept by construction rather than by a handler that
    /// has to remember to do it. The fork underneath still holds the wallet, so the way back
    /// in is one tap and starts from an empty step 1.
    fn back(&self) -> Nav {
        Nav::Back
    }
}

/// The masked run, clipped to the row it is drawn in.
///
/// Clipped rather than trusted: [`PIN_MAX`] bullets are wider than either shipped panel, and
/// `text_centered` would centre the overflow and draw half of it off the display, where
/// nothing but the pixel gate can see it. Past the clip the run stops growing and [`AT_CAP`]
/// is what tells the user where they are.
fn mask_run(n: usize, row: Rect) -> String {
    let advance = MONO.glyph(BULLET).advance as i32;
    let fits = if advance > 0 { (row.w / advance).max(0) as usize } else { 0 };
    core::iter::repeat_n(BULLET, n.min(fits)).collect()
}

/// Whether the two entries are the same PIN.
///
/// The loop folds every difference into one accumulator and never returns early, so nothing
/// observable - not the time it takes, not a log line, and above all not a pixel - is a
/// function of WHERE the two differ. The screen is allowed to say that they did not match
/// and nothing more: a panel that pointed at the third character would hand a shoulder
/// surfer two thirds of a PIN for the price of one glance.
///
/// The lengths are folded into the same accumulator rather than short-circuited. That they
/// are visible on the panel as two bullet runs is true and is not the point; the point is
/// that this function has one exit and one bit of output.
fn entries_match(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    // Both lengths are capped at `PIN_MAX`, so the widening is exact and the XOR cannot
    // alias two different lengths onto zero.
    let mut diff = (a.len() as u32) ^ (b.len() as u32);
    for i in 0..a.len().max(b.len()) {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= u32::from(x ^ y);
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::TOUCH_MIN;
    use crate::screens::testing::{fits, rows_are_clear_on, Fixture, GEOMETRIES};
    use crate::canvas::HEADING;
    use crate::screens::{Env, Nav};
    use crate::{PIN_MIN_DEFAULT, WIPE_AFTER_DEFAULT};

    /// Every store status, walked rather than sampled: `StoreStatus` is not iterable and
    /// this crate does not own it, but [`refusal`] matches it exhaustively, so a new status
    /// fails to compile there and is caught here the moment it is added below.
    const ALL_STATUSES: [StoreStatus; 5] = [
        StoreStatus::NotProvisioned,
        StoreStatus::Blank,
        StoreStatus::Locked,
        StoreStatus::Unlocked,
        StoreStatus::Unreadable,
    ];
    use notyas_core::bitcoin::Network;

    /// A device in the state this screen is for: a device key, nothing sealed, the store's
    /// own floor and the policy it will format with.
    fn blank(f: &mut Fixture) {
        f.lock.status = StoreStatus::Blank;
        f.lock.min_pin_len = PIN_MIN_DEFAULT;
        f.lock.wipe_after = Some(WIPE_AFTER_DEFAULT);
    }

    fn typed(state: &mut SetPinState, n: usize) {
        for _ in 0..n {
            state.active().push('7');
        }
    }

    /// Both panels, both steps: nothing overlaps, nothing leaves the panel, and every
    /// control is still a target a finger can hit.
    #[test]
    fn the_screen_fits_both_panels_in_both_steps() {
        for (w, h) in GEOMETRIES {
            let mut f = Fixture::new(w, h);
            blank(&mut f);
            for step in [Step::Enter, Step::Confirm] {
                let mut s = SetPinState::new();
                s.step = step;
                let l = s.layout(&f.ctx());
                let what = format!("{w}x{h} {step:?}");
                let mut rows = vec![
                    ("dots", l.dots),
                    ("copy", l.copy),
                    ("advice", l.advice),
                    ("backspace", l.backspace),
                    ("commit", l.commit),
                ];
                for (i, k) in l.keys.iter().enumerate() {
                    // The tenth key shares its row with the two controls and must clear
                    // both, so it goes in with them rather than being checked apart.
                    rows.push((KEY_NAMES[i], *k));
                }
                rows_are_clear_on(&f.m, &what, f.m.screen(), &rows);

                // Touch floors: keypad keys carry their own, everything else the general
                // one. A key below the floor is a PIN typed wrong on a moving bus.
                for k in l.keys {
                    assert!(
                        k.w >= KEYPAD_KEY_MIN && k.h >= KEYPAD_KEY_MIN,
                        "{what}: a key is {}x{}, below the keypad floor",
                        k.w,
                        k.h
                    );
                }
                for (name, r) in [("backspace", l.backspace), ("commit", l.commit)] {
                    assert!(
                        r.w >= TOUCH_MIN && r.h >= TOUCH_MIN,
                        "{what}: {name} is {}x{}, below the touch floor",
                        r.w,
                        r.h
                    );
                }
            }
        }
    }

    const KEY_NAMES: [&str; 10] =
        ["key0", "key1", "key2", "key3", "key4", "key5", "key6", "key7", "key8", "key9"];

    /// Every string this screen can draw fits the block it is drawn in, at both geometries.
    ///
    /// The blocks are measured from the same functions the layout uses, so this is a claim
    /// about the COPY: a longer sentence fails here rather than being cropped on a device or
    /// drawn off the bottom of the column, which is the one failure a region check cannot
    /// see.
    #[test]
    fn every_sentence_fits_the_block_it_is_drawn_in() {
        for (w, h) in GEOMETRIES {
            let mut f = Fixture::new(w, h);
            blank(&mut f);
            let s = SetPinState::new();
            let l = s.layout(&f.ctx());
            let what = format!("{w}x{h}");
            for step in [Step::Enter, Step::Confirm] {
                let need = paragraph_h(&copy_for(step, &f.lock), l.copy.w);
                assert!(
                    need <= l.copy.h,
                    "{what} {step:?}: the copy needs {need} px and has {}",
                    l.copy.h
                );
            }
            // A refusal takes the same block, so it is measured against the same reserve:
            // it is shorter than the explanation on both panels today, and this is what says
            // so rather than assuming it.
            for status in ALL_STATUSES {
                if let Some(why) = refusal(status) {
                    let need = wrap_words(why, l.copy.w, BODY).len() as i32 * SMALL_LINE;
                    assert!(
                        need <= l.copy.h,
                        "{what} {status:?}: the refusal needs {need} px and has {}",
                        l.copy.h
                    );
                }
            }
            // The advice reserve holds the worst sentence, and the two blocks together stay
            // inside the column they share with the pad.
            assert!(
                advice_block_h(l.advice.w, &f.lock) <= l.advice.h,
                "{what}: the advice reserve is short of its own worst case"
            );
            let body = f.m.body();
            assert!(
                l.advice.bottom() <= body.bottom(),
                "{what}: the advice block ends at {} and the body ends at {}",
                l.advice.bottom(),
                body.bottom()
            );
            // The bar title is drawn beside Back and is neither wrapped nor measured by the
            // bar, so a longer one would run off the panel silently.
            let title_x = back_rect(&f.m).right() + f.m.gap;
            for title in ["Set a PIN - 1 of 2", "Set a PIN - 2 of 2"] {
                fits(
                    &what,
                    title,
                    HEADING.text_width(title) as i32,
                    Rect::new(title_x, 0, f.m.w - title_x, f.m.bar),
                );
            }
            // The commit and backspace labels are centred in a key-sized cell, and
            // `text_centered` crops rather than wraps.
            for label in [NEXT_LABEL, SET_LABEL, BACKSPACE_LABEL] {
                fits(&what, label, HEADING.text_width(label) as i32, l.commit);
            }
        }
    }

    /// A draw target that records the bounding box of everything it is ASKED to paint,
    /// including the pixels a real framebuffer discards.
    ///
    /// The rectangle checks above prove the blocks agree with the panel; they cannot see a
    /// string drawn wider than the block it was measured for, because that draw leaves no
    /// rectangle behind - which is exactly how an 800x480 panel once shipped with text drawn
    /// through other text. The simulator's pixel gate is the tree-wide answer to that, and
    /// this is the same question asked where it can be asked of one screen in isolation.
    struct Bounds {
        min: (i32, i32),
        max: (i32, i32),
    }

    impl Bounds {
        fn new() -> Bounds {
            Bounds { min: (i32::MAX, i32::MAX), max: (i32::MIN, i32::MIN) }
        }

        fn saw(&mut self, x: i32, y: i32) {
            self.min = (self.min.0.min(x), self.min.1.min(y));
            self.max = (self.max.0.max(x), self.max.1.max(y));
        }
    }

    impl embedded_graphics::geometry::Dimensions for Bounds {
        fn bounding_box(&self) -> embedded_graphics::primitives::Rectangle {
            embedded_graphics::primitives::Rectangle::new(
                embedded_graphics::geometry::Point::new(i32::MIN / 2, i32::MIN / 2),
                embedded_graphics::geometry::Size::new(u32::MAX, u32::MAX),
            )
        }
    }

    impl DrawTarget for Bounds {
        type Color = Rgb565;
        type Error = core::convert::Infallible;

        fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
        where
            I: IntoIterator<Item = embedded_graphics::Pixel<Rgb565>>,
        {
            for embedded_graphics::Pixel(p, _) in pixels {
                self.saw(p.x, p.y);
            }
            Ok(())
        }

        fn fill_solid(
            &mut self,
            area: &embedded_graphics::primitives::Rectangle,
            _color: Rgb565,
        ) -> Result<(), Self::Error> {
            if area.size.width == 0 || area.size.height == 0 {
                return Ok(());
            }
            self.saw(area.top_left.x, area.top_left.y);
            self.saw(
                area.top_left.x + area.size.width as i32 - 1,
                area.top_left.y + area.size.height as i32 - 1,
            );
            Ok(())
        }
    }

    /// Nothing this screen draws lands off the panel, in any state it has, on either panel.
    #[test]
    fn no_state_of_this_screen_draws_off_the_panel() {
        for (w, h) in GEOMETRIES {
            for status in ALL_STATUSES {
                for step in [Step::Enter, Step::Confirm] {
                    for note in [Note::None, Note::Mismatch, Note::Refused] {
                        // Empty, at the floor, and at the cap: the three lengths the dot row
                        // and the advice line behave differently at.
                        for n in [0, usize::from(PIN_MIN_DEFAULT), PIN_MAX] {
                            let mut f = Fixture::new(w, h);
                            blank(&mut f);
                            f.lock.status = status;
                            let mut s = SetPinState::new();
                            s.step = step;
                            typed(&mut s, n);
                            s.note = note;
                            let mut t = Bounds::new();
                            s.draw(&mut t, &f.ctx()).expect("the target is infallible");
                            let what = format!("{w}x{h} {status:?} {step:?} {note:?} n={n}");
                            // A target that saw nothing would pass every bound below, so
                            // the first claim is that the screen painted at all.
                            assert!(
                                t.max.0 > 0 && t.max.1 > 0,
                                "{what}: the screen drew nothing"
                            );
                            assert!(
                                t.min.0 >= 0 && t.min.1 >= 0,
                                "{what}: drew at {:?}, above or left of the panel",
                                t.min
                            );
                            assert!(
                                t.max.0 < w as i32 && t.max.1 < h as i32,
                                "{what}: drew at {:?} on a {w}x{h} panel",
                                t.max
                            );
                        }
                    }
                }
            }
        }
    }

    /// The recorder above has teeth: it sees a fill and a text run beyond the panel, which
    /// is the failure it exists to catch and the one a clipping framebuffer hides.
    #[test]
    fn the_bounds_target_sees_what_a_framebuffer_would_discard() {
        let mut t = Bounds::new();
        fill(&mut t, Rect::new(0, 0, 10, 10), PAPER_1).expect("infallible");
        assert_eq!((t.min, t.max), ((0, 0), (9, 9)));
        fill(&mut t, Rect::new(1000, 1000, 4, 4), PAPER_1).expect("infallible");
        assert_eq!(t.max, (1003, 1003), "a fill off the panel was not seen");
        let mut t = Bounds::new();
        text(&mut t, "off", 2000, 0, BODY, INK_PRIMARY, PAPER_1).expect("infallible");
        assert!(t.max.0 >= 2000, "a text run off the panel was not seen");
    }

    /// The masked run never leaves its row, even at the length cap.
    #[test]
    fn a_full_length_pin_masks_inside_its_row() {
        for (w, h) in GEOMETRIES {
            let mut f = Fixture::new(w, h);
            blank(&mut f);
            let l = SetPinState::new().layout(&f.ctx());
            let run = mask_run(PIN_MAX, l.dots);
            let width: i32 = run.chars().map(|c| MONO.glyph(c).advance as i32).sum();
            assert!(
                width <= l.dots.w,
                "{w}x{h}: a full-length mask is {width} px in a {} px row",
                l.dots.w
            );
        }
    }

    /// The floor is the DEVICE's, in the enable rule and in the sentence beside it.
    ///
    /// The regression this pins is the one that reached hardware from the other direction:
    /// a screen carrying its own floor while the store formatted at another. Here it would
    /// be worse - a PIN accepted at creation that the unlock screen will not accept back -
    /// so the test drives the floor from the value the store publishes and asserts both the
    /// button and the reason move with it.
    #[test]
    fn the_floor_is_read_from_the_store_and_never_from_a_constant() {
        for floor in [1u8, 4, 8, 12] {
            let mut f = Fixture::new(720, 720);
            blank(&mut f);
            f.lock.min_pin_len = floor;
            let mut s = SetPinState::new();
            for n in 0..usize::from(floor) {
                assert!(!s.ready(&f.lock), "floor {floor}: ready at {n} characters");
                let (sentence, _) = s.advice(&f.lock).expect("a disabled commit owes a reason");
                assert!(
                    sentence.contains(&format!("{floor}")),
                    "floor {floor}: the reason says {sentence:?}"
                );
                typed(&mut s, 1);
            }
            assert!(s.ready(&f.lock), "floor {floor}: not ready at the floor itself");
            assert!(
                s.advice(&f.lock).is_none(),
                "floor {floor}: a live commit still shows a reason"
            );
        }
    }

    /// A floor the store could not have meant is clamped rather than obeyed, in the
    /// direction that keeps the device usable: a floor of zero must not let an empty PIN
    /// format the store, and a floor above the cap must not make the commit permanently
    /// dead.
    #[test]
    fn an_impossible_floor_is_clamped_both_ways() {
        let mut f = Fixture::new(720, 720);
        blank(&mut f);
        f.lock.min_pin_len = 0;
        let mut s = SetPinState::new();
        assert!(!s.ready(&f.lock), "an empty PIN formatted the store");
        typed(&mut s, 1);
        assert!(s.ready(&f.lock), "one character is at the clamped floor");

        f.lock.min_pin_len = 255;
        let mut s = SetPinState::new();
        typed(&mut s, PIN_MAX);
        assert!(s.ready(&f.lock), "the cap is unreachable, so the commit is dead forever");
    }

    fn env<'a>(f: &'a Fixture, network: &'a mut Network) -> Env<'a> {
        Env { network, lock: &f.lock, wallets: &f.wallets }
    }

    /// The happy path: two identical entries raise the request that carries the PIN, and the
    /// screen keeps nothing.
    #[test]
    fn two_matching_entries_hand_the_pin_over_and_forget_it() {
        let mut f = Fixture::new(720, 720);
        blank(&mut f);
        let mut net = Network::Bitcoin;
        let mut s = SetPinState::new();
        typed(&mut s, 6);
        let out = s.activate(RegionId::PinNext, &mut env(&f, &mut net));
        assert_eq!(out.request, None, "the step change asks the embedder for nothing");
        assert_eq!(s.step, Step::Confirm);
        typed(&mut s, 6);
        let out = s.activate(RegionId::PinConfirm, &mut env(&f, &mut net));
        match out.request {
            Some(UiRequest::SetPin(pin)) => assert_eq!(pin.as_str(), "777777"),
            other => panic!("a matching confirm raised {other:?}"),
        }
        assert!(s.entry.is_empty() && s.confirm.is_empty(), "the PIN outlived the handover");
        assert_eq!(s.step, Step::Enter);
    }

    /// A mismatch says so, keeps neither entry, and starts over. Nothing is written and
    /// nothing is asked for but a fresh pad.
    #[test]
    fn a_mismatch_clears_both_entries_and_writes_nothing() {
        let mut f = Fixture::new(720, 720);
        blank(&mut f);
        let mut net = Network::Bitcoin;
        let mut s = SetPinState::new();
        typed(&mut s, 5);
        s.activate(RegionId::PinNext, &mut env(&f, &mut net));
        for _ in 0..5 {
            s.active().push('1');
        }
        let out = s.activate(RegionId::PinConfirm, &mut env(&f, &mut net));
        assert_eq!(out.request, None, "a mismatch must not ask the embedder for anything");
        assert!(matches!(out.nav, Nav::Stay));
        assert!(s.entry.is_empty() && s.confirm.is_empty(), "a rejected PIN was kept");
        assert_eq!(s.step, Step::Enter);
        let (sentence, ink) = s.advice(&f.lock).expect("a mismatch owes a sentence");
        assert_eq!(sentence, MISMATCH);
        assert_eq!(ink, DANGER);
        // ... and the news is cleared by the next key, so it cannot be read as a verdict on
        // what the user types next.
        s.activate(RegionId::PinKey(0), &mut env(&f, &mut net));
        assert_ne!(s.advice(&f.lock).map(|(s, _)| s), Some(String::from(MISMATCH)));
    }

    /// A refusal from the embedder reaches the user in words. The handler that logs and
    /// returns is the defect this asserts against.
    #[test]
    fn a_refused_write_is_reported_on_the_panel() {
        let mut f = Fixture::new(720, 720);
        blank(&mut f);
        let mut s = SetPinState::new();
        s.report_failure();
        let (sentence, ink) = s.advice(&f.lock).expect("a refusal owes a sentence");
        assert_eq!(sentence, REFUSED);
        assert_eq!(ink, DANGER);
    }

    /// A device that cannot be formatted says why, and its commit is dead in the paint and
    /// in the tap alike.
    #[test]
    fn a_store_that_cannot_be_formatted_says_so_instead_of_doing_nothing() {
        let mut net = Network::Bitcoin;
        for status in ALL_STATUSES {
            let mut f = Fixture::new(720, 720);
            blank(&mut f);
            f.lock.status = status;
            let mut s = SetPinState::new();
            typed(&mut s, 8);
            s.step = Step::Confirm;
            typed(&mut s, 8);
            let out = s.activate(RegionId::PinConfirm, &mut env(&f, &mut net));
            match refusal(status) {
                None => assert!(
                    matches!(out.request, Some(UiRequest::SetPin(_))),
                    "{status:?}: a formattable store refused the PIN"
                ),
                Some(why) => {
                    assert!(!s.ready(&f.lock), "{status:?}: the commit is live");
                    assert!(out.request.is_none(), "{status:?}: a refused store was written to");
                    match s.body_copy(&f.lock) {
                        BodyCopy::Refusal(shown) => {
                            assert_eq!(shown, why, "{status:?}: the wrong reason is shown")
                        }
                        BodyCopy::Explanation(_) => {
                            panic!("{status:?}: the refusal is not on the panel")
                        }
                    }
                }
            }
        }
    }

    /// The comparison answers one bit and never says where.
    #[test]
    fn entries_match_is_total_and_positionless() {
        assert!(entries_match("1234", "1234"));
        assert!(entries_match("", ""));
        assert!(!entries_match("1234", "1235"));
        assert!(!entries_match("1234", "2234"));
        assert!(!entries_match("1234", "12345"));
        assert!(!entries_match("12345", "1234"));
        // A difference in the first character and one in the last are the same answer, which
        // is the property that keeps the screen from leaking a position.
        assert_eq!(entries_match("1234", "9234"), entries_match("1234", "1239"));
    }

    /// A key types the digit DRAWN on it, and the two PIN pads draw the same digit on the
    /// same slot: phone order, 1-2-3 / 4-5-6 / 7-8-9 with the zero centred under them.
    ///
    /// Asserted through `activate` rather than against the constant alone, because what
    /// matters is the round trip - the slot a finger lands on types the digit the user read
    /// there - and that is the property a create screen with its own pad would break.
    #[test]
    fn a_key_types_the_digit_drawn_on_it() {
        let mut f = Fixture::new(720, 720);
        blank(&mut f);
        let mut net = Network::Bitcoin;
        let mut s = SetPinState::new();
        for pos in 0..10u8 {
            s.activate(RegionId::PinKey(pos), &mut env(&f, &mut net));
        }
        assert_eq!(&*s.entry, "1234567890");
        // The slot the layout puts in the bottom-centre cell is the one that carries the
        // zero, which is where fifty years of keypads have put it.
        let l = s.layout(&f.ctx());
        assert_eq!(l.keys[9].y, l.backspace.y, "the zero is on the last row");
        assert!(l.keys[9].x > l.commit.x && l.keys[9].x < l.backspace.x, "and between them");
    }

    /// The cap is a stop, not a wrap: further keys are ignored and the reason says so.
    #[test]
    fn the_length_cap_stops_the_entry_and_states_itself() {
        let mut f = Fixture::new(720, 720);
        blank(&mut f);
        let mut net = Network::Bitcoin;
        let mut s = SetPinState::new();
        for _ in 0..PIN_MAX + 8 {
            s.activate(RegionId::PinKey(0), &mut env(&f, &mut net));
        }
        assert_eq!(s.entry.len(), PIN_MAX);
        assert_eq!(s.advice(&f.lock).map(|(t, _)| t), Some(String::from(AT_CAP)));
    }
}

