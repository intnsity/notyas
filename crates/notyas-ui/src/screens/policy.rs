// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! S-44's wrong-PIN policy: a LIVE EDITOR over the sealed policy, and the one screen that
//! states what turning the protection off actually costs.
//!
//! Four things here are acceptance criteria rather than wording, and each is written
//! where it is for a reason worth keeping:
//!
//! 1. **The threshold is always shown** (Q37). It tells the user the consequence of their
//!    next mistake and it leaks nothing a coercer could not get by trying one wrong PIN.
//!    Every number on this screen is a format string over runtime state - `N` is now
//!    editable, so a literal would be wrong the moment it was edited.
//!
//! 2. **The power-cut disclosure is ON THE SCREEN**, not in a manual. An interrupted
//!    verification consumes an attempt even when the PIN was right, because otherwise
//!    cutting power at the right moment would be a free guess. On a device carried in a
//!    bag that means the counter can advance with no wrong PIN ever entered - the m4a
//!    power-cut gate of 2026-08-18 walked exactly that path twenty times - and a user who
//!    does not know it will conclude the device is broken or that someone tried their PIN.
//!
//! 3. **Disabling the wipe states the arithmetic at the moment of the change.** Computed
//!    from the PIN ACTUALLY IN FORCE and the per-guess cost ACTUALLY MEASURED on this
//!    board (`crate::guess`), never a generic sentence: a 4-digit PIN and a 12-digit PIN
//!    are not the same decision. It takes a typed confirmation, and it offers the
//!    longer-PIN path as an ACTION beside accept and cancel, because that is the answer
//!    which makes the warning stop being true. No PIN-length precondition is enforced -
//!    the owner decided (Q62) the device states the trade rather than withholding the
//!    setting - and the floor is nevertheless implemented as a parameter
//!    ([`crate::WIPE_DISABLE_MIN_PIN`]) so that revisiting it is a constant, not a
//!    rewrite.
//!
//! 4. Committing is a BUTTON, not a live write. The policy is authenticated inside the
//!    AEAD (PIN-MODES.md), so changing it re-seals the store under the PIN; a stepper that
//!    wrote per tap would spend a flash erase and a two-second Argon2id stretch on every
//!    digit. The C12 notice above the button says what the write is before it happens.

use alloc::string::String;
use alloc::vec::Vec;

use embedded_graphics::draw_target::{DrawTarget, DrawTargetExt};
use embedded_graphics::pixelcolor::Rgb565;

use crate::canvas::{button, text, text_centered, wrap_words, ButtonKind, BODY, MONO, MONO_SMALL};
use crate::components::{back_rect, draw_bar, write_notice, write_notice_h, LINE, SMALL_LINE};
use crate::danger::{Danger, DangerGrade, DangerOutcome};
use crate::guess::{floor_blocks, Search};
use crate::layout::{Metrics, Rect};
use crate::screens::{Ctx, Env, Nav, Outcome, Screen};
use crate::theme::*;
use crate::{
    LockInfo, NullTarget, PinShape, Region, RegionId, StoredCounts, UiRequest, WIPE_AFTER_DEFAULT,
    WIPE_AFTER_MAX, WIPE_AFTER_MIN, WIPE_DISABLE_MIN_PIN,
};

/// The word typed back to turn the wipe off. Short and unambiguous: it names the state
/// being chosen, so the moment of consent describes itself.
const OFF_WORD: &str = "OFF";

/// The C12 copy: what the save writes, then what anyone who reads it could learn. Named
/// constants because the band is SIZED from them - `write_notice_h` measures the wrap on
/// the width the band actually gets, so the sentence grows the band instead of running
/// out of it.
const WRITE_WHAT: &str = "This writes to the device: the wrong-PIN policy.";
const WRITE_CONFIDENTIALITY: &str =
    "Stored wallets are re-sealed. No seed is written or changed.";

/// Width of a stepper key. A physical floor, like the keypad's: fingers do not scale.
const STEP_W: i32 = 80;
/// Width of the threshold reading between the stepper keys. Wide enough for its own
/// caption in the mono face, because a bare number is a number the reader has to guess the
/// meaning of.
const STEP_LABEL_W: i32 = 180;
/// Width of the whole `[-] N [+]` stepper. Every part of it is a physical floor, so this
/// is one too: the rail that carries it is sized FROM this rather than from a proportion
/// of the panel.
const STEP_BLOCK: i32 = 2 * STEP_W + STEP_LABEL_W;

pub(crate) struct PolicyState {
    /// The policy as the user has edited it, or `None` while the screen is still showing
    /// what the store holds.
    ///
    /// An OPTION OVER the stored value rather than a copy of it: the embedder installs a
    /// fresh [`LockInfo`] after every operation that can move the policy, and a screen
    /// that had snapshotted the threshold at construction would keep showing the old one
    /// after its own save succeeded.
    edit: Option<Option<u8>>,
    scroll: i32,
    /// The open turn-it-off confirmation, if any. Two sheets in sequence: the arithmetic,
    /// then the word (see [`crate::danger`]).
    danger: Option<Danger>,
    /// The verdict on the last save, or `None` before one was asked for. A refused write
    /// is reported, never swallowed.
    saved: Option<bool>,
}

impl PolicyState {
    pub fn new() -> PolicyState {
        PolicyState { edit: None, scroll: 0, danger: None, saved: None }
    }

    /// Answer to [`UiRequest::SetWipePolicy`]. On success the edit is dropped, so the
    /// screen goes back to showing the store - which the embedder is about to update.
    pub fn install_result(&mut self, saved: bool) {
        if saved {
            self.edit = None;
        }
        self.saved = Some(saved);
    }

    /// The policy the screen is showing: the user's edit if there is one, otherwise the
    /// store's. `None` means the wipe is off.
    fn shown(&self, lock: &LockInfo) -> Option<u8> {
        self.edit.unwrap_or(lock.wipe_after)
    }

    /// Whether there is an uncommitted change. An edit back to the stored value is not
    /// one, so a user who steps up and down again is not offered a pointless re-seal.
    fn dirty(&self, lock: &LockInfo) -> bool {
        self.edit.is_some_and(|e| e != lock.wipe_after)
    }

    /// The exhaustive-search arithmetic for the PIN in force, or `None` where the device
    /// did not record its shape.
    fn search(lock: &LockInfo) -> Option<Search> {
        lock.pin.map(|shape| Search::new(shape, lock.unlock_ms))
    }

    /// C4b: the arithmetic AT THE MOMENT OF THE CHANGE (criterion 3), computed from the
    /// PIN actually set and the per-guess cost actually measured on this board.
    ///
    /// The unknown-shape branch says so rather than inventing a number for a PIN the
    /// device never measured - the same rule the Verify screen keeps for every value it
    /// did not read.
    fn review_sheet(lock: &LockInfo) -> Danger {
        // ONE paragraph, four lines: that is what the 800x480 sheet holds once the
        // third answer has its row, and every word here is load bearing. The numbers come
        // first because they are the decision; the trade and the reassurance follow in
        // the same breath so neither can be cut off without the other going with it.
        let arithmetic = match (lock.pin, Self::search(lock)) {
            (Some(shape), Some(s)) => format!(
                "{} {}s give {} PINs. At {} a guess, all of them take {} - the only limit \
                 once erasing is off. Nothing stored is lost.",
                shape.len,
                unit(shape),
                s.keyspace_text(),
                s.per_guess_text(),
                s.worst_text()
            ),
            _ => String::from(
                "This device did not record its PIN length, so it cannot say how long \
                 guessing would take. That time is the only limit once erasing is off. \
                 Nothing stored is lost.",
            ),
        };
        Danger::confirm("Turn off erasing after wrong PINs?", &[&arithmetic], "Turn off erasing")
        // The third answer, and the reason this sheet is not a plain yes/no: a longer PIN
        // is what makes the warning stop being true, and a warning that offers only accept
        // or cancel hides the good option (PIN-MODES.md).
        .with_alternative("Use a longer PIN instead")
    }

    /// C4d: the word, with the punchline restated so consent is given against it.
    fn type_sheet() -> Danger {
        Danger::typed(
            "Turn off erasing",
            &["Guessing this PIN is then limited only by time."],
            "Turn off erasing",
            OFF_WORD,
        )
    }
}

/// "digit" or "character", so the sentence describes the PIN the user actually has.
fn unit(shape: PinShape) -> &'static str {
    if shape.alphabet == PinShape::DIGITS {
        "digit"
    } else {
        "character"
    }
}

pub(crate) struct Layout {
    /// The scrolling explanation. Everything that has to be READ, and the only part that
    /// gives when the panel is short.
    viewport: Rect,
    /// Turn erasing on, or open the sheet that turns it off.
    wipe: Rect,
    less: Rect,
    count: Rect,
    more: Rect,
    notice: Rect,
    save: Rect,
}

impl Screen for PolicyState {
    type Layout = Layout;

    /// The write band and its button are the FLOOR of this screen and are laid out first,
    /// from the bottom of the body up; the editing controls take a fixed block above them
    /// and the explanation takes what is left, because prose is the only part here that
    /// can scroll.
    ///
    /// Three things about that order are load bearing:
    ///
    /// - The band is sized by [`write_notice_h`] at the width it is actually given. A
    ///   fixed two-line reservation is what put the second half of the sentence off the
    ///   bottom of the 800x480 panel: the same copy wraps to four lines across the body
    ///   and to nine inside a 300 px rail.
    /// - The band spans the WHOLE body width on every panel, and the rail keeps the
    ///   controls beside the prose instead. Height is what a 480-tall panel is short of,
    ///   and a narrower band buys width back at 36 px of height per line lost.
    /// - The band's bottom edge IS the button's top edge. C12 asks for the announcement
    ///   directly above the action, and reading them as one unit rather than two spaced
    ///   ones is also what leaves the 800x480 rail the room it needs.
    ///
    /// The band keeps that height whether or not there is a write to announce, so tapping
    /// the stepper never moves the prose or the Save button out from under the finger.
    fn layout(&self, ctx: &Ctx) -> Layout {
        let m: &Metrics = &ctx.m;
        let body = m.body();
        let btn = m.btn.min(80);

        let save = Rect::new(body.x, body.bottom() - btn, body.w, btn);
        let notice_h = write_notice_h(body.w, WRITE_WHAT, WRITE_CONFIDENTIALITY);
        let notice = Rect::new(body.x, save.y - notice_h, body.w, notice_h);
        // What is left for the prose and the two editing controls.
        let upper = Rect::new(body.x, body.y, body.w, notice.y - m.gap - body.y);

        // Portrait has width to spare and no height, so the switch and the stepper share
        // the one row above the band. Landscape has the opposite problem: the controls
        // move BESIDE the prose (reflow rule 1) into a rail exactly as wide as the
        // stepper it carries - a physical floor, like the keypad's, not a proportion of
        // the panel. A 2/5 rail was NARROWER than the stepper on the 800x480 panel, which
        // put its keys over the text they are supposed to sit beside.
        let (view, wipe, step_y) = if m.landscape() {
            let rail_x = body.right() - STEP_BLOCK;
            (
                Rect::new(upper.x, upper.y, rail_x - m.gap - upper.x, upper.h),
                Rect::new(rail_x, upper.y, STEP_BLOCK, btn),
                upper.y + btn + m.gap,
            )
        } else {
            let row_y = upper.bottom() - btn;
            (
                Rect::new(upper.x, upper.y, upper.w, row_y - m.gap - upper.y),
                Rect::new(upper.x, row_y, upper.w - STEP_BLOCK - m.gap, btn),
                row_y,
            )
        };
        // Trimmed to whole body lines so the clip never slices a sentence in half, which
        // reads as a rendering fault rather than as "there is more below".
        let viewport = Rect::new(view.x, view.y, view.w, (view.h / LINE * LINE).max(0));

        // The stepper is `[-] N [+]`, and the count between the keys is wide enough for
        // its own caption: a number with no unit beside it is a number the reader has to
        // guess the meaning of.
        let less = Rect::new(body.right() - STEP_BLOCK, step_y, STEP_W, btn);
        let more = Rect::new(body.right() - STEP_W, step_y, STEP_W, btn);
        let count = Rect::new(less.right(), step_y, more.x - less.right(), btn);
        Layout { viewport, wipe, less, count, more, notice, save }
    }

    fn regions(&self, ctx: &Ctx, out: &mut Vec<Region>) {
        if let Some(d) = &self.danger {
            d.regions(&ctx.m, out);
            return;
        }
        let l = self.layout(ctx);
        out.push(Region { id: RegionId::Back, rect: back_rect(&ctx.m) });
        // A floor that withholds the OFF direction withholds the CONTROL, not just the
        // outcome: a button that opens a sheet whose answer is refused is worse than one
        // that is visibly unavailable with its reason stated below.
        if !wipe_blocked(ctx.lock, self.shown(ctx.lock)) {
            out.push(Region { id: RegionId::PolicyWipe, rect: l.wipe });
        }
        // The stepper exists only while there is a threshold to step. A drawn control
        // that is hit-tested but inert is the "silent dead button" the crate forbids; the
        // disabled state below carries its reason instead.
        if self.shown(ctx.lock).is_some() {
            out.push(Region { id: RegionId::PolicyLess, rect: l.less });
            out.push(Region { id: RegionId::PolicyMore, rect: l.more });
        }
        if self.dirty(ctx.lock) {
            out.push(Region { id: RegionId::PolicySave, rect: l.save });
        }
    }

    fn draw<D: DrawTarget<Color = Rgb565>>(&self, t: &mut D, ctx: &Ctx) -> Result<(), D::Error> {
        let m = &ctx.m;
        if let Some(d) = &self.danger {
            return d.draw(t, m, ctx.press, ctx.hold_released);
        }
        draw_bar(t, m, "Wrong-PIN policy")?;
        let l = self.layout(ctx);

        let mut clip = t.clipped(&l.viewport.to_eg());
        content(&mut clip, m, self, ctx, l.viewport, l.viewport.y - self.scroll)?;

        let shown = self.shown(ctx.lock);
        let (label, kind) = match shown {
            Some(_) if wipe_blocked(ctx.lock, shown) => ("Turn off erasing", ButtonKind::Disabled),
            Some(_) => ("Turn off erasing", ButtonKind::Secondary),
            None => ("Turn on erasing", ButtonKind::Primary),
        };
        button(t, l.wipe, label, kind, PAPER_1)?;

        // The stepper. Its bounds are the sealed format's, not a preference (the attempt
        // log's tail reserve is sized to the ceiling), so an end stop is a fact about the
        // store and is drawn as one.
        let at_min = shown == Some(WIPE_AFTER_MIN);
        let at_max = shown == Some(WIPE_AFTER_MAX);
        let step_kind = |off: bool| {
            if shown.is_none() || off {
                ButtonKind::Disabled
            } else {
                ButtonKind::Secondary
            }
        };
        button(t, l.less, "-", step_kind(at_min), PAPER_1)?;
        button(t, l.more, "+", step_kind(at_max), PAPER_1)?;
        match shown {
            Some(n) => {
                let number = Rect::new(l.count.x, l.count.y, l.count.w, l.count.h - SMALL_LINE);
                text_centered(t, &format!("{n}"), number, MONO, INK_PRIMARY, PAPER_1)?;
                let caption = Rect::new(l.count.x, number.bottom(), l.count.w, SMALL_LINE);
                text_centered(t, "wrong PINs", caption, MONO_SMALL, INK_MUTED, PAPER_1)?;
            }
            None => text_centered(t, "no limit", l.count, MONO_SMALL, INK_MUTED, PAPER_1)?,
        }

        // C12: the write is announced BEFORE it happens, directly above the control that
        // performs it - and when there is nothing to write, the same band says so, which
        // is the disabled Save button's reason.
        if self.dirty(ctx.lock) {
            write_notice(t, l.notice, WRITE_WHAT, WRITE_CONFIDENTIALITY)?;
            button(t, l.save, "Save policy", ButtonKind::Primary, PAPER_1)?;
        } else {
            let (line, ink) = match self.saved {
                Some(true) => ("Saved. This is the policy in force.", SUCCESS),
                Some(false) => ("Not saved. The device refused the change.", DANGER),
                None => ("No change to save.", INK_MUTED),
            };
            // Sat on the BOTTOM of the band, where the notice's last line would be: the
            // band is reserved at the write's height on every state so nothing moves when
            // one begins, and the reason for a disabled button belongs against it, not
            // floating a paragraph above it.
            let wrapped = wrap_words(line, l.notice.w, BODY);
            let y0 = l.notice.bottom() - wrapped.len() as i32 * LINE;
            for (i, w) in wrapped.iter().enumerate() {
                text(t, w, l.notice.x, y0 + i as i32 * LINE, BODY, ink, PAPER_1)?;
            }
            button(t, l.save, "Save policy", ButtonKind::Disabled, PAPER_1)?;
        }
        Ok(())
    }

    fn activate(&mut self, id: RegionId, env: &mut Env) -> Outcome {
        let lock = env.lock;
        // The sheet, while open, answers for the whole screen.
        if let Some(d) = &mut self.danger {
            let outcome = d.activate(id);
            let grade = d.grade();
            return match outcome {
                DangerOutcome::Open => Outcome::stay(),
                DangerOutcome::Cancelled => {
                    self.danger = None;
                    Outcome::stay()
                }
                // The longer-PIN path. It leaves the policy exactly as it was - the point
                // is to remove the REASON for the warning, not to accept it - and hands
                // the change-PIN sequence to the side that owns the PIN and the re-seal.
                DangerOutcome::Alternative => {
                    self.danger = None;
                    Outcome::ask(UiRequest::ChangePin)
                }
                DangerOutcome::Confirmed => match grade {
                    // The arithmetic has been read; the word is next. Never the change.
                    DangerGrade::Confirm => {
                        self.danger = Some(Self::type_sheet());
                        Outcome::stay()
                    }
                    // STAGED, not written: the policy lives inside the AEAD, so the write
                    // is the Save button and its C12 notice. Consent and write are
                    // deliberately separate acts.
                    _ => {
                        self.danger = None;
                        self.edit = Some(None);
                        self.saved = None;
                        Outcome::stay()
                    }
                },
            };
        }
        match id {
            RegionId::PolicyWipe if !wipe_blocked(lock, self.shown(lock)) => {
                self.saved = None;
                match self.shown(lock) {
                    // Turning it OFF is the only direction that needs a gate. Turning it
                    // on is the protective direction and should feel routine.
                    Some(_) => self.danger = Some(Self::review_sheet(lock)),
                    None => self.edit = Some(Some(restore_threshold(lock))),
                }
                Outcome::stay()
            }
            RegionId::PolicyLess => self.step(lock, -1),
            RegionId::PolicyMore => self.step(lock, 1),
            RegionId::PolicySave if self.dirty(lock) => {
                Outcome::ask(UiRequest::SetWipePolicy { wipe_after: self.shown(lock) })
            }
            _ => Outcome::stay(),
        }
    }

    fn back(&self) -> Nav {
        Nav::Back
    }

    fn scroll_mut(&mut self) -> Option<&mut i32> {
        // A sheet freezes the page under it, scrolling included.
        match self.danger {
            None => Some(&mut self.scroll),
            Some(_) => None,
        }
    }

    fn scroll_limit(&self, ctx: &Ctx) -> i32 {
        let view = self.layout(ctx).viewport;
        // Measured with the same walk that paints, so the bound cannot drift from what is
        // on the panel.
        let end = content(&mut NullTarget, &ctx.m, self, ctx, view, view.y).unwrap_or_default();
        (end - view.y - view.h).max(0)
    }
}

impl PolicyState {
    /// Step the threshold within the sealed format's bounds. An absolute value rather than
    /// an accumulated offset, so an end stop is an end stop and one tap the other way
    /// moves off it.
    fn step(&mut self, lock: &LockInfo, by: i32) -> Outcome {
        if let Some(n) = self.shown(lock) {
            let next = (i32::from(n) + by).clamp(i32::from(WIPE_AFTER_MIN), i32::from(WIPE_AFTER_MAX));
            self.edit = Some(Some(next as u8));
            self.saved = None;
        }
        Outcome::stay()
    }
}

/// Whether the configured floor withholds the OFF direction from the PIN in force.
///
/// Only the OFF direction can ever be withheld; turning erasing on is the protective
/// direction and is never refused. As shipped this is always false - the owner decided
/// (Q62) the device states the trade rather than withholding the setting - and it is
/// written as a live check so that changing [`WIPE_DISABLE_MIN_PIN`] is the whole of
/// revisiting that decision.
fn wipe_blocked(lock: &LockInfo, shown: Option<u8>) -> bool {
    shown.is_some() && floor_blocks(lock.pin, WIPE_DISABLE_MIN_PIN)
}

/// The threshold the wipe comes back on at: whatever the store last held, or the ratified
/// default (Q5) on a device whose policy has only ever been off.
fn restore_threshold(lock: &LockInfo) -> u8 {
    lock.wipe_after.unwrap_or(WIPE_AFTER_DEFAULT)
}

/// The explanation, in the frozen order. Drawing and measuring are the same walk, so the
/// scroll bound cannot drift from what is painted.
fn content<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    m: &Metrics,
    state: &PolicyState,
    ctx: &Ctx,
    view: Rect,
    y0: i32,
) -> Result<i32, D::Error> {
    let shown = state.shown(ctx.lock);
    let counts = StoredCounts::of(ctx.wallets);
    let w = view.w;
    let mut y = y0;

    // 1. What is in force, with the threshold always stated (Q37).
    let now = match (shown, ctx.lock.attempts_left) {
        (Some(n), Some(left)) => vec![
            format!("After {n} wrong PINs this device erases everything it has stored."),
            format!("{left} of {n} tries are left right now."),
        ],
        (Some(n), None) => {
            vec![format!("After {n} wrong PINs this device erases everything it has stored.")]
        }
        (None, _) => vec![String::from(
            "This device does not erase after wrong PINs. Someone holding it can keep trying \
             for as long as they like.",
        )],
    };
    y = block(t, m, view.x, y, "Now", &now, w)?;

    // 2. What a wipe costs, with counts read from the store (post-PIN, so Q2(a) permits
    //    them here and nowhere before the PIN).
    let destroys = vec![
        format!(
            "A wipe erases {} and {}, with their names and settings.",
            counts.wallets_text(),
            counts.registrations_text()
        ),
        String::from(
            "Your dice rolls or seed words bring the coins back. The registrations, the names \
             and the settings do not come back.",
        ),
    ];
    y = block(t, m, view.x, y, "If it erases", &destroys, w)?;

    // 3. The power-cut disclosure (criterion 2). It is on the screen because a user who
    //    does not know it reads a dropped counter as evidence that someone tried their PIN.
    let power = vec![
        String::from(
            "If power is lost while a PIN is being checked, that attempt still counts. \
             Otherwise cutting power at the right moment would be a free way to guess.",
        ),
        String::from(
            "So on a device you carry, the counter can move without a wrong PIN ever being \
             typed. A count that has dropped is not proof that anyone tried yours.",
        ),
    ];
    y = block(t, m, view.x, y, "Power cuts", &power, w)?;

    // 4. The arithmetic, visible before the switch is touched rather than only after.
    let guessing = match (ctx.lock.pin, PolicyState::search(ctx.lock)) {
        (Some(shape), Some(s)) => vec![format!(
            concat!(
                "This device checks one PIN every {}. {} {}s give {} PINs, so trying all ",
                "of them takes {} - about {} on average."
            ),
            s.per_guess_text(),
            shape.len,
            unit(shape),
            s.keyspace_text(),
            s.worst_text(),
            s.mean_text()
        )],
        _ => vec![String::from(
            "This device did not record how long its PIN is, so it cannot state how long \
             guessing every one would take.",
        )],
    };
    y = block(t, m, view.x, y, "Guessing this PIN", &guessing, w)?;

    // 5. Present only where a floor is configured and the PIN is under it, which as
    //    shipped is never (Q62). It is the disabled wipe button's reason, and it lives
    //    with the other explanations rather than in the control rail, where it would
    //    collide with the C12 notice.
    if wipe_blocked(ctx.lock, shown) {
        let floor = WIPE_DISABLE_MIN_PIN.unwrap_or(0);
        let have = ctx.lock.pin.map_or(0, |p| p.len);
        let why = vec![format!(
            concat!(
                "Turning erasing off needs a PIN of at least {} characters. ",
                "This one has {}. Change the PIN first."
            ),
            floor,
            have
        )];
        y = block(t, m, view.x, y, "Not available", &why, w)?;
    }

    Ok(y)
}

/// One captioned block of prose; returns the next y.
fn block<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    m: &Metrics,
    x: i32,
    y: i32,
    caption: &str,
    paragraphs: &[String],
    w: i32,
) -> Result<i32, D::Error> {
    text(t, caption, x, y, MONO_SMALL, INK_MUTED, PAPER_1)?;
    let mut y = y + SMALL_LINE;
    for para in paragraphs {
        for line in wrap_words(para, w, BODY) {
            text(t, &line, x, y, BODY, INK_SECONDARY, PAPER_1)?;
            y += LINE;
        }
    }
    Ok(y + m.gap)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canvas::HEADING;
    use crate::layout::{TOUCH_MIN, PANELS};
    use crate::screens::testing::{fits, rows_are_clear_on, Fixture, GEOMETRIES};
    use crate::{StoreStatus, UNLOCK_MS_M1};

    fn unlocked(w: u32, h: u32, wipe_after: Option<u8>, pin: Option<PinShape>) -> Fixture {
        let mut f = Fixture::new(w, h);
        f.lock.status = StoreStatus::Unlocked;
        f.lock.wipe_after = wipe_after;
        f.lock.attempts_left = wipe_after;
        f.lock.pin = pin;
        f.lock.unlock_ms = UNLOCK_MS_M1;
        f
    }

    /// The controls keep their physical floors and stay inside the body on EVERY shipped
    /// panel, and nothing lands on anything else - the prose included. The viewport is a
    /// row here rather than a backdrop: a rail narrower than the stepper it carries puts
    /// the keys over the text, and only measuring the two against each other says so.
    #[test]
    fn the_editor_lays_out_on_every_panel() {
        for (w, h) in PANELS {
            let f = unlocked(w, h, Some(10), Some(PinShape { len: 6, alphabet: 10 }));
            let ctx = f.ctx();
            let l = PolicyState::new().layout(&ctx);
            let what = format!("{w}x{h} wipe policy");
            let rows = [
                ("viewport", l.viewport),
                ("wipe", l.wipe),
                ("less", l.less),
                ("count", l.count),
                ("more", l.more),
                ("notice", l.notice),
                ("save", l.save),
            ];
            rows_are_clear_on(&ctx.m, &what, ctx.m.body(), &rows);
            for (name, r) in rows {
                assert!(r.w > 0 && r.h > 0, "{what}: {name} is empty");
            }
            for (name, r) in [("wipe", l.wipe), ("less", l.less), ("more", l.more), ("save", l.save)]
            {
                assert!(r.h >= TOUCH_MIN, "{what}: {name} below the touch floor: {r:?}");
            }
            assert!(l.less.w >= TOUCH_MIN && l.more.w >= TOUCH_MIN, "{what}: stepper too narrow");
            // The labels the switch has to carry at its narrowest, which on a landscape
            // panel is the stepper's physical floor rather than a share of the width.
            for label in ["Turn off erasing", "Turn on erasing", "Save policy"] {
                let r = if label == "Save policy" { l.save } else { l.wipe };
                fits(&what, label, HEADING.text_width(label) as i32, r);
            }
            // The prose is the part that gives, but it gives down to a paragraph, not to a
            // caption: everything on this screen has to be read.
            assert_eq!(l.viewport.h % LINE, 0, "{what}: the viewport slices a line in half");
            assert!(l.viewport.h >= 3 * LINE, "{what}: {} px of prose left", l.viewport.h);
        }
    }

    /// The C12 band holds the notice it draws, on every panel.
    ///
    /// `write_notice` WRAPS both of its sentences to the width of the band it is given, so
    /// a band reserved at a fixed line count is a promise about the copy that nothing
    /// keeps: these two sentences take four lines across the body of the 800x480 panel and
    /// nine inside a 300 px rail. The paint is not clipped, so the overflow does not stop
    /// at the band - it runs through the Save button and off the bottom of the glass,
    /// taking the half of the sentence that says what is written with it.
    ///
    /// Measured through `write_notice_h`, the same function the band is sized with, so the
    /// assertion cannot drift from the paint.
    #[test]
    fn the_write_band_holds_the_notice_it_draws() {
        for (w, h) in PANELS {
            let f = unlocked(w, h, Some(10), Some(PinShape { len: 6, alphabet: 10 }));
            let ctx = f.ctx();
            let l = PolicyState::new().layout(&ctx);
            let need = write_notice_h(l.notice.w, WRITE_WHAT, WRITE_CONFIDENTIALITY);
            assert!(
                need <= l.notice.h,
                "{w}x{h}: the C12 notice needs {need} px in a {} px band ({:?})",
                l.notice.h,
                l.notice
            );
            // The unedited state paints its reason in the same band, in the body face.
            for line in [
                "Saved. This is the policy in force.",
                "Not saved. The device refused the change.",
                "No change to save.",
            ] {
                let need = wrap_words(line, l.notice.w, BODY).len() as i32 * LINE;
                assert!(need <= l.notice.h, "{w}x{h}: {line:?} needs {need} px of {}", l.notice.h);
            }
        }
    }

    /// The arithmetic sheet must FIT: it is the whole reason the setting is not withheld
    /// (Q62), and a warning half drawn at the moment of consent is worse than none. Every
    /// PIN shape the sentence can be built from is checked, because the numbers change its
    /// length - a 4-digit PIN priced in hours and a 12-digit one priced in years do not
    /// wrap alike.
    #[test]
    fn the_wipe_off_sheets_fit_on_both_panels() {
        for (w, h) in GEOMETRIES {
            for pin in [
                Some(PinShape { len: 4, alphabet: 10 }),
                Some(PinShape { len: 6, alphabet: 10 }),
                Some(PinShape { len: 12, alphabet: 10 }),
                Some(PinShape { len: 8, alphabet: 36 }),
                Some(PinShape { len: 64, alphabet: 10 }),
                None,
            ] {
                let f = unlocked(w, h, Some(10), pin);
                for sheet in [PolicyState::review_sheet(&f.lock), PolicyState::type_sheet()] {
                    let (used, have) = sheet.text_budget(&f.m);
                    assert!(
                        used <= have,
                        "{w}x{h} pin {pin:?}: the copy needs {used} px of {have}"
                    );
                }
            }
        }
    }

    /// The stepper never leaves the sealed format's bounds, and an end stop is not sticky.
    #[test]
    fn the_threshold_stays_inside_the_format_bounds() {
        let f = unlocked(720, 720, Some(WIPE_AFTER_MIN), Some(PinShape { len: 6, alphabet: 10 }));
        let mut s = PolicyState::new();
        for _ in 0..5 {
            s.step(&f.lock, -1);
        }
        assert_eq!(s.shown(&f.lock), Some(WIPE_AFTER_MIN));
        s.step(&f.lock, 1);
        assert_eq!(s.shown(&f.lock), Some(WIPE_AFTER_MIN + 1), "the floor must not stick");

        let f = unlocked(720, 720, Some(WIPE_AFTER_MAX), None);
        let mut s = PolicyState::new();
        for _ in 0..5 {
            s.step(&f.lock, 1);
        }
        assert_eq!(s.shown(&f.lock), Some(WIPE_AFTER_MAX));
        s.step(&f.lock, -1);
        assert_eq!(s.shown(&f.lock), Some(WIPE_AFTER_MAX - 1), "the ceiling must not stick");
    }

    /// A disabled policy has no threshold to step, and turning it back on lands on the
    /// value the store last held rather than on a hardcoded one.
    #[test]
    fn turning_erasing_back_on_restores_the_stored_threshold() {
        let mut f = unlocked(720, 720, None, None);
        let mut s = PolicyState::new();
        assert_eq!(s.shown(&f.lock), None);
        s.step(&f.lock, 1);
        assert_eq!(s.shown(&f.lock), None, "there is no threshold to step while it is off");
        // A store that has never had a threshold falls back to the ratified default.
        assert_eq!(restore_threshold(&f.lock), WIPE_AFTER_DEFAULT);
        f.lock.wipe_after = Some(7);
        assert_eq!(restore_threshold(&f.lock), 7);
    }

    /// The floor is a parameter and it is off as shipped, so no PIN is refused the
    /// setting (Q62). The check is nevertheless wired, which is what makes revisiting the
    /// decision a constant rather than a rewrite.
    #[test]
    fn no_pin_length_is_refused_the_setting_as_shipped() {
        for len in [4u8, 6, 8, 12] {
            let shape = Some(PinShape { len, alphabet: 10 });
            assert!(!floor_blocks(shape, WIPE_DISABLE_MIN_PIN));
        }
    }
}
