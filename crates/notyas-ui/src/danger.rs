// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The C4 danger sheet: one component, and the one visual grammar every destructive
//! action in the product is asked for through.
//!
//! # Grades
//!
//! Grade is chosen by CONSEQUENCE and by nothing else - not by how important the calling
//! code feels the action is - which is what makes the grammar readable across the
//! product: a user who has typed a word back once knows what class of thing is behind the
//! next request to do it.
//!
//! - [`DangerGrade::Confirm`] (C4b) - destructive, recoverable from what the consequence
//!   names. Cancel and a `Danger` answer.
//! - [`DangerGrade::Hold`] (C4c) - irreversible in effect, so a tap must not be able to
//!   cause it. The confirm is not tappable at all; it fills while held.
//! - [`DangerGrade::Typed`] (C4d) - unrecoverable on this device. The confirm stays
//!   `Disabled`, with its reason beside it, until the required word is typed back exactly.
//!
//! # The third answer
//!
//! A sheet may offer an ALTERNATIVE beside accepting and cancelling: the action that
//! removes the REASON for the warning rather than accepting or dismissing it. PIN-MODES.md
//! requires one where the user could simply leave the state being warned about - turning
//! the wrong-PIN wipe off warns about a short PIN, and "use a longer PIN" is the answer
//! that makes the warning stop being true - and it is what turns a warning into a choice
//! instead of an obstacle. It gets its OWN row rather than a place between Cancel and the
//! destructive answer: a third target inside that gap is exactly the mistap
//! [`SEPARATION_MIN`](crate::layout::SEPARATION_MIN) exists to prevent.
//!
//! # Two grades in sequence
//!
//! Where a consequence cannot be named in the lines a typed-name sheet has left after its
//! keyboard - both destructions in m4b's settings work name several things individually,
//! with counts - the caller opens a [`DangerGrade::Confirm`] sheet first and replaces it
//! with the typed one when that is confirmed. Read, then commit. [`Danger::fits`] is how a
//! caller proves its own wording survives both shipped panels; the prose has no scroll and
//! no ellipsis, because a consequence half drawn at the moment of consent is worse than no
//! consequence at all.
//!
//! # Usage
//!
//! A screen embeds `Option<Danger>` and forwards three calls - `regions`, `draw`,
//! `activate`. The sheet is MODAL: while one is open its owner returns the sheet's regions
//! and nothing else, so the screen underneath is as inert to a finger as it is invisible.

use alloc::string::String;
use alloc::vec::Vec;

use embedded_graphics::draw_target::{DrawTarget, DrawTargetExt};
use embedded_graphics::pixelcolor::Rgb565;

use crate::canvas::{self, button, fill, frame, text, wrap_words, ButtonKind, BODY, HEADING};
use crate::components::{draw_keyboard, keyboard, keyboard_min_h, LINE};
use crate::layout::{Metrics, Rect, SEPARATION_MIN};
use crate::theme::*;
use crate::{Page, Press, Region, RegionId, HOLD_MS};

/// Height of the C4c bar: a physical minimum (C4c asks for at least 120 px), not a derived
/// one - it is a target a finger rests on for a second and a half.
const HOLD_BAR_H: i32 = 120;
/// Height of the typed-name field, matching the passphrase screen's.
const FIELD_H: i32 = 56;
/// Narrowest a landscape keyboard rail may be: ten keys at the audited 40 px floor plus
/// the nine gaps between them. Physical, like every other touch floor in the crate.
const KB_RAIL_W: i32 = 10 * 40 + 9 * 6;

/// How much friction an action's consequence earns (UX-SCREENS.md C4, commandment 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DangerGrade {
    Confirm,
    Hold,
    Typed,
}

/// What a tap did to an open sheet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DangerOutcome {
    /// Still open. Typing, an inert tap on a disabled control, or a tap the sheet does not
    /// act on - the sheet is modal, so that is every other region on the panel.
    Open,
    /// The user backed out. The caller closes the sheet and changes nothing.
    Cancelled,
    /// Consent was given at this grade. The caller performs the action - or, where the
    /// grade was [`DangerGrade::Confirm`] and a typed step follows, opens that.
    Confirmed,
    /// The third answer was taken. The caller closes the sheet, changes nothing, and does
    /// whatever removes the reason for the warning.
    Alternative,
}

/// An open danger sheet: which action it guards, and how far the user has got through
/// consenting to it.
///
/// A full-body SHEET rather than a small centred panel, because two of the three grades
/// need room a panel does not have - a hold bar has a physical minimum, a typed name needs
/// a keyboard - and because one shape for all three is the point of having one component.
pub(crate) struct Danger {
    grade: DangerGrade,
    title: String,
    /// What is destroyed, and what the way back is. Every line is drawn; a caller that
    /// cannot fill both has not understood the action well enough to ask for consent to it
    /// (C7's rule for refusals, applied where it matters more).
    consequence: Vec<String>,
    /// The exact string the user must type at the [`DangerGrade::Typed`] grade. Empty at
    /// the other two, which never read it.
    word: String,
    /// The destructive button's label: a verb naming the act ("Delete wallet"), never
    /// "Confirm" (3.3 decision 2), so a photograph of the moment of consent describes
    /// itself.
    label: String,
    /// The third answer's label, or empty for a sheet that has none.
    alternative: String,
    /// What the user has typed. Deliberately NOT masked and not `Zeroizing`: it is the
    /// name of the thing being destroyed, read off the screen above it.
    typed: String,
    page: Page,
}

impl Danger {
    /// C4b: destructive, recoverable from the backup the consequence names.
    pub(crate) fn confirm(title: &str, consequence: &[&str], label: &str) -> Danger {
        Danger::new(DangerGrade::Confirm, title, consequence, label, "")
    }

    /// C4c: irreversible in effect, so a tap must not be able to cause it.
    // No caller yet: S-36 (hold to sign) and S-48 (erase this device) are the two screens
    // this grade exists for and neither is in scope here. It is present rather than
    // deferred because one grammar for all three grades is the whole point of having one
    // component - and because `canvas::hold_bar` has been drawn and unit-tested since m4a
    // with nothing to call it.
    #[allow(dead_code)]
    pub(crate) fn hold(title: &str, consequence: &[&str], label: &str) -> Danger {
        Danger::new(DangerGrade::Hold, title, consequence, label, "")
    }

    /// C4d: unrecoverable on this device. `word` is typed back exactly, case sensitive.
    pub(crate) fn typed(title: &str, consequence: &[&str], label: &str, word: &str) -> Danger {
        Danger::new(DangerGrade::Typed, title, consequence, label, word)
    }

    /// Offer a third way out beside consenting and cancelling. See the module docs.
    pub(crate) fn with_alternative(mut self, label: &str) -> Danger {
        self.alternative = String::from(label);
        self
    }

    fn new(
        grade: DangerGrade,
        title: &str,
        consequence: &[&str],
        label: &str,
        word: &str,
    ) -> Danger {
        Danger {
            grade,
            title: String::from(title),
            consequence: consequence.iter().map(|s| String::from(*s)).collect(),
            word: String::from(word),
            label: String::from(label),
            alternative: String::new(),
            typed: String::new(),
            page: Page::Lower,
        }
    }

    /// Which grade this sheet is at, so a caller running two sheets in sequence can tell a
    /// consequence that has been READ from consent that has been GIVEN.
    pub(crate) fn grade(&self) -> DangerGrade {
        self.grade
    }

    /// Whether consent is complete enough for the confirm to be live. Unconditionally true
    /// at the grades with no precondition; the exact-match check at the typed grade.
    pub(crate) fn armed(&self) -> bool {
        match self.grade {
            DangerGrade::Typed => self.typed == self.word,
            _ => true,
        }
    }

    /// Whether the consequence prose fits the space this sheet gives it at this geometry.
    ///
    /// Callers owe a test that their own wording passes on BOTH shipped panels. There is
    /// no scroll and no ellipsis behind this: the prose either fits or it is silently cut
    /// off at the one moment the product most needs it read.
    ///
    /// Test-only, and deliberately so: at run time the answer would be too late to act on
    /// and there is nothing sensible to do with it. It is a proof obligation on the copy,
    /// discharged before the copy ships.
    #[cfg(test)]
    pub(crate) fn fits(&self, m: &Metrics) -> bool {
        let (used, have) = self.text_budget(m);
        used <= have
    }

    /// Pixels the consequence needs, and pixels it has. The failing half of [`fits`],
    /// reported separately so a test that trips says by how much rather than only that it
    /// did - the difference between a five-minute copy edit and a bisect.
    #[cfg(test)]
    pub(crate) fn text_budget(&self, m: &Metrics) -> (i32, i32) {
        let area = self.layout(m).text;
        let used: i32 = self
            .consequence
            .iter()
            .map(|p| wrap_words(p, area.w, BODY).len() as i32 * LINE + m.gap)
            .sum();
        (used, area.h)
    }

    /// Act on a tap. Every region the sheet emitted lands here, and nothing else on the
    /// panel is reachable while it is open.
    pub(crate) fn activate(&mut self, id: RegionId) -> DangerOutcome {
        match id {
            RegionId::DangerCancel => DangerOutcome::Cancelled,
            RegionId::DangerAlternative if !self.alternative.is_empty() => {
                DangerOutcome::Alternative
            }
            // The two ways to say yes. `HoldConfirm` arrives from `Ui::tick` once the bar
            // has filled and never from a tap; `DangerConfirm` (and the keyboard's Done,
            // which commits the field it belongs to exactly as it does on every other
            // screen in this crate) is drawn disabled until `armed`, and a tap on a
            // disabled control does nothing.
            RegionId::HoldConfirm => DangerOutcome::Confirmed,
            RegionId::DangerConfirm | RegionId::KeyDone if self.armed() => {
                DangerOutcome::Confirmed
            }
            // The typed field is capped at the length of the word it must match, so a
            // stray key can neither overrun it nor silently disarm a sheet the user has
            // already satisfied.
            RegionId::Key(c) if self.grade == DangerGrade::Typed => {
                self.push(c);
                DangerOutcome::Open
            }
            RegionId::Space if self.grade == DangerGrade::Typed => {
                self.push(' ');
                DangerOutcome::Open
            }
            RegionId::KeyBackspace => {
                self.typed.pop();
                DangerOutcome::Open
            }
            RegionId::Shift => {
                self.page = if self.page == Page::Lower { Page::Upper } else { Page::Lower };
                DangerOutcome::Open
            }
            RegionId::PageDigits => {
                self.page = Page::Digits;
                DangerOutcome::Open
            }
            RegionId::PageLetters => {
                self.page = Page::Lower;
                DangerOutcome::Open
            }
            RegionId::PageSymbols => {
                self.page = Page::Symbols;
                DangerOutcome::Open
            }
            _ => DangerOutcome::Open,
        }
    }

    fn push(&mut self, c: char) {
        if self.typed.chars().count() < self.word.chars().count() {
            self.typed.push(c);
        }
    }

    /// Everything tappable while this sheet is open, and nothing else.
    pub(crate) fn regions(&self, m: &Metrics, out: &mut Vec<Region>) {
        let l = self.layout(m);
        out.push(Region { id: RegionId::DangerCancel, rect: l.cancel });
        if !self.alternative.is_empty() {
            out.push(Region { id: RegionId::DangerAlternative, rect: l.alternative });
        }
        match self.grade {
            DangerGrade::Hold => out.push(Region { id: RegionId::HoldConfirm, rect: l.hold }),
            DangerGrade::Confirm => {
                out.push(Region { id: RegionId::DangerConfirm, rect: l.confirm })
            }
            DangerGrade::Typed => {
                out.push(Region { id: RegionId::DangerConfirm, rect: l.confirm });
                for k in keyboard(l.kb, self.page) {
                    out.push(Region { id: k.id, rect: k.rect });
                }
            }
        }
    }

    /// Paint the sheet over whatever is behind it. `press` and `released` are the two
    /// inputs the C4c bar renders from and are ignored at the other two grades; they are
    /// passed in rather than read here because a component cannot reach the `Ui` that
    /// tracks them.
    pub(crate) fn draw<D: DrawTarget<Color = Rgb565>>(
        &self,
        t: &mut D,
        m: &Metrics,
        press: Option<Press>,
        released: bool,
    ) -> Result<(), D::Error> {
        let l = self.layout(m);
        // Opaque: there is no alpha on RGB565, and a half-covered screen underneath would
        // read as content a finger can still reach.
        fill(t, m.screen(), PAPER_1)?;

        // Header band: danger tint, danger hairline, the action as a headline. Full width
        // on both panels (reflow rule 5) - it is what gets read first.
        fill(t, l.header, DANGER_TINT)?;
        frame(t, l.header, DANGER)?;
        let ty = l.header.y + (l.header.h - HEADING.line_height as i32) / 2;
        text(t, &self.title, l.header.x + m.gap, ty, HEADING, INK_PRIMARY, DANGER_TINT)?;

        let mut y = l.text.y;
        for para in &self.consequence {
            for line in wrap_words(para, l.text.w, BODY) {
                text(t, &line, l.text.x, y, BODY, INK_PRIMARY, PAPER_1)?;
                y += LINE;
            }
            y += m.gap;
        }

        match self.grade {
            DangerGrade::Confirm => {}
            DangerGrade::Hold => {
                let held = press.filter(|p| p.id == Some(RegionId::HoldConfirm));
                let permille = crate::hold_fill_permille(held.map_or(0, |p| p.held_ms));
                let status = match (held, released) {
                    (Some(_), _) => String::from("Keep holding"),
                    // The C4c line after an early release: what did NOT happen, and no
                    // scolding.
                    (None, true) => format!("Released - nothing was {}", self.undone()),
                    (None, false) => format!("Hold for {} seconds", HOLD_MS / 1000),
                };
                canvas::hold_bar(t, l.hold, &self.label, &status, permille, DANGER)?;
            }
            DangerGrade::Typed => {
                // The `Disabled` contract wants the reason beside the control it explains,
                // and on this sheet the space beside the control is the keyboard. So the
                // reason rides the PROMPT, which is the line the field belongs to and the
                // only one with room for it: "type this" and "that is not it yet" are the
                // same sentence anyway.
                // Two lines above the field, both clipped to the field's own width. The
                // `Disabled` contract wants the reason beside the control it explains, and
                // beside the control is where the keyboard is - so it goes directly above
                // the field the control is about, which is the same thing said closer. One
                // line each rather than one shared line because a wallet name may be 24
                // characters and the landscape column is a third of a panel: side by side,
                // the longer of the two would eat the other.
                let prompt = format!("Type {} to confirm:", self.word);
                let mut clip = t.clipped(
                    &Rect::new(l.field.x, l.field.y - 2 * LINE, l.field.w, 2 * LINE).to_eg(),
                );
                text(
                    &mut clip,
                    &prompt,
                    l.field.x,
                    l.field.y - 2 * LINE,
                    BODY,
                    INK_SECONDARY,
                    PAPER_1,
                )?;
                if !self.typed.is_empty() && !self.armed() {
                    let mark = "not a match yet";
                    text(&mut clip, mark, l.field.x, l.field.y - LINE, BODY, WARNING, PAPER_1)?;
                }
                // Unmasked by construction (the masking law, crate docs): the whole point
                // is that the user reads back the name of the thing being destroyed.
                canvas::field(t, l.field, &self.typed, false, true)?;
                draw_keyboard(t, l.kb, self.page, self.armed())?;
            }
        }

        if !self.alternative.is_empty() {
            button(t, l.alternative, &self.alternative, ButtonKind::Secondary, PAPER_1)?;
        }
        button(t, l.cancel, "Cancel", ButtonKind::Ghost, PAPER_1)?;
        if self.grade != DangerGrade::Hold {
            let kind = if self.armed() { ButtonKind::Danger } else { ButtonKind::Disabled };
            button(t, l.confirm, &self.label, kind, PAPER_1)?;
        }
        Ok(())
    }

    /// The past participle for the C4c released line, derived from the label rather than
    /// taken as a further constructor argument: every hold in the product is "Hold to
    /// <verb>", and a component that guessed would put the wrong word on the one line a
    /// user reads after letting go by accident.
    fn undone(&self) -> &'static str {
        if self.label.contains("sign") {
            "signed"
        } else {
            "erased"
        }
    }

    /// Geometry, computed once and consumed by `regions`, `draw` and `fits` alike.
    ///
    /// Bottom-up, because every element below the consequence prose has a physical floor
    /// and the prose is the one part that can take what is left. The typed grade splits
    /// into content plus a keyboard rail on the landscape panel (reflow rule 1): stacked,
    /// four keyboard rows and an action row do not both fit in 480 px of height.
    fn layout(&self, m: &Metrics) -> DangerLayout {
        let c = m.content();
        let btn = m.btn.min(80);
        let header = Rect::new(c.x, c.y, c.w, LINE + 16);
        let action_y = c.bottom() - btn;

        // A landscape keyboard sits in a RAIL beside the field rather than under it, and
        // the rail is sized from the keyboard rather than from the panel: ten keys on the
        // audited 40 px floor plus nine gaps is 454 px, and a rail narrower than that
        // draws 24 px keys with their control labels on top of one another - a sheet that
        // cannot be typed on is a delete that cannot be completed.
        //
        // The prose keeps the FULL width above it. That is the whole reason the rail is a
        // band rather than a column: what a consequence needs is characters per line, and
        // 736 px gives it twice what the strip left beside a keyboard does.
        let rail = match self.grade {
            DangerGrade::Typed if m.landscape() => KB_RAIL_W.min(c.w * 2 / 3),
            _ => 0,
        };
        let col_w = c.w;

        // Cancel hard left, the destructive answer hard right, with the whole body width
        // between them. The action row keeps the FULL width even under a keyboard rail -
        // the rail stops short of it precisely so that it can - because 200 + 96 + 280
        // does not fit in a 435 px column, and R-SEPARATION is not the constraint that
        // gives way.
        let cancel_w = (HEADING.text_width("Cancel") as i32 + 4 * m.pad).max(200);
        let confirm_w = (HEADING.text_width(&self.label) as i32 + 4 * m.pad)
            .max(280)
            .min(c.w - cancel_w - SEPARATION_MIN);
        let cancel = Rect::new(c.x, action_y, cancel_w, btn);
        let confirm = Rect::new(c.right() - confirm_w, action_y, confirm_w, btn);

        let none = Rect::new(0, 0, 0, 0);
        let (alternative, stack_top) = if self.alternative.is_empty() {
            (none, action_y)
        } else {
            let r = Rect::new(c.x, action_y - m.gap - btn, col_w, btn);
            (r, r.y)
        };

        let (mut hold, mut field, mut kb) = (none, none, none);
        let mut text_bottom = stack_top - m.gap;
        match self.grade {
            DangerGrade::Confirm => {}
            // The bar sits a full `SEPARATION_MIN` above whatever answer row is under
            // it, because at this grade the separation runs VERTICALLY: the bar is
            // full-width by C4c (at least 60% of the body, which no side-by-side
            // arrangement leaves once Cancel and the clearance are taken out of 672 px).
            DangerGrade::Hold => {
                hold = Rect::new(c.x, stack_top - SEPARATION_MIN - HOLD_BAR_H, col_w, HOLD_BAR_H);
                text_bottom = hold.y - m.gap;
            }
            DangerGrade::Typed if rail != 0 => {
                // Bottom-anchored above whatever answer row is under it: a rail run to the
                // floor of the sheet would be painted over the buttons and hit-tested over
                // them, which is a destruction under a keyboard key.
                let kb_h = keyboard_min_h();
                kb = Rect::new(c.right() - rail, stack_top - m.gap - kb_h, rail, kb_h);
                // The prompt and the field share the keyboard's band, in the column beside
                // it - the prompt is drawn one line above the field, so the field starts a
                // line down rather than at the top of the band.
                let col = c.w - rail - m.gap;
                // Two lines above the field for the prompt and the not-a-match reason,
                // inside the keyboard's own band and beside it.
                field = Rect::new(c.x, kb.y + 2 * LINE, col, FIELD_H);
                text_bottom = kb.y - m.gap;
            }
            DangerGrade::Typed => {
                let kb_h = keyboard_min_h().max((c.h / 3).min(4 * 64 + 3 * 8));
                kb = Rect::new(c.x, stack_top - m.gap - kb_h, c.w, kb_h);
                field = Rect::new(c.x, kb.y - m.gap - FIELD_H, c.w, FIELD_H);
                text_bottom = field.y - 2 * LINE - m.gap;
            }
        }

        let text_y = header.bottom() + m.gap;
        DangerLayout {
            header,
            text: Rect::new(c.x, text_y, col_w, (text_bottom - text_y).max(0)),
            hold,
            field,
            kb,
            alternative,
            cancel,
            confirm,
        }
    }
}

struct DangerLayout {
    header: Rect,
    /// The consequence prose and the width it wraps into - narrower beside a keyboard
    /// rail, which is why the width travels with the rectangle.
    text: Rect,
    hold: Rect,
    field: Rect,
    kb: Rect,
    alternative: Rect,
    cancel: Rect,
    confirm: Rect,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::TOUCH_MIN;

    /// The two shipped panels. Restated here rather than borrowed from `screens::testing`
    /// because a component must be provable without a screen around it.
    const GEOMETRIES: [(u32, u32); 2] = [(720, 720), (800, 480)];

    fn samples() -> [Danger; 4] {
        [
            Danger::confirm("Discard this wallet?", &["Nothing was written."], "Discard"),
            Danger::hold("Erase this device", &["Everything stored goes."], "Hold to erase"),
            // A SHORT consequence, because a typed sheet has a keyboard where the prose
            // would be: on the short panel its content column is what is left beside a
            // 454 px keyboard rail. The full statement belongs on the Confirm sheet that
            // precedes it, which is the sequence the module docs describe.
            Danger::typed(
                "Delete wallet \"savings\"",
                &["This erases the stored wallet slot."],
                "Delete wallet",
                "savings",
            ),
            Danger::confirm(
                "Turn off erasing after wrong PINs?",
                &["Guessing would then be limited only by time."],
                "Turn off erasing",
            )
            .with_alternative("Use a longer PIN instead"),
        ]
    }

    /// R-SEPARATION, and it is the rule this component exists to make structural: the gap
    /// between a destructive answer and its cancel is never below `SEPARATION_MIN`, at any
    /// grade, on either panel, with or without a third answer above them. A sheet that
    /// shrank it would put a delete one mistap from a cancel.
    #[test]
    fn the_cancel_and_the_destructive_answer_are_never_adjacent() {
        for (w, h) in GEOMETRIES {
            let m = Metrics::new(w, h);
            for d in samples() {
                let l = d.layout(&m);
                let far = match d.grade {
                    DangerGrade::Hold => l.hold,
                    _ => l.confirm,
                };
                // Along EITHER axis: the two answers share a row at the tap grades and
                // stack at the hold grade, and the rule is about the clear space between
                // two targets, not about which way the layout happens to run.
                let dx = (far.x - l.cancel.right()).max(l.cancel.x - far.right());
                let dy = (far.y - l.cancel.bottom()).max(l.cancel.y - far.bottom());
                assert!(
                    dx.max(dy) >= SEPARATION_MIN,
                    "{w}x{h} {:?}: only {} px between cancel and the destructive answer",
                    d.grade,
                    dx.max(dy)
                );
                assert!(l.cancel.h >= TOUCH_MIN, "{w}x{h}: cancel below the touch floor");
                assert!(far.h >= TOUCH_MIN, "{w}x{h}: the destructive answer is too short");
            }
        }
    }

    /// Nothing a finger can reach overlaps anything else it can reach, and nothing escapes
    /// the panel. The landscape typed grade is what this catches: the keyboard rail and the
    /// destructive answer are on the same side, and a rail run to the floor would sit on
    /// top of the button.
    #[test]
    fn no_two_targets_overlap_at_any_grade_on_either_panel() {
        for (w, h) in GEOMETRIES {
            let m = Metrics::new(w, h);
            for d in samples() {
                let mut out = Vec::new();
                d.regions(&m, &mut out);
                for r in &out {
                    assert!(r.rect.w > 0 && r.rect.h > 0, "{w}x{h}: {:?} is empty", r.id);
                    assert!(
                        r.rect.x >= 0
                            && r.rect.y >= 0
                            && r.rect.right() <= m.w
                            && r.rect.bottom() <= m.h,
                        "{w}x{h}: {:?} escapes the panel: {:?}",
                        r.id,
                        r.rect
                    );
                }
                for (i, a) in out.iter().enumerate() {
                    for b in &out[i + 1..] {
                        assert!(
                            !a.rect.overlaps(&b.rect),
                            "{w}x{h}: {:?} overlaps {:?}",
                            a.id,
                            b.id
                        );
                    }
                }
                // The prose never runs into whatever is below it.
                let l = d.layout(&m);
                let floor = if d.alternative.is_empty() { l.cancel.y } else { l.alternative.y };
                assert!(l.text.bottom() <= floor, "{w}x{h}: the prose reaches the buttons");
                assert!(d.fits(&m), "{w}x{h}: the sample copy does not fit its own sheet");
            }
        }
    }

    /// Every key of the sheet's own keyboard keeps the audited 40 px floor on both panels.
    ///
    /// The landscape rail is what this catches: a rail sized as a fraction of the panel
    /// rather than from the keyboard it has to hold produces 24 px keys whose control
    /// labels overlap, and the sheet that grade exists for is one a user cannot then
    /// complete. Geometry has to come from the thing being laid out, not from the panel.
    #[test]
    fn every_key_of_the_sheet_keyboard_stays_tappable() {
        for (w, h) in GEOMETRIES {
            let m = Metrics::new(w, h);
            let d = Danger::typed("t", &["c"], "Delete wallet", "savings");
            let mut out = Vec::new();
            d.regions(&m, &mut out);
            let keys = out.iter().filter(|r| {
                matches!(
                    r.id,
                    RegionId::Key(_)
                        | RegionId::Space
                        | RegionId::Shift
                        | RegionId::PageDigits
                        | RegionId::PageLetters
                        | RegionId::PageSymbols
                        | RegionId::KeyBackspace
                )
            });
            let mut n = 0;
            for r in keys {
                n += 1;
                assert!(
                    r.rect.w >= 40 && r.rect.h >= 40,
                    "{w}x{h}: {:?} is {}x{}, below the 40 px key floor",
                    r.id,
                    r.rect.w,
                    r.rect.h
                );
            }
            assert!(n >= 30, "{w}x{h}: only {n} keys - the keyboard is not there");
        }
    }

    /// The typed grade takes exactly the word, and nothing else arms it.
    #[test]
    fn the_typed_grade_arms_only_on_an_exact_match() {
        let mut d = Danger::typed("t", &["c"], "Erase everything", "WIPE");
        assert!(!d.armed());
        assert_eq!(d.activate(RegionId::DangerConfirm), DangerOutcome::Open);
        for c in "WIPE".chars() {
            d.activate(RegionId::Key(c));
        }
        assert!(d.armed());
        // The cap stops a further key silently disarming a sheet already satisfied.
        d.activate(RegionId::Key('X'));
        assert!(d.armed(), "the field is capped at the word's length");
        assert_eq!(d.activate(RegionId::DangerConfirm), DangerOutcome::Confirmed);
        d.activate(RegionId::KeyBackspace);
        d.activate(RegionId::Key('e'));
        assert!(!d.armed(), "the match is case sensitive");
    }

    /// The third answer exists only where a sheet offers one, so a stray tap on the region
    /// cannot take a path the caller never opened.
    #[test]
    fn the_third_answer_is_offered_only_where_it_exists() {
        let m = Metrics::new(720, 720);

        let mut plain = Danger::confirm("t", &["c"], "Go");
        assert_eq!(plain.activate(RegionId::DangerAlternative), DangerOutcome::Open);
        let mut out = Vec::new();
        plain.regions(&m, &mut out);
        assert!(!out.iter().any(|r| r.id == RegionId::DangerAlternative));

        let mut offered = Danger::confirm("t", &["c"], "Go").with_alternative("Instead");
        assert_eq!(offered.activate(RegionId::DangerAlternative), DangerOutcome::Alternative);
        let mut out = Vec::new();
        offered.regions(&m, &mut out);
        assert!(out.iter().any(|r| r.id == RegionId::DangerAlternative));
    }

    /// `fits` is the callers' contract and has to be able to say no.
    #[test]
    fn a_consequence_too_long_for_its_sheet_is_reported() {
        let long = "word ".repeat(400);
        let d = Danger::typed("t", &[&long], "Erase everything", "WIPE");
        for (w, h) in GEOMETRIES {
            assert!(!d.fits(&Metrics::new(w, h)), "{w}x{h}: an overlong consequence must not fit");
        }
    }
}

