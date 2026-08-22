// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! S-29: the screen the signing pipeline shows when it will not proceed (C7).
//!
//! Commandment 10: a refusal gets the same design care as a success. This is the surface
//! that decides whether a defence is a security property or an annoyance - a device that
//! refuses with a log line teaches its owner to retry blindly, and a device that refuses
//! with three sentences teaches them what the file did.
//!
//! # The split between copy and facts
//!
//! [`RefusalCode`] owns the HEADLINE, the "why this matters" and the "what to do": product
//! copy, stable across releases, asserted by CI. [`RefusalNotice::happened`] and
//! [`RefusalNotice::details`] are facts about ONE file that only the engine knows. This
//! screen renders the two together and computes neither, which is what lets a new engine
//! refusal reuse a ratified sentence rather than inventing a worse one.
//!
//! Every refusal fills all three sections. Two codes - the two about the CARD rather than
//! about a transaction - have no "why this matters", because there is no attack behind an
//! empty card slot and a fabricated sentence there would teach a reader to skim the section
//! on the codes where it carries the whole warning. That is the only permitted omission and
//! `every_code_fills_the_sections_it_claims_to` holds it to exactly those two.
//!
//! # Details
//!
//! `[ Show details ]` reveals the mono block a bug report gets photographed from: indexes,
//! txids, the claimed path, the check number. Complete, never truncated, and never key
//! material - every refusal is decided before any key exists, which is what makes that a
//! structural claim rather than a promise.
//!
//! # Where Back goes
//!
//! One pop, always. Every transition inside the signing flow is [`Nav::Enter`], so
//! review-sign-deliver and this screen occupy ONE back-stack slot between them and a single
//! [`Nav::Back`] leaves the whole flow. A refusal that arrives AFTER the hold says so in an
//! extra line and labels its button for where it is going, because "load a different file"
//! is the wrong instruction for someone whose device just failed its own post-sign gate.

use alloc::string::String;
use alloc::vec::Vec;

use embedded_graphics::draw_target::{DrawTarget, DrawTargetExt};
use embedded_graphics::pixelcolor::Rgb565;

use crate::canvas::{button, mono_wrapped, mono_wrapped_height, panel, text, wrap_words,
    ButtonKind, BODY, HEADING, MONO_SMALL};
use crate::components::{back_rect, draw_bar, LINE};
use crate::layout::{Metrics, Rect, TOUCH_MIN};
use crate::screens::review::marker;
use crate::screens::{Ctx, Env, Nav, Outcome, Screen};
use crate::theme::*;
use crate::{Region, RegionId, RefusalNotice, ScreenId};

/// Inner padding of the header band.
const BAND_PAD: i32 = 12;

/// The three section captions, in the fixed order C7 gives them. A refusal that cannot fill
/// all three is under-specified and does not ship.
const HAPPENED: &str = "What happened";
const MATTERS: &str = "Why this matters";
const TODO: &str = "What to do";

/// The extra line a post-sign refusal carries. Fixed copy: it is the sentence that tells a
/// user their coins are where they were.
const NOTHING_HAPPENED: &str = "Nothing was signed and nothing was written.";

pub(crate) struct RefusalState {
    notice: RefusalNotice,
    /// Whether the machine facts are revealed. Off by default: the three sentences above are
    /// what a user acts on, and a wall of hex above them is how those sentences go unread.
    details: bool,
    scroll: i32,
}

impl RefusalState {
    /// One refusal, ready to render.
    ///
    /// The constructor the sign source and the review both call; its name and its single
    /// parameter are part of the screen contract.
    pub(crate) fn new(notice: RefusalNotice) -> RefusalState {
        RefusalState { notice, details: false, scroll: 0 }
    }

    pub(crate) fn id(&self) -> ScreenId {
        ScreenId::Refusal
    }

    /// The label on the body button. It names where the user lands, which is a different
    /// place before and after the hold.
    fn exit_label(&self) -> &'static str {
        if self.notice.after_signing {
            "Back to wallet"
        } else {
            "Back to sign"
        }
    }

    /// The sheet, as rows: the header band, then the sections, then the details block.
    ///
    /// Built once and measured and drawn from the same value, so the scroll limit and the
    /// paint cannot disagree about how tall the copy is.
    fn sections(&self) -> Vec<(&'static str, String)> {
        let mut out = Vec::new();
        let mut happened = self.notice.happened.clone();
        if self.notice.after_signing {
            happened.push(' ');
            happened.push_str(NOTHING_HAPPENED);
        }
        out.push((HAPPENED, happened));
        if let Some(m) = self.notice.code.matters() {
            out.push((MATTERS, String::from(m)));
        }
        out.push((TODO, String::from(self.notice.code.todo())));
        out
    }

    /// Height of everything that scrolls, at body width `w`.
    fn content_h(&self, m: &Metrics, w: i32) -> i32 {
        let mut h = band_h(w, self.notice.code.headline()) + m.gap;
        for (_, body) in self.sections() {
            h += LINE + wrap_words(&body, w, BODY).len() as i32 * LINE + m.gap;
        }
        if self.details {
            h += LINE + mono_wrapped_height(&self.notice.details, w, MONO_SMALL) + m.gap;
        }
        h
    }
}

/// Height of the header band: the headline wrapped at the width the code leaves it.
fn band_h(w: i32, headline: &str) -> i32 {
    let code_w = MONO_SMALL.text_width("R-00") as i32;
    let lines = wrap_words(headline, w - 2 * BAND_PAD - code_w - BAND_PAD, HEADING).len();
    lines.max(1) as i32 * LINE + 2 * BAND_PAD
}

pub(crate) struct Layout {
    viewport: Rect,
    details: Rect,
    exit: Rect,
    limit: i32,
}

impl Screen for RefusalState {
    type Layout = Layout;

    fn layout(&self, ctx: &Ctx) -> Layout {
        let m = &ctx.m;
        let body = m.body();
        let footer = Rect::new(body.x, body.bottom() - m.btn, body.w, m.btn);
        let viewport = Rect::new(body.x, body.y, body.w, footer.y - m.gap - body.y);

        // `[ Show details ]` left, the way out right. The two are never confusable: one
        // reveals, one leaves, and the leaving one is the primary.
        let details_w = (HEADING.text_width("Show details") as i32 + 3 * m.pad).max(TOUCH_MIN * 3);
        let exit_w = (HEADING.text_width(self.exit_label()) as i32 + 3 * m.pad).max(TOUCH_MIN * 3);
        let details = Rect::new(footer.x, footer.y, details_w, footer.h);
        let exit = Rect::new(footer.right() - exit_w, footer.y, exit_w, footer.h);

        let limit = (self.content_h(m, viewport.w) - viewport.h).max(0);
        Layout { viewport, details, exit, limit }
    }

    fn regions(&self, ctx: &Ctx, out: &mut Vec<Region>) {
        let l = self.layout(ctx);
        out.push(Region { id: RegionId::Back, rect: back_rect(&ctx.m) });
        out.push(Region { id: RegionId::RefusalDetails, rect: l.details });
        // The body button IS Back. Two rectangles carrying one id is right here: they mean
        // the same thing, and the bar's affordance is the one a user reaches for by habit
        // while the body one is the one C7 puts under the instructions they just read.
        out.push(Region { id: RegionId::Back, rect: l.exit });
    }

    fn draw<D: DrawTarget<Color = Rgb565>>(&self, t: &mut D, ctx: &Ctx) -> Result<(), D::Error> {
        let m = &ctx.m;
        let l = self.layout(ctx);
        draw_bar(t, m, "Refused")?;

        let scroll = self.scroll.clamp(0, l.limit);
        {
            let mut clip = t.clipped(&l.viewport.to_eg());
            let w = l.viewport.w;
            let mut y = l.viewport.y - scroll;

            // The header band: headline left, the stable code right-aligned. The code is
            // what a user quotes in a bug report and what CI asserts, so it is mono and it
            // is never wrapped into the headline.
            let bh = band_h(w, self.notice.code.headline());
            let band = Rect::new(l.viewport.x, y, w, bh);
            panel(&mut clip, band, DANGER_TINT, DANGER)?;
            let code = self.notice.code.code();
            let cw = MONO_SMALL.text_width(code) as i32;
            text(&mut clip, code, band.right() - BAND_PAD - cw, band.y + BAND_PAD, MONO_SMALL,
                INK_SECONDARY, DANGER_TINT)?;
            let mut hy = band.y + BAND_PAD;
            for line in wrap_words(
                self.notice.code.headline(),
                w - 2 * BAND_PAD - cw - BAND_PAD,
                HEADING,
            ) {
                text(&mut clip, &line, band.x + BAND_PAD, hy, HEADING, INK_PRIMARY, DANGER_TINT)?;
                hy += LINE;
            }
            y += bh + m.gap;

            for (caption, body) in self.sections() {
                text(&mut clip, caption, l.viewport.x, y, HEADING, INK_PRIMARY, PAPER_1)?;
                y += LINE;
                for line in wrap_words(&body, w, BODY) {
                    text(&mut clip, &line, l.viewport.x, y, BODY, INK_SECONDARY, PAPER_1)?;
                    y += LINE;
                }
                y += m.gap;
            }

            if self.details {
                text(&mut clip, "Details", l.viewport.x, y, HEADING, INK_PRIMARY, PAPER_1)?;
                y += LINE;
                mono_wrapped(
                    &mut clip,
                    &self.notice.details,
                    Rect::new(l.viewport.x, y, w, l.viewport.bottom() - y),
                    MONO_SMALL,
                    INK_PRIMARY,
                    PAPER_1,
                )?;
            }
        }
        if scroll > 0 {
            marker(t, "more above", l.viewport, true)?;
        }
        if scroll < l.limit {
            marker(t, "more below", l.viewport, false)?;
        }

        button(
            t,
            l.details,
            if self.details { "Hide details" } else { "Show details" },
            ButtonKind::Secondary,
            PAPER_1,
        )?;
        button(t, l.exit, self.exit_label(), ButtonKind::Primary, PAPER_1)
    }

    fn activate(&mut self, id: RegionId, _env: &mut Env) -> Outcome {
        match id {
            RegionId::RefusalDetails => {
                self.details = !self.details;
                self.scroll = 0;
                Outcome::stay()
            }
            _ => Outcome::stay(),
        }
    }

    /// One pop leaves the whole signing flow - see the module docs. There is no confirm:
    /// nothing was signed, nothing was written, and there is nothing here to lose.
    fn back(&self) -> Nav {
        Nav::Back
    }

    fn scroll_mut(&mut self) -> Option<&mut i32> {
        Some(&mut self.scroll)
    }

    fn scroll_limit(&self, ctx: &Ctx) -> i32 {
        self.layout(ctx).limit
    }
}

#[cfg(test)]
mod tests {
    use crate::UnlockGate;
    use super::*;
    use crate::screens::testing::{rows_are_clear_on, Fixture, GEOMETRIES};
    use crate::RefusalCode;
    use alloc::format;
    use alloc::vec;

    fn notice(code: RefusalCode, after_signing: bool) -> RefusalNotice {
        RefusalNotice {
            code,
            happened: String::from(
                "Input 2 states an amount but does not include the transaction it came from.",
            ),
            details: String::from(
                "input 2 outpoint 9f2c1a44...:0 path m/84'/0'/0'/0/4 kind P2WPKH check 2",
            ),
            after_signing,
        }
    }

    const CODES: [RefusalCode; 18] = [
        RefusalCode::NotOurInputs,
        RefusalCode::MissingPrevTx,
        RefusalCode::ChangeNotProven,
        RefusalCode::CosignerMismatch,
        RefusalCode::WrongNetwork,
        RefusalCode::ImpossibleFee,
        RefusalCode::UnsupportedSighash,
        RefusalCode::UnexpectedTaproot,
        RefusalCode::MalformedFile,
        RefusalCode::SignatureCheckFailed,
        RefusalCode::NotAPsbt,
        RefusalCode::PsbtVersion2,
        RefusalCode::FileTooLarge,
        RefusalCode::NoCard,
        RefusalCode::NoPsbtFiles,
        RefusalCode::WriteFailed,
        RefusalCode::NotInThisBuild,
        RefusalCode::UnsupportedScript,
    ];

    fn ids(s: &RefusalState, f: &Fixture) -> Vec<RegionId> {
        let mut out = Vec::new();
        s.regions(&f.ctx(), &mut out);
        out.into_iter().map(|r| r.id).collect()
    }

    /// Every refusal the engine can raise renders as sentences a user can act on - never a
    /// log line, and never a section left empty by accident.
    ///
    /// Broken version: return `String::new()` from `RefusalCode::todo` for one code, or drop
    /// the `TODO` section from `sections`. The per-code loop trips on that code.
    #[test]
    fn every_code_fills_the_sections_it_claims_to() {
        for code in CODES {
            let s = RefusalState::new(notice(code, false));
            let sections = s.sections();
            let captions: Vec<&str> = sections.iter().map(|(c, _)| *c).collect();
            assert_eq!(captions.first(), Some(&HAPPENED), "{code:?}");
            assert_eq!(captions.last(), Some(&TODO), "{code:?}");
            for (caption, body) in &sections {
                assert!(
                    body.len() > 20 && body.ends_with('.'),
                    "{code:?} / {caption}: {body:?} is not a sentence"
                );
            }
            // The one permitted omission, and exactly the two codes it is permitted for.
            let has_matters = captions.contains(&MATTERS);
            let is_card = matches!(code, RefusalCode::NoCard | RefusalCode::NoPsbtFiles);
            assert_eq!(has_matters, !is_card, "{code:?} omits or invents 'why this matters'");
            assert!(!code.headline().is_empty() && code.code().starts_with("R-"), "{code:?}");
        }
    }

    /// A refusal after the hold says the coins did not move, and points at the wallet.
    ///
    /// Broken version: drop the `after_signing` branch of `sections`. The first assertion
    /// trips.
    #[test]
    fn a_post_sign_refusal_says_nothing_moved() {
        let s = RefusalState::new(notice(RefusalCode::SignatureCheckFailed, true));
        let happened = &s.sections()[0].1;
        assert!(happened.contains(NOTHING_HAPPENED), "{happened}");
        assert_eq!(s.exit_label(), "Back to wallet");
        let before = RefusalState::new(notice(RefusalCode::MissingPrevTx, false));
        assert!(!before.sections()[0].1.contains(NOTHING_HAPPENED));
        assert_eq!(before.exit_label(), "Back to sign");
    }

    /// The details block is the thing that gets photographed: complete, mono, and never on
    /// screen until it is asked for.
    #[test]
    fn details_are_hidden_until_asked_for_and_then_complete() {
        let f = Fixture::new(720, 720);
        let mut net = crate::Network::Bitcoin;
        let mut e = Env {
            network: &mut net,
            lock: &f.lock,
            wallets: &f.wallets,
            gate: &mut UnlockGate::default(),
        };
        let mut s = RefusalState::new(notice(RefusalCode::MissingPrevTx, false));
        assert!(!s.details);
        let plain = s.content_h(&f.m, f.m.body().w);
        s.activate(RegionId::RefusalDetails, &mut e);
        assert!(s.details);
        assert!(s.content_h(&f.m, f.m.body().w) > plain, "revealing must make the sheet taller");
        s.activate(RegionId::RefusalDetails, &mut e);
        assert!(!s.details, "the control toggles");
    }

    /// Both ways out are offered and both mean the same thing, on both panels.
    #[test]
    fn the_screen_always_has_a_way_out() {
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            for after in [false, true] {
                let s = RefusalState::new(notice(RefusalCode::MissingPrevTx, after));
                let set = ids(&s, &f);
                assert_eq!(
                    set.iter().filter(|i| **i == RegionId::Back).count(),
                    2,
                    "{w}x{h}: the bar and the body button are both Back"
                );
                assert!(set.contains(&RegionId::RefusalDetails), "{w}x{h}");
                assert!(matches!(s.back(), Nav::Back), "{w}x{h}");
            }
        }
    }

    /// The footer's two controls are tappable, clear of each other and of the sheet, on both
    /// panels and for the widest label either can carry.
    #[test]
    fn the_footer_lays_out_on_both_panels() {
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            let ctx = f.ctx();
            for code in CODES {
                for after in [false, true] {
                    let s = RefusalState::new(notice(code, after));
                    let l = s.layout(&ctx);
                    let what = format!("{w}x{h} {code:?} after={after}");
                    rows_are_clear_on(
                        &f.m,
                        &what,
                        f.m.screen(),
                        &[("viewport", l.viewport), ("details", l.details), ("exit", l.exit)],
                    );
                    for (name, r) in [("details", l.details), ("exit", l.exit)] {
                        assert!(
                            r.w >= TOUCH_MIN && r.h >= TOUCH_MIN,
                            "{what}: {name} is {}x{}",
                            r.w,
                            r.h
                        );
                    }
                    assert!(l.viewport.h > 3 * LINE, "{what}: the sheet has {} px", l.viewport.h);
                }
            }
        }
    }

    /// Every code's copy is ASCII and free of the banned reassurance vocabulary.
    #[test]
    fn the_copy_is_ascii_and_states_mechanisms() {
        let banned = ["secure", "safe", "simply", "just ", "please", "sorry", "successfully"];
        for code in CODES {
            let mut text = String::from(code.headline());
            text.push(' ');
            text.push_str(code.todo());
            if let Some(m) = code.matters() {
                text.push(' ');
                text.push_str(m);
            }
            assert!(text.is_ascii(), "{code:?} is not ASCII");
            assert!(!text.contains('\u{2013}') && !text.contains('\u{2014}'), "{code:?}");
            let lower = text.to_lowercase();
            for word in banned {
                assert!(!lower.contains(word), "{code:?} says {word:?}");
            }
        }
        let _ = vec![0u8];
    }
}
