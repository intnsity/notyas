// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Mnemonic display: the derived words, masked by default, revealed only through an
//! explicit two-step confirm.
//!
//! This is the screen the masking law is written for. Every masked slot draws the SAME
//! fixed bullet run, so the frame carries nothing about the words - not their letters and
//! not their lengths - and the pixel tests assert exactly that: two different mnemonics
//! must render byte-identical masked frames.

use alloc::string::String;
use alloc::vec::Vec;

use embedded_graphics::draw_target::{DrawTarget, DrawTargetExt};
use embedded_graphics::pixelcolor::Rgb565;

use crate::canvas::{button, text, ButtonKind, BODY, MONO, MONO_SMALL};
use crate::components::{back_rect, draw_bar, draw_modal, modal_regions, ModalSpec, LINE};
use crate::layout::Rect;
use crate::screens::deriving::SeedSource;
use crate::screens::passphrase::PassState;
use crate::screens::{Ctx, Env, Nav, Outcome, Screen, State};
use crate::theme::*;
use crate::{Region, RegionId};
use notyas_core::bip39::{Mnemonic, MnemonicMode};
use notyas_core::entropy::DiceEntropy;

pub(crate) struct MnemonicState {
    /// The entropy behind the words, carried forward so the passphrase screen can hand
    /// the pipeline its input without re-deriving anything.
    pub dice: DiceEntropy,
    mode: MnemonicMode,
    /// The words being shown. notyas-core's type: wipes itself on drop.
    pub mnem: Mnemonic,
    revealed: bool,
    /// Reveal-confirm modal is open.
    modal: bool,
    scroll: i32,
}

impl MnemonicState {
    pub fn new(dice: DiceEntropy, mode: MnemonicMode, mnem: Mnemonic) -> MnemonicState {
        MnemonicState { dice, mode, mnem, revealed: false, modal: false, scroll: 0 }
    }
}

/// The one gate in front of showing the words. Text follows the desktop reveal modal:
/// name what will appear, then what a reader of the screen could do with it.
static REVEAL_MODAL: ModalSpec = ModalSpec {
    title: "Show seed words?",
    body: &[
        "The seed words will appear on this screen in plain text.",
        "Anyone who reads them can spend everything this seed controls. \
         Confirm nobody else can see this screen.",
    ],
    cancel: "Cancel",
    confirm: "Show words",
};

pub(crate) struct Layout {
    sub_y: i32,
    viewport: Rect,
    reveal: Option<Rect>,
    next: Rect,
}

/// Grid geometry: (columns, cell width, cell height).
fn grid(ctx: &Ctx) -> (usize, i32, i32) {
    let body = ctx.m.body();
    let cols = (body.w / 220).clamp(2, 4) as usize;
    let cell_w = (body.w - (cols as i32 - 1) * ctx.m.gap) / cols as i32;
    (cols, cell_w, LINE + 12)
}

impl Screen for MnemonicState {
    type Layout = Layout;

    fn layout(&self, ctx: &Ctx) -> Layout {
        let m = &ctx.m;
        let body = m.body();
        let g = m.gap;
        let sub_y = body.y;
        let ctl_y = body.bottom() - m.btn;
        let viewport = Rect::new(body.x, sub_y + LINE + g, body.w, ctl_y - g - (sub_y + LINE + g));
        let (reveal, next) = if self.revealed {
            (None, Rect::new(body.x, ctl_y, body.w, m.btn))
        } else {
            let rw = (body.w - g) * 2 / 5;
            (
                Some(Rect::new(body.x, ctl_y, rw, m.btn)),
                Rect::new(body.x + rw + g, ctl_y, body.w - rw - g, m.btn),
            )
        };
        Layout { sub_y, viewport, reveal, next }
    }

    fn regions(&self, ctx: &Ctx, out: &mut Vec<Region>) {
        if self.modal {
            out.extend(modal_regions(&ctx.m, &REVEAL_MODAL));
            return;
        }
        let l = self.layout(ctx);
        out.push(Region { id: RegionId::Back, rect: back_rect(&ctx.m) });
        if let Some(reveal) = l.reveal {
            out.push(Region { id: RegionId::Reveal, rect: reveal });
        }
        out.push(Region { id: RegionId::Next, rect: l.next });
    }

    fn draw<D: DrawTarget<Color = Rgb565>>(&self, t: &mut D, ctx: &Ctx) -> Result<(), D::Error> {
        let m = &ctx.m;
        draw_bar(t, m, "Seed words")?;
        let l = self.layout(ctx);

        let mode = match self.mode {
            MnemonicMode::Raw => String::from("RAW"),
            MnemonicMode::Words(n) => format!("FIXED {n}"),
        };
        let sub = format!(
            "{} words - {mode} - {}",
            self.mnem.words.len(),
            if self.revealed { "REVEALED" } else { "masked" }
        );
        text(t, &sub, m.body().x, l.sub_y, BODY, INK_SECONDARY, PAPER_1)?;

        // The word grid. Masked, every slot draws the SAME fixed bullet run, so the pixels
        // carry nothing about the words (the masking tests assert this literally).
        let (cols, cell_w, cell_h) = grid(ctx);
        let num_w = MONO_SMALL.text_width("888") as i32 + 8;
        {
            let mut clip = t.clipped(&l.viewport.to_eg());
            for (i, word) in self.mnem.words.iter().enumerate() {
                let col = (i % cols) as i32;
                let row = (i / cols) as i32;
                let x = l.viewport.x + col * (cell_w + m.gap);
                let y = l.viewport.y + row * cell_h - self.scroll;
                let num = format!("{}", i + 1);
                let nw = MONO_SMALL.text_width(&num) as i32;
                text(&mut clip, &num, x + num_w - 8 - nw, y + 4, MONO_SMALL, INK_MUTED, PAPER_1)?;
                let shown: &str = if self.revealed { word } else { mask_word() };
                text(&mut clip, shown, x + num_w, y, MONO, INK_PRIMARY, PAPER_1)?;
            }
        }

        if let Some(r) = l.reveal {
            button(t, r, "Reveal...", ButtonKind::Secondary, PAPER_1)?;
        }
        button(t, l.next, "Next", ButtonKind::Primary, PAPER_1)?;

        if self.modal {
            draw_modal(t, m, &REVEAL_MODAL)?;
        }
        Ok(())
    }

    fn activate(&mut self, id: RegionId, _env: &mut Env) -> Outcome {
        match id {
            RegionId::Reveal if !self.modal => {
                self.modal = true;
                Outcome::stay()
            }
            RegionId::ModalConfirm => {
                self.revealed = true;
                self.modal = false;
                Outcome::stay()
            }
            RegionId::ModalCancel => {
                self.modal = false;
                Outcome::stay()
            }
            RegionId::Next if !self.modal => Outcome::push(State::Passphrase(PassState::new(
                SeedSource::Dice { dice: self.dice.clone(), mode: self.mode },
            ))),
            _ => Outcome::stay(),
        }
    }

    /// A derived secret is on this screen: Back asks first, so an accidental tap cannot
    /// silently discard the words the user may be in the middle of writing down.
    fn back(&self) -> Nav {
        Nav::ConfirmExit
    }

    /// The sheet under an open modal is inert, scrolling included.
    fn scroll_mut(&mut self) -> Option<&mut i32> {
        if self.modal {
            None
        } else {
            Some(&mut self.scroll)
        }
    }

    fn scroll_limit(&self, ctx: &Ctx) -> i32 {
        let l = self.layout(ctx);
        let (cols, _, cell_h) = grid(ctx);
        let rows = self.mnem.words.len().div_ceil(cols.max(1)) as i32;
        (rows * cell_h - l.viewport.h).max(0)
    }
}
