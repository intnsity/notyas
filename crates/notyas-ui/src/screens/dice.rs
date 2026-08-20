// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Dice entry: the rolls the user types, the mode they are interpreted in, and the
//! effective-bits gate that decides whether Done can fire.
//!
//! The rolls ARE the wallet: this screen's state is as secret as a mnemonic, and the
//! per-frame copies the history well needs are owned by a drop guard for that reason.
//! Typed input is shown unmasked (desktop survey section 5) - seeing what you rolled is
//! what makes a mis-entry catchable - while everything derived from it is not.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use embedded_graphics::draw_target::{DrawTarget, DrawTargetExt};
use embedded_graphics::pixelcolor::Rgb565;
use zeroize::{Zeroize, Zeroizing};

use crate::canvas::{
    button, fill, frame, panel, strength_meter, tabs, text, text_centered, wrap_words, ButtonKind,
    BODY, MONO, MONO_SMALL, TITLE,
};
use crate::components::{back_rect, draw_bar, LINE, SMALL_LINE};
use crate::layout::Rect;
use crate::screens::mnemonic::MnemonicState;
use crate::screens::{Ctx, Env, Nav, Outcome, Screen, State};
use crate::theme::*;
use crate::{secret_buf, Region, RegionId};
use notyas_core::bip39::{self, rolls_for_bits, MnemonicMode, WordCount, MIN_SECURE_BITS};
use notyas_core::entropy::{parse_dice, DiceEntropy};
use notyas_core::report;

pub(crate) struct DiceState {
    /// The digits as typed (1-6). `Zeroizing`, because this string alone regenerates the
    /// wallet.
    pub rolls: Zeroizing<String>,
    /// Parsed form of `rolls`, kept in step by the edit handlers (parsing is cheap but
    /// the draw path should not re-derive state). Self-wiping.
    pub entropy: DiceEntropy,
    mode: MnemonicMode,
}

impl DiceState {
    pub fn new() -> Self {
        DiceState {
            // Worst case one ASCII digit per entropy bit (rolls of 4/5 yield 1 bit), so
            // this capacity holds every string the MAX_ENTROPY_BITS guard can admit.
            rolls: secret_buf(bip39::MAX_ENTROPY_BITS),
            entropy: parse_dice(""),
            mode: MnemonicMode::Raw,
        }
    }

    /// ENT the current mode would put in the mnemonic, given the bits collected so far.
    fn ent(&self) -> usize {
        let total = self.entropy.binary().len();
        match self.mode {
            MnemonicMode::Raw => bip39::raw_bits_used(total),
            // ENT = words * 32 / 3 (each word is 11 bits, 32 of every 33 are entropy).
            MnemonicMode::Words(n) => n.get() * 32 / 3,
        }
    }

    /// The number every warning is computed from, per the desktop rule.
    fn effective_bits(&self) -> usize {
        report::effective_bits(self.mode, self.ent(), self.entropy.binary().len())
    }
}

/// Segment labels of the dice mode control, in [`dice_mode`] index order. Desktop
/// parity: the full `--words <raw|12|15|18|21|24>` set, not a binary toggle. All the
/// fixed counts share the Coldcard/SeedSigner-compatible SHA256 math; RAW is the
/// iancoleman-compatible raw-bits mode (ARCHITECTURE.md dice math note).
pub(crate) const DICE_MODE_LABELS: [&str; 6] = ["RAW", "12", "15", "18", "21", "24"];

/// The mode behind segment `i` of the dice mode control: 0 = RAW, 1..=5 = the
/// [`bip39::FIXED_WORD_COUNTS`] entry. Total for any u8 (out-of-range clamps to 24),
/// keeping the input path panic-free.
pub(crate) fn dice_mode(i: u8) -> MnemonicMode {
    match i {
        0 => MnemonicMode::Raw,
        _ => {
            let count = bip39::FIXED_WORD_COUNTS[(i as usize - 1).min(4)];
            // Every FIXED_WORD_COUNTS member is a valid WordCount by definition.
            MnemonicMode::Words(WordCount::new(count).unwrap_or_else(|_| unreachable!()))
        }
    }
}

/// Inverse of [`dice_mode`], for drawing the active segment.
fn dice_mode_index(mode: MnemonicMode) -> usize {
    match mode {
        MnemonicMode::Raw => 0,
        MnemonicMode::Words(n) => {
            1 + bip39::FIXED_WORD_COUNTS.iter().position(|&c| c == n.get()).unwrap_or(4)
        }
    }
}

/// Roll-history well height: one MONO_SMALL line, vertically centered.
const HIST_H: i32 = 44;
/// Mode segmented-control height.
const MODE_H: i32 = 48;
/// Keypad internal gap (tighter than `Metrics::gap` so the 800x480 landscape keypad
/// keeps its keys on the 80px physical floor).
const KEYPAD_GAP: i32 = 10;
/// Widest reason line the status block can show (128-bit deficit = 77 rolls); the
/// layout reserves what this measures so the drawn text can never clip.
const NEED_WORST: &str = "Need 128 bits - about 77 more rolls";

pub(crate) struct Layout {
    /// Full-width roll-history well (typed input, unmasked - see `draw`).
    hist: Rect,
    /// Full-width six-segment mode control (RAW / 12 / 15 / 18 / 21 / 24).
    mode: Rect,
    /// Info block: cross-check hint, meter, status lines.
    hint_y: i32,
    meter: Rect,
    status_y: i32,
    /// Reserved status height: bits line + measured worst-case reason wrap.
    status_h: i32,
    info_x: i32,
    info_w: i32,
    /// 1..6, reading order.
    keys: [Rect; 6],
    backspace: Rect,
    done: Rect,
}

/// The mode's cross-check hint: which external tool reproduces this mode's math
/// (ARCHITECTURE.md dice math note). Worded to the measured width budget: one line on
/// the 720x720 portrait info row, two on the 800x480 landscape info column - the
/// layout reserves exactly what `wrap_words` needs (review item: the old fixed
/// reservation clipped the third wrapped line at 800x480).
fn dice_hint(mode: MnemonicMode) -> &'static str {
    match mode {
        MnemonicMode::Raw => "Raw dice bits: iancoleman",
        MnemonicMode::Words(_) => "SHA256 of rolls: Coldcard, SeedSigner",
    }
}

impl Screen for DiceState {
    type Layout = Layout;

    fn layout(&self, ctx: &Ctx) -> Layout {
        let m = &ctx.m;
        let mode = self.mode;
        let body = m.body();
        let g = m.gap;
        // Two full-width rows first: the roll-history well and the mode control (six
        // finger-sized segments need the whole width on the 800x480 panel). Below them,
        // landscape splits into an info column and a keypad column so the keypad keeps
        // full-size touch targets; portrait stacks info over keypad.
        let hist = Rect::new(body.x, body.y, body.w, HIST_H);
        let mode_r = Rect::new(body.x, hist.bottom() + g, body.w, MODE_H);
        let top = mode_r.bottom() + g;

        // The hint and status rows are measured, not assumed: the info block reserves as
        // many lines as the current mode's hint (and the worst-case reason line) wrap to,
        // so no wording/geometry combination can clip (review item 3; the layout unit
        // tests pin the keypad floor and the info fit for every mode on both geometries).
        let info_w = if m.landscape() { (body.w - g) * 9 / 20 } else { body.w };
        let hint_lines = wrap_words(dice_hint(mode), info_w, BODY).len().max(1) as i32;
        let need_lines = (wrap_words(NEED_WORST, info_w, BODY).len() as i32).clamp(1, 2);
        let status_h = LINE + need_lines * LINE;

        let (info, pad) = if m.landscape() {
            (
                Rect::new(body.x, top, info_w, body.bottom() - top),
                Rect::new(body.x + info_w + g, top, body.w - info_w - g, body.bottom() - top),
            )
        } else {
            let info_h = hint_lines * LINE + 20 + status_h + 2 * g;
            (
                Rect::new(body.x, top, body.w, info_h),
                Rect::new(body.x, top + info_h + g, body.w, body.bottom() - (top + info_h + g)),
            )
        };

        let hint_y = info.y;
        let meter = Rect::new(info.x, hint_y + hint_lines * LINE + g, info.w, 20);
        let status_y = meter.bottom() + g;

        // Keypad: 3x2 digit grid above a Backspace | Done row, filling the pad column.
        let ctl_h = m.btn;
        let key_w = (pad.w - 2 * KEYPAD_GAP) / 3;
        let key_h = (pad.h - ctl_h - 3 * KEYPAD_GAP) / 2;
        let mut keys = [Rect::new(0, 0, 0, 0); 6];
        for (i, k) in keys.iter_mut().enumerate() {
            let col = (i % 3) as i32;
            let row = (i / 3) as i32;
            *k = Rect::new(
                pad.x + col * (key_w + KEYPAD_GAP),
                pad.y + row * (key_h + KEYPAD_GAP),
                key_w,
                key_h,
            );
        }
        let ctl_y = pad.y + 2 * (key_h + KEYPAD_GAP) + KEYPAD_GAP;
        let bs_w = (pad.w - KEYPAD_GAP) * 2 / 5;
        Layout {
            hist,
            mode: mode_r,
            hint_y,
            meter,
            status_y,
            status_h,
            info_x: info.x,
            info_w: info.w,
            keys,
            backspace: Rect::new(pad.x, ctl_y, bs_w, ctl_h),
            done: Rect::new(pad.x + bs_w + KEYPAD_GAP, ctl_y, pad.w - bs_w - KEYPAD_GAP, ctl_h),
        }
    }

    fn regions(&self, ctx: &Ctx, out: &mut Vec<Region>) {
        let l = self.layout(ctx);
        out.push(Region { id: RegionId::Back, rect: back_rect(&ctx.m) });
        for (i, k) in l.keys.iter().enumerate() {
            out.push(Region { id: RegionId::Digit(i as u8 + 1), rect: *k });
        }
        let n = DICE_MODE_LABELS.len() as i32;
        let seg_w = l.mode.w / n;
        for i in 0..n {
            let w = if i == n - 1 { l.mode.w - seg_w * (n - 1) } else { seg_w };
            out.push(Region {
                id: RegionId::Mode(i as u8),
                rect: Rect::new(l.mode.x + i * seg_w, l.mode.y, w, l.mode.h),
            });
        }
        out.push(Region { id: RegionId::DiceBackspace, rect: l.backspace });
        out.push(Region { id: RegionId::DiceDone, rect: l.done });
    }

    fn draw<D: DrawTarget<Color = Rgb565>>(&self, t: &mut D, ctx: &Ctx) -> Result<(), D::Error> {
        let m = &ctx.m;
        draw_bar(t, m, "New seed")?;
        let l = self.layout(ctx);

        // Roll history well: the digits as typed, deliberately UNMASKED - typed input is
        // the user's own (desktop survey section 5), and seeing it is what makes a
        // mis-entry catchable and backspace informed. Count on the left; on the right a
        // trailing tail grouped in fives from the first roll (stable group boundaries),
        // led by an ellipsis when older digits scrolled off. The derived mnemonic stays
        // masked as always.
        panel(t, l.hist, PAPER_3, BORDER_STRONG)?;
        let inner = l.hist.inset(2);
        let pad_x = 10;
        let ty = l.hist.y + (l.hist.h - SMALL_LINE) / 2;
        let count = format!("Rolls {}", self.entropy.events());
        let adv = MONO_SMALL.glyph('6').advance as i32;
        let cap = ((inner.w - 2 * pad_x - MONO_SMALL.text_width(&count) as i32 - 2 * m.gap) / adv)
            .max(0) as usize;
        let tmp = {
            let mut grouped = String::with_capacity(self.rolls.len() + self.rolls.len() / 5 + 2);
            for (i, c) in self.rolls.chars().enumerate() {
                if i > 0 && i % 5 == 0 {
                    grouped.push(' ');
                }
                grouped.push(c);
            }
            let total = grouped.chars().count();
            let mut shown = String::with_capacity(cap + 4);
            if total > cap {
                shown.push('\u{2026}');
                shown.push(' ');
                shown.extend(grouped.chars().skip(total - cap.saturating_sub(2)));
            } else {
                shown.push_str(&grouped);
            }
            RollTemps { grouped, shown }
        };
        let tw = MONO_SMALL.text_width(&tmp.shown) as i32;
        {
            let mut clip = t.clipped(&inner.to_eg());
            text(&mut clip, &count, inner.x + pad_x, ty, MONO_SMALL, INK_SECONDARY, PAPER_3)?;
            text(
                &mut clip,
                &tmp.shown,
                inner.right() - pad_x - tw,
                ty,
                MONO_SMALL,
                INK_PRIMARY,
                PAPER_3,
            )?;
        }
        drop(tmp);

        // Mode control, desktop parity: RAW plus every fixed word count, with the external
        // tool each mode cross-checks against below (the modes are deliberately not
        // interchangeable - see ARCHITECTURE.md's dice math note). The layout reserved
        // space for every wrapped hint line, so nothing here truncates.
        tabs(t, l.mode, &DICE_MODE_LABELS, dice_mode_index(self.mode))?;
        let mut hy = l.hint_y;
        for line in wrap_words(dice_hint(self.mode), l.info_w, BODY) {
            text(t, &line, l.info_x, hy, BODY, INK_SECONDARY, PAPER_1)?;
            hy += LINE;
        }

        // Effective-bits meter, desktop three-band semantics.
        let bits = self.effective_bits();
        strength_meter(t, l.meter, bits)?;
        let strength = Strength::of(bits);
        let pen = text(
            t,
            &format!("{bits} bits - "),
            l.info_x,
            l.status_y,
            MONO,
            INK_PRIMARY,
            PAPER_1,
        )?;
        text(t, strength.text(), pen, l.status_y, MONO, strength.color(), PAPER_1)?;

        // Keypad.
        for (i, k) in l.keys.iter().enumerate() {
            let label = ((b'1' + i as u8) as char).to_string();
            fill(t, *k, PAPER_3)?;
            frame(t, *k, BORDER_STRONG)?;
            text_centered(t, &label, *k, TITLE, INK_PRIMARY, PAPER_3)?;
        }
        button(t, l.backspace, "Backspace", ButtonKind::Secondary, PAPER_1)?;

        let ready = bits >= MIN_SECURE_BITS;
        button(
            t,
            l.done,
            "Done",
            if ready { ButtonKind::Primary } else { ButtonKind::Disabled },
            PAPER_1,
        )?;
        // The reason a disabled Done is disabled, always visible next to the meter. The
        // line budget is the one the layout reserved (measured from the worst case), so
        // this can neither clip nor overrun into the keypad.
        let status2_y = l.status_y + LINE;
        let need_lines = ((l.status_h - LINE) / LINE).max(1) as usize;
        if !ready {
            let deficit = MIN_SECURE_BITS - bits.min(MIN_SECURE_BITS);
            let more = rolls_for_bits(deficit);
            let need = format!("Need {MIN_SECURE_BITS} bits - about {more} more rolls");
            for (i, line) in wrap_words(&need, l.info_w, BODY).iter().take(need_lines).enumerate() {
                text(t, line, l.info_x, status2_y + i as i32 * LINE, BODY, DANGER, PAPER_1)?;
            }
        } else {
            let words = match self.mode {
                MnemonicMode::Raw => bip39::raw_bits_used(self.entropy.binary().len()) * 3 / 32,
                MnemonicMode::Words(n) => n.get(),
            };
            text(
                t,
                &format!("Ready: {words} words"),
                l.info_x,
                status2_y,
                BODY,
                SUCCESS,
                PAPER_1,
            )?;
        }
        Ok(())
    }

    fn activate(&mut self, id: RegionId, _env: &mut Env) -> Outcome {
        match id {
            RegionId::Digit(d) if (1..=6).contains(&d) => {
                // Stop short of the BIP39 encoder's ENT ceiling: past it more rolls can
                // no longer change the raw-mode result (see MAX_ENTROPY_BITS).
                if self.entropy.binary().len() + 2 <= bip39::MAX_ENTROPY_BITS {
                    self.rolls.push((b'0' + d) as char);
                    self.entropy = parse_dice(&self.rolls);
                }
                Outcome::stay()
            }
            RegionId::DiceBackspace => {
                self.rolls.pop();
                self.entropy = parse_dice(&self.rolls);
                Outcome::stay()
            }
            RegionId::Mode(i) if (i as usize) < DICE_MODE_LABELS.len() => {
                self.mode = dice_mode(i);
                Outcome::stay()
            }
            RegionId::DiceDone => {
                if self.effective_bits() < MIN_SECURE_BITS {
                    return Outcome::stay(); // Drawn disabled, with the reason beside it.
                }
                match bip39::mnemonic_from_dice(&self.entropy, self.mode) {
                    Ok(mnem) => Outcome::push(State::Mnemonic(MnemonicState::new(
                        self.entropy.clone(),
                        self.mode,
                        mnem,
                    ))),
                    Err(_) => Outcome::stay(),
                }
            }
            _ => Outcome::stay(),
        }
    }

    /// Back over rolls the user cannot get back asks first.
    ///
    /// The question is whether leaving LOSES something, and it is asked of the rolls
    /// themselves rather than of how the screen was reached: this screen is entered from
    /// Home, pushed from the wallet list and pushed from the lock screen, and ninety rolls
    /// are equally gone in all three. The exit modal's copy was written for exactly this
    /// screen - "You can re-enter your dice rolls or seed words to start again" - and every
    /// other screen in this chain that holds secret material already gates Back this way
    /// (mnemonic, passphrase, quiz, fork).
    ///
    /// An empty screen has nothing to lose, so it does not ask. A confirmation over nothing
    /// is the kind of prompt users learn to tap through, which costs the rolls the one time
    /// it mattered.
    fn back(&self) -> Nav {
        if self.rolls.is_empty() {
            Nav::Back
        } else {
            Nav::ConfirmExit
        }
    }
}

/// Per-frame heap copies of the roll digits, wiped on every exit path (the same drop
/// guard pattern as the phrase screen's - `?` returns must not strand secret bytes).
struct RollTemps {
    grouped: String,
    shown: String,
}

impl Drop for RollTemps {
    fn drop(&mut self) {
        self.grouped.zeroize();
        self.shown.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::DICE_KEY_MIN;
    use crate::screens::testing::{Fixture, GEOMETRIES};

    /// Review item (m3): the fixed hint reservation clipped the wrapped cross-check
    /// hint. The layout now reserves what `wrap_words` measures; this pins that no
    /// mode/geometry combination clips the hint, starves the keypad below its 80px
    /// physical floor, undersizes a mode segment, or pushes the status block out of
    /// the body - for the FULL desktop mode set (RAW, 12, 15, 18, 21, 24).
    #[test]
    fn dice_layout_fits_every_mode_on_both_geometries() {
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            let body = f.m.body();
            for i in 0..DICE_MODE_LABELS.len() as u8 {
                let mode = dice_mode(i);
                let mut s = DiceState::new();
                s.mode = mode;
                let l = s.layout(&f.ctx());
                for k in &l.keys {
                    assert!(
                        k.w >= DICE_KEY_MIN && k.h >= DICE_KEY_MIN,
                        "{w}x{h} {mode:?}: key {k:?} below the {DICE_KEY_MIN}px floor"
                    );
                }
                // Mode segments stay finger-sized on both panels.
                let seg_w = l.mode.w / DICE_MODE_LABELS.len() as i32;
                assert!(
                    seg_w >= DICE_KEY_MIN && l.mode.h >= 44,
                    "{w}x{h}: mode segment {seg_w}x{} too small",
                    l.mode.h
                );
                // Full-width rows precede the columns and never overlap them.
                assert!(l.hist.w == body.w && l.mode.w == body.w);
                assert!(l.hist.bottom() <= l.mode.y && l.mode.bottom() <= l.hint_y);
                let lines = wrap_words(dice_hint(mode), l.info_w, BODY).len() as i32;
                assert!(
                    l.hint_y + lines * LINE <= l.meter.y,
                    "{w}x{h} {mode:?}: hint clips into the meter"
                );
                assert!(
                    l.status_y + l.status_h <= body.bottom(),
                    "{w}x{h} {mode:?}: status block leaves the body"
                );
                assert!(l.done.bottom() <= body.bottom());
            }
        }
    }
}
