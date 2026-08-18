// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The screens: layout, hit regions and painting for every state of the [`crate::Ui`].
//!
//! Discipline: for each screen ONE layout function computes the rectangles from
//! [`Metrics`] (and the little state that affects geometry), and both `regions` (hit
//! testing) and `draw` (painting) consume it - a button can never be drawn where it
//! cannot be tapped or vice versa. Scrollable screens measure their content by running
//! the same draw code against [`NullTarget`], so scroll clamping cannot drift from
//! rendering either.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use embedded_graphics::draw_target::{DrawTarget, DrawTargetExt};
use embedded_graphics::pixelcolor::Rgb565;
use zeroize::Zeroize;

use crate::canvas::{
    self, button, fill, frame, mono_wrapped, panel, strength_meter, tabs, text, text_centered,
    toggle, wrap_words, ButtonKind, BODY, HEADING, MONO, MONO_SMALL, TITLE,
};
use crate::layout::{Metrics, Rect};
use crate::theme::*;
use crate::{
    dice_mode_index, DiceState, MnemonicState, NullTarget, Page, PassFocus, PassState,
    PhraseState, QrModal, Region, RegionId, SchemesState, State, VerifyInfo,
    DICE_MODE_LABELS, VERSION,
};
use notyas_core::bip39::{
    self, current_word_fragment, rolls_for_bits, words_with_prefix, Checksum, MnemonicMode,
    MIN_SECURE_BITS,
};
use notyas_core::bitcoin::Network;
use notyas_core::derive::Scheme;

const LINE: i32 = 42; // BODY / HEADING / MONO line height
const SMALL_LINE: i32 = 36; // MONO_SMALL line height

// ---------------------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------------------

pub(crate) fn regions(m: &Metrics, state: &State) -> Vec<Region> {
    let mut out = Vec::new();
    match state {
        State::Home => {
            let btns = home_buttons(m);
            out.push(Region { id: RegionId::HomeNewSeed, rect: btns[0] });
            out.push(Region { id: RegionId::HomeVerifySeed, rect: btns[1] });
            out.push(Region { id: RegionId::HomeVerifyDevice, rect: btns[2] });
            out.push(Region { id: RegionId::NetToggle, rect: home_net_toggle(m) });
        }
        State::Dice(s) => {
            let l = dice_layout(m, s.mode);
            out.push(Region { id: RegionId::Back, rect: back_rect(m) });
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
        State::Mnemonic(s) => {
            if s.modal {
                let (_, cancel, confirm) = modal_layout(m, &REVEAL_MODAL);
                out.push(Region { id: RegionId::ModalCancel, rect: cancel });
                out.push(Region { id: RegionId::ModalConfirm, rect: confirm });
            } else {
                let l = mnem_layout(m, s.revealed);
                out.push(Region { id: RegionId::Back, rect: back_rect(m) });
                if let Some(reveal) = l.reveal {
                    out.push(Region { id: RegionId::Reveal, rect: reveal });
                }
                out.push(Region { id: RegionId::Next, rect: l.next });
            }
        }
        State::Phrase(s) => {
            let l = phrase_layout(m);
            out.push(Region { id: RegionId::Back, rect: back_rect(m) });
            for i in 0..suggestions(&s.text).len() {
                out.push(Region { id: RegionId::Suggest(i as u8), rect: suggest_chip(l.strip, i) });
            }
            for k in keyboard(l.kb, s.page) {
                out.push(Region { id: k.id, rect: k.rect });
            }
        }
        State::Passphrase(s) => {
            let l = pass_layout(m);
            out.push(Region { id: RegionId::Back, rect: back_rect(m) });
            out.push(Region { id: RegionId::PassShow, rect: l.show_btn });
            out.push(Region { id: RegionId::PassToggle, rect: l.toggle });
            if s.enabled {
                out.push(Region { id: RegionId::PassEntry, rect: l.entry });
                if !s.entry.is_empty() {
                    out.push(Region { id: RegionId::PassConfirm, rect: l.confirm });
                }
                for k in keyboard(l.kb, s.page) {
                    out.push(Region { id: k.id, rect: k.rect });
                }
            } else {
                out.push(Region { id: RegionId::KeyDone, rect: l.continue_btn });
            }
        }
        State::Schemes(s) => {
            if let Some(qr) = &s.qr {
                // Modal open: like the reveal modal, the sheet below is inert.
                let l = qr_modal_layout(m, qr.data.size() as i32);
                out.push(Region { id: RegionId::ModalClose, rect: l.close });
            } else {
                let l = schemes_layout(m);
                out.push(Region { id: RegionId::Back, rect: back_rect(m) });
                let n = Scheme::ALL.len() as i32;
                let seg_w = l.tabs.w / n;
                for i in 0..n {
                    let w = if i == n - 1 { l.tabs.w - seg_w * (n - 1) } else { seg_w };
                    out.push(Region {
                        id: RegionId::Tab(i as u8),
                        rect: Rect::new(l.tabs.x + i * seg_w, l.tabs.y, w, l.tabs.h),
                    });
                }
                // QR buttons ride the scrolled content: replay the content walk (the
                // same code that draws, so the rects cannot drift) and keep only the
                // buttons fully inside the viewport - a partially clipped button draws
                // but does not tap, which is the honest reading of "half a button".
                let mut buttons = Vec::new();
                let _ = schemes_content(
                    &mut NullTarget,
                    m,
                    s,
                    l.viewport.y - s.scroll,
                    Some(&mut buttons),
                );
                out.extend(buttons.into_iter().filter(|b| {
                    b.rect.x >= l.viewport.x
                        && b.rect.y >= l.viewport.y
                        && b.rect.right() <= l.viewport.right()
                        && b.rect.bottom() <= l.viewport.bottom()
                }));
            }
        }
        // Deliberately empty: the derivation is synchronous and cannot be cancelled, so
        // the interstitial offers nothing to tap - not even Back, which would be a
        // button that lies.
        State::Deriving(_) => {}
        State::Verify { .. } => {
            out.push(Region { id: RegionId::Back, rect: back_rect(m) });
        }
    }
    out
}

pub(crate) fn draw<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    m: &Metrics,
    state: &State,
    verify: &VerifyInfo,
    network: Network,
) -> Result<(), D::Error> {
    fill(t, m.screen(), PAPER_1)?;
    match state {
        State::Home => draw_home(t, m, network),
        State::Dice(s) => draw_dice(t, m, s),
        State::Mnemonic(s) => draw_mnemonic(t, m, s),
        State::Phrase(s) => draw_phrase(t, m, s),
        State::Passphrase(s) => draw_passphrase(t, m, s),
        State::Deriving(_) => draw_deriving(t, m),
        State::Schemes(s) => draw_schemes(t, m, s),
        State::Verify { scroll } => draw_verify(t, m, verify, *scroll),
    }
}

/// Maximum scroll offset of the current screen (0 when everything fits).
pub(crate) fn scroll_limit(m: &Metrics, state: &State, verify: &VerifyInfo) -> i32 {
    match state {
        State::Mnemonic(s) => {
            let l = mnem_layout(m, s.revealed);
            let (cols, _, cell_h) = mnem_grid(m);
            let rows = s.mnem.words.len().div_ceil(cols.max(1)) as i32;
            (rows * cell_h - l.viewport.h).max(0)
        }
        State::Schemes(s) => {
            let l = schemes_layout(m);
            let end =
                schemes_content(&mut NullTarget, m, s, l.viewport.y, None).unwrap_or_default();
            (end - l.viewport.y - l.viewport.h).max(0)
        }
        State::Verify { .. } => {
            let body = m.body();
            let end = verify_content(&mut NullTarget, m, verify, body.y).unwrap_or_default();
            (end - body.y - body.h).max(0)
        }
        _ => 0,
    }
}

// ---------------------------------------------------------------------------------------
// Top bar
// ---------------------------------------------------------------------------------------

fn back_rect(m: &Metrics) -> Rect {
    Rect::new(m.gap, m.gap / 2, m.bar * 2, m.bar - m.gap)
}

fn draw_bar<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    m: &Metrics,
    title: &str,
) -> Result<(), D::Error> {
    bar(t, m, title, true)
}

/// Top bar without the Back affordance, for a screen that has no tappable regions at
/// all: a drawn button that nothing hit-tests would be a lie about what the panel does.
fn draw_bar_no_back<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    m: &Metrics,
    title: &str,
) -> Result<(), D::Error> {
    bar(t, m, title, false)
}

fn bar<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    m: &Metrics,
    title: &str,
    back: bool,
) -> Result<(), D::Error> {
    fill(t, Rect::new(0, 0, m.w, m.bar), PAPER_2)?;
    fill(t, Rect::new(0, m.bar - 1, m.w, 1), BORDER)?;
    let back_r = back_rect(m);
    let x = if back {
        button(t, back_r, "< Back", ButtonKind::Ghost, PAPER_2)?;
        back_r.right() + m.gap
    } else {
        back_r.x
    };
    let y = (m.bar - LINE) / 2;
    text(t, title, x, y, HEADING, INK_PRIMARY, PAPER_2)?;
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Home
// ---------------------------------------------------------------------------------------

fn home_buttons(m: &Metrics) -> [Rect; 3] {
    let c = m.content();
    let w = c.w * 3 / 4;
    let x = c.x + (c.w - w) / 2;
    let total = 3 * m.btn + 2 * m.gap;
    let y = m.h - m.pad - total;
    [
        Rect::new(x, y, w, m.btn),
        Rect::new(x, y + m.btn + m.gap, w, m.btn),
        Rect::new(x, y + 2 * (m.btn + m.gap), w, m.btn),
    ]
}

/// The mainnet/testnet toggle, top-right so it reads as a device setting rather than a
/// step of the flow. Compact on purpose: it clears the centered title on both shipped
/// geometries (asserted by the region-overlap tests).
fn home_net_toggle(m: &Metrics) -> Rect {
    let w = 260.min(m.w / 2);
    Rect::new(m.w - m.pad - w, m.pad, w, 48)
}

fn draw_home<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    m: &Metrics,
    network: Network,
) -> Result<(), D::Error> {
    let title_y = m.h / 7;
    text_centered(
        t,
        "notyas",
        Rect::new(0, title_y, m.w, TITLE.line_height as i32),
        TITLE,
        INK_PRIMARY,
        PAPER_1,
    )?;
    text_centered(
        t,
        &format!("version {VERSION}"),
        Rect::new(0, title_y + TITLE.line_height as i32 + m.gap, m.w, LINE),
        BODY,
        INK_SECONDARY,
        PAPER_1,
    )?;
    // Desktop parity: the network is a pipeline input. Everything derived downstream
    // (addresses, xpub prefixes, the schemes info line) reflects the choice.
    let mainnet = network == Network::Bitcoin;
    toggle(t, home_net_toggle(m), ["Mainnet", "Testnet"], usize::from(!mainnet))?;
    let [b0, b1, b2] = home_buttons(m);
    button(t, b0, "New seed (dice)", ButtonKind::Primary, PAPER_1)?;
    button(t, b1, "Verify existing seed", ButtonKind::Secondary, PAPER_1)?;
    button(t, b2, "Verify device", ButtonKind::Secondary, PAPER_1)?;
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Dice entry
// ---------------------------------------------------------------------------------------

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

struct DiceLayout {
    /// Full-width roll-history well (typed input, unmasked - see `draw_dice`).
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

fn dice_layout(m: &Metrics, mode: MnemonicMode) -> DiceLayout {
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
    DiceLayout {
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

/// Per-frame heap copies of the roll digits, wiped on every exit path (the same drop
/// guard pattern as `PhraseTemps` - `?` returns must not strand secret bytes).
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

fn draw_dice<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    m: &Metrics,
    s: &DiceState,
) -> Result<(), D::Error> {
    draw_bar(t, m, "New seed")?;
    let l = dice_layout(m, s.mode);

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
    let count = format!("Rolls {}", s.entropy.events());
    let adv = MONO_SMALL.glyph('6').advance as i32;
    let cap = ((inner.w - 2 * pad_x - MONO_SMALL.text_width(&count) as i32 - 2 * m.gap)
        / adv)
        .max(0) as usize;
    let tmp = {
        let mut grouped = String::with_capacity(s.rolls.len() + s.rolls.len() / 5 + 2);
        for (i, c) in s.rolls.chars().enumerate() {
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
    tabs(t, l.mode, &DICE_MODE_LABELS, dice_mode_index(s.mode))?;
    let mut hy = l.hint_y;
    for line in wrap_words(dice_hint(s.mode), l.info_w, BODY) {
        text(t, &line, l.info_x, hy, BODY, INK_SECONDARY, PAPER_1)?;
        hy += LINE;
    }

    // Effective-bits meter, desktop three-band semantics.
    let bits = s.effective_bits();
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
        let need = format!("Need {MIN_SECURE_BITS} bits - about {} more rolls", rolls_for_bits(deficit));
        for (i, line) in wrap_words(&need, l.info_w, BODY).iter().take(need_lines).enumerate() {
            text(t, line, l.info_x, status2_y + i as i32 * LINE, BODY, DANGER, PAPER_1)?;
        }
    } else {
        let words = match s.mode {
            MnemonicMode::Raw => bip39::raw_bits_used(s.entropy.binary().len()) * 3 / 32,
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

// ---------------------------------------------------------------------------------------
// Mnemonic display
// ---------------------------------------------------------------------------------------

struct MnemLayout {
    sub_y: i32,
    viewport: Rect,
    reveal: Option<Rect>,
    next: Rect,
}

fn mnem_layout(m: &Metrics, revealed: bool) -> MnemLayout {
    let body = m.body();
    let g = m.gap;
    let sub_y = body.y;
    let ctl_y = body.bottom() - m.btn;
    let viewport = Rect::new(body.x, sub_y + LINE + g, body.w, ctl_y - g - (sub_y + LINE + g));
    let (reveal, next) = if revealed {
        (None, Rect::new(body.x, ctl_y, body.w, m.btn))
    } else {
        let rw = (body.w - g) * 2 / 5;
        (
            Some(Rect::new(body.x, ctl_y, rw, m.btn)),
            Rect::new(body.x + rw + g, ctl_y, body.w - rw - g, m.btn),
        )
    };
    MnemLayout { sub_y, viewport, reveal, next }
}

/// Grid geometry: (columns, cell width, cell height).
fn mnem_grid(m: &Metrics) -> (usize, i32, i32) {
    let body = m.body();
    let cols = (body.w / 220).clamp(2, 4) as usize;
    let cell_w = (body.w - (cols as i32 - 1) * m.gap) / cols as i32;
    (cols, cell_w, LINE + 12)
}

fn draw_mnemonic<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    m: &Metrics,
    s: &MnemonicState,
) -> Result<(), D::Error> {
    draw_bar(t, m, "Seed words")?;
    let l = mnem_layout(m, s.revealed);

    let mode = match s.mode {
        MnemonicMode::Raw => String::from("RAW"),
        MnemonicMode::Words(n) => format!("FIXED {n}"),
    };
    let sub = format!(
        "{} words - {mode} - {}",
        s.mnem.words.len(),
        if s.revealed { "REVEALED" } else { "masked" }
    );
    text(t, &sub, m.body().x, l.sub_y, BODY, INK_SECONDARY, PAPER_1)?;

    // The word grid. Masked, every slot draws the SAME fixed bullet run, so the pixels
    // carry nothing about the words (the masking tests assert this literally).
    let (cols, cell_w, cell_h) = mnem_grid(m);
    let num_w = MONO_SMALL.text_width("888") as i32 + 8;
    {
        let mut clip = t.clipped(&l.viewport.to_eg());
        for (i, word) in s.mnem.words.iter().enumerate() {
            let col = (i % cols) as i32;
            let row = (i / cols) as i32;
            let x = l.viewport.x + col * (cell_w + m.gap);
            let y = l.viewport.y + row * cell_h - s.scroll;
            let num = format!("{}", i + 1);
            let nw = MONO_SMALL.text_width(&num) as i32;
            text(&mut clip, &num, x + num_w - 8 - nw, y + 4, MONO_SMALL, INK_MUTED, PAPER_1)?;
            let shown: &str = if s.revealed { word } else { mask_word() };
            text(&mut clip, shown, x + num_w, y, MONO, INK_PRIMARY, PAPER_1)?;
        }
    }

    if let Some(r) = l.reveal {
        button(t, r, "Reveal...", ButtonKind::Secondary, PAPER_1)?;
    }
    button(t, l.next, "Next", ButtonKind::Primary, PAPER_1)?;

    if s.modal {
        draw_modal(t, m, &REVEAL_MODAL)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Modal (reveal-confirm component)
// ---------------------------------------------------------------------------------------

pub(crate) struct ModalSpec {
    pub title: &'static str,
    pub body: &'static [&'static str],
    pub cancel: &'static str,
    pub confirm: &'static str,
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

fn modal_layout(m: &Metrics, spec: &ModalSpec) -> (Rect, Rect, Rect) {
    let w = (m.w - 4 * m.pad).min(620);
    let inner_w = w - 2 * m.pad;
    let mut lines = 0i32;
    for p in spec.body {
        lines += wrap_words(p, inner_w, BODY).len() as i32;
    }
    let btn_h = m.btn.min(72);
    let h = m.pad + LINE + m.gap + lines * LINE + m.gap + btn_h + m.pad;
    let x = (m.w - w) / 2;
    let y = (m.h - h) / 2;
    let panel = Rect::new(x, y, w, h);
    let by = panel.bottom() - m.pad - btn_h;
    let confirm_w = (canvas::HEADING.text_width(spec.confirm) as i32 + 3 * m.pad).max(180);
    let cancel_w = (canvas::HEADING.text_width(spec.cancel) as i32 + 3 * m.pad).max(150);
    let confirm = Rect::new(panel.right() - m.pad - confirm_w, by, confirm_w, btn_h);
    let cancel = Rect::new(confirm.x - m.gap - cancel_w, by, cancel_w, btn_h);
    (panel, cancel, confirm)
}

fn draw_modal<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    m: &Metrics,
    spec: &ModalSpec,
) -> Result<(), D::Error> {
    let (p, cancel, confirm) = modal_layout(m, spec);
    // Modals peak at white and carry the one 2px danger frame in the UI; there is no
    // backdrop dim (no alpha on RGB565) - the frame and elevation do the work.
    fill(t, p, PAPER_3)?;
    frame(t, p, DANGER)?;
    frame(t, p.inset(1), DANGER)?;
    let inner = Rect::new(p.x + m.pad, p.y + m.pad, p.w - 2 * m.pad, p.h);
    text(t, spec.title, inner.x, inner.y, HEADING, INK_PRIMARY, PAPER_3)?;
    let mut y = inner.y + LINE + m.gap;
    for para in spec.body {
        for line in wrap_words(para, inner.w, BODY) {
            text(t, &line, inner.x, y, BODY, INK_SECONDARY, PAPER_3)?;
            y += LINE;
        }
    }
    button(t, cancel, spec.cancel, ButtonKind::Ghost, PAPER_3)?;
    button(t, confirm, spec.confirm, ButtonKind::Danger, PAPER_3)?;
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Exit-confirmation modal (Back on serious screens)
// ---------------------------------------------------------------------------------------

/// The exit-confirmation modal shown when Back is pressed on a screen holding a
/// derived secret (Mnemonic, Passphrase, Schemes). The user sees their seed or
/// derived keys and could lose work by going back - this gate prevents an
/// accidental tap from discarding it silently.
static EXIT_MODAL: ModalSpec = ModalSpec {
    title: "Go back?",
    body: &[
        "Going back will clear your current work from this screen.",
        "You can re-enter your dice rolls or seed words to start again.",
    ],
    cancel: "Cancel",
    confirm: "Go back",
};

/// Hit regions for the exit modal: only Cancel and Confirm are tappable.
pub(crate) fn exit_modal_regions(m: &Metrics) -> Vec<Region> {
    let (_, cancel, confirm) = modal_layout(m, &EXIT_MODAL);
    vec![
        Region { id: RegionId::ModalCancel, rect: cancel },
        Region { id: RegionId::ModalConfirm, rect: confirm },
    ]
}

/// Draw the exit modal overlay on top of the current screen.
pub(crate) fn draw_exit_modal<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    m: &Metrics,
) -> Result<(), D::Error> {
    draw_modal(t, m, &EXIT_MODAL)
}

// ---------------------------------------------------------------------------------------
// On-screen keyboard (shared by phrase entry and passphrase)
// ---------------------------------------------------------------------------------------

pub(crate) struct Key {
    pub id: RegionId,
    pub rect: Rect,
    pub label: String,
}

fn page_rows(page: Page) -> [&'static str; 3] {
    match page {
        Page::Lower => ["qwertyuiop", "asdfghjkl", "zxcvbnm"],
        Page::Upper => ["QWERTYUIOP", "ASDFGHJKL", "ZXCVBNM"],
        Page::Digits => ["1234567890", "-/:;()$&@", ".,?!'\"_"],
        Page::Symbols => ["[]{}#%^*+=", "\\|~<>`", ".,?!'\"_"],
    }
}

/// Keyboard row gap and the floor/ceiling on a row's height. The floor is physical (a
/// 40 px key is ~4.4 mm on the primary panel, the smallest a letter key may get).
const KB_ROW_GAP: i32 = 8;
const KB_ROW_MIN: i32 = 40;
const KB_ROW_MAX: i32 = 72;

/// Height the keyboard occupies when every row is at its floor - the smallest `area`
/// [`keyboard`] can be given before it starts drawing above `area.y`. Screens that share
/// their body with a keyboard size themselves against this rather than restating it.
pub(crate) fn keyboard_min_h() -> i32 {
    4 * KB_ROW_MIN + 3 * KB_ROW_GAP
}

/// Bottom-anchored keyboard in `area`: three character rows and a control row.
fn keyboard(area: Rect, page: Page) -> Vec<Key> {
    let rg = KB_ROW_GAP;
    let kg = 6; // key gap
    let row_h = ((area.h - 3 * rg) / 4).clamp(KB_ROW_MIN, KB_ROW_MAX);
    let kb_h = 4 * row_h + 3 * rg;
    let top = area.bottom() - kb_h;
    let key_w = (area.w - 9 * kg) / 10;

    let mut keys = Vec::new();
    for (r, row) in page_rows(page).iter().enumerate() {
        let n = row.chars().count() as i32;
        let row_w = n * key_w + (n - 1) * kg;
        let x0 = area.x + (area.w - row_w) / 2;
        let y = top + r as i32 * (row_h + rg);
        for (i, c) in row.chars().enumerate() {
            keys.push(Key {
                id: RegionId::Key(c),
                rect: Rect::new(x0 + i as i32 * (key_w + kg), y, key_w, row_h),
                label: c.to_string(),
            });
        }
    }

    // Control row: [page A][page B][space][backspace][done], weighted 2:2:6:4:4.
    // Backspace gets a larger share (4/18 vs the old 3/20) so the correction key is
    // an easy target; "Bksp" labels it unambiguously (the atlas is ASCII plus the bullet
    // and the ellipsis, so there is no erase-left glyph to draw).
    let y = top + 3 * (row_h + rg);
    let unit = area.w - 4 * kg;
    let widths = [unit * 2 / 18, unit * 2 / 18, unit * 6 / 18, unit * 4 / 18, 0];
    let (a, b): ((RegionId, &str), (RegionId, &str)) = match page {
        Page::Lower | Page::Upper => ((RegionId::Shift, "Shift"), (RegionId::PageDigits, "?123")),
        Page::Digits => ((RegionId::PageLetters, "abc"), (RegionId::PageSymbols, "#+=")),
        Page::Symbols => ((RegionId::PageLetters, "abc"), (RegionId::PageDigits, "123")),
    };
    let ids = [a.0, b.0, RegionId::Space, RegionId::KeyBackspace, RegionId::KeyDone];
    let labels = [a.1, b.1, "", "Bksp", "Done"];
    let mut x = area.x;
    for i in 0..5 {
        let w = if i == 4 { area.right() - x } else { widths[i] };
        keys.push(Key {
            id: ids[i],
            rect: Rect::new(x, y, w, row_h),
            label: String::from(labels[i]),
        });
        x += w + kg;
    }
    keys
}

fn draw_keyboard<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    area: Rect,
    page: Page,
    done_enabled: bool,
) -> Result<(), D::Error> {
    for k in keyboard(area, page) {
        match k.id {
            RegionId::Key(_) => {
                fill(t, k.rect, PAPER_3)?;
                frame(t, k.rect, BORDER_STRONG)?;
                text_centered(t, &k.label, k.rect, MONO, INK_PRIMARY, PAPER_3)?;
            }
            RegionId::Space => {
                fill(t, k.rect, PAPER_3)?;
                frame(t, k.rect, BORDER_STRONG)?;
            }
            RegionId::KeyDone => {
                let kind = if done_enabled { ButtonKind::Primary } else { ButtonKind::Disabled };
                button(t, k.rect, "Done", kind, PAPER_1)?;
            }
            _ => {
                button(t, k.rect, &k.label, ButtonKind::Secondary, PAPER_1)?;
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Phrase entry (verify existing seed)
// ---------------------------------------------------------------------------------------

struct PhraseLayout {
    /// Tail view of the typed phrase. The FLEXIBLE element of this screen: everything
    /// below it is a physical minimum, so the well absorbs whatever the panel has left
    /// (three lines at 720x720, one at 800x480).
    well: Rect,
    advisory_y: i32,
    /// Always-reserved band for the BIP39 completion chips, so the keyboard cannot jump
    /// under a finger when suggestions appear or disappear.
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
/// Chips offered at once. The strip is ONE row, not a stack: five stacked 60 px rows
/// (300 px) do not exist on the 800x480 panel, whose whole body is 377 px and whose
/// keyboard alone needs 184. Four is what fits side by side at the 8-character
/// worst case of the wordlist on the narrower of the two shipped geometries.
const MAX_SUGGEST: usize = 4;
/// Vertical padding inside the phrase well (8 px above and below the text lines).
const WELL_PAD: i32 = 16;

/// The chips the strip offers for `text`: wordlist completions of the word being typed.
///
/// Single source of truth for the strip - `regions` hit-tests it, `draw_phrase` paints
/// it, and the tap handler indexes it - so a chip can never resolve to a different word
/// than the one under the finger.
///
/// Empty while no word is in progress, and empty when the fragment is already the only
/// word it can be: there is nothing left to complete, and the strip stays out of the way
/// so the checksum advisory is what the user reads at the end of a phrase.
pub(crate) fn suggestions(text: &str) -> Vec<&'static str> {
    let fragment = current_word_fragment(text);
    let words = words_with_prefix(fragment, MAX_SUGGEST);
    if words.len() == 1 && words[0] == fragment {
        return Vec::new();
    }
    words
}

/// Chip `i` of the strip. Chips keep a fixed width whatever the match count is, so the
/// row does not reflow letter by letter as the user types.
fn suggest_chip(strip: Rect, i: usize) -> Rect {
    let n = MAX_SUGGEST as i32;
    let w = (strip.w - (n - 1) * SUGGEST_GAP) / n;
    Rect::new(strip.x + i as i32 * (w + SUGGEST_GAP), strip.y, w, strip.h)
}

/// Lines of the phrase the well can show at the height it was given.
fn well_lines(well: Rect) -> usize {
    ((well.h - WELL_PAD) / SMALL_LINE).max(1) as usize
}

fn phrase_layout(m: &Metrics) -> PhraseLayout {
    let body = m.body();
    let g = m.gap;
    // Laid out from the bottom up. The keyboard floor and the chip height are physical
    // minimums; the advisory is one line; the well takes what remains, capped at the
    // three lines it wants and floored at one. On the 800x480 panel this budget is
    // exact to a few pixels, which is why the well - not the keyboard - is the part
    // that gives (the layout tests pin both ends of it).
    let spare = body.h - keyboard_min_h() - SUGGEST_H - LINE - 3 * g;
    let well_h = spare.clamp(SMALL_LINE + WELL_PAD, 3 * SMALL_LINE + WELL_PAD);
    let well = Rect::new(body.x, body.y, body.w, well_h);
    let advisory_y = well.bottom() + g;
    let strip = Rect::new(body.x, advisory_y + LINE + g, body.w, SUGGEST_H);
    let kb_top = strip.bottom() + g;
    PhraseLayout {
        well,
        advisory_y,
        strip,
        kb: Rect::new(body.x, kb_top, body.w, body.bottom() - kb_top),
    }
}

/// Per-frame copies of the typed phrase, wiped on drop. `draw_phrase` can leave early
/// through `?` on any draw error; owning the temporaries in a drop guard means no exit
/// path - early or normal - strands unwiped secret bytes in freed allocations.
struct PhraseTemps {
    chars: Vec<char>,
    lines: Vec<String>,
}

impl Drop for PhraseTemps {
    fn drop(&mut self) {
        self.lines.zeroize();
        self.chars.zeroize();
    }
}

fn draw_phrase<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    m: &Metrics,
    s: &PhraseState,
) -> Result<(), D::Error> {
    draw_bar(t, m, "Verify existing seed")?;
    let l = phrase_layout(m);

    // The typed phrase, UNMASKED: it is the user's own input, arriving from their eyes
    // and fingers - the desktop draws the same conclusion (survey section 5). Tail-end
    // display so the words being typed stay in view.
    panel(t, l.well, PAPER_3, BORDER_STRONG)?;
    let inner = l.well.inset(8);
    let adv = MONO_SMALL.glyph('m').advance as i32;
    let per_line = (inner.w / adv).max(1) as usize;
    // The phrase is shown unmasked by design, but its per-frame heap copies still obey
    // the hygiene rule: the drop guard wipes them on every exit path, including the `?`
    // returns inside the draw loop below.
    let tmp = {
        let chars: Vec<char> = s.text.chars().collect();
        let lines: Vec<String> = chars.chunks(per_line).map(|c| c.iter().collect()).collect();
        PhraseTemps { chars, lines }
    };
    let visible = tmp.lines.len().min(well_lines(l.well));
    for (i, line) in tmp.lines[tmp.lines.len() - visible..].iter().enumerate() {
        text(
            t,
            line,
            inner.x,
            inner.y + i as i32 * SMALL_LINE,
            MONO_SMALL,
            INK_PRIMARY,
            PAPER_3,
        )?;
    }

    // Caret: a short bar after the last character, so it is obvious where the next
    // keypress lands. Static, not blinking - the panel repaints on input only, and a
    // caret that needs a timer would be a lie about how this screen works. It rides the
    // LAST VISIBLE line, which is where the tail view always puts the end of the phrase.
    {
        let n = tmp.chars.len();
        let lines_total = n.div_ceil(per_line).max(1);
        let row = lines_total.min(visible.max(1)) - 1;
        let col = n - (lines_total - 1) * per_line;
        let cx = inner.x + col as i32 * adv;
        let cy = inner.y + row as i32 * SMALL_LINE + SMALL_LINE - 4;
        fill(t, Rect::new(cx, cy, 2, 3), ACCENT)?;
    }
    drop(tmp);

    // BIP39 completion chips. Cobalt-on-tint, the crate's "interactive" grammar, so they
    // read as buttons rather than as part of the phrase; each label is pixel-clipped to
    // its chip for the same reason the masked field is - a wide word must crop, never
    // bleed into the neighbouring target.
    for (i, word) in suggestions(&s.text).iter().enumerate() {
        let chip = suggest_chip(l.strip, i);
        fill(t, chip, ACCENT_TINT)?;
        frame(t, chip, ACCENT)?;
        let mut clip = t.clipped(&chip.to_eg());
        text_centered(&mut clip, word, chip, MONO_SMALL, ACCENT, ACCENT_TINT)?;
    }

    // Advisory only, never a veto: the desktop derives from any phrase and warns beside
    // it, and this screen reports the same three findings.
    let normalized = bip39::normalize_phrase(&s.text);
    if normalized.is_empty() {
        text(t, "Type your seed words", l.well.x, l.advisory_y, BODY, INK_MUTED, PAPER_1)?;
    } else {
        let check = bip39::check_phrase(&normalized);
        let (msg, color) = if !check.unknown_words.is_empty() {
            (
                format!(
                    "{} words - {} not in the word list",
                    check.word_count,
                    check.unknown_words.len()
                ),
                WARNING,
            )
        } else {
            match check.checksum {
                Checksum::Valid => (format!("{} words - checksum valid", check.word_count), SUCCESS),
                Checksum::Invalid => {
                    (format!("{} words - checksum invalid", check.word_count), WARNING)
                }
                Checksum::NotApplicable => (format!("{} words", check.word_count), INK_MUTED),
            }
        };
        text(t, &msg, l.well.x, l.advisory_y, BODY, color, PAPER_1)?;
    }

    draw_keyboard(t, l.kb, s.page, !normalized.is_empty())?;
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Passphrase entry
// ---------------------------------------------------------------------------------------

/// Width floor of the Show/Hide button. The measured widths of "Show" and "Hide" set the
/// real floor (see `pass_layout`); this keeps it a comfortable target rather than a label
/// with a border round it.
const SHOW_LABEL_W: i32 = 120;

struct PassLayout {
    toggle_label_y: i32,
    toggle: Rect,
    show_btn: Rect,
    entry: Rect,
    confirm: Rect,
    status_y: i32,
    kb: Rect,
    continue_btn: Rect,
    hint_y: i32,
}

fn pass_layout(m: &Metrics) -> PassLayout {
    let body = m.body();
    let g = m.gap;
    let toggle_h = 48;
    let toggle_w = (body.w / 3).max(200);
    let toggle = Rect::new(body.right() - toggle_w, body.y, toggle_w, toggle_h);
    // Header row, right to left: the Off/On toggle is right-anchored, the Show/Hide
    // button sits immediately left of it, and the "Use passphrase" label takes the
    // remaining space from the left edge. Anchoring Show to the LEFT edge instead put it
    // straight on top of that label on both shipped geometries.
    let show_w = SHOW_LABEL_W.max(HEADING.text_width("Hide") as i32 + 2 * m.gap);
    let show_btn = Rect::new(toggle.x - m.gap - show_w, body.y, show_w, toggle_h);
    let fields_y = body.y + toggle_h + g;
    let (entry, confirm, status_y) = if m.landscape() {
        let fw = (body.w - g) / 2;
        let e = Rect::new(body.x, fields_y, fw, 52);
        let c = Rect::new(body.x + fw + g, fields_y, body.w - fw - g, 52);
        (e, c, e.bottom() + g / 2)
    } else {
        let e = Rect::new(body.x, fields_y, body.w, 56);
        let c = Rect::new(body.x, e.bottom() + g, body.w, 56);
        (e, c, c.bottom() + g / 2)
    };
    let kb_top = status_y + SMALL_LINE + g;
    PassLayout {
        toggle_label_y: body.y + (toggle_h - LINE) / 2,
        toggle,
        show_btn,
        entry,
        confirm,
        status_y,
        kb: Rect::new(body.x, kb_top, body.w, body.bottom() - kb_top),
        continue_btn: Rect::new(body.x, body.bottom() - m.btn, body.w, m.btn),
        hint_y: fields_y + g,
    }
}

fn draw_passphrase<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    m: &Metrics,
    s: &PassState,
) -> Result<(), D::Error> {
    draw_bar(t, m, "Passphrase")?;
    let l = pass_layout(m);
    let body = m.body();

    // Clipped to the space the header row leaves it: the label is the only element here
    // that can grow with wording, so it is the one that must crop rather than run under
    // the Show button. `pass_layout_fits` pins that it never has to.
    let label = Rect::new(body.x, l.toggle_label_y, l.show_btn.x - m.gap - body.x, LINE);
    let mut clip = t.clipped(&label.to_eg());
    text(&mut clip, "Use passphrase", label.x, label.y, BODY, INK_PRIMARY, PAPER_1)?;
    toggle(t, l.toggle, ["Off", "On"], usize::from(s.enabled))?;
    // Show/Hide the passphrase fields (default Hidden): an unseen typo silently derives
    // a different wallet, which is the worse failure. Plain button, no confirm.
    let show_label = if s.show { "Hide" } else { "Show" };
    button(t, l.show_btn, show_label, ButtonKind::Secondary, PAPER_1)?;

    if !s.enabled {
        // Desktop wording for the off state, then the warning that matters before
        // opting in.
        let mut y = l.hint_y + LINE;
        for para in [
            "Off: the seed is derived with an empty passphrase.",
            "Any passphrase produces a valid but different wallet, so a typo cannot \
             be detected. Record the first receive address to verify this wallet later.",
        ] {
            for line in wrap_words(para, body.w, BODY) {
                text(t, &line, body.x, y, BODY, INK_SECONDARY, PAPER_1)?;
                y += LINE;
            }
            y += m.gap;
        }
        button(t, l.continue_btn, "Continue", ButtonKind::Primary, PAPER_1)?;
        return Ok(());
    }

    // Entry and confirm fields. Masked one bullet per typed character (the INPUT rule -
    // see `canvas::field`), or literal with spaces marked while Show is on.
    canvas::field(t, l.entry, &s.entry, !s.show, s.focus == PassFocus::Entry)?;
    if s.entry.is_empty() {
        let y = l.entry.y + (l.entry.h - LINE) / 2;
        text(t, "passphrase", l.entry.x + 12, y, BODY, INK_MUTED, PAPER_3)?;
    } else {
        // The opt-in confirm field appears once there is something to confirm.
        canvas::field(t, l.confirm, &s.confirm, !s.show, s.focus == PassFocus::Confirm)?;
        if s.confirm.is_empty() {
            let y = l.confirm.y + (l.confirm.h - LINE) / 2;
            text(t, "repeat passphrase", l.confirm.x + 12, y, BODY, INK_MUTED, PAPER_3)?;
        }
    }

    // `differ` is the exact predicate the Done handler blocks on; the drawn state must
    // never disagree with it. The status row carries ONE line (two would overlap on the
    // 720-wide panel): the mismatch warning once a confirm attempt exists, otherwise the
    // byte counter - extended with the reason Done is still disabled while the confirm
    // field is untouched (a disabled control always says why).
    //
    // The counter reports NFKD BYTES, the desktop's counter semantics: BIP39 feeds
    // PBKDF2 the NFKD byte string, and byte length is what external passphrase limits
    // (e.g. other wallets' 256-byte caps) are stated in. The on-screen keyboard emits
    // ASCII only (test-asserted), for which NFKD is the identity and every char is one
    // byte - so `len()` IS the NFKD byte count, with no normalization pass over the
    // secret here in the draw path.
    let bytes = s.entry.len();
    let differ = *s.entry != *s.confirm;
    if differ && !s.confirm.is_empty() {
        let msg = "The two passphrases are different.";
        text(t, msg, body.x, l.status_y, MONO_SMALL, DANGER, PAPER_1)?;
    } else if differ {
        let msg = format!("{bytes} bytes (NFKD) - repeat to continue");
        text(t, &msg, body.x, l.status_y, MONO_SMALL, INK_MUTED, PAPER_1)?;
    } else {
        let msg = format!("{bytes} bytes (NFKD)");
        text(t, &msg, body.x, l.status_y, MONO_SMALL, INK_MUTED, PAPER_1)?;
    }

    draw_keyboard(t, l.kb, s.page, !differ)?;
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Deriving interstitial
// ---------------------------------------------------------------------------------------

/// The frame that must be on the panel before `Ui::tick` starts PBKDF2. Everything here
/// is static: a screen that promises a spinner it cannot animate (the panel repaints on
/// input only) would be a worse lie than a still one, so this says what is happening,
/// how long it takes, and what not to do meanwhile.
fn draw_deriving<D: DrawTarget<Color = Rgb565>>(t: &mut D, m: &Metrics) -> Result<(), D::Error> {
    draw_bar_no_back(t, m, "Deriving")?;
    let body = m.body();
    let card_h = 3 * LINE + 4 * m.gap;
    let card = Rect::new(body.x, body.y + (body.h - card_h) / 2, body.w, card_h);
    panel(t, card, PAPER_2, BORDER_STRONG)?;
    let mut y = card.y + m.gap;
    text_centered(
        t,
        "Deriving keys...",
        Rect::new(card.x, y, card.w, LINE),
        HEADING,
        INK_PRIMARY,
        PAPER_2,
    )?;
    y += LINE + m.gap;
    for line in [
        "2048 rounds of PBKDF2, then every scheme.",
        "This takes a few seconds. Do not power off.",
    ] {
        text_centered(t, line, Rect::new(card.x, y, card.w, LINE), BODY, INK_SECONDARY, PAPER_2)?;
        y += LINE;
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Schemes (xpubs and receive addresses)
// ---------------------------------------------------------------------------------------

struct SchemesLayout {
    tabs: Rect,
    info_y: i32,
    viewport: Rect,
}

fn schemes_layout(m: &Metrics) -> SchemesLayout {
    let body = m.body();
    let g = m.gap;
    let tabs = Rect::new(body.x, body.y, body.w, 56);
    let info_y = tabs.bottom() + g;
    let vp_top = info_y + SMALL_LINE + g;
    SchemesLayout {
        tabs,
        info_y,
        viewport: Rect::new(body.x, vp_top, body.w, body.bottom() - vp_top),
    }
}

/// QR button geometry: fixed physical size, not panel-derived - fingers do not scale
/// with the panel (same reasoning as [`crate::layout::DICE_KEY_MIN`]).
const QR_BTN_W: i32 = 96;
const QR_BTN_H: i32 = 56;

/// One caption + wrapped-value block with a QR button on the right; returns the y after
/// the block. The value wraps beside the button column, and the block is never shorter
/// than the button so consecutive buttons cannot overlap. When `buttons` is given the
/// button's region is collected (content coordinates - the caller filters by viewport).
#[allow(clippy::too_many_arguments)] // one deep helper beats five drifting copies
fn qr_block<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    m: &Metrics,
    y: i32,
    caption: &str,
    value: &str,
    id: RegionId,
    buttons: &mut Option<&mut Vec<Region>>,
) -> Result<i32, D::Error> {
    let body = m.body();
    let rect = Rect::new(body.right() - QR_BTN_W, y, QR_BTN_W, QR_BTN_H);
    button(t, rect, "QR", ButtonKind::Secondary, PAPER_1)?;
    if let Some(list) = buttons {
        list.push(Region { id, rect });
    }
    let vw = body.w - QR_BTN_W - m.gap;
    text(t, caption, body.x, y, MONO_SMALL, INK_MUTED, PAPER_1)?;
    let end = mono_wrapped(
        t,
        value,
        Rect::new(body.x, y + SMALL_LINE, vw, i32::MAX / 2),
        MONO_SMALL,
        INK_PRIMARY,
        PAPER_1,
    )?;
    Ok(end.max(y + QR_BTN_H))
}

/// Draws (or measures, against [`NullTarget`]) the active tab's content starting at
/// `y0`; returns the y after the last line. Only PUBLIC values are drawn: account xpub,
/// SLIP-132 rendering, receive addresses - each with a QR button whose target is that
/// same public value (crate-level QR scope note). Private keys never reach the device
/// screen in 0.1.0 - there is no reveal for them, which is stronger than a mask.
fn schemes_content<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    m: &Metrics,
    s: &SchemesState,
    y0: i32,
    mut buttons: Option<&mut Vec<Region>>,
) -> Result<i32, D::Error> {
    let body = m.body();
    let g = m.gap;
    let sr = &s.report.schemes[s.tab.min(s.report.schemes.len() - 1)];
    let acct = &sr.derived.account;
    let mut y = y0;

    text(t, &format!("Account {}", acct.path), body.x, y, HEADING, INK_PRIMARY, PAPER_1)?;
    y += LINE + g;

    y = qr_block(t, m, y, "Account xpub", &acct.xpub, RegionId::QrXpub, &mut buttons)?;
    if let (Some(slip), Some((_, label))) = (&acct.slip132_pub, sr.scheme.slip132_labels()) {
        y += g;
        y = qr_block(
            t,
            m,
            y,
            &format!("{label} (SLIP-132)"),
            slip,
            RegionId::QrSlip132,
            &mut buttons,
        )?;
    }

    y += g * 2;
    text(t, "Receive addresses", body.x, y, HEADING, INK_PRIMARY, PAPER_1)?;
    y += LINE + g;
    for (i, row) in sr.derived.rows.iter().enumerate() {
        y = qr_block(
            t,
            m,
            y,
            &row.path,
            &row.address,
            RegionId::QrAddress(i as u8),
            &mut buttons,
        )?;
        y += g;
    }
    Ok(y)
}

fn draw_schemes<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    m: &Metrics,
    s: &SchemesState,
) -> Result<(), D::Error> {
    draw_bar(t, m, "Wallet")?;
    let l = schemes_layout(m);
    let body = m.body();

    let labels: Vec<String> =
        Scheme::ALL.iter().map(|sc| sc.name().to_ascii_uppercase()).collect();
    let label_refs: Vec<&str> = labels.iter().map(String::as_str).collect();
    tabs(t, l.tabs, &label_refs, s.tab)?;

    // Public wallet identity line: the master fingerprint is the standard cross-check
    // handle, and whether a passphrase was applied is exactly what the user must
    // verify. On testnet the line says so - a tb1/tpub screen must never pass for a
    // mainnet wallet at a glance.
    let info = format!(
        "fingerprint {} - passphrase {}{}",
        s.report.root_fingerprint,
        if s.report.has_passphrase { "ON" } else { "off" },
        if s.report.network == Network::Bitcoin { "" } else { " - TESTNET" }
    );
    text(t, &info, body.x, l.info_y, MONO_SMALL, INK_SECONDARY, PAPER_1)?;

    {
        let mut clip = t.clipped(&l.viewport.to_eg());
        schemes_content(&mut clip, m, s, l.viewport.y - s.scroll, None)?;
    }

    if let Some(qr) = &s.qr {
        draw_qr_modal(t, m, qr)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// QR modal
// ---------------------------------------------------------------------------------------

/// Light margin around the symbol, in modules. ISO/IEC 18004's four: the core's
/// `matrix()` deliberately ships no quiet zone (it belongs to the drawing - see that
/// module's docs), so the modal is the place that draws it.
const QR_QUIET: i32 = 4;

struct QrModalLayout {
    panel: Rect,
    label_y: i32,
    /// Free area between label and Close that the symbol is centered in. Read by the
    /// largest-fit layout test; the draw path only needs the finished `sym`.
    #[cfg_attr(not(test), allow(dead_code))]
    area: Rect,
    /// The full drawn symbol including the quiet zone, centered in `area`.
    sym: Rect,
    /// Pixels per module. Integer, so modules stay crisp squares a scanner can read;
    /// always the largest that fits, floored at 1.
    scale: i32,
    close: Rect,
}

fn qr_modal_layout(m: &Metrics, size: i32) -> QrModalLayout {
    let panel = m.screen().inset(m.pad);
    let pad = m.pad;
    let btn_h = m.btn.min(72);
    let label_y = panel.y + pad;
    let close_w = (panel.w / 3).clamp(180, 280);
    let close =
        Rect::new(panel.x + (panel.w - close_w) / 2, panel.bottom() - pad - btn_h, close_w, btn_h);
    let area_y = label_y + LINE + m.gap;
    let area = Rect::new(panel.x + pad, area_y, panel.w - 2 * pad, close.y - m.gap - area_y);
    let total = size + 2 * QR_QUIET;
    let scale = (area.w.min(area.h) / total.max(1)).max(1);
    let side = total * scale;
    let sym = Rect::new(area.x + (area.w - side) / 2, area.y + (area.h - side) / 2, side, side);
    QrModalLayout { panel, label_y, area, sym, scale, close }
}

fn draw_qr_modal<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    m: &Metrics,
    qr: &QrModal,
) -> Result<(), D::Error> {
    let size = qr.data.size() as i32;
    let l = qr_modal_layout(m, size);
    // Paper-3 like every modal; a 2px neutral frame (this modal shows a public value -
    // the danger frame stays reserved for the reveal gate). The white panel doubles as
    // the symbol's quiet zone surface.
    fill(t, l.panel, PAPER_3)?;
    frame(t, l.panel, BORDER_STRONG)?;
    frame(t, l.panel.inset(1), BORDER_STRONG)?;
    let title = Rect::new(l.panel.x + m.pad, l.label_y, l.panel.w - 2 * m.pad, LINE);
    text_centered(t, &qr.label, title, HEADING, INK_PRIMARY, PAPER_3)?;

    // The symbol: dark modules as horizontal runs (one fill per run, not per module).
    // Ink on white, drawn at integer scale so every module is an exact square.
    let origin_x = l.sym.x + QR_QUIET * l.scale;
    let origin_y = l.sym.y + QR_QUIET * l.scale;
    for y in 0..size {
        let mut x = 0;
        while x < size {
            if qr.data.module(x as u16, y as u16) {
                let run_start = x;
                while x < size && qr.data.module(x as u16, y as u16) {
                    x += 1;
                }
                fill(
                    t,
                    Rect::new(
                        origin_x + run_start * l.scale,
                        origin_y + y * l.scale,
                        (x - run_start) * l.scale,
                        l.scale,
                    ),
                    INK_PRIMARY,
                )?;
            } else {
                x += 1;
            }
        }
    }

    button(t, l.close, "Close", ButtonKind::Primary, PAPER_3)?;
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Verify device
// ---------------------------------------------------------------------------------------

/// One caption-over-value row; returns the next y.
fn kv<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    m: &Metrics,
    y: i32,
    caption: &str,
    value: &str,
    color: Rgb565,
) -> Result<i32, D::Error> {
    let body = m.body();
    text(t, caption, body.x, y, MONO_SMALL, INK_MUTED, PAPER_1)?;
    let y = y + SMALL_LINE;
    let end = mono_wrapped(
        t,
        value,
        Rect::new(body.x, y, body.w, i32::MAX / 2),
        MONO_SMALL,
        color,
        PAPER_1,
    )?;
    Ok(end + m.gap)
}

fn verify_content<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    m: &Metrics,
    v: &VerifyInfo,
    y0: i32,
) -> Result<i32, D::Error> {
    let ok_color = |ok: bool| if ok { SUCCESS } else { DANGER };
    let mut y = y0;
    y = kv(t, m, y, "Firmware version", &v.firmware_version, INK_PRIMARY)?;
    y = kv(t, m, y, "Board", &v.board, INK_PRIMARY)?;
    y = kv(t, m, y, "Platform", &v.platform, INK_PRIMARY)?;
    y = kv(t, m, y, "App SHA256 (running partition)", &v.app_sha256, INK_PRIMARY)?;
    y = kv(t, m, y, "Source id", &v.source_id, INK_PRIMARY)?;
    y = kv(t, m, y, "Boot self-test", &v.self_test, ok_color(v.self_test_ok))?;
    y = kv(t, m, y, "Radio", &v.radio, ok_color(v.radio_ok))?;
    y = kv(t, m, y, "Secure boot", &v.secure_boot, INK_PRIMARY)?;
    y = kv(t, m, y, "Flash encryption", &v.flash_encryption, INK_PRIMARY)?;
    Ok(y)
}

fn draw_verify<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    m: &Metrics,
    v: &VerifyInfo,
    scroll: i32,
) -> Result<(), D::Error> {
    draw_bar(t, m, "Verify device")?;
    let body = m.body();
    let mut clip = t.clipped(&body.to_eg());
    verify_content(&mut clip, m, v, body.y - scroll)?;
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Layout unit tests (geometry the integration suite cannot reach from outside)
// ---------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dice_mode;
    use crate::layout::DICE_KEY_MIN;

    /// The two shipped panels (docs/BOARDS.md): Waveshare 4B and Elecrow 5inch.
    const GEOMETRIES: [(u32, u32); 2] = [(720, 720), (800, 480)];

    /// The QR modal at every real symbol size the 0.1.0 targets produce (v3 addresses
    /// through v7 zpubs) plus the format extremes: integer scale, largest fit, symbol
    /// centered between label and Close, everything inside the panel.
    #[test]
    fn qr_modal_scales_integer_and_fits() {
        for (w, h) in GEOMETRIES {
            let m = Metrics::new(w, h);
            for size in [21, 29, 33, 45, 57, 177] {
                let l = qr_modal_layout(&m, size);
                let total = size + 2 * QR_QUIET;
                assert!(l.scale >= 1, "{w}x{h} size {size}: scale floor");
                assert_eq!(l.sym.w, total * l.scale, "{w}x{h} size {size}: integer scale");
                assert_eq!(l.sym.w, l.sym.h, "{w}x{h} size {size}: square");
                // Largest fit: one more scale step would overflow the free area
                // (unless the floor of 1 is already too big, as for v40 on tiny areas).
                if total * (l.scale + 1) <= l.area.w.min(l.area.h) {
                    panic!("{w}x{h} size {size}: scale {} is not the largest fit", l.scale);
                }
                // Centered in the free area (integer division may leave 1px bias).
                assert!(((l.sym.x - l.area.x) - (l.area.right() - l.sym.right())).abs() <= 1);
                assert!(((l.sym.y - l.area.y) - (l.area.bottom() - l.sym.bottom())).abs() <= 1);
                // Fully inside the panel, clear of label and Close.
                assert!(l.sym.x >= l.panel.x && l.sym.right() <= l.panel.right());
                assert!(l.sym.y >= l.label_y + LINE, "{w}x{h} size {size}: overlaps label");
                assert!(l.sym.bottom() <= l.close.y, "{w}x{h} size {size}: overlaps Close");
                assert!(l.close.bottom() <= l.panel.bottom());
            }
        }
    }

    /// Review item (m3): the fixed hint reservation clipped the wrapped cross-check
    /// hint. The layout now reserves what `wrap_words` measures; this pins that no
    /// mode/geometry combination clips the hint, starves the keypad below its 80px
    /// physical floor, undersizes a mode segment, or pushes the status block out of
    /// the body - for the FULL desktop mode set (RAW, 12, 15, 18, 21, 24).
    #[test]
    fn dice_layout_fits_every_mode_on_both_geometries() {
        for (w, h) in GEOMETRIES {
            let m = Metrics::new(w, h);
            let body = m.body();
            for i in 0..DICE_MODE_LABELS.len() as u8 {
                let mode = dice_mode(i);
                let l = dice_layout(&m, mode);
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
