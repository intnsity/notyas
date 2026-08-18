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
    DiceState, MnemonicState, NullTarget, Page, PassFocus, PassState, PhraseState, Region,
    RegionId, SchemesState, State, VerifyInfo, VERSION,
};
use notyas_core::bip39::{self, rolls_for_bits, Checksum, MnemonicMode, MIN_SECURE_BITS};
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
        }
        State::Dice(_) => {
            let l = dice_layout(m);
            out.push(Region { id: RegionId::Back, rect: back_rect(m) });
            for (i, k) in l.keys.iter().enumerate() {
                out.push(Region { id: RegionId::Digit(i as u8 + 1), rect: *k });
            }
            out.push(Region { id: RegionId::ModeToggle, rect: l.toggle });
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
            for k in keyboard(l.kb, s.page) {
                out.push(Region { id: k.id, rect: k.rect });
            }
        }
        State::Passphrase(s) => {
            let l = pass_layout(m);
            out.push(Region { id: RegionId::Back, rect: back_rect(m) });
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
        State::Schemes(_) => {
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
        }
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
) -> Result<(), D::Error> {
    fill(t, m.screen(), PAPER_1)?;
    match state {
        State::Home => draw_home(t, m),
        State::Dice(s) => draw_dice(t, m, s),
        State::Mnemonic(s) => draw_mnemonic(t, m, s),
        State::Phrase(s) => draw_phrase(t, m, s),
        State::Passphrase(s) => draw_passphrase(t, m, s),
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
            let end = schemes_content(&mut NullTarget, m, s, l.viewport.y).unwrap_or_default();
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
    let bar = Rect::new(0, 0, m.w, m.bar);
    fill(t, bar, PAPER_2)?;
    fill(t, Rect::new(0, m.bar - 1, m.w, 1), BORDER)?;
    let back = back_rect(m);
    button(t, back, "< Back", ButtonKind::Ghost, PAPER_2)?;
    let x = back.right() + m.gap;
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

fn draw_home<D: DrawTarget<Color = Rgb565>>(t: &mut D, m: &Metrics) -> Result<(), D::Error> {
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
    let [b0, b1, b2] = home_buttons(m);
    button(t, b0, "New seed (dice)", ButtonKind::Primary, PAPER_1)?;
    button(t, b1, "Verify existing seed", ButtonKind::Secondary, PAPER_1)?;
    button(t, b2, "Verify device", ButtonKind::Secondary, PAPER_1)?;
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Dice entry
// ---------------------------------------------------------------------------------------

struct DiceLayout {
    /// Info column: roll count line, mode toggle, cross-check hint, meter, status line.
    count_y: i32,
    toggle: Rect,
    hint_y: i32,
    hint_lines: i32,
    meter: Rect,
    status_y: i32,
    info_x: i32,
    info_w: i32,
    /// 1..6, reading order.
    keys: [Rect; 6],
    backspace: Rect,
    done: Rect,
}

fn dice_layout(m: &Metrics) -> DiceLayout {
    let body = m.body();
    let g = m.gap;
    // Landscape panels split into an info column and a keypad column so the keypad keeps
    // full-size touch targets; portrait stacks them.
    let (info, pad) = if m.landscape() {
        let info_w = (body.w - g) * 9 / 20;
        (
            Rect::new(body.x, body.y, info_w, body.h),
            Rect::new(body.x + info_w + g, body.y, body.w - info_w - g, body.h),
        )
    } else {
        let hint_lines = 1;
        // Two status lines: the bits/strength readout plus the reason/ready line.
        let info_h = LINE + 48 + hint_lines * LINE + 20 + 2 * LINE + 5 * g;
        (
            Rect::new(body.x, body.y, body.w, info_h),
            Rect::new(body.x, body.y + info_h + g, body.w, body.h - info_h - g),
        )
    };
    let hint_lines = if m.landscape() { 2 } else { 1 };

    let count_y = info.y;
    let toggle = Rect::new(info.x, count_y + LINE + g, info.w, 48);
    let hint_y = toggle.bottom() + g;
    let meter = Rect::new(info.x, hint_y + hint_lines * LINE + g, info.w, 20);
    let status_y = meter.bottom() + g;

    // Keypad: 3x2 digit grid above a Backspace | Done row, filling the pad column.
    let ctl_h = m.btn;
    let key_w = (pad.w - 2 * g) / 3;
    let key_h = (pad.h - ctl_h - 3 * g) / 2;
    let mut keys = [Rect::new(0, 0, 0, 0); 6];
    for (i, k) in keys.iter_mut().enumerate() {
        let col = (i % 3) as i32;
        let row = (i / 3) as i32;
        *k = Rect::new(pad.x + col * (key_w + g), pad.y + row * (key_h + g), key_w, key_h);
    }
    let ctl_y = pad.y + 2 * (key_h + g) + g;
    let bs_w = (pad.w - g) * 2 / 5;
    DiceLayout {
        count_y,
        toggle,
        hint_y,
        hint_lines,
        meter,
        status_y,
        info_x: info.x,
        info_w: info.w,
        keys,
        backspace: Rect::new(pad.x, ctl_y, bs_w, ctl_h),
        done: Rect::new(pad.x + bs_w + g, ctl_y, pad.w - bs_w - g, ctl_h),
    }
}

fn draw_dice<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    m: &Metrics,
    s: &DiceState,
) -> Result<(), D::Error> {
    draw_bar(t, m, "New seed")?;
    let l = dice_layout(m);

    // Roll count. The count is shown, the rolls themselves are not echoed: the digit
    // string alone regenerates the wallet, and it never has a reason to be on screen.
    let count = format!("Rolls: {}", s.entropy.events());
    text(t, &count, l.info_x, l.count_y, MONO, INK_PRIMARY, PAPER_1)?;

    // Mode toggle with the external tool each mode cross-checks against (the modes are
    // deliberately not interchangeable - see ARCHITECTURE.md's dice math note).
    let raw = matches!(s.mode, MnemonicMode::Raw);
    toggle(t, l.toggle, ["RAW", "FIXED 24"], if raw { 0 } else { 1 })?;
    let hint = if raw {
        "Raw dice bits. Cross-checks: iancoleman"
    } else {
        "SHA256 of rolls. Cross-checks: Coldcard, SeedSigner"
    };
    let mut hy = l.hint_y;
    for line in wrap_words(hint, l.info_w, BODY).iter().take(l.hint_lines as usize) {
        text(t, line, l.info_x, hy, BODY, INK_SECONDARY, PAPER_1)?;
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
    // The reason a disabled Done is disabled, always visible next to the meter.
    let status2_y = l.status_y + LINE;
    if !ready {
        let deficit = MIN_SECURE_BITS - bits.min(MIN_SECURE_BITS);
        let need = format!("Need {MIN_SECURE_BITS} bits - about {} more rolls", rolls_for_bits(deficit));
        for (i, line) in wrap_words(&need, l.info_w, BODY).iter().take(2).enumerate() {
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

/// Bottom-anchored keyboard in `area`: three character rows and a control row.
fn keyboard(area: Rect, page: Page) -> Vec<Key> {
    let rg = 8; // row gap
    let kg = 6; // key gap
    let row_h = ((area.h - 3 * rg) / 4).clamp(40, 72);
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

    // Control row: [page A][page B][space][backspace][done], weighted 3:3:7:3:4.
    let y = top + 3 * (row_h + rg);
    let unit = area.w - 4 * kg;
    let widths = [unit * 3 / 20, unit * 3 / 20, unit * 7 / 20, unit * 3 / 20, 0];
    let (a, b): ((RegionId, &str), (RegionId, &str)) = match page {
        Page::Lower | Page::Upper => ((RegionId::Shift, "Shift"), (RegionId::PageDigits, "?123")),
        Page::Digits => ((RegionId::PageLetters, "abc"), (RegionId::PageSymbols, "#+=")),
        Page::Symbols => ((RegionId::PageLetters, "abc"), (RegionId::PageDigits, "123")),
    };
    let ids = [a.0, b.0, RegionId::Space, RegionId::KeyBackspace, RegionId::KeyDone];
    let labels = [a.1, b.1, "", "Del", "Done"];
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
    well: Rect,
    advisory_y: i32,
    kb: Rect,
}

fn phrase_layout(m: &Metrics) -> PhraseLayout {
    let body = m.body();
    let g = m.gap;
    let well_h = 3 * SMALL_LINE + 16;
    let well = Rect::new(body.x, body.y, body.w, well_h);
    let advisory_y = well.bottom() + g;
    let kb_top = advisory_y + LINE + g;
    PhraseLayout {
        well,
        advisory_y,
        kb: Rect::new(body.x, kb_top, body.w, body.bottom() - kb_top),
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
    // These per-frame copies of the typed phrase are wiped before they are freed: the
    // phrase is shown unmasked by design, but its heap copies still obey the hygiene
    // rule (no stale secret bytes stranded in freed allocations).
    let mut chars: Vec<char> = s.text.chars().collect();
    let mut lines: Vec<String> = chars.chunks(per_line).map(|c| c.iter().collect()).collect();
    let visible = lines.len().min(3);
    for (i, line) in lines[lines.len() - visible..].iter().enumerate() {
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
    lines.zeroize();
    chars.zeroize();

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

struct PassLayout {
    toggle_label_y: i32,
    toggle: Rect,
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

    text(t, "Use passphrase", body.x, l.toggle_label_y, BODY, INK_PRIMARY, PAPER_1)?;
    toggle(t, l.toggle, ["Off", "On"], usize::from(s.enabled))?;

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

    // Entry and confirm fields. Both masked with the house FIXED bullet run - the char
    // counter below gives typing feedback, as the desktop's NFKD counter does.
    canvas::field(t, l.entry, &s.entry, true, s.focus == PassFocus::Entry)?;
    if s.entry.is_empty() {
        let y = l.entry.y + (l.entry.h - LINE) / 2;
        text(t, "passphrase", l.entry.x + 12, y, BODY, INK_MUTED, PAPER_3)?;
    } else {
        // The opt-in confirm field appears once there is something to confirm.
        canvas::field(t, l.confirm, &s.confirm, true, s.focus == PassFocus::Confirm)?;
        if s.confirm.is_empty() {
            let y = l.confirm.y + (l.confirm.h - LINE) / 2;
            text(t, "repeat passphrase", l.confirm.x + 12, y, BODY, INK_MUTED, PAPER_3)?;
        }
    }

    // `differ` is the exact predicate the Done handler blocks on; the drawn state must
    // never disagree with it. The status row carries ONE line (two would overlap on the
    // 720-wide panel): the mismatch warning once a confirm attempt exists, otherwise the
    // char counter - extended with the reason Done is still disabled while the confirm
    // field is untouched (a disabled control always says why).
    let chars = s.entry.chars().count();
    let differ = *s.entry != *s.confirm;
    if differ && !s.confirm.is_empty() {
        let msg = "The two passphrases are different.";
        text(t, msg, body.x, l.status_y, MONO_SMALL, DANGER, PAPER_1)?;
    } else if differ {
        let msg = format!("{chars} chars - repeat to continue");
        text(t, &msg, body.x, l.status_y, MONO_SMALL, INK_MUTED, PAPER_1)?;
    } else {
        text(t, &format!("{chars} chars"), body.x, l.status_y, MONO_SMALL, INK_MUTED, PAPER_1)?;
    }

    draw_keyboard(t, l.kb, s.page, !differ)?;
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

/// Draws (or measures, against [`NullTarget`]) the active tab's content starting at
/// `y0`; returns the y after the last line. Only PUBLIC values are drawn: account xpub,
/// SLIP-132 rendering, receive addresses. Private keys never reach the device screen in
/// 0.1.0 - there is no reveal for them, which is stronger than a mask.
fn schemes_content<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    m: &Metrics,
    s: &SchemesState,
    y0: i32,
) -> Result<i32, D::Error> {
    let body = m.body();
    let g = m.gap;
    let sr = &s.report.schemes[s.tab.min(s.report.schemes.len() - 1)];
    let acct = &sr.derived.account;
    let mut y = y0;

    text(t, &format!("Account {}", acct.path), body.x, y, HEADING, INK_PRIMARY, PAPER_1)?;
    y += LINE + g;

    text(t, "Account xpub", body.x, y, MONO_SMALL, INK_MUTED, PAPER_1)?;
    y += SMALL_LINE;
    y = mono_wrapped(
        t,
        &acct.xpub,
        Rect::new(body.x, y, body.w, i32::MAX / 2),
        MONO_SMALL,
        INK_PRIMARY,
        PAPER_1,
    )?;
    if let (Some(slip), Some((_, label))) = (&acct.slip132_pub, sr.scheme.slip132_labels()) {
        y += g;
        text(t, &format!("{label} (SLIP-132)"), body.x, y, MONO_SMALL, INK_MUTED, PAPER_1)?;
        y += SMALL_LINE;
        y = mono_wrapped(
            t,
            slip,
            Rect::new(body.x, y, body.w, i32::MAX / 2),
            MONO_SMALL,
            INK_PRIMARY,
            PAPER_1,
        )?;
    }

    y += g * 2;
    text(t, "Receive addresses", body.x, y, HEADING, INK_PRIMARY, PAPER_1)?;
    y += LINE + g;
    for row in &sr.derived.rows {
        text(t, &row.path, body.x, y, MONO_SMALL, INK_MUTED, PAPER_1)?;
        y += SMALL_LINE;
        y = mono_wrapped(
            t,
            &row.address,
            Rect::new(body.x, y, body.w, i32::MAX / 2),
            MONO_SMALL,
            INK_PRIMARY,
            PAPER_1,
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
    // handle, and whether a passphrase was applied is exactly what the user must verify.
    let info = format!(
        "fingerprint {} - passphrase {}",
        s.report.root_fingerprint,
        if s.report.has_passphrase { "ON" } else { "off" }
    );
    text(t, &info, body.x, l.info_y, MONO_SMALL, INK_SECONDARY, PAPER_1)?;

    let mut clip = t.clipped(&l.viewport.to_eg());
    schemes_content(&mut clip, m, s, l.viewport.y - s.scroll)?;
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
