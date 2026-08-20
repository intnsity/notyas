// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The painter: Butter Paper widgets over any `Rgb565` `DrawTarget`.
//!
//! Everything here is stateless drawing - fills, hairline frames, text runs, buttons,
//! fields, the strength meter - so the screens stay pure functions from state and
//! [`Metrics`](crate::layout::Metrics) to pixels. Corners are square: the device style is
//! terminal-plain (ARCHITECTURE.md), and hairline rectangles are exactly reviewable.

use alloc::string::String;
use embedded_graphics::draw_target::{DrawTarget, DrawTargetExt};
use embedded_graphics::geometry::Point;
use embedded_graphics::pixelcolor::Rgb565;
use notyas_fonts::{draw_text, Atlas, TextStyle};

use crate::layout::Rect;
use crate::theme::*;

// Font roles. The committed atlases are the whole palette; roles are named here once so
// a future atlas regeneration is a one-file change.
/// Screen titles.
pub static TITLE: &Atlas = &notyas_fonts::SANS_SEMIBOLD_44;
/// Section headings and button labels.
pub static HEADING: &Atlas = &notyas_fonts::SANS_SEMIBOLD_32;
/// Body copy and hints (hints differ by ink, not size - the panel is 229 PPI).
pub static BODY: &Atlas = &notyas_fonts::SANS_REGULAR_32;
/// The second line of a control that cannot grow, and the control's own title beside it.
///
/// NOT a smaller body size, and NOT a licence to fit more words onto a screen: when copy
/// does not fit, the copy is too long and shortening it is the fix. This face exists for
/// the one shape the page cannot solve by giving something more room - a TARGET whose
/// height is set by the finger and the panel rather than by its copy. A wallet action card
/// on the 800x480 panel is 88 px tall because four of them have to fit under the identity
/// card and stay tappable, which leaves 62 px inside it, and a 32 px title over a 32 px
/// hint needs 84. Both of a card's lines come down to this size together and separate by
/// INK, which is the rule the rest of the scale already uses for hints.
///
/// Never for anything a user compares against another device. Fingerprints, addresses,
/// xpubs, derivation paths and the device words stay [`MONO`]/[`MONO_SMALL`] at their own
/// size, where a misread character costs money.
pub static CAPTION: &Atlas = &notyas_fonts::SANS_REGULAR_24;
/// Mnemonic words, roll counts, keypad digits.
pub static MONO: &Atlas = &notyas_fonts::MONO_REGULAR_32;
/// Addresses, xpubs, hex - dense machine-checkable strings.
pub static MONO_SMALL: &Atlas = &notyas_fonts::MONO_REGULAR_28;

/// Visual kind of a button. The mapping to fills and inks is the Butter Paper component
/// spec: primary = solid cobalt, secondary = white with a strong border, ghost =
/// transparent with cobalt text, danger = solid crimson, disabled = recessed paper with
/// muted ink (and the reason shown beside it, never a silent dead button).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ButtonKind {
    Primary,
    Secondary,
    Ghost,
    Danger,
    Disabled,
}

pub fn fill<D: DrawTarget<Color = Rgb565>>(t: &mut D, r: Rect, c: Rgb565) -> Result<(), D::Error> {
    t.fill_solid(&r.to_eg(), c)
}

/// One-pixel hairline frame drawn as four fills (no line primitives, no anti-aliasing).
pub fn frame<D: DrawTarget<Color = Rgb565>>(t: &mut D, r: Rect, c: Rgb565) -> Result<(), D::Error> {
    fill(t, Rect::new(r.x, r.y, r.w, 1), c)?;
    fill(t, Rect::new(r.x, r.bottom() - 1, r.w, 1), c)?;
    fill(t, Rect::new(r.x, r.y, 1, r.h), c)?;
    fill(t, Rect::new(r.right() - 1, r.y, 1, r.h), c)
}

/// A filled panel with a hairline border: the Butter Paper card/well primitive.
pub fn panel<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    r: Rect,
    bg: Rgb565,
    border: Rgb565,
) -> Result<(), D::Error> {
    fill(t, r, bg)?;
    frame(t, r, border)
}

/// Left-aligned text run; `bg` must be the color the text sits on (the atlases blend
/// toward it). Returns the pen x after the run for chained spans.
pub fn text<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    s: &str,
    x: i32,
    y: i32,
    font: &'static Atlas,
    fg: Rgb565,
    bg: Rgb565,
) -> Result<i32, D::Error> {
    let style = TextStyle { font, fg, bg };
    let pen = draw_text(t, s, Point::new(x, y), &style)?;
    Ok(pen.x)
}

/// Text horizontally centered in `r`, vertically centered on the font's line box.
pub fn text_centered<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    s: &str,
    r: Rect,
    font: &'static Atlas,
    fg: Rgb565,
    bg: Rgb565,
) -> Result<(), D::Error> {
    let tw = font.text_width(s) as i32;
    let x = r.x + (r.w - tw) / 2;
    let y = r.y + (r.h - font.line_height as i32) / 2;
    text(t, s, x, y, font, fg, bg)?;
    Ok(())
}

/// Fill/ink/border resolution for a [`ButtonKind`] on a given surface color.
fn button_colors(kind: ButtonKind, surface: Rgb565) -> (Rgb565, Rgb565, Option<Rgb565>) {
    match kind {
        ButtonKind::Primary => (ACCENT, PAPER_3, None),
        ButtonKind::Secondary => (PAPER_3, INK_PRIMARY, Some(BORDER_STRONG)),
        ButtonKind::Ghost => (surface, ACCENT, None),
        ButtonKind::Danger => (DANGER, PAPER_3, None),
        ButtonKind::Disabled => (PAPER_0, INK_MUTED, Some(BORDER)),
    }
}

/// A labeled button. `surface` is the paper the button sits on (ghost buttons show it
/// through; every kind blends its label against its own fill).
pub fn button<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    r: Rect,
    label: &str,
    kind: ButtonKind,
    surface: Rgb565,
) -> Result<(), D::Error> {
    let (bg, fg, border) = button_colors(kind, surface);
    fill(t, r, bg)?;
    if let Some(b) = border {
        frame(t, r, b)?;
    }
    text_centered(t, label, r, HEADING, fg, bg)
}

/// A two-segment toggle (e.g. RAW / FIXED). The active segment is cobalt-on-tint with a
/// cobalt frame - "cobalt = interactive" made visible; the inactive one is a quiet well.
pub fn toggle<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    r: Rect,
    labels: [&str; 2],
    active: usize,
) -> Result<(), D::Error> {
    let half = r.w / 2;
    for (i, label) in labels.iter().enumerate() {
        let seg = Rect::new(r.x + i as i32 * half, r.y, half, r.h);
        if i == active {
            fill(t, seg, ACCENT_TINT)?;
            frame(t, seg, ACCENT)?;
            text_centered(t, label, seg, HEADING, ACCENT, ACCENT_TINT)?;
        } else {
            fill(t, seg, PAPER_0)?;
            frame(t, seg, BORDER)?;
            text_centered(t, label, seg, HEADING, INK_SECONDARY, PAPER_0)?;
        }
    }
    Ok(())
}

/// The entropy strength meter: a paper-0 trough with a semantic fill, full at 256 bits.
/// Same semantics as the desktop meter (three bands over effective bits).
pub fn strength_meter<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    r: Rect,
    bits: usize,
) -> Result<(), D::Error> {
    let strength = Strength::of(bits);
    panel(t, r, PAPER_0, BORDER)?;
    let inner = r.inset(2);
    let full = 256usize;
    let frac = bits.min(full) as i32;
    let w = inner.w * frac / full as i32;
    if w > 0 {
        fill(t, Rect::new(inner.x, inner.y, w, inner.h), strength.color())?;
    }
    Ok(())
}

/// The C4c hold-to-confirm control: a trough that fills while the finger stays down.
///
/// Not a button and drawn as one deliberately isn't: a tap must not fire it, so it shows
/// its own progress instead of a pressed state. `permille` comes from
/// [`crate::hold_fill_permille`] over the press age the touch layer tracks, and `ink` is
/// the consequence's colour - `ACCENT` to sign, `DANGER` to erase.
///
/// The caller supplies both lines because they name the specific action and its specific
/// undoing ("Hold to sign" / "Released - nothing was signed"), and a component that
/// guessed either would put the wrong verb on one of the two screens that use it.
pub fn hold_bar<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    r: Rect,
    label: &str,
    status: &str,
    permille: u32,
    ink: Rgb565,
) -> Result<(), D::Error> {
    panel(t, r, PAPER_0, BORDER_STRONG)?;
    let inner = r.inset(8);
    let line = HEADING.line_height as i32;
    text_centered(t, label, Rect::new(inner.x, inner.y, inner.w, line), HEADING, INK_PRIMARY, PAPER_0)?;

    // The trough is the middle third of the control, so the fill is the element the eye
    // tracks rather than a hairline under a label.
    let trough = Rect::new(inner.x, inner.y + line + 4, inner.w, (inner.h - 2 * line - 8).max(8));
    panel(t, trough, PAPER_3, BORDER_STRONG)?;
    let bore = trough.inset(2);
    // Integer math to the pixel: permille is capped at 1000 by its producer, and the
    // clamp here is what makes that a local fact rather than a caller's promise.
    let w = bore.w.saturating_mul(permille.min(1000) as i32) / 1000;
    if w > 0 {
        fill(t, Rect::new(bore.x, bore.y, w, bore.h), ink)?;
    }
    text_centered(
        t,
        status,
        Rect::new(inner.x, trough.bottom() + 4, inner.w, line),
        BODY,
        INK_SECONDARY,
        PAPER_0,
    )?;
    Ok(())
}

/// An INPUT field: white (paper-3, "white = editable"), strong border, mono content.
///
/// Masking here is the input rule, not the derived-secret rule (see the crate-level
/// secrecy note): ONE bullet per typed character. The user already knows how much they
/// typed, the byte counter beside the field states the length outright, and a fixed run
/// would read as a rendering bug on a field the user is actively editing. The fixed run
/// belongs to DERIVED secrets - `theme::mask_word` - whose length is itself information.
///
/// Unmasked (the Show toggle), each SPACE is drawn as a muted bullet instead of blank
/// paper. Leading and trailing spaces are exactly the characters a literal rendering
/// hides and PBKDF2 still consumes, so "revealed" has to mean revealed; the on-screen
/// keyboard is ASCII-only (test-asserted), so a bullet in a revealed field can only ever
/// mean a space.
pub fn field<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    r: Rect,
    value: &str,
    masked: bool,
    focused: bool,
) -> Result<(), D::Error> {
    panel(t, r, PAPER_3, if focused { ACCENT } else { BORDER_STRONG })?;
    if focused {
        // A 2 px frame stands in for the desktop's soft focus ring.
        frame(t, r.inset(1), ACCENT)?;
    }
    let inner = r.inset(if focused { 2 } else { 1 });
    let pad = MONO.glyph(' ').advance as i32;
    let y = inner.y + (inner.h - MONO.line_height as i32) / 2;
    if value.is_empty() {
        return Ok(());
    }
    // Clip from the left so the tail being typed stays visible. One bullet per character
    // means the masked run is exactly as long as the value, so both renderings scroll
    // identically and the field never changes shape when Show is toggled.
    let cap = ((inner.w - 2 * pad) / MONO.glyph('m').advance as i32).max(0) as usize;
    let n = value.chars().count();
    // Pixel-clip to the field: on the narrow side-by-side fields of the 800x480 landscape
    // pair the tail can still overrun by a fraction of a glyph, and it must crop rather
    // than bleed into the neighboring field.
    let mut clip = t.clipped(&inner.to_eg());
    let mut pen = inner.x + pad;
    let mut buf = [0u8; 4];
    for c in value.chars().skip(n.saturating_sub(cap)) {
        let (glyph, ink) = match (masked, c) {
            (true, _) => (BULLET, INK_PRIMARY),
            (false, ' ') => (BULLET, INK_MUTED),
            (false, c) => (c, INK_PRIMARY),
        };
        pen = text(&mut clip, glyph.encode_utf8(&mut buf), pen, y, MONO, ink, PAPER_3)?;
    }
    Ok(())
}

/// Mono text wrapped by character count into `r`'s width, top-aligned; returns the y
/// after the last line. For xpubs, addresses and hex - strings with no word structure.
pub fn mono_wrapped<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    s: &str,
    r: Rect,
    font: &'static Atlas,
    fg: Rgb565,
    bg: Rgb565,
) -> Result<i32, D::Error> {
    let adv = font.glyph('m').advance as i32;
    let per_line = (r.w / adv).max(1) as usize;
    let mut y = r.y;
    let chars: alloc::vec::Vec<char> = s.chars().collect();
    for line in chars.chunks(per_line) {
        let line: String = line.iter().collect();
        text(t, &line, r.x, y, font, fg, bg)?;
        y += font.line_height as i32;
    }
    Ok(y)
}

/// Height `mono_wrapped` will use for `s` in a region `w` wide (layout math shared with
/// the scroll-limit computation).
pub fn mono_wrapped_height(s: &str, w: i32, font: &Atlas) -> i32 {
    let adv = font.glyph('m').advance as i32;
    let per_line = (w / adv).max(1) as usize;
    let lines = s.chars().count().div_ceil(per_line).max(1) as i32;
    lines * font.line_height as i32
}

/// Greedy word wrap by measured width. For prose (hints, modal copy); mono strings with
/// no word structure use [`mono_wrapped`] instead.
pub fn wrap_words(s: &str, w: i32, font: &Atlas) -> alloc::vec::Vec<String> {
    let mut lines = alloc::vec::Vec::new();
    let mut line = String::new();
    for word in s.split_whitespace() {
        let candidate: String = if line.is_empty() {
            String::from(word)
        } else {
            let mut c = line.clone();
            c.push(' ');
            c.push_str(word);
            c
        };
        if font.text_width(&candidate) as i32 <= w || line.is_empty() {
            line = candidate;
        } else {
            lines.push(line);
            line = String::from(word);
        }
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

/// An N-segment tab bar (scheme tabs). Same visual grammar as [`toggle`]: the active
/// segment is cobalt on accent tint, the rest are quiet wells.
pub fn tabs<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    r: Rect,
    labels: &[&str],
    active: usize,
) -> Result<(), D::Error> {
    let n = labels.len().max(1) as i32;
    let seg_w = r.w / n;
    for (i, label) in labels.iter().enumerate() {
        let i32i = i as i32;
        // The last segment absorbs the rounding remainder so the bar spans `r` exactly.
        let w = if i32i == n - 1 { r.w - seg_w * (n - 1) } else { seg_w };
        let seg = Rect::new(r.x + i32i * seg_w, r.y, w, r.h);
        if i == active {
            fill(t, seg, ACCENT_TINT)?;
            frame(t, seg, ACCENT)?;
            text_centered(t, label, seg, HEADING, ACCENT, ACCENT_TINT)?;
        } else {
            fill(t, seg, PAPER_0)?;
            frame(t, seg, BORDER)?;
            text_centered(t, label, seg, HEADING, INK_SECONDARY, PAPER_0)?;
        }
    }
    Ok(())
}
