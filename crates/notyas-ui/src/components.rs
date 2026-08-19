// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The composite widgets shared by more than one screen (UX-SCREENS.md's component
//! library), one layer above [`crate::canvas`].
//!
//! `canvas` is the drawing vocabulary: a rectangle, a run of text, a button. This module
//! is the assembled furniture: the top bar, a confirmation modal, the on-screen keyboard,
//! a caption-over-value row, the C12 write notice. A widget earns its place here the
//! moment a SECOND screen needs it; anything one screen alone draws stays in that
//! screen's module, where its geometry can stay private.
//!
//! Every widget here follows the crate's layout discipline: geometry is computed by one
//! function, and both the hit-testing and the painting side consume that same function,
//! so a control can never be drawn where it cannot be tapped.

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use embedded_graphics::draw_target::{DrawTarget, DrawTargetExt};
use embedded_graphics::pixelcolor::Rgb565;

use crate::canvas::{
    self, button, fill, frame, panel, text, text_centered, wrap_words, ButtonKind, BODY, HEADING,
    MONO, MONO_SMALL,
};
use crate::layout::{Metrics, Rect, TOUCH_MIN};
use crate::theme::*;
use crate::{Page, Region, RegionId};

/// The vertical grid every screen measures text in: one BODY / HEADING / MONO line, and
/// one MONO_SMALL line. Screens reserve space in multiples of these rather than in raw
/// pixels, so a font change moves every layout together.
pub(crate) const LINE: i32 = 42;
pub(crate) const SMALL_LINE: i32 = 36;

// ---------------------------------------------------------------------------------------
// Top bar
// ---------------------------------------------------------------------------------------

/// The Back affordance's rectangle. Named by the screens rather than by the bar itself,
/// because Back is the SCREEN's region: each screen decides what going back means, and
/// a screen that offers no way out (the interstitial) does not emit this rectangle at
/// all.
///
/// The height is the bar inset by the standard gap, EXCEPT that it never goes under
/// [`TOUCH_MIN`]: on the short panels the bar is 64-66 px and the inset form measured 50-51,
/// which put the one control every screen in the crate offers below the floor commandment 7
/// sets for a target that is not self-correcting. The floor always fits, because `Metrics`
/// clamps the bar at 64 and 64 > 60; the breathing room above and below is what gives way,
/// and it gives way symmetrically so the label stays centred in the bar.
pub(crate) fn back_rect(m: &Metrics) -> Rect {
    let h = (m.bar - m.gap).max(TOUCH_MIN);
    Rect::new(m.gap, (m.bar - h) / 2, m.bar * 2, h)
}

pub(crate) fn draw_bar<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    m: &Metrics,
    title: &str,
) -> Result<(), D::Error> {
    bar(t, m, title, true)
}

/// Top bar without the Back affordance, for a screen that has no tappable regions at
/// all: a drawn button that nothing hit-tests would be a lie about what the panel does.
pub(crate) fn draw_bar_no_back<D: DrawTarget<Color = Rgb565>>(
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
// Confirmation modal
// ---------------------------------------------------------------------------------------

/// A two-button confirmation modal, defined entirely by its copy. Static text only: a
/// modal that formatted a secret into its body would put that secret on a screen the
/// user did not ask to reveal.
pub(crate) struct ModalSpec {
    pub title: &'static str,
    pub body: &'static [&'static str],
    pub cancel: &'static str,
    pub confirm: &'static str,
}

/// Geometry of `spec`: (panel, cancel, confirm). Sized to the wrapped copy, so longer
/// wording grows the panel instead of overflowing it.
pub(crate) fn modal_layout(m: &Metrics, spec: &ModalSpec) -> (Rect, Rect, Rect) {
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

/// The modal's two regions. A modal is MODAL: while one is open its owner returns these
/// and nothing else, so the sheet below is as inert to a finger as it looks.
pub(crate) fn modal_regions(m: &Metrics, spec: &ModalSpec) -> Vec<Region> {
    let (_, cancel, confirm) = modal_layout(m, spec);
    vec![
        Region { id: RegionId::ModalCancel, rect: cancel },
        Region { id: RegionId::ModalConfirm, rect: confirm },
    ]
}

pub(crate) fn draw_modal<D: DrawTarget<Color = Rgb565>>(
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
// On-screen keyboard (C9; shared by phrase entry and passphrase)
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
pub(crate) fn keyboard(area: Rect, page: Page) -> Vec<Key> {
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

pub(crate) fn draw_keyboard<D: DrawTarget<Color = Rgb565>>(
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
            // The control row divides whatever area it is given, so in a narrow one - the
            // danger sheet's landscape keyboard rail - a label is wider than its key.
            // Pixel-clipped to that key for the same reason the masked field is: a label
            // that bled into its neighbour would make the whole row unreadable rather
            // than merely tight.
            RegionId::KeyDone => {
                let kind = if done_enabled { ButtonKind::Primary } else { ButtonKind::Disabled };
                let mut clip = t.clipped(&k.rect.to_eg());
                button(&mut clip, k.rect, "Done", kind, PAPER_1)?;
            }
            _ => {
                let mut clip = t.clipped(&k.rect.to_eg());
                button(&mut clip, k.rect, &k.label, ButtonKind::Secondary, PAPER_1)?;
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Rows and notices
// ---------------------------------------------------------------------------------------

/// Height the C12 band needs for this copy at width `w`, so a caller can size the band to
/// the words rather than assume two lines fit.
pub(crate) fn write_notice_h(w: i32, what: &str, confidentiality: &str) -> i32 {
    let inner = w - 2 * NOTICE_PAD;
    let lines = wrap_words(what, inner, MONO_SMALL).len()
        + wrap_words(confidentiality, inner, MONO_SMALL).len();
    lines as i32 * SMALL_LINE + 2 * NOTICE_PAD
}

const NOTICE_PAD: i32 = 6;

/// C12 WriteNotice: an inline band that states the artifact and its confidentiality, in
/// that order, placed directly above the action that performs the write.
///
/// Both lines WRAP. The copy names a specific artifact and a specific confidentiality
/// claim, so it is as long as it needs to be; a band that let it run off the panel would
/// hide the half of the sentence that says what is written, which is the half the notice
/// exists for. Callers that size their band with [`write_notice_h`] get exactly the rows
/// the copy needs.
pub(crate) fn write_notice<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    r: Rect,
    what: &str,
    confidentiality: &str,
) -> Result<(), D::Error> {
    panel(t, r, PAPER_0, BORDER_STRONG)?;
    let inner = r.inset(NOTICE_PAD);
    let mut y = inner.y;
    for (copy, ink) in [(what, INK_PRIMARY), (confidentiality, INK_SECONDARY)] {
        for line in wrap_words(copy, inner.w, MONO_SMALL) {
            text(t, &line, inner.x, y, MONO_SMALL, ink, PAPER_0)?;
            y += SMALL_LINE;
        }
    }
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::PANELS;

    /// Back is the most-used control in the product and the only way off most screens, and
    /// it is not self-correcting: a missed tap does nothing, and the user is still stuck.
    /// It keeps the 60 px floor on every panel the firmware ships, and it stays inside the
    /// bar it is drawn in - a region hanging below the bar would swallow the first row of
    /// whatever the screen laid out under it.
    #[test]
    fn back_is_tappable_on_every_shipped_panel() {
        for (w, h) in PANELS {
            let m = Metrics::new(w, h);
            let r = back_rect(&m);
            assert!(
                r.h >= TOUCH_MIN && r.w >= TOUCH_MIN,
                "{w}x{h}: Back is {}x{}, under the {TOUCH_MIN} px floor",
                r.w,
                r.h
            );
            assert!(
                r.y >= 0 && r.bottom() <= m.bar,
                "{w}x{h}: Back at {r:?} leaves the {} px bar",
                m.bar
            );
        }
    }
}
