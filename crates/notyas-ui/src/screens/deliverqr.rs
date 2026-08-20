// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! S-39: the signed transaction on the glass, for a camera.
//!
//! Opened from S-38's second exit and closed back onto it, so this is not a screen of its
//! own: the transaction it renders belongs to the delivery screen, and the two answers here
//! are answers S-38 records ([`Exit`]). What that buys is the property S-38 rests on - the
//! only copy of a signed transaction is on the std side, and the ONE extra rendering of it
//! that exists while this is open lives inside the delivery screen's state and dies with
//! it. Nothing survives the close.
//!
//! # The device does not know whether the scan worked
//!
//! A camera reads a symbol; the panel cannot see the camera. So this surface never claims
//! the transfer happened, and the way out is a claim the USER makes: `My wallet has it`
//! marks the delivery, `Close` does not, and S-38's `Done` stays gated on one of its two
//! deliveries having actually landed.
//!
//! # And a scan is not a broadcast
//!
//! The one sentence that has to be here. A phone that beeps has received a transaction, not
//! sent one, and a signer that let a beep read as money moving would be teaching the
//! opposite of what its whole review flow is for. The line is drawn beside the symbol at
//! every geometry, never below the fold, and it says what to do next.
//!
//! # Why the symbol gets the panel and everything else gets the remainder
//!
//! Scannability is a pixel budget: the drawn module is what a phone has to resolve, so the
//! layout gives the symbol the largest square the panel has left and fits the copy and the
//! two exits around it - beside it on a landscape panel, under it on a portrait one. The
//! floor that falls out of this, three pixels per module for the largest payload
//! `notyas_core::psbt_qr` will encode, is what sets that module's limit in the first place;
//! `the_symbol_is_scannable_on_every_shipped_panel` measures it here, against this layout,
//! on every panel the firmware ships.
//!
//! Nothing here is secret. A signed transaction is about to be broadcast, so the objection
//! to putting one on a screen is size and legibility - which is what this file is about -
//! and not confidentiality.

use alloc::string::String;
use alloc::vec::Vec;

use embedded_graphics::draw_target::{DrawTarget, DrawTargetExt};
use embedded_graphics::pixelcolor::Rgb565;

use crate::canvas::{button, fill, text, wrap_words, ButtonKind, BODY, CAPTION, MONO_SMALL};
use crate::components::{LINE, SMALL_LINE};
use crate::layout::{Metrics, Rect, TOUCH_MIN};
use crate::theme::*;
use crate::{QrData, Region, RegionId};

/// Light margin around the symbol, in modules. ISO/IEC 18004's four - the same value the
/// export modal draws, and for the same reason: `notyas_core::qr::matrix` ships the bare
/// symbol, so the quiet zone belongs to whoever draws it.
const QUIET: i32 = 4;

/// What the user did with the symbol.
///
/// Two answers and no third: this surface cannot fail, because everything it needed was
/// computed before it opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Exit {
    /// Neither control was pressed.
    Stay,
    /// The user says their wallet has the transaction. S-38 records the delivery.
    Delivered,
    /// Closed without a claim. Nothing is recorded and the card exit is untouched.
    Closed,
}

/// The three lines drawn beside the symbol, top to bottom.
///
/// A table rather than three draw calls, so the height the layout reserves is measured from
/// the same list the painter walks - a copy change cannot silently outgrow its block.
///
/// The middle line is the one this screen exists to say. It is `WARNING` ink and it is not
/// optional, at any geometry.
const COPY: [(&str, Line); 3] = [
    ("Signed transaction", Line::Title),
    (
        "Scanning does not broadcast. Broadcast from your wallet.",
        Line::Warning,
    ),
    // C11: a payload that fits one symbol renders as a static symbol with no controls, and
    // says so. Nothing animates, so nothing repeats and nothing can be missed.
    ("single frame", Line::Status),
];

/// Which of the three rows a copy line is: its font, its ink and its line height.
#[derive(Clone, Copy)]
enum Line {
    Title,
    Warning,
    Status,
}

impl Line {
    fn font(self) -> &'static notyas_fonts::Atlas {
        match self {
            Line::Title => BODY,
            Line::Warning => CAPTION,
            Line::Status => MONO_SMALL,
        }
    }

    fn ink(self) -> Rgb565 {
        match self {
            Line::Title => INK_PRIMARY,
            Line::Warning => WARNING,
            Line::Status => INK_MUTED,
        }
    }

    fn height(self) -> i32 {
        match self {
            Line::Title => LINE,
            _ => SMALL_LINE,
        }
    }
}

/// The wrapped copy at `w` pixels wide, as drawable rows.
fn rows(w: i32) -> Vec<(String, Line)> {
    COPY.iter()
        .flat_map(|&(copy, line)| {
            wrap_words(copy, w, line.font())
                .into_iter()
                .map(move |part| (part, line))
        })
        .collect()
}

/// Total height of the wrapped copy at `w` pixels wide.
fn copy_height(w: i32) -> i32 {
    rows(w).iter().map(|(_, line)| line.height()).sum()
}

/// The symbol, its scale, the copy block and the two exits.
pub(crate) struct Layout {
    /// The drawn symbol INCLUDING its quiet zone.
    pub sym: Rect,
    /// Pixels per module: integer, so a module is an exact square, and the largest the
    /// panel allows. The number a scanner's chances rest on.
    pub scale: i32,
    /// Where the copy block starts, and how wide it may run.
    copy: Rect,
    delivered: Rect,
    close: Rect,
}

/// S-39, while it is open over S-38.
pub(crate) struct SignedQr {
    /// The finished symbol, computed on the std side and handed in. This crate never
    /// encodes one - see `crate::qr`.
    data: QrData,
}

impl SignedQr {
    pub(crate) fn new(data: QrData) -> SignedQr {
        SignedQr { data }
    }

    /// Where everything goes.
    ///
    /// Two shapes, chosen by [`Metrics::landscape`] rather than by a panel list: a wide
    /// panel has no vertical room to stack the copy under a symbol worth scanning, so the
    /// symbol takes the panel's height and the copy takes the width left over. A tall or
    /// square panel stacks, because there the width is what the symbol would waste.
    pub(crate) fn layout(&self, m: &Metrics) -> Layout {
        let total = self.data.size() as i32 + 2 * QUIET;
        let btn_h = m.btn.max(TOUCH_MIN);
        let fit = |area: Rect| {
            let side = area.w.min(area.h);
            let scale = (side / total.max(1)).max(1);
            let drawn = total * scale;
            (
                Rect::new(
                    area.x + (area.w - drawn) / 2,
                    area.y + (area.h - drawn) / 2,
                    drawn,
                    drawn,
                ),
                scale,
            )
        };

        if m.landscape() {
            // The symbol is bound by the height, and what is left of the width is the
            // column. Measured from the AREA and not from the drawn symbol, so the column
            // does not move when a smaller transaction produces a smaller symbol.
            let side = m.h - 2 * m.gap;
            let area = Rect::new(m.gap, m.gap, side, side);
            let (sym, scale) = fit(area);
            let x = area.right() + m.gap;
            let w = m.w - x - m.pad;
            let close = Rect::new(x, m.h - m.pad - btn_h, w, btn_h);
            let delivered = Rect::new(x, close.y - m.gap - btn_h, w, btn_h);
            let copy = Rect::new(x, m.pad, w, copy_height(w));
            return Layout { sym, scale, copy, delivered, close };
        }

        // Stacked: the exits sit on the floor, the copy above them, and the symbol takes
        // everything that is left.
        let w = m.w - 2 * m.pad;
        let row_y = m.h - m.pad - btn_h;
        let btn_w = (w - m.gap) / 2;
        let delivered = Rect::new(m.pad, row_y, btn_w, btn_h);
        let close = Rect::new(m.pad + btn_w + m.gap, row_y, w - btn_w - m.gap, btn_h);
        let copy_h = copy_height(w);
        let copy = Rect::new(m.pad, row_y - m.gap - copy_h, w, copy_h);
        let area = Rect::new(m.pad, m.pad, w, (copy.y - m.gap - m.pad).max(1));
        let (sym, scale) = fit(area);
        Layout { sym, scale, copy, delivered, close }
    }

    pub(crate) fn regions(&self, m: &Metrics, out: &mut Vec<Region>) {
        let l = self.layout(m);
        out.push(Region { id: RegionId::DeliverQrDelivered, rect: l.delivered });
        out.push(Region { id: RegionId::DeliverQrClose, rect: l.close });
    }

    pub(crate) fn activate(&self, id: RegionId) -> Exit {
        match id {
            RegionId::DeliverQrDelivered => Exit::Delivered,
            RegionId::DeliverQrClose => Exit::Closed,
            _ => Exit::Stay,
        }
    }

    pub(crate) fn draw<D: DrawTarget<Color = Rgb565>>(
        &self,
        t: &mut D,
        m: &Metrics,
    ) -> Result<(), D::Error> {
        let l = self.layout(m);
        // White, edge to edge. It is the highest contrast this palette has and it is what
        // the symbol's quiet zone is made of; a symbol on paper-coloured background scans,
        // but this one may be read at three pixels per module and every bit of contrast is
        // margin a phone gets to spend.
        fill(t, m.screen(), PAPER_3)?;

        let size = self.data.size() as i32;
        let origin_x = l.sym.x + QUIET * l.scale;
        let origin_y = l.sym.y + QUIET * l.scale;
        // Dark modules as horizontal runs: one fill per run rather than per module, which
        // is what makes a 141-module symbol a few hundred fills instead of twenty thousand.
        for y in 0..size {
            let mut x = 0;
            while x < size {
                if self.data.module(x as u16, y as u16) {
                    let start = x;
                    while x < size && self.data.module(x as u16, y as u16) {
                        x += 1;
                    }
                    fill(
                        t,
                        Rect::new(
                            origin_x + start * l.scale,
                            origin_y + y * l.scale,
                            (x - start) * l.scale,
                            l.scale,
                        ),
                        INK_PRIMARY,
                    )?;
                } else {
                    x += 1;
                }
            }
        }

        let mut y = l.copy.y;
        for (part, line) in rows(l.copy.w) {
            text(t, &part, l.copy.x, y, line.font(), line.ink(), PAPER_3)?;
            y += line.height();
        }

        // Clipped to their own keys, like every other pair of buttons in this crate: a
        // label wider than its button crops rather than bleeding into its neighbour.
        for (rect, label, kind) in [
            (l.delivered, "My wallet has it", ButtonKind::Primary),
            (l.close, "Close", ButtonKind::Secondary),
        ] {
            let mut clip = t.clipped(&rect.to_eg());
            button(&mut clip, rect, label, kind, PAPER_3)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::PANELS;
    use alloc::vec;
    use notyas_core::psbt_qr::MAX_SYMBOL_MODULES;

    /// A symbol of `size` modules a side, with a pattern in it so a drawing bug has
    /// something to get wrong. The contents do not matter to a layout test; the SIZE does,
    /// because it is what the scale is computed from.
    fn symbol(size: usize) -> QrData {
        let rows: Vec<Vec<bool>> = (0..size)
            .map(|y| (0..size).map(|x| (x * 7 + y * 13) % 3 == 0).collect())
            .collect();
        QrData::from_matrix(&rows).expect("square")
    }

    /// The floor the whole feature rests on: the LARGEST payload the encoder will produce
    /// still draws at three pixels per module on every panel the firmware ships, and the
    /// common single-input spend draws at four.
    ///
    /// Three is not a preference, it is what `notyas_core::psbt_qr::MAX_PSBT_BYTES` was
    /// chosen against, and it is measured here rather than asserted in prose because the
    /// number depends on this layout: the copy block and the two exits are pixels the
    /// symbol does not get.
    ///
    /// Broken version: give the copy block a second `LINE` of height, or drop the landscape
    /// branch so a 800x480 panel stacks. Either takes the largest symbol under three pixels
    /// per module on the short panels and this trips.
    #[test]
    fn the_symbol_is_scannable_on_every_shipped_panel() {
        for (w, h) in PANELS {
            let m = Metrics::new(w, h);
            // 141 modules is the largest the encoder can produce; 101 is a single-input
            // P2WPKH spend, the shape the owner of this device signs.
            for (size, floor) in [(MAX_SYMBOL_MODULES as usize, 3), (101, 4)] {
                let qr = SignedQr::new(symbol(size));
                let l = qr.layout(&m);
                assert!(
                    l.scale >= floor,
                    "{w}x{h}: a {size}-module symbol draws at {} px per module, under {floor}",
                    l.scale
                );
                assert_eq!(
                    l.sym.w,
                    (size as i32 + 2 * QUIET) * l.scale,
                    "{w}x{h}: the quiet zone is part of the drawn symbol"
                );
                assert_eq!(l.sym.w, l.sym.h, "{w}x{h}: square");
            }
        }
    }

    /// Everything is on the panel and nothing overlaps the symbol - a copy line drawn
    /// across a QR code is a QR code that does not scan.
    #[test]
    fn nothing_is_drawn_off_the_panel_or_over_the_symbol() {
        for (w, h) in PANELS {
            let m = Metrics::new(w, h);
            for size in [21usize, 101, MAX_SYMBOL_MODULES as usize] {
                let qr = SignedQr::new(symbol(size));
                let l = qr.layout(&m);
                let screen = m.screen();
                let copy = Rect::new(l.copy.x, l.copy.y, l.copy.w, copy_height(l.copy.w));
                let what = format!("{w}x{h} size {size}");
                for (name, r) in
                    [("symbol", l.sym), ("copy", copy), ("delivered", l.delivered), ("close", l.close)]
                {
                    assert!(
                        r.x >= 0 && r.y >= 0 && r.right() <= screen.right() && r.bottom() <= screen.bottom(),
                        "{what}: {name} is {r:?} on a {w}x{h} panel"
                    );
                }
                for (name, r) in [("copy", copy), ("delivered", l.delivered), ("close", l.close)] {
                    assert!(!l.sym.overlaps(&r), "{what}: {name} is drawn over the symbol");
                }
                assert!(!l.delivered.overlaps(&l.close), "{what}: the two exits overlap");
                assert!(!copy.overlaps(&l.delivered), "{what}: the copy runs into the exits");
            }
        }
    }

    /// Both exits are tappable at every geometry, and both are hit-testable - the second
    /// half is what stops a drawn control that does nothing.
    #[test]
    fn both_exits_are_tappable_and_hit_tested() {
        for (w, h) in PANELS {
            let m = Metrics::new(w, h);
            let qr = SignedQr::new(symbol(101));
            let l = qr.layout(&m);
            for (name, r) in [("delivered", l.delivered), ("close", l.close)] {
                assert!(
                    r.w >= TOUCH_MIN && r.h >= TOUCH_MIN,
                    "{w}x{h}: {name} is {}x{}, under the {TOUCH_MIN} px floor",
                    r.w,
                    r.h
                );
            }
            let mut out = Vec::new();
            qr.regions(&m, &mut out);
            let ids: Vec<RegionId> = out.iter().map(|r| r.id).collect();
            assert_eq!(ids, vec![RegionId::DeliverQrDelivered, RegionId::DeliverQrClose], "{w}x{h}");
            assert_eq!(qr.activate(RegionId::DeliverQrDelivered), Exit::Delivered);
            assert_eq!(qr.activate(RegionId::DeliverQrClose), Exit::Closed);
            assert_eq!(qr.activate(RegionId::DeliverSd), Exit::Stay, "a foreign region does nothing");
        }
    }

    /// The copy says a scan is not a broadcast, says what to do instead, and never says
    /// the transaction was sent. Requirement, not taste: a phone's beep must not read as
    /// money moving.
    #[test]
    fn the_copy_cannot_be_read_as_a_broadcast() {
        let all = COPY.iter().map(|(c, _)| *c).collect::<Vec<_>>().join(" ");
        assert!(all.contains("Scanning does not broadcast"), "{all}");
        assert!(all.contains("Broadcast from your wallet"), "{all}");
        for word in ["sent", "broadcast the", "complete", "confirmed", "successfully"] {
            assert!(!all.to_lowercase().contains(word), "the copy says {word:?}: {all}");
        }
        assert!(all.contains("single frame"), "C11's static case says which it is");
        assert!(all.is_ascii() && !all.contains('\u{2013}') && !all.contains('\u{2014}'), "{all}");
    }

    /// Every copy line fits the block it is wrapped into, at every geometry. The block is
    /// measured from the same table the painter walks, so this is really a check that the
    /// landscape column is not too narrow for a word.
    #[test]
    fn the_copy_fits_its_block_on_every_panel() {
        for (w, h) in PANELS {
            let m = Metrics::new(w, h);
            let l = SignedQr::new(symbol(101)).layout(&m);
            for (part, line) in rows(l.copy.w) {
                assert!(
                    line.font().text_width(&part) as i32 <= l.copy.w,
                    "{w}x{h}: {part:?} needs {} px in {} px",
                    line.font().text_width(&part),
                    l.copy.w
                );
            }
        }
    }
}
