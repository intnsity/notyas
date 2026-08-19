// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The render target the gate measures with.
//!
//! A device panel discards a pixel drawn off its edge, and so did this simulator's old
//! framebuffer: the bounds test threw the pixel away, and the font renderer documented
//! that it relied on that. The consequence is that overflow evidence was destroyed AT THE
//! TARGET - no assertion downstream can recover a pixel that was never recorded, and a
//! heading drawn 40 px past the right edge looked identical to one that fitted.
//!
//! [`Panel`] records instead. It allocates a margin on every side, so a draw that
//! overshoots lands somewhere countable and keeps its bounding box, and it fills the whole
//! buffer with a [`SENTINEL`] colour no screen can produce, so a pixel INSIDE the panel
//! that no screen painted is still that colour when the frame is done. Two invariants come
//! out of one instrument:
//!
//! - `escapes().count == 0` - nothing was drawn off the panel.
//! - `holes().count == 0` - nothing inside the panel was left unpainted.
//!
//! Only `draw_iter` is implemented. embedded-graphics' default `fill_solid`,
//! `fill_contiguous` and `clear` all funnel through it, so there is exactly one place a
//! pixel can enter this type and exactly one place the accounting can be wrong.

use embedded_graphics::draw_target::DrawTarget;
use embedded_graphics::geometry::{OriginDimensions, Size};
use embedded_graphics::pixelcolor::{Rgb565, RgbColor};
use embedded_graphics::prelude::IntoStorage;
use embedded_graphics::Pixel;

use notyas_core::bitcoin::hashes::{sha256, Hash, HashEngine};
use notyas_ui::layout::Rect;
use notyas_ui::theme::PAPER_1;

/// How far past each edge an escaping draw is still recorded exactly, in px.
///
/// Wide enough to hold any plausible overshoot (a whole button, a wrapped line) with its
/// position intact, small enough that five panels' worth of buffers stay trivial. A draw
/// further out than this is still COUNTED and still extends the escape bounding box - see
/// [`Escape::beyond_margin`] - it just has nowhere to store its colour.
pub const MARGIN: i32 = 64;

/// The colour that means "nothing drew here".
///
/// 0xFF00FF. Not in [`notyas_ui::theme::PALETTE`], which is what makes a surviving
/// sentinel pixel proof rather than a guess. A unit test asserts the palette stays clear
/// of it, so a future token cannot blind the instrument silently.
pub const SENTINEL: Rgb565 = Rgb565::new(0x1F, 0x00, 0x1F);

/// Pixels that went somewhere they should not have, and where.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Escape {
    /// How many pixels were involved.
    pub count: u32,
    /// The rectangle they occupied, in panel coordinates - negative x or y is left of or
    /// above the panel. `None` when `count` is zero.
    pub bbox: Option<Rect>,
    /// Of those, how many landed further out than [`MARGIN`] and so could not be stored.
    /// They are counted and their position is in `bbox`; only their colour is lost.
    pub beyond_margin: u32,
}

impl Escape {
    fn record(&mut self, x: i32, y: i32) {
        self.count += 1;
        self.bbox = Some(match self.bbox {
            None => Rect::new(x, y, 1, 1),
            Some(b) => {
                let (x0, y0) = (b.x.min(x), b.y.min(y));
                let (x1, y1) = (b.right().max(x + 1), b.bottom().max(y + 1));
                Rect::new(x0, y0, x1 - x0, y1 - y0)
            }
        });
    }

    /// One line naming what escaped and where, for a failure message.
    pub fn describe(&self) -> String {
        match self.bbox {
            None => String::from("none"),
            Some(b) => format!(
                "{} px in {},{} {}x{}{}",
                self.count,
                b.x,
                b.y,
                b.w,
                b.h,
                if self.beyond_margin > 0 {
                    format!(" ({} of them past the {MARGIN} px margin)", self.beyond_margin)
                } else {
                    String::new()
                }
            ),
        }
    }
}

/// What one pass over a finished frame yields. See [`Panel::measure`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Measured {
    /// Panel pixels nothing painted.
    pub holes: Escape,
    /// Bounding box of the pixels that are not bare paper; `None` on an all-paper frame.
    pub ink: Option<Rect>,
    /// How many such pixels there are. Moves when a clipped string is truncated, which is
    /// the overflow that by construction leaves no escape to find.
    pub ink_px: u32,
    /// SHA-256 over the panel's RGB565 pixels, little-endian, row major.
    pub digest: [u8; 32],
}

/// A panel plus its margins, with every pixel accounted for.
pub struct Panel {
    w: i32,
    h: i32,
    /// Row stride of the backing buffer, `w + 2 * MARGIN`.
    stride: i32,
    px: Vec<Rgb565>,
    escape: Escape,
}

impl Panel {
    pub fn new(w: u32, h: u32) -> Panel {
        let (w, h) = (w as i32, h as i32);
        let stride = w + 2 * MARGIN;
        let rows = h + 2 * MARGIN;
        Panel {
            w,
            h,
            stride,
            px: vec![SENTINEL; (stride * rows) as usize],
            escape: Escape::default(),
        }
    }

    pub fn width(&self) -> u32 {
        self.w as u32
    }

    pub fn height(&self) -> u32 {
        self.h as u32
    }

    /// What was drawn outside the panel.
    pub fn escapes(&self) -> Escape {
        self.escape
    }

    /// Panel pixels no screen painted: still [`SENTINEL`] after a full repaint.
    ///
    /// Sound because every screen's `draw` fills the whole panel with paper before it
    /// draws anything (`screens::draw`), so an unpainted pixel is not a screen that chose
    /// not to paint there - it is a screen that failed to.
    pub fn holes(&self) -> Escape {
        self.measure().holes
    }

    /// Bounding box and count of the pixels that are not bare paper - what a reader would
    /// call the content of the frame.
    pub fn ink(&self) -> (Option<Rect>, u32) {
        let m = self.measure();
        (m.ink, m.ink_px)
    }

    /// SHA-256 over the panel's pixels as RGB565, little-endian, row major.
    pub fn digest(&self) -> [u8; 32] {
        self.measure().digest
    }

    /// Everything the gate reads off a finished frame, in one pass over the panel.
    ///
    /// One pass rather than three because the gate renders the whole catalogue on every
    /// shipped panel - a few hundred frames - and three passes over a 1280 px-tall panel
    /// is the difference between a test that runs on every `cargo test` and one that gets
    /// disabled. The margins are deliberately not read: they are evidence about a defect
    /// (see [`Panel::escapes`]), never part of the frame's identity, and a digest that
    /// changed when an escape moved would make the escape approvable.
    pub fn measure(&self) -> Measured {
        let mut holes = Escape::default();
        let mut ink = Escape::default();
        let mut engine = sha256::Hash::engine();
        let mut row = Vec::with_capacity(self.w as usize * 2);
        for y in 0..self.h {
            row.clear();
            for x in 0..self.w {
                let c = self.at(x, y);
                if c == SENTINEL {
                    holes.record(x, y);
                }
                if c != PAPER_1 {
                    ink.record(x, y);
                }
                row.extend_from_slice(&c.into_storage().to_le_bytes());
            }
            engine.input(&row);
        }
        Measured {
            holes,
            ink: ink.bbox,
            ink_px: ink.count,
            digest: sha256::Hash::from_engine(engine).to_byte_array(),
        }
    }

    /// The panel as RGB888 rows, ready for a PNG encoder. Bit replication, the same
    /// expansion the font blender uses.
    pub fn rgb888(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity((self.w * self.h * 3) as usize);
        for y in 0..self.h {
            for x in 0..self.w {
                let p = self.at(x, y);
                let (r, g, b) = (p.r(), p.g(), p.b());
                out.push((r << 3) | (r >> 2));
                out.push((g << 2) | (g >> 4));
                out.push((b << 3) | (b >> 2));
            }
        }
        out
    }

    /// The panel rectangle as a PNG, with the byte-determinism settings pinned.
    pub fn png(&self) -> Vec<u8> {
        encode_png(self.w as u32, self.h as u32, &self.rgb888())
    }

    /// The panel AND its margins as a PNG, with the panel edge drawn in the sentinel
    /// colour.
    ///
    /// What an escape actually looks like. A count and a bounding box say a draw went off
    /// the glass; this says WHICH draw, which is the difference between a bug report and a
    /// fix. Written by `uisim render` only when something escaped, so it costs nothing in
    /// the common case.
    pub fn png_with_margins(&self) -> Vec<u8> {
        let (bw, bh) = (self.stride, self.h + 2 * MARGIN);
        let mut rgb = Vec::with_capacity((bw * bh * 3) as usize);
        for by in 0..bh {
            for bx in 0..bw {
                let (x, y) = (bx - MARGIN, by - MARGIN);
                let on_edge = (x == -1 || x == self.w) && (-1..=self.h).contains(&y)
                    || (y == -1 || y == self.h) && (-1..=self.w).contains(&x);
                let p = if on_edge {
                    SENTINEL
                } else {
                    self.px[(by * self.stride + bx) as usize]
                };
                let (r, g, b) = (p.r(), p.g(), p.b());
                rgb.push((r << 3) | (r >> 2));
                rgb.push((g << 2) | (g >> 4));
                rgb.push((b << 3) | (b >> 2));
            }
        }
        encode_png(bw as u32, bh as u32, &rgb)
    }

    /// One panel pixel. Panics on a coordinate off the panel: callers iterate the panel
    /// rectangle, and the margins are read through nothing else.
    pub fn at(&self, x: i32, y: i32) -> Rgb565 {
        assert!(x >= 0 && y >= 0 && x < self.w && y < self.h, "({x},{y}) is off the panel");
        self.px[((y + MARGIN) * self.stride + (x + MARGIN)) as usize]
    }
}

/// RGB888 rows to PNG with the byte-determinism settings pinned: fixed filter, fixed
/// compression. One encoder for the docs pictures and for the diff images, so a picture
/// written by one command can be compared with a picture written by another.
pub fn encode_png(w: u32, h: u32, rgb: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    {
        let mut enc = png::Encoder::new(&mut bytes, w, h);
        enc.set_color(png::ColorType::Rgb);
        enc.set_depth(png::BitDepth::Eight);
        enc.set_filter(png::FilterType::Paeth);
        enc.set_compression(png::Compression::Best);
        let mut writer = enc.write_header().expect("png header");
        writer.write_image_data(rgb).expect("png data");
    }
    bytes
}

impl OriginDimensions for Panel {
    fn size(&self) -> Size {
        Size::new(self.w as u32, self.h as u32)
    }
}

impl DrawTarget for Panel {
    type Color = Rgb565;
    type Error = core::convert::Infallible;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Rgb565>>,
    {
        let rows = self.h + 2 * MARGIN;
        for Pixel(p, c) in pixels {
            let on_panel = p.x >= 0 && p.y >= 0 && p.x < self.w && p.y < self.h;
            if !on_panel {
                self.escape.record(p.x, p.y);
            }
            let (bx, by) = (p.x + MARGIN, p.y + MARGIN);
            if bx >= 0 && by >= 0 && bx < self.stride && by < rows {
                self.px[(by * self.stride + bx) as usize] = c;
            } else {
                self.escape.beyond_margin += 1;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use embedded_graphics::primitives::{PrimitiveStyle, Rectangle, StyledDrawable};
    use notyas_ui::theme::PALETTE;

    /// The instrument's one assumption: no colour the UI can paint IS the sentinel, so a
    /// surviving sentinel pixel is an unpainted one and nothing else.
    #[test]
    fn the_sentinel_is_not_in_the_palette() {
        assert!(
            PALETTE.iter().all(|c| *c != SENTINEL),
            "a Butter Paper token is the sentinel colour; the hole check is blind"
        );
    }

    /// A fresh panel is all holes and no ink escapes: the instrument reads zero only
    /// because something painted, never because it cannot see.
    #[test]
    fn an_unpainted_panel_is_all_holes() {
        let p = Panel::new(8, 4);
        assert_eq!(p.holes().count, 32);
        assert_eq!(p.escapes().count, 0);
    }

    /// A draw off the panel is counted and located rather than dropped - the whole reason
    /// this type exists.
    #[test]
    fn a_draw_off_the_panel_is_recorded_with_its_position() {
        let mut p = Panel::new(8, 4);
        Rectangle::new(
            embedded_graphics::geometry::Point::new(6, 1),
            Size::new(4, 2),
        )
        .draw_styled(&PrimitiveStyle::with_fill(PAPER_1), &mut p)
        .unwrap();
        let e = p.escapes();
        assert_eq!(e.count, 4, "two columns past the right edge, two rows tall");
        assert_eq!(e.bbox, Some(Rect::new(8, 1, 2, 2)));
        assert_eq!(e.beyond_margin, 0);
    }

    /// ...and one further out than the margin is still counted and still located, so
    /// distance cannot make an escape disappear.
    #[test]
    fn a_draw_past_the_margin_is_still_counted() {
        let mut p = Panel::new(8, 4);
        Rectangle::new(
            embedded_graphics::geometry::Point::new(8 + MARGIN, 0),
            Size::new(2, 1),
        )
        .draw_styled(&PrimitiveStyle::with_fill(PAPER_1), &mut p)
        .unwrap();
        let e = p.escapes();
        assert_eq!(e.count, 2);
        assert_eq!(e.beyond_margin, 2);
        assert_eq!(e.bbox, Some(Rect::new(8 + MARGIN, 0, 2, 1)));
    }

    /// Ink is measured against paper, so a fully papered panel has none.
    #[test]
    fn paper_is_not_ink() {
        let mut p = Panel::new(8, 4);
        Rectangle::new(embedded_graphics::geometry::Point::zero(), Size::new(8, 4))
            .draw_styled(&PrimitiveStyle::with_fill(PAPER_1), &mut p)
            .unwrap();
        assert_eq!(p.holes().count, 0);
        assert_eq!(p.ink(), (None, 0));

        Rectangle::new(embedded_graphics::geometry::Point::new(2, 1), Size::new(3, 2))
            .draw_styled(&PrimitiveStyle::with_fill(notyas_ui::theme::INK_PRIMARY), &mut p)
            .unwrap();
        assert_eq!(p.ink(), (Some(Rect::new(2, 1, 3, 2)), 6));
    }
}
