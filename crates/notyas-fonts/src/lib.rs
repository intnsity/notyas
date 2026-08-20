//! notyas-fonts - pre-rasterized glyph atlases and a minimal text renderer.
//!
//! The firmware never parses fonts at runtime: tools/fonts/atlasgen rasterizes the
//! committed IBM Plex TTFs on the host into the static atlases under [`gen`], and this
//! crate draws them onto any `Rgb565` [`DrawTarget`] with alpha blending against a
//! known background color. `#![no_std]`, allocation-free, pure Rust.
//!
//! # Licensing
//!
//! The CODE in this crate is GPL-3.0-or-later, like the rest of notyas. The GENERATED
//! GLYPH DATA under `src/gen/` is a different work: it is derived from IBM Plex Sans
//! and IBM Plex Mono (Copyright 2017 IBM Corp.) and remains under the SIL Open Font
//! License, Version 1.1. "Plex" is a Reserved Font Name, so these rasterized Modified
//! Versions are renamed "notyas Sans" and "notyas Mono" per OFL clause 3. Full license
//! text, upstream release identifiers, URLs, and SHA256 digests: LICENSE-fonts at the
//! repository root.
//!
//! # Renderer design
//!
//! This crate deliberately exposes [`draw_text`] / [`Atlas::text_width`] instead of
//! implementing `embedded_graphics::text::renderer::TextRenderer`. The firmware UI is
//! a dozen static screens of left-aligned spans on known Butter Paper token colors;
//! the TextRenderer trait's baseline variants, per-fragment pixel iterators, and style
//! plumbing buy nothing here and would triple the surface to review. Advance widths
//! are kerning-free by design (the atlases carry no kerning tables), so measurement is
//! an exact integer sum and layout is trivially predictable.
//!
//! Blending is fg-over-bg only: text always sits on a solid, known background color,
//! so each pixel is a linear interpolation between `fg` and `bg` by the glyph's 8-bit
//! coverage - no read-back from the framebuffer, no general compositing. Pixels with
//! zero coverage are skipped entirely, so overlapping glyph boxes (negative bearings)
//! never erase a neighbor's ink.

#![no_std]
#![deny(unsafe_code)]

pub mod gen;

pub use gen::{
    ALL, MONO_REGULAR_28, MONO_REGULAR_32, SANS_REGULAR_24, SANS_REGULAR_32, SANS_SEMIBOLD_32,
    SANS_SEMIBOLD_44,
};

use embedded_graphics_core::draw_target::DrawTarget;
use embedded_graphics_core::geometry::Point;
use embedded_graphics_core::pixelcolor::{Rgb565, RgbColor};
use embedded_graphics_core::Pixel;

/// Number of glyphs in every atlas: U+0020..=U+007E, then U+2022, U+2026.
pub const GLYPH_COUNT: usize = 97;

/// Index of `'?'`, the substitute for characters outside the glyph set.
const FALLBACK: usize = '?' as usize - 0x20;

/// Placement record for one glyph. See the layout comment in any generated atlas file
/// for the authoritative description; fields mirror it exactly.
#[derive(Debug, Clone, Copy)]
pub struct Glyph {
    /// Pen advance in px (rounded from the font's fractional advance).
    pub advance: u8,
    /// Bitmap width in px (0 for blank glyphs such as space).
    pub w: u8,
    /// Bitmap height in px.
    pub h: u8,
    /// Bitmap left edge relative to the pen x (may be negative).
    pub left: i8,
    /// Bitmap top edge in px above the baseline.
    pub top: i8,
    /// Byte offset of this glyph's pixels within the atlas bitmap.
    pub off: u32,
}

/// A complete rasterized face at one pixel size: metrics, glyph table, packed 8-bit
/// alpha bitmap. All instances are `static`, emitted by tools/fonts/atlasgen.
#[derive(Debug)]
pub struct Atlas {
    /// Derived family name ("notyas Sans" / "notyas Mono" - OFL-renamed, see crate docs).
    pub family: &'static str,
    /// Style name ("Regular" / "SemiBold").
    pub style: &'static str,
    /// Em size in px the face was rasterized at.
    pub px: u32,
    /// Baseline to top of line box, px (positive).
    pub ascent: i32,
    /// Baseline to bottom of line box, px (negative).
    pub descent: i32,
    /// Recommended baseline-to-baseline distance, px.
    pub line_height: u32,
    /// One record per glyph, indexed by position in the fixed glyph set.
    pub glyphs: &'static [Glyph; GLYPH_COUNT],
    /// Packed coverage bytes; each glyph's `off` points into this.
    pub bitmap: &'static [u8],
}

impl Atlas {
    /// Index of `c` in the fixed glyph set, or `None` if it is outside the set.
    fn index_of(c: char) -> Option<usize> {
        match c {
            ' '..='~' => Some(c as usize - 0x20),
            '\u{2022}' => Some(95),
            '\u{2026}' => Some(96),
            _ => None,
        }
    }

    /// Glyph record for `c`; characters outside the set render as `'?'`.
    pub fn glyph(&self, c: char) -> &Glyph {
        &self.glyphs[Self::index_of(c).unwrap_or(FALLBACK)]
    }

    /// Exact advance width of `s` in px. Kerning-free sum of integer advances, so this
    /// is precisely the horizontal distance [`draw_text`] moves the pen.
    pub fn text_width(&self, s: &str) -> u32 {
        s.chars().map(|c| self.glyph(c).advance as u32).sum()
    }
}

/// Foreground/background pair for one text run. `bg` must be the color the text
/// actually sits on (a Butter Paper token color); edges blend toward it.
#[derive(Debug, Clone, Copy)]
pub struct TextStyle {
    pub font: &'static Atlas,
    pub fg: Rgb565,
    pub bg: Rgb565,
}

/// Linear interpolation between `fg` and `bg` by 8-bit coverage `a`, performed in
/// 8-bit-per-channel space (565 channels expanded by bit replication, requantized by
/// truncation). `a == 255` returns `fg` exactly; callers skip `a == 0`.
#[inline]
fn blend(fg: Rgb565, bg: Rgb565, a: u8) -> Rgb565 {
    if a == 255 {
        return fg;
    }
    let a = a as u32;
    let na = 255 - a;
    #[inline]
    fn expand5(v: u8) -> u32 {
        let v = v as u32;
        (v << 3) | (v >> 2)
    }
    #[inline]
    fn expand6(v: u8) -> u32 {
        let v = v as u32;
        (v << 2) | (v >> 4)
    }
    let lerp = |f: u32, b: u32| (f * a + b * na + 127) / 255;
    let r = lerp(expand5(fg.r()), expand5(bg.r()));
    let g = lerp(expand6(fg.g()), expand6(bg.g()));
    let b = lerp(expand5(fg.b()), expand5(bg.b()));
    Rgb565::new((r >> 3) as u8, (g >> 2) as u8, (b >> 3) as u8)
}

/// Draw `text` in a single left-to-right run.
///
/// `origin` is the TOP-LEFT of the line box: the baseline sits at
/// `origin.y + style.font.ascent`, so stacking lines `line_height` apart tiles
/// correctly. Returns the pen position after the last advance (same `y` as `origin`),
/// which lets callers chain runs of different styles on one line. Pixels outside the
/// target are dropped by the `DrawTarget` contract, so partial clipping is safe.
pub fn draw_text<D>(
    target: &mut D,
    text: &str,
    origin: Point,
    style: &TextStyle,
) -> Result<Point, D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    let font = style.font;
    let baseline = origin.y + font.ascent;
    let mut pen = origin.x;
    for c in text.chars() {
        let g = font.glyph(c);
        if g.w != 0 && g.h != 0 {
            let x0 = pen + g.left as i32;
            let y0 = baseline - g.top as i32;
            let w = g.w as i32;
            let start = g.off as usize;
            let cov = &font.bitmap[start..start + g.w as usize * g.h as usize];
            target.draw_iter(cov.iter().enumerate().filter(|&(_, &a)| a != 0).map(
                |(i, &a)| {
                    let p = Point::new(x0 + i as i32 % w, y0 + i as i32 / w);
                    Pixel(p, blend(style.fg, style.bg, a))
                },
            ))?;
        }
        pen += g.advance as i32;
    }
    Ok(Point::new(pen, origin.y))
}
