//! Host-side smoke test: render real text into an in-memory Rgb565 framebuffer and
//! check structural invariants of every generated atlas. Runs with std (integration
//! tests link std even though the library is no_std).

use embedded_graphics_core::draw_target::DrawTarget;
use embedded_graphics_core::geometry::{OriginDimensions, Point, Size};
use embedded_graphics_core::pixelcolor::Rgb565;
use embedded_graphics_core::Pixel;
use notyas_fonts::{
    draw_text, TextStyle, ALL, GLYPH_COUNT, MONO_REGULAR_32, SANS_REGULAR_24, SANS_REGULAR_32,
};

/// Minimal Rgb565 framebuffer. Out-of-bounds pixels are dropped, per the DrawTarget
/// contract, which also exercises the renderer's clipping assumption.
struct Frame {
    w: u32,
    h: u32,
    px: Vec<Rgb565>,
}

impl Frame {
    fn new(w: u32, h: u32, fill: Rgb565) -> Self {
        Frame { w, h, px: vec![fill; (w * h) as usize] }
    }
}

impl OriginDimensions for Frame {
    fn size(&self) -> Size {
        Size::new(self.w, self.h)
    }
}

impl DrawTarget for Frame {
    type Color = Rgb565;
    type Error = core::convert::Infallible;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Rgb565>>,
    {
        for Pixel(p, c) in pixels {
            if (0..self.w as i32).contains(&p.x) && (0..self.h as i32).contains(&p.y) {
                self.px[(p.y as u32 * self.w + p.x as u32) as usize] = c;
            }
        }
        Ok(())
    }
}

// Butter Paper-ish token pair: dark warm ink on light warm paper.
const INK: Rgb565 = Rgb565::new(6, 13, 6);
const PAPER: Rgb565 = Rgb565::new(29, 59, 27);

/// Every atlas: 97 glyphs, sane vertical metrics, and a bitmap that is exactly the
/// packed concatenation of the glyph boxes (monotonic offsets, no gaps, no overrun).
#[test]
fn atlas_invariants() {
    assert_eq!(GLYPH_COUNT, 97);
    assert_eq!(ALL.len(), 6);
    for atlas in ALL {
        assert!(atlas.ascent > 0 && atlas.descent < 0, "{} {}", atlas.family, atlas.px);
        assert!(atlas.line_height >= atlas.px, "{} {}", atlas.family, atlas.px);
        let mut expect_off = 0u32;
        for g in atlas.glyphs.iter() {
            assert_eq!(g.off, expect_off, "gap or overlap in {} {}", atlas.family, atlas.px);
            expect_off += g.w as u32 * g.h as u32;
        }
        assert_eq!(expect_off as usize, atlas.bitmap.len(), "{} {}", atlas.family, atlas.px);
    }
}

/// Render "notyas 0.1.0" and assert ink landed and the pen moved exactly the measured
/// width. The width constants are the generator's own output (atlasgen prints them),
/// pinned here so a regeneration that shifts metrics fails loudly.
#[test]
fn renders_notyas_version_string() {
    let text = "notyas 0.1.0";
    assert_eq!(SANS_REGULAR_32.text_width(text), 179);
    assert_eq!(MONO_REGULAR_32.text_width(text), 228);
    // The CAPTION face. Its line box is the reason it exists - a wallet action card has
    // 62 px inside it on the 800x480 panel and has to hold two of these - so the height
    // is pinned here beside the width, and a regeneration that moves either fails loudly.
    assert_eq!(SANS_REGULAR_24.text_width(text), 134);
    assert_eq!(SANS_REGULAR_24.line_height, 31);
    assert_eq!((SANS_REGULAR_24.ascent, SANS_REGULAR_24.descent), (25, -7));
    // Monospace really is monospaced: every advance identical.
    let mono_adv = MONO_REGULAR_32.glyphs[0].advance;
    assert!(MONO_REGULAR_32.glyphs.iter().all(|g| g.advance == mono_adv));
    assert_eq!(MONO_REGULAR_32.text_width(text), text.len() as u32 * mono_adv as u32);

    let mut fb = Frame::new(200, 48, PAPER);
    let style = TextStyle { font: &SANS_REGULAR_32, fg: INK, bg: PAPER };
    let pen = draw_text(&mut fb, text, Point::new(4, 2), &style).unwrap();
    assert_eq!(pen, Point::new(4 + 179, 2));

    let ink_px = fb.px.iter().filter(|&&c| c != PAPER).count();
    assert!(ink_px > 300, "only {ink_px} non-background pixels");
    // Full-coverage cores must come out as the exact foreground color.
    assert!(fb.px.contains(&INK), "no pixel with exact fg color");
}

/// Characters outside the glyph set fall back to '?'.
#[test]
fn out_of_set_falls_back_to_question_mark() {
    let q = SANS_REGULAR_32.text_width("?");
    assert_eq!(SANS_REGULAR_32.text_width("\u{00e9}"), q);
    // The two non-ASCII set members do NOT fall back.
    let bullet = SANS_REGULAR_32.glyph('\u{2022}');
    assert!(bullet.advance != 0 && bullet.w != 0);
    let ellipsis = SANS_REGULAR_32.glyph('\u{2026}');
    assert!(ellipsis.advance != 0 && ellipsis.w != 0);
}

/// Clipping at the target edge must not panic or write out of bounds.
#[test]
fn clipped_draw_is_safe() {
    let mut fb = Frame::new(40, 20, PAPER);
    let style = TextStyle { font: &SANS_REGULAR_32, fg: INK, bg: PAPER };
    draw_text(&mut fb, "WWWWWW", Point::new(-10, -10), &style).unwrap();
    draw_text(&mut fb, "WWWWWW", Point::new(30, 10), &style).unwrap();
}
