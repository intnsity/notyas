//! Butter Paper design tokens, RGB565-quantized.
//!
//! Source of truth: \\172.16.0.9\bear\code\YellowBGs.md (the house style
//! guide). Token names match the CSS custom properties there. RGB565 loses
//! the low bits (5/6/5), which is invisible at these pastel deltas; the
//! constants keep the 24-bit reference value in a comment for auditing.

// The full token set ships even before every token has a consumer - screens
// arriving in m3/m4 (dice entry, verify, errors) draw from it, and the theme
// must stay a faithful mirror of the style guide, not a per-screen subset.
#![allow(dead_code)]

use embedded_graphics::pixelcolor::Rgb565;

/// Quantize a 24-bit sRGB reference color to RGB565.
const fn rgb(r: u8, g: u8, b: u8) -> Rgb565 {
    Rgb565::new(r >> 3, g >> 2, b >> 3)
}

// Paper ramp - backgrounds only, lighter = closer (depth by tint, no shadows).
pub const PAPER_0: Rgb565 = rgb(0xFA, 0xF3, 0xD9); // #FAF3D9 recessed
pub const PAPER_1: Rgb565 = rgb(0xFF, 0xF7, 0xE0); // #FFF7E0 base page
pub const PAPER_2: Rgb565 = rgb(0xFF, 0xFB, 0xEB); // #FFFBEB cards
pub const PAPER_3: Rgb565 = rgb(0xFF, 0xFF, 0xFF); // #FFFFFF inputs, modals
pub const PAPER_TINT: Rgb565 = rgb(0xFF, 0xF4, 0xC9); // #FFF4C9 hover, selection

// Ink ramp - warm brown-black; never pure black on yellow paper.
pub const INK_PRIMARY: Rgb565 = rgb(0x2B, 0x24, 0x17); // #2B2417
pub const INK_SECONDARY: Rgb565 = rgb(0x6B, 0x62, 0x50); // #6B6250
pub const INK_MUTED: Rgb565 = rgb(0x9C, 0x92, 0x7C); // #9C927C

// Accents - cool and saturated against the warm paper.
pub const ACCENT: Rgb565 = rgb(0x1E, 0x40, 0xAF); // #1E40AF cobalt, interactive
pub const ACCENT_HOVER: Rgb565 = rgb(0x1B, 0x36, 0x91); // #1B3691
pub const ACCENT_TINT: Rgb565 = rgb(0xE4, 0xEB, 0xFA); // #E4EBFA
pub const GRAPHITE: Rgb565 = rgb(0x3F, 0x3F, 0x46); // #3F3F46 editorial only
pub const GRAPHITE_TINT: Rgb565 = rgb(0xEC, 0xEC, 0xEF); // #ECECEF

// Semantic.
pub const SUCCESS: Rgb565 = rgb(0x04, 0x78, 0x57); // #047857 emerald
pub const WARNING: Rgb565 = rgb(0xC2, 0x41, 0x0C); // #C2410C signal orange
pub const DANGER: Rgb565 = rgb(0xBE, 0x12, 0x3C); // #BE123C crimson

/// Hairline border. The style guide uses rgba(43,36,23,0.14) over paper;
/// with no alpha in RGB565 this is that hairline pre-composited over paper-2:
/// a solid warm gray #D9D2BA.
pub const HAIRLINE: Rgb565 = rgb(0xD9, 0xD2, 0xBA);
