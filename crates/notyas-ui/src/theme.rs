// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Butter Paper tokens as `Rgb565` constants, plus the masking and strength conventions
//! the desktop GUI established.
//!
//! Token source of truth: the Butter Paper house style guide (`YellowBGs.md`, kept
//! outside this repository), which is also what desktop BigDice's `gui/theme.rs`
//! transcribes - see <https://github.com/intnsity/BigDice>. The hex values below
//! are the guide's CSS custom properties quantized to RGB565; nothing here invents a
//! color. Depth is communicated by paper tint (lighter = closer), separation by warm
//! hairline borders - no shadows on the device, exactly as the guide's elevation rule
//! prescribes for its shadow-free tiers.

use embedded_graphics::pixelcolor::Rgb565;

/// `0xRRGGBB` -> `Rgb565` by channel truncation, the standard 888->565 quantization.
const fn rgb(c: u32) -> Rgb565 {
    Rgb565::new(
        ((c >> 16) & 0xFF) as u8 >> 3,
        ((c >> 8) & 0xFF) as u8 >> 2,
        (c & 0xFF) as u8 >> 3,
    )
}

// --- Paper ramp (backgrounds; lighter = closer) ---------------------------------------
/// `--paper-0` - recessed: wells, meter troughs, table header bands.
pub const PAPER_0: Rgb565 = rgb(0xFAF3D9);
/// `--paper-1` - the page itself.
pub const PAPER_1: Rgb565 = rgb(0xFFF7E0);
/// `--paper-2` - raised: cards, the top bar.
pub const PAPER_2: Rgb565 = rgb(0xFFFBEB);
/// `--paper-3` - peak: inputs and modals. White = editable, the only pure white here.
pub const PAPER_3: Rgb565 = rgb(0xFFFFFF);
/// `--paper-tint` - selection and pressed states.
pub const PAPER_TINT: Rgb565 = rgb(0xFFF4C9);

// --- Ink ramp (never pure black on yellow paper) --------------------------------------
pub const INK_PRIMARY: Rgb565 = rgb(0x2B2417);
pub const INK_SECONDARY: Rgb565 = rgb(0x6B6250);
pub const INK_MUTED: Rgb565 = rgb(0x9C927C);

// --- Accents (cool against the warm paper; cobalt = interactive) ----------------------
pub const ACCENT: Rgb565 = rgb(0x1E40AF);
pub const ACCENT_TINT: Rgb565 = rgb(0xE4EBFA);
/// Graphite - editorial emphasis only, never on interactive elements.
pub const GRAPHITE: Rgb565 = rgb(0x3F3F46);

// --- Semantic trio --------------------------------------------------------------------
pub const SUCCESS: Rgb565 = rgb(0x047857);
pub const WARNING: Rgb565 = rgb(0xC2410C);
pub const DANGER: Rgb565 = rgb(0xBE123C);
pub const DANGER_TINT: Rgb565 = rgb(0xFCE5EA);

// --- Hairlines ------------------------------------------------------------------------
// The guide's borders are ink at 14% / 28% alpha. RGB565 has no alpha, so these are the
// composite over `paper-1` precomputed; on the adjacent paper tints the error is under
// one 565 quantization step, invisible.
/// `--border`: ink 14% over paper-1.
pub const BORDER: Rgb565 = rgb(0xE1D9C4);
/// `--border-strong`: ink 28% over paper-1.
pub const BORDER_STRONG: Rgb565 = rgb(0xC3BCA8);

/// Every color this crate can put on a panel.
///
/// The list exists so a host instrument can prove its sentinel is unreachable: the
/// simulator paints an out-of-palette magenta under every frame and treats a surviving
/// magenta pixel as an unpainted one, which is only sound while no token IS that magenta.
/// A palette entry added without being added here is caught by that same test, since the
/// array length is what it counts.
pub const PALETTE: [Rgb565; 17] = [
    PAPER_0,
    PAPER_1,
    PAPER_2,
    PAPER_3,
    PAPER_TINT,
    INK_PRIMARY,
    INK_SECONDARY,
    INK_MUTED,
    ACCENT,
    ACCENT_TINT,
    GRAPHITE,
    SUCCESS,
    WARNING,
    DANGER,
    DANGER_TINT,
    BORDER,
    BORDER_STRONG,
];

// --- Masking convention (desktop BigDice house law; survey section 5) -----------------
// Two rules, and the difference between them is who chose the secret. A DERIVED secret
// masks as a FIXED run: its length is information the user never supplied and must not
// leak. TYPED input masks one bullet per character ([`canvas::field`]): the user knows
// what they typed, the byte counter states it anyway, and a fixed run on a field being
// edited reads as a bug. There is deliberately no fixed-run constant for input fields.
/// Bullets standing in for one hidden mnemonic word. Fixed for the same reason: BIP39
/// words run three to eight letters, and a mask cut to each word would narrow the
/// dictionary per slot.
pub const MASK_WORD_BULLETS: usize = 6;
/// U+2022 BULLET, escaped so the source stays ASCII. Present in every committed atlas.
pub const BULLET: char = '\u{2022}';

/// The fixed-length word mask: [`MASK_WORD_BULLETS`] bullets, the same string for every
/// word of every mnemonic.
pub fn mask_word() -> &'static str {
    "\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}"
}

// --- Strength bands (desktop gui/pipeline.rs semantics, verbatim) ---------------------

/// How much real entropy the user has actually collected, mapped to the desktop's
/// three-band meter. Computed from EFFECTIVE bits, never from the mnemonic's ENT: in
/// fixed word-count mode the mnemonic is a hash of the digit string, so a 24-word phrase
/// can be produced from three rolls, and reporting 256 bits there would be a lie.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strength {
    /// Below 128 bits: not safe to hold value.
    Weak,
    /// 128..255 bits: the usual 12-word security level.
    Fair,
    /// 256 bits and up.
    Strong,
}

impl Strength {
    pub fn of(bits: usize) -> Self {
        match bits {
            0..=127 => Strength::Weak,
            128..=255 => Strength::Fair,
            _ => Strength::Strong,
        }
    }

    /// The word shown next to the bit count, e.g. "320 bits - strong". Desktop wording.
    pub fn text(self) -> &'static str {
        match self {
            Strength::Weak => "weak",
            Strength::Fair => "ok",
            Strength::Strong => "strong",
        }
    }

    /// Semantic color of the band: danger / warning / success, as on the desktop meter.
    pub fn color(self) -> Rgb565 {
        match self {
            Strength::Weak => DANGER,
            Strength::Fair => WARNING,
            Strength::Strong => SUCCESS,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strength_bands_match_desktop() {
        assert_eq!(Strength::of(0), Strength::Weak);
        assert_eq!(Strength::of(127), Strength::Weak);
        assert_eq!(Strength::of(128), Strength::Fair);
        assert_eq!(Strength::of(255), Strength::Fair);
        assert_eq!(Strength::of(256), Strength::Strong);
    }

    #[test]
    fn word_mask_is_fixed_bullets() {
        assert_eq!(mask_word().chars().count(), MASK_WORD_BULLETS);
        assert!(mask_word().chars().all(|c| c == BULLET));
    }
}
