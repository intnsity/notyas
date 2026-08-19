//! Panel calibration frame: what the GLASS shows, against what the framebuffer holds.
//!
//! This exists because a display bug reached a point where source reading could not settle
//! it. The 800x480 lock screen renders clean in the host simulator and every layout test
//! passes at that geometry, the draw path bounds-checks every pixel and the flush publishes
//! `0,0,w,h` from a `w`-stride buffer - and yet the Elecrow panel showed content centred and
//! clipped on both edges. Every one of those facts is about the BUFFER. None of them is
//! evidence about the glass, and the gap between the two is exactly where the defect lives.
//!
//! So this draws a frame whose whole content is its own coordinates. The operator reads the
//! numbers off the panel and that is the measurement: which framebuffer columns and rows
//! are actually visible, and where the origin sits. A pattern of unlabelled colour bars
//! would not do - it shows THAT something is wrong without pinning down what, and the
//! question here is quantitative.
//!
//! Compiled only under `--features diag-display`, and a build that has it never reaches the
//! product UI. This is an instrument, not a screen.

use std::thread;
use std::time::Duration;

use embedded_graphics::mono_font::ascii::{FONT_10X20, FONT_6X10};
use embedded_graphics::mono_font::MonoTextStyle;
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;
use embedded_graphics::primitives::Rectangle;
use embedded_graphics::text::{Alignment, Text};

use crate::display::Display;

/// Ruler spacing. 100 px divides both shipped widths (720, 800) and both heights (720, 480)
/// without a remainder, so the last tick always lands ON the far edge rather than near it -
/// which is the tick that answers "is the right-hand column visible at all".
const STEP: i32 = 100;

const BG: Rgb565 = Rgb565::new(0, 0, 0);
const EDGE: Rgb565 = Rgb565::new(31, 63, 31); // white: the 4 px border, at the exact bounds
const TICK: Rgb565 = Rgb565::new(16, 32, 16); // grey: interior rulers
const LABEL: Rgb565 = Rgb565::new(31, 63, 31);
const LEFT_MARK: Rgb565 = Rgb565::new(31, 0, 0); // red band, column 0
const RIGHT_MARK: Rgb565 = Rgb565::new(0, 63, 0); // green band, last column
const TOP_MARK: Rgb565 = Rgb565::new(0, 0, 31); // blue band, row 0
const BOTTOM_MARK: Rgb565 = Rgb565::new(31, 63, 0); // yellow band, last row

fn fill<D: DrawTarget<Color = Rgb565>>(d: &mut D, x: i32, y: i32, w: i32, h: i32, c: Rgb565) {
    if w <= 0 || h <= 0 {
        return;
    }
    let _ = d.fill_solid(
        &Rectangle::new(Point::new(x, y), Size::new(w as u32, h as u32)),
        c,
    );
}

fn label<D: DrawTarget<Color = Rgb565>>(
    d: &mut D,
    s: &str,
    x: i32,
    y: i32,
    align: Alignment,
    big: bool,
) {
    let style = if big {
        MonoTextStyle::new(&FONT_10X20, LABEL)
    } else {
        MonoTextStyle::new(&FONT_6X10, LABEL)
    };
    let _ = Text::with_alignment(s, Point::new(x, y), style, align).draw(d);
}

/// Draw the calibration frame for a `w` x `h` framebuffer.
///
/// Everything is placed from the framebuffer's own extremes, so the picture is self-proving:
/// if the operator can read `0` at the left and `w-1` at the right, and sees all four
/// coloured bands, then the visible window IS the buffer and the defect is above this layer.
/// If the far edge is missing, the number that IS readable at the edge states how much of
/// each line reaches the glass.
pub fn calibration<D: DrawTarget<Color = Rgb565>>(d: &mut D, w: i32, h: i32) {
    fill(d, 0, 0, w, h, BG);

    // Edge bands, 16 px, inset past the border so a band and the border are distinguishable.
    // These answer the four yes/no questions before any number has to be read.
    fill(d, 4, 4, 16, h - 8, LEFT_MARK);
    fill(d, w - 20, 4, 16, h - 8, RIGHT_MARK);
    fill(d, 4, 4, w - 8, 16, TOP_MARK);
    fill(d, 4, h - 20, w - 8, 16, BOTTOM_MARK);

    // The bounds themselves: 4 px, drawn AT 0 and at w-4 / h-4.
    fill(d, 0, 0, w, 4, EDGE);
    fill(d, 0, h - 4, w, 4, EDGE);
    fill(d, 0, 0, 4, h, EDGE);
    fill(d, w - 4, 0, 4, h, EDGE);

    // Horizontal ruler: a tick and its x-coordinate every STEP, plus one final tick on the
    // last addressable column. The label is what gets read back.
    let mut x = 0;
    while x < w {
        fill(d, x, 24, 1, 28, TICK);
        label(d, &itoa(x), x + 3, 60, Alignment::Left, false);
        x += STEP;
    }
    fill(d, w - 1, 24, 1, 28, EDGE);
    label(d, &itoa(w - 1), w - 6, 74, Alignment::Right, false);

    // Vertical ruler down the left, clear of the red band.
    let mut y = 0;
    while y < h {
        fill(d, 24, y, 28, 1, TICK);
        label(d, &itoa(y), 56, y + 4, Alignment::Left, false);
        y += STEP;
    }
    fill(d, 24, h - 1, 28, 1, EDGE);

    // Corners, named. A crop shows up as a missing corner before any ruler is consulted.
    label(d, "TL", 26, 90, Alignment::Left, true);
    label(d, "TR", w - 26, 90, Alignment::Right, true);
    label(d, "BL", 26, h - 30, Alignment::Left, true);
    label(d, "BR", w - 26, h - 30, Alignment::Right, true);

    // Centre crosshair and its stated coordinate: if the buffer's centre is not the glass's
    // centre, the offset between them is the whole answer.
    let (cx, cy) = (w / 2, h / 2);
    fill(d, cx - 40, cy, 81, 1, EDGE);
    fill(d, cx, cy - 40, 1, 81, EDGE);
    label(d, &format!("{w}x{h}"), cx, cy - 52, Alignment::Center, true);
    label(d, "CENTER", cx, cy + 68, Alignment::Center, true);
}

fn itoa(n: i32) -> String {
    format!("{n}")
}

/// Put the calibration frame on the glass and keep it there for the rest of the power
/// cycle. This is the whole instrument: `main` calls it and nothing else changes.
///
/// The backlight comes up HERE rather than at the caller because the panel is dark until
/// something says otherwise, and the measurement is worthless if the operator has to take
/// the firmware's word for what was drawn before the light arrived.
///
/// It never returns, but it is typed `()` on purpose. A `!` here would make every line of
/// the product boot below the call site unreachable, which is true but would force a lint
/// attribute onto shared code for the sake of an off-by-default instrument.
pub fn run(display: &mut Display) {
    calibration(
        display,
        crate::board::DISPLAY_WIDTH as i32,
        crate::board::DISPLAY_HEIGHT as i32,
    );
    display.flush().expect("calibration frame flush");
    crate::board::backlight_set(crate::BACKLIGHT_PERCENT);
    log::warn!(
        "diag-display build: calibration frame held, product UI never runs (src/diag.rs)"
    );
    loop {
        // The frame is static; this line exists so a serial log proves the device is alive
        // and holding it, and says what to read off the glass.
        log::info!(
            "calibration: {}x{} held - the ruler labels at the edges should read 0 and {}",
            crate::board::DISPLAY_WIDTH,
            crate::board::DISPLAY_HEIGHT,
            crate::board::DISPLAY_WIDTH - 1
        );
        thread::sleep(Duration::from_secs(10));
    }
}
