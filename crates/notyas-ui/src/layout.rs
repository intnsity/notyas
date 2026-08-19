// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Geometry primitives and the display-derived spacing grid.
//!
//! Every screen computes its rectangles from [`Metrics`], which is itself computed from
//! the display size handed to `Ui::new` - there are no absolute pixel positions anywhere
//! in the crate, so a different panel (the tests exercise 800x480 next to the primary
//! 720x720) reflows instead of breaking. Where a dimension has a hard floor it is a floor
//! in physical pixels (touch targets), because fingers do not scale with the panel.

use embedded_graphics::geometry::{Point, Size};
use embedded_graphics::primitives::Rectangle;

/// An integer rectangle. Thin on purpose: signed math for layout (scroll offsets go
/// negative), converted to embedded-graphics' `Rectangle` only at the drawing boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

impl Rect {
    pub const fn new(x: i32, y: i32, w: i32, h: i32) -> Self {
        Rect { x, y, w, h }
    }

    pub fn contains(&self, x: i32, y: i32) -> bool {
        x >= self.x && x < self.x + self.w && y >= self.y && y < self.y + self.h
    }

    pub fn right(&self) -> i32 {
        self.x + self.w
    }

    pub fn bottom(&self) -> i32 {
        self.y + self.h
    }

    /// Shrink by `d` on every side.
    pub fn inset(&self, d: i32) -> Rect {
        Rect::new(self.x + d, self.y + d, self.w - 2 * d, self.h - 2 * d)
    }

    pub fn translated(&self, dx: i32, dy: i32) -> Rect {
        Rect::new(self.x + dx, self.y + dy, self.w, self.h)
    }

    pub fn overlaps(&self, other: &Rect) -> bool {
        self.x < other.right()
            && other.x < self.right()
            && self.y < other.bottom()
            && other.y < self.bottom()
    }

    pub fn to_eg(&self) -> Rectangle {
        Rectangle::new(
            Point::new(self.x, self.y),
            Size::new(self.w.max(0) as u32, self.h.max(0) as u32),
        )
    }
}

/// Every distinct panel geometry the firmware ships, as `(width, height)`.
///
/// The single list. `firmware/src/board/*.rs` selects one of these per board feature -
/// ten features, five distinct panels - and a screen that lays out on two of them is not
/// a screen that lays out. This crate cannot depend on the firmware crate (different
/// target, different toolchain), so the two lists are married by a drift test in
/// tools/uisim, which parses the board files and asserts the distinct set equals this
/// array. Add a panel here and to the board file in the same commit; the test fails if
/// only one of the two happens.
pub const PANELS: [(u32, u32); 5] =
    [(720, 720), (800, 480), (720, 1280), (800, 1280), (1024, 600)];

/// Minimum edge of any interactive region in px (UX-SCREENS.md 0.3, commandment 7).
///
/// The single audited exception is an on-screen keyboard key, which keeps its own 40 px
/// floor: a letter key is a self-correcting target - a wrong one is visible and one
/// backspace away - and a Sign button is not.
pub const TOUCH_MIN: i32 = 60;

/// Minimum edge of a keypad key (dice, PIN) in px. On the primary 720x720 panel
/// (229 PPI) this is about 8.9 mm, comfortably above the ~7 mm ergonomic floor; the
/// layout tests assert it holds on every supported geometry.
pub const KEYPAD_KEY_MIN: i32 = 80;

/// The 0.1.0 name for [`KEYPAD_KEY_MIN`], kept so the layout tests written against the
/// dice pad keep reading as they did. One floor, two names, no second constant.
pub const DICE_KEY_MIN: i32 = KEYPAD_KEY_MIN;

/// List and card row height floor in px: a row is a wide target, so height is the
/// constraint that decides whether it can be hit.
pub const LIST_ROW_MIN: i32 = 88;

/// Minimum clear space in px between a destructive confirm and its cancel, so the two
/// cannot be confused by a finger that lands between them.
pub const SEPARATION_MIN: i32 = 96;

/// The spacing grid, derived once from the display size.
#[derive(Debug, Clone, Copy)]
pub struct Metrics {
    pub w: i32,
    pub h: i32,
    /// Outer page padding: ~1/30 of the width, clamped so small panels keep breathing
    /// room and large ones do not waste it.
    pub pad: i32,
    /// Gap between sibling elements.
    pub gap: i32,
    /// Standard button height; the floor keeps buttons tappable on short panels.
    pub btn: i32,
    /// Top-bar height on the non-home screens.
    pub bar: i32,
}

impl Metrics {
    pub fn new(w: u32, h: u32) -> Self {
        let w = w as i32;
        let h = h as i32;
        let pad = (w / 30).clamp(16, 32);
        let gap = (pad / 2).max(8);
        let btn = (h / 9).clamp(64, 88);
        Metrics { w, h, pad, gap, btn, bar: btn }
    }

    /// The whole display.
    pub fn screen(&self) -> Rect {
        Rect::new(0, 0, self.w, self.h)
    }

    /// Page content area (screen minus outer padding).
    pub fn content(&self) -> Rect {
        self.screen().inset(self.pad)
    }

    /// Content area below the top bar of a non-home screen.
    pub fn body(&self) -> Rect {
        let c = self.content();
        Rect::new(c.x, self.bar + self.gap, c.w, self.h - self.pad - (self.bar + self.gap))
    }

    /// True when the panel is wide enough that stacked portrait layouts would starve the
    /// keypad: the dice screen then splits into an info column and a keypad column.
    pub fn landscape(&self) -> bool {
        self.w * 4 >= self.h * 5
    }
}
