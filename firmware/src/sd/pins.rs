// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Which GPIOs the microSD slot is on, per board, and the compile-time proof that they are
//! not the ESP32-C6's.
//!
//! # Why this table is here and not in `board/<name>.rs`
//!
//! MILESTONES.md m5 puts `sd_init()` / `sd_deinit()` on the board surface, and that is
//! where they belong. This workstream's fence does not extend to `src/board/`, so the
//! table lives beside the only code that reads it and the move is a follow-up. Nothing
//! else in the tree names these numbers, so there is exactly one definition either way.
//!
//! # SECURITY.md invariant 1, made a compile error
//!
//! Invariant 1 says the SDIO host is never configured on the C6's pins, per board and with
//! the numbers written out. MILESTONES.md R16 checked that m5 does not break it and left
//! the re-assertion to this milestone, explicitly so that "a future board that overlaps
//! forces an honest amendment instead of a silent one". A sentence in a document cannot do
//! that. The [`const _: ()`] assertions below can: a board whose microSD wiring collides
//! with its own radio module stops building, and the message names the invariant.
//!
//! The numbers reach the driver from this same table, so the assertion is about the
//! configuration that actually runs, not about a second copy that could drift from it, and
//! [`note`] prints them at every mount so the running configuration is also on the record.

/// `GPIO_NUM_NC`: a line this board does not route.
pub const NC: i32 = -1;

/// One board's microSD wiring.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Slot {
    /// SDMMC peripheral slot index handed to the driver.
    pub index: i32,
    /// Data lines actually wired: 1 or 4. Never 8 - see the assertion below.
    pub width: u8,
    /// `[clk, cmd, d0, d1, d2, d3]`, with [`NC`] for anything this board does not route.
    /// One array rather than six fields because the airgap cross-check iterates it, and a
    /// pin that is not in the array the check reads is a pin the check does not cover.
    pub pins: [i32; 6],
    /// The microSD power gate, if the board has one. Documented, never driven: on the
    /// Waveshare 4B it is a P-FET with a pulldown, so the card is powered from reset and
    /// the vendor BSP never touches the line either (docs/HARDWARE.md). Driving it would
    /// be a change with no evidence behind it, on the one rail whose failure mode is a
    /// card that browns out mid-write.
    pub power_gate: i32,
}

impl Slot {
    pub const fn clk(&self) -> i32 {
        self.pins[0]
    }
    pub const fn cmd(&self) -> i32 {
        self.pins[1]
    }
    pub const fn d0(&self) -> i32 {
        self.pins[2]
    }
    pub const fn d1(&self) -> i32 {
        self.pins[3]
    }
    pub const fn d2(&self) -> i32 {
        self.pins[4]
    }
    pub const fn d3(&self) -> i32 {
        self.pins[5]
    }
}

#[cfg(feature = "board-waveshare-4b")]
mod board {
    use super::Slot;

    /// docs/HARDWARE.md: "microSD (SDMMC slot 0, 4-bit) D0-D3 / CLK / CMD | 39-42 / 43 /
    /// 44" and "microSD power gate (P-FET, pulldown = default ON) | 45". These are also
    /// the ESP32-P4's own `SDMMC_SLOT_CONFIG_DEFAULT` pins, which is not a coincidence -
    /// the board follows the reference pinout - but they are written out here rather than
    /// inherited, because the default is a property of the chip and the wiring is a
    /// property of the board.
    pub const SLOT: Option<Slot> = Some(Slot {
        index: 0,
        width: 4,
        pins: [43, 44, 39, 40, 41, 42],
        power_gate: 45,
    });

    /// docs/BOARDS.md, "C6 SDIO pins (never configured)": 18/19/14-17.
    pub const C6_SDIO: &[i32] = &[18, 19, 14, 15, 16, 17];

    pub const SOURCE: &str = "docs/HARDWARE.md (schematic-verified)";
}

#[cfg(feature = "board-elecrow-5")]
mod board {
    use super::{Slot, NC};

    /// MILESTONES.md m5: "board B uses 1-bit on GPIO39/43/44". One data line, and that is
    /// the board rather than a conservative choice: GPIO40 and GPIO41 are the RGB panel's
    /// HSYNC and VSYNC and GPIO42 is the GT911 touch interrupt (src/board/elecrow_5.rs),
    /// so a four-bit configuration on this board would take the display and the
    /// touchscreen down with it.
    pub const SLOT: Option<Slot> = Some(Slot {
        index: 0,
        width: 1,
        pins: [43, 44, 39, NC, NC, NC],
        power_gate: NC,
    });

    /// docs/BOARDS.md, "C6 SDIO pins (never configured)": 53/54/49-52. The same set the
    /// board module's `RADIO_KILL_DOC` names as GPIO49-54.
    pub const C6_SDIO: &[i32] = &[53, 54, 49, 50, 51, 52];

    pub const SOURCE: &str = "MILESTONES.md 0.2.0-m5 and docs/BOARDS.md";
}

// Every other board is an UNTESTED scaffold (docs/BOARDS.md) whose microSD wiring has
// never been read off a schematic here. `None` is the honest value: the subsystem refuses
// to mount and says why, rather than driving six GPIOs picked by analogy with a board that
// happens to share a chip.
#[cfg(not(any(feature = "board-waveshare-4b", feature = "board-elecrow-5")))]
mod board {
    use super::Slot;

    pub const SLOT: Option<Slot> = None;
    pub const C6_SDIO: &[i32] = &[];
    pub const SOURCE: &str = "no verified microSD wiring for this board";
}

pub use board::{C6_SDIO, SLOT, SOURCE};

/// True if no routed pin in `a` also appears in `b`.
///
/// A `const fn` because the answer has to be available to `const _: ()` below; a runtime
/// check would report the collision to a log on a device that had already configured the
/// pads.
const fn disjoint(a: &[i32], b: &[i32]) -> bool {
    let mut i = 0;
    while i < a.len() {
        if a[i] != NC {
            let mut j = 0;
            while j < b.len() {
                if a[i] == b[j] {
                    return false;
                }
                j += 1;
            }
        }
        i += 1;
    }
    true
}

/// True if no routed pin appears twice in `pins`.
const fn distinct(pins: &[i32]) -> bool {
    let mut i = 0;
    while i < pins.len() {
        if pins[i] != NC {
            let mut j = i + 1;
            while j < pins.len() {
                if pins[i] == pins[j] {
                    return false;
                }
                j += 1;
            }
        }
        i += 1;
    }
    true
}

/// SECURITY.md invariant 1 and MILESTONES.md R16. This is the milestone with the only
/// plausible way to break it, and this is the assertion that makes breaking it a build
/// failure rather than a discovery.
const _: () = assert!(
    match SLOT {
        Some(slot) => disjoint(&slot.pins, C6_SDIO),
        None => true,
    },
    "SECURITY.md invariant 1: this board's microSD pins overlap its ESP32-C6 SDIO pins. \
     Configuring the SDMMC host would bring up a bus the radio module is also on. Fix the \
     wiring table, or amend invariant 1 honestly - do not delete this assertion."
);

/// Two lines shorted together is a wiring-table typo, and it is one the driver reports as
/// a card that does not answer, which is the hardest kind of fault to find on a bench.
const _: () = assert!(
    match SLOT {
        Some(slot) => distinct(&slot.pins),
        None => true,
    },
    "microSD wiring table names the same GPIO twice"
);

/// Eight-bit is not merely unused, it is unsafe on the Waveshare 4B: the ESP32-P4's default
/// `d4` line is GPIO45, which on that board is the microSD power gate. An eight-bit
/// configuration would drive the card's own supply as a data line.
const _: () = assert!(
    match SLOT {
        Some(slot) => slot.width == 1 || slot.width == 4,
        None => true,
    },
    "microSD bus width must be 1 or 4; 8-bit collides with the power gate on GPIO45"
);

/// The power gate is a rail, not a bus line.
const _: () = assert!(
    match SLOT {
        Some(slot) => slot.power_gate == NC || disjoint(&[slot.power_gate], &slot.pins),
        None => true,
    },
    "the microSD power gate is also listed as a bus line"
);

/// One line naming every pin this build will hand to the SDMMC driver, and every pin it
/// promises never to.
///
/// Logged at each mount, so the airgap cross-check appears against the RUNNING
/// configuration and not only against the source. Also the string the Verify screen can
/// show once m5's rows land there.
pub fn note() -> String {
    let Some(slot) = SLOT else {
        return format!("microSD: no slot configured for this board ({SOURCE})");
    };
    let mut lines = String::new();
    for (label, pin) in [
        ("clk", slot.clk()),
        ("cmd", slot.cmd()),
        ("d0", slot.d0()),
        ("d1", slot.d1()),
        ("d2", slot.d2()),
        ("d3", slot.d3()),
    ] {
        if pin != NC {
            if !lines.is_empty() {
                lines.push(' ');
            }
            lines.push_str(&format!("{label}=GPIO{pin}"));
        }
    }
    let c6 = C6_SDIO
        .iter()
        .map(|p| format!("GPIO{p}"))
        .collect::<Vec<_>>()
        .join("/");
    format!(
        "microSD: slot {} {}-bit, {lines} ({SOURCE}); C6 SDIO {} never configured; \
         disjoint (SECURITY invariant 1, R16)",
        slot.index,
        slot.width,
        if c6.is_empty() { "n/a" } else { &c6 },
    )
}
