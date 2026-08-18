//! Board selection: exactly one `board-*` cargo feature, resolved at compile
//! time (docs/BOARDS.md). No runtime board detection, no probing - the build
//! IS the board. Every board module exports the same flat surface of consts
//! and free functions; conformance is enforced by the call sites in main.rs
//! (a missing item is a compile error for every build of that board).
//!
//! Surface (names normative, see BOARDS.md):
//!   BOARD_NAME, DISPLAY_WIDTH, DISPLAY_HEIGHT, FLASH_SIZE_MB,
//!   RADIO_KILL_GPIO, RADIO_KILL_DOC, UNTESTED,
//!   radio_lockdown(), display_init(), backlight_set(), touch_init()

#[cfg(not(any(
    feature = "board-waveshare-4b",
    feature = "board-waveshare-5",
    feature = "board-waveshare-7b",
    feature = "board-waveshare-7x",
    feature = "board-waveshare-8x",
    feature = "board-waveshare-101x",
    feature = "board-elecrow-5",
    feature = "board-elecrow-7",
    feature = "board-elecrow-9",
    feature = "board-elecrow-101",
)))]
compile_error!(
    "select exactly one board feature: board-waveshare-4b | board-waveshare-5 | \
     board-waveshare-7b | board-waveshare-7x | board-waveshare-8x | board-waveshare-101x | \
     board-elecrow-5 | board-elecrow-7 | board-elecrow-9 | board-elecrow-101 \
     (use tools/build.ps1 -Board <name>)"
);

// Mutual exclusion: two boards cannot both be the build target. Counted
// instead of listed pairwise (the pair list grows O(n^2) with the board
// roster); cfg! expands to a bool literal, so this is a compile-time check.
const ENABLED_BOARD_FEATURES: u32 = cfg!(feature = "board-waveshare-4b") as u32
    + cfg!(feature = "board-waveshare-5") as u32
    + cfg!(feature = "board-waveshare-7b") as u32
    + cfg!(feature = "board-waveshare-7x") as u32
    + cfg!(feature = "board-waveshare-8x") as u32
    + cfg!(feature = "board-waveshare-101x") as u32
    + cfg!(feature = "board-elecrow-5") as u32
    + cfg!(feature = "board-elecrow-7") as u32
    + cfg!(feature = "board-elecrow-9") as u32
    + cfg!(feature = "board-elecrow-101") as u32;
const _: () = assert!(
    ENABLED_BOARD_FEATURES <= 1,
    "board features are mutually exclusive; enable exactly one"
);

/// Claim a GPIO as push-pull output driven to `level`. Panics on failure -
/// every caller is boot-critical (radio kill line, backlight power) where
/// proceeding in an unknown pin state is worse than a visible abort.
/// Note gpio_config enables the output with the output register still at its
/// reset value (0), so claiming a pin low never glitches high.
/// INPUT_OUTPUT, not OUTPUT: the input buffer stays enabled so the Verify
/// screen's radio readback (gpio_get_level on the kill line) reports the
/// ACTUAL pad level - an input-disabled pad reads as a constant 0, which
/// would fake exactly the value the screen exists to prove.
pub(crate) fn claim_output(gpio: i32, level: u32) {
    use esp_idf_svc::sys;
    let config = sys::gpio_config_t {
        pin_bit_mask: 1u64 << gpio,
        mode: sys::gpio_mode_t_GPIO_MODE_INPUT_OUTPUT,
        ..Default::default()
    };
    let err = unsafe { sys::gpio_config(&config) };
    assert!(err == sys::ESP_OK, "gpio_config(GPIO{gpio}) failed: 0x{err:x}");
    let err = unsafe { sys::gpio_set_level(gpio, level) };
    assert!(err == sys::ESP_OK, "gpio_set_level(GPIO{gpio}) failed: 0x{err:x}");
}

#[cfg(feature = "board-waveshare-4b")]
mod waveshare_4b;
#[cfg(feature = "board-waveshare-4b")]
pub use waveshare_4b::*;

// The Waveshare Touch-LCD DSI siblings of the 4B share the family-invariant
// circuits (GPIO54 radio kill with no C6 EN pullup, GT911 on I2C 7/8 with
// RST/INT unrouted, LEDC backlight on low-speed timer 1 / channel 1) but
// differ per board in panel driver, DSI rate/timing, and backlight pin and
// polarity - so each board is its own module over shared bring-up helpers
// in waveshare_common.rs. All are UNTESTED scaffolds (docs/BOARDS.md).
#[cfg(any(
    feature = "board-waveshare-5",
    feature = "board-waveshare-7b",
    feature = "board-waveshare-7x",
    feature = "board-waveshare-8x",
    feature = "board-waveshare-101x",
))]
mod waveshare_common;

#[cfg(feature = "board-waveshare-5")]
mod waveshare_5;
#[cfg(feature = "board-waveshare-5")]
pub use waveshare_5::*;

#[cfg(feature = "board-waveshare-7b")]
mod waveshare_7b;
#[cfg(feature = "board-waveshare-7b")]
pub use waveshare_7b::*;

// The Touch-LCD-7 / -8 / -10.1 "X" series share one PCB (one schematic, one
// BSP), but unlike the Elecrow DSI trio they are NOT electrically identical
// where it counts for bring-up: the panel differs per size (7: 720x1280
// ILI9881C at 1000 Mbps/lane; 8 and 10.1: 800x1280 JD9365 at 1500 Mbps/lane
// with DIFFERENT init command tables per size). So no shared-module-plus-
// name-wrappers here - each size is its own module over waveshare_common.
#[cfg(feature = "board-waveshare-7x")]
mod waveshare_7x;
#[cfg(feature = "board-waveshare-7x")]
pub use waveshare_7x::*;

#[cfg(feature = "board-waveshare-8x")]
mod waveshare_8x;
#[cfg(feature = "board-waveshare-8x")]
pub use waveshare_8x::*;

#[cfg(feature = "board-waveshare-101x")]
mod waveshare_101x;
#[cfg(feature = "board-waveshare-101x")]
pub use waveshare_101x::*;

#[cfg(feature = "board-elecrow-5")]
mod elecrow_5;
#[cfg(feature = "board-elecrow-5")]
pub use elecrow_5::*;

// The 7/9/10.1 inch CrowPanel Advanced siblings share one electrical design
// (verified against each board's own V1.0 Eagle schematic and factory
// sdkconfig - see docs/BOARDS.md); the shared implementation lives in
// elecrow_dsi.rs and each board module only adds its BOARD_NAME.
#[cfg(any(
    feature = "board-elecrow-7",
    feature = "board-elecrow-9",
    feature = "board-elecrow-101",
))]
mod elecrow_dsi;

#[cfg(feature = "board-elecrow-7")]
mod elecrow_7;
#[cfg(feature = "board-elecrow-7")]
pub use elecrow_7::*;

#[cfg(feature = "board-elecrow-9")]
mod elecrow_9;
#[cfg(feature = "board-elecrow-9")]
pub use elecrow_9::*;

#[cfg(feature = "board-elecrow-101")]
mod elecrow_101;
#[cfg(feature = "board-elecrow-101")]
pub use elecrow_101::*;
