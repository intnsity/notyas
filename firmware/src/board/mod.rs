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
    feature = "board-elecrow-5",
    feature = "board-elecrow-7",
    feature = "board-elecrow-9",
    feature = "board-elecrow-101",
)))]
compile_error!(
    "select exactly one board feature: board-waveshare-4b | board-elecrow-5 | \
     board-elecrow-7 | board-elecrow-9 | board-elecrow-101 (use tools/build.ps1 -Board <name>)"
);

// Mutual exclusion, pairwise: two boards cannot both be the build target.
#[cfg(any(
    all(feature = "board-waveshare-4b", feature = "board-elecrow-5"),
    all(feature = "board-waveshare-4b", feature = "board-elecrow-7"),
    all(feature = "board-waveshare-4b", feature = "board-elecrow-9"),
    all(feature = "board-waveshare-4b", feature = "board-elecrow-101"),
    all(feature = "board-elecrow-5", feature = "board-elecrow-7"),
    all(feature = "board-elecrow-5", feature = "board-elecrow-9"),
    all(feature = "board-elecrow-5", feature = "board-elecrow-101"),
    all(feature = "board-elecrow-7", feature = "board-elecrow-9"),
    all(feature = "board-elecrow-7", feature = "board-elecrow-101"),
    all(feature = "board-elecrow-9", feature = "board-elecrow-101"),
))]
compile_error!("board features are mutually exclusive; enable exactly one");

/// Claim a GPIO as push-pull output driven to `level`. Panics on failure -
/// every caller is boot-critical (radio kill line, backlight power) where
/// proceeding in an unknown pin state is worse than a visible abort.
/// Note gpio_config enables the output with the output register still at its
/// reset value (0), so claiming a pin low never glitches high.
pub(crate) fn claim_output(gpio: i32, level: u32) {
    use esp_idf_svc::sys;
    let config = sys::gpio_config_t {
        pin_bit_mask: 1u64 << gpio,
        mode: sys::gpio_mode_t_GPIO_MODE_OUTPUT,
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
