//! UNTESTED BOARD CONFIG - compile-checked scaffold, never run on hardware.
//! Board: Waveshare ESP32-P4-WIFI6-Touch-LCD-7B (1024x600 7inch MIPI-DSI,
//! EK79007). Landscape panel, same aspect class as the verified Elecrow 5.
//!
//! Sources beyond the family-invariant facts in waveshare_common.rs:
//! - docs/research/waveshare-family.md section 5 (schematic-verified): kill
//!   GPIO54 -> R33 0R -> C6 CHIP_PU, no EN pullup; EK79007 2-lane DSI at
//!   1000 Mbps; GT911; 32 MB flash (GD25Q256EYIGR); CH343P. The schematic's
//!   C6 block is annotated "optional" - a C6-unpopulated variant may exist
//!   (airgap only improves if so).
//! - BSP bsp/esp32_p4_wifi6_touch_lcd_7b v3.0.0 (Waveshare-ESP32-components
//!   @ be0e5e4, re-fetched 2026-08-17): the family's odd pins - LCD RESET =
//!   GPIO33, backlight = LEDC PWM GPIO32 with output_invert = 1 (both
//!   flipped vs the 4B/5/X siblings' 27/26); touch RST/INT = NC; panel init
//!   via the EK79007 driver's built-in table (no init_cmds).
//! - DPI timing = EK79007_1024_600_PANEL_60HZ_CONFIG from
//!   espressif/esp_lcd_ek79007 (function-like macro, replicated verbatim
//!   below; values verified identical in v1.0.4 and v2.0.2 - the 2.x line
//!   only adds IDF6 compatibility per its CHANGELOG, so the ^1 pin the
//!   Elecrow DSI boards already use serves this board too; the 7B BSP pins
//!   ^2.0.2). Note these differ from the Elecrow siblings' factory values
//!   for the same controller (52 vs 51 MHz, HPW 10 vs 70, VPW 1 vs 10):
//!   each vendor's own numbers are used for each vendor's panel.

use core::ffi::c_void;

use esp_idf_svc::sys;

use crate::board::waveshare_common as common;
use crate::display::{esp_check, Display, DisplayError};
use crate::touch::Touch;

pub const BOARD_NAME: &str = "Waveshare ESP32-P4-WIFI6-Touch-LCD-7B (UNTESTED)";
pub const DISPLAY_WIDTH: u32 = 1024;
pub const DISPLAY_HEIGHT: u32 = 600;
pub const FLASH_SIZE_MB: u32 = 32;
pub const UNTESTED: bool = true;

pub const RADIO_KILL_GPIO: i32 = common::RADIO_KILL_GPIO;
pub const RADIO_KILL_DOC: &str = "GPIO54 -> ESP32-C6 CHIP_PU (EN) via R33, driven low first \
     thing in app_main and never released: the only radio is hardware-held in reset for the \
     whole power cycle. C6 EN carries NO pullup (schematic-verified), so the radio is also \
     held down from power-on - no boot window exists. No WiFi stack in the build; C6 SDIO \
     host pins (GPIO14-19) never configured. UNTESTED BOARD CONFIG.";

// BSP display.h: 2-lane DSI at 1000 Mbps; DPI clock from the EK79007 macro.
const DSI_LANE_BIT_RATE_MBPS: f32 = 1000.0;
const DPI_CLOCK_FREQ_MHZ: f32 = 52.0;

// BSP esp32_p4_wifi6_touch_lcd_7b.h: BSP_LCD_BACKLIGHT / BSP_LCD_RST - the
// 7B's odd pins (GPIO32/GPIO33 where every sibling uses GPIO26/GPIO27).
const GPIO_BACKLIGHT_PWM: i32 = 32;
const GPIO_LCD_RESET: i32 = 33;

/// AIRGAP LOCKDOWN - first call in app_main, held forever.
pub fn radio_lockdown() {
    common::radio_lockdown_gpio54();
}

pub fn display_init() -> Display {
    try_display_init().unwrap_or_else(|e| panic!("display init: {e}"))
}

fn try_display_init() -> Result<Display, DisplayError> {
    // Backlight LEDC claimed at duty 0 so the panel stays dark until the
    // first real frame (same invariant as the verified boards).
    common::backlight_pwm_init(GPIO_BACKLIGHT_PWM, true)?;

    let (dsi_bus, io) = common::dsi_bus_and_dbi_io(DSI_LANE_BIT_RATE_MBPS)?;

    // EK79007_1024_600_PANEL_60HZ_CONFIG, RGB565 (values verbatim).
    let mut dpi_config = sys::esp_lcd_dpi_panel_config_t {
        dpi_clk_src: sys::soc_periph_mipi_dsi_dpi_clk_src_t_MIPI_DSI_DPI_CLK_SRC_DEFAULT,
        dpi_clock_freq_mhz: DPI_CLOCK_FREQ_MHZ,
        virtual_channel: 0,
        pixel_format: sys::lcd_color_rgb_pixel_format_t_LCD_COLOR_PIXEL_FORMAT_RGB565,
        num_fbs: 1,
        video_timing: sys::esp_lcd_video_timing_t {
            h_size: DISPLAY_WIDTH,
            v_size: DISPLAY_HEIGHT,
            hsync_back_porch: 160,
            hsync_pulse_width: 10,
            hsync_front_porch: 160,
            vsync_back_porch: 23,
            vsync_pulse_width: 1,
            vsync_front_porch: 12,
        },
        ..Default::default()
    };
    dpi_config.flags.set_use_dma2d(1);

    let mut vendor_config = sys::ek79007_vendor_config_t::default();
    vendor_config.mipi_config.dsi_bus = dsi_bus;
    vendor_config.mipi_config.dpi_config = &dpi_config;

    let mut panel_config = sys::esp_lcd_panel_dev_config_t {
        reset_gpio_num: GPIO_LCD_RESET,
        bits_per_pixel: 16,
        vendor_config: &mut vendor_config as *mut _ as *mut c_void,
        ..Default::default()
    };
    panel_config.__bindgen_anon_1.rgb_ele_order =
        sys::lcd_rgb_element_order_t_LCD_RGB_ELEMENT_ORDER_RGB;

    let mut panel: sys::esp_lcd_panel_handle_t = core::ptr::null_mut();
    esp_check!(
        sys::esp_lcd_new_panel_ek79007(io, &panel_config, &mut panel),
        "esp_lcd_new_panel_ek79007"
    );
    esp_check!(sys::esp_lcd_panel_reset(panel), "esp_lcd_panel_reset");
    esp_check!(sys::esp_lcd_panel_init(panel), "esp_lcd_panel_init");
    log::info!("EK79007 panel initialized (1024x600 RGB565, DPI {DPI_CLOCK_FREQ_MHZ} MHz)");

    common::display_over_dpi_fb(panel, DISPLAY_WIDTH, DISPLAY_HEIGHT)
}

/// Backlight: direct LEDC PWM on GPIO32, INVERTED output (BSP
/// bsp_display_brightness_init sets output_invert = 1 on this board; duty N
/// of 1023 still means N/1023 brightness because of the invert flag).
pub fn backlight_set(percent: u8) {
    common::backlight_set_duty(percent).unwrap_or_else(|e| panic!("backlight: {e}"))
}

pub fn touch_init() -> Touch {
    common::touch_init_probed(DISPLAY_WIDTH, DISPLAY_HEIGHT)
        .unwrap_or_else(|e| panic!("touch init: {e}"))
}
