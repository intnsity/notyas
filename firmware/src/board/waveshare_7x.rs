//! UNTESTED BOARD CONFIG - compile-checked scaffold, never run on hardware.
//! Board: Waveshare ESP32-P4-WIFI6-Touch-LCD-7 (720x1280 7inch MIPI-DSI,
//! ILI9881C; "X" series shared PCB). PORTRAIT panel - see the boot warning
//! in radio_lockdown.
//!
//! Sources beyond the family-invariant facts in waveshare_common.rs:
//! - docs/research/waveshare-family.md section 6 (schematic-verified): one
//!   X-series schematic for 7/8/10.1; kill GPIO54 -> R54 0R -> C6 CHIP_PU
//!   (C6-MINI-1U-H8 like the 4B), no EN pullup; 7 inch panel = ILI9881C,
//!   2-lane DSI at 1000 Mbps; GT911; 32 MB flash (GD25Q256EYIGR); CH343P.
//! - BSP bsp/esp32_p4_wifi6_touch_lcd_x v2.0.2 (Waveshare-ESP32-components
//!   @ be0e5e4, re-fetched 2026-08-17), CONFIG_BSP_LCD_TYPE_720_1280_7_INCH
//!   branch: LCD RESET GPIO27, backlight LEDC PWM GPIO26 (non-inverted),
//!   touch RST/INT = NC; explicit DPI config 80 MHz, HBP 239 / HPW 50 /
//!   HFP 33, VBP 20 / VPW 30 / VFP 2 (this branch does NOT set use_dma2d -
//!   replicated as-is); esp_lcd_panel_disp_on_off(true) after init.
//! - Panel init commands: the BSP passes an explicit 197-entry table which
//!   was verified entry-for-entry IDENTICAL (2026-08-17) to the built-in
//!   default of waveshare/esp_lcd_ili9881c v2.0.0 (the BSP's own component
//!   pin) - so this module lets the driver use its default table instead of
//!   replicating 197 commands.

use core::ffi::c_void;

use esp_idf_svc::sys;

use crate::board::waveshare_common as common;
use crate::display::{esp_check, Display, DisplayError};
use crate::touch::Touch;

pub const BOARD_NAME: &str = "Waveshare ESP32-P4-WIFI6-Touch-LCD-7 (UNTESTED)";
pub const DISPLAY_WIDTH: u32 = 720;
pub const DISPLAY_HEIGHT: u32 = 1280;
pub const FLASH_SIZE_MB: u32 = 32;
pub const UNTESTED: bool = true;

pub const RADIO_KILL_GPIO: i32 = common::RADIO_KILL_GPIO;
pub const RADIO_KILL_DOC: &str = "GPIO54 -> ESP32-C6 CHIP_PU (EN) via R54, driven low first \
     thing in app_main and never released: the only radio is hardware-held in reset for the \
     whole power cycle. C6 EN carries NO pullup (schematic-verified), so the radio is also \
     held down from power-on - no boot window exists. No WiFi stack in the build; C6 SDIO \
     host pins (GPIO14-19) never configured. UNTESTED BOARD CONFIG.";

// X BSP display.h (7 inch branch) + the BSP's explicit 7-inch dpi_config.
const DSI_LANE_BIT_RATE_MBPS: f32 = 1000.0;
const DPI_CLOCK_FREQ_MHZ: f32 = 80.0;

// X BSP esp32_p4_wifi6_touch_lcd_x.h: BSP_LCD_BACKLIGHT / BSP_LCD_RST.
const GPIO_BACKLIGHT_PWM: i32 = 26;
const GPIO_LCD_RESET: i32 = 27;

/// AIRGAP LOCKDOWN - first call in app_main, held forever.
pub fn radio_lockdown() {
    common::radio_lockdown_gpio54();
    common::warn_portrait_unverified(DISPLAY_WIDTH, DISPLAY_HEIGHT);
}

pub fn display_init() -> Display {
    try_display_init().unwrap_or_else(|e| panic!("display init: {e}"))
}

fn try_display_init() -> Result<Display, DisplayError> {
    // Backlight LEDC claimed at duty 0 so the panel stays dark until the
    // first real frame (same invariant as the verified boards).
    common::backlight_pwm_init(GPIO_BACKLIGHT_PWM, false)?;

    let (dsi_bus, io) = common::dsi_bus_and_dbi_io(DSI_LANE_BIT_RATE_MBPS)?;

    // X BSP 7-inch branch: explicit DPI values, RGB565, no use_dma2d flag
    // in this branch (unlike the JD9365 sizes) - replicated faithfully.
    let dpi_config = sys::esp_lcd_dpi_panel_config_t {
        dpi_clk_src: sys::soc_periph_mipi_dsi_dpi_clk_src_t_MIPI_DSI_DPI_CLK_SRC_DEFAULT,
        dpi_clock_freq_mhz: DPI_CLOCK_FREQ_MHZ,
        virtual_channel: 0,
        pixel_format: sys::lcd_color_rgb_pixel_format_t_LCD_COLOR_PIXEL_FORMAT_RGB565,
        num_fbs: 1,
        video_timing: sys::esp_lcd_video_timing_t {
            h_size: DISPLAY_WIDTH,
            v_size: DISPLAY_HEIGHT,
            hsync_back_porch: 239,
            hsync_pulse_width: 50,
            hsync_front_porch: 33,
            vsync_back_porch: 20,
            vsync_pulse_width: 30,
            vsync_front_porch: 2,
        },
        ..Default::default()
    };

    // init_cmds stays NULL: the driver's built-in table is the BSP's table
    // (verified identical; see module banner).
    let mut vendor_config = sys::ili9881c_vendor_config_t::default();
    vendor_config.mipi_config.dsi_bus = dsi_bus;
    vendor_config.mipi_config.dpi_config = &dpi_config;
    vendor_config.mipi_config.lane_num = 2;

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
        sys::esp_lcd_new_panel_ili9881c(io, &panel_config, &mut panel),
        "esp_lcd_new_panel_ili9881c"
    );
    esp_check!(sys::esp_lcd_panel_reset(panel), "esp_lcd_panel_reset");
    esp_check!(sys::esp_lcd_panel_init(panel), "esp_lcd_panel_init");
    // The X BSP turns the display on explicitly after init (its ILI9881C
    // and JD9365 branches both do; the 4B/5/7B BSPs do not).
    esp_check!(sys::esp_lcd_panel_disp_on_off(panel, true), "esp_lcd_panel_disp_on_off");
    log::info!("ILI9881C panel initialized (720x1280 RGB565, DPI {DPI_CLOCK_FREQ_MHZ} MHz)");

    common::display_over_dpi_fb(panel, DISPLAY_WIDTH, DISPLAY_HEIGHT)
}

/// Backlight: direct LEDC PWM on GPIO26, non-inverted (X BSP
/// bsp_display_brightness_init - no output_invert on this board).
pub fn backlight_set(percent: u8) {
    common::backlight_set_duty(percent).unwrap_or_else(|e| panic!("backlight: {e}"))
}

pub fn touch_init() -> Touch {
    common::touch_init_probed(DISPLAY_WIDTH, DISPLAY_HEIGHT)
        .unwrap_or_else(|e| panic!("touch init: {e}"))
}
