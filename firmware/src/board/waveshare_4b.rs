//! Board: Waveshare ESP32-P4-WiFi6-Touch-LCD-4B (docs/HARDWARE.md).
//! 720x720 MIPI-DSI (ST7703), GT911 touch (INT unrouted - polled), 32 MB
//! flash, ESP32-C6 radio killed via GPIO54 -> C6 CHIP_PU.
//! Status: VERIFIED on hardware (rev v1.3 dev unit, COM3).

use core::ffi::c_void;

use esp_idf_svc::sys;

use crate::board::claim_output;
use crate::display::{esp_check, Display, DisplayError};
use crate::touch::{touch_check, Touch, TouchError};

pub const BOARD_NAME: &str = "Waveshare ESP32-P4-WiFi6-Touch-LCD-4B";
pub const DISPLAY_WIDTH: u32 = 720;
pub const DISPLAY_HEIGHT: u32 = 720;
pub const FLASH_SIZE_MB: u32 = 32;
pub const UNTESTED: bool = false;

pub const RADIO_KILL_GPIO: i32 = 54;
pub const RADIO_KILL_DOC: &str = "GPIO54 -> ESP32-C6 CHIP_PU (EN), driven low first thing in \
     app_main and never released: the only radio is hardware-held in reset for the whole power \
     cycle. C6 EN carries NO pullup (1 uF to GND only, schematic-verified), so the radio is \
     also held down from power-on - no boot window exists. No WiFi stack in the build; C6 SDIO \
     host pins (GPIO14-19) never configured.";

// Display pins (board schematic, HARDWARE.md GPIO map).
const GPIO_LCD_RESET: i32 = 27;
const GPIO_BACKLIGHT_ENABLE: i32 = 33;
const GPIO_BACKLIGHT_PWM: i32 = 26;

/// Values of `ST7703_PANEL_BUS_DSI_2CH_CONFIG()` /
/// `ST7703_720_720_PANEL_60HZ_DPI_CONFIG()` from esp_lcd_st7703.h v2 -
/// function-like macros, so bindgen cannot surface them; replicated here
/// verbatim and checked against the vendored header on component updates.
const DSI_LANES: u8 = 2;
const DSI_LANE_BIT_RATE_MBPS: f32 = 480.0;
const DPI_CLOCK_FREQ_MHZ: f32 = 38.0;

// Touch wiring: shared I2C bus (touch, camera, audio codecs) on SDA=7/SCL=8;
// GT911 reset on GPIO23; INT is a test point only - polled operation.
const I2C_SDA: i32 = 7;
const I2C_SCL: i32 = 8;
const I2C_SPEED_HZ: u32 = 400_000;
const GPIO_TOUCH_RESET: i32 = 23;

/// AIRGAP LOCKDOWN - first call in app_main, held forever.
/// This is lockdown layer 2 of the security model (layer 1: no WiFi stack in
/// the build; layer 3: the C6 SDIO GPIOs are never configured as SDIO host).
pub fn radio_lockdown() {
    claim_output(RADIO_KILL_GPIO, 0);
    // No power-on window on this board: C6 EN has no pullup (1 uF to GND only), so the
    // radio was already held down between power-on and this line - the drive here makes
    // the hold active instead of relying on the pin's default state. See
    // docs/research/waveshare-family.md and BOARDS.md "The airgap invariant, per board".
    log::info!(
        "C6 radio held in reset (GPIO54 low; no EN pullup - C6 held down from power-on)"
    );
}

/// Full display pipeline bring-up. The backlight stays OFF (enable pin low)
/// until the caller pushes the first real frame and calls `backlight_set` -
/// the panel never shows uninitialized framebuffer content.
pub fn display_init() -> Display {
    try_display_init().unwrap_or_else(|e| panic!("display init: {e}"))
}

fn try_display_init() -> Result<Display, DisplayError> {
    // Backlight enable low before the DSI stream starts.
    claim_output(GPIO_BACKLIGHT_ENABLE, 0);

    // 1. Power rails (order: before any DSI register access - LDO channel 3
    // powers the MIPI DPHY and skipping it hangs esp_lcd_new_dsi_bus).
    crate::display::acquire_ldo(3, 2500)?;
    log::info!("LDO channel 3 acquired at 2500 mV (MIPI DPHY)");
    crate::display::acquire_ldo(4, 3300)?;
    log::info!("LDO channel 4 acquired at 3300 mV (GPIO39-48 bank)");

    // 2. DSI bus - 2 lanes at 480 Mbps (ST7703_PANEL_BUS_DSI_2CH_CONFIG).
    let mut dsi_bus: sys::esp_lcd_dsi_bus_handle_t = core::ptr::null_mut();
    let bus_config = sys::esp_lcd_dsi_bus_config_t {
        bus_id: 0,
        num_data_lanes: DSI_LANES,
        // 0 = "driver picks the default PLL ref" (same as the Waveshare
        // BSP and the ST7703 bus config macro).
        phy_clk_src: 0,
        lane_bit_rate_mbps: DSI_LANE_BIT_RATE_MBPS,
    };
    esp_check!(
        sys::esp_lcd_new_dsi_bus(&bus_config, &mut dsi_bus),
        "esp_lcd_new_dsi_bus"
    );
    log::info!("DSI bus up: {DSI_LANES} lanes, {DSI_LANE_BIT_RATE_MBPS} Mbps/lane");

    // 3. DBI IO channel for panel commands (ST7703_PANEL_IO_DBI_CONFIG).
    let mut io: sys::esp_lcd_panel_io_handle_t = core::ptr::null_mut();
    let dbi_config = sys::esp_lcd_dbi_io_config_t {
        virtual_channel: 0,
        lcd_cmd_bits: 8,
        lcd_param_bits: 8,
    };
    esp_check!(
        sys::esp_lcd_new_panel_io_dbi(dsi_bus, &dbi_config, &mut io),
        "esp_lcd_new_panel_io_dbi"
    );

    // 4. DPI video config (ST7703_720_720_PANEL_60HZ_DPI_CONFIG, RGB565).
    let mut dpi_config = sys::esp_lcd_dpi_panel_config_t {
        dpi_clk_src: sys::soc_periph_mipi_dsi_dpi_clk_src_t_MIPI_DSI_DPI_CLK_SRC_DEFAULT,
        dpi_clock_freq_mhz: DPI_CLOCK_FREQ_MHZ,
        virtual_channel: 0,
        pixel_format: sys::lcd_color_rgb_pixel_format_t_LCD_COLOR_PIXEL_FORMAT_RGB565,
        num_fbs: 1,
        video_timing: sys::esp_lcd_video_timing_t {
            h_size: DISPLAY_WIDTH,
            v_size: DISPLAY_HEIGHT,
            hsync_back_porch: 50,
            hsync_pulse_width: 20,
            hsync_front_porch: 50,
            vsync_back_porch: 20,
            vsync_pulse_width: 4,
            vsync_front_porch: 20,
        },
        ..Default::default()
    };
    dpi_config.flags.set_use_dma2d(1);

    // 5. ST7703 panel over the vendor config (MIPI interface).
    let mut vendor_config = sys::st7703_vendor_config_t::default();
    vendor_config.mipi_config.dsi_bus = dsi_bus;
    vendor_config.mipi_config.dpi_config = &dpi_config;
    vendor_config.flags.set_use_mipi_interface(1);

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
        sys::esp_lcd_new_panel_st7703(io, &panel_config, &mut panel),
        "esp_lcd_new_panel_st7703"
    );
    esp_check!(sys::esp_lcd_panel_reset(panel), "esp_lcd_panel_reset");
    esp_check!(sys::esp_lcd_panel_init(panel), "esp_lcd_panel_init");
    log::info!("ST7703 panel initialized (720x720 RGB565, DPI {DPI_CLOCK_FREQ_MHZ} MHz)");

    // 6. Borrow the driver's PSRAM framebuffer.
    let mut fb: *mut c_void = core::ptr::null_mut();
    esp_check!(
        sys::esp_lcd_dpi_panel_get_frame_buffer(panel, 1, &mut fb),
        "esp_lcd_dpi_panel_get_frame_buffer"
    );
    log::info!("DPI framebuffer at {fb:p} (PSRAM)");

    Ok(Display::over_panel_fb(
        panel,
        fb as *mut u16,
        DISPLAY_WIDTH as usize,
        DISPLAY_HEIGHT as usize,
    ))
}

/// Backlight: GPIO33 enable + LEDC PWM on GPIO26, replicating the Waveshare
/// BSP's proven setup exactly: low-speed timer 1 / channel 1, 5 kHz, 10-bit
/// resolution, INVERTED output (the board's backlight driver PWM input is
/// active-low; duty N of 1023 still means N/1023 brightness because of the
/// invert flag). First call initializes the PWM; percent 0 drops the enable
/// pin again.
pub fn backlight_set(percent: u8) {
    try_backlight_set(percent).unwrap_or_else(|e| panic!("backlight: {e}"))
}

fn try_backlight_set(percent: u8) -> Result<(), DisplayError> {
    use std::sync::Once;
    static PWM_INIT: Once = Once::new();

    let mut init_result: Result<(), DisplayError> = Ok(());
    PWM_INIT.call_once(|| init_result = backlight_pwm_init());
    init_result?;

    let percent = percent.min(100) as u32;
    let duty = 1023 * percent / 100;
    esp_check!(
        sys::ledc_set_duty(
            sys::ledc_mode_t_LEDC_LOW_SPEED_MODE,
            sys::ledc_channel_t_LEDC_CHANNEL_1,
            duty,
        ),
        "ledc_set_duty"
    );
    esp_check!(
        sys::ledc_update_duty(
            sys::ledc_mode_t_LEDC_LOW_SPEED_MODE,
            sys::ledc_channel_t_LEDC_CHANNEL_1,
        ),
        "ledc_update_duty"
    );
    // Enable pin gates the whole backlight driver; keep it in lockstep with
    // a zero/nonzero duty so percent 0 really means dark.
    esp_check!(
        sys::gpio_set_level(GPIO_BACKLIGHT_ENABLE, (percent > 0) as u32),
        "gpio_set_level(backlight enable)"
    );
    log::info!("backlight PWM duty set to {percent}%");
    Ok(())
}

fn backlight_pwm_init() -> Result<(), DisplayError> {
    let timer_config = sys::ledc_timer_config_t {
        speed_mode: sys::ledc_mode_t_LEDC_LOW_SPEED_MODE,
        duty_resolution: sys::ledc_timer_bit_t_LEDC_TIMER_10_BIT,
        timer_num: sys::ledc_timer_t_LEDC_TIMER_1,
        freq_hz: 5000,
        clk_cfg: sys::soc_periph_ledc_clk_src_legacy_t_LEDC_AUTO_CLK,
        ..Default::default()
    };
    esp_check!(sys::ledc_timer_config(&timer_config), "ledc_timer_config");

    let mut channel_config = sys::ledc_channel_config_t {
        gpio_num: GPIO_BACKLIGHT_PWM,
        speed_mode: sys::ledc_mode_t_LEDC_LOW_SPEED_MODE,
        channel: sys::ledc_channel_t_LEDC_CHANNEL_1,
        intr_type: sys::ledc_intr_type_t_LEDC_INTR_DISABLE,
        timer_sel: sys::ledc_timer_t_LEDC_TIMER_1,
        duty: 0,
        hpoint: 0,
        ..Default::default()
    };
    channel_config.flags.set_output_invert(1);
    esp_check!(sys::ledc_channel_config(&channel_config), "ledc_channel_config");
    Ok(())
}

/// Bring up the I2C bus, probe for the GT911, and initialize the driver.
///
/// Wiring constraint (HARDWARE.md): the GT911 INT line is NOT routed (test
/// point only), so the controller cannot signal readiness and cannot have its
/// I2C address forced at reset - it must be POLLED, and the address probed:
/// 0x5D first, 0x14 as fallback.
pub fn touch_init() -> Touch {
    try_touch_init().unwrap_or_else(|e| panic!("touch init: {e}"))
}

fn try_touch_init() -> Result<Touch, TouchError> {
    let mut bus_config = sys::i2c_master_bus_config_t {
        i2c_port: 0,
        sda_io_num: I2C_SDA,
        scl_io_num: I2C_SCL,
        glitch_ignore_cnt: 7,
        ..Default::default()
    };
    // clk_source lives in an anonymous union (shared with the LP-I2C
    // source selector).
    bus_config.__bindgen_anon_1.clk_source = sys::soc_periph_i2c_clk_src_t_I2C_CLK_SRC_DEFAULT;
    let mut bus: sys::i2c_master_bus_handle_t = core::ptr::null_mut();
    touch_check!(sys::i2c_new_master_bus(&bus_config, &mut bus), "i2c_new_master_bus");

    // Reset the GT911 ourselves, NOT via the driver. The chip re-latches
    // its I2C address from the INT level at every reset release, and INT
    // is unrouted on this board - so each reset is a coin flip between
    // 0x5D and 0x14. The gt911 driver pulses reset and reads config
    // immediately, racing the chip's ~50 ms post-reset wake-up; observed
    // on hardware as intermittent init failures with the address flipping
    // between boots. Sequence that is deterministic: one reset here, wait
    // out the wake-up, THEN probe for whichever address got latched, and
    // hand the driver rst = NC so it cannot re-reset behind our back.
    let reset_config = sys::gpio_config_t {
        pin_bit_mask: 1u64 << GPIO_TOUCH_RESET,
        mode: sys::gpio_mode_t_GPIO_MODE_OUTPUT,
        ..Default::default()
    };
    touch_check!(sys::gpio_config(&reset_config), "gpio_config(touch reset)");
    touch_check!(
        sys::gpio_set_level(GPIO_TOUCH_RESET, 0),
        "gpio_set_level(touch reset low)"
    );
    std::thread::sleep(core::time::Duration::from_millis(10));
    touch_check!(
        sys::gpio_set_level(GPIO_TOUCH_RESET, 1),
        "gpio_set_level(touch reset high)"
    );
    std::thread::sleep(core::time::Duration::from_millis(120));

    let addr = [crate::touch::GT911_ADDR_PRIMARY, crate::touch::GT911_ADDR_BACKUP]
        .into_iter()
        .find(|&a| unsafe { sys::i2c_master_probe(bus, a, 100) } == sys::ESP_OK)
        .ok_or(TouchError {
            what: "GT911 i2c probe (0x5D, 0x14)",
            code: sys::ESP_ERR_NOT_FOUND,
        })?;
    log::info!("GT911 responds at i2c address 0x{addr:02X}");

    // Values of ESP_LCD_TOUCH_IO_I2C_GT911_CONFIG() (function-like macro,
    // not bindgen-able): 16-bit register addresses, no control phase.
    let mut io_config = sys::esp_lcd_panel_io_i2c_config_t {
        dev_addr: addr as u32,
        control_phase_bytes: 1,
        dc_bit_offset: 0,
        lcd_cmd_bits: 16,
        lcd_param_bits: 0,
        scl_speed_hz: I2C_SPEED_HZ,
        ..Default::default()
    };
    io_config.flags.set_disable_control_phase(1);

    let mut io: sys::esp_lcd_panel_io_handle_t = core::ptr::null_mut();
    touch_check!(
        sys::esp_lcd_new_panel_io_i2c_v2(bus, &io_config, &mut io),
        "esp_lcd_new_panel_io_i2c_v2"
    );

    let touch_config = sys::esp_lcd_touch_config_t {
        x_max: DISPLAY_WIDTH as u16,
        y_max: DISPLAY_HEIGHT as u16,
        // Reset was already handled above; NC keeps the driver's hands
        // off the pin (a driver-issued reset would re-randomize the
        // address we just probed).
        rst_gpio_num: sys::gpio_num_t_GPIO_NUM_NC,
        // INT is not routed on this board - NC forces the driver into
        // pure polling mode (no ISR, no address strapping control).
        int_gpio_num: sys::gpio_num_t_GPIO_NUM_NC,
        ..Default::default()
    };
    let mut handle: sys::esp_lcd_touch_handle_t = core::ptr::null_mut();
    touch_check!(
        sys::esp_lcd_touch_new_i2c_gt911(io, &touch_config, &mut handle),
        "esp_lcd_touch_new_i2c_gt911"
    );

    Touch::finish_init(handle, io, "reset GPIO23")
}
