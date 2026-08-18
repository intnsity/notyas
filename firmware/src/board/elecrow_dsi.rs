//! ==========================================================================
//! UNTESTED BOARD CONFIG - COMPILE-CHECKED SCAFFOLD ONLY.
//!
//! Shared implementation for the Elecrow CrowPanel Advanced 7 / 9 / 10.1
//! inch ESP32-P4 boards (1024x600 MIPI-DSI). No such hardware exists on this
//! bench: nothing below has ever run. Every value traces to a published
//! Elecrow source, but "documented" is not "verified" - do not trust an
//! image built from this module until BOARDS.md marks the board verified.
//! main.rs logs "UNTESTED BOARD CONFIG" at boot via `UNTESTED = true`.
//!
//! Sources (all three boards were checked independently):
//! - Radio kill + SDIO pins: each board's factory sdkconfig
//!   (brookesia_phone zip: CONFIG_ESP_HOSTED_SDIO_GPIO_RESET_SLAVE=32,
//!   CMD=19 CLK=18 D0=14 D1=15, 1-bit) AND each board's V1.0 Eagle
//!   schematic: net C6_EN = U7.GPIO32 -> IC1.EN with 10K pullup R77 - same
//!   direct-EN wiring as the (hardware-verified) 5 inch board.
//! - Display: Elecrow factory firmware (modified esp32_p4_function_ev_board
//!   BSP 4.1.1, esp32_p4_function_ev_board.c, CONFIG_BSP_LCD_TYPE_1024_600
//!   branch): EK79007 panel via espressif/esp_lcd_ek79007, 2-lane DSI at
//!   1000 Mbps, DPI 51 MHz, HBP 160 / HPW 70 / HFP 160, VBP 23 / VPW 10 /
//!   VFP 12, LDO channel 3 at 2500 mV for the DSI PHY, no LCD reset pin.
//! - Backlight: same BSP - plain LEDC PWM on GPIO31 (30 kHz, 10-bit,
//!   non-inverted). Unlike the 5 inch, the P4 drives the backlight directly;
//!   the STC8 is not involved.
//! - Touch: same BSP + idf-code lessons - GT911 on I2C SDA 45 / SCL 46,
//!   RST GPIO40, INT GPIO42.
//! ==========================================================================

use core::ffi::c_void;

use esp_idf_svc::sys;

use crate::board::claim_output;
use crate::display::{esp_check, Display, DisplayError};
use crate::touch::{touch_check, Touch, TouchError};

pub const DISPLAY_WIDTH: u32 = 1024;
pub const DISPLAY_HEIGHT: u32 = 600;
pub const FLASH_SIZE_MB: u32 = 16;
pub const UNTESTED: bool = true;

pub const RADIO_KILL_GPIO: i32 = 32;
pub const RADIO_KILL_DOC: &str = "GPIO32 -> ESP32-C6 CHIP_PU (EN), driven low first thing in \
     app_main and never released (schematic net C6_EN; factory sdkconfig RESET_SLAVE=32). \
     Known power-on window: 10K pullup R77 boots the C6 until this line. No WiFi stack in the \
     build; C6 SDIO host pins (GPIO14/15/18/19) never configured. UNTESTED BOARD CONFIG.";

// Factory esp32_p4_function_ev_board.c, CONFIG_BSP_LCD_TYPE_1024_600 branch.
const DSI_LANES: u8 = 2;
const DSI_LANE_BIT_RATE_MBPS: f32 = 1000.0;
const DPI_CLOCK_FREQ_MHZ: f32 = 51.0;

// BSP_LCD_BACKLIGHT (1024x600 branch): direct LEDC PWM, no STC8 involved.
const GPIO_BACKLIGHT_PWM: i32 = 31;
const BACKLIGHT_PWM_HZ: u32 = 30_000;

// GT911 (factory BSP + idf-code lessons): same bus as the 5 inch, different
// reset pin - and GPIO40 is NOT a strap on these boards.
const I2C_SDA: i32 = 45;
const I2C_SCL: i32 = 46;
const I2C_SPEED_HZ: u32 = 400_000;
const GPIO_TOUCH_RESET: i32 = 40;
const GPIO_TOUCH_INT: i32 = 42;

/// AIRGAP LOCKDOWN - first call in app_main, held forever.
pub fn radio_lockdown() {
    claim_output(RADIO_KILL_GPIO, 0);
    log::info!("C6 radio held in reset (GPIO32 low)");
    log::warn!(
        "C6 power-on window: C6 EN is pulled up (R77) - the C6 ran from power-on until this \
         line; hardware-held in reset from here on"
    );
}

pub fn display_init() -> Display {
    try_display_init().unwrap_or_else(|e| panic!("display init: {e}"))
}

fn try_display_init() -> Result<Display, DisplayError> {
    // Backlight LEDC claimed at duty 0 so the panel stays dark until the
    // first real frame (same invariant as the verified boards).
    backlight_pwm_init()?;

    // DSI PHY power (factory bsp_enable_dsi_phy_power: LDO3 at 2500 mV).
    crate::display::acquire_ldo(3, 2500)?;
    log::info!("LDO channel 3 acquired at 2500 mV (MIPI DPHY)");

    let mut dsi_bus: sys::esp_lcd_dsi_bus_handle_t = core::ptr::null_mut();
    let bus_config = sys::esp_lcd_dsi_bus_config_t {
        bus_id: 0,
        num_data_lanes: DSI_LANES,
        phy_clk_src: 0, // driver default PLL ref, as in the factory BSP
        lane_bit_rate_mbps: DSI_LANE_BIT_RATE_MBPS,
    };
    esp_check!(sys::esp_lcd_new_dsi_bus(&bus_config, &mut dsi_bus), "esp_lcd_new_dsi_bus");
    log::info!("DSI bus up: {DSI_LANES} lanes, {DSI_LANE_BIT_RATE_MBPS} Mbps/lane");

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

    // DPI config: the factory BSP's explicit RGB565 values (its comment notes
    // these instead of EK79007_1024_600_PANEL_60HZ_CONFIG, whose macro form
    // bindgen cannot bind anyway).
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
            hsync_pulse_width: 70,
            hsync_front_porch: 160,
            vsync_back_porch: 23,
            vsync_pulse_width: 10,
            vsync_front_porch: 12,
        },
        ..Default::default()
    };
    dpi_config.flags.set_use_dma2d(1);

    let mut vendor_config = sys::ek79007_vendor_config_t::default();
    vendor_config.mipi_config.dsi_bus = dsi_bus;
    vendor_config.mipi_config.dpi_config = &dpi_config;

    let mut panel_config = sys::esp_lcd_panel_dev_config_t {
        reset_gpio_num: sys::gpio_num_t_GPIO_NUM_NC, // BSP_LCD_RST = NC
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

/// Backlight: direct LEDC PWM on GPIO31 (factory BSP: 30 kHz, 10-bit,
/// non-inverted, low-speed timer 1 / channel 1).
pub fn backlight_set(percent: u8) {
    try_backlight_set(percent).unwrap_or_else(|e| panic!("backlight: {e}"))
}

fn try_backlight_set(percent: u8) -> Result<(), DisplayError> {
    let duty = 1023 * percent.min(100) as u32 / 100;
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
    log::info!("backlight PWM duty set to {}%", percent.min(100));
    Ok(())
}

fn backlight_pwm_init() -> Result<(), DisplayError> {
    let timer_config = sys::ledc_timer_config_t {
        speed_mode: sys::ledc_mode_t_LEDC_LOW_SPEED_MODE,
        duty_resolution: sys::ledc_timer_bit_t_LEDC_TIMER_10_BIT,
        timer_num: sys::ledc_timer_t_LEDC_TIMER_1,
        freq_hz: BACKLIGHT_PWM_HZ,
        clk_cfg: sys::soc_periph_ledc_clk_src_legacy_t_LEDC_AUTO_CLK,
        ..Default::default()
    };
    esp_check!(sys::ledc_timer_config(&timer_config), "ledc_timer_config");

    let channel_config = sys::ledc_channel_config_t {
        gpio_num: GPIO_BACKLIGHT_PWM,
        speed_mode: sys::ledc_mode_t_LEDC_LOW_SPEED_MODE,
        channel: sys::ledc_channel_t_LEDC_CHANNEL_1,
        intr_type: sys::ledc_intr_type_t_LEDC_INTR_DISABLE,
        timer_sel: sys::ledc_timer_t_LEDC_TIMER_1,
        duty: 0,
        hpoint: 0,
        ..Default::default()
    };
    esp_check!(sys::ledc_channel_config(&channel_config), "ledc_channel_config");
    Ok(())
}

/// GT911 bring-up, same driver-managed sequence as the (verified) 5 inch
/// board: driver owns RST (GPIO40 - a plain GPIO here, not a strap) and INT
/// (GPIO42), strapping the address deterministically to 0x5D.
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
    bus_config.__bindgen_anon_1.clk_source = sys::soc_periph_i2c_clk_src_t_I2C_CLK_SRC_DEFAULT;
    // External pullups exist on this bus (same rail design as the 5 inch);
    // the internal pullup in parallel silences the driver's advisory.
    bus_config.flags.set_enable_internal_pullup(1);
    let mut bus: sys::i2c_master_bus_handle_t = core::ptr::null_mut();
    touch_check!(sys::i2c_new_master_bus(&bus_config, &mut bus), "i2c_new_master_bus");

    // Primary address, then the backup - same fallback Elecrow's own lesson
    // code uses on these boards.
    let mut last_err = TouchError {
        what: "GT911 init (0x5D, 0x14)",
        code: sys::ESP_ERR_NOT_FOUND,
    };
    for addr in [crate::touch::GT911_ADDR_PRIMARY, crate::touch::GT911_ADDR_BACKUP] {
        match gt911_init_at(bus, addr) {
            Ok(touch) => return Ok(touch),
            Err(e) => {
                log::warn!("GT911 init at 0x{addr:02X} failed ({e}); trying next address");
                last_err = e;
            }
        }
    }
    Err(last_err)
}

fn gt911_init_at(
    bus: sys::i2c_master_bus_handle_t,
    addr: u16,
) -> Result<Touch, TouchError> {
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

    // driver_data selects the INT strap level for the address; the driver
    // keeps the pointer, so give it 'static storage.
    static GT911_ADDR_CFG: [sys::esp_lcd_touch_io_gt911_config_t; 2] = [
        sys::esp_lcd_touch_io_gt911_config_t {
            dev_addr: crate::touch::GT911_ADDR_PRIMARY as u8,
        },
        sys::esp_lcd_touch_io_gt911_config_t {
            dev_addr: crate::touch::GT911_ADDR_BACKUP as u8,
        },
    ];
    let driver_data = if addr == crate::touch::GT911_ADDR_PRIMARY {
        &GT911_ADDR_CFG[0]
    } else {
        &GT911_ADDR_CFG[1]
    };

    let touch_config = sys::esp_lcd_touch_config_t {
        x_max: DISPLAY_WIDTH as u16,
        y_max: DISPLAY_HEIGHT as u16,
        rst_gpio_num: GPIO_TOUCH_RESET,
        int_gpio_num: GPIO_TOUCH_INT,
        driver_data: driver_data as *const _ as *mut c_void,
        ..Default::default()
    };

    let mut handle: sys::esp_lcd_touch_handle_t = core::ptr::null_mut();
    touch_check!(
        sys::esp_lcd_touch_new_i2c_gt911(io, &touch_config, &mut handle),
        "esp_lcd_touch_new_i2c_gt911"
    );
    log::info!("GT911 at i2c address 0x{addr:02X} (driver-strapped via INT GPIO{GPIO_TOUCH_INT})");

    Touch::finish_init(handle, io, "reset GPIO40 (driver-managed), int GPIO42")
}
