//! ==========================================================================
//! UNTESTED BOARD CONFIGS - COMPILE-CHECKED SCAFFOLDS ONLY.
//!
//! Shared bring-up helpers for the Waveshare ESP32-P4-WIFI6 Touch-LCD DSI
//! scaffolds (Touch-LCD-5 / -7B / -7 / -8 / -10.1). No such hardware exists
//! on this bench: nothing below has ever run. Every value traces to a
//! published Waveshare source, but "documented" is not "verified" - do not
//! trust an image built from these modules until BOARDS.md marks the board
//! verified. main.rs logs "UNTESTED BOARD CONFIG" at boot via `UNTESTED`.
//!
//! Sources (docs/research/waveshare-family.md; BSP monorepo
//! github.com/waveshareteam/Waveshare-ESP32-components @ be0e5e4, re-fetched
//! 2026-08-17 for the constants the family doc does not carry):
//! - Radio kill: each board's schematic C6 sheet (family doc, per-board
//!   sections + kill-pin table): P4 GPIO54 -> 0R -> C6 CHIP_PU (EN). The C6
//!   is a module part whose EN carries NO pullup (1 uF to GND only), so the
//!   radio is held down from power-on - the same no-boot-window guarantee as
//!   the (hardware-verified) 4B.
//! - Touch: every sibling BSP's bsp_touch_new probes the GT911 at 0x5D then
//!   0x14 on the shared I2C bus SDA=7/SCL=8 and hands the driver
//!   rst = int = GPIO_NUM_NC: TP RST and INT are not routed to the P4 on
//!   these boards. Like the 4B minus its reset pin - the address latched at
//!   power-on (floating INT) is a coin flip, so both addresses are probed;
//!   polled operation only.
//! - Backlight: every sibling BSP's bsp_display_brightness_init - LEDC
//!   low-speed mode, timer 1, channel 1, 5 kHz, 10-bit; the GPIO and the
//!   output polarity differ per board and live in the board modules.
//! - DSI: 2 data lanes on every board; MIPI DPHY power = LDO channel 3 at
//!   2500 mV (bsp_enable_dsi_phy_power). Lane rate and DPI timing are
//!   per-board.
//!
//! ==========================================================================

use core::ffi::c_void;

use esp_idf_svc::sys;

use crate::board::claim_output;
use crate::display::{esp_check, Display, DisplayError};
use crate::touch::{touch_check, Touch, TouchError};

// Family-invariant wiring (see module banner for sources).
pub(super) const RADIO_KILL_GPIO: i32 = 54;
const I2C_SDA: i32 = 7;
const I2C_SCL: i32 = 8;
const I2C_SPEED_HZ: u32 = 400_000;

/// AIRGAP LOCKDOWN - first call in app_main, held forever. Same circuit and
/// wording as the (verified) 4B: no EN pullup, so the C6 was already held
/// down between power-on and this line; the drive makes the hold active
/// instead of relying on the pin's default state.
pub(super) fn radio_lockdown_gpio54() {
    claim_output(RADIO_KILL_GPIO, 0);
    log::info!(
        "C6 radio held in reset (GPIO54 low; no EN pullup - C6 held down from power-on)"
    );
}

/// Boot warning for the portrait scaffolds: the UI derives its layout from
/// DISPLAY_WIDTH/HEIGHT but has only ever been rendered at 720x720 (square)
/// and 800x480 (landscape). Portrait output is layout-derived, not verified.
/// (cfg-gated to the portrait boards so the landscape 7B builds warning-free.)
#[cfg(any(
    feature = "board-waveshare-5",
    feature = "board-waveshare-7x",
    feature = "board-waveshare-8x",
    feature = "board-waveshare-101x",
))]
pub(super) fn warn_portrait_unverified(width: u32, height: u32) {
    log::warn!(
        "UNTESTED BOARD + PORTRAIT LAYOUT UNVERIFIED: {width}x{height} portrait has never \
         rendered this UI (verified resolutions: 720x720 square, 800x480 landscape)"
    );
}

/// LEDC backlight init at duty 0 (panel dark until the first real frame -
/// same invariant as the verified boards). Every sibling BSP uses low-speed
/// timer 1 / channel 1 at 5 kHz, 10-bit; `invert` replicates the per-board
/// `flags.output_invert` (backlight driver PWM input active-low on some
/// boards; duty N of 1023 still means N/1023 brightness under the invert).
pub(super) fn backlight_pwm_init(gpio: i32, invert: bool) -> Result<(), DisplayError> {
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
        gpio_num: gpio,
        speed_mode: sys::ledc_mode_t_LEDC_LOW_SPEED_MODE,
        channel: sys::ledc_channel_t_LEDC_CHANNEL_1,
        intr_type: sys::ledc_intr_type_t_LEDC_INTR_DISABLE,
        timer_sel: sys::ledc_timer_t_LEDC_TIMER_1,
        duty: 0,
        hpoint: 0,
        ..Default::default()
    };
    channel_config.flags.set_output_invert(invert as u32);
    esp_check!(sys::ledc_channel_config(&channel_config), "ledc_channel_config");
    Ok(())
}

/// Set backlight duty on the channel claimed by `backlight_pwm_init`.
pub(super) fn backlight_set_duty(percent: u8) -> Result<(), DisplayError> {
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
    log::info!("backlight PWM duty set to {percent}%");
    Ok(())
}

/// DPHY power + DSI bus + DBI command channel, common to every sibling:
/// LDO channel 3 at 2500 mV, then the bus at the board's lane rate, then an
/// 8-bit-cmd/8-bit-param DBI IO (all sibling BSPs use exactly this DBI
/// config regardless of panel).
pub(super) fn dsi_bus_and_dbi_io(
    lane_bit_rate_mbps: f32,
) -> Result<(sys::esp_lcd_dsi_bus_handle_t, sys::esp_lcd_panel_io_handle_t), DisplayError> {
    crate::display::acquire_ldo(3, 2500)?;
    log::info!("LDO channel 3 acquired at 2500 mV (MIPI DPHY)");

    let mut dsi_bus: sys::esp_lcd_dsi_bus_handle_t = core::ptr::null_mut();
    let bus_config = sys::esp_lcd_dsi_bus_config_t {
        bus_id: 0,
        num_data_lanes: 2,
        phy_clk_src: 0, // driver default PLL ref, as in the sibling BSPs
        lane_bit_rate_mbps,
    };
    esp_check!(sys::esp_lcd_new_dsi_bus(&bus_config, &mut dsi_bus), "esp_lcd_new_dsi_bus");
    log::info!("DSI bus up: 2 lanes, {lane_bit_rate_mbps} Mbps/lane");

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
    Ok((dsi_bus, io))
}

/// Borrow the DPI driver's PSRAM framebuffer and wrap it as the Display.
pub(super) fn display_over_dpi_fb(
    panel: sys::esp_lcd_panel_handle_t,
    width: u32,
    height: u32,
) -> Result<Display, DisplayError> {
    let mut fb: *mut c_void = core::ptr::null_mut();
    esp_check!(
        sys::esp_lcd_dpi_panel_get_frame_buffer(panel, 1, &mut fb),
        "esp_lcd_dpi_panel_get_frame_buffer"
    );
    log::info!("DPI framebuffer at {fb:p} (PSRAM)");
    Ok(Display::over_panel_fb(panel, fb as *mut u16, width as usize, height as usize))
}

/// GT911 bring-up shared by every sibling: I2C master bus on SDA 7 / SCL 8,
/// probe 0x5D then 0x14 (the BSPs' own fallback order), driver gets
/// rst = int = NC. There is no reset pin to pulse (TP_RST is unrouted), so
/// unlike the 4B no manual reset precedes the probe - the chip has been up
/// since power-on with whatever address its floating INT latched.
pub(super) fn touch_init_probed(width: u32, height: u32) -> Result<Touch, TouchError> {
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
        x_max: width as u16,
        y_max: height as u16,
        // Neither TP_RST nor TP_INT reaches the P4 on these boards; NC keeps
        // the driver in pure polling mode with no reset of its own (which
        // would re-randomize the address we just probed).
        rst_gpio_num: sys::gpio_num_t_GPIO_NUM_NC,
        int_gpio_num: sys::gpio_num_t_GPIO_NUM_NC,
        ..Default::default()
    };
    let mut handle: sys::esp_lcd_touch_handle_t = core::ptr::null_mut();
    touch_check!(
        sys::esp_lcd_touch_new_i2c_gt911(io, &touch_config, &mut handle),
        "esp_lcd_touch_new_i2c_gt911"
    );

    Touch::finish_init(handle, io, "no touch reset/int routed (probed, polled)")
}
