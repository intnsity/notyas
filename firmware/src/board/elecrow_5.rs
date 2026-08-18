//! Board: Elecrow CrowPanel Advanced 5inch ESP32-P4 (DHE04005D).
//! 800x480 IPS, 16-bit parallel RGB565 in DE mode on the P4's LCDCAM RGB
//! peripheral (NOT MIPI-DSI; the panel is dumb RGB-TTL glass with no init
//! sequence and no reset line). GT911 touch (INT routed), STC8H1K17 co-MCU
//! (I2C 0x2F) owns the backlight PWM, 16 MB flash, ESP32-C6 radio killed via
//! GPIO20 -> C6 CHIP_PU.
//! Status: VERIFIED on hardware (rev v1.3 dev unit, COM6).
//!
//! All display/touch constants below are taken verbatim from Elecrow's
//! factory ESP-IDF source for this exact product,
//! factory_sourcecode/V1.0/ESP32-P4-Advance-5inch-lvgl/
//!   peripheral/bsp_display/{include/bsp_display.h,bsp_display.c}  (panel)
//!   peripheral/bsp_stc8h1kxx/*                                    (backlight)
//! in the repo linked from docs/research/elecrow-board.md, and cross-checked
//! against the V1.0 Eagle schematic.

use core::ffi::c_void;

use esp_idf_svc::sys;

use crate::board::claim_output;
use crate::display::{esp_check, Display, DisplayError};
use crate::touch::{touch_check, Touch, TouchError};

pub const BOARD_NAME: &str = "Elecrow CrowPanel Advanced 5inch ESP32-P4";
pub const DISPLAY_WIDTH: u32 = 800;
pub const DISPLAY_HEIGHT: u32 = 480;
pub const FLASH_SIZE_MB: u32 = 16;
pub const UNTESTED: bool = false;

pub const RADIO_KILL_GPIO: i32 = 20;
pub const RADIO_KILL_DOC: &str = "GPIO20 -> ESP32-C6 CHIP_PU (EN) via R95, driven low first \
     thing in app_main and never released: the only radio is hardware-held in reset. Known \
     power-on window: R77 (10K pullup) boots the C6 until this line runs. No WiFi stack in the \
     build; C6 SDIO host pins (GPIO49-54) never configured. Wireless module socket must be EMPTY.";

// RGB panel pins (factory bsp_display.h RGB_PIN_NUM_*; schematic agrees).
const PIN_DE: i32 = 2;
const PIN_PCLK: i32 = 3;
const PIN_HSYNC: i32 = 40;
const PIN_VSYNC: i32 = 41;
// DATA0..15 = B3-B7, G2-G7, R3-R7 (only 16 of the FPC's 24 pads are wired).
const PIN_DATA: [i32; 16] = [8, 7, 6, 5, 4, 14, 13, 12, 11, 10, 9, 19, 18, 17, 16, 15];

// Timings from factory bsp_display.h: RGB_LCD_PIXEL_CLOCK_HZ 25 MHz,
// HSYNC pw 4 / HBP 8 / HFP 8, VSYNC pw 4 / VBP 16 / VFP 16, DE mode,
// pclk_active_neg + pclk_idle_high. (The Arduino lessons use 18 MHz; the
// factory IDF value is tried first per BOARDS.md TODO 4.)
// HBP reduced from 8 to 5: the factory value shifts the visible area a few
// pixels right, clipping the right edge of the UI on this panel.
const PCLK_HZ: u32 = 25_000_000;

// Touch + STC8 share I2C1 (factory bsp_i2c Kconfig: SDA 45 / SCL 46, 400 kHz;
// schematic: 4.7K pullups on the GPIO45-54 bank rail).
const I2C_SDA: i32 = 45;
const I2C_SCL: i32 = 46;
const I2C_SPEED_HZ: u32 = 400_000;
// GT911 wiring: INT routed on GPIO42, RST on GPIO36. GPIO36 doubles as the
// DOWNLOAD_BOOT strap - driving it at runtime is what the factory firmware
// does and is safe (the strap is only sampled at P4 reset, when our driver
// config is gone); the driver leaves it HIGH, keeping the strap intact for
// warm resets.
const GPIO_TOUCH_RESET: i32 = 36;
const GPIO_TOUCH_INT: i32 = 42;

// STC8H1K17 co-MCU (factory bsp_stc8h1kxx.h): I2C slave 0x2F; backlight
// brightness = write [0x20 + pwm_idx, duty 0-100], pwm_idx 0 = LCD_BL_EN.
const STC8_ADDR: u16 = 0x2F;
const STC8_REG_SET_PWM: u8 = 0x20;

/// AIRGAP LOCKDOWN - first call in app_main, held forever.
/// Layers: 1) no WiFi stack in the build; 2) this hardware hold; 3) the C6
/// SDIO host pins are never configured. See RADIO_KILL_DOC and BOARDS.md.
pub fn radio_lockdown() {
    claim_output(RADIO_KILL_GPIO, 0);
    log::info!("C6 radio held in reset (GPIO20 low)");
    // Documented, not hidden (BOARDS.md "board-elecrow-5"): C6 EN carries a
    // 10K pullup (R77) to an always-on rail, so the C6 booted its esp-hosted
    // slave firmware at power-on and ran until the line above - a window of
    // some hundreds of ms (ROM + bootloader) that firmware cannot close.
    // The slave idles waiting for an SDIO host and joins no network; hardware
    // mitigation for production units is removing R77/R95 or the C6 module.
    log::warn!(
        "C6 power-on window: C6 EN is pulled up (R77) - the C6 ran from power-on until this \
         line; hardware-held in reset from here on"
    );
}

/// Full display pipeline bring-up. The panel is dumb RGB glass: no init
/// commands, no reset - `esp_lcd_new_rgb_panel` + panel init starts the DMA
/// stream. Backlight is OFF until the caller pushes the first real frame and
/// calls `backlight_set` (the STC8 write here blanks it explicitly, which
/// also proves STC8 comms before panel bring-up).
pub fn display_init() -> Display {
    try_display_init().unwrap_or_else(|e| panic!("display init: {e}"))
}

fn try_display_init() -> Result<Display, DisplayError> {
    // Backlight to 0 first: establishes I2C comms with the STC8 and makes
    // the "panel dark until first frame" invariant explicit (the STC8 resets
    // with the P4 - shared reset rail - so duty should already be 0).
    stc8_backlight(0).map_err(|e| DisplayError { what: e.what, code: e.code })?;

    // Power rail: LDO channel 4 at 3300 mV feeds the VDDPST_5 bank
    // (GPIO45-54: our I2C bus and its pullups). The factory firmware also
    // acquires channel 3 (2500 mV, MIPI DPHY) - that rail only feeds the
    // camera CSI PHY, which notyas never uses, so it stays off (BOARDS.md).
    // Note the V1.0 schematic marks the LDO4 route NC yet the factory
    // firmware acquires it and the bank works - keep the acquire.
    crate::display::acquire_ldo(4, 3300)?;
    log::info!("LDO channel 4 acquired at 3300 mV (GPIO45-54 bank)");

    // RGB panel config, verbatim from factory bsp_display.c
    // display_port_init(): 16-bit DE mode, dma_burst_size 64, fb in PSRAM.
    // num_fbs = 1 (factory uses 2 for LVGL tear-avoidance; we draw into the
    // single driver framebuffer exactly like the Waveshare DPI path).
    let mut config = sys::esp_lcd_rgb_panel_config_t {
        clk_src: sys::soc_periph_lcd_clk_src_t_LCD_CLK_SRC_DEFAULT,
        timings: sys::esp_lcd_rgb_timing_t {
            pclk_hz: PCLK_HZ,
            h_res: DISPLAY_WIDTH,
            v_res: DISPLAY_HEIGHT,
            hsync_pulse_width: 4,
            hsync_back_porch: 5,
            hsync_front_porch: 8,
            vsync_pulse_width: 4,
            vsync_back_porch: 16,
            vsync_front_porch: 16,
            ..Default::default()
        },
        data_width: 16,
        bits_per_pixel: 16,
        num_fbs: 1,
        hsync_gpio_num: PIN_HSYNC,
        vsync_gpio_num: PIN_VSYNC,
        de_gpio_num: PIN_DE,
        pclk_gpio_num: PIN_PCLK,
        disp_gpio_num: -1,
        ..Default::default()
    };
    config.timings.flags.set_pclk_active_neg(1);
    config.timings.flags.set_pclk_idle_high(1);
    config.__bindgen_anon_1.dma_burst_size = 64;
    for (i, &pin) in PIN_DATA.iter().enumerate() {
        config.data_gpio_nums[i] = pin;
    }
    config.flags.set_fb_in_psram(1);

    let mut panel: sys::esp_lcd_panel_handle_t = core::ptr::null_mut();
    esp_check!(sys::esp_lcd_new_rgb_panel(&config, &mut panel), "esp_lcd_new_rgb_panel");
    esp_check!(sys::esp_lcd_panel_reset(panel), "esp_lcd_panel_reset");
    esp_check!(sys::esp_lcd_panel_init(panel), "esp_lcd_panel_init");
    log::info!(
        "RGB panel initialized (800x480 RGB565 DE mode, pclk {} MHz)",
        PCLK_HZ / 1_000_000
    );

    let mut fb: *mut c_void = core::ptr::null_mut();
    esp_check!(
        sys::esp_lcd_rgb_panel_get_frame_buffer(panel, 1, &mut fb),
        "esp_lcd_rgb_panel_get_frame_buffer"
    );
    log::info!("RGB framebuffer at {fb:p} (PSRAM)");

    Ok(Display::over_panel_fb(
        panel,
        fb as *mut u16,
        DISPLAY_WIDTH as usize,
        DISPLAY_HEIGHT as usize,
    ))
}

/// Backlight: one register write to the STC8 co-MCU (I2C 0x2F, reg 0x20,
/// duty 0-100), which PWMs the MT9201 boost driver's EN pin. The P4 has no
/// backlight pin on this board - this write is the only way, and the only
/// thing we ever tell the STC8 (BOARDS.md "STC8 co-MCU (accepted risk)").
pub fn backlight_set(percent: u8) {
    stc8_backlight(percent.min(100)).unwrap_or_else(|e| panic!("backlight: {e}"))
}

fn stc8_backlight(duty: u8) -> Result<(), TouchError> {
    use core::sync::atomic::{AtomicPtr, Ordering};
    static DEV: AtomicPtr<core::ffi::c_void> = AtomicPtr::new(core::ptr::null_mut());

    let mut dev = DEV.load(Ordering::Acquire) as sys::i2c_master_dev_handle_t;
    if dev.is_null() {
        dev = i2c_dev(STC8_ADDR)?;
        DEV.store(dev as *mut core::ffi::c_void, Ordering::Release);
    }
    let buf = [STC8_REG_SET_PWM, duty];
    touch_check!(
        sys::i2c_master_transmit(dev, buf.as_ptr(), buf.len(), 1000),
        "i2c_master_transmit(STC8 backlight)"
    );
    log::info!("backlight set to {duty}% (STC8 0x2F reg 0x20)");
    Ok(())
}

/// The one shared I2C bus (GPIO45/46): STC8 + GT911. Created on first use -
/// backlight (STC8) is needed before touch bring-up.
fn i2c_bus() -> Result<sys::i2c_master_bus_handle_t, TouchError> {
    use core::sync::atomic::{AtomicPtr, Ordering};
    static BUS: AtomicPtr<core::ffi::c_void> = AtomicPtr::new(core::ptr::null_mut());

    let existing = BUS.load(Ordering::Acquire);
    if !existing.is_null() {
        return Ok(existing as sys::i2c_master_bus_handle_t);
    }
    let mut bus_config = sys::i2c_master_bus_config_t {
        i2c_port: 0,
        sda_io_num: I2C_SDA,
        scl_io_num: I2C_SCL,
        glitch_ignore_cnt: 7,
        ..Default::default()
    };
    bus_config.__bindgen_anon_1.clk_source = sys::soc_periph_i2c_clk_src_t_I2C_CLK_SRC_DEFAULT;
    // The bus has external 4.7K pullups (schematic); the internal pullup in
    // parallel is harmless and silences the driver's pullup advisory.
    bus_config.flags.set_enable_internal_pullup(1);
    let mut bus: sys::i2c_master_bus_handle_t = core::ptr::null_mut();
    touch_check!(sys::i2c_new_master_bus(&bus_config, &mut bus), "i2c_new_master_bus");
    // Single-threaded boot path; a lost race would only leak one bus handle.
    BUS.store(bus as *mut core::ffi::c_void, Ordering::Release);
    Ok(bus)
}

fn i2c_dev(addr: u16) -> Result<sys::i2c_master_dev_handle_t, TouchError> {
    let bus = i2c_bus()?;
    let dev_config = sys::i2c_device_config_t {
        device_address: addr,
        scl_speed_hz: I2C_SPEED_HZ,
        ..Default::default()
    };
    let mut dev: sys::i2c_master_dev_handle_t = core::ptr::null_mut();
    touch_check!(
        sys::i2c_master_bus_add_device(bus, &dev_config, &mut dev),
        "i2c_master_bus_add_device"
    );
    Ok(dev)
}

/// GT911 bring-up, factory sequence: the driver owns BOTH reset (GPIO36) and
/// INT (GPIO42). With INT routed the driver drives it during the reset pulse
/// to force the address deterministically (low -> 0x5D), then waits out the
/// wake-up - the Waveshare board's float-INT address coin-flip (pitfall 7)
/// cannot happen here. We still poll (no ISR): one loop for all boards.
pub fn touch_init() -> Touch {
    try_touch_init().unwrap_or_else(|e| panic!("touch init: {e}"))
}

fn try_touch_init() -> Result<Touch, TouchError> {
    let bus = i2c_bus()?;

    // Primary address first; retry the backup like Elecrow's own idf-code
    // lessons do (their touch_init falls back to
    // ESP_LCD_TOUCH_IO_I2C_GT911_ADDRESS_BACKUP when 0x5D fails). With INT
    // driver-strapped the primary should always win; the fallback covers a
    // GT911 whose config pins latched differently.
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

    // driver_data tells the gt911 driver which address to strap INT for
    // during its reset sequence (esp_lcd_touch_io_gt911_config_t). The
    // driver keeps the pointer, so give it 'static storage.
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

    // levels default to 0 = reset active low, INT strapped per driver_data
    // (factory tp_cfg.levels; bitfields zeroed by Default).
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

    Touch::finish_init(handle, io, "reset GPIO36 (driver-managed), int GPIO42")
}
