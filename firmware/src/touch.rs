//! GT911 capacitive touch over the espressif/esp_lcd_touch_gt911 C component.
//!
//! Board constraints (HARDWARE.md): the GT911 INT line is NOT routed (test
//! point only), so the controller cannot signal readiness and cannot have its
//! I2C address forced at reset - it must be POLLED, and the address probed:
//! 0x5D first, 0x14 as fallback. Reset is GPIO23; the shared I2C bus (touch,
//! camera, audio codecs) is on SDA=GPIO7 / SCL=GPIO8 at 400 kHz via the new
//! i2c_master bus API.

use core::ffi::c_void;

use esp_idf_svc::sys;

use crate::display::{H_RES, V_RES};

const I2C_SDA: i32 = 7;
const I2C_SCL: i32 = 8;
const I2C_SPEED_HZ: u32 = 400_000;
const GPIO_TOUCH_RESET: i32 = 23;

// GT911 slave addresses (ESP_LCD_TOUCH_IO_I2C_GT911_ADDRESS[_BACKUP]).
const GT911_ADDR_PRIMARY: u16 = 0x5D;
const GT911_ADDR_BACKUP: u16 = 0x14;

// GT911 register: 4-byte ASCII product id ("911\0" on genuine parts).
const GT911_REG_PRODUCT_ID: u32 = 0x8140;

#[derive(Debug)]
pub struct TouchError {
    pub what: &'static str,
    pub code: sys::esp_err_t,
}

impl core::fmt::Display for TouchError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} failed: esp_err 0x{:x}", self.what, self.code)
    }
}

macro_rules! touch_check {
    ($call:expr, $what:literal) => {{
        let err = unsafe { $call };
        if err != sys::ESP_OK {
            return Err(TouchError { what: $what, code: err });
        }
    }};
}

pub struct Touch {
    handle: sys::esp_lcd_touch_handle_t,
}

impl Touch {
    /// Bring up the I2C bus, probe for the GT911, and initialize the driver.
    /// Logs the probed address and the chip's product id register.
    pub fn init() -> Result<Self, TouchError> {
        let mut bus_config = sys::i2c_master_bus_config_t {
            i2c_port: 0,
            sda_io_num: I2C_SDA,
            scl_io_num: I2C_SCL,
            glitch_ignore_cnt: 7,
            ..Default::default()
        };
        // clk_source lives in an anonymous union (shared with the LP-I2C
        // source selector).
        bus_config.__bindgen_anon_1.clk_source =
            sys::soc_periph_i2c_clk_src_t_I2C_CLK_SRC_DEFAULT;
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

        let addr = [GT911_ADDR_PRIMARY, GT911_ADDR_BACKUP]
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
            x_max: H_RES as u16,
            y_max: V_RES as u16,
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

        // The first read after reset reports a phantom point (observed
        // 481,481 with nothing touching the panel) - the status register
        // latches garbage across reset. One discarded read clears it.
        let mut throwaway = Self { handle };
        let _ = throwaway.poll();
        let Self { handle } = throwaway;

        // Read the product id straight from the chip so the init log carries
        // positive identification, not just a successful driver call.
        let mut id = [0u8; 4];
        touch_check!(
            sys::esp_lcd_panel_io_rx_param(
                io,
                GT911_REG_PRODUCT_ID as i32,
                id.as_mut_ptr() as *mut c_void,
                id.len(),
            ),
            "esp_lcd_panel_io_rx_param(product id)"
        );
        let id_str = core::str::from_utf8(&id)
            .unwrap_or("<non-ascii>")
            .trim_end_matches('\0');
        log::info!(
            "GT911 initialized: product id \"{}\" ({:02X?}), polled mode, reset GPIO{}",
            id_str,
            id,
            GPIO_TOUCH_RESET
        );

        Ok(Self { handle })
    }

    /// Poll the controller once. Returns the primary touch point, or None
    /// when nothing is pressed. Must be called from the main loop (the INT
    /// line does not exist on this board).
    pub fn poll(&mut self) -> Option<(u16, u16)> {
        let err = unsafe { sys::esp_lcd_touch_read_data(self.handle) };
        if err != sys::ESP_OK {
            log::warn!("esp_lcd_touch_read_data failed: 0x{err:x}");
            return None;
        }
        let mut x = [0u16; 1];
        let mut y = [0u16; 1];
        let mut count: u8 = 0;
        let pressed = unsafe {
            sys::esp_lcd_touch_get_coordinates(
                self.handle,
                x.as_mut_ptr(),
                y.as_mut_ptr(),
                core::ptr::null_mut(),
                &mut count,
                1,
            )
        };
        (pressed && count > 0).then_some((x[0], y[0]))
    }
}
