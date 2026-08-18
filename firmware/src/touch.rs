//! Board-agnostic GT911 touch plumbing over the espressif/esp_lcd_touch_gt911
//! C component. Both supported boards carry a GT911, but the wiring (I2C
//! pins, whether INT is routed, who owns the reset pin) differs - that logic
//! lives in the board modules, which hand a driver handle to
//! [`Touch::finish_init`]. The shared part is the polled read loop and the
//! post-init hygiene every GT911 needs (phantom-point flush, positive chip
//! identification in the log).

use core::ffi::c_void;

use esp_idf_svc::sys;

// GT911 slave addresses (ESP_LCD_TOUCH_IO_I2C_GT911_ADDRESS[_BACKUP]).
pub const GT911_ADDR_PRIMARY: u16 = 0x5D;
pub const GT911_ADDR_BACKUP: u16 = 0x14;

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

/// Run an esp-idf call, mapping a non-ESP_OK result to `TouchError`.
macro_rules! touch_check {
    ($call:expr, $what:literal) => {{
        let err = unsafe { $call };
        if err != esp_idf_svc::sys::ESP_OK {
            return Err($crate::touch::TouchError { what: $what, code: err });
        }
    }};
}
pub(crate) use touch_check;

pub struct Touch {
    handle: sys::esp_lcd_touch_handle_t,
}

impl Touch {
    /// Wrap a freshly created gt911 driver handle: flush the phantom first
    /// read and log the chip's product id register as positive identification
    /// (not just a successful driver call). Called by the board modules at
    /// the end of their wiring-specific `touch_init`.
    pub(crate) fn finish_init(
        handle: sys::esp_lcd_touch_handle_t,
        io: sys::esp_lcd_panel_io_handle_t,
        reset_desc: &str,
    ) -> Result<Self, TouchError> {
        // The first read after reset reports a phantom point (observed
        // 481,481 with nothing touching the panel) - the status register
        // latches garbage across reset. One discarded read clears it.
        let mut touch = Self { handle };
        let _ = touch.poll();

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
            "GT911 initialized: product id \"{}\" ({:02X?}), polled mode, {}",
            id_str,
            id,
            reset_desc
        );

        Ok(touch)
    }

    /// Poll the controller once. Returns the primary touch point, or None
    /// when nothing is pressed. Called from the main loop on every board -
    /// even where INT is routed we poll, keeping one code path (BOARDS.md:
    /// no per-board control flow above the board module).
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
