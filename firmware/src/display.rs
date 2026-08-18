//! Board-agnostic display plumbing: an embedded-graphics `DrawTarget` over an
//! off-screen back buffer, published whole-frame to the esp_lcd panel driver,
//! plus the small esp_err helpers the board modules share.
//!
//! Framebuffer strategy (identical on every supported bus): the panel driver
//! (MIPI-DSI DPI on the Waveshare board, LCDCAM RGB on the Elecrow 5 inch)
//! allocates its framebuffer in PSRAM and streams it to the panel
//! continuously. We never draw into that live buffer: every screen repaint
//! begins by clearing to the page background, so drawing in place puts
//! half-drawn frames on glass at scan-out rate - the "m3 flicker". Instead,
//! all drawing lands in a heap back buffer (one allocation, PSRAM via the
//! spiram malloc pool) and [`Display::flush`] publishes the finished frame
//! through `esp_lcd_panel_draw_bitmap`, whose copy path memcpys into the
//! driver framebuffer row-contiguously and handles the cache writeback
//! (esp_cache_msync) itself. The scan-out buffer therefore only ever holds
//! either the previous complete frame or the next one.
//!
//! Why a back buffer + copy rather than the drivers' own double buffering
//! (`num_fbs = 2` + flip): the flip APIs differ per bus (DPI and RGB expose
//! different config knobs and semantics), enabling them is per-board config
//! - the board modules' territory - and the copy is one board-agnostic
//! mechanism that behaves identically on both paths. The copy cost is paid
//! only when a frame actually changes (the main loop repaints on input, not
//! on a timer), measured and logged once at startup.
//!
//! Board modules construct `Display` via [`Display::over_panel_fb`] after
//! their bus-specific bring-up; everything above this layer (theme, screens)
//! is board-independent and works at any resolution.

use core::ffi::c_void;

use embedded_graphics::pixelcolor::raw::RawU16;
use embedded_graphics::prelude::*;
use embedded_graphics::primitives::Rectangle;
use esp_idf_svc::sys;

#[derive(Debug)]
pub struct DisplayError {
    pub what: &'static str,
    pub code: sys::esp_err_t,
}

impl core::fmt::Display for DisplayError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} failed: esp_err 0x{:x}", self.what, self.code)
    }
}

/// Run an esp-idf call, mapping a non-ESP_OK result to `DisplayError`.
macro_rules! esp_check {
    ($call:expr, $what:literal) => {{
        let err = unsafe { $call };
        if err != esp_idf_svc::sys::ESP_OK {
            return Err($crate::display::DisplayError { what: $what, code: err });
        }
    }};
}
pub(crate) use esp_check;

pub struct Display {
    panel: sys::esp_lcd_panel_handle_t,
    /// The complete-frames-only staging buffer all drawing goes into.
    back: Vec<u16>,
    width: usize,
    height: usize,
}

impl Display {
    /// Wrap a panel whose bring-up the board module just finished. `fb` is the
    /// driver-owned framebuffer pointer the board fetched
    /// (`esp_lcd_dpi_panel_get_frame_buffer` /
    /// `esp_lcd_rgb_panel_get_frame_buffer`); it is validated but not retained
    /// - drawing goes through the back buffer and the driver's own copy path,
    /// never through this pointer (see the module docs). The parameter stays
    /// so the board-module contract (and its proof that the driver allocated
    /// a framebuffer at all) is unchanged.
    ///
    /// Safety contract (callers are the board modules only): the panel is
    /// initialized and streaming, and `fb` came from its driver.
    pub fn over_panel_fb(
        panel: sys::esp_lcd_panel_handle_t,
        fb: *mut u16,
        width: usize,
        height: usize,
    ) -> Self {
        assert!(!fb.is_null(), "panel driver returned a null framebuffer");
        // One allocation for the process lifetime. With the PSRAM malloc pool
        // enabled (sdkconfig), an allocation this size lands in PSRAM.
        let back = vec![0u16; width * height];
        Self { panel, back, width, height }
    }

    pub fn size_rect(&self) -> Rectangle {
        Rectangle::new(Point::zero(), Size::new(self.width as u32, self.height as u32))
    }

    /// Publish the back buffer as one complete frame. The driver memcpys it
    /// into its scan-out framebuffer and performs the cache writeback; partial
    /// frames can never reach the glass because nothing else writes there.
    pub fn flush(&mut self) -> Result<(), DisplayError> {
        esp_check!(
            sys::esp_lcd_panel_draw_bitmap(
                self.panel,
                0,
                0,
                // esp_lcd end coordinates are exclusive.
                self.width as i32,
                self.height as i32,
                self.back.as_ptr() as *const c_void,
            ),
            "esp_lcd_panel_draw_bitmap"
        );
        Ok(())
    }

    /// Clip a rectangle to the panel; None when fully outside.
    fn clip(&self, area: &Rectangle) -> Option<Rectangle> {
        let clipped = area.intersection(&self.size_rect());
        (!clipped.is_zero_sized()).then_some(clipped)
    }
}

impl OriginDimensions for Display {
    fn size(&self) -> Size {
        Size::new(self.width as u32, self.height as u32)
    }
}

impl DrawTarget for Display {
    type Color = embedded_graphics::pixelcolor::Rgb565;
    type Error = core::convert::Infallible;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Self::Color>>,
    {
        for Pixel(p, color) in pixels {
            if (0..self.width as i32).contains(&p.x) && (0..self.height as i32).contains(&p.y) {
                let raw = RawU16::from(color).into_inner();
                self.back[p.y as usize * self.width + p.x as usize] = raw;
            }
        }
        Ok(())
    }

    fn fill_solid(&mut self, area: &Rectangle, color: Self::Color) -> Result<(), Self::Error> {
        let Some(area) = self.clip(area) else {
            return Ok(());
        };
        let raw = RawU16::from(color).into_inner();
        let (x0, y0) = (area.top_left.x as usize, area.top_left.y as usize);
        for y in y0..y0 + area.size.height as usize {
            let start = y * self.width + x0;
            self.back[start..start + area.size.width as usize].fill(raw);
        }
        Ok(())
    }
}

/// Acquire an internal LDO channel and never release it (the handle is a raw
/// pointer with no Drop; power rails stay up for the whole power cycle by
/// construction). Shared by the board modules.
pub(crate) fn acquire_ldo(chan_id: i32, voltage_mv: i32) -> Result<(), DisplayError> {
    let config = sys::esp_ldo_channel_config_t {
        chan_id,
        voltage_mv,
        ..Default::default()
    };
    let mut handle: sys::esp_ldo_channel_handle_t = core::ptr::null_mut();
    esp_check!(
        sys::esp_ldo_acquire_channel(&config, &mut handle),
        "esp_ldo_acquire_channel"
    );
    Ok(())
}
