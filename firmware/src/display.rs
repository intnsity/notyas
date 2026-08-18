//! Board-agnostic display plumbing: an embedded-graphics `DrawTarget` over
//! the esp_lcd panel driver's own PSRAM framebuffer, plus the small esp_err
//! helpers the board modules share.
//!
//! Framebuffer strategy (identical on every supported bus): the panel driver
//! (MIPI-DSI DPI on the Waveshare board, LCDCAM RGB on the Elecrow 5 inch)
//! allocates its framebuffer in PSRAM and streams it continuously. We draw
//! straight into that buffer and publish by passing the same pointer back
//! through `esp_lcd_panel_draw_bitmap`: both drivers recognize their own
//! framebuffer, skip the copy, and perform only the required cache writeback
//! (esp_cache_msync) for the dirtied window. One buffer, no memcpy, and the
//! cache maintenance stays inside the driver instead of being hand-rolled.
//! (Verified in IDF v5.5.4: esp_lcd_panel_dpi.c and esp_lcd_panel_rgb.c both
//! take the no-copy path when the draw buffer lies inside a driver fb.)
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
    fb: *mut u16,
    width: usize,
    height: usize,
}

impl Display {
    /// Wrap a panel whose driver-owned RGB565 framebuffer was fetched by the
    /// board module (`esp_lcd_dpi_panel_get_frame_buffer` /
    /// `esp_lcd_rgb_panel_get_frame_buffer`).
    ///
    /// Safety contract (callers are the board modules only): `fb` points at
    /// a width*height RGB565 buffer owned by `panel`'s driver and valid for
    /// the process lifetime; the panel is initialized and streaming.
    pub fn over_panel_fb(
        panel: sys::esp_lcd_panel_handle_t,
        fb: *mut u16,
        width: usize,
        height: usize,
    ) -> Self {
        assert!(!fb.is_null(), "panel driver returned a null framebuffer");
        Self { panel, fb, width, height }
    }

    pub fn size_rect(&self) -> Rectangle {
        Rectangle::new(Point::zero(), Size::new(self.width as u32, self.height as u32))
    }

    /// Publish the whole framebuffer to the panel (cache writeback only).
    pub fn flush(&mut self) -> Result<(), DisplayError> {
        self.flush_area(&self.size_rect())
    }

    /// Publish one window of the framebuffer. `area` is clipped to the panel.
    pub fn flush_area(&mut self, area: &Rectangle) -> Result<(), DisplayError> {
        let Some(area) = self.clip(area) else {
            return Ok(());
        };
        let (x0, y0) = (area.top_left.x, area.top_left.y);
        // esp_lcd end coordinates are exclusive. Passing the framebuffer's own
        // base pointer makes the driver take the no-copy cache-sync path; the
        // window offsets are computed driver-side from the coordinates.
        esp_check!(
            sys::esp_lcd_panel_draw_bitmap(
                self.panel,
                x0,
                y0,
                x0 + area.size.width as i32,
                y0 + area.size.height as i32,
                self.fb as *const c_void,
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
                // Bounds just checked; the framebuffer is width*height u16s.
                unsafe { *self.fb.add(p.y as usize * self.width + p.x as usize) = raw };
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
            let row = unsafe {
                core::slice::from_raw_parts_mut(
                    self.fb.add(y * self.width + x0),
                    area.size.width as usize,
                )
            };
            row.fill(raw);
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
