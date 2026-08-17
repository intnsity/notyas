//! MIPI-DSI display bring-up (ST7703 panel) and an embedded-graphics
//! `DrawTarget` over the DPI panel driver's own PSRAM framebuffer.
//!
//! Init order is load-bearing (HARDWARE.md, "power-rail requirements"):
//! internal LDO channel 3 at 2500 mV powers the MIPI DPHY and must be
//! acquired BEFORE the DSI bus is created, or `esp_lcd_new_dsi_bus` hangs.
//! Channel 4 at 3300 mV powers the GPIO39-48 IO bank.
//!
//! Framebuffer strategy: the DPI panel driver allocates its framebuffer in
//! PSRAM and streams it continuously over DSI. We draw straight into that
//! buffer (via `esp_lcd_dpi_panel_get_frame_buffer`) and publish by passing
//! the same pointer back through `esp_lcd_panel_draw_bitmap`: the driver
//! recognizes its own framebuffer, skips the copy, and performs only the
//! required cache writeback (esp_cache_msync) for the dirtied window. This
//! is the simplest reliable path - one buffer, no memcpy, and the cache
//! maintenance stays inside the driver instead of being hand-rolled here.

use core::ffi::c_void;

use embedded_graphics::pixelcolor::raw::RawU16;
use embedded_graphics::prelude::*;
use embedded_graphics::primitives::Rectangle;
use esp_idf_svc::sys;

pub const H_RES: usize = 720;
pub const V_RES: usize = 720;

// From the board schematic (HARDWARE.md GPIO map).
const GPIO_LCD_RESET: i32 = 27;
const GPIO_BACKLIGHT_PWM: i32 = 26;

/// Values of `ST7703_PANEL_BUS_DSI_2CH_CONFIG()` /
/// `ST7703_720_720_PANEL_60HZ_DPI_CONFIG()` from esp_lcd_st7703.h v2 -
/// function-like macros, so bindgen cannot surface them; replicated here
/// verbatim and checked against the vendored header on component updates.
const DSI_LANES: u8 = 2;
const DSI_LANE_BIT_RATE_MBPS: f32 = 480.0;
const DPI_CLOCK_FREQ_MHZ: f32 = 38.0;

macro_rules! esp_check {
    ($call:expr, $what:literal) => {{
        let err = unsafe { $call };
        if err != sys::ESP_OK {
            return Err(DisplayError { what: $what, code: err });
        }
    }};
}

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

pub struct Display {
    panel: sys::esp_lcd_panel_handle_t,
    fb: *mut u16,
    // Held, never released: dropping channel 3 powers down the MIPI DPHY
    // mid-stream; channel 4 feeds the GPIO39-48 bank (UART among it).
    _ldo_dphy: sys::esp_ldo_channel_handle_t,
    _ldo_vo4: sys::esp_ldo_channel_handle_t,
}

impl Display {
    /// Full display pipeline bring-up. Backlight is NOT touched here - the
    /// caller enables it after the first frame is flushed, so the panel never
    /// shows uninitialized framebuffer content.
    pub fn init() -> Result<Self, DisplayError> {
        // 1. Power rails (order: before any DSI register access).
        let ldo_dphy = acquire_ldo(3, 2500)?;
        log::info!("LDO channel 3 acquired at 2500 mV (MIPI DPHY)");
        let ldo_vo4 = acquire_ldo(4, 3300)?;
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
                h_size: H_RES as u32,
                v_size: V_RES as u32,
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
        assert!(!fb.is_null(), "DPI panel returned a null framebuffer");
        log::info!("DPI framebuffer at {fb:p} (PSRAM)");

        Ok(Self {
            panel,
            fb: fb as *mut u16,
            _ldo_dphy: ldo_dphy,
            _ldo_vo4: ldo_vo4,
        })
    }

    /// Publish the whole framebuffer to the panel (cache writeback only).
    pub fn flush(&mut self) -> Result<(), DisplayError> {
        self.flush_area(&Rectangle::new(
            Point::zero(),
            Size::new(H_RES as u32, V_RES as u32),
        ))
    }

    /// Publish one window of the framebuffer. `area` is clipped to the panel.
    pub fn flush_area(&mut self, area: &Rectangle) -> Result<(), DisplayError> {
        let Some(area) = clip(area) else {
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
}

/// Clip a rectangle to the panel; None when fully outside.
fn clip(area: &Rectangle) -> Option<Rectangle> {
    let screen = Rectangle::new(Point::zero(), Size::new(H_RES as u32, V_RES as u32));
    let clipped = area.intersection(&screen);
    (!clipped.is_zero_sized()).then_some(clipped)
}

impl OriginDimensions for Display {
    fn size(&self) -> Size {
        Size::new(H_RES as u32, V_RES as u32)
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
            if (0..H_RES as i32).contains(&p.x) && (0..V_RES as i32).contains(&p.y) {
                let raw = RawU16::from(color).into_inner();
                // Bounds just checked; the framebuffer is H_RES*V_RES u16s.
                unsafe { *self.fb.add(p.y as usize * H_RES + p.x as usize) = raw };
            }
        }
        Ok(())
    }

    fn fill_solid(&mut self, area: &Rectangle, color: Self::Color) -> Result<(), Self::Error> {
        let Some(area) = clip(area) else {
            return Ok(());
        };
        let raw = RawU16::from(color).into_inner();
        let (x0, y0) = (area.top_left.x as usize, area.top_left.y as usize);
        for y in y0..y0 + area.size.height as usize {
            let row = unsafe {
                core::slice::from_raw_parts_mut(
                    self.fb.add(y * H_RES + x0),
                    area.size.width as usize,
                )
            };
            row.fill(raw);
        }
        Ok(())
    }
}

fn acquire_ldo(chan_id: i32, voltage_mv: i32) -> Result<sys::esp_ldo_channel_handle_t, DisplayError> {
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
    Ok(handle)
}

/// Backlight PWM on GPIO26, replicating the Waveshare BSP's proven LEDC
/// setup exactly: low-speed timer 1 / channel 1, 5 kHz, 10-bit resolution,
/// INVERTED output (the board's backlight driver PWM input is active-low;
/// duty N of 1023 still means N/1023 brightness because of the invert flag).
/// The separate backlight ENABLE pin (GPIO33) is owned by main.
pub fn backlight_init(brightness_percent: u32) -> Result<(), DisplayError> {
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

    backlight_set(brightness_percent)
}

pub fn backlight_set(brightness_percent: u32) -> Result<(), DisplayError> {
    let duty = 1023 * brightness_percent.min(100) / 100;
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
    log::info!("backlight PWM duty set to {brightness_percent}%");
    Ok(())
}
