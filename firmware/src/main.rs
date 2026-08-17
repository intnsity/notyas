//! notyas firmware, milestone 0.1.0-m2 (part 1): display + touch bring-up.
//!
//! Boots on the Waveshare ESP32-P4-WiFi6-Touch-LCD-4B (rev v1.3), locks down
//! the radio, brings up the 720x720 MIPI-DSI panel and GT911 touch, and
//! renders the Butter Paper demo shell. Touches are drawn live and logged
//! over UART0 (CH343); a heartbeat banner logs once per second.

mod display;
mod theme;
mod touch;

use std::ffi::CStr;
use std::thread;
use std::time::{Duration, Instant};

use embedded_graphics::mono_font::ascii::{FONT_10X20, FONT_6X13, FONT_9X15};
use embedded_graphics::mono_font::MonoTextStyle;
use embedded_graphics::prelude::*;
use embedded_graphics::primitives::{PrimitiveStyleBuilder, Rectangle};
use embedded_graphics::text::renderer::TextRenderer;
use embedded_graphics::text::{Alignment, Baseline, Text};
use esp_idf_svc::hal::gpio::PinDriver;
use esp_idf_svc::hal::peripherals::Peripherals;
use esp_idf_svc::sys;

use crate::display::{Display, H_RES, V_RES};

const VERSION: &str = "0.1.0-m2";
const BACKLIGHT_PERCENT: u32 = 80;

// Centered card. 720x720 panel; sizes chosen for the built-in mono fonts -
// the real (IBM Plex derived) glyph atlases land in a parallel workstream.
const CARD: Rectangle = Rectangle::new(Point::new(120, 220), Size::new(480, 280));

fn main() {
    // Apply esp-idf-sys patches (rt linkage etc.) - must be first per template.
    sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();

    let peripherals = Peripherals::take().expect("peripherals already taken");

    // AIRGAP LOCKDOWN - do this before anything else.
    // GPIO54 is wired to the ESP32-C6 radio module's enable pin (CHIP_PU).
    // Driving it LOW and never releasing it holds the C6 - the only radio on
    // this board - in reset for the entire power cycle. This is lockdown
    // layer 2 of the security model (layer 1: no WiFi stack in the build;
    // layer 3: the C6 SDIO GPIOs are never configured as an SDIO host).
    let mut c6_reset = PinDriver::output(peripherals.pins.gpio54)
        .expect("failed to claim GPIO54 (C6 enable)");
    c6_reset.set_low().expect("failed to drive GPIO54 low");
    log::info!("C6 radio held in reset (GPIO54 low)");

    // Backlight enable (GPIO33) stays LOW until the first frame is flushed,
    // so the panel never shows uninitialized framebuffer content.
    let mut backlight_enable = PinDriver::output(peripherals.pins.gpio33)
        .expect("failed to claim GPIO33 (backlight enable)");
    backlight_enable
        .set_low()
        .expect("failed to drive GPIO33 low");

    let mut display = Display::init().expect("display init");

    // Text styles are constructed here and passed down as generic
    // TextRenderer values: swapping the font source (mono fonts now, the
    // notyas glyph atlases later) only changes these three lines.
    let title_style = MonoTextStyle::new(&FONT_10X20, theme::INK_PRIMARY);
    let version_style = MonoTextStyle::new(&FONT_6X13, theme::INK_SECONDARY);
    let prompt_style = MonoTextStyle::new(&FONT_9X15, theme::INK_MUTED);
    let touch_style = MonoTextStyle::new(&FONT_9X15, theme::ACCENT);

    paint_shell(&mut display, title_style, version_style);
    draw_status(&mut display, prompt_style, "touch the screen");
    display.flush().expect("framebuffer flush");

    // Panel is streaming real content now - light it up.
    backlight_enable
        .set_high()
        .expect("failed to drive GPIO33 high");
    display::backlight_init(BACKLIGHT_PERCENT).expect("backlight PWM init");

    let mut touch = touch::Touch::init().expect("touch init");

    let idf_version = unsafe { CStr::from_ptr(sys::esp_get_idf_version()) }
        .to_str()
        .unwrap_or("<invalid>");

    let mut shown: Option<(u16, u16)> = None;
    let mut last_heartbeat = Instant::now();
    log::info!("notyas {VERSION} shell up");
    loop {
        if let Some((x, y)) = touch.poll() {
            if shown != Some((x, y)) {
                shown = Some((x, y));
                log::info!("touch x={x} y={y}");
                draw_status(&mut display, touch_style, &format!("touch {x},{y}"));
                display.flush_area(&status_area()).expect("status flush");
            }
        }

        if last_heartbeat.elapsed() >= Duration::from_secs(1) {
            last_heartbeat = Instant::now();
            log::info!(
                "notyas {VERSION} | IDF {idf_version} | free heap {} bytes",
                unsafe { sys::esp_get_free_heap_size() }
            );
        }

        // GT911 poll cadence; also yields so the idle task feeds the WDT.
        thread::sleep(Duration::from_millis(25));
    }
    // Unreachable: c6_reset and backlight_enable must never drop - dropping
    // a PinDriver resets its pin (releasing the C6, blanking the panel).
}

/// Static shell: paper-1 page, centered paper-2 card with a 1px hairline
/// border, title and version. Drawn once; only the status line repaints.
fn paint_shell<S>(display: &mut Display, title_style: S, version_style: S)
where
    S: TextRenderer<Color = embedded_graphics::pixelcolor::Rgb565>,
{
    // Infallible error type - unwraps cannot fire.
    display
        .fill_solid(
            &Rectangle::new(Point::zero(), Size::new(H_RES as u32, V_RES as u32)),
            theme::PAPER_1,
        )
        .unwrap();

    let card_style = PrimitiveStyleBuilder::new()
        .fill_color(theme::PAPER_2)
        .stroke_color(theme::HAIRLINE)
        .stroke_width(1)
        .build();
    CARD.into_styled(card_style).draw(display).unwrap();

    let center_x = CARD.top_left.x + CARD.size.width as i32 / 2;
    Text::with_alignment(
        "notyas",
        Point::new(center_x, CARD.top_left.y + 90),
        title_style,
        Alignment::Center,
    )
    .draw(display)
    .unwrap();
    Text::with_alignment(
        VERSION,
        Point::new(center_x, CARD.top_left.y + 125),
        version_style,
        Alignment::Center,
    )
    .draw(display)
    .unwrap();
}

/// Live status line region, inset to keep the card's hairline border intact.
fn status_area() -> Rectangle {
    Rectangle::new(
        CARD.top_left + Point::new(1, 190),
        Size::new(CARD.size.width - 2, 40),
    )
}

/// Repaint the status line: card background, then centered text. The style
/// is a parameter (muted prompt vs accent coordinates - and later, the real
/// font atlases) so the caller owns the font source.
fn draw_status<S>(display: &mut Display, style: S, message: &str)
where
    S: TextRenderer<Color = embedded_graphics::pixelcolor::Rgb565>,
{
    let area = status_area();
    display.fill_solid(&area, theme::PAPER_2).unwrap();
    let center = area.top_left + Point::new(area.size.width as i32 / 2, area.size.height as i32 / 2);
    Text::with_text_style(
        message,
        center,
        style,
        embedded_graphics::text::TextStyleBuilder::new()
            .alignment(Alignment::Center)
            .baseline(Baseline::Middle)
            .build(),
    )
    .draw(display)
    .unwrap();
}
