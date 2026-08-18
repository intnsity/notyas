//! notyas firmware, milestone 0.1.0-m2: display + touch demo shell,
//! multi-board (docs/BOARDS.md).
//!
//! Boots on the board selected at compile time by exactly one `board-*`
//! feature, locks down the radio FIRST, brings up the panel and GT911 touch,
//! and renders the Butter Paper demo shell. Touches are drawn live and
//! logged over UART0; a heartbeat banner logs once per second.
//!
//! Everything hardware-specific lives in src/board/<name>.rs behind the flat
//! surface re-exported by `board`; this file is board-agnostic and lays the
//! shell out from `board::DISPLAY_WIDTH/HEIGHT` (no hardcoded pixels).

mod board;
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
use esp_idf_svc::sys;

use crate::display::Display;

const VERSION: &str = "0.1.0-m2";
const BACKLIGHT_PERCENT: u8 = 80;

/// Demo-shell geometry derived from the board's panel resolution. Fractions
/// of the display, not literals, so the same shell lays out on 720x720
/// (square, Waveshare) and 800x480 (landscape, Elecrow). The full `Layout`
/// system from BOARDS.md lands with the real screens (notyas-ui workstream);
/// this covers the one card + status line the m2 shell needs.
struct ShellLayout {
    card: Rectangle,
}

impl ShellLayout {
    fn new(width: u32, height: u32) -> Self {
        let card_w = width * 2 / 3;
        let card_h = height * 2 / 5;
        let card = Rectangle::new(
            Point::new(
                (width - card_w) as i32 / 2,
                (height - card_h) as i32 / 2,
            ),
            Size::new(card_w, card_h),
        );
        Self { card }
    }

    fn title_pos(&self) -> Point {
        self.center_x_at(self.card.size.height as i32 / 3)
    }

    fn version_pos(&self) -> Point {
        self.center_x_at(self.card.size.height as i32 / 3 + 35)
    }

    /// Live status line region, inset to keep the card's hairline border.
    fn status_area(&self) -> Rectangle {
        Rectangle::new(
            self.card.top_left + Point::new(1, self.card.size.height as i32 * 2 / 3 - 20),
            Size::new(self.card.size.width - 2, 40),
        )
    }

    fn center_x_at(&self, dy: i32) -> Point {
        Point::new(
            self.card.top_left.x + self.card.size.width as i32 / 2,
            self.card.top_left.y + dy,
        )
    }
}

fn main() {
    // Apply esp-idf-sys patches (rt linkage etc.) - must be first per template.
    sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();

    // AIRGAP LOCKDOWN - before anything else. The board module drives its
    // radio kill line (BOARDS.md, "The airgap invariant, per board") and
    // never releases it.
    board::radio_lockdown();
    // The per-board airgap surface, logged verbatim (same text the Verify
    // screen will show once it exists): positive identification of what this
    // image believes it runs on and how the radio is held dead.
    log::info!(
        "board: {} | flash {} MB | radio kill GPIO{}",
        board::BOARD_NAME,
        board::FLASH_SIZE_MB,
        board::RADIO_KILL_GPIO
    );
    log::info!("airgap: {}", board::RADIO_KILL_DOC);

    if board::UNTESTED {
        log::warn!(
            "UNTESTED BOARD CONFIG: {} - config from vendor docs only, never verified on hardware",
            board::BOARD_NAME
        );
    }

    let mut display = board::display_init();
    let layout = ShellLayout::new(board::DISPLAY_WIDTH, board::DISPLAY_HEIGHT);

    // Text styles are constructed here and passed down as generic
    // TextRenderer values: swapping the font source (mono fonts now, the
    // notyas glyph atlases later) only changes these three lines.
    let title_style = MonoTextStyle::new(&FONT_10X20, theme::INK_PRIMARY);
    let version_style = MonoTextStyle::new(&FONT_6X13, theme::INK_SECONDARY);
    let prompt_style = MonoTextStyle::new(&FONT_9X15, theme::INK_MUTED);
    let touch_style = MonoTextStyle::new(&FONT_9X15, theme::ACCENT);

    paint_shell(&mut display, &layout, title_style, version_style);
    draw_status(&mut display, &layout, prompt_style, "touch the screen");
    display.flush().expect("framebuffer flush");

    // Panel is streaming real content now - light it up.
    board::backlight_set(BACKLIGHT_PERCENT);

    let mut touch = board::touch_init();

    let idf_version = unsafe { CStr::from_ptr(sys::esp_get_idf_version()) }
        .to_str()
        .unwrap_or("<invalid>");

    let mut shown: Option<(u16, u16)> = None;
    let mut last_heartbeat = Instant::now();
    log::info!("notyas {VERSION} shell up on {}", board::BOARD_NAME);
    loop {
        if let Some((x, y)) = touch.poll() {
            if shown != Some((x, y)) {
                shown = Some((x, y));
                log::info!("touch x={x} y={y}");
                draw_status(&mut display, &layout, touch_style, &format!("touch {x},{y}"));
                display.flush_area(&layout.status_area()).expect("status flush");
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
}

/// Static shell: paper-1 page, centered paper-2 card with a 1px hairline
/// border, title and version. Drawn once; only the status line repaints.
fn paint_shell<S>(display: &mut Display, layout: &ShellLayout, title_style: S, version_style: S)
where
    S: TextRenderer<Color = embedded_graphics::pixelcolor::Rgb565>,
{
    // Infallible error type - unwraps cannot fire.
    display
        .fill_solid(&display.size_rect(), theme::PAPER_1)
        .unwrap();

    let card_style = PrimitiveStyleBuilder::new()
        .fill_color(theme::PAPER_2)
        .stroke_color(theme::HAIRLINE)
        .stroke_width(1)
        .build();
    layout.card.into_styled(card_style).draw(display).unwrap();

    Text::with_alignment("notyas", layout.title_pos(), title_style, Alignment::Center)
        .draw(display)
        .unwrap();
    Text::with_alignment(VERSION, layout.version_pos(), version_style, Alignment::Center)
        .draw(display)
        .unwrap();
}

/// Repaint the status line: card background, then centered text. The style
/// is a parameter (muted prompt vs accent coordinates - and later, the real
/// font atlases) so the caller owns the font source.
fn draw_status<S>(display: &mut Display, layout: &ShellLayout, style: S, message: &str)
where
    S: TextRenderer<Color = embedded_graphics::pixelcolor::Rgb565>,
{
    let area = layout.status_area();
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
