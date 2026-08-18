//! notyas firmware, milestone 0.1.0-m3: boot self-test + the real product UI,
//! multi-board (docs/BOARDS.md).
//!
//! Boot order is load-bearing (SECURITY.md):
//!
//! 1. Radio lockdown - FIRST, before anything else (invariant 1).
//! 2. notyas-core boot self-test - pure computation, before any peripheral,
//!    so a broken crypto build is known before the device looks alive.
//! 3. Display bring-up. On self-test failure the panel still comes up and
//!    shows the verdict (invariant 5 demands hard failure surfaced on
//!    screen, not a silent brick), then the device refuses to operate.
//! 4. The notyas-ui screens, fed with a VerifyInfo built entirely from
//!    values read at boot (src/verify.rs).
//! 5. Main loop: GT911 poll -> Down/Move/Up synthesis -> Ui::touch -> and,
//!    only when input arrived, full-screen Ui::draw into the back buffer ->
//!    whole-frame publish. Repaints are event-driven: the Ui's pixels are a
//!    pure function of its state, and this loop is the only thing that
//!    mutates that state (touch events; set_verify_info before the first
//!    frame), so "an event was fed" is a complete change signal - an idle
//!    device performs ZERO repaints (provable from the heartbeat's repaint
//!    counter) and the scan-out buffer never shows a partial frame (see
//!    display.rs). The full draw+publish time is measured and logged once.
//!
//! Everything hardware-specific lives in src/board/<name>.rs behind the flat
//! surface re-exported by `board`; this file is board-agnostic.

mod board;
mod display;
mod theme;
mod touch;
mod verify;

use std::ffi::CStr;
use std::thread;
use std::time::{Duration, Instant};

use embedded_graphics::prelude::*;
use esp_idf_svc::sys;
use notyas_core::selftest::{self, SelfTest};
use notyas_fonts::{draw_text, TextStyle, MONO_REGULAR_32, SANS_REGULAR_32, SANS_SEMIBOLD_44};
use notyas_ui::{TouchEvent, Ui};

use crate::display::Display;

/// Firmware semver (workspace releases in lockstep, so this is the product version).
const VERSION: &str = env!("CARGO_PKG_VERSION");
const BACKLIGHT_PERCENT: u8 = 80;
/// GT911 poll cadence; the sleep also yields so the idle task feeds the WDT.
const POLL_MS: u64 = 25;

fn main() {
    // Apply esp-idf-sys patches (rt linkage etc.) - must be first per template.
    sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();

    // AIRGAP LOCKDOWN - before anything else. The board module drives its
    // radio kill line (BOARDS.md, "The airgap invariant, per board") and
    // never releases it.
    board::radio_lockdown();
    // The per-board airgap surface, logged verbatim (the same facts the
    // Verify screen shows): positive identification of what this image
    // believes it runs on and how the radio is held dead.
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

    // Boot self-test, before any peripheral bring-up: pure computation over
    // pinned vectors (notyas-core::selftest), same verdict every boot.
    let t0 = Instant::now();
    let st = selftest::run();
    for check in &st.checks {
        log::info!(
            "selftest: {:<13} {}",
            check.name,
            if check.passed { "pass" } else { "FAIL" }
        );
    }
    log::info!(
        "selftest: {} in {} ms",
        verify::selftest_summary(&st),
        t0.elapsed().as_millis()
    );

    let mut display = board::display_init();

    if !st.passed() {
        // Invariant 5: hard failure, surfaced. The panel shows the verdict and
        // the device refuses to operate - it does not limp into the UI with a
        // crypto core that just failed its own vectors.
        paint_selftest_failure(&mut display, &st);
        display.flush().expect("failure-screen flush");
        board::backlight_set(BACKLIGHT_PERCENT);
        loop {
            log::error!("SELFTEST FAILED - device halted (reflash a verified release)");
            thread::sleep(Duration::from_secs(5));
        }
    }

    // The product UI, laid out for this board's panel, fed with measured facts.
    let mut ui = Ui::new(board::DISPLAY_WIDTH, board::DISPLAY_HEIGHT);
    let info = verify::build(&st);
    log::info!("verify: fw {} | {} | {}", info.firmware_version, info.board, info.platform);
    log::info!("verify: radio: {}", info.radio);
    log::info!(
        "verify: secure boot: {} | flash encryption: {}",
        info.secure_boot,
        info.flash_encryption
    );
    ui.set_verify_info(info);

    // First frame, timed: every repaint is a full-screen draw into the back
    // buffer plus a whole-frame publish (driver copy + cache writeback - see
    // display.rs), so this pair IS the cost of any later event-driven repaint.
    // Logged once here; per-frame timing would only spam the log.
    let t0 = Instant::now();
    ui.draw(&mut display).unwrap(); // draw errors are Infallible on this target
    let draw_ms = t0.elapsed().as_millis();
    let t0 = Instant::now();
    display.flush().expect("first frame publish");
    let publish_ms = t0.elapsed().as_millis();
    log::info!(
        "frame time: draw {draw_ms} ms + publish {publish_ms} ms ({}x{} full repaint)",
        board::DISPLAY_WIDTH,
        board::DISPLAY_HEIGHT
    );

    // Panel is streaming real content now - light it up.
    board::backlight_set(BACKLIGHT_PERCENT);

    let mut touch = board::touch_init();

    let idf_version = unsafe { CStr::from_ptr(sys::esp_get_idf_version()) }
        .to_str()
        .unwrap_or("<invalid>");

    log::info!("notyas {VERSION} ui up on {}", board::BOARD_NAME);

    // The GT911 reports the current point or nothing; Down/Move/Up are
    // synthesized from consecutive polls: point after none = Down, point
    // after point = Move, none after point = Up (at the last seen point).
    let mut last_point: Option<(u16, u16)> = None;
    let mut last_screen = ui.screen();
    let mut last_heartbeat = Instant::now();
    // Total repaints since boot, reported in every heartbeat: an untouched
    // device must show the same number for the whole idle stretch - the
    // provable form of "static screens repaint zero times".
    let mut repaints: u64 = 0;
    loop {
        let point = touch.poll();
        // Event-driven dirty flag (see the module docs): any synthesized
        // event marks the frame dirty, except a Move that goes nowhere (a
        // resting finger re-reports the same point every poll - repainting
        // an identical frame 40x/s would be flicker-free but pointless).
        let mut dirty = false;
        match (last_point, point) {
            (None, Some((x, y))) => {
                log::info!("touch down x={x} y={y}");
                ui.touch(TouchEvent::Down { x: x as i32, y: y as i32 });
                dirty = true;
            }
            (Some(prev), Some((x, y))) => {
                ui.touch(TouchEvent::Move { x: x as i32, y: y as i32 });
                dirty = prev != (x, y);
            }
            (Some((x, y)), None) => {
                log::info!("touch up x={x} y={y}");
                ui.touch(TouchEvent::Up { x: x as i32, y: y as i32 });
                dirty = true;
            }
            (None, None) => {}
        }
        last_point = point;

        // Screen transitions are the UI's audit trail (ScreenId carries no
        // data, so this is safe to log - notyas-ui's Debug discipline).
        let screen = ui.screen();
        if screen != last_screen {
            last_screen = screen;
            log::info!("screen: {screen:?}");
        }

        if dirty {
            ui.draw(&mut display).unwrap();
            display.flush().expect("frame publish");
            repaints += 1;
            log::debug!("repaint {repaints} ({screen:?})");
        }

        if last_heartbeat.elapsed() >= Duration::from_secs(1) {
            last_heartbeat = Instant::now();
            log::info!(
                "notyas {VERSION} | IDF {idf_version} | free heap {} bytes | repaints {repaints}",
                unsafe { sys::esp_get_free_heap_size() }
            );
        }

        thread::sleep(Duration::from_millis(POLL_MS));
    }
}

/// The self-test failure screen. Deliberately NOT a notyas-ui screen: it must
/// render even though the crate stack under test just failed, so it uses only
/// the font atlases and this file. Layout derives from the display size (no
/// hardcoded pixels); colors are the Butter Paper danger/ink tokens.
fn paint_selftest_failure(display: &mut Display, st: &SelfTest) {
    let title = TextStyle { font: &SANS_SEMIBOLD_44, fg: theme::DANGER, bg: theme::PAPER_1 };
    let body = TextStyle { font: &SANS_REGULAR_32, fg: theme::INK_PRIMARY, bg: theme::PAPER_1 };
    let pass = TextStyle { font: &MONO_REGULAR_32, fg: theme::INK_SECONDARY, bg: theme::PAPER_1 };
    let fail = TextStyle { font: &MONO_REGULAR_32, fg: theme::DANGER, bg: theme::PAPER_1 };

    // Infallible on this target - unwraps cannot fire.
    display.fill_solid(&display.size_rect(), theme::PAPER_1).unwrap();

    let x = (board::DISPLAY_WIDTH / 12) as i32;
    let mut y = (board::DISPLAY_HEIGHT / 12) as i32;
    draw_text(display, "Self-test failed", Point::new(x, y), &title).unwrap();
    y += SANS_SEMIBOLD_44.line_height as i32 * 3 / 2;
    draw_text(
        display,
        "This device failed its boot self-test.",
        Point::new(x, y),
        &body,
    )
    .unwrap();
    y += SANS_REGULAR_32.line_height as i32;
    draw_text(display, "Do not use it. Reflash a verified release.", Point::new(x, y), &body)
        .unwrap();
    y += SANS_REGULAR_32.line_height as i32 * 3 / 2;
    for check in &st.checks {
        let (style, verdict) = if check.passed { (&pass, "pass") } else { (&fail, "FAIL") };
        let line = format!("{:<13} {}", check.name, verdict);
        draw_text(display, &line, Point::new(x, y), style).unwrap();
        y += MONO_REGULAR_32.line_height as i32;
    }
}
