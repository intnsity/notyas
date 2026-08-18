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
//! 5. Main loop: Ui::tick (deferred work) -> GT911 poll -> Down/Move/Up
//!    synthesis -> Ui::touch -> and, only when input arrived, full-screen
//!    Ui::draw into the back buffer -> whole-frame publish. Repaints are
//!    event-driven: the Ui's pixels are a pure function of its state, and
//!    this loop is the only thing that mutates that state (touch events,
//!    Ui::tick; set_verify_info before the first frame), so "an event was
//!    fed or tick did work" is a complete change signal - an idle device
//!    performs ZERO repaints (provable from the heartbeat's repaint counter)
//!    and the scan-out buffer never shows a partial frame (see display.rs).
//!    The full draw+publish time is measured and logged once.
//!
//! Everything hardware-specific lives in src/board/<name>.rs behind the flat
//! surface re-exported by `board`; this file is board-agnostic.

mod board;
mod display;
/// 0.2.0-m4a hardware-in-the-loop test console. `--features hil-console` is the only
/// thing that compiles it in, build.rs refuses that feature in a release profile, and
/// the release symbol check asserts its absence from a shipped binary (Q41).
#[cfg(feature = "hil-console")]
mod hil;
/// 0.2.0-m3h development instrument: the esp-idf-hmac exercise against VIRTUAL
/// eFuses. Not part of the product image - `--features hmac-virtual-check` is
/// the only thing that compiles it in, and that feature refuses to build
/// against real fuses (esp-idf-hmac/build.rs).
#[cfg(feature = "hmac-virtual-check")]
mod hmac_check;
/// Temporary 0.2.0-m1 hardware-measurement harness. Not part of the product
/// image: `--features measure` is the only thing that compiles it in, and a
/// build that does never reaches the UI (see the call site below).
#[cfg(feature = "measure")]
mod measure;
mod readout;
/// The sealed store: the two `esp_partition` regions, the device-binding MAC, the PSRAM
/// Argon2id working set and the session lifetime. Product code, always compiled.
mod store;
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
use notyas_ui::{QrData, TouchEvent, Ui, UiRequest};

use crate::display::Display;

/// Firmware semver (workspace releases in lockstep, so this is the product version).
const VERSION: &str = env!("CARGO_PKG_VERSION");
const BACKLIGHT_PERCENT: u8 = 80;
/// GT911 poll cadence; the sleep also yields so the idle task feeds the WDT.
const POLL_MS: u64 = 25;

// A measurement build ends inside the harness; everything after that call is
// dead by design, and only in that build.
#[cfg_attr(feature = "measure", allow(unreachable_code))]
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

    // Measurement build (feature `measure`, off by default): run the harness
    // here - after the self-test proves the crypto core, before any peripheral
    // takes PSRAM or the flash bus - and never come back. Argon2id scratch
    // sizing depends on the PSRAM heap being untouched, and the flash timings
    // depend on nothing else driving the bus.
    #[cfg(feature = "measure")]
    measure::run();

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

    // The sealed store, brought up AFTER the panel so the heap numbers it reports are
    // the ones that matter: what is left with the framebuffers already standing. A
    // failure here is not fatal - the stateless flow needs no storage at all, and a
    // device that cannot mount its store must still be usable as a 0.1.0 device and must
    // say why on the Verify screen rather than refusing to boot.
    let mut store = match store::Store::bring_up() {
        Ok(mut s) => {
            let r = s.report().clone();
            log::info!(
                "store: key {} | state {} | records @0x{:x} | ledger @0x{:x}",
                r.provenance,
                store::state_label(r.state),
                r.records_base,
                r.ledger_base
            );
            log::info!(
                "store: argon2 scratch {} bytes in PSRAM | free PSRAM {} -> {} (delta {}) | free internal {}",
                r.scratch_bytes,
                r.free_psram_before,
                r.free_psram_after,
                r.free_psram_before.saturating_sub(r.free_psram_after),
                store::free_internal()
            );
            // VERIFY.md 6 / Q61: counted before the user is shown any verdict, and only
            // on a formatted store (R24 - a blank device still writes nothing).
            s.record_boot();
            Some(s)
        }
        Err(e) => {
            log::error!("store: unavailable: {e:?} - the stateless flow is unaffected");
            None
        }
    };

    // The product UI, laid out for this board's panel, fed with measured facts.
    let mut ui = Ui::new(board::DISPLAY_WIDTH, board::DISPLAY_HEIGHT);
    // One pass over the chip and flash, then everything downstream is a
    // rendering of it: the nine-row screen, the boot-log readout and (at m4b)
    // the QR export all read the same struct, so they cannot disagree.
    let ro = readout::read();
    let info = verify::build(&st, &ro);
    log::info!("verify: fw {} | {} | {}", info.firmware_version, info.board, info.platform);
    log::info!("verify: radio: {}", info.radio);
    log::info!(
        "verify: secure boot: {} | flash encryption: {}",
        info.secure_boot,
        info.flash_encryption
    );
    verify::log_readout(&ro);

    // Development instrument, compiled out of every product build. Runs after
    // the readout so the log shows the true (unburned) eFuse state first and
    // the virtual-mode changes second, in that order and clearly separated.
    #[cfg(feature = "hmac-virtual-check")]
    hmac_check::run();

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

    // Measured, not assumed. m4a found the previous main-task stack size by taking a
    // stack protection fault inside the key ladder; a headroom number printed at every
    // boot is the form of that lesson that cannot rot (see sdkconfig.base.defaults).
    log::info!(
        "main task stack: {} bytes free of {} (low-water mark since boot)",
        store::stack_headroom(),
        store::MAIN_STACK_BYTES
    );

    let idf_version = unsafe { CStr::from_ptr(sys::esp_get_idf_version()) }
        .to_str()
        .unwrap_or("<invalid>");

    log::info!("notyas {VERSION} ui up on {}", board::BOARD_NAME);

    // The test console comes up last, so the boot log above it is the ordinary one and a
    // capture can be split at the banner. Its first act is to print the mount verdict:
    // after a power cut taken mid-seal, that line is the evidence, and it must appear
    // before anything the operator does can change the state it describes.
    #[cfg(feature = "hil-console")]
    let mut console = {
        let mut c = hil::Console::install();
        c.boot_banner(&mut store);
        c
    };

    // The GT911 reports the current point or nothing; Down/Move/Up are
    // synthesized from consecutive polls: point after none = Down, point
    // after point = Move, none after point = Up (at the last seen point).
    let mut last_point: Option<(u16, u16)> = None;
    let mut last_screen = ui.screen();
    let mut last_network = ui.network();
    let mut last_heartbeat = Instant::now();
    // Total repaints since boot, reported in every heartbeat: an untouched
    // device must show the same number for the whole idle stretch - the
    // provable form of "static screens repaint zero times".
    let mut repaints: u64 = 0;
    loop {
        // Deferred work the UI parked for us, at the TOP of the iteration and
        // therefore strictly AFTER the frame that entered the parked state was
        // published. That ordering is the whole point: `Ui::touch` answers a
        // commit (keyboard Done) by switching to the Deriving interstitial and
        // returning immediately, so this loop paints "Deriving" first and only
        // then spends the ~830 ms of PBKDF2 + per-scheme derivation here.
        // Running tick in the same iteration as the touch would paint the
        // result only, leaving the panel frozen on the passphrase screen for
        // the whole computation - the m4 glitch this ordering fixes.
        let t_tick = Instant::now();
        let mut dirty = ui.tick();
        if dirty {
            // Duration only - no seed, phrase or passphrase material. Worth a
            // line: this is the one operation slow enough for a user to call
            // the device hung, so a regression here is a user-visible freeze.
            log::info!("derivation: finished in {} ms", t_tick.elapsed().as_millis());
        }

        // Auto-lock, ticked from the wall clock rather than from a pass count so that a
        // pass which spent 1.8 s inside an Argon2id derivation ages the session by
        // 1.8 s. Placed AFTER `ui.tick` for that reason: a long derivation must be
        // charged to the session it happened during, not to the next pass. A pass that
        // locks is a pass that must repaint.
        if store.as_mut().is_some_and(store::Store::tick) {
            dirty = true;
        }

        // One non-blocking UART read per pass. Zero-tick timeout, so an idle console
        // cannot perturb the idle-repaint or heap invariants the heartbeat proves.
        #[cfg(feature = "hil-console")]
        console.poll(&mut store);

        let point = touch.poll();
        // Event-driven dirty flag (see the module docs): any synthesized
        // event marks the frame dirty, except a Move that goes nowhere (a
        // resting finger re-reports the same point every poll - repainting
        // an identical frame 40x/s would be flicker-free but pointless).
        let request = match (last_point, point) {
            (None, Some((x, y))) => {
                log::info!("touch down x={x} y={y}");
                dirty = true;
                ui.touch(TouchEvent::Down { x: x as i32, y: y as i32 })
            }
            (Some(prev), Some((x, y))) => {
                dirty |= prev != (x, y);
                ui.touch(TouchEvent::Move { x: x as i32, y: y as i32 })
            }
            (Some((x, y)), None) => {
                log::info!("touch up x={x} y={y}");
                dirty = true;
                ui.touch(TouchEvent::Up { x: x as i32, y: y as i32 })
            }
            (None, None) => None,
        };
        last_point = point;

        answer_qr_request(&mut ui, request);

        // Screen transitions are the UI's audit trail (ScreenId carries no
        // data, so this is safe to log - notyas-ui's Debug discipline). The
        // network setting is public state and logged the same way.
        let screen = ui.screen();
        if screen != last_screen {
            last_screen = screen;
            log::info!("screen: {screen:?}");
        }
        let network = ui.network();
        if network != last_network {
            last_network = network;
            log::info!("network: {network:?}");
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

/// Answer a [`UiRequest`] from `Ui::touch`. The UI never computes a QR (it is
/// no_std; the encoder needs std): a tap on a QR button surfaces here as a
/// request naming a PUBLIC value - receive address or account xpub, the only
/// QR targets that exist in 0.1.0 - and the finished matrix goes back in
/// before the same iteration's repaint. The label is a derivation path /
/// caption (safe to log); the payload is not logged, as a matter of general
/// log hygiene even for public values.
fn answer_qr_request(ui: &mut Ui, request: Option<UiRequest>) {
    let Some(UiRequest::Qr(target)) = request else { return };
    match notyas_core::qr::matrix(&target.payload) {
        Ok(matrix) => match QrData::from_matrix(&matrix) {
            Some(data) => {
                log::info!(
                    "qr: open '{}' ({} chars -> {} modules/side)",
                    target.label,
                    target.payload.len(),
                    data.size()
                );
                ui.show_qr(target, data);
            }
            // Unreachable with the core encoder (always square); surfaced
            // rather than silently dropped, per the no-silent-failure rule.
            None => log::error!("qr: encoder returned a non-square matrix"),
        },
        Err(e) => log::error!("qr: '{}': {e}", target.label),
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
