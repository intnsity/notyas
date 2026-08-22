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
/// Panel calibration instrument (src/diag.rs). Not part of the product image:
/// `--features diag-display` is the only thing that compiles it in, and such a
/// build holds the calibration frame forever (see the call site below).
#[cfg(feature = "diag-display")]
mod diag;
mod display;
/// The work in flight between one screen and the next (0.2.0-m6/m7): the open wallet, the
/// reviewed transaction, the signed bytes and a registration awaiting approval. Every
/// request that needs a seed held ACROSS screens is answered there; this file holds the
/// value and decides when it dies.
mod flow;
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
/// The microSD subsystem (0.2.0-m5): the slot, mounted only inside a flow, under the
/// bounded card layer in `notyas_wallet::sd`. Called by `crate::flow`, which is where the
/// picker, the loader and the deliver screen's write are answered.
mod sd;
/// The public settings region (0.2.0): the `settings` partition, holding the values this
/// device has to read BEFORE a PIN - the device name the lock screen draws and the network
/// choice. Four `esp_partition_*` calls; every rule about the format lives in
/// `notyas_wallet::settings`, where the host tests can reach it.
mod settings;
/// The signing pipeline (0.2.0-m6): bytes in, a reviewed transaction, bytes out. All I/O
/// stays outside it - the transport hands it a `&[u8]` and takes a `Vec<u8>` back - which
/// is the same split `store` keeps against the sealing engine. Its callers are the review
/// and deliver screens, through `crate::flow`.
mod signing;
/// What an unlocked session remembers between screens: the passphrases the user has
/// typed once. Pure by construction - no store, no logger, no ESP-IDF - and covered on the
/// host by `firmware/hostcheck`, because "the bytes are gone when it is cleared" is a
/// property no panel photograph can show.
mod session;
/// The sealed store: the two `esp_partition` regions, the device-binding MAC, the PSRAM
/// Argon2id working set and the session lifetime. Product code, always compiled.
mod store;
mod theme;
mod touch;
/// Which unseal outcome an unlock refusal is - the one judgement that decides whether the
/// PIN screen accuses the owner of a miscount or reports a store it could not read. Pure,
/// and covered on the host by `firmware/hostcheck`.
mod unseal;
mod verify;
/// The unlocked wallet (0.2.0-m6/m7): the sealed record schema, the one place a seed
/// exists, and the only source of the `psbt::Context` the signing pipeline validates
/// against. Product code, always compiled.
mod wallet;

use std::ffi::CStr;
use std::thread;
use std::time::{Duration, Instant};

use embedded_graphics::prelude::*;
use esp_idf_svc::sys;
use notyas_core::selftest::{self, SelfTest};
use notyas_fonts::{draw_text, TextStyle, MONO_REGULAR_32, SANS_REGULAR_32, SANS_SEMIBOLD_44};
use notyas_ui::{
    BackupState, Bit, DeleteOutcome, Network, PassphraseRefusal, PassphraseState, QrData,
    ReservedSpace, ScreenId, StorageOutcome, TouchEvent, Ui, UiRequest, UnsealOutcome,
    VerifyInfo, WalletDraft, WalletInfo, WalletKind, WalletRow,
};
use notyas_wallet::{Pin, SlotState};
use zeroize::Zeroizing;

use crate::display::Display;
use crate::flow::Flow;
use crate::session::PassSession;
use crate::wallet::record::{RegistrationRecord, SealedWallet, StoredPassphrase, WalletRecord};
use crate::wallet::erase::Erased;
use crate::wallet::{Wallet, WalletError};

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

    // The sealed store is MOUNTED here, before the self-test, and this boot is counted
    // here (VERIFY.md 6, ratified Q61(i)). The order is the requirement, not an
    // optimisation: a boot that ends on the failure screen is still a boot, and counting
    // after the self-test would make a forced failure a free way to power the device on
    // without advancing the counter that exists to reveal unattended power-ups.
    //
    // Mounting allocates nothing - the Argon2id working set is taken after the panel is
    // up (`attach_scratch`), so the heap numbers in the boot log still answer the
    // question m4a asks of them: does the working set fit ALONGSIDE the framebuffers.
    //
    // A failure here is not fatal. The stateless flow needs no storage at all, and a
    // device that cannot mount its store must still be usable as a 0.1.0 device and must
    // say why on the Verify screen rather than refusing to boot.
    let mut store = match store::Store::mount() {
        Ok(mut s) => {
            let r = s.report().clone();
            log::info!(
                "store: key {} | state {} | records @0x{:x} | ledger @0x{:x}",
                r.provenance,
                store::state_label(r.state),
                r.records_base,
                r.ledger_base
            );
            // Writes NOTHING while the store is unprovisioned, blank or wiped: SECURITY
            // invariant 2a keeps the 0.1.0 stateless property verbatim for a device that
            // has never stored a wallet, and a convenience row does not get to falsify it
            // (R24). The Verify row then renders `not counted`, never `0`.
            s.record_boot();
            Some(s)
        }
        Err(e) => {
            log::error!("store: unavailable: {e:?} - the stateless flow is unaffected");
            None
        }
    };

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
    // depend on nothing else driving the bus. The mount above reads flash and
    // may program one boot cell, but it has finished and freed its buffers by
    // the time this runs, and nothing it left behind holds the bus or the heap.
    #[cfg(feature = "measure")]
    measure::run();

    let mut display = board::display_init();

    // Calibration build (feature `diag-display`, off by default): what this
    // instrument measures is the bring-up that just ran, so it goes here - with
    // nothing above it having taken PSRAM or the flash bus - and never comes back.
    #[cfg(feature = "diag-display")]
    diag::run(&mut display);

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

    // The Argon2id working set, taken with the framebuffers already standing so the
    // numbers below are the ones that matter: what is left AFTER the panel took its
    // share. Failing here leaves a device that boots, counts and shows every screen, and
    // refuses every PIN operation with a reason.
    if let Some(s) = store.as_mut() {
        match s.attach_scratch() {
            Ok(()) => {
                let r = s.report();
                log::info!(
                    "store: argon2 scratch {} bytes in PSRAM | free PSRAM {} -> {} (delta {}) | free internal {}",
                    r.scratch_bytes,
                    r.free_psram_before,
                    r.free_psram_after,
                    r.free_psram_before.saturating_sub(r.free_psram_after),
                    store::free_internal()
                );
            }
            Err(e) => log::error!(
                "store: no Argon2 working set: {e:?} - PIN operations will refuse, \
                 the stateless flow is unaffected"
            ),
        }
    }

    // The product UI, laid out for this board's panel, fed with measured facts.
    let mut ui = Ui::new(board::DISPLAY_WIDTH, board::DISPLAY_HEIGHT);
    // The public settings, read here because here is BEFORE the lock screen and before
    // any PIN. This read touches no key, no session and no sealed record: the region is
    // plaintext by requirement, since the value it carries furthest - the device name - is
    // drawn on the very screen that asks for the PIN. A device whose table has no settings
    // partition, a blank region and a torn write all land on the same defaults, so nothing
    // here has a failure path that can stop a boot.
    let saved = settings::load();
    ui.set_network(settings::network_from(saved.network()));
    // Seeded through `LockInfo` because that is where the name lives for the life of a
    // power-up; `refresh_lock_info` below carries it forward across every later refresh,
    // exactly as it does for a name typed on this boot.
    ui.set_lock_info(notyas_ui::LockInfo {
        device_name: String::from(saved.device_name()),
        ..notyas_ui::LockInfo::default()
    });
    log::info!(
        "settings: device name {} | network {:?}",
        if saved.device_name().is_empty() {
            String::from("<unnamed>")
        } else {
            format!("{:?}", saved.device_name())
        },
        saved.network()
    );
    // The one long-lived seed on this device, and everything derived from it. Empty until
    // a user opens a wallet, emptied again by every route out of one (see `close_flow`).
    let mut flow = Flow::default();
    // What the user has typed once and should not have to type again until this session
    // ends. Beside `flow` rather than inside it, and outliving it on purpose - see
    // `PassSession`.
    let mut passphrases = PassSession::default();
    // One pass over the chip and flash, then everything downstream is a
    // rendering of it: the nine-row screen, the boot-log readout and (at m4b)
    // the QR export all read the same struct, so they cannot disagree.
    let ro = readout::read();
    let info = verify::build(&st, &ro, store.as_ref().map(store::Store::report));
    log::info!(
        "verify: fw {} | {} | {}",
        stated(&info.firmware_version),
        stated(&info.board),
        stated(&info.chip)
    );
    log::info!("verify: radio: {}", stated(&info.radio));
    log::info!(
        "verify: secure boot: {} | flash encryption: {}",
        bit_words(info.secure_boot),
        bit_words(info.flash_encryption)
    );
    verify::log_readout(&ro);

    // Development instrument, compiled out of every product build. Runs after
    // the readout so the log shows the true (unburned) eFuse state first and
    // the virtual-mode changes second, in that order and clearly separated.
    #[cfg(feature = "hmac-virtual-check")]
    hmac_check::run();

    ui.set_verify_info(info);
    refresh_lock_info(&mut ui, store.as_ref());
    // A device with a PIN starts locked. `Ui::lock` refuses on any other state, which is
    // what keeps R20 true without a check at this call site: on an unprovisioned or blank
    // device the lock screen - and the device words behind it - cannot be reached at all.
    if ui.lock() {
        log::info!("store: PIN set - starting on the lock screen");
    }

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
    // Wall clock of the previous pass, so `Ui::tick` is fed real elapsed milliseconds.
    let mut last_pass = Instant::now();
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
        // Wall-clock elapsed, not a pass count: `Ui::tick` ages the press in flight, and
        // the C4c hold-to-confirm it drives is a time interlock. A pass that spent 1.8 s
        // inside a derivation must age the press by 1.8 s or the hold is not 1.5 s long.
        let elapsed_ms = u32::try_from(last_pass.elapsed().as_millis()).unwrap_or(u32::MAX);
        last_pass = Instant::now();
        // A tick is dirty for two unrelated reasons now - a finished derivation and a
        // filling hold bar - so the log line asks which one this was instead of reading
        // the flag. A hold repaints on every pass, and logging that as a derivation would
        // bury the boot log in lines about a finger resting on a button.
        let was_deriving = ui.screen() == ScreenId::Deriving;
        let ticked = ui.tick(elapsed_ms);
        let mut dirty = ticked.dirty;
        publish_before_answering(&ui, &mut display, &mut repaints, &ticked.request, &mut dirty);
        answer_request(&mut ui, &mut store, &mut flow, &mut passphrases, ticked.request);
        if was_deriving && ui.screen() != ScreenId::Deriving {
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
            // The seed goes with the session, on the same pass. An auto-lock that left a
            // wallet open would leave a signed transaction and a live seed behind a lock
            // screen, which is the opposite of what locking means.
            close_flow(&mut flow, "the session timed out");
            // The passphrases go with the session, and this is the pass that ends it. The
            // seed and the passphrases are two different lifetimes on purpose (see
            // `PassSession`) and this is one of the four places they coincide.
            clear_passphrases(&mut passphrases, "the session timed out");
            // The session is gone; the screens above it go with it. `Ui::lock` clears the
            // navigation stack, and each entry wipes its screen's secrets on drop, so the
            // auto-lock is a wipe on both sides of the boundary and not just on the
            // std one.
            refresh_lock_info(&mut ui, store.as_ref());
            ui.lock();
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
        // Any touch is user activity: it restarts the idle timer that would otherwise
        // lock the device out from under a user who is reading a long address.
        if point.is_some() {
            if let Some(s) = store.as_mut() {
                s.touch();
            }
        }

        publish_before_answering(&ui, &mut display, &mut repaints, &request, &mut dirty);
        answer_request(&mut ui, &mut store, &mut flow, &mut passphrases, request);

        // Screen transitions are the UI's audit trail (ScreenId carries no
        // data, so this is safe to log - notyas-ui's Debug discipline). The
        // network setting is public state and logged the same way.
        let screen = ui.screen();
        if screen != last_screen {
            last_screen = screen;
            log::info!("screen: {screen:?}");
            // The panel is the only thing that knows the user has finished with a wallet:
            // the UI raises no "close" request, and Back out of S-21 is a navigation rather
            // than an answer. So the seed's life is tied to what is on the glass, and the
            // moment that is a screen outside the wallet - the list, the lock, home - it is
            // wiped. See `holds_a_wallet`.
            if !holds_a_wallet(screen) {
                close_flow(&mut flow, "the panel left this wallet");
            }
        }
        let network = ui.network();
        if network != last_network {
            last_network = network;
            log::info!("network: {network:?}");
            // Persisted from the LOOP rather than from a request handler because the
            // network toggle is answered inside the UI - it changes a value the embedder
            // reads, and raises nothing. This is the one place that can observe the
            // change, and it observes it by comparing, so a toggle that lands back where
            // it started costs no flash write at all.
            //
            // Signet and regtest are reachable only from the test console and are not a
            // user preference; `network_tag` returns nothing for them and nothing is
            // written, rather than the record being made to say the nearest thing it can.
            if let Some(tag) = settings::network_tag(network) {
                if !settings::update(|s| s.set_network(tag)) {
                    log::warn!("settings: network {network:?} is in force but was not stored");
                }
            }
        }

        if dirty {
            publish(&ui, &mut display, &mut repaints);
            log::debug!("repaint {repaints} ({screen:?})");
        }

        // MILESTONES.md m5's "the mount is never held outside an SD flow, asserted in
        // code". This is the one place that can observe it: every card flow lives inside a
        // single `answer_request` above and drops its guard on the way out, so a mount
        // still standing here is a flow that returned holding one. A debug build aborts on
        // it; a release build logs, because a stuck mount is worth a loud line and not
        // worth bricking a device that is otherwise working.
        sd::assert_idle();

        if last_heartbeat.elapsed() >= Duration::from_secs(1) {
            last_heartbeat = Instant::now();
            log::info!(
                "notyas {VERSION} | IDF {idf_version} | free heap {} bytes | repaints                  {repaints} | card mounts {}",
                unsafe { sys::esp_get_free_heap_size() },
                // The other half of the m5 claim, and the half an assertion cannot make:
                // `assert_idle` says no mount is standing NOW, and this says how many there
                // have ever been. An untouched device holds both numbers still.
                sd::mounts()
            );
        }

        thread::sleep(Duration::from_millis(POLL_MS));
    }
}

/// Drop every remembered passphrase, and say so once.
///
/// One function rather than a `clear()` at each site, on `close_flow`'s precedent: "the
/// session forgot the passphrases and the log says why" is one obligation instead of four.
/// Silent when it was already empty.
fn clear_passphrases(session: &mut PassSession, why: &str) {
    if session.clear() {
        log::info!("wallet: session passphrases forgotten - {why}");
    }
}

/// Draw the current state into the back buffer and publish the whole frame.
///
/// The one place a frame reaches the panel, so that "how many frames has this device
/// painted" stays a number the heartbeat can be trusted with.
fn publish(ui: &Ui, display: &mut Display, repaints: &mut u64) {
    // Infallible on this target: the framebuffer target cannot fail a draw, and a flush
    // that does is a dead panel rather than a condition this loop can carry on through.
    ui.draw(display).unwrap();
    display.flush().expect("frame publish");
    *repaints += 1;
}

/// Publish the frame that is on screen BEFORE the blocking work behind `request` starts.
///
/// C3's law (UX-SCREENS.md): any operation that can block the input loop for more than
/// 150 ms paints a Busy frame and publishes it to the panel before the work. Every request
/// in this vocabulary is such an operation - an Argon2id stretch, a card mount, a PSBT
/// inspection, a flash erase - and the screen that raised it has already switched to the
/// frame that says so. This is the only moment at which both of those are true: after the
/// state changed, before the answer that will change it again.
///
/// 0.1.0 learned this the hard way on the derivation path and solved it there by parking
/// the work for the NEXT loop pass (`Ui::tick`). That trick does not generalise - an answer
/// has to arrive in the same pass as the request, or the embedder is holding a card mount
/// across a repaint - so the publish moves here instead, and `dirty` is set because the
/// answer will always want the frame after it.
fn publish_before_answering(
    ui: &Ui,
    display: &mut Display,
    repaints: &mut u64,
    request: &Option<UiRequest>,
    dirty: &mut bool,
) {
    if request.is_none() {
        return;
    }
    publish(ui, display, repaints);
    *dirty = true;
}

/// A [`VerifyInfo`] string for the boot log, rendered the way S-46 renders it.
///
/// `not read` is a statement about this build, and it is the one the screen makes; a bare
/// `None` on a line an owner is asked to compare against a release manifest would be this
/// firmware reporting a value it never read as if it were one.
fn stated(value: &Option<String>) -> &str {
    value.as_deref().unwrap_or("not read")
}

/// A [`Bit`] in the words S-46 prints beside the same two rows, so the boot log and the
/// panel cannot disagree about a fuse.
///
/// The four states stay four. An absent field and an unread one must not collapse into
/// `disabled`, which would be this line claiming a fuse state nothing measured - the same
/// rule [`Bit`] itself is shaped around.
fn bit_words(b: Bit) -> &'static str {
    match b {
        Bit::Set => "enabled",
        Bit::Clear => "disabled",
        Bit::Absent => "not present",
        Bit::NotRead => "not read",
    }
}

/// The lock and PIN screens' values, from what the store actually reports, plus the one
/// value that is NOT the store's: the device name.
///
/// # Where the device name lives, and why it is not in the store
///
/// It is shown on the lock screen, BEFORE a PIN is typed, so it cannot live in the sealed
/// store: the store's contents are unreadable until an unlock, which is precisely when the
/// name has to be on the panel. It is not a secret and does not want the store's
/// protection - see `notyas_ui::LockInfo::device_name`, which states in full what an
/// attacker learns from it (the name, by picking the device up) and what it therefore
/// proves (nothing).
///
/// So it lives beside the network choice, in the UI's own `LockInfo`, for the life of a
/// power-up: `answer_set_device_name` writes it there and this function carries it forward
/// across every refresh. Since 0.2.0 it ALSO lives on flash, in the plaintext `settings`
/// partition (`crate::settings`), which is read at boot before the first frame and written
/// when the user taps Save. That region is deliberately outside the sealing engine: no key,
/// no session, no `Layout`, and no `encrypted` flag, because a value the lock screen draws
/// has to be readable before the unlock that would produce a key.
///
/// It is not authenticated and nothing may claim it is. An attacker with a programmer
/// rewrites it, exactly as they can rewrite any plaintext region, and the CRC in that
/// format catches a torn write and nothing else. That costs the user nothing, because the
/// name was never evidence: the anti-swap evidence is the S-04 word pair a counterfeit
/// cannot compute, and the UI is tested to make no claim on the name at all.
///
/// On a device flashed with a table older than 0.2.0 there is no such partition, the name
/// is RAM-only exactly as it was before, and nothing raises an error about it.
fn lock_info(store: Option<&store::Store>, device_name: String) -> notyas_ui::LockInfo {
    let Some(s) = store else {
        return notyas_ui::LockInfo { device_name, ..notyas_ui::LockInfo::default() };
    };
    notyas_ui::LockInfo {
        status: s.ui_status(),
        device_name,
        attempts_left: s.attempts_remaining(),
        wipe_after: s.wipe_after(),
        // The PIN floor is the STORE's, read from the policy this device was formatted
        // with, and the UI draws and gates Unlock from it. Passed rather than left to the
        // crate default so that a device formatted at any floor - not just the one the
        // default happens to name - can be unlocked through the panel.
        min_pin_len: s.min_pin_len(),
        // The device does not know how long its PIN is. `notyas_wallet` retains no length -
        // a PIN is stretched and dropped - and this firmware records none at unlock either,
        // so there is nothing to read back. `None` is the field's own word for exactly that
        // case, and the wipe-policy screen renders it as an unknown exhaustive-search time
        // rather than printing a number for a PIN this device never measured.
        pin: None,
        // The published bench figure, because nothing here can better it: `Store::unlock`
        // measures the real cost of an attempt and the boot log prints it, but no part of
        // the store keeps that number, so there is no measured value to prefer.
        unlock_ms: notyas_ui::UNLOCK_MS_M1,
    }
}

/// Re-read the store into the UI, keeping the device name the user set.
///
/// One function rather than a `set_lock_info(lock_info(...))` at each of eight call sites,
/// because the name is the one field of `LockInfo` the STORE cannot answer for: a refresh
/// that rebuilt the struct from the store alone would silently un-name the device on the
/// next lock, the next unlock and the next policy write.
fn refresh_lock_info(ui: &mut Ui, store: Option<&store::Store>) {
    let device_name = ui.lock_info().device_name.clone();
    ui.set_lock_info(lock_info(store, device_name));
}

/// Drop the open wallet, and say so once.
///
/// One function rather than a `flow.close()` at each site, so that "the seed died and the
/// log says why" is one obligation instead of four. Silent when nothing was open, because a
/// line per screen change on a device with no wallet open would bury the ones that matter.
fn close_flow(flow: &mut Flow, why: &str) {
    if flow.close() {
        log::info!("wallet: closed and wiped - {why}");
    }
}

/// Whether this screen belongs to an open wallet.
///
/// Exhaustive on purpose. A seed's lifetime is the most security-relevant thing this file
/// decides, and a screen added to `notyas_ui` must not inherit an answer: a new variant
/// fails to compile here until someone says whether a wallet may still be open behind it.
///
/// The direction to get wrong is the safe one. Answering `false` for a screen that does hold
/// a wallet costs the user a re-open; answering `true` for one that does not leaves a seed
/// alive behind a screen nobody associates with a wallet.
fn holds_a_wallet(screen: ScreenId) -> bool {
    match screen {
        // S-21 and everything reachable from it: the export tabs, the card, the review,
        // the signature, the delivery and the registry.
        ScreenId::WalletHome
        | ScreenId::Schemes
        | ScreenId::SignSource
        | ScreenId::FilePicker
        | ScreenId::Working
        | ScreenId::Refusal
        | ScreenId::ReviewTransaction
        | ScreenId::Signing
        | ScreenId::Deliver
        | ScreenId::MultisigList
        | ScreenId::MultisigImport
        | ScreenId::MultisigDetail
        | ScreenId::Receive => true,
        // The wallet list is where a wallet is CHOSEN, so arriving there means the user has
        // left the one they had. Everything else is the create flow, the store surfaces or
        // a locked device, and none of them is behind a wallet at all.
        ScreenId::WalletList
        | ScreenId::Home
        | ScreenId::DiceEntry
        | ScreenId::MnemonicDisplay
        | ScreenId::PhraseEntry
        | ScreenId::PassphraseEntry
        // The unlock screen: the wallet it names is NOT open - asking for the passphrase
        // is what stands between the tap and opening it - and a refusal leaves the user
        // here with nothing behind the screen.
        | ScreenId::PassphraseUnlock
        | ScreenId::Deriving
        | ScreenId::VerifyDevice
        | ScreenId::ScanningFlash
        | ScreenId::Lock
        | ScreenId::PinEntry
        | ScreenId::PinCreate
        | ScreenId::BackupCheck
        | ScreenId::KeepOrSave
        | ScreenId::NameWallet
        | ScreenId::Settings
        | ScreenId::DeviceName
        | ScreenId::AboutDeviceWords
        | ScreenId::WipePolicy
        // S-47b is reached by REPLACING the wallet home, not by covering it, so the wallet
        // is already gone from the screen by the time this is asked. `false` closes the
        // flow on arrival, which is the answer this screen wants twice over: it needs no
        // wallet - the erase runs against the store - and the one thing that must not
        // outlive a record being destroyed is a live seed derived from it.
        | ScreenId::EraseWallet
        // S-49 is opened from Settings, which is not behind a wallet, and it never
        // touches one: the only thing it can destroy is on a card, and nothing secret is
        // ever written to a card.
        | ScreenId::FormatCard => false,
    }
}

/// Answer a [`UiRequest`]. This function IS the std side of the boundary: every flash
/// access, every key-ladder step and every QR encode happens here, and the no_std UI does
/// none of them. It asks; this answers.
///
/// A request whose answer needs a store the device does not have is answered with the
/// refusal rather than dropped, because a screen waiting for an answer that never comes
/// is a hung screen.
///
/// Three of the m4b requests are answered with a refusal in EVERY build of this image, and
/// each arm states its own reason at the site. Committing a wipe policy and removing the
/// PIN are operations `Store` publishes no route to at all; changing the PIN is one it does
/// publish, and the new PIN that route needs is a value no screen in this UI can hand over.
/// All three re-seal or destroy sealed records, which is why "close enough" is not one of
/// the options: a refusal is a screen the user can read and act on, while a handler that
/// quietly did nothing would teach the UI - and through it the user - that a destructive
/// operation had succeeded.
///
/// Erasing a wallet record used to be the fourth, and it was the one the rule was written
/// about: the refusal reached the user as a wallet list that looked unchanged, which after a
/// typed-name consent reads as a dead button. `Store::clear_payload` and
/// `crate::wallet::erase` are what closed it, and `UiRequest::DeleteWallet` is now answered
/// on both of the channels that request documents.
///
/// A device's FIRST PIN is the exception and arrives here through `UiRequest::SetPin`,
/// collected by S-06/S-07. That route formats a store holding nothing, so it re-seals
/// no record and destroys none - which is why it can be answered while the four that
/// re-key existing records cannot.
///
/// The eight card, transaction and registry requests are dispatched to `crate::flow`, which
/// holds the wallet they all need and answers each on the channel it documents. `flow` is
/// threaded through this function rather than parked in a static because a seed with a
/// lifetime is a seed somebody can reason about, and a static one has none.
fn answer_request(
    ui: &mut Ui,
    store: &mut Option<store::Store>,
    flow: &mut Flow,
    passphrases: &mut PassSession,
    request: Option<UiRequest>,
) {
    let Some(request) = request else { return };
    match request {
        UiRequest::Qr(target) => answer_qr(ui, target),
        UiRequest::DeviceWords(prefix) => {
            // Costs no attempt: showing the words is not a guess.
            match store.as_mut().map(|s| s.anti_phishing_words(prefix.as_str())) {
                Some(Ok(words)) => ui.show_device_words(words),
                Some(Err(e)) => log::error!("store: device words unavailable: {e}"),
                None => log::error!("store: device words unavailable: no store"),
            }
        }
        UiRequest::UnsealWallet(pin) => answer_unseal(ui, store, flow, passphrases, pin),
        UiRequest::SetPin(pin) => answer_set_pin(ui, store, pin),
        UiRequest::SetDeviceName(name) => answer_set_device_name(ui, store, name),
        UiRequest::PersistWallet(draft) => {
            answer_persist_wallet(ui, store, passphrases, &draft)
        }
        UiRequest::LockSession => {
            if let Some(s) = store.as_mut() {
                s.lock();
            }
            // The wallet is part of the session, so it goes with it. `Ui::lock` below
            // clears the screens; this clears what was behind them.
            close_flow(flow, "the device was locked");
            // What "remember for the session" means, at the moment the session ends.
            clear_passphrases(passphrases, "the device was locked");
            refresh_lock_info(ui, store.as_ref());
            ui.lock();
            log::info!("store: locked on request - session dropped");
        }
        UiRequest::ScanReservedSpace => {
            // VERIFY.md 3.3's raw read of every must-be-blank span is the one row on this
            // screen this build has no reader for yet (readout.rs states the scope). It is
            // answered rather than dropped anyway, and answered with `NotRead` rather than
            // an empty scan: the rule at the top of this function is not suspended because
            // a feature is unfinished, and "it looked and found nothing" would be a
            // sentence this device has not earned. The screen leaves its C3 Busy frame and
            // the row reads `not read`, which is the true statement about this image.
            log::warn!(
                "verify: reserved-space scan requested, and this build has no reader for it"
            );
            ui.set_flash_scan(ReservedSpace::NotRead);
        }
        UiRequest::AcknowledgeBoots => {
            match store.as_mut().map(store::Store::acknowledge_boots) {
                Some(Ok(_)) => {}
                Some(Err(e)) => log::error!("store: acknowledgement refused: {e}"),
                None => log::error!("store: acknowledgement refused: no store"),
            }
            // The screen re-reads what the write produced rather than assuming it.
            if let Some(s) = store.as_ref() {
                let r = s.report();
                ui.set_verify_info(VerifyInfo {
                    boot_count: r.boot_count,
                    acknowledged_at: r.acknowledged_at,
                    ..ui.verify_info().clone()
                });
            }
        }
        UiRequest::OpenWallet(slot) => {
            answer_open_wallet(ui, store, flow, passphrases, slot)
        }
        UiRequest::UnlockWallet { slot, passphrase } => {
            answer_unlock_wallet(ui, store, flow, passphrases, slot, passphrase.as_str())
        }
        UiRequest::StorePassphrase(slot) => {
            answer_passphrase_storage(ui, store, passphrases, slot, true)
        }
        UiRequest::ForgetPassphrase(slot) => {
            answer_passphrase_storage(ui, store, passphrases, slot, false)
        }
        UiRequest::DeleteWallet(slot) => {
            // The objection the previous build refused on was sound and is unchanged: no
            // EMPTY record is ever written into a payload slot, because an empty record
            // reads as occupied and decodes as nothing. What was wrong was the conclusion.
            // `Vault::clear` does not write an empty record - under
            // `Occupancy::AlwaysFilled` it writes device FILLER, sealed under the key
            // ladder's filler root, which `slot_state` tries FIRST and answers `Empty` to.
            // `Store::clear_payload` is the route to it, and `crate::wallet::erase` owns
            // the order the two record classes go in and the read-back that decides whether
            // this may be called a delete at all.
            //
            // Answered on BOTH channels, which is the rule at the top of this function: the
            // outcome says what happened to this wallet, and the list installed after it
            // says what the device now holds. The list is the evidence either way - and
            // this time it is evidence of something.
            let name = wallet_name(ui, slot);
            let outcome = flow::delete_wallet(ui, store, flow, slot, &name);
            // That slot's passphrase, and only that slot's: there is no wallet left for it
            // to open, and the next wallet stored on this device takes the lowest free
            // slot - which is this one.
            passphrases.forget(slot);
            install_wallets(ui, store);
            let next = ui.wallet_deleted(match outcome {
                Erased::Gone { registrations } => DeleteOutcome::Gone { registrations },
                Erased::Refused(why) => DeleteOutcome::Refused(why),
                // Both of the remaining outcomes mean the user must not walk away believing
                // the words are safely gone OR safely intact: one destroyed part of the
                // wallet, the other cannot say what it destroyed. Neither is a refusal, and
                // rendering them as one would be the lie this handler exists to stop
                // telling.
                Erased::Partial(why) | Erased::NotGone(why) => DeleteOutcome::Damaged(why),
            });
            answer_request(ui, store, flow, passphrases, next);
        }
        UiRequest::RecoveryWords(slot) => {
            // The last look at the words, from the one screen that offers it. No seed is
            // derived and no passphrase is asked for: the record stores the WORDS.
            let next = ui.recovery_words(flow::recovery_words(store, slot));
            answer_request(ui, store, flow, passphrases, next);
        }
        UiRequest::SetWipePolicy { wipe_after } => {
            // REFUSED. Committing a policy is `Vault::set_policy`, and it takes the PIN:
            // the policy is authenticated INSIDE the AEAD (PIN-MODES.md), so the commit is
            // a re-seal and the format demands a fresh confirmation of the PIN at the
            // moment of it. This request carries a threshold and no PIN, the session holds
            // a derived key and never the PIN itself, and `Store` publishes no route to
            // `set_policy` - there is nothing here to write with.
            //
            // Answered on both channels the request documents: the verdict says the write
            // did not happen, and the lock info behind it is the policy still in force,
            // read back from the store rather than echoed from the screen's edit.
            log::error!(
                "store: wipe policy ({}) refused: committing it re-seals the store under \
                 the PIN, and this build cannot ask for one",
                match wipe_after {
                    Some(n) => format!("wipe after {n}"),
                    None => String::from("wipe off"),
                }
            );
            ui.policy_result(false);
            refresh_lock_info(ui, store.as_ref());
        }
        UiRequest::ChangePin => {
            // REFUSED. `Store::change_pin` exists and re-seals every record correctly, and
            // it needs the new PIN. This request carries none, and no screen in the UI can
            // collect one FOR A DEVICE THAT ALREADY HAS ONE: S-06/S-07 collect the first
            // PIN and raise `SetPin`, but they are reachable only where `has_pin` is
            // false, and PIN entry - the surface a provisioned device has - raises
            // `UnsealWallet`. So the sequence cannot be started, and half of it must not
            // be: a change-PIN re-keys every stored wallet, which is the operation with
            // the least room to be approximately right.
            //
            // The UI documents no failure channel for this request, so the refusal is a log
            // line and the screens are re-fed the state as it still stands. Nothing is left
            // waiting for an answer.
            log::error!("store: change PIN refused: this build cannot collect a new PIN");
            refresh_lock_info(ui, store.as_ref());
        }
        UiRequest::RemovePin => {
            // REFUSED, and this is the one refusal that reaches the user in words:
            // `Ui::pin_removed(false)` is the failure line the settings screen renders.
            //
            // `Vault::remove_pin` is what performs it, and it takes the PIN for the same
            // reason `set_policy` does - it destroys every sealed record, so the format
            // asks for a fresh confirmation first. `Store` publishes no route to it and
            // this request carries no PIN. Nothing is destroyed here, and nothing tells a
            // device with eight sealed slots that it is stateless again.
            log::error!(
                "store: PIN removal refused: it destroys every sealed record and needs a \
                 fresh PIN confirmation this build cannot ask for"
            );
            // When this IS implemented, it must also call `settings::clear()`. The consent
            // sheet promises that "all settings" are destroyed, and since 0.2.0 the device
            // name and the network choice outlive a power cycle - leaving the previous
            // owner's name on the lock screen of a device that now stores nothing would
            // make that sheet a false statement. Nothing is destroyed on this path today,
            // settings included, so the promise is not broken by the refusal.
            //
            // It must also clear `passphrases`: a session passphrase for a record that no
            // longer exists opens nothing, and holding a secret with nothing to open is
            // the definition of a secret nobody is watching. Nothing is destroyed on this
            // path today, so nothing is stale, and the clear belongs with the destruction
            // rather than beside a refusal.
            ui.pin_removed(false);
        }
        // The card, the transaction and the registry. Every one of these needs a wallet
        // held open ACROSS screens, so the state lives in `crate::flow` and so do the
        // handlers; what is left here is the dispatch. Each returns the answer's own
        // follow-up request, which goes straight back through this function.
        UiRequest::ListCard { dir, filter } => {
            let next = flow::list_card(ui, dir, filter);
            answer_request(ui, store, flow, passphrases, next);
        }
        UiRequest::LoadPsbt { dir, name } => {
            let next = flow::load_psbt(ui, flow, dir, name);
            answer_request(ui, store, flow, passphrases, next);
        }
        UiRequest::SignTx => {
            let next = flow::sign_tx(ui, flow);
            answer_request(ui, store, flow, passphrases, next);
        }
        UiRequest::WriteSigned { overwrite } => {
            let next = flow::write_signed(ui, flow, overwrite);
            answer_request(ui, store, flow, passphrases, next);
        }
        UiRequest::DiscardSigned => {
            let next = flow::discard_signed(ui, flow);
            answer_request(ui, store, flow, passphrases, next);
        }
        UiRequest::ShowSignedQr => {
            use notyas_ui::{QrData, SignedQrOutcome};
            let Some(delivery) = flow.signed_ref() else {
                ui.show_signed_qr(SignedQrOutcome::Refused(String::from(
                    "This device is not holding a signed transaction.",
                )));
                return;
            };
            let bytes = delivery.signed_bytes();
            match notyas_core::psbt_qr::frame(bytes) {
                Ok(b64) => {
                    let rows = match notyas_core::qr::matrix(&b64) {
                        Ok(r) => r,
                        Err(_) => {
                            ui.show_signed_qr(SignedQrOutcome::Refused(String::from(
                                "QR encoding failed.",
                            )));
                            return;
                        }
                    };
                    match QrData::from_matrix(&rows) {
                        Some(qr) => {
                            ui.show_signed_qr(SignedQrOutcome::Symbol(qr));
                        }
                        None => {
                            ui.show_signed_qr(SignedQrOutcome::Refused(String::from(
                                "The signed transaction does not fit a single QR symbol.",
                            )));
                        }
                    }
                }
                Err(e) => {
                    ui.show_signed_qr(SignedQrOutcome::Refused(format!("{e:?}")));
                }
            }
        }
        UiRequest::ImportRegistration { dir, name } => {
            let next = flow::import_registration(ui, flow, dir, name);
            answer_request(ui, store, flow, passphrases, next);
        }
        UiRequest::ApproveRegistration { replace } => {
            let next = flow::approve_registration(ui, store, flow, replace);
            answer_request(ui, store, flow, passphrases, next);
        }
        // The two card-repair requests. Neither needs a wallet, a store or a session, so
        // both could have been answered inline here - they go through `flow` anyway
        // because every request that reaches `crate::sd` is answered in one place, and
        // because the format is the one operation in this image that destroys data the
        // device does not own: it belongs where a reader looking for "what can this
        // firmware erase" will find it beside the others.
        UiRequest::ProbeCardFormat => {
            let next = flow::probe_card_format(ui);
            answer_request(ui, store, flow, passphrases, next);
        }
        UiRequest::FormatCard { partition, card } => {
            let next = flow::format_card(ui, partition, card);
            answer_request(ui, store, flow, passphrases, next);
        }
        UiRequest::DeleteRegistration(slot) => {
            let next = flow::delete_registration(ui, store, flow, slot);
            answer_request(ui, store, flow, passphrases, next);
        }
        UiRequest::SaveAddress { address, overwrite } => {
            flow::save_address(ui, address, overwrite);
        }
    }
}

/// Seal the wallet the create flow just confirmed, and answer the screen either way.
///
/// # The identity that gets stored is the identity that was on the panel
///
/// The draft carries the fingerprint the derivation produced WITH whatever BIP-39
/// passphrase the user typed, and that value goes into the record as data. Nothing here
/// re-derives it, because the only passphrase this path could re-derive with is an empty
/// one - Q22 keeps the real one out of every structure that outlives the screen that took
/// it - and an empty-passphrase fingerprint sealed under the name of a passphrased wallet
/// inverts the guarantee the field exists for: the user's real passphrase would be refused
/// by `Wallet::open` forever, and an empty one would open a wallet they never approved.
///
/// # The slot
///
/// Chosen here, by the store, because the request carries none: the lowest free payload
/// slot ([`Wallet::seal_into_free_slot`], which carries the reasoning). A full device is a
/// refused save, not an eviction.
///
/// # What the UI still cannot be told, and it is not this function's to fix
///
/// C12 (UX-SCREENS.md 525-539) requires the write notice to NAME the slot before the write
/// happens, and S-20 renders it that way. It cannot be satisfied from here:
/// `UiRequest::PersistWallet` carries no slot and `Ui::persist_result` takes none back, so
/// the screen has no way to learn the number before or after. Reinstalling the wallet list
/// is the half that is reachable - it is the one route by which the slot a wallet actually
/// landed in gets to the screens, and without it the wallet home keeps rendering the slot
/// the create flow guessed.
fn answer_persist_wallet(
    ui: &mut Ui,
    store: &mut Option<store::Store>,
    passphrases: &mut PassSession,
    draft: &WalletDraft,
) {
    let sealed = match store.as_mut() {
        Some(s) => match seal_draft(s, draft) {
            Ok(slot) => {
                log::info!("store: wallet {} sealed into slot {slot}", draft.fingerprint);
                true
            }
            // Every refusal is a sentence, and each one is a different thing to do about
            // it: a full device, a slot that filled underneath us, a record too big for a
            // slot, a fingerprint that would not parse, a session that expired mid-flow.
            // The screen gets the verdict; the log gets which of them it was.
            Err(e) => {
                log::error!("store: wallet {} not saved: {e}", draft.fingerprint);
                false
            }
        },
        None => {
            log::error!("store: wallet {} not saved: no store", draft.fingerprint);
            false
        }
    };
    ui.persist_result(sealed);
    // Only after a save that happened, and always after one: this is the only channel that
    // carries the real slot to the screens (see the note above).
    if sealed {
        install_wallets(ui, store);
    }
    // The one place a passphrase enters the session other than an unlock. Without it the
    // user would type a passphrase, approve a fingerprint, name the wallet, save it - and
    // be asked for the passphrase again the moment they tapped the row they had just
    // created. The slot is looked up from the list that was just installed, because the
    // save chose it and the request never carried one.
    if let (true, Some(passphrase)) = (sealed, draft.passphrase.as_ref()) {
        match slot_of_fingerprint(ui, &draft.fingerprint) {
            Some(slot) => passphrases.remember(slot, passphrase.as_str()),
            // Not fatal: the wallet is saved and opening it will ask. Worth a line,
            // because the only way here is a list that does not hold a wallet this device
            // has just sealed.
            None => log::error!(
                "wallet: {} was sealed and is not in the list, so its passphrase was not \
                 remembered for this session",
                draft.fingerprint
            ),
        }
    }
    // Store the passphrase in the sealed record if the user asked for it at
    // creation time. The session already holds it; this makes it persistent.
    if sealed && draft.store_passphrase {
        if let Some(slot) = slot_of_fingerprint(ui, &draft.fingerprint) {
            if let Some(s) = store.as_mut() {
                if let Some(passphrase) = draft.passphrase.as_ref() {
                    match crate::wallet::Wallet::set_passphrase_storage(s, slot, Some(passphrase.as_str())) {
                        Ok(state) => log::info!("wallet: slot {} passphrase stored at creation: {:?}", slot, state),
                        Err(e) => log::error!("wallet: slot {} passphrase storage at creation failed: {:?}", slot, e),
                    }
                }
            }
        }
    }
    refresh_lock_info(ui, store.as_ref());
}

/// The draft as a sealed record, in the slot the store picked.
///
/// Split out so that the arm above has one thing to report and one place to report it:
/// every way this can fail - the fingerprint parse, the free-slot walk, the encode, the
/// write - arrives as one [`WalletError`] with a sentence already in it.
fn seal_draft(s: &mut store::Store, draft: &WalletDraft) -> Result<u8, WalletError> {
    let new = SealedWallet::confirmed(
        &draft.name,
        draft.network,
        draft.phrase(),
        &draft.fingerprint,
        // `Applied` and never `Stored`: a save states that this wallet HAS a passphrase,
        // and storing one is a decision the owner makes afterwards, per wallet, on a
        // screen that says what it costs (Q22 amendment, 2026-08-19). The default is that
        // the passphrase is written nowhere, and this is the line that keeps it.
        match draft.passphrase {
            Some(_) => StoredPassphrase::Applied,
            None => StoredPassphrase::None,
        },
    )?;
    Wallet::seal_into_free_slot(s, &new)
}

/// Which slot holds the wallet with this fingerprint, according to the list the embedder
/// has just installed.
///
/// The save picks the slot ([`Wallet::seal_into_free_slot`]) and neither the request nor
/// the answer carries it, so the list is the only channel by which the number reaches this
/// side again. Matched on the FINGERPRINT rather than on the name, because a fingerprint is
/// an identity and a name is a label the user may reuse.
fn slot_of_fingerprint(ui: &Ui, fingerprint: &str) -> Option<u8> {
    ui.wallets().iter().find_map(|row| match row {
        WalletRow::Wallet(w) if w.fingerprint == fingerprint => Some(w.slot),
        _ => None,
    })
}

/// Open the wallet in `slot`, hand the screens its identity AND its derivation, and keep the
/// seed for as long as the panel is inside that wallet.
///
/// # The passphrase, and the four cases
///
/// [`UiRequest::OpenWallet`] names a slot and nothing else, deliberately: the common case is
/// a wallet this device can open with what it already has, and that case must stay one tap
/// with no prompt. So this function DECIDES which passphrase to try, from the record and
/// from the session, before it spends the seconds that trying one costs:
///
/// 1. **The record stores one** (the per-wallet opt-in of the Q22 amendment). Open with it.
/// 2. **The session is holding one for this slot.** Open with it. A mismatch here means the
///    cache is stale rather than that the user typed anything wrong, so it falls through to
///    case 4 and NOTHING is shown about it.
/// 3. **The record says no passphrase was applied.** Open with the empty one, as every
///    build before this did. A format 1 record makes no statement, so it takes this path
///    too - and when the empty passphrase does not open it, the mismatch is discarded and
///    case 4 follows. The fingerprint those words derive with an EMPTY passphrase is never
///    shown to anyone: it is an existence proof for a hidden wallet.
/// 4. **Otherwise, ask.** [`Ui::wallet_needs_passphrase`] puts the entry screen up, and the
///    answer comes back through [`UiRequest::UnlockWallet`] into `answer_unlock_wallet`.
///
/// Case 3 falling through to case 4 is the whole of the owner's `tz` bug, fixed with no
/// migration: that wallet is a format 1 record whose words derive `73c5da0a` with no
/// passphrase and whose record was sealed for `b4e3f5ed`, and every build before this one
/// answered the tap with a refusal band naming both.
///
/// # Why the derivation is produced here
///
/// [`Ui::wallet_opened`] carries the public identity and nothing else, and a wallet opened
/// that way can do exactly one thing: be deleted. Export, the receive addresses, the QR codes
/// and the whole signing path are gated on the UI HOLDING a derivation, because the UI owns
/// no key ladder and cannot re-derive one from a slot number. Unsealing the record is what
/// produces the seed, so this is the one moment the device can hand it over, and
/// [`Wallet::derivation`] is what turns it into the public report S-26 renders. A stored
/// wallet that offered only Delete was the whole of the gap that made the PIN worth less than
/// the "use once, keep nothing" flow it protects.
///
/// It costs one BIP-39 stretch and four account derivations, which is the same work the
/// create flow spends on its own interstitial. The frame on the panel has already been
/// published before this runs (`publish_before_answering`), so the wallet list is on the
/// glass throughout rather than a half-drawn screen.
///
/// # Why the wallet is kept
///
/// Because the screens behind it need the seed: `crate::flow` answers eight requests that
/// cannot exist without one, and every one of them belongs to the wallet this call opened.
/// The lifetime is stated once, in `crate::flow`'s module docs, and enforced by `close_flow`
/// at three sites - a lock, an auto-lock, and the panel leaving this wallet's screens.
///
/// # Every failure reaches the user
///
/// A refused open produces NO screen change, so a handler that only logged would leave a row
/// that does nothing when it is tapped. [`Ui::wallet_open_failed`] is the other half: the
/// list stays where it is and says why it stayed.
fn answer_open_wallet(
    ui: &mut Ui,
    store: &mut Option<store::Store>,
    flow: &mut Flow,
    passphrases: &mut PassSession,
    slot: u8,
) {
    let Some(s) = store.as_mut() else {
        log::error!("wallet: slot {slot} not opened: no store");
        ui.wallet_open_failed(String::from(
            "This device could not reach its sealed storage, so no wallet was opened.",
        ));
        return;
    };
    // One AEAD open and a parse, no PBKDF2: what the record says about itself, which is
    // what decides which passphrase this open should try.
    let facts = match Wallet::inspect(s, slot) {
        Ok(f) => f,
        Err(e) => {
            log::error!("wallet: slot {slot} not opened: {e}");
            ui.wallet_open_failed(format!("Wallet slot {slot} did not open: {e}."));
            return;
        }
    };
    // The order is the case list in this function's docs. A `Zeroizing` copy, because the
    // value may come out of the record and must not be left in a plain buffer.
    let mut attempt = Zeroizing::new(String::new());
    let (source, applied) = match (facts.passphrase.stored(), passphrases.get(slot)) {
        (Some(stored), _) => {
            attempt.push_str(stored);
            ("the record", true)
        }
        (None, Some(cached)) => {
            attempt.push_str(cached);
            ("this session", true)
        }
        (None, None) => ("no passphrase", facts.passphrase.applied()),
    };
    // The record says a passphrase was applied and nothing here holds it: ask, without
    // spending a derivation that can only fail.
    if applied && attempt.is_empty() {
        log::info!("wallet: slot {slot} needs its passphrase - asking");
        ui.wallet_needs_passphrase(slot, facts.label);
        return;
    }
    log::info!("wallet: slot {slot} opening with the passphrase from {source}");
    let cached = source == "this session";
    match open_and_install(ui, store, flow, slot, &attempt) {
        Ok(()) => {
            // Remembered for the session whatever it came from, so that turning storage
            // ON later stores a value this device has just proven opens this wallet.
            passphrases.remember(slot, &attempt);
        }
        // The one refusal this path never SHOWS. Two ways to get here and both end in the
        // same place: the empty passphrase did not open a record that carries no flag (the
        // format 1 case), or a cached passphrase went stale. In neither case did the user
        // type anything, and in neither case may the derived fingerprint reach the panel -
        // it is what these words derive with the passphrase this device guessed, and for
        // the empty guess that is an existence proof for a hidden wallet.
        Err(WalletError::PassphraseMismatch { expected, derived }) => {
            log::info!(
                "wallet: slot {slot} did not open with the passphrase from {source} \
                 (record {expected}) - asking for one"
            );
            let _ = derived;
            if cached {
                passphrases.forget(slot);
            }
            ui.wallet_needs_passphrase(slot, facts.label);
        }
        // Everything else is already a sentence: a locked store, a slot that holds nothing,
        // a record that will not decode. Printing it is what turns "it did not open" into
        // something an owner can act on, and showing it is what stops the row looking dead.
        Err(e) => {
            log::error!("wallet: slot {slot} not opened: {e}");
            ui.wallet_open_failed(format!("Wallet slot {slot} did not open: {e}."));
        }
    }
}

/// The passphrase the user typed on the unlock screen, answering
/// [`UiRequest::UnlockWallet`].
///
/// The screen is showing its Busy frame and the embedder has already published it
/// (`publish_before_answering`), so the seconds this spends are seconds the panel is
/// explaining. BOTH answers leave that frame, which is what makes the phase impossible to
/// wedge: a success replaces the screen with the wallet home, and a refusal re-renders it
/// with what happened.
///
/// The refusal is the one place this device states two fingerprints to a user, and it may:
/// both are public, the record's is in the record, and the derived one is a function of
/// what they just typed. What it must never state is the fingerprint these words derive
/// with an EMPTY passphrase, and no path here can produce that - this function only ever
/// derives with what the user typed, and the screen refuses to raise a request with an
/// empty field.
fn answer_unlock_wallet(
    ui: &mut Ui,
    store: &mut Option<store::Store>,
    flow: &mut Flow,
    passphrases: &mut PassSession,
    slot: u8,
    passphrase: &str,
) {
    if store.is_none() {
        log::error!("wallet: slot {slot} not opened: no store");
        ui.wallet_open_failed(String::from(
            "This device could not reach its sealed storage, so no wallet was opened.",
        ));
        return;
    }
    match open_and_install(ui, store, flow, slot, passphrase) {
        Ok(()) => {
            // The whole of "remember for the session": typed once, good until the device
            // locks. It has just been proven to derive this wallet.
            passphrases.remember(slot, passphrase);
            log::info!("wallet: slot {slot} opened with a typed passphrase");
        }
        Err(WalletError::PassphraseMismatch { expected, derived }) => {
            // Public values, and the screen says the same two. The device does not say
            // "wrong": every passphrase opens some wallet, and this one opens that one.
            log::info!(
                "wallet: slot {slot} not opened: that passphrase opens wallet {derived} and \
                 this record is wallet {expected}"
            );
            ui.passphrase_refused(PassphraseRefusal {
                expected: expected.to_string(),
                derived: derived.to_string(),
            });
        }
        Err(e) => {
            log::error!("wallet: slot {slot} not opened: {e}");
            // The unlock screen's failure channel is the refusal; a storage fault is not a
            // refusal and must not be worded as one. It goes to the list's band, which
            // means leaving the Busy frame the only other way there is - and the panel must
            // not be left on it, so the list is where this lands.
            ui.wallet_open_failed(format!("Wallet slot {slot} did not open: {e}."));
        }
    }
}

/// Whether this device remembers the passphrase of the wallet in `slot`, answering
/// [`UiRequest::StorePassphrase`] and [`UiRequest::ForgetPassphrase`].
///
/// # Where the stored value comes from
///
/// From the SESSION, never from a screen: the toggle is offered only on a wallet that is
/// open, and a wallet that is open is one this device has just derived a seed for, so the
/// passphrase in hand is byte-for-byte the one that produced the fingerprint in the record.
/// Asking the user to type it again would mean storing something nothing had checked.
///
/// # The answer is the read-back
///
/// [`Wallet::set_passphrase_storage`] re-seals, reads the record back and reports what the
/// FLASH says. This hands that on unchanged. A toggle that rendered the intent would be a
/// switch that lies about the one thing it controls.
fn answer_passphrase_storage(
    ui: &mut Ui,
    store: &mut Option<store::Store>,
    passphrases: &mut PassSession,
    slot: u8,
    remember: bool,
) {
    let Some(s) = store.as_mut() else {
        log::error!("wallet: slot {slot} passphrase storage not changed: no store");
        ui.passphrase_storage_result(StorageOutcome::Refused(String::from(
            "This device could not reach its sealed storage, so nothing was changed.",
        )));
        return;
    };
    // Copied out of the session before the store is borrowed for the write, and dropped
    // with this function. Zeroizing: it is the passphrase.
    let held = passphrases.get(slot).map(|p| {
        let mut buf = Zeroizing::new(String::with_capacity(p.len()));
        buf.push_str(p);
        buf
    });
    let remember = match (remember, &held) {
        (true, Some(p)) => Some(p.as_str()),
        // Nothing to store. Reachable only from a screen that offered the control on a
        // wallet this session is not holding a passphrase for, which the wallet home does
        // not do - and stated rather than assumed, because storing an empty passphrase
        // would seal a record claiming a wallet nobody has.
        (true, None) => {
            log::error!(
                "wallet: slot {slot} passphrase not stored: this session is not holding one"
            );
            ui.passphrase_storage_result(StorageOutcome::Refused(String::from(
                "This device is not holding this wallet's passphrase, so it stored \
                 nothing. Open the wallet with it and try again.",
            )));
            return;
        }
        (false, _) => None,
    };
    match Wallet::set_passphrase_storage(s, slot, remember) {
        Ok(state) => {
            log::info!("wallet: slot {slot} record re-sealed, passphrase now {state:?}");
            // The session KEEPS what it knows when storage is turned off: this session
            // still has the passphrase, so re-opening or re-enabling inside it is
            // lossless. The lock that ends the session is what makes the forgetting real,
            // and the sheet says so.
            ui.passphrase_storage_result(StorageOutcome::Now(state));
        }
        Err(e) => {
            log::error!("wallet: slot {slot} passphrase storage not changed: {e}");
            ui.passphrase_storage_result(StorageOutcome::Refused(format!(
                "Nothing was changed: {e}."
            )));
        }
    }
}

/// Open the wallet in `slot` with `passphrase`, install it in the flow and hand the screens
/// its identity and its derivation.
///
/// The half of an open that is the same whichever of the four cases got here, so that the
/// registry re-proof, the derivation and the two `Ui` answers exist once. Failure is the
/// caller's to word, because only the caller knows whether the passphrase came from the
/// user, from the record or from a guess this device made.
fn open_and_install(
    ui: &mut Ui,
    store: &mut Option<store::Store>,
    flow: &mut Flow,
    slot: u8,
    passphrase: &str,
) -> Result<(), WalletError> {
    let s = store.as_mut().ok_or(WalletError::Locked)?;
    let t0 = Instant::now();
    let wallet = Wallet::open(s, slot, passphrase)?;
    // A registration that did not survive its re-proof is a multisig wallet the user
    // believes is registered and is not, and the next PSBT from it would be refused with
    // nothing to say why. One line each, at error level.
    for fault in wallet.registry_faults() {
        log::error!(
            "wallet: slot {slot} registry slot {}: {}",
            fault.slot,
            fault.reason
        );
    }
    // What the RECORDS say, which is what S-41 compares its proven list against. Counted
    // rather than taken from the proven set, because the GAP between the two is the only way
    // that screen can say "this device has registrations and could not read them" - a proven
    // count on both sides would report a wallet with a broken registration as a wallet with
    // one fewer registration.
    let claimed = registration_counts(s)
        .get(usize::from(slot))
        .copied()
        .unwrap_or(0);
    log::info!(
        "wallet: slot {slot} opened in {} ms | {} | {} of {claimed} registrations proven, {} \
         faults",
        t0.elapsed().as_millis(),
        wallet.fingerprint(),
        wallet.registrations().len(),
        wallet.registry_faults().len()
    );

    let t1 = Instant::now();
    // The SAME passphrase the record was just opened with, whichever of the four cases
    // supplied it. `Wallet::derivation` re-checks that what it produced belongs to the
    // wallet in hand and returns nothing rather than a report about somebody else's keys.
    let report = wallet.derivation(passphrase, notyas_ui::ADDRESS_ROWS);
    match &report {
        Some(_) => log::info!(
            "wallet: slot {slot} derivation ready in {} ms",
            t1.elapsed().as_millis()
        ),
        // Not fatal and not silent: the wallet still opens, and the home screen then offers
        // what a wallet with no derivation can do. Saying so is what keeps "Export is
        // missing" from being a mystery.
        None => log::error!(
            "wallet: slot {slot} opened and its public derivation could not be produced - \
             export and signing will not be offered"
        ),
    }

    let info = WalletInfo {
        registrations: claimed,
        // MEASURED, and by the one thing that can measure it: what it took to open this
        // record. `Wallet::open` decides it from the record's own flag AND from whether
        // the passphrase that worked was empty, which is the only evidence a format 1
        // record offers. The hardcoded `false` this replaces is why a wallet that
        // demonstrably had a passphrase rendered "passphrase off" on its own identity card.
        passphrase: wallet.passphrase(),
        ..stored_wallet(
            wallet.slot(),
            String::from(wallet.label()),
            // The fingerprint of the LIVE seed, which is the value `Wallet` derives and
            // never the copy the record carries.
            wallet.fingerprint().to_string(),
            wallet.network(),
        )
    };

    // The wallet moves into the flow BEFORE the screens are told, so that any request the
    // resulting frame raises already has a seed to be answered from.
    flow.open(wallet);
    flow::install_registrations(ui, flow);
    match report {
        Some(report) => ui.wallet_opened_with_keys(info, report),
        None => ui.wallet_opened(info),
    }
    // Every answer in this vocabulary is DROPPED unless the screen that asked is still
    // showing, and a dropped open leaves this function holding a seed no screen can use.
    // The screen-change watcher in the main loop cannot catch it - the screen did not
    // change, which is precisely why the answer was dropped - so it is caught here, at the
    // one site that can see both halves.
    if !holds_a_wallet(ui.screen()) {
        close_flow(flow, "the panel was not on this wallet when it opened");
    }
    Ok(())
}

/// Read the wallet list out of the store and install it.
///
/// The answer to every request whose contract is "the list as it now reads", and the only
/// way the list can ever be filled: the UI owns no flash and computes no part of this.
/// What to call the wallet in slot `slot` in a sentence.
///
/// Read out of the list the embedder itself installed, so the name in a delete's answer is
/// the same string the consent sheet asked the user to type. A slot with no row - a record
/// this session cannot read, or a list that has moved on - falls back to the slot number,
/// which is a true name for it and the one the C4d sheet uses in the same situation.
fn wallet_name(ui: &Ui, slot: u8) -> String {
    ui.wallets()
        .iter()
        .find_map(|row| match row {
            WalletRow::Wallet(w) if w.slot == slot => Some(w.name.clone()),
            _ => None,
        })
        .unwrap_or_else(|| format!("wallet slot {slot}"))
}

fn install_wallets(ui: &mut Ui, store: &mut Option<store::Store>) {
    let Some(s) = store.as_mut().filter(|s| s.is_unlocked()) else {
        // No session, no list - and nothing installed rather than an empty one. An empty
        // list is the statement "this device holds no wallets", which a store nobody has
        // unlocked has not made. `Ui::lock` has already cleared whatever was there.
        log::error!("store: wallet list unavailable: no unlocked store");
        return;
    };
    let rows = wallet_rows(s);
    log::info!("store: wallet list installed: {} occupied slots", rows.len());
    ui.set_wallets(rows);
}

/// Every occupied payload slot, as the post-PIN screens read it.
///
/// Metadata only: no seed is derived here, so the whole list costs one AEAD open per slot
/// rather than one PBKDF2 run per slot. Deriving is what OPENING a wallet is for, and it
/// happens once, for the one slot the user tapped.
///
/// A slot this device cannot read becomes a row and never a gap ([`WalletRow::Unreadable`],
/// R-32). The counts on the destruction sheet are counted from these rows, so a slot
/// dropped because its state would not read would understate what a wipe destroys.
fn wallet_rows(s: &mut store::Store) -> Vec<WalletRow> {
    let registrations = registration_counts(s);
    // Zeroizing because a wallet record IS a mnemonic: this buffer holds the user's words
    // between the AEAD and the parse, and it is reused across slots, so a plain Vec would
    // leave the last one read in freed heap.
    let mut body = Zeroizing::new(vec![0u8; store::Store::max_payload_bytes()]);
    let mut rows = Vec::new();
    for slot in 0..store::Store::payload_slots() {
        match s.payload_state(slot) {
            Ok(SlotState::Empty) => {}
            // Another PIN identity's record, or one whose tag did not verify under this
            // session's key. Either way this session cannot read it, which is what the row
            // says and all it says.
            Ok(SlotState::Opaque) => rows.push(WalletRow::Unreadable { slot }),
            Ok(SlotState::Occupied { .. }) => {
                let count = registrations.get(usize::from(slot)).copied().unwrap_or(0);
                rows.push(wallet_row(s, slot, &mut body, count));
            }
            Err(e) => {
                log::error!("store: payload slot {slot} did not read: {e}");
                rows.push(WalletRow::Unreadable { slot });
            }
        }
    }
    rows
}

/// One occupied payload slot as a row, or the unreadable row when the record will not come
/// back as a wallet.
///
/// The decoded record carries the recovery phrase and is dropped as this function returns;
/// its `Zeroizing` wipes it, and nothing on the row is derived from it.
fn wallet_row(s: &mut store::Store, slot: u8, body: &mut [u8], registrations: u8) -> WalletRow {
    let n = match s.read_payload(slot, body) {
        Ok(n) => n,
        Err(e) => {
            log::error!("store: payload slot {slot} did not open: {e}");
            return WalletRow::Unreadable { slot };
        }
    };
    let Some(bytes) = body.get(..n) else {
        log::error!("store: payload slot {slot} reported {n} bytes into a shorter buffer");
        return WalletRow::Unreadable { slot };
    };
    let record = match WalletRecord::decode(bytes) {
        Ok(r) => r,
        // A body that survived its AEAD and is not a wallet record this build understands.
        // It is still an occupied slot, so it is still a row - with no name, no fingerprint
        // and no path, because inventing blank fields for it would be describing a record
        // this device could not read (R-32).
        Err(e) => {
            log::error!("store: payload slot {slot} is not a readable wallet record: {e}");
            return WalletRow::Unreadable { slot };
        }
    };
    WalletRow::Wallet(WalletInfo {
        registrations,
        // What the RECORD says, which is all a list can know: reading a slot costs one AEAD
        // open and deciding this properly costs a PBKDF2 run per wallet. A format 2 record
        // states it; a format 1 record makes no statement and reads as `None` here. No row
        // renders this field - the identity card does, and by then the wallet is open and
        // the value is measured (see `open_and_install`).
        passphrase: match &record.passphrase {
            StoredPassphrase::Stored(_) => PassphraseState::Stored,
            StoredPassphrase::Applied => PassphraseState::Required,
            StoredPassphrase::None => PassphraseState::None,
        },
        ..stored_wallet(slot, record.label, record.fingerprint.to_string(), record.network)
    })
}

/// How many registry records name each payload slot.
///
/// Counted once for the whole list rather than per wallet: the registry is a flat class of
/// slots, and the alternative re-reads all of it for every wallet on the device.
///
/// This is what is STORED against a slot, not what has been proven. A registration is
/// re-parsed and re-proven against the live seed every time a wallet is opened, and only
/// that can say whether it still holds; a count needs no seed, and the list is a surface
/// that exists before any wallet is open.
fn registration_counts(s: &mut store::Store) -> Vec<u8> {
    let mut counts = vec![0u8; usize::from(store::Store::payload_slots())];
    // A registration record is public - cosigner xpubs, a threshold, a name - so this
    // buffer needs no wiping, unlike the payload one.
    let mut body = vec![0u8; store::Store::max_registry_bytes()];
    for slot in 0..store::Store::registry_slots() {
        match s.registry_state(slot) {
            Ok(SlotState::Occupied { .. }) => {}
            // Empty is empty; `Opaque` belongs to another identity and is not this
            // session's to count.
            Ok(_) => continue,
            Err(e) => {
                log::error!("store: registry slot {slot} did not read: {e}");
                continue;
            }
        }
        let n = match s.read_registry(slot, &mut body) {
            Ok(n) => n,
            Err(e) => {
                log::error!("store: registry slot {slot} did not open: {e}");
                continue;
            }
        };
        let Some(bytes) = body.get(..n) else {
            log::error!("store: registry slot {slot} reported {n} bytes into a shorter buffer");
            continue;
        };
        let record = match RegistrationRecord::decode(bytes) {
            Ok(r) => r,
            // An occupied registry slot this build cannot read. It is not counted against
            // any wallet: a number on the destruction sheet has to come from a record that
            // was read, and this one was not.
            Err(e) => {
                log::error!("store: registry slot {slot} is not a readable registration: {e}");
                continue;
            }
        };
        match counts.get_mut(usize::from(record.wallet_slot)) {
            Some(c) => *c = c.saturating_add(1),
            // A registration naming a slot this layout does not have. Reported and counted
            // against nothing: adding it to some other wallet's total would put a number on
            // the destruction sheet that no record supports.
            None => log::error!(
                "store: registry slot {slot} names payload slot {}, and this layout has {}",
                record.wallet_slot,
                store::Store::payload_slots()
            ),
        }
    }
    counts
}

/// A stored wallet as the post-PIN screens read it, with the four fields the sealed record
/// does not carry filled the same way at every call site.
///
/// - `path` is `m` and `script_type` is "every scheme" because the record names NO scheme
///   (it holds the phrase, the network, a label and a fingerprint) and this device derives
///   all four from the one seed - the export screen has a tab per scheme. Naming one of
///   them here would be this file choosing a scheme the owner never chose. The stateless
///   "use once" wallet already renders exactly this, for exactly this reason.
/// - `kind` is single-sig because a payload slot holds one seed. Multisig membership is a
///   registration held AGAINST that seed, not a different kind of record.
/// - `backup` is verified with no date. The record keeps no evidence of the check and does
///   not need to: the only paths that reach a save are the ones that proved the words -
///   the backup quiz, or a restore of words the user already held - so a record's existence
///   is the evidence. The date is empty because none was stored, and an empty `Verified`
///   renders as the bare badge rather than as a fabricated one.
///
/// `registrations` and `passphrase` are left at the values a caller who has measured
/// neither would have to state; both callers here override them with what they read.
fn stored_wallet(slot: u8, name: String, fingerprint: String, network: Network) -> WalletInfo {
    WalletInfo {
        slot,
        name,
        fingerprint,
        path: String::from("m"),
        script_type: String::from("every scheme"),
        kind: WalletKind::SingleSig,
        backup: BackupState::Verified(String::new()),
        network,
        registrations: 0,
        stored: true,
        passphrase: PassphraseState::None,
    }
}

/// One unlock attempt. The measured milliseconds are the number m4a's exit gate asks for:
/// the whole cost a user waits through between the last digit and an open device.
/// The label this device's own superblock carries, distinguishing a store the PRODUCT
/// formatted from one the test console did (`b"hil"`). Sixteen bytes, padded by the vault.
///
/// Worth spending a field on: a store's origin is not otherwise recoverable after the fact,
/// and "was this device ever formatted by a test build" is a question an owner and an
/// auditor can both reasonably ask of a signer holding real money.
const STORE_LABEL: &[u8] = b"notyas";

/// Install the device name, answering [`UiRequest::SetDeviceName`].
///
/// Public and unsealed, and since 0.2.0 written to the plaintext `settings` partition -
/// see `lock_info` for why it cannot live in the sealed store. It is logged like the
/// network setting, which is the other public device-wide preference: both are safe to log
/// precisely because neither is a secret.
///
/// # What a failure means, and when it is one
///
/// The name is in force either way, because the UI holds it for the life of the power-up.
/// A failure is therefore only ever about SURVIVING a power cycle, and the user is told
/// about it only when there is something to tell: if this device's table has no settings
/// partition - every device flashed before the 0.2.0 table - the name behaves exactly as it
/// did before the region existed, which is a known limitation of that table and not a fault
/// the user can act on. If the region IS there and the write failed, that is a real fault
/// and `device_name_result(false)` puts it on the panel, because a write that quietly did
/// nothing would leave the user believing their device is named.
///
/// Answered on BOTH channels the request documents, like every other write: the verdict,
/// so the screen can navigate or state a refusal, and the lock info as it now reads, so
/// the lock screen behind it draws the name that is actually in force.
fn answer_set_device_name(ui: &mut Ui, store: &mut Option<store::Store>, name: String) {
    if name.is_empty() {
        log::info!("device name: cleared");
    } else {
        log::info!("device name: set to {name:?}");
    }
    let mut record = settings::load();
    let saved = match record.set_device_name(&name) {
        Ok(()) => {
            let stored = settings::save(&record);
            if !stored {
                log::warn!("settings: device name is in force but was not stored");
            }
            // An absent region is not a fault to report: see the doc comment.
            stored || !settings::available()
        }
        Err(e) => {
            // The screen's rules are strictly tighter than the format's - same alphabet,
            // trimmed, and a width limit far below 256 bytes - so this arm is a
            // disagreement between the two and a defect on our side, not a user error.
            log::error!("settings: device name refused by the format: {e:?}");
            false
        }
    };
    ui.device_name_result(saved);
    refresh_lock_info(ui, store.as_ref());
}

/// Install the FIRST PIN, answering [`UiRequest::SetPin`], and report the verdict.
///
/// This is the device's first write - it creates the ledger and the superblock - and until
/// 0.2.0 the only route to it was the test console, which a product build compiles out. A
/// release image therefore could not be given a PIN, and so could not store a wallet.
///
/// Every arm answers. `Ui::pin_created(false)` is what puts a refusal on the panel, and a
/// handler that logged and returned here would leave the user staring at a confirm screen
/// that did nothing - the failure mode this function exists to remove, and the one the rule
/// at the top of `answer_request` names.
fn answer_set_pin(ui: &mut Ui, store: &mut Option<store::Store>, pin: notyas_ui::Secret) {
    let Some(s) = store.as_mut() else {
        log::error!("store: PIN not set: no store on this device");
        ui.pin_created(false);
        return;
    };
    // Length only, like the unlock path: the sealing layer has no opinion about character
    // classes, and the SCREEN owns the floor (LockInfo::min_pin_len, read from the store's
    // own policy so the two can never disagree). A PIN that gets here and is still refused
    // is a bug in that agreement, so it is logged as one rather than blamed on the user.
    let Ok(parsed) = Pin::from_normalized_utf8(pin.as_str()) else {
        log::error!(
            "store: PIN not set: the sealing layer refuses this length, which the screen              should have caught at its own floor"
        );
        ui.pin_created(false);
        return;
    };
    match s.format(&parsed, STORE_LABEL) {
        Ok(ms) => {
            // No PIN, no length, and nothing derived from either.
            log::info!("store: formatted with the first PIN in {ms} ms");
            ui.pin_created(true);
        }
        Err(e) => {
            log::error!("store: format refused: {e}");
            ui.pin_created(false);
        }
    }
    // Whether it worked or not: status, attempt budget and the PIN floor all move on a
    // format, and every screen downstream reads them from here.
    refresh_lock_info(ui, store.as_ref());
}

fn answer_unseal(
    ui: &mut Ui,
    store: &mut Option<store::Store>,
    flow: &mut Flow,
    passphrases: &mut PassSession,
    pin: notyas_ui::Secret,
) {
    let Some(s) = store.as_mut() else {
        ui.unseal_result(UnsealOutcome::Unreadable);
        return;
    };
    let Ok(parsed) = Pin::from_normalized_utf8(pin.as_str()) else {
        // Length only; the crate has no opinion about character classes. A PIN the
        // sealing layer will not accept is a wrong PIN that costs no attempt.
        ui.unseal_result(UnsealOutcome::WrongPin { attempts_left: s.attempts_remaining() });
        return;
    };
    let outcome = match s.unlock(&parsed) {
        Ok(ms) => {
            log::info!("store: unlocked in {ms} ms");
            UnsealOutcome::Unsealed
        }
        // A refusal is not automatically a wrong PIN, and the store's state after one
        // cannot say which it was: a hardware fault and a bad guess both leave it
        // `Formatted`. Only the typed failure knows, so it is what gets matched.
        Err(store::UnlockFailure::NoScratch) => {
            // The Argon2id working set was never allocated (bring-up logs that and warns
            // that PIN operations will refuse). No guess was made, no attempt was spent,
            // and the owner's correct PIN would fail exactly the same way - so this is
            // the store being unreadable, not the PIN being wrong.
            log::error!("store: unlock refused: no Argon2id working set");
            UnsealOutcome::Unreadable
        }
        Err(store::UnlockFailure::Refused(e)) => {
            log::info!("store: unlock refused: {e:?}");
            unseal::refusal_outcome(&e)
        }
    };
    refresh_lock_info(ui, store.as_ref());
    let next = ui.unseal_result(outcome);
    if matches!(outcome, UnsealOutcome::Unsealed) {
        // The wallet list is where an unlock lands, and this is the only thing that can
        // fill it: the UI owns no flash and keeps no list across a lock. AFTER
        // `unseal_result`, which is the call that navigates there, and after the session
        // exists - reading a slot needs one.
        install_wallets(ui, store);
    }
    answer_request(ui, store, flow, passphrases, next);
}

/// The UI never computes a QR (it is no_std; the encoder needs std): a tap on
/// a QR button surfaces here as a request naming a PUBLIC value - receive
/// address or account xpub - and the finished matrix goes back in before the
/// same iteration's repaint. The label is a derivation path / caption (safe to
/// log); the payload is not logged, as a matter of general log hygiene even
/// for public values.
fn answer_qr(ui: &mut Ui, target: notyas_ui::QrTarget) {
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
