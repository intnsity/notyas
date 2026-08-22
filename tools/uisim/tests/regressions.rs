// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The two 0.1.0 defects 0.2.0-m1 carried forward, and the sample data's own contract.
//!
//! This crate is the only host build that links notyas-ui together with notyas-core's
//! std-side `qr` feature, which is exactly the pairing the firmware has and no other host
//! crate can have (notyas-ui pins the core with default-features = false so it stays
//! provable on bare metal). The QR round trip therefore has nowhere else to be tested off
//! the device, and "QR buttons are dead on hardware" is precisely a failure of that round
//! trip: request raised -> encoded by the core -> handed back -> modal on screen.

use notyas_ui::layout::Rect;
use notyas_ui::{QrData, RegionId, ScreenId, TouchEvent, Ui, UiRequest, VERSION};

use uisim::catalog::{build, Frame, CATALOG};
use uisim::drive::{scroll_to, tap, ui_has};
use uisim::fixtures::dummy_verify_info;
use uisim::panel::Panel;

/// The primary panel, which is what these tests measure on: they are about behaviour
/// behind the pixels, and the gate is what covers every panel.
const PANEL: (u32, u32) = (720, 720);

fn frame_named(name: &str) -> &'static Frame {
    CATALOG.iter().find(|f| f.name == name).unwrap_or_else(|| panic!("no frame {name:?}"))
}

fn at(name: &str) -> Ui {
    build(frame_named(name), PANEL)
}

/// The current screen as pixels, through the gate's own render target.
fn pixels(ui: &Ui) -> Vec<u8> {
    let mut target = Panel::new(PANEL.0, PANEL.1);
    ui.draw(&mut target).expect("draw");
    target.rgb888()
}

/// Defect 1 (m1): the simulator's Verify-screen stand-in must not carry a hardcoded
/// version. The screen's whole purpose is reporting what the build IS, so a literal that
/// outlives its release is the one value on it that must not exist.
#[test]
fn the_dummy_verify_info_tracks_the_crate_version() {
    let v = dummy_verify_info();
    assert!(
        v.firmware_version.as_deref().is_some_and(|s| s.starts_with(VERSION)),
        "the simulator reports {:?} while the crate is at {VERSION}",
        v.firmware_version
    );
    // Every free-text value stays marked, so no screenshot can ever be mistaken for a
    // reading taken off real hardware.
    for (field, value) in [
        ("firmware_version", &v.firmware_version),
        ("board", &v.board),
        ("idf_app", &v.idf_app),
        ("idf_bootloader", &v.idf_bootloader),
        ("storage", &v.storage),
        ("radio", &v.radio),
        ("self_test", &v.self_test),
    ] {
        let value = value.as_deref().unwrap_or("");
        assert!(value.contains("DUMMY"), "{field} is not marked DUMMY: {value:?}");
    }
    // The digests cannot carry the word - they are hex - so they carry a repeating byte
    // instead, which no real SHA-256 is and which a reader recognises on sight.
    let repeating_byte = |field: &str, hex: &str| {
        let first: String = hex.chars().take(2).collect();
        assert!(
            !hex.is_empty()
                && hex.chars().collect::<Vec<_>>().chunks(2).all(|c| {
                    c.iter().collect::<String>() == first
                }),
            "{field} is not a recognisably fake byte pattern: {hex:?}"
        );
    };
    for (field, value) in [
        ("firmware_digest", &v.firmware_digest),
        ("die_unique_id", &v.die_unique_id),
        ("wallets_digest", &v.wallets_digest),
        ("counters_digest", &v.counters_digest),
    ] {
        repeating_byte(field, value.hex().unwrap_or(""));
    }
    for (field, region) in
        [("app", &v.app), ("bootloader", &v.bootloader), ("partition_table", &v.partition_table)]
    {
        repeating_byte(field, region.as_ref().map(|r| r.sha256.as_str()).unwrap_or(""));
    }
}

/// ...and the installed values must actually reach the pixels. `set_verify_info` is one
/// call away from being a no-op, and the failure would be invisible: the screen would
/// render `VerifyInfo::default()`'s honest "not read" placeholders and still look
/// plausible in a screenshot.
#[test]
fn the_verify_screen_renders_the_installed_values() {
    let installed = at("verify-device/pre-pin");
    let mut untouched = Ui::new(PANEL.0, PANEL.1);
    tap(&mut untouched, RegionId::HomeVerifyDevice);
    assert_eq!(untouched.screen(), ScreenId::VerifyDevice);
    assert_ne!(pixels(&installed), pixels(&untouched), "the Verify screen ignored set_verify_info");
}

/// The S-46 states the catalogue claims are actually different states.
///
/// The gate proves each frame lands on VerifyDevice and matches its golden; it cannot
/// prove two frames are not the SAME picture under two names, because two identical
/// frames have two identical, perfectly stable digests. This does.
#[test]
fn the_verify_frames_are_five_distinct_states() {
    let names = [
        "verify-device/pre-pin",
        "verify-device/digests",
        "verify-device/unlocked",
        "verify-device/reserved-space",
        "verify-device/acknowledge",
    ];
    let frames: Vec<Vec<u8>> = names.iter().map(|n| pixels(&at(n))).collect();
    for (i, a) in frames.iter().enumerate() {
        for (j, b) in frames.iter().enumerate().skip(i + 1) {
            assert_ne!(a, b, "{} and {} render the same picture", names[i], names[j]);
        }
    }
    // The Busy frame is a screen of its own and offers nothing to tap: a C3 screen with a
    // control on it would be a screen a user could leave mid-scan.
    let busy = at("scanning-flash/progress");
    assert_eq!(busy.screen(), ScreenId::ScanningFlash);
    assert!(busy.regions().is_empty(), "a C3 Busy screen offers nothing");
}

/// Defect 2 (m1): the QR round trip end to end, over the crate boundary the firmware
/// crosses. A tap raises the request, the CORE encodes the payload (this is the step that
/// is compiled out when the `qr` feature is off, which is how the buttons went dead), the
/// matrix goes back in, and the modal is on screen and tappable.
#[test]
fn a_qr_tap_round_trips_through_the_core_encoder() {
    let mut ui = at("schemes/bip84");
    assert!(!ui_has(&ui, RegionId::ModalClose), "no modal to start with");

    // Reached by dragging, because the descriptor block and its explainer lead the tab and
    // put the bare xpub's button below the fold. `scroll_to` is a no-op on a panel tall
    // enough to show it already, so this is one code path on every geometry.
    scroll_to(&mut ui, RegionId::QrXpub);
    // Photographed AFTER the drag, not before it: this is the picture the last assertion
    // demands the sheet come back to, and a modal closes onto the scroll position it was
    // opened from rather than onto the top of the tab. Taken at scroll 0 it would assert
    // that closing the modal also scrolls the screen back up, which is not what closing a
    // modal does or should do.
    let closed = pixels(&ui);

    let Some(UiRequest::Qr(target)) = tap(&mut ui, RegionId::QrXpub) else {
        panic!("the xpub QR button raised no request");
    };
    assert!(target.label.starts_with("Account xpub"), "label {:?}", target.label);
    assert!(target.payload.starts_with("xpub"), "payload {:?}", target.payload);

    let matrix = notyas_core::qr::matrix(&target.payload).expect("the core encodes it");
    let data = QrData::from_matrix(&matrix).expect("the core hands out a square matrix");
    assert_eq!(data.size() as usize, matrix.len());
    // Orientation and polarity survive the packing: a transposed or inverted symbol has
    // the same size and scans as nothing, so shape alone would not catch it.
    for (y, row) in matrix.iter().enumerate() {
        for (x, &dark) in row.iter().enumerate() {
            assert_eq!(data.module(x as u16, y as u16), dark, "module ({x},{y})");
        }
    }

    ui.show_qr(target, data);
    assert!(ui_has(&ui, RegionId::ModalClose), "the modal did not open");
    assert!(!ui_has(&ui, RegionId::QrXpub), "the sheet below must be inert");
    assert_ne!(pixels(&ui), closed, "the modal opened without painting anything");

    tap(&mut ui, RegionId::ModalClose);
    assert!(!ui_has(&ui, RegionId::ModalClose), "Close did not close the modal");
    assert_eq!(pixels(&ui), closed, "closing the modal did not restore the sheet");
}

/// Every region id the schemes screen ever offers, on any tab it starts on, discovered
/// by dragging through the whole of it rather than assumed.
///
/// A `RegionId::Qr*` allow-list here would have exactly the failure mode this function
/// exists to close: a new QR button joins the screen, nobody adds its variant to the
/// list, and the coverage gap is silent. Scrolling to the clamp and back finds every
/// region that ever exists on screen - QR or not - so the caller can decide what counts
/// as a QR button by what TAPPING it returns, not by its name.
///
/// "The clamp" is decided on (id, RECT) pairs and never on the id set alone. A drag moves
/// the content, and on tall content two consecutive viewports can hold the same regions at
/// different heights - five address rows and no new button between them is enough. Compared
/// by id alone that reads as "the screen stopped moving", the walk returns after two drags,
/// and the caller silently covers a fraction of the screen while still passing. Rects settle
/// only when the scroll does, which is the property the walk is actually waiting for.
fn every_region_id_on(name: &str) -> Vec<RegionId> {
    /// Every region the screen is offering right now, with where it is - the state whose
    /// stability means "this screen has stopped scrolling".
    fn snapshot(ui: &Ui) -> Vec<(RegionId, Rect)> {
        ui.regions().iter().map(|r| (r.id, r.rect)).collect()
    }

    let mut ui = at(name);
    let mut ids: Vec<RegionId> = ui.regions().iter().map(|r| r.id).collect();
    let mut prev = snapshot(&ui);
    for step in 0.. {
        assert!(step < 64, "{name}: scrolling to the clamp never settles");
        ui.touch(TouchEvent::Down { x: 100, y: 400 });
        ui.touch(TouchEvent::Move { x: 100, y: 240 });
        ui.touch(TouchEvent::Up { x: 100, y: 240 });
        let now = snapshot(&ui);
        for &(id, _) in &now {
            if !ids.contains(&id) {
                ids.push(id);
            }
        }
        if now == prev {
            // The clamp: one more drag moved nothing at all, so nothing further is reachable.
            break;
        }
        prev = now;
    }
    ids
}

/// Every QR button on the screen answers, not just the one the catalogue photographs -
/// found by tapping every region the screen ever offers (see [`every_region_id_on`]) and
/// treating whichever ones answer with [`UiRequest::Qr`] as the QR buttons, rather than
/// naming them: `RegionId::QrDescriptor` joined the screen with zero coverage here
/// because the old filter matched three named variants and this one is silent about
/// what a QR button IS in the type system, so the next one joins by construction.
///
/// Each tap runs on a fresh `Ui`, scrolled to that one region with the same drag a
/// finger would use ([`scroll_to`]) - not the accumulating `ui` the discovery pass
/// scrolled, and not a raw coordinate hit - so a non-QR region (Back, a tab) tapped along
/// the way cannot leave a later iteration on the wrong screen or the wrong scroll.
#[test]
fn every_qr_button_of_a_scheme_encodes() {
    let mut qr_buttons = Vec::new();
    for id in every_region_id_on("schemes/bip84") {
        let mut ui = at("schemes/bip84");
        if !ui_has(&ui, id) {
            scroll_to(&mut ui, id);
        }
        let Some(UiRequest::Qr(target)) = tap(&mut ui, id) else { continue };
        qr_buttons.push(id);

        let matrix =
            notyas_core::qr::matrix(&target.payload).unwrap_or_else(|e| panic!("{id:?}: {e}"));
        let data = QrData::from_matrix(&matrix).expect("square");
        ui.show_qr(target, data);
        assert!(ui_has(&ui, RegionId::ModalClose), "{id:?}: modal did not open");
        tap(&mut ui, RegionId::ModalClose);
    }
    assert!(
        qr_buttons.contains(&RegionId::QrXpub) && qr_buttons.contains(&RegionId::QrSlip132),
        "BIP84 offers an xpub and a zpub QR: {qr_buttons:?}"
    );
    assert!(
        qr_buttons.contains(&RegionId::QrDescriptor),
        "the descriptor QR button was not exercised: {qr_buttons:?}"
    );
    let addresses = qr_buttons.iter().filter(|id| matches!(id, RegionId::QrAddress(_))).count();
    assert_eq!(
        addresses, notyas_ui::ADDRESS_ROWS as usize,
        "every derived address row must offer its own QR: {qr_buttons:?}"
    );
}
