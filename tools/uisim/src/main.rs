// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! uisim - renders every notyas-ui screen to PNG for human review.
//!
//! The simulator IS the firmware's usage of the UI crate: it constructs a [`Ui`], taps
//! region centers through the public touch API, and renders the resulting frames. No
//! screen is reached any way a finger could not reach it.
//!
//! # Sample data (all of it public, none of it a real seed)
//!
//! - Dice: 64 sixes. A six maps to digit 0 (SPEC step 2), so RAW mode yields the
//!   all-zeros 128-bit entropy - the canonical BIP39 test vector #1, whose mnemonic is
//!   the world's best-known phrase ("abandon" x11 + "about"). Deliberate: the rendered
//!   words are instantly recognizable as the published test vector and useless as a
//!   wallet.
//! - Passphrase: "TREZOR", the official BIP39 test-vector passphrase, so the schemes
//!   screen shows exactly the keys any implementer can cross-check against the
//!   published vectors.
//! - Verify screen: placeholder values, every one carrying the marker "DUMMY" (the
//!   firmware fills the real ones from hardware). See [`dummy_verify_info`].
//!
//! Output is deterministic: fixed input, fixed geometry, fixed PNG settings; each frame
//! is rendered twice and must match itself byte for byte before it is written.

use std::path::{Path, PathBuf};

use notyas_ui::{QrData, Region, RegionId, TouchEvent, Ui, UiRequest, VerifyInfo, VERSION};

/// Primary panel geometry (Waveshare ESP32-P4 4B: 720x720, 229 PPI).
const W: u32 = 720;
const H: u32 = 720;

/// The all-zero-entropy dice input; see the module docs.
const SIXES: &str = "6666666666666666666666666666666666666666666666666666666666666666";

// ---------------------------------------------------------------------------------------
// Framebuffer
// ---------------------------------------------------------------------------------------

struct Fb {
    w: u32,
    h: u32,
    px: Vec<embedded::Rgb565>,
}

/// The embedded-graphics types come through notyas-ui's public API; the simulator only
/// needs the trait implementations below, kept in one place.
mod embedded {
    pub use embedded_graphics::draw_target::DrawTarget;
    pub use embedded_graphics::geometry::{OriginDimensions, Size};
    pub use embedded_graphics::pixelcolor::{Rgb565, RgbColor};
    pub use embedded_graphics::Pixel;
}

impl Fb {
    fn new(w: u32, h: u32) -> Self {
        Fb { w, h, px: vec![embedded::Rgb565::new(0, 0, 0); (w * h) as usize] }
    }

    /// RGB565 -> RGB888 by bit replication (the same expansion the font blender uses),
    /// row-major RGB bytes ready for the PNG encoder.
    fn rgb888(&self) -> Vec<u8> {
        use embedded::RgbColor;
        let mut out = Vec::with_capacity(self.px.len() * 3);
        for p in &self.px {
            let (r, g, b) = (p.r(), p.g(), p.b());
            out.push((r << 3) | (r >> 2));
            out.push((g << 2) | (g >> 4));
            out.push((b << 3) | (b >> 2));
        }
        out
    }
}

impl embedded::OriginDimensions for Fb {
    fn size(&self) -> embedded::Size {
        embedded::Size::new(self.w, self.h)
    }
}

impl embedded::DrawTarget for Fb {
    type Color = embedded::Rgb565;
    type Error = core::convert::Infallible;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = embedded::Pixel<embedded::Rgb565>>,
    {
        for embedded::Pixel(p, c) in pixels {
            if p.x >= 0 && p.y >= 0 && (p.x as u32) < self.w && (p.y as u32) < self.h {
                self.px[(p.y as u32 * self.w + p.x as u32) as usize] = c;
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------
// Driving
// ---------------------------------------------------------------------------------------

fn region(ui: &Ui, id: RegionId) -> Region {
    ui.regions()
        .into_iter()
        .find(|r| r.id == id)
        .unwrap_or_else(|| panic!("no region {id:?} on {:?}", ui.screen()))
}

fn tap(ui: &mut Ui, id: RegionId) -> Option<UiRequest> {
    let r = region(ui, id).rect;
    let (x, y) = (r.x + r.w / 2, r.y + r.h / 2);
    ui.touch(TouchEvent::Down { x, y });
    ui.touch(TouchEvent::Up { x, y })
}

fn type_dice(ui: &mut Ui, digits: &str) {
    for c in digits.chars() {
        tap(ui, RegionId::Digit(c as u8 - b'0'));
    }
}

fn type_keys(ui: &mut Ui, s: &str) {
    for c in s.chars() {
        if c == ' ' {
            tap(ui, RegionId::Space);
        } else {
            tap(ui, RegionId::Key(c));
        }
    }
}

/// The embedder's `touch -> draw -> tick` loop, which is what the Deriving interstitial
/// exists for: the frame is captured BEFORE the blocking derivation, exactly as the
/// firmware publishes it before spending seconds in PBKDF2.
fn done_and_derive(ui: &mut Ui, out_dir: &Path, name: &str) {
    tap(ui, RegionId::KeyDone);
    assert_eq!(ui.screen(), notyas_ui::ScreenId::Deriving, "Done must park on the interstitial");
    shot(out_dir, name, ui);
    assert!(ui.tick(), "tick must run the pending derivation");
}

// ---------------------------------------------------------------------------------------
// PNG output
// ---------------------------------------------------------------------------------------

fn encode_png(fb: &Fb) -> Vec<u8> {
    let mut bytes = Vec::new();
    {
        let mut enc = png::Encoder::new(&mut bytes, fb.w, fb.h);
        enc.set_color(png::ColorType::Rgb);
        enc.set_depth(png::BitDepth::Eight);
        // Fixed filter + compression: part of the byte-determinism contract.
        enc.set_filter(png::FilterType::Paeth);
        enc.set_compression(png::Compression::Best);
        let mut writer = enc.write_header().expect("png header");
        writer.write_image_data(&fb.rgb888()).expect("png data");
    }
    bytes
}

fn shot(out_dir: &Path, name: &str, ui: &Ui) -> PathBuf {
    let render = || {
        let mut fb = Fb::new(W, H);
        ui.draw(&mut fb).expect("draw");
        encode_png(&fb)
    };
    let first = render();
    let second = render();
    assert_eq!(first, second, "{name}: non-deterministic render");
    let path = out_dir.join(format!("{name}.png"));
    std::fs::write(&path, &first).expect("write png");
    println!("  {} ({} bytes) - {:?}", path.display(), first.len(), ui.screen());
    path
}

// ---------------------------------------------------------------------------------------
// Sample data
// ---------------------------------------------------------------------------------------

/// The Verify-screen values the tour installs.
///
/// Every field is marked DUMMY, and the version is COMPOSED from the crate version rather
/// than written out: a literal "0.1.0-DUMMY" survives a release bump silently, and the
/// screenshot then shows a version the tree has not been at since. That is the whole
/// failure mode of this screen - it exists to report what the running build actually is -
/// so the simulator's stand-in tracks the same constant the real screen reads
/// ([`notyas_ui::VERSION`], which is `CARGO_PKG_VERSION`).
///
/// A field ADDED to `VerifyInfo` cannot go stale here the same way: this is an exhaustive
/// struct literal with no `..Default::default()`, so a new field is a compile error in
/// this file rather than a screenshot that quietly omits a row. Keep it that way.
fn dummy_verify_info() -> VerifyInfo {
    VerifyInfo {
        firmware_version: format!("{VERSION}-DUMMY"),
        board: "DUMMY simulator (no hardware)".into(),
        platform: "DUMMY host render".into(),
        app_sha256: "DUMMY0000000000000000000000000000000000000000000000000000000000".into(),
        source_id: "DUMMY0000000000000000000000000000000000000000000000000000000000".into(),
        self_test: "DUMMY - BIP vectors pass".into(),
        self_test_ok: true,
        radio: "DUMMY - C6 held in reset (GPIO54 low)".into(),
        radio_ok: true,
        secure_boot: "DUMMY - off (dev board)".into(),
        flash_encryption: "DUMMY - off (dev board)".into(),
    }
}

// ---------------------------------------------------------------------------------------
// The tour
// ---------------------------------------------------------------------------------------

fn main() {
    // docs/screenshots/ui relative to the repo root, resolved from this crate.
    let out_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("docs")
        .join("screenshots")
        .join("ui");
    std::fs::create_dir_all(&out_dir).expect("create output dir");

    println!("uisim: rendering notyas-ui at {W}x{H} into {}", out_dir.display());
    println!("sample data: BIP39 test vector #1 (64 sixes -> all-zero entropy, passphrase TREZOR)");

    let mut ui = Ui::new(W, H);
    ui.set_verify_info(dummy_verify_info());

    shot(&out_dir, "01-home", &ui);

    // New seed: 64 sixes in RAW mode -> 128 bits, the all-zeros test vector.
    tap(&mut ui, RegionId::HomeNewSeed);
    type_dice(&mut ui, SIXES);
    shot(&out_dir, "02-dice-entry", &ui);

    // Mnemonic: masked by default; the reveal is a two-step confirm.
    tap(&mut ui, RegionId::DiceDone);
    shot(&out_dir, "03-mnemonic-masked", &ui);
    tap(&mut ui, RegionId::Reveal);
    shot(&out_dir, "04-reveal-confirm", &ui);
    tap(&mut ui, RegionId::ModalConfirm);
    shot(&out_dir, "05-mnemonic-revealed", &ui);

    // Passphrase: opt in, type the official test-vector passphrase in both fields.
    // Masked one bullet per character (the INPUT rule), then revealed through the
    // Show toggle - the two frames the passphrase QA round is about.
    tap(&mut ui, RegionId::Next);
    tap(&mut ui, RegionId::PassToggle);
    tap(&mut ui, RegionId::Shift); // TREZOR is uppercase
    type_keys(&mut ui, "TREZOR");
    tap(&mut ui, RegionId::PassConfirm);
    type_keys(&mut ui, "TREZOR");
    shot(&out_dir, "06-passphrase", &ui);
    tap(&mut ui, RegionId::PassShow);
    shot(&out_dir, "13-passphrase-shown", &ui);
    tap(&mut ui, RegionId::PassShow);

    // Schemes: BIP44 default tab, plus the BIP84 tab. Done paints the interstitial
    // first; `tick` is where PBKDF2 actually runs.
    done_and_derive(&mut ui, &out_dir, "14-deriving");
    shot(&out_dir, "07-schemes-bip44", &ui);
    tap(&mut ui, RegionId::Tab(2));
    shot(&out_dir, "08-schemes-bip84", &ui);

    // QR modal: the account-xpub button raises a request; the simulator answers it
    // with the core's encoder, exactly as the firmware does (public value only).
    let Some(UiRequest::Qr(target)) = tap(&mut ui, RegionId::QrXpub) else {
        panic!("xpub QR tap must raise a request");
    };
    let matrix = notyas_core::qr::matrix(&target.payload).expect("encode xpub");
    let data = QrData::from_matrix(&matrix).expect("square matrix");
    ui.show_qr(target, data);
    shot(&out_dir, "09-schemes-qr", &ui);
    tap(&mut ui, RegionId::ModalClose);

    // Verify device (DUMMY values installed above).
    // Back from Schemes goes through the exit modal chain: Schemes -> Passphrase
    // -> Mnemonic -> Dice -> Home. Each serious screen gates Back with a confirm.
    tap(&mut ui, RegionId::Back);
    shot(&out_dir, "12-exit-modal", &ui); // exit modal over Schemes
    tap(&mut ui, RegionId::ModalConfirm); // -> Passphrase
    tap(&mut ui, RegionId::Back);
    tap(&mut ui, RegionId::ModalConfirm); // -> Mnemonic
    tap(&mut ui, RegionId::Back);
    tap(&mut ui, RegionId::ModalConfirm); // -> Dice
    tap(&mut ui, RegionId::Back); // Dice -> Home (no modal)

    tap(&mut ui, RegionId::HomeVerifyDevice);
    shot(&out_dir, "10-verify-device", &ui);

    // Verify existing seed: the desktop's well-known bad-checksum example, typed in.
    tap(&mut ui, RegionId::Back);
    tap(&mut ui, RegionId::HomeVerifySeed);
    type_keys(&mut ui, "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong");
    shot(&out_dir, "11-phrase-entry", &ui);

    // ...and the same screen mid-word, where the BIP39 completion strip is live. "ab"
    // has more matches than the strip shows, so this is the strip at full width.
    type_keys(&mut ui, " ab");
    shot(&out_dir, "15-phrase-autocomplete", &ui);

    let shots = std::fs::read_dir(&out_dir)
        .expect("read output dir")
        .filter(|e| e.as_ref().is_ok_and(|e| e.path().extension().is_some_and(|x| x == "png")))
        .count();
    println!("done: {shots} screens, deterministic (each frame rendered twice, byte-identical)");
}

// ---------------------------------------------------------------------------------------
// Regression tests (0.2.0-m1: the two 0.1.0 defects the milestone carried forward)
// ---------------------------------------------------------------------------------------
//
// This binary is the only host build that links notyas-ui together with notyas-core's
// std-side `qr` feature, which is exactly the pairing the firmware has and no other host
// crate can have (notyas-ui pins the core with default-features = false so it stays
// provable on bare metal). The QR round trip therefore has nowhere else to be tested off
// the device, and "QR buttons are dead on hardware" is precisely a failure of that round
// trip: request raised -> encoded by the core -> handed back -> modal on screen.

#[cfg(test)]
mod tests {
    use super::*;

    use notyas_ui::ScreenId;

    /// The current screen as PNG bytes - the same encoder `shot` writes with, so a test
    /// comparing frames compares exactly what lands in docs/screenshots.
    fn frame(ui: &Ui) -> Vec<u8> {
        let mut fb = Fb::new(W, H);
        ui.draw(&mut fb).expect("draw");
        encode_png(&fb)
    }

    fn has_region(ui: &Ui, id: RegionId) -> bool {
        ui.regions().iter().any(|r| r.id == id)
    }

    /// The tour's route to the schemes screen, without the PNG writing.
    fn ui_at_schemes() -> Ui {
        let mut ui = Ui::new(W, H);
        tap(&mut ui, RegionId::HomeNewSeed);
        type_dice(&mut ui, SIXES);
        tap(&mut ui, RegionId::DiceDone);
        tap(&mut ui, RegionId::Next);
        tap(&mut ui, RegionId::KeyDone);
        assert_eq!(ui.screen(), ScreenId::Deriving, "Done parks on the interstitial");
        assert!(ui.tick(), "tick runs the pending derivation");
        assert_eq!(ui.screen(), ScreenId::Schemes);
        ui
    }

    /// Defect 1 (m1): the simulator's Verify-screen stand-in must not carry a hardcoded
    /// version. The screen's whole purpose is reporting what the build IS, so a literal
    /// that outlives its release is the one value on it that must not exist.
    #[test]
    fn the_dummy_verify_info_tracks_the_crate_version() {
        let v = dummy_verify_info();
        assert!(
            v.firmware_version.starts_with(VERSION),
            "the simulator reports {:?} while the crate is at {VERSION}",
            v.firmware_version
        );
        // Every value stays marked, so no screenshot can ever be mistaken for a reading
        // taken off real hardware.
        for (field, value) in [
            ("firmware_version", &v.firmware_version),
            ("board", &v.board),
            ("platform", &v.platform),
            ("app_sha256", &v.app_sha256),
            ("source_id", &v.source_id),
            ("self_test", &v.self_test),
            ("radio", &v.radio),
            ("secure_boot", &v.secure_boot),
            ("flash_encryption", &v.flash_encryption),
        ] {
            assert!(value.contains("DUMMY"), "{field} is not marked DUMMY: {value:?}");
        }
    }

    /// ...and the installed values must actually reach the pixels. `set_verify_info` is one
    /// call away from being a no-op, and the failure would be invisible: the screen would
    /// render `VerifyInfo::default()`'s honest "not read" placeholders and still look
    /// plausible in a screenshot.
    #[test]
    fn the_verify_screen_renders_the_installed_values() {
        let mut installed = Ui::new(W, H);
        installed.set_verify_info(dummy_verify_info());
        tap(&mut installed, RegionId::HomeVerifyDevice);
        assert_eq!(installed.screen(), ScreenId::VerifyDevice);

        let mut untouched = Ui::new(W, H);
        tap(&mut untouched, RegionId::HomeVerifyDevice);

        assert_ne!(
            frame(&installed),
            frame(&untouched),
            "the Verify screen ignored set_verify_info"
        );
    }

    /// Defect 2 (m1): the QR round trip end to end, over the crate boundary the firmware
    /// crosses. A tap raises the request, the CORE encodes the payload (this is the step
    /// that is compiled out when the `qr` feature is off, which is how the buttons went
    /// dead), the matrix goes back in, and the modal is on screen and tappable.
    #[test]
    fn a_qr_tap_round_trips_through_the_core_encoder() {
        let mut ui = ui_at_schemes();
        let closed = frame(&ui);
        assert!(!has_region(&ui, RegionId::ModalClose), "no modal to start with");

        let Some(UiRequest::Qr(target)) = tap(&mut ui, RegionId::QrXpub) else {
            panic!("the xpub QR button raised no request");
        };
        assert!(target.label.starts_with("Account xpub"), "label {:?}", target.label);
        assert!(target.payload.starts_with("xpub"), "payload {:?}", target.payload);

        let matrix = notyas_core::qr::matrix(&target.payload).expect("the core encodes it");
        let data = QrData::from_matrix(&matrix).expect("the core hands out a square matrix");
        assert_eq!(data.size() as usize, matrix.len());
        // Orientation and polarity survive the packing: a transposed or inverted symbol
        // has the same size and scans as nothing, so shape alone would not catch it.
        for (y, row) in matrix.iter().enumerate() {
            for (x, &dark) in row.iter().enumerate() {
                assert_eq!(data.module(x as u16, y as u16), dark, "module ({x},{y})");
            }
        }

        ui.show_qr(target, data);
        assert!(has_region(&ui, RegionId::ModalClose), "the modal did not open");
        assert!(!has_region(&ui, RegionId::QrXpub), "the sheet below must be inert");
        let open = frame(&ui);
        assert_ne!(open, closed, "the modal opened without painting anything");

        tap(&mut ui, RegionId::ModalClose);
        assert!(!has_region(&ui, RegionId::ModalClose), "Close did not close the modal");
        assert_eq!(frame(&ui), closed, "closing the modal did not restore the sheet");
    }

    /// Every QR button on the screen answers, not just the one the tour taps: the address
    /// rows and the SLIP-132 rendering are the same path and the same public-value rule.
    #[test]
    fn every_qr_button_of_a_scheme_encodes() {
        let mut ui = ui_at_schemes();
        // Tab 2 is BIP84, the one scheme with both a SLIP-132 rendering and address rows.
        tap(&mut ui, RegionId::Tab(2));
        let buttons: Vec<RegionId> = ui
            .regions()
            .iter()
            .map(|r| r.id)
            .filter(|id| {
                matches!(
                    id,
                    RegionId::QrXpub | RegionId::QrSlip132 | RegionId::QrAddress(_)
                )
            })
            .collect();
        assert!(
            buttons.contains(&RegionId::QrXpub) && buttons.contains(&RegionId::QrSlip132),
            "BIP84 offers an xpub and a zpub QR: {buttons:?}"
        );
        for id in buttons {
            let Some(UiRequest::Qr(target)) = tap(&mut ui, id) else {
                panic!("{id:?} raised no request");
            };
            let matrix = notyas_core::qr::matrix(&target.payload)
                .unwrap_or_else(|e| panic!("{id:?}: {e}"));
            let data = QrData::from_matrix(&matrix).expect("square");
            ui.show_qr(target, data);
            assert!(has_region(&ui, RegionId::ModalClose), "{id:?}: modal did not open");
            tap(&mut ui, RegionId::ModalClose);
        }
    }
}
