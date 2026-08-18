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
//! - Verify screen: placeholder values, every one prefixed "DUMMY" (the firmware fills
//!   the real ones from hardware).
//!
//! Output is deterministic: fixed input, fixed geometry, fixed PNG settings; each frame
//! is rendered twice and must match itself byte for byte before it is written.

use std::path::{Path, PathBuf};

use notyas_ui::{QrData, Region, RegionId, TouchEvent, Ui, UiRequest, VerifyInfo};

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
    ui.set_verify_info(VerifyInfo {
        firmware_version: "0.1.0-DUMMY".into(),
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
    });

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
    tap(&mut ui, RegionId::Next);
    tap(&mut ui, RegionId::PassToggle);
    tap(&mut ui, RegionId::Shift); // TREZOR is uppercase
    type_keys(&mut ui, "TREZOR");
    tap(&mut ui, RegionId::PassConfirm);
    type_keys(&mut ui, "TREZOR");
    shot(&out_dir, "06-passphrase", &ui);

    // Schemes: BIP44 default tab, plus the BIP84 tab.
    tap(&mut ui, RegionId::KeyDone);
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

    println!("done: 13 screens, deterministic (each frame rendered twice, byte-identical)");
}
