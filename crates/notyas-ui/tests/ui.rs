// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Behavioral tests of the UI: layout invariants on two panel geometries, touch
//! hit-testing driven purely through the public API (events in, regions and pixels
//! out), the state machine, and the masking discipline checked at the PIXEL level -
//! the strongest form of "the masked screen contains no word": two different mnemonics
//! must render byte-identical masked frames.

use embedded_graphics::draw_target::DrawTarget;
use embedded_graphics::geometry::{OriginDimensions, Size};
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::Pixel;

use notyas_ui::{theme, Region, RegionId, ScreenId, TouchEvent, Ui};

// ---------------------------------------------------------------------------------------
// Test framebuffer
// ---------------------------------------------------------------------------------------

struct Fb {
    w: u32,
    h: u32,
    px: Vec<Rgb565>,
}

impl Fb {
    fn new(w: u32, h: u32) -> Self {
        Fb { w, h, px: vec![Rgb565::new(0, 0, 0); (w * h) as usize] }
    }

    fn render(ui: &Ui, w: u32, h: u32) -> Fb {
        let mut fb = Fb::new(w, h);
        ui.draw(&mut fb).unwrap();
        fb
    }

    fn count(&self, c: Rgb565) -> usize {
        self.px.iter().filter(|&&p| p == c).count()
    }
}

impl OriginDimensions for Fb {
    fn size(&self) -> Size {
        Size::new(self.w, self.h)
    }
}

impl DrawTarget for Fb {
    type Color = Rgb565;
    type Error = core::convert::Infallible;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Rgb565>>,
    {
        for Pixel(p, c) in pixels {
            if p.x >= 0 && p.y >= 0 && (p.x as u32) < self.w && (p.y as u32) < self.h {
                self.px[(p.y as u32 * self.w + p.x as u32) as usize] = c;
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------
// Driving helpers
// ---------------------------------------------------------------------------------------

fn region(ui: &Ui, id: RegionId) -> Region {
    ui.regions()
        .into_iter()
        .find(|r| r.id == id)
        .unwrap_or_else(|| panic!("no region {id:?} on {:?}", ui.screen()))
}

/// Tap the center of a region, the way the simulator and a finger do.
fn tap(ui: &mut Ui, id: RegionId) {
    let r = region(ui, id).rect;
    let (x, y) = (r.x + r.w / 2, r.y + r.h / 2);
    ui.touch(TouchEvent::Down { x, y });
    ui.touch(TouchEvent::Up { x, y });
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

/// 64 sixes: the all-zero-entropy input. RAW mode maps it to the canonical BIP39 test
/// vector mnemonic ("abandon" x11 + "about"), so nothing here resembles a real seed.
const SIXES: &str = "6666666666666666666666666666666666666666666666666666666666666666";

/// A second 128-bit input with different words, for the masked-pixels invariant:
/// "12345" contributes 2+2+2+1+1 = 8 bits, so 16 repetitions are exactly 128.
const MIXED: &str =
    "12345123451234512345123451234512345123451234512345123451234512345123451234512345";

fn ui_at_mnemonic(w: u32, h: u32, dice: &str) -> Ui {
    let mut ui = Ui::new(w, h);
    tap(&mut ui, RegionId::HomeNewSeed);
    type_dice(&mut ui, dice);
    tap(&mut ui, RegionId::DiceDone);
    assert_eq!(ui.screen(), ScreenId::MnemonicDisplay);
    ui
}

// ---------------------------------------------------------------------------------------
// Layout invariants
// ---------------------------------------------------------------------------------------

/// Every region must lie inside the display and no two may overlap; dice keys carry the
/// 80 px physical floor. Checked on every screen the state machine can reach.
fn check_regions(ui: &Ui, w: i32, h: i32) {
    let regions = ui.regions();
    assert!(!regions.is_empty(), "{:?} has no tappable regions", ui.screen());
    for r in &regions {
        assert!(
            r.rect.x >= 0 && r.rect.y >= 0 && r.rect.right() <= w && r.rect.bottom() <= h,
            "{:?} out of bounds on {:?} at {w}x{h}: {:?}",
            r.id,
            ui.screen(),
            r.rect
        );
        assert!(r.rect.w > 0 && r.rect.h > 0, "{:?} empty on {:?}", r.id, ui.screen());
        if matches!(r.id, RegionId::Digit(_)) {
            assert!(
                r.rect.w >= 80 && r.rect.h >= 80,
                "dice key {:?} below 80px at {w}x{h}: {:?}",
                r.id,
                r.rect
            );
        }
    }
    for (i, a) in regions.iter().enumerate() {
        for b in &regions[i + 1..] {
            assert!(
                !a.rect.overlaps(&b.rect),
                "{:?} overlaps {:?} on {:?} at {w}x{h}",
                a.id,
                b.id,
                ui.screen()
            );
        }
    }
}

/// Drive the state machine through every screen (and the modal) on one geometry,
/// checking regions and doing a full render at each stop.
fn walk_all_screens(w: u32, h: u32) {
    let check = |ui: &Ui| {
        check_regions(ui, w as i32, h as i32);
        Fb::render(ui, w, h); // must not panic on any screen
    };

    let mut ui = Ui::new(w, h);
    check(&ui);

    // Dice -> mnemonic -> modal -> revealed -> passphrase (on) -> schemes.
    tap(&mut ui, RegionId::HomeNewSeed);
    check(&ui);
    type_dice(&mut ui, SIXES);
    check(&ui);
    tap(&mut ui, RegionId::DiceDone);
    check(&ui);
    tap(&mut ui, RegionId::Reveal);
    check(&ui); // modal open: only the modal's two buttons
    assert_eq!(ui.regions().len(), 2);
    tap(&mut ui, RegionId::ModalConfirm);
    check(&ui);
    tap(&mut ui, RegionId::Next);
    check(&ui);
    tap(&mut ui, RegionId::PassToggle);
    check(&ui);
    type_keys(&mut ui, "ab");
    check(&ui); // confirm field now present
    tap(&mut ui, RegionId::PassConfirm);
    type_keys(&mut ui, "ab");
    tap(&mut ui, RegionId::KeyDone);
    assert_eq!(ui.screen(), ScreenId::Schemes);
    check(&ui);
    for i in 0..4 {
        tap(&mut ui, RegionId::Tab(i));
        check(&ui);
    }
    tap(&mut ui, RegionId::Back);
    assert_eq!(ui.screen(), ScreenId::Home);

    // Phrase entry, all keyboard pages.
    tap(&mut ui, RegionId::HomeVerifySeed);
    check(&ui);
    tap(&mut ui, RegionId::Shift);
    check(&ui);
    tap(&mut ui, RegionId::PageDigits);
    check(&ui);
    tap(&mut ui, RegionId::PageSymbols);
    check(&ui);
    tap(&mut ui, RegionId::PageLetters);
    check(&ui);
    tap(&mut ui, RegionId::Back);

    // Verify device.
    tap(&mut ui, RegionId::HomeVerifyDevice);
    assert_eq!(ui.screen(), ScreenId::VerifyDevice);
    check(&ui);
    tap(&mut ui, RegionId::Back);
    assert_eq!(ui.screen(), ScreenId::Home);
}

#[test]
fn layout_holds_on_720x720() {
    walk_all_screens(720, 720);
}

#[test]
fn layout_holds_on_800x480() {
    walk_all_screens(800, 480);
}

// ---------------------------------------------------------------------------------------
// State machine and hit testing
// ---------------------------------------------------------------------------------------

#[test]
fn done_is_inert_below_min_secure_bits() {
    let mut ui = Ui::new(720, 720);
    tap(&mut ui, RegionId::HomeNewSeed);
    // 63 sixes = 126 bits; raw mode uses whole 32-bit blocks -> 96 effective. Refused.
    type_dice(&mut ui, &SIXES[..63]);
    tap(&mut ui, RegionId::DiceDone);
    assert_eq!(ui.screen(), ScreenId::DiceEntry);
    // One more roll crosses 128 exactly.
    type_dice(&mut ui, "6");
    tap(&mut ui, RegionId::DiceDone);
    assert_eq!(ui.screen(), ScreenId::MnemonicDisplay);
}

#[test]
fn backspace_removes_rolls() {
    let mut ui = Ui::new(720, 720);
    tap(&mut ui, RegionId::HomeNewSeed);
    type_dice(&mut ui, SIXES); // 128 bits: Done would succeed
    tap(&mut ui, RegionId::DiceBackspace); // 126 bits: it must not
    tap(&mut ui, RegionId::DiceDone);
    assert_eq!(ui.screen(), ScreenId::DiceEntry);
}

#[test]
fn fixed_mode_effective_bits_gate_matches_desktop() {
    // In FIXED mode the mnemonic is a hash stretch: 24 words advertise 256 ENT bits,
    // but three rolls are still three rolls. Done must stay inert (effective bits rule).
    let mut ui = Ui::new(720, 720);
    tap(&mut ui, RegionId::HomeNewSeed);
    tap(&mut ui, RegionId::ModeToggle); // RAW -> FIXED 24
    type_dice(&mut ui, "123");
    tap(&mut ui, RegionId::DiceDone);
    assert_eq!(ui.screen(), ScreenId::DiceEntry);
    // Enough rolls for 128 effective bits unlocks it, and FIXED yields a mnemonic.
    type_dice(&mut ui, SIXES);
    tap(&mut ui, RegionId::DiceDone);
    assert_eq!(ui.screen(), ScreenId::MnemonicDisplay);
}

#[test]
fn back_zeroizes_by_leaving_and_home_restarts_clean() {
    let mut ui = Ui::new(720, 720);
    tap(&mut ui, RegionId::HomeNewSeed);
    type_dice(&mut ui, SIXES);
    tap(&mut ui, RegionId::Back);
    assert_eq!(ui.screen(), ScreenId::Home);
    // Re-entering starts from zero rolls: Done is inert again.
    tap(&mut ui, RegionId::HomeNewSeed);
    tap(&mut ui, RegionId::DiceDone);
    assert_eq!(ui.screen(), ScreenId::DiceEntry);
}

#[test]
fn a_drag_is_not_a_tap() {
    let mut ui = Ui::new(720, 720);
    let r = region(&ui, RegionId::HomeNewSeed).rect;
    let (x, y) = (r.x + r.w / 2, r.y + r.h / 2);
    ui.touch(TouchEvent::Down { x, y });
    ui.touch(TouchEvent::Move { x, y: y + 40 });
    ui.touch(TouchEvent::Up { x, y: y + 40 });
    assert_eq!(ui.screen(), ScreenId::Home, "a 40px drag must not activate a button");
}

#[test]
fn passphrase_mismatch_blocks_done() {
    let mut ui = ui_at_mnemonic(720, 720, SIXES);
    tap(&mut ui, RegionId::Next);
    tap(&mut ui, RegionId::PassToggle);
    type_keys(&mut ui, "abc");
    tap(&mut ui, RegionId::PassConfirm);
    type_keys(&mut ui, "abd");
    tap(&mut ui, RegionId::KeyDone);
    assert_eq!(ui.screen(), ScreenId::PassphraseEntry, "mismatched passphrases must not derive");
    // Fix the confirm field and proceed.
    tap(&mut ui, RegionId::KeyBackspace);
    type_keys(&mut ui, "c");
    tap(&mut ui, RegionId::KeyDone);
    assert_eq!(ui.screen(), ScreenId::Schemes);
}

#[test]
fn phrase_entry_requires_words_and_reaches_schemes() {
    let mut ui = Ui::new(720, 720);
    tap(&mut ui, RegionId::HomeVerifySeed);
    tap(&mut ui, RegionId::KeyDone); // nothing typed
    assert_eq!(ui.screen(), ScreenId::PhraseEntry);
    type_keys(&mut ui, "zoo zoo zoo");
    tap(&mut ui, RegionId::KeyDone);
    assert_eq!(ui.screen(), ScreenId::PassphraseEntry);
    tap(&mut ui, RegionId::KeyDone); // passphrase off -> continue
    assert_eq!(ui.screen(), ScreenId::Schemes);
}

// ---------------------------------------------------------------------------------------
// Masking discipline
// ---------------------------------------------------------------------------------------

#[test]
fn masked_frame_is_independent_of_the_words() {
    // Two different 12-word mnemonics. If the masked screen leaked ANY function of the
    // words - letters, lengths, anything - these frames would differ somewhere.
    let a = Fb::render(&ui_at_mnemonic(720, 720, SIXES), 720, 720);
    let b = Fb::render(&ui_at_mnemonic(720, 720, MIXED), 720, 720);
    assert_eq!(a.px, b.px, "masked mnemonic frames must be pixel-identical across seeds");
}

#[test]
fn reveal_needs_the_modal_and_cancel_keeps_the_mask() {
    let mut ui = ui_at_mnemonic(720, 720, SIXES);
    let masked = Fb::render(&ui, 720, 720);

    tap(&mut ui, RegionId::Reveal);
    assert_eq!(ui.screen(), ScreenId::MnemonicDisplay);
    // Cancel: still masked, frame identical to before the modal.
    tap(&mut ui, RegionId::ModalCancel);
    let after_cancel = Fb::render(&ui, 720, 720);
    assert_eq!(masked.px, after_cancel.px, "cancelling the modal must change nothing");

    // Confirm: only now do the words appear.
    tap(&mut ui, RegionId::Reveal);
    tap(&mut ui, RegionId::ModalConfirm);
    let revealed = Fb::render(&ui, 720, 720);
    assert_ne!(masked.px, revealed.px, "reveal must actually change the frame");
}

#[test]
fn no_reveal_region_after_reveal() {
    let mut ui = ui_at_mnemonic(720, 720, SIXES);
    tap(&mut ui, RegionId::Reveal);
    tap(&mut ui, RegionId::ModalConfirm);
    assert!(
        !ui.regions().iter().any(|r| r.id == RegionId::Reveal),
        "revealed screen must not offer Reveal again"
    );
}

#[test]
fn masked_field_paints_inside_its_rect() {
    // The mask is a FIXED 24-bullet run; on the narrow side-by-side fields of the
    // 800x480 landscape layout it is wider than the field and must be clipped, not
    // bleed across the gap into the confirm field. The gap column between the two
    // fields must stay free of glyph ink.
    let mut ui = ui_at_mnemonic(800, 480, SIXES);
    tap(&mut ui, RegionId::Next);
    tap(&mut ui, RegionId::PassToggle);
    type_keys(&mut ui, "a");
    let entry = region(&ui, RegionId::PassEntry).rect;
    let fb = Fb::render(&ui, 800, 480);
    for y in entry.y..entry.y + entry.h {
        for x in entry.right() + 1..entry.right() + 12 {
            let px = fb.px[(y as u32 * fb.w + x as u32) as usize];
            assert_ne!(
                px,
                theme::INK_PRIMARY,
                "mask ink escaped the entry field at ({x},{y})"
            );
        }
    }
}

#[test]
fn debug_impl_names_no_secrets() {
    let ui = ui_at_mnemonic(720, 720, SIXES);
    let dbg = format!("{ui:?}");
    assert!(dbg.contains("MnemonicDisplay"));
    assert!(!dbg.contains("abandon"), "Debug must not leak words: {dbg}");
    assert!(!dbg.contains('6'), "Debug must not leak rolls: {dbg}");
}

// ---------------------------------------------------------------------------------------
// Golden smoke
// ---------------------------------------------------------------------------------------

#[test]
fn home_renders_butter_paper() {
    let ui = Ui::new(720, 720);
    let fb = Fb::render(&ui, 720, 720);
    assert!(fb.count(theme::PAPER_1) > 100_000, "the page must be paper-1");
    assert!(fb.count(theme::ACCENT) > 1_000, "the primary button must be cobalt");
}
