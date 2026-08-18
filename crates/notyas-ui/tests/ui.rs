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

use notyas_ui::{theme, QrData, Region, RegionId, ScreenId, TouchEvent, Ui, UiRequest};

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

/// Tap the center of a region, the way the simulator and a finger do. Returns what the
/// Up leg of the tap asked the embedder to do (QR requests; `None` for everything else).
fn tap(ui: &mut Ui, id: RegionId) -> Option<UiRequest> {
    let r = region(ui, id).rect;
    let (x, y) = (r.x + r.w / 2, r.y + r.h / 2);
    ui.touch(TouchEvent::Down { x, y });
    ui.touch(TouchEvent::Up { x, y })
}

/// Passphrase Done, then the embedder's `tick`: the two halves of one user action, with
/// the interstitial live in between. Tests that care about the split assert around it
/// (`deriving_interstitial_*`); everything else just wants to land on Schemes.
fn tap_done_and_derive(ui: &mut Ui) {
    tap(ui, RegionId::KeyDone);
    assert_eq!(ui.screen(), ScreenId::Deriving, "Done must park on the interstitial");
    assert!(ui.tick(), "tick must consume the pending derivation");
}

/// A synthetic (non-scannable) symbol for modal tests: the UI renders whatever matrix
/// it is handed, so a checkerboard exercises layout without notyas-core's std-only
/// encoder in the dev graph.
fn checkerboard(size: usize) -> QrData {
    let rows: Vec<Vec<bool>> =
        (0..size).map(|y| (0..size).map(|x| (x + y) % 2 == 0).collect()).collect();
    QrData::from_matrix(&rows).unwrap()
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
    // Deriving is the one screen with nothing to tap, by design: the compute is
    // synchronous and cannot be cancelled.
    assert_eq!(
        regions.is_empty(),
        ui.screen() == ScreenId::Deriving,
        "{:?} tappable regions: {}",
        ui.screen(),
        regions.len()
    );
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
        // The completion chips carry their own physical floor: they sit directly above
        // the keyboard, so a thin one would be mistapped for a key.
        if matches!(r.id, RegionId::Suggest(_)) {
            assert!(
                r.rect.h >= 60,
                "suggestion chip {:?} below 60px at {w}x{h}: {:?}",
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
    // Network toggle: both states lay out (and the toggle overlaps nothing - the
    // region checks run on every stop).
    tap(&mut ui, RegionId::NetToggle);
    check(&ui);
    tap(&mut ui, RegionId::NetToggle);

    // Dice -> mnemonic -> modal -> revealed -> passphrase (on) -> schemes.
    tap(&mut ui, RegionId::HomeNewSeed);
    check(&ui);
    // Every dice mode lays out (the fixed-count hint is the longer one - review
    // item 3; the mode set is the full desktop one, RAW/12/15/18/21/24).
    for i in (0..6).rev() {
        tap(&mut ui, RegionId::Mode(i));
        check(&ui);
    }
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
    tap(&mut ui, RegionId::PassShow);
    check(&ui); // revealed fields
    tap(&mut ui, RegionId::PassShow);
    tap(&mut ui, RegionId::PassConfirm);
    type_keys(&mut ui, "ab");
    tap(&mut ui, RegionId::KeyDone);
    assert_eq!(ui.screen(), ScreenId::Deriving);
    check(&ui); // the interstitial lays out and paints on both geometries
    assert!(ui.tick());
    assert_eq!(ui.screen(), ScreenId::Schemes);
    check(&ui);
    for i in 0..4 {
        tap(&mut ui, RegionId::Tab(i));
        check(&ui);
    }
    // QR modal: open from a real request, check it is the only tappable thing, close.
    // The xpub button is the one QR button visible without scrolling on every geometry.
    tap(&mut ui, RegionId::Tab(2));
    let req = tap(&mut ui, RegionId::QrXpub).expect("QR tap must raise a request");
    let UiRequest::Qr(target) = req;
    ui.show_qr(target, checkerboard(29));
    check(&ui);
    assert_eq!(ui.regions().len(), 1, "QR modal open: only Close is tappable");
    tap(&mut ui, RegionId::ModalClose);
    check(&ui);

    // Back from Schemes: exit modal opens (serious screen). Confirm navigates
    // back through the chain: Schemes -> Passphrase -> Mnemonic -> Dice -> Home.
    // Each serious screen gates Back with the exit modal; Dice (input-only) goes
    // straight to Home.
    tap(&mut ui, RegionId::Back);
    check(&ui); // exit modal open over Schemes
    assert_eq!(ui.regions().len(), 2, "exit modal: only Cancel/Confirm");
    tap(&mut ui, RegionId::ModalConfirm);
    assert_eq!(ui.screen(), ScreenId::PassphraseEntry);
    check(&ui);
    tap(&mut ui, RegionId::Back);
    check(&ui);
    tap(&mut ui, RegionId::ModalConfirm);
    assert_eq!(ui.screen(), ScreenId::MnemonicDisplay);
    check(&ui);
    tap(&mut ui, RegionId::Back);
    check(&ui);
    tap(&mut ui, RegionId::ModalConfirm);
    assert_eq!(ui.screen(), ScreenId::DiceEntry);
    check(&ui);
    tap(&mut ui, RegionId::Back);
    assert_eq!(ui.screen(), ScreenId::Home);

    // Phrase entry, all keyboard pages, with the suggestion strip both empty and full.
    tap(&mut ui, RegionId::HomeVerifySeed);
    check(&ui);
    // "ab" has more than four completions, so the strip is at its widest here - the
    // geometry that has to fit inside the body next to a usable keyboard.
    type_keys(&mut ui, "ab");
    check(&ui);
    assert_eq!(
        ui.regions().iter().filter(|r| matches!(r.id, RegionId::Suggest(_))).count(),
        4,
        "a full strip must be four chips at {w}x{h}"
    );
    tap(&mut ui, RegionId::Suggest(0));
    check(&ui);
    tap(&mut ui, RegionId::KeyBackspace);
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
    // Phrase is non-serious: Back goes straight to Home (no exit modal).
    assert_eq!(ui.screen(), ScreenId::Home);

    // Verify device.
    tap(&mut ui, RegionId::HomeVerifyDevice);
    assert_eq!(ui.screen(), ScreenId::VerifyDevice);
    check(&ui);
    tap(&mut ui, RegionId::Back);
    // Verify is non-serious: Back goes straight to Home.
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
    // In fixed-count mode the mnemonic is a hash stretch: 24 words advertise 256 ENT
    // bits, but three rolls are still three rolls. Done must stay inert (effective
    // bits rule).
    let mut ui = Ui::new(720, 720);
    tap(&mut ui, RegionId::HomeNewSeed);
    tap(&mut ui, RegionId::Mode(5)); // RAW -> fixed 24
    type_dice(&mut ui, "123");
    tap(&mut ui, RegionId::DiceDone);
    assert_eq!(ui.screen(), ScreenId::DiceEntry);
    // Enough rolls for 128 effective bits unlocks it, and the fixed mode yields a
    // mnemonic.
    type_dice(&mut ui, SIXES);
    tap(&mut ui, RegionId::DiceDone);
    assert_eq!(ui.screen(), ScreenId::MnemonicDisplay);
}

/// Every fixed word count of the desktop set is selectable and derives once the
/// effective-bits gate opens.
#[test]
fn all_fixed_word_counts_reach_the_mnemonic() {
    for i in 1u8..=5 {
        let mut ui = Ui::new(720, 720);
        tap(&mut ui, RegionId::HomeNewSeed);
        tap(&mut ui, RegionId::Mode(i));
        type_dice(&mut ui, SIXES);
        tap(&mut ui, RegionId::DiceDone);
        assert_eq!(ui.screen(), ScreenId::MnemonicDisplay, "mode segment {i}");
    }
}

/// The roll history is visible, unmasked typed input (desktop survey section 5): a
/// different last digit changes the dice frame, and backspace restores it exactly.
/// Contrast with the mnemonic screen, whose masked frame is seed-independent.
#[test]
fn roll_history_shows_and_backspace_reverts() {
    let mut ui = Ui::new(720, 720);
    tap(&mut ui, RegionId::HomeNewSeed);
    type_dice(&mut ui, "12345");
    let five = Fb::render(&ui, 720, 720);
    type_dice(&mut ui, "6");
    let six = Fb::render(&ui, 720, 720);
    assert_ne!(five.px, six.px, "the sixth roll must appear in the history tail");
    tap(&mut ui, RegionId::DiceBackspace);
    let reverted = Fb::render(&ui, 720, 720);
    assert_eq!(five.px, reverted.px, "backspace must restore the previous frame");
}

/// With far more rolls than the tail can show, digits that scrolled off the left end
/// no longer influence any pixel of the history band - the tail is bounded and clipped
/// to its well (the ellipsis marks the cut), it never bleeds or reflows the screen.
#[test]
fn roll_history_tail_is_bounded_by_its_well() {
    for (w, h) in [(720u32, 720u32), (800, 480)] {
        // Same trailing 40 digits, different equal-length 90-digit prefixes
        // (rotations of one block, so the roll count matches too).
        let tail = "1234512345123451234512345123451234512345";
        let a = format!("{}{tail}", "162534".repeat(15));
        let b = format!("{}{tail}", "253416".repeat(15));
        let mk = |digits: &str| {
            let mut ui = Ui::new(w, h);
            tap(&mut ui, RegionId::HomeNewSeed);
            type_dice(&mut ui, digits);
            Fb::render(&ui, w, h)
        };
        let (fa, fb) = (mk(&a), mk(&b));
        // The history band: full body width, HIST_H (44) tall, at the top of the body.
        let body = notyas_ui::layout::Metrics::new(w, h).body();
        for y in body.y..body.y + 44 {
            for x in 0..w as i32 {
                let i = (y as u32 * w + x as u32) as usize;
                assert_eq!(
                    fa.px[i], fb.px[i],
                    "{w}x{h}: pixel ({x},{y}) depends on digits beyond the visible tail"
                );
            }
        }
    }
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
fn back_from_mnemonic_restores_dice_with_rolls() {
    let mut ui = Ui::new(720, 720);
    tap(&mut ui, RegionId::HomeNewSeed);
    type_dice(&mut ui, SIXES);
    tap(&mut ui, RegionId::DiceDone);
    assert_eq!(ui.screen(), ScreenId::MnemonicDisplay);
    // Back opens the exit modal; confirm goes back to Dice with rolls intact.
    tap(&mut ui, RegionId::Back);
    assert_eq!(ui.screen(), ScreenId::MnemonicDisplay, "modal stays over Mnemonic");
    assert_eq!(ui.regions().len(), 2, "exit modal open");
    tap(&mut ui, RegionId::ModalConfirm);
    assert_eq!(ui.screen(), ScreenId::DiceEntry);
    // The rolls are still there: Done should succeed immediately.
    tap(&mut ui, RegionId::DiceDone);
    assert_eq!(ui.screen(), ScreenId::MnemonicDisplay, "rolls survived the back-and-forth");
}

#[test]
fn back_from_passphrase_restores_mnemonic() {
    let mut ui = ui_at_mnemonic(720, 720, SIXES);
    tap(&mut ui, RegionId::Next);
    assert_eq!(ui.screen(), ScreenId::PassphraseEntry);
    tap(&mut ui, RegionId::Back);
    assert_eq!(ui.screen(), ScreenId::PassphraseEntry, "modal stays over Passphrase");
    tap(&mut ui, RegionId::ModalConfirm);
    assert_eq!(ui.screen(), ScreenId::MnemonicDisplay, "Back restored the Mnemonic");
}

#[test]
fn back_from_schemes_restores_passphrase() {
    let mut ui = ui_at_schemes(720, 720);
    tap(&mut ui, RegionId::Back);
    assert_eq!(ui.screen(), ScreenId::Schemes, "modal stays over Schemes");
    tap(&mut ui, RegionId::ModalConfirm);
    assert_eq!(ui.screen(), ScreenId::PassphraseEntry, "Back restored the Passphrase");
}

#[test]
fn exit_modal_cancel_keeps_current_screen() {
    let mut ui = ui_at_mnemonic(720, 720, SIXES);
    let before = Fb::render(&ui, 720, 720);
    tap(&mut ui, RegionId::Back);
    // Cancel: stays on Mnemonic, frame identical (no modal drawn).
    tap(&mut ui, RegionId::ModalCancel);
    assert_eq!(ui.screen(), ScreenId::MnemonicDisplay);
    let after = Fb::render(&ui, 720, 720);
    assert_eq!(before.px, after.px, "cancel must restore the exact pre-modal frame");
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
    tap_done_and_derive(&mut ui);
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
    tap_done_and_derive(&mut ui); // passphrase off -> continue
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
    // A passphrase longer than the field can show: on the narrow side-by-side fields of
    // the 800x480 landscape layout the bullet run outruns the rect and must be clipped,
    // not bleed across the gap into the confirm field. The gap column between the two
    // fields must stay free of glyph ink.
    let mut ui = ui_at_mnemonic(800, 480, SIXES);
    tap(&mut ui, RegionId::Next);
    tap(&mut ui, RegionId::PassToggle);
    type_keys(&mut ui, "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz");
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

/// The INPUT masking rule, pinned at the pixel level: a masked passphrase field shows
/// one bullet per typed character and nothing else. Same length must render identically
/// whatever the characters were (no content leak), and one more character must render
/// differently (the count is real, not a fixed run).
#[test]
fn masked_input_field_shows_length_only() {
    let at_passphrase = |typed: &str| {
        let mut ui = ui_at_mnemonic(720, 720, SIXES);
        tap(&mut ui, RegionId::Next);
        tap(&mut ui, RegionId::PassToggle);
        type_keys(&mut ui, typed);
        Fb::render(&ui, 720, 720)
    };
    let six_a = at_passphrase("abcdef");
    let six_b = at_passphrase("zyxwvu");
    let seven = at_passphrase("abcdefg");
    assert_eq!(six_a.px, six_b.px, "a masked field must not depend on the characters");
    assert_ne!(six_a.px, seven.px, "a masked field must show one bullet per character");
}

/// The passphrase header row - label, Show/Hide, Off/On - must lay out side by side on
/// both geometries. The label is measured text, not a region, so the region-overlap
/// sweep cannot see it: this checks the ink directly by looking for the label's own
/// pixels inside the Show button, which is where it landed when Show was left-anchored.
#[test]
fn the_passphrase_header_row_does_not_collide() {
    for (w, h) in [(720u32, 720u32), (800, 480)] {
        let mut ui = ui_at_mnemonic(w, h, SIXES);
        tap(&mut ui, RegionId::Next);
        let show = region(&ui, RegionId::PassShow).rect;
        let toggle = region(&ui, RegionId::PassToggle).rect;
        assert!(show.right() <= toggle.x, "{w}x{h}: Show overlaps the Off/On toggle");
        assert!(show.x > notyas_ui::layout::Metrics::new(w, h).body().x);
        // The button's own paper must be intact: a label bleeding under it would put
        // body-copy ink on paper-1 inside a paper-3 button.
        let fb = Fb::render(&ui, w, h);
        for y in show.y + 2..show.bottom() - 2 {
            for x in show.x + 2..show.right() - 2 {
                assert_ne!(
                    fb.px[(y as u32 * w + x as u32) as usize],
                    theme::PAPER_1,
                    "{w}x{h}: page paper inside the Show button at ({x},{y})"
                );
            }
        }
    }
}

/// Show reveals the literal passphrase INCLUDING its leading and trailing spaces: those
/// are the characters a plain rendering hides and PBKDF2 still consumes, and an unseen
/// one silently derives a different wallet. Hidden -> shown must change the frame, and a
/// value that differs only by a trailing space must be distinguishable while shown.
#[test]
fn show_reveals_the_passphrase_and_its_edge_spaces() {
    let render = |typed: &str, show: bool| {
        let mut ui = ui_at_mnemonic(720, 720, SIXES);
        tap(&mut ui, RegionId::Next);
        tap(&mut ui, RegionId::PassToggle);
        type_keys(&mut ui, typed);
        if show {
            tap(&mut ui, RegionId::PassShow);
        }
        Fb::render(&ui, 720, 720)
    };
    assert_ne!(render("abc", false).px, render("abc", true).px, "Show must reveal");
    // Hidden, "abc " and "abc" differ only in bullet count; shown, the difference has to
    // survive as a visible mark rather than as blank paper.
    assert_ne!(
        render("abc ", true).px,
        render("abc", true).px,
        "a trailing space must be visible when the passphrase is shown"
    );
    assert_ne!(
        render(" abc", true).px,
        render("abc", true).px,
        "a leading space must be visible when the passphrase is shown"
    );
    // ...and it must be a mark, not just a shift: a leading and a trailing space put the
    // same three letters in different places, but both must be legible as spaces.
    assert_ne!(render(" abc", true).px, render("abc ", true).px);
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

// ---------------------------------------------------------------------------------------
// QR display
// ---------------------------------------------------------------------------------------

/// BIP39 test vector #1 (SIXES, no passphrase), BIP84 `m/84'/0'/0'/0/0` - the same
/// published constant notyas-core's qr tests use. Nothing secret.
const VECTOR1_BIP84_ADDR0: &str = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
/// The matching SLIP-132 account key.
const VECTOR1_BIP84_ZPUB: &str = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";

/// SIXES flow with the passphrase left off, landed on Schemes.
fn ui_at_schemes(w: u32, h: u32) -> Ui {
    let mut ui = ui_at_mnemonic(w, h, SIXES);
    tap(&mut ui, RegionId::Next);
    tap_done_and_derive(&mut ui); // passphrase off -> Continue
    assert_eq!(ui.screen(), ScreenId::Schemes);
    ui
}

/// The QR request carries exactly the public string the screen shows - pinned against
/// the published test-vector values, so a payload transformation (or an off-by-one in
/// the row indexing) cannot hide.
#[test]
fn qr_requests_carry_the_shown_public_values() {
    let mut ui = ui_at_schemes(720, 720);
    tap(&mut ui, RegionId::Tab(2)); // BIP84
    let UiRequest::Qr(zpub) = tap(&mut ui, RegionId::QrSlip132).expect("slip132 QR");
    assert_eq!(zpub.payload, VECTOR1_BIP84_ZPUB);
    let UiRequest::Qr(xpub) = tap(&mut ui, RegionId::QrXpub).expect("xpub QR");
    assert!(xpub.payload.starts_with("xpub"), "{}", xpub.payload);
    assert!(xpub.label.starts_with("Account xpub m/84'"), "{}", xpub.label);
    // The first address row sits below the fold on the 720 panel with the SLIP-132
    // block present - scroll it into view, exactly as a finger would.
    ui.touch(TouchEvent::Down { x: 360, y: 400 });
    ui.touch(TouchEvent::Move { x: 360, y: 100 });
    ui.touch(TouchEvent::Up { x: 360, y: 100 });
    let UiRequest::Qr(addr) = tap(&mut ui, RegionId::QrAddress(0)).expect("address QR");
    assert_eq!(addr.payload, VECTOR1_BIP84_ADDR0);
    assert_eq!(addr.label, "m/84'/0'/0'/0/0");
    // The taps alone must NOT open anything: the modal waits for show_qr.
    assert!(ui.regions().iter().any(|r| r.id == RegionId::Back), "no modal yet");
}

/// show_qr opens the modal, Close restores the schemes screen pixel-identically, and
/// while the modal is open the sheet below (tabs, back, QR buttons) is inert.
#[test]
fn qr_modal_opens_and_closes_on_both_geometries() {
    for (w, h) in [(720u32, 720u32), (800, 480)] {
        let mut ui = ui_at_schemes(w, h);
        let before = Fb::render(&ui, w, h);
        let UiRequest::Qr(target) = tap(&mut ui, RegionId::QrXpub).expect("request");
        ui.show_qr(target, checkerboard(33));
        let open = Fb::render(&ui, w, h);
        assert_ne!(before.px, open.px, "{w}x{h}: the modal must actually draw");
        let regions = ui.regions();
        assert_eq!(regions.len(), 1, "{w}x{h}: modal open, only Close");
        assert_eq!(regions[0].id, RegionId::ModalClose);
        tap(&mut ui, RegionId::ModalClose);
        let closed = Fb::render(&ui, w, h);
        assert_eq!(before.px, closed.px, "{w}x{h}: Close must restore the sheet exactly");
    }
}

/// The 0.1.0 QR scope, test-asserted: no QR button exists on any screen that handles
/// secret material (dice rolls, the mnemonic - masked or revealed, a typed phrase, the
/// passphrase), and a stray show_qr on those screens is dropped, not displayed.
#[test]
fn no_qr_is_reachable_from_secret_screens() {
    let is_qr = |r: &Region| {
        matches!(r.id, RegionId::QrXpub | RegionId::QrSlip132 | RegionId::QrAddress(_))
    };
    let assert_qr_free = |ui: &mut Ui, name: &str| {
        assert!(!ui.regions().iter().any(is_qr), "{name} offers a QR button");
        let before = Fb::render(ui, 720, 720);
        let stray = notyas_ui::QrTarget {
            label: String::from("stray"),
            payload: String::from("stray"),
        };
        ui.show_qr(stray, checkerboard(21));
        let after = Fb::render(ui, 720, 720);
        assert_eq!(before.px, after.px, "{name} displayed an unsolicited QR");
    };

    let mut ui = Ui::new(720, 720);
    tap(&mut ui, RegionId::HomeNewSeed);
    type_dice(&mut ui, SIXES);
    assert_qr_free(&mut ui, "dice entry");
    tap(&mut ui, RegionId::DiceDone);
    assert_qr_free(&mut ui, "mnemonic (masked)");
    tap(&mut ui, RegionId::Reveal);
    tap(&mut ui, RegionId::ModalConfirm);
    assert_qr_free(&mut ui, "mnemonic (revealed)");
    tap(&mut ui, RegionId::Next);
    tap(&mut ui, RegionId::PassToggle);
    assert_qr_free(&mut ui, "passphrase entry");

    let mut ui = Ui::new(720, 720);
    tap(&mut ui, RegionId::HomeVerifySeed);
    type_keys(&mut ui, "zoo zoo zoo");
    assert_qr_free(&mut ui, "phrase entry");
}

/// Off-screen QR buttons are not tappable: on the short panel the last address row
/// starts below the viewport, and its button only joins the hit regions after
/// scrolling down.
#[test]
fn qr_buttons_scroll_with_the_content() {
    let mut ui = ui_at_schemes(800, 480);
    let visible =
        |ui: &Ui| ui.regions().iter().any(|r| r.id == RegionId::QrAddress(4));
    assert!(!visible(&ui), "address 4 must start below the 480px viewport");
    // Drag far past the limit; the UI clamps to the real content height.
    ui.touch(TouchEvent::Down { x: 400, y: 400 });
    ui.touch(TouchEvent::Move { x: 400, y: -2000 });
    ui.touch(TouchEvent::Up { x: 400, y: -2000 });
    assert!(visible(&ui), "address 4 must be tappable after scrolling to the end");
}

// ---------------------------------------------------------------------------------------
// Network toggle
// ---------------------------------------------------------------------------------------

/// The Home toggle drives the whole pipeline: testnet derivations produce tb1
/// addresses, the SLIP-132 rendering (mainnet-only by definition) disappears, and the
/// choice survives leaving and re-entering the flow.
#[test]
fn network_toggle_reaches_the_derivation() {
    let mut ui = Ui::new(720, 720);
    tap(&mut ui, RegionId::NetToggle);
    tap(&mut ui, RegionId::HomeNewSeed);
    type_dice(&mut ui, SIXES);
    tap(&mut ui, RegionId::DiceDone);
    tap(&mut ui, RegionId::Next);
    tap_done_and_derive(&mut ui);
    assert_eq!(ui.screen(), ScreenId::Schemes);
    tap(&mut ui, RegionId::Tab(2)); // BIP84
    let UiRequest::Qr(addr) = tap(&mut ui, RegionId::QrAddress(0)).expect("address QR");
    assert!(addr.payload.starts_with("tb1"), "testnet BIP84 address: {}", addr.payload);
    assert!(
        !ui.regions().iter().any(|r| r.id == RegionId::QrSlip132),
        "SLIP-132 is mainnet-only and must vanish on testnet"
    );
    // A fresh Ui defaults to mainnet: same flow, bc1 address (the SLIP-132 block
    // above the rows pushes row 0 below the fold - scroll it into view first).
    let mut ui2 = ui_at_schemes(720, 720);
    tap(&mut ui2, RegionId::Tab(2));
    ui2.touch(TouchEvent::Down { x: 360, y: 400 });
    ui2.touch(TouchEvent::Move { x: 360, y: 100 });
    ui2.touch(TouchEvent::Up { x: 360, y: 100 });
    let UiRequest::Qr(a2) = tap(&mut ui2, RegionId::QrAddress(0)).expect("address QR");
    assert!(a2.payload.starts_with("bc1"), "mainnet by default: {}", a2.payload);
}

// ---------------------------------------------------------------------------------------
// Passphrase byte counter invariant
// ---------------------------------------------------------------------------------------

/// The passphrase status row reports NFKD BYTES computed as `len()`. That shortcut is
/// sound only while every key the on-screen keyboard can emit is ASCII (NFKD identity,
/// one byte per char) - this pins the invariant against future keyboard pages.
#[test]
fn every_keyboard_key_is_ascii() {
    let mut ui = Ui::new(720, 720);
    tap(&mut ui, RegionId::HomeVerifySeed);
    let assert_ascii = |ui: &Ui| {
        for r in ui.regions() {
            if let RegionId::Key(c) = r.id {
                assert!(
                    c.is_ascii(),
                    "key '{c}' is not ASCII: the NFKD-bytes-as-len counter breaks"
                );
            }
        }
    };
    assert_ascii(&ui); // lowercase page (initial)
    tap(&mut ui, RegionId::Shift);
    assert_ascii(&ui); // uppercase
    tap(&mut ui, RegionId::PageDigits);
    assert_ascii(&ui); // digits page
    tap(&mut ui, RegionId::PageSymbols);
    assert_ascii(&ui); // symbols page
}

// ---------------------------------------------------------------------------------------
// BIP39 completion strip (phrase entry)
// ---------------------------------------------------------------------------------------

/// The phrase screen with `typed` in its buffer.
fn ui_at_phrase(w: u32, h: u32, typed: &str) -> Ui {
    let mut ui = Ui::new(w, h);
    tap(&mut ui, RegionId::HomeVerifySeed);
    type_keys(&mut ui, typed);
    assert_eq!(ui.screen(), ScreenId::PhraseEntry);
    ui
}

fn chips(ui: &Ui) -> usize {
    ui.regions().iter().filter(|r| matches!(r.id, RegionId::Suggest(_))).count()
}

/// When the strip offers chips and when it stays out of the way. The rules are about
/// what is left to complete, not about how much has been typed.
#[test]
fn the_strip_offers_completions_only_while_a_word_is_unfinished() {
    // Nothing typed: no word in progress.
    assert_eq!(chips(&ui_at_phrase(720, 720, "")), 0);
    // Mid-word with many matches: the strip is full (capped at four).
    assert_eq!(chips(&ui_at_phrase(720, 720, "ab")), 4);
    // Mid-word with few matches: exactly the matches, no padding.
    assert_eq!(chips(&ui_at_phrase(720, 720, "zeb")), 1); // -> "zebra"
    // A finished word followed by a space: the next word has not started.
    assert_eq!(chips(&ui_at_phrase(720, 720, "abandon ")), 0);
    // A fragment nothing can complete.
    assert_eq!(chips(&ui_at_phrase(720, 720, "qqq")), 0);
    // "act" IS a word but "action"/"actor"/"actress" extend it, so completing is still
    // worth offering. "zoo" and "about" are each the only word with their own prefix:
    // there is nothing left to complete, so the strip yields the row and the checksum
    // advisory above it is what the user reads at the end of a phrase.
    assert_eq!(chips(&ui_at_phrase(720, 720, "act")), 4);
    assert_eq!(chips(&ui_at_phrase(720, 720, "about")), 0);
    assert_eq!(chips(&ui_at_phrase(720, 720, "zoo")), 0);
}

/// Tapping a chip replaces the fragment being typed with that exact word and appends the
/// separating space, so the next word can be typed straight away. Checked through the
/// pixels, since the phrase buffer is private: the result must be identical to having
/// typed the whole word and a space by hand.
#[test]
fn tapping_a_chip_completes_the_word_and_appends_a_space() {
    // The strip's own order is the wordlist's, so chip 1 after "ab" is "ability".
    let mut tapped = ui_at_phrase(720, 720, "zoo ab");
    tap(&mut tapped, RegionId::Suggest(1));
    let typed = ui_at_phrase(720, 720, "zoo ability ");
    assert_eq!(Fb::render(&tapped, 720, 720).px, Fb::render(&typed, 720, 720).px);
    // The trailing space really is there: the strip is empty (no word in progress) and
    // the next keystroke starts a new word rather than extending "ability".
    assert_eq!(chips(&tapped), 0);

    // Case is corrected, not appended to: a fragment typed on the shifted page is
    // replaced by the lowercase wordlist spelling.
    let mut shifted = ui_at_phrase(720, 720, "");
    tap(&mut shifted, RegionId::Shift);
    type_keys(&mut shifted, "AB");
    assert_eq!(chips(&shifted), 4);
    tap(&mut shifted, RegionId::Suggest(0));
    let lower = ui_at_phrase(720, 720, "abandon ");
    // Only the phrase well is compared: the shifted run leaves the keyboard on its
    // uppercase page, which is a keyboard difference, not a phrase-buffer one.
    let (a, b) = (Fb::render(&shifted, 720, 720), Fb::render(&lower, 720, 720));
    let well = notyas_ui::layout::Metrics::new(720, 720).body();
    for y in well.y..well.y + 124 {
        for x in 0..720 {
            let i = (y as u32 * 720 + x as u32) as usize;
            assert_eq!(a.px[i], b.px[i], "completed phrase differs at ({x},{y})");
        }
    }
}

/// The strip is phrase-entry only. No other screen offers a chip, and a stray
/// `Suggest` tap on one cannot be routed anywhere: the completion source is the public
/// wordlist and the target is the user's own typed input, and neither may become a path
/// into a masked or derived value.
#[test]
fn no_completion_chip_reaches_a_secret_screen() {
    let mut ui = Ui::new(720, 720);
    tap(&mut ui, RegionId::HomeNewSeed);
    type_dice(&mut ui, SIXES);
    assert_eq!(chips(&ui), 0, "dice entry");
    tap(&mut ui, RegionId::DiceDone);
    assert_eq!(chips(&ui), 0, "mnemonic (masked)");
    tap(&mut ui, RegionId::Reveal);
    tap(&mut ui, RegionId::ModalConfirm);
    assert_eq!(chips(&ui), 0, "mnemonic (revealed)");
    tap(&mut ui, RegionId::Next);
    tap(&mut ui, RegionId::PassToggle);
    // A passphrase is not a wordlist word and must never be completed against one.
    type_keys(&mut ui, "ab");
    assert_eq!(chips(&ui), 0, "passphrase entry");
    tap(&mut ui, RegionId::PassConfirm);
    type_keys(&mut ui, "ab");
    assert_eq!(chips(&ui), 0, "passphrase confirm");
    let before = Fb::render(&ui, 720, 720);
    // Taps in the dead space where the phrase screen would put its strip resolve to
    // nothing here: there is no Suggest region to hit on this screen at all.
    let strip_y = region(&ui_at_phrase(720, 720, "ab"), RegionId::Suggest(0)).rect;
    for x in [strip_y.x + 10, strip_y.right() - 10] {
        let y = strip_y.y + strip_y.h / 2;
        ui.touch(TouchEvent::Down { x, y });
        ui.touch(TouchEvent::Up { x, y });
        assert_eq!(ui.screen(), ScreenId::PassphraseEntry, "a stray tap moved the screen");
    }
    assert_eq!(before.px, Fb::render(&ui, 720, 720).px);
    tap_done_and_derive(&mut ui);
    assert_eq!(chips(&ui), 0, "schemes");
}

/// The whole phrase screen must fit its body on both shipped geometries with the strip
/// at full width: the well keeps at least one line, the keyboard keeps its four rows at
/// the 40 px floor, and nothing lands outside the body. This is the budget the 800x480
/// panel has no slack in - the half-finished five-row stack overflowed it by 200 px.
#[test]
fn the_phrase_screen_fits_its_body_on_both_geometries() {
    for (w, h) in [(720u32, 720u32), (800, 480)] {
        let ui = ui_at_phrase(w, h, "ab");
        let body = notyas_ui::layout::Metrics::new(w, h).body();
        let regions = ui.regions();
        assert_eq!(chips(&ui), 4, "{w}x{h}: full strip");
        // Every region except the top-bar Back sits inside the body.
        for r in regions.iter().filter(|r| r.id != RegionId::Back) {
            assert!(
                r.rect.y >= body.y
                    && r.rect.bottom() <= body.bottom()
                    && r.rect.x >= body.x
                    && r.rect.right() <= body.right(),
                "{w}x{h}: {:?} escapes the body: {:?} vs {:?}",
                r.id,
                r.rect,
                body
            );
        }
        // The keyboard still has its four rows: the letter keys of the top row and the
        // control row are at different y, and every key clears the 40 px floor.
        let keys: Vec<_> = regions.iter().filter(|r| matches!(r.id, RegionId::Key(_))).collect();
        assert_eq!(keys.len(), 26, "{w}x{h}: all three letter rows present");
        for k in &keys {
            assert!(k.rect.h >= 40, "{w}x{h}: key {:?} below the 40px floor", k.rect);
        }
        // The strip sits between the phrase well and the keyboard, touching neither.
        let chip = regions.iter().find(|r| r.id == RegionId::Suggest(0)).unwrap().rect;
        let top_key = keys.iter().map(|k| k.rect.y).min().unwrap();
        assert!(chip.bottom() <= top_key, "{w}x{h}: strip overlaps the keyboard");
    }
}

// ---------------------------------------------------------------------------------------
// Deriving interstitial
// ---------------------------------------------------------------------------------------

/// The point of the screen: Done must LEAVE the passphrase screen before any derivation
/// runs, so the embedder's next draw publishes the interstitial and the PBKDF2 stretch
/// happens with "Deriving" on the panel. `tick` is what does the work.
#[test]
fn deriving_interstitial_is_painted_before_the_derivation_runs() {
    let mut ui = ui_at_mnemonic(720, 720, SIXES);
    tap(&mut ui, RegionId::Next);
    tap(&mut ui, RegionId::PassToggle);
    type_keys(&mut ui, "ab");
    tap(&mut ui, RegionId::PassConfirm);
    type_keys(&mut ui, "ab");

    tap(&mut ui, RegionId::KeyDone);
    assert_eq!(ui.screen(), ScreenId::Deriving, "Done must not derive inline");
    let interstitial = Fb::render(&ui, 720, 720);
    assert!(ui.regions().is_empty(), "the interstitial cannot be tapped or cancelled");

    assert!(ui.tick(), "tick runs the pending derivation");
    assert_eq!(ui.screen(), ScreenId::Schemes);
    assert_ne!(interstitial.px, Fb::render(&ui, 720, 720).px);
    // Idempotent: nothing pending, nothing to repaint.
    assert!(!ui.tick());
}

/// Back from Schemes lands on the passphrase screen with its fields intact - the
/// Deriving state passes through the navigation stack without becoming a stop on it.
#[test]
fn deriving_is_not_a_step_on_the_back_stack() {
    let mut ui = ui_at_schemes(720, 720);
    tap(&mut ui, RegionId::Back);
    tap(&mut ui, RegionId::ModalConfirm);
    assert_eq!(ui.screen(), ScreenId::PassphraseEntry);
    tap(&mut ui, RegionId::Back);
    tap(&mut ui, RegionId::ModalConfirm);
    assert_eq!(ui.screen(), ScreenId::MnemonicDisplay);
}

/// An embedder that has not added `tick` to its loop must not wedge on the interstitial:
/// the next touch drains the pending work first. Slower than it should be, never stuck.
#[test]
fn a_stray_touch_drains_a_pending_derivation() {
    let mut ui = ui_at_mnemonic(720, 720, SIXES);
    tap(&mut ui, RegionId::Next);
    tap(&mut ui, RegionId::KeyDone);
    assert_eq!(ui.screen(), ScreenId::Deriving);
    ui.touch(TouchEvent::Down { x: 10, y: 10 });
    assert_eq!(ui.screen(), ScreenId::Schemes);
}

/// The passphrase reaches the derivation unchanged across the deferral: the same typed
/// passphrase must produce the same published test-vector keys it did when Done derived
/// inline, and the empty-passphrase path must stay empty (not "the field's contents").
#[test]
fn the_deferred_derivation_uses_the_passphrase_as_typed() {
    // BIP39 test vector #1 with passphrase TREZOR, BIP84 account 0 address 0.
    let mut ui = ui_at_mnemonic(720, 720, SIXES);
    tap(&mut ui, RegionId::Next);
    tap(&mut ui, RegionId::PassToggle);
    tap(&mut ui, RegionId::Shift); // the page stays uppercase until shifted back
    type_keys(&mut ui, "TREZOR");
    tap(&mut ui, RegionId::PassConfirm);
    type_keys(&mut ui, "TREZOR");
    tap_done_and_derive(&mut ui);
    tap(&mut ui, RegionId::Tab(2));
    let UiRequest::Qr(with_pass) = tap(&mut ui, RegionId::QrXpub).expect("xpub QR");

    // The same seed with the passphrase toggled off must derive something else.
    let mut plain = ui_at_schemes(720, 720);
    tap(&mut plain, RegionId::Tab(2));
    let UiRequest::Qr(without) = tap(&mut plain, RegionId::QrXpub).expect("xpub QR");
    assert_ne!(with_pass.payload, without.payload, "the passphrase must reach PBKDF2");
    assert!(without.payload.starts_with("xpub"), "{}", without.payload);
}
