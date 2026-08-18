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
    tap(&mut ui, RegionId::PassConfirm);
    type_keys(&mut ui, "ab");
    tap(&mut ui, RegionId::KeyDone);
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
    tap(&mut ui, RegionId::KeyDone); // passphrase off -> Continue
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
    tap(&mut ui, RegionId::KeyDone);
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
