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

use notyas_ui::{
    theme, BackupState, LockInfo, PinShape, QrData, Region, RegionId, ScreenId, StoreStatus,
    TouchEvent, Network, Ui, UiRequest, UnsealOutcome, VerifyInfo, WalletInfo, WalletKind,
    WalletRow, UNLOCK_MS_M1, WALLET_SLOTS, WIPE_AFTER_MAX, WIPE_AFTER_MIN,
};

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
        // The pixel count is checked rather than cast. Every caller passes
        // literals today, so this cannot fire - but `(w * h) as usize` is a
        // silent u32 wrap, and a wrapped length reaches vec![] as a request for
        // an astronomical allocation that takes the host down rather than the
        // test. The bound is one panel's worth of pixels with room to spare; a
        // geometry above it is a bug in the test, not a panel worth supporting.
        const MAX_PX: usize = 4 << 20;
        let n = (w as usize)
            .checked_mul(h as usize)
            .filter(|&n| n <= MAX_PX)
            .expect("test framebuffer larger than any supported panel");
        Fb { w, h, px: vec![Rgb565::new(0, 0, 0); n] }
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
    assert!(ui.tick(0).dirty, "tick must consume the pending derivation");
}

/// Answer the mandatory backup check (S-17), whatever the mnemonic behind it is.
///
/// The candidates are on the screen and this driver does not know which is correct - the
/// same position a user who did not write the words down is in - so it tries them. A wrong
/// answer re-poses the SAME word with a fresh candidate set, which is the S-17 rule and
/// the reason this reads the current view again after every tap rather than making one
/// pass over a fixed list.
fn answer_quiz(ui: &mut Ui) {
    let mut taps = 0;
    while let Some(view) = ui.quiz() {
        for i in 0..view.choices.len() as u8 {
            tap(ui, RegionId::QuizChoice(i));
            taps += 1;
            assert!(taps < 2000, "the backup check never advanced past word {}", view.word);
            match ui.quiz() {
                Some(v) if v.done > view.done => break,
                None => break,
                _ => {}
            }
        }
    }
}

/// The create path from the passphrase screen to a session wallet: derive, pass the
/// backup check, then take the stateless leg of the fork. Lands on the wallet home.
fn keep_nothing(ui: &mut Ui) {
    tap_done_and_derive(ui);
    assert_eq!(ui.screen(), ScreenId::BackupCheck, "the create path is gated on the quiz");
    answer_quiz(ui);
    assert_eq!(ui.screen(), ScreenId::KeepOrSave);
    tap(ui, RegionId::UseOnce);
    assert_eq!(ui.screen(), ScreenId::WalletHome);
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

/// BIP39 test vector #1 as a typed phrase: the world's best-known mnemonic, useless as a
/// wallet and accepted by the word-entry screen's checksum rule, which is what a restore
/// flow driven through the public API now has to satisfy.
const VECTOR1_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon \
                              abandon abandon abandon abandon about";

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
    assert!(ui.tick(0).dirty);
    // m4b: the create path is gated on the backup check, and the fork is the only way
    // out of it. Both lay out and paint at this geometry before anything else does.
    assert_eq!(ui.screen(), ScreenId::BackupCheck);
    check(&ui);
    answer_quiz(&mut ui);
    assert_eq!(ui.screen(), ScreenId::KeepOrSave);
    check(&ui);
    tap(&mut ui, RegionId::UseOnce);
    assert_eq!(ui.screen(), ScreenId::WalletHome);
    check(&ui);
    tap(&mut ui, RegionId::ActExport);
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
    let UiRequest::Qr(target) = req else { panic!("QR tap must raise a QR request") };
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
    assert_eq!(ui.screen(), ScreenId::BackupCheck);
}

/// The restore path reaches the fork WITHOUT the quiz, and that is the one place the two
/// entry paths differ (S-16 two exits): the words were just read off a backup and typed
/// in, which is the same evidence a dry-run re-check accepts, so quizzing the user on them
/// thirty seconds later proves nothing it has not already proved. Both paths still reach
/// the fork, so neither can store a wallet whose backup was never demonstrated.
#[test]
fn phrase_entry_requires_words_and_reaches_the_fork_without_a_quiz() {
    let mut ui = Ui::new(720, 720);
    tap(&mut ui, RegionId::HomeVerifySeed);
    tap(&mut ui, RegionId::KeyDone); // nothing typed
    assert_eq!(ui.screen(), ScreenId::PhraseEntry);
    type_keys(&mut ui, VECTOR1_PHRASE);
    tap(&mut ui, RegionId::KeyDone);
    assert_eq!(ui.screen(), ScreenId::PassphraseEntry);
    tap_done_and_derive(&mut ui); // passphrase off -> continue
    assert_eq!(ui.screen(), ScreenId::KeepOrSave, "typed words are their own backup check");
    tap(&mut ui, RegionId::UseOnce);
    tap(&mut ui, RegionId::ActExport);
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
///
/// Schemes is now the EXPORT view of a wallet rather than the end of the create flow, so
/// the route to it runs through the whole of m4b: the backup check, the save-or-keep-
/// nothing fork, and the wallet home. Every QR and back-stack test below therefore drives
/// the m4b flow whether or not it is about it.
fn ui_at_schemes(w: u32, h: u32) -> Ui {
    let mut ui = ui_at_mnemonic(w, h, SIXES);
    tap(&mut ui, RegionId::Next);
    keep_nothing(&mut ui); // passphrase off -> Continue -> quiz -> fork -> wallet home
    tap(&mut ui, RegionId::ActExport);
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
    let Some(UiRequest::Qr(zpub)) = tap(&mut ui, RegionId::QrSlip132) else { panic!("slip132 QR") };
    assert_eq!(zpub.payload, VECTOR1_BIP84_ZPUB);
    let Some(UiRequest::Qr(xpub)) = tap(&mut ui, RegionId::QrXpub) else { panic!("xpub QR") };
    assert!(xpub.payload.starts_with("xpub"), "{}", xpub.payload);
    assert!(xpub.label.starts_with("Account xpub m/84'"), "{}", xpub.label);
    // The first address row sits below the fold on the 720 panel with the SLIP-132
    // block present - scroll it into view, exactly as a finger would.
    ui.touch(TouchEvent::Down { x: 360, y: 400 });
    ui.touch(TouchEvent::Move { x: 360, y: 100 });
    ui.touch(TouchEvent::Up { x: 360, y: 100 });
    let Some(UiRequest::Qr(addr)) = tap(&mut ui, RegionId::QrAddress(0)) else { panic!("address QR") };
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
        let Some(UiRequest::Qr(target)) = tap(&mut ui, RegionId::QrXpub) else { panic!("request") };
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
    keep_nothing(&mut ui);
    tap(&mut ui, RegionId::ActExport);
    assert_eq!(ui.screen(), ScreenId::Schemes);
    tap(&mut ui, RegionId::Tab(2)); // BIP84
    let Some(UiRequest::Qr(addr)) = tap(&mut ui, RegionId::QrAddress(0)) else { panic!("address QR") };
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
    let Some(UiRequest::Qr(a2)) = tap(&mut ui2, RegionId::QrAddress(0)) else { panic!("address QR") };
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

    assert!(ui.tick(0).dirty, "tick runs the pending derivation");
    assert_eq!(ui.screen(), ScreenId::BackupCheck);
    assert_ne!(interstitial.px, Fb::render(&ui, 720, 720).px);
    // Idempotent: nothing pending, nothing to repaint.
    assert!(!ui.tick(0).dirty);
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
    assert_eq!(ui.screen(), ScreenId::BackupCheck);
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
    keep_nothing(&mut ui);
    tap(&mut ui, RegionId::ActExport);
    tap(&mut ui, RegionId::Tab(2));
    let Some(UiRequest::Qr(with_pass)) = tap(&mut ui, RegionId::QrXpub) else { panic!("xpub QR") };

    // The same seed with the passphrase toggled off must derive something else.
    let mut plain = ui_at_schemes(720, 720);
    tap(&mut plain, RegionId::Tab(2));
    let Some(UiRequest::Qr(without)) = tap(&mut plain, RegionId::QrXpub) else { panic!("xpub QR") };
    assert_ne!(with_pass.payload, without.payload, "the passphrase must reach PBKDF2");
    assert!(without.payload.starts_with("xpub"), "{}", without.payload);
}

// ---------------------------------------------------------------------------------------
// 0.2.0 m4a: the lock screen, PIN entry, the boot counter and the touch fixes
// ---------------------------------------------------------------------------------------

/// A device with a PIN set, locked, with the store values the embedder would have read.
fn locked(w: u32, h: u32) -> Ui {
    let mut ui = Ui::new(w, h);
    ui.set_lock_info(LockInfo {
        status: StoreStatus::Locked,
        nickname: String::from("kitchen-desk"),
        lock_word: String::from("anvil"),
        attempts_left: Some(9),
        wipe_after: Some(15),
        ..LockInfo::default()
    });
    assert!(ui.lock(), "a device with a PIN can show its lock screen");
    ui
}

/// The same device, formatted at a stated PIN floor.
///
/// The floor is written into the store's format header, so a test that means "this
/// device's floor" has to state it as a device fact. Named here rather than folded into
/// [`locked`] because most of the suite does not care which floor is in force, and the
/// tests that do should be the ones that say so.
fn locked_at_floor(w: u32, h: u32, min_pin_len: u8) -> Ui {
    let mut ui = locked(w, h);
    ui.set_lock_info(LockInfo { min_pin_len, ..ui.lock_info().clone() });
    ui
}

/// The pad every notyas prints, slot -> digit: fixed phone order since the owner
/// reversed Q35 on 2026-08-19. Stated once here because the crate's own copy is
/// `pub(crate)`, and a second literal per test is a second thing to get wrong.
const PAD: [u8; 10] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0];

/// Type `pin` by finding the POSITION that carries each digit, which is what a finger
/// does. Going through the position rather than tapping `PinKey(digit)` is what makes
/// these tests statements about the pad the user sees rather than about the region ids.
fn type_pin(ui: &mut Ui, pin: &str) {
    for c in pin.chars() {
        let d = c as u8 - b'0';
        let i = PAD.iter().position(|&p| p == d).expect("every digit is on the pad");
        tap(ui, RegionId::PinKey(i as u8));
    }
}

/// R20, and it is structural rather than editorial: the anti-phishing words are derived
/// from the eFuse key, so on a device with no key and no format they do not exist. The
/// screens that would show them cannot be reached at all.
#[test]
fn no_screen_can_imply_device_words_before_provisioning() {
    for status in [StoreStatus::NotProvisioned, StoreStatus::Blank, StoreStatus::Unreadable] {
        let mut ui = Ui::new(720, 720);
        ui.set_lock_info(LockInfo { status, ..LockInfo::default() });
        assert!(!ui.lock(), "{status:?} must not reach the lock screen");
        assert_eq!(ui.screen(), ScreenId::Home);
        assert!(
            !ui.regions().iter().any(|r| matches!(
                r.id,
                RegionId::PinShowWords | RegionId::LockWake | RegionId::PinKey(_)
            )),
            "{status:?} offers a PIN or lock affordance"
        );
    }
    // And with a PIN set it IS reachable, so the test above is proving a refusal rather
    // than a screen that never works.
    assert_eq!(locked(720, 720).screen(), ScreenId::Lock);
}

/// The lock screen wakes into PIN entry, and needs nothing from the embedder to draw it.
///
/// It used to ask for a freshly shuffled pad here. Since the pad is fixed the screen is
/// complete the moment it is entered, and the assertion is now that NO request is raised:
/// a panel that needed an answer to be right would be a panel that is wrong until one
/// arrives, and the fixed pad is what removes that window.
#[test]
fn the_lock_screen_wakes_into_pin_entry_and_asks_for_nothing() {
    let mut ui = locked(720, 720);
    let req = tap(&mut ui, RegionId::LockWake);
    assert_eq!(req, None);
    assert_eq!(ui.screen(), ScreenId::PinEntry);
    // Back returns to the lock screen and no further: it is the floor of a locked device.
    tap(&mut ui, RegionId::Back);
    assert_eq!(ui.screen(), ScreenId::Lock);
    // And the lock screen offers no Back at all: there is nothing behind it, and a
    // drawn button that leads nowhere is a button that lies.
    assert!(!ui.regions().iter().any(|r| r.id == RegionId::Back));
}

/// Verify device is reachable BEFORE the PIN (commandment 4): a user who suspects a
/// swapped device must be able to read the firmware hash without typing a digit into it.
#[test]
fn verify_device_is_reachable_from_the_lock_screen() {
    let mut ui = locked(720, 720);
    tap(&mut ui, RegionId::HomeVerifyDevice);
    assert_eq!(ui.screen(), ScreenId::VerifyDevice);
    tap(&mut ui, RegionId::Back);
    assert_eq!(ui.screen(), ScreenId::Lock);
}

/// Every position types the digit printed on it, and the order is phone order.
///
/// This replaces the pair of tests that stood here while the pad was installed by the
/// embedder - one that a permutation was typed as printed, one that a non-permutation was
/// refused. Both were statements about a setter, and the setter is gone: the pad is a
/// crate constant with no way in, so "the embedder cannot corrupt it" is no longer a
/// runtime property to assert but a shape the type system holds. What survives - and what
/// a user would notice - is which digit each cell yields, walked here over all ten cells
/// before the same route the real unlock takes.
#[test]
fn every_pad_position_types_the_digit_printed_on_it() {
    let mut ui = locked(720, 720);
    tap(&mut ui, RegionId::LockWake);
    for i in 0..10u8 {
        tap(&mut ui, RegionId::PinKey(i));
    }
    let Some(UiRequest::UnsealWallet(pin)) = tap(&mut ui, RegionId::PinSubmit) else {
        panic!("Unlock must hand the PIN to the embedder");
    };
    assert_eq!(pin.as_str(), "1234567890", "the pad is not phone order");

    // And the same order reached from the other side: type a PIN by hunting for each
    // digit, which is what a finger does, and get that PIN back out.
    let mut ui = locked(720, 720);
    tap(&mut ui, RegionId::LockWake);
    type_pin(&mut ui, "135790");
    let Some(UiRequest::UnsealWallet(pin)) = tap(&mut ui, RegionId::PinSubmit) else {
        panic!("submit");
    };
    assert_eq!(pin.as_str(), "135790");
}

/// Unlock is inert one character below the floor and submits at it - at whatever floor
/// the DEVICE was formatted with, which is the half of this property the suite was
/// missing. It was written against a literal 6, so it agreed with the screen's own
/// literal and neither of them agreed with the store.
#[test]
fn unlock_is_inert_below_the_devices_pin_floor() {
    // The ratified floor, the 6 S-04 used to hardcode, and a longer policy: the button
    // has to track the store in both directions, not only the one that shipped.
    for floor in [4u8, 6, 8] {
        for (w, h) in [(720u32, 720u32), (800, 480)] {
            let all: String = (0..floor).map(|i| char::from(b'0' + i % 10)).collect();
            let (short, last) = all.split_at(all.len() - 1);
            let mut ui = locked_at_floor(w, h, floor);
            tap(&mut ui, RegionId::LockWake);
            type_pin(&mut ui, short);
            assert_eq!(
                tap(&mut ui, RegionId::PinSubmit),
                None,
                "{w}x{h}: {} characters is below a floor of {floor}",
                short.len()
            );
            type_pin(&mut ui, last);
            assert!(
                matches!(tap(&mut ui, RegionId::PinSubmit), Some(UiRequest::UnsealWallet(_))),
                "{w}x{h}: a {floor}-character PIN is not submittable at a floor of {floor}"
            );
        }
    }
}

/// The reason under the disabled button names the DEVICE's floor, not a frozen number.
///
/// Asserted at the pixel level rather than against a string, because the failure that
/// matters is a sentence that contradicts the button beside it: a user told "at least 6"
/// by a device that unlocks at 4 stops believing the screen, and one told "at least 4" by
/// a device that refuses at 4 has no way to find out what it wants.
#[test]
fn the_disabled_reason_states_the_devices_own_floor() {
    for (w, h) in [(720u32, 720u32), (800, 480)] {
        let frame = |floor: u8| {
            let mut ui = locked_at_floor(w, h, floor);
            tap(&mut ui, RegionId::LockWake);
            // Below both floors, so the only thing that can differ is the sentence.
            type_pin(&mut ui, "12");
            Fb::render(&ui, w, h).px
        };
        assert_ne!(frame(4), frame(6), "{w}x{h}: the reason ignored the device's floor");
    }
}

/// The blocking defect 0.2.0 took to hardware: a device formatted at its own PIN floor
/// could not be unlocked through the panel at all.
///
/// The floor belongs to the STORE - `Policy::min_pin_len`, written at format time, 4 by
/// `WalletConfig`'s default and ratified for every state by PIN-MODES on 2026-08-17 - and
/// S-04 gated Unlock on a literal 6 of its own. An owner who set the 4-digit PIN the
/// device accepted could then type the whole of it and watch the button stay dead: the
/// anti-phishing words arrive at exactly that length (`PIN_WORDS_AT` is 4), so the one
/// affordance that DID respond confirmed the prefix and the one below it still refused.
/// The serial console was the only remaining way in, and it does not ship.
///
/// Both halves of "clickable" are asserted, because the defect had both: the button is
/// painted with the enabled fill, and the tap it accepts hands the PIN over.
#[test]
fn a_pin_at_the_devices_own_floor_unlocks_through_the_panel() {
    for (w, h) in [(720u32, 720u32), (800, 480)] {
        let mut ui = locked(w, h);
        tap(&mut ui, RegionId::LockWake);
        type_pin(&mut ui, "1234");
        let submit = region(&ui, RegionId::PinSubmit).rect;
        assert_eq!(
            Fb::render(&ui, w, h).px[(submit.y as u32 * w + submit.x as u32) as usize + 2],
            theme::ACCENT,
            "{w}x{h}: Unlock is still painted disabled at the device's own floor"
        );
        assert!(
            matches!(tap(&mut ui, RegionId::PinSubmit), Some(UiRequest::UnsealWallet(_))),
            "{w}x{h}: a PIN at the device's own floor cannot be submitted"
        );
    }
}

/// The words need a prefix and cost no attempt; the device answers for ANY prefix,
/// because refusing an unreal one would make the words an oracle for prefix correctness.
#[test]
fn the_device_words_need_a_prefix_and_answer_for_any_of_them() {
    let mut ui = locked(720, 720);
    tap(&mut ui, RegionId::LockWake);
    type_pin(&mut ui, "123");
    assert_eq!(tap(&mut ui, RegionId::PinShowWords), None, "three digits is not a prefix yet");
    type_pin(&mut ui, "4");
    let Some(UiRequest::DeviceWords(prefix)) = tap(&mut ui, RegionId::PinShowWords) else {
        panic!("four digits must raise the request");
    };
    assert_eq!(prefix.as_str(), "1234");
    // The request alone shows nothing: the words appear only when the embedder answers.
    let before = Fb::render(&ui, 720, 720);
    ui.show_device_words([String::from("anvil"), String::from("mercury")]);
    assert_ne!(before.px, Fb::render(&ui, 720, 720).px, "the answer must draw");
}

/// A wrong PIN wipes the entry, drops the words with it, and updates the counter the
/// screen shows - all three, because a screen that kept any of them would mislead.
///
/// It used to reshuffle the pad as a fourth thing, and the assertion here is now that it
/// asks for NOTHING: the pad is fixed (Q35, reversed 2026-08-19), so a new attempt needs
/// no answer from the embedder before the user can start typing into it.
#[test]
fn a_wrong_pin_clears_the_entry_and_updates_the_counter() {
    let mut ui = locked(720, 720);
    tap(&mut ui, RegionId::LockWake);
    type_pin(&mut ui, "123456");
    ui.show_device_words([String::from("anvil"), String::from("mercury")]);
    let typed = Fb::render(&ui, 720, 720);
    assert_eq!(
        ui.unseal_result(UnsealOutcome::WrongPin { attempts_left: Some(8) }),
        None,
        "a new attempt needs nothing from the embedder"
    );
    assert_eq!(ui.lock_info().attempts_left, Some(8));
    assert_ne!(typed.px, Fb::render(&ui, 720, 720).px);
    // Nothing was kept: the next submit is refused for length, so the buffer is empty.
    assert_eq!(tap(&mut ui, RegionId::PinSubmit), None);
}

/// The right PIN opens the device, and the Lock affordance exists exactly while a
/// session does.
#[test]
fn unlocking_opens_the_device_and_locking_closes_it() {
    let mut ui = locked(720, 720);
    tap(&mut ui, RegionId::LockWake);
    assert!(!ui.regions().iter().any(|r| r.id == RegionId::Lock));
    ui.unseal_result(UnsealOutcome::Unsealed);
    assert_eq!(ui.screen(), ScreenId::WalletList, "an unlock lands on the wallet list");
    assert_eq!(ui.lock_info().status, StoreStatus::Unlocked);
    assert_eq!(tap(&mut ui, RegionId::Lock), Some(UiRequest::LockSession));
    // The embedder drops the session and tells the UI, which is what returns the panel.
    assert!(ui.lock());
    assert_eq!(ui.screen(), ScreenId::Lock);
    assert_eq!(ui.lock_info().status, StoreStatus::Locked);
}

/// A wipe leaves a blank device, and a blank device has no lock screen to return to.
#[test]
fn a_wipe_returns_a_blank_stateless_device() {
    let mut ui = locked(720, 720);
    tap(&mut ui, RegionId::LockWake);
    assert_eq!(ui.unseal_result(UnsealOutcome::Wiped), None);
    assert_eq!(ui.lock_info().status, StoreStatus::Blank);
    assert_eq!(ui.screen(), ScreenId::Home);
    assert!(!ui.lock(), "there is no PIN left to lock behind");
}

/// The masking law extended to the PIN screens (0.6): two different PINs of the same
/// length must produce byte-identical frames.
#[test]
fn the_pin_screen_masks_the_same_for_two_different_pins() {
    let render = |pin: &str| {
        let mut ui = locked(720, 720);
        tap(&mut ui, RegionId::LockWake);
        type_pin(&mut ui, pin);
        Fb::render(&ui, 720, 720)
    };
    assert_eq!(render("135790").px, render("864213").px, "the dot run must not vary");
    assert_ne!(render("135790").px, render("1357903").px, "length is shown, by design");
}

/// The horizontal-slop fix: a sideways swipe across a button must CANCEL the tap, not
/// fire it. The old bookkeeping accumulated vertical movement only, so a finger that
/// slid across a key and lifted inside it pressed the key.
#[test]
fn a_sideways_swipe_across_a_button_cancels_the_tap() {
    let mut ui = locked(720, 720);
    tap(&mut ui, RegionId::LockWake);
    let key = region(&ui, RegionId::PinKey(0)).rect;
    let (x, y) = (key.x + 20, key.y + key.h / 2);
    ui.touch(TouchEvent::Down { x, y });
    // Straight across the key, well past the slop, and up while still inside it.
    ui.touch(TouchEvent::Move { x: x + 60, y });
    ui.touch(TouchEvent::Up { x: x + 60, y });
    assert_eq!(tap(&mut ui, RegionId::PinSubmit), None, "the swipe must not have typed");

    // A movement inside the slop is still a tap: the fix must not make buttons hard to
    // press for a finger that rolls a few pixels.
    ui.touch(TouchEvent::Down { x, y });
    ui.touch(TouchEvent::Move { x: x + 8, y: y + 4 });
    ui.touch(TouchEvent::Up { x: x + 8, y: y + 4 });
    type_pin(&mut ui, "23456");
    assert!(matches!(tap(&mut ui, RegionId::PinSubmit), Some(UiRequest::UnsealWallet(_))));
}

/// C4c: the hold fills over `HOLD_MS`, driven by `Ui::tick` and the press age, and a
/// release before it fills does nothing at all.
#[test]
fn the_hold_interlock_fills_over_time_and_a_release_fires_nothing() {
    assert_eq!(notyas_ui::hold_fill_permille(0), 0);
    assert_eq!(notyas_ui::hold_fill_permille(notyas_ui::HOLD_MS / 2), 500);
    assert_eq!(notyas_ui::hold_fill_permille(notyas_ui::HOLD_MS), 1000);
    assert_eq!(notyas_ui::hold_fill_permille(u32::MAX), 1000, "the fill saturates");

    let mut ui = locked(720, 720);
    tap(&mut ui, RegionId::LockWake);
    let key = region(&ui, RegionId::PinKey(0)).rect;
    let (x, y) = (key.x + key.w / 2, key.y + key.h / 2);
    ui.touch(TouchEvent::Down { x, y });
    assert_eq!(ui.press().map(|p| p.held_ms), Some(0));
    for _ in 0..3 {
        assert!(!ui.tick(500).dirty, "an ordinary press is a still frame");
    }
    assert_eq!(ui.press().map(|p| p.held_ms), Some(1500), "the press ages by real time");
    ui.touch(TouchEvent::Up { x, y });
    assert_eq!(ui.press(), None);
    assert!(!ui.hold_released(), "an ordinary tap is not a released hold");
}

/// The C4c control paints its fill from the permille it is handed and from nothing else,
/// so the same press age always draws the same bar - and an empty one is not the same
/// picture as a full one.
#[test]
fn the_hold_bar_paints_its_fill() {
    use notyas_ui::canvas;
    let bar = |permille: u32| {
        let mut fb = Fb::new(400, 200);
        canvas::hold_bar(
            &mut fb,
            notyas_ui::layout::Rect::new(20, 20, 360, 160),
            "Hold to erase",
            "Keep holding",
            permille,
            theme::DANGER,
        )
        .expect("draw");
        fb.px
    };
    assert_ne!(bar(0), bar(500), "the fill must move with the press age");
    assert_ne!(bar(500), bar(1000));
    assert_eq!(bar(1000), bar(4000), "the fill saturates rather than overrunning");
    assert_eq!(bar(500), bar(500), "and it is a pure function of the fraction");
}

/// A press that lands on bare paper does not age: there is nothing for a hold to fill.
#[test]
fn a_press_on_bare_paper_does_not_age() {
    let mut ui = locked(720, 720);
    tap(&mut ui, RegionId::LockWake);
    ui.touch(TouchEvent::Down { x: 0, y: 0 });
    ui.tick(1000);
    assert_eq!(ui.press().map(|p| p.held_ms), Some(0));
}

/// VERIFY.md 6 / R24: `not counted`, never `0`. A device that wrote nothing read nothing,
/// and `0` would be a value it did not measure.
#[test]
fn the_boot_counter_row_says_not_counted_rather_than_zero() {
    // The rows sit below the fold, so both readings are scrolled into view first - the
    // same drag a finger performs.
    let scrolled = |v: VerifyInfo| {
        let mut ui = Ui::new(720, 720);
        ui.set_verify_info(v);
        tap(&mut ui, RegionId::HomeVerifyDevice);
        ui.touch(TouchEvent::Down { x: 360, y: 600 });
        ui.touch(TouchEvent::Move { x: 360, y: -4000 });
        ui.touch(TouchEvent::Up { x: 360, y: -4000 });
        ui
    };
    let counted =
        scrolled(VerifyInfo { boot_count: Some(0), acknowledged_at: Some(0), ..VerifyInfo::default() });
    let uncounted = scrolled(VerifyInfo::default());

    assert_ne!(
        Fb::render(&counted, 720, 720).px,
        Fb::render(&uncounted, 720, 720).px,
        "a store that counted zero boots must not render like one that counted none"
    );
}

/// VERIFY.md 6.3: the mark is post-PIN only. A coercer who can press it erases the very
/// gap the counter exists to show, and there is nothing to acknowledge on a device that
/// has counted nothing.
#[test]
fn the_acknowledgement_mark_is_post_pin_only() {
    // The write sits in the sheet, beside the two rows it is about (C12: the band is
    // directly above the action), so reaching it means paging there - which is also the
    // only way a finger reaches it.
    let ack_ui = |status: StoreStatus, boots: Option<u64>| {
        let mut ui = Ui::new(720, 720);
        ui.set_lock_info(LockInfo { status, ..LockInfo::default() });
        ui.set_verify_info(VerifyInfo { boot_count: boots, ..VerifyInfo::default() });
        tap(&mut ui, RegionId::HomeVerifyDevice);
        assert_eq!(ui.screen(), ScreenId::VerifyDevice);
        ui
    };
    let has_ack = |status: StoreStatus, boots: Option<u64>| {
        let mut ui = ack_ui(status, boots);
        loop {
            if ui.regions().iter().any(|r| r.id == RegionId::VerifyAckBoots) {
                return true;
            }
            if !ui.regions().iter().any(|r| r.id == RegionId::ReviewNext) {
                return false;
            }
            tap(&mut ui, RegionId::ReviewNext);
        }
    };
    assert!(has_ack(StoreStatus::Unlocked, Some(42)));
    assert!(!has_ack(StoreStatus::Locked, Some(42)), "pre-PIN must not offer the write");
    assert!(!has_ack(StoreStatus::Blank, Some(42)));
    assert!(!has_ack(StoreStatus::Unlocked, None), "nothing counted, nothing to mark");

    let mut ui = ack_ui(StoreStatus::Unlocked, Some(42));
    while !ui.regions().iter().any(|r| r.id == RegionId::VerifyAckBoots) {
        tap(&mut ui, RegionId::ReviewNext);
    }
    assert_eq!(tap(&mut ui, RegionId::VerifyAckBoots), Some(UiRequest::AcknowledgeBoots));
}

/// Every geometry, every new screen: regions in bounds, non-overlapping, keypad keys on
/// their physical floor, and a full render that must not panic.
#[test]
fn the_lock_and_pin_screens_hold_on_both_geometries() {
    for (w, h) in [(720u32, 720u32), (800, 480)] {
        let mut ui = locked(w, h);
        check_regions(&ui, w as i32, h as i32);
        Fb::render(&ui, w, h);

        tap(&mut ui, RegionId::LockWake);
        check_regions(&ui, w as i32, h as i32);
        for r in ui.regions() {
            if matches!(r.id, RegionId::PinKey(_)) {
                assert!(
                    r.rect.w >= 80 && r.rect.h >= 80,
                    "PIN key {:?} below the keypad floor at {w}x{h}: {:?}",
                    r.id,
                    r.rect
                );
            }
        }
        Fb::render(&ui, w, h);

        // Every state the screen has, drawn: words shown, wrong PIN, the low-attempt
        // warning and the unlimited-tries line all wrap inside their reserved blocks.
        ui.show_device_words([String::from("anvil"), String::from("mercury")]);
        Fb::render(&ui, w, h);
        for attempts in [Some(9u8), Some(3), Some(1), None] {
            let mut info = ui.lock_info().clone();
            info.attempts_left = attempts;
            ui.set_lock_info(info);
            Fb::render(&ui, w, h);
        }
        ui.unseal_result(UnsealOutcome::WrongPin { attempts_left: Some(2) });
        check_regions(&ui, w as i32, h as i32);
        Fb::render(&ui, w, h);
    }
}

/// The region set is the same at both geometries for every new state (reflow rule 4:
/// nothing is dropped, only relocated).
#[test]
fn the_new_screens_offer_the_same_regions_at_both_geometries() {
    let ids = |ui: &Ui| {
        let mut v: Vec<String> = ui.regions().iter().map(|r| format!("{:?}", r.id)).collect();
        v.sort();
        v
    };
    let mut a = locked(720, 720);
    let mut b = locked(800, 480);
    assert_eq!(ids(&a), ids(&b), "lock screen");
    tap(&mut a, RegionId::LockWake);
    tap(&mut b, RegionId::LockWake);
    assert_eq!(ids(&a), ids(&b), "PIN entry");
}

/// The Lock affordance appears exactly where a session can be dropped, and the screens
/// that gain it still lay out cleanly: on Home (a stateless device the embedder has told
/// about a session) and on the wallet list, which only exists with one open.
#[test]
fn the_session_affordances_do_not_collide_at_either_geometry() {
    for (w, h) in [(720u32, 720u32), (800, 480)] {
        let unlocked = LockInfo { status: StoreStatus::Unlocked, ..LockInfo::default() };

        let mut home = Ui::new(w, h);
        home.set_lock_info(unlocked.clone());
        assert!(home.regions().iter().any(|r| r.id == RegionId::Lock));
        check_regions(&home, w as i32, h as i32);
        Fb::render(&home, w, h);

        let list = unlocked_with(w, h, 3);
        assert_eq!(list.screen(), ScreenId::WalletList);
        assert!(list.regions().iter().any(|r| r.id == RegionId::Lock));
        check_regions(&list, w as i32, h as i32);
        Fb::render(&list, w, h);
    }
}

// ---------------------------------------------------------------------------------------
// 0.2.0 m4b: the backup gate, the fork, the wallet list, the wallet home, and the C4d
// delete
// ---------------------------------------------------------------------------------------

/// Wallets as the embedder would report them after unsealing the store.
fn sample_wallets(n: u8) -> Vec<WalletRow> {
    const NAMES: [&str; 8] =
        ["savings", "vault", "testing", "spare", "cold", "hot", "gift", "misc"];
    (0..n)
        .map(|i| {
            WalletRow::Wallet(WalletInfo {
                slot: i,
                name: String::from(NAMES[i as usize % NAMES.len()]),
                fingerprint: format!("a1b2c3d{i}"),
                path: String::from("m/84'/0'/0'"),
                script_type: String::from("native segwit"),
                kind: WalletKind::SingleSig,
                backup: BackupState::Verified(String::new()),
                network: Network::Bitcoin,
                registrations: 0,
                stored: true,
                passphrase: false,
            })
        })
        .collect()
}

/// A device with a session open and `n` wallets read out of the store.
fn unlocked_with(w: u32, h: u32, n: u8) -> Ui {
    let mut ui = locked(w, h);
    tap(&mut ui, RegionId::LockWake);
    ui.unseal_result(UnsealOutcome::Unsealed);
    ui.set_wallets(sample_wallets(n));
    ui
}

/// Type a wallet name on S-20: raise the keyboard, type, put it away again.
fn name_the_wallet(ui: &mut Ui, name: &str) {
    tap(ui, RegionId::NameField);
    type_keys(ui, name);
    tap(ui, RegionId::KeyDone);
}

/// The create flow landed on the fork, with the passphrase left off.
fn ui_at_fork(w: u32, h: u32) -> Ui {
    let mut ui = ui_at_mnemonic(w, h, SIXES);
    tap(&mut ui, RegionId::Next);
    tap_done_and_derive(&mut ui);
    answer_quiz(&mut ui);
    assert_eq!(ui.screen(), ScreenId::KeepOrSave);
    ui
}

/// A device that already has a PIN and an open session.
///
/// Saving a wallet on a device with NO PIN routes through S-06/S-07 first, because the
/// sealing key IS the PIN and until one exists there is nothing to seal with. The tests
/// that follow are about naming and the write rather than about setting the PIN, so they
/// state which device they are on instead of walking a flow they are not testing; the route
/// through the PIN screens has its own test above.
fn already_has_a_pin(ui: &mut Ui) {
    ui.set_lock_info(LockInfo {
        status: StoreStatus::Unlocked,
        wipe_after: Some(15),
        ..LockInfo::default()
    });
}

/// Open the wallet in `slot` from the list, the way a finger does.
fn open_wallet(ui: &mut Ui, slot: u8) {
    let Some(UiRequest::OpenWallet(asked)) = tap(ui, RegionId::ListRow(slot)) else {
        panic!("a wallet row must ask the embedder to unseal it");
    };
    assert_eq!(asked, slot, "the row must name the slot the embedder reported");
    let WalletRow::Wallet(info) = sample_wallets(WALLET_SLOTS)[slot as usize].clone() else {
        panic!("sample")
    };
    ui.wallet_opened(info);
    assert_eq!(ui.screen(), ScreenId::WalletHome);
}

/// Commandment 3, made structural: the create path cannot reach the fork - and therefore
/// cannot reach a save - without every word of the backup being checked.
#[test]
fn the_create_path_is_gated_on_the_backup_check() {
    let mut ui = ui_at_mnemonic(720, 720, SIXES);
    tap(&mut ui, RegionId::Next);
    tap_done_and_derive(&mut ui);
    assert_eq!(ui.screen(), ScreenId::BackupCheck);
    // Neither leg of the fork exists yet, so there is nothing to skip to.
    let ids: Vec<RegionId> = ui.regions().iter().map(|r| r.id).collect();
    assert!(!ids.contains(&RegionId::SaveToDevice), "{ids:?}");
    assert!(!ids.contains(&RegionId::UseOnce), "{ids:?}");
    let view = ui.quiz().expect("the check is showing");
    assert_eq!(view.words, 12, "every word, no sampling");
    assert_eq!(view.word, 1);
    assert_eq!(view.choices.len(), 5, "five candidates (S-17)");
    answer_quiz(&mut ui);
    assert_eq!(ui.screen(), ScreenId::KeepOrSave);
}

/// A wrong answer re-poses THAT word with a fresh candidate set, rather than restarting
/// the quiz: a full restart punishes a fat finger with twenty-four re-taps and teaches
/// people to rush (the S-17 decision). The fresh set is what stops a retry from being
/// answerable by position.
#[test]
fn a_wrong_backup_answer_re_poses_the_same_word_with_a_fresh_set() {
    let mut ui = ui_at_mnemonic(720, 720, SIXES);
    tap(&mut ui, RegionId::Next);
    tap_done_and_derive(&mut ui);
    let first = ui.quiz().expect("the check is showing");

    // Word 1 of the all-zero-entropy vector is "abandon", so the test knows which of the
    // five is right and can pick one that is not - which is the only way to observe a
    // wrong answer without depending on where the derivation happened to put the answer.
    let wrong = first
        .choices
        .iter()
        .position(|c| c != "abandon")
        .expect("four of the five candidates are distractors");
    tap(&mut ui, RegionId::QuizChoice(wrong as u8));
    let after = ui.quiz().expect("a wrong answer stays on the check");
    assert_eq!(after.word, first.word, "the same word is re-posed");
    assert_eq!(after.done, first.done, "no progress is credited");
    assert_ne!(after.choices, first.choices, "the candidate set must be fresh");
    // And it is still finishable afterwards.
    answer_quiz(&mut ui);
    assert_eq!(ui.screen(), ScreenId::KeepOrSave);
}

/// The fork is the product's central choice, so the two halves are EQUAL: same size, both
/// present, neither reachable without the other. A layout that grew one card would be a
/// nudge whatever the wording said, which is why this is measured rather than reviewed.
#[test]
fn the_fork_weighs_the_two_choices_equally() {
    for (w, h) in [(720u32, 720u32), (800, 480)] {
        let ui = ui_at_fork(w, h);
        let save = region(&ui, RegionId::SaveToDevice).rect;
        let once = region(&ui, RegionId::UseOnce).rect;
        assert_eq!((save.w, save.h), (once.w, once.h), "{w}x{h}: the cards differ");
        assert!(!save.overlaps(&once), "{w}x{h}: the cards overlap");
        check_regions(&ui, w as i32, h as i32);
        Fb::render(&ui, w, h);
    }
}

/// The stateless leg writes nothing and lands on a wallet home that says so; the wallet it
/// produces is the session itself, so leaving it is gated by the exit modal.
#[test]
fn keeping_nothing_writes_nothing_and_says_so() {
    let mut ui = ui_at_fork(720, 720);
    assert_eq!(tap(&mut ui, RegionId::UseOnce), None, "nothing is asked of the embedder");
    assert_eq!(ui.screen(), ScreenId::WalletHome);
    // A session wallet has no slot to erase, so it offers no delete.
    assert!(!ui.regions().iter().any(|r| r.id == RegionId::WalletDelete));
    // ...and the keys are on this screen, so Back asks first.
    tap(&mut ui, RegionId::Back);
    assert_eq!(ui.regions().len(), 2, "the exit modal is the only thing tappable");
    tap(&mut ui, RegionId::ModalCancel);
    assert_eq!(ui.screen(), ScreenId::WalletHome);
}

/// The save leg on a device that has never had a PIN, which is every new device: the fork
/// routes through S-06/S-07, the same PIN twice is what raises the request that formats the
/// store, and the answer lands the user back on the naming screen with the wallet intact.
///
/// This is the route the 0.2.0 image did not have. Nothing in the product could set a PIN,
/// so nothing in the product could store a wallet; the console that could is compiled out of
/// a release build.
#[test]
fn saving_on_a_device_with_no_pin_sets_one_first() {
    let mut ui = ui_at_fork(720, 720);
    // A device key burned and nothing sealed: the state a new device is in the first time
    // anybody taps Save.
    ui.set_lock_info(LockInfo {
        status: StoreStatus::Blank,
        wipe_after: Some(15),
        ..LockInfo::default()
    });
    assert_eq!(
        tap(&mut ui, RegionId::SaveToDevice),
        None,
        "the create screen asks the embedder for nothing until a PIN is typed twice"
    );
    assert_eq!(ui.screen(), ScreenId::PinCreate);

    // Back is a real way out, and the fork behind it still offers both legs.
    tap(&mut ui, RegionId::Back);
    assert_eq!(ui.screen(), ScreenId::KeepOrSave);
    region(&ui, RegionId::SaveToDevice);
    tap(&mut ui, RegionId::SaveToDevice);

    // A mismatch writes nothing and asks for nothing.
    type_pin(&mut ui, "2468");
    assert_eq!(tap(&mut ui, RegionId::PinNext), None);
    type_pin(&mut ui, "2469");
    assert_eq!(tap(&mut ui, RegionId::PinConfirm), None, "a mismatch must not write");
    assert_eq!(ui.screen(), ScreenId::PinCreate);

    // The same PIN twice hands the embedder the value it needs to format the store.
    type_pin(&mut ui, "2468");
    tap(&mut ui, RegionId::PinNext);
    type_pin(&mut ui, "2468");
    let Some(UiRequest::SetPin(pin)) = tap(&mut ui, RegionId::PinConfirm) else {
        panic!("a matching confirm must hand the PIN to the embedder");
    };
    assert_eq!(pin.as_str(), "2468");

    // A refused write keeps the user on the screen, which is where the reason is stated.
    ui.pin_created(false);
    assert_eq!(ui.screen(), ScreenId::PinCreate);

    // ...and the one that succeeds advances the leg the user was already on.
    type_pin(&mut ui, "2468");
    tap(&mut ui, RegionId::PinNext);
    type_pin(&mut ui, "2468");
    tap(&mut ui, RegionId::PinConfirm);
    ui.pin_created(true);
    assert_eq!(ui.screen(), ScreenId::NameWallet);

    // The wallet survived the detour: it is still the one the fork was holding.
    name_the_wallet(&mut ui, "savings");
    let Some(UiRequest::PersistWallet(draft)) = tap(&mut ui, RegionId::ConfirmSave) else {
        panic!("a named wallet must be handed to the embedder");
    };
    assert_eq!(draft.name, "savings");
    assert_eq!(draft.phrase().split(' ').count(), 12, "the BIP39 phrase, as derived");
    ui.persist_result(true);
    assert_eq!(ui.screen(), ScreenId::WalletHome);
}

/// The storing leg: name the wallet, announce the write, hand the phrase over, land on the
/// new wallet home. The Save button is inert until the wallet has a name, and Back from
/// the naming screen finds the fork able to offer both legs again.
#[test]
fn saving_a_wallet_names_it_and_lands_on_its_home() {
    let mut ui = ui_at_fork(720, 720);
    already_has_a_pin(&mut ui);
    tap(&mut ui, RegionId::SaveToDevice);
    assert_eq!(ui.screen(), ScreenId::NameWallet);

    // Back is a real way out, and the fork survives it intact.
    tap(&mut ui, RegionId::Back);
    assert_eq!(ui.screen(), ScreenId::KeepOrSave);
    region(&ui, RegionId::SaveToDevice);
    region(&ui, RegionId::UseOnce);
    tap(&mut ui, RegionId::SaveToDevice);

    assert_eq!(tap(&mut ui, RegionId::ConfirmSave), None, "an unnamed wallet cannot be saved");
    // The field raises the keyboard and its Done puts it away: the write notice and the
    // button it announces cannot share a panel with four keyboard rows at 800x480.
    name_the_wallet(&mut ui, "savings");
    let Some(UiRequest::PersistWallet(draft)) = tap(&mut ui, RegionId::ConfirmSave) else {
        panic!("a named wallet must be handed to the embedder");
    };
    assert_eq!(draft.name, "savings");
    assert_eq!(draft.phrase().split(' ').count(), 12, "the BIP39 phrase, as derived");
    assert_eq!(draft.fingerprint.len(), 8, "the master fingerprint, not a truncation");
    assert!(!draft.passphrase);

    ui.persist_result(true);
    assert_eq!(ui.screen(), ScreenId::WalletHome);
    assert!(ui.regions().iter().any(|r| r.id == RegionId::WalletDelete), "a stored wallet");
}

/// Q22, at the placement where it can still change what the user does: a passphrase wallet
/// cannot be saved until the owner has acknowledged, explicitly, that the device does not
/// keep the passphrase. A wallet with no passphrase is not asked, so the tap never becomes
/// the habit the requirement exists to break.
#[test]
fn a_passphrase_wallet_cannot_be_saved_without_acknowledging_it_is_not_stored() {
    let mut ui = ui_at_mnemonic(720, 720, SIXES);
    tap(&mut ui, RegionId::Next);
    tap(&mut ui, RegionId::PassToggle);
    type_keys(&mut ui, "ab");
    tap(&mut ui, RegionId::PassConfirm);
    type_keys(&mut ui, "ab");
    tap_done_and_derive(&mut ui);
    answer_quiz(&mut ui);
    already_has_a_pin(&mut ui);
    tap(&mut ui, RegionId::SaveToDevice);
    assert_eq!(ui.screen(), ScreenId::NameWallet);

    name_the_wallet(&mut ui, "savings");
    assert_eq!(
        tap(&mut ui, RegionId::ConfirmSave),
        None,
        "a named passphrase wallet still needs the acknowledgement"
    );
    let before = Fb::render(&ui, 720, 720);
    tap(&mut ui, RegionId::PassNotStoredAck);
    assert_ne!(before.px, Fb::render(&ui, 720, 720).px, "the acknowledgement must show");
    let Some(UiRequest::PersistWallet(draft)) = tap(&mut ui, RegionId::ConfirmSave) else {
        panic!("the acknowledged save must go through");
    };
    assert!(draft.passphrase, "the record records that a passphrase was applied");

    // ...and a wallet with no passphrase is never asked.
    let mut plain = ui_at_fork(720, 720);
    tap(&mut plain, RegionId::SaveToDevice);
    assert!(!plain.regions().iter().any(|r| r.id == RegionId::PassNotStoredAck));
}

/// The Q22 warning reaches every placement its acceptance criterion names, and it is the
/// SAME words at each: the passphrase entry of the create and restore flows, the post-check
/// backup screen, and the save. Asserted by the pixels, because the fork and the naming
/// screen draw it only for a wallet that has a passphrase - so a frame that changes with
/// the passphrase is the warning arriving, and one that does not is it missing.
#[test]
fn the_passphrase_not_stored_warning_reaches_every_placement() {
    // (i) and (iii): the passphrase screen, which both entry paths pass through. Its OFF
    // state is where the block is drawn, so a frame with the fields up is a different
    // screen state rather than a missing warning - compare the state that carries it.
    let mut create = ui_at_mnemonic(720, 720, SIXES);
    tap(&mut create, RegionId::Next);
    let off = Fb::render(&create, 720, 720);
    let mut restore = Ui::new(720, 720);
    tap(&mut restore, RegionId::HomeVerifySeed);
    type_keys(&mut restore, VECTOR1_PHRASE);
    tap(&mut restore, RegionId::KeyDone);
    assert_eq!(restore.screen(), ScreenId::PassphraseEntry);
    assert_eq!(
        off.px,
        Fb::render(&restore, 720, 720).px,
        "the restore flow must see the same passphrase screen the create flow does"
    );
    // The warning is really drawn there: turning the passphrase on replaces that state.
    tap(&mut create, RegionId::PassToggle);
    assert_ne!(off.px, Fb::render(&create, 720, 720).px);

    // (ii) the fork, and the save: both carry it exactly for a wallet that has one.
    let with_pass = {
        let mut ui = ui_at_mnemonic(720, 720, SIXES);
        tap(&mut ui, RegionId::Next);
        tap(&mut ui, RegionId::PassToggle);
        type_keys(&mut ui, "ab");
        tap(&mut ui, RegionId::PassConfirm);
        type_keys(&mut ui, "ab");
        tap_done_and_derive(&mut ui);
        answer_quiz(&mut ui);
        ui
    };
    let without = ui_at_fork(720, 720);
    assert_ne!(
        Fb::render(&with_pass, 720, 720).px,
        Fb::render(&without, 720, 720).px,
        "the fork must warn about a passphrase it is about to let the user keep nothing of"
    );
}

/// Ratified Q2(a), and the easiest thing in this milestone to break by accident: NO
/// pre-PIN surface may state how many wallets exist. The adversarial case is the one
/// asserted - an embedder that installed the list and then locked, or installed it while
/// locked - because a device that only leaks when misdriven still leaks.
#[test]
fn no_pre_pin_surface_states_how_many_wallets_exist() {
    for (w, h) in [(720u32, 720u32), (800, 480)] {
        let frames = |n: u8| {
            let mut ui = locked(w, h);
            ui.set_wallets(sample_wallets(n));
            let lock = Fb::render(&ui, w, h).px;
            // The Verify screen is reachable BEFORE the PIN by design, so it is the other
            // half of the same surface.
            tap(&mut ui, RegionId::HomeVerifyDevice);
            assert_eq!(ui.screen(), ScreenId::VerifyDevice);
            (lock, Fb::render(&ui, w, h).px)
        };
        let (lock_blank, verify_blank) = frames(0);
        let (lock_full, verify_full) = frames(WALLET_SLOTS);
        assert_eq!(lock_blank, lock_full, "{w}x{h}: the lock screen counted the wallets");
        assert_eq!(verify_blank, verify_full, "{w}x{h}: the Verify screen counted them");
        // The occupancy WORD does still move, which is what makes the equalities above a
        // statement about the count rather than about a screen that says nothing.
        let mut blank = locked(w, h);
        blank.set_lock_info(LockInfo { status: StoreStatus::Blank, ..blank.lock_info().clone() });
        assert_ne!(
            lock_blank,
            Fb::render(&blank, w, h).px,
            "{w}x{h}: the lock screen must still report present against blank"
        );
    }
}

/// ...and after the PIN the same device shows the wallets themselves, because that reader
/// has already proved the PIN and the rows disclose more than the count does anyway.
#[test]
fn the_wallet_list_shows_the_real_wallets_after_the_pin() {
    let mut ui = unlocked_with(720, 720, 3);
    assert_eq!(ui.screen(), ScreenId::WalletList);
    for slot in 0..3u8 {
        region(&ui, RegionId::ListRow(slot));
    }
    assert!(!ui.regions().iter().any(|r| r.id == RegionId::ListRow(3)));
    // The count in use is on this screen and nowhere else, so the frame must move with it.
    let three = Fb::render(&ui, 720, 720);
    ui.set_wallets(sample_wallets(2));
    assert_ne!(three.px, Fb::render(&ui, 720, 720).px);

    // An empty store is a first-class row rather than a blank panel, and locking takes the
    // whole list with it.
    ui.set_wallets(Vec::new());
    Fb::render(&ui, 720, 720);
    region(&ui, RegionId::WalletNew);
    ui.set_wallets(sample_wallets(3));
    assert!(ui.lock());
    assert!(ui.wallets().is_empty(), "a locked device holds no list to render");
}

/// The C4d delete: the consequence is read, then the wallet's own name is typed back
/// exactly, and only then does the device ask for the erase. Nothing short of the exact
/// name arms it.
#[test]
fn deleting_a_wallet_needs_its_name_typed_back() {
    let mut ui = unlocked_with(720, 720, 3);
    open_wallet(&mut ui, 0);

    tap(&mut ui, RegionId::WalletDelete);
    // The sheet is MODAL: the wallet under it is as inert to a finger as it is invisible.
    let ids: Vec<RegionId> = ui.regions().iter().map(|r| r.id).collect();
    assert_eq!(ids.len(), 2, "the reading step offers Cancel and Continue only: {ids:?}");
    assert!(!ids.contains(&RegionId::WalletDelete), "the sheet covers its own trigger");

    // Cancel really cancels.
    tap(&mut ui, RegionId::DangerCancel);
    assert_eq!(ui.screen(), ScreenId::WalletHome);
    region(&ui, RegionId::WalletDelete);

    tap(&mut ui, RegionId::WalletDelete);
    tap(&mut ui, RegionId::DangerConfirm); // the consequence has been read
    assert_eq!(tap(&mut ui, RegionId::DangerConfirm), None, "nothing typed yet");
    type_keys(&mut ui, "saving");
    assert_eq!(tap(&mut ui, RegionId::DangerConfirm), None, "a prefix is not the name");
    type_keys(&mut ui, "s");
    let Some(UiRequest::DeleteWallet(slot)) = tap(&mut ui, RegionId::DangerConfirm) else {
        panic!("the exact name must arm the delete");
    };
    assert_eq!(slot, 0, "the slot the wallet reported");
    assert_eq!(ui.screen(), ScreenId::WalletList, "and the user lands back on the list");
}

/// Every m4b screen, on both panels: regions in bounds, non-overlapping, and a full render
/// that must not panic. The delete sheet is included at both of its steps, because the
/// keyboard it raises is the tightest layout in the milestone.
#[test]
fn the_m4b_screens_hold_on_both_geometries() {
    for (w, h) in [(720u32, 720u32), (800, 480)] {
        let check = |ui: &Ui| {
            check_regions(ui, w as i32, h as i32);
            Fb::render(ui, w, h);
        };

        let mut ui = unlocked_with(w, h, 3);
        check(&ui);
        open_wallet(&mut ui, 0);
        check(&ui);
        tap(&mut ui, RegionId::WalletDelete);
        check(&ui);
        tap(&mut ui, RegionId::DangerConfirm);
        check(&ui);
        type_keys(&mut ui, "savings");
        check(&ui);
        tap(&mut ui, RegionId::DangerCancel);

        let mut create = ui_at_mnemonic(w, h, SIXES);
        tap(&mut create, RegionId::Next);
        tap_done_and_derive(&mut create);
        check(&create); // the backup check
        answer_quiz(&mut create);
        check(&create); // the fork
        already_has_a_pin(&mut create);
        tap(&mut create, RegionId::SaveToDevice);
        check(&create); // naming: the write notice and the button it announces
        tap(&mut create, RegionId::NameField);
        check(&create); // ...and the keyboard phase
        type_keys(&mut create, "savings");
        tap(&mut create, RegionId::KeyDone);
        check(&create);
    }
}

/// Reflow rule 4 over the whole milestone: the same state offers the same regions on both
/// panels. Nothing is dropped on the shorter one, only relocated.
#[test]
fn the_m4b_screens_offer_the_same_regions_at_both_geometries() {
    let ids = |ui: &Ui| {
        let mut v: Vec<String> = ui.regions().iter().map(|r| format!("{:?}", r.id)).collect();
        v.sort();
        v
    };
    // Two wallets, because the list SCROLLS: the short panel shows two rows and the tall
    // one three, and a row scrolled out of the viewport is legitimately not tappable (the
    // same property the schemes screen QR buttons have). Parity is about the region
    // vocabulary of a state, not about how much of a reference list is on screen; that
    // every row is reachable by scrolling is asserted where the scrolling lives.
    let mut a = unlocked_with(720, 720, 2);
    let mut b = unlocked_with(800, 480, 2);
    assert_eq!(ids(&a), ids(&b), "wallet list");

    open_wallet(&mut a, 0);
    open_wallet(&mut b, 0);
    assert_eq!(ids(&a), ids(&b), "wallet home");
    tap(&mut a, RegionId::WalletDelete);
    tap(&mut b, RegionId::WalletDelete);
    assert_eq!(ids(&a), ids(&b), "delete: the reading step");
    tap(&mut a, RegionId::DangerConfirm);
    tap(&mut b, RegionId::DangerConfirm);
    assert_eq!(ids(&a), ids(&b), "delete: the typing step");

    let mut c = ui_at_mnemonic(720, 720, SIXES);
    let mut d = ui_at_mnemonic(800, 480, SIXES);
    tap(&mut c, RegionId::Next);
    tap(&mut d, RegionId::Next);
    tap_done_and_derive(&mut c);
    tap_done_and_derive(&mut d);
    assert_eq!(ids(&c), ids(&d), "backup check");
    answer_quiz(&mut c);
    answer_quiz(&mut d);
    assert_eq!(ids(&c), ids(&d), "the fork");
    tap(&mut c, RegionId::SaveToDevice);
    tap(&mut d, RegionId::SaveToDevice);
    assert_eq!(ids(&c), ids(&d), "name and save");
}

// ---------------------------------------------------------------------------------------
// 0.2.0 m4b: S-44, the wrong-PIN policy editor, and the PIN-removal flow
// ---------------------------------------------------------------------------------------

/// A device with a session open, three wallets, and a policy the editor can move.
fn ui_at_settings(w: u32, h: u32) -> Ui {
    let mut ui = unlocked_with(w, h, 3);
    ui.set_lock_info(LockInfo {
        status: StoreStatus::Unlocked,
        nickname: String::from("kitchen-desk"),
        lock_word: String::from("anvil"),
        attempts_left: Some(10),
        wipe_after: Some(10),
        pin: Some(PinShape { len: 6, alphabet: PinShape::DIGITS }),
        unlock_ms: UNLOCK_MS_M1,
        ..LockInfo::default()
    });
    tap(&mut ui, RegionId::OpenSettings);
    assert_eq!(ui.screen(), ScreenId::Settings);
    ui
}

/// Type an uppercase word on the on-screen keyboard, the way a finger does: shift, then
/// the letters. The confirmation words are uppercase precisely so that typing one is a
/// deliberate act rather than four taps of muscle memory.
fn type_shifted(ui: &mut Ui, word: &str) {
    tap(ui, RegionId::Shift);
    for c in word.chars() {
        tap(ui, RegionId::Key(c));
    }
}

fn has(ui: &Ui, id: RegionId) -> bool {
    ui.regions().iter().any(|r| r.id == id)
}

/// Settings is a POST-PIN surface and is reachable only from the screen a session lives
/// on. Every row it carries configures stored wallets, so on a device that stores nothing
/// there is nothing behind it - and there is no affordance either.
#[test]
fn settings_is_offered_only_with_a_session_open() {
    // Stateless: the home screen has no session and no Settings.
    let stateless = Ui::new(720, 720);
    assert!(!has(&stateless, RegionId::OpenSettings), "a blank device has nothing to configure");

    // Locked: the lock screen offers one thing, and it is not this.
    let locked = locked(720, 720);
    assert!(!has(&locked, RegionId::OpenSettings));

    // Unlocked: the wallet list carries it, beside the Lock chip.
    let mut ui = unlocked_with(720, 720, 2);
    assert_eq!(ui.screen(), ScreenId::WalletList);
    assert!(has(&ui, RegionId::OpenSettings));
    tap(&mut ui, RegionId::OpenSettings);
    assert_eq!(ui.screen(), ScreenId::Settings);
    // Back returns to the list rather than to an empty stack that happens to look like it.
    tap(&mut ui, RegionId::Back);
    assert_eq!(ui.screen(), ScreenId::WalletList);
}

/// The editor stages the threshold and commits it as ONE write, because committing
/// re-seals the store under the PIN: a stepper that wrote per tap would spend a flash
/// erase and a two-second stretch on every digit.
#[test]
fn the_policy_editor_stages_a_threshold_and_saves_it_as_one_write() {
    let mut ui = ui_at_settings(720, 720);
    tap(&mut ui, RegionId::SetRow(1));
    assert_eq!(ui.screen(), ScreenId::WipePolicy);

    // Nothing edited yet: there is nothing to save and no button offering to.
    assert!(!has(&ui, RegionId::PolicySave), "an unedited policy offers no write");

    // Stepping stages a change, and only then is a write on offer.
    assert_eq!(tap(&mut ui, RegionId::PolicyMore), None, "the stepper writes nothing");
    assert!(has(&ui, RegionId::PolicySave));
    assert_eq!(
        tap(&mut ui, RegionId::PolicySave),
        Some(UiRequest::SetWipePolicy { wipe_after: Some(11) })
    );

    // The embedder answers, and installs the policy as it now reads. The screen goes back
    // to showing the store, so there is nothing left to save.
    ui.policy_result(true);
    ui.set_lock_info(LockInfo { wipe_after: Some(11), ..ui.lock_info().clone() });
    assert!(!has(&ui, RegionId::PolicySave), "a saved policy is not still pending");

    // The bounds are the sealed format's, not a preference: the stepper cannot leave them.
    for _ in 0..40 {
        tap(&mut ui, RegionId::PolicyLess);
    }
    let Some(UiRequest::SetWipePolicy { wipe_after }) = tap(&mut ui, RegionId::PolicySave) else {
        panic!("a staged change offers a write");
    };
    assert_eq!(wipe_after, Some(WIPE_AFTER_MIN));
    ui.policy_result(true);
    ui.set_lock_info(LockInfo { wipe_after: Some(WIPE_AFTER_MIN), ..ui.lock_info().clone() });
    for _ in 0..40 {
        tap(&mut ui, RegionId::PolicyMore);
    }
    let Some(UiRequest::SetWipePolicy { wipe_after }) = tap(&mut ui, RegionId::PolicySave) else {
        panic!("a staged change offers a write");
    };
    assert_eq!(wipe_after, Some(WIPE_AFTER_MAX));
}

/// Turning the wipe off is the only genuinely weakened configuration in the product, and
/// the gate says so with the arithmetic for the PIN actually set. Two sheets, a typed
/// word, and no write until Save.
#[test]
fn turning_erasing_off_needs_the_arithmetic_read_and_the_word_typed() {
    let mut ui = ui_at_settings(720, 720);
    tap(&mut ui, RegionId::SetRow(1));

    let before = Fb::render(&ui, 720, 720);
    tap(&mut ui, RegionId::PolicyWipe);
    // The sheet is MODAL: the editor underneath is inert, and the panel changed.
    assert!(!has(&ui, RegionId::PolicyWipe), "the sheet must cover its own screen");
    assert!(!has(&ui, RegionId::PolicyLess));
    assert_ne!(before.px, Fb::render(&ui, 720, 720).px);
    // Three answers, not two: PIN-MODES requires the longer-PIN path be offered as an
    // action rather than the user having to choose between accepting and giving up.
    assert!(has(&ui, RegionId::DangerCancel));
    assert!(has(&ui, RegionId::DangerConfirm));
    assert!(has(&ui, RegionId::DangerAlternative));

    // Reading the consequence is not consenting to it: the next sheet is the word.
    assert_eq!(tap(&mut ui, RegionId::DangerConfirm), None, "no write from the first sheet");
    assert!(has(&ui, RegionId::Key('a')), "the typed sheet brings a keyboard");
    assert!(!has(&ui, RegionId::DangerAlternative), "the second sheet is accept or cancel");

    // The confirm is inert until the word matches exactly.
    assert_eq!(tap(&mut ui, RegionId::DangerConfirm), None);
    assert!(has(&ui, RegionId::Key('a')), "an unarmed confirm leaves the sheet open");
    type_shifted(&mut ui, "OF");
    assert_eq!(tap(&mut ui, RegionId::DangerConfirm), None, "a partial word is not the word");
    assert!(has(&ui, RegionId::Key('F')));
    tap(&mut ui, RegionId::Key('F'));

    // Consent complete: the sheet closes and the change is STAGED, not written.
    assert_eq!(tap(&mut ui, RegionId::DangerConfirm), None, "consent is not a write");
    assert!(has(&ui, RegionId::PolicyWipe), "the sheet closes on consent");
    assert_eq!(ui.lock_info().wipe_after, Some(10), "nothing was written yet");
    // With no threshold left there is nothing to step, so the stepper is not offered.
    assert!(!has(&ui, RegionId::PolicyLess));
    assert_eq!(
        tap(&mut ui, RegionId::PolicySave),
        Some(UiRequest::SetWipePolicy { wipe_after: None })
    );
}

/// The third answer. It exists to make the warning stop being true rather than to be
/// accepted or dismissed, so it changes no policy and hands the change-PIN sequence to
/// the side that owns the PIN.
#[test]
fn the_longer_pin_path_is_an_action_that_leaves_the_policy_alone() {
    let mut ui = ui_at_settings(720, 720);
    tap(&mut ui, RegionId::SetRow(1));
    tap(&mut ui, RegionId::PolicyWipe);
    assert_eq!(tap(&mut ui, RegionId::DangerAlternative), Some(UiRequest::ChangePin));
    assert!(has(&ui, RegionId::PolicyWipe), "the sheet closes");
    assert!(!has(&ui, RegionId::PolicySave), "and stages nothing");
    assert_eq!(ui.lock_info().wipe_after, Some(10));
}

/// A cancelled sheet changes nothing, at either step.
#[test]
fn cancelling_either_sheet_leaves_the_policy_where_it_was() {
    for steps in [0, 1] {
        let mut ui = ui_at_settings(720, 720);
        tap(&mut ui, RegionId::SetRow(1));
        let before = Fb::render(&ui, 720, 720);
        tap(&mut ui, RegionId::PolicyWipe);
        for _ in 0..steps {
            tap(&mut ui, RegionId::DangerConfirm);
        }
        tap(&mut ui, RegionId::DangerCancel);
        assert_eq!(before.px, Fb::render(&ui, 720, 720).px, "cancel restored nothing");
        assert!(!has(&ui, RegionId::PolicySave));
    }
}

/// Q5.5. Removing the PIN destroys everything the PIN protects, because the PIN is the key
/// that encrypts it; the confirmation names what goes, with counts read from the store,
/// and the word is typed back. What is left is a device that stores nothing.
#[test]
fn removing_the_pin_needs_the_word_and_returns_a_stateless_device() {
    let mut ui = ui_at_settings(720, 720);
    let list = Fb::render(&ui, 720, 720);
    tap(&mut ui, RegionId::RemoveThePin);
    assert_ne!(list.px, Fb::render(&ui, 720, 720).px, "the sheet must paint");
    assert!(!has(&ui, RegionId::SetRow(0)), "the list under the sheet is inert");
    // The consequence sheet accepts or cancels; there is no third way out of this one.
    assert!(!has(&ui, RegionId::DangerAlternative));

    assert_eq!(tap(&mut ui, RegionId::DangerConfirm), None, "reading is not consenting");
    assert_eq!(tap(&mut ui, RegionId::DangerConfirm), None, "and neither is an empty field");
    type_shifted(&mut ui, "WIPE");
    let Some(UiRequest::RemovePin) = tap(&mut ui, RegionId::DangerConfirm) else {
        panic!("the typed word must release the request");
    };

    // The embedder erases the store and says so. What comes back is the 0.1.0 device: no
    // PIN, no session, no wallets, and the stateless home.
    ui.pin_removed(true);
    assert_eq!(ui.screen(), ScreenId::Home);
    assert_eq!(ui.lock_info().status, StoreStatus::Blank);
    assert_eq!(ui.lock_info().wipe_after, None);
    assert!(ui.wallets().is_empty());
    assert!(!has(&ui, RegionId::OpenSettings), "there is nothing left to configure");
    assert!(!ui.lock(), "a device with no PIN has no lock screen to return to");
}

/// A destructive request that quietly did nothing is the worst outcome to leave a user
/// guessing at, so a refusal is reported on the screen that asked.
#[test]
fn a_refused_removal_is_reported_rather_than_swallowed() {
    let mut ui = ui_at_settings(720, 720);
    let quiet = Fb::render(&ui, 720, 720);
    tap(&mut ui, RegionId::RemoveThePin);
    tap(&mut ui, RegionId::DangerConfirm);
    type_shifted(&mut ui, "WIPE");
    tap(&mut ui, RegionId::DangerConfirm);

    ui.pin_removed(false);
    assert_eq!(ui.screen(), ScreenId::Settings, "a refusal does not move the user");
    assert_eq!(ui.lock_info().status, StoreStatus::Unlocked, "and destroys nothing");
    assert_ne!(quiet.px, Fb::render(&ui, 720, 720).px, "the refusal must be on the panel");
}

/// Both new screens and all four sheets lay out and paint on both shipped panels, with
/// nothing overlapping and nothing off the edge.
#[test]
fn the_settings_screens_hold_on_both_geometries() {
    for (w, h) in [(720u32, 720u32), (800, 480)] {
        let check = |ui: &Ui| {
            check_regions(ui, w as i32, h as i32);
            Fb::render(ui, w, h);
        };
        let mut ui = ui_at_settings(w, h);
        check(&ui);

        // The wipe-policy editor, its scroll, and both of its sheets.
        tap(&mut ui, RegionId::SetRow(1));
        check(&ui);
        ui.touch(TouchEvent::Down { x: w as i32 / 4, y: h as i32 / 2 });
        ui.touch(TouchEvent::Move { x: w as i32 / 4, y: h as i32 / 4 });
        ui.touch(TouchEvent::Up { x: w as i32 / 4, y: h as i32 / 4 });
        check(&ui);
        tap(&mut ui, RegionId::PolicyWipe);
        check(&ui);
        tap(&mut ui, RegionId::DangerConfirm);
        check(&ui);
        tap(&mut ui, RegionId::DangerCancel);
        // ...and the editor with the wipe already off, where the stepper is absent.
        ui.set_lock_info(LockInfo { wipe_after: None, ..ui.lock_info().clone() });
        check(&ui);
        tap(&mut ui, RegionId::PolicyWipe);
        check(&ui);

        // The removal sheets.
        tap(&mut ui, RegionId::Back);
        assert_eq!(ui.screen(), ScreenId::Settings);
        tap(&mut ui, RegionId::RemoveThePin);
        check(&ui);
        tap(&mut ui, RegionId::DangerConfirm);
        check(&ui);
    }
}

// ---------------------------------------------------------------------------------------
// 0.2.0 m4b: seed import by word entry (S-14)
// ---------------------------------------------------------------------------------------

/// The checksum is ENFORCED at entry, not reported beside it: Done cannot leave this
/// screen until the words are a real seed. This is the interlock the restore flow rests
/// on - a mistyped word is a different wallet, and finding that out later costs coins.
#[test]
fn word_entry_refuses_a_phrase_that_is_not_a_seed() {
    let mut ui = Ui::new(720, 720);
    tap(&mut ui, RegionId::HomeVerifySeed);
    for phrase in [
        "",
        "zoo zoo zoo ",
        // Twelve real words whose checksum does not hold.
        &VECTOR1_PHRASE.replace("about", "zoo"),
        // A word the list does not have, in an otherwise complete phrase.
        &VECTOR1_PHRASE.replace("about", "notaword"),
    ] {
        let mut ui = Ui::new(720, 720);
        tap(&mut ui, RegionId::HomeVerifySeed);
        type_keys(&mut ui, phrase);
        tap(&mut ui, RegionId::KeyDone);
        assert_eq!(ui.screen(), ScreenId::PhraseEntry, "Done must refuse {phrase:?}");
    }
    type_keys(&mut ui, VECTOR1_PHRASE);
    tap(&mut ui, RegionId::KeyDone);
    assert_eq!(ui.screen(), ScreenId::PassphraseEntry, "a real seed goes on");
}

/// The final-word helper. One word short of a seed, the strip offers the words that would
/// actually check rather than every word starting with the same letters, and the overflow
/// slot opens the rest of them.
#[test]
fn the_final_word_helper_offers_and_completes_a_checksum_valid_last_word() {
    let head = VECTOR1_PHRASE.rsplit_once(' ').unwrap().0;
    for (w, h) in [(720u32, 720u32), (800, 480)] {
        let mut ui = Ui::new(w, h);
        tap(&mut ui, RegionId::HomeVerifySeed);
        type_keys(&mut ui, &format!("{head} "));
        // Three chips and an overflow slot: 128 words can complete a 12-word seed and the
        // strip never pretends otherwise.
        assert_eq!(
            ui.regions().iter().filter(|r| matches!(r.id, RegionId::Suggest(_))).count(),
            3,
            "{w}x{h}: three chips beside the overflow slot"
        );
        assert!(has(&ui, RegionId::SuggestMore), "{w}x{h}: the rest must be reachable");

        // The sheet is modal, scrolls, and every chip on it completes the phrase.
        tap(&mut ui, RegionId::SuggestMore);
        check_regions(&ui, w as i32, h as i32);
        assert!(!has(&ui, RegionId::Key('a')), "{w}x{h}: the keyboard is covered");
        assert!(has(&ui, RegionId::SuggestClose));
        Fb::render(&ui, w, h);
        tap(&mut ui, RegionId::SuggestClose);
        assert!(has(&ui, RegionId::Key('a')), "{w}x{h}: closing gives the keyboard back");

        // Narrowing by prefix leaves a short list, and taking one finishes the seed.
        type_keys(&mut ui, "abou");
        tap(&mut ui, RegionId::Suggest(0));
        tap(&mut ui, RegionId::KeyDone);
        assert_eq!(
            ui.screen(),
            ScreenId::PassphraseEntry,
            "{w}x{h}: a completed last word must produce a valid seed"
        );
    }
}
