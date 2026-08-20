// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The delete-wallet route, end to end, through the public API only.
//!
//! Four properties, each of which failed against the build that shipped:
//!
//! 1. The erase cannot be reached without the typed-name gate AND the last-words step.
//! 2. A refusal reaches the user as a sentence. The old handler answered a refused delete
//!    by re-installing an unchanged list, which after a typed consent reads as a dead
//!    button - the owner's report.
//! 3. A completed delete lands on the wallet list with the wallet gone from it and a band
//!    naming what happened (S-47).
//! 4. The words shown before the erase are shown behind S-13's gate, with S-13's masking:
//!    two different stored phrases render byte-identical masked frames.
//!
//! Both shipped panels throughout, because a step nobody can reach on the 800x480 panel is
//! a step that does not exist on half the devices.

use embedded_graphics::draw_target::DrawTarget;
use embedded_graphics::geometry::{OriginDimensions, Size};
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::Pixel;

use notyas_ui::{
    PassphraseState,
    BackupState, DeleteOutcome, LockInfo, Network, Region, RegionId, ScreenId, StoreStatus,
    TouchEvent, Ui, UiRequest, UnsealOutcome, WalletInfo, WalletKind, WalletRow, WordsOutcome,
};

/// The two shipped panels.
const GEOMETRIES: [(u32, u32); 2] = [(720, 720), (800, 480)];

/// The wallet every test deletes. The name is what the C4d sheet demands typed back, so it
/// is short enough to type in a test and mixed-case enough that a case-insensitive compare
/// would pass when it must not.
const NAME: &str = "Savings";
const SLOT: u8 = 2;

// ---------------------------------------------------------------------------------------
// Framebuffer, for the masking assertions
// ---------------------------------------------------------------------------------------

struct Fb {
    w: u32,
    h: u32,
    px: Vec<Rgb565>,
    /// Pixels the screen asked for outside the panel. Counted rather than dropped: a frame
    /// that draws past the glass looks correct in every rectangle check, because no `Region`
    /// names a line of text.
    outside: usize,
}

impl Fb {
    fn render(ui: &Ui, w: u32, h: u32) -> Fb {
        let mut fb =
            Fb { w, h, px: vec![Rgb565::new(0, 0, 0); (w * h) as usize], outside: 0 };
        ui.draw(&mut fb).unwrap();
        assert_eq!(fb.outside, 0, "{w}x{h}: {} pixels drawn off the panel", fb.outside);
        fb
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
            } else {
                self.outside += 1;
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------
// Driving
// ---------------------------------------------------------------------------------------

fn wallet(slot: u8, name: &str, registrations: u8) -> WalletRow {
    WalletRow::Wallet(WalletInfo {
        slot,
        name: String::from(name),
        fingerprint: format!("dead{slot}eef"),
        path: String::from("m/84'/0'/0'"),
        script_type: String::from("native segwit"),
        kind: WalletKind::SingleSig,
        backup: BackupState::Verified(String::from("2026-08-14")),
        network: Network::Bitcoin,
        registrations,
        stored: true,
        passphrase: PassphraseState::None,
    })
}

fn find(ui: &Ui, id: RegionId) -> Option<Region> {
    ui.regions().into_iter().find(|r| r.id == id)
}

fn tap(ui: &mut Ui, id: RegionId) -> Option<UiRequest> {
    let r = find(ui, id).unwrap_or_else(|| panic!("no region {id:?} on {:?}", ui.screen()));
    let (x, y) = (r.rect.x + r.rect.w / 2, r.rect.y + r.rect.h / 2);
    ui.touch(TouchEvent::Down { x, y });
    ui.touch(TouchEvent::Up { x, y })
}

/// An unlocked device holding `rows`, on the wallet list.
fn unlocked(w: u32, h: u32, rows: Vec<WalletRow>) -> Ui {
    let mut ui = Ui::new(w, h);
    // Only the field this route depends on. Everything else on the lock screen belongs to
    // other tests, and naming it here would make this file fail for their reasons.
    ui.set_lock_info(LockInfo { status: StoreStatus::Locked, ..LockInfo::default() });
    assert!(ui.lock());
    tap(&mut ui, RegionId::LockWake);
    ui.unseal_result(UnsealOutcome::Unsealed);
    ui.set_wallets(rows);
    assert_eq!(ui.screen(), ScreenId::WalletList);
    ui
}

/// The wallet home for [`SLOT`], with `registrations` registrations against it.
fn wallet_home(w: u32, h: u32, registrations: u8) -> Ui {
    let rows = vec![
        wallet(0, "Cold", 0),
        wallet(SLOT, NAME, registrations),
        wallet(5, "Travel", 0),
    ];
    let mut ui = unlocked(w, h, rows.clone());
    tap(&mut ui, RegionId::ListRow(SLOT));
    let WalletRow::Wallet(info) = rows[1].clone() else { unreachable!() };
    ui.wallet_opened(info);
    assert_eq!(ui.screen(), ScreenId::WalletHome);
    ui
}

/// Type `NAME` into the C4d sheet, the way a finger does.
fn type_the_name(ui: &mut Ui) {
    tap(ui, RegionId::Shift);
    tap(ui, RegionId::Key('S'));
    tap(ui, RegionId::Shift);
    for c in "avings".chars() {
        tap(ui, RegionId::Key(c));
    }
}

/// The whole consent chain, up to and including the last-words step being on the panel.
fn at_the_offer(w: u32, h: u32, registrations: u8) -> Ui {
    let mut ui = wallet_home(w, h, registrations);
    tap(&mut ui, RegionId::WalletDelete);
    tap(&mut ui, RegionId::DangerConfirm);
    type_the_name(&mut ui);
    tap(&mut ui, RegionId::DangerConfirm);
    assert_eq!(ui.screen(), ScreenId::EraseWallet);
    ui
}

// ---------------------------------------------------------------------------------------
// 1. The consent chain
// ---------------------------------------------------------------------------------------

/// No tap anywhere on the route raises the erase until BOTH gates are behind it: the typed
/// name, and the last-words step. Every request the route produces is collected and the
/// erase must appear exactly once, at the end.
///
/// Against the previous build this fails at the third assertion: confirming the typed sheet
/// raised `DeleteWallet` there and then, with no step after it.
#[test]
fn the_erase_is_unreachable_without_the_typed_gate_and_the_last_words_step() {
    for (w, h) in GEOMETRIES {
        let mut ui = wallet_home(w, h, 2);
        let mut raised = Vec::new();

        // The action card opens the C4b consequence sheet. Nothing is requested.
        raised.extend(tap(&mut ui, RegionId::WalletDelete));
        assert_eq!(ui.screen(), ScreenId::WalletHome, "{w}x{h}: the sheet is modal, not a screen");

        // Confirming the consequence opens the C4d sheet. Still nothing.
        raised.extend(tap(&mut ui, RegionId::DangerConfirm));

        // The typed sheet is DISABLED until the name matches, and a tap on a disabled
        // control does nothing - not even advance the sheet.
        raised.extend(tap(&mut ui, RegionId::DangerConfirm));
        assert!(
            raised.is_empty(),
            "{w}x{h}: something was requested before the name was typed: {raised:?}"
        );

        // A near miss must not arm it either: the compare is exact and case sensitive.
        for c in "savings".chars() {
            tap(&mut ui, RegionId::Key(c));
        }
        raised.extend(tap(&mut ui, RegionId::DangerConfirm));
        assert!(raised.is_empty(), "{w}x{h}: a lower-case name armed the sheet: {raised:?}");
        for _ in 0..8 {
            tap(&mut ui, RegionId::KeyBackspace);
        }

        // The exact name arms it, and confirming lands on the last-words step - which is a
        // SCREEN, so the erase card is not at the coordinates the confirm just occupied.
        type_the_name(&mut ui);
        let confirm = find(&ui, RegionId::DangerConfirm).expect("the armed confirm").rect;
        raised.extend(tap(&mut ui, RegionId::DangerConfirm));
        assert_eq!(ui.screen(), ScreenId::EraseWallet, "{w}x{h}: the typed sheet went nowhere");
        assert!(
            raised.is_empty(),
            "{w}x{h}: the typed sheet erased the wallet by itself: {raised:?}"
        );

        // The mistap this step exists to make impossible: a second tap in the same place,
        // by somebody who thinks the first one did nothing. The point that just activated
        // the typed sheet's confirm must not now activate the erase.
        let (cx, cy) = (confirm.x + confirm.w / 2, confirm.y + confirm.h / 2);
        let under = ui.regions().into_iter().find(|r| {
            cx >= r.rect.x
                && cx < r.rect.right()
                && cy >= r.rect.y
                && cy < r.rect.bottom()
        });
        assert_ne!(
            under.map(|r| r.id),
            Some(RegionId::EraseNow),
            "{w}x{h}: a second tap on the confirm at ({cx},{cy}) would erase the wallet"
        );

        // Only now.
        raised.extend(tap(&mut ui, RegionId::EraseNow));
        assert_eq!(
            raised,
            vec![UiRequest::DeleteWallet(SLOT)],
            "{w}x{h}: the erase is raised exactly once, at the end"
        );
        assert_eq!(ui.screen(), ScreenId::Working, "{w}x{h}: the write is announced while it runs");
        assert!(ui.regions().is_empty(), "{w}x{h}: the busy frame is tappable");
    }
}

/// Backing out of the last-words step changes nothing and asks for nothing. The consent was
/// given; acting on it was not, and the way back has to exist.
///
/// It lands on the LIST rather than on the wallet home, because the wallet home is replaced
/// when this step opens - which is what drops the derivation it was holding instead of
/// parking it in the back stack behind the erase of the wallet it belongs to.
#[test]
fn the_last_words_step_can_be_left_without_erasing_anything() {
    for (w, h) in GEOMETRIES {
        let mut ui = at_the_offer(w, h, 0);
        let request = tap(&mut ui, RegionId::Back);
        assert_eq!(request, None, "{w}x{h}: Back asked for something");
        assert_eq!(ui.screen(), ScreenId::WalletList, "{w}x{h}: Back went nowhere useful");
        assert!(
            ui.wallets().iter().any(|r| matches!(r, WalletRow::Wallet(x) if x.slot == SLOT)),
            "{w}x{h}: the wallet is still listed"
        );
        assert_eq!(
            tap(&mut ui, RegionId::ListRow(SLOT)),
            Some(UiRequest::OpenWallet(SLOT)),
            "{w}x{h}: and can be opened again"
        );
    }
}

// ---------------------------------------------------------------------------------------
// 2. Every ending reaches the user
// ---------------------------------------------------------------------------------------

/// A refused delete lands on the wallet list, with the wallet still on it AND the embedder's
/// sentence drawn. This is the owner's bug stated as a property: the previous build answered
/// this case with a list that looked exactly like the one before the tap.
///
/// Against that build there is no `Ui::wallet_deleted` at all, so this does not compile -
/// which is how it fails first.
#[test]
fn a_refused_delete_says_so_on_the_list_that_still_holds_the_wallet() {
    let reason = "\"Savings\" was NOT deleted: the wallet slot would not erase. \
                  Nothing was changed.";
    for (w, h) in GEOMETRIES {
        for outcome in [
            DeleteOutcome::Refused(String::from(reason)),
            DeleteOutcome::Damaged(String::from(reason)),
        ] {
            let mut ui = at_the_offer(w, h, 1);
            tap(&mut ui, RegionId::EraseNow);

            // The embedder answers, then installs the list it read back - which still has
            // the wallet in it, because nothing was erased.
            let rows = vec![wallet(0, "Cold", 0), wallet(SLOT, NAME, 1), wallet(5, "Travel", 0)];
            ui.wallet_deleted(outcome.clone());
            ui.set_wallets(rows);

            assert_eq!(ui.screen(), ScreenId::WalletList, "{w}x{h}: {outcome:?} went nowhere");
            let before = Fb::render(&ui, w, h);

            // The same list with no band is a different frame. That difference IS the fix:
            // it is the pixels the previous build did not have.
            let mut plain = unlocked(w, h, ui.wallets().to_vec());
            let after = Fb::render(&plain, w, h);
            assert_ne!(
                before.px, after.px,
                "{w}x{h}: {outcome:?} rendered the same list as one with nothing to say"
            );
            // ... and the wallet really is still there and still openable.
            assert_eq!(
                tap(&mut plain, RegionId::ListRow(SLOT)),
                Some(UiRequest::OpenWallet(SLOT)),
                "{w}x{h}: the surviving wallet is still a live row"
            );
        }
    }
}

/// A completed delete lands on the list with the wallet gone from it and a band that names
/// what happened. S-47 ratifies both halves.
#[test]
fn a_completed_delete_leaves_a_list_without_the_wallet_and_a_band_naming_it() {
    for (w, h) in GEOMETRIES {
        let mut ui = at_the_offer(w, h, 2);
        tap(&mut ui, RegionId::EraseNow);
        ui.wallet_deleted(DeleteOutcome::Gone { registrations: 2 });
        ui.set_wallets(vec![wallet(0, "Cold", 0), wallet(5, "Travel", 0)]);

        assert_eq!(ui.screen(), ScreenId::WalletList);
        assert!(
            !ui.wallets().iter().any(|r| matches!(r, WalletRow::Wallet(x) if x.slot == SLOT)),
            "{w}x{h}: the deleted wallet is still on the list"
        );
        assert!(find(&ui, RegionId::ListRow(SLOT)).is_none(), "{w}x{h}: its row is still tappable");
        // The band is the difference between "gone" and "I am not sure I am reading this
        // right", so it has to be pixels and not an assumption.
        let banded = Fb::render(&ui, w, h);
        let plain = Fb::render(&unlocked(w, h, ui.wallets().to_vec()), w, h);
        assert_ne!(banded.px, plain.px, "{w}x{h}: a completed delete drew no status band");
    }
}

/// The last wallet on the device deletes to the empty state and not to a blank panel.
#[test]
fn deleting_the_last_wallet_lands_on_the_empty_state() {
    for (w, h) in GEOMETRIES {
        let rows = vec![wallet(SLOT, NAME, 0)];
        let mut ui = unlocked(w, h, rows.clone());
        tap(&mut ui, RegionId::ListRow(SLOT));
        let WalletRow::Wallet(info) = rows[0].clone() else { unreachable!() };
        ui.wallet_opened(info);
        tap(&mut ui, RegionId::WalletDelete);
        tap(&mut ui, RegionId::DangerConfirm);
        type_the_name(&mut ui);
        tap(&mut ui, RegionId::DangerConfirm);
        tap(&mut ui, RegionId::EraseNow);
        ui.wallet_deleted(DeleteOutcome::Gone { registrations: 0 });
        ui.set_wallets(Vec::new());

        assert_eq!(ui.screen(), ScreenId::WalletList, "{w}x{h}: an empty device is still S-10");
        assert!(ui.wallets().is_empty());
        assert!(
            find(&ui, RegionId::WalletNew).is_some(),
            "{w}x{h}: the empty list must still offer a new wallet"
        );
    }
}

// ---------------------------------------------------------------------------------------
// 3. The words, and the protection they keep
// ---------------------------------------------------------------------------------------

/// The offer raises the read, and the answer puts the words on S-13 - masked, behind the
/// reveal gate, with the choice still open behind it. Reading the words is not consent.
#[test]
fn the_offer_shows_the_words_and_leaves_the_choice_open() {
    for (w, h) in GEOMETRIES {
        let mut ui = at_the_offer(w, h, 0);
        assert_eq!(
            tap(&mut ui, RegionId::EraseShowWords),
            Some(UiRequest::RecoveryWords(SLOT)),
            "{w}x{h}: the offer must ask the embedder for the record"
        );
        assert_eq!(ui.screen(), ScreenId::Working, "{w}x{h}: the read has its own busy frame");

        ui.recovery_words(WordsOutcome::words(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon about",
        ));
        assert_eq!(ui.screen(), ScreenId::MnemonicDisplay, "{w}x{h}: the words did not appear");
        // Masked, and the way out of that is S-13's modal and nothing else.
        assert!(find(&ui, RegionId::Reveal).is_some(), "{w}x{h}: no reveal gate");
        tap(&mut ui, RegionId::Reveal);
        assert_eq!(ui.regions().len(), 2, "{w}x{h}: the reveal modal is not modal");
        tap(&mut ui, RegionId::ModalConfirm);
        assert!(find(&ui, RegionId::Reveal).is_none(), "{w}x{h}: revealed, so no gate is offered");

        // Leaving the words returns to the offer with BOTH answers still there. Nothing has
        // been requested by reading them.
        assert_eq!(tap(&mut ui, RegionId::Next), None, "{w}x{h}: leaving the words asked for work");
        assert_eq!(ui.screen(), ScreenId::EraseWallet);
        assert!(find(&ui, RegionId::EraseShowWords).is_some());
        assert!(find(&ui, RegionId::EraseNow).is_some());
    }
}

/// The masking law, on the surface that did not exist before: two DIFFERENT stored phrases
/// must produce byte-identical masked frames, so the pixels carry neither the letters nor
/// the lengths. This is S-13's own pixel test, re-run through the delete route.
#[test]
fn two_different_stored_phrases_render_identical_masked_frames() {
    const A: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                     abandon abandon abandon about";
    const B: &str = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";
    for (w, h) in GEOMETRIES {
        let mut frames = Vec::new();
        for phrase in [A, B] {
            let mut ui = at_the_offer(w, h, 0);
            tap(&mut ui, RegionId::EraseShowWords);
            ui.recovery_words(WordsOutcome::words(phrase));
            assert_eq!(ui.screen(), ScreenId::MnemonicDisplay);
            frames.push(Fb::render(&ui, w, h).px);
        }
        assert_eq!(
            frames[0], frames[1],
            "{w}x{h}: the masked frame differs between two stored phrases - it is carrying \
             the words"
        );

        // ... and revealing actually changes the frame, so the test above is not passing
        // because nothing is drawn.
        let mut ui = at_the_offer(w, h, 0);
        tap(&mut ui, RegionId::EraseShowWords);
        ui.recovery_words(WordsOutcome::words(A));
        let masked = Fb::render(&ui, w, h);
        tap(&mut ui, RegionId::Reveal);
        tap(&mut ui, RegionId::ModalConfirm);
        let revealed = Fb::render(&ui, w, h);
        assert_ne!(masked.px, revealed.px, "{w}x{h}: revealing changed nothing");
    }
}

/// A record that will not read leaves the user on the offer with a sentence, not on a
/// screen that did nothing and not bounced out of the flow. Both answers stay available:
/// failing to READ the words changes nothing about the wallet.
#[test]
fn words_that_cannot_be_read_are_stated_on_the_offer() {
    for (w, h) in GEOMETRIES {
        let mut ui = at_the_offer(w, h, 0);
        let before = Fb::render(&ui, w, h);
        tap(&mut ui, RegionId::EraseShowWords);
        ui.recovery_words(WordsOutcome::Refused(String::from(
            "Wallet slot 2 did not open: the record did not come back intact.",
        )));
        assert_eq!(ui.screen(), ScreenId::EraseWallet, "{w}x{h}: a refusal must not move the user");
        let after = Fb::render(&ui, w, h);
        assert_ne!(before.px, after.px, "{w}x{h}: the refusal drew nothing");
        assert!(find(&ui, RegionId::EraseShowWords).is_some(), "{w}x{h}: the offer is still open");
        assert!(find(&ui, RegionId::EraseNow).is_some(), "{w}x{h}: the erase is still offered");
    }
}

/// The locked device wipes what the delete route put on the stack. The words are pushed
/// onto the navigation stack, and `Ui::lock` clears it - which is what takes a revealed
/// screen down with the auto-lock.
#[test]
fn locking_takes_the_revealed_words_with_it() {
    for (w, h) in GEOMETRIES {
        let mut ui = at_the_offer(w, h, 0);
        tap(&mut ui, RegionId::EraseShowWords);
        ui.recovery_words(WordsOutcome::words("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"));
        tap(&mut ui, RegionId::Reveal);
        tap(&mut ui, RegionId::ModalConfirm);
        assert_eq!(ui.screen(), ScreenId::MnemonicDisplay);
        ui.lock();
        assert_eq!(ui.screen(), ScreenId::Lock, "{w}x{h}: the lock did not take the words down");
        assert!(ui.wallets().is_empty(), "{w}x{h}: the list survived the lock");
    }
}

// ---------------------------------------------------------------------------------------
// 4. The offer itself
// ---------------------------------------------------------------------------------------

/// Every frame the delete route draws stays on the panel, at both geometries and in each of
/// the states this screen has - including the busy frames, which no region check can see at
/// all because they emit none.
///
/// `Fb::render` is what asserts it; this walks the states so that it is asked.
#[test]
fn nothing_on_the_route_draws_off_the_panel() {
    for (w, h) in GEOMETRIES {
        let mut ui = at_the_offer(w, h, 4);
        Fb::render(&ui, w, h);

        // The read, its busy frame, the masked words, the reveal modal, the revealed words.
        tap(&mut ui, RegionId::EraseShowWords);
        Fb::render(&ui, w, h);
        ui.recovery_words(WordsOutcome::words(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon              abandon abandon about",
        ));
        Fb::render(&ui, w, h);
        tap(&mut ui, RegionId::Reveal);
        Fb::render(&ui, w, h);
        tap(&mut ui, RegionId::ModalConfirm);
        Fb::render(&ui, w, h);
        tap(&mut ui, RegionId::Next);

        // The refusal frame, where the failure sentence takes the Q22 line's place.
        tap(&mut ui, RegionId::EraseShowWords);
        ui.recovery_words(WordsOutcome::Refused(String::from(
            "Wallet slot 2 did not open: the record did not come back from flash intact, so              this device cannot show the words it was sealed with.",
        )));
        Fb::render(&ui, w, h);

        // The erase's own busy frame, and the two endings.
        tap(&mut ui, RegionId::EraseNow);
        Fb::render(&ui, w, h);
        ui.wallet_deleted(DeleteOutcome::Gone { registrations: 4 });
        ui.set_wallets(vec![wallet(0, "Cold", 0)]);
        Fb::render(&ui, w, h);

        let mut ui = at_the_offer(w, h, 0);
        tap(&mut ui, RegionId::EraseNow);
        ui.wallet_deleted(DeleteOutcome::Damaged(String::from(
            "\"Savings\" was NOT deleted: the wallet slot would not erase. Its 4 \
             multisig registrations were erased first and are gone.",
        )));
        ui.set_wallets(vec![wallet(0, "Cold", 0), wallet(SLOT, NAME, 0)]);
        Fb::render(&ui, w, h);
    }
}

/// Neither answer is cheaper than the other: both are one tap, on targets of the same size,
/// in the same row. The balance is asserted through the PUBLIC region list, which is what a
/// finger actually meets - a layout unit test can be right about rectangles the hit-tester
/// never emits.
#[test]
fn the_two_answers_cost_the_same_gesture() {
    for (w, h) in GEOMETRIES {
        let ui = at_the_offer(w, h, 3);
        let show = find(&ui, RegionId::EraseShowWords).expect("the words card").rect;
        let erase = find(&ui, RegionId::EraseNow).expect("the erase card").rect;
        assert_eq!((show.w, show.h), (erase.w, erase.h), "{w}x{h}: the answers differ in size");
        assert_eq!(show.y, erase.y, "{w}x{h}: the answers are not in one row");
        assert!(show.h >= 60 && show.w >= 60, "{w}x{h}: an answer is under the touch floor");
        // Three regions and no more: the two answers and the way back. Nothing on this
        // screen can be tapped by accident into an erase.
        let ids: Vec<RegionId> = ui.regions().into_iter().map(|r| r.id).collect();
        assert_eq!(ids.len(), 3, "{w}x{h}: unexpected regions on the offer: {ids:?}");
        assert!(ids.contains(&RegionId::Back));
    }
}
