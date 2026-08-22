// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The render set, as data.
//!
//! It used to be a script: a single `main` that walked the UI tapping controls and wrote
//! a PNG wherever the author thought of one. A script has one structural weakness and it
//! is fatal for a regression gate - a state nobody thought to script does not exist. That
//! is how the empty lock word went unrendered for a release, and how a quarter of the old
//! shots were 800x480 afterthoughts appended by hand.
//!
//! Here a frame is a [`Frame`]: a name, the state variant it claims to be, the screen it
//! must land on, and a recipe. The recipe takes a [`Ui`] that is ALREADY constructed at
//! some panel geometry and never learns which, so a frame is structurally incapable of
//! existing at one geometry only - the runner builds it once per entry of
//! [`notyas_ui::layout::PANELS`]. [`Doc`] decides only which frames additionally write a
//! picture into docs/screenshots/ui, which is why the historical filenames there survive
//! a catalogue that no longer has a shape anything like the tour that made them.
//!
//! Coverage is an obligation rather than a habit: [`required_variants`] is an exhaustive
//! match over [`ScreenId`], so a nineteenth screen fails to compile until someone names
//! the states it has to be photographed in, and the gate then fails until frames for them
//! exist on every panel.

use notyas_ui::{
    Artifact, CardListing, CardOutcome, FormatOffer, FormatOutcome, FormatRefusal, ImportOutcome,
    LockInfo, PassphraseRefusal, PassphraseState, PsbtOutcome, QrData, RefusalCode, RegionId,
    RegistrationOutcome, ScreenId, SignOutcome, StorageOutcome, StoreStatus, Ui, UiRequest,
    UnsealOutcome, WalletRow, WordsOutcome, WriteOutcome,
};

use crate::drive::{
    answer_quiz, device_words, hold, last_list_row, locked, page_forward, page_to, pin_entry,
    scroll_to, store_in, tap,
    type_dice, type_keys, type_shifted, unlocked, unlocked_with_dummy_wallets,
};
use crate::fixtures::{
    dummy_empty_card, dummy_flash_scan, dummy_format_target, dummy_lock_info,
    dummy_long_psbt_card, dummy_multisig_card, dummy_psbt_card, dummy_refusal,
    dummy_registration_review, dummy_registrations, dummy_report, dummy_saved_registration, dummy_signed,
    dummy_bluewallet_review, dummy_single_psbt_card, dummy_tx_review, dummy_verify_info,
    dummy_wallets, ReviewShape,
    DUMMY_DEVICE_NAME,
    ELEVEN_SIXES_WORDS, SIXES, SIXES_PHRASE,
};

/// The panel the portrait docs pictures are taken on (Waveshare 4B).
pub const DOC_PORTRAIT: (u32, u32) = (720, 720);
/// The panel the landscape docs pictures are taken on (Elecrow 5inch).
pub const DOC_LANDSCAPE: (u32, u32) = (800, 480);

/// Which frames also become a committed picture, and under which filename.
///
/// The names are given per panel rather than derived from the frame name plus a suffix,
/// because the committed set is historical: `45-wallet-list` and
/// `70-wallet-list-800x480` are the same frame on two panels and always were. Deriving
/// them would have meant renaming 65 files to satisfy a convention no reader benefits
/// from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Doc {
    /// Gated, but not pictured. The default: the matrix is 5x the docs tier, and a
    /// committed PNG per frame would be about 10 MB of binary churn per layout change.
    None,
    Portrait(&'static str),
    Landscape(&'static str),
    Both(&'static str, &'static str),
}

impl Doc {
    /// The docs filename stem for this frame on `panel`, if it has one.
    pub fn name_for(self, panel: (u32, u32)) -> Option<&'static str> {
        match self {
            Doc::None => None,
            Doc::Portrait(p) => (panel == DOC_PORTRAIT).then_some(p),
            Doc::Landscape(l) => (panel == DOC_LANDSCAPE).then_some(l),
            Doc::Both(p, l) => match panel {
                _ if panel == DOC_PORTRAIT => Some(p),
                _ if panel == DOC_LANDSCAPE => Some(l),
                _ => None,
            },
        }
    }
}

/// One frame of the render set.
pub struct Frame {
    /// Unique id, `screen-slug/what-state`. The key of the golden manifest and the
    /// argument to `uisim render`.
    pub name: &'static str,
    /// The state variant this frame claims to cover, from [`required_variants`]. Two
    /// frames may claim the same variant (a state worth seeing twice); none may claim one
    /// the list does not name.
    pub variant: &'static str,
    /// Where the recipe must land. Asserted after every build, so a flow that stops
    /// reaching its screen fails the gate instead of quietly photographing another one.
    pub screen: ScreenId,
    pub doc: Doc,
    /// The recipe. Receives a `Ui` already built at the panel under test.
    pub build: fn(&mut Ui),
}

// ---------------------------------------------------------------------------------------
// Shared route prefixes
// ---------------------------------------------------------------------------------------
//
// Each is the finger's route to a place several frames start from. Named rather than
// repeated so that a control moving costs one edit, and so that the route a frame took is
// readable in the recipe instead of being twelve taps deep.

/// A device the embedder has told about itself, on Home.
fn home(ui: &mut Ui) {
    ui.set_verify_info(dummy_verify_info());
}

/// Home -> dice entry, with the 64 sixes typed.
fn dice_typed(ui: &mut Ui) {
    home(ui);
    tap(ui, RegionId::HomeNewSeed);
    type_dice(ui, SIXES);
}

/// ...-> the mnemonic screen, revealed through the two-step confirm.
fn mnemonic_revealed(ui: &mut Ui) {
    dice_typed(ui);
    tap(ui, RegionId::DiceDone);
    tap(ui, RegionId::Reveal);
    tap(ui, RegionId::ModalConfirm);
}

/// ...-> the passphrase screen with the BIP39 test-vector passphrase in both fields.
fn passphrase_typed(ui: &mut Ui) {
    mnemonic_revealed(ui);
    tap(ui, RegionId::Next);
    tap(ui, RegionId::PassToggle);
    tap(ui, RegionId::Shift); // TREZOR is uppercase
    type_keys(ui, "TREZOR");
    tap(ui, RegionId::PassConfirm);
    type_keys(ui, "TREZOR");
}

/// ...-> the derivation actually run, landing on the mandatory backup check.
fn derived(ui: &mut Ui) {
    passphrase_typed(ui);
    tap(ui, RegionId::KeyDone);
    assert_eq!(ui.screen(), ScreenId::Deriving, "Done must park on the interstitial");
    assert!(ui.tick(0).dirty, "tick must run the pending derivation");
}

/// ...-> past the backup check, on the save-or-keep-nothing fork.
fn at_fork(ui: &mut Ui) {
    derived(ui);
    answer_quiz(ui);
}

/// ...-> the same fork on a device that already has a PIN and an open session.
///
/// The naming screen is reachable only this way. On a device with no PIN the Save leg
/// stops at S-06/S-07 first, so a recipe that wants S-20 has to state the store it is
/// saving to rather than inherit whatever `LockInfo::default` happens to be.
fn at_fork_provisioned(ui: &mut Ui) {
    ui.set_lock_info(LockInfo { status: StoreStatus::Unlocked, ..dummy_lock_info() });
    at_fork(ui);
}

/// ...-> S-06 step 1, on the store state this screen exists to format: a device key
/// present, nothing sealed, no PIN. `pin` and `attempts_left` are `None` because a blank
/// store has no PIN to have a shape or an attempt budget.
fn at_new_pin(ui: &mut Ui) {
    ui.set_lock_info(LockInfo {
        status: StoreStatus::Blank,
        attempts_left: None,
        pin: None,
        ..dummy_lock_info()
    });
    at_fork(ui);
    tap(ui, RegionId::SaveToDevice);
}

/// ...-> S-07 step 2, with a four-digit first entry behind it. The digits are pad
/// POSITIONS, so this types 1234.
fn at_new_pin_confirm(ui: &mut Ui) {
    at_new_pin(ui);
    for i in 0..4 {
        tap(ui, RegionId::PinKey(i));
    }
    tap(ui, RegionId::PinNext);
}

/// ...-> a session wallet home, the stateless half of the fork.
fn session_wallet(ui: &mut Ui) {
    at_fork(ui);
    tap(ui, RegionId::UseOnce);
}

/// A stored wallet opened from the post-PIN list.
/// S-47b, reached the way a user reaches it: the wallet home, the C4b consequence, the
/// C4d sheet with the wallet's own name typed back into it, and the answer to that.
///
/// Written out rather than shortcut into the state, because the ROUTE is half of what this
/// screen is for. A frame that constructed the state directly would still pass the day
/// somebody made the typed sheet skippable.
fn erase_offer(ui: &mut Ui) {
    stored_wallet(ui);
    scroll_to(ui, RegionId::WalletDelete);
            tap(ui, RegionId::WalletDelete);
    tap(ui, RegionId::DangerConfirm);
    // "DUMMY savings", exactly, case included - the sheet accepts nothing else.
    type_shifted(ui, "DUMMY");
    tap(ui, RegionId::Shift);
    type_keys(ui, " savings");
    tap(ui, RegionId::DangerConfirm);
}

fn stored_wallet(ui: &mut Ui) {
    unlocked_with_dummy_wallets(ui);
    let Some(UiRequest::OpenWallet(slot)) = tap(ui, RegionId::ListRow(0)) else {
        panic!("a wallet row must ask the embedder to unseal it");
    };
    let WalletRow::Wallet(info) = dummy_wallets()[slot as usize].clone() else {
        panic!("slot {slot} is not a readable wallet")
    };
    ui.wallet_opened(info);
}

/// A stored wallet, unsealed WITH its derivation, in the passphrase state the card is to
/// render.
///
/// The state is installed rather than derived from anything the simulator does, because it
/// is a fact about a sealed record and this harness has no flash: what is under test is
/// that the identity row and the action cards say the right thing about each of the three.
fn wallet_home_with(ui: &mut Ui, passphrase: PassphraseState) {
    unlocked_with_dummy_wallets(ui);
    let Some(UiRequest::OpenWallet(slot)) = tap(ui, RegionId::ListRow(0)) else {
        panic!("a wallet row must ask the embedder to unseal it");
    };
    let WalletRow::Wallet(mut info) = dummy_wallets()[slot as usize].clone() else {
        panic!("slot {slot} is not a readable wallet")
    };
    info.passphrase = passphrase;
    ui.wallet_opened_with_keys(info, dummy_report());
}

/// A tap on a wallet whose record needs a passphrase this device is not holding: the
/// embedder answers with the prompt rather than with a failure band.
fn passphrase_prompt(ui: &mut Ui) {
    unlocked_with_dummy_wallets(ui);
    let Some(UiRequest::OpenWallet(slot)) = tap(ui, RegionId::ListRow(0)) else {
        panic!("a wallet row must ask the embedder to unseal it");
    };
    ui.wallet_needs_passphrase(slot, String::from("dummy"));
}

/// ...-> a passphrase typed and handed over, and the answer that it opens a different
/// wallet. The two fingerprints are the published test vector's: the same words derive
/// b4e3f5ed under the passphrase TREZOR and 73c5da0a under none.
fn passphrase_refused(ui: &mut Ui) {
    passphrase_prompt(ui);
    type_keys(ui, "hunter");
    let Some(UiRequest::UnlockWallet { .. }) = tap(ui, RegionId::KeyDone) else {
        panic!("Done must hand the passphrase to the embedder");
    };
    ui.passphrase_refused(PassphraseRefusal {
        expected: String::from("b4e3f5ed"),
        derived: String::from("9f8e7d6c"),
    });
}

/// The multisig wallet's registry (S-41), with `held` installed and the wallet record
/// claiming `claims` registrations.
///
/// The two counts are separate parameters because the screen's most important edge state is
/// the one where they DISAGREE: a wallet that has registrations this device could not prove
/// must say so rather than render an empty registry.
fn multisig_registry(ui: &mut Ui, claims: u8, held: Vec<notyas_ui::RegistrationInfo>) {
    unlocked_with_dummy_wallets(ui);
    tap(ui, RegionId::ListRow(1));
    let WalletRow::Wallet(mut info) = dummy_wallets()[1].clone() else {
        panic!("slot 1 is the multisig wallet")
    };
    info.registrations = claims;
    // Both lists, because S-41 reads the CLAIM off the wallet row and the PROOF off the
    // registry - which is exactly the pair it compares.
    let mut rows = dummy_wallets();
    rows[1] = WalletRow::Wallet(info.clone());
    ui.set_wallets(rows);
    ui.wallet_opened(info);
    ui.set_registrations(held);
    scroll_to(ui, RegionId::ActMultisig);
            tap(ui, RegionId::ActMultisig);
}

/// A STORED wallet the embedder unsealed AND handed its derivation to.
///
/// The only state in which S-21 offers Sign, and the reason it is a route of its own: the
/// wallet home gates the card on holding a `Report`, because signing runs on a seed the
/// embedder only ever has after unsealing a slot. Everything below S-27 starts here.
fn wallet_home_signable(ui: &mut Ui) {
    unlocked_with_dummy_wallets(ui);
    let Some(UiRequest::OpenWallet(slot)) = tap(ui, RegionId::ListRow(0)) else {
        panic!("a wallet row must ask the embedder to unseal it");
    };
    let WalletRow::Wallet(info) = dummy_wallets()[slot as usize].clone() else {
        panic!("slot {slot} is not a readable wallet")
    };
    ui.wallet_opened_with_keys(info, dummy_report());
}

/// ...-> S-27 with the card read still in flight. The C3 frame, and the state every other
/// sign-source frame is an answer to.
fn sign_reading(ui: &mut Ui) {
    wallet_home_signable(ui);
    assert!(
        matches!(tap(ui, RegionId::ActSign), Some(UiRequest::ListCard { .. })),
        "S-27 must arrive with the card read that ends its Busy frame"
    );
}

/// ...-> S-27, answered.
fn sign_source(ui: &mut Ui, outcome: CardOutcome) {
    sign_reading(ui);
    ui.card_result(outcome);
}

/// ...-> S-28, over a listing with more than one transaction in it.
fn picker(ui: &mut Ui, listing: CardListing) {
    sign_reading(ui);
    ui.card_result(CardOutcome::Listed(listing));
}

/// ...-> a file chosen, with the read and the ten checks in flight.
///
/// Row 1, because row 0 is the directory: the card layer sorts directories first, and the
/// fixture is in the order a real listing would arrive in.
fn loading(ui: &mut Ui) {
    picker(ui, dummy_psbt_card());
    assert!(
        matches!(tap(ui, RegionId::ListRow(1)), Some(UiRequest::LoadPsbt { .. })),
        "a file row must ask the embedder to read and check it"
    );
}

/// ...-> a review of `shape`, paged to page `page` the way a finger reaches it.
///
/// Ten pages, always: three inputs and four outputs plus the overview, the fee and the
/// warnings. The indices are therefore the same in all three shapes, which is what lets a
/// recipe say "page 5" and mean the change output in every one of them.
fn review_at(ui: &mut Ui, shape: ReviewShape, page: usize) {
    loading(ui);
    ui.psbt_result(PsbtOutcome::Reviewed(dummy_tx_review(shape)));
    page_forward(ui, page);
}

/// ...-> the single-input BlueWallet review, paged to `page`.
///
/// Six pages rather than ten, because this fixture has one input and two outputs. It is a
/// separate recipe for that reason: the input count is the fact the file is about.
fn bluewallet_review_at(ui: &mut Ui, page: usize) {
    loading(ui);
    ui.psbt_result(PsbtOutcome::Reviewed(dummy_bluewallet_review()));
    page_forward(ui, page);
}

/// ...-> the hold filled and the signature in flight (S-37).
fn signing(ui: &mut Ui) {
    review_at(ui, ReviewShape::Proven, 9);
    assert!(
        matches!(hold(ui, RegionId::HoldConfirm), Some(UiRequest::SignTx)),
        "a filled hold is what asks for a signature"
    );
}

/// ...-> S-38, holding a signed transaction.
fn delivering(ui: &mut Ui, complete: bool) {
    signing(ui);
    ui.sign_result(SignOutcome::Signed(dummy_signed(complete)));
}

/// ...-> S-38 after a write that ended in `outcome`.
fn delivered(ui: &mut Ui, outcome: WriteOutcome) {
    delivering(ui, true);
    assert!(
        matches!(tap(ui, RegionId::DeliverSd), Some(UiRequest::WriteSigned { overwrite: false })),
        "Write to card is what asks for the write"
    );
    ui.write_result(outcome);
}

/// ...-> S-29, from a file the pipeline refused.
fn refused(ui: &mut Ui, code: RefusalCode) {
    loading(ui);
    ui.psbt_result(PsbtOutcome::Refused(dummy_refusal(code, false)));
}

/// ...-> the card read and the file chosen, with the engine's answer installed.
fn multisig_reviewing(ui: &mut Ui, ours: u8) {
    multisig_registry(ui, 0, Vec::new());
    tap(ui, RegionId::MsImport);
    ui.card_result(CardOutcome::Listed(dummy_multisig_card()));
    tap(ui, RegionId::ListRow(0));
    ui.import_result(ImportOutcome::Pending(dummy_registration_review(ours)));
}

/// ...-> the registration approved and stored, on its detail screen.
fn multisig_saved(ui: &mut Ui) {
    multisig_reviewing(ui, 1);
    page_to(ui, RegionId::MsApprove);
    tap(ui, RegionId::MsApprove);
    ui.set_registrations(vec![dummy_saved_registration()]);
    ui.registration_result(RegistrationOutcome::Saved(dummy_saved_registration()));
}

/// The schemes screen on its BIP84 tab, the one scheme with both a SLIP-132 rendering
/// and address rows.
fn schemes_bip84(ui: &mut Ui) {
    session_wallet(ui);
    tap(ui, RegionId::ActExport);
    tap(ui, RegionId::Tab(2));
}

/// The Verify screen with a session open, which is the state that carries every row.
fn verify_unlocked(ui: &mut Ui) {
    ui.set_verify_info(dummy_verify_info());
    ui.set_lock_info(LockInfo { status: StoreStatus::Unlocked, ..dummy_lock_info() });
    tap(ui, RegionId::HomeVerifyDevice);
}

/// The wipe-policy editor, reached from a session.
fn wipe_policy(ui: &mut Ui) {
    settings(ui);
    // Scrolled to, not indexed blind: the 800x480 list shows two rows at a time and the
    // policy row is the third since the device name took the top of the list.
    scroll_to(ui, RegionId::SetRow(2));
    tap(ui, RegionId::SetRow(2));
}

/// S-44 itself, reached from a session.
fn settings(ui: &mut Ui) {
    unlocked_with_dummy_wallets(ui);
    tap(ui, RegionId::OpenSettings);
}

/// Settings -> S-44a, opened on the name the device already has.
///
/// Reached by index because the device name is the FIRST row of the list and therefore
/// above the fold on every panel - the only row in this table of which that is true.
fn device_name_screen(ui: &mut Ui) {
    settings(ui);
    tap(ui, RegionId::SetRow(0));
}

/// Settings -> S-49, with the probe answered by `offer`.
///
/// The row is reached by SCROLLING to it rather than by index arithmetic, because on the
/// 800x480 panel it is below the fold: a recipe that could not scroll to it would be
/// photographing a screen no finger on that panel can open.
fn format_card(ui: &mut Ui, offer: FormatOffer) {
    settings(ui);
    let row = last_list_row(ui);
    let asked = tap(ui, row);
    assert!(
        matches!(asked, Some(UiRequest::ProbeCardFormat)),
        "S-49 must open with its probe in flight, never on an unasked card"
    );
    ui.format_offer(offer);
}

/// ...on the card the feature exists for, with the C4b consequence sheet open.
fn format_consequence(ui: &mut Ui) {
    format_card(ui, FormatOffer::Ready(dummy_format_target()));
    tap(ui, RegionId::CardFormat);
}

/// ...and on the C4d sheet, with the card's own capacity typed back in full.
///
/// The typing is the whole point of the frame: "32GB" needs the digit page and then a
/// shifted letter page, which is friction, and the friction is the feature. Nobody types
/// this by accident.
fn format_typed(ui: &mut Ui) {
    format_consequence(ui);
    tap(ui, RegionId::DangerConfirm);
    tap(ui, RegionId::PageDigits);
    type_keys(ui, "32");
    tap(ui, RegionId::PageLetters);
    type_shifted(ui, "GB");
}

/// ...consent complete and the write in flight, unanswered: the C3 frame during which the
/// user's own data is being overwritten.
fn format_writing(ui: &mut Ui) {
    format_typed(ui);
    let asked = tap(ui, RegionId::DangerConfirm);
    assert!(
        matches!(asked, Some(UiRequest::FormatCard { .. })),
        "the typed word is the only thing that raises the write"
    );
}

/// The restore screen with eleven of the twelve words typed, which is where it stops
/// completing prefixes and starts finishing the phrase.
fn eleven_words(ui: &mut Ui) {
    tap(ui, RegionId::HomeVerifySeed);
    type_keys(ui, ELEVEN_SIXES_WORDS);
    tap(ui, RegionId::Space);
}

// ---------------------------------------------------------------------------------------
// The catalogue
// ---------------------------------------------------------------------------------------

/// Every frame, in the order the manifest lists them.
pub const CATALOG: &[Frame] = &[
    // --- S-01 Home ---------------------------------------------------------------------
    Frame {
        name: "home/fresh",
        variant: "fresh",
        screen: ScreenId::Home,
        doc: Doc::Portrait("01-home"),
        build: home,
    },
    Frame {
        name: "home/store-blank",
        variant: "store-blank",
        screen: ScreenId::Home,
        doc: Doc::None,
        // A device key is burned but the ledger was never formatted: still stateless,
        // still no anti-phishing words, and the lock screen is unreachable (R20). The
        // state a device is in between provisioning and its first PIN.
        build: |ui| store_in(ui, StoreStatus::Blank),
    },
    Frame {
        name: "home/store-unreadable",
        variant: "store-unreadable",
        screen: ScreenId::Home,
        doc: Doc::None,
        // Both slots failed their AEAD tag. Typing a PIN into this device cannot succeed
        // (R-32), so it says so on Home rather than offering a lock screen that leads
        // nowhere.
        build: |ui| store_in(ui, StoreStatus::Unreadable),
    },
    // --- S-02 Dice entry ---------------------------------------------------------------
    Frame {
        name: "dice/empty",
        variant: "empty",
        screen: ScreenId::DiceEntry,
        doc: Doc::None,
        build: |ui| {
            home(ui);
            tap(ui, RegionId::HomeNewSeed);
        },
    },
    Frame {
        name: "dice/typed",
        variant: "typed",
        screen: ScreenId::DiceEntry,
        doc: Doc::Portrait("02-dice-entry"),
        build: dice_typed,
    },
    Frame {
        name: "dice/word-count-mode",
        variant: "word-count-mode",
        screen: ScreenId::DiceEntry,
        doc: Doc::None,
        // Fixed word count rather than RAW: the mnemonic becomes a hash of the digit
        // string, so the strength meter reports EFFECTIVE bits well below the phrase's
        // ENT. The one arrangement of this screen where the two numbers disagree.
        build: |ui| {
            home(ui);
            tap(ui, RegionId::HomeNewSeed);
            tap(ui, RegionId::Mode(1));
            type_dice(ui, "123456");
        },
    },
    // --- S-05 Mnemonic -----------------------------------------------------------------
    Frame {
        name: "mnemonic/masked",
        variant: "masked",
        screen: ScreenId::MnemonicDisplay,
        doc: Doc::Portrait("03-mnemonic-masked"),
        build: |ui| {
            dice_typed(ui);
            tap(ui, RegionId::DiceDone);
        },
    },
    Frame {
        name: "mnemonic/reveal-confirm",
        variant: "reveal-confirm",
        screen: ScreenId::MnemonicDisplay,
        doc: Doc::Portrait("04-reveal-confirm"),
        build: |ui| {
            dice_typed(ui);
            tap(ui, RegionId::DiceDone);
            tap(ui, RegionId::Reveal);
        },
    },
    Frame {
        name: "mnemonic/revealed",
        variant: "revealed",
        screen: ScreenId::MnemonicDisplay,
        doc: Doc::Portrait("05-mnemonic-revealed"),
        build: mnemonic_revealed,
    },
    // --- S-06 Passphrase ---------------------------------------------------------------
    Frame {
        name: "passphrase/off",
        variant: "off",
        screen: ScreenId::PassphraseEntry,
        doc: Doc::None,
        // The default: opted out, no fields, and the Q22 warning still on the screen.
        build: |ui| {
            mnemonic_revealed(ui);
            tap(ui, RegionId::Next);
        },
    },
    Frame {
        name: "passphrase/typed-masked",
        variant: "typed-masked",
        screen: ScreenId::PassphraseEntry,
        doc: Doc::Portrait("06-passphrase"),
        build: passphrase_typed,
    },
    Frame {
        name: "passphrase/typed-shown",
        variant: "typed-shown",
        screen: ScreenId::PassphraseEntry,
        doc: Doc::Portrait("13-passphrase-shown"),
        build: |ui| {
            passphrase_typed(ui);
            tap(ui, RegionId::PassShow);
        },
    },
    // --- S-07 Deriving -----------------------------------------------------------------
    Frame {
        name: "deriving/running",
        variant: "running",
        screen: ScreenId::Deriving,
        doc: Doc::Portrait("14-deriving"),
        // Captured BEFORE the blocking derivation, exactly as the firmware publishes it
        // before spending seconds in PBKDF2. `tick` is deliberately not called.
        build: |ui| {
            passphrase_typed(ui);
            tap(ui, RegionId::KeyDone);
        },
    },
    // --- S-17 Backup check -------------------------------------------------------------
    Frame {
        name: "backup-check/first-word",
        variant: "first-word",
        screen: ScreenId::BackupCheck,
        doc: Doc::Both("40-backup-check", "73-backup-check-800x480"),
        build: derived,
    },
    // --- S-19 The fork -----------------------------------------------------------------
    Frame {
        name: "keep-or-save/fork",
        variant: "fork",
        screen: ScreenId::KeepOrSave,
        doc: Doc::Both("41-keep-or-save", "74-keep-or-save-800x480"),
        build: at_fork,
    },
    // --- S-20 Name the wallet ----------------------------------------------------------
    Frame {
        name: "name-wallet/empty",
        variant: "empty",
        screen: ScreenId::NameWallet,
        doc: Doc::None,
        build: |ui| {
            at_fork_provisioned(ui);
            tap(ui, RegionId::SaveToDevice);
        },
    },
    Frame {
        name: "name-wallet/typed",
        variant: "typed",
        screen: ScreenId::NameWallet,
        doc: Doc::Portrait("42-name-a-wallet"),
        build: |ui| {
            at_fork_provisioned(ui);
            tap(ui, RegionId::SaveToDevice);
            tap(ui, RegionId::NameField);
            type_keys(ui, "savings");
        },
    },
    Frame {
        name: "name-wallet/save-notice",
        variant: "save-notice",
        screen: ScreenId::NameWallet,
        doc: Doc::Portrait("43-save-wallet"),
        // The C12 write notice. The catalogue stops here on purpose: sealing is the
        // embedder's, and a simulator that pretended to have flash would be lying in a
        // picture.
        build: |ui| {
            at_fork_provisioned(ui);
            tap(ui, RegionId::SaveToDevice);
            tap(ui, RegionId::NameField);
            type_keys(ui, "savings");
            tap(ui, RegionId::KeyDone);
        },
    },
    Frame {
        name: "passphrase/derive-intro",
        variant: "derive-intro",
        screen: ScreenId::PassphraseEntry,
        doc: Doc::Both("130-derive-passphrase-wallet", "131-derive-passphrase-wallet-800x480"),
        // The action that makes a SECOND wallet from an open wallet's words. Its first
        // page is the copy gate's other subject: it has to say that this does not change
        // the wallet the user came from, and that what it makes is a different wallet.
        build: |ui| {
            wallet_home_with(ui, PassphraseState::None);
            scroll_to(ui, RegionId::ActPassphraseDerive);
            
            tap(ui, RegionId::ActPassphraseDerive);
        },
    },
    // --- S-21b The passphrase of a wallet that already exists ---------------------------
    Frame {
        name: "passphrase-unlock/prompt",
        variant: "prompt",
        screen: ScreenId::PassphraseUnlock,
        doc: Doc::Both("121-passphrase-unlock", "122-passphrase-unlock-800x480"),
        build: passphrase_prompt,
    },
    Frame {
        name: "passphrase-unlock/typed",
        variant: "typed",
        screen: ScreenId::PassphraseUnlock,
        doc: Doc::None,
        build: |ui| {
            passphrase_prompt(ui);
            type_keys(ui, "hunter");
        },
    },
    Frame {
        name: "passphrase-unlock/refused",
        variant: "refused",
        screen: ScreenId::PassphraseUnlock,
        doc: Doc::Both("123-passphrase-refused", "124-passphrase-refused-800x480"),
        // The one frame in the product that states two fingerprints to a user, and the one
        // the copy gate reads: it may not contain "wrong", "incorrect" or "invalid", and it
        // may not contain the fingerprint the words derive with no passphrase.
        build: passphrase_refused,
    },
    // --- S-21 Wallet home --------------------------------------------------------------
    Frame {
        name: "wallet-home/session",
        variant: "session",
        screen: ScreenId::WalletHome,
        doc: Doc::Portrait("44-wallet-home-session"),
        build: session_wallet,
    },
    Frame {
        name: "wallet-home/stored",
        variant: "stored",
        screen: ScreenId::WalletHome,
        doc: Doc::Both("46-wallet-home-stored", "71-wallet-home-800x480"),
        build: stored_wallet,
    },
    Frame {
        name: "wallet-home/stored-with-keys",
        variant: "stored-with-keys",
        screen: ScreenId::WalletHome,
        doc: Doc::Both("117-wallet-home-signable", "118-wallet-home-signable-800x480"),
        // The state the PIN exists for: a wallet the store holds, unsealed, with its
        // derivation in hand. It is the only one that offers Sign, and until 0.2.0-m6 it
        // was unreachable - a wallet behind the PIN could be deleted and nothing else.
        build: wallet_home_signable,
    },
    Frame {
        name: "receive/address",
        variant: "receive",
        screen: ScreenId::Receive,
        doc: Doc::Both("90-receive", "91-receive-800x480"),
        build: |ui| {
            wallet_home_signable(ui);
            scroll_to(ui, RegionId::ActReceive);
            tap(ui, RegionId::ActReceive);
        },
    },
    Frame {
        name: "wallet-home/passphrase-required",
        variant: "passphrase-required",
        screen: ScreenId::WalletHome,
        doc: Doc::Both("125-wallet-home-passphrase", "126-wallet-home-passphrase-800x480"),
        // The card that used to read "passphrase off" for exactly this wallet.
        build: |ui| wallet_home_with(ui, PassphraseState::Required),
    },
    Frame {
        name: "wallet-home/passphrase-stored",
        variant: "passphrase-stored",
        screen: ScreenId::WalletHome,
        doc: Doc::None,
        build: |ui| wallet_home_with(ui, PassphraseState::Stored),
    },
    Frame {
        name: "wallet-home/store-passphrase-consequence",
        variant: "store-passphrase-consequence",
        screen: ScreenId::WalletHome,
        doc: Doc::Both("127-store-passphrase", "128-store-passphrase-800x480"),
        // C4b. The two dangers that are true whichever way the toggle goes.
        build: |ui| {
            wallet_home_with(ui, PassphraseState::Required);
            scroll_to(ui, RegionId::ActPassphraseStore);
            tap(ui, RegionId::ActPassphraseStore);
        },
    },
    Frame {
        name: "wallet-home/forget-passphrase-consequence",
        variant: "forget-passphrase-consequence",
        screen: ScreenId::WalletHome,
        doc: Doc::Portrait("129-forget-passphrase"),
        // C4b. The consequence, on a sheet with room for it - a hold bar leaves two lines
        // on the short panel, and this needs five.
        build: |ui| {
            wallet_home_with(ui, PassphraseState::Stored);
            scroll_to(ui, RegionId::ActPassphraseStore);
            tap(ui, RegionId::ActPassphraseStore);
        },
    },
    Frame {
        name: "wallet-home/forget-passphrase-hold",
        variant: "forget-passphrase-hold",
        screen: ScreenId::WalletHome,
        doc: Doc::Both("132-forget-passphrase-hold", "133-forget-passphrase-hold-800x480"),
        // C4c. A tap must not be able to destroy a secret this device can never show back.
        build: |ui| {
            wallet_home_with(ui, PassphraseState::Stored);
            scroll_to(ui, RegionId::ActPassphraseStore);
            tap(ui, RegionId::ActPassphraseStore);
            tap(ui, RegionId::DangerConfirm);
        },
    },
    Frame {
        name: "wallet-home/storage-refused",
        variant: "storage-refused",
        screen: ScreenId::WalletHome,
        doc: Doc::None,
        // The band a refused write leaves behind. The row must still read the state the
        // FLASH is in, which here is the state it was in before.
        build: |ui| {
            wallet_home_with(ui, PassphraseState::Required);
            scroll_to(ui, RegionId::ActPassphraseStore);
            tap(ui, RegionId::ActPassphraseStore);
            tap(ui, RegionId::DangerConfirm);
            ui.passphrase_storage_result(StorageOutcome::Refused(String::from(
                "Nothing was changed: the record is 3998 bytes and the slot holds 3996.",
            )));
        },
    },
    Frame {
        name: "wallet-home/exit-modal",
        variant: "exit-modal",
        screen: ScreenId::WalletHome,
        doc: Doc::Portrait("12-exit-modal"),
        // Back off a screen the user would LOSE by leaving is gated by a confirm, and the
        // modal is drawn OVER the sheet - the one frame where two layers are on the panel.
        // A session wallet is that screen: nothing was written, so its keys exist here and
        // nowhere else. It used to be photographed over the export view one step further
        // in, which was the bug - that Back belongs to the wallet, and asks nothing.
        build: |ui| {
            session_wallet(ui);
            tap(ui, RegionId::Back);
        },
    },
    Frame {
        name: "wallet-home/delete-consequence",
        variant: "delete-consequence",
        screen: ScreenId::WalletHome,
        doc: Doc::Portrait("47-delete-consequence"),
        build: |ui| {
            stored_wallet(ui);
            scroll_to(ui, RegionId::WalletDelete);
            tap(ui, RegionId::WalletDelete);
        },
    },
    Frame {
        name: "wallet-home/delete-typed-name",
        variant: "delete-typed-name",
        screen: ScreenId::WalletHome,
        doc: Doc::Both("48-delete-typed-name", "72-delete-typed-name-800x480"),
        build: |ui| {
            stored_wallet(ui);
            scroll_to(ui, RegionId::WalletDelete);
            tap(ui, RegionId::WalletDelete);
            tap(ui, RegionId::DangerConfirm);
            type_keys(ui, "dummy");
        },
    },
    // --- S-13 again, on the delete path ------------------------------------------------
    Frame {
        name: "mnemonic/stored-masked",
        variant: "stored-masked",
        screen: ScreenId::MnemonicDisplay,
        doc: Doc::None,
        // The same screen, the same bullet run, reached from a STORED wallet instead of
        // from the dice. If the masking law ever grew a second implementation this frame is
        // where the two would stop matching.
        build: |ui| {
            erase_offer(ui);
            tap(ui, RegionId::EraseShowWords);
            ui.recovery_words(WordsOutcome::words(SIXES_PHRASE));
        },
    },
    Frame {
        name: "mnemonic/stored-revealed",
        variant: "stored-revealed",
        screen: ScreenId::MnemonicDisplay,
        doc: Doc::None,
        // Through S-13's reveal gate, verbatim, and nowhere else: a stored wallet's words
        // are no cheaper to show than a fresh one's.
        build: |ui| {
            erase_offer(ui);
            tap(ui, RegionId::EraseShowWords);
            ui.recovery_words(WordsOutcome::words(SIXES_PHRASE));
            tap(ui, RegionId::Reveal);
            tap(ui, RegionId::ModalConfirm);
        },
    },
    // --- S-47b The last words ----------------------------------------------------------
    Frame {
        name: "erase-wallet/offer",
        variant: "offer",
        screen: ScreenId::EraseWallet,
        doc: Doc::Both("119-erase-offer", "120-erase-offer-800x480"),
        // Both panels, because this is the frame the balance claim is about: two cards of
        // the same size in one row, with the consequence above them. A layout that nudged
        // would be visible here before it was visible on a device.
        build: erase_offer,
    },
    Frame {
        name: "erase-wallet/words-refused",
        variant: "words-refused",
        screen: ScreenId::EraseWallet,
        doc: Doc::None,
        // The one state where the Q22 line steps aside: the words could not be read, so the
        // sentence about what they are not enough for has no subject, and the sentence
        // about why they are not there takes its place.
        build: |ui| {
            erase_offer(ui);
            tap(ui, RegionId::EraseShowWords);
            ui.recovery_words(WordsOutcome::Refused(String::from(
                "Wallet slot 0 did not open: the record did not come back intact.",
            )));
        },
    },
    // --- S-08 Schemes ------------------------------------------------------------------
    Frame {
        name: "schemes/bip44",
        variant: "bip44",
        screen: ScreenId::Schemes,
        doc: Doc::Portrait("07-schemes-bip44"),
        // The legacy tab, asked for BY TAP rather than inherited from wherever the screen
        // opens. Export opens on BIP-84 now (`schemes::DEFAULT_SCHEME`), so a recipe that
        // only pressed Export would render the BIP-84 tab under the name bip44 and write
        // it to docs/screenshots/ui as `07-schemes-bip44` - a frame, a variant name and a
        // published picture all claiming a screen none of them is. Tab(0) is BIP-44's
        // position in `Scheme::ALL`, which is what the tab strip is drawn from.
        build: |ui| {
            session_wallet(ui);
            tap(ui, RegionId::ActExport);
            tap(ui, RegionId::Tab(0));
        },
    },
    Frame {
        name: "schemes/bip84",
        variant: "bip84",
        screen: ScreenId::Schemes,
        doc: Doc::Portrait("08-schemes-bip84"),
        build: schemes_bip84,
    },
    Frame {
        name: "schemes/qr",
        variant: "qr",
        screen: ScreenId::Schemes,
        doc: Doc::Portrait("09-schemes-qr"),
        // The whole QR round trip, over the crate boundary the firmware crosses: the tap
        // raises a request, the CORE encodes the payload (std side, which is the step that
        // was compiled out when the buttons went dead), and the matrix comes back in.
        //
        // Photographed on the DESCRIPTOR, which is the block the tab now leads with and the
        // artifact `DESCRIPTOR_HELP` tells the reader to hand a coordinator: a documentation
        // picture of a QR symbol is an instruction to scan it, so it shows the symbol we
        // want scanned. The bare xpub's button keeps its own coverage - it is tapped by
        // `a_qr_tap_round_trips_through_the_core_encoder`, and every QR button on the tab
        // including it is tapped by `every_qr_button_of_a_scheme_encodes`, both in
        // tools/uisim/tests/regressions.rs - so nothing is lost by not photographing it.
        build: |ui| {
            schemes_bip84(ui);
            let Some(UiRequest::Qr(target)) = tap(ui, RegionId::QrDescriptor) else {
                panic!("the descriptor QR button raised no request");
            };
            let matrix = notyas_core::qr::matrix(&target.payload).expect("encode descriptor");
            let data = QrData::from_matrix(&matrix).expect("square matrix");
            ui.show_qr(target, data);
        },
    },
    // --- S-09 Phrase entry -------------------------------------------------------------
    Frame {
        name: "phrase/empty",
        variant: "empty",
        screen: ScreenId::PhraseEntry,
        doc: Doc::None,
        build: |ui| {
            home(ui);
            tap(ui, RegionId::HomeVerifySeed);
        },
    },
    Frame {
        name: "phrase/typed",
        variant: "typed",
        screen: ScreenId::PhraseEntry,
        doc: Doc::Portrait("11-phrase-entry"),
        // The desktop's well-known bad-checksum example, typed in.
        build: |ui| {
            home(ui);
            tap(ui, RegionId::HomeVerifySeed);
            type_keys(ui, "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong");
        },
    },
    Frame {
        name: "phrase/autocomplete",
        variant: "autocomplete",
        screen: ScreenId::PhraseEntry,
        doc: Doc::Portrait("15-phrase-autocomplete"),
        // "ab" has more matches than the strip can show, so this is the strip at full
        // width with the overflow slot occupied.
        build: |ui| {
            home(ui);
            tap(ui, RegionId::HomeVerifySeed);
            type_keys(ui, "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong ab");
        },
    },
    Frame {
        name: "phrase/final-word",
        variant: "final-word",
        screen: ScreenId::PhraseEntry,
        doc: Doc::Both("65-final-word-helper", "67-final-word-helper-800x480"),
        // Eleven words in, only 128 of the 2048 can be the twelfth: the screen stops
        // completing prefixes and starts finishing the phrase.
        build: eleven_words,
    },
    Frame {
        name: "phrase/final-word-sheet",
        variant: "final-word-sheet",
        screen: ScreenId::PhraseEntry,
        doc: Doc::Both("66-final-word-sheet", "68-final-word-sheet-800x480"),
        build: |ui| {
            eleven_words(ui);
            tap(ui, RegionId::SuggestMore);
        },
    },
    // --- S-46 Verify device ------------------------------------------------------------
    Frame {
        name: "verify-device/pre-pin",
        variant: "pre-pin",
        screen: ScreenId::VerifyDevice,
        doc: Doc::Both("10-verify-device", "10-verify-device-800x480"),
        // Reachable before the PIN by design (commandment 4); the pre-PIN sheet is a
        // strict subset of the unlocked one.
        build: |ui| {
            ui.set_verify_info(dummy_verify_info());
            tap(ui, RegionId::HomeVerifyDevice);
        },
    },
    Frame {
        name: "verify-device/digests",
        variant: "digests",
        screen: ScreenId::VerifyDevice,
        doc: Doc::Both("21-verify-digests", "21-verify-digests-800x480"),
        // The second viewport: where the digest blocks are, and where the frozen line
        // break is the one property the screen is arranged around.
        build: |ui| {
            ui.set_verify_info(dummy_verify_info());
            tap(ui, RegionId::HomeVerifyDevice);
            tap(ui, RegionId::ReviewNext);
        },
    },
    Frame {
        name: "verify-device/unlocked",
        variant: "unlocked",
        screen: ScreenId::VerifyDevice,
        doc: Doc::Both("22-verify-device-unlocked", "22-verify-device-unlocked-800x480"),
        build: verify_unlocked,
    },
    Frame {
        name: "verify-device/reserved-space",
        variant: "reserved-space",
        screen: ScreenId::VerifyDevice,
        doc: Doc::Both("24-verify-reserved-space", "24-verify-reserved-space-800x480"),
        build: |ui| {
            verify_unlocked(ui);
            page_to(ui, RegionId::VerifyScanFlash);
            assert_eq!(
                tap(ui, RegionId::VerifyScanFlash),
                Some(UiRequest::ScanReservedSpace),
                "the Scan control must ask the std side to read flash"
            );
            ui.set_flash_scan(dummy_flash_scan());
        },
    },
    Frame {
        name: "verify-device/acknowledge",
        variant: "acknowledge",
        screen: ScreenId::VerifyDevice,
        doc: Doc::Both("25-verify-acknowledge", "25-verify-acknowledge-800x480"),
        // The one write this screen offers, with its C12 band above it. The band and the
        // button are ONE row, so no page break can come between the sentence and the
        // action - which is only checkable by paging to it the way a finger does.
        build: |ui| {
            verify_unlocked(ui);
            page_to(ui, RegionId::VerifyScanFlash);
            tap(ui, RegionId::VerifyScanFlash);
            ui.set_flash_scan(dummy_flash_scan());
            page_to(ui, RegionId::VerifyAckBoots);
        },
    },
    // --- S-46's Busy frame -------------------------------------------------------------
    Frame {
        name: "scanning-flash/progress",
        variant: "progress",
        screen: ScreenId::ScanningFlash,
        doc: Doc::Both("23-verify-scanning", "23-verify-scanning-800x480"),
        build: |ui| {
            verify_unlocked(ui);
            page_to(ui, RegionId::VerifyScanFlash);
            tap(ui, RegionId::VerifyScanFlash);
            ui.set_scan_progress(3, 4);
        },
    },
    // --- S-03 Lock ---------------------------------------------------------------------
    Frame {
        name: "lock/named",
        variant: "named",
        screen: ScreenId::Lock,
        doc: Doc::Both("16-lock", "16-lock-800x480"),
        build: |ui| locked(ui, dummy_lock_info()),
    },
    Frame {
        name: "lock/no-name",
        variant: "no-name",
        screen: ScreenId::Lock,
        doc: Doc::Both("16b-lock-no-name", "16b-lock-no-name-800x480"),
        // The state EVERY device ships in and the one an owner meets first: the screen
        // renders its own edge state rather than a blank line. The two lock-word frames
        // this replaces went with the word itself on 2026-08-19 - there is one pre-PIN
        // string now, so there is one unset state to picture.
        build: |ui| {
            locked(ui, LockInfo { device_name: String::new(), ..dummy_lock_info() });
        },
    },
    Frame {
        name: "lock/wipe-off",
        variant: "wipe-off",
        screen: ScreenId::Lock,
        doc: Doc::None,
        // Wipe policy off: there is no attempt count to state, so the line that usually
        // carries one is absent.
        build: |ui| {
            locked(
                ui,
                LockInfo { attempts_left: None, wipe_after: None, ..dummy_lock_info() },
            );
        },
    },
    // --- S-04 PIN entry ----------------------------------------------------------------
    Frame {
        name: "pin/fresh",
        variant: "fresh",
        screen: ScreenId::PinEntry,
        doc: Doc::None,
        build: |ui| pin_entry(ui, dummy_lock_info(), &[]),
    },
    Frame {
        name: "pin/typed",
        variant: "typed",
        screen: ScreenId::PinEntry,
        doc: Doc::Portrait("17-pin-entry"),
        build: |ui| pin_entry(ui, dummy_lock_info(), &[0, 3, 6, 9]),
    },
    Frame {
        name: "pin/device-words",
        variant: "device-words",
        screen: ScreenId::PinEntry,
        doc: Doc::Portrait("18-pin-device-words"),
        build: |ui| {
            pin_entry(ui, dummy_lock_info(), &[0, 3, 6, 9]);
            device_words(ui, ["anvil".into(), "mercury".into()]);
        },
    },
    Frame {
        name: "pin/device-words-six-digits",
        variant: "device-words",
        screen: ScreenId::PinEntry,
        doc: Doc::Landscape("20-pin-entry-800x480"),
        // Six digits rather than four: the pad is the same 3x4 keypad on every panel, and
        // the entry indicator is what grows. On the shorter panel the whole screen reflows
        // into a full-height right rail rather than a pad below the words, which is the
        // kind of change only a picture is an honest check on.
        build: |ui| {
            pin_entry(ui, dummy_lock_info(), &[0, 3, 6, 9, 1, 2]);
            device_words(ui, ["anvil".into(), "mercury".into()]);
        },
    },
    Frame {
        name: "pin/wrong",
        variant: "wrong",
        screen: ScreenId::PinEntry,
        doc: Doc::Portrait("19-pin-wrong"),
        build: |ui| {
            pin_entry(ui, dummy_lock_info(), &[0, 3, 6, 9]);
            device_words(ui, ["anvil".into(), "mercury".into()]);
            ui.unseal_result(UnsealOutcome::WrongPin { attempts_left: Some(2) });
        },
    },
    Frame {
        name: "pin/last-attempt",
        variant: "last-attempt",
        screen: ScreenId::PinEntry,
        doc: Doc::None,
        // One attempt before the store is destroyed. The screen has to say so in a way
        // nobody can read as routine, and it is the state hardest to reach by hand.
        build: |ui| {
            pin_entry(ui, LockInfo { attempts_left: Some(2), ..dummy_lock_info() }, &[0, 3]);
            ui.unseal_result(UnsealOutcome::WrongPin { attempts_left: Some(1) });
        },
    },
    // --- S-06 / S-07 Set a PIN ---------------------------------------------------------
    Frame {
        name: "pin-create/step-1",
        variant: "step-1",
        screen: ScreenId::PinCreate,
        doc: Doc::None,
        build: at_new_pin,
    },
    Frame {
        name: "pin-create/step-2",
        variant: "step-2",
        screen: ScreenId::PinCreate,
        doc: Doc::None,
        build: at_new_pin_confirm,
    },
    Frame {
        name: "pin-create/typed",
        variant: "typed",
        screen: ScreenId::PinCreate,
        doc: Doc::None,
        // The only state that draws the dot row, and the row is the one secret-bearing
        // element on this screen: six bullets, at the length the wipe-policy arithmetic
        // assumes a PIN is. Photographed at step 2 because that is where a bullet run and
        // a live commit button share the panel.
        build: |ui| {
            at_new_pin_confirm(ui);
            for i in 0..6 {
                tap(ui, RegionId::PinKey(i));
            }
        },
    },
    Frame {
        name: "pin-create/mismatch",
        variant: "mismatch",
        screen: ScreenId::PinCreate,
        doc: Doc::None,
        // A second entry that differs from the first. The screen returns to step 1 with
        // BOTH entries gone, so what this pictures is an empty step 1 carrying the
        // mismatch line - which is the whole point of photographing it.
        build: |ui| {
            at_new_pin_confirm(ui);
            for i in [1, 2, 3, 4] {
                tap(ui, RegionId::PinKey(i));
            }
            tap(ui, RegionId::PinConfirm);
        },
    },
    Frame {
        name: "pin-create/refused",
        variant: "refused",
        screen: ScreenId::PinCreate,
        doc: Doc::None,
        // Two matching entries handed over, and the embedder unable to format. The
        // simulator has no flash, so the refusal is stated rather than provoked - the
        // frame that matters is the one the user is left looking at.
        build: |ui| {
            at_new_pin_confirm(ui);
            for i in 0..4 {
                tap(ui, RegionId::PinKey(i));
            }
            tap(ui, RegionId::PinConfirm);
            ui.pin_created(false);
        },
    },
    Frame {
        name: "pin-create/not-provisioned",
        variant: "not-provisioned",
        screen: ScreenId::PinCreate,
        doc: Doc::None,
        // A device whose eFuse key was never burned. The fork sends it here like any
        // other device without a PIN, and this screen is where it learns it cannot store
        // anything - stated on the panel, with the commit inert.
        build: |ui| {
            ui.set_lock_info(LockInfo {
                status: StoreStatus::NotProvisioned,
                attempts_left: None,
                pin: None,
                ..dummy_lock_info()
            });
            at_fork(ui);
            tap(ui, RegionId::SaveToDevice);
        },
    },
    // --- S-10 Wallet list --------------------------------------------------------------
    Frame {
        name: "wallet-list/none",
        variant: "none",
        screen: ScreenId::WalletList,
        doc: Doc::None,
        // A PIN set and nothing stored yet: the empty state of the device's real home.
        build: |ui| unlocked(ui, Vec::new()),
    },
    Frame {
        name: "wallet-list/one",
        variant: "one",
        screen: ScreenId::WalletList,
        doc: Doc::None,
        build: |ui| unlocked(ui, dummy_wallets().into_iter().take(1).collect()),
    },
    Frame {
        name: "wallet-list/many",
        variant: "many",
        screen: ScreenId::WalletList,
        doc: Doc::Both("45-wallet-list", "70-wallet-list-800x480"),
        build: unlocked_with_dummy_wallets,
    },
    Frame {
        name: "wallet-list/unreadable-slot",
        variant: "unreadable-slot",
        screen: ScreenId::WalletList,
        doc: Doc::None,
        // A slot that did not decrypt and nothing else. It has no name, no fingerprint
        // and no path, so the row is a different SHAPE rather than a wallet with blank
        // fields (R-32) - and on its own it is the whole list.
        build: |ui| unlocked(ui, vec![WalletRow::Unreadable { slot: 0 }]),
    },
    // --- S-44 Settings -----------------------------------------------------------------
    Frame {
        name: "settings/default",
        variant: "default",
        screen: ScreenId::Settings,
        doc: Doc::Both("53-settings", "60-settings-800x480"),
        build: settings,
    },
    Frame {
        name: "settings/network-testnet",
        variant: "network-testnet",
        screen: ScreenId::Settings,
        doc: Doc::None,
        // The one row that acts here rather than opening a screen, in its other position.
        // The network outlives this screen, so what it reads here is what the next
        // derivation runs on.
        // Row 1: the device name took the top of the list on 2026-08-19.
        build: |ui| {
            settings(ui);
            tap(ui, RegionId::SetRow(1));
        },
    },
    Frame {
        name: "settings/remove-pin-consequence",
        variant: "remove-pin-consequence",
        screen: ScreenId::Settings,
        doc: Doc::Portrait("58-remove-pin-consequence"),
        // What removing the PIN destroys, named individually with counts read from the
        // list the embedder installed.
        build: |ui| {
            settings(ui);
            tap(ui, RegionId::RemoveThePin);
        },
    },
    Frame {
        name: "settings/remove-pin-typed",
        variant: "remove-pin-typed",
        screen: ScreenId::Settings,
        doc: Doc::Both("59-remove-pin-typed", "64-remove-pin-typed-800x480"),
        build: |ui| {
            settings(ui);
            tap(ui, RegionId::RemoveThePin);
            tap(ui, RegionId::DangerConfirm);
            type_shifted(ui, "WIP");
        },
    },
    // --- S-44a Device name ---------------------------------------------------------------
    Frame {
        name: "device-name/current",
        variant: "current",
        screen: ScreenId::DeviceName,
        doc: Doc::Both("53a-device-name", "60a-device-name-800x480"),
        // Opened on the name the device already has, which is what the row promises.
        build: device_name_screen,
    },
    Frame {
        name: "device-name/typing",
        variant: "typing",
        screen: ScreenId::DeviceName,
        doc: Doc::None,
        // The keyboard phase. It replaces everything the screen SAYS, which is the whole
        // reason the screen has two phases on the 800x480 panel.
        build: |ui| {
            device_name_screen(ui);
            tap(ui, RegionId::DeviceNameField);
        },
    },
    Frame {
        name: "device-name/refused",
        variant: "refused",
        screen: ScreenId::DeviceName,
        doc: Doc::None,
        // A seed word typed into a field whose contents are printed before any PIN is.
        // The refusal is on the panel and the commit is inert.
        build: |ui| {
            device_name_screen(ui);
            tap(ui, RegionId::DeviceNameField);
            for _ in 0..DUMMY_DEVICE_NAME.chars().count() {
                tap(ui, RegionId::KeyBackspace);
            }
            type_keys(ui, "abandon");
            tap(ui, RegionId::KeyDone);
        },
    },
    // --- S-04a The device-words explainer -------------------------------------------------
    Frame {
        name: "about-device-words/explainer",
        variant: "explainer",
        screen: ScreenId::AboutDeviceWords,
        doc: Doc::Both("18a-device-words-explained", "20a-device-words-explained-800x480"),
        // Raised by the first answer of a power-up, over PIN entry with a prefix typed.
        build: |ui| {
            pin_entry(ui, dummy_lock_info(), &[0, 3, 6, 9]);
            ui.show_device_words(["anvil".into(), "mercury".into()]);
        },
    },
    // --- S-49 Format card ---------------------------------------------------------------
    //
    // Six variants, eight frames, and six of the eight are states in which NOTHING is
    // erased. That ratio is the feature: a format is offered for one fault and refused for
    // every other reason a card will not work.
    //
    // `Doc::None` throughout. The committed picture set is a curated, historically
    // numbered sequence, and appending to it is a separate decision from shipping the
    // screen - the gate covers every one of these on all five panels either way, which is
    // what stops a layout defect reaching a device.
    Frame {
        name: "format-card/offer",
        variant: "offer",
        screen: ScreenId::FormatCard,
        doc: Doc::None,
        build: |ui| format_card(ui, FormatOffer::Ready(dummy_format_target())),
    },
    Frame {
        name: "format-card/refused",
        variant: "refused",
        screen: ScreenId::FormatCard,
        doc: Doc::None,
        // The refusal worth a picture: a card that works. This device does not offer to
        // erase one, and the screen says so rather than leaving the button greyed out.
        build: |ui| {
            format_card(
                ui,
                FormatOffer::Refused {
                    why: FormatRefusal::CardAlreadyReadable,
                    note: String::new(),
                },
            )
        },
    },
    Frame {
        name: "format-card/refused-firmware",
        variant: "refused",
        screen: ScreenId::FormatCard,
        doc: Doc::None,
        // The refusal that stops the worst outcome this feature has: the FIRMWARE cannot
        // read cards, so every card looks unreadable, and formatting one would erase
        // somebody's data to work around a build setting.
        build: |ui| {
            format_card(
                ui,
                FormatOffer::Refused {
                    why: FormatRefusal::FirmwareCannotRead,
                    note: String::from("CONFIG_FATFS_LFN_HEAP=y"),
                },
            )
        },
    },
    Frame {
        name: "format-card/consequence",
        variant: "consequence",
        screen: ScreenId::FormatCard,
        doc: Doc::None,
        build: format_consequence,
    },
    Frame {
        name: "format-card/typed",
        variant: "typed",
        screen: ScreenId::FormatCard,
        doc: Doc::None,
        build: format_typed,
    },
    Frame {
        name: "format-card/done",
        variant: "done",
        screen: ScreenId::FormatCard,
        doc: Doc::None,
        build: |ui| {
            format_writing(ui);
            ui.format_result(FormatOutcome::Done(String::from(
                "The 32 GB card now holds one empty FAT filesystem in partition 1.",
            )));
        },
    },
    Frame {
        name: "format-card/failed",
        variant: "failed",
        screen: ScreenId::FormatCard,
        doc: Doc::None,
        // The state nobody wants to write and every user of a locked card reaches: the
        // write started and did not finish, so the card is in a state neither the device
        // nor its owner can describe.
        build: |ui| {
            format_writing(ui);
            ui.format_result(FormatOutcome::Failed {
                why: String::from(
                    "The card refused the write (FatFs error 1). A write-protect switch on \
                     the card or its adapter fails like this.",
                ),
                wrote: true,
            });
        },
    },
    Frame {
        name: "working/formatting-card",
        variant: "formatting-card",
        screen: ScreenId::Working,
        doc: Doc::None,
        build: format_writing,
    },
    // --- S-44's wrong-PIN policy -------------------------------------------------------
    Frame {
        name: "wipe-policy/default",
        variant: "default",
        screen: ScreenId::WipePolicy,
        doc: Doc::Both("54-wipe-policy", "61-wipe-policy-800x480"),
        build: wipe_policy,
    },
    Frame {
        name: "wipe-policy/edited",
        variant: "edited",
        screen: ScreenId::WipePolicy,
        doc: Doc::Portrait("55-wipe-policy-edited"),
        build: |ui| {
            wipe_policy(ui);
            tap(ui, RegionId::PolicyMore);
        },
    },
    Frame {
        name: "wipe-policy/wipe-off-arithmetic",
        variant: "wipe-off-arithmetic",
        screen: ScreenId::WipePolicy,
        doc: Doc::Both("56-wipe-off-arithmetic", "62-wipe-off-arithmetic-800x480"),
        // Turning the wipe off states the cost of guessing THIS PIN on THIS board, with
        // the longer-PIN path offered beside accept and cancel.
        build: |ui| {
            wipe_policy(ui);
            tap(ui, RegionId::PolicyWipe);
        },
    },
    Frame {
        name: "wipe-policy/wipe-off-typed",
        variant: "wipe-off-typed",
        screen: ScreenId::WipePolicy,
        doc: Doc::Both("57-wipe-off-typed", "63-wipe-off-typed-800x480"),
        build: |ui| {
            wipe_policy(ui);
            tap(ui, RegionId::PolicyWipe);
            tap(ui, RegionId::DangerConfirm);
            type_shifted(ui, "OF");
        },
    },
    // --- S-27 the sign source, and S-28 the picker -------------------------------------
    Frame {
        name: "working/reading",
        variant: "reading",
        screen: ScreenId::Working,
        doc: Doc::None,
        build: sign_reading,
    },
    Frame {
        name: "sign-source/ready",
        variant: "ready",
        screen: ScreenId::SignSource,
        doc: Doc::Both("91-sign-source", "96-sign-source-800x480"),
        // Exactly one transaction on the card: the screen names it and offers to read it,
        // and does NOT read it on its own. Inserting a card must not be enough to make this
        // device parse a stranger's file.
        build: |ui| sign_source(ui, CardOutcome::Listed(dummy_single_psbt_card())),
    },
    Frame {
        name: "sign-source/empty",
        variant: "empty",
        screen: ScreenId::SignSource,
        doc: Doc::Portrait("92-sign-source-empty"),
        build: |ui| sign_source(ui, CardOutcome::Listed(dummy_empty_card(""))),
    },
    Frame {
        name: "sign-source/no-card",
        variant: "no-card",
        screen: ScreenId::SignSource,
        doc: Doc::None,
        build: |ui| sign_source(ui, CardOutcome::NoCard),
    },
    Frame {
        name: "sign-source/unreadable",
        variant: "unreadable",
        screen: ScreenId::SignSource,
        doc: Doc::None,
        build: |ui| {
            sign_source(
                ui,
                CardOutcome::Unreadable(String::from(
                    "The card holds no filesystem this device can read. Format it as FAT32 \
                     and copy the transaction on again.",
                )),
            )
        },
    },
    Frame {
        name: "file-picker/listing",
        variant: "listing",
        screen: ScreenId::FilePicker,
        doc: Doc::Both("93-file-picker", "97-file-picker-800x480"),
        // Every row kind at once, including the two the picker draws and will not offer: a
        // file over the transfer cap, and a directory.
        build: |ui| picker(ui, dummy_psbt_card()),
    },
    Frame {
        name: "file-picker/all-files",
        variant: "all-files",
        screen: ScreenId::FilePicker,
        doc: Doc::None,
        build: |ui| {
            picker(ui, dummy_psbt_card());
            tap(ui, RegionId::Tab(1));
            ui.card_result(CardOutcome::Listed(dummy_multisig_card()));
        },
    },
    Frame {
        name: "file-picker/empty",
        variant: "empty",
        screen: ScreenId::FilePicker,
        doc: Doc::None,
        build: |ui| {
            picker(ui, dummy_psbt_card());
            tap(ui, RegionId::ListRow(0));
            ui.card_result(CardOutcome::Listed(dummy_empty_card("bundles")));
        },
    },
    Frame {
        name: "file-picker/paged",
        variant: "paged",
        screen: ScreenId::FilePicker,
        doc: Doc::None,
        build: |ui| {
            picker(ui, dummy_long_psbt_card());
            tap(ui, RegionId::ListPageNext);
        },
    },
    Frame {
        name: "working/reading-card",
        variant: "reading-card",
        screen: ScreenId::Working,
        doc: Doc::None,
        build: |ui| {
            picker(ui, dummy_psbt_card());
            tap(ui, RegionId::FileRefresh);
        },
    },
    Frame {
        name: "working/checking-transaction",
        variant: "checking-transaction",
        screen: ScreenId::Working,
        doc: Doc::Portrait("94-checking-transaction"),
        build: loading,
    },

    // --- S-30..S-36 the review ---------------------------------------------------------
    Frame {
        name: "review-transaction/overview",
        variant: "overview",
        screen: ScreenId::ReviewTransaction,
        doc: Doc::Both("98-review-overview", "105-review-overview-800x480"),
        build: |ui| review_at(ui, ReviewShape::Proven, 0),
    },
    Frame {
        name: "review-transaction/input-proven",
        variant: "input-proven",
        screen: ScreenId::ReviewTransaction,
        doc: Doc::Portrait("99-review-input-proven"),
        build: |ui| review_at(ui, ReviewShape::Proven, 1),
    },
    Frame {
        name: "review-transaction/input-stated",
        variant: "input-stated",
        screen: ScreenId::ReviewTransaction,
        doc: Doc::Both("100-review-input-stated", "106-review-input-stated-800x480"),
        // The amount the file states and nothing proves. The caveat is carried by WORDS,
        // so a monochrome photograph of this frame still says it.
        build: |ui| review_at(ui, ReviewShape::Stated, 2),
    },
    Frame {
        name: "review-transaction/input-bound",
        variant: "input-bound",
        screen: ScreenId::ReviewTransaction,
        doc: Doc::None,
        // The amount a BlueWallet spend states and this device's own signature binds. STATED
        // is still on the number, because it did come out of the file - but there is no
        // caveat band, no amber, and the row underneath says what the signature does. Beside
        // "input-stated", which is the same prefix over an amount nothing binds.
        build: |ui| bluewallet_review_at(ui, 1),
    },
    Frame {
        name: "review-transaction/output-external",
        variant: "output-external",
        screen: ScreenId::ReviewTransaction,
        doc: Doc::Portrait("101-review-output-external"),
        build: |ui| review_at(ui, ReviewShape::Proven, 4),
    },
    Frame {
        name: "review-transaction/output-change",
        variant: "output-change",
        screen: ScreenId::ReviewTransaction,
        doc: Doc::None,
        build: |ui| review_at(ui, ReviewShape::Proven, 5),
    },
    Frame {
        name: "review-transaction/output-data",
        variant: "output-data",
        screen: ScreenId::ReviewTransaction,
        doc: Doc::None,
        // An OP_RETURN payload, shown as hex and as printable ASCII with a byte count, and
        // never decoded into something that reads like an instruction.
        build: |ui| review_at(ui, ReviewShape::Proven, 6),
    },
    Frame {
        name: "review-transaction/claimed-change",
        variant: "claimed-change",
        screen: ScreenId::ReviewTransaction,
        doc: Doc::Both("102-review-claimed-change", "107-review-claimed-change-800x480"),
        // CHANGE - CLAIMED, NOT VERIFIED. The change-confusion attack, on the page where it
        // is caught.
        build: |ui| review_at(ui, ReviewShape::ClaimedChange, 5),
    },
    Frame {
        name: "review-transaction/fee-enforced",
        variant: "fee-enforced",
        screen: ScreenId::ReviewTransaction,
        doc: Doc::Portrait("103-review-fee"),
        build: |ui| review_at(ui, ReviewShape::Proven, 8),
    },
    Frame {
        name: "review-transaction/fee-stated",
        variant: "fee-stated",
        screen: ScreenId::ReviewTransaction,
        doc: Doc::None,
        // AT LEAST, on every number derived from the fee: a lower bound divided by an exact
        // vsize is still a lower bound.
        build: |ui| review_at(ui, ReviewShape::Stated, 8),
    },
    Frame {
        name: "review-transaction/warnings-armed",
        variant: "warnings-armed",
        screen: ScreenId::ReviewTransaction,
        doc: Doc::Both("104-review-warnings", "108-review-warnings-800x480"),
        build: |ui| review_at(ui, ReviewShape::Proven, 9),
    },
    Frame {
        name: "review-transaction/warnings-gated",
        variant: "warnings-gated",
        screen: ScreenId::ReviewTransaction,
        doc: Doc::None,
        // Every page seen, and the hold still absent: an unproven change claim cannot be
        // finished off by a user who read everything and trusted the button.
        build: |ui| review_at(ui, ReviewShape::ClaimedChange, 9),
    },

    // --- S-37 the signature, S-38 the delivery -----------------------------------------
    Frame {
        name: "signing/signing",
        variant: "signing",
        screen: ScreenId::Signing,
        doc: Doc::Portrait("109-signing"),
        build: signing,
    },
    Frame {
        name: "deliver/complete",
        variant: "complete",
        screen: ScreenId::Deliver,
        doc: Doc::Both("110-deliver", "113-deliver-800x480"),
        build: |ui| delivering(ui, true),
    },
    Frame {
        name: "deliver/partial",
        variant: "partial",
        screen: ScreenId::Deliver,
        doc: Doc::Portrait("111-deliver-partial"),
        build: |ui| delivering(ui, false),
    },
    Frame {
        name: "deliver/written",
        variant: "written",
        screen: ScreenId::Deliver,
        doc: Doc::Both("112-deliver-written", "114-deliver-written-800x480"),
        build: |ui| {
            delivered(
                ui,
                WriteOutcome::Written(vec![Artifact {
                    name: String::from("dummy-spend-2026-08-17-signed.psbt"),
                    bytes: 2_712,
                }]),
            )
        },
    },
    Frame {
        name: "deliver/no-card",
        variant: "no-card",
        screen: ScreenId::Deliver,
        doc: Doc::None,
        build: |ui| delivered(ui, WriteOutcome::NoCard),
    },
    Frame {
        name: "deliver/write-failed",
        variant: "write-failed",
        screen: ScreenId::Deliver,
        doc: Doc::None,
        build: |ui| {
            delivered(
                ui,
                WriteOutcome::Failed(String::from("The card stopped answering after 1.2 kB.")),
            )
        },
    },
    Frame {
        name: "deliver/overwrite-sheet",
        variant: "overwrite-sheet",
        screen: ScreenId::Deliver,
        doc: Doc::None,
        // A collision is a question, not a failure: nothing was written, and the sheet names
        // the file the user is about to replace.
        build: |ui| {
            delivered(
                ui,
                WriteOutcome::Collision(vec![String::from("dummy-spend-2026-08-17-signed.psbt")]),
            )
        },
    },
    Frame {
        name: "deliver/discard-sheet",
        variant: "discard-sheet",
        screen: ScreenId::Deliver,
        doc: Doc::None,
        // The C4b override, offered only after a SECOND failed attempt: one failure is a
        // card to reseat, and a user with a dead slot must still be able to leave.
        build: |ui| {
            delivered(
                ui,
                WriteOutcome::Failed(String::from("The card stopped answering after 1.2 kB.")),
            );
            tap(ui, RegionId::DeliverRetry);
            ui.write_result(WriteOutcome::Failed(String::from(
                "The card stopped answering after 1.2 kB.",
            )));
            tap(ui, RegionId::DeliverDiscard);
        },
    },
    Frame {
        name: "working/writing",
        variant: "writing",
        screen: ScreenId::Working,
        doc: Doc::None,
        build: |ui| {
            delivering(ui, true);
            tap(ui, RegionId::DeliverSd);
        },
    },

    // --- S-29 the refusal ---------------------------------------------------------------
    Frame {
        name: "refusal/missing-prevtx",
        variant: "missing-prevtx",
        screen: ScreenId::Refusal,
        doc: Doc::Both("95-refusal", "115-refusal-800x480"),
        build: |ui| refused(ui, RefusalCode::MissingPrevTx),
    },
    Frame {
        name: "refusal/change-not-proven",
        variant: "change-not-proven",
        screen: ScreenId::Refusal,
        doc: Doc::None,
        build: |ui| refused(ui, RefusalCode::ChangeNotProven),
    },
    Frame {
        name: "refusal/details",
        variant: "details",
        screen: ScreenId::Refusal,
        doc: Doc::Portrait("116-refusal-details"),
        // The block a bug report is photographed from. Hidden until asked for, because it is
        // machine facts and the three sentences above it are what the user acts on.
        build: |ui| {
            refused(ui, RefusalCode::MissingPrevTx);
            tap(ui, RegionId::RefusalDetails);
        },
    },
    Frame {
        name: "refusal/unsupported-script",
        variant: "unsupported-script",
        screen: ScreenId::Refusal,
        doc: Doc::Both("134-refusal-unsupported-script", "135-refusal-unsupported-script-800x480"),
        // Pictured on both panels because this band is what a user meets instead of a false
        // multisig-attack accusation (KNOWN-ISSUES K31), and the thing worth checking by eye
        // is that no sentence on it names a cosigner or a registration.
        build: |ui| refused(ui, RefusalCode::UnsupportedScript),
    },
    Frame {
        name: "refusal/post-sign",
        variant: "post-sign",
        screen: ScreenId::Refusal,
        doc: Doc::None,
        // The device's own post-sign gate refusing. Nothing was signed and nothing was
        // written, and the way out is the wallet home rather than the file.
        build: |ui| {
            signing(ui);
            ui.sign_result(SignOutcome::Refused(dummy_refusal(
                RefusalCode::SignatureCheckFailed,
                true,
            )));
        },
    },

    // --- S-41 the multisig registry ----------------------------------------------------
    Frame {
        name: "multisig-list/empty",
        variant: "empty",
        screen: ScreenId::MultisigList,
        doc: Doc::Both("72-multisig-empty", "77-multisig-empty-800x480"),
        build: |ui| multisig_registry(ui, 0, Vec::new()),
    },
    Frame {
        name: "multisig-list/registered",
        variant: "registered",
        screen: ScreenId::MultisigList,
        doc: Doc::Both("73-multisig-registry", "78-multisig-registry-800x480"),
        // Two rows, one of each kind: a registration that proved out, and a slot that did
        // not and can only be erased.
        build: |ui| multisig_registry(ui, 2, dummy_registrations()),
    },
    Frame {
        name: "multisig-list/unreadable-claim",
        variant: "unreadable-claim",
        screen: ScreenId::MultisigList,
        doc: Doc::Portrait("74-multisig-unreadable-claim"),
        // The wallet record claims two and this device proved none. The screen must say so
        // rather than render the empty state, which would claim there are none.
        build: |ui| multisig_registry(ui, 2, Vec::new()),
    },
    Frame {
        name: "multisig-list/no-card",
        variant: "no-card",
        screen: ScreenId::MultisigList,
        doc: Doc::None,
        build: |ui| {
            multisig_registry(ui, 0, Vec::new());
            tap(ui, RegionId::MsImport);
            ui.card_result(CardOutcome::NoCard);
        },
    },
    Frame {
        name: "multisig-list/pick",
        variant: "pick",
        screen: ScreenId::MultisigList,
        doc: Doc::Portrait("75-multisig-pick-file"),
        build: |ui| {
            multisig_registry(ui, 0, Vec::new());
            tap(ui, RegionId::MsImport);
            ui.card_result(CardOutcome::Listed(dummy_multisig_card()));
        },
    },
    // --- C3, raised from the registry ---------------------------------------------------
    Frame {
        name: "working/multisig-reading-card",
        variant: "multisig-reading-card",
        screen: ScreenId::Working,
        doc: Doc::None,
        build: |ui| {
            multisig_registry(ui, 0, Vec::new());
            tap(ui, RegionId::MsImport);
        },
    },
    // --- S-42 the import review ---------------------------------------------------------
    Frame {
        name: "multisig-import/facts",
        variant: "facts",
        screen: ScreenId::MultisigImport,
        doc: Doc::Both("76-multisig-import", "79-multisig-import-800x480"),
        build: |ui| multisig_reviewing(ui, 1),
    },
    Frame {
        name: "multisig-import/cosigner",
        variant: "cosigner",
        screen: ScreenId::MultisigImport,
        doc: Doc::Portrait("80-multisig-cosigner"),
        build: |ui| {
            multisig_reviewing(ui, 1);
            tap(ui, RegionId::ReviewNext);
        },
    },
    Frame {
        name: "multisig-import/approve",
        variant: "approve",
        screen: ScreenId::MultisigImport,
        doc: Doc::Both("81-multisig-approve", "82-multisig-approve-800x480"),
        // The write page, reached by the traversal C5 requires: the first receive address,
        // the C12 notice naming what is written, and a live Approve.
        build: |ui| {
            multisig_reviewing(ui, 1);
            page_to(ui, RegionId::MsApprove);
        },
    },
    Frame {
        name: "multisig-import/not-a-member",
        variant: "not-a-member",
        screen: ScreenId::MultisigImport,
        doc: Doc::Both("83-multisig-not-a-member", "84-multisig-not-a-member-800x480"),
        // The most important frame in this set: a descriptor whose cosigner set does not
        // name this device, refused with no approve anywhere on the screen.
        build: |ui| multisig_reviewing(ui, 3),
    },
    Frame {
        name: "multisig-import/replace",
        variant: "replace",
        screen: ScreenId::MultisigImport,
        doc: Doc::Portrait("85-multisig-replace"),
        build: |ui| {
            multisig_registry(ui, 0, Vec::new());
            tap(ui, RegionId::MsImport);
            ui.card_result(CardOutcome::Listed(dummy_multisig_card()));
            tap(ui, RegionId::ListRow(0));
            let mut review = dummy_registration_review(1);
            review.duplicate = true;
            ui.import_result(ImportOutcome::Pending(review));
            page_to(ui, RegionId::MsApprove);
            tap(ui, RegionId::MsApprove);
        },
    },
    // --- S-43 the detail screen ---------------------------------------------------------
    Frame {
        name: "multisig-detail/saved",
        variant: "saved",
        screen: ScreenId::MultisigDetail,
        doc: Doc::Both("86-multisig-saved", "87-multisig-saved-800x480"),
        build: multisig_saved,
    },
    Frame {
        name: "multisig-detail/cosigners",
        variant: "cosigners",
        screen: ScreenId::MultisigDetail,
        doc: Doc::Portrait("88-multisig-cosigners"),
        build: |ui| {
            multisig_saved(ui);
            tap(ui, RegionId::MsCosigners);
        },
    },
    Frame {
        name: "multisig-detail/delete-typed",
        variant: "delete-typed",
        screen: ScreenId::MultisigDetail,
        doc: Doc::Portrait("89-multisig-delete-typed"),
        build: |ui| {
            multisig_saved(ui);
            tap(ui, RegionId::MsDelete);
            tap(ui, RegionId::DangerConfirm);
            type_keys(ui, "dummy");
        },
    },
    Frame {
        name: "multisig-detail/unreadable",
        variant: "unreadable",
        screen: ScreenId::MultisigDetail,
        doc: Doc::Portrait("90-multisig-unreadable-slot"),
        build: |ui| {
            multisig_registry(ui, 2, dummy_registrations());
            tap(ui, RegionId::ListRow(1));
        },
    },
];

/// The states a screen has to be photographed in, per screen.
///
/// EXHAUSTIVE on purpose. A nineteenth [`ScreenId`] does not compile until whoever added
/// it says what its states are, and the gate then fails until a frame exists for each of
/// them on every entry of [`notyas_ui::layout::PANELS`]. Coverage stops being a matter of
/// the catalogue author's diligence and becomes a declared obligation that fails closed.
///
/// A variant is a STATE, never a panel: a frame renders on all five panels by
/// construction, so "landscape" is not a thing a frame can be.
pub fn required_variants(screen: ScreenId) -> &'static [&'static str] {
    match screen {
        // The three store states that are reachable pre-PIN. Locked is not among them:
        // a device with a PIN shows the lock screen, and R20 keeps the other three off
        // it, so this is where they have to be seen.
        ScreenId::Home => &["fresh", "store-blank", "store-unreadable"],
        ScreenId::DiceEntry => &["empty", "typed", "word-count-mode"],
        // Six states, not three: the SAME screen shows a freshly derived set of words on
        // the create path and a stored wallet's words on the delete path, and the masking
        // law has to hold on both. The stored pair is what makes that a photographed fact
        // rather than a claim about shared code.
        ScreenId::MnemonicDisplay => {
            &["masked", "reveal-confirm", "revealed", "stored-masked", "stored-revealed"]
        }
        ScreenId::PhraseEntry => {
            &["empty", "typed", "autocomplete", "final-word", "final-word-sheet"]
        }
        ScreenId::PassphraseEntry => {
            &["off", "typed-masked", "typed-shown", "derive-intro"]
        }
        // The prompt, something typed into it, and the refusal - which is the state the
        // copy gate reads, because it is the only frame in the product that names two
        // wallet fingerprints to a user.
        ScreenId::PassphraseUnlock => &["prompt", "typed", "refused"],
        ScreenId::Deriving => &["running"],
        ScreenId::Schemes => &["bip44", "bip84", "qr"],
        ScreenId::Receive => &["receive"],
        ScreenId::VerifyDevice => {
            &["pre-pin", "digests", "unlocked", "reserved-space", "acknowledge"]
        }
        ScreenId::ScanningFlash => &["progress"],
        // "store-blank", "store-unreadable" and "store-not-provisioned" are deliberately
        // NOT here: `Ui::lock` is a no-op without a PIN (R20), so this screen cannot exist
        // in those states at all. They are Home variants, which is where they are gated.
        ScreenId::Lock => &["named", "no-name", "wipe-off"],
        ScreenId::PinEntry => &["fresh", "typed", "device-words", "wrong", "last-attempt"],
        // The two spec screens are one id, so the STEP is a state here. "not-provisioned"
        // is the one refusal a user can arrive at by walking forward: the fork sends every
        // device without a PIN to this screen, including one whose key was never burned.
        ScreenId::PinCreate => {
            &["step-1", "step-2", "typed", "mismatch", "refused", "not-provisioned"]
        }
        ScreenId::WalletList => &["none", "one", "many", "unreadable-slot"],
        ScreenId::BackupCheck => &["first-word"],
        ScreenId::KeepOrSave => &["fork"],
        ScreenId::NameWallet => &["empty", "typed", "save-notice"],
        // "stored-with-keys" is the state the PIN is for and the one that used to be
        // unreachable: a wallet the store holds AND whose derivation the embedder handed
        // over. It is the only one that offers Sign, and every frame below S-27 starts on
        // it.
        ScreenId::WalletHome => {
            &[
                "session",
                "stored",
                "stored-with-keys",
                "exit-modal",
                "delete-consequence",
                "delete-typed-name",
                // The three states of the identity row are two frames plus "stored", which
                // every other wallet-home frame above is: the row may never read "ON" or
                // "off", and the only way to prove that of all three is to render all
                // three.
                "passphrase-required",
                "passphrase-stored",
                "store-passphrase-consequence",
                "forget-passphrase-consequence",
                "forget-passphrase-hold",
                "storage-refused",
            ]
        }
        // S-47b's two states. The busy frame is not among them: it reports
        // `ScreenId::Working`, like every other C3 frame in the product, and is gated there.
        ScreenId::EraseWallet => &["offer", "words-refused"],
        // The PIN-removal sheet lives on S-44 itself rather than on the policy
        // sub-screen: it is opened from a settings row and draws over settings.
        ScreenId::Settings => {
            &["default", "network-testnet", "remove-pin-consequence", "remove-pin-typed"]
        }
        ScreenId::DeviceName => &["current", "typing", "refused"],
        ScreenId::AboutDeviceWords => &["explainer"],
        ScreenId::WipePolicy => {
            &["default", "edited", "wipe-off-arithmetic", "wipe-off-typed"]
        }
        // The two ingress screens. "reading" is S-27's own C3 frame and is claimed by a
        // Working frame, which is what `State::id` reports while the card read is in
        // flight - the id says the panel will not move, and the heading says which
        // operation is holding it.
        ScreenId::SignSource => &["ready", "empty", "no-card", "unreadable"],
        ScreenId::FilePicker => &["listing", "all-files", "empty", "paged"],
        // Every page the review has a DIFFERENT rendering for. The three that carry the
        // security argument are the ones a picture is worth most: an amount the file
        // states, a change claim the device could not prove, and the warnings page where
        // the hold either is or is not offered.
        ScreenId::ReviewTransaction => &[
            "overview",
            "input-proven",
            "input-stated",
            "input-bound",
            "output-external",
            "output-change",
            "output-data",
            "claimed-change",
            "fee-enforced",
            "fee-stated",
            "warnings-armed",
            "warnings-gated",
        ],
        ScreenId::Signing => &["signing"],
        ScreenId::Deliver => &[
            "complete",
            "partial",
            "written",
            "no-card",
            "write-failed",
            "overwrite-sheet",
            "discard-sheet",
        ],
        ScreenId::Refusal => {
            &["missing-prevtx", "change-not-proven", "details", "unsupported-script", "post-sign"]
        }
        // C3 is one screen for every blocking request in the product, so its variants are
        // named for the OPERATION that raised them and each lane adds its own.
        ScreenId::Working => &[
            "multisig-reading-card",
            "reading",
            "reading-card",
            "checking-transaction",
            "writing",
            // The longest blocking operation in the product, and the only one during which
            // "Do not remove the card" is load-bearing rather than polite.
            "formatting-card",
        ],
        ScreenId::MultisigList => {
            &["empty", "registered", "unreadable-claim", "no-card", "pick"]
        }
        // "not-a-member" is the state this screen exists for: a cosigner set that does not
        // name this device is the 2021 substitution attack, and a picture of the refusal is
        // a picture of the defence.
        ScreenId::MultisigImport => {
            &["facts", "cosigner", "approve", "not-a-member", "replace"]
        }
        ScreenId::MultisigDetail => &["saved", "cosigners", "delete-typed", "unreadable"],
        // Six states, and the ORDER of this list is the argument: the two the user is most
        // likely to see are the two in which nothing is erased.
        ScreenId::FormatCard => {
            &["offer", "refused", "consequence", "typed", "done", "failed"]
        }
    }
}

/// Render one frame on one panel, and prove it is the frame it claims to be.
pub fn build(frame: &Frame, panel: (u32, u32)) -> Ui {
    let mut ui = Ui::new(panel.0, panel.1);
    (frame.build)(&mut ui);
    assert_eq!(
        ui.screen(),
        frame.screen,
        "{} at {}x{}: the recipe landed on the wrong screen",
        frame.name,
        panel.0,
        panel.1
    );
    ui
}
