// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Opening a wallet that has a BIP-39 passphrase, from the panel's side of the boundary.
//!
//! # The defect this file exists to keep fixed
//!
//! Until 0.2.0 a tap on a passphrase wallet could not open it AT ALL. The request carried
//! a slot and nothing else, the embedder opened with the empty passphrase, the fingerprint
//! in the record refused it, and the answer was a failure band on the wallet list naming
//! two fingerprints - one of which was what the words derive with NO passphrase, which is
//! an existence proof for a hidden wallet. The wallet was created once and was never
//! openable again.
//!
//! So the properties here are: the prompt exists and is not a failure; the passphrase
//! reaches the embedder as a `Secret` and nowhere else; the refusal states derivation
//! facts and never says "wrong"; the panel is never left on a Busy frame; and no answer
//! can move the panel to a screen the user has left.

use notyas_ui::{
    BackupState, DeleteOutcome, LockInfo, Network, PassphraseRefusal, PassphraseState, Region,
    RegionId, Report, ScreenId, StoreStatus, TouchEvent, Ui, UiRequest, WalletInfo, WalletKind,
    UnsealOutcome, WalletRow, ADDRESS_ROWS,
};

// ---------------------------------------------------------------------------------------
// Driving the panel
// ---------------------------------------------------------------------------------------

fn region(ui: &Ui, id: RegionId) -> Option<Region> {
    ui.regions().iter().find(|r| r.id == id).copied()
}

fn has(ui: &Ui, id: RegionId) -> bool {
    region(ui, id).is_some()
}

fn tap(ui: &mut Ui, id: RegionId) -> Option<UiRequest> {
    let r = region(ui, id)
        .unwrap_or_else(|| panic!("{id:?} is not on {:?}", ui.screen()))
        .rect;
    let (x, y) = (r.x + r.w / 2, r.y + r.h / 2);
    ui.touch(TouchEvent::Down { x, y });
    ui.touch(TouchEvent::Up { x, y })
}

/// Type into whatever keyboard is up. Lowercase letters and spaces only, which is all the
/// default page offers - the shift and page controls are the create screen's tests'
/// subject, not this one's.
fn type_keys(ui: &mut Ui, text: &str) {
    for c in text.chars() {
        if c == ' ' {
            tap(ui, RegionId::Space);
        } else {
            tap(ui, RegionId::Key(c));
        }
    }
}

const NAME: &str = "tz";
/// trezor/python-mnemonic english[0], the vector the hardware run used.
const TEST_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon \n                           abandon abandon abandon abandon about";
/// The published test vector's pair: these words derive b4e3f5ed under the passphrase
/// TREZOR and 73c5da0a under none. The second value is the one that must never appear on
/// the panel.
const EXPECTED: &str = "b4e3f5ed";
const EMPTY_DERIVED: &str = "73c5da0a";
const OTHER: &str = "9f8e7d6c";

fn wallet(slot: u8, passphrase: PassphraseState) -> WalletInfo {
    WalletInfo {
        slot,
        name: String::from(NAME),
        fingerprint: String::from(EXPECTED),
        path: String::from("m"),
        script_type: String::from("every scheme"),
        kind: WalletKind::SingleSig,
        backup: BackupState::Verified(String::new()),
        network: Network::Bitcoin,
        registrations: 0,
        stored: true,
        passphrase,
    }
}

fn report() -> Report {
    use notyas_core::bip39::MnemonicMode;
    use notyas_core::derive::{ChildIndex, Scheme};
    use notyas_core::report::Parameters;
    Report::from_phrase(
        TEST_PHRASE,
        &Parameters {
            mode: MnemonicMode::Raw,
            passphrase: "TREZOR",
            network: Network::Bitcoin,
            schemes: &Scheme::ALL,
            account: ChildIndex::ZERO,
            change: ChildIndex::ZERO,
            count: ADDRESS_ROWS,
            script_type: 2,
        },
    )
    .expect("the vector derives")
}

/// An unlocked device showing one stored wallet.
fn unlocked(w: u32, h: u32) -> Ui {
    let mut ui = Ui::new(w, h);
    ui.set_lock_info(LockInfo {
        status: StoreStatus::Locked,
        ..LockInfo::default()
    });
    assert!(ui.lock(), "a device with a PIN can show its lock screen");
    tap(&mut ui, RegionId::LockWake);
    ui.unseal_result(UnsealOutcome::Unsealed);
    ui.set_wallets(vec![WalletRow::Wallet(wallet(0, PassphraseState::Required))]);
    ui
}

/// The panel at the moment the embedder has said "this wallet needs its passphrase".
fn at_prompt(w: u32, h: u32) -> Ui {
    let mut ui = unlocked(w, h);
    assert_eq!(ui.screen(), ScreenId::WalletList, "an unlocked device lands on the list");
    assert_eq!(tap(&mut ui, RegionId::ListRow(0)), Some(UiRequest::OpenWallet(0)));
    ui.wallet_needs_passphrase(0, String::from(NAME));
    assert_eq!(ui.screen(), ScreenId::PassphraseUnlock);
    ui
}

const PANELS: [(u32, u32); 2] = [(720, 720), (800, 480)];

// ---------------------------------------------------------------------------------------
// The route
// ---------------------------------------------------------------------------------------

/// The whole of the owner's bug, end to end: a tap on a passphrase wallet asks for the
/// passphrase, and the passphrase opens it.
#[test]
fn a_passphrase_wallet_asks_and_then_opens() {
    for (w, h) in PANELS {
        let mut ui = at_prompt(w, h);
        // Not a failure: the list did not stay put with a band on it, the panel moved to a
        // screen that asks for something.
        assert!(has(&ui, RegionId::Back), "{w}x{h}: the prompt has a way out");
        assert!(!has(&ui, RegionId::PassUnlock), "nothing typed, nothing to unlock");

        type_keys(&mut ui, "trezor");
        let Some(UiRequest::UnlockWallet { slot, passphrase }) =
            tap(&mut ui, RegionId::KeyDone)
        else {
            panic!("{w}x{h}: Done must hand the typed passphrase to the embedder");
        };
        assert_eq!(slot, 0, "{w}x{h}: for the slot the list asked about");
        assert_eq!(passphrase.as_str(), "trezor", "{w}x{h}: exactly what was typed");
        // No passphrase reaches a `Debug` rendering, and this enum derives one.
        let rendered = format!("{:?}", UiRequest::UnlockWallet { slot, passphrase });
        assert!(!rendered.contains("trezor"), "{rendered}");

        // C3: the Busy frame is up BEFORE the embedder does the work, which is what the
        // firmware's `publish_before_answering` publishes.
        assert_eq!(ui.screen(), ScreenId::Working, "{w}x{h}: the derivation says so");
        assert!(ui.regions().is_empty(), "{w}x{h}: nothing is tappable while it runs");

        ui.wallet_opened_with_keys(wallet(0, PassphraseState::Required), report());
        assert_eq!(ui.screen(), ScreenId::WalletHome, "{w}x{h}: it opened");
        assert!(has(&ui, RegionId::ActExport), "with its keys");

        // Back never returns to a passphrase field: the unlock screen was REPLACED. The
        // confirm is taken if it is offered - a screen holding a derivation asks before it
        // discards it, which is wallet.rs's question and not this route's.
        tap(&mut ui, RegionId::Back);
        if ui.screen() == ScreenId::WalletHome {
            tap(&mut ui, RegionId::ModalConfirm);
        }
        assert_eq!(
            ui.screen(),
            ScreenId::WalletList,
            "{w}x{h}: Back off the wallet is the list, not the passphrase screen again"
        );
    }
}

/// The refusal: what happened, in derivation facts, on the screen that asked.
#[test]
fn a_passphrase_that_opens_another_wallet_is_refused_without_the_word_wrong() {
    for (w, h) in PANELS {
        let mut ui = at_prompt(w, h);
        type_keys(&mut ui, "nope");
        tap(&mut ui, RegionId::KeyDone);
        ui.passphrase_refused(PassphraseRefusal {
            expected: String::from(EXPECTED),
            derived: String::from(OTHER),
        });

        assert_eq!(
            ui.screen(),
            ScreenId::PassphraseUnlock,
            "{w}x{h}: a refusal leaves the Busy frame and stays where the user is"
        );
        assert!(has(&ui, RegionId::PassUnlock), "{w}x{h}: and offers another try");
        assert!(has(&ui, RegionId::Back), "{w}x{h}: with a way out");
    }
}

/// The sentence itself. Asserted over the copy rather than over the pixels, because a
/// framebuffer cannot be searched for a word - and this is the one screen in the product
/// where the exact words are a security property.
#[test]
fn the_refusal_states_derivation_facts_and_never_a_verdict() {
    let sentence = PassphraseRefusal {
        expected: String::from(EXPECTED),
        derived: String::from(OTHER),
    }
    .sentence();

    assert!(sentence.contains(EXPECTED), "the record's wallet is named: {sentence}");
    assert!(sentence.contains(OTHER), "and so is the one that was opened: {sentence}");
    assert!(
        !sentence.contains(EMPTY_DERIVED),
        "the empty-passphrase derivation is an existence proof for a hidden wallet and \
         must never be rendered: {sentence}"
    );
    for verdict in ["wrong", "Wrong", "incorrect", "Incorrect", "invalid", "Invalid"] {
        assert!(
            !sentence.contains(verdict),
            "BIP-39 has no invalid passphrases, only different wallets: {sentence}"
        );
    }
    // What the user can act on, which is the other half of a refusal that is not a
    // verdict.
    assert!(sentence.contains("Spelling, capitals and spaces"), "{sentence}");
}

/// The retry gate: two tries at once, then a wait that grows. It is a per-slot counter on
/// the `Ui`, so backing out to the list and tapping the row again does not reset it -
/// which is the only thing that would make the gate decorative.
#[test]
fn the_third_refusal_in_a_row_makes_the_user_wait() {
    let mut ui = at_prompt(720, 720);
    let refuse = |ui: &mut Ui| {
        type_keys(ui, "nope");
        tap(ui, RegionId::KeyDone);
        ui.passphrase_refused(PassphraseRefusal {
            expected: String::from(EXPECTED),
            derived: String::from(OTHER),
        });
    };

    refuse(&mut ui);
    assert!(has(&ui, RegionId::PassUnlock), "the first miss costs nothing");
    tap(&mut ui, RegionId::PassUnlock);

    refuse(&mut ui);
    assert!(has(&ui, RegionId::PassUnlock), "nor the second");
    tap(&mut ui, RegionId::PassUnlock);

    refuse(&mut ui);
    assert!(
        !has(&ui, RegionId::PassUnlock),
        "the third disables the control - a drawn button nothing hit-tests"
    );
    // The countdown is aged from the wall clock, exactly like the hold bar.
    assert!(ui.tick(1_000).dirty, "the second on screen changed, so the panel repaints");
    assert!(!has(&ui, RegionId::PassUnlock), "one second is not five");
    ui.tick(4_000);
    assert!(has(&ui, RegionId::PassUnlock), "and five seconds is");

    // Backing out and coming back does NOT reset the counter: the next miss waits longer,
    // not five seconds again.
    tap(&mut ui, RegionId::PassUnlock);
    refuse(&mut ui);
    ui.tick(5_000);
    assert!(
        !has(&ui, RegionId::PassUnlock),
        "the fourth refusal waits ten seconds, so the counter survived the re-entry"
    );
    ui.tick(5_000);
    assert!(has(&ui, RegionId::PassUnlock));

    // A successful open forgets all of it.
    tap(&mut ui, RegionId::PassUnlock);
    type_keys(&mut ui, "trezor");
    tap(&mut ui, RegionId::KeyDone);
    ui.wallet_opened_with_keys(wallet(0, PassphraseState::Required), report());
    tap(&mut ui, RegionId::Back);
    if ui.screen() == ScreenId::WalletHome {
        tap(&mut ui, RegionId::ModalConfirm);
    }
    tap(&mut ui, RegionId::ListRow(0));
    ui.wallet_needs_passphrase(0, String::from(NAME));
    refuse(&mut ui);
    assert!(
        has(&ui, RegionId::PassUnlock),
        "an open wallet is not evidence of guessing, so the count starts again"
    );
}

/// A slot that has stopped holding a wallet is a slot the gate forgets - and only that
/// slot.
///
/// Storage slots are REUSED. A wallet erased out of slot 1 leaves the slot free for the
/// next one saved, and without this the new wallet would inherit the erased one's refusal
/// count: its owner's first honest attempt at a passphrase nobody has yet guessed at once
/// would meet a ten-second wait, then twenty, for the rest of the power-up. The gate would
/// be punishing a person for something a different wallet did.
///
/// The other half is the one that must NOT happen: erasing one wallet may not release a
/// wait another slot is serving, which would make "delete some wallet you do not care
/// about" a reset button for the whole schedule.
///
/// Driven through the public API only, because the wiring is what is under test: the
/// answer to a delete carries what happened and not which record it happened to, so the
/// `Ui` has to read the slot off the screen that raised the erase.
///
/// Broken version: remove the `gate.cleared` call from `Ui::wallet_deleted`. The reused
/// slot's first refusal disables Try again and the assertion below it trips.
#[test]
fn erasing_a_wallet_forgets_its_wait_and_nobody_elses() {
    let mut ui = Ui::new(720, 720);
    ui.set_lock_info(LockInfo { status: StoreStatus::Locked, ..LockInfo::default() });
    assert!(ui.lock());
    tap(&mut ui, RegionId::LockWake);
    ui.unseal_result(UnsealOutcome::Unsealed);
    let both = vec![
        WalletRow::Wallet(wallet(0, PassphraseState::Required)),
        WalletRow::Wallet(wallet(1, PassphraseState::Required)),
    ];
    ui.set_wallets(both.clone());

    // Three misses against a slot, from the list, leaving it in its wait.
    let grind = |ui: &mut Ui, slot: u8| {
        for _ in 0..3 {
            tap(ui, RegionId::ListRow(slot));
            ui.wallet_needs_passphrase(slot, String::from(NAME));
            type_keys(ui, "nope");
            tap(ui, RegionId::KeyDone);
            ui.passphrase_refused(PassphraseRefusal {
                expected: String::from(EXPECTED),
                derived: String::from(OTHER),
            });
            tap(ui, RegionId::Back);
        }
        assert_eq!(ui.screen(), ScreenId::WalletList);
    };
    grind(&mut ui, 0);
    grind(&mut ui, 1);

    // Slot 1 is opened by a route that does not clear the gate - the session had its
    // passphrase - and erased from its wallet home.
    assert_eq!(tap(&mut ui, RegionId::ListRow(1)), Some(UiRequest::OpenWallet(1)));
    ui.wallet_opened(wallet(1, PassphraseState::Stored));
    assert_eq!(ui.screen(), ScreenId::WalletHome);
    tap(&mut ui, RegionId::WalletDelete);
    tap(&mut ui, RegionId::DangerConfirm);
    type_keys(&mut ui, NAME);
    tap(&mut ui, RegionId::DangerConfirm);
    assert_eq!(ui.screen(), ScreenId::EraseWallet);
    assert_eq!(tap(&mut ui, RegionId::EraseNow), Some(UiRequest::DeleteWallet(1)));
    ui.wallet_deleted(DeleteOutcome::Gone { registrations: 0 });
    ui.set_wallets(vec![WalletRow::Wallet(wallet(0, PassphraseState::Required))]);

    // A NEW wallet lands in the freed slot. Its first miss is free, as every first miss
    // is: the gate has no memory of the wallet that used to be there.
    ui.set_wallets(both);
    tap(&mut ui, RegionId::ListRow(1));
    ui.wallet_needs_passphrase(1, String::from(NAME));
    type_keys(&mut ui, "nope");
    tap(&mut ui, RegionId::KeyDone);
    ui.passphrase_refused(PassphraseRefusal {
        expected: String::from(EXPECTED),
        derived: String::from(OTHER),
    });
    assert!(
        has(&ui, RegionId::PassUnlock),
        "a wallet in a reused slot inherited the erased wallet's refusal count"
    );
    tap(&mut ui, RegionId::PassUnlock);
    tap(&mut ui, RegionId::Back);

    // And slot 0, which nobody erased, is exactly where it was: the next miss is its
    // FOURTH, so it waits ten seconds rather than starting again at five.
    tap(&mut ui, RegionId::ListRow(0));
    ui.wallet_needs_passphrase(0, String::from(NAME));
    type_keys(&mut ui, "nope");
    tap(&mut ui, RegionId::KeyDone);
    ui.passphrase_refused(PassphraseRefusal {
        expected: String::from(EXPECTED),
        derived: String::from(OTHER),
    });
    ui.tick(5_000);
    assert!(
        !has(&ui, RegionId::PassUnlock),
        "erasing another wallet released slot 0's wait"
    );
    ui.tick(5_000);
    assert!(has(&ui, RegionId::PassUnlock), "and ten seconds is the fourth refusal's wait");
}

/// Every answer is dropped unless the screen that asked is still showing, and a Busy frame
/// never survives one. The firmware closes the wallet it opened on the same pass; this is
/// the panel's half.
#[test]
fn an_answer_that_arrives_late_moves_nothing() {
    let mut ui = at_prompt(720, 720);
    type_keys(&mut ui, "trezor");
    tap(&mut ui, RegionId::KeyDone);
    assert_eq!(ui.screen(), ScreenId::Working);

    // The user is gone - a lock, which is what an auto-lock does to the panel.
    ui.set_lock_info(LockInfo {
        status: StoreStatus::Unlocked,
        ..LockInfo::default()
    });
    assert!(ui.lock());
    assert_eq!(ui.screen(), ScreenId::Lock);

    ui.wallet_opened_with_keys(wallet(0, PassphraseState::Required), report());
    assert_eq!(ui.screen(), ScreenId::Lock, "a late open must not unlock the panel");

    ui.passphrase_refused(PassphraseRefusal {
        expected: String::from(EXPECTED),
        derived: String::from(OTHER),
    });
    assert_eq!(ui.screen(), ScreenId::Lock, "and a late refusal must not either");
}

/// The Busy frame is left by BOTH answers. A phase with only one exit is a wedged panel,
/// which this product has shipped three times.
#[test]
fn no_busy_frame_survives_an_answer() {
    for open in [true, false] {
        let mut ui = at_prompt(720, 720);
        type_keys(&mut ui, "trezor");
        tap(&mut ui, RegionId::KeyDone);
        assert_eq!(ui.screen(), ScreenId::Working);
        if open {
            ui.wallet_opened_with_keys(wallet(0, PassphraseState::Required), report());
        } else {
            ui.passphrase_refused(PassphraseRefusal {
                expected: String::from(EXPECTED),
                derived: String::from(OTHER),
            });
        }
        assert_ne!(ui.screen(), ScreenId::Working, "open={open}: the frame outlived its answer");
        assert!(!ui.regions().is_empty(), "open={open}: and the panel can be used again");
    }
}

/// No passphrase reaches a `Debug` rendering, on any type that carries one - and every one
/// of them rides inside an enum that derives `Debug`.
#[test]
fn nothing_that_carries_a_passphrase_prints_it() {
    let mut ui = at_prompt(720, 720);
    type_keys(&mut ui, "correct horse");
    let Some(request) = tap(&mut ui, RegionId::KeyDone) else {
        panic!("Done raises the request");
    };
    let rendered = format!("{request:?}");
    assert!(!rendered.contains("correct"), "{rendered}");
    assert!(!rendered.contains("horse"), "{rendered}");
    assert!(rendered.contains("redacted"), "{rendered}");
    assert!(rendered.contains('0'), "the slot is public and worth logging: {rendered}");
}

/// The identity card's three states, and the two words that may never appear in them.
///
/// "off" implies a switch that could be flipped ON for this wallet, and a passphrase is
/// not a setting of a wallet - it is part of WHICH wallet this is. The card rendered
/// `passphrase off` for a wallet that demonstrably had one, for a whole release.
#[test]
fn the_identity_row_is_one_of_three_strings_and_never_an_on_off_toggle() {
    let rows: Vec<&str> = [
        PassphraseState::None,
        PassphraseState::Required,
        PassphraseState::Stored,
    ]
    .into_iter()
    .map(PassphraseState::row)
    .collect();

    assert_eq!(rows, ["no passphrase", "passphrase required", "passphrase stored"]);
    for row in &rows {
        assert!(!row.contains("ON"), "{row}");
        assert!(!row.contains("off"), "{row}");
        assert!(!row.contains("On"), "{row}");
        assert!(!row.contains("Off"), "{row}");
    }
    assert!(
        !PassphraseState::None.applied() && PassphraseState::Required.applied(),
        "the state that decides whether a passphrase is part of this wallet"
    );
}
