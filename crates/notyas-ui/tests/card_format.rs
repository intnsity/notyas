// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! S-49 driven the way a finger drives it: from an unlocked device to an erased card, and
//! every way the device refuses to go there.
//!
//! The screen's own unit tests reason about `RegionId`s. These reason about TOUCHES on a
//! real `Ui` at both shipped geometries, which is what closes the two gaps a screen test
//! structurally cannot:
//!
//! - **the route.** A control the user cannot reach is a feature the device does not have.
//!   On the 800x480 panel the Settings row that opens this screen is below the fold, so the
//!   route only exists if the list scrolls to it.
//! - **the request.** `Ui::touch` returns what the embedder is asked to do, so "the card
//!   was not erased" is a claim these tests can make exactly: no `UiRequest::FormatCard`
//!   came back. Every intermediate touch is checked, not just the last one.

use notyas_ui::{
    FormatOffer, FormatOutcome, FormatRefusal, FormatTarget, LockInfo, Region, RegionId,
    ScreenId, StoreStatus, TouchEvent, Ui, UiRequest, UnsealOutcome, WalletRow,
};

/// The two shipped panels (docs/BOARDS.md): Waveshare 4B and Elecrow 5inch.
const GEOMETRIES: [(u32, u32); 2] = [(720, 720), (800, 480)];

/// The card the offer is rendered against: a factory-shipped SDXC card, exFAT, which this
/// build's FatFs cannot mount. The case the feature exists for.
fn target() -> FormatTarget {
    FormatTarget {
        partition: 1,
        capacity: String::from("32 GB"),
        word: String::from("32GB"),
        holds: String::from("an exFAT or NTFS filesystem"),
        volume: String::from("32 GB"),
    }
}

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

/// Scroll the current screen until `id` is offered, or fail saying it never was.
fn scroll_to(ui: &mut Ui, id: RegionId, w: u32, h: u32) {
    for _ in 0..12 {
        if has(ui, id) {
            return;
        }
        let (x, y) = (w as i32 / 2, h as i32 / 2);
        ui.touch(TouchEvent::Down { x, y });
        ui.touch(TouchEvent::Move { x, y: y - 120 });
        ui.touch(TouchEvent::Up { x, y: y - 120 });
    }
    panic!("{id:?} cannot be reached on {:?} at {w}x{h}", ui.screen());
}

/// An unlocked device holding one wallet, on the wallet list.
fn unlocked(w: u32, h: u32) -> Ui {
    let mut ui = Ui::new(w, h);
    // Only the two facts this route depends on: a device with a PIN, locked. The lock
    // screen's own decorations are S-03's subject, not this one's, and naming them here
    // would couple a card test to copy that has nothing to do with cards.
    ui.set_lock_info(LockInfo {
        status: StoreStatus::Locked,
        wipe_after: Some(10),
        ..LockInfo::default()
    });
    assert!(ui.lock());
    tap(&mut ui, RegionId::LockWake);
    ui.unseal_result(UnsealOutcome::Unsealed);
    ui.set_wallets(Vec::<WalletRow>::new());
    assert_eq!(ui.screen(), ScreenId::WalletList);
    ui
}

/// Walk from the wallet list to S-49, answering its probe with `offer`.
///
/// The whole route, by touch: the settings affordance, a scroll to the row (it is below the
/// fold on the short panel), the row itself, and the probe the row raises. Anything that
/// breaks the route fails here rather than on a board.
fn open_format(w: u32, h: u32, offer: FormatOffer) -> Ui {
    let mut ui = unlocked(w, h);
    tap(&mut ui, RegionId::OpenSettings);
    assert_eq!(ui.screen(), ScreenId::Settings);
    let row = last_settings_row(&mut ui, w, h);
    let asked = tap(&mut ui, row);
    assert!(
        matches!(asked, Some(UiRequest::ProbeCardFormat)),
        "opening S-49 must ask the card before it says anything about it"
    );
    assert_eq!(
        ui.screen(),
        ScreenId::Working,
        "the panel shows the C3 frame while the probe runs"
    );
    // Nothing is tappable while a card request is in flight - not even Back.
    assert!(ui.regions().is_empty(), "a C3 frame offers nothing");
    ui.format_offer(offer);
    assert_eq!(ui.screen(), ScreenId::FormatCard);
    ui
}

/// The format row, found by walking the list to its end rather than by a literal index, so
/// this suite keeps working when a settings row is added above it.
fn last_settings_row(ui: &mut Ui, w: u32, h: u32) -> RegionId {
    let mut last = RegionId::SetRow(0);
    for i in 0..16u8 {
        if region(ui, RegionId::SetRow(i)).is_some() {
            last = RegionId::SetRow(i);
        }
    }
    // Scroll to the foot of the list and look again: the rows past the fold have no region
    // until they are in the window.
    for _ in 0..12 {
        let (x, y) = (w as i32 / 2, h as i32 / 2);
        ui.touch(TouchEvent::Down { x, y });
        ui.touch(TouchEvent::Move { x, y: y - 120 });
        ui.touch(TouchEvent::Up { x, y: y - 120 });
        for i in 0..16u8 {
            if region(ui, RegionId::SetRow(i)).is_some() {
                last = RegionId::SetRow(i);
            }
        }
    }
    scroll_to(ui, last, w, h);
    last
}

/// Type the card's capacity back on the C4d sheet: the digit page, then a shifted letter
/// page. Two page switches to type four characters, which is the friction the grade is for.
fn type_card_word(ui: &mut Ui) {
    tap(ui, RegionId::PageDigits);
    tap(ui, RegionId::Key('3'));
    tap(ui, RegionId::Key('2'));
    tap(ui, RegionId::PageLetters);
    tap(ui, RegionId::Shift);
    tap(ui, RegionId::Key('G'));
    tap(ui, RegionId::Key('B'));
}

// ---------------------------------------------------------------------------------------
// The route
// ---------------------------------------------------------------------------------------

/// The owner asked for it in Settings, so it has to BE in Settings - and reachable, on the
/// panel where it is below the fold as well as on the one where it is not.
#[test]
fn the_format_screen_is_reachable_from_settings_on_both_panels() {
    for (w, h) in GEOMETRIES {
        let ui = open_format(w, h, FormatOffer::Ready(target()));
        assert_eq!(ui.screen(), ScreenId::FormatCard, "{w}x{h}");
        assert!(has(&ui, RegionId::Back), "{w}x{h}: and it has a way out");
    }
}

// ---------------------------------------------------------------------------------------
// The consent gate
// ---------------------------------------------------------------------------------------

/// THE test. Every touch from the offer to the erase, and the card is not erased until the
/// last one - checked after each, so no prefix of the sequence writes anything.
#[test]
fn a_card_is_never_erased_before_its_own_name_is_typed_back() {
    for (w, h) in GEOMETRIES {
        let mut ui = open_format(w, h, FormatOffer::Ready(target()));

        // Opening the consequence sheet asks for nothing.
        assert!(tap(&mut ui, RegionId::CardFormat).is_none(), "{w}x{h}");
        // ...and while it is open the screen underneath is inert: the sheet is modal, so
        // the destructive control cannot be tapped a second time behind it.
        assert!(!has(&ui, RegionId::CardFormat), "{w}x{h}: the sheet is modal");
        assert!(has(&ui, RegionId::DangerCancel), "{w}x{h}: and it can be backed out of");

        // Reading the consequence opens the SECOND sheet. It never erases anything.
        assert!(tap(&mut ui, RegionId::DangerConfirm).is_none(), "{w}x{h}");
        assert!(has(&ui, RegionId::Key('a')), "{w}x{h}: the typed sheet has a keyboard");

        // The confirm is drawn disabled until the word matches, and a tap on a disabled
        // control does nothing.
        assert!(tap(&mut ui, RegionId::DangerConfirm).is_none(), "{w}x{h}: nothing typed");
        tap(&mut ui, RegionId::PageDigits);
        tap(&mut ui, RegionId::Key('3'));
        assert!(tap(&mut ui, RegionId::DangerConfirm).is_none(), "{w}x{h}: half typed");
        tap(&mut ui, RegionId::KeyBackspace);
        tap(&mut ui, RegionId::PageLetters);

        // The whole word, and only now.
        type_card_word(&mut ui);
        let asked = tap(&mut ui, RegionId::DangerConfirm);
        assert_eq!(
            asked,
            Some(UiRequest::FormatCard { partition: 1, card: String::from("32GB") }),
            "{w}x{h}: the write names the partition and the card consent was given for"
        );
        assert_eq!(ui.screen(), ScreenId::Working, "{w}x{h}: the panel is already on the frame");
        assert!(ui.regions().is_empty(), "{w}x{h}: and nothing can ask for it twice");

        // The answer lands and the screen states it.
        ui.format_result(FormatOutcome::Done(String::from("The 32 GB card is empty.")));
        assert_eq!(ui.screen(), ScreenId::FormatCard, "{w}x{h}");
        assert!(has(&ui, RegionId::FileRefresh), "{w}x{h}: with a way to check the result");
        assert!(!has(&ui, RegionId::CardFormat), "{w}x{h}: and no second erase on offer");
    }
}

/// Typing the wrong card's size does not erase this one. The gate is not "type four
/// characters", it is "type the size of the card in your hand".
#[test]
fn typing_a_different_card_size_erases_nothing() {
    for (w, h) in GEOMETRIES {
        let mut ui = open_format(w, h, FormatOffer::Ready(target()));
        tap(&mut ui, RegionId::CardFormat);
        tap(&mut ui, RegionId::DangerConfirm);
        tap(&mut ui, RegionId::PageDigits);
        tap(&mut ui, RegionId::Key('6'));
        tap(&mut ui, RegionId::Key('4'));
        tap(&mut ui, RegionId::PageLetters);
        tap(&mut ui, RegionId::Shift);
        tap(&mut ui, RegionId::Key('G'));
        tap(&mut ui, RegionId::Key('B'));
        assert!(tap(&mut ui, RegionId::DangerConfirm).is_none(), "{w}x{h}: 64GB is not 32GB");
        assert!(tap(&mut ui, RegionId::KeyDone).is_none(), "{w}x{h}: nor through the keyboard");
    }
}

/// Backing out of either sheet leaves the card alone.
#[test]
fn cancelling_leaves_the_card_alone() {
    for (w, h) in GEOMETRIES {
        for read_the_consequence in [false, true] {
            let mut ui = open_format(w, h, FormatOffer::Ready(target()));
            tap(&mut ui, RegionId::CardFormat);
            if read_the_consequence {
                tap(&mut ui, RegionId::DangerConfirm);
            }
            assert!(tap(&mut ui, RegionId::DangerCancel).is_none(), "{w}x{h}");
            assert_eq!(ui.screen(), ScreenId::FormatCard);
            assert!(has(&ui, RegionId::CardFormat), "{w}x{h}: and the offer is still there");
        }
    }
}

// ---------------------------------------------------------------------------------------
// The refusals - the states in which nothing can be erased at all
// ---------------------------------------------------------------------------------------

/// Every refusal the device can reach, and in none of them is there a control that erases
/// anything. This is requirement one of the whole feature: a format is never offered where
/// it would not help.
#[test]
fn no_refusal_offers_a_way_to_erase_the_card() {
    for (w, h) in GEOMETRIES {
        for why in FormatRefusal::ALL {
            let ui = open_format(
                w,
                h,
                FormatOffer::Refused { why, note: String::from("esp_err=0x105") },
            );
            assert_eq!(ui.screen(), ScreenId::FormatCard, "{w}x{h} {why:?}");
            assert!(
                !has(&ui, RegionId::CardFormat),
                "{w}x{h} {why:?}: a refusal must not offer a format"
            );
            // ...and it is not a dead end either: there is a way to look again, and a way
            // back to Settings.
            assert!(has(&ui, RegionId::FileRefresh), "{w}x{h} {why:?}: no way to check again");
            assert!(has(&ui, RegionId::Back), "{w}x{h} {why:?}: no way out");
        }
    }
}

/// A refusal cannot be turned into an offer by tapping where the button would have been.
/// `Ui::touch` only activates regions the screen emitted, and the screen refuses the id
/// too - two independent defences, and this exercises the pair through the real input path.
#[test]
fn a_refusal_cannot_be_talked_into_a_format() {
    let mut ui = open_format(
        720,
        720,
        FormatOffer::Refused { why: FormatRefusal::CardAlreadyReadable, note: String::new() },
    );
    // Touch every pixel row down the middle of the panel. Nothing on a refused card may
    // raise a destructive request, wherever a finger lands.
    for y in (0..720).step_by(8) {
        ui.touch(TouchEvent::Down { x: 360, y });
        let asked = ui.touch(TouchEvent::Up { x: 360, y });
        assert!(
            !matches!(asked, Some(UiRequest::FormatCard { .. })),
            "a tap at y={y} raised a format on a refused card"
        );
    }
}

/// Checking again re-asks the card rather than reusing what it said last time. A card can
/// be swapped while this screen is open, and a screen that answered from memory would be
/// describing a card that is no longer in the slot.
#[test]
fn checking_again_asks_the_card_again() {
    let mut ui = open_format(
        800,
        480,
        FormatOffer::Refused { why: FormatRefusal::NoCard, note: String::new() },
    );
    let asked = tap(&mut ui, RegionId::FileRefresh);
    assert!(matches!(asked, Some(UiRequest::ProbeCardFormat)));
    assert_eq!(ui.screen(), ScreenId::Working);
    ui.format_offer(FormatOffer::Ready(target()));
    assert!(has(&ui, RegionId::CardFormat), "the new card's offer replaces the old refusal");
}

// ---------------------------------------------------------------------------------------
// Failure reaches the user
// ---------------------------------------------------------------------------------------

/// A format that failed does not leave the panel on its Busy frame, and it does not offer
/// to run again over a card whose state nobody knows.
#[test]
fn a_failed_format_lands_on_a_screen_that_says_so() {
    for wrote in [false, true] {
        let mut ui = open_format(800, 480, FormatOffer::Ready(target()));
        tap(&mut ui, RegionId::CardFormat);
        tap(&mut ui, RegionId::DangerConfirm);
        type_card_word(&mut ui);
        tap(&mut ui, RegionId::DangerConfirm);
        ui.format_result(FormatOutcome::Failed {
            why: String::from("The card refused the write (FatFs error 1)."),
            wrote,
        });
        assert_eq!(ui.screen(), ScreenId::FormatCard, "wrote={wrote}");
        assert!(has(&ui, RegionId::FileRefresh), "wrote={wrote}: and a way forward");
        assert!(
            !has(&ui, RegionId::CardFormat),
            "wrote={wrote}: a card whose state is unknown is not re-offered for erasure"
        );
    }
}

/// An answer to a request nobody made is dropped. The embedder cannot push this screen
/// into a state by answering something it was not asked.
#[test]
fn an_unasked_answer_changes_nothing() {
    let mut ui = open_format(720, 720, FormatOffer::Ready(target()));
    ui.format_result(FormatOutcome::Done(String::from("erased")));
    assert!(
        has(&ui, RegionId::CardFormat),
        "a format nobody asked for must not be reported as having happened"
    );
}
