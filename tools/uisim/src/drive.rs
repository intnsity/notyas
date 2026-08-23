// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Driving a [`Ui`] the way a finger does.
//!
//! Every helper here resolves a [`RegionId`] against what the screen is CURRENTLY
//! offering and taps its centre, so no screen in this crate is reached any way a user
//! could not reach it. A frame recipe that stops working because a control moved fails
//! loudly at the missing region rather than quietly photographing a different screen.

use notyas_ui::{
    LockInfo, RegionId, StoreStatus, TouchEvent, Ui, UiRequest, UnsealOutcome, WalletRow,
};

use crate::fixtures::{dummy_lock_info, dummy_verify_info, dummy_wallets};

/// The region with this id, or a panic naming the screen that did not offer it.
pub fn region(ui: &Ui, id: RegionId) -> notyas_ui::Region {
    ui.regions()
        .into_iter()
        .find(|r| r.id == id)
        .unwrap_or_else(|| panic!("no region {id:?} on {:?}", ui.screen()))
}

pub fn ui_has(ui: &Ui, id: RegionId) -> bool {
    ui.regions().iter().any(|r| r.id == id)
}

/// Down and up on the centre of a region, which is what a tap is.
pub fn tap(ui: &mut Ui, id: RegionId) -> Option<UiRequest> {
    let r = region(ui, id).rect;
    let (x, y) = (r.x + r.w / 2, r.y + r.h / 2);
    ui.touch(TouchEvent::Down { x, y });
    ui.touch(TouchEvent::Up { x, y })
}

/// Down on the centre of a region, and left there.
///
/// Half a tap, and the beginning of every hold. It returns nothing because a press is not
/// an activation: no screen in this crate acts on the touch, only on the release or on the
/// fill, which is the property [`hold`] depends on.
pub fn press(ui: &mut Ui, id: RegionId) {
    let r = region(ui, id).rect;
    ui.touch(TouchEvent::Down { x: r.x + r.w / 2, y: r.y + r.h / 2 });
}

/// Advance the wall clock by `ms`, with the finger wherever it was left.
///
/// The one input here that is not a touch, and the other half of a hold. A press aged part
/// of the way is a C4c bar caught mid-fill - a state no tap can produce and no still frame
/// of the catalogue holds, because the gesture is the thing being shown.
pub fn age(ui: &mut Ui, ms: u32) -> Option<UiRequest> {
    ui.tick(ms).request
}

pub fn type_dice(ui: &mut Ui, digits: &str) {
    for c in digits.chars() {
        tap(ui, RegionId::Digit(c as u8 - b'0'));
    }
}

pub fn type_keys(ui: &mut Ui, s: &str) {
    for c in s.chars() {
        if c == ' ' {
            tap(ui, RegionId::Space);
        } else {
            tap(ui, RegionId::Key(c));
        }
    }
}

/// Type an uppercase word the way a finger does: shift, then the letters. The
/// confirmation words are uppercase precisely so that typing one is a deliberate act.
pub fn type_shifted(ui: &mut Ui, word: &str) {
    tap(ui, RegionId::Shift);
    for c in word.chars() {
        tap(ui, RegionId::Key(c));
    }
}

/// Answer the mandatory backup check (S-17) correctly.
///
/// The driver is in the position of someone holding the words: the candidates are on
/// screen and one of them is right, so it tries them. A wrong answer re-poses the same
/// word with a fresh set, which is why the view is read again after every tap rather than
/// walked once.
pub fn answer_quiz(ui: &mut Ui) {
    let mut taps = 0;
    while let Some(view) = ui.quiz() {
        for i in 0..view.choices.len() as u8 {
            tap(ui, RegionId::QuizChoice(i));
            taps += 1;
            assert!(taps < 2000, "the backup check never advanced");
            match ui.quiz() {
                Some(v) if v.done > view.done => break,
                None => break,
                _ => {}
            }
        }
    }
}

/// Hold a C4c bar until it fires, the way a finger does.
///
/// Down, then the wall clock. `Ui::tick` is what ages a press and what fires a filled hold -
/// a tap cannot do it, deliberately, because a tap can be caused by a jolt or a wet panel -
/// so the driver has to do both. The finger is left DOWN afterwards, which is what the panel
/// actually looks like at the moment a hold completes.
pub fn hold(ui: &mut Ui, id: RegionId) -> Option<UiRequest> {
    press(ui, id);
    let ticked = ui.tick(notyas_ui::HOLD_MS + 1);
    assert!(ticked.dirty, "a filled hold must move the panel");
    ticked.request
}

/// Page a review sheet forward `n` times, exactly as a finger does.
///
/// Sequential and never a jump: the visited set that gates the hold counts pages SEEN, so a
/// driver that could land on page 9 without passing through the others would be photographing
/// a state the screen does not let a user reach.
pub fn page_forward(ui: &mut Ui, n: usize) {
    for step in 0..n {
        assert!(
            ui_has(ui, RegionId::ReviewNext),
            "the review ran out of pages after {step} of {n}"
        );
        tap(ui, RegionId::ReviewNext);
    }
}

/// Page a review sheet forward until it offers `id`, exactly as a finger reaches it.
pub fn page_to(ui: &mut Ui, id: RegionId) {
    let mut steps = 0;
    while !ui_has(ui, id) {
        assert!(ui_has(ui, RegionId::ReviewNext), "{id:?} is unreachable on {:?}", ui.screen());
        tap(ui, RegionId::ReviewNext);
        steps += 1;
        assert!(steps < 64, "the pager never reached {id:?}");
    }
}

/// Drag a scrolling list until `id` is reachable, exactly as a finger does it.
///
/// The counterpart to [`page_to`] for the screens that scroll instead of paging. It drags
/// rather than reaching into the state, so a row this cannot reach is a row a user cannot
/// reach either - which is the property the frame is being built to photograph.
pub fn scroll_to(ui: &mut Ui, id: RegionId) {
    // Well inside the body of the shortest shipped panel (480 px) and the narrowest
    // (720 px), and a drag is acted on wherever it starts, so these coordinates are about
    // being ON the panel and nothing else.
    let (x, from, to) = (100, 400, 240);
    for step in 0..16 {
        if ui_has(ui, id) {
            return;
        }
        ui.touch(TouchEvent::Down { x, y: from });
        ui.touch(TouchEvent::Move { x, y: to });
        ui.touch(TouchEvent::Up { x, y: to });
        assert!(step < 15, "{id:?} is unreachable by scrolling on {:?}", ui.screen());
    }
}

/// Scroll a settings-style list to its foot and return its LAST row.
///
/// Rows are addressed by position in the live list, so a recipe that wants "the last row"
/// must not hardcode an index: adding a setting above it would silently move the recipe
/// onto a different row, and the frame would keep passing while photographing the wrong
/// screen. Scrolling first is what makes the answer complete - a row below the fold has no
/// region until it is in the window.
pub fn last_list_row(ui: &mut Ui) -> RegionId {
    /// Far above any settings list this product will have, and far below the 256 a `u8`
    /// allows: every probe here rebuilds the whole region set, so the bound is what keeps
    /// a helper used by forty frames from costing a quarter of a million of them.
    const MAX_LIST_ROWS: u8 = 32;

    let mut last = None;
    for _ in 0..16 {
        for i in 0..MAX_LIST_ROWS {
            if ui_has(ui, RegionId::SetRow(i)) {
                last = Some(RegionId::SetRow(i));
            }
        }
        let before = last;
        let (x, from, to) = (100, 400, 240);
        ui.touch(TouchEvent::Down { x, y: from });
        ui.touch(TouchEvent::Move { x, y: to });
        ui.touch(TouchEvent::Up { x, y: to });
        for i in 0..MAX_LIST_ROWS {
            if ui_has(ui, RegionId::SetRow(i)) {
                last = Some(RegionId::SetRow(i));
            }
        }
        if last == before && before.is_some() {
            break;
        }
    }
    let last = last.expect("a settings list has rows");
    scroll_to(ui, last);
    last
}

/// A device with a PIN, locked, with the DUMMY device facts installed.
pub fn locked(ui: &mut Ui, lock: LockInfo) {
    ui.set_verify_info(dummy_verify_info());
    ui.set_lock_info(lock);
    assert!(ui.lock(), "a device with a PIN starts locked");
}

/// Answer `UiRequest::DeviceWords` and leave PIN entry on the panel.
///
/// The first answer of a power-up raises S-04a over the PIN screen, which is the point of
/// it - so a recipe that wants the PIN screen has to dismiss it, exactly as a finger does.
/// Written as one helper rather than a tap after every call site, so that a frame cannot
/// silently become a picture of the explainer.
pub fn device_words(ui: &mut Ui, words: [String; 2]) {
    ui.show_device_words(words);
    if ui_has(ui, RegionId::WordsUnderstood) {
        tap(ui, RegionId::WordsUnderstood);
    }
}

/// A device with a session open, holding `wallets`.
///
/// The PIN is typed and answered rather than assumed: `unseal_result` is the only door
/// into the post-PIN screens, and going through it is what makes these frames statements
/// about the flow rather than about a state nobody can reach.
pub fn unlocked(ui: &mut Ui, wallets: Vec<WalletRow>) {
    locked(ui, dummy_lock_info());
    tap(ui, RegionId::LockWake);
    ui.unseal_result(UnsealOutcome::Unsealed);
    ui.set_wallets(wallets);
}

/// The common case: a session open over the four DUMMY rows.
pub fn unlocked_with_dummy_wallets(ui: &mut Ui) {
    unlocked(ui, dummy_wallets());
}

/// PIN entry, woken from the lock screen, with `digits` tapped as pad POSITIONS.
///
/// Positions rather than values, because that is what a finger picks and what
/// [`RegionId::PinKey`] indexes. The pad they print is the same on every device and in
/// the simulator - fixed phone order since the 2026-08-19 reversal of Q35 - so these
/// frames need nothing installed and show what hardware shows.
pub fn pin_entry(ui: &mut Ui, lock: LockInfo, digits: &[u8]) {
    locked(ui, lock);
    tap(ui, RegionId::LockWake);
    for i in digits {
        tap(ui, RegionId::PinKey(*i));
    }
}

/// A locked device whose store is in `status`. Only [`StoreStatus::Locked`] reaches the
/// lock screen (R20); the rest are Home states, which is exactly the point of rendering
/// them.
pub fn store_in(ui: &mut Ui, status: StoreStatus) {
    ui.set_verify_info(dummy_verify_info());
    ui.set_lock_info(LockInfo { status, ..dummy_lock_info() });
    ui.lock();
}
