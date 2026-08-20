// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The wallet list driven end to end through the PUBLIC API: touch events in, regions
//! and PIXELS out.
//!
//! The unit tests inside `screens::wallets` check the same invariant against the module's
//! own arithmetic, which is exactly the arithmetic under suspicion. These drive `Ui`
//! instead and decide "is this row painted?" by DIFFING FRAMEBUFFERS, so a row that draws
//! and does not tap is caught by the ink it leaves rather than by a rectangle the screen
//! agrees with itself about. Slots are deliberately non-zero-based, because the region id
//! carries the SLOT while the rect is placed by INDEX and a list starting at slot 1 is the
//! shape that reached the owner's hands.

use embedded_graphics::draw_target::DrawTarget;
use embedded_graphics::geometry::{OriginDimensions, Size};
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::Pixel;

use notyas_ui::{
    PassphraseState,
    BackupState, LockInfo, Network, Region, RegionId, ScreenId, StoreStatus, TouchEvent,
    Ui, UiRequest, UnsealOutcome, WalletInfo, WalletKind, WalletRow,
};

const GEOM: [(u32, u32); 2] = [(720, 720), (800, 480)];

struct Fb {
    w: u32,
    h: u32,
    px: Vec<Rgb565>,
}
impl Fb {
    fn render(ui: &Ui, w: u32, h: u32) -> Fb {
        let mut fb = Fb { w, h, px: vec![Rgb565::new(0, 0, 0); (w * h) as usize] };
        ui.draw(&mut fb).unwrap();
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
            }
        }
        Ok(())
    }
}

fn locked(w: u32, h: u32) -> Ui {
    let mut ui = Ui::new(w, h);
    ui.set_lock_info(LockInfo {
        status: StoreStatus::Locked,
        device_name: String::from("kitchen-desk"),
        attempts_left: Some(9),
        ..LockInfo::default()
    });
    assert!(ui.lock());
    ui
}

fn wallet(slot: u8, name: &str) -> WalletRow {
    WalletRow::Wallet(WalletInfo {
        slot,
        name: String::from(name),
        fingerprint: format!("a1b2c3d{slot}"),
        path: String::from("m/84'/0'/0'"),
        script_type: String::from("native segwit"),
        kind: WalletKind::SingleSig,
        backup: BackupState::Verified(String::new()),
        network: Network::Bitcoin,
        registrations: 0,
        stored: true,
        passphrase: PassphraseState::None,
    })
}

/// Wallets in the slots the OWNER has: slot 1 and slot 2, not 0-based indices.
fn owner_rows() -> Vec<WalletRow> {
    vec![wallet(1, "tw"), wallet(2, "tz")]
}

fn rows(slots: &[u8]) -> Vec<WalletRow> {
    slots.iter().map(|&s| wallet(s, &format!("w{s}"))).collect()
}

fn unlocked(w: u32, h: u32, list: Vec<WalletRow>) -> Ui {
    let mut ui = locked(w, h);
    tap_id(&mut ui, RegionId::LockWake);
    ui.unseal_result(UnsealOutcome::Unsealed);
    ui.set_wallets(list);
    assert_eq!(ui.screen(), ScreenId::WalletList);
    ui
}

fn find(ui: &Ui, id: RegionId) -> Option<Region> {
    ui.regions().into_iter().find(|r| r.id == id)
}

fn tap_at(ui: &mut Ui, x: i32, y: i32) -> Option<UiRequest> {
    ui.touch(TouchEvent::Down { x, y });
    ui.touch(TouchEvent::Up { x, y })
}

fn tap_id(ui: &mut Ui, id: RegionId) -> Option<UiRequest> {
    let r = find(ui, id).unwrap_or_else(|| panic!("no region {id:?} on {:?}", ui.screen())).rect;
    tap_at(ui, r.x + r.w / 2, r.y + r.h / 2)
}

/// Which region a point lands in, resolved the same way `Ui::hit` does.
fn hit(ui: &Ui, x: i32, y: i32) -> Option<RegionId> {
    ui.regions().into_iter().find(|r| r.rect.contains(x, y)).map(|r| r.id)
}

/// Drag the list up by `dy` pixels the way a finger does, then lift.
fn drag(ui: &mut Ui, dy: i32) {
    let (x, y) = (40, 200);
    ui.touch(TouchEvent::Down { x, y });
    ui.touch(TouchEvent::Move { x, y: y - dy });
    ui.touch(TouchEvent::Up { x, y: y - dy });
}

/// Does row `i` leave INK? Answered at the pixel level, not from geometry: re-render the
/// same list with row `i` swapped for an `Unreadable` row, which repaints that row's frame
/// in DANGER and its text differently while changing NOTHING else on the screen - the row
/// count, every other row's position and the capacity line are all identical. Any pixel
/// difference therefore means some part of row `i` reached the framebuffer.
fn painted(base: &Ui, w: u32, h: u32, list: &[WalletRow], i: usize, scroll: i32) -> bool {
    let mut probe_rows = list.to_vec();
    let slot = match &list[i] {
        WalletRow::Wallet(x) => x.slot,
        WalletRow::Unreadable { slot } => *slot,
    };
    probe_rows[i] = WalletRow::Unreadable { slot };
    let mut probe = unlocked(w, h, probe_rows);
    if scroll != 0 {
        drag(&mut probe, scroll);
    }
    Fb::render(base, w, h).px != Fb::render(&probe, w, h).px
}

// ---------------------------------------------------------------------------------------
// 1. THE OWNER CASE
// ---------------------------------------------------------------------------------------

#[test]
fn the_owner_can_tap_both_of_his_two_wallets() {
    for (w, h) in GEOM {
        let mut ui = unlocked(w, h, owner_rows());
        let tw = find(&ui, RegionId::ListRow(1)).expect("tw has no region");
        let tz = find(&ui, RegionId::ListRow(2)).expect("tz has no region - THE DEFECT");
        assert!(!tw.rect.overlaps(&tz.rect), "{w}x{h}: the two rows overlap");
        assert!(tz.rect.y > tw.rect.y, "{w}x{h}: tz must sit below tw");
        let got = tap_at(&mut ui, tz.rect.x + tz.rect.w / 2, tz.rect.y + tz.rect.h / 2);
        assert_eq!(
            got,
            Some(UiRequest::OpenWallet(2)),
            "{w}x{h}: tapping tz asked for {got:?} at {:?}",
            tz.rect
        );
        for dy in [0, tz.rect.h / 2, tz.rect.h - 1] {
            for dx in [0, tz.rect.w / 2, tz.rect.w - 1] {
                assert_eq!(
                    hit(&ui, tz.rect.x + dx, tz.rect.y + dy),
                    Some(RegionId::ListRow(2)),
                    "{w}x{h}: ({dx},{dy}) inside tz resolves elsewhere"
                );
            }
        }
        let mut ui2 = unlocked(w, h, owner_rows());
        assert_eq!(tap_id(&mut ui2, RegionId::ListRow(1)), Some(UiRequest::OpenWallet(1)));
    }
}

// ---------------------------------------------------------------------------------------
// 2. THE SWEEP: painted == tappable, at rest, driven
// ---------------------------------------------------------------------------------------

#[test]
fn every_painted_row_is_tappable_and_resolves_to_itself() {
    for (w, h) in GEOM {
        for n in [1u8, 2, 3, 8] {
            // Non-zero-based slots on purpose: the region id carries the SLOT while the
            // rect is placed by INDEX, and a list that starts at slot 1 is the shape the
            // owner is holding.
            let slots: Vec<u8> = (0..n).map(|i| i + 1).collect();
            let list = rows(&slots);
            for scroll in [0, 10_000] {
                let mut ui = unlocked(w, h, list.clone());
                if scroll != 0 {
                    drag(&mut ui, scroll); // clamps to the limit: the far rest point
                }
                let regs = ui.regions();
                for (i, a) in regs.iter().enumerate() {
                    for b in &regs[i + 1..] {
                        assert!(
                            !a.rect.overlaps(&b.rect),
                            "{w}x{h} n={n} scroll={scroll}: {:?} {:?} overlaps {:?} {:?}",
                            a.id,
                            a.rect,
                            b.id,
                            b.rect
                        );
                    }
                }
                for (i, &slot) in slots.iter().enumerate() {
                    let ink = painted(&ui, w, h, &list, i, scroll);
                    let reg = find(&ui, RegionId::ListRow(slot));
                    assert_eq!(
                        ink,
                        reg.is_some(),
                        "{w}x{h}, {n} wallets at rest (scroll {scroll}): row {i} (slot {slot}) \
                         painted={ink} tappable={}",
                        reg.is_some()
                    );
                    if let Some(r) = reg {
                        let (cx, cy) = (r.rect.x + r.rect.w / 2, r.rect.y + r.rect.h / 2);
                        assert_eq!(
                            hit(&ui, cx, cy),
                            Some(RegionId::ListRow(slot)),
                            "{w}x{h} n={n}: the centre of row {i} resolves elsewhere"
                        );
                        let mut fresh = unlocked(w, h, list.clone());
                        if scroll != 0 {
                            drag(&mut fresh, scroll);
                        }
                        assert_eq!(
                            tap_at(&mut fresh, cx, cy),
                            Some(UiRequest::OpenWallet(slot)),
                            "{w}x{h} n={n} scroll={scroll}: tapping row {i} did not open {slot}"
                        );
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------------------
// 3. THE FIT RULE MUST SURVIVE: a half-SCROLLED row is inert
// ---------------------------------------------------------------------------------------

#[test]
fn a_half_scrolled_row_is_painted_and_inert() {
    for (w, h) in GEOM {
        let slots: Vec<u8> = (1..=8u8).collect();
        let list = rows(&slots);
        let mut ui = unlocked(w, h, list.clone());
        // Half a row pitch: the list is mid-drag, not at rest.
        drag(&mut ui, 54);
        let mut half = 0;
        for (i, &slot) in slots.iter().enumerate() {
            let ink = painted(&ui, w, h, &list, i, 54);
            let reg = find(&ui, RegionId::ListRow(slot));
            if ink && reg.is_none() {
                half += 1;
            }
        }
        assert!(
            half > 0,
            "{w}x{h}: mid-drag, no row is painted-and-inert - the fit rule was REMOVED"
        );
        assert!(find(&ui, RegionId::ListRow(1)).is_none(), "{w}x{h}: a half row still taps");
    }
}

// ---------------------------------------------------------------------------------------
// 4. NOTHING ELSE REGRESSED
// ---------------------------------------------------------------------------------------

macro_rules! alloc_vec { ($($x:expr),* $(,)?) => { vec![$($x),*] } }

#[test]
fn the_chips_and_the_actions_still_resolve() {
    for (w, h) in GEOM {
        for n in [0usize, 1, 2, 3, 8] {
            let slots: Vec<u8> = (0..n as u8).map(|i| i + 1).collect();
            let mut ui = unlocked(w, h, rows(&slots));
            // At capacity the two create actions are drawn Disabled and emit NO region.
            // That is deliberate: a control that looks disabled and still activates is the
            // defect this asserts against, and it shipped - the buttons were painted
            // Disabled at 8 wallets and started the create flow anyway. So the expectation
            // here is a function of occupancy, not a constant.
            let at_capacity = n >= notyas_ui::WALLET_SLOTS as usize;
            let mut expected = alloc_vec![RegionId::Lock, RegionId::OpenSettings];
            if !at_capacity {
                expected.push(RegionId::WalletNew);
                expected.push(RegionId::WalletRestore);
            }
            for id in expected {
                let r = find(&ui, id).unwrap_or_else(|| panic!("{w}x{h} n={n}: no {id:?}"));
                assert_eq!(
                    hit(&ui, r.rect.x + r.rect.w / 2, r.rect.y + r.rect.h / 2),
                    Some(id),
                    "{w}x{h} n={n}: {id:?} centre resolves elsewhere"
                );
                assert!(r.rect.w >= 60 && r.rect.h >= 60, "{w}x{h}: {id:?} is {:?}", r.rect);
            }
            let lock = find(&ui, RegionId::Lock).unwrap().rect;
            let set = find(&ui, RegionId::OpenSettings).unwrap().rect;
            assert_eq!((lock.y, lock.h), (set.y, set.h), "{w}x{h}: the chips are not a pair");
            assert!(set.right() < lock.x, "{w}x{h}: Settings must sit left of Lock");
            for r in ui.regions() {
                assert!(
                    r.rect.x >= 0
                        && r.rect.y >= 0
                        && r.rect.right() <= w as i32
                        && r.rect.bottom() <= h as i32,
                    "{w}x{h} n={n}: {:?} at {:?} escapes the panel",
                    r.id,
                    r.rect
                );
            }
            assert_eq!(tap_id(&mut ui, RegionId::Lock), Some(UiRequest::LockSession));
            let mut s = unlocked(w, h, rows(&slots));
            tap_id(&mut s, RegionId::OpenSettings);
            assert_eq!(s.screen(), ScreenId::Settings, "{w}x{h}: Settings did not open");
            // Below capacity the two create actions open their flows. AT capacity they are
            // drawn Disabled and emit no region at all, so there is nothing to tap - and the
            // assertion that matters there is the opposite one: that a tap in the middle of
            // the disabled control does NOT start a flow. A button that looks dead and acts
            // live is the defect; a button that looks dead and IS dead is the fix.
            if at_capacity {
                for id in [RegionId::WalletNew, RegionId::WalletRestore] {
                    assert!(
                        find(&ui, id).is_none(),
                        "{w}x{h} n={n}: {id:?} still emits a region at capacity"
                    );
                }
            } else {
                let mut a = unlocked(w, h, rows(&slots));
                tap_id(&mut a, RegionId::WalletNew);
                assert_eq!(a.screen(), ScreenId::DiceEntry, "{w}x{h}: New wallet did not open");
                let mut b = unlocked(w, h, rows(&slots));
                tap_id(&mut b, RegionId::WalletRestore);
                assert_eq!(b.screen(), ScreenId::PhraseEntry, "{w}x{h}: Restore did not open");
            }
        }
    }
}

/// A list that mixes an unreadable slot in must still place and tap the readable ones by
/// SLOT, not by index. Driven at the scroll offsets the list can rest at, because the
/// 800x480 viewport is only two rows tall and the third row lives past the first one.
#[test]
fn an_unreadable_slot_does_not_shift_the_tappable_rows() {
    for (w, h) in GEOM {
        let list = vec![WalletRow::Unreadable { slot: 0 }, wallet(1, "tw"), wallet(2, "tz")];
        for scroll in [0, 10_000] {
            let mut ui = unlocked(w, h, list.clone());
            if scroll != 0 {
                drag(&mut ui, scroll);
            }
            assert!(
                find(&ui, RegionId::ListRow(0)).is_none(),
                "{w}x{h}: an unreadable slot must never tap"
            );
        }
        let mut ui = unlocked(w, h, list.clone());
        drag(&mut ui, 10_000);
        let tz = find(&ui, RegionId::ListRow(2))
            .unwrap_or_else(|| panic!("{w}x{h}: tz unreachable even at the scroll limit"));
        assert_eq!(
            tap_at(&mut ui, tz.rect.x + tz.rect.w / 2, tz.rect.y + tz.rect.h / 2),
            Some(UiRequest::OpenWallet(2))
        );
    }
}

/// Every stored wallet must be openable by touch. The painted==tappable invariant alone
/// permits a list that simply never shows a row; this is the other half - a wallet the
/// user cannot bring into the viewport is as lost as one that draws and does not tap.
///
/// Driven by dragging the list a whole ROW PITCH at a time, which is what a user does to
/// walk a list: the two ends are quantized by construction, and every stop in between has
/// to be found the same way.
#[test]
fn every_wallet_can_be_scrolled_into_reach_and_opened() {
    for (w, h) in GEOM {
        // The pitch, measured off the screen rather than assumed.
        let probe = unlocked(w, h, rows(&[1, 2]));
        let pitch = find(&probe, RegionId::ListRow(2)).unwrap().rect.y
            - find(&probe, RegionId::ListRow(1)).unwrap().rect.y;
        assert!(pitch > 0, "{w}x{h}: could not measure a row pitch");
        for n in 1..=8u8 {
            let slots: Vec<u8> = (0..n).map(|i| i + 1).collect();
            let list = rows(&slots);
            for &slot in &slots {
                let mut found = false;
                for step in 0..=n as i32 {
                    let mut ui = unlocked(w, h, list.clone());
                    if step > 0 {
                        drag(&mut ui, step * pitch);
                    }
                    if let Some(r) = find(&ui, RegionId::ListRow(slot)) {
                        let got =
                            tap_at(&mut ui, r.rect.x + r.rect.w / 2, r.rect.y + r.rect.h / 2);
                        assert_eq!(
                            got,
                            Some(UiRequest::OpenWallet(slot)),
                            "{w}x{h} n={n} step={step}: row for slot {slot} did not open it"
                        );
                        found = true;
                        break;
                    }
                }
                assert!(found, "{w}x{h}, {n} wallets: slot {slot} can never be brought into view");
            }
        }
    }
}
