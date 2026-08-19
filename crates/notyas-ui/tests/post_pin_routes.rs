// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! What an UNLOCKED device can actually reach, driven the way a finger does.
//!
//! An unlock lands on the wallet list, and the wallet list is its own floor - `Back` there
//! is `Nav::Stay`. So every route out of the post-PIN surface has to be a control ON that
//! surface or on something it opens, and a screen with no such route is a screen the device
//! stops having the moment a PIN is set, however complete its code is. Two were in exactly
//! that position: S-46 Verify device, whose row set is strictly LARGER post-PIN, and the
//! network choice that every derivation the list starts reads. A third gap was one step
//! further in - a stored wallet the embedder unsealed could only be deleted, because the
//! answer it was handed carried the wallet's public identity and not its keys.
//!
//! These tests are written as reachability claims rather than as layout checks: each one
//! starts at the wallet list and walks, on BOTH shipped panels, so a route that exists only
//! on the tall one fails here rather than on a board.

use embedded_graphics::draw_target::DrawTarget;
use embedded_graphics::geometry::{OriginDimensions, Size};
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::Pixel;

use notyas_ui::{
    BackupState, LockInfo, Network, Region, RegionId, Report, ScreenId, StoreStatus, TouchEvent,
    Ui, UiRequest, UnsealOutcome, VerifyInfo, WalletInfo, WalletKind, WalletRow, ADDRESS_ROWS,
};

/// The two shipped panels (docs/BOARDS.md): Waveshare 4B and Elecrow 5inch.
const GEOMETRIES: [(u32, u32); 2] = [(720, 720), (800, 480)];

// ---------------------------------------------------------------------------------------
// A framebuffer, so "it renders" is a claim these tests can make
// ---------------------------------------------------------------------------------------

struct Fb {
    w: u32,
    h: u32,
    px: Vec<Rgb565>,
}

impl Fb {
    fn render(ui: &Ui, w: u32, h: u32) -> Fb {
        let mut fb = Fb { w, h, px: vec![Rgb565::new(0, 0, 0); (w * h) as usize] };
        ui.draw(&mut fb).expect("the panel is infallible");
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
                self.px[p.y as usize * self.w as usize + p.x as usize] = c;
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------
// Driving the panel
// ---------------------------------------------------------------------------------------

fn region(ui: &Ui, id: RegionId) -> Option<Region> {
    ui.regions().iter().find(|r| r.id == id).copied()
}

fn has(ui: &Ui, id: RegionId) -> bool {
    region(ui, id).is_some()
}

/// Tap the centre of a region, the way the simulator and a finger both do.
fn tap(ui: &mut Ui, id: RegionId) -> Option<UiRequest> {
    let r = region(ui, id)
        .unwrap_or_else(|| panic!("{id:?} is not on {:?}", ui.screen()))
        .rect;
    let (x, y) = (r.x + r.w / 2, r.y + r.h / 2);
    ui.touch(TouchEvent::Down { x, y });
    ui.touch(TouchEvent::Up { x, y })
}

/// Drag `dy` px upwards from `(x, y)`, which is how a list is scrolled: the movement
/// exceeds the drag slop, so the lift is a scroll and never a tap.
fn drag_up(ui: &mut Ui, x: i32, y: i32, dy: i32) {
    ui.touch(TouchEvent::Down { x, y });
    ui.touch(TouchEvent::Move { x, y: y - dy });
    ui.touch(TouchEvent::Up { x, y: y - dy });
}

/// Scroll the current screen until `id` is offered, or fail saying it never was.
///
/// A control below the fold is reachable only if the screen it is on can be scrolled to it,
/// so a reachability test that assumed the first viewport would have proved the route on the
/// tall panel and nothing about the short one. The bound is what makes a screen that refuses
/// to move a failure instead of a hang.
fn scroll_to(ui: &mut Ui, id: RegionId, w: u32, h: u32) {
    for _ in 0..12 {
        if has(ui, id) {
            return;
        }
        drag_up(ui, w as i32 / 2, h as i32 / 2, 120);
    }
    panic!("{id:?} cannot be reached on {:?} at {w}x{h}", ui.screen());
}

/// Bring settings row `i` into the window and tap it.
///
/// The short panel shows two rows of the list at a time, so a route to the third is a route
/// only if the list can be scrolled to it - which is the whole reason this helper scrolls
/// rather than asserting the row is already there. The bound is what makes a list that
/// refuses to move a failure instead of a hang.
fn tap_settings_row(ui: &mut Ui, w: u32, h: u32, i: u8) {
    scroll_to(ui, RegionId::SetRow(i), w, h);
    tap(ui, RegionId::SetRow(i));
}

fn wallet(slot: u8) -> WalletInfo {
    WalletInfo {
        slot,
        name: format!("wallet {slot}"),
        fingerprint: String::from("73c5da0a"),
        path: String::from("m/84'/0'/0'"),
        script_type: String::from("native segwit"),
        kind: WalletKind::SingleSig,
        backup: BackupState::Verified(String::new()),
        network: Network::Bitcoin,
        registrations: 0,
        stored: true,
        passphrase: false,
    }
}

/// A device with a PIN, unlocked, holding one wallet - the state the whole post-PIN
/// surface is defined against.
fn unlocked(w: u32, h: u32) -> Ui {
    let mut ui = Ui::new(w, h);
    ui.set_lock_info(LockInfo {
        status: StoreStatus::Locked,
        nickname: String::from("kitchen-desk"),
        lock_word: String::from("anvil"),
        wipe_after: Some(10),
        ..LockInfo::default()
    });
    assert!(ui.lock(), "a device with a PIN can show its lock screen");
    tap(&mut ui, RegionId::LockWake);
    ui.unseal_result(UnsealOutcome::Unsealed);
    ui.set_wallets(vec![WalletRow::Wallet(wallet(0))]);
    // A device that has counted boots. Without a count there is no boot index to
    // acknowledge and S-46 offers no acknowledgement at all (VERIFY.md 6.3 / R24), so a
    // test of that route has to state the device fact the route depends on.
    ui.set_verify_info(VerifyInfo { boot_count: Some(42), ..VerifyInfo::default() });
    assert_eq!(ui.screen(), ScreenId::WalletList, "an unlock lands on the list");
    ui
}

/// The 12-word all-`abandon` vector: a real derivation with no value in it, so a test can
/// hold the keys the embedder would hand over without inventing a wallet worth stealing.
const TEST_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                           abandon abandon abandon about";

/// What the embedder produces while unsealing a stored wallet, and hands to
/// [`Ui::wallet_opened_with_keys`].
fn report() -> Report {
    use notyas_core::bip39::MnemonicMode;
    use notyas_core::derive::{ChildIndex, Scheme};
    use notyas_core::report::Parameters;
    Report::from_phrase(
        TEST_PHRASE,
        &Parameters {
            mode: MnemonicMode::Raw,
            passphrase: "",
            network: Network::Bitcoin,
            schemes: &Scheme::ALL,
            account: ChildIndex::ZERO,
            change: ChildIndex::ZERO,
            count: ADDRESS_ROWS,
            script_type: 2,
        },
    )
    .expect("a phrase with words in it derives")
}

/// Every region on the panel is inside it, has area, and touches no other. Region overlap
/// is the failure that makes a tap resolve to the wrong control, and it is invisible in a
/// screenshot.
fn regions_are_sane(ui: &Ui, w: u32, h: u32) {
    let regions = ui.regions();
    assert!(!regions.is_empty(), "{:?} at {w}x{h} has nothing to tap", ui.screen());
    for r in &regions {
        assert!(
            r.rect.x >= 0
                && r.rect.y >= 0
                && r.rect.right() <= w as i32
                && r.rect.bottom() <= h as i32,
            "{:?} on {:?} at {w}x{h} escapes the panel: {:?}",
            r.id,
            ui.screen(),
            r.rect
        );
        assert!(r.rect.w > 0 && r.rect.h > 0, "{:?} on {:?} is empty", r.id, ui.screen());
    }
    for (i, a) in regions.iter().enumerate() {
        for b in &regions[i + 1..] {
            assert!(
                !a.rect.overlaps(&b.rect),
                "{:?} at {:?} overlaps {:?} at {:?} on {:?} at {w}x{h}",
                a.id,
                a.rect,
                b.id,
                b.rect,
                ui.screen()
            );
        }
    }
    Fb::render(ui, w, h);
}

// ---------------------------------------------------------------------------------------
// The routes
// ---------------------------------------------------------------------------------------

/// S-46 is reachable while a session is open - which is the only state in which it is
/// complete.
///
/// The Verify screen shows a STRICTLY LARGER row set post-PIN, and the boot-counter
/// acknowledgement is post-PIN only by design: a coercer who can press it erases the gap
/// the counter shows. Home was its only entrance, and an unlocked device cannot reach Home,
/// so the one action that requires a session sat on the one screen a session could not open.
/// This walks the route that fixes that and then walks the pager to the acknowledgement,
/// because a screen you can open and an action you can take are different claims.
#[test]
fn verify_device_is_reachable_from_a_session_and_can_be_acknowledged() {
    for (w, h) in GEOMETRIES {
        let mut ui = unlocked(w, h);
        assert!(!has(&ui, RegionId::HomeVerifyDevice), "the list is not Home");

        tap(&mut ui, RegionId::OpenSettings);
        assert_eq!(ui.screen(), ScreenId::Settings);
        tap_settings_row(&mut ui, w, h, 2);
        assert_eq!(ui.screen(), ScreenId::VerifyDevice, "{w}x{h}: Verify device did not open");
        regions_are_sane(&ui, w, h);

        // "Mark as seen" is a post-PIN row, so it is somewhere in this sheet; the pager is
        // how a reader gets to it. Bounded, because a pager that will not advance is a
        // failure and not a reason to spin.
        let mut found = has(&ui, RegionId::VerifyAckBoots);
        for _ in 0..40 {
            if found || !has(&ui, RegionId::ReviewNext) {
                break;
            }
            tap(&mut ui, RegionId::ReviewNext);
            regions_are_sane(&ui, w, h);
            found = has(&ui, RegionId::VerifyAckBoots);
        }
        assert!(found, "{w}x{h}: the boot-counter acknowledgement is not reachable post-PIN");
        assert_eq!(
            tap(&mut ui, RegionId::VerifyAckBoots),
            Some(UiRequest::AcknowledgeBoots),
            "{w}x{h}: the acknowledgement must ask the embedder to write the mark"
        );

        // And the way back is the screen it was opened from, not an empty stack that
        // happens to look like one.
        tap(&mut ui, RegionId::Back);
        assert_eq!(ui.screen(), ScreenId::Settings);
        tap(&mut ui, RegionId::Back);
        assert_eq!(ui.screen(), ScreenId::WalletList);
    }
}

/// The network is an input to every derivation the wallet list starts, and it must be
/// changeable from the surface that starts them.
///
/// It lived on Home's toggle alone, so a user who unlocked and tapped `New wallet` derived
/// on whatever network the session began with and had no way to say otherwise - and a
/// wallet on the wrong network is a real error class, not a cosmetic one. The assertion
/// that matters is the last: the choice is still in force on the screen that consumes it.
#[test]
fn the_network_can_be_chosen_after_unlock_and_survives_to_the_next_derivation() {
    for (w, h) in GEOMETRIES {
        let mut ui = unlocked(w, h);
        assert_eq!(ui.network(), Network::Bitcoin);
        assert!(!has(&ui, RegionId::NetToggle), "the list carries no toggle of its own");

        tap(&mut ui, RegionId::OpenSettings);
        tap_settings_row(&mut ui, w, h, 0);
        assert_eq!(ui.network(), Network::Testnet, "{w}x{h}: the network row did not act");
        assert_eq!(ui.screen(), ScreenId::Settings, "a row that acts in place goes nowhere");
        regions_are_sane(&ui, w, h);

        // It flips back, so the row is a choice rather than a one-way trip.
        tap_settings_row(&mut ui, w, h, 0);
        assert_eq!(ui.network(), Network::Bitcoin);
        tap_settings_row(&mut ui, w, h, 0);

        // ...and the choice outlives the screen that made it, all the way to the flow that
        // reads it.
        tap(&mut ui, RegionId::Back);
        assert_eq!(ui.screen(), ScreenId::WalletList);
        tap(&mut ui, RegionId::WalletNew);
        assert_eq!(ui.screen(), ScreenId::DiceEntry);
        assert_eq!(ui.network(), Network::Testnet, "{w}x{h}: the derivation lost the network");
    }
}

/// A wallet the PIN protects reaches its public keys - as long as the embedder hands them
/// over with the answer.
///
/// The UI owns no key ladder, so a slot number is not something it can turn into an xpub.
/// Answering `OpenWallet` with the public identity alone therefore produced a wallet home
/// whose only action was Delete: no addresses, no xpub, no descriptor, no QR. The same
/// wallet answered with its derivation reaches S-26 and everything S-26 carries, and this
/// walks both answers to the same slot so the difference is the answer and nothing else.
#[test]
fn a_stored_wallet_reaches_its_public_keys_when_the_embedder_sends_them() {
    for (w, h) in GEOMETRIES {
        let mut ui = unlocked(w, h);

        // Identity only: one action, and it is the destructive one.
        assert_eq!(tap(&mut ui, RegionId::ListRow(0)), Some(UiRequest::OpenWallet(0)));
        ui.wallet_opened(wallet(0));
        assert_eq!(ui.screen(), ScreenId::WalletHome);
        assert!(!has(&ui, RegionId::ActExport), "{w}x{h}: no keys were sent, so no export");
        assert!(has(&ui, RegionId::WalletDelete));
        regions_are_sane(&ui, w, h);

        // The same wallet, unsealed.
        tap(&mut ui, RegionId::Back);
        assert_eq!(ui.screen(), ScreenId::WalletList);
        assert_eq!(tap(&mut ui, RegionId::ListRow(0)), Some(UiRequest::OpenWallet(0)));
        ui.wallet_opened_with_keys(wallet(0), report());
        assert_eq!(ui.screen(), ScreenId::WalletHome);
        assert!(has(&ui, RegionId::ActExport), "{w}x{h}: an unsealed wallet must export");
        assert!(has(&ui, RegionId::WalletDelete), "and must still be deletable");
        regions_are_sane(&ui, w, h);

        tap(&mut ui, RegionId::ActExport);
        assert_eq!(ui.screen(), ScreenId::Schemes, "{w}x{h}: export must open S-26");
        regions_are_sane(&ui, w, h);
        // What S-26 is FOR: the account xpub and the receive addresses under it, each
        // offerable as a QR. This is the whole of "a stored wallet offers no addresses".
        assert!(has(&ui, RegionId::QrXpub), "{w}x{h}: the account xpub must be exportable");
        scroll_to(&mut ui, RegionId::QrAddress(0), w, h);
        let Some(UiRequest::Qr(target)) = tap(&mut ui, RegionId::QrAddress(0)) else {
            panic!("{w}x{h}: a receive-address QR must ask the embedder to encode it");
        };
        assert!(!target.payload.is_empty(), "an address QR with no address in it");
    }
}

/// A late answer to `OpenWallet` is dropped rather than shown.
///
/// Both answers are one method over one guard, so the rule the identity-only answer already
/// kept has to keep holding for the one that carries keys - and this is the answer where
/// getting it wrong is worse: it would push a screen holding a live derivation over
/// whatever the user navigated to instead.
#[test]
fn keys_arriving_after_the_user_moved_on_are_dropped() {
    let mut ui = unlocked(720, 720);
    tap(&mut ui, RegionId::OpenSettings);
    assert_eq!(ui.screen(), ScreenId::Settings);
    ui.wallet_opened_with_keys(wallet(0), report());
    assert_eq!(ui.screen(), ScreenId::Settings, "a late answer must not change the screen");
}

/// Every post-PIN surface lays out on both panels: nothing off the edge, nothing on top of
/// anything else, and it paints.
///
/// The walk is the point. Each new route is exercised at both geometries in the order a
/// user meets them, so a screen that is only correct on the tall panel - the failure the
/// 800x480 board keeps producing - fails here.
#[test]
fn every_post_pin_surface_holds_on_both_panels() {
    for (w, h) in GEOMETRIES {
        let mut ui = unlocked(w, h);
        regions_are_sane(&ui, w, h);

        tap(&mut ui, RegionId::OpenSettings);
        regions_are_sane(&ui, w, h);

        // The settings list, at both ends of its travel, and with a refusal on the footer
        // line - the state where the hint and the refusal compete for it.
        drag_up(&mut ui, w as i32 / 2, h as i32 / 2, 400);
        regions_are_sane(&ui, w, h);
        drag_up(&mut ui, w as i32 / 2, h as i32 / 2, -400);
        regions_are_sane(&ui, w, h);
        tap(&mut ui, RegionId::RemoveThePin);
        regions_are_sane(&ui, w, h);
        tap(&mut ui, RegionId::DangerCancel);
        ui.pin_removed(false);
        regions_are_sane(&ui, w, h);

        // The network row, in both states, because one of them draws a different control.
        tap_settings_row(&mut ui, w, h, 0);
        regions_are_sane(&ui, w, h);
        tap_settings_row(&mut ui, w, h, 0);
        regions_are_sane(&ui, w, h);

        // The wipe-policy editor and the Verify readout, from their new row positions.
        tap_settings_row(&mut ui, w, h, 1);
        assert_eq!(ui.screen(), ScreenId::WipePolicy);
        regions_are_sane(&ui, w, h);
        tap(&mut ui, RegionId::Back);
        tap_settings_row(&mut ui, w, h, 2);
        assert_eq!(ui.screen(), ScreenId::VerifyDevice);
        regions_are_sane(&ui, w, h);
        tap(&mut ui, RegionId::Back);
        tap(&mut ui, RegionId::Back);

        // And the wallet home with both cards, which is its tightest layout.
        tap(&mut ui, RegionId::ListRow(0));
        ui.wallet_opened_with_keys(wallet(0), report());
        regions_are_sane(&ui, w, h);
        tap(&mut ui, RegionId::WalletDelete);
        regions_are_sane(&ui, w, h);
        tap(&mut ui, RegionId::DangerCancel);
        tap(&mut ui, RegionId::ActExport);
        assert_eq!(ui.screen(), ScreenId::Schemes);
        regions_are_sane(&ui, w, h);
    }
}
