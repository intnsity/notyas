// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Registering a multisig wallet, driven the way a finger does, on BOTH shipped panels.
//!
//! The unit tests beside the screens prove rectangles and refusals. What they cannot prove
//! is that the three screens are REACHABLE and that the exchange between them and the
//! embedder closes: every one of these routes starts at the lock screen, types the PIN,
//! opens a wallet, and reaches the registry through controls that are on the panel. A
//! request that nothing raises, an answer that lands nowhere, or a screen with no route to
//! it fails here rather than on a board.
//!
//! The other half is the C3 contract. Every blocking request parks the panel on
//! [`ScreenId::Working`] with nothing tappable, and every answer takes it off again - so a
//! step that asserts `Working` and then asserts a screen with regions is asserting that the
//! device cannot be left frozen holding a card.

use embedded_graphics::draw_target::DrawTarget;
use embedded_graphics::geometry::{OriginDimensions, Size};
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::Pixel;

use notyas_ui::{
    PassphraseState,
    BackupState, CardListing, CardOutcome, CosignerRow, FileFilter, FileKind, FileRow,
    ImportOutcome, LockInfo, Network, RefusalCode, RefusalNotice, Region, RegionId,
    RegistrationInfo, RegistrationOutcome, RegistrationReview, ScreenId, StoreStatus, TouchEvent,
    Ui, UiRequest, UnsealOutcome, VerifyInfo, WalletInfo, WalletKind, WalletRow,
};

/// The two shipped panels this suite drives: Waveshare 4B and Elecrow 5inch.
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
        I: IntoIterator<Item = Pixel<Self::Color>>,
    {
        for Pixel(p, c) in pixels {
            if p.x >= 0 && p.y >= 0 && (p.x as u32) < self.w && (p.y as u32) < self.h {
                let i = p.y as usize * self.w as usize + p.x as usize;
                self.px[i] = c;
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------
// Driving
// ---------------------------------------------------------------------------------------

fn region(ui: &Ui, id: RegionId) -> Option<Region> {
    ui.regions().into_iter().find(|r| r.id == id)
}

fn has(ui: &Ui, id: RegionId) -> bool {
    region(ui, id).is_some()
}

fn tap(ui: &mut Ui, id: RegionId) -> Option<UiRequest> {
    let r = region(ui, id)
        .unwrap_or_else(|| panic!("no region {id:?} on {:?}", ui.screen()))
        .rect;
    let (x, y) = (r.x + r.w / 2, r.y + r.h / 2);
    ui.touch(TouchEvent::Down { x, y });
    ui.touch(TouchEvent::Up { x, y })
}

/// Type a word on the C9 keyboard, walking to the page the character is on exactly as a
/// finger does.
///
/// The page walk is the point rather than a convenience: a C4d sheet that requires a
/// character no page carries is a confirmation nobody can complete, so a driver that could
/// not reach a key would be hiding the defect this suite exists to catch.
fn type_word(ui: &mut Ui, word: &str) {
    for c in word.chars() {
        if c == ' ' {
            tap(ui, RegionId::Space);
            continue;
        }
        if !has(ui, RegionId::Key(c)) {
            let page = if c.is_ascii_digit() {
                RegionId::PageDigits
            } else if c.is_ascii_uppercase() {
                RegionId::Shift
            } else {
                RegionId::PageLetters
            };
            assert!(has(ui, page), "{page:?} is not on the keyboard, so {c:?} is unreachable");
            tap(ui, page);
        }
        tap(ui, RegionId::Key(c));
    }
}

/// Drag the panel up until `id` is offered, exactly as a finger reaches a row below the
/// fold. Fails loudly rather than looping, because a control that scrolling cannot reach is
/// a control the device does not have.
fn scroll_to(ui: &mut Ui, id: RegionId, w: u32, h: u32) {
    for _ in 0..40 {
        if has(ui, id) {
            return;
        }
        let (x, y) = (w as i32 / 2, h as i32 * 3 / 4);
        ui.touch(TouchEvent::Down { x, y });
        ui.touch(TouchEvent::Move { x, y: y - 80 });
        ui.touch(TouchEvent::Up { x, y: y - 80 });
    }
    panic!("{id:?} is unreachable on {:?} at {w}x{h}", ui.screen());
}

/// Every offered region sits on the panel, and the frame paints.
fn panel_is_sane(ui: &Ui, w: u32, h: u32) {
    for r in ui.regions() {
        assert!(
            r.rect.x >= 0
                && r.rect.y >= 0
                && r.rect.right() <= w as i32
                && r.rect.bottom() <= h as i32,
            "{w}x{h} {:?}: {:?} at {:?} escapes the panel",
            ui.screen(),
            r.id,
            r.rect
        );
    }
    Fb::render(ui, w, h);
}

/// A C3 Busy frame: the id says so, nothing is tappable, and it still paints.
fn is_busy(ui: &Ui, w: u32, h: u32) {
    assert_eq!(ui.screen(), ScreenId::Working, "a blocking request must park on C3");
    assert!(ui.regions().is_empty(), "a Busy frame must have nothing tappable");
    Fb::render(ui, w, h);
}

// ---------------------------------------------------------------------------------------
// Sample data - published test vectors, worthless as keys
// ---------------------------------------------------------------------------------------

const XPUBS: [&str; 3] = [
    "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
    "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
    "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
];
const ADDRESS: &str = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";
const PATH: &str = "m/48'/0'/0'/2'";
/// The registration's label. One word on purpose: it is what the C4d delete sheet asks to
/// be typed back, and this suite types it.
const LABEL: &str = "vault";

fn wallet_info(registrations: u8) -> WalletInfo {
    WalletInfo {
        slot: 0,
        name: String::from("savings"),
        fingerprint: String::from("a1b2c300"),
        path: String::from("m/84'/0'/0'"),
        script_type: String::from("native segwit"),
        kind: WalletKind::Multisig,
        backup: BackupState::Verified(String::new()),
        network: Network::Bitcoin,
        registrations,
        stored: true,
        passphrase: PassphraseState::None,
    }
}

fn review(ours: u8) -> RegistrationReview {
    let cosigners = (0..3usize)
        .map(|i| CosignerRow {
            fingerprint: format!("a1b2c3{i:02}"),
            path: String::from(PATH),
            xpub: String::from(XPUBS[i]),
            ours: i + 1 == usize::from(ours),
        })
        .collect();
    RegistrationReview {
        name: String::from(LABEL),
        threshold: 2,
        policy: String::from("sortedmulti"),
        script: String::from("P2WSH (native segwit)"),
        derivation: String::from(PATH),
        network: Network::Bitcoin,
        cosigners,
        ours,
        first_address: String::from(ADDRESS),
        descriptor: format!(
            "wsh(sortedmulti(2,[a1b2c300/48h/0h/0h/2h]{}/<0;1>/*,[a1b2c301/48h/0h/0h/2h]{}/<0;1>/*,\
             [a1b2c302/48h/0h/0h/2h]{}/<0;1>/*))#8zl0zxma",
            XPUBS[0], XPUBS[1], XPUBS[2]
        ),
        converted: false,
        duplicate: false,
    }
}

fn saved_info() -> RegistrationInfo {
    RegistrationInfo {
        slot: 0,
        name: String::from(LABEL),
        threshold: 2,
        cosigners: 3,
        script: String::from("P2WSH"),
        derivation: String::from(PATH),
        fingerprint: String::from("a1b2c300"),
        network: Network::Bitcoin,
        proven: true,
    }
}

fn card_with_one_file() -> CardListing {
    CardListing {
        dir: String::new(),
        rows: vec![FileRow {
            name: String::from("vault-2of3.txt"),
            kind: FileKind::Text,
            len: 640,
            modified: String::from("17 Aug 14:02"),
            oversize: false,
        }],
        truncated: false,
        rejected: 0,
    }
}

// ---------------------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------------------

/// A device with a PIN, unlocked, holding the multisig wallet - reached by typing the PIN,
/// because that is the only door into the post-PIN screens.
fn unlocked(w: u32, h: u32, registrations: u8) -> Ui {
    let mut ui = Ui::new(w, h);
    ui.set_verify_info(VerifyInfo::default());
    ui.set_lock_info(LockInfo {
        status: StoreStatus::Locked,
        device_name: String::from("bench"),
        attempts_left: Some(9),
        wipe_after: Some(10),
        ..LockInfo::default()
    });
    assert!(ui.lock(), "a device with a PIN starts locked");
    tap(&mut ui, RegionId::LockWake);
    for i in 0..6u8 {
        tap(&mut ui, RegionId::PinKey(i));
    }
    tap(&mut ui, RegionId::PinSubmit);
    ui.unseal_result(UnsealOutcome::Unsealed);
    ui.set_wallets(vec![WalletRow::Wallet(wallet_info(registrations))]);
    assert_eq!(ui.screen(), ScreenId::WalletList);
    ui
}

/// ...and on into the registry, through the wallet home's Multisig card.
fn registry(w: u32, h: u32, registrations: u8, held: Vec<RegistrationInfo>) -> Ui {
    let mut ui = unlocked(w, h, registrations);
    assert_eq!(tap(&mut ui, RegionId::ListRow(0)), Some(UiRequest::OpenWallet(0)));
    ui.wallet_opened(wallet_info(registrations));
    assert_eq!(ui.screen(), ScreenId::WalletHome);
    ui.set_registrations(held);
    tap(&mut ui, RegionId::ActMultisig);
    assert_eq!(ui.screen(), ScreenId::MultisigList, "the wallet home must reach the registry");
    ui
}

/// The registry, a card read, and the file chosen: the point at which the engine has been
/// asked for a decision about a descriptor.
fn asked_to_import(w: u32, h: u32) -> Ui {
    let mut ui = registry(w, h, 0, Vec::new());
    panel_is_sane(&ui, w, h);

    assert_eq!(
        tap(&mut ui, RegionId::MsImport),
        Some(UiRequest::ListCard { dir: String::new(), filter: FileFilter::All }),
        "Import must ask the embedder to read the card"
    );
    is_busy(&ui, w, h);

    assert_eq!(ui.card_result(CardOutcome::Listed(card_with_one_file())), None);
    assert_eq!(ui.screen(), ScreenId::MultisigList);
    panel_is_sane(&ui, w, h);

    assert_eq!(
        tap(&mut ui, RegionId::ListRow(0)),
        Some(UiRequest::ImportRegistration {
            dir: String::new(),
            name: String::from("vault-2of3.txt")
        }),
        "a file row must ask the engine to read AND decide"
    );
    is_busy(&ui, w, h);
    ui
}

// ---------------------------------------------------------------------------------------
// The whole act
// ---------------------------------------------------------------------------------------

/// MILESTONES 9.2, the multisig half: register a 2-of-3 P2WSH wallet from a card, see the
/// first receive address that has to be cross-checked, and delete it again.
///
/// Every step is a control on the panel and every blocking step is a C3 frame. This is the
/// route the release bar names, walked end to end on both shipped panels.
#[test]
fn a_two_of_three_wallet_is_registered_reviewed_and_deleted() {
    for (w, h) in GEOMETRIES {
        let mut ui = asked_to_import(w, h);

        // The engine proved membership. What is left is the comparison the screen exists
        // for, and C5 will not let it be skipped.
        assert_eq!(ui.import_result(ImportOutcome::Pending(review(1))), None);
        assert_eq!(ui.screen(), ScreenId::MultisigImport);
        panel_is_sane(&ui, w, h);

        assert!(!has(&ui, RegionId::MsApprove), "{w}x{h}: page one could approve");
        let mut pages = 1;
        while has(&ui, RegionId::ReviewNext) {
            tap(&mut ui, RegionId::ReviewNext);
            panel_is_sane(&ui, w, h);
            pages += 1;
            assert!(pages < 32, "{w}x{h}: the pager never reached the last page");
        }
        assert_eq!(pages, 5, "{w}x{h}: the overview, three cosigners and the address page");
        assert!(has(&ui, RegionId::MsApprove), "{w}x{h}: a full traversal cannot approve");

        assert_eq!(
            tap(&mut ui, RegionId::MsApprove),
            Some(UiRequest::ApproveRegistration { replace: false })
        );
        is_busy(&ui, w, h);

        // The embedder answers with what happened AND re-installs the registry.
        ui.set_registrations(vec![saved_info()]);
        assert_eq!(ui.registration_result(RegistrationOutcome::Saved(saved_info())), None);
        assert_eq!(ui.screen(), ScreenId::MultisigDetail);
        panel_is_sane(&ui, w, h);
        assert!(
            has(&ui, RegionId::MsFirstAddress) && has(&ui, RegionId::MsCosigners),
            "{w}x{h}: a saved registration must be re-inspectable"
        );

        // Delete: C4b, then C4d with the registration's own name.
        scroll_to(&mut ui, RegionId::MsDelete, w, h);
        tap(&mut ui, RegionId::MsDelete);
        assert!(has(&ui, RegionId::DangerConfirm), "{w}x{h}: no consequence sheet");
        assert!(!has(&ui, RegionId::MsDelete), "{w}x{h}: the screen is live under the sheet");
        assert_eq!(tap(&mut ui, RegionId::DangerConfirm), None, "reading must erase nothing");
        // The typed step: the confirm is inert until the name is back.
        assert_eq!(tap(&mut ui, RegionId::DangerConfirm), None, "an unarmed sheet must not fire");
        type_word(&mut ui, LABEL);
        assert_eq!(
            tap(&mut ui, RegionId::DangerConfirm),
            Some(UiRequest::DeleteRegistration(0)),
            "{w}x{h}: the armed sheet must ask for the erase"
        );
        is_busy(&ui, w, h);

        ui.set_registrations(Vec::new());
        assert_eq!(ui.registration_deleted(true), None);
        assert_eq!(ui.screen(), ScreenId::MultisigList, "an erased slot returns to the registry");
        panel_is_sane(&ui, w, h);

        // ...and the registry is the way back to the wallet it belongs to.
        tap(&mut ui, RegionId::Back);
        assert_eq!(ui.screen(), ScreenId::WalletHome);
    }
}

/// A descriptor this device is not a member of never reaches an approve button, and the
/// user is not stranded on it.
///
/// This is the 2021 xpub-substitution defence as the user meets it: the engine refuses, and
/// the screen has to make the refusal unmistakable and leave a way out that changes nothing.
#[test]
fn a_wallet_this_device_is_not_in_cannot_be_approved_from_the_panel() {
    for (w, h) in GEOMETRIES {
        let mut ui = asked_to_import(w, h);

        // `ours` names a cosigner that does not claim to be this device.
        let mut forged = review(1);
        forged.ours = 3;
        assert_eq!(ui.import_result(ImportOutcome::Pending(forged)), None);
        assert_eq!(ui.screen(), ScreenId::MultisigImport);
        panel_is_sane(&ui, w, h);

        assert!(!has(&ui, RegionId::MsApprove), "{w}x{h}: a forged membership could be approved");
        assert!(!has(&ui, RegionId::ReviewNext), "{w}x{h}: and it is not a review to page through");
        assert!(has(&ui, RegionId::MsReject), "{w}x{h}: with no way to reject it");

        tap(&mut ui, RegionId::MsReject);
        assert_eq!(ui.screen(), ScreenId::MultisigList, "rejecting returns to the registry");
        panel_is_sane(&ui, w, h);
    }
}

/// A refused import lands on the refusal screen and comes back to the registry, rather than
/// leaving the panel on the Busy frame it was reading the card from.
#[test]
fn a_refused_import_is_answered_on_the_panel() {
    for (w, h) in GEOMETRIES {
        let mut ui = asked_to_import(w, h);
        assert_eq!(
            ui.import_result(ImportOutcome::Refused(RefusalNotice {
                code: RefusalCode::CosignerMismatch,
                happened: String::from(
                    "cosigner 2 claims this device's key and names an xpub this seed does not \
                     derive"
                ),
                details: String::from("at=1 origin=m/48'/0'/0'/2'"),
                after_signing: false,
            })),
            None
        );
        assert_eq!(ui.screen(), ScreenId::Refusal, "a refusal is a screen, never silence");
        panel_is_sane(&ui, w, h);

        tap(&mut ui, RegionId::Back);
        assert_eq!(ui.screen(), ScreenId::MultisigList, "and Back is the registry");
        panel_is_sane(&ui, w, h);
    }
}

/// A card that is not there is answered on the registry, with the retry beside the import.
#[test]
fn a_missing_card_is_answered_without_leaving_the_registry() {
    for (w, h) in GEOMETRIES {
        let mut ui = registry(w, h, 0, Vec::new());
        tap(&mut ui, RegionId::MsImport);
        is_busy(&ui, w, h);
        assert_eq!(ui.card_result(CardOutcome::NoCard), None);
        assert_eq!(ui.screen(), ScreenId::MultisigList);
        assert!(has(&ui, RegionId::FileRefresh), "{w}x{h}: no way to try again");
        panel_is_sane(&ui, w, h);
        assert_eq!(
            tap(&mut ui, RegionId::FileRefresh),
            Some(UiRequest::ListCard { dir: String::new(), filter: FileFilter::All })
        );
        is_busy(&ui, w, h);
    }
}

/// A registration the device could not prove is reachable and erasable.
///
/// The row is the only thing standing between the user and a wallet that refuses every
/// transaction it is handed, and deleting it is the whole of the remedy the row states - so
/// a route to that delete has to exist from the registry.
#[test]
fn an_unreadable_registration_can_be_erased_from_the_registry() {
    for (w, h) in GEOMETRIES {
        let mut ui = registry(
            w,
            h,
            1,
            vec![RegistrationInfo { proven: false, slot: 4, ..saved_info() }],
        );
        panel_is_sane(&ui, w, h);
        tap(&mut ui, RegionId::ListRow(4));
        assert_eq!(ui.screen(), ScreenId::MultisigDetail);
        assert!(!has(&ui, RegionId::MsCosigners), "{w}x{h}: it has no cosigners to show");
        assert!(has(&ui, RegionId::MsDelete), "{w}x{h}: and no way to erase it");
        panel_is_sane(&ui, w, h);

        tap(&mut ui, RegionId::MsDelete);
        tap(&mut ui, RegionId::DangerConfirm);
        // With no label in memory the sheet asks for the slot, which the fault card prints.
        type_word(&mut ui, "4");
        assert_eq!(
            tap(&mut ui, RegionId::DangerConfirm),
            Some(UiRequest::DeleteRegistration(4))
        );
        is_busy(&ui, w, h);

        ui.set_registrations(Vec::new());
        assert_eq!(ui.registration_deleted(true), None);
        assert_eq!(ui.screen(), ScreenId::MultisigList);
        panel_is_sane(&ui, w, h);
    }
}

/// A delete the device refused to perform leaves the user on the screen, told so.
///
/// The alternative is a user who believes a registration is gone while it is still on the
/// device - which is the belief that makes them stop looking for it.
#[test]
fn a_delete_the_device_refused_says_so_and_stays() {
    let (w, h) = (720, 720);
    let mut ui = registry(w, h, 1, vec![saved_info()]);
    tap(&mut ui, RegionId::ListRow(0));
    tap(&mut ui, RegionId::MsDelete);
    tap(&mut ui, RegionId::DangerConfirm);
    // Opened from a row, this screen holds no label - so the sheet asks for the SLOT, which
    // is the value its own facts card prints. See `MultisigDetailState::names`.
    type_word(&mut ui, "0");
    assert_eq!(tap(&mut ui, RegionId::DangerConfirm), Some(UiRequest::DeleteRegistration(0)));
    assert_eq!(ui.registration_deleted(false), None);
    assert_eq!(ui.screen(), ScreenId::MultisigDetail, "a refused delete must not leave");
    assert!(has(&ui, RegionId::MsDelete), "and must be tryable again");
    panel_is_sane(&ui, w, h);
}

/// The registry is emptied by a lock, exactly like the wallet list.
///
/// A registration is proven from the seed at open time, so a device with no session has
/// none to show - and a screen that kept rendering the last one would be showing a proof it
/// no longer holds.
#[test]
fn locking_clears_the_registry() {
    let mut ui = registry(720, 720, 1, vec![saved_info()]);
    assert_eq!(ui.registrations().len(), 1);
    assert!(ui.lock());
    assert!(ui.registrations().is_empty(), "a lock must drop what the session proved");
    assert_eq!(ui.screen(), ScreenId::Lock);
}
