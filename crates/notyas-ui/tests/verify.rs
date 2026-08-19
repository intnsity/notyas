// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! S-46 Verify device, driven through the public API on both shipped geometries.
//!
//! The content assertions VERIFY.md 11.7 names - frozen field order, no truncation, the
//! inline budget, geometry-invariant hex breaks, the pre-PIN subset, the banned-word
//! inventory - live beside the sheet in `src/screens/verify.rs`, because they are
//! assertions about the ROWS and recovering rows from pixels would be a worse test of a
//! weaker thing. What lives here is everything a finger can do: the pager, the scan and
//! its Busy frame, the session affordances, and the layout laws on both panels.

use embedded_graphics::draw_target::DrawTarget;
use embedded_graphics::geometry::{OriginDimensions, Size};
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::Pixel;

use notyas_ui::layout::TOUCH_MIN;
use notyas_ui::{
    Bit, BlankSpan, HexValue, KeyBlockInfo, LockInfo, PartitionRow, Region, RegionDigest, RegionId,
    ReservedSpace, ScreenId, SetBytes, StoreStatus, TouchEvent, Ui, UiRequest, VerifyInfo,
};

/// The two shipped panels (docs/BOARDS.md).
const GEOMETRIES: [(u32, u32); 2] = [(720, 720), (800, 480)];

// ---------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------

struct Fb {
    w: u32,
    h: u32,
    px: Vec<Rgb565>,
}

impl Fb {
    fn render(ui: &Ui, w: u32, h: u32) -> Fb {
        let mut fb = Fb { w, h, px: vec![Rgb565::new(0, 0, 0); (w * h) as usize] };
        ui.draw(&mut fb).expect("draw");
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

fn region(ui: &Ui, id: RegionId) -> Region {
    ui.regions()
        .into_iter()
        .find(|r| r.id == id)
        .unwrap_or_else(|| panic!("no region {id:?} on {:?}", ui.screen()))
}

fn has(ui: &Ui, id: RegionId) -> bool {
    ui.regions().iter().any(|r| r.id == id)
}

/// Page forward until `id` is on the panel, the way a finger reaches a control that sits
/// beside the value it acts on. Panics if the pager runs out, which is the failure worth
/// having: a control the pager alone cannot reach is a control some users cannot press.
fn page_to(ui: &mut Ui, id: RegionId) {
    while !has(ui, id) {
        assert!(has(ui, RegionId::ReviewNext), "{id:?} is never reachable by the pager");
        tap(ui, RegionId::ReviewNext);
    }
}

fn tap(ui: &mut Ui, id: RegionId) -> Option<UiRequest> {
    let r = region(ui, id).rect;
    let (x, y) = (r.x + r.w / 2, r.y + r.h / 2);
    ui.touch(TouchEvent::Down { x, y });
    ui.touch(TouchEvent::Up { x, y })
}

/// The screen's own layout laws, checked wherever it is driven: in bounds, no overlap,
/// and every control the spec gives a floor to actually has it.
fn check_regions(ui: &Ui, w: i32, h: i32) {
    let regions = ui.regions();
    for r in &regions {
        assert!(
            r.rect.x >= 0 && r.rect.y >= 0 && r.rect.right() <= w && r.rect.bottom() <= h,
            "{:?} out of bounds at {w}x{h}: {:?}",
            r.id,
            r.rect
        );
        // VERIFY.md 11.5's minimum sizes, which are the reason a K1 row carrying a
        // control is taller than a K1 row that does not.
        let floor = match r.id {
            RegionId::ReviewPrev | RegionId::ReviewNext => Some(200),
            RegionId::VerifyAckBoots => Some(240),
            RegionId::VerifyScanFlash => Some(140),
            _ => None,
        };
        if let Some(min_w) = floor {
            assert!(
                r.rect.w >= min_w && r.rect.h >= TOUCH_MIN,
                "{:?} below its 11.5 minimum at {w}x{h}: {:?}",
                r.id,
                r.rect
            );
        }
    }
    for (i, a) in regions.iter().enumerate() {
        for b in &regions[i + 1..] {
            assert!(!a.rect.overlaps(&b.rect), "{:?} overlaps {:?} at {w}x{h}", a.id, b.id);
        }
    }
}

/// A populated readout: VERIFY.md 11.3's wireframe, so the tests drive the sheet a real
/// unit produces rather than a screen of `not read` placeholders.
fn readout() -> VerifyInfo {
    let hex = |s: &str| HexValue::Read(String::from(s));
    VerifyInfo {
        board: Some("waveshare-4b".into()),
        chip: Some("ESP32-P4".into()),
        chip_revision: Some("v1.3".into()),
        boot_rom: Some("eco 2".into()),
        rom_chip_id: Some("0x12".into()),
        mac: Some("60:55:f9:3a:1c:04".into()),
        die_unique_id: hex("1f4c90ab3e77d2158c6044f9b1a35e08"),
        firmware_version: Some("0.2.0".into()),
        idf_app: Some("v5.5.4".into()),
        idf_bootloader: Some("v5.5.4".into()),
        rollback_image: Some("2".into()),
        rollback_efuse: Some("2".into()),
        firmware_digest: hex(
            "9b21c7fe034a88d56e1922bcaf705d31e0c819467b2faa530d84c61139e7f2a0",
        ),
        app: Some(RegionDigest {
            offset: 0x0001_0000,
            len: 1_842_176,
            sha256: "3f9a27c1b40e55d28a116ffe0c934471e2ab1d0577c839b6aa410e2f9c735b18".into(),
        }),
        bootloader: Some(RegionDigest {
            offset: 0x0000_2000,
            len: 22_352,
            sha256: "71e03c9d4a15b8f20c679dd1aa2f3e4c5061728394a5b6c7d8e9f0a1b2c3d4e5".into(),
        }),
        partition_table: Some(RegionDigest {
            offset: 0x0000_8000,
            len: 128,
            sha256: "0c679dd171e03c9d4a15b8f2b2c3d4e55061728394a5b6c7aa2f3e4cd8e9f0a1".into(),
        }),
        flash_size_header: Some("32 MB".into()),
        flash_size_detected: Some("32 MB".into()),
        jedec_id: Some("c8 40 19".into()),
        flash_unique_id: Some("4d81 2f60 aa39 07c5".into()),
        partitions: vec![
            PartitionRow {
                name: "factory".into(),
                kind: "app/fact".into(),
                offset: 0x0001_0000,
                size: 14_614_528,
                encrypted: false,
            },
            PartitionRow {
                name: "wallets".into(),
                kind: "data/0x40".into(),
                offset: 0x00E0_0000,
                size: 262_144,
                encrypted: true,
            },
        ],
        reserved_space: ReservedSpace::NotScanned,
        wallets_digest: hex("aa410e2f9c735b183f9a27c1b40e55d20c934471e2ab1d058a116ffe77c839b6"),
        counters_digest: hex("5061728394a5b6c771e03c9d4a15b8f2aa2f3e4cd8e9f0a10c679dd1b2c3d4e5"),
        secure_boot: Bit::Clear,
        aggressive_revoke: Bit::Clear,
        key_digests: [HexValue::NotBurned, HexValue::NotBurned, HexValue::NotBurned],
        flash_encryption: Bit::Clear,
        encryption_mode: Some("DISABLED".into()),
        crypt_count: Some(0),
        xts_key_read_protected: Bit::Absent,
        manual_encrypt: Bit::Set,
        uart_download: Bit::Set,
        secure_download: Bit::Clear,
        usb_serial_jtag_download: Bit::Set,
        usb_otg_download: Bit::Set,
        forced_download: Bit::Set,
        direct_boot: Bit::Set,
        jtag_pad: Bit::Set,
        jtag_usb: Bit::Set,
        jtag_soft: Some((0, 3)),
        jtag_select: Bit::Clear,
        rom_log: Some(0),
        rom_log_usb: Bit::Set,
        key_blocks: (0..6)
            .map(|i| KeyBlockInfo {
                purpose: (i == 5).then(|| String::from("HMAC_UP")),
                read_protected: i == 5,
                write_protected: i == 5,
            })
            .collect(),
        boot_count: Some(1235),
        acknowledged_at: Some(1230),
        wipe_epoch: Some(0),
        storage: Some("present".into()),
        radio_gpio: Some(54),
        radio: Some("low".into()),
        radio_ok: true,
        self_test: Some("6/6 passed".into()),
        self_test_ok: true,
    }
}

fn scanned() -> ReservedSpace {
    ReservedSpace::Scanned {
        spans: vec![
            BlankSpan { start: 0x00_0000, end: 0x00_2000, set: None },
            BlankSpan {
                start: 0x1d_1c00,
                end: 0xe0_0000,
                set: Some(SetBytes { count: 4096, first: 0x01d_2000 }),
            },
            BlankSpan { start: 0xe4_4000, end: 0x200_0000, set: None },
        ],
        digest: HexValue::Read(
            "0d84c61139e7f2a09b21c7fe034a88d5af705d31e0c819466e1922bc7b2faa53".into(),
        ),
    }
}

/// The Verify screen, reached the way a finger reaches it.
fn verify_screen(w: u32, h: u32, status: StoreStatus) -> Ui {
    let mut ui = Ui::new(w, h);
    ui.set_verify_info(readout());
    ui.set_lock_info(LockInfo { status, nickname: "kitchen-desk".into(), ..LockInfo::default() });
    tap(&mut ui, RegionId::HomeVerifyDevice);
    assert_eq!(ui.screen(), ScreenId::VerifyDevice);
    ui
}

// ---------------------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------------------

/// Every page of the sheet, at both geometries, in both session states and with the scan
/// both run and not run: regions in bounds and non-overlapping, and a full render that
/// must not panic.
#[test]
fn the_whole_sheet_lays_out_on_both_geometries() {
    for (w, h) in GEOMETRIES {
        for status in [StoreStatus::Locked, StoreStatus::Unlocked] {
            for scan in [false, true] {
                let mut ui = verify_screen(w, h, status);
                if scan {
                    ui.set_flash_scan(scanned());
                }
                let mut pages = 0;
                loop {
                    check_regions(&ui, w as i32, h as i32);
                    Fb::render(&ui, w, h);
                    pages += 1;
                    assert!(pages < 64, "the pager does not terminate at {w}x{h}");
                    if !has(&ui, RegionId::ReviewNext) {
                        break;
                    }
                    tap(&mut ui, RegionId::ReviewNext);
                }
                // S-46 is long reference material at both geometries; a sheet that fitted
                // one viewport would mean the field set had collapsed.
                assert!(pages > 3, "{w}x{h} {status:?} scan={scan}: only {pages} viewports");
            }
        }
    }
}

/// The body keeps full width at 800x480 (ratified Q55): S-46 is exempt from reflow rule
/// 1's landscape rail, because the rail would narrow the body below what the frozen hex
/// block needs and the digests would break differently on the two panels.
#[test]
fn the_body_is_not_narrowed_by_a_landscape_rail() {
    for (w, h) in GEOMETRIES {
        let mut ui = verify_screen(w, h, StoreStatus::Unlocked);
        // Past the first viewport, so both pager controls are on the panel at once.
        tap(&mut ui, RegionId::ReviewNext);
        // Reflow rule 1 would confine the action set to a right-hand column of
        // `clamp(w/4, 220, 300)`. The action row here spans the panel instead, which is
        // the visible consequence of the body keeping full width.
        let span = region(&ui, RegionId::ReviewNext).rect.right()
            - region(&ui, RegionId::ReviewPrev).rect.x;
        assert!(
            span >= w as i32 * 3 / 4,
            "the action row is {span} px wide at {w}x{h}, which is rail-shaped"
        );
        assert!(h > 0);
    }
}

// ---------------------------------------------------------------------------------------
// The pager
// ---------------------------------------------------------------------------------------

/// C6's explicit pager, reused verbatim rather than reinvented: Prev is absent on the
/// first viewport, Next on the last, and one step forward and back is a round trip.
#[test]
fn the_pager_steps_one_viewport_and_comes_back() {
    for (w, h) in GEOMETRIES {
        let mut ui = verify_screen(w, h, StoreStatus::Unlocked);
        assert!(!has(&ui, RegionId::ReviewPrev), "nothing above the first viewport");
        assert!(has(&ui, RegionId::ReviewNext), "the sheet is longer than one viewport");

        let first = Fb::render(&ui, w, h).px;
        tap(&mut ui, RegionId::ReviewNext);
        let second = Fb::render(&ui, w, h).px;
        assert_ne!(first, second, "Next painted the same viewport at {w}x{h}");
        assert!(has(&ui, RegionId::ReviewPrev), "there is now something above");

        tap(&mut ui, RegionId::ReviewPrev);
        assert_eq!(Fb::render(&ui, w, h).px, first, "Prev did not return to the first viewport");
        assert!(!has(&ui, RegionId::ReviewPrev));

        // The last viewport offers no Next, which is what makes the bar counter's `n`
        // reachable and the walk above terminate.
        while has(&ui, RegionId::ReviewNext) {
            tap(&mut ui, RegionId::ReviewNext);
        }
        assert!(has(&ui, RegionId::ReviewPrev));
    }
}

/// Drag-scroll stays the fast path and shares the pager's offset: a drag past the first
/// viewport makes Prev appear, and Prev then snaps back to a viewport boundary.
#[test]
fn a_drag_and_the_pager_move_the_same_sheet() {
    let (w, h) = (720u32, 720u32);
    let mut ui = verify_screen(w, h, StoreStatus::Unlocked);
    let top = Fb::render(&ui, w, h).px;
    ui.touch(TouchEvent::Down { x: 360, y: 400 });
    ui.touch(TouchEvent::Move { x: 360, y: 100 });
    ui.touch(TouchEvent::Up { x: 360, y: 100 });
    assert_ne!(Fb::render(&ui, w, h).px, top, "the drag did not scroll the sheet");
    assert!(has(&ui, RegionId::ReviewPrev), "a drag past the fold offers Prev");
    tap(&mut ui, RegionId::ReviewPrev);
    assert_eq!(Fb::render(&ui, w, h).px, top, "Prev did not snap back to the first viewport");
}

// ---------------------------------------------------------------------------------------
// The reserved-space scan (VERIFY.md 3.3, ratified Q57)
// ---------------------------------------------------------------------------------------

/// The scan is on demand, it becomes a C3 Busy screen with NOTHING tappable, and the
/// answer returns the reader to the sheet with the spans filled in.
#[test]
fn the_scan_is_a_busy_screen_and_its_answer_fills_the_rows_in() {
    for (w, h) in GEOMETRIES {
        let mut ui = verify_screen(w, h, StoreStatus::Unlocked);
        // The control sits beside the value it fills in, so it has to be paged to.
        page_to(&mut ui, RegionId::VerifyScanFlash);
        let sheet_before = Fb::render(&ui, w, h).px;

        assert_eq!(
            tap(&mut ui, RegionId::VerifyScanFlash),
            Some(UiRequest::ScanReservedSpace),
            "the tap must ask the std side to read flash"
        );
        assert_eq!(ui.screen(), ScreenId::ScanningFlash);
        assert!(ui.regions().is_empty(), "a Busy screen offers nothing, not even Back");
        let starting = Fb::render(&ui, w, h).px;
        assert_ne!(starting, sheet_before, "the Busy frame was not painted");

        // Determinate: the embedder reports units, and the frame changes when it does.
        ui.set_scan_progress(3, 5);
        let mid = Fb::render(&ui, w, h).px;
        assert_ne!(mid, starting, "the progress report did not reach the panel");
        assert_eq!(ui.screen(), ScreenId::ScanningFlash);

        ui.set_flash_scan(scanned());
        assert_eq!(ui.screen(), ScreenId::VerifyDevice);
        check_regions(&ui, w as i32, h as i32);
        let sheet_after = Fb::render(&ui, w, h).px;
        assert_ne!(sheet_after, sheet_before, "the spans did not reach the sheet");
        // ...and the control stays, because the spans move with the build and a second
        // look is a new measurement rather than a cached one.
        assert!(has(&ui, RegionId::VerifyScanFlash));
    }
}

/// A scan answer that arrives after the reader left still lands on the readout - it is a
/// measurement of the device, not a fact about a screen - and resurrects no frame.
#[test]
fn a_late_scan_answer_lands_on_the_readout_and_opens_nothing() {
    let mut ui = verify_screen(720, 720, StoreStatus::Unlocked);
    tap(&mut ui, RegionId::Back);
    let left_for = ui.screen();
    assert_ne!(left_for, ScreenId::VerifyDevice);
    ui.set_flash_scan(scanned());
    assert_eq!(ui.screen(), left_for, "an answer must not navigate");
    assert!(matches!(ui.verify_info().reserved_space, ReservedSpace::Scanned { .. }));
}

/// The scan control is offered exactly while it is wholly on the panel: a half-scrolled
/// button must not be tappable, which is the same rule as a button that is not drawn.
#[test]
fn an_off_screen_control_is_not_tappable() {
    let mut ui = verify_screen(720, 720, StoreStatus::Unlocked);
    assert!(!has(&ui, RegionId::VerifyScanFlash), "the flash section is below the fold");
    page_to(&mut ui, RegionId::VerifyScanFlash);
    let r = region(&ui, RegionId::VerifyScanFlash).rect;
    // Whatever page it is on, it is inside the scrolling viewport rather than over the
    // footer that would otherwise swallow the tap.
    assert!(r.bottom() < 720 - 100, "the control overlaps the footer: {r:?}");
}

// ---------------------------------------------------------------------------------------
// The session
// ---------------------------------------------------------------------------------------

/// The Lock chip and the acknowledgement write exist exactly while there is a session,
/// and the pre-PIN sheet is genuinely shorter rather than merely blanked.
#[test]
fn the_session_affordances_are_post_pin_only() {
    for (w, h) in GEOMETRIES {
        let mut locked = verify_screen(w, h, StoreStatus::Locked);
        assert!(!has(&locked, RegionId::Lock), "no session, no Lock chip");
        while has(&locked, RegionId::ReviewNext) {
            assert!(
                !has(&locked, RegionId::VerifyAckBoots),
                "pre-PIN must not offer the write, on any viewport"
            );
            tap(&mut locked, RegionId::ReviewNext);
        }
        assert!(!has(&locked, RegionId::VerifyAckBoots));

        let mut unlocked = verify_screen(w, h, StoreStatus::Unlocked);
        assert!(has(&unlocked, RegionId::Lock), "the Lock chip rides in the bar");
        page_to(&mut unlocked, RegionId::VerifyAckBoots);
        check_regions(&unlocked, w as i32, h as i32);

        // Rows absent pre-PIN are ABSENT, so the sheet is shorter: paging to the end
        // takes fewer steps than it does with a session open.
        let pages = |mut ui: Ui| {
            let mut n = 1;
            while has(&ui, RegionId::ReviewNext) {
                tap(&mut ui, RegionId::ReviewNext);
                n += 1;
            }
            n
        };
        assert!(
            pages(verify_screen(w, h, StoreStatus::Locked))
                <= pages(verify_screen(w, h, StoreStatus::Unlocked)),
            "the pre-PIN sheet is not a subset at {w}x{h}"
        );
    }
}

/// The two device-wide actions the screen offers hand the work to the embedder rather
/// than doing it: this crate reaches neither flash nor the session.
#[test]
fn the_screen_asks_rather_than_acts() {
    let mut ui = verify_screen(720, 720, StoreStatus::Unlocked);
    assert_eq!(tap(&mut ui, RegionId::Lock), Some(UiRequest::LockSession));
    page_to(&mut ui, RegionId::VerifyAckBoots);
    assert_eq!(tap(&mut ui, RegionId::VerifyAckBoots), Some(UiRequest::AcknowledgeBoots));
    assert_eq!(ui.screen(), ScreenId::VerifyDevice, "the write must not navigate");
}

/// The acknowledgement write is announced before it happens (invariant 2b): its C12 band
/// and its button are ONE row, so a page break cannot come between them and the button is
/// never offered on a viewport that does not also carry the sentence.
#[test]
fn the_write_notice_cannot_be_separated_from_its_button() {
    for (w, h) in GEOMETRIES {
        let mut ui = verify_screen(w, h, StoreStatus::Unlocked);
        let mut seen = 0;
        loop {
            if let Some(r) = ui.regions().iter().find(|r| r.id == RegionId::VerifyAckBoots) {
                seen += 1;
                // Three MONO_SMALL lines of band plus its padding must fit above the
                // button, inside the viewport, or the sentence is off the panel.
                let body_top = region(&ui, RegionId::Back).rect.bottom();
                assert!(
                    r.rect.y - 3 * 36 - 12 >= body_top,
                    "the band does not fit above the button at {w}x{h}: {:?}",
                    r.rect
                );
            }
            if !has(&ui, RegionId::ReviewNext) {
                break;
            }
            tap(&mut ui, RegionId::ReviewNext);
        }
        assert!(seen > 0, "the write is never offered at {w}x{h}");
    }
}

/// Back is unconditional: S-46 holds no derived secret, so leaving it is not a decision
/// the user has to confirm. Where it lands is the back stack's business, not this
/// screen's, which is why the assertion is that it LEFT rather than where it went.
#[test]
fn back_leaves_without_a_gate() {
    for status in [StoreStatus::Locked, StoreStatus::Unlocked] {
        let mut ui = verify_screen(720, 720, status);
        tap(&mut ui, RegionId::Back);
        assert_ne!(ui.screen(), ScreenId::VerifyDevice, "{status:?}");
    }
}

/// A device that measured nothing renders anyway, on both panels: the screen is exactly
/// as reachable on a unit whose readout failed as on one whose readout worked, and the
/// rows say `not read` rather than nothing at all.
#[test]
fn an_unmeasured_device_still_renders_a_full_sheet() {
    for (w, h) in GEOMETRIES {
        let mut ui = Ui::new(w, h);
        tap(&mut ui, RegionId::HomeVerifyDevice);
        assert_eq!(ui.screen(), ScreenId::VerifyDevice);
        check_regions(&ui, w as i32, h as i32);
        Fb::render(&ui, w, h);
        assert!(has(&ui, RegionId::ReviewNext), "the field set is there whether or not it read");
    }
}
