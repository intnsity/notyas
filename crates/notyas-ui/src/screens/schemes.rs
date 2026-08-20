// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Schemes: the finished wallet, one tab per derivation scheme, and the QR modal.
//!
//! Only PUBLIC values are drawn and only public values can be offered as a QR: the
//! account xpub, its SLIP-132 rendering, and the receive addresses. There is deliberately
//! no private-key path on this screen at all - no mnemonic, xprv, seed or WIF renders
//! here or leaves the device any other way - which is stronger than masking them.
//!
//! The UI never COMPUTES a QR (the encoder needs std): a tap returns [`UiRequest::Qr`]
//! naming the payload, the embedder encodes it, and the finished matrix comes back
//! through [`SchemesState::open_qr`].
//!
//! # Two journeys end here, and Back is a different promise on each
//!
//! This screen is the end of a wallet's Export card AND the end of a fresh derivation, and
//! the two disagree about what leaving COSTS. From a wallet, nothing is lost by leaving:
//! the wallet still exists, so Back is a step back into it - and it carries the derivation
//! back with it, because the wallet is the only screen that can offer Export again. From a
//! fresh derivation there is nothing behind this screen but the work that produced it, and
//! leaving discards what the user cannot recover, so Back asks first.
//!
//! A screen that behaved the same on both would be wrong for one of them, so the journey is
//! not inferred from the state - it is [`Origin`], named by the caller, and there is no
//! constructor that lets a caller decline to name it.

use alloc::string::String;
use alloc::vec::Vec;

use embedded_graphics::draw_target::{DrawTarget, DrawTargetExt};
use embedded_graphics::pixelcolor::Rgb565;

use crate::canvas::{
    button, fill, frame, mono_wrapped, tabs, text, text_centered, ButtonKind, HEADING, MONO_SMALL,
};
use crate::components::{back_rect, draw_bar, LINE, SMALL_LINE};
use crate::layout::{Metrics, Rect};
use crate::screens::wallet::WalletState;
use crate::screens::{Ctx, Env, Nav, Outcome, Screen, State};
use crate::theme::*;
use crate::{NullTarget, QrData, QrTarget, Region, RegionId, UiRequest, WalletInfo};
use notyas_core::bitcoin::Network;
use notyas_core::derive::Scheme;
use notyas_core::report::{Report, SchemeReport};

/// The QR modal, open over this screen: a finished symbol plus its title.
pub(crate) struct QrModal {
    label: String,
    data: QrData,
}

/// Which journey ended on this screen, and therefore what Back promises here.
///
/// A variant per journey rather than a flag beside the report: [`SchemesState::new`] cannot
/// be called without naming one, so a third caller has to DECIDE what Back means from there
/// before the crate will compile. That is the whole design. What it replaced was an
/// unconditional `Nav::ConfirmExit` written for the journey the screen no longer had, which
/// asked the user to confirm discarding work that was not at risk and then landed them past
/// the wallet they had come from.
pub(crate) enum Origin {
    /// From a wallet's Export card (S-21). Carries that wallet's identity so Back can put
    /// the user back on it.
    ///
    /// A [`WalletInfo`] is entirely public - a name, a slot, a fingerprint, a path - so
    /// this is a copy of facts, never of keys. The keys stay in `report`, in one copy, and
    /// travel back with the user.
    Wallet(WalletInfo),
    /// The end of a fresh derivation: dice or seed words, straight through to the keys.
    ///
    /// There is no wallet behind this one to return to and the work is unrecoverable, so
    /// Back is the exit question - which is what the exit modal's copy already says ("You
    /// can re-enter your dice rolls or seed words to start again").
    ///
    /// Not constructed outside the tests yet: the create flow reaches the fork rather than
    /// this screen, and S-26's second entrance (the end of a verify-existing-seed run,
    /// docs/plan-0.2.0/UX-SCREENS.md S-26) is a 0.2.0 requirement that has not landed. It
    /// is stated here rather than when that route arrives, because deciding Back one route
    /// at a time is how the first origin got it wrong.
    #[cfg_attr(not(test), allow(dead_code))]
    Fresh,
}

pub(crate) struct SchemesState {
    /// The full pipeline output; its own Drop wipes the secrets it holds.
    ///
    /// `Option` for the same reason [`WalletState::report`] is one, one screen over: the
    /// wallet origin's Back MOVES it back into the wallet it came from, out of a
    /// `&mut self` that has no second `Report` to leave in its place. It is empty only
    /// inside the call that also names the state replacing this screen, and `Ui::apply`
    /// drops this one on that call - so no frame is ever built from an empty screen. The
    /// draw path still reads it as an `Option` rather than unwrapping: a panic there would
    /// take the device down to save four lines.
    pub report: Option<Report>,
    /// How the user got here. Decides Back, and nothing else - see [`Origin`].
    origin: Origin,
    tab: usize,
    scroll: i32,
    /// `Some` while the QR modal is open. Filled only through [`SchemesState::open_qr`]
    /// (the embedder answering a [`UiRequest::Qr`]), never computed here.
    qr: Option<QrModal>,
}

impl SchemesState {
    /// The derivation, and where the user came from to see it. Both, always: an export
    /// view that does not know its own way back is the defect this signature prevents.
    pub fn new(report: Report, origin: Origin) -> SchemesState {
        SchemesState { report: Some(report), origin, tab: 0, scroll: 0, qr: None }
    }

    /// Answer to [`UiRequest::Qr`]: install the finished symbol and open the modal.
    pub fn open_qr(&mut self, label: String, data: QrData) {
        self.qr = Some(QrModal { label, data });
    }

    /// The scheme the active tab shows. Clamped and then fetched rather than indexed
    /// blindly: the tab is user state and the scheme list is the core's, and a panic in the
    /// draw path would take the device down over a cosmetic disagreement. `None` also
    /// covers the instant the report is on its way back to the wallet (see the field).
    fn active(&self) -> Option<&SchemeReport> {
        let report = self.report.as_ref()?;
        report.schemes.get(self.tab.min(report.schemes.len().saturating_sub(1)))
    }
}

pub(crate) struct Layout {
    tabs: Rect,
    info_y: i32,
    viewport: Rect,
}

/// QR button geometry: fixed physical size, not panel-derived - fingers do not scale
/// with the panel (same reasoning as [`crate::layout::DICE_KEY_MIN`]).
const QR_BTN_W: i32 = 96;
const QR_BTN_H: i32 = 56;

impl Screen for SchemesState {
    type Layout = Layout;

    fn layout(&self, ctx: &Ctx) -> Layout {
        let m = &ctx.m;
        let body = m.body();
        let g = m.gap;
        let tabs = Rect::new(body.x, body.y, body.w, 56);
        let info_y = tabs.bottom() + g;
        let vp_top = info_y + SMALL_LINE + g;
        Layout { tabs, info_y, viewport: Rect::new(body.x, vp_top, body.w, body.bottom() - vp_top) }
    }

    fn regions(&self, ctx: &Ctx, out: &mut Vec<Region>) {
        let m = &ctx.m;
        if let Some(qr) = &self.qr {
            // Modal open: like the reveal modal, the sheet below is inert.
            out.push(Region {
                id: RegionId::ModalClose,
                rect: qr_modal_layout(m, qr.data.size() as i32).close,
            });
            return;
        }
        let l = self.layout(ctx);
        out.push(Region { id: RegionId::Back, rect: back_rect(m) });
        let n = Scheme::ALL.len() as i32;
        let seg_w = l.tabs.w / n;
        for i in 0..n {
            let w = if i == n - 1 { l.tabs.w - seg_w * (n - 1) } else { seg_w };
            out.push(Region {
                id: RegionId::Tab(i as u8),
                rect: Rect::new(l.tabs.x + i * seg_w, l.tabs.y, w, l.tabs.h),
            });
        }
        // QR buttons ride the scrolled content: replay the content walk (the same code
        // that draws, so the rects cannot drift) and keep only the buttons fully inside
        // the viewport - a partially clipped button draws but does not tap, which is the
        // honest reading of "half a button".
        let mut buttons = Vec::new();
        let _ = self.content(&mut NullTarget, m, l.viewport.y - self.scroll, Some(&mut buttons));
        out.extend(buttons.into_iter().filter(|b| {
            b.rect.x >= l.viewport.x
                && b.rect.y >= l.viewport.y
                && b.rect.right() <= l.viewport.right()
                && b.rect.bottom() <= l.viewport.bottom()
        }));
    }

    fn draw<D: DrawTarget<Color = Rgb565>>(&self, t: &mut D, ctx: &Ctx) -> Result<(), D::Error> {
        let m = &ctx.m;
        // The report is absent only inside the Back that is handing it to the wallet, and
        // that call replaces this screen before a frame is asked for. Paper and nothing
        // else beats a panic if that ever stops being true.
        let Some(report) = self.report.as_ref() else { return Ok(()) };
        draw_bar(t, m, "Wallet")?;
        let l = self.layout(ctx);
        let body = m.body();

        let labels: Vec<String> =
            Scheme::ALL.iter().map(|sc| sc.name().to_ascii_uppercase()).collect();
        let label_refs: Vec<&str> = labels.iter().map(String::as_str).collect();
        tabs(t, l.tabs, &label_refs, self.tab)?;

        // Public wallet identity line: the master fingerprint is the standard cross-check
        // handle, and whether a passphrase was applied is exactly what the user must
        // verify. On testnet the line says so - a tb1/tpub screen must never pass for a
        // mainnet wallet at a glance.
        let info = format!(
            "fingerprint {} - passphrase {}{}",
            report.root_fingerprint,
            if report.has_passphrase { "ON" } else { "off" },
            if report.network == Network::Bitcoin { "" } else { " - TESTNET" }
        );
        text(t, &info, body.x, l.info_y, MONO_SMALL, INK_SECONDARY, PAPER_1)?;

        {
            let mut clip = t.clipped(&l.viewport.to_eg());
            self.content(&mut clip, m, l.viewport.y - self.scroll, None)?;
        }

        if let Some(qr) = &self.qr {
            draw_qr_modal(t, m, qr)?;
        }
        Ok(())
    }

    fn activate(&mut self, id: RegionId, _env: &mut Env) -> Outcome {
        match id {
            RegionId::Tab(i) if (i as usize) < Scheme::ALL.len() => {
                self.tab = i as usize;
                self.scroll = 0;
                Outcome::stay()
            }
            // The QR buttons: every payload here is a PUBLIC value (module note). The
            // request carries the exact string the screen shows - encoding happens on the
            // embedder's std side, the modal opens via `open_qr`.
            RegionId::QrXpub => {
                let Some(sr) = self.active() else { return Outcome::stay() };
                let acct = &sr.derived.account;
                Outcome::ask(UiRequest::Qr(QrTarget {
                    label: format!("Account xpub {}", acct.path),
                    payload: acct.xpub.clone(),
                }))
            }
            RegionId::QrSlip132 => {
                let Some(sr) = self.active() else { return Outcome::stay() };
                match (sr.derived.account.slip132_pub.as_ref(), sr.scheme.slip132_labels()) {
                    (Some(slip), Some((_, label))) => Outcome::ask(UiRequest::Qr(QrTarget {
                        label: format!("{label} {}", sr.derived.account.path),
                        payload: slip.clone(),
                    })),
                    _ => Outcome::stay(),
                }
            }
            RegionId::QrAddress(i) => match self
                .active()
                .and_then(|sr| sr.derived.rows.get(i as usize))
            {
                Some(row) => Outcome::ask(UiRequest::Qr(QrTarget {
                    label: row.path.clone(),
                    payload: row.address.clone(),
                })),
                None => Outcome::stay(),
            },
            RegionId::ModalClose => {
                self.qr = None;
                Outcome::stay()
            }
            _ => Outcome::stay(),
        }
    }

    /// Back, and it is a different promise per [`Origin`].
    ///
    /// From a wallet it is a step back into a wallet that still exists, so it moves rather
    /// than asks - and the derivation goes back with the user, because the wallet gates its
    /// Export and Sign cards on holding one, and a wallet returned to without its keys is a
    /// wallet that has lost the ability to sign. The move is an ENTER and not a pop: the
    /// wallet home is a pure function of its identity and its keys, both of which are in
    /// hand here, so rebuilding it is lossless and leaves the stack the depth it was -
    /// while a push at the Export card would have left a keyless copy of this same wallet
    /// buried under the new one for as long as the session lasts.
    ///
    /// From a fresh derivation there is nothing behind this screen but work that cannot be
    /// recovered, and the exit modal is the question that fits.
    ///
    /// This is [`Screen::back_moving`] and not [`Screen::back`] because the handoff is a
    /// MOVE: a `&self` receiver could only copy the keys or defer the return to a second
    /// tap.
    fn back_moving(&mut self) -> Nav {
        let info = match &self.origin {
            Origin::Wallet(info) => info.clone(),
            Origin::Fresh => return Nav::ConfirmExit,
        };
        Nav::Enter(State::Wallet(WalletState::new(info, self.report.take())))
    }

    /// The sheet under an open QR modal is inert, scrolling included.
    fn scroll_mut(&mut self) -> Option<&mut i32> {
        if self.qr.is_some() {
            None
        } else {
            Some(&mut self.scroll)
        }
    }

    fn scroll_limit(&self, ctx: &Ctx) -> i32 {
        let l = self.layout(ctx);
        let end = self.content(&mut NullTarget, &ctx.m, l.viewport.y, None).unwrap_or_default();
        (end - l.viewport.y - l.viewport.h).max(0)
    }
}

impl SchemesState {
    /// Draws (or measures, against [`NullTarget`]) the active tab's content starting at
    /// `y0`; returns the y after the last line. When `buttons` is given the QR buttons'
    /// regions are collected in content coordinates - the caller filters by viewport.
    fn content<D: DrawTarget<Color = Rgb565>>(
        &self,
        t: &mut D,
        m: &Metrics,
        y0: i32,
        mut buttons: Option<&mut Vec<Region>>,
    ) -> Result<i32, D::Error> {
        let body = m.body();
        let g = m.gap;
        // Nothing to measure or draw while the report is on its way back to the wallet (see
        // the field); the caller reads this as "the content ended where it began".
        let Some(sr) = self.active() else { return Ok(y0) };
        let acct = &sr.derived.account;
        let mut y = y0;

        text(t, &format!("Account {}", acct.path), body.x, y, HEADING, INK_PRIMARY, PAPER_1)?;
        y += LINE + g;

        y = qr_block(t, m, y, "Account xpub", &acct.xpub, RegionId::QrXpub, &mut buttons)?;
        if let (Some(slip), Some((_, label))) = (&acct.slip132_pub, sr.scheme.slip132_labels()) {
            y += g;
            y = qr_block(
                t,
                m,
                y,
                &format!("{label} (SLIP-132)"),
                slip,
                RegionId::QrSlip132,
                &mut buttons,
            )?;
        }

        y += g * 2;
        text(t, "Receive addresses", body.x, y, HEADING, INK_PRIMARY, PAPER_1)?;
        y += LINE + g;
        for (i, row) in sr.derived.rows.iter().enumerate() {
            y = qr_block(
                t,
                m,
                y,
                &row.path,
                &row.address,
                RegionId::QrAddress(i as u8),
                &mut buttons,
            )?;
            y += g;
        }
        Ok(y)
    }
}

/// One caption + wrapped-value block with a QR button on the right; returns the y after
/// the block. The value wraps beside the button column, and the block is never shorter
/// than the button so consecutive buttons cannot overlap.
#[allow(clippy::too_many_arguments)] // one deep helper beats five drifting copies
fn qr_block<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    m: &Metrics,
    y: i32,
    caption: &str,
    value: &str,
    id: RegionId,
    buttons: &mut Option<&mut Vec<Region>>,
) -> Result<i32, D::Error> {
    let body = m.body();
    let rect = Rect::new(body.right() - QR_BTN_W, y, QR_BTN_W, QR_BTN_H);
    button(t, rect, "QR", ButtonKind::Secondary, PAPER_1)?;
    if let Some(list) = buttons {
        list.push(Region { id, rect });
    }
    let vw = body.w - QR_BTN_W - m.gap;
    text(t, caption, body.x, y, MONO_SMALL, INK_MUTED, PAPER_1)?;
    let end = mono_wrapped(
        t,
        value,
        Rect::new(body.x, y + SMALL_LINE, vw, i32::MAX / 2),
        MONO_SMALL,
        INK_PRIMARY,
        PAPER_1,
    )?;
    Ok(end.max(y + QR_BTN_H))
}

// ---------------------------------------------------------------------------------------
// QR modal
// ---------------------------------------------------------------------------------------

/// Light margin around the symbol, in modules. ISO/IEC 18004's four: the core's
/// `matrix()` deliberately ships no quiet zone (it belongs to the drawing - see that
/// module's docs), so the modal is the place that draws it.
const QR_QUIET: i32 = 4;

struct QrModalLayout {
    panel: Rect,
    label_y: i32,
    /// Free area between label and Close that the symbol is centered in. Read by the
    /// largest-fit layout test; the draw path only needs the finished `sym`.
    #[cfg_attr(not(test), allow(dead_code))]
    area: Rect,
    /// The full drawn symbol including the quiet zone, centered in `area`.
    sym: Rect,
    /// Pixels per module. Integer, so modules stay crisp squares a scanner can read;
    /// always the largest that fits, floored at 1.
    scale: i32,
    close: Rect,
}

fn qr_modal_layout(m: &Metrics, size: i32) -> QrModalLayout {
    let panel = m.screen().inset(m.pad);
    let pad = m.pad;
    let btn_h = m.btn.min(72);
    let label_y = panel.y + pad;
    let close_w = (panel.w / 3).clamp(180, 280);
    let close =
        Rect::new(panel.x + (panel.w - close_w) / 2, panel.bottom() - pad - btn_h, close_w, btn_h);
    let area_y = label_y + LINE + m.gap;
    let area = Rect::new(panel.x + pad, area_y, panel.w - 2 * pad, close.y - m.gap - area_y);
    let total = size + 2 * QR_QUIET;
    let scale = (area.w.min(area.h) / total.max(1)).max(1);
    let side = total * scale;
    let sym = Rect::new(area.x + (area.w - side) / 2, area.y + (area.h - side) / 2, side, side);
    QrModalLayout { panel, label_y, area, sym, scale, close }
}

fn draw_qr_modal<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    m: &Metrics,
    qr: &QrModal,
) -> Result<(), D::Error> {
    let size = qr.data.size() as i32;
    let l = qr_modal_layout(m, size);
    // Paper-3 like every modal; a 2px neutral frame (this modal shows a public value -
    // the danger frame stays reserved for the reveal gate). The white panel doubles as
    // the symbol's quiet zone surface.
    fill(t, l.panel, PAPER_3)?;
    frame(t, l.panel, BORDER_STRONG)?;
    frame(t, l.panel.inset(1), BORDER_STRONG)?;
    let title = Rect::new(l.panel.x + m.pad, l.label_y, l.panel.w - 2 * m.pad, LINE);
    text_centered(t, &qr.label, title, HEADING, INK_PRIMARY, PAPER_3)?;

    // The symbol: dark modules as horizontal runs (one fill per run, not per module).
    // Ink on white, drawn at integer scale so every module is an exact square.
    let origin_x = l.sym.x + QR_QUIET * l.scale;
    let origin_y = l.sym.y + QR_QUIET * l.scale;
    for y in 0..size {
        let mut x = 0;
        while x < size {
            if qr.data.module(x as u16, y as u16) {
                let run_start = x;
                while x < size && qr.data.module(x as u16, y as u16) {
                    x += 1;
                }
                fill(
                    t,
                    Rect::new(
                        origin_x + run_start * l.scale,
                        origin_y + y * l.scale,
                        (x - run_start) * l.scale,
                        l.scale,
                    ),
                    INK_PRIMARY,
                )?;
            } else {
                x += 1;
            }
        }
    }

    button(t, l.close, "Close", ButtonKind::Primary, PAPER_3)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::screens::testing::GEOMETRIES;
    use crate::{BackupState, PassphraseState, WalletKind};

    /// The 12-word all-`abandon` vector: a real derivation with nothing in it, so a test
    /// can hold keys without inventing a wallet worth stealing.
    const TEST_PHRASE: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon about";

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
                count: crate::ADDRESS_ROWS,
                script_type: 2,
            },
        )
        .expect("a phrase with words in it derives")
    }

    fn info() -> WalletInfo {
        WalletInfo {
            slot: 3,
            name: String::from("kitchen"),
            fingerprint: String::from("73c5da0a"),
            path: String::from("m/84'/0'/0'"),
            script_type: String::from("native segwit"),
            kind: WalletKind::SingleSig,
            backup: BackupState::Verified(String::new()),
            network: Network::Bitcoin,
            registrations: 0,
            stored: true,
            passphrase: PassphraseState::None,
        }
    }

    /// Back off the export view of a WALLET returns to that wallet, and returns its keys
    /// with it.
    ///
    /// Both halves are the bug. Landing anywhere else is what the owner sees as "it takes
    /// me to the home screen"; landing there without the derivation is what a naive
    /// enter-to-push swap produces, and it is worse - the wallet gates Export AND Sign on
    /// holding one, so the device silently loses the ability to sign until the user backs
    /// out to the list and re-opens the wallet.
    #[test]
    fn back_from_a_wallet_export_returns_the_wallet_with_its_keys() {
        let mut s = SchemesState::new(report(), Origin::Wallet(info()));
        let nav = s.back_moving();
        let State::Wallet(wallet) = (match nav {
            Nav::Enter(next) => next,
            _ => panic!("Back from a wallet export must land on that wallet"),
        }) else {
            panic!("Back from a wallet export must land on a WALLET");
        };
        assert_eq!(wallet.info.slot, 3, "and on the wallet it was exported from");
        assert!(wallet.report.is_some(), "the wallet came back without its keys");
        assert!(s.report.is_none(), "the keys were copied rather than handed over");
    }

    /// ...and the other journey keeps the question, because there the work IS at risk.
    ///
    /// One screen, two origins, two answers: this is the pair that makes the origin worth
    /// storing. A screen that answered either of these the other way would be wrong for
    /// exactly one of its two callers.
    #[test]
    fn back_from_a_fresh_derivation_still_asks_before_discarding_it() {
        let mut s = SchemesState::new(report(), Origin::Fresh);
        assert!(matches!(s.back_moving(), Nav::ConfirmExit));
        assert!(s.report.is_some(), "the question is not the move: nothing may leave yet");
    }

    /// The QR modal at every real symbol size the 0.1.0 targets produce (v3 addresses
    /// through v7 zpubs) plus the format extremes: integer scale, largest fit, symbol
    /// centered between label and Close, everything inside the panel.
    #[test]
    fn qr_modal_scales_integer_and_fits() {
        for (w, h) in GEOMETRIES {
            let m = Metrics::new(w, h);
            for size in [21, 29, 33, 45, 57, 177] {
                let l = qr_modal_layout(&m, size);
                let total = size + 2 * QR_QUIET;
                assert!(l.scale >= 1, "{w}x{h} size {size}: scale floor");
                assert_eq!(l.sym.w, total * l.scale, "{w}x{h} size {size}: integer scale");
                assert_eq!(l.sym.w, l.sym.h, "{w}x{h} size {size}: square");
                // Largest fit: one more scale step would overflow the free area
                // (unless the floor of 1 is already too big, as for v40 on tiny areas).
                if total * (l.scale + 1) <= l.area.w.min(l.area.h) {
                    panic!("{w}x{h} size {size}: scale {} is not the largest fit", l.scale);
                }
                // Centered in the free area (integer division may leave 1px bias).
                assert!(((l.sym.x - l.area.x) - (l.area.right() - l.sym.right())).abs() <= 1);
                assert!(((l.sym.y - l.area.y) - (l.area.bottom() - l.sym.bottom())).abs() <= 1);
                // Fully inside the panel, clear of label and Close.
                assert!(l.sym.x >= l.panel.x && l.sym.right() <= l.panel.right());
                assert!(l.sym.y >= l.label_y + LINE, "{w}x{h} size {size}: overlaps label");
                assert!(l.sym.bottom() <= l.close.y, "{w}x{h} size {size}: overlaps Close");
                assert!(l.close.bottom() <= l.panel.bottom());
            }
        }
    }
}
