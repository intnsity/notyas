// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Receive: one address at a time, with a QR code, a Next button, and an SD save.

use alloc::string::String;
use alloc::vec::Vec;

use embedded_graphics::draw_target::DrawTarget;
use embedded_graphics::pixelcolor::Rgb565;

use crate::canvas::{button, fill, frame, mono_wrapped, mono_wrapped_height, text, ButtonKind, BODY, HEADING, MONO_SMALL};
use crate::components::{back_rect, draw_bar, LINE};
use crate::layout::Rect;
use crate::qr::QrData;
use crate::screens::schemes::default_scheme_index;
use crate::screens::{Ctx, Env, Nav, Outcome, Screen};
use crate::theme::*;
use crate::{Region, RegionId, Report, UiRequest};
use notyas_core::derive::Scheme;

const QR_QUIET: i32 = 4;

/// The scheme in the words the reader has to be able to repeat.
///
/// The address on this screen is about to be handed to somebody who will send money to
/// it, and the string itself does not answer "which derivation is this" - a `1...`
/// address and a `bc1...` address look like two formats, not like two wallets. The BIP
/// number alone is not the answer either, because owners meet these as script names in
/// coordinators; the line carries both so it matches whichever word the reader already
/// knows. Exhaustive over [`Scheme`] rather than a catch-all: a scheme added without a
/// name here should fail to compile, not render an address with no provenance.
fn scheme_label(scheme: Scheme) -> &'static str {
    match scheme {
        Scheme::Bip44 => "BIP-44 legacy",
        Scheme::Bip49 => "BIP-49 wrapped segwit",
        Scheme::Bip84 => "BIP-84 native segwit",
        Scheme::Bip86 => "BIP-86 taproot",
        // No address rows are derived for multisig (see `derive::derive`), so this screen
        // cannot open on it - named anyway, because the compiler is what keeps that true.
        Scheme::Bip48 => "BIP-48 multisig",
    }
}

/// Separator between the scheme name and the path on the provenance line. Held as a
/// constant because the width test measures the same three runs the draw path paints.
const LABEL_SEP: &str = " - ";

pub(crate) struct ReceiveState {
    index: usize,
    /// Which derivation these addresses came from. Drawn beside the path, because an
    /// address handed out with no scheme beside it is the funnel that put an owner's
    /// coins in a legacy wallet the device would not spend from.
    scheme: Scheme,
    address: String,
    path: String,
    qr: Option<QrData>,
    rows: Vec<(String, String)>,
    /// A status band shown after a Save-to-SD attempt. Cleared by the next tap.
    status: Option<String>,
    /// Set by a [`crate::SaveAddrResult::Collision`]: the next tap on Save to SD raises
    /// the request again with `overwrite` set, which is the confirm. Cleared by any tap
    /// that is not that confirming tap, so paging to a different address never inherits a
    /// yes meant for the one before it.
    confirm_overwrite: bool,
}

impl ReceiveState {
    /// Opens on [`crate::screens::schemes::DEFAULT_SCHEME`], not on whichever scheme the
    /// report happens to list first.
    ///
    /// `schemes.first()` was BIP-44 for every wallet this device derives, so the card an
    /// owner is told to show a sender was a legacy address that nothing on screen named
    /// as one. The index comes from [`default_scheme_index`], which falls back to the
    /// report's first scheme when the wallet has no BIP-84 - a wallet derived for BIP-44
    /// alone must still be able to receive on the addresses its coins are on, and a
    /// receive screen that renders nothing is worse than one showing a legacy address it
    /// labels honestly.
    pub fn new(report: &Report) -> Option<ReceiveState> {
        let scheme = report.schemes.get(default_scheme_index(report))?;
        let row = scheme.derived.rows.first()?;
        let qr = notyas_core::qr::matrix(&row.address)
            .ok()
            .and_then(|m| QrData::from_matrix(&m));
        let rows: Vec<(String, String)> = scheme
            .derived
            .rows
            .iter()
            .map(|r| (r.address.clone(), r.path.clone()))
            .collect();
        Some(ReceiveState {
            index: 0,
            scheme: scheme.scheme,
            address: row.address.clone(),
            path: row.path.clone(),
            qr,
            rows,
            status: None,
            confirm_overwrite: false,
        })
    }

    pub fn advance(&mut self) {
        let next = self.index + 1;
        if next < self.rows.len() {
            self.index = next;
            self.address = self.rows[next].0.clone();
            self.path = self.rows[next].1.clone();
            self.qr = notyas_core::qr::matrix(&self.address)
                .ok()
                .and_then(|m| QrData::from_matrix(&m));
        }
    }
}

pub(crate) struct ReceiveLayout {
    addr_y: i32,
    /// Y where the wrapped address text starts.
    addr_text_y: i32,
    /// Y where the derivation path goes (below the address text).
    path_y: i32,
    /// Height of the wrapped address text block.
    addr_h: i32,
    sym: Rect,
    scale: i32,
    next: Rect,
    save: Rect,
}

impl Screen for ReceiveState {
    type Layout = ReceiveLayout;

    fn layout(&self, ctx: &Ctx) -> ReceiveLayout {
        let m = &ctx.m;
        let body = m.body();
        let g = m.gap;
        let addr_y = body.y + 10;

        // Measure how tall the address text will be when wrapped.
        let vw = body.w - 20;
        let addr_h = mono_wrapped_height(&self.address, vw, MONO_SMALL);

        // Address text starts after the heading.
        let addr_text_y = addr_y + LINE + 2;
        // Path goes after the wrapped address text.
        let path_y = addr_text_y + addr_h + g;

        let qr_size = self.qr.as_ref().map(|q| q.size() as i32).unwrap_or(0);
        // Reserve room for the button row: "Save to SD" and "Next address" side by side.
        // There is no card-detect line on either shipped board, so this device always
        // offers the Save button - it handles the no-card case when the user taps it.
        let btn_area_h = m.btn + g;
        let avail_h = body.bottom() - path_y - LINE - g - btn_area_h - g;
        let avail_w = body.w;
        let total = qr_size + 2 * QR_QUIET;
        let scale = if total > 0 {
            (avail_w.min(avail_h) / total).max(1)
        } else {
            1
        };
        let sym_size = total * scale;
        let sym = Rect::new(
            body.x + (body.w - sym_size) / 2,
            path_y + LINE + g,
            sym_size,
            sym_size,
        );

        let btn_w = ((body.w - g) / 2).max(180).min(body.w);
        let next = Rect::new(
            body.right() - btn_w,
            body.bottom() - m.btn,
            btn_w,
            m.btn,
        );
        let save = Rect::new(
            body.x,
            body.bottom() - m.btn,
            btn_w,
            m.btn,
        );
        ReceiveLayout {
            addr_y,
            addr_text_y,
            path_y,
            addr_h,
            sym,
            scale,
            next,
            save,
        }
    }

    fn regions(&self, ctx: &Ctx, out: &mut Vec<Region>) {
        let l = self.layout(ctx);
        out.push(Region {
            id: RegionId::Back,
            rect: back_rect(&ctx.m),
        });
        out.push(Region {
            id: RegionId::SaveAddr,
            rect: l.save,
        });
        out.push(Region {
            id: RegionId::NextAddr,
            rect: l.next,
        });
    }

    fn draw<D: DrawTarget<Color = Rgb565>>(
        &self,
        t: &mut D,
        ctx: &Ctx,
    ) -> Result<(), D::Error> {
        let m = &ctx.m;
        draw_bar(t, m, "Receive address")?;
        let l = self.layout(ctx);
        let body = m.body();

        text(
            t,
            &format!("Address #{}", self.index),
            body.x,
            l.addr_y,
            HEADING,
            INK_PRIMARY,
            PAPER_1,
        )?;

        let vw = body.w - 20;
        mono_wrapped(
            t,
            &self.address,
            Rect::new(body.x, l.addr_text_y, vw, l.addr_h),
            MONO_SMALL,
            INK_PRIMARY,
            PAPER_1,
        )?;

        // Provenance, on one line and in the reading order that matters: the scheme is
        // the fact the reader is being asked to pass on, so it leads and keeps the
        // stronger ink, and the path stays the quiet cross-check it has always been.
        // Three runs rather than one formatted string so the two halves can differ in
        // ink without a second line's worth of vertical budget - which on the 800x480
        // panel comes straight out of the QR symbol.
        let pen = text(
            t,
            scheme_label(self.scheme),
            body.x,
            l.path_y,
            MONO_SMALL,
            INK_SECONDARY,
            PAPER_1,
        )?;
        let pen = text(t, LABEL_SEP, pen, l.path_y, MONO_SMALL, INK_MUTED, PAPER_1)?;
        text(t, &self.path, pen, l.path_y, MONO_SMALL, INK_MUTED, PAPER_1)?;

        if let Some(ref qr) = self.qr {
            let size = qr.size() as i32;
            fill(t, l.sym, PAPER_3)?;
            frame(t, l.sym, BORDER_STRONG)?;

            let origin_x = l.sym.x + QR_QUIET * l.scale;
            let origin_y = l.sym.y + QR_QUIET * l.scale;

            for y in 0..size {
                let mut x = 0;
                while x < size {
                    if qr.module(x as u16, y as u16) {
                        let run_start = x;
                        while x < size && qr.module(x as u16, y as u16) {
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
        } else {
            text(t, "Address too long for QR", l.sym.x, l.sym.y, BODY, INK_MUTED, PAPER_1)?;
        }

        // Status band after save attempt
        if let Some(ref status) = self.status {
            text(t, status, body.x, l.save.y - LINE - 4, MONO_SMALL, INK_MUTED, PAPER_1)?;
        }

        button(t, l.save, "Save to SD", ButtonKind::Secondary, PAPER_1)?;
        button(t, l.next, "Next address", ButtonKind::Primary, PAPER_1)?;
        Ok(())
    }

    fn activate(&mut self, id: RegionId, _env: &mut Env) -> Outcome {
        match id {
            RegionId::Back => Outcome { nav: Nav::Back, request: None },
            RegionId::NextAddr => {
                self.advance();
                self.status = None;
                self.confirm_overwrite = false;
                Outcome::stay()
            }
            RegionId::SaveAddr => {
                let overwrite = self.confirm_overwrite;
                self.confirm_overwrite = false;
                self.status = None;
                Outcome::ask(UiRequest::SaveAddress {
                    address: self.address.clone(),
                    overwrite,
                })
            }
            _ => Outcome::stay(),
        }
    }

    fn answered(&mut self, answer: crate::screens::Answer, _env: &mut Env) -> Outcome {
        match answer {
            crate::screens::Answer::SaveAddr(result) => {
                self.confirm_overwrite = matches!(result, crate::SaveAddrResult::Collision(_));
                self.status = Some(match result {
                    crate::SaveAddrResult::Saved(name) => format!("Saved: {}", name),
                    crate::SaveAddrResult::Collision(name) => {
                        format!("{} is already on the card. Tap Save to SD again to overwrite it.", name)
                    }
                    crate::SaveAddrResult::Failed(why) => format!("Save failed: {}", why),
                });
                Outcome::stay()
            }
            _ => Outcome::stay(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::screens::testing::{fits, Fixture, GEOMETRIES};
    use crate::NullTarget;
    use notyas_core::bip39::MnemonicMode;
    use notyas_core::bitcoin::Network;
    use notyas_core::derive::ChildIndex;
    use notyas_core::report::Parameters;

    /// The 12-word all-`abandon` vector: a real derivation with nothing in it, so a test
    /// can hold keys without inventing a wallet worth stealing.
    const TEST_PHRASE: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon about";

    /// A report over exactly `schemes`, in the order given - which is how a test states
    /// "this wallet has no BIP-84" without waiting for a device that derives one that way.
    fn report_over(schemes: &[Scheme]) -> Report {
        Report::from_phrase(
            TEST_PHRASE,
            &Parameters {
                mode: MnemonicMode::Raw,
                passphrase: "",
                network: Network::Bitcoin,
                schemes,
                account: ChildIndex::ZERO,
                change: ChildIndex::ZERO,
                count: crate::ADDRESS_ROWS,
                script_type: 2,
            },
        )
        .expect("a phrase with words in it derives")
    }

    fn report() -> Report {
        report_over(&Scheme::ALL)
    }

    /// The reported defect, at the entrance it came in through: the Receive card showed
    /// `schemes.first()`, which is BIP-44 for every wallet this device derives, so the
    /// address an owner was told to hand a sender was a legacy one.
    ///
    /// Asserted against the OTHER schemes' first rows as well as against BIP-84's, because
    /// "it is not the legacy address" is the half that regresses: an off-by-one that
    /// landed on BIP-49 would satisfy a bare "not BIP-44" check.
    #[test]
    fn receive_opens_on_bip84_not_on_the_reports_first_scheme() {
        let r = report();
        let s = ReceiveState::new(&r).expect("a derived wallet can receive");
        assert_eq!(s.scheme, Scheme::Bip84, "Receive must default to BIP-84");
        let expected = &r.schemes[2];
        assert_eq!(expected.scheme, Scheme::Bip84, "fixture assumption: report order");
        assert_eq!(s.address, expected.derived.rows[0].address);
        assert_eq!(s.path, expected.derived.rows[0].path);
        assert!(s.path.starts_with("m/84'"), "path {}", s.path);
        assert!(s.address.starts_with("bc1q"), "a native segwit address: {}", s.address);
        for other in r.schemes.iter().filter(|sr| sr.scheme != Scheme::Bip84) {
            assert_ne!(s.address, other.derived.rows[0].address, "{:?}", other.scheme);
        }
    }

    /// Paging keeps the scheme: every row on this screen comes from one derivation, so the
    /// label printed beside the path stays true for row 4 as well as row 0.
    #[test]
    fn advancing_stays_on_the_same_derivation() {
        let r = report();
        let mut s = ReceiveState::new(&r).expect("a derived wallet can receive");
        let rows = &r.schemes[2].derived.rows;
        for (i, row) in rows.iter().enumerate().skip(1) {
            s.advance();
            assert_eq!(s.index, i);
            assert_eq!(s.scheme, Scheme::Bip84);
            assert_eq!(s.address, row.address);
            assert_eq!(s.path, row.path);
        }
    }

    /// A wallet with no BIP-84 in it still receives, on the scheme its coins are actually
    /// on. Showing nothing would be the worse failure - it takes an owner's own addresses
    /// away from an owner to avoid naming a scheme - so the fallback is the report's first
    /// scheme, labelled honestly.
    #[test]
    fn a_bip44_only_wallet_receives_on_bip44_and_draws() {
        let r = report_over(&[Scheme::Bip44]);
        let s = ReceiveState::new(&r).expect("a BIP-44 wallet can still receive");
        assert_eq!(s.scheme, Scheme::Bip44);
        assert_eq!(s.address, r.schemes[0].derived.rows[0].address);
        assert!(s.address.starts_with('1'), "a legacy address: {}", s.address);
        assert_eq!(scheme_label(s.scheme), "BIP-44 legacy", "and it says so");
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            s.draw(&mut NullTarget, &f.ctx()).expect("a legacy wallet's receive card draws");
        }
    }

    /// The provenance line fits the panel it is drawn on, on every scheme this screen can
    /// open on and every panel the firmware ships.
    ///
    /// `text` neither wraps nor clips: a line wider than the body runs off the right edge
    /// and the evidence is gone before it reaches a render target - which is why this is
    /// measured against the whole of [`crate::layout::PANELS`] and not against the two
    /// panels the rest of these tests use. The widest label is BIP-49's, and the
    /// measurement is the three runs the draw path paints - the scheme name, the
    /// separator, the path - not a copy of the finished string.
    #[test]
    fn the_provenance_line_fits_every_shipped_panel_on_every_scheme() {
        for scheme in Scheme::ALL {
            let r = report_over(&[scheme]);
            let s = ReceiveState::new(&r).expect("every single-sig scheme derives rows");
            let need = (MONO_SMALL.text_width(scheme_label(s.scheme))
                + MONO_SMALL.text_width(LABEL_SEP)
                + MONO_SMALL.text_width(&s.path)) as i32;
            for (w, h) in crate::layout::PANELS {
                let f = Fixture::new(w, h);
                fits(&format!("{w}x{h} receive"), scheme_label(scheme), need, f.m.body());
            }
        }
    }
}
