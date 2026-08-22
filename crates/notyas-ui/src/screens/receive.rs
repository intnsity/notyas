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
use crate::screens::{Ctx, Env, Nav, Outcome, Screen};
use crate::theme::*;
use crate::{Region, RegionId, Report, UiRequest};

const QR_QUIET: i32 = 4;

pub(crate) struct ReceiveState {
    index: usize,
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
    pub fn new(report: &Report) -> Option<ReceiveState> {
        let scheme = report.schemes.first()?;
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

        text(t, &self.path, body.x, l.path_y, MONO_SMALL, INK_MUTED, PAPER_1)?;

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
