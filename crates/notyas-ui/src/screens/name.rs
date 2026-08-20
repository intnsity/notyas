// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! S-20 Name and save: the storing leg of the fork, and the one screen in the create flow
//! that writes to flash.
//!
//! Invariant 2b: the write is ANNOUNCED before it happens, by the C12 notice sitting
//! directly above the button that performs it. The notice names the artifact and states
//! its confidentiality in plain terms - "The PIN is the key" is a mechanism, not a
//! security adjective (copy decision 7).
//!
//! It is also placement (iii) of the ratified Q22, in its strongest form: a passphrase
//! wallet cannot be saved until the owner has explicitly acknowledged that the passphrase
//! is not stored. A warning a habit can skip is not a warning, so this one is a
//! precondition of the button rather than a paragraph beside it.
//!
//! MILESTONES asks for that acknowledgement ONCE per device rather than once per save.
//! It is required per save here, which is strictly stronger, because the gate has to be
//! decidable at the moment of the tap: `Screen::activate` receives the narrow `Env` and
//! not the device-wide `Ctx` (screens/mod.rs, the contract), so a precondition keyed on
//! stored device state could be drawn but not enforced. A wallet with a passphrase is a
//! rare thing to create, so a tap per creation does not become the habit the requirement
//! exists to break.

use alloc::string::String;
use alloc::vec::Vec;

use embedded_graphics::draw_target::{DrawTarget, DrawTargetExt};
use embedded_graphics::pixelcolor::Rgb565;
use zeroize::Zeroizing;

use crate::canvas::{self, button, fill, frame, text, ButtonKind, BODY, MONO_SMALL};
use crate::components::{
    back_rect, draw_bar, draw_keyboard, keyboard, write_notice, write_notice_h, LINE,
};
use crate::layout::Rect;
use crate::screens::{Ctx, Env, Outcome, Screen};
use crate::theme::*;
use crate::{
    secret_buf, BackupState, Page, PassphraseState, Region, RegionId, Secret, UiRequest,
    WalletDraft, WalletInfo, WalletKind, NAME_MAX, PASS_MAX, PHRASE_MAX,
};
use notyas_core::bitcoin::Network;
use notyas_core::report::Report;

/// Characters a wallet name may hold: letters, digits, spaces, `-` and `_` (S-20).
///
/// Filtered at the keyboard rather than refused after the fact, so an illegal character
/// never appears in the field and the rule needs no error message.
/// The rule, as short as it can be said. The keyboard enforces it silently - an illegal
/// character never reaches the field - so this is a description rather than an error.
const NAME_RULE: &str = "Letters, digits, spaces, - and _";

fn allowed(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == ' ' || c == '-' || c == '_'
}

pub(crate) struct NameState {
    /// The BIP-39 phrase this wallet seals under. The screen's only secret, and it is
    /// here rather than borrowed from the fork because the request that carries it is
    /// built from a `&mut self` that cannot reach back.
    pub phrase: Zeroizing<String>,
    /// The public facts the record and the wallet home need. All copied from the report,
    /// none re-derived: a second implementation of the same arithmetic is a second thing
    /// that can be wrong.
    fingerprint: String,
    network: Network,
    /// The passphrase this wallet was derived with, empty where none was applied.
    ///
    /// The screen reads two things from it and draws neither: whether the Q22
    /// acknowledgement gates the save, and what the [`WalletDraft`] carries to the
    /// embedder. It is `Zeroizing` and named in the parent module's drop-equals-zeroize
    /// check, exactly like the phrase beside it.
    pub(super) passphrase: Zeroizing<String>,
    backup: BackupState,
    name: String,
    page: Page,
    /// The keyboard is up. See [`Screen::layout`] for why this screen has two phases.
    typing: bool,
    /// The Q22 acknowledgement has been given on this screen.
    acked: bool,
    /// Set when a PersistWallet was refused, so the failure is reported on the panel
    /// rather than swallowed. Cleared on the next Save tap. (K14)
    pub(crate) save_failed: bool,
    /// Whether the user chose to remember the passphrase on this device.
    /// Only shown when has_passphrase() is true.
    pub(crate) remember_passphrase: bool,
}

impl NameState {
    pub fn new(report: &Report, passphrase: &str) -> NameState {
        // Exact-capacity allocation: a push that reallocated would strand an unwiped
        // partial phrase outside the `Zeroizing` wrapper's reach.
        let mut phrase = secret_buf(PHRASE_MAX);
        phrase.push_str(&report.phrase);
        let mut pass = secret_buf(PASS_MAX);
        pass.push_str(passphrase);
        debug_assert_eq!(
            report.has_passphrase,
            !pass.is_empty(),
            "the carried passphrase and the derivation must describe the same wallet"
        );
        NameState {
            phrase,
            fingerprint: report.root_fingerprint.clone(),
            network: report.network,
            passphrase: pass,
            backup: BackupState::Verified(String::new()),
            name: String::new(),
            page: Page::Lower,
            typing: false,
            acked: false,
            save_failed: false,
            remember_passphrase: false,
        }
    }

    /// Whether a passphrase is part of this wallet. What the Q22 gate keys on, and the
    /// only question this screen asks of the value it carries.
    fn has_passphrase(&self) -> bool {
        !self.passphrase.is_empty()
    }

    /// Whether Save is live. Both preconditions, and whichever one is holding it back
    /// has its reason drawn beside the button.
    fn ready(&self) -> bool {
        !self.name.trim().is_empty() && (self.acked || !self.has_passphrase())
    }

    /// The wallet as it will read once the store has it. Built here rather than by the
    /// `Ui`, because this screen is the only place that holds all of it at once.
    pub fn saved(&self) -> WalletInfo {
        WalletInfo {
            // The embedder assigns the real slot when it seals; until it answers, the
            // wallet home shows the wallet rather than a slot number it invented.
            slot: 0,
            name: String::from(self.name.trim()),
            fingerprint: self.fingerprint.clone(),
            path: String::from("m/84'/0'/0'"),
            script_type: String::from("native segwit"),
            kind: WalletKind::SingleSig,
            backup: self.backup.clone(),
            network: self.network,
            registrations: 0,
            stored: true,
            // `Required` and never `Stored`: a wallet is saved with the passphrase held
            // for the session only, and storing it is a separate decision the owner makes
            // afterwards, per wallet, on the wallet home (Q22 amendment, 2026-08-19).
            passphrase: if self.has_passphrase() {
                PassphraseState::Required
            } else {
                PassphraseState::None
            },
        }
    }
}

/// The C12 notice: what is written, then what anyone who reads it could learn. Named
/// constants because the band is SIZED from them - `write_notice_h` measures the wrap, so
/// a longer sentence grows the band instead of running out of it.
const NOTICE_WHAT: &str = "This writes to the device: one wallet slot, encrypted.";
const NOTICE_CONFIDENTIALITY: &str = "The PIN is the key. Nothing readable leaves here.";
/// Height of the name field.
const FIELD_H: i32 = 56;
/// Height of the acknowledgement row: one line and the box beside it.
const ACK_H: i32 = LINE + 8;

pub(crate) struct Layout {
    field: Rect,
    hint_y: i32,
    ack: Option<Rect>,
    notice: Rect,
    kb: Rect,
    save: Rect,
}

impl Screen for NameState {
    type Layout = Layout;

    /// Two phases of one screen, for the reason the C4d sheet has two: the keyboard and
    /// everything the write has to say do not fit together on the 800x480 panel. The
    /// notice, the acknowledgement and the Save button do fit; so does the keyboard on its
    /// own; so the field raises the keyboard and its Done puts it away again.
    ///
    /// That ordering is also what invariant 2b wants. The C12 notice sits DIRECTLY above
    /// the control that performs the write, and it can only be directly above a control
    /// that is on the screen - so Save exists exactly in the phase where the notice does,
    /// and the phase with a keyboard has no way to write anything.
    fn layout(&self, ctx: &Ctx) -> Layout {
        let m = &ctx.m;
        let body = m.body();
        let g = m.gap;
        let field = Rect::new(body.x, body.y, body.w, FIELD_H);
        let hint_y = field.bottom() + g / 2;
        let none = Rect::new(0, 0, 0, 0);

        if self.typing {
            let kb_top = hint_y + g;
            return Layout {
                field,
                hint_y,
                ack: None,
                notice: none,
                kb: Rect::new(body.x, kb_top, body.w, body.bottom() - kb_top),
                save: none,
            };
        }

        let save = Rect::new(
            body.right() - (body.w * 2 / 5).max(280).min(body.w),
            body.bottom() - m.btn,
            (body.w * 2 / 5).max(280).min(body.w),
            m.btn,
        );
        let notice_h = write_notice_h(body.w, NOTICE_WHAT, NOTICE_CONFIDENTIALITY);
        let notice = Rect::new(body.x, save.y - g - notice_h, body.w, notice_h);
        let ack_h = ACK_H * 2 + g;
        let ack = if self.has_passphrase() {
            Some(Rect::new(body.x, notice.y - g - ack_h, body.w, ack_h))
        } else {
            None
        };
        Layout { field, hint_y, ack, notice, kb: none, save }
    }

    fn regions(&self, ctx: &Ctx, out: &mut Vec<Region>) {
        let l = self.layout(ctx);
        out.push(Region { id: RegionId::Back, rect: back_rect(&ctx.m) });
        out.push(Region { id: RegionId::NameField, rect: l.field });
        if self.typing {
            for k in keyboard(l.kb, self.page) {
                out.push(Region { id: k.id, rect: k.rect });
            }
            return;
        }
        if let Some(ack) = l.ack {
            out.push(Region { id: RegionId::PassNotStoredAck, rect: ack });
        if let Some(a) = l.ack {
            let remember_y = a.y + ACK_H + ctx.m.gap;
            out.push(Region { id: RegionId::RememberPassphraseAck, rect: Rect::new(a.x, remember_y, a.w, ACK_H) });
        }
        }
        out.push(Region { id: RegionId::ConfirmSave, rect: l.save });
    }

    fn draw<D: DrawTarget<Color = Rgb565>>(&self, t: &mut D, ctx: &Ctx) -> Result<(), D::Error> {
        let m = &ctx.m;
        // The fingerprint rides the bar, as it does on the fork: it is the wallet identity
        // the user is being asked to name, and the body below has a write to announce.
        draw_bar(t, m, &format!("Save wallet - {}", self.fingerprint))?;
        let l = self.layout(ctx);
        let body = m.body();

        // The name is typed input and is not a secret: it is a label, and the user must be
        // able to read the one they will pick this wallet out of a list by.
        canvas::field(t, l.field, &self.name, false, self.typing)?;
        if self.name.is_empty() {
            let y = l.field.y + (l.field.h - LINE) / 2;
            text(t, "name this wallet", l.field.x + 12, y, BODY, INK_MUTED, PAPER_3)?;
        }
        // The rule on the left, the budget on the right: both are short enough to sit on
        // one mono line at either panel width, which is what keeps them out of each
        // other and out of the field above them.
        text(t, NAME_RULE, body.x, l.hint_y, MONO_SMALL, INK_MUTED, PAPER_1)?;
        let budget = format!("{}/{NAME_MAX}", self.name.chars().count());
        let bw = MONO_SMALL.text_width(&budget) as i32;
        text(t, &budget, body.right() - bw, l.hint_y, MONO_SMALL, INK_MUTED, PAPER_1)?;

        if self.typing {
            draw_keyboard(t, l.kb, self.page, !self.name.trim().is_empty())?;
            return Ok(());
        }

        // Q22, as a gate rather than a paragraph: the sentence has to be TAPPED, and the
        // save cannot happen until it has been. The full statement was on the fork one
        // screen back; what is here is the part the owner has to own.
        if let Some(r) = l.ack {
            let side = LINE - 10;
            let boxr = Rect::new(r.x, r.y + 4, side, side);
            fill(t, boxr, if self.acked { ACCENT } else { PAPER_3 })?;
            frame(t, boxr, if self.acked { ACCENT } else { BORDER_STRONG })?;
            let tx = boxr.right() + m.gap;
            let mut clip = t.clipped(&Rect::new(tx, r.y, r.right() - tx, r.h).to_eg());
            text(
                &mut clip,
                "This device does not keep my passphrase.",
                tx,
                r.y,
                BODY,
                INK_PRIMARY,
                PAPER_1,
            )?;
        }

        // C12: what is written, then what anyone who reads it could learn.
        write_notice(t, l.notice, NOTICE_WHAT, NOTICE_CONFIDENTIALITY)?;

        // K14: a refused save is reported on the panel, not swallowed.
        if self.save_failed && !self.typing {
            let msg_y = l.hint_y + 22;
            text(t, "Save failed - nothing was written. Try again.",
                 body.x, msg_y, BODY, DANGER, PAPER_1)?;
        }

        let ready = self.ready();
        let kind = if ready { ButtonKind::Primary } else { ButtonKind::Disabled };
        button(t, l.save, "Save wallet", kind, PAPER_1)?;
        // A disabled control always carries its reason, and the reason is whichever
        // precondition is actually holding it back.
        if !ready {
            let why = if self.name.trim().is_empty() {
                "Give the wallet a name."
            } else {
                "Tick the box above."
            };
            let mut clip = t.clipped(
                &Rect::new(body.x, l.save.y, l.save.x - m.gap - body.x, m.btn).to_eg(),
            );
            text(&mut clip, why, body.x, l.save.y + (m.btn - LINE) / 2, BODY, INK_MUTED, PAPER_1)?;
        }
        Ok(())
    }

    fn activate(&mut self, id: RegionId, env: &mut Env) -> Outcome {
        match id {
            RegionId::Key(c) if allowed(c) => {
                if self.name.chars().count() < NAME_MAX {
                    self.name.push(c);
                }
                Outcome::stay()
            }
            RegionId::Space => {
                if self.name.chars().count() < NAME_MAX {
                    self.name.push(' ');
                }
                Outcome::stay()
            }
            RegionId::KeyBackspace => {
                self.name.pop();
                Outcome::stay()
            }
            RegionId::RememberPassphraseAck => {
                self.remember_passphrase = !self.remember_passphrase;
                Outcome::stay()
            }
            RegionId::PassNotStoredAck => {
                self.acked = !self.acked;
                Outcome::stay()
            }
            RegionId::Shift => {
                self.page = if self.page == Page::Lower { Page::Upper } else { Page::Lower };
                Outcome::stay()
            }
            RegionId::PageDigits => {
                self.page = Page::Digits;
                Outcome::stay()
            }
            RegionId::PageLetters => {
                self.page = Page::Lower;
                Outcome::stay()
            }
            RegionId::PageSymbols => {
                self.page = Page::Symbols;
                Outcome::stay()
            }
            // The field raises the keyboard and its Done puts it away again: the two
            // phases of one screen, and the reason the write notice can always be
            // directly above the control that performs the write.
            RegionId::NameField => {
                self.typing = true;
                Outcome::stay()
            }
            RegionId::KeyDone => {
                self.typing = false;
                Outcome::stay()
            }
            // Drawn disabled until every precondition holds, so a tap before then does
            // nothing at all.
            RegionId::ConfirmSave if self.ready() => {
                // Clear the failure flag on retry (K14).
                self.save_failed = false;
                let mut phrase = secret_buf(PHRASE_MAX);
                phrase.push_str(&self.phrase);
                Outcome::ask(UiRequest::PersistWallet(WalletDraft {
                    phrase,
                    name: String::from(self.name.trim()),
                    fingerprint: self.fingerprint.clone(),
                    network: *env.network,
                    // The one journey this value makes. The embedder needs it to write
                    // the record's flag truthfully and to seed the session, so that the
                    // wallet the user just created opens without asking for a passphrase
                    // they typed a minute ago. `Secret` is what lets it ride inside a
                    // `Debug`-deriving enum.
                    passphrase: self
                        .has_passphrase()
                        .then(|| Secret::passphrase(&self.passphrase)),
                    store_passphrase: self.remember_passphrase,
                }))
            }
            _ => Outcome::stay(),
        }
    }
}
