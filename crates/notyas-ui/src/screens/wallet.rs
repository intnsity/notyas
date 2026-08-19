// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! S-21 Wallet home (UX 7): the per-wallet hub. Identity first, then what can be done
//! with it.
//!
//! The identity card is the point of the screen. An airgapped device has no chain view,
//! so there are no balances here and never will be - a stale balance is worse than none -
//! and what identifies a wallet is the fingerprint, which is also how a user notices that
//! a passphrase typo has given them a DIFFERENT wallet (commandment 8). Everything on the
//! card is public: a name, eight hex characters, a path, a network.
//!
//! # Which actions exist
//!
//! Only the ones that lead somewhere. The 0.1.0 rule about never drawing an affordance
//! nothing hit-tests decides what this screen carries: a card appears when the screen
//! behind it exists AND this wallet can reach it, and a card that opened nothing would be
//! a worse introduction to the wallet than a shorter list. Multisig is here because S-41
//! is, and it is offered on a STORED wallet only - a registration is a record in a registry
//! slot that names a wallet slot, so a session wallet has nowhere to put one and nothing to
//! list. Sign is here because S-27 is, and it is offered on a STORED wallet holding its
//! derivation - both halves, for the reason on the card itself.
//!
//! Export is offered exactly when this UI holds the derivation, and that is a property of
//! the CALLER rather than of the wallet: a "Use once, keep nothing" session hands it over
//! because the keys ARE this screen's state, and the embedder hands it over for a stored
//! wallet it has just unsealed ([`crate::Ui::wallet_opened_with_keys`]). Without it the
//! card is absent - the UI owns no key ladder and cannot re-derive what it was not given.
//! Export is also the route to the receive addresses: S-26 carries the per-scheme address
//! list, so one card reaches the xpub, the descriptor, the QR codes and the addresses.

use alloc::string::String;
use alloc::vec::Vec;

use embedded_graphics::draw_target::{DrawTarget, DrawTargetExt};
use embedded_graphics::pixelcolor::Rgb565;

use crate::canvas::{button, fill, frame, text, wrap_words, ButtonKind, BODY, HEADING, MONO_SMALL};
use notyas_fonts::Atlas;
use crate::components::{back_rect, draw_bar, LINE, SMALL_LINE};
use crate::danger::{Danger, DangerGrade, DangerOutcome};
use crate::layout::{Rect, LIST_ROW_MIN};
use crate::screens::multisig::MultisigListState;
use crate::screens::wallets::chip;
use crate::screens::schemes::SchemesState;
use crate::screens::wallets::WalletsState;
use crate::screens::{Ctx, Env, Nav, Outcome, Screen, State};
use crate::theme::*;
use crate::{BackupState, Region, RegionId, StoreStatus, UiRequest, WalletInfo};
use notyas_core::bitcoin::Network;
use notyas_core::report::Report;

pub(crate) struct WalletState {
    pub info: WalletInfo,
    /// The derivation behind this wallet, when the caller had one to give: a session
    /// wallet, because nothing was written and this state IS the wallet, or a stored one
    /// the embedder unsealed and handed over. `None` where the keys stayed sealed on the
    /// std side - this crate owns no key ladder and can derive nothing back.
    ///
    /// `Option` because Export moves it into the schemes screen out of a `&mut self`.
    pub report: Option<Report>,
    /// The open danger sheet, while the user is being asked to consent to a delete.
    ///
    /// One field for both steps of the C4d sequence: the sheet knows its own grade, so
    /// "the consequence has been read" and "the name has been typed" are the same
    /// `Confirmed` answer asked of two different sheets, and there is no second flag to
    /// disagree with it.
    danger: Option<Danger>,
}

impl WalletState {
    /// This wallet, with the derivation behind it if the caller has one.
    ///
    /// ONE constructor over the one axis that matters, rather than a pair named after the
    /// two situations it was first used in: whether the store holds the wallet
    /// (`info.stored`) and whether this screen holds its keys (`report`) are INDEPENDENT
    /// facts, and a constructor per situation made the four combinations look like two.
    /// The one that was missing is the one the product needs most - a STORED wallet the
    /// embedder has just unsealed, which is both - and its absence is why a wallet behind
    /// the PIN could be deleted and nothing else.
    pub fn new(info: WalletInfo, report: Option<Report>) -> WalletState {
        WalletState { info, report, danger: None }
    }

    /// What deleting this wallet destroys, and what the way back is.
    ///
    /// Read off the wallet in hand rather than written as a constant: the registration
    /// count is runtime state, and Q14 deferred encrypted backup to 0.3.0, so a
    /// registration really has no recovery path on this device and the sentence that says
    /// so has to be here rather than in a manual. The closing line is the product one
    /// backup sentence, word for word (copy decision 8).
    fn consequence(&self) -> Vec<String> {
        let slot = match self.info.registrations {
            0 => String::from("This erases the stored wallet slot."),
            1 => String::from(
                "This erases the stored wallet slot and its 1 multisig registration.",
            ),
            n => format!(
                "This erases the stored wallet slot and its {n} multisig registrations."
            ),
        };
        let mut lines = alloc::vec![slot];
        if self.info.registrations > 0 {
            lines.push(String::from(
                "A registration cannot be re-derived from your seed. Import it again from \
                 your other devices.",
            ));
        }
        lines.push(String::from("Your dice rolls or seed words are the only way back."));
        lines
    }

    /// The first sheet: what deleting this wallet destroys, on a sheet with room to say
    /// it. The typed step follows and has a keyboard where this prose would be.
    fn read_sheet(&self) -> Danger {
        let lines = self.consequence();
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        Danger::confirm("Delete this wallet?", &refs, "Continue")
    }

    /// The second sheet: the consent itself.
    ///
    /// The required word is the wallet's own name. A user who cannot type it is not
    /// certain which wallet they are looking at, which is exactly when the device should
    /// not proceed.
    fn type_sheet(&self) -> Danger {
        let lines = self.consequence();
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        Danger::typed(
            &format!("Delete \"{}\"", self.info.name),
            &refs[..1],
            "Delete wallet",
            &self.info.name,
        )
    }
}

/// Height of the identity card: the name, then three rows of paired facts, and its own
/// padding. Four rows rather than three because every row here is a PAIR - a caption on
/// the left and a value on the right - and three rows meant three values sharing a line
/// with a fourth, which is how a fingerprint ends up with its tail under a badge.
const CARD_H: i32 = LINE + 3 * SMALL_LINE + 24;

pub(crate) struct Layout {
    card: Rect,
    /// The action cards that exist on this wallet, in draw and hit-test order.
    actions: Vec<(RegionId, Rect)>,
    lock_chip: Rect,
    /// The session warning band, present exactly when nothing was written.
    session: Option<Rect>,
}

impl Screen for WalletState {
    type Layout = Layout;

    fn layout(&self, ctx: &Ctx) -> Layout {
        let m = &ctx.m;
        let body = m.body();
        let g = m.gap;
        let card = Rect::new(body.x, body.y, body.w, CARD_H);

        // The band that says nothing was written. It is above the actions, not below
        // them, because it changes what every one of them means.
        let session = if self.info.stored {
            None
        } else {
            Some(Rect::new(body.x, card.bottom() + g, body.w, 2 * LINE))
        };
        let top = session.map_or(card.bottom(), |s| s.bottom()) + g;

        let mut ids = Vec::new();
        // Sign leads, because it is what the device is for. It needs BOTH facts, and the
        // second one is the surprising half: signing runs on the std side's seed, and the
        // only seed the std side ever holds is the one it unsealed out of a slot. A "use
        // once, keep nothing" session hands this screen a derivation without ever handing
        // the embedder a seed, so a Sign card there would raise a request that could only
        // be refused - which is the affordance-that-leads-nowhere this screen's whole
        // action list is written against. That is a real gap in 0.2.0 and it is stated
        // here rather than papered over: a stateless signing entry (S-40) is what closes
        // it, and it does not exist yet.
        if self.info.stored && self.report.is_some() {
            ids.push(RegionId::ActSign);
        }
        // Export needs only the derivation, because the keys ARE this screen's state.
        if self.report.is_some() {
            ids.push(RegionId::ActExport);
        }
        if self.info.stored {
            ids.push(RegionId::ActMultisig);
            ids.push(RegionId::WalletDelete);
        }
        let actions = action_grid(ids, Rect::new(body.x, top, body.w, body.bottom() - top), g);

        Layout { card, actions, lock_chip: chip(m), session }
    }

    fn regions(&self, ctx: &Ctx, out: &mut Vec<Region>) {
        // While a sheet is open it is the only thing on the panel: the wallet beneath is
        // as inert to a finger as it is invisible.
        if let Some(d) = &self.danger {
            d.regions(&ctx.m, out);
            return;
        }
        let l = self.layout(ctx);
        out.push(Region { id: RegionId::Back, rect: back_rect(&ctx.m) });
        if ctx.lock.status == StoreStatus::Unlocked {
            out.push(Region { id: RegionId::Lock, rect: l.lock_chip });
        }
        for (id, rect) in l.actions {
            out.push(Region { id, rect });
        }
    }

    fn draw<D: DrawTarget<Color = Rgb565>>(&self, t: &mut D, ctx: &Ctx) -> Result<(), D::Error> {
        let m = &ctx.m;
        if let Some(d) = &self.danger {
            return d.draw(t, m, ctx.press, ctx.hold_released);
        }
        draw_bar(t, m, &self.info.name)?;
        let l = self.layout(ctx);
        if ctx.lock.status == StoreStatus::Unlocked {
            button(t, l.lock_chip, "Lock device", ButtonKind::Secondary, PAPER_2)?;
        }

        // Identity card. Mono for everything a user compares against another device, and
        // every row is a PAIR drawn into its own half, so a long name or a long path
        // crops rather than running under the value beside it.
        fill(t, l.card, PAPER_2)?;
        frame(t, l.card, BORDER_STRONG)?;
        let inner = l.card.inset(m.gap);
        {
            // Scoped: the clip belongs to the card, and the band below it is not part
            // of the card.
            let mut clip = t.clipped(&inner.to_eg());
            pair(
                &mut clip,
                Rect::new(inner.x, inner.y, inner.w, LINE),
                (&self.info.name, HEADING, INK_PRIMARY),
                (self.info.kind.badge(), HEADING, INK_SECONDARY),
                m.gap,
            )?;
            let backup = match &self.info.backup {
                BackupState::Verified(on) if on.is_empty() => String::from("backup verified"),
                BackupState::Verified(on) => format!("backup verified {on}"),
                BackupState::Unchecked => String::from("BACKUP UNCHECKED"),
            };
            let backup_ink = match self.info.backup {
                BackupState::Verified(_) => SUCCESS,
                BackupState::Unchecked => WARNING,
            };
            let network =
                if self.info.network == Network::Bitcoin { "mainnet" } else { "TESTNET" };
            let passphrase = format!("passphrase {}", if self.info.passphrase { "ON" } else { "off" });
            let fingerprint = format!("fingerprint {}", self.info.fingerprint);
            let rows: [(&str, Rgb565, &str); 3] = [
                (&fingerprint, INK_PRIMARY, &self.info.path),
                (&self.info.script_type, INK_SECONDARY, &passphrase),
                (&backup, backup_ink, network),
            ];
            for (i, (left, ink, right)) in rows.into_iter().enumerate() {
                let row =
                    Rect::new(inner.x, inner.y + LINE + i as i32 * SMALL_LINE, inner.w, SMALL_LINE);
                pair(
                    &mut clip,
                    row,
                    (left, MONO_SMALL, ink),
                    (right, MONO_SMALL, INK_SECONDARY),
                    m.gap,
                )?;
        }
        }

        // The honest statement about a session wallet, in the words S-21 specifies.
        if let Some(r) = l.session {
            let mut y = r.y;
            for line in wrap_words(
                "Not stored. Locking or powering off loses this wallet until you retype \
                 the words.",
                r.w,
                BODY,
            ) {
                text(t, &line, r.x, y, BODY, WARNING, PAPER_1)?;
                y += LINE;
            }
        }

        for (id, rect) in &l.actions {
            let (title, detail, ink) = action_copy(*id);
            fill(t, *rect, if ink == DANGER { DANGER_TINT } else { PAPER_2 })?;
            frame(t, *rect, if ink == DANGER { DANGER } else { BORDER_STRONG })?;
            let inner = rect.inset(m.gap);
            let mut clip = t.clipped(&inner.to_eg());
            text(&mut clip, title, inner.x, inner.y, HEADING, ink, PAPER_2)?;
            text(&mut clip, detail, inner.x, inner.y + LINE, MONO_SMALL, INK_SECONDARY, PAPER_2)?;
        }
        Ok(())
    }

    fn activate(&mut self, id: RegionId, _env: &mut Env) -> Outcome {
        // A sheet, while open, answers for the whole screen.
        if let Some(d) = &mut self.danger {
            let reading = d.grade() == DangerGrade::Confirm;
            return match d.activate(id) {
                DangerOutcome::Open | DangerOutcome::Alternative => Outcome::stay(),
                DangerOutcome::Cancelled => {
                    self.danger = None;
                    Outcome::stay()
                }
                // The consequence has been read; the name is typed on the next sheet.
                DangerOutcome::Confirmed if reading => {
                    self.danger = Some(self.type_sheet());
                    Outcome::stay()
                }
                // Consent complete. The UI cannot erase anything - it owns no flash - so
                // it NAMES where the user lands and REQUESTS the erase; the embedder
                // answers by installing the list as it now reads, which is the evidence
                // either way.
                DangerOutcome::Confirmed => Outcome {
                    nav: Nav::Enter(State::Wallets(WalletsState::new())),
                    request: Some(UiRequest::DeleteWallet(self.info.slot)),
                },
            };
        }
        match id {
            // One call returns the whole Outcome - the push AND the card read that ends
            // the Busy frame it lands on - so the two cannot be got wrong separately.
            RegionId::ActSign => crate::screens::sdcard::SignSourceState::open(),
            // Export moves the derivation on: the schemes screen becomes the owner of the
            // keys, and this screen must not keep a second copy of them.
            RegionId::ActExport => match self.report.take() {
                Some(report) => Outcome::enter(State::Schemes(SchemesState::new(report))),
                None => Outcome::stay(),
            },
            // Pushed, so Back from the registry returns to the wallet it belongs to
            // rather than to whatever the stack happened to hold.
            RegionId::ActMultisig => {
                Outcome::push(State::MultisigList(MultisigListState::new(&self.info)))
            }
            RegionId::WalletDelete => {
                self.danger = Some(self.read_sheet());
                Outcome::stay()
            }
            RegionId::Lock => Outcome::ask(UiRequest::LockSession),
            _ => Outcome::stay(),
        }
    }

    /// A session wallet's keys are on this screen, so Back asks first; a stored wallet's
    /// are not, and Back is the list it was opened from.
    fn back(&self) -> Nav {
        if self.report.is_some() {
            Nav::ConfirmExit
        } else {
            Nav::Back
        }
    }
}

/// Lay the action cards out in `room`, in one column while that fits and in two when it
/// does not.
///
/// A card is a TARGET with two lines of copy in it, so the thing that may not give way is
/// its height: [`LIST_ROW_MIN`] is the floor, and a card squeezed under it is a control
/// whose second line - the one saying what the tap costs - is cut off. What gives way is
/// the number of COLUMNS. The 800x480 panel has 190 px under the identity card, which holds
/// two cards and not three, and a wallet that is both stored and unsealed has three.
///
/// A row holding one card takes the full width. That is not only tidiness: the odd card out
/// is the last one, the last one is Delete, and a full-width danger card alone on the
/// bottom row is the shape the rest of the product gives a destructive action.
fn action_grid(ids: Vec<RegionId>, room: Rect, g: i32) -> Vec<(RegionId, Rect)> {
    let n = ids.len().max(1) as i32;
    let single = n * LIST_ROW_MIN + (n - 1) * g <= room.h;
    let cols = if single { 1 } else { 2 };
    let rows = (n + cols - 1) / cols;
    let row_h = ((room.h - (rows - 1) * g) / rows).clamp(LIST_ROW_MIN, 140);
    let col_w = (room.w - (cols - 1) * g) / cols;
    let last_row_len = n - (rows - 1) * cols;
    ids.into_iter()
        .enumerate()
        .map(|(i, id)| {
            let (row, col) = (i as i32 / cols, i as i32 % cols);
            let alone = row == rows - 1 && last_row_len == 1;
            let w = if alone { room.w } else { col_w };
            (id, Rect::new(room.x + col * (col_w + g), room.y + row * (row_h + g), w, row_h))
        })
        .collect()
}

/// One row of the identity card: a value on the left, a value on the right, each clipped
/// to the half the other one leaves it.
///
/// The right value is measured first and the left gets what remains, so the pair can never
/// overlap however long a user names a wallet or however wide a path runs. Cropping the
/// left is the right way round: what a reader compares against another device - the
/// fingerprint, the badge, the network - is on the side that keeps its full width.
fn pair<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    row: Rect,
    left: (&str, &'static Atlas, Rgb565),
    right: (&str, &'static Atlas, Rgb565),
    gap: i32,
) -> Result<(), D::Error> {
    let rw = right.1.text_width(right.0) as i32;
    text(t, right.0, row.right() - rw, row.y, right.1, right.2, PAPER_2)?;
    let room = Rect::new(row.x, row.y, (row.w - rw - gap).max(0), row.h);
    let mut clip = t.clipped(&room.to_eg());
    text(&mut clip, left.0, room.x, room.y, left.1, left.2, PAPER_2)?;
    Ok(())
}

/// Title, secondary line and ink for an action card. One table, so a card cannot be drawn
/// with copy that disagrees with what its region does - and the secondary line says what
/// the tap COSTS, which is the part a user cannot see from the title.
fn action_copy(id: RegionId) -> (&'static str, &'static str, Rgb565) {
    match id {
        RegionId::ActSign => ("Sign a transaction", "load a PSBT from the card", INK_PRIMARY),
        RegionId::ActExport => ("Export public keys", "xpub, descriptor, QR", INK_PRIMARY),
        RegionId::ActMultisig => {
            ("Multisig", "registered wallets, import a descriptor", INK_PRIMARY)
        }
        RegionId::WalletDelete => ("Delete this wallet", "type the name to confirm", DANGER),
        _ => ("", "", INK_PRIMARY),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::TOUCH_MIN;
    use crate::screens::testing::{Fixture, GEOMETRIES};
    use crate::WalletKind;

    fn info(stored: bool) -> WalletInfo {
        WalletInfo {
            slot: 3,
            name: String::from("savings"),
            fingerprint: String::from("a1b2c3d4"),
            path: String::from("m/84'/0'/0'"),
            script_type: String::from("native segwit"),
            kind: WalletKind::SingleSig,
            backup: BackupState::Verified(String::new()),
            network: Network::Bitcoin,
            registrations: 0,
            stored,
            passphrase: false,
        }
    }

    /// The 12-word all-`abandon` vector, so a test can hold a real derivation without
    /// inventing one. Public knowledge and worthless by construction.
    const TEST_PHRASE: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon about";

    /// A derivation, for the cases that turn on this screen holding one.
    fn report() -> Report {
        use notyas_core::derive::{ChildIndex, Scheme};
        use notyas_core::bip39::MnemonicMode;
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

    /// Every action card is a full-width target on its floor, inside the body, clear of
    /// the identity card and of the session band that changes what it means.
    ///
    /// All four combinations of the two INDEPENDENT facts this screen lays out from:
    /// whether the store holds the wallet, and whether the embedder handed over its keys.
    /// The one that used to be unreachable - a stored wallet with keys, which is what the
    /// PIN protects - is also the one carrying both cards, and therefore the tightest fit.
    #[test]
    fn the_action_cards_are_tappable_and_clear_of_the_identity_card() {
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            let ctx = f.ctx();
            for stored in [false, true] {
                for keys in [false, true] {
                    let s = WalletState::new(info(stored), keys.then(report));
                    let l = s.layout(&ctx);
                    let body = f.m.body();
                    for (id, r) in &l.actions {
                        assert!(
                            r.h >= LIST_ROW_MIN && r.w >= TOUCH_MIN,
                            "{w}x{h} stored={stored} keys={keys}: {id:?} is {}x{}",
                            r.w,
                            r.h
                        );
                        assert!(
                            r.y >= l.card.bottom() && r.bottom() <= body.bottom(),
                            "{w}x{h} stored={stored} keys={keys}: {id:?} at {r:?} escapes the \
                             body"
                        );
                        if let Some(band) = l.session {
                            assert!(
                                !r.overlaps(&band),
                                "{w}x{h}: {id:?} overlaps the session band"
                            );
                        }
                    }
                    for (i, (_, a)) in l.actions.iter().enumerate() {
                        for (_, b) in &l.actions[i + 1..] {
                            assert!(
                                !a.overlaps(b),
                                "{w}x{h} stored={stored} keys={keys}: {a:?} overlaps {b:?}"
                            );
                        }
                    }
                }
            }
        }
    }

    /// A wallet the PIN protects can do more than be deleted - as long as the embedder
    /// hands its keys over.
    ///
    /// This is the whole of the stored-wallet gap in one assertion. The UI owns no key
    /// ladder, so what a stored wallet can DO is decided entirely by whether the answer to
    /// [`crate::UiRequest::OpenWallet`] carried a derivation: without one the identical
    /// wallet offers Delete and nothing else, and everything S-26 reaches - the account
    /// xpub, the descriptor, the receive addresses, their QR codes - is behind the card
    /// this proves appears.
    #[test]
    fn a_stored_wallet_exports_exactly_when_its_keys_were_handed_over() {
        let f = Fixture::new(720, 720);
        let ctx = f.ctx();
        let offered = |s: &WalletState| {
            let mut out = Vec::new();
            s.regions(&ctx, &mut out);
            out.iter().map(|r| r.id).collect::<Vec<_>>()
        };
        let bare = offered(&WalletState::new(info(true), None));
        assert!(!bare.contains(&RegionId::ActExport), "no keys, no export");
        assert!(bare.contains(&RegionId::WalletDelete));

        let opened = offered(&WalletState::new(info(true), Some(report())));
        assert!(opened.contains(&RegionId::ActExport), "an unsealed wallet can export");
        assert!(opened.contains(&RegionId::WalletDelete), "and is still deletable");
    }

    /// Sign is the ingress path, and it is offered on exactly the same evidence Export is:
    /// the embedder handed this screen a derivation, which is the only proof the UI has
    /// that the std side is still holding the seed the review engine needs.
    ///
    /// The tap must produce BOTH halves of the outcome. A push with no request behind it
    /// lands the user on a Busy frame nothing will ever answer, which is the exact defect
    /// the 0.2.0 request/answer vocabulary exists to make impossible.
    #[test]
    fn signing_is_offered_with_the_keys_and_asks_for_the_card() {
        let f = Fixture::new(720, 720);
        let ctx = f.ctx();
        let offered = |s: &WalletState| {
            let mut out = Vec::new();
            s.regions(&ctx, &mut out);
            out.iter().any(|r| r.id == RegionId::ActSign)
        };
        assert!(!offered(&WalletState::new(info(true), None)), "no keys, no signing");
        assert!(offered(&WalletState::new(info(true), Some(report()))));
        assert!(
            !offered(&WalletState::new(info(false), Some(report()))),
            "a session wallet's seed never reached the embedder, so it cannot sign"
        );

        let mut network = Network::Bitcoin;
        let mut env = Env { network: &mut network, lock: &f.lock, wallets: &f.wallets };
        let mut s = WalletState::new(info(true), Some(report()));
        let outcome = s.activate(RegionId::ActSign, &mut env);
        assert!(matches!(outcome.nav, Nav::Push(State::SignSource(_))), "Sign opens S-27");
        assert!(
            matches!(outcome.request, Some(UiRequest::ListCard { .. })),
            "S-27 must arrive with the card read that ends its Busy frame"
        );
        assert!(s.report.is_some(), "signing needs the seed on the std side, not the report");
    }

    /// Export hands the derivation ON rather than copying it: the wallet home must not
    /// keep a second copy of the keys once the schemes screen owns them.
    #[test]
    fn exporting_moves_the_keys_out_of_this_screen() {
        let f = Fixture::new(720, 720);
        let mut network = Network::Bitcoin;
        let mut env = Env { network: &mut network, lock: &f.lock, wallets: &f.wallets };
        let mut s = WalletState::new(info(true), Some(report()));
        let outcome = s.activate(RegionId::ActExport, &mut env);
        assert!(matches!(outcome.nav, Nav::Enter(State::Schemes(_))), "export opens S-26");
        assert!(s.report.is_none(), "the wallet home kept a second copy of the keys");
    }

    /// Delete is offered for a stored wallet and for nothing else: there is no slot to
    /// erase behind a session wallet, and a button that erased nothing would be a lie
    /// about what the device just did.
    #[test]
    fn only_a_stored_wallet_can_be_deleted() {
        let f = Fixture::new(720, 720);
        let ctx = f.ctx();
        let has = |s: &WalletState| {
            let mut out = Vec::new();
            s.regions(&ctx, &mut out);
            out.iter().any(|r| r.id == RegionId::WalletDelete)
        };
        assert!(has(&WalletState::new(info(true), None)));
        assert!(!has(&WalletState::new(info(false), None)));
    }
}
