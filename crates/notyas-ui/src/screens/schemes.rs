// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Schemes: the finished wallet, one tab per derivation scheme, and the QR modal.
//!
//! Only PUBLIC values are drawn and only public values can be offered as a QR: the
//! account xpub, the origin-carrying BIP-380 descriptor built from that same xpub
//! ([`export::descriptor`]), its SLIP-132 rendering, and the receive addresses. There is
//! deliberately no private-key path on this screen at all - no mnemonic, xprv, seed or WIF
//! renders here or leaves the device any other way - which is stronger than masking them.
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
use core::str::FromStr;

use embedded_graphics::draw_target::{DrawTarget, DrawTargetExt};
use embedded_graphics::pixelcolor::Rgb565;

use crate::canvas::{
    button, fill, frame, mono_wrapped, tabs, text, text_centered, wrap_words, ButtonKind, BODY,
    HEADING, MONO_SMALL,
};
use crate::components::{back_rect, draw_bar, LINE, SMALL_LINE};
use crate::layout::{Metrics, Rect};
use crate::screens::wallet::WalletState;
use crate::screens::{Ctx, Env, Nav, Outcome, Screen, State};
use crate::theme::*;
use crate::{NullTarget, QrData, QrTarget, Region, RegionId, UiRequest, WalletInfo};
use notyas_core::bitcoin::bip32::Fingerprint;
use notyas_core::bitcoin::Network;
use notyas_core::derive::Scheme;
use notyas_core::export;
use notyas_core::report::{Report, SchemeReport};

/// [`Report::root_fingerprint`] parsed back into the typed form [`export::descriptor`]
/// wants. `Report` only carries the hex string this screen already prints on the info
/// line (`derive::root_fingerprint`'s own rendering) - not attacker input, and never a
/// value this crate did not compute itself - so a failed parse would mean a bug in this
/// crate's own formatting, not a malformed input this screen has to refuse.
fn root_fingerprint(report: &Report) -> Fingerprint {
    Fingerprint::from_str(&report.root_fingerprint)
        .expect("Report::root_fingerprint is always this crate's own 8 lowercase hex chars")
}

/// The scheme a wallet's keys are shown under when nobody has chosen one.
///
/// Both entrances to a wallet's public keys - this screen and Receive - open here, and
/// BIP-84 is the choice because it is the one every modern coordinator assumes: handed a
/// native-segwit descriptor or a zpub, BlueWallet, Sparrow, Electrum and Bitcoin Core all
/// build the wallet the device meant. The scheme this replaced as the default was BIP-44,
/// which is `Scheme::ALL`'s first entry for report-ordering reasons that have nothing to
/// do with what a reader should be shown first, and which a bare xpub export turns into a
/// legacy wallet in BlueWallet (see [`BARE_KEY_HELP`]). BIP-44 is still derived, still
/// signed and still one tap away - the default is about what the device picks SILENTLY,
/// not about which schemes exist.
pub(crate) const DEFAULT_SCHEME: Scheme = Scheme::Bip84;

/// Where [`DEFAULT_SCHEME`] sits in `report.schemes`, or 0 for a report that does not
/// carry it.
///
/// Resolved by scheme IDENTITY and not by a literal index, so reordering [`Scheme::ALL`]
/// cannot silently move the default back onto the legacy scheme - the failure the index
/// this replaced would have had no way to signal. Total rather than fallible because both
/// callers have to render something: a wallet derived for BIP-44 alone opens on the only
/// scheme it has, which is the one its coins are on.
pub(crate) fn default_scheme_index(report: &Report) -> usize {
    report.schemes.iter().position(|sr| sr.scheme == DEFAULT_SCHEME).unwrap_or(0)
}

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
    ///
    /// Opens on [`DEFAULT_SCHEME`]'s tab, resolved through [`default_scheme_index`]. The
    /// literal `0` this replaced put every wallet's Export card on the legacy tab, whose
    /// first artifact is a bare xpub, which is the exact string BlueWallet reads as a
    /// legacy wallet - a default nobody chose, on the scheme with the worst
    /// interoperability of the four.
    pub fn new(report: Report, origin: Origin) -> SchemesState {
        let tab = default_scheme_index(&report);
        SchemesState { report: Some(report), origin, tab, scroll: 0, qr: None }
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

/// Why the descriptor block exists, printed under it. A coordinator that only ever sees
/// the bare xpub below has no fingerprint to put in the PSBTs it builds, so it writes
/// `00000000` - indistinguishable from every OTHER signer that got the same bare key -
/// and every downstream signer is left guessing whose key that was. BlueWallet in
/// particular parses this exact bracketed form (its `AbstractHDElectrumWallet.setSecret`
/// accepts a `wpkh([fp/path]xpub...)` descriptor, and reads the fingerprint straight out
/// of the brackets), so naming it by that coordinator is concrete rather than generic
/// advice.
const DESCRIPTOR_HELP: &str = "Give BlueWallet this descriptor, not the bare xpub below. \
    BlueWallet reads the fingerprint in the brackets and writes it into every PSBT it \
    builds; handed the bare xpub, it has none to write, and every signer downstream has \
    to guess whose key made each signature.";

/// What a bare extended key costs the reader, printed under the block that offers one.
///
/// The reported defect in one sentence and its consequence in the next, because the
/// consequence is the half an owner cannot see coming: an extended key on its own is
/// nothing but a chain code and a public point, so the coordinator that receives it has
/// to invent the two facts it needs - whose key this is, and which derivation it came
/// from. BlueWallet's documented answer to that second question for a bare `xpub` is
/// m/44, which is how a wallet exported from this device arrived in a coordinator as a
/// LEGACY wallet whose coins the owner then could not spend.
///
/// Named for the artifact and not for the coordinator: the guessing is a property of
/// bare extended keys, and BlueWallet is quoted because a named guess is checkable and
/// "some wallets may interpret this differently" is not.
const BARE_KEY_HELP: &str = "A bare extended key carries no master fingerprint and no \
    derivation path, so the coordinator that reads it has to guess the derivation. \
    BlueWallet guesses legacy (m/44) from a bare xpub.";

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
            // The origin-carrying twin of `QrXpub`: same public account key, wrapped with
            // the key-origin path and this wallet's root fingerprint so a coordinator that
            // reads it (BlueWallet's descriptor parser among them) has a real fingerprint to
            // write into the PSBTs it builds, instead of `00000000`.
            RegionId::QrDescriptor => {
                let (Some(report), Some(sr)) = (self.report.as_ref(), self.active()) else {
                    return Outcome::stay();
                };
                match export::descriptor(sr.scheme, root_fingerprint(report), &sr.derived.account) {
                    Some(desc) => Outcome::ask(UiRequest::Qr(QrTarget {
                        label: format!("Descriptor {}", sr.derived.account.path),
                        payload: desc,
                    })),
                    None => Outcome::stay(),
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

    /// The last address row stays reachable whatever else is on the tab.
    ///
    /// Clamp to whichever is smaller: the true content end, or the point at which the
    /// last address row's top is flush with the viewport's. A tab with no address rows
    /// (or no report yet) has no row to protect and falls back to the true end unchanged.
    ///
    /// The clamp is stated as an invariant rather than as a fix for one layout, and it
    /// outlives the layout that needed it: with the descriptor block and its explainer
    /// last, a drag could push the last address row - and the QR button that is the only
    /// way to spend into it - clean off the TOP of the viewport on a short panel. Those
    /// two now sit above the rows, so the true content end is the binding limit today and
    /// this clamp binds on nothing. It stays because the property it names is the one that
    /// matters ("the last row can always be reached"), and the next block somebody appends
    /// below the rows must not be able to strand that row silently - see
    /// [`ContentEnd::last_address_row`].
    fn scroll_limit(&self, ctx: &Ctx) -> i32 {
        let l = self.layout(ctx);
        let content =
            self.content(&mut NullTarget, &ctx.m, l.viewport.y, None).unwrap_or_default();
        let true_limit = (content.y - l.viewport.y - l.viewport.h).max(0);
        match content.last_address_row {
            Some(top) => true_limit.min((top - l.viewport.y).max(0)),
            None => true_limit,
        }
    }
}

/// Where a [`SchemesState::content`] walk ended, and - when the active tab drew any
/// receive-address rows - the y of the TOP of the last one.
///
/// [`SchemesState::scroll_limit`] reads `last_address_row` alone; `y` is the true
/// bottom, kept for the ordinary "how far can this scroll" measurement. Splitting the
/// two out of a bare `i32` is what makes the clamp below possible at all: the total
/// height of the content is not the fact the clamp needs.
#[derive(Default)]
struct ContentEnd {
    y: i32,
    last_address_row: Option<i32>,
}

impl SchemesState {
    /// Draws (or measures, against [`NullTarget`]) the active tab's content starting at
    /// `y0`; returns the y after the last line, and the top of the last address row (see
    /// [`ContentEnd`]). When `buttons` is given the QR buttons' regions are collected in
    /// content coordinates - the caller filters by viewport.
    fn content<D: DrawTarget<Color = Rgb565>>(
        &self,
        t: &mut D,
        m: &Metrics,
        y0: i32,
        mut buttons: Option<&mut Vec<Region>>,
    ) -> Result<ContentEnd, D::Error> {
        let body = m.body();
        let g = m.gap;
        // Nothing to measure or draw while the report is on its way back to the wallet (see
        // the field); the caller reads this as "the content ended where it began".
        let Some(report) = self.report.as_ref() else {
            return Ok(ContentEnd { y: y0, last_address_row: None });
        };
        let Some(sr) = self.active() else {
            return Ok(ContentEnd { y: y0, last_address_row: None });
        };
        let acct = &sr.derived.account;
        let mut y = y0;

        text(t, &format!("Account {}", acct.path), body.x, y, HEADING, INK_PRIMARY, PAPER_1)?;
        y += LINE + g;

        // FIRST, above the bare key and above the address rows, because DESCRIPTOR_HELP
        // directly below it tells the reader this is the artifact to hand a coordinator -
        // and a screen whose layout disagrees with its own instructions teaches the
        // opposite of what it says. What this ordering replaced put the descriptor last,
        // below five address rows, where the reader had to scroll past the bare xpub to
        // reach the thing the text told them to use; the bare xpub is what they used.
        //
        // The block is long - it carries this wallet's key-origin path and fingerprint on
        // top of the xpub every other block prints - and its explainer is longer, so this
        // ordering costs the reader a scroll to reach the address rows. That is the right
        // trade: an address row is read here and used here, while the descriptor is
        // COPIED OUT, and a copy made from the wrong block is not recoverable on this
        // screen. `scroll_limit`'s clamp keeps the last address row reachable regardless
        // of what sits above it.
        //
        // `None` only for Bip48 (module docs on `export::descriptor` - multisig needs
        // cosigner keys this crate does not accept), which is exactly the scheme with no
        // key-origin story to tell here.
        if let Some(desc) = export::descriptor(sr.scheme, root_fingerprint(report), acct) {
            y = qr_block(t, m, y, "Descriptor", &desc, RegionId::QrDescriptor, &mut buttons)?;
            y += g;
            for line in wrap_words(DESCRIPTOR_HELP, body.w, BODY) {
                text(t, &line, body.x, y, BODY, INK_SECONDARY, PAPER_1)?;
                y += LINE;
            }
            y += g;
        }

        // Kept, and demoted: some coordinators still want the bare key, and withdrawing
        // what this button has always emitted would break an established workflow. What
        // it may not do any more is stand first with nothing said about it - the caption
        // names what makes this key different from the descriptor above, and BARE_KEY_HELP
        // under it is the consequence the reader was missing when this block led the
        // screen. The QR request's own label is unchanged ("Account xpub <path>"): the
        // caption describes the block on THIS screen, and the label titles a symbol
        // somebody is about to photograph.
        y = qr_block(t, m, y, "Account xpub (bare)", &acct.xpub, RegionId::QrXpub, &mut buttons)?;
        y += g;
        for line in wrap_words(BARE_KEY_HELP, body.w, BODY) {
            text(t, &line, body.x, y, BODY, INK_SECONDARY, PAPER_1)?;
            y += LINE;
        }

        if let (Some(slip), Some((_, label))) = (&acct.slip132_pub, sr.scheme.slip132_labels()) {
            y += g;
            // Below the bare xpub because it IS one, with one difference worth its place
            // on the screen: SLIP-132's version bytes name the script type, so a zpub at
            // least tells its reader m/84 where a bare xpub tells it nothing. That is why
            // BARE_KEY_HELP sits above this block and not below it.
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
        // The top of each row, captured before `qr_block` advances `y`: after the loop
        // this holds the LAST row's top, which is exactly what `scroll_limit` needs to
        // keep in reach (see `ContentEnd`). `None` stays correct for a scheme with no
        // rows to show, though every shipped scheme derives `ADDRESS_ROWS` of them.
        let mut last_address_row = None;
        for (i, row) in sr.derived.rows.iter().enumerate() {
            last_address_row = Some(y);
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

        Ok(ContentEnd { y, last_address_row })
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
    use crate::screens::testing::{Fixture, GEOMETRIES};
    use crate::{BackupState, PassphraseState, UnlockGate, WalletKind};

    /// The 12-word all-`abandon` vector: a real derivation with nothing in it, so a test
    /// can hold keys without inventing a wallet worth stealing.
    const TEST_PHRASE: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon about";

    /// A report over exactly `schemes`, in the order given - which is how a test states
    /// "this wallet has no BIP-84", or hands the screen a scheme order the shipped
    /// `Scheme::ALL` does not have, without waiting for a device that derives one that way.
    fn report_over(schemes: &[Scheme]) -> Report {
        use notyas_core::bip39::MnemonicMode;
        use notyas_core::derive::ChildIndex;
        use notyas_core::report::Parameters;
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

    /// The QR buttons the active tab lays out, in the order the content walk draws them.
    /// Measured against [`NullTarget`] through the same walk that paints, so an ordering
    /// this asserts is the ordering a reader sees.
    fn button_order(s: &SchemesState, m: &Metrics) -> Vec<RegionId> {
        let mut buttons = Vec::new();
        let _ = s.content(&mut NullTarget, m, 0, Some(&mut buttons));
        let mut sorted = buttons;
        sorted.sort_by_key(|b| b.rect.y);
        sorted.into_iter().map(|b| b.id).collect()
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

    /// This is the test that would have caught the upstream bug: a coordinator that only
    /// ever sees `QrXpub` never learns this wallet's root fingerprint, so it writes
    /// `00000000` into every PSBT it builds and every signer downstream has to guess whose
    /// key that was. It drives the screen the way a finger would -
    /// `activate(RegionId::QrDescriptor)` on the BIP84 tab, not a direct call into
    /// `notyas_core::export` - and checks the resulting payload against BIP-380's own
    /// grammar (https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki) and the
    /// exact shape BlueWallet's `AbstractHDElectrumWallet.setSecret` accepts for a
    /// descriptor - `wpkh([fingerprint/path]xpub.../<0;1>/*)`, reading `fingerprint` as
    /// `MasterFingerprint` - rather than against memory: the `wpkh(...)` wrapper, hardened
    /// steps spelled with `h` and not `'`, the bracketed origin starting with the real
    /// master fingerprint in lowercase hex (not the wallet-info fixture's, and not
    /// zeroes), the plain account xpub, and the `<0;1>/*` multipath suffix. The checksum's
    /// own validity is `export::checksum::create`'s independently-tested property, not
    /// re-proven here.
    #[test]
    fn qr_descriptor_carries_the_real_fingerprint_bluewallet_can_parse() {
        assert_eq!(Scheme::ALL[2], Scheme::Bip84, "test assumes tab index 2 is BIP84");
        let r = report();
        let expected_fp = r.root_fingerprint.clone();
        let expected_xpub = r.schemes[2].derived.account.xpub.clone();

        let f = Fixture::new(720, 720);
        let mut network = Network::Bitcoin;
        let mut env = Env {
            network: &mut network,
            lock: &f.lock,
            wallets: &f.wallets,
            gate: &mut UnlockGate::default(),
        };
        let mut s = SchemesState::new(r, Origin::Fresh);
        s.tab = 2;

        let outcome = s.activate(RegionId::QrDescriptor, &mut env);
        let Some(UiRequest::Qr(target)) = outcome.request else {
            panic!("QrDescriptor on a BIP84 tab must raise a Qr request");
        };
        let desc = target.payload;

        let (body, checksum) =
            desc.rsplit_once('#').expect("a BIP-380 descriptor carries a checksum");
        assert_eq!(checksum.len(), 8, "checksum length: {checksum}");
        assert!(body.starts_with("wpkh(["), "not a wpkh() descriptor: {body}");
        assert!(body.ends_with(')'), "wpkh(...) wrapper unclosed: {body}");

        let origin_start = body.find('[').expect("key origin present");
        let origin_end = body.find(']').expect("key origin closed");
        let origin = &body[origin_start + 1..origin_end];
        let (fp, path) = origin.split_once('/').expect("fingerprint/path in the key origin");
        assert_eq!(fp, expected_fp, "must be the WALLET's own root fingerprint, not a stand-in");
        assert_ne!(fp, "00000000", "the bug this screen exists to fix");
        assert_eq!(fp.len(), 8, "fingerprint length: {fp}");
        assert!(
            fp.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "fingerprint must be lowercase hex: {fp}"
        );
        assert_eq!(path, "84h/0h/0h", "hardened steps must use h, not the report's own '");

        let key_and_suffix = &body[origin_end + 1..];
        assert!(
            key_and_suffix.starts_with(&expected_xpub),
            "must carry the plain xpub, not a SLIP-132 alias: {key_and_suffix}"
        );
        assert!(
            key_and_suffix.ends_with("/<0;1>/*)"),
            "must carry the multipath receive/change suffix: {key_and_suffix}"
        );
    }

    /// The open half of K29, at the entrance it came in through: the Export card opened on
    /// tab 0, which is BIP-44, whose first artifact is a bare xpub - the exact string
    /// BlueWallet turns into a legacy wallet.
    ///
    /// Asserted through `active()` rather than against the literal 2, because the number is
    /// the thing that must stop mattering: what the screen owes the reader is the BIP-84
    /// scheme, wherever the report happens to keep it.
    #[test]
    fn export_opens_on_bip84_and_not_on_the_legacy_tab() {
        let s = SchemesState::new(report(), Origin::Fresh);
        let opened = s.active().expect("a derived wallet has schemes to show");
        assert_eq!(opened.scheme, Scheme::Bip84, "Export must open on BIP-84");
        assert_ne!(opened.scheme, Scheme::Bip44, "the funnel this closes");
        let path = &opened.derived.account.path;
        assert!(path.starts_with("m/84'"), "{path}");
    }

    /// ...and it finds that scheme by IDENTITY, not at a remembered index.
    ///
    /// Two orders, and a hard-coded index passes at most one of them: the first puts BIP-84
    /// last, the second puts it first. This is the test that a later reordering of
    /// `Scheme::ALL` has to survive - the failure mode of the literal `0` this replaced was
    /// precisely that nothing anywhere said which scheme index 0 was.
    #[test]
    fn the_opening_tab_is_resolved_by_scheme_not_by_index() {
        let shuffled = report_over(&[Scheme::Bip86, Scheme::Bip49, Scheme::Bip84]);
        let last = SchemesState::new(shuffled, Origin::Fresh);
        assert_eq!(last.tab, 2);
        assert_eq!(last.active().unwrap().scheme, Scheme::Bip84);
        let first = SchemesState::new(report_over(&[Scheme::Bip84, Scheme::Bip44]), Origin::Fresh);
        assert_eq!(first.tab, 0);
        assert_eq!(first.active().unwrap().scheme, Scheme::Bip84);
    }

    /// A wallet with no BIP-84 in it still exports, on the scheme its coins are on.
    ///
    /// The fix is about what the device chooses silently, never about withdrawing a scheme:
    /// an owner holding BIP-44 coins has to be able to reach that key, and a screen that
    /// renders nothing because its preferred scheme is absent would take an owner's own
    /// wallet away from them. Drawn on both panels, because "does not panic" is the floor
    /// and the draw path is where an empty-report assumption would fire.
    #[test]
    fn a_bip44_only_wallet_opens_on_its_only_scheme_and_draws() {
        let s = SchemesState::new(report_over(&[Scheme::Bip44]), Origin::Fresh);
        assert_eq!(s.tab, 0, "the only scheme it has");
        assert_eq!(s.active().unwrap().scheme, Scheme::Bip44);
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            s.draw(&mut NullTarget, &f.ctx()).expect("a legacy-only wallet's export card draws");
            let ids = button_order(&s, &f.m);
            assert_eq!(
                ids.first(),
                Some(&RegionId::QrDescriptor),
                "{w}x{h}: BIP-44 has an origin-carrying descriptor too, and it still leads"
            );
        }
    }

    /// The layout now agrees with its own instructions: DESCRIPTOR_HELP tells the reader to
    /// hand a coordinator the descriptor rather than the bare xpub BELOW it, and the
    /// descriptor is the first thing on the tab.
    ///
    /// What this replaced put the descriptor LAST, under five address rows, while the same
    /// help text called the xpub "above" - so a reader who followed the screen top to bottom
    /// met the bare key first and never had a reason to keep scrolling. The wording is
    /// asserted next to the order deliberately: the two are one statement, and moving either
    /// without the other puts the screen back in the state that misled an owner.
    #[test]
    fn the_descriptor_leads_and_the_bare_key_follows_it() {
        assert!(
            DESCRIPTOR_HELP.contains("xpub below"),
            "the descriptor's help text says where the bare xpub is; move both or neither"
        );
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            let s = SchemesState::new(report(), Origin::Fresh);
            let ids = button_order(&s, &f.m);
            let mut expected = vec![RegionId::QrDescriptor, RegionId::QrXpub, RegionId::QrSlip132];
            expected.extend((0..crate::ADDRESS_ROWS as u8).map(RegionId::QrAddress));
            assert_eq!(ids, expected, "{w}x{h}: the tab's blocks are in the wrong order");
        }
    }

    /// The scroll clamp, measured: the last address row's QR button is fully inside the
    /// viewport once the screen is dragged as far as it goes, on every tab and both panels.
    ///
    /// That button is the only way to show somebody the fifth receive address, so "it exists
    /// in the content" is not the property - "a finger can reach it at the end of the drag"
    /// is. The check is made at `scroll_limit` itself rather than after a fixed number of
    /// drags, so no amount of dragging can pass a screen this fails: `scroll_limit` IS the
    /// end of the drag.
    #[test]
    fn the_last_address_row_is_reachable_at_the_scroll_clamp() {
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            let ctx = f.ctx();
            for tab in 0..Scheme::ALL.len() {
                let mut s = SchemesState::new(report(), Origin::Fresh);
                s.tab = tab;
                let vp = s.layout(&ctx).viewport;
                s.scroll = s.scroll_limit(&ctx);
                let mut regions = Vec::new();
                s.regions(&ctx, &mut regions);
                let last = RegionId::QrAddress(crate::ADDRESS_ROWS as u8 - 1);
                let hit = regions.iter().find(|r| r.id == last).unwrap_or_else(|| {
                    panic!("{w}x{h} tab {tab}: {last:?} unreachable at the clamp")
                });
                assert!(
                    hit.rect.y >= vp.y && hit.rect.bottom() <= vp.bottom(),
                    "{w}x{h} tab {tab}: {:?} is not wholly inside {vp:?}",
                    hit.rect
                );
            }
        }
    }

    /// The QR modal at every real symbol size the 0.1.0 targets produce (v3 addresses
    /// through v7 zpubs), the v9 the BIP-380 descriptor (0.2.1) lands at - byte mode, no
    /// lowercase-to-alphanumeric trick (module docs), so its ~150 bytes cost more than
    /// twice a bare xpub's - plus the format extremes: integer scale, largest fit, symbol
    /// centered between label and Close, everything inside the panel.
    #[test]
    fn qr_modal_scales_integer_and_fits() {
        for (w, h) in GEOMETRIES {
            let m = Metrics::new(w, h);
            for size in [21, 29, 33, 45, 53, 57, 177] {
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
