// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The [`Ui`]: the embedder's whole interface, and the one owner of the live screen.
//!
//! Deliberately a sibling of [`crate::screens`] rather than its parent. A screen cannot
//! name a field of this struct - Rust's privacy is by module, and this module is not an
//! ancestor of theirs - so "exactly one screen state is alive" is not a convention the
//! screens agree to keep. Every screen change in the crate happens in [`Ui::apply`],
//! [`Ui::enter`] or [`Ui::reset`], each a single move out of one field; the value moved
//! out is dropped, and dropping a screen state wipes the secrets it owned.
//!
//! The embedder's loop is `touch` for every panel event, `draw` when anything may have
//! changed, and `tick` after the frame is published.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use embedded_graphics::draw_target::DrawTarget;
use embedded_graphics::pixelcolor::Rgb565;

use crate::components::{draw_modal, modal_regions, ModalSpec};
use crate::layout::Metrics;
use crate::screens::home::HomeState;
use crate::screens::lock::LockState;
use crate::screens::passphrase::PassUnlockState;
use crate::screens::wallet::WalletState;
use crate::screens::wallets::WalletsState;
use crate::screens::words::WordsInfoState;
use crate::screens::{self, Answer, Ctx, Env, Nav, Outcome, State};
use crate::{QuizView, Report, WalletInfo, WalletRow};
use crate::{
    CardOutcome, DeleteOutcome, FormatOffer, FormatOutcome, ImportOutcome, LockInfo,
    PassphraseRefusal, Press, PsbtOutcome, QrData, QrTarget, Region, RegionId,
    RegistrationInfo, RegistrationOutcome, ReservedSpace, ScreenId, SignOutcome,
    SignedQrOutcome, StorageOutcome, StoreStatus, Ticked, TouchEvent, UiRequest, UnlockGate,
    UnsealOutcome, VerifyInfo,
    WordsOutcome, WriteOutcome, HOLD_MS,
};
use notyas_core::bitcoin;

/// Movement beyond this many pixels in EITHER axis turns a press into a drag and cancels
/// the tap.
///
/// Both axes, not just the vertical one. A finger that slides sideways across a button
/// and lifts inside it has not tapped it - it has swiped over it, usually on the way
/// somewhere else - and firing the button on that gesture is how a Sign or a Delete gets
/// pressed by an unrelated movement. Only the vertical component scrolls, which is why
/// the old bookkeeping tracked only that; the tap-vs-drag decision is a different
/// question and takes the whole movement.
const DRAG_SLOP: i32 = 16;

/// The exit-confirmation modal shown when Back is pressed on a screen holding a derived
/// secret (see [`crate::screens::Nav::ConfirmExit`]). The user sees their seed or derived
/// keys and could lose work by going back - this gate prevents an accidental tap from
/// discarding it silently.
static EXIT_MODAL: ModalSpec = ModalSpec {
    title: "Go back?",
    body: &[
        "Going back will clear your current work from this screen.",
        "You can re-enter your dice rolls or seed words to start again.",
    ],
    cancel: "Cancel",
    confirm: "Go back",
};

/// In-flight touch bookkeeping between Down and Up.
struct Pressed {
    id: Option<RegionId>,
    last: (i32, i32),
    /// Accumulated absolute movement per axis, for the tap-vs-drag decision. Kept split
    /// because the vertical component also drives scrolling and the horizontal one does
    /// not; summing them would make a diagonal drag cancel at half the intended slop.
    moved_x: i32,
    moved_y: i32,
    /// How long the finger has been down, fed by [`Ui::tick`]. The press age C4c needs.
    held_ms: u32,
    /// The hold already fired; further ticks must not fire it again while the finger
    /// stays down.
    fired: bool,
}

/// The whole user interface: screen state, pipeline inputs, and the renderer.
///
/// The firmware's loop is: `touch()` for every panel event, then `draw()` into the
/// framebuffer when anything may have changed. Both are total - no screen can panic on
/// any event - and `draw` is a pure function of the current state.
pub struct Ui {
    m: Metrics,
    state: State,
    verify: VerifyInfo,
    pressed: Option<Pressed>,
    /// Navigation stack: each forward transition pushes the prior screen here,
    /// so Back restores it exactly (user's rolls, mnemonic, passphrase survive).
    /// One level per forward step; Back pops. Empty stack + Back -> Home.
    ///
    /// Boxed on purpose (clippy's `vec_box` reads only the size, not the contents): a
    /// `State` holds rolls, a mnemonic and a passphrase, and storing them inline would
    /// memcpy those bytes on every push, pop and Vec regrow - each copy leaving an
    /// unwiped duplicate behind at the old address. A pointer move copies no secret.
    #[allow(clippy::vec_box)]
    prior: Vec<Box<State>>,
    /// Exit-confirmation modal is open over the current screen. When true, only
    /// the modal's Cancel/Confirm are tappable; the sheet below is inert.
    exit_modal: bool,
    /// Network every derivation runs on. Toggled on Home (desktop parity: the desktop
    /// pipeline takes the network as an input too); lives on the `Ui` rather than in a
    /// screen state so the choice survives screen changes within a session.
    ///
    /// Across a power cycle it survives only if the EMBEDDER keeps it: this crate reads it
    /// back through [`Ui::set_network`] at boot and knows nothing about where it was kept.
    /// It is a preference, not a claim - every wallet record carries its own network and
    /// every signing surface states the network in force - so nothing downstream is
    /// weakened by the value having come from somewhere unauthenticated.
    network: bitcoin::Network,
    /// What the embedder told us about the sealed store. The lock and PIN screens read
    /// it; every other screen ignores it.
    lock: LockInfo,
    /// The wallets the embedder read out of the store after a successful unlock.
    ///
    /// Empty until then, and emptied again by a lock. That is ratified Q2(a) made
    /// structural rather than editorial: the count in use cannot leak onto a pre-PIN
    /// surface, because before the PIN this crate does not have one.
    wallets: Vec<WalletRow>,
    /// The multisig registrations the embedder read out of the wallet that is open.
    ///
    /// Beside `wallets` and cleared with it, because it has the same lifetime and the same
    /// reason for one: a registration is re-proven from the seed every time a wallet is
    /// opened, so a device with no session holds nothing here it could honestly draw.
    registrations: Vec<RegistrationInfo>,
    /// True once a hold-to-confirm was released before it filled, so the screen can say
    /// "Released - nothing was signed" without a modal and without scolding. Cleared by
    /// the next press.
    hold_released: bool,
    /// How many passphrase attempts each wallet slot has refused, and how long the one
    /// that is waiting has left.
    ///
    /// On the `Ui` rather than on the unlock screen because its lifetime is deliberately
    /// longer than that screen's: a counter the screen owned would be reset by one tap on
    /// Back, and a gate that a tap resets is decoration. It survives a lock for the same
    /// reason - a lock is not evidence about a passphrase - and dies with the power, which
    /// is RAM rather than a policy.
    gate: UnlockGate,
    /// The anti-phishing explainer (S-04a) has been shown on this power-up.
    ///
    /// On the `Ui` because it outlives both screens that raise it - the PIN-create screen
    /// is popped by the very transition that shows the explainer, and PIN entry is a fresh
    /// state on every visit - so neither of them can remember it. Reset by power-off,
    /// which is the right lifetime for a screen whose value is entirely in the first read:
    /// a user who has seen it twice in one session has learned nothing the second time,
    /// and a user coming back to a device days later is exactly who should see it again.
    words_explained: bool,
}

impl core::fmt::Debug for Ui {
    /// Screen id only. The state behind it holds rolls, words and passphrases, none of
    /// which may reach a `Debug` rendering (house rule, same as every notyas-core type).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ui").field("screen", &self.screen()).finish()
    }
}

impl Ui {
    /// A UI for a `width` x `height` Rgb565 display. All layout derives from this size.
    pub fn new(width: u32, height: u32) -> Self {
        Ui {
            m: Metrics::new(width, height),
            state: State::Home(HomeState),
            verify: VerifyInfo::default(),
            pressed: None,
            prior: Vec::new(),
            exit_modal: false,
            network: bitcoin::Network::Bitcoin,
            lock: LockInfo::default(),
            wallets: Vec::new(),
            registrations: Vec::new(),
            hold_released: false,
            gate: UnlockGate::default(),
            words_explained: false,
        }
    }

    /// The network the next derivation will run on (Home-screen toggle).
    pub fn network(&self) -> bitcoin::Network {
        self.network
    }

    /// Install the network the embedder read back from the device.
    ///
    /// Called once at boot, before the first frame, so that a user who chose testnet finds
    /// testnet after a power cycle instead of a device silently back on mainnet. It is a
    /// preference and not a claim: every wallet record carries its own network and every
    /// signing surface states the network in force, so nothing downstream trusts this value
    /// to be anything more than what the toggle last said.
    pub fn set_network(&mut self, network: bitcoin::Network) {
        self.network = network;
    }

    pub fn screen(&self) -> ScreenId {
        self.state.id()
    }

    /// Install the values the Verify screen shows. The firmware calls this once at boot
    /// with what it measured; until then the screen shows "not read" placeholders.
    pub fn set_verify_info(&mut self, info: VerifyInfo) {
        self.verify = info;
    }

    /// What the Verify screen is showing, for an embedder that wants to replace one
    /// measured field without rebuilding the rest of what it already read.
    pub fn verify_info(&self) -> &VerifyInfo {
        &self.verify
    }

    /// Report progress on a [`UiRequest::ScanReservedSpace`] the embedder is part-way
    /// through, so the C3 Busy frame is determinate rather than a still picture.
    ///
    /// Called between spans, with `draw` after it: the scan blocks the loop, so the only
    /// frames it can publish are the ones it publishes itself. Dropped unless a scan is
    /// in flight.
    pub fn set_scan_progress(&mut self, done: u8, spans: u8) {
        if let State::Verify(s) = &mut self.state {
            s.scan_progress(done, spans);
        }
    }

    /// Install the finished reserved-space scan, answering
    /// [`UiRequest::ScanReservedSpace`].
    ///
    /// The RESULT lands on the readout unconditionally - it is a measurement of the
    /// device, not a fact about a screen, and the next reader of the Verify sheet is
    /// entitled to it - while the Busy frame only ends if the screen that raised the
    /// request is still the one showing.
    pub fn set_flash_scan(&mut self, scan: ReservedSpace) {
        self.verify.reserved_space = scan;
        if let State::Verify(s) = &mut self.state {
            s.scan_finished();
        }
    }

    /// Every tappable region of the current screen, in no particular order. When the
    /// modal is open, only the modal's buttons are returned - the sheet below it is
    /// inert, exactly as it is unreachable on screen.
    pub fn regions(&self) -> Vec<Region> {
        if self.exit_modal {
            return modal_regions(&self.m, &EXIT_MODAL);
        }
        screens::regions(&self.state, &self.ctx())
    }

    /// Feed one touch event. Taps fire on Up over the same region the Down hit;
    /// vertical drags scroll the scrollable screens (mnemonic grid, scheme details).
    ///
    /// Returns `Some` when the tap needs work only the embedder can do (currently: QR
    /// encoding, which is std-only - see [`UiRequest`]). Dropping a request loses
    /// nothing but the response; the state machine has already moved on cleanly.
    pub fn touch(&mut self, ev: TouchEvent) -> Option<UiRequest> {
        // The Deriving screen has no tappable regions, so an event arriving in that
        // state is a stray - finishing the pending work first is the only sane response,
        // and it means an embedder that has not yet added `tick` to its loop recovers on
        // the next touch instead of wedging on the interstitial forever.
        let pending = self.tick(0).request;
        match ev {
            TouchEvent::Down { x, y } => {
                let id = self.hit(x, y);
                self.hold_released = false;
                self.pressed = Some(Pressed {
                    id,
                    last: (x, y),
                    moved_x: 0,
                    moved_y: 0,
                    held_ms: 0,
                    fired: false,
                });
                pending
            }
            TouchEvent::Move { x, y } => {
                let Some(p) = self.pressed.as_mut() else { return pending };
                let (dx, dy) = (x - p.last.0, y - p.last.1);
                p.last = (x, y);
                p.moved_x += dx.abs();
                p.moved_y += dy.abs();
                let dragged = p.moved_x > DRAG_SLOP || p.moved_y > DRAG_SLOP;
                let was_holding = p.id == Some(RegionId::HoldConfirm);
                if dragged {
                    p.id = None;
                    p.held_ms = 0;
                }
                // Dragging off a hold reads to the user exactly like letting go of it,
                // so it says the same thing (C4c) rather than nothing.
                if dragged && was_holding {
                    self.hold_released = true;
                }
                self.scroll_by(-dy);
                pending
            }
            TouchEvent::Up { x, y } => {
                let Some(p) = self.pressed.take() else { return pending };
                // A hold that filled has already fired from `tick`; the lift that ends it
                // is not a second activation, and it is not a release either.
                if p.fired {
                    return pending;
                }
                if p.id == Some(RegionId::HoldConfirm) {
                    self.hold_released = true;
                    return pending;
                }
                let (Some(down), Some(up)) = (p.id, self.hit(x, y)) else { return pending };
                if down == up && p.moved_x <= DRAG_SLOP && p.moved_y <= DRAG_SLOP {
                    self.activate(down).or(pending)
                } else {
                    pending
                }
            }
        }
    }

    /// The press in flight, for the screens that render one (the C4c hold bar).
    pub fn press(&self) -> Option<Press> {
        self.pressed.as_ref().map(|p| Press { id: p.id, held_ms: p.held_ms })
    }

    /// True while a hold-to-confirm's "Released - nothing was done" line should show.
    pub fn hold_released(&self) -> bool {
        self.hold_released
    }

    /// Run the pending blocking computation, if the current screen has one.
    ///
    /// The embedder's loop is `touch -> draw -> tick`. Only the Deriving screen has
    /// pending work (the seed stretch and the whole scheme derivation, seconds of PBKDF2
    /// on this silicon), and it exists precisely so that the "Deriving" frame is painted
    /// and published BEFORE that work starts - a synchronous derivation behind the
    /// passphrase screen is indistinguishable from a hung device.
    ///
    /// It also ages the press in flight by `elapsed_ms`, which is what drives the C4c
    /// hold-to-confirm: a hold fires from HERE, while the finger is still down, so the
    /// returned [`Ticked`] carries a request as well as the repaint flag.
    ///
    /// A no-op on every other screen with no press in flight, so the loop can call it
    /// unconditionally; `dirty` means the state advanced and the screen needs a repaint.
    pub fn tick(&mut self, elapsed_ms: u32) -> Ticked {
        let mut out = Ticked::default();
        // Age the press, then decide. Split in two so the hold's activation is not
        // reached through the same borrow that advanced the clock.
        let mut fire = false;
        if let Some(p) = self.pressed.as_mut() {
            if p.id.is_some() && elapsed_ms > 0 {
                let before = p.held_ms;
                p.held_ms = p.held_ms.saturating_add(elapsed_ms);
                // Only a hold bar renders the press age, so only a hold bar makes the
                // panel dirty for it. Every other press is a still frame.
                if p.id == Some(RegionId::HoldConfirm) && !p.fired {
                    out.dirty = true;
                    fire = before < HOLD_MS && p.held_ms >= HOLD_MS;
                    p.fired = fire;
                }
            }
        }
        if fire {
            out.request = self.activate(RegionId::HoldConfirm);
        }
        // The countdown beside a disabled Unlock is the one thing on this device that has
        // to repaint while nobody is touching it. Only when the SECOND changes: a repaint
        // per poll would be forty frames a second of an unchanged number.
        //
        // The gate is told which slot is on the glass rather than being asked whether
        // anything moved, because every slot's wait ages on every tick - a countdown that
        // only ran while its own screen was open would be one a user could pause by
        // backing out - and only the shown one can produce a visible change.
        let showing = match &self.state {
            State::PassUnlock(s) => Some(s.slot()),
            _ => None,
        };
        if self.gate.tick(elapsed_ms, showing) {
            out.dirty = true;
        }
        let derived = match &self.state {
            State::Deriving(d) => d.run(self.network),
            _ => return out,
        };
        match derived {
            Some(next) => self.enter(next),
            // Both entry paths were validated before the passphrase screen, so a failure
            // here is a core bug. Falling back to the screen the user came from beats
            // wedging on an interstitial that will never finish, and beats panicking in
            // the input path.
            None => self.pop(),
        }
        out.dirty = true;
        out
    }

    /// Install the finished QR symbol for a [`UiRequest::Qr`] and open the modal.
    ///
    /// Only acts while the schemes screen is showing - the one screen whose regions can
    /// emit a QR request. A response arriving after the user navigated away is dropped:
    /// resurrecting a modal over a different screen would show a QR nobody asked for.
    pub fn show_qr(&mut self, target: QrTarget, data: QrData) {
        if self.exit_modal {
            return;
        }
        if let State::Schemes(s) = &mut self.state {
            s.open_qr(target.label, data);
        }
    }

    // --- the sealed store: what the embedder tells the UI, and what it answers ---------

    /// Install what the embedder read about the sealed store.
    ///
    /// Called at boot and after every operation that can move it (unlock, lock, wipe).
    /// Nothing here is secret, and nothing here is derived: the UI displays this struct
    /// and never computes any part of it, which is what keeps the flash and the key
    /// ladder on the std side of the boundary.
    pub fn set_lock_info(&mut self, info: LockInfo) {
        self.lock = info;
    }

    pub fn lock_info(&self) -> &LockInfo {
        &self.lock
    }

    /// Install the wallets the embedder read out of the store.
    ///
    /// Called after a successful unlock, and again after anything that changes the set: a
    /// save, a delete. The UI computes no part of this and keeps none of it past a lock -
    /// [`Ui::lock`] clears it, so a locked device holds no wallet list to render.
    pub fn set_wallets(&mut self, wallets: Vec<WalletRow>) {
        self.wallets = wallets;
    }

    pub fn wallets(&self) -> &[WalletRow] {
        &self.wallets
    }

    /// Install the wallet the embedder unsealed, answering [`UiRequest::OpenWallet`], with
    /// nothing but its public identity.
    ///
    /// The wallet home then offers what can be done without the keys, which today is
    /// exactly one thing: delete it. Prefer [`Ui::wallet_opened_with_keys`] wherever the
    /// embedder has the derivation in hand - see there for why.
    pub fn wallet_opened(&mut self, info: WalletInfo) {
        self.open_wallet(info, None);
    }

    /// The same answer, carrying the derivation the embedder produced while unsealing.
    ///
    /// This is what makes a STORED wallet usable rather than merely listable. The UI owns
    /// no key ladder: it cannot re-derive an xpub, a descriptor or a receive address from a
    /// slot number, so a wallet opened without a [`Report`] can only be deleted, while the
    /// identical wallet opened WITH one reaches S-26 and everything S-26 carries. The
    /// embedder already holds it - unsealing the record is what produced the seed - and
    /// this is the call that hands it over.
    ///
    /// The `Report` moves in, and it moves on again when the user taps Export: exactly one
    /// copy of the derivation exists in this crate at a time, and leaving the screen that
    /// holds it wipes it.
    pub fn wallet_opened_with_keys(&mut self, info: WalletInfo, report: Report) {
        self.open_wallet(info, Some(report));
    }

    /// The other answer to [`UiRequest::OpenWallet`]: it did not open, and this is why.
    ///
    /// The success path is a screen change, so the failure path has to be something the user
    /// can see on the screen they are still looking at - otherwise a tap on a wallet that
    /// will not unseal is a control that does nothing, which is the exact defect the
    /// request/answer vocabulary exists to remove. `reason` is the embedder's sentence,
    /// because only it knows which of the ways a sealed record can refuse this was.
    ///
    /// Dropped unless the wallet list is showing, like every other answer here.
    pub fn wallet_open_failed(&mut self, reason: String) {
        if let State::Wallets(w) = &mut self.state {
            w.report_failure(reason);
        }
    }

    /// Dropped unless the screen that asked is still showing: an answer arriving after
    /// the user has navigated away belongs to a tap they have moved on from, and opening a
    /// wallet over whatever they are looking at now would be a screen change nobody asked
    /// for. An embedder that gets a drop is holding a seed no screen can use, and the
    /// firmware closes it on the same pass.
    ///
    /// Two screens can be waiting for this, and they are left differently. The wallet list
    /// is PUSHED from, so Back returns to it. The unlock screen is REPLACED - Back must
    /// never return to a passphrase field, which is a screen that would ask for a secret
    /// the device is already holding, on a wallet that is already open.
    fn open_wallet(&mut self, info: WalletInfo, report: Option<Report>) {
        let slot = info.slot;
        let next = State::Wallet(WalletState::new(info, report));
        match &self.state {
            State::Wallets(_) => {
                self.apply(Outcome { nav: Nav::Push(next), request: None });
            }
            // Only the unlock screen for THIS slot, and only while it is waiting: an
            // answer for another wallet is a late answer whoever raised it.
            State::PassUnlock(u) if u.busy() && u.slot() == slot => {
                // It opened, so the refusals before it are not evidence about anything.
                self.gate.cleared(slot);
                self.enter(next);
            }
            _ => {}
        }
    }

    /// The wallet in `slot` cannot be opened without its BIP-39 passphrase: put the entry
    /// screen up and let the user type one.
    ///
    /// The OTHER answer to [`UiRequest::OpenWallet`], beside opening it and beside failing.
    /// It is not a failure and must not be rendered as one: nothing went wrong, the record
    /// is exactly what it always was, and the device is asking for the half of the seed it
    /// does not hold. The build before this one had no way to say that, so a passphrase
    /// wallet answered a tap with a refusal band naming two fingerprints - which is how the
    /// owner's own wallet became unopenable on his own device.
    ///
    /// `name` is what the list calls that slot, so every sentence on the screen names the
    /// wallet rather than a number.
    ///
    /// Dropped unless the wallet list is showing, like every other answer here: a prompt
    /// for a passphrase appearing over another screen is a request for a secret that
    /// nothing on the panel explains.
    pub fn wallet_needs_passphrase(&mut self, slot: u8, name: String) {
        if matches!(self.state, State::Wallets(_)) {
            self.apply(Outcome {
                nav: Nav::Push(State::PassUnlock(PassUnlockState::new(slot, &name))),
                request: None,
            });
        }
    }

    /// The passphrase that was typed opens a different wallet, so nothing was opened.
    ///
    /// Answers [`UiRequest::UnlockWallet`] and leaves the Busy frame - which is the half a
    /// failure path has to get right: an answer that only logged would leave the panel on a
    /// frame that says the device is working, forever.
    ///
    /// Both fingerprints are public values, and what the screen may say about them is
    /// [`PassphraseRefusal`]'s to decide. The retry gate is stepped HERE rather than on the
    /// screen, because it outlives the screen on purpose.
    ///
    /// Dropped unless that wallet's unlock screen is the one showing.
    pub fn passphrase_refused(&mut self, refusal: PassphraseRefusal) {
        let State::PassUnlock(u) = &mut self.state else { return };
        if !u.busy() {
            return;
        }
        let slot = u.slot();
        u.refused(refusal.sentence());
        self.gate.refused(slot);
    }

    /// Whether this device now remembers a wallet's passphrase, as the record reads AFTER
    /// the write. Answers [`UiRequest::StorePassphrase`] and
    /// [`UiRequest::ForgetPassphrase`].
    ///
    /// Routed through the screen's own `answered`, like every other 0.2.0 answer, so the
    /// row that renders it and the request that asked for it live in one module.
    pub fn passphrase_storage_result(&mut self, outcome: StorageOutcome) -> Option<UiRequest> {
        self.answer(Answer::PassphraseStorage(outcome))
    }

    /// What the backup check is asking, for a host driver that has no other way to read
    /// the panel (tools/uisim, the test suite). `None` on every other screen.
    pub fn quiz(&self) -> Option<QuizView> {
        match &self.state {
            State::Quiz(q) => Some(q.view()),
            _ => None,
        }
    }

    /// Show the lock screen, dropping every screen below it.
    ///
    /// This IS the UI half of a lock: the navigation stack is cleared, and because each
    /// entry owns its screen's secrets and wipes them on drop, clearing it wipes the
    /// rolls, mnemonic and passphrase of whatever the user was doing. The session itself
    /// lives on the std side and is dropped there; the two halves are called together.
    ///
    /// A no-op with no PIN set. That is R20 made structural rather than editorial: on an
    /// unprovisioned or blank device the lock screen cannot be reached at all, so no
    /// screen can imply that anti-phishing words - which are derived from the device key
    /// and therefore do not exist yet - are waiting behind it.
    pub fn lock(&mut self) -> bool {
        if !self.lock.status.has_pin() {
            return false;
        }
        self.lock.status = StoreStatus::Locked;
        self.exit_modal = false;
        self.pressed = None;
        // The list goes with the session it was read under. A locked device still holding
        // a renderable wallet list would be exactly the pre-PIN count Q2(a) forbids.
        self.wallets.clear();
        self.registrations.clear();
        self.reset(State::Lock(LockState));
        true
    }

    /// Install the anti-phishing words, answering [`UiRequest::DeviceWords`].
    ///
    /// Dropped unless PIN entry is showing: words arriving after the user navigated away
    /// belong to a prefix that is no longer typed.
    pub fn show_device_words(&mut self, words: [String; 2]) {
        let State::Pin(s) = &mut self.state else { return };
        s.install_words(words);
        // The words are installed FIRST and the explainer goes over the top, so dismissing
        // it lands on a PIN screen with the pair already on it. That ordering is the whole
        // instruction: the user reads what the words are for, taps once, and is looking at
        // them with the rest of the PIN still untyped - which is the moment the explainer
        // exists to reach.
        self.explain_device_words();
    }

    /// Show S-04a over whatever is on the panel, at most once per power-up.
    ///
    /// One function for both moments the owner named - a PIN has just been set, and the
    /// words are about to be shown for the first time - so the "at most once" is one flag
    /// checked in one place rather than a rule two call sites each half-implement.
    ///
    /// Pushed, never entered: the screen underneath is mid-flow (a PIN prefix typed, or a
    /// save the new PIN interrupted) and dismissing the explainer has to give it back
    /// exactly as it was.
    fn explain_device_words(&mut self) {
        if self.words_explained {
            return;
        }
        self.words_explained = true;
        let _ = self.apply(Outcome::push(State::WordsInfo(WordsInfoState)));
    }

    /// Install the verdict on a [`UiRequest::SetDeviceName`].
    ///
    /// On success the name is installed HERE as well as being written by the embedder, for
    /// the reason [`Ui::pin_created`] sets the status here: the lock screen may be drawn
    /// before the embedder gets back to [`Ui::set_lock_info`], and a device that has just
    /// been named must not draw itself as unnamed. The embedder still answers with the
    /// lock info it reads back - this is the transition, that is the truth.
    ///
    /// A refusal is REPORTED on the screen that asked rather than swallowed, and the name
    /// is left untouched: a user who was told nothing would go on believing their device
    /// is named until the next time they locked it.
    pub fn device_name_result(&mut self, saved: bool) {
        let State::DeviceName(s) = &mut self.state else { return };
        if !saved {
            s.report_failure();
            return;
        }
        self.lock.device_name = s.committed();
        self.pop();
    }

    /// Install the verdict on a [`UiRequest::UnsealWallet`].
    ///
    /// Returns the next request the outcome raises, so that answering one request can raise
    /// the next without the embedder having to know which outcomes do that. No outcome
    /// does today: the wrong-PIN arm used to reshuffle the pad, and the pad has been fixed
    /// since the 2026-08-19 reversal of Q35. The return type stays for the m4b outcomes,
    /// which re-seal records and will have a next request.
    pub fn unseal_result(&mut self, outcome: UnsealOutcome) -> Option<UiRequest> {
        let State::Pin(s) = &mut self.state else { return None };
        match outcome {
            UnsealOutcome::Unsealed => {
                self.lock.status = StoreStatus::Unlocked;
                // The wallet list is where an unlock lands: it is the real home once
                // anything is stored, and it is post-PIN, so it may show the wallets
                // themselves. The embedder fills it with `set_wallets`.
                self.reset(State::Wallets(WalletsState::new()));
                None
            }
            UnsealOutcome::WrongPin { attempts_left } => {
                s.reject();
                self.lock.attempts_left = attempts_left;
                None
            }
            UnsealOutcome::Wiped => {
                self.lock.status = StoreStatus::Blank;
                self.lock.attempts_left = None;
                self.reset(State::Home(HomeState));
                None
            }
            UnsealOutcome::Unreadable => {
                s.reject();
                self.lock.status = StoreStatus::Unreadable;
                self.reset(State::Home(HomeState));
                None
            }
        }
    }

    /// Install the verdict on a [`UiRequest::PersistWallet`]: `true` when the wallet was
    /// sealed.
    ///
    /// A success lands on the new wallet home and drops the whole create flow with it:
    /// the dice, the words and the passphrase are all on the back stack, and each wipes
    /// what it held as the stack is cleared. A failure leaves the naming screen exactly as
    /// it was, so a retry does not cost the user their typing.
    pub fn persist_result(&mut self, sealed: bool) {
        if !sealed {
            // K14: a refused save is reported on the panel, not swallowed.
            // The Name screen keeps the user's input and shows the failure.
            if let State::Name(n) = &mut self.state {
                n.save_failed = true;
            }
            return;
        }
        self.lock.status = StoreStatus::Unlocked;
        let State::Name(n) = &self.state else { return };
        let saved = n.saved();
        self.reset(State::Wallet(WalletState::new(saved, None)));
    }

    /// Install the verdict on a [`UiRequest::SetPin`]: `true` when the store was formatted
    /// under the new PIN and the session that formatting opens is live.
    ///
    /// A success is a whole-device transition and the flow continues where it was
    /// interrupted: the create screen is popped - which drops both of its entries - and the
    /// screen that asked for the PIN advances down the leg the user was already on. Today
    /// that is the save fork, and the advance is [`ForkState::save_target`], so the direct
    /// route and the post-PIN route are one definition rather than two that can drift.
    ///
    /// A failure is REPORTED, never swallowed: the screen keeps the panel and states that
    /// nothing was written. This is the first flash write the device ever makes, and a
    /// handler that logged it and returned would leave the user looking at a screen that
    /// says nothing happened while the device may have been left mid-format.
    ///
    /// The status is set here for the same reason [`Ui::persist_result`] sets it - the
    /// device is unlocked the instant the format returns, and a screen drawn before the
    /// embedder gets to [`Ui::set_lock_info`] must not describe a device with no PIN. The
    /// embedder still answers with the lock info it reads back; this is the transition, that
    /// is the truth.
    /// Dropped unless the create screen is showing, like every other answer here: the
    /// transition below pops a screen, and popping one the user has already left would move
    /// them somewhere they never asked to go. The store is still described correctly either
    /// way, because [`Ui::set_lock_info`] is what carries the truth about it.
    pub fn pin_created(&mut self, created: bool) {
        let State::SetPin(s) = &mut self.state else { return };
        if !created {
            s.report_failure();
            return;
        }
        self.lock.status = StoreStatus::Unlocked;
        self.pop();
        let next = match &self.state {
            State::Fork(f) => f.save_target(),
            _ => None,
        };
        if let Some(next) = next {
            let _ = self.apply(Outcome::push(next));
        }
        // The first of the two moments S-04a is shown at, and it is placed AFTER the flow
        // has advanced rather than instead of advancing it: the user set a PIN to get
        // somewhere, and an explainer that swallowed the transition would be a screen that
        // took the destination away. Dismissing it lands on the screen the PIN was for.
        //
        // This is also the only moment in the device's life when the words are new. The
        // user has just created the secret they are derived from, and has not yet typed a
        // PIN into a lock screen even once.
        self.explain_device_words();
    }

    /// Install the verdict on a [`UiRequest::SetWipePolicy`].
    ///
    /// Only the policy screen can have asked, so only it is told. The embedder answers
    /// this AND [`Ui::set_lock_info`] with the policy as it reads back afterwards: this
    /// call says whether the write happened, the other says what is now in force, and the
    /// screen shows the second while reporting the first.
    pub fn policy_result(&mut self, saved: bool) {
        if let State::Policy(s) = &mut self.state {
            s.install_result(saved);
        }
    }

    /// Install the verdict on a [`UiRequest::RemovePin`].
    ///
    /// A success is a whole-device transition, not a screen one: the store is unformatted,
    /// there is no PIN, no session and nothing sealed, so the UI returns to the 0.1.0
    /// stateless home with the back stack cleared - which wipes whatever the screens under
    /// it held - and the wallet list goes with it. That is the same shape as
    /// [`UnsealOutcome::Wiped`], because it is the same event arrived at deliberately.
    ///
    /// A failure is reported ON the settings screen rather than swallowed: a destructive
    /// request that quietly did nothing is the worst outcome to leave a user guessing at.
    pub fn pin_removed(&mut self, removed: bool) {
        if !removed {
            if let State::Settings(s) = &mut self.state {
                s.report_failure();
            }
            return;
        }
        self.lock.status = StoreStatus::Blank;
        self.lock.attempts_left = None;
        self.lock.wipe_after = None;
        self.lock.pin = None;
        self.wallets.clear();
        self.registrations.clear();
        self.exit_modal = false;
        self.pressed = None;
        self.reset(State::Home(HomeState));
    }

    // --- the card, the transaction and the registry -----------------------------------
    //
    // One method per request, each taking ONE outcome value whose variants include the
    // failures. That shape is the rule at the top of the firmware's `answer_request` made
    // structural: an embedder cannot answer with the success alone, because there is no
    // success-only call to make, and a request that is answered at all is answered on the
    // panel. Three handlers in this product's history logged an error and returned, each
    // leaving the user on a screen that had done nothing.
    //
    // Every one of them routes through [`Ui::answer`] and therefore returns the request the
    // screen raised next, if it raised one - the same chaining [`Ui::unseal_result`]
    // established, and the reason the embedder feeds the return value back into its own
    // request loop.

    /// Install the multisig registrations the embedder read out of the open wallet.
    ///
    /// An installer rather than an answer, exactly like [`Ui::set_wallets`]: the registry
    /// is device state that several screens read, it is filled when a wallet is opened, and
    /// it is refilled after anything that changes the set. Cleared by a lock.
    ///
    /// A wallet whose [`WalletInfo::registrations`] count is non-zero while this list is
    /// empty is a device that HAS registrations and could not read them; S-41 says exactly
    /// that rather than rendering the empty state, which would claim there are none.
    pub fn set_registrations(&mut self, registrations: Vec<RegistrationInfo>) {
        self.registrations = registrations;
    }

    /// Answer a [`UiRequest::SaveAddress`] with the result of the SD write.
    pub fn save_addr_result(&mut self, result: crate::SaveAddrResult) {
        let mut env = Env {
            network: &mut self.network,
            lock: &self.lock,
            wallets: &self.wallets,
            gate: &mut self.gate,
        };
        screens::answered(&mut self.state, Answer::SaveAddr(result), &mut env);
    }

    pub fn registrations(&self) -> &[RegistrationInfo] {
        &self.registrations
    }

    /// Install the answer to a [`UiRequest::ListCard`].
    pub fn card_result(&mut self, outcome: CardOutcome) -> Option<UiRequest> {
        self.answer(Answer::Card(outcome))
    }

    /// Install the answer to a [`UiRequest::LoadPsbt`]: a transaction that passed every
    /// check, or the refusal that ended it.
    pub fn psbt_result(&mut self, outcome: PsbtOutcome) -> Option<UiRequest> {
        self.answer(Answer::Psbt(outcome))
    }

    /// Install the answer to a [`UiRequest::SignTx`].
    pub fn sign_result(&mut self, outcome: SignOutcome) -> Option<UiRequest> {
        self.answer(Answer::Sign(outcome))
    }

    /// Install the answer to a [`UiRequest::WriteSigned`].
    pub fn write_result(&mut self, outcome: WriteOutcome) -> Option<UiRequest> {
        self.answer(Answer::Write(outcome))
    }

    /// Install the answer to a [`UiRequest::DiscardSigned`]: `true` when the signed
    /// transaction the std side was holding has been destroyed.
    ///
    /// `false` is not a formality. It is the state in which a signed transaction still
    /// exists in RAM while the user believes they have thrown it away, and the screen has
    /// to say so instead of leaving.
    pub fn discard_result(&mut self, discarded: bool) -> Option<UiRequest> {
        self.answer(Answer::Discard(discarded))
    }

    /// Install the answer to a [`UiRequest::ProbeCardFormat`]: whether formatting the card
    /// in the slot could repair it, or the reason it could not.
    ///
    /// Nothing has been written when this arrives, on any path, and the screen it lands on
    /// says so. The offer is the ONLY thing that puts a destructive control on S-49; a
    /// refusal leaves the screen with a sentence and a way out and no button that erases
    /// anything.
    pub fn format_offer(&mut self, offer: FormatOffer) -> Option<UiRequest> {
        self.answer(Answer::FormatOffer(offer))
    }

    /// Install the answer to a [`UiRequest::FormatCard`].
    ///
    /// `Failed` is not a formality here and it is not a shade of `Done`. It is the one
    /// answer in this whole vocabulary that can mean the user's card is in a WORSE state
    /// than before they touched the device, and the screen states that difference rather
    /// than reporting a generic failure over it.
    pub fn format_result(&mut self, outcome: FormatOutcome) -> Option<UiRequest> {
        self.answer(Answer::Formatted(outcome))
    }

    /// Install the answer to a [`UiRequest::ShowSignedQr`]: the signed transaction as a
    /// symbol S-39 can draw, or the sentence saying why it is not going on the glass.
    ///
    /// Deliberately NOT [`Ui::show_qr`]. That one installs onto the schemes screen and
    /// drops its answer anywhere else, which is right for the payloads it carries - an
    /// xpub, a receive address - and would silently swallow this one, because the delivery
    /// screen is not the schemes screen. Routed through the screen's own `answered` like
    /// every other 0.2.0 answer instead, so a late symbol is dropped by the screen the
    /// user has moved on to rather than opening a QR of a transaction over whatever they
    /// are now looking at.
    ///
    /// The symbol lands in the delivery screen's state and dies with it, which is what
    /// keeps "the only copy is on the std side, plus one rendering while S-39 is open"
    /// true.
    pub fn show_signed_qr(&mut self, outcome: SignedQrOutcome) -> Option<UiRequest> {
        self.answer(Answer::SignedQr(outcome))
    }

    /// Install the answer to a [`UiRequest::ImportRegistration`].
    pub fn import_result(&mut self, outcome: ImportOutcome) -> Option<UiRequest> {
        self.answer(Answer::Import(outcome))
    }

    /// Install the answer to a [`UiRequest::ApproveRegistration`].
    ///
    /// The embedder answers this AND [`Ui::set_registrations`] with the registry as it
    /// reads back afterwards: this call says what happened to the one registration, the
    /// other says what the wallet now holds.
    pub fn registration_result(&mut self, outcome: RegistrationOutcome) -> Option<UiRequest> {
        self.answer(Answer::Register(outcome))
    }

    /// Install the answer to a [`UiRequest::DeleteRegistration`]: `true` when the slot was
    /// erased.
    pub fn registration_deleted(&mut self, deleted: bool) -> Option<UiRequest> {
        self.answer(Answer::DeleteRegistration(deleted))
    }

    /// Install the answer to a [`UiRequest::DeleteWallet`].
    ///
    /// The embedder answers this AND [`Ui::set_wallets`] with the list as it reads back
    /// afterwards, in that order: this call says what happened to the one wallet, the other
    /// says what the device now holds. Both, always, and the failure variants are not
    /// optional - a delete that is answered on neither channel is the dead button this
    /// release was opened to fix.
    pub fn wallet_deleted(&mut self, outcome: DeleteOutcome) -> Option<UiRequest> {
        // The retry gate forgets a slot that has stopped holding the wallet it was
        // refusing, which is the second half of `UnlockGate::cleared`'s stated contract.
        //
        // Slots are REUSED. Without this, a user who mistyped a passphrase three times,
        // deleted that wallet and restored a new one into the freed slot would meet a
        // ten-second wait on their first honest attempt at the NEW wallet, and a doubling
        // one after that, for the rest of the power-up - a delay inherited from a wallet
        // that no longer exists, against a passphrase nobody has yet guessed at once.
        //
        // Only on `Gone`, and only for the slot the screen that raised the erase is
        // holding. `Refused` and `Damaged` have not established that the record is gone,
        // and releasing a wait for a wallet that may still be sitting in that slot would
        // be a relaxation of the gate bought with an ambiguous answer - which is the one
        // direction this gate must never move by accident.
        let emptied = match (&self.state, &outcome) {
            (State::Erase(e), DeleteOutcome::Gone { .. }) => Some(e.slot()),
            _ => None,
        };
        if let Some(slot) = emptied {
            self.gate.cleared(slot);
        }
        self.answer(Answer::DeleteWallet(outcome))
    }

    /// Install the answer to a [`UiRequest::RecoveryWords`]: the stored words, or why they
    /// could not be read.
    ///
    /// The words are pushed onto the navigation stack inside the screen that shows them, so
    /// [`Ui::lock`] wipes them with everything else it clears - a revealed set of words does
    /// not survive the auto-lock.
    pub fn recovery_words(&mut self, outcome: WordsOutcome) -> Option<UiRequest> {
        self.answer(Answer::RecoveryWords(outcome))
    }

    /// Route an answer to the screen that is showing and perform what it asks for.
    ///
    /// The ONE place an answer becomes a screen transition, mirroring [`Ui::activate`] for
    /// taps: the screen decides, this performs the single move, and a screen that did not
    /// raise the request takes the trait default and drops it - a late answer belongs to a
    /// tap the user has moved on from.
    fn answer(&mut self, answer: Answer) -> Option<UiRequest> {
        let mut env = Env {
            network: &mut self.network,
            lock: &self.lock,
            wallets: &self.wallets,
            gate: &mut self.gate,
        };
        let outcome = screens::answered(&mut self.state, answer, &mut env);
        self.apply(outcome)
    }

    /// Repaint the whole screen. The only output path this crate has.
    pub fn draw<D: DrawTarget<Color = Rgb565>>(&self, target: &mut D) -> Result<(), D::Error> {
        screens::draw(target, &self.state, &self.ctx())?;
        if self.exit_modal {
            draw_modal(target, &self.m, &EXIT_MODAL)?;
        }
        Ok(())
    }

    // --- internals ---------------------------------------------------------------------

    /// The read-only view the screens lay out, hit-test and paint from.
    fn ctx(&self) -> Ctx<'_> {
        Ctx {
            m: self.m,
            lock: &self.lock,
            verify: &self.verify,
            wallets: &self.wallets,
            registrations: &self.registrations,
            network: self.network,
            press: self.press(),
            hold_released: self.hold_released,
            gate: &self.gate,
        }
    }

    fn hit(&self, x: i32, y: i32) -> Option<RegionId> {
        self.regions().into_iter().find(|r| r.rect.contains(x, y)).map(|r| r.id)
    }

    /// Apply a vertical scroll delta to the current screen, clamped to its content.
    fn scroll_by(&mut self, dy: i32) {
        if dy == 0 || self.exit_modal {
            return;
        }
        // Built from the named fields rather than through `ctx()`: the screen needs
        // `&mut self.state` at the same time, and only a field-by-field borrow is
        // disjoint enough for that.
        let press = self.pressed.as_ref().map(|p| Press { id: p.id, held_ms: p.held_ms });
        let ctx = Ctx {
            m: self.m,
            lock: &self.lock,
            verify: &self.verify,
            wallets: &self.wallets,
            registrations: &self.registrations,
            network: self.network,
            press,
            hold_released: self.hold_released,
            gate: &self.gate,
        };
        screens::scroll(&mut self.state, dy, &ctx);
    }

    /// What a completed tap on `id` does. The exit modal takes priority over everything:
    /// while it is open only Cancel and Confirm are tappable (`regions` returns only
    /// those two), and every other tap is ignored.
    fn activate(&mut self, id: RegionId) -> Option<UiRequest> {
        if self.exit_modal {
            match id {
                RegionId::ModalCancel => self.exit_modal = false,
                RegionId::ModalConfirm => {
                    self.exit_modal = false;
                    self.pop();
                }
                _ => {}
            }
            return None;
        }
        let outcome = if id == RegionId::Back {
            // Back is the one region every screen may offer and each defines for itself,
            // so it is routed to that definition rather than through `activate`. `&mut`
            // for the same reason `activate` takes one: a screen whose Back hands its own
            // state to the screen it names has to be able to move it (`back_moving`).
            Outcome { nav: screens::back(&mut self.state), request: None }
        } else {
            // Field by field rather than through `ctx()`: the screen needs
            // `&mut self.state` at the same time, and only disjoint field borrows are
            // disjoint enough for that.
            let mut env = Env {
                network: &mut self.network,
                lock: &self.lock,
                wallets: &self.wallets,
                gate: &mut self.gate,
            };
            screens::activate(&mut self.state, id, &mut env)
        };
        self.apply(outcome)
    }

    /// Perform what a screen asked for. THE transition point of the crate: every screen
    /// change is one of these four moves, each of which drops the state it replaces.
    fn apply(&mut self, outcome: Outcome) -> Option<UiRequest> {
        match outcome.nav {
            Nav::Stay => {}
            Nav::Push(next) => {
                let previous = core::mem::replace(&mut self.state, next);
                self.prior.push(Box::new(previous));
            }
            Nav::Enter(next) => self.enter(next),
            Nav::Back => self.pop(),
            Nav::ConfirmExit => self.exit_modal = true,
        }
        outcome.request
    }

    /// Replace the current screen without remembering it. The old state is dropped here,
    /// which is what wipes the rolls, words or passphrase it owned.
    fn enter(&mut self, next: State) {
        self.state = next;
    }

    /// The previous screen, or the floor of this device when the stack is empty.
    fn pop(&mut self) {
        let previous = match self.prior.pop() {
            Some(p) => *p,
            None => self.floor(),
        };
        self.enter(previous);
    }

    /// What lies below everything: the wallet list on an unlocked device, the lock screen
    /// on a locked one, the stateless home on a device with nothing sealed. One function,
    /// because "where does Back go when there is nothing behind it" must have the same
    /// answer everywhere in the crate.
    ///
    /// The floor is a CLAIM ABOUT THE DEVICE, which is why this is a match over the store
    /// status and not one test for `Unlocked` with a default. Home's first line is that
    /// nothing is stored on this device; on a locked device holding a sealed wallet that
    /// sentence is false, and a screen that lies about what the device holds is a worse
    /// answer than one that asks for the PIN. Nothing in today's navigation graph reaches
    /// here with a locked store - S-03 is the only floor a locked device has, and PIN entry
    /// ENTERS it rather than pushing it - but that is an accident of two call sites rather
    /// than an invariant anything enforces, and it costs a lie the moment a third appears.
    /// The property is asserted directly in this module's tests, over every status, so it
    /// does not depend on the graph staying the shape it is today.
    fn floor(&self) -> State {
        match self.lock.status {
            StoreStatus::Unlocked => State::Wallets(WalletsState::new()),
            // R20 is satisfied for free: `Locked` is one of the two statuses `has_pin`
            // covers, so the device key - and therefore the anti-phishing word this screen
            // shows - exists.
            StoreStatus::Locked => State::Lock(LockState),
            // Nothing is sealed on any of these, so the stateless home describes them.
            // `Unreadable` sits here deliberately: there is no session to list and no PIN
            // that can be typed into a store that cannot be read (R-32), which is the same
            // place `unseal_result` puts that outcome, and the screen states the unreadable
            // store in its own status line rather than through the screen it picked.
            StoreStatus::NotProvisioned | StoreStatus::Blank | StoreStatus::Unreadable => {
                State::Home(HomeState)
            }
        }
    }

    /// Enter `next` and drop the whole back stack with it: what a lock, a wipe and a
    /// successful unlock all do. Each stack entry owns its screen's secrets, so clearing
    /// the stack wipes them.
    fn reset(&mut self, next: State) {
        self.prior.clear();
        self.enter(next);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The floor of the navigation stack is never a screen that misdescribes the device.
    ///
    /// S-09's first line is "Nothing is stored on this device." That is a fact about a
    /// device with no PIN and a falsehood about a locked one holding a sealed wallet, so
    /// the floor of a device that HAS a PIN may not be that screen - whatever the
    /// navigation graph happens to look like. The graph is the reason this was unreachable
    /// rather than the reason it was safe: today the lock screen is entered rather than
    /// pushed and no pop can arrive here with a locked store, but that is two call sites
    /// agreeing, not an invariant, and it is exactly the kind of agreement a new flow
    /// breaks. The table is the mapping; the assertion under it is the rule the mapping has
    /// to keep.
    #[test]
    fn the_floor_never_claims_a_device_with_a_sealed_store_is_empty() {
        for (status, expected) in [
            (StoreStatus::NotProvisioned, ScreenId::Home),
            (StoreStatus::Blank, ScreenId::Home),
            (StoreStatus::Locked, ScreenId::Lock),
            (StoreStatus::Unlocked, ScreenId::WalletList),
            (StoreStatus::Unreadable, ScreenId::Home),
        ] {
            let mut ui = Ui::new(720, 720);
            ui.set_lock_info(LockInfo { status, ..LockInfo::default() });
            let floor = ui.floor().id();
            assert_eq!(floor, expected, "{status:?}: wrong floor");
            assert!(
                !(status.has_pin() && floor == ScreenId::Home),
                "{status:?}: the floor is the stateless home on a device that has a PIN - \
                 a screen stating the device holds nothing while it holds a sealed store"
            );
        }
    }

    /// A pop with an empty stack lands on that floor, which is the only way any of it is
    /// reachable: `floor` has exactly one caller, and this is the behaviour it exists for.
    #[test]
    fn back_with_nothing_behind_it_lands_on_the_floor() {
        let mut ui = Ui::new(720, 720);
        ui.set_lock_info(LockInfo { status: StoreStatus::Locked, ..LockInfo::default() });
        // A screen with an empty back stack, reached the way a lock does it.
        ui.reset(State::Verify(crate::screens::verify::VerifyState::new()));
        assert!(ui.prior.is_empty());
        ui.pop();
        assert_eq!(ui.screen(), ScreenId::Lock);
    }
}
