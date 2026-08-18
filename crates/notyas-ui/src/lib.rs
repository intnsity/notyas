// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! notyas-ui - the board-independent UI layer of the notyas device.
//!
//! One deep module with a four-call interface: construct [`Ui`] with the display size,
//! feed it [`TouchEvent`]s, ask it to [`Ui::draw`] into any `Rgb565` [`DrawTarget`], and
//! call [`Ui::tick`] after the frame is published - the device framebuffer and the host
//! simulator (tools/uisim) are the same code path. `tick` exists for one reason: the
//! seed derivation blocks for seconds, and the frame that says so has to reach the panel
//! BEFORE it starts, so `touch` parks the work and `tick` runs it. It is a no-op on every
//! screen but [`ScreenId::Deriving`], so the embedder's loop calls it unconditionally.
//! Every screen repaints in full (no dirty rectangles in 0.1.0), every
//! rectangle derives from the display size through [`layout::Metrics`] (no absolute
//! coordinates; the primary panel is 720x720 but 800x480 must lay out correctly too),
//! and the pipeline itself is [`notyas_core`] - this crate renders what the core
//! computes and computes nothing of its own.
//!
//! # Secrecy rules (non-negotiable; desktop BigDice house law, adapted for touch)
//!
//! - DERIVED secrets (mnemonic words) mask as a FIXED-length bullet run
//!   ([`theme::MASK_WORD_BULLETS`]), never a run proportional to the secret: their
//!   length is itself information.
//! - INPUT fields (passphrase entry/confirm) mask ONE bullet per typed character:
//!   the user already knows what they typed, the NFKD byte counter beside the field
//!   discloses the length anyway, and a fixed run there reads as a rendering bug.
//!   A Show/Hide toggle (default Hidden) can reveal the literal input - an unseen
//!   typo silently derives a different wallet, which is the worse failure; the
//!   desktop shows typed input unmasked outright, hidden-by-default is the
//!   touch-device tightening of that same law.
//! - The mnemonic is masked by default and revealed only through the explicit two-step
//!   confirm modal; what the user TYPES (rolls, a phrase they already have) is their own
//!   input and is not masked, matching the desktop.
//! - Every buffer that held rolls, words, a phrase or a passphrase is zeroized when its
//!   screen is left: the state enum owns the secrets, the secrets' types wipe on drop
//!   ([`zeroize`], plus the self-wiping types of notyas-core), and leaving a screen drops
//!   the state.
//! - No secret appears in any `Debug` output; [`Ui`]'s impl prints the screen id only.
//! - There is no clipboard, no export, no persistence: pixels are the only output.
//!
//! # QR scope (0.1.0)
//!
//! The only values the UI ever offers as a QR code are **public**: per-scheme receive
//! addresses and the account xpub (plus its SLIP-132 rendering where one exists). There
//! is deliberately **no private-key export path on the device at all** - no mnemonic,
//! xprv, seed or WIF ever renders as a QR (or leaves the device any other way), which is
//! stronger than masking: desktop BigDice can reveal private values behind its reveal
//! gate, the device cannot. SeedQR-style mnemonic export is a considered 0.2.x feature,
//! not an 0.1.0 omission. Enforced structurally (the QR buttons exist only on the
//! Schemes screen, and only on public values) and asserted by the test suite.
//!
//! The UI also never *computes* a QR: notyas-core's `qr` feature needs std, and this
//! crate stays `no_std`. A tap on a QR button makes [`Ui::touch`] return
//! [`UiRequest::Qr`] naming the payload; the firmware encodes it (std side) and hands
//! the finished matrix back through [`Ui::show_qr`]. See [`qr`] for why this
//! request/response split was chosen over a provider callback.
//!
//! # Hit testing
//!
//! [`Ui::regions`] is the single source of truth for what is tappable: `touch` resolves
//! a tap against it and `draw` paints the same rectangles, so the tests (and the
//! simulator, which drives the UI by tapping region centers) exercise exactly what a
//! finger would.

#![no_std]
#![deny(unsafe_code)]

#[macro_use]
extern crate alloc;

#[cfg(test)]
extern crate std;

pub mod canvas;
pub mod layout;
pub mod qr;
mod screens;
pub mod theme;

use alloc::string::String;
use alloc::vec::Vec;
use alloc::boxed::Box;
use core::convert::Infallible;

use embedded_graphics::draw_target::DrawTarget;
use embedded_graphics::geometry::{Dimensions, Point, Size};
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::primitives::Rectangle;
use zeroize::{Zeroize, Zeroizing};

use layout::{Metrics, Rect};
pub use qr::QrData;
// `bitcoin` through the core's re-export: the UI names the pipeline's own exact pin
// (it only needs `Network::Bitcoin`), never a second dependency that could drift.
use notyas_core::bip39::{self, Mnemonic, MnemonicMode, WordCount, MIN_SECURE_BITS};
use notyas_core::bitcoin;
use notyas_core::derive::{ChildIndex, Scheme};
use notyas_core::entropy::{parse_dice, DiceEntropy};
use notyas_core::report::{self, Parameters, Report};

/// Crate version, shown on the Home screen. The workspace releases in lockstep, so this
/// is the product version too.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Receive addresses derived per scheme. The device screen is the bound here, exactly as
/// each desktop front end picks its own count.
pub const ADDRESS_ROWS: u32 = 5;

/// Byte caps on the typed-phrase and passphrase buffers. Each buffer is created with
/// its full capacity pre-reserved (`secret_buf`), so a `push` can never reallocate and
/// strand an unwiped copy of a partial secret outside the `Zeroizing` wrapper's reach -
/// the same discipline desktop BigDice applies to its passphrase buffers.
const PHRASE_MAX: usize = 1024;
const PASS_MAX: usize = 256;

/// A self-wiping string that will never reallocate below `cap` bytes (+3 slack for the
/// widest UTF-8 char a guard of `len() < cap` can still admit).
fn secret_buf(cap: usize) -> Zeroizing<String> {
    Zeroizing::new(String::with_capacity(cap + 3))
}

/// A touch panel event in display coordinates. The GT911 (or the simulator) reports
/// down/move/up; the UI turns down+up-on-the-same-region into a tap and vertical moves
/// into scrolling on the scrollable screens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TouchEvent {
    Down { x: i32, y: i32 },
    Move { x: i32, y: i32 },
    Up { x: i32, y: i32 },
}

/// Which screen is showing. Carries no data - the data lives in the state the `Ui` owns -
/// so it is safe to log and compare.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScreenId {
    Home,
    DiceEntry,
    MnemonicDisplay,
    PhraseEntry,
    PassphraseEntry,
    /// Interstitial while the seed/derivation pipeline runs (see [`Ui::tick`]). No
    /// tappable regions: the compute is synchronous and cannot be cancelled.
    Deriving,
    Schemes,
    VerifyDevice,
}

/// Semantic identity of a tappable region. What a tap MEANS, decoupled from where the
/// rectangle happens to be on this panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionId {
    /// Top-bar back: returns to Home, dropping (and thereby zeroizing) the screen state.
    Back,
    HomeNewSeed,
    HomeVerifySeed,
    HomeVerifyDevice,
    /// Dice keypad digit, 1..=6.
    Digit(u8),
    DiceBackspace,
    /// Dice mode segment, indexing the desktop mode set: RAW, then
    /// [`bip39::FIXED_WORD_COUNTS`] (12/15/18/21/24) - see [`dice_mode`].
    Mode(u8),
    DiceDone,
    /// Opens the reveal-confirm modal on the mnemonic screen.
    Reveal,
    /// Mnemonic screen -> passphrase screen.
    Next,
    /// "Use passphrase" opt-in toggle.
    PassToggle,
    /// Show/Hide the passphrase fields (default Hidden; plain button, no confirm -
    /// the passphrase is session-only typed input and an unseen typo is the worse
    /// failure).
    PassShow,
    /// Focus the passphrase entry field.
    PassEntry,
    /// Focus the repeat-passphrase field.
    PassConfirm,
    /// On-screen keyboard character key.
    Key(char),
    Shift,
    PageDigits,
    PageLetters,
    PageSymbols,
    Space,
    KeyBackspace,
    /// Keyboard Done: commits the phrase / passphrase screen.
    KeyDone,
    /// Scheme tab, indexing [`Scheme::ALL`].
    Tab(u8),
    /// QR button beside the account xpub on the schemes screen.
    QrXpub,
    /// QR button beside the SLIP-132 rendering (BIP49/84 mainnet only).
    QrSlip132,
    /// QR button beside receive address row `n` (0-based).
    QrAddress(u8),
    ModalCancel,
    ModalConfirm,
    /// Close button of the QR modal.
    ModalClose,
    /// Mainnet / testnet toggle on the Home screen.
    NetToggle,
    /// BIP39 completion chip `n` (0-based) in the phrase-entry suggestion strip.
    /// Tapping replaces the word fragment being typed with the full word and appends
    /// the separating space. Offered on the phrase screen only: it completes the user's
    /// OWN typed input against a public wordlist, which is not a path any derived or
    /// masked value can reach.
    Suggest(u8),
}

// ---------------------------------------------------------------------------------------
// Requests to the embedder
// ---------------------------------------------------------------------------------------

/// What the user asked to see as a QR code. Both fields are **public values by
/// construction**: the only [`RegionId`]s that produce a target are the schemes screen's
/// QR buttons, which sit beside receive addresses and account xpubs (see the crate-level
/// "QR scope" note). `label` is what the modal will title itself with (a derivation
/// path or "Account xpub ..."), safe to log; `payload` is the exact string to encode -
/// no transformation between what the screen shows and what the scanner reads, the same
/// policy as `notyas_core::qr`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QrTarget {
    pub label: String,
    pub payload: String,
}

/// Work the [`Ui`] needs its embedder to do, returned from [`Ui::touch`].
///
/// Chosen over a provider trait/callback deliberately: a callback would have to be
/// stored (`Box<dyn ...>` erasing what runs inside the input path) or threaded through
/// every `touch` call, and either way QR encoding - std-only code - would execute
/// *inside* this no_std crate's state machine. Returning a request keeps `touch` a pure
/// state transition, keeps the std/no_std boundary visible in the type system, and
/// costs the embedder three lines: match, encode, [`Ui::show_qr`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UiRequest {
    /// Encode `payload` (e.g. with `notyas_core::qr::matrix`, std side), pack it into a
    /// [`QrData`] and hand it back via [`Ui::show_qr`] together with this target.
    Qr(QrTarget),
}

/// A tappable region: identity plus the rectangle it occupies right now.
#[derive(Debug, Clone, Copy)]
pub struct Region {
    pub id: RegionId,
    pub rect: Rect,
}

/// The Verify-device screen's values. The firmware fills this from what it actually
/// read (running-partition hash, eFuse state, GPIO54 level - SECURITY.md invariant 5);
/// the UI only displays it. The simulator passes obviously-fake values marked DUMMY.
#[derive(Debug, Clone)]
pub struct VerifyInfo {
    pub firmware_version: String,
    /// Board name this image was built for (the build IS the board - BOARDS.md).
    pub board: String,
    /// Runtime platform as read at boot: IDF version and silicon revision.
    pub platform: String,
    /// SHA256 of the running app partition, lowercase hex.
    pub app_sha256: String,
    /// Source-id hash of the tree the firmware was built from.
    pub source_id: String,
    pub self_test: String,
    pub self_test_ok: bool,
    /// Radio lockdown state, e.g. "C6 held in reset (GPIO54 low)".
    pub radio: String,
    pub radio_ok: bool,
    pub secure_boot: String,
    pub flash_encryption: String,
}

impl Default for VerifyInfo {
    /// Honest placeholders: a Verify screen with nothing supplied reports exactly that,
    /// never a reassuring constant.
    fn default() -> Self {
        VerifyInfo {
            firmware_version: String::from("not read"),
            board: String::from("not read"),
            platform: String::from("not read"),
            app_sha256: String::from("not read"),
            source_id: String::from("not read"),
            self_test: String::from("not run"),
            self_test_ok: false,
            radio: String::from("not read"),
            radio_ok: false,
            secure_boot: String::from("not read"),
            flash_encryption: String::from("not read"),
        }
    }
}

// ---------------------------------------------------------------------------------------
// Screen state (private; owns all secrets)
// ---------------------------------------------------------------------------------------

/// On-screen keyboard page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Page {
    Lower,
    Upper,
    Digits,
    Symbols,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PassFocus {
    Entry,
    Confirm,
}

pub(crate) struct DiceState {
    /// The digits as typed (1-6). `Zeroizing`, because this string alone regenerates the
    /// wallet.
    pub rolls: Zeroizing<String>,
    /// Parsed form of `rolls`, kept in step by the edit handlers (parsing is cheap but
    /// the draw path should not re-derive state). Self-wiping.
    pub entropy: DiceEntropy,
    pub mode: MnemonicMode,
}

impl DiceState {
    fn new() -> Self {
        DiceState {
            // Worst case one ASCII digit per entropy bit (rolls of 4/5 yield 1 bit), so
            // this capacity holds every string the MAX_ENTROPY_BITS guard can admit.
            rolls: secret_buf(bip39::MAX_ENTROPY_BITS),
            entropy: parse_dice(""),
            mode: MnemonicMode::Raw,
        }
    }

    /// ENT the current mode would put in the mnemonic, given the bits collected so far.
    fn ent(&self) -> usize {
        let total = self.entropy.binary().len();
        match self.mode {
            MnemonicMode::Raw => bip39::raw_bits_used(total),
            // ENT = words * 32 / 3 (each word is 11 bits, 32 of every 33 are entropy).
            MnemonicMode::Words(n) => n.get() * 32 / 3,
        }
    }

    /// The number every warning is computed from, per the desktop rule.
    pub fn effective_bits(&self) -> usize {
        report::effective_bits(self.mode, self.ent(), self.entropy.binary().len())
    }
}

pub(crate) struct MnemonicState {
    pub dice: DiceEntropy,
    pub mode: MnemonicMode,
    /// The words being shown. notyas-core's type: wipes itself on drop.
    pub mnem: Mnemonic,
    pub revealed: bool,
    /// Reveal-confirm modal is open.
    pub modal: bool,
    pub scroll: i32,
}

pub(crate) struct PhraseState {
    pub text: Zeroizing<String>,
    pub page: Page,
}

/// Where the seed material for the passphrase screen came from.
pub(crate) enum SeedSource {
    Dice { dice: DiceEntropy, mode: MnemonicMode },
    Phrase(Zeroizing<String>),
}

impl SeedSource {
    /// A self-wiping copy, for handing the seed material to the Deriving state while the
    /// passphrase screen keeps its own (Back must restore that screen intact). Not a
    /// `Clone` impl on purpose: duplicating secret material is a decision each call site
    /// should have to write out.
    fn duplicate(&self) -> SeedSource {
        match self {
            SeedSource::Dice { dice, mode } => {
                SeedSource::Dice { dice: dice.clone(), mode: *mode }
            }
            // Exact-capacity allocation, so the copy cannot grow and strand a partial
            // phrase outside the Zeroizing wrapper.
            SeedSource::Phrase(p) => SeedSource::Phrase(Zeroizing::new(String::from(&**p))),
        }
    }

    /// The mnemonic mode the pipeline should run in. The phrase path does not use one;
    /// it takes the same placeholder the core does.
    fn mode(&self) -> MnemonicMode {
        match self {
            SeedSource::Dice { mode, .. } => *mode,
            SeedSource::Phrase(_) => MnemonicMode::Raw,
        }
    }
}

/// Everything the pending derivation needs, parked while the interstitial is on screen.
///
/// The seed material lives HERE rather than being read back off the passphrase screen so
/// that [`Ui::tick`] is a pure function of this state: the blocking work cannot depend on
/// anything the user might have changed between the frame being painted and the compute
/// starting.
pub(crate) struct DerivingState {
    pub source: SeedSource,
    /// Empty when the user did not opt in, which is exactly what the pipeline wants.
    pub passphrase: Zeroizing<String>,
}

pub(crate) struct PassState {
    pub source: SeedSource,
    /// The desktop's explicit opt-in: off means the seed derives with an empty
    /// passphrase, and the screen says so.
    pub enabled: bool,
    pub entry: Zeroizing<String>,
    pub confirm: Zeroizing<String>,
    pub focus: PassFocus,
    pub page: Page,
    /// Show/Hide toggle (default hidden). When true the passphrase fields render
    /// unmasked so the user can verify what they typed - an unseen typo silently
    /// derives a different wallet, which is the worse failure.
    pub show: bool,
}

/// The QR modal, open over the schemes screen: a finished symbol plus its title.
pub(crate) struct QrModal {
    pub label: String,
    pub data: QrData,
}

pub(crate) struct SchemesState {
    /// The full pipeline output; its own Drop wipes the secrets it holds.
    pub report: Report,
    pub tab: usize,
    pub scroll: i32,
    /// `Some` while the QR modal is open. Filled only through [`Ui::show_qr`]
    /// (the embedder answering a [`UiRequest::Qr`]), never computed here.
    pub qr: Option<QrModal>,
}

// The variants differ in size because each owns exactly its screen's data (a Report is
// large); exactly one State exists at a time, so boxing would buy indirection, not memory.
#[allow(clippy::large_enum_variant)]
pub(crate) enum State {
    Home,
    Dice(DiceState),
    Mnemonic(MnemonicState),
    Phrase(PhraseState),
    Passphrase(PassState),
    Deriving(DerivingState),
    Schemes(SchemesState),
    Verify { scroll: i32 },
}

// ---------------------------------------------------------------------------------------
// The Ui
// ---------------------------------------------------------------------------------------

/// Movement beyond this many pixels turns a press into a drag and cancels the tap.
const DRAG_SLOP: i32 = 16;

/// In-flight touch bookkeeping between Down and Up.
struct Pressed {
    id: Option<RegionId>,
    last_y: i32,
    /// Accumulated absolute vertical movement, for the tap-vs-drag decision.
    moved: i32,
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
    /// screen state so the choice survives screen changes within a session. Power-off
    /// resets it to mainnet like everything else - the device is stateless.
    network: bitcoin::Network,
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
            state: State::Home,
            verify: VerifyInfo::default(),
            pressed: None,
            prior: Vec::new(),
            exit_modal: false,
            network: bitcoin::Network::Bitcoin,
        }
    }

    /// The network the next derivation will run on (Home-screen toggle).
    pub fn network(&self) -> bitcoin::Network {
        self.network
    }

    pub fn screen(&self) -> ScreenId {
        match self.state {
            State::Home => ScreenId::Home,
            State::Dice(_) => ScreenId::DiceEntry,
            State::Mnemonic(_) => ScreenId::MnemonicDisplay,
            State::Phrase(_) => ScreenId::PhraseEntry,
            State::Passphrase(_) => ScreenId::PassphraseEntry,
            State::Deriving(_) => ScreenId::Deriving,
            State::Schemes(_) => ScreenId::Schemes,
            State::Verify { .. } => ScreenId::VerifyDevice,
        }
    }

    /// Install the values the Verify screen shows. The firmware calls this once at boot
    /// with what it measured; until then the screen shows "not read" placeholders.
    pub fn set_verify_info(&mut self, info: VerifyInfo) {
        self.verify = info;
    }

    /// Every tappable region of the current screen, in no particular order. When the
    /// modal is open, only the modal's buttons are returned - the sheet below it is
    /// inert, exactly as it is unreachable on screen.
    pub fn regions(&self) -> Vec<Region> {
        if self.exit_modal {
            return screens::exit_modal_regions(&self.m);
        }
        screens::regions(&self.m, &self.state)
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
        self.tick();
        match ev {
            TouchEvent::Down { x, y } => {
                let id = self.hit(x, y);
                self.pressed = Some(Pressed { id, last_y: y, moved: 0 });
                None
            }
            TouchEvent::Move { x: _, y } => {
                let p = self.pressed.as_mut()?;
                let dy = y - p.last_y;
                p.last_y = y;
                p.moved += dy.abs();
                if p.moved > DRAG_SLOP {
                    p.id = None;
                }
                self.scroll_by(-dy);
                None
            }
            TouchEvent::Up { x, y } => {
                let p = self.pressed.take()?;
                let (down, up) = (p.id?, self.hit(x, y)?);
                if down == up && p.moved <= DRAG_SLOP {
                    self.activate(down)
                } else {
                    None
                }
            }
        }
    }

    /// Run the pending blocking computation, if the current screen has one.
    ///
    /// The embedder's loop is `touch -> draw -> tick`. Only the Deriving screen has
    /// pending work (the seed stretch and the whole scheme derivation, seconds of PBKDF2
    /// on this silicon), and it exists precisely so that the "Deriving" frame is painted
    /// and published BEFORE that work starts - a synchronous derivation behind the
    /// passphrase screen is indistinguishable from a hung device.
    ///
    /// A no-op returning `false` on every other screen, so the loop can call it
    /// unconditionally; `true` means the state advanced and the screen needs a repaint.
    pub fn tick(&mut self) -> bool {
        let State::Deriving(d) = &self.state else {
            return false;
        };
        let params = Parameters {
            mode: d.source.mode(),
            passphrase: &d.passphrase,
            network: self.network,
            schemes: &Scheme::ALL,
            account: ChildIndex::ZERO,
            change: ChildIndex::ZERO,
            count: ADDRESS_ROWS,
            script_type: 2,
        };
        let report = match &d.source {
            SeedSource::Dice { dice, .. } => Report::build(dice, &params).ok(),
            SeedSource::Phrase(text) => Report::from_phrase(text, &params),
        };
        self.state = match report {
            Some(report) => State::Schemes(SchemesState { report, tab: 0, scroll: 0, qr: None }),
            // Both arms were validated before the passphrase screen, so a None here is a
            // core bug. Falling back to the screen the user came from beats wedging on an
            // interstitial that will never finish, and beats panicking in the input path.
            None => self.prior.pop().map(|p| *p).unwrap_or(State::Home),
        };
        true
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
            s.qr = Some(QrModal { label: target.label, data });
        }
    }

    /// Repaint the whole screen. The only output path this crate has.
    pub fn draw<D: DrawTarget<Color = Rgb565>>(&self, target: &mut D) -> Result<(), D::Error> {
        screens::draw(target, &self.m, &self.state, &self.verify, self.network)?;
        if self.exit_modal {
            screens::draw_exit_modal(target, &self.m)?;
        }
        Ok(())
    }

    // --- internals ---------------------------------------------------------------------

    fn hit(&self, x: i32, y: i32) -> Option<RegionId> {
        self.regions().into_iter().find(|r| r.rect.contains(x, y)).map(|r| r.id)
    }

    /// Apply a vertical scroll delta to the current screen, clamped to its content.
    fn scroll_by(&mut self, dy: i32) {
        if dy == 0 || self.exit_modal {
            return;
        }
        let limit = screens::scroll_limit(&self.m, &self.state, &self.verify);
        match &mut self.state {
            State::Mnemonic(s) if !s.modal => s.scroll = (s.scroll + dy).clamp(0, limit),
            // The sheet under an open QR modal is inert, scrolling included.
            State::Schemes(s) if s.qr.is_none() => s.scroll = (s.scroll + dy).clamp(0, limit),
            State::Verify { scroll } => *scroll = (*scroll + dy).clamp(0, limit),
            _ => {}
        }
    }

    /// The state machine: what a completed tap on `id` does in the current state.
    /// Unmatched combinations are ignored by construction - `regions` never offers a
    /// region the current state cannot act on. Returns the request a QR button raises;
    /// every other tap resolves entirely inside this crate and returns `None`.
    fn activate(&mut self, id: RegionId) -> Option<UiRequest> {
        // Exit-confirmation modal takes priority over everything: while it is
        // open, only Cancel and Confirm are tappable (regions() returns only
        // those two), and every other tap is ignored.
        if self.exit_modal {
            match id {
                RegionId::ModalCancel => self.exit_modal = false,
                RegionId::ModalConfirm => {
                    self.exit_modal = false;
                    if let Some(prev) = self.prior.pop() {
                        self.state = *prev;
                    } else {
                        self.state = State::Home;
                    }
                }
                _ => {}
            }
            return None;
        }

        match (&mut self.state, id) {
            // --- global -----------------------------------------------------------------
            // Back: navigates to the prior screen. On serious screens (where a
            // derived secret is in memory) the exit-confirmation modal opens
            // first; on input-only screens (Dice, Phrase, Verify) it goes
            // straight back, matching the user's expectation that "Back" means
            // "the screen I was on before".
            (_, RegionId::Back) => {
                match &self.state {
                    State::Mnemonic(_) | State::Passphrase(_) | State::Schemes(_) => {
                        self.exit_modal = true;
                    }
                    _ => {
                        if let Some(prev) = self.prior.pop() {
                            self.state = *prev;
                        } else {
                            self.state = State::Home;
                        }
                    }
                }
            }

            // --- home: network toggle ---------------------------------------------------
            (State::Home, RegionId::NetToggle) => {
                self.network = match self.network {
                    bitcoin::Network::Bitcoin => bitcoin::Network::Testnet,
                    _ => bitcoin::Network::Bitcoin,
                };
            }

            // --- home -------------------------------------------------------------------
            (State::Home, RegionId::HomeNewSeed) => self.state = State::Dice(DiceState::new()),
            (State::Home, RegionId::HomeVerifySeed) => {
                self.state = State::Phrase(PhraseState {
                    text: secret_buf(PHRASE_MAX),
                    page: Page::Lower,
                })
            }
            (State::Home, RegionId::HomeVerifyDevice) => self.state = State::Verify { scroll: 0 },

            // --- dice entry -------------------------------------------------------------
            (State::Dice(s), RegionId::Digit(d)) if (1..=6).contains(&d) => {
                // Stop short of the BIP39 encoder's ENT ceiling: past it more rolls can
                // no longer change the raw-mode result (see MAX_ENTROPY_BITS).
                if s.entropy.binary().len() + 2 <= bip39::MAX_ENTROPY_BITS {
                    s.rolls.push((b'0' + d) as char);
                    s.entropy = parse_dice(&s.rolls);
                }
            }
            (State::Dice(s), RegionId::DiceBackspace) => {
                s.rolls.pop();
                s.entropy = parse_dice(&s.rolls);
            }
            (State::Dice(s), RegionId::Mode(i)) if (i as usize) < DICE_MODE_LABELS.len() => {
                s.mode = dice_mode(i);
            }
            (State::Dice(s), RegionId::DiceDone) => {
                if s.effective_bits() < MIN_SECURE_BITS {
                    return None; // Drawn disabled, with the reason; a tap does nothing.
                }
                if let Ok(mnem) = bip39::mnemonic_from_dice(&s.entropy, s.mode) {
                    let dice = s.entropy.clone();
                    let mode = s.mode;
                    self.prior.push(Box::new(core::mem::replace(&mut self.state, State::Home)));
                    self.state = State::Mnemonic(MnemonicState {
                        dice,
                        mode,
                        mnem,
                        revealed: false,
                        modal: false,
                        scroll: 0,
                    });
                }
            }

            // --- mnemonic display -------------------------------------------------------
            (State::Mnemonic(s), RegionId::Reveal) if !s.modal => s.modal = true,
            (State::Mnemonic(s), RegionId::ModalConfirm) => {
                s.revealed = true;
                s.modal = false;
            }
            (State::Mnemonic(s), RegionId::ModalCancel) => s.modal = false,
            (State::Mnemonic(s), RegionId::Next) if !s.modal => {
                let dice = s.dice.clone();
                let mode = s.mode;
                self.prior.push(Box::new(core::mem::replace(&mut self.state, State::Home)));
                self.state = State::Passphrase(PassState {
                    source: SeedSource::Dice { dice, mode },
                    enabled: false,
                    entry: secret_buf(PASS_MAX),
                    confirm: secret_buf(PASS_MAX),
                    focus: PassFocus::Entry,
                    page: Page::Lower,
                    show: false,
                });
            }

            // --- phrase entry (verify existing seed) ------------------------------------
            (State::Phrase(s), RegionId::Key(c)) => {
                if s.text.len() < PHRASE_MAX {
                    s.text.push(c);
                }
            }
            (State::Phrase(s), RegionId::Space) => {
                if s.text.len() < PHRASE_MAX {
                    s.text.push(' ');
                }
            }
            (State::Phrase(s), RegionId::KeyBackspace) => {
                s.text.pop();
            }
            // Completing a word: replace the fragment being typed with the chosen word
            // and append the separating space, so the next word can be typed straight
            // away. The list comes from `screens::suggestions` - the same call the strip
            // drew and `regions` hit-tested - so index `i` cannot resolve to a different
            // word than the one under the finger.
            (State::Phrase(s), RegionId::Suggest(i)) => {
                if let Some(word) = screens::suggestions(&s.text).get(i as usize) {
                    let keep = s.text.len() - bip39::current_word_fragment(&s.text).len();
                    s.text.truncate(keep);
                    // The truncate freed at least one byte per fragment character, so
                    // this only declines at a phrase that was already at the cap.
                    // (`+ 1` is the separating space, folded into the comparison.)
                    if s.text.len() + word.len() < PHRASE_MAX {
                        s.text.push_str(word);
                        s.text.push(' ');
                    }
                }
            }
            (State::Phrase(s), RegionId::Shift) => {
                s.page = if s.page == Page::Lower { Page::Upper } else { Page::Lower };
            }
            (State::Phrase(s), RegionId::PageDigits) => s.page = Page::Digits,
            (State::Phrase(s), RegionId::PageLetters) => s.page = Page::Lower,
            (State::Phrase(s), RegionId::PageSymbols) => s.page = Page::Symbols,
            (State::Phrase(s), RegionId::KeyDone) => {
                let normalized = bip39::normalize_phrase(&s.text);
                if normalized.is_empty() {
                    return None; // Nothing typed; Done is drawn disabled.
                }
                self.prior.push(Box::new(core::mem::replace(&mut self.state, State::Home)));
                self.state = State::Passphrase(PassState {
                    source: SeedSource::Phrase(normalized),
                    enabled: false,
                    entry: secret_buf(PASS_MAX),
                    confirm: secret_buf(PASS_MAX),
                    focus: PassFocus::Entry,
                    page: Page::Lower,
                    show: false,
                });
            }

            // --- passphrase -------------------------------------------------------------
            (State::Passphrase(s), RegionId::PassToggle) => {
                s.enabled = !s.enabled;
                if !s.enabled {
                    // Off wipes what was typed: an abandoned passphrase must not linger.
                    s.entry.zeroize();
                    s.confirm.zeroize();
                    s.focus = PassFocus::Entry;
                }
            }
            (State::Passphrase(s), RegionId::PassShow) => s.show = !s.show,
            (State::Passphrase(s), RegionId::PassEntry) => s.focus = PassFocus::Entry,
            (State::Passphrase(s), RegionId::PassConfirm) => s.focus = PassFocus::Confirm,
            (State::Passphrase(s), RegionId::Key(c)) => pass_edit(s, Some(c)),
            (State::Passphrase(s), RegionId::Space) => pass_edit(s, Some(' ')),
            (State::Passphrase(s), RegionId::KeyBackspace) => pass_edit(s, None),
            (State::Passphrase(s), RegionId::Shift) => {
                s.page = if s.page == Page::Lower { Page::Upper } else { Page::Lower };
            }
            (State::Passphrase(s), RegionId::PageDigits) => s.page = Page::Digits,
            (State::Passphrase(s), RegionId::PageLetters) => s.page = Page::Lower,
            (State::Passphrase(s), RegionId::PageSymbols) => s.page = Page::Symbols,
            // Done on the passphrase screen does NOT derive. It parks the seed material
            // in the Deriving state and returns, so the embedder's next draw puts the
            // interstitial on the panel BEFORE [`Ui::tick`] spends several seconds in
            // PBKDF2. Deriving inline here is what made this transition feel like a
            // freeze: the last passphrase keypress stayed on screen for the whole stretch.
            (State::Passphrase(s), RegionId::KeyDone) => {
                if s.enabled && *s.entry != *s.confirm {
                    return None; // Mismatch shown in danger ink; Done is drawn disabled.
                }
                let mut passphrase = secret_buf(PASS_MAX);
                if s.enabled {
                    passphrase.push_str(&s.entry);
                }
                let source = s.source.duplicate();
                self.prior.push(Box::new(core::mem::replace(&mut self.state, State::Home)));
                self.state = State::Deriving(DerivingState { source, passphrase });
            }

            // --- schemes ----------------------------------------------------------------
            (State::Schemes(s), RegionId::Tab(i)) if (i as usize) < Scheme::ALL.len() => {
                s.tab = i as usize;
                s.scroll = 0;
            }
            // The QR buttons: every payload here is a PUBLIC value (crate-level QR scope
            // note). The request carries the exact string the screen shows - encoding
            // happens on the embedder's std side, the modal opens via `show_qr`.
            (State::Schemes(s), RegionId::QrXpub) => {
                let acct = &s.report.schemes[s.tab.min(s.report.schemes.len() - 1)].derived.account;
                return Some(UiRequest::Qr(QrTarget {
                    label: format!("Account xpub {}", acct.path),
                    payload: acct.xpub.clone(),
                }));
            }
            (State::Schemes(s), RegionId::QrSlip132) => {
                let sr = &s.report.schemes[s.tab.min(s.report.schemes.len() - 1)];
                let (slip, (_, label)) =
                    (sr.derived.account.slip132_pub.as_ref()?, sr.scheme.slip132_labels()?);
                return Some(UiRequest::Qr(QrTarget {
                    label: format!("{label} {}", sr.derived.account.path),
                    payload: slip.clone(),
                }));
            }
            (State::Schemes(s), RegionId::QrAddress(i)) => {
                let sr = &s.report.schemes[s.tab.min(s.report.schemes.len() - 1)];
                let row = sr.derived.rows.get(i as usize)?;
                return Some(UiRequest::Qr(QrTarget {
                    label: row.path.clone(),
                    payload: row.address.clone(),
                }));
            }
            (State::Schemes(s), RegionId::ModalClose) => s.qr = None,

            _ => {}
        }
        None
    }
}

/// Segment labels of the dice mode control, in [`dice_mode`] index order. Desktop
/// parity: the full `--words <raw|12|15|18|21|24>` set, not a binary toggle. All the
/// fixed counts share the Coldcard/SeedSigner-compatible SHA256 math; RAW is the
/// iancoleman-compatible raw-bits mode (ARCHITECTURE.md dice math note).
pub(crate) const DICE_MODE_LABELS: [&str; 6] = ["RAW", "12", "15", "18", "21", "24"];

/// The mode behind segment `i` of the dice mode control: 0 = RAW, 1..=5 = the
/// [`bip39::FIXED_WORD_COUNTS`] entry. Total for any u8 (out-of-range clamps to 24),
/// keeping the input path panic-free.
pub(crate) fn dice_mode(i: u8) -> MnemonicMode {
    match i {
        0 => MnemonicMode::Raw,
        _ => {
            let count = bip39::FIXED_WORD_COUNTS[(i as usize - 1).min(4)];
            // Every FIXED_WORD_COUNTS member is a valid WordCount by definition.
            MnemonicMode::Words(WordCount::new(count).unwrap_or_else(|_| unreachable!()))
        }
    }
}

/// Inverse of [`dice_mode`], for drawing the active segment.
pub(crate) fn dice_mode_index(mode: MnemonicMode) -> usize {
    match mode {
        MnemonicMode::Raw => 0,
        MnemonicMode::Words(n) => {
            1 + bip39::FIXED_WORD_COUNTS.iter().position(|&c| c == n.get()).unwrap_or(4)
        }
    }
}

/// Append/remove one character on whichever passphrase field has focus.
fn pass_edit(s: &mut PassState, c: Option<char>) {
    if !s.enabled {
        return;
    }
    let buf = match s.focus {
        PassFocus::Entry => &mut s.entry,
        PassFocus::Confirm => &mut s.confirm,
    };
    match c {
        Some(c) if buf.len() < PASS_MAX => buf.push(c),
        Some(_) => {}
        None => {
            buf.pop();
        }
    }
}

// ---------------------------------------------------------------------------------------
// Measuring target
// ---------------------------------------------------------------------------------------

/// A draw target that discards everything: running a screen's draw function against it
/// measures layout (content heights for scroll clamping) with the same code that paints,
/// so measurement can never drift from rendering.
pub(crate) struct NullTarget;

impl Dimensions for NullTarget {
    fn bounding_box(&self) -> Rectangle {
        Rectangle::new(Point::zero(), Size::new(1 << 15, 1 << 15))
    }
}

impl DrawTarget for NullTarget {
    type Color = Rgb565;
    type Error = Infallible;

    fn draw_iter<I>(&mut self, _pixels: I) -> Result<(), Infallible>
    where
        I: IntoIterator<Item = embedded_graphics::Pixel<Rgb565>>,
    {
        Ok(())
    }

    fn fill_solid(&mut self, _area: &Rectangle, _color: Rgb565) -> Result<(), Infallible> {
        Ok(())
    }

    fn clear(&mut self, _color: Rgb565) -> Result<(), Infallible> {
        Ok(())
    }
}
