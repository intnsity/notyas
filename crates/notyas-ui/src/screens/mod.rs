// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! One module per screen, plus the small vocabulary every screen is written in.
//!
//! # The contract a screen module satisfies
//!
//! A screen is ONE module holding ONE state type, and that type implements [`Screen`].
//! The trait is the contract: a module that satisfies it plugs into [`State`] and the
//! five dispatch functions below with one line each, and a module that does not fails to
//! compile rather than half-working. There is no `dyn Screen` anywhere and there never
//! may be - static dispatch through a CLOSED enum is what makes "exactly one screen state
//! is alive" a property the compiler and the reviewer can both check.
//!
//! ## The four entry points
//!
//! - [`Screen::layout`] receives `&self` and the read-only [`Ctx`], and returns the
//!   screen's own `Layout`: every rectangle it has, derived from [`Metrics`] and from the
//!   state that changes geometry (a mode, a revealed flag, whether a footer is present).
//!   `regions` and `draw` both consume it and neither computes geometry of its own, which
//!   is what makes "a control is drawn exactly where it can be tapped" structural instead
//!   of a habit. A component with many sub-rectangles (the keyboard, a modal) keeps the
//!   same discipline one level down: `layout` hands it an AREA, and its own geometry
//!   function is what both sides call. No absolute coordinates, ever: a panel this crate
//!   has not seen must reflow, and the two shipped geometries (720x720 and 800x480) are
//!   both gates.
//!
//! - [`Screen::regions`] receives `&self`, the [`Ctx`], and the output vector, and
//!   appends what is tappable RIGHT NOW. Order is significant: hit testing takes the
//!   first region containing the point, so a region pushed earlier wins an overlap. A
//!   region is offered only while its action is available - a screen must not paint a
//!   button it does not hit-test, and must not hit-test one it does not paint. While a
//!   modal is open a screen returns the modal's regions and nothing else, so the sheet
//!   below is as inert to a finger as it looks.
//!
//! - [`Screen::draw`] receives `&self`, a `DrawTarget` and the [`Ctx`], and paints the
//!   whole screen. It is a pure function of those two inputs: same state, same pixels.
//!   The dispatcher has already filled the panel with paper, and it may hand the screen
//!   [`crate::NullTarget`] instead of a framebuffer to MEASURE a layout with the same
//!   code that paints it, so `draw` must never be where a state change hides.
//!
//! - [`Screen::activate`] receives `&mut self`, the [`RegionId`] of a completed tap, and
//!   the narrow [`Env`], and returns an [`Outcome`]: what should happen next. A screen
//!   sees only regions its own `regions` produced, so an unreachable combination is
//!   `Outcome::stay()` by construction. `activate` never assigns the current screen - it
//!   NAMES the next one in a [`Nav`] and the `Ui` performs the single move.
//!
//! Three optional hooks carry a default that is right for a screen that needs none of
//! them: [`Screen::back`] (what the top bar's Back means here; the default is the previous
//! screen), [`Screen::scroll_mut`] / [`Screen::scroll_limit`] (a screen that scrolls owns
//! the offset and reports its content bound; the default is a screen that does not), and
//! [`Screen::answered`] (what an [`Answer`] to a request this screen raised does; the
//! default drops it, which is right for every screen that asked for nothing).
//!
//! ## What a screen may and may not do
//!
//! - **It may not touch the `Ui`.** Screens live beside [`crate::ui`], not inside it, so
//!   its fields are out of reach at the language level rather than by agreement. Every
//!   screen change in the crate is one move performed by `Ui::apply`, reached only
//!   through a returned [`Nav`], and the value moved out is dropped there. That is
//!   exactly-one-state-alive, made structural: a screen cannot clone a state (`State` is
//!   not `Clone`), cannot stash one, and cannot leave a second one behind.
//!
//! - **It may not do I/O.** This crate is no_std, reaches neither flash nor the eFuse nor
//!   a clock, and has NO RNG (SECURITY.md invariant 3) - a screen that needs a QR matrix
//!   asks for one. Work that only the std side can do is REQUESTED, by returning
//!   a [`UiRequest`] in the `Outcome`; the embedder performs it and answers through a
//!   `Ui` method, which lands in an installer on this screen's own state (see
//!   [`schemes::SchemesState::open_qr`]). The screen owns
//!   both ends of that exchange, so the rule about what a late answer does - drop it, the
//!   user has moved on - lives with the state it would have landed in.
//!
//! - **It may allocate, within two rules.** `regions` fills a caller-owned `Vec`;
//!   `layout` may allocate to MEASURE (wrapping a string is how a block learns its
//!   height); `draw` may build per-frame strings. But: (1) every heap copy of a secret is
//!   owned by a drop guard that wipes it, because `draw` can leave early through `?` on
//!   any draw error and a `String` freed unwiped is the secret still in the allocator
//!   (see the `Temps` guards in `dice`, `phrase` and `pin`); and (2) a buffer that
//!   accumulates typed secret bytes is created at full capacity with
//!   [`crate::secret_buf`], so a push can never reallocate and strand a partial secret
//!   outside the `Zeroizing` wrapper's reach.
//!
//! - **It must keep drop-equals-zeroize.** A screen's state OWNS its secrets, and leaving
//!   the screen drops the state, which wipes them. Every secret-bearing field is named in
//!   `secrets_wipe_when_a_screen_is_dropped` below against the type it actually has; that
//!   function is never called and exists only to stop compiling if a field is changed to
//!   a type whose `Drop` does not wipe - the single edit that would defeat the discipline
//!   while passing every behavioural test in the suite.
//!
//! - **It obeys the masking law** (crate docs, "Secrecy rules"): a DERIVED secret masks
//!   as a fixed bullet run whose length says nothing, typed INPUT masks one bullet per
//!   character, and no secret reaches `Debug`. The pixel tests hold the line: two
//!   different mnemonics must render byte-identical masked frames.
//!
//! ## Adding a screen
//!
//! 1. A module here, holding one state type. Secrets go in `Zeroizing` (or a self-wiping
//!    notyas-core type) and get a line in the drop-equals-zeroize check.
//! 2. `impl Screen for YourState`: the four entry points and the `Layout` type they
//!    agree on. The defaulted hooks only if the screen goes back somewhere unusual,
//!    scrolls, or raises a request - and a screen that raises one implements
//!    [`Screen::answered`] over BOTH halves of its outcome, because a failure with no arm
//!    is a panel frozen on a screen that did nothing.
//! 3. A variant in [`State`], and one line in each dispatch match plus [`State::id`].
//! 4. A [`crate::ScreenId`], and a [`RegionId`] per control (semantic identity, never a
//!    coordinate).
//! 5. A test in `tests/ui.rs` that drives it through the public API on BOTH geometries,
//!    and - if it renders a secret - a pixel test that two different secrets produce the
//!    same masked frame.

use alloc::vec::Vec;

use embedded_graphics::draw_target::DrawTarget;
use embedded_graphics::pixelcolor::Rgb565;

use crate::canvas::fill;
use crate::layout::Metrics;
use crate::theme::PAPER_1;
use crate::{
    CardOutcome, DeleteOutcome, FormatOffer, FormatOutcome, ImportOutcome, LockInfo, Press,
    PsbtOutcome, Region, RegionId,
    RegistrationInfo, RegistrationOutcome, ScreenId, SignOutcome, SignedQrOutcome,
    StorageOutcome, UiRequest,
    UnlockGate, VerifyInfo, WalletRow, WordsOutcome, WriteOutcome,
};
use notyas_core::bitcoin::Network;

pub(crate) mod deriving;
pub(crate) mod dice;
mod erase;
pub(crate) mod door;
pub(crate) mod fork;
pub(crate) mod format;
pub(crate) mod home;
pub(crate) mod lock;
pub(crate) mod mnemonic;
pub(crate) mod multisig;
pub(crate) mod name;
pub(crate) mod passphrase;
pub(crate) mod phrase;
pub(crate) mod pin;
pub(crate) mod policy;
pub(crate) mod quiz;
pub(crate) mod schemes;
pub(crate) mod setpin;
pub(crate) mod settings;
pub(crate) mod verify;
pub(crate) mod wallet;
pub(crate) mod wallets;
pub(crate) mod sdcard;
pub(crate) mod devicename;
pub(crate) mod review;
pub(crate) mod refusal;
pub(crate) mod deliver;
pub(crate) mod deliverqr;
pub(crate) mod words;

use deriving::{DerivingState, SeedSource};
use devicename::DeviceNameState;
use dice::DiceState;
use fork::ForkState;
use format::FormatCardState;
use home::HomeState;
use lock::LockState;
use erase::EraseState;
use mnemonic::MnemonicState;
use multisig::{MultisigDetailState, MultisigImportState, MultisigListState};
use name::NameState;
use passphrase::{PassState, PassUnlockState};
use phrase::PhraseState;
use pin::PinState;
use policy::PolicyState;
use quiz::QuizState;
use schemes::SchemesState;
use setpin::SetPinState;
use settings::SettingsState;
use verify::VerifyState;
use wallet::WalletState;
use wallets::WalletsState;
use sdcard::{FilePickerState, SignSourceState};
use deliver::DeliverState;
use refusal::RefusalState;
use review::ReviewState;
use words::WordsInfoState;

// ---------------------------------------------------------------------------------------
// The contract
// ---------------------------------------------------------------------------------------

/// Everything a screen may READ about the device while laying out, hit-testing and
/// painting. Assembled by the `Ui` for each call and never stored: a screen holds its own
/// state and borrows the rest for the length of one operation.
pub(crate) struct Ctx<'a> {
    pub m: Metrics,
    /// What the embedder read about the sealed store. Read-only here - the store is the
    /// std side's, and a screen changes it by asking (see [`UiRequest`]).
    pub lock: &'a LockInfo,
    pub verify: &'a VerifyInfo,
    /// The wallets the embedder read out of the store after a successful unlock.
    ///
    /// Empty until then, and that is the Q2(a) boundary made structural rather than
    /// editorial: no screen can state a count it was never given, and the only screen
    /// that is ever given one is reached by proving the PIN.
    pub wallets: &'a [WalletRow],
    /// The multisig registrations the embedder read out of the wallet that is open.
    ///
    /// Empty until one is, and emptied again by a lock, exactly like `wallets`: a
    /// registration is proven from the seed at open time, so a device with no session has
    /// none to show and must not render a list it could not prove.
    pub registrations: &'a [RegistrationInfo],
    /// The network the next derivation runs on (Home's toggle).
    pub network: Network,
    /// The press in flight and whether the last hold was released before it filled: the
    /// two inputs a C4c hold-to-confirm bar renders from. Plumbed here because a screen
    /// cannot reach the `Ui` that tracks them; read by the danger sheet's hold grade.
    pub press: Option<Press>,
    pub hold_released: bool,
    /// The passphrase retry gate, so the screen that is waiting can draw the countdown
    /// and refuse to offer a control the wait is holding.
    pub gate: &'a UnlockGate,
}

/// The device-wide state a screen may CHANGE, as distinct from the much larger set it may
/// read through [`Ctx`]. Exactly one thing qualifies today: the network is a pipeline
/// input the user picks on Home, and it outlives the screen that sets it.
///
/// Anything else a screen wants to change belongs on the std side and is asked for.
pub(crate) struct Env<'a> {
    pub network: &'a mut Network,
    /// What the embedder last read about the store, and the wallets it read out of it.
    /// READ-ONLY, and the same borrows [`Ctx`] carries rather than copies that could get
    /// out of step with it.
    ///
    /// A tap sometimes has to know the state it is changing FROM, and `activate` is not
    /// handed the `Ctx` a frame gets: stepping the wrong-PIN threshold needs the
    /// threshold, and naming what a destruction destroys needs the counts. Both live in
    /// the store, not on the screen.
    pub lock: &'a LockInfo,
    pub wallets: &'a [WalletRow],
    /// The passphrase retry gate. Device-wide state a screen may CHANGE - it outlives
    /// every screen that reads it, which is the whole reason it is not a field of one.
    pub gate: &'a mut UnlockGate,
}

/// Where the tap leaves the user.
///
/// The variants are the only screen transitions this crate has. A screen returns one; the
/// `Ui` performs it. The back stack is the difference between the two forward moves:
/// [`Nav::Push`] remembers the screen being left (Back restores it with its rolls, words
/// and passphrase intact), [`Nav::Enter`] does not.
pub(crate) enum Nav {
    /// Same screen. Its state may have changed.
    Stay,
    /// Forward, remembering this screen on the back stack.
    Push(State),
    /// Sideways or downward: replace this screen without remembering it. Leaving it drops
    /// it, which wipes whatever it held.
    Enter(State),
    /// The previous screen, or Home when the stack is empty.
    Back,
    /// Open the exit-confirmation modal over this screen. The screens that hold a derived
    /// secret use it for Back: an accidental tap must not silently discard the work.
    ConfirmExit,
}

/// What a tap did: where it leaves the user, and what it needs the std side to do.
///
/// Two independent fields rather than an enum, because a transition and a request are not
/// exclusive in principle. No screen combines them today - the shuffled PIN pad was the one
/// that did, and the pad is fixed since the 2026-08-19 reversal of Q35 - so the constructors
/// below cover one half each, and a screen that needs both again writes the struct out.
pub(crate) struct Outcome {
    pub nav: Nav,
    pub request: Option<UiRequest>,
}

impl Outcome {
    /// Nothing to do. The default answer for a region this screen does not act on.
    pub fn stay() -> Outcome {
        Outcome { nav: Nav::Stay, request: None }
    }

    /// Stay here and ask the embedder for work.
    pub fn ask(request: UiRequest) -> Outcome {
        Outcome { nav: Nav::Stay, request: Some(request) }
    }

    /// Forward, remembering this screen (see [`Nav::Push`]).
    pub fn push(next: State) -> Outcome {
        Outcome { nav: Nav::Push(next), request: None }
    }

    /// Replace this screen without remembering it (see [`Nav::Enter`]).
    pub fn enter(next: State) -> Outcome {
        Outcome { nav: Nav::Enter(next), request: None }
    }
}

/// An answer to a request this screen raised, on its way back to the screen that raised it.
///
/// The `Ui` has answer methods and a screen has `activate`, and until 0.2.0 the two were
/// joined by hand: each answer method reached into `State`, matched the one variant that
/// could have asked, and called an installer on it. That worked while three requests had
/// three answers. It does not scale to the card, the transaction and the registry, where a
/// request can be raised from either of two screens and every one of them needs BOTH a
/// success and a failure path - and the failure path is the one that got dropped, three
/// times, each time leaving a panel frozen on a screen that did nothing.
///
/// So an answer arrives the way a tap does: through the dispatcher, into the screen that is
/// showing, as ONE value it must match on. The failure is a variant of that value rather
/// than a call the embedder can forget to make, and the screen returns an [`Outcome`] - so
/// answering a request can navigate, can raise the next request, or can stay put and render
/// a band, in exactly the vocabulary a tap already has.
///
/// An answer that reaches a screen which did not ask for it is dropped by that screen's
/// default: the user has moved on, and a late answer must not move the panel back.
pub(crate) enum Answer {
    Card(CardOutcome),
    Psbt(PsbtOutcome),
    Sign(SignOutcome),
    Write(WriteOutcome),
    /// The signed transaction the std side was holding is gone. False is a refusal to
    /// destroy it, which S-38 states rather than leaving the user believing it is gone.
    Discard(bool),
    /// The signed transaction as a symbol S-39 can draw, or why it is not going on the
    /// glass. The symbol lives in the delivery screen's own state and dies with it.
    SignedQr(SignedQrOutcome),
    Import(ImportOutcome),
    /// Whether the card in the slot can be repaired by a format (S-49). Nothing has been
    /// written when this arrives.
    FormatOffer(FormatOffer),
    /// What became of a format that WAS run. The one answer in this enum that can mean the
    /// user's own data is gone.
    Formatted(FormatOutcome),
    Register(RegistrationOutcome),
    /// The registry slot was erased. False is a refusal, stated on the screen that asked.
    DeleteRegistration(bool),
    /// What became of a wallet the user consented to destroy. Never a bool: "nothing was
    /// destroyed" and "some of it was" are different sentences and the second one is the
    /// dangerous one to get wrong.
    DeleteWallet(DeleteOutcome),
    /// The stored recovery words for the wallet about to be erased, or why there are none
    /// to show. Secret-bearing - see [`WordsOutcome`].
    RecoveryWords(WordsOutcome),
    /// Whether this device now remembers the wallet's passphrase, as the record READ BACK
    /// says - or why nothing was written. Carries no passphrase and never will: the
    /// subject is what the flash holds, not what it holds.
    PassphraseStorage(StorageOutcome),
}

/// The four entry points every screen exports, plus two defaulted hooks.
///
/// Implemented BY the state type rather than by a marker beside it: the screen and the
/// data it owns are one thing, so there is no way to reach a screen's behaviour without
/// holding its state, and no way to hold its state without the behaviour coming along.
/// See the module docs for the full contract.
pub(crate) trait Screen: Sized {
    /// Every rectangle this screen has. Screen-private: no other module needs to know
    /// where this screen puts its buttons, and the geometry is free to change with the
    /// panel.
    type Layout;

    /// Compute the geometry. Pure, and the single source of truth for it.
    fn layout(&self, ctx: &Ctx) -> Self::Layout;

    /// Append what is tappable now, most-specific first (hit testing takes the first
    /// match).
    fn regions(&self, ctx: &Ctx, out: &mut Vec<Region>);

    /// Paint the screen. A pure function of `self` and `ctx`.
    fn draw<D: DrawTarget<Color = Rgb565>>(&self, t: &mut D, ctx: &Ctx)
        -> Result<(), D::Error>;

    /// Act on a completed tap on one of this screen's own regions.
    fn activate(&mut self, id: RegionId, env: &mut Env) -> Outcome;

    /// What this screen does with an [`Answer`] the embedder handed back.
    ///
    /// The default DROPS it and stays, which is right for every screen that raised no
    /// request and for every screen the user has navigated to since: a late answer belongs
    /// to a tap they have moved on from. A screen that raises a request implements this and
    /// matches the outcome, both halves of it - the success that advances, and the failure
    /// that has to say so on the panel.
    fn answered(&mut self, _answer: Answer, _env: &mut Env) -> Outcome {
        Outcome::stay()
    }

    /// What Back means here. The default is the screen the user came from; a screen
    /// holding a derived secret returns [`Nav::ConfirmExit`] instead, and a screen that
    /// is the floor of a locked device returns [`Nav::Stay`].
    ///
    /// A screen whose Back has to MOVE what it owns implements [`Screen::back_moving`]
    /// instead - this receiver cannot, and the two ways around that are both worse than
    /// the hook.
    fn back(&self) -> Nav {
        Nav::Back
    }

    /// Back, from the receiver that can MOVE.
    ///
    /// This is the one the dispatcher calls; the default forwards to [`Screen::back`],
    /// which is what a screen implements when answering Back only NAMES a destination.
    /// Override THIS one, and not that one, when answering Back means handing this
    /// screen's own state to the screen it names - the export view returning a derivation
    /// to the wallet it was lent, so that the wallet can offer Export a second time.
    ///
    /// The hook exists because `&self` leaves exactly two ways to do that, and both are
    /// defects this crate has already paid for. COPYING the value breaks the one-copy rule
    /// for key material (crate docs, "Secrecy rules"). DEFERRING the move to the next tap -
    /// the [`review::ReviewState::leaving`] pattern, which is right when Back is a QUESTION
    /// because the sheet it opens supplies that tap - turns a Back that should be one tap
    /// into two.
    ///
    /// A screen implements one or the other, never both: the `back` of a screen that
    /// overrides this is dead code, and the two would be free to disagree.
    fn back_moving(&mut self) -> Nav {
        self.back()
    }

    /// The scroll offset this screen owns, while it is scrollable. `None` opts out, which
    /// is also how a screen freezes the sheet under an open modal.
    fn scroll_mut(&mut self) -> Option<&mut i32> {
        None
    }

    /// Maximum scroll offset (0 when everything fits). Measured against the same draw
    /// code that paints, so clamping cannot drift from rendering.
    fn scroll_limit(&self, _ctx: &Ctx) -> i32 {
        0
    }
}

// ---------------------------------------------------------------------------------------
// The closed state
// ---------------------------------------------------------------------------------------

/// Which screen is alive, and its data.
///
/// CLOSED on purpose. A trait object here would buy extensibility this device does not
/// want and would cost the property the whole design rests on: with a closed enum, every
/// screen is enumerable, exactly one variant exists at a time, and dropping the value
/// wipes precisely the secrets that screen owned.
// The variants differ in size because each owns exactly its screen's data (a Report is
// large); exactly one State exists at a time, so boxing would buy indirection, not memory.
#[allow(clippy::large_enum_variant)]
pub(crate) enum State {
    Home(HomeState),
    Dice(DiceState),
    Mnemonic(MnemonicState),
    Phrase(PhraseState),
    Passphrase(PassState),
    /// S-21b. The passphrase of a wallet that already exists, asked for at open time.
    /// Distinct from `Passphrase`, which is part of MAKING one: this screen belongs to a
    /// record, has one field and an Unlock, and reports `Working` while the derivation it
    /// asked for runs.
    PassUnlock(PassUnlockState),
    Deriving(DerivingState),
    Schemes(SchemesState),
    Verify(VerifyState),
    Lock(LockState),
    Pin(PinState),
    /// S-06/S-07. The first PIN, typed twice. Distinct from `Pin` because the two spend
    /// different things: one guesses at a store that has a PIN, this one formats a store
    /// that has none.
    SetPin(SetPinState),
    Wallets(WalletsState),
    Quiz(QuizState),
    Fork(ForkState),
    Name(NameState),
    Wallet(WalletState),
    /// S-47b. The step between the typed-name consent and the write: read the recovery
    /// words once more, or erase knowing the backup is checked.
    Erase(EraseState),
    Settings(SettingsState),
    /// S-44a. The one string this device shows before a PIN is typed. Distinct from
    /// `Name`, which names a WALLET: the two accept different characters, refuse for
    /// different reasons and commit to different places.
    DeviceName(DeviceNameState),
    /// S-04a. What the anti-phishing words are and when to look at them, at the two
    /// moments a user can act on it.
    WordsInfo(WordsInfoState),
    Policy(PolicyState),
    /// S-27. The card ingress path: what is on the card, and what may be read off it.
    SignSource(SignSourceState),
    /// S-28. The picker, when auto-detect is not enough.
    FilePicker(FilePickerState),
    /// S-49. The card repair: look at a card this device cannot read, and - only where a
    /// format would repair it - offer to write an empty filesystem into the partition it
    /// already has. Opened from Settings, and the only screen in the product that can
    /// destroy something the device never held.
    FormatCard(FormatCardState),
    /// S-41. What this wallet is registered in, and the way to import more.
    MultisigList(MultisigListState),
    /// S-42. The cosigner review: every key in full, and this device's own statement
    /// that it found itself in the set.
    MultisigImport(MultisigImportState),
    /// S-43. Re-inspect, cross-check, delete.
    MultisigDetail(MultisigDetailState),
    /// S-30..S-37. ONE state for the whole paged review AND for the signing frame it
    /// commits to. A page turn is not a screen change (the `PinCreate` precedent), and
    /// S-37 is a MODE this state reports by name rather than a second value that could
    /// exist beside a review the user could still walk back into.
    Review(ReviewState),
    /// S-29. C7 as a screen rather than a modal: it needs the space, and a modal invites
    /// dismiss-without-reading.
    Refusal(RefusalState),
    /// S-38. The one screen in the product with no Back: the signed bytes exist in exactly
    /// one place and leaving without delivering them is the loss it exists to prevent.
    Deliver(DeliverState),
}

impl State {
    /// The public name of this screen. Carries no data, so it is safe to log and compare.
    pub fn id(&self) -> ScreenId {
        match self {
            State::Home(_) => ScreenId::Home,
            State::Dice(_) => ScreenId::DiceEntry,
            State::Mnemonic(_) => ScreenId::MnemonicDisplay,
            State::Phrase(_) => ScreenId::PhraseEntry,
            State::Passphrase(_) => ScreenId::PassphraseEntry,
            // Another screen that names itself, for the reason `State::Verify` does: while
            // the derivation runs it is a C3 frame with no Back and nothing tappable.
            State::PassUnlock(s) => s.id(),
            State::Deriving(_) => ScreenId::Deriving,
            State::Schemes(_) => ScreenId::Schemes,
            // The one variant that names itself: S-46 becomes a C3 Busy screen while its
            // reserved-space scan runs, and "which screen is showing" has to say so - a
            // Busy frame with nothing tappable is a different screen to an embedder and
            // to the region checks, not a mode of the sheet underneath it.
            State::Verify(s) => s.id(),
            State::Lock(_) => ScreenId::Lock,
            State::Pin(_) => ScreenId::PinEntry,
            State::SetPin(_) => ScreenId::PinCreate,
            State::Wallets(_) => ScreenId::WalletList,
            State::Quiz(_) => ScreenId::BackupCheck,
            State::Fork(_) => ScreenId::KeepOrSave,
            State::Name(_) => ScreenId::NameWallet,
            State::Wallet(_) => ScreenId::WalletHome,
            // Another screen that names itself: it becomes a C3 Busy frame while the erase
            // it announced is running, and a frame with no Back is a different screen to an
            // embedder rather than a mode of the sheet underneath it.
            State::Erase(s) => s.id(),
            State::Settings(_) => ScreenId::Settings,
            State::DeviceName(_) => ScreenId::DeviceName,
            State::WordsInfo(_) => ScreenId::AboutDeviceWords,
            State::Policy(_) => ScreenId::WipePolicy,
            // Each of the three reports `ScreenId::Working` while its own request is in
            // flight, on the `State::Verify` precedent: a C3 frame has no Back and nothing
            // tappable, so it IS a different screen to an embedder.
            // Both become C3 Busy screens while a card request is in flight, and "which
            // screen is showing" has to say so - see `State::Verify` above.
            State::SignSource(s) => s.id(),
            State::FilePicker(s) => s.id(),
            // Names itself for the same reason, with more at stake: while its format runs
            // the panel is a C3 frame with nothing tappable and a card being overwritten
            // behind it.
            State::FormatCard(s) => s.id(),
            State::MultisigList(s) => s.id(),
            State::MultisigImport(s) => s.id(),
            State::MultisigDetail(s) => s.id(),
            // Two more screens that name themselves, for the reason `Verify` does: S-37 and
            // the deliver screen's write both become C3 Busy frames with nothing tappable,
            // and a frame with no Back is a different screen to an embedder and to the
            // region checks rather than a mode of the sheet underneath it.
            State::Review(s) => s.id(),
            State::Refusal(s) => s.id(),
            State::Deliver(s) => s.id(),
        }
    }
}

// ---------------------------------------------------------------------------------------
// Dispatch: one line per screen, and nothing else
// ---------------------------------------------------------------------------------------

pub(crate) fn regions(state: &State, ctx: &Ctx) -> Vec<Region> {
    let mut out = Vec::new();
    match state {
        State::Home(s) => s.regions(ctx, &mut out),
        State::Dice(s) => s.regions(ctx, &mut out),
        State::Mnemonic(s) => s.regions(ctx, &mut out),
        State::Phrase(s) => s.regions(ctx, &mut out),
        State::Passphrase(s) => s.regions(ctx, &mut out),
        State::PassUnlock(s) => s.regions(ctx, &mut out),
        State::Deriving(s) => s.regions(ctx, &mut out),
        State::Schemes(s) => s.regions(ctx, &mut out),
        State::Verify(s) => s.regions(ctx, &mut out),
        State::Lock(s) => s.regions(ctx, &mut out),
        State::Pin(s) => s.regions(ctx, &mut out),
        State::SetPin(s) => s.regions(ctx, &mut out),
        State::Wallets(s) => s.regions(ctx, &mut out),
        State::Quiz(s) => s.regions(ctx, &mut out),
        State::Fork(s) => s.regions(ctx, &mut out),
        State::Name(s) => s.regions(ctx, &mut out),
        State::Wallet(s) => s.regions(ctx, &mut out),
        State::Erase(s) => s.regions(ctx, &mut out),
        State::Settings(s) => s.regions(ctx, &mut out),
        State::DeviceName(s) => s.regions(ctx, &mut out),
        State::WordsInfo(s) => s.regions(ctx, &mut out),
        State::Policy(s) => s.regions(ctx, &mut out),
        State::SignSource(s) => s.regions(ctx, &mut out),
        State::FilePicker(s) => s.regions(ctx, &mut out),
        State::FormatCard(s) => s.regions(ctx, &mut out),
        State::MultisigList(s) => s.regions(ctx, &mut out),
        State::MultisigImport(s) => s.regions(ctx, &mut out),
        State::MultisigDetail(s) => s.regions(ctx, &mut out),
        State::Review(s) => s.regions(ctx, &mut out),
        State::Refusal(s) => s.regions(ctx, &mut out),
        State::Deliver(s) => s.regions(ctx, &mut out),
    }
    out
}

/// Repaint the panel: paper, then the screen.
pub(crate) fn draw<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    state: &State,
    ctx: &Ctx,
) -> Result<(), D::Error> {
    fill(t, ctx.m.screen(), PAPER_1)?;
    match state {
        State::Home(s) => s.draw(t, ctx),
        State::Dice(s) => s.draw(t, ctx),
        State::Mnemonic(s) => s.draw(t, ctx),
        State::Phrase(s) => s.draw(t, ctx),
        State::Passphrase(s) => s.draw(t, ctx),
        State::PassUnlock(s) => s.draw(t, ctx),
        State::Deriving(s) => s.draw(t, ctx),
        State::Schemes(s) => s.draw(t, ctx),
        State::Verify(s) => s.draw(t, ctx),
        State::Lock(s) => s.draw(t, ctx),
        State::Pin(s) => s.draw(t, ctx),
        State::SetPin(s) => s.draw(t, ctx),
        State::Wallets(s) => s.draw(t, ctx),
        State::Quiz(s) => s.draw(t, ctx),
        State::Fork(s) => s.draw(t, ctx),
        State::Name(s) => s.draw(t, ctx),
        State::Wallet(s) => s.draw(t, ctx),
        State::Erase(s) => s.draw(t, ctx),
        State::Settings(s) => s.draw(t, ctx),
        State::DeviceName(s) => s.draw(t, ctx),
        State::WordsInfo(s) => s.draw(t, ctx),
        State::Policy(s) => s.draw(t, ctx),
        State::SignSource(s) => s.draw(t, ctx),
        State::FilePicker(s) => s.draw(t, ctx),
        State::FormatCard(s) => s.draw(t, ctx),
        State::MultisigList(s) => s.draw(t, ctx),
        State::MultisigImport(s) => s.draw(t, ctx),
        State::MultisigDetail(s) => s.draw(t, ctx),
        State::Review(s) => s.draw(t, ctx),
        State::Refusal(s) => s.draw(t, ctx),
        State::Deliver(s) => s.draw(t, ctx),
    }
}

pub(crate) fn activate(state: &mut State, id: RegionId, env: &mut Env) -> Outcome {
    match state {
        State::Home(s) => s.activate(id, env),
        State::Dice(s) => s.activate(id, env),
        State::Mnemonic(s) => s.activate(id, env),
        State::Phrase(s) => s.activate(id, env),
        State::Passphrase(s) => s.activate(id, env),
        State::PassUnlock(s) => s.activate(id, env),
        State::Deriving(s) => s.activate(id, env),
        State::Schemes(s) => s.activate(id, env),
        State::Verify(s) => s.activate(id, env),
        State::Lock(s) => s.activate(id, env),
        State::Pin(s) => s.activate(id, env),
        State::SetPin(s) => s.activate(id, env),
        State::Wallets(s) => s.activate(id, env),
        State::Quiz(s) => s.activate(id, env),
        State::Fork(s) => s.activate(id, env),
        State::Name(s) => s.activate(id, env),
        State::Wallet(s) => s.activate(id, env),
        State::Erase(s) => s.activate(id, env),
        State::Settings(s) => s.activate(id, env),
        State::DeviceName(s) => s.activate(id, env),
        State::WordsInfo(s) => s.activate(id, env),
        State::Policy(s) => s.activate(id, env),
        State::SignSource(s) => s.activate(id, env),
        State::FilePicker(s) => s.activate(id, env),
        State::FormatCard(s) => s.activate(id, env),
        State::MultisigList(s) => s.activate(id, env),
        State::MultisigImport(s) => s.activate(id, env),
        State::MultisigDetail(s) => s.activate(id, env),
        State::Review(s) => s.activate(id, env),
        State::Refusal(s) => s.activate(id, env),
        State::Deliver(s) => s.activate(id, env),
    }
}


/// Hand an [`Answer`] to the screen that is showing.
///
/// Routed exactly like [`activate`], and for the same reason: the screen that raised a
/// request is the screen that knows what its answer means, and the `Ui` performs the one
/// move that comes back. Screens that raised nothing take the trait default and drop it.
pub(crate) fn answered(state: &mut State, answer: Answer, env: &mut Env) -> Outcome {
    match state {
        State::Home(s) => s.answered(answer, env),
        State::Dice(s) => s.answered(answer, env),
        State::Mnemonic(s) => s.answered(answer, env),
        State::Phrase(s) => s.answered(answer, env),
        State::Passphrase(s) => s.answered(answer, env),
        State::PassUnlock(s) => s.answered(answer, env),
        State::Deriving(s) => s.answered(answer, env),
        State::Schemes(s) => s.answered(answer, env),
        State::Verify(s) => s.answered(answer, env),
        State::Lock(s) => s.answered(answer, env),
        State::Pin(s) => s.answered(answer, env),
        State::SetPin(s) => s.answered(answer, env),
        State::Wallets(s) => s.answered(answer, env),
        State::Quiz(s) => s.answered(answer, env),
        State::Fork(s) => s.answered(answer, env),
        State::Name(s) => s.answered(answer, env),
        State::Wallet(s) => s.answered(answer, env),
        State::Erase(s) => s.answered(answer, env),
        State::Settings(s) => s.answered(answer, env),
        State::DeviceName(s) => s.answered(answer, env),
        State::WordsInfo(s) => s.answered(answer, env),
        State::Policy(s) => s.answered(answer, env),
        State::SignSource(s) => s.answered(answer, env),
        State::FilePicker(s) => s.answered(answer, env),
        State::FormatCard(s) => s.answered(answer, env),
        State::MultisigList(s) => s.answered(answer, env),
        State::MultisigImport(s) => s.answered(answer, env),
        State::MultisigDetail(s) => s.answered(answer, env),
        State::Review(s) => s.answered(answer, env),
        State::Refusal(s) => s.answered(answer, env),
        State::Deliver(s) => s.answered(answer, env),
    }
}

/// What the top bar's Back does on the current screen. Routed separately from
/// [`activate`] so that every screen has an answer whether or not it thought about one.
///
/// `&mut` because [`Screen::back_moving`] is the hook this calls: a screen whose Back
/// hands its own state to the screen it is naming needs a receiver that can move, and
/// every screen that does not simply takes the default forwarding to [`Screen::back`].
pub(crate) fn back(state: &mut State) -> Nav {
    match state {
        State::Home(s) => s.back_moving(),
        State::Dice(s) => s.back_moving(),
        State::Mnemonic(s) => s.back_moving(),
        State::Phrase(s) => s.back_moving(),
        State::Passphrase(s) => s.back_moving(),
        State::PassUnlock(s) => s.back_moving(),
        State::Deriving(s) => s.back_moving(),
        State::Schemes(s) => s.back_moving(),
        State::Verify(s) => s.back_moving(),
        State::Lock(s) => s.back_moving(),
        State::Pin(s) => s.back_moving(),
        State::SetPin(s) => s.back_moving(),
        State::Wallets(s) => s.back_moving(),
        State::Quiz(s) => s.back_moving(),
        State::Fork(s) => s.back_moving(),
        State::Name(s) => s.back_moving(),
        State::Wallet(s) => s.back_moving(),
        State::Erase(s) => s.back_moving(),
        State::Settings(s) => s.back_moving(),
        State::DeviceName(s) => s.back_moving(),
        State::WordsInfo(s) => s.back_moving(),
        State::Policy(s) => s.back_moving(),
        State::SignSource(s) => s.back_moving(),
        State::FilePicker(s) => s.back_moving(),
        State::FormatCard(s) => s.back_moving(),
        State::MultisigList(s) => s.back_moving(),
        State::MultisigImport(s) => s.back_moving(),
        State::MultisigDetail(s) => s.back_moving(),
        State::Review(s) => s.back_moving(),
        State::Refusal(s) => s.back_moving(),
        State::Deliver(s) => s.back_moving(),
    }
}

/// Apply a vertical scroll delta, clamped to the screen's own content bound.
pub(crate) fn scroll(state: &mut State, dy: i32, ctx: &Ctx) {
    match state {
        State::Home(s) => scroll_one(s, dy, ctx),
        State::Dice(s) => scroll_one(s, dy, ctx),
        State::Mnemonic(s) => scroll_one(s, dy, ctx),
        State::Phrase(s) => scroll_one(s, dy, ctx),
        State::Passphrase(s) => scroll_one(s, dy, ctx),
        State::PassUnlock(s) => scroll_one(s, dy, ctx),
        State::Deriving(s) => scroll_one(s, dy, ctx),
        State::Schemes(s) => scroll_one(s, dy, ctx),
        State::Verify(s) => scroll_one(s, dy, ctx),
        State::Lock(s) => scroll_one(s, dy, ctx),
        State::Pin(s) => scroll_one(s, dy, ctx),
        State::SetPin(s) => scroll_one(s, dy, ctx),
        State::Wallets(s) => scroll_one(s, dy, ctx),
        State::Quiz(s) => scroll_one(s, dy, ctx),
        State::Fork(s) => scroll_one(s, dy, ctx),
        State::Name(s) => scroll_one(s, dy, ctx),
        State::Wallet(s) => scroll_one(s, dy, ctx),
        State::Erase(s) => scroll_one(s, dy, ctx),
        State::Settings(s) => scroll_one(s, dy, ctx),
        State::DeviceName(s) => scroll_one(s, dy, ctx),
        State::WordsInfo(s) => scroll_one(s, dy, ctx),
        State::Policy(s) => scroll_one(s, dy, ctx),
        State::SignSource(s) => scroll_one(s, dy, ctx),
        State::FilePicker(s) => scroll_one(s, dy, ctx),
        State::FormatCard(s) => scroll_one(s, dy, ctx),
        State::MultisigList(s) => scroll_one(s, dy, ctx),
        State::MultisigImport(s) => scroll_one(s, dy, ctx),
        State::MultisigDetail(s) => scroll_one(s, dy, ctx),
        State::Review(s) => scroll_one(s, dy, ctx),
        State::Refusal(s) => scroll_one(s, dy, ctx),
        State::Deliver(s) => scroll_one(s, dy, ctx),
    }
}

fn scroll_one<S: Screen>(s: &mut S, dy: i32, ctx: &Ctx) {
    let limit = s.scroll_limit(ctx);
    if let Some(offset) = s.scroll_mut() {
        *offset = (*offset + dy).clamp(0, limit);
    }
}

// ---------------------------------------------------------------------------------------
// drop-equals-zeroize, checked by the compiler
// ---------------------------------------------------------------------------------------

/// Types whose `Drop` wipes the bytes they hold.
///
/// Explicit impls rather than a blanket one: adding a type here is a claim about that
/// type's `Drop`, and whoever adds a screen has to make it deliberately.
pub(crate) trait WipesOnDrop {}

// `Zeroizing` wipes by construction.
impl WipesOnDrop for zeroize::Zeroizing<alloc::string::String> {}
// #[derive(ZeroizeOnDrop)] - notyas-core entropy.rs.
impl WipesOnDrop for notyas_core::entropy::DiceEntropy {}
// Hand-written Drop that zeroizes the words - notyas-core bip39.rs.
impl WipesOnDrop for notyas_core::bip39::Mnemonic {}
// Hand-written Drop that zeroizes the phrase, xprvs and WIFs - notyas-core report.rs.
impl WipesOnDrop for notyas_core::report::Report {}
// An `Option` runs the inner value's `Drop`, so it wipes exactly when its contents do.
// The one generic impl here, and it earns that: parking a secret in an `Option` is how a
// screen hands a non-`Clone` derivation forward out of a `&mut self`, and four screens do
// it. Blanket-impl-by-accident is still refused - `T` must itself be a claim someone made.
impl<T: WipesOnDrop> WipesOnDrop for Option<T> {}

/// Every secret-bearing field of every screen, named against the type it actually has.
///
/// Never called: being type-checked is its whole job. Change one of these fields to a
/// plain `String` - the single edit that would defeat drop-equals-zeroize while passing
/// every behavioural test in the suite, because a leaked secret has no pixels - and the
/// crate stops compiling here. The `SeedSource` match is exhaustive on purpose, so a new
/// way to carry seed material cannot skip the check.
#[allow(dead_code)]
// One parameter per secret-bearing screen, which is the point: the arity IS the
// inventory, and a screen missing from it is a screen nobody claimed wipes.
#[allow(clippy::too_many_arguments)]
fn secrets_wipe_when_a_screen_is_dropped(
    dice: &DiceState,
    mnemonic: &MnemonicState,
    phrase: &PhraseState,
    pass: &PassState,
    unlock: &PassUnlockState,
    deriving: &DerivingState,
    schemes: &SchemesState,
    pin: &PinState,
    setpin: &SetPinState,
    quiz: &QuizState,
    fork: &ForkState,
    name: &NameState,
    wallet: &WalletState,
) {
    fn wipes<T: WipesOnDrop>(_: &T) {}
    fn seed_wipes(source: &SeedSource) {
        match source {
            SeedSource::Dice { dice, .. } => wipes(dice),
            SeedSource::Phrase(text) => wipes(text),
        }
    }

    wipes(&dice.rolls);
    wipes(&dice.entropy);
    // Both variants of the words screen, named separately: the create path owns the dice
    // and the derived mnemonic, and the re-show path owns a phrase read back out of a
    // record. A wipe check that covered only the first would leave the newer surface -
    // which shows the words of a wallet that is about to be deleted - outside the property.
    match &mnemonic.words {
        mnemonic::Words::Fresh { dice, mnem, .. } => {
            wipes(dice);
            wipes(mnem);
        }
        mnemonic::Words::Stored { phrase } => wipes(phrase),
    }
    wipes(&phrase.text);
    seed_wipes(&pass.source);
    wipes(&pass.entry);
    wipes(&pass.confirm);
    // The one field of the unlock screen that is a secret. It is wiped on the way OUT of
    // the busy phase as well (see `PassUnlockState::refused`), which is a second wipe on
    // top of this one rather than a substitute for it.
    wipes(&unlock.entry);
    seed_wipes(&deriving.source);
    wipes(&deriving.passphrase);
    wipes(&schemes.report);
    wipes(&pin.entry);
    // Both entries of the create screen, named separately: the confirm buffer holds a
    // complete PIN for the length of one comparison, which is exactly as much of a secret
    // as the first one.
    wipes(&setpin.entry);
    wipes(&setpin.confirm);
    wipes(&quiz.report);
    // In transit from the entry screen to the save, on three screens in a row. Each one
    // is the only holder while it is alive, and each drops it on the way out.
    wipes(&quiz.passphrase);
    wipes(&fork.report);
    wipes(&fork.passphrase);
    wipes(&name.phrase);
    wipes(&name.passphrase);
    wipes(&wallet.report);
}

// ---------------------------------------------------------------------------------------
// Test fixture
// ---------------------------------------------------------------------------------------

/// What a screen's layout unit tests need: a [`Ctx`] and something to own the values it
/// borrows. Geometry tests belong beside the geometry, and every one of them has to run
/// on BOTH shipped panels, so both live here rather than being restated per module.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use crate::layout::{Rect, PANELS};

    /// The two panels these layout tests are known to hold on: Waveshare 4B and
    /// Elecrow 5inch, the first two entries of [`crate::layout::PANELS`].
    ///
    /// A SLICE of the real list, never a second list, so a panel cannot be added to the
    /// firmware and silently missed here: the assertion below pins these to the entries
    /// they claim to be. The remaining three shipped panels are gated by pixels instead -
    /// tools/uisim renders every screen on all five and refuses a frame that draws off the
    /// panel - because widening this array today fails on one assumption a layout test
    /// makes about the panel rather than on a layout defect (wallets.rs:432 requires the
    /// eight-slot list to overflow the viewport, which it does not on a 1280 px-tall
    /// panel). Widen it when that assertion is expressed per panel.
    pub(crate) const GEOMETRIES: [(u32, u32); 2] = [PANELS[0], PANELS[1]];

    /// Assert that every rectangle in `rows` sits inside `bounds` and that no two of them
    /// touch.
    ///
    /// The region checks can only see what a screen makes TAPPABLE. MEASURED TEXT - a
    /// heading, a hint, a footer line - is drawn at a rectangle no [`Region`] names, so two
    /// of them can land on each other and every other check in this suite still passes:
    /// that is precisely how S-03 drew its unlock hint 42 px through its capacity line on
    /// the 800x480 panel for a whole release. A screen whose layout owns those rectangles
    /// hands them here, and this is the one place the property is worded, so a second
    /// screen adopting it does not get to word it more weakly.
    pub(crate) fn rows_are_clear(what: &str, bounds: Rect, rows: &[(&str, Rect)]) {
        for (name, r) in rows {
            assert!(
                r.x >= bounds.x
                    && r.right() <= bounds.right()
                    && r.y >= bounds.y
                    && r.bottom() <= bounds.bottom(),
                "{what}: {name} at {r:?} escapes {bounds:?}"
            );
        }
        for (i, (an, a)) in rows.iter().enumerate() {
            for (bn, b) in &rows[i + 1..] {
                assert!(!a.overlaps(b), "{what}: {an} at {a:?} overlaps {bn} at {b:?}");
            }
        }
    }

    /// [`rows_are_clear`], plus the obligation its `bounds` parameter cannot carry: that
    /// the frame being measured against is itself ON THE PANEL.
    ///
    /// The caller chooses `bounds`, so `rows_are_clear` alone proves only that the rows
    /// agree with a rectangle the test picked - a screen whose body starts 40 px below the
    /// bottom of a short panel measures perfectly clear against its own body and is
    /// invisible on the device. Nothing catches that at the layout tier unless the panel
    /// is passed in, which is why this is the form to reach for: 0 <= x, 0 <= y,
    /// right <= m.w, bottom <= m.h, for the frame first and then, transitively, for every
    /// row in it.
    ///
    /// The pixel gate in tools/uisim is the backstop for the rectangles no layout struct
    /// names, and it is what covers screens that have not adopted this yet.
    pub(crate) fn rows_are_clear_on(m: &Metrics, what: &str, bounds: Rect, rows: &[(&str, Rect)]) {
        let panel = m.screen();
        assert!(
            bounds.x >= 0
                && bounds.y >= 0
                && bounds.right() <= panel.right()
                && bounds.bottom() <= panel.bottom(),
            "{what}: the frame {bounds:?} is not on the {}x{} panel",
            m.w,
            m.h
        );
        rows_are_clear(what, bounds, rows);
    }

    /// A fixed line fits the row it is drawn in.
    ///
    /// `text_centered` will happily centre a string wider than its rectangle and lose both
    /// ends of it, and a clipped draw destroys the evidence before it reaches any render
    /// target, so a row that is too narrow does not wrap - it crops, silently. Several
    /// screens assert this by hand; this is the one wording, so a screen adopting it does
    /// not get to word it more weakly.
    pub(crate) fn fits(what: &str, label: &str, need_px: i32, r: Rect) {
        assert!(
            need_px <= r.w,
            "{what}: {label:?} needs {need_px} px in a {} px row ({r:?})",
            r.w
        );
    }


    pub(crate) struct Fixture {
        pub m: Metrics,
        pub lock: LockInfo,
        pub verify: VerifyInfo,
        pub wallets: Vec<WalletRow>,
        pub registrations: Vec<RegistrationInfo>,
        pub network: Network,
        pub gate: UnlockGate,
    }

    impl Fixture {
        pub fn new(w: u32, h: u32) -> Fixture {
            Fixture {
                m: Metrics::new(w, h),
                lock: LockInfo::default(),
                verify: VerifyInfo::default(),
                wallets: Vec::new(),
                registrations: Vec::new(),
                network: Network::Bitcoin,
                gate: UnlockGate::default(),
            }
        }

        pub fn ctx(&self) -> Ctx<'_> {
            Ctx {
                m: self.m,
                lock: &self.lock,
                verify: &self.verify,
                wallets: &self.wallets,
                registrations: &self.registrations,
                network: self.network,
                press: None,
                hold_released: false,
                gate: &self.gate,
            }
        }
        /// The narrow half of the same fixture: what a tap may CHANGE.
        ///
        /// One constructor, so a screen test that needs to drive `activate` does not have
        /// to know which fields `Env` has today - which is what made adding one to it a
        /// twelve-file edit.
        pub fn env(&mut self) -> Env<'_> {
            Env {
                network: &mut self.network,
                lock: &self.lock,
                wallets: &self.wallets,
                gate: &mut self.gate,
            }
        }
    }
    #[cfg(test)]
    mod self_tests {
        use super::*;

        /// The instrument itself: a frame off the panel is refused, which is the whole
        /// difference between [`rows_are_clear_on`] and [`rows_are_clear`].
        #[test]
        #[should_panic(expected = "is not on the 800x480 panel")]
        fn a_frame_off_the_panel_is_refused() {
            let m = Metrics::new(800, 480);
            let off = Rect::new(0, 400, 800, 200);
            rows_are_clear_on(&m, "self test", off, &[("row", Rect::new(0, 400, 800, 100))]);
        }

        /// ...and a frame on it is not, so the check cannot pass by refusing everything.
        #[test]
        fn a_frame_on_the_panel_is_accepted() {
            let m = Metrics::new(800, 480);
            rows_are_clear_on(
                &m,
                "self test",
                Rect::new(0, 0, 800, 480),
                &[("a", Rect::new(0, 0, 800, 100)), ("b", Rect::new(0, 200, 800, 100))],
            );
            fits("self test", "a line", 100, Rect::new(0, 0, 200, 40));
        }

        #[test]
        #[should_panic(expected = "needs 300 px in a 200 px row")]
        fn a_line_wider_than_its_row_is_refused() {
            fits("self test", "a line", 300, Rect::new(0, 0, 200, 40));
        }

        /// The two panels this module measures against are the first two of the real
        /// list, not a copy of them.
        #[test]
        fn the_geometries_are_a_slice_of_the_shipped_panels() {
            assert_eq!(GEOMETRIES[..], PANELS[..2]);
        }
    }
}
