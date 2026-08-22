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
//! # Module map
//!
//! - `ui` - the [`Ui`] itself: the embedder's interface, the touch bookkeeping, and the
//!   ONE owner of the live screen state.
//! - `screens` - one module per screen, and the contract they satisfy. Read
//!   `screens/mod.rs` first when adding a screen: it states what layout/regions/draw/
//!   activate receive and return, where a screen may allocate, and how it asks the std
//!   side for work instead of doing I/O.
//! - `components` - the widgets more than one screen draws (top bar, modal, keyboard,
//!   rows, write notice).
//! - `danger` - the C4 danger sheet: one component, three grades (confirm, hold,
//!   typed-name), and the one visual grammar every destructive action in the product is
//!   asked for through. A screen embeds one and forwards regions/draw/activate.
//! - `guess` - the exhaustive-search arithmetic the wipe-policy screen states at the
//!   moment the wipe is turned off: keyspace, measured per-guess cost, resulting time.
//!   Pure integer math with no drawing in it, so the numbers can be checked against the
//!   table the decision was made on rather than read off a screenshot.
//! - [`canvas`] - the drawing vocabulary; [`theme`] - the Butter Paper palette and the
//!   masking constants; [`layout`] - [`layout::Metrics`], [`layout::Rect`] and the
//!   physical touch floors; [`qr`] - the precomputed-symbol container.
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
//!   screen is left: the screen state owns the secrets, the secrets' types wipe on drop
//!   ([`zeroize`], plus the self-wiping types of notyas-core), and leaving a screen drops
//!   the state. `screens` checks that field by field at compile time.
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
mod components;
mod danger;
mod guess;
pub mod layout;
pub mod qr;
mod screens;
pub mod theme;
mod ui;

use alloc::string::String;
use alloc::vec::Vec;
use core::convert::Infallible;
use core::fmt;

use embedded_graphics::draw_target::DrawTarget;
use embedded_graphics::geometry::{Dimensions, Point, Size};
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::primitives::Rectangle;
use zeroize::Zeroizing;

use layout::Rect;
pub use qr::QrData;
pub use ui::Ui;
// `bitcoin` through the core's re-export: the UI names the pipeline's own exact pin
// (it only needs `Network::Bitcoin`), never a second dependency that could drift.
use notyas_core::bitcoin;
/// The pipeline's own `Network`, re-exported because [`WalletInfo`] carries one and an
/// embedder that cannot name the type cannot build the struct. One pin, one name: this is
/// the same `bitcoin` the core derives with, never a second copy of the crate.
pub use notyas_core::bitcoin::Network;
/// The pipeline's finished derivation, re-exported for the same reason `Network` is: an
/// embedder that unseals a stored wallet hands the keys over through
/// [`Ui::wallet_opened_with_keys`], and a caller that cannot name the type cannot make
/// the call. Nothing in this crate builds one from outside a screen - the UI holds a
/// `Report` only while the screen that owns it is alive, and dropping that screen wipes it.
pub use notyas_core::report::Report;
/// The pipeline's PSBT facts, re-exported for the reason [`Report`] is: the review screens
/// render what the engine established, and an embedder that cannot name these types cannot
/// build the [`TxReview`] that carries them. One pipeline, many renderers - the same
/// discipline `report.rs` has kept since 0.1.0, applied to the transaction path.
pub use notyas_core::psbt::{
    AmountProof, Claim, ClaimedKey, InputFacts, MultisigBinding, OutputFacts, OutputRole, Owner,
    ScriptKind,
};
/// Bitcoin's own amount and lock time, through the core's pin like [`Network`]. The review
/// pages render both and format neither anywhere else.
pub use notyas_core::bitcoin::absolute::LockTime;
pub use notyas_core::bitcoin::Amount;

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
pub(crate) const PHRASE_MAX: usize = 1024;
/// Public because it is not only this crate's: a passphrase the owner asks the device to
/// remember is stored in the sealed wallet record, and the record format caps it at the
/// same number (`firmware/src/wallet/record.rs`, `MAX_PASSPHRASE_BYTES`). The firmware's
/// host cover asserts the two are equal, so a change here that is not made there fails a
/// test rather than a save.
pub const PASS_MAX: usize = 256;
/// PIN length cap in bytes, matching `notyas_wallet::Pin::MAX_BYTES` (ratified Q5). At
/// the cap further keys are ignored and the hint says so, rather than a `Pin` the
/// sealing layer would refuse after the user finished typing it.
pub(crate) const PIN_MAX: usize = 64;
/// The PIN pad: slot index in reading order -> the digit printed on it. Phone order, which
/// with the tenth slot centred on the last row draws 1-2-3 / 4-5-6 / 7-8-9 over a 0.
///
/// A CONSTANT, and that is the 2026-08-19 reversal of Q35: the per-attempt shuffle C10
/// specified derived the permutation from the device-bound ladder, and the owner overturned
/// it after using it on hardware - accepting, in writing, that fixed positions mean one
/// clear look at the hand yields the PIN, in exchange for the layout every telephone and
/// cash machine has already taught.
///
/// It lives in the crate root because BOTH PIN pads must print the same digit on the same
/// slot: a device whose create screen and unlock screen disagreed about where the 7 is would
/// have taught the user one layout and then asked for the PIN on another.
pub(crate) const PIN_PAD: [u8; 10] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0];
/// Digits that must be typed before the anti-phishing words are offered. Coldcard's
/// half-PIN pattern: enough prefix that the words are specific to this user, short
/// enough that they arrive before the PIN is complete.
pub(crate) const PIN_WORDS_AT: usize = 4;
/// The PIN floor this crate assumes about a device whose embedder has not stated one.
///
/// The floor belongs to the STORE, not to this crate: `notyas_wallet` writes
/// `min_pin_len` into the format header and refuses anything shorter, and only the device
/// knows what its own format was written with. So this is a fallback for
/// [`LockInfo::default`] and nothing else - the live value arrives through
/// [`LockInfo::min_pin_len`].
///
/// It is the ratified floor (PIN-MODES.md, decided 2026-08-17: "The 4-digit floor applies
/// in every state"), which is also `WalletConfig`'s default. The invariant that matters is
/// the direction: this must never sit ABOVE the smallest floor the store will format at.
/// A UI floor above the store's is a PIN the owner set and the panel refuses to submit,
/// which is a provisioned device nobody can unlock.
pub(crate) const PIN_MIN_DEFAULT: u8 = 4;

/// The PIN floor in force on THIS device, as a length a screen can actually reach.
///
/// The number is the store's ([`LockInfo::min_pin_len`]); the clamp is this crate's, and
/// it is here because both ends of the range are states no device should be able to put a
/// user in. A floor of zero would make the empty entry committable - an unlock attempt
/// spent on nothing, or worse, a store formatted under no PIN at all; a floor above
/// [`PIN_MAX`] would make the commit button permanently dead, which is the defect
/// `PIN_MIN_DEFAULT` replaced, reached from the other side. Clamped rather than refused
/// because a device carrying an odd policy byte still has to be usable by its owner.
///
/// ONE reader for one number, and that is the point of it living here rather than beside a
/// screen: the surface that CREATES a PIN and the surface that ENTERS one must gate on the
/// same length, or the device accepts a PIN at creation that it will not let the owner
/// type back - the same class of defect as a UI floor above the store's, arrived at from
/// inside the crate instead of from the spec.
pub(crate) fn pin_floor(lock: &LockInfo) -> usize {
    usize::from(lock.min_pin_len).clamp(1, PIN_MAX)
}
/// Characters a wallet name may hold (UX-SCREENS.md S-20).
pub(crate) const NAME_MAX: usize = 24;

/// Smallest and largest wrong-PIN thresholds the sealed store accepts while the wipe is
/// enabled. Frozen FORMAT constants mirrored from `notyas_wallet::config`: the attempt
/// log's tail reserve is sized to the ceiling, so these are not preferences and the
/// policy editor must not offer a value outside them. This crate is no_std and cannot
/// depend on the wallet crate, so the two copies are checked against each other in the
/// firmware, which links both.
pub const WIPE_AFTER_MIN: u8 = 3;
pub const WIPE_AFTER_MAX: u8 = 25;
/// The threshold a device erases at unless the owner has changed it (ratified Q5), and
/// the value the policy editor restores when the wipe is turned back on from off.
pub const WIPE_AFTER_DEFAULT: u8 = 15;

/// The shortest PIN that may DISABLE the wipe, or `None` for no floor at all.
///
/// `None` is the owner's answer to Q62, reconfirmed with the arithmetic in front of it:
/// the device STATES the trade at the moment of the change and does not withhold the
/// setting. It is a constant rather than a hardcoded absence so that revisiting the
/// decision is an edit here and nothing else - `guess::floor_blocks` takes the floor as
/// an argument and its unit tests exercise it both ways, so the refusal path is live code
/// a changed constant switches on rather than code that would have to be written first.
pub const WIPE_DISABLE_MIN_PIN: Option<u8> = None;

/// One unlock attempt on the bench boards, in milliseconds: the pinned Argon2id
/// parameters (m = 16 MiB, t = 1, p = 1) at 1827 ms on the Waveshare and 1825 ms on the
/// Elecrow, plus 82.5 ms to zeroize the working set (MEASUREMENTS.md m1).
///
/// A measurement, not a target. It is the default [`LockInfo::unlock_ms`] so that a
/// screen computing an exhaustive-search time has a real number rather than a zero; an
/// embedder that has timed its own board installs that instead.
pub const UNLOCK_MS_M1: u32 = 1910;

/// How many wallets this device can ever hold - the STATIC MAXIMUM, and the only
/// occupancy number any pre-PIN surface may state (ratified Q2(a)).
///
/// A constant is not a leak: it is the same on every unit, so a coercer holding a locked
/// device learns nothing from it. The COUNT IN USE is a different value entirely and
/// appears on exactly one surface, the post-unlock wallet list, where the holder has
/// already proved the PIN. Storage geometry: ESP-SEAL.md 3.2, eight payload slot pairs.
pub const WALLET_SLOTS: u8 = 8;

/// A self-wiping string that will never reallocate below `cap` bytes (+3 slack for the
/// widest UTF-8 char a guard of `len() < cap` can still admit).
pub(crate) fn secret_buf(cap: usize) -> Zeroizing<String> {
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
    /// S-21b. The passphrase of a STORED wallet, asked for at open time.
    ///
    /// Its own id and not a mode of [`ScreenId::PassphraseEntry`]: that screen is part of
    /// creating a wallet and has an opt-in toggle, two fields and a Continue; this one
    /// belongs to a record that already exists, has one field and an Unlock, and its Back
    /// goes to the wallet list. They also differ in what a mistake costs - a typo here is
    /// caught by the fingerprint in the record, which is why there is no confirm field.
    PassphraseUnlock,
    /// Interstitial while the seed/derivation pipeline runs (see [`Ui::tick`]). No
    /// tappable regions: the compute is synchronous and cannot be cancelled.
    Deriving,
    Schemes,
    Receive,
    VerifyDevice,
    /// The C3 Busy frame S-46 shows while the reserved-space scan runs (ratified Q57).
    /// A distinct id rather than a flag on `VerifyDevice`, because what is on the panel
    /// while it runs is a Busy screen: no Back, nothing tappable, and an embedder that
    /// knows the difference can say so.
    ScanningFlash,
    /// S-03. The device says which device it is, before the user gives it a PIN.
    /// Reachable only with a PIN set - see [`Ui::lock`].
    Lock,
    /// S-04. PIN entry on the fixed phone-order pad, with the anti-phishing words.
    PinEntry,
    /// S-06 / S-07. Choose a PIN and type it again: the only surface in the product that
    /// can put a PIN on a device that has none, and therefore the only route to a store
    /// that stores anything.
    ///
    /// ONE id for the two spec screens, which is the test [`ScreenId::ScanningFlash`] had
    /// to pass and this does not: that variant exists because a Busy frame has no Back and
    /// nothing tappable, so it IS a different screen to an embedder. S-07 is S-06 with a
    /// different heading line and a different button label - same bar, same pad, same
    /// rectangles, same Back - so splitting it would report a step counter as a screen
    /// change.
    PinCreate,
    /// S-10. The device's real home once anything is stored. Post-PIN, and the only
    /// surface in the product that states how many wallets exist (Q2(a)).
    WalletList,
    /// S-17. The mandatory backup check: every word, five candidates.
    BackupCheck,
    /// S-19. The save-or-keep-nothing fork - the product's central choice.
    KeepOrSave,
    /// S-20. Name the wallet, announce the flash write, seal it.
    NameWallet,
    /// S-21. The per-wallet hub: identity first, then what can be done with it.
    WalletHome,
    /// S-47b. The last moment a stored wallet's recovery words exist on this device: the
    /// offer to read them once more, or to erase knowing the backup is already checked.
    ///
    /// Its own screen and not a fourth danger sheet, because consent has already been
    /// given - the C4b consequence was read and the wallet's own name was typed back - and
    /// what is on the panel now is an OFFER between two legitimate answers. It also reports
    /// [`ScreenId::Working`] while the erase runs.
    EraseWallet,
    /// S-44. Device settings. Reachable only with a session open, because every row it
    /// carries today configures stored wallets.
    Settings,
    /// S-44a. The device name: the one string this device shows before a PIN is typed.
    ///
    /// Its own id rather than a mode of [`ScreenId::Settings`], on the
    /// [`ScreenId::FormatCard`] reasoning: a different bar, a keyboard, and a Back that
    /// returns to the list. It is also the surface an embedder most needs to recognise,
    /// because it is the only one whose commit writes a string that is later shown to
    /// someone who has not authenticated.
    DeviceName,
    /// S-04a. What the anti-phishing words are, and when to look at them.
    ///
    /// Shown at the two moments the user can act on it - the PIN has just been set, and
    /// the words are about to be shown for the first time - and never again. It is an
    /// explainer with one button, so it reports its own id rather than borrowing the
    /// screen underneath: an embedder logging screens should be able to see that the
    /// panel stopped being PIN entry.
    AboutDeviceWords,
    /// S-44's wrong-PIN policy sub-screen: a live editor over the sealed policy, and the
    /// surface the wipe-off trade and the PIN-removal entry point live on.
    ///
    /// (The card-format screen is `FormatCard`, below, with the card screens it belongs
    /// beside rather than here with the settings screen it is opened from.)
    WipePolicy,

    // --- 0.2.0: the card, the transaction and the registry (UX-SCREENS.md 2.4, 2.5) ---
    /// S-27. Get an unsigned transaction into the device, and say plainly why the card is
    /// the only way in.
    SignSource,
    /// S-28. The card's files, when auto-detect is not enough.
    FilePicker,
    /// S-49. The one destructive thing this device does to a card: look at a card it
    /// cannot read, say what is on it, and - only where a format would repair the fault -
    /// offer to write an empty filesystem into the partition that is already there.
    ///
    /// Its own id rather than a mode of [`ScreenId::Settings`], because it is a different
    /// screen in every sense an embedder cares about: a different bar, a different back,
    /// and the only surface in the product outside S-38 whose whole subject is a write to
    /// something the device does not own.
    FormatCard,
    /// The C3 Busy frame, whenever a screen has asked the std side for work that blocks
    /// the input loop: reading a card, checking a transaction, writing a file, sealing a
    /// registration.
    ///
    /// ONE id for every one of them, and that is the difference from
    /// [`ScreenId::ScanningFlash`], which was minted before there was a second blocking
    /// request. An id earns its place when it tells a reader something they do not already
    /// have; here the embedder is, by construction, part-way through answering the request
    /// that raised the frame, so it already knows which operation is running and the id
    /// would only repeat it. What the id DOES say is the thing no other screen says: there
    /// is no Back, nothing is tappable, and the panel will not move until an answer lands.
    /// The heading on the frame names the operation to the user.
    Working,
    /// S-29 (C7). The signing pipeline will not proceed, and says which check refused, why
    /// it matters and what to do. A screen and never a modal: a modal invites
    /// dismiss-without-reading.
    Refusal,
    /// S-30..S-36. The paged review, and the hold that ends it.
    ///
    /// ONE id for the seven spec screens, on the [`ScreenId::PinCreate`] reasoning: C5 is
    /// one screen with a pager - same bar, same `[ i / n ]`, same Prev/Next rectangles -
    /// and the page is state. Reporting a page turn as a screen change would make every
    /// instrument that logs screens report a transaction review as nine screens.
    ReviewTransaction,
    /// S-37. The signature itself: a C3 frame with a determinate meter, and the one
    /// blocking operation the ratified inventory names as a screen of its own.
    ///
    /// Distinct from [`ScreenId::Working`] because it is the only frame during which a
    /// seed is live and the only one nothing may cancel, and a device that cannot say
    /// "the panel was here" cannot answer what a power cut interrupted.
    Signing,
    /// S-38. Two independent exits, so no flow ends with a signed transaction stranded in
    /// RAM. No Back by construction.
    Deliver,
    /// S-41. What this wallet is registered in, and the way to import more.
    MultisigList,
    /// S-42. The cosigner review: every key in full, and the device's own statement that
    /// it found itself in the set.
    MultisigImport,
    /// S-43. Re-inspect, cross-check, delete.
    MultisigDetail,
}

impl ScreenId {
    /// Every screen, once. The list a host instrument iterates when it has to prove it
    /// covered all of them.
    ///
    /// Written out rather than derived because there is no derive that would be checked:
    /// the unit test below maps every variant to its index through an exhaustive `match`,
    /// so a new variant breaks compilation twice - at the array length and at the match -
    /// and cannot be added without saying where it belongs.
    pub const ALL: [ScreenId; 35] = [
        ScreenId::Home,
        ScreenId::DiceEntry,
        ScreenId::MnemonicDisplay,
        ScreenId::PhraseEntry,
        ScreenId::PassphraseEntry,
        ScreenId::Deriving,
        ScreenId::Schemes,
        ScreenId::VerifyDevice,
        ScreenId::ScanningFlash,
        ScreenId::Lock,
        ScreenId::PinEntry,
        ScreenId::PinCreate,
        ScreenId::WalletList,
        ScreenId::BackupCheck,
        ScreenId::KeepOrSave,
        ScreenId::NameWallet,
        ScreenId::WalletHome,
        ScreenId::EraseWallet,
        ScreenId::Settings,
        ScreenId::DeviceName,
        ScreenId::AboutDeviceWords,
        ScreenId::WipePolicy,
        ScreenId::SignSource,
        ScreenId::FilePicker,
        ScreenId::Working,
        ScreenId::Refusal,
        ScreenId::ReviewTransaction,
        ScreenId::Signing,
        ScreenId::Deliver,
        ScreenId::MultisigList,
        ScreenId::MultisigImport,
        ScreenId::MultisigDetail,
        ScreenId::FormatCard,
        ScreenId::PassphraseUnlock,
        ScreenId::Receive,
    ];
}

#[cfg(test)]
mod screen_id_tests {
    use super::ScreenId;

    /// `ALL` holds every variant exactly once, in the order the match below names.
    #[test]
    fn every_screen_is_in_all_exactly_once() {
        let index = |s: ScreenId| match s {
            ScreenId::Home => 0,
            ScreenId::DiceEntry => 1,
            ScreenId::MnemonicDisplay => 2,
            ScreenId::PhraseEntry => 3,
            ScreenId::PassphraseEntry => 4,
            ScreenId::Deriving => 5,
            ScreenId::Schemes => 6,
            ScreenId::VerifyDevice => 7,
            ScreenId::ScanningFlash => 8,
            ScreenId::Lock => 9,
            ScreenId::PinEntry => 10,
            ScreenId::PinCreate => 11,
            ScreenId::WalletList => 12,
            ScreenId::BackupCheck => 13,
            ScreenId::KeepOrSave => 14,
            ScreenId::NameWallet => 15,
            ScreenId::WalletHome => 16,
            ScreenId::EraseWallet => 17,
            ScreenId::Settings => 18,
            ScreenId::DeviceName => 19,
            ScreenId::AboutDeviceWords => 20,
            ScreenId::WipePolicy => 21,
            ScreenId::SignSource => 22,
            ScreenId::FilePicker => 23,
            ScreenId::Working => 24,
            ScreenId::Refusal => 25,
            ScreenId::ReviewTransaction => 26,
            ScreenId::Signing => 27,
            ScreenId::Deliver => 28,
            ScreenId::MultisigList => 29,
            ScreenId::MultisigImport => 30,
            ScreenId::MultisigDetail => 31,
            ScreenId::FormatCard => 32,
            ScreenId::PassphraseUnlock => 33,
            ScreenId::Receive => 34,
        };
        for (i, s) in ScreenId::ALL.into_iter().enumerate() {
            assert_eq!(index(s), i, "{s:?} is at the wrong index of ScreenId::ALL");
        }
    }
}

/// Semantic identity of a tappable region. What a tap MEANS, decoupled from where the
/// rectangle happens to be on this panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionId {
    /// Top-bar back. What it DOES is each screen's own answer (`Screen::back`): the
    /// previous screen for an input-only one, a confirmation gate where a derived secret
    /// is in memory, nothing at all on the floor of a locked device.
    Back,
    HomeNewSeed,
    HomeVerifySeed,
    HomeVerifyDevice,
    /// Dice keypad digit, 1..=6.
    Digit(u8),
    DiceBackspace,
    /// Dice mode segment, indexing the desktop mode set: RAW, then
    /// `bip39::FIXED_WORD_COUNTS` (12/15/18/21/24).
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
    /// Open the wallet the unlock screen is asking for, with the passphrase typed into it.
    /// Raises [`UiRequest::UnlockWallet`]. Drawn disabled - and not emitted at all - while
    /// the retry gate is holding, so a tap during the wait does nothing.
    PassUnlock,
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
    /// Scheme tab, indexing [`notyas_core::derive::Scheme::ALL`].
    Tab(u8),
    /// QR button beside the account xpub on the schemes screen.
    QrXpub,
    /// QR button beside the SLIP-132 rendering (BIP49/84 mainnet only).
    QrSlip132,
    /// QR button beside the origin-carrying BIP-380 descriptor
    /// (`wpkh([fingerprint/path]xpub.../<0;1>/*)`, UX-SCREENS.md S-26), offered beside
    /// `QrXpub` rather than instead of it: the descriptor is the form a coordinator needs
    /// to learn this wallet's root fingerprint (BlueWallet's importer among them), and the
    /// bare xpub some coordinators still ask for carries none. Absent for BIP48
    /// (multisig) - see `export::descriptor`'s doc comment for why.
    QrDescriptor,
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

    // --- 0.2.0: lock, PIN and the session (UX-SCREENS.md 4) --------------------------
    /// The lock screen's body: touch anywhere to reach PIN entry.
    LockWake,
    /// PIN pad position `n` (0-based, reading order). The POSITION, not the digit: hit
    /// testing must never depend on what is printed on a key, so the region vocabulary
    /// stays the same whatever the pad prints. Every device prints [`PIN_PAD`] on it
    /// since the 2026-08-19 reversal of Q35, and this indexing outlives that decision.
    PinKey(u8),
    PinBackspace,
    /// Switch between the digit pad and the alphanumeric keyboard. Declared
    /// here because the region vocabulary is frozen with the screen spec, and NOT emitted
    /// by m4a's minimal S-04: an alphanumeric PIN needs the C9 keyboard, which is m4b's
    /// graft, and a drawn key that no screen hit-tests is a button that lies.
    PinAlpha,
    /// "Show device words": derives the anti-phishing words for the digits typed so far.
    /// Costs no attempt-counter decrement (ARCHITECTURE.md 3).
    PinShowWords,
    PinSubmit,
    /// S-06's commit: the PIN typed so far is accepted as the FIRST entry, and the screen
    /// asks for it a second time. Nothing has been written to the device yet.
    PinNext,
    /// S-07's commit: the second entry is compared with the first, and a match is what
    /// raises [`UiRequest::SetPin`]. Distinct from [`RegionId::PinSubmit`] because the two
    /// spend different things - `PinSubmit` spends an attempt against a store that already
    /// has a PIN, this one formats a store that has none - and a region vocabulary that
    /// blurred them would let a mis-wired screen turn one into the other.
    PinConfirm,
    /// Drop the open session now. Offered only while one is open.
    Lock,
    /// C4c hold-to-confirm. Fires from [`Ui::tick`] once the fill completes, not from a
    /// tap; released early it fires nothing.
    HoldConfirm,
    /// "Mark as seen": writes the boot-counter acknowledgement mark (VERIFY.md 6.3).
    /// Post-PIN only - a coercer who can press it erases the gap the counter shows.
    VerifyAckBoots,
    /// "Scan": run the reserved-space scan now (VERIFY.md 3.3, ratified Q57). Always
    /// offered, and re-runs when it has already been run - the spans move with the
    /// build, so a second look is a different measurement rather than a cached one.
    VerifyScanFlash,
    /// "Show as QR": hand the whole `notyas-verify/1` readout to the C11 QrPlayer
    /// (VERIFY.md 7.2). Declared here because Q54 ratified the region vocabulary with
    /// the screen spec, and NOT emitted by S-46 yet: C11's player is the schemes
    /// screen's private modal, and a drawn button no screen hit-tests is a button that
    /// lies - the same rule that keeps `PinAlpha` declared and unemitted.
    VerifyQr,
    /// Step one viewport back / forward through a long review sheet (C6's explicit
    /// pager, reused verbatim by S-46 rather than inventing a second scroll model).
    /// Offered only where there is a viewport to step to.
    ReviewPrev,
    ReviewNext,
    /// "Save to this device": the storing half of the S-19 fork.
    SaveToDevice,

    // --- 0.2.0-m4b: wallet management (UX-SCREENS.md 4) ------------------------------
    /// A wallet row, carrying the storage SLOT the embedder reported for it rather than
    /// the row's position. Position is a rendering fact that changes with scrolling and
    /// with a re-ordered list; the slot is what the tap MEANS, and carrying it is what
    /// lets `activate` name the wallet without reading the list back.
    ListRow(u8),
    /// "New wallet" - start the dice flow from the wallet list.
    WalletNew,
    /// "Restore from words" - start the word-entry flow from the wallet list.
    WalletRestore,
    /// Backup-check candidate `n` (0-based, reading order). The DIGIT-pad reasoning
    /// applies: the position is hit-tested, the word on it is derived, so a candidate can
    /// never resolve to a different word than the one under the finger.
    QuizChoice(u8),
    /// "Use once, keep nothing": the stateless half of the S-19 fork. Equal weight with
    /// [`RegionId::SaveToDevice`] by construction - see the fork screen.
    UseOnce,
    /// Focus the wallet-name field (S-20).
    NameField,
    /// "Save wallet": commit the sealed write announced by the C12 notice above it.
    ConfirmSave,
    /// The one-time acknowledgement that the passphrase is not stored (Q22). Gates the
    /// first save of a passphrase wallet, so the warning cannot be skipped by habit.
    PassNotStoredAck,
    /// Remember passphrase on this device (offered on the save screen alongside
    /// the not-stored acknowledgement).
    RememberPassphraseAck,
    /// "Export public keys" on the wallet home.
    ActExport,
    ActReceive,
    NextAddr,
    /// "Remember passphrase on this device" / "Forget the passphrase" on the wallet home
    /// of an open passphrase wallet. ONE region for the two directions, because it is one
    /// row whose state decides which sheet opens - a second region could be drawn in the
    /// state the first one is in.
    ActPassphraseStore,
    /// "Derive a passphrase wallet from these words" on the wallet home of an open wallet
    /// with no passphrase. Creates a SECOND wallet; it changes nothing about this one.
    ActPassphraseDerive,
    /// "Delete this wallet" on the wallet home: opens the C4d typed-name sheet.
    WalletDelete,
    /// S-47b's two answers, offered together after the typed-name consent and before the
    /// write.
    ///
    /// Named for what each DOES and not for which is the way on: they are the same size, in
    /// the same row, and neither is the sheet's "confirm". `EraseShowWords` raises
    /// [`UiRequest::RecoveryWords`] and comes back to this screen with the choice still
    /// open - reading the words is not consent to anything - while `EraseNow` raises
    /// [`UiRequest::DeleteWallet`].
    EraseShowWords,
    EraseNow,
    /// The C4 danger sheet's two answers. Every grade offers Cancel; the Confirm and
    /// typed-name grades offer this confirm, the hold grade offers
    /// [`RegionId::HoldConfirm`] instead.
    DangerCancel,
    DangerConfirm,
    /// The C4 danger sheet's THIRD way out, offered by the sheets that have one: the
    /// action that removes the reason for the warning rather than accepting or dismissing
    /// it (PIN-MODES.md's longer-PIN path).
    DangerAlternative,
    /// The full candidate list behind the restore screen's final-word strip, opened when
    /// more valid last words exist than the four chips can show, and closed again.
    SuggestMore,
    SuggestClose,
    /// The Settings affordance, on the screen a session lives on (S-10). Not on Home:
    /// an unlocked device lands on the wallet list and never leaves it, so a chip there
    /// would be one no finger could reach.
    OpenSettings,
    /// Settings list row `n` (0-based), indexing the rows the screen is CURRENTLY
    /// showing rather than a fixed catalogue, so a row that is absent cannot be reached
    /// by index.
    SetRow(u8),
    /// Turn the wrong-PIN wipe on, or open the sheet that turns it off.
    PolicyWipe,
    /// Step the wrong-PIN threshold within [`WIPE_AFTER_MIN`]..=[`WIPE_AFTER_MAX`].
    PolicyLess,
    PolicyMore,
    /// Commit the edited policy. A button rather than a live write, because committing
    /// re-seals the store (PIN-MODES.md) and a stepper that did that per tap would spend
    /// a flash erase and an Argon2id stretch on every digit.
    PolicySave,
    /// "Remove PIN and stored wallets": opens the C4d sheet for the revert-to-stateless
    /// operation (Q5.5).
    RemoveThePin,
    /// Focus the device-name field (S-44a), raising the keyboard. Distinct from
    /// [`RegionId::NameField`], which names a WALLET: the two screens accept different
    /// characters, refuse for different reasons and write to different places, and one id
    /// for both would let a mis-wired screen route a device name into a wallet record.
    DeviceNameField,
    /// Commit the typed device name, raising [`UiRequest::SetDeviceName`]. Offered only
    /// while the typed name is acceptable - see `screens/devicename.rs`.
    DeviceNameSave,
    /// Dismiss the anti-phishing explainer (S-04a). One region, because the screen has one
    /// answer: it is read once and then never asked for again.
    WordsUnderstood,

    // --- 0.2.0: the card, the transaction and the registry (UX-SCREENS.md 2.4, 2.5) ---
    /// S-21's two remaining action cards, which exist now that the screens behind them
    /// do. Named for the ACTION and not for the screen, like [`RegionId::ActExport`]:
    /// what the tap means is "sign something with this wallet", and which screen answers
    /// that is the wallet home's to decide.
    ActSign,
    ActMultisig,
    /// S-27's auto-detected file card. Tapping it loads that file, so the card is the
    /// primary action and not decoration.
    SignReady,
    /// S-27 -> S-28: choose a different file.
    SignPickFile,
    /// "Check again": re-read the card. S-28's own region name, and the one every other
    /// surface that can be looking at a card which is not there uses too - S-27's empty
    /// state and S-38's write band - because it is the same affordance with the same
    /// label, "insert the card and try again" is the whole remedy for R-23, and a user who
    /// has to navigate away to reach it will power-cycle instead.
    FileRefresh,
    /// "Show all files": S-28 with the PSBT filter off, so a mis-extensioned file is
    /// findable. On S-27's no-PSBT state and on S-28's tab row alike.
    FileShowAll,
    /// The picker's explicit pager (C2: drag alone is undiscoverable with no scrollbar).
    /// Offered only when the listing exceeds two viewports.
    ListPagePrev,
    ListPageNext,
    /// C7's "Show details": toggles the mono block a bug report gets photographed from.
    /// It never contains key material - a refusal is decided before any key exists.
    RefusalDetails,
    /// S-38's two exits and its two ways out.
    ///
    /// `DeliverSd` writes the files the C12 notice above it named; `DeliverDone` leaves,
    /// and is offered only once a delivery has succeeded, because Back from a signed and
    /// undelivered transaction is exactly the loss S-38 exists to prevent. `DeliverRetry`
    /// appears after a failed write, `DeliverDiscard` after the second one - the C4b red
    /// card that lets a user with a dead card slot leave with informed consent rather
    /// than by pulling the power, which is the same outcome without it.
    DeliverSd,
    DeliverDone,
    DeliverRetry,
    DeliverDiscard,
    /// "Show as QR" (S-38): opens S-39 over the delivery screen, with the signed
    /// transaction as one static symbol.
    ///
    /// EMITTED. The reason this id spent two milestones declared and unemitted was that
    /// C11's player animates a fountain-coded sequence and nothing in this workspace
    /// produced one; `notyas_core::psbt_qr` now encodes a signed transaction as base64 in
    /// a SINGLE symbol, which is the one form every wallet this device targets reads from
    /// a camera, so there is no sequence to animate and no button drawn that nothing
    /// hit-tests. It is still emitted DISABLED - with the size and the limit in the
    /// sentence beside it - whenever `psbt_qr::fits` says the transaction is larger than a
    /// symbol the shortest shipped panel can draw scannably, because a control that
    /// refuses on tap teaches nothing and the card is the remedy for that case.
    DeliverQr,
    /// S-39's two answers, which are answers S-38 records.
    ///
    /// `DeliverQrDelivered` is a claim the USER makes: the panel cannot see the camera, so
    /// nothing on this device can know a scan landed, and this is the only thing that
    /// ungates `DeliverDone` on the QR path - exactly as a successful card write does on
    /// the other one. `DeliverQrClose` dismisses the symbol and records nothing.
    ///
    /// Separate ids from the delivery screen's own exits because the overlay is hit-tested
    /// INSTEAD of the screen beneath it: one id shared between the two layers would let a
    /// tap land on whichever of them answered first, which is the class of bug the whole
    /// region vocabulary exists to make unrepresentable.
    DeliverQrDelivered,
    DeliverQrClose,
    /// S-41: import a descriptor or a Coldcard multisig file from the card.
    MsImport,
    /// S-41's "Export our xpub (BIP48)", S-43's "Export to card" and "Export as QR".
    /// DECLARED and NOT EMITTED for the same reason as [`RegionId::DeliverQr`], with one
    /// addition for the two card exports: invariant 2b requires the file name to be on
    /// screen BEFORE the write, and no request in this crate's vocabulary yet asks the std
    /// side what that name would be.
    MsExportXpub,
    MsExportSd,
    MsExportQr,
    /// S-42's two answers. `MsApprove` exists only on the last page and only after the
    /// whole cosigner set has been seen (C5's enforced traversal); `MsReject` is offered
    /// throughout, because refusing an import needs no traversal.
    MsApprove,
    MsReject,
    /// S-43's re-inspection actions: the paged cosigner review again, read-only, and the
    /// first receive address this registration produces - the value a user compares
    /// against another signer before the wallet is used.
    MsCosigners,
    MsFirstAddress,
    /// S-43's "Delete registration": opens the C4d typed-name sheet.
    MsDelete,

    /// S-49's one destructive control: opens the C4b sheet that leads to the typed one.
    ///
    /// Emitted only while the probe came back [`FormatOffer::Ready`], so there is no
    /// region to tap on a card the device refused - the button a user cannot press is the
    /// button that is not drawn. "Check again" on that screen is [`RegionId::FileRefresh`],
    /// which is the same affordance with the same label everywhere a card might not be
    /// there.
    ActWords,
    SaveAddr,
    CardFormat,
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
///
/// # Every request is answered, and the failure is part of the answer
///
/// Each variant names the `Ui` method that answers it, and every one of those methods
/// takes ONE value whose variants include the ways the work can fail. That is not a
/// convenience: an embedder cannot answer with the success alone, because no success-only
/// call exists, and a request that is answered at all is answered on the panel. The
/// alternative - a handler that logs an error and returns - leaves the user in front of a
/// screen that did nothing, and this product has shipped that three times.
///
/// The answer goes back to the screen that raised the request (see `screens::Answer`), so
/// the two halves of an exchange live in one module, and a late answer is dropped by the
/// screen the user has moved on to rather than dragging them back.
#[derive(Debug, PartialEq, Eq)]
pub enum UiRequest {
    /// Encode `payload` (e.g. with `notyas_core::qr::matrix`, std side), pack it into a
    /// [`QrData`] and hand it back via [`Ui::show_qr`] together with this target.
    Qr(QrTarget),
    /// Derive the anti-phishing words for the prefix typed so far and answer with
    /// [`Ui::show_device_words`]. Costs no attempt-counter decrement.
    DeviceWords(Secret),
    /// Try this PIN against the sealed store; answer with [`Ui::unseal_result`]. The
    /// unsealing, the attempt accounting and every flash write live on the std side.
    UnsealWallet(Secret),
    /// Install this PIN as the device's FIRST one - format the store under it and open the
    /// session that formatting produces - and answer with [`Ui::pin_created`].
    ///
    /// Raised only by S-06/S-07, only where [`StoreStatus::has_pin`] is false, and only
    /// after the same PIN has been typed twice. Distinct from [`UiRequest::ChangePin`],
    /// which re-seals records that already exist under a key that already exists: there is
    /// nothing here to re-seal and no old key to retire, so the two are different flash
    /// operations with different failure modes and they do not share a request.
    ///
    /// This is a WRITE, and the first one the device has ever made: it creates the ledger
    /// and the superblock. Until 0.2.0 shipped this variant the only route to it was the
    /// test console, which a product build compiles out - so a release image could not be
    /// given a PIN at all, and therefore could not store a wallet at all.
    SetPin(Secret),
    /// Seal this wallet into the store; answer with [`Ui::persist_result`].
    PersistWallet(WalletDraft),
    /// Drop the open session now (the Lock affordance, and the power-off path). Answer
    /// with [`Ui::lock`], which is also what the auto-lock timeout calls.
    LockSession,
    /// Write the boot-counter acknowledgement mark (VERIFY.md 6.3); answer with
    /// [`Ui::set_verify_info`] carrying the values read back after the write.
    AcknowledgeBoots,
    /// Raw-read every must-be-blank flash span and answer with [`Ui::set_flash_scan`]
    /// (VERIFY.md 3.3). Roughly 14 MiB on board B and 30 MiB on board A, so it is on
    /// demand and never at boot (ratified Q57), and the C3 Busy frame that says so is
    /// already on the panel when this request is returned.
    ScanReservedSpace,
    /// Unseal the wallet in this slot and answer with [`Ui::wallet_opened`]. The slot
    /// comes from the [`WalletInfo`] the embedder itself installed, so the UI never
    /// invents one.
    ///
    /// Carries no passphrase and never will. A wallet that needs one is answered with
    /// [`Ui::wallet_needs_passphrase`], which puts the entry screen up; the passphrase
    /// then comes back through [`UiRequest::UnlockWallet`]. Splitting it that way is what
    /// keeps the common case - a wallet with no passphrase, or one this session already
    /// holds the passphrase for - a single tap with no prompt.
    OpenWallet(u8),
    /// Open the wallet in this slot with the passphrase the user has just typed, and
    /// answer with [`Ui::wallet_opened_with_keys`] or [`Ui::passphrase_refused`].
    ///
    /// Raised only by the unlock screen [`Ui::wallet_needs_passphrase`] put up, and only
    /// for the slot that screen was opened for. The passphrase travels as [`Secret`], for
    /// the reason `SetPin` and `UnsealWallet` do: this enum derives `Debug`, and `Secret`
    /// is what makes that safe.
    ///
    /// Blocking, for seconds: one BIP-39 stretch and four account derivations, the same
    /// work the create interstitial spends. The screen is already showing its Busy frame
    /// when this is returned, and the embedder publishes it before doing the work.
    UnlockWallet {
        slot: u8,
        passphrase: Secret,
    },
    /// Re-seal this wallet's record so that it CARRIES the passphrase the session is
    /// holding, and answer with [`Ui::passphrase_storage_result`] carrying the state read
    /// back from flash afterwards.
    ///
    /// Raised only from the wallet home of an OPEN passphrase wallet, behind the C4b
    /// consequence sheet. It carries no passphrase: the embedder is holding the one that
    /// just opened this wallet, and the value it stores is therefore byte-for-byte the one
    /// that derived the fingerprint in the record rather than something retyped.
    StorePassphrase(u8),
    /// Re-seal this wallet's record WITHOUT the passphrase it currently stores, and answer
    /// with [`Ui::passphrase_storage_result`].
    ///
    /// Destructive: the device can never show the passphrase back, so what it forgets it
    /// forgets for good. Raised only behind the C4c hold sheet, which says so.
    ForgetPassphrase(u8),
    /// Erase this slot's record and every multisig registration that names it, then answer
    /// with [`Ui::wallet_deleted`] AND install the list as it now reads with
    /// [`Ui::set_wallets`]. Both halves: the answer says what happened to this wallet, the
    /// list says what the device now holds, and the screen renders the two together.
    ///
    /// Raised only from S-47b, which is reachable only through the C4b consequence sheet
    /// and the C4d typed-name sheet before it. Three surfaces stand between a tap on
    /// "Delete this wallet" and this request, and the last of them is not a confirm button
    /// at the coordinates the one before it used.
    DeleteWallet(u8),
    /// Read back the recovery words stored in this slot and answer with
    /// [`Ui::recovery_words`]. Raised only from S-47b, and only by a tap on the card that
    /// says so.
    ///
    /// The UI holds no flash and no key ladder, so it cannot open a record; what comes back
    /// is the normalized phrase the record stores, which the words screen shows behind
    /// S-13's reveal gate exactly as it shows a freshly derived one. Nothing here derives a
    /// seed and nothing needs a BIP-39 passphrase: the record stores the WORDS, which is
    /// what makes re-showing them possible at all.
    RecoveryWords(u8),
    /// Re-seal the store under a new wrong-PIN policy; `None` disables the wipe.
    ///
    /// A change-PIN-class operation rather than a settings write: the policy is
    /// authenticated INSIDE the AEAD (PIN-MODES.md), so committing it re-seals under the
    /// PIN and carries the fresh PIN confirmation the std side performs. Answer with
    /// [`Ui::policy_result`], and with [`Ui::set_lock_info`] carrying the policy as it
    /// reads back afterwards.
    SetWipePolicy { wipe_after: Option<u8> },
    /// Run the change-PIN sequence: the std side owns the PIN, the re-seal of every
    /// stored record under the new one, and the fresh PIN confirmation the format
    /// requires; it answers with [`Ui::set_lock_info`] carrying the new [`PinShape`].
    ///
    /// Raised by S-44's change-PIN row, and - the reason it exists at this milestone - by
    /// the longer-PIN action on the wipe-off sheet. PIN-MODES.md requires that sheet to
    /// offer the longer-PIN PATH rather than only accept or cancel, and a path is an
    /// action that goes somewhere.
    ChangePin,
    /// Destroy every sealed record and leave the store unformatted, returning the device
    /// to 0.1.0 stateless operation (Q5.5). Answer with [`Ui::pin_removed`].
    ///
    /// Deliberately NOT named "turn the PIN off": the sealing key IS the PIN, so no state
    /// exists in which the records survive its removal, and a name that implied otherwise
    /// would be the one place this enum could mislead about what the button does.
    RemovePin,
    /// Persist the device name the user typed on S-44a, and answer with
    /// [`Ui::device_name_result`].
    ///
    /// The string is PUBLIC and carries no [`Secret`] wrapper, deliberately: it is shown
    /// on the lock screen, before any authentication, to whoever is holding the device.
    /// See [`LockInfo::device_name`] for what that means and what it does not mean.
    ///
    /// Validated by the screen before it is raised - ASCII, short enough for the narrower
    /// panel, and not a PIN or a BIP-39 word - so an embedder receives a string it can
    /// store as it stands. An empty string is legal and means the device has no name.
    SetDeviceName(String),

    // --- 0.2.0: the card, the transaction and the registry ----------------------------
    //
    // NOTHING in this group carries key material, and that is a property of the flows
    // rather than an omission: a PSBT, a descriptor, a cosigner xpub and a file name are
    // all public, and the two values that are not - the seed and the PIN - never leave the
    // std side at all. [`Secret`] is therefore absent here, and a request that ever needs
    // to carry a typed secret uses it, as `UnsealWallet` and `SetPin` do.
    //
    // Every one of these blocks the input loop for well over C3's 150 ms, so each is
    // raised from a screen that has already switched to its Busy frame
    // ([`ScreenId::Working`], [`ScreenId::Signing`]) and the embedder publishes that frame
    // BEFORE it starts work. The answer is what moves the panel off it - which is why
    // every one of them has a failure answer, not just a success one.
    /// List one directory of the card: the root when `dir` is empty, one level below it
    /// otherwise (S-28's depth limit). Answer with [`Ui::card_result`].
    ListCard { dir: String, filter: FileFilter },
    /// Read this file off the card AND decide whether it may be signed. Answer with
    /// [`Ui::psbt_result`].
    ///
    /// ONE request for the read and the check, because the user does nothing between them
    /// and because both fail into the same C7 screen: "no card" (R-23), "not a PSBT"
    /// (R-20) and "change output not proven" (R-03) are all answers to one tap on one file,
    /// and splitting them would give the screen two failure channels for one action.
    LoadPsbt { dir: String, name: String },
    /// Sign the transaction the user has just held to sign, and run the post-sign gate on
    /// what was produced. Answer with [`Ui::sign_result`].
    ///
    /// Carries nothing: the reviewed file lives on the std side, which is also where the
    /// seed is, and re-sending either would mean the UI held a copy of one of them. What
    /// binds this to what was on the panel is the engine's own binding - the inspection
    /// carries the SHA-256 of the bytes it read and signing recomputes it.
    SignTx,
    /// Write the signed transaction to the card, as the files the C12 notice named.
    /// `overwrite` is true only on the second raise, behind the C4a confirm that a
    /// [`WriteOutcome::Collision`] opens. Answer with [`Ui::write_result`].
    WriteSigned { overwrite: bool },
    /// Encode the signed transaction the std side is holding as a QR symbol and answer
    /// with [`Ui::show_signed_qr`]. S-38's second exit, which opens S-39 over it.
    ///
    /// Carries nothing, exactly like [`UiRequest::SignTx`] and
    /// [`UiRequest::WriteSigned`]: the bytes live on the std side with the seed that made
    /// them, and a request that carried them would put a second copy of a signed
    /// transaction in this crate for the length of a function call. The embedder frames
    /// what it is already holding.
    ///
    /// Distinct from [`UiRequest::Qr`], which carries its own payload and is answered by
    /// [`Ui::show_qr`] onto the schemes screen. Two requests rather than one because the
    /// two payloads are owned by different sides of the boundary and land on different
    /// screens; sharing either half would mean a QR answer that could be installed over
    /// whichever of them happened to be showing.
    ///
    /// The screen raises this only when `notyas_core::psbt_qr::fits` says the transaction
    /// can be drawn scannably, so the refusal in the answer is for a disagreement between
    /// the two sides - not for the ordinary too-large case, which never gets this far.
    ShowSignedQr,
    /// Destroy the signed transaction the std side is holding without delivering it - the
    /// C4b override S-38 offers after two failed writes. Answer with
    /// [`Ui::discard_result`].
    ///
    /// A request rather than a screen change, because the bytes are not the UI's to drop:
    /// leaving S-38 without this would strand a signed transaction in RAM, which is the
    /// exact loss that screen exists to prevent.
    DiscardSigned,
    /// Read a descriptor or a Coldcard multisig file off the card and prove this device is
    /// one of its cosigners. Answer with [`Ui::import_result`].
    ///
    /// The proof happens HERE and not at approval: a wallet this device cannot sign for
    /// must never reach a review screen that implies it can, which is R-04's whole point.
    ImportRegistration { dir: String, name: String },
    /// Seal the reviewed registration into a registry slot. `replace` is true only behind
    /// the C4a confirm a [`RegistrationReview::duplicate`] opens. Answer with
    /// [`Ui::registration_result`].
    ApproveRegistration { replace: bool },
    /// Erase this registry slot, then install the registry as it now reads with
    /// [`Ui::set_registrations`]. Raised only behind the C4d typed-name sheet. Answer with
    /// [`Ui::registration_deleted`].
    DeleteRegistration(u8),

    // --- 0.2.0: repairing a card the device cannot read (S-49) -------------------------
    //
    // Two requests and never one. A probe reads and a format destroys, they are separated
    // by a typed consent the user gives IN BETWEEN them, and a single request that did
    // both would mean the decision to write was taken on the std side out of a state no
    // screen had shown anybody.
    /// Look at the card at BLOCK level and decide whether writing a filesystem into its
    /// existing partition could make it readable. Answer with [`Ui::format_offer`].
    ///
    /// Reads. Writes nothing, ever, on any path - which is what lets it run the moment the
    /// screen opens, with no consent behind it.
    ProbeCardFormat,
    /// Write an empty FAT filesystem into partition `partition` of the card whose capacity
    /// renders as `card`. Answer with [`Ui::format_result`].
    ///
    /// The most destructive request in this vocabulary: it erases a card whose contents
    /// this device never held and cannot describe. It is raised from exactly one place -
    /// behind the C4d typed sheet on S-49 - and it carries the two facts consent was given
    /// AGAINST rather than a bare "do it", so the embedder can re-read the card and refuse
    /// if what is in the slot is no longer what was on the panel. A card swapped between
    /// the sheet and the tap is the failure this shape exists to make impossible.
    FormatCard {
        /// The MBR partition index, 1..=4, that the offer named.
        partition: u8,
        /// The card's capacity as [`FormatTarget::word`] rendered it - which is also the
        /// word the user typed back.
        card: String,
    },
    /// Write a receive address to a text file on the SD card. Answer with
    /// [`Ui::save_addr_result`]. The address is public data.
    ///
    /// `overwrite` is true only on the second raise, behind the confirm that a
    /// [`SaveAddrResult::Collision`] opens - the same shape [`UiRequest::WriteSigned`]
    /// uses for the same reason: an existing file is a question for the user, not
    /// something this device deletes on its own say-so.
    SaveAddress { address: String, overwrite: bool },
}

/// A secret on its way from a screen to the embedder: a PIN, or the prefix of one.
///
/// The [`Ui`] is no_std and touches neither flash nor crypto, so the one thing it can do
/// with a typed PIN is hand it over. This type is that handover made explicit: it wipes
/// on drop, it is not `Clone` (duplicating a PIN is a decision a call site should have to
/// write out), and its `Debug` says nothing.
pub struct Secret(Zeroizing<String>);

impl Secret {
    fn new(value: &str) -> Secret {
        Secret::sized(value, PIN_MAX)
    }

    /// A secret sized for a BIP-39 passphrase rather than a PIN.
    ///
    /// The capacity is the whole point of the type (see [`secret_buf`]): a buffer built at
    /// `PIN_MAX` and filled with 200 bytes of passphrase reallocates four times on the way,
    /// and every abandoned allocation is a prefix of the passphrase that no `Zeroizing`
    /// reaches. One constructor per bound, and each call site says which bound it means.
    pub(crate) fn passphrase(value: &str) -> Secret {
        Secret::sized(value, PASS_MAX)
    }

    fn sized(value: &str, cap: usize) -> Secret {
        let mut buf = secret_buf(cap);
        buf.push_str(value);
        Secret(buf)
    }

    /// The characters to hand to `notyas_wallet::Pin`, or to the anti-phishing
    /// derivation when this is a prefix.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Debug for Secret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

/// Equality over the secret itself, so a test can assert which PIN a screen handed out.
/// Not constant time and deliberately not pretending to be: the comparison that decides
/// anything happens in `notyas-wallet`, against a key, not here against a `String`.
impl PartialEq for Secret {
    fn eq(&self, other: &Secret) -> bool {
        *self.0 == *other.0
    }
}

impl Eq for Secret {}

/// The wallet a finished create flow is offering to save, on its way to be sealed.
///
/// Carries the BIP39 phrase, which is the whole secret; the fingerprint and network ride
/// along because the record's label needs them and re-deriving them on the std side would
/// be a second implementation of the same arithmetic.
pub struct WalletDraft {
    phrase: Zeroizing<String>,
    /// The user's label for the slot, as typed on S-20. Not a secret and not an
    /// identity - the fingerprint is the identity - but the record needs it.
    pub name: String,
    pub fingerprint: String,
    pub network: bitcoin::Network,
    /// The BIP-39 passphrase this wallet was derived with, or `None` where none was
    /// applied.
    ///
    /// It travels ONCE, here, at the save - which is the moment the embedder has to write
    /// the record's flag truthfully and to seed the session so that the wallet the user
    /// just created does not immediately ask for the passphrase back. What the embedder
    /// STORES is a separate decision the owner makes per wallet (Q22 amendment,
    /// 2026-08-19); the default is that it is held for the session and written nowhere.
    ///
    /// [`Secret`], not `String`, for the reason the PIN is: the redacting `Debug` is what
    /// lets this ride inside a `Debug`-deriving enum at all.
    pub passphrase: Option<Secret>,
    /// Whether to store the passphrase in the sealed record at creation time.
    /// When true, the firmware calls set_passphrase_storage after sealing.
    pub store_passphrase: bool,
}

impl WalletDraft {
    pub fn phrase(&self) -> &str {
        &self.phrase
    }
}

impl core::fmt::Debug for WalletDraft {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WalletDraft")
            .field("name", &self.name)
            .field("fingerprint", &self.fingerprint)
            .field("phrase", &"<redacted>")
            .field("passphrase", &self.passphrase.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl PartialEq for WalletDraft {
    fn eq(&self, other: &WalletDraft) -> bool {
        *self.phrase == *other.phrase
            && self.name == other.name
            && self.fingerprint == other.fingerprint
            && self.network == other.network
            && self.passphrase == other.passphrase
    }
}

impl Eq for WalletDraft {}

// ---------------------------------------------------------------------------------------
// Wallets, as the post-PIN screens read them
// ---------------------------------------------------------------------------------------

/// What kind of wallet a slot holds. The badge on the list row and on the identity card.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletKind {
    SingleSig,
    Multisig,
}

impl WalletKind {
    /// The badge word, in the copy vocabulary (UX-SCREENS.md S-10).
    pub fn badge(self) -> &'static str {
        match self {
            WalletKind::SingleSig => "single-sig",
            WalletKind::Multisig => "multisig",
        }
    }
}

/// Whether the backup behind a wallet has been proved (commandment 3).
///
/// Two states and no third: a wallet is either backed by words the owner demonstrably
/// holds or it is not, and the screens say which in the same two words everywhere.
#[derive(Debug, Clone, PartialEq, Eq)]

pub enum BackupState {
    /// The check was passed. The string is what the embedder recorded (a date); empty
    /// when the record carries none, which renders as the bare badge rather than a
    /// fabricated date.
    Verified(String),
    /// Never checked on this device. Uppercase on screen: it should stop a reader.
    Unchecked,
}

/// One stored or session wallet, as every post-PIN screen reads it.
///
/// One vocabulary for two screens on purpose: the list row and the identity card show
/// overlapping subsets of the same facts, and two structs would let them disagree about
/// the same wallet. Everything here is PUBLIC - a name, a fingerprint, a path, a network -
/// so the struct is `Clone` and printable; the seed behind it never enters this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletInfo {
    /// Storage slot this record lives in, as the embedder read it. The UI never invents
    /// one and never renumbers: it is the handle [`UiRequest::OpenWallet`] and
    /// [`UiRequest::DeleteWallet`] name.
    pub slot: u8,
    pub name: String,
    /// Master fingerprint, 8 lowercase hex. The identity surface, and the only
    /// abbreviation the product permits (it is a full value, not a truncation).
    pub fingerprint: String,
    /// Account derivation path, e.g. `m/84'/0'/0'`.
    pub path: String,
    /// Script type in words, e.g. "native segwit". Supplied rather than derived: naming
    /// a script type from a path is the embedder's job, not a rendering rule.
    pub script_type: String,
    pub kind: WalletKind,
    pub backup: BackupState,
    pub network: bitcoin::Network,
    /// Multisig registrations stored against this wallet.
    pub registrations: u8,
    /// False for a "Use once, keep nothing" session: nothing was written, and the wallet
    /// home says so rather than letting the user assume it survives a power cut.
    pub stored: bool,
    /// What a BIP-39 passphrase has to do with this wallet. Never the passphrase itself.
    pub passphrase: PassphraseState,
}

/// What a passphrase has to do with a wallet, as the identity card states it.
///
/// Three states and not a bool, and the reason is a lie this product shipped: the card
/// rendered `passphrase off` for a wallet that demonstrably had one, because the embedder
/// had no way to say otherwise and `false` was the closest the vocabulary came to "not
/// measured". A value that cannot express what is true is a value that will be wrong.
///
/// The words ON and off are banned from this row and the copy gate enforces it. A
/// passphrase is not a setting of a wallet that could be switched: it is part of WHICH
/// wallet this is - the same words under a different passphrase are a different wallet with
/// a different fingerprint. What IS a setting is whether this device remembers it, and
/// that is what [`PassphraseState::Stored`] names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassphraseState {
    /// The words alone derive this wallet.
    None,
    /// A passphrase is part of this wallet, and this device does not keep it. Opening asks
    /// for it once per session.
    Required,
    /// A passphrase is part of this wallet and this device remembers it, because the owner
    /// turned that on for this wallet (Q22 amendment, 2026-08-19).
    Stored,
}

impl PassphraseState {
    /// The identity-card row, and the only three strings that row may ever contain.
    pub fn row(self) -> &'static str {
        match self {
            PassphraseState::None => "no passphrase",
            PassphraseState::Required => "passphrase required",
            PassphraseState::Stored => "passphrase stored",
        }
    }

    /// Whether a passphrase is part of this wallet's identity at all.
    pub fn applied(self) -> bool {
        !matches!(self, PassphraseState::None)
    }
}

/// A row of the wallet list.
///
/// Two variants because a slot whose record fails its AEAD tag has no name, no
/// fingerprint and no path to show, and rendering it as a wallet with blank fields would
/// invent facts about a record the device could not read (R-32).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletRow {
    Wallet(WalletInfo),
    /// This slot did not decrypt with this PIN.
    Unreadable { slot: u8 },
}

/// The two counts a destruction confirmation names individually (Q5.5), counted from the
/// wallet list the embedder installed.
///
/// Counted rather than tracked separately on purpose: two sources of truth for "how many
/// wallets" is exactly the drift that would eventually put a wrong number on the one
/// screen where the number is the whole point. POST-PIN only, like the list it is
/// counted from - Q2(a) forbids an occupancy count on every pre-PIN surface and on the
/// Verify screen, permanently and for all users.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StoredCounts {
    pub wallets: usize,
    pub registrations: usize,
}

impl StoredCounts {
    pub fn of(rows: &[WalletRow]) -> StoredCounts {
        let mut counts = StoredCounts::default();
        for row in rows {
            counts.wallets += 1;
            // An unreadable slot is still an occupied slot and is still destroyed; what
            // is unknown is what it holds, which is why it contributes no registrations
            // rather than being left out of the wallet count.
            if let WalletRow::Wallet(w) = row {
                counts.registrations += usize::from(w.registrations);
            }
        }
        counts
    }

    /// "no stored wallets" / "1 stored wallet" / "3 stored wallets".
    ///
    /// The phrasing lives here rather than in each screen because two screens name these
    /// counts and a paraphrase between them would be a second vocabulary for one fact -
    /// the same reasoning as [`PASSPHRASE_WARNING`].
    pub fn wallets_text(&self) -> String {
        match self.wallets {
            0 => String::from("no stored wallets"),
            1 => String::from("1 stored wallet"),
            n => format!("{n} stored wallets"),
        }
    }

    /// "no multisig registrations" / "1 multisig registration" / "2 multisig registrations".
    pub fn registrations_text(&self) -> String {
        match self.registrations {
            0 => String::from("no multisig registrations"),
            1 => String::from("1 multisig registration"),
            n => format!("{n} multisig registrations"),
        }
    }
}

/// What the backup check is asking right now.
///
/// Public because a host driver - tools/uisim and the test suite - has no other way to
/// read the panel, and it discloses exactly what the screen already paints: five
/// candidate words, one of them correct and carrying no marker that says which.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuizView {
    /// 1-based position of the word under test.
    pub word: u8,
    /// Words in the mnemonic.
    pub words: u8,
    /// Positions already answered correctly.
    pub done: u8,
    /// The candidates, in the order they are drawn.
    pub choices: alloc::vec::Vec<String>,
}

/// What the std side made of a [`UiRequest::UnsealWallet`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsealOutcome {
    /// The PIN was right and a session is open on the std side.
    Unsealed,
    /// The PIN was wrong. `attempts_left` is `None` when the wipe policy is off.
    WrongPin { attempts_left: Option<u8> },
    /// The attempt threshold was reached and the stored records were destroyed.
    Wiped,
    /// The store could not be read at all: typing a PIN into it cannot succeed (R-32).
    Unreadable,
}

/// What the sealed store holds, as much of it as a screen is allowed to know.
///
/// Deliberately NOT a count. Ratified Q2(a): no pre-PIN surface and no Verify row ever
/// states how many wallets are stored, permanently and for all users, because the count
/// is what a coercer learns for free from a device they cannot open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreStatus {
    /// No device key is burned. Nothing can be sealed, and no anti-phishing word exists
    /// to show - they are derived from that key (R20).
    NotProvisioned,
    /// A device key is present but the ledger has never been formatted. Still stateless,
    /// still no words, still nothing written to flash.
    Blank,
    /// A PIN is set and the device is locked.
    Locked,
    /// A PIN is set and a session is open.
    Unlocked,
    /// Both slots are unreadable; the device says so rather than pretending.
    Unreadable,
}

impl StoreStatus {
    /// Whether a PIN has ever been set on this device - the precondition for the lock
    /// screen, for PIN entry, and for the existence of anti-phishing words (R20).
    pub fn has_pin(self) -> bool {
        matches!(self, StoreStatus::Locked | StoreStatus::Unlocked)
    }
}

/// The shape of the PIN currently set, as much of it as the exhaustive-search arithmetic
/// on the wipe-policy screen needs.
///
/// The LENGTH and the ALPHABET, never the PIN: the two together are the keyspace, which
/// is the only thing that sentence is a function of. The alphabet is a count supplied by
/// the embedder rather than an enum here, so the day PIN entry grows its alphanumeric
/// page ([`RegionId::PinAlpha`]) the arithmetic is already right and nothing in this
/// crate changes.
///
/// Post-PIN only. Nothing pre-PIN reads it and nothing may: the length of a PIN is a hint
/// for anyone guessing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinShape {
    pub len: u8,
    /// Distinct characters one position can hold. 10 for the digit pad.
    pub alphabet: u32,
}

impl PinShape {
    /// The alphabet of the digit pad, which is the only PIN entry the device has today.
    pub const DIGITS: u32 = 10;
}

/// The lock and PIN screens' values, filled by the embedder from what it read.
///
/// Everything here is either public device state or a user-chosen label; nothing in it
/// is derived from a secret, which is why the whole struct is `Clone` and printable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockInfo {
    pub status: StoreStatus,
    /// The one user-chosen string this device shows before a PIN is typed (S-44's
    /// device-name row). Empty when unset, which the lock screen renders as its own edge
    /// state rather than as a blank line.
    ///
    /// # What an attacker learns from it, stated because it is readable without a PIN
    ///
    /// The name, in full, by picking the device up. That is the whole of it, and it is
    /// not an oversight to be sealed later: a pre-PIN surface is readable by anyone
    /// holding the device, so ANY string shown there is public to whoever has it. A name
    /// is not a secret and this field is not protected - it is deliberately outside the
    /// sealed store, because a string that could only be read after unlocking could not
    /// be shown on the screen that asks for the PIN.
    ///
    /// It follows that the name proves NOTHING about which device this is. A counterfeit
    /// built by someone who has held this one shows the same name. The device's actual
    /// anti-swap evidence is the word pair S-04 derives from the typed PIN prefix and a
    /// device-held secret, which a counterfeit cannot compute; the copy rule that follows
    /// is enforced in `screens/lock.rs`. Until 2026-08-19 this struct carried a SECOND
    /// pre-PIN string - a "lock word" whose panel claimed it let the user tell this
    /// device from a fake - and that claim was false for exactly the reason above. One
    /// string, and no claim on it.
    pub device_name: String,
    /// Attempts left before the wipe; `None` when the wipe policy is off.
    pub attempts_left: Option<u8>,
    /// The configured threshold, so every number on screen is a format string over the
    /// runtime policy rather than a literal (Q5 / Q37).
    pub wipe_after: Option<u8>,
    /// The shortest PIN this device's store will accept, read from its format-time policy
    /// (`notyas_wallet::Policy::min_pin_len`).
    ///
    /// Pre-PIN and safe there: it is a property of the FORMAT, identical on every device
    /// formatted with the same config, and it says nothing about the PIN actually in
    /// force - that is [`PinShape`], which is post-PIN only. The PIN screen already states
    /// this number to the user, because a disabled Unlock owes its reason.
    ///
    /// A device fact rather than a constant of this crate because the STORE is what
    /// refuses a short PIN, and 0.2.0 shipped an S-04 whose own literal sat above it: a
    /// device formatted at the ratified 4-digit floor could type its whole PIN and never
    /// enable Unlock. Two crates each believing they owned the number is the defect; this
    /// field is the single owner, and [`PIN_MIN_DEFAULT`] is only what a silent embedder
    /// gets.
    pub min_pin_len: u8,
    /// The shape of the PIN in force, once a session has been opened with it. `None`
    /// where no PIN exists, and also where the embedder did not record one - the
    /// wipe-policy screen then says the search time is unknown rather than printing a
    /// number for a PIN it never measured.
    pub pin: Option<PinShape>,
    /// What one unlock attempt costs on THIS board, in milliseconds: the other half of
    /// the exhaustive-search arithmetic, and the half that is a measurement. See
    /// [`UNLOCK_MS_M1`], which is both the default and the bench figure.
    pub unlock_ms: u32,
}

impl Default for LockInfo {
    /// A device the embedder has told nothing about has no PIN, so neither the lock
    /// screen nor PIN entry can be reached from it. The honest default, and the one that
    /// keeps R20 true for a caller that forgets to call [`Ui::set_lock_info`].
    fn default() -> Self {
        LockInfo {
            status: StoreStatus::NotProvisioned,
            device_name: String::new(),
            attempts_left: None,
            wipe_after: None,
            min_pin_len: PIN_MIN_DEFAULT,
            pin: None,
            unlock_ms: UNLOCK_MS_M1,
        }
    }
}

/// The Q22 warning, in the plain words the ratified answer requires, at every one of its
/// placements.
///
/// ONE constant rather than four paraphrases: the acceptance criterion is that the same
/// facts reach the user wherever a passphrase is involved, and four copies of a sentence
/// drift until one of them says something weaker. The placements are passphrase entry
/// (create AND restore), the post-check backup screen, the save that would otherwise imply
/// the device kept it, and - since the 2026-08-19 amendment - the sheet that offers to
/// store it.
///
/// # What the amendment changed, and what it did not
///
/// "Not stored" is still the DEFAULT and still the only state a user can reach without
/// deliberately turning storage on for one wallet, so the claim is qualified rather than
/// dropped. The rest is the fact that actually loses coins, and it holds whichever way the
/// toggle goes: the seed words alone restore a DIFFERENT wallet, so the passphrase has to
/// be written down and kept apart from them - remembered HERE is not backed up here. It
/// says in one clause what the ratified wording said in two ("restoring needs both halves"
/// and "a seed backup alone will not do"), because the space is measured rather than
/// editorial: three BODY lines is what the 800x480 fork screen has under two equal cards,
/// and a fourth line would push the block off the panel with no scroll behind it.
pub const PASSPHRASE_NOT_STORED: [&str; 1] = [
    "Not stored here unless you choose to store it. Your seed words alone restore a \
     DIFFERENT wallet - write this passphrase down and keep it apart.",
];

/// The refusal an unlock attempt gets when the passphrase derives a different wallet.
///
/// The device never says "wrong", "incorrect" or "invalid" about a passphrase, and the
/// copy gate asserts those words appear in no frame of this screen. BIP-39 has no invalid
/// passphrases: every one of them opens SOME wallet, so the only true statement is which
/// wallet the typed one opens and which wallet this record is. Both fingerprints are public
/// values - one is in the record, and the other is a function of what the user just typed -
/// so stating them discloses nothing they do not already hold.
///
/// What is never shown, here or anywhere: the fingerprint these words derive with an EMPTY
/// passphrase. That value is an existence proof for a hidden wallet, and the open path
/// discards it rather than rendering it.
pub struct PassphraseRefusal {
    /// The wallet the record names. Eight lowercase hex.
    pub expected: String,
    /// The wallet the typed passphrase opens. Eight lowercase hex.
    pub derived: String,
}

impl PassphraseRefusal {
    /// The sentence the unlock screen renders. One place, so the rule about what this may
    /// say cannot be broken by a second caller wording it again.
    pub fn sentence(&self) -> String {
        format!(
            "Every passphrase opens some wallet. That one opens wallet {}. This record is \
             wallet {}, so nothing was opened. Spelling, capitals and spaces all count - \
             check them and try again.",
            self.derived, self.expected
        )
    }
}

impl core::fmt::Debug for PassphraseRefusal {
    /// Public values, both of them, and the error type in the firmware says so too. Safe
    /// to print, unlike everything else on the screen that renders it.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PassphraseRefusal")
            .field("expected", &self.expected)
            .field("derived", &self.derived)
            .finish()
    }
}

/// What became of a change to whether this device remembers a wallet's passphrase.
///
/// The state is READ BACK from the record after the write and reported here, never
/// inferred from the intent: a toggle that rendered what the user asked for rather than
/// what the flash says would be a switch that lies about the one thing it controls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageOutcome {
    /// The record now says this, as it read back after the re-seal.
    Now(PassphraseState),
    /// Nothing was written, and this is why. The wallet is exactly as it was.
    Refused(String),
}

/// The retry gate on passphrase unlock attempts, per wallet slot, for this power-up.
///
/// # Why there is one at all
///
/// A stored record carries the fingerprint its seed must produce, so the device can tell a
/// right passphrase from a wrong one - which makes the unlock screen an ORACLE: without a
/// gate, somebody holding the device and the PIN could grind passphrase guesses against it
/// at whatever rate the panel accepts. The gate is what makes that rate the device's
/// decision rather than the attacker's.
///
/// It is honest about what it does not fix: the same grinding runs OFF the device, at
/// PBKDF2 speed, against a flash dump plus the PIN, and no on-panel delay reaches that.
/// Only passphrase strength does. What this closes is the cheap attack - the one that
/// needs no equipment beyond the device in the hand.
///
/// # The schedule
///
/// The first two attempts are immediate, because the common case is a typo and a person
/// who has just mistyped their own passphrase should not be punished for it. From the
/// third, the wait doubles from five seconds and is capped at five minutes. A power cycle
/// clears it - and costs more than the early delays are worth, which is why the early
/// delays are small.
///
/// # Where it lives, and why not on the screen
///
/// On the [`Ui`], not on the unlock screen: a counter the screen owned would reset every
/// time the user backed out to the wallet list and tapped the row again, which is one tap
/// and would make the gate decorative. It survives a lock for the same reason. It does NOT
/// survive a power cycle, because it is RAM, and that is stated rather than worked around.
#[derive(Debug, Default)]
pub(crate) struct UnlockGate {
    /// One entry per slot that has been refused at least once this power-up.
    ///
    /// A list rather than a table sized for the store, because the entries are failures
    /// and not wallets: on a device in normal use it is empty, and on a device somebody is
    /// guessing at it holds the one slot they are guessing at.
    slots: Vec<GateSlot>,
}

/// What the gate remembers about ONE wallet slot: how many consecutive refusals it has
/// taken, and how much of its wait is left.
///
/// The wait lives HERE, and that is the whole reason this type exists. It used to be a
/// single `Option<(slot, ms)>` on the gate, which meant only one slot could be waiting at
/// a time and a refusal on any other slot overwrote it - so a five-minute countdown on
/// slot 0 was cleared by one deliberate wrong guess against slot 1, and the schedule could
/// be held at zero indefinitely for the cost of one extra tap per attempt. That is the
/// entire attack the gate exists to stop, so it is made unrepresentable rather than merely
/// tested for: there is no shared field left to overwrite.
#[derive(Debug)]
struct GateSlot {
    slot: u8,
    /// Consecutive refusals. Cleared by a successful open, or by the wallet ceasing to
    /// exist; NOT by the wait running out, because the schedule is cumulative for the
    /// power-up and a gate that forgot on expiry would cap the delay at five seconds.
    attempts: u32,
    /// How much of this slot's wait is left, in milliseconds. Zero means it may try now.
    wait_ms: u32,
}

impl UnlockGate {
    /// Ceiling on the wait, in milliseconds. Five minutes: long enough that grinding on
    /// the panel is pointless, short enough that a legitimate owner who is looking for a
    /// piece of paper does not have to power cycle.
    const MAX_WAIT_MS: u32 = 300_000;

    /// Record a refusal for `slot` and return the wait it now carries, in milliseconds.
    ///
    /// Only this slot moves. A wrong passphrase for one wallet is not evidence about any
    /// other one, in either direction: it neither delays another wallet nor releases one.
    pub(crate) fn refused(&mut self, slot: u8) -> u32 {
        let i = match self.slots.iter().position(|e| e.slot == slot) {
            Some(i) => i,
            None => {
                self.slots.push(GateSlot { slot, attempts: 0, wait_ms: 0 });
                self.slots.len() - 1
            }
        };
        let entry = &mut self.slots[i];
        entry.attempts = entry.attempts.saturating_add(1);
        // 1, 2: immediate. 3: 5s. 4: 10s. 5: 20s... capped.
        //
        // The `.min(20)` is a shift guard and not a second ceiling: `1u32 << 32` panics in
        // a debug build and wraps in a release one, and `attempts` is a count a finger
        // resting on the glass can push past thirty-two. Twenty already saturates
        // `MAX_WAIT_MS` a thousand times over, so the guard costs nothing real.
        entry.wait_ms = match entry.attempts {
            0..=2 => 0,
            n => 5_000u32.saturating_mul(1u32 << (n - 3).min(20)).min(Self::MAX_WAIT_MS),
        };
        entry.wait_ms
    }

    /// This slot opened, or stopped existing. The gate forgets it - the count and the wait
    /// together, and neither for any other slot.
    ///
    /// The "stopped existing" half is what the wallet-deleted answer calls. Slots are
    /// reused, so a new wallet saved into a deleted one's slot would otherwise inherit a
    /// dead wallet's five-minute wait for the rest of the power-up.
    pub(crate) fn cleared(&mut self, slot: u8) {
        self.slots.retain(|e| e.slot != slot);
    }

    /// How much longer this slot has to wait, in milliseconds. Zero for a slot the gate
    /// has never refused, and zero for one whose wait has run out.
    pub(crate) fn wait_ms(&self, slot: u8) -> u32 {
        self.slots.iter().find(|e| e.slot == slot).map_or(0, |e| e.wait_ms)
    }

    /// How many consecutive refusals this slot has taken. For the tests and for a caller
    /// that wants to say so; nothing on screen prints it, because a count in front of a
    /// person guessing is a progress bar for them.
    #[cfg(test)]
    pub(crate) fn attempts(&self, slot: u8) -> u32 {
        self.slots.iter().find(|e| e.slot == slot).map_or(0, |e| e.attempts)
    }

    /// Age EVERY pending wait by `elapsed_ms`, and report whether the countdown that is on
    /// the glass changed the second it prints.
    ///
    /// Every wait ages, because a wait that only ran down while its own screen was open
    /// would be a wait a user could pause by backing out to the wallet list - which is one
    /// tap, and would make the whole schedule decorative.
    ///
    /// Only `showing` decides the return value. It is the slot the unlock screen is up
    /// for, or `None` when no unlock screen is showing, and it is the only countdown a
    /// repaint could change: redrawing the panel for a number nobody can see is forty
    /// frames a second of an unchanged screen.
    pub(crate) fn tick(&mut self, elapsed_ms: u32, showing: Option<u8>) -> bool {
        let mut changed = false;
        for entry in &mut self.slots {
            if entry.wait_ms == 0 {
                continue;
            }
            let before = entry.wait_ms.div_ceil(1000);
            entry.wait_ms = entry.wait_ms.saturating_sub(elapsed_ms);
            if showing == Some(entry.slot) && before != entry.wait_ms.div_ceil(1000) {
                changed = true;
            }
        }
        changed
    }
}

#[cfg(test)]
mod unlock_gate_tests {
    use super::UnlockGate;

    /// The published schedule, in one place: two free attempts, then five seconds
    /// doubling, and the refusal count is what drives it.
    ///
    /// Broken version: reset `attempts` when a wait expires. The third row below still
    /// passes and every one after it collapses to 5000.
    #[test]
    fn the_schedule_is_two_free_attempts_then_five_seconds_doubling() {
        let mut gate = UnlockGate::default();
        let schedule = [(1u32, 0u32), (2, 0), (3, 5_000), (4, 10_000), (5, 20_000), (6, 40_000)];
        for (n, expected) in schedule {
            assert_eq!(gate.refused(0), expected, "refusal {n}");
            assert_eq!(gate.attempts(0), n, "the count behind refusal {n}");
            assert_eq!(gate.wait_ms(0), expected, "what the screen would read after {n}");
        }
    }

    /// The wait stops at five minutes and stays there, and the arithmetic that produces it
    /// survives a count large enough to shift a u32 off its own width.
    ///
    /// The `.min(20)` in `refused` is the only thing standing between this test and a
    /// panic in the input path: at the thirty-fifth refusal the shift would be `1 << 32`.
    /// A device left face-down with something resting on the glass is not a hypothesis.
    ///
    /// Broken version: drop the `.min(20)`. This panics in a debug build and silently
    /// wraps the wait back down to five seconds in a release one.
    #[test]
    fn the_wait_caps_at_five_minutes_and_the_shift_cannot_overflow() {
        let mut gate = UnlockGate::default();
        let mut last = 0;
        for _ in 0..200 {
            last = gate.refused(3);
        }
        assert_eq!(last, 300_000, "the cap");
        assert_eq!(gate.wait_ms(3), 300_000);
        assert_eq!(gate.attempts(3), 200, "the count keeps rising underneath the cap");
    }

    /// THE security property: the gate is per wallet, so a refusal on one slot cannot
    /// release another slot's wait.
    ///
    /// With a single shared wait this was a one-tap reset - guess slot 0 until it costs
    /// five minutes, then deliberately fail once against slot 1, and slot 0 is open for
    /// business again - which made the entire schedule cost one extra tap per attempt.
    ///
    /// Broken version: put the wait back on the gate as `Option<(u8, u32)>`. The last two
    /// assertions trip.
    #[test]
    fn a_wait_on_one_wallet_survives_a_refusal_on_another() {
        let mut gate = UnlockGate::default();
        for _ in 0..3 {
            gate.refused(0);
        }
        assert_eq!(gate.wait_ms(0), 5_000, "slot 0 is serving its first real wait");

        // One deliberate wrong guess against a different wallet.
        assert_eq!(gate.refused(1), 0, "slot 1 has spent one of its two free attempts");
        assert_eq!(gate.wait_ms(1), 0, "and is not itself waiting");
        assert_eq!(gate.wait_ms(0), 5_000, "slot 0's wait is untouched");
        assert_eq!(gate.attempts(0), 3, "and so is its count");
    }

    /// A successful open forgets ONE slot. The others keep both halves of their state,
    /// which is what makes opening one wallet a statement about that wallet only.
    #[test]
    fn cleared_forgets_one_slot_and_leaves_the_rest() {
        let mut gate = UnlockGate::default();
        for _ in 0..4 {
            gate.refused(0);
            gate.refused(1);
        }
        assert_eq!(gate.wait_ms(0), 10_000);
        assert_eq!(gate.wait_ms(1), 10_000);

        gate.cleared(0);
        assert_eq!(gate.attempts(0), 0, "the count is gone");
        assert_eq!(gate.wait_ms(0), 0, "and so is the wait");
        assert_eq!(gate.attempts(1), 4, "the other slot is untouched");
        assert_eq!(gate.wait_ms(1), 10_000);

        // And the cleared slot starts again from the top of the schedule rather than from
        // where it left off: the two free attempts belong to an unlock session, not to a
        // lifetime.
        assert_eq!(gate.refused(0), 0);
    }

    /// `tick` repaints on the SECOND boundary and on nothing else, for the slot on screen
    /// and for no other.
    ///
    /// The countdown beside a disabled Try again is the only thing on this device that has
    /// to repaint while nobody is touching it, so this contract is what stands between a
    /// live number and forty redundant frames a second.
    ///
    /// Broken version: return `changed` for every slot rather than only for `showing`. The
    /// hidden-countdown assertion trips.
    #[test]
    fn tick_repaints_only_when_the_shown_second_changes() {
        let mut gate = UnlockGate::default();
        for _ in 0..3 {
            gate.refused(0);
        }
        assert_eq!(gate.wait_ms(0), 5_000);

        // 5000 -> 4900 still prints "5s", because the screen rounds up.
        assert!(!gate.tick(100, Some(0)), "no boundary crossed");
        assert_eq!(gate.wait_ms(0), 4_900);
        // 4900 -> 3900 prints "4s".
        assert!(gate.tick(1_000, Some(0)), "the printed second changed");

        // The same crossing, for a slot nobody is looking at, is not a repaint - but the
        // wait still ages, because a countdown a user can pause by navigating away is not
        // a countdown.
        let before = gate.wait_ms(0);
        assert!(!gate.tick(1_000, Some(1)), "a hidden countdown does not dirty the panel");
        assert!(!gate.tick(1_000, None), "and neither does one with no screen up");
        assert_eq!(gate.wait_ms(0), before - 2_000, "it aged anyway");

        // It runs out at zero and stays there rather than wrapping, and an expired wait
        // reports no further change however long the loop keeps calling.
        gate.tick(300_000, Some(0));
        assert_eq!(gate.wait_ms(0), 0);
        assert!(!gate.tick(1_000, Some(0)), "an expired wait has nothing left to repaint");
        assert_eq!(gate.attempts(0), 3, "and expiry does not forgive the attempts");
    }
}

/// What one [`Ui::tick`] did.
///
/// Two independent facts that used to be one `bool`: whether the panel needs repainting,
/// and whether the tick raised work only the embedder can do. A hold-to-confirm that
/// completes while the finger is still down is exactly a request with no touch event
/// behind it, so `tick` needs both halves.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Ticked {
    pub dirty: bool,
    pub request: Option<UiRequest>,
}

/// A tappable region: identity plus the rectangle it occupies right now.
#[derive(Debug, Clone, Copy)]
pub struct Region {
    pub id: RegionId,
    pub rect: Rect,
}

// ---------------------------------------------------------------------------------------
// The Verify-device readout (S-46; VERIFY.md sections 10 and 11)
// ---------------------------------------------------------------------------------------

/// A value that is hex when it exists, and a STATED REASON when it does not.
///
/// Five variants because the silicon gives five different answers, and collapsing them
/// loses the one that matters most: `esp_efuse_read_block()` performs no `RD_DIS` check
/// and a read-protected block hands back zeros, so an absent digest must not be able to
/// reach the screen as thirty-two zero bytes (VERIFY.md 5.1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum HexValue {
    /// Lowercase unspaced hex, exactly as read. The screen groups and wraps it; it never
    /// shortens it (contract rule 1).
    Read(String),
    /// The fuse or field is not burned. An absence, not a failure.
    NotBurned,
    /// A secure-boot digest slot that has been revoked.
    Revoked,
    /// Read protection is set, so software - this firmware included - cannot see it.
    ReadProtected,
    /// This build could not read it.
    #[default]
    NotRead,
}

impl HexValue {
    /// The hex itself, if there is any. The screen needs the distinction because a
    /// reason renders as a one-line K1 value and a digest renders as a K2 block.
    pub fn hex(&self) -> Option<&str> {
        match self {
            HexValue::Read(h) => Some(h),
            _ => None,
        }
    }
}

/// One hashed flash region: what was hashed, from where, and to what.
///
/// The offset and length travel with the digest because a digest without them is a
/// number rather than a checkable number - the same three-part shape the firmware's own
/// `notyas-verify/1` readout emits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionDigest {
    pub offset: u32,
    /// Bytes hashed. For an image this excludes the appended 32-byte digest, which is
    /// the length the release manifest publishes as `*_image_len`.
    pub len: u32,
    /// SHA-256 over exactly `len` bytes at `offset`, lowercase unspaced hex.
    pub sha256: String,
}

/// One row of the live partition table, in the order the iterator returned it.
///
/// Field set and spelling match `firmware/partitions.csv` so the screen and the file are
/// compared directly rather than translated (VERIFY.md 11.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionRow {
    pub name: String,
    /// IDF's own `type/subtype` rendering, e.g. `app/fact` or `data/0x40`.
    pub kind: String,
    pub offset: u32,
    pub size: u32,
    /// The partition carries the `encrypted` flag.
    pub encrypted: bool,
}

/// Bytes found in a span that was supposed to be erased, and where they start.
///
/// A count alone tells the owner nothing they can act on; an offset tells them, and
/// anyone they report it to, exactly where to look (VERIFY.md 3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetBytes {
    pub count: u64,
    pub first: u32,
}

/// One must-be-blank flash span and what a RAW read found in it.
///
/// Raw, not decrypted: erased flash is physically `0xff` whether or not the unit is
/// encrypted, while the decrypted view of erased flash is pseudorandom.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlankSpan {
    pub start: u32,
    /// One past the last byte read.
    pub end: u32,
    /// `None` is `all 0xff` - the only value on this screen whose comparand the owner
    /// needs nothing from anywhere to know.
    pub set: Option<SetBytes>,
}

/// The reserved-space scan: on demand behind `[ Scan ]`, never at boot (ratified Q57).
///
/// `NotScanned` is a statement about the device rather than a missing value: it has not
/// looked. Rendering it as `all 0xff`, or as anything else, would be the firmware
/// answering a question nobody asked it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ReservedSpace {
    #[default]
    NotScanned,
    /// The scan was asked for and produced no result: this build could not perform the
    /// raw read. Distinct from [`ReservedSpace::NotScanned`] on one side (which is "it has
    /// not looked") and from an empty [`ReservedSpace::Scanned`] on the other (which would
    /// claim it looked and found nothing), because those are three different statements
    /// about the device and only one of them is true at a time.
    NotRead,
    Scanned {
        /// In address order, which is also the order the digest concatenates them in.
        spans: alloc::vec::Vec<BlankSpan>,
        /// SHA-256 over the concatenated spans, so two units compare in one value and
        /// the scan survives the QR export.
        digest: HexValue,
    },
}

/// One eFuse bit as the SCREEN names it.
///
/// Four states, and the two past set/clear are the honest ones: a field this silicon
/// does not have (P4 has no `HARD_DIS_JTAG`) is [`Bit::Absent`], and a field this build
/// could not resolve is [`Bit::NotRead`]. Neither may collapse into [`Bit::Clear`],
/// which would be the screen reporting a fuse state it never read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Bit {
    Set,
    Clear,
    /// Not a field on this silicon, or no key block carries the purpose the row is about.
    Absent,
    #[default]
    NotRead,
}

impl Bit {
    /// A bit that was read.
    pub fn read(set: bool) -> Bit {
        if set {
            Bit::Set
        } else {
            Bit::Clear
        }
    }

    /// A bit that may not exist on this silicon: `None` is [`Bit::Absent`], never
    /// [`Bit::Clear`].
    pub fn present(set: Option<bool>) -> Bit {
        match set {
            Some(b) => Bit::read(b),
            None => Bit::Absent,
        }
    }

    /// The bit as read, or `None` when there was none to read.
    pub fn get(self) -> Option<bool> {
        match self {
            Bit::Set => Some(true),
            Bit::Clear => Some(false),
            Bit::Absent | Bit::NotRead => None,
        }
    }
}

/// One of the six eFuse key blocks (VERIFY.md 5.1, rendered per 11.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyBlockInfo {
    /// IDF's own purpose enumerator name, printed verbatim and never translated: the
    /// name IS the value a reader compares against `espefuse.py summary` and against the
    /// burn runbook. `None` is `esp_efuse_key_block_unused()`, printed `<unused>`.
    pub purpose: Option<String>,
    pub read_protected: bool,
    pub write_protected: bool,
}

/// Everything S-46 shows, in VERIFY.md section 10's frozen field order.
///
/// The firmware fills this from what it MEASURED (SECURITY.md invariant 5); this crate
/// displays it and computes no part of it. Every field carries its own way of saying
/// "this build did not read this" - `Option`, [`Bit::NotRead`], [`HexValue::NotRead`],
/// an empty `Vec` - because the contract rule "read, never claim" means an unread field
/// renders `not read` and never a plausible default, and because a row that could only
/// ever render one thing would make the screen a liar about the state it reports.
///
/// Flat, with section 11.2's six banners, deliberately: the field order is frozen, this
/// struct is in that order, and a reviewer checking one against the other should be
/// reading a list rather than walking a tree.
#[derive(Debug, Clone, Default)]
pub struct VerifyInfo {
    // --- identity (VERIFY.md 10.1) -----------------------------------------------------
    /// Board this image was built for; the build IS the board (BOARDS.md). One of the
    /// two legitimately compile-time values here - the flash rows beside it are what
    /// check the build against the hardware it is running on.
    pub board: Option<String>,
    pub chip: Option<String>,
    pub chip_revision: Option<String>,
    /// Boot ROM ECO version, e.g. `eco 2`.
    pub boot_rom: Option<String>,
    pub rom_chip_id: Option<String>,
    pub mac: Option<String>,
    /// eFuse `OPTIONAL_UNIQUE_ID`, 128 bits. `NotBurned` on a die that never had one,
    /// which says nothing rather than zero.
    pub die_unique_id: HexValue,

    // --- firmware (VERIFY.md 10.2) -----------------------------------------------------
    /// The other legitimately compile-time value: what the build calls itself. The
    /// digests below it are why a string is enough here.
    pub firmware_version: Option<String>,
    pub idf_app: Option<String>,
    /// The IDF that built the bootloader now in flash. Beside the app's row on purpose:
    /// a different string is a stale bootloader, which no digest alone can name.
    pub idf_bootloader: Option<String>,
    pub rollback_image: Option<String>,
    pub rollback_efuse: Option<String>,
    /// The composite over the three immutable regions (VERIFY.md 2.4).
    pub firmware_digest: HexValue,
    pub app: Option<RegionDigest>,
    pub bootloader: Option<RegionDigest>,
    pub partition_table: Option<RegionDigest>,

    // --- flash (VERIFY.md 10.3) --------------------------------------------------------
    /// What the build was told the flash is.
    pub flash_size_header: Option<String>,
    /// What the fitted part reports.
    pub flash_size_detected: Option<String>,
    pub jedec_id: Option<String>,
    /// Top 64 of 128 bits on GD parts; `None` where the part does not implement `4Bh`.
    pub flash_unique_id: Option<String>,
    /// The live table, row by row. Empty is `not read`.
    pub partitions: alloc::vec::Vec<PartitionRow>,
    pub reserved_space: ReservedSpace,
    /// Raw digest of the `wallets` partition - a digest of ciphertext, so it says
    /// nothing about content. Pre-PIN under the ratified Q2(a) (Q56).
    pub wallets_digest: HexValue,
    /// Raw digest of the `counters` partition. Expected to change on every boot.
    pub counters_digest: HexValue,

    // --- efuse (VERIFY.md 10.4) --------------------------------------------------------
    pub secure_boot: Bit,
    pub aggressive_revoke: Bit,
    /// All three slots, always: three rows where two read `not burned` make the absence
    /// of a second enrolled signing key a readable value rather than an inference from
    /// silence (ratified Q58).
    pub key_digests: [HexValue; 3],
    pub flash_encryption: Bit,
    /// IDF's own `esp_get_flash_encryption_mode()` enumerator name, untranslated.
    pub encryption_mode: Option<String>,
    /// Raw `SPI_BOOT_CRYPT_CNT` popcount, 0..=3.
    pub crypt_count: Option<u8>,
    /// `RD_DIS` on whichever block carries an XTS purpose; [`Bit::Absent`] when none
    /// does. A burned but software-readable XTS key is not flash encryption in any
    /// useful sense, which is why it is a row of its own.
    pub xts_key_read_protected: Bit,
    // Every remaining field in this group names an ACCESS rather than a fuse: `Set` is
    // "enabled", and it is the state of a chip whose `DIS_*` fuse is NOT burned. The
    // inversion happens once, in the firmware that reads the fuse, so that no reader of
    // this struct has to remember which way each symbol points.
    /// `DIS_DOWNLOAD_MANUAL_ENCRYPT` inverted: manual encryption is still allowed.
    pub manual_encrypt: Bit,
    pub uart_download: Bit,
    /// `ENABLE_SECURITY_DOWNLOAD` - the one field in the group that is not inverted.
    pub secure_download: Bit,
    pub usb_serial_jtag_download: Bit,
    pub usb_otg_download: Bit,
    pub forced_download: Bit,
    pub direct_boot: Bit,
    pub jtag_pad: Bit,
    pub jtag_usb: Bit,
    /// `SOFT_DIS_JTAG` as `(count, width)`, printed raw: it is a 3-bit odd/even field,
    /// IDF treats soft-disabled as complete only at the full width, and the count is
    /// what `espefuse.py` prints.
    pub jtag_soft: Option<(u8, u8)>,
    /// Which JTAG path the strapping pin selects. A selector, so the raw bit.
    pub jtag_select: Bit,
    /// `UART_PRINT_CONTROL`, two bits, printed raw.
    pub rom_log: Option<u8>,
    /// ROM printing over USB-serial-JTAG, as the access.
    pub rom_log_usb: Bit,
    /// All six blocks in block order. Empty is `not read`.
    pub key_blocks: alloc::vec::Vec<KeyBlockInfo>,

    // --- state (VERIFY.md 10.5) --------------------------------------------------------
    /// Boots counted since the ledger was formatted. `None` renders `not counted` and
    /// NEVER `0`: on an unprovisioned or blank device nothing is written and nothing is
    /// read, so `0` would be a value the device did not measure (VERIFY.md 6 / R24).
    pub boot_count: Option<u64>,
    /// The boot index the owner last marked as seen. `None` renders `not acknowledged`.
    pub acknowledged_at: Option<u64>,
    /// Times this device has been wiped. Pre-PIN: a wipe is not a secret, and the value
    /// is in the plaintext `counters` partition where a flash dump reads it anyway.
    pub wipe_epoch: Option<u64>,
    /// Occupancy at the granularity Q2(a) permits: `present` / `blank`, never a count.
    pub storage: Option<String>,

    // --- operation (VERIFY.md 10.6) ----------------------------------------------------
    /// The kill line's GPIO number, so the row names the pad it read.
    pub radio_gpio: Option<u8>,
    /// The pad level as it reads right now.
    pub radio: Option<String>,
    /// One of exactly two rows where semantic colour survives on S-46 (11.6), because a
    /// device not holding its radio in reset is a different situation from a field the
    /// reader is being asked to compare - and even there the WORD carries the meaning.
    pub radio_ok: bool,
    pub self_test: Option<String>,
    pub self_test_ok: bool,
}

/// On-screen keyboard page. Shared vocabulary: the keyboard component draws it, and the
/// two screens that carry a keyboard own one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Page {
    Lower,
    Upper,
    Digits,
    Symbols,
}

/// The C4c fill time: how long an irreversible action's button must be held before it
/// fires (UX-SCREENS.md C4c). A constant, never a setting - a user-shortenable hold is a
/// user-shortenable safety interlock.
pub const HOLD_MS: u32 = 1500;

/// Fill of a hold-to-confirm button after `held_ms`, in permille of [`HOLD_MS`].
///
/// Permille rather than a float: this crate has no FPU on the target and the value is a
/// pixel width in the end, so integer math all the way to the trough is both exact and
/// what the drawing code wants.
pub fn hold_fill_permille(held_ms: u32) -> u32 {
    held_ms.saturating_mul(1000).checked_div(HOLD_MS).unwrap_or(1000).min(1000)
}

/// A press in flight, for the screens that render one (the C4c hold bar).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Press {
    /// The region the Down landed on, or `None` if it landed on bare paper.
    pub id: Option<RegionId>,
    /// Milliseconds the finger has been down, as [`Ui::tick`] has been told.
    pub held_ms: u32,
}

// ---------------------------------------------------------------------------------------
// The card, as the ingress screens read it (S-27, S-28)
// ---------------------------------------------------------------------------------------

/// Which files S-28 is listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileFilter {
    /// `.psbt` files, plus directories so the tab can still be navigated.
    PsbtOnly,
    /// Everything the card holds. The escape hatch for a mis-extensioned file, reached
    /// through [`RegionId::FileShowAll`] - hiding a file the user can plainly see on the
    /// card is how a picker sends someone hunting for a transaction that is right there.
    All,
}

/// What one row of the picker is, as far as a screen needs to know.
///
/// The extensions this device acts on, and one bucket for everything else. Deliberately
/// NOT "is this really a PSBT": deciding that belongs to the decoder, which already owns
/// the magic check and already writes the sentence a user acts on, and answering it here
/// would mean opening every file on the card to draw a list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    Directory,
    Psbt,
    /// `.txn`, the finalized-transaction file.
    Txn,
    /// `.txt`, which is how the Coldcard dialect ships multisig descriptors.
    Text,
    /// `.json`, the coordinator export bodies.
    Json,
    Other,
}

/// One row of S-28, and the value [`UiRequest::LoadPsbt`] names.
///
/// Everything here came off a FAT directory entry, which is untrusted input that someone
/// else wrote: the embedder has already bounded and validated it (`notyas_wallet::sd`
/// does the deciding) and this is what survived. The UI renders it and re-derives none of
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRow {
    /// The name exactly as it is on the card, which is also the name a request carries
    /// back. Never shortened for display: a truncated name is a name the user cannot
    /// match against what their computer wrote.
    pub name: String,
    pub kind: FileKind,
    pub len: u32,
    /// The directory entry's timestamp, already rendered ("17 Aug 14:02"). A STRING
    /// because this crate has no clock and no calendar, and because the device makes no
    /// timezone claim about a number some other machine wrote. Empty where the entry
    /// carries none, which renders as a blank column rather than as an invented date.
    pub modified: String,
    /// The entry claims more than the transfer cap. The row is still drawn - a file the
    /// user can see on the card must be findable on the screen - and it is not selectable,
    /// and the refusal states the cap.
    pub oversize: bool,
}

/// One directory of the card, as S-28 shows it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CardListing {
    /// The directory listed. Empty is the card root; anything else is the one level below
    /// it that S-28's depth limit permits.
    pub dir: String,
    /// Rows in the order they will be drawn, which is the order the embedder sorted them
    /// into. The screen does not re-sort: the row a user taps has to be a function of what
    /// they were shown, not of a layout whoever wrote the card chose.
    pub rows: Vec<FileRow>,
    /// The walk stopped at its entry bound. The screen says so rather than implying the
    /// card holds only this.
    pub truncated: bool,
    /// Entries dropped because their names could not be validated. Counted, never
    /// transliterated: a name this device cannot open must not reach a row.
    pub rejected: u16,
}

/// What the std side made of a [`UiRequest::ListCard`].
///
/// Three variants, and the two failures are separate because they are two different
/// remedies: a slot with nothing in it is answered by inserting a card, and a card that
/// mounted and would not list is answered by a different card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CardOutcome {
    Listed(CardListing),
    /// R-23. No card in the slot, or it did not mount.
    NoCard,
    /// The card could not be listed. The sentence is the embedder's, because the fault is
    /// its filesystem's - or its build's - to describe.
    Unreadable(String),
}

// ---------------------------------------------------------------------------------------
// Repairing a card the device cannot read (S-49)
// ---------------------------------------------------------------------------------------

/// A card that can be repaired by writing a filesystem into the partition it already has.
///
/// Every field is a FACT the embedder read off the hardware, already rendered, because
/// this crate has neither a driver nor a partition-table parser and must not grow either.
/// The fixed copy - what a format destroys, what it cannot undo, what it does not touch -
/// belongs to the screen and is frozen there, which is the same split
/// [`RefusalNotice`] draws between a code's ratified sentences and what happened to one
/// file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatTarget {
    /// The MBR partition entry that will be written into, 1..=4.
    ///
    /// On the panel and in [`UiRequest::FormatCard`], so the partition the user consented
    /// to is the partition the embedder writes. Never chosen by this crate.
    pub partition: u8,
    /// The whole card, in the units printed on its own label ("32 GB").
    pub capacity: String,
    /// The word typed back to consent: the capacity with the space taken out ("32GB").
    ///
    /// The card's own identity, on the precedent that a wallet deletion types the wallet's
    /// name. A card has no volume label to read back - an unmountable one especially - so
    /// its size is the only thing about it a user can check against the card in their
    /// hand, and checking THAT is the mistake this gate exists to catch: the wrong card in
    /// the slot.
    pub word: String,
    /// What the partition's type byte says it holds, in words. A claim somebody else
    /// wrote, rendered so the user recognises their own card, and never treated as a fact
    /// about the contents.
    pub holds: String,
    /// The partition's own size, which is not the card's when the table leaves slack.
    pub volume: String,
}

/// Why a format is not offered.
///
/// A CODE with frozen copy, on [`RefusalCode`]'s reasoning and for the same reason: what
/// this device says about somebody's card is product copy - stable across releases,
/// asserted with its exact text by CI, and measured against both panels before it ships -
/// so it belongs in this crate beside every other frozen string. What the embedder
/// contributes is the machine detail in `FormatOffer::Refused`'s `note`, which is the one
/// part it knows and this crate cannot.
///
/// The refusals are the point of the feature as much as the offer is. Formatting repairs
/// exactly one fault - a partition holding a filesystem this device cannot read - and
/// every other reason a card will not work is here, with the remedy that does apply.
/// Three sentences each, never fewer: a refusal with no way forward is an obstacle, not
/// an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatRefusal {
    /// The board has no microSD wiring this build trusts.
    NoSlot,
    /// The firmware, not the card, is why nothing can be read. Formatting here would erase
    /// a card that may be perfectly good in order to work around a build setting, which is
    /// the single worst outcome this feature has.
    FirmwareCannotRead,
    /// The card mounted and listed. There is nothing to repair, and this device does not
    /// offer to erase a working card.
    CardAlreadyReadable,
    /// Nothing answered in the slot.
    NoCard,
    /// Something else is using the card. Not reachable from the shipped screens - a format
    /// is not offered from inside a card flow - and given its own sentence anyway, because
    /// the alternative is a branch that reports one of the others and lies.
    Busy,
    /// The card answered and then would not return its first sector. Formatting writes to
    /// that same region, so it would fail too - after destroying whatever could still have
    /// been recovered.
    Hardware,
    /// The filesystem starts at LBA 0 with no table above it. Formatting would mean
    /// INVENTING a partition layout, which is a partition change and therefore refused.
    NoPartitionTable,
    /// A GPT-partitioned card, which this build's FatFs cannot address at all.
    Gpt,
    /// A table with no partitions in it. This device formats an existing partition and
    /// never creates one.
    NoPartitions,
    /// More than one partition. Carries the count, because "there are three" is the whole
    /// sentence: the device will not pick one of somebody's volumes to destroy.
    SeveralPartitions(u8),
    /// One partition entry, and it is an extended container - a chain of further volumes
    /// this device does not read. Separate from [`FormatRefusal::SeveralPartitions`]
    /// because that one states a COUNT and this is precisely the case where the count is
    /// unknown.
    ExtendedPartition,
    /// The table describes a partition that does not fit on the card.
    TableDamaged,
    /// The partition is too small to hold a filesystem.
    TooSmall,
}

impl FormatRefusal {
    /// What is true of the card. One sentence, and nothing in it to look up.
    pub fn headline(&self) -> &'static str {
        match self {
            FormatRefusal::NoSlot => "This device has no card slot.",
            FormatRefusal::FirmwareCannotRead => "This firmware cannot read cards.",
            FormatRefusal::CardAlreadyReadable => "This card is already readable.",
            FormatRefusal::NoCard => "No card answered in the slot.",
            FormatRefusal::Busy => "The card is in use.",
            FormatRefusal::Hardware => "This card has a hardware fault.",
            FormatRefusal::NoPartitionTable => "This card has no partition table.",
            FormatRefusal::Gpt => "This card uses a GPT partition table.",
            FormatRefusal::NoPartitions => "This card's partition table is empty.",
            FormatRefusal::SeveralPartitions(_) => "This card holds more than one partition.",
            FormatRefusal::ExtendedPartition => "This card has an extended partition.",
            FormatRefusal::TableDamaged => "This card's partition table is damaged.",
            FormatRefusal::TooSmall => "This card's partition is too small.",
        }
    }

    /// Why the device stops. States the LIMIT rather than blaming the card: in most of
    /// these the card is perfectly good for the machine that wrote it.
    pub fn detail(&self) -> String {
        match self {
            FormatRefusal::NoSlot => {
                String::from("No microSD wiring is verified for this board.")
            }
            FormatRefusal::FirmwareCannotRead => String::from(
                "It was built without long file names, so it refuses every card before it \
                 powers the slot. Formatting would erase the card and change nothing.",
            ),
            FormatRefusal::CardAlreadyReadable => String::from(
                "This device mounted it without trouble, so there is nothing here to \
                 repair. It does not offer to erase a working card.",
            ),
            FormatRefusal::NoCard => {
                String::from("The slot is empty, or the card did not respond at all.")
            }
            FormatRefusal::Busy => {
                String::from("Another card operation is running, so nothing can be checked.")
            }
            FormatRefusal::Hardware => String::from(
                "It answered but would not return its first sector. Formatting cannot \
                 repair that, and would overwrite data a recovery tool might still reach.",
            ),
            FormatRefusal::NoPartitionTable => String::from(
                "Its filesystem starts at the very beginning of the card. Inventing a \
                 partition layout for it is not this device's to do.",
            ),
            FormatRefusal::Gpt => String::from(
                "This device reads MBR tables only, so formatting here would not make the \
                 card readable.",
            ),
            FormatRefusal::NoPartitions => String::from(
                "This device formats a partition that already exists, and never creates \
                 one.",
            ),
            FormatRefusal::SeveralPartitions(n) => format!(
                "The table describes {n} partitions. This device will not choose which of \
                 them to erase.",
            ),
            FormatRefusal::ExtendedPartition => String::from(
                "It contains further partitions this device does not read, so it cannot \
                 even say how many volumes are on the card.",
            ),
            FormatRefusal::TableDamaged => String::from(
                "The partition it describes does not fit on the card. Writing on the \
                 strength of it would destroy data that is still recoverable.",
            ),
            FormatRefusal::TooSmall => {
                String::from("Nothing this device can build would fit in it.")
            }
        }
    }

    /// What to do instead. Ratified R-23's shape: the remedy for a card this device cannot
    /// serve is a computer that can.
    pub fn remedy(&self) -> &'static str {
        match self {
            FormatRefusal::NoSlot => "Nothing on any card is at risk.",
            FormatRefusal::FirmwareCannotRead => {
                "Install a firmware build with long file names."
            }
            FormatRefusal::CardAlreadyReadable => "Use a computer if you want to erase it.",
            FormatRefusal::NoCard => "Insert a card and check again.",
            FormatRefusal::Busy => "Wait for it to finish, then check again.",
            FormatRefusal::Hardware => {
                "Copy what you can off it on a computer, then replace it."
            }
            FormatRefusal::NoPartitionTable
            | FormatRefusal::Gpt
            | FormatRefusal::NoPartitions
            | FormatRefusal::TableDamaged => "Format it on a computer as one FAT32 partition.",
            FormatRefusal::SeveralPartitions(_) | FormatRefusal::ExtendedPartition => {
                "Use a card with a single partition."
            }
            FormatRefusal::TooSmall => "Use a larger card.",
        }
    }

    /// Every refusal, so the test that measures copy against both panels measures ALL of
    /// it rather than the one somebody remembered to add.
    pub const ALL: [FormatRefusal; 13] = [
        FormatRefusal::NoSlot,
        FormatRefusal::FirmwareCannotRead,
        FormatRefusal::CardAlreadyReadable,
        FormatRefusal::NoCard,
        FormatRefusal::Busy,
        FormatRefusal::Hardware,
        FormatRefusal::NoPartitionTable,
        FormatRefusal::Gpt,
        FormatRefusal::NoPartitions,
        // The largest count a four-entry MBR can produce.
        FormatRefusal::SeveralPartitions(4),
        FormatRefusal::ExtendedPartition,
        FormatRefusal::TableDamaged,
        FormatRefusal::TooSmall,
    ];
}

/// What the embedder found when it looked at the card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatOffer {
    Ready(FormatTarget),
    Refused {
        why: FormatRefusal,
        /// The machine detail behind the refusal - a driver error code, the sdkconfig line
        /// a build is missing - or empty where there is none.
        ///
        /// The embedder's, and the LAST thing drawn, so that a panel with no room for it
        /// loses a hex code rather than the sentence the user has to act on. Bounded and
        /// checked for printability before it is drawn, on the rule this crate applies to
        /// every string it did not write.
        note: String,
    },
}

/// What became of a format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatOutcome {
    /// The card now holds an empty filesystem. The sentence is the embedder's: it names
    /// the card and the partition it actually wrote.
    Done(String),
    /// It did not finish.
    Failed {
        why: String,
        /// Whether any part of the card may already have been overwritten.
        ///
        /// The whole reason this is a field and not a shade of the sentence: a user whose
        /// card was left untouched and a user whose card was left half-written need
        /// different things from the next minute of their life, and the second one has to
        /// be told to stop trusting the card. A write-protected card fails exactly here,
        /// because this firmware cannot see the switch (the wp line is not routed).
        wrote: bool,
    },
}

// ---------------------------------------------------------------------------------------
// Refusals (S-29 / C7)
// ---------------------------------------------------------------------------------------

/// A refusal code, and the three fixed sentences the ratified table gives it
/// (UX-SCREENS.md 3.2).
///
/// The COPY lives here and the FACTS arrive with it, and that split is the point. A
/// refusal's headline, the reason it matters and what to do about it are product copy,
/// stable across releases and asserted with their exact text by CI - so they belong in the
/// crate the screen is in, beside every other frozen string. What HAPPENED is a fact about
/// one file that only the engine knows ("Input 2 states an amount but does not include the
/// transaction it came from"), so it travels in [`RefusalNotice::happened`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalCode {
    NotOurInputs,
    MissingPrevTx,
    ChangeNotProven,
    CosignerMismatch,
    WrongNetwork,
    ImpossibleFee,
    UnsupportedSighash,
    UnexpectedTaproot,
    MalformedFile,
    SignatureCheckFailed,
    NotAPsbt,
    PsbtVersion2,
    FileTooLarge,
    NoCard,
    NoPsbtFiles,
    WriteFailed,
    /// An input claims this device's key and its script is not one this device signs.
    ///
    /// NOT in the ratified table and outside its numbering, exactly like R-20..R-25, because
    /// it is a per-variant LIFT rather than a check: the engine still files the failure under
    /// check 4 and still writes the same "what happened" line. What it lifts is the copy. The
    /// failure used to render R-04, so an ordinary single-sig spend of the user's own legacy
    /// coins was described as a cosigner substitution and the reader was told to compare
    /// registrations he did not have (KNOWN-ISSUES K31). R-04 stays reserved for a genuine
    /// mismatch in a cosigner SET - the 2021 substitution attack's own code, and the one
    /// refusal here that has to be believed the instant it appears.
    UnsupportedScript,
    /// The device cannot do this at all - not because of anything in the file.
    ///
    /// NOT in the ratified table, and deliberately outside its numbering. Every code above
    /// describes a FILE and tells the user what to do about that file; this one describes
    /// the DEVICE, and it exists so that no request in this vocabulary can be answered by
    /// silence. A build in which every screen is wired never constructs it, which is the
    /// only sense in which it is temporary - the alternative it replaces is a handler that
    /// logs and returns, and this codebase has shipped three of those.
    NotInThisBuild,
}

impl RefusalCode {
    /// The stable code, right-aligned in C7's header band.
    pub fn code(self) -> &'static str {
        match self {
            RefusalCode::NotOurInputs => "R-01",
            RefusalCode::MissingPrevTx => "R-02",
            RefusalCode::ChangeNotProven => "R-03",
            RefusalCode::CosignerMismatch => "R-04",
            RefusalCode::WrongNetwork => "R-05",
            RefusalCode::ImpossibleFee => "R-06",
            RefusalCode::UnsupportedSighash => "R-07",
            RefusalCode::UnexpectedTaproot => "R-08",
            RefusalCode::MalformedFile => "R-09",
            RefusalCode::SignatureCheckFailed => "R-10",
            RefusalCode::NotAPsbt => "R-20",
            RefusalCode::PsbtVersion2 => "R-21",
            RefusalCode::FileTooLarge => "R-22",
            RefusalCode::NoCard => "R-23",
            RefusalCode::NoPsbtFiles => "R-24",
            RefusalCode::WriteFailed => "R-25",
            RefusalCode::UnsupportedScript => "R-26",
            RefusalCode::NotInThisBuild => "R-00",
        }
    }

    /// The headline in the C7 band.
    pub fn headline(self) -> &'static str {
        match self {
            RefusalCode::NotOurInputs => "These inputs are not from this wallet",
            RefusalCode::MissingPrevTx => "Missing the previous transaction",
            RefusalCode::ChangeNotProven => "Change output not proven",
            RefusalCode::CosignerMismatch => "Cosigner keys do not match",
            RefusalCode::WrongNetwork => "Wrong network",
            RefusalCode::ImpossibleFee => "Fee is impossible",
            RefusalCode::UnsupportedSighash => "Unsupported signature type",
            RefusalCode::UnexpectedTaproot => "Unexpected taproot data",
            RefusalCode::MalformedFile => "This file is malformed",
            RefusalCode::SignatureCheckFailed => "Signature check failed",
            RefusalCode::NotAPsbt => "This file is not a PSBT",
            RefusalCode::PsbtVersion2 => "PSBT version 2 is not supported",
            RefusalCode::FileTooLarge => "File is too large",
            RefusalCode::NoCard => "No card detected",
            RefusalCode::NoPsbtFiles => "No PSBT files on this card",
            RefusalCode::WriteFailed => "Card write failed",
            RefusalCode::UnsupportedScript => "Not a script this device signs",
            RefusalCode::NotInThisBuild => "This build cannot do that",
        }
    }

    /// C7's "Why this matters": the attack or the fault this refusal defends against.
    ///
    /// `None` on the two codes the ratified table leaves blank, and only those two. They
    /// are the codes about the CARD rather than about a transaction - there is no attack
    /// behind an empty slot - and a fabricated sentence there would teach a user to skim
    /// the section on the codes where it carries the whole warning.
    pub fn matters(self) -> Option<&'static str> {
        match self {
            RefusalCode::NotOurInputs => Some("Signing needs the wallet that owns the coins."),
            RefusalCode::MissingPrevTx => Some(
                "Without it, nothing proves what these coins are worth. Telling a signer a \
                 false amount is how it is tricked into paying its balance as a fee, and \
                 with more than one input this device cannot rule that out.",
            ),
            RefusalCode::ChangeNotProven => {
                Some("This is exactly what an attacker does to redirect your change.")
            }
            RefusalCode::CosignerMismatch => {
                Some("A substituted cosigner key sends your coins to someone else's multisig.")
            }
            RefusalCode::WrongNetwork => Some(
                "Signing across networks can expose keys that were meant to stay separate.",
            ),
            RefusalCode::ImpossibleFee => {
                Some("A negative fee means the file is corrupt or hostile.")
            }
            RefusalCode::UnsupportedSighash => Some(
                "notyas signs SIGHASH_ALL only. Other types let the outputs be changed \
                 after you sign.",
            ),
            RefusalCode::UnexpectedTaproot => {
                Some("Signing data the device cannot interpret is signing a blank cheque.")
            }
            RefusalCode::MalformedFile => {
                Some("A signer that accepts malformed input is a signer that can be steered.")
            }
            RefusalCode::SignatureCheckFailed => Some(
                "This is a device fault, not a problem with your transaction. Nothing was \
                 signed and nothing was written.",
            ),
            RefusalCode::NotAPsbt => Some("The device reads PSBT files only."),
            RefusalCode::PsbtVersion2 => Some(
                "This device reads version 0, which is what wallet software produces today.",
            ),
            RefusalCode::FileTooLarge => {
                Some("The device holds the whole transaction in memory to check it.")
            }
            RefusalCode::NoCard | RefusalCode::NoPsbtFiles => None,
            RefusalCode::WriteFailed => Some("The file on the card is incomplete."),
            RefusalCode::UnsupportedScript => Some(
                "This device signs only script types it can verify end to end. Anything \
                 else is refused rather than signed blind.",
            ),
            RefusalCode::NotInThisBuild => Some(
                "A device that quietly does nothing teaches you that an operation \
                 succeeded.",
            ),
        }
    }

    /// C7's "What to do": the user's next action, always present.
    pub fn todo(self) -> &'static str {
        match self {
            RefusalCode::NotOurInputs => "Open that wallet and load the file again.",
            // The old sentence named one remedy, and it was one the wallet that most often
            // raises this refusal cannot perform: a watch-only BlueWallet import has no
            // previous transactions to attach. Coin control is the remedy that wallet does
            // have, and it is first because a single-input spend is a file this device now
            // signs.
            RefusalCode::MissingPrevTx => {
                "Spend a single coin - use coin control to select one - or re-export from \
                 software that includes full previous transactions (Sparrow, Electrum, \
                 Bitcoin Core), then load it again."
            }
            RefusalCode::ChangeNotProven => {
                "Do not sign. Check the transaction in your wallet software."
            }
            RefusalCode::CosignerMismatch => {
                "Compare the registration on all your devices. Import it again if it \
                 changed legitimately."
            }
            RefusalCode::WrongNetwork => "Open the testnet wallet, or load a mainnet transaction.",
            RefusalCode::ImpossibleFee => "Rebuild the transaction in your wallet software.",
            RefusalCode::UnsupportedSighash => {
                "Rebuild the transaction with the default signature type."
            }
            RefusalCode::UnexpectedTaproot => "Rebuild the transaction without it.",
            RefusalCode::MalformedFile => "Re-export the transaction and load it again.",
            RefusalCode::SignatureCheckFailed => {
                "Run Verify device and report this with the details below."
            }
            RefusalCode::NotAPsbt => "Check the file, or choose a different one.",
            RefusalCode::PsbtVersion2 => "Export as a version 0 PSBT.",
            RefusalCode::FileTooLarge => "Split the transaction, or use fewer inputs.",
            RefusalCode::NoCard => "Insert a FAT32-formatted card and try again.",
            RefusalCode::NoPsbtFiles => "Copy the transaction onto the card, or show all files.",
            RefusalCode::WriteFailed => {
                "Delete that file, then retry - or show the signed transaction as a QR instead."
            }
            // Two sentences because two situations reach this code and they have different
            // remedies. The second is the one a sender can act on today: a wrapped-segwit
            // input of ours whose redeem script the coordinator left out of the file looks
            // like a bare P2SH here, and re-exporting it with the field restores it.
            RefusalCode::UnsupportedScript => {
                "Spend these coins from a wallet that supports this script type. If this is \
                 a wrapped-segwit coin, re-export the transaction with its redeem script \
                 included."
            }
            RefusalCode::NotInThisBuild => {
                "Update to a firmware release that carries this screen."
            }
        }
    }
}

/// One refusal, ready to render as S-29.
///
/// A refusal that arrives AFTER signing has started returns the user to the wallet home
/// rather than to the source screen, and says so; [`RefusalNotice::after_signing`] is that
/// distinction, because "load a different file" is the wrong instruction to give someone
/// whose device just failed its own post-sign gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusalNotice {
    pub code: RefusalCode,
    /// What happened to THIS file, in the copy vocabulary and naming the index, the path
    /// or the name involved. Supplied by the embedder because only the engine knows it.
    pub happened: String,
    /// The machine facts C7's `[ Show details ]` reveals: indexes, txids, the claimed
    /// path, the script type, the check number. Photographed for bug reports, so it is
    /// complete and it never contains key material - which costs nothing, because every
    /// refusal is decided before any key exists.
    pub details: String,
    /// The refusal happened after the hold-to-sign, so the way out is the wallet home and
    /// the screen adds "Nothing was signed and nothing was written."
    pub after_signing: bool,
}

// ---------------------------------------------------------------------------------------
// The transaction under review (S-30..S-36)
// ---------------------------------------------------------------------------------------

/// The fee, and whether it is a number any transaction carrying this device's signature
/// would actually have to pay.
///
/// There is deliberately no accessor that hands out the amount alone: a caller has to
/// match, and matching is how the caveat reaches the screen. A signer that renders an
/// unprovable number the same way it renders a proven one has lied by omission.
///
/// This mirrors the firmware's own `signing::ReviewedFee` across the no_std boundary, and
/// the exhaustive match that converts one into the other is the pin between them: neither
/// can grow a third state without the other refusing to compile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewedFee {
    /// No input amount is left resting on the file's word: each was either proven against
    /// its own previous transaction or made binding by a signature this device is about to
    /// add ([`AmountProof::BoundByOurSignature`]).
    Enforced(Amount),
    /// At least one input's amount is the file's word and no signature of ours makes it
    /// binding. A lower bound on what this transaction costs, never a measurement, and it
    /// renders as such beside the input whose [`AmountProof`] is
    /// [`AmountProof::ClaimedByFile`].
    Stated(Amount),
}

/// One entry of S-35, in the order it is numbered.
///
/// Two lines and never one: what it is, and why it matters. A warning that is a bare noun
/// phrase teaches the reader to skip the page, which is the page the whole review builds
/// towards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxWarning {
    pub headline: String,
    pub detail: String,
}

/// Everything the review pages render, exactly as the engine established it.
///
/// The fact vectors are notyas-core's own types, carried rather than re-modelled, for the
/// reason this crate has given since 0.1.0: one pipeline, many renderers. The screen reads
/// [`OutputFacts::role`] - what the device PROVED - and never `claims_our_key`, which is
/// what the file asserted; the difference between those two is the change-confusion attack.
///
/// The presentation facts beside them are the ones the engine has no opinion about: which
/// file this came from, which wallet is open, the vsize estimate, and the warnings, whose
/// thresholds are ratified policy and therefore the embedder's to apply.
///
/// Nothing here is secret. A PSBT is public, its addresses are public, and the file itself
/// arrived over a card anyone could read - which is why this struct is `Clone` and
/// printable and carries no wipe obligation, unlike everything on the create path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxReview {
    /// Every input, in the transaction's own order, INCLUDING the ones that are not ours.
    /// A signer that hides them is a signer that can be shown one thing and sign another.
    pub inputs: Vec<InputFacts>,
    pub outputs: Vec<OutputFacts>,
    pub input_total: Amount,
    pub output_total: Amount,
    pub fee: ReviewedFee,
    pub lock_time: LockTime,
    /// Any input signals replaceability (BIP125).
    pub rbf_signaled: bool,
    pub network: bitcoin::Network,
    /// The open wallet's master fingerprint, 8 lowercase hex - the same identity
    /// vocabulary [`WalletInfo`] uses.
    pub fingerprint: String,
    /// The open wallet's name, for "all from savings (a1b2c3d4)".
    pub wallet: String,
    /// The file this was read from, for the review bar and the deliver notice.
    pub source: String,
    /// How many inputs this device would sign. Zero is a wrong-wallet screen, not an
    /// error - and it is R-01 before this struct is ever built.
    pub signable_inputs: usize,
    /// Unknown and proprietary key-value pairs the file carries. Preserved through signing
    /// untouched and never read for any decision; the count exists so the screen can say
    /// they are there.
    pub unknown_fields: usize,
    pub serialized_len: usize,
    /// SHA-256 of the exact bytes reviewed, 64 lowercase hex. The deliver screen prints
    /// its leading bytes so that what left the device can be tied to what was on screen.
    pub psbt_id: String,
    /// Virtual size for the fee-rate row.
    pub vsize: u32,
    /// The vsize is exact, and it is exact for one shape only: every input a taproot
    /// key-path spend under SIGHASH_DEFAULT, where BIP-341 fixes the Schnorr signature at
    /// 64 bytes with no encoding left to vary.
    ///
    /// False for everything else, multisig or not. An ECDSA signature is DER, and low-R
    /// grinding (ratified Q3) BOUNDS it at 71 bytes rather than fixing it there - a leading
    /// zero in S encodes a byte shorter about one signature in 64 - so a vsize quoted
    /// before the signatures exist is an estimate, and the fee page says "estimated". An
    /// exact-looking number that shifts after signing erodes trust in every other number on
    /// the screen.
    pub vsize_exact: bool,
    /// Legal but notable, collected for S-35. Empty is a page that reads "No warnings.",
    /// never a page that is absent: the page count has to be stable and the hold has to be
    /// in the same place every time.
    pub warnings: Vec<TxWarning>,
}

/// Add amounts without an overflow panic.
///
/// `Amount: Add` panics on overflow, and a review screen is the last place in the product
/// that may abort: the values here came off a card someone else wrote, and the engine
/// bounds the transaction rather than the arithmetic a renderer performs over it.
/// Saturating is the honest failure - a total pinned at 21 million times a hundred million
/// is visibly wrong on a screen, where a panic is a dead device holding an unsigned file.
fn sum_sats(values: impl Iterator<Item = Amount>) -> Amount {
    Amount::from_sat(values.fold(0u64, |acc, v| acc.saturating_add(v.to_sat())))
}

impl TxReview {
    /// What this transaction actually sends away, which is the number a user has to
    /// internalise on a signer. Change is excluded by definition.
    ///
    /// Summed here rather than carried, because it is a sum over a classification the
    /// engine already made and the UI cannot second-guess: [`OutputRole::is_change`] is
    /// the only question asked, and it is the core's own answer to it. The same reasoning
    /// as [`StoredCounts::of`].
    pub fn leaving(&self) -> Amount {
        sum_sats(self.outputs.iter().filter(|o| !o.role.is_change()).map(|o| o.value))
    }

    /// What comes back to this wallet as proven change.
    pub fn change(&self) -> Amount {
        sum_sats(self.outputs.iter().filter(|o| o.role.is_change()).map(|o| o.value))
    }

    /// Inputs whose amount rests on the file's word and nothing else.
    ///
    /// [`AmountProof::BoundByOurSignature`] is deliberately NOT counted here, and the
    /// comparison is a `==` rather than a `!=` for that reason: an amount a signature of
    /// ours makes binding is not one the reader has to discount, so the warning band this
    /// number raises stays silent on an ordinary single-input spend. Only the file's bare
    /// word counts.
    pub fn unproven_amounts(&self) -> usize {
        self.inputs
            .iter()
            .filter(|i| i.amount_proof == AmountProof::ClaimedByFile)
            .count()
    }

    /// How many pages the C5 traversal has: the overview, one per input, one per output,
    /// the fee page and the warnings page.
    ///
    /// Pagination is this crate's own arithmetic - it is a property of the screen, not of
    /// the transaction - and it lives here so that the page count in the bar, the visited
    /// set that gates the hold, and the page the Next button lands on are one definition
    /// rather than three that can disagree by one.
    pub fn pages(&self) -> usize {
        3 + self.inputs.len() + self.outputs.len()
    }
}

/// What the std side made of a [`UiRequest::LoadPsbt`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PsbtOutcome {
    Reviewed(TxReview),
    /// The card, the decoder or one of the ten checks refused. There is no third answer:
    /// a file that is not refused is reviewed, and a file that is refused is never
    /// partially reviewed.
    Refused(RefusalNotice),
}

// ---------------------------------------------------------------------------------------
// The signed transaction and its delivery (S-37, S-38)
// ---------------------------------------------------------------------------------------

/// One file a delivery will write, or has written.
///
/// Named BEFORE the write, which is what makes the C12 notice worth something: invariant
/// 2b requires the announcement to carry the value the writer is later handed, and this is
/// that value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    pub name: String,
    pub bytes: u32,
}

/// What signing produced, as the deliver screen reads it.
///
/// The BYTES are not here and never will be. They live on the std side with the seed that
/// made them, the UI asks for them to be written, and a signed transaction therefore
/// exists in exactly one place on this device - which is also why leaving S-38 has to be a
/// request ([`UiRequest::DiscardSigned`]) rather than a screen change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTx {
    /// Signatures this device added.
    pub signed_inputs: u16,
    /// Signatures the post-sign gate re-verified against a digest recomputed from the PSBT
    /// alone. Equal to `signed_inputs` on every path that reaches this screen - the gate
    /// refuses rather than reporting a shortfall - and shown anyway, because a gate whose
    /// result nobody can see is a gate nobody can tell has stopped running.
    pub verified_inputs: u16,
    /// Inputs the review said this device would sign.
    pub signable_inputs: u16,
    /// The transaction is complete and ready to broadcast. False for a multisig that still
    /// needs another cosigner, where S-38 says so and omits the `-final.txn` line.
    pub complete: bool,
    /// The files a write will create, in the order the notice lists them.
    pub artifacts: Vec<Artifact>,
    /// SHA-256 of the bytes that were reviewed, 64 lowercase hex - the same value
    /// [`TxReview::psbt_id`] carried, so the screen can tie what left the device to what
    /// was on the panel.
    pub psbt_id: String,
}

/// What the std side made of a [`UiRequest::SignTx`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignOutcome {
    Signed(SignedTx),
    /// The post-sign gate refused (R-10), or the wallet holding the seed is not the wallet
    /// the review was taken under. Either way NO file exists: signing builds a new PSBT and
    /// returns it only on success, so there is nothing partially signed to deliver.
    Refused(RefusalNotice),
}

/// What the std side made of a [`UiRequest::ShowSignedQr`].
///
/// Two variants, and the second is not a formality. S-38 decides whether to OFFER the
/// exit from a length rule it shares with the encoder, but the encoder is the thing that
/// actually runs, and it refuses bytes that are not a BIP-174 file as well as bytes that
/// are too many. A device that reached that arm has a bug in it; what this variant buys is
/// that the bug arrives as a sentence on the panel instead of as a button that does
/// nothing, which is the failure the whole request/answer vocabulary exists to prevent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignedQrOutcome {
    /// The finished symbol, ready to draw. Public data: a signed transaction is about to
    /// be broadcast, so the objection to putting one on a screen is legibility and not
    /// confidentiality.
    Symbol(QrData),
    /// Nothing is going on the glass, and this is the sentence that says why. The
    /// transaction is untouched and still deliverable by card.
    Refused(String),
}

/// What the std side made of a [`UiRequest::WriteSigned`].
///
/// Four answers because S-38 does four different things with them, and three of the four
/// are not failures of the same kind: a collision is a question for the user, an empty slot
/// is a remedy they can perform standing there, and a part-written file is a mess they have
/// to clean up before reusing the name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteOutcome {
    /// The files that landed, as they landed.
    Written(Vec<Artifact>),
    /// These names are already on the card. S-38 opens the C4a overwrite confirm and
    /// raises [`UiRequest::WriteSigned`] again with `overwrite` set.
    Collision(Vec<String>),
    /// R-23, as an inline band rather than a screen: the transaction is still signed and
    /// still deliverable, and a screen change would take the user away from the only place
    /// they can deliver it from.
    NoCard,
    /// R-25. The sentence names how far the write got, because the file on the card is
    /// incomplete and has to be deleted before the name is reused.
    Failed(String),
}

// ---------------------------------------------------------------------------------------
// Save address to SD (receive screen)
// ---------------------------------------------------------------------------------------

/// What the std side made of a [`UiRequest::SaveAddress`].
///
/// The file name on success, or the reason it failed. Neither is secret: a receive
/// address is public data and a file name is what the user looks for on the card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SaveAddrResult {
    /// The file that was written, as the card sees it.
    Saved(String),
    /// This name is already on the card and the write was refused rather than silently
    /// replacing it. Tapping Save again raises [`UiRequest::SaveAddress`] with
    /// `overwrite` set, which is the confirm.
    Collision(String),
    /// Why nothing was written. "No card" is the common one on hardware without a
    /// card-detect line.
    Failed(String),
}

// ---------------------------------------------------------------------------------------
// The multisig registry (S-41, S-42, S-43)
// ---------------------------------------------------------------------------------------

/// One cosigner of a multisig wallet, in full. Nothing here is masked, ever: an xpub is
/// public and comparing it against the other signers is the entire defence against a
/// substituted key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CosignerRow {
    /// 8 lowercase hex.
    pub fingerprint: String,
    /// The origin path this cosigner's key sits at.
    pub path: String,
    /// The account xpub, complete and never abbreviated.
    pub xpub: String,
    /// This device. Proven by derivation from the live seed, never read off the file.
    pub ours: bool,
}

/// A multisig registration this device has proven it is a member of, as S-41 and S-43 read
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationInfo {
    /// The registry slot this record lives in, as the embedder read it. The handle
    /// [`UiRequest::DeleteRegistration`] names; the UI never invents one.
    pub slot: u8,
    pub name: String,
    pub threshold: u8,
    pub cosigners: u8,
    /// The script type in words, e.g. "P2WSH". Supplied rather than derived, like
    /// [`WalletInfo::script_type`].
    pub script: String,
    /// The account derivation this registration sits at.
    pub derivation: String,
    /// This device's own cosigner fingerprint within the set.
    pub fingerprint: String,
    pub network: bitcoin::Network,
    /// The stored record proved out against the live seed at open time. False is a record
    /// that did not: the row renders in DANGER and reads "unreadable - delete and import
    /// again", because a registration the user believes is live and is not would refuse
    /// their next PSBT with nothing to say why.
    pub proven: bool,
}

/// A registration waiting to be approved: everything S-42 pages through.
///
/// The membership PROOF has already happened - [`UiRequest::ImportRegistration`] is what
/// performs it, and a wallet this device is not a cosigner of is R-04 and never a page.
/// What is left for the user is the comparison this screen exists for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationReview {
    pub name: String,
    pub threshold: u8,
    /// The descriptor function, e.g. "sortedmulti".
    pub policy: String,
    /// The script type in words, e.g. "P2WSH (native segwit)".
    pub script: String,
    /// The account derivation this registration sits at.
    pub derivation: String,
    pub network: bitcoin::Network,
    /// Every cosigner, in the order the registration orders them.
    pub cosigners: Vec<CosignerRow>,
    /// 1-based position of this device in the set, for "This device is cosigner 1 of 3".
    /// Zero would be a wallet this device is not in, which cannot reach this struct.
    pub ours: u8,
    /// The first receive address this registration produces, complete and chunked by the
    /// screen. The value page 5 asks the user to compare on their other signers before the
    /// wallet is used.
    pub first_address: String,
    /// The canonical descriptor this device will store, which is its own rendering and not
    /// the text that came in.
    pub descriptor: String,
    /// The file was a Coldcard multisig `.txt` and was converted on ingest. Page 1 says so.
    pub converted: bool,
    /// An identical registration is already stored. Approval opens the C4a "Replace it?"
    /// confirm and raises [`UiRequest::ApproveRegistration`] with `replace` set.
    pub duplicate: bool,
}

/// What the std side made of a [`UiRequest::ImportRegistration`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportOutcome {
    Pending(RegistrationReview),
    /// The card, the parser, or the membership proof refused. R-04 is the one that matters
    /// most: importing a wallet you cannot sign for is how a substituted key gets accepted.
    Refused(RefusalNotice),
}

/// What the std side made of a [`UiRequest::ApproveRegistration`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistrationOutcome {
    Saved(RegistrationInfo),
    Refused(RefusalNotice),
}

/// What the std side made of a [`UiRequest::DeleteWallet`].
///
/// Three variants and not `Result<(), String>`, because "it failed" is two different
/// situations for the owner of a wallet and the device has to say which. The split is by
/// WHAT THE USER MUST DO NEXT, which is the only distinction a screen can render:
///
/// - [`DeleteOutcome::Gone`] - it is done, and the list is the evidence.
/// - [`DeleteOutcome::Refused`] - nothing was destroyed and the device is as it was. Try
///   again, or do not.
/// - [`DeleteOutcome::Damaged`] - something WAS destroyed, or the device cannot say
///   whether the words are gone. Never a refusal, because a refusal reads as "nothing
///   happened" and something did.
///
/// The embedder writes the sentence; this crate renders it. A delete has too many ways to
/// go wrong for a fixed catalogue of copy, and the one thing that must not happen is a
/// failure with nothing to show for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeleteOutcome {
    /// The record and its `registrations` registry records are gone, and the slot was read
    /// back afterwards to prove it. The count is the one that actually happened, which is
    /// not necessarily the one the consequence sheet named a minute earlier.
    Gone { registrations: u8 },
    /// Nothing was destroyed.
    Refused(String),
    /// Something was destroyed, or the outcome cannot be established. Either way the user
    /// must not walk away believing the wallet is safely gone or safely intact.
    Damaged(String),
}

/// What the std side made of a [`UiRequest::RecoveryWords`].
///
/// The words themselves, or the reason there are none to show. `Zeroizing`, and the screen
/// that receives it never copies out of it: the display borrows into this buffer and the
/// buffer is wiped when the screen is dropped, which `Ui::lock` does to the whole
/// navigation stack on the auto-lock.
pub enum WordsOutcome {
    /// The normalized phrase: BIP-39 words separated by single ASCII spaces.
    Words(Zeroizing<String>),
    /// Why the record could not be read. Kept SHORT by the embedder: it is drawn in the
    /// space Q22's sentence would have taken on a screen with no room to spare.
    Refused(String),
}

impl WordsOutcome {
    /// The words, taken into a self-wiping buffer at exactly the length they need.
    ///
    /// For callers that hold a `&str` - the simulator, the tests. The firmware uses the
    /// variant directly, because the record decoder already hands it a `Zeroizing<String>`
    /// and MOVING that is one copy fewer than making another.
    pub fn words(phrase: &str) -> WordsOutcome {
        let mut buf = String::with_capacity(phrase.len());
        buf.push_str(phrase);
        WordsOutcome::Words(Zeroizing::new(buf))
    }
}

impl fmt::Debug for WordsOutcome {
    /// Hand written for the reason every secret-bearing type in this workspace has one: a
    /// `{:?}` in a log line or a panic payload copies the words somewhere nothing wipes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WordsOutcome::Words(_) => f.write_str("WordsOutcome::Words(<redacted>)"),
            WordsOutcome::Refused(why) => write!(f, "WordsOutcome::Refused({why:?})"),
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
