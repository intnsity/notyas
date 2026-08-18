// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! notyas-ui - the board-independent UI layer of the notyas device.
//!
//! One deep module with a three-call interface: construct [`Ui`] with the display size,
//! feed it [`TouchEvent`]s, and ask it to [`Ui::draw`] into any `Rgb565`
//! [`DrawTarget`] - the device framebuffer and the host simulator (tools/uisim) are the
//! same code path. Every screen repaints in full (no dirty rectangles in 0.1.0), every
//! rectangle derives from the display size through [`layout::Metrics`] (no absolute
//! coordinates; the primary panel is 720x720 but 800x480 must lay out correctly too),
//! and the pipeline itself is [`notyas_core`] - this crate renders what the core
//! computes and computes nothing of its own.
//!
//! # Secrecy rules (non-negotiable; desktop BigDice house law)
//!
//! - Masked values are a FIXED-length bullet run ([`theme::MASK_BULLETS`] /
//!   [`theme::MASK_WORD_BULLETS`]), never a run proportional to the secret.
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
mod screens;
pub mod theme;

use alloc::string::String;
use alloc::vec::Vec;
use core::convert::Infallible;

use embedded_graphics::draw_target::DrawTarget;
use embedded_graphics::geometry::{Dimensions, Point, Size};
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::primitives::Rectangle;
use zeroize::{Zeroize, Zeroizing};

use layout::{Metrics, Rect};
use notyas_core::bip39::{self, Mnemonic, MnemonicMode, WordCount, MIN_SECURE_BITS};
use notyas_core::derive::{ChildIndex, Scheme};
use notyas_core::entropy::{parse_dice, DiceEntropy};
use notyas_core::report::{self, Parameters, Report};

/// Crate version, shown on the Home screen. The workspace releases in lockstep, so this
/// is the product version too.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Receive addresses derived per scheme. The device screen is the bound here, exactly as
/// each desktop front end picks its own count.
pub const ADDRESS_ROWS: u32 = 5;

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
    /// RAW / FIXED mode toggle on the dice screen.
    ModeToggle,
    DiceDone,
    /// Opens the reveal-confirm modal on the mnemonic screen.
    Reveal,
    /// Mnemonic screen -> passphrase screen.
    Next,
    /// "Use passphrase" opt-in toggle.
    PassToggle,
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
    ModalCancel,
    ModalConfirm,
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
            rolls: Zeroizing::new(String::new()),
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

pub(crate) struct PassState {
    pub source: SeedSource,
    /// The desktop's explicit opt-in: off means the seed derives with an empty
    /// passphrase, and the screen says so.
    pub enabled: bool,
    pub entry: Zeroizing<String>,
    pub confirm: Zeroizing<String>,
    pub focus: PassFocus,
    pub page: Page,
}

pub(crate) struct SchemesState {
    /// The full pipeline output; its own Drop wipes the secrets it holds.
    pub report: Report,
    pub tab: usize,
    pub scroll: i32,
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
        }
    }

    pub fn screen(&self) -> ScreenId {
        match self.state {
            State::Home => ScreenId::Home,
            State::Dice(_) => ScreenId::DiceEntry,
            State::Mnemonic(_) => ScreenId::MnemonicDisplay,
            State::Phrase(_) => ScreenId::PhraseEntry,
            State::Passphrase(_) => ScreenId::PassphraseEntry,
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
        screens::regions(&self.m, &self.state)
    }

    /// Feed one touch event. Taps fire on Up over the same region the Down hit;
    /// vertical drags scroll the scrollable screens (mnemonic grid, scheme details).
    pub fn touch(&mut self, ev: TouchEvent) {
        match ev {
            TouchEvent::Down { x, y } => {
                let id = self.hit(x, y);
                self.pressed = Some(Pressed { id, last_y: y, moved: 0 });
            }
            TouchEvent::Move { x: _, y } => {
                let Some(p) = self.pressed.as_mut() else { return };
                let dy = y - p.last_y;
                p.last_y = y;
                p.moved += dy.abs();
                if p.moved > DRAG_SLOP {
                    p.id = None;
                }
                self.scroll_by(-dy);
            }
            TouchEvent::Up { x, y } => {
                let Some(p) = self.pressed.take() else { return };
                let (Some(down), Some(up)) = (p.id, self.hit(x, y)) else { return };
                if down == up && p.moved <= DRAG_SLOP {
                    self.activate(down);
                }
            }
        }
    }

    /// Repaint the whole screen. The only output path this crate has.
    pub fn draw<D: DrawTarget<Color = Rgb565>>(&self, target: &mut D) -> Result<(), D::Error> {
        screens::draw(target, &self.m, &self.state, &self.verify)
    }

    // --- internals ---------------------------------------------------------------------

    fn hit(&self, x: i32, y: i32) -> Option<RegionId> {
        self.regions().into_iter().find(|r| r.rect.contains(x, y)).map(|r| r.id)
    }

    /// Apply a vertical scroll delta to the current screen, clamped to its content.
    fn scroll_by(&mut self, dy: i32) {
        if dy == 0 {
            return;
        }
        let limit = screens::scroll_limit(&self.m, &self.state, &self.verify);
        match &mut self.state {
            State::Mnemonic(s) if !s.modal => s.scroll = (s.scroll + dy).clamp(0, limit),
            State::Schemes(s) => s.scroll = (s.scroll + dy).clamp(0, limit),
            State::Verify { scroll } => *scroll = (*scroll + dy).clamp(0, limit),
            _ => {}
        }
    }

    /// The state machine: what a completed tap on `id` does in the current state.
    /// Unmatched combinations are ignored by construction - `regions` never offers a
    /// region the current state cannot act on.
    fn activate(&mut self, id: RegionId) {
        match (&mut self.state, id) {
            // --- global -----------------------------------------------------------------
            // Dropping the state zeroizes every secret it held (see the state types).
            (_, RegionId::Back) => self.state = State::Home,

            // --- home -------------------------------------------------------------------
            (State::Home, RegionId::HomeNewSeed) => self.state = State::Dice(DiceState::new()),
            (State::Home, RegionId::HomeVerifySeed) => {
                self.state = State::Phrase(PhraseState {
                    text: Zeroizing::new(String::new()),
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
            (State::Dice(s), RegionId::ModeToggle) => {
                s.mode = match s.mode {
                    MnemonicMode::Raw => MnemonicMode::Words(fixed_words()),
                    MnemonicMode::Words(_) => MnemonicMode::Raw,
                };
            }
            (State::Dice(s), RegionId::DiceDone) => {
                if s.effective_bits() < MIN_SECURE_BITS {
                    return; // Drawn disabled, with the reason; a tap does nothing.
                }
                if let Ok(mnem) = bip39::mnemonic_from_dice(&s.entropy, s.mode) {
                    let dice = core::mem::take(&mut s.entropy);
                    let mode = s.mode;
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
                let dice = core::mem::take(&mut s.dice);
                let mode = s.mode;
                // `s.mnem` is dropped with the state and wipes itself.
                self.state = State::Passphrase(PassState {
                    source: SeedSource::Dice { dice, mode },
                    enabled: false,
                    entry: Zeroizing::new(String::new()),
                    confirm: Zeroizing::new(String::new()),
                    focus: PassFocus::Entry,
                    page: Page::Lower,
                });
            }

            // --- phrase entry (verify existing seed) ------------------------------------
            (State::Phrase(s), RegionId::Key(c)) => {
                if s.text.len() < 1024 {
                    s.text.push(c);
                }
            }
            (State::Phrase(s), RegionId::Space) => {
                if s.text.len() < 1024 {
                    s.text.push(' ');
                }
            }
            (State::Phrase(s), RegionId::KeyBackspace) => {
                s.text.pop();
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
                    return; // Nothing typed; Done is drawn disabled.
                }
                self.state = State::Passphrase(PassState {
                    source: SeedSource::Phrase(normalized),
                    enabled: false,
                    entry: Zeroizing::new(String::new()),
                    confirm: Zeroizing::new(String::new()),
                    focus: PassFocus::Entry,
                    page: Page::Lower,
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
            (State::Passphrase(s), RegionId::KeyDone) => {
                if s.enabled && *s.entry != *s.confirm {
                    return; // Mismatch shown in danger ink; Done is drawn disabled.
                }
                let passphrase: &str = if s.enabled { &s.entry } else { "" };
                let params = Parameters {
                    mode: match &s.source {
                        SeedSource::Dice { mode, .. } => *mode,
                        // Unused on the phrase path, same placeholder the core uses.
                        SeedSource::Phrase(_) => MnemonicMode::Raw,
                    },
                    passphrase,
                    network: bitcoin::Network::Bitcoin,
                    schemes: &Scheme::ALL,
                    account: ChildIndex::ZERO,
                    change: ChildIndex::ZERO,
                    count: ADDRESS_ROWS,
                    script_type: 2,
                };
                let report = match &s.source {
                    SeedSource::Dice { dice, .. } => Report::build(dice, &params).ok(),
                    SeedSource::Phrase(text) => Report::from_phrase(text, &params),
                };
                // Both arms were validated before this screen; a None here would be a
                // core bug, and staying put beats panicking in the input path.
                if let Some(report) = report {
                    self.state = State::Schemes(SchemesState { report, tab: 0, scroll: 0 });
                }
            }

            // --- schemes ----------------------------------------------------------------
            (State::Schemes(s), RegionId::Tab(i)) if (i as usize) < Scheme::ALL.len() => {
                s.tab = i as usize;
                s.scroll = 0;
            }

            _ => {}
        }
    }
}

/// The FIXED mode's word count: 24, the Coldcard/SeedSigner-compatible full-length seed
/// (their dice math is algorithm-identical to this mode - see ARCHITECTURE.md).
fn fixed_words() -> WordCount {
    // 24 is a member of FIXED_WORD_COUNTS, so this cannot fail; unwrap_or keeps the
    // input path panic-free anyway.
    WordCount::new(24).unwrap_or_else(|_| unreachable!())
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
        Some(c) if buf.len() < 256 => buf.push(c),
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
