// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! S-30..S-37: the transaction under review, and the hold that signs it.
//!
//! This is the screen the device exists for, and its whole job is to keep one distinction
//! visible: what the engine PROVED against what the file CLAIMED. `notyas-core`'s check
//! pipeline refuses to collapse the two - [`AmountProof`] separates an amount read out of a
//! previous transaction from one asserted by the coordinator, [`OutputRole`] separates
//! change this device re-derived from change the file merely says is ours, and
//! [`ReviewedFee`] separates a fee that binds from a fee that is a lower bound. A renderer
//! that drew either side of those three pairs the same way would throw the whole pipeline
//! away at the last inch.
//!
//! # The three rules that make the distinction unmissable
//!
//! 1. **The caveat is in the WORDS, never only in the colour.** An unproven amount is
//!    written `STATED 0.05 000 000 BTC`; an unenforced fee is written
//!    `AT LEAST 0.00 004 210 BTC`. The qualifier comes out of the SAME function that
//!    produces the digits ([`input_amount_text`], [`fee_amount_text`]) and is part of the
//!    same string, so there is no code path that renders the number without it, no
//!    colour-blind reader who loses it, and no photograph of the panel that drops it.
//!    Colour and a full-width band reinforce; they never carry it alone.
//! 2. **A claim nobody proved is counted as money leaving, everywhere money is counted.**
//!    [`OutputRole::is_change`] is the only question this module asks of an output, so the
//!    overview's leaving/change split, the "Leaving this wallet" headline and the fee's
//!    percentage all partition on the core's own verdict.
//!    [`OutputRole::ClaimedButUnproven`] falls on the LEAVING side of every one of them,
//!    and the overview names it in a sentence rather than leaving it to arithmetic.
//! 3. **A refusal condition is not a page.** `ClaimedButUnproven` is R-03 and must never
//!    reach a signable review; [`ReviewState::blocker`] restates that here, at the hold, so
//!    that a file which somehow arrives with one cannot be finished off by a user who read
//!    every page and trusted the button. There is no override anywhere in this module and
//!    no way to add one without deleting `blocker` (ratified Q24).
//!
//! # The traversal and the hold
//!
//! C5: the page set is computed once from [`TxReview::pages`], which is the ONLY definition
//! of the count - the bar's `[ i / n ]`, the visited set and the Next target all read it,
//! so they cannot disagree by one. The order is fixed and semantic (overview, each input in
//! transaction order, each output in transaction order, fee, warnings) and never sorted by
//! amount: a stable order is what lets a user compare two runs of the same file.
//!
//! [`RegionId::HoldConfirm`] EXISTS only on the last page, and only once every page has
//! been seen and [`ReviewState::blocker`] is empty. It is not merely drawn disabled: the
//! rectangle is absent from `regions`, so no press can carry that id - and
//! [`ReviewState::activate`] re-asks both questions anyway, because `Ui::tick` fires a
//! filled hold by calling `activate` DIRECTLY and a screen that trusted `regions` to have
//! gated it would be trusting a caller it cannot see.
//!
//! The gesture is a hold of [`crate::HOLD_MS`] and not a tap, because a tap can be caused
//! by a jolt, a wet panel, or the second half of a double tap on the `Next >` button one
//! page earlier - and none of those may spend a signature. Releasing early, or dragging off
//! the bar, resets the fill to zero and says "Released - nothing was signed."; nothing is
//! sent, and the page is exactly as it was.
//!
//! # Leaving
//!
//! Every transition inside the signing flow is [`Nav::Enter`] and none of them pushes, so
//! review-sign-deliver occupies ONE back-stack slot and a single [`Nav::Back`] leaves the
//! whole flow for the screen that opened the sign source. Back from a review page opens a
//! C4 confirm first: an accidental Back after nine pages costs the entire reading.
//!
//! Nothing here is secret. A PSBT, its addresses and its amounts arrived on a card anyone
//! could read, so this module owns no wipe obligation and appears in no line of
//! `secrets_wipe_when_a_screen_is_dropped`.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::{format, vec};
use core::cell::Cell as CoreCell;
use core::cell::RefCell;

use embedded_graphics::draw_target::{DrawTarget, DrawTargetExt};
use embedded_graphics::pixelcolor::Rgb565;
use notyas_fonts::Atlas;

use crate::canvas::{
    button, hold_bar, panel, text, text_centered, wrap_words, ButtonKind, BODY, HEADING, MONO,
    MONO_SMALL,
};
use crate::components::{back_rect, draw_bar, draw_bar_no_back, LINE, SMALL_LINE};
use crate::danger::{Danger, DangerOutcome};
use crate::layout::{Metrics, Rect};
use crate::screens::deliver::DeliverState;
use crate::screens::refusal::RefusalState;
use crate::screens::{Answer, Ctx, Env, Nav, Outcome, Screen, State};
use crate::theme::*;
use crate::{
    hold_fill_permille, Amount, AmountProof, Claim, InputFacts, LockTime, OutputFacts, OutputRole,
    Region, RegionId, ReviewedFee, ScreenId, ScriptKind, SignOutcome, TxReview, UiRequest, HOLD_MS,
};
use notyas_core::bitcoin::{Address, Network, ScriptBuf};

// ---------------------------------------------------------------------------------------
// Frozen measurements
// ---------------------------------------------------------------------------------------

/// Inner padding of a full-width band (the badge, a warning, the summary card).
const BAND_PAD: i32 = 10;

/// Height of the C4c hold bar. A PHYSICAL minimum rather than a derived one: a finger rests
/// on it for a second and a half, and C4c asks for at least 120 px.
const HOLD_BAR_H: i32 = 120;

/// Width of the label column in a [`Row::Pair`], and therefore the value column's origin.
///
/// A constant sized to the label set rather than to the panel, on the `verify` precedent
/// and for the same reason: a label that wrapped would break the column model and a label
/// that cropped could not be identified against the wallet software beside it.
/// `the_pair_labels_fit_the_column` holds the frozen vocabulary to it. What remains is the
/// value budget - and a value past THAT is promoted to its own full-width line rather than
/// shrunk or cropped (see [`Row::Pair`]).
const LABEL_COL: i32 = 280;

/// Minimum widths of the two pager buttons. `Next >` is the primary action and carries
/// S-30's 280 px floor; `< Prev` is secondary.
const PREV_MIN_W: i32 = 180;
const NEXT_MIN_W: i32 = 280;

/// Characters per group in a C8 mono block.
const GROUP: usize = 4;

/// Width of a C8 block's offset gutter, in characters, for a value of `len` characters.
///
/// Derived rather than fixed at three. A 62-character address indexes to `56` and two
/// digits are enough; a script rendered as hex can run to several hundred characters, and a
/// gutter sized for two digits would have `112` growing rightwards into the value it
/// indexes. The digits of the LAST offset decide the column, plus one for the space.
fn gutter_cols(len: usize) -> i32 {
    let mut digits = 2;
    let mut bound = 100usize;
    while len >= bound {
        digits += 1;
        bound = bound.saturating_mul(10);
    }
    digits + 1
}

// ---------------------------------------------------------------------------------------
// Copy CI freezes
// ---------------------------------------------------------------------------------------

/// The S-32 badge vocabulary, verbatim. The whole review is written in it, so it is one
/// table rather than six literals scattered through a draw function.
const BADGE_EXTERNAL: &str = "EXTERNAL - leaving your wallet";
const BADGE_CHANGE: &str = "CHANGE - coming back to you (verified)";
const BADGE_UNPROVEN: &str = "CHANGE - CLAIMED, NOT VERIFIED";
const BADGE_OURS: &str = "OURS - another address of this wallet";
const BADGE_DATA: &str = "DATA - not spendable";
const BADGE_UNKNOWN: &str = "UNKNOWN SCRIPT";

/// The qualifier that travels with every amount this device could not prove, and the one
/// that travels with a fee it could not bind.
///
/// Constants because they are the load-bearing words on the screen: an edit to either is an
/// edit to the security property rather than to the copy, and the tests assert the rendered
/// text carries them.
const STATED: &str = "STATED ";
const AT_LEAST: &str = "AT LEAST ";

// ---------------------------------------------------------------------------------------
// Formatting: the one definition of every number on this screen
// ---------------------------------------------------------------------------------------

/// Satcomma (UX-SCREENS 0.5): eight decimals, fractional part grouped 2-3-3 with spaces.
/// Spaces rather than commas because a comma is a decimal separator in half the world.
///
/// Never rounded and never abbreviated. A review is a verification context and 0.4's rule
/// is that numbers there are exact.
fn btc(a: Amount) -> String {
    let sats = a.to_sat();
    let whole = sats / 100_000_000;
    let frac = sats % 100_000_000;
    format!(
        "{whole}.{:02} {:03} {:03} BTC",
        frac / 1_000_000,
        (frac / 1_000) % 1_000,
        frac % 1_000
    )
}

/// `numer / denom` to one decimal place, without floating point. Saturating rather than
/// panicking: every value here came off a card somebody else wrote.
fn one_decimal(numer: u64, denom: u64) -> String {
    if denom == 0 {
        return String::from("-");
    }
    let tenths = numer.saturating_mul(10) / denom;
    format!("{}.{}", tenths / 10, tenths % 10)
}

/// What an input's amount reads as, qualifier included.
///
/// The ONE place an input amount becomes text. An amount that did not come out of a
/// previous transaction cannot be rendered without [`STATED`] in front of it, because there
/// is no other function that turns [`InputFacts::value`] into a string. That is the property
/// this screen rests on; `an_unproven_amount_never_renders_like_a_proven_one` says so.
///
/// [`AmountProof::BoundByOurSignature`] renders IDENTICALLY to
/// [`AmountProof::ClaimedByFile`], and that is deliberate rather than an omission. The
/// number still came from the file rather than from the transaction the coin came from,
/// which is what this prefix is about. What a signature of ours makes of it is a different
/// sentence, and it is carried by the caveat row further down the page - a THIRD qualifier
/// on the amount line of the commonest spend there is would be exactly the qualifier
/// fatigue this screen's own header rails against.
fn input_amount_text(f: &InputFacts) -> String {
    match f.amount_proof {
        AmountProof::ProvenByPrevTx => btc(f.value),
        AmountProof::BoundByOurSignature | AmountProof::ClaimedByFile => {
            format!("{STATED}{}", btc(f.value))
        }
    }
}

/// [`STATED`] again, for the Script type and Address rows further down this same input
/// page - the amount is not the only value `resolve_prevout` reads out of an unproven
/// `witness_utxo`; the scriptPubKey it derives Script type and Address FROM is the exact
/// same unverified bytes. Worth spelling out for segwit v0: BIP-143 hashes the
/// scriptCode, not the scriptPubKey, so a native P2WPKH/P2WSH coin and its P2SH-wrapped
/// form sign identically, and this device cannot tell which one the file is even naming.
/// The prefix on these two rows is the same "the file's word, not the previous
/// transaction's" caveat as the amount's, not a new one.
fn witness_utxo_prefix(proof: AmountProof) -> &'static str {
    match proof {
        AmountProof::ProvenByPrevTx => "",
        AmountProof::BoundByOurSignature | AmountProof::ClaimedByFile => STATED,
    }
}

/// What the fee reads as, qualifier included. Matched rather than accessed, for the reason
/// [`ReviewedFee`] hands out no bare amount: matching is how the caveat reaches the screen.
fn fee_amount_text(fee: ReviewedFee) -> String {
    match fee {
        ReviewedFee::Enforced(a) => btc(a),
        ReviewedFee::Stated(a) => format!("{AT_LEAST}{}", btc(a)),
    }
}

/// The fee's sats, for the arithmetic that derives sat/vB and the percentage. Private, and
/// paired with [`fee_qualifier`] at every call site, so nothing can reach an unqualified
/// number derived from an unenforced fee.
fn fee_sats(fee: ReviewedFee) -> u64 {
    match fee {
        ReviewedFee::Enforced(a) | ReviewedFee::Stated(a) => a.to_sat(),
    }
}

/// The prefix a number DERIVED from the fee has to carry: a lower bound divided by an exact
/// vsize is still a lower bound.
fn fee_qualifier(fee: ReviewedFee) -> &'static str {
    match fee {
        ReviewedFee::Enforced(_) => "",
        ReviewedFee::Stated(_) => "at least ",
    }
}

/// A short fixed name for a script type. The engine's own `Display` reads as a phrase
/// ("a segwit address"), which is right inside a sentence and wrong as the value half of a
/// labelled row.
fn kind_label(k: ScriptKind) -> &'static str {
    match k {
        ScriptKind::P2pkh => "P2PKH (legacy)",
        ScriptKind::P2sh => "P2SH (script)",
        ScriptKind::P2shP2wpkh => "P2SH-P2WPKH (wrapped segwit)",
        ScriptKind::P2wpkh => "P2WPKH (segwit v0)",
        ScriptKind::P2wsh => "P2WSH (segwit script)",
        ScriptKind::P2tr => "P2TR (taproot)",
        ScriptKind::OpReturn => "OP_RETURN (data)",
        ScriptKind::Other => "not recognised",
    }
}

/// Lowercase hex, for a script this device cannot turn into an address.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0'));
        out.push(char::from_digit((b & 0x0f) as u32, 16).unwrap_or('0'));
    }
    out
}

/// An OP_RETURN payload as text: printable ASCII, a period for every other byte.
///
/// Never a decoded string. A byte outside the printable range is not in the atlas at all,
/// and one inside it that a naive decoder turned into a control sequence would be payload
/// steering the panel. The substitution IS the rendering, not a fallback from one, and the
/// byte count is stated beside it so nothing is hidden by the periods.
fn printable(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| if (0x20..0x7f).contains(b) { *b as char } else { '.' })
        .collect()
}

/// The locktime row's value.
fn locktime_text(lt: LockTime) -> String {
    match lt {
        LockTime::Blocks(h) if h.to_consensus_u32() == 0 => String::from("not set"),
        LockTime::Blocks(h) => format!("block {}", h.to_consensus_u32()),
        LockTime::Seconds(t) => format!("unix time {}", t.to_consensus_u32()),
    }
}

/// The address this script pays to, or `None` for a script no address encodes (OP_RETURN,
/// bare multisig, anything unrecognised).
///
/// A SPELLING of a value the engine established, not a decision about it. Nothing on this
/// screen or behind it reads the result, and a failure to encode changes no verdict - the
/// page falls back to the script's own bytes, which is strictly more information and
/// strictly less readable. That is why a screen forbidden from computing Bitcoin facts may
/// still do this: the fact is the scriptPubKey the core proved, and this is how it is
/// written down.
fn address_of(script: &ScriptBuf, network: Network) -> Option<String> {
    Address::from_script(script.as_script(), network).ok().map(|a| a.to_string())
}

// ---------------------------------------------------------------------------------------
// The row vocabulary
// ---------------------------------------------------------------------------------------

/// One row of a review page. Six shapes; a seventh is a design review.
///
/// Every row measures and paints through the same two functions, so a page cannot be laid
/// out by one rule and drawn by another - which is exactly how a review page ends up with
/// its last line under the action band on the short panel.
enum Row {
    /// Vertical breathing space.
    Gap,
    /// A full-width band: the S-32 badge, a warning, the summary card. Read first, so it is
    /// always full width (reflow rule 5) and its copy always wraps.
    Band {
        lines: Vec<String>,
        ink: Rgb565,
        bg: Rgb565,
        border: Rgb565,
        heading: bool,
    },
    /// A caption on the left and a value on the right.
    ///
    /// PROMOTED to two lines when the value does not fit what [`LABEL_COL`] leaves it:
    /// caption on its own line, value beneath at the full body width. Cropping is the one
    /// option foreclosed - an amount with its tail cut off is the failure this screen exists
    /// to prevent - and shrinking the font would make the two panels disagree about where a
    /// value breaks.
    Pair {
        label: String,
        value: String,
        mono: bool,
        ink: Rgb565,
    },
    /// A section caption over the block that follows it.
    Caption(String),
    /// C8: one long value, grouped in fours, wrapped by whole groups, with the offset
    /// gutter. Never truncated, never ellipsized, never prefix-and-suffix.
    Mono(String),
    /// Wrapped prose.
    Prose { text: String, ink: Rgb565 },
}

impl Row {
    fn band(lines: &[&str], ink: Rgb565, bg: Rgb565, border: Rgb565) -> Row {
        Row::Band {
            lines: lines.iter().map(|s| String::from(*s)).collect(),
            ink,
            bg,
            border,
            heading: false,
        }
    }

    fn badge(label: &str, ink: Rgb565, bg: Rgb565) -> Row {
        Row::Band {
            lines: vec![String::from(label)],
            ink,
            bg,
            border: ink,
            heading: true,
        }
    }

    fn pair(label: &str, value: impl Into<String>) -> Row {
        Row::Pair { label: String::from(label), value: value.into(), mono: true, ink: INK_PRIMARY }
    }

    fn plain(label: &str, value: impl Into<String>) -> Row {
        Row::Pair { label: String::from(label), value: value.into(), mono: false, ink: INK_PRIMARY }
    }

    fn prose(text: impl Into<String>) -> Row {
        Row::Prose { text: text.into(), ink: INK_SECONDARY }
    }

    /// Height at body width `w`. The single definition; [`draw_row`] walks the same wrap.
    fn height(&self, m: &Metrics, w: i32) -> i32 {
        match self {
            Row::Gap => m.gap,
            Row::Band { lines, heading, .. } => {
                let font = band_font(*heading);
                let n: usize =
                    lines.iter().map(|l| wrap_words(l, w - 2 * BAND_PAD, font).len()).sum();
                n.max(1) as i32 * LINE + 2 * BAND_PAD
            }
            Row::Pair { value, mono, .. } => {
                if pair_value_fits(value, *mono, w) {
                    LINE
                } else {
                    LINE + value_lines(value, *mono, w)
                }
            }
            Row::Caption(_) => LINE,
            Row::Mono(v) => mono_lines(v, w).len().max(1) as i32 * SMALL_LINE,
            Row::Prose { text, .. } => wrap_words(text, w, BODY).len().max(1) as i32 * LINE,
        }
    }
}

fn band_font(heading: bool) -> &'static Atlas {
    if heading {
        HEADING
    } else {
        BODY
    }
}

/// The font a [`Row::Pair`] value is drawn in.
fn pair_font(mono: bool) -> &'static Atlas {
    if mono {
        MONO
    } else {
        BODY
    }
}

/// Whether a pair's value fits beside its label.
fn pair_value_fits(value: &str, mono: bool, w: i32) -> bool {
    pair_font(mono).text_width(value) as i32 <= w - LABEL_COL
}

/// Height a promoted pair value needs on its own full-width lines.
fn value_lines(value: &str, mono: bool, w: i32) -> i32 {
    wrap_words(value, w, pair_font(mono)).len().max(1) as i32 * LINE
}

/// C8 line breaking: `(gutter, groups)` per line, groups of [`GROUP`] characters, broken by
/// whole groups only.
///
/// One function for measuring and for drawing, which is what keeps the offset gutter
/// honest. The number in the gutter is the character offset of the first group ON THAT
/// LINE, and two devices held side by side compare line by line only because the break is
/// computed once and identically on both.
fn mono_lines(value: &str, w: i32) -> Vec<(String, String)> {
    let adv = MONO_SMALL.glyph('m').advance as i32;
    let chars: Vec<char> = value.chars().collect();
    let cols = gutter_cols(chars.len());
    // A group costs its characters plus the space that follows it; the gutter is charged
    // once. At least one group a line, whatever the panel.
    let usable = (w - cols * adv).max(adv * (GROUP as i32 + 1));
    let per_line = (usable / (adv * (GROUP as i32 + 1))).max(1) as usize;
    let width = (cols - 1).max(2) as usize;
    let mut out = Vec::new();
    let mut offset = 0usize;
    for line in chars.chunks(GROUP * per_line) {
        let mut s = String::with_capacity(line.len() + per_line);
        for (i, group) in line.chunks(GROUP).enumerate() {
            if i > 0 {
                s.push(' ');
            }
            s.extend(group.iter());
        }
        out.push((format!("{offset:0width$}"), s));
        offset += line.len();
    }
    if out.is_empty() {
        out.push((String::from("00"), String::new()));
    }
    out
}

fn draw_row<D: DrawTarget<Color = Rgb565>>(t: &mut D, r: Rect, row: &Row) -> Result<(), D::Error> {
    match row {
        Row::Gap => Ok(()),
        Row::Band { lines, ink, bg, border, heading } => {
            panel(t, r, *bg, *border)?;
            let font = band_font(*heading);
            let inner = r.inset(BAND_PAD);
            let mut y = inner.y;
            for para in lines {
                for line in wrap_words(para, inner.w, font) {
                    text(t, &line, inner.x, y, font, *ink, *bg)?;
                    y += LINE;
                }
            }
            Ok(())
        }
        Row::Pair { label, value, mono, ink } => {
            text(t, label, r.x, r.y, BODY, INK_SECONDARY, PAPER_1)?;
            let font = pair_font(*mono);
            if pair_value_fits(value, *mono, r.w) {
                text(t, value, r.x + LABEL_COL, r.y, font, *ink, PAPER_1)?;
            } else {
                let mut y = r.y + LINE;
                for line in wrap_words(value, r.w, font) {
                    text(t, &line, r.x, y, font, *ink, PAPER_1)?;
                    y += LINE;
                }
            }
            Ok(())
        }
        Row::Caption(c) => {
            text(t, c, r.x, r.y, BODY, INK_SECONDARY, PAPER_1)?;
            Ok(())
        }
        Row::Mono(v) => {
            let adv = MONO_SMALL.glyph('m').advance as i32;
            let cols = gutter_cols(v.chars().count());
            let mut y = r.y;
            for (gutter, line) in mono_lines(v, r.w) {
                text(t, &gutter, r.x, y, MONO_SMALL, INK_MUTED, PAPER_1)?;
                text(t, &line, r.x + cols * adv, y, MONO_SMALL, INK_PRIMARY, PAPER_1)?;
                y += SMALL_LINE;
            }
            Ok(())
        }
        Row::Prose { text: body, ink } => {
            let mut y = r.y;
            for line in wrap_words(body, r.w, BODY) {
                text(t, &line, r.x, y, BODY, *ink, PAPER_1)?;
                y += LINE;
            }
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------------------
// The page set
// ---------------------------------------------------------------------------------------

/// Which page of the fixed traversal this is.
///
/// Derived from the page index and the transaction's own shape, so the order is a property
/// of the review rather than a list something can get out of step with. The COUNT comes
/// from [`TxReview::pages`] and nothing here restates it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PageKind {
    Overview,
    Input(usize),
    Output(usize),
    Fee,
    Warnings,
}

// ---------------------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------------------

/// Whether the panel is showing the review or the signature it committed to.
enum Phase {
    Reviewing,
    /// S-37. The request is in flight, nothing is tappable, and a seed is live on the std
    /// side. The one frame in the product that nothing may cancel.
    Signing,
}

pub(crate) struct ReviewState {
    review: TxReview,
    page: usize,
    /// One flag per page of THIS review. A set rather than a high-water mark, because
    /// jumping back and forth is fine and skipping is not (C5).
    visited: Vec<bool>,
    scroll: i32,
    /// Whether the C4 sheet that guards abandoning the reading is open.
    ///
    /// A [`CoreCell`] and not a `bool`, for one structural reason. Back never reaches
    /// `activate`: `Ui::activate` routes [`RegionId::Back`] to [`Screen::back`], which takes
    /// `&self`. A screen whose Back is a QUESTION rather than a move therefore has to record
    /// the question from an immutable receiver, and this is that record. It cannot be read
    /// stale - every frame and every press goes through `regions`/`draw` afterwards - and
    /// the sheet itself is rebuilt from fixed copy each time it is needed, so there is no
    /// second piece of state to disagree with this flag. `Danger::confirm` carries no
    /// mutable state of its own at that grade (the typed buffer belongs to C4d), which is
    /// what makes rebuilding it sound rather than merely convenient.
    leaving: CoreCell<bool>,
    phase: Phase,
    /// The page on the panel, built into rows and measured, for every caller in the frame.
    ///
    /// Not an optimisation bolted on top: it is the only place the row set exists. Every
    /// caller in a frame needs it - `regions` and `draw` each through `layout`, `draw` again
    /// to paint, and the scroll clamp while a finger is down - and each of them used to
    /// build every row and measure every height from scratch. On the warnings page of a file
    /// with 255 outputs paying one address, one `draw` alone measured 2.9 million
    /// allocations and 162 ms on a host far faster than the panel.
    ///
    /// Keyed on everything a row set is a function of rather than invalidated by hand:
    /// which page, how many pages remain unseen (the warnings page prints that), and the
    /// width and gap `Row::height` measures against. A key cannot be forgotten by a future
    /// mutation the way an `invalidate()` call can, and a stale review page is a user
    /// deciding on numbers that are not there.
    rows: RefCell<Option<PageRows>>,
    /// How many row sets this screen has ever built, for the test that pins one build to a
    /// frame. Test-only because the invariant is the only thing it can be used for.
    #[cfg(test)]
    builds: CoreCell<usize>,
}

/// One page, built and measured once.
struct PageRows {
    page: usize,
    unseen: usize,
    width: i32,
    gap: i32,
    rows: Vec<Row>,
    /// `rows[i].height(m, width)`, in step with `rows`, so painting walks the measurement
    /// the scroll clamp was computed from instead of a second one that could disagree.
    heights: Vec<i32>,
    /// Their sum: the content height the scroll limit comes from.
    content: i32,
}

impl ReviewState {
    /// The reviewed transaction, on its first page.
    ///
    /// The constructor the sign source calls. Its name and its single parameter are part of
    /// the screen contract: S-27 has to be able to hand a review on without knowing anything
    /// about how this screen paginates it.
    pub(crate) fn new(review: TxReview) -> ReviewState {
        let pages = review.pages();
        let mut visited = vec![false; pages];
        // Page one is on the panel the moment this value exists, so it is seen by
        // construction. Anything else would need a first Next before the count could ever
        // complete on a one-page review.
        if let Some(first) = visited.first_mut() {
            *first = true;
        }
        ReviewState {
            review,
            page: 0,
            visited,
            scroll: 0,
            leaving: CoreCell::new(false),
            phase: Phase::Reviewing,
            rows: RefCell::new(None),
            #[cfg(test)]
            builds: CoreCell::new(0),
        }
    }

    /// The public name of what is on the panel right now.
    pub(crate) fn id(&self) -> ScreenId {
        match self.phase {
            Phase::Reviewing => ScreenId::ReviewTransaction,
            Phase::Signing => ScreenId::Signing,
        }
    }

    fn pages(&self) -> usize {
        self.review.pages()
    }

    fn kind(&self, page: usize) -> PageKind {
        let ins = self.review.inputs.len();
        let outs = self.review.outputs.len();
        match page {
            0 => PageKind::Overview,
            p if p <= ins => PageKind::Input(p - 1),
            p if p <= ins + outs => PageKind::Output(p - ins - 1),
            p if p == ins + outs + 1 => PageKind::Fee,
            _ => PageKind::Warnings,
        }
    }

    /// Pages the user has not seen yet.
    fn unseen(&self) -> usize {
        self.visited.iter().filter(|v| !**v).count()
    }

    /// A reason this transaction cannot be signed at all, independent of the traversal.
    ///
    /// The second gate on a refusal that should already have happened. `ClaimedButUnproven`
    /// is R-03 and never reaches a signable review; this restates it AT THE HOLD so that a
    /// pipeline which failed to refuse cannot be completed by a user who read every page and
    /// trusted the button. There is deliberately no way to clear it: an override on this
    /// check is the 2019 change-confusion attack with a consent dialog in front of it
    /// (ratified Q24).
    ///
    /// The zero-signable case is R-01 and equally unreachable, and is here for the same
    /// reason: a hold that produced no signature would teach a user that the gesture is
    /// decorative.
    fn blocker(&self) -> Option<String> {
        if let Some(o) =
            self.review.outputs.iter().find(|o| o.role == OutputRole::ClaimedButUnproven)
        {
            return Some(format!(
                "Output {} claims to be change and this device could not prove it (R-03). \
                 This transaction cannot be signed here.",
                o.index
            ));
        }
        if self.review.signable_inputs == 0 {
            return Some(String::from(
                "No input in this transaction belongs to this wallet, so there is nothing \
                 here for this device to sign.",
            ));
        }
        None
    }

    /// Whether the hold exists. Both halves, in one place, so `regions`, `draw` and
    /// `activate` cannot answer it differently.
    fn armed(&self) -> bool {
        self.unseen() == 0 && self.blocker().is_none()
    }

    /// Why it does not, in full. The last row of the warnings page, where it has the body
    /// width to wrap into.
    fn gate_reason(&self) -> Option<String> {
        if let Some(b) = self.blocker() {
            return Some(b);
        }
        match self.unseen() {
            0 => None,
            n => Some(format!(
                "Review all {} pages first. {n} {} not yet been seen, and this device will \
                 not sign a transaction nobody has read.",
                self.pages(),
                if n == 1 { "has" } else { "have" },
            )),
        }
    }

    /// The same reason in ONE line, for the `Disabled` control that stands where the hold
    /// would be.
    ///
    /// Two forms of one fact rather than one form squeezed into both places. A disabled
    /// control always carries its reason (0.1.0's `ButtonKind::Disabled` contract) and the
    /// space it has is a single line, so the line is written to fit that space and asserted
    /// against it - `the_gate_line_fits_beside_the_disabled_control`. The sentence with the
    /// argument in it goes where sentences go.
    fn gate_line(&self) -> Option<String> {
        if self.blocker().is_some() {
            return Some(String::from("This transaction cannot be signed here."));
        }
        match self.unseen() {
            0 => None,
            n => Some(format!("Review all {} pages first - {n} not yet seen.", self.pages())),
        }
    }

    /// Outputs that are proven change, and outputs that are not.
    ///
    /// [`OutputRole::is_change`] is the only question asked, which is what puts a claim
    /// nobody proved on the LEAVING side of the split rather than in a third bucket that
    /// something downstream would eventually round toward change.
    fn output_split(&self) -> (usize, usize) {
        let change = self.review.outputs.iter().filter(|o| o.role.is_change()).count();
        (self.review.outputs.len() - change, change)
    }

    fn unproven_change_claims(&self) -> usize {
        self.review.outputs.iter().filter(|o| o.role == OutputRole::ClaimedButUnproven).count()
    }

    fn bar_title(&self) -> String {
        match self.kind(self.page) {
            PageKind::Overview => String::from("Review"),
            PageKind::Input(i) => format!("Input {} of {}", i + 1, self.review.inputs.len()),
            PageKind::Output(i) => format!("Output {} of {}", i + 1, self.review.outputs.len()),
            PageKind::Fee => String::from("Fee"),
            PageKind::Warnings => String::from("Warnings"),
        }
    }

    /// The C4 sheet that guards abandoning a reading. Fixed copy, rebuilt rather than
    /// stored - see [`ReviewState::leaving`].
    fn leave_sheet() -> Danger {
        Danger::confirm(
            "Leave this review?",
            &[
                "Nothing is signed and nothing is written.",
                "You will have to load the file and read every page again before this device \
                 will sign it.",
            ],
            "Leave",
        )
    }

    /// Arriving on a page: it counts as seen, and it starts at the top.
    ///
    /// Marked on ARRIVAL rather than on departure, so the page showing when the last Next is
    /// tapped is counted without a further gesture.
    fn arrive(&mut self) {
        if let Some(v) = self.visited.get_mut(self.page) {
            *v = true;
        }
        self.scroll = 0;
    }

    // -- The pages -----------------------------------------------------------------------

    /// The current page, built and measured, handed to `f` without being copied.
    ///
    /// The borrow is held across `f`, so `f` may not reach back into this method. Neither
    /// caller does: one reads the content height, the other paints. `draw` takes its
    /// `layout` first for the same reason.
    fn page_rows<R>(&self, m: &Metrics, width: i32, f: impl FnOnce(&PageRows) -> R) -> R {
        let mut slot = self.rows.borrow_mut();
        let stale = !matches!(
            slot.as_ref(),
            Some(p) if p.page == self.page
                && p.unseen == self.unseen()
                && p.width == width
                && p.gap == m.gap
        );
        if stale {
            #[cfg(test)]
            self.builds.set(self.builds.get() + 1);
            let rows = self.build_rows();
            let heights: Vec<i32> = rows.iter().map(|r| r.height(m, width)).collect();
            *slot = Some(PageRows {
                page: self.page,
                unseen: self.unseen(),
                width,
                gap: m.gap,
                content: heights.iter().sum(),
                rows,
                heights,
            });
        }
        f(slot.as_ref().expect("the slot was filled above"))
    }

    fn build_rows(&self) -> Vec<Row> {
        match self.kind(self.page) {
            PageKind::Overview => self.overview_rows(),
            PageKind::Input(i) => self.input_rows(i),
            PageKind::Output(i) => self.output_rows(i),
            PageKind::Fee => self.fee_rows(),
            PageKind::Warnings => self.warning_rows(),
        }
    }

    /// S-30. Primes the reader; never a substitute for the pages behind it.
    fn overview_rows(&self) -> Vec<Row> {
        let r = &self.review;
        let mut rows = Vec::new();

        // The two numbers a user has to internalise, in one raised card. "Leaving this
        // wallet" rather than "Amount": it answers "how much am I spending?" and it excludes
        // PROVEN change by construction, which is what makes an unproven change claim land
        // inside it.
        rows.push(Row::Band {
            lines: vec![
                format!("Leaving this wallet    {}", btc(r.leaving())),
                format!("Fee                    {}", fee_amount_text(r.fee)),
            ],
            ink: INK_PRIMARY,
            bg: PAPER_2,
            border: BORDER_STRONG,
            heading: false,
        });
        rows.push(Row::Gap);

        // Everything the device could NOT prove, in words, above the arithmetic that rests
        // on it.
        let unproven = r.unproven_amounts();
        if unproven > 0 {
            rows.push(Row::band(
                &[&format!(
                    "{unproven} of {} input amounts {} stated by the file and not proven \
                     against the transaction the coin came from. Every total on this screen, \
                     including the fee, rests on that.",
                    r.inputs.len(),
                    if unproven == 1 { "is" } else { "are" },
                )],
                WARNING,
                PAPER_0,
                WARNING,
            ));
            rows.push(Row::Gap);
        }
        let claims = self.unproven_change_claims();
        if claims > 0 {
            rows.push(Row::band(
                &[&format!(
                    "{claims} output{} claim{} to be change and this device could not prove \
                     it. {} counted as money leaving, and this transaction cannot be signed \
                     here.",
                    if claims == 1 { "" } else { "s" },
                    if claims == 1 { "s" } else { "" },
                    if claims == 1 { "It is" } else { "They are" },
                )],
                DANGER,
                DANGER_TINT,
                DANGER,
            ));
            rows.push(Row::Gap);
        }

        rows.push(Row::pair("Inputs", format!("{} - {}", r.inputs.len(), btc(r.input_total))));
        let ours = r.signable_inputs;
        rows.push(Row::prose(if ours == r.inputs.len() {
            format!("all from {} ({})", r.wallet, r.fingerprint)
        } else {
            format!("{ours} of {} from {} ({})", r.inputs.len(), r.wallet, r.fingerprint)
        }));

        let (leaving, change) = self.output_split();
        rows.push(Row::plain(
            "Outputs",
            if claims > 0 {
                format!(
                    "{} - {leaving} leaving (of which {claims} an unproven change claim), \
                     {change} change (verified)",
                    r.outputs.len()
                )
            } else {
                format!("{} - {leaving} leaving, {change} change (verified)", r.outputs.len())
            },
        ));
        rows.push(Row::Pair {
            label: String::from("Network"),
            value: String::from(if r.network == Network::Bitcoin { "mainnet" } else { "TESTNET" }),
            mono: false,
            ink: if r.network == Network::Bitcoin { INK_PRIMARY } else { WARNING },
        });
        rows.push(Row::Pair {
            label: String::from("Warnings"),
            value: r.warnings.len().to_string(),
            mono: false,
            ink: if r.warnings.is_empty() { INK_PRIMARY } else { WARNING },
        });
        rows.push(Row::pair("File", r.source.clone()));

        if r.unknown_fields > 0 {
            rows.push(Row::prose(format!(
                "This file carries {} field{} this device does not read. They are kept \
                 unchanged and are used for no decision.",
                r.unknown_fields,
                if r.unknown_fields == 1 { "" } else { "s" },
            )));
        }
        if r.leaving() == Amount::ZERO {
            rows.push(Row::Gap);
            rows.push(Row::prose("This transaction sends everything back to itself, minus the fee."));
        }
        rows.push(Row::Gap);
        rows.push(Row::prose(
            "You will see every input and every output on its own page. The Sign button \
             appears after the last page.",
        ));
        rows
    }

    /// S-31. What is being spent, so the fee arithmetic is auditable.
    fn input_rows(&self, i: usize) -> Vec<Row> {
        let Some(f) = self.review.inputs.get(i) else { return Vec::new() };
        let mut rows = Vec::new();

        // The caveat band sits ABOVE the number it is about, because it changes what the
        // number means. Two different bands: an amount nothing binds, and an amount this
        // device's own signature will bind (BIP-341) even though no previous transaction
        // proved it. They are different facts and a single band would flatten them.
        if f.amount_proof == AmountProof::ClaimedByFile {
            rows.push(match self.review.fee {
                ReviewedFee::Stated(_) => Row::band(
                    &["NOT PROVEN - the file states this amount. This device could not check \
                       it against the transaction the coin came from, so the fee and every \
                       total rest on the coordinator's word."],
                    DANGER,
                    DANGER_TINT,
                    DANGER,
                ),
                ReviewedFee::Enforced(_) => Row::band(
                    &["STATED, BOUND BY YOUR SIGNATURE - the file states this amount, and the \
                       taproot signature this device adds commits to every input amount at \
                       once. A wrong amount makes the transaction unusable rather than \
                       expensive."],
                    WARNING,
                    PAPER_0,
                    WARNING,
                ),
            });
            rows.push(Row::Gap);
        }

        rows.push(Row::Pair {
            label: String::from("Amount"),
            value: input_amount_text(f),
            mono: true,
            ink: match f.amount_proof {
                // Bound is not a warning colour. An ordinary single-input spend carries a
                // stated amount that this device's own signature makes binding, and
                // painting it amber would spend the alarm on the commonest file there is.
                AmountProof::ProvenByPrevTx | AmountProof::BoundByOurSignature => INK_PRIMARY,
                AmountProof::ClaimedByFile => WARNING,
            },
        });

        match &f.claim {
            Claim::Ours { path, .. } => {
                rows.push(Row::pair("From", format!("m/{path}")));
                rows.push(Row::Prose {
                    text: format!("yours ({})", self.review.fingerprint),
                    ink: SUCCESS,
                });
            }
            Claim::Foreign => {
                rows.push(Row::Pair {
                    label: String::from("From"),
                    value: String::from("not from this wallet"),
                    mono: false,
                    ink: WARNING,
                });
                rows.push(Row::Prose {
                    text: String::from(
                        "This input is not yours. It will not be signed here, and its amount \
                         is still part of the fee.",
                    ),
                    ink: WARNING,
                });
            }
        }
        rows.push(Row::plain(
            "Script type",
            format!("{}{}", witness_utxo_prefix(f.amount_proof), kind_label(f.kind)),
        ));
        if let Some(b) = &f.multisig {
            rows.push(Row::pair("Registration", b.registration.to_string()));
        }

        rows.push(Row::Gap);
        let prefix = witness_utxo_prefix(f.amount_proof);
        match address_of(&f.script_pubkey, self.review.network) {
            Some(a) => {
                rows.push(Row::Caption(format!("{prefix}Address")));
                rows.push(Row::Mono(a));
            }
            None => {
                rows.push(Row::Caption(format!("{prefix}Script (hex)")));
                rows.push(Row::Mono(hex(f.script_pubkey.as_bytes())));
            }
        }
        rows.push(Row::Gap);
        rows.push(Row::Caption(String::from("Previous transaction")));
        rows.push(Row::Mono(f.outpoint.txid.to_string()));
        rows.push(Row::pair("Output index", f.outpoint.vout.to_string()));

        rows.push(Row::Gap);
        // The proof alone decides this row, and it did not always: until the third
        // [`AmountProof`] state landed, "the file states it and our signature binds it" was
        // a fact the FEE had to supply, so this matched the pair. It no longer has to, and
        // it must not - a row about one input has no business reading a total over all of
        // them, and the two could disagree.
        rows.push(match f.amount_proof {
            AmountProof::ProvenByPrevTx => Row::Prose {
                text: String::from(
                    "Checked: the amount and the script came out of the full previous \
                     transaction, which hashes to the txid above.",
                ),
                ink: SUCCESS,
            },
            // Not "(taproot)" any more. Taproot's `sha_amounts` is one of the two ways this
            // row is reachable; the other is a transaction with a single input, where
            // BIP-143 binds the only amount there is.
            AmountProof::BoundByOurSignature => Row::Prose {
                text: String::from(
                    "Checked: if this amount is wrong, the signature this device adds is \
                     worthless and this transaction cannot confirm.",
                ),
                ink: INK_SECONDARY,
            },
            AmountProof::ClaimedByFile => Row::Prose {
                text: String::from(
                    "NOT CHECKED: nothing here proves this amount. It is what the file says \
                     the coin is worth.",
                ),
                ink: DANGER,
            },
        });
        rows
    }

    /// S-32 and S-33. The page the whole device exists for.
    fn output_rows(&self, i: usize) -> Vec<Row> {
        let Some(o) = self.review.outputs.get(i) else { return Vec::new() };
        let mut rows = Vec::new();
        let (badge, ink, bg) = badge_for(o);
        rows.push(Row::badge(badge, ink, bg));
        rows.push(Row::Gap);
        rows.push(Row::pair("Amount", btc(o.value)));
        rows.push(Row::plain("Script type", kind_label(o.kind)));

        match o.role {
            OutputRole::Change { owner, index } => {
                rows.push(Row::pair("Derived by", format!("{owner}")));
                rows.push(Row::pair("Change index", index.to_string()));
            }
            OutputRole::OwnNotChange { owner, index } => {
                rows.push(Row::pair("Derived by", format!("{owner}")));
                rows.push(Row::pair("Receive index", index.to_string()));
            }
            OutputRole::Payment | OutputRole::ClaimedButUnproven => {}
        }

        rows.push(Row::Gap);
        if o.kind == ScriptKind::OpReturn {
            let payload = o.script_pubkey.as_bytes();
            rows.push(Row::Caption(format!("Payload ({} bytes, hex)", payload.len())));
            rows.push(Row::Mono(hex(payload)));
            rows.push(Row::Gap);
            rows.push(Row::Caption(String::from("As text (printable characters only)")));
            rows.push(Row::Mono(printable(payload)));
            rows.push(Row::Gap);
            rows.push(Row::prose("This output carries data, not coins. Nobody can spend it."));
            return rows;
        }
        match address_of(&o.script_pubkey, self.review.network) {
            Some(a) => {
                rows.push(Row::Caption(String::from("Address")));
                rows.push(Row::Mono(a));
            }
            None => {
                rows.push(Row::Caption(String::from("Script (hex)")));
                rows.push(Row::Mono(hex(o.script_pubkey.as_bytes())));
                rows.push(Row::Gap);
                rows.push(Row::Prose {
                    text: String::from("This device cannot tell who can spend this output."),
                    ink: DANGER,
                });
            }
        }
        rows.push(Row::Gap);
        rows.push(match o.role {
            OutputRole::Payment => Row::prose(
                "Compare every group with the address you were given. Attackers grind \
                 lookalikes that match at both ends.",
            ),
            OutputRole::Change { .. } => Row::Prose {
                text: String::from(
                    "Checked: this device derived this exact address from your wallet, on the \
                     change keychain, at the index the file claimed.",
                ),
                ink: SUCCESS,
            },
            OutputRole::OwnNotChange { .. } => Row::Prose {
                text: String::from(
                    "Checked: this device derived this address from your wallet, on the \
                     RECEIVE keychain. It is yours and it is not this transaction's change, \
                     so it counts as money leaving.",
                ),
                ink: ACCENT,
            },
            OutputRole::ClaimedButUnproven => Row::Prose {
                text: String::from(
                    "The file says this output is yours. This device could not derive it from \
                     any wallet in scope, so the claim is not believed: it counts as money \
                     leaving, and this transaction cannot be signed here.",
                ),
                ink: DANGER,
            },
        });
        rows
    }

    /// S-34. The other number attackers manipulate.
    fn fee_rows(&self) -> Vec<Row> {
        let r = &self.review;
        let mut rows = Vec::new();
        if let ReviewedFee::Stated(_) = r.fee {
            rows.push(Row::band(
                &["NOT ENFORCED - at least one input amount is the file's word, and no \
                   signature of this device's makes it binding. Every number below is a lower \
                   bound on what this transaction costs, not a measurement."],
                DANGER,
                DANGER_TINT,
                DANGER,
            ));
            rows.push(Row::Gap);
        }
        let q = fee_qualifier(r.fee);
        let sats = fee_sats(r.fee);
        rows.push(Row::Pair {
            label: String::from("Fee"),
            value: fee_amount_text(r.fee),
            mono: true,
            ink: match r.fee {
                ReviewedFee::Enforced(_) => INK_PRIMARY,
                ReviewedFee::Stated(_) => DANGER,
            },
        });
        rows.push(Row::pair("In sats", format!("{q}{sats} sats")));
        let vsize = if r.vsize_exact {
            format!("{} vB", r.vsize)
        } else {
            format!("{} vB, estimated", r.vsize)
        };
        rows.push(Row::pair(
            "Fee rate",
            format!("{q}{} sat/vB ({vsize})", one_decimal(sats, r.vsize as u64)),
        ));
        rows.push(Row::pair(
            "Of what leaves",
            format!("{q}{}%", one_decimal(sats.saturating_mul(100), r.leaving().to_sat())),
        ));
        rows.push(Row::Gap);
        rows.push(match r.fee {
            ReviewedFee::Enforced(_) => Row::Prose {
                text: String::from(
                    "The fee is computed by this device from the inputs it checked. It is not \
                     taken from the file.",
                ),
                ink: INK_SECONDARY,
            },
            ReviewedFee::Stated(_) => Row::Prose {
                text: String::from(
                    "The fee is inputs minus outputs, and one of those inputs is only claimed. \
                     The real fee is this or larger.",
                ),
                ink: DANGER,
            },
        });
        rows.push(Row::Gap);
        rows.push(Row::plain("Locktime", locktime_text(r.lock_time)));
        if let LockTime::Blocks(h) = r.lock_time {
            if h.to_consensus_u32() > 0 {
                rows.push(Row::prose(format!(
                    "This transaction is not valid before block {}.",
                    h.to_consensus_u32()
                )));
            }
        }
        rows.push(Row::plain(
            "Replaceable",
            if r.rbf_signaled { "yes (RBF signalled)" } else { "no" },
        ));
        rows
    }

    /// S-35. Everything legal but notable, in one place, before the hold.
    fn warning_rows(&self) -> Vec<Row> {
        let mut rows = Vec::new();
        if self.review.warnings.is_empty() {
            rows.push(Row::prose("No warnings."));
        } else {
            for (i, w) in self.review.warnings.iter().enumerate() {
                rows.push(Row::band(
                    &[&format!("{}. {}", i + 1, w.headline), &w.detail],
                    INK_PRIMARY,
                    PAPER_0,
                    WARNING,
                ));
                rows.push(Row::Gap);
            }
        }
        rows.push(Row::Gap);
        // The reason the hold is not there, in full, immediately above the control that is
        // not there. A disabled control with a one-line reason under it and the argument up
        // here is the only shape that fits both panels without cropping either.
        rows.push(match (self.blocker(), self.gate_reason()) {
            (Some(b), _) => Row::Prose { text: b, ink: DANGER },
            (None, Some(r)) => Row::Prose { text: r, ink: WARNING },
            (None, None) => Row::prose("These are not errors. Read them, then sign or go back."),
        });
        rows
    }
}

/// The badge for one output, and the precedence between the two things a badge can be
/// about.
///
/// A claim the device could not prove OUTRANKS the script's own shape, because the claim is
/// the attack: a data output or an unrecognised script that also carries our fingerprint is
/// a lie worth showing as the lie. Below that, a script nothing can classify outranks its
/// role, because "who can spend this" is unanswered and no role means anything without it.
fn badge_for(o: &OutputFacts) -> (&'static str, Rgb565, Rgb565) {
    if o.role == OutputRole::ClaimedButUnproven {
        return (BADGE_UNPROVEN, DANGER, DANGER_TINT);
    }
    match o.kind {
        ScriptKind::OpReturn => (BADGE_DATA, WARNING, PAPER_0),
        ScriptKind::Other => (BADGE_UNKNOWN, DANGER, DANGER_TINT),
        _ => match o.role {
            OutputRole::Payment => (BADGE_EXTERNAL, DANGER, DANGER_TINT),
            OutputRole::Change { .. } => (BADGE_CHANGE, SUCCESS, PAPER_0),
            OutputRole::OwnNotChange { .. } => (BADGE_OURS, ACCENT, ACCENT_TINT),
            OutputRole::ClaimedButUnproven => (BADGE_UNPROVEN, DANGER, DANGER_TINT),
        },
    }
}

// ---------------------------------------------------------------------------------------
// Geometry
// ---------------------------------------------------------------------------------------

pub(crate) struct Layout {
    /// The bar's `[ i / n ]` slot.
    counter: Rect,
    /// The scrolling body of the page.
    viewport: Rect,
    prev: Option<Rect>,
    next: Option<Rect>,
    /// The C4c bar on the last page. Always DRAWN there - as a `Disabled` control carrying
    /// its reason while the review is incomplete - and hit-tested only when `armed`.
    hold: Option<Rect>,
    armed: bool,
    limit: i32,
}

impl Screen for ReviewState {
    type Layout = Layout;

    fn layout(&self, ctx: &Ctx) -> Layout {
        let m = &ctx.m;
        let body = m.body();
        let last = self.page + 1 == self.pages();

        // One action band on every page and at both geometries, rather than the landscape
        // rail reflow rule 1 suggests. The rail cannot hold a C4c bar - C4c's floor is 60%
        // of the body width and a rail is a quarter of it - so a rail would put the pager
        // in one place for eight pages and somewhere else for the ninth, which is exactly
        // the surface R-NOTHROUGH is about. One layout, both panels.
        let (viewport, prev, next, hold) = if last {
            // The hold sits in a band of its OWN, above the pager row, and the bottom right
            // of the last page is EMPTY.
            //
            // R-NOTHROUGH is the reason. The primary action of the page before is `Next >`
            // at the bottom right, and a fast second tap lands where the first one did: on
            // this page that rectangle has to be something a mistap can survive. A C4c bar
            // there would survive it - a tap cannot fire one, which is the whole point of
            // the grade - but a finger that stayed down expecting the panel to advance
            // would be a finger holding to sign, and that is the one confusion this screen
            // may not create. So the hold is bottom-anchored ABOVE the pager row, its band
            // does not reach the rectangle Next occupied, and a stray second tap finds
            // paper.
            //
            // The bar keeps the FULL body width. C4c's floor is 60% and the vertical
            // arrangement is what buys it: no side-by-side row leaves 60% once a pager
            // button and its clearance come out of 672 px, which is the same conclusion
            // `danger::Danger`'s hold grade reached and for the same reason.
            //
            // R-SEPARATION governs the gap between a hold and the CANCEL beside it, and the
            // only cancel this screen has is the bar's Back, a full body height away. What
            // sits under the bar is `< Prev`, a pager: a finger that misses the hold and
            // finds it steps BACKWARDS through the review, which is the direction every
            // mistap on this page should go.
            let prev = Rect::new(
                body.x,
                body.bottom() - m.btn,
                PREV_MIN_W.max(body.w / 4),
                m.btn,
            );
            let hold = Rect::new(body.x, prev.y - m.gap - HOLD_BAR_H, body.w, HOLD_BAR_H);
            let viewport = Rect::new(body.x, body.y, body.w, hold.y - m.gap - body.y);
            (viewport, Some(prev), None, Some(hold))
        } else {
            let band = Rect::new(body.x, body.bottom() - m.btn, body.w, m.btn);
            let viewport = Rect::new(body.x, body.y, body.w, band.y - m.gap - body.y);
            let next_w = NEXT_MIN_W.max(body.w / 3);
            let next = Rect::new(body.right() - next_w, band.y, next_w, band.h);
            let prev = if self.page == 0 {
                None
            } else {
                Some(Rect::new(body.x, band.y, PREV_MIN_W.max(body.w / 4), band.h))
            };
            (viewport, prev, Some(next), None)
        };

        // Content height, measured with the same row walk that paints - the same walk in
        // the literal sense now: both read one cached measurement of one row set.
        let content = self.page_rows(m, viewport.w, |p| p.content);
        let limit = (content - viewport.h).max(0);

        let cw = BODY.text_width(&counter_label(self.page + 1, self.pages())) as i32;
        let counter = Rect::new(m.w - m.pad - cw, (m.bar - LINE) / 2, cw, LINE);

        Layout { counter, viewport, prev, next, hold, armed: self.armed(), limit }
    }

    fn regions(&self, ctx: &Ctx, out: &mut Vec<Region>) {
        // S-37: nothing tappable, not even Back. The seed is live on the std side and the
        // panel does not move until the answer lands.
        if matches!(self.phase, Phase::Signing) {
            return;
        }
        if self.leaving.get() {
            ReviewState::leave_sheet().regions(&ctx.m, out);
            return;
        }
        let l = self.layout(ctx);
        out.push(Region { id: RegionId::Back, rect: back_rect(&ctx.m) });
        if let Some(r) = l.prev {
            out.push(Region { id: RegionId::ReviewPrev, rect: r });
        }
        if let Some(r) = l.next {
            out.push(Region { id: RegionId::ReviewNext, rect: r });
        }
        // The hold is a REGION only when it is armed. The disabled gate occupies the same
        // rectangle and is deliberately not hit-tested: a control that is not available is
        // not a control, and a press that cannot carry `HoldConfirm` cannot age into one.
        if let (Some(r), true) = (l.hold, l.armed) {
            out.push(Region { id: RegionId::HoldConfirm, rect: r });
        }
    }

    fn draw<D: DrawTarget<Color = Rgb565>>(&self, t: &mut D, ctx: &Ctx) -> Result<(), D::Error> {
        let m = &ctx.m;
        if matches!(self.phase, Phase::Signing) {
            return draw_signing(t, m, self.review.signable_inputs);
        }
        if self.leaving.get() {
            return ReviewState::leave_sheet().draw(t, m, ctx.press, ctx.hold_released);
        }
        let l = self.layout(ctx);
        draw_bar(t, m, &self.bar_title())?;
        text_centered(
            t,
            &counter_label(self.page + 1, self.pages()),
            l.counter,
            BODY,
            INK_SECONDARY,
            PAPER_2,
        )?;

        let scroll = self.scroll.clamp(0, l.limit);
        {
            let mut clip = t.clipped(&l.viewport.to_eg());
            let mut y = l.viewport.y - scroll;
            self.page_rows(m, l.viewport.w, |p| {
                for (row, h) in p.rows.iter().zip(&p.heights) {
                    // Rows wholly off the viewport are skipped rather than clipped: the
                    // panel has no dirty rectangles, so a full repaint walks every row every
                    // frame.
                    if y + h > l.viewport.y && y < l.viewport.bottom() {
                        draw_row(&mut clip, Rect::new(l.viewport.x, y, l.viewport.w, *h), row)?;
                    }
                    y += h;
                }
                Ok(())
            })?;
        }
        // C6's edge markers. A review page that silently has more below is a page the user
        // believes they have read, which is the one belief this screen may not create.
        //
        // Painted ON the content rather than in a reserved strip, each on its own chip of
        // paper: a strip would cost a line of a viewport that is already the tightest thing
        // on the short panel, and a strip that is only sometimes there would make the page
        // reflow as it is scrolled.
        if scroll > 0 {
            marker(t, "more above", l.viewport, true)?;
        }
        if scroll < l.limit {
            marker(t, "more below", l.viewport, false)?;
        }

        if let Some(r) = l.prev {
            button(t, r, "< Prev", ButtonKind::Secondary, PAPER_1)?;
        }
        if let Some(r) = l.next {
            button(t, r, "Next >", ButtonKind::Primary, PAPER_1)?;
        }
        if let Some(r) = l.hold {
            if l.armed {
                let held = ctx.press.filter(|p| p.id == Some(RegionId::HoldConfirm));
                let permille = hold_fill_permille(held.map_or(0, |p| p.held_ms));
                let status = match (held, ctx.hold_released) {
                    (Some(p), _) if p.held_ms > 0 => format!(
                        "Keep holding - {} s of {} s",
                        one_decimal(p.held_ms as u64, 1000),
                        HOLD_MS / 1000
                    ),
                    (_, true) => String::from("Released - nothing was signed."),
                    _ => format!("Hold for {} seconds", HOLD_MS / 1000),
                };
                hold_bar(t, r, "Hold to sign", &status, permille, ACCENT)?;
            } else {
                // A disabled control always carries its reason beside it, never silently -
                // and the reason has to FIT, so the band is split into the control and one
                // line, and the line is the short form the gate keeps for exactly this.
                let (control, line) = gate_split(r);
                button(t, control, "Hold to sign", ButtonKind::Disabled, PAPER_1)?;
                if let Some(reason) = self.gate_line() {
                    text_centered(t, &reason, line, BODY, WARNING, PAPER_1)?;
                }
            }
        }
        Ok(())
    }

    fn activate(&mut self, id: RegionId, _env: &mut Env) -> Outcome {
        if matches!(self.phase, Phase::Signing) {
            return Outcome::stay();
        }
        if self.leaving.get() {
            let mut sheet = ReviewState::leave_sheet();
            return match sheet.activate(id) {
                DangerOutcome::Open | DangerOutcome::Alternative => Outcome::stay(),
                DangerOutcome::Cancelled => {
                    self.leaving.set(false);
                    Outcome::stay()
                }
                DangerOutcome::Confirmed => {
                    self.leaving.set(false);
                    Outcome { nav: Nav::Back, request: None }
                }
            };
        }
        match id {
            RegionId::ReviewPrev => {
                self.page = self.page.saturating_sub(1);
                self.arrive();
                Outcome::stay()
            }
            RegionId::ReviewNext => {
                if self.page + 1 < self.pages() {
                    self.page += 1;
                    self.arrive();
                }
                Outcome::stay()
            }
            // The last gate, and deliberately not the only one. `Ui::tick` fires a filled
            // hold by calling this function DIRECTLY, so a screen that trusted `regions` to
            // have gated it would be trusting a caller it cannot see. Both questions are
            // asked again here; an unarmed hold signs nothing and says nothing, because the
            // panel is already showing the reason.
            RegionId::HoldConfirm if self.armed() => {
                // C3's law: the frame that says what is happening is chosen by THIS
                // transition, and the embedder publishes it before answering the request.
                self.phase = Phase::Signing;
                Outcome::ask(UiRequest::SignTx)
            }
            _ => Outcome::stay(),
        }
    }

    fn answered(&mut self, answer: Answer, _env: &mut Env) -> Outcome {
        let Answer::Sign(outcome) = answer else { return Outcome::stay() };
        // An answer arriving while the panel is not showing S-37 belongs to a request this
        // screen is no longer waiting for.
        if !matches!(self.phase, Phase::Signing) {
            return Outcome::stay();
        }
        match outcome {
            SignOutcome::Signed(tx) => Outcome::enter(State::Deliver(DeliverState::new(tx))),
            SignOutcome::Refused(n) => Outcome::enter(State::Refusal(RefusalState::new(n))),
        }
    }

    /// Back is a QUESTION here, not a move: an accidental tap after nine pages costs the
    /// whole reading. `back` cannot mutate, so it records the question (see
    /// [`ReviewState::leaving`]) and moves nothing; the sheet is on the next frame.
    ///
    /// During signing there is no Back at all, and `regions` emits none.
    fn back(&self) -> Nav {
        if matches!(self.phase, Phase::Signing) {
            return Nav::Stay;
        }
        self.leaving.set(true);
        Nav::Stay
    }

    fn scroll_mut(&mut self) -> Option<&mut i32> {
        if matches!(self.phase, Phase::Signing) || self.leaving.get() {
            return None;
        }
        Some(&mut self.scroll)
    }

    fn scroll_limit(&self, ctx: &Ctx) -> i32 {
        self.layout(ctx).limit
    }
}

/// The C4c band, divided between the `Disabled` control and the one line that says why it
/// is disabled. One function, so the copy is measured against the rectangle it is drawn in.
fn gate_split(band: Rect) -> (Rect, Rect) {
    let line = Rect::new(band.x, band.bottom() - LINE, band.w, LINE);
    (Rect::new(band.x, band.y, band.w, band.h - LINE - 4), line)
}

/// The `[ i / n ]` string, formatted in the one place the bar measures and paints it from.
fn counter_label(page: usize, pages: usize) -> String {
    format!("{page} / {pages}")
}

/// One C6 edge marker, right-aligned on its own chip of paper at the top or the bottom of
/// `viewport`.
///
/// The chip is what makes it legible over whatever line of the page it lands on, and it is
/// why the marker costs no layout: painting it is a decision about pixels rather than about
/// where the rows go, so a page does not reflow when it starts or stops scrolling.
///
/// Shared by the three screens of this flow rather than repeated in each, because a
/// scroll affordance that looked different on the refusal screen than on the review would
/// read as a different mechanism.
pub(crate) fn marker<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    label: &str,
    viewport: Rect,
    top: bool,
) -> Result<(), D::Error> {
    let w = MONO_SMALL.text_width(label) as i32 + 8;
    let y = if top { viewport.y } else { viewport.bottom() - SMALL_LINE };
    let chip = Rect::new(viewport.right() - w, y, w, SMALL_LINE);
    crate::canvas::fill(t, chip, PAPER_1)?;
    text(t, label, chip.x + 4, chip.y, MONO_SMALL, INK_MUTED, PAPER_1)?;
    Ok(())
}

/// S-37, a C3 Busy frame.
///
/// No meter and no percentage. C3 permits a determinate meter only where the work has
/// countable units the screen is TOLD about, and this request vocabulary carries no signing
/// progress report - so a bar here would be an animation of nothing, which is precisely
/// what C3 forbids. What the frame does state is the size of the batch, which is a fact the
/// review already established.
fn draw_signing<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    m: &Metrics,
    inputs: usize,
) -> Result<(), D::Error> {
    draw_bar_no_back(t, m, "Signing")?;
    let body = m.body();
    let card_h = 4 * LINE + 5 * m.gap;
    let card = Rect::new(body.x, body.y + (body.h - card_h).max(0) / 2, body.w, card_h);
    panel(t, card, PAPER_2, BORDER_STRONG)?;
    let line = |y: i32| Rect::new(card.x, y, card.w, LINE);
    let mut y = card.y + m.gap;
    text_centered(t, "Signing", line(y), HEADING, INK_PRIMARY, PAPER_2)?;
    y += LINE + m.gap;
    text_centered(
        t,
        "Deriving a key for each input, then signing.",
        line(y),
        BODY,
        INK_SECONDARY,
        PAPER_2,
    )?;
    y += LINE + m.gap;
    let batch = format!("{inputs} input{}", if inputs == 1 { "" } else { "s" });
    text_centered(t, &batch, line(y), MONO, INK_PRIMARY, PAPER_2)?;
    y += LINE + m.gap;
    text_centered(t, "This cannot be cancelled.", line(y), BODY, INK_SECONDARY, PAPER_2)
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::UnlockGate;
    use super::*;
    use crate::layout::TOUCH_MIN;
    use crate::screens::testing::{fits, rows_are_clear_on, Fixture, GEOMETRIES};
    use crate::{RefusalCode, RefusalNotice, SignedTx, TxWarning};
    use notyas_core::bitcoin::hashes::Hash;
    use notyas_core::bitcoin::{OutPoint, Txid};

    // -- Fixtures ------------------------------------------------------------------------

    /// A P2WPKH script, so a page has a real address to render.
    fn wpkh(seed: u8) -> ScriptBuf {
        ScriptBuf::from_bytes([&[0x00u8, 0x14][..], &[seed; 20][..]].concat())
    }

    fn outpoint(seed: u8) -> OutPoint {
        OutPoint { txid: Txid::from_byte_array([seed; 32]), vout: seed as u32 }
    }

    pub(crate) fn input(index: u16, sats: u64, proof: AmountProof, ours: bool) -> InputFacts {
        InputFacts {
            index,
            outpoint: outpoint(index as u8 + 1),
            value: Amount::from_sat(sats),
            amount_proof: proof,
            script_pubkey: wpkh(index as u8 + 1),
            redeem_script: None,
            kind: ScriptKind::P2wpkh,
            claim: if ours {
                Claim::Ours {
                    path: "84'/0'/0'/0/4".parse().expect("a fixed test path parses"),
                    key: claimed_key(),
                }
            } else {
                Claim::Foreign
            },
            multisig: None,
            tap_merkle_root: None,
        }
    }

    fn claimed_key() -> crate::ClaimedKey {
        // A fixed, public compressed key: the generator point. Worthless by construction and
        // never used for anything but filling a field the renderer does not read.
        let bytes = [
            0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce,
            0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81,
            0x5b, 0x16, 0xf8, 0x17, 0x98,
        ];
        crate::ClaimedKey::Ecdsa(
            notyas_core::bitcoin::secp256k1::PublicKey::from_slice(&bytes)
                .expect("the generator point is a valid key"),
        )
    }

    pub(crate) fn output(index: u16, sats: u64, role: OutputRole) -> OutputFacts {
        OutputFacts {
            index,
            value: Amount::from_sat(sats),
            script_pubkey: wpkh(index as u8 + 100),
            kind: ScriptKind::P2wpkh,
            claims_our_key: !matches!(role, OutputRole::Payment),
            role,
        }
    }

    /// An account of this device's own, for the two proven roles.
    ///
    /// Derived rather than constructed: `AccountId` has no public constructor, deliberately,
    /// because the only honest source of one is a derivation from a seed. The seed here is
    /// sixty-four zero bytes - public, worthless, and never used for anything but filling a
    /// field the renderer prints and reads nothing from.
    fn account() -> crate::Owner {
        use notyas_core::derive::{Account, ChildIndex, Scheme};
        crate::Owner::Account(
            Account::derive(&[0u8; 64], Network::Bitcoin, Scheme::Bip84, ChildIndex::ZERO)
                .expect("bip84 is a derivable scheme")
                .id(),
        )
    }

    pub(crate) fn review(inputs: Vec<InputFacts>, outputs: Vec<OutputFacts>) -> TxReview {
        let input_total = Amount::from_sat(inputs.iter().map(|i| i.value.to_sat()).sum());
        let output_total = Amount::from_sat(outputs.iter().map(|o| o.value.to_sat()).sum());
        let signable = inputs.iter().filter(|i| matches!(i.claim, Claim::Ours { .. })).count();
        TxReview {
            inputs,
            outputs,
            input_total,
            output_total,
            fee: ReviewedFee::Enforced(Amount::from_sat(
                input_total.to_sat().saturating_sub(output_total.to_sat()),
            )),
            lock_time: LockTime::ZERO,
            rbf_signaled: true,
            network: Network::Bitcoin,
            fingerprint: String::from("a1b2c3d4"),
            wallet: String::from("savings"),
            source: String::from("psbt-2026-08-17.psbt"),
            signable_inputs: signable,
            unknown_fields: 0,
            serialized_len: 2400,
            psbt_id: String::from(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            ),
            vsize: 226,
            vsize_exact: true,
            warnings: vec![TxWarning {
                headline: String::from("Fee is 3.4% of the amount leaving."),
                detail: String::from("0.00 004 210 BTC on 0.00 123 456 BTC sent."),
            }],
        }
    }

    /// The ordinary case: two proven inputs, one payment, one proven change.
    pub(crate) fn plain_review() -> TxReview {
        review(
            vec![
                input(0, 5_000_000, AmountProof::ProvenByPrevTx, true),
                input(1, 8_000_000, AmountProof::ProvenByPrevTx, true),
            ],
            vec![
                output(0, 12_345_678, OutputRole::Payment),
                output(1, 650_112, OutputRole::Change { owner: account(), index: 12 }),
            ],
        )
    }

    /// A review whose second input's amount is the file's word and whose fee is therefore a
    /// lower bound.
    fn unproven_review() -> TxReview {
        let mut r = review(
            vec![
                input(0, 5_000_000, AmountProof::ProvenByPrevTx, true),
                input(1, 8_000_000, AmountProof::ClaimedByFile, false),
            ],
            vec![output(0, 12_345_678, OutputRole::Payment)],
        );
        r.fee = ReviewedFee::Stated(Amount::from_sat(654_322));
        r
    }

    /// The commonest spend there is, once the amount rule of 2026-08-21 landed: ONE input,
    /// its amount off `witness_utxo` alone, and the signature this device adds makes it
    /// binding because there is no second amount in the transaction to lie about.
    ///
    /// This is what a BlueWallet watch-only wallet sends back, and every property UI-1 to
    /// UI-4 is about is visible on it: the STATED prefix stays, the warning ink and the
    /// caveat band do not appear, the fee is exact, and the row at the bottom of the page
    /// says what the signature is doing rather than naming a script type.
    fn bound_review() -> TxReview {
        review(
            vec![input(0, 13_000_000, AmountProof::BoundByOurSignature, true)],
            vec![
                output(0, 12_345_678, OutputRole::Payment),
                output(1, 650_112, OutputRole::Change { owner: account(), index: 12 }),
            ],
        )
    }

    /// The change-confusion shape: the file says output 1 is change and nothing proved it.
    fn claimed_change_review() -> TxReview {
        review(
            vec![input(0, 13_000_000, AmountProof::ProvenByPrevTx, true)],
            vec![
                output(0, 12_345_678, OutputRole::Payment),
                output(1, 650_112, OutputRole::ClaimedButUnproven),
            ],
        )
    }

    /// Everything one page of this screen would print, recovered from the row set.
    ///
    /// The rows ARE the render: `draw_row` writes exactly these strings and adds no others,
    /// so a test that reads them is testing what reaches the panel rather than a parallel
    /// description of it.
    fn page_text(s: &ReviewState) -> String {
        let mut out = String::new();
        for row in s.build_rows() {
            match row {
                Row::Gap => {}
                Row::Band { lines, .. } => {
                    for l in lines {
                        out.push_str(&l);
                        out.push('\n');
                    }
                }
                Row::Pair { label, value, .. } => {
                    out.push_str(&label);
                    out.push(' ');
                    out.push_str(&value);
                    out.push('\n');
                }
                Row::Caption(c) => {
                    out.push_str(&c);
                    out.push('\n');
                }
                Row::Mono(v) => {
                    out.push_str(&v);
                    out.push('\n');
                }
                Row::Prose { text, .. } => {
                    out.push_str(&text);
                    out.push('\n');
                }
            }
        }
        out
    }

    /// Everything the whole traversal would print.
    fn all_text(review: TxReview) -> String {
        let mut s = ReviewState::new(review);
        let mut out = String::new();
        for p in 0..s.pages() {
            s.page = p;
            out.push_str(&page_text(&s));
        }
        out
    }

    fn ids(s: &ReviewState, f: &Fixture) -> Vec<RegionId> {
        let mut out = Vec::new();
        s.regions(&f.ctx(), &mut out);
        out.into_iter().map(|r| r.id).collect()
    }

    fn env<'a>(f: &'a Fixture, network: &'a mut Network, gate: &'a mut UnlockGate) -> Env<'a> {
        Env { network, lock: &f.lock, wallets: &f.wallets, gate }
    }

    /// Walk the whole traversal with Next, which is what a user who reads every page does.
    fn read_everything(s: &mut ReviewState, f: &Fixture) {
        let mut net = Network::Bitcoin;
        let mut gate = UnlockGate::default();
        let mut e = env(f, &mut net, &mut gate);
        for _ in 0..s.pages() {
            s.activate(RegionId::ReviewNext, &mut e);
        }
    }

    // -- The security core ---------------------------------------------------------------

    /// An amount the device could not prove never renders like one it did.
    ///
    /// The claim is about the STRING, not about the colour: [`input_amount_text`] is the
    /// only function that turns an input's value into text, so the qualifier is inseparable
    /// from the digits on a monochrome photograph and for a colour-blind reader alike.
    ///
    /// Broken version that this fails against: drop the `ClaimedByFile` arm of
    /// `input_amount_text` to `btc(f.value)`. The two amounts then render identically and
    /// the first two assertions trip.
    #[test]
    fn an_unproven_amount_never_renders_like_a_proven_one() {
        let proven = input(0, 5_000_000, AmountProof::ProvenByPrevTx, true);
        let claimed = input(1, 5_000_000, AmountProof::ClaimedByFile, true);
        assert_eq!(input_amount_text(&proven), "0.05 000 000 BTC");
        assert_eq!(input_amount_text(&claimed), "STATED 0.05 000 000 BTC");
        assert_ne!(
            input_amount_text(&proven),
            input_amount_text(&claimed),
            "two inputs of equal value must not print the same when only one is proven"
        );

        // ...and it reaches the panel: the page carries the qualifier and a band saying so.
        let mut s = ReviewState::new(unproven_review());
        s.page = 2; // the second input
        let text = page_text(&s);
        assert!(text.contains("STATED 0.08 000 000 BTC"), "{text}");
        assert!(text.contains("NOT PROVEN"), "{text}");
        assert!(text.contains("NOT CHECKED"), "{text}");
    }

    /// The single-input spend the amount rule admits, rendered end to end.
    ///
    /// Four claims at once, because they are one claim about one page: the amount keeps its
    /// STATED prefix (UI-1), it is NOT painted in the warning ink and no caveat band sits
    /// above it (UI-3), the caveat row says what the signature does rather than naming
    /// taproot (UI-2), and the fee is a measurement rather than a lower bound (UI-4).
    ///
    /// Broken version: give [`AmountProof::BoundByOurSignature`] the WARNING ink in
    /// `input_rows`. The third assertion trips, and an ordinary spend starts shouting.
    #[test]
    fn a_bound_amount_is_stated_without_being_warned_about() {
        let mut s = ReviewState::new(bound_review());
        s.page = 1; // the only input
        let rows = s.build_rows();
        let text = page_text(&s);

        assert!(text.contains("STATED 0.13 000 000 BTC"), "{text}");
        assert!(!text.contains("NOT PROVEN"), "{text}");
        assert!(!text.contains("NOT CHECKED"), "{text}");
        assert!(text.contains("cannot confirm"), "{text}");
        assert!(!text.contains("(taproot)"), "{text}");

        let amount_ink = rows
            .iter()
            .find_map(|r| match r {
                Row::Pair { label, ink, .. } if label == "Amount" => Some(*ink),
                _ => None,
            })
            .expect("the input page prints an amount");
        assert_ne!(amount_ink, WARNING, "a bound amount must not wear the warning ink");
        assert!(
            !rows.iter().any(|r| matches!(r, Row::Band { .. })),
            "a bound amount raises no caveat band"
        );

        // UI-4: nothing on the traversal qualifies this fee, because the transaction that
        // carries this signature has to pay it.
        let all = all_text(bound_review());
        assert!(!all.contains("AT LEAST"), "{all}");
        assert!(!all.contains("at least "), "{all}");
    }

    /// A forged change claim beside a bound amount still cannot be signed.
    ///
    /// Fixture E of the BlueWallet corpus reaches the output map for the first time under
    /// the amount rule of 2026-08-21: the input level has nothing to say about it, so the
    /// only thing standing between the user and a signature is `blocker`. This is that
    /// second gate, on the exact shape that now reaches it.
    ///
    /// Broken version: delete the first arm of `blocker`. Both assertions trip and the hold
    /// appears on a transaction whose change nobody proved.
    #[test]
    fn a_forged_change_claim_beside_a_bound_amount_still_blocks_the_hold() {
        let mut r = bound_review();
        r.outputs[1].role = OutputRole::ClaimedButUnproven;
        let blocked = ReviewState::new(r);
        assert!(blocked.blocker().is_some(), "an unproven change claim must block");

        // ...and the same file with its change proven is signable, so what blocks it is the
        // change claim and not the bound amount beside it.
        assert!(ReviewState::new(bound_review()).blocker().is_none());
    }

    /// A fee the device could not bind is never printed as a measurement, and neither is any
    /// number derived from it.
    ///
    /// Broken version: return `btc(a)` from both arms of `fee_amount_text`. The first
    /// assertion trips; deleting `fee_qualifier` instead trips the sat/vB one.
    #[test]
    fn an_unenforced_fee_is_a_lower_bound_everywhere_it_appears() {
        let enforced = ReviewedFee::Enforced(Amount::from_sat(4210));
        let stated = ReviewedFee::Stated(Amount::from_sat(4210));
        assert_eq!(fee_amount_text(enforced), "0.00 004 210 BTC");
        assert_eq!(fee_amount_text(stated), "AT LEAST 0.00 004 210 BTC");

        let text = all_text(unproven_review());
        assert!(text.contains("AT LEAST"), "the overview and the fee page must qualify it");
        assert!(text.contains("NOT ENFORCED"), "{text}");
        assert!(text.contains("at least") && text.contains("sat/vB"), "{text}");
        // The bare number must not appear anywhere on the traversal.
        assert!(
            !text.contains("\nFee 0.00 654 322 BTC"),
            "an unenforced fee printed as a measurement: {text}"
        );
    }

    /// A change claim nobody proved is counted as money leaving, and never as change.
    ///
    /// Three places count money and all three must agree, because a user reads the overview
    /// and never re-does the arithmetic: the leaving/change split, the "Leaving this wallet"
    /// headline, and the badge on the output's own page.
    ///
    /// Broken version: change `output_split` to count `ClaimedButUnproven` as change (or add
    /// it to `OutputRole::is_change` in the core). "1 leaving, 1 change" appears, the
    /// headline drops to the payment alone, and the first two assertions trip.
    #[test]
    fn an_unproven_change_claim_is_not_counted_as_change() {
        let r = claimed_change_review();
        // 12_345_678 + 650_112: the claim is INSIDE the amount leaving.
        assert_eq!(r.leaving(), Amount::from_sat(12_995_790));
        assert_eq!(r.change(), Amount::ZERO);

        let s = ReviewState::new(r);
        assert_eq!(s.output_split(), (2, 0), "the claim belongs on the leaving side");
        let overview = page_text(&s);
        assert!(overview.contains("2 leaving"), "{overview}");
        assert!(overview.contains("0 change (verified)"), "{overview}");
        assert!(overview.contains("Leaving this wallet    0.12 995 790 BTC"), "{overview}");
        assert!(overview.contains("counted as money leaving"), "{overview}");

        let mut s = ReviewState::new(claimed_change_review());
        s.page = 3; // the second output
        let page = page_text(&s);
        assert!(page.contains(BADGE_UNPROVEN), "{page}");
        assert!(!page.contains(BADGE_CHANGE), "the unproven claim must not wear the change badge");
    }

    /// ...and it cannot be signed, however thoroughly it is read.
    ///
    /// Broken version: delete the first arm of `blocker`. The hold appears after the
    /// traversal and both assertions trip.
    #[test]
    fn an_unproven_change_claim_cannot_be_signed() {
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            let mut s = ReviewState::new(claimed_change_review());
            read_everything(&mut s, &f);
            assert_eq!(s.unseen(), 0, "{w}x{h}: the traversal did not complete");
            assert!(
                !ids(&s, &f).contains(&RegionId::HoldConfirm),
                "{w}x{h}: a refused transaction offered the hold"
            );
            let mut net = Network::Bitcoin;
        let mut gate = UnlockGate::default();
            let out = s.activate(RegionId::HoldConfirm, &mut env(&f, &mut net, &mut gate));
            assert!(out.request.is_none(), "{w}x{h}: a forced hold raised SignTx");
            assert_eq!(s.id(), ScreenId::ReviewTransaction, "{w}x{h}: it entered S-37 anyway");
        }
    }

    /// Signing is unreachable until every page has been seen, and the button that is not
    /// there says why.
    ///
    /// Broken version: make `armed` return `self.blocker().is_none()`. The hold appears on
    /// the last page of an unread review and the loop's first assertion trips.
    #[test]
    fn signing_is_unreachable_without_the_whole_review() {
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            let mut s = ReviewState::new(plain_review());
            let last = s.pages() - 1;

            // Jump straight to the last page, which is the shortest route a mis-wired
            // pager could offer.
            s.page = last;
            s.arrive();
            assert!(
                !ids(&s, &f).contains(&RegionId::HoldConfirm),
                "{w}x{h}: the hold existed with {} pages unseen",
                s.unseen()
            );
            let reason = s.gate_reason().expect("an unarmed gate states its reason");
            assert!(reason.contains("Review all"), "{w}x{h}: {reason}");
            assert!(
                page_text(&s).contains(&reason),
                "{w}x{h}: the reason is not on the page the control is on"
            );
            let mut net = Network::Bitcoin;
        let mut gate = UnlockGate::default();
            assert!(
                s.activate(RegionId::HoldConfirm, &mut env(&f, &mut net, &mut gate)).request.is_none(),
                "{w}x{h}: a hold fired from Ui::tick bypassed the traversal"
            );

            // Reading every page is what arms it.
            let mut s = ReviewState::new(plain_review());
            read_everything(&mut s, &f);
            assert!(
                ids(&s, &f).contains(&RegionId::HoldConfirm),
                "{w}x{h}: a complete review must offer the hold"
            );
            assert!(s.gate_reason().is_none(), "{w}x{h}: an armed gate has no reason");
            assert!(s.gate_line().is_none(), "{w}x{h}");
        }
    }

    /// Reading back and forth is fine; skipping is not. C5's visited-set rule, which index
    /// arithmetic cannot express.
    #[test]
    fn the_visited_set_counts_pages_and_not_distance() {
        let f = Fixture::new(720, 720);
        let mut net = Network::Bitcoin;
        let mut gate = UnlockGate::default();
        let mut e = env(&f, &mut net, &mut gate);
        let mut s = ReviewState::new(plain_review());
        let pages = s.pages();
        s.activate(RegionId::ReviewNext, &mut e);
        s.activate(RegionId::ReviewPrev, &mut e);
        assert_eq!(s.unseen(), pages - 2, "going back must not un-see a page");
        for _ in 0..pages {
            s.activate(RegionId::ReviewNext, &mut e);
        }
        assert_eq!(s.unseen(), 0);
        assert_eq!(s.page, pages - 1, "Next must not run off the end");
    }

    /// The hold is the commit point, and it is the ONLY way into S-37.
    #[test]
    fn the_hold_is_the_only_route_into_signing() {
        let f = Fixture::new(800, 480);
        let mut net = Network::Bitcoin;
        let mut gate = UnlockGate::default();
        let mut s = ReviewState::new(plain_review());
        for id in [RegionId::ReviewNext, RegionId::ReviewPrev, RegionId::Back, RegionId::Lock] {
            let out = s.activate(id, &mut env(&f, &mut net, &mut gate));
            assert!(out.request.is_none(), "{id:?} raised a request");
            assert_eq!(s.id(), ScreenId::ReviewTransaction, "{id:?} entered S-37");
        }
        read_everything(&mut s, &f);
        let out = s.activate(RegionId::HoldConfirm, &mut env(&f, &mut net, &mut gate));
        assert!(matches!(out.request, Some(UiRequest::SignTx)));
        assert_eq!(s.id(), ScreenId::Signing, "the hold must publish S-37 before the work");
        // S-37 is inert: nothing tappable, no Back, and no second signature.
        assert!(ids(&s, &f).is_empty(), "S-37 offered a control");
        assert!(matches!(s.back(), Nav::Stay), "S-37 offered a way out");
        assert!(s.activate(RegionId::HoldConfirm, &mut env(&f, &mut net, &mut gate)).request.is_none());
    }

    /// Both halves of the signing answer land somewhere the user can act on.
    #[test]
    fn signing_answers_both_ways() {
        let f = Fixture::new(720, 720);
        let mut net = Network::Bitcoin;
        let mut gate = UnlockGate::default();
        let mut s = ReviewState::new(plain_review());
        read_everything(&mut s, &f);
        s.activate(RegionId::HoldConfirm, &mut env(&f, &mut net, &mut gate));
        let signed = SignedTx {
            signed_inputs: 2,
            verified_inputs: 2,
            signable_inputs: 2,
            complete: true,
            artifacts: Vec::new(),
            psbt_id: String::from("00"),
        };
        let out = s.answered(Answer::Sign(SignOutcome::Signed(signed)), &mut env(&f, &mut net, &mut gate));
        assert!(matches!(out.nav, Nav::Enter(State::Deliver(_))));

        let mut s = ReviewState::new(plain_review());
        read_everything(&mut s, &f);
        s.activate(RegionId::HoldConfirm, &mut env(&f, &mut net, &mut gate));
        let notice = RefusalNotice {
            code: RefusalCode::SignatureCheckFailed,
            happened: String::from("The device produced a signature that did not verify."),
            details: String::from("check 10"),
            after_signing: true,
        };
        let out = s.answered(Answer::Sign(SignOutcome::Refused(notice)), &mut env(&f, &mut net, &mut gate));
        assert!(matches!(out.nav, Nav::Enter(State::Refusal(_))), "a refusal must be a screen");
    }

    /// Back is a question. An accidental tap after nine pages must not cost the reading.
    #[test]
    fn back_asks_before_it_leaves() {
        let f = Fixture::new(720, 720);
        let mut net = Network::Bitcoin;
        let mut gate = UnlockGate::default();
        let s = ReviewState::new(plain_review());
        assert!(matches!(s.back(), Nav::Stay), "Back must move nothing on its own");
        let sheet: Vec<RegionId> = ids(&s, &f);
        assert_eq!(
            sheet,
            vec![RegionId::DangerCancel, RegionId::DangerConfirm],
            "an open sheet is the only thing on the panel"
        );
        let mut s = s;
        assert!(matches!(
            s.activate(RegionId::DangerCancel, &mut env(&f, &mut net, &mut gate)).nav,
            Nav::Stay
        ));
        assert!(ids(&s, &f).contains(&RegionId::ReviewNext), "cancel returns to the page");
        s.back();
        assert!(matches!(
            s.activate(RegionId::DangerConfirm, &mut env(&f, &mut net, &mut gate)).nav,
            Nav::Back
        ));
    }

    // -- Geometry ------------------------------------------------------------------------

    /// Every page's rectangles are on the panel, clear of one another, and tappable, on both
    /// shipped geometries and on every page of a transaction with a page of each kind.
    #[test]
    fn every_page_lays_out_on_both_panels() {
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            let ctx = f.ctx();
            let mut s = ReviewState::new(plain_review());
            for page in 0..s.pages() {
                s.page = page;
                s.arrive();
                let l = s.layout(&ctx);
                let what = format!("{w}x{h} page {page}");
                let mut rects = vec![("viewport", l.viewport)];
                if let Some(r) = l.prev {
                    rects.push(("prev", r));
                }
                if let Some(r) = l.next {
                    rects.push(("next", r));
                }
                if let Some(r) = l.hold {
                    rects.push(("hold", r));
                }
                rows_are_clear_on(&f.m, &what, f.m.screen(), &rects);
                assert!(l.viewport.h > 3 * LINE, "{what}: the viewport is {} px", l.viewport.h);
                for (name, r) in &rects[1..] {
                    assert!(
                        r.w >= TOUCH_MIN && r.h >= TOUCH_MIN,
                        "{what}: {name} is {}x{}",
                        r.w,
                        r.h
                    );
                }
                if let Some(hold) = l.hold {
                    assert!(hold.h >= HOLD_BAR_H, "{what}: the hold bar is {} px tall", hold.h);
                    assert!(
                        hold.w * 5 >= f.m.body().w * 3,
                        "{what}: the hold bar is under 60% of the body"
                    );
                    assert!(l.prev.is_some(), "{what}: the last page kept no way back");
                }
            }
        }
    }

    /// The primary action of a page never sits where the previous page's primary action was
    /// (R-NOTHROUGH): a double tap on `Next >` must not land on the hold.
    #[test]
    fn the_hold_never_lands_under_the_next_button() {
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            let ctx = f.ctx();
            let mut s = ReviewState::new(plain_review());
            s.page = s.pages() - 2;
            let next = s.layout(&ctx).next.expect("the page before the last has Next");
            s.page = s.pages() - 1;
            let hold = s.layout(&ctx).hold.expect("the last page has the hold");
            assert!(!next.overlaps(&hold), "{w}x{h}: {next:?} overlaps the hold at {hold:?}");
        }
    }

    /// The same region set at both geometries, on every page. Reflow rule 4: nothing is
    /// dropped on the shorter panel, only relocated.
    #[test]
    fn the_region_set_is_the_same_on_both_panels() {
        let a = Fixture::new(GEOMETRIES[0].0, GEOMETRIES[0].1);
        let b = Fixture::new(GEOMETRIES[1].0, GEOMETRIES[1].1);
        let mut sa = ReviewState::new(plain_review());
        let mut sb = ReviewState::new(plain_review());
        for page in 0..sa.pages() {
            sa.page = page;
            sa.arrive();
            sb.page = page;
            sb.arrive();
            assert_eq!(ids(&sa, &a), ids(&sb, &b), "page {page} differs between panels");
        }
    }

    /// Every label of the frozen vocabulary fits the column it is drawn in, on both panels.
    /// A label that wrapped would break the column model; one that cropped could not be
    /// identified against the wallet software beside it.
    #[test]
    fn the_pair_labels_fit_the_column() {
        const LABELS: [&str; 15] = [
            "Inputs",
            "Outputs",
            "Network",
            "Warnings",
            "File",
            "Amount",
            "From",
            "Script type",
            "Registration",
            "Output index",
            "Derived by",
            "Change index",
            "Receive index",
            "Fee",
            "In sats",
        ];
        for label in LABELS {
            let need = BODY.text_width(label) as i32;
            assert!(need < LABEL_COL - 16, "{label:?} needs {need} px of a {LABEL_COL} px column");
        }
        // ...and the column itself fits the narrower body.
        for (w, h) in GEOMETRIES {
            let m = Metrics::new(w, h);
            assert!(LABEL_COL * 2 < m.body().w, "{w}x{h}: the label column is over half the body");
        }
    }

    /// A value too wide for the value column is promoted to its own full-width line rather
    /// than cropped. The one rule that keeps an amount whole on the narrow panel.
    #[test]
    fn a_long_value_is_promoted_and_never_cropped() {
        for (w, h) in GEOMETRIES {
            let m = Metrics::new(w, h);
            let body = m.body().w;
            let long = "STATED 21000000.00 000 000 BTC";
            let row = Row::pair("Amount", long);
            let promoted = !pair_value_fits(long, true, body);
            let expected = if promoted { LINE + value_lines(long, true, body) } else { LINE };
            assert_eq!(row.height(&m, body), expected, "{w}x{h}");
            // Whatever happens, the whole value is drawn: wrapping preserves every
            // character, and there is no ellipsis path in this module at all.
            let drawn: String = wrap_words(long, body, MONO).join(" ");
            assert_eq!(drawn, long, "{w}x{h}: a value lost characters");
        }
    }

    /// A C8 block breaks by whole groups and never loses a character, at either geometry.
    #[test]
    fn a_mono_block_never_truncates() {
        let value = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        for (w, h) in GEOMETRIES {
            let m = Metrics::new(w, h);
            let lines = mono_lines(value, m.body().w);
            let recovered: String = lines.iter().map(|(_, l)| l.replace(' ', "")).collect();
            assert_eq!(recovered, value, "{w}x{h}: the block dropped characters");
            let mut offset = 0usize;
            for (gutter, line) in &lines {
                assert_eq!(*gutter, format!("{offset:02}"), "{w}x{h}: the gutter drifted");
                offset += line.replace(' ', "").chars().count();
            }
        }
    }

    // -- Copy ----------------------------------------------------------------------------

    /// Every string this screen can put on the panel is ASCII, so the atlas can draw it.
    #[test]
    fn every_rendered_string_is_ascii() {
        let mut text = all_text(plain_review());
        text.push_str(&all_text(unproven_review()));
        text.push_str(&all_text(claimed_change_review()));
        for (i, c) in text.chars().enumerate() {
            assert!(
                c.is_ascii() && (c == '\n' || (' '..='~').contains(&c)),
                "character {i} is {c:?}, which is not in the atlas"
            );
        }
        assert!(!text.contains('\u{2013}') && !text.contains('\u{2014}'), "a dash escaped");
    }

    /// The badge vocabulary is the frozen one, and the precedence is the documented one.
    #[test]
    fn the_badges_are_the_frozen_vocabulary() {
        let owner = account();
        let cases: [(OutputRole, ScriptKind, &str); 6] = [
            (OutputRole::Payment, ScriptKind::P2wpkh, BADGE_EXTERNAL),
            (OutputRole::Change { owner, index: 1 }, ScriptKind::P2wpkh, BADGE_CHANGE),
            (OutputRole::ClaimedButUnproven, ScriptKind::P2wpkh, BADGE_UNPROVEN),
            (OutputRole::OwnNotChange { owner, index: 1 }, ScriptKind::P2wpkh, BADGE_OURS),
            (OutputRole::Payment, ScriptKind::OpReturn, BADGE_DATA),
            (OutputRole::Payment, ScriptKind::Other, BADGE_UNKNOWN),
        ];
        for (role, kind, expected) in cases {
            let mut o = output(0, 1, role);
            o.kind = kind;
            assert_eq!(badge_for(&o).0, expected, "{role:?} / {kind:?}");
        }
        // Precedence: a claim nobody proved outranks the script's own shape, because the
        // claim is the attack.
        let mut o = output(0, 1, OutputRole::ClaimedButUnproven);
        o.kind = ScriptKind::Other;
        assert_eq!(badge_for(&o).0, BADGE_UNPROVEN);
    }

    /// Satcomma, exactly: eight decimals grouped 2-3-3, never rounded.
    #[test]
    fn amounts_are_satcomma() {
        assert_eq!(btc(Amount::from_sat(0)), "0.00 000 000 BTC");
        assert_eq!(btc(Amount::from_sat(1)), "0.00 000 001 BTC");
        assert_eq!(btc(Amount::from_sat(12_345_678)), "0.12 345 678 BTC");
        assert_eq!(btc(Amount::from_sat(2_100_000_000_000_000)), "21000000.00 000 000 BTC");
    }

    /// An OP_RETURN payload is shown as printable ASCII with a period for every other byte,
    /// with the count stated - never a decoded string that could carry control characters.
    #[test]
    fn a_data_payload_is_never_decoded() {
        assert_eq!(printable(b"hi\x00\x1b[2Jthere"), "hi..[2Jthere");
        let mut r = claimed_change_review();
        r.outputs = vec![{
            let mut o = output(0, 0, OutputRole::Payment);
            o.kind = ScriptKind::OpReturn;
            o.script_pubkey = ScriptBuf::from_bytes(b"\x6a\x04\x00\x01\x02\x03".to_vec());
            o
        }];
        let mut s = ReviewState::new(r);
        s.page = 2;
        let text = page_text(&s);
        assert!(text.contains("Payload (6 bytes, hex)"), "{text}");
        assert!(text.contains("6a04000102 03") || text.contains("6a04000102"), "{text}");
        assert!(text.contains("This output carries data, not coins."), "{text}");
    }

    /// The page order is the fixed semantic one, and its count is the core's.
    #[test]
    fn the_page_order_is_fixed_and_semantic() {
        let s = ReviewState::new(plain_review());
        assert_eq!(s.pages(), 3 + 2 + 2);
        assert_eq!(s.kind(0), PageKind::Overview);
        assert_eq!(s.kind(1), PageKind::Input(0));
        assert_eq!(s.kind(2), PageKind::Input(1));
        assert_eq!(s.kind(3), PageKind::Output(0));
        assert_eq!(s.kind(4), PageKind::Output(1));
        assert_eq!(s.kind(5), PageKind::Fee);
        assert_eq!(s.kind(6), PageKind::Warnings);
    }

    /// A foreign input is shown, never hidden. A signer that drops the rows it will not
    /// sign is a signer that can be shown one thing and sign another.
    #[test]
    fn a_foreign_input_is_shown_and_named() {
        let mut s = ReviewState::new(unproven_review());
        s.page = 2;
        let text = page_text(&s);
        assert!(text.contains("not from this wallet"), "{text}");
        assert!(text.contains("It will not be signed here"), "{text}");
        let overview = page_text(&ReviewState::new(unproven_review()));
        assert!(overview.contains("1 of 2 from savings"), "{overview}");
    }

    /// The line beside the disabled control fits the line it is drawn in, on both panels
    /// and for both reasons a gate can have. A reason that crops is a dead button.
    #[test]
    fn the_gate_line_fits_beside_the_disabled_control() {
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            let ctx = f.ctx();
            for review in [plain_review(), claimed_change_review()] {
                let mut s = ReviewState::new(review);
                s.page = s.pages() - 1;
                let l = s.layout(&ctx);
                let band = l.hold.expect("the last page has the band");
                let (control, line) = gate_split(band);
                assert!(!control.overlaps(&line), "{w}x{h}: the control sits on its reason");
                assert!(control.h >= TOUCH_MIN, "{w}x{h}: the control is {} px", control.h);
                let reason = s.gate_line().expect("an unread review states its reason");
                fits(&format!("{w}x{h} gate"), &reason, BODY.text_width(&reason) as i32, line);
            }
        }
    }

    /// The C4c copy is C4c's, so a photograph of the moment of consent describes itself.
    #[test]
    fn the_hold_says_what_it_signs() {
        let f = Fixture::new(720, 720);
        let mut s = ReviewState::new(plain_review());
        read_everything(&mut s, &f);
        let l = s.layout(&f.ctx());
        assert!(l.armed);
        assert!(l.hold.is_some());
        assert_eq!(HOLD_MS, 1500, "the hold duration is a constant, never a setting");
    }
    /// A frame builds the page it paints ONCE, however much is on it.
    ///
    /// The defect this pins is structural rather than cosmetic. `regions` and `draw` each
    /// call `layout`, `layout` needs the content height, and `draw` needs the rows again to
    /// paint them: three builds and three full measurements per frame of a row set whose
    /// size the file's author chooses. Measured on the warnings page of a 255-output file
    /// before the fix, one `draw` alone cost 2.9 million allocations and 162 ms on a host
    /// far faster than the panel; after it, a frame costs 82.
    ///
    /// Broken version this fails against: have `layout` and `draw` call `build_rows`
    /// directly, as they did. The count goes to 3 on the first frame and keeps climbing.
    #[test]
    fn a_frame_builds_its_page_once() {
        let f = Fixture::new(800, 480);
        let ctx = f.ctx();
        let mut r = plain_review();
        r.warnings = (0..255)
            .map(|i| TxWarning {
                headline: format!("Outputs {i} and {} pay the same address.", i + 1),
                detail: String::from("This transaction pays it twice; check that is intended."),
            })
            .collect();
        let mut s = ReviewState::new(r);
        s.page = s.pages() - 1;

        // One frame, in the order the driver runs it: hit-testing, then painting, then the
        // scroll clamp a drag asks for.
        let mut regions = Vec::new();
        s.regions(&ctx, &mut regions);
        s.draw(&mut crate::NullTarget, &ctx).expect("the null target never fails");
        let _ = s.scroll_limit(&ctx);
        assert_eq!(s.builds.get(), 1, "one page on the panel is one row build");

        // ...and the frame after it costs nothing at all.
        s.regions(&ctx, &mut regions);
        s.draw(&mut crate::NullTarget, &ctx).expect("the null target never fails");
        assert_eq!(s.builds.get(), 1, "an unchanged page must not be rebuilt");

        // What the cache is keyed on, one key at a time. Each of these three changes the
        // rows, and a screen that showed the previous page's text would be a user deciding
        // on numbers that are not on the panel.
        s.page -= 1;
        s.draw(&mut crate::NullTarget, &ctx).expect("the null target never fails");
        assert_eq!(s.builds.get(), 2, "a different page is a different row set");

        s.page += 1;
        s.visited = vec![true; s.pages()];
        s.draw(&mut crate::NullTarget, &ctx).expect("the null target never fails");
        assert_eq!(s.builds.get(), 3, "the warnings page prints how many pages are unseen");

        let narrow = Fixture::new(480, 800);
        s.draw(&mut crate::NullTarget, &narrow.ctx()).expect("the null target never fails");
        assert_eq!(s.builds.get(), 4, "heights are measured against a body width");
    }

}
