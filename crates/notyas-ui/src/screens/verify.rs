// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! S-46 Verify device: an instrument panel, not a report.
//!
//! The screen displays [`VerifyInfo`] and computes no part of it: every value is read by
//! the firmware from the running system (SECURITY.md invariant 5), and a value the
//! device did not measure prints `not read` rather than a plausible default. VERIFY.md
//! sections 10 and 11 are the specification; three of its rules shape this module and
//! are worth stating where the code is, because each of them rules out an implementation
//! that would otherwise be shorter.
//!
//! **Raw values, shown.** No digest is truncated, abbreviated or hidden behind a tap.
//! Grouping a digest into fours and wrapping it is formatting and is required;
//! substituting a shortened form is obscuring and is forbidden. Scrolling is acceptable,
//! hiding is not - which is why the sheet is long and has a pager rather than collapsed
//! sections.
//!
//! **No opining.** Label the field, print the value, stop. No verdict, no badge, no
//! advice sentence beside a value. The only semantic colour is [`DANGER`] on the two
//! rows 0.1.0 already coloured - a failed self-test and a radio not held in reset - and
//! even there the WORD carries the meaning and the colour only reinforces it. `not read`
//! is [`INK_MUTED`] because it is the absence of a value, not a bad value.
//!
//! **A frozen field order.** [`sheet`] is that order, written once. Two units held side
//! by side are meant to be SCANNED rather than read, which only works if the same field
//! is at the same position in every build; CI asserts the rendered label sequence
//! against a checked-in list, at both geometries.
//!
//! # The three row kinds, and the one decision this module makes about them
//!
//! Everything on the sheet is a section heading or one of exactly three shapes (11.1):
//! K1 an inline row, K2 a block that gets the full width, K3 a fixed-column table. A
//! fourth shape is a design review.
//!
//! The decision: **a K1 value that does not fit the inline column becomes a K2 block**,
//! chosen by [`INLINE_BUDGET`] rather than by the panel. 11.7 asserts that no K1 value
//! ever exceeds the 720x720 value column, so the choice cannot be left to the renderer: a
//! value that wrapped would break the column model, and a value that truncated would break
//! contract rule 1. Routing it to a block satisfies both, keeps the label sequence
//! identical, and is why a self-test row naming five failed vectors still shows all five.
//! See [`LABEL_COL`] for why the two column widths are constants here rather than 11.1's
//! formula - which does not hold its own field list.
//!
//! # The pager, and why nothing on this screen is a fixed footer
//!
//! The sheet is ten to twenty viewports long, so C6's explicit pager applies: `[ < Prev ]`
//! and `[ Next > ]` at the foot, `[ i / n ]` in the bar's right slot, and one reserved
//! edge strip carrying `more above` / `more below`. Drag-scroll stays the fast path and
//! shares the same offset. Two properties are load-bearing and both live in
//! [`page_starts`]: the viewport height never depends on the page count (or the two would
//! chase each other), and a page break never cuts a row that FITS - which is what makes
//! every control reachable by the pager alone rather than only by a drag.
//!
//! Both controls that act on the device - `[ Scan ]` and `[ Mark as seen ]` - sit IN the
//! sheet beside the values they concern, not in a fixed footer. That is Q54's stated
//! reason for the regions existing, and for the write it is also invariant 2b's: the C12
//! band and its button are ONE row, so no page break can come between the sentence that
//! says what is written and the button that writes it. A footer band would have cost a
//! quarter of the body on the short panel and still let the reader page the rows it is
//! about out of sight.
//!
//! # What is on demand, and why the screen becomes a Busy screen
//!
//! The reserved-space scan reads roughly 14 MiB on board B and 30 MiB on board A, so it
//! runs behind `[ Scan ]` and never at boot (ratified Q57). This crate performs no I/O:
//! the tap raises [`UiRequest::ScanReservedSpace`], the screen becomes a C3 Busy frame
//! with nothing tappable, and the embedder answers through `Ui::set_flash_scan`. The
//! Busy state is a mode of THIS screen rather than a screen of its own because the
//! result fills in rows of this sheet and the reader's scroll position has to survive
//! it - but it reports its own [`ScreenId`], because a frame with no Back and nothing to
//! tap is a different screen to an embedder and to the region checks.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cell::Cell as CoreCell;

use embedded_graphics::draw_target::{DrawTarget, DrawTargetExt};
use embedded_graphics::pixelcolor::Rgb565;

use crate::canvas::{
    button, fill, panel, text, text_centered, wrap_words, ButtonKind, BODY, HEADING, MONO_SMALL,
};
use crate::components::{
    back_rect, draw_bar, draw_bar_no_back, write_notice, write_notice_h, LINE, SMALL_LINE,
};
use crate::layout::{Metrics, Rect, TOUCH_MIN};
use crate::screens::{Ctx, Env, Outcome, Screen};
use crate::theme::*;
use crate::{
    Bit, HexValue, Region, RegionDigest, RegionId, ReservedSpace, ScreenId, StoreStatus,
    UiRequest, VerifyInfo,
};

// ---------------------------------------------------------------------------------------
// Frozen measurements (VERIFY.md 11.1)
// ---------------------------------------------------------------------------------------

/// K1 row height: `SANS_REGULAR_32`'s line box plus 8.
const ROW_H: i32 = LINE + 8;

/// Height of a row that carries a control. A row is at least a touch target tall whatever
/// the type wants, because a 50 px button is not tappable and a control drawn where it
/// cannot be pressed is the one failure this crate's layout discipline exists to prevent.
const ACTION_ROW_H: i32 = if ROW_H > TOUCH_MIN + 4 { ROW_H } else { TOUCH_MIN + 4 };

/// Hex characters per group and groups per K2 line.
///
/// The break is a CONSTANT, not a fit computation. A 64-character digest is therefore
/// always exactly three lines, broken at exactly the same characters, on every panel and
/// in every build - which is what lets two devices be held side by side and compared line
/// by line. This is the single most important formatting decision on the screen.
const HEX_GROUP: usize = 4;
const HEX_GROUPS_PER_LINE: usize = 6;
/// Hex characters on one K2 line: 24.
const HEX_PER_LINE: usize = HEX_GROUP * HEX_GROUPS_PER_LINE;

/// Characters in C8's offset gutter, including its trailing space (`00 `).
const GUTTER_COLS: i32 = 3;

/// K3 character budget: `gap(12) + 38 * 17 = 658 px`, against 672 px of body at 720x720.
/// A table wider than this wraps to a two-line-per-entry form rather than shrinking the
/// font or truncating - which is why the key-block and span tables are two lines each.
// Read by the tests that hold the three shipped tables to the budget; the formatters
// themselves lay their columns out explicitly, so nothing in the draw path names it.
#[cfg_attr(not(test), allow(dead_code))]
const TABLE_COLS: usize = 38;

/// Width of the label column, and therefore the value column's origin.
///
/// A CONSTANT, and the one place this implementation departs from 11.1's arithmetic.
/// 11.1 computes `(body.w * 2 / 5).clamp(220, 300)`, which is 268 px at 720x720 - sixteen
/// characters of `SANS_REGULAR_32` - while section 10's own field list contains
/// `USB-serial-JTAG download` and `Flash unique ID (64 of 128)`, which measure 396 px.
/// The two cannot both hold, and truncating a LABEL is the option the contract forecloses:
/// a row whose NAME is cut cannot be identified on the unit beside it, which is the entire
/// point of freezing the order. So the column is sized to the label set rather than to the
/// panel, frozen with that set, and asserted against it; the inline value budget below is
/// what remains. 412 px is the widest label plus a 16 px gutter.
const LABEL_COL: i32 = 412;

/// Inline value budget in `MONO_SMALL` characters.
///
/// A constant rather than a function of the panel, deliberately: what remains beside
/// [`LABEL_COL`] is 248 px = 14 characters at 720x720 and 323 px = 19 at 800x480, and the
/// NARROWER panel governs so that a value never wraps on one panel and not on the other. A
/// value past this is a K2 block (see the module docs), which is where the MAC and the
/// flash unique id land - both are compared character by character anyway, so the block is
/// the better shape for them and no information is lost either way.
const INLINE_BUDGET: usize = 14;

/// The bar's title, and the label on the bar's Lock chip.
///
/// Named rather than written at the two call sites because both are MEASURED as well as
/// drawn: the right slot is sized to the label it paints and the title is what the slot
/// has to clear. A literal repeated between the draw and the measurement is a literal
/// that can be changed in one of them, and the failure that produces is text laid out
/// past the panel - which is invisible on the device and unrecoverable from a screenshot.
const BAR_TITLE: &str = "Verify device";
const LOCK_LABEL: &str = "Lock device";

/// The viewport counter's text, in the one place that formats it.
///
/// The width the layout reserves and the string the draw paints come from here, so the
/// two cannot be measured from different formats.
fn counter_label(page: i32, pages: i32) -> String {
    format!("{page} / {pages}")
}

/// The provenance note at the foot of the sheet (VERIFY.md 9.4). One line, no band, no
/// colour, no icon: a statement of where the numbers came from, which opines about
/// nothing. Fixed copy, asserted in CI like every other literal.
const PROVENANCE: &str =
    "These values are read from the chip and from flash by the firmware running on this \
     device.";

// ---------------------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------------------

/// The screen owns its scroll offset and whether the scan it asked for is still running.
/// Every value it SHOWS belongs to the `Ui`, installed by the embedder, and none of it is
/// secret.
pub(crate) struct VerifyState {
    scroll: i32,
    /// The pager's geometry as of the last layout.
    ///
    /// A cache, and the only interior mutability in the crate, for one reason worth
    /// stating. `Screen::activate` is given a [`RegionId`] and nothing else, deliberately,
    /// so that a screen cannot compute rectangles outside `layout`; a pager tap
    /// nevertheless has to step by exactly one viewport, which is geometry. It cannot be
    /// read stale: every press resolves through `Ui::hit` to `regions` to `layout`, so a
    /// tap that reaches `activate` has laid out first, twice.
    paging: CoreCell<Paging>,
    scan: Scan,
}

/// Where the two pager controls move to, as the last layout computed them.
#[derive(Clone, Copy, Default)]
struct Paging {
    prev: i32,
    next: i32,
}

/// Whether a reserved-space scan is in flight, and how far the embedder says it has got.
///
/// `Running` is what makes this screen a C3 Busy screen: the frame is painted by the
/// transition and the work runs on the std side, so the progress is something the
/// embedder TELLS the screen between spans rather than something the screen can observe.
/// `spans == 0` is the honest reading of "asked for, nothing reported yet".
enum Scan {
    Idle,
    Running { done: u8, spans: u8 },
}

impl VerifyState {
    pub fn new() -> VerifyState {
        VerifyState { scroll: 0, paging: CoreCell::new(Paging::default()), scan: Scan::Idle }
    }

    /// The public name of what is on the panel right now.
    pub fn id(&self) -> ScreenId {
        match self.scan {
            Scan::Idle => ScreenId::VerifyDevice,
            Scan::Running { .. } => ScreenId::ScanningFlash,
        }
    }

    /// Advance the C3 determinate progress, answering nothing: the scan is still running.
    /// Dropped unless a scan is in flight, so a stale report cannot resurrect the Busy
    /// frame over a sheet the user is reading.
    pub fn scan_progress(&mut self, done: u8, spans: u8) {
        if let Scan::Running { .. } = self.scan {
            self.scan = Scan::Running { done, spans };
        }
    }

    /// The scan finished. The RESULT lands on the `Ui`'s [`VerifyInfo`] because it is a
    /// measurement of the device rather than a fact about this screen; all that ends here
    /// is the Busy frame.
    pub fn scan_finished(&mut self) {
        self.scan = Scan::Idle;
    }
}

// ---------------------------------------------------------------------------------------
// The row vocabulary
// ---------------------------------------------------------------------------------------

/// A K1 value: what to print, and the ink to print it in.
///
/// The ink is never a verdict. It is [`INK_MUTED`] for an absent value, [`DANGER`] on
/// exactly the two rows 0.1.0 already coloured, and [`INK_PRIMARY`] everywhere else.
struct Cell {
    text: String,
    ink: Rgb565,
}

impl Cell {
    /// A value the device measured.
    fn read(text: impl Into<String>) -> Cell {
        Cell { text: text.into(), ink: INK_PRIMARY }
    }

    /// The absence of a value. VERIFY.md's one permitted placeholder.
    fn not_read() -> Cell {
        Cell { text: String::from("not read"), ink: INK_MUTED }
    }

    /// A measured value the WORD already marks (`FAILED: ...`, a radio not held low).
    /// The colour reinforces the word; it never carries the meaning alone.
    fn alarming(text: impl Into<String>) -> Cell {
        Cell { text: text.into(), ink: DANGER }
    }
}

/// A control that lives ON a row rather than in the footer, because it belongs beside the
/// value it fills in (Q54's stated reason for the region existing at all).
struct Action {
    id: RegionId,
    label: &'static str,
    /// Rectangle width; the height is [`TOUCH_MIN`].
    w: i32,
}

impl Action {
    /// What the control costs the value beside it, in `MONO_SMALL` characters: its own
    /// width plus a gutter, rounded up so the two never touch.
    fn cols(&self) -> usize {
        let adv = MONO_SMALL.glyph('m').advance as i32;
        ((self.w + adv) / adv) as usize + 1
    }
}

/// How a raw bit reads on a given row.
///
/// Three vocabularies because the wireframe uses three, and the row is where the choice
/// belongs: `enabled` is right for an access, `yes` for a policy flag, and the raw digit
/// for a selector that names a path rather than a state.
#[derive(Clone, Copy)]
enum Words {
    EnabledDisabled,
    YesNo,
    Raw,
}

/// The long half of a K2 block.
enum Body {
    /// Grouped in fours, six groups a line, with C8's offset gutter.
    Hex(String),
    /// A value too long for the inline column, wrapped at the full body width. The same
    /// shape as a hex block and for the same reason - the value gets the width - but
    /// without the gutter, which indexes hex characters and would mean nothing here.
    Text(String),
}

/// One row of the sheet. Exactly three kinds plus the section heading and the foot note;
/// a fourth shape is a design review, and this enum is where that is enforced.
enum Row {
    Section(&'static str),
    /// K1 - one label, one short value, one line.
    Inline { label: String, value: Cell, action: Option<Action> },
    /// K2 - one label, one long value that gets the full width.
    Block { label: String, body: Body, action: Option<Action> },
    /// K3 - a small matrix in fixed mono columns, specified in CHARACTERS so the table is
    /// byte-identical at both geometries.
    Table { label: String, lines: Vec<String>, action: Option<Action> },
    /// C12: the write announcement and the button that performs it, in that order.
    ///
    /// Not a fourth row KIND - the three kinds are how a FIELD is rendered, and this
    /// renders no field. It is furniture, like the section rule and the provenance note.
    /// It lives IN the sheet rather than in a fixed footer for the reason invariant 2b
    /// exists: the band has to be above the action, and a footer band costs a quarter of
    /// the body on the short panel while still letting the reader scroll the rows it is
    /// about out of sight.
    Write,
    /// The provenance note (VERIFY.md 9.4).
    Note,
}

/// The C12 copy, verbatim from VERIFY.md 6.3.
const WRITE_WHAT: &str = "This writes to the device: boot counter acknowledgement.";
const WRITE_CONFIDENTIALITY: &str = "Nothing secret is written.";

impl Row {
    /// The row's label, for the frozen-order assertion. A section heading is a label too:
    /// the six headings are part of the order CI pins.
    #[cfg_attr(not(test), allow(dead_code))]
    fn label(&self) -> &str {
        match self {
            Row::Section(s) => s,
            Row::Inline { label, .. } => label,
            Row::Block { label, .. } => label,
            Row::Table { label, .. } => label,
            Row::Write => WRITE_WHAT,
            Row::Note => PROVENANCE,
        }
    }

    fn action(&self) -> Option<&Action> {
        match self {
            Row::Inline { action, .. }
            | Row::Block { action, .. }
            | Row::Table { action, .. } => action.as_ref(),
            _ => None,
        }
    }

    /// Height in the sheet. The one place a row's vertical extent is decided, so the
    /// scroll bound, the pager and the painting all agree by construction.
    fn height(&self, m: &Metrics, body_w: i32) -> i32 {
        let head = match self.action() {
            Some(_) => ACTION_ROW_H,
            None => ROW_H,
        };
        match self {
            Row::Section(_) => 2 * m.gap + LINE + m.gap,
            Row::Inline { .. } => head,
            Row::Block { body, .. } => head + body.lines(body_w, m) * SMALL_LINE + m.gap,
            Row::Table { lines, .. } => head + lines.len() as i32 * SMALL_LINE + m.gap,
            Row::Write => {
                write_notice_h(body_w, WRITE_WHAT, WRITE_CONFIDENTIALITY) + m.gap + m.btn + m.gap
            }
            Row::Note => 2 * m.gap + note_lines(body_w).len() as i32 * SMALL_LINE + m.gap,
        }
    }
}

impl Body {
    fn lines(&self, body_w: i32, m: &Metrics) -> i32 {
        match self {
            Body::Hex(h) => hex_lines(h).len() as i32,
            Body::Text(s) => wrap_words(s, body_w - m.gap, MONO_SMALL).len() as i32,
        }
    }
}

fn note_lines(body_w: i32) -> Vec<String> {
    wrap_words(PROVENANCE, body_w, MONO_SMALL)
}

/// Split hex into its frozen lines: `(offset gutter, grouped characters)` per line.
///
/// Geometry-invariant by construction - it takes no `Metrics` - which is what makes
/// 11.7's "hex breaks are identical at 720x720 and 800x480" true rather than tested.
fn hex_lines(hex: &str) -> Vec<(String, String)> {
    let chars: Vec<char> = hex.chars().collect();
    let mut out = Vec::new();
    for (i, chunk) in chars.chunks(HEX_PER_LINE).enumerate() {
        let mut groups = String::with_capacity(HEX_PER_LINE + HEX_GROUPS_PER_LINE);
        for (g, group) in chunk.chunks(HEX_GROUP).enumerate() {
            if g > 0 {
                groups.push(' ');
            }
            groups.extend(group.iter());
        }
        // Two digits and a space: the longest value on this screen is a 64-character
        // digest, whose last line starts at 48.
        out.push((format!("{:02}", i * HEX_PER_LINE), groups));
    }
    out
}

// ---------------------------------------------------------------------------------------
// The frozen field order (VERIFY.md 10, sectioned per 11.2)
// ---------------------------------------------------------------------------------------

/// Every row the screen shows, in the order it shows them.
///
/// This function IS the frozen order. Pre-PIN it emits a STRICT SUBSET (7.4): the rows a
/// person holding the device cannot already obtain with a USB cable, or that say
/// something about the wallets stored on this unit, are ABSENT - not disabled and not
/// blanked, because never drawing an affordance or a label that resolves to nothing is
/// the rule `draw_bar_no_back` established in 0.1.0.
fn sheet(ctx: &Ctx) -> Vec<Row> {
    let v = ctx.verify;
    let unlocked = ctx.lock.status == StoreStatus::Unlocked;
    let mut r = Vec::with_capacity(64);

    // --- identity (10.1) --------------------------------------------------------------
    r.push(Row::Section("identity"));
    r.push(k1("Device name", device_name(&ctx.lock.device_name)));
    r.push(k1("Board", opt(&v.board)));
    r.push(k1("Chip", opt(&v.chip)));
    r.push(k1("Chip revision", opt(&v.chip_revision)));
    r.push(k1("Boot ROM", opt(&v.boot_rom)));
    r.push(k1("ROM chip id", opt(&v.rom_chip_id)));
    r.push(k1("MAC", opt(&v.mac)));
    r.push(hex_row("Die unique ID", &v.die_unique_id));

    // --- firmware (10.2) --------------------------------------------------------------
    r.push(Row::Section("firmware"));
    r.push(k1("Version", opt(&v.firmware_version)));
    // The two IDF rows are adjacent because that is what makes them useful: a bootloader
    // string differing from the app's is a stale bootloader, which no digest can name.
    r.push(k1("ESP-IDF (app)", opt(&v.idf_app)));
    r.push(k1("ESP-IDF (bootloader)", opt(&v.idf_bootloader)));
    r.push(k1("Anti-rollback (image)", opt(&v.rollback_image)));
    r.push(k1("Anti-rollback (efuse)", opt(&v.rollback_efuse)));
    r.push(hex_row("Firmware digest", &v.firmware_digest));
    r.push(region_row("App image", &v.app));
    r.push(region_row("Bootloader image", &v.bootloader));
    r.push(region_row("Partition table", &v.partition_table));

    // --- flash (10.3) -----------------------------------------------------------------
    r.push(Row::Section("flash"));
    r.push(k1("Size (header)", opt(&v.flash_size_header)));
    r.push(k1("Size (detected)", opt(&v.flash_size_detected)));
    r.push(k1("JEDEC ID", opt(&v.jedec_id)));
    r.push(k1("Flash unique ID (64 of 128)", opt(&v.flash_unique_id)));
    r.push(partitions_row(v));
    reserved_rows(&mut r, &v.reserved_space);
    // Permitted pre-PIN by the ratified Q2(a) (Q56): every unoccupied slot holds a real
    // AEAD record under a device-derived key, so there is no publicly computable constant
    // for a blank partition to be recognised by.
    r.push(hex_row("wallets digest (raw)", &v.wallets_digest));
    if unlocked {
        r.push(hex_row("counters digest (raw)", &v.counters_digest));
    }

    // --- efuse (10.4) -----------------------------------------------------------------
    r.push(Row::Section("efuse"));
    r.push(k1("Secure boot", bit(v.secure_boot, Words::EnabledDisabled)));
    r.push(k1("Aggressive revoke", bit(v.aggressive_revoke, Words::YesNo)));
    // All three slots unconditionally (ratified Q58): three rows where two read
    // `not burned` make the absence of a second enrolled signing key a readable value
    // rather than an inference from silence.
    for (i, digest) in v.key_digests.iter().enumerate() {
        r.push(hex_row(&format!("Key digest {i}"), digest));
    }
    r.push(k1("Flash encryption", bit(v.flash_encryption, Words::EnabledDisabled)));
    r.push(k1("Encryption mode", opt(&v.encryption_mode)));
    r.push(k1("Crypt count", num(v.crypt_count.map(u64::from))));
    r.push(k1("XTS key read protection", bit(v.xts_key_read_protected, Words::Raw)));
    r.push(k1("Manual encrypt", bit(v.manual_encrypt, Words::EnabledDisabled)));
    r.push(k1("UART download", bit(v.uart_download, Words::EnabledDisabled)));
    r.push(k1("Secure download", bit(v.secure_download, Words::EnabledDisabled)));
    r.push(k1(
        "USB-serial-JTAG download",
        bit(v.usb_serial_jtag_download, Words::EnabledDisabled),
    ));
    r.push(k1("USB-OTG download", bit(v.usb_otg_download, Words::EnabledDisabled)));
    r.push(k1("Forced download", bit(v.forced_download, Words::EnabledDisabled)));
    r.push(k1("Direct boot", bit(v.direct_boot, Words::EnabledDisabled)));
    // Three JTAG rows, never one: soft-disabled JTAG is re-enablable with an HMAC token
    // and the pad and USB fuses are permanent, so collapsing them would hide the case
    // that matters and would be the interpretation contract rule 2 forbids.
    r.push(k1("JTAG (pad)", bit(v.jtag_pad, Words::EnabledDisabled)));
    r.push(k1("JTAG (USB)", bit(v.jtag_usb, Words::EnabledDisabled)));
    r.push(k1("JTAG (soft)", soft_jtag(v.jtag_soft)));
    r.push(k1("JTAG select", bit(v.jtag_select, Words::Raw)));
    r.push(k1("ROM log", num(v.rom_log.map(u64::from))));
    r.push(k1("ROM log (USB)", bit(v.rom_log_usb, Words::EnabledDisabled)));
    r.push(key_blocks_row(v));

    // --- state (10.5) -----------------------------------------------------------------
    r.push(Row::Section("state"));
    // Pre-PIN, and that is the point: a counter the owner can only read AFTER unlocking
    // is useless for its one job, which is telling them - before they trust the device
    // with a PIN - that it was powered on more times than they powered it on.
    r.push(k1("Boot count", counted(v.boot_count)));
    if unlocked {
        r.push(k1("Since acknowledged", since_acknowledged(v)));
        r.push(k1("Acknowledged at boot", acknowledged(v.acknowledged_at)));
        // Two conditions, both from VERIFY.md 6.3 and neither cosmetic. Post-PIN only: a
        // coercer who can press it erases the very gap the counter exists to show. And
        // only with a count to acknowledge: on a device that has counted nothing there is
        // no boot index to write, and creating the ledger's auxiliary sector to record
        // that would be a flash write on a device whose whole claim is that it performs
        // none (R24).
        if v.boot_count.is_some() {
            r.push(Row::Write);
        }
    }
    r.push(k1("Wipe epoch", counted(v.wipe_epoch)));
    if unlocked {
        r.push(k1("Storage", opt(&v.storage)));
    }

    // --- operation (10.6) -------------------------------------------------------------
    r.push(Row::Section("operation"));
    r.push(k1(&radio_label(v.radio_gpio), radio(v)));
    r.push(k1("Boot self-test", self_test(v)));
    r.push(Row::Note);
    r
}

/// A K1 row.
fn k1(label: &str, value: Cell) -> Row {
    row(label, value, None)
}

/// A K1 row, or the K2 block it becomes when its value does not fit the column left
/// beside its label - and beside its control, where it has one.
///
/// The routing is by CHARACTER COUNT against a constant, never by the panel: a value must
/// not be inline on one geometry and a block on the other, or the hex breaks and the row
/// heights would stop being the same picture on two units held side by side.
fn row(label: &str, value: Cell, action: Option<Action>) -> Row {
    let budget = match &action {
        Some(a) => INLINE_BUDGET.saturating_sub(a.cols()),
        None => INLINE_BUDGET,
    };
    if value.text.chars().count() > budget {
        Row::Block { label: String::from(label), body: Body::Text(value.text), action }
    } else {
        Row::Inline { label: String::from(label), value, action }
    }
}

fn opt(v: &Option<String>) -> Cell {
    match v {
        Some(s) => Cell::read(s.as_str()),
        None => Cell::not_read(),
    }
}

fn num(v: Option<u64>) -> Cell {
    match v {
        Some(n) => Cell::read(n.to_string()),
        None => Cell::not_read(),
    }
}

/// A ledger counter. `not counted` and never `0`: while the ledger is unformatted nothing
/// is written and nothing is read, so `0` would be a value the device did not measure
/// (VERIFY.md 6 / R24).
fn counted(v: Option<u64>) -> Cell {
    match v {
        Some(n) => Cell::read(grouped(n)),
        None => Cell::read("not counted"),
    }
}

fn acknowledged(v: Option<u64>) -> Cell {
    match v {
        Some(n) => Cell::read(grouped(n)),
        None => Cell::read("not acknowledged"),
    }
}

fn since_acknowledged(v: &VerifyInfo) -> Cell {
    match (v.boot_count, v.acknowledged_at) {
        (Some(n), Some(at)) => Cell::read(grouped(n.saturating_sub(at))),
        _ => Cell::read("not acknowledged"),
    }
}

/// The user's own label. Empty is a setting they have not made, which is a value the
/// device read; it is not a value it failed to read.
///
/// It is a LABEL on this sheet too, and the sheet is read by someone checking whether the
/// device in their hand is theirs. What answers that question here is the digest rows
/// below, not this one: the name is what the owner chose and anyone holding the device can
/// read it (see [`crate::LockInfo::device_name`]).
fn device_name(name: &str) -> Cell {
    if name.is_empty() {
        Cell::read("not set")
    } else {
        Cell::read(name)
    }
}

fn bit(b: Bit, words: Words) -> Cell {
    match (b, words) {
        (Bit::NotRead, _) => Cell::not_read(),
        // Not a field on this silicon, or no key block carries the purpose the row is
        // about. A determined fact, so it is not muted.
        (Bit::Absent, _) => Cell::read("not present"),
        (Bit::Set, Words::EnabledDisabled) => Cell::read("enabled"),
        (Bit::Clear, Words::EnabledDisabled) => Cell::read("disabled"),
        (Bit::Set, Words::YesNo) => Cell::read("yes"),
        (Bit::Clear, Words::YesNo) => Cell::read("no"),
        (Bit::Set, Words::Raw) => Cell::read("1"),
        (Bit::Clear, Words::Raw) => Cell::read("0"),
    }
}

/// `SOFT_DIS_JTAG` as `count of width`: a 3-bit odd/even field IDF treats as fully
/// soft-disabled only at the full width, so both numbers are printed and neither is
/// turned into a word.
fn soft_jtag(v: Option<(u8, u8)>) -> Cell {
    match v {
        Some((count, width)) => Cell::read(format!("{count} of {width}")),
        None => Cell::not_read(),
    }
}

fn radio_label(gpio: Option<u8>) -> String {
    match gpio {
        Some(n) => format!("Radio kill GPIO{n}"),
        None => String::from("Radio kill GPIO"),
    }
}

fn radio(v: &VerifyInfo) -> Cell {
    match &v.radio {
        Some(s) if v.radio_ok => Cell::read(s.as_str()),
        Some(s) => Cell::alarming(s.as_str()),
        None => Cell::not_read(),
    }
}

fn self_test(v: &VerifyInfo) -> Cell {
    match &v.self_test {
        Some(s) if v.self_test_ok => Cell::read(s.as_str()),
        Some(s) => Cell::alarming(s.as_str()),
        None => Cell::not_read(),
    }
}

/// A digest row: a K2 block when there is a digest, and a one-line K1 row carrying the
/// silicon's own reason when there is not. Never zeros - `esp_efuse_read_block()` does no
/// `RD_DIS` check, so an absent digest that rendered as bytes would be the worst wrong
/// value on this screen.
fn hex_row(label: &str, v: &HexValue) -> Row {
    match v {
        HexValue::Read(h) => {
            Row::Block { label: String::from(label), body: Body::Hex(h.clone()), action: None }
        }
        HexValue::NotBurned => k1(label, Cell::read("not burned")),
        HexValue::Revoked => k1(label, Cell::read("revoked")),
        HexValue::ReadProtected => k1(label, Cell::read("read-protected")),
        HexValue::NotRead => k1(label, Cell::not_read()),
    }
}

/// A hashed region: the offset and the length ride in the LABEL, because a digest without
/// them is a number rather than a checkable number.
fn region_row(label: &str, v: &Option<RegionDigest>) -> Row {
    match v {
        Some(r) => Row::Block {
            label: format!("{label} (0x{:06X}, {} B)", r.offset, grouped(u64::from(r.len))),
            body: Body::Hex(r.sha256.clone()),
            action: None,
        },
        None => k1(label, Cell::not_read()),
    }
}

/// The live partition table, in `firmware/partitions.csv`'s own field order and spelling
/// so the two are compared directly rather than translated. Columns are specified in
/// CHARACTERS (10 + 10 + 9 + 6 + 3 = 38), so the table is byte-identical at both panels.
fn partitions_row(v: &VerifyInfo) -> Row {
    if v.partitions.is_empty() {
        return k1("Partitions", Cell::not_read());
    }
    let lines = v
        .partitions
        .iter()
        .map(|p| {
            // 9 + 10 + 9 + 6 + 4 = the 38-character budget. One character moves from the
            // name column to the flag column against 11.1's 10 + 10 + 9 + 6 + 3, because
            // at 3 the `enc` flag butts against a six-character size with no separator -
            // which 11.1's own worked example draws a gap in. Names in partitions.csv
            // are at most eight characters, so the column that gives it up has it spare.
            let line = format!(
                "{:<9}{:<10}{:<9}{:>6}{:>4}",
                p.name,
                p.kind,
                format!("0x{:06X}", p.offset),
                format!("{}K", p.size / 1024),
                if p.encrypted { "enc" } else { "" },
            );
            String::from(line.trim_end())
        })
        .collect();
    Row::Table { label: String::from("Partitions"), lines, action: None }
}

/// The six eFuse key blocks, TWO LINES each.
///
/// Two lines because P4's longest purpose enumerator is `HMAC_DOWN_DIGITAL_SIGNATURE` at
/// 27 characters, and truncating an enumerator name would break the one property that
/// makes the row useful: it is compared character for character against `espefuse.py
/// summary` output and against the burn runbook.
fn key_blocks_row(v: &VerifyInfo) -> Row {
    if v.key_blocks.is_empty() {
        return k1("Key blocks", Cell::not_read());
    }
    let mut lines = Vec::with_capacity(v.key_blocks.len() * 2);
    for (i, b) in v.key_blocks.iter().enumerate() {
        let purpose = b.purpose.as_deref().unwrap_or("<unused>");
        lines.push(format!("KEY{i}  {purpose}"));
        // Raw bit values, not words: this line is read beside `espefuse.py`, not instead
        // of it.
        lines.push(format!(
            "      rd_dis {}   wr_dis {}",
            u8::from(b.read_protected),
            u8::from(b.write_protected)
        ));
    }
    Row::Table { label: String::from("Key blocks"), lines, action: None }
}

/// The reserved-space scan. `[ Scan ]` is offered either way - the spans move with the
/// build, so a second look is a new measurement rather than a cached one.
fn reserved_rows(rows: &mut Vec<Row>, v: &ReservedSpace) {
    let scan = Action { id: RegionId::VerifyScanFlash, label: "Scan", w: 140 };
    match v {
        // The device has not looked. Rendering that as `all 0xff`, or as anything else,
        // would be the firmware answering a question nobody asked it.
        ReservedSpace::NotScanned => {
            rows.push(row("Reserved space", Cell::read("not scanned"), Some(scan)))
        }
        // It looked and could not read. A different statement, and the muted ink says so.
        ReservedSpace::NotRead => {
            rows.push(row("Reserved space", Cell::not_read(), Some(scan)))
        }
        ReservedSpace::Scanned { spans, digest } => {
            let mut lines = Vec::with_capacity(spans.len() * 2);
            for s in spans {
                lines.push(format!(
                    "{:<20}{:>15} B",
                    format!("0x{:06x}-0x{:06x}", s.start, s.end),
                    grouped(u64::from(s.end - s.start))
                ));
                // Per-span rather than aggregate, and with the offset: an aggregate
                // "not blank" tells the owner nothing they can act on, an offset tells
                // them and anyone they report it to exactly where to look.
                lines.push(match s.set {
                    None => String::from("  all 0xff"),
                    Some(set) => {
                        format!("  {} set, first 0x{:07x}", grouped(set.count), set.first)
                    }
                });
            }
            rows.push(Row::Table {
                label: String::from("Reserved space"),
                lines,
                action: Some(scan),
            });
            rows.push(hex_row("Reserved space digest", digest));
        }
    }
}

/// Digits in groups of three, separated by a space: `18 595 840`. A space rather than a
/// comma or a period, because both of those mean the opposite thing somewhere.
fn grouped(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    let head = digits.len() % 3;
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && i % 3 == head {
            out.push(' ');
        }
        out.push(c);
    }
    out
}

// ---------------------------------------------------------------------------------------
// Geometry
// ---------------------------------------------------------------------------------------

pub(crate) struct Layout {
    /// The scrolling viewport. Body minus the footer, and minus the C12 band when the
    /// acknowledgement write is offered.
    viewport: Rect,
    prev: Option<Rect>,
    next: Option<Rect>,
    /// The bar's right slot: the `[ i / n ]` viewport counter, and the Lock chip.
    counter: Rect,
    lock: Option<Rect>,
    /// Which viewport is showing, out of how many.
    page: i32,
    pages: i32,
    /// Maximum scroll offset. 0 when the sheet fits.
    limit: i32,
    /// In-sheet controls, already resolved to panel coordinates and already filtered to
    /// the ones wholly inside the viewport - a half-scrolled button must not be tappable.
    actions: Vec<Region>,
}

/// Label column width, and therefore the value column origin.
///
/// The ceiling never binds on either shipped panel (asserted below); it is there so that a
/// panel this crate has not seen degrades to a narrow value column rather than to a
/// negative one.
fn label_w(body: &Rect) -> i32 {
    LABEL_COL.min(body.w * 2 / 3)
}

impl Screen for VerifyState {
    type Layout = Layout;

    fn layout(&self, ctx: &Ctx) -> Layout {
        let m = &ctx.m;
        let body = m.body();
        let unlocked = ctx.lock.status == StoreStatus::Unlocked;

        // The footer carries the pager and nothing else, and it is reserved whether or not
        // the pager is offered, so that the viewport height - and therefore the page count
        // - cannot depend on the page count.
        let footer_h = m.btn;
        // One line of edge strip below the sheet, reserved whether or not either marker
        // is showing. Reserved rather than overlaid for the reason the whole screen
        // exists: a marker painted over the sheet occludes the right-hand end of a value,
        // and a value this screen hides is a value a reader could compare wrongly.
        let viewport = Rect::new(
            body.x,
            body.y,
            body.w,
            (body.h - footer_h - m.gap - SMALL_LINE).max(SMALL_LINE),
        );

        let rows = sheet(ctx);
        let heights: Vec<i32> = rows.iter().map(|r| r.height(m, body.w)).collect();
        let sheet_h: i32 = heights.iter().sum();
        let limit = (sheet_h - viewport.h).max(0);
        let scroll = self.scroll.clamp(0, limit);

        let starts = page_starts(&heights, viewport.h, limit);
        let here = starts.iter().rposition(|s| *s <= scroll).unwrap_or(0);
        let pages = starts.len() as i32;
        let page = here as i32 + 1;
        // A drag can leave the reader between two page starts, so Prev means "the top of
        // what I am looking at" there and "the previous viewport" on a boundary. Both
        // targets are computed HERE, with the geometry, and read by `activate`, which is
        // given none - so what the bar counts and what the buttons do cannot disagree.
        self.paging.set(Paging {
            prev: if scroll > starts[here] {
                starts[here]
            } else {
                starts[here.saturating_sub(1)]
            },
            next: starts.get(here + 1).copied().unwrap_or(limit),
        });

        // Footer: the pager at the edges, the write in the middle where its notice is.
        // Offered by what is off the panel rather than by the page index, so the two
        // buttons and C6's "more above" / "more below" markers say the same thing.
        let fy = body.bottom() - footer_h;
        let side = 200.min((body.w - 2 * m.gap) / 3);
        let prev = (scroll > 0).then(|| Rect::new(body.x, fy, side, footer_h));
        let next =
            (scroll < limit).then(|| Rect::new(body.right() - side, fy, side, footer_h));
        // The bar's right slot. The Lock chip is offered exactly while there is a session
        // to drop, and the counter sits inboard of it so the two never trade places.
        //
        // Both widths are MEASURED from the text they carry, not taken as a fraction of
        // the panel. `text_centered` centres a label wider than its rectangle and lets
        // both ends run past it, so the old `150.min(m.w / 5)` - 144 px on the 720 px
        // panels, against a 174 px "Lock device" - laid the tail of its own label out at
        // x >= 720, off the edge of the glass. Measuring is the only sizing rule that
        // cannot do that, on this panel or on one this crate has not seen.
        //
        // The chip is a control and gets a gap of padding each side; the counter is text
        // and takes exactly its own width. The counter is sized for the widest index this
        // sheet will ever show rather than for the one showing now, so paging cannot make
        // the bar move under the reader's eye.
        let chip_h = m.bar - m.gap;
        let chip_w = HEADING.text_width(LOCK_LABEL) as i32 + 2 * m.gap;
        let lock =
            unlocked.then(|| Rect::new(m.w - m.gap - chip_w, m.gap / 2, chip_w, chip_h));
        let counter_w = BODY.text_width(&counter_label(pages, pages)) as i32;
        let counter_x = match lock {
            Some(l) => l.x - m.gap - counter_w,
            None => m.w - m.gap - counter_w,
        };
        let counter = Rect::new(counter_x, m.gap / 2, counter_w, chip_h);

        // In-sheet controls: located by the same walk that paints them, and offered only
        // while wholly visible.
        let mut actions = Vec::new();
        let mut y = viewport.y - scroll;
        for (row, h) in rows.iter().zip(&heights) {
            if let Some((id, _, r)) = control(row, m, &body, y) {
                // Offered only while WHOLLY visible. A page break never cuts a row that
                // fits (see `page_starts`), so every control is reachable by the pager
                // alone rather than only by a drag.
                if r.y >= viewport.y && r.bottom() <= viewport.bottom() {
                    actions.push(Region { id, rect: r });
                }
            }
            y += h;
        }

        Layout {
            viewport,
            prev,
            next,
            counter,
            lock,
            page,
            pages,
            limit,
            actions,
        }
    }

    fn regions(&self, ctx: &Ctx, out: &mut Vec<Region>) {
        // C3: a Busy screen offers nothing, not even Back. The scan is a single blocking
        // read on the std side and cannot be cancelled, so a live control would be a lie
        // about what the loop can do.
        if matches!(self.scan, Scan::Running { .. }) {
            return;
        }
        let l = self.layout(ctx);
        out.push(Region { id: RegionId::Back, rect: back_rect(&ctx.m) });
        if let Some(r) = l.lock {
            out.push(Region { id: RegionId::Lock, rect: r });
        }
        if let Some(r) = l.prev {
            out.push(Region { id: RegionId::ReviewPrev, rect: r });
        }
        if let Some(r) = l.next {
            out.push(Region { id: RegionId::ReviewNext, rect: r });
        }
        out.extend(l.actions);
    }

    fn draw<D: DrawTarget<Color = Rgb565>>(&self, t: &mut D, ctx: &Ctx) -> Result<(), D::Error> {
        if let Scan::Running { done, spans } = self.scan {
            return draw_busy(t, &ctx.m, done, spans);
        }
        let m = &ctx.m;
        let body = m.body();
        let l = self.layout(ctx);
        draw_bar(t, m, BAR_TITLE)?;
        // The C1 right slot. Painted over the bar rather than by it: only this screen has
        // a viewport counter, and a widget one screen draws stays in that screen.
        text_centered(
            t,
            &counter_label(l.page, l.pages),
            l.counter,
            BODY,
            INK_SECONDARY,
            PAPER_2,
        )?;
        if let Some(r) = l.lock {
            button(t, r, LOCK_LABEL, ButtonKind::Secondary, PAPER_2)?;
        }

        let scroll = self.scroll.clamp(0, l.limit);
        {
            let mut clip = t.clipped(&l.viewport.to_eg());
            let mut y = l.viewport.y - scroll;
            for row in sheet(ctx) {
                let h = row.height(m, body.w);
                // Rows wholly off the viewport are skipped, not clipped: the panel has no
                // dirty rectangles, so a full repaint walks every row on every frame.
                if y + h > l.viewport.y && y < l.viewport.bottom() {
                    draw_row(&mut clip, m, &body, &row, y, h)?;
                }
                y += h;
            }
        }
        // C6's edge markers, in the strip the viewport reserved for them: 0.1.0 lacks
        // them and C6 names that as a bug. Both ends in one strip, so the sheet keeps
        // every pixel of its own.
        let strip = Rect::new(l.viewport.x, l.viewport.bottom(), l.viewport.w, SMALL_LINE);
        if scroll > 0 {
            text(t, "more above", strip.x, strip.y, MONO_SMALL, INK_MUTED, PAPER_1)?;
        }
        if scroll < l.limit {
            let w = MONO_SMALL.text_width("more below") as i32;
            text(t, "more below", strip.right() - w, strip.y, MONO_SMALL, INK_MUTED, PAPER_1)?;
        }

        if let Some(r) = l.prev {
            button(t, r, "< Prev", ButtonKind::Secondary, PAPER_1)?;
        }
        if let Some(r) = l.next {
            button(t, r, "Next >", ButtonKind::Secondary, PAPER_1)?;
        }
        Ok(())
    }

    fn activate(&mut self, id: RegionId, _env: &mut Env) -> Outcome {
        match id {
            RegionId::VerifyAckBoots => Outcome::ask(UiRequest::AcknowledgeBoots),
            RegionId::VerifyScanFlash => {
                // The C3 law: the frame that says what is happening is painted by THIS
                // transition and published before the read starts.
                self.scan = Scan::Running { done: 0, spans: 0 };
                Outcome::ask(UiRequest::ScanReservedSpace)
            }
            RegionId::Lock => Outcome::ask(UiRequest::LockSession),
            // The pager moves the same offset a drag does, snapped to a viewport
            // boundary, so the screen has one scroll model and not two.
            RegionId::ReviewPrev => {
                self.scroll = self.paging.get().prev;
                Outcome::stay()
            }
            RegionId::ReviewNext => {
                self.scroll = self.paging.get().next;
                Outcome::stay()
            }
            _ => Outcome::stay(),
        }
    }

    fn scroll_mut(&mut self) -> Option<&mut i32> {
        match self.scan {
            // The sheet under a Busy frame is frozen, exactly as it is unreachable.
            Scan::Running { .. } => None,
            Scan::Idle => Some(&mut self.scroll),
        }
    }

    fn scroll_limit(&self, ctx: &Ctx) -> i32 {
        self.layout(ctx).limit
    }
}

/// The one tappable thing a row can carry, in panel coordinates: what it means, what it
/// says, and where it is.
///
/// One function for every shape, consumed by both `layout` and `draw`, so a control can
/// never be painted where it cannot be pressed.
fn control(row: &Row, m: &Metrics, body: &Rect, y: i32) -> Option<(RegionId, &'static str, Rect)> {
    match row {
        // C12: directly BELOW its band, full-width right-aligned, so the sentence and the
        // button that acts on it are read in that order and cannot be separated.
        Row::Write => {
            let w = 260.min(body.w);
            let by = y + write_notice_h(body.w, WRITE_WHAT, WRITE_CONFIDENTIALITY) + m.gap;
            Some((
                RegionId::VerifyAckBoots,
                "Mark as seen",
                Rect::new(body.right() - w, by, w, m.btn),
            ))
        }
        // Everything else: right-aligned on the row's first line, vertically centred in
        // it. The row is [`ACTION_ROW_H`] tall precisely so this is a full touch target
        // without the control overhanging the row it belongs to.
        _ => row.action().map(|a| {
            (
                a.id,
                a.label,
                Rect::new(body.right() - a.w, y + (ACTION_ROW_H - TOUCH_MIN) / 2, a.w, TOUCH_MIN),
            )
        }),
    }
}

// ---------------------------------------------------------------------------------------
// Painting
// ---------------------------------------------------------------------------------------

fn draw_row<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    m: &Metrics,
    body: &Rect,
    row: &Row,
    y: i32,
    h: i32,
) -> Result<(), D::Error> {
    let lw = label_w(body);
    let value_x = body.x + lw + m.gap;
    match row {
        Row::Section(name) => {
            text(t, name, body.x, y + 2 * m.gap, HEADING, INK_PRIMARY, PAPER_1)?;
            fill(t, Rect::new(body.x, y + 2 * m.gap + LINE, body.w, 2), BORDER_STRONG)?;
        }
        Row::Inline { label, value, .. } => {
            let line_y = y + (h.min(ACTION_ROW_H) - LINE) / 2;
            text(t, label, body.x, line_y, BODY, INK_SECONDARY, PAPER_1)?;
            // ONE baseline for both faces (11.1). `draw_text` places a run at
            // `y + ascent`, and the two faces have different ascents, so the value's
            // origin is offset by the difference rather than by a number that looked
            // right - two columns that sit a pixel apart are what makes a long sheet
            // read as ragged.
            let baseline = line_y + BODY.ascent - MONO_SMALL.ascent;
            // Left-aligned, not right-aligned: a column of left-aligned mono values makes
            // differing PREFIXES jump out, which is how digests and IDs are compared.
            text(t, &value.text, value_x, baseline, MONO_SMALL, value.ink, PAPER_1)?;
            if let Some((_, label, r)) = control(row, m, body, y) {
                button(t, r, label, ButtonKind::Secondary, PAPER_1)?;
            }
            hairline(t, body, y + h)?;
        }
        Row::Block { label, body: content, action } => {
            let head = match action {
                Some(_) => ACTION_ROW_H,
                None => ROW_H,
            };
            text(t, label, body.x, y + (head.min(ROW_H) - LINE) / 2, BODY, INK_SECONDARY, PAPER_1)?;
            if let Some((_, label, r)) = control(row, m, body, y) {
                button(t, r, label, ButtonKind::Secondary, PAPER_1)?;
            }
            let mut ly = y + head;
            match content {
                Body::Hex(hex) => {
                    let adv = MONO_SMALL.glyph('m').advance as i32;
                    for (gutter, groups) in hex_lines(hex) {
                        let x = body.x + m.gap;
                        text(t, &gutter, x, ly, MONO_SMALL, INK_MUTED, PAPER_1)?;
                        text(
                            t,
                            &groups,
                            x + GUTTER_COLS * adv,
                            ly,
                            MONO_SMALL,
                            INK_PRIMARY,
                            PAPER_1,
                        )?;
                        ly += SMALL_LINE;
                    }
                }
                Body::Text(s) => {
                    for line in wrap_words(s, body.w - m.gap, MONO_SMALL) {
                        text(t, &line, body.x + m.gap, ly, MONO_SMALL, INK_PRIMARY, PAPER_1)?;
                        ly += SMALL_LINE;
                    }
                }
            }
            hairline(t, body, y + h)?;
        }
        Row::Table { label, lines, action } => {
            text(
                t,
                label,
                body.x,
                y + (h.min(ACTION_ROW_H) - LINE) / 2,
                BODY,
                INK_SECONDARY,
                PAPER_1,
            )?;
            if let Some((_, label, r)) = control(row, m, body, y) {
                button(t, r, label, ButtonKind::Secondary, PAPER_1)?;
            }
            let head = match action {
                Some(_) => ACTION_ROW_H,
                None => ROW_H,
            };
            let mut ly = y + head;
            // No per-row hairline inside a table: the column alignment is the separator.
            for line in lines {
                text(t, line, body.x + m.gap, ly, MONO_SMALL, INK_PRIMARY, PAPER_1)?;
                ly += SMALL_LINE;
            }
            hairline(t, body, y + h)?;
        }
        Row::Write => {
            // Invariant 2b: the write is announced BEFORE it happens, inline and directly
            // above the action that triggers it (C12), not in a modal after the fact.
            let band = write_notice_h(body.w, WRITE_WHAT, WRITE_CONFIDENTIALITY);
            write_notice(
                t,
                Rect::new(body.x, y, body.w, band),
                WRITE_WHAT,
                WRITE_CONFIDENTIALITY,
            )?;
            if let Some((_, label, r)) = control(row, m, body, y) {
                button(t, r, label, ButtonKind::Secondary, PAPER_1)?;
            }
        }
        Row::Note => {
            let mut ly = y + 2 * m.gap;
            for line in note_lines(body.w) {
                text(t, &line, body.x, ly, MONO_SMALL, INK_SECONDARY, PAPER_1)?;
                ly += SMALL_LINE;
            }
        }
    }
    Ok(())
}

fn hairline<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    body: &Rect,
    y: i32,
) -> Result<(), D::Error> {
    fill(t, Rect::new(body.x, y - 1, body.w, 1), BORDER)
}

/// The C3 Busy frame for the reserved-space scan.
///
/// Determinate, because the work has countable units and the embedder reports them
/// between spans (ratified Q57). Before the first report there is no bar to fill and the
/// line says so - a trough at some invented fraction would be the fake percentage C3
/// forbids.
fn draw_busy<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    m: &Metrics,
    done: u8,
    spans: u8,
) -> Result<(), D::Error> {
    draw_bar_no_back(t, m, BAR_TITLE)?;
    let body = m.body();
    // Heading, one mechanical line, the trough, the progress line and the trailing line,
    // with a gap above each of the first four: the card is sized to its contents rather
    // than to a round number, so the last line cannot fall off the bottom edge.
    let card_h = 4 * LINE + LINE / 2 + 5 * m.gap;
    let card = Rect::new(body.x, body.y + (body.h - card_h) / 2, body.w, card_h);
    panel(t, card, PAPER_2, BORDER_STRONG)?;
    let mut y = card.y + m.gap;
    text_centered(t, "Reading flash", Rect::new(card.x, y, card.w, LINE), HEADING, INK_PRIMARY, PAPER_2)?;
    y += LINE + m.gap;
    text_centered(
        t,
        "Raw read of every span that must be blank.",
        Rect::new(card.x, y, card.w, LINE),
        BODY,
        INK_SECONDARY,
        PAPER_2,
    )?;
    y += LINE + m.gap;

    let trough = Rect::new(card.x + m.pad, y, card.w - 2 * m.pad, LINE / 2);
    panel(t, trough, PAPER_0, BORDER)?;
    if spans > 0 {
        let bore = trough.inset(2);
        let w = bore.w * i32::from(done.min(spans)) / i32::from(spans);
        if w > 0 {
            fill(t, Rect::new(bore.x, bore.y, w, bore.h), ACCENT)?;
        }
    }
    y += LINE / 2 + m.gap;
    let progress = match spans {
        0 => String::from("starting"),
        n => format!("span {} of {n}", done.min(n)),
    };
    text_centered(t, &progress, Rect::new(card.x, y, card.w, LINE), BODY, INK_SECONDARY, PAPER_2)?;
    y += LINE;
    text_centered(
        t,
        "This cannot be cancelled.",
        Rect::new(card.x, y, card.w, LINE),
        BODY,
        INK_SECONDARY,
        PAPER_2,
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Scroll, snapped to viewports
// ---------------------------------------------------------------------------------------

/// Where each viewport starts.
///
/// A page break never cuts a row that FITS, which is the property that makes the pager
/// sufficient on its own: every row - and therefore every control on a row - is wholly
/// visible on exactly one page, so `[ Scan ]` cannot be a button only a drag can reach. A
/// row TALLER than the viewport (the key-block table on the shorter panel) is read across
/// two pages, because the alternative is shrinking or truncating it and 11.1 forbids both;
/// the break re-aligns to a row boundary on the next page.
fn page_starts(heights: &[i32], view_h: i32, limit: i32) -> Vec<i32> {
    let mut starts = alloc::vec![0];
    let mut start = 0;
    while start < limit {
        let mut y = 0;
        let mut fits = None;
        for h in heights {
            if y >= start && y + h <= start + view_h {
                fits = Some(y + h);
            }
            y += h;
        }
        let next = fits.unwrap_or(start + view_h).min(limit);
        if next <= start {
            break;
        }
        starts.push(next);
        start = next;
    }
    starts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::PANELS;
    use crate::screens::testing::{fits, rows_are_clear_on, Fixture, GEOMETRIES};
    use crate::{BlankSpan, KeyBlockInfo, LockInfo, PartitionRow, SetBytes};

    /// VERIFY.md 11.3's wireframe, as data.
    ///
    /// Every field populated, because the assertions below are about the FULL sheet and a
    /// half-filled fixture would let a row go missing without failing anything. The
    /// values are the wireframe's own, so the golden field list reads against the
    /// specification directly rather than against numbers invented for a test.
    fn wireframe() -> VerifyInfo {
        let digest = |s: &str| HexValue::Read(String::from(s));
        VerifyInfo {
            board: Some(String::from("waveshare-4b")),
            chip: Some(String::from("ESP32-P4")),
            chip_revision: Some(String::from("v1.3")),
            boot_rom: Some(String::from("eco 2")),
            rom_chip_id: Some(String::from("0x12")),
            mac: Some(String::from("60:55:f9:3a:1c:04")),
            die_unique_id: digest("1f4c90ab3e77d2158c6044f9b1a35e08"),

            firmware_version: Some(String::from("0.2.0")),
            idf_app: Some(String::from("v5.5.4")),
            idf_bootloader: Some(String::from("v5.5.4")),
            rollback_image: Some(String::from("2")),
            rollback_efuse: Some(String::from("2")),
            firmware_digest: digest(
                "9b21c7fe034a88d56e1922bcaf705d31e0c819467b2faa530d84c61139e7f2a0",
            ),
            app: Some(RegionDigest {
                offset: 0x0001_0000,
                len: 1_842_176,
                sha256: String::from(
                    "3f9a27c1b40e55d28a116ffe0c934471e2ab1d0577c839b6aa410e2f9c735b18",
                ),
            }),
            bootloader: Some(RegionDigest {
                offset: 0x0000_2000,
                len: 22_352,
                sha256: String::from(
                    "71e03c9d4a15b8f20c679dd1aa2f3e4c5061728394a5b6c7d8e9f0a1b2c3d4e5",
                ),
            }),
            partition_table: Some(RegionDigest {
                offset: 0x0000_8000,
                len: 128,
                sha256: String::from(
                    "0c679dd171e03c9d4a15b8f2b2c3d4e55061728394a5b6c7aa2f3e4cd8e9f0a1",
                ),
            }),

            flash_size_header: Some(String::from("32 MB")),
            flash_size_detected: Some(String::from("32 MB")),
            jedec_id: Some(String::from("c8 40 19")),
            flash_unique_id: Some(String::from("4d81 2f60 aa39 07c5")),
            // The table `firmware/partitions.csv` actually ships, including the
            // subtype every region really carries: `undefined` (0x06), because
            // esp-idf-part panics on a numeric user-range data subtype and the LABEL is
            // the identity. A fixture that showed a table nobody flashes would make the
            // column test below prove nothing.
            partitions: alloc::vec![
                PartitionRow {
                    name: String::from("factory"),
                    kind: String::from("app/fact"),
                    offset: 0x0001_0000,
                    size: 4_194_304,
                    encrypted: false,
                },
                PartitionRow {
                    name: String::from("wallets"),
                    kind: String::from("data/0x06"),
                    offset: 0x0041_0000,
                    size: 262_144,
                    encrypted: true,
                },
                PartitionRow {
                    name: String::from("counters"),
                    kind: String::from("data/0x06"),
                    offset: 0x0045_0000,
                    size: 16_384,
                    encrypted: false,
                },
                PartitionRow {
                    name: String::from("settings"),
                    kind: String::from("data/0x06"),
                    offset: 0x0046_0000,
                    size: 65_536,
                    encrypted: false,
                },
            ],
            reserved_space: ReservedSpace::NotScanned,
            wallets_digest: digest(
                "aa410e2f9c735b183f9a27c1b40e55d20c934471e2ab1d058a116ffe77c839b6",
            ),
            counters_digest: digest(
                "5061728394a5b6c771e03c9d4a15b8f2aa2f3e4cd8e9f0a10c679dd1b2c3d4e5",
            ),

            secure_boot: Bit::Clear,
            aggressive_revoke: Bit::Clear,
            key_digests: [HexValue::NotBurned, HexValue::NotBurned, HexValue::NotBurned],
            flash_encryption: Bit::Clear,
            encryption_mode: Some(String::from("DISABLED")),
            crypt_count: Some(0),
            xts_key_read_protected: Bit::Absent,
            manual_encrypt: Bit::Set,
            uart_download: Bit::Set,
            secure_download: Bit::Clear,
            usb_serial_jtag_download: Bit::Set,
            usb_otg_download: Bit::Set,
            forced_download: Bit::Set,
            direct_boot: Bit::Set,
            jtag_pad: Bit::Set,
            jtag_usb: Bit::Set,
            jtag_soft: Some((0, 3)),
            jtag_select: Bit::Clear,
            rom_log: Some(0),
            rom_log_usb: Bit::Set,
            key_blocks: (0..6)
                .map(|i| KeyBlockInfo {
                    purpose: (i == 5).then(|| String::from("HMAC_UP")),
                    read_protected: i == 5,
                    write_protected: i == 5,
                })
                .collect(),

            boot_count: Some(1235),
            acknowledged_at: Some(1230),
            wipe_epoch: Some(0),
            storage: Some(String::from("present")),

            radio_gpio: Some(54),
            radio: Some(String::from("low")),
            radio_ok: true,
            self_test: Some(String::from("6/6 passed")),
            self_test_ok: true,
        }
    }

    /// The fixture at one geometry, with or without a session open.
    fn fixture(w: u32, h: u32, unlocked: bool) -> Fixture {
        let mut f = Fixture::new(w, h);
        f.verify = wireframe();
        f.lock = LockInfo {
            status: if unlocked { StoreStatus::Unlocked } else { StoreStatus::Locked },
            device_name: String::from("kitchen-desk"),
            ..LockInfo::default()
        };
        f
    }

    fn labels(f: &Fixture) -> Vec<String> {
        sheet(&f.ctx()).iter().map(|r| String::from(r.label())).collect()
    }

    fn golden(text: &str) -> Vec<String> {
        text.lines().filter(|l| !l.is_empty()).map(String::from).collect()
    }

    // -- 11.7: field order is frozen ----------------------------------------------------

    /// The rendered label sequence equals the checked-in list, at BOTH geometries. A
    /// reordering is a deliberate, reviewed change to `goldens/s46-fields.txt` - which is
    /// the property two units held side by side are compared on.
    #[test]
    fn the_field_order_is_frozen_at_both_geometries() {
        let want = golden(include_str!("../../goldens/s46-fields.txt"));
        for (w, h) in GEOMETRIES {
            assert_eq!(labels(&fixture(w, h, true)), want, "field order moved at {w}x{h}");
        }
    }

    /// ...and the pre-PIN sheet is its own checked-in list, and a STRICT SUBSET of the
    /// unlocked one in the same order (VERIFY.md 7.4). Rows absent pre-PIN are absent,
    /// not disabled and not blanked.
    #[test]
    fn the_pre_pin_field_set_is_a_strict_subset() {
        let want = golden(include_str!("../../goldens/s46-fields-pre-pin.txt"));
        for (w, h) in GEOMETRIES {
            let locked = labels(&fixture(w, h, false));
            assert_eq!(locked, want, "pre-PIN field set moved at {w}x{h}");
            let unlocked = labels(&fixture(w, h, true));
            assert!(locked.len() < unlocked.len(), "the pre-PIN set must be strictly smaller");
            // Subset AND in order: walking the unlocked list must consume the pre-PIN one
            // in sequence, so a row cannot move position by being hidden.
            let mut it = unlocked.iter();
            for label in &locked {
                assert!(it.any(|u| u == label), "{label:?} is not in the unlocked sheet, in order");
            }
        }
    }

    /// The four rows 7.4 withholds are exactly the four that are missing, named here so
    /// the reason travels with the assertion rather than living only in the golden diff.
    #[test]
    fn the_rows_withheld_pre_pin_are_the_four_that_leak() {
        let f = fixture(720, 720, false);
        for absent in [
            // A digest of the mutable ledger, whose leak is governed post-PIN.
            "counters digest (raw)",
            // The acknowledgement is owner state; a coercer who reads it learns the gap.
            "Since acknowledged",
            "Acknowledged at boot",
            // Occupancy at any granularity finer than S-01's own row (Q2(a)).
            "Storage",
        ] {
            assert!(!labels(&f).iter().any(|l| l == absent), "{absent:?} must be absent pre-PIN");
        }
        // ...and the two that instinct says to withhold and 7.4 keeps, because withholding
        // them costs the owner the exact check they need and buys the attacker nothing.
        for present in ["Boot count", "wallets digest (raw)"] {
            assert!(labels(&f).iter().any(|l| l == present), "{present:?} must be pre-PIN");
        }
    }

    // -- 11.7: no truncation ------------------------------------------------------------

    /// Every digest on the screen, recovered from its rendered lines with the grouping
    /// spaces removed, equals its full source string. No allow-listed exceptions: a
    /// shortened digest is a value a reader could compare wrongly, which is worse than a
    /// taller row.
    #[test]
    fn no_digest_is_truncated() {
        let f = fixture(720, 720, true);
        let mut blocks = 0;
        for row in sheet(&f.ctx()) {
            let Row::Block { label, body: Body::Hex(hex), .. } = &row else { continue };
            let rendered: String =
                hex_lines(hex).iter().map(|(_, g)| g.replace(' ', "")).collect();
            assert_eq!(&rendered, hex, "{label} was not rendered in full");
            blocks += 1;
        }
        // The count is asserted too: a sheet that stopped emitting hex blocks entirely
        // would pass a loop over nothing.
        assert_eq!(
            blocks, 7,
            "die id, firmware digest, three hashed regions, both mutable-region digests"
        );
    }

    // -- 11.7: inline budget ------------------------------------------------------------

    /// No K1 value's rendered advance exceeds the 720x720 value column. Structural rather
    /// than incidental: [`k1`] routes an over-long value to a block, so this asserts the
    /// routing rather than the luck of the fixture.
    #[test]
    fn no_inline_value_exceeds_the_value_column() {
        for (w, h) in GEOMETRIES {
            let f = fixture(w, h, true);
            let body = Fixture::new(720, 720).m.body();
            let column = body.w - label_w(&body) - Fixture::new(720, 720).m.gap;
            for row in sheet(&f.ctx()) {
                let Row::Inline { label, value, action } = &row else { continue };
                let mut room = column;
                // A row carrying a control gives the control its width first.
                if let Some(a) = action {
                    room -= a.cols() as i32 * MONO_SMALL.glyph('m').advance as i32;
                }
                assert!(
                    MONO_SMALL.text_width(&value.text) as i32 <= room,
                    "{label}: {:?} overflows the 720x720 value column ({w}x{h})",
                    value.text
                );
            }
        }
    }

    /// ...and the routing itself: a value past the budget becomes a block, in full.
    #[test]
    fn an_over_long_value_becomes_a_block_rather_than_a_truncation() {
        let long = "FAILED: bip39-vectors, bip32-vectors, slip132, bech32 (2/6 passed)";
        assert!(long.chars().count() > INLINE_BUDGET);
        match k1("Boot self-test", Cell::alarming(long)) {
            Row::Block { body: Body::Text(s), .. } => assert_eq!(s, long),
            _ => panic!("an over-long value must get the full width, not the inline column"),
        }
        match k1("Boot self-test", Cell::read("6/6 passed")) {
            Row::Inline { .. } => {}
            _ => panic!("a value inside the budget stays inline"),
        }
    }

    // -- 11.7: hex breaks are geometry-invariant ----------------------------------------

    /// The line partition of every K2 block is identical at 720x720 and 800x480. This is
    /// the property the whole screen is arranged around: two units with different panels,
    /// side by side, break the same digest at the same character.
    #[test]
    fn hex_breaks_are_identical_at_both_geometries() {
        let partition = |w, h| -> Vec<Vec<(String, String)>> {
            let f = fixture(w, h, true);
            sheet(&f.ctx())
                .iter()
                .filter_map(|r| match r {
                    Row::Block { body: Body::Hex(hex), .. } => Some(hex_lines(hex)),
                    _ => None,
                })
                .collect()
        };
        assert_eq!(partition(720, 720), partition(800, 480));
    }

    // -- 11.7: no banned words ----------------------------------------------------------

    /// The reassurance vocabulary UX-SCREENS.md 6 bans, extended with the verdict
    /// vocabulary VERIFY.md's contract rule 2 bans.
    const BANNED: &[&str] = &[
        "secure", "safe", "simply", "just", "please", "sorry", "successfully", "oops",
        "genuine", "verified", "protected", "trusted", "clean", " ok",
    ];

    /// Strings that contain a banned word and ship anyway, each because the word is the
    /// SILICON'S OWN NAME for the field rather than this screen's opinion of it. A reader
    /// compares these character for character against `espefuse.py summary` and against
    /// the burn runbook, so translating them would destroy the row's only use.
    const SILICON_NAMES: &[&str] = &[
        "Secure boot",
        "Secure download",
        "XTS key read protection",
        "read-protected",
        "SECURE_BOOT_DIGEST0",
        "SECURE_BOOT_DIGEST1",
        "SECURE_BOOT_DIGEST2",
    ];

    /// Every literal the screen can put on the panel, banned-word checked. The allow-list
    /// is exact strings, not substrings of a pattern: a new row that happens to contain
    /// "protected" has to be argued for here rather than slipping through a wildcard.
    #[test]
    fn no_banned_word_reaches_the_screen() {
        let mut literals: Vec<String> = alloc::vec![
            String::from(PROVENANCE),
            String::from(BAR_TITLE),
            String::from("Reading flash"),
            String::from("Raw read of every span that must be blank."),
            String::from("This cannot be cancelled."),
            String::from("starting"),
            String::from("more above"),
            String::from("more below"),
            String::from("< Prev"),
            String::from("Next >"),
            String::from("Mark as seen"),
            String::from(LOCK_LABEL),
            String::from("This writes to the device: boot counter acknowledgement."),
            String::from("Nothing secret is written."),
        ];
        // Every rendering of every row, over the four states a bit can be in and both
        // scan states, so a value string cannot escape the check by not being in the
        // wireframe fixture.
        for unlocked in [false, true] {
            let mut f = fixture(720, 720, unlocked);
            for scanned in [false, true] {
                f.verify.reserved_space = if scanned { scanned_spans() } else { ReservedSpace::NotScanned };
                for row in sheet(&f.ctx()) {
                    literals.push(String::from(row.label()));
                    if let Some(a) = row.action() {
                        literals.push(String::from(a.label));
                    }
                    match &row {
                        Row::Inline { value, .. } => literals.push(value.text.clone()),
                        Row::Table { lines, .. } => literals.extend(lines.iter().cloned()),
                        Row::Block { body: Body::Text(s), .. } => literals.push(s.clone()),
                        _ => {}
                    }
                }
            }
        }
        for words in [Words::EnabledDisabled, Words::YesNo, Words::Raw] {
            for b in [Bit::Set, Bit::Clear, Bit::Absent, Bit::NotRead] {
                literals.push(bit(b, words).text);
            }
        }
        for v in [
            HexValue::NotBurned,
            HexValue::Revoked,
            HexValue::ReadProtected,
            HexValue::NotRead,
        ] {
            if let Row::Inline { value, .. } = hex_row("Key digest 0", &v) {
                literals.push(value.text);
            }
        }

        for literal in &literals {
            let lower = literal.to_lowercase();
            if SILICON_NAMES.contains(&literal.as_str()) {
                continue;
            }
            for banned in BANNED {
                assert!(
                    !lower.contains(banned),
                    "{literal:?} contains the banned word {banned:?}"
                );
            }
        }
        assert!(literals.len() > 100, "the literal inventory did not collect the sheet");
    }

    fn scanned_spans() -> ReservedSpace {
        ReservedSpace::Scanned {
            spans: alloc::vec![
                BlankSpan { start: 0x000000, end: 0x002000, set: None },
                BlankSpan {
                    start: 0x1d1c00,
                    end: 0xe00000,
                    set: Some(SetBytes { count: 4096, first: 0x01d2000 }),
                },
                BlankSpan { start: 0xe44000, end: 0x2000000, set: None },
            ],
            digest: HexValue::Read(String::from(
                "0d84c61139e7f2a09b21c7fe034a88d5af705d31e0c819466e1922bc7b2faa53",
            )),
        }
    }

    // -- the eFuse rows report TRUE state -----------------------------------------------

    /// Every eFuse bit row renders what it was GIVEN, and a different string for each of
    /// the four states a bit can be in.
    ///
    /// This is the assertion the screen most depends on. A row that rendered a constant
    /// would pass every layout test, every golden image and every field-order check, and
    /// would make the screen a liar about the one thing on it the app cannot forge.
    #[test]
    fn every_efuse_bit_row_renders_the_state_it_was_given() {
        // The rows, by the field each one reads, as setters on a fixture.
        type Set = fn(&mut VerifyInfo, Bit);
        let rows: &[(&str, Set)] = &[
            ("Secure boot", |v, b| v.secure_boot = b),
            ("Aggressive revoke", |v, b| v.aggressive_revoke = b),
            ("Flash encryption", |v, b| v.flash_encryption = b),
            ("XTS key read protection", |v, b| v.xts_key_read_protected = b),
            ("Manual encrypt", |v, b| v.manual_encrypt = b),
            ("UART download", |v, b| v.uart_download = b),
            ("Secure download", |v, b| v.secure_download = b),
            ("USB-serial-JTAG download", |v, b| v.usb_serial_jtag_download = b),
            ("USB-OTG download", |v, b| v.usb_otg_download = b),
            ("Forced download", |v, b| v.forced_download = b),
            ("Direct boot", |v, b| v.direct_boot = b),
            ("JTAG (pad)", |v, b| v.jtag_pad = b),
            ("JTAG (USB)", |v, b| v.jtag_usb = b),
            ("JTAG select", |v, b| v.jtag_select = b),
            ("ROM log (USB)", |v, b| v.rom_log_usb = b),
        ];
        for (label, set) in rows {
            let mut seen: Vec<String> = Vec::new();
            for b in [Bit::Set, Bit::Clear, Bit::Absent, Bit::NotRead] {
                let mut f = fixture(720, 720, true);
                set(&mut f.verify, b);
                let value = sheet(&f.ctx())
                    .into_iter()
                    .find_map(|r| match r {
                        Row::Inline { label: l, value, .. } if l == *label => Some(value.text),
                        _ => None,
                    })
                    .unwrap_or_else(|| panic!("{label} is not on the sheet"));
                assert!(
                    !seen.contains(&value),
                    "{label} rendered {value:?} for two different fuse states"
                );
                seen.push(value);
            }
            assert_eq!(seen.len(), 4, "{label}");
        }
    }

    /// The provisioned and unprovisioned key-block renderings, which is the pair the
    /// bench actually produces: board B carries `HMAC_UP` in KEY5 with both protection
    /// bits burned, board A carries nothing at all. Both must be correct, and the two
    /// must be distinguishable.
    #[test]
    fn a_provisioned_key_block_reads_differently_from_an_unprovisioned_one() {
        let lines = |blocks: Vec<KeyBlockInfo>| {
            let mut f = fixture(720, 720, true);
            f.verify.key_blocks = blocks;
            sheet(&f.ctx())
                .into_iter()
                .find_map(|r| match r {
                    Row::Table { label, lines, .. } if label == "Key blocks" => Some(lines),
                    _ => None,
                })
                .expect("the key-block table is on the sheet")
        };
        let unprovisioned: Vec<KeyBlockInfo> = (0..6)
            .map(|_| KeyBlockInfo {
                purpose: None,
                read_protected: false,
                write_protected: false,
            })
            .collect();
        let mut provisioned = unprovisioned.clone();
        provisioned[5] = KeyBlockInfo {
            purpose: Some(String::from("HMAC_UP")),
            read_protected: true,
            write_protected: true,
        };

        let a = lines(unprovisioned);
        let b = lines(provisioned);
        assert_eq!(a.len(), 12, "two lines per block, six blocks");
        assert_eq!(a[10], "KEY5  <unused>");
        assert_eq!(a[11], "      rd_dis 0   wr_dis 0");
        assert_eq!(b[10], "KEY5  HMAC_UP");
        assert_eq!(b[11], "      rd_dis 1   wr_dis 1");
        assert_ne!(a, b, "a provisioned unit must not read like an unprovisioned one");
        // The purposes are printed as IDF's own enumerator names, never translated, and
        // the longest of them still fits the 38-character table budget.
        let longest = KeyBlockInfo {
            purpose: Some(String::from("HMAC_DOWN_DIGITAL_SIGNATURE")),
            read_protected: false,
            write_protected: true,
        };
        let widest = lines(alloc::vec![longest]);
        assert_eq!(widest[0], "KEY0  HMAC_DOWN_DIGITAL_SIGNATURE");
        assert!(widest.iter().all(|l| l.chars().count() <= TABLE_COLS));
    }

    /// A device that could not read its fuses at all says so on every row rather than
    /// reporting a chip with everything unburned - the two are entirely different
    /// findings and the default must be the honest one.
    #[test]
    fn an_unread_efuse_section_says_not_read_and_not_disabled() {
        let f = Fixture::new(720, 720);
        for row in sheet(&f.ctx()) {
            if let Row::Inline { label, value, .. } = &row {
                if matches!(label.as_str(), "Secure boot" | "Flash encryption" | "Direct boot") {
                    assert_eq!(value.text, "not read", "{label}");
                    assert_eq!(value.ink, INK_MUTED, "{label} is an absence, not a bad value");
                }
            }
        }
    }

    // -- the scan --------------------------------------------------------------------

    /// Scanning adds exactly one row, in exactly one place: the spans replace the
    /// `not scanned` value in the row that already existed, and the concatenated digest
    /// follows it. Nothing else on the sheet moves, so the frozen order survives it.
    #[test]
    fn a_completed_scan_adds_one_row_after_the_row_it_belongs_to() {
        let mut f = fixture(720, 720, true);
        let before = labels(&f);
        f.verify.reserved_space = scanned_spans();
        let after = labels(&f);
        assert_eq!(after.len(), before.len() + 1);
        let at = after.iter().position(|l| l == "Reserved space").expect("the row");
        assert_eq!(after[at + 1], "Reserved space digest");
        let mut without = after.clone();
        without.remove(at + 1);
        assert_eq!(without, before, "scanning moved a field");
    }

    /// The span table, both cases, in the two-line form 11.1 fixes. A blank span says so;
    /// a span with bytes in it reports the count AND the offset, because an offset is the
    /// only part of the answer the owner can act on.
    #[test]
    fn a_span_reports_its_bytes_and_where_they_start() {
        let mut f = fixture(720, 720, true);
        f.verify.reserved_space = scanned_spans();
        let lines = sheet(&f.ctx())
            .into_iter()
            .find_map(|r| match r {
                Row::Table { label, lines, .. } if label == "Reserved space" => Some(lines),
                _ => None,
            })
            .expect("the span table");
        assert_eq!(lines.len(), 6, "two lines per span");
        assert_eq!(lines[1], "  all 0xff");
        assert_eq!(lines[3], "  4 096 set, first 0x01d2000");
        assert!(lines[2].starts_with("0x1d1c00-0xe00000"));
        assert!(lines[2].ends_with("12 772 352 B"));
        assert!(lines.iter().all(|l| l.chars().count() <= TABLE_COLS), "{lines:?}");
    }

    /// The partition map, in `partitions.csv`'s own columns and inside the 38-character
    /// budget, so the screen and the file are read against each other directly.
    #[test]
    fn the_partition_map_uses_the_frozen_columns() {
        let f = fixture(720, 720, true);
        let lines = sheet(&f.ctx())
            .into_iter()
            .find_map(|r| match r {
                Row::Table { label, lines, .. } if label == "Partitions" => Some(lines),
                _ => None,
            })
            .expect("the partition map");
        assert_eq!(lines[0], "factory  app/fact  0x010000  4096K");
        assert_eq!(lines[1], "wallets  data/0x06 0x410000   256K enc");
        assert_eq!(lines[2], "counters data/0x06 0x450000    16K");
        // 0.2.0's third region. Public, pre-PIN, and it volunteers nothing: the map says
        // a partition exists and how big it is, which the same person reads off the table
        // at 0x8000 with a USB cable.
        assert_eq!(lines[3], "settings data/0x06 0x460000    64K");
        assert!(lines.iter().all(|l| l.chars().count() <= TABLE_COLS), "{lines:?}");
    }

    // -- geometry -----------------------------------------------------------------------

    /// Nothing in the top bar is laid out past the panel, on any panel that ships.
    ///
    /// This is the defect the pixel gate caught the screen on. The Lock chip took a
    /// fraction of the panel - `150.min(m.w / 5)`, 144 px at 720 px wide - while its own
    /// label measures 174 px, and `text_centered` centres an oversized label rather than
    /// refusing it: the tail of "Lock device" was laid out at x >= 720, off the glass,
    /// where the device cannot paint it and no screenshot can recover it. On the screen
    /// whose whole job is letting an owner read values off the device, a character the
    /// panel cannot show is the worst defect available.
    ///
    /// So both widths are measured, and the measurement is asserted here against the
    /// text - which is why this checks every entry of `PANELS` rather than the two
    /// `GEOMETRIES` the rest of this suite uses: the escape was on a panel those two
    /// contain and on one they do not, and a bar this crowded is a per-panel fact.
    ///
    /// The clearance half matters as much as the fit half. The right slot is anchored to
    /// the right edge and knows nothing of the title beside it, so widening the chip to
    /// its label is only a fix if the slot still clears the title - and the day this sheet
    /// grows enough pages to widen the counter past that clearance, this fails rather than
    /// the bar overprinting itself.
    #[test]
    fn nothing_in_the_bar_is_laid_out_off_the_panel() {
        for (w, h) in PANELS {
            for unlocked in [false, true] {
                let f = fixture(w, h, unlocked);
                let m = &f.m;
                let l = VerifyState::new().layout(&f.ctx());
                let what = &format!("verify bar at {w}x{h}, unlocked={unlocked}");
                assert_eq!(l.lock.is_some(), unlocked, "{what}: the Lock chip follows the session");

                // Every index the pager can reach, not only the widest: the counter is
                // reserved once for the whole sheet, so a reservation that held for the
                // page it was measured from and not for page 9 of 12 would crop mid-sheet.
                for page in 1..=l.pages {
                    let s = counter_label(page, l.pages);
                    fits(what, &s, BODY.text_width(&s) as i32, l.counter);
                }

                // The title's rectangle as `components::bar` lays it out. Reconstructed
                // rather than returned because the bar paints the title for every screen
                // and hands back nothing; if that formula moves, this test is the thing
                // that has to move with it.
                let back = back_rect(m);
                let title = Rect::new(
                    back.right() + m.gap,
                    (m.bar - LINE) / 2,
                    HEADING.text_width(BAR_TITLE) as i32,
                    LINE,
                );
                let mut rows =
                    alloc::vec![("back", back), ("title", title), ("counter", l.counter)];
                if let Some(chip) = l.lock {
                    fits(what, LOCK_LABEL, HEADING.text_width(LOCK_LABEL) as i32, chip);
                    rows.push(("lock chip", chip));
                }
                rows_are_clear_on(m, what, Rect::new(0, 0, m.w, m.bar), &rows);
            }
        }
    }

    /// 11.1's inline budget is a character count over a monospace face, and the two
    /// numbers it is derived from are the value columns of the two shipped panels. Pin
    /// the constant to the geometry it was computed from, so a font change or a metric
    /// change fails here rather than by wrapping a value on one panel only.
    /// The two column constants, pinned to the geometry and to the label set they were
    /// computed from. A font change, a metric change or a new field name too long for the
    /// column fails HERE rather than by overprinting a value on one panel only - which is
    /// exactly the defect 11.1's own arithmetic has.
    #[test]
    fn the_columns_hold_the_label_set_on_both_panels() {
        let adv = MONO_SMALL.glyph('m').advance as i32;
        assert_eq!(adv, 17, "the character budgets are computed at 17 px per glyph");

        let widest = sheet(&fixture(720, 720, true).ctx())
            .iter()
            .filter_map(|r| match r {
                Row::Inline { label, .. } => Some((BODY.text_width(label) as i32, label.clone())),
                _ => None,
            })
            .max_by_key(|(w, _)| *w)
            .expect("the sheet has inline rows");
        assert!(
            widest.0 < LABEL_COL,
            "{:?} is {} px, past the {LABEL_COL} px label column",
            widest.1,
            widest.0
        );

        let mut narrowest = i32::MAX;
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            let body = f.m.body();
            assert_eq!(label_w(&body), LABEL_COL, "the ceiling bound at {w}x{h}");
            narrowest = narrowest.min(body.w - label_w(&body) - f.m.gap);
        }
        assert_eq!(narrowest / adv, INLINE_BUDGET as i32);
    }

    /// The K3 budget in the same terms: 38 characters plus the indent must fit the
    /// narrower body, and 39 must not.
    #[test]
    fn the_table_budget_fits_the_narrower_panel() {
        let adv = MONO_SMALL.glyph('m').advance as i32;
        for (w, h) in GEOMETRIES {
            let f = Fixture::new(w, h);
            let body = f.m.body();
            assert!(
                f.m.gap + TABLE_COLS as i32 * adv <= body.w,
                "the K3 budget overflows the body at {w}x{h}"
            );
        }
    }

    /// The hex break is a constant, and this is the worked example VERIFY.md 11.1 states:
    /// a 64-character digest is exactly three lines, at offsets 00 / 24 / 48.
    #[test]
    fn a_digest_breaks_into_three_lines_at_fixed_offsets() {
        let digest = "9b21c7fe034a88d56e1922bcaf705d31e0c819467b2faa530d84c61139e7f2a0";
        assert_eq!(digest.len(), 64);
        let lines = hex_lines(digest);
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0].0, "00");
        assert_eq!(lines[1].0, "24");
        assert_eq!(lines[2].0, "48");
        assert_eq!(lines[0].1, "9b21 c7fe 034a 88d5 6e19 22bc");
        assert_eq!(lines[2].1, "0d84 c611 39e7 f2a0");
        // ...and nothing was lost on the way.
        let joined: String =
            lines.iter().map(|(_, g)| g.replace(' ', "")).collect::<Vec<_>>().join("");
        assert_eq!(joined, digest);
    }

    /// A 128-bit die id is two lines, which is what the wireframe draws.
    #[test]
    fn a_128_bit_id_breaks_into_two_lines() {
        let lines = hex_lines("1f4c90ab3e77d2158c6044f9b1a35e08");
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[1].0, "24");
        assert_eq!(lines[1].1, "b1a3 5e08");
    }

    #[test]
    fn digit_grouping_is_by_threes_from_the_right() {
        assert_eq!(grouped(0), "0");
        assert_eq!(grouped(128), "128");
        assert_eq!(grouped(1235), "1 235");
        assert_eq!(grouped(1842176), "1 842 176");
        assert_eq!(grouped(18595840), "18 595 840");
    }
}

