// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! S-44 Settings: the device-level rows, with the dangerous one last and separated.
//!
//! Reached from the wallet list, which is where a session lives. Every row here either
//! configures stored wallets or states a fact about the device holding them, and there is
//! nothing to configure on a device that stores nothing - which is also why S-44's
//! stateless edge state ("This device has nothing stored...") is absent rather than
//! written-but-unreachable: it arrives with the first row that means something on a blank
//! device, and a branch no path can reach is a claim no test can check.
//!
//! # This screen is the post-unlock surface's second exit
//!
//! An unlock lands on the wallet list and the list is its own floor, so Home - and with it
//! everything Home is the sole route to - is unreachable for the whole life of a session.
//! Two controls were stranded there: S-46 Verify device, whose row set is strictly LARGER
//! post-PIN (the boot-counter acknowledgement is post-PIN only, so the one action that
//! needs a session sat on the one screen a session could not reach), and the network
//! choice, which is an input to every derivation the list's `New wallet` button starts.
//! Both are rows here. That is the placement S-44's own wireframe already specifies for
//! Verify device, and the cheapest honest home for the network: this screen is a list, a
//! list grows, and growing it costs no second surface.
//!
//! # The list scrolls; the destructive control does not
//!
//! The row catalogue is the extension point and it is longer than the short panel: the
//! 800x480 body holds two rows. So the rows scroll, in the shape the wallet list
//! established - a viewport that is a WHOLE number of rows, and a scroll extent that is an
//! exact multiple of the row pitch, so the list comes to rest showing complete rows only
//! and every row that is painted at rest is a row a finger can reach.
//!
//! The removal control is NOT in that list. It is pinned below it, separated by a full
//! page pad, and it carries its own frozen [`RegionId::RemoveThePin`] rather than a
//! position in the row table. Three things follow, and each is why: the separation from
//! the list holds at every scroll offset rather than only at the bottom of the travel; the
//! one irreversible control on the screen can never be scrolled out of sight or scrolled
//! UNDER a finger that was reaching for a list row; and the arithmetic that keeps the
//! viewport a whole number of rows stays uniform, which it could not with a row that needs
//! a pad of clearance in front of it.
//!
//! Rows in the list are named by POSITION IN THE LIVE LIST ([`RegionId::SetRow`]) rather
//! than by a fixed catalogue index, so a row that is absent cannot be reached by tapping
//! where it would have been.
//!
//! # Removing the PIN
//!
//! Q5.5, and the copy rule is easy to get backwards. "Keep the stored wallets with no PIN"
//! is not a state this device has: the sealing key is DERIVED FROM the PIN, so with no PIN
//! there is no key and no sealed storage. Removing it is therefore defined as reverting to
//! 0.1.0 stateless operation, and the confirmation
//!
//! - names what is destroyed INDIVIDUALLY, with counts read from the store rather than a
//!   generic phrase - post-PIN, where Q2(a) permits a count;
//! - must NOT describe the result as less secure. A device that stores nothing has nothing
//!   to extract and nothing to brute-force, which is the safest state this hardware has.
//!   The cost is data and convenience. Saying otherwise would teach exactly the wrong
//!   instinct about the setting in the row above it, where the risk runs the other way.

use alloc::string::String;
use alloc::vec::Vec;

use embedded_graphics::draw_target::{DrawTarget, DrawTargetExt};
use embedded_graphics::pixelcolor::Rgb565;

use crate::canvas::{button, fill, frame, text, toggle, ButtonKind, BODY, HEADING, MONO_SMALL};
use crate::components::{back_rect, draw_bar, LINE, SMALL_LINE};
use crate::danger::{Danger, DangerGrade, DangerOutcome};
use crate::layout::{Metrics, Rect, LIST_ROW_MIN};
use crate::screens::policy::PolicyState;
use crate::screens::verify::VerifyState;
use crate::screens::{Ctx, Env, Nav, Outcome, Screen, State};
use crate::theme::*;
use crate::{Region, RegionId, StoredCounts, UiRequest};
use notyas_core::bitcoin::Network;

/// The word typed back to confirm the removal. C4d specifies `WIPE` for device-level
/// destruction where there is no name to type, and it is the honest word here: Q5.5
/// defines removing the PIN as a wipe followed by leaving the store unformatted.
const REMOVE_WORD: &str = "WIPE";

/// Height of the two-state control a row carries instead of a chevron. Home's network
/// toggle is the same height, because it is the same control: the row is the target, and
/// this is what the state it holds looks like.
const TOGGLE_H: i32 = 48;

/// The refusal line, and the one hint that says the list continues. Constants because both
/// are drawn on one footer line that neither wraps nor scrolls, and a test measures them.
///
/// The refusal is two short sentences rather than one long one because the line has 672 px
/// on the narrower body and the sentence it replaced needed 823 - it ran off the panel
/// edge, unclipped, on the one screen whose job is to report that a destruction did not
/// happen. Both facts survive the shortening: the device said no, and nothing is gone.
const REFUSAL: &str = "The device refused. Nothing was erased.";
const MORE_BELOW: &str = "Scroll for more settings.";

pub(crate) struct SettingsState {
    /// The open confirmation, if any. Two sheets in sequence - the consequence, then the
    /// word - because what this destroys cannot be named individually in the lines a
    /// typed-name sheet has left after its keyboard, and naming it individually is the
    /// requirement.
    danger: Option<Danger>,
    /// The embedder could not complete a removal it was asked for. Shown as a line on the
    /// list rather than swallowed: a destructive request that quietly did nothing is the
    /// worst thing to leave a user guessing about.
    failed: bool,
    /// Scroll offset of the row list, in pixels. Clamped by [`Screen::scroll_limit`] to an
    /// exact multiple of the row pitch, so the list is never at rest on a part-row.
    scroll: i32,
}

impl SettingsState {
    pub fn new() -> SettingsState {
        SettingsState { danger: None, failed: false, scroll: 0 }
    }

    /// Answer to [`UiRequest::RemovePin`] when the store refused or could not finish.
    ///
    /// The success case is not reported here: it resets the whole UI (see
    /// [`crate::Ui::pin_removed`]) and this screen no longer exists to be told.
    pub fn report_failure(&mut self) {
        self.danger = None;
        self.failed = true;
    }

    /// The rows this device is showing, in the frozen order. One place, consumed by
    /// `layout`, `regions`, `draw` and `activate` alike, so a row can never be drawn at an
    /// index that resolves to a different action.
    ///
    /// Ordered the way S-44's wireframe orders what it has: the benign preference first,
    /// then the policy that decides what a wrong PIN costs, then the read-only readout.
    /// The destructive control is not in this table at all - see the module docs.
    fn rows(&self) -> &'static [Row] {
        &[Row::Network, Row::WipePolicy, Row::VerifyDevice]
    }

    /// The pinned destructive control, as a row.
    ///
    /// A function rather than a literal at the draw site so that the crowding test measures
    /// the copy the screen actually paints - this caption is the longest on the screen, and
    /// it is the one a clip would silently cut.
    fn removal_row() -> RowView {
        RowView {
            // Never "turn the PIN off": the sealing key IS the PIN, so removing it and
            // destroying what it protects are one act, and the row names both.
            caption: "Remove PIN and stored wallets",
            // No value at all: the caption already names both halves of what it does, and
            // the only phrase that could stand beside it - the device goes back to storing
            // nothing - does not fit next to a caption that long. It is said in full one tap
            // later, on the sheet that asks for consent, which is where it has to be read
            // anyway.
            value: None,
            trailing: Trailing::Opens,
        }
    }

    /// C4b: what removing the PIN destroys, named individually with counts from the store.
    fn review_sheet(counts: StoredCounts) -> Danger {
        // Two paragraphs, and no more: the 800x480 sheet holds six lines of body copy
        // and a third paragraph would spend one of them on its own gap. The three things
        // that must survive any further edit are what is destroyed (individually, with
        // counts), that the result stores nothing, and the way back.
        let destroyed = format!(
            "Destroyed: {}, {}, their names, all settings and the anti-phishing words.",
            counts.wallets_text(),
            counts.registrations_text()
        );
        Danger::confirm(
            "Remove the PIN and everything it protects?",
            &[
                &destroyed,
                // The result is a device that stores nothing, which is the SAFEST state
                // this hardware has (PIN-MODES.md). This is a data-loss event and the copy
                // says so; it must not read as a security downgrade.
                "The device then stores nothing at all, the safest state it has. Your \
                 dice rolls or seed words are the only way back.",
            ],
            "Continue",
        )
    }

    /// C4d: the word, with the counts restated so consent is given against the numbers
    /// rather than against a remembered sentence.
    ///
    /// One short line and nothing else: after its keyboard, its field and its action row,
    /// the landscape sheet has three lines of a 435 px column left. The counts are what
    /// earn them - the rest of the consequence was read on the sheet before this one.
    fn type_sheet(counts: StoredCounts) -> Danger {
        // Bare counts rather than the fuller phrases the sheet before this one used:
        // after its keyboard rail the landscape sheet leaves an eighteen-character column,
        // and the numbers are what has to survive that. What they are was named in full
        // one sheet ago.
        let restated = format!(
            "Erasing {} wallets and {} multisig registrations.",
            counts.wallets, counts.registrations
        );
        Danger::typed(
            "Remove PIN and stored wallets",
            &[&restated],
            "Erase everything",
            REMOVE_WORD,
        )
    }
}

/// A row of S-44's scrolling list. The enum is the catalogue; [`SettingsState::rows`] is
/// what is showing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Row {
    /// The network every derivation this device starts runs on. A device-wide pipeline
    /// input rather than a per-wallet fact, which is why it outlives the flow that reads it
    /// and why it belongs to a settings list rather than to a creation screen.
    Network,
    WipePolicy,
    /// S-46. A readout, so it changes nothing and can be opened at any time - and post-PIN
    /// it is the only place the boot-counter acknowledgement can be given at all.
    VerifyDevice,
}

impl Row {
    /// Everything the row shows, and therefore everything a tap on it can mean.
    fn view(self, ctx: &Ctx) -> RowView {
        match self {
            Row::Network => RowView {
                caption: "Network",
                value: None,
                // Both states on the panel and a tap between them, exactly as Home draws
                // the same choice: one control with one behaviour, in the two places the
                // choice can be made.
                trailing: Trailing::Toggle(
                    ["Mainnet", "Testnet"],
                    usize::from(ctx.network != Network::Bitcoin),
                ),
            },
            // A format string over runtime policy, never a literal (Q37).
            Row::WipePolicy => RowView {
                caption: "Wrong-PIN policy",
                value: Some(match ctx.lock.wipe_after {
                    Some(n) => format!("erase after {n}"),
                    None => String::from("never erases"),
                }),
                trailing: Trailing::Opens,
            },
            // No value: what the readout says IS the screen, and any word here would be a
            // summary of a measurement this row never made.
            Row::VerifyDevice => {
                RowView { caption: "Verify device", value: None, trailing: Trailing::Opens }
            }
        }
    }
}

/// What a row shows on its right, which is also what tapping it does.
enum Trailing {
    /// Opens a screen. Drawn with a chevron at the edge.
    Opens,
    /// Flips between the two states it shows. The only row shape on this device that acts
    /// in place, and it earns that by making what it will become visible before it is
    /// tapped - a row whose effect could only be seen afterwards would need a screen.
    Toggle([&'static str; 2], usize),
}

/// One row as it is drawn. Assembled once from [`Row::view`] and consumed by `draw` and by
/// the crowding test alike, so no row can be measured against copy it does not paint.
struct RowView {
    caption: &'static str,
    /// The value column, or `None` for a row whose caption is the whole statement.
    value: Option<String>,
    trailing: Trailing,
}

pub(crate) struct Layout {
    /// The scrolling list's window: a whole number of rows tall.
    viewport: Rect,
    /// One rect per live row, in list order, at the current offset. Rows outside the
    /// viewport are still here - `draw` clips them and `regions` refuses them - so both
    /// sides read one piece of arithmetic.
    rows: Vec<Rect>,
    /// One line under the list. Carries the scroll hint while there is more list below, and
    /// the refusal line when the embedder could not complete a removal; the refusal wins,
    /// because a destructive request that did nothing is the more urgent sentence and it
    /// sits directly above the control that raised it.
    footer: Rect,
    /// The destructive control, pinned to the foot of the body and separated from the list
    /// by a full page pad.
    remove: Rect,
    /// The session affordance in the top bar. Always present here: a session is the only
    /// way onto this screen.
    lock_chip: Rect,
}

/// Height of one row: the touch floor, or the button height where the panel is generous
/// enough to want it.
fn row_h(m: &Metrics) -> i32 {
    LIST_ROW_MIN.max(m.btn)
}

/// How tall `n` stacked rows are: `n` rows and the `n - 1` gaps BETWEEN them.
///
/// There is no gap after the last row. Every measurement of list content goes through here
/// so that the viewport and the scroll extent cannot disagree about where the content ends -
/// the disagreement that leaves a row painted a few pixels out of reach.
fn row_extent(n: i32, h: i32, gap: i32) -> i32 {
    (n * (h + gap) - gap).max(0)
}

/// The tallest window that is a whole number of rows, out of `room` px.
///
/// Zero when not even one row fits, which is a panel this screen cannot serve; both shipped
/// panels clear two rows and a test says so.
fn whole_rows(room: i32, h: i32, gap: i32) -> i32 {
    row_extent((room + gap) / (h + gap), h, gap)
}

impl Screen for SettingsState {
    type Layout = Layout;

    fn layout(&self, ctx: &Ctx) -> Layout {
        let m: &Metrics = &ctx.m;
        let body = m.body();
        let h = row_h(m);
        // Laid out from the FOOT upwards, because the two fixed things on this screen are
        // at the bottom: the destructive control and the line above it. The list takes what
        // is left, rounded down to whole rows.
        let remove = Rect::new(body.x, body.bottom() - h, body.w, h);
        let footer = Rect::new(body.x, remove.y - m.pad - SMALL_LINE, body.w, SMALL_LINE);
        let viewport =
            Rect::new(body.x, body.y, body.w, whole_rows(footer.y - m.gap - body.y, h, m.gap));
        let rows = (0..self.rows().len() as i32)
            .map(|i| Rect::new(body.x, viewport.y + i * (h + m.gap) - self.scroll, body.w, h))
            .collect();
        let chip_w = 200.min(m.w / 4);
        Layout {
            viewport,
            rows,
            footer,
            remove,
            lock_chip: Rect::new(m.w - m.pad - chip_w, m.gap / 2, chip_w, m.bar - m.gap),
        }
    }

    fn regions(&self, ctx: &Ctx, out: &mut Vec<Region>) {
        // A sheet is MODAL: while one is open it is the only thing on the panel a finger
        // can reach, so the list below it is as inert as it looks.
        if let Some(d) = &self.danger {
            d.regions(&ctx.m, out);
            return;
        }
        let l = self.layout(ctx);
        out.push(Region { id: RegionId::Back, rect: back_rect(&ctx.m) });
        out.push(Region { id: RegionId::Lock, rect: l.lock_chip });
        // A row that is only partly in the window draws but does not tap, which is the
        // honest reading of half a row. Safe only because the window is a whole number of
        // rows and the extent an exact multiple of the pitch: at either end of the travel
        // the list is at rest showing complete rows, so the rule can never fire on a row
        // nobody moved.
        for (i, r) in l.rows.iter().enumerate() {
            if r.y >= l.viewport.y && r.bottom() <= l.viewport.bottom() {
                out.push(Region { id: RegionId::SetRow(i as u8), rect: *r });
            }
        }
        out.push(Region { id: RegionId::RemoveThePin, rect: l.remove });
    }

    fn draw<D: DrawTarget<Color = Rgb565>>(&self, t: &mut D, ctx: &Ctx) -> Result<(), D::Error> {
        let m = &ctx.m;
        if let Some(d) = &self.danger {
            return d.draw(t, m, ctx.press, ctx.hold_released);
        }
        draw_bar(t, m, "Settings")?;
        let l = self.layout(ctx);
        button(t, l.lock_chip, "Lock device", ButtonKind::Secondary, PAPER_2)?;

        {
            let mut clip = t.clipped(&l.viewport.to_eg());
            for (row, rect) in self.rows().iter().zip(&l.rows) {
                draw_row(&mut clip, m, *rect, &row.view(ctx), false)?;
            }
        }

        {
            let mut foot = t.clipped(&l.footer.to_eg());
            if self.failed {
                text(&mut foot, REFUSAL, l.footer.x, l.footer.y, BODY, DANGER, PAPER_1)?;
            } else if self.scroll < self.scroll_limit(ctx) {
                // A whole-row window shows no sliver of the next row, so nothing on the
                // panel would otherwise say the list continues. This line is that
                // statement, and it is drawn only while it is true.
                text(&mut foot, MORE_BELOW, l.footer.x, l.footer.y, BODY, INK_SECONDARY, PAPER_1)?;
            }
        }

        draw_row(t, m, l.remove, &SettingsState::removal_row(), true)
    }

    fn activate(&mut self, id: RegionId, env: &mut Env) -> Outcome {
        // The sheet, while open, answers for the whole screen.
        if let Some(d) = &mut self.danger {
            let outcome = d.activate(id);
            let grade = d.grade();
            return match outcome {
                // This sheet offers no third answer, so the region cannot be emitted and
                // the arm cannot be reached from a tap.
                DangerOutcome::Open | DangerOutcome::Alternative => Outcome::stay(),
                DangerOutcome::Cancelled => {
                    self.danger = None;
                    Outcome::stay()
                }
                DangerOutcome::Confirmed => match grade {
                    // The consequence has been read; the word is next. Never the action.
                    DangerGrade::Confirm => {
                        self.danger = Some(Self::type_sheet(StoredCounts::of(env.wallets)));
                        Outcome::stay()
                    }
                    // Consent complete. The sheet closes BEFORE the request goes out, so a
                    // tap arriving behind it cannot ask for the same destruction twice.
                    _ => {
                        self.danger = None;
                        Outcome::ask(UiRequest::RemovePin)
                    }
                },
            };
        }
        match id {
            RegionId::SetRow(i) => match self.rows().get(i as usize) {
                // The one row that acts here rather than opening a screen. The network
                // outlives this screen (it is `Env`'s only mutable field), so the change is
                // still in force when the wallet list starts the next derivation.
                Some(Row::Network) => {
                    *env.network = match *env.network {
                        Network::Bitcoin => Network::Testnet,
                        _ => Network::Bitcoin,
                    };
                    Outcome::stay()
                }
                Some(Row::WipePolicy) => Outcome::push(State::Policy(PolicyState::new())),
                Some(Row::VerifyDevice) => Outcome::push(State::Verify(VerifyState::new())),
                None => Outcome::stay(),
            },
            RegionId::RemoveThePin => {
                self.failed = false;
                self.danger = Some(Self::review_sheet(StoredCounts::of(env.wallets)));
                Outcome::stay()
            }
            RegionId::Lock => Outcome::ask(UiRequest::LockSession),
            _ => Outcome::stay(),
        }
    }

    /// Back is the screen the settings were opened from. While a sheet is open there is no
    /// Back region at all - the sheet's own Cancel is the way out - so this cannot be
    /// reached mid-confirmation.
    fn back(&self) -> Nav {
        Nav::Back
    }

    /// Frozen while a sheet is open, so the list cannot move under a confirmation.
    fn scroll_mut(&mut self) -> Option<&mut i32> {
        if self.danger.is_some() {
            return None;
        }
        Some(&mut self.scroll)
    }

    fn scroll_limit(&self, ctx: &Ctx) -> i32 {
        let l = self.layout(ctx);
        let content = row_extent(self.rows().len() as i32, row_h(&ctx.m), ctx.m.gap);
        (content - l.viewport.h).max(0)
    }
}

/// One row: caption left, then whatever the row shows on the right. The pinned destructive
/// control is the same shape in a different ink, so it reads as the end of the list rather
/// than as a button that wandered in.
fn draw_row<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    m: &Metrics,
    r: Rect,
    view: &RowView,
    danger: bool,
) -> Result<(), D::Error> {
    let (paper, ink, edge) = if danger {
        (DANGER_TINT, DANGER, DANGER)
    } else {
        (PAPER_2, INK_PRIMARY, BORDER_STRONG)
    };
    fill(t, r, paper)?;
    frame(t, r, edge)?;
    let inner = r.inset(m.gap);
    let y = inner.y + (inner.h - LINE) / 2;
    let muted = if danger { DANGER } else { INK_SECONDARY };

    // Laid out from the RIGHT, and MEASURED rather than offset by a guess: whatever the row
    // carries takes its width first and the caption is pixel-clipped to what remains, so no
    // copy change can make the two run into each other - the one failure that would make
    // both unreadable at once.
    let caption_right = match &view.trailing {
        Trailing::Opens => {
            let chevron_w = HEADING.text_width(">") as i32;
            let chevron_x = inner.right() - chevron_w;
            text(t, ">", chevron_x, y, HEADING, muted, paper)?;
            let mut right = chevron_x - m.gap;
            if let Some(value) = &view.value {
                let value_w = MONO_SMALL.text_width(value) as i32;
                right -= value_w;
                text(t, value, right, y + 6, MONO_SMALL, muted, paper)?;
                right -= m.gap;
            }
            right
        }
        Trailing::Toggle(labels, active) => {
            let w = toggle_w(inner.w);
            let rect =
                Rect::new(inner.right() - w, inner.y + (inner.h - TOGGLE_H) / 2, w, TOGGLE_H);
            toggle(t, rect, *labels, *active)?;
            rect.x - m.gap
        }
    };
    let mut clip =
        t.clipped(&Rect::new(inner.x, inner.y, (caption_right - inner.x).max(0), inner.h).to_eg());
    text(&mut clip, view.caption, inner.x, y, HEADING, ink, paper)?;
    Ok(())
}

/// Width of a row's two-state control: half the row at most, so the caption keeps the other
/// half whatever the panel is.
fn toggle_w(inner_w: i32) -> i32 {
    240.min(inner_w / 2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::{Metrics, TOUCH_MIN};
    use crate::screens::testing::{rows_are_clear, Fixture, GEOMETRIES};
    use crate::{StoreStatus, WalletRow, WALLET_SLOTS};

    /// A device with a session open, on the settings screen.
    fn at_settings(w: u32, h: u32) -> Fixture {
        let mut f = Fixture::new(w, h);
        f.lock.status = StoreStatus::Unlocked;
        f.lock.wipe_after = Some(10);
        f
    }

    /// The consequence must FIT. It is the one block on a sheet with no scroll and no
    /// ellipsis, it is the whole reason the confirmation exists, and half of it drawn is
    /// worse than none. Checked at the widest counts the store can produce and at the
    /// empty device, because both render different lengths.
    #[test]
    fn the_removal_consequence_fits_both_sheets_on_both_panels() {
        for (w, h) in GEOMETRIES {
            let m = Metrics::new(w, h);
            for counts in [
                StoredCounts::default(),
                StoredCounts { wallets: 1, registrations: 1 },
                // Every slot full and every registration slot with it: the longest
                // string both counts can render, so nothing a real store holds is longer.
                StoredCounts {
                    wallets: usize::from(WALLET_SLOTS),
                    registrations: usize::from(WALLET_SLOTS) * usize::from(u8::MAX),
                },
            ] {
                for sheet in
                    [SettingsState::review_sheet(counts), SettingsState::type_sheet(counts)]
                {
                    let (used, have) = sheet.text_budget(&m);
                    assert!(
                        used <= have,
                        "{w}x{h} {counts:?}: the consequence needs {used} px of {have}"
                    );
                }
            }
        }
    }

    /// The counts come from the wallet list itself rather than a parallel tally, and an
    /// unreadable slot still counts as a wallet: it occupies a slot and it is destroyed.
    #[test]
    fn the_counts_are_read_from_the_store() {
        let mut f = Fixture::new(720, 720);
        f.lock.status = StoreStatus::Unlocked;
        f.wallets = vec![WalletRow::Unreadable { slot: 0 }, WalletRow::Unreadable { slot: 3 }];
        let counts = StoredCounts::of(&f.wallets);
        assert_eq!(counts.wallets, 2);
        assert_eq!(counts.registrations, 0);
        assert_eq!(counts.wallets_text(), "2 stored wallets");
        assert_eq!(StoredCounts::default().wallets_text(), "no stored wallets");
        assert_eq!(
            StoredCounts { wallets: 1, registrations: 1 }.registrations_text(),
            "1 multisig registration"
        );
    }

    /// Caption and trailing never run into each other. The clip in `draw_row` makes an
    /// overlap impossible to SEE, which is exactly why it has to be impossible to HAVE:
    /// a clipped caption is a row whose meaning was cut, and the assertion is what stops
    /// a copy change reaching a device that way. The pinned removal control is measured
    /// with the list rows because its caption is the longest one on the screen.
    #[test]
    fn no_row_caption_is_crowded_out_by_what_it_carries() {
        for (w, h) in GEOMETRIES {
            for wipe_after in [Some(3u8), Some(25), None] {
                for network in [Network::Bitcoin, Network::Testnet] {
                    let mut f = at_settings(w, h);
                    f.lock.wipe_after = wipe_after;
                    let mut ctx = f.ctx();
                    ctx.network = network;
                    let state = SettingsState::new();
                    let l = state.layout(&ctx);
                    let drawn = state
                        .rows()
                        .iter()
                        .zip(&l.rows)
                        .map(|(row, rect)| (*rect, row.view(&ctx)))
                        .chain(core::iter::once((l.remove, SettingsState::removal_row())));
                    for (rect, view) in drawn {
                        let inner = rect.inset(ctx.m.gap);
                        let caption = HEADING.text_width(view.caption) as i32;
                        let trailing = match &view.trailing {
                            Trailing::Opens => {
                                HEADING.text_width(">") as i32
                                    + ctx.m.gap
                                    + view.value.as_deref().map_or(0, |v| {
                                        MONO_SMALL.text_width(v) as i32 + ctx.m.gap
                                    })
                            }
                            Trailing::Toggle(..) => toggle_w(inner.w) + ctx.m.gap,
                        };
                        assert!(
                            caption + trailing <= inner.w,
                            "{w}x{h}: \"{}\" needs {} px of {}",
                            view.caption,
                            caption + trailing,
                            inner.w
                        );
                    }
                }
            }
        }
    }

    /// The parts of the screen that are not rows still have to clear each other. The bar
    /// chip, the list window, the footer line and the pinned removal control are MEASURED
    /// rectangles that no `Region` names on its own, which is exactly the class of overlap
    /// every other check in this suite is blind to.
    #[test]
    fn the_fixed_furniture_is_clear_on_both_panels() {
        for (w, h) in GEOMETRIES {
            let f = at_settings(w, h);
            let ctx = f.ctx();
            let l = SettingsState::new().layout(&ctx);
            rows_are_clear(
                &format!("{w}x{h} settings"),
                ctx.m.screen(),
                &[
                    ("lock chip", l.lock_chip),
                    ("list window", l.viewport),
                    ("footer", l.footer),
                    ("removal control", l.remove),
                ],
            );
            assert!(
                l.viewport.y >= ctx.m.body().y && l.remove.bottom() <= ctx.m.body().bottom(),
                "{w}x{h}: the list escapes the body"
            );
        }
    }

    /// The destructive control keeps a full page pad of clearance from the list AT EVERY
    /// SCROLL OFFSET, which is the property pinning it buys and the reason it is not a row.
    #[test]
    fn the_removal_control_stands_apart_wherever_the_list_is() {
        for (w, h) in GEOMETRIES {
            let f = at_settings(w, h);
            let ctx = f.ctx();
            let mut s = SettingsState::new();
            for offset in [0, s.scroll_limit(&ctx)] {
                *s.scroll_mut().unwrap() = offset;
                let l = s.layout(&ctx);
                assert!(
                    l.remove.y - l.viewport.bottom() >= ctx.m.pad,
                    "{w}x{h} at {offset}: the removal control is not separated from the list"
                );
                assert!(
                    l.remove.h >= LIST_ROW_MIN && l.remove.w >= TOUCH_MIN,
                    "{w}x{h}: the removal control is {}x{}",
                    l.remove.w,
                    l.remove.h
                );
            }
        }
    }

    /// THE INVARIANT, in the wallet list's words: at rest, every row that is PAINTED is
    /// TAPPABLE. `draw` paints each row through a clip on the window, so any overlap at all
    /// leaves ink; `regions` emits a row only when it fits entirely. The two sets have to be
    /// the SAME set wherever the list is standing still, or the screen shows a control that
    /// does nothing.
    #[test]
    fn every_painted_row_at_rest_is_tappable() {
        for (w, h) in GEOMETRIES {
            let f = at_settings(w, h);
            let ctx = f.ctx();
            let mut s = SettingsState::new();
            let limit = s.scroll_limit(&ctx);
            for offset in [0, limit] {
                *s.scroll_mut().unwrap() = offset;
                let l = s.layout(&ctx);
                let mut out = Vec::new();
                s.regions(&ctx, &mut out);
                for (i, r) in l.rows.iter().enumerate() {
                    let painted = r.y < l.viewport.bottom() && r.bottom() > l.viewport.y;
                    let tappable =
                        out.iter().any(|g| g.id == RegionId::SetRow(i as u8) && g.rect == *r);
                    assert_eq!(
                        painted, tappable,
                        "{w}x{h} at scroll {offset}: row {i} at {r:?} is painted={painted} \
                         but tappable={tappable} in window {:?}",
                        l.viewport
                    );
                }
            }
        }
    }

    /// The window is a whole number of rows, both panels hold at least two, and the scroll
    /// extent is an exact multiple of the row pitch - which is what makes the invariant
    /// above hold by construction rather than by luck. Every row must also be REACHABLE: a
    /// settings row no scroll can bring into the window is a setting the device does not
    /// have.
    #[test]
    fn the_window_is_whole_rows_and_every_row_can_be_reached() {
        for (w, h) in GEOMETRIES {
            let f = at_settings(w, h);
            let ctx = f.ctx();
            let mut s = SettingsState::new();
            let l = s.layout(&ctx);
            let (rh, gap) = (row_h(&ctx.m), ctx.m.gap);
            let pitch = rh + gap;
            let shown = (l.viewport.h + gap) / pitch;
            assert!(shown >= 2, "{w}x{h}: the settings window holds {shown} rows");
            assert_eq!(
                l.viewport.h,
                row_extent(shown, rh, gap),
                "{w}x{h}: the window ends inside row {shown}"
            );
            let limit = s.scroll_limit(&ctx);
            assert_eq!(limit % pitch, 0, "{w}x{h}: the scroll extent is not whole rows");

            *s.scroll_mut().unwrap() = limit;
            let l = s.layout(&ctx);
            let last = l.rows.last().expect("the catalogue is not empty");
            assert!(
                last.y >= l.viewport.y && last.bottom() <= l.viewport.bottom(),
                "{w}x{h}: the last row is at {last:?} in a window of {:?}",
                l.viewport
            );
        }
    }

    /// The refusal line and the scroll hint share one line, and neither wraps, so both have
    /// to fit the line they are drawn on at both geometries.
    #[test]
    fn the_footer_line_fits_what_it_can_carry() {
        for (w, h) in GEOMETRIES {
            let f = at_settings(w, h);
            let ctx = f.ctx();
            let l = SettingsState::new().layout(&ctx);
            for line in [REFUSAL, MORE_BELOW] {
                assert!(
                    BODY.text_width(line) as i32 <= l.footer.w,
                    "{w}x{h}: \"{line}\" needs {} px of {}",
                    BODY.text_width(line),
                    l.footer.w
                );
            }
            assert!(l.footer.h >= SMALL_LINE, "{w}x{h}: the footer line is {} px", l.footer.h);
        }
    }
}
