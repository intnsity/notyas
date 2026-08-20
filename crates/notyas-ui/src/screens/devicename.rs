// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! S-44a Device name: the one string this device shows before a PIN is typed.
//!
//! # Why this screen exists
//!
//! Because S-03 advertised a control that was never built. The lock screen carried two
//! user-set strings - a nickname and a "lock word" - and its edge state told the user to
//! "set one in Settings", where no such row had ever existed. On 2026-08-19 the owner
//! collapsed the two into one device NAME and asked for the row. This is the row's other
//! half; a screen that says "set it in Settings" and a Settings that cannot is the defect
//! that started all of it, and it is not repeated here.
//!
//! # What this screen is careful about
//!
//! The name is drawn on a surface shown BEFORE authentication, so it is public to whoever
//! is holding the device - see [`crate::LockInfo::device_name`], which states that in the
//! one place a future reader will look. Three consequences, and each is enforced rather
//! than described:
//!
//! - **It makes no security claim.** The copy here says the name is a label and points at
//!   the anti-phishing words for the thing it is not. A test below checks that no string
//!   this screen can paint says otherwise.
//! - **It cannot be a secret by accident.** A user who types their PIN into a field
//!   labelled "name" has published it on the lock screen, and a seed word typed here is a
//!   word of a backup shown to anyone who picks the device up. Both are refused, with the
//!   reason on the panel.
//! - **It cannot overrun the row that shows it.** The lock screen centres the name,
//!   unwrapped, in a fixed row, and `text_centered` crops rather than wraps - so a name
//!   too wide for the narrowest shipped panel loses both its ends with nothing raised
//!   anywhere. The only place that can be refused is here, at the moment it is typed.

use alloc::string::String;
use alloc::vec::Vec;

use embedded_graphics::draw_target::{DrawTarget, DrawTargetExt};
use embedded_graphics::pixelcolor::Rgb565;

use crate::canvas::{self, button, text, wrap_words, ButtonKind, BODY, MONO, MONO_SMALL};
use crate::components::{back_rect, draw_bar, draw_keyboard, keyboard, LINE, SMALL_LINE};
use crate::layout::{Metrics, Rect, PANELS};
use crate::screens::{Ctx, Env, Outcome, Screen};
use crate::theme::*;
use crate::{Page, Region, RegionId, UiRequest};
use notyas_core::bip39;

/// Field height, matching S-20's: the two typed-name fields in the product are the same
/// control and a user should not have to learn it twice.
const FIELD_H: i32 = 56;

/// The rule, as short as it can be said. The keyboard enforces it silently - an illegal
/// character never reaches the field - so this is a description rather than an error.
const NAME_RULE: &str = "Letters, digits, spaces, - and _";

/// The placeholder, which is also the honest description of an empty name: a device with
/// no name is unnamed, not misconfigured.
const PLACEHOLDER: &str = "name this device";

/// What the name is FOR, and - the sentence this screen exists to get right - what it is
/// not for.
///
/// Two facts and no adjectives. The first is the one a user cannot guess and would be
/// annoyed to discover: this string is readable by anyone holding the device. The second
/// is the claim the deleted lock word used to make, redirected to the mechanism that can
/// actually keep it.
const EXPLAIN: [&str; 2] = [
    "Shown on the lock screen, before any PIN is typed. Anyone holding the device can \
     read it.",
    "It tells your devices apart. It is not proof - the device words on the PIN screen \
     are that.",
];

/// The refusals, as the sentences the panel shows. Named so the copy test reads what the
/// screen paints, and `&'static str` so a refusal cannot be assembled out of user input.
const REFUSE_CHARS: &str = "Letters, digits, spaces, - and _ only.";
const REFUSE_PIN: &str = "That is a row of digits and reads as a PIN. Names are public.";
const REFUSE_SEED_WORD: &str = "That is a seed word. Nothing from a backup goes on the lock screen.";
const REFUSE_LONG: &str = "Too long for the lock screen to show whole.";

/// Characters a device name may hold, and the same set S-20 allows a wallet name.
///
/// ASCII by construction, which is not a style choice: the font atlas is ASCII-only, so a
/// non-ASCII character has no glyph and would draw as nothing at all on the one screen a
/// user reads to recognise their device.
fn allowed(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == ' ' || c == '-' || c == '_'
}

/// Why this name is refused, or `None` if it is acceptable.
///
/// Empty is acceptable and means the device is unnamed - the user must be able to take a
/// name off, and the lock screen has an edge state for exactly that.
///
/// Order is deliberate: the character rule first, because it decides whether the rest of
/// the string is even meaningful, and the width rule last, because a name can be perfectly
/// legal and still too wide, and telling a user their name is too long when it is actually
/// the seed word that stopped it would be a lie.
pub(crate) fn name_refusal(name: &str) -> Option<&'static str> {
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    if !name.chars().all(allowed) {
        return Some(REFUSE_CHARS);
    }
    // A PIN typed into a field labelled "name" is a PIN published on the lock screen. The
    // test is the SHAPE - every character a digit - rather than a comparison against the
    // real PIN, which this crate does not have and must never be given: a screen that
    // could answer "is this the PIN" is an oracle, and the whole product is built so that
    // no surface but the store can answer it.
    if name.chars().all(|c| c.is_ascii_digit()) {
        return Some(REFUSE_PIN);
    }
    // One BIP-39 word is one word of somebody's backup, and this is the one screen in the
    // product that would then print it to an unauthenticated reader. Refused whatever the
    // user meant by it: "anvil" is a fine name and a bad thing to volunteer, and the
    // device cannot tell which it is looking at.
    //
    // Single words only. A multi-word name is not a phrase in any useful sense - order and
    // count both matter to a backup - and refusing "the north window" because "north" is
    // on the list would make the rule feel arbitrary, which is how a rule gets worked
    // around instead of understood.
    if !name.contains(' ') && is_seed_word(name) {
        return Some(REFUSE_SEED_WORD);
    }
    if quoted_width(name) > name_row_w() {
        return Some(REFUSE_LONG);
    }
    None
}

/// Whether `word` is on the BIP-39 English list, case-insensitively.
///
/// The list is sorted (asserted in `notyas_core::bip39`) and every entry is lowercase
/// ASCII, so a lowercased copy binary-searches directly.
fn is_seed_word(word: &str) -> bool {
    let lower: String = word.chars().map(|c| c.to_ascii_lowercase()).collect();
    bip39::wordlist().binary_search(&lower.as_str()).is_ok()
}

/// How wide the name is as the lock screen actually draws it: in the mono face, inside the
/// quotes that screen puts around it.
///
/// Measured through the same font and the same decoration, because a limit derived from
/// anything else is a guess about the row it is protecting.
fn quoted_width(name: &str) -> i32 {
    MONO.text_width(&alloc::format!("\"{name}\"")) as i32
}

/// The width a device name has to fit: the NARROWEST body of any panel the firmware
/// ships, not this one.
///
/// Stricter than the panel in front of the user, and deliberately. A name is typed once
/// and read for the life of the device, the firmware builds for five distinct geometries
/// off one source tree, and a name that fits the 800x480 body (748 px) would be cropped on
/// the 720x720 one (672 px) with nothing raised anywhere. Taking the minimum over
/// [`PANELS`] means the answer this screen gives is true on every device the name could
/// end up on, and it is READ from that list rather than restated, so a narrower panel
/// added to the firmware tightens the rule instead of silently escaping it.
fn name_row_w() -> i32 {
    PANELS
        .into_iter()
        .map(|(w, h)| Metrics::new(w, h).content().w)
        .min()
        .unwrap_or(0)
}

/// S-44a's state. The name is public, so nothing here is a secret and nothing is wiped.
pub(crate) struct DeviceNameState {
    name: String,
    page: Page,
    /// The keyboard is up. Two phases for S-20's reason: the keyboard and everything the
    /// screen has to SAY do not fit together on the 800x480 panel.
    typing: bool,
    /// The embedder could not store the name. Reported on the panel rather than swallowed:
    /// a write that quietly did nothing leaves the user believing their device is named.
    failed: bool,
}

impl DeviceNameState {
    /// Opened on the name the device currently has, so the row is an EDITOR rather than a
    /// blank field that silently discards whatever was there.
    pub fn new(current: &str) -> DeviceNameState {
        DeviceNameState {
            name: String::from(current),
            page: Page::Lower,
            typing: false,
            failed: false,
        }
    }

    /// Answer to [`UiRequest::SetDeviceName`] that the embedder refused.
    pub fn report_failure(&mut self) {
        self.failed = true;
    }

    /// The name as it will be STORED: trimmed, exactly as `activate` hands it over.
    ///
    /// One definition, called by both the commit and the `Ui` that installs the result, so
    /// the string the device shows can never differ from the string the embedder was given.
    pub fn committed(&self) -> String {
        String::from(self.name.trim())
    }

    /// Why Save is disabled, or `None` when it is live.
    ///
    /// Save is live for an empty name: clearing the name is a thing the user is entitled
    /// to do, and a screen that could only ever ADD a name would be a one-way door.
    fn refusal(&self) -> Option<&'static str> {
        name_refusal(&self.name)
    }
}

pub(crate) struct Layout {
    field: Rect,
    /// The rule and the character budget, on one line under the field.
    hint_y: i32,
    /// The two explaining sentences, or the refusal when there is one. Zero-height in the
    /// typing phase.
    say: Rect,
    kb: Rect,
    save: Rect,
}

impl Screen for DeviceNameState {
    type Layout = Layout;

    fn layout(&self, ctx: &Ctx) -> Layout {
        let m = &ctx.m;
        let body = m.body();
        let g = m.gap;
        let field = Rect::new(body.x, body.y, body.w, FIELD_H);
        let hint_y = field.bottom() + g / 2;
        let none = Rect::new(0, 0, 0, 0);

        if self.typing {
            let kb_top = hint_y + SMALL_LINE + g;
            return Layout {
                field,
                hint_y,
                say: none,
                kb: Rect::new(body.x, kb_top, body.w, body.bottom() - kb_top),
                save: none,
            };
        }

        // Save is bottom-right, the width S-20 gives the same control, and what is left
        // above it belongs to the sentences. Anchored to the foot rather than flowed after
        // the copy so that a longer refusal cannot walk the button under a finger that was
        // already reaching for it.
        let save_w = (body.w * 2 / 5).max(280).min(body.w);
        let save = Rect::new(body.right() - save_w, body.bottom() - m.btn, save_w, m.btn);
        let say_top = hint_y + SMALL_LINE + g;
        let say = Rect::new(body.x, say_top, body.w, (save.y - g - say_top).max(0));
        Layout { field, hint_y, say, kb: none, save }
    }

    fn regions(&self, ctx: &Ctx, out: &mut Vec<Region>) {
        let l = self.layout(ctx);
        out.push(Region { id: RegionId::Back, rect: back_rect(&ctx.m) });
        out.push(Region { id: RegionId::DeviceNameField, rect: l.field });
        if self.typing {
            for k in keyboard(l.kb, self.page) {
                out.push(Region { id: k.id, rect: k.rect });
            }
            return;
        }
        out.push(Region { id: RegionId::DeviceNameSave, rect: l.save });
    }

    fn draw<D: DrawTarget<Color = Rgb565>>(&self, t: &mut D, ctx: &Ctx) -> Result<(), D::Error> {
        let m = &ctx.m;
        draw_bar(t, m, "Device name")?;
        let l = self.layout(ctx);
        let body = m.body();

        // Never masked. The whole point of the string is that it is read, and by someone
        // who has not authenticated at that.
        canvas::field(t, l.field, &self.name, false, self.typing)?;
        if self.name.is_empty() {
            let y = l.field.y + (l.field.h - LINE) / 2;
            text(t, PLACEHOLDER, l.field.x + 12, y, BODY, INK_MUTED, PAPER_3)?;
        }
        // The rule, and NOT the character budget S-20 draws beside its own. A wallet name
        // has a character maximum, so a count out of it means something; a device name is
        // bounded by PIXELS on a row of a screen the user is not looking at, so the only
        // honest counterpart would be a width, which is not a number anyone can act on.
        // The refusal below says when the name is too long, in the words that say what to
        // do about it. The test below is what keeps this line inside its row - the first
        // draft drew a count on the right that landed on top of the rule at 720x720.
        text(t, NAME_RULE, body.x, l.hint_y, MONO_SMALL, INK_MUTED, PAPER_1)?;

        if self.typing {
            draw_keyboard(t, l.kb, self.page, self.refusal().is_none())?;
            return Ok(());
        }

        // Whichever the user most needs: why the device would not take this name, why the
        // embedder would not store it, or what the name is and is not. One block, so the
        // three can never be drawn over each other.
        let mut y = l.say.y;
        let mut clip = t.clipped(&l.say.to_eg());
        let (block, ink) = match (self.refusal(), self.failed) {
            (Some(why), _) => (alloc::vec![why], DANGER),
            (None, true) => (alloc::vec![SAVE_FAILED], DANGER),
            (None, false) => (EXPLAIN.to_vec(), INK_SECONDARY),
        };
        // The gap goes BETWEEN paragraphs and not after the last one. A trailing gap is
        // invisible on the panel and costs a third of a line of the height budget the test
        // below measures against, on the panel that has the least of it.
        for (i, para) in block.iter().enumerate() {
            if i > 0 {
                y += m.gap;
            }
            for line in wrap_words(para, l.say.w, BODY) {
                text(&mut clip, &line, l.say.x, y, BODY, ink, PAPER_1)?;
                y += LINE;
            }
        }

        let kind = if self.refusal().is_none() { ButtonKind::Primary } else { ButtonKind::Disabled };
        button(t, l.save, SAVE_LABEL, kind, PAPER_1)?;
        Ok(())
    }

    fn activate(&mut self, id: RegionId, _env: &mut Env) -> Outcome {
        match id {
            // Filtered at the key, so an illegal character never reaches the field and the
            // rule needs no error message. The LENGTH rules still refuse after the fact,
            // because a width is a property of the whole string.
            RegionId::Key(c) if allowed(c) => {
                self.failed = false;
                self.name.push(c);
                Outcome::stay()
            }
            RegionId::Space => {
                self.failed = false;
                self.name.push(' ');
                Outcome::stay()
            }
            RegionId::KeyBackspace => {
                self.failed = false;
                self.name.pop();
                Outcome::stay()
            }
            RegionId::Shift => {
                self.page = if self.page == Page::Lower { Page::Upper } else { Page::Lower };
                Outcome::stay()
            }
            RegionId::PageDigits => {
                self.page = Page::Digits;
                Outcome::stay()
            }
            RegionId::PageLetters => {
                self.page = Page::Lower;
                Outcome::stay()
            }
            RegionId::PageSymbols => {
                self.page = Page::Symbols;
                Outcome::stay()
            }
            // The field raises the keyboard and Done puts it away again: the two halves of
            // one control, exactly as S-20 has it.
            RegionId::DeviceNameField => {
                self.typing = true;
                Outcome::stay()
            }
            RegionId::KeyDone => {
                self.typing = false;
                Outcome::stay()
            }
            // Trimmed on the way out, so the string the device stores is the string the
            // user can see they typed. The guard is the same call the button was DRAWN
            // from: a tap can never commit a name the panel showed as refused.
            RegionId::DeviceNameSave if self.refusal().is_none() => {
                Outcome::ask(UiRequest::SetDeviceName(self.committed()))
            }
            _ => Outcome::stay(),
        }
    }
}

/// The commit, and the sentence for a commit that did not happen.
const SAVE_LABEL: &str = "Save name";
const SAVE_FAILED: &str = "The device could not store that name. Nothing was changed.";

#[cfg(test)]
mod tests {
    use crate::UnlockGate;
    use super::*;
    use crate::screens::testing::{fits, rows_are_clear_on, Fixture, GEOMETRIES};

    fn laid_out(w: u32, h: u32, name: &str, typing: bool) -> (Fixture, DeviceNameState, Layout) {
        let f = Fixture::new(w, h);
        let mut s = DeviceNameState::new(name);
        s.typing = typing;
        let l = s.layout(&f.ctx());
        (f, s, l)
    }

    /// Nothing S-44a draws lands on anything else, in either phase, on either panel.
    #[test]
    fn no_two_blocks_of_the_device_name_screen_overlap() {
        for (w, h) in GEOMETRIES {
            for typing in [false, true] {
                let (f, _, l) = laid_out(w, h, "kitchen drawer", typing);
                let m = &f.m;
                let body = m.body();
                let hint = Rect::new(body.x, l.hint_y, body.w, SMALL_LINE);
                let mut rows = alloc::vec![("field", l.field), ("rule and budget", hint)];
                if typing {
                    rows.push(("keyboard", l.kb));
                } else {
                    rows.push(("explanation", l.say));
                    rows.push(("save", l.save));
                }
                rows_are_clear_on(
                    m,
                    &format!("{w}x{h} typing={typing}"),
                    Rect::new(0, m.bar, m.w, m.h - m.bar),
                    &rows,
                );
            }
        }
    }

    /// The rule under the field fits the row it is drawn on, at both geometries.
    ///
    /// It is drawn from the left with no wrap and no clip, so a rule that outgrew its row
    /// would run off the panel edge - which is what the pixel gate catches - or, as the
    /// first draft of this screen did, straight through whatever else shares the line.
    #[test]
    fn the_rule_under_the_field_fits_its_row() {
        for (w, h) in GEOMETRIES {
            let (f, _, l) = laid_out(w, h, "", false);
            let body = f.m.body();
            fits(
                &format!("{w}x{h}"),
                NAME_RULE,
                MONO_SMALL.text_width(NAME_RULE) as i32,
                Rect::new(body.x, l.hint_y, body.w, SMALL_LINE),
            );
        }
    }

    /// The keyboard gets the height it needs, in the phase that has one.
    ///
    /// `keyboard` is bottom-anchored and will happily draw ABOVE the rectangle it is
    /// given when that rectangle is shorter than four rows at their floor, straight over
    /// the field this screen is typing into.
    #[test]
    fn the_keyboard_phase_leaves_the_keyboard_room() {
        for (w, h) in GEOMETRIES {
            let (_, _, l) = laid_out(w, h, "", true);
            assert!(
                l.kb.h >= crate::components::keyboard_min_h(),
                "{w}x{h}: {} px of keyboard room, {} needed",
                l.kb.h,
                crate::components::keyboard_min_h()
            );
        }
    }

    /// Everything the non-typing phase can SAY fits the block it is drawn in, at both
    /// geometries: the two explaining sentences, and the longest refusal.
    ///
    /// The block is what is left between the hint and the Save button, so a copy edit that
    /// overran would be clipped by the `clipped` target in `draw` - which is to say it
    /// would vanish, silently, on the one screen whose job is to explain itself.
    #[test]
    fn everything_this_screen_says_fits_the_block_it_says_it_in() {
        for (w, h) in GEOMETRIES {
            let (f, _, l) = laid_out(w, h, "", false);
            let g = f.m.gap;
            for block in [
                EXPLAIN.to_vec(),
                alloc::vec![REFUSE_CHARS],
                alloc::vec![REFUSE_PIN],
                alloc::vec![REFUSE_SEED_WORD],
                alloc::vec![REFUSE_LONG],
                alloc::vec![SAVE_FAILED],
            ] {
                let lines: i32 =
                    block.iter().map(|p| wrap_words(p, l.say.w, BODY).len() as i32).sum();
                let need = lines * LINE + (block.len() as i32 - 1) * g;
                assert!(
                    need <= l.say.h,
                    "{w}x{h}: a block needs {need} px in a {} px space: {block:?}",
                    l.say.h
                );
            }
        }
    }

    /// The four refusals, each on the input class it exists for, and an acceptance beside
    /// each so the rule cannot pass by refusing everything.
    #[test]
    fn a_name_that_is_not_one_is_refused() {
        assert_eq!(name_refusal(""), None, "an unnamed device is legal");
        assert_eq!(name_refusal("  "), None, "whitespace is an unnamed device");
        assert_eq!(name_refusal("kitchen drawer"), None);
        assert_eq!(name_refusal("desk-2"), None, "digits in a name are fine");

        assert_eq!(name_refusal("captain\u{e9}"), Some(REFUSE_CHARS), "non-ASCII has no glyph");
        assert_eq!(name_refusal("box!"), Some(REFUSE_CHARS));

        assert_eq!(name_refusal("1234"), Some(REFUSE_PIN));
        assert_eq!(name_refusal(" 830125 "), Some(REFUSE_PIN), "trimmed before it is judged");

        assert_eq!(name_refusal("abandon"), Some(REFUSE_SEED_WORD));
        assert_eq!(name_refusal("ABANDON"), Some(REFUSE_SEED_WORD), "case is not a defence");
        assert_eq!(name_refusal("abandons"), None, "a word that is merely near one is fine");
        assert_eq!(
            name_refusal("the abandon"),
            None,
            "a multi-word name is not a phrase, and refusing it would read as arbitrary"
        );
    }

    /// The width rule is measured against the narrowest shipped panel, and it BITES.
    ///
    /// Both halves matter. A limit no string can reach is not a limit, and a limit derived
    /// from the panel in front of the user would let a name typed on the widest board be
    /// cropped on the narrowest.
    #[test]
    fn a_name_too_wide_for_the_narrowest_panel_is_refused() {
        let mut name = String::new();
        while name_refusal(&name).is_none() {
            name.push('W');
            assert!(name.len() < 400, "the width rule never refuses anything");
        }
        assert_eq!(name_refusal(&name), Some(REFUSE_LONG));
        assert!(
            quoted_width(&name) > name_row_w(),
            "the refusal fired for a reason other than width"
        );
        // One character shorter is accepted, so the boundary is where it is claimed to be.
        name.pop();
        assert_eq!(name_refusal(&name), None);
        // ...and the narrowest panel is the one being measured against, not this one.
        let narrowest = PANELS
            .into_iter()
            .map(|(w, h)| Metrics::new(w, h).content().w)
            .min()
            .expect("PANELS is not empty");
        assert_eq!(name_row_w(), narrowest);
    }

    /// Nothing this screen says claims the name proves which device this is.
    ///
    /// The same rule S-03 holds, checked here too because this is where the user decides
    /// what the name is FOR. The one place "device words" may appear is the sentence that
    /// hands the claim to them, which is why it is checked to be present rather than
    /// merely permitted.
    #[test]
    fn no_line_on_this_screen_promises_the_name_detects_a_swap() {
        let copy: Vec<&str> = alloc::vec![
            NAME_RULE,
            PLACEHOLDER,
            SAVE_LABEL,
            SAVE_FAILED,
            REFUSE_CHARS,
            REFUSE_PIN,
            REFUSE_SEED_WORD,
            REFUSE_LONG,
            EXPLAIN[0],
            EXPLAIN[1],
        ];
        for line in &copy {
            let l = line.to_lowercase();
            for banned in ["fake", "counterfeit", "genuine", "authentic", "secure", "protect"] {
                assert!(
                    !l.contains(banned),
                    "S-44a claims something the name cannot deliver ({banned:?}): {line:?}"
                );
            }
        }
        assert!(
            EXPLAIN.iter().any(|s| s.contains("device words")),
            "the anti-swap claim is not handed to the mechanism that can keep it"
        );
    }

    /// Save commits the TRIMMED name, and refuses while the panel says it would.
    #[test]
    fn save_commits_the_trimmed_name_and_refuses_what_the_panel_refuses() {
        let f = Fixture::new(800, 480);
        let mut net = notyas_core::bitcoin::Network::Bitcoin;
        let mut env =
            Env {
            network: &mut net,
            lock: &f.lock,
            wallets: &f.wallets,
            gate: &mut UnlockGate::default(),
        };

        let mut s = DeviceNameState::new("  kitchen drawer  ");
        let out = s.activate(RegionId::DeviceNameSave, &mut env);
        match out.request {
            Some(UiRequest::SetDeviceName(name)) => assert_eq!(name, "kitchen drawer"),
            other => panic!("Save raised {other:?}"),
        }

        let mut s = DeviceNameState::new("1234");
        let out = s.activate(RegionId::DeviceNameSave, &mut env);
        assert!(out.request.is_none(), "a refused name was committed anyway");
    }
}
