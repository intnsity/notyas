// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The deriving interstitial, and the seed material it runs on.
//!
//! This screen exists for one reason: the derivation blocks for seconds on this silicon,
//! and the frame that says so has to reach the panel BEFORE it starts. So the passphrase
//! screen PARKS its seed material here and returns; `Ui::tick` calls [`DerivingState::run`]
//! after the frame is published. The material lives in this state rather than being read
//! back off the screen behind it, which is what makes the blocking work a pure function of
//! the state and not of anything the user touched in between.

use alloc::string::String;
use alloc::vec::Vec;

use embedded_graphics::draw_target::DrawTarget;
use embedded_graphics::pixelcolor::Rgb565;
use zeroize::Zeroizing;

use crate::canvas::{panel, text_centered, BODY, HEADING};
use crate::components::{draw_bar_no_back, LINE};
use crate::layout::Rect;
use crate::screens::fork::ForkState;
use crate::screens::quiz::QuizState;
use crate::screens::{Ctx, Env, Outcome, Screen, State};
use crate::theme::*;
use crate::{BackupState, Region, RegionId, ADDRESS_ROWS};
use notyas_core::bip39::MnemonicMode;
use notyas_core::bitcoin::Network;
use notyas_core::derive::{ChildIndex, Scheme};
use notyas_core::entropy::DiceEntropy;
use notyas_core::report::{Parameters, Report};

/// Where the seed material came from. Both variants wipe on drop, which is what the
/// drop-equals-zeroize check in the parent module asserts variant by variant.
pub(crate) enum SeedSource {
    Dice { dice: DiceEntropy, mode: MnemonicMode },
    Phrase(Zeroizing<String>),
}

impl SeedSource {
    /// A self-wiping copy, for handing the seed material forward while the screen that
    /// holds it keeps its own (Back must restore that screen intact). Not a `Clone` impl
    /// on purpose: duplicating secret material is a decision each call site should have
    /// to write out.
    pub fn duplicate(&self) -> SeedSource {
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
pub(crate) struct DerivingState {
    pub source: SeedSource,
    /// Empty when the user did not opt in, which is exactly what the pipeline wants.
    pub passphrase: Zeroizing<String>,
}

impl DerivingState {
    /// Run the whole pipeline: the seed stretch and every scheme. Seconds of PBKDF2 on
    /// this silicon, which is why it is called from `Ui::tick` and never from a touch.
    ///
    /// Returns the screen the finished wallet lands on, which is where the create and the
    /// restore paths part company (S-16's two exits):
    ///
    /// - **Dice.** The words were produced by this device and exist nowhere else yet, so
    ///   the mandatory backup check stands between them and a usable wallet
    ///   (commandment 3: no backup exists until it is verified).
    /// - **Typed words.** The backup is what the user just read out of and typed in;
    ///   quizzing them on words they copied thirty seconds ago proves nothing it did not
    ///   already prove, and it is the same evidence a Trezor-style dry run accepts. The
    ///   path goes straight to the fork with the backup marked verified.
    ///
    /// Both paths reach the fork, so neither can store a wallet whose backup was never
    /// demonstrated - which is what MILESTONES asks of both flows. UX-SCREENS S-17 owns
    /// the screen and places the quiz on the create path; that is the reading followed
    /// here (MILESTONES 1.1: the companion wins on WHAT is built inside its subject).
    ///
    /// `None` means the core refused input both entry paths validated before they got
    /// here, which is a core bug rather than a user error; the caller falls back to the
    /// screen the user came from rather than wedging on an interstitial.
    pub fn run(&self, network: Network) -> Option<State> {
        let params = Parameters {
            mode: self.source.mode(),
            passphrase: &self.passphrase,
            network,
            schemes: &Scheme::ALL,
            account: ChildIndex::ZERO,
            change: ChildIndex::ZERO,
            count: ADDRESS_ROWS,
            script_type: 2,
        };
        match &self.source {
            SeedSource::Dice { dice, .. } => Report::build(dice, &params)
                .ok()
                .map(|r| State::Quiz(QuizState::new(r))),
            SeedSource::Phrase(text) => Report::from_phrase(text, &params).map(|r| {
                State::Fork(ForkState::new(r, BackupState::Verified(String::new())))
            }),
        }
    }
}

impl Screen for DerivingState {
    /// The card the message sits in.
    type Layout = Rect;

    fn layout(&self, ctx: &Ctx) -> Rect {
        let m = &ctx.m;
        let body = m.body();
        let card_h = 3 * LINE + 4 * m.gap;
        Rect::new(body.x, body.y + (body.h - card_h) / 2, body.w, card_h)
    }

    /// Deliberately empty: the derivation is synchronous and cannot be cancelled, so the
    /// interstitial offers nothing to tap - not even Back, which would be a button that
    /// lies.
    fn regions(&self, _ctx: &Ctx, _out: &mut Vec<Region>) {}

    /// The frame that must be on the panel before `run` starts. Everything here is
    /// static: a screen that promises a spinner it cannot animate (the panel repaints on
    /// input only) would be a worse lie than a still one, so this says what is happening,
    /// how long it takes, and what not to do meanwhile.
    fn draw<D: DrawTarget<Color = Rgb565>>(&self, t: &mut D, ctx: &Ctx) -> Result<(), D::Error> {
        let m = &ctx.m;
        draw_bar_no_back(t, m, "Deriving")?;
        let card = self.layout(ctx);
        panel(t, card, PAPER_2, BORDER_STRONG)?;
        let mut y = card.y + m.gap;
        text_centered(
            t,
            "Deriving keys...",
            Rect::new(card.x, y, card.w, LINE),
            HEADING,
            INK_PRIMARY,
            PAPER_2,
        )?;
        y += LINE + m.gap;
        for line in [
            "2048 rounds of PBKDF2, then every scheme.",
            "This takes a few seconds. Do not power off.",
        ] {
            let row = Rect::new(card.x, y, card.w, LINE);
            text_centered(t, line, row, BODY, INK_SECONDARY, PAPER_2)?;
            y += LINE;
        }
        Ok(())
    }

    fn activate(&mut self, _id: RegionId, _env: &mut Env) -> Outcome {
        Outcome::stay()
    }
}
