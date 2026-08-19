// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! S-01 Home: the three things a stateless device can start, and the two device-wide
//! settings that outlive a flow.
//!
//! Holds no state of its own and therefore no secrets: everything the screen shows is
//! either a constant, the store status the embedder installed, or the network toggle,
//! which lives on the `Ui` because the choice has to survive the screen changes of a
//! whole derivation.

use alloc::vec::Vec;

use embedded_graphics::draw_target::DrawTarget;
use embedded_graphics::pixelcolor::Rgb565;

use crate::canvas::{button, text_centered, toggle, ButtonKind, BODY, TITLE};
use crate::components::LINE;
use crate::layout::{Metrics, Rect};
use crate::screens::dice::DiceState;
use crate::screens::phrase::PhraseState;
use crate::screens::verify::VerifyState;
use crate::screens::{Ctx, Env, Outcome, Screen, State};
use crate::theme::*;
use crate::{Region, RegionId, StoreStatus, UiRequest, VERSION};
use notyas_core::bitcoin::Network;

/// The home screen has nothing to remember.
pub(crate) struct HomeState;

pub(crate) struct Layout {
    /// New seed, Verify existing seed, Verify device - in that order.
    buttons: [Rect; 3],
    /// The mainnet/testnet toggle, top-right so it reads as a device setting rather than
    /// a step of the flow. Compact on purpose: it clears the centered title on both
    /// shipped geometries (asserted by the region-overlap tests).
    net: Rect,
    /// The Lock affordance, top-left so it never lands under the finger reaching for the
    /// network toggle on the opposite corner.
    lock_chip: Rect,
}

impl Screen for HomeState {
    type Layout = Layout;

    fn layout(&self, ctx: &Ctx) -> Layout {
        let m = &ctx.m;
        let c = m.content();
        let w = c.w * 3 / 4;
        let x = c.x + (c.w - w) / 2;
        let total = 3 * m.btn + 2 * m.gap;
        let y = m.h - m.pad - total;
        let net_w = 260.min(m.w / 2);
        let chip_w = 200.min(m.w / 3);
        Layout {
            buttons: [
                Rect::new(x, y, w, m.btn),
                Rect::new(x, y + m.btn + m.gap, w, m.btn),
                Rect::new(x, y + 2 * (m.btn + m.gap), w, m.btn),
            ],
            net: Rect::new(m.w - m.pad - net_w, m.pad, net_w, 48),
            lock_chip: Rect::new(m.pad, m.pad, chip_w, 48),
        }
    }

    fn regions(&self, ctx: &Ctx, out: &mut Vec<Region>) {
        let l = self.layout(ctx);
        out.push(Region { id: RegionId::HomeNewSeed, rect: l.buttons[0] });
        out.push(Region { id: RegionId::HomeVerifySeed, rect: l.buttons[1] });
        out.push(Region { id: RegionId::HomeVerifyDevice, rect: l.buttons[2] });
        out.push(Region { id: RegionId::NetToggle, rect: l.net });
        // The Lock affordance exists exactly while there is a session to drop. Settings
        // is NOT offered here: on a device with a PIN the wallet list is the home an
        // unlock lands on and never leaves, so a Settings chip on this screen would be a
        // button no finger could reach. It lives on S-10 instead, which is where
        // UX-SCREENS puts it.
        if ctx.lock.status == StoreStatus::Unlocked {
            out.push(Region { id: RegionId::Lock, rect: l.lock_chip });
        }
    }

    fn draw<D: DrawTarget<Color = Rgb565>>(&self, t: &mut D, ctx: &Ctx) -> Result<(), D::Error> {
        let m: &Metrics = &ctx.m;
        let l = self.layout(ctx);
        if ctx.lock.status == StoreStatus::Unlocked {
            button(t, l.lock_chip, "Lock", ButtonKind::Secondary, PAPER_1)?;
        }
        let title_y = m.h / 7;
        text_centered(
            t,
            "notyas",
            Rect::new(0, title_y, m.w, TITLE.line_height as i32),
            TITLE,
            INK_PRIMARY,
            PAPER_1,
        )?;
        text_centered(
            t,
            &format!("version {VERSION}"),
            Rect::new(0, title_y + TITLE.line_height as i32 + m.gap, m.w, LINE),
            BODY,
            INK_SECONDARY,
            PAPER_1,
        )?;
        // Desktop parity: the network is a pipeline input. Everything derived downstream
        // (addresses, xpub prefixes, the schemes info line) reflects the choice.
        let mainnet = ctx.network == Network::Bitcoin;
        toggle(t, l.net, ["Mainnet", "Testnet"], usize::from(!mainnet))?;
        let [b0, b1, b2] = l.buttons;
        button(t, b0, "New seed (dice)", ButtonKind::Primary, PAPER_1)?;
        button(t, b1, "Verify existing seed", ButtonKind::Secondary, PAPER_1)?;
        button(t, b2, "Verify device", ButtonKind::Secondary, PAPER_1)?;
        Ok(())
    }

    fn activate(&mut self, id: RegionId, env: &mut Env) -> Outcome {
        match id {
            RegionId::NetToggle => {
                *env.network = match *env.network {
                    Network::Bitcoin => Network::Testnet,
                    _ => Network::Bitcoin,
                };
                Outcome::stay()
            }
            // The three flows start FROM home, so none of them remembers it: Back from
            // any of them lands on an empty stack, which is Home.
            RegionId::HomeNewSeed => Outcome::enter(State::Dice(DiceState::new())),
            RegionId::HomeVerifySeed => Outcome::enter(State::Phrase(PhraseState::new())),
            RegionId::HomeVerifyDevice => Outcome::enter(State::Verify(VerifyState::new())),
            // The Lock affordance. The UI cannot drop the session - it does not own it -
            // so it asks, and the embedder answers by dropping it and calling `Ui::lock`.
            RegionId::Lock => Outcome::ask(UiRequest::LockSession),
            _ => Outcome::stay(),
        }
    }
}
