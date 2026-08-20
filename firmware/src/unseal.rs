// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Which unseal outcome an unlock refusal is.
//!
//! One judgement, and it is the one the PIN screen cannot make for itself: whether a
//! refusal means the owner guessed wrong, or means the device never got as far as a
//! guess. The engine already holds that distinction and marks it in its own type - every
//! [`UnlockError`] variant is documented "AN ATTEMPT WAS CONSUMED" or "NO ATTEMPT
//! CONSUMED" - so the whole job here is to carry it into [`UnsealOutcome`] intact.
//!
//! The thing this module exists to prevent is re-deriving the answer from a state query.
//! A store that refused for a hardware fault and a store that refused because the PIN was
//! wrong are BOTH still `Formatted` afterwards, so `state()` cannot tell them apart, and
//! a caller that asks it ends up telling a user with the right PIN that their PIN is
//! wrong - and rendering structural evidence of interference as an ordinary miscount.
//!
//! Pure by construction: no store, no ESP-IDF, no allocation. That is what lets
//! `firmware/hostcheck` compile this exact file and test every variant of it.

use notyas_ui::UnsealOutcome;
use notyas_wallet::UnlockError;

/// The UI outcome for a refusal from the sealing engine's unlock.
///
/// Exhaustive on purpose, with no wildcard arm: a new `UnlockError` variant must stop the
/// build here and be classified by a person. Either default a wildcard could pick is
/// wrong for half of what could be added, and the cost of picking wrong is silent - the
/// device just shows the wrong screen forever.
pub fn refusal_outcome<FE, ME>(e: &UnlockError<FE, ME>) -> UnsealOutcome {
    match e {
        // The two refusals that ARE a guess, and the only two that spend the attempt
        // budget. `attempts_remaining` is the engine's own count, taken after the attempt
        // was charged; nothing else on the device knows it as precisely.
        UnlockError::WrongPin { attempts_remaining } => UnsealOutcome::WrongPin {
            attempts_left: *attempts_remaining,
        },
        UnlockError::Wiped { .. } => UnsealOutcome::Wiped,

        // Everything below is the device failing to try, so none of it is the owner's
        // fault and none of it may be shown as a miscount (R-32: the store could not be
        // read, so no PIN typed into it can succeed).
        //
        // `Corrupt` and `Tamper` are the reason this matters beyond politeness. They are
        // the engine's fail-closed verdicts on structural evidence of interference, they
        // consume no attempt, and a "wrong PIN, N attempts left" screen would bury them
        // behind the one message an owner is trained to shrug off and retype through.
        //
        // `Hardware` is here even though it may have consumed an attempt: it is still
        // never a statement about the PIN, which is what the wrong-PIN screen asserts.
        UnlockError::Corrupt { .. }
        | UnlockError::Tamper(_)
        | UnlockError::NotFormatted
        | UnlockError::Locked
        | UnlockError::Scratch { .. }
        | UnlockError::Provenance(_)
        | UnlockError::Hardware { .. }
        | UnlockError::Invariant(_) => UnsealOutcome::Unreadable,
    }
}
