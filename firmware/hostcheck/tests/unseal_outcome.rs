// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! `firmware/src/unseal.rs` under test, on the host, as the device links it.
//!
//! One property, stated two ways because it is wrong in two different directions:
//!
//! 1. **An owner with the right PIN is never told it is wrong.** Every refusal that is not
//!    a guess - no Argon2id working set, a MAC fault, an unformatted store - would leave a
//!    correct PIN rejected on screen, with a wipe threshold counting down beside it, if it
//!    were classified as a miscount.
//! 2. **Tamper and corruption reach the owner.** They are the engine's fail-closed verdicts
//!    on structural evidence of interference and they consume no attempt. Rendered as
//!    "wrong PIN", they are buried behind the one message a user is trained to retype
//!    through, and the device's whole tamper indication never arrives.
//!
//! The screen has a state for both (`UnsealOutcome::Unreadable`, R-32). This is the test
//! that the classification actually reaches it.

use notyas_firmware_hostcheck::unseal::refusal_outcome;
use notyas_ui::UnsealOutcome;
use notyas_wallet::{Corruption, HardwareFault, KeyProvenance, SlotId, TamperKind, UnlockError};

/// The concrete flash and MAC error types do not matter to a classification that never
/// looks inside `Hardware`; the unit keeps the test about the variants.
type Error = UnlockError<(), ()>;

#[test]
fn a_wrong_guess_is_the_only_thing_shown_as_a_wrong_pin() {
    assert_eq!(
        refusal_outcome::<(), ()>(&Error::WrongPin {
            attempts_remaining: Some(4)
        }),
        UnsealOutcome::WrongPin {
            attempts_left: Some(4)
        },
    );
    // The engine's own count is carried through, including "the wipe policy is off".
    assert_eq!(
        refusal_outcome::<(), ()>(&Error::WrongPin {
            attempts_remaining: None
        }),
        UnsealOutcome::WrongPin { attempts_left: None },
    );
}

#[test]
fn the_last_attempt_is_the_wipe_screen() {
    assert_eq!(
        refusal_outcome::<(), ()>(&Error::Wiped { epoch: 7 }),
        UnsealOutcome::Wiped,
    );
}

/// The headline defect: a store that could not be read must never accuse the owner.
#[test]
fn nothing_that_is_not_a_guess_is_shown_as_a_wrong_pin() {
    let not_guesses: [Error; 8] = [
        UnlockError::Corrupt {
            slot: SlotId::superblock(),
            detail: Corruption::HeaderMac,
        },
        UnlockError::Tamper(TamperKind::LedgerRollback),
        UnlockError::NotFormatted,
        UnlockError::Locked,
        UnlockError::Scratch {
            required_blocks: 16,
        },
        UnlockError::Provenance(KeyProvenance::Emulated),
        UnlockError::Hardware {
            source: HardwareFault::Mac(()),
            attempt_consumed: false,
        },
        UnlockError::Hardware {
            source: HardwareFault::DerivationMismatch,
            attempt_consumed: true,
        },
    ];
    for e in &not_guesses {
        let got = refusal_outcome(e);
        assert_eq!(
            got,
            UnsealOutcome::Unreadable,
            "{e:?} must be reported as an unreadable store, not as a PIN the owner typed wrong",
        );
        assert!(
            !matches!(got, UnsealOutcome::WrongPin { .. }),
            "{e:?} consumed no guess and must never render the miscount screen",
        );
    }
}

/// Tamper and corruption specifically, spelled out apart from the loop: these two are
/// evidence, and burying evidence under a routine message is the failure that matters most.
#[test]
fn interference_is_never_disguised_as_a_miscount() {
    for kind in [
        TamperKind::LedgerMissing,
        TamperKind::LedgerAmbiguous,
        TamperKind::LedgerRollback,
        TamperKind::GuardMismatch,
        TamperKind::LogHole,
        TamperKind::ForeignDevice,
    ] {
        assert_eq!(
            refusal_outcome::<(), ()>(&UnlockError::Tamper(kind)),
            UnsealOutcome::Unreadable,
            "tamper {kind:?} was hidden behind a wrong-PIN screen",
        );
    }
    for detail in [
        Corruption::HeaderMac,
        Corruption::BodyDigest,
        Corruption::Tag,
        Corruption::Padding,
        Corruption::LengthPrefix,
        Corruption::EpochStale,
    ] {
        assert_eq!(
            refusal_outcome::<(), ()>(&UnlockError::Corrupt {
                slot: SlotId::superblock(),
                detail,
            }),
            UnsealOutcome::Unreadable,
            "corruption {detail:?} was hidden behind a wrong-PIN screen",
        );
    }
}
