// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The delete-wallet ordering rule, over slots that can be made to fail on demand.
//!
//! What this covers that nothing else can: the ORDER (registrations before the record), the
//! read-back that decides whether a delete may be reported as done, and the three failure
//! shapes a screen has to render differently. On the device those run against an ESP-IDF
//! flash partition; here they run against `Slots` below, which is the same code path with a
//! `BTreeMap` where the flash is.

use std::collections::BTreeMap;
use std::fmt;

use notyas_firmware_hostcheck::erase::{self, Erased, Occupancy, WalletSlots};

/// What a fake slot store did, in the order it did it. The ORDER is the property under
/// test, so it is recorded rather than inferred from the end state.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Step {
    Closed(u8),
    Listed(u8),
    ErasedRegistration(u8),
    ErasedWallet(u8),
    ReadBack(u8),
}

#[derive(Debug)]
struct Fault(String);

impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A registry and a payload map, plus a switch for each way the store can refuse.
struct Slots {
    /// registry slot -> the payload slot its record names.
    registry: BTreeMap<u8, u8>,
    /// payload slot -> what it holds.
    payload: BTreeMap<u8, Occupancy>,
    /// The payload slot the session has open, if any.
    open: Option<u8>,
    log: Vec<Step>,

    fail_list: bool,
    /// Refuse to erase this registry slot.
    fail_registry: Option<u8>,
    fail_wallet: bool,
    /// Report this after the wallet erase instead of what the map says.
    lie_on_read_back: Option<Occupancy>,
    fail_read_back: bool,
}

impl Slots {
    /// One wallet in payload slot 3 with `registrations` registry records naming it, plus a
    /// second wallet in slot 5 with one of its own - so a test that erased too much has
    /// something to have erased.
    fn with(registrations: u8) -> Slots {
        let mut registry = BTreeMap::new();
        for i in 0..registrations {
            registry.insert(i, 3);
        }
        registry.insert(7, 5);
        Slots {
            registry,
            payload: BTreeMap::from([(3, Occupancy::Mine), (5, Occupancy::Mine)]),
            open: None,
            log: Vec::new(),
            fail_list: false,
            fail_registry: None,
            fail_wallet: false,
            lie_on_read_back: None,
            fail_read_back: false,
        }
    }

    fn registrations_left_for(&self, wallet: u8) -> usize {
        self.registry.values().filter(|s| **s == wallet).count()
    }
}

impl WalletSlots for Slots {
    type Error = Fault;

    fn registrations_of(&mut self, slot: u8) -> Result<Vec<u8>, Fault> {
        self.log.push(Step::Listed(slot));
        if self.fail_list {
            return Err(Fault(String::from("the registry did not read")));
        }
        Ok(self
            .registry
            .iter()
            .filter(|(_, w)| **w == slot)
            .map(|(r, _)| *r)
            .collect())
    }

    fn erase_registration(&mut self, registry_slot: u8) -> Result<(), Fault> {
        self.log.push(Step::ErasedRegistration(registry_slot));
        if self.fail_registry == Some(registry_slot) {
            return Err(Fault(String::from("that registry slot would not erase")));
        }
        self.registry.remove(&registry_slot);
        Ok(())
    }

    fn erase_wallet(&mut self, slot: u8) -> Result<(), Fault> {
        self.log.push(Step::ErasedWallet(slot));
        if self.fail_wallet {
            return Err(Fault(String::from("the wallet slot would not erase")));
        }
        self.payload.insert(slot, Occupancy::Free);
        Ok(())
    }

    fn occupancy(&mut self, slot: u8) -> Result<Occupancy, Fault> {
        self.log.push(Step::ReadBack(slot));
        if self.fail_read_back {
            return Err(Fault(String::from("the slot did not read")));
        }
        if let Some(lie) = self.lie_on_read_back {
            return Ok(lie);
        }
        Ok(self.payload.get(&slot).copied().unwrap_or(Occupancy::Free))
    }

    fn close_if_open(&mut self, slot: u8) {
        self.log.push(Step::Closed(slot));
        if self.open == Some(slot) {
            self.open = None;
        }
    }
}

/// The happy path, end to end: the wallet and its registrations are gone, the OTHER
/// wallet's registration is untouched, and the slot was read back before any of that was
/// claimed.
///
/// This is the test the shipped build could not pass. Against the previous firmware there
/// was no `erase` to call - the handler logged "this build has no erase path" and
/// re-installed the list - so this file did not compile, which is the strongest form of
/// failing first.
#[test]
fn a_delete_erases_the_registrations_then_the_record_and_checks_the_slot() {
    let mut slots = Slots::with(2);
    slots.open = Some(3);

    let out = erase::erase(&mut slots, 3, "savings");

    assert_eq!(out, Erased::Gone { registrations: 2 });
    assert_eq!(out.reason(), None, "a completed delete explains nothing");
    assert_eq!(slots.payload.get(&3), Some(&Occupancy::Free));
    assert_eq!(slots.registrations_left_for(3), 0);
    assert_eq!(slots.registrations_left_for(5), 1, "another wallet's registration survived");
    assert_eq!(slots.open, None, "the open wallet was dropped");

    // The order is the safety property. Closed first, then listed, then every registration,
    // then the record, then the read-back - and the record is erased AFTER the last
    // registration, never before.
    assert_eq!(
        slots.log,
        vec![
            Step::Closed(3),
            Step::Listed(3),
            Step::ErasedRegistration(0),
            Step::ErasedRegistration(1),
            Step::ErasedWallet(3),
            Step::ReadBack(3),
        ]
    );
}

/// A wallet nobody has open deletes exactly the same way. The close is still attempted, so
/// there is one code path and not two.
#[test]
fn a_wallet_that_is_not_open_deletes_the_same_way() {
    let mut slots = Slots::with(0);
    let out = erase::erase(&mut slots, 3, "cold");
    assert_eq!(out, Erased::Gone { registrations: 0 });
    assert_eq!(slots.log.first(), Some(&Step::Closed(3)));
}

/// The registry would not list. Nothing is erased at all - not even the payload record,
/// which is the orphan the ordering rule exists to prevent - and the sentence says so.
#[test]
fn a_registry_that_will_not_list_refuses_the_whole_delete() {
    let mut slots = Slots::with(2);
    slots.fail_list = true;

    let out = erase::erase(&mut slots, 3, "savings");

    assert!(matches!(out, Erased::Refused(_)), "{out:?}");
    let reason = out.reason().expect("a refusal states itself");
    assert!(reason.contains("was not deleted"), "{reason}");
    assert!(reason.contains("Nothing was erased"), "{reason}");
    assert_eq!(slots.payload.get(&3), Some(&Occupancy::Mine), "the wallet survived");
    assert!(
        !slots.log.contains(&Step::ErasedWallet(3)),
        "the record must not be erased when the registry could not be listed"
    );
}

/// The first registration refuses. Nothing was destroyed, so this is a refusal and not a
/// partial - and the wallet record is untouched.
#[test]
fn a_registration_that_refuses_first_leaves_the_device_unchanged() {
    let mut slots = Slots::with(2);
    slots.fail_registry = Some(0);

    let out = erase::erase(&mut slots, 3, "savings");

    assert!(matches!(out, Erased::Refused(_)), "{out:?}");
    assert!(out.reason().unwrap().contains("Nothing was erased"));
    assert_eq!(slots.registrations_left_for(3), 2);
    assert_eq!(slots.payload.get(&3), Some(&Occupancy::Mine));
}

/// The SECOND registration refuses. One is already gone, so the honest answer is `Partial`
/// and the sentence has to name both halves: what survived and what did not.
#[test]
fn a_registration_that_refuses_after_one_went_is_partial_and_says_which() {
    let mut slots = Slots::with(3);
    slots.fail_registry = Some(1);

    let out = erase::erase(&mut slots, 3, "savings");

    let Erased::Partial(reason) = &out else {
        panic!("expected a partial, got {out:?}");
    };
    assert!(reason.contains("was NOT deleted"), "{reason}");
    assert!(reason.contains("1 of its 3"), "{reason}");
    assert_eq!(slots.registrations_left_for(3), 2);
    assert_eq!(slots.payload.get(&3), Some(&Occupancy::Mine), "the words are still here");
}

/// The record itself refuses after its registrations went. Partial, and the sentence says
/// out loud that the recovery words are still on the device.
#[test]
fn a_record_that_refuses_after_its_registrations_went_says_the_words_are_still_here() {
    let mut slots = Slots::with(2);
    slots.fail_wallet = true;

    let out = erase::erase(&mut slots, 3, "savings");

    let Erased::Partial(reason) = &out else {
        panic!("expected a partial, got {out:?}");
    };
    assert!(reason.contains("recovery words are still on this device"), "{reason}");
    assert_eq!(slots.registrations_left_for(3), 0);
    assert_eq!(slots.payload.get(&3), Some(&Occupancy::Mine));
}

/// A wallet with no registrations whose record refuses. Nothing went, so it is a refusal.
#[test]
fn a_record_that_refuses_with_nothing_else_erased_is_a_refusal() {
    let mut slots = Slots::with(0);
    slots.fail_wallet = true;

    let out = erase::erase(&mut slots, 3, "cold");

    assert!(matches!(out, Erased::Refused(_)), "{out:?}");
    assert!(out.reason().unwrap().contains("Nothing was erased"));
}

/// Every write returned `Ok` and the slot still reads as holding a wallet. This is the exact
/// shape of the bug that produced this module - a delete that reports success it has not
/// earned - and the read-back is the only thing that can catch it.
#[test]
fn a_slot_that_still_reads_occupied_is_never_reported_as_deleted() {
    for (lie, expect) in [(Occupancy::Mine, "still reads as holding a wallet"),
                          (Occupancy::Opaque, "still holds a record it cannot open")] {
        let mut slots = Slots::with(1);
        slots.lie_on_read_back = Some(lie);

        let out = erase::erase(&mut slots, 3, "savings");

        let Erased::NotGone(reason) = &out else {
            panic!("expected NotGone for {lie:?}, got {out:?}");
        };
        assert!(out.reason().is_some(), "a slot that still reads occupied is not gone");
        assert!(reason.contains(expect), "{reason}");
        assert!(
            reason.contains("Do not treat those recovery words as destroyed"),
            "{reason}"
        );
    }
}

/// The read-back itself fails. The device cannot say the words are gone, so it does not.
#[test]
fn a_read_back_that_fails_is_not_a_completed_delete() {
    let mut slots = Slots::with(0);
    slots.fail_read_back = true;

    let out = erase::erase(&mut slots, 3, "cold");

    assert!(matches!(out, Erased::NotGone(_)), "{out:?}");
    assert!(out.reason().unwrap().contains("cannot say the words are gone"));
}

/// Every outcome that is not `Gone` carries a sentence, and `Gone` carries none. This is
/// firmware/src/main.rs's "every failure reaches the user" made mechanical at the layer that
/// produces the failures: there is no variant a screen could receive with nothing to render.
#[test]
fn every_outcome_that_is_not_gone_has_something_to_say() {
    let mut cases: Vec<Erased> = Vec::new();
    for build in [
        (true, None, false, None, false),
        (false, Some(0), false, None, false),
        (false, Some(1), false, None, false),
        (false, None, true, None, false),
        (false, None, false, Some(Occupancy::Mine), false),
        (false, None, false, None, true),
        (false, None, false, None, false),
    ] {
        let mut slots = Slots::with(3);
        slots.fail_list = build.0;
        slots.fail_registry = build.1;
        slots.fail_wallet = build.2;
        slots.lie_on_read_back = build.3;
        slots.fail_read_back = build.4;
        cases.push(erase::erase(&mut slots, 3, "savings"));
    }
    assert!(
        cases.iter().any(|c| c.reason().is_none()),
        "the table must include the success or it proves nothing about the rest"
    );
    for case in &cases {
        match case {
            Erased::Gone { .. } => assert!(case.reason().is_none()),
            other => {
                let reason = other.reason().expect("a failure the user can read");
                assert!(reason.len() > 40, "too terse to act on: {reason}");
                assert!(reason.contains("savings"), "a failure names the wallet: {reason}");
                assert!(reason.is_ascii(), "ASCII only: {reason}");
            }
        }
    }
}
