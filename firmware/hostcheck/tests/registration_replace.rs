// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Cover for `firmware/src/flow/replace.rs`: replacing a registry record must never leave
//! the device holding neither the old registration nor the new one.
//!
//! The defect this suite exists for shipped as a straight line: deregister the duplicate,
//! then register the replacement, with no rollback between them. Every failure of the
//! second call therefore consumed the first: the wallet lost a registration it still had a
//! perfectly good record for, and got nothing in return. For a multisig wallet that is the
//! difference between one the device can sign for and one it cannot, and no test could see
//! it - the ordering lived inside a function that takes an ESP-IDF flash partition.
//!
//! So the ordering was lifted behind `RegistrySlots`, and this drives it against a registry
//! whose four operations can each be told to fail. The assertion that matters is not the
//! outcome variant: it is what `Fake::slots` holds afterwards.

use std::collections::BTreeMap;

use notyas_firmware_hostcheck::replace::{replace_in_slot, RegistrySlots, Replaced};

/// Which operation, if any, is rigged to fail on its next call.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Fail {
    Nothing,
    Snapshot,
    Erase,
    Install,
    /// The double failure: the write fails AND the record cannot be put back.
    InstallAndRestore,
}

/// A registry of byte blobs in slots, plus a rigged failure and a call log.
struct Fake {
    slots: BTreeMap<u8, Vec<u8>>,
    fail: Fail,
    /// Where `install` writes when it succeeds: the lowest free slot, as the store does.
    installed: Vec<u8>,
    calls: Vec<&'static str>,
}

impl Fake {
    /// One occupied slot, holding the record a replacement is aimed at.
    fn with_record(slot: u8, record: &[u8], fail: Fail) -> Fake {
        let mut slots = BTreeMap::new();
        slots.insert(slot, record.to_vec());
        Fake { slots, fail, installed: b"the replacement".to_vec(), calls: Vec::new() }
    }

    fn free_slot(&self) -> u8 {
        (0u8..8).find(|s| !self.slots.contains_key(s)).expect("a free slot")
    }
}

impl RegistrySlots for Fake {
    type Id = u8;
    type Error = String;

    fn snapshot(&mut self, slot: u8) -> Result<Vec<u8>, String> {
        self.calls.push("snapshot");
        if self.fail == Fail::Snapshot {
            return Err(String::from("the store refused the read"));
        }
        self.slots.get(&slot).cloned().ok_or_else(|| format!("no record in slot {slot}"))
    }

    fn erase(&mut self, slot: u8) -> Result<(), String> {
        self.calls.push("erase");
        if self.fail == Fail::Erase {
            return Err(String::from("the store refused the erase"));
        }
        self.slots.remove(&slot);
        Ok(())
    }

    fn install(&mut self) -> Result<u8, String> {
        self.calls.push("install");
        if matches!(self.fail, Fail::Install | Fail::InstallAndRestore) {
            return Err(String::from("the store refused the write"));
        }
        let slot = self.free_slot();
        let body = self.installed.clone();
        self.slots.insert(slot, body);
        Ok(slot)
    }

    fn restore(&mut self, slot: u8, bytes: &[u8]) -> Result<(), String> {
        self.calls.push("restore");
        if self.fail == Fail::InstallAndRestore {
            return Err(String::from("the store refused the restore"));
        }
        self.slots.insert(slot, bytes.to_vec());
        Ok(())
    }
}

const OLD: &[u8] = b"the registration that is already there";

#[test]
fn a_replacement_that_writes_leaves_only_the_replacement() {
    let mut reg = Fake::with_record(3, OLD, Fail::Nothing);
    let outcome = replace_in_slot(&mut reg, 3);

    assert!(matches!(outcome, Replaced::Done(_)), "{outcome:?}");
    assert_eq!(reg.calls, ["snapshot", "erase", "install"]);
    // The old record is gone and exactly one record is held: the new one.
    assert_eq!(reg.slots.len(), 1);
    assert_eq!(reg.slots.values().next().map(Vec::as_slice), Some(&b"the replacement"[..]));
}

#[test]
fn a_write_that_fails_puts_the_old_record_back() {
    // THE REGRESSION. Before the rollback existed this left slot 3 empty and the
    // replacement unwritten: one failed store call, two registrations gone.
    let mut reg = Fake::with_record(3, OLD, Fail::Install);
    let outcome = replace_in_slot(&mut reg, 3);

    match outcome {
        Replaced::RolledBack { slot, ref cause } => {
            assert_eq!(slot, 3);
            assert!(cause.contains("refused the write"), "{cause}");
        }
        other => panic!("expected RolledBack, got {other:?}"),
    }
    assert_eq!(reg.calls, ["snapshot", "erase", "install", "restore"]);
    // What the device holds is what it held before the tap.
    assert_eq!(reg.slots.len(), 1);
    assert_eq!(reg.slots.get(&3).map(Vec::as_slice), Some(OLD));
}

#[test]
fn a_rollback_that_also_fails_is_reported_as_a_loss_and_not_as_a_write_failure() {
    let mut reg = Fake::with_record(3, OLD, Fail::InstallAndRestore);
    let outcome = replace_in_slot(&mut reg, 3);

    match outcome {
        Replaced::Lost { slot, ref cause, ref restore } => {
            assert_eq!(slot, 3);
            assert!(cause.contains("refused the write"), "{cause}");
            assert!(restore.contains("refused the restore"), "{restore}");
        }
        other => panic!("expected Lost, got {other:?}"),
    }
    // The one path on which something really is gone. The variant is what makes the screen
    // say "import it again" instead of "that did not save".
    assert!(reg.slots.is_empty());
    assert_eq!(reg.calls, ["snapshot", "erase", "install", "restore"]);
}

#[test]
fn a_record_that_cannot_be_read_is_never_erased() {
    // The rule that makes every other outcome recoverable: nothing is erased that this
    // code has no copy of.
    let mut reg = Fake::with_record(3, OLD, Fail::Snapshot);
    let outcome = replace_in_slot(&mut reg, 3);

    assert!(matches!(outcome, Replaced::Untouched(_)), "{outcome:?}");
    assert_eq!(reg.calls, ["snapshot"], "erase must not have been attempted");
    assert_eq!(reg.slots.get(&3).map(Vec::as_slice), Some(OLD));
}

#[test]
fn an_erase_that_fails_leaves_the_device_exactly_as_it_was() {
    let mut reg = Fake::with_record(3, OLD, Fail::Erase);
    let outcome = replace_in_slot(&mut reg, 3);

    assert!(matches!(outcome, Replaced::Untouched(_)), "{outcome:?}");
    assert_eq!(reg.calls, ["snapshot", "erase"], "install must not have been attempted");
    assert_eq!(reg.slots.get(&3).map(Vec::as_slice), Some(OLD));
}

#[test]
fn a_missing_record_is_refused_before_anything_is_touched() {
    // A slot the screen named that the registry does not hold. The screen's list is older
    // than the registry; erasing whatever is there now would destroy an unrelated record.
    let mut reg = Fake::with_record(3, OLD, Fail::Nothing);
    let outcome = replace_in_slot(&mut reg, 5);

    assert!(matches!(outcome, Replaced::Untouched(_)), "{outcome:?}");
    assert_eq!(reg.calls, ["snapshot"]);
    assert_eq!(reg.slots.get(&3).map(Vec::as_slice), Some(OLD));
}
