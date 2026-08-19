// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! SECURITY invariant 2a, checked against the FLASH rather than against a return value.
//!
//! `record_boot` is documented as refusing on any state but `Formatted`. A refusal that
//! happens AFTER a sector erase still leaves the device non-stateless, so every case here
//! asserts `erase_count() == 0 && program_count() == 0` on the way out, not just `Err`.

use notyas_wallet::fuzz::{fuzz_config, geometry_for};
use notyas_wallet::sim::{SimFlash, SoftMac, VecScratch};
use notyas_wallet::{
    Config, KeyProvenance, Pin, StorageError, StoreState, Vault,
};

type V = Vault<SimFlash, SoftMac>;

fn scratch(cfg: &Config) -> VecScratch {
    VecScratch::for_params(&cfg.kdf)
}

fn unprovisioned(cfg: &Config) -> V {
    let flash = SimFlash::new(geometry_for(&cfg.layout));
    let mac = SoftMac::new().with_provenance(KeyProvenance::Absent);
    Vault::mount(flash, mac, cfg).expect("an unprovisioned board mounts and reports its state")
}

fn blank(cfg: &Config) -> V {
    let flash = SimFlash::new(geometry_for(&cfg.layout));
    Vault::mount(flash, SoftMac::new(), cfg).expect("a blank store mounts")
}

fn assert_untouched(v: V, what: &str) {
    let (flash, _) = v.into_parts();
    assert_eq!(flash.erase_count(), 0, "{what}: erased a sector");
    assert_eq!(flash.program_count(), 0, "{what}: programmed a page");
}

#[test]
fn the_boot_counter_writes_nothing_on_an_unprovisioned_board() {
    let cfg = fuzz_config();
    let mut v = unprovisioned(&cfg);
    assert_eq!(v.state(), StoreState::Unprovisioned);
    assert!(matches!(v.record_boot(), Err(StorageError::WrongState)));
    assert!(matches!(v.acknowledge_boots(), Err(StorageError::WrongState)));
    assert_eq!(v.boot_count(), 0);
    assert_eq!(v.acknowledged_at(), None);
    assert_untouched(v, "unprovisioned");
}

#[test]
fn a_repeated_boot_on_a_blank_store_still_writes_nothing() {
    let cfg = fuzz_config();
    let mut v = blank(&cfg);
    assert_eq!(v.state(), StoreState::Blank);
    // The firmware calls this once per boot. A device that is power-cycled a thousand
    // times without ever saving a wallet must still be byte-for-byte a 0.1.0 device.
    for _ in 0..1000 {
        assert!(matches!(v.record_boot(), Err(StorageError::WrongState)));
    }
    assert_untouched(v, "blank, 1000 boots");
}

#[test]
fn a_wiped_store_counts_no_boots_either() {
    // After a wipe the device is stateless again by PIN-MODES' own definition, so the
    // counter must not restart on it. This is the one state the existing suite does not
    // exercise against the boot log, and `Wiped` is NOT `Formatted`.
    let cfg = fuzz_config();
    let flash = SimFlash::new(geometry_for(&cfg.layout));
    let mut v: V = Vault::mount(flash, SoftMac::new(), &cfg).expect("mount");
    let mut s = scratch(&cfg);
    let session = v
        .format(&Pin::from_normalized_utf8("135790").unwrap(), b"primary", s.scratch())
        .expect("format");
    drop(session);
    v.record_boot().expect("a formatted store counts");
    v.wipe().expect("wipe");
    assert!(matches!(v.state(), StoreState::Wiped { .. }));

    let before_erase = {
        let (f, m) = v.into_parts();
        let c = (f.erase_count(), f.program_count());
        v = Vault::mount(f, m, &cfg).expect("remount a wiped store");
        c
    };
    assert!(matches!(v.record_boot(), Err(StorageError::WrongState)));
    assert!(matches!(v.acknowledge_boots(), Err(StorageError::WrongState)));
    let (f, _) = v.into_parts();
    assert_eq!(
        (f.erase_count(), f.program_count()),
        before_erase,
        "a wiped store must not write when a boot is recorded against it"
    );
}
