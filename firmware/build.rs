// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Re-emits the ESP-IDF configuration flags, and refuses two configurations outright.
//!
//! The two refusals are ESP-SEAL.md 6.4 fence 2 and MILESTONES.md m4a's Q41 release
//! gate. Both exist because cargo feature unification means a transitive dependency can
//! turn a feature on without the application author noticing - a feature flag alone is
//! never the control. A build script failure is, because it cannot be unified away and
//! it stops the artefact from existing.

fn main() {
    embuild::espidf::sysenv::output();

    let release = std::env::var("PROFILE").as_deref() == Ok("release");
    // CARGO_FEATURE_* rather than `cfg!(feature = ...)`: cargo documents the environment
    // variables, and a misspelled `cfg!` silently evaluates false forever - which is the
    // one failure mode a firewall cannot afford.
    let feature = |name: &str| std::env::var(format!("CARGO_FEATURE_{name}")).is_ok();
    let emulated_key = feature("UNSAFE_EMULATED_KEY");
    let hil_console = feature("HIL_CONSOLE");

    // Fence 2. `unsafe-emulated-key` substitutes a compiled-in constant for the
    // read-protected eFuse block. There is no environment override: the escape hatch is
    // to build in debug, which is itself the visible signal that this is not a product
    // image.
    if release && emulated_key {
        panic!(
            "notyas-firmware: feature `unsafe-emulated-key` is enabled in a RELEASE build.\n\
             \n\
             That feature replaces the device-binding eFuse key with a constant compiled \
             into the image. Every wallet a device seals under it is protected by a key \
             that is published in this repository's source.\n\
             \n\
             There is no override. A development image is a debug image."
        );
    }

    // Q41. The HIL console can format the store, seal records, erase both partitions and
    // print ledger internals over the serial port with no PIN. That is exactly the
    // command set a bench needs and exactly the one a shipped device must not answer.
    if release && hil_console {
        panic!(
            "notyas-firmware: feature `hil-console` is enabled in a RELEASE build.\n\
             \n\
             The test console drives the store from the UART with no PIN: it can format, \
             seal, wipe and dump raw flash. A shipped image must not contain it.\n\
             \n\
             There is no override."
        );
    }
}
