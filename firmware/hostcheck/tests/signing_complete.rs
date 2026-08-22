// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Host cover for `firmware/src/signing.rs`.
//!
//! Same technique as the rest of this package and the same rule with it: THE FILE UNDER
//! TEST IS THE REAL ONE, byte for byte. This file is a crate root that supplies the two
//! module paths `signing.rs` names - `crate::flow::model`, which is the firmware's own file
//! again, and `crate::wallet`, which cannot be: `Wallet` owns an ESP-IDF partition. What
//! stands in for it here is a struct with the four accessors `signing.rs` calls, plus
//! `for_test` so `signing.rs`'s own tests can build one from a fixture seed - nothing in
//! this suite asserts anything about `Wallet` itself.
//!
//! The assertions live in `signing.rs`'s own `#[cfg(test)] mod tests`. An integration test
//! binary is compiled with `--test`, so `cfg(test)` holds for every module of this crate,
//! including the two that came in by `#[path]`. That keeps the tests beside the function
//! they are about - the device file carries its own cover - and keeps this root free of
//! any statement about the firmware that the firmware does not make itself.

#![allow(dead_code)]

mod flow {
    #[path = "../../../src/flow/model.rs"]
    pub mod model;
}

/// Stand-in for `firmware/src/wallet`, which is not host-compilable. See the module header.
mod wallet {
    use notyas_core::bitcoin::bip32::Fingerprint;
    use notyas_core::bitcoin::Network;
    use notyas_core::multisig::Registration;
    use notyas_core::psbt::{Context, StructuralLimits};

    pub struct Wallet {
        network: Network,
        fingerprint: Fingerprint,
        registrations: Vec<Registration>,
        seed: [u8; 64],
    }

    impl Wallet {
        pub fn network(&self) -> Network {
            self.network
        }

        pub fn fingerprint(&self) -> Fingerprint {
            self.fingerprint
        }

        pub fn seed(&self) -> &[u8; 64] {
            &self.seed
        }

        pub fn context(&self) -> Context<'_> {
            Context {
                network: self.network,
                fingerprint: self.fingerprint,
                limits: StructuralLimits::DEFAULT,
                registry: &self.registrations,
            }
        }

        /// A single-sig wallet with an empty registry - what `signing.rs`'s own encoding
        /// tests need to call `review`/`sign` against a fixture PSBT, and all any of them
        /// ask for.
        pub fn for_test(network: Network, fingerprint: Fingerprint, seed: [u8; 64]) -> Wallet {
            Wallet {
                network,
                fingerprint,
                registrations: Vec::new(),
                seed,
            }
        }
    }
}

#[path = "../../src/signing.rs"]
mod signing;
