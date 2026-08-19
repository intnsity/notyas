// Copyright (C) 2025-2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The PSBT engine: decode a BIP-174 file, decide whether it may be signed, sign it,
//! encode it again.
//!
//! Three stages, in one direction, and the split between them is the whole design:
//!
//! ```text
//!   bytes            -> [`decode`]  -> bitcoin::psbt::Psbt
//!   psbt + context   -> [`inspect`] -> [`Inspection`]   (no key material in scope)
//!   psbt + seed      -> [`sign`]    -> [`SignReport`]   (signs only what the inspection named)
//!   psbt             -> [`encode`]  -> bytes
//! ```
//!
//! [`inspect`] takes a [`Context`] that holds a network, a master fingerprint and a set of
//! structural limits. A fingerprint is a public value, so the type system says what the
//! prose would otherwise only promise: the validation pipeline cannot derive a key,
//! because it has no seed to derive one from. Every refusal therefore happens before any
//! spending authority exists, which is the property ARCHITECTURE.md 5.3 asks for.
//!
//! [`sign`] will not act on an [`Inspection`] taken from a different PSBT: the inspection
//! carries the SHA-256 of the exact bytes it read and [`sign`] recomputes it. A PSBT
//! mutated between review and signature is a refusal, not a signature over something
//! nobody looked at.
//!
//! # What this module enforces, and what it deliberately leaves to notyas-wallet
//!
//! ARCHITECTURE.md 5.3 numbers ten checks and assigns each a layer. This module is the
//! part that needs nothing but the PSBT itself, the device's network and its fingerprint;
//! [`Check`] names all ten so a refusal can state which one it failed, and the variants of
//! [`CheckFailure`] and [`SignFailure`] cover exactly the ones core can decide:
//!
//! | ARCH check | Here | Left to notyas-wallet |
//! |---|---|---|
//! | 1 input ownership | path sanity, the claimed key is the one the script commits to, and derive-and-compare at signing time | nothing |
//! | 2 full prev-tx | all of it | nothing |
//! | 3 change derivation | all of it: multisig outputs against a registered wallet, single-sig outputs against the accounts given to [`inspect_with_accounts`], each re-derived and compared whole ([`OutputRole`]) | nothing |
//! | 4 multisig binding | all of it, against [`Context::registry`] | nothing |
//! | 5 network isolation | coin_type of every origin naming our fingerprint | the wallet-record network comparison |
//! | 6 fee | the arithmetic, and a negative fee | the warn and refuse thresholds |
//! | 7 sighash whitelist | all of it | nothing |
//! | 8 taproot | output-key tweak, annex, script-path refusal | the registered-leaf whitelist |
//! | 9 global sanity | all of it | the review model |
//! | 10 post-sign gate | every signature this device produced re-verified against a sighash recomputed from the PSBT alone | the miniscript interpreter |
//!
//! Checks 3 and 4 need state a PSBT cannot supply, and it enters as arguments: a
//! fingerprint and a slice of [`crate::multisig::Registration`]s on the [`Context`], and a
//! slice of [`crate::derive::Account`]s beside it ([`inspect_with_accounts`]). All three
//! are public values and not one of them can be built out of a PSBT - a registration comes
//! from [`crate::multisig::Pending::verify`] and an account from
//! [`crate::derive::Account::derive`], both of which need a seed - so the engine is still a
//! pure function of its inputs and still has no way to derive a key. That is what lets
//! both halves of check 3 land here: what each one needs is a public record that happens
//! to contain everything required to rebuild a script.
//!
//! Check 3 is also the one check whose WORK a file can size: every origin on an output map
//! naming our fingerprint buys a wallet re-derivation, the map is the file's, and the file
//! may write that map on every output it has. Three bounds hold it, every one of them a
//! refusal and none of them a truncation:
//! [`StructuralLimits::max_own_output_origins`] on one output map,
//! [`StructuralLimits::max_own_origins_in_file`] on all of them together - a bound on each
//! factor of a product is not a bound on the product - and
//! [`StructuralLimits::max_change_derivations`] on what proving the survivors may cost,
//! which is the only one of the three that bounds the CLOCK, because what an origin costs
//! is decided by the registry this device holds rather than by the file.
//! [`crate::derive::device_accounts`] is the account set the single-sig half is meant to
//! be given.
//!
//! Purity is what makes the adversarial corpus a regression suite, and it survives the
//! addition: the same PSBT with the same context, registry included, always yields the same
//! verdict.
//!
//! # Why rust-bitcoin parses the file
//!
//! [`decode`] and [`encode`] are a thin skin over `bitcoin::psbt::Psbt`. Writing a second
//! BIP-174 parser would add an attack surface to the one part of the pipeline that reads
//! wholly untrusted bytes, and would diverge from notyas-wallet, whose API is typed on
//! `bitcoin::psbt::Psbt` throughout (WALLET-API.md 2.8). What this module adds is the
//! plain-language distinction between "this file is not a PSBT" and "this PSBT is
//! damaged", which a refusal screen needs and a parser error does not give.
//!
//! Unknown and proprietary key-value pairs survive a decode-encode round trip, in the
//! global map and in every input and output map: every pair that came in goes back out
//! with its value unaltered, because a coordinator may round trip fields this device has
//! never heard of. That is BIP-174's obligation on a signer, in its words - "If the signer
//! encounters key-value pairs that it does not understand, it must pass those key-value
//! pairs through when re-serializing the transaction" - and it is the whole of what is
//! owed.
//!
//! What is NOT owed, though this doc claimed it until 2026-08-18, is byte-for-byte identity
//! with the coordinator's file. rust-bitcoin emits each map in its own canonical order, so
//! a file whose pairs arrived in a different order comes back equivalent rather than
//! identical: no pair is lost and no value is changed, and BIP-174 fixes no order on the
//! pairs, so there is nothing downstream that a stable byte layout would buy. [`encode`]
//! carries the reasoning and names the test that holds the line. What the engine actually
//! rests on is the weaker statement, and that one does hold: this device's serialization is
//! canonical, so [`psbt_id`] and [`unsigned_id`] are identities of bytes taken and
//! rechecked on this side of the parse.
//!
//! The pairs are counted ([`Inspection::unknown_fields`]) so the review screen can say they
//! are there, and they are never read for any decision.
//!
//! # Why not `Psbt::sign`
//!
//! rust-bitcoin's `Psbt::sign` signs ECDSA through `sign_ecdsa`, which does not grind the
//! nonce. Q3 ratified low-R grinding, and [`crate::sign::MAX_ECDSA_SIGNATURE_LEN`] is the
//! fee estimate that rests on it. [`sign`] therefore drives [`crate::sign`] directly:
//! same `SighashCache`, same rust-bitcoin digests, `sign_ecdsa_low_r` instead. Nothing
//! here computes a sighash or a signature of its own.

mod checks;
mod codec;
mod signer;

// The fixture PSBTs. `cfg(test)`, as they have always been, plus the `testkit` feature:
// tools/psbtgen drives this same corpus from outside the crate, so the release-bar harness
// checks its coordinator-side verifier against the exact files these tests are pinned to
// instead of against a second, unpinned copy of them. Public in both configurations, and
// deliberately not two declarations: a module that is private under `test` and public
// under `testkit` is two spellings of one thing, which is how a fixture and the tests that
// pin it drift apart.
#[cfg(any(test, feature = "testkit"))]
pub mod fixture;
#[cfg(test)]
mod test_corpus;

// Every verdict `inspect` can reach has to be nameable by the caller that renders it:
// `AmountProof` is a public field of `InputFacts` and was missing from this list until
// 2026-08-18, which made it a public field no caller outside this crate could match on.
pub use checks::{
    inspect, inspect_with_accounts, AmountProof, Check, CheckFailure, Claim, ClaimedKey, Context,
    InputFacts, Inspection, Location, MultisigBinding, OutputFacts, OutputRole, Owner, ScriptKind,
    StructuralLimits,
};
pub use codec::{decode, encode, psbt_id, unsigned_id, Malformed, PSBT_MAGIC};
pub use signer::{sign, verify_signatures, SignFailure, SignReport, Signed};
