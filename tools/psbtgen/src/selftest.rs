// Copyright (C) 2025-2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Proof that the verifier can tell a good signature from a bad one.
//!
//! A verifier nobody has tried to fool is a rubber stamp, and a rubber stamp pointed at a
//! device produces the most expensive kind of evidence: the kind that says yes when the
//! answer is no. So before `verify` is aimed at hardware, it is aimed at files whose
//! verdict is already known.
//!
//! Two corpora, and each answers something the other cannot:
//!
//! * `notyas_core::psbt::fixture`, reachable through the core's `testkit` feature. These
//!   are the exact PSBTs the engine's own tests are pinned to, which is why they are
//!   borrowed rather than rebuilt: a second, unpinned copy of a fixture drifts, and the
//!   whole value of running against this corpus is that a disagreement here is a bug in
//!   THIS tool. They also carry what the generated artifacts do not: the P2SH-wrapped
//!   script type and taproot, so the ECDSA and the Schnorr halves of the verifier are both
//!   exercised, and a batch whose other party has not signed yet, which is the shape that
//!   would otherwise extract cleanly and be reported as accepted.
//!
//! * The generated artifacts themselves, host-signed. That path proves the files an
//!   operator is about to carry to a bench are signable at all, and that the fee promised on
//!   the card is the fee the finished transaction pays.
//!
//! Then the negatives, which are the point. Each is a file that passed a moment earlier
//! with exactly one thing changed, so a refusal names the change rather than proving only
//! that some broken file is refused:
//!
//!   - the payment output swapped BEFORE signing       -> case-diverges
//!   - a spend of a UTXO this harness never generated  -> unrecognised, and not accepted
//!   - a signature with a flipped bit                  -> signature-invalid
//!   - a signature removed                             -> signature-missing
//!   - the previous transaction stripped after signing -> amount-unproven
//!   - an output edited after signing                  -> signature-invalid
//!   - a witness the file finished for itself          -> witness-unverified
//!   - a forged second leg on the 2-of-3               -> signature-invalid
//!
//! The first is the case this harness was rebuilt around, and the only one where everything
//! internal is impeccable: the device really did sign the transaction in the file, the
//! signature really does verify, the fee really is the fee, and the money goes to an address
//! nobody approved. Nothing short of comparing the whole transaction with the one that was
//! issued can refuse it, which is why the verifier now does that first and why this case is
//! listed first.
//!
//! The second is the limit of the tool stated as a test: a file it did not generate has no
//! approved copy to be measured against, so the only honest answers are "not accepted" and
//! "here is why I cannot judge it". It gets its own verdict and its own exit status.
//!
//! The fifth is the 1 BTC attack in miniature: nothing about the signature changed, and the
//! file still must not be accepted, because the amount it commits to is no longer proven by
//! anything.
//!
//! The last two are the pair that were once accepted with exit 0, and they are here rather
//! than only in `negatives` because they are the two an operator most needs this command to
//! have covered before a card is carried to a bench. Both are files whose signatures the
//! verifier never looked at: one finished its own witness, so ownership resolved to "not
//! ours" and nothing was checked; the other satisfied a 2-of-3 with a leg that exists but
//! belongs to no key. `negatives` takes each class apart one edit at a time; this list is
//! the operator's copy of the answer.

use notyas_core::bitcoin::hashes::Hash as _;
use notyas_core::bitcoin::psbt::Psbt;
use notyas_core::bitcoin::secp256k1::ecdsa;
use notyas_core::bitcoin::{Amount, PublicKey, ScriptBuf, WPubkeyHash, Witness};
use notyas_core::psbt::{self, fixture, Context, StructuralLimits};

use crate::build;
use crate::harness::{self, Harness};
use crate::verify::{Coordinator, Outcome};
use crate::{Failure, Verdict};

/// The address a swapped payment output is sent to. Not derived from anything: the point is
/// that it belongs to nobody in this harness, which is what an attacker's address is.
const SOMEBODY_ELSES_KEY_HASH: [u8; 20] = [0x11; 20];

/// What a case is supposed to produce.
enum Wants {
    Accepted,
    /// Refused, with this [`crate::verify::Refusal::code`] among the reasons.
    Refused(&'static str),
    /// Not accepted, and not blamed on the device either: a file psbtgen never generated,
    /// which it cannot judge and must not wave through.
    Unrecognised,
}

/// Run every case and report. Returns [`Verdict::Refused`] if any case disagreed with what
/// it was supposed to do - a selftest that reports its own failure as success would be
/// worse than none.
pub fn run() -> Result<Verdict, Failure> {
    let mut failures = 0usize;
    let mut ran = 0usize;

    let fixtures = Coordinator::for_fixture();
    let stateless = fixture::context();
    // The fixture's own 2-of-3, in scope for the multisig case: a P2WSH input is ours only
    // if a registered wallet rebuilds its script, and with an empty registry the right
    // answer would be "not ours" rather than "incomplete".
    let fixture_registry = [fixture::registration()];
    let registered = fixture::context_with(&fixture_registry);

    for (label, psbt, context, wants) in [
        (
            "fixture p2wpkh, host-signed",
            fixture::p2wpkh_psbt(),
            &stateless,
            Wants::Accepted,
        ),
        (
            "fixture p2sh-p2wpkh, host-signed",
            fixture::p2sh_p2wpkh_psbt(),
            &stateless,
            Wants::Accepted,
        ),
        (
            "fixture taproot key path, host-signed",
            fixture::p2tr_psbt(),
            &stateless,
            Wants::Accepted,
        ),
        (
            "fixture 2-of-3, one leg only",
            fixture::multisig_psbt(),
            &registered,
            Wants::Refused("incomplete"),
        ),
        // The device signs its own input and nothing else, which is correct - and the file
        // that comes back is still not one a coordinator can broadcast, because the other
        // party's input is unauthorised. Calling that "signed, accepted" is the exact
        // half-answer this tool exists to refuse.
        (
            "fixture batch with somebody else's input still unsigned",
            fixture::ours_and_a_foreign_input_psbt(),
            &stateless,
            Wants::Refused("consensus-shape"),
        ),
    ] {
        ran += 1;
        failures += report(label, run_case(&fixtures, &psbt, context, &fixture::SEED), wants);
    }

    let harness = Harness::new();
    let coordinator = Coordinator::for_harness(&harness);
    let context = Context {
        network: harness::NETWORK,
        fingerprint: harness.device.fingerprint(),
        limits: StructuralLimits::DEFAULT,
        registry: std::slice::from_ref(harness.registration()),
    };
    let seed = *harness.device.seed();

    for case in build::cases(&harness) {
        ran += 1;
        failures += report(
            &format!("generated '{}', host-signed", case.name),
            run_case(&coordinator, &case.psbt, &context, &seed),
            Wants::Accepted,
        );
    }

    // The negatives, all built from the generated single-sig case, which passed above.
    let single = build::cases(&harness).swap_remove(0).psbt;
    let signed = match host_sign(&single, &context, &seed) {
        Ok(psbt) => psbt,
        Err(error) => {
            println!("  [XX] the generated single-sig case does not host-sign: {error}");
            return Ok(Verdict::Refused);
        }
    };

    // The two negatives that change the TRANSACTION rather than a signature, and so are
    // applied before the device ever sees the file. Both come back with a signature that
    // verifies perfectly against the transaction the file carries, which is exactly why "the
    // signatures verify" cannot be the whole of an answer: what is wrong with these files is
    // what the signature is ON.
    for (label, mutation, wants) in [
        (
            "the payment output swapped for another address before signing",
            swap_the_payee as fn(&Psbt) -> Psbt,
            Wants::Refused("case-diverges"),
        ),
        (
            "a spend of a UTXO this harness never generated",
            spend_an_unissued_utxo as fn(&Psbt) -> Psbt,
            Wants::Unrecognised,
        ),
    ] {
        ran += 1;
        failures += report(
            label,
            run_case(&coordinator, &mutation(&single), &context, &seed),
            wants,
        );
    }

    for (label, mutation, wants) in [
        (
            "a signature with one bit flipped",
            corrupt_signature as fn(&Psbt) -> Psbt,
            Wants::Refused("signature-invalid"),
        ),
        (
            "a witness the file finished for itself, over stripped origins",
            finish_the_witness_by_hand as fn(&Psbt) -> Psbt,
            Wants::Refused("witness-unverified"),
        ),
        (
            "the signature removed",
            remove_signature as fn(&Psbt) -> Psbt,
            Wants::Refused("signature-missing"),
        ),
        (
            "the previous transaction stripped after signing",
            strip_amount_proof as fn(&Psbt) -> Psbt,
            Wants::Refused("amount-unproven"),
        ),
        (
            "an output edited after signing",
            edit_an_output as fn(&Psbt) -> Psbt,
            Wants::Refused("signature-invalid"),
        ),
    ] {
        ran += 1;
        failures += report(label, Ok(coordinator.verify(&mutation(&signed))), wants);
    }

    // The multisig forgery needs the 2-of-3 rather than the single-sig case, so it does not
    // fit the list above: the leg being forged is one the single-sig file has no room for.
    let multi = build::cases(&harness).swap_remove(1).psbt;
    match host_sign(&multi, &context, &seed) {
        Ok(signed) => {
            ran += 1;
            failures += report(
                "a forged second leg on the 2-of-3",
                Ok(coordinator.verify(&forge_a_cosigner_leg(&signed))),
                Wants::Refused("signature-invalid"),
            );
        }
        Err(error) => {
            println!("  [XX] the generated multisig case does not host-sign: {error}");
            failures += 1;
            ran += 1;
        }
    }

    println!("\n{ran} case(s), {failures} unexpected");
    if failures == 0 {
        println!("SELFTEST PASSED: the verifier accepts what it should and refuses what it should");
        Ok(Verdict::Accepted)
    } else {
        println!("SELFTEST FAILED");
        Ok(Verdict::Refused)
    }
}

/// Inspect, sign on the host, then verify. The whole loop, minus the device.
fn run_case(
    coordinator: &Coordinator,
    psbt: &Psbt,
    context: &Context<'_>,
    seed: &[u8; 64],
) -> Result<Outcome, String> {
    let signed = host_sign(psbt, context, seed)?;
    Ok(coordinator.verify(&signed))
}

fn host_sign(psbt: &Psbt, context: &Context<'_>, seed: &[u8; 64]) -> Result<Psbt, String> {
    let inspection =
        psbt::inspect(psbt, context).map_err(|e| format!("inspect refused the file: {e}"))?;
    let signed = psbt::sign(psbt, &inspection, seed).map_err(|e| format!("sign refused: {e}"))?;
    Ok(signed.into_psbt())
}

/// Print one line, and say whether it was what was wanted.
fn report(label: &str, outcome: Result<Outcome, String>, wants: Wants) -> usize {
    let (ok, detail) = match (&outcome, &wants) {
        (Err(error), _) => (false, error.clone()),
        (Ok(outcome), Wants::Accepted) => (outcome.accepted(), describe(outcome)),
        // The code, not just the refusal: a case that is refused for the wrong reason is a
        // verifier that happens to be right today, and the next edit moves it.
        (Ok(outcome), Wants::Refused(code)) => (
            outcome.refusals.iter().any(|r| r.code() == *code),
            describe(outcome),
        ),
        (Ok(outcome), Wants::Unrecognised) => (
            matches!(outcome.verdict(), Verdict::Unrecognised),
            describe(outcome),
        ),
    };
    let wanted = match wants {
        Wants::Accepted => "accept".to_string(),
        Wants::Refused(code) => format!("refuse: {code}"),
        Wants::Unrecognised => "report it unrecognised".to_string(),
    };
    println!(
        "  [{}] {label}\n        wanted {wanted}, got {detail}",
        if ok { "ok" } else { "XX" }
    );
    if ok {
        0
    } else {
        1
    }
}

/// What actually happened, in the vocabulary [`Wants`] is written in.
fn describe(outcome: &Outcome) -> String {
    match outcome.verdict() {
        Verdict::Accepted => format!(
            "accepted the '{}' case, {} signature(s) verified",
            outcome.case_name().unwrap_or("?"),
            outcome.signatures_checked
        ),
        Verdict::Refused => format!(
            "refused: {}",
            outcome
                .refusals
                .iter()
                .map(|r| r.code().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Verdict::Unrecognised => {
            "unrecognised: not a transaction psbtgen generated, so not accepted".to_string()
        }
    }
}

// ---------------------------------------------------------------------------------------
// The mutations
// ---------------------------------------------------------------------------------------

/// The file the QA run built by hand, and the reason this module has a section 0.
///
/// One output's script replaced and nothing else touched, before the device is asked to
/// sign. Every internal check still passes afterwards - the amounts are consistent, the fee
/// is the fee, the signature verifies against the transaction that is really there - and the
/// money goes to an address nobody approved. Whether the substitution happened in the
/// coordinator or in the device's own display is a question for whoever investigates; a
/// verifier that accepts this file cannot even raise it.
fn swap_the_payee(psbt: &Psbt) -> Psbt {
    let mut out = psbt.clone();
    out.unsigned_tx.output[0].script_pubkey =
        ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array(SOMEBODY_ELSES_KEY_HASH));
    out
}

/// A perfectly good spend of a UTXO this harness never handed out.
///
/// Built by changing which outpoint the FUNDING transaction itself spends, which changes
/// that transaction's txid and therefore the outpoint the case spends, while leaving the
/// wallet, the script, the amount and every output alone. So the device signs it, the
/// signature verifies, the transaction extracts - and there is no approved copy of it
/// anywhere, because psbtgen never issued it. That is the whole shape of the limitation
/// this tool now states out loud instead of papering over.
fn spend_an_unissued_utxo(psbt: &Psbt) -> Psbt {
    let mut out = psbt.clone();
    let Some(mut funding) = out.inputs[0].non_witness_utxo.clone() else {
        return out;
    };
    funding.input[0].previous_output.vout ^= 1;
    out.unsigned_tx.input[0].previous_output.txid = funding.compute_txid();
    out.inputs[0].non_witness_utxo = Some(funding);
    out
}

/// One bit of one signature, which is all a fault injection or a bad RNG would take.
fn corrupt_signature(psbt: &Psbt) -> Psbt {
    let mut out = psbt.clone();
    let Some((key, signature)) = out.inputs[0].partial_sigs.iter().next() else {
        return out;
    };
    let (key, mut signature) = (*key, *signature);
    let mut compact = signature.signature.serialize_compact();
    // Byte 40 sits inside s. Flipping it leaves a syntactically valid signature that
    // commits to nothing, which is exactly the failure mode worth catching: a verifier that
    // only checked the encoding would pass this file.
    compact[40] ^= 0x01;
    signature.signature =
        ecdsa::Signature::from_compact(&compact).expect("a flipped low byte is still a scalar");
    out.inputs[0].partial_sigs.insert(key, signature);
    out
}

/// A device that reported success and wrote nothing.
fn remove_signature(psbt: &Psbt) -> Psbt {
    let mut out = psbt.clone();
    out.inputs[0].partial_sigs.clear();
    out
}

/// The amount proof taken away after the fact, leaving the coordinator's claim standing
/// alone. Nothing about the signature changes; what changes is what is known about the
/// number it commits to.
fn strip_amount_proof(psbt: &Psbt) -> Psbt {
    let mut out = psbt.clone();
    out.inputs[0].non_witness_utxo = None;
    out
}

/// A file that arrives already finalized, the way BIP-174 says a finalizer leaves one, and
/// with a witness of bytes nobody produced.
///
/// The device's signature and its origin are gone because that is what finalizing removes,
/// which is what made this the dangerous shape: with the origin absent the input is not
/// recognised as the wallet's, so nothing about it was ever checked, and the witness the
/// file brought went straight into the extracted transaction. Deleting the evidence used to
/// improve the verdict.
fn finish_the_witness_by_hand(psbt: &Psbt) -> Psbt {
    let mut out = psbt.clone();
    out.inputs[0].partial_sigs.clear();
    out.inputs[0].bip32_derivation.clear();
    out.inputs[0].final_script_witness = Some(Witness::from_slice(&[
        [0x30u8; 71].as_slice(),
        [0x02u8; 33].as_slice(),
    ]));
    out
}

/// A second leg on the 2-of-3 that is not a signature by the key it sits under: the
/// device's own signature, copied across to a cosigner's key.
///
/// Well-formed DER, the right sighash byte, and no relation to anything. It satisfies the
/// threshold by being present, which is all a coordinator that only checks its own leg
/// requires of it, and it produces a transaction no node will accept.
fn forge_a_cosigner_leg(psbt: &Psbt) -> Psbt {
    let mut out = psbt.clone();
    let Some(device_leg) = out.inputs[0].partial_sigs.values().next().copied() else {
        return out;
    };
    let ours: Vec<PublicKey> = out.inputs[0].partial_sigs.keys().copied().collect();
    let cosigner = out.inputs[0]
        .bip32_derivation
        .keys()
        .map(|k| PublicKey::new(*k))
        .find(|k| !ours.contains(k));
    if let Some(cosigner) = cosigner {
        out.inputs[0].partial_sigs.insert(cosigner, device_leg);
    }
    out
}

/// A coordinator that edits the transaction after the device signed it.
fn edit_an_output(psbt: &Psbt) -> Psbt {
    let mut out = psbt.clone();
    out.unsigned_tx.output[0].value -= Amount::from_sat(10_000);
    out
}

#[cfg(test)]
mod tests {
    /// The same corpus `psbtgen selftest` runs, as an ordinary test.
    ///
    /// Not a duplicate of the subcommand and deliberately not a second corpus: it calls the
    /// very same function, so `cargo test` at the workspace root - which is what CI runs -
    /// covers this tool without anyone having to remember a gate script. A harness whose
    /// own correctness is only checked when a human thinks to check it is a harness that is
    /// wrong on the day it matters.
    #[test]
    fn the_verifier_agrees_with_every_known_answer() {
        assert!(
            matches!(super::run(), Ok(crate::Verdict::Accepted)),
            "the verifier disagreed with a case whose answer is known; see the output above"
        );
    }
}
