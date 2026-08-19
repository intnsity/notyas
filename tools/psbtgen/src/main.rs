// Copyright (C) 2025-2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! psbtgen - the release-bar harness for MILESTONES.md section 9 clause 2.
//!
//! Clause 2 is the one clause that can fail the release on its own: a working wallet has to
//! do the whole loop on real hardware - load a PSBT from SD, review it, sign it, and hand
//! the result to a coordinator that accepts it. Nothing in the tree could previously
//! produce a file for the device to load, or judge what came back. This tool is both ends
//! of that loop, and nothing in between: it never opens a serial port, never flashes
//! anything and never talks to a device. A human carries the card.
//!
//! ```text
//!   psbtgen generate --out DIR   the artifacts: a mnemonic, two spendable PSBTs, a
//!                                descriptor to register, and every address and fee the
//!                                device must agree with. Files for the card, hex on
//!                                stdout for the serial route.
//!   psbtgen sign FILE            the HOST stand-in for the device: notyas-core inspects
//!                                and signs the same file. Proof that an artifact is
//!                                signable at all, and the reference answer a device
//!                                disagreement is measured against.
//!   psbtgen verify FILE          the coordinator: re-derive every amount, recompute every
//!                                sighash, verify every signature, complete the multisig,
//!                                extract, and price the result.
//!   psbtgen selftest             the verifier, run against the engine's own fixture
//!                                corpus and against deliberately broken files, so that
//!                                "verify passed" means something before it is pointed at
//!                                hardware.
//! ```
//!
//! Exit status is the interface: 0 accepted, 1 refused, 2 the tool could not do its job
//! (bad usage, unreadable file), 3 the file is not one this tool generated and so cannot be
//! judged at all. A refusal always names the input and the reason.

mod build;
mod harness;
#[cfg(test)]
mod negatives;
mod selftest;
mod verify;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use notyas_core::bitcoin::hex::{DisplayHex as _, FromHex as _};
use notyas_core::bitcoin::psbt::Psbt;
use notyas_core::psbt::{self, Context, StructuralLimits, PSBT_MAGIC};

use crate::harness::Harness;
use crate::verify::Coordinator;

const USAGE: &str = "\
psbtgen - build the notyas device-test PSBT set, and judge what comes back

  psbtgen generate [--out DIR]   write the artifact set (default DIR: psbtgen-out)
  psbtgen sign FILE [--out FILE] sign on the host with notyas-core, as the device would
  psbtgen verify FILE            would a coordinator accept this signed PSBT?
  psbtgen selftest               run the verifier against the known corpus

FILE may be a binary .psbt or a file of hex, and may be - for stdin. Exit status is
0 accepted, 1 refused, 2 the tool could not run, 3 the file is not one psbtgen
generated and there is no approved copy of it to judge against.
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let command = if refs.is_empty() {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    } else {
        refs.remove(0)
    };

    let result = match command {
        "generate" => generate(&refs),
        "sign" => sign(&refs),
        "verify" => verify(&refs),
        "selftest" => selftest::run(),
        "-h" | "--help" | "help" => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        other => Err(Failure::Usage(format!("unknown command '{other}'"))),
    };

    match result {
        Ok(Verdict::Accepted) => ExitCode::SUCCESS,
        Ok(Verdict::Refused) => ExitCode::from(1),
        Ok(Verdict::Unrecognised) => ExitCode::from(3),
        Err(Failure::Usage(message)) => {
            eprintln!("psbtgen: {message}");
            eprint!("\n{USAGE}");
            ExitCode::from(2)
        }
        Err(Failure::Io(message)) => {
            eprintln!("psbtgen: {message}");
            ExitCode::from(2)
        }
    }
}

/// What a subcommand decided. Distinct from [`Failure`] on purpose: "the device produced a
/// bad signature" and "you gave me a path that does not exist" are different answers and
/// must not share an exit code, or a broken harness reads as a broken device.
///
/// [`Verdict::Unrecognised`] is there for the same reason one step further out. A file this
/// tool did not generate has no approved copy to be compared with, so nothing here can say
/// whether its destinations are the ones a human agreed to - and every way of reporting
/// that with the two statuses above is worse than a third one. Calling it accepted is the
/// defect this verdict was added to remove: it is how `verify` once printed ACCEPTED and
/// exited 0 for a transaction whose payee had been rewritten. Calling it refused would put
/// a release gate in the position of reporting a device fault when an operator merely
/// verified the wrong file.
pub enum Verdict {
    Accepted,
    Refused,
    /// Not one of ours: judged as far as it can be, which is not far enough to accept.
    Unrecognised,
}

pub enum Failure {
    Usage(String),
    Io(String),
}

/// Write the artifact set, and print the same bytes as hex for the serial route.
fn generate(args: &[&str]) -> Result<Verdict, Failure> {
    let out = PathBuf::from(option(args, "--out")?.unwrap_or("psbtgen-out"));
    let harness = Harness::new();
    let cases = build::cases(&harness);
    let artifacts = build::artifacts(&harness, &cases);

    std::fs::create_dir_all(&out)
        .map_err(|e| Failure::Io(format!("cannot create {}: {e}", out.display())))?;
    for artifact in &artifacts {
        let path = out.join(&artifact.file);
        std::fs::write(&path, &artifact.bytes)
            .map_err(|e| Failure::Io(format!("cannot write {}: {e}", path.display())))?;
        println!("wrote {} ({} bytes)", path.display(), artifact.bytes.len());
    }

    println!("\nwallet");
    println!("  words       {}", harness.device.vector.mnemonic);
    println!("  passphrase  {}", harness::PASSPHRASE);
    println!("  fingerprint {}", harness.device.fingerprint());
    println!("  descriptor  {}", harness.descriptor());
    for case in &cases {
        println!("\n{} ({})", case.name, case.file);
        println!("  first receive {}", case.first_receive_address);
        println!(
            "  pays          {} sat to {}",
            case.payment.to_sat(),
            case.payment_address
        );
        println!(
            "  change        {} sat to {}",
            case.change.to_sat(),
            case.change_address
        );
        println!("  fee           {} sat", case.fee.to_sat());
    }

    // Hex last, and each on one line: this is what gets pasted over a serial console, and a
    // wrapped or interleaved line is a transfer that fails for a reason nobody can see.
    println!("\nhex (paste over the serial console)");
    for artifact in &artifacts {
        if artifact.binary {
            println!("\n{}", artifact.file);
            println!("{}", artifact.bytes.to_lower_hex_string());
        }
    }
    Ok(Verdict::Accepted)
}

/// Sign on the host with notyas-core, exactly as the device does.
///
/// This is not a substitute for the hardware loop and must never be reported as one. What
/// it is for: proving that a generated artifact is signable at all before an operator
/// carries a card to a bench, and giving a device disagreement something to be measured
/// against - if the host signs a file the device refuses, the finding is in the device.
fn sign(args: &[&str]) -> Result<Verdict, Failure> {
    let (path, rest) = positional(args)?;
    let out = option(rest, "--out")?;
    let psbt_in = read_psbt(path)?;
    let harness = Harness::new();

    let context = Context {
        network: harness::NETWORK,
        fingerprint: harness.device.fingerprint(),
        limits: StructuralLimits::DEFAULT,
        registry: std::slice::from_ref(harness.registration()),
    };
    let inspection = match psbt::inspect(&psbt_in, &context) {
        Ok(inspection) => inspection,
        Err(failure) => {
            println!("REFUSED by inspect (check {}): {failure}", failure.check());
            return Ok(Verdict::Refused);
        }
    };
    println!(
        "inspected: {} input(s), {} output(s), fee {} sat, {} to sign",
        inspection.inputs.len(),
        inspection.outputs.len(),
        inspection.fee.to_sat(),
        inspection.signable_input_indexes().len()
    );
    let signed = match psbt::sign(&psbt_in, &inspection, harness.device.seed()) {
        Ok(signed) => signed,
        Err(failure) => {
            println!("REFUSED by sign (check {}): {failure}", failure.check());
            return Ok(Verdict::Refused);
        }
    };
    let report = signed.report();
    println!(
        "signed: {} signature(s) added, {} verified by the device's own gate, input(s) {:?}",
        report.signatures_added, report.signatures_verified, report.inputs_signed
    );

    let bytes = psbt::encode(signed.psbt());
    let destination = match out {
        Some(out) => PathBuf::from(out),
        None => signed_name(path),
    };
    std::fs::write(&destination, &bytes)
        .map_err(|e| Failure::Io(format!("cannot write {}: {e}", destination.display())))?;
    println!("wrote {} ({} bytes)", destination.display(), bytes.len());
    println!("{}", bytes.to_lower_hex_string());
    Ok(Verdict::Accepted)
}

/// Judge a signed PSBT the way a coordinator would.
fn verify(args: &[&str]) -> Result<Verdict, Failure> {
    let (path, _) = positional(args)?;
    let psbt = read_psbt(path)?;
    let harness = Harness::new();
    let outcome = Coordinator::for_harness(&harness).verify(&psbt);

    println!("verifying {path}");
    print!("{outcome}");
    match outcome.verdict() {
        Verdict::Accepted => {
            // The case name leads the line on purpose. "The signatures verify" is a claim
            // about internal consistency and was, on its own, what this tool used to accept
            // on; the sentence worth printing is the one that says WHICH approved
            // transaction this is, because that is the half a swapped payee breaks.
            println!(
                "ACCEPTED: this is the approved '{}' case, unchanged, and {} device \
                 signature(s) verify against digests recomputed here; the transaction \
                 extracts",
                outcome.case_name().unwrap_or("?"),
                outcome.signatures_checked
            );
            if let Some(extracted) = &outcome.extracted {
                println!("{}", extracted.raw.to_lower_hex_string());
            }
            Ok(Verdict::Accepted)
        }
        Verdict::Refused => {
            println!(
                "REFUSED: {} reason(s) above. This file is not one a coordinator would \
                 broadcast.",
                outcome.refusals.len()
            );
            Ok(Verdict::Refused)
        }
        Verdict::Unrecognised => {
            println!(
                "UNRECOGNISED: psbtgen did not generate this transaction, so it holds no \
                 approved copy to compare it against and cannot tell you the device signed \
                 what it displayed. Its signatures and its shape were checked and nothing is \
                 wrong with them; that is a smaller statement than ACCEPTED and is not a \
                 substitute for it. Verify a file produced from 'psbtgen generate'."
            );
            Ok(Verdict::Unrecognised)
        }
    }
}

/// `<stem>-signed.psbt`, the convention ARCHITECTURE.md 5.4 fixes and the device follows.
fn signed_name(path: &str) -> PathBuf {
    let path = Path::new(path);
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "psbt".to_string());
    path.with_file_name(format!("{stem}-signed.psbt"))
}

/// Read a PSBT from a file, from stdin, in binary or in hex.
///
/// Both forms are accepted because both routes exist: the card carries the binary file and
/// the serial console carries the hex. Autodetection is by the BIP-174 magic rather than by
/// the file name, so a hex file called `.psbt` - which is what a paste into an editor
/// produces - still works instead of failing as a corrupt file.
fn read_psbt(path: &str) -> Result<Psbt, Failure> {
    let bytes = if path == "-" {
        use std::io::Read as _;
        let mut buffer = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buffer)
            .map_err(|e| Failure::Io(format!("cannot read stdin: {e}")))?;
        buffer
    } else {
        std::fs::read(path).map_err(|e| Failure::Io(format!("cannot read {path}: {e}")))?
    };

    let bytes = if bytes.starts_with(&PSBT_MAGIC) {
        bytes
    } else {
        let text: String = String::from_utf8_lossy(&bytes)
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        Vec::<u8>::from_hex(&text).map_err(|e| {
            Failure::Io(format!(
                "{path} is neither a PSBT nor hex: it does not start with the BIP-174 magic, \
                 and reading it as hex failed: {e}"
            ))
        })?
    };

    // The device's own decoder, for its refusal vocabulary: "this is not a PSBT" and "this
    // PSBT is damaged" are different findings and a parser error says neither.
    psbt::decode(&bytes).map_err(|e| Failure::Io(format!("{path}: {e}")))
}

/// The first non-flag argument, and what follows it.
fn positional<'a>(args: &'a [&'a str]) -> Result<(&'a str, &'a [&'a str]), Failure> {
    match args.split_first() {
        Some((first, rest)) if !first.starts_with("--") => Ok((first, rest)),
        _ => Err(Failure::Usage("expected a file argument".to_string())),
    }
}

/// The value of `--name`, if it is there.
fn option<'a>(args: &'a [&'a str], name: &str) -> Result<Option<&'a str>, Failure> {
    match args.iter().position(|a| *a == name) {
        None => Ok(None),
        Some(at) => args
            .get(at + 1)
            .copied()
            .ok_or_else(|| Failure::Usage(format!("{name} needs a value")))
            .map(Some),
    }
}
