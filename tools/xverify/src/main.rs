// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! `xverify-device` - the notyas half of the third-party cross-check.
//!
//! # What this binary is for
//!
//! Every PSBT and every signature in this project is checked, today, by this project's
//! code against vectors this project chose. That is how an implementation and its tests
//! come to be wrong together, and it has already happened here twice: a BIP-174 vector
//! with a transposed key type whose assertion agreed with it, and a relaxed check that
//! passed while reopening a demonstrated loss. MILESTONES.md section 9 clause 2 sets the
//! release bar accordingly: sign it, and hand the result to a coordinator that ACCEPTS it.
//!
//! This binary makes that mechanical. It exposes the notyas signing engine as four
//! subcommands over files, so that `tools/xverify/xverify.py` can put Bitcoin Core and
//! embit - two implementations that share no code with this tree and none with each
//! other - on the other side of every artefact it produces.
//!
//! # The one rule of this program
//!
//! **It decides nothing.** It derives, signs, re-encodes and REPORTS. Every comparison,
//! every pass and every fail belongs to the driver and to the oracles. A producer that
//! also judged its own output would put the failure mode this whole exercise exists to
//! close right back where it was.
//!
//! Concretely: no subcommand compares an address to an expected address, and no subcommand
//! exits non-zero because a value "looks wrong". It exits non-zero only when the engine
//! itself refused - a decode failure, a check failure, a signing failure - and then it
//! prints that refusal, because a refusal is a result the driver must be able to assert on
//! too.
//!
//! # Why it may only ever hold a published seed
//!
//! A cross-check binary takes a mnemonic on the command line. That is acceptable for
//! exactly one class of mnemonic, so [`published_seed`] enforces that class: the three
//! BIP-39 vector phrases of CORPUS.md 2.3 and nothing else, with mainnet permitted only
//! for the all-zero `abandon` wallet (CORPUS.md 2.3's network rule). No artefact this tool
//! produces can be a real wallet's, and nobody can quietly repoint it at one.
//!
//! # Placement
//!
//! Outside the workspace, by the m8 precedent: the transport cross-check lived in a
//! throwaway crate because `foundation-ur` pulls an RNG that SECURITY.md invariant 3 bans
//! graph-wide. The same shape holds here for a second reason that has nothing to do with
//! dependencies - an oracle inside the tree under test is not an oracle. See Cargo.toml.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;

use notyas_core::address::SinglesigAccount;
use notyas_core::bitcoin::psbt::{raw, Input, Psbt};
use notyas_core::bitcoin::{Network, PublicKey};
use notyas_core::derive::{self, ChildIndex, Scheme};
use notyas_core::multisig::{Keychain, Registration};
use notyas_core::psbt::{self, Context, StructuralLimits};
use serde_json::{json, Value};

/// The mnemonics this binary will act on, and the only networks each may be used on.
///
/// CORPUS.md 2.3: "The generator refuses to emit a case whose seed is not on that list."
/// This is that rule applied one layer earlier - to the thing that holds the seed rather
/// than to the thing that writes the file - because the tool is what somebody could point
/// at a real wallet by editing one command line.
///
/// The second column is CORPUS.md 2.3's network rule: mainnet cases exist only for address
/// rendering and network isolation, and only for the published all-zero wallet.
const PUBLISHED: [(&str, bool); 3] = [
    (
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon about",
        true,
    ),
    ("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong", false),
    (
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        false,
    ),
];

const USAGE: &str = "\
usage: xverify-device <subcommand> [options]

  wallet     singlesig account facts: fingerprint, xpub, descriptor, addresses
  multisig   registration facts for a descriptor we are a cosigner of
  roundtrip  decode a PSBT and re-encode it, changing nothing
  sign       inspect and sign a PSBT, and report what was signed

options:
  --mnemonic <words>      a published BIP-39 test mnemonic (required except for roundtrip)
  --passphrase <text>     BIP-39 passphrase, default empty
  --network <name>        bitcoin | testnet | signet | regtest
  --scheme <name>         bip44 | bip49 | bip84 | bip86   (wallet)
  --account <n>           account index, default 0        (wallet)
  --count <n>             addresses per keychain, default 5
  --descriptor-file <p>   the multisig descriptor to register (multisig, sign)
  --in <path>             input PSBT, raw bytes           (roundtrip, sign)
  --out <path>            output PSBT, raw bytes          (roundtrip, sign)";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    }
    let opts = match Options::parse(&args[1..]) {
        Ok(opts) => opts,
        Err(message) => return fail(&message),
    };
    let outcome = match args[0].as_str() {
        "wallet" => wallet(&opts),
        "multisig" => multisig(&opts),
        "roundtrip" => roundtrip(&opts),
        "sign" => sign(&opts),
        other => Err(format!("unknown subcommand {other}\n{USAGE}")),
    };
    match outcome {
        Ok(report) => {
            // One JSON document on stdout and nothing else, so the driver never has to
            // guess which line was the answer.
            println!("{report}");
            ExitCode::SUCCESS
        }
        Err(message) => fail(&message),
    }
}

fn fail(message: &str) -> ExitCode {
    eprintln!("xverify-device: {message}");
    ExitCode::FAILURE
}

// -----------------------------------------------------------------------------------------
// Options
// -----------------------------------------------------------------------------------------

struct Options {
    mnemonic: Option<String>,
    passphrase: String,
    network: Network,
    scheme: Scheme,
    account: u32,
    count: u32,
    descriptor_file: Option<PathBuf>,
    input: Option<PathBuf>,
    output: Option<PathBuf>,
}

impl Options {
    fn parse(args: &[String]) -> Result<Options, String> {
        let mut opts = Options {
            mnemonic: None,
            passphrase: String::new(),
            network: Network::Regtest,
            scheme: Scheme::Bip84,
            account: 0,
            count: 5,
            descriptor_file: None,
            input: None,
            output: None,
        };
        let mut i = 0;
        while i < args.len() {
            let flag = args[i].as_str();
            let value = args
                .get(i + 1)
                .ok_or_else(|| format!("{flag} needs a value"))?;
            match flag {
                "--mnemonic" => opts.mnemonic = Some(value.clone()),
                "--passphrase" => opts.passphrase = value.clone(),
                "--network" => {
                    opts.network = value
                        .parse()
                        .map_err(|_| format!("unknown network {value}"))?
                }
                "--scheme" => {
                    opts.scheme = match value.as_str() {
                        "bip44" => Scheme::Bip44,
                        "bip49" => Scheme::Bip49,
                        "bip84" => Scheme::Bip84,
                        "bip86" => Scheme::Bip86,
                        other => return Err(format!("unknown scheme {other}")),
                    }
                }
                "--account" => {
                    opts.account = value
                        .parse()
                        .map_err(|_| "--account is not a number".to_owned())?
                }
                "--count" => {
                    opts.count = value
                        .parse()
                        .map_err(|_| "--count is not a number".to_owned())?
                }
                "--descriptor-file" => opts.descriptor_file = Some(PathBuf::from(value)),
                "--in" => opts.input = Some(PathBuf::from(value)),
                "--out" => opts.output = Some(PathBuf::from(value)),
                other => return Err(format!("unknown option {other}\n{USAGE}")),
            }
            i += 2;
        }
        Ok(opts)
    }

    /// The 64-byte seed, or a refusal naming why this mnemonic is not allowed here.
    fn seed(&self) -> Result<[u8; 64], String> {
        let phrase = self
            .mnemonic
            .as_deref()
            .ok_or("--mnemonic is required for this subcommand")?;
        published_seed(phrase, &self.passphrase, self.network)
    }

    fn registration(&self, seed: &[u8; 64]) -> Result<Option<Registration>, String> {
        let Some(path) = &self.descriptor_file else {
            return Ok(None);
        };
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let pending = notyas_core::multisig::parse(&text)
            .map_err(|e| format!("descriptor is malformed: {e:?}"))?;
        let registration = pending
            .verify(seed, self.network)
            .map_err(|e| format!("registration refused: {e:?}"))?;
        Ok(Some(registration))
    }

    fn read_psbt(&self) -> Result<Psbt, String> {
        let path = self.input.as_ref().ok_or("--in is required")?;
        let bytes =
            std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        psbt::decode(&bytes).map_err(|e| format!("decode refused: {e:?}"))
    }

    fn write_psbt(&self, psbt: &Psbt) -> Result<String, String> {
        let path = self.output.as_ref().ok_or("--out is required")?;
        let bytes = psbt::encode(psbt);
        std::fs::write(path, &bytes).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        Ok(path.display().to_string())
    }
}

/// Turn a mnemonic into a seed, or refuse.
///
/// The refusal is the feature. See the module docs: this binary exists to be pointed at
/// test material, and the list is what stops it being pointed at anything else.
fn published_seed(phrase: &str, passphrase: &str, network: Network) -> Result<[u8; 64], String> {
    let normalized = notyas_core::bip39::normalize_phrase(phrase);
    let entry = PUBLISHED
        .iter()
        .find(|(known, _)| *known == normalized.as_str());
    let Some((_, mainnet_allowed)) = entry else {
        return Err("refusing: this mnemonic is not one of the published BIP-39 test vectors \
                    (CORPUS.md 2.3). This tool may only ever hold public test material."
            .to_owned());
    };
    if network == Network::Bitcoin && !mainnet_allowed {
        return Err("refusing: CORPUS.md 2.3's network rule permits mainnet only for the \
                    all-zero abandon wallet"
            .to_owned());
    }
    Ok(*notyas_core::bip39::seed(&normalized, passphrase))
}

// -----------------------------------------------------------------------------------------
// Subcommands
// -----------------------------------------------------------------------------------------

/// Singlesig account facts: what an oracle needs in order to derive the same account
/// independently, beside what this device says the answers are.
fn wallet(opts: &Options) -> Result<Value, String> {
    let seed = opts.seed()?;
    let account_index = ChildIndex::new(opts.account).ok_or("account index out of range")?;
    // count = 0: the address rows this call would derive are not the ones reported. Those
    // come from `SinglesigAccount` below, which is the path notyas-wallet's address screen
    // actually uses, so the cross-check covers the shipping code rather than a report
    // helper that happens to agree with it.
    let derived = derive::derive(
        &seed,
        opts.network,
        opts.scheme,
        account_index,
        ChildIndex::ZERO,
        0,
        2,
    );
    let fingerprint = derive::master_fingerprint(&seed, opts.network);
    let account = SinglesigAccount::new(opts.scheme, opts.network, &derived.account)
        .ok_or("this scheme has no singlesig account")?;

    let mut receive = Vec::new();
    let mut change = Vec::new();
    for index in 0..opts.count {
        let child = ChildIndex::new(index).ok_or("address index out of range")?;
        for (keychain, out) in [
            (Keychain::Receive, &mut receive),
            (Keychain::Change, &mut change),
        ] {
            let address = account
                .address(keychain, child)
                .ok_or("address did not derive")?;
            out.push(json!({
                "index": index,
                "path": account.leaf_path(keychain, child),
                "address": address.to_string(),
            }));
        }
    }

    Ok(json!({
        "kind": "wallet",
        "network": opts.network.to_string(),
        "scheme": opts.scheme.name(),
        "fingerprint": fingerprint.to_string(),
        "account_path": derived.account.path,
        "xpub": derived.account.xpub,
        "slip132_pub": derived.account.slip132_pub,
        "descriptor": notyas_core::export::descriptor(opts.scheme, fingerprint, &derived.account),
        "receive": receive,
        "change": change,
    }))
}

/// Registration facts for a multisig descriptor we claim to be a cosigner of.
///
/// The descriptor is written by the DRIVER, out of cosigner xpubs the oracles produced.
/// That direction matters: a descriptor this tree composed and this tree then agreed with
/// would prove nothing about BIP-67 ordering, which is the disagreement that puts funds
/// where nobody can spend from.
fn multisig(opts: &Options) -> Result<Value, String> {
    let seed = opts.seed()?;
    let registration = opts
        .registration(&seed)?
        .ok_or("--descriptor-file is required for this subcommand")?;

    let mut receive = Vec::new();
    let mut change = Vec::new();
    for index in 0..opts.count {
        for (keychain, out) in [
            (Keychain::Receive, &mut receive),
            (Keychain::Change, &mut change),
        ] {
            let address = registration
                .address(keychain, index)
                .ok_or("address did not derive")?;
            let witness_script = registration
                .witness_script(keychain, index)
                .ok_or("witness script did not derive")?;
            out.push(json!({
                "index": index,
                "chain": registration.chain_index(keychain),
                "address": address.to_string(),
                "witness_script": hex::encode(witness_script.as_bytes()),
            }));
        }
    }
    let (threshold, cosigners) = registration.threshold_of();

    Ok(json!({
        "kind": "multisig",
        "network": registration.network().to_string(),
        "registration_id": registration.id().to_string(),
        "descriptor": registration.descriptor(),
        "threshold": threshold,
        "cosigners": cosigners,
        "our_position": registration.our_position(),
        "our_fingerprint": registration.ours().fingerprint.to_string(),
        "first_receive_address": registration.first_receive_address().map(|a| a.to_string()),
        "receive": receive,
        "change": change,
    }))
}

/// Decode a PSBT and write it straight back out.
///
/// This is BIP-174's pass-through obligation on a signer, isolated from signing: "If the
/// signer encounters key-value pairs that it does not understand, it must pass those
/// key-value pairs through when re-serializing the transaction." The counts reported here
/// are what stops the driver's preservation assertion from being vacuous - a case carrying
/// no unknown pairs would satisfy "every unknown pair survived" trivially, so the driver
/// asserts these are non-zero before it believes the comparison.
fn roundtrip(opts: &Options) -> Result<Value, String> {
    let psbt = opts.read_psbt()?;
    let written = opts.write_psbt(&psbt)?;
    Ok(json!({
        "kind": "roundtrip",
        "out": written,
        "fields": unknown_census(&psbt),
    }))
}

/// Inspect and sign, and report exactly what was signed.
///
/// The signatures are reported in the form an oracle can check without parsing a PSBT at
/// all: input index, public key, DER signature with its sighash byte, and the prevout the
/// signature commits to. embit recomputes the sighash from those and verifies; Bitcoin
/// Core reaches the same conclusion the hard way, by finalizing the PSBT and running the
/// script interpreter over the result in `testmempoolaccept`.
fn sign(opts: &Options) -> Result<Value, String> {
    let seed = opts.seed()?;
    let psbt = opts.read_psbt()?;
    let registration = opts.registration(&seed)?;
    let registry: Vec<Registration> = registration.into_iter().collect();
    let context = Context {
        network: opts.network,
        fingerprint: derive::master_fingerprint(&seed, opts.network),
        limits: StructuralLimits::DEFAULT,
        registry: &registry,
    };

    let inspection =
        psbt::inspect(&psbt, &context).map_err(|e| format!("inspection refused: {e:?}"))?;
    let signed =
        psbt::sign(&psbt, &inspection, &seed).map_err(|e| format!("sign refused: {e:?}"))?;
    let report = signed.report().clone();
    let out = signed.into_psbt();
    let written = opts.write_psbt(&out)?;

    // The signature census is a DIFF against the input, not a dump of the output: a
    // cosigner's signature that was already in the file is not ours to claim, and the whole
    // point of handing these to an oracle is that they are the ones this device produced.
    let mut added = Vec::new();
    for (index, (before, after)) in psbt.inputs.iter().zip(out.inputs.iter()).enumerate() {
        for (pubkey, signature) in &after.partial_sigs {
            if before.partial_sigs.contains_key(pubkey) {
                continue;
            }
            added.push(signature_facts(index, pubkey, &signature.to_vec(), after));
        }
        if after.tap_key_sig != before.tap_key_sig {
            if let Some(sig) = after.tap_key_sig {
                added.push(json!({
                    "input": index,
                    "kind": "taproot_key_path",
                    "signature": hex::encode(sig.to_vec()),
                    "prevout": prevout_facts(after),
                }));
            }
        }
    }

    Ok(json!({
        "kind": "sign",
        "out": written,
        "signatures_added": report.signatures_added,
        "signatures_verified": report.signatures_verified,
        "inputs_signed": report.inputs_signed,
        "signatures": added,
        "fields": unknown_census(&out),
    }))
}

// -----------------------------------------------------------------------------------------
// Reporting helpers
// -----------------------------------------------------------------------------------------

fn signature_facts(index: usize, pubkey: &PublicKey, signature: &[u8], input: &Input) -> Value {
    json!({
        "input": index,
        "kind": "ecdsa",
        "pubkey": pubkey.to_string(),
        // DER, with the sighash byte, the way a scriptSig or a witness carries it.
        "signature": hex::encode(signature),
        "prevout": prevout_facts(input),
        "witness_script": input.witness_script.as_ref().map(|s| hex::encode(s.as_bytes())),
        "redeem_script": input.redeem_script.as_ref().map(|s| hex::encode(s.as_bytes())),
    })
}

/// The amount and script a signature commits to, as the PSBT states them.
///
/// Reported from the PSBT rather than from the inspection on purpose: an oracle that
/// recomputes the sighash needs the file's own claim, so that a file whose claimed amount
/// is a lie produces an oracle DISAGREEMENT rather than a quietly corrected agreement.
fn prevout_facts(input: &Input) -> Value {
    match &input.witness_utxo {
        Some(txout) => json!({
            "value": txout.value.to_sat(),
            "script_pubkey": hex::encode(txout.script_pubkey.as_bytes()),
        }),
        None => Value::Null,
    }
}

/// How many key-value pairs in this PSBT are ones nothing in the tree understands.
///
/// Split by map, because "preserved" has to hold of each of them separately: BIP-174 puts
/// unknown pairs in the global map, in every input map and in every output map, and a
/// serializer that dropped only the output ones would still pass a whole-file count.
fn unknown_census(psbt: &Psbt) -> Value {
    let mut input_unknown = 0usize;
    let mut input_proprietary = 0usize;
    for input in &psbt.inputs {
        input_unknown += input.unknown.len();
        input_proprietary += input.proprietary.len();
    }
    let mut output_unknown = 0usize;
    let mut output_proprietary = 0usize;
    for output in &psbt.outputs {
        output_unknown += output.unknown.len();
        output_proprietary += output.proprietary.len();
    }
    json!({
        "global_unknown": psbt.unknown.len(),
        "global_proprietary": psbt.proprietary.len(),
        "input_unknown": input_unknown,
        "input_proprietary": input_proprietary,
        "output_unknown": output_unknown,
        "output_proprietary": output_proprietary,
        "global_keys": raw_keys(&psbt.unknown),
        "inputs": psbt.inputs.len(),
        "outputs": psbt.outputs.len(),
    })
}

/// The unknown global keys, rendered the way the driver's own BIP-174 reader names them:
/// `<keytype hex>:<keydata hex>`. Two implementations naming the same key the same way is
/// a weaker claim than byte identity and is not the claim the driver rests on; it is here
/// so a mismatch can be read by a person without a hex editor.
fn raw_keys(map: &BTreeMap<raw::Key, Vec<u8>>) -> Vec<String> {
    map.keys()
        .map(|key| {
            let mut out = String::new();
            let _ = write!(out, "{:02x}:{}", key.type_value, hex::encode(&key.key));
            out
        })
        .collect()
}
