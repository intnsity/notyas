// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The judgements that turn an engine verdict into what a screen renders.
//!
//! Everything here is a pure function of values that are already public: no seed, no store,
//! no card, no ESP-IDF. That is what lets `firmware/hostcheck` compile this exact file and
//! test it, and it is the reason the split exists at all - the three things in this module
//! are the ones most likely to be wrong in a way no compiler can see:
//!
//! 1. **Which refusal code a failure is.** The ratified table (UX-SCREENS.md 3.2) numbers
//!    R-01..R-10 in the order of ARCHITECTURE.md 5.3's ten checks, so the mapping is one
//!    exhaustive match on [`Check`] rather than a per-variant table that could drift from
//!    the engine's own `check()`.
//! 2. **What a transaction will weigh.** A fee rate is the number a user judges a
//!    transaction by, and it is a quotient whose denominator this device has to estimate,
//!    because the signatures do not exist yet.
//! 3. **Which warnings fire.** Every one is a predicate over a single review, which is the
//!    rule S-35 states: anything needing history, a price, a clock or a network is not a
//!    warning this device can honestly raise.
//!
//! Nothing here decides whether a file may be signed. That is `notyas_core::psbt`'s, it has
//! already happened by the time any of these run, and a second opinion here would be a
//! second place for the answer to come from.

use notyas_core::bitcoin::bip32::Fingerprint;
use notyas_core::multisig;
use notyas_core::psbt::{
    Check, CheckFailure, Claim, InputFacts, Malformed, OutputFacts, OutputRole, ScriptKind,
    SignFailure,
};
use notyas_ui::{RefusalCode, RefusalNotice, ReviewedFee, TxReview, TxWarning};

// ---------------------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------------------

/// A refusal notice from a code and the two sentences only the engine can write.
///
/// `happened` is about THIS file and `details` is what a bug report is photographed from.
/// Both come from the engine's own rendering, which already names the index, the txid or
/// the check; rewriting them here would be this file inventing facts about a file it never
/// read.
fn notice(code: RefusalCode, happened: String, details: String) -> RefusalNotice {
    RefusalNotice {
        code,
        happened,
        details,
        after_signing: false,
    }
}

/// The bytes are not a PSBT this device reads (gate 0, before any check runs).
///
/// Three of the eight get their own code because three of them have their own remedy: the
/// wrong file entirely, a file over the transfer cap, and a version this device does not
/// implement. What is left is a file whose magic was right and whose body was not.
pub fn file_refusal(e: &Malformed) -> RefusalNotice {
    let code = match e {
        // Nothing to parse, too short to carry the magic, or the magic is wrong. All three
        // are "that is not a transaction file", and the remedy is to choose another.
        Malformed::Empty | Malformed::Truncated { .. } | Malformed::NotAPsbt => {
            RefusalCode::NotAPsbt
        }
        Malformed::TooLarge { .. } => RefusalCode::FileTooLarge,
        Malformed::PsbtVersionUnsupported { .. } => RefusalCode::PsbtVersion2,
        Malformed::LengthPrefixOverrun { .. } | Malformed::Damaged(_) => RefusalCode::MalformedFile,
    };
    notice(code, sentence(&e.to_string()), format!("gate 0 (decode): {e:?}"))
}

/// One of the ten checks refused.
///
/// The code comes from `CheckFailure::check` and nowhere else, because the ratified table
/// numbers R-01..R-10 in exactly the order ARCHITECTURE.md 5.3 numbers the checks. Two
/// global-sanity failures are lifted out of R-09 first: a file over the structural cap and
/// a PSBT version this device does not implement are the same two facts gate 0 already has
/// codes for, and a user must not get a different code for the same file depending on which
/// of the two bounds caught it.
pub fn check_refusal(e: &CheckFailure) -> RefusalNotice {
    let code = match e {
        CheckFailure::PsbtTooLarge { .. } => RefusalCode::FileTooLarge,
        CheckFailure::PsbtVersionUnsupported { .. } => RefusalCode::PsbtVersion2,
        _ => code_for(e.check()),
    };
    notice(code, sentence(&e.to_string()), format!("{e:?}"))
}

/// Signing, or the post-sign gate that runs after every signature was produced.
///
/// `after_signing` is set on every one of these: whatever the user believed they were
/// holding to, no file left this device, and "load a different file" is the wrong
/// instruction to give someone whose device just failed its own gate.
pub fn sign_refusal(e: &SignFailure) -> RefusalNotice {
    RefusalNotice {
        after_signing: true,
        ..notice(code_for(e.check()), sentence(&e.to_string()), format!("{e:?}"))
    }
}

/// The review was taken under one wallet and another one is holding the seed.
///
/// Reachable only from an embedder that swapped wallets between the review and the hold.
/// R-01, because that is what it is from the user's side: these inputs are not from the
/// wallet that is open.
pub fn wrong_wallet(reviewed: Fingerprint, holding: Fingerprint) -> RefusalNotice {
    RefusalNotice {
        after_signing: true,
        ..notice(
            RefusalCode::NotOurInputs,
            format!(
                "This transaction was reviewed for wallet {reviewed} and this device is \
                 holding wallet {holding}."
            ),
            format!("reviewed={reviewed} holding={holding}"),
        )
    }
}

/// The ratified code for one of the ten checks.
///
/// An exhaustive match, so a check added to ARCHITECTURE.md 5.3 cannot reach a screen
/// without someone deciding what the user is told about it. Public because it is the
/// mapping worth a test of its own: R-01..R-10 are the ten checks in order, and the whole
/// table holds or none of it does.
pub fn code_for(check: Check) -> RefusalCode {
    match check {
        Check::InputOwnership => RefusalCode::NotOurInputs,
        Check::Prevouts => RefusalCode::MissingPrevTx,
        Check::ChangeDerivation => RefusalCode::ChangeNotProven,
        Check::MultisigBinding => RefusalCode::CosignerMismatch,
        Check::NetworkIsolation => RefusalCode::WrongNetwork,
        Check::Fee => RefusalCode::ImpossibleFee,
        Check::SighashWhitelist => RefusalCode::UnsupportedSighash,
        Check::Taproot => RefusalCode::UnexpectedTaproot,
        Check::GlobalSanity => RefusalCode::MalformedFile,
        Check::PostSign => RefusalCode::SignatureCheckFailed,
    }
}

/// A multisig description this device could not read.
pub fn registration_malformed(e: &multisig::Malformed) -> RefusalNotice {
    notice(
        RefusalCode::MalformedFile,
        format!("This file is not a wallet description this device reads: {e}."),
        format!("multisig parse: {e:?}"),
    )
}

/// A multisig description this device read and will not store.
///
/// The two network refusals are R-05, because that is the fact the user has to act on: the
/// device is on the other chain. Everything about the cosigner SET is R-04, which is the
/// 2021 substitution attack's own code and carries the instruction that answers it -
/// compare the registration on every device that holds this wallet. What is left is a
/// wallet whose SHAPE this release does not do, a threshold out of range or a BIP-48 script
/// type that is not P2WSH, and that is a property of the file rather than of anybody's
/// keys.
pub fn registration_refused(e: &multisig::Refusal) -> RefusalNotice {
    let code = match e {
        multisig::Refusal::NetworkMismatch { .. } | multisig::Refusal::CoinTypeMismatch { .. } => {
            RefusalCode::WrongNetwork
        }
        multisig::Refusal::NotAMember { .. }
        | multisig::Refusal::XpubDoesNotDerive { .. }
        | multisig::Refusal::DuplicateXpub { .. }
        | multisig::Refusal::DuplicateFingerprint { .. } => RefusalCode::CosignerMismatch,
        multisig::Refusal::ThresholdOutOfRange { .. }
        | multisig::Refusal::TooManyCosigners { .. }
        | multisig::Refusal::ScriptTypeNotP2wsh { .. }
        | multisig::Refusal::OriginNotBip48 { .. }
        | multisig::Refusal::KeychainsIdentical { .. }
        | multisig::Refusal::Derivation
        | multisig::Refusal::DescriptorUnrenderable => RefusalCode::MalformedFile,
    };
    notice(code, sentence(&e.to_string()), format!("multisig verify: {e:?}"))
}

/// An engine sentence as C7 renders it: capitalised, and closed with a full stop.
///
/// The engines write clauses ("input 2 does not say what it is worth") because they are
/// composed into longer log lines; S-29 puts one of them on a panel under a heading, where
/// a clause with no capital and no stop reads as a fragment somebody forgot to finish. The
/// TEXT is never rewritten, only bracketed: what the user photographs for a bug report has
/// to be the engine's own words.
fn sentence(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 1);
    let mut chars = text.chars();
    if let Some(first) = chars.next() {
        out.extend(first.to_uppercase());
        out.push_str(chars.as_str());
    }
    if !out.ends_with('.') {
        out.push('.');
    }
    out
}

// ---------------------------------------------------------------------------------------
// Virtual size
// ---------------------------------------------------------------------------------------

/// A DER-encoded ECDSA signature plus its sighash byte, at the low-R bound.
///
/// `notyas_core::sign::MAX_ECDSA_SIGNATURE_LEN` is 71 and is a BOUND rather than a size:
/// low-R grinding (ratified Q3) fixes the leading byte of R, and DER minimality still lets
/// S encode a byte short about one time in 64. So this is the largest a signature this
/// device produces can be, which is why the number it feeds is an estimate and never a
/// measurement.
const ECDSA_SIG_BYTES: usize = notyas_core::sign::MAX_ECDSA_SIGNATURE_LEN + 1;

/// A BIP-340 signature under SIGHASH_DEFAULT: 64 bytes, fixed, with no encoding left to
/// vary. The one witness this device can size EXACTLY before it signs.
const SCHNORR_SIG_BYTES: usize = 64;

/// A compressed public key.
const PUBKEY_BYTES: usize = 33;

/// The redeem script a P2SH-wrapped P2WPKH input carries in its scriptSig, pushed whole:
/// one push opcode, then `OP_0 <20-byte key hash>`.
const P2SH_P2WPKH_SCRIPTSIG: usize = 1 + 1 + 1 + 20;

/// What one input contributes to the two halves of the size.
struct InputCost {
    /// scriptSig bytes, WITHOUT its length prefix. Zero for a native segwit spend, which
    /// still costs the one byte that encodes the zero - see [`vsize`].
    script_sig: usize,
    /// Witness bytes, including the item count. Zero for a legacy spend.
    witness: usize,
    /// Whether this input's size is known before it is signed.
    exact: bool,
}

/// The estimated virtual size of the transaction once signed, and whether that estimate is
/// exact.
///
/// The estimate is what the fee-rate row divides by, so it is computed the way BIP-141
/// defines it: `weight = base * 3 + total`, `vsize = ceil(weight / 4)`, where `base` is the
/// transaction with every scriptSig and witness stripped and `total` is the transaction as
/// it goes on the wire. Every witness is sized from the SCRIPT KIND, which the engine
/// established by rebuilding the script, not from anything the file asserted.
///
/// `exact` is true only when every input is a taproot key-path spend, for the reason stated
/// at [`SCHNORR_SIG_BYTES`]: a vsize quoted before signing is an estimate for every ECDSA
/// input, multisig or not. A device that dropped the qualifier would be claiming a broadcast
/// size it has no way to know, and the number it quoted would usually be a few bytes high.
///
/// An input this device cannot classify - a bare P2SH, an unrecognised script, a foreign
/// coin whose spend is somebody else's problem - is charged the largest single-signature
/// spend this module knows about rather than nothing. A missing witness would UNDERSTATE
/// the size, which OVERSTATES the fee rate on the one screen a user judges the fee from,
/// and an estimate that is wrong should be wrong in the direction that does not make a
/// transaction look cheaper than it is.
pub fn vsize(inputs: &[InputFacts], outputs: &[OutputFacts]) -> (u32, bool) {
    let costs: Vec<InputCost> = inputs.iter().map(input_cost).collect();
    let segwit = costs.iter().any(|c| c.witness > 0);

    // 4 byte version, the two counts, 4 byte locktime.
    let mut base = 4 + varint(inputs.len()) + varint(outputs.len()) + 4;
    for cost in &costs {
        // 32 byte txid, 4 byte vout, the scriptSig with its length prefix, 4 byte sequence.
        // The prefix is added here rather than folded into `script_sig` because a segwit
        // input's EMPTY scriptSig still costs the byte that says it is empty, and folding it
        // in is how that byte goes missing from every input of every transaction.
        base += 32 + 4 + varint(cost.script_sig) + cost.script_sig + 4;
    }
    for output in outputs {
        let script = output.script_pubkey.len();
        base += 8 + varint(script) + script;
    }

    // The marker and flag bytes exist only on a transaction that carries a witness at all.
    let witness: usize = costs.iter().map(|c| c.witness).sum();
    let total = base + if segwit { 2 + witness } else { 0 };

    let vsize = (base * 3 + total).div_ceil(4);
    // At least one input as well as all of them taproot: an empty transaction cannot reach
    // here (the engine refuses it) and would otherwise be reported as an exact size for a
    // file with nothing in it.
    let exact = !inputs.is_empty() && costs.iter().all(|c| c.exact);
    (u32::try_from(vsize).unwrap_or(u32::MAX), exact)
}

/// What one input adds, decided from the script kind the engine established.
fn input_cost(input: &InputFacts) -> InputCost {
    match input.kind {
        // <sig> <pubkey>, two witness items.
        ScriptKind::P2wpkh => InputCost {
            script_sig: 0,
            witness: varint(2) + push(ECDSA_SIG_BYTES) + push(PUBKEY_BYTES),
            exact: false,
        },
        // The same witness, plus the redeem script pushed in the scriptSig.
        ScriptKind::P2shP2wpkh => InputCost {
            script_sig: P2SH_P2WPKH_SCRIPTSIG,
            witness: varint(2) + push(ECDSA_SIG_BYTES) + push(PUBKEY_BYTES),
            exact: false,
        },
        // Key path only: check 8 refuses a script-path spend, so there is one item.
        ScriptKind::P2tr => InputCost {
            script_sig: 0,
            witness: varint(1) + push(SCHNORR_SIG_BYTES),
            exact: true,
        },
        // OP_0 (the CHECKMULTISIG off-by-one), M signatures, then the witness script. The
        // threshold and the script come from the REGISTRATION the engine bound, and from a
        // single-signature guess when it bound none, which is the direction every other
        // unknown here is rounded.
        ScriptKind::P2wsh => match &input.multisig {
            Some(binding) => {
                let script = binding.witness_script.len();
                let m = usize::from(multisig_threshold(binding.witness_script.as_bytes()));
                InputCost {
                    script_sig: 0,
                    witness: varint(m + 2) + push(0) + m * push(ECDSA_SIG_BYTES) + push(script),
                    exact: false,
                }
            }
            None => InputCost {
                script_sig: 0,
                witness: varint(2) + push(ECDSA_SIG_BYTES) + push(PUBKEY_BYTES),
                exact: false,
            },
        },
        // Legacy and everything unclassified: <sig> <pubkey> in the scriptSig, no witness.
        ScriptKind::P2pkh | ScriptKind::P2sh | ScriptKind::OpReturn | ScriptKind::Other => {
            InputCost {
                script_sig: push(ECDSA_SIG_BYTES) + push(PUBKEY_BYTES),
                witness: 0,
                exact: false,
            }
        }
    }
}

/// The M of an `OP_M ... OP_N OP_CHECKMULTISIG` script.
///
/// Read off the script rather than looked up in the registry, because the script is what
/// the witness has to satisfy and it is the value the engine already rebuilt from the
/// registration. Two callers ask: the size estimate above, and the completeness test in
/// `crate::signing`, which needs the same number for the same reason - how many signatures
/// this input takes before it is spendable.
///
/// A script that does not open with a small-integer opcode is charged one signature. Both
/// callers are describing a file the engine has already accepted, and refusing here would
/// turn a rendering detail into a failure.
pub fn multisig_threshold(script: &[u8]) -> u8 {
    match script.first() {
        // OP_1 .. OP_16 are 0x51 .. 0x60.
        Some(&op) if (0x51..=0x60).contains(&op) => op - 0x50,
        _ => 1,
    }
}

/// A witness item or a script push: the item's length prefix plus its bytes.
fn push(len: usize) -> usize {
    varint(len) + len
}

/// The wire size of a CompactSize holding `n`.
fn varint(n: usize) -> usize {
    match n {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

// ---------------------------------------------------------------------------------------
// Warnings (S-35)
// ---------------------------------------------------------------------------------------

/// Fee share of what leaves that is worth saying out loud, in percent (ratified Q12).
const FEE_PERCENT_WARN: u64 = 5;

/// Fee rate worth saying out loud, in satoshis per virtual byte (ratified Q12).
const FEE_RATE_WARN: u64 = 500;

/// Outputs past which a transaction is worth calling large (S-30's edge state).
const MANY_OUTPUTS: usize = 10;

/// Reused addresses written out one by one before the remainder is counted together.
///
/// A bound on the PAGE, not on the check. The check sees every duplicate; past this many
/// distinct reused addresses the page stops naming them individually and states how many
/// more there are, because a warnings page with a hundred numbered entries on it is a page
/// nobody reads - and unread warnings are the failure this screen exists to prevent.
/// `StructuralLimits::max_outputs` is 255, so 127 distinct addresses can each be paid twice
/// in one legal transaction.
const DUPLICATE_SCRIPTS_NAMED: usize = 4;

/// Output numbers written out inside one warning before the remainder is counted.
///
/// The same bound one level down: 255 outputs paying one address would otherwise put a
/// 1 KB list of numbers in a headline. The count is always exact and every output has its
/// own review page, so nothing is hidden by shortening the list.
const DUPLICATE_OUTPUTS_NAMED: usize = 8;

/// Everything legal but notable about this transaction, numbered by the screen.
///
/// A predicate over ONE review and nothing else, which is the rule S-35 states: this device
/// has no chain, no clock, no price and no history, so a warning that needed any of them
/// would either never fire or be fabricated, and a page of warnings a user learns to
/// distrust is the page the whole review builds towards.
///
/// The order is fixed and runs from the most expensive mistake to the least: money, then
/// addresses, then the file's own oddities.
pub fn warnings(review: &TxReview) -> Vec<TxWarning> {
    let mut out = Vec::new();
    fee_warning(review, &mut out);
    unproven_warning(review, &mut out);
    duplicate_output_warning(review, &mut out);
    self_send_warning(review, &mut out);
    dust_warning(review, &mut out);
    foreign_input_warning(review, &mut out);
    lock_time_warning(review, &mut out);
    shape_warnings(review, &mut out);
    out
}

/// The fee, when it is a large share of what leaves or a high rate.
///
/// Both halves quote it with the qualifier its proof deserves. A lower bound divided by an
/// exact vsize is still a lower bound, and a percentage of a bound is a bound - so the
/// threshold is compared against the bound, which is the direction that cannot hide a fee.
fn fee_warning(review: &TxReview, out: &mut Vec<TxWarning>) {
    let (fee, bounded) = match review.fee {
        ReviewedFee::Enforced(a) => (a.to_sat(), false),
        ReviewedFee::Stated(a) => (a.to_sat(), true),
    };
    let qualifier = if bounded { "at least " } else { "" };
    let leaving = review.leaving().to_sat();

    // `checked_div` rather than a guard, because the guard IS the question: a transaction
    // with nothing leaving - a consolidation - has no percentage, and there is nothing to
    // warn about rather than a zero to compare.
    if let Some(percent) = fee.saturating_mul(100).checked_div(leaving) {
        if percent >= FEE_PERCENT_WARN {
            out.push(TxWarning {
                headline: format!("Fee is {qualifier}{percent}% of the amount leaving."),
                detail: format!(
                    "{qualifier}{fee} sats on {leaving} sats sent. Check that against your \
                     wallet software before signing."
                ),
            });
        }
    }
    if let Some(rate) = fee.checked_div(u64::from(review.vsize)) {
        if rate >= FEE_RATE_WARN {
            out.push(TxWarning {
                headline: format!("Fee rate is {qualifier}{rate} sat/vB."),
                detail: String::from(
                    "That is far above an ordinary rate. A fee cannot be taken back once the \
                     transaction confirms.",
                ),
            });
        }
    }
}

/// Input amounts the file states and nothing proves.
///
/// On this page as well as in the band the overview leads with, because this is where the
/// user is asked to decide, and the fee they are judging is a sum over these.
fn unproven_warning(review: &TxReview, out: &mut Vec<TxWarning>) {
    let n = review.unproven_amounts();
    if n == 0 {
        return;
    }
    out.push(TxWarning {
        headline: format!("{n} of {} input amounts are not proven.", review.inputs.len()),
        detail: String::from(
            "This device could not check them against the transactions the coins came from, \
             so every total on this screen, the fee included, rests on the file's word.",
        ),
    });
}

/// Two outputs of THIS transaction paying the same script.
///
/// Decided by comparing the outputs against each other, which is all one inspection holds.
/// Reuse against a wallet's PAST is a statement about history, and an airgapped signer has
/// none.
///
/// One warning per reused ADDRESS, never one per pair. The pairwise form this replaces was
/// quadratic in the thing an attacker chooses. At the structural limit of 255 outputs, all
/// paying one address, it built a heap-allocated warning for each of the 32,385 PAIRS -
/// 64,786 allocations and 7 MB, measured - which the review screen then rebuilt as rows on
/// every frame. Grouping is the honest shape as well as the cheap one: "outputs 3, 9 and 40
/// pay the same address" is the fact, and the pairs were only ever a way of spelling it.
///
/// Nothing is dropped when the bounds bite. Both of them replace names with an exact count,
/// so a transaction with a hundred reused addresses still says a hundred; on a signing
/// device a warning that quietly disappears is worse than any amount of slowness.
fn duplicate_output_warning(review: &TxReview, out: &mut Vec<TxWarning>) {
    // Equal scripts brought next to each other, so the groups can be read off in one walk.
    // A sort rather than a map: this is `no_std`-shaped code with at most 255 outputs of at
    // most 34 script bytes, where an ordering beats hashing on both size and dependencies.
    let mut order: Vec<usize> = (0..review.outputs.len()).collect();
    order.sort_unstable_by(|a, b| {
        review.outputs[*a].script_pubkey.cmp(&review.outputs[*b].script_pubkey)
    });

    let mut named = 0usize;
    let mut unnamed_scripts = 0usize;
    let mut unnamed_outputs = 0usize;
    let mut start = 0usize;
    while start < order.len() {
        let script = &review.outputs[order[start]].script_pubkey;
        let mut end = start + 1;
        while end < order.len() && review.outputs[order[end]].script_pubkey == *script {
            end += 1;
        }
        let group = &order[start..end];
        start = end;
        if group.len() < 2 {
            continue;
        }
        if named < DUPLICATE_SCRIPTS_NAMED {
            named += 1;
            // The transaction's own numbering, because that is what the output pages are
            // titled with and what the user will go and look at.
            let mut indices: Vec<u16> = group.iter().map(|i| review.outputs[*i].index).collect();
            indices.sort_unstable();
            out.push(TxWarning {
                headline: format!(
                    "Outputs {} pay the same address.",
                    output_list(&indices, DUPLICATE_OUTPUTS_NAMED)
                ),
                detail: format!(
                    "This transaction pays that address {} times; check that is intended. \
                     Every one of those outputs has its own page.",
                    indices.len()
                ),
            });
        } else {
            unnamed_scripts += 1;
            unnamed_outputs += group.len();
        }
    }

    if unnamed_scripts > 0 {
        out.push(TxWarning {
            headline: format!("{unnamed_scripts} more addresses are each paid more than once."),
            detail: format!(
                "{unnamed_outputs} outputs pay them, beyond the {DUPLICATE_SCRIPTS_NAMED} \
                 addresses named above. Every duplicate this device found is counted here, \
                 and every output has its own page."
            ),
        });
    }
}

/// Output numbers as a sentence fragment: "0 and 1", "0, 1 and 2", "0, 1 and 253 more".
///
/// The tail is a COUNT and not an ellipsis. A list that trails off tells the reader the
/// device stopped looking; a list that ends in "and 253 more" tells them exactly what it
/// found and that the page is only shortening the way it is said.
fn output_list(indices: &[u16], named: usize) -> String {
    let mut parts: Vec<String> = indices.iter().take(named).map(|i| i.to_string()).collect();
    let rest = indices.len() - parts.len();
    if rest > 0 {
        parts.push(format!("{rest} more"));
    }
    match parts.len() {
        0 => String::new(),
        1 => parts.swap_remove(0),
        _ => {
            let last = parts.pop().expect("two or more parts");
            format!("{} and {last}", parts.join(", "))
        }
    }
}

/// An output of ours on the RECEIVE keychain: ours, and not this transaction's change.
fn self_send_warning(review: &TxReview, out: &mut Vec<TxWarning>) {
    for o in &review.outputs {
        if matches!(o.role, OutputRole::OwnNotChange { .. }) {
            out.push(TxWarning {
                headline: format!("Output {} pays an address of this wallet.", o.index),
                detail: String::from(
                    "It is not change, so the amount leaving counts it as money sent.",
                ),
            });
        }
    }
}

/// Outputs under the relay floor for their own script type.
fn dust_warning(review: &TxReview, out: &mut Vec<TxWarning>) {
    for o in &review.outputs {
        let Some(floor) = dust_floor(o.kind) else { continue };
        if o.value.to_sat() < floor {
            out.push(TxWarning {
                headline: format!("Output {} is below the dust limit.", o.index),
                detail: format!(
                    "{} sats, under the {floor} sat floor for this address type. Some nodes \
                     will not relay this transaction.",
                    o.value.to_sat()
                ),
            });
        }
    }
}

/// Bitcoin Core's dust threshold per output type, at its default 3000 sat/kvB dust rate.
///
/// Per type rather than one number, because a single 546 would call an ordinary segwit
/// change output dust and teach the user to ignore the warning. `None` for the two kinds the
/// rule does not apply to: a data output is provably unspendable and carries no value, and a
/// script this device did not recognise has no size for the input that would spend it.
fn dust_floor(kind: ScriptKind) -> Option<u64> {
    match kind {
        ScriptKind::P2pkh => Some(546),
        ScriptKind::P2sh | ScriptKind::P2shP2wpkh => Some(540),
        ScriptKind::P2wpkh => Some(294),
        ScriptKind::P2wsh | ScriptKind::P2tr => Some(330),
        ScriptKind::OpReturn | ScriptKind::Other => None,
    }
}

/// Inputs no origin in the file claims for this wallet.
///
/// Never a refusal on its own - a transaction may legitimately spend a cosigner's coin
/// beside ours - and always said out loud, because their amounts are part of every total on
/// the screen and this device signs none of them.
fn foreign_input_warning(review: &TxReview, out: &mut Vec<TxWarning>) {
    let foreign: Vec<String> = review
        .inputs
        .iter()
        .filter(|i| matches!(i.claim, Claim::Foreign))
        .map(|i| i.index.to_string())
        .collect();
    if foreign.is_empty() {
        return;
    }
    let (subject, verb) = if foreign.len() == 1 { ("Input", "is") } else { ("Inputs", "are") };
    out.push(TxWarning {
        headline: format!("{subject} {} {verb} not from this wallet.", foreign.join(", ")),
        detail: String::from(
            "This device will not sign them. Another signer has to, and the transaction is \
             not finished until it does.",
        ),
    });
}

/// A locktime that holds the transaction back.
fn lock_time_warning(review: &TxReview, out: &mut Vec<TxWarning>) {
    use notyas_core::bitcoin::absolute::LockTime;
    let detail = match review.lock_time {
        // Height zero is what a transaction with no locktime carries, and it is not a
        // locktime: saying so would put a warning on every ordinary spend.
        LockTime::Blocks(h) if h.to_consensus_u32() == 0 => return,
        LockTime::Blocks(h) => format!("It is not valid before block {}.", h.to_consensus_u32()),
        LockTime::Seconds(t) => {
            format!("It is not valid before unix time {}.", t.to_consensus_u32())
        }
    };
    out.push(TxWarning {
        headline: String::from("This transaction has a locktime set."),
        detail: format!("{detail} A node will reject it before that point."),
    });
}

/// The file's own oddities: how many outputs it has, and fields this device does not read.
fn shape_warnings(review: &TxReview, out: &mut Vec<TxWarning>) {
    if review.outputs.len() > MANY_OUTPUTS {
        out.push(TxWarning {
            headline: format!("Large transaction - {} outputs.", review.outputs.len()),
            detail: String::from(
                "Every one of them has its own page. None is sampled and none is skipped.",
            ),
        });
    }
    if review.unknown_fields > 0 {
        let (subject, verb) = if review.unknown_fields == 1 {
            ("field", "it")
        } else {
            ("fields", "they")
        };
        out.push(TxWarning {
            headline: format!(
                "The file carries {} {subject} this device does not read.",
                review.unknown_fields
            ),
            detail: format!(
                "BIP-174 requires a signer to pass {verb} through unaltered, and this device \
                 does. No decision on this screen was made from any of them.",
            ),
        });
    }
}
