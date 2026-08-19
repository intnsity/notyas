// Copyright (C) 2025-2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The validation pipeline: everything the device can decide about a PSBT before any key
//! exists.
//!
//! [`inspect`] is a pure function of a PSBT and a [`Context`]. It returns either the facts
//! a review screen needs ([`Inspection`]) or the single named reason the device refuses
//! ([`CheckFailure`]). There is no collect-all-errors mode: the first reason a device
//! refuses is the one a user has to act on, and a screen listing eleven complaints is a
//! screen nobody reads (WALLET-API.md 3).
//!
//! # Order
//!
//! Cheap and decisive first, so that a hostile file is rejected before it can cost
//! anything:
//!
//! 1. global sanity (ARCH check 9) - version, size, counts, duplicates, annex;
//! 2. prevouts (check 2) - the values every later stage depends on, and how firmly each
//!    one is known;
//! 3. ownership claims (checks 1, 4, 5) - path sanity, coin type, the claimed key against
//!    the script it says it can spend, and the two refusals that are only refusals for an
//!    input this device would sign: an already finalized input, and an amount with no
//!    previous transaction behind it;
//! 4. sighash whitelist (check 7);
//! 5. taproot (check 8) - the output-key tweak;
//! 6. fee (check 6) - the arithmetic, once the prevouts are trustworthy.
//!
//! Fee is last because it is the only stage that needs every prevout to already have been
//! checked; putting it earlier would be computing a number from unvalidated input, which
//! is the Trezor 2020 BIP-143 bug in a different order.
//!
//! # What "ours" means here
//!
//! Which is also what decides how much of the file this device is entitled to judge. A
//! refusal that protects what this device signs belongs on the inputs it would sign, and
//! nowhere else: a cosigner who finalized their own input or sent it without its previous
//! transaction has done nothing to us, and a device that refuses the whole file for it
//! cannot take part in an ordinary multi-party round - Bitcoin Core's `walletprocesspsbt`
//! finalizes every input it can before it hands the file back. What stays global is what
//! is global in fact: the shape of the file, contradictions inside it, and an amount that
//! is missing rather than merely unproven, because the fee is a sum over every input.
//!
//! An OUTPUT is a different question, and a harder one, because nothing this device signs
//! is at stake in the answer: what is at stake is the number a review screen leads with.
//! An output is change only when a wallet of ours rebuilds the script it pays, from a
//! [`Registration`] or an [`Account`] - values that could only have come from the seed.
//! Everything else, including an output whose map carries our fingerprint at a perfectly
//! plausible change path, is money leaving. See [`OutputRole`].
//!
//! An input is `Ours` when exactly one BIP32 origin in its map names the device's master
//! fingerprint. That is a CLAIM, not proof: a fingerprint is four public bytes and anyone
//! can write ours into a file. The proof is [`super::sign`]'s derive-and-compare, which
//! rebuilds the script from the key the path actually derives and refuses if it differs.
//! Splitting the claim from the proof is what lets the whole of this file run with no seed
//! in scope.

use alloc::vec::Vec;
use core::fmt;

use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint};
use bitcoin::key::{CompressedPublicKey, TapTweak};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::{absolute, Amount, Network, OutPoint, Script, ScriptBuf, TxOut};

use crate::derive::{secp, Account, AccountId, Leaf};
use crate::multisig::{self, Keychain, Registration, RegistrationId};

use super::codec;

// ---------------------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------------------

/// Structural bounds on an accepted PSBT.
///
/// Deliberately smaller than notyas-wallet's `policy::Limits` (WALLET-API.md 2.8), which
/// is this plus the fee thresholds, the change gap bounds and the sighash policy. Those
/// three need a wallet; the fields here do not, and keeping them apart is what stops the
/// engine from acquiring a dependency on wallet state it has no use for.
///
/// None of these is adjustable from any screen. Q24 forbids an override that reaches a
/// refusal, and every one of these is a refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StructuralLimits {
    /// Serialized size of the accepted file. Ratified at 1 MiB (Q25), to be re-measured
    /// against a worst-case consolidation carrying full previous transactions before
    /// 0.2.0 ships. It bounds RAM on a device whose PSRAM also holds a 720x720
    /// framebuffer and the Argon2 arena.
    pub max_psbt_bytes: usize,
    /// Input count. Not pinned by a ratified question: the byte cap is the real bound, and
    /// this exists so that a pathological many-input file fails with a sentence about
    /// inputs ("too large for the device: N inputs") rather than one about bytes.
    pub max_inputs: u16,
    /// Output count. Same reasoning, and it also bounds the review model, which is one
    /// page per output.
    pub max_outputs: u16,
    /// Deepest derivation path accepted. BIP48 is the deepest shape this device produces
    /// at six levels; the headroom is for a coordinator that adds one and not for an
    /// unbounded walk, which on a 400 MHz core is a denial of service.
    pub max_path_depth: u8,
    /// How many origins on ONE output map may name THIS DEVICE's fingerprint.
    ///
    /// The bound on check 3's work, and the reason it has to exist: `classify_output`
    /// re-derives a wallet of ours for every such origin until one of them proves the
    /// script, and a PSBT is an attacker's file whose derivation map is an attacker's
    /// size. Measured on an x86-64 release build, one origin that names a registration's
    /// own leaf shape costs 170 microseconds against a single 2-of-3 registration - a
    /// 15-of-15 is five times that - and costs 60 bytes of file. A megabyte of origins is
    /// therefore roughly 17,000 derivations, which is seconds on a desktop and minutes to
    /// an hour on a 400 MHz core with a software secp256k1, with no progress and no way
    /// out but power.
    ///
    /// 15 is [`crate::multisig::MAX_COSIGNERS`], and that is the whole justification: a
    /// legitimate output of ours is locked by one of our keys per cosigner slot it fills,
    /// single-sig and taproot key-path fill exactly one, and a P2WSH wallet this device
    /// can register has at most `MAX_COSIGNERS` slots. Nothing honest is above it, so the
    /// bound costs no real transaction anything, and it turns an unbounded walk into at
    /// most fifteen derivations per output.
    ///
    /// Counted over ONLY the origins naming our fingerprint, across both
    /// `bip32_derivation` and `tap_key_origins`. Foreign origins are not bounded here and
    /// must not be: a 15-cosigner output legitimately carries 14 of them, and reading one
    /// costs a four-byte comparison.
    ///
    /// The one honest file this can refuse is a payment to a taproot SCRIPT TREE that
    /// names us in more than `MAX_COSIGNERS` leaves. That is accepted: this device builds
    /// no such output (Q7 - BIP-86 key path, no tree), so it could never have proven one
    /// either, and a readable refusal is a better answer than an hour of derivation ending
    /// in "payment".
    pub max_own_output_origins: u8,
    /// How many origins in the WHOLE FILE may name this device's fingerprint.
    ///
    /// [`max_own_output_origins`](StructuralLimits::max_own_output_origins) bounds one
    /// output map. It does not bound the file, and the difference is not a detail: a file
    /// may carry [`max_outputs`](StructuralLimits::max_outputs) output maps, so the
    /// per-output bound on its own ACCEPTS 255 x 15 = 3,825 origins naming us. Measured on
    /// an x86-64 release build on 2026-08-19, such a file is accepted in 27.7 seconds
    /// against the largest registry this device holds - about 2.7 hours on the device, at
    /// the host-to-device ratio [`max_change_derivations`](StructuralLimits::max_change_derivations)
    /// derives. A bound on each factor of a product is not a bound on the product.
    ///
    /// 256 is one origin per output, rounded up to a power of two. This device is exactly
    /// ONE cosigner of any wallet it registers ([`Registration::our_position`] is a single
    /// index) and holds exactly one key at any single-sig leaf, so an honest output of ours
    /// names us once and a transaction cannot have more outputs of ours than it has
    /// outputs. Nothing honest is above it.
    ///
    /// Counted the same way and in the same pass as the per-output bound, over both
    /// `bip32_derivation` and `tap_key_origins`, so the two cannot come to disagree about
    /// what an origin of ours is.
    ///
    /// [`Registration::our_position`]: crate::multisig::Registration::our_position
    pub max_own_origins_in_file: u16,
    /// How many BIP-32 child derivations check 3 may spend on ONE FILE.
    ///
    /// The count above bounds what a file may CLAIM; this bounds what those claims may
    /// COST, and only the second is a bound on TIME. They are not interchangeable, because
    /// one origin is not one price: what an origin costs is decided by the registry this
    /// device happens to hold, which the count knows nothing about.
    ///
    /// # The multiplier the count cannot see
    ///
    /// [`multisig::locate_in`] walks the registry and [`Registration::locate`] does the
    /// free half first, so a registration whose origin the claimed path cannot name costs
    /// a path comparison. A path that every registration's origin DOES name costs every
    /// registration's [`Registration::leaf_derivations`] - and registrations share an
    /// origin whenever a user registers several wallets at the same BIP-48 account, which
    /// is the ordinary thing to do. Eight 15-of-15 records is therefore 240 derivations to
    /// answer "no" about ONE origin, against 6 for the single 2-of-3 the doc comments used
    /// to quote: a 40x multiplier on an attacker's file, and the count bound is blind to
    /// all of it.
    ///
    /// # Cost, measured
    ///
    /// x86-64 release build, 2026-08-19. One origin naming us on a BIP-48 leaf path:
    /// 179.8 us against one 2-of-3 registration, 7,000.7 us against eight 15-of-15
    /// registrations sharing our origin. Divided by the derivations each of those actually
    /// performs (6 and 240; a script that does not match never reaches `our_key_at`) that
    /// is 30.0 and 29.2 microseconds per derivation, which is the same number twice and is
    /// what makes a derivation the honest unit to ration.
    ///
    /// The device is 350x slower at exactly this arithmetic, and that figure is measured
    /// rather than scaled from a clock speed. Two independent anchors agree: v0.1.0's six
    /// boot self-test checks - the same PBKDF2-HMAC-SHA512, BIP-32 and secp256k1 mix -
    /// take 1.41 ms here against the 494 ms both dev boards reported (350.6x), and
    /// Argon2id at MEASUREMENTS.md section 3's parameters is 308x to 383x slower on
    /// silicon across three orders of magnitude of working set. So one derivation costs
    /// about 10.3 ms on the device.
    ///
    /// # The budget
    ///
    /// 512 derivations is 5.3 seconds on the device, and that is the number this is: the
    /// outer edge of what a person holding a signer will wait for a review screen that has
    /// nothing on it yet. The device's one other deliberate wait, the PIN's Argon2id, is
    /// 1.83 s and at least has a screen that says so. An ordinary file is nowhere near:
    /// a payment with one change output from a registered 2-of-3 spends 8.
    ///
    /// Charged as the proving loops run, not levied per origin in advance, and that
    /// difference is what keeps honest files out of it. An honest change output is found
    /// by the registration that owns it and the walk stops there, so it pays for one
    /// wallet; only a file whose paths name wallets that do not build its scripts pays for
    /// all of them. The headroom that leaves is 64 of a 2-of-3 wallet's own outputs in one
    /// transaction, or 16 of a 15-of-15's - past any self-send a person signs on a
    /// hardware device, where the ordinary count is one.
    ///
    /// [`multisig::locate_in`]: crate::multisig::locate_in
    /// [`Registration::locate`]: crate::multisig::Registration::locate
    /// [`Registration::leaf_derivations`]: crate::multisig::Registration::leaf_derivations
    pub max_change_derivations: u32,
}

impl StructuralLimits {
    pub const DEFAULT: StructuralLimits = StructuralLimits {
        max_psbt_bytes: 1024 * 1024,
        max_inputs: 255,
        max_outputs: 255,
        max_path_depth: 8,
        max_own_output_origins: multisig::MAX_COSIGNERS,
        max_own_origins_in_file: 256,
        max_change_derivations: 512,
    };
}

impl Default for StructuralLimits {
    fn default() -> Self {
        StructuralLimits::DEFAULT
    }
}

/// Everything [`inspect`] is allowed to know besides the PSBT.
///
/// A `Fingerprint` is four public bytes derived from the master public key, so this type
/// carries no secret and cannot be turned into one. That is the mechanism behind
/// WALLET-API.md's "the whole pipeline runs before any key derivation": not a convention,
/// an absence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Context<'a> {
    /// The network the DEVICE is on. Never read from the PSBT: taking it from the file
    /// being validated is the Coldcard 2020 isolation bypass.
    pub network: Network,
    /// The master fingerprint of the seed that would sign.
    pub fingerprint: Fingerprint,
    pub limits: StructuralLimits,
    /// The multisig wallets this device has been registered into (0.2.0-m7).
    ///
    /// Every one of them was produced by [`crate::multisig::Pending::verify`], which needed
    /// a seed; none of them can be built from a PSBT. That is what makes ARCHITECTURE.md's
    /// check 4 decidable here without a key in scope, and it is why the cosigner xpubs a
    /// PSBT carries are never read: the answer to "is this our script" comes from this
    /// slice or it does not come at all.
    ///
    /// An empty slice is signing statelessly. A multisig input is then refused outright
    /// rather than downgraded to a warning (WALLET-API.md `MultisigStatelessUnverifiable`,
    /// ratified Q11/Q24), because an unverifiable cosigner set is exactly the 2021 attack.
    pub registry: &'a [Registration],
}

// ---------------------------------------------------------------------------------------
// The checks, named
// ---------------------------------------------------------------------------------------

/// The ten checks of ARCHITECTURE.md 5.3, by their number in that table.
///
/// All ten are named even though this crate enforces eight of them, because a refusal has
/// to be able to say which check it failed in the same vocabulary the design document and
/// notyas-wallet use. Checks 3 and 4 are here so that the wallet layer can report against
/// the same enum rather than inventing a second numbering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Check {
    /// 1: the key origin an input claims really does derive that input's script, and the
    /// path it claims has a sane shape.
    InputOwnership = 1,
    /// 2: the full previous transaction is present and agrees with what the input claims.
    Prevouts = 2,
    /// 3: an output is change only if a wallet of this device's own independently
    /// derives the script it pays. Enforced here for both kinds of wallet: multisig
    /// against [`Context::registry`], single-sig against the accounts given to
    /// [`inspect_with_accounts`].
    ChangeDerivation = 3,
    /// 4: a multisig script rebuilds from a REGISTERED descriptor. Needs a registry;
    /// notyas-wallet. Enforced here only as the refusal that a claimed input this crate
    /// cannot verify single-sig is not signed at all.
    MultisigBinding = 4,
    /// 5: coin type and network isolation.
    NetworkIsolation = 5,
    /// 6: the fee arithmetic. Thresholds are notyas-wallet's.
    Fee = 6,
    /// 7: SIGHASH_ALL / SIGHASH_DEFAULT only, with no override.
    SighashWhitelist = 7,
    /// 8: the taproot output-key tweak, the annex, and script-path spends.
    Taproot = 8,
    /// 9: global sanity of the file itself.
    GlobalSanity = 9,
    /// 10: every signature re-verified before anything leaves the device.
    PostSign = 10,
}

impl Check {
    /// The row number in the ARCHITECTURE.md 5.3 table.
    pub fn number(self) -> u8 {
        self as u8
    }

    /// Short name, for a log line or a refusal footer. Not user-facing prose: the
    /// user-facing sentence is notyas-wallet's `Refusal::explain`.
    pub fn name(self) -> &'static str {
        match self {
            Check::InputOwnership => "input ownership",
            Check::Prevouts => "previous transactions",
            Check::ChangeDerivation => "change derivation",
            Check::MultisigBinding => "multisig binding",
            Check::NetworkIsolation => "network isolation",
            Check::Fee => "fee",
            Check::SighashWhitelist => "sighash whitelist",
            Check::Taproot => "taproot",
            Check::GlobalSanity => "global sanity",
            Check::PostSign => "post-sign gate",
        }
    }
}

impl fmt::Display for Check {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "check {} ({})", self.number(), self.name())
    }
}

/// Where in the PSBT a failure sits, for the checks that apply to both maps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Location {
    Input(u16),
    Output(u16),
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Location::Input(i) => write!(f, "input {i}"),
            Location::Output(i) => write!(f, "output {i}"),
        }
    }
}

/// The single reason the device refused, named after the check it failed.
///
/// One variant per concrete reason, not one per check: "this PSBT failed check 2" is not
/// something a screen can turn into a sentence, and a generic error is how a signer ends
/// up telling a user to try again with a file that will never work. The variants line up
/// with notyas-wallet's `RefusalCode` (WALLET-API.md 2.8) wherever the same condition
/// exists there, so the wallet's mapping is a rename and never a judgement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckFailure {
    // -- Check 9: global sanity ----------------------------------------------------------
    /// PSBT v2 (BIP-370) and anything later. Parse-and-refuse is deliberate: every
    /// coordinator this device targets emits v0, and silently signing a structure we only
    /// half understand is worse than saying no.
    PsbtVersionUnsupported { version: u32 },
    PsbtTooLarge { bytes: usize, max: usize },
    NoInputs,
    NoOutputs,
    TooManyInputs { found: usize, max: u16 },
    TooManyOutputs { found: usize, max: u16 },
    /// The per-input maps and the unsigned transaction disagree about how many inputs
    /// there are. rust-bitcoin rejects most of these at parse time; this covers the rest,
    /// because every later loop indexes both.
    InputMapCountMismatch { maps: usize, tx_inputs: usize },
    OutputMapCountMismatch { maps: usize, tx_outputs: usize },
    /// Two inputs spend the same outpoint. Consensus would reject the transaction, but the
    /// device must not sign it either: it is how a hostile coordinator gets two signatures
    /// over one UTXO.
    DuplicateInput {
        first: u16,
        second: u16,
        outpoint: OutPoint,
    },
    /// An input THIS DEVICE would sign already carries a final scriptSig or witness.
    /// Signing alongside one is how a finalize-then-resign trick gets a second signature
    /// under a different sighash. Raised from the ownership stage, not from
    /// [`global_sanity`], because a cosigner's finished witness on a cosigner's own input
    /// is what a multi-party round looks like and not an attack on anything of ours.
    InputAlreadyFinalized { index: u16 },

    // -- Check 2: prevouts ---------------------------------------------------------------
    /// Neither `non_witness_utxo` nor `witness_utxo`: nothing states what this input is
    /// worth. Refused whoever the input belongs to, unlike its neighbour below, because
    /// the fee is a sum over EVERY input: a missing amount is not a weak number to caveat
    /// on the review screen, it is the absence of one, and this device does not ask for an
    /// authorisation whose cost it cannot state. BIP-174 has the Input Finalizer keep the
    /// UTXO ("The UTXO should be kept to allow Transaction Extractors to verify the final
    /// network serialized transaction"), so a file arriving without it is one the sender
    /// can fix.
    MissingPrevout { index: u16 },
    /// `witness_utxo` alone, for an input of ours that is not taproot. BIP-143 signs an
    /// amount the signer cannot otherwise verify, which is exactly the 2020 Trezor fee
    /// attack; only BIP-341, which commits to every prevout, is safe without the full
    /// transaction. Named per input because it is the one the user can act on: the file's
    /// sender still holds the transaction that proves it.
    ///
    /// This variant covers the input being signed. What the previous transaction ALSO
    /// protects - the amounts of every OTHER input - is
    /// [`CheckFailure::UnprovenAmountBesideOurSignature`], and the two together are the
    /// whole of BIP-174's line 415 footnote.
    MissingPreviousTransaction { index: u16 },
    /// This device would sign an input whose signature commits only to that input's own
    /// amount, while some input in the file states an amount nothing proves.
    ///
    /// This is BIP-174's line 415 footnote, in its own words: "the amounts in
    /// PSBT_IN_WITNESS_UTXO of other segwit inputs can be modified without effecting the
    /// signature for a particular input. In order to prevent this kind of attack, many
    /// wallets are requiring that the full previous transaction ... be provided to ensure
    /// that the amounts of OTHER inputs are not being tampered with." The demand is about
    /// the other inputs, and scoping it to the input being signed - which this crate did
    /// between 2026-08-18 and the same day's second pass - removed the protection while
    /// leaving the sentence that describes it in place.
    ///
    /// What it costs is a full coin. Ownership in a PSBT is decided by metadata the
    /// coordinator writes, so deleting `bip32_derivation` from one of the user's own
    /// inputs turns that input into a stranger's and its amount into a free lie. Present
    /// two of the user's 1 BTC coins twice, each round proving one and claiming 20000 sat
    /// for the other, and both rounds display the same ordinary fee, this device signs one
    /// input per round over its own REAL amount, and the two signatures combine into one
    /// valid transaction that burns 0.9999 BTC. Every number on both screens is the number
    /// the user expected, which is why this is a refusal and not a caveat: a warning
    /// cannot be attached to a figure that is not wrong.
    ///
    /// `signing` is an input this device would sign whose sighash covers one amount;
    /// `unproven` is an input whose amount rests on nothing. Both are named because the
    /// pair is what makes the file unsignable, and either end may be the one the sender can
    /// fix.
    UnprovenAmountBesideOurSignature { signing: u16, unproven: u16 },
    PrevoutIndexOutOfRange {
        index: u16,
        vout: u32,
        outputs: usize,
    },
    /// The supplied previous transaction is not the one the input spends.
    PrevTxidMismatch { index: u16 },
    /// `witness_utxo` and the full transaction disagree about the amount.
    PrevAmountMismatch {
        index: u16,
        non_witness: Amount,
        witness: Amount,
    },
    /// The same disagreement about the script.
    PrevScriptMismatch { index: u16 },

    // -- Check 5: network isolation ------------------------------------------------------
    /// A path of ours claims a coin type the device's network does not use.
    CoinTypeMismatch {
        at: Location,
        found: u32,
        expected: u32,
    },

    // -- Check 1: input ownership (the half that needs no key) ---------------------------
    /// More than one origin in one input names our fingerprint. For a single-sig input
    /// there is exactly one key to sign with, and guessing which is not a decision a
    /// signer gets to make.
    AmbiguousOwnershipClaim { index: u16, claims: usize },
    PathTooShallow { at: Location, depth: usize },
    PathTooDeep {
        at: Location,
        depth: usize,
        max: u8,
    },
    /// Not one of BIP44, BIP48, BIP49, BIP84, BIP86. An arbitrary path is how the 2019
    /// Coldcard change-path ransom worked: a key the user can never re-derive.
    PathOutsidePurposeWhitelist { at: Location, purpose: u32 },
    /// The hardened steps are not a prefix of the path, or there are fewer than three of
    /// them. Every BIP44-family path is hardened down to the account and unhardened below
    /// it; anything else is a shape no wallet software will recover from a seed backup.
    PathHardenedShapeInvalid { at: Location },
    /// The public key the origin names is not the key the input's script commits to. The
    /// origin and the script would then describe different keys, and only one of them can
    /// be what the coordinator meant.
    ClaimedKeyNotInScript { index: u16 },
    /// A P2SH input whose redeem script does not hash to its own scriptPubKey.
    RedeemScriptDoesNotMatchInput { index: u16 },

    // -- Check 4: multisig binding -------------------------------------------------------
    /// An input claims our key and its script is none of the four this device spends:
    /// P2WPKH, P2SH-P2WPKH, P2TR key-path or a REGISTERED P2WSH sortedmulti. P2SH and
    /// P2SH-P2WSH multisig land here by design (OPEN-QUESTIONS Q7).
    ClaimedInputNotSingleSig { index: u16, kind: ScriptKind },
    /// A P2WSH input of ours with no registration in scope at all. Signing statelessly,
    /// where Q11 and Q24 make a multisig claim a refusal with no override: without a
    /// registration the cosigner set and the witness-script membership are both
    /// unverifiable, and believing the PSBT's own account of them is the 2021 attack.
    MultisigStatelessUnverifiable { index: u16 },
    /// A P2WSH input of ours that no registered wallet rebuilds at the path it claims.
    /// Either the wallet was never registered on this device or the script is not the one
    /// the registration produces; the device cannot tell those apart and must refuse
    /// either way.
    MultisigNotRegistered { index: u16 },
    /// A P2WSH input of ours carrying no `witness_script`. BIP-174 requires the field, the
    /// post-sign gate reads it back independently, and a signature over a script only one
    /// side of the device can see is not one this device will produce.
    MultisigWitnessScriptMissing { index: u16 },
    /// The `witness_script` the PSBT supplied is not the one the registration builds at
    /// the claimed leaf, even though the scriptPubKey matched. Only reachable from a
    /// deliberately inconsistent file, and it is a refusal rather than a silent preference
    /// for our own copy so that the post-sign gate - which re-reads the PSBT's field - can
    /// never be checking a different script than the one that was signed.
    MultisigWitnessScriptMismatch { index: u16 },

    // -- Check 7: sighash whitelist ------------------------------------------------------
    /// Anything but SIGHASH_ALL on a segwit-v0 input or SIGHASH_DEFAULT on a taproot one.
    /// No override exists, in 0.2.0 or later (Q24): SINGLE, NONE and ANYONECANPAY are how
    /// outputs get swapped after a signature is taken.
    SighashTypeNotWhitelisted { index: u16, found: u32 },

    // -- Check 8: taproot ----------------------------------------------------------------
    /// A witness carrying a taproot annex. rust-bitcoin's key-spend digest does not commit
    /// to one, so a signature produced here would not cover it: refusing is the only
    /// honest answer.
    TaprootAnnexPresent { index: u16 },
    /// A taproot input of ours with no `tap_internal_key`, so the tweak cannot be checked.
    TaprootInternalKeyMissing { index: u16 },
    /// The origin's key is not the input's declared internal key.
    TaprootInternalKeyMismatch { index: u16 },
    /// The declared internal key, tweaked with the declared merkle root, is not the output
    /// key in the scriptPubKey. Signing anyway produces a signature under a key the
    /// verifier will not use, or worse, under one the coordinator chose.
    TaprootTweakMismatch { index: u16 },
    /// A script-path spend. The leaf would have to come from a registered descriptor
    /// (ARCH check 8); this crate has no registry. notyas-wallet reports the same
    /// condition as `TaprootLeafNotRegistered`.
    TaprootScriptPathUnsupported { index: u16 },

    // -- Check 3: change derivation ------------------------------------------------------
    /// One output map names this device in more origins than any wallet of ours has keys
    /// at a leaf. See [`StructuralLimits::max_own_output_origins`]: each such origin buys
    /// a re-derivation of one of our wallets, so an unbounded map is unbounded work on a
    /// file an attacker wrote.
    ///
    /// A refusal and not a truncation. Ignoring the tail would leave the device reviewing
    /// a file whose change it had decided not to look at, and silently reviewing less than
    /// the file says is how a change output goes unrecognised.
    TooManyOwnOutputOrigins {
        at: Location,
        found: usize,
        max: u8,
    },
    /// The output maps TOGETHER name this device in more origins than a transaction of
    /// ours could. See [`StructuralLimits::max_own_origins_in_file`]: the per-output bound
    /// leaves the file free to repeat itself 255 times, which is 3,825 origins and hours
    /// of derivation, so the file needs a bound of its own.
    TooManyOwnOriginsInFile { found: usize, max: u16 },
    /// Proving what the outputs claim would cost more key derivations than the device will
    /// spend on one file. See [`StructuralLimits::max_change_derivations`].
    ///
    /// `at` is where the budget ran out, not where the fault is: what exhausts it is the
    /// file as a whole, and an earlier output is as likely to have paid for it as this
    /// one. It is here because a refusal a user can act on has to say how far the device
    /// got.
    ///
    /// A refusal and not a truncation, for the same reason as
    /// [`TooManyOwnOutputOrigins`](CheckFailure::TooManyOwnOutputOrigins) and with more at
    /// stake: giving up quietly on the rest of the outputs would leave a change output
    /// unproven for want of budget rather than for want of proof, and an unproven change
    /// output reads as money leaving on the one screen the user is deciding from.
    ChangeDerivationBudgetExhausted { at: Location, max: u32 },

    // -- Check 6: fee --------------------------------------------------------------------
    /// Summing inputs or outputs left the range of `Amount`. Only reachable from a file
    /// that is already impossible, and it must be a refusal rather than a panic.
    FeeArithmeticOverflow,
    /// Outputs exceed inputs. Not a transaction, and a signature over it is a signature
    /// over a lie about what the device was told the inputs were worth.
    NegativeFee {
        input_total: Amount,
        output_total: Amount,
    },
}

impl CheckFailure {
    /// Which of the ten checks refused. This is what lets a refusal screen cite the design
    /// document rather than an error string.
    pub fn check(&self) -> Check {
        use CheckFailure::*;
        match self {
            PsbtVersionUnsupported { .. }
            | PsbtTooLarge { .. }
            | NoInputs
            | NoOutputs
            | TooManyInputs { .. }
            | TooManyOutputs { .. }
            | InputMapCountMismatch { .. }
            | OutputMapCountMismatch { .. }
            | DuplicateInput { .. }
            | InputAlreadyFinalized { .. } => Check::GlobalSanity,

            MissingPrevout { .. }
            | MissingPreviousTransaction { .. }
            | UnprovenAmountBesideOurSignature { .. }
            | PrevoutIndexOutOfRange { .. }
            | PrevTxidMismatch { .. }
            | PrevAmountMismatch { .. }
            | PrevScriptMismatch { .. } => Check::Prevouts,

            CoinTypeMismatch { .. } => Check::NetworkIsolation,

            AmbiguousOwnershipClaim { .. }
            | PathTooShallow { .. }
            | PathTooDeep { .. }
            | PathOutsidePurposeWhitelist { .. }
            | PathHardenedShapeInvalid { .. }
            | ClaimedKeyNotInScript { .. }
            | RedeemScriptDoesNotMatchInput { .. } => Check::InputOwnership,

            ClaimedInputNotSingleSig { .. }
            | MultisigStatelessUnverifiable { .. }
            | MultisigNotRegistered { .. }
            | MultisigWitnessScriptMissing { .. }
            | MultisigWitnessScriptMismatch { .. } => Check::MultisigBinding,

            TooManyOwnOutputOrigins { .. }
            | TooManyOwnOriginsInFile { .. }
            | ChangeDerivationBudgetExhausted { .. } => Check::ChangeDerivation,

            SighashTypeNotWhitelisted { .. } => Check::SighashWhitelist,

            TaprootAnnexPresent { .. }
            | TaprootInternalKeyMissing { .. }
            | TaprootInternalKeyMismatch { .. }
            | TaprootTweakMismatch { .. }
            | TaprootScriptPathUnsupported { .. } => Check::Taproot,

            FeeArithmeticOverflow | NegativeFee { .. } => Check::Fee,
        }
    }
}

impl fmt::Display for CheckFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use CheckFailure::*;
        write!(f, "{}: ", self.check())?;
        match self {
            PsbtVersionUnsupported { version } => {
                write!(f, "PSBT version {version} is not supported, only version 0")
            }
            PsbtTooLarge { bytes, max } => {
                write!(f, "the PSBT is {bytes} bytes, over the {max} byte limit")
            }
            NoInputs => write!(f, "the transaction has no inputs"),
            NoOutputs => write!(f, "the transaction has no outputs"),
            TooManyInputs { found, max } => write!(f, "{found} inputs, over the limit of {max}"),
            TooManyOutputs { found, max } => write!(f, "{found} outputs, over the limit of {max}"),
            TooManyOwnOutputOrigins { at, found, max } => write!(
                f,
                "{at} names this wallet in {found} key origins, over the limit of {max}"
            ),
            TooManyOwnOriginsInFile { found, max } => write!(
                f,
                "the outputs name this wallet in {found} key origins, \
                 over the limit of {max} for one transaction"
            ),
            ChangeDerivationBudgetExhausted { at, max } => write!(
                f,
                "checking which outputs are change would cost more than this device \
                 spends on one transaction: the budget of {max} key derivations ran \
                 out at {at}"
            ),
            InputMapCountMismatch { maps, tx_inputs } => write!(
                f,
                "{maps} input records for {tx_inputs} transaction inputs"
            ),
            OutputMapCountMismatch { maps, tx_outputs } => write!(
                f,
                "{maps} output records for {tx_outputs} transaction outputs"
            ),
            DuplicateInput {
                first,
                second,
                outpoint,
            } => write!(f, "inputs {first} and {second} both spend {outpoint}"),
            InputAlreadyFinalized { index } => write!(f, "input {index} is already finalized"),
            MissingPrevout { index } => {
                write!(f, "input {index} does not say what it is worth")
            }
            MissingPreviousTransaction { index } => write!(
                f,
                "input {index} has no previous transaction, which is required for anything but taproot"
            ),
            UnprovenAmountBesideOurSignature { signing, unproven } => write!(
                f,
                "input {unproven} has no previous transaction to prove what it is worth, \
                 and signing input {signing} would not commit to it"
            ),
            PrevoutIndexOutOfRange {
                index,
                vout,
                outputs,
            } => write!(
                f,
                "input {index} spends output {vout} of a transaction with {outputs} outputs"
            ),
            PrevTxidMismatch { index } => write!(
                f,
                "the previous transaction given for input {index} is not the one it spends"
            ),
            PrevAmountMismatch {
                index,
                non_witness,
                witness,
            } => write!(
                f,
                "input {index} is worth {non_witness} by its previous transaction and {witness} by its own claim"
            ),
            PrevScriptMismatch { index } => write!(
                f,
                "input {index} and its previous transaction disagree about the output script"
            ),
            CoinTypeMismatch {
                at,
                found,
                expected,
            } => write!(f, "{at} uses coin type {found}, not {expected}"),
            AmbiguousOwnershipClaim { index, claims } => write!(
                f,
                "input {index} names this device {claims} times and there is only one key to sign with"
            ),
            PathTooShallow { at, depth } => {
                write!(f, "{at} claims a path only {depth} levels deep")
            }
            PathTooDeep { at, depth, max } => {
                write!(f, "{at} claims a path {depth} levels deep, over the limit of {max}")
            }
            PathOutsidePurposeWhitelist { at, purpose } => write!(
                f,
                "{at} claims purpose {purpose}, which is not one this device uses"
            ),
            PathHardenedShapeInvalid { at } => {
                write!(f, "{at} claims a path whose hardened steps are not its first three or more")
            }
            ClaimedKeyNotInScript { index } => write!(
                f,
                "the key named for input {index} is not the key that input can be spent with"
            ),
            RedeemScriptDoesNotMatchInput { index } => write!(
                f,
                "the redeem script given for input {index} does not belong to it"
            ),
            ClaimedInputNotSingleSig { index, kind } => write!(
                f,
                "input {index} is {kind}, which is not a script this device spends"
            ),
            MultisigStatelessUnverifiable { index } => write!(
                f,
                "input {index} is multisig and no multisig wallet is registered on this device"
            ),
            MultisigNotRegistered { index } => write!(
                f,
                "input {index} is multisig and no registered wallet builds that script"
            ),
            MultisigWitnessScriptMissing { index } => write!(
                f,
                "multisig input {index} does not carry the script it is locked to"
            ),
            MultisigWitnessScriptMismatch { index } => write!(
                f,
                "the script given for multisig input {index} is not the one the registered wallet builds"
            ),
            SighashTypeNotWhitelisted { index, found } => write!(
                f,
                "input {index} asks for sighash type {found}; only SIGHASH_ALL and SIGHASH_DEFAULT are signed"
            ),
            TaprootAnnexPresent { index } => {
                write!(f, "input {index} carries a taproot annex")
            }
            TaprootInternalKeyMissing { index } => {
                write!(f, "taproot input {index} does not declare its internal key")
            }
            TaprootInternalKeyMismatch { index } => write!(
                f,
                "the key named for taproot input {index} is not the internal key it declares"
            ),
            TaprootTweakMismatch { index } => write!(
                f,
                "the internal key of taproot input {index} does not tweak to the key it is locked to"
            ),
            TaprootScriptPathUnsupported { index } => write!(
                f,
                "input {index} is a taproot script-path spend, which needs a registered descriptor"
            ),
            FeeArithmeticOverflow => write!(f, "the amounts in this transaction do not add up"),
            NegativeFee {
                input_total,
                output_total,
            } => write!(
                f,
                "outputs total {output_total} against inputs of {input_total}"
            ),
        }
    }
}

impl core::error::Error for CheckFailure {}

// ---------------------------------------------------------------------------------------
// The facts a review screen renders
// ---------------------------------------------------------------------------------------

/// What kind of output script this is. Enough to decide signability and to label a review
/// row; not a script analyser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptKind {
    P2pkh,
    /// P2SH whose redeem script the PSBT did not supply, or supplied as something other
    /// than a P2WPKH program.
    P2sh,
    /// P2SH wrapping a P2WPKH program (BIP49). Only distinguishable from `P2sh` when the
    /// PSBT supplies the redeem script, which BIP-174 requires it to.
    P2shP2wpkh,
    P2wpkh,
    P2wsh,
    P2tr,
    OpReturn,
    Other,
}

impl ScriptKind {
    /// Whether [`super::sign`] can produce a signature for an input of this kind. The
    /// three that answer yes are exactly BIP84, BIP49 and BIP86 key-path.
    pub fn is_single_sig(self) -> bool {
        matches!(
            self,
            ScriptKind::P2wpkh | ScriptKind::P2shP2wpkh | ScriptKind::P2tr
        )
    }
}

impl fmt::Display for ScriptKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            ScriptKind::P2pkh => "a legacy address",
            ScriptKind::P2sh => "a script address",
            ScriptKind::P2shP2wpkh => "a wrapped segwit address",
            ScriptKind::P2wpkh => "a segwit address",
            ScriptKind::P2wsh => "a segwit script address",
            ScriptKind::P2tr => "a taproot address",
            ScriptKind::OpReturn => "a data output",
            ScriptKind::Other => "an unrecognised script",
        };
        f.write_str(name)
    }
}

/// How firmly this device knows what an input is worth.
///
/// Two states and not three: an input that states no amount at all never reaches an
/// [`InputFacts`], because [`CheckFailure::MissingPrevout`] refuses the file first.
///
/// The distinction exists because the fee is a sum over EVERY input, so the moment one
/// amount is only claimed the fee is only claimed too, and a signer that renders an
/// unprovable number the same way it renders a proven one has lied by omission.
///
/// This device's own exposure IS at stake, and a comment here said otherwise until
/// 2026-08-18. The argument it made - that what we can lose is our inputs minus the change
/// we proved, so a foreign amount only moves a cosigner's money - assumes the file's
/// account of who owns what is true. Nothing checks that: ownership is decided by
/// `bip32_derivation`, which the coordinator writes, so a coin of OURS presented without
/// its origin is a "foreign" input whose claimed amount we will happily take on trust
/// while signing the coin next to it for its real value. The two rounds of that trick
/// combine into one transaction, which is the attack BIP-174's line 415 footnote is about.
///
/// So [`AmountProof::ClaimedByFile`] is safe in exactly one place, and it is a property of
/// the DIGEST rather than of who owns what: a signature of ours that commits to every
/// input amount at once makes a claimed amount binding, because substituting it produces a
/// transaction that cannot confirm. BIP-341 with a whitelisted flag is that signature and
/// BIP-143 is not, which is what
/// [`CheckFailure::UnprovenAmountBesideOurSignature`] enforces and
/// [`Inspection::fee_is_enforced`] reads from the other end.
///
/// A review screen has to render the two differently, which is the whole reason this is a
/// public type and not a private flag:
///
/// ```
/// use notyas_core::psbt::{AmountProof, InputFacts};
///
/// /// What a review row has to say about the number beside it.
/// fn caveat(facts: &InputFacts) -> Option<&'static str> {
///     match facts.amount_proof {
///         AmountProof::ProvenByPrevTx => None,
///         AmountProof::ClaimedByFile => Some("stated by the file, not proven"),
///     }
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmountProof {
    /// The full previous transaction was supplied and hashes to the txid this input
    /// spends, so the amount and the script are that transaction's own and not anybody's
    /// assertion about it.
    ProvenByPrevTx,
    /// `witness_utxo` alone. Nothing binds it to the outpoint, so it is the file's word.
    /// Only reachable for an input this device will not sign, or for a taproot input,
    /// whose amount BIP-341 makes binding on the signature instead
    /// ([`Inspection::fee_is_enforced`]).
    ClaimedByFile,
}

/// The public key an origin names, in whichever form its script type uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimedKey {
    /// 33-byte compressed, for P2WPKH and P2SH-P2WPKH.
    Ecdsa(bitcoin::secp256k1::PublicKey),
    /// x-only internal key, for P2TR.
    Taproot(XOnlyPublicKey),
}

/// Where a multisig input's script came from, once check 4 has rebuilt it.
///
/// Every field here was produced by [`crate::multisig::Registration`] and none of it was
/// read out of the PSBT. That is deliberate and it is the point: [`super::sign`] and the
/// post-sign gate both need the witness script, and if either reached back into the input
/// map for it, the thing signed would be the coordinator's script rather than the
/// registered wallet's. `inspect` proves the PSBT's copy equals this one, and then this
/// one is what travels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultisigBinding {
    /// Which registered wallet rebuilt the script, by its content-derived id.
    pub registration: RegistrationId,
    pub keychain: Keychain,
    /// The leaf index under that keychain.
    pub address_index: u32,
    /// `OP_M ... OP_N OP_CHECKMULTISIG`, rebuilt with BIP-67 ordering.
    pub witness_script: ScriptBuf,
    /// Our own cosigner's key at this leaf, from the REGISTRATION. [`super::sign`] derives
    /// from the seed and compares against this, so its derive-and-compare is against the
    /// registry and not against anything the file said.
    pub our_key: CompressedPublicKey,
}

/// Which wallet of this device's own rebuilt an output's script.
///
/// Two kinds of wallet prove ownership two ways, and this is the one place that difference
/// is named, so that everything downstream - the review row, the log line, the netting of
/// change out of what leaves - reads one verdict instead of two.
///
/// Whichever it is, the value could only have come from the seed: a [`RegistrationId`]
/// names a [`Registration`] that [`crate::multisig::Pending::verify`] produced, and an
/// [`AccountId`] names an [`Account`] that [`Account::derive`] produced. Neither can be
/// assembled out of a PSBT, which is the whole of what check 3 rests on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Owner {
    /// A multisig wallet this device proved it is a member of (m7).
    Registered(RegistrationId),
    /// A single-sig account of this device's own seed.
    Account(AccountId),
}

impl fmt::Display for Owner {
    /// The wallet's own name in either case: a registration's content-derived id, or an
    /// account's scheme and index (`bip84/0`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Owner::Registered(id) => write!(f, "{id}"),
            Owner::Account(id) => write!(f, "{id}"),
        }
    }
}

/// What the device can prove about where one output's money goes.
///
/// Four states, not two, because "is this change" has more than one honest negative answer
/// and a signer that collapses them is the 2019 Coldcard change-confusion bug. `Change` is
/// the only one that is change, and [`OutputRole::is_change`] is the only way to ask.
///
/// The two proven variants carry an [`Owner`] rather than a registration id, which is what
/// the field held while a registered multisig wallet was the only thing that could own an
/// output. It is destructured BY NAME where the device logs a review, so the name is part
/// of the contract with that log site and not a local detail;
/// `a_proven_role_names_its_owner_by_field` is the test that says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputRole {
    /// No origin in this output's map names this device. Money leaving, and the only
    /// honest label for it.
    Payment,
    /// The file says this output is ours and the device could not prove it.
    ///
    /// That covers three very different files and deliberately does not distinguish them
    /// here, because what they buy is identical: a coordinator that attached our
    /// fingerprint to its own address - the change-confusion attack, where the claim is a
    /// lie; a claim against a wallet this session did not put in scope, which is an empty
    /// [`Context::registry`] or [`inspect`] called where [`inspect_with_accounts`] was
    /// meant; and a leaf further along a keychain than the device will follow (the gap
    /// bound, at `prove_account_output`). In every case it is NOT change: it counts as a
    /// payment everywhere money is counted, and the variant exists only so a review screen
    /// can say the claim was made and not believed rather than dropping it.
    ClaimedButUnproven,
    /// A wallet of ours rebuilds this exact script on its RECEIVE keychain. Ours, and not
    /// this transaction's change (WALLET-API.md's `OwnNotChange`): a self-send to a
    /// receive address is a real thing a user may mean, and calling it change would net it
    /// out of the amount leaving and understate what the transaction does.
    OwnNotChange { owner: Owner, index: u32 },
    /// A wallet of ours rebuilds this exact script on its CHANGE keychain, at the leaf the
    /// file claimed. The only role that is change.
    Change { owner: Owner, index: u32 },
}

impl OutputRole {
    /// The one question this enum exists to answer. Written as a method so that no caller
    /// has to remember which variants are and are not change, and so that adding a variant
    /// forces this line to be revisited instead of silently defaulting a new state to
    /// "change".
    pub fn is_change(self) -> bool {
        match self {
            OutputRole::Change { .. } => true,
            OutputRole::Payment
            | OutputRole::ClaimedButUnproven
            | OutputRole::OwnNotChange { .. } => false,
        }
    }
}

/// Whether an input says this device can spend it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Claim {
    /// No origin here names our master fingerprint. Shown on the review screen, never
    /// signed, and never silently dropped.
    Foreign,
    /// Exactly one origin names our fingerprint, its path has a sane shape, its coin type
    /// matches, and the key it names is the key the script commits to. Still a claim:
    /// [`super::sign`] proves it by derivation before it signs.
    Ours { path: DerivationPath, key: ClaimedKey },
}

/// Everything the engine established about one input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputFacts {
    pub index: u16,
    pub outpoint: OutPoint,
    pub value: Amount,
    /// Whether `value` and `script_pubkey` were proven or taken on trust. Kept per input
    /// rather than as one flag on the [`Inspection`] so a review screen can point at the
    /// row the caveat is about.
    pub amount_proof: AmountProof,
    pub script_pubkey: ScriptBuf,
    /// Present only for P2SH inputs; carried because signing and the post-sign gate both
    /// need the script code and neither should reach back into the PSBT for it.
    pub redeem_script: Option<ScriptBuf>,
    pub kind: ScriptKind,
    pub claim: Claim,
    /// Present exactly when this is a P2WSH input of ours: which registered wallet builds
    /// its script, and everything signing needs about that leaf. `None` for every
    /// single-sig input and for every input that is not ours.
    pub multisig: Option<MultisigBinding>,
    /// The merkle root a taproot input's output key is tweaked with. `None` for BIP86.
    pub tap_merkle_root: Option<bitcoin::taproot::TapNodeHash>,
}

/// Everything the engine established about one output.
///
/// `claims_our_key` and `role` are evidence and verdict, and they are separate fields for
/// the reason the whole of check 3 exists: what a file asserts about an output is not what
/// the device has established about it. `claims_our_key` is what the PSBT said.
/// [`OutputRole`] is what this crate could prove: everything, for an output of a
/// registered multisig wallet (m7) or of an account in scope, and nothing for a claim
/// against a wallet the session did not put in scope, which is the same verdict a forged
/// claim gets.
///
/// The two are computed together in one pass so they cannot drift: `role` is
/// [`OutputRole::Payment`] exactly when `claims_our_key` is false.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputFacts {
    pub index: u16,
    pub value: Amount,
    pub script_pubkey: ScriptBuf,
    pub kind: ScriptKind,
    /// An origin on this output names our fingerprint. Evidence for the change check,
    /// never a substitute for it.
    pub claims_our_key: bool,
    /// What the device established, as opposed to what the file asserted.
    pub role: OutputRole,
}

/// The result of a clean pass: the facts, and the identity of the bytes they came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inspection {
    psbt_id: [u8; 32],
    unsigned_id: [u8; 32],
    pub network: Network,
    pub fingerprint: Fingerprint,
    pub serialized_len: usize,
    pub inputs: Vec<InputFacts>,
    pub outputs: Vec<OutputFacts>,
    pub input_total: Amount,
    pub output_total: Amount,
    /// `input_total - output_total`. Non-negative by construction: a negative fee is a
    /// refusal, so no caller has to handle the case.
    pub fee: Amount,
    /// How many unknown and proprietary key-value pairs the file carries, across the
    /// global map and every input and output map. They are preserved through signing and
    /// re-emission and are never read for any decision; this count exists so the review
    /// screen can say they are there (WALLET-API.md `UnknownPsbtFieldsPresent`).
    pub unknown_fields: usize,
    pub lock_time: absolute::LockTime,
    /// Any input signals replaceability (BIP125).
    pub rbf_signaled: bool,
}

impl Inspection {
    /// SHA-256 of the PSBT this inspection was taken from. [`super::sign`] recomputes it
    /// and refuses on a mismatch, which is what makes "sign what was reviewed" a checked
    /// property rather than a hope.
    pub fn psbt_id(&self) -> [u8; 32] {
        self.psbt_id
    }

    /// SHA-256 of the same PSBT with its signature fields cleared
    /// ([`super::unsigned_id`]). [`super::verify_signatures`] checks this one rather than
    /// [`Inspection::psbt_id`], because by the time the post-sign gate runs the file
    /// carries signatures the reviewed bytes did not; see [`super::unsigned_id`] for why
    /// that is the strongest binding the gate can be given rather than a relaxation of
    /// this one.
    pub fn unsigned_id(&self) -> [u8; 32] {
        self.unsigned_id
    }

    /// Whether [`Inspection::fee`] is a number that any transaction carrying this device's
    /// signature would actually have to pay.
    ///
    /// Two ways to get there, and the second is the one worth stating. Either every input
    /// amount was proven against its own previous transaction, or this device is about to
    /// commit to all of them at once: BIP-341 hashes `sha_amounts` over every input of the
    /// transaction, so a key-path signature of ours under a whitelisted flag makes the
    /// claimed amounts the only amounts under which that signature verifies. Lying about
    /// one then costs the coordinator a transaction that cannot confirm, not a fee the user
    /// was never shown.
    ///
    /// The second clause reads the same predicate the amount-substitution refusal does
    /// ([`CheckFailure::UnprovenAmountBesideOurSignature`]), which is deliberate: they are
    /// one fact seen from two ends, and two spellings of it would eventually disagree about
    /// which signatures bind which amounts.
    ///
    /// `false` is not a refusal and must not become one - the only files that reach here
    /// with `false` are ones this device signs nothing in, or signs nothing SEGWIT V0 in.
    /// It is a fact the review screen has to render differently, next to the input whose
    /// [`InputFacts::amount_proof`] is [`AmountProof::ClaimedByFile`], and a fee threshold
    /// (check 6, notyas-wallet) has to read as a lower bound rather than a measurement.
    pub fn fee_is_enforced(&self) -> bool {
        if self
            .inputs
            .iter()
            .all(|i| i.amount_proof == AmountProof::ProvenByPrevTx)
        {
            return true;
        }
        self.signable_inputs() > 0 && self.every_signature_of_ours_covers_every_amount()
    }

    /// Whether every signature this device would add commits to the amount of every input,
    /// rather than only to the amount of the input it is on.
    ///
    /// Vacuously true of a file this device signs nothing in, which is why
    /// [`Inspection::fee_is_enforced`] asks for a signature to exist before it asks this.
    fn every_signature_of_ours_covers_every_amount(&self) -> bool {
        self.ours()
            .all(|i| commits_to_every_amount(i.kind, whitelisted_sighashes(i.kind)))
    }

    /// The inputs this device would sign.
    ///
    /// The one place this type spells that predicate, so the count, the list and the total
    /// below cannot disagree about which rows the batch is - which is the whole of what an
    /// approval screen is showing when it shows a batch.
    fn ours(&self) -> impl Iterator<Item = &InputFacts> {
        self.inputs
            .iter()
            .filter(|i| matches!(i.claim, Claim::Ours { .. }))
    }

    /// How many inputs this device would sign.
    pub fn signable_inputs(&self) -> usize {
        self.ours().count()
    }

    // -- The batch one approval covers (0.2.0-G10) --------------------------------------
    //
    // A batch is not a second signing mode: `sign` has always signed every input an
    // inspection classified as ours, so what "Sign All" needs is not new machinery but an
    // honest account of what the one approval is about to buy. These accessors are that
    // account, and they are METHODS ON THE INSPECTION rather than a summary value the
    // caller assembles, for the reason batch approval goes wrong: a screen that renders
    // one thing and a signature that covers another. `sign` refuses any inspection but the
    // one whose bytes it is holding, so a summary taken from this value is a summary of
    // exactly what will be signed, and there is no second object for the two to disagree
    // through.
    //
    // Every number here is a total over the WHOLE file rather than over the batch, except
    // where its name says otherwise: `input_total`, `output_total` and `fee` already are,
    // and `fee` is only a number the transaction must pay when `fee_is_enforced` says so.
    // A batch of ours beside a cosigner's inputs is the ordinary multi-party case, and a
    // review that quietly counted only our own rows would understate the transaction the
    // user is signing into.

    /// Which inputs this device will sign, ascending, which is the order [`super::sign`]
    /// signs them in.
    ///
    /// The batch, named. One approval buys one signature per entry, so this is the list an
    /// approval screen has to show and the list [`super::sign`] is held to afterwards: it
    /// rebuilds the same list from the same predicate and refuses to release a file whose
    /// signatures are not exactly these
    /// ([`super::SignFailure::BatchDiffersFromReview`]).
    pub fn signable_input_indexes(&self) -> Vec<u16> {
        self.ours().map(|i| i.index).collect()
    }

    /// What the inputs of this batch are worth: the coins one approval spends.
    ///
    /// Below [`Inspection::input_total`] exactly when the file also carries inputs this
    /// device does not sign, which is what a multi-party transaction looks like. Neither
    /// number is a substitute for the other, and a review screen that showed only this one
    /// would tell a cosigner their 2-of-3 spend was smaller than it is.
    pub fn signable_input_total(&self) -> Amount {
        // The fallback is a true upper bound and errs toward showing MORE money committed
        // than really is, which is the direction a person approving a spend can survive.
        // Unreachable: `inspect` summed every input with `checked_add`.
        total_of(self.ours().map(|i| i.value)).unwrap_or(self.input_total)
    }

    /// Value this file returns to the wallet as PROVEN change ([`OutputRole::Change`]).
    ///
    /// Only what was proven is in this sum, which is the same conservative reading
    /// [`OutputRole`] documents, arrived at once here so that a batch review cannot net
    /// out a "change" output nobody proved. An output nothing in scope re-derives is
    /// counted as money leaving, so a file inspected without the wallet it belongs to -
    /// [`Context::registry`] empty, or [`inspect`] rather than [`inspect_with_accounts`] -
    /// reports zero change and OVERSTATES what the transaction sends. Safe, and not
    /// harmless: it is the number a user reads.
    pub fn change_total(&self) -> Amount {
        // Zero on the unreachable overflow, so change is understated and
        // `leaving_total` correspondingly overstated. See the note there.
        total_of(
            self.outputs
                .iter()
                .filter(|o| o.role.is_change())
                .map(|o| o.value),
        )
        .unwrap_or(Amount::ZERO)
    }

    /// What this transaction actually sends away: every output that is not proven change.
    ///
    /// The number a batch review has to lead with. [`Inspection::output_total`] counts
    /// change as an output, which for a consolidation of thirty inputs into one change
    /// address is the whole balance and says nothing about what the user is giving up.
    pub fn leaving_total(&self) -> Amount {
        // Partitions `output_total` with `change_total` by construction: every output is
        // change or it is not. The fallback is again the upper bound, so an impossible
        // overflow shows more leaving rather than less.
        total_of(
            self.outputs
                .iter()
                .filter(|o| !o.role.is_change())
                .map(|o| o.value),
        )
        .unwrap_or(self.output_total)
    }

    /// How many inputs state an amount the file has not proven
    /// ([`AmountProof::ClaimedByFile`]).
    ///
    /// Zero for most files. Above zero it is the caveat [`Inspection::fee`] and every
    /// total above it have to be rendered with, and [`Inspection::fee_is_enforced`] is the
    /// separate question of whether this device's own signatures make those amounts
    /// binding anyway.
    pub fn unproven_amounts(&self) -> usize {
        self.inputs
            .iter()
            .filter(|i| i.amount_proof == AmountProof::ClaimedByFile)
            .count()
    }
}

/// Sum a subset of one file's amounts, or `None` if that sum overflows.
///
/// It cannot: [`inspect`] adds every input and every output with `checked_add` and refuses
/// the file on overflow, so no subset of either can overflow after it returns. Written as
/// an `Option` anyway, and with a bound rather than a panic at each call site, because
/// this crate runs on a device that is holding a seed when it is called.
fn total_of(mut amounts: impl Iterator<Item = Amount>) -> Option<Amount> {
    amounts.try_fold(Amount::ZERO, |sum, value| sum.checked_add(value))
}

// ---------------------------------------------------------------------------------------
// The pipeline
// ---------------------------------------------------------------------------------------

/// The BIP44 purposes a path may claim.
///
/// Kept as a literal rather than built from [`crate::derive::Scheme`] because
/// `Scheme::purpose` is not a const fn; `the_purpose_whitelist_is_the_scheme_list` below is
/// what keeps the two from drifting.
const PURPOSE_WHITELIST: [u32; 5] = [44, 48, 49, 84, 86];

/// Validate a PSBT against a device context, with no key and no account in scope.
///
/// [`inspect_with_accounts`] with an empty slice, and every word of that function's
/// contract holds here. What is missing is only the single-sig half of check 3: with no
/// account to re-derive from, an output claiming to be ours can only be
/// [`OutputRole::ClaimedButUnproven`], so it counts as money leaving and the review
/// OVERSTATES what the transaction sends by the whole of its change. Safe, and the wrong
/// number to show anyone who has a session open - a caller holding the wallet's accounts
/// should pass them.
pub fn inspect(psbt: &Psbt, cx: &Context<'_>) -> Result<Inspection, CheckFailure> {
    inspect_with_accounts(psbt, cx, &[])
}

/// Validate a PSBT against a device context and the wallet's own single-sig accounts, with
/// no key in scope.
///
/// Returns the review facts, or the one named check that refused. See the module docs for
/// the order and for which of ARCHITECTURE.md's ten checks run here.
///
/// `accounts` is the second thing check 3 needs that no PSBT can supply, and it is exactly
/// as public as [`Context::registry`]: an [`Account`] holds an account xpub and cannot be
/// built without a seed, so the pipeline still derives nothing and still cannot. Accounts
/// on a network other than the context's are ignored rather than trusted - a device fact
/// that disagrees with the device is not one to reason from.
///
/// By rights this belongs beside `registry` on the [`Context`] itself, and it is a
/// parameter instead for a reason that is about the calendar and not the design: a field
/// added to `Context` is a field every caller has to fill in the same change, and the
/// firmware session that builds the context is not what this one touches. There is no
/// second code path either way - [`inspect`] is this function with an empty slice - so
/// moving it onto the context later is a rename and one call site.
pub fn inspect_with_accounts(
    psbt: &Psbt,
    cx: &Context<'_>,
    accounts: &[Account],
) -> Result<Inspection, CheckFailure> {
    let serialized = codec::encode(psbt);
    global_sanity(psbt, cx, serialized.len())?;

    let tx = &psbt.unsigned_tx;
    let expected_coin_type = coin_type_for(cx.network);

    let mut inputs = Vec::with_capacity(psbt.inputs.len());
    let mut input_total = Amount::ZERO;
    for (i, input) in psbt.inputs.iter().enumerate() {
        let index = i as u16;
        let outpoint = tx.input[i].previous_output;
        let (prevout, amount_proof) = resolve_prevout(input, outpoint, index)?;

        let redeem_script = input.redeem_script.clone();
        let kind = classify(&prevout.script_pubkey, redeem_script.as_deref());

        // Everything below applies only to an input that names this device. A foreign
        // input's fields are shown and never trusted, and refusing a whole transaction
        // because somebody else's input carries a field we dislike would make legitimate
        // coordinator output look like an attack.
        let claim = claim_for_input(input, index, kind, cx, expected_coin_type)?;
        let mut multisig = None;
        if let Claim::Ours { key, path } = &claim {
            // ARCH check 9's finalized clause, on the inputs it is actually about. What it
            // defends against is finalize-then-resign: a coordinator holding a complete
            // witness for an input of ours can come back for a second signature under a
            // different sighash and keep both. That argument reaches exactly as far as the
            // inputs this device signs. A finished witness on a cosigner's own input is
            // what a round of a multi-party signing IS, and refusing the file for it named
            // an input index the user had no way to act on, with no override to reach for
            // (Q24).
            //
            // INVARIANT: an input this device would sign is refused if it carries either
            // final field, and nothing in this file makes an exception to that.
            if input.final_script_sig.is_some() || input.final_script_witness.is_some() {
                return Err(CheckFailure::InputAlreadyFinalized { index });
            }
            // ARCH check 2, on the input being signed. What the previous transaction
            // proves is the amount, and the amount is what BIP-143 makes a signer commit to
            // on a coordinator's say-so: being told a false one twice is the 2020 Trezor
            // fee attack.
            //
            // Taproot is the exception it has always been: BIP-341 commits to every
            // prevout, so a lie about this input's amount moves the digest rather than the
            // money.
            //
            // This is HALF of check 2. The other half is about the other inputs and cannot
            // be decided one input at a time, so it runs over the finished facts below; see
            // `amounts_our_signatures_do_not_cover`.
            if amount_proof == AmountProof::ClaimedByFile && kind != ScriptKind::P2tr {
                return Err(CheckFailure::MissingPreviousTransaction { index });
            }
            if kind != ScriptKind::P2wsh && !kind.is_single_sig() {
                return Err(CheckFailure::ClaimedInputNotSingleSig { index, kind });
            }
            if let Some(redeem) = &redeem_script {
                if ScriptBuf::new_p2sh(&redeem.script_hash()) != prevout.script_pubkey {
                    return Err(CheckFailure::RedeemScriptDoesNotMatchInput { index });
                }
            }
            // The two branches make the same statement - the key this origin names is the
            // key this script can be spent with - and differ only in what has to be rebuilt
            // to check it. For single-sig that is a hash of one key; for multisig it is the
            // whole cosigner script, from a registration, which is check 4.
            if kind == ScriptKind::P2wsh {
                multisig = Some(bind_multisig(
                    input,
                    index,
                    &prevout.script_pubkey,
                    path,
                    *key,
                    cx,
                )?);
            } else {
                key_matches_script(
                    *key,
                    kind,
                    &prevout.script_pubkey,
                    redeem_script.as_deref(),
                    index,
                )?;
            }
            sighash_whitelisted(input, kind, index)?;
            if let ClaimedKey::Taproot(claimed) = key {
                taproot_tweak(input, *claimed, &prevout.script_pubkey, index)?;
            }
        }

        input_total = input_total
            .checked_add(prevout.value)
            .ok_or(CheckFailure::FeeArithmeticOverflow)?;

        inputs.push(InputFacts {
            index,
            outpoint,
            value: prevout.value,
            amount_proof,
            script_pubkey: prevout.script_pubkey,
            redeem_script,
            kind,
            claim,
            multisig,
            tap_merkle_root: input.tap_merkle_root,
        });
    }

    amounts_our_signatures_do_not_cover(&inputs)?;

    // Check 3's two bounds, and both are the FILE's rather than one output's: the work is
    // sized by maps the file writes, and a bound held per output leaves the product of the
    // two unbounded. The census refuses before any of it happens; the budget rations what
    // survives the census.
    own_origin_census(psbt, cx)?;
    let mut budget = ChangeDerivationBudget::new(cx.limits);

    let mut outputs = Vec::with_capacity(psbt.outputs.len());
    let mut output_total = Amount::ZERO;
    for (i, output) in psbt.outputs.iter().enumerate() {
        let index = i as u16;
        let txout = &tx.output[i];
        let at = Location::Output(index);
        let (claims_our_key, role) = classify_output(
            output,
            txout,
            at,
            cx,
            expected_coin_type,
            accounts,
            &mut budget,
        )?;

        output_total = output_total
            .checked_add(txout.value)
            .ok_or(CheckFailure::FeeArithmeticOverflow)?;

        outputs.push(OutputFacts {
            index,
            value: txout.value,
            script_pubkey: txout.script_pubkey.clone(),
            kind: classify(&txout.script_pubkey, None),
            claims_our_key,
            role,
        });
    }

    let fee = input_total
        .checked_sub(output_total)
        .ok_or(CheckFailure::NegativeFee {
            input_total,
            output_total,
        })?;

    Ok(Inspection {
        psbt_id: codec::psbt_id(psbt),
        unsigned_id: codec::unsigned_id(psbt),
        network: cx.network,
        fingerprint: cx.fingerprint,
        serialized_len: serialized.len(),
        inputs,
        outputs,
        input_total,
        output_total,
        fee,
        unknown_fields: count_unknown_fields(psbt),
        lock_time: tx.lock_time,
        rbf_signaled: tx.input.iter().any(|i| i.sequence.is_rbf()),
    })
}

/// ARCH check 9. Everything decidable from the shape of the file alone.
fn global_sanity(psbt: &Psbt, cx: &Context<'_>, serialized_len: usize) -> Result<(), CheckFailure> {
    if psbt.version != 0 {
        return Err(CheckFailure::PsbtVersionUnsupported {
            version: psbt.version,
        });
    }
    if serialized_len > cx.limits.max_psbt_bytes {
        return Err(CheckFailure::PsbtTooLarge {
            bytes: serialized_len,
            max: cx.limits.max_psbt_bytes,
        });
    }

    let tx = &psbt.unsigned_tx;
    if tx.input.is_empty() {
        return Err(CheckFailure::NoInputs);
    }
    if tx.output.is_empty() {
        return Err(CheckFailure::NoOutputs);
    }
    if tx.input.len() > usize::from(cx.limits.max_inputs) {
        return Err(CheckFailure::TooManyInputs {
            found: tx.input.len(),
            max: cx.limits.max_inputs,
        });
    }
    if tx.output.len() > usize::from(cx.limits.max_outputs) {
        return Err(CheckFailure::TooManyOutputs {
            found: tx.output.len(),
            max: cx.limits.max_outputs,
        });
    }
    if psbt.inputs.len() != tx.input.len() {
        return Err(CheckFailure::InputMapCountMismatch {
            maps: psbt.inputs.len(),
            tx_inputs: tx.input.len(),
        });
    }
    if psbt.outputs.len() != tx.output.len() {
        return Err(CheckFailure::OutputMapCountMismatch {
            maps: psbt.outputs.len(),
            tx_outputs: tx.output.len(),
        });
    }

    // Quadratic, and deliberately so: `max_inputs` bounds it at 255 pairs, and a BTreeMap
    // to make it linearithmic would allocate on every PSBT to save nothing measurable.
    for (i, a) in tx.input.iter().enumerate() {
        for (j, b) in tx.input.iter().enumerate().skip(i + 1) {
            if a.previous_output == b.previous_output {
                return Err(CheckFailure::DuplicateInput {
                    first: i as u16,
                    second: j as u16,
                    outpoint: a.previous_output,
                });
            }
        }
    }

    // The annex is the one thing about a finalized witness that is this device's business
    // whoever owns the input: it is a consensus field with no defined meaning, riding on
    // the transaction this device is being asked to help build, and a signer that cannot
    // say what a transaction does must not sign it. There is nowhere else in a v0 PSBT for
    // one to appear, which is what makes this reachable at all. The finalized-input
    // refusal that used to sit beside it is now in `inspect`, where the ownership claim it
    // depends on exists.
    for (i, input) in psbt.inputs.iter().enumerate() {
        if let Some(witness) = &input.final_script_witness {
            if witness.len() >= 2 {
                if let Some(last) = witness.last() {
                    if last.first() == Some(&0x50) {
                        return Err(CheckFailure::TaprootAnnexPresent { index: i as u16 });
                    }
                }
            }
        }
    }

    Ok(())
}

/// ARCH check 2. What an input spends, and how firmly the file establishes it.
///
/// This function answers the question and does not decide what to do about the answer:
/// whether [`AmountProof::ClaimedByFile`] is good enough depends on whether this device
/// signs the input, which is not known until its ownership claim has been read. What is
/// still refused here is what holds for every input whoever owns it: a previous
/// transaction that is not the one this input spends or does not reach the outpoint, a
/// `witness_utxo` that contradicts the one supplied, and an input that states no value at
/// all - the first three because a file at odds with itself is evidence of tampering
/// rather than of a cosigner's habits, the last because the fee is a sum over every
/// input.
fn resolve_prevout(
    input: &bitcoin::psbt::Input,
    outpoint: OutPoint,
    index: u16,
) -> Result<(TxOut, AmountProof), CheckFailure> {
    match (&input.non_witness_utxo, &input.witness_utxo) {
        (Some(prev), witness) => {
            if prev.compute_txid() != outpoint.txid {
                return Err(CheckFailure::PrevTxidMismatch { index });
            }
            let out = prev.output.get(outpoint.vout as usize).ok_or(
                CheckFailure::PrevoutIndexOutOfRange {
                    index,
                    vout: outpoint.vout,
                    outputs: prev.output.len(),
                },
            )?;
            if let Some(claimed) = witness {
                if claimed.value != out.value {
                    return Err(CheckFailure::PrevAmountMismatch {
                        index,
                        non_witness: out.value,
                        witness: claimed.value,
                    });
                }
                if claimed.script_pubkey != out.script_pubkey {
                    return Err(CheckFailure::PrevScriptMismatch { index });
                }
            }
            Ok((out.clone(), AmountProof::ProvenByPrevTx))
        }
        (None, Some(claimed)) => Ok((claimed.clone(), AmountProof::ClaimedByFile)),
        (None, None) => Err(CheckFailure::MissingPrevout { index }),
    }
}

/// ARCH check 2, the half that is about the OTHER inputs.
///
/// Refuse when this device will sign ANY input whose sighash does not commit to every input
/// amount, AND any input in the file carries an unproven amount.
///
/// That is BIP-174's line 415 footnote as written - "to ensure that the amounts of other
/// inputs are not being tampered with" - and it cannot be decided while walking one input,
/// because it is a statement about a pair of them. The refusal is what the blanket
/// "previous transaction for every input" rule used to buy, at the cost the blanket rule
/// did not charge:
///
/// - a cosigner's already-finalized input is still accepted, because a finished witness
///   says nothing about anybody's amount;
/// - a taproot spend of ours beside a cosigner's claimed amount is still accepted, because
///   `sha_amounts` puts every one of those amounts inside our own digest;
/// - a file this device signs nothing in is still readable, because there is no signature
///   of ours for a substituted amount to ride on;
/// - and the published BIP-174 vectors that the blanket rule refused stay unblocked, for
///   the same reason: this device's fingerprint is in none of them.
///
/// What it closes is the one combination that drains a wallet: a BIP-143 signature of ours,
/// which covers its own input's amount and no other, standing beside an amount the file
/// merely asserts. `check_2_refuses_an_unproven_amount_beside_a_segwit_v0_signature_of_ours`
/// is the pin, and `the_amount_substitution_probe_burns_a_coin_no_screen_could_have_named`
/// is what it costs when the rule is not there.
fn amounts_our_signatures_do_not_cover(inputs: &[InputFacts]) -> Result<(), CheckFailure> {
    let Some(unproven) = inputs
        .iter()
        .find(|i| i.amount_proof == AmountProof::ClaimedByFile)
    else {
        return Ok(());
    };
    let narrow = inputs.iter().find(|i| {
        matches!(i.claim, Claim::Ours { .. })
            && !commits_to_every_amount(i.kind, whitelisted_sighashes(i.kind))
    });
    match narrow {
        Some(signing) => Err(CheckFailure::UnprovenAmountBesideOurSignature {
            signing: signing.index,
            unproven: unproven.index,
        }),
        None => Ok(()),
    }
}

/// Whether a signature this device makes over an input of `kind`, under `admitted` and
/// nothing else, commits to the amount of EVERY input of the transaction.
///
/// Taproot is the only family that can, and it is `admitted` and not `kind` that decides
/// whether it does: BIP-341 hashes `sha_amounts` - every prevout of the transaction - into
/// the digest, but SIGHASH_ANYONECANPAY replaces that with this input's prevout alone, and
/// a signature under it would cover exactly as little as a BIP-143 one. BIP-143 covers one
/// amount under every flag it has, so segwit v0 answers no whatever the whitelist says.
///
/// INVARIANT: this reads the SAME list [`sighash_whitelisted`] enforces. It is a parameter
/// rather than a call so that a test can hand it a widened list and watch the answer turn
/// false - the coupling is the thing that keeps
/// [`CheckFailure::UnprovenAmountBesideOurSignature`] sound, and it must not be a comment.
fn commits_to_every_amount(kind: ScriptKind, admitted: &[u32]) -> bool {
    /// The bit that takes `sha_amounts` out of a BIP-341 digest.
    const SIGHASH_ANYONECANPAY: u32 = 0x80;
    kind == ScriptKind::P2tr
        && !admitted.is_empty()
        && admitted.iter().all(|flag| flag & SIGHASH_ANYONECANPAY == 0)
}

/// ARCH check 7's whitelist: every sighash flag this device will sign an input of `kind`
/// under, and the empty slice for a kind it will not sign at all.
///
/// One list, read by the enforcement in [`sighash_whitelisted`] and by the reasoning in
/// [`commits_to_every_amount`], because a device that admitted one flag while reasoning
/// about another would keep saying an amount was bound by a signature that no longer bound
/// it.
fn whitelisted_sighashes(kind: ScriptKind) -> &'static [u32] {
    match kind {
        // SIGHASH_ALL. P2WSH is here rather than in its own arm because BIP-143 gives
        // segwit v0 one flag encoding whatever the script code is; the multisig case
        // differs in what is hashed, never in what is whitelisted.
        ScriptKind::P2wpkh | ScriptKind::P2shP2wpkh | ScriptKind::P2wsh => &[0x01],
        // SIGHASH_DEFAULT. BIP-341 gives it the shorter signature, and accepting 0x01 as
        // well would let a coordinator pick the encoding of our witness.
        ScriptKind::P2tr => &[0x00],
        ScriptKind::P2pkh
        | ScriptKind::P2sh
        | ScriptKind::OpReturn
        | ScriptKind::Other => &[],
    }
}

/// ARCH checks 1 and 5, the halves that need no key: is this input claimed as ours, and if
/// so is the path it claims a shape a wallet could ever have produced.
fn claim_for_input(
    input: &bitcoin::psbt::Input,
    index: u16,
    kind: ScriptKind,
    cx: &Context<'_>,
    expected_coin_type: u32,
) -> Result<Claim, CheckFailure> {
    let mut found: Option<(DerivationPath, ClaimedKey)> = None;
    let mut claims = 0usize;

    for (pk, source) in &input.bip32_derivation {
        if source.0 == cx.fingerprint {
            claims += 1;
            found = Some((source.1.clone(), ClaimedKey::Ecdsa(*pk)));
        }
    }
    for (xonly, (leaves, source)) in &input.tap_key_origins {
        if source.0 != cx.fingerprint {
            continue;
        }
        // A non-empty leaf-hash list is a script-path claim: the key would sign a leaf,
        // not the key path, and the leaf is unverifiable without a registration.
        if !leaves.is_empty() {
            return Err(CheckFailure::TaprootScriptPathUnsupported { index });
        }
        claims += 1;
        found = Some((source.1.clone(), ClaimedKey::Taproot(*xonly)));
    }

    if claims > 1 {
        return Err(CheckFailure::AmbiguousOwnershipClaim { index, claims });
    }
    let Some((path, key)) = found else {
        return Ok(Claim::Foreign);
    };
    if kind == ScriptKind::P2tr && !input.tap_scripts.is_empty() {
        return Err(CheckFailure::TaprootScriptPathUnsupported { index });
    }
    path_sanity(&path, Location::Input(index), cx, expected_coin_type)?;
    Ok(Claim::Ours { path, key })
}

/// The path shape rule, applied wherever an origin names this device.
///
/// Three or more hardened steps, then only unhardened ones: that is the shape of every
/// BIP44-family path, and it is the shape a user can recover from a seed backup with any
/// other wallet. A path outside it may be perfectly derivable and still be a key nobody
/// can find again, which is what the 2019 Coldcard ransom traded on.
fn path_sanity(
    path: &DerivationPath,
    at: Location,
    cx: &Context<'_>,
    expected_coin_type: u32,
) -> Result<(), CheckFailure> {
    let steps: Vec<ChildNumber> = path.into_iter().copied().collect();
    let depth = steps.len();
    if depth < 3 {
        return Err(CheckFailure::PathTooShallow { at, depth });
    }
    if depth > usize::from(cx.limits.max_path_depth) {
        return Err(CheckFailure::PathTooDeep {
            at,
            depth,
            max: cx.limits.max_path_depth,
        });
    }

    let hardened = steps.iter().take_while(|c| c.is_hardened()).count();
    if hardened < 3 || steps[hardened..].iter().any(|c| c.is_hardened()) {
        return Err(CheckFailure::PathHardenedShapeInvalid { at });
    }

    let purpose = child_index(steps[0]);
    if !PURPOSE_WHITELIST.contains(&purpose) {
        return Err(CheckFailure::PathOutsidePurposeWhitelist { at, purpose });
    }

    let coin_type = child_index(steps[1]);
    if coin_type != expected_coin_type {
        return Err(CheckFailure::CoinTypeMismatch {
            at,
            found: coin_type,
            expected: expected_coin_type,
        });
    }

    Ok(())
}

/// ARCH check 1, the other half of what can be decided without a key: the origin names a
/// public key, and the script names a hash of one. They must be the same key.
fn key_matches_script(
    key: ClaimedKey,
    kind: ScriptKind,
    script_pubkey: &Script,
    redeem_script: Option<&Script>,
    index: u16,
) -> Result<(), CheckFailure> {
    match (key, kind) {
        (ClaimedKey::Ecdsa(pk), ScriptKind::P2wpkh) => {
            let want = ScriptBuf::new_p2wpkh(&CompressedPublicKey(pk).wpubkey_hash());
            if want != *script_pubkey {
                return Err(CheckFailure::ClaimedKeyNotInScript { index });
            }
        }
        (ClaimedKey::Ecdsa(pk), ScriptKind::P2shP2wpkh) => {
            let want = ScriptBuf::new_p2wpkh(&CompressedPublicKey(pk).wpubkey_hash());
            // `classify` only answers P2shP2wpkh when the redeem script is present.
            if redeem_script != Some(want.as_script()) {
                return Err(CheckFailure::ClaimedKeyNotInScript { index });
            }
        }
        (ClaimedKey::Taproot(_), ScriptKind::P2tr) => {
            // The internal key is checked against the script by `taproot_tweak`, which is
            // the only comparison that means anything for a tweaked output key.
        }
        // A claimed key of the wrong shape for the script is not a mismatch to explain in
        // taproot terms; it is the same statement as the two arms above.
        _ => return Err(CheckFailure::ClaimedKeyNotInScript { index }),
    }
    Ok(())
}

/// ARCH check 4, the whole of it: rebuild a claimed multisig input's script from a
/// REGISTERED wallet, and refuse the input if that rebuild does not produce the script the
/// input is actually locked to.
///
/// Nothing in here reads a cosigner xpub, a threshold or a witness script out of the PSBT
/// in order to decide anything. The PSBT contributes exactly two things: the path, which
/// says WHICH leaf of a registration to build, and its own copy of the witness script,
/// which is compared against ours and never preferred to it. That asymmetry is the 2021
/// xpub-substitution defense - a coordinator that supplies a different cosigner set
/// changes what it claims, not what this device builds.
fn bind_multisig(
    input: &bitcoin::psbt::Input,
    index: u16,
    script_pubkey: &Script,
    path: &DerivationPath,
    key: ClaimedKey,
    cx: &Context<'_>,
) -> Result<MultisigBinding, CheckFailure> {
    if cx.registry.is_empty() {
        return Err(CheckFailure::MultisigStatelessUnverifiable { index });
    }
    // Required before the registry is consulted, so that a file missing the field gets the
    // sentence about the field rather than one about registration. The post-sign gate reads
    // this same field back independently, which is why its absence cannot be papered over
    // with the copy we are about to rebuild.
    let supplied = input
        .witness_script
        .as_ref()
        .ok_or(CheckFailure::MultisigWitnessScriptMissing { index })?;

    let Some((registration, located)) = multisig::locate_in(cx.registry, path, script_pubkey)
    else {
        return Err(CheckFailure::MultisigNotRegistered { index });
    };
    if *supplied != located.witness_script {
        return Err(CheckFailure::MultisigWitnessScriptMismatch { index });
    }
    // The same statement `key_matches_script` makes for a single-sig input: the origin and
    // the script have to describe one key. Here the script's account of our key comes from
    // the registration rather than from a hash in the scriptPubKey.
    if key != ClaimedKey::Ecdsa(located.our_key.0) {
        return Err(CheckFailure::ClaimedKeyNotInScript { index });
    }

    Ok(MultisigBinding {
        registration,
        keychain: located.keychain,
        address_index: located.index,
        witness_script: located.witness_script,
        our_key: located.our_key,
    })
}

/// How many origins on ONE output map name this device.
///
/// The one definition of "an origin of ours" there is, read by the census that bounds the
/// file and by [`classify_output`], which walks the same two maps to decide what they
/// claim. Two spellings of this count would be two answers to "how many did the device
/// look at", and the bound would be enforced against one of them and the work done against
/// the other.
///
/// Both maps, because a file that spent its allowance in `bip32_derivation` and carried on
/// in `tap_key_origins` would have bought itself a second helping. Only ours: a foreign
/// origin costs a four-byte comparison and a 15-cosigner output legitimately carries
/// fourteen of them.
fn own_origins(output: &bitcoin::psbt::Output, fingerprint: Fingerprint) -> usize {
    output
        .bip32_derivation
        .values()
        .map(|source| source.0)
        .chain(output.tap_key_origins.values().map(|(_, source)| source.0))
        .filter(|claimed| *claimed == fingerprint)
        .count()
}

/// Both counting bounds on check 3, taken over the whole file before a single key is
/// derived.
///
/// Per output first and then the file, because they are two different statements and only
/// the second one was ever missing: [`StructuralLimits::max_own_output_origins`] says no
/// output of ours holds more keys at a leaf than a wallet of ours has, and
/// [`StructuralLimits::max_own_origins_in_file`] says a transaction of ours does not repeat
/// that 255 times over. A bound on each factor of a product is not a bound on the product,
/// and the product is what an attacker writes.
///
/// Counted in full rather than accumulated as the proving loop runs, for two reasons that
/// both matter to the person reading the refusal. The file is refused before the first
/// derivation instead of partway through them, and the number the refusal quotes is the
/// file's real total rather than wherever a running sum happened to cross the line.
///
/// It is affordable precisely because it derives nothing: one four-byte comparison per map
/// entry, over maps [`StructuralLimits::max_psbt_bytes`] already bounds.
fn own_origin_census(psbt: &Psbt, cx: &Context<'_>) -> Result<(), CheckFailure> {
    let mut total = 0usize;
    // The cast holds because `global_sanity` ran first and refused any file with more than
    // `max_outputs` output maps, and that limit is itself a u16.
    for (i, output) in psbt.outputs.iter().enumerate() {
        let ours = own_origins(output, cx.fingerprint);
        if ours > usize::from(cx.limits.max_own_output_origins) {
            return Err(CheckFailure::TooManyOwnOutputOrigins {
                at: Location::Output(i as u16),
                found: ours,
                max: cx.limits.max_own_output_origins,
            });
        }
        // Saturating rather than wrapping: the byte cap puts the true sum nowhere near
        // usize::MAX, and a counter that overflowed into acceptance is the failure this
        // census exists to prevent.
        total = total.saturating_add(ours);
    }
    if total > usize::from(cx.limits.max_own_origins_in_file) {
        return Err(CheckFailure::TooManyOwnOriginsInFile {
            found: total,
            max: cx.limits.max_own_origins_in_file,
        });
    }
    Ok(())
}

/// What proving ONE FILE's outputs may spend, counted in BIP-32 child derivations.
///
/// The census above bounds what a file may CLAIM. This bounds what those claims may COST,
/// and only the second is a bound on the clock: one origin is not one price, because what
/// an origin costs is decided by the registry this device holds rather than by the file,
/// and 40x separates the cheapest device from the dearest
/// ([`StructuralLimits::max_change_derivations`] has the arithmetic).
///
/// Charged BEFORE the derivations it pays for, and levied on one candidate wallet at a
/// time. A budget checked afterwards is not a bound but a report of how far over the device
/// already went, and charging per wallet rather than per output is what makes the overshoot
/// zero rather than one wallet's worth.
///
/// Running out is a REFUSAL, never a truncation. See
/// [`CheckFailure::ChangeDerivationBudgetExhausted`]: a device that quietly stopped proving
/// outputs would report an unproven change output as money leaving, which is the review
/// screen lying about the amount - strictly worse than the hang the bound exists to
/// prevent.
struct ChangeDerivationBudget {
    spent: u32,
    max: u32,
}

impl ChangeDerivationBudget {
    fn new(limits: StructuralLimits) -> Self {
        ChangeDerivationBudget {
            spent: 0,
            max: limits.max_change_derivations,
        }
    }

    /// Charge `n` derivations that are about to run.
    fn charge(&mut self, at: Location, n: u32) -> Result<(), CheckFailure> {
        self.spent = self.spent.saturating_add(n);
        if self.spent > self.max {
            return Err(CheckFailure::ChangeDerivationBudgetExhausted { at, max: self.max });
        }
        Ok(())
    }
}

/// ARCH checks 3 and 4 over one output: what the file claims, and what can be proven.
///
/// Returns the claim and the verdict together because they are two readings of one pass and
/// separating the passes is how they would come to disagree.
///
/// The proving loops below are the only unbounded-by-nature work in the pipeline - one
/// wallet re-derivation per origin naming us, on a map an attacker sizes - and they are
/// bounded from both ends. How many origins may reach them at all is settled before this
/// runs, by [`own_origin_census`] over the whole file; what those origins may then cost is
/// rationed derivation by derivation by [`ChangeDerivationBudget`].
///
/// INVARIANT, and it is the caller's to keep: `inspect_with_accounts` runs the census
/// before the first call to this function, so the map walked here is already known to name
/// us no more than [`StructuralLimits::max_own_output_origins`] times and the file no more
/// than [`StructuralLimits::max_own_origins_in_file`] times. Calling this without that
/// census is calling it on an unbounded map.
fn classify_output(
    output: &bitcoin::psbt::Output,
    txout: &TxOut,
    at: Location,
    cx: &Context<'_>,
    expected_coin_type: u32,
    accounts: &[Account],
    budget: &mut ChangeDerivationBudget,
) -> Result<(bool, OutputRole), CheckFailure> {
    let mut claims_our_key = false;
    let mut role = OutputRole::Payment;

    for (pk, source) in &output.bip32_derivation {
        if source.0 != cx.fingerprint {
            continue;
        }
        claims_our_key = true;
        path_sanity(&source.1, at, cx, expected_coin_type)?;

        // The first origin that proves the script decides and a later one cannot revise
        // it. Two proofs would mean two wallets building one script, which means the same
        // keys at the same leaf; letting the last writer win would make the verdict depend
        // on map iteration order for no benefit, and the direction that matters is that an
        // unproven claim never displaces a proven one.
        if matches!(role, OutputRole::Payment | OutputRole::ClaimedButUnproven) {
            let claim = OutputClaim {
                output,
                txout,
                path: &source.1,
                claimed: ClaimedKey::Ecdsa(*pk),
                at,
            };
            role = prove_output(&claim, cx, accounts, budget)?
                .unwrap_or(OutputRole::ClaimedButUnproven);
        }
    }

    for (xonly, (leaves, source)) in &output.tap_key_origins {
        if source.0 != cx.fingerprint {
            continue;
        }
        claims_our_key = true;
        path_sanity(&source.1, at, cx, expected_coin_type)?;
        if !matches!(role, OutputRole::Payment | OutputRole::ClaimedButUnproven) {
            continue;
        }
        // A non-empty leaf-hash list is a script-path claim: this key would appear inside
        // a tree, and the only taproot output this device builds is BIP-86's key path with
        // no tree at all (Q7). Nothing here could rebuild such a script, so the claim
        // stays a claim - and taproot multisig is not in 0.2.0 either, which is why no
        // registration is consulted for a taproot output.
        role = if leaves.is_empty() {
            let claim = OutputClaim {
                output,
                txout,
                path: &source.1,
                claimed: ClaimedKey::Taproot(*xonly),
                at,
            };
            prove_output(&claim, cx, accounts, budget)?.unwrap_or(OutputRole::ClaimedButUnproven)
        } else {
            OutputRole::ClaimedButUnproven
        };
    }

    Ok((claims_our_key, role))
}

/// One ownership claim on one output: everything the proving functions read out of the file
/// about a single origin, and nothing they read about the device.
///
/// A parameter list rather than a type is how this started, and it grew past what a reader
/// can hold: three of the five arguments come from the same output map and are meaningless
/// apart, so passing them as one value is what stops a caller pairing an output's script
/// with a different output's path. The device's own side - the registry, the accounts, the
/// budget - stays outside deliberately, because the whole design of check 3 is that the
/// file supplies a hint and only the device supplies the answer.
#[derive(Clone, Copy)]
struct OutputClaim<'a> {
    output: &'a bitcoin::psbt::Output,
    txout: &'a TxOut,
    /// The path the file claims this key sits at. A hint, and a hostile one may point
    /// anywhere; see [`prove_output`].
    path: &'a DerivationPath,
    claimed: ClaimedKey,
    at: Location,
}

/// The proof, or nothing.
///
/// `None` is the answer whenever anything is unproven, and the caller turns that into
/// [`OutputRole::ClaimedButUnproven`], which spends money exactly like a payment. There is
/// no branch here that upgrades a partial match, no tolerance, and nothing that looks at
/// the SHAPE of the script: a script-shape rule is what "looks like change" means, and it
/// is what the 2019 Coldcard multisig change confusion was.
///
/// What the PSBT contributes is a hint about where to look. What decides is whether a
/// wallet of ours, derived independently, produces this exact scriptPubKey there. An
/// attacker controls the hint completely and controls none of the derivation, so the most
/// a forged claim can do is make the device rebuild some genuine script of ours and find
/// that it is not the script the output pays.
///
/// Two wallet kinds, asked in that order and never merged: a P2WSH script comes from a
/// registration or from nowhere, and a single-key script comes from an account or from
/// nowhere. The order is not a fallback chain that loosens anything - each half compares
/// the whole scriptPubKey, so a script the first half rebuilds cannot be a script the
/// second one does.
///
/// # Why the return type has two layers
///
/// `Ok(None)` is "unproven" and `Err` is "refused", and collapsing them is the bug this
/// signature exists to make unwritable. Both halves derive, both are rationed by
/// [`ChangeDerivationBudget`], and a budget that ran out is not evidence about the output -
/// it is the device declining to answer. Reporting it as `None` would classify a change
/// output as money leaving because the device got tired, which is a wrong number on the
/// review screen rather than a refusal on it.
fn prove_output(
    claim: &OutputClaim<'_>,
    cx: &Context<'_>,
    accounts: &[Account],
    budget: &mut ChangeDerivationBudget,
) -> Result<Option<OutputRole>, CheckFailure> {
    let registered = match claim.claimed {
        ClaimedKey::Ecdsa(key) => prove_registered_output(claim, key, cx, budget)?,
        // No registration builds a taproot script in 0.2.0 (Q7), so there is nothing to
        // ask; the account half is the whole of the taproot answer.
        ClaimedKey::Taproot(_) => None,
    };
    match registered {
        Some(role) => Ok(Some(role)),
        None => prove_account_output(claim, accounts, cx.network, budget),
    }
}

/// Check 3 over a MULTISIG output: does a registered wallet build this script at the leaf
/// the file names?
fn prove_registered_output(
    claim: &OutputClaim<'_>,
    claimed_key: bitcoin::secp256k1::PublicKey,
    cx: &Context<'_>,
    budget: &mut ChangeDerivationBudget,
) -> Result<Option<OutputRole>, CheckFailure> {
    let OutputClaim {
        output,
        txout,
        path,
        at,
        ..
    } = *claim;
    // The walk [`multisig::locate_in`] would do, opened up here for one reason its own doc
    // gives: this is the caller that runs it once per entry of a map the FILE sizes, so the
    // derivations have to be charged before they run, and `locate_in` cannot say what it is
    // about to spend.
    for registration in cx.registry {
        // Free, and that is the point: `locate_path` compares the claimed path against a
        // stored origin and derives nothing, so a registration this path cannot name costs
        // the file no budget. Only the registrations a path really could be a leaf of are
        // charged for.
        let Some((keychain, index)) = registration.locate_path(path) else {
            continue;
        };
        budget.charge(at, registration.leaf_derivations())?;
        // The load-bearing comparison: `locate_leaf` answers only for a registration that
        // rebuilds `script_pubkey` at that leaf.
        let Some(located) = registration.locate_leaf(keychain, index, &txout.script_pubkey) else {
            continue;
        };

        // Past here the answer is this registration's and a later one cannot revise it,
        // exactly as `multisig::locate_in` decides it: two registrations that both build
        // this script hold the same cosigner keys at this index, so there is nothing left
        // for another to say.
        //
        // The origin is keyed by a public key, and for this leaf there is exactly one key
        // it may be. A file whose script we rebuilt but whose key we did not is internally
        // inconsistent; it has no honest reading, so it gets no proof.
        if located.our_key.0 != claimed_key {
            return Ok(None);
        }
        // A witness script on an output map is optional and is never needed - we built our
        // own. When one is there it has to agree, for the same reason the input case
        // refuses a mismatch: two accounts of one script, and the device must not pick.
        if let Some(supplied) = &output.witness_script {
            if *supplied != located.witness_script {
                return Ok(None);
            }
        }

        return Ok(Some(match located.keychain {
            Keychain::Change => OutputRole::Change {
                owner: Owner::Registered(registration.id()),
                index: located.index,
            },
            Keychain::Receive => OutputRole::OwnNotChange {
                owner: Owner::Registered(registration.id()),
                index: located.index,
            },
        }));
    }
    Ok(None)
}

/// How far along a keychain a claimed single-sig leaf may sit and still be believed.
///
/// This is ARCHITECTURE.md check 3's gap bound, and the first thing to say about it is what
/// it is not: it is not a search width. The device derives ONE leaf per account per claim -
/// the leaf the file's own origin path names - and the verdict is whether that leaf's
/// script is the script the output pays. Nothing here walks a range, so a hostile index
/// costs one BIP-32 derivation and buys a comparison that fails. A signer that SCANNED
/// 0..N for a match would be handing an attacker N chances to collide with something of
/// ours; this is deliberately not that design, and the bound must never be turned into a
/// loop bound by a later change.
///
/// What it does bound is the claim the device is willing to honour by SUBTRACTING an
/// output from the money leaving. Coordinators allocate change sequentially from index 0,
/// so a leaf at index N implies roughly N change outputs before it: 20,000 is five spends
/// a day for a decade, past any wallet a person carries on a hardware signer, and a claim
/// beyond it is not a used wallet but a file asking a review screen to net out an output
/// its owner would have to go hunting for. The honest answer to that is the answer every
/// other unproven claim gets - it is money leaving.
///
/// Erring the other way is the failure this whole check exists to fix, and it is not
/// hypothetical: a wallet with five hundred spends behind it presents change at index
/// around 500, and a device that stopped at BIP-44's gap limit of 20 would call it a
/// payment and overstate what the transaction sends by the whole of its change. That is
/// today's bug in miniature, which is why the bound is generous and why it can afford to
/// be.
///
/// Not a [`StructuralLimits`] field: every field there is a refusal and this is not one -
/// stated that way rather than by counting them, because a comment that counts the fields
/// beside it is a comment that goes stale the next time one is added, and it did. An output
/// past this bound is classified, not rejected, and no screen may move it (Q24).
const MAX_ACCOUNT_LEAF_INDEX: u32 = 20_000;

/// Check 3 over a SINGLE-SIG output: does an account of ours build this script at the leaf
/// the file names?
///
/// The single-sig statement of the same property [`prove_registered_output`] makes, and it
/// is made the same way for the same reason. The PSBT contributes a path, which says which
/// leaf of which account to derive; a coordinator writes that path and may write anything
/// in it, including our own fingerprint at a perfectly ordinary change path pointing at
/// its own address. What answers is [`Account::leaf`], which derives from an account xpub
/// that only the seed could have produced, and the answer is a whole-scriptPubKey
/// comparison. Nothing about the shape of the output is consulted, and there is no branch
/// that accepts a near miss.
fn prove_account_output(
    claim: &OutputClaim<'_>,
    accounts: &[Account],
    network: Network,
    budget: &mut ChangeDerivationBudget,
) -> Result<Option<OutputRole>, CheckFailure> {
    let OutputClaim {
        output,
        txout,
        path,
        claimed,
        at,
    } = *claim;
    for account in accounts {
        // Check 5 refuses a cross-chain PATH; this skips a cross-chain ACCOUNT, which is a
        // caller's mistake rather than a file's and must not be reasoned from either way.
        if account.network() != network {
            continue;
        }
        // Free for the same reason the registration walk's `locate_path` is: nothing is
        // derived until the path really could be a leaf of this account.
        let Some((keychain, index)) = account.locate_path(path) else {
            continue;
        };
        if index > MAX_ACCOUNT_LEAF_INDEX {
            continue;
        }
        budget.charge(at, Account::LEAF_DERIVATIONS)?;
        let Some(leaf) = account.leaf(keychain, index) else {
            continue;
        };
        // The load-bearing comparison, and the only one that decides ownership.
        if leaf.script_pubkey != txout.script_pubkey {
            continue;
        }
        // Past here the script is one this account locks, so this account is THE candidate
        // and no other can also build it. What is left is whether the file's own account of
        // the leaf agrees with ours; where it does not, the file has no honest reading and
        // gets no proof rather than a second guess.
        if !claim_agrees_with_leaf(claimed, output, &leaf) {
            return Ok(None);
        }
        return Ok(Some(match keychain {
            Keychain::Change => OutputRole::Change {
                owner: Owner::Account(account.id()),
                index,
            },
            Keychain::Receive => OutputRole::OwnNotChange {
                owner: Owner::Account(account.id()),
                index,
            },
        }));
    }
    Ok(None)
}

/// Whether the key the file's origin names is the key this leaf derives.
///
/// For a hashed script this is a tautology the compiler cannot see - the scriptPubKey
/// already commits to the key, and the caller has just compared it. For taproot it is not:
/// a scriptPubKey holds an output key, which is a tweak, and BIP-341 lets more than one
/// internal key and merkle root be claimed to reach one. So the internal key is compared
/// against ours directly, and a declared [`bitcoin::psbt::Output::tap_internal_key`] has to
/// be ours too - a file that names a different one is describing a different output.
fn claim_agrees_with_leaf(
    claimed: ClaimedKey,
    output: &bitcoin::psbt::Output,
    leaf: &Leaf,
) -> bool {
    match claimed {
        ClaimedKey::Ecdsa(key) => key == leaf.key.0,
        ClaimedKey::Taproot(xonly) => {
            let ours = XOnlyPublicKey::from(leaf.key.0);
            xonly == ours && output.tap_internal_key.is_none_or(|declared| declared == ours)
        }
    }
}

/// ARCH check 7. No override exists, so this is a single comparison and not a policy.
fn sighash_whitelisted(
    input: &bitcoin::psbt::Input,
    kind: ScriptKind,
    index: u16,
) -> Result<(), CheckFailure> {
    let Some(declared) = input.sighash_type else {
        // Absent means the default for the script type, which is the whitelisted value in
        // both families.
        return Ok(());
    };
    let raw = declared.to_u32();
    if !whitelisted_sighashes(kind).contains(&raw) {
        return Err(CheckFailure::SighashTypeNotWhitelisted { index, found: raw });
    }
    Ok(())
}

/// ARCH check 8. The declared internal key, tweaked with the declared merkle root, has to
/// be the key in the scriptPubKey. Without this the coordinator, not the device, decides
/// which key a Schnorr signature will be checked against.
fn taproot_tweak(
    input: &bitcoin::psbt::Input,
    claimed: XOnlyPublicKey,
    script_pubkey: &Script,
    index: u16,
) -> Result<(), CheckFailure> {
    let internal = input
        .tap_internal_key
        .ok_or(CheckFailure::TaprootInternalKeyMissing { index })?;
    // The origin says which key we would derive and `tap_internal_key` says which key the
    // output was built from. If those differ, one of them is describing a different output
    // and the tweak below would be checking the wrong claim.
    if claimed != internal {
        return Err(CheckFailure::TaprootInternalKeyMismatch { index });
    }
    let output_key = internal.tap_tweak(secp(), input.tap_merkle_root).0;
    if ScriptBuf::new_p2tr_tweaked(output_key) != *script_pubkey {
        return Err(CheckFailure::TaprootTweakMismatch { index });
    }
    Ok(())
}

/// Coin type by BIP44/SLIP44: 0 for mainnet, 1 for every test chain.
fn coin_type_for(network: Network) -> u32 {
    match network {
        Network::Bitcoin => 0,
        _ => 1,
    }
}

fn child_index(child: ChildNumber) -> u32 {
    match child {
        ChildNumber::Normal { index } | ChildNumber::Hardened { index } => index,
    }
}

/// Script classification. A P2SH input is only P2SH-P2WPKH when the PSBT says what it
/// wraps: guessing from the scriptPubKey is impossible, and guessing from anything else is
/// a heuristic, which ARCH check 3 forbids in the neighbouring case for the same reason.
fn classify(script: &Script, redeem: Option<&Script>) -> ScriptKind {
    if script.is_p2wpkh() {
        ScriptKind::P2wpkh
    } else if script.is_p2tr() {
        ScriptKind::P2tr
    } else if script.is_p2sh() {
        match redeem {
            Some(r) if r.is_p2wpkh() => ScriptKind::P2shP2wpkh,
            _ => ScriptKind::P2sh,
        }
    } else if script.is_p2wsh() {
        ScriptKind::P2wsh
    } else if script.is_p2pkh() {
        ScriptKind::P2pkh
    } else if script.is_op_return() {
        ScriptKind::OpReturn
    } else {
        ScriptKind::Other
    }
}

fn count_unknown_fields(psbt: &Psbt) -> usize {
    let mut n = psbt.unknown.len() + psbt.proprietary.len();
    for input in &psbt.inputs {
        n += input.unknown.len() + input.proprietary.len();
    }
    for output in &psbt.outputs {
        n += output.unknown.len() + output.proprietary.len();
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::psbt::{fixture, test_corpus};
    use alloc::string::ToString;
    use bitcoin::hashes::Hash;

    /// The whitelist and [`crate::derive::Scheme`] must name the same purposes; a scheme
    /// added to one and not the other is a path the device derives and then refuses.
    #[test]
    fn the_purpose_whitelist_is_the_scheme_list() {
        use crate::derive::Scheme;
        let mut from_schemes: Vec<u32> = [
            Scheme::Bip44,
            Scheme::Bip48,
            Scheme::Bip49,
            Scheme::Bip84,
            Scheme::Bip86,
        ]
        .iter()
        .map(|s| s.purpose())
        .collect();
        from_schemes.sort_unstable();
        let mut whitelist = PURPOSE_WHITELIST.to_vec();
        whitelist.sort_unstable();
        assert_eq!(from_schemes, whitelist);
    }

    /// Every named check has a distinct number, and every failure variant reports one.
    #[test]
    fn check_numbers_match_the_architecture_table() {
        assert_eq!(Check::InputOwnership.number(), 1);
        assert_eq!(Check::Prevouts.number(), 2);
        assert_eq!(Check::ChangeDerivation.number(), 3);
        assert_eq!(Check::MultisigBinding.number(), 4);
        assert_eq!(Check::NetworkIsolation.number(), 5);
        assert_eq!(Check::Fee.number(), 6);
        assert_eq!(Check::SighashWhitelist.number(), 7);
        assert_eq!(Check::Taproot.number(), 8);
        assert_eq!(Check::GlobalSanity.number(), 9);
        assert_eq!(Check::PostSign.number(), 10);
    }

    // -- the happy paths -----------------------------------------------------------------

    #[test]
    fn a_p2wpkh_spend_of_ours_inspects_clean() {
        let psbt = fixture::p2wpkh_psbt();
        let inspection = inspect(&psbt, &fixture::context()).unwrap();
        assert_eq!(inspection.inputs.len(), 1);
        assert_eq!(inspection.inputs[0].kind, ScriptKind::P2wpkh);
        assert!(matches!(inspection.inputs[0].claim, Claim::Ours { .. }));
        assert_eq!(inspection.signable_inputs(), 1);
        assert_eq!(inspection.fee, Amount::from_sat(fixture::FEE_SAT));
        assert!(inspection.rbf_signaled);
        assert_eq!(inspection.unknown_fields, 0);
        assert_eq!(inspection.psbt_id(), crate::psbt::psbt_id(&psbt));
    }

    #[test]
    fn a_p2sh_p2wpkh_spend_of_ours_inspects_clean() {
        let psbt = fixture::p2sh_p2wpkh_psbt();
        let inspection = inspect(&psbt, &fixture::context()).unwrap();
        assert_eq!(inspection.inputs[0].kind, ScriptKind::P2shP2wpkh);
        assert!(matches!(inspection.inputs[0].claim, Claim::Ours { .. }));
    }

    #[test]
    fn a_taproot_key_path_spend_of_ours_inspects_clean() {
        let psbt = fixture::p2tr_psbt();
        let inspection = inspect(&psbt, &fixture::context()).unwrap();
        assert_eq!(inspection.inputs[0].kind, ScriptKind::P2tr);
        assert!(matches!(inspection.inputs[0].claim, Claim::Ours { .. }));
    }

    /// An input nobody claims is shown, not signed, and not an error.
    #[test]
    fn an_input_that_names_another_device_is_foreign_not_a_refusal() {
        let mut psbt = fixture::p2wpkh_psbt();
        let entry = psbt.inputs[0].bip32_derivation.iter().next().unwrap();
        let (pk, (_, path)) = (*entry.0, entry.1.clone());
        psbt.inputs[0]
            .bip32_derivation
            .insert(pk, (Fingerprint::from([9u8; 4]), path));
        let inspection = inspect(&psbt, &fixture::context()).unwrap();
        assert_eq!(inspection.inputs[0].claim, Claim::Foreign);
        assert_eq!(inspection.signable_inputs(), 0);
    }

    /// Unknown fields are counted for the review screen and never refused.
    #[test]
    fn unknown_fields_are_counted_and_tolerated() {
        let mut psbt = fixture::p2wpkh_psbt();
        psbt.inputs[0].unknown.insert(
            bitcoin::psbt::raw::Key {
                type_value: 0x0f,
                key: alloc::vec![1, 2, 3],
            },
            alloc::vec![4, 5, 6],
        );
        let inspection = inspect(&psbt, &fixture::context()).unwrap();
        assert_eq!(inspection.unknown_fields, 1);
    }

    // -- one negative per check ----------------------------------------------------------

    #[test]
    fn check_9_refuses_psbt_v2() {
        let mut psbt = fixture::p2wpkh_psbt();
        psbt.version = 2;
        let err = inspect(&psbt, &fixture::context()).unwrap_err();
        assert_eq!(err, CheckFailure::PsbtVersionUnsupported { version: 2 });
        assert_eq!(err.check(), Check::GlobalSanity);
        assert!(err.to_string().contains("version 0"));
    }

    #[test]
    fn check_9_refuses_an_oversized_psbt() {
        let psbt = fixture::p2wpkh_psbt();
        let mut cx = fixture::context();
        cx.limits.max_psbt_bytes = 16;
        assert!(matches!(
            inspect(&psbt, &cx).unwrap_err(),
            CheckFailure::PsbtTooLarge { max: 16, .. }
        ));
    }

    #[test]
    fn check_9_refuses_a_duplicated_input() {
        let psbt = fixture::duplicate_input_psbt();
        let err = inspect(&psbt, &fixture::context()).unwrap_err();
        assert!(matches!(
            err,
            CheckFailure::DuplicateInput {
                first: 0,
                second: 1,
                ..
            }
        ));
        assert_eq!(err.check(), Check::GlobalSanity);
    }

    #[test]
    fn check_9_refuses_an_already_finalized_input() {
        let mut psbt = fixture::p2wpkh_psbt();
        psbt.inputs[0].final_script_sig = Some(ScriptBuf::new());
        assert_eq!(
            inspect(&psbt, &fixture::context()).unwrap_err(),
            CheckFailure::InputAlreadyFinalized { index: 0 }
        );
    }

    #[test]
    fn check_9_refuses_a_count_mismatch() {
        let mut psbt = fixture::p2wpkh_psbt();
        psbt.inputs.push(bitcoin::psbt::Input::default());
        assert!(matches!(
            inspect(&psbt, &fixture::context()).unwrap_err(),
            CheckFailure::InputMapCountMismatch {
                maps: 2,
                tx_inputs: 1
            }
        ));
    }

    #[test]
    fn check_2_refuses_a_segwit_v0_input_with_no_previous_transaction() {
        let mut psbt = fixture::p2wpkh_psbt();
        psbt.inputs[0].non_witness_utxo = None;
        let err = inspect(&psbt, &fixture::context()).unwrap_err();
        assert_eq!(err, CheckFailure::MissingPreviousTransaction { index: 0 });
        assert_eq!(err.check(), Check::Prevouts);
    }

    #[test]
    fn check_2_refuses_an_input_stating_nothing_about_its_value() {
        let mut psbt = fixture::p2wpkh_psbt();
        psbt.inputs[0].non_witness_utxo = None;
        psbt.inputs[0].witness_utxo = None;
        assert_eq!(
            inspect(&psbt, &fixture::context()).unwrap_err(),
            CheckFailure::MissingPrevout { index: 0 }
        );
    }

    /// The 2020 Trezor attack, in one line: the full transaction says one amount and the
    /// input claims another.
    #[test]
    fn check_2_refuses_a_lied_about_amount() {
        let mut psbt = fixture::p2wpkh_psbt();
        let witness = psbt.inputs[0].witness_utxo.as_mut().unwrap();
        witness.value = Amount::from_sat(1);
        assert!(matches!(
            inspect(&psbt, &fixture::context()).unwrap_err(),
            CheckFailure::PrevAmountMismatch { index: 0, .. }
        ));
    }

    #[test]
    fn check_2_refuses_the_wrong_previous_transaction() {
        let mut psbt = fixture::p2wpkh_psbt();
        let prev = psbt.inputs[0].non_witness_utxo.as_mut().unwrap();
        prev.output[0].value = Amount::from_sat(fixture::PREVOUT_SAT + 1);
        // Touching the previous transaction changes its txid, which is the whole point of
        // requiring it.
        assert_eq!(
            inspect(&psbt, &fixture::context()).unwrap_err(),
            CheckFailure::PrevTxidMismatch { index: 0 }
        );
    }

    #[test]
    fn check_5_refuses_a_testnet_path_on_a_mainnet_device() {
        let psbt = fixture::psbt_with_input_path("m/84'/1'/0'/0/0");
        let err = inspect(&psbt, &fixture::context()).unwrap_err();
        assert_eq!(
            err,
            CheckFailure::CoinTypeMismatch {
                at: Location::Input(0),
                found: 1,
                expected: 0,
            }
        );
        assert_eq!(err.check(), Check::NetworkIsolation);
    }

    #[test]
    fn check_1_refuses_a_purpose_outside_the_whitelist() {
        let psbt = fixture::psbt_with_input_path("m/1234'/0'/0'/0/0");
        let err = inspect(&psbt, &fixture::context()).unwrap_err();
        assert_eq!(
            err,
            CheckFailure::PathOutsidePurposeWhitelist {
                at: Location::Input(0),
                purpose: 1234,
            }
        );
        assert_eq!(err.check(), Check::InputOwnership);
    }

    #[test]
    fn check_1_refuses_a_path_too_deep_to_be_a_wallet_path() {
        let psbt = fixture::psbt_with_input_path("m/84'/0'/0'/0/0/0/0/0/0");
        assert!(matches!(
            inspect(&psbt, &fixture::context()).unwrap_err(),
            CheckFailure::PathTooDeep { depth: 9, .. }
        ));
    }

    #[test]
    fn check_1_refuses_a_hardened_step_below_the_account() {
        let psbt = fixture::psbt_with_input_path("m/84'/0'/0'/0/7'");
        assert_eq!(
            inspect(&psbt, &fixture::context()).unwrap_err(),
            CheckFailure::PathHardenedShapeInvalid {
                at: Location::Input(0)
            }
        );
    }

    #[test]
    fn check_1_refuses_a_path_with_no_account_level() {
        let psbt = fixture::psbt_with_input_path("m/84'/0'");
        assert!(matches!(
            inspect(&psbt, &fixture::context()).unwrap_err(),
            CheckFailure::PathTooShallow { depth: 2, .. }
        ));
    }

    #[test]
    fn check_1_refuses_a_key_that_cannot_spend_the_input() {
        let psbt = fixture::psbt_claiming_the_wrong_key();
        let err = inspect(&psbt, &fixture::context()).unwrap_err();
        assert_eq!(err, CheckFailure::ClaimedKeyNotInScript { index: 0 });
        assert_eq!(err.check(), Check::InputOwnership);
    }

    #[test]
    fn check_1_refuses_two_of_our_keys_on_one_input() {
        let psbt = fixture::psbt_with_two_of_our_claims();
        assert!(matches!(
            inspect(&psbt, &fixture::context()).unwrap_err(),
            CheckFailure::AmbiguousOwnershipClaim { index: 0, claims: 2 }
        ));
    }

    #[test]
    fn check_1_refuses_a_redeem_script_that_is_not_the_inputs() {
        let mut psbt = fixture::p2sh_p2wpkh_psbt();
        psbt.inputs[0].redeem_script = Some(ScriptBuf::new_p2wpkh(
            &bitcoin::WPubkeyHash::from_byte_array([3u8; 20]),
        ));
        assert_eq!(
            inspect(&psbt, &fixture::context()).unwrap_err(),
            CheckFailure::RedeemScriptDoesNotMatchInput { index: 0 }
        );
    }

    /// The stateless multisig refusal (Q11, Q24), which has no override anywhere.
    ///
    /// m6 answered `ClaimedInputNotSingleSig` here because it had no vocabulary for a
    /// registry. The refusal is the same refusal on the same check and the sentence is now
    /// the true one: an empty registry is what makes this input unverifiable, not the
    /// script type.
    #[test]
    fn check_4_refuses_a_multisig_claim_with_no_registry() {
        let psbt = fixture::p2wsh_psbt_claiming_our_key();
        let err = inspect(&psbt, &fixture::context()).unwrap_err();
        assert_eq!(err, CheckFailure::MultisigStatelessUnverifiable { index: 0 });
        assert_eq!(err.check(), Check::MultisigBinding);
    }

    /// A registry that holds a wallet, and an input that wallet does not build.
    #[test]
    fn check_4_refuses_a_multisig_input_no_registration_builds() {
        let registry = alloc::vec![fixture::registration()];
        let psbt = fixture::p2wsh_psbt_claiming_our_key();
        let err = inspect(&psbt, &fixture::context_with(&registry)).unwrap_err();
        assert_eq!(err, CheckFailure::MultisigNotRegistered { index: 0 });
        assert_eq!(err.check(), Check::MultisigBinding);
    }

    /// P2SH multisig stays outside the scope whatever is registered (Q7). m7 widened the
    /// accepted set by exactly one script type and this is the test that says so.
    #[test]
    fn check_4_still_refuses_a_script_type_outside_the_scope() {
        let registry = alloc::vec![fixture::registration()];
        let err = inspect(
            &fixture::p2sh_psbt_claiming_our_key(),
            &fixture::context_with(&registry),
        )
        .unwrap_err();
        assert_eq!(
            err,
            CheckFailure::ClaimedInputNotSingleSig {
                index: 0,
                kind: ScriptKind::P2sh
            }
        );
        assert_eq!(err.check(), Check::MultisigBinding);
    }

    /// A registered 2-of-3 input passes every check and is named as ours.
    #[test]
    fn check_4_binds_a_registered_multisig_input() {
        let registry = alloc::vec![fixture::registration()];
        let psbt = fixture::multisig_psbt();
        let inspection = inspect(&psbt, &fixture::context_with(&registry)).unwrap();
        assert_eq!(inspection.signable_inputs(), 1);
        let binding = inspection.inputs[0].multisig.as_ref().unwrap();
        assert_eq!(binding.registration, registry[0].id());
        assert_eq!(binding.keychain, Keychain::Receive);
        assert_eq!(binding.address_index, 0);
        assert_eq!(
            Some(&binding.witness_script),
            psbt.inputs[0].witness_script.as_ref()
        );
    }

    /// The witness script is required, because the post-sign gate reads it back.
    #[test]
    fn check_4_refuses_a_multisig_input_with_no_witness_script() {
        let registry = alloc::vec![fixture::registration()];
        let mut psbt = fixture::multisig_psbt();
        psbt.inputs[0].witness_script = None;
        assert_eq!(
            inspect(&psbt, &fixture::context_with(&registry)).unwrap_err(),
            CheckFailure::MultisigWitnessScriptMissing { index: 0 }
        );
    }

    /// The 2021 xpub substitution, arriving as a witness script that does not match the
    /// registered wallet's while the scriptPubKey still does. Refused rather than quietly
    /// resolved in favour of our own rebuild, so that the gate and the signer cannot end
    /// up looking at different scripts.
    #[test]
    fn check_4_refuses_a_substituted_witness_script() {
        let registry = alloc::vec![fixture::registration()];
        let mut psbt = fixture::multisig_psbt();
        psbt.inputs[0].witness_script = Some(ScriptBuf::from_bytes(alloc::vec![0x51, 0x51, 0xae]));
        assert_eq!(
            inspect(&psbt, &fixture::context_with(&registry)).unwrap_err(),
            CheckFailure::MultisigWitnessScriptMismatch { index: 0 }
        );
    }

    // -- Check 3 over multisig outputs: the change proof --------------------------------

    /// An output the registered wallet really does build on its change keychain.
    #[test]
    fn check_3_proves_multisig_change() {
        let registry = alloc::vec![fixture::registration()];
        let psbt = fixture::multisig_psbt_with_real_change();
        let inspection = inspect(&psbt, &fixture::context_with(&registry)).unwrap();
        assert_eq!(
            inspection.outputs[1].role,
            OutputRole::Change {
                owner: Owner::Registered(registry[0].id()),
                index: 4
            }
        );
        assert!(inspection.outputs[1].role.is_change());
        assert!(inspection.outputs[1].claims_our_key);
        // And the payment beside it is still a payment.
        assert_eq!(inspection.outputs[0].role, OutputRole::Payment);
    }

    /// THE m7 NEGATIVE TEST. An attacker's script, wearing our fingerprint on an internal
    /// path, with the same script type as real change and an index inside any plausible
    /// gap: everything a heuristic looks at says change. The registered wallet does not
    /// build that script, so it is a payment.
    ///
    /// This is the 2019 Coldcard multisig change confusion. If this test ever passes by
    /// classifying the output as change, the device silently hands an attacker the
    /// difference between the two outputs on every transaction it signs.
    #[test]
    fn check_3_refuses_a_forged_multisig_change_claim() {
        let registry = alloc::vec![fixture::registration()];
        let psbt = fixture::multisig_psbt_with_forged_change();
        let inspection = inspect(&psbt, &fixture::context_with(&registry)).unwrap();

        assert_eq!(inspection.outputs[1].role, OutputRole::ClaimedButUnproven);
        assert!(
            !inspection.outputs[1].role.is_change(),
            "an output no registration re-derives must never be change"
        );
        // The claim itself is still reported, so a review screen can say it was made and
        // refused rather than dropping it.
        assert!(inspection.outputs[1].claims_our_key);
    }

    /// The same forgery pointed at a leaf the wallet DOES build, but on a script the
    /// wallet does not: proving the path is not what decides.
    #[test]
    fn check_3_refuses_a_change_claim_whose_script_is_not_the_leafs() {
        let registry = alloc::vec![fixture::registration()];
        let mut psbt = fixture::multisig_psbt_with_real_change();
        // One byte of the script, nothing else. The path, the fingerprint and the key in
        // the map all still say change.
        let mut bytes = psbt.unsigned_tx.output[1].script_pubkey.to_bytes();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let mutated = ScriptBuf::from_bytes(bytes);
        let mut tx = psbt.unsigned_tx.clone();
        tx.output[1].script_pubkey = mutated;
        let outputs = psbt.outputs.clone();
        let inputs = psbt.inputs.clone();
        psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs = inputs;
        psbt.outputs = outputs;

        let inspection = inspect(&psbt, &fixture::context_with(&registry)).unwrap();
        assert_eq!(inspection.outputs[1].role, OutputRole::ClaimedButUnproven);
        assert!(!inspection.outputs[1].role.is_change());
    }

    /// A self-send to the wallet's own RECEIVE keychain is ours and is not change.
    #[test]
    fn check_3_separates_a_self_send_from_change() {
        let registry = alloc::vec![fixture::registration()];
        let inspection = inspect(
            &fixture::multisig_psbt_with_receive_claim(),
            &fixture::context_with(&registry),
        )
        .unwrap();
        assert_eq!(
            inspection.outputs[1].role,
            OutputRole::OwnNotChange {
                owner: Owner::Registered(registry[0].id()),
                index: 4
            }
        );
        assert!(!inspection.outputs[1].role.is_change());
    }

    /// With no registry in scope there is no way to prove a change claim, and the fallback
    /// is a payment rather than a guess.
    #[test]
    fn check_3_proves_nothing_without_a_registry() {
        let inspection = inspect(&fixture::p2wpkh_psbt(), &fixture::context()).unwrap();
        assert_eq!(inspection.outputs[0].role, OutputRole::Payment);
        assert!(!inspection.outputs[0].claims_our_key);
    }

    // -- Check 3 over single-sig outputs: the change proof -------------------------------
    //
    // The transaction every test in this section is built from is the one board A refused
    // to net out on 2026-08-18: 200,000 sat of ours in, a 120,000 sat payment out, 78,500
    // sat of change back to `m/84'/0'/0'/1/0`, 1,500 sat of fee. The device classified the
    // change as an unprovable output and told its owner the transaction was sending
    // 198,500 sat - true only if the change was somebody else's, which is exactly what
    // this check is for.
    //
    // The change scripts below are built with `fixture::key_at`, which derives a PRIVATE
    // child through `crate::sign`. The proof under test derives the PUBLIC child of an
    // account xpub. Two derivations by two code paths have to land on one script or these
    // tests fail, which is the property that makes them worth writing.

    const TRANSCRIPT_PREVOUT_SAT: u64 = 200_000;
    const TRANSCRIPT_PAYMENT_SAT: u64 = 120_000;
    const TRANSCRIPT_CHANGE_SAT: u64 = 78_500;
    const TRANSCRIPT_FEE_SAT: u64 =
        TRANSCRIPT_PREVOUT_SAT - TRANSCRIPT_PAYMENT_SAT - TRANSCRIPT_CHANGE_SAT;
    const CHANGE_PATH: &str = "m/84'/0'/0'/1/0";

    /// The account the fixture wallet spends from: BIP84, account 0, on the fixture
    /// network. The only account any test here puts in scope, so a claim against another
    /// one is a claim against a wallet the session does not hold.
    fn bip84_account() -> Account {
        Account::derive(
            &fixture::SEED,
            fixture::NETWORK,
            crate::derive::Scheme::Bip84,
            crate::derive::ChildIndex::ZERO,
        )
        .expect("bip84 is a single-sig scheme")
    }

    /// This account's own script at one leaf, derived the way the DEVICE would.
    fn leaf_script(account: &Account, keychain: Keychain, index: u32) -> ScriptBuf {
        account
            .leaf(keychain, index)
            .expect("fixture leaf derives")
            .script_pubkey
    }

    /// A P2WPKH script of a key at `p`, built through the signing derivation rather than
    /// through an account node.
    fn script_at(p: &str) -> ScriptBuf {
        ScriptBuf::new_p2wpkh(&fixture::key_at(p).public_key().wpubkey_hash())
    }

    /// The transcript transaction: one 200,000 sat P2WPKH input of ours, a 120,000 sat
    /// payment, and a second output of 78,500 sat paying `change_spk` whose map claims our
    /// fingerprint at `claim_path` for `claim_key`.
    ///
    /// Every hostile case in this section is this file with one of those three things
    /// changed, for the reason `fixture`'s own module docs give: a negative test built from
    /// its own hand-written file proves only that some file is refused.
    fn transcript_psbt(
        change_spk: ScriptBuf,
        claim_key: bitcoin::secp256k1::PublicKey,
        claim_path: &str,
    ) -> Psbt {
        use bitcoin::{transaction, Sequence, Transaction, TxIn, Witness};

        let input_key = fixture::key_at(fixture::P2WPKH_PATH);
        let input_pk = input_key.public_key();
        let input_spk = ScriptBuf::new_p2wpkh(&input_pk.wpubkey_hash());
        let prev = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: alloc::vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: alloc::vec![TxOut {
                value: Amount::from_sat(TRANSCRIPT_PREVOUT_SAT),
                script_pubkey: input_spk.clone(),
            }],
        };
        let unsigned = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: alloc::vec![TxIn {
                previous_output: OutPoint {
                    txid: prev.compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: alloc::vec![
                TxOut {
                    // A key of ours from an account nothing puts in scope, carrying no
                    // derivation information, which is what somebody else's address looks
                    // like from here.
                    value: Amount::from_sat(TRANSCRIPT_PAYMENT_SAT),
                    script_pubkey: script_at("m/84'/0'/9'/0/0"),
                },
                TxOut {
                    value: Amount::from_sat(TRANSCRIPT_CHANGE_SAT),
                    script_pubkey: change_spk,
                },
            ],
        };
        let mut psbt = Psbt::from_unsigned_tx(unsigned).expect("transcript psbt");
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(TRANSCRIPT_PREVOUT_SAT),
            script_pubkey: input_spk,
        });
        psbt.inputs[0].non_witness_utxo = Some(prev);
        psbt.inputs[0]
            .bip32_derivation
            .insert(input_pk.0, (fixture::fingerprint(), fixture::path(fixture::P2WPKH_PATH)));
        psbt.outputs[1]
            .bip32_derivation
            .insert(claim_key, (fixture::fingerprint(), fixture::path(claim_path)));
        psbt
    }

    /// The transcript, with the account in scope. THE CASE THIS CHECK EXISTS FOR.
    ///
    /// The device re-derives `m/84'/0'/0'/1/0` from its own account node, finds the script
    /// the output pays, and the review stops overstating the spend by 65 percent.
    #[test]
    fn check_3_proves_singlesig_change() {
        let account = bip84_account();
        let key = fixture::key_at(CHANGE_PATH).public_key();
        let psbt = transcript_psbt(script_at(CHANGE_PATH), key.0, CHANGE_PATH);
        let accounts = core::slice::from_ref(&account);
        let inspection = inspect_with_accounts(&psbt, &fixture::context(), accounts).unwrap();

        assert_eq!(
            inspection.outputs[1].role,
            OutputRole::Change {
                owner: Owner::Account(account.id()),
                index: 0
            }
        );
        assert!(inspection.outputs[1].role.is_change());
        assert!(inspection.outputs[1].claims_our_key);
        assert_eq!(inspection.outputs[0].role, OutputRole::Payment);

        // The three numbers from the transcript, in the state they should have been in.
        assert_eq!(
            inspection.change_total(),
            Amount::from_sat(TRANSCRIPT_CHANGE_SAT)
        );
        assert_eq!(
            inspection.leaving_total(),
            Amount::from_sat(TRANSCRIPT_PAYMENT_SAT)
        );
        assert_eq!(inspection.fee, Amount::from_sat(TRANSCRIPT_FEE_SAT));
        assert_eq!(
            inspection.leaving_total() + inspection.change_total(),
            inspection.output_total
        );
    }

    /// THE SINGLE-SIG NEGATIVE TEST, and the reason the positive one is not enough.
    ///
    /// An attacker's address wearing our fingerprint at our own change path, at index 0,
    /// as a P2WPKH script: every field a heuristic reads says change. The account does not
    /// build that script, so it is a payment and all 198,500 sat are leaving.
    ///
    /// This is the 2019 change-confusion attack in its single-sig form. If it ever passes
    /// by classifying the output as change, the device hands the attacker 78,500 sat of
    /// every transaction shaped like this one while showing the user a smaller spend than
    /// they are making.
    #[test]
    fn check_3_refuses_a_forged_singlesig_change_claim() {
        let account = bip84_account();
        // A key the attacker holds, standing in for any script this wallet does not build.
        let attacker = fixture::key_at("m/84'/0'/7'/0/3").public_key();
        let psbt = transcript_psbt(
            ScriptBuf::new_p2wpkh(&attacker.wpubkey_hash()),
            attacker.0,
            CHANGE_PATH,
        );
        let inspection = inspect_with_accounts(&psbt, &fixture::context(), &[account]).unwrap();

        assert_eq!(inspection.outputs[1].role, OutputRole::ClaimedButUnproven);
        assert!(
            !inspection.outputs[1].role.is_change(),
            "an output no account re-derives must never be change"
        );
        // The claim is still reported, so a review screen can say it was made and refused.
        assert!(inspection.outputs[1].claims_our_key);
        assert_eq!(inspection.change_total(), Amount::ZERO);
        assert_eq!(inspection.leaving_total(), inspection.output_total);
    }

    /// The script is ours and the key the map names is not the key that leaf derives. Two
    /// accounts of one output that do not agree, which has no honest reading and so gets
    /// no proof.
    #[test]
    fn check_3_refuses_a_singlesig_change_claim_whose_key_is_not_the_leafs() {
        let account = bip84_account();
        let other = fixture::key_at("m/84'/0'/0'/1/1").public_key();
        let psbt = transcript_psbt(script_at(CHANGE_PATH), other.0, CHANGE_PATH);
        let inspection = inspect_with_accounts(&psbt, &fixture::context(), &[account]).unwrap();

        assert_eq!(inspection.outputs[1].role, OutputRole::ClaimedButUnproven);
        assert!(!inspection.outputs[1].role.is_change());
    }

    /// A claim on an account this session does not hold. The path is well formed and the
    /// script really is that account's change, and the device still has nothing to derive
    /// it from, so the only honest answer is that it is money leaving.
    #[test]
    fn check_3_refuses_a_change_claim_on_an_account_not_in_scope() {
        let elsewhere = "m/84'/0'/1'/1/0";
        let key = fixture::key_at(elsewhere).public_key();
        let psbt = transcript_psbt(script_at(elsewhere), key.0, elsewhere);
        let inspection =
            inspect_with_accounts(&psbt, &fixture::context(), &[bip84_account()]).unwrap();

        assert_eq!(inspection.outputs[1].role, OutputRole::ClaimedButUnproven);
        assert_eq!(inspection.change_total(), Amount::ZERO);
    }

    /// A self-send to the account's own RECEIVE keychain is ours and is not change, for
    /// the same reason as the multisig case above: netting it out would understate what
    /// the transaction does.
    #[test]
    fn check_3_separates_a_singlesig_self_send_from_change() {
        let account = bip84_account();
        let receive = "m/84'/0'/0'/0/1";
        let key = fixture::key_at(receive).public_key();
        let psbt = transcript_psbt(script_at(receive), key.0, receive);
        let accounts = core::slice::from_ref(&account);
        let inspection = inspect_with_accounts(&psbt, &fixture::context(), accounts).unwrap();

        assert_eq!(
            inspection.outputs[1].role,
            OutputRole::OwnNotChange {
                owner: Owner::Account(account.id()),
                index: 1
            }
        );
        assert!(!inspection.outputs[1].role.is_change());
        assert_eq!(inspection.change_total(), Amount::ZERO);
        assert_eq!(inspection.leaving_total(), inspection.output_total);
    }

    /// The gap bound, from both sides. The last leaf the device will follow is proven and
    /// the first one past it is not, and the file is otherwise identical.
    ///
    /// The bound is a bound on what may be BELIEVED, not a range anything walks: both
    /// halves of this test cost one derivation each, and the failing one fails because the
    /// device declines to look, not because it looked and found nothing.
    #[test]
    fn check_3_stops_at_the_gap_bound() {
        let account = bip84_account();
        for (index, expected) in [
            (
                MAX_ACCOUNT_LEAF_INDEX,
                OutputRole::Change {
                    owner: Owner::Account(account.id()),
                    index: MAX_ACCOUNT_LEAF_INDEX,
                },
            ),
            (MAX_ACCOUNT_LEAF_INDEX + 1, OutputRole::ClaimedButUnproven),
        ] {
            let spk = leaf_script(&account, Keychain::Change, index);
            let key = account.leaf(Keychain::Change, index).unwrap().key;
            let path = alloc::format!("m/84'/0'/0'/1/{index}");
            let psbt = transcript_psbt(spk, key.0, &path);
            let accounts = core::slice::from_ref(&account);
            let inspection = inspect_with_accounts(&psbt, &fixture::context(), accounts).unwrap();
            assert_eq!(
                inspection.outputs[1].role, expected,
                "change claimed at leaf {index}"
            );
        }
    }

    /// BIP-86 change, proven the same way through the taproot half of the output map.
    ///
    /// Worth its own case because the comparison that decides is different: a taproot
    /// scriptPubKey holds an output key, which is a tweak of the internal key, so the
    /// device rebuilds the whole tweaked script rather than a hash of a key.
    #[test]
    fn check_3_proves_taproot_change_for_a_bip86_account() {
        let account = Account::derive(
            &fixture::SEED,
            fixture::NETWORK,
            crate::derive::Scheme::Bip86,
            crate::derive::ChildIndex::ZERO,
        )
        .expect("bip86 is a single-sig scheme");
        let path = "m/86'/0'/0'/1/0";
        let key = fixture::key_at(path);
        let internal = key.internal_key();

        let mut psbt = transcript_psbt(
            ScriptBuf::new_p2tr_tweaked(key.output_key(None)),
            key.public_key().0,
            path,
        );
        // A taproot output is claimed through `tap_key_origins`, not `bip32_derivation`.
        psbt.outputs[1].bip32_derivation.clear();
        psbt.outputs[1].tap_internal_key = Some(internal);
        psbt.outputs[1]
            .tap_key_origins
            .insert(internal, (alloc::vec![], (fixture::fingerprint(), fixture::path(path))));

        let accounts = core::slice::from_ref(&account);
        let inspection = inspect_with_accounts(&psbt, &fixture::context(), accounts).unwrap();
        assert_eq!(
            inspection.outputs[1].role,
            OutputRole::Change {
                owner: Owner::Account(account.id()),
                index: 0
            }
        );
        assert_eq!(
            inspection.change_total(),
            Amount::from_sat(TRANSCRIPT_CHANGE_SAT)
        );
    }

    /// The same taproot claim with one leaf hash added to it: a script-path claim, which
    /// names a tree this device does not build (Q7). The scriptPubKey is still ours, and
    /// the file is still describing something the device cannot account for, so it stays a
    /// claim.
    #[test]
    fn check_3_refuses_a_taproot_change_claim_with_a_script_path() {
        let account = Account::derive(
            &fixture::SEED,
            fixture::NETWORK,
            crate::derive::Scheme::Bip86,
            crate::derive::ChildIndex::ZERO,
        )
        .expect("bip86 is a single-sig scheme");
        let path = "m/86'/0'/0'/1/0";
        let key = fixture::key_at(path);
        let internal = key.internal_key();
        let leaf = bitcoin::taproot::TapLeafHash::from_byte_array([7u8; 32]);

        let mut psbt = transcript_psbt(
            ScriptBuf::new_p2tr_tweaked(key.output_key(None)),
            key.public_key().0,
            path,
        );
        psbt.outputs[1].bip32_derivation.clear();
        psbt.outputs[1].tap_key_origins.insert(
            internal,
            (alloc::vec![leaf], (fixture::fingerprint(), fixture::path(path))),
        );

        let inspection = inspect_with_accounts(&psbt, &fixture::context(), &[account]).unwrap();
        assert_eq!(inspection.outputs[1].role, OutputRole::ClaimedButUnproven);
    }

    /// With no account in scope there is nothing to derive a proof from, and the fallback
    /// is a payment rather than a guess. This is what board A did on 2026-08-18 and what
    /// [`inspect`] still does: safe, and 65 percent wrong about the spend.
    #[test]
    fn check_3_proves_nothing_without_accounts() {
        let key = fixture::key_at(CHANGE_PATH).public_key();
        let psbt = transcript_psbt(script_at(CHANGE_PATH), key.0, CHANGE_PATH);
        let inspection = inspect(&psbt, &fixture::context()).unwrap();

        assert_eq!(inspection.outputs[1].role, OutputRole::ClaimedButUnproven);
        assert!(inspection.outputs[1].claims_our_key);
        assert_eq!(inspection.change_total(), Amount::ZERO);
        assert_eq!(inspection.leaving_total(), inspection.output_total);
    }

    /// An account cannot prove a multisig output and a registration cannot prove a
    /// single-sig one, however much of the other is in scope. Two proofs, one verdict
    /// each, and no path where one wallet's state loosens the other's answer.
    #[test]
    fn check_3_does_not_let_one_wallet_kind_answer_for_the_other() {
        // The registered wallet's own change leaf, on an output of the transcript
        // transaction, offered to a session that holds accounts and no registry. The claim
        // is internally consistent - that really is our cosigner key at that leaf - and an
        // account still cannot build a P2WSH script.
        let registration = fixture::registration();
        let leaf_path = alloc::format!("{}/1/4", fixture::BIP48_ORIGIN);
        let key = fixture::key_at(&leaf_path).public_key();
        let psbt = transcript_psbt(
            registration
                .script_pubkey(Keychain::Change, 4)
                .expect("fixture change leaf derives"),
            key.0,
            &leaf_path,
        );
        let inspection =
            inspect_with_accounts(&psbt, &fixture::context(), &[bip84_account()]).unwrap();
        assert_eq!(
            inspection.outputs[1].role,
            OutputRole::ClaimedButUnproven,
            "an account must not answer for a P2WSH output"
        );

        // And the single-sig change of the same transaction, offered to a session that
        // holds the registry and no accounts.
        let registry = alloc::vec![registration];
        let key = fixture::key_at(CHANGE_PATH).public_key();
        let singlesig_change = transcript_psbt(script_at(CHANGE_PATH), key.0, CHANGE_PATH);
        let inspection = inspect(&singlesig_change, &fixture::context_with(&registry)).unwrap();
        assert_eq!(
            inspection.outputs[1].role,
            OutputRole::ClaimedButUnproven,
            "a registration must not answer for a P2WPKH output"
        );
    }

    /// The shape the device's review log destructures: a proven role names its owner in a
    /// field called `owner`, and that owner renders on its own.
    ///
    /// Pinned here because the reader lives in another crate (the firmware HIL console
    /// prints one line per output), so a rename of this field is a rename in two places and
    /// a compile error in the one that is not this one. The rendered form is part of it: a
    /// log column that suddenly reads `Account(AccountId { .. })` is a log nobody can diff
    /// against yesterday's.
    #[test]
    fn a_proven_role_names_its_owner_by_field() {
        let account = bip84_account();
        let role = OutputRole::Change {
            owner: Owner::Account(account.id()),
            index: 3,
        };
        let OutputRole::Change { owner, index } = role else {
            panic!("the variant a change proof returns");
        };
        assert_eq!(alloc::format!("{owner}"), "bip84/0");
        assert_eq!(index, 3);

        let registry = alloc::vec![fixture::registration()];
        let id = registry[0].id();
        assert_eq!(
            alloc::format!("{}", Owner::Registered(id)),
            alloc::format!("{id}"),
            "a registration still logs as its own id"
        );
    }

    /// The invariant `OutputFacts` documents: evidence and verdict move together.
    #[test]
    fn an_output_role_is_payment_exactly_when_nothing_claims_our_key() {
        let registry = alloc::vec![fixture::registration()];
        for psbt in [
            fixture::multisig_psbt(),
            fixture::multisig_psbt_with_real_change(),
            fixture::multisig_psbt_with_forged_change(),
            fixture::p2wpkh_psbt(),
        ] {
            let inspection = inspect(&psbt, &fixture::context_with(&registry)).unwrap();
            for output in &inspection.outputs {
                assert_eq!(
                    output.role == OutputRole::Payment,
                    !output.claims_our_key,
                    "output {} disagrees with itself",
                    output.index
                );
            }
        }
    }

    #[test]
    fn check_7_refuses_sighash_single() {
        let mut psbt = fixture::p2wpkh_psbt();
        psbt.inputs[0].sighash_type = Some(bitcoin::psbt::PsbtSighashType::from_u32(0x03));
        let err = inspect(&psbt, &fixture::context()).unwrap_err();
        assert_eq!(
            err,
            CheckFailure::SighashTypeNotWhitelisted {
                index: 0,
                found: 0x03
            }
        );
        assert_eq!(err.check(), Check::SighashWhitelist);
    }

    #[test]
    fn check_7_refuses_sighash_all_on_a_taproot_input() {
        let mut psbt = fixture::p2tr_psbt();
        psbt.inputs[0].sighash_type = Some(bitcoin::psbt::PsbtSighashType::from_u32(0x01));
        assert_eq!(
            inspect(&psbt, &fixture::context()).unwrap_err(),
            CheckFailure::SighashTypeNotWhitelisted {
                index: 0,
                found: 0x01
            }
        );
    }

    #[test]
    fn check_7_accepts_an_explicit_sighash_all_on_segwit_v0() {
        let mut psbt = fixture::p2wpkh_psbt();
        psbt.inputs[0].sighash_type = Some(bitcoin::psbt::PsbtSighashType::from_u32(0x01));
        assert!(inspect(&psbt, &fixture::context()).is_ok());
    }

    #[test]
    fn check_8_refuses_a_tweak_that_does_not_reach_the_output_key() {
        let mut psbt = fixture::p2tr_psbt();
        // A merkle root the output key was never tweaked with: the coordinator choosing
        // the verifying key, which is the whole attack.
        psbt.inputs[0].tap_merkle_root =
            Some(bitcoin::taproot::TapNodeHash::from_byte_array([5u8; 32]));
        let err = inspect(&psbt, &fixture::context()).unwrap_err();
        assert_eq!(err, CheckFailure::TaprootTweakMismatch { index: 0 });
        assert_eq!(err.check(), Check::Taproot);
    }

    #[test]
    fn check_8_refuses_a_taproot_input_with_no_internal_key() {
        let mut psbt = fixture::p2tr_psbt();
        psbt.inputs[0].tap_internal_key = None;
        assert_eq!(
            inspect(&psbt, &fixture::context()).unwrap_err(),
            CheckFailure::TaprootInternalKeyMissing { index: 0 }
        );
    }

    #[test]
    fn check_8_refuses_an_internal_key_the_origin_does_not_name() {
        let mut psbt = fixture::p2tr_psbt();
        psbt.inputs[0].tap_internal_key = Some(fixture::key_at("m/86'/0'/0'/0/1").internal_key());
        let err = inspect(&psbt, &fixture::context()).unwrap_err();
        assert_eq!(err, CheckFailure::TaprootInternalKeyMismatch { index: 0 });
        assert_eq!(err.check(), Check::Taproot);
    }

    #[test]
    fn check_8_refuses_a_script_path_claim() {
        let psbt = fixture::p2tr_psbt_with_a_leaf_claim();
        let err = inspect(&psbt, &fixture::context()).unwrap_err();
        assert_eq!(err, CheckFailure::TaprootScriptPathUnsupported { index: 0 });
        assert_eq!(err.check(), Check::Taproot);
    }

    #[test]
    fn check_8_refuses_an_annex() {
        let psbt = fixture::psbt_with_an_annex();
        let err = inspect(&psbt, &fixture::context()).unwrap_err();
        assert_eq!(err, CheckFailure::TaprootAnnexPresent { index: 0 });
        assert_eq!(err.check(), Check::Taproot);
    }

    #[test]
    fn check_6_refuses_a_negative_fee() {
        let mut psbt = fixture::p2wpkh_psbt();
        psbt.unsigned_tx.output[0].value = Amount::from_sat(fixture::PREVOUT_SAT * 2);
        let err = inspect(&psbt, &fixture::context()).unwrap_err();
        assert!(matches!(err, CheckFailure::NegativeFee { .. }));
        assert_eq!(err.check(), Check::Fee);
    }

    // -- interoperability: what a cosigner did to a cosigner's own input ------------------

    /// ARCH check 9's finalized clause is about an input THIS DEVICE would sign. Bitcoin
    /// Core's `walletprocesspsbt` finalizes every input it can before it hands the file
    /// back, so refusing the whole file because a cosigner finalized their own input makes
    /// the ordinary multi-party round unsignable here, over an input index the user cannot
    /// do anything about.
    #[test]
    fn check_9_accepts_a_cosigners_already_finalized_input() {
        let psbt = fixture::foreign_input_finalized_psbt();
        let inspection = inspect(&psbt, &fixture::context()).expect("a cosigner's own input");
        assert!(matches!(inspection.inputs[1].claim, Claim::Foreign));
        assert_eq!(inspection.signable_inputs(), 1);
    }

    /// The other half, and the reason the refusal exists at all: finalize-then-resign is
    /// how a coordinator gets a second signature out of this device under a different
    /// sighash, so an input of OURS arriving finalized is still refused.
    #[test]
    fn check_9_still_refuses_a_finalized_input_of_ours() {
        let mut psbt = fixture::ours_and_a_foreign_input_psbt();
        psbt.inputs[0].final_script_sig = Some(ScriptBuf::new());
        let err = inspect(&psbt, &fixture::context()).unwrap_err();
        assert_eq!(err, CheckFailure::InputAlreadyFinalized { index: 0 });
        assert_eq!(err.check(), Check::GlobalSanity);
    }

    /// A cosigner's unproven amount is accepted when no signature of ours would be made
    /// under a digest that leaves it free. Here that is a taproot spend of ours: BIP-341
    /// hashes `sha_amounts` over every prevout, so the cosigner's claimed amount is inside
    /// our own digest and substituting it produces a transaction that cannot confirm.
    ///
    /// This is the interop win the relaxation was made for, kept without the hole: BIP-174
    /// asks a Signer to verify the UTXO of an input "before signing" it, and a coordinator
    /// that has not supplied its own previous transaction has not made the file unsignable.
    #[test]
    fn check_2_accepts_a_cosigners_unproven_amount_a_signature_of_ours_binds() {
        let psbt = fixture::taproot_spend_beside_an_unproven_input_psbt();
        let inspection = inspect(&psbt, &fixture::context()).expect("a cosigner's own input");
        assert!(matches!(inspection.inputs[1].claim, Claim::Foreign));
        assert_eq!(inspection.signable_inputs(), 1);
        assert_eq!(inspection.inputs[0].kind, ScriptKind::P2tr);
        assert_eq!(inspection.inputs[0].amount_proof, AmountProof::ClaimedByFile);
        assert_eq!(inspection.inputs[1].amount_proof, AmountProof::ClaimedByFile);
        assert!(inspection.fee_is_enforced());
    }

    /// And the other file that keeps its unproven amount: one this device signs nothing in.
    /// There is no signature of ours for a substituted amount to ride on, so reading it is
    /// exactly as safe as reading any other stranger's transaction, and refusing it would
    /// take away the review this device exists to give.
    #[test]
    fn check_2_accepts_an_unproven_amount_in_a_file_we_sign_nothing_in() {
        let psbt = fixture::no_input_of_ours_one_unproven_psbt();
        let inspection = inspect(&psbt, &fixture::context()).expect("a file to read, not sign");
        assert_eq!(inspection.signable_inputs(), 0);
        assert_eq!(inspection.inputs[1].amount_proof, AmountProof::ClaimedByFile);
    }

    /// The fee is a sum over every input, so an unproven amount makes the fee unproven too.
    /// The arithmetic is unchanged and the number is still shown; what the engine adds is
    /// the fact that it is a claim, which the screen has to render differently and a fee
    /// threshold has to read as a lower bound.
    #[test]
    fn an_unproven_amount_anywhere_makes_the_fee_unproven() {
        let psbt = fixture::no_input_of_ours_one_unproven_psbt();
        let inspection = inspect(&psbt, &fixture::context()).unwrap();
        assert_eq!(inspection.fee, Amount::from_sat(fixture::FEE_SAT));
        assert!(!inspection.fee_is_enforced());

        // A file whose every amount is proven: the fee is a measurement.
        let proven = inspect(
            &fixture::ours_and_a_foreign_input_psbt(),
            &fixture::context(),
        )
        .unwrap();
        assert!(proven.fee_is_enforced());
    }

    /// A key-path signature of ours commits to every input amount in the transaction, so a
    /// claimed amount a taproot spend of ours rides on is binding whether or not a previous
    /// transaction proved it.
    #[test]
    fn a_taproot_spend_of_ours_makes_the_claimed_amounts_binding() {
        let psbt = fixture::p2tr_psbt();
        let inspection = inspect(&psbt, &fixture::context()).unwrap();
        assert_eq!(inspection.inputs[0].amount_proof, AmountProof::ClaimedByFile);
        assert!(inspection.fee_is_enforced());
    }

    /// And the pin under that claim: it holds only while check 7 keeps taproot at
    /// SIGHASH_DEFAULT. A signature under ANYONECANPAY would commit to one amount instead
    /// of all of them, so widening the whitelist has to fail here rather than quietly
    /// downgrade a fee this device called binding.
    #[test]
    fn the_taproot_route_to_a_binding_fee_rests_on_the_sighash_whitelist() {
        let mut psbt = fixture::p2tr_psbt();
        psbt.inputs[0].sighash_type = Some(bitcoin::TapSighashType::AllPlusAnyoneCanPay.into());
        let err = inspect(&psbt, &fixture::context()).unwrap_err();
        assert!(matches!(
            err,
            CheckFailure::SighashTypeNotWhitelisted { index: 0, .. }
        ));
    }

    /// And the 2020 Trezor fee attack stays closed: for an input of ours the full previous
    /// transaction is the only thing that proves the amount BIP-143 makes us sign.
    #[test]
    fn check_2_still_demands_the_previous_transaction_for_an_input_of_ours() {
        let mut psbt = fixture::ours_and_a_foreign_input_psbt();
        psbt.inputs[0].non_witness_utxo = None;
        let err = inspect(&psbt, &fixture::context()).unwrap_err();
        assert_eq!(err, CheckFailure::MissingPreviousTransaction { index: 0 });
        assert_eq!(err.check(), Check::Prevouts);
    }

    /// An input that states no value at all is refused whoever it belongs to. The fee is a
    /// sum over EVERY input, so a missing amount is not an unproven number to caveat, it is
    /// the absence of a number this device has to show before anyone can authorise it.
    #[test]
    fn check_2_refuses_a_cosigners_input_that_states_no_value() {
        let mut psbt = fixture::ours_and_a_foreign_input_psbt();
        psbt.inputs[1].non_witness_utxo = None;
        psbt.inputs[1].witness_utxo = None;
        assert_eq!(
            inspect(&psbt, &fixture::context()).unwrap_err(),
            CheckFailure::MissingPrevout { index: 1 }
        );
    }

    // -- the published corpus ------------------------------------------------------------

    /// What this device does with every vector in the corpus, as the sentence its screen
    /// would show.
    ///
    /// A table rather than a handful of named assertions because the interoperability
    /// question is not "is this one file refused" but "which of the published files can a
    /// user of this device actually sign": a refusal that creeps in somewhere else in the
    /// pipeline shows up here as a changed row, and every row that says `refused` has to be
    /// a refusal this device is prepared to defend. The four the BIP itself files under
    /// "Fails Signer checks" are the interesting negatives: none of their defects sits on
    /// an input this device would sign, so it accepts the files and signs nothing in them,
    /// which is the same answer a signer that checked them all and found nothing of its own
    /// would give.
    const PUBLISHED_VERDICTS: &[(&str, &str)] = &[
        ("bip174 valid 1 unsigned p2sh", "accepted"),
        // Input 0 of this vector carries a final scriptSig and nothing else - not even the
        // UTXO that BIP-174 tells an Input Finalizer to keep - so there is no amount for
        // it, and with one input's amount missing there is no fee to show. See
        // `MissingPrevout`.
        (
            "bip174 valid 2 one input finalized",
            "refused: check 2 (previous transactions): input 0 does not say what it is worth",
        ),
        ("bip174 valid 3 declared sighash all", "accepted"),
        ("bip174 valid 4 output derivations", "accepted"),
        ("bip174 valid 5 p2sh p2wsh multisig", "accepted"),
        ("bip174 valid 6 p2wsh 2of2 global xpubs", "accepted"),
        // Constructed to carry an unknown key-value pair and nothing else, so its single
        // input states no value either. Refused for the same reason as vector 2, and the
        // unknown-field pass-through it exists to prove is tested in `codec.rs`, which
        // needs no amounts.
        (
            "bip174 valid 7 unknown types",
            "refused: check 2 (previous transactions): input 0 does not say what it is worth",
        ),
        ("bip174 valid 8 global xpub", "accepted"),
        (
            "bip174 valid 9 no inputs no outputs",
            "refused: check 9 (global sanity): the transaction has no inputs",
        ),
        (
            "bip174 valid 10 no inputs",
            "refused: check 9 (global sanity): the transaction has no inputs",
        ),
        ("bip174 valid 11 witness utxo for a legacy input", "accepted"),
        (
            "bip174 valid 12 redeem script mismatch non witness",
            "accepted",
        ),
        ("bip174 valid 13 redeem script mismatch witness", "accepted"),
        ("bip174 valid 14 witness script mismatch", "accepted"),
        ("bip371 taproot key path", "accepted"),
        ("bip371 taproot key path signed", "accepted"),
        ("bip371 taproot script tree", "accepted"),
    ];

    /// The BIP-174 vectors are not spends of ours, so nothing in them is signable; what
    /// this asserts is that each one reaches a NAMED outcome rather than a panic or a
    /// generic error, which is the property that matters for untrusted input.
    #[test]
    fn every_published_vector_reaches_a_named_outcome() {
        let cx = fixture::context();
        for (name, hex_bytes) in test_corpus::VECTORS {
            let raw = hex::decode(hex_bytes).expect(name);
            let psbt = crate::psbt::decode(&raw).unwrap_or_else(|e| panic!("{name}: {e}"));
            match inspect(&psbt, &cx) {
                Ok(inspection) => {
                    // None of the published vectors is a spend by this fixture seed.
                    assert_eq!(inspection.signable_inputs(), 0, "{name}");
                }
                Err(e) => {
                    assert!(!e.to_string().is_empty(), "{name}");
                }
            }
        }
    }

    /// The whole table at once, compared as one string so that a failing run prints every
    /// row and not just the first disagreement.
    #[test]
    fn the_published_vectors_get_the_verdicts_this_device_stands_behind() {
        let cx = fixture::context();
        let mut actual = alloc::string::String::new();
        for (name, hex_bytes) in test_corpus::VECTORS {
            let raw = hex::decode(hex_bytes).expect(name);
            let psbt = crate::psbt::decode(&raw).unwrap_or_else(|e| panic!("{name}: {e}"));
            let verdict = match inspect(&psbt, &cx) {
                Ok(_) => "accepted".to_string(),
                Err(e) => alloc::format!("refused: {e}"),
            };
            actual += &alloc::format!("{name} -> {verdict}\n");
        }
        let mut expected = alloc::string::String::new();
        for (name, verdict) in PUBLISHED_VERDICTS {
            expected += &alloc::format!("{name} -> {verdict}\n");
        }
        assert_eq!(actual, expected);
    }

    // -- the amount-substitution attack (BIP-174 line 415) -------------------------------

    /// BIP-174's line 415 footnote, enforced: a BIP-143 signature of ours commits to its
    /// own input's amount and to nothing else, so it must not stand beside an amount the
    /// file merely asserts.
    ///
    /// Both rounds of the probe are refused, and the refusal names both ends of the pair -
    /// the input whose signature would be too narrow, and the input whose amount rests on
    /// nothing - because either end is one a sender could fix.
    #[test]
    fn check_2_refuses_an_unproven_amount_beside_a_segwit_v0_signature_of_ours() {
        for round in 0..2u16 {
            let psbt = fixture::amount_substitution_round(round as usize);
            let err = inspect(&psbt, &fixture::context()).unwrap_err();
            assert_eq!(
                err,
                CheckFailure::UnprovenAmountBesideOurSignature {
                    signing: round,
                    unproven: 1 - round,
                },
                "round {round}"
            );
            assert_eq!(err.check(), Check::Prevouts);
        }
    }

    /// The same rule on the minimal file, so that the refusal is not read as a property of
    /// the probe's scale: one input of ours with its previous transaction, one input
    /// presented as a cosigner's whose amount is the file's word, and nothing else.
    #[test]
    fn check_2_refuses_the_minimal_shape_of_the_substitution() {
        let psbt = fixture::foreign_input_without_its_prev_tx_psbt();
        let err = inspect(&psbt, &fixture::context()).unwrap_err();
        assert_eq!(
            err,
            CheckFailure::UnprovenAmountBesideOurSignature {
                signing: 0,
                unproven: 1,
            }
        );
        // And the sentence it gives names both ends, because either can be the one fixed.
        let said = err.to_string();
        assert!(said.contains("input 1 has no previous transaction"), "{said}");
        assert!(said.contains("signing input 0"), "{said}");
    }

    /// What that refusal is worth, measured on the files themselves so it cannot be read as
    /// a story about a check.
    ///
    /// The two rounds share one unsigned transaction, so the signatures they harvest
    /// combine. Each round's own arithmetic - one proven coin plus one claimed 20000 sat -
    /// lands on the ordinary 10000 sat fee every other fixture declares, while the two coins
    /// really behind that transaction are 1 BTC each and the payment is 1.0001 BTC. The
    /// loss is 0.9999 BTC and it is invisible in every number either screen could show,
    /// which is why this is a refusal and not a warning.
    #[test]
    fn the_amount_substitution_probe_burns_a_coin_no_screen_could_have_named() {
        let rounds = [
            fixture::amount_substitution_round(0),
            fixture::amount_substitution_round(1),
        ];
        assert_eq!(
            rounds[0].unsigned_tx, rounds[1].unsigned_tx,
            "the two rounds have to be one transaction, or they do not combine"
        );

        for (round, psbt) in rounds.iter().enumerate() {
            // What the file states about itself, read the way `inspect` would read it.
            let stated: u64 = psbt
                .inputs
                .iter()
                .map(|i| match (&i.non_witness_utxo, &i.witness_utxo) {
                    (Some(prev), _) => prev.output[0].value.to_sat(),
                    (None, Some(claimed)) => claimed.value.to_sat(),
                    (None, None) => unreachable!("the probe states every amount"),
                })
                .sum();
            let paid: u64 = psbt.unsigned_tx.output.iter().map(|o| o.value.to_sat()).sum();
            assert_eq!(stated - paid, fixture::FEE_SAT, "round {round}");
            // And exactly one input of ours to sign, which is what makes it two rounds.
            assert_eq!(
                inspect(psbt, &fixture::context()).unwrap_err().check(),
                Check::Prevouts
            );
        }

        let real = 2 * fixture::PROBE_COIN_SAT;
        let paid: u64 = rounds[0].unsigned_tx.output.iter().map(|o| o.value.to_sat()).sum();
        assert_eq!(real - paid, 99_990_000, "0.9999 BTC, against a screen saying 10000 sat");
    }

    /// The end-to-end half: with the refusal in place, no signature of ours exists for the
    /// combined transaction to carry.
    ///
    /// `sign` cannot be reached without an [`Inspection`], and an [`Inspection`] is what
    /// `inspect` refuses to produce, so this is a property of the pipeline's shape and not
    /// of a check somebody has to remember to call. What the probe harvested before
    /// 2026-08-18 was one ECDSA signature per round, each made over its own input's REAL
    /// 100,000,000 sat, each verifying against that amount, and both valid in the same
    /// transaction.
    #[test]
    fn no_signature_of_ours_survives_the_amount_substitution_probe() {
        for round in 0..2usize {
            let psbt = fixture::amount_substitution_round(round);
            assert!(inspect(&psbt, &fixture::context()).is_err(), "round {round}");
        }
    }

    /// The sighash whitelist the refusal rests on, pinned as a set.
    ///
    /// [`commits_to_every_amount`] says a taproot key-path signature of ours binds every
    /// input amount. That is true of BIP-341's `sha_amounts` and false the moment an
    /// ANYONECANPAY flag is admitted, so the admitted set is not something to leave to a
    /// comment: widening it has to fail HERE, loudly, rather than quietly withdraw the
    /// premise under an acceptance the device already grants.
    #[test]
    fn the_admitted_sighash_set_is_the_one_the_amount_rule_rests_on() {
        for (kind, admitted) in [
            (ScriptKind::P2wpkh, &[0x01u32] as &[u32]),
            (ScriptKind::P2shP2wpkh, &[0x01]),
            (ScriptKind::P2wsh, &[0x01]),
            (ScriptKind::P2tr, &[0x00]),
            (ScriptKind::P2pkh, &[]),
            (ScriptKind::P2sh, &[]),
            (ScriptKind::OpReturn, &[]),
            (ScriptKind::Other, &[]),
        ] {
            assert_eq!(whitelisted_sighashes(kind), admitted, "{kind:?}");
        }
    }

    /// And the coupling is live rather than decorative: hand the predicate a widened list
    /// and watch the answer change.
    ///
    /// This is what makes the pin above worth failing on. If a future change admits
    /// SIGHASH_ALL for taproot the claim survives, because `sha_amounts` is still in the
    /// digest; if it admits any ANYONECANPAY flag the claim is withdrawn, and
    /// [`amounts_our_signatures_do_not_cover`] starts refusing the files it used to allow
    /// instead of trusting a signature that no longer binds them.
    #[test]
    fn the_amount_rule_reads_the_whitelist_rather_than_the_script_kind() {
        assert!(commits_to_every_amount(ScriptKind::P2tr, &[0x00]));
        assert!(commits_to_every_amount(ScriptKind::P2tr, &[0x00, 0x01]));
        for widened in [&[0x00u32, 0x81] as &[u32], &[0x83], &[]] {
            assert!(
                !commits_to_every_amount(ScriptKind::P2tr, widened),
                "{widened:x?} must withdraw the claim"
            );
        }
        // BIP-143 hashes one amount under every flag it has, so segwit v0 answers no
        // whatever it is offered.
        for kind in [ScriptKind::P2wpkh, ScriptKind::P2shP2wpkh, ScriptKind::P2wsh] {
            for offered in [&[0x01u32] as &[u32], &[0x00, 0x01]] {
                assert!(!commits_to_every_amount(kind, offered), "{kind:?}");
            }
        }
    }
    // -- the batch one approval covers (0.2.0-G10) ---------------------------------------

    /// The list an approval screen shows is the list of inputs that carry a claim of ours,
    /// and it is a list rather than a count because a batch approval has to be able to name
    /// them.
    #[test]
    fn a_batch_review_names_every_input_this_device_would_sign() {
        let psbt = fixture::batch_psbt(6);
        let inspection = inspect(&psbt, &fixture::context()).unwrap();
        assert_eq!(inspection.signable_input_indexes(), alloc::vec![0, 1, 2, 3, 4, 5]);
        assert_eq!(inspection.signable_inputs(), 6);
        assert_eq!(
            inspection.signable_input_total(),
            Amount::from_sat(6 * fixture::PREVOUT_SAT)
        );
        assert_eq!(inspection.input_total, inspection.signable_input_total());

        // The same file with one input that is somebody else's: the list shrinks, the
        // totals do not, and the difference between the two is what a multi-party review
        // has to show.
        let mixed = fixture::ours_and_a_foreign_input_psbt();
        let inspection = inspect(&mixed, &fixture::context()).unwrap();
        assert_eq!(inspection.signable_input_indexes(), alloc::vec![0]);
        assert!(inspection.signable_input_total() < inspection.input_total);
    }

    /// What leaves and what comes back, over a file where this crate can actually prove the
    /// difference.
    ///
    /// Proven change is the only kind that may be netted out, so a multisig registration is
    /// the only file where `leaving_total` is below `output_total`. The two partition the
    /// outputs exactly, which is the property that stops a review from double counting a
    /// change output or losing one.
    #[test]
    fn a_batch_review_separates_change_from_what_leaves() {
        let registry = alloc::vec![fixture::registration()];
        let psbt = fixture::multisig_psbt_with_real_change();
        let inspection = inspect(&psbt, &fixture::context_with(&registry)).unwrap();

        let change = inspection.change_total();
        let leaving = inspection.leaving_total();
        assert!(change > Amount::ZERO, "the fixture pays real change");
        assert_eq!(change + leaving, inspection.output_total);
        assert_eq!(
            leaving + change + inspection.fee,
            inspection.input_total,
            "every satoshi of the file is accounted for once"
        );

        // A self-send to the wallet's own RECEIVE address is not change and must not be
        // netted out; check 3 already separates the two and this is the arithmetic that
        // rests on it.
        let self_send = fixture::multisig_psbt_with_receive_claim();
        let inspection = inspect(&self_send, &fixture::context_with(&registry)).unwrap();
        assert_eq!(inspection.change_total(), Amount::ZERO);
        assert_eq!(inspection.leaving_total(), inspection.output_total);
    }

    /// Inspected with no account in scope, a single-sig batch says everything is leaving.
    /// Conservative on purpose: with nothing to re-derive from, a device that netted out
    /// an unproven claim would be the 2019 change-confusion bug with better arithmetic.
    /// What the same file says once its account IS in scope is
    /// `check_3_proves_singlesig_change`.
    #[test]
    fn a_single_sig_batch_counts_every_output_as_leaving() {
        let psbt = fixture::batch_psbt(3);
        let inspection = inspect(&psbt, &fixture::context()).unwrap();
        assert_eq!(inspection.change_total(), Amount::ZERO);
        assert_eq!(inspection.leaving_total(), inspection.output_total);
    }

    /// How many rows carry the caveat, and the separate question of whether the fee is
    /// binding anyway.
    ///
    /// Both amounts in this file rest on the file's word, and the fee is still enforced,
    /// because the signature this device is about to make is a BIP-341 key-path one and
    /// `sha_amounts` puts every one of those amounts inside its digest. A review that
    /// collapsed the two questions would either hide a caveat or refuse a file it has no
    /// reason to.
    #[test]
    fn a_batch_review_counts_the_amounts_that_rest_on_the_files_word() {
        let psbt = fixture::taproot_spend_beside_an_unproven_input_psbt();
        let inspection = inspect(&psbt, &fixture::context()).unwrap();
        assert_eq!(inspection.unproven_amounts(), 2);
        assert!(inspection.fee_is_enforced());

        let proven = fixture::batch_psbt(4);
        let inspection = inspect(&proven, &fixture::context()).unwrap();
        assert_eq!(inspection.unproven_amounts(), 0);
        assert!(inspection.fee_is_enforced());
    }

    /// Check 2's pairing rule is about the FILE, not about a row, so burying the unproven
    /// input among a batch of honest ones changes nothing.
    ///
    /// The refusal names the first signature of ours and the unproven input, which for a
    /// batch is the only pair worth naming: it is the combination that is the defect, and
    /// every other signature in the batch is in the same position as the first.
    #[test]
    fn check_2_refuses_an_unproven_amount_buried_in_a_batch() {
        for ours in [1u32, 8] {
            let psbt = fixture::batch_psbt_with_an_unproven_input(ours);
            let err = inspect(&psbt, &fixture::context()).unwrap_err();
            assert_eq!(
                err,
                CheckFailure::UnprovenAmountBesideOurSignature {
                    signing: 0,
                    unproven: ours as u16,
                },
                "{ours} inputs of ours"
            );
            assert_eq!(err.check(), Check::Prevouts);
        }

        // And the batch without it inspects clean, so what the refusal is about is the
        // unproven amount and not the input count.
        assert!(inspect(&fixture::batch_psbt(8), &fixture::context()).is_ok());
    }

    // -- Check 3's work bound ------------------------------------------------------------
    //
    // Every origin on an output map that names our fingerprint buys a re-derivation of one
    // of our wallets, and the map is written by whoever wrote the file. Measured on an
    // x86-64 release build against a single 2-of-3 registration, one such origin costs 170
    // microseconds and 60 bytes; the megabyte this device accepts therefore held roughly
    // 17,000 of them, which was seconds here and minutes to an hour on the device, with
    // nothing on screen and no way out but power. These pin the bound that ends that.

    /// Distinct public keys for a map an attacker sizes. From small fixed scalars rather
    /// than an RNG, so the hostile file is the same file on every run.
    fn filler_keys(n: usize) -> alloc::vec::Vec<bitcoin::secp256k1::PublicKey> {
        (1..=n)
            .map(|i| {
                let mut scalar = [0u8; 32];
                scalar[24..].copy_from_slice(&(i as u64).to_be_bytes());
                bitcoin::secp256k1::PublicKey::from_secret_key(
                    secp(),
                    &bitcoin::secp256k1::SecretKey::from_slice(&scalar)
                        .expect("a small non-zero scalar is a valid secret key"),
                )
            })
            .collect()
    }

    /// Add `n` origins naming our fingerprint at `path` to output `index`, none of which
    /// proves anything - which is the point: an unproven claim is what keeps the loop
    /// deriving.
    fn stuff_output_origins(psbt: &mut Psbt, index: usize, path: &DerivationPath, n: usize) {
        for key in filler_keys(n) {
            psbt.outputs[index]
                .bip32_derivation
                .insert(key, (fixture::fingerprint(), path.clone()));
        }
    }

    /// How many origins on one output map name us. Counted here from the file rather than
    /// read back out of the engine, so the assertions below cannot agree with a miscount.
    fn count_own_origins(psbt: &Psbt, index: usize) -> usize {
        let output = &psbt.outputs[index];
        output
            .bip32_derivation
            .values()
            .map(|source| source.0)
            .chain(output.tap_key_origins.values().map(|(_, source)| source.0))
            .filter(|fingerprint| *fingerprint == fixture::fingerprint())
            .count()
    }

    /// THE DEFECT. One origin past the bound is refused, by name, against check 3.
    #[test]
    fn check_3_refuses_more_own_origins_on_one_output_than_a_wallet_can_have() {
        let registry = alloc::vec![fixture::registration()];
        let cx = fixture::context_with(&registry);
        let max = usize::from(cx.limits.max_own_output_origins);

        // The real change fixture, which already names us once, plus enough fillers to
        // cross the bound. Every filler carries the SAME path as the honest claim, so what
        // is refused is the count and not the shape.
        let mut psbt = fixture::multisig_psbt_with_real_change();
        let path = fixture::multisig_leaf_path(Keychain::Change, 4);
        stuff_output_origins(&mut psbt, 1, &path, max);
        assert_eq!(count_own_origins(&psbt, 1), max + 1);

        let err = inspect(&psbt, &cx).unwrap_err();
        assert_eq!(
            err,
            CheckFailure::TooManyOwnOutputOrigins {
                at: Location::Output(1),
                found: max + 1,
                max: cx.limits.max_own_output_origins,
            }
        );
        assert_eq!(err.check(), Check::ChangeDerivation);
    }

    /// The bound is where a legitimate file ends and not before it: an output naming us in
    /// as many origins as a wallet has cosigner slots is inspected, and the honest claim
    /// among them is still proven.
    #[test]
    fn check_3_still_proves_change_at_the_origin_limit() {
        let registry = alloc::vec![fixture::registration()];
        let cx = fixture::context_with(&registry);
        let max = usize::from(cx.limits.max_own_output_origins);

        let mut psbt = fixture::multisig_psbt_with_real_change();
        let path = fixture::multisig_leaf_path(Keychain::Change, 4);
        stuff_output_origins(&mut psbt, 1, &path, max - 1);
        assert_eq!(count_own_origins(&psbt, 1), max);

        let inspection = inspect(&psbt, &cx).unwrap();
        assert_eq!(
            inspection.outputs[1].role,
            OutputRole::Change {
                owner: Owner::Registered(registry[0].id()),
                index: 4
            }
        );
    }

    /// The hostile file the bound exists for: a map far past anything a wallet has, on the
    /// path shape that costs the most to disprove. Against the unbounded code this ran
    /// every one of these derivations before answering.
    #[test]
    fn check_3_refuses_a_hostile_output_derivation_map() {
        let registry = alloc::vec![fixture::registration()];
        let cx = fixture::context_with(&registry);

        let mut psbt = fixture::multisig_psbt_with_real_change();
        let path = fixture::multisig_leaf_path(Keychain::Change, 4);
        stuff_output_origins(&mut psbt, 1, &path, 4_000);

        let err = inspect(&psbt, &cx).unwrap_err();
        assert_eq!(err.check(), Check::ChangeDerivation);
        assert!(matches!(
            err,
            CheckFailure::TooManyOwnOutputOrigins { found: 4_001, .. }
        ));
    }

    /// Both maps are one budget. A file that spent the bound on `bip32_derivation` and
    /// then carried on in `tap_key_origins` would have bought itself a second helping.
    #[test]
    fn check_3_counts_taproot_origins_in_the_same_budget() {
        let cx = fixture::context();
        let max = usize::from(cx.limits.max_own_output_origins);
        let half = max / 2;

        let key = fixture::key_at(CHANGE_PATH).public_key();
        let mut psbt = transcript_psbt(script_at(CHANGE_PATH), key.0, CHANGE_PATH);
        let path = fixture::path(CHANGE_PATH);
        // One in the map already, so `half` more here and `max - half` taproot origins put
        // the file exactly one past the bound.
        stuff_output_origins(&mut psbt, 1, &path, half);
        for filler in filler_keys(max - half) {
            psbt.outputs[1].tap_key_origins.insert(
                XOnlyPublicKey::from(filler),
                (alloc::vec![], (fixture::fingerprint(), path.clone())),
            );
        }
        assert_eq!(count_own_origins(&psbt, 1), max + 1);

        let err = inspect(&psbt, &cx).unwrap_err();
        assert_eq!(
            err,
            CheckFailure::TooManyOwnOutputOrigins {
                at: Location::Output(1),
                found: max + 1,
                max: cx.limits.max_own_output_origins,
            }
        );
    }

    /// Origins naming somebody else are not rationed, and must not be: a 15-cosigner
    /// output legitimately carries fourteen of them and reading one costs a four-byte
    /// comparison.
    #[test]
    fn the_origin_bound_does_not_count_other_peoples_keys() {
        let cx = fixture::context();
        let foreign = Fingerprint::from([0xde, 0xad, 0xbe, 0xef]);
        let mut psbt = fixture::p2wpkh_psbt();
        let path = fixture::path(CHANGE_PATH);
        for key in filler_keys(usize::from(cx.limits.max_own_output_origins) * 4) {
            psbt.outputs[0]
                .bip32_derivation
                .insert(key, (foreign, path.clone()));
        }
        assert_eq!(count_own_origins(&psbt, 0), 0);

        let inspection = inspect(&psbt, &cx).unwrap();
        assert_eq!(inspection.outputs[0].role, OutputRole::Payment);
        assert!(!inspection.outputs[0].claims_our_key);
    }

    // -- The device's own account set ----------------------------------------------------

    /// THE DEFECT. `psbt::inspect` is `inspect_with_accounts` with an EMPTY slice, and the
    /// firmware called it, so the single-sig half of check 3 never ran on hardware: change
    /// could not be proven, so it counted as money leaving and the review overstated the
    /// spend by the whole of it. `derive::device_accounts` is the set that half needs.
    #[test]
    fn device_accounts_prove_single_sig_change() {
        let key = fixture::key_at(CHANGE_PATH).public_key();
        let psbt = transcript_psbt(script_at(CHANGE_PATH), key.0, CHANGE_PATH);

        // What the device did: 198,500 sat of 200,000 reported as leaving, true only if
        // the change belonged to somebody else.
        let blind = inspect(&psbt, &fixture::context()).unwrap();
        assert_eq!(blind.outputs[1].role, OutputRole::ClaimedButUnproven);
        assert_eq!(
            blind.leaving_total(),
            Amount::from_sat(TRANSCRIPT_PAYMENT_SAT + TRANSCRIPT_CHANGE_SAT)
        );

        let accounts = crate::derive::device_accounts(&fixture::SEED, fixture::NETWORK);
        let seeing = inspect_with_accounts(&psbt, &fixture::context(), &accounts).unwrap();
        assert_eq!(
            seeing.outputs[1].role,
            OutputRole::Change {
                owner: Owner::Account(bip84_account().id()),
                index: 0
            }
        );
        assert_eq!(
            seeing.leaving_total(),
            Amount::from_sat(TRANSCRIPT_PAYMENT_SAT)
        );
        assert_eq!(seeing.change_total(), Amount::from_sat(TRANSCRIPT_CHANGE_SAT));
    }

    /// The set covers every scheme the device derives, not just the one the transcript
    /// used. A scheme missing from it is a whole address family whose change reads as a
    /// payment, which is the same defect one wallet at a time.
    #[test]
    fn device_accounts_cover_every_single_sig_scheme() {
        let accounts = crate::derive::device_accounts(&fixture::SEED, fixture::NETWORK);
        assert_eq!(accounts.len(), crate::derive::Scheme::ALL.len());

        for account in &accounts {
            assert_eq!(account.id().account(), crate::derive::ChildIndex::ZERO);
            let leaf = account
                .leaf(Keychain::Change, 0)
                .expect("a single-sig account builds its own change leaf");
            let path = alloc::format!("{}/1/0", account.origin());
            let psbt = transcript_psbt(leaf.script_pubkey.clone(), leaf.key.0, &path);

            let inspection = inspect_with_accounts(&psbt, &fixture::context(), &accounts).unwrap();
            assert_eq!(
                inspection.outputs[1].role,
                OutputRole::Change {
                    owner: Owner::Account(account.id()),
                    index: 0
                },
                "{} change went unproven",
                account.id()
            );
        }
    }

    // -- Check 3's FILE bound ------------------------------------------------------------
    //
    // The bound above is per OUTPUT, and a file is not one output. `max_outputs` is 255, so
    // a file that sits exactly on the per-output bound on every output carries 255 x 15 =
    // 3,825 origins naming us and was ACCEPTED: measured on an x86-64 release build on
    // 2026-08-19, 27.671 seconds against the largest registry this device holds, which is
    // about 2.7 hours on the device at the 350x ratio `max_change_derivations` derives. The
    // same file now costs 0.017 s and a refusal. These pin the bounds that end that, and
    // there are two of them because a file buys two things: origins to read, and
    // derivations to prove them with.

    /// Eight 15-of-15 wallets sharing our BIP-48 origin: the most expensive registry this
    /// device can hold, and not a contrived one - registrations share an origin whenever a
    /// user registers several wallets at the same BIP-48 account, which is the ordinary
    /// thing to do. Every one of them accepts a claimed path as its own leaf shape, so
    /// every one of them has to rebuild its script to say no.
    fn widest_registry() -> alloc::vec::Vec<Registration> {
        (0..8).map(|salt| n_of_n_registration(15, salt)).collect()
    }

    /// An `n`-of-`n` P2WSH wallet with this device as a member, at the fixture BIP-48
    /// origin. `salt` varies the OTHER cosigners, so two registrations differ in the keys
    /// they build with and agree in the paths they answer to.
    fn n_of_n_registration(n: usize, salt: u8) -> Registration {
        let mut keys = alloc::vec![cosigner_expression(&fixture::SEED)];
        for i in 1..n {
            let mut seed = [0u8; 64];
            seed[0] = salt;
            seed[1] = i as u8;
            seed[2] = 0xa5;
            keys.push(cosigner_expression(&seed));
        }
        crate::multisig::parse(&alloc::format!(
            "wsh(sortedmulti({n},{}))",
            keys.join(",")
        ))
        .expect("a sortedmulti of valid xpubs parses")
        .verify(&fixture::SEED, fixture::NETWORK)
        .expect("the fixture seed is the first cosigner")
    }

    /// One cosigner key expression at the fixture BIP-48 origin, derived rather than
    /// hand-written so a registration built here is one `Pending::verify` really accepts.
    fn cosigner_expression(seed: &[u8; 64]) -> alloc::string::String {
        let secp = crate::derive::secp();
        let master = bitcoin::bip32::Xpriv::new_master(fixture::NETWORK, seed)
            .expect("a fixed 64-byte seed is a valid master");
        let account = master
            .derive_priv(secp, &fixture::path(fixture::BIP48_ORIGIN))
            .expect("the BIP-48 origin derives");
        alloc::format!(
            "[{}/48h/0h/0h/2h]{}/<0;1>/*",
            crate::derive::master_fingerprint(seed, fixture::NETWORK),
            bitcoin::bip32::Xpub::from_priv(secp, &account)
        )
    }

    /// A single-sig spend widened to `outputs` outputs, each carrying `per_output` origins
    /// that name us on a BIP-48 change-leaf path and prove nothing.
    ///
    /// The path shape is the expensive one on purpose: every registration's `locate_path`
    /// accepts it, so every registration has to derive its whole cosigner set to disprove
    /// it. The input is single-sig so that what is being measured is the OUTPUT half.
    fn hostile_output_map_psbt(outputs: usize, per_output: usize) -> Psbt {
        let base = fixture::p2wpkh_psbt();
        let mut tx = base.unsigned_tx.clone();
        tx.output[0].value = Amount::from_sat(100);
        let not_ours = ScriptBuf::new_p2wsh(&bitcoin::WScriptHash::hash(b"not a script of ours"));
        while tx.output.len() < outputs {
            tx.output.push(TxOut {
                value: Amount::from_sat(100),
                script_pubkey: not_ours.clone(),
            });
        }
        let inputs = base.inputs.clone();
        let mut psbt = Psbt::from_unsigned_tx(tx).expect("a widened fixture is a valid psbt");
        psbt.inputs = inputs;

        let path = fixture::multisig_leaf_path(Keychain::Change, 4);
        let keys = filler_keys(per_output);
        for output in psbt.outputs.iter_mut() {
            for key in &keys {
                output
                    .bip32_derivation
                    .insert(*key, (fixture::fingerprint(), path.clone()));
            }
        }
        psbt
    }

    /// How many origins name us across the WHOLE file, counted from the file rather than
    /// read back out of the engine.
    fn own_origins_in_file(psbt: &Psbt) -> usize {
        (0..psbt.outputs.len()).map(|i| count_own_origins(psbt, i)).sum()
    }

    /// THE DEFECT. The per-output bound is exactly obeyed on all 255 outputs and the file
    /// is still refused, because 255 obediences are not a bound.
    #[test]
    fn check_3_refuses_a_file_that_spends_the_per_output_bound_on_every_output() {
        let cx = fixture::context();
        let per_output = usize::from(cx.limits.max_own_output_origins);
        let psbt = hostile_output_map_psbt(usize::from(cx.limits.max_outputs), per_output);

        // Every part of this file is within the per-output bound; the whole of it is not.
        assert_eq!(psbt.outputs.len(), 255);
        for i in 0..psbt.outputs.len() {
            assert_eq!(count_own_origins(&psbt, i), per_output);
        }
        assert_eq!(own_origins_in_file(&psbt), 3_825);

        let err = inspect(&psbt, &cx).unwrap_err();
        assert_eq!(
            err,
            CheckFailure::TooManyOwnOriginsInFile {
                found: 3_825,
                max: cx.limits.max_own_origins_in_file,
            }
        );
        assert_eq!(err.check(), Check::ChangeDerivation);
    }

    /// The control that makes the test above mean something: the very same shape, judged
    /// with the file bounds lifted and only the per-output bound left, is ACCEPTED. That is
    /// what the device did before these two fields existed, and it is why neither of them
    /// is decoration.
    ///
    /// A hundred outputs rather than 255 and an empty registry, so the control costs
    /// milliseconds instead of the half minute the full worst case took to be accepted in.
    #[test]
    fn the_per_output_bound_alone_accepts_what_the_file_bound_refuses() {
        let unbounded = Context {
            limits: StructuralLimits {
                max_own_origins_in_file: u16::MAX,
                max_change_derivations: u32::MAX,
                ..StructuralLimits::DEFAULT
            },
            ..fixture::context()
        };
        let psbt = hostile_output_map_psbt(100, 15);
        assert_eq!(own_origins_in_file(&psbt), 1_500);

        // Every output obeys the per-output bound, so the only bound that was there had
        // nothing to say, and the file went through.
        assert!(inspect(&psbt, &unbounded).is_ok());

        assert_eq!(
            inspect(&psbt, &fixture::context()).unwrap_err(),
            CheckFailure::TooManyOwnOriginsInFile {
                found: 1_500,
                max: StructuralLimits::DEFAULT.max_own_origins_in_file,
            }
        );
    }

    /// The number the refusal quotes is the file's real total and not wherever a running
    /// sum crossed the line, because the census counts the file before it judges it.
    #[test]
    fn the_file_bound_reports_what_the_file_actually_holds() {
        let cx = fixture::context();
        let over = usize::from(cx.limits.max_own_origins_in_file) + 1;
        // Ten origins on each of `over / 10 + 1` outputs: every output far inside the
        // per-output bound, the file one origin past its own.
        let psbt = hostile_output_map_psbt(over / 10 + 1, 10);
        let total = own_origins_in_file(&psbt);
        assert!(total > usize::from(cx.limits.max_own_origins_in_file));

        assert_eq!(
            inspect(&psbt, &cx).unwrap_err(),
            CheckFailure::TooManyOwnOriginsInFile {
                found: total,
                max: cx.limits.max_own_origins_in_file,
            }
        );
    }

    /// The per-output bound still speaks first, and still names the output. A file bound
    /// that swallowed it would have made every fat map report the same sentence.
    #[test]
    fn one_fat_output_is_still_refused_as_one_fat_output() {
        let cx = fixture::context();
        let psbt = hostile_output_map_psbt(1, usize::from(cx.limits.max_own_output_origins) + 1);

        assert_eq!(
            inspect(&psbt, &cx).unwrap_err(),
            CheckFailure::TooManyOwnOutputOrigins {
                at: Location::Output(0),
                found: usize::from(cx.limits.max_own_output_origins) + 1,
                max: cx.limits.max_own_output_origins,
            }
        );
    }

    /// THE SECOND DEFECT, and the one a count cannot reach. Every output here carries a
    /// single origin - a fifteenth of what the per-output bound allows, sixty-four of them
    /// well inside the file bound - and proving one against the widest registry this device
    /// holds costs 240 derivations. What an origin COSTS is set by the device's registry,
    /// which no bound on the file's SIZE can see: the very same file is inspected without
    /// complaint by the test below, on a device whose registry is cheaper.
    #[test]
    fn check_3_refuses_claims_that_would_cost_more_than_the_device_will_spend() {
        let registry = widest_registry();
        let cx = fixture::context_with(&registry);
        let psbt = hostile_output_map_psbt(64, 1);

        assert_eq!(own_origins_in_file(&psbt), 64);
        assert!(own_origins_in_file(&psbt) < usize::from(cx.limits.max_own_origins_in_file));

        let err = inspect(&psbt, &cx).unwrap_err();
        assert_eq!(
            err,
            CheckFailure::ChangeDerivationBudgetExhausted {
                // Eight registrations at 32 derivations each is 256 an output, so the
                // budget of 512 covers two outputs and stops inside the third.
                at: Location::Output(2),
                max: cx.limits.max_change_derivations,
            }
        );
        assert_eq!(err.check(), Check::ChangeDerivation);
    }

    /// The same file against a registry that costs less is inspected, not refused. The
    /// budget rations WORK, so the device that can afford the file gets to read it.
    #[test]
    fn the_derivation_budget_follows_what_the_registry_costs() {
        let one = alloc::vec![fixture::registration()];
        let cx = fixture::context_with(&one);
        let psbt = hostile_output_map_psbt(64, 1);

        // One 2-of-3 is 8 derivations an origin against the widest registry's 240, so the
        // same 64 origins cost 512 here and 15,360 there.
        assert_eq!(one[0].leaf_derivations(), 8);
        let inspection = inspect(&psbt, &cx).unwrap();
        assert!(inspection
            .outputs
            .iter()
            .all(|o| o.role == OutputRole::ClaimedButUnproven));
    }

    /// A path no registration can read is free, and has to be: the walk charges for the
    /// derivations a registration performs, and `locate_path` performs none. Otherwise a
    /// device that had registered eight wallets could not review an ordinary single-sig
    /// transaction.
    #[test]
    fn a_path_no_registration_answers_to_costs_the_budget_nothing() {
        let registry = widest_registry();
        let cx = fixture::context_with(&registry);
        let accounts = crate::derive::device_accounts(&fixture::SEED, fixture::NETWORK);

        // BIP-84 change leaves: five levels, where every registration's origin needs six.
        let key = fixture::key_at(CHANGE_PATH).public_key();
        let mut psbt = transcript_psbt(script_at(CHANGE_PATH), key.0, CHANGE_PATH);
        stuff_output_origins(&mut psbt, 1, &fixture::path(CHANGE_PATH), 14);
        assert_eq!(count_own_origins(&psbt, 1), 15);

        let inspection = inspect_with_accounts(&psbt, &cx, &accounts).unwrap();
        assert_eq!(
            inspection.outputs[1].role,
            OutputRole::Change {
                owner: Owner::Account(bip84_account().id()),
                index: 0
            }
        );
    }

    /// The largest honest transaction the budget accepts, driven whole: a self-send that
    /// splits one coin across 64 of the registered wallet's own change leaves, every one of
    /// them a script the wallet really builds. 64 x 8 derivations is the budget exactly.
    ///
    /// An honest output is proven by the registration that owns it and the walk stops
    /// there, which is why the honest ceiling is 64 outputs where the hostile one is two:
    /// the budget is spent on wallets that had to be ruled out, not on wallets that
    /// answered.
    #[test]
    fn check_3_proves_every_output_of_the_largest_honest_self_send() {
        let registry = alloc::vec![fixture::registration()];
        let cx = fixture::context_with(&registry);
        let outputs = cx.limits.max_change_derivations / registry[0].leaf_derivations();
        assert_eq!(outputs, 64);

        let psbt = self_send_psbt(outputs);
        let inspection = inspect(&psbt, &cx).unwrap();
        for (i, output) in inspection.outputs.iter().enumerate() {
            assert_eq!(
                output.role,
                OutputRole::Change {
                    owner: Owner::Registered(registry[0].id()),
                    index: i as u32,
                },
                "output {i} of an honest self-send went unproven"
            );
        }
        assert_eq!(inspection.leaving_total(), Amount::ZERO);
    }

    /// One output past it, and the answer is a sentence rather than a wrong number: the
    /// outputs it did prove are not reported either, because a partial reading of a
    /// transaction is the failure that gets money stolen rather than the one that delays a
    /// signature.
    #[test]
    fn a_self_send_past_the_budget_is_refused_and_not_truncated() {
        let registry = alloc::vec![fixture::registration()];
        let cx = fixture::context_with(&registry);
        let outputs = cx.limits.max_change_derivations / registry[0].leaf_derivations() + 1;

        let err = inspect(&self_send_psbt(outputs), &cx).unwrap_err();
        assert_eq!(
            err,
            CheckFailure::ChangeDerivationBudgetExhausted {
                at: Location::Output(64),
                max: cx.limits.max_change_derivations,
            }
        );
        // The whole point of a refusal over a truncation: there is no inspection to render.
        assert!(inspect(&self_send_psbt(outputs), &cx).is_err());
    }

    /// Every refusal in this section is readable as a sentence, because a bound a screen
    /// cannot state is a bound the user experiences as a device that stopped working.
    #[test]
    fn the_file_bounds_render_as_sentences() {
        let census = CheckFailure::TooManyOwnOriginsInFile {
            found: 3_825,
            max: 256,
        };
        assert_eq!(
            census.to_string(),
            "check 3 (change derivation): the outputs name this wallet in 3825 key \
             origins, over the limit of 256 for one transaction"
        );
        let budget = CheckFailure::ChangeDerivationBudgetExhausted {
            at: Location::Output(2),
            max: 512,
        };
        assert_eq!(
            budget.to_string(),
            "check 3 (change derivation): checking which outputs are change would cost \
             more than this device spends on one transaction: the budget of 512 key \
             derivations ran out at output 2"
        );
    }

    /// A spend of one of the registered wallet's coins that pays `outputs` of its own
    /// change leaves and nothing else: the shape of a UTXO split, and the honest file with
    /// the most outputs of ours a transaction can have.
    fn self_send_psbt(outputs: u32) -> Psbt {
        let registration = fixture::registration();
        let base = fixture::multisig_psbt();
        let mut tx = base.unsigned_tx.clone();
        tx.output.clear();
        for index in 0..outputs {
            tx.output.push(TxOut {
                value: Amount::from_sat(100),
                script_pubkey: registration
                    .script_pubkey(Keychain::Change, index)
                    .expect("the registered wallet builds its own change leaf"),
            });
        }
        let inputs = base.inputs.clone();
        let mut psbt = Psbt::from_unsigned_tx(tx).expect("a self-send is a valid psbt");
        psbt.inputs = inputs;
        for index in 0..outputs {
            let key = registration
                .our_key_at(Keychain::Change, index)
                .expect("our cosigner key at that leaf");
            psbt.outputs[index as usize].bip32_derivation.insert(
                key.0,
                (
                    fixture::fingerprint(),
                    fixture::multisig_leaf_path(Keychain::Change, index),
                ),
            );
        }
        psbt
    }
}
