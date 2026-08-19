// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The work in flight between one screen and the next: the card, the transaction and the
//! registry.
//!
//! Eight of the requests in `notyas_ui`'s vocabulary cannot be answered from a slot number
//! and a store handle. They need a WALLET held open across screens - S-27 lists a card,
//! S-28 picks a file, S-30..S-36 review it, S-37 signs it, S-38 writes it - and the seed
//! that makes the review possible has to survive every one of those frames. `main.rs` opens
//! a wallet, reads its identity and drops it; this module is what holds one instead, and
//! everything about that lifetime is in one place because it is the most security-relevant
//! decision in the file.
//!
//! ```text
//!   S-21 Sign        -> ListCard            -> Catalog::scan      -> CardOutcome
//!   S-27/S-28 tap    -> LoadPsbt            -> signing::review    -> PsbtOutcome
//!   S-36 hold        -> SignTx              -> Review::sign       -> SignOutcome
//!   S-38 write       -> WriteSigned         -> sd::deliver        -> WriteOutcome
//!   S-38 done        -> DiscardSigned       -> drop the bytes     -> bool
//!   S-41 import      -> ImportRegistration  -> multisig::verify   -> ImportOutcome
//!   S-42 approve     -> ApproveRegistration -> Wallet::register   -> RegistrationOutcome
//!   S-43 delete      -> DeleteRegistration  -> Wallet::deregister -> bool
//! ```
//!
//! # The seed's lifetime, stated once
//!
//! [`Flow::wallet`] is the only long-lived seed on this device, and it exists exactly
//! between two events:
//!
//! - it is OPENED by `UiRequest::OpenWallet`, which is a tap on a wallet the user has
//!   already unsealed the store to see;
//! - it is CLOSED by [`Flow::close`], which `main.rs` calls on a lock, on the auto-lock,
//!   and the moment the panel leaves the screens that belong to a wallet.
//!
//! There is no third case and there must not be one. `Wallet` is `Zeroizing` inside, so
//! closing wipes rather than merely dropping, and the review, the signed bytes and any
//! pending registration go with it - a signed transaction outliving the wallet that made it
//! would be a signature nobody could attribute.
//!
//! # Every arm answers
//!
//! Every function here ends in a `Ui::*_result` call on every path, including the ones that
//! log an error first. A handler that logged and returned would leave the screen that
//! raised the request on its C3 Busy frame forever, which is the defect the whole
//! request/answer vocabulary exists to remove. The `Option<UiRequest>` each one returns is
//! the answer's own follow-up request, and `main.rs` feeds it back through the dispatcher.
//!
//! # What this module does not do
//!
//! It decides nothing about a transaction. `notyas_core::psbt` runs the ten checks,
//! `notyas_core::multisig` proves membership, `notyas_wallet::sd` bounds and orders
//! everything that comes off a card. What is here is the plumbing between those and the
//! screens, plus [`model`], which is the small set of judgements a renderer needs and none
//! of them owns.

pub mod model;

use notyas_ui::{
    Artifact, CardListing, CardOutcome, CosignerRow, FileFilter, FileKind, FileRow, ImportOutcome,
    PsbtOutcome, RefusalCode, RefusalNotice, RegistrationInfo, RegistrationOutcome,
    RegistrationReview, ReviewedFee, SignOutcome, SignedTx, TxReview, Ui, UiRequest, WriteOutcome,
};
use notyas_wallet::sd::{self as card, Bounds, Catalog, Filter, Kind, Location, Name, OnCollision};

use crate::sd::{self, Card, CardError, FsError};
use crate::signing::{self, Review, Signed};
use crate::store::Store;
use crate::wallet::{RegisterError, Wallet};

/// Everything held between one screen and the next.
///
/// Four fields, and each is dropped by the step that consumes it: opening a different file
/// replaces the review, signing consumes the review into a delivery, delivering and then
/// discarding drops the bytes. Nothing here is `Clone`, for the reason `Wallet` is not: a
/// second copy of any of it is a second thing to wipe.
#[derive(Default)]
pub struct Flow {
    wallet: Option<Wallet>,
    loaded: Option<Loaded>,
    signed: Option<Delivery>,
    pending: Option<Proposed>,
}

/// A transaction that passed every check, and where it was read from.
///
/// The location is kept because the delivery is NAMED from it (`sd::plan` derives
/// `<stem>-signed.psbt`), and invariant 2b requires that name to be on the panel before the
/// write. A review with no source could only be delivered under a name this device invented.
struct Loaded {
    dir: Option<Name>,
    name: Name,
    review: Review,
}

/// A signed transaction, its planned file, and where it goes.
struct Delivery {
    dir: Option<Name>,
    target: Name,
    signed: Signed,
}

/// A multisig registration this device has proven it is a member of, waiting for the user.
///
/// The TEXT is kept beside the proof rather than the proof alone, because `Wallet::register`
/// is the one write path to the registry and it takes text: it re-parses and re-verifies
/// before it seals, so an approval cannot store anything the proof below did not cover.
struct Proposed {
    text: String,
    label: String,
    /// The registry slot already holding this exact wallet, if there is one. Approval with
    /// `replace` erases it first; approval without it is refused by `Wallet::register`.
    duplicate: Option<u8>,
}

impl Flow {
    /// Take the wallet the embedder just unsealed. Anything the previous wallet left behind
    /// goes with it: a review, a signed transaction and a pending registration all belong to
    /// the wallet that produced them.
    pub fn open(&mut self, wallet: Wallet) {
        self.close();
        self.wallet = Some(wallet);
    }

    /// Drop the seed and everything derived from it. Returns whether anything was there.
    ///
    /// The one way out. `Wallet` wipes on drop and so does everything it fed, so this is a
    /// wipe on the std side of the boundary in the same sense `Ui::lock` is one on the
    /// no_std side.
    pub fn close(&mut self) -> bool {
        let held = self.wallet.is_some();
        self.wallet = None;
        self.loaded = None;
        self.signed = None;
        self.pending = None;
        held
    }
}

// ---------------------------------------------------------------------------------------
// The registry, as the screens read it
// ---------------------------------------------------------------------------------------

/// Install the open wallet's PROVEN registrations, which is the only thing S-41 renders.
///
/// A record that did not prove out at open time is deliberately absent rather than listed
/// as unproven: it has no threshold, no cosigner set and no fingerprint this device would
/// stand behind, so a row for it could only be fabricated. It surfaces the other way, as
/// the gap between `WalletInfo::registrations` - which counts the records that NAME this
/// wallet, seed or no seed - and the length of this list. S-41 says exactly that: a device
/// that has registrations and could not read them.
pub fn install_registrations(ui: &mut Ui, flow: &Flow) {
    let Some(wallet) = flow.wallet.as_ref() else {
        ui.set_registrations(Vec::new());
        return;
    };
    ui.set_registrations(
        wallet
            .registered()
            .map(|(entry, registration)| {
                let (threshold, cosigners) = registration.threshold_of();
                RegistrationInfo {
                    slot: entry.slot,
                    name: entry.label.clone(),
                    threshold,
                    cosigners,
                    script: String::from("P2WSH"),
                    derivation: registration.ours().origin.to_string(),
                    fingerprint: registration.ours().fingerprint.to_string(),
                    network: registration.network(),
                    // Every row here came back through `Pending::verify` against the live
                    // seed AND matched the id it was approved under. That is what proven
                    // means, and nothing else reaches this list.
                    proven: true,
                }
            })
            .collect(),
    );
}

// ---------------------------------------------------------------------------------------
// The card
// ---------------------------------------------------------------------------------------

/// Why a card operation did not produce what was asked for, in the two shapes the screens
/// distinguish.
///
/// The split is the one UX-SCREENS draws and it is about the REMEDY: an empty slot is
/// answered by inserting a card, and a card that mounted and would not read is answered by a
/// different card. `TooLarge` is separate again because it is about one file rather than
/// about the card, and it has its own ratified code.
enum Fault {
    NoCard,
    Unreadable(String),
    TooLarge(u32),
    /// The target name is already on the card and the caller said not to replace it. A
    /// question for the user rather than a failure, kept separate so `write` can put it to
    /// them without asking the card a second time.
    Collision,
}

impl Fault {
    /// The sentence a card band shows. Never the raw driver error alone: an `esp_err` code
    /// belongs in the log, and what reaches the panel has to say what to do.
    fn sentence(&self) -> String {
        match self {
            Fault::NoCard => String::from("No card detected."),
            Fault::Unreadable(msg) => msg.clone(),
            Fault::TooLarge(max) => format!(
                "That file is larger than the {} kB this device will read.",
                max / 1024
            ),
            Fault::Collision => String::from("That file name is already on the card."),
        }
    }
}

/// Mount, do one thing, unmount, and classify whatever went wrong.
///
/// The guard is dropped by `sd::with_card` on the way out however `f` ended, which is what
/// keeps MILESTONES.md m5's "the mount is never held outside an SD flow" true of this
/// module without a rule anybody has to remember.
fn on_card<T>(f: impl FnOnce(&mut Card) -> Result<T, card::SdError<FsError>>) -> Result<T, Fault> {
    match sd::with_card(f) {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(e)) => Err(match e {
            card::SdError::TooLarge { max } => Fault::TooLarge(max),
            // A backend failure inside a mounted flow is the card going away underneath
            // us, which reads the same way to the user as a card that would not mount.
            card::SdError::Backend(e) => Fault::Unreadable(format!(
                "The card stopped answering: {}.",
                e.source
            )),
            card::SdError::Name(e) => {
                Fault::Unreadable(format!("This device cannot use that file name: {e}."))
            }
            card::SdError::Collision => Fault::Collision,
            card::SdError::ReadBackMismatch { wrote, read } => Fault::Unreadable(format!(
                "The card did not return what was written to it ({wrote} bytes out, {read} \
                 back). Use a different card."
            )),
        }),
        Err(CardError::NoCard(_)) => Err(Fault::NoCard),
        Err(e) => Err(Fault::Unreadable(format!("{e}."))),
    }
}

/// The transfer cap every listing is bounded by, for every filter.
///
/// One cap for the picker, and it is the PSBT one, which is the largest thing this device
/// reads. It is what decides the `oversize` flag on a row, and the screen prints that cap
/// beside a row it refuses - so a listing bounded by the smaller text cap would show a
/// descriptor as "too large" against a number no screen states. A descriptor is bounded
/// again where it is actually read, by [`sd::text_bounds`], and that refusal names its own
/// number.
fn listing_bounds() -> Bounds {
    sd::psbt_bounds()
}

/// `dir` off a request, as the card layer names a directory.
///
/// Empty is the card root, which is `None`, and there is no third case: S-28's depth limit
/// is root plus one level and `Location` cannot express anything deeper.
fn directory(dir: &str) -> Result<Option<Name>, String> {
    if dir.is_empty() {
        return Ok(None);
    }
    Name::parse(dir)
        .map(Some)
        .map_err(|e| format!("This device cannot use that directory name: {e}."))
}

/// Answer `UiRequest::ListCard`: one directory of the card, bounded, validated and ordered.
pub fn list_card(ui: &mut Ui, dir: String, filter: FileFilter) -> Option<UiRequest> {
    let where_ = if dir.is_empty() { String::from("the card root") } else { dir.clone() };
    let parsed = match directory(&dir) {
        Ok(parsed) => parsed,
        Err(msg) => {
            log::error!("card: listing of {where_} refused: {msg}");
            return ui.card_result(CardOutcome::Unreadable(msg));
        }
    };
    let want = match filter {
        FileFilter::PsbtOnly => Filter::PsbtOnly,
        FileFilter::All => Filter::All,
    };
    let bounds = listing_bounds();
    let outcome = match on_card(|c| Catalog::scan(c, parsed.as_ref(), want, &bounds)) {
        Ok(catalog) => {
            log::info!(
                "card: listed {where_} ({filter:?}): {} rows, truncated={}, rejected={}",
                catalog.entries().len(),
                catalog.truncated(),
                catalog.rejected()
            );
            CardOutcome::Listed(listing(dir, &catalog))
        }
        Err(Fault::NoCard) => {
            log::error!("card: listing of {where_} refused: no card in the slot");
            CardOutcome::NoCard
        }
        Err(fault) => {
            log::error!("card: listing of {where_} refused: {}", fault.sentence());
            CardOutcome::Unreadable(fault.sentence())
        }
    };
    ui.card_result(outcome)
}

/// A catalog as the picker reads it. The order is the card layer's and is not re-sorted:
/// the row a user taps has to be a function of what they were shown.
fn listing(dir: String, catalog: &Catalog) -> CardListing {
    CardListing {
        dir,
        rows: catalog
            .entries()
            .iter()
            .map(|e| FileRow {
                name: e.name.as_str().to_string(),
                kind: match e.kind {
                    Kind::Directory => FileKind::Directory,
                    Kind::Psbt => FileKind::Psbt,
                    Kind::Txn => FileKind::Txn,
                    Kind::Text => FileKind::Text,
                    Kind::Json => FileKind::Json,
                    Kind::Other => FileKind::Other,
                },
                len: e.len,
                // Already rendered, because this crate has a clock and the UI does not, and
                // because the device makes no timezone claim about digits another machine
                // wrote.
                modified: e.modified.map(|t| t.to_string()).unwrap_or_default(),
                oversize: e.oversize,
            })
            .collect(),
        truncated: catalog.truncated(),
        rejected: catalog.rejected(),
    }
}

// ---------------------------------------------------------------------------------------
// Loading and reviewing a transaction
// ---------------------------------------------------------------------------------------

/// The refusal a request gets when no wallet is open.
///
/// R-01 and not a device code, because R-01 is exactly what has happened from the user's
/// side: there is no wallet here that owns these coins, and its ratified instruction - "Open
/// that wallet and load the file again." - is the right one. Reachable only from a screen
/// raised while the wallet behind it was closed, which the S-21 gate makes hard and does not
/// make impossible.
fn no_wallet(what: &str) -> RefusalNotice {
    RefusalNotice {
        code: RefusalCode::NotOurInputs,
        happened: format!("No wallet is open on this device, so {what} cannot be checked."),
        details: String::from("no open wallet"),
        after_signing: false,
    }
}

/// A card fault as a refusal screen, with the ratified code for what went wrong.
fn card_refusal(fault: &Fault, name: &str) -> RefusalNotice {
    let code = match fault {
        Fault::NoCard => RefusalCode::NoCard,
        Fault::TooLarge(_) => RefusalCode::FileTooLarge,
        Fault::Unreadable(_) => RefusalCode::MalformedFile,
        // Only `deliver` can produce one, and it is answered by the write screen's own
        // overwrite confirm rather than by a refusal screen. Kept exhaustive so a card
        // fault added later cannot inherit a code nobody chose for it.
        Fault::Collision => RefusalCode::WriteFailed,
    };
    RefusalNotice {
        code,
        happened: fault.sentence(),
        details: format!("reading {name}"),
        after_signing: false,
    }
}

/// Answer `UiRequest::LoadPsbt`: read the file AND decide about it, in one request.
///
/// One request for both because the user does nothing between them and both fail onto the
/// same screen. The bytes never outlive this function: what is kept is the `Review`, which
/// holds the parsed PSBT and the inspection that let it through.
pub fn load_psbt(
    ui: &mut Ui,
    flow: &mut Flow,
    dir: String,
    name: String,
) -> Option<UiRequest> {
    let outcome = read_and_review(flow, &dir, &name);
    ui.psbt_result(outcome)
}

fn read_and_review(flow: &mut Flow, dir: &str, name: &str) -> PsbtOutcome {
    // Dropped up front: a new file replaces whatever the last one left, and a review that
    // outlived its own screen is a review nothing on the panel refers to.
    flow.loaded = None;

    let Some(wallet) = flow.wallet.as_ref() else {
        log::error!("psbt: {dir}/{name} not loaded: no wallet is open");
        return PsbtOutcome::Refused(no_wallet("this transaction"));
    };
    let parsed_dir = match directory(dir) {
        Ok(parsed) => parsed,
        Err(msg) => {
            log::error!("psbt: {dir}/{name} not loaded: {msg}");
            return PsbtOutcome::Refused(card_refusal(&Fault::Unreadable(msg), name));
        }
    };
    let file = match Name::parse(name) {
        Ok(file) => file,
        Err(e) => {
            let msg = format!("This device cannot use that file name: {e}.");
            log::error!("psbt: {dir}/{name} not loaded: {msg}");
            return PsbtOutcome::Refused(card_refusal(&Fault::Unreadable(msg), name));
        }
    };

    let bounds = sd::psbt_bounds();
    let bytes = match on_card(|c| card::read(c, at(&parsed_dir, &file), &bounds)) {
        Ok(bytes) => bytes,
        Err(fault) => {
            log::error!("psbt: {dir}/{name} not read: {}", fault.sentence());
            return PsbtOutcome::Refused(card_refusal(&fault, name));
        }
    };
    log::info!("psbt: {dir}/{name} read: {} bytes", bytes.len());

    let review = match signing::review(wallet, &bytes) {
        Ok(review) => review,
        Err(e) => {
            log::error!("psbt: {dir}/{name} refused: {e}");
            return PsbtOutcome::Refused(refusal_for(&e));
        }
    };
    let rendered = tx_review(&review, wallet.label(), name);
    log::info!(
        "psbt: {dir}/{name} reviewed: {} inputs ({} ours), {} outputs, {} vB, fee enforced={}",
        rendered.inputs.len(),
        rendered.signable_inputs,
        rendered.outputs.len(),
        rendered.vsize,
        matches!(rendered.fee, ReviewedFee::Enforced(_))
    );
    flow.loaded = Some(Loaded {
        dir: parsed_dir,
        name: file,
        review,
    });
    PsbtOutcome::Reviewed(rendered)
}

/// A `signing::Refusal` as the screen renders it. One match, so a new refusal arm cannot
/// reach a panel without someone choosing what the user is told.
fn refusal_for(e: &signing::Refusal) -> RefusalNotice {
    match e {
        signing::Refusal::NotAFile(e) => model::file_refusal(e),
        signing::Refusal::Check(e) => model::check_refusal(e),
        signing::Refusal::Sign(e) => model::sign_refusal(e),
        signing::Refusal::WrongWallet { reviewed, holding } => {
            model::wrong_wallet(*reviewed, *holding)
        }
    }
}

/// A file, addressed relative to the volume root.
fn at<'a>(dir: &'a Option<Name>, file: &'a Name) -> Location<'a> {
    match dir {
        Some(dir) => Location::under(dir, file),
        None => Location::root(file),
    }
}

/// Everything the review pages render, as the engine established it.
///
/// A copy and not a computation: every fact here came out of `notyas_core::psbt`, and the
/// four values this side adds are the ones the engine has no opinion about - which file it
/// came from, which wallet is open, what the transaction will weigh, and which of the
/// ratified warnings fire. The last two are [`model`]'s, where they can be tested on a host.
fn tx_review(review: &Review, wallet: &str, source: &str) -> TxReview {
    let (vsize, vsize_exact) = model::vsize(review.inputs(), review.outputs());
    let mut out = TxReview {
        inputs: review.inputs().to_vec(),
        outputs: review.outputs().to_vec(),
        input_total: review.totals().0,
        output_total: review.totals().1,
        fee: match review.fee() {
            signing::ReviewedFee::Enforced(a) => ReviewedFee::Enforced(a),
            signing::ReviewedFee::Stated(a) => ReviewedFee::Stated(a),
        },
        lock_time: review.lock_time(),
        rbf_signaled: review.rbf_signaled(),
        network: review.network(),
        fingerprint: review.fingerprint().to_string(),
        wallet: String::from(wallet),
        source: String::from(source),
        signable_inputs: review.signable_inputs(),
        unknown_fields: review.unknown_fields(),
        serialized_len: review.serialized_len(),
        psbt_id: hex(&review.psbt_id()),
        vsize,
        vsize_exact,
        // Filled below, from the assembled review: every warning is a predicate over one
        // transaction, so the value they are about has to exist before they can be asked.
        warnings: Vec::new(),
    };
    out.warnings = model::warnings(&out);
    out
}

// ---------------------------------------------------------------------------------------
// Signing and delivering
// ---------------------------------------------------------------------------------------

/// Answer `UiRequest::SignTx`: the hold has filled, and the seed enters the pipeline.
///
/// The request carries nothing, deliberately: the reviewed file and the seed are both here,
/// and `psbt::sign` re-establishes the binding between them for itself - the inspection
/// carries the SHA-256 of the bytes it read and signing recomputes it. A caller cannot ask
/// for a signature over anything but the file that was reviewed.
pub fn sign_tx(ui: &mut Ui, flow: &mut Flow) -> Option<UiRequest> {
    let outcome = sign(flow);
    ui.sign_result(outcome)
}

fn sign(flow: &mut Flow) -> SignOutcome {
    let (Some(wallet), Some(loaded)) = (flow.wallet.as_ref(), flow.loaded.as_ref()) else {
        log::error!("sign: refused: no reviewed transaction is held on this device");
        return SignOutcome::Refused(RefusalNotice {
            after_signing: true,
            ..no_wallet("this transaction")
        });
    };
    let signed = match loaded.review.sign(wallet) {
        Ok(signed) => signed,
        Err(e) => {
            log::error!("sign: refused: {e}");
            return SignOutcome::Refused(RefusalNotice {
                // Whatever happened, this device produced no file. That is the sentence
                // S-29 owes someone who has just held to sign, and it is true of every arm
                // here: `psbt::sign` builds a new PSBT and returns it only on success.
                after_signing: true,
                ..refusal_for(&e)
            });
        }
    };

    // The name the delivery will use, decided BEFORE the notice that announces it. That
    // ordering is invariant 2b: the value on the panel is the value the writer is handed.
    // No `-final.txn`: nothing in this workspace finalizes a PSBT, and a screen may not
    // print the name of a file no code can write.
    let plan = match card::plan(&loaded.name, false) {
        Ok(plan) => plan,
        Err(e) => {
            log::error!("sign: signed, and the output name is unusable: {e}");
            return SignOutcome::Refused(RefusalNotice {
                code: RefusalCode::WriteFailed,
                happened: format!(
                    "The transaction was signed and this device cannot name the file it \
                     would write: {e}."
                ),
                details: format!("source={} error={e:?}", loaded.name),
                after_signing: true,
            });
        }
    };

    let report = signed.report();
    let summary = SignedTx {
        signed_inputs: report.signatures_added,
        verified_inputs: report.signatures_verified,
        signable_inputs: u16::try_from(loaded.review.signable_inputs()).unwrap_or(u16::MAX),
        complete: signed.complete(),
        artifacts: vec![Artifact {
            name: plan.signed.as_str().to_string(),
            bytes: u32::try_from(signed.bytes().len()).unwrap_or(u32::MAX),
        }],
        psbt_id: hex(&loaded.review.psbt_id()),
    };
    log::info!(
        "sign: {} signatures added, {} re-verified, complete={}, {} bytes -> {}",
        summary.signed_inputs,
        summary.verified_inputs,
        summary.complete,
        signed.bytes().len(),
        plan.signed
    );

    let dir = loaded.dir.clone();
    // The review is consumed: what is held now is a signed transaction, and the only ways
    // out of S-38 are a delivery and a discard.
    flow.loaded = None;
    flow.signed = Some(Delivery {
        dir,
        target: plan.signed,
        signed,
    });
    SignOutcome::Signed(summary)
}

/// Answer `UiRequest::WriteSigned`: stage the file, verify it off the card, then name it.
pub fn write_signed(ui: &mut Ui, flow: &mut Flow, overwrite: bool) -> Option<UiRequest> {
    let outcome = write(flow, overwrite);
    ui.write_result(outcome)
}

fn write(flow: &mut Flow, overwrite: bool) -> WriteOutcome {
    let Some(delivery) = flow.signed.as_ref() else {
        log::error!("card: signed write refused: this device holds no signed transaction");
        return WriteOutcome::Failed(String::from(
            "This device is not holding a signed transaction. Nothing was written.",
        ));
    };
    let collision = if overwrite { OnCollision::Replace } else { OnCollision::Refuse };
    let result = on_card(|c| {
        card::deliver(
            c,
            delivery.dir.as_ref(),
            &delivery.target,
            delivery.signed.bytes(),
            collision,
        )
    });
    match result {
        Ok(written) => {
            log::info!(
                "card: wrote {} ({} bytes, replaced={})",
                written.name,
                written.bytes,
                written.replaced
            );
            WriteOutcome::Written(vec![Artifact {
                name: written.name.as_str().to_string(),
                bytes: u32::try_from(written.bytes).unwrap_or(u32::MAX),
            }])
        }
        Err(Fault::NoCard) => {
            log::error!("card: signed write refused: no card in the slot");
            WriteOutcome::NoCard
        }
        // A collision is a question for the user and not a failure: `sd::deliver` refuses
        // it BEFORE it writes anything, so nothing has happened yet, and S-38 opens the C4a
        // confirm and raises this request again with `overwrite` set.
        Err(Fault::Collision) => {
            let name = delivery.target.as_str().to_string();
            log::info!("card: {name} is already on the card - asking before replacing it");
            WriteOutcome::Collision(vec![name])
        }
        Err(fault) => {
            log::error!("card: signed write failed: {}", fault.sentence());
            WriteOutcome::Failed(fault.sentence())
        }
    }
}

/// Answer `UiRequest::DiscardSigned`: destroy the only copy of the signed transaction.
///
/// `true` only when there was one and it is now gone. A `true` for a device that was holding
/// nothing would be a claim about an erasure that never happened, which is the one claim a
/// signer must not make.
pub fn discard_signed(ui: &mut Ui, flow: &mut Flow) -> Option<UiRequest> {
    let held = flow.signed.take().is_some();
    if held {
        log::info!("sign: the signed transaction was discarded at the user's request");
    } else {
        log::error!("sign: discard refused: this device holds no signed transaction");
    }
    ui.discard_result(held)
}

// ---------------------------------------------------------------------------------------
// The multisig registry
// ---------------------------------------------------------------------------------------

/// Answer `UiRequest::ImportRegistration`: read a wallet description and PROVE membership.
///
/// Read and decide in one request, like `LoadPsbt` and for the same reason. The proof is the
/// point: a wallet this device is not a cosigner of is refused here, before any screen
/// renders it, because importing a wallet you cannot sign for is how a substituted key gets
/// accepted.
pub fn import_registration(
    ui: &mut Ui,
    flow: &mut Flow,
    dir: String,
    name: String,
) -> Option<UiRequest> {
    let outcome = read_and_verify(flow, &dir, &name);
    ui.import_result(outcome)
}

fn read_and_verify(flow: &mut Flow, dir: &str, name: &str) -> ImportOutcome {
    flow.pending = None;

    let Some(wallet) = flow.wallet.as_ref() else {
        log::error!("multisig: {dir}/{name} not imported: no wallet is open");
        return ImportOutcome::Refused(no_wallet("this registration"));
    };
    let parsed_dir = match directory(dir) {
        Ok(parsed) => parsed,
        Err(msg) => {
            log::error!("multisig: {dir}/{name} not imported: {msg}");
            return ImportOutcome::Refused(card_refusal(&Fault::Unreadable(msg), name));
        }
    };
    let file = match Name::parse(name) {
        Ok(file) => file,
        Err(e) => {
            let msg = format!("This device cannot use that file name: {e}.");
            log::error!("multisig: {dir}/{name} not imported: {msg}");
            return ImportOutcome::Refused(card_refusal(&Fault::Unreadable(msg), name));
        }
    };

    // The TEXT cap, not the PSBT one: a coordinator export of a multisig wallet is a few
    // kilobytes, and the cap exists to stop a hostile card feeding a megabyte of text into a
    // parser rather than to accommodate a plausible file.
    let bounds = sd::text_bounds();
    let bytes = match on_card(|c| card::read(c, at(&parsed_dir, &file), &bounds)) {
        Ok(bytes) => bytes,
        Err(fault) => {
            log::error!("multisig: {dir}/{name} not read: {}", fault.sentence());
            return ImportOutcome::Refused(card_refusal(&fault, name));
        }
    };
    let Ok(text) = String::from_utf8(bytes) else {
        log::error!("multisig: {dir}/{name} is not text");
        return ImportOutcome::Refused(RefusalNotice {
            code: RefusalCode::MalformedFile,
            happened: String::from(
                "That file is not text. A wallet description is a descriptor or a Coldcard \
                 setup file, both of them plain text.",
            ),
            details: format!("reading {name}: not valid UTF-8"),
            after_signing: false,
        });
    };

    let pending = match notyas_core::multisig::parse(&text) {
        Ok(pending) => pending,
        Err(e) => {
            log::error!("multisig: {dir}/{name} not read: {e}");
            return ImportOutcome::Refused(model::registration_malformed(&e));
        }
    };
    let converted = pending.dialect != notyas_core::multisig::ImportDialect::Descriptor;
    // The proof. It needs the seed, which is why it happens here and not on a screen, and
    // what comes back is the record the registry would store.
    let registration = match pending.verify(wallet.seed(), wallet.network()) {
        Ok(registration) => registration,
        Err(e) => {
            log::error!("multisig: {dir}/{name} refused: {e}");
            return ImportOutcome::Refused(model::registration_refused(&e));
        }
    };
    let Some(first_address) = registration.first_receive_address() else {
        log::error!("multisig: {dir}/{name} refused: its first receive address will not derive");
        return ImportOutcome::Refused(RefusalNotice {
            code: RefusalCode::MalformedFile,
            happened: String::from(
                "This device could not derive this wallet's first receive address, so there \
                 is nothing to check against your other signers.",
            ),
            details: format!("registration {} first_receive_address=None", registration.id()),
            after_signing: false,
        });
    };

    let id = registration.id();
    let duplicate = wallet
        .registered()
        .find(|(_, held)| held.id() == id)
        .map(|(entry, _)| entry.slot);
    let label = label_for(&file);
    let (threshold, cosigners) = registration.threshold_of();
    let review = RegistrationReview {
        name: label.clone(),
        threshold,
        policy: String::from("sortedmulti"),
        script: String::from("P2WSH (native segwit)"),
        derivation: registration.ours().origin.to_string(),
        network: registration.network(),
        cosigners: registration
            .cosigners()
            .iter()
            .enumerate()
            .map(|(i, c)| CosignerRow {
                fingerprint: c.fingerprint.to_string(),
                path: c.origin.to_string(),
                xpub: c.xpub.to_string(),
                // PROVEN, by the derive-and-compare `verify` just performed, and never read
                // off the file's own claim about which cosigner we are.
                ours: i == registration.our_position(),
            })
            .collect(),
        ours: u8::try_from(registration.our_position() + 1).unwrap_or(u8::MAX),
        first_address: first_address.to_string(),
        // The registration's OWN canonical rendering, which is what would be sealed, and
        // never the text that came in.
        descriptor: registration.descriptor().to_string(),
        converted,
        duplicate: duplicate.is_some(),
    };
    log::info!(
        "multisig: {dir}/{name} proven: {threshold} of {cosigners}, id {id}, this device is \
         cosigner {} of {cosigners}, duplicate={duplicate:?}",
        review.ours
    );
    flow.pending = Some(Proposed { text, label, duplicate });
    ImportOutcome::Pending(review)
}

/// What a registration is called, from the file it came in as.
///
/// The file's stem, which is what the coordinator named it and what the user will recognise
/// on the card. `Name::sanitize` bounds it and substitutes a fallback for a stem with
/// nothing usable in it, so a hostile name cannot reach the registry as a label.
fn label_for(file: &Name) -> String {
    Name::sanitize(file.stem(), 32, "multisig")
        .map(|n| n.as_str().to_string())
        .unwrap_or_else(|_| String::from("multisig"))
}

/// Answer `UiRequest::ApproveRegistration`: seal the wallet the user just read through.
///
/// `Wallet::register` re-parses and re-verifies the text before it writes, so the approval
/// stores what the proof covered rather than what this module remembered about it. That is
/// one write path to the registry and there is deliberately no second one.
pub fn approve_registration(
    ui: &mut Ui,
    store: &mut Option<Store>,
    flow: &mut Flow,
    replace: bool,
) -> Option<UiRequest> {
    let outcome = approve(store, flow, replace);
    // Installed BEFORE the answer, because the answer navigates to the detail screen and
    // that screen reads the registry list out of the `Ui`.
    install_registrations(ui, flow);
    ui.registration_result(outcome)
}

fn approve(store: &mut Option<Store>, flow: &mut Flow, replace: bool) -> RegistrationOutcome {
    let Some(store) = store.as_mut() else {
        log::error!("multisig: approval refused: no store on this device");
        return RegistrationOutcome::Refused(store_unavailable());
    };
    // The pending review is copied out before the wallet is borrowed mutably. Two lines of
    // clone, and the alternative is holding a shared borrow of `flow` across the write that
    // needs a unique one.
    let Some((text, label, duplicate)) = flow
        .pending
        .as_ref()
        .map(|p| (p.text.clone(), p.label.clone(), p.duplicate))
    else {
        log::error!("multisig: approval refused: this device reviewed no registration");
        return RegistrationOutcome::Refused(no_wallet("this registration"));
    };
    let Some(wallet) = flow.wallet.as_mut() else {
        log::error!("multisig: approval refused: no wallet is open");
        return RegistrationOutcome::Refused(no_wallet("this registration"));
    };

    // A replace is an erase and then a write, in that order and never the other way round:
    // the registry has eight slots, and writing first would refuse for want of a free one on
    // a device that is about to have one.
    if replace {
        if let Some(slot) = duplicate {
            if let Err(e) = wallet.deregister(store, slot) {
                log::error!("multisig: replacing the registration in slot {slot} failed: {e}");
                return RegistrationOutcome::Refused(register_refusal(&e));
            }
            log::info!("multisig: registry slot {slot} erased to make room for the replacement");
        }
    }

    let id = match wallet.register(store, &label, &text) {
        Ok(id) => id,
        Err(e) => {
            log::error!("multisig: {label} not registered: {e}");
            return RegistrationOutcome::Refused(register_refusal(&e));
        }
    };
    flow.pending = None;

    // Read back off the wallet rather than rebuilt from the pending review: what the screen
    // is shown has to be what the registry now holds, including the slot the store chose.
    let Some(info) = wallet
        .registered()
        .find(|(_, r)| r.id() == id)
        .map(|(entry, r)| {
            let (threshold, cosigners) = r.threshold_of();
            RegistrationInfo {
                slot: entry.slot,
                name: entry.label.clone(),
                threshold,
                cosigners,
                script: String::from("P2WSH"),
                derivation: r.ours().origin.to_string(),
                fingerprint: r.ours().fingerprint.to_string(),
                network: r.network(),
                proven: true,
            }
        })
    else {
        log::error!("multisig: {label} was written as {id} and is not in the open wallet");
        return RegistrationOutcome::Refused(RefusalNotice {
            code: RefusalCode::MalformedFile,
            happened: String::from(
                "The registration was written and this device could not read it back. Lock \
                 the device and unlock it again before using this wallet.",
            ),
            details: format!("registration {id} written and absent from the open wallet"),
            after_signing: false,
        });
    };
    log::info!("multisig: {label} registered as {id} in registry slot {}", info.slot);
    RegistrationOutcome::Saved(info)
}

/// Answer `UiRequest::DeleteRegistration`: erase one registry slot.
///
/// `false` is a refusal the screen states, and it is the honest answer whenever the record
/// is still there: a device that reported an erasure it did not perform would leave the user
/// believing a wallet had been removed from it.
pub fn delete_registration(
    ui: &mut Ui,
    store: &mut Option<Store>,
    flow: &mut Flow,
    slot: u8,
) -> Option<UiRequest> {
    let erased = match (store.as_mut(), flow.wallet.as_mut()) {
        (Some(store), Some(wallet)) => match wallet.deregister(store, slot) {
            Ok(()) => {
                log::info!("multisig: registry slot {slot} erased");
                true
            }
            Err(e) => {
                log::error!("multisig: registry slot {slot} not erased: {e}");
                false
            }
        },
        (None, _) => {
            log::error!("multisig: registry slot {slot} not erased: no store on this device");
            false
        }
        (_, None) => {
            log::error!("multisig: registry slot {slot} not erased: no wallet is open");
            false
        }
    };
    install_registrations(ui, flow);
    ui.registration_deleted(erased)
}

/// A `RegisterError` as the screen renders it.
fn register_refusal(e: &RegisterError) -> RefusalNotice {
    match e {
        RegisterError::Malformed(e) => model::registration_malformed(e),
        RegisterError::Refused(e) => model::registration_refused(e),
        // Everything else is about this DEVICE's registry rather than about the wallet: a
        // slot that is full, a record that will not encode, a store that refused. R-09 is
        // the wrong code for those, so they carry the write code with the store's own
        // sentence, which is what an owner can act on.
        RegisterError::AlreadyRegistered(_)
        | RegisterError::NoFreeSlot { .. }
        | RegisterError::NoSuchRegistration { .. }
        | RegisterError::Storage(_)
        | RegisterError::Record(_) => RefusalNotice {
            code: RefusalCode::WriteFailed,
            happened: format!("This registration was not stored: {e}."),
            details: format!("{e:?}"),
            after_signing: false,
        },
    }
}

/// The refusal for a request that needs the sealed store on a device that has none.
fn store_unavailable() -> RefusalNotice {
    RefusalNotice {
        code: RefusalCode::WriteFailed,
        happened: String::from(
            "This device could not reach its sealed storage, so nothing was written.",
        ),
        details: String::from("no store"),
        after_signing: false,
    }
}

/// Lowercase hex, for the two public digests the screens print.
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    out
}
