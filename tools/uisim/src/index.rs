// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! What each committed picture shows, and the index that says so.
//!
//! The index used to be a table typed by hand into docs/screenshots/ui/README.md. It
//! stopped at the fifteenth file and stayed there for two releases, which left 119 of the
//! committed pictures with no caption anywhere in the repository - and a hand-kept table
//! of a hundred and sixty files would rot the same way again on the next promotion.
//!
//! So the table is generated and the prose is not. [`CAPTIONS`] is one line per PICTURED
//! frame, keyed on the frame name; [`markdown`] joins it to [`crate::catalog::CATALOG`]
//! and writes docs/screenshots/ui/INDEX.md as part of `uisim tour`. Because that file
//! lands in the byte-checked directory, tools/ci/check-screenshots.sh regenerates and
//! diffs it exactly as it does the PNGs: an index that disagrees with the catalogue is a
//! failing gate rather than a stale paragraph.
//!
//! Three properties the tests here hold, and each one is a way the old table went wrong:
//!
//! - Every pictured frame has a caption, and every caption names a pictured frame. A
//!   promotion without a line here fails `cargo test`, and so does a line left behind by a
//!   demotion.
//! - Captions are keyed on the FRAME, never on the filename and never on the numeric
//!   prefix. Five prefixes in the committed set name two different screens (72, 73, 74, 90
//!   and 91), so anything that matched on a prefix would caption the wrong picture.
//! - Captions are ASCII with no table metacharacter in them, because the file they land in
//!   is gated by tools/ci/check-ascii-prose.sh and is a markdown table.

use crate::catalog::{CATALOG, DOC_LANDSCAPE, DOC_PORTRAIT};

/// One line per pictured frame: what a reader is looking at.
///
/// Sorted by frame name, which is where a new one goes and what the tests check. These say
/// what is ON the panel; why the frame exists at all is the comment beside its recipe in
/// `catalog.rs`, and the two are deliberately different jobs.
pub const CAPTIONS: &[(&str, &str)] = &[
    (
        "about-device-words/explainer",
        "What the two words above the PIN pad are, raised by the first answer of a power-up.",
    ),
    (
        "backup-check/first-word",
        "The backup check, word one. It is asked on both paths and cannot be skipped.",
    ),
    (
        "deliver/complete",
        "A fully signed transaction, with the file it will write named before the write.",
    ),
    (
        "deliver/discard-sheet",
        "Discarding a signed transaction after a second failed write. It destroys the only \
         copy this device holds.",
    ),
    (
        "deliver/overwrite-sheet",
        "A name collision on the card, named and asked about. Nothing has been written.",
    ),
    (
        "deliver/partial",
        "A transaction still short of a cosigner: signed by this device, not finished.",
    ),
    ("deliver/written", "The file written, under the name the panel showed beforehand."),
    (
        "deriving/running",
        "The interstitial the firmware publishes BEFORE the derivation runs, not after it.",
    ),
    (
        "device-name/current",
        "The device name, opened on the name the device already has. It is what the lock \
         screen prints.",
    ),
    (
        "dice/typed",
        "Dice entry: the roll history, the RAW and fixed-word mode strip, and the effective \
         bits collected so far.",
    ),
    (
        "erase-wallet/offer",
        "The recovery words offered one last time, beside the erase itself.",
    ),
    (
        "file-picker/listing",
        "The picker, showing every row kind it has including a file over the transfer cap \
         and a directory.",
    ),
    ("format-card/consequence", "What formatting destroys, stated before any typing."),
    ("format-card/done", "The write reported in the device's own words."),
    (
        "format-card/offer",
        "A card this device cannot read, named with its capacity and what it holds, and the \
         offer to erase it.",
    ),
    (
        "format-card/refused-firmware",
        "A refusal: this build cannot read cards at all, so every card looks unreadable and \
         formatting one would erase somebody's data for a build setting.",
    ),
    (
        "format-card/typed",
        "The card's own capacity typed back in full. It costs a digit page and then a \
         shifted letter page.",
    ),
    (
        "home/fresh",
        "A device with nothing saved: the menu is the way in, with the mainnet/testnet \
         toggle above it.",
    ),
    (
        "keep-or-save/fork",
        "The only place anything is written, on a device with no PIN: \"Save to this device\" \
         or \"Use once, keep nothing\".",
    ),
    (
        "keep-or-save/fork-with-pin",
        "The same fork on a device that already has a PIN, where the Save card reads \
         \"Stored encrypted. The PIN is the key.\"",
    ),
    (
        "lock/named",
        "A device that has saved a wallet: \"Locked\", the name its owner gave it, and \
         \"Touch anywhere to unlock\".",
    ),
    (
        "lock/no-name",
        "The same screen on a device nobody has named. It states that as a fact rather than \
         leaving the row blank.",
    ),
    ("mnemonic/masked", "The recovery words, masked by default in fixed six-bullet runs."),
    (
        "mnemonic/reveal-confirm",
        "The two-step confirm that stands between the words and the screen.",
    ),
    ("mnemonic/revealed", "The words themselves, after the confirm."),
    (
        "mnemonic/stored-masked",
        "The same masked screen, reached from a stored wallet instead of from the dice.",
    ),
    (
        "mnemonic/stored-revealed",
        "A stored wallet's words revealed, through the same two-step gate a fresh set costs.",
    ),
    ("multisig-detail/cosigners", "A registration's cosigners, one key at a time."),
    ("multisig-detail/delete-typed", "Deleting a registration, with its name typed back."),
    (
        "multisig-detail/saved",
        "A stored registration: the quorum, the policy, and what this device is bound to in \
         it.",
    ),
    (
        "multisig-detail/unreadable",
        "A registration slot that did not come back intact. It can be erased and nothing \
         else.",
    ),
    (
        "multisig-import/approve",
        "The write page: the first receive address, what is about to be stored, and a live \
         Approve.",
    ),
    ("multisig-import/cosigner", "One cosigner of the descriptor being imported."),
    (
        "multisig-import/facts",
        "What the descriptor on the card actually says, before any of it is stored.",
    ),
    (
        "multisig-import/not-a-member",
        "A cosigner set that does not name this device, refused with no Approve anywhere on \
         the screen.",
    ),
    (
        "multisig-import/replace",
        "A descriptor imported over a slot that already holds one, with what changes if the \
         two differ.",
    ),
    ("multisig-list/empty", "The registry with nothing in it, and the card as the way to fill it."),
    (
        "multisig-list/pick",
        "Picking a descriptor or a Coldcard setup file off the card.",
    ),
    (
        "multisig-list/registered",
        "Two rows, one of each kind: a registration that proved out, and a slot that did not.",
    ),
    (
        "multisig-list/unreadable-claim",
        "The wallet record claims registrations and this device proved none. It says so \
         rather than drawing the empty state.",
    ),
    ("name-wallet/save-notice", "What the save writes, stated before the seal."),
    ("name-wallet/typed", "Naming the wallet that is about to be sealed."),
    (
        "passphrase-unlock/prompt",
        "A stored wallet whose record carries no passphrase, asking for one at unlock.",
    ),
    (
        "passphrase-unlock/refused",
        "The refusal, which states two derivation fingerprints rather than a verdict.",
    ),
    (
        "passphrase/derive-intro",
        "Making a second wallet from an open wallet's words. The first page says the wallet \
         you came from does not change.",
    ),
    (
        "passphrase/typed-masked",
        "The optional passphrase, both fields masked one bullet per typed character, with \
         the NFKD byte count.",
    ),
    (
        "passphrase/typed-shown",
        "The same screen with Show on: the literal input, spaces drawn as muted bullets.",
    ),
    (
        "phrase/autocomplete",
        "Mid-word: the BIP-39 completion strip at full width, with the overflow slot taken.",
    ),
    (
        "phrase/final-word",
        "Eleven words in. Only 128 of the 2048 can be the twelfth, so the screen finishes \
         the phrase instead of the word.",
    ),
    ("phrase/final-word-sheet", "The 128 words that fit, listed."),
    (
        "phrase/typed",
        "Restoring by typing a mnemonic, with the checksum verdict under it.",
    ),
    (
        "pin-create/mismatch",
        "A second entry that differed. Both entries are dropped and step 1 carries the \
         reason.",
    ),
    (
        "pin-create/step-1",
        "Setting the first PIN. This is where the device stops storing nothing.",
    ),
    ("pin-create/step-2", "The second entry. Nothing has been written yet."),
    (
        "pin/device-words",
        "The anti-phishing words, shown at half entry and derived from the eFuse key.",
    ),
    (
        "pin/device-words-six-digits",
        "Six digits rather than four, on the panel where this screen reflows into a \
         full-height right rail.",
    ),
    ("pin/last-attempt", "One wrong PIN before the device erases its stored wallets."),
    ("pin/typed", "PIN entry with four digits typed."),
    ("pin/wrong", "A wrong PIN, and what it cost."),
    ("receive/address", "One address, its QR, and the derivation named underneath it."),
    (
        "refusal/details",
        "The machine-fact block a bug report is photographed from, hidden until it is asked \
         for.",
    ),
    (
        "refusal/missing-prevtx",
        "A refusal is a full screen: a code, a headline, what happened, why it matters, and \
         what to do.",
    ),
    (
        "refusal/unsupported-script",
        "R-26, a script this device does not sign. No sentence on it names a cosigner or a \
         registration.",
    ),
    (
        "review-transaction/claimed-change",
        "CHANGE - CLAIMED, NOT VERIFIED: the change-confusion attack, on the page where it \
         is caught.",
    ),
    ("review-transaction/fee-enforced", "A fee that the proven amounts enforce."),
    (
        "review-transaction/fee-stated",
        "A fee the file merely claims, with AT LEAST on every number derived from it.",
    ),
    (
        "review-transaction/input-proven",
        "An input whose amount a full previous transaction proves.",
    ),
    (
        "review-transaction/input-stated",
        "An amount the file states and nothing proves. The caveat is carried by words, so a \
         monochrome photograph still says it.",
    ),
    ("review-transaction/output-external", "An output leaving this wallet."),
    (
        "review-transaction/overview",
        "Page one: what the transaction does, before any of the detail.",
    ),
    ("review-transaction/warnings-armed", "Every page seen, and the hold armed."),
    (
        "review-transaction/warnings-gated",
        "Every page seen and the hold still absent: an unproven change claim cannot be \
         signed past by reading everything.",
    ),
    ("scanning-flash/progress", "Reading the reserved space, block by block."),
    (
        "schemes/bip44",
        "Export, BIP-44 tab: the descriptor, then the account xpub, then the address rows.",
    ),
    (
        "schemes/bip84",
        "Export, BIP-84 tab: descriptor, account xpub, the SLIP-132 zpub, address rows, and \
         a QR button on every block.",
    ),
    (
        "schemes/qr",
        "The descriptor as a QR symbol. Every payload this screen encodes is a public value.",
    ),
    (
        "settings/default",
        "Settings as it opens, ending on \"Scroll for more settings.\" with the one \
         destructive row pinned under it.",
    ),
    (
        "settings/remove-pin-consequence",
        "What removing the PIN destroys, counted from the wallets this device holds.",
    ),
    ("settings/remove-pin-typed", "The same, with the confirmation word typed back."),
    (
        "settings/scrolled",
        "The foot of the settings list, which is the only place \"Format SD card\" can be \
         seen.",
    ),
    ("sign-source/empty", "A card with no transaction on it."),
    (
        "sign-source/ready",
        "One transaction on the card. The screen names it and offers to read it; inserting a \
         card reads nothing.",
    ),
    (
        "signing/signing",
        "Signing. Every signature produced here is re-verified against a sighash recomputed \
         from the file alone.",
    ),
    (
        "verify-device/acknowledge",
        "The one write this screen offers, on the same row as the sentence saying what it \
         costs.",
    ),
    (
        "verify-device/digests",
        "The digest blocks: the running app partition and the source id, whole rather than \
         wrapped.",
    ),
    (
        "verify-device/pre-pin",
        "Verify device before any PIN is typed. The pre-PIN readout is a strict subset of \
         the unlocked one.",
    ),
    (
        "verify-device/reserved-space",
        "The reserved-space section, before the scan is asked for.",
    ),
    (
        "verify-device/unlocked",
        "The same readout with a session open, which is the full set of rows.",
    ),
    ("wallet-home/delete-consequence", "What deleting a stored wallet destroys."),
    ("wallet-home/delete-typed-name", "The wallet's own name typed back, case included."),
    (
        "wallet-home/exit-modal",
        "Leaving a screen whose keys exist nowhere else. The modal is drawn over the sheet.",
    ),
    (
        "wallet-home/forget-passphrase-consequence",
        "Forgetting a stored passphrase, and what that costs.",
    ),
    (
        "wallet-home/forget-passphrase-hold",
        "The hold that has to fill before a secret this device can never show back is \
         destroyed.",
    ),
    (
        "wallet-home/passphrase-required",
        "A stored wallet whose record carries no passphrase. The identity row says which of \
         the three states it is in.",
    ),
    (
        "wallet-home/session",
        "\"Session wallet\": not stored, offering public keys and an address and nothing \
         else.",
    ),
    (
        "wallet-home/store-passphrase-consequence",
        "Storing a passphrase in the wallet's sealed record, with the two dangers that are \
         true whichever way it goes.",
    ),
    (
        "wallet-home/stored",
        "A stored wallet the embedder has not handed a derivation for: three actions.",
    ),
    (
        "wallet-home/stored-with-keys",
        "The same wallet unsealed WITH its derivation: seven actions, and the only state \
         that offers Sign.",
    ),
    (
        "wallet-list/many",
        "Three wallets and a slot that did not decrypt, over the count of slots in use.",
    ),
    (
        "wallet-list/none",
        "A PIN set and nothing stored: the list offers \"New wallet\" and \"Restore from \
         words\".",
    ),
    ("wallet-list/one", "What the list looks like the day after the first save."),
    ("wipe-policy/default", "The wrong-PIN policy on its default: erase after 15."),
    ("wipe-policy/edited", "The threshold moved off its default."),
    (
        "wipe-policy/wipe-off-arithmetic",
        "Turning the wipe off prices guessing THIS PIN on THIS board, with a longer PIN \
         offered beside accept and cancel.",
    ),
    ("wipe-policy/wipe-off-typed", "The same, with the confirmation word typed back."),
    (
        "working/checking-transaction",
        "The blocking frame while the file is validated, with no signing key in scope.",
    ),
    (
        "working/formatting-card",
        "The one blocking frame in the product during which \"Do not remove the card\" is \
         load-bearing rather than polite.",
    ),
];

/// What the index says about `frame`, if anything.
pub fn caption(frame: &str) -> Option<&'static str> {
    CAPTIONS.iter().find(|(name, _)| *name == frame).map(|(_, text)| *text)
}

/// One row of the index.
struct Row {
    stem: &'static str,
    panel: &'static str,
    frame: &'static str,
    caption: &'static str,
}

/// Every committed picture, in the order the directory listing puts them: numeric prefix
/// first, then the whole stem.
///
/// Sorted on the prefix as a NUMBER rather than as text, because a plain sort puts
/// `100-review-input-stated` between `10-verify-device` and `11-phrase-entry`, and an index
/// nobody can scan is the failure this file exists to fix.
fn rows() -> Vec<Row> {
    let mut rows = Vec::new();
    for frame in CATALOG {
        for (panel, label) in [(DOC_PORTRAIT, "720x720"), (DOC_LANDSCAPE, "800x480")] {
            let Some(stem) = frame.doc.name_for(panel) else { continue };
            rows.push(Row {
                stem,
                panel: label,
                frame: frame.name,
                caption: caption(frame.name).unwrap_or(""),
            });
        }
    }
    rows.sort_by_key(|r| (prefix(r.stem), r.stem));
    rows
}

/// The leading run of digits in a filename stem, as a number. Every committed picture has
/// one; a stem that ever stops having one sorts first rather than panicking, because this
/// is an index and not a gate.
fn prefix(stem: &str) -> u32 {
    stem.chars().take_while(char::is_ascii_digit).collect::<String>().parse().unwrap_or(0)
}

/// The generated index, as markdown. Written into docs/screenshots/ui by `uisim tour`.
pub fn markdown() -> String {
    let rows = rows();
    let mut out = String::new();
    out.push_str(
        "# What each picture shows\n\
         \n\
         Generated by `cargo run -p uisim -- tour` from `tools/uisim/src/index.rs`. Do not\n\
         edit it: tools/ci/check-screenshots.sh regenerates this file with the pictures and\n\
         fails on any difference. [README.md](README.md) carries the sample data and how to\n\
         regenerate the set.\n\
         \n",
    );
    out.push_str(&format!(
        "{} pictures, from {} of the {} frames `tools/uisim/src/catalog.rs` declares. A\n\
         frame appears twice when the 800x480 panel rearranges the screen rather than\n\
         compressing it; one row means the shorter panel needs no separate picture.\n\
         \n\
         The **Frame** column is the argument to `cargo run -p uisim -- render <frame>` and\n\
         the key of `tools/uisim/goldens.txt`, so a picture leads back to the state that\n\
         produced it. Match on the whole stem and never on the number: five prefixes name\n\
         two different screens each (72, 73, 74, 90 and 91).\n\
         \n",
        rows.len(),
        rows.iter().map(|r| r.frame).collect::<std::collections::BTreeSet<_>>().len(),
        CATALOG.len(),
    ));
    out.push_str("| File | Panel | Frame | What it shows |\n|---|---|---|---|\n");
    for r in &rows {
        out.push_str(&format!(
            "| {}.png | {} | `{}` | {} |\n",
            r.stem, r.panel, r.frame, r.caption
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::Doc;

    /// A promotion without a caption would publish a picture the index describes as an
    /// empty cell, which is how the hand-kept table decayed in the first place.
    #[test]
    fn every_committed_picture_has_a_caption() {
        let missing: Vec<&str> = CATALOG
            .iter()
            .filter(|f| f.doc != Doc::None && caption(f.name).is_none())
            .map(|f| f.name)
            .collect();
        assert!(missing.is_empty(), "pictured frames with no caption: {missing:?}");
    }

    /// And the other direction: a caption left behind by a demotion or a rename is a line
    /// about a picture nobody can look at.
    #[test]
    fn no_caption_names_a_frame_that_is_not_pictured() {
        for (name, _) in CAPTIONS {
            let frame = CATALOG.iter().find(|f| f.name == *name);
            match frame {
                None => panic!("{name} is captioned and is not a frame"),
                Some(f) => assert!(f.doc != Doc::None, "{name} is captioned and is not pictured"),
            }
        }
    }

    /// Sorted and unique, so a new caption has exactly one place to go and two lines can
    /// never disagree about the same frame.
    #[test]
    fn the_captions_are_sorted_and_unique() {
        for pair in CAPTIONS.windows(2) {
            assert!(pair[0].0 < pair[1].0, "{} and {} are out of order", pair[0].0, pair[1].0);
        }
    }

    /// The file these land in is gated by tools/ci/check-ascii-prose.sh, and it is a
    /// markdown table, so a pipe in a caption would split a row.
    #[test]
    fn the_captions_are_ascii_prose() {
        for (name, text) in CAPTIONS {
            assert!(!text.is_empty(), "{name} has an empty caption");
            assert!(text.is_ascii(), "{name}: caption is not ASCII");
            assert!(!text.contains('|'), "{name}: a pipe would split the table row");
            assert!(!text.contains('\n'), "{name}: a caption is one line");
            assert_eq!(text.trim(), *text, "{name}: caption has edge whitespace");
        }
    }

    /// The index has to describe the set that is actually written, file for file.
    #[test]
    fn the_index_has_one_row_per_committed_picture() {
        let pictures = CATALOG
            .iter()
            .flat_map(|f| [f.doc.name_for(DOC_PORTRAIT), f.doc.name_for(DOC_LANDSCAPE)])
            .flatten()
            .count();
        assert_eq!(rows().len(), pictures);
        let text = markdown();
        assert_eq!(text.lines().filter(|l| l.starts_with("| ")).count(), pictures + 1);
    }

    /// Ordered the way the directory reads, which a plain string sort does not do.
    #[test]
    fn the_index_is_ordered_by_number() {
        let rows = rows();
        let first = rows.iter().position(|r| r.stem == "10-verify-device").unwrap();
        let second = rows.iter().position(|r| r.stem == "100-review-input-stated").unwrap();
        assert!(first < second, "the index is sorting numbers as text");
        for pair in rows.windows(2) {
            assert!(prefix(pair[0].stem) <= prefix(pair[1].stem));
        }
    }
}
