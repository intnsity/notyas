// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The recorded flows, as data.
//!
//! A [`Frame`](crate::catalog::Frame) is one screen in one state. That is the right unit
//! for a gate - every state, on every panel, measured - and the wrong unit for showing
//! somebody what this device is like to use, because most of what a signer IS is the
//! order: which page the amounts are on, how many pages a finger has to turn before the
//! hold appears at all, what the device asks before it writes a file. A still of the fee
//! page cannot say that nine pages were traversed to reach it.
//!
//! A [`Flow`] is that order, written down. One [`Ui`], built once at the flow's panel and
//! never rebuilt, walked by a sequence of [`Step`]s with the panel photographed after each
//! one. Adding a flow is adding an entry here; the recorder learns nothing about any
//! particular flow and neither does the renderer.
//!
//! Two properties are inherited rather than re-earned:
//!
//! - Steps drive through [`crate::drive`] and start from the catalogue's own route
//!   prefixes, so a recording reaches a screen the way a finger does or fails loudly at a
//!   missing region. It cannot quietly become a film of a state nobody can get to.
//! - Every step declares the [`ScreenId`] it must land on, exactly as a frame does, so a
//!   route that stops working stops the recording instead of producing a plausible film of
//!   the wrong screens.
//!
//! What these are NOT is evidence. Recordings are written to the build directory, at one
//! panel each, and nothing under `cargo test` reads their pixels; the gate is
//! [`crate::gate`] and stays there. A GIF is not something a reviewer can read as a diff,
//! which is the whole basis on which the committed pictures are trusted.

use notyas_ui::{
    Artifact, CardOutcome, DeleteOutcome, FormatOffer, FormatOutcome, LockInfo, PsbtOutcome,
    RegionId, ScreenId, SignOutcome, StoreStatus, Ui, UiRequest, UnsealOutcome, WordsOutcome,
    WriteOutcome, HOLD_MS,
};

use crate::catalog::{
    blank_store, home, home_unlocked, open_first_wallet, show_qr, wallet_home_signable,
    DOC_LANDSCAPE, DOC_PORTRAIT,
};
use crate::drive::{
    age, answer_quiz, last_list_row, locked, page_forward, page_to, press, scroll_to, tap,
    type_dice, type_keys, type_shifted, unlocked_with_dummy_wallets,
};
use crate::fixtures::{
    dummy_flash_scan, dummy_format_target, dummy_lock_info, dummy_signed,
    dummy_single_psbt_card, dummy_tx_review, dummy_wallets, ReviewShape, SIXES, SIXES_PHRASE,
};

/// One route through the product, photographed at every step.
pub struct Flow {
    /// Unique id. The argument to `uisim record`, the directory the frames land in, and
    /// the stem of the GIF assembled from them.
    pub name: &'static str,
    /// One line saying what the recording shows. Printed by the recorder.
    pub about: &'static str,
    /// The single panel this flow is recorded on.
    ///
    /// One geometry per flow, unlike a frame, and the comment on each says which and why:
    /// these are illustrations, and the same route shot five times is five times the bytes
    /// in a repository people clone. Covering every panel is the gate's job, not this
    /// one's, and the gate still does it for every screen a flow passes through.
    pub panel: (u32, u32),
    pub steps: &'static [Step],
}

/// One step: what the finger does, where that must leave it, and how long the assembled
/// GIF holds the picture.
pub struct Step {
    /// Slug for the numbered PNG and for the recorder's console line.
    pub name: &'static str,
    /// Where this step must land. Asserted after every step, so a flow that stops reaching
    /// its screen fails instead of filming a different one.
    pub screen: ScreenId,
    pub dwell: Dwell,
    /// What the finger does, applied to the `Ui` the previous step left behind.
    pub act: fn(&mut Ui),
}

/// How long a step stays on screen. Three lengths, chosen by what the frame asks of a
/// reader rather than by taste.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dwell {
    /// One tap's worth of change on a screen already taken in: the entropy meter stepping,
    /// a page of the review turning, a sheet being dismissed.
    Beat,
    /// A screen the reader has not seen before. Long enough for a heading and the controls
    /// under it.
    Screen,
    /// A screen carrying a value somebody is meant to actually read: an address, an amount,
    /// a fee, a digest, a file name. These are what the recording exists for.
    Value,
}

impl Dwell {
    /// In centiseconds, which is GIF's own unit of delay and therefore the last place this
    /// number gets rounded.
    pub fn centiseconds(self) -> u32 {
        match self {
            Dwell::Beat => 55,
            Dwell::Screen => 120,
            Dwell::Value => 190,
        }
    }
}

// ---------------------------------------------------------------------------------------
// Step actions used by more than one step
// ---------------------------------------------------------------------------------------

/// Eight more rolls of the catalogue's sample die, which is one notch of the meter here.
///
/// A slice of [`SIXES`] rather than eight typed characters, so a recording enters the same
/// sample data every frame does: BIP39 test vector #1, 64 sixes, all-zero entropy. Eight
/// identical steps rather than one that counts, because a step is a `fn(&mut Ui)` and the
/// sequence is what carries the count; `the_sample_die_is_uniform` is what makes taking the
/// first eight the same as taking any eight.
fn eight_rolls(ui: &mut Ui) {
    type_dice(ui, &SIXES[..8]);
}

/// One page of a review sheet, turned.
fn next_page(ui: &mut Ui) {
    page_forward(ui, 1);
}

/// Back, from a screen that has one.
fn back(ui: &mut Ui) {
    tap(ui, RegionId::Back);
}

// ---------------------------------------------------------------------------------------
// The flows
// ---------------------------------------------------------------------------------------

/// Every recorded flow.
pub const FLOWS: &[Flow] = &[
    // --- Making a seed out of dice -----------------------------------------------------
    Flow {
        name: "dice-entropy",
        about: "rolling a seed: the entropy meter filling roll by roll, then the words",
        // Landscape. The strength meter, the bit count and the keypad are side by side at
        // 800x480 and stacked at 720x720, so the thing this recording is about - a reading
        // changing under the finger that changed it - is one glance rather than two.
        panel: DOC_LANDSCAPE,
        steps: &[
            Step { name: "home", screen: ScreenId::Home, dwell: Dwell::Screen, act: home },
            Step {
                name: "dice-empty",
                screen: ScreenId::DiceEntry,
                dwell: Dwell::Screen,
                act: |ui| {
                    tap(ui, RegionId::HomeNewSeed);
                },
            },
            Step {
                name: "rolls-08",
                screen: ScreenId::DiceEntry,
                dwell: Dwell::Beat,
                act: eight_rolls,
            },
            Step {
                name: "rolls-16",
                screen: ScreenId::DiceEntry,
                dwell: Dwell::Beat,
                act: eight_rolls,
            },
            Step {
                name: "rolls-24",
                screen: ScreenId::DiceEntry,
                dwell: Dwell::Beat,
                act: eight_rolls,
            },
            Step {
                name: "rolls-32",
                screen: ScreenId::DiceEntry,
                dwell: Dwell::Beat,
                act: eight_rolls,
            },
            Step {
                name: "rolls-40",
                screen: ScreenId::DiceEntry,
                dwell: Dwell::Beat,
                act: eight_rolls,
            },
            Step {
                name: "rolls-48",
                screen: ScreenId::DiceEntry,
                dwell: Dwell::Beat,
                act: eight_rolls,
            },
            Step {
                name: "rolls-56",
                screen: ScreenId::DiceEntry,
                dwell: Dwell::Beat,
                act: eight_rolls,
            },
            // 128 bits, and the meter says so. The one roll count here a reader is meant to
            // stop on.
            Step {
                name: "rolls-64",
                screen: ScreenId::DiceEntry,
                dwell: Dwell::Value,
                act: eight_rolls,
            },
            Step {
                name: "masked",
                screen: ScreenId::MnemonicDisplay,
                dwell: Dwell::Screen,
                act: |ui| {
                    tap(ui, RegionId::DiceDone);
                },
            },
            Step {
                name: "reveal-confirm",
                screen: ScreenId::MnemonicDisplay,
                dwell: Dwell::Screen,
                act: |ui| {
                    tap(ui, RegionId::Reveal);
                },
            },
            Step {
                name: "revealed",
                screen: ScreenId::MnemonicDisplay,
                dwell: Dwell::Value,
                act: |ui| {
                    tap(ui, RegionId::ModalConfirm);
                },
            },
        ],
    },
    // --- Signing a transaction off the card --------------------------------------------
    Flow {
        name: "psbt-signing",
        about: "signing a PSBT: the file, all ten review pages, the hold, the written file",
        // Landscape. Every page of the review is a label column beside a value column, and
        // an amount that fits on one line is an amount that cannot be misread across a wrap.
        panel: DOC_LANDSCAPE,
        steps: &[
            Step {
                name: "wallet-home",
                screen: ScreenId::WalletHome,
                dwell: Dwell::Screen,
                act: wallet_home_signable,
            },
            Step {
                name: "reading-card",
                screen: ScreenId::Working,
                dwell: Dwell::Beat,
                act: |ui| {
                    assert!(
                        matches!(tap(ui, RegionId::ActSign), Some(UiRequest::ListCard { .. })),
                        "Sign must arrive with the card read that ends its Busy frame"
                    );
                },
            },
            // One transaction on the card: the device names it and offers to read it, and
            // does not read it on its own.
            Step {
                name: "file-found",
                screen: ScreenId::SignSource,
                dwell: Dwell::Value,
                act: |ui| {
                    ui.card_result(CardOutcome::Listed(dummy_single_psbt_card()));
                },
            },
            Step {
                name: "checking",
                screen: ScreenId::Working,
                dwell: Dwell::Beat,
                act: |ui| {
                    assert!(
                        matches!(tap(ui, RegionId::SignReady), Some(UiRequest::LoadPsbt { .. })),
                        "the file card must ask the embedder to read and check it"
                    );
                },
            },
            Step {
                name: "review-overview",
                screen: ScreenId::ReviewTransaction,
                dwell: Dwell::Value,
                act: |ui| {
                    ui.psbt_result(PsbtOutcome::Reviewed(dummy_tx_review(ReviewShape::Proven)));
                },
            },
            // Ten pages, turned one at a time, because that is the gate: the hold does not
            // exist until every page has been SEEN. A recording that jumped would be showing
            // a shortcut the device does not have.
            Step {
                name: "input-1",
                screen: ScreenId::ReviewTransaction,
                dwell: Dwell::Value,
                act: next_page,
            },
            Step {
                name: "input-2",
                screen: ScreenId::ReviewTransaction,
                dwell: Dwell::Beat,
                act: next_page,
            },
            Step {
                name: "input-3",
                screen: ScreenId::ReviewTransaction,
                dwell: Dwell::Beat,
                act: next_page,
            },
            Step {
                name: "output-payment",
                screen: ScreenId::ReviewTransaction,
                dwell: Dwell::Value,
                act: next_page,
            },
            Step {
                name: "output-change",
                screen: ScreenId::ReviewTransaction,
                dwell: Dwell::Value,
                act: next_page,
            },
            Step {
                name: "output-data",
                screen: ScreenId::ReviewTransaction,
                dwell: Dwell::Beat,
                act: next_page,
            },
            Step {
                name: "output-ours",
                screen: ScreenId::ReviewTransaction,
                dwell: Dwell::Beat,
                act: next_page,
            },
            Step {
                name: "fee",
                screen: ScreenId::ReviewTransaction,
                dwell: Dwell::Value,
                act: next_page,
            },
            Step {
                name: "warnings",
                screen: ScreenId::ReviewTransaction,
                dwell: Dwell::Value,
                act: next_page,
            },
            // The gesture, caught half done. A tap can be a jolt or a wet panel, so the one
            // control that spends a key is the one control a tap cannot reach.
            Step {
                name: "hold-half",
                screen: ScreenId::ReviewTransaction,
                dwell: Dwell::Beat,
                act: |ui| {
                    press(ui, RegionId::HoldConfirm);
                    age(ui, HOLD_MS / 2);
                },
            },
            Step {
                name: "signing",
                screen: ScreenId::Signing,
                dwell: Dwell::Screen,
                act: |ui| {
                    assert!(
                        matches!(age(ui, HOLD_MS), Some(UiRequest::SignTx)),
                        "a filled hold is what asks for a signature"
                    );
                },
            },
            Step {
                name: "signed",
                screen: ScreenId::Deliver,
                dwell: Dwell::Value,
                act: |ui| {
                    ui.sign_result(SignOutcome::Signed(dummy_signed(true)));
                },
            },
            // A write is a Busy frame of its own: the device says what it is doing to the
            // card while it does it, and the delivery screen comes back with the answer.
            Step {
                name: "writing",
                screen: ScreenId::Working,
                dwell: Dwell::Beat,
                act: |ui| {
                    assert!(
                        matches!(
                            tap(ui, RegionId::DeliverSd),
                            Some(UiRequest::WriteSigned { overwrite: false })
                        ),
                        "Write to card is what asks for the write"
                    );
                },
            },
            // The file, named and sized, on a screen that offers no exit until a delivery
            // has actually succeeded.
            Step {
                name: "written",
                screen: ScreenId::Deliver,
                dwell: Dwell::Value,
                act: |ui| {
                    ui.write_result(WriteOutcome::Written(vec![Artifact {
                        name: String::from("dummy-spend-2026-08-17-signed.psbt"),
                        bytes: 2_712,
                    }]));
                },
            },
        ],
    },
    // --- What a stored wallet is, and what it offers -----------------------------------
    Flow {
        name: "wallet-details",
        about: "a stored wallet: its identity row, receive, export, and the delete at the foot",
        // Landscape. The action cards are a two-column grid at 800x480 and one column at
        // 720x720, so more of what the wallet offers is on the glass at once.
        panel: DOC_LANDSCAPE,
        steps: &[
            Step {
                name: "wallet-list",
                screen: ScreenId::WalletList,
                dwell: Dwell::Screen,
                act: unlocked_with_dummy_wallets,
            },
            // Fingerprint, derivation path, script type, network, passphrase state: what
            // this wallet IS, above anything it can do.
            Step {
                name: "wallet-home",
                screen: ScreenId::WalletHome,
                dwell: Dwell::Value,
                act: open_first_wallet,
            },
            Step {
                name: "receive",
                screen: ScreenId::Receive,
                dwell: Dwell::Value,
                act: |ui| {
                    scroll_to(ui, RegionId::ActReceive);
                    tap(ui, RegionId::ActReceive);
                },
            },
            Step {
                name: "next-address",
                screen: ScreenId::Receive,
                dwell: Dwell::Value,
                act: |ui| {
                    tap(ui, RegionId::NextAddr);
                },
            },
            Step {
                name: "back-to-wallet",
                screen: ScreenId::WalletHome,
                dwell: Dwell::Beat,
                act: back,
            },
            Step {
                name: "export-keys",
                screen: ScreenId::Schemes,
                dwell: Dwell::Value,
                act: |ui| {
                    scroll_to(ui, RegionId::ActExport);
                    tap(ui, RegionId::ActExport);
                },
            },
            // The descriptor, as the symbol a coordinator is meant to scan. Export opens on
            // BIP-84 already, so the tab strip is not what this step is for - the round trip
            // is: the tap raises a request, the core encodes the payload on the std side,
            // and the matrix comes back in, exactly as it does on the device.
            Step {
                name: "descriptor-qr",
                screen: ScreenId::Schemes,
                dwell: Dwell::Value,
                act: |ui| {
                    let Some(UiRequest::Qr(target)) = tap(ui, RegionId::QrDescriptor) else {
                        panic!("the descriptor QR button raised no request");
                    };
                    show_qr(ui, target);
                },
            },
            Step {
                name: "close-qr",
                screen: ScreenId::Schemes,
                dwell: Dwell::Beat,
                act: |ui| {
                    tap(ui, RegionId::ModalClose);
                },
            },
            Step {
                name: "back-again",
                screen: ScreenId::WalletHome,
                dwell: Dwell::Beat,
                act: back,
            },
            // The rest of the list, ending on the one destructive row. Scrolled to rather
            // than reached by index, because a row this cannot reach is a row a finger
            // cannot reach either.
            Step {
                name: "delete-at-the-foot",
                screen: ScreenId::WalletHome,
                dwell: Dwell::Screen,
                act: |ui| scroll_to(ui, RegionId::WalletDelete),
            },
        ],
    },
    // --- Checking that the device is the one you left ----------------------------------
    Flow {
        name: "device-fingerprint",
        about: "verifying the device: the paged readout, the reserved-space scan, the boot mark",
        // Portrait. The same readout is 12 pages at 720x720 and 23 at 800x480, and the hex
        // blocks - the die id and the firmware digests, which are the point of the screen -
        // fit whole in the taller viewport instead of breaking across a page.
        panel: DOC_PORTRAIT,
        steps: &[
            Step {
                name: "home",
                screen: ScreenId::Home,
                dwell: Dwell::Screen,
                act: home_unlocked,
            },
            Step {
                name: "identity",
                screen: ScreenId::VerifyDevice,
                dwell: Dwell::Value,
                act: |ui| {
                    tap(ui, RegionId::HomeVerifyDevice);
                },
            },
            Step {
                name: "die-id",
                screen: ScreenId::VerifyDevice,
                dwell: Dwell::Value,
                act: next_page,
            },
            Step {
                name: "firmware-digest",
                screen: ScreenId::VerifyDevice,
                dwell: Dwell::Value,
                act: next_page,
            },
            Step {
                name: "image-digests",
                screen: ScreenId::VerifyDevice,
                dwell: Dwell::Value,
                act: next_page,
            },
            Step {
                name: "flash",
                screen: ScreenId::VerifyDevice,
                dwell: Dwell::Screen,
                act: next_page,
            },
            // Paged to rather than counted to: the section moves as the readout grows, and
            // a recording that hardcoded its page number would quietly start filming the
            // page before it.
            Step {
                name: "reserved-space",
                screen: ScreenId::VerifyDevice,
                dwell: Dwell::Screen,
                act: |ui| page_to(ui, RegionId::VerifyScanFlash),
            },
            Step {
                name: "scanning",
                screen: ScreenId::ScanningFlash,
                dwell: Dwell::Beat,
                act: |ui| {
                    assert_eq!(
                        tap(ui, RegionId::VerifyScanFlash),
                        Some(UiRequest::ScanReservedSpace),
                        "Scan must ask the std side to read flash"
                    );
                },
            },
            Step {
                name: "scanned",
                screen: ScreenId::VerifyDevice,
                dwell: Dwell::Value,
                act: |ui| {
                    ui.set_flash_scan(dummy_flash_scan());
                },
            },
            // The one write this screen offers, under the sentence that says what it costs.
            Step {
                name: "boot-count",
                screen: ScreenId::VerifyDevice,
                dwell: Dwell::Value,
                act: |ui| page_to(ui, RegionId::VerifyAckBoots),
            },
        ],
    },
    // --- The settings a session can reach ----------------------------------------------
    Flow {
        name: "settings",
        about: "settings: the device name, the network, the wrong-PIN policy, and the one red row",
        // Portrait. The list shows four rows plus the pinned destructive row at 720x720 and
        // two rows at 800x480, so the recording is about the settings rather than about
        // scrolling.
        panel: DOC_PORTRAIT,
        steps: &[
            Step {
                name: "wallet-list",
                screen: ScreenId::WalletList,
                dwell: Dwell::Screen,
                act: unlocked_with_dummy_wallets,
            },
            Step {
                name: "settings",
                screen: ScreenId::Settings,
                dwell: Dwell::Value,
                act: |ui| {
                    tap(ui, RegionId::OpenSettings);
                },
            },
            // The one string this device prints before a PIN is typed, which is why it is
            // the first row.
            Step {
                name: "device-name",
                screen: ScreenId::DeviceName,
                dwell: Dwell::Value,
                act: |ui| {
                    tap(ui, RegionId::SetRow(0));
                },
            },
            Step {
                name: "renaming",
                screen: ScreenId::DeviceName,
                dwell: Dwell::Value,
                act: |ui| {
                    tap(ui, RegionId::DeviceNameField);
                    for _ in 0..4 {
                        tap(ui, RegionId::KeyBackspace);
                    }
                    type_keys(ui, "shed");
                },
            },
            Step {
                name: "back-to-settings",
                screen: ScreenId::Settings,
                dwell: Dwell::Beat,
                act: back,
            },
            // The row that acts here rather than opening a screen. What it reads is what the
            // next derivation runs on, so it outlives this screen.
            Step {
                name: "testnet",
                screen: ScreenId::Settings,
                dwell: Dwell::Screen,
                act: |ui| {
                    tap(ui, RegionId::SetRow(1));
                },
            },
            Step {
                name: "mainnet",
                screen: ScreenId::Settings,
                dwell: Dwell::Beat,
                act: |ui| {
                    tap(ui, RegionId::SetRow(1));
                },
            },
            Step {
                name: "wipe-policy",
                screen: ScreenId::WipePolicy,
                dwell: Dwell::Value,
                act: |ui| {
                    scroll_to(ui, RegionId::SetRow(2));
                    tap(ui, RegionId::SetRow(2));
                },
            },
            Step {
                name: "threshold-up",
                screen: ScreenId::WipePolicy,
                dwell: Dwell::Beat,
                act: |ui| {
                    tap(ui, RegionId::PolicyMore);
                },
            },
            Step {
                name: "settings-again",
                screen: ScreenId::Settings,
                dwell: Dwell::Beat,
                act: back,
            },
            // The destructive row is pinned to the foot of the list on every panel, and it
            // names what it destroys with counts read from the wallets this device holds.
            Step {
                name: "remove-pin",
                screen: ScreenId::Settings,
                dwell: Dwell::Value,
                act: |ui| {
                    tap(ui, RegionId::RemoveThePin);
                },
            },
            Step {
                name: "cancelled",
                screen: ScreenId::Settings,
                dwell: Dwell::Beat,
                act: |ui| {
                    tap(ui, RegionId::DangerCancel);
                },
            },
        ],
    },
    // --- The way in on a device that has saved a wallet, and the way back out -----------
    Flow {
        name: "unlock-and-lock",
        about: "the round trip: Locked, the PIN, the device words, Wallets, and Locked again",
        // Portrait. At 800x480 the PIN screen reflows into a full-height right rail; the
        // portrait arrangement puts the anti-phishing words directly above the pad, which
        // is the reading order this recording exists to teach.
        panel: DOC_PORTRAIT,
        steps: &[
            Step {
                name: "locked",
                screen: ScreenId::Lock,
                dwell: Dwell::Screen,
                act: |ui| locked(ui, dummy_lock_info()),
            },
            Step {
                name: "pin-pad",
                screen: ScreenId::PinEntry,
                dwell: Dwell::Beat,
                act: |ui| {
                    tap(ui, RegionId::LockWake);
                },
            },
            Step {
                name: "two-digits",
                screen: ScreenId::PinEntry,
                dwell: Dwell::Beat,
                act: |ui| {
                    tap(ui, RegionId::PinKey(0));
                    tap(ui, RegionId::PinKey(3));
                },
            },
            // The words arrive at half entry and the explainer arrives with them, once per
            // power-up. `show_device_words` rather than `drive::device_words` because that
            // helper dismisses the explainer in the same call, and this recording wants the
            // two apart: what the words are, and then the words themselves over the pad.
            Step {
                name: "words-explained",
                screen: ScreenId::AboutDeviceWords,
                dwell: Dwell::Value,
                act: |ui| {
                    ui.show_device_words(["anvil".into(), "mercury".into()]);
                },
            },
            Step {
                name: "device-words",
                screen: ScreenId::PinEntry,
                dwell: Dwell::Value,
                act: |ui| {
                    tap(ui, RegionId::WordsUnderstood);
                },
            },
            // What a wrong PIN costs, stated by the device rather than by a caption. Unlock
            // is live at four digits because the DUMMY store's floor is four.
            Step {
                name: "wrong-pin",
                screen: ScreenId::PinEntry,
                dwell: Dwell::Screen,
                act: |ui| {
                    tap(ui, RegionId::PinKey(6));
                    tap(ui, RegionId::PinKey(9));
                    assert!(
                        matches!(tap(ui, RegionId::PinSubmit), Some(UiRequest::UnsealWallet(_))),
                        "Unlock must ask the embedder to unseal"
                    );
                    ui.unseal_result(UnsealOutcome::WrongPin { attempts_left: Some(2) });
                },
            },
            Step {
                name: "retyped",
                screen: ScreenId::PinEntry,
                dwell: Dwell::Beat,
                act: |ui| {
                    for i in [0, 3, 6, 9] {
                        tap(ui, RegionId::PinKey(i));
                    }
                },
            },
            Step {
                name: "wallets",
                screen: ScreenId::WalletList,
                dwell: Dwell::Value,
                act: |ui| {
                    assert!(
                        matches!(tap(ui, RegionId::PinSubmit), Some(UiRequest::UnsealWallet(_))),
                        "Unlock must ask the embedder to unseal"
                    );
                    ui.unseal_result(UnsealOutcome::Unsealed);
                    ui.set_wallets(dummy_wallets());
                },
            },
            // The same dice screen the stateless home reaches, from inside a session: there
            // is no second seed generator and no method fork in between.
            Step {
                name: "same-dice",
                screen: ScreenId::DiceEntry,
                dwell: Dwell::Screen,
                act: |ui| {
                    tap(ui, RegionId::WalletNew);
                },
            },
            Step {
                name: "back-to-wallets",
                screen: ScreenId::WalletList,
                dwell: Dwell::Beat,
                act: back,
            },
            // The return leg. The chip is in the top bar of the wallet list, the wallet home
            // and settings, and it drops the session rather than dimming the screen.
            Step {
                name: "locked-again",
                screen: ScreenId::Lock,
                dwell: Dwell::Screen,
                act: |ui| {
                    assert_eq!(
                        tap(ui, RegionId::Lock),
                        Some(UiRequest::LockSession),
                        "Lock device must ask for the session to be dropped"
                    );
                    assert!(ui.lock(), "a device with a PIN locks");
                },
            },
        ],
    },
    // --- The one crossing from a device that stores nothing to one that stores something -
    Flow {
        name: "first-pin",
        about: "the first save: the fork, a PIN set twice, the device words, and a stored wallet",
        // Portrait. Four pad-and-keyboard screens plus the fork, and the pad's portrait
        // arrangement is what this route is about; the fork already has a committed
        // landscape still, so the pair covers both geometries between them.
        panel: DOC_PORTRAIT,
        steps: &[
            // A provisioned device that has written nothing. The stateless home IS the way
            // in here - there is no lock screen on a device with no PIN (R20).
            Step {
                name: "nothing-stored",
                screen: ScreenId::Home,
                dwell: Dwell::Screen,
                act: blank_store,
            },
            Step {
                name: "dice",
                screen: ScreenId::DiceEntry,
                dwell: Dwell::Beat,
                act: |ui| {
                    tap(ui, RegionId::HomeNewSeed);
                    type_dice(ui, SIXES);
                },
            },
            Step {
                name: "masked",
                screen: ScreenId::MnemonicDisplay,
                dwell: Dwell::Beat,
                act: |ui| {
                    tap(ui, RegionId::DiceDone);
                },
            },
            Step {
                name: "words",
                screen: ScreenId::MnemonicDisplay,
                dwell: Dwell::Value,
                act: |ui| {
                    tap(ui, RegionId::Reveal);
                    tap(ui, RegionId::ModalConfirm);
                },
            },
            // The default: opted out, and the continue button is what the screen offers in
            // that state.
            Step {
                name: "passphrase-off",
                screen: ScreenId::PassphraseEntry,
                dwell: Dwell::Screen,
                act: |ui| {
                    tap(ui, RegionId::Next);
                },
            },
            Step {
                name: "backup-check",
                screen: ScreenId::BackupCheck,
                dwell: Dwell::Screen,
                act: |ui| {
                    tap(ui, RegionId::KeyDone);
                    assert!(ui.tick(0).dirty, "Done must run the pending derivation");
                },
            },
            // The only place anything is written, and it comes after the check with the
            // words already behind the user. On this device the Save card reads "Sets a PIN
            // first. The PIN is the key."
            Step {
                name: "fork",
                screen: ScreenId::KeepOrSave,
                dwell: Dwell::Value,
                act: answer_quiz,
            },
            Step {
                name: "set-a-pin",
                screen: ScreenId::PinCreate,
                dwell: Dwell::Screen,
                act: |ui| {
                    tap(ui, RegionId::SaveToDevice);
                },
            },
            Step {
                name: "pin-once",
                screen: ScreenId::PinCreate,
                dwell: Dwell::Beat,
                act: |ui| {
                    for i in 0..4 {
                        tap(ui, RegionId::PinKey(i));
                    }
                    tap(ui, RegionId::PinNext);
                },
            },
            Step {
                name: "pin-again",
                screen: ScreenId::PinCreate,
                dwell: Dwell::Beat,
                act: |ui| {
                    for i in 0..4 {
                        tap(ui, RegionId::PinKey(i));
                    }
                },
            },
            // A matching second entry is what asks for the format, and the explainer lands
            // on the one occasion in the device's life when the words are new.
            Step {
                name: "words-explained",
                screen: ScreenId::AboutDeviceWords,
                dwell: Dwell::Value,
                act: |ui| {
                    assert!(
                        matches!(tap(ui, RegionId::PinConfirm), Some(UiRequest::SetPin(_))),
                        "a matching second entry is what asks for the format"
                    );
                    ui.pin_created(true);
                },
            },
            Step {
                name: "name-it",
                screen: ScreenId::NameWallet,
                dwell: Dwell::Screen,
                act: |ui| {
                    tap(ui, RegionId::WordsUnderstood);
                    tap(ui, RegionId::NameField);
                    type_keys(ui, "savings");
                },
            },
            Step {
                name: "save-notice",
                screen: ScreenId::NameWallet,
                dwell: Dwell::Value,
                act: |ui| {
                    tap(ui, RegionId::KeyDone);
                },
            },
            Step {
                name: "stored",
                screen: ScreenId::WalletHome,
                dwell: Dwell::Value,
                act: |ui| {
                    assert!(
                        matches!(
                            tap(ui, RegionId::ConfirmSave),
                            Some(UiRequest::PersistWallet(_))
                        ),
                        "Save wallet is what asks for the seal"
                    );
                    ui.persist_result(true);
                },
            },
            // The device this run started on booted to a menu. This one boots to "Locked".
            // Order matters: the chip is tapped while the session is still open, and the
            // lock info the embedder reads back off the freshly formatted store - which has
            // an attempt budget and a PIN shape the blank one did not - is installed after.
            Step {
                name: "locked",
                screen: ScreenId::Lock,
                dwell: Dwell::Screen,
                act: |ui| {
                    assert_eq!(
                        tap(ui, RegionId::Lock),
                        Some(UiRequest::LockSession),
                        "Lock device must ask for the session to be dropped"
                    );
                    ui.set_lock_info(LockInfo {
                        status: StoreStatus::Unlocked,
                        ..dummy_lock_info()
                    });
                    assert!(ui.lock(), "a device with a PIN locks");
                },
            },
        ],
    },
    // --- Erasing a card, the one operation here that destroys data the device does not own
    Flow {
        name: "format-card",
        about: "formatting a card: the row at the foot of settings, the probe, the typed word",
        // Portrait. The settings list shows four rows plus the pinned destructive row at
        // 720x720 and two at 800x480, so the drag to the foot is one gesture rather than
        // four and the recording is about the row rather than about scrolling.
        panel: DOC_PORTRAIT,
        steps: &[
            Step {
                name: "wallets",
                screen: ScreenId::WalletList,
                dwell: Dwell::Screen,
                act: unlocked_with_dummy_wallets,
            },
            Step {
                name: "settings",
                screen: ScreenId::Settings,
                dwell: Dwell::Screen,
                act: |ui| {
                    tap(ui, RegionId::OpenSettings);
                },
            },
            // The frame that proves the row exists. It is below the fold on every shipped
            // panel, which is why the default settings picture cannot show it.
            Step {
                name: "below-the-fold",
                screen: ScreenId::Settings,
                dwell: Dwell::Value,
                act: |ui| {
                    let _ = last_list_row(ui);
                },
            },
            // `ScreenId::Working` and not `FormatCard`: S-49 is pushed with its probe
            // already in flight, and a screen with a request outstanding reports the busy
            // id like every other C3 frame in the product.
            Step {
                name: "probing",
                screen: ScreenId::Working,
                dwell: Dwell::Beat,
                act: |ui| {
                    let row = last_list_row(ui);
                    assert!(
                        matches!(tap(ui, row), Some(UiRequest::ProbeCardFormat)),
                        "S-49 must open with its probe in flight, never on an unasked card"
                    );
                },
            },
            Step {
                name: "offer",
                screen: ScreenId::FormatCard,
                dwell: Dwell::Value,
                act: |ui| {
                    ui.format_offer(FormatOffer::Ready(dummy_format_target()));
                },
            },
            Step {
                name: "consequence",
                screen: ScreenId::FormatCard,
                dwell: Dwell::Value,
                act: |ui| {
                    tap(ui, RegionId::CardFormat);
                },
            },
            // The friction is the feature: "32GB" costs a digit page and then a shifted
            // letter page, so nobody types it by accident.
            Step {
                name: "type-the-capacity",
                screen: ScreenId::FormatCard,
                dwell: Dwell::Value,
                act: |ui| {
                    tap(ui, RegionId::DangerConfirm);
                    tap(ui, RegionId::PageDigits);
                    type_keys(ui, "32");
                    tap(ui, RegionId::PageLetters);
                    type_shifted(ui, "GB");
                },
            },
            // The one busy frame in the product during which "Do not remove the card" is
            // load-bearing rather than polite.
            Step {
                name: "formatting",
                screen: ScreenId::Working,
                dwell: Dwell::Beat,
                act: |ui| {
                    assert!(
                        matches!(
                            tap(ui, RegionId::DangerConfirm),
                            Some(UiRequest::FormatCard { .. })
                        ),
                        "the typed word is the only thing that raises the write"
                    );
                },
            },
            Step {
                name: "done",
                screen: ScreenId::FormatCard,
                dwell: Dwell::Value,
                act: |ui| {
                    ui.format_result(FormatOutcome::Done(String::from(
                        "The 32 GB card now holds one empty FAT filesystem in partition 1.",
                    )));
                },
            },
        ],
    },
    // --- Taking a wallet off the device -------------------------------------------------
    Flow {
        name: "erase-a-wallet",
        about: "deleting a stored wallet: the typed name, the words offered first, the list after",
        // Portrait. The word grid and the wallet menu are both vertical, and the
        // `wallet-details` recording already covers this menu at 800x480, so the two cover
        // both shipped geometries between them.
        panel: DOC_PORTRAIT,
        steps: &[
            Step {
                name: "wallets",
                screen: ScreenId::WalletList,
                dwell: Dwell::Screen,
                act: unlocked_with_dummy_wallets,
            },
            Step {
                name: "wallet",
                screen: ScreenId::WalletHome,
                dwell: Dwell::Screen,
                act: open_first_wallet,
            },
            Step {
                name: "delete-row",
                screen: ScreenId::WalletHome,
                dwell: Dwell::Beat,
                act: |ui| scroll_to(ui, RegionId::WalletDelete),
            },
            Step {
                name: "consequence",
                screen: ScreenId::WalletHome,
                dwell: Dwell::Value,
                act: |ui| {
                    tap(ui, RegionId::WalletDelete);
                },
            },
            // The sheet takes the wallet's own name, case included.
            Step {
                name: "type-the-name",
                screen: ScreenId::WalletHome,
                dwell: Dwell::Value,
                act: |ui| {
                    tap(ui, RegionId::DangerConfirm);
                    type_shifted(ui, "DUMMY");
                    tap(ui, RegionId::Shift);
                    type_keys(ui, " savings");
                },
            },
            // Two answers side by side, and neither of them is the sheet's confirm: the
            // device offers the recovery words before it destroys the record that holds
            // them.
            Step {
                name: "last-words-offered",
                screen: ScreenId::EraseWallet,
                dwell: Dwell::Value,
                act: |ui| {
                    tap(ui, RegionId::DangerConfirm);
                },
            },
            Step {
                name: "words-masked",
                screen: ScreenId::MnemonicDisplay,
                dwell: Dwell::Screen,
                act: |ui| {
                    assert!(
                        matches!(
                            tap(ui, RegionId::EraseShowWords),
                            Some(UiRequest::RecoveryWords(_))
                        ),
                        "Show the words must ask the embedder for them"
                    );
                    ui.recovery_words(WordsOutcome::words(SIXES_PHRASE));
                },
            },
            // A stored wallet's words are no cheaper to show than a fresh one's: the same
            // two-step gate, the same modal.
            Step {
                name: "words-revealed",
                screen: ScreenId::MnemonicDisplay,
                dwell: Dwell::Value,
                act: |ui| {
                    tap(ui, RegionId::Reveal);
                    tap(ui, RegionId::ModalConfirm);
                },
            },
            // Reading the words is not consent to anything, so this pops back to the offer
            // with the choice still open.
            Step {
                name: "still-offered",
                screen: ScreenId::EraseWallet,
                dwell: Dwell::Beat,
                act: back,
            },
            // The list first, then the answer: the embedder writes flash, re-reads the
            // slots, and only then reports what the flash actually holds.
            Step {
                name: "gone",
                screen: ScreenId::WalletList,
                dwell: Dwell::Value,
                act: |ui| {
                    assert!(
                        matches!(
                            tap(ui, RegionId::EraseNow),
                            Some(UiRequest::DeleteWallet(_))
                        ),
                        "Erase is what asks for the delete"
                    );
                    ui.set_wallets(dummy_wallets().into_iter().skip(1).collect());
                    ui.wallet_deleted(DeleteOutcome::Gone { registrations: 0 });
                },
            },
        ],
    },
];

/// The flow with this name, if there is one.
pub fn flow_named(name: &str) -> Option<&'static Flow> {
    FLOWS.iter().find(|f| f.name == name)
}

/// How long the assembled GIF runs, in centiseconds.
pub fn running_time(flow: &Flow) -> u32 {
    flow.steps.iter().map(|s| s.dwell.centiseconds()).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The recording writes `<flow>/NN-<step>.png` and a GIF named for the flow, so both
    /// halves of every name have to be a filename and unique among their siblings.
    #[test]
    fn every_name_is_a_usable_filename() {
        let ok = |s: &str| {
            !s.is_empty()
                && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        };
        let mut names: Vec<&str> = FLOWS.iter().map(|f| f.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), FLOWS.len(), "two flows share a name");
        for flow in FLOWS {
            assert!(ok(flow.name), "flow name {:?} is not a filename", flow.name);
            assert!(!flow.about.is_empty(), "{} says nothing about itself", flow.name);
            assert!(!flow.steps.is_empty(), "{} has no steps", flow.name);
            let mut steps: Vec<&str> = flow.steps.iter().map(|s| s.name).collect();
            steps.sort_unstable();
            steps.dedup();
            assert_eq!(steps.len(), flow.steps.len(), "{} names a step twice", flow.name);
            for step in flow.steps {
                assert!(ok(step.name), "{}/{:?} is not a filename", flow.name, step.name);
            }
        }
    }

    /// One geometry per flow, and a shipped one: a recording at a panel no board has is a
    /// picture of a layout nobody will ever see.
    #[test]
    fn every_flow_is_recorded_on_a_shipped_panel() {
        for flow in FLOWS {
            assert!(
                notyas_ui::layout::PANELS.contains(&flow.panel),
                "{} is recorded at {:?}, which no board ships",
                flow.name,
                flow.panel
            );
        }
    }

    /// [`eight_rolls`] takes the first eight of [`SIXES`] and calls it a notch of the meter,
    /// which is the same as any other eight only because they are all the same.
    #[test]
    fn the_sample_die_is_uniform() {
        assert_eq!(SIXES.len(), 64);
        assert!(SIXES.chars().all(|c| c == '6'), "the sample die is not 64 sixes any more");
    }

    /// A GIF nobody watches to the end illustrates nothing. The bound is generous - the
    /// signing flow traverses all ten review pages deliberately - and exists to catch a step
    /// list that grew without anybody adding up what it costs to sit through.
    #[test]
    fn no_recording_outstays_its_welcome() {
        for flow in FLOWS {
            let cs = running_time(flow);
            assert!(cs <= 2500, "{} runs for {}.{:02} s", flow.name, cs / 100, cs % 100);
        }
    }
}
