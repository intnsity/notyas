// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The sample data every consumer of this crate shares.
//!
//! One copy on purpose. The docs pictures, the gate and the unit tests are supposed to be
//! statements about the same thing; a second `dummy_verify_info` in a second crate would
//! drift, and the pictures would quietly stop being evidence about what is under gate.
//!
//! # What the values are (all of it public, none of it a real seed)
//!
//! - Dice: 64 sixes. A six maps to digit 0 (SPEC step 2), so RAW mode yields the
//!   all-zeros 128-bit entropy - the canonical BIP39 test vector #1, whose mnemonic is
//!   the world's best-known phrase ("abandon" x11 + "about"). Deliberate: the rendered
//!   words are instantly recognizable as the published test vector and useless as a
//!   wallet.
//! - Passphrase: "TREZOR", the official BIP39 test-vector passphrase, so the schemes
//!   screen shows exactly the keys any implementer can cross-check against the
//!   published vectors.
//! - Verify screen: placeholder values, every one carrying the marker "DUMMY" (the
//!   firmware fills the real ones from hardware). See [`dummy_verify_info`].

use notyas_core::bitcoin::absolute::LockTime;
use notyas_core::bitcoin::secp256k1::PublicKey;
use notyas_core::bitcoin::{Amount, OutPoint, ScriptBuf};
use notyas_core::derive::{Account, ChildIndex, Scheme};
use notyas_core::report::{Parameters, Report};
use notyas_ui::{
    AmountProof, Artifact, BackupState, Bit, BlankSpan, CardListing, Claim, ClaimedKey,
    CosignerRow, FileKind, FileRow, FormatTarget, HexValue, InputFacts, KeyBlockInfo, LockInfo,
    Network,
    OutputFacts, OutputRole, Owner, PartitionRow, PassphraseState, RefusalCode, RefusalNotice,
    RegionDigest,
    RegistrationInfo, RegistrationReview, ReservedSpace, ReviewedFee, ScriptKind, SetBytes,
    SignedTx, StoreStatus, TxReview, VerifyInfo, WalletInfo, WalletKind, WalletRow, ADDRESS_ROWS,
    VERSION,
};

/// The all-zero-entropy dice input; see the module docs.
pub const SIXES: &str =
    "6666666666666666666666666666666666666666666666666666666666666666";

/// The first eleven words of BIP39 test vector #1 - the phrase 64 sixes produce - so the
/// final-word helper is rendered against the seed the rest of this catalogue already
/// shows.
pub const ELEVEN_SIXES_WORDS: &str = "abandon abandon abandon abandon abandon abandon abandon                                       abandon abandon abandon abandon";

/// Wallets for the post-unlock screens: three readable and one slot that did not decrypt,
/// so the list renders every row kind it has. Marked DUMMY like every other value this
/// simulator installs - nothing here was read off a device.
pub fn dummy_wallets() -> Vec<WalletRow> {
    let wallet = |slot: u8, name: &str, kind, backup, network| {
        WalletRow::Wallet(WalletInfo {
            slot,
            name: String::from(name),
            fingerprint: format!("dead{slot}eef"),
            path: String::from("m/84'/0'/0'"),
            script_type: String::from("native segwit"),
            kind,
            backup,
            network,
            registrations: 0,
            stored: true,
            passphrase: PassphraseState::None,
        })
    };
    vec![
        wallet(
            0,
            "DUMMY savings",
            WalletKind::SingleSig,
            BackupState::Verified(String::from("2026-08-14")),
            Network::Bitcoin,
        ),
        wallet(
            1,
            "DUMMY vault 2of3",
            WalletKind::Multisig,
            BackupState::Verified(String::new()),
            Network::Bitcoin,
        ),
        wallet(2, "DUMMY testing", WalletKind::SingleSig, BackupState::Unchecked, Network::Testnet),
        WalletRow::Unreadable { slot: 3 },
    ]
}

/// The Verify-screen values the tour installs (S-46; VERIFY.md 10).
///
/// Every free-text field is marked DUMMY and every digest is a recognisably fake byte
/// pattern, so no screenshot of this screen can be mistaken for a reading taken off real
/// hardware. The version is COMPOSED from the crate version rather than written out: a
/// literal "0.1.0-DUMMY" survives a release bump silently, and the screenshot then shows a
/// version the tree has not been at since. That is the whole failure mode of this screen -
/// it exists to report what the running build actually is - so the simulator's stand-in
/// tracks the same constant the real screen reads ([`notyas_ui::VERSION`]).
///
/// A field ADDED to `VerifyInfo` cannot go stale here the same way: this is an exhaustive
/// struct literal with no `..Default::default()`, so a new field is a compile error in
/// this file rather than a screenshot that quietly omits a row. Keep it that way.
///
/// The eFuse posture is a DEV BOARD as one reads today - secure boot off, every download
/// path open, one key block carrying the sealing ladder's `HMAC_UP` - because that is the
/// honest worst case and the state most readers will meet first.
pub fn dummy_verify_info() -> VerifyInfo {
    // Obviously-fake hex: no real digest is a repeating byte, and `de ad be ef` reads as
    // a placeholder to anyone who would otherwise try to compare it against a release.
    let fake = |byte: &str| HexValue::Read(byte.repeat(32));
    VerifyInfo {
        board: Some("DUMMY simulator (no hardware)".into()),
        chip: Some("ESP32-P4".into()),
        chip_revision: Some("v1.3".into()),
        boot_rom: Some("eco 2".into()),
        rom_chip_id: Some("0x12".into()),
        mac: Some("de:ad:be:ef:00:01".into()),
        die_unique_id: HexValue::Read("da".repeat(16)),

        firmware_version: Some(format!("{VERSION}-DUMMY")),
        idf_app: Some("DUMMY host render".into()),
        idf_bootloader: Some("DUMMY host render".into()),
        rollback_image: Some("0".into()),
        rollback_efuse: Some("0".into()),
        firmware_digest: fake("de"),
        app: Some(RegionDigest {
            offset: 0x0001_0000,
            len: 1_842_176,
            sha256: "de".repeat(32),
        }),
        bootloader: Some(RegionDigest {
            offset: 0x0000_2000,
            len: 22_352,
            sha256: "ad".repeat(32),
        }),
        partition_table: Some(RegionDigest {
            offset: 0x0000_8000,
            len: 128,
            sha256: "be".repeat(32),
        }),

        flash_size_header: Some("32 MB".into()),
        flash_size_detected: Some("32 MB".into()),
        jedec_id: Some("c8 40 19".into()),
        flash_unique_id: Some("dead beef dead beef".into()),
        partitions: vec![
            PartitionRow {
                name: "factory".into(),
                kind: "app/fact".into(),
                offset: 0x0001_0000,
                size: 14_614_528,
                encrypted: false,
            },
            PartitionRow {
                name: "wallets".into(),
                kind: "data/0x40".into(),
                offset: 0x00E0_0000,
                size: 262_144,
                encrypted: true,
            },
            PartitionRow {
                name: "counters".into(),
                kind: "data/0x41".into(),
                offset: 0x00E4_0000,
                size: 16_384,
                encrypted: false,
            },
        ],
        // On demand, never at boot (ratified Q57): the screen opens saying the device has
        // not looked, which is the state every reader meets first.
        reserved_space: ReservedSpace::NotScanned,
        wallets_digest: fake("ef"),
        counters_digest: fake("ba"),

        secure_boot: Bit::Clear,
        aggressive_revoke: Bit::Clear,
        key_digests: [HexValue::NotBurned, HexValue::NotBurned, HexValue::NotBurned],
        flash_encryption: Bit::Clear,
        encryption_mode: Some("DISABLED".into()),
        crypt_count: Some(0),
        xts_key_read_protected: Bit::Absent,
        manual_encrypt: Bit::Set,
        uart_download: Bit::Set,
        secure_download: Bit::Clear,
        usb_serial_jtag_download: Bit::Set,
        usb_otg_download: Bit::Set,
        forced_download: Bit::Set,
        direct_boot: Bit::Set,
        jtag_pad: Bit::Set,
        jtag_usb: Bit::Set,
        jtag_soft: Some((0, 3)),
        jtag_select: Bit::Clear,
        rom_log: Some(0),
        rom_log_usb: Bit::Set,
        key_blocks: (0..6)
            .map(|i| KeyBlockInfo {
                purpose: (i == 5).then(|| String::from("HMAC_UP")),
                read_protected: i == 5,
                write_protected: i == 5,
            })
            .collect(),

        boot_count: Some(1240),
        acknowledged_at: Some(1235),
        wipe_epoch: Some(0),
        storage: Some("DUMMY - present".into()),

        radio_gpio: Some(54),
        radio: Some("DUMMY - low (C6 held in reset)".into()),
        radio_ok: true,
        self_test: Some("DUMMY - 6/6 passed".into()),
        self_test_ok: true,
    }
}

/// A finished reserved-space scan, for the frame that shows what `[ Scan ]` produces: one
/// span with bytes in it, so the screenshot carries the case a reader needs to recognise
/// rather than only the quiet one.
pub fn dummy_flash_scan() -> ReservedSpace {
    ReservedSpace::Scanned {
        spans: vec![
            BlankSpan { start: 0x00_0000, end: 0x00_2000, set: None },
            BlankSpan { start: 0x00_8080, end: 0x01_0000, set: None },
            BlankSpan {
                start: 0x1d_1c00,
                end: 0xe0_0000,
                set: Some(SetBytes { count: 4096, first: 0x01d_2000 }),
            },
            BlankSpan { start: 0xe4_4000, end: 0x200_0000, set: None },
        ],
        digest: HexValue::Read("ce".repeat(32)),
    }
}

/// The DUMMY device's name, named so a recipe that has to CLEAR the field can count the
/// characters it is deleting rather than restating the string.
pub const DUMMY_DEVICE_NAME: &str = "DUMMY kitchen-desk";

/// The lock and PIN screens' values for the tour. A device WITH a PIN, because the tour
/// exists to render the screens and the lock screen only exists on such a device (R20).
pub fn dummy_lock_info() -> LockInfo {
    LockInfo {
        status: StoreStatus::Locked,
        device_name: DUMMY_DEVICE_NAME.into(),
        attempts_left: Some(9),
        wipe_after: Some(15),
        // The floor this DUMMY device was formatted at. The firmware reads it from the
        // store's policy; the simulator has no store, so it states the ratified 4
        // (PIN-MODES.md, decided 2026-08-17) - the value a real device carries by default,
        // and the one whose frames a reader needs to see, since it is the floor the PIN
        // screen enables Unlock at.
        min_pin_len: 4,
        // DUMMY shape: the wipe-policy screen prices guessing from the PIN actually set,
        // so the tour has to state one. Six digits is a common choice above the floor,
        // which makes it the shape whose arithmetic a reader most needs to see.
        pin: Some(notyas_ui::PinShape { len: 6, alphabet: notyas_ui::PinShape::DIGITS }),
        unlock_ms: notyas_ui::UNLOCK_MS_M1,
    }
}

// ---------------------------------------------------------------------------------------
// The multisig registry (S-41, S-42, S-43)
// ---------------------------------------------------------------------------------------

/// Three published BIP-32 test-vector account keys.
///
/// Real xpubs, so the cosigner pages render values of exactly the length and shape the
/// device meets - which is what those pages are measured against - and worthless as keys,
/// like every other value in this file. The names beside them carry the DUMMY marker.
pub const DUMMY_XPUBS: [&str; 3] = [
    "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
    "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
    "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
];

/// The BIP-173 example P2WSH address. Published, and nobody's.
pub const DUMMY_MULTISIG_ADDRESS: &str =
    "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";

/// The registration's label. Lower case and short on purpose: it is the word the C4d delete
/// sheet asks to be typed back, and a frame that types it has to be able to reach every
/// character from the keyboard page the sheet opens on.
pub const DUMMY_MULTISIG_NAME: &str = "dummy vault";

const DUMMY_MULTISIG_PATH: &str = "m/48'/0'/0'/2'";

/// The registry as S-41 lists it: one registration that proved out, and one slot that did
/// not - so the screen renders both row kinds it has.
pub fn dummy_registrations() -> Vec<RegistrationInfo> {
    vec![
        RegistrationInfo {
            slot: 0,
            name: String::from(DUMMY_MULTISIG_NAME),
            threshold: 2,
            cosigners: 3,
            script: String::from("P2WSH"),
            derivation: String::from(DUMMY_MULTISIG_PATH),
            fingerprint: String::from("a1b2c300"),
            network: Network::Bitcoin,
            proven: true,
        },
        RegistrationInfo {
            slot: 1,
            name: String::new(),
            threshold: 0,
            cosigners: 0,
            script: String::new(),
            derivation: String::new(),
            fingerprint: String::new(),
            network: Network::Bitcoin,
            proven: false,
        },
    ]
}

/// A 2-of-3 P2WSH registration waiting for approval, with this device as cosigner `ours`.
///
/// `ours` is a parameter because the frame that matters most on S-42 is the one where the
/// set does NOT name this device: the review is then a refusal, and a picture of it is the
/// picture of the 2021 substitution attack being stopped.
pub fn dummy_registration_review(ours: u8) -> RegistrationReview {
    let cosigners = (0..3usize)
        .map(|i| CosignerRow {
            fingerprint: format!("a1b2c3{i:02}"),
            path: String::from(DUMMY_MULTISIG_PATH),
            xpub: String::from(DUMMY_XPUBS[i]),
            ours: i + 1 == usize::from(ours),
        })
        .collect();
    let keys: Vec<String> = (0..3usize)
        .map(|i| format!("[a1b2c3{i:02}/48h/0h/0h/2h]{}/<0;1>/*", DUMMY_XPUBS[i]))
        .collect();
    RegistrationReview {
        name: String::from(DUMMY_MULTISIG_NAME),
        threshold: 2,
        policy: String::from("sortedmulti"),
        script: String::from("P2WSH (native segwit)"),
        derivation: String::from(DUMMY_MULTISIG_PATH),
        network: Network::Bitcoin,
        cosigners,
        ours,
        first_address: String::from(DUMMY_MULTISIG_ADDRESS),
        descriptor: format!("wsh(sortedmulti(2,{}))#8zl0zxma", keys.join(",")),
        converted: false,
        duplicate: false,
    }
}

/// What the registration is once it is stored, as S-43 reads it back.
pub fn dummy_saved_registration() -> RegistrationInfo {
    dummy_registrations()[0].clone()
}

/// A card holding the file the registry imports from, plus one it will not read.
pub fn dummy_multisig_card() -> CardListing {
    let row = |name: &str, kind, len, oversize| FileRow {
        name: String::from(name),
        kind,
        len,
        modified: String::from("17 Aug 14:02"),
        oversize,
    };
    CardListing {
        dir: String::new(),
        rows: vec![
            row("dummy-vault-2of3.txt", FileKind::Text, 640, false),
            row("dummy-export.json", FileKind::Json, 2_100_000, true),
            row("wallets", FileKind::Directory, 0, false),
        ],
        truncated: false,
        rejected: 0,
    }
}

// ---------------------------------------------------------------------------------------
// The transaction path (S-27..S-38)
// ---------------------------------------------------------------------------------------

/// BIP39 test vector #1, which is what 64 sixes produce. The world's best-known phrase and
/// worthless as a wallet, so a derivation from it is safe to render and safe to publish.
pub const SIXES_PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
     about";

/// The derivation the embedder hands a STORED wallet it has just unsealed.
///
/// Real, not a stub: `Ui::wallet_opened_with_keys` takes a `Report` and the wallet home
/// gates Sign and Export on holding one, so a frame that wanted a stub would be a frame
/// about a screen state the device cannot produce. The phrase is the published test vector,
/// so every key it yields is one an implementer can cross-check.
pub fn dummy_report() -> Report {
    Report::from_phrase(
        SIXES_PHRASE,
        &Parameters {
            mode: notyas_core::bip39::MnemonicMode::Raw,
            passphrase: "",
            network: Network::Bitcoin,
            schemes: &Scheme::ALL,
            account: ChildIndex::ZERO,
            change: ChildIndex::ZERO,
            count: ADDRESS_ROWS,
            script_type: 2,
        },
    )
    .expect("the published test vector derives")
}

/// A card holding exactly one transaction: S-27's "ready to sign" state.
pub fn dummy_single_psbt_card() -> CardListing {
    CardListing {
        dir: String::new(),
        rows: vec![psbt_row("dummy-spend-2026-08-17.psbt", 2_600)],
        truncated: false,
        rejected: 0,
    }
}

/// A card holding more than one: the state that sends S-27 to the picker.
///
/// Every row kind S-28 draws is here, including the two it will not offer - a file over the
/// transfer cap and a directory - because a picker that only ever renders openable rows is a
/// picker whose refusals have never been seen.
pub fn dummy_psbt_card() -> CardListing {
    CardListing {
        dir: String::new(),
        // Directories first, then by name: the order `notyas_wallet::sd` sorts a listing
        // into, because the row a user taps has to be a function of what they were shown
        // rather than of the order whoever wrote the card chose.
        rows: vec![
            FileRow {
                name: String::from("bundles"),
                kind: FileKind::Directory,
                len: 0,
                modified: String::from("17 Aug 09:31"),
                oversize: false,
            },
            psbt_row("dummy-consolidate.psbt", 41_000),
            psbt_row("dummy-huge.psbt", 2_100_000),
            psbt_row("dummy-spend-2026-08-17.psbt", 2_600),
        ],
        truncated: false,
        rejected: 2,
    }
}

/// A card with more rows than one viewport holds, so the pager exists and can be used.
pub fn dummy_long_psbt_card() -> CardListing {
    CardListing {
        dir: String::new(),
        rows: (0..40).map(|i| psbt_row(&format!("dummy-batch-{i:03}.psbt"), 2_600 + i)).collect(),
        truncated: true,
        rejected: 0,
    }
}

/// A directory with nothing in it: the picker's own empty state.
pub fn dummy_empty_card(dir: &str) -> CardListing {
    CardListing {
        dir: String::from(dir),
        rows: Vec::new(),
        truncated: false,
        rejected: 0,
    }
}

fn psbt_row(name: &str, len: u32) -> FileRow {
    FileRow {
        name: String::from(name),
        kind: FileKind::Psbt,
        len,
        modified: String::from("17 Aug 14:02"),
        // The row for a file over the cap is DRAWN and not offered, which is why the
        // fixture carries one: hiding a file the user can see on the card is how a picker
        // sends someone hunting for a transaction that is right there.
        oversize: len > 1_048_576,
    }
}

/// Which of the three shapes a review fixture is in.
///
/// One transaction in three states rather than three transactions, so every page index is
/// the same in all of them and a frame recipe reads as "page 5" rather than as arithmetic
/// over a fixture. The three are the ones the review screen renders DIFFERENTLY, and each is
/// a different thing the user is being told.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ReviewShape {
    /// Every amount proven against its own previous transaction. The ordinary spend.
    Proven,
    /// One input's amount is the file's word, so the fee is a lower bound and every number
    /// derived from it says so.
    Stated,
    /// An output claims to be change and the device could not prove it (R-03). It counts as
    /// money leaving, and the hold is not offered at all.
    ClaimedChange,
}

/// A transaction under review: 3 inputs, 4 outputs, and therefore ten pages.
///
/// The outputs are one of each kind the screen has a badge for - a payment leaving, proven
/// change, a data output, and an address of this wallet that is NOT change - because the
/// badge vocabulary is frozen (UX-SCREENS S-32) and a picture of it is how it stays frozen.
pub fn dummy_tx_review(shape: ReviewShape) -> TxReview {
    let stated = shape == ReviewShape::Stated;
    // The Stated shape is a transaction this device signs NOTHING in, and that is not a
    // stylistic choice. The engine refuses a file where a signature of ours would sit beside
    // an amount nothing proves (`UnprovenAmountBesideOurSignature`, BIP-174's line 415
    // footnote), so an unenforced fee can only ever reach a screen on a file whose inputs
    // are all somebody else's: a cosigner's transaction, read here before another device
    // signs it.
    let inputs = if stated {
        vec![
            foreign(0, ScriptKind::P2wpkh, 1_400_000, AmountProof::ClaimedByFile),
            foreign(1, ScriptKind::P2wpkh, 600_000, AmountProof::ClaimedByFile),
            foreign(2, ScriptKind::P2tr, 250_000, AmountProof::ClaimedByFile),
        ]
    } else {
        vec![
            ours(0, ScriptKind::P2wpkh, 1_400_000, AmountProof::ProvenByPrevTx),
            ours(1, ScriptKind::P2wpkh, 600_000, AmountProof::ProvenByPrevTx),
            foreign(2, ScriptKind::P2tr, 250_000, AmountProof::ProvenByPrevTx),
        ]
    };
    let change = if shape == ReviewShape::ClaimedChange {
        OutputRole::ClaimedButUnproven
    } else {
        OutputRole::Change { owner: dummy_owner(), index: 7 }
    };
    let outputs = vec![
        out(0, 1_800_000, ScriptKind::P2wpkh, OutputRole::Payment),
        out(1, 400_000, ScriptKind::P2wpkh, change),
        out(2, 0, ScriptKind::OpReturn, OutputRole::Payment),
        out(3, 45_000, ScriptKind::P2wpkh, OutputRole::OwnNotChange { owner: dummy_owner(), index: 2 }),
    ];
    let fee = Amount::from_sat(5_000);
    let mut review = TxReview {
        inputs,
        outputs,
        input_total: Amount::from_sat(2_250_000),
        output_total: Amount::from_sat(2_245_000),
        fee: if stated { ReviewedFee::Stated(fee) } else { ReviewedFee::Enforced(fee) },
        lock_time: LockTime::ZERO,
        rbf_signaled: true,
        network: Network::Bitcoin,
        fingerprint: String::from("dead0eef"),
        wallet: String::from("DUMMY savings"),
        source: String::from("dummy-spend-2026-08-17.psbt"),
        signable_inputs: if stated { 0 } else { 2 },
        unknown_fields: 1,
        serialized_len: 2_600,
        psbt_id: String::from("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"),
        vsize: 312,
        vsize_exact: false,
        warnings: Vec::new(),
    };
    // The same predicates the firmware applies, over the same value: these frames are
    // pictures of the warnings page, so the page has to hold what the device would put
    // there rather than a list somebody typed.
    review.warnings = dummy_warnings(&review);
    review
}

/// The warnings the fixtures raise, spelled out here because `tools/uisim` cannot call the
/// firmware's own `flow::model` (different target, different crate).
///
/// Kept short and kept honest: each is one this device could actually decide from a single
/// inspection, and each is two lines - what it is, and why it matters.
fn dummy_warnings(review: &TxReview) -> Vec<notyas_ui::TxWarning> {
    let mut out = Vec::new();
    if review.unproven_amounts() > 0 {
        out.push(notyas_ui::TxWarning {
            headline: format!(
                "{} of {} input amounts are not proven.",
                review.unproven_amounts(),
                review.inputs.len()
            ),
            detail: String::from(
                "This device could not check them against the transactions the coins came \
                 from, so every total on this screen, the fee included, rests on the file's \
                 word.",
            ),
        });
    }
    let foreign: Vec<String> = review
        .inputs
        .iter()
        .filter(|i| matches!(i.claim, Claim::Foreign))
        .map(|i| i.index.to_string())
        .collect();
    if !foreign.is_empty() {
        let (subject, verb) = if foreign.len() == 1 { ("Input", "is") } else { ("Inputs", "are") };
        out.push(notyas_ui::TxWarning {
            headline: format!("{subject} {} {verb} not from this wallet.", foreign.join(", ")),
            detail: String::from(
                "This device will not sign them. Another signer has to, and the transaction \
                 is not finished until it does.",
            ),
        });
    }
    for o in &review.outputs {
        if matches!(o.role, OutputRole::OwnNotChange { .. }) {
            out.push(notyas_ui::TxWarning {
                headline: format!("Output {} pays an address of this wallet.", o.index),
                detail: String::from(
                    "It is not change, so the amount leaving counts it as money sent.",
                ),
            });
        }
    }
    out
}

/// What signing produced, as S-38 reads it.
///
/// `complete` is the multisig axis and the one the status card's second line turns on: a
/// transaction still waiting for a cosigner is not a transaction anybody can broadcast.
pub fn dummy_signed(complete: bool) -> SignedTx {
    SignedTx {
        signed_inputs: 2,
        verified_inputs: 2,
        signable_inputs: 2,
        complete,
        artifacts: vec![Artifact {
            name: String::from("dummy-spend-2026-08-17-signed.psbt"),
            bytes: 2_712,
        }],
        psbt_id: String::from("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"),
    }
}

/// A refusal, in the two shapes S-29 renders differently.
///
/// `after_signing` is the axis: a refusal that arrives before the hold sends the user back
/// to the file they chose, and one that arrives after it sends them to the wallet home and
/// adds that nothing was signed and nothing was written.
pub fn dummy_refusal(code: RefusalCode, after_signing: bool) -> RefusalNotice {
    let happened = match code {
        RefusalCode::MissingPrevTx => String::from(
            "Input 1 has no previous transaction to prove what it is worth, and signing \
             input 0 would not commit to it.",
        ),
        RefusalCode::ChangeNotProven => String::from(
            "Output 1 says it is change of this wallet and this device could not rebuild \
             the script it pays.",
        ),
        RefusalCode::SignatureCheckFailed => String::from(
            "A signature this device produced does not verify against a digest recomputed \
             from the file.",
        ),
        _ => String::from("This device will not sign this transaction."),
    };
    RefusalNotice {
        code,
        happened,
        details: format!(
            "check {} | DUMMY psbt 9f86d081 | firmware {VERSION}",
            code.code()
        ),
        after_signing,
    }
}

/// An input of the open wallet, with the amount proof it deserves.
fn ours(index: u16, kind: ScriptKind, sats: u64, proof: AmountProof) -> InputFacts {
    InputFacts {
        claim: Claim::Ours {
            path: "m/84'/0'/0'/0/0".parse().expect("a BIP-84 leaf parses"),
            key: ClaimedKey::Ecdsa(dummy_pubkey()),
        },
        ..foreign(index, kind, sats, proof)
    }
}

/// A coin this device cannot spend: somebody else's, beside ours or instead of them.
fn foreign(index: u16, kind: ScriptKind, sats: u64, proof: AmountProof) -> InputFacts {
    InputFacts {
        index,
        outpoint: OutPoint::null(),
        value: Amount::from_sat(sats),
        amount_proof: proof,
        script_pubkey: script_for(kind, index),
        redeem_script: None,
        kind,
        claim: Claim::Foreign,
        multisig: None,
        tap_merkle_root: None,
    }
}

fn out(index: u16, sats: u64, kind: ScriptKind, role: OutputRole) -> OutputFacts {
    OutputFacts {
        index,
        value: Amount::from_sat(sats),
        script_pubkey: script_for(kind, index),
        kind,
        claims_our_key: !matches!(role, OutputRole::Payment),
        role,
    }
}

/// A REAL script of the given kind, so the review screen can spell an address from it.
///
/// Real and not a filler run of bytes, because the screen falls back to script hex when
/// `Address::from_script` will not encode - which is honest behaviour and a poor picture:
/// the frames that document the review would show a hex dump where every device shows a
/// bech32 address. The key hash is the index repeated, which makes each output visibly
/// distinct and is plainly not anybody's key.
fn script_for(kind: ScriptKind, index: u16) -> ScriptBuf {
    let mut bytes = Vec::new();
    match kind {
        // OP_RETURN, then a 21-byte push of printable ASCII: the payload is rendered as
        // hex AND as text with a byte count, and never decoded into something that reads
        // like an instruction.
        ScriptKind::OpReturn => {
            bytes.push(0x6a);
            bytes.push(21);
            bytes.extend_from_slice(b"notyas DUMMY payload!");
        }
        // OP_0 <20-byte key hash>.
        _ => {
            bytes.push(0x00);
            bytes.push(20);
            bytes.extend(std::iter::repeat_n(0x10 + index as u8, 20));
        }
    }
    ScriptBuf::from(bytes)
}

/// The BIP-84 account of the published test vector, as an `Owner`.
///
/// Derived rather than assembled: an `AccountId` names an account only a seed can produce,
/// which is the whole of what check 3 rests on, and it has no public constructor for exactly
/// that reason.
fn dummy_owner() -> Owner {
    Owner::Account(
        Account::derive(
            &notyas_core::bip39::seed(SIXES_PHRASE, ""),
            Network::Bitcoin,
            Scheme::Bip84,
            ChildIndex::ZERO,
        )
        .expect("BIP-84 derives an account from the test vector")
        .id(),
    )
}

/// secp256k1's generator point: the one compressed public key that can be written down.
/// The fixtures need a claim to BE `Ours`, not a key that could spend anything.
fn dummy_pubkey() -> PublicKey {
    PublicKey::from_slice(&[
        0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
        0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16,
        0xF8, 0x17, 0x98,
    ])
    .expect("the generator point is a valid compressed key")
}

/// The card S-49's offer is rendered against: an ordinary factory-shipped SDXC card, which
/// ships exFAT and which this build's FatFs cannot mount. It is the exact case the feature
/// exists for, and the numbers are a real 32 GB card's.
pub fn dummy_format_target() -> FormatTarget {
    FormatTarget {
        partition: 1,
        capacity: String::from("32 GB"),
        word: String::from("32GB"),
        holds: String::from("an exFAT or NTFS filesystem"),
        volume: String::from("32 GB"),
    }
}
