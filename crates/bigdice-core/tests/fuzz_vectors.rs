// Copyright (C) 2025-2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The differential fuzz corpus, run against the library pipeline.
//!
//! The desktop crate's `tests/cli_end_to_end.rs` runs the shipped `bigdice-cli` executable
//! per case and compares its `--json` output with `tests/vectors/fuzz_vectors.json` -
//! expectations produced by two independent implementations (iancoleman's own JS under
//! node, and python bip-utils) that agreed with each other before a value was written
//! down. This crate has no executable, so the driver is rewritten to call
//! [`Report::build`] directly - the same single pipeline the desktop CLI's JSON renderer
//! reads its fields from - and compares the same fields.
//!
//! Not portable from the CLI harness, and therefore not covered here (see PORTING.md):
//! exit codes, stderr wording, the ASCII-only promise of the process streams, the
//! `--dice-file` / `--dice` equivalence, and byte-identity of the rendered JSON document.
//! Every derived VALUE the corpus records is compared.

use bigdice_core::bip39::MnemonicMode;
use bigdice_core::derive::{ChildIndex, Scheme};
use bigdice_core::entropy;
use bigdice_core::report::{BuildError, Parameters, Report};
use bitcoin::Network;
use serde_json::Value;

const FUZZ_VECTORS: &str = include_str!("vectors/fuzz_vectors.json");

/// Rows per scheme in the corpus (`params.rows_per_scheme`), asserted below so a
/// regenerated vector file that changes it cannot silently compare zero rows.
const ROWS_PER_SCHEME: usize = 3;

fn field<'a>(value: &'a Value, key: &str, context: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{context}: `{key}` is missing or not a string"))
}

fn number(value: &Value, key: &str, context: &str) -> u64 {
    value[key]
        .as_u64()
        .unwrap_or_else(|| panic!("{context}: `{key}` is missing or not a number"))
}

/// The corpus is generated for the desktop CLI's defaults: raw mode, mainnet, empty
/// passphrase, account 0, change 0, all four schemes, three rows each. `params` in the
/// file records that; this is its library-side transcription, asserted against the file
/// before anything is compared.
fn corpus_parameters() -> Parameters<'static> {
    Parameters {
        mode: MnemonicMode::Raw,
        passphrase: "",
        network: Network::Bitcoin,
        schemes: &Scheme::ALL,
        account: ChildIndex::ZERO,
        change: ChildIndex::ZERO,
        count: ROWS_PER_SCHEME as u32,
        script_type: 0,
    }
}

/// The whole corpus: run the pipeline once per case and compare every recorded field.
#[test]
fn pipeline_output_matches_the_fuzz_corpus() {
    let doc: Value = serde_json::from_str(FUZZ_VECTORS).expect("fuzz vector file is not JSON");
    let params = &doc["params"];
    assert_eq!(field(params, "words", "params"), "raw");
    assert_eq!(field(params, "network", "params"), "mainnet");
    assert_eq!(field(params, "passphrase", "params"), "");
    assert_eq!(number(params, "account", "params"), 0);
    assert_eq!(number(params, "change", "params"), 0);
    assert_eq!(
        number(params, "rows_per_scheme", "params") as usize,
        ROWS_PER_SCHEME
    );

    let vectors = doc["vectors"]
        .as_array()
        .expect("`vectors` is not an array");
    assert!(vectors.len() >= 10, "the fuzz corpus was trimmed");

    let build_params = corpus_parameters();
    for vector in vectors {
        let id = field(vector, "id", "vector");
        let dice = entropy::parse_dice(field(vector, "input", id));
        let report = Report::build(&dice, &build_params)
            .unwrap_or_else(|err| panic!("{id}: pipeline refused the input: {err}"));

        let want = &vector["expected"];
        compare_case(id, &report, want);
    }
}

fn compare_case(id: &str, got: &Report, want: &Value) {
    assert_eq!(
        got.events as u64,
        number(want, "events", id),
        "{id}: events"
    );
    assert_eq!(got.clean, field(want, "clean", id), "{id}: clean");
    assert_eq!(got.binary, field(want, "binary", id), "{id}: binary");
    assert_eq!(
        got.total_bits as u64,
        number(want, "bits", id),
        "{id}: bits"
    );
    assert_eq!(
        got.bits_used as u64,
        number(want, "bits_used", id),
        "{id}: bits_used"
    );

    assert_eq!(got.mode, MnemonicMode::Raw, "{id}: mode");
    assert_eq!(
        got.words.len() as u64,
        number(want, "word_count", id),
        "{id}: word count"
    );
    assert_eq!(
        got.phrase.as_str(),
        field(want, "phrase", id),
        "{id}: phrase"
    );
    assert_eq!(
        got.entropy_hex,
        field(want, "entropy_hex", id),
        "{id}: entropy hex"
    );
    // `words` must be exactly `phrase` split on spaces, or the two views disagree.
    assert_eq!(
        got.words.join(" "),
        field(want, "phrase", id),
        "{id}: words vs phrase"
    );

    assert_eq!(got.seed_hex, field(want, "seed_hex", id), "{id}: seed");
    assert_eq!(
        got.root_xprv,
        field(want, "root_xprv", id),
        "{id}: root xprv"
    );

    let expected_schemes = want["schemes"].as_object().expect("expected schemes");
    assert_eq!(
        got.schemes.len(),
        expected_schemes.len(),
        "{id}: scheme count (Scheme::ALL)"
    );
    for scheme in &got.schemes {
        let name = scheme.scheme.name();
        let context = format!("{id}/{name}");
        let want = expected_schemes
            .get(name)
            .unwrap_or_else(|| panic!("{context}: scheme missing from the corpus"));
        let account = &scheme.derived.account;
        assert_eq!(
            account.path,
            field(want, "account_path", &context),
            "{context}: account path"
        );
        assert_eq!(
            account.xprv,
            field(want, "xprv", &context),
            "{context}: account xprv"
        );
        assert_eq!(
            account.xpub,
            field(want, "xpub", &context),
            "{context}: account xpub"
        );
        // Compared as options so `null` for bip44/bip86 is an assertion, not a skip.
        assert_eq!(
            account.slip132_prv.as_deref(),
            want["slip132_prv"].as_str(),
            "{context}: slip132_prv (null for bip44 and bip86)"
        );
        assert_eq!(
            account.slip132_pub.as_deref(),
            want["slip132_pub"].as_str(),
            "{context}: slip132_pub (null for bip44 and bip86)"
        );

        let want_rows = want["rows"].as_array().expect("expected rows");
        assert_eq!(
            scheme.derived.rows.len(),
            ROWS_PER_SCHEME,
            "{context}: row count"
        );
        assert_eq!(
            scheme.derived.rows.len(),
            want_rows.len(),
            "{context}: row count"
        );
        for (index, (got, want)) in scheme.derived.rows.iter().zip(want_rows).enumerate() {
            let context = format!("{context}/row{index}");
            assert_eq!(got.path, field(want, "path", &context), "{context}: path");
            assert_eq!(
                got.address,
                field(want, "address", &context),
                "{context}: address"
            );
            assert_eq!(
                got.pubkey,
                field(want, "pubkey", &context),
                "{context}: pubkey"
            );
            assert_eq!(got.wif, field(want, "wif", &context), "{context}: wif");
        }
    }
}

/// The corpus cases that must be refused: too few dice bits to fill one 32-bit block.
///
/// The desktop test asserts a clean usage exit of the executable; here the same refusal is
/// the pipeline's error value. An input whose few bits came from real rolls is
/// `NotEnoughEntropy` carrying the bit count; an input with no rolls at all would be
/// `NoRolls`, and the corpus is checked to actually exercise the former.
#[test]
fn insufficient_entropy_vectors_are_refused() {
    let doc: Value = serde_json::from_str(FUZZ_VECTORS).expect("fuzz vector file is not JSON");
    let vectors = doc["negative_vectors"]
        .as_array()
        .expect("`negative_vectors` is not an array");
    assert!(vectors.len() >= 4, "the negative corpus was trimmed");

    let params = corpus_parameters();
    for vector in vectors {
        let id = field(vector, "id", "negative vector");
        let want = &vector["expected"];
        let dice = entropy::parse_dice(field(vector, "input", id));
        assert_eq!(
            dice.events() as u64,
            number(want, "events", id),
            "{id}: events"
        );
        assert_eq!(
            dice.binary().len() as u64,
            number(want, "bits", id),
            "{id}: bits"
        );

        let err = Report::build(&dice, &params)
            .err()
            .unwrap_or_else(|| panic!("{id}: the pipeline accepted an under-length input"));
        let expected = if dice.events() == 0 {
            BuildError::NoRolls
        } else {
            BuildError::Bip39(bigdice_core::bip39::Bip39Error::NotEnoughEntropy {
                bits: dice.binary().len(),
            })
        };
        assert_eq!(err, expected, "{id}: refusal kind");
    }
}
