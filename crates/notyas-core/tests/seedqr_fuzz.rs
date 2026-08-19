// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The SeedQR ingress fuzzer.
//!
//! The vector suite next door proves the decoder agrees with SeedSigner on nine seeds.
//! That is conformance, and conformance is not the property that matters here: the bytes
//! this parser reads are chosen by whoever printed the symbol, and the interesting
//! question is what it does with the payloads SeedSigner never published. Q48 attached
//! that as a condition when it ratified scan-in - "the `seedqr` decoder must be a fuzz
//! target, not only a conformance target ... brand-new code doing 11-bit unpacking on
//! attacker-supplied bytes".
//!
//! # Method
//!
//! The same method as notyas-wallet's power-loss fuzzer, for the same reason: the corpus
//! is enumerated, not sampled. Every case is a pure function of this file, so a failure is
//! a bug report rather than a seed nobody can reproduce, and the run gives the same answer
//! twice. Where a family needs a spread of byte values it takes them from [`mix`], a fixed
//! permutation of a counter - arithmetic on literals, not a random source; SECURITY
//! invariant 3 forbids an RNG anywhere in this tree, including transitively, and this
//! harness introduces none.
//!
//! # The invariants, and what each one protects
//!
//! | # | Invariant | Protects |
//! |---|-----------|----------|
//! | F1 | `decode` returns for every input; it never panics | the device stays up while a hostile symbol is in frame |
//! | F2 | one call allocates at most a fixed budget, and a payload refused on length allocates nothing at all | memory on a device with no room to spare |
//! | F3 | acceptance implies a BIP-39 checksum this harness recomputed itself | the accepted phrase is a real mnemonic |
//! | F4 | acceptance implies the payload re-encodes byte-for-byte from the accepted seed | the accepted phrase is THIS payload's mnemonic |
//! | F5 | only the four defined lengths are ever accepted | the ingress surface is the documented one |
//! | F6 | an accepted payload's format is the one `classify` names | no silent format confusion |
//! | F7 | `decode` is deterministic | a refusal cannot be retried into an acceptance |
//! | F8 | a refusal's reason matches the payload's shape | the user is told the truth about why |
//!
//! **F3, F4 and F5 together are the one that loses money.** Separately they are three
//! reasonable checks; together they say that `decode` accepts a payload if and only if it
//! is exactly the canonical encoding of a checksum-valid mnemonic in one of the two
//! defined formats. Nothing can be accepted that "looks like" a seed: not a digit stream
//! with a wrong checksum, not a digit stream with an out-of-range group reduced modulo
//! 2048, not a valid payload with a byte appended, and not a payload that decodes to some
//! other seed than the one it encodes. F3's recomputation is deliberately independent -
//! it uses `bitcoin::hashes`, a different SHA-256 implementation from the `sha2` one
//! [`notyas_core::bip39`] uses, and does its own 11-bit unpacking - so agreement means
//! two implementations agree rather than one implementation agreeing with itself.
//!
//! F2 is measured rather than argued: this binary installs a counting global allocator and
//! reads the bytes each call actually took.
//!
//! # The encoder
//!
//! Round-tripping needs an encoder, and under Q17 (SeedQR display-out declined) this
//! project ships none. So the encoder lives here, in test code, as the oracle - which is
//! also the honest place for it, because an oracle that shared code with the decoder would
//! only prove the decoder consistent with itself.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::panic::{catch_unwind, AssertUnwindSafe};

use notyas_core::bip39;
use notyas_core::seedqr::{self, Format, IngressError, Scan, ACCEPTED_LENGTHS, MAX_PAYLOAD_LEN};

// ---------------------------------------------------------------------------------------
// F2's instrument: a counting allocator
// ---------------------------------------------------------------------------------------

// Counters are thread-local rather than global because the test harness runs test
// functions on several threads at once and a global counter would report their sum. Each
// thread measures only what it allocated. `const`-initialized `Cell`s so that reading a
// counter from inside the allocator cannot itself allocate, and `try_with` so that an
// allocation during thread-local teardown is dropped rather than panicking inside `alloc`.
thread_local! {
    static LIVE: Cell<usize> = const { Cell::new(0) };
    static PEAK: Cell<usize> = const { Cell::new(0) };
    static TOTAL: Cell<usize> = const { Cell::new(0) };
}

struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = System.alloc(layout);
        if !pointer.is_null() {
            let _ = LIVE.try_with(|live| {
                let now = live.get().saturating_add(layout.size());
                live.set(now);
                let _ = PEAK.try_with(|peak| {
                    if now > peak.get() {
                        peak.set(now);
                    }
                });
                let _ = TOTAL.try_with(|total| total.set(total.get().saturating_add(layout.size())));
            });
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let _ = LIVE.try_with(|live| live.set(live.get().saturating_sub(layout.size())));
        System.dealloc(pointer, layout);
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// Peak live bytes and total bytes requested during `body`, on this thread.
///
/// `realloc` is not implemented above, so the default `GlobalAlloc::realloc` runs and its
/// alloc/dealloc pair is counted like any other - a decoder that grew a buffer by doubling
/// would show up in `total` even though `peak` stayed small.
fn measured<T>(body: impl FnOnce() -> T) -> (T, usize, usize) {
    LIVE.with(|live| live.set(0));
    PEAK.with(|peak| peak.set(0));
    TOTAL.with(|total| total.set(0));
    let out = body();
    (
        out,
        PEAK.with(|peak| peak.get()),
        TOTAL.with(|total| total.get()),
    )
}

/// F2's budget, in bytes, for one call on the longest accepted payload.
///
/// A budget, not a measurement: the point is that the number is a constant. The payload is
/// at most 96 bytes and the work is a 24-word phrase, a 256-character bit string and two
/// short vectors, so anything that scales with something else - a buffer sized from a
/// length field, a per-byte allocation, a doubling `Vec` - lands far outside this and
/// fails. The current run reports its real peak in the summary; if that ever approaches
/// this number, find out what changed rather than raising it.
const ALLOC_PEAK_BUDGET: usize = 8 * 1024;
const ALLOC_TOTAL_BUDGET: usize = 16 * 1024;

// ---------------------------------------------------------------------------------------
// The oracle: an encoder that shares no code with the decoder (Q17 keeps it out of the crate)
// ---------------------------------------------------------------------------------------

/// Words to a Standard SeedQR payload: each index as exactly four zero-padded digits.
fn encode_standard(words: &[&str]) -> Vec<u8> {
    let list = bip39::wordlist();
    let mut out = Vec::with_capacity(words.len() * 4);
    for word in words {
        let index = list
            .iter()
            .position(|candidate| candidate == word)
            .expect("an accepted phrase is made of wordlist words");
        out.extend_from_slice(format!("{index:04}").as_bytes());
    }
    out
}

/// Entropy to a CompactSeedQR payload.
///
/// The identity function, and that is the whole content of the format: "we can directly
/// encode the relevant bits that determine our mnemonic seed phrase", checksum omitted. It
/// is written out as a function anyway so that F4 reads the same for both formats and so
/// that this file states, in code, what the compact payload is.
fn encode_compact(entropy: &[u8]) -> Vec<u8> {
    entropy.to_vec()
}

/// An independent BIP-39 verifier: 11-bit unpacking and a checksum, using `bitcoin::hashes`
/// rather than the `sha2` the crate under test uses.
///
/// Returns the entropy the phrase encodes, or `None` if the checksum does not hold.
fn independently_verify(phrase: &str) -> Option<Vec<u8>> {
    use bitcoin::hashes::{sha256, Hash};

    let list = bip39::wordlist();
    let words: Vec<&str> = phrase.split(' ').collect();
    if words.is_empty() || words.len() % 3 != 0 {
        return None;
    }

    let mut bits = Vec::with_capacity(words.len() * 11);
    for word in &words {
        let index = list.iter().position(|candidate| candidate == word)?;
        for shift in (0..11).rev() {
            bits.push(u8::from((index >> shift) & 1 == 1));
        }
    }

    let entropy_bits = words.len() * 11 - words.len() / 3;
    if entropy_bits % 8 != 0 {
        return None;
    }
    let entropy: Vec<u8> = bits[..entropy_bits]
        .chunks(8)
        .map(|chunk| chunk.iter().fold(0u8, |acc, &bit| (acc << 1) | bit))
        .collect();

    let digest = sha256::Hash::hash(&entropy).to_byte_array();
    for (i, bit) in bits[entropy_bits..].iter().enumerate() {
        if *bit != (digest[i / 8] >> (7 - i % 8)) & 1 {
            return None;
        }
    }
    Some(entropy)
}

// ---------------------------------------------------------------------------------------
// Corpus generation: a fixed permutation of a counter, not a random source
// ---------------------------------------------------------------------------------------

/// SplitMix64's finalizer over a counter. Deterministic, dependency-free, and used only to
/// spread byte values across the corpus - never as entropy for anything, which SECURITY
/// invariant 3 would forbid.
fn mix(counter: u64) -> u64 {
    let mut z = counter.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn mixed_bytes(seed: u64, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (mix(seed ^ (i as u64).wrapping_mul(0x2545_f491_4f6c_dd1d)) >> 24) as u8)
        .collect()
}

// ---------------------------------------------------------------------------------------
// Findings and the report
// ---------------------------------------------------------------------------------------

/// A failure named precisely enough to reproduce: the family that generated the case, the
/// invariant it broke and the exact payload, in hex.
#[derive(Clone, Debug)]
struct Finding {
    family: &'static str,
    invariant: &'static str,
    payload: String,
    detail: String,
}

#[derive(Clone, Debug, Default)]
struct Report {
    cases: u64,
    accepted: u64,
    refused: u64,
    /// Highest peak-live and total-requested allocation any single call took.
    peak_alloc: usize,
    total_alloc: usize,
    findings: Vec<Finding>,
}

impl Report {
    fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }

    /// One line per (family, invariant) pair with a count and the first payload that
    /// reproduces it. A single defect fires for thousands of consecutive cases, and a
    /// report that printed all of them would bury the second defect under the first.
    fn grouped(&self) -> Vec<String> {
        let mut keys: Vec<(&'static str, &'static str)> = Vec::new();
        for finding in &self.findings {
            let key = (finding.family, finding.invariant);
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
        keys.into_iter()
            .map(|(family, invariant)| {
                let hits: Vec<&Finding> = self
                    .findings
                    .iter()
                    .filter(|f| f.family == family && f.invariant == invariant)
                    .collect();
                let first = hits[0];
                format!(
                    "{family} / {invariant}: {} case(s), first at payload {}: {}",
                    hits.len(),
                    first.payload,
                    first.detail
                )
            })
            .collect()
    }

    fn summary(&self) -> String {
        format!(
            "{} cases ({} accepted, {} refused), {} findings; worst call took {} peak / {} \
             total bytes against a {} / {} budget",
            self.cases,
            self.accepted,
            self.refused,
            self.findings.len(),
            self.peak_alloc,
            self.total_alloc,
            ALLOC_PEAK_BUDGET,
            ALLOC_TOTAL_BUDGET,
        )
    }

    fn fail(&mut self, family: &'static str, invariant: &'static str, payload: &[u8], detail: String) {
        self.findings.push(Finding {
            family,
            invariant,
            payload: hex::encode(payload),
            detail,
        });
    }
}

// ---------------------------------------------------------------------------------------
// The case: one payload, every invariant
// ---------------------------------------------------------------------------------------

/// Run one payload through `decode` and assert F1..F8 against the result.
fn case(family: &'static str, payload: &[u8], report: &mut Report) {
    report.cases += 1;

    // F1. A panic is recorded and the run continues, so one hostile input does not hide
    // the rest of the corpus. `AssertUnwindSafe` is sound here because the payload is a
    // shared slice and nothing is mutated across the boundary.
    let (outcome, peak, total) = measured(|| catch_unwind(AssertUnwindSafe(|| seedqr::decode(payload))));
    let result = match outcome {
        Ok(result) => result,
        Err(_) => {
            report.fail(family, "F1 no panic", payload, "decode panicked".to_string());
            return;
        }
    };

    // F2. Measured, both as peak live bytes and as total bytes requested.
    report.peak_alloc = report.peak_alloc.max(peak);
    report.total_alloc = report.total_alloc.max(total);
    if peak > ALLOC_PEAK_BUDGET || total > ALLOC_TOTAL_BUDGET {
        report.fail(
            family,
            "F2 bounded allocation",
            payload,
            format!("{peak} peak / {total} total bytes for a {}-byte payload", payload.len()),
        );
    }
    // The sharper half of F2: a payload refused for its length must not have allocated at
    // all, because the length check is the first statement in `decode`. This is what makes
    // a megabyte-long symbol free rather than merely bounded.
    if payload.len() > MAX_PAYLOAD_LEN && total != 0 {
        report.fail(
            family,
            "F2 bounded allocation",
            payload,
            format!("{total} bytes allocated before the length refusal"),
        );
    }

    // F7. Same bytes, same answer.
    let again = seedqr::decode(payload);
    let same = match (&result, &again) {
        (Ok(first), Ok(second)) => {
            first.format == second.format
                && first.mnemonic.phrase().as_str() == second.mnemonic.phrase().as_str()
        }
        (Err(first), Err(second)) => first == second,
        _ => false,
    };
    if !same {
        report.fail(
            family,
            "F7 determinism",
            payload,
            "two calls disagreed".to_string(),
        );
    }

    match result {
        Ok(scan) => {
            report.accepted += 1;
            accepted_case(family, payload, &scan, report);
        }
        Err(error) => {
            report.refused += 1;
            refused_case(family, payload, error, report);
        }
    }
}

fn accepted_case(family: &'static str, payload: &[u8], scan: &Scan, report: &mut Report) {
    let phrase = scan.mnemonic.phrase();

    // F5. Only the four defined lengths.
    if !ACCEPTED_LENGTHS.contains(&payload.len()) {
        report.fail(
            family,
            "F5 length",
            payload,
            format!("accepted a payload of {} bytes", payload.len()),
        );
    }

    // F6. The format the classifier names is the format that was decoded.
    if seedqr::classify(payload) != Some(scan.format) {
        report.fail(
            family,
            "F6 format",
            payload,
            format!(
                "decoded as {} but classified as {:?}",
                scan.format,
                seedqr::classify(payload)
            ),
        );
    }

    // F3. An independent verifier's checksum, and an independent unpacking of the words
    // back to entropy.
    match independently_verify(&phrase) {
        None => report.fail(
            family,
            "F3 checksum",
            payload,
            "accepted a phrase whose BIP-39 checksum this harness could not verify".to_string(),
        ),
        Some(entropy) if entropy != scan.mnemonic.entropy => report.fail(
            family,
            "F3 checksum",
            payload,
            "the accepted words do not unpack to the accepted entropy".to_string(),
        ),
        Some(_) => {}
    }

    // F4. Re-encode from the accepted seed and require the original bytes back. This is
    // what rules out an accepted payload that decodes to some other seed than the one it
    // encodes - a dropped bit, a swapped group, a trimmed byte.
    let words: Vec<&str> = phrase.split(' ').collect();
    let reencoded = match scan.format {
        Format::Standard => encode_standard(&words),
        Format::Compact => encode_compact(&scan.mnemonic.entropy),
    };
    if reencoded != payload {
        report.fail(
            family,
            "F4 round trip",
            payload,
            format!("re-encodes to {}", hex::encode(&reencoded)),
        );
    }
}

fn refused_case(family: &'static str, payload: &[u8], error: IngressError, report: &mut Report) {
    // F8. The reason must match the payload's shape, so a user is not told "wrong length"
    // about a payload of the right length, or "bad checksum" about a payload that was
    // never parsed.
    let len = payload.len();
    let consistent = match error {
        IngressError::TooLong { len: reported } => reported == len && len > MAX_PAYLOAD_LEN,
        IngressError::UnknownLength { len: reported } => {
            reported == len && !ACCEPTED_LENGTHS.contains(&len)
        }
        IngressError::NotNumeric { offset } => {
            (len == 48 || len == 96) && payload.get(offset).is_some_and(|b| !b.is_ascii_digit())
        }
        IngressError::IndexOutOfRange { position, value } => {
            (len == 48 || len == 96) && value >= 2048 && position < len / 4
        }
        IngressError::ChecksumFailed { words } => {
            (len == 48 || len == 96) && words == len / 4 && payload.iter().all(u8::is_ascii_digit)
        }
        // Unreachable by construction; if the corpus ever reaches it, that is the finding.
        IngressError::Unverifiable => false,
    };
    if !consistent {
        report.fail(
            family,
            "F8 refusal reason",
            payload,
            format!("{len}-byte payload refused with {error:?}"),
        );
    }
}

// ---------------------------------------------------------------------------------------
// The corpus
// ---------------------------------------------------------------------------------------

/// A base payload in each format, derived from one deterministic entropy.
fn base_pair(seed: u64, entropy_len: usize) -> (Vec<u8>, Vec<u8>) {
    let compact = mixed_bytes(seed, entropy_len);
    let scan = seedqr::decode(&compact).expect("any 16 or 32 bytes are a CompactSeedQR");
    let phrase = scan.mnemonic.phrase();
    let words: Vec<&str> = phrase.split(' ').collect();
    let standard = encode_standard(&words);
    (compact, standard)
}

fn run() -> Report {
    let mut report = Report::default();

    // A. Every 16- and 32-byte payload is a valid CompactSeedQR, and its Standard form is
    // a valid Standard SeedQR. 512 seeds of each length, both formats: the acceptance
    // path, where F3 and F4 do the work.
    for seed in 0..512u64 {
        for entropy_len in [16usize, 32] {
            let (compact, standard) = base_pair(seed, entropy_len);
            case("valid compact", &compact, &mut report);
            case("valid standard", &standard, &mut report);
        }
    }

    // Four bases the mutation families work on: both formats, both word counts.
    let (compact_12, standard_12) = base_pair(9_001, 16);
    let (compact_24, standard_24) = base_pair(9_002, 32);
    let bases: [(&'static str, &[u8]); 4] = [
        ("compact 12", &compact_12),
        ("compact 24", &compact_24),
        ("standard 12", &standard_12),
        ("standard 24", &standard_24),
    ];

    // B. Every byte of every base replaced by every value. This is the family that puts a
    // NUL, a newline, a `+`, a space and every non-ASCII byte into every position of a
    // digit stream, and every possible byte into a compact payload.
    for (name, base) in bases {
        for position in 0..base.len() {
            for value in 0..=255u8 {
                let mut payload = base.to_vec();
                payload[position] = value;
                case(name, &payload, &mut report);
            }
        }
    }

    // C. Every single-bit flip of every base. A flipped bit in a compact payload must give
    // a different seed (F4 catches a decoder that ignored the bit); in a digit stream it
    // usually breaks the charset or the checksum.
    for (name, base) in bases {
        for position in 0..base.len() {
            for bit in 0..8u32 {
                let mut payload = base.to_vec();
                payload[position] ^= 1 << bit;
                case(name, &payload, &mut report);
            }
        }
    }

    // D. Length sweep well past the maximum, with fillers chosen so that a length is
    // refused for its length and not for its content: all-digit, all-zero, all-0xff and a
    // mixed filler. Also the family that proves the oversized refusal allocates nothing.
    for len in 0..=512usize {
        for (name, filler) in [
            ("length sweep digits", None),
            ("length sweep zeros", Some(0x00u8)),
            ("length sweep ones", Some(0xffu8)),
        ] {
            let payload = match filler {
                Some(byte) => vec![byte; len],
                None => vec![b'7'; len],
            };
            case(name, &payload, &mut report);
        }
        case("length sweep mixed", &mixed_bytes(len as u64, len), &mut report);
    }

    // E. Truncations and extensions of each base: every prefix, and one byte of every
    // value appended. A decoder that padded or trimmed to a known length would accept
    // something here.
    for (name, base) in bases {
        for len in 0..base.len() {
            case(name, &base[..len], &mut report);
        }
        for value in 0..=255u8 {
            let mut payload = base.to_vec();
            payload.push(value);
            case(name, &payload, &mut report);
        }
    }

    // F. Every value of the first 4-digit group of a valid 24-word digit stream, 0000
    // through 9999. Exactly the values below 2048 may be accepted, and only then if the
    // checksum survives; 2048 and above must be refused by range rather than reduced.
    for value in 0..10_000u32 {
        let mut payload = standard_24.clone();
        payload[..4].copy_from_slice(format!("{value:04}").as_bytes());
        case("index range sweep", &payload, &mut report);
    }

    // G. Structural specials, each one a shape a real scan can produce.
    let mut specials: Vec<(&'static str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        // Digit streams of the right length whose every group is out of range, and the
        // boundary value 2047 in every group: real words, checksum almost certainly wrong.
        ("all 9999", b"9999".repeat(12)),
        ("all 2048", b"2048".repeat(24)),
        ("all 2047", b"2047".repeat(12)),
    ];
    // Leading and trailing whitespace around a valid digit stream, which is what a
    // decoder that trimmed would silently accept.
    let mut padded = b" ".to_vec();
    padded.extend_from_slice(&standard_12);
    specials.push(("space prefixed", padded));
    let mut trailing = standard_12.clone();
    trailing.extend_from_slice(b"\r\n");
    specials.push(("crlf suffixed", trailing));
    // A UTF-8 BOM in front of a valid digit stream.
    let mut bom = vec![0xef, 0xbb, 0xbf];
    bom.extend_from_slice(&standard_12);
    specials.push(("bom prefixed", bom));
    // The classifier-ordering hazard from `classify`'s docs: a compact payload whose
    // entropy begins with another format's prefix. These must still decode as compact.
    let mut ur_prefixed = compact_12.clone();
    ur_prefixed[..3].copy_from_slice(b"ur:");
    specials.push(("ur-prefixed compact", ur_prefixed));
    let mut bbqr_prefixed = compact_24.clone();
    bbqr_prefixed[..2].copy_from_slice(b"B$");
    specials.push(("bbqr-prefixed compact", bbqr_prefixed));
    // A digit stream in which one group is the four bytes of a NUL-terminated string.
    let mut embedded_nul = standard_12.clone();
    embedded_nul[10] = 0;
    specials.push(("nul in digits", embedded_nul));
    // Non-ASCII digits: Arabic-Indic zero in UTF-8, which `is_ascii_digit` must reject.
    let mut arabic = standard_12.clone();
    arabic[0..2].copy_from_slice(&[0xd9, 0xa0]);
    specials.push(("non-ascii digits", arabic));
    // A 96-byte payload of digits that decodes, with a 97th byte appended.
    let mut too_long = standard_24.clone();
    too_long.push(b'0');
    specials.push(("97 bytes", too_long));
    for (name, payload) in specials {
        case(name, &payload, &mut report);
    }

    report
}

// ---------------------------------------------------------------------------------------
// Drivers
// ---------------------------------------------------------------------------------------

/// The corpus, and the milestone's fuzz gate.
///
/// It runs in the default `cargo test` path on purpose: it costs seconds, not minutes, so
/// there is no reason to hide it behind `--ignored` and every reason for it to run on the
/// commit that breaks it.
#[test]
fn the_ingress_validator_holds_over_the_corpus() {
    let report = run();
    println!("{}", report.summary());
    for line in report.grouped() {
        println!("  {line}");
    }
    assert!(
        report.is_clean(),
        "{} invariant failure(s) in the SeedQR ingress corpus. Each one is a payload an \
         attacker can print; do not weaken an invariant to make this pass.",
        report.findings.len()
    );
    // A corpus that generated nothing would report clean, which is the failure mode a
    // fuzz gate is least able to notice about itself.
    assert!(
        report.cases > 30_000,
        "the corpus shrank to {} cases",
        report.cases
    );
    assert!(
        report.accepted > 1_000 && report.refused > 10_000,
        "the corpus must exercise both verdicts, got {} accepted and {} refused",
        report.accepted,
        report.refused
    );
}

/// The corpus is a constant of this file: two runs must agree exactly.
///
/// Without this, a corpus that quietly depended on hash iteration order or on the clock
/// would still pass the gate above while covering something different every time, and a
/// finding could not be reproduced from the payload it printed.
#[test]
fn the_corpus_is_reproducible() {
    let first = run();
    let second = run();
    assert_eq!(first.cases, second.cases);
    assert_eq!(first.accepted, second.accepted);
    assert_eq!(first.refused, second.refused);
    assert_eq!(first.findings.len(), second.findings.len());
}
