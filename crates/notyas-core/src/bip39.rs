// Copyright (C) 2025-2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Bit selection, BIP39 mnemonic construction and seed stretching (SPEC steps 4-8).
//!
//! BIP39 is implemented here rather than pulled from a crate for one reason: raw mode
//! routinely produces more than 24 words (200 rolls is about 333 bits, 320 of which are
//! used, i.e. 30 words) and every published BIP39 crate rejects that. iancoleman's
//! `jsbip39.toMnemonic` only requires `bytes % 4 == 0`, and so do we.

use core::fmt;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

// The official BIP39 English wordlist, embedded so the binary is standalone.
// Downloaded from bitcoin/bips `bip-0039/english.txt`
// (sha256 2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda).
//
// The desktop crate parses the file at first use behind a `std::sync::OnceLock`; here the
// parse happens in build.rs - which also verifies that digest and the list's count and
// order - and this include supplies the resulting `static WORDLIST: [&str; WORDLIST_LEN]`.
include!(concat!(env!("OUT_DIR"), "/wordlist.rs"));

/// Words in the BIP39 list; also the radix of the 11-bit index groups.
pub const WORDLIST_LEN: usize = 2048;

/// Below this many entropy bits the result is weaker than a standard 12-word seed and the
/// CLI must warn about it.
pub const MIN_SECURE_BITS: usize = 128;

/// Hard ceiling on ENT: the checksum is taken from a single SHA256 digest, so ENT/32
/// checksum bits can never exceed 256. Raw mode is expected to stay far below this.
pub const MAX_ENTROPY_BITS: usize = 8192;

/// Word counts accepted by [`MnemonicMode::Words`].
pub const FIXED_WORD_COUNTS: [usize; 5] = [12, 15, 18, 21, 24];

/// Bits per BIP39 word index, and therefore the group size of SPEC step 7.
const BITS_PER_WORD: usize = 11;

/// Raw mode consumes whole 32-bit blocks (BIP39 requires ENT % 32 == 0), so this is both
/// the block size and the smallest usable ENT.
const ENTROPY_BLOCK_BITS: usize = 32;

/// Average bits contributed by one d6 under the SPEC step 3 encoding, as a fraction:
/// four of six faces cost two bits and two cost one, so (4*2 + 2*1) / 6 = 5/3.
const BITS_PER_ROLL_NUM: usize = 5;
const BITS_PER_ROLL_DEN: usize = 3;

/// A word count the fixed-length mode supports.
///
/// Invariant, established by the only constructor: the wrapped value is one of
/// [`FIXED_WORD_COUNTS`]. That is what makes [`WordCount::entropy_bits`] a whole number of
/// bytes, so no code downstream of construction has to re-validate or handle the
/// impossible case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WordCount(u8);

impl WordCount {
    /// The only way to build a [`WordCount`]; rejects anything outside
    /// [`FIXED_WORD_COUNTS`].
    pub fn new(words: usize) -> Result<Self, Bip39Error> {
        if FIXED_WORD_COUNTS.contains(&words) {
            Ok(WordCount(words as u8))
        } else {
            Err(Bip39Error::UnsupportedWordCount(words.to_string()))
        }
    }

    pub fn get(self) -> usize {
        usize::from(self.0)
    }

    /// ENT for this word count: three words carry 32 entropy bits plus one checksum bit,
    /// so ENT is a whole number of bytes for every accepted count.
    fn entropy_bits(self) -> usize {
        ENTROPY_BLOCK_BITS * self.get() / 3
    }
}

impl fmt::Display for WordCount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// How the final bit string is chosen from the dice bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MnemonicMode {
    /// SPEC step 4: use the trailing `floor(bits/32)*32` dice bits verbatim. Word count is
    /// whatever falls out, and may exceed 24.
    Raw,
    /// SPEC step 5: hash the clean digit string and take a fixed number of words.
    Words(WordCount),
}

impl fmt::Display for MnemonicMode {
    /// Renders the value used for the JSON `mnemonic.mode` field: "raw" or the count.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MnemonicMode::Raw => f.write_str("raw"),
            MnemonicMode::Words(n) => write!(f, "{n}"),
        }
    }
}

impl core::str::FromStr for MnemonicMode {
    type Err = Bip39Error;

    /// Parses the `--words` argument: "raw" or one of 12/15/18/21/24. The error carries the
    /// text the user typed, not a normalized number, so the message can quote it back.
    ///
    /// The accepted spellings are exactly the documented ones. `usize::from_str` also takes
    /// "+12" and "012", which the error message tells the user are invalid, and a flag that
    /// decides which wallet comes out should not accept a language wider than the one it
    /// advertises.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("raw") {
            return Ok(MnemonicMode::Raw);
        }
        s.parse::<usize>()
            .ok()
            .filter(|n| n.to_string() == s)
            .and_then(|n| WordCount::new(n).ok())
            .map(MnemonicMode::Words)
            .ok_or_else(|| Bip39Error::UnsupportedWordCount(s.to_string()))
    }
}

/// A mnemonic plus the exact entropy it encodes.
///
/// `entropy` holds only the bytes that were actually used (SPEC step 6), so
/// `entropy.len() * 8` is the ENT reported by the CLI, and `words.len()` is always
/// `entropy.len() * 8 * 33 / 32 / 11`.
#[derive(Clone)]
pub struct Mnemonic {
    pub entropy: Vec<u8>,
    pub words: Vec<&'static str>,
}

impl fmt::Debug for Mnemonic {
    /// Hand written rather than derived: `{:?}` on key material - in a caller, a log line
    /// or a panic payload - would copy it into a fresh string that nothing wipes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mnemonic")
            .field("entropy_bits", &(self.entropy.len() * 8))
            .field("entropy", &"<redacted>")
            .field(
                "words",
                &format_args!("<redacted, {} words>", self.words.len()),
            )
            .finish()
    }
}

impl Mnemonic {
    /// The mnemonic sentence: words joined by single ASCII spaces, no trailing space.
    /// This exact string is the PBKDF2 password before NFKD (SPEC step 8).
    ///
    /// Wrapped for the same reason [`seed`] is: the sentence alone regenerates the wallet,
    /// and a bare `String` return value would leave an unwiped copy in freed heap however
    /// careful the caller is. It derefs to `String`, so callers read it as one.
    ///
    /// `join` is what makes the wrapper sufficient here rather than decorative: it sums the
    /// word lengths before it allocates, so the buffer `Zeroizing` receives is the only one
    /// the sentence was ever written into. Building the sentence by pushing into a `String`
    /// that starts empty would not be, and the wrapper would then cover the last copy of
    /// four.
    pub fn phrase(&self) -> Zeroizing<String> {
        Zeroizing::new(self.words.join(" "))
    }
}

impl Drop for Mnemonic {
    /// Key material must not outlive the value that owns it. Note this makes `Mnemonic`
    /// non-destructurable; clone the fields you need instead.
    ///
    /// INVARIANT, and the limit of what this impl can promise: a `Drop` reaches the buffer
    /// the value owns AT THIS INSTANT and nothing else. A `String` or `Vec` that grew,
    /// was collected into from an iterator of unknown length, or was `shrink_to_fit`ed left
    /// its previous buffer in the allocator's free list with the contents intact, and no
    /// wipe here can follow it. That is why the discipline this type stands for lives along
    /// the whole data path and not in these two lines: `entropy` is built at its final size
    /// (see `pack_bits`), the sentence is built at its final size (see `phrase`), and the
    /// normalization `seed` performs on it is too (see `nfkd_secret`).
    ///
    /// `crates/notyas-core/tests/key_material_residue.rs` watches the allocator and fails
    /// if any of those becomes untrue, which is the only way to keep it true: the mistake
    /// is a single innocuous `to_string()` away and leaves the code reading correctly.
    fn drop(&mut self) {
        self.entropy.zeroize();
    }
}

/// Failures that are the user's to fix, plus the two structural limits of the scheme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bip39Error {
    /// Raw mode produced fewer than 32 usable bits. Carries the bits available so the CLI
    /// can tell the user roughly how many more rolls are needed (5/3 bits per roll).
    NotEnoughEntropy { bits: usize },
    /// `--words` was neither "raw" nor one of 12/15/18/21/24.
    UnsupportedWordCount(String),
    /// ENT above [`MAX_ENTROPY_BITS`], where the 32-bit-per-checksum-bit budget of a
    /// single SHA256 digest runs out.
    EntropyTooLarge { bits: usize },
}

impl fmt::Display for Bip39Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Bip39Error::NotEnoughEntropy { bits } => write!(
                f,
                "not enough dice entropy: {bits} bit(s) collected, but raw mode uses whole \
                 {ENTROPY_BLOCK_BITS}-bit blocks and needs at least {ENTROPY_BLOCK_BITS}. \
                 Roll about {min} more dice for a 3-word result, {secure} in total for a \
                 12-word ({MIN_SECURE_BITS}-bit) seed, or {full} for a 24-word (256-bit) \
                 seed.",
                min = rolls_for_bits(ENTROPY_BLOCK_BITS.saturating_sub(*bits)),
                secure = rolls_for_bits(MIN_SECURE_BITS),
                full = rolls_for_bits(256),
            ),
            Bip39Error::UnsupportedWordCount(got) => write!(
                f,
                "unsupported word count \"{got}\": expected \"raw\" or one of 12, 15, 18, \
                 21, 24"
            ),
            Bip39Error::EntropyTooLarge { bits } => write!(
                f,
                "too much entropy: {bits} bits, but the maximum is {MAX_ENTROPY_BITS} \
                 (the BIP39 checksum is drawn from a single 256-bit SHA256 digest, which \
                 covers at most {MAX_ENTROPY_BITS}/32 checksum bits). Use fewer dice or \
                 pick a fixed word count."
            ),
        }
    }
}

impl core::error::Error for Bip39Error {}

/// Dice needed, on average, to collect `bits` bits under the SPEC step 3 encoding.
/// Rounded up, so the advice is never short.
///
/// This is the crate's only definition of the 5/3 ratio: the CLI's warnings and help text
/// quote the same numbers as the error messages here, and a second copy would eventually
/// disagree with this one.
pub fn rolls_for_bits(bits: usize) -> usize {
    bits.saturating_mul(BITS_PER_ROLL_DEN)
        .div_ceil(BITS_PER_ROLL_NUM)
}

/// The embedded wordlist as a 2048-entry slice, index == BIP39 word index.
///
/// The desktop crate parses the embedded file here, at first use; this port has build.rs
/// do that parse (and the count/order checks) at compile time, so this is a plain borrow
/// of a `static` and no failure case exists at run time.
pub fn wordlist() -> &'static [&'static str] {
    &WORDLIST
}

/// Order `word` against the first `prefix.len()` bytes of `prefix` folded to ASCII
/// lowercase. `Equal` therefore means exactly "word starts with prefix, ignoring case".
///
/// Folding the PREFIX rather than lowercasing a copy of it is what keeps
/// [`words_with_prefix`] allocation-free: the prefix is a slice of the user's phrase, and
/// a lowercase heap copy of part of a phrase would be one more buffer to wipe. The fold
/// is exact because every wordlist entry is ASCII a-z (build.rs verifies the list);
/// a non-ASCII prefix byte is >= 0x80 > b'z', so it simply orders past the whole list.
fn cmp_prefix_folded(word: &str, prefix: &str) -> core::cmp::Ordering {
    use core::cmp::Ordering;
    let w = word.as_bytes();
    for (i, p) in prefix.as_bytes().iter().enumerate() {
        match w.get(i) {
            // The word ran out inside the prefix: it is a strict prefix of it, so it
            // sorts before every word the prefix can match.
            None => return Ordering::Less,
            Some(c) => match c.cmp(&p.to_ascii_lowercase()) {
                Ordering::Equal => {}
                other => return other,
            },
        }
    }
    Ordering::Equal
}

/// Up to `max` BIP39 words starting with `prefix`, in wordlist (alphabetical) order.
///
/// Case-insensitive, so a phrase typed on a shifted keyboard still completes. An empty
/// prefix returns nothing: every word matches it, which is no suggestion at all.
///
/// The wordlist is sorted (asserted by build.rs and by `wordlist_is_the_official_2048`),
/// so the matches are one contiguous run and a binary search finds its start.
pub fn words_with_prefix(prefix: &str, max: usize) -> Vec<&'static str> {
    use core::cmp::Ordering;
    if prefix.is_empty() || max == 0 {
        return Vec::new();
    }
    let list = wordlist();
    let start = list.partition_point(|w| cmp_prefix_folded(w, prefix) == Ordering::Less);
    list[start..]
        .iter()
        .take_while(|w| cmp_prefix_folded(w, prefix) == Ordering::Equal)
        .take(max)
        .copied()
        .collect()
}

/// The word currently being typed at the end of `text`: everything after the last
/// whitespace run, or the empty string when `text` ends with whitespace (the next word
/// has not started) or is empty.
///
/// The splitter is [`char::is_whitespace`], the same one [`normalize_phrase`] uses, so
/// the fragment is exactly the token the phrase parser would eventually see.
pub fn current_word_fragment(text: &str) -> &str {
    match text.rsplit_once(char::is_whitespace) {
        Some((_, fragment)) => fragment,
        None => text,
    }
}

/// The BIP39 words that would give `phrase` a valid checksum as its LAST word.
///
/// The final-word helper of the restore screen (UX-SCREENS.md S-14). With 11, 14, 17, 20
/// or 23 words typed, the word still missing is almost entirely determined: it carries
/// only `ENT - 11 * typed` entropy bits (7, 6, 5, 4 and 3 respectively) and the WHOLE
/// checksum, so between 128 and 8 of the 2048 words can complete the phrase. Offering
/// that set is what stops a user with a smudged backup hand-searching the wordlist, and
/// it is exactly the information the checksum already published - no secret of theirs
/// enters the list that their own other words did not put there.
///
/// Empty unless `phrase` is exactly one word short of a count in [`FIXED_WORD_COUNTS`]
/// and every word already typed is in the list. An unknown word leaves no entropy to
/// complete, and guessing past it would offer candidates for a phrase the user did not
/// type.
///
/// The result is in wordlist (alphabetical) order: the candidate index is
/// `value << checksum_bits | checksum`, which is strictly increasing in the entropy
/// value the loop walks, so no sort is needed and none is done.
pub fn valid_last_words(phrase: &str) -> Vec<&'static str> {
    let list = wordlist();
    let typed: Vec<&str> = phrase.split_whitespace().collect();
    let total = typed.len() + 1;
    if !FIXED_WORD_COUNTS.contains(&total) {
        return Vec::new();
    }

    // The bit string of the words already typed, wiped on drop: it is the user's entropy
    // less the last word's share, which is most of their wallet.
    let mut bits = Zeroizing::new(String::with_capacity(total * BITS_PER_WORD));
    for word in &typed {
        let lower = Zeroizing::new(word.to_lowercase());
        let Ok(index) = list.binary_search_by(|probe| (**probe).cmp(lower.as_str())) else {
            return Vec::new();
        };
        for shift in (0..BITS_PER_WORD).rev() {
            bits.push(char::from(b'0' + ((index >> shift) & 1) as u8));
        }
    }

    let ent = total / 3 * ENTROPY_BLOCK_BITS;
    let checksum_bits = ent / ENTROPY_BLOCK_BITS;
    // What the last word contributes to ENT; the rest of its 11 bits is the checksum.
    // Non-negative and under `BITS_PER_WORD` for every count in `FIXED_WORD_COUNTS`,
    // which is why this arithmetic needs no clamp: 12 words give 7, 24 words give 3.
    let tail = ent - typed.len() * BITS_PER_WORD;
    let base = bits.len();

    let mut out = Vec::with_capacity(1usize << tail);
    for value in 0..(1usize << tail) {
        // Reuse the one buffer rather than cloning it per candidate: the capacity above
        // covers `base + tail` exactly, so no push here can reallocate and leave a copy
        // of the user's entropy in freed heap.
        bits.truncate(base);
        for shift in (0..tail).rev() {
            bits.push(char::from(b'0' + ((value >> shift) & 1) as u8));
        }
        let entropy = Zeroizing::new(pack_bits(bits.as_bytes()));
        let digest = Zeroizing::new(<[u8; 32]>::from(Sha256::digest(&*entropy)));
        let mut checksum = 0usize;
        for i in 0..checksum_bits {
            checksum = (checksum << 1) | usize::from(digest[i / 8] >> (7 - i % 8) & 1);
        }
        out.push(list[(value << checksum_bits) | checksum]);
    }
    out
}

/// Turn parsed dice into a mnemonic (SPEC steps 4-7).
///
/// SPEC obligations:
/// - Step 4 ([`MnemonicMode::Raw`]): `bits_used = floor(binary.len()/32)*32` and the bits
///   taken are the LAST `bits_used` of `binary`, i.e. leading bits are discarded
///   (`start = len - bits_used`). `bits_used == 0` is [`Bip39Error::NotEnoughEntropy`].
/// - Step 5 ([`MnemonicMode::Words`]): `SHA256` over the UTF-8 bytes of the `clean` DIGIT
///   STRING (the ASCII characters, not packed bytes), digest read as a 256-bit big-endian
///   bit string, take the FIRST `32 * words / 3` bits. Note this path ignores `binary`
///   entirely and is defined even for very short inputs.
/// - Step 6: pack the selected bits into bytes, 8 bits per byte, most significant bit
///   first. The bit count is always a multiple of 32, so no padding case exists.
/// - Step 7: ENT = 8 * entropy.len(); checksum = first ENT/32 bits of SHA256(entropy);
///   split ENT + ENT/32 bits into 11-bit big-endian groups; each group indexes
///   [`wordlist`]. Do NOT cap the word count at 24.
pub fn mnemonic_from_dice(
    e: &crate::entropy::DiceEntropy,
    mode: MnemonicMode,
) -> Result<Mnemonic, Bip39Error> {
    let entropy = match mode {
        MnemonicMode::Raw => raw_entropy(e.binary())?,
        MnemonicMode::Words(words) => hashed_entropy(e.clean(), words),
    };
    mnemonic_from_entropy(entropy)
}

/// SPEC step 4's selection rule: how many of `available` dice bits raw mode keeps.
///
/// This is the crate's only statement of that rule; the CLI reports the number and the
/// tests compare against it rather than restating `len / 32 * 32` a third time.
pub fn raw_bits_used(available: usize) -> usize {
    available / ENTROPY_BLOCK_BITS * ENTROPY_BLOCK_BITS
}

/// SPEC step 4 + 6: keep the trailing whole 32-bit blocks of the dice bit string.
///
/// Discarding LEADING bits (rather than trailing) is not arbitrary: it is what
/// iancoleman's `index.js` does (`bits.substring(bits.length - bitsToUse)`), and matching
/// it byte-for-byte is the whole point of this program.
fn raw_entropy(binary: &str) -> Result<Vec<u8>, Bip39Error> {
    let available = binary.len();
    let used = raw_bits_used(available);
    if used == 0 {
        return Err(Bip39Error::NotEnoughEntropy { bits: available });
    }
    Ok(pack_bits(&binary.as_bytes()[available - used..]))
}

/// SPEC step 5 + 6: hash the clean digit STRING and keep the leading `32*words/3` bits.
///
/// The hash input is the ASCII digit characters, not the packed dice bits, so this path
/// never fails for short inputs - it is a deterministic stretch, not an entropy source.
/// The wallet is therefore only as strong as the dice were, whatever ENT the word count
/// advertises, and the front end must say so; `report::effective_bits` is the number that
/// warning is computed from.
///
/// Infallible by construction: [`WordCount`] cannot hold a count whose ENT is not a whole
/// number of bytes.
fn hashed_entropy(clean: &str, words: WordCount) -> Vec<u8> {
    let bits = words.entropy_bits();
    debug_assert_eq!(
        bits % 8,
        0,
        "fixed word counts must land on a byte boundary"
    );

    // Zeroizing: the unused tail of the digest is as sensitive as the entropy itself.
    let digest = Zeroizing::new(<[u8; 32]>::from(Sha256::digest(clean.as_bytes())));
    digest[..bits / 8].to_vec()
}

/// SPEC step 6: pack ASCII '0'/'1' characters into bytes, most significant bit first.
///
/// `bits.len()` is always a multiple of 32 here, so no partial trailing byte can occur.
/// A character other than '1' is read as 0, which cannot happen for a [`DiceEntropy`]
/// produced by [`crate::entropy::parse_dice`] (its `binary` invariant guarantees '0'/'1').
///
/// INVARIANT: the output is the master entropy, so the buffer is allocated at its final
/// size and filled, never collected into. `collect` happens to allocate exactly once here
/// today - `Chunks` is a `TrustedLen` iterator and the standard library specializes on
/// that - but the wipe discipline of [`Mnemonic`] cannot rest on a library optimization
/// that no API promises. If it ever stopped applying, the entropy would be silently
/// duplicated into freed heap at every doubling and nothing would fail.
///
/// [`DiceEntropy`]: crate::entropy::DiceEntropy
fn pack_bits(bits: &[u8]) -> Vec<u8> {
    debug_assert_eq!(bits.len() % 8, 0, "bit count must be byte aligned");
    let mut out = Vec::with_capacity(bits.len() / 8);
    for chunk in bits.chunks(8) {
        out.push(
            chunk
                .iter()
                .fold(0u8, |byte, &c| (byte << 1) | u8::from(c == b'1')),
        );
    }
    out
}

/// SPEC step 7: the generalized BIP39 encoder.
///
/// Accepts any ENT that is a non-zero multiple of 32 bits up to [`MAX_ENTROPY_BITS`],
/// which is what lets raw mode emit 27, 30, ... word phrases. `ENT + ENT/32` is always
/// `33 * ENT/32`, i.e. divisible by 11, so the bit string always fills whole words.
/// Visible to the crate because [`crate::bip85`] needs it: a BIP-85 child is DEFINED as
/// a mnemonic, so stopping at raw entropy would leave every caller unable to use the
/// result. It was briefly duplicated there, which is the wrong answer for a word
/// encoding whose two copies could drift apart silently and produce a phrase that
/// checksums but is not the child the path names.
pub(crate) fn mnemonic_from_entropy(mut entropy: Vec<u8>) -> Result<Mnemonic, Bip39Error> {
    let ent = entropy.len() * 8;
    assert!(
        ent != 0 && ent % ENTROPY_BLOCK_BITS == 0,
        "ENT must be a non-zero multiple of {ENTROPY_BLOCK_BITS} bits, got {ent}"
    );
    if ent > MAX_ENTROPY_BITS {
        // The success path hands these bytes to `Mnemonic`, which wipes them on drop; this
        // is the one return that owns them and would otherwise free them untouched.
        entropy.zeroize();
        return Err(Bip39Error::EntropyTooLarge { bits: ent });
    }

    let checksum_bits = ent / ENTROPY_BLOCK_BITS;
    let digest = Zeroizing::new(<[u8; 32]>::from(Sha256::digest(&entropy)));

    // Bit `i` of the concatenation entropy||checksum, MSB first within each byte.
    let bit = |i: usize| -> usize {
        let (src, j) = if i < ent {
            (&entropy[..], i)
        } else {
            (&digest[..], i - ent)
        };
        usize::from(src[j / 8] >> (7 - j % 8) & 1)
    };

    let total_bits = ent + checksum_bits;
    let list = wordlist();
    let words = (0..total_bits / BITS_PER_WORD)
        .map(|w| {
            let index =
                (0..BITS_PER_WORD).fold(0usize, |acc, b| (acc << 1) | bit(w * BITS_PER_WORD + b));
            list[index]
        })
        .collect();

    Ok(Mnemonic { entropy, words })
}

/// BIP39 seed derivation (SPEC step 8).
///
/// PBKDF2-HMAC-SHA512, 2048 iterations, 64-byte output.
/// Password = NFKD(`phrase`), salt = NFKD("mnemonic" + `passphrase`).
/// `phrase` is expected to already be space-joined as produced by [`Mnemonic::phrase`];
/// the NFKD pass is what makes non-ASCII passphrases interoperable.
///
/// The seed is returned wrapped: a bare `[u8; 64]` return value would leave an unwiped
/// copy on this function's stack frame no matter what the caller does with it.
pub fn seed(phrase: &str, passphrase: &str) -> Zeroizing<[u8; 64]> {
    // Normalize the concatenation, not the parts: NFKD of "mnemonic" + passphrase is what
    // BIP39 specifies, and for a passphrase starting with a combining mark the two differ.
    //
    // The salt is assembled at its final size rather than with `format!`: `format!` sizes
    // its buffer from a heuristic over the format string, so any passphrase longer than
    // that guess makes the buffer grow, and the abandoned buffer is a prefix of the
    // passphrase that no `Zeroizing` reaches. See `nfkd_secret` for the general rule.
    let mut joined = Zeroizing::new(String::with_capacity(SALT_PREFIX.len() + passphrase.len()));
    joined.push_str(SALT_PREFIX);
    joined.push_str(passphrase);

    let password = nfkd_secret(phrase);
    let salt = nfkd_secret(&joined);

    let mut out = Zeroizing::new([0u8; 64]);
    pbkdf2::pbkdf2_hmac::<sha2::Sha512>(password.as_bytes(), salt.as_bytes(), 2048, &mut *out);
    out
}

/// BIP39's fixed salt prefix; the passphrase is appended to it (SPEC step 8).
const SALT_PREFIX: &str = "mnemonic";

/// NFKD-normalize `text` into a buffer that is wiped on drop and provably never grows.
///
/// INVARIANT, and the reason this is not `text.nfkd().collect::<String>()`: normalization
/// is a character iterator whose length is not known in advance, so `collect` starts from
/// an empty buffer and doubles. Each doubling copies what it has to a new allocation and
/// hands the old one back to the allocator UNREAD - and for a mnemonic those abandoned
/// buffers hold the first 8, 16, 32 and 64 bytes of the sentence, in plaintext, after the
/// `Zeroizing` that owns the final buffer has done its job. Measuring first and then
/// filling a buffer of exactly that size is what makes the wipe cover every copy that ever
/// existed: `String::push` reallocates only when it is full, and this one never is.
///
/// Anything added here that returns a `String` by value, or that collects, reintroduces
/// the defect. `crates/notyas-core/tests/key_material_residue.rs` fails if it does.
///
/// The measuring pass costs a second normalization of a few hundred bytes, next to a
/// 2048-round PBKDF2. That is not a tradeoff worth thinking about twice.
fn nfkd_secret(text: &str) -> Zeroizing<String> {
    use unicode_normalization::UnicodeNormalization;

    let len: usize = text.nfkd().map(char::len_utf8).sum();
    let mut out = Zeroizing::new(String::with_capacity(len));
    for c in text.nfkd() {
        out.push(c);
    }
    debug_assert_eq!(out.len(), len, "the two normalization passes must agree");
    out
}

// ---------------------------------------------------------------------------------------
// Mnemonic input: a phrase the user supplies instead of dice
// ---------------------------------------------------------------------------------------

/// The whitespace-normalized form of a typed phrase: words split on any run of whitespace
/// and rejoined with single ASCII spaces.
///
/// This is the exact string iancoleman's `jsbip39.toSeed` hands to PBKDF2 (before its own
/// NFKD pass, which [`seed`] does). Case is left as typed, because the page does not fold it
/// either and folding it here would silently derive a different wallet from the same
/// keystrokes.
pub fn normalize_phrase(text: &str) -> Zeroizing<String> {
    // The result is never longer than the input, so this buffer cannot grow and leave a
    // copy of the phrase in freed heap.
    let mut out = Zeroizing::new(String::with_capacity(text.len()));
    for word in text.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(word);
    }
    out
}

/// What the BIP39 checksum of a typed phrase says about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Checksum {
    Valid,
    Invalid,
    /// The phrase carries no checksum this program can check: a word that is not in the
    /// list, a word count that is not a non-zero multiple of three, or a count so large that
    /// its checksum would need more bits than one SHA256 digest has (see
    /// [`MAX_ENTROPY_BITS`]).
    NotApplicable,
}

impl Checksum {
    /// The token used in the JSON document.
    pub fn as_str(self) -> &'static str {
        match self {
            Checksum::Valid => "valid",
            Checksum::Invalid => "invalid",
            Checksum::NotApplicable => "not_applicable",
        }
    }
}

/// What [`check_phrase`] found in a typed phrase. Advisory only: every field here describes
/// the phrase, and none of them decides whether a seed is derived from it.
pub struct PhraseCheck {
    pub word_count: usize,
    /// Words that are not in the English list, in the order they were typed and spelled as
    /// they were typed. The comparison is case-insensitive; this listing is not, so the user
    /// sees the word they wrote.
    pub unknown_words: Vec<String>,
    pub checksum: Checksum,
    /// The entropy the phrase encodes, empty unless the phrase decodes at all. Filled even
    /// when the checksum is wrong, because the leading ENT bits are still what the words
    /// say.
    pub entropy: Vec<u8>,
}

impl Drop for PhraseCheck {
    /// The entropy is the wallet, and an unknown word is still a word of someone's phrase.
    fn drop(&mut self) {
        self.entropy.zeroize();
        for word in &mut self.unknown_words {
            word.zeroize();
        }
    }
}

impl fmt::Debug for PhraseCheck {
    /// Hand written for the reason every secret-bearing type in this crate has one: a `{:?}`
    /// in a log line or a panic payload would copy the phrase's entropy somewhere nothing
    /// wipes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PhraseCheck")
            .field("word_count", &self.word_count)
            .field(
                "unknown_words",
                &format_args!("<redacted, {} words>", self.unknown_words.len()),
            )
            .field("checksum", &self.checksum)
            .finish()
    }
}

/// Read a phrase the user supplied: how many words, which of them are not BIP39 words, and
/// whether the checksum holds.
///
/// This never fails and never blocks anything. A phrase that is misspelled, mis-counted or
/// simply not a mnemonic at all still derives a seed through [`seed`], exactly as the
/// reference page does; what this produces is the warning the user is shown, not a veto.
///
/// `phrase` is expected to be [`normalize_phrase`]d, though any whitespace is tolerated.
pub fn check_phrase(phrase: &str) -> PhraseCheck {
    let list = wordlist();
    // Counted by walking the phrase rather than by collecting it: a `Vec<&str>` of the
    // words would be a second, growing buffer describing the user's phrase, and the split
    // is cheap enough to do twice.
    let word_count = phrase.split_whitespace().count();

    let mut unknown_words = Vec::new();
    // INVARIANT: this vector IS the phrase. A BIP39 word index is the whole of what a word
    // carries - eleven bits, losslessly - so a `Vec<usize>` of every index is the user's
    // mnemonic in another encoding, and it must be wiped exactly as `PhraseCheck::entropy`
    // is. It cannot be left to `PhraseCheck::drop`, because this vector never reaches the
    // returned value: it is a local, consumed below and freed before the caller sees
    // anything. Two properties keep the wipe complete, and both are load bearing:
    // `Zeroizing` covers the buffer at drop, and the exact capacity means there is only
    // ever one buffer for it to cover.
    let mut indices: Zeroizing<Vec<usize>> = Zeroizing::new(Vec::with_capacity(word_count));
    for word in phrase.split_whitespace() {
        // The list is lowercase, so "Zoo" is the word "zoo" for this comparison, which is
        // why case is only a display detail here while it stays significant for the seed.
        // The page's validator is stricter: its `WORDLISTS[language].indexOf(word)` is an
        // exact match, so "Zoo" is a word it does not know and the phrase is refused. That
        // divergence is deliberate and is written up in the desktop crate's
        // docs/EQUIVALENCE.md.
        let lower = Zeroizing::new(word.to_lowercase());
        match list.binary_search_by(|probe| (**probe).cmp(lower.as_str())) {
            Ok(index) => indices.push(index),
            Err(_) => unknown_words.push(word.to_string()),
        }
    }

    // ENT is 32 bits per three words, so only these counts encode anything to check. The
    // upper bound is the same one [`mnemonic_from_entropy`] enforces: beyond it the checksum
    // would need more bits than a single SHA256 digest has.
    let ent = word_count / 3 * ENTROPY_BLOCK_BITS;
    if !unknown_words.is_empty() || word_count % 3 != 0 || ent == 0 || ent > MAX_ENTROPY_BITS {
        return PhraseCheck {
            word_count,
            unknown_words,
            checksum: Checksum::NotApplicable,
            entropy: Vec::new(),
        };
    }

    let mut bits = Zeroizing::new(String::with_capacity(word_count * BITS_PER_WORD));
    // Borrowed, not consumed. `Zeroizing` deliberately owns no `IntoIterator`, so the
    // by-value `for index in indices` this replaces does not compile against the wrapped
    // type at all: the only way to read the indices is to leave the wiping owner in place.
    for &index in indices.iter() {
        for shift in (0..BITS_PER_WORD).rev() {
            bits.push(char::from(b'0' + ((index >> shift) & 1) as u8));
        }
    }
    let entropy = pack_bits(&bits.as_bytes()[..ent]);
    let digest = Zeroizing::new(<[u8; 32]>::from(Sha256::digest(&entropy)));
    let valid = bits.as_bytes()[ent..]
        .iter()
        .enumerate()
        .all(|(i, bit)| *bit == b'0' + (digest[i / 8] >> (7 - i % 8) & 1));

    PhraseCheck {
        word_count,
        unknown_words,
        checksum: if valid {
            Checksum::Valid
        } else {
            Checksum::Invalid
        },
        entropy,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::DiceEntropy;
    use serde_json::Value;

    /// `trezor_vectors.json` is the verbatim upstream file
    /// (sha256 fa3b937b7cff9c9b8ecd3aa011faeb8d6dd67993174b72326e83f4de8fdb30f8).
    ///
    /// Embedded, not read at run time; see the desktop crate's `tests/vectors/README.md`
    /// for why every vector file is loaded that way.
    const TREZOR_VECTORS: &str = include_str!("../tests/vectors/trezor_vectors.json");
    const IANCOLEMAN_VECTORS: &str = include_str!("../tests/vectors/iancoleman_vectors.json");

    fn vectors(name: &str) -> Value {
        let text = match name {
            "trezor_vectors.json" => TREZOR_VECTORS,
            "iancoleman_vectors.json" => IANCOLEMAN_VECTORS,
            other => panic!("no vector file embedded under the name {other}"),
        };
        serde_json::from_str(text).unwrap_or_else(|e| panic!("malformed JSON in {name}: {e}"))
    }

    /// Shorthand for the tests; every count used here is a valid one.
    fn wc(words: usize) -> WordCount {
        WordCount::new(words).expect("test uses a supported word count")
    }

    /// The vector's dice session, parsed from the recorded input and cross-checked against
    /// the recorded digits and bits so a vector edited on one side cannot slip through.
    fn dice(v: &Value) -> DiceEntropy {
        let e = crate::entropy::parse_dice(v["input"].as_str().expect("input"));
        assert_eq!(e.events() as u64, v["events"].as_u64().expect("events"));
        assert_eq!(e.clean(), v["clean"].as_str().expect("clean"));
        assert_eq!(e.binary(), v["binary"].as_str().expect("binary"));
        e
    }

    /// Independent decoder used to check the encoder from the other direction: recovers
    /// the entropy from a phrase and verifies the BIP39 checksum against a fresh SHA256.
    /// Deliberately does not share code with [`mnemonic_from_entropy`].
    fn decode_and_check(phrase: &str) -> Vec<u8> {
        let list = wordlist();
        let mut bits = String::new();
        for word in phrase.split(' ') {
            let index = list.iter().position(|w| *w == word).expect("word in list");
            bits.push_str(&format!("{index:011b}"));
        }
        assert_eq!(
            bits.len() % 33,
            0,
            "total bits must be 33 per 32 entropy bits"
        );
        let ent = bits.len() / 33 * 32;
        let entropy = pack_bits(&bits.as_bytes()[..ent]);
        let digest = <[u8; 32]>::from(Sha256::digest(&entropy));
        let expected: String = (0..ent / 32)
            .map(|i| char::from(b'0' + (digest[i / 8] >> (7 - i % 8) & 1)))
            .collect();
        assert_eq!(&bits[ent..], expected, "checksum mismatch for: {phrase}");
        entropy
    }

    /// Byte pattern with no structure that could accidentally match a bug (all-zero or
    /// all-one entropy hides bit-order errors).
    fn pattern(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(37).wrapping_add(11))
            .collect()
    }

    #[test]
    fn wordlist_is_the_official_2048() {
        let list = wordlist();
        assert_eq!(list.len(), WORDLIST_LEN);
        assert_eq!(list[0], "abandon");
        assert_eq!(list[2047], "zoo");
        assert!(
            list.windows(2).all(|w| w[0] < w[1]),
            "wordlist must be sorted"
        );
    }

    // (a) Official Trezor vectors: entropy -> mnemonic, mnemonic -> seed (passphrase
    // "TREZOR"). Covers ENT 128/192/256 across all 24 english cases.
    #[test]
    fn trezor_english_vectors() {
        let json = vectors("trezor_vectors.json");
        let cases = json["english"].as_array().expect("english array");
        assert_eq!(cases.len(), 24);
        for case in cases {
            let entropy_hex = case[0].as_str().unwrap();
            let expected_phrase = case[1].as_str().unwrap();
            let expected_seed = case[2].as_str().unwrap();

            let entropy = hex::decode(entropy_hex).unwrap();
            let m = mnemonic_from_entropy(entropy.clone()).unwrap();
            assert_eq!(
                m.phrase().as_str(),
                expected_phrase,
                "entropy {entropy_hex}"
            );
            assert_eq!(m.entropy, entropy);
            assert_eq!(decode_and_check(&m.phrase()), entropy);
            assert_eq!(
                hex::encode(seed(expected_phrase, "TREZOR")),
                expected_seed,
                "seed for {entropy_hex}"
            );
        }
    }

    // (b) iancoleman dice vectors: the exact pipeline this program must reproduce.
    #[test]
    fn iancoleman_dice_vectors() {
        let json = vectors("iancoleman_vectors.json");
        let cases = json["vectors"].as_object().expect("vectors object");
        assert!(!cases.is_empty(), "vector file has no cases");

        for (name, case) in cases {
            let e = dice(case);
            assert_eq!(e.clean().len(), e.events(), "{name}: clean/events disagree");

            match mnemonic_from_dice(&e, MnemonicMode::Raw) {
                Ok(m) => {
                    let raw = &case["raw"];
                    assert_eq!(
                        m.entropy.len() * 8,
                        raw["bits_used"].as_u64().unwrap() as usize,
                        "{name}: bits used"
                    );
                    assert_eq!(
                        hex::encode(&m.entropy),
                        raw["entropy_hex"].as_str().unwrap(),
                        "{name}: raw entropy"
                    );
                    let phrase = m.phrase();
                    assert_eq!(
                        phrase.as_str(),
                        raw["phrase"].as_str().unwrap(),
                        "{name}: raw phrase"
                    );
                    assert_eq!(decode_and_check(&phrase), m.entropy);
                    assert_eq!(
                        hex::encode(seed(&phrase, "")),
                        raw["seed_hex_nopass"].as_str().unwrap(),
                        "{name}: seed without passphrase"
                    );
                    assert_eq!(
                        hex::encode(seed(&phrase, "TREZOR")),
                        raw["seed_hex_trezor"].as_str().unwrap(),
                        "{name}: seed with passphrase"
                    );
                }
                Err(err) => {
                    assert!(
                        case["raw"].is_null(),
                        "{name}: unexpected raw failure: {err}"
                    );
                    assert_eq!(
                        err,
                        Bip39Error::NotEnoughEntropy {
                            bits: e.binary().len()
                        }
                    );
                }
            }

            for (key, words) in [("w12", 12usize), ("w24", 24)] {
                let m = mnemonic_from_dice(&e, MnemonicMode::Words(wc(words))).unwrap();
                assert_eq!(m.words.len(), words, "{name}/{key}: word count");
                assert_eq!(
                    hex::encode(&m.entropy),
                    case[key]["entropy_hex"].as_str().unwrap(),
                    "{name}/{key}: entropy"
                );
                assert_eq!(
                    m.phrase().as_str(),
                    case[key]["phrase"].as_str().unwrap(),
                    "{name}/{key}: phrase"
                );
                assert_eq!(decode_and_check(&m.phrase()), m.entropy);
            }
        }
    }

    // (c) Checksum length edge cases: one checksum bit per 32 entropy bits, three words
    // per 32 bits, at and beyond the standard BIP39 range.
    #[test]
    fn checksum_and_word_count_across_entropy_sizes() {
        for bits in [32usize, 64, 128, 256, 320, 512, MAX_ENTROPY_BITS] {
            let entropy = pattern(bits / 8);
            let m = mnemonic_from_entropy(entropy.clone()).unwrap();
            assert_eq!(m.words.len(), bits * 3 / 32, "word count at ENT {bits}");
            assert_eq!(
                decode_and_check(&m.phrase()),
                entropy,
                "round trip at ENT {bits}"
            );
        }
    }

    #[test]
    fn entropy_above_the_cap_is_rejected() {
        let bits = MAX_ENTROPY_BITS + ENTROPY_BLOCK_BITS;
        let e = DiceEntropy::from_bits(&"1".repeat(bits));
        assert_eq!(
            mnemonic_from_dice(&e, MnemonicMode::Raw).unwrap_err(),
            Bip39Error::EntropyTooLarge { bits }
        );
    }

    /// SPEC step 4 is explicit that the LEADING bits are dropped; a trailing-bit
    /// implementation passes many vectors by luck, so pin it down directly.
    #[test]
    fn raw_mode_discards_leading_bits() {
        let e = DiceEntropy::from_bits(&format!("{}{}", "1".repeat(7), "0".repeat(32)));
        let m = mnemonic_from_dice(&e, MnemonicMode::Raw).unwrap();
        assert_eq!(m.entropy, vec![0u8; 4]);
        assert_eq!(m.phrase().as_str(), "abandon abandon ability");
        assert_eq!(decode_and_check(&m.phrase()), m.entropy);
    }

    #[test]
    fn raw_mode_needs_a_full_block() {
        for bits in 0..ENTROPY_BLOCK_BITS {
            let e = DiceEntropy::from_bits(&"1".repeat(bits));
            assert_eq!(
                mnemonic_from_dice(&e, MnemonicMode::Raw).unwrap_err(),
                Bip39Error::NotEnoughEntropy { bits }
            );
        }
    }

    /// The fixed-word path hashes the digit string, so it is defined even with no rolls
    /// at all - the front end, not this module, is responsible for warning about that.
    ///
    /// `from_bits` is exactly the value that separates the two inputs: plenty of bits, no
    /// digits. A fixed word count must give the same answer for it as for no input at all.
    #[test]
    fn fixed_word_mode_ignores_the_bit_string() {
        let bits_only = DiceEntropy::from_bits(&"1".repeat(256));
        let nothing = crate::entropy::parse_dice("");
        let phrase = |e: &DiceEntropy| {
            mnemonic_from_dice(e, MnemonicMode::Words(wc(12)))
                .expect("the fixed path is defined for any input")
                .phrase()
        };
        assert_eq!(phrase(&bits_only), phrase(&nothing));

        // ... and a different digit string must give a different answer, or the mode is
        // ignoring the dice altogether.
        assert_ne!(
            phrase(&crate::entropy::parse_dice("12345612345612345612")),
            phrase(&nothing)
        );
    }

    /// Unsupported counts are refused where the user's typo lives - at construction - and
    /// are therefore not representable anywhere downstream.
    #[test]
    fn unsupported_word_counts_are_rejected() {
        for words in [0usize, 1, 11, 13, 23, 25, 30] {
            assert_eq!(
                WordCount::new(words).unwrap_err(),
                Bip39Error::UnsupportedWordCount(words.to_string())
            );
        }
        for words in FIXED_WORD_COUNTS {
            let count = wc(words);
            assert_eq!(count.get(), words);
            assert_eq!(count.to_string(), words.to_string());
            assert_eq!(count.entropy_bits() % 8, 0);
            assert_eq!(count.entropy_bits() * 3 / 32, words);
        }
        for bad in ["10", "abc", "", "12.0", "-12", "+12", "012", " 12", "12 "] {
            assert_eq!(
                bad.parse::<MnemonicMode>(),
                Err(Bip39Error::UnsupportedWordCount(bad.to_string()))
            );
        }
        assert_eq!("RAW".parse::<MnemonicMode>().unwrap(), MnemonicMode::Raw);
        assert_eq!(
            "24".parse::<MnemonicMode>().unwrap(),
            MnemonicMode::Words(wc(24))
        );
        assert_eq!(MnemonicMode::Words(wc(15)).to_string(), "15");
        assert_eq!(MnemonicMode::Raw.to_string(), "raw");
    }

    /// The salt side of SPEC step 8: a fullwidth passphrase must fold to its ASCII
    /// compatibility form, or seeds produced here would not match other wallets.
    #[test]
    fn seed_normalizes_the_passphrase() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon about";
        // FULLWIDTH LATIN SMALL LETTERS t, e, s, t.
        let fullwidth = "\u{FF54}\u{FF45}\u{FF53}\u{FF54}";
        assert_eq!(*seed(phrase, fullwidth), *seed(phrase, "test"));
        assert_ne!(*seed(phrase, "test"), *seed(phrase, ""));
    }

    /// The password side of SPEC step 8: the upstream japanese vectors separate words
    /// with U+3000 IDEOGRAPHIC SPACE, which only survives interop because NFKD folds it
    /// to U+0020. The wordlist is irrelevant here - `seed` takes a sentence.
    #[test]
    fn trezor_japanese_seeds_exercise_nfkd() {
        let json = vectors("trezor_vectors.json");
        let cases = json["japanese"].as_array().expect("japanese array");
        for case in cases {
            let phrase = case[1].as_str().unwrap();
            assert!(
                phrase.contains('\u{3000}'),
                "vector lost its ideographic spaces"
            );
            assert_eq!(
                hex::encode(seed(phrase, "TREZOR")),
                case[2].as_str().unwrap()
            );
        }
    }

    /// [`nfkd_secret`] measures the normalized length and then fills a buffer of exactly
    /// that size. Both halves are asserted here: the text must be what a plain `collect`
    /// would have produced, and the buffer must still be the one it started with, because
    /// a buffer that grew is a copy of the phrase nothing wipes.
    #[test]
    fn nfkd_secret_normalizes_exactly_and_never_reallocates() {
        use unicode_normalization::UnicodeNormalization;

        let cases = [
            "",
            "abandon abandon about",
            // Halfwidth katakana with a combining voiced mark, and a fullwidth digit:
            // NFKD both decomposes and folds these, so the output differs from the input
            // in character count and in byte length, in opposite directions.
            "\u{ff71}\u{ff9e}\u{ff10}",
            // The same letter precomposed and decomposed; NFKD leaves only the latter.
            "\u{00c5} A\u{030a}",
            // The shape of the Trezor Japanese vectors: ideographic spaces and kana.
            "\u{3042}\u{3044}\u{3046}\u{3000}\u{3048}\u{304a}",
            // Long enough that an incrementally grown buffer would have doubled several
            // times, which is the case the measuring pass exists for.
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon about",
        ];
        for case in cases {
            let want: String = case.nfkd().collect();
            let got = nfkd_secret(case);
            assert_eq!(*got, want, "{case:?}");
            // Compared against a control rather than against `want.len()`: the claim is
            // that the buffer is the one `String::with_capacity` handed over, whatever
            // rounding that does, not that the allocator returned an exact fit.
            assert_eq!(
                got.capacity(),
                String::with_capacity(want.len()).capacity(),
                "{case:?}: the buffer grew, so an unwiped copy was left behind"
            );
        }
    }

    /// Normalization is the whole of what the seed sees: the words as typed, one space
    /// between them. Case must survive it, because the reference page derives from the
    /// characters the user typed.
    #[test]
    fn a_typed_phrase_is_normalized_to_single_spaces_with_its_case_intact() {
        assert_eq!(
            normalize_phrase("  Zoo\tzoo \n zoo  ").as_str(),
            "Zoo zoo zoo"
        );
        assert_eq!(normalize_phrase("").as_str(), "");
        assert_eq!(normalize_phrase("   \t\r\n ").as_str(), "");
        assert_eq!(normalize_phrase("one").as_str(), "one");
        // Same seed as the page: normalization, not the wordlist, decides what is hashed.
        assert_eq!(
            *seed(&normalize_phrase("  abandon   abandon\tabout "), ""),
            *seed("abandon abandon about", "")
        );
    }

    /// The autocomplete's contract, checked against the whole committed list rather than
    /// a handful of examples: for every prefix length the binary-searched run must equal
    /// the run a linear scan finds, and it must be capped at `max`.
    #[test]
    fn words_with_prefix_matches_a_linear_scan_over_the_whole_wordlist() {
        let list = wordlist();
        for word in list {
            for take in 1..=word.len() {
                let prefix = &word[..take];
                let want: Vec<&str> =
                    list.iter().filter(|w| w.starts_with(prefix)).copied().collect();
                assert_eq!(
                    words_with_prefix(prefix, usize::MAX),
                    want,
                    "prefix {prefix:?}"
                );
                assert_eq!(
                    words_with_prefix(prefix, 4),
                    want[..want.len().min(4)],
                    "prefix {prefix:?} capped at 4"
                );
            }
        }
    }

    /// Case folding, the empty cases, and inputs the wordlist cannot contain. None of
    /// these may panic or return a stray word: the device calls this on every keypress.
    #[test]
    fn words_with_prefix_folds_case_and_refuses_the_degenerate_inputs() {
        assert_eq!(words_with_prefix("ZOO", 4), ["zoo"]);
        assert_eq!(words_with_prefix("Ab", 3), ["abandon", "ability", "able"]);
        assert_eq!(words_with_prefix("aB", 3), words_with_prefix("ab", 3));
        // A prefix that is itself a whole word still lists the longer completions.
        assert_eq!(words_with_prefix("act", 4), ["act", "action", "actor", "actress"]);
        // Empty prefix means "every word", which is no suggestion at all.
        assert!(words_with_prefix("", 4).is_empty());
        assert!(words_with_prefix("abandon", 0).is_empty());
        // Nothing in the list can match these.
        assert!(words_with_prefix("zzz", 4).is_empty());
        assert!(words_with_prefix("abandonment", 4).is_empty());
        assert!(words_with_prefix("ab-", 4).is_empty());
        assert!(words_with_prefix("\u{fc}ber", 4).is_empty());
        assert!(words_with_prefix(" ", 4).is_empty());
    }

    /// The fragment is the token the phrase parser would see, which is what makes it a
    /// sound completion prefix. Whitespace of every flavour ends a word.
    #[test]
    fn current_word_fragment_is_the_last_split_whitespace_token() {
        for text in [
            "",
            "abandon",
            "abandon ",
            "  ",
            "abandon about",
            "abandon  ab",
            "abandon\tab",
            "abandon\r\n",
            "zoo zoo z",
            "\u{a0}ab",
        ] {
            let want = if text.ends_with(char::is_whitespace) {
                ""
            } else {
                text.split_whitespace().next_back().unwrap_or("")
            };
            assert_eq!(current_word_fragment(text), want, "{text:?}");
        }
    }

    /// Every official vector is a well formed phrase, so the checker must accept all 24 and
    /// recover exactly the entropy the vector was built from.
    #[test]
    fn check_phrase_accepts_the_trezor_vectors_and_recovers_their_entropy() {
        let json = vectors("trezor_vectors.json");
        for case in json["english"].as_array().expect("english array") {
            let entropy_hex = case[0].as_str().unwrap();
            let phrase = case[1].as_str().unwrap();
            let check = check_phrase(phrase);
            assert_eq!(check.checksum, Checksum::Valid, "{phrase}");
            assert_eq!(check.word_count, phrase.split(' ').count());
            assert!(check.unknown_words.is_empty(), "{phrase}");
            assert_eq!(hex::encode(&check.entropy), entropy_hex);
        }
    }

    /// The final-word helper, checked against the checker rather than against a fixture:
    /// every word it offers must produce a valid phrase, and it must offer EVERY word
    /// that would. The second half is what makes it a helper instead of a shortlist - a
    /// user whose missing word is not on the list would be told their backup is wrong.
    #[test]
    fn every_valid_last_word_is_offered_and_every_offered_word_is_valid() {
        // Word count -> how many of the 2048 words can complete it: 2^(ENT - 11 * typed).
        for (typed_count, expected) in [(11usize, 128usize), (14, 64), (17, 32), (20, 16), (23, 8)]
        {
            let head = ["abandon"; 1].repeat(typed_count).join(" ");
            let offered = valid_last_words(&head);
            assert_eq!(offered.len(), expected, "{typed_count} words typed");

            for word in &offered {
                assert_eq!(
                    check_phrase(&format!("{head} {word}")).checksum,
                    Checksum::Valid,
                    "{typed_count} + {word} was offered but does not check out"
                );
            }
            // ...and nothing else in the list does. The brute-force half is the one that
            // catches an off-by-one in the checksum bit packing, which would still yield
            // a plausible-looking list of the right length.
            let all_valid: Vec<&str> = wordlist()
                .iter()
                .copied()
                .filter(|w| check_phrase(&format!("{head} {w}")).checksum == Checksum::Valid)
                .collect();
            assert_eq!(offered, all_valid, "{typed_count} words typed");
        }
    }

    /// The canonical vector's own last word is on its own list, and the list is sorted.
    #[test]
    fn the_test_vector_last_word_is_offered_in_wordlist_order() {
        let head = ["abandon"; 11].join(" ");
        let offered = valid_last_words(&head);
        assert!(offered.contains(&"about"), "the BIP39 vector #1 last word must be offered");
        let mut sorted = offered.clone();
        sorted.sort_unstable();
        assert_eq!(offered, sorted, "the helper must come out in wordlist order");
    }

    /// The helper answers only where a last word is actually determined, and refuses to
    /// invent candidates for a phrase it cannot read.
    #[test]
    fn the_final_word_helper_declines_everything_that_is_not_one_word_short() {
        // Counts that are not one short of 12/15/18/21/24.
        for n in [0usize, 1, 5, 10, 12, 13, 15, 24, 25] {
            let head = vec!["abandon"; n].join(" ");
            assert!(valid_last_words(&head).is_empty(), "{n} words must offer nothing");
        }
        // One short, but with a word the list does not have: there is no entropy to
        // complete, and a candidate offered here would belong to a phrase nobody typed.
        let mut head = ["abandon"; 10].to_vec();
        head.push("notaword");
        assert!(valid_last_words(&head.join(" ")).is_empty());
        // Case is folded for the lookup, exactly as `check_phrase` folds it.
        assert_eq!(valid_last_words(&["ABANDON"; 11].join(" ")).len(), 128);
    }

    /// The three things the checker is there to report, each on the phrase that produces it.
    #[test]
    fn check_phrase_reports_unknown_words_a_bad_checksum_and_an_unusable_word_count() {
        const VALID: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                             abandon abandon abandon about";

        // One word swapped for another list word: the entropy still decodes, the checksum
        // does not hold.
        let flipped = VALID.replacen("about", "abandon", 1);
        let check = check_phrase(&flipped);
        assert_eq!(check.checksum, Checksum::Invalid);
        assert!(check.unknown_words.is_empty());
        assert_eq!(check.entropy.len(), 16, "ENT is still readable");

        // Case is not a spelling mistake, and the listing quotes what was typed.
        assert_eq!(
            check_phrase("ZOO Zoo zoo").unknown_words,
            Vec::<String>::new()
        );
        let check = check_phrase("abandon notaword abandon Nonsense");
        assert_eq!(check.word_count, 4);
        assert_eq!(check.unknown_words, vec!["notaword", "Nonsense"]);
        assert_eq!(check.checksum, Checksum::NotApplicable);
        assert!(check.entropy.is_empty());

        // Counts that encode no checksum: not a multiple of three, and empty.
        for phrase in [
            "abandon",
            "abandon abandon",
            "abandon abandon abandon abandon",
            "",
        ] {
            assert_eq!(
                check_phrase(phrase).checksum,
                Checksum::NotApplicable,
                "{phrase:?}"
            );
        }

        // 30 words is the raw-mode shape this program itself produces, and it checks out.
        let long = mnemonic_from_entropy(pattern(40)).unwrap();
        assert_eq!(long.words.len(), 30);
        assert_eq!(check_phrase(&long.phrase()).checksum, Checksum::Valid);

        // Past the checksum budget of one digest there is nothing to check against.
        let huge = "abandon ".repeat(MAX_ENTROPY_BITS / 32 * 3 + 3);
        assert_eq!(check_phrase(&huge).checksum, Checksum::NotApplicable);
    }

    #[test]
    fn error_messages_are_ascii_and_actionable() {
        let messages = [
            Bip39Error::NotEnoughEntropy { bits: 6 }.to_string(),
            Bip39Error::UnsupportedWordCount("7".into()).to_string(),
            Bip39Error::EntropyTooLarge { bits: 8224 }.to_string(),
        ];
        for m in &messages {
            assert!(m.is_ascii(), "message must be ASCII: {m}");
            assert!(!m.ends_with(' '));
        }
        assert!(messages[0].contains("6 bit(s)"));
        // These three numbers also appear in the desktop CLI's warning and help text, which
        // call this same function; a second definition of the 5/3 ratio would drift from
        // them.
        assert!(messages[0].contains(&rolls_for_bits(MIN_SECURE_BITS).to_string()));
        assert_eq!(rolls_for_bits(32), 20);
        assert_eq!(rolls_for_bits(128), 77);
        assert_eq!(rolls_for_bits(256), 154);
    }
}

