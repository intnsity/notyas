// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Bytewords: the byte-to-word alphabet a UR string is written in (BCR-2020-012).
//!
//! Two hundred and fifty six four-letter English words, one per byte value, chosen so that
//! no two share both their first and their last letter. That property is the whole point of
//! the "minimal" style this module emits: a byte becomes exactly two characters, the first
//! and last letter of its word, and the word is still recoverable from the pair. Standard
//! style (whole words, spaces) and URI style (whole words, hyphens) exist so a person can
//! read a payload aloud; a QR frame is never read aloud, so the encoder ships only the dense
//! form and the tests reconstruct standard style to pin all four letters of every word.
//!
//! Every bytewords string carries a CRC-32 of its payload in its last four bytes, mapped to
//! words like any other byte. The checksum belongs to the encoding rather than to the
//! payload: a decoder strips and verifies it, and a caller of this module never sees it.
//!
//! Encoding only. Decoding is m11's scope - camera scan-in - and none of it belongs in the
//! device image before then; the decoder below is behind `cfg(test)` and exists so the
//! encoder can be proven to round-trip.

use alloc::string::String;

use super::checksum::crc32;

/// The alphabet, concatenated in byte-value order. One string rather than an array of 256
/// `&str`, because on a 32-bit target that array spends 2 KB of fat pointers to index 1 KB
/// of letters - and the concatenated form is how BCR-2020-012 publishes the list, so it can
/// be diffed against the spec by eye.
const WORDS: &str = "\
    ableacidalsoapexaquaarchatomauntawayaxisbackbaldbarnbeltbetabias\
    bluebodybragbrewbulbbuzzcalmcashcatschefcityclawcodecolacookcost\
    cruxcurlcuspcyandarkdatadaysdelidicedietdoordowndrawdropdrumdull\
    dutyeacheasyechoedgeepicevenexamexiteyesfactfairfernfigsfilmfish\
    fizzflapflewfluxfoxyfreefrogfuelfundgalagamegeargemsgiftgirlglow\
    goodgraygrimgurugushgyrohalfhanghardhawkheathelphighhillholyhope\
    hornhutsicedideaidleinchinkyintoirisironitemjadejazzjoinjoltjowl\
    judojugsjumpjunkjurykeepkenokeptkeyskickkilnkingkitekiwiknoblamb\
    lavalazyleaflegsliarlimplionlistlogoloudloveluaulucklungmainmany\
    mathmazememomenumeowmildmintmissmonknailnavyneednewsnextnoonnote\
    numbobeyoboeomitonyxopenovalowlspaidpartpeckplaypluspoempoolpose\
    puffpumapurrquadquizraceramprealredorichroadrockroofrubyruinruns\
    rustsafesagascarsetssilkskewslotsoapsolosongstubsurfswantacotask\
    taxitenttiedtimetinytoiltombtoystriptunatwinuglyundouniturgeuser\
    vastveryvetovialvibeviewvisavoidvowswallwandwarmwaspwavewaxywebs\
    whatwhenwhizwolfworkyankyawnyellyogayurtzapszerozestzinczonezoom";

/// Letters per word. Fixed by the alphabet, not a tuning knob.
const WORD_LEN: usize = 4;

/// Append the minimal-style bytewords for `payload` - its bytes and then its CRC-32, two
/// characters each - to `out`.
///
/// Appends rather than returns so that a caller assembling a UR string fills one
/// allocation: the scheme, the type, the sequence header and the body all land in the same
/// `String`.
pub(super) fn append_minimal(out: &mut String, payload: &[u8]) {
    let crc = crc32(payload).to_be_bytes();
    out.reserve(payload.len().saturating_add(crc.len()).saturating_mul(2));
    for &byte in payload.iter().chain(crc.iter()) {
        let [first, last] = minimal_pair(byte);
        out.push(char::from(first));
        out.push(char::from(last));
    }
}

/// The two letters that stand for `byte`: the first and the last of its word.
fn minimal_pair(byte: u8) -> [u8; 2] {
    let pair = WORDS
        .as_bytes()
        .chunks_exact(WORD_LEN)
        .nth(usize::from(byte))
        .and_then(|word| Some([*word.first()?, *word.last()?]));

    // `WORDS` is exactly 256 four-letter words, so the lookup cannot miss. The fallback is
    // the shape of that proof the compiler can check: the crate forbids the indexing
    // operator, which would state the same invariant as a panic - and a panic here would
    // end a signing session over an unreachable arithmetic edge.
    pair.unwrap_or(*b"ae")
}

// ---------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------

#[cfg(test)]
// A test asserts by panicking, which is what a test is for. The crate-wide bans on
// panicking constructs exist to keep a panic out of the device image, and nothing below
// compiles into one.
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::integer_division_remainder_used
)]
pub(super) mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// The whole word for `byte`. Only the tests need it: the encoder emits two letters,
    /// and the spec's other two styles exist for people rather than for QR frames.
    fn word(byte: u8) -> &'static str {
        &WORDS[usize::from(byte) * WORD_LEN..][..WORD_LEN]
    }

    /// Standard style: whole words, single spaces. Reconstructed here so that the published
    /// standard-style vector can pin all four letters of every word it touches, which the
    /// minimal form cannot.
    fn encode_standard(payload: &[u8]) -> String {
        let crc = crc32(payload).to_be_bytes();
        payload
            .iter()
            .chain(crc.iter())
            .map(|&b| word(b))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Minimal style, as a fresh string. The encoder appends; the tests compare.
    pub(in crate::transport) fn encode_minimal(payload: &[u8]) -> String {
        let mut out = String::new();
        append_minimal(&mut out, payload);
        out
    }

    /// Inverse of [`encode_minimal`], checksum included. Test-only, deliberately: decoding
    /// is m11's scope and no part of it belongs in the device image at m8.
    pub(in crate::transport) fn decode_minimal(text: &str) -> Option<Vec<u8>> {
        let bytes = text.as_bytes();
        if bytes.len() % 2 != 0 {
            return None;
        }
        let mut out = Vec::with_capacity(bytes.len() / 2);
        for pair in bytes.chunks_exact(2) {
            out.push((0..=u8::MAX).find(|&b| minimal_pair(b) == [pair[0], pair[1]])?);
        }
        // The last four bytes are the checksum, not payload.
        let (payload, want) = out.split_at(out.len().checked_sub(4)?);
        if crc32(payload).to_be_bytes() != want {
            return None;
        }
        Some(payload.to_vec())
    }

    /// The alphabet is 256 distinct four-letter lowercase words whose first-and-last letter
    /// pairs are also distinct. Every one of those is load-bearing: the count indexes a
    /// byte, the length fixes the offset arithmetic, and the distinctness of the pairs is
    /// what makes the minimal style reversible at all.
    #[test]
    fn alphabet_is_well_formed() {
        assert_eq!(WORDS.len(), 256 * WORD_LEN);
        assert!(WORDS.bytes().all(|b| b.is_ascii_lowercase()));

        let mut words: Vec<&str> = (0..=u8::MAX).map(word).collect();
        words.sort_unstable();
        words.dedup();
        assert_eq!(words.len(), 256, "words are not distinct");

        let mut pairs: Vec<[u8; 2]> = (0..=u8::MAX).map(minimal_pair).collect();
        pairs.sort_unstable();
        pairs.dedup();
        assert_eq!(pairs.len(), 256, "minimal pairs are not distinct");
    }

    /// The alphabet's anchors, spelled out. If the table is ever regenerated these say
    /// immediately whether it moved.
    #[test]
    fn alphabet_anchors() {
        assert_eq!(word(0), "able");
        assert_eq!(word(1), "acid");
        assert_eq!(word(128), "lava");
        assert_eq!(word(255), "zoom");
    }

    /// BCR-2020-012's own vector, in both published styles. `jade need echo taxi` is the
    /// appended CRC-32 of `[0, 1, 2, 128, 255]`, which is where the checksum being part of
    /// the encoding rather than of the payload becomes visible.
    #[test]
    fn published_five_byte_vector() {
        const INPUT: [u8; 5] = [0, 1, 2, 128, 255];
        assert_eq!(
            encode_standard(&INPUT),
            "able acid also lava zoom jade need echo taxi"
        );
        assert_eq!(encode_minimal(&INPUT), "aeadaolazmjendeoti");
        assert_eq!(decode_minimal("aeadaolazmjendeoti").unwrap(), INPUT);
    }

    /// bc-ur's 100-byte vector, both styles. Long enough that a transposed word or a
    /// byte-order slip in the appended checksum cannot survive it.
    #[test]
    fn published_hundred_byte_vector() {
        const INPUT: [u8; 100] = [
            245, 215, 20, 198, 241, 235, 69, 59, 209, 205, 165, 18, 150, 158, 116, 135, 229, 212,
            19, 159, 17, 37, 239, 240, 253, 11, 109, 191, 37, 242, 38, 120, 223, 41, 156, 189, 242,
            254, 147, 204, 66, 163, 216, 175, 191, 72, 169, 54, 32, 60, 144, 230, 210, 137, 184,
            197, 33, 113, 88, 14, 157, 31, 177, 46, 1, 115, 205, 69, 225, 150, 65, 235, 58, 144,
            65, 240, 133, 69, 113, 247, 63, 53, 242, 165, 160, 144, 26, 13, 79, 237, 133, 71, 82,
            69, 254, 165, 138, 41, 85, 24,
        ];
        const STANDARD: &str = "yank toys bulb skew when warm free fair tent swan open brag mint \
            noon jury list view tiny brew note body data webs what zinc bald join runs data whiz \
            days keys user diet news ruby whiz zone menu surf flew omit trip pose runs fund part \
            even crux fern math visa tied loud redo silk curl jugs hard beta next cost puma drum \
            acid junk swan free very mint flap warm fact math flap what limp free jugs yell fish \
            epic whiz open numb math city belt glow wave limp fuel grim free zone open love diet \
            gyro cats fizz holy city puff";
        const MINIMAL: &str = "yktsbbswwnwmfefrttsnonbgmtnnjyltvwtybwnebydawswtzcbdjnrsdawzdsks\
            urdtnsrywzzemusffwottppersfdptencxfnmhvatdldroskcljshdbantctpadmadjksnfevymtfpwmftmhfp\
            wtlpfejsylfhecwzonnbmhcybtgwwelpflgmfezeonledtgocsfzhycypf";

        assert_eq!(encode_standard(&INPUT), STANDARD);
        assert_eq!(encode_minimal(&INPUT), MINIMAL);
        assert_eq!(decode_minimal(MINIMAL).unwrap(), INPUT);
    }

    /// Every byte value survives a round trip, and the empty payload encodes to its bare
    /// checksum rather than to nothing.
    #[test]
    fn round_trips_every_byte_and_the_empty_payload() {
        let all: Vec<u8> = (0..=u8::MAX).collect();
        assert_eq!(decode_minimal(&encode_minimal(&all)).unwrap(), all);

        let empty = encode_minimal(&[]);
        assert_eq!(empty.len(), 8, "four checksum bytes, two characters each");
        assert!(decode_minimal(&empty).unwrap().is_empty());
    }

    /// Corruption is refused rather than decoded into whatever it happens to spell.
    /// `aeadaolazojendeowf` is the published vector with two words changed, and bc-ur pins
    /// the same refusal.
    #[test]
    fn corruption_is_refused() {
        assert!(decode_minimal("aeadaolazojendeowf").is_none(), "bad checksum");
        assert!(decode_minimal("aeadaolazmjendeot").is_none(), "odd length");
        assert!(decode_minimal("zzzzzzzzzzzz").is_none(), "not a word pair");
    }
}
