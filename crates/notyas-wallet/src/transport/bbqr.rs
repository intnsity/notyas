// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! BBQr: the Coldcard family's animated-QR format.
//!
//! Eight characters of header and then base32, which is the whole protocol:
//!
//! ```text
//! B$        the two characters that say "this is BBQr"
//! 2         data encoding: H hex, 2 base32, Z deflate then base32
//! P         file type: P PSBT, T transaction, U unicode text, ...
//! 04        parts in the series, two digits of base 36
//! 00        which part this is, two digits of base 36, counting from zero
//! ```
//!
//! There is no checksum, no sequence beyond the index, and no fountain: the parts are the
//! payload cut into equal pieces, and a reader needs every one of them. That is a real step
//! down from UR2 - a dropped frame has to come round again - and it buys interoperability
//! with the Coldcard Q, Sparrow, Nunchuk and everything else that reads this format. UR2 is
//! the primary transport for that reason; this one is offered beside it.
//!
//! # What this encoder does and does not emit
//!
//! **Base32 only.** Of the three encodings, hex wastes a third of every symbol and buys
//! nothing an encoder wants, and `Z` prescribes raw deflate at `wbits=10`, which means a
//! compressor in the firmware image. The specification requires *readers* to implement all
//! three and lets writers pick, in as many words: "For QR creators, they are free to pick
//! the encoding they prefer." A 30% smaller PSBT is not worth a compression library inside
//! a signing device, so the choice here is base32 and the frames are correspondingly longer
//! than a Coldcard's.
//!
//! **Balanced parts, not packed ones.** Every part but the last is the same length, which
//! the format requires so a reader can place a part it receives out of order. Which length
//! is left open, and the specification asks for the parts to be even: "If you are doing 3
//! QR codes, best if all have about the same amount of data, don't just have a small runt
//! QR at the end, because you are making the QR's harder to read." So the payload is spread
//! over the fewest parts the caller's density allows rather than packed into full ones.
//!
//! # The symbol these strings belong in
//!
//! BBQr's density argument rests on the QR alphanumeric mode, which spends 5.5 bits per
//! character against byte mode's 8. Every character this module emits - `B`, `$`, the
//! encoding and type letters, base 36 and base32 - is inside that character set, so the
//! strings are ready for it. `notyas_core::qr` encodes in byte mode today, which costs
//! about 45% more symbol for the same string; the strings are still correct and every
//! reader accepts them, and closing the gap is a change to the symbol encoder rather than
//! to this module.

use alloc::string::String;

use super::{TransportError, MAX_PARTS};

/// Characters of header on every frame.
const HEADER_LEN: usize = 8;

/// Bytes that base32 turns into a whole number of characters. A part that is not a
/// multiple of this cannot be decoded on its own, which the format forbids for every part
/// but the last.
const GROUP_BYTES: usize = 5;

/// Characters those bytes turn into.
const GROUP_CHARS: usize = 8;

/// A BBQr series over one payload.
pub(super) struct Encoder {
    /// The file-type character, `P`, `T` or `U`.
    file_type: char,
    /// The whole payload in base32. Held encoded rather than raw because a part boundary at
    /// a multiple of [`GROUP_BYTES`] is a boundary at a multiple of [`GROUP_CHARS`] in the
    /// text, so cutting the text is the same operation as cutting the payload and saves
    /// re-encoding a fragment on every frame.
    text: String,
    /// Characters per part, except the last.
    chunk: usize,
    count: u32,
}

impl core::fmt::Debug for Encoder {
    /// Shape only, for the same reason [`super::ur::Encoder`]'s is: identity, not contents.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("bbqr::Encoder")
            .field("type", &self.file_type)
            .field("parts", &self.count)
            .field("chars", &self.chunk)
            .finish()
    }
}

impl Encoder {
    /// Prepare a series for `payload` under `file_type`, with no part carrying more than
    /// `max_fragment` bytes of it.
    ///
    /// The effective part size is rounded down to a multiple of [`GROUP_BYTES`], so a
    /// `max_fragment` of 200 yields parts of at most 200 bytes and one of 202 yields the
    /// same 200.
    ///
    /// # Errors
    ///
    /// [`TransportError::EmptyPayload`] for an empty payload,
    /// [`TransportError::FragmentTooSmall`] when `max_fragment` is under one base32 group,
    /// and [`TransportError::TooManyParts`] when the series would not fit the two base 36
    /// digits the header has for a part count.
    pub(super) fn new(
        file_type: char,
        payload: &[u8],
        max_fragment: usize,
    ) -> Result<Encoder, TransportError> {
        if payload.is_empty() {
            return Err(TransportError::EmptyPayload);
        }
        let groups = max_fragment.checked_div(GROUP_BYTES).unwrap_or(0);
        if groups == 0 {
            return Err(TransportError::FragmentTooSmall {
                minimum: GROUP_BYTES,
            });
        }

        // Spread the payload over the fewest parts the cap allows, then round the part back
        // up to whole base32 groups. That rounding cannot push it past the cap: the balanced
        // size is already at or below a cap that is itself a multiple of the group.
        let cap = groups.saturating_mul(GROUP_BYTES);
        let balanced = payload.len().div_ceil(payload.len().div_ceil(cap));
        let part = balanced.div_ceil(GROUP_BYTES).saturating_mul(GROUP_BYTES);

        let text = base32(payload);
        let chunk = part
            .checked_div(GROUP_BYTES)
            .unwrap_or(1)
            .saturating_mul(GROUP_CHARS);
        let count = u32::try_from(text.len().div_ceil(chunk.max(1)))
            .ok()
            .filter(|&n| (1..=MAX_PARTS).contains(&n))
            .ok_or(TransportError::TooManyParts { limit: MAX_PARTS })?;

        Ok(Encoder {
            file_type,
            text,
            chunk,
            count,
        })
    }

    /// How many parts carry the payload. A reader needs all of them.
    pub(super) fn part_count(&self) -> u32 {
        self.count
    }

    /// The complete BBQr string for frame `n`, counting from zero.
    ///
    /// The series has no frames beyond its parts, so the animation cycles: frame
    /// `part_count` is part zero again.
    pub(super) fn frame(&self, n: u32) -> String {
        let index = n.checked_rem(self.count).unwrap_or(0);
        let start = (index as usize).saturating_mul(self.chunk);
        let end = start.saturating_add(self.chunk).min(self.text.len());
        let body = self.text.get(start..end).unwrap_or("");

        let mut out = String::with_capacity(HEADER_LEN.saturating_add(body.len()));
        out.push_str("B$2");
        out.push(self.file_type);
        for digit in base36(self.count).into_iter().chain(base36(index)) {
            out.push(char::from(digit));
        }
        out.push_str(body);
        out
    }
}

/// `value` as two digits of base 36, most significant first.
///
/// Values over 1295 cannot be written in two digits; the caller has already refused those,
/// and the saturation here keeps the refusal from turning into a panic if it ever slips.
fn base36(value: u32) -> [u8; 2] {
    const DIGITS: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let value = value.min(1295) as usize;
    let high = value.checked_div(36).unwrap_or(0);
    let low = value.checked_rem(36).unwrap_or(0);
    [
        DIGITS.get(high).copied().unwrap_or(b'0'),
        DIGITS.get(low).copied().unwrap_or(b'0'),
    ]
}

/// RFC 4648 base32, standard alphabet, no padding.
///
/// Padding is not merely unnecessary here, it is illegal: `=` is outside the QR
/// alphanumeric character set, and the format keeps every part a whole number of groups so
/// that there is nothing to pad except at the very end.
fn base32(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    /// Characters a group of 1 to 5 bytes turns into.
    const CHARS: [usize; 6] = [0, 2, 4, 5, 7, 8];
    /// Bit positions of each character within a 40-bit group held in the low bits of a u64.
    const SHIFTS: [u32; GROUP_CHARS] = [35, 30, 25, 20, 15, 10, 5, 0];

    let mut out =
        String::with_capacity(data.len().div_ceil(GROUP_BYTES).saturating_mul(GROUP_CHARS));
    for group in data.chunks(GROUP_BYTES) {
        let mut bytes = [0u8; GROUP_BYTES];
        for (slot, &byte) in bytes.iter_mut().zip(group) {
            *slot = byte;
        }
        let [a, b, c, d, e] = bytes;
        let packed = u64::from_be_bytes([0, 0, 0, a, b, c, d, e]);
        let chars = CHARS.get(group.len()).copied().unwrap_or(GROUP_CHARS);
        for &shift in SHIFTS.iter().take(chars) {
            let index = (packed.wrapping_shr(shift) & 0x1f) as usize;
            out.push(char::from(ALPHABET.get(index).copied().unwrap_or(b'A')));
        }
    }
    out
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
    use crate::transport::fountain::tests::make_message;
    use alloc::vec::Vec;

    /// Inverse of [`base32`]. Test-only, like every decoder in this module tree.
    fn unbase32(text: &str) -> Option<Vec<u8>> {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut out = Vec::with_capacity(text.len() * GROUP_BYTES / GROUP_CHARS);
        for group in text.as_bytes().chunks(GROUP_CHARS) {
            let mut packed = 0u64;
            for i in 0..GROUP_CHARS {
                let value = match group.get(i) {
                    Some(&c) => ALPHABET.iter().position(|&a| a == c)? as u64,
                    None => 0,
                };
                packed = (packed << 5) | value;
            }
            // A partial group carries 2, 4, 5 or 7 characters for 1, 2, 3 or 4 bytes.
            let bytes = group.len() * 5 / 8;
            out.extend_from_slice(&packed.to_be_bytes()[3..3 + bytes]);
        }
        Some(out)
    }

    /// Reassemble a whole series, checking the header of every part as it goes.
    pub(in crate::transport) fn join(frames: &[String]) -> Option<(char, Vec<u8>)> {
        let mut file_type = None;
        let mut bodies: Vec<Option<&str>> = Vec::new();
        for frame in frames {
            let header = frame.get(..HEADER_LEN)?;
            assert_eq!(header.get(..3)?, "B$2");
            let ft = header.chars().nth(3)?;
            assert!(*file_type.get_or_insert(ft) == ft, "type changed mid-series");
            let count = usize::from_str_radix(header.get(4..6)?, 36).ok()?;
            let index = usize::from_str_radix(header.get(6..8)?, 36).ok()?;
            bodies.resize(count, None);
            *bodies.get_mut(index)? = Some(frame.get(HEADER_LEN..)?);
        }
        let mut text = String::new();
        for body in bodies {
            text.push_str(body?);
        }
        Some((file_type?, unbase32(&text)?))
    }

    /// RFC 4648's own base32 vectors, which pin the alphabet, the bit order and the refusal
    /// to pad in one go.
    #[test]
    fn published_base32_vectors() {
        const VECTORS: [(&str, &str); 7] = [
            ("", ""),
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ];
        for (input, want) in VECTORS {
            assert_eq!(base32(input.as_bytes()), want, "{input:?}");
            assert_eq!(unbase32(want).unwrap(), input.as_bytes(), "{input:?}");
        }
    }

    /// Base 36, at the three places it matters: the low digit rolling over, the top of the
    /// range, and a part count that needs both digits.
    #[test]
    fn two_digit_base36() {
        assert_eq!(base36(0), *b"00");
        assert_eq!(base36(9), *b"09");
        assert_eq!(base36(10), *b"0A");
        assert_eq!(base36(35), *b"0Z");
        assert_eq!(base36(36), *b"10");
        assert_eq!(base36(1295), *b"ZZ");
        assert_eq!(base36(u32::MAX), *b"ZZ", "saturates rather than wrapping");
    }

    /// The header the specification spells out for an unsplit payload, and the shape of a
    /// split one. Zero-based index, one-based count, and the first six characters constant
    /// across the series.
    #[test]
    fn header_shape() {
        let encoder = Encoder::new('P', b"hello", 200).unwrap();
        assert_eq!(encoder.part_count(), 1);
        assert_eq!(encoder.frame(0), "B$2P0100NBSWY3DP");

        let encoder = Encoder::new('T', &make_message("bbqr", 300), 100).unwrap();
        assert_eq!(encoder.part_count(), 3);
        let frames: Vec<String> = (0..3).map(|n| encoder.frame(n)).collect();
        assert_eq!(&frames[0][..8], "B$2T0300");
        assert_eq!(&frames[1][..8], "B$2T0301");
        assert_eq!(&frames[2][..8], "B$2T0302");
        // The series cycles rather than running out.
        assert_eq!(encoder.frame(3), frames[0]);
        assert_eq!(encoder.frame(4), frames[1]);
    }

    /// A whole series, character for character, against strings produced by CPython's
    /// `base64.b32encode` driven through the reference splitter's algorithm. Self-generated
    /// in the sense that the BBQr project publishes no vector file, but not self-checked:
    /// the base32 comes from an implementation this crate had no hand in, and the header
    /// comes from the specification text.
    #[test]
    fn generated_series_vector() {
        const EXPECTED: [&str; 4] = [
            "B$2P0400IEHV6NGVN5EVZ5Y7NDCE2FDDWCOJDRCYD27Q673OOU5DEVVNOZRMYEYVBYHPWKISSTZFLCOWEAIEVF64ORLEIZZTYC2XV3F7XXWO4TS2M5JRLYATZPEJ4SJGWSFQUH63O3OL3ACPSWLPU35YF2QBZFDZ7SOWDPLVHL4PJATXZM66R4YM6CENDIXYEAZW5MIXZTYXMZIZ",
            "B$2P0401JL4CA52TLTT7F6YGEYO2G6S6FABB3GJN6E3QP66OM745RWT553JVRDBQB6ECLSZB2YT55EMECQLHJPR5TCCOJ46P4SYJ36JZA3YDVG3AADFCURTMNVHNHQ4KVOHXPG3ZWUHT3KCQDABAQG6DMBU3YGXM2WZAWTIBIJ4DAFK3QZ7DZVKSR4YIQFZGKZFPCHA34DCXCB6B",
            "B$2P04024YMBOXINTQOGGLD3NI6FWVV2WFUQWJGG5WVXZW7EMI66ECCYEZ74G7S4TDWPU2KYHWZPXAKMGTZ2JPGAKKTFINIFR57V5QKZTRCQHHWXGBVVLA5JF6HACOSZDIO7SEEUGFZU23QCP7FGREOAKER6WMOHJVLLVTDPZ4YG2GJQDFAHNGERALYQFJSOFJH4L5ZUARXUS7HT",
            "B$2P0403YXO35VUW5IKP3FAJ4HVA2KGI5T5ZYGIACGD72PX4HSKJIKCVW3SHSGIWRI2H7TCMTHXTGCZNCXKIQQVIEACL444GD4F4FLJ5TAT5G2XT7RP4VGUGCCCGOB5KB36IZ45OHQXCQ5N7WP4NPDYUQNFI4B4IX3OK7JQIKZEGBIM22SG5QKOP7JON45QT5T6IU6U7KKQFMY4P",
        ];
        let payload = make_message("notyas-bbqr", 500);
        let encoder = Encoder::new('P', &payload, 128).unwrap();
        assert_eq!(encoder.part_count(), 4);
        let frames: Vec<String> = (0..4).map(|n| encoder.frame(n)).collect();
        for (i, want) in EXPECTED.iter().enumerate() {
            assert_eq!(frames[i], *want, "part {i}");
        }
        assert_eq!(join(&frames).unwrap(), ('P', payload));
    }

    /// Every part but the last is the same length, and none of them carries more than the
    /// caller's cap. The first is what lets a reader place an out-of-order part; the second
    /// is what the density steps are for.
    #[test]
    fn parts_are_equal_and_within_the_cap() {
        for cap in [5usize, 32, 100, 200, 1000] {
            for len in [1usize, 4, 5, 6, 99, 100, 101, 1024, 9999] {
                let payload = make_message("notyas-bbqr-shape", len);
                let encoder = match Encoder::new('P', &payload, cap) {
                    Ok(encoder) => encoder,
                    // 9999 bytes at five to a part is over the two-base-36-digit ceiling.
                    Err(TransportError::TooManyParts { .. }) => continue,
                    Err(other) => panic!("cap {cap} len {len}: {other:?}"),
                };
                let frames: Vec<String> =
                    (0..encoder.part_count()).map(|n| encoder.frame(n)).collect();
                let bodies: Vec<usize> = frames.iter().map(|f| f.len() - HEADER_LEN).collect();
                let first = bodies[0];
                assert!(first * GROUP_BYTES / GROUP_CHARS <= cap, "cap {cap} len {len}");
                for (i, &body) in bodies.iter().enumerate() {
                    if i + 1 < bodies.len() {
                        assert_eq!(body, first, "cap {cap} len {len} part {i}");
                    } else {
                        assert!(body <= first && body > 0, "cap {cap} len {len} runt");
                    }
                }
            }
        }
    }

    /// The round-trip property, over the same bracket of payload sizes and density steps
    /// the UR encoder is held to.
    #[test]
    fn round_trips_over_sizes_and_capacities() {
        for len in [1usize, 2, 5, 31, 32, 33, 100, 255, 256, 257, 999, 4096, 20_001] {
            for cap in [10usize, 30, 100, 200, 400, 1000] {
                let payload = make_message("notyas-bbqr-rt", len);
                let encoder = match Encoder::new('U', &payload, cap) {
                    Ok(encoder) => encoder,
                    Err(TransportError::TooManyParts { .. }) => continue,
                    Err(other) => panic!("len {len} cap {cap}: {other:?}"),
                };
                let frames: Vec<String> =
                    (0..encoder.part_count()).map(|n| encoder.frame(n)).collect();
                assert_eq!(join(&frames).unwrap(), ('U', payload), "len {len} cap {cap}");
            }
        }
    }

    /// A reader that gets the parts out of order still reassembles, which is the one thing
    /// the header's index buys over a bare sequence.
    #[test]
    fn parts_may_arrive_in_any_order() {
        let payload = make_message("notyas-bbqr-order", 2000);
        let encoder = Encoder::new('P', &payload, 200).unwrap();
        let mut frames: Vec<String> = (0..encoder.part_count()).map(|n| encoder.frame(n)).collect();
        frames.reverse();
        assert_eq!(join(&frames).unwrap(), ('P', payload));
    }

    /// Refusals. The part cap is the specification's own: two digits of base 36.
    #[test]
    fn construction_refuses_what_it_cannot_encode() {
        assert_eq!(
            Encoder::new('P', &[], 200).unwrap_err(),
            TransportError::EmptyPayload
        );
        assert_eq!(
            Encoder::new('P', b"x", 4).unwrap_err(),
            TransportError::FragmentTooSmall { minimum: 5 }
        );
        let big = alloc::vec![0u8; MAX_PARTS as usize * 5 + 5];
        assert_eq!(
            Encoder::new('P', &big, 5).unwrap_err(),
            TransportError::TooManyParts { limit: MAX_PARTS }
        );
    }
}
