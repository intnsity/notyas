// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! UR2 strings: `ur:crypto-psbt/...`, single part and multi part (BCR-2020-005).
//!
//! A UR is a URI whose body is a CBOR item written in bytewords. When the item fits in one
//! symbol the string is `ur:<type>/<bytewords>` and there is nothing else to say. When it
//! does not, the item is fragmented and each frame carries a five-element CBOR array -
//! sequence number, sequence count, message length, message checksum, fragment - which is
//! itself written in bytewords and prefixed with `<seq>-<seqLen>/` so a reader can see the
//! shape before decoding anything.
//!
//! The payload item for both `ur:crypto-psbt` and `ur:bytes` is a CBOR byte string and
//! nothing more, so the only difference between them is the type name in the URI. That is
//! why this module encodes bytes and takes the type as a parameter: there is no PSBT
//! semantics here, and there should not be. Whether the bytes are a valid PSBT was settled
//! before they arrived.
//!
//! `crypto-psbt` is the legacy type name. The registry has since moved to `psbt`, but the
//! coordinators this device has to work with - Sparrow, Nunchuk, Bitcoin Core through
//! Sparrow - all read the legacy name, and several still only read the legacy name.
//! MILESTONES.md 0.2.0-m8 fixes the choice; it is compatibility, not preference.
//!
//! Frame N is a pure function of N. Nothing here advances a cursor, so the caller's tick
//! handler can ask for any frame at any time - repeat one while the user photographs it,
//! skip forward, restart - and the answer is always a complete, independently decodable
//! part.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Write as _;

use super::checksum::crc32;
use super::fountain::{self, fragment_length};
use super::{bytewords, TransportError, MAX_PARTS};

/// A UR animation over one message.
pub(super) struct Encoder {
    ur_type: &'static str,
    /// The CBOR message, zero-padded up to `seq_len * fragment_len`.
    ///
    /// Padded once at construction rather than per frame: the format requires every
    /// fragment to be the same length, so the alternative is a bounds check and a partial
    /// copy on the frame path for the sake of at most `fragment_len - 1` bytes.
    padded: Vec<u8>,
    /// Length of the CBOR message before padding - the `messageLen` every part reports.
    message_len: usize,
    fragment_len: usize,
    seq_len: u32,
    /// CRC-32 of the unpadded message. Both the part header and the fountain's fragment
    /// choice are derived from it, so it is computed once and kept.
    checksum: u32,
}

impl core::fmt::Debug for Encoder {
    /// Shape only. The message is public by policy, but a kilobyte of PSBT in a log line
    /// helps nobody; the house style is "identity, not contents".
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ur::Encoder")
            .field("type", &self.ur_type)
            .field("parts", &self.seq_len)
            .field("fragment", &self.fragment_len)
            .finish()
    }
}

impl Encoder {
    /// Prepare an animation for `payload` under `ur_type`, with no fragment longer than
    /// `max_fragment` bytes.
    ///
    /// `max_fragment` bounds the fragment, not the frame: a part also carries about twenty
    /// bytes of CBOR header, and bytewords then spends two characters per byte. A 200-byte
    /// fragment is therefore a frame of roughly 450 characters, which is a version 16 QR
    /// symbol at the error correction level `notyas_core::qr` uses.
    ///
    /// # Errors
    ///
    /// [`TransportError::EmptyPayload`] for an empty payload,
    /// [`TransportError::FragmentTooSmall`] for a zero fragment bound, and
    /// [`TransportError::TooManyParts`] when the payload would need more parts than
    /// [`MAX_PARTS`].
    pub(super) fn new(
        ur_type: &'static str,
        payload: &[u8],
        max_fragment: usize,
    ) -> Result<Encoder, TransportError> {
        if payload.is_empty() {
            return Err(TransportError::EmptyPayload);
        }
        if max_fragment == 0 {
            return Err(TransportError::FragmentTooSmall { minimum: 1 });
        }

        let message = cbor::byte_string(payload);
        let fragment_len =
            fragment_length(message.len(), max_fragment).ok_or(TransportError::EmptyPayload)?;
        let parts = message.len().div_ceil(fragment_len);
        let seq_len = u32::try_from(parts)
            .ok()
            .filter(|&n| n <= MAX_PARTS)
            .ok_or(TransportError::TooManyParts { limit: MAX_PARTS })?;

        let checksum = crc32(&message);
        let message_len = message.len();
        let mut padded = message;
        padded.resize(parts.saturating_mul(fragment_len), 0);

        Ok(Encoder {
            ur_type,
            padded,
            message_len,
            fragment_len,
            seq_len,
            checksum,
        })
    }

    /// How many parts carry the message. One means the whole thing fits in a single symbol
    /// and the animation is a still.
    pub(super) fn part_count(&self) -> u32 {
        self.seq_len
    }

    /// The complete UR string for frame `n`, counting from zero.
    ///
    /// Frames past [`part_count`](Self::part_count) are fountain mixtures rather than
    /// repeats: a reader that missed a fragment recovers it from them, so the animation is
    /// worth looping indefinitely.
    pub(super) fn frame(&self, n: u32) -> String {
        let mut out = String::from("ur:");
        out.push_str(self.ur_type);
        out.push('/');

        if self.seq_len <= 1 {
            bytewords::append_minimal(&mut out, self.padded.get(..self.message_len).unwrap_or(&[]));
            return out;
        }

        // Sequence numbers are 1-based on the wire. Saturating rather than wrapping: a
        // sequence number of zero is not a legal part, and at the frame rates this is drawn
        // at the saturation point is decades away.
        let seq = n.saturating_add(1);
        let _ = write!(out, "{seq}-{}/", self.seq_len);
        bytewords::append_minimal(&mut out, &self.part(seq));
        out
    }

    /// The CBOR part for sequence number `seq`.
    fn part(&self, seq: u32) -> Vec<u8> {
        let mut fragment = vec![0u8; self.fragment_len];
        for index in fountain::choose_fragments(seq, self.seq_len, self.checksum) {
            if let Some(source) = self.padded.chunks_exact(self.fragment_len).nth(index) {
                fountain::xor_into(&mut fragment, source);
            }
        }
        cbor::part(
            seq,
            self.seq_len,
            self.message_len,
            self.checksum,
            &fragment,
        )
    }
}

/// The two CBOR shapes a UR needs, written by hand.
///
/// A UR carries either a byte string or a five-element array of four unsigned integers and
/// a byte string. That is the whole grammar, it is frozen by BCR-2020-005, and a general
/// CBOR library would be several thousand lines of parser and derive macro to emit thirty
/// bytes of header. Both writers below produce the shortest encoding of every value, which
/// CBOR calls canonical and which every UR decoder assumes.
mod cbor {
    use alloc::vec::Vec;

    /// Major type 0, unsigned integer, in the initial byte's high bits.
    const UINT: u8 = 0x00;
    /// Major type 2, byte string.
    const BYTES: u8 = 0x40;
    /// Major type 4, array, with the length five in the low bits.
    const ARRAY_5: u8 = 0x85;

    /// `bytes(payload)`: the whole item a single-part UR carries.
    pub(super) fn byte_string(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(payload.len().saturating_add(5));
        push_bytes(&mut out, payload);
        out
    }

    /// `[seq, seq_len, message_len, checksum, fragment]`: the item a multi-part UR carries.
    pub(super) fn part(
        seq: u32,
        seq_len: u32,
        message_len: usize,
        checksum: u32,
        fragment: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(fragment.len().saturating_add(32));
        out.push(ARRAY_5);
        push_head(&mut out, UINT, u64::from(seq));
        push_head(&mut out, UINT, u64::from(seq_len));
        push_head(&mut out, UINT, message_len as u64);
        push_head(&mut out, UINT, u64::from(checksum));
        push_bytes(&mut out, fragment);
        out
    }

    fn push_bytes(out: &mut Vec<u8>, data: &[u8]) {
        push_head(out, BYTES, data.len() as u64);
        out.extend_from_slice(data);
    }

    /// The initial byte of an item of major type `major` with argument `value`, plus
    /// however many following bytes the argument needs.
    fn push_head(out: &mut Vec<u8>, major: u8, value: u64) {
        match value {
            0..=0x17 => out.push(major | value as u8),
            0x18..=0xff => {
                out.push(major | 24);
                out.push(value as u8);
            }
            0x100..=0xffff => {
                out.push(major | 25);
                out.extend_from_slice(&(value as u16).to_be_bytes());
            }
            0x1_0000..=0xffff_ffff => {
                out.push(major | 26);
                out.extend_from_slice(&(value as u32).to_be_bytes());
            }
            _ => {
                out.push(major | 27);
                out.extend_from_slice(&value.to_be_bytes());
            }
        }
    }
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
    use crate::transport::bytewords::tests::decode_minimal;
    use crate::transport::fountain::tests::make_message;
    use alloc::collections::{BTreeMap, BTreeSet};
    use alloc::format;

    /// Hex, for comparing against the published vectors in the form they are published in.
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    }

    /// A test-only reader for the strings this module writes: bytewords out, CBOR out,
    /// fountain solved, message back.
    ///
    /// Deliberately not shipped. m8 is the display leg only, and a decoder that exists but
    /// is never called is a decoder nobody audits; m11 adds the real one alongside the
    /// camera. Its value here is that it makes the round-trip property test a genuine round
    /// trip through the emitted characters rather than a re-run of the encoder's own
    /// arithmetic.
    pub(in crate::transport) struct Reader {
        seq_len: u32,
        message_len: usize,
        checksum: u32,
        /// Fragments whose index is settled.
        known: BTreeMap<usize, Vec<u8>>,
        /// Mixtures of two or more still-unknown fragments, held until one of them can be
        /// reduced out.
        mixed: Vec<(BTreeSet<usize>, Vec<u8>)>,
        /// The whole message, when the series turned out to be a single part.
        single: Option<Vec<u8>>,
        pub(in crate::transport) ur_type: String,
    }

    impl Reader {
        pub(in crate::transport) fn new() -> Reader {
            Reader {
                seq_len: 0,
                message_len: 0,
                checksum: 0,
                known: BTreeMap::new(),
                mixed: Vec::new(),
                single: None,
                ur_type: String::new(),
            }
        }

        /// Take one frame. `false` if the string is not a well-formed UR part.
        pub(in crate::transport) fn receive(&mut self, frame: &str) -> bool {
            let Some(rest) = frame.strip_prefix("ur:") else {
                return false;
            };
            let fields: Vec<&str> = rest.split('/').collect();
            match fields.as_slice() {
                [ur_type, body] => {
                    let Some(bytes) = decode_minimal(body) else {
                        return false;
                    };
                    self.ur_type = String::from(*ur_type);
                    self.single = Some(bytes);
                    true
                }
                [ur_type, header, body] => {
                    let Some((seq_text, len_text)) = header.split_once('-') else {
                        return false;
                    };
                    let (Ok(header_seq), Ok(header_len)) =
                        (seq_text.parse::<u32>(), len_text.parse::<u32>())
                    else {
                        return false;
                    };
                    let Some(cbor) = decode_minimal(body) else {
                        return false;
                    };
                    let Some((seq, seq_len, message_len, checksum, fragment)) = parse_part(&cbor)
                    else {
                        return false;
                    };
                    // The URI header and the CBOR carry the same two numbers twice. A reader
                    // has no other way to notice a frame whose visible label disagrees with
                    // what it actually contains.
                    assert_eq!((header_seq, header_len), (seq, seq_len), "header disagrees");

                    self.ur_type = String::from(*ur_type);
                    if self.seq_len == 0 {
                        self.seq_len = seq_len;
                        self.message_len = message_len;
                        self.checksum = checksum;
                    }
                    assert_eq!((self.seq_len, self.checksum), (seq_len, checksum), "two series");

                    let indexes = fountain::choose_fragments(seq, seq_len, checksum)
                        .into_iter()
                        .collect();
                    self.install(indexes, fragment);
                    true
                }
                _ => false,
            }
        }

        /// Add one part and run the reduction to a fixed point: reduce every held mixture
        /// by the fragments now known, promote any that collapses to a single index, and
        /// repeat while that keeps yielding something new.
        fn install(&mut self, indexes: BTreeSet<usize>, data: Vec<u8>) {
            self.mixed.push((indexes, data));
            loop {
                let mut progressed = false;
                for (mut indexes, mut data) in core::mem::take(&mut self.mixed) {
                    for (index, fragment) in self.known.iter() {
                        if indexes.remove(index) {
                            fountain::xor_into(&mut data, fragment);
                        }
                    }
                    match indexes.iter().next().copied() {
                        Some(index) if indexes.len() == 1 => {
                            progressed |= self.known.insert(index, data).is_none();
                        }
                        Some(_) => self.mixed.push((indexes, data)),
                        // Fully reduced: a mixture of fragments already known carries
                        // nothing, which is what a repeated frame looks like from here.
                        None => {}
                    }
                }
                if !progressed {
                    return;
                }
            }
        }

        /// The message, once every fragment is known and the checksum agrees.
        pub(in crate::transport) fn message(&self) -> Option<Vec<u8>> {
            if let Some(single) = &self.single {
                return Some(single.clone());
            }
            if self.seq_len == 0 || self.known.len() != self.seq_len as usize {
                return None;
            }
            let mut out = Vec::with_capacity(self.message_len);
            for i in 0..self.seq_len as usize {
                out.extend_from_slice(self.known.get(&i)?);
            }
            out.truncate(self.message_len);
            assert_eq!(crc32(&out), self.checksum, "assembled message fails its checksum");
            Some(out)
        }
    }

    /// Parse the five-element part array. Only the shapes this crate writes are accepted.
    fn parse_part(cbor: &[u8]) -> Option<(u32, u32, usize, u32, Vec<u8>)> {
        if *cbor.first()? != 0x85 {
            return None;
        }
        let mut cursor = 1usize;
        let mut fields = [0u64; 4];
        for field in fields.iter_mut() {
            let (value, used) = head(cbor.get(cursor..)?, 0x00)?;
            *field = value;
            cursor += used;
        }
        let (len, used) = head(cbor.get(cursor..)?, 0x40)?;
        cursor += used;
        let fragment = cbor.get(cursor..cursor + len as usize)?.to_vec();
        let [seq, seq_len, message_len, checksum] = fields;
        Some((
            seq as u32,
            seq_len as u32,
            message_len as usize,
            checksum as u32,
            fragment,
        ))
    }

    /// The argument of the item at the start of `bytes` and how many bytes its head took.
    fn head(bytes: &[u8], major: u8) -> Option<(u64, usize)> {
        let initial = *bytes.first()?;
        if initial & 0xe0 != major {
            return None;
        }
        let be = |n: usize| -> Option<u64> {
            bytes
                .get(1..1 + n)?
                .iter()
                .try_fold(0u64, |acc, &b| Some(acc * 256 + u64::from(b)))
        };
        match initial & 0x1f {
            n @ 0..=23 => Some((u64::from(n), 1)),
            24 => Some((be(1)?, 2)),
            25 => Some((be(2)?, 3)),
            26 => Some((be(4)?, 5)),
            27 => Some((be(8)?, 9)),
            _ => None,
        }
    }

    /// Strip the CBOR byte-string head a UR message wraps its payload in.
    pub(in crate::transport) fn unwrap_byte_string(cbor: &[u8]) -> Option<Vec<u8>> {
        let (len, used) = head(cbor, 0x40)?;
        Some(cbor.get(used..used + len as usize)?.to_vec())
    }

    /// bc-ur's fragment split: a 1024-byte message at a 100-byte cap becomes eleven
    /// 94-byte fragments, the last of them zero-padded. This pins the padding as well as
    /// the balancing, which the fragment lengths on their own do not.
    #[test]
    fn published_fragment_split() {
        const EXPECTED: [&str; 11] = [
            "916ec65cf77cadf55cd7f9cda1a1030026ddd42e905b77adc36e4f2d3ccba44f7f04f2de44f42d84c374a0e149136f25b01852545961d55f7f7a8cde6d0e2ec43f3b2dcb644a2209e8c9e34af5c4747984a5e873c9cf5f965e25ee29039f",
            "df8ca74f1c769fc07eb7ebaec46e0695aea6cbd60b3ec4bbff1b9ffe8a9e7240129377b9d3711ed38d412fbb4442256f1e6f595e0fc57fed451fb0a0101fb76b1fb1e1b88cfdfdaa946294a47de8fff173f021c0e6f65b05c0a494e50791",
            "270a0050a73ae69b6725505a2ec8a5791457c9876dd34aadd192a53aa0dc66b556c0c215c7ceb8248b717c22951e65305b56a3706e3e86eb01c803bbf915d80edcd64d4d41977fa6f78dc07eecd072aae5bc8a852397e06034dba6a0b570",
            "797c3a89b16673c94838d884923b8186ee2db5c98407cab15e13678d072b43e406ad49477c2e45e85e52ca82a94f6df7bbbe7afbed3a3a830029f29090f25217e48d1f42993a640a67916aa7480177354cc7440215ae41e4d02eae9a1912",
            "33a6d4922a792c1b7244aa879fefdb4628dc8b0923568869a983b8c661ffab9b2ed2c149e38d41fba090b94155adbed32f8b18142ff0d7de4eeef2b04adf26f2456b46775c6c20b37602df7da179e2332feba8329bbb8d727a138b4ba7a5",
            "03215eda2ef1e953d89383a382c11d3f2cad37a4ee59a91236a3e56dcf89f6ac81dd4159989c317bd649d9cbc617f73fe10033bd288c60977481a09b343d3f676070e67da757b86de27bfca74392bac2996f7822a7d8f71a489ec6180390",
            "089ea80a8fcd6526413ec6c9a339115f111d78ef21d456660aa85f790910ffa2dc58d6a5b93705caef1091474938bd312427021ad1eeafbd19e0d916ddb111fabd8dcab5ad6a6ec3a9c6973809580cb2c164e26686b5b98cfb017a337968",
            "c7daaa14ae5152a067277b1b3902677d979f8e39cc2aafb3bc06fcf69160a853e6869dcc09a11b5009f91e6b89e5b927ab1527a735660faa6012b420dd926d940d742be6a64fb01cdc0cff9faa323f02ba41436871a0eab851e7f5782d10",
            "fbefde2a7e9ae9dc1e5c2c48f74f6c824ce9ef3c89f68800d44587bedc4ab417cfb3e7447d90e1e417e6e05d30e87239d3a5d1d45993d4461e60a0192831640aa32dedde185a371ded2ae15f8a93dba8809482ce49225daadfbb0fec629e",
            "23880789bdf9ed73be57fa84d555134630e8d0f7df48349f29869a477c13ccca9cd555ac42ad7f568416c3d61959d0ed568b2b81c7771e9088ad7fd55fd4386bafbf5a528c30f107139249357368ffa980de2c76ddd9ce4191376be0e6b5",
            "170010067e2e75ebe2d2904aeb1f89d5dc98cd4a6f2faaa8be6d03354c990fd895a97feb54668473e9d942bb99e196d897e8f1b01625cf48a7b78d249bb4985c065aa8cd1402ed2ba1b6f908f63dcd84b66425df00000000000000000000",
        ];
        let message = make_message("Wolf", 1024);
        let fragment_len = fragment_length(message.len(), 100).unwrap();
        let mut padded = message;
        padded.resize(EXPECTED.len() * fragment_len, 0);

        for (i, want) in EXPECTED.iter().enumerate() {
            let got = padded.chunks_exact(fragment_len).nth(i).unwrap();
            assert_eq!(hex(got), *want, "fragment {i}");
        }
    }

    /// bc-ur's part vector, as CBOR. Twenty parts of a nine-part message, so the last
    /// eleven are mixtures: this is the only test that pins the whole header - the array
    /// length, the integer widths, the message length and the checksum - beside the
    /// fountain's choice of fragments.
    #[test]
    fn published_part_cbor() {
        const EXPECTED: [&str; 20] = [
            "8501091901001a0167aa07581d916ec65cf77cadf55cd7f9cda1a1030026ddd42e905b77adc36e4f2d3c",
            "8502091901001a0167aa07581dcba44f7f04f2de44f42d84c374a0e149136f25b01852545961d55f7f7a",
            "8503091901001a0167aa07581d8cde6d0e2ec43f3b2dcb644a2209e8c9e34af5c4747984a5e873c9cf5f",
            "8504091901001a0167aa07581d965e25ee29039fdf8ca74f1c769fc07eb7ebaec46e0695aea6cbd60b3e",
            "8505091901001a0167aa07581dc4bbff1b9ffe8a9e7240129377b9d3711ed38d412fbb4442256f1e6f59",
            "8506091901001a0167aa07581d5e0fc57fed451fb0a0101fb76b1fb1e1b88cfdfdaa946294a47de8fff1",
            "8507091901001a0167aa07581d73f021c0e6f65b05c0a494e50791270a0050a73ae69b6725505a2ec8a5",
            "8508091901001a0167aa07581d791457c9876dd34aadd192a53aa0dc66b556c0c215c7ceb8248b717c22",
            "8509091901001a0167aa07581d951e65305b56a3706e3e86eb01c803bbf915d80edcd64d4d0000000000",
            "850a091901001a0167aa07581d330f0f33a05eead4f331df229871bee733b50de71afd2e5a79f196de09",
            "850b091901001a0167aa07581d3b205ce5e52d8c24a52cffa34c564fa1af3fdffcd349dc4258ee4ee828",
            "850c091901001a0167aa07581ddd7bf725ea6c16d531b5f03254783803048ca08b87148daacd1cd7a006",
            "850d091901001a0167aa07581d760be7ad1c6187902bbc04f539b9ee5eb8ea6833222edea36031306c01",
            "850e091901001a0167aa07581d5bf4031217d2c3254b088fa7553778b5003632f46e21db129416f65b55",
            "850f091901001a0167aa07581d73f021c0e6f65b05c0a494e50791270a0050a73ae69b6725505a2ec8a5",
            "8510091901001a0167aa07581db8546ebfe2048541348910267331c643133f828afec9337c318f71b7df",
            "8511091901001a0167aa07581d23dedeea74e3a0fb052befabefa13e2f80e4315c9dceed4c8630612e64",
            "8512091901001a0167aa07581dd01a8daee769ce34b6b35d3ca0005302724abddae405bdb419c0a6b208",
            "8513091901001a0167aa07581d3171c5dc365766eff25ae47c6f10e7de48cfb8474e050e5fe997a6dc24",
            "8514091901001a0167aa07581de055c2433562184fa71b4be94f262e200f01c6f74c284b0dc6fae6673f",
        ];
        // The vector's message is the raw 256 bytes, fragmented directly rather than
        // wrapped in CBOR first, so the encoder is driven at the fountain level here.
        let message = make_message("Wolf", 256);
        let fragment_len = fragment_length(message.len(), 30).unwrap();
        let mut padded = message.clone();
        padded.resize(message.len().div_ceil(fragment_len) * fragment_len, 0);
        let encoder = Encoder {
            ur_type: "bytes",
            padded,
            message_len: message.len(),
            fragment_len,
            seq_len: message.len().div_ceil(fragment_len) as u32,
            checksum: crc32(&message),
        };
        assert_eq!(encoder.seq_len, 9);
        assert_eq!(encoder.checksum, 23_570_951);

        for (i, want) in EXPECTED.iter().enumerate() {
            assert_eq!(hex(&encoder.part(i as u32 + 1)), *want, "part {}", i + 1);
        }
    }

    /// bc-ur's single-part vector: fifty bytes wrapped in CBOR fit one symbol, so there is
    /// no sequence header and no fountain.
    #[test]
    fn published_single_part_ur() {
        const EXPECTED: &str = "ur:bytes/hdeymejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtgwdpfnsboxgwlbaawzuefywkdplrsrjynbvygabwjldapfcsdwkbrkch";
        let payload = make_message("Wolf", 50);
        let encoder = Encoder::new("bytes", &payload, 1000).unwrap();
        assert_eq!(encoder.part_count(), 1);
        assert_eq!(encoder.frame(0), EXPECTED);
        // A still: every frame of a one-part animation is the same string.
        assert_eq!(encoder.frame(7), EXPECTED);
    }

    /// bc-ur's twenty-frame vector, as the strings that go on the glass. Everything below
    /// this line - bytewords, the checksum, the CBOR, the fountain, the URI shape - has to
    /// be right for a single one of these to match.
    #[test]
    fn published_multipart_ur() {
        const EXPECTED: [&str; 20] = [
            "ur:bytes/1-9/lpadascfadaxcywenbpljkhdcahkadaemejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtdkgslpgh",
            "ur:bytes/2-9/lpaoascfadaxcywenbpljkhdcagwdpfnsboxgwlbaawzuefywkdplrsrjynbvygabwjldapfcsgmghhkhstlrdcxaefz",
            "ur:bytes/3-9/lpaxascfadaxcywenbpljkhdcahelbknlkuejnbadmssfhfrdpsbiegecpasvssovlgeykssjykklronvsjksopdzmol",
            "ur:bytes/4-9/lpaaascfadaxcywenbpljkhdcasotkhemthydawydtaxneurlkosgwcekonertkbrlwmplssjtammdplolsbrdzcrtas",
            "ur:bytes/5-9/lpahascfadaxcywenbpljkhdcatbbdfmssrkzmcwnezelennjpfzbgmuktrhtejscktelgfpdlrkfyfwdajldejokbwf",
            "ur:bytes/6-9/lpamascfadaxcywenbpljkhdcackjlhkhybssklbwefectpfnbbectrljectpavyrolkzczcpkmwidmwoxkilghdsowp",
            "ur:bytes/7-9/lpatascfadaxcywenbpljkhdcavszmwnjkwtclrtvaynhpahrtoxmwvwatmedibkaegdosftvandiodagdhthtrlnnhy",
            "ur:bytes/8-9/lpayascfadaxcywenbpljkhdcadmsponkkbbhgsoltjntegepmttmoonftnbuoiyrehfrtsabzsttorodklubbuyaetk",
            "ur:bytes/9-9/lpasascfadaxcywenbpljkhdcajskecpmdckihdyhphfotjojtfmlnwmadspaxrkytbztpbauotbgtgtaeaevtgavtny",
            "ur:bytes/10-9/lpbkascfadaxcywenbpljkhdcahkadaemejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtwdkiplzs",
            "ur:bytes/11-9/lpbdascfadaxcywenbpljkhdcahelbknlkuejnbadmssfhfrdpsbiegecpasvssovlgeykssjykklronvsjkvetiiapk",
            "ur:bytes/12-9/lpbnascfadaxcywenbpljkhdcarllaluzmdmgstospeyiefmwejlwtpedamktksrvlcygmzemovovllarodtmtbnptrs",
            "ur:bytes/13-9/lpbtascfadaxcywenbpljkhdcamtkgtpknghchchyketwsvwgwfdhpgmgtylctotzopdrpayoschcmhplffziachrfgd",
            "ur:bytes/14-9/lpbaascfadaxcywenbpljkhdcapazewnvonnvdnsbyleynwtnsjkjndeoldydkbkdslgjkbbkortbelomueekgvstegt",
            "ur:bytes/15-9/lpbsascfadaxcywenbpljkhdcaynmhpddpzmversbdqdfyrehnqzlugmjzmnmtwmrouohtstgsbsahpawkditkckynwt",
            "ur:bytes/16-9/lpbeascfadaxcywenbpljkhdcawygekobamwtlihsnpalnsghenskkiynthdzotsimtojetprsttmukirlrsbtamjtpd",
            "ur:bytes/17-9/lpbyascfadaxcywenbpljkhdcamklgftaxykpewyrtqzhydntpnytyisincxmhtbceaykolduortotiaiaiafhiaoyce",
            "ur:bytes/18-9/lpbgascfadaxcywenbpljkhdcahkadaemejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtntwkbkwy",
            "ur:bytes/19-9/lpbwascfadaxcywenbpljkhdcadekicpaajootjzpsdrbalpeywllbdsnbinaerkurspbncxgslgftvtsrjtksplcpeo",
            "ur:bytes/20-9/lpbbascfadaxcywenbpljkhdcayapmrleeleaxpasfrtrdkncffwjyjzgyetdmlewtkpktgllepfrltataztksmhkbot",
        ];
        let payload = make_message("Wolf", 256);
        let encoder = Encoder::new("bytes", &payload, 30).unwrap();
        assert_eq!(encoder.part_count(), 9);
        for (i, want) in EXPECTED.iter().enumerate() {
            assert_eq!(encoder.frame(i as u32), *want, "frame {i}");
        }
    }

    /// The type name is the only thing that separates a PSBT from any other byte string,
    /// and it is the legacy one.
    #[test]
    fn the_psbt_type_name_is_the_legacy_one() {
        let encoder = Encoder::new("crypto-psbt", b"psbt\xffnot-really", 200).unwrap();
        assert!(encoder.frame(0).starts_with("ur:crypto-psbt/"));
    }

    /// Refusals: nothing to send, no room to send it in, and more parts than the sequence
    /// field will name.
    #[test]
    fn construction_refuses_what_it_cannot_encode() {
        assert_eq!(
            Encoder::new("bytes", &[], 200).unwrap_err(),
            TransportError::EmptyPayload
        );
        assert_eq!(
            Encoder::new("bytes", b"x", 0).unwrap_err(),
            TransportError::FragmentTooSmall { minimum: 1 }
        );
        let big = vec![0u8; MAX_PARTS as usize + 64];
        assert_eq!(
            Encoder::new("bytes", &big, 1).unwrap_err(),
            TransportError::TooManyParts { limit: MAX_PARTS }
        );
    }

    /// A reader that sees only every third frame still finishes, and gets the payload back
    /// byte for byte. This is what the fountain is for: no frame is mandatory.
    #[test]
    fn a_lossy_reader_still_recovers_the_payload() {
        for &(len, cap) in &[(256usize, 30usize), (1024, 100), (4096, 200)] {
            let payload = make_message("notyas-lossy", len);
            let encoder = Encoder::new("crypto-psbt", &payload, cap).unwrap();
            let mut reader = Reader::new();
            let mut frame = 0u32;
            while reader.message().is_none() {
                assert!(frame < 10_000, "no convergence for len {len} cap {cap}");
                if frame % 3 == 0 {
                    assert!(reader.receive(&encoder.frame(frame)));
                }
                frame += 1;
            }
            let message = reader.message().unwrap();
            assert_eq!(reader.ur_type, "crypto-psbt");
            assert_eq!(unwrap_byte_string(&message).unwrap(), payload);
        }
    }

    /// The round-trip property, over payload sizes and fragment caps that bracket
    /// everything this device emits: a PSBT of a few hundred bytes up to a large multisig
    /// one, at every density step the player offers. Reading the frames in order is the
    /// happy path; `a_lossy_reader_still_recovers_the_payload` covers the other one.
    #[test]
    fn round_trips_over_sizes_and_capacities() {
        for len in [1usize, 2, 5, 31, 32, 33, 100, 255, 256, 257, 999, 4096, 20_001] {
            for cap in [10usize, 30, 100, 200, 400, 1000] {
                let payload = make_message(&format!("notyas-{len}-{cap}"), len);
                let encoder = match Encoder::new("crypto-psbt", &payload, cap) {
                    Ok(encoder) => encoder,
                    // A 20 KB payload at ten bytes a frame is over the part cap, which is
                    // the refusal the density steps exist to keep the user away from.
                    Err(TransportError::TooManyParts { .. }) => continue,
                    Err(other) => panic!("len {len} cap {cap}: {other:?}"),
                };
                let mut reader = Reader::new();
                for frame in 0..encoder.part_count() {
                    assert!(reader.receive(&encoder.frame(frame)), "len {len} cap {cap}");
                }
                let message = reader.message().expect("no message");
                assert_eq!(
                    unwrap_byte_string(&message).unwrap(),
                    payload,
                    "len {len} cap {cap}"
                );
            }
        }
    }

    /// No fragment exceeds the cap the caller set, and every frame of a multi-part series
    /// is the same length - which is what keeps the symbol size steady while it animates.
    #[test]
    fn frames_respect_the_cap_and_hold_their_size() {
        for cap in [20usize, 50, 200] {
            let payload = make_message("notyas-density", 3000);
            let encoder = Encoder::new("bytes", &payload, cap).unwrap();
            assert!(encoder.fragment_len <= cap, "cap {cap}");
            let first = encoder.frame(0).len();
            for frame in 1..encoder.part_count().saturating_add(5) {
                let len = encoder.frame(frame).len();
                // Only the sequence number's decimal width varies.
                assert!(len.abs_diff(first) <= 4, "cap {cap} frame {frame}");
            }
        }
    }
}
