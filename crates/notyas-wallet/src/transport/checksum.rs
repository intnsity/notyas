// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! CRC-32, the integrity check both halves of a UR string carry.
//!
//! Bytewords appends it to every payload it encodes (BCR-2020-012) and a multi-part UR
//! part header repeats it over the whole message (BCR-2020-005). Neither use is ours to
//! choose: both are read by every other implementation in the ecosystem, so the
//! parameterisation has to be the one they use - ISO-HDLC, the same one zlib, PNG and
//! Ethernet use. Reflected input and output, polynomial 0x04c11db7 in its reversed form
//! 0xedb88320, initial value and final XOR both 0xffffffff.
//!
//! Bit-serial rather than table-driven. A whole animation checksums its message exactly
//! once, at construction, over a payload measured in tens of kilobytes; a 1 KB table to
//! save a few hundred microseconds once would be flash spent on nothing.

/// CRC-32/ISO-HDLC of `data`.
pub(super) fn crc32(data: &[u8]) -> u32 {
    const POLY: u32 = 0xedb8_8320;

    let mut crc = u32::MAX;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            // Branchless: `mask` is all ones when the low bit is set and all zeros
            // otherwise, so the polynomial is XORed in or not without a branch.
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (POLY & mask);
        }
    }
    !crc
}

#[cfg(test)]
// A test asserts by panicking, which is the whole point of one. The crate-wide bans on
// panicking constructs exist to keep a panic out of the device image; nothing below
// compiles into one.
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    /// The check value every CRC-32 catalogue publishes for this parameterisation, plus
    /// the two strings bc-ur's own suite pins - which is what ties this implementation to
    /// the one the UR ecosystem actually runs rather than merely to a catalogue entry.
    #[test]
    fn published_check_values() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926, "CRC-32/ISO-HDLC check value");
        assert_eq!(crc32(b"Hello, world!"), 0xebe6_c6e6, "bc-ur test vector");
        assert_eq!(crc32(b"Wolf"), 0x598c_84dc, "bc-ur test vector");
        assert_eq!(crc32(b""), 0, "empty input");
    }

    /// A single flipped bit anywhere must move the checksum. Weak as a proof, but it is
    /// the property the format is relying on and it catches a mis-transcribed polynomial
    /// that happens to agree on the vectors above.
    #[test]
    fn every_single_bit_flip_is_detected() {
        let base = [0x00u8, 0x01, 0x02, 0x80, 0xff, 0x5a, 0xa5];
        let want = crc32(&base);
        for byte in 0..base.len() {
            for bit in 0..8u8 {
                let mut flipped = base;
                flipped[byte] ^= 1 << bit;
                assert_ne!(crc32(&flipped), want, "byte {byte} bit {bit}");
            }
        }
    }
}
