// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The UR fountain code: which fragments of the message a given part carries.
//!
//! A multi-part UR is not a numbered series that has to be scanned in order. Parts 1..=N
//! are the message's N fragments in order, and every part after N is the exclusive-or of a
//! pseudo-randomly chosen subset of them. A decoder that missed part 4 recovers it from a
//! later mixture, so a camera that drops frames still finishes, and an encoder can loop
//! forever without the user ever having to catch a particular frame.
//!
//! The subset is not transmitted. Both sides derive it from `(seqNum, seqLen, checksum)`
//! alone, which is what makes a part self-describing and this module's only real
//! obligation: **every arithmetic step below has to match the reference implementation bit
//! for bit**, because a decoder that computes a different subset does not fail loudly - it
//! assembles a different message. The stack is
//!
//! 1. SHA-256 over the eight seed bytes, read as four big-endian `u64`s of xoshiro state,
//! 2. xoshiro256\*\* for the raw stream,
//! 3. a `u64`-to-`f64` scaling the reference defines by dividing by `u64::MAX + 1.0`,
//! 4. Walker's alias method over the degree distribution `1/1, 1/2, ... 1/n`,
//! 5. a draw-without-replacement shuffle for which fragments the chosen degree names.
//!
//! Steps 3 to 5 run on `f64`. That is not a choice this module gets to revisit: the
//! reference is written in floating point and interoperability is defined by its rounding.
//! IEEE-754 double arithmetic is exact and identical on every target that has it, so the
//! result is still deterministic - see `next_double` for the one place the rounding bites.
//!
//! Encoding only. A decoder needs exactly the same subset derivation, so when m11 adds
//! camera scan-in it reuses this module rather than growing a second copy.

use alloc::vec;
use alloc::vec::Vec;

use sha2::{Digest, Sha256};

/// Nominal fragment length for a message of `message_len` bytes with no fragment longer
/// than `max_fragment`.
///
/// Not simply `max_fragment`: filling every fragment to the brim leaves a runt at the end,
/// and a UR fragment cannot be short - the format pads the message so that all `seqLen`
/// fragments are the same size, so a runt is paid for in padding on the wire and in a
/// visibly smaller final symbol. Dividing the message evenly over the fragment count that
/// `max_fragment` implies costs nothing and gives every frame the same density.
///
/// `None` when either input is zero: there is no such thing as a zero-length fragment, and
/// an empty message has nothing to fragment.
pub(super) fn fragment_length(message_len: usize, max_fragment: usize) -> Option<usize> {
    if message_len == 0 || max_fragment == 0 {
        return None;
    }
    let count = message_len.div_ceil(max_fragment);
    Some(message_len.div_ceil(count))
}

/// The fragment indexes part `seq` of a `seq_len`-part message carries.
///
/// `seq` is 1-based, as it is on the wire. Parts 1..=`seq_len` are the plain fragments in
/// order; past that the result is the mixture described in the module documentation.
///
/// The returned indexes are all less than `seq_len` and free of duplicates, which is what
/// makes the caller's exclusive-or well defined.
pub(super) fn choose_fragments(seq: u32, seq_len: u32, checksum: u32) -> Vec<usize> {
    let count = seq_len as usize;
    if seq_len == 0 {
        return Vec::new();
    }
    if seq <= seq_len {
        return vec![seq.saturating_sub(1) as usize];
    }

    let seed = [seq.to_be_bytes(), checksum.to_be_bytes()].concat();
    let mut rng = Xoshiro256::from_seed(&seed);
    let degree = choose_degree(&mut rng, count);

    // Draw without replacement from a pool of every index: the reference shuffles the whole
    // index list and takes a prefix, which for a prefix of length `degree` is the same
    // sequence of draws and the same consumption of the stream.
    let mut pool: Vec<usize> = (0..count).collect();
    let mut chosen = Vec::with_capacity(degree);
    while chosen.len() < degree && !pool.is_empty() {
        let last = pool.len().saturating_sub(1);
        let index = (rng.next_int(0, last as u64) as usize).min(last);
        chosen.push(pool.remove(index));
    }
    chosen
}

/// Exclusive-or `fragment` into `out`, over the length they share.
pub(super) fn xor_into(out: &mut [u8], fragment: &[u8]) {
    for (dst, &src) in out.iter_mut().zip(fragment.iter()) {
        *dst ^= src;
    }
}

/// How many fragments a mixed part carries, drawn from `1/1, 1/2, ... 1/n`.
///
/// The distribution is the soliton-ish shape the UR specification fixes: degree 1 is the
/// most likely draw, so a decoder keeps receiving plain fragments it can install directly,
/// while the long tail supplies the mixtures that recover a fragment it missed.
fn choose_degree(rng: &mut Xoshiro256, count: usize) -> usize {
    // The table is rebuilt for every mixed part rather than cached on the encoder. It is
    // O(seqLen) in a loop that runs at the frame rate, against a part count this crate caps
    // at `super::MAX_PARTS`; caching it would trade that for state on a type whose whole
    // value is that `frame(n)` is a pure function of `n`.
    match AliasTable::over_reciprocals(count) {
        Some(table) => table.sample(rng).saturating_add(1),
        // Unreachable: `over_reciprocals` returns `None` only for `count == 0`, and
        // `choose_fragments` has already returned in that case. Degree 1 keeps this a
        // legal part rather than a panic mid-animation.
        None => 1,
    }
}

/// Walker's alias table over the weights `1/1, 1/2, ... 1/count`.
///
/// Sampling a weighted distribution in two `f64` draws and one comparison, rather than in a
/// linear scan of cumulative weights. The construction is the reference's, down to the
/// order in which the small and large stacks are filled and popped, because the sample it
/// yields for a given pair of draws depends on that order.
struct AliasTable {
    probs: Vec<f64>,
    aliases: Vec<usize>,
}

impl AliasTable {
    fn over_reciprocals(count: usize) -> Option<AliasTable> {
        if count == 0 {
            return None;
        }

        // Normalised so the weights average 1: the alias method's invariant is that each
        // bucket holds probability mass 1, split between its own outcome and its alias.
        let mut weights: Vec<f64> = (0..count).map(|i| 1.0 / (i as f64 + 1.0)).collect();
        let total: f64 = weights.iter().sum();
        if !total.is_finite() || total <= 0.0 {
            return None;
        }
        let ratio = count as f64 / total;
        for weight in weights.iter_mut() {
            *weight *= ratio;
        }

        let mut probs = vec![0.0f64; count];
        let mut aliases = vec![0usize; count];
        let mut small: Vec<usize> = Vec::new();
        let mut large: Vec<usize> = Vec::new();
        // Descending, so that popping from the back of each stack visits the buckets in
        // ascending order. The reference does the same, and the pairing it produces is
        // observable in the sampled degrees.
        for i in (0..count).rev() {
            if *weights.get(i)? < 1.0 {
                small.push(i);
            } else {
                large.push(i);
            }
        }

        while !small.is_empty() && !large.is_empty() {
            let (Some(under), Some(over)) = (small.pop(), large.pop()) else {
                break;
            };
            let deficit = *weights.get(under)?;
            *probs.get_mut(under)? = deficit;
            *aliases.get_mut(under)? = over;
            let donor = weights.get_mut(over)?;
            *donor += deficit - 1.0;
            if *donor < 1.0 {
                small.push(over);
            } else {
                large.push(over);
            }
        }
        // Whatever is left is within rounding of a full bucket and takes its own outcome.
        for i in large.into_iter().chain(small) {
            *probs.get_mut(i)? = 1.0;
        }

        Some(AliasTable { probs, aliases })
    }

    /// One sample, costing exactly two draws from `rng`. The count of draws is part of the
    /// contract: the shuffle that follows reads the same stream.
    fn sample(&self, rng: &mut Xoshiro256) -> usize {
        let bucket = rng.next_double();
        let within = rng.next_double();
        let count = self.probs.len();
        // `next_double` can return exactly 1.0; see its documentation. Clamping keeps the
        // pick inside the table.
        let i = ((count as f64 * bucket) as usize).min(count.saturating_sub(1));
        match self.probs.get(i) {
            Some(&prob) if within < prob => i,
            Some(_) => self.aliases.get(i).copied().unwrap_or(i),
            None => 0,
        }
    }
}

/// xoshiro256\*\*, seeded the way the UR specification seeds it.
///
/// Not a general-purpose random source and deliberately not reachable from outside this
/// module: it is a reproducible sequence both ends of a QR link have to agree on, and the
/// crate's whole point is that there is no RNG in the device image. Calling this an RNG
/// would be a category error - it is a shared derivation, like an HKDF expansion.
struct Xoshiro256 {
    state: [u64; 4],
}

impl Xoshiro256 {
    /// State from SHA-256 of `seed`, read as four big-endian `u64`s.
    ///
    /// The reference implementations reach the same state by a longer route (hash, read
    /// big-endian, re-serialise little-endian, hand to a seeded constructor that reads
    /// little-endian); the round trip cancels and this is what is left. They also replace an
    /// all-zero seed - the one state xoshiro cannot leave - with a fixed substitute. That
    /// branch is not reproduced because reaching it means finding a SHA-256 preimage of
    /// zero, and a branch that cannot be exercised is a branch that cannot be trusted.
    fn from_seed(seed: &[u8]) -> Xoshiro256 {
        let digest = Sha256::digest(seed);
        let mut state = [0u64; 4];
        for (word, chunk) in state.iter_mut().zip(digest.chunks_exact(8)) {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(chunk);
            *word = u64::from_be_bytes(bytes);
        }
        Xoshiro256 { state }
    }

    fn next_u64(&mut self) -> u64 {
        let [s0, s1, s2, s3] = self.state;
        let result = s1.wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = s1.wrapping_shl(17);
        let s2 = s2 ^ s0;
        let s3 = s3 ^ s1;
        let s1 = s1 ^ s2;
        let s0 = s0 ^ s3;
        let s2 = s2 ^ t;
        let s3 = s3.rotate_left(45);
        self.state = [s0, s1, s2, s3];
        result
    }

    /// The raw stream scaled into `[0, 1]`.
    ///
    /// The reference divides by `u64::MAX + 1.0`, and both that denominator and a draw near
    /// the top of the range round to 2^64 in `f64`, so this returns exactly 1.0 for roughly
    /// one draw in 2^54 rather than staying below it. That is the reference's behaviour and
    /// therefore the interoperable one; the two callers clamp instead of trusting the
    /// half-open range, which is the only divergence in this module and is unobservable
    /// short of a deliberate search for the seed that triggers it.
    fn next_double(&mut self) -> f64 {
        self.next_u64() as f64 / (u64::MAX as f64 + 1.0)
    }

    /// A draw in `low..=high`, by the reference's definition. May return `high + 1` on the
    /// rounding edge described above; callers clamp.
    fn next_int(&mut self, low: u64, high: u64) -> u64 {
        let span = high.saturating_sub(low).saturating_add(1);
        low.saturating_add((self.next_double() * span as f64) as u64)
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
    use alloc::format;

    /// bc-ur's message generator, reproduced so the published vectors can be checked
    /// against the payloads they were computed over. The seed string is hashed to xoshiro
    /// state and the stream is read one byte at a time through `next_int(0, 255)` - not
    /// through the raw `u64`s, which is why this is worth pinning rather than inlining.
    pub(in crate::transport) fn make_message(seed: &str, len: usize) -> Vec<u8> {
        let mut rng = Xoshiro256::from_seed(seed.as_bytes());
        (0..len).map(|_| rng.next_int(0, 255) as u8).collect()
    }

    /// bc-ur's raw-stream vector: the first hundred draws from the "Wolf" seed, modulo 100.
    /// This is the bottom of the stack - if it moves, nothing above it can be right.
    #[test]
    fn published_raw_stream() {
        const EXPECTED: [u64; 100] = [
            42, 81, 85, 8, 82, 84, 76, 73, 70, 88, 2, 74, 40, 48, 77, 54, 88, 7, 5, 88, 37, 25, 82,
            13, 69, 59, 30, 39, 11, 82, 19, 99, 45, 87, 30, 15, 32, 22, 89, 44, 92, 77, 29, 78, 4,
            92, 44, 68, 92, 69, 1, 42, 89, 50, 37, 84, 63, 34, 32, 3, 17, 62, 40, 98, 82, 89, 24,
            43, 85, 39, 15, 3, 99, 29, 20, 42, 27, 10, 85, 66, 50, 35, 69, 70, 70, 74, 30, 13, 72,
            54, 11, 5, 70, 55, 91, 52, 10, 43, 43, 52,
        ];
        let mut rng = Xoshiro256::from_seed(b"Wolf");
        for (i, &want) in EXPECTED.iter().enumerate() {
            assert_eq!(rng.next_u64() % 100, want, "draw {i}");
        }
    }

    /// bc-ur's scaled-draw vector. `next_int` is where the `f64` scaling becomes visible,
    /// so this pins the rounding as well as the stream.
    #[test]
    fn published_scaled_stream() {
        const EXPECTED: [u64; 100] = [
            6, 5, 8, 4, 10, 5, 7, 10, 4, 9, 10, 9, 7, 7, 1, 1, 2, 9, 9, 2, 6, 4, 5, 7, 8, 5, 4, 2,
            3, 8, 7, 4, 5, 1, 10, 9, 3, 10, 2, 6, 8, 5, 7, 9, 3, 1, 5, 2, 7, 1, 4, 4, 4, 4, 9, 4,
            5, 5, 6, 9, 5, 1, 2, 8, 3, 3, 2, 8, 4, 3, 2, 1, 10, 8, 9, 3, 10, 8, 5, 5, 6, 7, 10, 5,
            8, 9, 4, 6, 4, 2, 10, 2, 1, 7, 9, 6, 7, 4, 2, 5,
        ];
        let mut rng = Xoshiro256::from_seed(b"Wolf");
        for (i, &want) in EXPECTED.iter().enumerate() {
            assert_eq!(rng.next_int(1, 10), want, "draw {i}");
        }
    }

    /// bc-ur's degree vector: two hundred draws from the alias table over eleven
    /// reciprocals, each from its own seed. This is what pins Walker's construction, which
    /// has several orderings that all sample the same distribution and only one that
    /// samples it in the same order as everybody else.
    #[test]
    fn published_degrees() {
        const EXPECTED: [usize; 200] = [
            11, 3, 6, 5, 2, 1, 2, 11, 1, 3, 9, 10, 10, 4, 2, 1, 1, 2, 1, 1, 5, 2, 4, 10, 3, 2, 1,
            1, 3, 11, 2, 6, 2, 9, 9, 2, 6, 7, 2, 5, 2, 4, 3, 1, 6, 11, 2, 11, 3, 1, 6, 3, 1, 4, 5,
            3, 6, 1, 1, 3, 1, 2, 2, 1, 4, 5, 1, 1, 9, 1, 1, 6, 4, 1, 5, 1, 2, 2, 3, 1, 1, 5, 2, 6,
            1, 7, 11, 1, 8, 1, 5, 1, 1, 2, 2, 6, 4, 10, 1, 2, 5, 5, 5, 1, 1, 4, 1, 1, 1, 3, 5, 5,
            5, 1, 4, 3, 3, 5, 1, 11, 3, 2, 8, 1, 2, 1, 1, 4, 5, 2, 1, 1, 1, 5, 6, 11, 10, 7, 4, 7,
            1, 5, 3, 1, 1, 9, 1, 2, 5, 5, 2, 2, 3, 10, 1, 3, 2, 3, 3, 1, 1, 2, 1, 3, 2, 2, 1, 3, 8,
            4, 1, 11, 6, 3, 1, 1, 1, 1, 1, 3, 1, 2, 1, 10, 1, 1, 8, 2, 7, 1, 2, 1, 9, 2, 10, 2, 1,
            3, 4, 10,
        ];
        // The eleven-fragment shape of a 1024-byte message at the reference's 100-byte cap.
        let fragment = fragment_length(1024, 100).unwrap();
        let count = 1024usize.div_ceil(fragment);
        assert_eq!(count, 11);

        for (nonce, &want) in EXPECTED.iter().enumerate() {
            let mut rng = Xoshiro256::from_seed(format!("Wolf-{}", nonce + 1).as_bytes());
            assert_eq!(choose_degree(&mut rng, count), want, "nonce {nonce}");
        }
    }

    /// bc-ur's fragment-index vector for the first thirty parts of an eleven-fragment
    /// message. Parts 1 to 11 are the plain fragments; everything after is a mixture, and
    /// this is the end-to-end check that seed, stream, degree and shuffle all line up.
    #[test]
    fn published_fragment_indexes() {
        const EXPECTED: [&[usize]; 30] = [
            &[0],
            &[1],
            &[2],
            &[3],
            &[4],
            &[5],
            &[6],
            &[7],
            &[8],
            &[9],
            &[10],
            &[9],
            &[2, 5, 6, 8, 9, 10],
            &[8],
            &[1, 5],
            &[1],
            &[0, 2, 4, 5, 8, 10],
            &[5],
            &[2],
            &[2],
            &[0, 1, 3, 4, 5, 7, 9, 10],
            &[0, 1, 2, 3, 5, 6, 8, 9, 10],
            &[0, 2, 4, 5, 7, 8, 9, 10],
            &[3, 5],
            &[4],
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            &[0, 1, 3, 4, 5, 6, 7, 9, 10],
            &[6],
            &[5, 6],
            &[7],
        ];
        let message = make_message("Wolf", 1024);
        let checksum = crate::transport::checksum::crc32(&message);
        let fragment = fragment_length(message.len(), 100).unwrap();
        let count = message.len().div_ceil(fragment) as u32;

        for (i, want) in EXPECTED.iter().enumerate() {
            let mut got = choose_fragments(i as u32 + 1, count, checksum);
            got.sort_unstable();
            assert_eq!(&got[..], *want, "part {}", i + 1);
        }
    }

    /// The nominal length balances rather than fills. bc-ur pins these four.
    #[test]
    fn published_fragment_lengths() {
        assert_eq!(fragment_length(12345, 1955).unwrap(), 1764);
        assert_eq!(fragment_length(12345, 30000).unwrap(), 12345);
        assert_eq!(fragment_length(10, 4).unwrap(), 4);
        assert_eq!(fragment_length(10, 6).unwrap(), 5);
        assert_eq!(fragment_length(0, 10), None);
        assert_eq!(fragment_length(10, 0), None);
    }

    /// Whatever the part number, the indexes it names are in range, distinct, and no more
    /// numerous than there are fragments. The caller's exclusive-or depends on all three.
    #[test]
    fn chosen_indexes_are_always_a_subset() {
        for count in [1u32, 2, 3, 9, 11, 64] {
            for seq in 1..400u32 {
                let mut indexes = choose_fragments(seq, count, 0x0167_aa07);
                assert!(!indexes.is_empty(), "count {count} seq {seq}");
                assert!(indexes.len() <= count as usize, "count {count} seq {seq}");
                assert!(indexes.iter().all(|&i| i < count as usize));
                indexes.sort_unstable();
                let before = indexes.len();
                indexes.dedup();
                assert_eq!(indexes.len(), before, "duplicate index");
            }
        }
    }

    /// The first `seq_len` parts are the plain fragments in order. A decoder that receives
    /// them all in sequence never has to solve anything, which is the common case.
    #[test]
    fn the_first_parts_are_the_plain_fragments() {
        for seq in 1..=9u32 {
            assert_eq!(choose_fragments(seq, 9, 0xdead_beef), vec![seq as usize - 1]);
        }
    }
}
