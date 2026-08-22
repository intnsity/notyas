// Copyright (C) 2025-2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Bytes in, bytes out, and the identity of what is in between.
//!
//! The parse is rust-bitcoin's; see the module docs for why. This file exists for four
//! things it does not give us: a magic check that fails with a sentence a user can act on
//! rather than a parser's, a bound on what a stranger's length prefix may cost before that
//! parse begins ([`survey`]), a serialization helper that names the round-trip guarantee
//! the rest of the engine depends on, and [`psbt_id`], which is what binds an
//! [`super::Inspection`] to the exact bytes it was taken from.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use bitcoin::psbt::Psbt;
use sha2::{Digest, Sha256};

/// The five bytes every PSBT starts with (BIP-174: `psbt` and a 0xff separator).
///
/// Public because the SD reader (m5) uses it to tell a PSBT from the other files on a
/// card without paying for a full parse.
pub const PSBT_MAGIC: [u8; 5] = [0x70, 0x73, 0x62, 0x74, 0xff];

/// The largest file this module will hand to the parser.
///
/// Read out of [`super::StructuralLimits`] rather than restated, because two copies of a
/// safety limit are two limits. Check 9 enforces the same number against the SERIALIZED
/// length, which is the figure a review screen quotes; this one enforces it against the
/// bytes as they arrived, which is the only point at which it can still protect anything.
const MAX_PSBT_BYTES: usize = super::StructuralLimits::DEFAULT.max_psbt_bytes;

/// PSBT_GLOBAL_VERSION, BIP-174's type 0xFB. Its key data is empty and its value is a
/// four-byte little-endian integer.
const PSBT_GLOBAL_VERSION: u8 = 0xfb;

/// Type 0x00: PSBT_GLOBAL_UNSIGNED_TX in the global map, PSBT_IN_NON_WITNESS_UTXO in an
/// input map. One constant for the two because they are the same byte carrying the same
/// shape - a whole transaction - and they are the only two places in a v0 file where a
/// value holds one.
const PSBT_TYPE_TRANSACTION: u8 = 0x00;

/// PSBT_IN_FINAL_SCRIPTWITNESS, type 0x08 in an input map: a bare BIP-144 witness, and
/// the shortest route in the format from five bytes to sixteen megabytes.
const PSBT_IN_FINAL_SCRIPTWITNESS: u8 = 0x08;

/// PSBT_IN_WITNESS_UTXO, type 0x01 in an input map: one transaction output, whose
/// scriptPubKey length is the only prefix in it.
const PSBT_IN_WITNESS_UTXO: u8 = 0x01;

/// PSBT_IN_TAP_BIP32_DERIVATION, BIP-371's type 0x16 in an input map, and
/// PSBT_OUT_TAP_BIP32_DERIVATION, its type 0x07 in an output map. Two constants because
/// the byte differs; one grammar, because the value does not - a count of taproot leaf
/// hashes, the hashes themselves, then a BIP-32 key source.
const PSBT_IN_TAP_BIP32_DERIVATION: u8 = 0x16;
const PSBT_OUT_TAP_BIP32_DERIVATION: u8 = 0x07;

/// PSBT_OUT_TAP_TREE, BIP-371's type 0x06 in an output map: a depth-first list of leaves,
/// each one a depth, a leaf version and a script.
const PSBT_OUT_TAP_TREE: u8 = 0x06;

/// PSBT_GLOBAL_PROPRIETARY, PSBT_IN_PROPRIETARY and PSBT_OUT_PROPRIETARY. One constant for
/// the three because BIP-174 gives them the same byte AND the same key grammar, which is
/// the one place in this walk where knowing the map is not needed to know the shape.
const PSBT_PROPRIETARY: u8 = 0xfc;

/// What one element of a counted vector costs on the wire at its very smallest: the `w` of
/// [`affordable`].
///
/// Each is a floor and not an estimate, which is what makes requiring it safe: a
/// transaction input is a 36-byte outpoint, a one-byte empty script length and a four-byte
/// sequence; a transaction output is an eight-byte amount and a one-byte empty script
/// length; a taproot leaf hash is exactly 32 bytes; a witness element is a one-byte length
/// and no data. Nothing smaller can be serialized, so a file a parser would accept always
/// carries them, and demanding them is what holds a reservation to a small multiple of the
/// bytes that bought it rather than to `MAX_VEC_SIZE`.
const TX_INPUT_MIN_BYTES: u64 = 41;
const TX_OUTPUT_MIN_BYTES: u64 = 9;
const TAP_LEAF_HASH_BYTES: u64 = 32;
const WITNESS_ELEMENT_MIN_BYTES: u64 = 1;

/// Why a file did not become a PSBT.
///
/// Distinct from [`super::CheckFailure`] on purpose: this is not a refusal. A refusal
/// means the device understood a transaction and declined it, which is a different screen
/// and a different sentence from "that file is not a transaction" (WALLET-API.md 3, gate
/// 0). [`Malformed::PsbtVersionUnsupported`] is the one entry that strains that line, and
/// [`decode`] says why it has to live here anyway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Malformed {
    /// Nothing to parse.
    Empty,
    /// Too short to even carry the magic.
    Truncated { len: usize },
    /// The magic is wrong. Almost always the wrong file, or a base64/hex wrapper that the
    /// caller was supposed to strip first. That autodetect is `firmware::signing::PsbtEncoding`
    /// (`firmware/src/signing.rs`) - the plan this crate's own doc once pointed at,
    /// `notyas-wallet`'s `transport::decode` (WALLET-API.md 2.10), was never built; the
    /// device's own transport layer took the job instead.
    NotAPsbt,
    /// More bytes than [`MAX_PSBT_BYTES`], caught before the parser sees any of them.
    TooLarge { len: usize, max: usize },
    /// A length prefix, or a count of things of a known size, asks for more bytes than the
    /// file has left to give. `declared` is the bytes asked for and not the count that
    /// asked, so the two figures in the sentence are in the same unit.
    ///
    /// Reported instead of the parser's end-of-file error because the parser reaches that
    /// error only after reserving what the prefix asked for; see [`survey`].
    LengthPrefixOverrun { declared: u64, remaining: usize },
    /// The file names a PSBT version this device does not implement. BIP-370 v2 is the
    /// only one in circulation and a coordinator can usually be told to emit v0 instead,
    /// which is why this says which version rather than only that the file was unreadable.
    PsbtVersionUnsupported { version: u32 },
    /// The magic was right and the body was not. Carries the parser's reason as text
    /// rather than as `bitcoin::psbt::Error`: it is specific enough to be worth showing
    /// under the plain-language headline, and keeping the dependency's error type out of
    /// this crate's public API means a change to their enum is not a change to ours.
    Damaged(String),
}

impl fmt::Display for Malformed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Malformed::Empty => write!(f, "the file is empty"),
            Malformed::Truncated { len } => {
                write!(f, "the file is {len} bytes, too short to be a transaction")
            }
            Malformed::NotAPsbt => write!(f, "this file is not a PSBT"),
            Malformed::TooLarge { len, max } => {
                write!(f, "the file is {len} bytes, too large to read (the limit is {max})")
            }
            Malformed::LengthPrefixOverrun {
                declared,
                remaining,
            } => write!(
                f,
                "this PSBT is damaged: a field claims {declared} bytes and {remaining} are left"
            ),
            // Deliberately the same sentence as `CheckFailure::PsbtVersionUnsupported`,
            // minus the check number a gate-0 screen has no business showing.
            Malformed::PsbtVersionUnsupported { version } => {
                write!(f, "PSBT version {version} is not supported, only version 0")
            }
            Malformed::Damaged(e) => write!(f, "this PSBT is damaged: {e}"),
        }
    }
}

impl core::error::Error for Malformed {}

/// Parse a binary PSBT.
///
/// Binary only. Base64 and hex are transport encodings and are autodetected one layer up
/// (`firmware::signing::PsbtEncoding`, sniffed off the file as it comes off the card, where
/// the file name also lives) rather than here; teaching the parser about them would put
/// three ways to reach the same bytes inside the component that reads untrusted input. The
/// size cap is applied there too and again here, because a cap only the transport applies
/// is a cap that a second reader walks around.
///
/// The order of what follows is the whole of what this function decides, and it is the
/// order it is in because everything ahead of `Psbt::deserialize` exists to make sure no
/// length a stranger wrote reaches an allocator before the file has been shown small
/// enough to pay for it. [`super::StructuralLimits::max_psbt_bytes`] cannot do that job
/// from [`super::inspect`]: by the time inspect measures a serialized length, the
/// allocation the file asked for has already happened or already failed.
///
/// The version IS checked here, by [`survey`], and a BIP-370 file is refused as
/// [`Malformed::PsbtVersionUnsupported`]. This is not where the design put it, and the
/// difference is worth stating rather than hiding: "we understood this and will not sign
/// it" is a refusal, and [`super::CheckFailure::PsbtVersionUnsupported`] is the refusal it
/// belongs with. But [`super::inspect`] can only refuse a `Psbt`, and rust-bitcoin will
/// not build one from a v2 file - `decode_global` returns a version error in place of a
/// structure, exactly as BIP-174 tells a parser to ("If a parser encounters a version
/// number it does not recognize, it should exit immediately"). Reaching check 9 with a v2
/// file would therefore take a BIP-370 parser this module deliberately does not have. The
/// two variants print the same sentence instead, so that the screen a user is shown does
/// not depend on which of them ran.
pub fn decode(bytes: &[u8]) -> Result<Psbt, Malformed> {
    if bytes.is_empty() {
        return Err(Malformed::Empty);
    }
    if bytes.len() < PSBT_MAGIC.len() {
        return Err(Malformed::Truncated { len: bytes.len() });
    }
    if bytes[..PSBT_MAGIC.len()] != PSBT_MAGIC {
        return Err(Malformed::NotAPsbt);
    }
    if bytes.len() > MAX_PSBT_BYTES {
        return Err(Malformed::TooLarge {
            len: bytes.len(),
            max: MAX_PSBT_BYTES,
        });
    }
    survey(bytes)?;
    Psbt::deserialize(bytes).map_err(|e| Malformed::Damaged(e.to_string()))
}

/// Walk the key-value pair stream without building anything out of it.
///
/// Not a second parser and not a validity check: it decides nothing about whether a file
/// is a PSBT. It answers one question per length prefix - can the bytes behind this pay
/// for what it says - and reads one field, and it allocates nothing at all.
///
/// It exists because [`MAX_PSBT_BYTES`] cannot bound the peak on its own. rust-bitcoin's
/// `raw::Key::decode` reserves a key's declared length before reading a byte of it, and
/// bounds that figure against its own `MAX_VEC_SIZE` of 4,000,000 and against nothing in
/// the file. Eleven bytes on an SD card can therefore reserve four megabytes, which is
/// under no cap because eleven is under every cap. On a `no_std` plus `alloc` target there
/// is no fallible allocation to fail: a reservation the heap cannot meet runs
/// `handle_alloc_error` next to a 720x720 framebuffer and, during an unlock, the Argon2
/// arena. Requiring every prefix to fit in the bytes behind it puts the peak back within
/// a fixed multiple of the size of the file, instead of at the mercy of a constant inside
/// somebody else's crate, and a bound that moves with the file is the only kind that means
/// anything here. What the multiple is, and why it is not one, is measured further down.
///
/// # Why the walk descends into values
///
/// It bounded only the pair-level prefixes until 2026-08-18, and a prefix nested one level
/// in reached the allocator untouched. `Witness::consensus_decode` runs
/// `vec![0u8; elements * 4 + 128]` with `elements` bounded by `MAX_VEC_SIZE` and by
/// nothing in the file, so an 82-byte PSBT carrying PSBT_IN_FINAL_SCRIPTWITNESS with the
/// five-byte value `fe00093d00` peaked at 16,000,928 bytes, and a 144-byte one carrying
/// the same count inside a segwit-serialised PSBT_IN_NON_WITNESS_UTXO peaked at
/// 16,001,123. Both are more than fifteen times [`MAX_PSBT_BYTES`], and both are reachable
/// from any SD card or QR scan.
///
/// The descent reached two grammars and this doc was written as though it reached all of
/// them, which was false for six more, all of them measured on 2026-08-18 before they were
/// closed: a 90-byte file peaked at 131,877 bytes on the scriptPubKey length inside
/// PSBT_IN_WITNESS_UTXO, a 114-byte one at 1,000,832 on the leaf-hash count of
/// PSBT_IN_TAP_BIP32_DERIVATION and at 1,001,112 on its output twin, an 84-byte one at
/// 132,152 on a script length inside PSBT_OUT_TAP_TREE, and an 82-byte one at about
/// 131,900 on the prefix length inside a proprietary KEY - once in each of the three maps.
/// `the_worst_case_peak_stays_under_the_file_size_cap` carries the whole table, closed
/// routes included.
///
/// The same descent closes a residual this doc used to apologise for. The unsigned
/// transaction's input and output counts were left alone on the argument that
/// `MAX_VEC_SIZE / 4` already bounded them at about a megabyte, which a legitimate
/// full-size file costs anyway - measured, 999,969 and 1,000,010 bytes from files of 17 and
/// 18. Reaching them needed a transaction walk, and now that one exists for the witness
/// they cost nothing extra: both are counts, both go through [`counted`], and both now peak
/// at zero.
///
/// INVARIANT: no length and no count a stranger wrote reaches an allocator before the
/// bytes behind it have been shown able to pay for it. "Pay" is [`affordable`] and it is
/// one line of arithmetic: a length of `n` needs `n` bytes behind it, and a count of `n`
/// needs `n * w` bytes, where `w` is the least one element of that vector can cost on the
/// wire. It holds at every depth of every value grammar the parser descends into, and
/// "What 'every grammar' is exhaustive over", below, is the argument that those are all of
/// them.
///
/// `w` is why the table's after column is zero and not merely small. With `w` at one for
/// everything - which
/// is true of every consensus vector and was all this walk used to require - the invariant
/// still held word for word and still allowed a 5,017-byte file to peak at 525,007 bytes,
/// because 5,000 declared inputs bought 5,000 `TxIn` of 104 bytes each for 5,000 bytes of
/// padding. Requiring the real floor instead (41 bytes for an input, 9 for an output, 32
/// for a taproot leaf hash, 1 for a witness element) costs nothing a real file can notice
/// and pulls every reservation back to a small multiple of the bytes behind it.
///
/// A small multiple, and not one, and the difference is worth stating rather than leaving
/// for somebody to find. What this walk removes is the allocation a file did not pay a
/// byte for; what it cannot remove is the RATIO a paid-for byte buys, and the two worst
/// ratios in the format are both above eight.
///
/// `Witness::consensus_decode` reserves four bytes of index space per element and then
/// doubles its content buffer as it fills, while a witness element can honestly be one
/// byte - so a 1,048,576-byte file carrying 1,048,490 empty elements peaks at 9,437,544
/// bytes and PARSES. That one is not a refusal at all; it is a well-formed file the device
/// accepts, and `the_worst_ratio_a_paid_for_file_can_still_buy` is what keeps the figure
/// current. Nothing this walk can do would help: every element pays the most it can be
/// asked to pay, which is the one byte it costs on the wire.
///
/// `Psbt::deserialize` reserves one `bitcoin::psbt::Input` per transaction input before it
/// reads an input map, and that struct is 648 bytes against the 41 an input costs on the
/// wire, so a legitimate 1,048,518-byte file declaring 25,573 inputs peaks at 20,571,144
/// bytes - measured, with every prefix in it honest. Closing that needs a bound on the
/// input COUNT before the parse, which is a different limit from this one:
/// `StructuralLimits::max_inputs` is 255 and check 9 enforces it, but check 9 runs on a
/// `Psbt` that already exists. It is left alone here deliberately, because moving it would
/// change which sentence an oversized but well-formed file gets, and that is a decision
/// about screens and not about allocators.
///
/// So the honest ceiling this module offers is not [`MAX_PSBT_BYTES`] but about twenty
/// times it, and every byte of the difference is bought at a fixed rate from a file that
/// paid for it. What no longer exists is the other kind: the megabyte that eighty bytes
/// bought.
///
/// One rule buys all of it, and it is the rule [`payable`] already applied at pair level.
/// [`affordable`] is that single piece of arithmetic; [`counted`] and [`length_prefixed`]
/// are the only two ways any depth of the walk reads a number, and both call it;
/// [`walk_transaction`], [`walk_txout`], [`walk_witness`], [`walk_tap_key_origins`],
/// [`walk_tap_tree`] and [`walk_proprietary_key`] are the grammars needed to reach the
/// prefixes it has to be applied to. None of the six builds anything or judges anything:
/// they locate prefixes and hand each one to the same rule.
///
/// # What "every grammar" is exhaustive over
///
/// Not BIP-174, and the honest version of that sentence is the point of this section. A
/// walk cannot know the shape of a value whose key type it has never met, and guessing at
/// one would refuse files that are perfectly good. What it is exhaustive over is the
/// PARSER, which is a closed thing this crate pins exactly (`bitcoin = "=0.32.102"`), and
/// the argument that it is closed has two halves.
///
/// A key type the parser does not know is not parsed at all: `insert_pair` files it under
/// `unknown` with its value as raw bytes, which cost the bytes they occupy and not one
/// more. A key type a future BIP assigns therefore cannot open a route here while the pin
/// stands, which is the thing an enumeration would otherwise be silently wrong about. What
/// CAN open one is a `bitcoin` bump that teaches the parser a grammar it did not have.
///
/// Among the key types it does know, the grammars carrying a wire-supplied number are the
/// six walked above - five values and one key - and the rest carry none. That is a claim about someone else's
/// code, so it is worth saying where it comes from: a script value is `bytes.to_vec()`, so
/// PSBT_IN_REDEEM_SCRIPT, PSBT_IN_WITNESS_SCRIPT, PSBT_IN_FINAL_SCRIPTSIG and their output
/// twins hold no length inside the value at all; signatures, public keys, hash preimages,
/// x-only keys, a sighash type and a merkle root are fixed-width or bounded by the value
/// itself; a BIP-32 derivation path is one `ChildNumber` per four bytes of value; and a
/// control block is bounded by the key that carries it.
///
/// None of which is trusted. `every_key_type_in_every_map_stays_inside_its_own_bytes`
/// sweeps all 256 type bytes across the three maps against eleven adversarial key and
/// value shapes and measures the peak of each, so the claim above is checked by
/// measurement and not by reading. It is also the tripwire for that `bitcoin` bump, and it
/// needs no list of key types to keep working.
///
/// # Why it knows which map it is in
///
/// The same type byte means different things in different maps: 0x00 is a whole
/// transaction in the global and input maps and a redeem script in an output map, and 0x07
/// is a finalized scriptSig in an input map and BIP-371 key origins in an output one. Reading a value
/// as the wrong shape would refuse files that are perfectly good, so the walk descends only
/// where it knows what it is looking at, and [`Map`] is how it knows: the unsigned
/// transaction says how many input and output maps follow, and BIP-174 fixes their order.
/// Until the global map has stated that shape the walk descends nowhere, which costs
/// nothing - `decode_global` refuses a file with no unsigned transaction before it reads a
/// single input map, so there is no allocation left there to protect.
///
/// A proprietary key is the exception that shows the rule is about ambiguity and not about
/// caution: 0xFC means the same thing in all three maps and carries the same key grammar
/// in each, so [`walk_proprietary_key`] runs wherever the walk is, [`Map::Opaque`]
/// included. There is no map in which reading it that way could be wrong.
///
/// The second job is the version, and it is here because this is the only walk that sees
/// the global map before the parser gives up on it; [`decode`] carries the reasoning.
///
/// What it refuses is what the parser was going to refuse anyway, one allocation earlier,
/// with a single exception worth naming: bytes trailing the last output map, which the
/// parser stops before reading and this walk does not. A file carrying those is not one
/// this device would reproduce byte for byte in any case.
fn survey(bytes: &[u8]) -> Result<(), Malformed> {
    let mut at = PSBT_MAGIC.len();
    let mut map = Map::Global;
    // How many input maps and output maps the unsigned transaction says follow. `None`
    // until the global map has said, which is why [`Map::next`] can hand over to
    // [`Map::Opaque`] rather than guess.
    let mut shape: Option<(u64, u64)> = None;

    while at < bytes.len() {
        // A prefix the file ends inside of costs nothing to reach and is the parser's to
        // report: stopping here leaves its sentence intact rather than inventing a second.
        let Some((key_len, past_prefix)) = compact_size(bytes, at) else {
            return Ok(());
        };
        at = past_prefix;
        // An empty key separates one map from the next.
        if key_len == 0 {
            map = map.next(shape);
            continue;
        }
        let key = payable(bytes, at, key_len)?;
        at += key.len();

        let Some((value_len, past_prefix)) = compact_size(bytes, at) else {
            return Ok(());
        };
        at = past_prefix;
        let value = payable(bytes, at, value_len)?;
        at += value.len();

        match (map, key) {
            // BIP-174's unsigned transaction. `decode_global` reads it field by field -
            // version, inputs, outputs, lock time - with no BIP-144 marker in the grammar
            // at all, so no witness can reach an allocator through it and the walk must not
            // look for one either, or the two would disagree about where the outputs start.
            // What it is walked for is the shape: how many maps follow.
            //
            // The first such pair wins, because the parser refuses a second one
            // (`Error::DuplicateKey`) rather than letting it replace the first.
            (Map::Global, [PSBT_TYPE_TRANSACTION]) if shape.is_none() => {
                shape = walk_transaction(value, Serialization::Unsigned)?;
            }
            // A previous transaction, in network serialization, which may carry witnesses
            // and for any segwit spend does.
            (Map::Input { .. }, [PSBT_TYPE_TRANSACTION]) => {
                walk_transaction(value, Serialization::Network)?;
            }
            (Map::Input { .. }, [PSBT_IN_FINAL_SCRIPTWITNESS]) => {
                walk_witness(value, 0)?;
            }
            // One transaction output. The same two fields the transaction walk reads for
            // each of its own outputs, which is why it is the same function.
            (Map::Input { .. }, [PSBT_IN_WITNESS_UTXO]) => {
                walk_txout(value, 0)?;
            }
            // BIP-371's key origins, whose value opens with a count of taproot leaf
            // hashes. `[_, _, ..]` because the key data is the x-only public key the
            // origins belong to: the parser reads the value only when a key is there, so
            // the walk descends only then and the two agree about which files exist.
            (Map::Input { .. }, [PSBT_IN_TAP_BIP32_DERIVATION, _, ..])
            | (Map::Output { .. }, [PSBT_OUT_TAP_BIP32_DERIVATION, _, ..]) => {
                walk_tap_key_origins(value)?;
            }
            (Map::Output { .. }, [PSBT_OUT_TAP_TREE]) => {
                walk_tap_tree(value)?;
            }
            // The one prefix in the format that lives in a KEY rather than a value, and
            // the one shape that does not depend on which map it was found in.
            (_, [PSBT_PROPRIETARY, key_data @ ..]) => {
                walk_proprietary_key(key_data)?;
            }
            // Only a well-formed version pair is read as one. A malformed one (non-empty
            // key data, or a value that is not four bytes) is left to the parser, which has
            // its own sentences for both and is the authority on them. 0xFB is a version
            // only in the global map; in an input map the same byte is an unknown key type
            // that BIP-174 says must be passed through untouched.
            (Map::Global, [PSBT_GLOBAL_VERSION]) if value.len() == 4 => {
                let version = u32::from_le_bytes([value[0], value[1], value[2], value[3]]);
                if version != 0 {
                    return Err(Malformed::PsbtVersionUnsupported { version });
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Which of BIP-174's maps the walk is inside, and how many of that kind are still to come.
///
/// BIP-174 fixes the order - the global map, then one map per transaction input, then one
/// per transaction output - so counting separators against the unsigned transaction's own
/// input and output counts is enough to know exactly what a type byte means. Nothing here
/// is a validity judgement: a file whose maps do not match its transaction is the parser's
/// to refuse, and this walk only stops descending into it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Map {
    Global,
    /// This map, and `left - 1` more input maps after it.
    Input { left: u64 },
    Output { left: u64 },
    /// A map whose meaning the walk cannot name: past the last output map, or reached
    /// before the global map stated a shape. Descended into nowhere.
    Opaque,
}

impl Map {
    /// The map an empty key hands over to.
    fn next(self, shape: Option<(u64, u64)>) -> Map {
        let Some((inputs, outputs)) = shape else {
            return Map::Opaque;
        };
        match self {
            Map::Global => Map::opening(inputs, outputs),
            Map::Input { left } if left > 1 => Map::Input { left: left - 1 },
            Map::Input { .. } => Map::opening(0, outputs),
            Map::Output { left } if left > 1 => Map::Output { left: left - 1 },
            Map::Output { .. } | Map::Opaque => Map::Opaque,
        }
    }

    /// The first map of a run of `inputs` input maps followed by `outputs` output maps.
    /// Either count may be zero: BIP-174's published vectors 9 and 10 have no inputs.
    fn opening(inputs: u64, outputs: u64) -> Map {
        if inputs > 0 {
            Map::Input { left: inputs }
        } else if outputs > 0 {
            Map::Output { left: outputs }
        } else {
            Map::Opaque
        }
    }
}

/// Which grammar a transaction-bearing value is walked with.
///
/// Two, because rust-bitcoin reads the two values with two different decoders, and a walk
/// that disagreed with the decoder about where a field starts would refuse files the
/// decoder accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Serialization {
    /// PSBT_GLOBAL_UNSIGNED_TX. `decode_global` decodes the four fields by hand rather than
    /// through `Transaction::consensus_decode`, precisely so that a zero-input transaction
    /// is read as a zero-input transaction and not as a BIP-144 marker. An input count of
    /// zero therefore means zero inputs here, and no witness section exists.
    Unsigned,
    /// PSBT_IN_NON_WITNESS_UTXO, read by `Transaction::consensus_decode`, where an input
    /// count of zero IS BIP-144's marker and a flag byte and a witness section follow.
    Network,
}

/// Walk one transaction-shaped value, refusing any prefix its own bytes cannot pay for.
///
/// `Ok(Some((inputs, outputs)))` when the walk reached the end of the transaction, which is
/// the shape [`survey`] needs from the unsigned one. `Ok(None)` when the value ends inside
/// the transaction: the parser reaches the same end and reports it, and inventing a second
/// sentence for it here would only disagree with the first.
///
/// Every loop is bounded by the value: a count that survived [`counted`] is at most the
/// bytes left behind it, and each turn of each loop either consumes at least one of those
/// bytes or returns.
fn walk_transaction(value: &[u8], how: Serialization) -> Result<Option<(u64, u64)>, Malformed> {
    // Version.
    let Some(mut at) = step(value, 0, 4) else {
        return Ok(None);
    };

    let Some((mut inputs, past)) = counted(value, at, TX_INPUT_MIN_BYTES)? else {
        return Ok(None);
    };
    at = past;

    // BIP-144: in network serialization an input count of zero is the marker, and the real
    // count follows the flag byte. The witnesses then sit after the outputs, one per input.
    let mut witnesses = false;
    if inputs == 0 && how == Serialization::Network {
        let Some(past) = step(value, at, 1) else {
            return Ok(None);
        };
        let Some((real, past)) = counted(value, past, TX_INPUT_MIN_BYTES)? else {
            return Ok(None);
        };
        inputs = real;
        at = past;
        witnesses = true;
    }

    for _ in 0..inputs {
        // Outpoint, script_sig, sequence.
        let Some(past) = step(value, at, 36) else {
            return Ok(None);
        };
        let Some(past) = length_prefixed(value, past)? else {
            return Ok(None);
        };
        let Some(past) = step(value, past, 4) else {
            return Ok(None);
        };
        at = past;
    }

    let Some((outputs, past)) = counted(value, at, TX_OUTPUT_MIN_BYTES)? else {
        return Ok(None);
    };
    at = past;
    for _ in 0..outputs {
        let Some(past) = walk_txout(value, at)? else {
            return Ok(None);
        };
        at = past;
    }

    if witnesses {
        for _ in 0..inputs {
            let Some(past) = walk_witness(value, at)? else {
                return Ok(None);
            };
            at = past;
        }
    }

    Ok(Some((inputs, outputs)))
}

/// Walk one witness at `at`, and the offset just past it.
///
/// This is the prefix the whole descent exists for: `Witness::consensus_decode` turns the
/// element count into `vec![0u8; count * 4 + 128]` before it reads a single element, and
/// bounds that count against `MAX_VEC_SIZE` alone. [`counted`] bounds it against the bytes
/// behind it instead, which is what a witness of that many elements would actually cost.
fn walk_witness(value: &[u8], at: usize) -> Result<Option<usize>, Malformed> {
    let Some((elements, mut at)) = counted(value, at, WITNESS_ELEMENT_MIN_BYTES)? else {
        return Ok(None);
    };
    for _ in 0..elements {
        let Some(past) = length_prefixed(value, at)? else {
            return Ok(None);
        };
        at = past;
    }
    Ok(Some(at))
}

/// Walk one transaction output at `at`, and the offset just past it.
///
/// Two callers and one grammar: a transaction's own outputs, and PSBT_IN_WITNESS_UTXO,
/// which is a single `TxOut` on its own. `TxOut::consensus_decode` reads the script through
/// the `Vec<u8>` decoder every script goes through, which reserves in 128 KiB chunks rather
/// than in one bite - so an unpayable length here cost 131,877 bytes out of a 90-byte file
/// rather than the four megabytes a single reservation would have. Smaller than the witness
/// route, and just as unpaid for.
fn walk_txout(value: &[u8], at: usize) -> Result<Option<usize>, Malformed> {
    // Amount, then the script.
    let Some(past) = step(value, at, 8) else {
        return Ok(None);
    };
    length_prefixed(value, past)
}

/// Walk a BIP-371 key-origins value: PSBT_IN_TAP_BIP32_DERIVATION and its output twin.
///
/// `<leaf hash count> <32 bytes each> <fingerprint> <derivation path>`, and only the first
/// of those is a number a stranger chose. `Vec<TapLeafHash>::consensus_decode` reserves
/// `min(count, MAX_VEC_SIZE / 4 / 32)` hashes of 32 bytes before reading any of them, which
/// is a megabyte out of a 114-byte file, and `MAX_VEC_SIZE` was the only thing standing
/// between that count and the allocator.
///
/// The walk stops after the count on purpose rather than by omission: what follows is the
/// hashes, which are fixed-width, and then a key source, whose derivation path is one
/// `ChildNumber` per four bytes of whatever is left of the value. Neither holds a prefix,
/// so there is nothing further to hand to the rule.
fn walk_tap_key_origins(value: &[u8]) -> Result<(), Malformed> {
    counted(value, 0, TAP_LEAF_HASH_BYTES)?;
    Ok(())
}

/// Walk PSBT_OUT_TAP_TREE: `<depth> <leaf version> <script>`, repeated to the end of the
/// value.
///
/// Every script there is a length a stranger wrote, and `TapTree::deserialize` reads each
/// one with the same chunked `Vec<u8>` decoder, so a single leaf whose script claims more
/// than the value holds cost 132,152 bytes out of an 84-byte file. The loop cannot spin:
/// each turn consumes the two fixed bytes and at least one prefix byte, or returns.
///
/// Reaching the end of the value mid-leaf is not this walk's to report. `TapTree` refuses
/// it too, and a second sentence for it here would only disagree with the parser's.
fn walk_tap_tree(value: &[u8]) -> Result<(), Malformed> {
    let mut at = 0;
    while at < value.len() {
        // Depth and leaf version, then the script.
        let Some(past) = step(value, at, 2) else {
            return Ok(());
        };
        let Some(past) = length_prefixed(value, past)? else {
            return Ok(());
        };
        at = past;
    }
    Ok(())
}

/// Walk the key data of a proprietary pair: `<prefix len> <prefix> <subtype> <key data>`.
///
/// `key_data` is what follows the 0xFC type byte, and it opens with a length prefix nested
/// inside a key the pair-level rule has already made payable - which does not make the
/// nested one payable, and 131,874 bytes out of an 82-byte file is what the difference was
/// worth. Nothing after the prefix needs the rule: `ProprietaryKey`'s decoder reads the
/// subtype as one byte and takes the remainder under a 1,024-byte limit of its own.
fn walk_proprietary_key(key_data: &[u8]) -> Result<(), Malformed> {
    length_prefixed(key_data, 0)?;
    Ok(())
}

/// The count at `at`, checked to be one the bytes behind it could pay for, and the offset
/// just past its prefix.
///
/// `each` is what one of the counted things costs on the wire at its smallest, so that the
/// bytes a count is asked for are the bytes its elements would actually occupy.
fn counted(value: &[u8], at: usize, each: u64) -> Result<Option<(u64, usize)>, Malformed> {
    let Some((count, past)) = compact_size(value, at) else {
        return Ok(None);
    };
    affordable(value.len() - past, count, each)?;
    Ok(Some((count, past)))
}

/// The offset just past a length-prefixed field at `at`, refusing a length the bytes behind
/// it cannot pay for.
fn length_prefixed(value: &[u8], at: usize) -> Result<Option<usize>, Malformed> {
    let Some((len, past)) = compact_size(value, at) else {
        return Ok(None);
    };
    // A length counts bytes, so one unit is one byte and the rule is the identity.
    affordable(value.len() - past, len, 1)?;
    Ok(Some(past + len as usize))
}

/// `at + by`, or `None` if the value ends first. Fixed-width fields only, so there is no
/// stranger's number in it and nothing to refuse.
fn step(value: &[u8], at: usize, by: usize) -> Option<usize> {
    let past = at.checked_add(by)?;
    (past <= value.len()).then_some(past)
}

/// Whether `remaining` bytes can pay for `units` things of `each` bytes.
///
/// The whole of the rule, and one function for lengths and for counts because it is one
/// piece of arithmetic: a length is `units` bytes with `each` at 1, and a count is `units`
/// elements of the least an element of that vector can be. The per-element constants say
/// why those floors are floors and not guesses.
///
/// The product is taken as `u128` and compared before anything is narrowed, so neither a
/// figure larger than the address space nor a pair of wire numbers whose product leaves
/// `u64` can wrap into something affordable. `declared` reports the bytes demanded rather
/// than the count that demanded them, because that is the figure the sentence quotes
/// against `remaining`; it saturates, which can only bite for a count no file could hold
/// the elements of in any case.
fn affordable(remaining: usize, units: u64, each: u64) -> Result<(), Malformed> {
    let declared = u128::from(units) * u128::from(each);
    if declared > remaining as u128 {
        return Err(Malformed::LengthPrefixOverrun {
            declared: u64::try_from(declared).unwrap_or(u64::MAX),
            remaining,
        });
    }
    Ok(())
}

/// The `len` bytes at `at`, or the overrun that says the file cannot pay for them.
fn payable(bytes: &[u8], at: usize, len: u64) -> Result<&[u8], Malformed> {
    affordable(bytes.len() - at, len, 1)?;
    Ok(&bytes[at..at + len as usize])
}

/// The compact size integer at `at`, and the offset just past it.
///
/// `None` when the file ends inside the prefix. Non-minimal encodings are accepted here
/// and rejected by the parser: this walk is not the authority on what a valid file looks
/// like, and disagreeing with the parser about it would only mean refusing files for a
/// reason the parser could not confirm.
fn compact_size(bytes: &[u8], at: usize) -> Option<(u64, usize)> {
    let (width, value) = match *bytes.get(at)? {
        0xff => (8, u64::from_le_bytes(bytes.get(at + 1..at + 9)?.try_into().ok()?)),
        0xfe => (
            4,
            u64::from(u32::from_le_bytes(bytes.get(at + 1..at + 5)?.try_into().ok()?)),
        ),
        0xfd => (
            2,
            u64::from(u16::from_le_bytes(bytes.get(at + 1..at + 3)?.try_into().ok()?)),
        ),
        small => (0, u64::from(small)),
    };
    Some((value, at + 1 + width))
}

/// Serialize a PSBT back to the wire format.
///
/// What is guaranteed, and the reason this is a named function rather than a call to
/// `Psbt::serialize` at each site: every key-value pair that came in goes back out, in the
/// global map and in every input and output map, unknown and proprietary pairs included,
/// each with its value unaltered. That is BIP-174's obligation on a signer, in its words:
/// "If the signer encounters key-value pairs that it does not understand, it must pass
/// those key-value pairs through when re-serializing the transaction."
/// `psbt_roundtrip_preserves_unknown_fields` is the standing proof, over the BIP-174
/// vector that carries an unknown type.
///
/// What is NOT guaranteed, though this doc claimed it until 2026-08-18: byte-for-byte
/// identity with the coordinator's file. rust-bitcoin emits each map in its own canonical
/// order - unsigned transaction, xpubs, version, proprietary, unknown, and within each of
/// those the key order of the `BTreeMap` holding it - so a file whose pairs arrived in a
/// different order comes back equivalent rather than identical. No pair is lost and no
/// value is changed, which is the whole of what BIP-174 asks: it fixes no order on the
/// pairs, so there is no spec violation to fix and nothing downstream is owed byte
/// stability across this device. Reproducing a coordinator's layout would mean carrying
/// the original byte offsets of every pair alongside its contents, through parse, review
/// and signature, for a property nothing needs.
/// `an_out_of_order_file_survives_as_pairs_and_not_as_bytes` is what holds that line, and
/// it is a claim about this device, not a defect in the coordinator that produced the file.
///
/// What the engine actually rests on is the weaker statement, and that one does hold: this
/// serialization is canonical, so serializing it again reproduces it exactly. [`psbt_id`]
/// and [`unsigned_id`] are identities of THIS device's bytes, taken and rechecked on this
/// side of the parse, and their stability needs nothing at all about the coordinator's
/// layout. `encode_is_idempotent_over_the_corpus` is the proof.
pub fn encode(psbt: &Psbt) -> Vec<u8> {
    psbt.serialize()
}

/// SHA-256 of the serialized PSBT: the identity an [`super::Inspection`] is bound to.
///
/// Not a txid and not consensus-relevant. Its only job is to make "sign what was
/// reviewed" checkable, so it must cover every byte the reviewer's decision could have
/// depended on - which is why it hashes the serialization rather than the unsigned
/// transaction.
pub fn psbt_id(psbt: &Psbt) -> [u8; 32] {
    <[u8; 32]>::from(Sha256::digest(encode(psbt)))
}

/// SHA-256 of the PSBT with every signature field cleared: the identity signing does not
/// move.
///
/// [`psbt_id`] is the strict one, and it is the one [`super::sign`] checks, because before
/// a signature exists nothing about the file is allowed to have changed. The post-sign
/// gate needs the weaker statement and cannot use the strict one at all: by the time it
/// runs, the PSBT in front of it carries signatures the reviewed bytes did not. Clearing
/// the three fields a signer may write and hashing what is left says exactly "this is the
/// reviewed transaction, plus signatures", which is the premise the gate needs and the
/// most it can be given.
///
/// It is deliberately blind to WHOSE signatures, ours included. Signatures are what the
/// gate exists to check, so making them part of its admission ticket would be circular;
/// and a coordinator can add a foreign `partial_sigs` entry at any moment, so an identity
/// that moved when one appeared would let anyone lock the gate shut (see
/// [`super::verify_signatures`] on foreign entries).
pub fn unsigned_id(psbt: &Psbt) -> [u8; 32] {
    let mut stripped = psbt.clone();
    for input in &mut stripped.inputs {
        input.partial_sigs.clear();
        input.tap_key_sig = None;
        input.tap_script_sigs.clear();
    }
    // The clone is released before the hash rather than at the end of the function: with
    // `StructuralLimits::max_psbt_bytes` at a megabyte, holding the clone and its
    // serialization and the digest at once is three copies of a file on a device whose
    // PSRAM also carries a framebuffer.
    let serialized = encode(&stripped);
    drop(stripped);
    <[u8; 32]>::from(Sha256::digest(serialized))
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::psbt::test_corpus;
    use crate::psbt::CheckFailure;
    use alloc::string::ToString;

    /// Byte-for-byte over the CORPUS, which is a narrower statement than it looks: the
    /// published vectors happen to be in rust-bitcoin's emission order, so this proves
    /// that this device agrees with the BIPs about their bytes and not that any file
    /// survives unchanged. [`encode`] says which of those two [`psbt_id`] needs.
    #[test]
    fn every_corpus_vector_round_trips_byte_for_byte() {
        for (name, hex_bytes) in test_corpus::VECTORS {
            let raw = hex::decode(hex_bytes).expect(name);
            let psbt = decode(&raw).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(encode(&psbt), raw, "{name} did not round trip");
        }
    }

    /// The one that matters for a coordinator: BIP-174's "unknown types in the input"
    /// vector carries a key this crate has never heard of, and it must come back out.
    #[test]
    fn psbt_roundtrip_preserves_unknown_fields() {
        let raw = hex::decode(test_corpus::BIP174_UNKNOWN_TYPES).unwrap();
        let psbt = decode(&raw).unwrap();
        assert_eq!(psbt.inputs[0].unknown.len(), 1);
        let (key, value) = psbt.inputs[0].unknown.iter().next().unwrap();
        // 0xf0, not 0x0f. Both the vector and this assertion carried the transposed byte
        // until 2026-08-18 and agreed with each other, which is why the test passed while
        // proving nothing about BIP-174's actual file. 0x0f is PSBT_IN_OUTPUT_INDEX, a
        // BIP-370 field excluded from v0; 0xf0 is genuinely unassigned, which is what
        // makes it an unknown type worth round-tripping.
        assert_eq!(key.type_value, 0xf0);
        assert_eq!(key.key, hex::decode("010203040506070809").unwrap());
        assert_eq!(value, &hex::decode("0102030405060708090a0b0c0d0e0f").unwrap());
        assert_eq!(encode(&psbt), raw);
    }

    #[test]
    fn an_empty_file_is_not_a_damaged_psbt() {
        assert_eq!(decode(&[]).unwrap_err(), Malformed::Empty);
        assert_eq!(
            decode(&[0x70, 0x73]).unwrap_err(),
            Malformed::Truncated { len: 2 }
        );
    }

    /// A base64 file handed straight to the parser is the commonest real mistake, and it
    /// must not read as a damaged PSBT.
    #[test]
    fn a_wrong_file_says_so_rather_than_blaming_the_psbt() {
        let err = decode(b"cHNidP8BAHUCAAAAASaBcTce3").unwrap_err();
        assert_eq!(err, Malformed::NotAPsbt);
        assert_eq!(err.to_string(), "this file is not a PSBT");
    }

    /// A body cut short is a damaged PSBT and not a wrong file, whichever of the two
    /// things that read it notices first. Where the cut lands decides which: through a
    /// declared length, [`survey`] refuses it and can say by how much; past the last pair,
    /// there is no prefix left to disagree with and the parser reports it.
    #[test]
    fn a_truncated_body_under_a_good_magic_is_damaged() {
        let whole = hex::decode(test_corpus::BIP174_UNKNOWN_TYPES).unwrap();

        // Four bytes gone takes two out of the last pair's 15-byte value.
        let mut through_a_value = whole.clone();
        through_a_value.truncate(whole.len() - 4);
        assert_eq!(
            decode(&through_a_value).unwrap_err(),
            Malformed::LengthPrefixOverrun {
                declared: 15,
                remaining: 13
            }
        );

        // Two bytes gone takes the input and output map separators and nothing else, so
        // every length prefix in the file is still payable and the parser runs out first.
        let mut after_the_last_pair = whole.clone();
        after_the_last_pair.truncate(whole.len() - 2);
        assert!(matches!(
            decode(&after_the_last_pair),
            Err(Malformed::Damaged(_))
        ));
    }

    /// The identity must move when anything in the file moves, including a field the
    /// engine itself never reads.
    #[test]
    fn psbt_id_covers_the_unknown_fields_too() {
        let raw = hex::decode(test_corpus::BIP174_UNKNOWN_TYPES).unwrap();
        let psbt = decode(&raw).unwrap();
        let before = psbt_id(&psbt);
        let mut stripped = psbt.clone();
        stripped.inputs[0].unknown.clear();
        assert_ne!(before, psbt_id(&stripped));
        assert_eq!(before, psbt_id(&psbt));
    }

    /// [`unsigned_id`] must move for every byte [`psbt_id`] moves for except the signature
    /// fields, or it is not a binding; and must not move for those, or the post-sign gate
    /// could never run.
    #[test]
    fn unsigned_id_ignores_signatures_and_nothing_else() {
        // BIP-174 vector 5 is the corpus entry that actually carries a partial signature.
        let psbt = decode(&hex::decode(test_corpus::BIP174_P2WSH_MULTISIG).unwrap()).unwrap();
        let before = unsigned_id(&psbt);
        let signature = *psbt.inputs[0].partial_sigs.values().next().unwrap();

        let mut without = psbt.clone();
        without.inputs[0].partial_sigs.clear();
        assert_eq!(before, unsigned_id(&without), "removing a signature must not move it");
        assert_ne!(psbt_id(&psbt), psbt_id(&without), "psbt_id is the strict one");

        // A key nothing in this vector signs with - what a coordinator can add for free.
        let mut foreign = psbt;
        let other = bitcoin::PublicKey::from_slice(
            &hex::decode("02657d118d3357b8e0f4c2cd46db7b39f6d9c38d9a70abcb9b2de5dc8dbfe4ce31")
                .unwrap(),
        )
        .unwrap();
        foreign.inputs[0].partial_sigs.insert(other, signature);
        assert_eq!(before, unsigned_id(&foreign), "adding one must not move it either");

        // Everything else still moves it, unknown fields included.
        let carrier = decode(&hex::decode(test_corpus::BIP174_UNKNOWN_TYPES).unwrap()).unwrap();
        let mut stripped = carrier.clone();
        stripped.inputs[0].unknown.clear();
        assert_ne!(unsigned_id(&carrier), unsigned_id(&stripped));
    }

    // -----------------------------------------------------------------------------------
    // What a hostile file costs
    // -----------------------------------------------------------------------------------

    /// A thread-local allocation meter.
    ///
    /// Peak allocation is a safety property on this device and not a performance one:
    /// `no_std` plus `alloc` has no fallible allocation path, so a reservation the heap
    /// cannot satisfy runs `handle_alloc_error` while PSRAM is already carrying a 720x720
    /// framebuffer and, during an unlock, the Argon2 arena. It therefore has to be
    /// measured rather than argued about, which is what this exists for.
    ///
    /// Accounting is per-thread because the harness runs the rest of this suite in
    /// parallel and a process-wide counter would be measuring those tests too.
    mod meter {
        use core::alloc::{GlobalAlloc, Layout};
        use core::cell::Cell;
        use std::alloc::System;

        std::thread_local! {
            /// `Some((live, peak))` while a measurement is running on this thread.
            /// Const-initialized and free of `Drop` on purpose: a thread-local that
            /// allocates on first touch or registers a destructor would re-enter the
            /// allocator that reads it.
            static LEDGER: Cell<Option<(usize, usize)>> = const { Cell::new(None) };
        }

        fn took(bytes: usize) {
            // `try_with`, not `with`: a thread-local read after TLS teardown must not
            // panic inside the allocator.
            let _ = LEDGER.try_with(|ledger| {
                if let Some((live, peak)) = ledger.get() {
                    let live = live + bytes;
                    ledger.set(Some((live, peak.max(live))));
                }
            });
        }

        fn gave(bytes: usize) {
            let _ = LEDGER.try_with(|ledger| {
                if let Some((live, peak)) = ledger.get() {
                    // Saturating: a buffer allocated before the window and freed inside it
                    // is a real deallocation of bytes this ledger never counted.
                    ledger.set(Some((live.saturating_sub(bytes), peak)));
                }
            });
        }

        pub struct Metered;

        unsafe impl GlobalAlloc for Metered {
            unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
                took(layout.size());
                System.alloc(layout)
            }

            unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
                took(layout.size());
                System.alloc_zeroed(layout)
            }

            unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
                gave(layout.size());
                System.dealloc(ptr, layout)
            }

            unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
                gave(layout.size());
                took(new_size);
                System.realloc(ptr, layout, new_size)
            }
        }

        /// The high-water mark of live bytes on this thread while `f` runs.
        pub fn peak_bytes<T>(f: impl FnOnce() -> T) -> usize {
            LEDGER.with(|ledger| ledger.set(Some((0, 0))));
            drop(f());
            LEDGER.with(|ledger| ledger.take()).expect("the meter was armed").1
        }
    }

    #[global_allocator]
    static METERED: meter::Metered = meter::Metered;

    /// An eleven-byte file must not cost more than an eleven-byte file.
    #[test]
    fn a_hostile_key_length_costs_only_what_the_file_holds() {
        // Magic, then one key whose declared length is 4,000,001. `keylen` covers the type
        // byte and the key data together, so this promises 4,000,000 bytes of key data in
        // a file with one byte left. rust-bitcoin's `raw::Key::decode` bounds that 4,000,000
        // against its own `MAX_VEC_SIZE` and against nothing else, then reserves it before
        // reading a byte of it, so the reservation succeeds and only the read after it
        // fails: before `survey` this file peaked at 4,000,000 bytes.
        let hostile = hex::decode("70736274fffe01093d0000").unwrap();
        assert_eq!(hostile.len(), 11);

        let peak = meter::peak_bytes(|| decode(&hostile));
        assert!(peak < 8 * 1024, "an 11-byte file peaked at {peak} bytes");

        assert_eq!(
            decode(&hostile).unwrap_err(),
            Malformed::LengthPrefixOverrun {
                declared: 4_000_001,
                remaining: 1
            }
        );
    }

    /// The BIP-174 unknown-types vector's global map: the magic, the unsigned transaction
    /// pair (one input, one output), and the separator that closes the map. 72 bytes, and
    /// every prefix in it honest, so whatever follows is the only thing under measurement.
    fn global_map_prefix() -> Vec<u8> {
        hex::decode(concat!(
            "70736274ff",
            "0100",
            "3f",
            "0200000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "0000000000ffffffff010000000000000000036a010000000000",
            "00",
        ))
        .unwrap()
    }

    /// That prefix, `pairs` as the single input map, and the two separators that close the
    /// input map and the (empty) output map.
    fn with_input_map(pairs: &str) -> Vec<u8> {
        let mut out = global_map_prefix();
        out.extend_from_slice(&hex::decode(pairs).unwrap());
        out.extend_from_slice(&[0x00, 0x00]);
        out
    }

    /// That prefix, an empty input map, and `pairs` as the single output map.
    fn with_output_map(pairs: &str) -> Vec<u8> {
        let mut out = global_map_prefix();
        out.push(0x00);
        out.extend_from_slice(&hex::decode(pairs).unwrap());
        out.push(0x00);
        out
    }

    /// That prefix with `pairs` spliced into the global map, ahead of its separator, and
    /// an empty input map and output map after it.
    fn with_global_pair(pairs: &str) -> Vec<u8> {
        let mut out = global_map_prefix();
        out.truncate(out.len() - 1);
        out.extend_from_slice(&hex::decode(pairs).unwrap());
        out.extend_from_slice(&[0x00, 0x00, 0x00]);
        out
    }

    /// A valid x-only public key, needed because the parser deserializes a keyed pair's KEY
    /// before its value: a hostile value behind a key that is not a public key would never
    /// be reached, and the route would look closed when it was only unreachable. Any point
    /// on the curve does; this is the generator's x coordinate.
    const XONLY: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    /// Every route a stranger's number has to an allocator, measured rather than assumed.
    ///
    /// The test carried this name from the start and did not earn it twice over. It began
    /// as the two transaction counts alone, so it passed for months while an 82-byte
    /// counterexample stood; the four routes that replaced them were still only the ones
    /// [`survey`] happened to walk, and six more stood behind them until 2026-08-18. The
    /// eleven below are the whole set, and what makes that a claim and not a hope is
    /// [`every_key_type_in_every_map_stays_inside_its_own_bytes`], which finds routes
    /// instead of listing them.
    ///
    /// Measured with `bitcoin` 0.32.102, before and after [`survey`] learned each grammar:
    ///
    /// | route | file | before | after |
    /// |---|---|---|---|
    /// | transaction input count | 17 B | 999,969 B | 0 B |
    /// | transaction output count | 18 B | 1,000,010 B | 0 B |
    /// | PSBT_IN_FINAL_SCRIPTWITNESS | 82 B | 16,000,928 B | 0 B |
    /// | witness inside PSBT_IN_NON_WITNESS_UTXO | 144 B | 16,001,123 B | 0 B |
    /// | PSBT_IN_WITNESS_UTXO script length | 90 B | 131,877 B | 0 B |
    /// | PSBT_IN_TAP_BIP32_DERIVATION leaf-hash count | 114 B | 1,000,832 B | 0 B |
    /// | PSBT_OUT_TAP_BIP32_DERIVATION leaf-hash count | 114 B | 1,001,112 B | 0 B |
    /// | PSBT_OUT_TAP_TREE script length | 84 B | 132,152 B | 0 B |
    /// | proprietary key prefix, global map | 82 B | 131,226 B | 0 B |
    /// | proprietary key prefix, input map | 82 B | 131,874 B | 0 B |
    /// | proprietary key prefix, output map | 82 B | 132,154 B | 0 B |
    ///
    /// The four smaller "before" figures are not a smaller problem than the two witness
    /// ones. 131,877 bytes is what the chunked `Vec<u8>` decoder happens to reserve first;
    /// it is the parser's choice of chunk size and not a bound the file paid for, and the
    /// leaf-hash count next to it reaches a megabyte from 114 bytes with nothing but
    /// `MAX_VEC_SIZE` in its way.
    ///
    /// Zero, not "small": every refusal happens before `Psbt::deserialize` is called, so
    /// nothing is allocated and then freed. A `bitcoin` bump that opens a twelfth route
    /// fails here rather than surprising a device that carries a 1 MiB PSBT budget, a
    /// 720x720 framebuffer and an Argon2 arena on one heap.
    #[test]
    fn the_worst_case_peak_stays_under_the_file_size_cap() {
        // <keylen 1> <PSBT_GLOBAL_UNSIGNED_TX> <valuelen> <tx version> <count> ...
        let by_input_count = hex::decode("70736274ff01000902000000feffffffff").unwrap();
        let by_output_count = hex::decode("70736274ff01000a0200000000feffffffff").unwrap();
        // PSBT_IN_FINAL_SCRIPTWITNESS whose five-byte value declares 4,000,000 witness
        // elements. `Witness::consensus_decode` reserves `elements * 4 + 128` before it
        // reads one of them.
        let by_final_witness = with_input_map(concat!("0108", "05", "fe00093d00"));
        // The same count one level deeper: PSBT_IN_NON_WITNESS_UTXO holding a
        // segwit-serialised transaction whose single input's witness declares it.
        let by_nested_witness = with_input_map(concat!(
            "0100", "43", //   the pair, and the transaction's own length
            "02000000", //     version
            "00", "01", //     BIP-144 marker and flag
            "01", //           one input
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "00000000", //     its outpoint
            "00", "ffffffff", // empty script_sig, sequence
            "01", //           one output
            "0000000000000000", "00", // zero value, empty script
            "fe00093d00", //   the witness element count
            "00000000", //     lock time
        ));
        // PSBT_IN_WITNESS_UTXO: an eight-byte amount, then a scriptPubKey length no value
        // of thirteen bytes can pay for.
        let by_witness_utxo = with_input_map(concat!("0101", "0d", "0000000000000000", "fe00093d00"));
        // BIP-371 key origins, in both maps: a leaf-hash count behind an x-only key.
        let by_input_tap_origins = with_input_map(&alloc::format!("2116{XONLY}05fe00093d00"));
        let by_output_tap_origins = with_output_map(&alloc::format!("2107{XONLY}05fe00093d00"));
        // PSBT_OUT_TAP_TREE: one leaf, at depth 0 with leaf version 0xc0, whose script
        // claims four megabytes.
        let by_tap_tree = with_output_map(concat!("0106", "07", "00", "c0", "fe00093d00"));
        // A proprietary key whose own prefix length overruns the key that carries it. The
        // same key data in all three maps, because 0xFC is the same field in all three.
        const PROPRIETARY: &str = concat!("06", "fc", "fe00093d00", "00");

        for (what, hostile) in [
            ("input count", by_input_count),
            ("output count", by_output_count),
            ("final scriptwitness", by_final_witness),
            ("nested witness", by_nested_witness),
            ("witness utxo", by_witness_utxo),
            ("input tap key origins", by_input_tap_origins),
            ("output tap key origins", by_output_tap_origins),
            ("tap tree", by_tap_tree),
            ("global proprietary key", with_global_pair(PROPRIETARY)),
            ("input proprietary key", with_input_map(PROPRIETARY)),
            ("output proprietary key", with_output_map(PROPRIETARY)),
        ] {
            assert!(hostile.len() < 256, "{what}");
            assert!(
                matches!(decode(&hostile), Err(Malformed::LengthPrefixOverrun { .. })),
                "{what} was not refused as an overrun: {:?}",
                decode(&hostile).map(|_| ())
            );
            let peak = meter::peak_bytes(|| decode(&hostile));
            assert_eq!(
                peak, 0,
                "a {} byte file cost {peak} bytes on its {what}",
                hostile.len()
            );
        }
    }

    /// The one test here that does not take a list of routes on trust.
    ///
    /// [`survey`] has to name the grammars it descends into, and a list is exactly the
    /// thing that goes quietly stale: the four routes this file measured before
    /// 2026-08-18 were a list, and six live routes stood behind it. So this sweeps the
    /// space instead of the list - all 256 type bytes, in each of the three maps, against
    /// eleven adversarial key and value shapes drawn from every grammar rust-bitcoin
    /// actually has - and asks only that no 100-odd-byte file cost more than a
    /// 100-odd-byte file. It needs to know nothing about which types exist, which is what
    /// makes it survive a `bitcoin` bump that adds one.
    ///
    /// Every one of the seven routes closed on 2026-08-18 was found by running exactly
    /// this over the code as it stood; the worst it now reports across the whole space is
    /// 2,680 bytes, against 1,001,112 before.
    ///
    /// The bound is 8 KiB rather than zero because most of the space is not a refusal at
    /// all: an unknown type is a pair the parser keeps, and keeping a 114-byte file costs
    /// what a 114-byte file costs.
    #[test]
    fn every_key_type_in_every_map_stays_inside_its_own_bytes() {
        // A 33-byte compressed public key, for the pairs keyed by one.
        const COMPRESSED: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        // An xpub as PSBT_GLOBAL_XPUB carries one, from BIP-174's own test vector.
        const XPUB: &str = concat!(
            "043587cf02da3fd0088000000097048b1ad0445b1ec8275517727c87b4e4ebc18a2",
            "03ffa0f94c01566bd38e9000351b743887ee1d40dc32a6043724f2d6459b3b5a4d7",
            "3daec8fbae0472f3bc43e2",
        );
        // 4,000,000 as a compact size: over rust-bitcoin's `MAX_VEC_SIZE`, and past every
        // chunk and capacity bound inside it.
        const HUGE: &str = "fe00093d00";

        // <what it imitates, key data after the type byte, value>.
        let shapes: [(&str, &str, &str); 11] = [
            ("a bare count or length", "", HUGE),
            ("a TxOut", "", concat!("0000000000000000", "fe00093d00")),
            ("a taproot tree leaf", "", concat!("00", "c0", "fe00093d00")),
            ("a prefix inside the key", HUGE, ""),
            ("a value behind an x-only key", XONLY, HUGE),
            ("a value behind a public key", COMPRESSED, HUGE),
            ("a value behind a key and leaf hash", concat!(
                "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            ), HUGE),
            ("a value behind a control block", concat!(
                "c0", "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            ), HUGE),
            ("a count with bytes behind it", "", concat!(
                "fe00093d00", "0000000000000000000000000000000000000000000000000000000000000000",
            )),
            ("a global xpub", XPUB, "0000000000000000"),
            ("a length nested in a long key", concat!(
                "fd0004", "0000000000000000000000000000000000000000000000000000000000000000",
            ), HUGE),
        ];

        let mut worst = 0;
        for type_value in 0x00..=0xffu8 {
            for (imitates, key_data, value) in shapes {
                let pair = alloc::format!(
                    "{:02x}{type_value:02x}{key_data}{:02x}{value}",
                    1 + key_data.len() / 2,
                    value.len() / 2,
                );
                for (map, hostile) in [
                    ("the global map", with_global_pair(&pair)),
                    ("an input map", with_input_map(&pair)),
                    ("an output map", with_output_map(&pair)),
                ] {
                    let peak = meter::peak_bytes(|| decode(&hostile));
                    worst = worst.max(peak);
                    assert!(
                        peak <= 8 * 1024,
                        "type {type_value:#04x} in {map}, {imitates}: a {} byte file peaked at {peak} bytes",
                        hostile.len(),
                    );
                }
            }
        }
        // Not a bound, a record: it is what the sweep found, and it moving is worth a look
        // even when it stays under the assertion above.
        assert!(worst < 4 * 1024, "the worst peak over the sweep was {worst} bytes");
    }

    /// What a file that pays for every prefix can still cost, which is the number
    /// [`survey`] does NOT promise away.
    ///
    /// A witness element is one byte on the wire at its smallest, and the walk demands
    /// that byte, so this file is honest by every rule this module has. It is also 1 MiB
    /// of PSBT turning into nine megabytes of heap, because `Witness::consensus_decode`
    /// spends four bytes of index space on each element and then doubles its buffer while
    /// filling it. The assertion is a ceiling and a floor at once: if the figure falls a
    /// `bitcoin` bump got cheaper, and if it rises the budget this device was sized
    /// against moved.
    #[test]
    fn the_worst_ratio_a_paid_for_file_can_still_buy() {
        // The global map, the pair frame around the witness (key, value length, element
        // count) and the two separators, so that the file lands exactly on the cap.
        let framing = global_map_prefix().len() + 2 + 5 + 5 + 2;
        let elements = MAX_PSBT_BYTES - framing;

        let mut value = alloc::vec![0xfeu8];
        value.extend_from_slice(&(elements as u32).to_le_bytes());
        // Each element is a one-byte length of zero: the cheapest a witness element gets.
        value.resize(value.len() + elements, 0x00);

        let mut file = global_map_prefix();
        file.extend_from_slice(&[0x01, PSBT_IN_FINAL_SCRIPTWITNESS, 0xfe]);
        file.extend_from_slice(&(value.len() as u32).to_le_bytes());
        file.extend_from_slice(&value);
        file.extend_from_slice(&[0x00, 0x00]);
        assert_eq!(file.len(), MAX_PSBT_BYTES);

        let psbt = decode(&file).expect("every prefix in it is payable");
        assert_eq!(psbt.inputs[0].final_script_witness.as_ref().unwrap().len(), elements);

        let peak = meter::peak_bytes(|| decode(&file));
        assert!(
            (9_000_000..10_000_000).contains(&peak),
            "the worst paid-for ratio moved: {peak} bytes from a {} byte file",
            file.len()
        );
    }

    /// The other half of every route closed above: the walk must still accept the files
    /// those grammars appear in legitimately.
    ///
    /// The corpus covers PSBT_IN_WITNESS_UTXO and BIP-371's key origins with a leaf-hash
    /// count of zero (`every_corpus_vector_round_trips_byte_for_byte`). What it has no
    /// vector for is a NON-ZERO leaf-hash count, a taproot tree, or a proprietary key, and
    /// those are exactly the three the new arithmetic could get wrong: 32 bytes demanded
    /// per leaf hash, a script length per tree leaf, and a prefix length inside a key.
    #[test]
    fn the_grammars_the_walk_learned_still_carry_real_files() {
        // <keylen 33> <0x16> <x-only key> <valuelen 41> <count 1> <leaf hash>
        // <fingerprint> <one child>. Any 32 bytes are a leaf hash, so the key serves.
        let origins =
            with_input_map(&alloc::format!("2116{XONLY}2901{XONLY}d90c6a4f00000080"));
        let psbt = decode(&origins).expect("one taproot leaf hash");
        assert_eq!(psbt.inputs[0].tap_key_origins.len(), 1);
        assert_eq!(encode(&psbt), origins);

        // A one-leaf taproot tree: depth 0, leaf version 0xc0, and OP_1 as the script.
        let tree = with_output_map(concat!("0106", "04", "00", "c0", "0151"));
        let psbt = decode(&tree).expect("a one-leaf taproot tree");
        assert!(psbt.outputs[0].tap_tree.is_some());
        assert_eq!(encode(&psbt), tree);

        // A proprietary pair in each map: a three-byte prefix, subtype 1, no key data.
        const PROPRIETARY: &str = concat!("06", "fc", "03", "6e7961", "01", "00");
        for (what, file) in [
            ("global", with_global_pair(PROPRIETARY)),
            ("input", with_input_map(PROPRIETARY)),
            ("output", with_output_map(PROPRIETARY)),
        ] {
            let psbt = decode(&file).unwrap_or_else(|e| panic!("{what} proprietary pair: {e}"));
            assert_eq!(encode(&psbt), file, "{what} proprietary pair did not round trip");
        }
    }

    /// The two witness routes, named as refusals rather than only as budgets.
    ///
    /// A peak under the cap could also be reached by the parser failing for some unrelated
    /// reason, so this pins WHICH sentence the device gives and that no allocation happens
    /// at all: the count is refused against the bytes behind it, before `Psbt::deserialize`
    /// is called.
    #[test]
    fn a_witness_count_the_file_cannot_pay_for_is_refused_before_the_parse() {
        let final_witness = with_input_map(concat!("0108", "05", "fe00093d00"));
        assert_eq!(
            decode(&final_witness).unwrap_err(),
            Malformed::LengthPrefixOverrun {
                declared: 4_000_000,
                remaining: 0
            }
        );
        let peak = meter::peak_bytes(|| decode(&final_witness));
        assert_eq!(peak, 0, "refusing it cost {peak} bytes");
    }

    /// And the other half of that: the descent must not refuse the witnesses a real file
    /// carries. BIP-174's valid vector 1 supplies a previous transaction in segwit
    /// serialization, with two inputs whose witnesses hold a signature and a public key
    /// each, so the walk crosses a genuine witness section to reach the lock time.
    #[test]
    fn a_real_previous_transactions_witnesses_are_walked_and_kept() {
        let raw = hex::decode(test_corpus::BIP174_UNSIGNED_P2SH).unwrap();
        let psbt = decode(&raw).expect("a segwit-serialised previous transaction");
        let prev = psbt.inputs[0]
            .non_witness_utxo
            .as_ref()
            .expect("the previous transaction");
        assert_eq!(prev.input.len(), 2);
        assert!(prev.input.iter().all(|i| !i.witness.is_empty()));
        assert_eq!(encode(&psbt), raw);
    }

    /// The BIP-174 vector with one oversized unknown pair spliced into its global map. It
    /// is still a PSBT and it still parses, which is the point: the size cap has to be
    /// what refuses it, and until 2026-08-18 nothing did until after the parse returned.
    fn a_psbt_of_exactly(total: usize) -> Vec<u8> {
        let base = hex::decode(test_corpus::BIP174_UNKNOWN_TYPES).unwrap();
        // magic (5), key (2), value length (1), unsigned transaction (0x3f).
        let global_end = 5 + 2 + 1 + 0x3f;
        assert_eq!(base[global_end], 0x00, "the global map separator");

        // <keylen 2> <type 0xf0> <keydata 0x01> <valuelen 0xfe u32>: eight bytes of frame
        // around whatever padding brings the file to `total`.
        let padding = total - base.len() - 8;
        let mut pair = alloc::vec![0x02u8, 0xf0, 0x01, 0xfe];
        pair.extend_from_slice(&(padding as u32).to_le_bytes());
        pair.resize(pair.len() + padding, 0x00);

        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&base[..global_end]);
        out.extend_from_slice(&pair);
        out.extend_from_slice(&base[global_end..]);
        assert_eq!(out.len(), total);
        out
    }

    #[test]
    fn an_oversized_file_is_refused_before_it_is_parsed() {
        let oversized = a_psbt_of_exactly(MAX_PSBT_BYTES + 1);

        let err = decode(&oversized).unwrap_err();
        assert!(err.to_string().contains("too large"), "{err}");
        assert_eq!(
            err,
            Malformed::TooLarge {
                len: MAX_PSBT_BYTES + 1,
                max: MAX_PSBT_BYTES
            }
        );

        // The refusal has to be free of the parse it is refusing, or it is only a second
        // opinion about a file the device already paid for.
        let peak = meter::peak_bytes(|| decode(&oversized));
        assert!(peak < 8 * 1024, "refusing it peaked at {peak} bytes");
    }

    /// The cap is a cap and not a fence some way short of one: the largest accepted file
    /// has to be accepted, or the limit a refusal quotes is not the limit that runs.
    #[test]
    fn a_file_of_exactly_the_cap_is_still_read() {
        let at_the_cap = a_psbt_of_exactly(MAX_PSBT_BYTES);
        let psbt = decode(&at_the_cap).expect("the largest file the device reads");
        assert_eq!(encode(&psbt), at_the_cap);
    }

    /// A file from a coordinator that emits BIP-370. The device cannot sign it, and the
    /// sentence it gives has to be the one that names the setting to change: "damaged"
    /// sends a user back to the card to try the same file again.
    fn a_bip370_version_2_psbt() -> Vec<u8> {
        hex::decode(concat!(
            "70736274ff",
            "010204", "02000000", // PSBT_GLOBAL_TX_VERSION = 2
            "010401", "01",       // PSBT_GLOBAL_INPUT_COUNT = 1
            "010501", "01",       // PSBT_GLOBAL_OUTPUT_COUNT = 1
            "01fb04", "02000000", // PSBT_GLOBAL_VERSION = 2
            "00",
            "010e20", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "010f04", "00000000", // PSBT_IN_OUTPUT_INDEX
            "00",
            "010308", "0000000000000000", // PSBT_OUT_AMOUNT
            "010416", "00140000000000000000000000000000000000000000", // PSBT_OUT_SCRIPT
            "00",
        ))
        .unwrap()
    }

    #[test]
    fn a_version_2_file_says_which_version_it_is() {
        let err = decode(&a_bip370_version_2_psbt()).unwrap_err();
        assert_eq!(
            err.to_string(),
            "PSBT version 2 is not supported, only version 0"
        );
        assert_eq!(err, Malformed::PsbtVersionUnsupported { version: 2 });
    }

    /// The codec's version refusal and check 9's are two variants because they run in two
    /// places, not because they are two answers. A user must never be able to tell which
    /// one they reached.
    #[test]
    fn both_version_refusals_say_the_same_thing() {
        let sentence = Malformed::PsbtVersionUnsupported { version: 2 }.to_string();
        let refusal = CheckFailure::PsbtVersionUnsupported { version: 2 }.to_string();
        assert!(refusal.ends_with(&sentence), "{refusal} does not end with {sentence}");
    }

    /// 0xFB is a version only in the global map. In an input map it is an unknown key type
    /// and BIP-174 says it must be passed through, so reading it as a version there would
    /// turn a file this device can sign into a file it refuses.
    #[test]
    fn a_version_shaped_key_in_an_input_map_is_just_an_unknown_field() {
        const PAIR_F0: &str = "0af00102030405060708090f0102030405060708090a0b0c0d0e0f";
        let version_shaped = "01fb0402000000";
        let raw = hex::decode(
            test_corpus::BIP174_UNKNOWN_TYPES.replace(PAIR_F0, &format!("{version_shaped}{PAIR_F0}")),
        )
        .unwrap();

        let psbt = decode(&raw).expect("an unknown input key, not a version");
        assert_eq!(psbt.version, 0);
        assert_eq!(psbt.inputs[0].unknown.len(), 2);
    }

    /// The BIP-174 unknown-types vector with a second unknown input pair spliced in ahead
    /// of the first, so the file's pair order runs where rust-bitcoin's emission order
    /// does not. Nothing about it violates BIP-174, which fixes no order on the pairs.
    fn unknown_types_with_pairs_out_of_order() -> Vec<u8> {
        const PAIR_F0: &str = "0af00102030405060708090f0102030405060708090a0b0c0d0e0f";
        let pair_f1 = PAIR_F0.replacen("0af0", "0af1", 1);
        let reordered =
            test_corpus::BIP174_UNKNOWN_TYPES.replace(PAIR_F0, &format!("{pair_f1}{PAIR_F0}"));
        assert_ne!(
            reordered,
            test_corpus::BIP174_UNKNOWN_TYPES,
            "the splice found nothing"
        );
        hex::decode(reordered).unwrap()
    }

    /// The contract [`encode`] used to claim, stated as what it actually is.
    ///
    /// BIP-174's obligation is pass-through of the pairs and it holds; byte-for-byte
    /// identity with the coordinator's file was never true and is not owed. This test is
    /// the difference, so that the doc cannot drift back.
    #[test]
    fn an_out_of_order_file_survives_as_pairs_and_not_as_bytes() {
        let raw = unknown_types_with_pairs_out_of_order();
        let psbt = decode(&raw).unwrap();

        let out = encode(&psbt);
        assert_ne!(out, raw, "the coordinator's byte order is not reproduced");
        assert_eq!(out.len(), raw.len(), "and nothing was added or dropped");

        // Both pairs are there, with their values, which is the whole of what is owed.
        let unknown = &psbt.inputs[0].unknown;
        assert_eq!(unknown.len(), 2);
        let value = hex::decode("0102030405060708090a0b0c0d0e0f").unwrap();
        for type_value in [0xf0u8, 0xf1] {
            let key = bitcoin::psbt::raw::Key {
                type_value,
                key: hex::decode("010203040506070809").unwrap(),
            };
            assert_eq!(unknown.get(&key), Some(&value), "type {type_value:#x}");
        }

        // And the file that came out is the one the identities are taken over.
        assert_eq!(decode(&out).map(|p| encode(&p)).unwrap(), out);
    }

    /// The property [`psbt_id`] actually needs, and the reason losing the stronger one
    /// costs nothing: this device's serialization is a fixed point of this device's
    /// serializer.
    #[test]
    fn encode_is_idempotent_over_the_corpus() {
        for (name, hex_bytes) in test_corpus::VECTORS {
            let once = encode(&decode(&hex::decode(hex_bytes).expect(name)).expect(name));
            let twice = encode(&decode(&once).expect(name));
            assert_eq!(once, twice, "{name} is not a fixed point");
            assert_eq!(
                psbt_id(&decode(&once).expect(name)),
                psbt_id(&decode(&twice).expect(name)),
                "{name} identity moved"
            );
        }
    }
}
