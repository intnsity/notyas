// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Every parser that eats bytes a stranger chose, driven with bytes a stranger chose.
//!
//! `notyas-core` has no `deny(clippy::unwrap_used / panic / indexing_slicing)` the way
//! `notyas-wallet` does, so "this decoder cannot panic" is not enforced by the build. This
//! file enforces it by exercise instead: a deterministic mutation walk (no RNG crate -
//! SECURITY invariant 3 - just a counter-driven LCG) over the published corpora, plus the
//! shapes a hand-written attack takes: truncation at every byte, a single flipped bit at
//! every position, and lengths that claim more than the file holds.

use notyas_core::{address, bip39, multisig, psbt, seedqr};
use bitcoin::Network;

/// A counter-driven LCG. Reproducible by construction: the seed is the case number, so a
/// failure names the exact input without a corpus file.
struct Lcg(u64);

impl Lcg {
    fn next_u32(&mut self) -> u32 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (self.0 >> 33) as u32
    }
    fn byte(&mut self) -> u8 {
        self.next_u32() as u8
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            self.next_u32() as usize % n
        }
    }
}

/// BIP-174's own P2WSH-multisig test vector, verbatim. A published file rather than a
/// fixture: a mutation walk is only as good as the valid file it starts from.
const BIP174_P2WSH_MULTISIG: &str = "70736274ff0100550200000001279a2323a5dfb51fc45f220fa58b0fc13e1e3342792a85d7e36cd6333b5cbc390000000000ffffffff01a05aea0b000000001976a914ffe9c0061097cc3b636f2cb0460fa4fc427d2b4588ac0000000000010120955eea0b0000000017a9146345200f68d189e1adc0df1c4d16ea8f14c0dbeb87220203b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4646304302200424b58effaaa694e1559ea5c93bbfd4a89064224055cdf070b6771469442d07021f5c8eb0fea6516d60b8acb33ad64ede60e8785bfb3aa94b99bdf86151db9a9a010104220020771fd18ad459666dd49f3d564e3dbc42f4c84774e360ada16816a8ed488d5681010547522103b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd462103de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd52ae220603b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4610b4a6ba67000000800000008004000080220603de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd10b4a6ba670000008000000080050000800000";

fn base_psbt() -> Vec<u8> {
    let raw = hex_decode(BIP174_P2WSH_MULTISIG);
    assert!(psbt::decode(&raw).is_ok(), "the published vector must parse");
    raw
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn psbt_decode_survives_truncation_at_every_length() {
    let raw = base_psbt();
    for n in 0..=raw.len() {
        // The contract is a verdict, not a process exit. Either is fine; a panic is not.
        let _ = psbt::decode(&raw[..n]);
    }
}

#[test]
fn psbt_decode_survives_a_flipped_bit_at_every_position() {
    let raw = base_psbt();
    for i in 0..raw.len() {
        for bit in 0..8u8 {
            let mut m = raw.clone();
            m[i] ^= 1 << bit;
            let _ = psbt::decode(&m);
        }
    }
}

#[test]
fn psbt_decode_survives_a_mutation_walk() {
    let raw = base_psbt();
    for case in 0..20_000u64 {
        let mut r = Lcg(case);
        let mut m = raw.clone();
        for _ in 0..1 + r.below(6) {
            if m.is_empty() {
                m.push(r.byte());
            }
            match r.below(4) {
                0 => {
                    let at = r.below(m.len());
                    m[at] = r.byte();
                }
                1 => {
                    // Splice a compact-size prefix that claims far more than remains: the
                    // shape that turns a length field into an allocation request.
                    let at = r.below(m.len());
                    let claim = [0xfe, 0xff, 0xff, 0xff, 0x7f];
                    for (k, b) in claim.iter().enumerate() {
                        if at + k < m.len() {
                            m[at + k] = *b;
                        }
                    }
                }
                2 => {
                    let at = r.below(m.len());
                    m.truncate(at);
                }
                _ => {
                    let at = r.below(m.len().max(1));
                    m.insert(at.min(m.len()), r.byte());
                }
            }
        }
        let _ = psbt::decode(&m);
    }
}

#[test]
fn multisig_parse_survives_a_mutation_walk_over_a_published_descriptor() {
    // BIP-129 test vector 1, the descriptor this crate already parses.
    const BSMS: &str = "wsh(sortedmulti(2,[1cf0bf7e/48'/0'/0'/2']xpub6FL8FhxNNUVnG64YurPd16Af\
GyvFLhh7S2uSsDqR3Qfcm6o9jtcMYwh6DvmcBF9qozxNQmTCVvWtxLpKTnhVLN3Pgnu2D3pAoXYFgVyd8Yz/**,[4fc1\
dd4a/48'/0'/0'/2']xpub6EebMbEps7ZcV3FYEnddRsvrFWDrt2tiPmCeM7pPXQEmphvq9ZfJ1LWFUDjf3vxCeBuPrf\
yGrMazWUsYsetrnHatQZVLJH7LsgCjtMqdzgj/**))";
    assert!(multisig::parse(BSMS).is_ok(), "the published descriptor must parse");

    for n in 0..=BSMS.len() {
        let _ = multisig::parse(&BSMS[..n]);
    }
    let bytes = BSMS.as_bytes();
    for case in 0..20_000u64 {
        let mut r = Lcg(case);
        let mut m = bytes.to_vec();
        for _ in 0..1 + r.below(5) {
            let at = r.below(m.len());
            // Printable ASCII only: a descriptor arrives as text, and a non-UTF-8 body
            // never reaches the parser at all.
            m[at] = 0x20 + (r.byte() % 95);
        }
        if let Ok(s) = core::str::from_utf8(&m) {
            let _ = multisig::parse(s);
        }
    }
}

#[test]
fn address_parse_survives_arbitrary_text() {
    const ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1:";
    for case in 0..50_000u64 {
        let mut r = Lcg(case);
        let len = r.below(96);
        let mut s = String::with_capacity(len + 4);
        // Half the cases carry a real human-readable part, so the bech32 body is reached
        // rather than refused at the prefix.
        if case % 2 == 0 {
            s.push_str(if case % 4 == 0 { "bc1" } else { "tb1" });
        }
        for _ in 0..len {
            s.push(ALPHABET[r.below(ALPHABET.len())] as char);
        }
        for net in [Network::Bitcoin, Network::Testnet] {
            let _ = address::parse(&s, net);
        }
    }
}

#[test]
fn seedqr_decode_survives_arbitrary_digits_and_text() {
    for case in 0..50_000u64 {
        let mut r = Lcg(case);
        let len = r.below(300);
        let mut s = String::with_capacity(len);
        for _ in 0..len {
            // Digits dominate: compact SeedQR is a digit string, and a decoder that
            // indexes the wordlist by a parsed number is what this is looking for.
            s.push(match r.below(8) {
                0 => (0x20 + (r.byte() % 95)) as char,
                _ => (b'0' + (r.byte() % 10)) as char,
            });
        }
        let _ = seedqr::decode(s.as_bytes());
    }
}

#[test]
fn the_phrase_checker_survives_arbitrary_text() {
    for case in 0..30_000u64 {
        let mut r = Lcg(case);
        let len = r.below(200);
        let mut s = String::with_capacity(len);
        for _ in 0..len {
            s.push(match r.below(4) {
                0 => ' ',
                _ => (b'a' + (r.byte() % 26)) as char,
            });
        }
        let _ = bip39::check_phrase(&s);
        let _ = bip39::normalize_phrase(&s);
    }
}
