// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The signed transaction as a QR payload: what goes on the glass, and what will not fit.
//!
//! One function ([`frame`]) and one rule ([`fits`]). The function turns the bytes a
//! signature produced into the exact string a camera is meant to read; the rule says, from
//! a length alone, whether the device may offer that at all - so a screen can decide
//! whether to draw the button before anything has been encoded.
//!
//! # Why base64 text, and not the raw bytes
//!
//! A QR symbol can carry the PSBT's raw bytes in about 25% fewer modules, and exactly one
//! of the wallets this device is meant to reach accepts that (Sparrow, via
//! `new PSBT(rawBytes)`). Every one of them accepts the BASE64 text: BlueWallet hands an
//! unrecognised scan to `Psbt.fromBase64`, Sparrow to `PSBT.fromString`, and Electrum's
//! camera path (`transaction.py::convert_raw_tx_to_hex`) tries base64 the moment the scan
//! starts `cHNidP`. Electrum reads NO animated format at all, so base64 text in one static
//! symbol is the only encoding that reaches all three from a camera. The 25% is spent
//! deliberately.
//!
//! What is on the glass is therefore what a scanner reads and nothing else: the same
//! no-transformation policy [`crate::qr`] states for its own payloads.
//!
//! # Why there is a size limit at all, and why it is not the encoder's
//!
//! [`crate::qr`] refuses at 2331 bytes, the byte-mode capacity of a version 40 symbol at
//! level M. That limit is about the FORMAT. This module's is about the PANEL: a version 40
//! symbol drawn on the shortest display this firmware ships (480 px tall) leaves 2 pixels
//! per module, which is a symbol that exists and cannot be scanned. [`MAX_PSBT_BYTES`] is
//! the largest transaction that still lands at three pixels per module on every shipped
//! panel, and `notyas-ui`'s player asserts that against the real layout - see
//! [`MAX_SYMBOL_MODULES`].
//!
//! A transaction over the limit is not a failure of this module and is not shown as one:
//! the card is the delivery path for it, S-38 keeps that exit at all times, and the QR
//! button is drawn disabled with the reason rather than drawn as a control that does
//! nothing.
//!
//! # What this module is not
//!
//! It is not an animated encoder. `ur:crypto-psbt` in multi-part frames is what a
//! transaction too large for one symbol would need, and nothing in this workspace produces
//! one; the limit here is the honest edge of what does exist, which is why it is a public
//! constant a screen can ask about rather than an error a user discovers by tapping.

use alloc::string::String;
use core::fmt;

use crate::message::base64_encode;
use crate::psbt::PSBT_MAGIC;

/// The largest signed transaction this device will put on the glass, in bytes.
///
/// Set by the SHORTEST panel the firmware ships, not by the QR format. 1089 bytes encode
/// to 1452 base64 characters, which is the most a version 31 symbol holds in byte mode at
/// level M - 141 modules, 149 with the four-module quiet zone a scanner needs - and 149
/// modules is what a 480-pixel-tall display can still draw at three pixels each. Three is
/// the floor this device is prepared to call scannable: a modern phone resolves it at
/// 10-20 cm, and level M's error correction is what makes that margin survivable, which is
/// also why the level is not dropped to L to buy a smaller symbol.
///
/// The value is therefore the version's capacity and not a round number: rounding down
/// would refuse transactions the panel can already show at the same symbol size.
///
/// For scale: a single-input P2WPKH spend signs to about 509 bytes and a 2-of-3 P2WSH
/// multisig leg to about 917, so the realistic corpus fits with room to spare. What does
/// not fit is a transaction with several inputs funded by large previous transactions -
/// `non_witness_utxo` is required by check 2 and it carries the whole funding transaction
/// - and that is exactly the case the card exists for.
pub const MAX_PSBT_BYTES: usize = 1089;

/// The base64 length of [`MAX_PSBT_BYTES`]. Stated rather than derived at the call site so
/// the QR capacity this limit was chosen against is readable here; the test below pins the
/// two together.
pub const MAX_BASE64_CHARS: usize = 1452;

/// Modules per side of the largest symbol [`frame`] can return: version 31, the smallest
/// version whose byte-mode capacity at level M holds [`MAX_BASE64_CHARS`].
///
/// The quiet zone is NOT included, because [`crate::qr::matrix`] does not include one - the
/// light margin belongs to the drawing. A caller sizing a panel adds eight (four each
/// side), which is what the layout test in `notyas-ui` does.
pub const MAX_SYMBOL_MODULES: u16 = 141;

/// Why a signed transaction is not going on the glass.
///
/// Two variants because they are two different sentences to a user: one says the device
/// was handed something that is not a transaction, which is a bug on this side of the
/// panel, and the other says the transaction is real and too big, which is a fact about
/// their spend and has a remedy (the card).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// The bytes are not a BIP-174 file. Encoding them anyway would draw a symbol every
    /// wallet rejects with no explanation - `cHNidP` is the prefix each of them looks for.
    NotPsbt,
    /// Real, and larger than one scannable symbol. Carries the size so the screen can
    /// state both numbers instead of an unexplained refusal.
    TooLarge { bytes: usize },
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refused::NotPsbt => f.write_str("these bytes are not a PSBT"),
            Refused::TooLarge { bytes } => write!(
                f,
                "{bytes} bytes is too large to show as a QR code: the limit is {MAX_PSBT_BYTES}"
            ),
        }
    }
}

impl core::error::Error for Refused {}

/// Whether a signed transaction of `bytes` bytes can be shown as a QR symbol.
///
/// The one rule, exported so that the decision a screen makes before drawing the button is
/// the same decision [`frame`] makes when the button is pressed. A screen that hard-coded
/// its own threshold would eventually draw a control this module refuses.
pub const fn fits(bytes: usize) -> bool {
    bytes <= MAX_PSBT_BYTES
}

/// The exact string to encode into a QR symbol for `psbt`: standard base64, the form every
/// target wallet decodes from a camera.
///
/// # Errors
///
/// [`Refused::NotPsbt`] for bytes that are not a BIP-174 file, [`Refused::TooLarge`] for a
/// transaction over [`MAX_PSBT_BYTES`].
pub fn frame(psbt: &[u8]) -> Result<String, Refused> {
    if psbt.len() < PSBT_MAGIC.len() || psbt[..PSBT_MAGIC.len()] != PSBT_MAGIC {
        return Err(Refused::NotPsbt);
    }
    if !fits(psbt.len()) {
        return Err(Refused::TooLarge { bytes: psbt.len() });
    }
    Ok(base64_encode(psbt))
}

// ---------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    /// Standard base64, decoded. Independent of the encoder by construction: it is written
    /// from the alphabet in the other direction, so a transposed table or a mis-shifted
    /// group cannot pass both halves.
    fn base64_decode(text: &str) -> Option<Vec<u8>> {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let bytes = text.as_bytes();
        if bytes.len() % 4 != 0 {
            return None;
        }
        let mut out = Vec::new();
        for quad in bytes.chunks(4) {
            let mut group = 0u32;
            let mut got = 0usize;
            for (i, &c) in quad.iter().enumerate() {
                if c == b'=' {
                    // Padding is only legal in the last two positions of a quad.
                    if i < 2 {
                        return None;
                    }
                    continue;
                }
                let v = ALPHABET.iter().position(|&a| a == c)? as u32;
                group |= v << (18 - 6 * i);
                got += 1;
            }
            for i in 0..got.saturating_sub(1) {
                out.push((group >> (16 - 8 * i)) as u8);
            }
        }
        Some(out)
    }

    /// A byte string that starts like a PSBT, for the size rules. Not a real file: the
    /// rules under test are about LENGTH, and the real one is signed below.
    fn psbt_shaped(len: usize) -> Vec<u8> {
        let mut out = vec![0x41u8; len];
        out[..PSBT_MAGIC.len()].copy_from_slice(&PSBT_MAGIC);
        out
    }

    /// The decoder above is the check on the encoder, so it is itself checked against
    /// RFC 4648's vectors first. A round trip against a broken decoder proves nothing.
    #[test]
    fn the_test_decoder_reads_the_rfc_4648_vectors() {
        for (text, bytes) in [
            ("", &b""[..]),
            ("Zg==", b"f"),
            ("Zm8=", b"fo"),
            ("Zm9v", b"foo"),
            ("Zm9vYg==", b"foob"),
            ("Zm9vYmE=", b"fooba"),
            ("Zm9vYmFy", b"foobar"),
        ] {
            assert_eq!(base64_decode(text).as_deref(), Some(bytes), "{text}");
        }
        assert!(base64_decode("Zm9vYmFy=").is_none(), "a length that is not a multiple of 4");
        assert!(base64_decode("Zm9.YmFy").is_none(), "a character outside the alphabet");
    }

    /// The payload is the PSBT and nothing else, and it announces itself as one: every
    /// target wallet's camera path keys on the `cHNidP` prefix that a BIP-174 magic
    /// produces, and the bytes come back byte for byte.
    ///
    /// Broken version: encode `&psbt[1..]`, or transform the payload in any way. The
    /// prefix assertion trips, and so does the round trip.
    #[test]
    fn a_frame_is_the_psbt_itself_and_says_so() {
        let psbt = psbt_shaped(509);
        let text = frame(&psbt).unwrap();
        assert!(text.starts_with("cHNidP"), "{}", &text[..8.min(text.len())]);
        assert_eq!(base64_decode(&text).unwrap(), psbt, "the scan is not the file");
        assert_eq!(text.len(), 4 * psbt.len().div_ceil(3), "base64 length");
    }

    /// The limit is a limit on BOTH sides, and it is the one `fits` states.
    ///
    /// Broken version: change either constant on its own, or make `frame` refuse at a
    /// different length than `fits` reports. The assertions below cannot all hold.
    #[test]
    fn the_limit_is_the_same_one_the_screen_asks_about() {
        assert!(fits(MAX_PSBT_BYTES));
        assert!(!fits(MAX_PSBT_BYTES + 1));
        let at = frame(&psbt_shaped(MAX_PSBT_BYTES)).expect("the limit itself is allowed");
        assert_eq!(at.len(), MAX_BASE64_CHARS, "the stated base64 length");
        assert_eq!(
            frame(&psbt_shaped(MAX_PSBT_BYTES + 1)),
            Err(Refused::TooLarge { bytes: MAX_PSBT_BYTES + 1 }),
            "one byte over is refused, with the size in the refusal"
        );
    }

    /// Bytes that are not a BIP-174 file are refused rather than drawn. A symbol nobody
    /// can decode is worse than no symbol: it fails in the user's hand, silently, after
    /// they have aimed a camera at it.
    #[test]
    fn only_a_psbt_is_offered_as_one() {
        assert_eq!(frame(b"not a psbt at all"), Err(Refused::NotPsbt));
        assert_eq!(frame(b""), Err(Refused::NotPsbt));
        assert_eq!(frame(&PSBT_MAGIC[..4]), Err(Refused::NotPsbt), "a truncated magic");
        // The shape rule is reached before the size rule: a huge non-PSBT is still "not a
        // PSBT", which is the true sentence.
        assert_eq!(frame(&vec![0u8; MAX_PSBT_BYTES + 1]), Err(Refused::NotPsbt));
    }

    /// The refusals say what happened, in ASCII, with the numbers in them.
    #[test]
    fn the_refusals_state_the_fact() {
        let text = alloc::format!("{}", Refused::TooLarge { bytes: 4096 });
        assert!(text.contains("4096") && text.contains("1089"), "{text}");
        assert!(text.is_ascii() && !text.contains('\u{2014}'));
        assert!(alloc::format!("{}", Refused::NotPsbt).is_ascii());
    }

    /// The end to end claim, against a transaction this crate really signed: the string
    /// the device would show decodes to the exact bytes the card would receive, and those
    /// bytes parse as a PSBT by the same decoder the engine uses on the way in.
    ///
    /// This is the round trip that matters. `base64_decode` above proves the alphabet;
    /// `psbt::decode` proves the payload is a transaction and not a plausible-looking
    /// string, which is the failure a length assertion cannot see.
    ///
    /// Broken version: drop the trailing byte before encoding. The length assertion
    /// survives (it is computed from the same slice) but `decode` refuses the result.
    #[test]
    fn a_really_signed_transaction_round_trips() {
        use crate::psbt::{decode, encode, fixture, inspect, sign};

        let psbt = fixture::p2wpkh_psbt();
        let inspection = inspect(&psbt, &fixture::context()).unwrap();
        let signed = sign(&psbt, &inspection, &fixture::SEED).unwrap();
        let bytes = encode(signed.psbt());

        let text = frame(&bytes).expect("a signed single-input spend fits one symbol");
        let back = base64_decode(&text).expect("the frame is standard base64");
        assert_eq!(back, bytes, "the scan is not the signed file");
        let reparsed = decode(&back).expect("what a wallet decodes is a PSBT");
        assert_eq!(encode(&reparsed), bytes, "and it is the same transaction");
        assert!(fits(bytes.len()), "{} bytes", bytes.len());
    }

    /// The panel's side of the limit: the largest allowed payload lands in the version
    /// [`MAX_SYMBOL_MODULES`] names, and the next grouping up would need a larger one.
    ///
    /// This is the constant `notyas-ui`'s layout test measures its pixels-per-module
    /// against, so it is pinned here where the encoder that produces it lives.
    ///
    /// Broken version: raise `MAX_PSBT_BYTES` by one grouping. The symbol grows past 141
    /// modules and the first assertion trips before any panel ever draws it.
    #[cfg(feature = "qr")]
    #[test]
    fn the_largest_allowed_payload_is_the_symbol_the_panels_were_sized_for() {
        let at = frame(&psbt_shaped(MAX_PSBT_BYTES)).unwrap();
        let symbol = crate::qr::matrix(&at).expect("inside the format's own capacity");
        assert_eq!(symbol.len(), MAX_SYMBOL_MODULES as usize, "version 31, 4v + 17 modules");
        // ...and it is the LARGEST payload that version holds: the next byte of
        // transaction is another base64 group, and that needs a bigger symbol than any
        // panel was sized against.
        let over = base64_encode(&psbt_shaped(MAX_PSBT_BYTES + 1));
        assert!(over.len() > MAX_BASE64_CHARS, "one byte more is another base64 group");
        assert!(
            crate::qr::matrix(&over).unwrap().len() > MAX_SYMBOL_MODULES as usize,
            "the limit is not at the version's edge"
        );
    }

    /// Every realistic signed transaction fits, and the sizes are the measured ones. A
    /// regression here means the button silently stopped being offered for a shape of
    /// spend that used to have it.
    #[cfg(feature = "qr")]
    #[test]
    fn the_measured_transaction_shapes_land_in_the_expected_symbols() {
        // (bytes, modules per side): a 1-in-1-out and a 1-in-2-out P2WPKH spend, a
        // 2-in-2-out, and a 2-of-3 P2WSH leg, as measured off this workspace's own signer.
        for (bytes, modules) in [(417usize, 89usize), (509, 101), (875, 129), (917, 133)] {
            let text = frame(&psbt_shaped(bytes)).expect("a realistic spend fits");
            assert_eq!(crate::qr::matrix(&text).unwrap().len(), modules, "{bytes} bytes");
        }
    }
}

