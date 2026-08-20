// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Animated QR out: UR2 as the primary transport, BBQr for the Coldcard family.
//!
//! # The question this module answers
//!
//! *What string does frame N of this animation contain?*
//!
//! That is the whole encoding interface. A caller builds an [`Animation`] once over the
//! bytes it wants off the device, and from then on every tick of the player is one call to
//! [`Animation::frame`] and one call to `notyas_core::qr` on the result. Nothing here draws,
//! measures, times or repaints anything, and nothing here reads a camera.
//!
//! [`Playback`] answers the second question a screen has - *which N* - by holding the
//! cursor, the speed step and the density step that screen 11's controls move. The
//! firmware's tick handler drives a [`Playback`], and the [`Playback`] drives the
//! [`Animation`]; neither of them holds a clock.
//!
//! # Why frame N rather than "next frame"
//!
//! [`Animation::frame`] is a pure function of its argument. It takes `&self`, advances no
//! cursor and can be called in any order, so the player owns the entire notion of time: it
//! may hold one frame while the user lines up a phone, step backwards, restart, or stop
//! dead. That matters beyond taste, because the claim m8 must not break is that an idle
//! device performs zero repaints outside an active animation - and an encoder that only
//! knows how to hand out the *next* frame quietly makes the encoder the thing that decides
//! when a frame happens.
//!
//! The two transports differ in what lies past the last part, and the difference is
//! [`Animation::is_fountain`]:
//!
//! - **UR2** parts past the count are exclusive-or mixtures of the fragments, not repeats.
//!   A reader that missed one recovers it from a later frame, so the animation is worth
//!   looping and no single frame is mandatory.
//! - **BBQr** has no such thing. The series is the payload cut into pieces, a reader needs
//!   every piece, and frame `part_count` is part zero coming round again.
//!
//! # Scope
//!
//! Encoding only. Decoding is m11's, with the camera; the readers under `cfg(test)` in the
//! submodules exist to prove these encoders round-trip and compile into no shipped build.
//! There is no PSBT semantics here either - whether the bytes are a PSBT worth signing was
//! settled long before they reached a QR code.
//!
//! # Placement
//!
//! MILESTONES.md section 6 (R6) puts UR and transport encoding in this crate rather than in
//! `notyas-core`, because the reference `foundation-urtypes` is GPL-3.0-or-later and the
//! permissively licensed crates must be able to stay clear of it. The rule holds under this
//! implementation for a second reason: `foundation-ur` reaches xoshiro256\*\* through
//! `rand_xoshiro`, which depends on `rand_core`, which SECURITY.md invariant 3 bans
//! graph-wide and `tools/build-graph-check.sh` enforces with no exemption for exactly the
//! four crates that link into the device image. The dependency ledger admitted a crate the
//! security gate rejects; the arithmetic it wraps is in `fountain.rs`, pinned against that
//! crate's own published vectors.

use alloc::string::String;

mod bbqr;
mod bytewords;
pub(crate) mod checksum;
mod fountain;
mod playback;
mod ur;

pub use playback::{Playback, Speed, DENSITY_STEPS, SPEED_STEPS};

/// Payload bytes per frame unless the caller says otherwise (MILESTONES.md 0.2.0-m8).
///
/// A frame, not a fragment: what reaches the symbol is roughly twice this in characters for
/// UR2 and 1.6 times for BBQr, plus a header. 200 bytes is a mid-sized QR symbol that a
/// phone camera reads across a desk, which is the constraint that actually binds.
pub const DEFAULT_MAX_FRAGMENT: usize = 200;

/// The most parts either transport will produce.
///
/// BBQr's own limit: the header names the part in two digits of base 36, so 1295 is the
/// last one that can be written. UR2 has no such ceiling, and takes this one anyway - a
/// 1295-part animation at the 250 ms frame rate the Coldcard Q documentation recommends is
/// already five minutes for a single pass, so a density step that produced more of them
/// would be offering the user something they will never sit through. Refusing is the honest
/// answer, and it also bounds the per-frame work of the fountain's fragment chooser.
pub const MAX_PARTS: u32 = 1295;

/// What an animation is carrying.
///
/// The variants exist because the two transports each name the content, and the names are
/// how a coordinator knows what it just scanned. Nothing here inspects the bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Payload<'a> {
    /// A BIP-174 partially signed transaction: `ur:crypto-psbt`, BBQr type `P`.
    Psbt(&'a [u8]),
    /// A finalized transaction ready for the network: `ur:bytes`, BBQr type `T`. This is
    /// the honest equivalent of a phone-tap broadcast - the phone reads it off the glass.
    Transaction(&'a [u8]),
    /// UTF-8 text, such as the Verify readout: `ur:bytes`, BBQr type `U`.
    Text(&'a str),
}

impl core::fmt::Debug for Payload<'_> {
    /// Kind and length. These payloads are public by policy, but a wall of PSBT in a log
    /// line helps nobody; the house style is "identity, not contents".
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let (kind, len) = match self {
            Payload::Psbt(bytes) => ("Psbt", bytes.len()),
            Payload::Transaction(bytes) => ("Transaction", bytes.len()),
            Payload::Text(text) => ("Text", text.len()),
        };
        f.debug_struct(kind).field("len", &len).finish()
    }
}

impl<'a> Payload<'a> {
    fn bytes(&self) -> &'a [u8] {
        match *self {
            Payload::Psbt(bytes) | Payload::Transaction(bytes) => bytes,
            Payload::Text(text) => text.as_bytes(),
        }
    }

    /// The UR type name. `crypto-psbt` is the legacy registry name and is deliberate: it is
    /// what Sparrow, Nunchuk and the rest read, and several read nothing else.
    fn ur_type(&self) -> &'static str {
        match self {
            Payload::Psbt(_) => "crypto-psbt",
            Payload::Transaction(_) | Payload::Text(_) => "bytes",
        }
    }

    /// The BBQr file-type character.
    fn bbqr_type(&self) -> char {
        match self {
            Payload::Psbt(_) => 'P',
            Payload::Transaction(_) => 'T',
            Payload::Text(_) => 'U',
        }
    }
}

/// Which format the frames are written in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Transport {
    /// UR2. The primary transport: fountain-coded, so no frame is mandatory.
    Ur,
    /// BBQr. Offered for the Coldcard family and everything that follows it.
    Bbqr,
}

/// Why an animation could not be prepared.
///
/// Every one of these is a property of the request rather than of the payload's contents,
/// and all three are decided before a single frame is produced - so a player that got an
/// [`Animation`] at all can go on drawing frames forever without another failure path.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TransportError {
    /// Nothing to send.
    EmptyPayload,
    /// The requested frame size is below the smallest this transport can produce.
    FragmentTooSmall {
        /// The smallest `max_fragment` that would have worked.
        minimum: usize,
    },
    /// The payload needs more parts than the format can number. Raise `max_fragment` - a
    /// denser symbol - or send the payload another way.
    TooManyParts {
        /// The most parts the format will name; see [`MAX_PARTS`].
        limit: u32,
    },
}

/// A prepared animation: everything needed to produce any frame, in any order, forever.
pub struct Animation {
    inner: Inner,
}

enum Inner {
    Ur(ur::Encoder),
    Bbqr(bbqr::Encoder),
}

impl core::fmt::Debug for Animation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Animation")
            .field("transport", &self.transport())
            .field("parts", &self.part_count())
            .field("fountain", &self.is_fountain())
            .finish()
    }
}

impl Animation {
    /// Prepare `payload` for display over `transport`, with no frame carrying more than
    /// `max_fragment` bytes of it.
    ///
    /// `max_fragment` is the density knob the player's density steps move.
    /// [`DEFAULT_MAX_FRAGMENT`] is the middle of that range. It bounds payload bytes rather
    /// than characters, so the same setting means the same amount of progress per frame
    /// whichever transport is selected, even though the resulting symbols differ in size.
    ///
    /// # Errors
    ///
    /// See [`TransportError`]. All three are decided here, once.
    pub fn new(
        payload: Payload<'_>,
        transport: Transport,
        max_fragment: usize,
    ) -> Result<Animation, TransportError> {
        let inner = match transport {
            Transport::Ur => Inner::Ur(ur::Encoder::new(
                payload.ur_type(),
                payload.bytes(),
                max_fragment,
            )?),
            Transport::Bbqr => Inner::Bbqr(bbqr::Encoder::new(
                payload.bbqr_type(),
                payload.bytes(),
                max_fragment,
            )?),
        };
        Ok(Animation { inner })
    }

    /// Which format the frames are written in.
    pub fn transport(&self) -> Transport {
        match self.inner {
            Inner::Ur(_) => Transport::Ur,
            Inner::Bbqr(_) => Transport::Bbqr,
        }
    }

    /// How many distinct parts carry the payload. One means the payload fits a single
    /// symbol and the "animation" is a still.
    pub fn part_count(&self) -> u32 {
        match &self.inner {
            Inner::Ur(encoder) => encoder.part_count(),
            Inner::Bbqr(encoder) => encoder.part_count(),
        }
    }

    /// Whether frames past [`part_count`](Self::part_count) carry new information.
    ///
    /// True for a multi-part UR2, where they are fountain mixtures that let a reader
    /// recover a fragment it missed. False for BBQr and for any single-part animation,
    /// where looping only repeats what has already been shown. A player can use it to
    /// decide whether stopping after one pass is safe.
    pub fn is_fountain(&self) -> bool {
        matches!(&self.inner, Inner::Ur(_)) && self.part_count() > 1
    }

    /// The complete string for frame `n`, counting from zero.
    ///
    /// Total: every `n` yields a frame, and every frame is independently decodable - a
    /// reader that sees only this one string knows the series it belongs to, how long the
    /// payload is and where this part fits. There is no failure path, which is what lets
    /// the player's tick handler be a straight line.
    pub fn frame(&self, n: u32) -> String {
        match &self.inner {
            Inner::Ur(encoder) => encoder.frame(n),
            Inner::Bbqr(encoder) => encoder.frame(n),
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
mod tests {
    use super::*;
    use crate::transport::fountain::tests::make_message;
    use alloc::vec::Vec;

    /// A PSBT-shaped payload. Only its first five bytes are PSBT at all: this module has no
    /// opinion about the rest and the test exists to say so.
    fn psbt_shaped(len: usize) -> Vec<u8> {
        let mut bytes = alloc::vec![0x70, 0x73, 0x62, 0x74, 0xff];
        bytes.extend_from_slice(&make_message("notyas-psbt", len.saturating_sub(5)));
        bytes
    }

    /// The type names each payload kind carries in each transport. These are the strings a
    /// coordinator matches on, so they are pinned here rather than left to the submodules.
    #[test]
    fn payload_kinds_carry_their_names() {
        let psbt = psbt_shaped(64);
        let cases: [(Payload<'_>, &str, &str); 3] = [
            (Payload::Psbt(&psbt), "ur:crypto-psbt/", "B$2P"),
            (Payload::Transaction(&psbt), "ur:bytes/", "B$2T"),
            (Payload::Text("notyas-verify/1 ..."), "ur:bytes/", "B$2U"),
        ];
        for (payload, ur_prefix, bbqr_prefix) in cases {
            let ur = Animation::new(payload, Transport::Ur, DEFAULT_MAX_FRAGMENT).unwrap();
            assert!(ur.frame(0).starts_with(ur_prefix), "{payload:?}");
            let bbqr = Animation::new(payload, Transport::Bbqr, DEFAULT_MAX_FRAGMENT).unwrap();
            assert!(bbqr.frame(0).starts_with(bbqr_prefix), "{payload:?}");
        }
    }

    /// Frames are a pure function of their index: asking twice gives the same string, and
    /// asking out of order gives the same strings as asking in order. The player's freedom
    /// to pause, repeat and step backwards rests on this.
    #[test]
    fn frames_are_a_pure_function_of_the_index() {
        let psbt = psbt_shaped(2000);
        for transport in [Transport::Ur, Transport::Bbqr] {
            let animation = Animation::new(Payload::Psbt(&psbt), transport, 200).unwrap();
            let forwards: Vec<String> = (0..30).map(|n| animation.frame(n)).collect();
            for n in (0..30u32).rev() {
                assert_eq!(animation.frame(n), forwards[n as usize], "{transport:?} {n}");
            }
            assert_eq!(animation.frame(7), forwards[7]);
        }
    }

    /// Which transport keeps saying something new past its last part, and which repeats.
    #[test]
    fn only_a_multipart_ur_is_a_fountain() {
        let big = psbt_shaped(4000);
        let small = psbt_shaped(40);

        let ur = Animation::new(Payload::Psbt(&big), Transport::Ur, 200).unwrap();
        assert!(ur.part_count() > 1 && ur.is_fountain());
        assert_ne!(ur.frame(ur.part_count()), ur.frame(0), "a mixture, not a repeat");

        let bbqr = Animation::new(Payload::Psbt(&big), Transport::Bbqr, 200).unwrap();
        assert!(bbqr.part_count() > 1 && !bbqr.is_fountain());
        assert_eq!(bbqr.frame(bbqr.part_count()), bbqr.frame(0), "cycles");

        for transport in [Transport::Ur, Transport::Bbqr] {
            let still = Animation::new(Payload::Psbt(&small), transport, 200).unwrap();
            assert_eq!(still.part_count(), 1);
            assert!(!still.is_fountain());
            assert_eq!(still.frame(9), still.frame(0));
        }
    }

    /// Both transports refuse the same three requests, and neither can fail afterwards.
    #[test]
    fn refusals_are_decided_once_at_construction() {
        for transport in [Transport::Ur, Transport::Bbqr] {
            assert_eq!(
                Animation::new(Payload::Text(""), transport, 200).unwrap_err(),
                TransportError::EmptyPayload,
                "{transport:?}"
            );
            assert!(matches!(
                Animation::new(Payload::Text("x"), transport, 0).unwrap_err(),
                TransportError::FragmentTooSmall { .. }
            ));
        }
        let huge = psbt_shaped(64 * 1024);
        assert_eq!(
            Animation::new(Payload::Psbt(&huge), Transport::Bbqr, 10).unwrap_err(),
            TransportError::TooManyParts { limit: MAX_PARTS }
        );
    }

    /// End to end at the level a caller sees: a PSBT out through each transport and back
    /// through the test readers, byte for byte, at the default density.
    #[test]
    fn a_psbt_survives_both_transports() {
        let psbt = psbt_shaped(3000);

        let ur = Animation::new(Payload::Psbt(&psbt), Transport::Ur, DEFAULT_MAX_FRAGMENT).unwrap();
        let mut reader = ur::tests::Reader::new();
        for n in 0..ur.part_count() {
            assert!(reader.receive(&ur.frame(n)));
        }
        let message = reader.message().unwrap();
        assert_eq!(reader.ur_type, "crypto-psbt");
        assert_eq!(ur::tests::unwrap_byte_string(&message).unwrap(), psbt);

        let bbqr =
            Animation::new(Payload::Psbt(&psbt), Transport::Bbqr, DEFAULT_MAX_FRAGMENT).unwrap();
        let frames: Vec<String> = (0..bbqr.part_count()).map(|n| bbqr.frame(n)).collect();
        assert_eq!(bbqr::tests::join(&frames).unwrap(), ('P', psbt));
    }

    /// Every character of every frame is inside the QR alphanumeric set, which is what BBQr
    /// requires and what lets a symbol encoder pick the dense mode. UR2 does not require it,
    /// since bytewords are lowercase and alphanumeric mode has no room for those, so only
    /// the BBQr frames are held to it and the UR frames are held to plain ASCII.
    #[test]
    fn frames_stay_inside_the_character_sets_they_promise() {
        const ALNUM: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$%*+-./:";
        let psbt = psbt_shaped(1500);

        let bbqr = Animation::new(Payload::Psbt(&psbt), Transport::Bbqr, 200).unwrap();
        for n in 0..bbqr.part_count() {
            for c in bbqr.frame(n).chars() {
                assert!(ALNUM.contains(c), "frame {n} has {c:?}");
            }
        }

        let ur = Animation::new(Payload::Psbt(&psbt), Transport::Ur, 200).unwrap();
        for n in 0..ur.part_count().saturating_add(5) {
            let frame = ur.frame(n);
            assert!(frame.is_ascii(), "frame {n} is not ASCII");
            assert!(frame.starts_with("ur:crypto-psbt/"));
        }
    }

    // -- The join with the PSBT engine (MILESTONES.md 0.2.0-m8) --------------------------
    //
    // m8's whole reason to exist is that a PSBT this device signed can leave it as light.
    // Everything above proves the transports carry arbitrary bytes; these two prove they
    // carry the exact bytes `notyas-core`'s signing engine produces, and that what comes
    // off the frames is a PSBT that same engine parses. `notyas-core` is a DEV dependency
    // for this and nothing else - see the manifest.

    /// A signed 2-of-3 P2WSH `sortedmulti` PSBT, and a signed single-sig one.
    ///
    /// GENERATED, not published: both come from the fixed fixture seed `[0x2a; 64]` through
    /// this tree's own signer. `tests/corpus/README.md` carries the provenance and the
    /// regeneration recipe. The published vectors this module is held to are bc-ur's and
    /// BBQr's, pinned in `ur.rs` and `bbqr.rs`.
    const SIGNED_MULTISIG: &str = include_str!("../../tests/corpus/signed-psbt-multisig.hex");
    const SIGNED_P2WPKH: &str = include_str!("../../tests/corpus/signed-psbt-p2wpkh.hex");

    /// The corpus files, hex, wrapped at eighty columns.
    fn unhex(text: &str) -> Vec<u8> {
        let digits: Vec<u8> = text
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .map(|c| c.to_digit(16).expect("corpus is not hex") as u8)
            .collect();
        assert_eq!(digits.len() % 2, 0, "corpus has an odd number of hex digits");
        digits.chunks_exact(2).map(|pair| pair[0] * 16 + pair[1]).collect()
    }

    /// The corpus is what it claims to be. A transport test over bytes that were not really
    /// a signed PSBT would prove nothing about the join it exists to prove, and a corpus
    /// file that rotted would fail here rather than somewhere misleading.
    #[test]
    fn the_corpus_is_signed_psbts_this_engine_parses() {
        for (name, hex, len) in [
            ("multisig", SIGNED_MULTISIG, 643usize),
            ("p2wpkh", SIGNED_P2WPKH, 379),
        ] {
            let bytes = unhex(hex);
            assert_eq!(bytes.len(), len, "{name}");
            let psbt = notyas_core::psbt::decode(&bytes).expect(name);
            assert_eq!(notyas_core::psbt::encode(&psbt), bytes, "{name} does not re-encode");
            assert_eq!(psbt.inputs.len(), 1, "{name}");
            assert_eq!(psbt.inputs[0].partial_sigs.len(), 1, "{name}: no signature");
        }
    }

    /// End to end, at the level the milestone names: a signed PSBT goes out as animated
    /// frames over both transports and comes back byte for byte, still a PSBT the engine
    /// parses to the same identity. One full cycle of the player, at the default density.
    #[test]
    fn a_signed_psbt_survives_the_player_and_is_a_psbt_again() {
        for (name, hex) in [("multisig", SIGNED_MULTISIG), ("p2wpkh", SIGNED_P2WPKH)] {
            let signed = unhex(hex);
            let id = notyas_core::psbt::psbt_id(&notyas_core::psbt::decode(&signed).unwrap());

            let mut player = Playback::new(Payload::Psbt(&signed), Transport::Ur).unwrap();
            assert!(player.part_count() > 1, "{name}: not an animation at all");
            let mut reader = ur::tests::Reader::new();
            for _ in 0..player.frame_count() {
                let frame = player.frame();
                assert!(frame.starts_with("ur:crypto-psbt/"), "{name}");
                assert!(reader.receive(&frame), "{name}");
                player.advance();
            }
            let message = reader.message().expect("the UR cycle did not assemble");
            assert_eq!(reader.ur_type, "crypto-psbt", "{name}");
            let recovered = ur::tests::unwrap_byte_string(&message).unwrap();
            assert_eq!(recovered, signed, "{name}: UR did not carry the PSBT");
            let back = notyas_core::psbt::decode(&recovered).expect("UR output is not a PSBT");
            assert_eq!(notyas_core::psbt::psbt_id(&back), id, "{name}");

            let mut player = Playback::new(Payload::Psbt(&signed), Transport::Bbqr).unwrap();
            let frames: Vec<String> = (0..player.frame_count())
                .map(|_| {
                    let frame = player.frame();
                    player.advance();
                    frame
                })
                .collect();
            let (kind, recovered) = bbqr::tests::join(&frames).expect("the BBQr series is short");
            assert_eq!(kind, 'P', "{name}");
            assert_eq!(recovered, signed, "{name}: BBQr did not carry the PSBT");
            let back = notyas_core::psbt::decode(&recovered).expect("BBQr output is not a PSBT");
            assert_eq!(notyas_core::psbt::psbt_id(&back), id, "{name}");
        }
    }
}
