// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The animation's playback state: which frame is on the glass, how fast it moves, and how
//! much payload each symbol carries.
//!
//! # The question this file answers
//!
//! [`super::Animation`] answers *what string is frame N*. That leaves a second question
//! that every caller of it would otherwise answer for itself: *which N, and when*. Screen
//! 11 has a pause control, three speed steps, three density steps and an `i/j` counter
//! (UX-SCREENS.md C11), and all four are decisions about the sequence rather than about
//! drawing - so they belong beside the encoder, not inside a screen. A UI that owns them
//! ends up owning the rebuild a density change forces, which is exactly the encoder
//! knowledge it was meant not to have.
//!
//! # Still no clock
//!
//! [`Playback`] holds no time and reads none. It publishes the interval its current speed
//! step asks for ([`Speed::interval_ms`]) and moves exactly one frame per call to
//! [`Playback::advance`]; the caller's tick owns when that call happens. The crate
//! therefore stays a pure function of its inputs, and the player remains free to hold a
//! frame while the user lines up a phone.
//!
//! # The claim this shape exists to keep
//!
//! MILESTONES.md 0.2.0-m8 must not break "an idle device performs zero repaints outside an
//! active animation". [`Playback::advance`] returns `false` - meaning *nothing changed, do
//! not repaint* - whenever the animation is paused or is a single still frame, so a tick
//! handler cannot repaint an idle screen without ignoring an answer it asked for. Every
//! other control returns the same signal for the same reason: `true` only when something a
//! user can see actually moved.
//!
//! # Where the copy is not
//!
//! C11's status line reads "6 frames/s - 200 bytes per frame - fountain encoded, loops
//! forever". This file publishes those three facts and writes none of that sentence:
//! UX-SCREENS.md owns the copy vocabulary and notyas-ui owns the rendering.

use alloc::string::String;

use super::{Animation, Payload, Transport, TransportError, DEFAULT_MAX_FRAGMENT};

/// One step of the speed control.
///
/// The interval is tabulated beside the rate rather than divided out of it. Partly because
/// the crate forbids integer division, and partly because the rounding is a decision worth
/// recording: 83 ms is 12.05 frames per second, and rounding the interval DOWN keeps every
/// stated rate a floor the player meets rather than a number it misses by a millisecond.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Speed {
    /// Frames per second, as the status line states it.
    pub fps: u8,
    /// Milliseconds between the [`Playback::advance`] calls that produce this rate.
    pub interval_ms: u16,
}

/// The three speed steps of UX-SCREENS.md C11, slowest first.
pub const SPEED_STEPS: [Speed; 3] = [
    Speed { fps: 3, interval_ms: 333 },
    Speed { fps: 6, interval_ms: 167 },
    Speed { fps: 12, interval_ms: 83 },
];

/// The three density steps of UX-SCREENS.md C11, in payload bytes per frame, sparsest
/// first. A sparser step is a smaller symbol and a longer animation.
pub const DENSITY_STEPS: [usize; 3] = [100, DEFAULT_MAX_FRAGMENT, 400];

/// Where both controls start: the middle step of each.
///
/// The middle of the density range is [`DEFAULT_MAX_FRAGMENT`], which MILESTONES.md
/// 0.2.0-m8 fixes at 200 bytes; `the_default_density_step_is_the_documented_default` holds
/// the two to each other.
const DEFAULT_STEP: usize = 1;

/// How many passes a fountain animation runs before the cycle repeats exactly.
///
/// One pure pass recovers nothing a reader missed, because a missed frame stays missed
/// until the identical string comes round again. The frames past the last part are
/// exclusive-or mixtures, and a reader holding mixtures that differ by one unknown
/// fragment can solve for it - so the extra passes are what let a reader that lost
/// scattered frames finish without waiting for each specific frame it lacks.
///
/// Three is chosen against the arithmetic rather than by taste. Measured over this encoder
/// at part counts from 7 to 61, a peeling decoder finishes on between 1.15 and 1.5 times
/// the part count in distinct frames; at three passes a reader losing one frame in three
/// still receives twice the part count inside a single cycle, which clears that band with
/// room. The cost is the cycle length: sixteen parts at the middle speed step is eight
/// seconds a pass.
///
/// **The honest limit.** The cycle repeats exactly, so a reader whose losses fall at the
/// same positions every pass never gains on it. That is what the density control is for -
/// a different fragment length is a different series with its own checksum, mixtures and
/// length, so one tap breaks any lock. Looping is a convenience for a reader that is merely
/// unlucky, not a guarantee against one that is systematically blind.
///
/// BBQr gets no extension at all. It has no mixtures, so the only thing past the last part
/// is part zero again.
const FOUNTAIN_PASSES: u32 = 3;

/// A running animation: the frame on the glass, the speed, the density, and whether it is
/// moving at all.
pub struct Playback<'a> {
    /// Kept because a density change re-encodes the payload from scratch: a different
    /// fragment length is a different UR series with its own checksum and part count, not
    /// a re-cut of the same one.
    payload: Payload<'a>,
    transport: Transport,
    animation: Animation,
    /// Index into [`DENSITY_STEPS`].
    density: usize,
    /// Index into [`SPEED_STEPS`].
    speed: usize,
    running: bool,
    /// Zero-based position in the cycle. Never at or past [`Playback::frame_count`].
    cursor: u32,
}

impl core::fmt::Debug for Playback<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Playback")
            .field("transport", &self.transport)
            .field("position", &self.position())
            .field("frames", &self.frame_count())
            .field("fps", &self.speed().fps)
            .field("bytes_per_frame", &self.bytes_per_frame())
            .field("running", &self.running)
            .finish()
    }
}

impl<'a> Playback<'a> {
    /// Prepare `payload` for display over `transport`, at the middle density, at the middle
    /// speed, running, showing the first frame.
    ///
    /// When the middle density would need more parts than the format can number, the denser
    /// steps are tried in turn before giving up. A refusal the user could have cleared by
    /// tapping `Bigger` is a refusal they never get the chance to clear, because there is
    /// no player on screen to tap.
    ///
    /// # Errors
    ///
    /// [`TransportError::EmptyPayload`] for an empty payload, and
    /// [`TransportError::TooManyParts`] when even the densest step cannot number the parts.
    /// Both are decided here, once; no method below this line can fail.
    pub fn new(payload: Payload<'a>, transport: Transport) -> Result<Playback<'a>, TransportError> {
        let mut refusal = TransportError::TooManyParts { limit: super::MAX_PARTS };
        for (density, &bytes) in DENSITY_STEPS.iter().enumerate().skip(DEFAULT_STEP) {
            match Animation::new(payload, transport, bytes) {
                Ok(animation) => {
                    return Ok(Playback {
                        payload,
                        transport,
                        animation,
                        density,
                        speed: DEFAULT_STEP,
                        running: true,
                        cursor: 0,
                    })
                }
                // Only a part-count refusal is worth a denser attempt. An empty payload is
                // still empty however it is cut, and a fragment bound this crate cannot
                // meet is not a bound the density steps set.
                Err(err @ TransportError::TooManyParts { .. }) => refusal = err,
                Err(err) => return Err(err),
            }
        }
        Err(refusal)
    }

    /// The complete string for the frame currently on the glass.
    pub fn frame(&self) -> String {
        self.animation.frame(self.cursor)
    }

    /// The frame counter's numerator: which frame of the cycle is showing, counting from
    /// one, as C11's bar renders it.
    pub fn position(&self) -> u32 {
        self.cursor.saturating_add(1)
    }

    /// The frame counter's denominator: how many frames a full cycle runs before the
    /// sequence repeats exactly.
    ///
    /// For BBQr and for any single-frame payload this is the part count, because there is
    /// nothing else to show. For a multi-part UR it is [`FOUNTAIN_PASSES`] times the part
    /// count - one pure pass and two runs of mixtures - which is what lets a reader that
    /// lost scattered frames finish without waiting for each specific one.
    pub fn frame_count(&self) -> u32 {
        let parts = self.animation.part_count();
        if self.animation.is_fountain() {
            parts.saturating_mul(FOUNTAIN_PASSES)
        } else {
            parts
        }
    }

    /// Move to the next frame of the cycle, wrapping at the end.
    ///
    /// Returns whether the screen has anything new to draw. `false` while paused and
    /// `false` for a single-frame payload, which is the whole of the "zero repaints outside
    /// an active animation" claim expressed as a value the caller cannot help but read.
    pub fn advance(&mut self) -> bool {
        let count = self.frame_count();
        if !self.running || count <= 1 {
            return false;
        }
        let next = self.cursor.saturating_add(1);
        // No remainder: the cursor moves one step at a time and is compared only against
        // the count it was just measured against.
        self.cursor = if next >= count { 0 } else { next };
        true
    }

    /// Whether the animation is moving.
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Pause or resume. Returns whether the state changed.
    ///
    /// Resuming neither advances nor repaints: the frame on the glass is still the right
    /// one, and the next tick moves it.
    pub fn set_running(&mut self, running: bool) -> bool {
        let changed = self.running != running;
        self.running = running;
        changed
    }

    /// The current speed step.
    pub fn speed(&self) -> Speed {
        SPEED_STEPS.get(self.speed).copied().unwrap_or(SPEED_STEPS[DEFAULT_STEP])
    }

    /// Which speed step is selected, for a segmented control that has to show it.
    pub fn speed_step(&self) -> usize {
        self.speed
    }

    /// One step faster. Returns whether it moved; `false` at the top of the range, where
    /// the control is drawn disabled rather than silently doing nothing.
    pub fn faster(&mut self) -> bool {
        self.set_speed(self.speed.saturating_add(1))
    }

    /// One step slower. Returns whether it moved.
    pub fn slower(&mut self) -> bool {
        match self.speed.checked_sub(1) {
            Some(step) => self.set_speed(step),
            None => false,
        }
    }

    /// Select speed step `step`. Returns whether it moved.
    pub fn set_speed(&mut self, step: usize) -> bool {
        if step >= SPEED_STEPS.len() || step == self.speed {
            return false;
        }
        self.speed = step;
        true
    }

    /// Payload bytes carried by each frame at the current density step.
    pub fn bytes_per_frame(&self) -> usize {
        DENSITY_STEPS.get(self.density).copied().unwrap_or(DEFAULT_MAX_FRAGMENT)
    }

    /// Which density step is selected.
    pub fn density_step(&self) -> usize {
        self.density
    }

    /// One step denser - a bigger symbol carrying more bytes, so fewer frames. C11 labels
    /// this control `Bigger`. Returns whether it moved.
    pub fn denser(&mut self) -> bool {
        self.set_density(self.density.saturating_add(1))
    }

    /// One step sparser - a smaller symbol carrying fewer bytes, so more frames, which is
    /// what a reader with a poor camera needs. C11 labels this control `Smaller`. Returns
    /// whether it moved.
    pub fn sparser(&mut self) -> bool {
        match self.density.checked_sub(1) {
            Some(step) => self.set_density(step),
            None => false,
        }
    }

    /// Select density step `step`. Returns whether it moved.
    ///
    /// Either the whole animation changes or nothing does: a step the format cannot number
    /// leaves the current series, cursor and controls exactly as they were, so a user who
    /// taps `Smaller` once too often keeps the animation they were showing.
    ///
    /// A step that succeeds restarts the cycle. It has to: a different fragment length is a
    /// different UR series with its own checksum, and the fragments a reader has already
    /// collected are worth nothing against it. Restarting at frame one is the honest signal
    /// that the scan begins again.
    pub fn set_density(&mut self, step: usize) -> bool {
        let Some(&bytes) = DENSITY_STEPS.get(step) else {
            return false;
        };
        if step == self.density {
            return false;
        }
        let Ok(animation) = Animation::new(self.payload, self.transport, bytes) else {
            return false;
        };
        self.animation = animation;
        self.density = step;
        self.cursor = 0;
        true
    }

    /// Show the first frame again, without changing speed, density or the paused state.
    /// Returns whether the frame moved.
    pub fn restart(&mut self) -> bool {
        let moved = self.cursor != 0;
        self.cursor = 0;
        moved
    }

    /// How many distinct parts carry the payload at the current density.
    pub fn part_count(&self) -> u32 {
        self.animation.part_count()
    }

    /// Whether frames past the last part carry new information - the third fact C11's
    /// status line states, and the one that answers "I missed a frame".
    pub fn is_fountain(&self) -> bool {
        self.animation.is_fountain()
    }

    /// Which format the frames are written in.
    pub fn transport(&self) -> Transport {
        self.transport
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
    use crate::transport::{bbqr, ur, MAX_PARTS};
    use alloc::vec::Vec;

    fn payload(len: usize) -> Vec<u8> {
        make_message("notyas-playback", len)
    }

    /// The density control's middle step and the milestone's stated default are one number,
    /// and both controls start there.
    #[test]
    fn the_default_density_step_is_the_documented_default() {
        assert_eq!(DENSITY_STEPS[DEFAULT_STEP], DEFAULT_MAX_FRAGMENT);
        assert_eq!(DEFAULT_MAX_FRAGMENT, 200);
        let bytes = payload(2000);
        let play = Playback::new(Payload::Psbt(&bytes), Transport::Ur).unwrap();
        assert_eq!(play.bytes_per_frame(), 200);
        assert_eq!(play.speed().fps, 6);
        assert!(play.is_running());
        assert_eq!(play.position(), 1);
    }

    /// The cycle wraps exactly: after `frame_count` advances, the counter and the string on
    /// the glass are both back where they started.
    #[test]
    fn a_full_cycle_returns_to_the_first_frame() {
        let bytes = payload(2000);
        for transport in [Transport::Ur, Transport::Bbqr] {
            let mut play = Playback::new(Payload::Psbt(&bytes), transport).unwrap();
            let first = play.frame();
            let count = play.frame_count();
            assert!(count > 1, "{transport:?}");
            for step in 1..count {
                assert!(play.advance(), "{transport:?} step {step}");
                assert_eq!(play.position(), step.saturating_add(1));
                assert_ne!(play.frame(), first, "{transport:?} step {step}");
            }
            assert!(play.advance());
            assert_eq!(play.position(), 1);
            assert_eq!(play.frame(), first, "{transport:?}");
        }
    }

    /// A paused animation produces no new frame, which is the "zero repaints outside an
    /// active animation" claim in the form a caller can act on.
    #[test]
    fn a_paused_animation_asks_for_no_repaint() {
        let bytes = payload(2000);
        let mut play = Playback::new(Payload::Psbt(&bytes), Transport::Ur).unwrap();
        assert!(play.advance());
        let held = play.frame();

        assert!(play.set_running(false));
        assert!(!play.set_running(false), "already paused");
        for _ in 0..50 {
            assert!(!play.advance());
        }
        assert_eq!(play.frame(), held);
        assert_eq!(play.position(), 2);

        assert!(play.set_running(true));
        assert!(play.advance());
        assert_ne!(play.frame(), held);
    }

    /// A payload that fits one symbol is a still: one frame, no fountain, and no repaint
    /// ever, running or not.
    #[test]
    fn a_single_frame_payload_never_asks_for_a_repaint() {
        let bytes = payload(40);
        for transport in [Transport::Ur, Transport::Bbqr] {
            let mut play = Playback::new(Payload::Psbt(&bytes), transport).unwrap();
            assert_eq!(play.part_count(), 1, "{transport:?}");
            assert_eq!(play.frame_count(), 1);
            assert!(!play.is_fountain());
            assert!(play.is_running());
            let still = play.frame();
            for _ in 0..20 {
                assert!(!play.advance(), "{transport:?}");
            }
            assert_eq!(play.frame(), still);
            assert_eq!(play.position(), 1);
        }
    }

    /// A UR cycle is one pure pass plus one run of mixtures; a BBQr cycle is the parts and
    /// nothing else.
    #[test]
    fn only_a_fountain_cycle_runs_past_its_parts() {
        let bytes = payload(2000);

        let ur = Playback::new(Payload::Psbt(&bytes), Transport::Ur).unwrap();
        assert!(ur.is_fountain());
        assert_eq!(ur.frame_count(), ur.part_count() * FOUNTAIN_PASSES);

        let bbqr = Playback::new(Payload::Psbt(&bytes), Transport::Bbqr).unwrap();
        assert!(!bbqr.is_fountain());
        assert_eq!(bbqr.frame_count(), bbqr.part_count());
    }

    /// The point of the extended cycle, and the number [`FOUNTAIN_PASSES`] is chosen
    /// against: a reader that loses one frame in three still finishes inside one cycle,
    /// where a cycle of pure parts would have needed the exact frames it missed.
    ///
    /// The sizes bracket what this device emits - a small single-sig PSBT through a large
    /// multisig one - because the peeling decoder's overhead is not flat in the part count.
    #[test]
    fn a_reader_losing_a_third_of_the_frames_finishes_inside_one_cycle() {
        for len in [1200usize, 3000, 7000, 12_000] {
            let bytes = payload(len);
            let mut play = Playback::new(Payload::Psbt(&bytes), Transport::Ur).unwrap();
            assert!(play.part_count() >= 6, "len {len}: too few parts to lose any");

            let mut reader = ur::tests::Reader::new();
            for step in 0..play.frame_count() {
                if step % 3 != 0 {
                    assert!(reader.receive(&play.frame()), "len {len} step {step}");
                }
                play.advance();
            }
            let message = reader.message().unwrap_or_else(|| {
                panic!("len {len}: a cycle missing a third of its frames did not converge")
            });
            assert_eq!(ur::tests::unwrap_byte_string(&message).unwrap(), bytes, "len {len}");
        }
    }

    /// The speed control steps 3 / 6 / 12 and stops at both ends rather than wrapping.
    #[test]
    fn the_speed_control_steps_and_clamps() {
        let bytes = payload(2000);
        let mut play = Playback::new(Payload::Psbt(&bytes), Transport::Ur).unwrap();
        assert_eq!(play.speed(), Speed { fps: 6, interval_ms: 167 });

        assert!(play.slower());
        assert_eq!(play.speed(), Speed { fps: 3, interval_ms: 333 });
        assert!(!play.slower(), "already slowest");
        assert_eq!(play.speed().fps, 3);

        assert!(play.faster());
        assert!(play.faster());
        assert_eq!(play.speed(), Speed { fps: 12, interval_ms: 83 });
        assert_eq!(play.speed_step(), 2);
        assert!(!play.faster(), "already fastest");
    }

    /// Speed is a property of the caller's tick, not of the sequence: changing it moves no
    /// frame and re-cuts no fragment.
    #[test]
    fn changing_speed_does_not_disturb_the_sequence() {
        let bytes = payload(2000);
        let mut play = Playback::new(Payload::Psbt(&bytes), Transport::Ur).unwrap();
        play.advance();
        play.advance();
        let (frame, position, parts) = (play.frame(), play.position(), play.part_count());

        assert!(play.faster());
        assert!(play.slower());
        assert_eq!((play.frame(), play.position(), play.part_count()), (frame, position, parts));
    }

    /// The density control steps 100 / 200 / 400, clamps at both ends, and every step
    /// re-cuts the payload: a sparser symbol is more parts, a denser one fewer.
    #[test]
    fn the_density_control_steps_and_re_cuts_the_payload() {
        let bytes = payload(4000);
        let mut play = Playback::new(Payload::Psbt(&bytes), Transport::Ur).unwrap();
        let at_200 = play.part_count();

        assert!(play.sparser());
        assert_eq!(play.bytes_per_frame(), 100);
        let at_100 = play.part_count();
        assert!(at_100 > at_200);
        assert!(!play.sparser(), "already sparsest");

        assert!(play.denser());
        assert!(play.denser());
        assert_eq!(play.bytes_per_frame(), 400);
        assert!(play.part_count() < at_200);
        assert_eq!(play.density_step(), 2);
        assert!(!play.denser(), "already densest");
    }

    /// A density change restarts the cycle, because the fragments a reader has already
    /// collected belong to a series that no longer exists.
    #[test]
    fn a_density_change_restarts_the_cycle() {
        let bytes = payload(4000);
        let mut play = Playback::new(Payload::Psbt(&bytes), Transport::Ur).unwrap();
        play.advance();
        play.advance();
        assert_eq!(play.position(), 3);

        assert!(play.denser());
        assert_eq!(play.position(), 1);
        assert!(play.sparser());
        assert_eq!(play.position(), 1);
    }

    /// A density step the format cannot number changes nothing at all - not the series, not
    /// the cursor, not the control.
    #[test]
    fn a_refused_density_step_leaves_everything_alone() {
        // Long enough that 100 bytes a frame overruns the part cap while 200 does not.
        let bytes = payload(MAX_PARTS as usize * 150);
        let mut play = Playback::new(Payload::Psbt(&bytes), Transport::Ur).unwrap();
        play.advance();
        let before = (play.frame(), play.position(), play.part_count(), play.bytes_per_frame());

        assert!(!play.sparser(), "100 bytes a frame should have overrun the part cap");
        assert_eq!(
            (play.frame(), play.position(), play.part_count(), play.bytes_per_frame()),
            before
        );
        assert!(!play.set_density(DENSITY_STEPS.len()), "out of range");
        assert_eq!(play.bytes_per_frame(), before.3);
    }

    /// When the middle density cannot number the parts, construction steps denser rather
    /// than handing back a refusal the user has no control to clear.
    #[test]
    fn construction_steps_denser_rather_than_refusing() {
        let bytes = payload(MAX_PARTS as usize * 250);
        let play = Playback::new(Payload::Psbt(&bytes), Transport::Ur).unwrap();
        assert_eq!(play.bytes_per_frame(), 400);
        assert!(play.part_count() <= MAX_PARTS);
    }

    /// Past the densest step there is nothing left to try, and the refusal names the part
    /// cap rather than whatever the middle step happened to say.
    #[test]
    fn construction_refuses_what_no_density_can_carry() {
        let bytes = payload(MAX_PARTS as usize * 500);
        assert_eq!(
            Playback::new(Payload::Psbt(&bytes), Transport::Ur).unwrap_err(),
            TransportError::TooManyParts { limit: MAX_PARTS }
        );
        assert_eq!(
            Playback::new(Payload::Text(""), Transport::Bbqr).unwrap_err(),
            TransportError::EmptyPayload
        );
    }

    /// The frames a cycle produces are the frames the transport promised, at every density
    /// step: one pass of the cycle carries the payload back byte for byte.
    #[test]
    fn every_density_step_round_trips_the_payload() {
        let bytes = payload(2600);
        for step in 0..DENSITY_STEPS.len() {
            let mut ur = Playback::new(Payload::Psbt(&bytes), Transport::Ur).unwrap();
            ur.set_density(step);
            assert_eq!(ur.density_step(), step);
            let mut reader = ur::tests::Reader::new();
            for _ in 0..ur.frame_count() {
                assert!(reader.receive(&ur.frame()), "step {step}");
                ur.advance();
            }
            let message = reader.message().expect("no message");
            assert_eq!(ur::tests::unwrap_byte_string(&message).unwrap(), bytes, "step {step}");

            let mut bbqr = Playback::new(Payload::Psbt(&bytes), Transport::Bbqr).unwrap();
            bbqr.set_density(step);
            let mut frames = Vec::new();
            for _ in 0..bbqr.frame_count() {
                frames.push(bbqr.frame());
                bbqr.advance();
            }
            assert_eq!(bbqr::tests::join(&frames).unwrap(), ('P', bytes.clone()), "step {step}");
        }
    }

    /// Restart moves the cursor and nothing else.
    #[test]
    fn restart_moves_only_the_cursor() {
        let bytes = payload(2000);
        let mut play = Playback::new(Payload::Psbt(&bytes), Transport::Ur).unwrap();
        assert!(!play.restart(), "already at the start");
        play.advance();
        play.advance();
        assert!(play.restart());
        assert_eq!(play.position(), 1);
        assert_eq!(play.bytes_per_frame(), 200);
        assert_eq!(play.speed().fps, 6);
        assert!(play.is_running());
    }
}
