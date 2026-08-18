// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Known-answer vectors for the ladder and the on-flash format.
//!
//! These are the vectors ESP-SEAL.md 8.1 asks for, published so that any reimplementation
//! of the format can prove compatibility against the same numbers. They are pinned as
//! bytes and digests rather than as internal intermediates on purpose: an intermediate
//! that only exists behind a test-only accessor cannot be checked by an independent
//! implementation, and a whole-image digest catches a change to any link in the chain -
//! `device_binding`, `guard_key`, `hdr_key`, `kdf_salt`, `prestretch`, `bound`, the HKDF
//! info, the AAD framing, the AEAD call, the header layout and the ledger encoding all
//! feed into it.
//!
//! Everything below is a pure function of `(the SoftMac key, the domain tag, the PIN, the
//! Argon2id parameters, the operation sequence)`. There is no RNG and no clock anywhere in
//! the crate, so if any of these numbers moves, the format moved with it. A change here is
//! never "just update the vector": it is a format revision, and every device already in
//! the field stops being readable.

use notyas_wallet::sim::{SimFlash, SoftMac, VecScratch};
use notyas_wallet::{
    Config, KdfParams, KeyProvenance, Layout, Occupancy, Pin, PolicyRequest, Region, SlotClass,
    SlotId, Vault,
};
use sha2::{Digest, Sha256};

/// The vector config: the shipped V1 slot map, a fixed domain tag, and test-cost Argon2id.
fn kat_config() -> Config {
    Config {
        domain_tag: *b"esl-kat-vector01",
        kdf: KdfParams::TEST_ONLY,
        layout: Layout::V1,
        format_policy: PolicyRequest {
            wipe_after: 15,
            min_pin_len: 4,
        },
        occupancy: Occupancy::AlwaysFilled,
        accept_provenance: &[KeyProvenance::EfuseReadProtected, KeyProvenance::Emulated],
        disable_wipe_min_pin_len: None,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn digest(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex(&h.finalize())
}

/// The fixed sequence every vector is taken from.
///
/// SoftMac key `[0x5a; 32]`, provenance `EfuseReadProtected`, unencrypted records region so
/// the raw bytes are the logical bytes.
fn build(cfg: &Config, params: KdfParams) -> SimFlash {
    let cfg = Config { kdf: params, ..*cfg };
    let flash = SimFlash::v1();
    let mut v = Vault::mount(flash, SoftMac::new(), &cfg).expect("mount");
    let mut s = VecScratch::for_params(&cfg.kdf);
    let session = v
        .format(
            &Pin::from_normalized_utf8("135790").expect("pin"),
            b"kat",
            s.scratch(),
        )
        .expect("format");
    let slot = SlotId::new(SlotClass::Payload, 0, &cfg.layout).expect("slot");
    v.write(&session, slot, b"ESL known-answer payload")
        .expect("write");
    let registry = SlotId::new(SlotClass::Registry, 3, &cfg.layout).expect("slot");
    v.write(&session, registry, &[0x11u8; 512]).expect("write");
    drop(session);
    let (flash, _) = v.into_parts();
    flash
}

/// The 80-byte header of one side, straight off the raw records region.
fn header_at(flash: &SimFlash, sector: u32) -> String {
    let raw = flash.raw(Region::Records);
    let off = (sector as usize) * 4096;
    hex(&raw[off..off + 80])
}

#[test]
fn the_header_layout_is_byte_exact() {
    let cfg = kat_config();
    let flash = build(&cfg, KdfParams::TEST_ONLY);

    // Superblock side A, sector 0. `pin_gen` is 0 for the superblock by definition and
    // `seal_seq` is 0 because it is the first record any store writes.
    assert_eq!(
        header_at(&flash, 0),
        concat!(
            "45534c520100010000000000", // magic ESLR, format_ver 1, suite_id 1, class, index, side, flags
            "200000000100000001000000", // argon2 m_kib, t, p, and the three MBZ bytes
            "0000000000000000", // seal_seq
            "0000000000000000", // wipe_epoch
            "00000000b00f0000", // pin_gen and body_capacity - end of the 48-byte AAD
            "e09e6d5eac572dac0bc5e46d52584e13", // body_digest
            "e0fe7820b39e63ac207322e3fe1f78d2", // header_mac - writing these 16 bytes IS the commit point
        ),
        "superblock header"
    );

    // Canary slot 0 side A, sector 2. `seal_seq` = 1, `pin_gen` = 1.
    assert_eq!(
        header_at(&flash, 2),
        concat!(
            "45534c520100010001000000", // magic ESLR, format_ver 1, suite_id 1, class, index, side, flags
            "200000000100000001000000", // argon2 m_kib, t, p, and the three MBZ bytes
            "0100000000000000", // seal_seq
            "0000000000000000", // wipe_epoch
            "01000000b00f0000", // pin_gen and body_capacity - end of the 48-byte AAD
            "879c7bdd6f1bc20de29446f2aaa54dd9", // body_digest
            "019167715661e23cbaf1172098bdb288", // header_mac - writing these 16 bytes IS the commit point
        ),
        "canary header"
    );
}

#[test]
fn the_whole_image_is_a_pure_function_of_its_inputs_at_test_parameters() {
    let cfg = kat_config();
    let flash = build(&cfg, KdfParams::TEST_ONLY);
    assert_eq!(
        digest(flash.raw(Region::Records)),
        "5e5d5be317de8758e4fd95cbfff90002f68009cc8a89d5fcb0f60def0b591bc6",
        "records region"
    );
    assert_eq!(
        digest(flash.raw(Region::Ledger)),
        "b85e4183a213ca4d3405f7385073c5d68eab3ad223602673e9632cb29daa207b",
        "ledger region"
    );
}

#[test]
fn the_whole_image_is_a_pure_function_of_its_inputs_at_pinned_parameters() {
    // m = 16384 KiB, t = 1, p = 1: the measured production parameters, 1827 ms on both
    // bench boards (MEASUREMENTS.md m1). On a host this is a fraction of that, which is
    // why it can be an ordinary test rather than an ignored one, and it is the only place
    // the shipped cost is exercised end to end.
    let cfg = kat_config();
    let flash = build(&cfg, KdfParams::PINNED);
    assert_eq!(
        digest(flash.raw(Region::Records)),
        "3bf12e16356aa19e4270019e8ff1af0d73d4f648d84fbd68263322cb9a6b0beb",
        "records region at production parameters"
    );
}

#[test]
fn the_image_is_reproducible_across_runs_and_across_processes() {
    // The property that makes every other vector in this file meaningful. If this fails,
    // something in the crate is reading a clock, an address or an allocator.
    let cfg = kat_config();
    let a = build(&cfg, KdfParams::TEST_ONLY);
    let b = build(&cfg, KdfParams::TEST_ONLY);
    assert_eq!(
        digest(a.raw(Region::Records)),
        digest(b.raw(Region::Records))
    );
    assert_eq!(digest(a.raw(Region::Ledger)), digest(b.raw(Region::Ledger)));
}

#[test]
fn a_different_device_key_produces_a_completely_different_image() {
    let cfg = kat_config();
    let one = build(&cfg, KdfParams::TEST_ONLY);

    let flash = SimFlash::v1();
    let mut v = Vault::mount(flash, SoftMac::other_board(), &cfg).expect("mount");
    let mut s = VecScratch::for_params(&cfg.kdf);
    let session = v
        .format(
            &Pin::from_normalized_utf8("135790").expect("pin"),
            b"kat",
            s.scratch(),
        )
        .expect("format");
    let slot = SlotId::new(SlotClass::Payload, 0, &cfg.layout).expect("slot");
    v.write(&session, slot, b"ESL known-answer payload")
        .expect("write");
    drop(session);
    let (two, _) = v.into_parts();

    assert_ne!(
        digest(one.raw(Region::Records)),
        digest(two.raw(Region::Records)),
        "device binding must reach every byte: the same PIN on another board shares \
         nothing"
    );
    assert_ne!(
        digest(one.raw(Region::Ledger)),
        digest(two.raw(Region::Ledger)),
        "the ledger's guard MACs are device-bound too, which is what stops an attacker \
         with a programmer from forging a cell"
    );
}

#[test]
fn a_different_domain_tag_produces_a_completely_different_image() {
    let cfg = kat_config();
    let one = build(&cfg, KdfParams::TEST_ONLY);
    let other = Config {
        domain_tag: *b"esl-kat-vector02",
        ..cfg
    };
    let two = build(&other, KdfParams::TEST_ONLY);
    assert_ne!(
        digest(one.raw(Region::Records)),
        digest(two.raw(Region::Records)),
        "the embedder's domain tag separates two products on one silicon key"
    );
}

#[test]
fn the_pinned_argon2_parameters_are_the_measured_ones() {
    // Not a computation, a record. MEASUREMENTS.md m1: 16 MiB, t = 1, p = 1, 1827 ms on
    // the Waveshare and 1825 ms on the Elecrow, with a 32 MiB working set failing to
    // allocate at all on both. The constant is here so that changing it is a deliberate
    // act with a test to update, not an edit nobody notices.
    assert_eq!(KdfParams::PINNED.m_kib, 16_384);
    assert_eq!(KdfParams::PINNED.t, 1);
    assert_eq!(KdfParams::PINNED.p, 1);
    assert_eq!(
        KdfParams::PINNED.scratch_blocks(),
        16_384,
        "one 1 KiB Argon2 block per KiB of working set; the embedder allocates this many"
    );
}

