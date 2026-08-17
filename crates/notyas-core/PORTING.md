# notyas-core - port record

Port of the desktop BigDice crate (`\\...\btc\dice_generator`, `bigdice` v0.3.0) into a
`#![no_std]` + `alloc` crate for the notyas device. The desktop crate's `docs/SPEC.md`
is normative; every "SPEC step N" reference in the sources carries over unchanged.
Divergence from desktop BigDice output on identical input is a release-blocking bug.

Ported modules: `entropy.rs`, `bip39.rs`, `derive.rs`, `qr.rs`, `report.rs` (pipeline
half). Not ported: `cli.rs`, `gui/*`, `main.rs`, the two binaries, `build_info.rs` (see
below). Plain `std::` -> `core::`/`alloc::` import swaps are not listed here; everything
else that differs from the desktop modules is.

## Wordlist

`src/wordlist_english.txt` is a byte-for-byte copy of the desktop crate's file
(upstream bitcoin/bips `bip-0039/english.txt`). SHA-256, verified by `build.rs` on every
build and pinned against checkout-time line-ending rewrites by `.gitattributes`:

    2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda

## Intentional differences vs the desktop modules

1. `bip39.rs`: the `std::sync::OnceLock` wordlist cache is gone. `build.rs` parses the
   file at compile time, verifies the digest above plus the 2048-word count and strict
   sort order (the same two checks the desktop makes at first use), and generates
   `static WORDLIST: [&str; WORDLIST_LEN]`. `wordlist()` keeps its exact signature; its
   runtime panic path no longer exists because the failure moved to build time.

2. `derive.rs`: the `std::sync::OnceLock` secp256k1 context is replaced by a hand-rolled
   racy-init static (`AtomicPtr` + compare-exchange over a leaked `Box`) - the
   `once_cell::race` pattern without the dependency. no_std has no blocking primitive to
   reproduce OnceLock with; racy init is sound here because the context is deterministic
   (curve constants, never randomized), so a lost race frees its candidate and adopts the
   winner's identical context. Same one-context-per-process behavior and cost profile as
   desktop; `derive`/`root_xprv`/`root_fingerprint` signatures unchanged.

3. `Cargo.toml`, `bitcoin`: `features = ["std"]` -> `default-features = false` with NO
   extra features. bitcoin 0.32.102 has no "alloc" feature (docs/ARCHITECTURE.md guessed
   it would): with "std" off the crate is no_std + alloc by construction and enables
   `secp256k1/alloc` itself, so `Secp256k1::new` remains available. Same exact pin
   `=0.32.102`. The secp256k1 C library still compiles for the host via cc/MSVC for
   tests, and cross-compiles for RISC-V (see the bare-metal check below).

4. `Cargo.toml`, `qrcode` / the `qr` module: qrcode 0.14.1 is NOT a no_std crate (it
   imports `std` unconditionally, e.g. `use std::ops::Index` in its lib.rs), so the task's
   preferred outcome - a plain no_std dependency - is impossible without forking it. The
   dependency is optional and `qr` sits behind the cargo feature `qr`, DEFAULT ON. The
   firmware is std Rust on ESP-IDF and keeps the default; only the bare-metal no_std
   proof builds with `--no-default-features`. Module contents are otherwise a straight
   port.

5. `Cargo.toml`, `unicode-normalization`: `default-features = false` (drops its "std"
   feature; NFKD itself is no_std + alloc). `sha2`/`hmac`/`pbkdf2`/`zeroize` declarations
   carry over unchanged because their defaults are already std-free (verified against the
   pinned versions: sha2 0.11 default = alloc+oid; hmac 0.13 has no default features;
   pbkdf2 0.13 default = hmac only; zeroize default = alloc).

6. `report.rs`: the hand-rolled JSON writer is not ported - the device emits no JSON.
   Dropped: `json_document`, `render_json`, `json_string`, `JsonWriter`, `push_decimal`,
   `INDENT`, and the `cfg(test)` `fixtures` module (it existed to feed the desktop
   renderers). Kept, byte-for-byte in behavior: `Report`, `SchemeReport`, `Parameters`,
   `BuildError` (including the zero-roll `NoRolls` refusal), `Report::build`,
   `Report::from_phrase`, `derive_all`, `effective_bits`, `capacity`, `escaped_len`,
   `hex_encode`. `effective_bits` is still the single source of the MIN_SECURE_BITS
   warning arithmetic. The module doc is trimmed to match.

7. `lib.rs` is written fresh for the new crate: no `#![doc = include_str!("README")]`
   (no README here), and the desktop's static-CRT `compile_error!` guard is dropped - it
   defends a Windows-release concern this crate does not have. `#[macro_use] extern crate
   alloc` supplies `format!`/`vec!` crate-wide; `#[cfg(test)] extern crate std` lets the
   ported unit tests run under the host test harness.

8. `build_info.rs` is not ported. On the device, source identity is the firmware image
   hash shown by the Verify screen (ARCHITECTURE.md); a per-crate source hash adds
   nothing the image hash does not cover. Revisit when firmware wires that screen.

9. Error trait impls moved from `std::error::Error` to `core::error::Error` (stable since
   Rust 1.81; identical behavior, and the crate floor is 1.85 regardless).

10. ASCII-only repo rule: three em-dashes in desktop `derive.rs` comments became `-`.
    Doc comments that pointed at desktop-only artifacts were re-worded, not re-claimed:
    references to `crate::cli`, `tests/vectors/README.md` and `docs/EQUIVALENCE.md` now
    name the desktop crate explicitly, and "the CLI must warn" style sentences now say
    "the front end".

## Tests

- Every module unit test is ported: entropy 8, bip39 15, derive 13, qr 6, report 7.
  The report count differs from desktop by design: 6 pipeline/hex tests ported verbatim;
  the JSON-writer tests (escaping, document shape, key order, buffer-growth) stayed with
  the writer; `the_json_buffer_is_never_outgrown` is replaced by
  `capacity_covers_every_string_the_report_holds`, which bounds `capacity` against the
  report's own contents since there is no writer to drive it end to end.
- `tests/spec_vectors.rs` is the desktop file with `bigdice::` -> `notyas_core::` and
  nothing else: BIP-32 vectors 1-5, BIP-39 Trezor vectors, BIP-44/49/84/86 and SLIP-132.
  The one `#[ignore]`d test (`vector_5_invalid_keys_are_rejected`) is ignored on desktop
  too; it documents a bitcoin 0.32 parser laxness, not a defect in this crate.
- `tests/fuzz_vectors.rs` is the differential corpus, rewritten to drive the library
  pipeline (`Report::build`) instead of the desktop CLI binary. The corpus file is the
  desktop's committed `tests/vectors/fuzz_vectors.json` - the trimmed representative set
  (10 positive + 4 negative cases) from the 224-case iancoleman/bip-utils fuzz campaign;
  the desktop suite runs this same file. Every recorded VALUE is compared (entropy
  fields, mnemonic, seed, root xprv, per-scheme account keys and SLIP-132 forms, all
  address rows). CLI-only assertions have no library equivalent and are not ported:
  exit codes, stderr wording, process-stream ASCII purity, `--dice-file`/`--dice`
  equivalence, and byte-identity of the rendered JSON document.
- Not ported: `cli_end_to_end.rs` (drives the executable; its corpus consumer became
  `fuzz_vectors.rs` above) and `page_vectors.rs` (desktop-only browser capture).

### Results (host: x86_64-pc-windows-msvc, rustc 1.96.0)

    cargo test:            72 passed, 0 failed, 1 ignored
      unit tests           49 passed  (entropy 8, bip39 15, derive 13, qr 6, report 7)
      tests/fuzz_vectors   2 passed   (10 positive + 4 negative corpus cases)
      tests/spec_vectors   21 passed, 1 ignored (same as desktop)
    cargo clippy --all-targets: clean, no warnings.

### Bare-metal no_std proof

    rustup target add riscv32imac-unknown-none-elf
    cargo check --target riscv32imac-unknown-none-elf --no-default-features

Passes (exit 0, whole graph checked including the cross-compiled secp256k1 C library).
`--no-default-features` drops only the `qr` feature, per item 4; everything
cryptographic - entropy, bip39, derive, report - is in the no_std build. The same check
WITH default features fails inside `qrcode` ("can't find crate for `std`"), which is the
direct proof the gate in item 4 is required and sufficient.

The check compiles the secp256k1 C library for riscv32, so cc-rs needs a RISC-V C
toolchain, named via environment when not on PATH (xPack GNU RISC-V Embedded GCC 15.2.0
was used here):

    CC_riscv32imac_unknown_none_elf  = ...\riscv-none-elf-gcc.exe
    AR_riscv32imac_unknown_none_elf  = ...\riscv-none-elf-ar.exe
    CFLAGS_riscv32imac_unknown_none_elf = -march=rv32imac_zicsr -mabi=ilp32

The firmware build gets its cross C toolchain from ESP-IDF anyway; this is only for the
standalone bare-metal proof.
