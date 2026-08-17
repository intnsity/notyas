# Research: desktop BigDice codebase survey (2026-08-17)

Agent-produced survey of \\172.16.0.9\bear\code\btc\dice_generator (crate `bigdice`
v0.3.0, GPL-3.0-or-later, github.com/intnsity/BigDice). This is the porting map for
crates/bigdice-core.

## 1. What it does end to end

Single linear pipeline, "SPEC steps 1-9" in docs\SPEC.md, cited by step number in code.
- Dice path: raw text -> entropy::parse_dice (steps 1-3) -> bip39::mnemonic_from_dice
  (4-7) -> bip39::seed (8) -> derive::derive (9). Orchestrated in Report::build
  (src\report.rs:187).
- Phrase path: typed text -> bip39::normalize_phrase + advisory check_phrase ->
  bip39::seed -> derive::derive. Report::from_phrase (src\report.rs:235). Both converge
  at derive_all (src\report.rs:272).
- Derivation output: BIP32 root xprv/tprv, root fingerprint; per scheme: account node
  path + xprv/xpub (+ SLIP-132 yprv/ypub/zprv/zpub for BIP49/84 mainnet), N address
  rows (path | address | compressed pubkey | WIF). Schemes: BIP44 P2PKH, BIP49
  P2SH-P2WPKH, BIP84 P2WPKH, BIP86 P2TR key-path, BIP48 multisig account keys (4th
  hardened script_type level, no address rows) (src\derive.rs:309-338).
- **Signing: none.** No Transaction/Psbt/sighash anywhere.
- Invariant (asserted + tested): derivation path reads no OS randomness, clock, locale,
  env, socket. secp context never randomized (src\derive.rs:419-427).

## 2. Dependencies (Cargo.toml is heavily commented with rationale)

Features: default = ["cli"]; cli = ["dep:rpassword"]; gui = ["dep:eframe","dep:wgpu"].
Lib bigdice; bins bigdice-cli (cli), BigDice (gui). autobins = false.

| Dep | Version | Features |
|---|---|---|
| bitcoin | =0.32.102 exact | default-features = false, ["std"] |
| sha2 | 0.11 | default |
| hmac | 0.13 | default |
| pbkdf2 | 0.13 | default-features = false, ["hmac"] |
| unicode-normalization | 0.1 | default (NFKD) |
| qrcode | =0.14.1 exact | default-features = false (zero-edge) |
| zeroize | 1 | ["derive"] |
| rpassword | 7 | cli only |

GUI (windows): eframe =0.36.1 (accesskit, default_fonts, wgpu_no_default_features),
wgpu =30.0.0 (std, wgsl, dx12 - D3D12-only is load-bearing: WARP fallback).
Build-deps: sha2. Dev-deps: serde, serde_json, hex.
Profiles: dev package.* opt-level 2; release lto = true, codegen-units = 1, strip.
rust-toolchain.toml: channel 1.96.0 (rust-version floor 1.85).
.cargo\config.toml: +crt-static for windows-msvc; lib.rs:47-57 compile_error! guard.

## 3. Module map (src\)

| File | Lines | Responsibility / public surface |
|---|---|---|
| main.rs | 11 | bigdice-cli entry |
| lib.rs | 75 | crate docs, module decls, static-CRT guard |
| entropy.rs | 319 | SPEC 1-3. DiceEntropy (events/clean/binary/from_bits, Zeroize + ZeroizeOnDrop, redacting Debug), parse_dice |
| bip39.rs | 991 | SPEC 4-8. WORDLIST_LEN, MIN_SECURE_BITS(128), MAX_ENTROPY_BITS(8192), FIXED_WORD_COUNTS, WordCount, MnemonicMode{Raw,Words}, Mnemonic, Bip39Error, rolls_for_bits, wordlist, mnemonic_from_dice, raw_bits_used, seed, normalize_phrase, Checksum, PhraseCheck, check_phrase |
| derive.rs | 968 | SPEC 9. YPRV/YPUB/ZPRV/ZPUB, ChildIndex, Scheme, AccountKeys, AddressRow, Derived, root_xprv, root_fingerprint, derive |
| report.rs | 1157 | pipeline + hand-rolled JSON writer. SchemeReport, Report, Parameters, BuildError, build, from_phrase, effective_bits, capacity, json_document, render_json, hex_encode |
| qr.rs | 311 | QR gen only. QrError, matrix, ascii |
| build_info.rs | 67 | SOURCE_HASH (env! BIGDICE_SOURCE_HASH), version_line |
| cli.rs | 3208 | desktop-only. Hand-rolled args, interactive session, secret-audit harness (AUDIT_ARMED, cli.rs:2318) |
| gui\mod.rs | 2088 | egui window; masking rules gui\mod.rs:17-38; clipboard TTL 90s |
| gui\pipeline.rs | 283 | Inputs, Strength, compute; fixed-key FNV-1a cache (:42-61) |
| gui\theme.rs | 593 | Butter Paper tokens + widgets |
| wordlist_english.txt | 2048 words | sha256 2f5eed...dbda |

## 4. Entropy algorithm (SPEC 1-8)

- Step 1 (entropy.rs:112-136): scan bytes, keep [1-6], drop everything else silently
  (byte-wise safe for UTF-8). Order preserved, never sorted.
- Step 2: 1..5 unchanged, 6 -> 0. Typed 0 is noise (entropy.rs:206).
- Step 3 (entropy.rs:100): prefix-free variable-length code, NOT von Neumann:
  0->"00" 1->"01" 2->"10" 3->"11" 4->"0" 5->"1". Yield 5/3 bits per d6. Bit length
  depends on roll values. rolls_for_bits (bip39.rs:225) is the single 5/3 definition.
- Step 4 raw mode: bits_used = floor(len/32)*32, take the LAST bits_used bits
  (iancoleman-compatible; direction pinned by test). 0 -> NotEnoughEntropy.
- Step 5 fixed mode: SHA256(UTF-8 of clean digit chars), MSB-first, first 32*words/3
  bits (bip39.rs:314-325). Deterministic stretch, not entropy: effective_bits =
  min(bits_used, total) in Words mode (report.rs:302); all warnings use effective_bits.
- Step 6: pack MSB-first, 32-bit aligned.
- Step 7: generalized BIP39, checksum = first ENT/32 bits of SHA256(entropy), 11-bit
  groups, NO 24-word cap (MAX_ENTROPY_BITS = 8192). In-crate impl because published
  crates reject >256 bits.
- Step 8: PBKDF2-HMAC-SHA512, 2048 iters, 64 bytes; password = NFKD(phrase), salt =
  NFKD("mnemonic" + passphrase) - concatenation normalized, not parts (bip39.rs:398).
- Zero-roll refusal: Report::build rejects events == 0 (BuildError::NoRolls).
- Memory hygiene: every secret type has redacting Debug + zeroizing Drop (DiceEntropy,
  Mnemonic, PhraseCheck, AccountKeys, AddressRow, Report); SecretXpriv
  (derive.rs:438-453) wraps Xpriv and wipes key + chain code; buffers pre-sized from
  report::capacity to avoid stranded heap copies.

## 5. UI notes relevant to the device port

- Masking: fixed 24-bullet run so mask length never leaks secret length; mnemonic words
  and entropy hex masked; typed input not masked; passphrase behind opt-in + confirm;
  QR only on explicit click behind reveal gate.
- Butter Paper theme constants in gui\theme.rs:12-40 (CSS-token -> const map).
- Fonts: Inter subsets + renamed Source Serif 4 subset (OFL RFN rules); Georgia
  rejected as non-redistributable. LICENSE-fonts generated by tools\fonts\*.py.

## 6. Reproducibility and verification

- build.rs: BIGDICE_SOURCE_HASH = SHA256 over domain-tagged (b"bigdice-source-v1"),
  length-prefixed, path-sorted records of Cargo.toml/lock, build.rs, README, src/**,
  assets/**. Source identity, not a reproducibility claim.
- Repro recipe (README:586-601): signed tag, --locked, pinned toolchain, RUSTFLAGS
  +crt-static --remap-path-prefix ... -C link-arg=/Brepro.
- Releases: 4 files (2 exes, SHA256SUMS.txt, .asc), GPG key A1E9 53B2 5C6A 623B 77A1
  D522 3AC4 BBCF E51A B37D; git verify-tag.
- tools\verify.ps1: 24 cases, CLI --json vs GUI --selftest, byte-identity via SHA256.
- tools\qr_check.py: decodes exported matrices with zxing-cpp (independent impl).

## 7. Tests

111 unit tests in src\ + 56 in tests\. Key files:
- tests\spec_vectors.rs (800): BIP-32 vectors 1-5, BIP-39 Trezor vectors, BIP-49/84/86/
  44 vectors, SLIP-132 re-versioning. Vectors transcribed inline.
- tests\cli_end_to_end.rs (1828, 32 tests): differential vs fuzz_vectors.json
  (iancoleman + bip-utils, 224 cases/17890 fields); byte-identity vs 0.1.0 release
  output; dependency-graph invariants (:533, :578) - walk Cargo.lock and fail if
  getrandom/rand*/ring/tokio/socket/http crates reachable (CLI: zero; GUI: getrandom
  off-target only); also asserts secp256k1 present so the walk keeps proving something.
- tests\page_vectors.rs: pipeline vs headless capture of bip39-standalone.html 0.5.6.
- tests\vectors\: 6 JSON corpora (~600 KB), include_str!-embedded, shape-asserted.

## 8. no_std portability verdict

Portable with alloc + trivial import swaps:
- entropy.rs (319): only core::fmt + alloc strings. Cleanest.
- bip39.rs (991): sha2/hmac/pbkdf2/unicode-normalization all no_std+alloc capable;
  ONE blocker: std::sync::OnceLock wordlist cache (bip39.rs:12,235) -> const/static.
- derive.rs (968): bitcoin 0.32 is no_std+alloc capable (drop "std" feature);
  secp256k1 C lib cross-compiles on RISC-V; OnceLock secp context (derive.rs:12,425)
  -> static or explicit context.
- report.rs (1157): hand-rolled JSON, String-only, portable (may not be needed on
  device; effective_bits/capacity logic is the valuable part).
- qr.rs (311): qrcode 0.14.1 already dependency-free with default-features off; verify
  no_std; matrix() is the embedded-relevant primitive (no quiet zone by design).
- build_info.rs: portable.

Desktop-bound: cli.rs, gui\*, bins (~6570 lines) - replaced by device UI.

Practical split: entropy + bip39 (+ report logic) ~2470 lines move with minor edits;
derive 968 modulo secp build; qr 311 probably; two OnceLocks are the entire std-sync
surface of the core.
