# Research: feature spec inputs (BigDice, SeedSigner, airgap I/O) (2026-08-17)

Agent-produced report. 0.1.0 scope decision on top of it: BigDice feature set (seed
generation/restore/export) + device verification; PSBT signing deferred to 0.2.x.

## 1. BigDice (github.com/intnsity/BigDice)

Offline Windows desktop (GUI + CLI) dice-to-BIP39 seed generator, GPL-3.0.
Features: dice rolls -> BIP39 mnemonic; reverse mode (enter mnemonic); BIP44/49/84/86 +
BIP48 multisig account keys; xpub/zpub (SLIP-132) export; QR display via --qr; BIP39
passphrase; private values masked by default. Security claims: deterministic, no OS
randomness on derivation path, no sockets; zeroize-on-drop memory hygiene; reproducible
builds (--locked, pinned toolchain, /Brepro, source-id hash); GPG-signed SHA256SUMS
(key fpr A1E9 53B2 5C6A 623B 77A1 D522 3AC4 BBCF E51A B37D); verified against BIP
vectors and differentially against iancoleman + Python bip-utils. Docs: SPEC.md
(normative), REFERENCE.md, EQUIVALENCE.md, LINEAGE.md.

## 2. SeedSigner (github.com/SeedSigner/seedsigner)

- Seed gen: dice (50 rolls = 12 words, 99 = 24), camera image entropy, manual word
  picking with final/checksum word calc.
- SeedQR (numeric 48/96 digits; 25x25/29x29) and CompactSeedQR (raw entropy binary;
  21x21/25x25); guided manual SeedQR transcription.
- PSBT signing: review flow verifies single-sig and multisig change/self-transfer;
  in via animated QR, out as animated QR. QR formats (docs/qr_formats.md): scan = BC
  UR2 crypto-psbt (fountain), Specter base64 segments, legacy UR (deprecated), static
  base64; display = UR2 + Specter base64. No BBQr.
- Multisig xpub export; address verification by scanning (camera-dependent); BIP39
  passphrase; custom derivation; message signing; BIP85.
- Stateless: seeds RAM-only; SD removable after boot; settings persistence opt-in
  (settings.json; seeds never persisted) - PR #240.
- Camera-dependent: image entropy + all scanning. Dice, manual entry, final-word calc,
  QR display do not need the camera.

## 3. Airgap I/O without a camera

- PSBT-in via microSD is the proven pattern:
  - Coldcard "Ready To Sign": coordinator saves tx-1.psbt (binary or base64, hex
    accepted) to SD; device auto-detects, reviews, signs, writes *-signed.psbt (+
    *-final.txn when finalizable); output encoding matches input.
    https://coldcard.com/docs/ready-to-sign/
  - Foundation Passport: manual file picker for .psbt on SD; signed file written back.
- Coordinators (Sparrow/Electrum/Specter) all do File > Save PSBT binary or base64.
- Manual touch entry impractical for PSBTs; fine for mnemonic restore.
- USB would work but breaks the airgap story; flashing/power only.
- Out: static QR for small payloads (xpub, address); animated BC-UR2 crypto-psbt for
  signed PSBTs; SD writeback of *-signed.psbt. Sparrow reads animated UR via webcam, so
  QR-out + SD-in is workable; SD both ways is lowest-friction.
  https://developer.blockchaincommons.com/ur/psbts/

## 4. Security architecture of stateless signers

- SeedSigner: nothing persisted; verification external (GPG-signed images, DIY
  hardware). No secure boot (stock Pi Zero).
- Coldcard: bootrom verifies firmware signature + flash every boot, Genuine/Caution
  light driven by SE-tied circuitry; anti-phishing words (device+PIN-prefix specific);
  bag-number supply chain; on-device firmware hash display.
  https://coldcard.com/resources/security/coldcard-security-and-verification
- BigDice's software analog: reproducible builds + signed manifests + differential
  verification; determinism lets users re-derive on a second tool.
- "Verify the device" features worth copying: firmware version + SHA256 on demand;
  boot self-test; deterministic dice math checkable against rolls.py / iancoleman;
  xpub cross-check flow against watch-only wallet.

## 5. Dice entropy math and the compatibility trap

- log2(6) = 2.585 bits/roll. 128 bits -> 50 rolls; 256 -> 99 (Coldcard and SeedSigner).
- Coldcard mapping: seed = SHA256(ASCII roll string, digits 1-6); 24-word = all 32
  bytes, 12-word = first 16. https://coldcard.com/docs/verifying-dice-roll-math/
- SeedSigner mapping: identical (sha256(roll_string).digest(), truncate 16 for 12w).
  Docs warn NOT compatible with iancoleman "dice" mode.
- BigDice mapping (docs/SPEC.md), two modes:
  - RAW (default): 6->0, prefix-free variable-length code (0-3 -> two bits, 4-5 -> one;
    ~1.67 bits/roll; ~77 rolls for 128-bit), last N bits kept, no hashing. Reproduces
    iancoleman dice/base-6 exactly (EQUIVALENCE.md).
  - FIXED: SHA256 over the filtered digit string (faces 1-6), first ENT bits.
- Conclusion: BigDice RAW and Coldcard/SeedSigner are different, incompatible mappings
  by design. BigDice FIXED appears algorithm-identical to Coldcard/SeedSigner math but
  neither project documents the equivalence - publish test vectors proving agreement
  for whichever mapping is canonical, and label the UI with which external tool
  cross-checks each mode.
- Debiasing: SHA256-of-rolls needs none; BigDice RAW's prefix-free code is unbiased per
  bit. Both sound; fixed-width truncation is the thing to avoid.

## Proposed v0.1 feature list from the agent (camera-less stateless signer)

MUST: stateless RAM-only seeds zeroized on exit; dice seed gen (both mappings, with
on-device roll-string hash display for external verification); seed restore via touch
keyboard + final-word calc; BIP39 passphrase; PSBT in/out via microSD (Coldcard
conventions) with full review flow; animated UR2 QR-out; xpub export (QR + SD);
receive-address display; firmware verifiability (reproducible build, signed hashes,
on-device firmware SHA256, boot self-test); deterministic (no HW RNG for keys).

SHOULD: multisig (BIP48 export, multisig PSBT, descriptor import); SeedQR/CompactSeedQR
display; message signing; opt-in non-sensitive settings on SD; dice quality aids
(histogram, thresholds).

WONT (v0.1): camera anything; USB data; seed storage/PIN; secure-element claims; BIP85;
altcoins; BBQr; legacy UR.

NOTE (orchestrator): PSBT items moved to 0.2.x for this project - 0.1.0 scope is the
BigDice feature set + verification, per plan.md ("implementation of BigDice" whose only
apps beyond it are device-security verification). The SD/QR format decisions above are
recorded so 0.1.0 designs don't foreclose them.

Key sources: github.com/intnsity/BigDice (README, docs/) - github.com/SeedSigner/
seedsigner (README, docs/qr_formats.md, docs/dice_verification.md,
helpers/mnemonic_generation.py) - coldcard.com/docs/ready-to-sign/ -
coldcard.com/docs/verifying-dice-roll-math/ - coldcard.com/resources/security/ -
docs.foundation.xyz/passport/ - developer.blockchaincommons.com/ur/psbts/
