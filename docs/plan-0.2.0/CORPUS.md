# notyas 0.2.0 - Test corpus and verification strategy

Status: PLAN, written 2026-08-17. Companion to plan-0.2.0/{ARCHITECTURE,SECURITY,UX,
PARITY,MILESTONES}.md and to the storage crate design in plan-0.2.0/ESP-SEAL.md
(written in parallel; every storage-fault hook named here is a request against that
file's harness surface). This document defines what 0.2.0 must PROVE about signing,
sealing and refusing, with what material, against what oracles, and where each test
runs.

---

## 0. The standard of proof, and why signing needs a harder one

0.1.0's credibility rests on a specific, reproducible discipline, and it is worth
naming precisely before extending it:

- Official BIP vectors transcribed from the specification texts themselves, inline,
  with the source URL beside every constant (crates/notyas-core/tests/spec_vectors.rs:
  BIP-32 vectors 1-5, BIP-39 Trezor vectors, BIP-44/49/84/86, SLIP-132).
- A differential campaign in which no expected value was written down until two
  implementations that share no code with us and no code with each other agreed on it
  (desktop BigDice tests/vectors/FUZZ_REPORT.md: 224 deterministic cases, oracle A =
  iancoleman's own entropy.js/jsbip39.js under node, oracle B = python bip-utils with
  the seed recomputed a third time through hashlib; 10 representative cases plus 4
  negative cases carried into this repo as crates/notyas-core/tests/vectors/
  fuzz_vectors.json).
- Byte-identity as the assertion of choice: same input, same bytes, forever, on host
  and in the on-device boot self-test.
- Refusals tested as first-class outputs, not as absence of success (the negative
  vectors assert the exact error value, not merely that something failed).

Signing raises the stakes in three ways that the generation corpus never had to face:

1. **The input is attacker-controlled.** A dice roll is typed by the owner. A PSBT
   arrives from a coordinator that may be compromised, over media the SECURITY.md
   threat model explicitly distrusts. Every historical hardware-wallet loss in the
   research came through this door, not through a bad BIP-39 implementation.
2. **The correct answer is often "no".** For generation, correctness is one value.
   For signing, correctness is a verdict plus a rendered explanation, and the
   dangerous failure mode is signing something valid-looking that the user did not
   intend. A corpus that only tests "we produce the right signature" tests the easy
   half.
3. **Byte-identity against the obvious reference is impossible.** The red-team pass
   established this (ARCHITECTURE 5.1, OPEN-QUESTIONS Q13) and section 3 below turns
   it into a positive strategy rather than a caveat.

The standard 0.2.0 must meet, stated as testable propositions:

| # | Proposition | Proved by |
|---|---|---|
| P1 | Our sighash for every input of every corpus case equals the value an independent implementation computes | section 3 layer 3 (hermetic) |
| P2 | Our signature bytes for every corpus case are frozen and never change without a reviewed diff | section 3 layer 1 (hermetic) |
| P3 | Everything we sign is accepted by Bitcoin Core as consensus- and policy-valid | section 3 layer 2 (node) |
| P4 | Every refusal gate refuses exactly what it claims to, and no gate is dead code | section 2.5 check-necessity matrix |
| P5 | Every refusal reason has a screen whose exact text is asserted, at both geometries | section 5 |
| P6 | No power-cut sequence in a sealed-storage operation yields garbage, a repeated nonce, a resurrected attempt, or a readable stale secret | section 4 |
| P7 | The device on real silicon agrees byte-for-byte with the host-frozen vectors | section 6 |
| P8 | We add signatures to a PSBT and nothing else | section 2.6 emission-delta test |

Everything below serves one of those eight.

---

## 1. Inventory: public test material that already exists

Rule of use, inherited from 0.1.0: material transcribed from a specification is
transcribed with its URL beside it; material vendored as a file records the upstream
commit hash and the fetch date in a sidecar. Nothing is "adapted" silently.

### 1.1 Signing and sighash known-answer vectors (the byte-identity layer)

| Material | Where | What it pins | Consumed as |
|---|---|---|---|
| BIP-340 Schnorr vectors, 19 rows, CSV with `aux_rand` column | https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv | BIP-340 sign and verify. Row 0 has `aux_rand` = 32 zero bytes, which is EXACTLY our no-aux path: libsecp256k1's `nonce_function_bip340` with `data == NULL` uses a precomputed `TaggedHash("BIP0340/aux", 0x00*32)` mask (https://github.com/bitcoin-core/secp256k1/blob/master/src/modules/schnorrsig/main_impl.h). So the zero-aux rows are direct KATs for our signer, not merely for the dependency | vendored CSV, host test |
| BIP-341 wallet test vectors | https://github.com/bitcoin/bips/blob/master/bip-0341/wallet-test-vectors.json ; mirrored in Core as `src/test/data/bip341_wallet_vectors.json` (https://github.com/bitcoin/bitcoin/blob/master/src/test/data/bip341_wallet_vectors.json) and in rust-bitcoin as `bitcoin/tests/data/bip341_tests.json` | taproot output-key tweak, script-tree merkle roots, key-path sighash for every SIGHASH type, control blocks | vendored JSON, host test |
| BIP-143 segwit v0 sighash vectors (inline in the BIP: P2WPKH, P2SH-P2WPKH, P2WSH, P2SH-P2WSH, plus the "no FindAndDelete" and SIGHASH_SINGLE cases) | https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki | segwit v0 sighash, including the historical amount-commitment change that check 2 exists to exploit-proof | transcribed inline, host test |
| Legacy sighash vectors | Core `src/test/data/sighash.json` (https://github.com/bitcoin/bitcoin/blob/master/src/test/data/sighash.json), same file as rust-bitcoin's `bitcoin/tests/data/legacy_sighash.json` | pre-segwit sighash including SIGHASH_SINGLE index overflow | vendored JSON, host test |
| BIP-342 tapscript semantics | not a committed file: Core generates `script_assets_test.json` from `test/functional/feature_taproot.py --dumptests` and consumes it in `src/test/script_tests.cpp` / `src/test/fuzz/script_assets_test_minimizer.cpp` | tapscript execution and signature-opcode semantics | out of 0.2.0 scope for signing (no script-path signing, Q7), but the generated file is the reference if 0.3.x adds it. Recorded so it is not rediscovered later |
| BIP-32/39/49/84/86, SLIP-132 | already in crates/notyas-core/tests/spec_vectors.rs | key derivation | unchanged, extended with `derive_path()` arbitrary-path cases in m2 |

### 1.2 PSBT format, role and rejection vectors

| Material | Where | What it pins |
|---|---|---|
| BIP-174 test vectors (invalid PSBTs, creator/updater/signer/combiner/finalizer/extractor role outputs) | https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki | the wire format and the role state machine |
| rust-bitcoin's BIP-174 harness and data (pinned version 0.32.x: `bitcoin/tests/bip_174.rs`, `bitcoin/tests/psbt-sign-taproot.rs`, and `bitcoin/tests/data/{create,update_1,update_2,sign_1,sign_2,combine,lex_combine,finalize,extract_tx}_psbt_hex`, `psbt_fuzz1.hex`, `psbt_fuzz2.hex`) | that our pinned dependency itself passes BIP-174. We do NOT re-run the dependency's suite as our own; we cite it and pin the version. What we DO run is the BIP's own vectors through OUR pipeline, which is a different assertion |
| Bitcoin Core `test/functional/data/rpc_psbt.json` (invalid, invalid-with-message, valid, creator/signer/combiner/finalizer/extractor sections) driven by `test/functional/rpc_psbt.py` | https://github.com/bitcoin/bitcoin/blob/master/test/functional/data/rpc_psbt.json | a second, independently curated invalid-PSBT set, including cases the BIP text does not carry |
| HWI `test/data/test_psbt.json` + `test/test_psbt.py` | https://github.com/bitcoin-core/HWI/blob/master/test/test_psbt.py | a third serialization suite, from a Python implementation with no shared code with rust-bitcoin |
| BIP-370 (PSBT v2, status Deployed) test vectors: invalid PSBTv0-carrying-v2-fields, invalid PSBTv2 missing required fields, invalid locktimes, valid PSBTv2s, locktime-determination cases | https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki | our v2 REFUSAL path. 0.2.0 is v0-only (ARCHITECTURE 5.2), so every BIP-370 valid vector must produce a clean "PSBT version 2 is not supported" refusal and every invalid one a clean parse refusal. Free, high-quality negative material |
| Bitcoin Core fuzz seed corpora `fuzz_corpora/{psbt, psbt_base64_decode, psbt_input_deserialize, psbt_output_deserialize}` | https://github.com/bitcoin-core/qa-assets | thousands of malformed PSBTs already minimized by OSS-Fuzz. Our parser-robustness fuzz target seeds from these directly. This is the single highest-value free artifact in the inventory |
| bitcoinjs-lib PSBT fixtures | https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/test/fixtures/psbt.json | a fourth independent set, JS lineage; used opportunistically for parser cases, not as an oracle |

### 1.3 Descriptor and multisig material

| Material | Where | Use |
|---|---|---|
| BIP-380/381/382/383/384/385 descriptor definitions and checksum algorithm | https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki | descriptor parse/serialize/checksum conformance |
| BIP-389 multipath `<0;1>` descriptors | https://github.com/bitcoin/bips/blob/master/bip-0389.mediawiki | the storage form ARCHITECTURE 4 chose |
| Core descriptor documentation and `src/test/descriptor_tests.cpp` | https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md | the practical descriptor conformance corpus; Core is the interop reference for `wsh(sortedmulti(...))` |
| Core `test/functional/wallet_multisig_descriptor_psbt.py` | https://github.com/bitcoin/bitcoin/blob/master/test/functional/wallet_multisig_descriptor_psbt.py | an end-to-end multisig PSBT round trip we can mirror in the node lane, using Core wallets as the other cosigners |
| Core `test/functional/data/rpc_bip67.json` | https://github.com/bitcoin/bitcoin/tree/master/test/functional/data | BIP-67 lexicographic key sorting, which is what `sortedmulti` means. A sorting bug produces a wrong address, not an error, so this needs explicit vectors |
| Coldcard multisig file format and examples (`ms-example.txt`, `ms-example-segwit.txt`) | https://coldcard.com/docs/multisig/ ; https://github.com/Coldcard/psbt_faker | the import dialect ARCHITECTURE 4 accepts |
| BIP-129 BSMS | https://github.com/bitcoin/bips/blob/master/bip-0129.mediawiki | deferred (Q6); vectors recorded for the 0.2.x/0.3.x revisit |

### 1.4 Published wallet-interop corpora

**HWI is the most relevant single artifact in this inventory and deserves its own
paragraph.** HWI (MIT, https://github.com/bitcoin-core/HWI) ships a device-agnostic
test suite in `test/test_device.py`: `TestDeviceConnect`, `TestGetKeypool`,
`TestGetDescriptors`, `TestSignTx`, `TestDisplayAddress`, `TestSignMessage`,
`TestRegisterDescriptor`. Per-device files (`test_coldcard.py`, `test_trezor.py`,
`test_jade.py`, `test_bitbox02.py`, ...) do nothing but parameterize those classes
against a device or its simulator. `TestSignTx` is driven by `signtx_cases`, a list of
(address types, multisig types, external-input flag, OP_RETURN flag) tuples covering
P2PKH, P2SH-P2WPKH, P2WPKH, P2TR and 2-of-3 multisig in legacy and segwit forms, and
the harness spins a real `bitcoind` regtest (mining 101 blocks, funding the cases,
checking the signed result). That is a ready-made, externally maintained conformance
suite for exactly the device class we are building.

- DECISION: we treat the HWI device-agnostic suite as a **target to become
  runnable against notyas**, not as something to copy. Two consequences for 0.2.0:
  (a) our node lane (section 3, layer 2) mirrors the `signtx_cases` matrix so we get
  the same coverage without depending on HWI's plumbing; (b) we do NOT write an HWI
  device driver for 0.2.0, because HWI drivers assume a USB transport and notyas has
  no USB data path by design (SECURITY.md). Revisit when/if an SD- or QR-transport
  HWI backend exists. Recording this now prevents "just add HWI support" from being
  proposed as a testing shortcut that would breach the USB posture.
- The HWI **simulators** it tests against (Trezor emulator, Jade emulator, Coldcard
  simulator) are also usable as differential cosigners in a multisig ceremony. Lower
  priority than Core; recorded as an option for m7.

Coldcard's own material, all MIT or public:

- `Coldcard/firmware/testing/` - `test_sign.py`, `test_multisig.py`, `test_attended.py`
  plus `testing/data/` with 54 files of which 37 are `.psbt`, including
  `2-of-2.psbt`, `multisig-single.psbt`, `p2pkh+p2sh+outs.psbt`,
  `p2pkh-p2sh-p2wpkh.psbt`, `p2sh_p2wpkh.psbt`, `filled_scriptsig.psbt`,
  `failed-ex.psbt` and a set of `worked-*.psbt`. Real files from a shipping signer, in
  the exact SD conventions we adopted. https://github.com/Coldcard/firmware/tree/master/testing
- `Coldcard/psbt_faker` (MIT, https://github.com/Coldcard/psbt_faker) - "create test
  PSBT files which are valid, but garbage values", with Coldcard-format multisig
  config examples. Directly reusable as a corpus generator input and as prior art for
  the generator design in section 2.
- Coldcard's published historical disclosures are the source of the attack classes in
  section 2.4: https://coinkite.com/historical-disclosures ,
  https://benma.github.io/2021/02/09/coldcard-multisig-vulnerability.html ,
  https://benma.github.io/2020/11/24/coldcard-isolation-bypass.html
- Trezor's 2020 segwit fee-attack writeup: https://blog.trezor.io/details-of-firmware-updates-for-trezor-one-version-1-9-1-and-trezor-model-t-version-2-3-1-1eba8f60f2dd

### 1.5 Independent implementations available as oracles

| Implementation | Language / lineage | License | Covers | Role here |
|---|---|---|---|---|
| Bitcoin Core (regtest) | C++ | MIT | consensus + policy acceptance, PSBT roles, descriptors, `descriptorprocesspsbt` signing without wallet import (https://bitcoincore.org/en/doc/27.0.0/rpc/rawtransactions/descriptorprocesspsbt/) | the acceptance oracle (layer 2) |
| `hwilib` (HWI's own Python PSBT/descriptor implementation) | Python | MIT | PSBT parse/serialize, sighash, descriptors | serialization + sighash oracle (layer 3) |
| `embit` | Python / MicroPython, used by SeedSigner, Krux and Specter DIY | MIT (https://github.com/diybitcoinhardware/embit) | PSBT v0/v2, descriptors, miniscript, taproot key-path, custom sighash flags | sighash + descriptor oracle (layer 3). Embedded-signer lineage, so it is the closest analogue to what we are building and shares no code with rust-bitcoin |
| `bip-utils` + `iancoleman` JS | Python / JS | MIT | BIP-32/39 derivation | unchanged from 0.1.0; still the derivation oracles |
| `corepc-node` 0.12 (rust-bitcoin's regtest launcher, ex-`bitcoind` crate) | Rust | CC0/MIT | spawning a pinned bitcoind from a Rust test, the same mechanism rust-miniscript's `bitcoind-tests/` uses | node-lane plumbing, not an oracle |

- DECISION: two independent oracles for the hermetic layer (`hwilib` and `embit`),
  not one. The 0.1.0 rule was that no expected value is written down until two
  implementations that share no code agree; signing does not get a weaker rule.
  Where the two disagree, generation aborts and a human reads the spec - exactly the
  desktop FUZZ_REPORT.md discipline.

---

## 2. The corpus we build

### 2.1 Two corpora, because they answer different questions

The single most important structural decision in this document:

- **Corpus A - hermetic, committed, byte-frozen.** Synthetic funding transactions,
  deterministic bytes, no node, no chain. Answers: does the policy engine reach the
  right verdict, is the sighash right, are the signature bytes stable, is the refusal
  screen right, does the parser survive hostile input. This is what runs on every
  push, on a laptop, offline, in seconds.
- **Corpus B - chain-anchored, generated at test time, never committed.** Built
  inside a fresh regtest by the differential harness: mine to our descriptors,
  `createpsbt` with explicit inputs, sign, `finalizepsbt`, `testmempoolaccept`.
  Answers: would the network actually accept this. Its inputs are chain-dependent
  (block hashes, coinbase txids), so committing it would be committing noise; the
  harness and its assertions are committed instead.

Anything that can be asserted hermetically is asserted in corpus A. The node lane
exists for the one question a hermetic test cannot answer.

### 2.2 Generation must not share code with the implementation under test

A corpus generated with rust-bitcoin and consumed by a signer built on rust-bitcoin
proves that the library agrees with itself. Worse, a hostile PSBT round-tripped
through rust-bitcoin's serializer is silently NORMALIZED: field ordering fixed,
unknown keys reordered, malformed lengths rejected before they ever reach us. The
attack we most need to test is the one whose bytes never survive our own writer.

Therefore:

- **Bases** (well-formed PSBTs for each script type and wallet shape) are produced by
  Bitcoin Core RPC where a node is available, and otherwise by a small Python builder
  over `embit`/`hwilib`. Never by rust-bitcoin.
- **Mutations** (the adversarial corpus) are byte- and field-level surgery applied by
  a Python mutator that writes PSBT key-value pairs directly. A mutator may emit bytes
  no serializer would produce; that is the point.
- **Committed artifacts are bytes.** Once a case file exists, the generator is needed
  only to prove reproducibility, never to run a test. CI does not generate.
- The generator is Python despite the house Rust preference. Justified: independence
  from the implementation under test outranks language uniformity for test-material
  production, the oracles (`embit`, `hwilib`) are Python, and this code is never
  shipped, never linked, and never runs on the device. The harness that ORCHESTRATES
  the node lane is Rust (`corepc-node`), because it only spawns and compares.

### 2.3 Determinism without randomness

The desktop campaign seeded `python random.Random(20260813)`. For 0.2.0 we go one
step stricter, matching the device's own doctrine (SECURITY.md invariant 3): the
generator uses **no RNG at all**. Every value that needs to look arbitrary - foreign
prevout txids, foreign pubkeys, amounts, output ordering - is derived from a
domain-separated hash chain:

```
value(case_id, field, n) = SHA256("notyas-corpus-v1" || case_id || field || n)
```

Consequences worth having: the corpus regenerates byte-identically on any machine and
any Python version (no dependence on Mersenne Twister behaviour surviving an
interpreter upgrade), a case id is a complete description of its own inputs, and
"regenerate and diff" is a meaningful release gate.

Key material rule: every corpus wallet derives from one of exactly three PUBLISHED
test mnemonics (the BIP-39 all-zero `abandon ... about` vector, the all-ones
`zoo ... wrong` vector, and one further Trezor vector for the third cosigner). The
generator refuses to emit a case whose seed is not on that list, and a CI lint
re-checks the committed corpus for the same property. No corpus artifact can ever be
mistaken for, or become, a real wallet.

Network rule: mainnet cases use only the `abandon` wallet (public, funds-free) and
exist for address-rendering and network-isolation tests; everything else is testnet or
regtest.

### 2.4 Corpus A layout

```
crates/notyas-wallet/tests/corpus/
  manifest.json              generator version, oracle versions, case index, per-case
                             oracle attestations (which two agreed, on what)
  wallets/*.json             wallet definitions: descriptor(s), mnemonic id, network,
                             registration records for multisig
  positive/<id>.psbt         raw PSBT bytes
  positive/<id>.json         sidecar: description, expected verdict, expected review
                             rows, expected warnings, provenance
  adversarial/<id>.psbt      raw PSBT bytes
  adversarial/<id>.json      sidecar: mutation, attack class + citation, expected
                             refusal reason code, ARCHITECTURE 5.3 check number
  frozen/sighashes.json      per case, per input: the sighash, attested by two oracles
  frozen/signatures.json     per case, per input: our signature bytes (see 3.1)
tools/corpus/                the Python generator: gen | verify | mutate | report
tools/differential/          the Rust node-lane harness (corepc-node)
```

Raw `.psbt` files plus JSON sidecars, not one monolithic JSON: the bytes stay
inspectable with any tool, and any other signer project can consume the adversarial
set directly. Size budget: roughly 40 authored positive cases plus roughly 200
generated adversarial cases at a few KB each is under 1 MB. The generator refuses to
emit a corpus over 5 MB; the oversized/DoS cases (section 2.4, group X) are
constructed at test time rather than committed.

#### Positive groups

| Group | Cases | What each is for |
|---|---|---|
| P1 single-sig P2WPKH | 1-in/2-out (send + change), 2-in/2-out, 1-in/1-out (no change), self-send (all outputs ours), consolidation (20 ours-in/1-out) | the common path; change classification; the no-change and all-change UI edges |
| P2 single-sig P2SH-P2WPKH | 1-in/2-out, 2-in/2-out | nested segwit redeem-script handling |
| P3 single-sig P2PKH | 1-in/2-out | legacy sighash path, and the strictest `non_witness_utxo` requirement |
| P4 single-sig P2TR key-path | SIGHASH_DEFAULT (64-byte sig) and explicit SIGHASH_ALL (65-byte sig) variants; 1-in and 3-in | the two taproot signature lengths are a classic off-by-one; both must be produced and both must be accepted |
| P5 multisig P2WSH sortedmulti | 1-of-2, 2-of-2, 2-of-3, 3-of-5, and the declared upper bound N (plus one case at N+1 that must be refused) | threshold arithmetic, BIP-67 sorting, registry bounds |
| P6 partial-signature states | PSBT already carrying cosigner 1's signature (we add ours, theirs preserved byte-exact); PSBT where our signature completes the threshold (finalize + extract, `-final.txn` emitted) | the two multisig ceremonies; the finalize-when-complete rule |
| P7 mixed-input | P2WPKH + P2SH-P2WPKH + P2TR + one foreign input in one transaction | per-input sighash dispatch; foreign-input display; fee attribution |
| P8 output-shape edges | 30-output batch; OP_RETURN with payload; 1-sat and dust-threshold outputs; an output paying a bare/unknown witness program | the review-paging and fatigue-overview rules (UX 10c), and the "never silently skip a non-address output" rule (UX 10a) |
| P9 transaction-field edges | nonzero nLockTime; non-final sequences (RBF signalling); tx version 2 and 3 | the fee-page disclosures UX 10b requires |
| P10 fee edges | exactly at the warn threshold, one sat over, one sat under (Q12 constants) | that a policy constant is a constant and not a rounding accident |

#### Adversarial groups

Section 2.5 lists them case by case, because each is a named attack.

#### Group X, constructed at test time

Oversized PSBT above the accepted cap, a PSBT with a 10 MB `non_witness_utxo`, a
PSBT with 10,000 inputs. These exist to prove bounded memory and a clean refusal; they
are generated in the test rather than committed so the repository does not carry
megabytes of hostile filler.

### 2.5 The adversarial corpus

Every case names the attack class it represents, the ARCHITECTURE 5.3 check that must
catch it, and the exact expected outcome. Reason codes (`RejectReason` variants in
notyas-wallet) are given in the last column and are normative for the enum.

**Mutators, not hand-written files.** Each row below is implemented as a MUTATOR - a
function from (base case, parameters) to a hostile PSBT - and applied to every
positive base for which it is meaningful. Twelve bases times roughly eighteen
applicable mutators gives around 200 adversarial cases from a small amount of authored
material, and every future script type inherits the whole attack battery automatically.
This is the difference between a corpus that ages well and a directory of one-off
files.

| id | Mutation | Attack class and precedent | Check | Expected |
|---|---|---|---|---|
| A1 | Drop `non_witness_utxo`, leave only `witness_utxo`, on a segwit-v0 input | BIP-143 amount-lie fee attack; Trezor 1.9.1 / 2.3.1 (https://blog.trezor.io/details-of-firmware-updates-for-trezor-one-version-1-9-1-and-trezor-model-t-version-2-3-1-1eba8f60f2dd) | 2 | Reject `MissingPrevTx` |
| A2 | Keep both, make `witness_utxo.value` disagree with the prev-tx output | same family, direct amount substitution | 2 | Reject `PrevoutAmountMismatch` |
| A3 | Substitute a `non_witness_utxo` whose txid is not the input's prevout txid | prev-tx substitution | 2 | Reject `PrevTxMismatch` |
| A4 | Point the input at a valid prev-tx but a different output index | prevout index confusion | 2 | Reject `PrevoutIndexMismatch` |
| A5 | Change output whose `script_pubkey` is NOT what our descriptor derives at the claimed index | fake change / theft-as-change; Coldcard 2019 change-path issue (https://coinkite.com/historical-disclosures) | 3 | Reject `ChangeNotDerivable`; UI must show it as EXTERNAL if signing proceeds under an override |
| A6 | Change at an index far beyond the gap bound (100000) | change-path ransom: funds land where the user's wallet will never scan | 3 | Reject `ChangeIndexOutOfRange` |
| A7 | Owned output on the EXTERNAL keychain declared as change | change/receive confusion | 3 | Approve, but tagged OWN (receive), never CHANGE; ScreenModel asserted |
| A8 | `bip32_derivation` claims our 4-byte fingerprint with a foreign xpub | fingerprint spoofing (4 bytes are trivially collidable, so a claimed origin is not evidence) | 1 | Approve-with-EXTERNAL: the output must NOT be classified as ours. Asserts classification is derivation-based, not claim-based |
| A9 | Multisig change built from the registered descriptor with ONE cosigner xpub replaced | Coldcard 2021 xpub substitution (https://benma.github.io/2021/02/09/coldcard-multisig-vulnerability.html) | 4 | Reject `ChangeNotInRegistration` |
| A10 | Valid-looking multisig PSBT for a wallet that was never registered | same family, one step earlier | 4 | Reject `NoRegistration` (stateless-mode behaviour per Q11) |
| A11 | Registration says 2-of-3, the PSBT's witness script is 1-of-3 | threshold downgrade | 4 | Reject `ScriptNotInRegistration` |
| A12 | `multi()` key order where the registration says `sortedmulti()` | sorting/format confusion; different address, same keys | 4 | Reject `ScriptNotInRegistration` |
| A13 | P2SH-P2WSH multisig (out of 0.2.0 scope) | unsupported-shape handling | 9 | Reject `UnsupportedScriptType`, in plain words, never a panic |
| A14 | Mainnet wallet, testnet coin_type in the origins and testnet output addresses | Coldcard isolation bypass 2020 (https://benma.github.io/2020/11/24/coldcard-isolation-bypass.html) | 5 | Reject `NetworkMismatch` |
| A15 | Testnet wallet, mainnet outputs | same, reversed | 5 | Reject `NetworkMismatch` |
| A16 | Fee = 50% of the sent value | fee burn / griefing | 6 | Warn or reject per Q12; exact screen asserted either way |
| A17 | Outputs exceed inputs | negative fee, only detectable with validated prevouts | 6 | Reject `NegativeFee` |
| A18 | Amounts summing past MAX_MONEY / near u64 overflow | integer-overflow in fee arithmetic, a classic wallet bug | 6/9 | Reject `AmountOutOfRange`, with no wrap and no panic |
| A19 | SIGHASH_SINGLE on an input with no output at the same index | the SIGHASH_SINGLE bug; output substitution | 7 | Reject `SighashNotAllowed` |
| A20 | SIGHASH_NONE | outputs freely replaceable after signing | 7 | Reject `SighashNotAllowed` |
| A21 | SIGHASH_ALL \| ANYONECANPAY | input-set mutation, fee inflation by a third party adding inputs | 7 | Reject `SighashNotAllowed` (expert gate only) |
| A22 | Different sighash types across inputs of one tx | partial-authorization confusion | 7/9 | Reject `SighashNotAllowed` |
| A23 | Taproot input carrying an annex | BIP-341 leaves annex semantics undefined: signing over unknown data | 8 | Reject `UnknownAnnex` |
| A24 | Taproot input with a `tap_leaf_script` not present in any registration | signing under an attacker-chosen script | 8 | Reject `LeafNotRegistered` |
| A25 | Taproot output key inconsistent with the claimed internal key and merkle root | key substitution / wrong tweak | 8 | Reject `TaprootTweakMismatch` |
| A26 | Same outpoint appears twice as an input | malformed input set; double-count fee bugs | 9 | Reject `DuplicateInput` |
| A27 | Input already carrying `final_scriptWitness` | re-sign / replay confusion | 9 | Reject or skip-with-notice; screen asserted |
| A28 | An input we cannot classify (foreign, no origin info) | "you are paying someone else's fee" / hostile coinjoin shape | 9 | Approve, with the input rendered explicitly as FOREIGN and the fee attribution shown. Display requirement, not a refusal |
| A29 | Derivation path with absurd depth, or a non-whitelisted purpose (`m/1234'/0'/0'`) | path-sanity escape | 1 | Reject `PathNotSane` |
| A30 | Truncation at every PSBT key-value boundary of a valid case | parser robustness / DoS | 9 | Reject `Parse`, never a panic, bounded allocation |
| A31 | Byte flips inside key-value lengths and type bytes | parser robustness | 9 | Reject `Parse` |
| A32 | Unknown global/input/output fields and proprietary keys | must be preserved untouched and never trusted | 9 | Approve, and the emission-delta test (2.6) proves the fields survive byte-exact |
| A33 | Every BIP-370 valid PSBTv2 vector | version handling | 9 | Reject `UnsupportedPsbtVersion` with the plain-words screen |
| A34 | Output address sharing a 6-char prefix and 6-char suffix with one of our own change addresses | address poisoning (https://arxiv.org/abs/2501.16681) | UX 1 | Approve; the test asserts the FULL address is rendered chunked and that the two addresses are visually distinguishable in the rendered frame. See OPEN (corpus-4) for the proposed warning |
| A35 | PSBT whose inputs belong to a DIFFERENT stored wallet | first-timer dead end (UX 9 red-team addition) | 1 | Reject `WrongWallet`, naming the stored wallet that does match |
| A36 | Oversized PSBT above the cap; 10 MB `non_witness_utxo` | memory-exhaustion DoS | 9 | Reject `TooLarge` before allocating; peak allocation asserted bounded |
| A37 | Faulted-digest signing (test-only hook corrupts the sighash between validation and signing) | fault-injection nonce-reuse key extraction, the accepted risk of deterministic nonces (ARCHITECTURE 2.4) | 10 | The post-sign gate MUST catch it. Nothing leaves the device |
| A38 | Corrupt one byte of a produced signature before emission | same gate, different fault site | 10 | Post-sign gate catches it |

Two properties of this table are themselves tested:

- **Reason-code exhaustiveness.** A CI test asserts that every `RejectReason` variant
  appears as the expected outcome of at least one corpus case, and that every
  expected outcome in the corpus is a real variant. A refusal reason with no case is
  either untested or unreachable, and both are defects.
- **Check necessity (the strongest structural claim in this document).** For each of
  the ten ARCHITECTURE 5.3 checks, a `#[cfg(test)]`-only `Policy::without(check)`
  disables exactly that check, and the harness asserts that at least one corpus case
  flips from Reject to Approve. This proves every check is load-bearing and that each
  case is gated by the check it claims, rather than being caught incidentally by
  another. The `without()` API exists only under `cfg(test)`; a release gate asserts
  the symbol is absent from the shipped binary.

### 2.6 Corpus-wide invariants, asserted over every case

Beyond the per-case verdict, five properties are asserted on every case in the corpus.
These catch the class of bug that no single case is written for.

1. **Emission delta (P8).** Diff the input PSBT against our output. The only permitted
   additions are `partial_sigs` / `tap_key_sig` (plus finalized fields when we
   finalize). Every other key-value pair, including unknown and proprietary ones, must
   be byte-identical and in the same order. "We add signatures and nothing else" is
   thereby a mechanical statement.
2. **No-panic, bounded-allocation.** Every case runs under a counting allocator; peak
   allocation must stay under the declared device budget, and no case may panic.
   Running the corpus through a no_std-shaped allocation budget on the host is the
   cheapest available proxy for the device's RAM ceiling.
3. **Determinism.** Every case is evaluated and signed twice in the same process and
   once in a fresh process; all three must agree byte-for-byte. This is the
   already-proven uisim discipline ("render twice, refuse on divergence") applied to
   signing.
4. **Secret hygiene.** After each case, the harness scans the process's returned
   artifacts and the ScreenModel for the test seed bytes, the derived xprv and any
   private key material. Zero occurrences permitted. (The 0.1.0 masking tests do the
   pixel-level version of this; here it is the data-level version.)
5. **Refusal completeness.** Every Reject case must produce a screen with a reason
   string, an explanation and at least one exit region (section 5). A refusal with no
   way out is a defect even though the refusal itself is correct.

---

## 3. Differential strategy, and the verdict on byte-identity

### 3.0 The verdict, stated plainly

**Byte-identical signatures against Bitcoin Core are impossible in general and we do
not claim them.** Two independent reasons, both verified against source:

- Core signs BIP-341 with random aux-rand; its Schnorr signature over the same input
  differs run to run by design.
- Core grinds ECDSA nonces for low-R (71-byte DER) signatures; plain RFC6979, which is
  what `Psbt::sign` produces, yields a high-R signature roughly half the time.
  (Confirmed in the pinned dependency: rust-bitcoin 0.32.x `Psbt::sign` calls
  `secp.sign_ecdsa(...)` for ECDSA and `secp.sign_schnorr_no_aux_rand(...)` for taproot
  when the `rand` feature is off - https://github.com/rust-bitcoin/rust-bitcoin/blob/bitcoin-0.32.5/bitcoin/src/psbt/mod.rs .)

Even with low-R grinding adopted, WHOLE-PSBT byte-identity against Core remains
unachievable, because Core adds, keeps and orders PSBT fields differently. The correct
comparison granularity is the signature bytes of an individual input, never the
serialized PSBT.

The strategy that replaces the impossible claim has three layers, and the key insight
is that **the differential moves to the sighash**, which is consensus-defined and
therefore identical across every correct implementation, while the signature is
compared against frozen vectors instead.

### 3.1 Layer 1 - byte-identity against pinned vectors (hermetic, every push)

- The published KATs of section 1.1, run through OUR stack: BIP-340 zero-aux rows,
  BIP-341 wallet vectors, BIP-143 vectors, legacy `sighash.json`.
- **Frozen signature vectors.** Because our signing is fully deterministic (RFC6979
  ECDSA, no-aux BIP-340 Schnorr, no RNG anywhere in the graph - SECURITY.md invariant
  3), every corpus case has exactly one correct signature byte string, forever. Those
  bytes are generated once, reviewed, and committed as `frozen/signatures.json`. CI
  compares and NEVER regenerates. A dependency bump that changes one byte of one
  signature shows up as a reviewable diff, which is precisely what we want to see.
- The same file is the source for the on-device signing known-answer check in the boot
  self-test (a small pinned subset that fits the 1 s budget) and for the HIL agreement
  test in section 6.

This layer needs no node, no network, and runs in seconds. It is the layer that
carries invariant 4.

### 3.2 Layer 2 - "Core verifies and accepts" (node lane)

Corpus B, inside a fresh regtest spawned by `corepc-node` from a Rust test:

1. Import our wallet descriptors into Core as watch-only (`importdescriptors`), mine
   to them, and build the PSBT with `createpsbt` over explicit inputs plus
   `utxoupdatepsbt` (explicit inputs, not `walletcreatefundedpsbt`, so coin selection
   randomness never enters).
2. We sign.
3. Core `analyzepsbt` must report the expected next role; `finalizepsbt` must
   finalize; `testmempoolaccept` (with `maxfeerate=0` so a deliberate high-fee case is
   not rejected for the wrong reason) must return `allowed: true`.
4. For multisig, Core is the other cosigner: `descriptorprocesspsbt` signs with the
   cosigner descriptors, in both orders (Core first then us, us first then Core), and
   both orders must finalize to the same transaction.
5. Mirror of the HWI `signtx_cases` matrix (section 1.4): legacy, sh_wit, wit, tap,
   legacy multisig, segwit multisig, with and without an external input, with and
   without an OP_RETURN output.
6. If Q13 adopts low-R grinding, this layer gains a byte comparison for ECDSA inputs:
   our signature bytes must equal Core's `walletprocesspsbt` output for the same input
   and key. That upgrade converts a semantic check into a byte check for the most
   common script types and is the main technical argument for adopting Q13's
   recommendation.

Pinning: the bitcoind version is pinned by release tag AND SHA256 in the harness, and
recorded in the corpus report. An unpinned node turns a differential into a rumour.

### 3.3 Layer 3 - cross-implementation self-consistency (hermetic, every push)

For every corpus-A case and every input:

- The **sighash** we compute must equal the sighash `embit` computes and the sighash
  `hwilib` computes. All three are byte-comparable for every script type and every
  sighash flag, with no randomness anywhere. The two oracle values are committed in
  `frozen/sighashes.json` with tool versions, so CI is hermetic; a nightly job
  re-derives them from the live oracles and fails on drift.
- Our signature must VERIFY under an independent verifier (the oracle's own secp
  binding), which catches the class of bug where we sign the right digest with the
  wrong key or the right key over the wrong digest.
- Descriptor derivation: for each wallet, the first 20 receive and 20 change
  `script_pubkey`s must match what Core's `deriveaddresses` and `embit` derive. This
  is the multisig `sortedmulti` sorting check in practice, and it is where a BIP-67
  bug would surface.

### 3.4 What runs where

| Lane | Trigger | Contents | Budget |
|---|---|---|---|
| A: host, hermetic | every push, offline | corpus A verdicts, layer 1 KATs and frozen vectors, layer 3 frozen oracle values, emission-delta, allocation bounds, refusal-text goldens, UI autopilot, storage power-loss fuzz (bounded iterations), build-graph check | under 5 minutes; no network access permitted, enforced |
| B: node | PRs touching notyas-core/notyas-wallet, plus nightly | corpus B, layer 2 acceptance, Core-as-cosigner, `deriveaddresses` cross-check | pinned bitcoind in a container; under 20 minutes |
| C: hardware | milestone close and release | section 6 | manual trigger, self-hosted runner |
| D: nightly fuzz | nightly | cargo-fuzz over the PSBT parser seeded from qa-assets `fuzz_corpora/psbt*`, the mutator space, and the storage fault tree at high iteration counts | time-boxed; new crashes are auto-filed with the minimized input |

Lane A having NO network access is itself a test: it proves the hermetic corpus is
really hermetic and that no test silently depends on fetching a vector.

---

## 4. Storage and power-loss testing

Coordinated by name with plan-0.2.0/ESP-SEAL.md, which owns the crate and its fault
harness; this section states what the corpus/verification side needs from it and what
invariants the notyas-wallet tests assert. Where the two documents disagree, ESP-SEAL.md
governs the interface and this document governs the assertions.

### 4.1 The fault model

A host-side `FaultingFlash` implementing the Storage trait, with NOR semantics modelled
honestly rather than as a byte array:

- erase sets a sector to 0xFF; program can only clear bits (1 -> 0), never set them;
- program granularity and sector size come from the real device geometry (4 KiB
  sectors), and the `wallets` partition additionally enforces the XTS constraint that
  writes are 16-byte aligned and 16 bytes minimum and that individual bits of an
  already-written region cannot be reprogrammed
  (https://docs.espressif.com/projects/esp-idf/en/v5.5/esp32p4/security/flash-encryption.html);
  the `counters` partition allows bit-clear programming, which is exactly why
  ARCHITECTURE 2.5 put it in its own plaintext partition;
- a torn write is NOT assumed prefix-clean: the model emits (a) the prefix only,
  (b) the prefix plus a partially programmed trailing word, and (c) the prefix plus
  trailing garbage, because real flash does all three;
- a torn erase leaves a partially erased sector, modelled as a small deterministic
  set of bit patterns rather than a random one.

### 4.2 The fuzzer

Exhaustive over step boundaries, not sampled: for every esp-seal operation (first
seal, re-seal, unseal, counter decrement, counter clear, PIN change with its
re-seal-then-erase-stale sequence, wallet delete, wipe-on-N, mount/recovery), the
harness enumerates every flash operation the implementation issues and, for each,
cuts power before it, after it, and at every torn-write variant within it. Then it
remounts and asserts. Because the operation set is small and the cut points are
enumerable, this is a complete tree at the step granularity, not a random walk;
byte-offset variants inside large writes are sampled deterministically by the hash
chain of 2.3 and swept fully in the nightly lane.

### 4.3 The invariants asserted after every cut

| # | Invariant | Why it is the one that matters |
|---|---|---|
| S1 | `mount()` returns the previously committed record or the newly written one, never garbage, never a partial mix, never a panic | the base A/B commit property (ARCHITECTURE 2.6) |
| S2 | Remaining attempts never increase across a cut | fail-closed. A cut during a decrement that restores an attempt is a free brute-force oracle |
| S3 | No (key, nonce) pair is ever emitted twice anywhere in the entire fault tree | THE invariant the no-RNG decision rests on (ARCHITECTURE 2.4). A global observer records every pair the ladder produces across the whole run and fails on the first duplicate. Nonce reuse in ChaCha20-Poly1305 is catastrophic, and determinism means we cannot fall back on randomness to save us |
| S4 | `wipe_epoch` is monotonic and one-way; a post-wipe re-save under the same PIN and slot derives a different key than the pre-wipe record did | closes the snapshot/keystream-reuse hole 2.2 identified |
| S5 | After a completed PIN change (and after any cut followed by remount and cleanup), no sector in the image decrypts under the OLD PIN | the stale-ciphertext rule of ARCHITECTURE 2.6. Tested by brute-attempting the old PIN against every sector, not by trusting the erase call |
| S6 | At no point in the fault tree do the plaintext entropy bytes, the derived seed, or any xprv appear anywhere in the simulated flash image | cheap, absolute, and catches an entire class of "I only meant to buffer it" bugs |
| S7 | `mount()` is idempotent and converges: mounting a recovered image twice yields identical state and issues no further writes | prevents a recovery path that rewrites on every boot and wears the flash |
| S8 | Write amplification per operation is bounded by a declared constant | a recovery loop that writes unboundedly is a denial of service against a device with finite flash endurance |
| S9 | Seal, unseal and mount are constant in their control flow with respect to PIN correctness, up to the deliberate counter decrement | no timing oracle beyond the one the design admits |

S3, S5 and S6 are the three that a naive "does it still boot" fuzzer would miss, and
they are the three whose failure would be unrecoverable in the field.

### 4.4 Known-answer vectors for the ladder

Separate from the fuzzer and equally required: pinned KATs for Argon2id (RFC 9106
vectors plus our own pinned-parameter vector), HKDF-SHA256 (RFC 5869 vectors),
HMAC-SHA256 (RFC 4231), and ChaCha20-Poly1305 (RFC 8439), plus one end-to-end
`seal(pin, record) -> ciphertext` vector with the eFuse HMAC step stubbed by the
trait injection, so the whole ladder is byte-pinned. The reduced-cost variant that the
boot self-test runs is a separate pinned vector with its cost parameters recorded in
the source comment (ARCHITECTURE 2.3).

---

## 5. UI flow testing

### 5.1 What 0.1.0 has, and why it does not scale unchanged

0.1.0's UI testing is genuinely strong for what it covers: 28 behavioural tests in
crates/notyas-ui/tests/ui.rs driving the public touch API at two geometries, with
masking asserted at the PIXEL level (two different mnemonics must render
byte-identical masked frames; a masked field must depend on length and not on
content), plus tools/uisim rendering a fixed tour to deterministic PNGs (each frame
rendered twice, refuse to write on divergence).

Two things break when 0.2.0 arrives:

1. **The UI stops being a pure function.** With the extended `UiRequest` protocol
   (ListSdFiles, ReadPsbt, WriteSignedPsbt, UnsealWallet, PersistWallet), a flow is a
   DIALOGUE with the embedder. A test that only sends touches can no longer reach the
   interesting screens.
2. **Golden PNGs explode.** Sixteen screens, dozens of refusal variants, two
   geometries and a per-corpus-case review screen is hundreds of images that all churn
   on a font tweak, which trains everyone to rubber-stamp the diff.

### 5.2 The autopilot harness, as a first-class component

- DECISION: yes, the scripted walk through `Ui::regions()` that the 0.1.0 hardware
  agents used ad hoc becomes a first-class, committed harness. It has already proven
  itself twice (uisim IS that technique, and the ui.rs tests are its assertions); 0.2.0
  makes it the primary UI verification vehicle rather than a screenshot tool.

Shape:

```
Script = [ Tap(RegionId) | Hold(RegionId, ms) | Tick(ms) | Expect(ScreenId)
         | ExpectModel(predicate) | Answer(UiRequest -> UiResponse) | Shot(name) ]
```

The harness is a MOCK EMBEDDER as well as a driver: it answers `ReadPsbt` from the
corpus, `UnsealWallet` from an in-memory sealed store backed by the real notyas-wallet
sealing code, and records `WriteSignedPsbt` for assertion. That makes complete signing
flows testable on the host, at both geometries, with no hardware and no node - which
is what makes P5 affordable enough to hold for every refusal reason.

One script format, three executors: the host simulator, the on-device HIL console
(section 6), and a printable human checklist for the steps only a person can do. A
flow is written once.

### 5.3 `Ui::describe() -> ScreenModel`

- DECISION: add a structured description of the current screen (screen id, title,
  ordered rows with role tags, button labels, modal state) alongside `draw()`. Goldens
  then guard PIXELS; ScreenModel guards MEANING. Refusal-text assertions, review-row
  assertions and traversal assertions all go through ScreenModel and survive a font
  change; the curated golden PNGs (roughly the uisim tour, extended to the new
  screens) stay small enough that a human actually reviews the diff.
- Secret hygiene comes along for free: a test asserts ScreenModel never contains the
  test mnemonic, entropy or xprv on any screen reachable in any script - the data-level
  companion to the existing pixel-level masking tests.

### 5.4 The flow properties worth asserting

Beyond "screen X renders", these are the properties whose violation is a security
bug:

1. **Traversal enforcement.** The sign affordance must not EXIST as a region until the
   last review page has been visited. Asserted directly, and then fuzzed: deterministic
   pseudo-random walks over available regions (hash-chain driven, reproducible) of
   bounded length must never produce a `WriteSignedPsbt` unless the walk contains the
   full traversal followed by a completed hold. A monkey test with a real invariant.
2. **Screen-graph reachability.** BFS from Home over `regions()` enumerates every
   reachable screen; assert the set equals the documented UX 3 inventory (no orphans,
   no unreachable screens), and that every screen has a path back. This catches dead UI
   that no scripted tour would visit.
3. **No dead ends.** Every refusal screen has at least one exit region. Asserted for
   every corpus reject case, at both geometries.
4. **No clipping.** Every text run's bounding box lies inside its card rect at both
   geometries. This is the mechanical version of "the full address must be shown", and
   it catches the classic long-address and long-label overflow the moment a new string
   appears.
5. **Hold semantics.** A hold released early cancels and leaves no state; a hold
   completed by `Tick` advances exactly once. Tick-driven, so it is testable without
   real time.
6. **Danger-grade correctness.** Every destructive action goes through the modal grade
   UX 15 assigns it (confirm / hold / typed-name); asserted by walking every
   destructive region and checking the modal grade that appears.
7. **Geometry parity.** Every script runs at 720x720 and 800x480, and the ScreenModel
   (not the pixels) must be equal at both. A row that exists in one layout and not the
   other is a bug, not a layout choice.

### 5.5 Refusal screens are corpus-driven

Every corpus reject case is a UI test: load the case through the mock embedder, assert
the exact reason string, the explanation text, the presence of a next-step
instruction, and the absence of any jargon token from a small banned-word list
(UX commandment 10 made mechanical). The refusal text lives in one place and the
corpus sidecar names the expected reason code, so a new refusal reason cannot ship
without both a case and a screen.

---

## 6. Hardware in the loop

### 6.1 What must be proven on real silicon, per release

Host tests cannot see the three things that actually differ on the device: the
riscv32imafc target, the real flash and eFuse peripherals, and the panel and touch
stack. The per-release hardware gate, on BOTH verified boards (Waveshare 4B 720x720
and Elecrow CrowPanel 5in 800x480):

| # | Proof | Why it cannot be a host test |
|---|---|---|
| H1 | Boot self-test green with storage BLANK and with storage POPULATED | the self-test reads real eFuse and real partitions |
| H2 | Signing agreement: the device recomputes a pinned subset of `frozen/signatures.json` and reports each SHA256 over the test-mode console; all must match the host file | 32-bit target, different libsecp build. An endianness or width bug is invisible on x86_64. This is P7 and it is cheap |
| H3 | Argon2id unlock time within the 0.5-2 s target measured on a RELEASE-configured unit (flash + PSRAM encryption ON, per ARCHITECTURE 2.3) | the dev-board number is not the shipping number |
| H4 | Power-cut campaign: relay- or FET-switched supply, N cycles cut at pseudo-random moments during scripted seal / unseal / PIN-change / wipe operations, asserting S1-S8 after each boot | validates that the section 4 host model is not fiction |
| H5 | eFuse and boot state readout matches the intended provisioning (secure boot v2 RSA-3072, flash encryption, HMAC key present and read-protected, anti-rollback) | eFuses are one-way; this is the only place the truth lives |
| H6 | Radio invariant measured EXTERNALLY: kill GPIO level captured on a logic analyzer, not merely reported by the firmware that would also be the liar in the failure case | self-report is not proof, and SECURITY.md invariant 1 is the project's headline claim |
| H7 | Full Sparrow SD round trip on testnet for all four script types plus a 2-of-3 P2WSH multisig, including partial and completing cosigner ceremonies | the coordinator is the real interop surface |
| H8 | A hostile corpus case refused with the correct screen, photographed | the refusal path is the one users hit when it matters |
| H9 | Animated UR2 QR scanned successfully by Sparrow at default and lowest density on both panels | panel geometry, refresh and contrast are physical properties |
| H10 | Stateless path writes nothing: flash readback diff over a full 0.1.0-style flow on a dev board | the statelessness claim survives 0.2.0 only if measured |

### 6.2 Making it repeatable rather than ad hoc

- DECISION: adopt `pytest-embedded` (Espressif's own HIL plugin, the framework ESP-IDF
  CI uses; https://github.com/espressif/pytest-embedded ,
  https://docs.espressif.com/projects/esp-idf/en/stable/esp32p4/contribute/esp-idf-tests-with-pytest.html)
  as the HIL driver. It gives serial DUT fixtures with `dut.expect()` regex matching,
  target/port autodetection and flashing, which is exactly the plumbing we would
  otherwise hand-roll badly. A `hil/` directory holds the suites; results are written
  as a signed HIL report committed per release, alongside the corpus report.
- **The test-mode console.** For H2, H4 and the autopilot-on-device story, the firmware
  gains a `hil` build feature exposing a serial console that can report the current
  ScreenId and ScreenModel, list regions, inject synthetic touch and tick events, and
  run the pinned signing KAT subset. The same section 5 scripts then execute on the
  device, and pass/fail becomes automatic instead of a human with a camera.
  Honest cost, stated rather than buried: a touch-injection console is an attack
  surface. Mitigations, all mechanical: the feature is off by default and never enabled
  in a release build; the Verify screen renders a prominent HIL BUILD banner when it is
  compiled in; and the release gate asserts the console's symbols are absent from the
  shipped binary (the same style of check as the build-graph invariant test in
  tools/build-graph-check.sh). See OPEN (corpus-3).
- **Fixtures.** SD tests run from a committed FAT image built by the corpus tool
  (`tools/corpus sd-image`), so "what was on the card" is reproducible. Card insertion
  and removal remain manual unless an SD-mux is acquired; the power-cut rig (H4) needs
  a USB-controlled relay or FET on the supply rail. Both are small, one-time hardware
  purchases - see OPEN (corpus-5).
- **Evidence discipline.** Each HIL run produces: the pytest report, the device's
  serial log, the SHA256 of the flashed binary, the eFuse readout, and the photographs
  named by the checklist. The 0.1.0 house rule that every milestone lands as a working
  flashable commit gains a companion: every release lands with a HIL report that names
  the exact firmware hash it was produced from.

---

## 7. Reporting: the corpus report

The desktop campaign's FUZZ_REPORT.md is the model, with one correction. Its own text
says "the harness lives outside this repository", which means the campaign cannot be
independently reproduced by a reader. For signing, that is not acceptable: the
generator, the mutators, the oracle drivers and the report tool all live in
`tools/corpus/` under version control.

`tools/corpus report` emits `docs/corpus-report.md` containing: case counts per group,
per ARCHITECTURE 5.3 check and per reason code; the check-necessity matrix result; the
oracle agreement statistics (how many sighashes were confirmed by two independent
implementations, with tool versions); the pinned bitcoind version and hash; and the
SHA256 of the corpus tree. The release gate re-runs generation and requires a
byte-identical corpus tree, which is the reproducibility claim made mechanical.

---

## 8. Dependency-ordered corpus checklist for MILESTONES.md

Each item names the milestone it blocks. "Blocks" means the milestone's test gate
cannot be evaluated without it.

| id | Work | Blocks | Depends on |
|---|---|---|---|
| C0.1 | Ratify OPEN (corpus-1..5); pin corpus format, generator language and the no-RNG generation rule | m1 close | Q13 (differential scope), Q11, Q12 |
| C0.2 | `tools/corpus` skeleton: hash-chain value derivation, wallet definitions from the three published mnemonics, `gen`/`verify`/`report` commands | m2 | C0.1 |
| C0.3 | CI lane split A/B/C/D; lane A enforced network-free; pinned bitcoind container image (tag + SHA256) | m2 | C0.1 |
| C1.1 | Import external KATs: BIP-340 CSV (zero-aux rows flagged as our exact path), BIP-341 wallet vectors, BIP-143 inline, legacy `sighash.json` | **m2 close** | C0.2 |
| C1.2 | Pinned signing KAT subset wired into selftest.rs and the boot self-test (fits the 1 s budget) | **m2 close** | C1.1 |
| C2.1 | `FaultingFlash` NOR model with real geometry and XTS granularity (interface per ESP-SEAL.md) | **m3 close** | ESP-SEAL.md interface frozen |
| C2.2 | Step-boundary fault enumerator + invariants S1-S9, including the global (key, nonce) observer | **m3 close** | C2.1 |
| C2.3 | Ladder KATs: Argon2id (RFC 9106 + pinned params), HKDF (RFC 5869), HMAC (RFC 4231), ChaCha20-Poly1305 (RFC 8439), end-to-end seal vector | **m3 close** | C2.1 |
| C3.1 | `hil/` skeleton on pytest-embedded; serial DUT fixtures; flash + boot + self-test assertions (H1) | **m4a close** | C0.3 |
| C3.2 | Power-cut rig and the on-device H4 campaign | **m4a close** | C2.2, hardware purchase (OPEN corpus-5) |
| C4.1 | `Ui::describe() -> ScreenModel` + autopilot harness with mock embedder | **m4b close** | none |
| C4.2 | Flow properties 1-7 (traversal, reachability, no dead ends, no clipping, hold semantics, danger grades, geometry parity); masking tests extended to PIN and session screens | **m4b close** | C4.1 |
| C4.3 | Curated golden PNG set regenerated for the new screens; uisim tour extended | m4b | C4.1 |
| C5.1 | SD fixture image builder (`tools/corpus sd-image`); malformed-file and file-cap cases | **m5 close** | C0.2 |
| C6.1 | Positive bases P1-P4, P7-P10 generated and oracle-attested (two oracles agree before a value is written) | **m6 close** | C0.2, C1.1 |
| C6.2 | Mutator library implementing A1-A8, A13-A38 (multisig mutators deferred to C7.1); adversarial corpus generated | **m6 close** | C6.1 |
| C6.3 | Reason-code exhaustiveness test and the check-necessity matrix (`Policy::without`) | **m6 close** | C6.2 |
| C6.4 | Corpus-wide invariants: emission delta, allocation bound, determinism, secret hygiene, refusal completeness | **m6 close** | C6.2 |
| C6.5 | Frozen `sighashes.json` (two oracles) and `signatures.json` (reviewed, never auto-regenerated) | **m6 close** | C6.1 |
| C6.6 | Node lane: corpus B, `finalizepsbt` + `testmempoolaccept`, `analyzepsbt` role checks, HWI `signtx_cases` matrix mirror, `deriveaddresses` cross-check | **m6 close** | C0.3, C6.1 |
| C6.7 | Refusal-screen text goldens for every reject case at both geometries | **m6 close** | C4.1, C6.2 |
| C6.8 | Post-sign gate mutation tests A37, A38 | **m6 close** | C6.1 |
| C7.1 | Multisig bases P5, P6 and mutators A9-A12; registry corpus; N and N+1 bound cases | **m7 close** | C6.2 |
| C7.2 | Core-as-cosigner ceremonies in both signing orders; both must finalize identically | **m7 close** | C6.6, C7.1 |
| C8.1 | UR2 round-trip vectors: encode with `foundation-ur`, decode with the independent `ur` crate; fragment-loss and out-of-order fountain decode | **m8 close** | none |
| C9.1 | Nightly fuzz lane seeded from qa-assets `fuzz_corpora/psbt*` plus the mutator space; crash triage workflow | m9 | C6.2 |
| C9.2 | `docs/corpus-report.md` generation; release gate requires a byte-identical regenerated corpus tree | **m9 close** | C6.5, C7.1 |
| C9.3 | HIL release checklist H1-H10 executed and the signed HIL report committed | **m9 close** | C3.1, C3.2, C6.7 |

Critical path, stated in one line: C0.2 -> C1.1 -> C6.1 -> C6.2 -> C6.3/C6.5 -> C6.6.
Everything else parallelizes around it.

---

## 9. Open questions

OPEN: (corpus-1) **Corpus licensing and publication.** The adversarial PSBT set is
reusable by every other signer project, and publishing it is the kind of contribution
PLATFORM.md argues for. Options: (a) keep it in-tree under GPL-3.0-or-later like
everything else; (b) keep the harness GPL3 but license the vector FILES permissively
(CC0 or MIT) with their own SPDX headers, so other wallets can adopt them; (c) also
upstream selected cases to HWI and to Coldcard's psbt_faker.
RECOMMENDATION: (b) plus (c). Test vectors gain their value from adoption, the same
argument PLATFORM.md section 6 makes for the extracted crates, and vectors carry no
implementation to protect. The generator stays GPL3.

OPEN: (corpus-2) **Does CI get a bitcoind?** Layer 2 needs a pinned node, which means
either a container in hosted CI (slower, needs an image we maintain) or a self-hosted
runner (faster, one more machine to operate).
RECOMMENDATION: pinned container, run on PRs that touch notyas-core/notyas-wallet plus
nightly, not on every push. Lane A stays the fast gate. The operational cost is real
but a signer whose acceptance testing is manual will eventually ship a transaction the
network rejects.

OPEN: (corpus-3) **The HIL test-mode console.** Repeatable hardware testing wants a
serial console that can inject touch events and dump the ScreenModel; that console is
an attack surface if it ever ships. Proposed package: build-feature gated, off by
default, HIL BUILD banner on the Verify screen, and a release gate asserting the
symbols are absent from the shipped binary.
RECOMMENDATION: accept the package. Without it, hardware verification stays a person
with a camera and a checklist, which is exactly the ad-hoc situation this section was
asked to fix, and the mitigations are all mechanical rather than procedural.

OPEN: (corpus-4) **Lookalike-address warning.** Case A34 covers address poisoning by
asserting we render the full address. We could go further: compare each external
output address against our own derived addresses in the gap window and warn when a
prefix/suffix near-match is found ("this address resembles your own address at index
7"). Cost is a handful of string comparisons over addresses we already derive.
RECOMMENDATION: implement it in m6. It directly counters a documented, active attack
(https://arxiv.org/abs/2501.16681) that the industry's standard mitigation - showing
the full address - only partially addresses, because users still compare ends.

OPEN: (corpus-5) **HIL hardware purchases.** A USB-controlled relay or FET for the
power-cut rig (H4), and optionally an SD-mux so card insert/remove can be automated.
RECOMMENDATION: buy the relay now (H4 is a milestone-m4a gate and cannot be faked);
treat the SD-mux as optional, since SD steps are few and already batched into the
release HIL run.

Dependencies on existing open questions: Q13 sets the scope of layer 2's byte
comparison (adopting low-R grinding upgrades ECDSA from "accepted" to "byte-identical"
against Core); Q11 determines whether the stateless-signing corpus cases exist and
whether A10's expected verdict is a refusal or an expert-gated warning; Q12's fee
constants are the pinned numbers in P10 and A16; Q7 keeps taproot multisig and
therefore BIP-342 script-path signing out of the 0.2.0 corpus.
