# notyas 0.2.0 - claims audit (m13)

Audit date: 2026-08-18. Audited tree: the working tree at `4b8accc`, at the m13
claims-audit pass, with m1, m2, m3h, m3, m6 and m7 landed and m4a, m4b, m8, m10 and
m12 in flight.

This file exists so the m13 gate can be **re-run rather than re-argued**. MILESTONES.md
section 9 requires that every SECURITY.md claim be mechanically enforced or removed, and
that every PARITY.md row be implemented, equivalent-and-documented, or deferred with a
reason. Both clauses are checked here claim by claim and row by row, with the mechanism
named and cited. A claim without a mechanism in this file is a claim that was deleted or
narrowed, not one that was allowed through.

## Method

1. Every assertion in `docs/SECURITY.md` and `docs/plan-0.2.0/SECURITY.md` was enumerated
   as a separate claim, splitting compound sentences where the halves have different
   enforcement.
2. For each, the mechanism was located in the tree and cited by `path:line`. **Line
   numbers are anchors as of the audit date and several of these files were being edited
   by other milestones while the audit ran**, so every citation also names the symbol,
   constant or comment it points at. A line that has moved is found by the name; a name
   that has disappeared is the finding.
3. Each claim carries a verdict and a strength, because "enforced" is not one thing.

**Verdicts.**

- **ENFORCED** - something in the tree makes the claim true and would fail if it stopped
  being true.
- **DOCUMENTED-ONLY** - the claim is true today, and nothing mechanical stops it
  regressing. Legitimate for statements about intent, procedure and UI copy; not
  legitimate for a property a user's key security rests on.
- **UNSUPPORTED** - the code does not do this. Every one of these was removed or reworded
  in this pass; none is left flagged. Section 4 lists them with the before and after.

**Strength ladder**, strongest first. A claim enforced by a test is genuinely weaker than
one enforced by a type or a build gate, and the difference is recorded rather than
flattened.

| Strength | Why it ranks where it does |
|---|---|
| `BUILD GATE` | Fails the build or CI for the whole workspace. Cannot be forgotten. |
| `TYPE` | Illegal state is unrepresentable or the crate stops compiling. Cannot be skipped by a test that was not written. |
| `HARDWARE READ` | The value is read from silicon at runtime and rendered; a wrong value shows as a wrong value. |
| `TEST` | A named test asserts it. Strong, but only over the cases someone thought of. |
| `CONSTRUCTION` | True because only one code path exists and it is small enough to audit by reading. Weaker than a type: a second path can be added without anything failing. |
| `DOC` | Prose, procedure or UI copy. Enforced by review only. |

## 1. Claims in docs/SECURITY.md (normative)

`docs/SECURITY.md` was rewritten in this pass to be the shipped 0.2.0 text; before this
pass it was the 0.1.0 document, and its invariants 5 and 6 asserted Secure Boot v2, flash
encryption and eFuse anti-rollback on release hardware, none of which 0.2.0 has. The claim
numbers below index the rewritten file.

### 1.1 The seven stated absences (R30)

Negative claims. Each is verified as ABSENT in the tree, and each is stated in the shipped
text rather than left to inference.

**N1. No Secure Boot v2 is burned; an attacker who has held the device can flash a
modified image.** ENFORCED / `HARDWARE READ` + `BUILD GATE`. The three digest slots are
read from eFuse and rendered as read, with a read-protected block reported as
`ReadProtected` rather than as thirty-two zero bytes
(`crates/esp-idf-hmac/src/secure_boot.rs:1-45`, `firmware/src/readout.rs:1-30`). Release
firmware contains no eFuse-burn code at all: the burn helpers sit behind the
`provisioning` feature, off by default, and `build.rs` fails a build that enables it
without virtualised eFuses (`crates/esp-idf-hmac/Cargo.toml:22-28`,
`firmware/Cargo.toml:39-46`).

**N2. No eFuse anti-rollback.** ENFORCED / `HARDWARE READ`. Same readout path; the
anti-rollback fields are raw eFuse values with no verdict computed over them
(`crates/esp-idf-hmac/src/posture.rs:1-28`).

**N3. No flash encryption; the `wallets` partition is not encrypted at rest and its
`encrypted` flag is inert.** ENFORCED / `HARDWARE READ` + `DOC`. The flash-encryption
fields are read and rendered (`firmware/src/readout.rs`, `firmware/src/verify.rs:76`), and
the partition table states the inertness at the point of definition
(`firmware/partitions.csv`, the `encrypted` flag note). R17 is the reconciliation that
forbids reading the flag as evidence that encryption is active.

**N4. No hardware-held signing key.** ENFORCED / `TYPE`. There is no API that keeps a
private key inside a peripheral: `KeyProvenance` enumerates the four states the device
binding can be in and nothing else (`crates/notyas-wallet/src/hal.rs:107-121`), and the
only key material in a peripheral is the HMAC device-binding key, which signs nothing
Bitcoin-shaped.

**N5. No third-party attestation of reproducibility; the signing key is on a
general-purpose machine.** DOCUMENTED-ONLY / `DOC`. What is mechanical is weaker and
worth naming: `.github/workflows/repro.yml` builds each board twice and compares, and
`tools/ci/check-repro-pins.sh` fails CI when the four pinned-version files drift apart.
Neither is corroboration by an outside party (Q31), and neither says anything about key
custody (Q30).

**N6. No backup of any kind; multisig registrations, labels and settings are
unrecoverable after a wipe.** ENFORCED / `CONSTRUCTION`. No backup container, no archive
code and no key-material-to-SD path exists in any crate. Invariant 2b is the standing
prohibition that keeps it that way.

**N7. No BSMS and no taproot multisig.** ENFORCED / `TYPE`. `notyas-core::multisig`
accepts P2WSH `sortedmulti` only and refuses P2SH, P2SH-P2WSH, bare `multi(...)` and
taproot multisig by name rather than ignoring them
(`crates/notyas-core/src/multisig.rs:39-45`, refusal variants at `:304-360`). No BSMS
round-handling code exists.

### 1.2 The self-reporting boundary

**B1. Every value on the Verify screen is read and reported by the firmware being
verified, and without Secure Boot nothing on the device checks that firmware.** ENFORCED /
`HARDWARE READ` + `DOC`, and it is the most important claim in the document because it
bounds every other readout claim. The readout module's own contract is "read, never claim":
no value is compiled in, and a field this build cannot read renders `not read` rather than
a plausible default (`firmware/src/readout.rs:1-30`). The rest of the claim is an honest
statement of what that cannot buy (plan-0.2.0/VERIFY.md section 9), and it is DOC by
nature: no mechanism can prove a negative about the software running the mechanism.

**B2. The reproducible-build chain is the answer to firmware substitution, and in 0.2.0 it
is exercised by the owner rather than by the device.** DOCUMENTED-ONLY / `DOC` plus the
`repro` workflow above. Stated as a change in who does the work, which is the honest form.

### 1.3 Threat model

**T1. In-scope and out-of-scope lists, including "an attacker who has held the device and
replaced its firmware" as out of scope in 0.2.0.** DOCUMENTED-ONLY / `DOC`. A threat model
is a scoping statement; the audit's job is that it not overstate, and after this pass it
concedes firmware replacement explicitly rather than implying detection.

**T2. No vendor genuine-check exists and none will be built; the eFuse HMAC key is
provisioned by whoever flashes the device.** ENFORCED / `CONSTRUCTION` + `DOC`. There is
no challenge-response path in the tree, and the provisioning ceremony is host-side with
`espefuse.py` before first boot (`firmware/src/store/mac.rs:1-16`, PROVISIONING.md).
COMPETITIVE.md 9.9 is the reasoning; the shipped text carries it in one paragraph.

### 1.4 Device states and the stored-wallet tiers

**D1. Stateless is the default and a first-class mode; with no stored wallet nothing is
ever written to flash.** ENFORCED / `TYPE` + `CONSTRUCTION`. The partition table declares
no NVS, no otadata, no phy_init and no coredump, so there is nowhere else to write
(`firmware/partitions.csv`), and the store reports `Blank` or `Unprovisioned` rather than
formatting itself (`crates/notyas-wallet/src/vault.rs:68-80`, resolved at `:2165-2178`;
surfaced as `StoreStatus` at `crates/notyas-ui/src/lib.rs:759-772` (`StoreStatus`)). The boot counter deliberately does not count
before the ledger is formatted, which is R24's resolution and the one place this invariant
was nearly traded away (`firmware/src/main.rs:130-143` (the R24 boot-count comment),
`crates/notyas-ui/src/screens/verify.rs:549-555` (`not counted`)).

**D2. State 2 defaults to N = 15; state 3 removes the attempt limit.** ENFORCED / `TYPE`.
`Policy::wipe_after` uses 0 as the disabled sentinel and 3..=25 otherwise, with the bounds
as format constants (`crates/notyas-wallet/src/config.rs:136-158`), and the format-time
default is 15 (`:253`).

**Tier 1. A bench attacker gets an AEAD-sealed record, and each PIN guess requires this
physical board because the ladder passes through the eFuse-keyed HMAC peripheral.**
ENFORCED / `TYPE`. The ladder is `device_binding = hmac_efuse(0x01, domain_tag)` and every
record key descends from it (`crates/notyas-wallet/src/crypto.rs:6-17`). The product
accepts only `KeyProvenance::EfuseReadProtected`, and `Config::validate` rejects a
configuration that would accept a weaker provenance
(`crates/notyas-wallet/src/config.rs:238-258`, `:293-308`); "read-protected" is itself
checked against the block's `RD_DIS` state rather than assumed
(`crates/esp-idf-hmac/src/key_block.rs:224-253`).

**Tier 1a. 15 consecutive failures destroy the sealed records.** ENFORCED / `TEST` over a
`TYPE`. The comparison is in the unlock path
(`crates/notyas-wallet/src/vault.rs:1142-1146`), and the power-loss fuzzer cuts power at
every step boundary of every storage operation and asserts the eleven invariants after
each cut, in CI, in release mode (`.github/workflows/ci.yml:73-74`).

**Tier 1b. The flash is not encrypted, so the PIN ladder is the whole of the protection,
and the counter is user-disableable.** ENFORCED / `TYPE`. See N3 and the policy rules at
`crates/notyas-wallet/src/vault.rs:1549-1584`.

**Tier 2. Assume the key and image are extracted; the attack collapses to offline
Argon2id-stretched guessing, and 4 digits does not survive.** ENFORCED / `TYPE` for the
cost, `DOC` for the arithmetic. The pinned cost is 16 MiB, t=1, p=1, a measurement rather
than a target (`crates/notyas-wallet/src/config.rs:79-89`), and the PIN floor of 4 is
enforced at both entry points that set or change a PIN (`vault.rs:887-889`, `:1353-1355`).
The "hours, not years" statement is arithmetic over that cost and is DOC.

**Tier 3. The counter converts unlimited offline guesses into N per full-flash restore
cycle; ledger-only rollback is detected and refused, a consistent full-flash restore is
not.** ENFORCED / `TYPE` + `TEST`. Mount raises `TamperKind::LedgerRollback` when a record
outranks the ledger's high-water or a blank ledger sits beside non-blank records
(`crates/notyas-wallet/src/vault.rs:287-341`), and every entry point refuses on
`StoreState::Inconsistent` (`:880`, `:1038`, `:1759`). The undefended case is stated
rather than implied, which is the only honest treatment available on hardware with no
CPU-unreachable monotonic counter.

**W1. The seed is re-derivable from the user's backup; the rest of the device's state is
not.** ENFORCED / `CONSTRUCTION` + `DOC`. It follows from N6: nothing writes registrations
or settings anywhere off-device. The requirement that every wipe surface name them
individually is UI copy and is DOC (R21).

### 1.5 Invariants

**I1. No radio: the C6 is driven into reset before anything else in `app_main` and the
line is never released.** ENFORCED / `CONSTRUCTION` + `HARDWARE READ`. `radio_lockdown()`
is the first call after logger init (`firmware/src/main.rs:88-97` (`board::radio_lockdown()`)); the per-board
implementations claim the pin as an output driven low
(`firmware/src/board/elecrow_5.rs:74-87`,
`firmware/src/board/waveshare_common.rs:52-57`); and the Verify screen reads the live level
back with `gpio_get_level` rather than reporting what was written
(`firmware/src/verify.rs:70-73`, `:190-197`).

**I1a. No network, RNG or closed-crypto crate is in the graph.** ENFORCED / `BUILD GATE`.
`tools/build-graph-check.sh` bans them lockfile-wide with a build-tool exemption for host
tools only (`:32-38`, `:71-114`), and re-checks each device-linked crate's resolved
subtree with no exemption at all (`:116-149`). It also fences the `testkit` feature out of
the default graph (`:151-173`) and positively asserts secp256k1's presence, so a stubbed
derivation path fails too (`:175-188`). Wired at `.github/workflows/ci.yml:124-136`.

**I1b. The ESP-IDF component list contains no esp_hosted, esp_wifi_remote or network
component.** DOCUMENTED-ONLY / `DOC` over a pinned file. **This was UNSUPPORTED before
this pass**: the 0.1.0 text claimed "a CI grep over the linked component list" and no such
grep exists in `tools/` or `.github/`. The managed component set is pinned by
`firmware/components_esp32p4.lock` (verified by inspection: LCD, touch, i2c_bus and
cmake_utilities only) and the reproducible build fails if that lock changes during a build
(`tools/repro/build.sh:418-425`). The claim now states the pinned list and the review
rather than a grep. See section 4, item U1.

**I2a. No plaintext secret leaves RAM; RAM copies are zeroized.** ENFORCED / `TYPE`. The UI
carries a compile-time drop-equals-zeroize check: a function that is never called and
exists only to be type-checked names every secret-bearing field of every screen against
its type, so changing one to a plain `String` stops the crate compiling
(`crates/notyas-ui/src/screens/mod.rs:499-545` (`WipesOnDrop`, `secrets_wipe_when_a_screen_is_dropped`)). Secrets elsewhere are `Zeroizing` or
carry hand-written `Drop` wipes across notyas-core and notyas-wallet, and the sealing
session's `Drop` is a wipe point (`crates/notyas-wallet/src/session.rs:9`, `:135`).

**I2b. NVS is never mounted.** ENFORCED / `CONSTRUCTION`. No `nvs` symbol appears anywhere
in `firmware/src/` and the partition table declares no NVS partition.

**I2c. QR display covers public values only.** ENFORCED / `CONSTRUCTION` + `TEST`. The
request type is a label plus a payload string documented as public by construction
(`crates/notyas-ui/src/lib.rs:429-435` (`QrTarget`)), the only three constructors are the export
screen's address, account-xpub and SLIP-132 buttons
(`crates/notyas-ui/src/screens/schemes.rs:170-194` (`RegionId::QrXpub`, `QrSlip132`, `QrAddress`)), and the UI tests assert what those
buttons emit against published-vector values
(`crates/notyas-ui/tests/ui.rs:795-832` (`VECTOR1_BIP84_ADDR0`)). Strength is CONSTRUCTION rather than TYPE
because nothing in the type system prevents a fourth constructor being added with a secret
payload; a `PublicValue` newtype would raise it, and that is a 0.3.0 note rather than a
0.2.0 claim.

**I2d. What the device may write is enumerated and closed.** ENFORCED / `TYPE` for flash,
`DOC` for SD. Flash is the two partitions the table declares, and their geometry is frozen
in `Layout::V1` with a superblock mismatch as a hard mount refusal rather than a
reinterpretation (`crates/notyas-wallet/src/config.rs:33-45`,
`crates/notyas-wallet/src/format.rs`). The SD half is a prohibition on a subsystem that
does not exist yet (m5 is not started), so it is a bound rather than a description; that
is why the shipped wording says "may write" and names the milestone.

**I2e. Every write to flash or SD is announced on-screen before it happens.**
DOCUMENTED-ONLY / `DOC`. A UI requirement carried by the screen specifications and the
S-46 write notice (`crates/notyas-ui/src/screens/verify.rs:292-305` (the C12 write announcement)); the storage engine
cannot enforce it. Stated as a UI requirement in the shipped text rather than as an
engine property.

**I3. Deterministic: no RNG on any derivation path or in the sealing path; salts and
nonces are derived.** ENFORCED / `BUILD GATE` + `TYPE`. The ban list is I1a. The sealing
nonces come out of the same HKDF as the record key, so no random source is even
expressible (`crates/notyas-wallet/src/crypto.rs:6-17`, `:373-395`), and a debug-time
probe asserts that no (key, nonce) pair is ever reused
(`crates/notyas-wallet/src/probe.rs:43`). Signing is RFC 6979 with low-R grinding and the
no-aux-rand BIP-340 path, pinned by vectors (see I4).

**I4. Equivalence with desktop BigDice and with pinned published vectors.** ENFORCED /
`TEST` + `HARDWARE READ`. Host vectors run on every CI run (`.github/workflows/ci.yml:58`)
and name their upstream artefact per section: BIP-143's worked examples, BIP-340's
`test-vectors.csv`, BIP-341's `wallet-test-vectors.json`, and Bitcoin Core's
`key_tests.cpp` (`crates/notyas-core/tests/signing_vectors.rs:1-37`). The low-R corpus
expectations were produced by an independent RFC 6979 implementation that reproduces both
of Core's published signatures and both of BIP-143's byte for byte, and seven of its twelve
cases need grinding, so a build that called stock `sign_ecdsa` fails the file (`:24-37`).
On-device, eleven checks covering every primitive on the derivation and signing path run at
boot and render their verdict without panicking
(`crates/notyas-core/src/selftest.rs:1-64`, `:293`).

**I4a. Byte-equality with Core is claimed for ECDSA and never for Schnorr.** ENFORCED /
`TEST`. The asymmetry is a fact about Core randomizing BIP-341 aux-rand, and the test file
pins exactly the half that is claimable.

**I4b. A live `walletprocesspsbt` + `testmempoolaccept` differential runs in CI.**
UNSUPPORTED before this pass, now removed. No CI job runs `bitcoind`; the corpus fixtures
are generated from a fixed in-tree seed (`crates/notyas-core/src/psbt/fixture.rs:1-12`).
See section 4, item U2.

**I5. The Verify screen reports state as actually read, never as constants; a field it
cannot read renders `not read`.** ENFORCED / `HARDWARE READ`, with the field order frozen
so two units diff cleanly (`firmware/src/readout.rs:1-30`).

**I5a. The storage readout is `present` or `blank` and never a count.** ENFORCED / `TYPE`.
The mapping from store state to string has four arms and none of them can produce a count
(`firmware/src/verify.rs:178-187`). Two further values exist and are not counts:
`not provisioned` and `unreadable (kind)`. The shipped text now names them, because a
reader who saw one and had been told there were exactly two would rightly distrust the
rest of the screen.

**I5b. Unused slots always hold device-derived filler, so `present` is the true state of
every formatted device.** ENFORCED / `TYPE`. `Occupancy::AlwaysFilled` is the shipped mode
and the on-flash format is byte-identical under either mode, so the choice never reaches
the bytes (`crates/notyas-wallet/src/config.rs:113-133`,
`crates/notyas-wallet/src/vault.rs:1290-1301`, `:2101`).

**I5c. The wipe policy is user-settable within 3..=25 or disableable, from an unlocked
session only, and a malformed or absent policy resolves to wipe ON.** ENFORCED / `TYPE`.
Bounds and the disabled sentinel at `config.rs:136-158`; the unlocked-session and
fresh-PIN requirement plus the refusal to set a threshold at or below the failures already
recorded at `vault.rs:1549-1584`; the strict fallback at `vault.rs:1876-1900`.

**I6. Secure boot, honestly: nothing is burned except the HMAC key, and that is burned
host-side.** ENFORCED / `BUILD GATE` (N1) + `HARDWARE READ`. Q63 is answered and closed in
favour of exactly this reading, so the previous "single open question in the set" wording
was stale and is corrected.

**I7. The signing policy engine is the trust boundary.** ENFORCED / `TYPE` + `TEST`.
`inspect` is a pure function of a PSBT and a context with no key in scope and one named
refusal rather than a list (`crates/notyas-core/src/psbt/checks.rs:1-49`, `:982`); the
check order puts cheap and decisive first and computes the fee last, from prevouts that
have already been validated (`:13-30`); structural limits bound size, counts and path
depth (`:79-104`); ownership is a claim and the proof is the derive-and-compare in the
signer (`:41-49`).

**I7a. Change is proven, not believed.** ENFORCED / `TYPE`. `OutputRole` distinguishes
`Change` (a registration rebuilds this exact script on its change keychain at the claimed
leaf) from `ClaimedButUnproven`, and `is_change()` is written so that adding a variant
forces the question to be answered again rather than defaulting to change
(`crates/notyas-core/src/psbt/checks.rs:770-805`). Multisig registrations have no public
constructor: the only way to make one is `Pending::verify`, which derives our key at the
claimed origin and refuses a wallet this device is not provably a member of
(`crates/notyas-core/src/multisig.rs:17-27`, `:778`).

**I7b. Single-sig change is proven by exact descriptor derivation.** UNSUPPORTED before
this pass, now narrowed. Check 3 is assigned to notyas-wallet and is not implemented, so a
single-sig output claiming to be ours classifies as `ClaimedButUnproven` and counts as a
payment. That is conservative and safe, but it is not what "change is proven by exact
descriptor derivation" told a reader. See section 4, item U3.

**I7c. The fee is bounded.** UNSUPPORTED before this pass, now removed. No fee ceiling
exists in either crate. What does exist, and is now what the text claims, is that the fee
is computed together with whether this device's own signatures would enforce it, so a
claimed amount is never rendered as a measured one
(`crates/notyas-core/src/psbt/checks.rs:883-885`, `:915-940`). See section 4, item U4.

**I7d. After signing, miniscript's interpreter re-verifies the result.** UNSUPPORTED
before this pass, now corrected. `miniscript` is not a dependency of any crate in this
workspace and does not appear in `Cargo.lock`. What runs is
`notyas_core::psbt::signer::verify_signatures`, which re-verifies every signature this
device produced against a sighash recomputed from the PSBT alone, bound to the
signature-cleared digest of the reviewed file
(`crates/notyas-core/src/psbt/signer.rs:373-418`,
`crates/notyas-core/src/psbt/checks.rs:902-912`). It shares rust-bitcoin's digest
implementation with the signing path, so it is a fault and caller-bug detector, not an
independent second implementation. See section 4, item U5.

### 1.6 Duress and wipe stance

**U-W1. A power cut between the attempt-cell program and the success-cell write consumes
an attempt even when the PIN was correct.** ENFORCED / `TEST`. Fail-closed by design, and
the power-loss fuzzer is what proves the ordering holds under a cut at every step boundary
(`.github/workflows/ci.yml:73-74`, `crates/notyas-wallet/tests/powerloss.rs`). The
hardware half of the evidence is the 20-cut seal-mode gate in
`docs/m4a-power-cut-evidence.md`.

**U-W2. A policy change needs the PIN, and offline editing cannot forge one because the
guard and the superblock MAC descend from the eFuse key.** ENFORCED / `TYPE`
(`crates/notyas-wallet/src/crypto.rs:6-17` for the descent,
`crates/notyas-wallet/src/vault.rs:1549-1584` for the gate).

**U-W3. A consistent full-flash snapshot and restore defeats all of it.** ENFORCED as an
honest negative / `DOC`. Nothing can defend it on this silicon; the value of the claim is
that it is stated.

**U-W4. Removing the PIN destroys every stored wallet and is a data-loss event, not a
security downgrade.** ENFORCED / `TYPE` for the structure (no PIN means no sealing key, so
the state is unrepresentable), `DOC` for the framing, which PIN-MODES.md requires and which
matters because describing two opposite "off" switches the same way teaches the wrong
instinct about both.

**U-W5. Duress PIN opens a decoy wallet set, OFF by default, with no stored marker.**
DOCUMENTED-ONLY at the audit date. The format half is ENFORCED / `TYPE` - four identities
with index 0 primary, filler indistinguishable without the eFuse key, and the unlock loop
deliberately not breaking on the first match
(`crates/notyas-wallet/src/slot.rs:161`, `crates/notyas-wallet/src/vault.rs:1104`,
`:1479`) - but the PIN-classification and UX half is m13 scope and has no screen in
`crates/notyas-ui/src/screens/` at the audit date. The claim as worded says what the
feature is and that it is off by default, which is true of the tree today; it must be
re-checked at the gate, and if the UX half does not land, the sentence describes a
capability of the format and must say so.

**U-W6. Anti-phishing words detect a swapped board but not replaced firmware on the same
board.** ENFORCED / `TYPE` for the derivation, `DOC` for the boundary. Every
embedder-facing derivation goes through `device_derive`, tag 0x7f, with length-prefixed
inputs so that a partial PIN can never be steered into colliding with the internal `0x02
|| prestretch` message (`crates/notyas-wallet/src/crypto.rs:19-27`, `:258`,
`crates/notyas-wallet/src/vault.rs:697-706`); the firmware answers the UI's request from
that path (`firmware/src/main.rs:463-466` (`UiRequest::DeviceWords`)). **The firmware-replacement half was missing
from both security documents before this pass** and is the exact overclaim COMPETITIVE.md
9.10 warns about. See section 4, item U6.

### 1.7 Accepted risks

**AR1-AR10** (ESP-IDF in the TCB, USB physical surface, vendor panel and touch init,
vendored libsecp256k1, Argon2 parameters as a measured compromise, the HMAC binding making
a flash transplant unrecoverable, FATFS not power-loss safe, the IDF media stack as C
attack surface, signing-key custody, and the three Elecrow board-specific items).
DOCUMENTED-ONLY / `DOC` by nature - a disclosed risk is a statement, not a mechanism - with
three exceptions that carry one: the Argon2 parameters are pinned constants
(`crates/notyas-wallet/src/config.rs:79-89`), the C6 power-on window is logged as a warning
at every boot on the affected board (`firmware/src/board/elecrow_5.rs:83-86`), and the
flash-transplant consequence follows from the eFuse binding at `crypto.rs:6-17`.

## 2. Claims in docs/plan-0.2.0/SECURITY.md

The plan document is the working half of the pair and its claims are the same claims,
with the research citations and the tier reasoning kept in full. It was corrected in place
rather than rewritten; the six corrections are marked `[m13]` inline and are the same
items U1 to U6 of section 4, plus two staleness fixes:

- **P1. "Q63 is the single open question in the set."** Stale: Q63 was answered (a) and
  closed on 2026-08-18. Corrected, with the consequence spelled out - the HMAC burn
  proceeds, and because it is performed by whoever flashes the device, no vendor
  genuine-check claim may appear anywhere.
- **P2. The `media` partition "is DECLARED and never written".** UNSUPPORTED: the flashed
  table declares `factory`, `wallets` and `counters` only, and there is no `media`
  partition at any offset. Struck from the enumeration, with the underlying geometry
  discrepancy raised in section 6 rather than papered over.
- **P3. "miniscript" listed among the new dependency edges the ban list covers.**
  UNSUPPORTED: it is not in the graph at all. Corrected in invariant 1.

## 3. R30: the seven things a reader would wrongly assume

MILESTONES 8 (R30) names seven. Each was hunted specifically, in both security documents,
in PARITY.md, and - as a reporting matter, since they are outside this audit's fence - in
README.md and VERIFYING.md.

| # | Assumption | Where it now says otherwise | Residual risk |
|---|---|---|---|
| 1 | Secure Boot exists | docs/SECURITY.md "What 0.2.0 does not have" 1, invariant 6, the self-reporting boundary; PARITY firmware-upgrade and Bless-Firmware rows | README.md still says release hardware runs Secure Boot v2 (section 6) |
| 2 | Anti-rollback exists | Same list, item 2; PARITY downgrade-protection row | README.md, same paragraph |
| 3 | A hardware-held signing key exists | Item 4; the tier statement; PARITY dual-secure-elements row | None found |
| 4 | Third-party attestation exists | Item 5; accepted risks | None found |
| 5 | A backup exists | Item 6; the wipe posture; PARITY encrypted-backups, clone and Key Teleport rows, all three corrected | None found |
| 6 | BSMS exists | Item 7; PARITY BSMS row DEFER | None found |
| 7 | Taproot multisig exists | Item 7; PARITY taproot row PARTIAL, tapscript and MuSig2 deferred | None found |

Cross-check: `docs/RELEASE-0.2.0.md` (written in parallel by m12) enumerates the same seven
and states the three that are properties of the release rather than absent features, which
is R30's actual requirement. The two documents were written independently and agree, which
is the outcome that makes the hunt worth running twice.

Two further wrong assumptions were found while hunting these seven, and both were closed
because they are the same kind of error:

- **That the anti-phishing words prove the SOFTWARE is genuine.** They prove the board.
  Section 4, item U6.
- **That the Verify screen's storage row could be read as evidence about encryption at
  rest.** It cannot: nothing is encrypted at rest in 0.2.0, and R25 already forbids the
  screen from carrying the caveat, which is why the caveat lives at the save fork and the
  wipe-policy screen instead. The shipped security text states it in the tier-1 paragraph
  so it is not left only to a screen the user may never open.

## 4. Claims removed or reworded

Every UNSUPPORTED claim found in this pass was fixed in the text, not flagged. An
overstated security claim is worse than a missing feature, because a user makes decisions
on it.

**U1. "A CI grep over the linked component list."** (docs/SECURITY.md invariant 1, and
plan invariant 1's inherited wording.) No such check exists in `tools/` or
`.github/workflows/`. **Now:** the Cargo-graph half is named as the build gate it is, and
the component half is stated as a pinned lock file plus a release review. If
`tools/ci/check-airgap.sh` lands and greps the component list, this sentence can be
restored to its stronger form; until then it is a review.

**U2. "walletprocesspsbt + testmempoolaccept differential in CI."** (plan invariant 4.) No
CI job runs `bitcoind`. **Now:** stated as a release-time procedure, with the pinned-vector
suite named as the mechanical part.

**U3. "Change is proven by exact descriptor derivation"** without qualification. **Now:**
change is proven from an on-device multisig registration; a single-sig output that claims
to be ours and cannot be proven counts as a payment, which is conservative and is what the
code does.

**U4. "Fee is computed, shown, and bounded."** No fee ceiling exists. **Now:** the fee is
computed, and whether this device's own signatures would enforce it is computed with it, so
a claimed amount is never rendered as a measured one. No bound is claimed.

**U5. "Miniscript's interpreter re-verifies the result."** `miniscript` is not in the
dependency graph. **Now:** the post-sign gate is named for what it is, including the
statement that it shares a digest implementation with the signing path and is therefore not
an independent second implementation.

**U6. Anti-phishing words described only as "device authentication" with the evil-maid
replay limit.** The firmware-replacement boundary was absent from both documents. **Now:**
both say the words catch a different device, not different software on the same device, and
tie it to Secure Boot's absence.

**U6a. "Roughly one guess per second" with the wipe disabled.** Not an overclaim - it
understated the protection - but it is wrong against the pinned cost, and a number a user
plans around should be the measured one. The pinned Argon2id cost is 1827 ms
(`crates/notyas-wallet/src/config.rs:79-89`), so an exhaustive 4-digit search is a few
hours rather than under three, halved on both cores. **Now:** stated as one guess per
Argon2id stretch at the measured cost, in both documents.

**U7. The 0.1.0 document's invariants 5 and 6** asserted Secure Boot v2 RSA-3072, XTS-AES
flash encryption and eFuse anti-rollback on release hardware, and its threat model asserted
that "the device stores no secrets". All four are false for 0.2.0. **Now:** replaced
wholesale by the rewritten normative text, with the four breaks stated as breaks.

## 5. PARITY.md

Every one of the 72 rows now carries a `0.2.0` disposition token, and the file explains the
vocabulary and the two cautions on reading it (a deferred row can still have math in
notyas-core; `BUILDING` and `QUEUED` are statements about a date and are re-checked at the
gate). Tally at the audit date: LANDED 7, BUILDING 13, QUEUED 3, PARTIAL 11, EQUIV 13,
DEFER 18, REJECT 7.

Corrections made to row content, all of them claims that the code does not support:

1. Section 2's preamble said the notyas equivalent is "offline-hard but not
   attempt-limited" (R8) and leaned on flash encryption (R17). Both corrected.
2. Seed Vault: master-seed-keyed encryption replaced by the device PIN ladder (R9), and
   the flash-encryption clause removed.
3. Anti-phishing words: "a device secret in encrypted flash" replaced by the eFuse
   derivation, which is stronger against a board swap, with the firmware-replacement
   boundary added.
4. 13-attempt brick equivalent: restated as N guesses per full-flash restore cycle.
5. Key Teleport: the "encrypted state file over microSD" equivalent removed outright (R10)
   and replaced with "not available; move the mnemonic yourself", in both the row and the
   hardware-impossible table.
6. Clone device and encrypted backups: marked deferred with the R21 consequence stated.
7. Firmware upgrade and downgrade protection: both restated as needing the Secure Boot burn
   Q32 deferred.
8. Nuke Device: "crypto-erase of the flash-encryption-keyed storage" replaced by erase of
   the sealed records plus the wipe-epoch bump, because there is no flash-encryption key to
   erase.
9. Bless Firmware LEDs: the equivalent is now labelled weaker than the row implied, per
   MILESTONES 7.2's explicit instruction to the m13 audit.
10. Dual secure elements and the secure-element key-slot row: flash encryption removed from
    both counter-positions.
11. The summary's row and class counts replaced by R7's recount (72 rows; a=31, b=21, c=14,
    d=6).

## 6. Findings outside this audit's fence

Recorded here because they are release-blocking or claim-relevant, and because the audit's
job is to find them, not to reach across a fence to fix them.

1. **README.md still describes the 0.1.0 security posture.** Line 141 says release hardware
   "is intended to run Secure Boot v2 RSA-3072, flash encryption, and eFuse anti-rollback";
   line 272 lists "Secure Boot v2 on production hardware" as a 0.2.0 headline item; line 148
   says the device "stores nothing". All three are false for 0.2.0 and all three are exactly
   the R30 assumptions. `docs/RELEASE-0.2.0.md` and `VERIFYING.md` already state the
   0.2.0 posture correctly, which makes the front page the one place a reader meets the old
   claims first - the worst place for them to survive.
2. **The frozen partition geometry is not what ships.** R2, R23 and Q7 freeze
   `wallets` at 0xE00000 and `counters` at 0xE40000 with a 2 MiB reserved `media` partition
   at 0xC00000. `firmware/partitions.csv` still carries the superseded 0x410000/0x450000
   layout and declares no `media` partition. Either the freeze never landed at m1 or the
   documents describe a table nobody adopted; VERIFY.md's reserved-space scan, its cost
   table and its raw-digest ranges were all corrected TO the frozen numbers, so they and the
   flashed table now disagree. This must be settled before any device stores a wallet a user
   cares about, because moving data partitions destroys every sealed record.
3. ~~**m5 (SD subsystem) has not started.**~~ **Superseded 2026-08-19: it has landed, and
   is reached by nothing.** `firmware/src/sd/` (`mod.rs`, `mount.rs`, `fs.rs`, `pins.rs`)
   and `crates/notyas-wallet/src/sd.rs` are complete and host-tested against a hostile
   simulated card. `firmware/src/main.rs:55` declares `mod sd;` and no file in the tree
   names `sd::` thereafter. The MILESTONES section 9 clause 2 consequence is unchanged in
   substance - the loop still cannot load a PSBT from SD - but the reason changed from
   absent code to unwired code, which is a different remaining task. The same holds for
   `crates/notyas-wallet/src/transport/` (UR, BBQr, bytewords, fountain): complete, and
   referenced by no firmware or UI file. Recorded as K18.
4. **No PSBT review or signing screens exist.** Re-checked 2026-08-19 and unchanged.
   `crates/notyas-ui/src/screens/` has no PSBT screens, `ScreenId` has no S-27..S-39,
   `RegionId` carries no signing region and `UiRequest` carries no signing request. The
   engine is landed and host-proven - the `notyas-core` lib tests plus `psbt_vectors`,
   `multisig_vectors` and `address_vectors`, all green on 2026-08-19 - and
   `firmware/src/signing.rs`
   has exactly one consumer in the tree, `firmware/src/hil.rs`, which every product image
   excludes. So the on-device review that invariant 7 assumes a user reads does not exist,
   and the device cannot sign. Recorded as K17.
5. **The workspace was transiently broken mid-audit and recovered.** An early
   `cargo test --locked` failed in `crates/notyas-core/src/psbt/codec.rs:379` with four
   unresolved `walk_*` functions, a file being edited by another milestone; the same
   command run at the end of the audit was green (756 passed, 0 failed, 6 ignored). Worth
   recording only because it is the reason the citations in this file are symbol-anchored:
   the tree moved by ten lines in `firmware/src/main.rs` alone while the audit ran.
6. **`firmware/src/store/mac.rs:19` says both development boards are "irreversibly
   eFuse-virgin by owner instruction".** Board B has since been eFuse-provisioned and its
   store formatted, so the comment is stale in a file whose subject is exactly that state.


### 6a. Addendum, 2026-08-19: the shipped UI walked against the spec

Added after the audit date because it changes the answer to the question this file exists to
settle. The audit above checks whether each claim has a mechanism. This addendum checks
something the claim-by-claim method cannot see: whether the mechanism is REACHABLE from the
panel. A claim can be fully enforced in code that no user can get to, and the verdict
`ENFORCED` is then true and misleading at the same time.

Method: start at the screen a device shows at power-on, follow every control that exists, and
for each one that raises a `UiRequest`, read the firmware arm that answers it. Both shipped
geometries. Re-verified against the tree on 2026-08-19, with three other workstreams landing
changes during the walk, so every item below was re-read immediately before being written.

**The finding, stated once.** A device flashed from a release artifact cannot format its
sealed store, because `Store::format` has exactly two call sites and both are in
`firmware/src/hil.rs`, which three independent build fences keep out of every product image.
No screen can collect a new PIN either: of the fourteen `UiRequest` variants, only
`UnsealWallet(Secret)` carries one and it tries an EXISTING PIN. Since `StoreStatus::has_pin`
is true only for `Locked` and `Unlocked`, and both require `StoreState::Formatted`, the lock
screen, PIN entry, the wallet list, the wallet home, Settings and the wipe-policy editor are
unreachable on a shipped unit. A fix was landing as this addendum was written -
`ScreenId::PinCreate` and `UiRequest::SetPin(Secret)` are in the vocabulary, with no screen,
no route and no firmware arm behind them yet - so the citation to re-run is
`grep -rn "SetPin" firmware/src crates/notyas-ui/src` rather than a line number. Full detail:
`docs/KNOWN-ISSUES.md` K13.

**What this does to the verdicts above.** Nothing in sections 1 to 5 becomes false. The
mechanisms cited are present and would fail if they stopped being true. What changes is the
scope of several of them: an invariant about what a stored wallet's sealing does is enforced
over a state a shipped device cannot enter, and an invariant about what the user reads before
signing is enforced over a path with no screen. Those are still worth having - they are what
makes the next release safe - but a reader who takes them as descriptions of the artifact will
be wrong. The five affected classes are the sealed-store invariants, the PIN and attempt
policy, the on-device PSBT review, the SD bounds, and the multisig registration proof.

**The reachability findings, each recorded in `docs/KNOWN-ISSUES.md`:**

| # | Finding | Entry |
|---|---|---|
| a | No PIN can be set, so nothing can be stored, so the whole post-PIN surface is unreachable | K13 |
| b | The save path is offered anyway and its failure is discarded by `Ui::persist_result` | K14 |
| c | Delete wallet takes two-stage typed-name consent and is then refused with no user-visible statement | K15 |
| d | The wipe policy and change-PIN cannot be committed; the change-PIN refusal is silent | K16 |
| e | No PSBT screen exists; the proven engine is reachable only from the excluded bench console | K17 |
| f | The SD subsystem and the QR transport codecs are complete and called by nothing | K18 |
| g | Multisig registration has no screen, so the registration count can only ever be zero | K19 |
| h | The session auto-locks at 120 s with no warning, no countdown and no setting | K20 |
| i | The ratified simple-mode dice door is written and has no call site | K21 |
| j | The reserved-space scan button always answers `not read` | K22 |

**Three findings from the first pass of this walk were fixed before it finished** and are
recorded here so they are not re-reported as open: the touch-UI save path now seals a real
`WalletRecord` through `Wallet::seal_into_free_slot` rather than writing a raw phrase; all
eight payload slots are usable with the slot chosen by the store rather than hardcoded to 0;
and Settings is reachable from the wallet list with Verify device and the network choice as
rows on it, closing the two controls that were previously stranded on the pre-PIN Home. Each
was re-read in the tree on 2026-08-19 before being struck.

**What the artifact IS**, stated positively, because this addendum would otherwise read as a
list of absences: dice and typed-word seed generation with an optional BIP-39 passphrase, a
mandatory backup check, public-key and address export across every supported scheme with QR,
and a device-verification screen reading firmware digests, eFuse security state and the boot
counter. The sealed store, the signing engine, the SD subsystem, the transport codecs and the
eFuse provisioning are all real and all proven on the host or on the bench - the power-cut
record in `docs/m4a-power-cut-evidence.md` is twenty valid cuts with no epoch change and no
sequence regression - and none of them is reached by the shipped UI.
`docs/RELEASE-0.2.0.md` section 0 is the one-page form of this paragraph.

## 7. How to re-run this gate

```
bash tools/build-graph-check.sh            # invariants 1 and 3, and secp present
bash tools/ci/check-dashes.sh              # ASCII hyphens, tracked and untracked
bash tools/ci/check-repro-pins.sh          # the four pinned-version files agree
cargo test --locked                        # every host crate, every vector suite
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --release -p notyas-wallet --test powerloss -- --ignored --nocapture
```

Observed at the audit date, on a tree with m4b mid-edit:

- `tools/build-graph-check.sh`: OK, no banned crates, secp256k1 present.
- `tools/ci/check-dashes.sh`: OK over tracked and untracked files.
- `cargo test --locked`: **756 passed, 0 failed, 6 ignored** across 27 test binaries. The
  three ignored in `notyas-wallet` are the power-loss corpus, which CI runs separately in
  release mode.
- `cargo clippy --locked --all-targets --all-features -- -D warnings`: **fails in
  `notyas-ui` only** - one unused import, two `drop_non_drop`, one `unnecessary_cast`, and
  `too_many_arguments` on the drop-equals-zeroize check function - all in screens being
  written by m4b at the audit date. No other package warns. This is work in flight, not an
  audit finding, and it is recorded so the next runner is not surprised by a red gate that
  has nothing to do with the claims.

Then re-read this file against the tree. A claim whose citation no longer resolves is a
claim that has to be re-earned or removed - that is the whole rule, and it is the reason
the citations name a symbol as well as a line.

The claims that must be re-checked at the m13 gate specifically, because their verdict is
a statement about a date rather than about a mechanism: I2d and the SD half of 2b (m5),
U-W5's duress UX half (m13), I5c's settings screen copy (m4b), and every PARITY row still
holding a `BUILDING` or `QUEUED` token.
