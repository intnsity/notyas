# notyas 0.2.0 - Decision list

Status: **RATIFIED 2026-08-17.** Sixty-one numbered questions are merged here from wave 1,
wave 2, the red team and the wave-3 design documents. On 2026-08-17 the project owner
instructed that every question with a clear technical optimum be decided for them,
leaving only the ones that turn on money, law, doctrine or risk appetite. That pass is
applied. **Fifty-one are now settled** (thirty-nine ratified in the main pass, Q8 answered
directly by the owner during it, Q22 answered earlier, and Q52-Q61 ratified in the
VERIFY.md sweep below). **Ten remain open**, and they are the only thing the owner needs
to read: they are in the OWNER DECISIONS section directly below, and nothing else in this
file is required to answer them.

**The VERIFY.md sweep (2026-08-17) added ten questions and no owner decisions.** That
document landed after the ratification pass; its section 14 raised ten open items, every
one of which turns on a technical optimum, a measurement, or a consequence of a decision
already taken. They are ratified in place as Q52-Q61 under the milestones that consume
them. The owner's list is unchanged at ten.

No question was deleted. Every settled question keeps its full reasoning in the
RATIFIED DECISIONS section, ordered by milestone so that section doubles as an
implementation reference and as the audit record for why the device behaves as it
does.

**New m1 blocking set: empty.** The original text said "Q1-Q8 block milestone 1". Of
those eight, Q1, Q3, Q4, Q5, Q6, Q7 are ratified, Q8 is answered, and Q2's deadline is
m4b (ESP-SEAL.md 3.6 showed duress needs no format change). **No question the owner
still holds blocks m1**, and none blocks the m3 format freeze. Two owner items have
lead time rather than a milestone - Q43 and Q50 are purchases - and Q50 de-risks m1's
camera spike without gating it.

---

# OWNER DECISIONS

Ten questions. Each one turns on something that is not a technical optimum: money,
licence, doctrine, an outside person, or a tolerance for user harm. Everything else in
this file is decided.

### Q2. Should the duress PIN hide the number of wallets, at a cost paid by every user?
- **Options:** (a) full deniability package - unused slots always filled with
  device-derived ciphertext, and the Verify screen's storage readout degraded to
  "present / blank" permanently and for ALL users, duress or not; (b) duress without
  the package, documented as "a coercer can see how many wallets exist"; (c) no duress
  in 0.2.0, keep the honest "N sealed slots" readout.
- **Recommendation:** (a), off by default. A duress feature that leaks the wallet count
  invites the coercion it cannot survive.
- **What it blocks:** the m4b capacity line, three screens (S-01, S-03, S-46), SECURITY
  invariant 5's wording, and the ratified half of Q37. Not the storage format.
- **Deadline:** m4b.
- **Why it is yours:** (a) imposes a permanent honesty cost on every user, including
  every user who will never enable duress, to protect a minority under coercion. That
  is a values trade, not an engineering one.

### Q9. Which ESP32-P4 silicon revision do production units ship on?
- **Options:** confirm rev v1.x (both bench units are v1.3) and ship the HMAC-eFuse
  ladder as designed; or source rev >= v3.0 and schedule a Key-Manager-backed ladder as
  0.3.x.
- **Recommendation:** confirm the revision before release units are provisioned; if
  >= v3.0, schedule the stronger ladder for 0.3.x on the same record format.
- **What it blocks:** m13's provisioning runbook only. No 0.2.0 code depends on it.
- **Deadline:** before m13.
- **Why it is yours:** it is a purchasing and supply decision.

### Q14. Should a backup that carries seed material ever be written to microSD?
- **Options:** (a) seedless backup only - multisig registrations, labels, settings, no
  seed material; (b) also a seed-bearing backup, plus device clone and a Key Teleport
  equivalent, behind an advanced gate.
- **Recommendation:** (a) in 0.2.0 (m9), and decline (b). BACKUP-FEATURES.md OPEN-B1
  recommends the opposite; both positions are honest.
- **What it blocks:** m9 scope, three PARITY rows, the wipe-screen copy, and the m13
  claims audit. Under (b), SECURITY invariant 2b must be amended explicitly.
- **Deadline:** by m9.
- **Why it is yours:** (b) amends the invariant that forbids key material on removable
  media. That is a doctrine change, and this plan's credibility rests on that
  invariant being hard.

### Q30. Move the release signing key onto a hardware token before 0.2.0 ships?
- **Options:** buy an OpenPGP card / YubiKey, generate a revocation certificate and
  hold it offline; or keep the key on disk.
- **Recommendation:** yes, buy it. A wallet vendor's release key on a general-purpose
  disk is the weakest link in the whole verification chain this plan builds.
- **What it blocks:** m13's release gate and every future signed tag. The key identity
  (A1E9 53B2 5C6A 623B 77A1 D522 3AC4 BBCF E51A B37D) does not change.
- **Deadline:** procure now, gate at m13. Lead time means deciding late is deciding
  badly.
- **Why it is yours:** it costs money and it is your key.

### Q31. Recruit an independent builder to publish their own signed SHA256SUMS.txt?
- **Options:** recruit at least one third party and add an `attestations/` directory;
  or ship with only our own claim.
- **Recommendation:** recruit one. Coldcard's credibility here comes from third parties
  publicly matching builds, not from the vendor's own assertion.
- **What it blocks:** release timing (a human has to be lined up in advance) and the
  repo layout.
- **Deadline:** m13.
- **Why it is yours:** it means asking a named outside person for their time.

### Q32. Whose secure-boot key is burned into release hardware?
- **Options:** (a) we sign and burn our digest, which locks owners out of running their
  own builds; (b) ship unsigned images plus a documented procedure for the USER to
  generate and burn their own key; (c) both, as separate download channels.
- **Recommendation:** (b) as the default, with (a) only if assembled units are ever
  sold. Under (a) the UNSIGNED image must also be published and be the object of the
  reproducibility claim, because a vendor-signed image can never be byte-reproduced by
  anyone without the key.
- **What it blocks:** SECURITY invariant 6's text and m13's provisioning runbook. It
  also settles the burn ordering the ratified Q45 needs written down, because under
  (b) a self-builder performs two separate one-way eFuse ceremonies.
- **Deadline:** m13.
- **Why it is yours:** it decides whether an owner of this device can build and run
  their own firmware. That is the product's whole premise.

### Q34. Publish the backup container format as a public specification?
- **Options:** publish the format document so other software can read a notyas backup;
  or keep it in-repo and undocumented externally.
- **Recommendation:** yes, publish the format document. A backup format nobody else can
  read is lock-in by omission. The in-repo reference decoder is a release gate either
  way. Applies only if Q14 ships a backup at all.
- **What it blocks:** m12 documentation. No firmware change.
- **Deadline:** by m12.
- **Why it is yours:** a published format is a standing compatibility commitment.

### Q43. Buy the HIL power-cut rig now?
- **Options:** buy a USB-controlled relay or FET (and optionally an SD-mux); or test by
  hand.
- **Recommendation:** buy the relay/FET now; treat the SD-mux as optional. m4a's "power
  cut taken mid-decrement" gate cannot be faked, and the ratified Q5 makes that gate
  load-bearing: a power cut consumes an attempt by design.
- **What it blocks:** m4a's exit gate.
- **Deadline:** now; lead time.
- **Why it is yours:** it costs money.

### Q50. Buy a known-good Waveshare OV5647 reference module?
- **Options:** buy one (about 10 USD); or run the m1 spike on the bench's existing
  SeedSigner-class module only.
- **Recommendation:** buy it, before the m1 spike if lead time allows. The bench module
  is plausibly a 25 MHz clone against drivers that assume 24 MHz, which makes every
  derived rate 4.17% high and garbled frames an expected outcome of the spike rather
  than a defeat. A clean module turns every future "is it the camera or the firmware"
  question into a two-minute swap.
- **What it blocks:** nothing. It de-risks the m1 camera spike that the ratified Q6
  depends on.
- **Deadline:** now; lead time.
- **Why it is yours:** it costs money.

### Q51. May we contribute code and test data to outside projects under THEIR permissive licence? [NEW 2026-08-17, raised by the Q8 answer]
- **Context:** Q8 settled that everything notyas produces is GPL-3.0-or-later. Two
  planned contributions are not notyas products: the `bbqr` no_std decode is an
  upstream feature PR to SatoshiPortal's MIT crate (PLATFORM.md item 5, MILESTONES
  m12), and the ratified Q39 offers selected adversarial PSBT vectors upstream to HWI
  and Coldcard's psbt_faker, which are permissively licensed. Contributing to either
  means our patch is licensed under the receiving project's terms, not ours.
- **Options:** (a) contribute both, accepting that those specific patches and vector
  files go out permissively; (b) contribute the vectors but not the code patch; (c)
  contribute neither - keep the no_std BBQr work in-tree under GPL-3.0 and keep the
  vectors in-repo under GPL-3.0.
- **Recommendation:** (a). A test vector carries no implementation to protect and gains
  its value from adoption, and a small upstream patch to a crate we depend on is
  maintenance we would otherwise carry forever in a fork. Neither gives away anything
  that handles user keys, which is what the Q8 stance protects.
- **What it blocks:** m12's contribution scope and the SPDX headers on the vector files
  (the harness stays GPL-3.0-or-later under all three options). Nothing in the firmware.
- **Deadline:** by m12.
- **Why it is yours:** Q8 was answered as a position, not just a licence field. Whether
  that position extends to outbound patches under someone else's terms is the same kind
  of call and is not mine to infer.

---

# RATIFIED DECISIONS

Every entry below is settled. Ordered by the milestone that consumes it. Each carries
the decision in one line, then the reasoning that produced it, because the reasoning is
what a later reader or auditor needs in order to understand why the device behaves as
it does.

---

## m1 - foundations, ratified decisions, frozen storage geometry

### Q1. Fully deterministic sealing, no RNG anywhere [was Q4]
**DECISION: the sealing path stays RNG-free** - derived salts, monotonic `seal_seq`
plus one-way `wipe_epoch` for nonce uniqueness, deterministic no-aux-rand BIP-340,
exactly as ARCHITECTURE 2.4 specifies. The P4 TRNG is used for nothing.
*Ratified 2026-08-17 on the project owner's instruction to settle all questions with a
clear technical optimum.*

**Reasoning.** It keeps SECURITY.md invariant 3 mechanically checkable by the
build-graph test rather than promised in prose, and the P4 TRNG is already distrusted
(esp-hal#5982). Accepted cost, recorded rather than hidden: deterministic nonces are
the textbook fault-injection target. The mitigation is the post-sign gate that
re-verifies every signature against an independently recomputed sighash, on a code path
that must not share code with the signing path's digest computation.

**Blast radius.** The highest-leverage decision in the plan. Overruling it would rewrite
SECURITY.md invariant 3, the record format, the whole m3 KDF ladder, and the
build-graph ban list.

### Q4. PIN format and floor [was Q5]
**DECISION: minimum 6 characters, full alphanumeric supported and actively nudged, no
maximum below 64 characters.**
*Ratified 2026-08-17 on the project owner's instruction to settle all questions with a
clear technical optimum.*

**Reasoning.** An entropy meter at creation, with the wording "a digits-only PIN
protects against theft, not against a funded lab". Post-fault-injection, offline
guessing is bounded only by this entropy, which makes the floor a SECURITY.md tier-2
claim rather than a UX preference.

**Blast radius.** m1 SPEC text, the m3 KDF ladder's NFKD normalization and cost target,
and screens 2 and 4.

### Q5. Wipe-after-N default [was Q3]
**DECISION: default N = 10, range 3..=25 inclusive.** The setup screen states the
policy and names what a wipe destroys.
*Ratified 2026-08-17 on the project owner's instruction to settle all questions with a
clear technical optimum.*

**Reasoning.** 10 is stricter than Coldcard's 13 and is affordable because the seed is
re-derivable from the user's own dice rolls or words. The ceiling of 25 is not a
preference: ESP-SEAL.md 8.x sizes the attempt ledger's tail reserve to exactly 25
(rotation fires at `len(attempt_entry) >= 128 - 25`), so 25 is a frozen format
constant and raising it later is a format migration.

**Three corrections applied during ratification. None changes the number; all three are
requirements on the milestones that own it.**

1. **The original justification was false and is struck.** It read "every notyas wallet
   is re-derivable". It is not: multisig registrations, labels and device settings are
   state no mnemonic can re-derive, which is exactly the fact BACKUP-FEATURES.md raised
   and Q14 now owns. The honest justification is: *the seed is re-derivable; the
   registrations and settings are not, which is why Q14(a) exists and why the wipe copy
   must say so.* Until a backup ships at m9, a wipe between m4a and m9 destroys that
   state with no recovery path at all. **Requirement:** the wipe-on-N screens (the
   post-wipe S-48b text and the S-06 setup line) must name registrations and settings
   the way the deliberate-erase screen S-48 already does. The accidental path currently
   discloses less than the deliberate one, which is backwards.
2. **The floor was inconsistent with the frozen API.** `ESP-SEAL.md` declared
   `wipe_after: 1..=25`; `wipe_after = 1` means one mistyped PIN destroys the device.
   Ratified as `3..=25`, and ESP-SEAL.md is amended to match.
3. **"Configurable" is not yet implementable and must be settled at m3.** N lives in
   the superblock at format time and no set-policy operation exists in either
   ESP-SEAL.md's state machine or WALLET-API.md's `Vault` surface, yet S-44 ships a
   live "Wrong-PIN policy" row. **Requirement at m3:** either specify a superblock
   rewrite path for N (using the same A/B commit discipline as a PIN change, permitted
   only from an unlocked session and never lowered below the failures already
   accumulated), or make N format-time-only and render the S-44 row read-only. This is
   inside the m3 format freeze, so it cannot be deferred past it. **This sub-item is
   recorded as open implementation design, not ratified.**

**Also required, because it is real and currently undisclosed:** a power cut taken
between the attempt-cell program and the success-cell write consumes an attempt even
when the PIN was correct. ESP-SEAL.md 4.x makes this deliberate and fail-closed - "a
cut in the middle of a verification must cost a guess, or power-cutting becomes a free
oracle" - and m4a tests for it. The wrong-PIN policy sub-screen must say so, because on
a battery-powered device it is an N-attempt clock that can run with zero wrong PINs
entered. Every hardcoded "10" in the screen copy becomes a format string.

**Blast radius.** The m3 counter bit-log format (the bit budget is sized to N), m4a's
wipe gate, and five copy sites.

### Q6. Camera in 0.2.0 [wave 2, CAMERA.md; CAMERA-HW.md 6.2 merged in]
**DECISION: camera lands in 0.2.0 as m11, subject to the m1 spike passing, sequenced
LAST and individually droppable.**
*Ratified 2026-08-17 on the project owner's instruction to settle all questions with a
clear technical optimum.*

**Reasoning.** CAMERA.md ranks CSI + OV5647 (the module class a SeedSigner already
uses) first, SD-only second, and rejects USB-UVC outright. A working camera closes the
single biggest gap versus the Coldcard Q, and the parity bar is the product bar. The
spike runs inside m1 either way (half a day: plug the module into J1, run the esp-video
`capture_stream` example), because the answer changes the app-size budget the partition
freeze depends on and because the m6 sign-flow UX should not be frozen as "no camera
exists" if one is coming.

CAMERA-HW.md 6.2 refines this into "(a) but droppable", and that refinement is adopted:
every camera parity row has a working SD equivalent, so nothing else in 0.2.0 is
blocked on it, while the riskiest part (the bench replug experiment) is the cheapest
part. m11 splits into six steps - m-camera-0 (the replug experiment, which is m1's
spike), m-camera-1 (the `board::shared_i2c_bus()` refactor, cheap, independent, and
landed with the early infrastructure work), and m-camera-2..5 (esp_video integration,
PPA plus rqrr decode, the ingress validator and fuzz harness, then the scan session in
the UI) at the end of the list, each individually droppable. Partial delivery is
legitimate.

**One correction to the stated blast radius, made during ratification.** Q6 claimed to
BLOCK m1 "because `esp_video` + `esp_cam_sensor` change the app-size budget the
partition freeze depends on". That dependency is unsupported: no document in the set
contains a flash-size figure for `esp_video` - CAMERA.md has none at all, and every
size figure in CAMERA-HW.md is PSRAM or bandwidth, never flash - and the spike as
scoped ("record pass/fail") would not produce one either. m1 was therefore about to
block a permanent decision on an input it never collects. Two things fix it, and both
are adopted: the amended Q7 removes the coupling outright (the camera only ever
affected the app partition's SIZE field, never the offsets, and the size field is no
longer a compatibility surface), and **the m1 spike deliverable gains one line: record
`app.bin`'s byte count for the `capture_stream` build and for a notyas build with the
`camera` feature on.** That number is wanted regardless, because nobody has ever
measured it. For reference, the current 0.1.0 debug build's flash-loadable sections
total roughly 2.5 MiB against a 4 MiB partition.

**Action item embedded in the CAMERA-HW refinement, to apply now rather than at m11:**
place m-camera-1 (`board::shared_i2c_bus()`) in the early infrastructure work. m11's
depends-on line records the intent but no earlier milestone's scope carries it yet.

**Blast radius.** m6's PSBT load path takes a source abstraction so m11 is purely
additive; m11's shape and the position of the I2C-bus refactor. It no longer gates the
partition freeze.

### Q7. Freeze the storage geometry [reconciliation R2]
**DECISION: the partition table below is frozen permanently, identical on both boards.
AMENDED during ratification: the app partition is declared at its collision bound
(0xDF0000) rather than at 8M, so that the frozen table is literally frozen and never
needs a future edit.**
*Ratified 2026-08-17 on the project owner's instruction to settle all questions with a
clear technical optimum, with one amendment.*

```
# Name,    Type, SubType, Offset,   Size,     Flags
factory,   app,  factory, 0x10000,  0xDF0000
wallets,   data, 0x40,    0xE00000, 256K,     encrypted
counters,  data, 0x41,    0xE40000, 16K
```

**Reasoning for the geometry.** ARCH 2.7 put `wallets` at 0x410000, immediately behind
a 4 MB app. 0.2.0 adds miniscript, argon2, the AEAD stack, FATFS and possibly
esp_video; when the app outgrows 4 MB the data partitions move, and moving them
destroys every sealed record on upgrade. Pushing the data to a fixed high offset makes
app growth incapable of relocating a user's wallets.

Arithmetic, checked: the table ends at 0xE44000 = 14,958,592 bytes = 14.27 MiB, inside
board B's 16 MB (1.73 MiB spare) and unchanged on board A's 32 MB, whose extra flash is
simply unused. The app spans 0x10000 to 0xE00000 = 0xDF0000 = 13.94 MiB. App offset
0x10000 is unchanged from 0.1.0, so the Verify screen's running-partition SHA256
procedure stays board-independent. All alignments are legal: 64 KiB for the app offset,
4 KiB for the data partitions and every size.

**Why the size field was amended, and it is the one place the original recommendation
contradicted itself.** The recommendation declared `factory` at 8M and then claimed
13.94 MiB of headroom "before a collision", with the table "frozen now, permanently".
Those cannot both be true. ESP-IDF enforces the size field - the build fails with "app
partition is too small for binary" - which is precisely what MILESTONES relies on when
it says "CI asserts image size against the partition size". So the headroom is not
reachable without editing `partitions.csv`, and the table would demonstrably change.
Editing it is data-safe (growing `factory` moves nothing; the flashers rewrite only
0x8000 and 0x10000, never 0xE00000 and above), but it is not free: REPRODUCIBLE.md
makes `partition-table.bin` a pinned, published, byte-identical release artifact and
offers it to verifiers as "a good first sanity check that your tooling works at all".
Silently churning that hash on a product whose entire pitch is byte-reproducibility is
the wrong trade.

Declaring the app at 0xDF0000 from the first commit makes "frozen permanently" literally
true: no future edit, no artifact-hash churn, and no 5.94 MiB gap belonging to no
partition. **The one thing it costs is the accidental CI tripwire, and that is replaced
deliberately: CI carries an explicit app-size BUDGET constant - fail above 8 MiB, warn
above 6 MiB - which is a policy number that may be edited freely precisely because it is
not a compatibility surface.** This separates the two concepts the 8M field was
conflating: flash geometry, which is permanent, and size discipline, which is a
judgement call. It also removes the coupling to Q6 entirely, because the camera only
ever affected the size field.

**No `nvs`, `otadata` or `phy_init` partition, and one guard to make that stick.** 0.1.0
already ships a single-app table with none of them; NVS is never mounted (invariant 2),
there is no OTA path by decision (an airgapped signer updates by USB reflash, and eFuse
anti-rollback works with a factory-only layout), and `phy_init` is only needed with an
on-die radio the P4 lacks. The risk is that 0.2.0 adds FATFS and possibly
`esp_cam_sensor`, and some sensor drivers persist calibration through NVS - which would
fail at runtime with `ESP_ERR_NVS_PART_NOT_FOUND` on a device with no recovery path.
**Requirement: the Q47 link-map gate also asserts that `nvs_flash_init` and `nvs_open`
are absent from the image.** Same mechanism, same CI job, and it converts an invariant
currently held by prose into one held by the linker. Recorded while it is free: under
these frozen offsets a future 0.2.x OTA scheme would have 13.94 MiB to split, roughly
6.9 MiB per slot plus otadata, so nothing is stranded.

Slot budget inside 256 KiB is as designed: 8 wallet slot pairs, 8 registry record
pairs, 1 header pair, so "8 wallets max" is displayed honestly. Capacity cannot be
raised later without a format migration.

**Blast radius.** m1's deliverable and every stored record for the life of the product.
Interacts with Q2 (filler slots consume the same slot budget). No longer interacts with
Q6.

### Q47. Camera support is a build variant, not a runtime capability [CAMERA-HW.md 6.2]
**DECISION: adopt the build-variant model, and replace m11's unachievable exit gate.**
*Ratified 2026-08-17 on the project owner's instruction to settle all questions with a
clear technical optimum. Paired with Q6, as CAMERA-HW.md 6.2 requires.*

**Reasoning.** The camera works on one of the two hardware-verified boards. Board A
(Waveshare 4B) takes a 15-pin Pi-class OV5647 on J1; board B (Elecrow 5inch) has a
MIPI-CSI path that is not the same path - 24-pin FPC, sensor I2C on a separate 1.8 V
shifted bus, reset driven by the STC8 co-MCU, a factory target of SC2336 - and nobody
on this bench owns that module. BOARDS.md's governing rule is "the build IS the board",
and it had no precedent for a feature only one board can have. Three parts:

1. A cargo feature `camera`, valid only with a board feature whose module declares
   camera hardware, enforced by `compile_error!` in `board/mod.rs` exactly like the
   existing exactly-one-board check, producing a separately hashed artifact
   (`notyas-0.2.0-waveshare-4b-camera.bin` beside `notyas-0.2.0-waveshare-4b.bin`). Two
   artifacts for one board is the honest representation of two hardware configurations.
2. The support statement is per board AND per variant in the BOARDS.md table, with the
   UNTESTED-scaffold discipline: hardware-verified or not shipped. The Elecrow row says
   "camera: not supported (24-pin SC2336 path, no hardware on bench)".
3. Parity language follows the artifact: camera-dependent rows are class b **on the
   camera variant** and stay class c on the base unit. No row claims a capability the
   base artifact does not have.

**The m11 gate correction is part of this decision, not a side effect.** esp-idf-sys
metadata cannot be feature-gated, so the esp_video C sources sit in every build's
component tree; the per-board sdkconfig overlay turns them off. The old gate - "the
camera-off build's image SHA256 is unchanged by the feature's presence in the tree" -
is not achievable. The ratified gate is a LINK-MAP assertion that no camera symbol
reaches the image, plus a pinned hash for each named artifact. That is verification of
absence rather than absence, and the release notes must say which property is being
claimed. Overstating it would be exactly the kind of claim this project's release gate
exists to catch. The independent corroboration is in REPRODUCIBLE.md item 24: the same
metadata limitation already means every board build compiles all seven panel
components. **Per the ratified Q7, this same link-map gate also asserts that
`nvs_flash_init` and `nvs_open` are absent.**

**Status note:** MILESTONES m11's gate text was already pre-emptively rewritten to
"provably free of camera code" with the SHA256 wording surviving only inside a "pending
Q47" correction note. Ratifying is therefore a wording cleanup - delete the scaffolding
and state the settled gate - not a behavioural change.

**Two loose ends this creates that no document has absorbed yet.** REPRODUCIBLE.md's
artifact set enumerates artifacts for `waveshare-4b` and `elecrow-5` with no camera
variant row, and contains no occurrence of the word "camera" at all: the `-camera`
artifact, its `.elf`, its sdkconfig and its `SHA256SUMS.txt` line all need adding, plus
one more row in m12's bit-identical rebuild matrix. And BOARDS.md's support table needs
the per-variant column.

**Blast radius.** The release artifact set and its naming, BOARDS.md's support table,
PARITY.md's class assignment for four rows, m11's exit gate, and m12's
reproducible-build matrix (one more artifact to rebuild bit-identically).

### Q44. The sealing layer lives inside notyas-wallet, not in a separate crate [ESP-SEAL.md 2.4]
**DECISION: no `esp-seal` crate. The sealing layer is a module inside notyas-wallet,
and ESP-SEAL.md remains the authoritative DESIGN document for it.**
*Ratified 2026-08-17 as the direct consequence of the owner's Q8 answer.*

**Reasoning.** ESP-SEAL.md 9.1 stated the consequence up front: under a
GPL-3.0-or-later answer the crate should not be extracted at all, because a GPL3
"platform contribution" that the permissively licensed ESP32/Rust ecosystem will not
depend on is worse than an honest internal module. Q8 answered GPL-3.0-or-later. The
extraction therefore buys nothing and costs a crate boundary and a version-pin
discipline to maintain, so it is not done. This is a scope reduction, consistent with
the standing preference for fewer moving parts.

**This resolves the WALLET-API.md / ESP-SEAL.md overlap in notyas-wallet's favour, and
it must be recorded rather than left to be discovered.** WALLET-API.md 1.2 and 2.3
define a `seal` module that claims the key ladder outright (`device_id`, `stretch`,
`seal`/`open` over two platform traits, owning the Argon2id parameters, the HKDF info
construction, the AAD framing and the ChaCha20-Poly1305 call) and a `store` module that
claims the two-slot A/B commit, the counters area and `seal_seq`/`wipe_epoch`
reconciliation. ESP-SEAL.md claimed the same ground. **WALLET-API.md keeps it.**
ESP-SEAL.md's sections 2-5 are read as the implementation specification of
WALLET-API.md's `seal` + `store` modules: the byte-exact on-flash format, the
mount/unlock/seal/wipe state machine, the power-loss guarantees and the attack analysis
are all still normative and are still ESP-SEAL.md's to own. Only the crate boundary is
withdrawn. One implementation, one address, and the document that lost the address says
so before m3 opens.

**Blast radius.** ARCHITECTURE.md section 1's crate table (no new crate row),
WALLET-API.md's module table, m3's crate list and dependency ledger, and m12's
publication scope (Q46).

### Q8. Licensing for everything this project produces [OWNER-ANSWERED 2026-08-17]
**DECISION: GPL-3.0-or-later, everywhere.** The firmware, notyas-core, notyas-wallet,
notyas-ui, notyas-fonts, the tools, and anything that would otherwise have been
extracted. The owner answered this directly during the ratification pass.

**Reasoning as recorded.** For wallet firmware, GPL-3.0 prevents closed forks of code
that handles user keys. The owner accepts the adoption cost that copyleft imposes on
the low-level pieces, which is real: the ecosystems those pieces would have served
(esp-hal, the esp-idf-* stack, `ur`, `bbqr`, `gt911`) are MIT/Apache and generally will
not take a GPL dependency.

**Consequences, all of them now settled rather than conditional.**
- No crate is extracted. `esp-seal` becomes a notyas-wallet module (Q44) and is never
  published to crates.io (Q46). The `esp-idf-hmac` wrapper, `seedqr` and `bsms` stay
  in-tree under GPL-3.0-or-later; see the m12 entry for what remains of the
  contribution shortlist and why it is still worth something.
- Reconciliation R6 (GPL contagion through `foundation-urtypes`, which is itself
  GPL-3.0-or-later) is moot. There is no permissive crate for it to contaminate, so UR
  and transport code has no placement constraint beyond the ordinary one.
- The clean-room constraint is unchanged and still binds: Trezor's and Jade's code are
  copyleft, so only their published DESIGNS may inform a clean-room implementation.
  Being GPL ourselves does not license a port.
- Fonts are the one carve-out and it survives intact: the IBM Plex TTFs and the
  generated glyph atlases are SIL OFL 1.1, not GPL, with the Reserved Font Name renaming
  ("notyas Sans" / "notyas Mono") already handled in LICENSE-fonts. That distinction is
  load-bearing and must not be flattened into a blanket GPL statement.
- Outbound contributions to other projects under THEIR licence are not covered by this
  answer and are now Q51.

**Blast radius.** Every SPDX header from the first commit; the m12 publication scope;
what "platform contribution" means for this project. Relicensing after publication would
require every contributor's consent, so it is effectively irreversible.

### Q60. The flash unique-ID row ships only if the bench says it works [VERIFY.md 4.6 / 14]
**DECISION: measurement-gated. Ship the row if m1's new V3 bench run returns a plausible,
stable, non-zero unique ID on both fitted parts; otherwise render `not supported`.**
*Ratified 2026-08-17 in the VERIFY.md sweep, on the standing instruction to settle
questions with a clear technical optimum.*

**Reasoning.** This is not a judgement call, it is an experiment whose result nobody has
yet, and VERIFY.md 4.6 documents four independent ways it can come back useless: the vendor
driver may be off by default on P4, GigaDevice's 128-bit IDs may be truncated to 64, the
GD25Q128C shares a JEDEC ID with the E die while lacking the `4Bh` command, and 32 MB parts
in 4-byte address mode probably byte-shift the response. A row that prints a
plausible-looking constant on a part that does not really support the command is worse than
no row: it is exactly the kind of value a reader would compare between two units and draw a
conclusion from. V3 runs on the bench at the same moment as m1's existing M6 JEDEC-ID read,
so finding out costs nothing extra.

**What `not supported` costs, stated so the fallback is not silently weaker than it looks:**
flash-substitution detection then rests on the JEDEC ID and the detected size alone, which
does not catch a swap for the same model of part. That sentence goes in VERIFYING.md, not on
the screen - the screen does not opine (VERIFY.md rule 2).

**Blast radius.** One row in VERIFY.md's identity section, one line in VERIFYING.md, and one
measurement added to m1's harness. No format impact.

---

## m2 - notyas-core signing API

### Q3. ECDSA low-R grinding and the scope of the equivalence claim [was Q13]
**DECISION: adopt low-R grinding (`secp256k1::sign_ecdsa_low_r`).**
*Ratified 2026-08-17 on the project owner's instruction to settle all questions with a
clear technical optimum.*

**Reasoning.** The draft's "byte-identical signatures to Bitcoin Core" was impossible as
written: Core randomizes BIP-341 aux-rand, and grinds ECDSA nonces for low-R (71-byte
DER) while plain RFC6979 does not. Adopting low-R buys Core-identical ECDSA bytes,
predictable 71-byte signatures and therefore exact vsize and fee prediction, and
byte-level differential testing against Core as a CI gate. Predictable signature size
matters on a device that shows a fee it must stand behind, and byte-level differential
testing is a materially stronger gate than "Core accepts it". Schnorr byte-equality
versus Core is impossible under either option and is never claimed.

**Consequence, propagated:** SECURITY.md invariant 4 no longer needs its conditional
wording. ECDSA byte-equality with Core IS claimed and IS tested; Schnorr equality is
claimed only against pinned BIP-340 vectors plus Core-accepts.

**Blast radius.** Blocks m2's signing API shape and its known-answer vectors, not just
SPEC text (R12). Sets SECURITY.md invariant 4's wording.

---

## m3 / m3h - sealing, storage engine, silicon

### Q22. A sealed record never stores the BIP39 passphrase [WALLET-API.md W1]
**DECISION: the BIP39 passphrase is NEVER stored on the device.**
*Resolved 2026-08-17 by the project owner, ahead of this ratification pass. Kept
visible because its two consequences are requirements and its reasoning is
load-bearing.*

The owner's words: "we can leave out storing the bip39 passphrase but warn users it
will not be stored and they need a backup." This matches Coldcard, and it is what makes
a passphrase wallet hidden: the passphrase is typed per session and exists only in RAM.

Two consequences are requirements, not options, and both are acceptance criteria on the
milestones that own passphrase wallets (m3 for the field, m4b/m9 for the copy):

1. **Keep `passphrase_check`.** A BIP39 passphrase produces a DIFFERENT wallet, so a
   silent typo on re-entry yields an empty wallet with no error and the user concludes
   their funds vanished. With a stored verification fingerprint the device says "this
   passphrase does not match the one this wallet was created with" instead of silently
   deriving a stranger's empty wallet. Requirements on the field: it is a KDF-separated
   value derived through a distinct HKDF info label, never the seed and never anything
   from which the passphrase or any key can be recovered; it lives INSIDE the sealed
   record, so it is reachable only after a correct PIN unlock and hands an offline
   attacker no passphrase oracle; and a mismatch is a WARNING the user can override,
   never a hard block, because entering a different passphrase to reach a different
   wallet is a legitimate action.
2. **The not-stored warning is a placement requirement, not one line of copy.** It must
   appear at (i) passphrase entry during wallet creation, before the wallet is saved;
   (ii) the post-creation backup screen; and (iii) any restore or unlock flow that asks
   for a passphrase. Required substance, house voice, plain and factual: the passphrase
   is not stored on this device; anyone restoring this wallet needs BOTH the seed words
   AND the passphrase; a seed backup alone will not recover a passphrase-protected
   wallet; the device cannot help recover a forgotten passphrase. **A one-time explicit
   acknowledgment is required before the first passphrase wallet is saved**, so the
   warning cannot be skipped by muscle memory.

UX-SCREENS.md must carry the exact placement and copy for all three points; if it does
not, that is a gap to patch, tracked in INDEX.md.

**Blast radius.** `passphrase_check` is a RECORD-FORMAT field, so it had to land before
m3 froze the layout; it also touches m4b's unlock flow, m9's Lock Down Seed, and Q2's
filler-slot sizing.

### Q45. eFuse provisioning is a host-side factory step, with no burn code in release firmware [ESP-SEAL.md 4.3]
**DECISION: factory provisioning. Release firmware contains no eFuse-burn code at all.**
*Ratified 2026-08-17 on the project owner's instruction to settle all questions with a
clear technical optimum.*

**Reasoning, both parts load-bearing.** First, invariant 3: notyas has no RNG, and a
device-unique key must be unpredictable, so it has to come from outside. The host
CSPRNG is a trust dependency we can name and audit; the P4 TRNG is already declared
distrusted (esp-hal#5982). Second, firmware that cannot burn eFuses cannot brick a
board through a bug and offers no burn path for a glitch to steer. It also matches how
the release runbook already treats secure boot and flash encryption. Cost: a user who
builds their own firmware from source runs one extra documented command, which is
acceptable for a device whose whole story is "verify your firmware".

**Brick check, performed before ratifying, since the step is irreversible.** The
recommendation strictly REMOVES a brick class rather than adding one.
- *Never provisioned:* the device refuses. `DeviceMac::hmac` must fail rather than
  silently substitute a key when the block is unset, and a release build's
  `accept_provenance` list refuses to mount anything but `EfuseReadProtected`. No wallet
  exists yet, nothing is lost, and the user runs `espefuse.py` later. Fully recoverable;
  the only irreversible step is the one they have not taken.
- *Power loss mid-burn:* handled, and handled better than in-app burning would be,
  because the host tool verifies each burn before proceeding. A cut between the burn and
  the read-protect leaves a burned but readable key, which the product refuses (correct:
  a half-provisioned unit is a refusing unit, not a silently weakened one), and the
  operator re-runs the protect step. A cut during the burn itself leaves a partially
  burned block that espefuse detects on re-read; the operator moves to the next block.
- *Retry budget:* thinner than "six blocks" suggests. One block for the secure-boot
  digest, one for the flash-encryption XTS key, one for the HMAC_UP key, three spare -
  and Secure Boot v2 can occupy up to three digest slots if multiple signing keys are
  enrolled. Three retries with one signing key, one retry with three. **That number
  belongs in the runbook explicitly.**
- *Second attempt on the same block:* impossible by design, and correct. Recovery is
  always a different block.
- *Key loss:* harmless. The host shreds the key file after protecting the block; the key
  is unreadable to everything afterwards, so the host copy has no post-burn value. Loss
  of the CHIP is what loses wallets, which is unchanged and already documented honestly.

**Five amendments this ratification adds, because Q45's original blast radius did not
name them.**
1. **`StoreState::Unprovisioned` and an absent tier on `KeyProvenance` must exist.** The
   state diagram already draws `Unprovisioned -> Blank`, but neither enum can express
   it, so "refuses to format" would degrade into a generic hardware fault - blurring the
   one distinction the design insists on: wrong PIN, corrupt record and hardware fault
   are three different things with three different next steps.
2. **The unprovisioned path reaches further than first save.** The randomized PIN pad
   permutation and the backup quiz's distractor set are both `HMAC_efuse`-derived, so an
   unprovisioned device cannot render its own PIN screen. Specify the behaviour, add the
   refusal screen (S-06 and S-19 have no such edge state), and give the Verify screen's
   `HMAC eFuse key` row a "not provisioned" value - that row must read true state, never
   a constant.
3. **The restore path burns too, and must stop.** BACKUP-FEATURES.md 2.6 says "restore
   onto a device that has never been provisioned burns the eFuse HMAC key and sets a PIN
   as part of the flow". Under this decision it refuses instead.
4. **Burn ordering must be written down and is not cosmetic.** Flash encryption in
   Release mode disables the UART download path, and `espefuse.py` reaches the chip over
   that same path. The runbook must state that HMAC-key provisioning happens BEFORE the
   flash-encryption and secure-boot burns, and must say why. **This is the one place
   Q45 depends on an owner decision:** under Q32(b) a self-builder performs two
   independent one-way ceremonies and the ordering becomes their problem, so the
   build-from-source instructions inherit it. Resolve the wording with Q32; the
   factory-provisioning decision itself holds under every Q32 outcome. Related
   pre-existing conflict to close at the same time: REPRODUCIBLE.md scopes eFuse burning
   OUT of 0.2.0 while MILESTONES m13 scopes it IN.
5. **The build-graph check's specification is too narrow to enforce this.**
   ESP-SEAL.md already describes the right check - assert `esp-seal-sim` absent,
   `unsafe-emulated-key` off, `provisioning` off, with `release.ps1` refusing to produce
   an artefact otherwise - but REPRODUCIBLE.md and MILESTONES describe the check as a
   banned-crate walk only. Extend the specification to feature-state assertions, at m3h.

**Mechanics that follow.** The `Provisioner` still exists behind a non-default
`provisioning` feature, because a general-purpose sealing layer must serve products that
provision in the field; notyas release builds never enable it, and the build-graph check
asserts that. `P1..P4` (host CSPRNG key generation, `espefuse.py burn_key ... HMAC_UP`,
write-protect the purpose and read-protect the block, shred the key file, no escrow)
need concrete commands and a block-selection rule written into a user-facing document -
VERIFYING.md currently has no provisioning step at all, and no milestone owns the
build-from-source half.

**Naming defect to fix while implementing:** `Vault::provision()` currently means
"format", while `StoreState::Provisioned` also means "formatted". Under this decision
PROVISION is the irreversible host ceremony. Rename, so one codebase does not carry two
meanings of the word.

**Blast radius.** Amends ARCHITECTURE 2.2's "burned at first save" and its firmware work
list; amends MILESTONES R20, the m4a first-save path and the m4a "runs on board B first
(eFuse burn)" note; amends BACKUP-FEATURES.md's restore path; adds a build-graph
assertion at m3h; adds a provisioning step to m13's release runbook and to the
build-from-source instructions. No record-format impact.

### Q53. The boot log takes reserved ledger space, and its cell count is sized by M6 [VERIFY.md 6.2 / 14]
**DECISION: the boot counter's cell array comes from the ledger sector's reserved region
and the second reserved sector pair - not from shrinking an existing log - and the array is
sized against m1's measured M6 partial-page-program limit. This is inside the m3 format
freeze and cannot be deferred past it.**
*Ratified 2026-08-17 in the VERIFY.md sweep, on the standing instruction to settle
questions with a clear technical optimum.*

**Reasoning.** The boot counter is a bit-clear cell array in the same plaintext `counters`
partition as the attempt log, so it consumes the same scarce resource under the same
physical limit, and adding it after the format is frozen would be a format change under
existing users. That is why VERIFY.md specifies it now and implements it at m4a. Taking the
cells from the reserved region rather than from `attempt_entry`, `attempt_success` or
`pin_gen_log` is the only option that does not weaken a security-relevant budget: the
attempt log's tail reserve is what makes the ratified Q5 ceiling of 25 a frozen constant,
and shrinking it to buy a convenience row would trade a security parameter for a
nice-to-have. Two head words are added (`acknowledged_at` and the boot log's `log_id`).

**Ownership, stated so the edit lands in one place.** ESP-SEAL.md 3.7 owns the sector map;
this decision instructs that document to allocate the array there, and ESP-SEAL.md stays
authoritative for the resulting byte layout. VERIFY.md flagged it rather than deciding it,
which was correct.

**The dependency runs the other way too, and it is an m1 exit-gate consequence:** if M6
comes back below the design's 32 cells per 256-byte page, both the attempt ledger AND this
boot log are re-laid-out together, before m3 writes a line of the format.

**Blast radius.** The `counters` on-flash format for the life of the product; ESP-SEAL.md
3.7's sector map; m1's M6 measurement gains a second consumer; m4a's implementation.

### Q58. The Verify screen prints all three secure-boot key digest slots [VERIFY.md 5.1 / 14]
**DECISION: print all three slots unconditionally, `not burned` for empty ones, with the
revocation bit shown per slot.**
*Ratified 2026-08-17 in the VERIFY.md sweep, on the standing instruction to settle
questions with a clear technical optimum.*

**Reasoning.** The alternative - show only the first burned digest - hides precisely the
case that makes the row worth having: a second signing key enrolled without the owner's
knowledge. Printing three rows where two say `not burned` costs three lines on a scrolling
screen and makes the absence of a second key a *readable value* rather than an inference
from silence, which is the same principle as rendering `not read` instead of a plausible
default.

**Interaction with the owner's Q32, which this does not pre-empt.** Q32 decides WHOSE key is
burned - ours, the user's, or both as separate channels. Under Q32(b), where an owner
generates and burns their own key, a device may legitimately carry a user digest alongside
or instead of a project digest, and the screen showing all three slots is what lets that
owner confirm their own ceremony worked. This decision is about what is displayed and holds
under every Q32 outcome; Q32 remains the owner's.

**Blast radius.** Three rows in VERIFY.md's eFuse section, read through the m3h eFuse
readout surface (`esp_secure_boot_read_key_digests()`), and one line of m13's release-unit
validation. No format impact.

---

## m4a - storage on hardware and PIN unlock

### Q21. Anti-phishing words and the lock-screen word [was Q10]
**DECISION: ship both** - two words derived at half-PIN, plus a user-chosen lock-screen
word.
*Ratified 2026-08-17 on the project owner's instruction to settle all questions with a
clear technical optimum.*

**Reasoning.** Both need only HMAC-eFuse plus UI work. Two limits must be stated on
screen rather than implied away: an evil maid who held the device can enumerate and
replay the words on a look-alike, so they defeat swap-by-a-stranger, not substitution by
someone who had your device; and the words exist only after the eFuse key is
provisioned, so a blank stateless device has none (R20 - and note that under the
ratified Q45 provisioning is a host step, not first save, so the honest phrasing is
"after the device has been provisioned", not "after first save"). Half-PIN display costs
no attempt-counter decrement.

**Blast radius.** m4a screens 2 and 16.

### Q35. PIN pad shuffle domain [UX-SCREENS.md]
**DECISION: accept as specified** - the randomized keypad permutation derives from the
device-bound HMAC ladder with its own HKDF info string.
*Ratified 2026-08-17 on the project owner's instruction to settle all questions with a
clear technical optimum.*

**Reasoning.** It keeps invariant 3 mechanically checkable, and a display permutation
needs unpredictability to an observer between attempts, not cryptographic
unpredictability. Note the interaction the ratified Q45 creates: this derivation is one
of the two paths that cannot run on an unprovisioned device, so it needs the behaviour
specified there.

**Blast radius.** One derivation label in m4a; none elsewhere.

### Q41. The HIL test-mode console [CORPUS.md corpus-3]
**DECISION: accept the proposed package** - build-feature gated, off by default, "HIL
BUILD" banner on the Verify screen, and a release gate asserting the symbols are absent
from the shipped binary.
*Ratified 2026-08-17 on the project owner's instruction to settle all questions with a
clear technical optimum.*

**Reasoning.** Repeatable hardware testing wants a serial console that can inject touch
events and dump the screen model, and that console is an attack surface if it ever
ships. Every mitigation here is mechanical rather than procedural, which is the standard
this project holds itself to. Without it, hardware verification stays a person with a
camera and a checklist.

**Blast radius.** Firmware build features and one m13 release gate.

### Q61. The boot counter counts failed boots, and does not exist on a blank device [VERIFY.md 6 / 14]
**DECISION, in two halves. (i) The counter increments before the boot self-test runs, so a
boot that ends at S-02 is still counted. (ii) It does not exist, and NOTHING is written,
while the store is `Unprovisioned` or `Blank`; the row renders `not counted`.**
*Ratified 2026-08-17 in the VERIFY.md sweep. Half (i) is VERIFY.md's own recommendation;
half (ii) is a correctness fix the sweep found and is not optional.*

**Reasoning for (i).** A boot that failed still happened, and a counter that skips failed
boots is a counter an attacker can advance for free by causing failures. Incrementing first
costs one bit-clear program into an already-erased cell, early in boot, before the UI exists.

**Reasoning for (ii), which is an invariant question rather than a design preference.**
SECURITY.md invariant 2a says of a device with no stored wallet that "nothing is ever
written to flash" - the 0.1.0 stateless property, retained verbatim and mechanically
enforced. A counter that incremented on every power-up would falsify that sentence on every
blank device, and the project's governing rule is that a claim is mechanically enforced or
it is not made. Weakening a headline invariant to buy a convenience row is the wrong side of
that trade, so counting begins when the ledger is formatted - the same moment the device
stops being stateless for every other reason. The row renders `not counted` rather than `0`,
because `0` would be a value the device did not read.

**The honest cost, documented in VERIFYING.md and not on the screen:** the counter answers
"has anyone powered this on since I set it up", not "since it left the factory". The second
question is not answerable on this hardware by any means, so nothing available was lost.

**Blast radius.** m4a's boot path and one row's rendering; VERIFY.md section 6; one sentence
in VERIFYING.md. It removes a conflict with invariant 2a rather than creating one, so
SECURITY.md needs no amendment.

---

## m4b - wallet management UI

### Q37. Wrong-PIN policy visibility [UX-SCREENS.md; explicitly coupled to Q2]
**DECISION, in the form that holds under every Q2 outcome: the wipe threshold is ALWAYS
shown on S-44. The slot count is not a separate question - its visibility is whatever
Q2 decides, and needs no further decision.**
*Ratified 2026-08-17 on the project owner's instruction to settle all questions with a
clear technical optimum. Q37's threshold half is unconditional; its count half is a
mechanical consequence of Q2 and is therefore removed from the open list rather than
left pending.*

**Reasoning.** The two halves are genuinely separable, which is why Q37 can be closed
before Q2 is answered. Showing the threshold is right under (a), (b) and (c) alike: it
tells the user the consequence of their next mistake and it leaks nothing a coercer
cannot obtain by trying a wrong PIN once. The count is different, and Q2 already owns
it in full: under Q2(a) S-01, S-03 and S-46 degrade together to "present / blank"
permanently and for all users; under Q2(b) or (c) they show the true count. There is no
third possibility and therefore nothing left for Q37 to decide. The ratified Q5 adds a
requirement to this screen: the threshold sub-screen must also state that an interrupted
verification consumes an attempt.

**Blast radius.** Three screens and SECURITY invariant 5's wording, all of which move
with Q2 rather than with Q37.

### Q54. Three new `RegionId` values for S-46 [VERIFY.md 11.5 / 14]
**DECISION: accept `VerifyQr`, `VerifyScanFlash` and `VerifyAckBoots`.**
*Ratified 2026-08-17 in the VERIFY.md sweep, on the standing instruction to settle
questions with a clear technical optimum.*

**Reasoning.** They follow UX-SCREENS.md section 4's naming rule and no existing variant
carries the meaning. The alternative - moving the reserved-space scan and the acknowledgement
mark onto a settings screen - separates an action from the value it changes, which is what
makes both legible: `[ Scan ]` sits beside the span list it fills in, and `[ Mark as seen ]`
sits beside the `Since acknowledged` number it resets.

**Blast radius.** Three enum variants in notyas-ui and three rows in UX-SCREENS.md section 4.

### Q55. S-46 is exempt from reflow rule 1 at 800x480 [VERIFY.md 11.4 / 14]
**DECISION: accept the exemption. The body keeps full width on board B rather than moving
actions into a landscape rail, so hex line breaks are identical on both panels.**
*Ratified 2026-08-17 in the VERIFY.md sweep, on the standing instruction to settle
questions with a clear technical optimum.*

**Reasoning.** Reflow rule 3 - "verification data gets the width" - is the governing rule for
a screen made of nothing but verification data, so this is less an exemption than the correct
rule winning where two collide. The property it buys is the one the screen exists for: two
units with different panels, side by side, break their digests at the same character, so a
reader compares blocks rather than re-reading. An exemption argued from an existing rule and
recorded at the point of use is the acceptable kind.

**Blast radius.** One screen's reflow behaviour and one entry in UX-SCREENS.md's reflow table,
which must record the exemption rather than leave it to be discovered.

### Q56. The `wallets` raw digest is post-PIN unless Q2 ships always-filled slots [VERIFY.md 7.4 / 14]
**DECISION, in the form that holds under every Q2 outcome: post-PIN only under Q2(b) or
Q2(c); permitted pre-PIN under Q2(a).**
*Ratified 2026-08-17 in the VERIFY.md sweep. Like Q37, this is a mechanical consequence of
Q2 rather than an independent question, and is closed here so it is not left pending.*

**Reasoning.** Under `Occupancy::Sparse` a blank encrypted partition raw-reads as all `0xff`,
so its digest is a constant anyone can compute in advance; showing it before the PIN
announces blank-versus-not to whoever is holding the device, which is exactly the leak Q2
exists to close. Under `Occupancy::AlwaysFilled` there is no recognisable constant, so the
digest reveals nothing and may sit pre-PIN with the other identity values. There is no third
case, so nothing is left for the owner to decide beyond Q2 itself.

**Blast radius.** One row's pre-PIN eligibility and the CI golden list for the pre-PIN field
set (VERIFY.md 7.4). Moves with Q2; adds nothing to Q2's own cost.

### Q57. The reserved-space scan stays on demand, never at boot [VERIFY.md 3.3, 3.4 / 14]
**DECISION: on demand behind `[ Scan ]`, with a C3 determinate Busy screen.**
*Ratified 2026-08-17 in the VERIFY.md sweep, on the standing instruction to settle
questions with a clear technical optimum.*

**Reasoning.** Under the frozen geometry the scan reads roughly 14 MiB on board B and 30 MiB
on board A - order of a second - to check a value that changes only when someone has written
to flash outside the partitions. Paying that on every boot, for every user, forever, is the
wrong trade, and the C3 law would force a Busy screen into the boot path to do it. The
rejected alternative is recorded: making the boot self-test a complete integrity pass is a
coherent position, but then it belongs on S-01 with its own progress unit rather than
arriving as a Verify-row default.

**Blast radius.** One button, one Busy screen, and the boot budget - which VERIFY.md 2.5
shows is otherwise unchanged from 0.1.0 by everything that document adds.

### Q59. No mask-ROM digest; report the ROM version fields only [VERIFY.md 4.3 / 14]
**DECISION: print `_rom_eco_version` and `_rom_chip_id`; do not hash the mask ROM.**
*Ratified 2026-08-17 in the VERIFY.md sweep, on the standing instruction to settle
questions with a clear technical optimum.*

**Reasoning.** Two independent reasons, either sufficient. A ROM digest can only ever detect
a *different chip*, never a modified one, because mask ROM is silicon (VERIFY.md section 8
R7) - so it duplicates what the chip-identity rows already say. And no offline reference
exists to compare it against: Espressif published two P4 ROM ELFs covering 97.5% and 99.4% of
the region and neither is the ROM these boards run, so the row would be 64 hex characters
with no comparand, which contract rule 5 exists to prevent. Revisit only if the project ever
runs the per-revision reference enrolment the owner's Q31 contemplates, at which point the
digest becomes comparable and earns a row.

**Blast radius.** Two rows instead of three in VERIFY.md's identity section. The ROM is
readable and hashing it is milliseconds, so the reason not to is not cost - it is that the
number would mean nothing.

---

## m6 - PSBT engine and single-sig signing

### Q12. Stateless signing [was Q11]
**DECISION: yes, ship stateless signing** - a session need not come from a sealed slot,
so a seed loaded transiently by dice or mnemonic entry can sign a PSBT with storage
never touched. **Amended during ratification: there is NO expert override for the
stateless multisig refusal.**
*Ratified 2026-08-17 on the project owner's instruction to settle all questions with a
clear technical optimum, in the form Q24 requires.*

**Reasoning for yes.** It falls out of the session design and preserves the 0.1.0
identity for storage-averse users, at the cost of some m6 session plumbing and one home
screen state.

**Why the override clause was struck rather than ratified.** Q12 inherited "refused by
default with an expert override" from wave-1 Q11. Q24 - which is WALLET-API.md's own
OPEN-W3 recommendation, written after Q11 - says the opposite and says so explicitly:
"no override ever disables a REFUSAL", naming stateless multisig as a hard rule and
noting "this narrows Q12's suggested override". WALLET-API.md's normative code comments
agree with Q24, not with Q12 (`SigningMode::Stateless`: "Multisig change claims are
refused, not downgraded to a warning: an unverifiable cosigner set is exactly the 2021
attack"), and the reference to the override at WALLET-API.md 5.x already records that
"the override is not implemented in 0.2.0".

The decisive argument is SECURITY.md invariant 7, which is phrased with no exceptions:
"No PSBT input is signed unless ... change is proven by exact descriptor derivation
(multisig change from the on-device registration only, never from PSBT-supplied
xpubs)". Any expert setting that lets a stateless multisig change claim be signed
falsifies a shipped security invariant. Ratifying Q12's clause would have required
rewriting invariant 7, and that trade is not worth making for a mode whose users chose
it precisely to avoid stored state. Two documents therefore carried a licence to build
the one setting Q24 forbids, and both are corrected: MILESTONES m9's stateless line and
UX-SCREENS' S-40 / S-31 override branches.

**One sub-item is NOT ratified and must be settled at m6: the SCOPE of the stateless
multisig refusal.** WALLET-API.md's gate-5 row scopes it to "any input or output whose
script is multisig", which refuses all stateless multisig signing; three other places
(the `SigningMode` comment, the `TransientSeed` comment, S-40's copy "a multisig
transaction with change will be refused") scope it to change claims only, implying a
changeless multisig spend is signable. **Recommended answer, and the one invariant 7
forces: the broader scope.** Without a registration the device cannot verify the input's
witness-script membership either, so a stateless multisig signature is unverifiable
regardless of outputs, which makes stateless multisig simply out of scope for 0.2.0.
S-40's copy should say that rather than implying a change-free workaround. Recorded here
so it is decided once, in one place, rather than discovered as a discrepancy at m6.

**Blast radius.** m6 session plumbing, the blank-device home screen, S-40's copy, and
the A9-A13 corpus verdicts.

### Q13. Fee thresholds [was Q12]
**DECISION: warn above 5% of send value or 500 sat/vB; hard-block only on a negative fee
and rust-bitcoin's absurd-fee guard; always show absolute sats, sat/vB and percent.**
*Ratified 2026-08-17 on the project owner's instruction to settle all questions with a
clear technical optimum.*

**Reasoning.** Constants live in notyas-wallet and are adjustable in Settings behind the
expert gate, which is legitimate under Q24 because they are WARNING thresholds.
Coldcard defaults to a 10% cap; 5% warn plus a hard block only on arithmetic
impossibilities is stricter where it costs nothing and looser where a hard block would
be paternalistic. Note the boundary Q24 draws inside the same struct: `warn_percent_of_send`
and `warn_sat_per_vb` are tunable; `sighash` and `hard_max_percent` are not.

**Blast radius.** m6 policy constants and one review screen.

### Q23. Change gap bounds, and no persisted index high-water [WALLET-API.md W2]
**DECISION: anchor on the highest index among this PSBT's own inputs for that
descriptor, with `forward: 200` and `ceiling: 100_000`. No per-wallet high-water is
persisted.**
*Ratified 2026-08-17 on the project owner's instruction to settle all questions with a
clear technical optimum.*

**Reasoning.** An airgapped device has no chain view, so change-index plausibility needs
an anchor. Persisting a high-water would mean a flash write on every signature - wear,
latency, and a write the user did not ask for, against UX commandment 6 - to tighten a
case that is already handled with a warning rather than a refusal. Re-check both
constants against real coordinator behaviour at m6.

**Blast radius.** m6 policy engine. The rejected option (b) would also have made this a
record-format change, which is the main reason it had to be decided before m3 rather
than at m6.

### Q24. Expert overrides may tune warnings and may never disable a refusal [WALLET-API.md W3; UX-SCREENS.md]
**DECISION: the line is drawn at warnings versus refusals.**
*Ratified 2026-08-17 on the project owner's instruction to settle all questions with a
clear technical optimum. This is the strongest security-relevant ratification in the
pass and it narrows two other questions.*

- **No override ever disables a REFUSAL.** SIGHASH_ALL/DEFAULT-only, the stateless
  multisig rule, ownership re-derivation and the post-sign gate are hard rules. The enum
  variants exist so the future is expressible, but no Settings screen turns them on. A
  setting that disables the check which stops output substitution is a setting an
  attacker will talk a user into enabling, and the device cannot detect that
  conversation. This narrows Q12.
- **An expert toggle MAY adjust WARNING thresholds** - the fee percentage and sat/vB of
  Q13, the lookalike-address sensitivity of Q42 - with each override individually named
  and no master bypass. Accepted on that boundary: refusing to build any gate at all
  pushes determined users toward patched firmware, which is worse.

**Reasoning.** SECURITY.md invariant 7 is written without exceptions, and Q24's own
blast radius already recognised that "the warning/refusal line is also the sentence
SECURITY.md invariant 7 has to keep true". Either the invariant is unconditional or the
override exists; it cannot be both.

**Six places carried the opposite licence and are corrected as part of this
ratification.** ARCHITECTURE 5.3 check 7's "(expert-gated otherwise)" on the sighash
whitelist; UX-SCREENS' S-31 "Hold to sign anyway" branch for an unverified change
claim; S-31's stateless override badge; S-33's "refused by default ... unless the expert
override is on" for unknown script types; S-49's "multisig change will be shown as
UNVERIFIED instead of refused"; and, most visibly, S-44's own copy, which promised
"Expert options let you sign transactions this device would otherwise refuse" - the
exact thing this decision forbids, on the screen Q24 cited approvingly. S-44's copy
becomes "Expert options change when this device warns you. They cannot turn off a check
that makes the device refuse." The corpus's two override clauses (A5's "if signing
proceeds under an override", A21's "(expert gate only)") go with them, and CORPUS.md's
open dependency on A10's verdict closes as "refusal".

**Blast radius.** m6 policy surface, the Settings screen, five UX-SCREENS entries, two
corpus rows, and the sentence SECURITY.md invariant 7 has to keep true.

### Q25. Accepted PSBT size cap [WALLET-API.md W4]
**DECISION: 1 MiB accepted file, re-measured and re-pinned at m6.**
*Ratified 2026-08-17 on the project owner's instruction to settle all questions with a
clear technical optimum.*

**Reasoning.** The cap bounds RAM on a device whose PSRAM also holds a 720x720
framebuffer and the Argon2 arena, while requiring full previous transactions makes real
PSBTs large. Re-measure against the worst realistic case - a many-input consolidation
carrying full prev-txs - before pinning. The refusal must say "this transaction is too
large for the device: N inputs" and suggest splitting, not just fail.

**Blast radius.** m6 limits and one refusal screen; interacts with the m1 Argon2 memory
parameters.

### Q26. `-final.txn` byte format [WALLET-API.md W5]
**DECISION: hex text of the raw transaction, Coldcard's own behaviour, with the exact
bytes confirmed against a real Coldcard output file before the writer ships.**
*Ratified 2026-08-17 on the project owner's instruction to settle all questions with a
clear technical optimum.*

**Reasoning.** Getting this wrong is a silent interop failure - the file looks fine and
the coordinator rejects it - so the confirmation is a corpus item, not a code comment.

**Blast radius.** m6 emission and coordinator interop.

### Q36. Deliver-screen escape hatch [UX-SCREENS.md]
**DECISION: accept.** S-38 keeps the user in the delivery flow until one delivery
succeeds, then offers "Discard signed transaction" after two failures.
*Ratified 2026-08-17 on the project owner's instruction to settle all questions with a
clear technical optimum.*

**Reasoning.** The alternative is a power cycle, which discards the signature anyway
without informed consent. Offering the discard explicitly turns a silent loss into a
consented one.

**Blast radius.** One screen.

### Q40. CI gets a bitcoind [CORPUS.md corpus-2]
**DECISION: a pinned container, run on pull requests that touch notyas-core or
notyas-wallet plus nightly, not on every push.**
*Ratified 2026-08-17 on the project owner's instruction to settle all questions with a
clear technical optimum.*

**Reasoning.** The fast lane stays fast. The operational cost is real - one more image
to maintain - but a signer whose acceptance testing is manual will eventually ship a
transaction the network rejects, and m6's differential gate depends on having a node.

**Blast radius.** CI cost and one maintained image.

### Q42. Lookalike-address warning [CORPUS.md corpus-4]
**DECISION: implement it in m6.** Compare each external output address against our own
derived addresses in the gap window and warn on a prefix/suffix near-match ("this
address resembles your own address at index 7").
*Ratified 2026-08-17 on the project owner's instruction to settle all questions with a
clear technical optimum.*

**Reasoning.** It costs a handful of string comparisons over addresses the device
already derives, and it counters a documented active attack that showing the full
address only partially addresses, because users still compare ends. Sensitivity is a
warning threshold, so Q24's expert gate may tune it; it can never be turned into a
refusal.

**Blast radius.** m6 policy engine and the review screen.

---

## m7 - multisig

### Q15. No on-device BSMS in 0.2.0; `bsms` built only with spare capacity [was Q6]
**DECISION: no on-device BSMS (BIP-129) in 0.2.0.** Descriptor import plus the mandatory
first-address cross-device comparison covers the security need. Build the `bsms` module
at m12 only if m7 finishes with capacity.
*Ratified 2026-08-17 on the project owner's instruction to settle all questions with a
clear technical optimum.*

**Reasoning.** The spec is complete but adoption is thin, and Coldcard implements it on
its EDGE branch only. Note the Q8 consequence: `bsms` is no longer a candidate published
crate, so "BDK has an open request for one" no longer supplies a named external consumer.
It is now purely a question of whether m7 leaves room, and the answer defaults to no.

**Blast radius.** m7 scope.

### Q16. Taproot multisig timing [was Q7]
**DECISION: 0.2.0 multisig is P2WSH `sortedmulti` (BIP-48) only.** Taproot single-sig
(BIP-86) is fully supported for signing; tapscript, multi-leaf and MuSig2 revisit at
0.3.x.
*Ratified 2026-08-17 on the project owner's instruction to settle all questions with a
clear technical optimum.*

**Reasoning.** Interop across Sparrow, Specter and Coldcard is not there yet, and
upstream Coldcard has it on EDGE only. The descriptor model is designed to accept
taproot descriptors later without a format change, so this costs nothing later.

**Blast radius.** m6/m7 scope, and BIP-342 script-path cases stay out of the 0.2.0
corpus.

---

## m8 - animated QR out

### Q18. BBQr alongside UR2 [wave 2]
**DECISION: yes, if the `bbqr` crate clears the dependency ledger** - no RNG, no
network, pinned version, licence compatible with a GPL-3.0-or-later consumer (MIT is).
UR2 stays the default.
*Ratified 2026-08-17 on the project owner's instruction to settle all questions with a
clear technical optimum.*

**Reasoning.** It is Coldcard-family interop for the cost of one encoder. Note that
CONSUMING the MIT `bbqr` crate from GPL-3.0 firmware is unproblematic and is settled
here; CONTRIBUTING the no_std decode back upstream under that project's licence is a
separate question and is Q51.

**Blast radius.** m8 scope and one dependency edge.

---

## m9 - seed math and seed lifecycle

### Q10. Ratify the class-d reject list [wave 2]
**DECISION: all nine rejections stand** - PSBT over USB host protocol, USB virtual disk,
BIP-85 password typing over USB HID, HSM Mode / CKBunker, paper wallets, WIF store,
Delta Mode, Secure Notes and Passwords, and the trick-PIN brick variants.
*Ratified 2026-08-17 on the project owner's instruction to settle all questions with a
clear technical optimum.*

**Reasoning.** The four USB rows are one decision - they all reopen the data port the
airgap posture closes - and rejecting them is a positioning statement, not a gap. No
engineering depends on a yes.

**Blast radius.** Parity messaging and m13 documentation.

### Q17. SeedQR display-out is declined [reconciliation R19; BACKUP-FEATURES.md OPEN-B3/B5]
**DECISION: (a) decline SeedQR display-out.** Scan-IN ships with the camera (Q48);
display-OUT does not ship, and is documented as deliberately declined rather than
pending.
*Ratified 2026-08-17 on the project owner's instruction to settle all questions with a
clear technical optimum. BACKUP-FEATURES.md OPEN-B3 recommended the opposite; its
position is preserved below.*

**Reasoning.** A SeedQR encodes a mnemonic. 0.1.0's invariant 2 corollary is that QR
display covers public values only - never a mnemonic, xprv, seed or WIF. Shipping
display-out means amending the one invariant that makes the whole QR path safe to trust,
for a backup format the user can already produce off-device from the displayed words. On
a device with a 720x720 mnemonic display that is a bad trade. The rejected alternative is
recorded in full: BACKUP-FEATURES.md OPEN-B3 proposed a "secret-QR screen class" with an
explicit warning gate, hold-to-reveal, auto-blank, and a reachability test proving no
other screen can reach it, amending the invariant to "no QR renders a secret except from
the secret-QR screen class, which is gated, held and auto-blanked" - and under that
option the sentence would have to be mechanically enforced by the reachability test or
not made at all. It is a coherent position. It is not the one taken.

**Verified before ratifying: declining costs no other feature.** Seed XOR parts are
delivered and re-entered as WORDS, not as QR, so Q33 does not depend on this. BIP-85's
export routes are "display-only ... and, subject to OPEN-B5, a SeedQR", which degrades
cleanly to words-only. No parity row requires a secret QR.

**Consequences that must be applied rather than assumed.**
- B22, B23 and B24 are dropped. B24's schedule cell still says "0.2.x" with a dead
  dependency on B23, and B24 still appears in the 0.2.x ordering list; both go.
- B14 (BIP-85 passwords, "display and QR only") is "Later", so it does not dangle in
  0.2.0, but its "and QR" clause must be struck now or it reopens the invariant by the
  back door in 0.2.x.
- The `seedqr` module survives, because m11's scan-in needs the decoder. Its ENCODE half
  becomes test-vector-only code. Say so, or someone will wire it to a screen.
- **The corollary this decision protects has been quietly dropped from the 0.2.0
  SECURITY text and must be restored.** 0.1.0's invariant 2 carries it; plan-0.2.0's
  SECURITY.md splits invariant 2 into 2a and 2b and neither half mentions QR display at
  all. MILESTONES R19 promises m13 will "restate the corollary in 0.2.0 terms rather than
  quietly dropping it", and as the text stood it was dropped. Declining display-out while
  deleting the rule that makes the decline enforceable would be the worst of both. The
  sentence is restored to invariant 2a as part of this ratification.
- Q17's stated blast radius said "three PARITY rows". PARITY.md contains one SeedQR row
  and it is a SCAN row, satisfied by Q48. The count is an erratum; the row is documented
  as scan-in only.

**Blast radius.** SECURITY.md invariant 2a's corollary; m9 scope; BACKUP-FEATURES rows
B14, B22-B24; one PARITY row.

### Q33. Seed XOR part generation defaults to dice [BACKUP-FEATURES.md OPEN-B2]
**DECISION: dice default, deterministic as a clearly labeled second option, both
shipped - with the deterministic mode behind its own confirmation screen rather than a
same-screen one-line label.**
*Ratified 2026-08-17 on the project owner's instruction to settle all questions with a
clear technical optimum, with one strengthening amendment.*

**Reasoning.** The two modes are not security-equivalent and the docs say so plainly:
dice-generated parts give information-theoretic secrecy, while Coldcard's deterministic
mode makes every part a function of the master secret, so an adversary holding N-1 parts
holds enough information to determine the seed uniquely and is stopped only by the
preimage resistance of double-SHA256. A computational wall where an information-theoretic
one was available. The stronger guarantee is therefore the default. Deterministic ships
anyway because it buys two real things: a user who still has the seed can regenerate a
lost part, and it is a byte-level interop vector against Coldcard, which is the class of
verifiable-equivalence claim this project makes elsewhere.

**Why the amendment.** Only N-1 parts are rolled (the last is the XOR of the rest), so a
24-word seed costs 99 rolls for 2 parts, 198 for 3, 297 for 4. The two options were
specified as peers on one screen, where the weaker one costs zero rolls against up to
297 - the incentive gradient points at the weak button precisely when the user is most
fatigued - and B7 sits behind no gate beyond the Advanced / Seed Tools gate B6 already
has. A one-line label is not proportionate to a downgrade from information-theoretic to
computational secrecy. Deterministic mode gets its own confirmation screen naming the
downgrade, the same treatment B18 already gets.

**Confirmed, so nobody worries about it later:** shipping dice as the default does not
break reading someone else's split. Parts are ordinary checksum-valid BIP-39 mnemonics
and combine in any order; recombination is generation-mode-agnostic.

**Blast radius.** m9 scope and two screens.

---

## m10 - addresses, messages, exports

### Q11. How loudly must class-c equivalents be shipped? [wave 2]
**DECISION: on-device text only where a user would otherwise hunt for a missing feature**
- NFC transfers, camera scan-in when the camera is absent, battery - documentation for
the rest.
*Ratified 2026-08-17 on the project owner's instruction to settle all questions with a
clear technical optimum.*

**Reasoning.** Every hardware-impossible row has a named equivalent (MILESTONES 7.2). A
line of on-screen text earns its place when it stops a user searching for something that
does not exist; otherwise it is clutter that dilutes the text that matters.

**Blast radius.** m10 and m13 screen copy.

### Q38. Address-list truncation [UX-SCREENS.md]
**DECISION: keep the truncated preview** in S-22's navigation list, with its "never check
an address from this list" statement.
*Ratified 2026-08-17 on the project owner's instruction to settle all questions with a
clear technical optimum.*

**Reasoning.** Users navigate by the characters they already know, and the verification
screen is one tap away and never truncates. The stricter alternative - indices and paths
only - buys a zero-truncation product with no exception to explain, at the cost of making
the list unusable for the thing lists are for.

**Blast radius.** One screen; UX commandment 1's phrasing.

---

## m11 - camera scan-in

### Q48. SeedQR scan-in is accepted, behind mnemonic-entry friction [CAMERA-HW.md 6.4]
**DECISION: yes, gated behind the same friction as manual mnemonic entry, and never a
default-visible action on the general scan screen** - reachable only from the seed import
flow.
*Ratified 2026-08-17 on the project owner's instruction to settle all questions with a
clear technical optimum, with two conditions.*

**Reasoning.** Scanning a seed is genuinely useful - it is what SeedSigner users already
have - and the risk is the risk of typing one in, plus the fact that a camera pointed at
a paper backup is a camera pointed at a paper backup. The 0.1.0 structural rule that no
private value ever leaves the device is about OUTPUT; an input path does not touch it.
This does not reopen Q17: that is display-OUT, and it already recorded scan-IN as
uncontroversial. What is decided here is friction and placement.

**The safety case checked out.** A scanned seed follows exactly the same path as a typed
one - checksum validated, XFP displayed, "use once / save" fork - with no shortcut for
having arrived by camera. Nothing decoded from a QR reaches a transport decoder, let
alone a PSBT parser, without passing an ingress validator that lives in notyas-wallet, is
no_std, allocates nothing unbounded, and is fuzzed on the host. And the structural rule
that answers the "scan this QR to configure your device" phishing shape is already
written: a camera cannot approve anything - no scanned payload may set a flag, skip a
review page, shorten a hold, or change any setting.

**Two conditions attached, both found during verification.**
1. **The autodetect table cannot classify CompactSeedQR, and m11's own exit gate is a
   CompactSeedQR scan.** The order is prefix-driven and total: `ur:` -> UR, `B$` -> BBQr,
   all-digits of a known length -> SeedQR, otherwise plain text subject to the charset
   rule. CompactSeedQR is byte mode - 16 or 32 raw bytes including `0x00` - so it never
   matches all-digits and falls into plain text, which the charset rule rejects. The
   classifier as written cannot pass its own gate. Fix the table at m-camera-3. (Minor:
   the cross-reference to "the charset rule in 5.4" points at the wrong section; it is
   5.2.)
2. **The `seedqr` decoder must be a fuzz target, not only a conformance target.** The
   fuzz deliverable currently covers the ingress validator. The seedqr decoder is
   brand-new code doing 11-bit unpacking on attacker-supplied bytes and is only
   "validated against SeedSigner's published vectors", which is conformance, not hostile
   input. Add it to the m-camera-4 fuzz corpus.

**Blast radius.** The m11 scan-screen action list, the `seedqr` module's caller, one
UX-SCREENS entry, and two additions to m-camera-3/4. No format or invariant impact.

### Q49. Camera viewfinder preview on by default [CAMERA-HW.md 6.4]
**DECISION: on.**
*Ratified 2026-08-17 on the project owner's instruction to settle all questions with a
clear technical optimum.*

**Reasoning.** It costs one PPA pass, it is the only camera-activity indicator this
hardware has - there is no activity LED on the CSI path - and a scan without a viewfinder
is unattributable when it fails, because the user cannot tell aim from focus from decode.

**Blast radius.** One screen and a small per-frame cost already measured in CAMERA-HW 3.6.

---

## m12 - reproducible builds and contributions

### Q27. esptool is the normative image producer if the two tools differ [REPRODUCIBLE.md]
**DECISION: compare esptool and espflash output once during reproducibility bring-up; if
they differ at all, esptool becomes the normative release producer** and espflash stays
the developer flashing tool. Either way, pin the version exactly and record it in
BUILDINFO.
*Ratified 2026-08-17 on the project owner's instruction to settle all questions with a
clear technical optimum.*

**Reasoning.** espflash has open defects around image production, and esptool is the
reference implementation shipped inside the pinned IDF image. One fewer independently
versioned tool in the trusted path.

**Blast radius.** m12's recipe and tools/flash.ps1's role; no firmware change.

### Q28. Do not vendor the ESP-IDF managed components; publish an archival mirror [REPRODUCIBLE.md]
**DECISION: do not vendor for 0.2.0, but publish `components-<tag>.tar.gz` alongside the
release artifacts as an archival mirror, with its hash in the signed SHA256SUMS.txt.**
*Ratified 2026-08-17 on the project owner's instruction to settle all questions with a
clear technical optimum.*

**Reasoning.** `components_esp32p4.lock` pins seven remote components by version and
hash, and the hashes already make substitution detectable, which is the security
property. The risk that remains is registry rot over five years, which a mirror answers
for the cost of one tarball.

**Blast radius.** m12 artifact set; revisit if a component publisher ever yanks.

### Q29. No Nix flake for 0.2.0 [REPRODUCIBLE.md]
**DECISION: no.**
*Ratified 2026-08-17 on the project owner's instruction to settle all questions with a
clear technical optimum.*

**Reasoning.** A flake pins the full closure more strongly than a Docker digest and
appeals to a subset of verifiers, but ESP-IDF under Nix is a real maintenance burden.
Revisit if a contributor owns it.

**Blast radius.** None.

### Q39. Corpus licensing and publication [CORPUS.md corpus-1]
**DECISION, in part: the harness and the generator stay GPL-3.0-or-later, per Q8.**
Selected cases are still worth offering upstream to HWI and Coldcard's psbt_faker, and
the vector files' own licence follows that answer - **both of which are now Q51 and are
NOT ratified here.**
*Partially ratified 2026-08-17. The harness half is settled; the outbound half was
overtaken by the owner's Q8 answer and is escalated rather than silently resolved.*

**Reasoning, and why this one could not be ratified whole.** Q39 originally recommended
licensing the vector FILES permissively (CC0 or MIT) with their own SPDX headers, on the
argument that test vectors gain their value from adoption and carry no implementation to
protect. That argument is still sound on its merits. But it was written as a companion to
Q8's per-crate split, and Q8 has since been answered as a blanket GPL-3.0-or-later
position. Quietly carving CC0 vectors out of a blanket answer would be substituting my
judgement for a decision the owner just made deliberately, and upstreaming to HWI and
psbt_faker (both permissive) is the same shape of question. Both go to Q51.

Default if Q51 is never answered: the vectors stay GPL-3.0-or-later in-repo, and the
upstreaming does not happen. That default costs a community contribution at no
engineering cost, which is the reason to answer Q51 rather than let it lapse.

**Blast radius.** Repo licensing headers on the vector files; one contribution that costs
no engineering because the vectors already exist as m6's gate.

### Q46. The sealing layer stays in-tree and is never published [ESP-SEAL.md 9.1]
**DECISION: no separate repository, no crates.io publication. The sealing layer lives in
notyas-wallet for the life of 0.2.0.**
*Ratified 2026-08-17 as the direct consequence of the owner's Q8 answer.*

**Reasoning.** The question was where `esp-seal` lives and when it is published. Under
Q8's answer and Q44's consequence there is no `esp-seal` to place. Publication is not
deferred; it is withdrawn.

**The contribution is not lost, it changes form, and that is worth stating plainly rather
than dropping the claim.** ESP-SEAL.md itself is published in the repo under
GPL-3.0-or-later: the byte-exact on-flash format, the mount/unlock/seal/wipe state
machine, the power-loss analysis, the honest attempt-counter trust model, and the attack
analysis behind it. Any other project can read all of it and reimplement freely under
whatever licence they like, because a document does not impose its licence on an
independent implementation of the ideas it describes. Nothing in this plan claimed the
value was in the three thousand lines; ESP-SEAL.md 9.1 argued the opposite, that "the
thing worth protecting is the design, which this planning set publishes either way".
Publishing the design and not the crate is a coherent contribution, and it is the honest
description of what 0.2.0 delivers.

**What remains of PLATFORM.md's contribution shortlist under GPL-3.0-or-later, restated
honestly rather than dropped.**
- **esp-seal (item 1):** in-tree module. Contribution = ESP-SEAL.md, published.
- **esp-idf-hmac / esp-idf-ds / esp-idf-key-mgr wrappers (item 2):** in-tree, GPL-3.0.
  The verified gap is real (esp-idf-sys does not bind `esp_hmac.h`; esp-hal has no P4
  HMAC), but the named consumer was esp-idf-hal, which will not take a GPL dependency, so
  "candidate for upstreaming into esp-idf-hal" is withdrawn. Residual value: the
  `extra_components` / `bindings_header` recipe is documentable and useful to anyone
  regardless of licence, and it is the silicon leg under every storage row for us. Keep
  m3h; drop the upstream-adoption claim.
- **seedqr (item 3):** in-tree, GPL-3.0. Still the only Rust implementation, still needed
  by m11's scan-in, and under the ratified Q17 its encode half is test-vector-only. No
  external adoption claim survives.
- **bsms (item 4):** in-tree if built at all, per Q15. BDK's open request is no longer a
  reason to build it, because BDK is permissive.
- **no_std BBQr decode (item 5):** the only shortlist item that is an upstream PR to
  someone else's permissive project rather than a crate of ours, which is why it needs
  the owner's sign-off. **Q51.**
- **Reproducible Rust-on-ESP-IDF recipe (item 6):** unaffected, and now the strongest
  remaining contribution. It is a document plus a CI example, licensing is not a barrier
  to anyone reading it, and no published recipe exists for the Rust + esp-idf-sys +
  `-Zbuild-std` stack. It stands on its own.

**Blast radius.** m12's scope loses every "published to crates.io" clause and gains the
document publications; MILESTONES section 9's "done" definition loses "the published
crates build from crates.io for someone who has never seen this repository"; measurement
M9 (crate-name availability on crates.io) is no longer needed.

### Q52. Publish a per-board verification manifest artifact [VERIFY.md 7.3 / 14]
**DECISION: accept. `notyas-<ver>-<board>-VERIFY.json` joins REPRODUCIBLE.md 3.5's artifact
set, is emitted by the container build, and is listed in the signed SHA256SUMS.txt. Its
field set is frozen at m1 because m12's artifact set depends on it.**
*Ratified 2026-08-17 in the VERIFY.md sweep, on the standing instruction to settle
questions with a clear technical optimum.*

**Reasoning.** Without it, the device's digests have no published comparand and the whole
Verify screen degrades to decoration - values a user can read and cannot check. It also
closes the confusion REPRODUCIBLE.md 4.3 calls the single most likely support question, the
difference between the digest of an image's CONTENT and the digest of the FILE, by publishing
both with their offsets and lengths. The rejected alternative - folding the fields into
`BUILDINFO.txt` - fails on a real property: that artifact's format is deliberately loose for
human triage, and an off-device checker needs a stable parse.

**Two consequences that must be applied, not assumed.** REPRODUCIBLE.md 3.5's artifact table
gains the row (and it already owes one for the ratified Q47's camera variant, so both land
together); and m12's bit-identical rebuild matrix gains the manifest, because an artifact
that is published but not reproduced is a gap in exactly the chain this project sells.

**Blast radius.** REPRODUCIBLE.md's artifact set and rebuild matrix, one build-script
deliverable, one VERIFYING.md section, and an m1 freeze of the field set. No firmware change.

---

## m13 - hardening closeout and release

### Q19. Login extras [reconciliation]
**DECISION: Kill Key yes; escalating wrong-PIN delay yes (m4a); configurable long Login
Countdown no; MicroSD 2FA no for 0.2.0.**
*Ratified 2026-08-17 on the project owner's instruction to settle all questions with a
clear technical optimum.*

**Reasoning.** The Kill Key is real when implemented as storage-key zeroization rather
than as a UI gesture. A configurable countdown of 5 minutes to 28 days invites
self-lockout and only deters an attacker who is using the UI, which is not the attacker
the design is worried about. MicroSD 2FA binds unlock to a card serial, which adds a
bricking failure mode for modest gain.

**Blast radius.** Three parity rows; m4a/m13 UI.

---

## Post-0.2.0

### Q20. Blind-oracle unlock mode [was Q9]
**DECISION: not in 0.2.0.** Documented in SECURITY.md as a known alternative with its
tradeoff, revisited only on user demand.
*Ratified 2026-08-17 on the project owner's instruction to settle all questions with a
clear technical optimum.*

**Reasoning.** It is the only known way to give a no-secure-element device real
offline-brute-force resistance, and it is what Jade does. But every unlock would need a
network-connected helper, against the single-device airgap identity that is this
product's whole premise. If it ever returns, a self-hosted oracle over QR transport is
the shape.

**Blast radius.** Documentation only.

---

# Disposition notes

- **Ratification pass, 2026-08-17.** Thirty-nine questions ratified, Q8 answered by the
  owner during the pass, Q22 already resolved: forty-one settled. Nine of the original
  fifty remain open, plus one new question (Q51) raised by the Q8 answer. Every
  ratification was checked against the source documents rather than accepted on its own
  summary; five recommendations needed amendment before they could be ratified, and one
  (Q39) could only be ratified in part. Those are recorded inside the entries, not here.
- **Amendments made during ratification, in one place for auditability:** Q5's false
  "every notyas wallet is re-derivable" justification struck and its floor reconciled with
  the frozen API; Q12's expert-override clause struck as incompatible with Q24 and
  SECURITY invariant 7; Q33's deterministic mode moved behind its own confirmation
  screen; Q45 extended with five spec gaps (an `Unprovisioned` state, the PIN-pad and
  quiz derivation paths, the restore path, burn ordering, and the build-graph check's
  specification); Q48 conditioned on fixing the CompactSeedQR classifier and fuzzing the
  seedqr decoder; Q17 conditioned on restoring the invariant-2 QR corollary that
  plan-0.2.0's SECURITY.md had dropped; Q7's app partition declared at its collision
  bound so that "frozen permanently" is literally true, with the size discipline moved
  to an explicit CI budget constant; and Q6's claim to gate the partition freeze
  withdrawn as unsupported, with the missing app-size measurement added to the m1 spike.
- **Sub-items deliberately left as implementation design rather than ratified:** whether
  the wipe-after-N value is runtime-mutable or format-time-only (Q5, must be settled
  inside m3's format freeze), and the scope of the stateless multisig refusal (Q12, must
  be settled at m6, recommended answer recorded).
- Red team (2026-08-17): everything fixable was fixed directly in the plan texts. Only two
  items needed a human: the duress deniability package (Q2) and the signing equivalence
  scope (Q3). Q3 is now ratified; Q2 remains the owner's.
- Reconciliation (2026-08-17): four questions changed scope or moved earlier - Q2 (later
  relieved to m4b by ESP-SEAL.md 3.6), Q3 blocks m2's API, Q6 blocks the m1 partition
  freeze, and two new questions were raised by cross-checking the documents against each
  other (Q7 storage geometry, Q17 SeedQR display-out). Wave-1 questions Q1-Q13 all survive
  under new numbers; nothing was dropped.
- **R11 relief, recorded because it is why Q2 is not an m1 blocker.** ESP-SEAL.md 3.6
  showed the duress filler needs no format change: a filler slot is a genuine AEAD record
  sealed under a *device-derived* key (`HKDF(filler_root, kdf_salt, RecordInfo)`),
  carrying the same header shape, the same `pin_gen` identity 0, and consuming `seal_seq`
  like any other record. The device tells empty from occupied with one HKDF and one AEAD
  open per slot and no PIN; an attacker without the eFuse key cannot. The format is
  byte-identical under `Occupancy::AlwaysFilled` and `Occupancy::Sparse` - only the
  CONTENT of an unoccupied slot differs. The concrete format beats the inference drawn
  from ARCHITECTURE 2.5's prose, which had no filler construction in it yet. m3 builds the
  filler mechanism unconditionally; Q2 picks the runtime mode.
- **Old question numbers still appear in the wave-1 and wave-3 documents** (ARCHITECTURE,
  SECURITY, WALLET-API, BACKUP-FEATURES, CORPUS, UX-SCREENS cite Q1-Q13 in the wave-1
  numbering). INDEX.md carries the translation table and is the designed mitigation. A
  bulk renumber was considered and NOT done in this pass: it touches seven documents and a
  mis-mapped reference is worse than a reference the table resolves. Two are worth knowing
  because they mislead badly: BACKUP-FEATURES' "Floor | 6 digits (Q5)" means the PIN floor,
  now Q4; SECURITY 2b's "encrypted backups if Q8 is accepted" means Q14, not the licensing
  question.
- Wave-1 to reconciled number map: Q1->Q9, Q2->Q2, Q3->Q5, Q4->Q1, Q5->Q4, Q6->Q15,
  Q7->Q16, Q8->Q14, Q9->Q20, Q10->Q21, Q11->Q12, Q12->Q13, Q13->Q3.
- Wave-3 map: WALLET-API.md W1->Q22, W2->Q23, W3->Q24, W4->Q25, W5->Q26; REPRODUCIBLE.md's
  six OPEN items -> Q27-Q32; BACKUP-FEATURES.md OPEN-B1 -> folded into Q14, OPEN-B2 -> Q33,
  OPEN-B3 (aliased OPEN-B5 in that document's section 6.1) -> folded into Q17 as option
  (b), OPEN-B4 -> Q34.
- UX-SCREENS.md and CORPUS.md map: shuffle domain -> Q35, deliver escape hatch -> Q36,
  wrong-PIN visibility -> Q37, address truncation -> Q38, expert overrides -> folded into
  Q24; corpus-1 -> Q39, corpus-2 -> Q40, corpus-3 -> Q41, corpus-4 -> Q42, corpus-5 -> Q43.
- ESP-SEAL.md map: 2.4 crate boundary -> Q44; 4.3 in-app provisioning -> Q45; 9.1 licence
  -> folded into Q8; 9.1 publish location and timing -> Q46. Its three escalations were
  applied to the plan texts as correctness fixes: the attempt-counter honesty fix, M6 as an
  m1 exit gate, and the R11 relief above.
- CAMERA-HW.md map: 6.2 per-board camera policy -> Q47; 6.2 ship-or-slip -> folded into
  Q6; 6.4 SeedQR scan-in friction -> Q48; 6.4 default preview -> Q49; 1.7 and 6.4
  reference-module purchase -> Q50. Its DECISION items (the shared-I2C-bus refactor, the
  25 MHz clock-mismatch triage rule, the abort criteria, USB-UVC rejection) are its own and
  were not re-litigated.
- **VERIFY.md sweep, 2026-08-17 (Q52-Q61).** That document landed after the ratification
  pass and raised ten items in its section 14. All ten are ratified, none reaches the owner,
  and the owner's list stays at ten. Map: 7.3 manifest artifact -> **Q52** (m12, field set
  frozen at m1); 6.2 boot-log cell budget -> **Q53** (m3, inside the format freeze); 11.5
  RegionId values -> **Q54** (m4b); 11.4 reflow exemption -> **Q55** (m4b); 7.4 `wallets`
  digest pre-PIN -> **Q56** (m4b, mechanical consequence of Q2, like Q37); 3.3/3.4 scan at
  boot -> **Q57** (m4b); 5.1 secure-boot digest slots -> **Q58** (m3h readout, m13
  validation; does not pre-empt the owner's Q32); 4.3 mask-ROM digest -> **Q59** (m4b,
  declined); 4.6 flash unique ID -> **Q60** (m1, measurement-gated on the new V3 run); 6/14
  boot counter on a failed self-test -> **Q61** (m4a, with a correctness fix attached).
- **Three correctness fixes were applied to the plan texts during the VERIFY.md sweep rather
  than raised as questions**, per the standing rule. (1) VERIFY.md was drafted against the
  SUPERSEDED partition geometry - `wallets` at 0x410000, `counters` at 0x450000, a 4 MiB app,
  an 11.7 MiB tail - in sixteen places including its flash map, its scan example, its cost
  table and both wireframes; all are corrected to the frozen Q7 offsets, and the analysis
  that moved with them is restated honestly (MILESTONES R23). (2) Its scan example also
  omitted each image's base offset when computing where that image's tail began; fixed with
  the arithmetic shown. (3) A boot counter incrementing on every power-up would have
  falsified SECURITY invariant 2a on blank devices; the precondition is now stated in
  VERIFY.md section 6 and ratified as Q61(ii) (MILESTONES R24).
- Sweep status: complete through VERIFY.md. Every open item present in docs/plan-0.2.0/ is
  folded in, including the ones that do not use the literal `OPEN:` prefix. No document in
  this directory is owed a sweep. The list runs to **Q61**; a further design document
  continues from Q62.
