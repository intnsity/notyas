# notyas 0.2.0 - Decision list

Status: **OWNER-ANSWERED AND RE-SCOPED 2026-08-18.** Sixty-three numbered questions are
merged here from wave 1, wave 2, the red team and the wave-3 design documents. On
2026-08-17 the project owner instructed that every question with a clear technical
optimum be decided for them; fifty-one were settled in that pass. **On 2026-08-18 the
owner answered the remaining ten**, and those answers re-scoped 0.2.0. All sixty-one
original questions are now settled. **Two new questions were raised by those answers, and
the owner closed both on 2026-08-18: Q62 (must disabling wipe require a longer PIN?)
answered (b), any PIN may disable wipe; Q63 (does "no eFuse burned" include the HMAC key?)
answered (a), secure-boot fuses only, so the Q45 HMAC_UP provisioning proceeds and is the
one burn 0.2.0 performs.** Both answers and their reasoning are in the OWNER DECISIONS
section directly below. **Every question in this set is now settled: nothing here is
open, and no milestone waits on a decision.**

**What the 2026-08-18 answers changed, in one place.** Six things left 0.2.0 entirely and
are recorded in "Deferred to 0.3.0" below: encrypted backups (Q14), BSMS (Q15), the
release-key hardware token (Q30), independent builder attestation (Q31), secure-boot key
ownership and therefore Secure Boot v2 itself (Q32), the backup format publication (Q34)
and the HIL power-cut rig (Q43). Three things changed shape: licensing became a per-crate
split (Q8), the wipe policy became user-settable and therefore a format change inside the
m3 freeze (Q5), and the storage geometry gained a reserved media region (Q7). One thing
stayed and got a gating rule: the camera (Q6) is in 0.2.0, and every exit gate that needs
a physical module is marked **[HW-CAMERA]** so the rest of 0.2.0 can finish without it.

**Read Q32's consequence before anything else, because it is the one that changes what
the product claims.** Deferring Q32 means **0.2.0 ships without Secure Boot v2 burned**.
VERIFY.md is explicit that secure boot is the only check on the Verify screen that does
not depend on the firmware being honest, so without it every value that screen prints is
self-reported by software an attacker may have replaced. This is written into SECURITY.md
tier 1 and invariant 6, into m13's release documentation, and into VERIFYING.md. It is
recorded as a stated limitation of the release, not as an open item.

No question was deleted. Every settled question keeps its full reasoning in the
RATIFIED DECISIONS section, ordered by milestone so that section doubles as an
implementation reference and as the audit record for why the device behaves as it
does.

**Blocking set: empty for every milestone, and now empty of open questions too.** Both
remaining items closed on 2026-08-18: Q62 tuned a threshold inside a policy mechanism
whose format Q5 already specifies in full, and Q63 confirmed that the Q45 HMAC_UP
provisioning is the one burn 0.2.0 performs. No milestone waits on a decision.

---

# OWNER DECISIONS

**One live question (Q63) and one re-presentation (Q62).** Both were raised by the owner's
own 2026-08-18 answers. Q62 turned out to have been answered already in a document that
landed in parallel, so it is recorded as answered and re-presented once, with the
arithmetic, rather than left hanging.

**Two documents landed in this directory alongside the re-scope and both are authoritative
inside their subject. Neither is superseded by anything below.**

- **PIN-MODES.md** (owner-directed, 2026-08-17) is authoritative for PIN, wipe and
  stateless BEHAVIOUR - the three device states, which modal appears where, and the copy
  rules. Q4 and Q5 below defer to it on behaviour and own the on-flash FORMAT and the
  authentication mechanism, which it does not specify. Where the two texts differed, the
  difference is recorded in Q5.1 rather than silently resolved.
- **SECUREBOOT.md** (target 0.3.0) is authoritative for Secure Boot v2, the key-ownership
  decision that was Q32, the burn order and the runbook. The Q32 entry below stays as the
  record of the deferral and its consequences for the security claims; SECUREBOOT.md owns
  the mechanism and the eventual ceremony.

### Q62. Should disabling wipe-on-N require a PIN longer than the 4-digit floor? [raised 2026-08-18; ANSWERED (b), RECONFIRMED AND CLOSED 2026-08-18]

**STATUS: CLOSED.** The re-presentation below was put to the owner with the arithmetic on
2026-08-18 and **the owner reconfirmed (b) unchanged**, which is what this entry said would
close it. PIN-MODES.md records the owner's direct decision of
2026-08-17: *"disabling wipe does NOT require a longer PIN. The 4-digit floor applies in
every state. The warning still states the concrete guess count for the PIN length in use,
so the user makes the trade knowingly; the device does not withhold the setting from
them."* That is a coherent position, it is the owner's, and it is implemented as written.

**It is re-presented here exactly once, with the arithmetic, and then it closes.** The
instruction that produced this entry was to make sure the interaction between a 4-digit
floor and a disable switch was in view before it was decided, and the honest way to
satisfy that is to put the numbers in front of the decision rather than to reopen it. If
the owner reads the table below and does not change the answer, **the answer stands and
this entry is moved into the ratified section unchanged.** No milestone waits on it: m4b
builds the disable-floor as a parameter, so either answer costs the same.

- **The arithmetic, which is the part that may not have been in view.** The PIN floor is 4
  characters (Q4) and the wipe may be turned off (Q5). Each is defensible alone; together
  they interact, and the interaction is not close. The device-bound HMAC-eFuse ladder stops
  OFFLINE attack: every guess must run on this physical board. It does nothing about
  ON-DEVICE guessing, and wipe-on-N is the only thing that bounds that. With wipe off, an
  attacker holding the device grinds the PIN at the pinned Argon2id cost and nothing stops
  them.

  At the m1 target of roughly 1 second per unlock attempt (the pinned range is 0.5-2 s),
  exhausting the whole keyspace costs:

  | PIN | Keyspace | Worst case at 1 s/guess | Mean |
  |---|---|---|---|
  | 4 digits | 10,000 | 2.8 hours | 1.4 hours |
  | 6 digits | 1,000,000 | 11.6 days | 5.8 days |
  | 8 digits | 10^8 | 3.2 years | 1.6 years |
  | 10 digits | 10^10 | 317 years | 158 years |
  | 6 chars, digits + lowercase | 2.2 x 10^9 | 69 years | 35 years |
  | 8 chars, digits + lowercase | 2.8 x 10^12 | 89,000 years | 45,000 years |

  Halve every figure for an attacker who runs their own firmware on both P4 cores, which
  in 0.2.0 needs no key because Secure Boot is not burned (Q32). **A 4-digit PIN with wipe
  disabled is an afternoon's work.** Raising the Argon2 cost does not rescue it: even at a
  punishing 5 s per guess, 4 digits is 14 hours. The PIN length is the only lever.
- **Options, for the record:** (a) disabling wipe requires at least 10 digits, or at least
  8 characters if any non-digit is used, and the settings screen refuses otherwise and
  says why; **(b) any PIN may disable wipe, with the arithmetic stated plainly at the
  moment of the change - THE OWNER'S ANSWER**; (c) a middle floor of 8 digits (1.6 years
  mean), which beats a thief's patience but not a funded lab's.
- **My recommendation was (a); the owner chose (b) and (b) is what ships.** The case for
  (a) is that 10 digits is the shortest all-digit PIN whose exhaustive on-device search
  exceeds a century at the pinned cost. The case for (b), which PIN-MODES.md makes
  explicitly and which is not weak, is that the device should not withhold a setting from
  an informed owner: the warning states the concrete guess count for the PIN actually in
  use, so the trade is made knowingly rather than prevented paternalistically. Under (b)
  the burden moves entirely onto the copy, which is why the disclosure requirements below
  are acceptance criteria and not suggestions.
- **What (b) makes mandatory, and none of it is optional:** the S-44 wipe-policy
  sub-screen computes the warning from the user's ACTUAL PIN length - never a generic
  sentence - naming the keyspace, the measured per-guess cost from m1 and the resulting
  time; the modal offers the longer-PIN path as an action rather than only accept/cancel
  (PIN-MODES.md's requirement, and it is what turns a warning into a choice); and turning
  wipe off is a typed confirmation, not a tap. **SECURITY.md additionally records the
  snapshot consequence** (Q5.3): a flash image captured while wipe was disabled is a
  permanent unlimited-guess oracle for that device, and turning wipe back on does not
  repair it.
- **What it blocks:** nothing. m4b builds the disable-floor as a parameter so both answers
  cost the same, and the policy record carries a `min_pin_len` byte either way, so there
  is no format impact under any outcome.
- **Deadline:** none. It is answered. If the owner does not revisit it, this entry moves
  to the ratified section as answered (b) at the next sweep.

### Q63. Does "no eFuse burned in 0.2.0" include the HMAC key the sealed storage depends on? [NEW 2026-08-18; ANSWERED (a) AND CLOSED 2026-08-18]

**ANSWERED (a) by the owner on 2026-08-18: "no eFuse burned" means no SECURE-BOOT-related
eFuse - no secure-boot digest, no anti-rollback, no flash-encryption key. The HMAC_UP
provisioning of Q45 proceeds as designed and is the one burn 0.2.0 performs.** The
SECUREBOOT.md sentence was narrowed accordingly on the same day; see the recommendation
bullet below for the exact wording that landed. Sealed storage, the PIN ladder, the wipe
policy and multisig registration are all in 0.2.0, and m3, m4a and m4b keep their full
scope.

**The reasoning is retained below as the record of why, because this was a contradiction
between two documents that could not both be implemented, and the next reader deserves to
see how it was resolved rather than only what was decided.**

- **What SECUREBOOT.md says.** It landed in parallel with this re-scope, it is
  authoritative for secure boot, and its opening states that 0.2.0 ships "without Secure
  Boot v2, without flash encryption, and with **no eFuse burned on any device, at any
  point**." Read as written, that is a broader statement than secure boot, and it settles
  the flash-encryption half of this question in the same direction I had recommended:
  **burn nothing, keep the device reflashable.** Agreed, adopted, and the reasoning below
  is retained only as the record of why.
- **What it collides with.** The ratified Q45 provisions a **32-byte HMAC_UP key into an
  eFuse block, host-side with `espefuse.py`, before m4a's firmware runs**, and the entire
  sealed-storage design hangs off it: `device_binding = hmac_efuse(0x01, domain_tag)` is
  the root of `guard_key`, `hdr_key`, `filler_root` and the `bound` session secret. It is
  also what makes each PIN guess require this physical board, which is SECURITY.md tier
  1's whole claim.
- **The consequence if the sweeping reading is the intended one, stated plainly because it
  is severe.** With no HMAC key burned, `KeyProvenance` is absent, `StoreState` is
  `Unprovisioned`, and a correctly implemented device **refuses to format and stores
  nothing at all**. 0.2.0 would then be 0.1.0 with a better signing engine: no stored
  wallets, no multisig registrations, no PIN, no wipe policy - and m3, m4a and m4b would
  lose most of their reason to exist. That is the opposite of the release the owner asked
  for ("a working storage + signing + multisig wallet").
- **Options:** (a) **"no eFuse burned" means no SECURE-BOOT-related eFuse burned** - no
  secure-boot digest, no anti-rollback, no flash-encryption key - **and the HMAC_UP
  provisioning of Q45 proceeds as designed.** This is almost certainly the intent, since
  SECUREBOOT.md's subject is secure boot and its own section 2 excludes "any burn tooling
  pointed at a real device" from ITS preparatory slice rather than from the release; (b)
  literally no eFuse at all, which means no sealed storage in 0.2.0 and a very different
  release; (c) no eFuse at all AND a software-only device binding, which is not a real
  option - a key the software can read is a key an attacker who dumps flash can read, so
  it would make tier 1's "each guess requires the physical device" false and must not be
  built.
- **Recommendation was (a), the owner answered (a), and the wording in SECUREBOOT.md has
  been narrowed to say so (done 2026-08-18).** That document's opening now reads that no
  secure-boot digest, no anti-rollback fuse and no flash-encryption key is burned on any
  device at any point, and that the HMAC_UP provisioning of Q45 is unaffected and is the
  one burn 0.2.0 performs. The edit was held until the owner answered because SECUREBOOT.md
  is another document's subject and the sentence might have been deliberate, in which case
  it would have been a scope decision far larger than a wording fix. It was not.
- **What it blocked:** everything storage, had the answer been (b). Under the answer given
  it blocked nothing, and one sentence changed.
- **Deadline:** met. It was answered before m4a ordered its first burn, and before m3
  closed.
- **Why it was yours:** it is a one-way burn on hardware you own, and under (b) it would
  have deleted the feature the release was named for.

**The flash-encryption reasoning, retained because it is why (a) burns nothing else.**
m13's runbook had four burns: HMAC key, XTS-AES flash encryption, Secure Boot v2,
anti-rollback. Q32's deferral removes the last two (anti-rollback is only meaningful with
secure boot, since without it an attacker flashes any image they like). That leaves flash
encryption, whose mode choice was previously masked by secure boot being present:
  - **Release mode** permanently disables the UART download path. That is the path
    `espefuse.py` uses and the path a user reflashes over. The device would have no
    firmware update route at all, because there is no OTA by design (ARCHITECTURE 2.7,
    factory-only partition table) and 0.2.0 does not ship one.
  - **Development mode** keeps the download path and a bounded re-flash count (m1
    measurement M7 reads the actual field), at the cost that plaintext can still be
    written over the UART downloader by anyone holding the device.
  - **Not burned at all** leaves the `wallets` partition's `encrypted` flag inert: a
    stored wallet is protected by the PIN ladder alone, which the Verify screen already
    reports truthfully.
**Settled by SECUREBOOT.md, and it matches the recommendation: burn no flash-encryption
key in 0.2.0.** It is the only option that keeps the device reflashable, keeps the
reproducible-build story usable by the person it is for - a verifier can flash what they
built - and avoids spending a one-way eFuse on a half-configuration. Release mode is
disqualified outright: it permanently disables the UART download path, and a signer with
no update path is a signer that cannot ship a security fix. The cost is the at-rest
encryption of the `wallets` partition, which matters against a bench attacker with a flash
programmer, and **SECURITY.md tier 1 now says so plainly rather than implying encryption
is present.**

**A pre-existing three-way conflict closes with it, and is recorded so it is not
rediscovered:** m13's runbook scoped flash encryption IN, REPRODUCIBLE.md scoped eFuse
burning OUT of 0.2.0, and ARCHITECTURE's "an airgapped signer updates by USB reflash" is
incompatible with Release mode. All three now agree on "burn nothing but the HMAC key",
subject to the one question above (R29).

---

# DEFERRED TO 0.3.0 (owner instruction, 2026-08-18)

Seven questions were answered "not in 0.2.0". They are settled decisions, not open
items: nothing in 0.2.0 waits on them, and each one names what leaves the release with
it. The consequence of Q32 is the significant one and is stated first.

### Q32. Whose secure-boot key is burned into release hardware? DEFERRED - and 0.2.0 therefore ships WITHOUT Secure Boot v2
**DECISION: held for 0.3.0. Release units do not have Secure Boot v2 burned, and eFuse
anti-rollback goes with it** (anti-rollback protects a signature chain that does not
exist without secure boot).

**This is the one deferral that changes what the product can claim, so it is written
into the security text rather than into a schedule.** VERIFY.md section 9 is explicit
that the Verify screen is produced by the software under suspicion, and that **secure
boot is the only check on that screen which does not depend on the firmware being
honest**: every other row - the running-app digest, the eFuse readout, the storage
state, the boot counter - is a value the firmware reports about itself. With secure boot
burned, a modified image cannot boot, so the readout is trustworthy because the reader
is. Without it, an attacker who has held the device can flash a modified image that
prints whatever digests the owner expects, and nothing on the screen contradicts it.

Stated in plain terms, and this is the sentence the release notes carry: **on a 0.2.0
release unit the Verify screen tells you what the running firmware says about itself. If
you did not build and flash that firmware yourself from a reproduced image, the screen
cannot prove it is the firmware you think it is.** The reproducible-build chain still
works and is still the answer - it just has to be exercised by the owner, on their own
machine, rather than certified by the device.

**Where this lands, all of it required at m13, none of it optional:** SECURITY.md tier 1
and invariant 6 (both rewritten 2026-08-18); the m13 release-unit runbook, which loses
two of its four burns; VERIFYING.md's opening statement of what the procedure does and
does not establish; and the release announcement. Nothing about the record format, the
key ladder or the reproducible build changes.

**What comes back in 0.3.0:** the Q32 options are unchanged and the recommendation
stands - (b), ship unsigned images plus a documented procedure for the USER to generate
and burn their own key, with (a) only if assembled units are ever sold, and with the
UNSIGNED image published and made the object of the reproducibility claim under (a). The
burn ORDER the ratified Q45 needs written down travels with it: HMAC key before flash
encryption and secure boot, because Release-mode flash encryption disables the UART
download path `espefuse.py` uses.

**One question it leaves behind for 0.2.0, which is why Q63 exists:** flash encryption
was going to be burned in the same ceremony, and on its own it has a mode choice that
secure boot's presence used to mask. See Q63.

### Q14. Encrypted backups. DEFERRED whole, both profiles
**DECISION: no backup in 0.2.0** - not the seedless profile the reconciliation
recommended, and not the seed-bearing profile BACKUP-FEATURES.md OPEN-B1 recommended.
Both move to 0.3.0 with their positions intact and undecided between.

**The cost, stated because it is real and it is now unmitigated for the life of 0.2.0.**
Multisig registrations, labels and device settings are the only state a mnemonic cannot
re-derive, and with no backup there is no recovery path for them at all. A wipe - whether
deliberate, or on N failures, or by a power cut that consumed the last attempt - destroys
them permanently. **Requirement, carried from Q5's ratification and now load-bearing
rather than conditional: every wipe surface must name registrations and settings as
things that are destroyed and not recoverable.** That is the S-06 setup line, the S-44
wipe-policy sub-screen, the post-wipe S-48b text, and the deliberate-erase S-48 screen.
SECURITY.md's deterministic-wipe posture paragraph is corrected in the same edit: "every
notyas wallet is re-derivable" was already struck as false, and with Q14 gone there is no
compensating control to point at.

**Consequences applied:** m9's backup scope is removed; PARITY's encrypted-backup, device
clone and Key Teleport rows stay deferred with the honest "no equivalent in 0.2.0"
statement (R10); Q34 goes with it; SECURITY invariant 2b needs no amendment, because
nothing new is written to SD.

### Q34. Publish the backup container format. DEFERRED with Q14
**DECISION: moot for 0.2.0.** There is no backup container to specify. The recommendation
is unchanged for 0.3.0: publish the format, because a backup format nobody else can read
is lock-in by omission, and keep the in-repo reference decoder as a release gate.

### Q15. On-device BSMS (BIP-129). DEFERRED, and the `bsms` module is not built at all
**DECISION: no BSMS in 0.2.0, and no speculative `bsms` module at m12 either.** The
earlier ratification said "build it at m12 only if m7 finishes with capacity"; the
owner's scope instruction removes the conditional. Descriptor import plus the mandatory
first-address cross-device comparison covers the security need, and that is what ships.

### Q16. Taproot multisig. Unchanged and confirmed
**DECISION: 0.2.0 multisig is P2WSH `sortedmulti` (BIP-48) only.** Taproot single-sig
(BIP-86) is fully supported for signing; tapscript, multi-leaf and MuSig2 revisit at
0.3.x. Ratified 2026-08-17, re-confirmed by the owner 2026-08-18. The descriptor model
accepts taproot descriptors later without a format change, so this costs nothing later.

### Q30. Release signing key on a hardware token. DEFERRED
**DECISION: 0.2.0 signs with the existing on-disk key** (A1E9 53B2 5C6A 623B 77A1 D522
3AC4 BBCF E51A B37D). The recommendation is unchanged and stands for 0.3.0: an OpenPGP
card or YubiKey plus an offline revocation certificate. **Documented rather than
implied:** the release documentation states that the signing key is held on a
general-purpose machine, because a verifier's trust in SHA256SUMS.txt is exactly as good
as that key's custody and they are entitled to know which regime it is under. The key
identity does not change when the key later moves to a token.

### Q31. Independent builder attestation. DEFERRED
**DECISION: 0.2.0 ships with only our own signed SHA256SUMS.txt.** No `attestations/`
directory and no recruited third party. The recommendation stands for 0.3.0. **Stated
plainly in the release notes:** the reproducibility claim is currently ours alone, the
recipe is published so anyone can check it, and a matching third-party build is invited
rather than presented as already existing.

### Q43. HIL power-cut rig. DEFERRED, and m4a's gate degrades to a manual method
**DECISION: no rig purchase for 0.2.0; the power-cut gates are performed by hand.**
m4a's "power cut taken mid-decrement" gate cannot be faked and does not go away - it is
load-bearing, because the ratified Q5 makes a power cut consume an attempt by design.
**The method is therefore specified rather than left to improvisation:** pull power at
the USB connector (or a bench inline switch) at a scripted delay after the attempt-cell
program begins, repeated at least twenty times across the window, with the resulting
ledger state read back over the HIL console after each cut and recorded in the milestone
note. That is weaker than a relay in exactly one way - the timing is not repeatable to
the millisecond, so the window is sampled rather than swept - and the milestone note says
so instead of claiming coverage it does not have. The rig moves to 0.3.0, where the sweep
becomes exhaustive.

### Q50. Reference camera module. ANSWERED: the owner will buy a mating module
**DECISION: buy one.** Recorded here with the mating specification so the purchase is
right the first time. Board A (Waveshare ESP32-P4-NANO / 4B class) exposes a **15-pin,
1.0 mm pitch, Raspberry Pi-compatible CSI FPC at J1**, and the supported sensor is the
**OV5647** (the module class SeedSigner already uses). A Waveshare or Raspberry Pi
Camera Module v1.3 (OV5647, 15-pin ribbon) mates directly. Two things to avoid: a
Raspberry Pi Camera v2 (IMX219) or v3 (IMX708), which are different sensors, and a 22-pin
CM4-style ribbon, which is the wrong connector. Board B (Elecrow 5inch) is **not**
compatible with any of these - its path is a 24-pin FPC with a factory SC2336 - and no
purchase makes board B work in 0.2.0.

**Why a known-good module matters even though the bench already has one:** the bench
module is plausibly a 25 MHz clone against drivers that assume 24 MHz, which makes every
derived rate 4.17% high, so garbled frames would be an expected outcome of the spike
rather than a defeat. A clean module turns every future "is it the camera or the
firmware" question into a two-minute swap.

**Until the module arrives, every camera exit gate is marked [HW-CAMERA] and no other
milestone waits on one.** See the ratified Q6.

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

### Q4. PIN format and floor [was Q5] - OWNER-ANSWERED 2026-08-18
**DECISION: minimum 4 characters, full alphanumeric supported and actively nudged, no
maximum below 64 characters.** The owner set the floor at 4; the 2026-08-17 ratification
had proposed 6.
*Owner-answered 2026-08-18. Everything else in the original ratification stands.*

**Reasoning as the owner set it.** A 4-digit minimum is what people expect from a device
with a PIN pad, and the wipe counter is what makes a short PIN survivable. That is a
coherent position and it is the one taken.

**What the floor now rests on, stated because it moved.** With wipe-on-N enabled - the
default, N = 15 - a 4-digit PIN gives an attacker holding the device 15 guesses out of
10,000 before the records are destroyed, which is a 0.15% chance per wipe cycle and is
perfectly sound. Post-fault-injection, offline guessing is bounded only by PIN entropy,
and 4 digits does not survive that: SECURITY.md tier 2 must say so without hedging, and
the entropy meter at creation stays, with the wording "a digits-only PIN protects against
theft, not against a funded lab".

**The floor and the wipe-off setting interact badly, and that is Q62, not this entry.**
With wipe disabled there is no counter and 10,000 on-device guesses is an afternoon. The
floor is not the wrong answer; combining it with a disable switch is the thing that needs
a decision, and it is presented to the owner rather than resolved here.

**Settled in place while it was in front of me: raising the Argon2id cost is not an
alternative to the floor.** At the pinned 0.5-2 s target a 4-digit exhaustive search is
1.4-5.6 hours; at a punishing 5 s per unlock it is 14 hours. An order of magnitude in
per-guess cost buys an order of magnitude, and the gap that needs closing is four orders.
The m1 parameter target is therefore unchanged, and no milestone re-litigates it.

**Blast radius.** m1 SPEC text, the m3 KDF ladder's NFKD normalization and cost target
(unchanged), screens 2 and 4, and the `min_pin_len` byte in the policy record Q5
specifies.

### Q5. Wipe-after-N default, and a user-settable wipe policy [was Q3] - OWNER-ANSWERED 2026-08-18
**DECISION, in four parts.**
1. **Default N = 15**, range 3..=25 inclusive. (The 2026-08-17 ratification proposed 10;
   the owner set 15.)
2. **N is user-settable from an unlocked session**, through the SET-POLICY operation
   specified below.
3. **Wipe-on-N may be turned off entirely**, subject to the disclosure requirements
   below and to whatever Q62 decides about a PIN-length precondition.
4. **The PIN may be removed**, which means exactly one thing and is never presented as
   anything else: the device reverts to 0.1.0 stateless operation and every stored wallet
   is destroyed.

*Owner-answered 2026-08-18. Parts 2, 3 and 4 are new capability and force a design change
inside the m3 format freeze, which is specified here in full rather than deferred.*

**Authority split with PIN-MODES.md, which landed in parallel and is owner-directed.**
That document is authoritative for the BEHAVIOUR: the three device states, that stateless
is a first-class default rather than a degraded mode, that the PIN is introduced at first
save rather than at first boot, which modal appears where, and the copy rules - including
the one that is easy to get wrong and is adopted verbatim here: **turning the PIN off is a
DATA-LOSS event, not a security downgrade, and the copy must not claim the device is
becoming less secure.** A device that stores nothing is the safest state this hardware has;
saying otherwise is false and teaches the wrong instinct. This entry owns the on-flash
FORMAT and the authentication mechanism, which PIN-MODES.md does not specify, and Q5.1
records the one place the two texts differed and why the mechanism below is the way it is.

**Reasoning for 15.** It is close to Coldcard's 13 and comfortably inside the frozen
ceiling. The ceiling of 25 is not a preference: ESP-SEAL.md 8.x sizes the attempt
ledger's tail reserve to exactly 25 (rotation fires at `len(attempt_entry) >= 128 - 25`),
so 25 is a frozen format constant and raising it later is a format migration.

**Corrections from the 2026-08-17 pass, all still binding.**

1. **The original justification was false and is struck.** It read "every notyas wallet
   is re-derivable". It is not: multisig registrations, labels and device settings are
   state no mnemonic can re-derive. With Q14 deferred whole to 0.3.0 there is now **no
   backup at all in 0.2.0**, so a wipe destroys that state permanently with no recovery
   path for the life of the release. **Requirement, hardened accordingly:** every wipe
   surface - the S-06 setup line, the S-44 policy sub-screen, the post-wipe S-48b text
   and the deliberate-erase S-48 screen - names multisig registrations, labels and
   settings as destroyed and not recoverable. The accidental path must not disclose less
   than the deliberate one.
2. **The floor was inconsistent with the frozen API.** ESP-SEAL.md declared
   `wipe_after: 1..=25`; `wipe_after = 1` means one mistyped PIN destroys the device.
   Ratified as `3..=25`, and ESP-SEAL.md is amended to match.
3. **A power cut consumes an attempt, and this must be on the screen.** A cut taken
   between the attempt-cell program and the success-cell write consumes an attempt even
   when the PIN was correct. ESP-SEAL.md 4.5 makes this deliberate and fail-closed - "a
   cut in the middle of a verification must cost a guess, or power-cutting becomes a free
   oracle" - and m4a tests for it. On a portable device that is an N-attempt clock which
   can run with zero wrong PINs entered. Every hardcoded number in the screen copy becomes
   a format string, because N is now variable at runtime.

---

#### Q5.1 The policy record: where a settable policy lives, and how it is authenticated

The 2026-08-17 pass found that "configurable" was not implementable as designed: N lived
in the plaintext superblock at format time and no set-policy operation existed in either
ESP-SEAL.md's state machine or WALLET-API.md's `Vault` surface. The owner's answer makes
a settable N and a settable wipe-off mandatory, so the mechanism is specified here, inside
the m3 freeze, in the same terms as the rest of the format.

**The requirement that shapes everything else: the policy must be enforceable with no PIN
in hand.** MOUNT step M8 runs `if failures >= wipe_after { WIPE }` before any unlock is
possible, so the enforced copy of the policy cannot live inside a PIN-sealed record. It
must be readable at mount. That rules out the obvious answer for the enforced copy, and it
is why the design below uses three copies with different jobs.

**The one place PIN-MODES.md and this entry differ, recorded rather than resolved
silently.** PIN-MODES.md states as non-negotiable that "the wipe policy MUST be
authenticated inside the sealed record, covered by the AEAD's associated data alongside
`wipe_epoch` and `seal_seq`", on the ground that a policy alterable without the PIN makes
the attempt counter theatre. **The ground is correct and is fully honoured below.** The
mechanism cannot be exactly as written, for a reason that is arithmetic rather than
preference: **the wipe fires on FAILED attempts, when no AEAD ever opens.** A policy
readable only after a successful AEAD open could never be enforced against the attacker it
exists to stop, because that attacker never supplies a correct PIN. So the enforced copy
must be readable while locked. What the design does instead is give the AEAD copy the job
PIN-MODES.md actually needs it for - proving a human who knew the PIN authorised this
policy - and put the enforced copy behind a device-bound MAC that an attacker cannot forge
either. **The requirement "policy cannot be altered without the PIN" is met in full:** both
writes that constitute a change need `bound`. PIN-MODES.md's other consequence is adopted
as written - this is a change-PIN-class operation, it commits by the same power-loss rules,
and it cannot be performed from a locked device.

**Policy bytes, 8 bytes, one fixed little-endian encoding used everywhere:**

```
off len field
0    1  wipe_after      u8. 0 = wipe DISABLED (PIN-MODES.md's sentinel); otherwise 3..=25
1    1  flags           bit0 occupancy (0 Sparse, 1 AlwaysFilled; pinned to 1 by Q2),
                        bits1-7 MBZ
2    1  min_pin_len     u8, the floor in force when this policy was written
3    1  MBZ
4    4  policy_gen      u32, strictly increasing, device-global
```

**`wipe_after = 0` is the disabled sentinel, adopted from PIN-MODES.md in preference to a
separate enable flag.** Two encodings for one fact is a defect waiting to happen: a record
with `wipe_after = 7` and the flag clear would have no defined meaning, and something would
eventually pick the wrong half. One field, one meaning, and the floor of 3 applies to
enabled values only.

**Three homes, three jobs. This is the whole answer to "how is it authenticated".**

1. **The ledger `policy_log` is the AUTHORITY.** A new bit-clear cell array in the
   plaintext `counters` partition, in the same guarded-cell style as `pin_gen_log`:

   ```
   cell[i] = policy_bytes[0..8]
           || HMAC(guard_key, b"ESLY" || side || rotation_ctr || u16_le(i)
                              || policy_bytes[0..8])[0..8]           16 bytes
   ```

   `guard_key = HKDF(device_binding, ...)` and `device_binding = hmac_efuse(0x01,
   domain_tag)`, so a valid cell cannot be fabricated without the read-protected eFuse
   key. The effective policy is the highest-index well-formed cell; if the array is empty,
   it is the superblock's format-time policy. `policy_gen` equals the cell's index plus
   one, so the array is self-describing and monotonic by construction.

2. **The superblock carries a MIRROR.** The existing plaintext superblock body keeps
   `wipe_after` and `occupancy` at 0x26/0x27 and gains `policy_gen` (u32, in the MBZ words
   at 0x32) and `min_pin_len` (u8). The body is covered by `body_digest` and `header_mac`
   under `hdr_key`, which is device-bound, so it cannot be edited offline either. Its job
   is speed and readability: mount reads it in one sector read, and the Verify screen
   prints it. **It is never the authority.** If the mirror and the ledger disagree, the
   ledger wins and mount rewrites the mirror.

3. **The canary carries a WITNESS, inside the AEAD.** Identity 0's canary plaintext gains
   `policy_bytes[0..8]` in eight of its trailing MBZ bytes. This copy is sealed under
   `bound`, so writing it requires the PIN. It proves that a human who knew the PIN
   authorised this policy, which is the property neither of the other two copies can
   supply on its own.

**Reconciliation at unlock, once the canary has opened and the PIN is therefore proven:**

| Condition | Meaning | Action |
|---|---|---|
| `canary.policy_gen == ledger.policy_gen` and bytes equal | normal | proceed |
| `canary.policy_gen == ledger.policy_gen` and bytes differ | impossible without forgery | `TamperSuspected(PolicyMismatch)`, fall back to the strict default |
| `canary.policy_gen == ledger.policy_gen - 1` | SET-POLICY was interrupted after its commit | repair: re-seal the canary with the ledger's policy, no user action |
| `canary.policy_gen > ledger.policy_gen` | the ledger was rolled back independently | `TamperSuspected(LedgerRollback)`, strict default |
| any other gap | unreachable | `TamperSuspected`, strict default |

**The strict default, defined once so "fail closed" means something specific:**
`wipe_enabled = 1`, `wipe_after` = the superblock's format-time value, occupancy
unchanged. Every fail-closed path in this design resolves toward wipe being ON, never OFF.
A malformed `policy_log` cell counts as consumed for generation purposes, flags tamper,
and forces the strict default until a later well-formed cell supersedes it - so glitching
a cell during a "turn wipe back on" write cannot preserve an "off" policy.

#### Q5.2 SET-POLICY, and how the change commits power-loss-safely

```
Y1  Require an Unlocked session AND Session::confirm_pin (constant-time compare of a
      recomputed ladder against the session's `bound`; touches no flash, consumes no
      attempt). No PIN, no policy change - this is the whole answer to the attacker
      question below.
Y2  Validate: 3 <= wipe_after <= 25 when enabling; never lower wipe_after below the
      failures already accumulated (that would wipe on commit); occupancy is not
      settable in 0.2.0 (Q2 fixes it to AlwaysFilled) and a request to change it is
      refused rather than ignored.
Y3  If the request DISABLES wipe: under the owner's answer (Q62(b), PIN-MODES.md) there
      is NO PIN-length precondition and the operation proceeds at any PIN length. The
      check is still implemented as a parameter, defaulting to "no floor", so the answer
      is a constant rather than a code change if it is ever revisited. The disclosure
      that replaces the precondition is computed from the PIN just confirmed at Y1, in
      RAM, never from a stored length.
Y4  Program one policy_log cell.                                  <-- COMMIT POINT
Y5  Re-seal identity 0's canary with the new policy bytes into its inactive side,
      following SEAL S1-S8 in full including the read-back verification.
Y6  Rewrite the superblock mirror into its inactive side; erase the stale side.
Y7  Erase the stale canary side.
```

| Cut at | Result |
|---|---|
| before Y4 | Nothing written. Old policy in force. |
| during Y4's cell program | Malformed cell: counts as consumed, flags tamper, forces the strict default. The user re-runs the change. Fail-closed toward wipe ON. |
| after Y4, before Y5 | New policy is in force (the ledger is the authority). The canary is one generation behind, which the reconciliation table repairs at the next unlock without user action. |
| Y5 | Standard SEAL power-loss behaviour: the header MAC either verifies or it does not, and mount elects by `seal_seq`. |
| Y6 or Y7 | Mirror stale or a stale side left behind. Mount rewrites the mirror from the ledger and cleanup erases the stale side. Idempotent. |

**One cell program is the commit, exactly like WIPE's epoch cell and CHANGE-PIN's
`pin_gen` cell.** That is deliberate: the design already has one power-loss story for a
single guarded cell program, and this reuses it rather than inventing a second.

#### Q5.3 The attacker question: what stops someone holding the device from turning wipe off before guessing?

This is the question that decides whether the counter is worth anything, so it is answered
in full rather than asserted.

**Three independent barriers, any one of which is sufficient:**

1. **A policy change requires the PIN.** Both writes that constitute a change - the
   `policy_log` cell and the canary re-seal - are gated on an Unlocked session plus a
   fresh `confirm_pin`. An attacker without the PIN cannot reach SET-POLICY, and every
   attempt to get an Unlocked session spends an attempt against the counter they are
   trying to disable. The ordering is what makes this work: the counter is enforced at
   MOUNT, before any UI exists, so there is no state in which the device is running,
   reachable, and not yet counting.
2. **Offline editing cannot do it.** The `policy_log` cell's guard is keyed by
   `guard_key`, and the superblock mirror is covered by `header_mac` under `hdr_key`; both
   descend from `hmac_efuse(0x01, domain_tag)` and therefore from a read-protected eFuse
   key. An attacker with a flash programmer can write any bytes they like and cannot make
   them verify. A failed guard is malformed, and malformed resolves to the strict default.
   Note the domain separation that makes this hold in practice: embedder-facing
   derivations (anti-phishing words, the PIN-pad permutation) go through `device_derive`
   with tag `0x7F` and length-prefixed inputs, so the device cannot be used as an oracle
   to produce `hmac_efuse(0x01, domain_tag)`.
3. **Deleting is not weakening.** Erasing the `policy_log`, or the whole ledger, does not
   turn wipe off: an empty array falls back to the superblock's format-time policy, which
   has `wipe_enabled = 1`, and a blank ledger beside a non-blank records region is already
   `TamperSuspected(LedgerMissing)` at M2, which refuses everything. There is no erase that
   produces a permissive state.

**What is NOT defended, stated plainly because the alternative is a false claim.** A
consistent **full-flash snapshot and restore** restores the policy along with everything
else, exactly as it already restores the attempt counter (SECURITY.md tier 3, ESP-SEAL.md
7.2). This is not new, but the wipe-off setting makes its consequence qualitatively worse
and that has to be written down:

> With wipe enabled, a full-flash restore buys an attacker N more guesses per restore
> cycle. If a snapshot was taken during a period when wipe was DISABLED, restoring it buys
> unlimited guesses, permanently, for that snapshot. **Turning wipe back on afterwards
> does not repair this**: the old image still exists and still opens with unlimited
> attempts. Any device on which wipe has ever been disabled must be treated as having no
> attempt limit from the moment of the earliest snapshot an attacker might hold.

That sentence goes in SECURITY.md's duress and wipe stance, in VERIFYING.md, and on the
S-44 sub-screen in the user's own words. It is also the strongest argument available for
Q62's option (a).

#### Q5.4 One format consequence the settable policy creates, and its fix

**With wipe disabled, the attempt log can overflow.** `attempt_entry` holds 128 cells and
rotation fires only on a **successful** unlock (ESP-SEAL.md 4.8), which is safe today only
because a failure streak long enough to fill the log would have triggered a wipe first.
Disable the wipe and that guarantee is gone: 128 consecutive failures with no success
exhausts the log, and the existing rules leave the device with nowhere to write the next
attempt. Refusing further attempts would be a permanent lockout, which is worse than the
wipe the user just turned off.

**Fix, inside the m3 freeze:** the ledger head gains `failures_base: u32` in its MBZ region
at 0x40, and the derived quantity becomes

```
failures = head.failures_base + len(attempt_entry) - len(attempt_success)
```

Rotation writes `failures_base` = the failure count in force at rotation time. On today's
post-success rotation that value is 0, so **behaviour on a wipe-enabled device is
byte-for-byte unchanged**. On a wipe-disabled device the log may now rotate on failure as
well, carrying the count forward, so rotation stops being a counter reset and can safely
be reached without a PIN. The cost is flash wear, and it is bounded and worth stating: one
rotation per 128 attempts, 100k erase cycles per sector, is on the order of 12 million
attempts, which at 1 s per Argon2id evaluation is about 148 days of uninterrupted
guessing. The wear is not the wall; the PIN is.

**ESP-SEAL.md owns the resulting byte layout** for `policy_log` (allocated from the ledger
sector's reserved region and the second reserved sector pair, alongside the boot log of
Q53), for the two superblock fields, for the canary's witness bytes, and for
`failures_base`. **All of it is sized against m1's measured M6 partial-page-program
limit**, which now has three consumers: the attempt ledger, the boot log, and this. If M6
comes back below 32 cells per 256-byte page, all three are re-laid-out together before m3
writes a line of the format.

#### Q5.5 Turning the PIN off means destroying the stored wallets, and the screen says exactly that

The owner asked that the user be able to turn the PIN off. **"Keep the stored wallets with
no PIN" is not a thing this device can do**, and the reason is structural rather than a
policy choice: the sealing key is derived from the PIN
(`prestretch = Argon2id(pin, ...)` -> `bound = hmac_efuse(0x02, prestretch)`), so with no
PIN there is no key, and with no key there is no sealed storage. Storing wallets under a
device-only key would mean anyone holding the device can read them, which is not "no PIN",
it is "no protection", and it would falsify SECURITY invariant 2a.

**So "turn the PIN off" is defined as: revert this device to 0.1.0 stateless operation.**
The operation is a WIPE followed by leaving the store unformatted. What it destroys, named
individually on the confirmation screen and not summarised:

- every stored wallet (all sealed records),
- every multisig registration, which cannot be re-derived from any seed and, with Q14
  deferred, has no backup,
- all labels and device settings,
- the anti-phishing words and the lock-screen word, which are re-derived on the next
  format but will not be the same words.

**The copy rule PIN-MODES.md sets, adopted verbatim because it is easy to get backwards:
the modal must NOT claim the device is becoming less secure.** It is becoming a device
that stores nothing, which is the safest state this hardware can be in; the cost is
convenience and data, not security. This is the opposite of the wipe-disable modal, where
no data is lost and the security consequence is the whole point. Two "off" switches,
opposite risks, and a design that describes them the same way teaches the wrong lesson.

**Confirmation is the strongest gate the component library has:** the typed-name danger
modal (grade 3), the same one that guards wallet deletion, with the counts read from the
store - the number of wallets and registrations, not a generic phrase - and note that
under the ratified Q2 those counts are shown *here*, post-PIN, where they are not a leak. After it completes the device is genuinely stateless: nothing is
written to flash, the home screen returns to the 0.1.0 blank-device state, and the boot
counter renders `not counted` again (Q61).

**Blast radius.** The `counters` on-flash format for the life of the product (policy_log,
`failures_base`); the superblock body (two fields); the canary plaintext (eight bytes); a
new `Vault::set_policy` operation in WALLET-API.md's surface; the S-44 wrong-PIN policy
sub-screen and a new PIN-removal flow at m4b; m4a's wipe gate; and every copy site that
hardcoded a number, all of which become format strings.

### Q6. Camera in 0.2.0 [wave 2, CAMERA.md; CAMERA-HW.md 6.2 merged in] - OWNER-CONFIRMED 2026-08-18
**DECISION: the camera is IN 0.2.0. The software path is built now; only the HARDWARE
verification waits on a module arriving.**
*Ratified 2026-08-17, confirmed and re-scoped by the owner 2026-08-18.*

**The gating rule, which is the operative part of the owner's answer.** The owner does not
yet own a mating module and will buy one (Q50). Therefore:

- **Every exit gate that requires a physical camera is marked `[HW-CAMERA]`** in
  MILESTONES.md. A `[HW-CAMERA]` gate is met the day the module arrives and never before,
  and no other milestone's closure depends on one.
- **The m1 camera spike is one of them and moves out of m1.** m1's exit gate previously
  required "the camera spike result committed as pass or fail"; that is now m-camera-0
  inside m11, marked `[HW-CAMERA]`, and m1 closes without it. This is safe because the
  ratified Q7 already removed the spike's only claimed dependency (the partition freeze),
  and the spike's second deliverable - `app.bin`'s byte count with the `camera` feature on
  - needs no module at all, only a build, so it stays in m1 as a pure build measurement.
- **Everything that is not the physical bring-up ships on schedule:** the
  `board::shared_i2c_bus()` refactor (m-camera-1, already pulled into m1's infrastructure
  work), the cargo feature and `compile_error!` guard, the artifact split (Q47), the
  ingress validator and its fuzz harness, the `seedqr` decoder, the autodetect classifier,
  and the scan-session UI. All of it compiles, is unit-tested and is fuzzed on the host
  with no hardware present.
- **0.2.0 may therefore ship with the camera variant built but not hardware-verified.**
  If that happens, BOARDS.md's support column says `camera: built, not hardware-verified`
  and the artifact is published with that statement attached, per the standing rule that a
  capability is hardware-verified or it is not claimed. It is not silently dropped and it
  is not silently claimed.

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

### Q7. Freeze the storage geometry [reconciliation R2] - OWNER-APPROVED 2026-08-18 WITH A MEDIA RESERVE
**DECISION: the partition table below is frozen permanently, identical on both boards. It
gains a 2 MiB reserved `media` region for camera and video assets, taken out of the app's
declared span and not out of the tail, so that every already-frozen offset - `wallets` at
0xE00000 and `counters` at 0xE40000 - is unchanged.**
*Ratified 2026-08-17; amended 2026-08-18 on the owner's approval of the freeze with the
added requirement to leave room for video if it is ever needed.*

```
# Name,    Type, SubType, Offset,   Size,     Flags
factory,   app,  factory, 0x10000,  0xBF0000
media,     data, 0x42,    0xC00000, 0x200000, encrypted
wallets,   data, 0x40,    0xE00000, 256K,     encrypted
counters,  data, 0x41,    0xE40000, 16K
```

**Reasoning for the geometry.** ARCH 2.7 put `wallets` at 0x410000, immediately behind
a 4 MB app. 0.2.0 adds miniscript, argon2, the AEAD stack, FATFS and possibly
esp_video; when the app outgrows 4 MB the data partitions move, and moving them
destroys every sealed record on upgrade. Pushing the data to a fixed high offset makes
app growth incapable of relocating a user's wallets.

**Full arithmetic, re-verified end to end 2026-08-18 with the media reserve in place.**

| Partition | Start | Size | End | Notes |
|---|---|---|---|---|
| (bootloader + table) | 0x0 | 0x10000 | 0x10000 | unchanged from 0.1.0 |
| `factory` | 0x10000 | 0xBF0000 = 12,517,376 = 11.9375 MiB | 0xC00000 | declared at its collision bound |
| `media` | 0xC00000 | 0x200000 = 2,097,152 = 2 MiB | 0xE00000 | reserved, declared, never written in 0.2.0 |
| `wallets` | 0xE00000 | 0x40000 = 262,144 = 256 KiB | 0xE40000 | unchanged offset |
| `counters` | 0xE40000 | 0x4000 = 16,384 = 16 KiB | 0xE44000 | unchanged offset |

- Total consumed: 0xE44000 = 14,958,592 bytes = 14.2656 MiB. **Unchanged by the media
  reserve**, because the reserve came out of the app's declared span rather than out of
  the tail.
- Board B (16 MB = 16,777,216): tail = 1,818,624 bytes = **1.7344 MiB spare, unchanged**.
  That number is load-bearing beyond "spare": under R23 it is the fully trustworthy region
  of VERIFY.md's reserved-space scan on an encrypted unit flashed from a merged image, and
  taking the media reserve from the tail would have shrunk it to 732 KiB. That is the
  single reason the reserve sits where it does.
- Board A (32 MB = 33,554,432): tail = 18,595,840 bytes = 17.73 MiB, simply unused.
- Alignment, all legal: app offset 0x10000 is 64 KiB aligned; `media` at 0xC00000 is both
  64 KiB and 4 KiB aligned; `wallets` and `counters` are 4 KiB aligned; every size is a
  4 KiB multiple. Data subtype 0x42 does not collide with 0x40 or 0x41.
- App offset 0x10000 is unchanged from 0.1.0, so the Verify screen's running-partition
  SHA256 procedure stays board-independent.
- The CI app-size budget constant is unchanged (fail above 8 MiB, warn above 6 MiB). The
  declared app span of 11.94 MiB is 1.49x the fail budget, so the budget still bites long
  before the geometry does. For scale, 0.1.0's debug build's flash-loadable sections total
  roughly 2.5 MiB.
- Recorded while it is free, and revised for the new span: a future 0.2.x OTA scheme would
  have 11.94 MiB to split, roughly 5.9 MiB per slot plus otadata. Nothing is stranded.

**Why 2 MiB, and why the reserve is for camera ASSETS rather than for video.** The size is
argued rather than rounded, because a reserved region nobody can justify is a region
someone will later repurpose badly.

- Sensor and ISP tuning data for a camera build - lens shading tables, colour correction
  matrices, an `esp_cam_sensor` register-list blob for a variant module: tens of KiB each,
  under 256 KiB together even generously.
- One full-resolution still, staged for review: an OV5647 frame at 2592x1944 is roughly
  600-900 KiB as JPEG; a 640x480 grayscale Y-plane is 300 KiB raw.
- Headroom of about 2x over the sum of those, which is what makes it a reserve rather than
  a fitted allocation.
- **Video is explicitly NOT the use case, and the region must never become a recorder's
  backing store.** One second of 640x480 MJPEG at 15 fps is roughly 1.5 MiB, so the whole
  reserve holds under two seconds of footage; NOR flash rated at 100k erase cycles is the
  wrong medium for streaming writes; and the device has a microSD slot, which is the right
  one. The reserve exists so a camera build can persist assets and stage a single frame.
  Written down here so nobody later "discovers" 2 MiB of free flash and builds the wrong
  feature on it.

**Two rules attached to the reserve, both mechanical.** (1) **0.2.0 writes nothing to
`media`.** It reads all-`0xff`, its SHA256 is a Verify-screen row, and CI asserts no
symbol in the image references it. Any non-blank content in a 0.2.0 release unit is a
finding. (2) **It carries the `encrypted` flag from the first commit**, even though
nothing writes it, because the flag is part of the frozen table and cannot be added later
without changing the table. The justification is concrete rather than precautionary: the
one thing most likely to be staged there is a camera frame, and under the ratified Q48 a
camera frame can contain a SeedQR, which is a mnemonic. A partition that may one day hold
a photograph of a seed phrase is inside the XTS boundary or it is a defect.

**Why the size field was amended in the 2026-08-17 pass, and why that reasoning still
governs.** The original recommendation declared `factory` at 8M and then claimed 13.94 MiB
of headroom "before a collision", with the table "frozen now, permanently". Those cannot
both be true. ESP-IDF enforces the size field - the build fails with "app partition is too
small for binary" - so the headroom is not reachable without editing `partitions.csv`, and
`partition-table.bin` is a pinned, published, byte-identical release artifact whose hash
verifiers are told is stable (REPRODUCIBLE.md 3.5). Declaring the app at its collision
bound makes "frozen permanently" literally true. **That bound is now 0xC00000 rather than
0xE00000, and the same argument applies unchanged: the app is still declared right up to
the next partition, so the table still never needs a future edit.**

**This is the last moment the table can change at no cost, and it is being taken
deliberately.** `partition-table.bin`'s hash changes once, now, before m1 freezes it and
before anything is published. After m1 it never changes again.

**The one thing the collision-bound declaration costs is the accidental CI tripwire, and
that is replaced deliberately: CI carries an explicit app-size BUDGET constant - fail
above 8 MiB, warn above 6 MiB - which is a policy number that may be edited freely
precisely because it is not a compatibility surface.** This separates the two concepts the
old 8M field was conflating: flash geometry, which is permanent, and size discipline,
which is a judgement call. It also removes the coupling to Q6 entirely, because the camera
only ever affected the size field - and now, additionally, the media reserve, which is
declared rather than grown into.

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
pairs, 1 header pair. Under the ratified Q2 the device displays the maximum ("this device
holds up to 8 wallets") and never the count in use, which is a constant rather than a
leak. Capacity cannot be raised later without a format migration.

**Blast radius.** m1's deliverable and every stored record for the life of the product;
`firmware/partitions.csv`; the reserved-space scan's span list and one new Verify row for
the `media` digest; REPRODUCIBLE.md's `partition-table.bin` hash, once, now. Interacts
with Q2 (filler slots consume the same slot budget). No longer interacts with Q6.

### Q2. The full duress deniability package, off by default [OWNER-ANSWERED 2026-08-18]
**DECISION: option (a).** Unused slots are ALWAYS filled with device-derived ciphertext,
for every user; the Verify screen's storage readout is degraded to "present / blank"
permanently and for all users, duress or not; and the duress PIN feature itself ships OFF
by default.
*Owner-answered 2026-08-18, as recommended.*

**Reasoning as recorded.** A duress feature that leaks the wallet count invites the
coercion it cannot survive. The cost is real, is paid by every user including every user
who will never enable duress, and is accepted deliberately rather than minimised.

**The distinction that matters and is easy to get wrong when implementing:**
`Occupancy::AlwaysFilled` is **not** the duress feature and is not off by default. It is
the permanent, only, unconditional storage mode - that is precisely what "a cost paid by
every user" means. What is off by default is the second PIN identity that opens a decoy
wallet set. Building the filler only for duress users would defeat the entire point,
because "this device has filler" would itself be the tell.

**Consequences, all of them now decided rather than pending.**
- **`Occupancy::AlwaysFilled` is the only mode notyas ships.** m3 still builds the mode
  switch (ESP-SEAL.md is a general layer and `Sparse` remains valid for other embedders),
  but the notyas product pins it, and a request to change it through SET-POLICY is
  refused rather than silently ignored (Q5.2 Y2).
- **The m4b capacity line dies.** "3 of 8 slots" is replaced by the static capacity ("this
  device holds up to 8 wallets") plus a binary state. Pre-PIN and on the Verify screen the
  storage rows read `present` or `blank` and nothing else. **After a successful unlock the
  user sees their real wallet list**, because that is post-PIN and leaks nothing to a
  coercer who does not have the PIN. S-01, S-03 and S-46 all move together.
- **Q37's count half resolves to present/blank**; its threshold half was already
  unconditional. Nothing further is owed there.
- **Q56 resolves to its Q2(a) branch: the `wallets` raw digest MAY sit pre-PIN.** Under
  AlwaysFilled a blank partition never raw-reads as a recognisable all-`0xff` constant, so
  the digest announces nothing. It joins the pre-PIN identity field set and the CI golden
  list for that set is written accordingly.
- **SECURITY invariant 5's wording takes the degraded readout** and states why, rather
  than leaving the conditional in place.
- **The duress PIN classification and its UX land at m13**, off by default; the record
  format half already shipped at m3 and needs nothing further (revised R11).
- **No indistinguishability claim is made beyond what the mechanism delivers**, and the
  boundary is stated in SECURITY.md: an attacker without the eFuse key cannot tell filler
  from a real record, and that is the claim. It is not a claim about an attacker who has
  extracted the key, and it is not a claim that the device's behaviour under a duress PIN
  is indistinguishable from its behaviour under the real one at every UI surface.

**Blast radius.** Three screens (S-01, S-03, S-46), SECURITY invariant 5, the pre-PIN
field set, and m13's duress UX. Not the storage format (revised R11).

### Q9. Ship on rev v1.x silicon; the Key-Manager ladder is 0.3.x [OWNER-ANSWERED 2026-08-18]
**DECISION: release units ship on the rev v1.x silicon both bench units already run (both
are v1.3), with the HMAC-eFuse ladder exactly as designed.** A Key-Manager-backed ladder
is scheduled for 0.3.x, on the same record format.
*Owner-answered 2026-08-18 ("do what is optimal"), and recorded as decided rather than
left open.*

**Reasoning.** The HMAC-eFuse ladder is the design the whole storage layer is written
against, it is verified on the two boards that exist, and the P4 Key Manager needs rev
>= v3.0 silicon that nobody on this bench has. Sourcing v3.0 parts to get a better ladder
would re-open m3h, m3 and m4a for a benefit no 0.2.0 user can perceive, and it would do it
during the release the owner wants shipped.

**Why 0.3.x costs nothing to schedule now.** The Key Manager would replace exactly one
step - `hmac_efuse(0x02, prestretch)` - and the record format does not encode which
mechanism produced `bound`. A future device on v3.0 silicon can carry a stronger ladder
under the same format, and the `suite_id` field exists precisely so the two can be told
apart if they ever need to be.

**Two standing requirements this creates, both cheap and both easy to forget.** The
`ESP_EFUSE_*` symbols the m3h readout surface uses are revision-family dependent and must
be re-checked against the post-v3 table if production silicon ever moves. And the Verify
screen's chip-revision row must print the real revision, never a compiled-in constant, so
that a unit built on different silicon is visible rather than assumed.

**Blast radius.** m13's provisioning runbook and one line in SECURITY.md's tier list. No
0.2.0 code depends on it.

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

### Q44. The sealing layer lives inside notyas-wallet, not in a separate crate [ESP-SEAL.md 2.4] - REOPENED AND RE-DECIDED 2026-08-18
**DECISION: unchanged - no `esp-seal` crate. The sealing layer is a module inside
notyas-wallet, and ESP-SEAL.md remains the authoritative DESIGN document for it. The
REASONING is replaced, because the reason it was decided on 2026-08-17 no longer exists.**
*Reopened 2026-08-18 by the owner's split-licensing answer, re-argued on its merits, same
outcome.*

**Why it had to be reopened, stated rather than skipped.** The 2026-08-17 decision rested
entirely on the blanket GPL answer: "a GPL3 platform contribution the permissively
licensed ESP32/Rust ecosystem will not depend on is worse than an honest internal module."
Under a per-crate split that argument is simply unavailable - a dual MIT/Apache `esp-seal`
would be adoptable. Leaving the outcome standing on a reason that has evaporated would be
exactly the kind of stale decision this file exists to prevent.

**Re-argued on the merits, and the answer is the same for two independent reasons, either
sufficient.**

1. **It is on the GPL side of the line anyway.** The sealing layer is the PIN key ladder,
   the sealed record format and the wipe policy. It handles user key material and it
   encodes this project's security policy - both criteria in Q8's principle, at once.
   Extracting it would produce a GPL crate, which puts us back at the 2026-08-17 argument
   with extra steps. Licensing it permissively to make it adoptable would mean publishing
   a permissive implementation of the thing that protects users' seeds, which is the one
   place the owner's GPL stance is unambiguous.
2. **Extraction is scope this release cannot afford**, and R4's original sequencing
   argument survives untouched: publishing an unproven security crate to satisfy an
   ordering diagram is a disservice to the ecosystem it is meant to serve. The layer is
   proven on hardware at m4a, which is after the point where a crate boundary would have
   had to exist.

**Revisit condition, recorded so this is a decision and not an omission:** extraction may
be reconsidered at 0.3.x, after the format has survived a release on real hardware. It
would still be GPL-3.0-or-later, and the honest expectation is therefore modest adoption -
which is why ESP-SEAL.md, published and readable by anyone, remains the contribution that
actually travels.

**The clean platform boundary stays, for the reason it has had since Q44 was first
settled: testability.** The host simulator and the fuzz harness substitute the Storage,
DeviceBinding and KdfScratch traits, and no ESP-IDF type crosses the boundary. That
discipline is worth keeping on its own and does not depend on any extraction plan.

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

### Q8. Licensing: a per-crate split, monorepo, with GPL where it matters [OWNER-ANSWERED 2026-08-18, SUPERSEDES the 2026-08-17 blanket answer]
**DECISION: split licensing.** GPL-3.0-or-later for the product and for everything that
touches user key material; **MIT OR Apache-2.0** for the generic, reusable, low-level
pieces that hold no secret and no policy of their own; **CC0-1.0** for pure test data;
**SIL OFL 1.1** for font data, unchanged and explicitly protected. **Everything stays in
the notyas repository - one monorepo, no separate repositories.**
*Owner-answered 2026-08-18: "split licensing is acceptable to meet Rust ecosystem norms,
GPL-3.0-or-later stays for the parts where it matters, do what is optimal, and everything
stays in the notyas repo." This supersedes the 2026-08-17 blanket GPL-3.0-or-later
answer.*

**The principle that decides every row, stated once so future crates do not need a new
decision.**

> A crate is **GPL-3.0-or-later** if it is the product, or if it handles user key
> material, or if it encodes this project's security policy. A crate is **MIT OR
> Apache-2.0** if it is a generic platform or format building block whose entire value is
> being adopted by a permissively licensed ecosystem, and which holds no secret and makes
> no policy decision. Test vectors are data, not implementation, and are **CC0-1.0**. Font
> data is **SIL OFL 1.1** and is never folded into either scheme.

The dual MIT OR Apache-2.0 pairing rather than MIT alone is deliberate: it is the Rust
ecosystem's default and it gives downstream users the patent grant in Apache-2.0 without
forcing its notice requirements. A permissive crate in this tree may be consumed by the
GPL crates without friction; the reverse is not true, which is why the split runs in the
direction it does.

#### Per-crate licence table

| Crate / artifact | Licence | Why this side of the line |
|---|---|---|
| `firmware` | GPL-3.0-or-later | It is the product. A closed fork of a signer's firmware is the exact outcome copyleft exists to prevent. |
| `crates/notyas-core` | GPL-3.0-or-later | Derivation, `SecretSigningKey`, sighash, signing. Handles key material directly. |
| `crates/notyas-wallet` (incl. the `seal` and `store` modules) | GPL-3.0-or-later | The PIN key ladder, the sealed record format, the policy engine. Both criteria at once: it handles keys AND it is the security policy. |
| `crates/notyas-ui` | GPL-3.0-or-later | Renders secrets, owns the reveal gates and the masking discipline. Product surface. |
| `crates/notyas-fonts` (code) | GPL-3.0-or-later | Product surface. |
| `crates/notyas-fonts/src/gen/*` (generated atlases) | **SIL OFL 1.1** | Font DATA, not code. Carve-out preserved verbatim, see below. |
| `tools/fonts/upstream/*.ttf` | **SIL OFL 1.1** | Unmodified IBM Plex release files. |
| `esp-idf-hmac` (m3h) | **MIT OR Apache-2.0** | A thin safe binding over ESP-IDF's HMAC peripheral. Holds no key (the key is in an eFuse), makes no policy decision, and its only value is adoption by esp-idf-hal / esp-hal, which are MIT/Apache and will not take a GPL dependency. The clearest case in the tree. |
| `seedqr` (m11) | **MIT OR Apache-2.0** | An 11-bit packer for a public format. The algorithm is published by SeedSigner; there is no implementation to protect and the only Rust one should be usable by anyone. It touches a mnemonic in memory, which is why it is dual-licensed rather than CC0: attribution and the patent grant still matter for code. |
| `bsms` (0.3.0, if built) | **MIT OR Apache-2.0** | A BIP-129 protocol codec. BDK asked for one and BDK is permissive; a GPL one would be pointless. Recorded now so the header is right the day it is written. |
| `tools/uisim`, `tools/fonts/atlasgen`, `tools/*.ps1`, `tools/*.sh` | GPL-3.0-or-later | Development tooling, tied to the product. |
| Reproducible-build example artifacts (the container definition and the CI workflow REPRODUCIBLE.md tells readers to copy) | **MIT OR Apache-2.0** | Their entire purpose is to be lifted into someone else's repository. A GPL snippet a reader must license-audit before pasting is a recipe nobody follows. |
| Adversarial PSBT vector FILES (`.psbt` and their expected-verdict fixtures) | **CC0-1.0** | Data. Value comes from adoption; there is no implementation to protect. Own SPDX headers, per file. |
| The corpus HARNESS and generator | GPL-3.0-or-later | Code, and it encodes our verdict policy. |
| The `notyas-<ver>-<board>-VERIFY.json` schema and any off-device checker script | **MIT OR Apache-2.0** | A verification format nobody may reimplement is a verification format nobody checks. |
| Planning and design documents (this directory, ESP-SEAL.md, REPRODUCIBLE.md, VERIFY.md) | GPL-3.0-or-later, as part of the repository | A document does not impose its licence on an independent implementation of the ideas it describes, so this is not a barrier to the contribution they represent. |

**Reasoning for keeping GPL where it is kept.** For wallet firmware, GPL-3.0 prevents
closed forks of code that handles user keys. That argument is exactly as strong as it was;
what changed is that it was being applied to pieces it was never about. A safe binding
over an HMAC peripheral protects no user and forecloses no fork; it just fails to get
adopted. The split gives up nothing the blanket answer was buying.

**Consequences, worked through rather than assumed.**
- **Q44 is REOPENED by this answer and re-decided: the outcome stands, the reasoning is
  replaced.** See its entry. The sealing layer stays a notyas-wallet module - but no
  longer because "a GPL crate would not be adopted"; now because extraction is scope this
  release cannot afford and because that layer is on the GPL side of the line anyway.
- **Q46 is reopened and re-decided.** The sealing layer is still never published. But
  `esp-idf-hmac` and `seedqr` are now publishable, and their licence headers are set from
  the first commit so publication later costs nothing. See its entry for what publishes
  when.
- **Q51 is answered YES** by the owner in the same instruction. See its entry.
- **Q39's outbound half closes** with it: the vector files are CC0-1.0 in-repo and may be
  offered upstream.
- **Reconciliation R6 comes back to life and must be honoured again.**
  `foundation-urtypes` is itself GPL-3.0-or-later, so any crate depending on it must be
  GPL. Under the blanket answer that constraint bound nothing; under a split it binds
  again. **Requirement: UR and transport encoding stay inside notyas-wallet (GPL), and
  neither `esp-idf-hmac` nor `seedqr` may take a `foundation-*` dependency.** R6 was marked
  moot on 2026-08-17; that marking is withdrawn.
- **The clean-room constraint is unchanged and still binds.** Trezor's and Jade's code are
  copyleft; only their published DESIGNS may inform a clean-room implementation. Neither
  being GPL ourselves nor shipping permissive crates licenses a port.
- **The font carve-out survives intact and is protected explicitly.** The IBM Plex TTFs and
  the generated glyph atlases are SIL OFL 1.1, with the Reserved Font Name renaming
  ("notyas Sans" / "notyas Mono") recorded in LICENSE-fonts. It is not GPL and it is not
  MIT/Apache. **A split licence scheme makes flattening it more likely, not less, so the
  rule is stated as a prohibition: no crate-level licence statement may be read as
  covering `crates/notyas-fonts/src/gen/` or `tools/fonts/upstream/`, and every SPDX sweep
  must exclude those paths explicitly.** LICENSE-fonts remains the authority.
- **Monorepo confirmed.** Everything lives in the notyas repository. Publishing a crate to
  crates.io from a path inside this repository is not a repository split and is not
  precluded by the owner's answer; what is precluded is a second git repository.

**Mechanical enforcement, because a licence policy that is not checked drifts.** m1 adds
an SPDX header assertion to CI: every `.rs`, `.toml`, `.ps1` and `.sh` file carries an
`SPDX-License-Identifier` matching the table above for its path, with the font paths on an
explicit exclusion list, and the job fails on a missing or mismatched header. The same job
asserts that no crate declared MIT OR Apache-2.0 has a GPL crate in its dependency tree,
which is what keeps R6 honoured after the person who read this forgets.

**Blast radius.** Every SPDX header from the first commit; `Cargo.toml` `license` fields;
`COPYING` gains a per-path licence map at the top; the m12 publication scope; R6's
revival. Relicensing after publication would require every contributor's consent, so the
permissive rows are effectively irreversible in the permissive direction - which is the
correct direction for the pieces chosen.

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
milestones that own passphrase wallets (m3 for the field, m4b for the copy - m9 is
retired, R26):

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

#### REVERSED 2026-08-19: the pad is FIXED PHONE ORDER
*The decision above is left exactly as it was ratified. It was overturned, not amended, and
the reasoning it was ratified on is kept so the record shows what the reversal cost rather
than only what it chose.*

**What ships instead.** 1-2-3 / 4-5-6 / 7-8-9 across the first three rows, `0` in the
bottom-centre slot, `OK` bottom-left and `Del` bottom-right: the layout of every telephone
and cash machine, identical on both panels, on every attempt, and on every device. The pad
is a constant in the UI (`PIN_PAD`, `crates/notyas-ui/src/screens/pin.rs`), not a value the
embedder derives and installs.

**Who reversed it and why.** The project owner, on 2026-08-19, after using the shuffled pad
on hardware. Reading all ten keys on every unlock was not worth what it bought him. He was
shown the trade explicitly before deciding - that fixed positions mean anyone who observes
his fingers once has learned the PIN - and chose the familiar layout with that stated. The
risk falls entirely on the person accepting it, so this plan records the decision rather
than argues with it.

**What was traded away, precisely.**

- **Observation resistance between attempts. This was the whole property.** With a shuffled
  pad, a watcher who saw one entry - over a shoulder, from a ceiling camera, in a window -
  learned finger POSITIONS, and those positions carried different digits on the next
  attempt. Positions are now digits, permanently: one clear observation of the hand is a
  complete PIN, and every later attempt confirms it rather than muddying it. What is left
  against a shoulder surfer is what never depended on the pad - the attempt counter, the
  escalating backoff, and the wipe - and none of those stop someone who has the digits.
- **The strongest version of the pattern, permanently out of reach.** Trezor's blind matrix
  and Keystone's scrambled pad are the state of the art this product had matched; it now
  scores an honest `N` on that row (COMPETITIVE.md) and UX-PATTERNS records it as a
  deliberate divergence rather than an oversight.
- **Nothing else.** The anti-phishing words at four digits, the attempt line, the backoff
  and the masking discipline are untouched.

**What was not traded away.** SECURITY.md invariant 3 (no RNG in the UI crate) is not
weakened - the screen now needs no derived value at all, which is a strictly smaller
surface. C10's other half, press feedback on the dot row rather than on the key, stays, on
a rationale rewritten beside the code: on a fixed pad a lit key IS the digit and a lit
80 px cell is legible where a fingertip is not, so non-local feedback earns its place for a
stronger reason than the one it was introduced with.

**Why the reversal is legitimate.** The property given up protects the device's owner from
being watched by people near him, and no one else: it is not one of the invariants that
protect a user from the device, from the project, or from a supply chain. A user is
entitled to decline a defence aimed at his own environment when he judges the daily cost
too high, and this one is declined knowingly and in writing. The plan's rule is that a
claim is mechanically enforced or it is not made - so the claim is withdrawn everywhere it
appeared, which is what the blast radius below is for. It is not weakened, hedged, or left
standing in a document nobody re-read.

**Knock-on to the ratified Q45, which is unchanged.** Q45's amendment 2 named two
`HMAC_efuse`-derived values an unprovisioned device cannot produce, and the PIN pad was one
of them. It is no longer derived, so the PIN screen renders on an unprovisioned device
without a special case; only the anti-phishing words and the backup quiz's distractor set
remain on that path. Q45's decision stands and its reasoning has one fewer example.

**Blast radius of the reversal.** `crates/notyas-ui/src/screens/pin.rs` (the constant, and
an `install_pad` that refuses so no embedder can put a shuffle back). Then a path that is
now dead end to end and should be deleted: `UiRequest::PinPad`, `Ui::set_pin_pad`,
`Vault::pin_pad_order`, the firmware arm that answers the request, its HKDF info string,
and the simulator's installed pad. Documents: UX.md commandment 5 and screen 2,
UX-PATTERNS 3.3, UX-REVISION A4 and A10 (done with this entry); UX-SCREENS C10, S-04 and
its region table, COMPETITIVE.md's scrambled-keypad row, SIMPLE-MODE.md's `PinPad`
mentions, MILESTONES.md's unprovisioned-path note and ESP-SEAL.md's pad-permutation line
(outstanding).

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
**RESOLVED 2026-08-18 by the owner's Q2(a) answer: the slot COUNT is never shown pre-PIN
or on the Verify screen; those surfaces read `present` / `blank`.** The threshold half was
already unconditional and is unchanged. S-44 additionally becomes the live wipe-policy
editor under the ratified Q5, so it now carries the threshold, the power-cut disclosure,
the wipe-off switch with its arithmetic, and the PIN-removal entry point.

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
**RESOLVED 2026-08-18 by the owner's Q2(a) answer: the digest is PERMITTED PRE-PIN** and
joins the pre-PIN identity field set, with the CI golden list for that set written
accordingly. The conditional form below is kept because it is the reasoning.

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

### Q13. Fee thresholds, pinned against what other signers actually do [was Q12] - RESEARCHED AND PINNED 2026-08-18
**DECISION: three warning axes and two refusals, with the numbers below pinned as
`FeePolicy` constants in notyas-wallet. All three values are always displayed regardless
of whether any threshold fires.**

| Axis | notyas | Kind |
|---|---|---|
| Fee as percent of amount sent | **warn at >= 5%** | warning, tunable 1..25 under the Q24 expert gate |
| Fee rate | **warn at >= 500 sat/vB** | warning, tunable 50..2000 |
| Absolute fee | **warn at >= 100,000 sat** (0.001 BTC) | warning, tunable 10,000..1,000,000 |
| Negative fee (outputs exceed inputs) | **refuse** | hard, never overridable |
| Fee rate >= 25,000 sat/vB | **refuse** | hard, never overridable |

*Ratified 2026-08-17 in the abstract; the owner asked on 2026-08-18 for established
practice to be researched, cited and pinned to concrete numbers. That is done here and the
numbers changed: an absolute-fee axis was added, and the reasoning behind each is now
evidence rather than assertion.*

**What the field actually does, verified against source on 2026-08-18.**

- **Coldcard** (`shared/psbt.py`) is the closest comparand and has exactly two lines. It
  computes `per_fee = the_fee * 100 / self.total_value_out`, appends a `Big Fee` warning
  when `per_fee >= 5`, and raises `FatalPSBTIssue("Network fee bigger than %d%% of total
  amount")` when `per_fee >= fee_limit`, where `fee_limit` defaults to
  `DEFAULT_MAX_FEE_PERCENTAGE = const(10)` and is user-settable, with `-1` disabling the
  check entirely. So: warn at 5%, refuse at 10%, refusal defeatable.
- **Trezor** (`core/src/apps/bitcoin/sign_tx/approvers.py` with
  `trezor-common/defs/bitcoin/bitcoin.json`) works in fee RATE, not percentage. Bitcoin's
  `maxfee_kb` is 2,000,000 sat/kB, i.e. **2,000 sat/vB**; `fee_threshold = (maxfee_kb /
  1000) * tx_size_vB` and `fee > fee_threshold` forces an explicit confirmation. Above
  `10 * fee_threshold` (**20,000 sat/vB**) with strict safety checks it raises
  `DataError("The fee is unexpectedly large")`. It also confirms above
  `MAX_SILENT_CHANGE_COUNT = 2` change outputs, which is a different axis worth knowing
  about.
- **SeedSigner** has **no fee threshold at all.** `models/psbt_parser.py` does
  `self.fee_amount = self.psbt.fee()` and `views/psbt_views.py` displays it; there is no
  comparison, no threshold and no warning anywhere in the flow. This is recorded rather
  than glossed, because the earlier ratification implied a practice to follow and there is
  none: SeedSigner shows the number and trusts the user to read it.
- **rust-bitcoin 0.32** (our own dependency, `psbt/mod.rs`) refuses at extraction:
  `Psbt::DEFAULT_MAX_FEE_RATE = FeeRate::from_sat_per_vb_unchecked(25_000)`, returning
  `ExtractTxError::AbsurdFeeRate`.

**How each number was chosen from that.**

- **5% of amount sent** is Coldcard's warn line exactly. A user moving from a Coldcard
  sees the same trigger at the same place, which is worth more than a marginally better
  number. Note the denominator difference and implement ours deliberately: Coldcard divides
  by `total_value_out`, which includes change; notyas divides by the amount actually
  leaving the wallet, because a 1 BTC self-transfer with a 0.005 BTC fee should warn and
  under Coldcard's denominator it does not.
- **500 sat/vB** is 4x tighter than Trezor's 2,000 sat/vB silent-confirm line. Trezor's
  number is set to almost never fire; ours is set to fire on a genuinely unusual fee while
  costing only one extra screen when it is wrong. It is a warning, so a false positive is
  cheap and a false negative is not.
- **100,000 sat absolute** exists because the other two axes both have a blind spot. A
  large consolidation has a huge absolute fee, a normal rate and a tiny percentage; a
  sweep of a small UTXO has a small absolute fee and a large percentage. Only an absolute
  line catches "you are about to pay 0.004 BTC in fees" when neither ratio looks odd.
  100,000 sat is the fee a typical 200 vB single-sig spend pays at exactly the 500 sat/vB
  rate line, so the two warnings agree at the ordinary case and diverge only where they
  should.
- **The two refusals are arithmetic, not judgement.** A negative fee is an impossible
  transaction. The 25,000 sat/vB line is pinned to rust-bitcoin's own constant on purpose:
  our dependency refuses to extract such a transaction anyway, so a device that signed it
  would produce something it then could not finalize. Pinning to the library's constant
  means the two can never disagree.
- **Coldcard's 10% hard refusal is deliberately NOT adopted.** Two reasons. A 10% fee is
  legitimate when sweeping a nearly-dust UTXO, and refusing it makes the device wrong in a
  case the user understands better than the device does. And Coldcard itself makes that
  refusal settable and disable-able with `-1`, which is an override on a refusal - exactly
  what the ratified Q24 forbids. Rather than ship a refusal we would then have to let
  people turn off, notyas keeps every fee refusal to arithmetic impossibilities and lets
  the warnings carry the judgement.

**Display is unconditional.** The review screen always shows absolute sats, sat/vB and
percent of amount sent, whether or not any threshold fires. That is the SeedSigner
instinct - show the number - kept alongside the thresholds rather than instead of them.

**The Q24 boundary inside the same struct, restated because it is easy to violate:**
`warn_percent_of_send`, `warn_sat_per_vb` and `warn_absolute_sat` are tunable under the
expert gate; `refuse_negative_fee` and `refuse_sat_per_vb` are not, and no Settings screen
exposes them.

**Blast radius.** m6 policy constants, one review screen, three corpus cases (one per
warning axis) plus two refusal cases.

**Sources.** [Coldcard shared/psbt.py](https://raw.githubusercontent.com/Coldcard/firmware/master/shared/psbt.py),
[Trezor approvers.py](https://raw.githubusercontent.com/trezor/trezor-firmware/main/core/src/apps/bitcoin/sign_tx/approvers.py),
[trezor-common bitcoin.json](https://raw.githubusercontent.com/trezor/trezor-common/master/defs/bitcoin/bitcoin.json),
[SeedSigner psbt_parser.py](https://raw.githubusercontent.com/SeedSigner/seedsigner/dev/src/seedsigner/models/psbt_parser.py),
[SeedSigner psbt_views.py](https://raw.githubusercontent.com/SeedSigner/seedsigner/dev/src/seedsigner/views/psbt_views.py),
rust-bitcoin 0.32 `bitcoin/src/psbt/mod.rs` line 136 (read from the vendored crate in this
workspace's Cargo registry).

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

### Q15. BSMS - see "Deferred to 0.3.0"
Deferred whole by the owner on 2026-08-18, and the `bsms` module is not built at all in
0.2.0 (the earlier "build it at m12 if m7 leaves capacity" conditional is removed).
Descriptor import plus the mandatory first-address cross-device comparison covers the
security need. Full entry in the deferred section above. **Blast radius.** m7 scope and
m12 scope, both reductions.

### Q16. Taproot multisig timing [was Q7]
**DECISION: 0.2.0 multisig is P2WSH `sortedmulti` (BIP-48) only.** Taproot single-sig
(BIP-86) is fully supported for signing; tapscript, multi-leaf and MuSig2 revisit at
0.3.x.
*Ratified 2026-08-17; re-confirmed by the owner 2026-08-18 as the recommended option.*

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

## Seed math and seed lifecycle (m9 is RETIRED - see MILESTONES section 4)

**Milestone id m9 was retired in the 2026-08-18 re-scope**, not renumbered, so every
reference to m10-m13 elsewhere stays valid. Its contents were redistributed: seed import
by words and the create/restore flows were already m4b's; the stateless-seed session moved
to m6, where signing lives; the `seedqr` decoder moved to m11, the only thing that needs
it. BIP-85, Seed XOR, Lock Down Seed and the encrypted backup all left 0.2.0. The
decisions below keep their numbers and are filed against the milestone that now consumes
them.

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

### Q33. Seed XOR part generation defaults to dice [BACKUP-FEATURES.md OPEN-B2] - DEFERRED WITH SEED XOR to 0.3.0
**DECISION STANDS, BUT NOTHING IMPLEMENTS IT IN 0.2.0.** Seed XOR left the release in the
2026-08-18 re-scope: it is not needed for a working storage, signing and multisig wallet,
and its dice mode costs up to 297 rolls of UX to build and test. The decision below is
kept in full so 0.3.0 starts from a settled answer rather than re-deriving one, and
because the information-theoretic versus computational argument in it is the reason the
default is not obvious.

*Ratified 2026-08-17 with one strengthening amendment; deferred unimplemented
2026-08-18.*

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

### Q11. How loudly must class-c equivalents be shipped? [wave 2] - REFINED BY THE OWNER 2026-08-18
**DECISION: on-device text earns its place only where a user would otherwise expect the
feature and go hunting for it. That is exactly two cases: camera scan-in when the camera
is absent, and battery. NFC is REMOVED from the on-device list and is covered by
documentation.**
*Refined by the owner 2026-08-18, tightening the 2026-08-17 ratification.*

**The owner's rule, which is the general form and should be applied to any future row:**
a line is earned where a user would otherwise expect the feature and hunt for it.
**Nobody expects NFC on this device.** It is not on the box, it is not in the shape of the
product, and no screen implies it. A line saying "no NFC" answers a question the user was
not asking, and every such line dilutes the two that matter.

- **Camera absent** stays on-device: the base artifact and board B both lack it, the sign
  flow has a load screen where a scan option would obviously belong, and a user who has
  seen a SeedSigner will look for it. The wording is "no camera on this board/build", per
  R3, never "no camera exists".
- **Battery** stays on-device: the device has no power source of its own and a user
  unplugging it expects it to keep running. That is a surprise worth pre-empting.
- **NFC moves to documentation**, alongside every other hardware-impossible row: dual
  secure elements, dual microSD slots, Bless Firmware LEDs, the USB transport rows.
  PARITY.md and the release notes carry them; no screen does.

**Reasoning.** Every hardware-impossible row has a named equivalent (MILESTONES 7.2). A
line of on-screen text earns its place when it stops a user searching for something that
does not exist; otherwise it is clutter, and clutter on a security device is not neutral,
because it trains people to skim the text that matters.

**Blast radius.** m10 and m13 screen copy; one fewer line than the 2026-08-17 version.

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

### Q39. Corpus licensing and publication [CORPUS.md corpus-1] - COMPLETED 2026-08-18
**DECISION, now whole: the harness and the generator are GPL-3.0-or-later; the vector
FILES are CC0-1.0 with their own per-file SPDX headers; selected cases may be offered
upstream to HWI and Coldcard's psbt_faker under those projects' terms (Q51, answered
yes).**
*Partially ratified 2026-08-17, completed 2026-08-18 once the owner's split-licensing
answer made the original recommendation available again.*

**Reasoning.** Q39's original argument was always sound on its merits: test vectors gain
their value from adoption and carry no implementation to protect. It could not be ratified
on 2026-08-17 only because a blanket GPL answer was in force and carving CC0 out of it
would have substituted judgement for a decision the owner had just made. The split answer
makes it the obvious outcome, and Q8's principle names it directly: data is CC0, code is
copyleft where it encodes policy. The harness encodes our verdict policy - what a hostile
PSBT should DO to this device - and stays GPL-3.0-or-later.

**One implementation note so this is not discovered at review time:** the CC0 headers go
on the vector files and their expected-verdict fixtures, not on the directory, and the
CI SPDX check (Q8) carries the path rule. A `.psbt` binary cannot hold a header, so each
one is paired with a `.spdx` sidecar or an entry in a per-directory `REUSE.toml`.

**Blast radius.** Per-file licensing headers on the vector files; one contribution that
costs no engineering because the vectors already exist as m6's gate. The upstream offer
itself is 0.3.0 work (Q46 item 5).

### Q51. Outbound contributions under the receiving project's licence [OWNER-ANSWERED 2026-08-18]
**DECISION: YES - option (a).** We may contribute code and test data to outside projects
under THEIR permissive licence.
*Owner-answered 2026-08-18, as recommended, in the same instruction that split the
licensing.*

**Reasoning as recorded.** A test vector carries no implementation to protect and gains
its value from adoption. A small upstream patch to a crate we depend on is maintenance we
would otherwise carry forever in a fork. Neither gives away anything that handles user
keys, which is what the GPL stance protects.

**What this permits, and what it does not.** It permits the no_std BBQr decode as an
upstream PR to SatoshiPortal's MIT crate, and it permits offering selected adversarial
PSBT vectors to HWI and psbt_faker. It does not permit relicensing anything in the GPL
column of Q8's table, and it does not turn an outbound patch into a precedent for the next
one: each contribution is evaluated against Q8's principle, and anything that would hand
out a piece of the key-handling path stays in.

**Timing, separate from permission.** Both contributions are 0.3.0 work under the
2026-08-18 re-scope. The permission is recorded now so the work is not blocked on a second
conversation later.

**Blast radius.** SPDX headers on the vector files (already handled by Q39); m12's
contribution scope, which loses the patch and keeps the documents. Nothing in the
firmware.

### Q46. What publishes, and when [ESP-SEAL.md 9.1] - REOPENED AND RE-DECIDED 2026-08-18
**DECISION, in three parts.**
1. **The sealing layer is never published.** No separate repository, no crates.io
   publication, for the life of 0.2.0 and beyond unless Q44's revisit condition is met.
2. **`esp-idf-hmac` and `seedqr` carry MIT OR Apache-2.0 headers from their first commit
   and are publishable**, but **neither is published during 0.2.0**. Publication is
   0.3.0 work, and it costs nothing to defer because the licence - the only irreversible
   part - is already in place.
3. **Everything stays in the notyas monorepo.** A crates.io publication from a path inside
   this repository is not a repository split.
*Reopened 2026-08-18 by the split-licensing answer. Part 1 is unchanged; parts 2 and 3 are
new.*

**Reasoning for part 2, which is the one that changed.** Under the blanket GPL answer
there was nothing worth publishing. Under the split there are two genuine contributions:
`esp-idf-hmac` fills a verified gap (esp-idf-sys does not bind `esp_hmac.h`; esp-hal has
HMAC for S2/S3/C3/C6/H2 but not P4) and can now actually be adopted by the crates that
needed it, and `seedqr` is still the only Rust implementation of a format SeedSigner
users depend on. Both are proven by their own gates - m3h's hardware gate for the first,
published vectors for the second - so neither is an unproven-security-crate publication of
the kind R4 warned against.

**Why publication still waits for 0.3.0.** Publishing creates a maintenance obligation to
strangers - issues, semver, MSRV, a release cadence - during the release the owner wants
shipped. The licence header is the part that is expensive to change later; the
`cargo publish` is the part that is cheap to do later. Doing the expensive part now and the
cheap part later is the correct ordering, and it is a deliberate scope decision rather than
an oversight.

**Reasoning for part 1, unchanged and still the honest description of what 0.2.0
delivers.** ESP-SEAL.md itself is published in the repository: the byte-exact on-flash
format, the mount/unlock/seal/wipe state machine, the power-loss analysis, the honest
attempt-counter trust model, and the attack analysis. Any other project can read all of it
and reimplement freely, because a document does not impose its licence on an independent
implementation of the ideas it describes. ESP-SEAL.md 9.1 argued the value was in the
design rather than in three thousand lines of well-trodden construction; publishing the
design and not the crate is that position carried through.

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

**PLATFORM.md's contribution shortlist, restated under the split licence and against the
re-scoped release.**

| # | Item | Licence | 0.2.0 | Later |
|---|---|---|---|---|
| 1 | `esp-seal` | GPL-3.0-or-later, in-tree module | not extracted; the contribution is **ESP-SEAL.md, published in-repo** | extraction revisitable at 0.3.x (Q44) |
| 2 | `esp-idf-hmac` (+ optional `esp-ds`, `esp-key-mgr` surfaces) | **MIT OR Apache-2.0** | built at m3h, header set, **not published** | published 0.3.0; the "candidate for upstreaming into esp-idf-hal" claim is BACK, because a dual-licensed crate can actually be taken |
| 3 | `seedqr` | **MIT OR Apache-2.0** | built for m11's scan-in, header set, **not published**; its ENCODE half stays test-vector-only under the ratified Q17 | published 0.3.0 |
| 4 | `bsms` | **MIT OR Apache-2.0** | **not built at all** (Q15 deferred whole) | 0.3.0; BDK's open request is a reason again, because BDK is permissive and so is this |
| 5 | no_std BBQr decode | receiving project's MIT | **not done in 0.2.0** - permission is granted (Q51) but the work is deferred | upstream PR at 0.3.0 |
| 6 | Reproducible Rust-on-ESP-IDF recipe | document GPL-3.0-or-later; **its copyable example artifacts MIT OR Apache-2.0** | **ships at m12**, and is the strongest contribution 0.2.0 makes | - |

Item 6 is worth one sentence of emphasis: no published recipe exists for the Rust +
esp-idf-sys + `-Zbuild-std` stack, licensing is not a barrier to anyone reading a
document, and the pieces a reader must copy are permissive precisely so they can copy
them. It stands entirely on its own and needs nothing from the crate publications.

**Blast radius.** m12's scope carries the document publications and no crate publications;
MILESTONES section 9's "done" definition loses "the published crates build from crates.io
for someone who has never seen this repository"; measurement M9 (crate-name availability
on crates.io) is deferred to 0.3.0 rather than withdrawn, since two names will eventually
be wanted.

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

- **Owner answers and re-scope, 2026-08-18.** The owner answered all ten remaining
  questions. Seven results deferred work to 0.3.0 (Q14, Q15, Q30, Q31, Q32, Q34, Q43),
  three changed the shape of 0.2.0 (Q5 settable wipe policy, Q7 media reserve, Q8 split
  licensing), and three confirmed a recommendation as written (Q2, Q16, Q50, plus Q6 with
  a hardware-gating rule and Q9 and Q51 answered as "do what is optimal" / yes). Two new
  questions were raised BY those answers and are the only open items: Q62 and Q63.
- **Questions whose reasoning was replaced rather than whose outcome changed, listed
  because a stale reason is a future mistake:** Q44 (extraction) and Q46 (publication)
  both rested on "a GPL crate will not be adopted", which the split licence removes; both
  were re-argued from scratch and both kept their outcome for different reasons. R6 (GPL
  contagion through `foundation-urtypes`) was marked moot on 2026-08-17 and is REVIVED:
  under a split licence it binds again, and neither permissive crate may take a
  `foundation-*` dependency.
- **Amendments the owner's answers forced, in one place for auditability:** Q4's floor
  moved 6 -> 4; Q5's N moved 10 -> 15 and gained a settable policy, which is a format
  change inside the m3 freeze (policy_log cells, two superblock fields, eight canary
  bytes, `failures_base` in the ledger head); Q7 gained a 2 MiB `media` partition taken
  from the app's declared span so no existing offset moved; Q11 lost NFC from the
  on-device text list; Q13's numbers were re-derived from Coldcard, Trezor, SeedSigner and
  rust-bitcoin source and gained an absolute-fee axis; Q39 completed to CC0-1.0 vectors;
  Q56 and Q37 resolved to their Q2(a) branches.
- **Sub-items that were left as implementation design and are now CLOSED:** whether
  wipe-after-N is runtime-mutable is answered (it is, and Q5.1-Q5.4 specify how). The
  scope of the stateless multisig refusal (Q12) remains the one open implementation
  detail, is settled at m6, and its recommended answer - the broader scope - is recorded.
- **What the re-scope removed from 0.2.0, as a checklist for the parity audit at m13:**
  encrypted backups of either profile, device clone, any Key Teleport equivalent, BSMS,
  taproot multisig, BIP-85, Seed XOR, Lock Down Seed, BIP-322 and proof-of-reserves,
  message signing, Secure Boot v2 and eFuse anti-rollback, third-party build attestation,
  the release-key hardware token, and the HIL power-cut rig. Every one of them has a row
  in MILESTONES section 7.4 with the reason, and none of them is silently dropped.

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
