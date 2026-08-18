# notyas 0.2.0 - Open questions for the user

Status: PLAN. Decisions the plan cannot make alone. Each has a recommendation; the
plan documents assume the recommendation unless overruled. Q1-Q5 block m1 (they pin
SPEC/SECURITY text); the rest can be decided during their milestone.

## Q1. Production silicon revision (blocks nothing in 0.2.0, shapes 0.3.x)
Both bench units are rev v1.3; the ESP32-P4 Key Manager (HUK/SRAM-PUF-bound keys)
requires rev >= v3.0
(https://docs.espressif.com/projects/esp-idf/en/stable/esp32p4/api-reference/peripherals/key_manager.html).
0.2.0 designs for v1.x (HMAC-eFuse path) and works on both.
RECOMMENDATION: confirm what revision production hardware will carry before 0.2.0
release units are provisioned; if >= v3.0, schedule a Key-Manager-backed ladder
upgrade as 0.3.x (stronger key story, same record format).

## Q2. Duress PIN: ship in 0.2.0? [BLOCKER - red-team analysis changed the shape]
Original framing: architecture supports it cheaply (decoy slot set, no stored
marker - Coldcard trick-PIN precedent,
https://blog.coinkite.com/understanding-mk4-security-model/).

RED-TEAM FINDING (2026-08-17): "indistinguishable by construction" was FALSE as
drafted, in two independent ways:
1. Slot occupancy is visible in a pre-PIN flash dump (the plan itself says a dump
   "reveals only that sealed slots exist" - that IS the leak). A coercer who sees
   3 occupied slots and is shown a 1-wallet decoy set knows there is more.
2. The Verify screen as drafted reports "blank / N sealed slots" - the true wallet
   count, readable by anyone holding the device, no PIN needed.

Shipping duress honestly therefore requires the full package:
- All slots ciphertext-filled at all times: unused slots hold device-bound
  pseudorandom filler (HMAC-eFuse-derived stream - no RNG, satisfies invariant 3;
  indistinguishable from sealed records to anyone without the eFuse key, i.e., to
  every attacker below the fault-injection tier that breaks everything anyway).
- Verify screen storage readout degraded to "storage: present/blank" - a real
  honesty cost to invariant 5, permanently, for ALL users, whether or not they
  enable duress (a readout that changes when duress is enabled would itself be the
  marker).
- Wipe/delete semantics must rewrite filler, not leave erased-flash signatures
  that betray "a wallet was deleted here".

DECISION NEEDED: (a) ship duress WITH the package above (deniability wins, Verify
loses slot-count honesty for everyone); (b) ship duress WITHOUT the package,
documented as "coercer sees the wallet count, duress hides only which PIN opens
what" (weaker but honest); (c) drop duress from 0.2.0 and keep the full-count
Verify readout. The three are mutually exclusive; the plan text currently claims
none of them.
RECOMMENDATION: (a), in m9, OFF by default - filler slots and the degraded readout
are cheap, and a duress feature that leaks the wallet count is worse than none
(it invites the coercion it cannot survive). If (c) is chosen instead, the Verify
screen keeps "N sealed slots" and SECURITY.md invariant 5 reverts to the plain
readout. A wipe-PIN variant (silent destroy on entry) stays deferred either way -
it invites accidental self-harm and the deterministic-wipe posture already covers
the coercion case partially.

## Q3. Wipe-after-N default
Counter is advisory against a lab attacker but decisive against theft-and-tinker.
Because notyas wallets are re-derivable from the user's backup, wipe is recoverable.
RECOMMENDATION: N=10, not configurable below 3 or above 25; the setup screen states
the policy and that the backup is the recovery path.

## Q4. Randomness policy ratification
The plan picks fully-deterministic sealing (no RNG anywhere; derived salts, monotonic
seal_seq nonce uniqueness; deterministic no-aux-rand BIP-340) over TRNG-for-salts,
because it keeps invariant 3 mechanically checkable and the P4 TRNG is already
distrusted (esp-hal#5982). See ARCHITECTURE 2.4 for the construction.
RECOMMENDATION: ratify as written. This is the highest-leverage decision in the plan;
overruling it changes SECURITY.md invariant 3 and the record format.

## Q5. PIN format and floor
Post-fault-injection, offline guessing is bounded only by PIN/passphrase entropy
(6-digit PIN falls in days-to-weeks at 1 s/guess Argon2id; storage research 3.2).
RECOMMENDATION: minimum 6 digits, full alphanumeric supported and actively nudged
(entropy meter at creation, honest wording: "a digits-only PIN protects against
theft, not against a funded lab"). No maximum below 64 chars.

## Q6. BSMS (BIP-129) support tier
Spec complete, adoption thin; Coldcard implements, most others do not
(https://github.com/bitcoin/bips/blob/master/bip-0129.mediawiki).
RECOMMENDATION: not in 0.2.0. Descriptor import + mandatory first-address
cross-device comparison covers the security need. Keep the format on file.

## Q7. Taproot multisig timing
tr() multi-leaf / musig coordination is not yet stable interop territory across our
target coordinators; P2WSH sortedmulti is what Sparrow/Specter/Coldcard multisig
actually is today.
RECOMMENDATION: 0.2.0 multisig = P2WSH sortedmulti (BIP-48) only; taproot single-sig
(BIP-86) fully supported for signing. Revisit taproot multisig at 0.3.x.

## Q8. Encrypted SD backup export (Passport/Krux pattern)
Users love it ("more manageable than 24 words",
https://foundation.xyz/2023/01/why-we-love-encrypted-microsd-backups/), but it is a
second sealed-secret artifact whose security rests entirely on its passphrase, and
it dilutes the "SD is untrusted, backup = your mnemonic" story.
RECOMMENDATION: not in 0.2.0. The mandatory backup-verify quiz plus deterministic
re-derivation is our backup story. Reconsider for 0.2.x with explicit
"this file's security = this passphrase" labeling if users ask.

## Q9. Blind-oracle unlock mode (Jade model)
The only known way to give a no-SE device real offline-brute-force resistance
(https://blog.blockstream.com/jade-virtual-secure-element/), but every unlock needs a
network-connected helper, against the single-device airgap identity.
RECOMMENDATION: not in 0.2.0, documented in SECURITY.md as a known alternative with
its tradeoff. Revisit only if user demand materializes; self-hosted oracle +
QR-transport variant would be the shape.

## Q10. Anti-phishing words and lock-screen word
Both require nothing but HMAC-eFuse and UI work.
RECOMMENDATION: ship both in 0.2.0 (anti-phishing words at half-PIN in m4; the
user-chosen lock-screen word likewise). Cheap, unique swap-detection value.

## Q11. Stateless signing (sign without ever saving a wallet)
The plan keeps "use once, keep nothing" for generation. Should a user also be able
to LOAD a seed transiently (dice/mnemonic entry) and sign a PSBT with it, SeedSigner
style, no storage ever touched?
RECOMMENDATION: yes - it falls out of the session design (a session need not come
from a sealed slot) and preserves the 0.1.0 identity for storage-averse users.
Limitation stated honestly: stateless multisig signing cannot verify cosigners
against a registration; the review screen labels multisig change UNVERIFIED in that
mode (or we refuse multisig change claims statelessly - recommend refuse-by-default
with an expert override).

## Q12. Fee thresholds
RECOMMENDATION: warn at fee > 5% of send value or > 500 sat/vB; hard-block only on
negative fee and rust-bitcoin's absurd-fee extraction guard; always show absolute
sats + sat/vB + percent. Numbers are policy constants in notyas-wallet, adjustable
in Settings behind an expert gate. (Coldcard defaults to a 10% cap.)

## Q13. ECDSA low-R grinding and the scope of signing equivalence [BLOCKER for
invariant-4 wording; added by the red-team pass 2026-08-17]
The draft plan claimed "byte-identical signatures to reference signers (Bitcoin
Core)". That claim is unachievable as written and has been corrected in the plan
texts: Bitcoin Core signs BIP-341 with RANDOM aux-rand (its Schnorr signatures
differ run to run by design), and Core grinds ECDSA nonces until the signature
has a low R (71-byte DER, since Core 0.17), while plain RFC6979 - what
rust-bitcoin's Psbt::sign produces - yields a high-R signature roughly half the
time. Two consequences:
1. Schnorr byte-equality vs Core is impossible, period. Our equivalence claim for
   Schnorr is: byte-identical to the official BIP-340 no-aux vectors, and
   Core-verified on regtest.
2. ECDSA byte-equality vs Core IS achievable if we grind low-R with the same
   algorithm (libsecp's grind loop, exposed as sign_ecdsa_low_r in the secp256k1
   crate) - at the cost of not using Psbt::sign's stock signing loop and a small
   variable signing-time cost.
DECISION NEEDED: adopt low-R grinding (Core-identical ECDSA bytes, predictable
71-byte signatures and thus exact fee/vsize prediction, stronger differential
testing) or stay on stock RFC6979 via Psbt::sign (simpler code path, equivalence
= verified-and-accepted only).
RECOMMENDATION: adopt low-R grinding. Predictable signature size is worth it on a
device that shows the user a fee it must stand behind, and byte-level ECDSA
differential testing against Core is a materially stronger CI gate. Either choice
must be pinned in SPEC at m1 because invariant 4's text depends on it.

## Red-team disposition note (2026-08-17)
The adversarial review pass fixed everything it could directly in the plan texts
(see each file's "red-team" annotations). Only two items required human decisions
and live here: Q2 (duress deniability package - the draft's indistinguishability
claim was false without it) and Q13 (signing equivalence scope - the draft's
byte-identical-to-Core claim was impossible). Q1-Q5 still block m1 as before;
Q13 joins them.
