# notyas 0.2.0: interaction patterns to adopt, anti-patterns to avoid

Sources: the six teardowns above, cross-read against `<the working tree>\notyas\docs\plan-0.2.0\` (`UX.md`, `UX-SCREENS.md`, `PIN-MODES.md`, `VERIFY.md`). Where notyas already specifies a pattern I say so, because the useful output is the delta, not a restatement.

---

## 1. First run and onboarding on a device that stores nothing yet

**Adopt**

1. **Defer the PIN to the first thing worth protecting.** PIN creation is reached from the save-a-wallet fork, never from first boot; a device that has never saved a wallet never asks for a PIN. No surveyed device does this - Coldcard, Passport, Trezor, BitBox02 and Jade all demand a secret before the user owns anything worth locking. SeedSigner is the closest by omitting the concept entirely. notyas S-19 -> S-06 is the correct shape and is currently unique in the field.
2. **State statelessness as a capability, not an absence.** Best: SeedSigner's Power menu, whose only real action is a screen titled "Just Unplug It" reading "It is safe to disconnect power at any time." The device turns its own architecture into an instruction; the off affordance is a permission slip, not a process. notyas S-19's "Use once, keep nothing" card is the same move applied at the moment of consequence rather than at shutdown - keep both moments.
3. **Present the two ways to own the device as a fork at the point of consequence, not a settings toggle at setup.** Two full-width cards with the storage consequence spelled out in each ("Nothing is written... the seed is gone and you retype the words") is more honest than any onboarding wizard in the survey, because the choice is made when the user can see what it costs.
4. **Bind identity during onboarding so later swap checks have a baseline.** Coldcard and Passport derive anti-phishing words from a device secret; Specter-DIY additionally folds the paired smartcard's public key into the same words. notyas adds a user-chosen lock word and nickname (S-03). Add one more thing nobody does: prompt the user, once, to record the hardware identity values off-device (MAC, die unique ID, flash JEDEC + unique ID, `VERIFY.md` 9.2 item 3). A substituted unit then has to lie about them rather than merely display them.
5. **BitBox02's restore rule, generalized:** force a brand new device password at the end of every microSD restore rather than carrying the old one over. It closes "stale unlock secret survives onto new hardware" by construction instead of by advisory.

**Avoid**

- **Onboarding that needs a second computer before the device works at all.** SeedSigner (verify a GPG signature, reflash an SD card) and Specter-DIY (source a genuine board, solder a header, flash an unverified first image from "a secure computer") both push supply chain and assembly onto the user.
- **Tiering that keeps the name and drops the differentiator.** Jade Core carries the Jade name with no camera, so no SeedQR, no stateless QR signing, no air-gapped flow at all. Reviewers report buyer confusion.
- **Onboarding that never mentions the unforgiving parts.** Coldcard's "no PIN recovery, ever" and Trezor's "a passphrase cannot be changed, removed, or recovered" are true, correct for the threat model, and discovered by most users at exactly the wrong moment.

---

## 2. Entropy entry, and justified confidence in it

**Adopt**

1. **Live, dual, honest progress during collection.** Best: Krux - one bar for rolls against the minimum, a second for running Shannon entropy against target, frame recoloring on success, plus a "Stats for Nerds" roll-distribution histogram. A biased die becomes visible before the mnemonic is generated instead of after. notyas S-12 has the strength meter but not the distribution view; the histogram is cheap and it is the only mechanic in the survey that catches a loaded die.
2. **Reproducibility is the confidence mechanism; a meter is only a hint.** Best: SeedSigner - `docs/dice_verification.md` walks dice string -> mnemonic -> fingerprint -> zpub -> receive and change addresses, cross-checked against Sparrow, iancoleman and bitcoiner.guide, and ships `tools/mnemonic.py` running **the identical production code path** standalone. Coldcard publishes the exact construction (SHA256 over the ASCII roll string) plus a verification script. The SeedSigner version is better because the CLI is the same code, not a reimplementation that can drift.
3. **Name the compatibility mode on screen.** notyas already labels RAW (iancoleman-compatible) and FIXED (Coldcard/SeedSigner-compatible). That label is what makes the off-device check possible at all; without it the user does not know which tool to compare against. Keep it visible on the mnemonic screen too, not only during entry.
4. **Show the entropy hash on the device.** Krux displays the SHA-256 of the collected entropy so the comparison unit is short enough to transcribe or photograph.
5. **Liveness checks where the source can stall silently, plus honesty about their limits.** SeedSigner's image entropy rejects a flat-color frame and a SHA256-duplicate frame (modeled on NIST SP 800-90B 4.2) and explicitly does not claim to measure entropy quality it cannot assess. Adopt the disclaimer as much as the check.
6. **State the consequence, do not refuse the user's own choice.** notyas S-12 keeps Done available below the minimum with a WARNING band. Correct.

**Avoid**

- **Any bit count for something the device did not choose.** notyas already forbids this for PIN strength (`S-06`: the meter says "digits only", never a bit count). Apply the same rule to any user-supplied entropy path.
- **Making an experimental, environment-dependent source a headline path.** Krux's photo entropy is marked "(Experimental!)" and depends on lighting and contrast; the mechanical dice path does not.
- **Trusting the on-chip TRNG with no external check.** notyas invariant 3 already distrusts the P4 TRNG - this is a real differentiator and should be said on the entropy screen, not only in `SECURITY.md`.

---

## 3. PIN entry, wrong-PIN backoff, and an honest wipe policy

**Adopt**

1. **The device authenticates itself before the user authenticates to it.** Passport does this earliest - anti-phishing words after only 4 digits, the earliest possible point at which a swapped device is caught before more PIN is revealed. Coldcard does it strongest - the words are bound to the secure element, so a cloned unit running byte-identical firmware cannot reproduce them. Specter-DIY does it most economically - the words key off the device secret **and** the smartcard public key, so one glance covers two swap vectors.
2. **Seeing the words must cost no attempt, and a wrong prefix must still produce words.** notyas S-04 specifies both ("Available after 4 digits. Seeing them costs no attempt", and words are derived from whatever was typed so they cannot become a prefix oracle). No surveyed vendor documents either property. This is a genuine notyas lead - keep the hint line on screen so the user knows the look is free.
3. **Randomized keypad, reshuffled per attempt, not per keystroke.** Per-keystroke shuffling causes mistaps. notyas C10 additionally draws the press feedback on the dot row rather than the key, so touch-down never reveals position - the only control in the product with no local press feedback, and deliberately so. Trezor's blind matrix (host shows blank positions, device shows the shuffled digit map) is the strongest version of the idea; the transferable principle is that feedback is deliberately non-local.
4. **Render backoff as a live countdown anchored to a persisted counter.** notyas S-05: "Try again in 0:47", "The wait doubles after each wrong PIN", "8 of 10 tries left", and "Powering off does not skip the wait" shown only because it is true. Trezor has the exponential curve; nobody surveyed renders it as a countdown instead of a frozen device.
5. **Always show remaining tries as a number, and escalate the copy at <= 3** to name what is destroyed and what the recovery path is. Coldcard's hard ceiling of 13 is knowable but not surfaced per-attempt.
6. **Compute the warning from the user's actual PIN length.** `PIN-MODES.md` requires the disable-wipe modal to state the concrete guess count for the PIN in use, because a 4-digit PIN and a 12-character PIN are not the same decision. No surveyed device does anything but state a policy in the abstract. This is the single most honest piece of copy in the whole plan.
7. **Authenticate the policy inside the AEAD.** If N and wipe-on/off can be changed without the PIN, an attacker turns wipe off and guesses freely, and the counter was theatre. This is the structural fix for Krux's failure below.
8. **If duress ships at all, steal these two mechanics regardless of which model you pick:** trick-PIN attempts never increment the real PIN's failure counter (Coldcard), so a user can rehearse without burning budget; and the destructive response executes before any confirming UI is painted (Coldcard Brick Self, ~50 ms), so an onlooker cannot interrupt or even observe it. Jade's Wallet-Erase PIN shows the right surface: a generic "Internal Error" and a drop back to onboarding, deniable because it is indistinguishable, not because it is labeled.
9. **Warn, do not block, on weak PINs.** notyas S-06 allows `111111` with "This PIN is one of the first an attacker tries." A blocklist teaches attackers the blocklist.

**Avoid**

- **A counter whose displayed number is not the number of chances.** Specter-DIY decrements and persists the attempt counter *before* comparing the PIN, so the documented "10 attempts" is 9 usable guesses and the 10th wipes without ever checking whether it was correct.
- **Backoff that a reboot skips.** Krux shipped encrypted mnemonics with no throttle at all for about eighteen months; the exponential backoff added in 26.04.0 still resets on reboot and never persists a lockout.
- **Unlock that depends on a network service.** A non-camera Jade Core cannot be unlocked without a companion app relaying an ECDH handshake to a live PIN oracle. A physically fine device with intact secrets becomes unusable when reachability fails.
- **No access-control gate once a secret is in RAM.** Krux and SeedSigner will both sign for whoever picks up the powered device. Krux's TC Code detects tampering and then just powers off; it gates nothing, including USB reflash.
- **A wipe threshold the vendor never documents.** Keystone's own support material does not state keypad mechanics, randomization, or the wipe threshold; third-party sites repeat an unsourced "10 attempts."
- **Naming a feature something users will misread.** "Wallet-erase PIN" versus duress-PIN expectations generated real confusion on Blockstream/Jade issue #49.
- **A hard brick with no escalating on-screen urgency.** Passport's 21-attempt lockout has no documented countdown warning between attempts.

---

## 4. Showing a seed phrase, and hiding it again

**Adopt**

1. **A reveal gate whose modal states exactly what is about to happen** ("The seed words will appear on this screen in plain text"), with a **fixed-run mask** such that two different mnemonics render byte-identical masked frames - asserted by a pixel test. notyas 0.1.0 has this. Nobody else in the survey makes the byte-identical claim, and it is the mechanic that makes a mask trustworthy rather than decorative.
2. **Mandatory backup verification before the words can be dismissed.** Best: BitBox02's every-word quiz. notyas S-17 improves on it concretely: five candidates weighted toward confusables (same 4-letter BIP-39 prefix first, then edit distance 1), a wrong answer restarts **that word only**, distractors derived deterministically from `HMAC_efuse` so no RNG is involved, and a CI test asserting the correct answer lands in each of the five slots with equal frequency. The uniform-position test is the part nobody else has and the part that stops the quiz leaking its own answer through layout.
3. **Re-verifiable forever without exposure.** Trezor's dry-run pattern: re-enter the words later, the device answers match / no-match only.
4. **Make re-verification a one-tap standing action, not a setup-only ceremony.** Nunchuk's "Run health check" is the right framing - a lightweight, repeatable, no-transaction re-derivation living on the wallet detail screen.
5. **Hiding is a deliberate, per-item, color-coded act.** SeedSigner's "Discard Seed?" modal with the Discard button uniquely styled red, distinct from every other button in the app, because dropping a seed must never be a side effect of navigation.
6. **Warn before an auto-lock drops the session, without covering what is being read.** notyas S-49's bottom band ("Locking in 20 s. [ Stay unlocked ]") is better than Krux's Auto Shutdown, which simply powers off on a timer and can ambush a user mid-address-verification.

**Avoid**

- **Sampling the backup check.** Every word, every time; ~2 minutes is the only moment the device can catch a transcription error while the words are still on the table.
- **Restarting the whole quiz on one wrong tap.** It punishes a fat finger with 24 re-taps and trains people to rush.
- **Relying on a managed runtime to scrub secrets.** SeedSigner sets photo bytes, hash chains and mnemonic lists to `None` and relies on power-cycle-clears-RAM plus CPython GC; there is no prompt or scrubbed deallocation guarantee within a session. Rust zeroize-on-drop is a real, statable advantage over every Python/MicroPython device in this survey (SeedSigner, Krux, Specter-DIY).
- **Any QR rendered from secret material** (notyas invariant; keep it).
- **Transcription burden without transcription tooling.** SLIP-39 users report writing 3 to 5 shares of 20 to 33 words each, and one could not tell a doubled word at positions 3/4 from expected content. Error opportunity scales linearly with share count.

---

## 5. Verifying the device and firmware are genuine

**Adopt**

1. **Reachable before PIN entry.** notyas S-03 puts a "Verify device" chip on the lock screen precisely so a user who suspects a swap can check without typing a digit into the suspect device. Coldcard is the strongest form of the same principle: the GENUINE / CAUTION verdict is delivered by a hardware LED driven by the secure element **before** PIN entry, so the verdict does not travel through the channel under suspicion. Rule: never render a genuineness verdict on the surface that might be lying.
2. **Host-independent challenge-response with a human carrying the value.** Best: Passport - the vendor page shows a signed random challenge as a QR, the device derives BIP-39 words from its secure element's response, the user **types the first four words back into the web page by hand**. The connecting computer is removed from the trust path for the verification result itself. Keystone's Web Authentication is the same shape with an 8-digit code against a server-issued nonce, so a captured "genuine" response cannot be replayed.
3. **Split the fingerprint so the user can tell what changed.** Krux's TC Flash Hash renders one memorable image plus two two-word pairs: the first pair changes only if firmware or bootloader changed, the second only if settings or stored mnemonics changed. That answers "did my firmware change, or did I just save a wallet?" without hex diffing. notyas should adopt the split explicitly - its two-digest, one-scan design in `VERIFY.md` 3.3 already has the right regions; the delta is rendering them as two independently readable comparands rather than one wall of hex.
4. **Continuous, silent attestation so the user does not have to remember a ceremony,** with one memorable interaction as the tamper signal. BitBox02 runs its attestation check essentially every use, and teaches the property through the pairing code: an unexpected re-pairing prompt on an already-trusted pair is documented as the thing that should raise suspicion.
5. **Record hardware identity off-device once.** MAC, die unique ID, flash JEDEC and unique ID. A look-alike must forge these on different silicon rather than merely display them.
6. **Say what the check cannot do, in one line, without a warning band.** notyas's wording is the best honesty in the entire field: `These values are read from the chip and from flash by the firmware running on this device.` Compare Krux, which concedes "Experimental" plus an SD-card bypass mitigated only by procedural advice. Keep the notyas line as a provenance note, MONO_SMALL, INK_SECONDARY, no colour, no icon - it opines about nothing and is short enough to actually be read.
7. **Supply chain before power-on.** Coldcard by a distance: bag number recorded in device flash at the factory, an internal tear-off tab to cross-check it, a multi-layer VOID seal, a moisture-indicator strip that dyes blue if the bag was steamed open, and a transparent case so an implanted chip has nowhere to hide. Three independent tamper signals plus visual inspection, all checkable before the device is ever powered.

**Avoid**

- **A verdict rendered by the app that could also be lying.** Jade's Genuine Check and Trezor Suite's counterfeit check both display pass/fail in the same host software whose compromise is part of the threat model.
- **A tamper check with a documented bypass mitigated only by procedure.** Krux: copy flash to SD, run altered firmware that hashes the SD copy; official mitigation is "avoid verifying while an SD card is inserted."
- **Per-model verification gaps.** Trezor Model T has no secure-element device authentication; the Safe family does. Same brand, same UI, different guarantee.
- **No post-boot on-device check at all.** SeedSigner's chain ends when the SD card is flashed; there is no on-device way to ask "am I still running what I verified."
- **Reproducibility claims that exclude the code holding keys.** Bitkey's firmware cannot be reproduced end-to-end because the fingerprint-matching library is proprietary; the reproducible artifact is the mobile app.
- **A device that shows its digest next to "and here is what it should be."** That is a device comparing itself against itself (`VERIFY.md` 9.2.2). The comparand must come from off-device.

---

## 6. Irreversible-action confirmation

**Adopt**

1. **One component, four grades chosen by consequence** (notyas C4, the most complete scheme in the survey - the field mostly reuses one dialog for everything):
   - yellow card, reversible (overwrite an SD file), buttons spatially separated;
   - red card, destructive but recoverable from backup, with a mandatory consequence line naming what dies and what the recovery path is;
   - hold-to-confirm, 1500 ms with a progress fill, for irreversible-in-effect (sign, early wipe);
   - typed-name, for unrecoverable-on-device (delete wallet, factory wipe), with `WIPE` as the required word where there is no name.
2. **Hold duration is a constant, never a setting.** A user-shortenable hold is a user-shortenable safety interlock.
3. **Release without scolding.** Fill resets instantly, label returns, one secondary line: "Released - nothing was signed." No modal.
4. **Counts read from the store, not generic phrases.** "This erases all 3 wallets, 2 multisig registrations, the PIN and all settings."
5. **Disabled controls carry their reason beside them** ("Name does not match yet.", "Review all 7 pages first - 2 not yet seen."). Never a silent dead button.
6. **Get the direction of the warning right.** This is notyas's sharpest and most contrarian copy decision, and no surveyed vendor makes the distinction: turning the PIN **off** is a data-loss event and simultaneously the safest state the hardware can be in, so the modal must name what is destroyed and must **not** claim the device is becoming less secure. Disabling **wipe** is the inverse - nothing is lost and the security consequence is real, so that modal states the concrete guess count for the PIN in use and offers the longer-PIN path rather than only accept/cancel. Every other vendor treats "less protection configured" as uniformly worse, which teaches users the wrong instinct.
7. **Stack two grades only for the one action that destroys everything at once.** notyas S-48 requires typed `WIPE` *and* a hold. Reserving the double gate for exactly one action is what keeps it meaningful.

**Avoid**

- **The same dialog for "overwrite a file" and "erase every key."** Grade must track consequence or the grammar stops carrying information.
- **A one-directional review that cannot step back.** BitBox02 lets you scroll forward or decline and restart, with no way to re-check a field you scrolled past.
- **Treating a no-confirmation destructive action as a general pattern.** Coldcard's Brick Self, with no confirming UI at all, is correct for coercion and wrong as an ordinary settings item; keep zero-confirmation destruction strictly inside a duress path if one ever ships.
- **Making a whole-device brick reachable by ordinary error with no urgency signal** (Passport, above).

---

## 7. Error and refusal states

**Adopt**

1. **The three-part refusal, as a screen.** notyas C7 is the best-specified refusal grammar in the survey and nothing in the field is close: a `DANGER_TINT` header band with a stable refusal code, then **What happened** (facts about this specific file), **Why this matters** (the attack or fault it defends against, one or two sentences), **What to do** (the user's next action). Any refusal that cannot fill all three sections is under-specified and does not ship. A refusal is never a modal, because a modal invites dismiss-without-reading.
2. **A `[ Show details ]` mono block with the machine facts** - input/output index, txid, claimed path, script type, policy check number - because this is what gets photographed for a bug report. Mono, complete, and never containing key material.
3. **Route the user forward with information the device already has.** notyas's wrong-wallet refusal names the stored wallet whose fingerprint matches ("these inputs belong to 'savings' (a1b2c3d4) - open it to sign") instead of a bare "nothing to sign." This is the single highest-value refusal in the plan because it rescues a guaranteed first-timer dead end.
4. **Fail loudly on a wrong secret rather than silently deriving a different wallet.** Krux's KEF decrypt returns a hard error on a wrong key and its docs name this as a deliberate tradeoff against passphrase-derived hidden wallets. Where a wrong input legitimately yields a different wallet (BIP-39 passphrase), echo the resulting fingerprint and make the user own it.
5. **Assert refusal text in CI**, exact literals, so it cannot rot (notyas m6 gate).
6. **Reuse the industry vocabulary rather than inventing it.** "Verify address on your device", "verify this address" - Sparrow, Nunchuk and the Electrum ecosystem all converged here. Do not invent "confirm receiving address."

**Avoid**

- **Accepting an input in the wrong role instead of rejecting it.** Krux 25.09.0 to 25.10.0: a base43-encoded KEF envelope scanned at a BIP-39 passphrase prompt was used as the literal passphrase text, silently deriving the wrong wallet.
- **Mislabelling identity on the one screen where identity moves money.** Trezor Suite repeatedly labelled the plain standard wallet as a numbered "Hidden wallet" when passphrase was off or blank (issues #2578, #3207, #7927, #8029).
- **The audit screen itself being wrong.** Electrum's Wallet -> Information dialog rendered only the first cosigner's master public key regardless of quorum size (#4777), in the exact screen meant to let a user audit their multisig, and it went unnoticed until milestone 3.4.
- **Gating the material facts behind "Advanced."** Electrum's transaction preview hides input and output addresses and the change address behind a checkbox, so a user who never finds it broadcasts on amount and fee alone.
- **Burying the verification unit.** Sparrow's always-visible Keystores table (Label / Master fingerprint / Derivation / xpub) on the same screen as the quorum policy is the target; Electrum's one-menu-level-down Information dialog is the anti-pattern.

---

## 8. Waiting and progress, where work is synchronous and uncancellable

**Adopt** (notyas C3 is already the strongest specification in the survey; these are its load-bearing rules, plus two additions)

1. **The 150 ms law.** Any operation that can block the input loop for more than 150 ms paints a Busy frame **and publishes it to the panel before the work starts**. A blocking derivation with no painted frame is indistinguishable from a crash - 0.1.0 learned this the hard way.
2. **Fixed content order:** gerund heading ("Deriving keys", "Reading card", "Signing", "Writing to card"); one or two mechanical lines saying what the device is actually doing, with no reassurance; then progress.
3. **Exactly two honest kinds of progress.** Determinate - a filled trough plus "step i of n" - only where units are countable (4 schemes, i of n inputs, i of 1528 addresses, i of n QR fragments, quiz words). Otherwise indeterminate elapsed seconds ticking at 1 Hz. Never a fake percentage; never a spinner the repaint model cannot animate honestly.
4. **Exactly one trailing line, and only when it is true.** "This cannot be cancelled." / "Do not remove the card." / "Do not power off." - the last one only while a flash write is actually in flight. 0.1.0 said "Do not power off" during pure computation, which is false and trains people to ignore the warning when it matters. Killing that line is the highest-value small fix in the whole plan and it is a lie shipped by most embedded UI.
5. **No Back in the bar during Busy.** A Busy screen with a live Back is a lie about what the loop can do.
6. **A Stop button only where the loop can check between units,** and a stopped operation returns to its launching screen with a status line ("Search stopped at index 412 of 1528."), never to a blank state.
7. **Countdown, not a frozen screen,** for the wrong-PIN delay (S-05).
8. **Progress for user-paced work too,** not just machine work: Krux's dual dice bars, and Krux's Flash Map grid of occupied versus empty 4KB blocks, which lets a user visually confirm that "erase user data" touched the memory it claimed to. That second one is worth stealing directly for the post-wipe screen - it makes an invisible destructive operation observable.
9. **Treat QR playback as a waiting state.** Pause, three speed steps, three density steps, frame i/j, and a status line stating that the fountain code loops forever - because "I missed a frame" is the single most common support question.

**Avoid**

- **Indeterminate spinners on a tick-driven repaint model.** They either lie or stutter.
- **Any timer that advances a review page.** Traversal must be user-driven and enforceable.
- **Silent multi-second waits after a tap.** Post-Mk3 Coldcard hardware imposes an unavoidable ~4 s secure-element delay per PIN attempt; the delay is defensible, the absence of a rendered story about it is not.

---

## The single highest-leverage UX decision

**Make every claim the device makes independently re-checkable off-device through one uniform affordance, and design the whole product around never asking to be believed.**

The mechanic, concretely:

- A single chip in the top bar - one region, one label, one place - on **every** screen that asserts a verification value: the mnemonic derived from these rolls, an address at a path, an xpub with its key origin, multisig membership, the firmware and flash digests, the backup-check result, the signed PSBT.
- Tapping it writes `receipt-<kind>-<seq>.txt` to SD and offers the same bytes as a UR QR. Plain ASCII, no secret material, and it states the exact construction: algorithm, domain strings, the entropy mode label (RAW / FIXED), derivation path, script type, the comparand it claims.
- A `notyas-verify` tool - reproducible-built, hash-published in the same signed manifest as the firmware - consumes a receipt on the user's own computer and prints MATCH or MISMATCH plus the recomputed value.
- On-device, the caveat stays one provenance line. The device never shows the answer next to itself.

Why this is the one to make:

Every device in this survey asks to be trusted somewhere, and each one hides that fact in a different place. Coldcard's two secure elements are a vendor claim with no independent audit of the attestation chain. Jade and Trezor render the verdict in the same app that could be lying. Krux's tamper check has a bypass mitigated by advice. SeedSigner's trust chain ends when the SD card is flashed. Bitkey's reproducibility does not cover the firmware holding a key. Meanwhile the two best verification experiences in the field - SeedSigner's `tools/mnemonic.py` and Coldcard's published dice construction - both exist for **entropy only**, and Sparrow's PSBT inspection only works on a machine you already trust.

notyas has an honest structural weakness that this converts into its organizing principle: with software attestation and no secure element, `VERIFY.md` 9.1 already concedes that firmware which has been replaced controls every value on the Verify screen. The correct response to "this device cannot prove its own honesty" is not a better badge - it is to architect the product so nothing it says ever has to be taken on faith. Every assertion leaves with a portable receipt; every receipt is re-derivable by an open tool the user rebuilds. That is a claim no wallet in this survey can make across its whole surface, and it is fully compatible with the airgap (SD and QR out, no radio) and with the three-state PIN model.

The second-order win is the one that actually meets the owner's bar. It gives the product **one ritual, learned once, applied everywhere** - the same chip in the same place for a seed, an address, a quorum, a firmware digest, a signature. Every other device teaches five unrelated verification ceremonies and the user performs none of them twice. A single repeatable ritual is the difference between having security features and being world class.

Runners-up, and why they lose: a Coldcard-style duress spectrum is more feature-rich but adds a large, coercion-specific surface that Foundation declined on defensible grounds, and it does not change the trust question. A secure element for hardware-rooted attestation is the right long-term answer but it is a hardware decision, not a UX one, and it would still be a vendor claim rather than something the user can check.