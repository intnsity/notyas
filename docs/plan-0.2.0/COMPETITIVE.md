# notyas 0.2.0 - Competitive feature matrix, gap ranking, and anti-patterns

Sources: the six supplied teardowns plus this repository (README.md, docs/plan-0.2.0/{INDEX,MILESTONES,PARITY,PIN-MODES,VERIFY,UX-SCREENS,OPEN-QUESTIONS}.md). Every notyas cell is traced to a milestone or a ratified decision, not inferred.

## Legend

Devices: **CC** Coldcard Mk4/Q, **SS** SeedSigner, **KX** Krux, **PP** Passport Core, **JD** Jade Plus, **TZ** Trezor Safe family, **BB** BitBox02, **SP** Specter-DIY, **KS** Keystone 3 Pro, **BK** Bitkey.

Cells: `Y` present, `P` partial, `N` absent, `D` present in the field but declined by that project on principle, `?` not evidenced in the supplied research (treat as unknown, not absent).

**P4** = feasibility on an airgapped ESP32-P4 touch device, no radio, optional CSI camera: `Y` feasible, `C` needs the camera, `W` feasible but weaker without a secure element, `X` hardware-impossible.

**notyas** column: `0.1` shipped, `m<N>` planned in 0.2.0 at that milestone, `0.3` deferred, `REJ` rejected permanently, `HW` in 0.2.0 but contingent on a camera module arriving, `NO` absent and unplanned.

---

## 1. Entropy and seed creation

| Capability | CC | SS | KX | PP | JD | TZ | BB | SP | KS | BK | P4 | notyas 0.2.0 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| D6 dice entropy (50/99 rolls) | Y | Y | Y | ? | N | N | N | ? | ? | N | Y | 0.1 (RAW + FIXED, 6 modes) |
| D20 dice entropy (30/60 rolls) | N | N | Y | N | N | N | N | N | N | N | Y | NO |
| Live roll counter / running entropy readout | Y | N | Y | ? | N | N | N | N | N | N | Y | 0.1 (effective bits + history) |
| Roll-distribution histogram (bias check) | N | N | Y | N | N | N | N | N | N | N | Y | **NO** |
| On-screen SHA256 of the roll string | N | N | Y | N | N | N | N | N | N | N | Y | **NO** |
| Published independent verification tooling | Y | Y | Y | N | N | N | N | N | N | N | Y | 0.1 (desktop BigDice + committed vectors) |
| Declared cross-tool dice compatibility, labeled in UI | P | P | P | N | N | N | N | N | N | N | Y | 0.1 (RAW=iancoleman, FIXED=CC/SS) |
| TRNG seed generation | Y | N | N | Y | Y | Y | Y | Y | Y | Y | X | REJ (P4 TRNG weak, esp-hal 5982) |
| TRNG+dice XOR mixing | Y | N | N | ? | N | N | N | N | N | N | X | REJ |
| Camera / image entropy | N | Y | Y | N | N | N | N | N | N | N | C | REJ (breaks determinism invariant) |
| Coin-flip entropy for free bits | N | Y | Y | N | N | N | N | N | N | N | Y | **NO** |
| Final-word (checksum) calculator | N | Y | Y | N | N | N | N | N | N | N | Y | **NO** |
| Import seed by word entry, with autocomplete | Y | Y | Y | Y | Y | Y | Y | Y | Y | n/a | Y | 0.1 verify / m4b restore |
| SeedQR / CompactSeedQR scan-in | Y(Q) | Y | Y | Y | Y | N | N | Y | Y | N | C | HW (m11) |
| SeedQR display-out | N | Y | Y | N | N | N | N | N | N | N | Y | **D** (Q17: no secret in a QR) |
| BIP39 passphrase, entered on device | Y | Y | Y | Y | Y | Y | Y | Y | Y | N | Y | 0.1 + m4b warnings |
| Passphrase "not stored, you need both" warning, gated ack | P | N | P | N | N | P | Y | N | P | n/a | Y | m4b (3 placements, one-time ack) |
| Temporary / RAM-only seed session | Y | Y | Y | N | N | N | N | Y | N | n/a | Y | m6 |
| Multi-seed vault / multiple stored wallets | Y | P | P | N | N | N | N | N | N | N | W | m4b (8 slots) |
| Seed XOR split and recombine | Y | N | Y | N | N | N | N | N | N | N | Y | 0.3 |
| SLIP-39 Shamir backup | N | N | N | N | N | Y | N | N | P | N | Y | NO |
| BIP-85 child seeds | Y | N | N | N | N | N | N | N | N | N | Y | 0.3 |
| Double mnemonic (12+12 = valid 24) | N | N | Y | N | N | N | N | N | N | N | Y | NO |
| Lock Down Seed (destructive passphrase promotion) | Y | N | N | N | N | N | N | N | N | N | Y | 0.3 |

## 2. Access control, PIN, duress

| Capability | CC | SS | KX | PP | JD | TZ | BB | SP | KS | BK | P4 | notyas 0.2.0 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Device PIN / password gate | Y | N | N | Y | Y | Y | Y | Y | Y | N | W | m4a |
| First-class stateless mode (no stored secret at all) | P | Y | Y | N | N | N | N | Y | N | N | Y | 0.1 + m4b (State 1, default) |
| PIN removal returning the device to stateless | N | n/a | n/a | N | N | N | N | N | N | N | Y | **m4b (unique in field)** |
| PIN stretched into the storage key (KDF sealing) | P | n/a | Y | P | N | P | P | Y | ? | n/a | Y | m3 (Argon2id + eFuse HMAC bind) |
| Hardware-enforced attempt counter (secure element) | Y | n/a | N | Y | P(oracle) | Y | Y | Y | ? | Y | X | **X - no SE on P4** |
| Wipe after N failed attempts | Y | n/a | N | N(bricks) | Y(3) | Y(16) | Y(10) | Y(10) | ? | N | W | m4a (N=15 default) |
| User-settable wipe threshold | N | n/a | N | N | N | N | N | N | N | N | Y | **m4b (unique)** |
| Wipe policy authenticated inside the AEAD | n/a | n/a | N | n/a | n/a | n/a | n/a | P | n/a | n/a | Y | **m3 (unique, correct)** |
| Escalating delay between attempts | Y | n/a | P | ? | N | Y | N | N | ? | n/a | Y | m4a |
| Anti-phishing words after PIN prefix | Y | N | N | Y | N | Y | N | Y | N | N | W | m4a (HMAC-eFuse derived) |
| Scrambled / randomized keypad | Y | N | N | N | N | Y | Y | N | N | n/a | Y | **REJ 2026-08-19 - built at m4a, then declined (Q35 reversed); the pad is fixed phone order and notyas has no defence here** |
| Duress PIN opening a decoy wallet | Y | N | N | **D** | N | N | N | N | P(passphrase) | N | Y | m13, off by default |
| Decoy indistinguishable from empty (filler slots) | Y | n/a | N | n/a | n/a | n/a | n/a | n/a | N | n/a | Y | **m3 AlwaysFilled (best in field)** |
| Wipe / erase PIN (destructive duress) | Y | N | N | **D** | Y | Y | N | N | N | N | W | m13 (wipe variant only) |
| Brick-self PIN (permanent destruction) | Y | N | N | P | N | N | N | N | N | N | X | **REJ (correct)** |
| Delta mode (real seed, bad signatures) | Y | N | N | N | N | N | N | N | N | N | W | **REJ (correct)** |
| Look Blank / factory-fresh disguise | Y | N | N | N | N | N | N | N | N | N | Y | NO |
| Login countdown (5 min to 28 days) | Y | N | N | N | N | N | N | N | N | N | Y | P (escalating delay only) |
| Kill key / instant-wipe gesture | Y | N | N | N | N | N | N | N | N | N | Y | m13 |
| Calculator-login disguise | Y(Q) | N | N | N | N | N | N | N | N | N | Y | m4b "if kept" - **keep it** |
| Auto-lock / inactivity shutdown | Y | n/a | Y | ? | ? | Y | ? | ? | ? | n/a | Y | m4b (S-49) |
| MicroSD as a second factor at login | Y | N | N | N | N | N | N | Y | N | N | Y | 0.2.x (deferred) |
| Biometric unlock | N | N | N | N | N | N | N | N | Y | Y | X | REJ (no sensor, wrong model) |
| Plausible-deniability hidden wallet via passphrase | Y | Y | Y | Y | Y | Y | Y | Y | Y | N | Y | 0.1 (passphrase) |

## 3. Attestation and firmware integrity

| Capability | CC | SS | KX | PP | JD | TZ | BB | SP | KS | BK | P4 | notyas 0.2.0 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Boot-time signature check on firmware (secure boot) | Y | N | N | Y | Y | Y | Y | Y | Y | Y | Y | **0.3 (deferred, Q32)** |
| Signed-only firmware update enforced by the device | Y | N | Y | Y | Y | Y | Y | Y | Y | Y | Y | **0.3** |
| Anti-rollback / downgrade protection | Y | N | N | ? | ? | Y | ? | ? | ? | ? | Y | 0.3 |
| On-device update flow (SD or app), no toolchain needed | Y | N | Y | Y | Y | Y | Y | Y | Y | Y | Y | **NO (host reflash only)** |
| Factory attestation, vendor-signed key in silicon | Y | N | N | Y | Y | Y | Y | P(card) | Y | Y | X | **X - never claim it** |
| Hardware genuine/caution LED, pre-PIN, SE-driven | Y | N | N | N | N | N | N | N | N | N | X | X |
| On-device running-firmware hash readout | Y | N | Y | N | N | N | N | N | N | N | Y | 0.1 + m4b (S-46, richest in field) |
| Verify screen reachable before PIN entry | Y | n/a | Y | Y | N | N | N | N | Y | N | Y | 0.1 / m4b |
| Frozen field order + CI assertion against baked constants | N | N | N | N | N | N | N | N | N | N | Y | **m4b (unique)** |
| Boot counter / tamper-since-last-seen indicator | N | N | Y | N | N | N | N | N | N | N | Y | **m4a (ahead of field)** |
| Reproducible builds | N | Y | Y | N | N | Y | Y | Y | P | P | Y | m12 |
| Signed release hashes (GPG/PGP) | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | m12/m13 (key on disk, disclosed) |
| Third-party / independent build attestation | N | P | N | N | N | N | N | Y | N | N | Y | 0.3 (disclosed as absent) |
| Tamper-evident packaging or potting | Y | N | N | Y | ? | Y | Y | N | Y | ? | X | X (documented equivalent) |
| Disassembly-triggered wipe | N | N | N | N | N | N | N | N | Y | N | X | X |
| Boot self-test of the crypto core before peripherals | Y | N | Y | ? | ? | ? | ? | ? | ? | ? | Y | **0.1 (6 checks, ahead of field)** |
| Touch panel dead-zone self-test | n/a | n/a | Y | n/a | n/a | n/a | n/a | n/a | ? | n/a | Y | **NO** |

## 4. Transaction signing and transport

| Capability | CC | SS | KX | PP | JD | TZ | BB | SP | KS | BK | P4 | notyas 0.2.0 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| PSBT in via microSD | Y | N | Y | Y | N | N | Y | Y | Y | N | Y | m5/m6 |
| PSBT in via animated QR (UR2 / BBQr) | Y(Q) | Y | Y | Y | Y | N | N | Y | Y | N | C | **HW (m11)** |
| PSBT out as animated QR | Y(Q) | Y | Y | Y | Y | N | N | Y | Y | N | Y | m8 (UR2 + BBQr) |
| PSBT via NFC | Y(Q) | N | N | P | N | N | N | N | P | Y | X | X (QR/SD equivalent) |
| PSBT via USB host protocol | Y | N | N | N | Y | Y | Y | N | N | N | Y | **REJ (correct)** |
| PSBT via USB mass-storage drive | Y | N | N | N | N | N | N | N | N | N | Y | **REJ (correct)** |
| Full transaction review on the device's own display | Y | Y | Y | Y | Y | Y | Y | Y | Y | **N** | Y | m6 (S-30..S-36, 7 review screens) |
| Named wallet shown per input, unknown-wallet warning | N | N | N | N | N | N | N | Y | N | N | Y | m7 (registration-derived) |
| Change / self-transfer detection | Y | Y | Y | Y | Y | Y | Y | Y | Y | n/a | Y | m6/m7 (check 4, from registry) |
| Max-fee guard and sighash gating | Y | ? | ? | ? | ? | Y | Y | ? | ? | n/a | Y | m6 (10-check table) |
| Hold-to-sign confirmation | N | N | N | N | N | N | N | N | N | N | Y | m6 (S-36) |
| Batch signing / Sign All | Y | N | N | N | N | N | N | N | N | N | Y | **NO** |
| On-device finalization to a broadcastable txn | Y | N | ? | ? | ? | N | N | ? | ? | n/a | Y | m8 (final txn as QR) |
| Taproot single-sig (BIP-86) signing | Y | Y | Y | Y | Y | Y | Y | Y | Y | N | Y | m6 |
| Taproot multisig / MuSig2 | P(edge) | N | N | N | N | N | N | N | N | N | Y | 0.3 (field-wide gap) |
| Miniscript policy spending | P(edge) | N | Y | N | N | N | N | N | N | N | Y | P / 0.3 |
| PSBT v2 | ? | ? | ? | ? | ? | ? | ? | ? | ? | n/a | Y | parse-and-reject with a clear message |

## 5. Multisig, addresses, exports

| Capability | CC | SS | KX | PP | JD | TZ | BB | SP | KS | BK | P4 | notyas 0.2.0 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Multisig registration stored on device | Y | N | Y | Y | Y | N | Y | Y | Y | n/a | W | m7 (P2WSH sortedmulti) |
| BIP-48 cosigner xpub export | Y | Y | Y | Y | Y | Y | Y | Y | Y | n/a | Y | m7 |
| Descriptor import (BIP-380) and Coldcard .txt dialect | Y | Y | Y | Y | Y | N | Y | Y | Y | n/a | Y | m7 |
| BSMS (BIP-129) rounds | P | N | N | N | N | N | N | N | N | n/a | Y | 0.3 (first-address cross-check instead) |
| First-receive-address cross-check ceremony | Y | Y | Y | Y | Y | N | N | Y | Y | n/a | Y | m7 (mandatory) |
| Address explorer with per-address QR | Y | Y | Y | Y | Y | N | N | Y | Y | n/a | Y | m10 |
| Verify address ownership (is this address mine) | Y | Y | Y | Y | Y | N | N | N | Y | N | Y | m10 (typed or SD; camera makes it smooth) |
| Full address always shown, chunked, never truncated | N | P | P | P | P | P | P | P | Y | n/a | Y | **0.1 (commandment 1, ahead of field)** |
| Watch-only export in named coordinator formats | Y | Y | Y | Y | Y | P | Y | Y | Y | n/a | Y | m10 (Sparrow, Core, Electrum, Nunchuk) |
| Address-range CSV export | Y | N | N | N | N | N | N | N | N | n/a | Y | m10 (detached signature -> 0.3) |
| Message signing (BIP-137) | Y | Y | Y | Y | Y | Y | Y | Y | Y | N | Y | **0.3** |
| BIP-322 / proof of reserves | Y | N | N | N | N | N | N | N | N | N | Y | 0.3 |
| Per-key health check (re-derive without signing) | N | N | N | N | N | N | N | N | N | N | Y | NO (Nunchuk pattern, cheap) |
| Testnet / signet toggle | Y | Y | Y | Y | Y | Y | Y | Y | Y | N | Y | 0.1 |
| Spending policy engine (velocity, whitelist) | Y | N | N | N | N | N | N | N | N | P | X | 0.3.x (needs trusted clock) |

## 6. Backup, restore, lifecycle

| Capability | CC | SS | KX | PP | JD | TZ | BB | SP | KS | BK | P4 | notyas 0.2.0 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Encrypted backup of full device state | Y | n/a | Y | Y | N | N | Y | N | ? | N | Y | **NO (0.3)** |
| Backup of non-key state (registrations, labels, settings) | Y | n/a | P | Y | N | N | Y | N | ? | N | Y | **NO (0.3)** |
| Two-factor backup (file + separate code) | N | n/a | N | Y | N | N | N | N | N | N | Y | NO |
| Device clone / key teleport | Y | n/a | N | N | N | N | N | N | N | N | Y | NO (no equivalent, per R10) |
| Backup-verification quiz before use | Y | N | N | N | N | N | N | N | N | n/a | Y | **m4b (mandatory gate, ahead of field)** |
| Crypto-erase / wipe device, reusable afterwards | Y | n/a | Y | N(bricks) | Y | Y | Y | Y | Y | Y | Y | m4a/m4b (S-48) |
| Print or engrave a QR backup | N | N | Y | N | N | N | N | N | N | N | Y | NO (out of identity) |
| Metal-plate machine-vision restore | N | N | Y | N | N | N | N | N | N | N | C | NO |
| Social / delay-and-notify recovery | N | N | N | N | N | N | N | N | N | Y | X | X (needs a server) |

---

## 7. Table stakes in this field and absent from the notyas 0.2.0 plan

Four items. "Table stakes" here means: present on essentially every device a buyer would cross-shop, and the buyer will ask about it in the first five minutes.

1. **Boot-time firmware signature verification (Secure Boot v2) and signed-update enforcement.** Present on Coldcard, Passport, Jade, Trezor, BitBox02, Keystone, and even DIY Specter-DIY (locked bootloader after first flash). Deferred to 0.3.0 by Q32. This is the sharpest gap because it is load-bearing for everything else notyas claims: `VERIFY.md` itself says secure boot was the only row on S-46 that does not depend on the firmware being honest. SeedSigner is the only comparator without it, and SeedSigner's defence is that the Pi Zero has no writable bootrom and no stored secret - notyas has 32 MB of writable flash and, as of 0.2.0, a PIN-sealed secret in it. notyas is therefore behind the DIY tier here, not just the commercial tier.
2. **Encrypted backup and restore of device state.** Coldcard (7z AES), Passport (encrypted microSD plus a detached 20-digit code), BitBox02 (microSD), Krux (KEF). notyas 0.2.0 ships persistent storage with no backup at all, and the plan states the consequence plainly: multisig registrations, labels and settings have no recovery path for the life of the release. A wallet that can lose a 2-of-3 registration to a wipe, with no export, is not credible against Passport or Coldcard.
3. **On-device firmware update.** Every comparator, including Krux and Specter-DIY, lets a user update from SD or a companion app with the currently-trusted firmware or bootloader validating the incoming image. notyas 0.2.0's update path is "download a .bin, install esptool on a host, reflash over USB". It is a real product gap independent of secure boot, and it compounds gap 1.
4. **Message signing (BIP-137).** Present on all ten comparators except Bitkey. Deferred to 0.3.0. It is the standard way to prove address ownership to an exchange or a counterparty, and users will try it within the first session. Deferring it while shipping "Verify address ownership" is incoherent from the buyer's side: both answer "is this address mine", one for the user and one for a third party.

Two further items are field-standard but genuinely hardware-blocked and correctly handled as documented equivalents rather than gaps: **hardware-enforced PIN attempt limiting** (no secure element on P4) and **vendor factory attestation** (same reason). The plan's honest framing of both is right and should not be softened.

One is contingent rather than absent: **QR PSBT scan-in**. It is in 0.2.0 but gated on a camera module. If it slips, the release is SD-in / QR-out, which is Mk4-class transport paired with a Q-class screen, and address verification requires typing an address by hand. Treat the module purchase as release-critical, not as a nice-to-have.

---

## 8. Gap ranking: cost to add versus how much it matters

Ordered by (matters / cost). Cost is engineering effort plus irreversibility; "matters" is what a knowledgeable buyer notices.

### Tier 1 - fix before the release, or the release notes carry a hole

| # | Gap | Cost | Matters | Note |
|---|---|---|---|---|
| G1 | Secure Boot v2 burn plus signed-update enforcement | High (irreversible eFuse, key ceremony, flash geometry, update UX) | Very high | SECUREBOOT.md is already written. Minimum viable move for 0.2.0: ship the burn as a documented, opt-in, owner-performed hardening runbook with the key generated offline, so a buyer who wants it does not wait for 0.3.0. Resolve Q63 first; it currently blocks even the HMAC provisioning that all of m3/m4a depends on. |
| G2 | Seedless encrypted backup (registrations, labels, settings, wipe policy - no key material) | Low to medium | High | Does not touch invariant 2b, needs no new key hierarchy beyond m3's, and removes the worst sentence in the release notes. Q14 deferred backup *whole*; the seed-bearing profile is the expensive half and can stay in 0.3.0. Splitting the two is the highest-leverage single change available. |
| G3 | Camera module purchase and m11 hardware gates | Medium (money, lead time, esp_video bring-up) | High | Half the work is host-side and already proceeding. Without it, the two most-used flows in the field (scan a PSBT, scan an address to verify) are manual. |

### Tier 2 - cheap, visible, and directly on the "world class" claim

| # | Gap | Cost | Matters | Note |
|---|---|---|---|---|
| G4 | Message signing (BIP-137) | Low (rust-bitcoin) | Medium-high | Pull back from 0.3.0. The review UI is one screen, not a second signing surface the way BIP-322 is. Keep BIP-322 deferred. |
| G5 | Dice-screen integrity affordances: roll-distribution histogram, on-screen SHA256 of the filtered roll string | Low | Medium-high | This is the identity-defining screen and Krux currently out-features it. A histogram catches a loaded die; the hash lets a user re-derive offline without transcribing 99 rolls. Both are pure UI over data already in hand. |
| G6 | Touch panel dead-zone self-test | Low | Medium | The panel is the only input path. Coldcard Q shipped phantom-keypress defects; Krux ships a sweep. A mis-registered tap during dice entry silently changes the seed and nothing downstream will catch it. |
| G7 | BIP-85, specifically to derive the duress wallet | Low (pure math in notyas-core) | Medium | Coldcard's duress wallet is BIP-85-derived, so it is reproducible from the master seed. notyas's duress slot is an independent stored secret in a release with no backup, so enabling duress creates a second unrecoverable secret. Either derive it, or state that burden in the m13 duress UX. |
| G8 | Final-word checksum calculator, coin-flip entropy for the free bits | Low | Medium | SeedSigner and Krux both ship it; it is the standard way to finish a hand-picked mnemonic and costs one screen. |
| G9 | Calculator-login disguise (currently "if kept" at m4b) | Low on a touchscreen | Medium | Keep it. It is the only covert-duress affordance in the field that survives an inspector actually picking the device up, and a 720x720 touch panel makes it cheaper for notyas than it was for Coinkite. |
| G10 | Batch signing (Sign All) | Low once single signing exists | Low-medium | Class-a in PARITY.md, unassigned in the milestones. |
| G11 | Per-key health check (re-derive a known address, no signature) | Low | Low-medium | Nunchuk's pattern. A standing "prove this wallet is still intact" action on the wallet-detail screen, useful before an emergency rather than during one. |

### Tier 3 - real but expensive, or low value for this buyer; deferring is defensible

| # | Gap | Cost | Matters | Verdict |
|---|---|---|---|---|
| G12 | On-device SD update validated by the running firmware | Medium | Medium | Mostly meaningless before G1; schedule together. |
| G13 | Seed XOR | Medium (up to 297 rolls of re-entry UX) | Low-medium | Defer as planned; the audience overlap with dice users is real but the UX cost is not small. |
| G14 | BSMS (BIP-129) | Medium | Low-medium | Descriptor import plus the mandatory first-address cross-check genuinely covers the need. Nunchuk-centric buyers will ask; answer in docs. |
| G15 | Non-English wordlists and UI localization | Medium (font atlases) | Low for this buyer | Krux and Trezor ship it. Defer. |
| G16 | SLIP-39 Shamir | High | Low | Trezor-only, with documented cross-vendor interop failures and transcription-error scaling. Skip, not defer. |
| G17 | Login countdown (long, configurable) | Low | Low | Self-lockout risk and weak without a secure element. Escalating delay is the right subset. |
| G18 | MicroSD 2FA | Medium | Low | Adds a bricking failure mode. Keep deferred. |
| G19 | Thermal / CNC backup printing, metal-plate scanning | Medium-high | Low | Out of identity. |

---

## 9. What the field does that notyas should deliberately NOT do

Each of these is already rejected in the plan or should be, and the reason should survive into the public docs so a reviewer does not read the absence as an oversight.

1. **Firmware-only "brick self" PIN (Coldcard).** A brick without hardware backing is reversible by anyone with a flasher. Implementing it would ship a lie in the one place where a lie is fatal. Already rejected at MILESTONES 7.3. Correct.
2. **Delta Mode (Coldcard).** It is meaningful only because two secure elements gate the seed release. A software reimplementation is theater. Already rejected. Correct.
3. **Any USB data path** - host protocol, virtual-disk MSC, HID password typing, HSM/CKBunker. All four reopen exactly the port the airgap posture closes, and the whole value proposition rests on that port being dead. Already rejected permanently. Correct.
4. **SeedQR display-out (SeedSigner, Krux).** Rendering a mnemonic as a QR puts a secret into a form that a camera across the room can capture instantly and that a phone will silently copy. Declined by Q17 rather than deferred. Correct, and worth stating as a deliberate divergence rather than a missing feature, because two respected projects do ship it.
5. **Camera or photo entropy for key material (SeedSigner, Krux).** It adds an unauditable, unreproducible source into a derivation path whose entire selling point is that it is reproducible from the user's own dice log. It would also require notyas to make an entropy-quality claim about a sensor it cannot characterize. Refuse permanently, not just for 0.2.0.
6. **TRNG-mixed seeds.** Same argument, plus the P4's specific TRNG defect. Note the field precedent that supports the stance: Coldcard shipped a limited-entropy seed-generation hotfix in July 2026.
7. **Blind-oracle unlock (Jade).** It buys secure-element-class attempt limiting without a secure element, which is exactly the hole notyas has - and it buys it with a network dependency that makes an airgapped device unusable when the oracle is unreachable. Refusing it is the right trade for a device with no radio.
8. **Biometric unlock (Keystone, Bitkey).** No sensor, and it substitutes something the user cannot change and leaves on every surface they touch for something they can.
9. **A vendor "Genuine Check" challenge-response (Passport, Jade, Keystone).** This is the most tempting thing on the list and the most dangerous. notyas will have an eFuse HMAC key, so a challenge-response ceremony is technically buildable - but the key is provisioned by whoever flashes the device, not by a factory, and it lives in a chip with no tamper resistance. Such a check would prove only "this device knows a key someone provisioned", which an attacker who flashes their own firmware and burns their own key reproduces exactly. Building the UI would import the credibility of a claim notyas cannot make. Reproducible builds plus a firmware hash the user compares against their own build is the honest substitute, and it should be described in those words.
10. **Overstating the anti-phishing words.** Because the HMAC key sits in eFuse and is not software-readable, the words genuinely detect a swapped *board* - stronger than PARITY.md's cautious "a flash-cloning attacker can replay the words" note. But any firmware running on that same board can compute them, so they do **not** detect firmware replacement. Without secure boot in 0.2.0, firmware replacement is precisely the attack in play. State that boundary in the copy: the words catch a different device, not different software on the same device.
11. **Krux's TC-Flash-Hash pattern in its current form.** Its own docs concede a bypass (copy flash to SD, run altered firmware that hashes the SD copy) mitigated only by procedural advice. notyas's S-46 already avoids this by hashing the running app partition; do not add a removable-media-assisted variant that reintroduces it.
12. **Paper wallets, WIF store, secure notes and password manager.** Already rejected. A signing device that also types passwords over USB has, by construction, a USB typing path.
13. **Passport's no-duress-at-all stance.** Foundation's argument (an attacker who expects duress features reacts badly when none is configured) is coherent but it is a product decision, not a security result. notyas's answer is better: the deniability cost (AlwaysFilled filler slots, present/blank readouts) is paid by every user unconditionally, so the presence of the feature leaks nothing about whether a given owner uses it. Keep that and keep it unconditional - the entire property dies the moment filler becomes a duress-users-only option.
14. **Electrum's "Advanced" toggle over transaction details.** Do not gate any part of the review behind a disclosure control. Sparrow's maximal-by-default exposure is the right model, and m6's seven review screens already follow it.
15. **Nunchuk's simplification ceiling.** Do not hide the derivation path or script type next to an xpub or address in exchange for a cleaner screen. Keep fingerprint plus derivation plus script type together as one verification unit, as m10 plans.

---

## 10. Where notyas already leads the field (for the m13 claims audit)

These are the rows a competitive review should lead with, because no comparator has them and each is defensible as a mechanism rather than a claim.

- **Three explicit device states with a real path back to stateless.** SeedSigner is stateless-only, everyone else is stored-only. notyas is the only device where an owner can save wallets under a PIN and later revert to a device that stores nothing - and PIN-MODES.md's insistence that this be worded as a data-loss event and not a security downgrade is correct and rare.
- **Wipe policy authenticated inside the AEAD.** Nobody else documents it. Without it the attempt counter is decoration, as Specter-DIY's HMAC'd PIN-state file half-recognizes.
- **User-settable wipe threshold with the arithmetic computed from the actual PIN length at the moment of the change.** The field either hardcodes N or omits it. Showing a 4-digit user their real keyspace and offering the longer-PIN path as an action is better than any warning copy surveyed.
- **AlwaysFilled occupancy paid by every user.** Coldcard's duress wallet is the only comparable design, and Coldcard does not make the indistinguishability property unconditional.
- **S-46's design contract**: raw values in full, no verdict or advice beside a value, frozen field order across builds so two units can be diffed rather than read, every value read from the running system with a CI assertion that a compiled-in constant fails. This is a better instrument than anything in the field, and it stays honest only if the self-reporting sentence ships verbatim.
- **Boot self-test of the crypto core before any peripheral initializes**, refusing to present a normal UI on failure, rendered without the crate under test.
- **Mandatory backup-verification quiz before a wallet can be saved.** Coldcard quizzes the backup password; nobody gates the save on proving the seed was recorded.
- **Full address always shown chunked to the end, with the truncated list carrying its own "never check an address from this list" statement.** Coldcard Mk4's scrolling OLED is the documented counterexample.
- **Dual dice modes with the incompatibility labeled in the UI** (RAW is iancoleman-compatible, FIXED is Coldcard/SeedSigner-compatible). Krux claims cross-tool compatibility in prose; notyas states it on the screen where it matters.
- **Boot counter plus an owner-set acknowledgement mark**, post-PIN only so a coercer cannot erase the gap it exists to show.

The single sentence that decides whether the "world class" claim survives contact with a knowledgeable buyer: everything in this section is produced by firmware that, in 0.2.0, nothing on the device verifies. G1 is not one gap among eleven; it is the gap that determines how much the other ten are worth.