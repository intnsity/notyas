# PARITY.md - Coldcard feature parity matrix for notyas 0.2.0

Status: reference document, wave-2 planning input, **row-by-row dispositioned by the m13
claims audit on 2026-08-18**. Companion documents in this directory: ARCHITECTURE.md,
SECURITY.md, UX.md, MILESTONES.md, OPEN-QUESTIONS.md (written by a parallel planning
workflow; where they exist they govern the storage, security and UX designs this matrix
assumes). MILESTONES.md section 7 wins on scope and this file records what it decided;
`docs/claims-audit-0.2.0.md` records the evidence.

## The 0.2.0 column

MILESTONES section 9 requires every row here to be implemented, equivalent-and-documented,
or deferred with a stated reason. The `0.2.0` column is that verdict, one token per row,
and no row is allowed to be blank. **The parity bar itself is a PROJECT bar and a 0.3.0
release bar, not the 0.2.0 release bar** (R28): the owner's 2026-08-18 scope instruction
sends anything not needed for a working storage, signing and multisig wallet to 0.3.0, so
a `DEFER` token is the rule working, not the rule failing.

| Token | Meaning |
|---|---|
| `LANDED <ver/milestone>` | In the tree and covered by a green host gate. |
| `BUILDING <m#>` | In 0.2.0 scope, milestone in flight at the audit date. |
| `QUEUED <m#>` | In 0.2.0 scope, no code yet at the audit date. |
| `PARTIAL <m#>` | Part ships in 0.2.0; the named remainder is deferred. The Notes say which is which. |
| `EQUIV` | Hardware-impossible as-is; the documented equivalent named in the Notes is what ships. |
| `DEFER <ver>` | Deferred beyond 0.2.0 with the reason in MILESTONES 7.4. |
| `REJECT` | Rejected, permanently or for 0.2.0, with the reason in MILESTONES 7.3. |

Two cautions on reading it. A `DEFER` row can still have math in `notyas-core` - the token
is about the FEATURE reaching a user, which needs a screen and a flow, not about whether a
module exists. And `BUILDING` and `QUEUED` are statements about a date: they are re-checked
at the m13 gate, and a row still `QUEUED` when the release is cut becomes `DEFER` there
rather than shipping as an implied promise.

## Parity definition

notyas targets functional parity with the Coldcard Mk4 and Coldcard Q per this
matrix. "Parity" means: for every Coldcard feature, notyas either implements it,
implements a design-adapted version of it, or ships a documented equivalent that
achieves the same user outcome on notyas hardware. Class-c items (hardware-
impossible as-is) ship as documented equivalents, plainly labeled; notyas never
claims hardware guarantees its silicon does not provide.

Classification codes used throughout:

- **a** - directly portable. Same feature, same behavior, no hardware obstacle.
- **b** - portable with design changes (the change is stated in the notes).
- **c** - hardware-impossible as-is (reason given; nearest honest equivalent named).
- **d** - judgment call: portable but of questionable value or in tension with the
  notyas design identity (reason given; decision deferred to OPEN-QUESTIONS.md /
  MILESTONES.md reconciliation).

Hardware baseline for classification: ESP32-P4, no secure element, no NFC chip,
no camera fitted (the board exposes a Pi-compatible CSI camera path - see
CAMERA.md in this directory), no battery, native USB 2.0 OTG, one microSD slot,
720x720 touch LCD, radio absent/held in reset. 0.1.0 is stateless; rows marked
"needs storage layer" assume the 0.2.0 persistent-storage design (see
ARCHITECTURE.md / SECURITY.md in this directory when present).

Coldcard is a product of Coinkite Inc. All feature descriptions below are drawn
from Coinkite's public documentation and firmware repository, cited per row.
Coldcard's security model is well engineered for its hardware; this document
records only what does and does not transfer to different silicon.

## 1. Seed generation and seed management

| Feature | What it does | Source | Class | 0.2.0 | Notes |
|---|---|---|---|---|---|
| TRNG seed generation (12/24 words) | New seed from onboard true RNGs; Mk4 mixes RNG sources across MCU and both secure elements | https://coldcard.com/docs/temporary-seeds/ ; https://blog.coinkite.com/understanding-mk4-security-model/ | c | **EQUIV** | P4 has a single TRNG with a known entropy-quality issue (esp-hal issue 5982) and no secure-element sources to mix. notyas policy is dice-only for key material. Honest equivalent: dice entropy (already core). Coldcard's 2026-07-31 hotfix 5.6.0/1.5.0Q addressed a limited-entropy seed-generation bug (https://github.com/Coldcard/firmware/blob/master/releases/ChangeLog.md), which supports dice-first as a defensible design stance for any vendor. |
| Dice-roll seed with verification math | SHA256 over ASCII roll string; >=50 rolls for 128-bit, 99 for 256-bit; warning on too few; rolls.py/rolls12.py for independent verification | https://coldcard.com/docs/verifying-dice-roll-math/ | a | **LANDED 0.1.0** | Already implemented: BigDice FIXED mode is algorithm-identical; RAW mode adds iancoleman compatibility. Ship equivalent verification scripts and published vectors. |
| Import seed by word entry (12/18/24) | Restore any BIP-39 seed; word-list prefix entry | https://coldcard.com/docs/temporary-seeds/ | a | **LANDED 0.1.0** | Touch keyboard matches or exceeds keypad/QWERTY entry. Already the 0.1.0 restore flow. |
| Scan seed via QR (SeedQR, words, xprv) | Q scans SeedQR, truncated words, xprv via camera | https://coldcard.com/docs/qr-scanner/ | c base / b with camera | **QUEUED m11** | No camera fitted on the base unit. The board's CSI path makes this class b on a camera-equipped variant (see CAMERA.md). Equivalent today: manual entry. |
| Temporary seeds (RAM-only) | Work from a different seed without touching master; discarded at reboot | https://coldcard.com/docs/temporary-seeds/ | a | **LANDED 0.1.0** | Fits the notyas stateless model exactly; 0.1.0 is effectively temporary-seed-only. |
| Seed Vault | AES-256-CTR store of multiple seeds, encrypted with a key derived from the master seed; labels, quick switch | https://coldcard.com/docs/temporary-seeds/ | b | **BUILDING m4b** | Corrected by R9 and R17: notyas has no single master seed on a multi-wallet device, so the notyas Seed Vault is a multi-slot registry sealed under the device PIN ladder, NOT under a master-seed key. At-rest protection is the PIN ladder alone - there is no flash encryption in 0.2.0 - and the slot count is never shown pre-PIN (Q2(a)). |
| BIP-85 derived seeds | Child entropy: 12/18/24 words, WIF, xprv, hex, passwords; index 0-9999+; use in-device as temporary seed | https://coldcard.com/docs/bip85/ | a | **DEFER 0.3.0** | Pure math on the master seed; add to notyas-core with BIP-85 test vectors. |
| BIP-85 passwords + USB keyboard emulation | Derive deterministic passwords; type them into a host as a USB HID keyboard | https://coldcard.com/docs/bip85-passwords/ ; https://coldcard.com/docs/settings/ | d | **REJECT** | Password derivation itself is class a (display + QR). Keystroke emulation over USB HID is feasible on P4 but conflicts with the notyas no-USB-data identity; judgment call. |
| Seed XOR split/recombine | Split seed into 2-4 XOR parts, each a valid-checksum mnemonic; recombine on any device | https://coldcard.com/docs/seedxor/ ; https://seedxor.com | a | **DEFER 0.3.0** | Simple XOR math; strong fit for a dice-first device. |
| BIP-39 passphrase | On-device entry; applied as temporary seed; optional save to microSD encrypted AES-256-CTR keyed by seed + card serial hash; never stored internally | https://coldcard.com/docs/passphrase/ | a | **LANDED 0.1.0** | 0.1.0 already has passphrase. Card-serial-bound saved passphrases port cleanly (SDMMC exposes the CID serial). |
| Lock Down Seed | Destructively replace master seed with the passphrase-derived secret | https://coldcard.com/docs/passphrase/ | b | **DEFER 0.3.0** | Meaningful only once notyas stores a master seed (0.2.0 storage layer); then trivial. |
| Destroy Seed / View Seed Words | Danger Zone seed functions | https://coldcard.com/docs/advanced/ | a | **BUILDING m4b** | View/verify already present; destroy needs the storage layer to be meaningful. |
| Key Teleport | Encrypted seed/PSBT/backup transfer between two devices: ECDH ephemeral keys + dual AES-256-CTR via BBQr or NFC-assisted relay | https://coldcard.com/docs/key-teleport/ | c base | **DEFER 0.3.0** | Receiving requires scanning BBQr (camera). Send-only (display BBQr) is half a protocol. **R10: the "encrypted backup file on microSD" equivalent this row used to name does NOT exist and must not be claimed** - SECURITY invariant 2b forbids key material on SD and Q14 defers encrypted backup whole. The honest statement for 0.2.0 is "not available; move the mnemonic yourself". Class b on a camera variant. |

## 2. PINs, login, and duress

Coldcard's PIN system is anchored in the bootrom plus two secure elements from
different vendors, with attempt counting and brick enforced in hardware
(https://blog.coinkite.com/understanding-mk4-security-model/ ;
https://coldcard.com/docs/physical-notes/). notyas has no secure element, so
every row below carries the same framing: PIN logic is firmware, and a physical
attacker who can read and rewrite flash can roll a counter back.

**This preamble was superseded on two points by the wave-1 design and both corrections
matter (R8, R17).** First, "offline-hard but not attempt-limited" understates it: the key
ladder passes through the eFuse-keyed HMAC peripheral, so each guess needs THIS physical
board, and wipe-on-N destroys the sealed records - the honest claim is "N guesses per
full-flash restore cycle", never a bare "attempt limited" and never "not attempt limited".
Second, **there is no flash encryption in 0.2.0** (Q63): no XTS key is burned, the
`encrypted` partition flag is inert, and every sentence in this section that leans on flash
encryption for at-rest protection is wrong - the PIN ladder is the whole of it. The
governing text is docs/SECURITY.md, with the tier analysis in this directory's SECURITY.md.
notyas's stateless mode remains a first-class option, where there is no stored secret to
attack at all.

| Feature | What it does | Source | Class | 0.2.0 | Notes |
|---|---|---|---|---|---|
| Two-part main PIN (prefix + suffix) | 2-6 + 2-6 digits | https://coldcard.com/docs/pins/ | b | **BUILDING m4a** | Port the UX; enforce via KDF into the storage key, not a hardware counter. |
| Anti-phishing words | Device-unique words shown after prefix; detects a swapped device | https://coldcard.com/docs/pins/ | b | **BUILDING m4a** | Corrected by the m13 audit: the words are derived from the read-protected eFuse HMAC key, not from a secret in encrypted flash, which makes them STRONGER than this row assumed against a swapped board - a clone of the flash on other hardware cannot compute them. The real boundary is the other one (COMPETITIVE.md 9.10): any firmware on THIS board can compute them, so they do not detect firmware replacement, which without Secure Boot is the attack in play. Unprovisioned devices have no words at all (R20). |
| 13-failed-attempts brick | Unconditional hardware brick | https://coldcard.com/docs/pins/ | c | **EQUIV** | No hardware counter on P4. Equivalent: a device-bound Argon2id ladder plus wipe-on-N (default 15, range 3..=25, user-disableable). The honest claim is N guesses per full-flash restore cycle: the counters partition is plaintext by necessity, so a consistent snapshot and restore rolls it back with no key. Ledger-only rollback IS refused at mount. |
| Trick PINs (13 slots: Brick Self, Wipe Seed variants, Duress Wallet, Login Countdown, Look Blank, Just Reboot, Delta Mode, Policy Unlock) | Decoy PINs triggering alternate behavior | https://coldcard.com/docs/pins/ ; https://coldcard.com/docs/advanced/ | b/d | **BUILDING m13** | Duress wallet (BIP-85 child seed on a decoy PIN) is pure firmware and genuinely useful: class b, needs storage. Brick/wipe variants without a hardware counter are firmware-enforced only - implement only with honest documentation (d). Delta Mode is deeply secure-element-integrated upstream and of questionable value re-implemented in software (d). |
| Wrong PIN actions (wipe/brick/last chance) | Configurable consequences below 13 attempts | https://coldcard.com/docs/pins/ | c | **EQUIV** | Same as brick row; firmware-only wipe is best-effort. |
| Login Countdown | Forced delay 5 min to 28 days before login | https://coldcard.com/docs/settings/ | b | **PARTIAL m4a** | Firmware timer; without a secure element it deters only an attacker using the UI. Low cost; labeled honestly. |
| Kill Key | Designated key during login instantly wipes seed | https://coldcard.com/docs/settings/ | b | **QUEUED m13** | Portable as a touch gesture. The wipe is real if implemented as storage-key zeroization (the flash-encrypted blob becomes unrecoverable) - genuinely effective without a secure element. |
| Scramble Keypad | Randomized digit layout against shoulder-surfing | https://coldcard.com/docs/settings/ | a | **BUILDING m4a** | Trivial on a touchscreen. |
| Calculator Login (Q) | Login screen disguised as a working calculator | https://coldcard.com/docs/settings/ | a | **DEFER 0.3.0** | Pure UI; low cost. |
| MicroSD 2FA | Enrolled card (AES file keyed by master secret + card serial) required at login, else fast seed wipe | https://coldcard.com/docs/microsd-2fa/ | b | **DEFER 0.3.0** | Ports directly once a stored seed exists; firmware-enforced, labeled as such. |
| Device nickname / home XFP / idle timeout / menu wrapping | Login and UI conveniences | https://coldcard.com/docs/settings/ | a | **PARTIAL m4b** | Trivial. |
| Secure Logout | Clean logout wiping RAM state | https://coldcard.com/docs/settings/ | a | **LANDED 0.1.0** | notyas already zeroizes on screen exit. |

## 3. Transaction signing (PSBT)

| Feature | What it does | Source | Class | 0.2.0 | Notes |
|---|---|---|---|---|---|
| PSBT signing via microSD | Read PSBT from card, verify, display outputs/fees, sign, write -signed file; FAT12/32 up to 32GB | https://coldcard.com/docs/ready-to-sign/ ; https://coldcard.com/docs/microsd/ | a | **PARTIAL m6/m5** | The planned 0.2.x core. Coldcard file conventions already adopted in the repo's ARCHITECTURE.md. |
| Batch signing ([Sign All]) | One approval pass over all PSBTs on the card | https://coldcard.com/docs/advanced/ | a | **DEFER 0.3.0** | Straightforward once single signing exists. |
| PSBT via USB (encrypted host protocol) | Host tools (Electrum, Sparrow) send PSBT over an encrypted USB protocol | https://coldcard.com/docs/cli/ | d | **REJECT** | Technically possible on P4 native USB; conflicts with the notyas no-USB-data identity. QR and SD cover the use case; deliberate decision required. |
| PSBT via virtual disk (USB MSC, optional auto-sign) | Device appears as a 4MB USB drive; drag-and-drop PSBT | https://coldcard.com/docs/settings/ ; https://coldcard.com/mk4 | d | **REJECT** | Same USB judgment call: feasible (TinyUSB MSC), but reopens the USB attack surface the airgap posture closes. |
| PSBT via QR/BBQr | Scan unsigned PSBT (BBQr up to 2MiB); display signed PSBT as animated BBQr | https://coldcard.com/docs/qr-scanner/ | b display / c scan on base | **PARTIAL m8/m11** | Displaying signed-PSBT BBQr/UR out is pure rendering - planned 0.2.x. Scanning in requires the camera option (CAMERA.md). Without it, SD in / QR out is the documented asymmetric flow. |
| PSBT via NFC | Send/receive PSBT by tap | https://coldcard.com/docs/nfc-tools/ | c | **EQUIV** | No NFC hardware. Equivalent: QR display plus SD. |
| Output/input explorer | Inspect outputs (QR per output) and input UTXO details before signing | https://github.com/Coldcard/firmware/blob/master/releases/History-Mk.md | a | **PARTIAL m6** | Pure UI over the PSBT parser; include from day one. |
| On-device finalization | Emit a fully final network transaction when the last signature is added | https://coldcard.com/docs/multisig/ | a | **BUILDING m6** | Needed for any broadcast-helper flow. |
| Max fee guard, v3 txns, sighash checks | Fee ceiling; non-standard SIGHASH gate | https://coldcard.com/docs/settings/ ; https://coldcard.com/docs/advanced/ | a | **PARTIAL m6** | Port the guardrails with the signer. |
| NFC PushTX | Tap phone to broadcast signed txn via a configurable URL | https://coldcard.com/docs/settings/ ; https://coldcard.com/docs/nfc-tools/ | c | **EQUIV** | No NFC and no radio, by design. Equivalent: display the signed transaction as QR/BBQr for a phone to scan and broadcast - same outcome, zero device connectivity. |
| Taproot send-to-P2TR | Verify/display P2TR outputs | https://coldcard.com/docs/version-history/ | a | **LANDED m6** | rust-bitcoin handles bech32m natively. |
| Taproot keyspend, tapscript, MuSig2 | Full taproot signing (upstream: experimental/EDGE branch) | https://github.com/Coldcard/firmware/blob/edge/docs/taproot.md ; https://blog.coinkite.com/edge-635/ | b | **PARTIAL m6** | Not in upstream mainline as of 2026-08, so the parity target is moving. rust-bitcoin + secp256k1 provide schnorr/taproot directly; an area where notyas can reach parity or better. Design change: taproot descriptors in the wallet-registration model. |
| Miniscript / MiniTapscript (BIP-380 descriptors, BIP-388 policies) | Spend arbitrary miniscript policies (upstream: EDGE branch) | https://github.com/Coldcard/firmware/blob/edge/docs/miniscript.md | b | **DEFER 0.3.0** | rust-miniscript is mature; notyas could match or exceed upstream mainline. Significant descriptor-wallet design work. |

## 4. Multisig

| Feature | What it does | Source | Class | 0.2.0 | Notes |
|---|---|---|---|---|---|
| Multisig registration (file/descriptor import) | Up to 15 co-signers; P2SH, P2WSH, P2SH-P2WSH; import via SD, virtual disk, QR, NFC, or PSBT-carried | https://coldcard.com/docs/multisig/ | b | **PARTIAL m7** | Needs the 0.2.0 storage layer for registrations; SD plus QR-display transports available. Import formats (Coldcard text file and BIP-380 descriptor) port as-is. |
| Trust policy knobs, Skip Checks, Unsorted multisig, Full Address View | XPUB-handling policy options | https://coldcard.com/docs/multisig/ ; https://coldcard.com/docs/settings/ | a | **DEFER 0.3.0** | Policy logic only. |
| Export XPUB / Create Airgapped | Emit co-signer xpub files; build a wallet from collected xpubs offline | https://coldcard.com/docs/multisig/ ; https://coldcard.com/docs/airgap-multisig/ | a | **BUILDING m10** | Already the planned 0.2.x multisig xpub export. |
| Descriptor export (pretty/raw, Core importdescriptors) | BIP-380 descriptor out | https://coldcard.com/docs/descriptor_export/ | a | **BUILDING m10** | rust-miniscript descriptor serialization. |
| BSMS (BIP-129) coordinator + signer | Secure multisig setup rounds over SD/QR (upstream: EDGE preview) | https://coldcard.com/docs/bsms/ | b | **DEFER 0.3.0** | File-based rounds over SD port cleanly. EDGE-only upstream, so implementing it is parity-plus. A Rust BSMS crate is a proposed platform contribution - see PLATFORM.md. |
| CCC - Coldcard Co-Signing | Device holds a spending-policy key and auto-co-signs 2-of-N only within policy (magnitude, velocity, whitelist, TOTP 2FA via NFC) | https://coldcard.com/docs/coldcard-cosigning/ | b/d | **DEFER 0.3.x** | Policy engine and policy key are firmware plus math (b, needs storage). The NFC TOTP leg is class c; equivalents are a QR the phone scans or on-device TOTP with user-entered code. Without a secure element the policy key's extraction resistance is weaker; stated plainly. |

## 5. Addresses, messages, identity

| Feature | What it does | Source | Class | 0.2.0 | Notes |
|---|---|---|---|---|---|
| Address Explorer | Browse receive/change addresses; custom accounts and paths; CSV export of 250 addresses + detached signature; per-address QR; NFC share | https://coldcard.com/docs/address-explorer/ | a | **BUILDING m10** | 0.1.0 already shows addresses + QR; add change toggle, CSV export, signed export. NFC share drops (c). |
| Verify Address Ownership | Given an address, search first 1,528 addresses across singlesig, multisig, accounts; report path or Unknown | https://coldcard.com/docs/verify-address-ownership/ | b | **BUILDING m10** | Search logic is pure math; input needs typing on base hardware (camera variant makes it smooth). High-value anti-phishing feature; build it. |
| Message signing (BIP-137, RFC2440 armor) | Sign short ASCII messages from SD file or on-device entry; on-device signature-file verify | https://coldcard.com/docs/message-signing/ | a | **DEFER 0.3.0** | SD path plus on-screen entry; rust-bitcoin covers message signing. |
| BIP-322 signing / proof-of-reserves | Generic signed-message standard; PoR PSBTs | https://coldcard.com/docs/bip322/ | a | **DEFER 0.3.0** | Spec work only; good parity item. |
| View Identity | Master fingerprint, serial, extended master key | https://coldcard.com/docs/advanced/ | a | **PARTIAL m10** | notyas Verify screen already covers device identity; add XFP display. |
| Export watch-only wallet | Named exports: Sparrow, Bitcoin Core, Electrum, Nunchuk, and many others; generic JSON; XPUB paths; signed exports | https://coldcard.com/docs/menu-tree/ | a | **BUILDING m10** | File writers plus QR; high leverage for works-with-your-software credibility. |
| Paper wallets | Unrelated random key to address + WIF, templated print, TRNG or dice entropy | https://coldcard.com/docs/paper-wallets/ | d | **REJECT** | Portable (dice-entropy variant), but paper wallets are broadly discouraged, including in Coldcard's own documentation. If kept: dice-only. |
| WIF Store | Import loose WIF keys, sign PSBTs with them | https://github.com/Coldcard/firmware/blob/master/releases/History-Mk.md | d | **REJECT** | Niche; needs storage; encourages loose-key handling. Defer. |
| Secure Notes and Passwords | AES-256-CTR notes and password entries keyed by master seed; generators; JSON export; USB keystroke typing | https://coldcard.com/docs/secure_notes/ | b/d | **REJECT** | Crypto and storage port (b, needs storage layer). Whether a signing device should also be a password manager is a scope question (d); the keystroke-typing leg is the USB judgment call. |

## 6. Backup, restore, device lifecycle

| Feature | What it does | Source | Class | 0.2.0 | Notes |
|---|---|---|---|---|---|
| Encrypted backups | Standard 7z AES-256-CBC; key = SHA256 of 12 BIP-39 words; password quiz; includes seed/settings/multisig/notes; restore as master or temporary seed | https://coldcard.com/docs/backups/ | a | **DEFER 0.3.0** | Deferred whole by Q14, both the seedless and the seed-bearing profile. **The consequence is the largest single gap in 0.2.0 and every wipe surface must state it: multisig registrations, labels and settings have no recovery path for the life of the release** (R21). The design when it returns is unchanged: standard formats verifiable with any 7z tool, with the quiz as UI. |
| Clone device | SD round-trip: target writes a pubkey, source encrypts full state to it, target decrypts | https://coldcard.com/docs/clone-coldcard/ | a | **DEFER 0.3.0** | Clean ECDH-over-SD design, no radio needed - but it writes encrypted key material to SD, which invariant 2b forbids, so it travels with the backup deferral (R10, Q14). Not claimed for 0.2.0 in any form. |
| Firmware upgrade, factory-signed only | Only vendor-key-signed firmware loads; SHA-256 + GPG user verification | https://coldcard.com/docs/upgrade/ | b | **DEFER 0.3.0** | **Needs the Secure Boot v2 burn that Q32 deferred, so nothing enforces signed-only firmware in 0.2.0.** The release's answer is the user-buildable reproducible chain, described as what it is: a check the OWNER performs, not one the device enforces. When it returns in 0.3.0 it is RSA-3072 only (the ECDSA ROM path is excluded per AR2026-006). GPL3 difference, unchanged: users can build and sign their own firmware. |
| Bless Firmware / genuine-state LEDs | Secure-element-controlled LEDs attest flash contents | https://coldcard.com/docs/upgrade/ ; https://coldcard.com/docs/physical-notes/ | c | **EQUIV** | No secure element to drive an unspoofable LED. Equivalent: the notyas Verify screen (eFuse state, running-app SHA256, boot self-test) - software attestation, labeled as such. **Weaker in 0.2.0 than "equivalent" suggests, and the m13 audit requires it stated here:** with Secure Boot not burned, the screen is produced by the firmware under suspicion, where Coldcard's LED is driven by a separate security chip. The reproducible-build comparison the owner performs is the part that carries weight. |
| Downgrade protection | Bootloader refuses older firmware | https://coldcard.com/docs/upgrade/ ; https://coldcard.com/docs/advanced/ | b | **DEFER 0.3.0** | ESP32 Secure Boot v2 supports eFuse anti-rollback counters, and none is burned in 0.2.0: anti-rollback protects a signature chain that does not exist without secure boot, so it travels with Q32 to 0.3.0. No downgrade protection of any kind ships. |
| Nuke Device | Wipe seed and destroy the secure element | https://coldcard.com/docs/advanced/ | c | **EQUIV** | No secure element to destroy. Equivalent: erase of the PIN-sealed records plus a one-way wipe-epoch bump - real, and the device remains reusable, which is arguably a feature. Not "crypto-erase of flash-encryption-keyed storage": no flash-encryption key exists in 0.2.0 to erase. |
| Selftest, settings-space and cache maintenance, dev menu | Maintenance and developer functions | https://coldcard.com/docs/advanced/ | a/b | **PARTIAL m13** | Selftest exists (boot BIP vectors). Secure-element key-slot functions are c (not applicable). The rest is trivial. |
| Testnet4 / regtest toggle | Network switch | https://coldcard.com/docs/advanced/ | a | **PARTIAL m4b** | Essential for development and integrations. |

## 7. Q-specific hardware and remaining hardware surface

| Feature | What it does | Source | Class | 0.2.0 | Notes |
|---|---|---|---|---|---|
| QWERTY keyboard (Q) | Fast passphrase/word entry | https://coldcard.com/docs/coldcard-q/ | a equivalent | **EQUIV** | 720x720 capacitive touch keyboard meets or exceeds physical-key entry for this use. |
| 320x240 2.3" LCD (Q) | Larger display than Mk4 | https://coldcard.com/docs/coldcard-q/ | a exceeded | **EQUIV** | notyas panel is 720x720 4"; higher BBQr density per frame. |
| QR scanner module + flashlight (Q) | Camera-based scanning | https://coldcard.com/docs/coldcard-q/ | c base / b variant | **QUEUED m11** | The single biggest hardware gap versus the Q. P4 has MIPI-CSI plus hardware JPEG; a camera-fitted variant is the honest path to full Q-class parity (CAMERA.md). Without it, notyas is an SD-plus-QR-display device: Mk4-class transport with a Q-class screen. |
| Dual microSD slots (Q) | Separate unsigned/signed cards | https://coldcard.com/docs/coldcard-q/ | c | **EQUIV** | One slot. Workflow equivalent: distinct -signed filenames (already the upstream convention). |
| AAA battery power (Q) | Fully unplugged operation | https://coldcard.com/docs/coldcard-q/ | c | **EQUIV** | No battery or PMIC on board. Equivalent: USB power bank (power only, no data - the cleanest notyas posture). |
| NFC + NFC kill-trace | Tap transfers; PCB trace cut to disable permanently | https://coldcard.com/docs/coldcard-q/ ; https://coldcard.com/docs/nfc-tools/ | c | **EQUIV** | No NFC chip. notyas embodies a stronger form of the kill-trace idea: the radio is absent from the build and the companion radio chip is held in reset. Every NFC feature maps to a QR-display or SD equivalent above. |
| USB kill-trace | Cut trace to permanently disable USB data | https://coldcard.com/docs/coldcard-q/ | b | **LANDED 0.1.0** | Options: document a board-level modification, or ship firmware that never enumerates USB data (current plan). |
| Dual secure elements + MCU, seed split across three vendors' chips | Extraction requires defeating all three chips | https://coldcard.com/docs/physical-notes/ ; https://blog.coinkite.com/understanding-mk4-security-model/ | c | **EQUIV** | The foundational hardware difference: no secure element on P4. The notyas counter-position: stateless-by-default (no stored secret to extract), and for stored-seed mode a device-bound Argon2id ladder with the three tiers stated in docs/SECURITY.md. **Not "flash encryption plus PIN-as-KDF"** - there is no flash encryption in 0.2.0, so the ladder is the whole of it. notyas never claims secure-element-class extraction resistance. |
| Tamper-evident bag, bag number in secure flash, sealed case | Supply-chain verification | https://coldcard.com/docs/physical-notes/ | b/d | **BUILDING m12** | Bag-number-in-flash is portable in spirit (provision at flash time). The primary notyas answer is reproducible builds plus user-flashable firmware: verify by rebuilding rather than by packaging. |
| HSM Mode + CKBunker (Mk4) | Unattended USB signing under an uploaded policy | https://coldcard.com/docs/hsm/ | d | **REJECT** | Requires an always-connected USB host - the opposite posture. If policy signing is wanted, the SSSP/CCC-style on-device policy rows are the coherent subset. Defer or reject deliberately. |
| SSSP - Single Signer Spending Policy | On-device policy for singlesig: magnitude, velocity, whitelist, TOTP-via-NFC 2FA, menu lockdown | https://coldcard.com/docs/sssp/ | b | **DEFER 0.3.x** | Policy engine ports (needs storage); the NFC-2FA leg needs a QR or manual-TOTP redesign; without a secure element the lockdown is firmware-enforced only - labeled honestly. |

## Summary

**Row count, corrected (R7).** The matrix is **72 rows**: the old "61 feature rows total"
counted sections 1 to 6 only, and section 7 adds 11. A row-by-row recount by primary class
gives **a=31, b=21, c=14, d=6**, against the old tally's 30/17/12/6. The old numbers are an
erratum, not a scope change - assignment in MILESTONES 7 is by row title, and the m13
audit dispositioned all 72 by title as well.

Row counts by primary class (rows with split classes counted under their first code):

- **a (directly portable): 31** - the seed-math family (dice, passphrase, temporary
  seeds), SD-based PSBT and batch signing, multisig xpub/descriptor file flows, message
  signing and BIP-322, address explorer, encrypted backups, clone-via-SD, watch-only
  exports, testnet, and the UI conveniences. Class a says "no hardware obstacle", not "in
  0.2.0": the lean re-scope defers a large part of this column, which is what the 0.2.0
  token records.
- **b (design changes): 21** - everything touching persistent state (Seed Vault, multisig
  registrations, SSSP/CCC policy, trick-PIN table, MicroSD 2FA), plus taproot/miniscript,
  where upstream mainline has not landed either. The secure-element-less pattern is the
  device-bound PIN ladder of docs/SECURITY.md, **not** master-seed-keyed AES and **not**
  flash encryption (R9, R17).
- **c (hardware-impossible as-is): 14** - see the list below.
- **d (judgment calls): 6** - USB data features (virtual disk, host protocol, HID typing,
  HSM/CKBunker), paper wallets, WIF store. All six are decided at MILESTONES 7.3 and none
  is left open.

**Disposition tally over the 72 rows, as of the m13 audit (2026-08-18):** LANDED 7,
BUILDING 13, QUEUED 3, PARTIAL 11, EQUIV 13, DEFER 18, REJECT 7. No row is blank, which is
the clause this file has to satisfy. `QUEUED` and `BUILDING` are the only tokens that can
change without a design decision; each is re-checked at the m13 gate, and anything still
`QUEUED` at release becomes `DEFER` there rather than shipping as an implied promise.

### Hardware-impossible list with honest equivalents

Corrected by the m13 audit: three rows named an equivalent that does not exist in 0.2.0.

| Missing hardware capability | notyas equivalent (shipped and documented) |
|---|---|
| Secure-element seed split / extraction resistance | Stateless-by-default (no stored secret); stored-seed mode uses the device-bound Argon2id PIN ladder, with the three tiers and their limits stated in docs/SECURITY.md. No flash encryption in 0.2.0 |
| Hardware attempt counter / 13-attempt brick | Device-bound ladder (each guess needs this board) + wipe-on-N, default 15: N guesses per full-flash restore cycle, labeled as exactly that |
| Secure-element-attested genuine LEDs | Verify screen: eFuse state, running-app SHA256, boot self-test; plus reproducible builds. Weaker without Secure Boot - the screen is produced by the firmware under suspicion |
| Nuke Device (destroy secure element) | Erase of the sealed records plus a one-way wipe-epoch bump; device remains reusable |
| TRNG-mixed seed generation | Dice-only key material with published verification math |
| NFC transfers (PSBT, address share, PushTX, TOTP) | QR display + microSD; PushTX outcome via phone-scans-QR broadcast |
| Camera scanning (base unit) | Manual entry + SD import today; CSI camera variant in m11, hardware gates contingent on a module |
| Key Teleport receive | **None in 0.2.0.** Not an encrypted state file over microSD - that would put key material on SD, which invariant 2b forbids (R10). The honest statement is "move the mnemonic yourself" |
| Dual microSD slots | -signed filename convention on one slot |
| Battery operation | USB power bank, power-only |
| Wrong-PIN hardware consequences | Same as attempt-counter row |
| Secure-element key slots | Not applicable. One eFuse key block is used, for the HMAC device binding; no flash-encryption or secure-boot key hierarchy exists in 0.2.0 |

Cross-reference: storage and PIN design in docs/SECURITY.md (normative) and this
directory's SECURITY.md and ARCHITECTURE.md; camera variant in CAMERA.md; ecosystem
crates that serve class-b rows in PLATFORM.md, with the reminder that nothing publishes in
0.2.0 (Q46).

Input to: MILESTONES.md reconciliation. Dispositioned by: docs/claims-audit-0.2.0.md,
which is where the m13 gate is re-run rather than re-argued.
