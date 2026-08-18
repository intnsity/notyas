# PARITY.md - Coldcard feature parity matrix for notyas 0.2.0

Status: reference document, wave-2 planning input.
Companion documents in this directory: ARCHITECTURE.md, SECURITY.md, UX.md,
MILESTONES.md, OPEN-QUESTIONS.md (written by a parallel planning workflow; where
they exist they govern the storage, security and UX designs this matrix assumes).

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

| Feature | What it does | Source | Class | Notes |
|---|---|---|---|---|
| TRNG seed generation (12/24 words) | New seed from onboard true RNGs; Mk4 mixes RNG sources across MCU and both secure elements | https://coldcard.com/docs/temporary-seeds/ ; https://blog.coinkite.com/understanding-mk4-security-model/ | c | P4 has a single TRNG with a known entropy-quality issue (esp-hal issue 5982) and no secure-element sources to mix. notyas policy is dice-only for key material. Honest equivalent: dice entropy (already core). Coldcard's 2026-07-31 hotfix 5.6.0/1.5.0Q addressed a limited-entropy seed-generation bug (https://github.com/Coldcard/firmware/blob/master/releases/ChangeLog.md), which supports dice-first as a defensible design stance for any vendor. |
| Dice-roll seed with verification math | SHA256 over ASCII roll string; >=50 rolls for 128-bit, 99 for 256-bit; warning on too few; rolls.py/rolls12.py for independent verification | https://coldcard.com/docs/verifying-dice-roll-math/ | a | Already implemented: BigDice FIXED mode is algorithm-identical; RAW mode adds iancoleman compatibility. Ship equivalent verification scripts and published vectors. |
| Import seed by word entry (12/18/24) | Restore any BIP-39 seed; word-list prefix entry | https://coldcard.com/docs/temporary-seeds/ | a | Touch keyboard matches or exceeds keypad/QWERTY entry. Already the 0.1.0 restore flow. |
| Scan seed via QR (SeedQR, words, xprv) | Q scans SeedQR, truncated words, xprv via camera | https://coldcard.com/docs/qr-scanner/ | c base / b with camera | No camera fitted on the base unit. The board's CSI path makes this class b on a camera-equipped variant (see CAMERA.md). Equivalent today: manual entry. |
| Temporary seeds (RAM-only) | Work from a different seed without touching master; discarded at reboot | https://coldcard.com/docs/temporary-seeds/ | a | Fits the notyas stateless model exactly; 0.1.0 is effectively temporary-seed-only. |
| Seed Vault | AES-256-CTR store of multiple seeds, encrypted with a key derived from the master seed; labels, quick switch | https://coldcard.com/docs/temporary-seeds/ | b | Encryption is keyed by the master seed, not the secure element, so the cryptography ports. Needs the 0.2.0 storage layer; without a secure element, at-rest protection reduces to flash encryption plus the master-seed key - documented plainly. |
| BIP-85 derived seeds | Child entropy: 12/18/24 words, WIF, xprv, hex, passwords; index 0-9999+; use in-device as temporary seed | https://coldcard.com/docs/bip85/ | a | Pure math on the master seed; add to notyas-core with BIP-85 test vectors. |
| BIP-85 passwords + USB keyboard emulation | Derive deterministic passwords; type them into a host as a USB HID keyboard | https://coldcard.com/docs/bip85-passwords/ ; https://coldcard.com/docs/settings/ | d | Password derivation itself is class a (display + QR). Keystroke emulation over USB HID is feasible on P4 but conflicts with the notyas no-USB-data identity; judgment call. |
| Seed XOR split/recombine | Split seed into 2-4 XOR parts, each a valid-checksum mnemonic; recombine on any device | https://coldcard.com/docs/seedxor/ ; https://seedxor.com | a | Simple XOR math; strong fit for a dice-first device. |
| BIP-39 passphrase | On-device entry; applied as temporary seed; optional save to microSD encrypted AES-256-CTR keyed by seed + card serial hash; never stored internally | https://coldcard.com/docs/passphrase/ | a | 0.1.0 already has passphrase. Card-serial-bound saved passphrases port cleanly (SDMMC exposes the CID serial). |
| Lock Down Seed | Destructively replace master seed with the passphrase-derived secret | https://coldcard.com/docs/passphrase/ | b | Meaningful only once notyas stores a master seed (0.2.0 storage layer); then trivial. |
| Destroy Seed / View Seed Words | Danger Zone seed functions | https://coldcard.com/docs/advanced/ | a | View/verify already present; destroy needs the storage layer to be meaningful. |
| Key Teleport | Encrypted seed/PSBT/backup transfer between two devices: ECDH ephemeral keys + dual AES-256-CTR via BBQr or NFC-assisted relay | https://coldcard.com/docs/key-teleport/ | c base | Receiving requires scanning BBQr (camera). Send-only (display BBQr) is half a protocol. Equivalent: encrypted backup file on microSD moved between devices (see Clone row). Class b on a camera variant. |

## 2. PINs, login, and duress

Coldcard's PIN system is anchored in the bootrom plus two secure elements from
different vendors, with attempt counting and brick enforced in hardware
(https://blog.coinkite.com/understanding-mk4-security-model/ ;
https://coldcard.com/docs/physical-notes/). notyas has no secure element, so
every row below carries the same framing: on P4, PIN logic is firmware plus
flash encryption only, and a physical attacker who can read and rewrite flash
can bypass counters. The robust equivalent is PIN-as-key-material - the PIN
stretched through a KDF into the storage encryption key, so guessing is
offline-hard but not attempt-limited - or notyas's existing stateless mode,
where there is no stored secret to attack. See SECURITY.md in this directory
for the governing design when present.

| Feature | What it does | Source | Class | Notes |
|---|---|---|---|---|
| Two-part main PIN (prefix + suffix) | 2-6 + 2-6 digits | https://coldcard.com/docs/pins/ | b | Port the UX; enforce via KDF into the storage key, not a hardware counter. |
| Anti-phishing words | Device-unique words shown after prefix; detects a swapped device | https://coldcard.com/docs/pins/ | b | Derivable from a device secret in encrypted flash + eFuse key. Weaker guarantee without a secure element (a flash-cloning attacker can replay the words); the reduced claim is stated in docs. |
| 13-failed-attempts brick | Unconditional hardware brick | https://coldcard.com/docs/pins/ | c | No hardware counter on P4. Equivalent: KDF-hard PIN plus optional firmware wipe-on-fail (best effort, bypassable by chip-off; labeled as such). |
| Trick PINs (13 slots: Brick Self, Wipe Seed variants, Duress Wallet, Login Countdown, Look Blank, Just Reboot, Delta Mode, Policy Unlock) | Decoy PINs triggering alternate behavior | https://coldcard.com/docs/pins/ ; https://coldcard.com/docs/advanced/ | b/d | Duress wallet (BIP-85 child seed on a decoy PIN) is pure firmware and genuinely useful: class b, needs storage. Brick/wipe variants without a hardware counter are firmware-enforced only - implement only with honest documentation (d). Delta Mode is deeply secure-element-integrated upstream and of questionable value re-implemented in software (d). |
| Wrong PIN actions (wipe/brick/last chance) | Configurable consequences below 13 attempts | https://coldcard.com/docs/pins/ | c | Same as brick row; firmware-only wipe is best-effort. |
| Login Countdown | Forced delay 5 min to 28 days before login | https://coldcard.com/docs/settings/ | b | Firmware timer; without a secure element it deters only an attacker using the UI. Low cost; labeled honestly. |
| Kill Key | Designated key during login instantly wipes seed | https://coldcard.com/docs/settings/ | b | Portable as a touch gesture. The wipe is real if implemented as storage-key zeroization (the flash-encrypted blob becomes unrecoverable) - genuinely effective without a secure element. |
| Scramble Keypad | Randomized digit layout against shoulder-surfing | https://coldcard.com/docs/settings/ | a | Trivial on a touchscreen. |
| Calculator Login (Q) | Login screen disguised as a working calculator | https://coldcard.com/docs/settings/ | a | Pure UI; low cost. |
| MicroSD 2FA | Enrolled card (AES file keyed by master secret + card serial) required at login, else fast seed wipe | https://coldcard.com/docs/microsd-2fa/ | b | Ports directly once a stored seed exists; firmware-enforced, labeled as such. |
| Device nickname / home XFP / idle timeout / menu wrapping | Login and UI conveniences | https://coldcard.com/docs/settings/ | a | Trivial. |
| Secure Logout | Clean logout wiping RAM state | https://coldcard.com/docs/settings/ | a | notyas already zeroizes on screen exit. |

## 3. Transaction signing (PSBT)

| Feature | What it does | Source | Class | Notes |
|---|---|---|---|---|
| PSBT signing via microSD | Read PSBT from card, verify, display outputs/fees, sign, write -signed file; FAT12/32 up to 32GB | https://coldcard.com/docs/ready-to-sign/ ; https://coldcard.com/docs/microsd/ | a | The planned 0.2.x core. Coldcard file conventions already adopted in the repo's ARCHITECTURE.md. |
| Batch signing ([Sign All]) | One approval pass over all PSBTs on the card | https://coldcard.com/docs/advanced/ | a | Straightforward once single signing exists. |
| PSBT via USB (encrypted host protocol) | Host tools (Electrum, Sparrow) send PSBT over an encrypted USB protocol | https://coldcard.com/docs/cli/ | d | Technically possible on P4 native USB; conflicts with the notyas no-USB-data identity. QR and SD cover the use case; deliberate decision required. |
| PSBT via virtual disk (USB MSC, optional auto-sign) | Device appears as a 4MB USB drive; drag-and-drop PSBT | https://coldcard.com/docs/settings/ ; https://coldcard.com/mk4 | d | Same USB judgment call: feasible (TinyUSB MSC), but reopens the USB attack surface the airgap posture closes. |
| PSBT via QR/BBQr | Scan unsigned PSBT (BBQr up to 2MiB); display signed PSBT as animated BBQr | https://coldcard.com/docs/qr-scanner/ | b display / c scan on base | Displaying signed-PSBT BBQr/UR out is pure rendering - planned 0.2.x. Scanning in requires the camera option (CAMERA.md). Without it, SD in / QR out is the documented asymmetric flow. |
| PSBT via NFC | Send/receive PSBT by tap | https://coldcard.com/docs/nfc-tools/ | c | No NFC hardware. Equivalent: QR display plus SD. |
| Output/input explorer | Inspect outputs (QR per output) and input UTXO details before signing | https://github.com/Coldcard/firmware/blob/master/releases/History-Mk.md | a | Pure UI over the PSBT parser; include from day one. |
| On-device finalization | Emit a fully final network transaction when the last signature is added | https://coldcard.com/docs/multisig/ | a | Needed for any broadcast-helper flow. |
| Max fee guard, v3 txns, sighash checks | Fee ceiling; non-standard SIGHASH gate | https://coldcard.com/docs/settings/ ; https://coldcard.com/docs/advanced/ | a | Port the guardrails with the signer. |
| NFC PushTX | Tap phone to broadcast signed txn via a configurable URL | https://coldcard.com/docs/settings/ ; https://coldcard.com/docs/nfc-tools/ | c | No NFC and no radio, by design. Equivalent: display the signed transaction as QR/BBQr for a phone to scan and broadcast - same outcome, zero device connectivity. |
| Taproot send-to-P2TR | Verify/display P2TR outputs | https://coldcard.com/docs/version-history/ | a | rust-bitcoin handles bech32m natively. |
| Taproot keyspend, tapscript, MuSig2 | Full taproot signing (upstream: experimental/EDGE branch) | https://github.com/Coldcard/firmware/blob/edge/docs/taproot.md ; https://blog.coinkite.com/edge-635/ | b | Not in upstream mainline as of 2026-08, so the parity target is moving. rust-bitcoin + secp256k1 provide schnorr/taproot directly; an area where notyas can reach parity or better. Design change: taproot descriptors in the wallet-registration model. |
| Miniscript / MiniTapscript (BIP-380 descriptors, BIP-388 policies) | Spend arbitrary miniscript policies (upstream: EDGE branch) | https://github.com/Coldcard/firmware/blob/edge/docs/miniscript.md | b | rust-miniscript is mature; notyas could match or exceed upstream mainline. Significant descriptor-wallet design work. |

## 4. Multisig

| Feature | What it does | Source | Class | Notes |
|---|---|---|---|---|
| Multisig registration (file/descriptor import) | Up to 15 co-signers; P2SH, P2WSH, P2SH-P2WSH; import via SD, virtual disk, QR, NFC, or PSBT-carried | https://coldcard.com/docs/multisig/ | b | Needs the 0.2.0 storage layer for registrations; SD plus QR-display transports available. Import formats (Coldcard text file and BIP-380 descriptor) port as-is. |
| Trust policy knobs, Skip Checks, Unsorted multisig, Full Address View | XPUB-handling policy options | https://coldcard.com/docs/multisig/ ; https://coldcard.com/docs/settings/ | a | Policy logic only. |
| Export XPUB / Create Airgapped | Emit co-signer xpub files; build a wallet from collected xpubs offline | https://coldcard.com/docs/multisig/ ; https://coldcard.com/docs/airgap-multisig/ | a | Already the planned 0.2.x multisig xpub export. |
| Descriptor export (pretty/raw, Core importdescriptors) | BIP-380 descriptor out | https://coldcard.com/docs/descriptor_export/ | a | rust-miniscript descriptor serialization. |
| BSMS (BIP-129) coordinator + signer | Secure multisig setup rounds over SD/QR (upstream: EDGE preview) | https://coldcard.com/docs/bsms/ | b | File-based rounds over SD port cleanly. EDGE-only upstream, so implementing it is parity-plus. A Rust BSMS crate is a proposed platform contribution - see PLATFORM.md. |
| CCC - Coldcard Co-Signing | Device holds a spending-policy key and auto-co-signs 2-of-N only within policy (magnitude, velocity, whitelist, TOTP 2FA via NFC) | https://coldcard.com/docs/coldcard-cosigning/ | b/d | Policy engine and policy key are firmware plus math (b, needs storage). The NFC TOTP leg is class c; equivalents are a QR the phone scans or on-device TOTP with user-entered code. Without a secure element the policy key's extraction resistance is weaker; stated plainly. |

## 5. Addresses, messages, identity

| Feature | What it does | Source | Class | Notes |
|---|---|---|---|---|
| Address Explorer | Browse receive/change addresses; custom accounts and paths; CSV export of 250 addresses + detached signature; per-address QR; NFC share | https://coldcard.com/docs/address-explorer/ | a | 0.1.0 already shows addresses + QR; add change toggle, CSV export, signed export. NFC share drops (c). |
| Verify Address Ownership | Given an address, search first 1,528 addresses across singlesig, multisig, accounts; report path or Unknown | https://coldcard.com/docs/verify-address-ownership/ | b | Search logic is pure math; input needs typing on base hardware (camera variant makes it smooth). High-value anti-phishing feature; build it. |
| Message signing (BIP-137, RFC2440 armor) | Sign short ASCII messages from SD file or on-device entry; on-device signature-file verify | https://coldcard.com/docs/message-signing/ | a | SD path plus on-screen entry; rust-bitcoin covers message signing. |
| BIP-322 signing / proof-of-reserves | Generic signed-message standard; PoR PSBTs | https://coldcard.com/docs/bip322/ | a | Spec work only; good parity item. |
| View Identity | Master fingerprint, serial, extended master key | https://coldcard.com/docs/advanced/ | a | notyas Verify screen already covers device identity; add XFP display. |
| Export watch-only wallet | Named exports: Sparrow, Bitcoin Core, Electrum, Nunchuk, and many others; generic JSON; XPUB paths; signed exports | https://coldcard.com/docs/menu-tree/ | a | File writers plus QR; high leverage for works-with-your-software credibility. |
| Paper wallets | Unrelated random key to address + WIF, templated print, TRNG or dice entropy | https://coldcard.com/docs/paper-wallets/ | d | Portable (dice-entropy variant), but paper wallets are broadly discouraged, including in Coldcard's own documentation. If kept: dice-only. |
| WIF Store | Import loose WIF keys, sign PSBTs with them | https://github.com/Coldcard/firmware/blob/master/releases/History-Mk.md | d | Niche; needs storage; encourages loose-key handling. Defer. |
| Secure Notes and Passwords | AES-256-CTR notes and password entries keyed by master seed; generators; JSON export; USB keystroke typing | https://coldcard.com/docs/secure_notes/ | b/d | Crypto and storage port (b, needs storage layer). Whether a signing device should also be a password manager is a scope question (d); the keystroke-typing leg is the USB judgment call. |

## 6. Backup, restore, device lifecycle

| Feature | What it does | Source | Class | Notes |
|---|---|---|---|---|
| Encrypted backups | Standard 7z AES-256-CBC; key = SHA256 of 12 BIP-39 words; password quiz; includes seed/settings/multisig/notes; restore as master or temporary seed | https://coldcard.com/docs/backups/ | a | Standard formats verifiable with any 7z tool - fits the notyas auditability story. Rust 7z-AES exists (sevenz-rust) or a vetted implementation can be wrapped; the quiz is UI. |
| Clone device | SD round-trip: target writes a pubkey, source encrypts full state to it, target decrypts | https://coldcard.com/docs/clone-coldcard/ | a | Clean ECDH-over-SD design, no radio needed; good fit for fleet setup. |
| Firmware upgrade, factory-signed only | Only vendor-key-signed firmware loads; SHA-256 + GPG user verification | https://coldcard.com/docs/upgrade/ | b | notyas: signed image on SD plus ESP32 Secure Boot v2 RSA-3072 (the ECDSA ROM path is excluded per AR2026-006, already in the repo's SECURITY.md). GPL3 difference: users can build and sign their own firmware - both chains documented. |
| Bless Firmware / genuine-state LEDs | Secure-element-controlled LEDs attest flash contents | https://coldcard.com/docs/upgrade/ ; https://coldcard.com/docs/physical-notes/ | c | No secure element to drive an unspoofable LED. Equivalent: the notyas Verify screen (eFuse secure-boot state, app SHA256, boot self-test) - software attestation, labeled as such. |
| Downgrade protection | Bootloader refuses older firmware | https://coldcard.com/docs/upgrade/ ; https://coldcard.com/docs/advanced/ | b | ESP32 Secure Boot v2 supports eFuse anti-rollback counters; open design decision on burning user-device fuses. |
| Nuke Device | Wipe seed and destroy the secure element | https://coldcard.com/docs/advanced/ | c | No secure element to destroy. Equivalent: crypto-erase of the flash-encryption-keyed storage - real, and the device remains reusable, which is arguably a feature. |
| Selftest, settings-space and cache maintenance, dev menu | Maintenance and developer functions | https://coldcard.com/docs/advanced/ | a/b | Selftest exists (boot BIP vectors). Secure-element key-slot functions are c (not applicable). The rest is trivial. |
| Testnet4 / regtest toggle | Network switch | https://coldcard.com/docs/advanced/ | a | Essential for development and integrations. |

## 7. Q-specific hardware and remaining hardware surface

| Feature | What it does | Source | Class | Notes |
|---|---|---|---|---|
| QWERTY keyboard (Q) | Fast passphrase/word entry | https://coldcard.com/docs/coldcard-q/ | a equivalent | 720x720 capacitive touch keyboard meets or exceeds physical-key entry for this use. |
| 320x240 2.3" LCD (Q) | Larger display than Mk4 | https://coldcard.com/docs/coldcard-q/ | a exceeded | notyas panel is 720x720 4"; higher BBQr density per frame. |
| QR scanner module + flashlight (Q) | Camera-based scanning | https://coldcard.com/docs/coldcard-q/ | c base / b variant | The single biggest hardware gap versus the Q. P4 has MIPI-CSI plus hardware JPEG; a camera-fitted variant is the honest path to full Q-class parity (CAMERA.md). Without it, notyas is an SD-plus-QR-display device: Mk4-class transport with a Q-class screen. |
| Dual microSD slots (Q) | Separate unsigned/signed cards | https://coldcard.com/docs/coldcard-q/ | c | One slot. Workflow equivalent: distinct -signed filenames (already the upstream convention). |
| AAA battery power (Q) | Fully unplugged operation | https://coldcard.com/docs/coldcard-q/ | c | No battery or PMIC on board. Equivalent: USB power bank (power only, no data - the cleanest notyas posture). |
| NFC + NFC kill-trace | Tap transfers; PCB trace cut to disable permanently | https://coldcard.com/docs/coldcard-q/ ; https://coldcard.com/docs/nfc-tools/ | c | No NFC chip. notyas embodies a stronger form of the kill-trace idea: the radio is absent from the build and the companion radio chip is held in reset. Every NFC feature maps to a QR-display or SD equivalent above. |
| USB kill-trace | Cut trace to permanently disable USB data | https://coldcard.com/docs/coldcard-q/ | b | Options: document a board-level modification, or ship firmware that never enumerates USB data (current plan). |
| Dual secure elements + MCU, seed split across three vendors' chips | Extraction requires defeating all three chips | https://coldcard.com/docs/physical-notes/ ; https://blog.coinkite.com/understanding-mk4-security-model/ | c | The foundational hardware difference: no secure element on P4. The notyas counter-position (already in the repo's SECURITY.md): stateless-by-default (no stored secret to extract), and for 0.2.0 stored-seed mode, flash encryption plus PIN-as-KDF with plainly stated limits. notyas never claims secure-element-class extraction resistance. |
| Tamper-evident bag, bag number in secure flash, sealed case | Supply-chain verification | https://coldcard.com/docs/physical-notes/ | b/d | Bag-number-in-flash is portable in spirit (provision at flash time). The primary notyas answer is reproducible builds plus user-flashable firmware: verify by rebuilding rather than by packaging. |
| HSM Mode + CKBunker (Mk4) | Unattended USB signing under an uploaded policy | https://coldcard.com/docs/hsm/ | d | Requires an always-connected USB host - the opposite posture. If policy signing is wanted, the SSSP/CCC-style on-device policy rows are the coherent subset. Defer or reject deliberately. |
| SSSP - Single Signer Spending Policy | On-device policy for singlesig: magnitude, velocity, whitelist, TOTP-via-NFC 2FA, menu lockdown | https://coldcard.com/docs/sssp/ | b | Policy engine ports (needs storage); the NFC-2FA leg needs a QR or manual-TOTP redesign; without a secure element the lockdown is firmware-enforced only - labeled honestly. |

## Summary

Row counts by primary class (rows with split classes counted under their
first/primary code; 61 feature rows total):

- **a (directly portable): 30** - the entire seed-math family (dice, BIP-85,
  Seed XOR, passphrase, temporary seeds), SD-based PSBT and batch signing,
  multisig xpub/descriptor file flows, message signing and BIP-322, address
  explorer, encrypted 7z backups, clone-via-SD, watch-only exports, testnet,
  and the UI conveniences. This is most of the daily-use surface.
- **b (design changes): 17** - everything touching persistent state (Seed
  Vault, multisig registrations, SSSP/CCC policy, trick-PIN table, MicroSD
  2FA), blocked on the 0.2.0 storage design, with master-seed-keyed AES +
  flash encryption + PIN-as-KDF as the secure-element-less pattern; plus
  taproot/miniscript, where upstream mainline has not landed either.
- **c (hardware-impossible as-is): 12** - see the list below.
- **d (judgment calls): 6** - USB data features (virtual disk, host protocol,
  HID typing, HSM/CKBunker), paper wallets, WIF store. Each is deferred to
  OPEN-QUESTIONS.md / MILESTONES.md for a deliberate accept/reject.

### Hardware-impossible list with honest equivalents

| Missing hardware capability | notyas equivalent (shipped and documented) |
|---|---|
| Secure-element seed split / extraction resistance | Stateless-by-default (no stored secret); stored-seed mode uses flash encryption + PIN-as-KDF with stated limits |
| Hardware attempt counter / 13-attempt brick | KDF-hard PIN (offline-hard guessing) + best-effort firmware wipe, labeled |
| Secure-element-attested genuine LEDs | Verify screen: eFuse secure-boot state, app SHA256, boot self-test; plus reproducible builds |
| Nuke Device (destroy secure element) | Crypto-erase of keyed storage; device remains reusable |
| TRNG-mixed seed generation | Dice-only key material with published verification math |
| NFC transfers (PSBT, address share, PushTX, TOTP) | QR display + microSD; PushTX outcome via phone-scans-QR broadcast |
| Camera scanning (base unit) | Manual entry + SD import today; CSI camera variant proposed in CAMERA.md |
| Key Teleport receive | Encrypted state file over microSD (clone flow) |
| Dual microSD slots | -signed filename convention on one slot |
| Battery operation | USB power bank, power-only |
| Wrong-PIN hardware consequences | Same as attempt-counter row |
| Secure-element key slots | Not applicable; eFuse + flash-encryption key hierarchy documented instead |

Cross-reference: storage and PIN design in this directory's SECURITY.md and
ARCHITECTURE.md (parallel workflow); camera variant in CAMERA.md; ecosystem
crates that serve class-b rows (BSMS, SeedQR, sealed storage) in PLATFORM.md.

Input to: MILESTONES.md reconciliation
