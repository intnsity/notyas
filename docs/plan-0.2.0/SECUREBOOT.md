# SECUREBOOT.md - Secure Boot v2 for notyas

**Status: PLAN. Target release: 0.3.0.** 0.2.0 ships **without** Secure Boot v2, without
flash encryption, and with **no eFuse burned on any device, at any point**. What 0.2.0
carries is a small preparatory slice (section 2) chosen so that nothing in it costs
anything to carry and nothing in it touches a fuse.

**This document has never been executed.** The burn runbook in section 11 is a paper
procedure. No step in it has been performed on any board belonging to this project, and
nothing in this document has been validated against a chip whose eFuses were actually
programmed. Section 12 lists exactly which claims are therefore unverified-on-hardware and
what the first real burn risks as a consequence. Read that section before running section
11 for the first time.

Owner document for: the signature scheme and why it is not negotiable, the two-key
distinction (release-manifest GPG key versus secure-boot signing key), key generation, the
key-ownership decision (the former `OPEN-QUESTIONS` Q32), the flash-geometry constraint
that secure boot imposes, anti-rollback, the burn order, and the runbook.

Companions: `VERIFY.md` (which already specifies every secure-boot row the device shows,
and section 9.3 of which is the load-bearing argument this document exists to eventually
satisfy), `REPRODUCIBLE.md` (the reproducibility claim and the release key), `ESP-SEAL.md`
(the eFuse key-block budget 6.1, the brick classes 6.2, the provisioning ceremony 4.3),
`SECURITY.md` (invariant 6), `ARCHITECTURE.md` (2.7 geometry, the no-OTA decision),
`MILESTONES.md` (m1, m3h, m4a, m12, m13), `docs/HARDWARE.md` and `docs/BOARDS.md`.

---

## 0. The one-paragraph summary

Secure Boot v2 on ESP32-P4 must use **RSA-3072**; ECDSA secure boot is broken at ROM level
on every P4 revision that exists, with no software fix (section 3). Enabling it requires a
**new RSA-3072 private key that the owner generates personally and never lets any tool or
machine generate on their behalf** (section 5), and that key is **not** the existing GPG
release key and cannot be derived from it (section 4). Burning is irreversible and
performed partly by the operator and partly, at the point of no return, by the device
itself on its first boot after a secure-boot bootloader is flashed (section 10). The
project's current flash geometry does not have room for a signed bootloader and must move
the partition table before secure boot can be enabled (section 7). ESP-IDF's anti-rollback
feature is incompatible with the project's factory-only partition table (section 8). None
of this happens in 0.2.0.

---

## 1. What is in 0.2.0 and what is not

| | 0.2.0 | 0.3.0 |
|---|---|---|
| Secure Boot v2 enabled on any device | **no** | subject to section 6's decision |
| Any eFuse burned by this project on either dev board | **no** | no - dev boards stay clean permanently (section 9) |
| Flash encryption | **no** (`OPEN-QUESTIONS` Q63(a)) | with secure boot, or not at all |
| Anti-rollback | **no** - and it is not merely deferred, it is currently *unavailable* (section 8) | subject to section 8's decision |
| Secure-boot key generated | **no** | yes, by the owner, before anything is burned |
| Verify screen reads and prints secure-boot eFuse state | **yes** - it prints `disabled` and three `not burned` digests | unchanged code, different values |
| Signed release artifacts | **no** | yes, as *derived* artifacts (section 6) |
| Burn runbook exists on paper | **yes** (section 11) | executed for the first time |

**The release documentation must say this, in these terms, and must not soften it.** The
sentence for `VERIFYING.md`, `docs/SECURITY.md` and the release announcement:

> notyas 0.2.0 does not use Secure Boot. No eFuse on your device is programmed by notyas,
> and the chip will run any firmware that is flashed to it. Every value the Verify screen
> shows is read and reported by the firmware being verified; firmware that has been
> replaced can report anything. The way to know what your device is running is to build it
> from source yourself, or to reproduce the published build and compare, and then flash it
> yourself.

That is `VERIFY.md` 9.4's wording with the secure-boot escape clause removed, because in
0.2.0 there is no escape clause. See section 13.1 for the exact edit.

---

## 2. The 0.2.0 preparatory slice, and what was rejected from it

The bar: **it costs nothing to carry now and it would be painful or expensive to retrofit
later.** Anything that fails either half is not in 0.2.0. Anything requiring key material,
any burn tooling pointed at a real device, and any config change that alters the shipped
image's behaviour is excluded outright.

### 2.1 Accepted

**P1 - the Verify screen already does the right thing; confirm and leave it alone.**
`VERIFY.md` 5.1 and 5.4 already specify every field: `SECURE_BOOT_EN`,
`SECURE_BOOT_AGGRESSIVE_REVOKE`, all three key digests through
`esp_secure_boot_read_key_digests()` with their revocation bits (ratified Q58), the
key-block purpose/`RD_DIS`/`WR_DIS` table, and the anti-rollback image/eFuse pair. On an
unburned device these render `disabled`, `no`, three times `not burned`, six times
`<unused>`, and two zeros. That is a truthful readout of an absent anchor and it needs no
change. Cost of carrying it: zero, it is already m3h's scope. Cost of not having it:
the owner could not confirm a burn worked, which is the one moment the row matters most.
Confirmed against `VERIFY.md`'s design contract: rule 2 (no opining) means the screen says
`Secure boot   disabled` and nothing else - no warning band, no colour, no advice. The
interpretation lives in `VERIFYING.md`. **No change to `VERIFY.md` is required by this
document.**

**P2 - measurement SB1: how big is a signed bootloader.** Build a bootloader with
`CONFIG_SECURE_BOOT=y`, `CONFIG_SECURE_BOOT_V2_ENABLED=y`,
`CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME=y` against a throwaway key, and record its size.
**Never flash it** (section 9, trap T1). This is a build-only measurement with no device
involvement whatsoever, and it is the number that decides the partition-table offset in
section 7 - a geometry question, and geometry questions are the expensive kind to get
wrong late. Earns its place on that basis alone.

**P3 - measurement SB2: what signing does to the app image and to the device's digest.**
Build the app with `CONFIG_SECURE_SIGNED_APPS_NO_SECURE_BOOT=y` (ESP-IDF: *"Require apps to
be signed to verify their integrity. This option uses the same app signature scheme as
hardware secure boot, but unlike hardware secure boot it does not prevent the bootloader
from being physically updated."*) under a throwaway key, flash it to a dev board with an
ordinary non-secure-boot bootloader - which is safe, because nothing on either side burns
anything - and record three numbers: the signed `app.bin` length, whether
`esp_partition_get_sha256()` on the running partition returns the same value as for the
unsigned build, and the `esp_image_get_metadata()` `image_len`. This decides what the
release manifest has to contain (section 6.4) and it settles it before m12 freezes the
artifact set, which is the only reason it is in 0.2.0 rather than 0.3.0.

**P4 - a tooling refusal, five lines, and the highest value item here.** `tools/flash.ps1`
and the container's flash path **refuse to flash** a bootloader whose generating sdkconfig
contains `CONFIG_SECURE_BOOT=y` or `CONFIG_SECURE_FLASH_ENC_ENABLED=y`, with an explicit
message naming this document. Rationale in section 9: flashing a secure-boot bootloader is
not a reversible mistake, it is *the* burn, performed by the device on the next power-up
with no further prompt. A guard that costs five lines against an accident that costs a
board is not a close call. Related and equally cheap: **the string `--do-not-confirm` must
never appear in any script in this repository**, and a CI grep asserts that.

**P5 - three documentation corrections, because the current text is wrong rather than
merely incomplete.** Listed with their exact wording in section 13.1: `ARCHITECTURE.md`'s
claim that eFuse anti-rollback works with the factory-only layout (it does not, section 8),
the burn-order rationale recorded in `ESP-SEAL.md` 4.3, `MILESTONES.md` section 3 and
`OPEN-QUESTIONS` Q45 (the stated reason is not the operative one, section 10.2), and
`REPRODUCIBLE.md` 4.4's description of a signed image as differing by "an appended
signature block" (it also differs by up to 64 KiB of padding, section 6.2).

**P6 - keep the manifest format tag versioned and record the successor.** `VERIFY.md` 7.3's
`notyas-verify-manifest/1` and 7.2's `notyas-verify/1` are already self-describing and
versioned, so signed-artifact fields land in a `/2` without a format break. Nothing to do
except write that intent down, which this sentence does.

### 2.2 Rejected, with the reason

**Moving `CONFIG_PARTITION_TABLE_OFFSET` now (section 7).** Fails the second half of the
bar. The retrofit is genuinely cheap: with the recommended target of `0xC000` the app,
`wallets` and `counters` offsets do not move at all, and `partition-table.bin`'s *content*
is unchanged because the CSV records absolute partition offsets, not the table's own
location. Only `bootloader.bin` (which embeds the offset) and the flashing offsets change,
and both are regenerated at the burn anyway. Moving it in 0.2.0 would change the shipped
image for no benefit that survives to 0.3.0. **What is required is that the arithmetic be
recorded** so nobody later assumes the layout is secure-boot-ready as it stands - which is
section 7's job.

**Switching `factory` to `ota_0` and adding an `otadata` partition to make anti-rollback
possible (section 8).** Fails both halves. It changes the shipped partition table, it
introduces a data partition that `SECURITY.md` invariant 2 says does not exist, and it
buys nothing until secure boot is on - anti-rollback protects a signature chain, and
without one an attacker flashes whatever they like. It belongs to the 0.3.0 geometry
decision, taken once, with section 7's decision, in the same edit.

**Any key material, anywhere.** No secure-boot key is generated in 0.2.0. No key is placed
in the repository, in the container image, in CI, on the NAS share, or in any environment
variable. The throwaway keys used by measurements SB1 and SB2 are generated on the bench,
named `bench-throwaway-DO-NOT-BURN.pem`, `.gitignore`d, and are not the owner's key and
never become it.

**Any burn tooling wired to a device.** No `espefuse` invocation targeting a COM port ships
in `tools/`. Section 11 is prose, deliberately, and it stays prose until the owner runs it
by hand.

**Enabling app signing in the shipped configuration.** `CONFIG_SECURE_SIGNED_APPS_NO_SECURE_BOOT`
is used only for measurement SB2's scratch build. It requires a key and it changes the
shipped image; both are out of scope.

---

## 3. RSA-3072, and never ECDSA - re-verified

ESP32-P4 supports both schemes. **Only RSA-3072 may be used**, and this is not a
preference.

**Espressif advisory AR2026-006**, *Security Advisory Concerning ECDSA Secure Boot Issue in
ESP32-H2 / ESP32-C5 / ESP32-C61 / ESP32-P4 / ESP32-S31*, issued 2026/06/24, revision V1.1
of 2026/07/28. Re-read in full for this document; it still stands and has not been
withdrawn or narrowed.
https://www.espressif.com/en/support/documents/advisories ,
https://documentation.espressif.com/AR2026-006_Security_Advisory_Concerning_ECDSA_Secure_Boot_Issue_in_ESP32-H2_ESP32-C5_ESP32-C61_ESP32-P4_ESP32-S31_EN.pdf

The five sentences that decide this:

- Root cause: *"the ECDSA Secure Boot verification workflow in the chip does not
  sufficiently validate that the supplied (r, s) signature components lie within the valid
  range defined by the elliptic curve (1 <= r, s <= n - 1)."*
- Effect: *"the ROM-based ECDSA signature verification step may return a successful result
  for an invalid signature, allowing an attacker who can replace the signed firmware image
  in flash memory to bypass ECDSA Secure Boot."*
- Affected: *"ESP32-P4 (up-to chip revision v3.2)"*. **Both of this project's boards are rev
  v1.3, and the production-silicon candidate in `OPEN-QUESTIONS` Q9 is rev >= v3.1. Both are
  inside the affected range.** There is no P4 silicon on the market that is not affected.
  *"The hardware fix for this issue will be included in future tape-outs."*
- No fix: *"At present, there is no software fix available for this issue on currently
  affected SoCs."*
- RSA is clean: *"RSA-based Secure Boot is not affected by this issue and remains a fully
  supported firmware authentication mechanism on the affected products."* The recommended
  countermeasure is *"to configure Secure Boot to use RSA signatures instead of ECDSA for
  the new production batches."*

Two further facts worth carrying:

- **ESP-IDF now gates ECDSA secure boot behind a deliberate insecure-options opt-in.** Per
  the advisory, building it requires setting **both** `CONFIG_SECURE_BOOT_INSECURE` and
  `CONFIG_SECURE_BOOT_V2_FORCE_ENABLE_ECDSA`. That is Espressif treating the scheme as
  unfit; a build of ours that turned those on would be doing so against the vendor's own
  gate.
- **Application-layer ECDSA is unaffected.** *"ECDSA verification from the application
  layer is not affected, since the ECDSA driver ensures correct peripheral initialization
  and validation for the input signature components."* The bug is in the ROM's boot-time
  verifier only. Nothing in notyas's signing engine is implicated, and this document says
  so explicitly so that nobody reads the advisory and reaches for the wrong conclusion
  about the wallet's own ECDSA.

**The mechanical enforcement.** `firmware/sdkconfig.base.defaults` never contains
`CONFIG_SECURE_BOOT_V2_FORCE_ENABLE_ECDSA` or
`CONFIG_SECURE_SIGNED_APPS_ECDSA_V2_SCHEME`, and the release script's sdkconfig assertion
list (`REPRODUCIBLE.md` 3.3 step 6) gains both as *forbidden* entries alongside the
existing required ones. A grep is not a control; an assertion in the build that already
aborts on sdkconfig drift is.

The exact option names, from `components/bootloader/Kconfig.projbuild` at v5.5 (note the
commonly guessed name `CONFIG_SECURE_BOOT_V2_RSA_SCHEME` **does not exist**):

```
CONFIG_SECURE_BOOT                       "Enable hardware Secure Boot in bootloader (READ DOCS FIRST)"
CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME     "RSA"          <- this one
CONFIG_SECURE_SIGNED_APPS_ECDSA_V2_SCHEME "ECDSA (V2)"  <- never
CONFIG_SECURE_BOOT_SIGNING_KEY           path to the private key, default "secure_boot_signing_key.pem"
CONFIG_SECURE_BOOT_BUILD_SIGNED_BINARIES default y, depends on SECURE_SIGNED_APPS
```
https://docs.espressif.com/projects/esp-idf/en/v5.5/esp32p4/security/secure-boot-v2.html

Espressif's own framing of the tradeoff - *"RSA is recommended for use cases where fast
boot-up time is required whereas ECDSA is recommended for use cases where shorter key
length is required"* - is superseded here by the advisory: key length is not a constraint
for this product, and the shorter-key branch is broken.

---

## 4. Two keys, two jobs. They are not interchangeable.

This section exists because conflating them is the single most plausible way this design
goes wrong, and the conflation is easy to make: both are RSA, both are "the signing key",
both are the owner's, and both must be protected.

| | **Release manifest key** | **Secure-boot signing key** |
|---|---|---|
| What it is | OpenPGP RSA-4096, the existing BigDice identity | RSA-3072, **new, does not exist yet** |
| Fingerprint / identity | `A1E9 53B2 5C6A 623B 77A1 D522 3AC4 BBCF E51A B37D` | none yet; identified by the SHA-256 digest of its public key |
| What it signs | `SHA256SUMS.txt`, and the annotated git tag | `bootloader.bin` and `app.bin`, as an appended signature block |
| Who verifies it | **a person, on their computer, before flashing** | **the chip's boot ROM and bootloader, on every single boot** |
| The question it answers | "did this file come from intnsity?" | "may this firmware run on this chip?" |
| Tooling | `gpg` | `espsecure` |
| Where the public half lives | keyservers, `docs/keys/`, the GitHub profile | burned into eFuse `SECURE_BOOT_DIGEST0`, as a 32-byte digest |
| If lost | annoying: generate a new one, publish it, re-sign future releases | **catastrophic and permanent: no future firmware can ever be installed on any device whose eFuse holds its digest** |
| If leaked | bad: an attacker can publish files that appear to come from intnsity, until revocation propagates | **worse: an attacker can sign firmware that burned devices will boot, and there is no revocation channel that reaches an offline device** |

**They cannot be the same key and the GPG key cannot be converted into one.** Three
independent reasons, any one sufficient:

1. **The sizes do not match.** ESP32-P4 Secure Boot v2 requires RSA-3072. The owner's GPG
   key is RSA-4096. The signature block format has a fixed 384-byte modulus field; a
   4096-bit modulus is 512 bytes and does not fit. This is not a configuration option.
2. **The formats and the tooling do not meet.** `espsecure` consumes a PEM-encoded
   PKCS#8/PKCS#1 private key. An OpenPGP secret key is a different container with different
   packet framing, and if the key is on a hardware token (`OPEN-QUESTIONS` Q30, deferred)
   the private half cannot be exported at all, by design.
3. **The blast radii are different and must stay separated.** The GPG key is used regularly,
   on a machine with a network. The secure-boot key authorizes code execution on hardware
   that has no way to learn about a revocation. Using one key for both means every routine
   release signing is also an exposure of the key that owns every burned device forever.
   Separation here is not hygiene, it is the difference between "re-issue a key" and
   "every device I ever burned is now permanently ownable by whoever took it".

**Both exist, both matter, they sit at different layers.** A user flashing a 0.3.0 release
would use the GPG signature to decide whether to trust the download, and their chip would
use the secure-boot signature to decide whether to run it. Neither substitutes for the
other: a GPG-verified download that is not secure-boot-signed will not boot on a burned
device, and a secure-boot-signed image with no GPG signature gives the user no reason to
believe where it came from.

---

## 5. Generating the secure-boot key. The owner does this, personally.

**Answer to "maybe i need to be the one to make it IDK": yes. You, personally, by hand, on
a machine you control, and no tool in this project will ever do it for you.** This
document deliberately contains no step in which a key is generated by tooling on the
owner's behalf, no CI job that produces one, and no container that holds one. A key that
some automation generated is a key that some automation had a copy of.

### 5.1 The ceremony

Preferably on an offline machine; at minimum on a machine that is not shared, not being
screen-recorded, and whose shell history you are willing to clear. Everything below runs
once and is never repeated for the life of the key.

```
# 1. Confirm the tool. Command spelling changed between esptool v4.x (underscores)
#    and v5.x (hyphens); check yours before typing anything else.
espsecure version
espsecure --help

# 2. Generate. esptool v5.x spelling:
espsecure generate-signing-key --version 2 --scheme rsa3072 notyas-secureboot-v1.pem
#    esptool v4.x spelling:
# espsecure.py generate_signing_key --version 2 --scheme rsa3072 notyas-secureboot-v1.pem

# 3. Derive the public-key digest. THIS is the 32 bytes that get burned; the private key
#    itself never goes near a device.
espsecure digest-sbv2-public-key --keyfile notyas-secureboot-v1.pem \
    --output notyas-secureboot-v1-digest.bin
sha256sum notyas-secureboot-v1-digest.bin        # record this; it is the row the
                                                 # Verify screen will show
```

The private key is a PEM file of roughly 2.5 KB. That is small enough to be printed and
re-typed, which is what makes the backup below practical.

### 5.2 What must never happen to it

- It is never committed to any repository, including a private one.
- It never goes on the NAS share (`<the share>\...`). The share is a working
  filesystem accessible to build tooling and to agents; it is not a key store.
- It is never pasted into a terminal, chat, issue or agent prompt that is being logged.
  Note that this project's development involves automated agents with shell access: any
  path readable by a build script is a path the key must not be on.
- It never enters the reproducible-build container, CI, or any hosted runner.
  `REPRODUCIBLE.md` 6.3 already establishes the principle for the GPG key - *"Signing
  itself stays off CI - the key never touches a hosted runner"* - and it applies here with
  more force, not less.
- It is not stored unencrypted on a machine that also browses the web.

### 5.3 Backup, because the failure mode is symmetric and brutal

Lose it and every burned device is frozen at whatever firmware it holds, forever. Leak it
and an attacker signs firmware those devices will boot, forever. So the backup has to
survive loss without creating a second attack surface.

Recommended: **two copies, both offline, in two physical locations, both encrypted, plus
one paper copy.**

- Copy 1 and 2: the PEM inside an encrypted container (age, GPG symmetric, or a VeraCrypt
  volume) on two separate removable media, stored apart. The passphrase is memorised or
  held separately from the media - a passphrase stored with the media is not a passphrase.
- Paper copy: `base64 notyas-secureboot-v1.pem` printed, roughly 3.4 KB of text, about two
  pages. Paper survives bit rot and format obsolescence, and it is the copy that is still
  readable in ten years. Store it as you would a seed backup - and note the asymmetry with
  a seed: a seed backup protects funds you own, this protects the update path for hardware
  other people own.
- Record the public-key digest (5.1 step 3) somewhere *not* secret, because you will want
  to compare it against a device's Verify screen later and it is not sensitive.

**Do not** hold the only copy on a hardware token unless you have verified the token can
be used by `espsecure` for signing; `OPEN-QUESTIONS` Q30 deferred the token question for
the GPG key and the same investigation would be needed here separately.

### 5.4 Key rotation, and why there may be no second chance

Secure Boot v2 supports three digest slots, and a burned digest can be revoked
(`SECURE_BOOT_KEY_REVOKE0/1/2`). That sounds like a rotation story. It is a weak one for
this product, for a reason that is settled by a default: ESP-IDF's
`CONFIG_SECURE_BOOT_ALLOW_UNUSED_DIGEST_SLOTS` ("Leave unused digest slots available (not
revoke)") **defaults to n**, and turning it on requires `CONFIG_SECURE_BOOT_INSECURE`. So
under the default configuration, enabling secure boot with one enrolled key **revokes the
other two slots**, and there is no second chance: the enrolled key is the only key that
device will ever accept.

Keeping the spare slots means shipping a build with `CONFIG_SECURE_BOOT_INSECURE=y`, which
also unlocks `ALLOW_JTAG`, `ALLOW_SHORT_APP_PARTITION` and the ECDSA force-enable, and
which is visible in the published sdkconfig as an "insecure options" flag that a reviewer
will reasonably ask about.

`OPEN:` **revoke the unused digest slots, or keep them as a rotation reserve?**
*Recommendation: revoke (accept the IDF default, keep `SECURE_BOOT_INSECURE` off).* The
spare slot is only reachable by an operator who can still burn eFuses, and the same burn
that enables secure boot also closes ROM download mode (section 10) - so in the field the
spare slot is reachable by nobody, including the owner. It is not a rotation path, it is a
slot an attacker with a programmer could fill before the device leaves the box. The real
insurance against key loss is section 5.3's backup, and the real insurance against key
compromise is that the device is not remotely updatable in the first place. **Reject this
recommendation only if you decide the product will ship a documented key-rotation
procedure, in which case the reserve has to be deliberate and the `INSECURE` flag has to
be explained in the release notes.**

---

## 6. Reproducibility: what exactly is the object of the claim

`REPRODUCIBLE.md` 1.1's claim is that a third party rebuilds and byte-compares. A signed
image embeds a signature. This section states precisely how those coexist. It decides what
the release manifest contains, so it is not a detail.

### 6.1 RSA-PSS signatures are not reproducible, and this is settled, not uncertain

Espressif's own format description: the signature block carries the *"RSA-PSS Signature
result (section 8.1.1 of RFC8017) of image content, computed using the following PSS
parameters: SHA256 hash, MGF1 function, salt length 32 bytes."*

`salt_length=32` fixes the salt's *length*, not its *value*. `espsecure`'s implementation,
verified in source at
https://raw.githubusercontent.com/espressif/esptool/master/espsecure/__init__.py :

```python
signature = private_key.sign(
    digest,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
    utils.Prehashed(hashes.SHA256()),
)
```

`pyca/cryptography`'s `PSS` generates 32 fresh CSPRNG bytes of salt per call. **Two signing
runs of the same image, with the same key, on the same machine, produce different bytes.**
There is no deterministic-PSS option for secure boot v2. Do not go looking for one.

### 6.2 Therefore: the unsigned image is the object of the reproducibility claim

**DECISION.** `REPRODUCIBLE.md` 1.1's claim is unchanged and stays scoped to the **unsigned**
`app.bin`, `bootloader.bin` and `partition-table.bin`. Under 0.3.0 those remain the
artifacts a third party rebuilds and byte-compares, and they remain the artifacts a
self-builder flashes to an unburned device.

Signed images are published as **separate, derived artifacts** whose digests appear in
`SHA256SUMS.txt` like everything else, but which are explicitly **not** claimed to be
reproducible and are labelled as such in the release notes. This is Jade's framing and
Espressif's format forces it; the honest phrasing is "the signature is not reproducible;
the thing it signs is".

Proposed naming, extending `REPRODUCIBLE.md` 3.5:

```
notyas-<ver>-<board>-app.bin                  reproducible; the object of the claim
notyas-<ver>-<board>-bootloader.bin           reproducible
notyas-<ver>-<board>-partition-table.bin      reproducible
notyas-<ver>-<board>-app-signed.bin           NOT reproducible; derived from app.bin
notyas-<ver>-<board>-bootloader-signed.bin    NOT reproducible; derived from bootloader.bin
notyas-secureboot-v1-public.pem               the public key, so verification needs no trust
```

**The partition table is not signed.** Secure Boot v2 covers the bootloader and the app;
the partition table is protected only in the sense that the bootloader that reads it is
verified. `VERIFY.md` 2.3's partition-table digest row therefore keeps exactly the value it
has today, which is a point in its favour rather than against it.

### 6.3 How a verifier checks a signed release

Two checks, answering two different questions. Both are needed and neither substitutes for
the other.

```sh
# A. Reproduce the content. Unchanged from REPRODUCIBLE.md 4.1: rebuild in the container,
#    then byte-compare against the UNSIGNED artifacts.
cmp out/notyas-0.3.0-elecrow-5-app.bin published/notyas-0.3.0-elecrow-5-app.bin

# B. Verify the signature over the SIGNED artifact, against the published public key.
espsecure verify-signature --version 2 \
    --keyfile published/notyas-secureboot-v1-public.pem \
    published/notyas-0.3.0-elecrow-5-app-signed.bin

# C. Confirm the signed artifact is the reproduced one, plus padding and a signature.
#    The signed image is the unsigned image, secure-pad-v2 padded up to the 64 KiB flash
#    MMU page boundary, followed by a 4 KiB signature sector. So its leading bytes are the
#    unsigned image byte-for-byte:
head -c $(stat -c%s out/notyas-0.3.0-elecrow-5-app.bin) \
     published/notyas-0.3.0-elecrow-5-app-signed.bin \
  | cmp - out/notyas-0.3.0-elecrow-5-app.bin
```

Check C is the one that closes the loop, and it is the reason both artifacts are published:
without it, "the signed image is the reproducible image plus a signature" is an assertion
rather than something a verifier can test. **Whether check C holds exactly as written is
measurement SB2's job** (section 2.1 P3) - specifically whether `elf2image` regenerates the
image header (flash size, mode, and the appended content digest) when `--secure-pad-v2` is
in play, which would make the signed image's *leading* bytes differ too. If it does, C
becomes a comparison of the reproduced image against the signed image with the header and
the appended digest excluded, and the manifest publishes the excluded ranges. Measure it;
do not assume it.

### 6.4 What the device's own digest becomes, and why SB2 is in 0.2.0

`VERIFY.md` 2.1's `App image` row is `esp_partition_get_sha256()` over the running
partition, which returns the digest of the **image content** stopping before the appended
32 bytes. Under secure boot the image is padded to a 64 KiB boundary and gains a 4 KiB
signature sector, and `esp_image_get_metadata()`'s `image_len` is what decides where the
hash stops. So there are three candidate values - the unsigned image's digest, the padded
image's digest, and the padded-plus-signature digest - and **which one a burned device
shows is not knowable from the documentation.**

This matters beyond secure boot because it decides the shape of
`notyas-<ver>-<board>-VERIFY.json` (ratified Q52), whose field set m12 freezes and which is
covered by the signed `SHA256SUMS.txt`. Publishing a `/1` manifest that has no room for the
signed variant means a `/2` at 0.3.0 and two formats in circulation. Measuring it in 0.2.0
costs one scratch build and one flash of a signed-but-not-secure-boot app to an unburned
board - which burns nothing - and it lets `/1` reserve the fields. That is the whole case
for P3 being in the 0.2.0 slice.

### 6.5 The one-line correction to `REPRODUCIBLE.md`

4.4 item 6 currently lists, among the honest exceptions, *"a secure-boot-signed image
versus an unsigned one (an appended signature block; Jade documents exactly this as their
only expected difference)"*. That understates it in two ways: the difference is a
signature block **plus up to 64 KiB of `--secure-pad-v2` padding**, and, unlike Jade's
framing, the signature block itself is **not** reproducible even by the key holder. The
corrected text is in section 13.1.

---

## 7. The geometry constraint: a signed bootloader does not fit today

This is the finding that changes a plan rather than adding to one, and it is the reason
section 2 accepts measurement SB1.

**The arithmetic.** On ESP32-P4 the second-stage bootloader is at `0x2000` (a P4 special
case; `VERIFY.md` 2.2 has the Kconfig proof) and the region available to it is
`CONFIG_PARTITION_TABLE_OFFSET - 0x2000` = `0x8000 - 0x2000` = **`0x6000`, 24 576 bytes**.

Espressif, on the same page: *"Enabling Secure Boot and/or flash encryption will increase
the size of the bootloader, which might require updating the partition table offset."*
And in the bootloader guide: with Secure Boot V2 enabled there is *"an absolute binary size
limit of 64 KB (0x10000 bytes) (excluding the 4 KB signature)"*, and if the bootloader
outgrows its region you *"Set CONFIG_PARTITION_TABLE_OFFSET to a higher value than 0x8000,
to place the partition table later in the flash"*, subject to the rule that *"no partition
has an offset lower than `CONFIG_PARTITION_TABLE_OFFSET + 0x1000`"*.
https://docs.espressif.com/projects/esp-idf/en/v5.5/esp32p4/api-guides/bootloader.html

Against the numbers this project already has: `VERIFY.md` 3.3's worked example uses a
bootloader of 22 352 bytes (illustrative; m1's V1 commits the measured value). Adding only
the 4 KiB signature sector gives 26 448 bytes, which already exceeds the 24 576 available -
**before** the RSA-3072 verification code the secure-boot bootloader has to carry. The
current geometry has no room for a signed bootloader at all.

**Recommended target for 0.3.0: `CONFIG_PARTITION_TABLE_OFFSET = 0xC000`.** Chosen because
it is the smallest 4 KiB-aligned move that leaves the rest of the frozen Q7 geometry
completely untouched:

```
  before                                  after (0.3.0)
  0x000000 .. 0x002000   key manager      0x000000 .. 0x002000   unchanged
  0x002000 .. 0x008000   bootloader 24K   0x002000 .. 0x00C000   bootloader 40K
  0x008000 .. 0x009000   part. table      0x00C000 .. 0x00D000   part. table
  0x009000 .. 0x010000   gap 28K          0x00D000 .. 0x010000   gap 12K
  0x010000 .. 0xE00000   factory app      unchanged
  0xE00000 .. 0xE40000   wallets          unchanged
  0xE40000 .. 0xE44000   counters         unchanged
```

The app does not move, `wallets` and `counters` do not move, and `partition-table.bin`'s
*content* does not change at all, because the CSV records absolute partition offsets rather
than the table's own location. What changes: `bootloader.bin` (it embeds the offset), the
flashing offsets in `flash.ps1` and the merged-image recipe, `VERIFY.md` 2.3's stated
partition-table offset, and the must-be-blank span map in `VERIFY.md` 3.1. All of that is
regenerated at a burn anyway, which is why section 2.2 rejects doing it in 0.2.0.

**40 KiB of bootloader budget is a projection, not a measurement.** A signed secure-boot
bootloader on comparable targets runs in the high twenties of kilobytes plus the 4 KiB
signature; 40 KiB looks comfortable and is not proven. `0xE000` (48 KiB budget, gap reduced
to the minimum 4 KiB) and `0x10000` (56 KiB budget, but the app must then move to `0x20000`
and every published digest changes) are the fallbacks in order of preference. **SB1
measures the real number and the offset is chosen from it, not from this paragraph.**

One further constraint the app already satisfies: `CONFIG_SECURE_BOOT_ALLOW_SHORT_APP_PARTITION`
exists because a signed app must sit in a partition whose length is 64 KiB aligned. The
frozen 13.94 MiB app partition at `0x10000` is; nothing to do, recorded so it is not
re-derived under pressure.

---

## 8. Anti-rollback: ESP-IDF's feature is unavailable to this device as designed

**`ARCHITECTURE.md` currently states that eFuse anti-rollback "works with the factory-only
layout and ships on release units". That is incorrect and must be corrected in 0.2.0.**

The eFuse itself is real and is exactly as `VERIFY.md` 5.4 describes: `ESP_EFUSE_SECURE_VERSION`,
`EFUSE_BLK0` bit 137, **16 bits**, thermometer-encoded so `esp_efuse_read_secure_version()`
returns a `__builtin_popcount()`. `CONFIG_BOOTLOADER_APP_SEC_VER_SIZE_EFUSE_FIELD` defaults
to 16 on P4 (the Kconfig's own comment: *"32 bits (ESP32), 4 bits (ESP32C2), 16 bits
(others)"*). So the device has **16 increments, for its entire life**, and there is no
mechanism to recover one.

What does not work is the feature that consumes it:

> *"Factory and Test partitions are not supported in anti rollback scheme and hence
> partition table should not have partition with SubType set to `factory` or `test`."*
> https://docs.espressif.com/projects/esp-idf/en/v5.5/esp32p4/api-reference/system/ota.html

`CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK` depends on `CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE`,
and the check it installs lives in the bootloader's **OTA slot-selection** path. notyas has
one `factory` partition, no `otadata`, and no OTA by design (`ARCHITECTURE.md`; `SECURITY.md`
invariant 2). Enabling the option against this table is at best inert and at worst a
misconfiguration that silently does nothing while the Verify screen prints an
`Anti-rollback (efuse)` row that implies enforcement.

There is also no code path that would ever increment the counter: ESP-IDF increments it
from `esp_ota_mark_app_valid_cancel_rollback()`, called after a successful OTA. A device
that never does an OTA never calls it. If the counter is to advance, **the host advances
it, in the burn runbook, with `espefuse burn-efuse SECURE_VERSION <n>`.**

### 8.1 The counter budget, and the mistake to avoid

`secure_version` is **a security counter, not a version number.** Setting
`CONFIG_BOOTLOADER_APP_SECURE_VERSION` to something derived from the release version - 3
for 0.3.0, 20 for 2.0 - would consume the budget immediately and irreversibly. Sixteen
increments is the whole allowance.

**Recommended discipline, if anti-rollback is adopted at all:** ship 0.3.0 with
`secure_version = 0` and burn nothing. Increment **only** when a release fixes a
vulnerability whose re-introduction by downgrade would matter, and increment by exactly
one. At a realistic rate of one security release a year, sixteen is more than a decade. At
one per release it is exhausted in sixteen releases and then the protection silently stops
existing, which is worse than never having claimed it - a device that reports
`Anti-rollback (efuse) 16` and cannot go higher is a device where the row means nothing.

**When it is first incremented:** never at provisioning. The first increment is a
deliberate act in a specific release's runbook, recorded in that release's notes, and it is
the point at which every earlier signed release becomes unbootable on burned devices -
including any release the owner might have wanted to fall back to. That is the protection
working, and it is also a foot-gun; state it in the runbook at the step, not in a footnote.

### 8.2 `OPEN:` does 0.3.0 adopt anti-rollback, and at what geometry cost?

Two options, both requiring a decision taken in the same edit as section 7's offset.

- **(a) No anti-rollback.** Keep `factory`, keep invariant 2 exactly as written, and state
  in `PARITY.md` that the downgrade-protection row is not closed. Cost: an attacker holding
  a burned device can flash any *older, still-validly-signed* notyas release, including one
  with a known bug. Secure boot does not distinguish our old signature from our new one.
- **(b) Adopt it.** Change the app partition's subtype from `factory` to `ota_0` and add an
  8 KiB `otadata` partition in the `0xD000..0xF000` gap that section 7's move creates. The
  bootloader then enforces the eFuse floor. Cost: the partition table's *content* changes
  (so `partition_table_sha256`, the composite `firmware_digest` and the whole published
  manifest change - fine at a minor release, but it means the 0.2.0 and 0.3.0 tables are
  different files), and `SECURITY.md` invariant 2's "no otadata, no data partitions of any
  kind" acquires a named exception. Mitigating detail worth having: an `otadata` that is
  never written stays erased, so `VERIFY.md` 3.3's reserved-space scan covers it and a
  non-blank `otadata` becomes a *finding*. That is a genuinely nice property rather than a
  consolation.

*Recommendation: (b), decided together with section 7 and not before.* Downgrade protection
is a real control against exactly the attacker secure boot leaves standing, it is a
`PARITY.md` row, and the cost is 8 KiB plus an honest amendment to an invariant. Take (a)
only if the invariant-2 exception is judged too expensive for the security text, in which
case say so in `PARITY.md` rather than leaving the row ambiguous. **Neither option is
implementable in 0.2.0** - both change the shipped partition table.

---

## 9. Developing with nothing burned: the traps that would burn something anyway

Both boards - Waveshare 4B on COM3 (32 MB) and Elecrow 5 on COM6 (16 MB), both rev v1.3 -
stay eFuse-virgin for the whole of 0.2.0 and, on this document's recommendation,
permanently. There are exactly two of them, the remaining development depends on flashing
them freely, and there is no third.

**T1 - never flash a bootloader built with `CONFIG_SECURE_BOOT=y`. This is the one that
would actually cost a board.** The burn is not performed by the operator. It is performed
by the bootloader, on the device, on the first boot after a valid partition table and app
have been flashed. `components/bootloader_support/src/esp32p4/secure_boot_secure_features.c`,
`esp_secure_boot_enable_secure_features()`, burns in this order:

```
  ESP_EFUSE_DIS_DIRECT_BOOT                        unconditional
  esp_efuse_enable_rom_secure_download_mode()      if CONFIG_SECURE_ENABLE_SECURE_ROM_DL_MODE
  esp_efuse_disable_rom_download_mode()            if CONFIG_SECURE_DISABLE_ROM_DL_MODE
  ESP_EFUSE_DIS_PAD_JTAG                           unless CONFIG_SECURE_BOOT_ALLOW_JTAG
  ESP_EFUSE_DIS_USB_JTAG                           unless CONFIG_SECURE_BOOT_ALLOW_JTAG
  ESP_EFUSE_SOFT_DIS_JTAG                          unless CONFIG_SECURE_BOOT_ALLOW_JTAG
  ESP_EFUSE_SECURE_BOOT_AGGRESSIVE_REVOKE          if CONFIG_SECURE_BOOT_ENABLE_AGGRESSIVE_KEY_REVOKE
  ESP_EFUSE_SECURE_BOOT_EN                         unconditional
  ESP_EFUSE_WR_DIS_RD_DIS                          unless CONFIG_SECURE_BOOT_V2_ALLOW_EFUSE_RD_DIS
```
https://raw.githubusercontent.com/espressif/esp-idf/v5.5/components/bootloader_support/src/esp32p4/secure_boot_secure_features.c

Espressif's own phrasing confirms the timing: *"Secure Boot will not be enabled until after
a valid partition table and app image have been flashed."* There is no prompt and no
undo. **A build artifact that has never been near a fuse becomes an irreversible burn the
moment it is flashed and the board is powered.** Hence P4's tooling refusal: the flash path
reads the generating sdkconfig and declines. This is also why measurement SB1 is
explicitly a *build* measurement.

**T2 - the safe way to exercise signing is `CONFIG_SECURE_SIGNED_APPS_NO_SECURE_BOOT`.** It
uses the same signature scheme and the same `espsecure` path, and it burns nothing, because
it configures no hardware secure boot. A throwaway key. This is what measurement SB2 runs
on.

**T3 - `CONFIG_EFUSE_VIRTUAL` is the way to exercise eFuse *code* paths without eFuses.**
It backs the eFuse API with a RAM copy (`..._KEEP_IN_FLASH` persists it), so
`espefuse`-shaped logic and the readout surface can be developed and tested. Two hard
limits: it proves nothing about the *hardware* behaviour (the HMAC peripheral reads the
real block, which is all zeros under virtualisation, so an HMAC computed this way is an
HMAC under a zero key), and `VERIFY.md` 5 already requires the release build to assert
`CONFIG_EFUSE_VIRTUAL` is **off**. It is a development instrument, never a shipped
configuration.

**T4 - `CONFIG_BOOTLOADER_EFUSE_SECURE_VERSION_EMULATE` needs an `emul_efuse` partition**
(`emul_efuse, data, efuse, , 0x2000`) and pulls in `EFUSE_VIRTUAL`. It never appears in the
shipped table, and the CI assertion on `partitions.csv` should say so.

**T5 - `--do-not-confirm` never appears in this repository.** `espefuse`'s confirmation
pause is the last thing standing between a typo and a permanent state change; a script that
removes it has removed the only control that exists.

**T6 - flash encryption's Development mode is not a safe dev setting here either.** It burns
`SPI_BOOT_CRYPT_CNT` and permits only a bounded number of further plaintext flashes. Under
this document's constraint it is simply not used; `OPEN-QUESTIONS` Q63's answer for 0.2.0
is (a), burn nothing, and section 2.2 keeps it that way for 0.3.0 development too.

**Abort criteria, for the record even though no burn is planned.** If a burn is ever
contemplated on a board that is still needed for development, the answer is no. There is no
staged version of this: the first three steps of section 11 consume key blocks and are
survivable, and the fourth is a cliff. A board that has completed section 11 step 6 is a
release-configuration board and is no longer a development board, whatever anyone intended.

---

## 10. The full burn sequence, and what each step forecloses

Paper only. This is the order the 0.3.0 runbook implements, worked out from primary sources
rather than inherited.

### 10.1 The sequence

| # | Step | Performed by | Forecloses |
|---|---|---|---|
| 0 | Pre-flight: `espefuse summary`, confirm virgin eFuse, confirm chip revision, confirm the esptool version and command spelling, flash and boot the unsigned image and capture the whole Verify screen | operator | nothing - this is the last unrestricted read of the device |
| 1 | Burn the **esp-seal `HMAC_UP` key** into a key block; then read-protect and write-protect it, and write-protect its `KEY_PURPOSE` | operator, `espefuse` | one of six key blocks; the key value becomes unreadable by everything including JTAG. Does **not** brick (`ESP-SEAL.md` 6.2) |
| 2 | Burn the **XTS-AES flash-encryption key** into a key block; read-protect and write-protect it | operator, `espefuse` | a second key block. Only needed if flash encryption is adopted; see 10.3 |
| 3 | Burn the **secure-boot public-key digest** into a key block with purpose `SECURE_BOOT_DIGEST0`; **write-protect it, do NOT read-protect it** | operator, `espefuse` | a third key block, and fixes which key this device will ever trust. **`SECURE_BOOT_EN` is still 0 at this point - the chip still boots anything.** This is the last recoverable step |
| 4 | Optionally burn `SECURE_VERSION` (only if section 8 adopts anti-rollback, and only if this release warrants it) | operator, `espefuse` | one of sixteen increments, and every older signed release |
| 5 | Flash the signed bootloader, the partition table and the signed app | operator | nothing yet |
| 6 | **Power on.** The bootloader verifies, then burns `DIS_DIRECT_BOOT`, closes ROM download mode, disables all three JTAG paths, sets `SECURE_BOOT_EN`, and sets `WR_DIS_RD_DIS` | **the device, unprompted** | **the cliff.** Unsigned code will never run again. JTAG is gone. ROM download mode is closed or restricted. No eFuse can ever be read-protected again |
| 7 | Flash encryption enable, if adopted: the bootloader's `esp_flash_encrypt_check_and_update()` runs at the same first boot, before secure boot's own burn | the device | in Release mode: writing a usable plaintext image over UART, forever |

### 10.2 Why the order is what it is - and a correction to the reason currently on file

`ESP-SEAL.md` 4.3, `MILESTONES.md` section 3 and `OPEN-QUESTIONS` Q45 all record the
ordering constraint as: *HMAC key before flash encryption and secure boot, because
Release-mode flash encryption disables the UART download path `espefuse.py` uses.* **The
ordering is right. The stated reason is not the operative one and should be corrected**,
because a runbook whose justification is wrong is a runbook people will reorder when the
justification looks inapplicable.

The two operative reasons, in order of force:

1. **`WR_DIS_RD_DIS`.** Step 6 write-disables the read-protection register itself. After
   secure boot is enabled, **no eFuse key block can ever be read-protected again.** So any
   key that must be read-protected - the `HMAC_UP` sealing key, the XTS flash-encryption key
   - must be burned *and* read-protected before step 6. This is categorical and it comes
   straight from `esp_secure_boot_enable_secure_features()`'s last line. It is a much
   stronger constraint than the one currently recorded, and it applies whether or not flash
   encryption is ever adopted.
2. **Download mode closes at step 6, not at flash encryption.** `espefuse` reaches the chip
   through the ROM downloader. What closes that path is `DIS_DOWNLOAD_MODE` or
   `ENABLE_SECURITY_DOWNLOAD`, burned by the **secure-boot** bootloader according to
   `CONFIG_SECURE_DISABLE_ROM_DL_MODE` / `CONFIG_SECURE_ENABLE_SECURE_ROM_DL_MODE`. Flash
   encryption's Release mode burns `DIS_DOWNLOAD_MANUAL_ENCRYPT`, which stops the downloader
   *encrypting what it writes* - so a plaintext image written over UART lands as garbage
   that will not decrypt - but that is a different eFuse and a different mechanism.
   Espressif's flash-encryption page says only that `DIS_DOWNLOAD_MANUAL_ENCRYPT` *"disables
   flash encryption operation when running in UART bootloader boot mode"*, and does not
   claim it disables the downloader. **Do not assert in the runbook that flash encryption
   alone shuts `espefuse` out; assert that step 6 does.**

Both point the same way, so nothing about the sequence changes. Only the sentence changes,
and the corrected sentence is stronger.

**One pre-flight item that must be verified before step 7 is ever executed.** IDF's
flash-encryption first boot will *generate* an XTS key on-chip if none is present. notyas
cannot accept that: `SECURITY.md` invariant 3 distrusts the P4 TRNG, and
`ESP-SEAL.md` 4.3's whole argument is that device-unique key material comes from the host
CSPRNG. So step 2 pre-burns the key and step 7 must be confirmed to *use* the pre-burned key
rather than generate a new one. That is a behaviour of `esp_flash_encrypt_init()` that this
document has **not** verified against source; it is listed in section 12 as an unverified
claim and it is a blocking pre-flight check, not a runbook footnote.

### 10.3 A note on flash encryption's mode

`OPEN-QUESTIONS` Q63 asked what mode release units burn, in a world where secure boot was
deferred, and recommended (a) burn nothing. With secure boot present the calculus changes:
AR2026-006's own defence-in-depth recommendation is *flash encryption in Release mode
alongside secure boot, combined with secure or disabled UART download mode*, because it
forces an attacker to break XTS-AES before a flash modification is worth anything. That is
the right configuration for a release unit and it is also the configuration in which the
device has **no firmware update path at all** (there is no OTA by design). Q63(c)'s
disqualifying objection - "a signer with no update path is a signer that cannot ship a
security fix" - is unchanged and is not resolved by this document. **Q63 must be re-answered
for 0.3.0 in light of secure boot being present; the 0.2.0 answer (a) stands and is
untouched.**

---

## 11. The burn runbook

> **THIS RUNBOOK HAS NEVER BEEN EXECUTED.** No step below has been performed on any device
> by this project. It is written from primary sources and reasoning, not from experience.
> Section 12 lists what is therefore unverified. Read it, and section 10.2's pre-flight
> item, before the first execution. Assume the reader has one board and one chance.

**Before anything.** Print this section. Have the Verify screen readout from step 0 on
paper beside you. Do not run these steps from a script. Do not run them while tired.

### Step 0 - pre-flight, no burns

```sh
# 0a. Confirm the tool and its command spelling. esptool v4.x uses underscores
#     (burn_key), v5.x uses hyphens (burn-key). Every command below is written in the
#     v5.x form. Check which you have and translate once, in writing, before starting.
espefuse version

# 0b. Read the chip. Save this output to a file and keep it.
espefuse -p COM<n> summary > preburn-summary.txt

#     Confirm, by eye: SECURE_BOOT_EN = 0; SPI_BOOT_CRYPT_CNT = 0; every BLOCK_KEY0..5
#     unused with KEY_PURPOSE USER; SECURE_VERSION = 0; no RD_DIS or WR_DIS bits set that
#     you did not expect; the chip revision is the one you think it is.

# 0c. Check for existing eFuse coding-scheme errors before adding to them.
espefuse -p COM<n> check-error

# 0d. Flash the exact unsigned release image you intend to sign, boot it, and photograph
#     or transcribe the ENTIRE Verify screen. This is the last time you can read this
#     device with the door open, and the values are the baseline you will compare the
#     post-burn readout against.
```

**Failure modes at step 0.** A non-zero `SPI_BOOT_CRYPT_CNT` or any burned key block means
this is not a virgin device - stop and find out why. `check-error` reporting a coding-scheme
failure means the block is already damaged; do not burn into it.

### Step 1 - the esp-seal HMAC key

Per `ESP-SEAL.md` 4.3 P1-P4. Key from the host OS CSPRNG, 32 bytes, never escrowed.

```sh
# P1: on the host, not on the device.
head -c 32 /dev/urandom > hmac-key.bin        # or the platform equivalent

# P2: burn into an unused block with purpose HMAC_UP (purpose value 8).
espefuse -p COM<n> burn-key BLOCK_KEY0 hmac-key.bin HMAC_UP

# Verify before proceeding.
espefuse -p COM<n> summary | grep -A2 BLOCK_KEY0

# P3: read-protect and write-protect. THIS IS THE POINT OF NO RETURN FOR THIS KEY.
espefuse -p COM<n> read-protect-efuse BLOCK_KEY0
espefuse -p COM<n> write-protect-efuse BLOCK_KEY0
espefuse -p COM<n> write-protect-efuse KEY_PURPOSE_0

# P4: shred the key file. There is no escrow, by design.
shred -u hmac-key.bin
```

**Verify after:** `espefuse summary` shows `BLOCK_KEY0` with purpose `HMAC_UP`, `RD_DIS`
set, `WR_DIS` set. Boot the firmware and confirm the Verify screen's key-block table shows
`KEY0  HMAC_UP  RD_DIS WR`, and that `SealStore::key_provenance()` reports
`EfuseReadProtected`.

**Failure modes.** A power cut between P2 and P3 leaves a burned but software-readable key:
the next boot reports `KeyProvenance::EfuseReadable`, the product refuses to format, and
you re-run P3. A cut during P2 leaves a partially burned block that `espefuse` detects on
re-read; that block is dead, move to `BLOCK_KEY1` and record which blocks are consumed.

### Step 2 - the XTS-AES flash-encryption key

**Only if flash encryption is adopted (section 10.3 / Q63 re-answered).** Same shape as
step 1, key purpose `XTS_AES_128_KEY`, into `BLOCK_KEY1`, read-protected and write-protected.

**Do not skip the pre-flight item in section 10.2:** confirm that the bootloader's
first-boot flash-encryption path uses this pre-burned key rather than generating one.

### Step 3 - the secure-boot key digest

```sh
# The digest, computed on the machine that holds the private key.
espsecure digest-sbv2-public-key --keyfile notyas-secureboot-v1.pem \
    --output sb-digest.bin

# Burn it. Note the purpose name and note that this block is WRITE-protected but NOT
# read-protected - Espressif: "The key(s) must be readable in order to give software
# access to it ... The write-protection bit must be set, but the read-protection bit
# must not."
espefuse -p COM<n> burn-key BLOCK_KEY2 sb-digest.bin SECURE_BOOT_DIGEST0
```

**Verify after, and this is the most important verification in the whole runbook:** boot
the firmware - the device still boots anything, because `SECURE_BOOT_EN` is still 0 - and
read `Key digest 0` off the Verify screen. **Compare all 64 hex characters against
`sha256sum sb-digest.bin`.** If they do not match, stop: you are one step away from
enrolling a key you do not hold. This is the entire reason `VERIFY.md` prints the digest
value rather than a yes/no, and it is the reason step 3 is separated from step 6.

**Failure modes.** A mistyped block name burns a digest into a block you meant for
something else - survivable, three spares remain, but record it. A wrong *file* burns a
digest for a key you do not have - survivable **only** because `SECURE_BOOT_EN` is still 0;
burn the correct digest into `SECURE_BOOT_DIGEST1` and note that both are now enrolled and
the wrong one must be revoked before step 6.

### Step 4 - anti-rollback, if adopted

```sh
espefuse -p COM<n> burn-efuse SECURE_VERSION 1
```

Only when section 8's decision is (b), only when this release warrants an increment, and
only with the number written into the release notes. **One of sixteen, forever.** Every
previously signed release becomes unbootable on this device at this moment.

### Step 5 - flash the signed images

```sh
idf.py bootloader                                  # produces the signed bootloader
# Flash the bootloader explicitly. CONFIG_SECURE_BOOT_FLASH_BOOTLOADER_DEFAULT defaults
# to n precisely so this is a deliberate act; leave it at n.
esptool -p COM<n> --chip esp32p4 write-flash 0x2000  build/bootloader/bootloader.bin
esptool -p COM<n> --chip esp32p4 write-flash 0xC000  partition-table.bin
esptool -p COM<n> --chip esp32p4 write-flash 0x10000 app-signed.bin
```

Note the partition-table offset is section 7's, not `0x8000`. **Nothing has burned yet.**
Power is still off, or the board has not been reset. This is the last moment to stop.

### Step 6 - power on. The device burns.

There is no command. Reset or power-cycle the board and the bootloader does everything in
section 9's list. Espressif: *"If the ESP32-P4 is reset or powered down during the first
boot, it will start the process again on the next boot."*

**Verify after:** the device boots to the notyas UI. The Verify screen reads
`Secure boot  enabled`, `Key digest 0` matches the value recorded at step 3, digests 1 and
2 read `revoked` (default configuration, section 5.4), `JTAG (pad)`, `JTAG (USB)` and
`JTAG (soft)` all read disabled, `Direct boot` disabled, and `UART download` or
`Secure download` reflects whichever `CONFIG_SECURE_*_ROM_DL_MODE` was built in. Compare
the whole screen against step 0d's baseline, field by field.

**Failure mode, and it is total.** If the device does not boot after step 6, it will not
boot again. The signature did not verify, or the bootloader was built for the wrong chip
revision family (`firmware/README.md` records that a wrong-revision bootloader flashes
cleanly and then boot-loops printing only the ROM banner - and that failure is
indistinguishable from a signature failure once download mode is closed). This is why step
0d flashes and boots the *unsigned* image first: it proves the revision configuration is
right before the signature is the only variable left.

### Step 7 - flash encryption, if adopted

Runs as part of the same first boot. **Verify after:** the Verify screen's
`Flash encryption` row reads enabled, `Mode` reads `RELEASE` (or `DEVELOPMENT`), `Crypt
count` shows the expected popcount, and the XTS key block shows `RD_DIS`. Per
`VERIFY.md` 5.2, P4's release-mode determination is: encryption enabled AND
(`WR_DIS_SPI_BOOT_CRYPT_CNT` set OR the count maxed to `0b111`) AND
`DIS_DOWNLOAD_MANUAL_ENCRYPT` AND `SPI_DOWNLOAD_MSPI_DIS` - and the four fields the generic
documentation lists (`DIS_DOWNLOAD_ICACHE`, `DIS_DOWNLOAD_DCACHE`, `HARD_DIS_JTAG`,
`DIS_LEGACY_SPI_BOOT`) **do not exist on ESP32-P4** and must not be looked for.

---

## 12. What is unverified-on-hardware, and what the first burn therefore risks

Because nothing was ever burned, the following are reasoned rather than observed. This list
is the honest cost of the no-burn constraint and it is also the pre-flight checklist for
whoever executes section 11 first.

| # | Claim | Status | What a wrong guess costs |
|---|---|---|---|
| U1 | The whole of section 11 | never executed | the board |
| U2 | The signed bootloader fits in the chosen region | unmeasured until SB1; the *current* region provably does not fit | a bootloader that cannot be flashed, discovered after key blocks are spent |
| U3 | `esp_flash_encrypt_init()` uses a pre-burned XTS key rather than generating one on-chip | **not verified against source** - blocking pre-flight item (10.2) | a TRNG-generated key on a device whose whole design distrusts the TRNG, unrecoverable |
| U4 | `esp_partition_get_sha256()`'s value on a signed image | unmeasured until SB2 | a published manifest whose app digest does not match any burned device |
| U5 | Whether `espefuse` still functions after step 6 under `CONFIG_SECURE_ENABLE_SECURE_ROM_DL_MODE` | unverified; Espressif's docs describe secure download mode's command whitelist but do not enumerate `espefuse`'s fate | a runbook step 4 that cannot be performed later, if anti-rollback increments are deferred to a future release |
| U6 | `esp_efuse_read_block()` on a read-protected block returns zeros | `VERIFY.md` 5.1 already flags this as TRM-level and undocumented | the Verify screen printing 32 zero bytes as if they were a digest |
| U7 | Exact `espefuse`/`espsecure` command spelling for the esptool version IDF v5.5 actually pins | unresolved: upstream esptool is v5.x (hyphens) but IDF v5.5's constraints file was not located | a failed command, harmless, but it wastes the operator's attention at the worst moment |
| U8 | The eFuse symbol set, for post-v3 silicon | standing requirement already recorded in `VERIFY.md` 1 and 5 (`OPEN-QUESTIONS` Q9) | reading the wrong bits on production hardware |
| U9 | The `HMAC_UP` read-protection behaviour on real silicon | m3h's exit gate requires a burn and therefore cannot be met - section 13.3 | the sealing layer's core assumption is untested on hardware |

**The first real burn therefore risks:** the board, and only the board - there is no
scenario in which it risks a wallet, because a device that fails a burn holds nothing. That
is the one comfortable thing about deferring this. The mitigation is to execute section 11
first on a unit the project can afford to lose, and this document's position is that **that
unit is not one of the two dev boards**; it is a third board, bought for the purpose, before
0.3.0's runbook is executed on anything else. That is the cost of the no-burn constraint,
stated as a purchase rather than hidden as a risk.

---

## 13. Consequences elsewhere, and milestone impact

### 13.1 Text corrections owed by 0.2.0 (documents this file does not own)

1. **`ARCHITECTURE.md`**, the no-OTA paragraph: *"eFuse anti-rollback (secure_version) works
   with the factory-only layout and ships on release units"* is false. Replace with:
   *"ESP-IDF's app anti-rollback requires an ota_0/ota_1 partition table and explicitly does
   not support a `factory` subtype, so it is unavailable under the current layout; see
   SECUREBOOT.md section 8."*
2. **`ESP-SEAL.md` 4.3, `MILESTONES.md` section 3, `OPEN-QUESTIONS` Q45 item 4**: the burn
   ordering rationale. Replace *"because Release-mode flash encryption disables the UART
   download path espefuse.py uses"* with *"because enabling Secure Boot v2 burns
   `WR_DIS_RD_DIS`, after which no eFuse key block can ever be read-protected, and because
   the same first boot closes ROM download mode"*. The ordering is unchanged.
3. **`REPRODUCIBLE.md` 4.4 item 6**: *"a secure-boot-signed image versus an unsigned one (an
   appended signature block)"* becomes *"a secure-boot-signed image versus an unsigned one:
   `--secure-pad-v2` padding up to the 64 KiB flash MMU page boundary plus a 4 KiB signature
   sector, and the signature itself is not reproducible even by the key holder (RSA-PSS uses
   a fresh 32-byte random salt per signing) - see SECUREBOOT.md section 6"*.
4. **`REPRODUCIBLE.md` 5.2 / `OPEN-QUESTIONS` Q32**: the key-ownership question moves to
   0.3.0 with the reframing in section 14 rather than staying as written.
5. **`VERIFY.md` 9.4** - the documentation paragraph, not the on-device line. Its last
   sentence promises an anchor that no 0.2.0 device has. Append: *"No notyas 0.2.0 device has
   Secure Boot burned. On 0.2.0, the row always reads `disabled`, and the paragraph above is
   the whole of the guarantee."* The on-device string is unchanged. The design contract is
   unchanged. Nothing else in `VERIFY.md` needs editing for this document - confirmed field
   by field against sections 5.1, 5.4, 10.4 and 14's secure-boot `OPEN:`.

### 13.2 Milestone deltas

**m1 (foundations, frozen geometry).** Two new measurements, both build-only or
burn-free, both cheap:
- **SB1** - build a secure-boot-enabled bootloader against a throwaway key and record its
  signed size. **Never flashed.** Feeds section 7's offset choice.
- **SB2** - build a `CONFIG_SECURE_SIGNED_APPS_NO_SECURE_BOOT` app against a throwaway key,
  flash it to an unburned board, and record the signed image length, the
  `esp_image_get_metadata()` `image_len`, and whether the Verify screen's `App image` digest
  changes. Feeds section 6.4 and the `VERIFY.json` field set that m12 freezes.
- One decision to record, not to implement: the target `CONFIG_PARTITION_TABLE_OFFSET` for
  0.3.0, and the note that the *current* geometry cannot hold a signed bootloader.
- One correction to fold in: `ARCHITECTURE.md`'s anti-rollback claim (13.1 item 1).

**m3h (esp-idf-hmac / the eFuse readout surface).** No new scope - the readout surface
`VERIFY.md` 5 needs is already m3h's, and it works unburned. **But its hardware exit gate is
now unmeetable as written.** It requires burning a key into a block, computing an HMAC,
read-protecting the block, and re-computing. With no burns permitted, the achievable gate
is: the readout surface returns correct values on both boards for the *unburned* state
(every block `<unused>`, `SECURE_BOOT_EN` 0, three digests `not burned`), and the
`esp_hmac_calculate()` path is exercised under `CONFIG_EFUSE_VIRTUAL` against published
vectors. **The read-protection behaviour - the property the whole sealing model rests on -
becomes unverified-on-hardware (U9).** That is a real reduction in what m3h proves and the
milestone text must say so rather than quietly narrowing the gate.

**m4a (storage on hardware).** Follows from m3h. With no `HMAC_UP` key burned on either
board, all of m3 and m4a develop under `KeyProvenance::Emulated`. Section 13.4 confirms the
fence is sufficient for that, and names the consequence the milestone gate must not assume
away.

**m12 (reproducible builds).** No signing step. Two additions, both from section 6:
`VERIFY.json`'s field set reserves room for signed-artifact digests (or the format tag is
accepted as the versioning mechanism and `/2` is planned), and the artifact naming for
signed images is fixed now so 0.3.0 does not have to rename anything. m12's exit gate is
unchanged.

**m13 (hardening closeout and release).** Loses its release-unit burn runbook entirely.
`MILESTONES.md` m13 currently scopes *"Release-unit runbook: eFuse HMAC-key provisioning,
XTS-AES flash encryption, Secure Boot v2 RSA-3072 (never ECDSA - AR2026-006), anti-rollback,
in a fixed order of burns with a dry run on a sacrificial unit."* Under this document that
becomes: **the runbook is written and published as SECUREBOOT.md section 11, is labelled
never-executed, and no burn is performed.** m13's exit-gate line *"a release unit completes
the burn runbook and still passes every gate"* is struck. What m13 gains instead: the
release documentation statement in section 1, the `VERIFY.md` 9.4 amendment, and the
`PARITY.md` rows that must now be re-classified (see below).

**New: 0.3.0-m14 (or whatever 0.3.0 numbers it) - secure boot activation.** Scope: the
owner's key ceremony (section 5); the geometry decision (sections 7 and 8, taken together,
once); the sdkconfig set; the signing step in the release pipeline; the signed artifact set
(section 6.2); the first execution of section 11 on a purpose-bought sacrificial board;
`VERIFY.json` `/2`; and only then a release unit. Depends on: a third board, and the Q63
re-answer.

**`PARITY.md` rows affected at m13.** "Firmware upgrade, factory-signed only" and
"Downgrade protection" were both scheduled to close at m13 on the strength of secure boot
and anti-rollback. Neither closes in 0.2.0. The honest classification is the one
`PARITY.md` already uses for this situation: the notyas answer is reproducible builds plus
user-flashable firmware, labelled as software attestation, with the hardware anchor named
as a 0.3.0 item.

### 13.3 The storage consequence that is not obvious

The emulated-key fence is **sufficient for development** and it is not sufficient as a
*shipping* answer, and those are two different questions that must not be run together.

**Sufficient for development: yes, confirmed.** `ESP-SEAL.md` 6.4 fences
`KeyProvenance::Emulated` five ways, and the load-bearing one is the third: the provenance
byte is inside the AEAD's associated data and the header carries an `EMULATED_KEY` flag, so
a record sealed in emulated mode **cannot** be opened in production mode or vice versa -
"not should not, cannot". Every derivation in the ladder is domain-separated by provenance.
So all of m3 (host) and m4a (hardware) can be built, tested and gated with nothing burned,
and a dev-mode wallet can never be mistaken for a real one. The fence does its job.

**Not sufficient as a shipping answer, and this needs an owner decision.** The notyas
release build passes `accept_provenance = &[KeyProvenance::EfuseReadProtected]`
(`ESP-SEAL.md` 6.4 item 4), and `ESP-SEAL.md` 4.3's ratified Q45 makes HMAC provisioning a
host step. So **a 0.2.0 release image running on a device with no `HMAC_UP` key burned will
refuse to format and will store nothing.** With no burn anywhere, either:

- **(i)** the user runs the one-line `espefuse` provisioning step on their own device before
  first use - a burn, but on their hardware, by them, which is exactly what Q45 already
  designed and is consistent with "no burn on *my* dev boards"; or
- **(ii)** `accept_provenance` widens for 0.2.0 to admit a non-eFuse mode, which removes the
  device binding from the sealing ladder and guts the storage security story.

`OPEN:` **which of those is 0.2.0's answer.** *Recommendation: (i).* The owner's constraint
is about this project's two irreplaceable dev boards, not about what a user does to their
own device, and (ii) trades away the property the entire sealing design exists to provide.
(i) costs one documented command in `VERIFYING.md` and the setup flow, and it means the
0.2.0 release genuinely cannot store a wallet until the user has provisioned - which the
Verify screen already reports truthfully as `not provisioned`. **This is a `SECURITY.md` /
`ESP-SEAL.md` / `MILESTONES.md` decision, not this document's; it is raised here because the
no-burn constraint is what surfaced it.**

### 13.4 Burning later is a fresh start, not an upgrade, and there is no migration path

State this where a user will read it before they can lose anything by not knowing it.

A device that is later burned **begins empty**. Records sealed under
`KeyProvenance::Emulated` carry the emulated-key flag inside the AEAD's associated data;
once a real `HMAC_UP` key exists, those records cannot be opened, by design and not by
accident. The same is true in reverse. This is a feature - it is what prevents a dev-mode
wallet from being mistaken for a real one - and it means there is no in-place upgrade from a
pre-burn device to a burned one.

**And there is no migration path, at all, for anything except the seed.**
`OPEN-QUESTIONS` Q14 deferred encrypted backups whole to 0.3.0, and states the cost in its
own words: *"Multisig registrations, labels and device settings are the only state a
mnemonic cannot re-derive, and with no backup there is no recovery path for them at all."*
So a user who sets up a 0.2.0 device and later burns it must re-enter their mnemonic, and
their multisig registrations, labels and settings are gone permanently.

**This is a known limitation and it must be stated, not left implicit.** It belongs in the
same places Q14's ratification already requires the wipe surfaces to name what is lost -
`VERIFYING.md`, the release notes, and the setup flow - with one sentence: *"If you later
enable Secure Boot or provision this device's storage key, the device starts empty. Your
seed phrase restores your wallets; your multisig registrations, labels and settings are not
recoverable."*

---

## 14. Open decisions

Each is a genuine owner decision with a recommendation. Greppable for the reconciliation
pass that folds them into `OPEN-QUESTIONS.md`.

`OPEN:` **Whose secure-boot key is burned - the former Q32, reframed.** The world it was
written for no longer exists: there is no factory, there is no burn during development, and
the burn now happens later, by whoever flashes the device, without anyone looking over their
shoulder. The three options, restated for that world:

- **(a) Project key only.** The project's release-key digest is burned, so only official
  notyas releases run. On a device with no factory this means the *user* burns *our* key, and
  from that moment they cannot run firmware they built themselves - on a GPL-3.0 device whose
  entire pitch is "verify it yourself, build it yourself". It is also the option that makes
  the owner's private key a single point of failure for every device in the field: lose it
  and nobody can ever update; leak it and everybody's device will boot the attacker's build.
- **(b) User key.** The user generates their own RSA-3072 key and burns their own digest,
  signing the builds they flash - whether those are their own builds or our published
  unsigned artifacts signed by them. The device then trusts exactly one key: the user's. Our
  key never touches their hardware, our key's compromise cannot reach them, and a
  self-builder is not locked out because they are the signer. The cost is a real one-way
  ceremony performed by a person who may only do it once.
- **(c) Both, as separate channels.** Two digests enrolled, or two download channels. On one
  device, enrolling both means the device runs either the project's builds or the user's -
  which is strictly *weaker* than either alone, because it doubles the number of keys whose
  compromise runs code on that device, and it makes "whose secure boot?" unanswerable by
  looking at one digest. As two separate *channels* (a signed release for people who want
  ours, an unsigned release for people who burn their own) it is coherent, and it costs one
  extra artifact set.

**Recommendation: (b) as the default and the documented path, with (c)-as-channels
available - publish both the unsigned artifacts and a project-signed set - and (a) only if
assembled units are ever sold.** Reasoning: notyas has no factory, so (a) requires the user
to burn our key anyway, at which point the only thing (a) buys over (b) is that we control
what runs on their device, which is precisely what this product declines to do. (b) also
puts the key-loss consequence in the hands of the person who bears it. Burning two digests on
one device (c-as-enrolment) is the footgun and is **not** recommended: it is more keys, not
more choice.

**What each choice means for someone who wants to build from source later.** Under (b),
everything: they hold the key, they sign, they flash. Under (a), nothing - once our digest
is burned and the unused slots are revoked, their own build will not boot, ever, on that
device. Under (c)-as-channels, whichever they chose at burn time is what they have; the
choice is one-way and must be presented as such at the moment it is made.

`OPEN:` **Revoke unused digest slots, or keep them as a rotation reserve.** Section 5.4.
*Recommendation: revoke (the IDF default, `SECURE_BOOT_INSECURE` off).*

`OPEN:` **Does 0.3.0 adopt anti-rollback, and accept the `otadata` partition it requires.**
Section 8.2. *Recommendation: yes (option b), decided in the same edit as the partition-table
offset.*

`OPEN:` **`CONFIG_PARTITION_TABLE_OFFSET` for 0.3.0.** Section 7. *Recommendation: `0xC000`
if measurement SB1 shows the signed bootloader fits in 40 KiB; `0xE000` if it needs more;
`0x10000` only as a last resort, because it moves the app and changes every published
digest.*

`OPEN:` **How a 0.2.0 release image stores anything on an unprovisioned device.** Section
13.3. *Recommendation: (i), the user runs the documented one-line `espefuse` HMAC
provisioning on their own hardware.* This is `ESP-SEAL.md`'s and `SECURITY.md`'s to own; it
is raised here because the no-burn constraint surfaced it.

`OPEN:` **Q63 re-answered for 0.3.0.** Section 10.3. Flash-encryption mode in a world where
secure boot *is* present. The 0.2.0 answer (a) stands untouched; 0.3.0's answer has to
resolve the conflict between AR2026-006's defence-in-depth recommendation and
`ARCHITECTURE.md`'s "an airgapped signer updates by USB reflash".

`OPEN:` **A third board, bought before the first execution of section 11.** Section 12.
*Recommendation: yes.* The runbook has never been run and its first run is the one most
likely to go wrong; running it on either of the two irreplaceable dev boards spends a
development resource to learn something a cheap board can teach.

---

## Sources

Espressif, ESP-IDF v5.5, ESP32-P4:
- https://docs.espressif.com/projects/esp-idf/en/v5.5/esp32p4/security/secure-boot-v2.html
- https://docs.espressif.com/projects/esp-idf/en/v5.5/esp32p4/security/flash-encryption.html
- https://docs.espressif.com/projects/esp-idf/en/v5.5/esp32p4/security/security.html
- https://docs.espressif.com/projects/esp-idf/en/v5.5/esp32p4/api-guides/bootloader.html
- https://docs.espressif.com/projects/esp-idf/en/v5.5/esp32p4/api-guides/startup.html
- https://docs.espressif.com/projects/esp-idf/en/v5.5/esp32p4/api-reference/system/ota.html
- https://docs.espressif.com/projects/esp-idf/en/v5.5/esp32p4/api-reference/system/efuse.html
- https://raw.githubusercontent.com/espressif/esp-idf/v5.5/components/bootloader/Kconfig.projbuild
- https://raw.githubusercontent.com/espressif/esp-idf/v5.5/components/bootloader/Kconfig.app_rollback
- https://raw.githubusercontent.com/espressif/esp-idf/v5.5/components/bootloader_support/src/esp32p4/secure_boot_secure_features.c

Espressif advisories:
- https://www.espressif.com/en/support/documents/advisories
- https://documentation.espressif.com/AR2026-006_Security_Advisory_Concerning_ECDSA_Secure_Boot_Issue_in_ESP32-H2_ESP32-C5_ESP32-C61_ESP32-P4_ESP32-S31_EN.pdf

esptool / espsecure / espefuse:
- https://docs.espressif.com/projects/esptool/en/latest/esp32p4/espefuse/index.html
- https://docs.espressif.com/projects/esptool/en/latest/esp32p4/espsecure/index.html
- https://raw.githubusercontent.com/espressif/esptool/master/espsecure/__init__.py

In-repo, consulted and not edited: `docs/plan-0.2.0/{VERIFY,REPRODUCIBLE,ESP-SEAL,SECURITY,
ARCHITECTURE,MILESTONES,OPEN-QUESTIONS,BACKUP-FEATURES,PARITY}.md`, `docs/HARDWARE.md`,
`docs/BOARDS.md`, `firmware/sdkconfig.base.defaults`, `firmware/partitions.csv`.

Input to: `MILESTONES.md` (section 13.2), `OPEN-QUESTIONS.md` (section 14),
`REPRODUCIBLE.md` (sections 6 and 13.1), `ARCHITECTURE.md` and `ESP-SEAL.md` (section 13.1).
