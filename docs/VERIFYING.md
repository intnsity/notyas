# Verifying a notyas release

notyas is an airgapped Bitcoin signer. It holds key material, so you should not have to
take anybody's word for what is running on it. This document is how you check, end to
end, starting from nothing: a release page, a terminal, and a machine with Docker.

It assumes you have never seen this repository. Everything it needs is either published
on the release page or named here by path.

Source: https://github.com/intnsity/notyas (GPL-3.0-or-later).

---

## 1. Read this before you start: what verification is worth today

**Every notyas release so far ships without Secure Boot v2 and without flash encryption.
That is a deliberate scope decision, and it has one consequence you must understand before
you rely on anything the device tells you about itself:**

> The Verify screen reports what the RUNNING FIRMWARE says about itself.
> If you did not build that firmware yourself from a reproduced image and flash it
> yourself, the screen cannot prove it is the firmware you think it is.

That is not a caveat at the bottom of a page. It is the reason this document is
organised the way it is. The device cannot vouch for itself in this release, so the
chain of trust has to be closed on your own machine: reproduce the published image from
published source, satisfy yourself that the image you flash is that image, and flash it
yourself. Everything after that point is comparison, and a comparison is worth exactly
what the value being compared against is worth.

Secure Boot v2 is planned for 0.3.0. With it burned, the chip's boot ROM - mask silicon,
not this project's code - checks a signature before the bootloader runs, and the
bootloader checks one before the app runs, so modified firmware does not execute and
there is nothing left to print a reassuring screen. That link does not exist in any
release published so far, and no amount of software can substitute for it.

### Which releases have anything to check

**0.2.3 is the first notyas release for which a build artifact was ever produced.** The
release container failed at step 5 of 7 on every attempt before it, on GitHub Actions and on
every local host, so `v0.2.0` and `v0.2.2` are tags over gated firmware that was never
packaged: their release pages carry no `app.bin`, no `SHA256SUMS.txt` and no signature over
one. Until 0.2.3 this document was accurate about the intent and unusable in fact, because
the container it tells you to build in step 4 could not be built by anybody.

So if you are holding an earlier tag, there is nothing on its page to check and no procedure
here can be run against it. 0.2.3 is `v0.2.2`'s firmware with a version string that says so,
and it is the version to take. `docs/RELEASE-0.2.3.md` sections 0, 1 and 4 are the account,
and `docs/KNOWN-ISSUES.md` K34 is the defect entry. Every command below is written out with
`0.2.3` for that reason.

### What each step actually answers

| Step | Time | The question it answers |
| --- | --- | --- |
| 2. Check the hashes | 2 min | Is the file I downloaded the file that was published? |
| 3. Check the signature | 10 min | Did the notyas maintainer publish that list of hashes? |
| 4. Rebuild it yourself | 30-90 min, mostly waiting | Is the published binary what the published source compiles to? |
| 5. Flash what you built | 10 min | Is the firmware on this chip the firmware I just checked? |
| 6. Provision the device | 5 min, irreversible | Can this board store wallets at all? |
| 7. Compare the device | 5 min | Do the device's own numbers agree with the release? |

None of these say the source code is safe or correct, and none of them is a security
audit; no independent audit of this code has been performed and none is claimed. What
they buy is the thing that makes reading the source worth anything: without them, "open
source" describes a repository with no provable connection to the binary holding your
keys.

A signature alone is not enough, which is why step 4 exists. A signature says "the
maintainer produced this file", and that includes a maintainer whose build machine has
been quietly compromised. Reproducibility is what lets other people rebuild and
disagree.

### Three limits of this release, stated plainly

1. **No Secure Boot v2, no flash encryption.** Covered above. It is the reason step 5 is
   not optional if you want step 7 to mean anything.
2. **The release signing key lives on a general-purpose computer**, not on a hardware
   token. A signature over `SHA256SUMS.txt` is exactly as good as that machine is, and
   that bounds what step 3 can be worth to you.
3. **The reproducibility claim currently carries no third-party attestation.** The
   recipe, the pinned toolchain and a double-build check are all in this repository, and
   the release process refuses to sign a build it has not reproduced first. What that
   cannot supply is independence: the reproducing machines are the maintainer's, and the
   release notes for your version state whether a second machine matched for that tag.
   Nobody outside the project has yet published their own signed hash list. If you run
   step 4, publishing your result is the single most useful thing you can do for every
   other user of this device, and it is welcome whether it matches or not.

---

## 2. What to install

Very little for steps 2 and 3, and Docker for step 4.

| For | Tool | Where it comes from |
| --- | --- | --- |
| steps 2-3 | `sha256sum`, or `shasum`, or `Get-FileHash` | already present on Linux, macOS and Windows |
| step 3 | GnuPG | `apt install gnupg`, `brew install gnupg`, or Gpg4win |
| step 3 | git | `apt install git`, `brew install git`, or git-scm.com |
| step 4 | Docker, on an x86-64 Linux host, with about 20 GB free | docs.docker.com |
| steps 5-6 | esptool 5.x | `pip install esptool` |
| step 7 | Python 3.6 or newer | already present on Linux and macOS |
| step 4, optional | `riscv32-esp-elf-nm` | ships with ESP-IDF; also inside the release container |

Steps 2 and 3 work anywhere. Step 4 wants x86-64 Linux: the release container is an
x86-64 image, and while it will run under emulation elsewhere, a build that takes five
times as long through a different emulation layer is not the build anybody else ran.
Steps 5 and 6 need a USB cable to the board.

One wrinkle on current Linux distributions: `pip install esptool` into the system Python
is refused there with `error: externally-managed-environment`, which is the distribution
protecting its own packages rather than anything to do with this project. Use `pipx
install esptool`, or a virtual environment:

```sh
python3 -m venv ~/.venv/esptool && ~/.venv/esptool/bin/pip install esptool
~/.venv/esptool/bin/esptool version
```

The verification tool itself is in the source tree you clone in step 4
(`tools/repro/verify-manifest.py`, Python standard library only). There is nothing to
install from a package index that this project controls.

---

## 3. Step 2: check the hashes (2 minutes)

Download, into one directory, the artifacts for your board plus `SHA256SUMS.txt` and
`SHA256SUMS.txt.asc`.

**About the version in the commands below.** Every filename and tag here is written out
with a concrete version so the commands are copy-pasteable, and `0.2.3` is the one they
use, because it is the first release with any files to name (section 1). Substitute the
version you actually downloaded, and the board slug you actually have: an artifact is named
`notyas-<version>-<board>-app.bin` and its tag is `v<version>`. The release page for your
version is the authority on which files it carries.

Linux:

```sh
sha256sum -c SHA256SUMS.txt --ignore-missing
```

macOS. `shasum` is a different program from GNU `sha256sum` and has no
`--ignore-missing`, so give it only the lines for the files you actually downloaded:

```sh
ls > have.txt
grep -F -f have.txt SHA256SUMS.txt > mine.txt
shasum -a 256 -c mine.txt
```

Windows PowerShell, comparing the printed hash by eye against the line in
`SHA256SUMS.txt` for the same filename:

```powershell
Get-FileHash .\notyas-0.2.3-waveshare-4b-app.bin -Algorithm SHA256
```

Every file must say `OK`. A failure here is far more often a truncated download than an
attack: fetch it again before concluding anything, then see section 9.

This step proves only that the bytes you have are the bytes the release page served. It
says nothing about who produced them, which is step 3.

---

## 4. Step 3: check the signature (10 minutes)

`SHA256SUMS.txt.asc` is a detached OpenPGP signature over `SHA256SUMS.txt`. One
signature covers every artifact, because every artifact is listed in that file.

The notyas release key:

```
uid          intnsity <at@intnsity.com>
type         RSA 4096
created      2026-08-15
fingerprint  A1E9 53B2 5C6A 623B 77A1 D522 3AC4 BBCF E51A B37D
```

Fetch it:

```sh
gpg --keyserver keys.openpgp.org --recv-keys A1E953B25C6A623B77A1D5223AC4BBCFE51AB37D
```

**Compare all forty hex digits against at least two independent sources.** The key is
published on keys.openpgp.org, in this repository under `docs/keys/`, and on the
maintainer's GitHub profile. A key server hands you whatever was uploaded under a given
name, so the fingerprint is the check, not the search result. Never accept a short key
id from anyone, in this project or any other: short ids are cheap to collide.

If you take the copy from `docs/keys/`, read it before you import it. `--show-keys`
parses a key file without putting anything in your keyring, so you can compare the
fingerprint, the size and the creation date against the block above first:

```sh
gpg --show-keys --with-fingerprint docs/keys/A1E953B25C6A623B77A1D5223AC4BBCFE51AB37D.asc
```

It must report exactly one primary key, RSA 4096, created 2026-08-15, under that
fingerprint. A file is named by whoever wrote it; the key inside it is the claim.
`tools/release.sh` refuses to publish a release whose committed key file says anything
else.

One thing to know before you look: this is **not** the key used by the maintainer's
desktop BigDice project. Different project, different key, different size.

The fingerprint above is the ONLY one that signs a notyas release. A release signed by
any other fingerprint - including the BigDice key, and including any earlier notyas key -
is not a notyas release, and that is worth reporting.

An earlier revision of this page inverted that sentence and told readers a signature from
`A1E9...` was the WRONG key. It is the right one. If you verified a release against this
page before 2026-08-19 and rejected it on that basis, re-check it: the fingerprint above
and the copy in `docs/keys/` have not changed, only this description of them.

Then verify. Use this form, which checks WHICH KEY signed:

```sh
gpg --status-fd 1 --verify SHA256SUMS.txt.asc SHA256SUMS.txt 2>/dev/null   | grep -q '^\[GNUPG:\] VALIDSIG A1E953B25C6A623B77A1D5223AC4BBCFE51AB37D'   && echo "signed by the notyas release key"   || echo "NOT signed by the notyas release key - do not use these files"
```

Why not plain `gpg --verify`: it exits 0 for **any** key in your keyring, and the
`Good signature from intnsity` line it prints is reading a UID, which whoever made the
signature chose for themselves. Someone can generate a key this afternoon, put that name
on it, sign their own files, and your terminal will say `Good signature from intnsity`.
The forty hex digits above are the only part an impostor cannot copy.

The human-readable form is still worth running for context:

```sh
gpg --verify SHA256SUMS.txt.asc SHA256SUMS.txt
```

You want `Good signature from ...`, and that line is necessary but not sufficient:
read "Check the fingerprint, not the name" below before you accept it. You will **also**
see:

```
WARNING: This key is not certified with a trusted signature!
         There is no indication that the signature belongs to the owner.
```

That warning is normal and expected. It means "you have not personally signed this key
in your own web of trust", not "something is wrong". It appears for nearly every
software release anybody verifies. The check that carries the weight is the one you did
by hand: the full fingerprint, from two places.

### Check the fingerprint, not the name

`Good signature from "intnsity <at@intnsity.com>"` is weaker than it looks, and so is the
exit status beside it:

- The name is a **uid**, which is a string whoever made the key typed into it when they
  made it. A key with that uid takes about a minute to produce, on any machine.
- `gpg --verify` exits 0 for a good signature from **any** key in your keyring, including
  one you imported five minutes ago from the same page that served the files.

Neither says which key. The fingerprint does, and gpg will compare it for you if you ask
on its machine-readable channel instead of reading its prose:

```sh
gpg --status-fd 1 --verify SHA256SUMS.txt.asc SHA256SUMS.txt \
  | grep "^\[GNUPG:\] VALIDSIG .*A1E953B25C6A623B77A1D5223AC4BBCFE51AB37D"
```

One line of output and exit status 0 means the release key made this signature. **No
output means it did not**, whatever name gpg printed above, and that is a stop: see
section 9. The line names the signing key first and its primary key last, which is why
matching either end of it is the check:

```
[GNUPG:] VALIDSIG A1E953B2...E51AB37D 2026-08-19 1787167236 0 4 0 1 10 00 A1E953B2...E51AB37D
```

### One more line to look for

A `VALIDSIG` line is necessary and still not quite sufficient. If the key had been
revoked or had expired, gpg would print the same `VALIDSIG` and still exit 0, alongside a
`REVKEYSIG` or `EXPKEYSIG` line saying so - it is telling you "the signature is good, and
the key behind it is one you should not be trusting". For a release key those are
refusals, so check that none of them is there:

```sh
gpg --status-fd 1 --verify SHA256SUMS.txt.asc SHA256SUMS.txt \
  | grep -E "^\[GNUPG:\] (BADSIG|ERRSIG|EXPSIG|EXPKEYSIG|REVKEYSIG)"
```

**No output is what you want here** - the opposite of the check above. Any output means
stop, and see section 9. `tools/release.sh` refuses on exactly these five, which is how
the retired 2026-08-18 key stays retired.

The release process makes the same comparison from the other side: `tools/release.sh`
refuses to sign, tag or push anything that is not this fingerprint's, and
`tools/ci/selftest-release-signature.sh` is the fixture proving that it refuses - it
builds a key whose uid copies the release identity and checks that the release path says
no to it.

The git tag is signed with the same key, which is a separate and useful check because it
authenticates the source revision rather than the downloaded files. `git tag -v` has the
same weakness as `gpg --verify`, and `--raw` is how you ask git the same pinned question:

```sh
git clone https://github.com/intnsity/notyas && cd notyas
git verify-tag --raw v0.2.3 2>&1 \
  | grep "VALIDSIG .*A1E953B25C6A623B77A1D5223AC4BBCFE51AB37D"
```

---

## 5. Step 4: rebuild the firmware yourself (30-90 minutes)

This is the step that makes the others worth doing.

```sh
# 1. The source, at the exact tag, with the tag's signature checked against the
#    fingerprint rather than against the name on it (section 4).
git clone https://github.com/intnsity/notyas && cd notyas
git checkout v0.2.3
git verify-tag --raw v0.2.3 2>&1 | grep "VALIDSIG .*A1E953B25C6A623B77A1D5223AC4BBCFE51AB37D"

# 2. Build the container, then build one board.
docker build -t notyas-repro -f tools/repro/Dockerfile .
docker run --rm -v "$PWD":/mnt/src:ro -v "$PWD/out":/out notyas-repro waveshare-4b

# 3. Compare against what was published. Put the downloaded files in ./published/.
cd out
grep waveshare-4b ../published/SHA256SUMS.txt | sha256sum -c -
cmp notyas-0.2.3-waveshare-4b-app.bin ../published/notyas-0.2.3-waveshare-4b-app.bin
```

Substitute `elecrow-5` for the other board. `bash tools/repro/build.sh --list-boards`
prints the current list, and it is the only place the board vocabulary is defined.

Every script in this repository is invoked as `bash tools/...` here rather than by path
alone. Both work on a clone that kept its permission bits; only the first works on one
that did not, and a "permission denied" in the middle of a verification tells you nothing
about the release.

Most of the elapsed time is the container image and the ESP-IDF C build. It is not hung.

### Compare all four flashable files, not just the app

They answer different questions:

- `app.bin` - the Rust firmware plus the ESP-IDF it links. Most of the trust.
- `bootloader.bin` - runs before the app and decides whether the app runs at all. It is
  built from this project's pinned configuration, so a substituted bootloader is a
  complete compromise that an app-only comparison would miss.
- `partition-table.bin` - defines what exists in flash: one app partition, one sealed
  storage region, one counter region, and nothing else. The claim that the device writes
  nothing anywhere else is encoded in these bytes. It is identical on both boards, which
  also makes it the cheapest way to confirm your own tooling works.
- `merged.bin` - the three above in one file, padded with `0xff`, for a single flash
  command. If the three match and this one does not, the fault is in the merging tool.

The release also publishes, per board, the unstripped `.elf`, the merged `sdkconfig.txt`,
`BUILDINFO.txt` (toolchain versions, input hashes, environment) and `VERIFY.json`
(step 7), plus one source tarball and one archive of the fetched ESP-IDF components. All
of them are listed in `SHA256SUMS.txt` and all of them reproduce.

### The two boards produce different bytes on purpose

The flash size lands in the image header, so a Waveshare `app.bin` and an Elecrow
`app.bin` are never equal. Comparing one board's artifact against the other's always
fails and is not a bug.

| Board | Slug in every filename | Flash |
| --- | --- | --- |
| Waveshare ESP32-P4-WiFi6-Touch-LCD-4B | `waveshare-4b` | 32 MB |
| Elecrow CrowPanel Advanced 5 inch | `elecrow-5` | 16 MB |

Only these two boards are hardware-verified and only these two get release artifacts.
The other board configurations in the repository are compile-checked scaffolds, shipped
as source.

### Proving it reproduces, rather than observing it once

```sh
bash tools/repro/check-repro.sh
```

builds each board twice, from two different host paths, at different times, handing the
second run a deliberately hostile environment, and compares every byte of every
artifact. That is the check the project itself runs. The release notes for the version
you downloaded record whether the two-machine run passed for that tag; if they do not
say so, treat this section as a procedure you can follow rather than a property somebody
else has already demonstrated.

### Proving the test console is not in the image you downloaded

The firmware has a hardware test console behind a build feature. Compiled in, it answers
commands on the board's serial port with no PIN, and one of those commands signs a
transaction. Release images are built without it. Three separate things say so, and two
of them are statements about a build rather than findings about a file: the build script
refuses to compile the console into a release profile, and the console's own module
carries the same rule as a compile error. Only the third reads the artifact, which is why
it is the one written down here:

```sh
bash tools/ci/check-release-symbols.sh --image notyas-0.2.3-waveshare-4b.elf
```

It looks for three different kinds of evidence, because each covers a gap in the others:
the Rust module path of the console's code, in both of the manglings the compiler uses;
the two ESP-IDF entry points its serial receive path cannot exist without, which are C
symbols and so cannot be inlined away; and the console's own printed strings, which are
data rather than code and survive inlining, link-time optimisation and `strip` alike.

Hand it the unstripped `.elf`. That is the file the release publishes, and it is the only
one this check can clear. A stripped file has no symbol table at all, and the script
reports it as unverifiable rather than clean - the absence of a symbol in a file with no
symbols is not evidence of anything. For the same reason it refuses an `app.bin` or a
`merged.bin`, which are not the linked image, and it refuses any ELF it cannot recognise
as notyas firmware.

If you would rather see the check fail before you trust it passing:

```sh
bash tools/ci/selftest-release-symbols.sh
```

builds small ELFs carrying each of the console's signatures - including a stripped one -
and asserts the check rejects every one of them, and clears an image carrying none.

---

## 6. Step 5: flash what you built

The images are unsigned and unencrypted, so they flash like any other ESP32 image. There
is no vendor key to work around and no unlock step. That is the other half of what step 4
buys: the firmware you verified is firmware you can actually install.

```sh
pip install esptool     # or pipx, or a venv: see section 2
esptool --chip esp32p4 -p /dev/ttyUSB0 write-flash 0x0 \
        notyas-0.2.3-waveshare-4b-merged.bin
```

Or the three regions separately, which is the same thing spelled out:

```sh
esptool --chip esp32p4 -p /dev/ttyUSB0 write-flash \
    0x2000  notyas-0.2.3-waveshare-4b-bootloader.bin \
    0x8000  notyas-0.2.3-waveshare-4b-partition-table.bin \
    0x10000 notyas-0.2.3-waveshare-4b-app.bin
```

On Windows the port is `COM3` or similar. Command spellings changed between esptool 4.x
(`write_flash`) and 5.x (`write-flash`); everything here is 5.x.

Flash the artifacts YOU built, from `./out`, rather than the ones you downloaded. They
are byte-identical if step 4 succeeded, and flashing your own copy takes the download out
of the chain entirely.

---

## 7. Step 6: provision the board (once per device, irreversible)

A freshly flashed board runs and signs, but it cannot save anything until one eFuse key
block has been burned. That burn is what binds sealed storage to this physical board, so
that every PIN guess requires the board itself.

**Provisioning is a host-side ceremony, performed once per device with `espefuse`.
Release firmware contains no eFuse-burn code.** Provisioning burns exactly one key block: no
secure-boot digest, no anti-rollback fuse, no flash-encryption key.

**The procedure is `docs/PROVISIONING.md` in this repository, and it is deliberately not
repeated here.** Read it before you run anything. It carries the block-selection rule,
the retry budget, how to rehearse the entire ceremony against a virtual chip first, the
acceptance table to check afterwards, and what to do when it goes wrong. An eFuse burn
cannot be undone, and a document that half-describes an irreversible step is worse than
one that sends you to the whole thing.

Where it fits in this sequence:

```
build (step 4) -> flash (step 5) -> PROVISION -> use the device -> compare (step 7)
```

Two ordering facts worth carrying with you:

- **Provision after flashing, not before.** Nothing in the ceremony depends on the
  firmware, but the board must be reachable over the UART download path, and it is the
  running firmware that tells you afterwards whether the burn took: the Verify screen
  reports the HMAC key block state as it actually reads it.
- **A board that already held a store will refuse to mount it after the burn.** That is
  correct behaviour, not a fault. The burn changes the device binding, and refusing a
  store bound to a different binding is exactly what stops a transplanted flash chip from
  being silently reinterpreted. `docs/PROVISIONING.md` covers the recovery, which is
  host-side.

If you never provision, the device still runs, still derives keys and still signs. It
simply has no storage.

---

## 8. Step 7: compare the device against the release

Everything so far has been about files. This is about the chip in your hand.

On the device: **Settings -> Verify device**. The screen shows the firmware version and
board, the digests of the three members of the boot chain (app image, bootloader,
partition table) each with the offset and length that were hashed, the composite
`firmware_digest` built from them, the eFuse posture including all three secure-boot
digest slots and the HMAC key block, the chip and flash identity, the radio kill line
level, the self-test verdict and the storage state. `[ Show as QR ]` exports the whole
readout.

A release that publishes artifacts publishes a signed manifest per board,
`notyas-0.2.3-<board>-VERIFY.json`, listed in `SHA256SUMS.txt` and therefore covered by
the signature you checked in step 3. It carries exactly the numbers the screen shows.

Compare the device against it:

Both commands below run from the clone you made in step 4, because that is where the
tool lives; give each path where your files actually are (the manifest is a file you
downloaded, so it is wherever you put the downloads).

```sh
# Save the device readout as readout.txt: scan the QR, or type the rows in. The first
# line must be exactly
#     notyas-verify/1
# and every line after it is one key=value pair, in any order. The tool says which line
# it could not read rather than guessing, and it refuses a file whose first line is
# something else.
python3 tools/repro/verify-manifest.py check \
    --manifest notyas-0.2.3-waveshare-4b-VERIFY.json \
    --readout readout.txt
```

And compare the manifest against the artifacts you built, which is the same comparison
from the other end:

```sh
python3 tools/repro/verify-manifest.py check \
    --manifest notyas-0.2.3-waveshare-4b-VERIFY.json \
    --dir ./out
```

The tool prints one line per field and exits non-zero on any mismatch. A row the device
did not print is reported as skipped rather than counted as agreement.

### The one number that confuses everybody

The device's app digest is **not** `sha256sum app.bin`, and both numbers are correct.

An ESP32 application image carries a SHA-256 of itself in its last 32 bytes. The device
reports the digest of the image *content*, which stops before those 32 bytes.
`sha256sum` covers the whole file, including them. Two legitimate, different numbers.

This is the single most likely way an honest verification attempt fails, so the manifest
publishes both and names them:

- `app_image_sha256` - what the device shows.
- `app_file_sha256` - what `sha256sum app.bin` prints, and what is in `SHA256SUMS.txt`.

To see the relationship for yourself:

```sh
# The image-content digest, read straight out of the file's own last 32 bytes:
tail -c 32 notyas-0.2.3-waveshare-4b-app.bin | od -An -tx1 | tr -d ' \n'; echo

# The same number, recomputed over everything before those 32 bytes:
head -c $(( $(wc -c < notyas-0.2.3-waveshare-4b-app.bin) - 32 )) \
     notyas-0.2.3-waveshare-4b-app.bin | sha256sum
```

`od` and `wc` rather than `xxd` and `stat`: `xxd` is part of vim and is missing from a
minimal Linux install, and `stat -c%s` is the GNU spelling, which is not the one macOS
has. On macOS, use `shasum -a 256` in place of `sha256sum`.

### What the Verify screen does and does not prove

This is the statement the project holds itself to. `docs/SECURITY.md` makes it under
the heading "The self-reporting boundary", in its own words and at more length; what
follows is the short form:

> Every value on the Verify screen is read and reported by the firmware being verified.
> Firmware that has been replaced can report anything.
>
> The screen detects accidental corruption and incomplete flashes, it lets you compare
> the firmware digests against the digests published for the release and independently
> rebuilt from source, and it lets you confirm that the hardware identity in front of you
> is the hardware identity you recorded. It cannot establish that the firmware reporting
> those values is the firmware you intended to run.
>
> One check does not depend on the firmware: with Secure Boot v2 burned, the chip's boot
> ROM verifies the signature on the bootloader, and the bootloader verifies the signature
> on the application, before either runs. Unsigned or modified code does not execute, so
> there is nothing left to report a false value. The Verify screen shows whether that
> eFuse is burned on your unit.

On a unit running any release published so far that last row reads `not burned` for all
three digest slots, and that is
the true and important answer rather than an omission.

Concretely, then, what the screen is good for on a device running any release published
so far:

- **Catching accidental corruption and incomplete flashes**, by far the most common real
  failure: a flash interrupted partway, a stale bootloader left from a different board,
  an app written at the wrong offset. In each of those the firmware is honest and wrong,
  which is exactly the case a self-reported digest catches perfectly.
- **Comparing against values you obtained somewhere else** - the signed manifest, or your
  own rebuild. The comparison means something precisely because the expected number came
  from outside the device.
- **Confirming device identity against a substituted unit.** The chip MAC, the die unique
  id and the flash ids are values you record once, off the device, when you first set it
  up. A look-alike unit reports different ones.

What it cannot do is establish its own honesty. Step 5 is what covers that, and without
Secure Boot v2 nothing else does.

---

## 9. If something does not match

**Do not flash it, and do not put funds behind it.** A mismatch is cheap to investigate
and expensive to ignore.

1. **Step 2 failed** (a downloaded file's hash is wrong): re-download, ideally over a
   different network. A truncated download is far more likely than an attack. If it fails
   again, report it.
2. **Step 3 failed** (bad signature, or a fingerprint that is not the one in section 4):
   stop. Do not flash anything from that download, and report it with the exact
   fingerprint you saw.
3. **Step 4 failed** (your rebuild differs from the published binary): this is the
   interesting case, and it is more often a recipe bug than an attack. Work outside-in:
   - `diff -u` the two `*-BUILDINFO.txt` files. Toolchain versions, environment and input
     hashes are all in there, and most differences die at this step.
   - `diff -u` the two `*-sdkconfig.txt` files. One differing `CONFIG_` line explains an
     arbitrarily large binary difference; the usual offender is the flash size, which
     means a board slug was wrong somewhere.
   - `cmp -l a.bin b.bin | head` for the first differing offset. A handful of bytes near
     the start of the app image is metadata. Differences scattered across the whole image
     mean the compiled code differs.
   - Report it with both BUILDINFO files, both sdkconfigs, that `cmp` output and your host
     details. That is nearly always enough to find the cause without access to your
     machine.
4. **Step 7 failed** (the device's numbers do not match the manifest for the version it
   claims to be running): the device is not running the firmware you think it is. Move
   funds using a different signer first, then reflash from your own build, then report it.

The rule this project holds itself to: under the container recipe there are **no**
expected differences. A reproducible build with a section listing harmless differences is
not a reproducible build. If your rebuild differs and none of the above explains it, that
is a bug in the recipe, and it gets fixed rather than explained.

Report to https://github.com/intnsity/notyas/issues. A report that turns out to be a
recipe bug is as useful as one that turns out to be an attack, and far more likely.

---

## 10. Where the detail lives

- `docs/PROVISIONING.md` - the one eFuse burn provisioning performs, in full.
- `docs/plan-0.2.0/REPRODUCIBLE.md` - the recipe and its reasoning: every source of
  nonreproducibility in this stack, named, with its fix and the check that proves the fix
  worked.
- `tools/repro/` - the container definition, the toolchain pin, the build script, the
  double-build check and the manifest tool. The container definition and the CI workflow
  are MIT OR Apache-2.0 so another project can lift them; the rest of notyas is
  GPL-3.0-or-later.
- `docs/plan-0.2.0/VERIFY.md` - what the device can honestly report about itself, and
  exactly where that stops being worth anything.
- `docs/SECURITY.md` - the security model these checks belong to, including what is
  explicitly out of scope.
- `docs/RELEASE-0.2.0.md`, and the `docs/RELEASE-*.md` for every point release after it -
  what shipped, what deliberately did not, and the known limitations a buyer should read.
