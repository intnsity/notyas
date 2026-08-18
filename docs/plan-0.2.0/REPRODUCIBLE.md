# REPRODUCIBLE.md - reproducible builds and signed releases for notyas 0.2.0

Status: wave-2 planning input. This is PLATFORM.md contribution #6 ("Reproducible
Rust-on-ESP-IDF recipe") written out in full, and the mechanism behind
SECURITY.md invariant 5 ("Verifiable firmware"). Companion documents in this
directory: ARCHITECTURE.md, SECURITY.md, PARITY.md, PLATFORM.md, and
MILESTONES.md / OPEN-QUESTIONS.md (parallel workflow - the checklist in section 7
is written to be lifted into MILESTONES.md, and every "OPEN:" line here is meant
to be pulled into OPEN-QUESTIONS.md).

Honest status up front, because it is the first thing a reviewer will check:

- **0.1.0 ships signed but not yet reproducible.** The release carries a
  GPG-signed SHA256SUMS.txt over source and (if published) binaries; nobody
  outside this bench can rebuild those binaries byte-for-byte, because the build
  runs on Windows from a UNC share with machine-local absolute paths baked in.
  0.1.0 is a source-only preview and its firmware/src/verify.rs already says so:
  the Verify screen's `source_id` field literally reports `"unavailable"` rather
  than invent a build identity it cannot honor.
- **0.2.0 closes the gap.** A container build is the normative release path, the
  two hardware-verified boards produce two named, independently rebuildable
  artifact sets, and the Verify screen's source id becomes a value a third party
  can derive from the published source.

Do not describe notyas as having reproducible builds until section 7's checklist
is green on a tagged release. Until then the correct phrasing is "signed
releases; reproducible builds are the 0.2.0 target" (see the no-hype rule in
docs/SECURITY.md: claims are mechanically enforced or they are not made).

---

## 1. What reproducibility means here, and why a wallet needs it

### 1.1 The property

A build is reproducible when the same source, at the same revision, built by
anyone following a published recipe, yields **byte-identical** binaries. For
notyas 0.2.0 the claim is scoped precisely:

> For a given git tag and a given board slug, the container recipe in section 3
> produces `app.bin`, `bootloader.bin` and `partition-table.bin` whose SHA-256
> digests equal the ones listed in that release's signed SHA256SUMS.txt, on any
> x86-64 Linux host with Docker.

That is the whole claim. Explicitly **not** claimed: identical `.elf` under
arbitrary toolchain substitutions, identical output from the Windows host recipe
(section 3.4), reproducibility of the mask ROM (impossible - it is silicon), or
that reproducibility says anything about whether the source is *correct*. It
says only that the binary and the source are the same artifact.

### 1.2 Why the signature is not enough

A GPG signature answers "did the notyas maintainer produce this file?" It does
not answer "does this file correspond to the source I read?" The two failure
modes a signature cannot cover:

1. **A compromised build machine.** The key is used correctly, on a binary that
   contains something the source does not. Signing authenticates the publisher,
   including a publisher who has been silently subverted. This is not
   hypothetical for wallets - a signer that leaks nonces or biases key
   derivation is a total loss of funds, and the diff that does it is a handful
   of instructions invisible in a binary nobody can regenerate.
2. **A coerced or substituted publisher.** Reproducibility lets N independent
   people rebuild and attest. An attacker then has to compromise the source
   (public, reviewable) instead of one machine or one key.

For an airgapped signing device this is the *only* mechanism by which "open
source" means anything to a user who flashes a prebuilt binary. Without it, GPL3
publishes source that no one can connect to the code that holds their keys.
Coldcard (`make repro`, docker-based, with third parties publicly matching
released builds) and Blockstream Jade (REPRODUCIBLE.md, docker-based) both treat
this as table stakes; PARITY.md sets Coldcard as the product bar, and this is
part of that bar.
https://github.com/Coldcard/firmware/blob/master/docs/notes-on-repro.md ,
https://github.com/Blockstream/Jade/blob/master/REPRODUCIBLE.md

### 1.3 The two halves of our stack

notyas firmware is Rust on top of ESP-IDF, so reproducibility has a C half and a
Rust half, each with its own mechanism.

**C half - ESP-IDF.** ESP-IDF has first-class support via
`CONFIG_APP_REPRODUCIBLE_BUILD`. When enabled, the build system passes
`-fmacro-prefix-map` and `-fdebug-prefix-map` so that the IDF path becomes
`/IDF`, the project directory `/IDF_PROJECT`, the build directory `/IDF_BUILD`,
each component directory `/COMPONENT_<NAME>_DIR` and the toolchain path
`/TOOLCHAIN`; build date and time are dropped from the application and
bootloader metadata structures; IDF source stops using `__DATE__`/`__TIME__`;
and source-file, component and linker-fragment lists are sorted before reaching
CMake. Espressif is explicit that what remains outside the option's reach is the
ESP-IDF version itself and the versions of CMake, Ninja and the cross-compiler -
and that the IDF Docker image is the intended way to pin those.
https://docs.espressif.com/projects/esp-idf/en/v5.5.1/esp32p4/api-guides/reproducible-builds.html

Note the flag is not in `firmware/sdkconfig.base.defaults` today. Adding it is
checklist item M-REPRO-2.

**Rust half - cargo/rustc.** There is no `CONFIG_APP_REPRODUCIBLE_BUILD`
equivalent; the tool is `--remap-path-prefix`, which rewrites path prefixes in
diagnostics, debug info and macro expansions (`file!()`, and therefore every
panic location).
https://doc.rust-lang.org/rustc/command-line-arguments.html

Hand-writing `--remap-path-prefix` for the workspace, `CARGO_HOME`, `OUT_DIR`
and the sysroot is error-prone, and cargo already implements exactly that as
RFC 3127 `trim-paths`: a profile setting that remaps workspace packages to paths
relative to the workspace root, registry dependencies to
`/cargo/registry/<registry-id>/<pkg>-<version>`, git dependencies to
`/cargo/git/...`, build output including `OUT_DIR` to `/cargo/build-dir`, and -
the part that matters for us - **standard library sources to
`/rustc/<rustc-commit-hash>/library/...`**. It also exports
`CARGO_TRIM_PATHS_SCOPE` and `CARGO_TRIM_PATHS_REMAP` so build scripts can
forward the same mapping to C compilers via `-ffile-prefix-map`.
https://doc.rust-lang.org/nightly/cargo/reference/unstable.html#profile-trim-paths-option ,
https://rust-lang.github.io/rfcs/3127-trim-paths.html

**`-Zbuild-std` is the reason we cannot skip this.** Our target
`riscv32imafc-esp-espidf` is tier 3, so `firmware/.cargo/config.toml` sets
`build-std = ["std", "panic_abort"]`. With a prebuilt std, rustc's release CI
has already remapped std paths to `/rustc/<hash>/...`; with `-Zbuild-std`, std
is compiled *here*, from `rust-src` under the local rustup sysroot, and the
binary ends up carrying the local sysroot path unless it is remapped -
rust-lang/rust#73167 is exactly this bug, and rustup sysroot paths contain the
user name on Windows. So: `-Zbuild-std` converts std from a pinned upstream
artifact into a local build input, and everything in this document that applies
to our crates applies to `core`, `alloc` and `std` as well.
https://github.com/rust-lang/rust/issues/73167 ,
https://github.com/rust-lang/rust/issues/129080 (rustc reproducible-build
tracking issue)

`trim-paths` is nightly-only, which for us is free: `firmware/rust-toolchain.toml`
already pins `nightly-2026-07-27` because `-Zbuild-std` requires nightly anyway.

DECISION: use cargo `trim-paths` (`[profile.release] trim-paths = "all"` plus
`cargo-features = ["trim-paths"]` in the root Cargo.toml, or `[unstable]
trim-paths = true` in `.cargo/config.toml`) rather than hand-rolled
`--remap-path-prefix` entries in RUSTFLAGS. Reasons: it covers the sysroot/
`rust-src` case correctly (which the hand-rolled version historically got
wrong), it covers `OUT_DIR` (which we need - see item 5 below), it survives
`CARGO_HOME` moving, and putting flags in RUSTFLAGS changes the fingerprint of
every crate in the graph including build-std, making an accidental RUSTFLAGS
difference an invisible source of divergence. Fallback if a `trim-paths` bug
bites on the pinned nightly: explicit `--remap-path-prefix` for
`<workspace>=/src`, `$CARGO_HOME=/cargo`, `$CARGO_TARGET_DIR=/build` and
`$(rustc --print sysroot)=/rustc`, recorded in BUILDINFO.txt either way.

---

## 2. Every source of nonreproducibility in our exact stack

Enumerated concretely against this repository as it stands (0.1.0), because a
generic list is useless. Each item: what leaks, how it reaches the binary, the
fix, and what proves the fix worked. Items marked **[live problem]** are things
this bench does today that would break a byte-comparison.

### Group A - absolute paths

**1. The source tree lives on a UNC share, the target dir is machine-local.
[live problem]**
`tools/build.ps1` sets `CARGO_TARGET_DIR` to `C:\nyt-ws` (Waveshare) or
`C:\nyt-e5` (Elecrow) while the sources sit on a UNC network share
(`\\<host>\<share>\...\notyas`). So a single build mixes two unrelated
absolute path roots, one of them a host name and a share name. Both reach the
binary: the source root through `file!()` in panic locations and DWARF, the
target root through `OUT_DIR` (item 5) and through the ESP-IDF CMake build,
which esp-idf-sys runs *inside* `OUT_DIR`.
Fix: the normative build happens in a container at fixed paths - source copied
to `/build/src`, `CARGO_TARGET_DIR=/build/target` - plus `trim-paths` so even
those fixed paths do not appear. Jade learned the same lesson the hard way and
mandates a specific mount path (`/builds/blockstream/jade`) "because it gets
encoded into build artifacts"; we prefer remapping over mandating, and get both.
Check: `strings app.bin | grep -Ei '172\.16|/build/|C:|nyt-|Users'` returns
nothing.

**2. `CARGO_HOME` / registry sources.**
Dependency source paths under `~/.cargo/registry/src/...` embed the user name
and appear in panic locations from any dependency that can panic (in our graph:
`bitcoin`, `secp256k1`, `qrcode`, and all of `std`).
Fix: `trim-paths` maps them to `/cargo/registry/<registry-id>/<pkg>-<version>`.
Check: same `strings` grep; plus BUILDINFO records `CARGO_HOME`.

**3. The rustup sysroot and `rust-src` under `-Zbuild-std`.**
Covered in 1.3. On this bench the sysroot path contains the Windows user name.
Fix: `trim-paths` maps std sources to `/rustc/<rustc-commit-hash>/library/...`.
Note that the *rustc commit hash* becomes part of the remapped path, which is a
feature: it makes a toolchain substitution visible as a diff rather than
silently invisible.
Check: `strings app.bin | grep -o '/rustc/[0-9a-f]*' | sort -u` matches
`rustc -vV`'s commit-hash line.

**4. ESP-IDF, component and toolchain paths in the C objects.**
`~/.espressif/esp-idf/...`, `~/.espressif/tools/riscv32-esp-elf/...`, and the
managed components under `OUT_DIR/managed_components/...`.
Fix: `CONFIG_APP_REPRODUCIBLE_BUILD=y` (the `-fmacro-prefix-map`/
`-fdebug-prefix-map` set described in 1.3).
Check: `strings` grep; `readelf --debug-dump=info` shows `/IDF`, `/IDF_BUILD`,
`/TOOLCHAIN` prefixes only.

**5. `OUT_DIR` inside the generated esp-idf-sys bindings. [live problem]**
esp-idf-sys generates `bindings.rs` into `OUT_DIR` and includes it with
`include!(concat!(env!("OUT_DIR"), "/bindings.rs"))`. Any code generated there
that can panic carries `C:\nyt-ws\...\out\bindings.rs` as its `file!()`. Our
`firmware/Cargo.toml` declares seven `bindings_header` entries, so this is a
large generated surface, not a corner case.
Fix: `trim-paths` remaps build output to `/cargo/build-dir`.
Check: `strings app.bin | grep bindings.rs` shows only `/cargo/build-dir/...`.

**6. `secp256k1-sys` C objects built by cc-rs, outside the IDF prefix maps.
[live problem]**
`tools/build.ps1` points cc-rs at the embuild-installed GCC via
`CC_riscv32imafc_esp_espidf` and sets `CFLAGS_riscv32imafc_esp_espidf`. Those
objects are compiled by cargo, not by the IDF CMake build, so
`CONFIG_APP_REPRODUCIBLE_BUILD`'s prefix maps do not apply to them. Any
`__FILE__` or `assert()` in that C carries an absolute registry path, and DWARF
carries it unconditionally.
Fix: append `-ffile-prefix-map=$CARGO_HOME=/cargo -ffile-prefix-map=/build=/build`
(or forward `CARGO_TRIM_PATHS_REMAP`) to the `CFLAGS_*` variable the container
script already sets. Do not drop the existing flags: the `-march`/`-mabi`/
`-fno-pic` triple in build.ps1 is load-bearing (hard-float ABI and static link),
and changing them changes the binary.
Check: `readelf --debug-dump=info` over the secp256k1 objects, or the global
`strings` grep.

**7. The generated `sdkconfig` and the CMake/ninja files under `OUT_DIR`.**
Not linked into the image, but the merged `sdkconfig` is the input that decides
what the binary *is*, and the CMake/ninja files record absolute paths verbatim.
Fix: publish the merged `sdkconfig` as a release artifact (it is the highest-value
triage input there is - section 4.4 step 2), and make the container script strip
any absolute path it contains before packaging, so the published copy is
byte-stable across builders and can be hashed into SHA256SUMS.txt like everything
else. Do not publish the CMake/ninja files at all; they are machine-local by
nature and comparing them produces noise.
Check: the packaged `*-sdkconfig.txt` contains no `/` -prefixed host path and is
identical between two builders.

### Group B - time and version metadata

**8. Build timestamp in `esp_app_desc_t` and the bootloader description.**
The app descriptor carries `time` and `date` fields filled from `__DATE__`/
`__TIME__`.
Fix: `CONFIG_APP_REPRODUCIBLE_BUILD=y` removes them.
Check: `esptool image_info --version 2 app.bin` shows an empty/zeroed compile
time.

**9. `esp_app_desc_t.version` from `git describe`. [live problem]**
ESP-IDF resolves the project version as: `CONFIG_APP_PROJECT_VER` if
`CONFIG_APP_PROJECT_VER_FROM_CONFIG` is set; else `PROJECT_VER` from CMake; else
`$PROJECT_PATH/version.txt`; else `git describe`; else `"1"`. Under esp-idf-sys
the "project" is a generated CMake project inside `OUT_DIR`, so what
`git describe` sees is undefined and environment-dependent (a shallow clone, a
missing tag, or a dirty tree all change it - and a CI checkout is shallow by
default, which is exactly the ESP-IDF issue IDFGH-7504).
Fix: set `CONFIG_APP_PROJECT_VER_FROM_CONFIG=y` and
`CONFIG_APP_PROJECT_VER="0.2.0"` in `sdkconfig.base.defaults`, bumped with the
crate version by the release script.
Check: `esptool image_info` shows exactly `0.2.0`.
https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-guides/build-system.html ,
https://github.com/espressif/esp-idf/issues/9071

**10. `esp_app_desc_t.idf_ver` from `git describe` in the IDF checkout.**
Same class of problem one level down: if the IDF clone is shallow or tagless,
`IDF_VER` becomes a raw hash instead of `v5.5.4`, and the string is linked into
the image.
Fix: the container's ESP-IDF is the image's own `/opt/esp/idf` checkout, tagged,
and the image is pinned by digest (section 3.2).
Check: `esptool image_info` shows `v5.5.4`; the on-device Verify screen shows the
same string via `esp_get_idf_version()` (firmware/src/verify.rs already reads it).

**11. `app_elf_sha256` in the descriptor.**
Deterministic *given* a deterministic ELF - it is the digest of the ELF, patched
into the image at elf2image time. It is therefore an excellent tripwire: if the
ELF differs at all, this field differs, and the whole image diverges from byte
~48 of the app onward. Do not treat a mismatch here as a separate bug; it is a
symptom.

**12. `SOURCE_DATE_EPOCH`, `TZ`, wall-clock.**
Not consumed by the IDF image pipeline once item 8 is fixed, but any tarball or
zip we publish embeds mtimes.
Fix: set `SOURCE_DATE_EPOCH` to the tag's committer date, `TZ=UTC`, `LC_ALL=C`,
`umask 022` in the container script; pack tarballs with `--sort=name
--mtime=@$SOURCE_DATE_EPOCH --owner=0 --group=0 --numeric-owner`.

### Group C - toolchain identity

**13. The pinned nightly.**
`firmware/rust-toolchain.toml` pins `nightly-2026-07-27` with `rust-src`, and its
comment already documents why it must not be bumped blindly (a `std::fs`
`set_perm_nofollow` fallback referencing `libc::AT_FDCWD`, undefined on espidf,
breaks `-Zbuild-std` on nightlies after 2026-07-28 -
rust-lang/rust#158168). Good, but a channel name is not a verifiable pin: it is
a name resolved against a mutable server.
Fix (verifiable pin): (a) keep rust-toolchain.toml as the human-facing pin;
(b) record `rustc -vV` **including the commit-hash and commit-date lines** in
BUILDINFO.txt and assert them in the container build; (c) in the Dockerfile,
install the toolchain with rustup and then record the SHA-256 of the installed
`rustc` binary and of the `rust-src` component tree, so a substituted dist
tarball is detectable. Rustup dist artifacts are published with `.sha256`
sidecars; dated nightlies remain downloadable, which is what makes this pin
usable a year later.
Check: the container build fails if `rustc -vV`'s commit hash differs from the
one recorded in `tools/repro/toolchain.lock`.

**14. The ESP-IDF version, and `v5.5.4` specifically.**
`firmware/.cargo/config.toml` sets `ESP_IDF_VERSION = "v5.5.4"` with a comment
recording why not v5.5.5 (backported struct fields break esp-idf-hal 0.46.2
initializers). A tag is mutable in principle and a fresh clone is a network
dependency.
Fix: the normative build does **not** let embuild clone. It uses the ESP-IDF
already inside `espressif/idf:v5.5.4`, selected with
`ESP_IDF_TOOLS_INSTALL_DIR=fromenv`, which esp-idf-sys documents as "uses
activated environment variables for existing installations" - precisely what the
image's entrypoint provides. The image digest then pins IDF source, CMake,
Ninja, Python and the RISC-V cross-compiler in one artifact, which is the exact
remedy Espressif's own reproducible-builds page recommends for the factors
`CONFIG_APP_REPRODUCIBLE_BUILD` cannot control.
https://github.com/esp-rs/esp-idf-sys/blob/master/BUILD-OPTIONS.md ,
https://docs.espressif.com/projects/esp-idf/en/v5.5.1/esp32p4/api-guides/tools/idf-docker-image.html

**15. The C cross-compiler for `secp256k1-sys`. [live problem]**
`tools/build.ps1` finds `riscv32-esp-elf-gcc.exe` by globbing
`~/.espressif/tools/riscv32-esp-elf` and taking the highest-sorting path. That
is a version lottery: two benches with different IDF tool installs silently use
different GCC versions, and GCC version changes object code.
Fix: in the container, take the compiler from the image's activated PATH
(pinned by the image digest) and **assert** its version string; never glob.
Check: BUILDINFO records `riscv32-esp-elf-gcc --version`; the build script exits
non-zero on mismatch with `tools/repro/toolchain.lock`.

**16. libclang, for bindgen. [live problem]**
`tools/build.ps1` points `LIBCLANG_PATH` at a pip `libclang` wheel under
`%APPDATA%\Python\Python312\site-packages\clang\native` because the esp-clang
tool that embuild installs ships no `libclang.dll` on Windows. bindgen output is
known to differ across libclang versions - upstream keeps *per-libclang-version*
expectation files for exactly this reason - so the libclang version is a build
input on par with the compiler.
https://github.com/rust-lang/rust-bindgen/blob/main/CONTRIBUTING.md
Fix: in the container, use one pinned libclang. Preference order: (a) the
`esp-clang` tool managed by ESP-IDF's own `idf_tools.py`, since its version is
pinned by the IDF release and therefore by the image digest; (b) failing that,
the image's distro `libclang-dev`, pinned by the image digest. Either way the
version is recorded and asserted.
Implementation check for M-REPRO-3: confirm that Linux `esp-clang` in
`espressif/idf:v5.5.4` ships a usable `libclang.so`. (On Windows it does not,
which is one of the reasons the host recipe is non-normative.)
Check: BUILDINFO records `clang --version` and `LIBCLANG_PATH`; the generated
`bindings.rs` is hashed into BUILDINFO so a bindgen drift is visible before the
binary diff is analyzed.

**17. `espflash` (our elf2image). [live problem]**
We do not use `idf.py`; `app.bin` is produced from the ELF by espflash, and
`tools/flash.ps1` also generates the partition-table binary with
`espflash partition-table --to-binary`. espflash therefore sits directly in the
artifact path, and it has had image-layout bugs of exactly the kind that changes
bytes (issue #714 on what `save-image --merge` emits; issue #715 on the app
image SHA-256 being written to the wrong location).
https://github.com/esp-rs/espflash/issues/714 ,
https://github.com/esp-rs/espflash/issues/715
Fix: pin espflash to an exact version in the Dockerfile
(`cargo install espflash --version =X.Y.Z --locked`), record it in BUILDINFO,
and cross-check the produced `app.bin` against `esptool image_info` from the
image's own esptool (an independent implementation reading our output is a
cheap, genuinely useful second opinion).
OPEN: whether to make **esptool** rather than espflash the normative image
producer for releases (espflash stays the developer flashing tool). Recommend
yes if the elf2image outputs ever differ: esptool is the reference
implementation, ships inside the pinned IDF image, and removes one independently
versioned tool from the trusted path. Decide by comparing both outputs once,
during M-REPRO-4.

### Group D - generated and fetched inputs

**18. Cargo dependency resolution.**
Fix: the repo already has a single root `Cargo.lock` covering the firmware
(commit b0f9452 unified the workspace). Build with `--locked`; the lock pins
versions *and* checksums, so a compromised crates.io mirror cannot substitute
content. Optionally `cargo vendor` into the image for a fully offline build.
Check: `--locked` fails the build if the lock would change.

**19. ESP-IDF managed components. This is why
`firmware/components_esp32p4.lock` is committed.**
`firmware/Cargo.toml` pulls seven remote components with **caret ranges**
(`waveshare/esp_lcd_st7703 ^2`, `espressif/esp_lcd_touch_gt911 ^1`, and so on).
A caret range is not a pin: without the lockfile, a component publisher shipping
2.1.0 tomorrow silently changes tens of kilobytes of C driver code inside our
image. The committed lock pins every direct and transitive component to an exact
version *and* a `component_hash` (e.g. `waveshare/esp_lcd_st7703` 2.0.0,
`component_hash: d82de857...`), plus `idf: 5.5.4` and a `manifest_hash`. It is
the C-side equivalent of Cargo.lock and it is a release-critical file: without
it the recipe is not reproducible next month, only today.
Fix/rule: the container build copies the lock in, runs the component manager,
and **fails if the lock file changed** during the build. A component update is a
deliberate commit, never a build-time surprise.
Check: `git diff --exit-code firmware/components_esp32p4.lock` inside the
container after the build.
OPEN: whether to vendor the managed components into the repo (or a submodule)
instead of relying on `components.espressif.com` being up and immutable years
from now. Recommend: do not vendor for 0.2.0 (the hashes make substitution
detectable, which is the security property), but publish a
`components-<tag>.tar.gz` alongside the release artifacts as an archival mirror,
with its hash in SHA256SUMS.txt. Cheap insurance against registry rot.

**20. Generated bindings and the generated sdkconfig.**
`bindings.rs` (item 16) and the merged `sdkconfig` (item 7) are generated
per-build. They are deterministic given items 14/16 and the defaults files, but
they are the right things to compare *first* when a diff appears, because they
localize the fault to "input drift" versus "codegen drift".
Fix: hash both into BUILDINFO.txt.

### Group E - environment leakage

**21. Environment variables that change codegen.**
The dangerous set for our build: `RUSTFLAGS`, `CARGO_ENCODED_RUSTFLAGS`,
`RUSTC_WRAPPER`/`sccache`, `CARGO_INCREMENTAL`, `CC_*`/`AR_*`/`CFLAGS_*`,
`BINDGEN_EXTRA_CLANG_ARGS`, `LIBCLANG_PATH`, `IDF_PATH`, `IDF_TOOLS_PATH`,
`IDF_CCACHE_ENABLE`, `IDF_TARGET`, `MCU`, every `ESP_IDF_*`
(`ESP_IDF_VERSION`, `ESP_IDF_SDKCONFIG_DEFAULTS`, `ESP_IDF_TOOLS_INSTALL_DIR`,
`ESP_IDF_COMPONENT_MANAGER`, `ESP_IDF_CMAKE_GENERATOR`, `ESP_IDF_COMPONENTS`),
`SOURCE_DATE_EPOCH`, `TZ`, `LC_ALL`, `PATH` (which GCC wins), and `HOME` (which
`CARGO_HOME` and `~/.espressif` hang off).
Fix: the container entry script starts from a **clean environment** (`env -i`
plus an explicit allowlist), sets exactly the documented set, and dumps the full
resulting environment into BUILDINFO.txt. Incremental compilation off
(`CARGO_INCREMENTAL=0`), ccache off, no `RUSTC_WRAPPER`.
Check: BUILDINFO's environment block is itself part of the comparison; two
builders diffing BUILDINFO before diffing binaries usually find the cause in
one line.

**22. Host filesystem semantics. [live problem, Windows]**
CRLF checkout (git `core.autocrlf` on Windows) changes source bytes;
case-insensitive paths hide filename mismatches that break on Linux; the UNC
share reorders directory listings differently than ext4, which matters anywhere
a build step globs (ESP-IDF sorts its own lists, but our own tooling should not
rely on that).
Fix: add `.gitattributes` with `* text=auto eol=lf` and binary markers, and
never glob for toolchain binaries (item 15). The container reads a fresh
`git archive`/copy of the tree, so the checkout's line endings are the
repository's.

### Group F - per-board configuration

**23. The sdkconfig overlay pair defines the artifact.**
`firmware/sdkconfig.base.defaults` plus `firmware/boards/<board>/sdkconfig.defaults`,
passed as a semicolon list via `ESP_IDF_SDKCONFIG_DEFAULTS` (later file wins).
The overlays differ by flash size only - `CONFIG_ESPTOOLPY_FLASHSIZE_32MB` for
waveshare-4b, `..._16MB` for elecrow-5 - and flash size lands in the image
header of both `bootloader.bin` and `app.bin`. Therefore the two boards produce
**different bytes even where the code is identical**, and there is no such thing
as a board-neutral notyas binary.
Fix: none needed; this is correct behavior. It is documented here so a verifier
does not "helpfully" compare a Waveshare app.bin against an Elecrow one and
report a bug.
Trap to avoid: `firmware/.cargo/config.toml` hardcodes the **waveshare-4b**
overlay as the in-repo default so a bare `cargo build` stays safe. A release
build that forgets to override `ESP_IDF_SDKCONFIG_DEFAULTS` silently produces a
32 MB-header image labeled "elecrow-5". The container script must set it
explicitly per board and assert the resulting `CONFIG_ESPTOOLPY_FLASHSIZE_*` in
the generated sdkconfig before packaging.

**24. The board cargo feature.**
Exactly one `board-*` feature, no default (`firmware/Cargo.toml`: "the build IS
the board"). Note the counter-intuitive part already documented there: esp-idf-sys
package metadata cannot be feature-gated, so *every* board build compiles *all*
seven panel components. The C side of the image is therefore board-independent
except for sdkconfig; only the cfg-gated Rust differs. This is useful during
triage: a diff confined to the Rust text section points at feature selection, a
diff in the C blob points at components or sdkconfig.

**25. The partition table is repo-pinned, not build-derived.**
`firmware/partitions.csv` is handed to espflash directly (see `tools/flash.ps1`)
- a single 4 MB factory app at 0x10000 and nothing else, identical for both
boards. So `partition-table.bin` should be **byte-identical across boards**,
which makes it the easiest artifact to verify and a good first sanity check that
a verifier's tooling works at all. Its binary form carries an MD5 checksum
appended by the generator; that is deterministic.

---

## 3. The recipe

### 3.1 Normative statement

DECISION: **the container build is normative.** A release artifact is defined as
the output of `tools/repro/build.sh <board>` run inside the image built from
`tools/repro/Dockerfile`, which is itself `FROM espressif/idf:v5.5.4` pinned by
digest. The Windows host recipe (3.4) remains the development path and is
explicitly not expected to match byte-for-byte. Reasons: (a) it pins CMake,
Ninja, Python, the RISC-V GCC and the ESP-IDF checkout in one hash, which is
precisely the residue `CONFIG_APP_REPRODUCIBLE_BUILD` cannot address; (b) it is
the only recipe a third party on any OS can execute unchanged; (c) it is what
Coldcard and Jade do, so it is the workflow verifiers already know.

### 3.2 The image

`espressif/idf:v5.5.4` exists on Docker Hub (published 2026-03-27; manifest
digest observed 2026-08-17: `sha256:b9f2d6ea1c19e0c9f7959bdb74a9e3c775642f9d0f3b841937c5fa3363db892b`
- re-read and re-pin at release time, and record the pin in the release notes).
It ships ESP-IDF with `IDF_PATH` set, the Python virtualenv, CMake, Ninja and
toolchains for all targets, with an entrypoint that activates the environment.
https://hub.docker.com/r/espressif/idf/tags ,
https://docs.espressif.com/projects/esp-idf/en/v5.5.1/esp32p4/api-guides/tools/idf-docker-image.html

`tools/repro/Dockerfile` (sketch - exact pins land in M-REPRO-3):

```dockerfile
FROM espressif/idf:v5.5.4@sha256:b9f2d6ea...   # re-verify digest at release time

# Rust: the pin from firmware/rust-toolchain.toml, installed explicitly so the
# image, not the network at build time, is the toolchain.
ENV RUSTUP_HOME=/opt/rust/rustup CARGO_HOME=/opt/rust/cargo
ENV PATH=/opt/rust/cargo/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --profile minimal --default-toolchain nightly-2026-07-27 \
                    --component rust-src --no-modify-path \
 && rustc -vV > /opt/rust/rustc-version.txt

# Host tools in the artifact path, exact versions.
RUN cargo install ldproxy   --version =0.3.4  --locked \
 && cargo install espflash  --version =3.3.0  --locked   # pin at M-REPRO-3

# bindgen's libclang (see item 16 - resolve esp-clang vs distro clang there).
RUN . $IDF_PATH/export.sh && python $IDF_PATH/tools/idf_tools.py install esp-clang

COPY tools/repro/build.sh tools/repro/toolchain.lock /opt/notyas/
ENTRYPOINT ["/opt/notyas/build.sh"]
```

Version numbers above are placeholders to be filled from the bench's working set
during M-REPRO-3; the point is that every one of them is an exact `=` pin and
appears in `toolchain.lock`, which the build script asserts against reality
before compiling anything.

### 3.3 The container build

```sh
# From the repository root, on any x86-64 Linux host with Docker.
docker build -t notyas-repro:0.2.0 -f tools/repro/Dockerfile .

# One invocation per board. Source is mounted READ-ONLY; the script copies it to
# a fixed in-container path so the build cannot mutate your tree.
docker run --rm \
  -v "$PWD":/mnt/src:ro \
  -v "$PWD/out":/out \
  notyas-repro:0.2.0 waveshare-4b

docker run --rm \
  -v "$PWD":/mnt/src:ro \
  -v "$PWD/out":/out \
  notyas-repro:0.2.0 elecrow-5
```

What `build.sh <board>` does, in order:

1. Clean environment (`env -i` + allowlist); `TZ=UTC`, `LC_ALL=C`, `umask 022`,
   `SOURCE_DATE_EPOCH` from the tag's committer date, `CARGO_INCREMENTAL=0`.
2. Assert every entry in `toolchain.lock`: `rustc -vV` commit hash,
   `cargo --version`, `riscv32-esp-elf-gcc --version`, `clang --version`,
   `espflash -V`, `esptool version`, `cmake --version`, `ninja --version`,
   `$IDF_PATH` git describe. Any mismatch aborts.
3. Copy `/mnt/src` to `/build/src` (fixed path), refuse to proceed on a dirty
   tree unless `--dirty` is passed (a dirty build is never a release build).
4. Export the build environment:
   `ESP_IDF_TOOLS_INSTALL_DIR=fromenv` (use the image's IDF - item 14),
   `MCU=esp32p4`, `CARGO_TARGET_DIR=/build/target`,
   `ESP_IDF_SDKCONFIG_DEFAULTS=/build/src/firmware/sdkconfig.base.defaults;/build/src/firmware/boards/<board>/sdkconfig.defaults`,
   `CC_riscv32imafc_esp_espidf` / `AR_...` / `CFLAGS_...` (the existing
   `-march=rv32imafc_zicsr_zifencei -mabi=ilp32f -fno-pic` plus
   `-ffile-prefix-map=...`), `LIBCLANG_PATH`.
5. `cd /build/src/firmware && cargo build --release --locked --features board-<board>`.
6. Assert the generated `/build/src/firmware/sdkconfig` contains the expected
   `CONFIG_ESPTOOLPY_FLASHSIZE_*`, `CONFIG_APP_REPRODUCIBLE_BUILD=y`,
   `CONFIG_APP_PROJECT_VER_FROM_CONFIG=y` and chip-revision options (item 23's
   trap).
7. Assert `components_esp32p4.lock` is unchanged (item 19).
8. Emit artifacts (section 3.5) into `/out`, plus `BUILDINFO.txt` and a local
   `SHA256SUMS.txt`.

Image production from the ELF, with offsets fixed by the P4's boot layout
(bootloader at 0x2000, partition table at 0x8000, app at 0x10000 -
firmware/partitions.csv; note there is deliberately no otadata/`boot_app0`
partition because the device is stateless):
https://docs.espressif.com/projects/esptool/en/latest/esp32p4/esptool/flashing-firmware.html

```sh
espflash save-image --chip esp32p4 --flash-size 32mb \
    "$TARGET/riscv32imafc-esp-espidf/release/notyas-firmware" \
    /out/notyas-0.2.0-waveshare-4b-app.bin

espflash partition-table --to-binary \
    -o /out/notyas-0.2.0-waveshare-4b-partition-table.bin \
    /build/src/firmware/partitions.csv

# bootloader.bin comes from the esp-idf-sys build tree (the one built for THIS
# board's sdkconfig - flash.ps1's warning about stale bootloaders applies here
# too; the container's target dir is fresh, so "newest" is unambiguous).

# Merged image for convenience flashing; padded with 0xFF between regions.
esptool --chip esp32p4 merge-bin -o /out/notyas-0.2.0-waveshare-4b-merged.bin \
    --flash-size 32mb \
    0x2000  /out/notyas-0.2.0-waveshare-4b-bootloader.bin \
    0x8000  /out/notyas-0.2.0-waveshare-4b-partition-table.bin \
    0x10000 /out/notyas-0.2.0-waveshare-4b-app.bin
```

### 3.4 Host recipe (development; NOT normative)

Unchanged from today: `tools\build.ps1 -Board <board> --release`, then
`tools\flash.ps1`. It will not match the container output, and the reasons are
enumerable rather than mysterious: a different libclang (pip wheel, item 16), a
globbed GCC (item 15), a different espflash build (item 17), CRLF checkout
(item 22), and Windows path handling in anything that escapes the prefix maps.
Treat any accidental match as luck.

Two things the host recipe must nevertheless adopt, because they are correctness
fixes independent of reproducibility: the `-ffile-prefix-map` CFLAGS addition
(item 6) and the `CONFIG_APP_PROJECT_VER_FROM_CONFIG` pin (item 9).

A Linux host recipe (no Docker: install IDF v5.5.4 via `install.sh`, rustup with
the pinned nightly, the same env block) is publishable and *may* reproduce
byte-identical output if every version in `toolchain.lock` matches. Document it
as best-effort; when it diverges, the container wins by definition.

OPEN: publish a Nix flake as a second, independent pinning mechanism? It would
give a stronger pin than a Docker digest (full dependency closure, content
addressed) and appeals to a subset of verifiers, but ESP-IDF under Nix is a
maintenance burden. Recommend: no for 0.2.0; revisit if a contributor owns it.

### 3.5 Artifact set and naming

Board slugs reuse the ones `tools/build.ps1` and `docs/BOARDS.md` already
define, so there is exactly one vocabulary for a board across the repo. Only the
two hardware-verified boards get release artifacts; the eight untested scaffolds
are compile-checked in CI and shipped as source only (BOARDS.md status table).

For `<board>` in {`waveshare-4b`, `elecrow-5`}:

| Artifact | Notes |
| --- | --- |
| `notyas-<ver>-<board>-app.bin` | flashed at 0x10000; the one users verify |
| `notyas-<ver>-<board>-bootloader.bin` | flashed at 0x2000; differs per board (flash size) |
| `notyas-<ver>-<board>-partition-table.bin` | flashed at 0x8000; identical across boards |
| `notyas-<ver>-<board>-merged.bin` | 0x2000..end, 0xFF padded; single-file flashing |
| `notyas-<ver>-<board>.elf` | unstripped release ELF; enables real triage (section 4.5) |
| `notyas-<ver>-<board>-sdkconfig.txt` | merged sdkconfig actually used |
| `notyas-<ver>-<board>-BUILDINFO.txt` | toolchain versions, env, input hashes |
| `notyas-<ver>-src.tar.gz` | `git archive` of the tag, deterministic packing |
| `notyas-<ver>-components.tar.gz` | archival mirror of the managed components (item 19) |
| `SHA256SUMS.txt` | over every file above |
| `SHA256SUMS.txt.asc` | detached armored GPG signature |

DECISION: publish `app.bin`, `bootloader.bin` and `partition-table.bin`
separately *and* the merged image, and require all four to reproduce. A verifier
who only checks the merged image cannot tell which region diverged; a verifier
who only checks `app.bin` is not checking the bootloader, which is code that
runs before ours and (with secure boot or flash encryption in play) decides
whether ours runs at all. The bootloader is built from our pinned sdkconfig, so
it is ours to be accountable for.

---

## 4. Verifying a release as a third party

### 4.1 The steps

```sh
# 1. Get the source at the exact tag and check the tag's own signature.
git clone https://github.com/<org>/notyas && cd notyas
git tag -v v0.2.0                       # must show the fingerprint in section 5

# 2. Get the published artifacts (release page) into ./published/

# 3. Check the publisher's signature over the hash list.
gpg --verify published/SHA256SUMS.txt.asc published/SHA256SUMS.txt

# 4. Rebuild, exactly as in section 3.3.
docker build -t notyas-repro:0.2.0 -f tools/repro/Dockerfile .
docker run --rm -v "$PWD":/mnt/src:ro -v "$PWD/out":/out \
       notyas-repro:0.2.0 waveshare-4b

# 5. Byte-compare. This is the whole point; do not skip to hashes only.
cd out && sha256sum -c <(grep waveshare-4b ../published/SHA256SUMS.txt)
cmp notyas-0.2.0-waveshare-4b-app.bin ../published/notyas-0.2.0-waveshare-4b-app.bin
```

Steps 3 and 5 answer different questions and both are needed: 3 says the
maintainer published these hashes, 5 says these hashes are what the source
compiles to.

### 4.2 What to compare, and why the bootloader and partition regions matter

Compare all four flashable artifacts, not just the app:

- **`app.bin`** - our Rust plus the linked IDF. The bulk of the trust.
- **`bootloader.bin`** - runs before `app_main`, chooses and (under secure boot)
  authenticates the app, and is where the chip-revision gate lives. Our
  `sdkconfig.base.defaults` sets `CONFIG_ESP32P4_SELECTS_REV_LESS_V3` and
  `CONFIG_ESP32P4_REV_MIN_100` precisely because a bootloader built for the
  wrong revision family flashes fine and then never boots. A substituted
  bootloader is a complete compromise that an app-only comparison misses.
- **`partition-table.bin`** - defines what exists in flash. The whole stateless
  claim (SECURITY.md invariant 2: no NVS, no data partitions, nothing written at
  runtime) is encoded in these 3 KB. If this region differs from the repo CSV,
  the device is not the device the security model describes. It is identical
  across both boards, so it is also the cheapest self-test of a verifier's
  toolchain.
- **`merged.bin`** - derived; must equal the concatenation with 0xFF padding. If
  the three regions match and the merged image does not, the bug is in the
  merging tool or its `--flash-size`, not in the firmware.

### 4.3 Relating an artifact to the device in your hand

The Verify screen shows the **running-partition SHA-256**, read at boot via
`esp_partition_get_sha256()` over the running app partition
(firmware/src/verify.rs - deliberately hashed from flash, never a compiled-in
constant). Note carefully: for an app image with the hash appended, that value is
the digest of the **image content**, which is *not* the same number as
`sha256sum app.bin` (the file digest covers the appended 32-byte digest too).
Both numbers are legitimate; confusing them is the single most likely support
question, so VERIFYING.md must state it plainly.

```sh
# The number the device shows (image-content digest = the appended digest):
tail -c 32 notyas-0.2.0-waveshare-4b-app.bin | xxd -p -c 32

# ...which must equal the digest recomputed over everything before it:
head -c $(( $(stat -c%s notyas-0.2.0-waveshare-4b-app.bin) - 32 )) \
     notyas-0.2.0-waveshare-4b-app.bin | sha256sum

# The number in SHA256SUMS.txt (file digest, covers the appended digest):
sha256sum notyas-0.2.0-waveshare-4b-app.bin
```

Confirm this relationship empirically during M-REPRO-5 and pin it as a test;
the exact appended-hash layout is set by the image producer (item 17), and
secure boot v2 appends a signature block after it, shifting nothing but adding
bytes.
https://docs.espressif.com/projects/esp-idf/en/v5.5.1/esp32p4/api-reference/system/app_image_format.html

### 4.4 Triage: a diff appeared

Work outside-in. Each step is cheap and eliminates a class.

1. **Compare BUILDINFO.txt first.** Toolchain versions, environment, input
   hashes (`bindings.rs`, merged sdkconfig, Cargo.lock, components lock). Most
   diffs die here: a different image digest, a different espflash, a stale
   components lock.
2. **Compare the merged sdkconfig** (`diff -u` the two `*-sdkconfig.txt`). A
   single differing `CONFIG_*` explains an arbitrarily large binary diff. The
   most likely offender is the flash-size line (item 23's trap: wrong or missing
   `ESP_IDF_SDKCONFIG_DEFAULTS`).
3. **Locate the diff by region.**
   ```sh
   cmp -l a.bin b.bin | wc -l                 # how many bytes differ
   cmp -l a.bin b.bin | head                  # first differing offset (1-based!)
   cmp -l a.bin b.bin | awk '{printf "%x\n",$1-1}' | cut -c1-3 | uniq -c | head
   ```
   A handful of bytes near the start of the app image (roughly offsets
   0x20..0x90, the `esp_app_desc_t`) means metadata: version string, IDF
   version, timestamp, or the `app_elf_sha256` tripwire (item 11) telling you
   the ELF differed. Diffs scattered across the whole image mean codegen or a
   layout shift.
4. **Look at the image header and descriptor with an independent tool.**
   ```sh
   esptool image_info --version 2 a.bin > a.txt
   esptool image_info --version 2 b.bin > b.txt
   diff -u a.txt b.txt      # flash size/mode/freq, segments, app version, IDF version
   ```
5. **If the ELFs differ, diff the ELFs, not the images.** This is why we publish
   the ELF.
   ```sh
   riscv32-esp-elf-readelf -S a.elf > a.sec; ... ; diff -u a.sec b.sec   # section sizes
   riscv32-esp-elf-nm --size-sort a.elf > a.sym; ... ; diff -u a.sym b.sym
   riscv32-esp-elf-objdump -d a.elf > a.dis; ... ; diff -u a.dis b.dis | head -100
   diffoscope a.elf b.elf     # if available: does all of the above and more
   ```
   Section sizes identical but content different points at path or string leakage;
   run `strings -a a.elf | sort > a.str` on both and diff - an absolute path in
   the diff names its own cause (items 1-6).
6. **Regions expected to differ, ever.** Under the normative recipe: **none.**
   That is the claim. The honest exceptions, all of which are *not* the same
   artifact and must be labeled as such:
   - a secure-boot-signed image versus an unsigned one (an appended signature
     block; Jade documents exactly this as their only expected difference);
   - a build of a *different board slug* (flash size in the header, plus the
     cfg-gated Rust);
   - a debug-profile build versus `--release` (the root Cargo.toml gives dev
     `opt-level = "z"` with `debug = true`, release `opt-level = "s"`);
   - a dirty working tree (the script refuses this for releases).
   If a diff persists after steps 1-5 with none of these in play, that is a
   **bug in this recipe** and it gets filed and fixed, not explained away. A
   reproducible build with a "known harmless differences" section is not a
   reproducible build.

### 4.5 Reporting

File an issue with: both BUILDINFO.txt files, both `*-sdkconfig.txt`, the
`cmp -l | head` output, the `esptool image_info` diff, and the host details.
That set is nearly always enough to identify the cause without access to the
reporter's machine.

---

## 5. The signing layer

### 5.1 What is signed

One file: `SHA256SUMS.txt`, listing every artifact from section 3.5 in
`sha256sum` format (lowercase hex, two spaces, filename, no paths). One detached
armored signature: `SHA256SUMS.txt.asc`. Plus the annotated git tag, which is
itself signed (`git tag -s`, as `tools/release.sh` already does for 0.1.0), so
the source revision is authenticated independently of the artifact hosting.

DECISION: hash list plus one detached signature, rather than signing each binary.
It is one verification step for the user, it covers source tarballs and text
artifacts uniformly, and it is the convention verifiers already know from
Bitcoin Core and every hardware-wallet vendor.

### 5.2 The key

Fingerprint **A1E9 53B2 5C6A 623B 77A1 D522 3AC4 BBCF E51A B37D** (the BigDice
release key; notyas is signed with the same identity, per docs/SECURITY.md
invariant 5).

Publication, so that "get the key" does not reduce to "trust the same server
that served the binary":
- `docs/keys/A1E953B25C6A623B77A1D5223AC4BBCFE51AB37D.asc` in this repository
  (so the key's history is in git, alongside the signed tags that use it);
- keys.openpgp.org (fetchable by fingerprint);
- the maintainer's GitHub profile / the BigDice repository, which already
  carries the same key.

VERIFYING.md must tell the user to compare the **full 40-hex-digit fingerprint**
against at least two of those sources, and must never print a short key id.

OPEN: signing-key hygiene for 0.2.0 - is the release key on a hardware token
(YubiKey/OpenPGP card), and is there a documented revocation path and a
published revocation certificate? Recommend: yes to the token before 0.2.0 ships
(a wallet vendor's release key on a general-purpose disk is the weakest link in
the chain this document builds), plus a pre-generated revocation certificate
held offline. Cheap, one-time, and it is the kind of thing users ask about.

OPEN: multi-party attestation. Reproducibility only pays off when someone else
actually rebuilds. Recommend: for 0.2.0, recruit at least one independent builder
to publish their own signed `SHA256SUMS.txt` for the same tag, and add a
`attestations/` directory collecting them. Coldcard's credibility here comes
from third parties publicly matching builds, not from Coinkite's own claim.

OPEN: secure boot key ownership. SECURITY.md invariant 6 says release hardware
runs Secure Boot v2 RSA-3072 + XTS-AES flash encryption, but does not say whose
key. Options: (a) we sign images with a vendor key and burn the corresponding
digest - locks the user out of running their own builds, which contradicts a
GPL3 verify-it-yourself device; (b) ship unsigned images plus a documented
procedure for the *user* to generate their own secure-boot key and burn it -
preserves user control, at the cost of a nontrivial one-way eFuse step; (c) both,
as separate download channels. Recommend (b) as the default with (a) available
only if we ever ship assembled units. Note the reproducibility interaction: a
vendor-signed image can never be byte-reproduced by anyone without the key, so
under (a) the *unsigned* image must also be published and be the object of the
reproducibility claim (this is exactly how Jade frames it: the only expected
difference between local and official is the appended signature block).

### 5.3 VERIFYING.md outline (repo root, aimed at a non-expert)

Written for someone who has never used GPG, on the assumption they will read
three screens and no more. Ordered by effort, with the honest value of each
level stated:

1. **What this proves, in one paragraph.** Signature = "notyas published this".
   Reproducible build = "this file is what the published source compiles to".
   Neither proves the source is safe; both are prerequisites for anyone checking.
2. **Level 1 (2 minutes): check the hash.** Download the artifact and
   `SHA256SUMS.txt`; run `sha256sum -c` (or `Get-FileHash` on Windows, or
   `shasum -a 256` on macOS - give all three verbatim). Says the download is not
   corrupted or swapped in transit.
3. **Level 2 (10 minutes): check the signature.** Install GPG; fetch the key;
   **compare the full fingerprint** against the two published locations;
   `gpg --verify SHA256SUMS.txt.asc SHA256SUMS.txt`. Explain what "Good
   signature" plus "WARNING: This key is not certified with a trusted
   signature" means, because everyone sees that warning and half of them
   conclude something is wrong.
4. **Level 3 (30-60 minutes, mostly waiting): rebuild it yourself.** The four
   commands from section 4.1. State the expected wall-clock time and disk usage
   so nobody thinks it hung.
5. **Level 4: check the device, not the file.** Verify screen walkthrough:
   firmware version, running-app SHA-256 and how it relates to the published
   artifact (section 4.3, with the file-digest-versus-image-digest distinction
   spelled out), IDF version and chip revision, self-test result, radio kill-GPIO
   reading, secure-boot and flash-encryption state. Explain that dev units
   honestly report secure boot as disabled and why that is reported rather than
   hidden.
6. **If something does not match.** Do not flash it. Steps 1-2 of the triage
   guide in plain language, and where to file.
7. **Which board am I verifying?** One short table mapping the two boards to
   their artifact names, with a warning that cross-board comparison always fails
   and is not a bug.

---

## 6. CI

### 6.1 What CI can check without a firmware build

Already established as the cheap tier (docs/plan-0.2.0/MILESTONES.md, and
`tools/build-graph-check.sh` in-repo):

- host unit tests and BIP vector tests over `crates/notyas-core` (equivalence,
  invariant 4);
- `cargo clippy` across the workspace's default members;
- the no_std check: `notyas-ui` built for a bare-metal `riscv32imac` target,
  which is what proves the `qr`/std feature does not leak into the UI graph;
- `tools/build-graph-check.sh`, which walks every Cargo.lock and fails on a
  banned crate (rand/getrandom/ring/reqwest/hyper/tokio/...), enforcing
  SECURITY.md invariants 1 and 3;
- `cargo build --locked` everywhere, so lock drift is a CI failure;
- documentation and hash-consistency lints (fingerprint string, board slug
  vocabulary, SHA256SUMS format).

None of these need ESP-IDF, Docker, or nightly. They should run on every push.

### 6.2 What needs the container

The firmware build, and therefore: the reproducibility check itself, the
artifact production, and any on-target size regression check.

**Verdict: yes, a GitHub-hosted runner can do the reproducible firmware build.**
Not through `espressif/esp-idf-ci-action`, which wraps the IDF image around
`idf.py build` - our build is cargo-driven (`esp-idf-sys` invokes CMake itself),
so the action's contract does not fit. Use the job-level `container:` key with
our own digest-pinned image instead, or plain `docker run`, which keeps CI and
local verification running *the identical script*: that identity is worth more
than any convenience the action offers.
https://github.com/espressif/esp-idf-ci-action

Feasibility against the runner limits: `ubuntu-latest` on a public repository
provides 4 vCPU / 16 GB RAM / 14 GB SSD, free and unlimited, with a 6-hour
per-job ceiling. RAM and time are comfortable; **disk is the binding
constraint** (the IDF image unpacks to several GB, and each board's build tree
adds the IDF C build plus `-Zbuild-std` plus secp256k1).
https://docs.github.com/en/actions/reference/github-hosted-runners-reference ,
https://docs.github.com/en/actions/reference/actions-limits

Design that fits:

- one job **per board** in a matrix (never two board trees on one 14 GB runner);
- cache the cargo registry only (`actions/cache` keyed on Cargo.lock). Caching
  cannot change the output: Cargo.lock pins checksums. Do not cache the target
  dir - a stale artifact is exactly the failure mode this whole document exists
  to prevent;
- run it on tags and on a nightly schedule, plus on PRs that touch
  `firmware/`, `crates/`, `tools/repro/` or the lockfiles - not on every push;
- publish artifacts plus `BUILDINFO.txt` and the job's computed `SHA256SUMS.txt`.

Expected cost: to be measured in M-REPRO-9. Order-of-magnitude expectation for a
cold 4-vCPU build (IDF C build + build-std + secp256k1, no LTO): tens of minutes
per board, well inside the 6-hour ceiling. Recording the measured number in
BUILDINFO is itself useful - a sudden change in build time is a signal.

### 6.3 The check that actually proves reproducibility

A single build proves nothing. The strong CI gate is a **double build that
varies everything the recipe claims is irrelevant, while holding fixed
everything it pins** (the reprotest idea, narrowed to our recipe):

vary: the host checkout path, the runner user and uid, hostname, `TZ`, locale,
wall-clock time (run the second build later, or on a different day's schedule),
build parallelism (`-j`), and the host OS image generation;
hold fixed: the container digest, `toolchain.lock`, the in-container paths, the
sdkconfig pair, both lockfiles.

Then `cmp` the two outputs. This catches path and environment leakage
automatically, on every run, before a user ever finds it. Escalation: a third
build in a self-hosted or differently-architected environment (arm64 runners are
free for public repositories, and an arm64 host running the same amd64 image
under emulation, or a native arm64 image, is a genuinely independent test of
whether *host* architecture leaks into our artifacts).

Release gate: the tag workflow builds both boards, runs the double-build check,
and **fails the release** if the produced hashes differ from the ones the
maintainer committed in the release PR. The maintainer's local container build
and CI's container build must agree before anything is signed. Signing itself
stays off CI - the key never touches a hosted runner.

---

## 7. Implementation checklist (for MILESTONES.md)

Ordered; each item has a mechanical gate. Sized as a small milestone (PLATFORM.md
rates the contribution "Effort: S"); items 1-8 are the substance, 9-12 are
publication.

1. **M-REPRO-1 - inventory and baseline.** Build both boards twice on this bench
   with today's toolchain; `cmp` the outputs. Record what already differs. Gate:
   a written baseline in the tracking issue (expected: differs, with a `strings`
   grep naming the UNC path and `C:\nyt-*`).
2. **M-REPRO-2 - sdkconfig pins.** Add to `firmware/sdkconfig.base.defaults`:
   `CONFIG_APP_REPRODUCIBLE_BUILD=y`, `CONFIG_APP_PROJECT_VER_FROM_CONFIG=y`,
   `CONFIG_APP_PROJECT_VER="0.2.0"`. Gate: both boards still boot and the Verify
   screen is unchanged except for the version string; `esptool image_info` shows
   a zeroed compile time.
3. **M-REPRO-3 - path remapping.** Enable cargo `trim-paths` for the release
   profile; add `-ffile-prefix-map` to the `CFLAGS_riscv32imafc_esp_espidf` set
   in build.ps1 and the container script. Gate:
   `strings app.bin | grep -Ei '172\.16|nyt-|Users|\.cargo|\.espressif|rustlib'`
   is empty, and the `/rustc/<hash>` prefix matches `rustc -vV`.
4. **M-REPRO-4 - toolchain lock + container.** `tools/repro/Dockerfile`
   (digest-pinned `espressif/idf:v5.5.4`, nightly-2026-07-27 + rust-src, pinned
   ldproxy/espflash, resolved libclang per item 16), `tools/repro/toolchain.lock`,
   `tools/repro/build.sh` with the clean-environment and assertion steps from
   3.3. Resolve the espflash-versus-esptool question (item 17). Gate: the script
   aborts on any deliberately mismatched lock entry; both boards build.
5. **M-REPRO-5 - artifact production and naming.** Emit the full section 3.5 set
   plus `BUILDINFO.txt`; pin the app-digest relationship of section 4.3 as a test.
   Gate: `sha256sum -c` round-trips; the merged image flashes and boots on both
   verified boards.
6. **M-REPRO-6 - the double-build check.** `tools/repro/check-repro.sh`: two
   container builds with varied host-side conditions, `cmp` all artifacts. Gate:
   byte-identical on both boards, locally.
7. **M-REPRO-7 - CI wiring.** Per-board matrix job with the pinned container;
   registry-only cache; artifact upload; the double-build gate; on tags,
   schedule, and relevant paths. Gate: green twice in a row on two different
   days, with the measured wall-clock and peak disk recorded.
8. **M-REPRO-8 - source id on the Verify screen.** Replace `source_id:
   "unavailable"` in firmware/src/verify.rs with a value derived from the source
   revision and reproducible inputs (candidate: the git tree hash of the tagged
   tree, or the digest of the source tarball, compiled in by the container
   script). Gate: the value on screen matches a documented one-line command a
   verifier can run against the published source. Note this is a firmware
   change - it belongs to the firmware owner's queue, not to this document's.
9. **M-REPRO-9 - VERIFYING.md.** Write it to the section 5.3 outline, at the
   repository root. Gate: someone who has not used GPG completes levels 1-2
   unaided; the level-3 timing statement matches the measured CI numbers.
10. **M-REPRO-10 - key publication and hygiene.** Key in `docs/keys/`, on
    keys.openpgp.org, and on the maintainer profile; resolve the hardware-token
    and revocation-certificate OPEN. Gate: `gpg --verify` succeeds from a clean
    machine following only VERIFYING.md.
11. **M-REPRO-11 - release automation.** Extend `tools/release.sh` past
    tag-and-push: build both boards in the container, generate SHA256SUMS.txt,
    sign locally (never in CI), and refuse to publish if CI's hashes disagree.
    Gate: a dry run on a release-candidate tag.
12. **M-REPRO-12 - publish upstream.** PLATFORM.md contribution #6: publish the
    recipe as a standalone document plus a minimal working example repository
    (esp-idf-sys + `-Zbuild-std` + trim-paths + IDF container), and offer it to
    the esp-rs community docs. Gate: the example repo's CI reproduces its own
    binary; a link from this file.

Not in scope for 0.2.0, recorded so it is not forgotten: secure-boot-signed
release images and eFuse burning (blocked on the section 5.2 OPEN), OTA (there
is none by design - ARCHITECTURE.md), and reproducibility for the eight untested
board scaffolds (compile-checked only until hardware verification).

---

## Sources

ESP-IDF and Espressif tooling:
- https://docs.espressif.com/projects/esp-idf/en/v5.5.1/esp32p4/api-guides/reproducible-builds.html
- https://docs.espressif.com/projects/esp-idf/en/v5.5.1/esp32p4/api-guides/tools/idf-docker-image.html
- https://docs.espressif.com/projects/esp-idf/en/v5.5.1/esp32p4/api-reference/system/app_image_format.html
- https://docs.espressif.com/projects/esp-idf/en/v5.5.1/esp32p4/api-reference/storage/partition.html
- https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-guides/build-system.html
- https://docs.espressif.com/projects/esptool/en/latest/esp32p4/esptool/flashing-firmware.html
- https://hub.docker.com/r/espressif/idf/tags
- https://github.com/espressif/esp-idf/issues/9071
- https://github.com/espressif/esp-idf-ci-action

Rust toolchain:
- https://doc.rust-lang.org/rustc/command-line-arguments.html
- https://doc.rust-lang.org/nightly/cargo/reference/unstable.html#profile-trim-paths-option
- https://rust-lang.github.io/rfcs/3127-trim-paths.html
- https://github.com/rust-lang/rust/issues/73167
- https://github.com/rust-lang/rust/issues/129080
- https://github.com/rust-lang/rust-bindgen/blob/main/CONTRIBUTING.md

esp-rs:
- https://github.com/esp-rs/esp-idf-sys/blob/master/BUILD-OPTIONS.md
- https://github.com/esp-rs/espflash/issues/714
- https://github.com/esp-rs/espflash/issues/715

Prior art:
- https://github.com/Blockstream/Jade/blob/master/REPRODUCIBLE.md
- https://github.com/Coldcard/firmware/blob/master/docs/notes-on-repro.md
- https://coldcard.com/resources/security/coldcard-security-and-verification

CI limits:
- https://docs.github.com/en/actions/reference/github-hosted-runners-reference
- https://docs.github.com/en/actions/reference/actions-limits

Repo files consulted (not edited): firmware/Cargo.toml, firmware/.cargo/config.toml,
firmware/rust-toolchain.toml, firmware/components_esp32p4.lock,
firmware/sdkconfig.base.defaults, firmware/boards/*/sdkconfig.defaults,
firmware/partitions.csv, firmware/src/verify.rs, tools/build.ps1, tools/flash.ps1,
tools/release.sh, tools/build-graph-check.sh, Cargo.toml (workspace),
docs/SECURITY.md, docs/plan-0.2.0/{SECURITY,ARCHITECTURE,PLATFORM,PARITY}.md.

Input to: MILESTONES.md (section 7), OPEN-QUESTIONS.md (the OPEN: lines),
PLATFORM.md contribution #6.
