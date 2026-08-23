#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# notyas - the normative release build for one board.
#
# Licence note: this file, tools/repro/Dockerfile and tools/repro/toolchain.lock
# are the container definition, and .github/workflows/repro.yml is the CI
# workflow. Those are the reproducible-build recipe's copyable artifacts and are
# permissively licensed on purpose (MILESTONES 0.2.0-m12): a recipe a reader has
# to licence-audit before pasting is a recipe nobody follows. Everything else in
# the repository is GPL-3.0-or-later.
#
# This script IS the definition of a notyas release artifact. A file that some
# other command produced is not a release artifact, however identical it looks,
# because the point of the exercise is that a stranger can run this exact script
# and get the same bytes.
#
# Usage, from the repository root on any x86-64 Linux host with Docker:
#
#   docker build -t notyas-repro -f tools/repro/Dockerfile .
#   docker run --rm -v "$PWD":/mnt/src:ro -v "$PWD/out":/out notyas-repro waveshare-4b
#
# Options:
#   --bootstrap   fill in the "pending" entries of toolchain.lock instead of
#                 asserting them, and mark the run as not-a-release.
#   --dirty       build an uncommitted tree. Never a release; the source tarball
#                 and the source id would describe a tree nobody else has.
#   --list-boards print the release board slugs, one per line, and exit. CI and
#                 tools/repro/check-repro.sh take their matrix from here so the
#                 board vocabulary has exactly one definition.
#
# What this script guarantees, and what it does not: it neutralises every source
# of nonreproducibility enumerated in docs/plan-0.2.0/REPRODUCIBLE.md section 2
# that is inside our control, and it asserts the ones that are not. It cannot
# make a build reproducible that was never run twice, which is what
# tools/repro/check-repro.sh is for.

set -euo pipefail

# ---------------------------------------------------------------------------
# Fixed paths. These are constants, not preferences: a build that happens at a
# fixed path on every machine has no machine-local path to leak, which is the
# cheapest half of the fix for REPRODUCIBLE.md items 1 to 6. cargo trim-paths
# then removes even these, so the artifacts contain neither.
SRC_MOUNT=/mnt/src
SRC=/build/src
TARGET=/build/target
OUT=/out
# Resolved from this script rather than hardcoded to /opt/notyas: inside the
# image it is /opt/notyas, and outside it the lock and the manifest tool are
# still the ones that sit beside this file, which is what makes the assertion
# stage exercisable without a container.
SELF_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
LOCK="$SELF_DIR/toolchain.lock"
MANIFEST_TOOL="$SELF_DIR/verify-manifest.py"

# The image's own locations. Overridable only so the script can be exercised
# outside the container during development; a release build uses the defaults.
IDF_PATH_DEFAULT=/opt/esp/idf
IDF_TOOLS_PATH_DEFAULT=/opt/esp
RUSTUP_HOME_DEFAULT=/opt/rust/rustup
CARGO_HOME_DEFAULT=/opt/rust/cargo

# ---------------------------------------------------------------------------
# The release board vocabulary. Only the two hardware-verified boards get
# release artifacts; the eight untested scaffolds are compile-checked in CI and
# shipped as source (docs/BOARDS.md status table, REPRODUCIBLE.md 3.5).
#
# Fields: slug | cargo feature | espflash flash-size | expected sdkconfig symbol
#
# When m11 lands, the camera variant is one more row here - slug
# waveshare-4b-camera, its own cargo feature - because ratified Q47 makes the
# camera a separately hashed build variant rather than a runtime capability.
# Adding the row is all it takes: the CI matrix, check-repro.sh and the artifact
# set all read this table.
BOARDS="
waveshare-4b|board-waveshare-4b|32mb|CONFIG_ESPTOOLPY_FLASHSIZE_32MB
elecrow-5|board-elecrow-5|16mb|CONFIG_ESPTOOLPY_FLASHSIZE_16MB
"

board_slugs() {
    printf '%s\n' "$BOARDS" | sed '/^$/d' | cut -d'|' -f1
}

board_field() {
    printf '%s\n' "$BOARDS" | sed '/^$/d' | awk -F'|' -v s="$1" -v n="$2" '$1 == s { print $n }'
}

die() {
    printf 'build.sh: %s\n' "$*" >&2
    exit 1
}

step() {
    printf '\n=== %s\n' "$*"
}

# ---------------------------------------------------------------------------
# --list-boards is answered before anything else so a caller can read the matrix
# without a container, a source mount or a lock file.
if [ "${1:-}" = "--list-boards" ]; then
    board_slugs
    exit 0
fi

BOARD=""
BOOTSTRAP=0
DIRTY_OK=0
for arg in "$@"; do
    case "$arg" in
        --bootstrap) BOOTSTRAP=1 ;;
        --dirty) DIRTY_OK=1 ;;
        --*) die "unknown option $arg" ;;
        *)
            [ -z "$BOARD" ] || die "more than one board given ($BOARD, $arg)"
            BOARD="$arg"
            ;;
    esac
done
[ -n "$BOARD" ] || die "usage: build.sh <board> [--bootstrap] [--dirty]; boards: $(board_slugs | tr '\n' ' ')"
FEATURE=$(board_field "$BOARD" 2)
FLASH_SIZE=$(board_field "$BOARD" 3)
FLASH_SYMBOL=$(board_field "$BOARD" 4)
[ -n "$FEATURE" ] || die "unknown board '$BOARD'; boards: $(board_slugs | tr '\n' ' ')"

# ---------------------------------------------------------------------------
# Step 1: a clean environment.
#
# REPRODUCIBLE.md item 21 lists the variables that change codegen in this exact
# stack - RUSTFLAGS, RUSTC_WRAPPER, CARGO_INCREMENTAL, the CC/CFLAGS family,
# every ESP_IDF_*, LIBCLANG_PATH, TZ, LC_ALL, PATH. Rather than unset a list
# that will fall out of date, start from nothing and add back what is needed.
# The values below are the only inherited ones, and they are locations, not
# behaviour.
if [ "${NOTYAS_REPRO_CLEAN:-0}" != "1" ]; then
    exec env -i \
        NOTYAS_REPRO_CLEAN=1 \
        HOME="${HOME:-/root}" \
        TERM=dumb \
        PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
        IDF_PATH="${IDF_PATH:-$IDF_PATH_DEFAULT}" \
        IDF_TOOLS_PATH="${IDF_TOOLS_PATH:-$IDF_TOOLS_PATH_DEFAULT}" \
        RUSTUP_HOME="${RUSTUP_HOME:-$RUSTUP_HOME_DEFAULT}" \
        CARGO_HOME="${CARGO_HOME:-$CARGO_HOME_DEFAULT}" \
        LIBCLANG_PATH="${LIBCLANG_PATH:-}" \
        "$0" "$@"
fi

# The re-exec above supplies all four, but the script must also survive being
# entered with NOTYAS_REPRO_CLEAN already set - by a debugging session, or by a
# caller that did its own environment scrubbing - rather than dying on an unbound
# variable three lines later.
: "${IDF_PATH:=$IDF_PATH_DEFAULT}"
: "${IDF_TOOLS_PATH:=$IDF_TOOLS_PATH_DEFAULT}"
: "${RUSTUP_HOME:=$RUSTUP_HOME_DEFAULT}"
: "${CARGO_HOME:=$CARGO_HOME_DEFAULT}"
export IDF_PATH IDF_TOOLS_PATH RUSTUP_HOME CARGO_HOME

export TZ=UTC
export LC_ALL=C
export LANG=C
umask 022
export PATH="$CARGO_HOME/bin:$PATH"

# Two git facts about reading a bind-mounted repository from inside a container,
# both of which otherwise present as a confusing refusal rather than an error:
# the mount is owned by the host user while this runs as the image's user, which
# modern git rejects as "dubious ownership", and several read-only-looking
# commands will try to take a lock or refresh the index on a read-only mount.
# Setting these through the environment avoids writing to a global git config.
export GIT_OPTIONAL_LOCKS=0
export GIT_CONFIG_COUNT=1
export GIT_CONFIG_KEY_0=safe.directory
export GIT_CONFIG_VALUE_0="*"

step "activating ESP-IDF from $IDF_PATH"
[ -f "$IDF_PATH/export.sh" ] || die "no ESP-IDF at $IDF_PATH - this script runs inside the image built from tools/repro/Dockerfile"
# export.sh is chatty and references unset variables while it works, so the
# strict flags come back on immediately afterwards rather than being disabled
# for the rest of the run.
set +u
# shellcheck disable=SC1091
. "$IDF_PATH/export.sh" > /dev/null
set -u

# ---------------------------------------------------------------------------
# Step 2: assert the toolchain lock.

[ -f "$LOCK" ] || die "toolchain lock not found at $LOCK"

lock_get() {
    awk -F' *= *' -v k="$1" '$1 == k { print $2; found = 1 } END { if (!found) exit 3 }' "$LOCK" \
        || die "toolchain.lock has no entry '$1'"
}

OBSERVED=""
FAILED_PINS=0
assert_pin() {
    # $1 key, $2 observed value. A pending pin is recorded, not asserted; a
    # recorded pin that disagrees is fatal, because from here on every number
    # this build publishes would describe a toolchain nobody else has.
    local key="$1" got="$2" want
    want=$(lock_get "$key")
    if [ -z "$got" ]; then
        # An empty observation means the probe broke, not that the tool has no
        # version. Recording it would write an empty pin into the lock, and an
        # empty pin asserts nothing forever after.
        printf '  %-20s <no output>\n' "$key"
        FAILED_PINS=$((FAILED_PINS + 1))
        return 0
    fi
    OBSERVED="${OBSERVED}${key} = ${got}
"
    if [ "$want" = "pending" ]; then
        printf '  %-20s %s   (pending in the lock)\n' "$key" "$got"
        return 0
    fi
    if [ "$want" != "$got" ]; then
        printf '  %-20s %s\n       LOCK SAYS      %s\n' "$key" "$got" "$want"
        FAILED_PINS=$((FAILED_PINS + 1))
        return 0
    fi
    printf '  %-20s %s\n' "$key" "$got"
}

first_line() { head -n 1; }

step "asserting $LOCK"

# rustc identity, including the commit hash: with -Zbuild-std the standard
# library is compiled from this toolchain's rust-src, so a substituted nightly
# changes core, alloc and std as well as our crates.
RUSTC_VV=$(rustc -vV)
assert_pin rustc_version    "$(printf '%s\n' "$RUSTC_VV" | awk '/^release:/ { print $2 }')"
assert_pin rustc_commit_hash "$(printf '%s\n' "$RUSTC_VV" | awk '/^commit-hash:/ { print $2 }')"
assert_pin rustc_commit_date "$(printf '%s\n' "$RUSTC_VV" | awk '/^commit-date:/ { print $2 }')"
assert_pin cargo_version    "$(cargo -V | awk '{ print $2 }')"
# ldproxy has no --version flag, so its pin is read from what cargo installed.
assert_pin ldproxy_version  "$(cargo install --list | awk '/^ldproxy v/ { sub(/^v/, "", $2); sub(/:$/, "", $2); print $2; exit }')"
assert_pin espflash_version "$(espflash -V | awk '{ print $2 }')"

# esptool is the reference implementation of our image format and reads what
# espflash writes; the spelling of its entry point changed between major
# versions, so probe rather than assume (ratified Q27 keeps both in play).
ESPTOOL=""
for candidate in esptool.py esptool; do
    if command -v "$candidate" > /dev/null 2>&1; then ESPTOOL="$candidate"; break; fi
done
[ -n "$ESPTOOL" ] || die "neither esptool.py nor esptool is on PATH inside the image"
assert_pin esptool_version "$("$ESPTOOL" version 2>&1 | first_line | awk '{ print $NF }')"

assert_pin gcc_version    "$(riscv32-esp-elf-gcc -dumpversion)"
assert_pin cmake_version  "$(cmake --version | first_line | awk '{ print $3 }')"
assert_pin ninja_version  "$(ninja --version)"
assert_pin python_version "$(python3 -c 'import platform; print(platform.python_version())')"
assert_pin idf_git_describe "$(git -C "$IDF_PATH" describe --tags --always --dirty)"
# The tag, separately from the describe: it is the string that ends up inside
# the image as esp_app_desc_t.idf_ver and on the Verify screen, so it is asserted
# against the lock rather than merely recorded.
assert_pin idf_version "$(git -C "$IDF_PATH" describe --tags --abbrev=0 2>/dev/null || cat "$IDF_PATH/version.txt")"

# bindgen's output differs across libclang versions, so libclang is a build
# input on par with the compiler (REPRODUCIBLE.md item 16).
if [ -z "${LIBCLANG_PATH:-}" ]; then
    # find printing nothing is the case that matters: dirname of the empty
    # string is ".", which is a directory, so the guard below would pass and
    # LIBCLANG_PATH would be exported as "." - a missing libclang would then
    # surface as an unreadable bindgen failure deep inside the cargo build
    # instead of here. Catch the empty result before dirname sees it.
    LIBCLANG_SO=$(find "$IDF_TOOLS_PATH" /usr/lib -name 'libclang.so*' -print 2>/dev/null | sort | head -n 1)
    [ -n "$LIBCLANG_SO" ] || die "no libclang found under $IDF_TOOLS_PATH or /usr/lib; the image must install esp-clang-libs (REPRODUCIBLE.md item 16)"
    LIBCLANG_PATH=$(dirname "$LIBCLANG_SO")
fi
[ -d "$LIBCLANG_PATH" ] || die "no libclang found; set LIBCLANG_PATH in the Dockerfile (REPRODUCIBLE.md item 16)"
export LIBCLANG_PATH
assert_pin clang_version "$(clang --version 2>/dev/null | first_line | awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^[0-9]+\./) { print $i; exit } }')"

if [ "$FAILED_PINS" -gt 0 ]; then
    die "$FAILED_PINS toolchain pin(s) disagree with $LOCK. Either the image changed or the lock did; resolve it deliberately, do not edit the lock to match."
fi

PENDING=$(grep -c ' = pending$' "$LOCK" || true)
if [ "$PENDING" -gt 0 ] && [ "$BOOTSTRAP" -eq 0 ]; then
    printf '\n%s\n' "$LOCK still has $PENDING pending pin(s). Observed on this image:" >&2
    printf '%s' "$OBSERVED" >&2
    die "re-run with --bootstrap to build anyway, then commit the values above. A release build never runs against a pending lock."
fi

# ---------------------------------------------------------------------------
# Step 3: take the source.

step "taking the source from $SRC_MOUNT"
[ -f "$SRC_MOUNT/firmware/Cargo.toml" ] || die "$SRC_MOUNT does not look like the notyas repository"

GIT_COMMIT=$(git -C "$SRC_MOUNT" rev-parse HEAD 2>/dev/null || echo unknown)
GIT_DESCRIBE=$(git -C "$SRC_MOUNT" describe --tags --always --dirty 2>/dev/null || echo unknown)
if git -C "$SRC_MOUNT" diff-index --quiet HEAD -- 2>/dev/null; then
    TREE_CLEAN=1
else
    TREE_CLEAN=0
fi
if [ "$TREE_CLEAN" -eq 0 ] && [ "$DIRTY_OK" -eq 0 ]; then
    die "the working tree at $SRC_MOUNT has uncommitted changes. A dirty build cannot be reproduced by anyone else; pass --dirty for a development run."
fi

rm -rf "$SRC" "$TARGET"
mkdir -p "$SRC" "$TARGET" "$OUT"
if [ "$TREE_CLEAN" -eq 1 ]; then
    # git archive, not cp: it copies exactly the committed tree, so an ignored
    # build directory or a stray untracked file cannot become a build input.
    git -C "$SRC_MOUNT" archive --format=tar HEAD | tar -x -C "$SRC"
else
    # The documented invocation bind-mounts ./out INSIDE the source directory,
    # so a plain recursive copy would pull the output tree into the build tree
    # and grow it every run. tar with excludes is the copy that cannot.
    tar -C "$SRC_MOUNT" --exclude=./.git --exclude=./out --exclude=./target -cf - . \
        | tar -x -C "$SRC"
fi

# The tag's committer date, so anything that must carry a timestamp carries a
# value derived from the source rather than from the clock.
SOURCE_DATE_EPOCH=$(git -C "$SRC_MOUNT" log -1 --format=%ct 2>/dev/null || echo 0)
export SOURCE_DATE_EPOCH

VERSION=$(awk '/^\[package\]/ { in_pkg = 1; next } /^\[/ { in_pkg = 0 } in_pkg && /^version *=/ { gsub(/[",]/, "", $3); print $3; exit }' "$SRC/firmware/Cargo.toml")
[ -n "$VERSION" ] || die "could not read the firmware version from firmware/Cargo.toml"
printf '  version   %s\n  commit    %s\n  describe  %s\n  epoch     %s\n' \
    "$VERSION" "$GIT_COMMIT" "$GIT_DESCRIBE" "$SOURCE_DATE_EPOCH"

name() { printf 'notyas-%s-%s-%s' "$VERSION" "$BOARD" "$1"; }

# ---------------------------------------------------------------------------
# Step 4: the build environment.

step "building $BOARD ($FEATURE)"

# The version pin has one source of truth, firmware/Cargo.toml, and reaches the
# image through a generated defaults file. Writing "0.2.0" into a checked-in
# sdkconfig as well would be the same number in two places, and the two places
# would eventually disagree: esp_app_desc_t.version would say one thing and the
# Verify screen's env!("CARGO_PKG_VERSION") another. Without the pin, ESP-IDF
# falls back to `git describe` inside a generated CMake project under OUT_DIR,
# where what it sees is undefined (REPRODUCIBLE.md item 9).
VERSION_DEFAULTS=/build/repro-version.defaults
cat > "$VERSION_DEFAULTS" <<EOF
CONFIG_APP_PROJECT_VER_FROM_CONFIG=y
CONFIG_APP_PROJECT_VER="$VERSION"
EOF

export MCU=esp32p4
export CARGO_TARGET_DIR="$TARGET"
export CARGO_INCREMENTAL=0
export CARGO_NET_OFFLINE=false
# fromenv: use the ESP-IDF that is already in the image rather than letting
# embuild clone one at build time. The image digest is then the pin for the IDF
# source, CMake, Ninja, Python and the cross-compiler in one hash.
export ESP_IDF_TOOLS_INSTALL_DIR=fromenv
export ESP_IDF_SDKCONFIG_DEFAULTS="$SRC/firmware/sdkconfig.base.defaults;$SRC/firmware/boards/$BOARD/sdkconfig.defaults;$VERSION_DEFAULTS"

# secp256k1-sys is compiled by cargo, not by the IDF CMake build, so
# CONFIG_APP_REPRODUCIBLE_BUILD's prefix maps do not reach it. The -march/-mabi/
# -fno-pic triple is load-bearing (hard-float ABI, static link) and is copied
# from tools/build.ps1 unchanged; -ffile-prefix-map is the addition that keeps
# registry paths out of its DWARF and its __FILE__ strings.
export CC_riscv32imafc_esp_espidf=riscv32-esp-elf-gcc
export AR_riscv32imafc_esp_espidf=riscv32-esp-elf-ar
export CFLAGS_riscv32imafc_esp_espidf="-march=rv32imafc_zicsr_zifencei -mabi=ilp32f -fno-pic -ffile-prefix-map=$CARGO_HOME=/cargo -ffile-prefix-map=$SRC=/src -ffile-prefix-map=$TARGET=/build-dir"

cd "$SRC/firmware"

# trim-paths is passed here rather than committed to firmware/.cargo/config.toml
# on purpose. It is a property of the RELEASE recipe, the development build on
# Windows is explicitly not expected to match anyway (REPRODUCIBLE.md 3.4), and
# a profile key in the repository would silently change every bench build the
# day a nightly regressed it. It is the cargo profile option either way, not a
# hand-rolled --remap-path-prefix in RUSTFLAGS: RUSTFLAGS changes the
# fingerprint of every crate in the graph including build-std, which makes an
# accidental difference invisible rather than loud.
cargo +"$(lock_get rustc_channel)" build \
    --release --locked \
    --features "$FEATURE" \
    -Ztrim-paths \
    --config 'profile.release.trim-paths="all"'

ELF="$TARGET/riscv32imafc-esp-espidf/release/notyas-firmware"
[ -f "$ELF" ] || die "the build produced no ELF at $ELF"

# ---------------------------------------------------------------------------
# Step 5: assert what the build actually consumed.

step "asserting the generated configuration"

SDKCONFIG=""
for candidate in "$SRC/firmware/sdkconfig" "$TARGET"/riscv32imafc-esp-espidf/release/build/esp-idf-sys-*/out/sdkconfig; do
    if [ -f "$candidate" ]; then SDKCONFIG="$candidate"; break; fi
done
[ -n "$SDKCONFIG" ] || die "the merged sdkconfig was not found; the assertions below cannot be skipped"

# Item 23's trap: firmware/.cargo/config.toml hardcodes the waveshare overlay so
# a bare `cargo build` stays safe, so a release build that failed to override
# ESP_IDF_SDKCONFIG_DEFAULTS produces a 32 MB-header image labelled elecrow-5.
# The flash size is in the image header of both bootloader.bin and app.bin, so
# this is the difference between a bootable board and a support ticket.
for symbol in "$FLASH_SYMBOL=y" "CONFIG_APP_REPRODUCIBLE_BUILD=y" \
              "CONFIG_APP_PROJECT_VER_FROM_CONFIG=y" "CONFIG_APP_PROJECT_VER=\"$VERSION\"" \
              "CONFIG_ESP32P4_SELECTS_REV_LESS_V3=y" "CONFIG_ESP32P4_REV_MIN_100=y"; do
    grep -qxF "$symbol" "$SDKCONFIG" || die "the merged sdkconfig does not contain $symbol"
    printf '  ok  %s\n' "$symbol"
done

# The container's paths are fixed constants, so there is nothing machine-local
# to strip from the published sdkconfig - REPRODUCIBLE.md item 7's stripping step
# was written for the general case where the path IS machine-local. A path from
# outside those roots is still worth surfacing, because it means something
# reached the build from the host. It is a note rather than a failure: this file
# is text that every builder produces identically, so it cannot by itself make
# two images differ, and killing a forty-minute build over a false positive in a
# grep would be the worse trade.
if grep -nE '(^|=|")/[A-Za-z0-9_./-]+' "$SDKCONFIG" \
   | grep -vE '/(build|opt|usr|src|cargo|IDF|COMPONENT|TOOLCHAIN|dev)' > /tmp/sdkpaths.txt; then
    printf '  note: the merged sdkconfig names paths outside the container roots:\n' >&2
    head -n 10 /tmp/sdkpaths.txt >&2
fi

# A managed component is pinned by version AND component_hash in
# firmware/components_esp32p4.lock. If the build rewrote it, a caret range
# resolved to something new and tens of kilobytes of C driver code changed under
# us. That is a deliberate commit, never a build-time surprise.
if ! cmp -s "$SRC/firmware/components_esp32p4.lock" "$SRC_MOUNT/firmware/components_esp32p4.lock"; then
    diff -u "$SRC_MOUNT/firmware/components_esp32p4.lock" "$SRC/firmware/components_esp32p4.lock" >&2 || true
    die "components_esp32p4.lock changed during the build"
fi
printf '  ok  components_esp32p4.lock unchanged\n'

# ---------------------------------------------------------------------------
# Step 6: produce the artifacts.

step "producing artifacts in $OUT"

APP="$OUT/$(name app.bin)"
BOOTLOADER="$OUT/$(name bootloader.bin)"
PTABLE="$OUT/$(name partition-table.bin)"
MERGED="$OUT/$(name merged.bin)"

espflash save-image --chip esp32p4 --flash-size "$FLASH_SIZE" "$ELF" "$APP"
espflash partition-table --to-binary -o "$PTABLE" "$SRC/firmware/partitions.csv"

# Caught here rather than at the manifest step, which is a merge and a hash
# later: a save-image that padded to the flash size would produce a 16 or 32 MB
# "app image" that is mostly 0xff. 8 MiB is the app-size budget the architecture
# fails at, so anything above it is either padding or a genuine size regression,
# and both want a human before the build continues.
APP_BYTES=$(stat -c%s "$APP")
if [ "$APP_BYTES" -gt 8388608 ]; then
    die "app.bin is $APP_BYTES bytes, past the 8 MiB budget. If it is mostly 0xff the producer padded it to the flash size: add --skip-padding to the espflash save-image call above."
fi
printf '  app image %s bytes\n' "$APP_BYTES"

# The bootloader comes from the esp-idf-sys build tree, built for THIS board's
# sdkconfig. tools/flash.ps1 takes the newest match because a bench target dir
# accumulates them; here the target dir was created empty a few steps ago, so
# there must be exactly one, and more than one means an assumption broke.
mapfile -t BL_CANDIDATES < <(find "$TARGET" -path '*esp-idf-sys*' -name bootloader.bin -print | sort)
[ "${#BL_CANDIDATES[@]}" -eq 1 ] || die "expected exactly one bootloader.bin under $TARGET, found ${#BL_CANDIDATES[@]}: ${BL_CANDIDATES[*]:-none}"
cp "${BL_CANDIDATES[0]}" "$BOOTLOADER"

# The unstripped release ELF, which is what makes real triage possible when two
# builders disagree (REPRODUCIBLE.md 4.4 step 5).
cp "$ELF" "$OUT/notyas-$VERSION-$BOARD.elf"
cp "$SDKCONFIG" "$OUT/$(name sdkconfig.txt)"

# Merged image, for the verifier who wants one flash command. esptool is the
# reference implementation and is used as the producer; the regions are then
# extracted back out and compared byte for byte against their sources, so the
# merged artifact is provably the three regions plus 0xff padding rather than
# whatever a tool decided to emit (REPRODUCIBLE.md 4.2's last bullet).
#
# The subcommand and its option spellings changed between esptool 4 and 5, and
# which one the pinned image ships is a property of the image rather than a
# choice; try the modern spelling, then the legacy one, and fail loudly if
# neither works rather than leaving a half-written file behind.
# The size itself is spelled differently by the two tools, which is why the
# board table carries espflash's spelling and this derives esptool's: espflash
# takes a lowercase "32mb", esptool's --flash-size choice list is uppercase
# ("keep", "4MB", "32MB", ...) and rejects anything else at argument parsing,
# under both the modern and the legacy spelling. Deriving it keeps one value in
# the board table instead of two that can drift apart.
ESPTOOL_FLASH_SIZE=$(printf %s "$FLASH_SIZE" | tr '[:lower:]' '[:upper:]')

if ! "$ESPTOOL" --chip esp32p4 merge-bin -o "$MERGED" --flash-size "$ESPTOOL_FLASH_SIZE" \
        0x2000 "$BOOTLOADER" 0x8000 "$PTABLE" 0x10000 "$APP" 2> /tmp/merge.err; then
    if ! "$ESPTOOL" --chip esp32p4 merge_bin -o "$MERGED" --flash_size "$ESPTOOL_FLASH_SIZE" \
            0x2000 "$BOOTLOADER" 0x8000 "$PTABLE" 0x10000 "$APP"; then
        cat /tmp/merge.err >&2
        die "esptool could not merge the image under either subcommand spelling"
    fi
fi

check_region() {
    # $1 offset, $2 source file. skip_bytes/count_bytes keeps this a handful of
    # large reads rather than two million one-byte ones.
    local off="$1" src="$2" tmp
    tmp=$(mktemp)
    dd if="$MERGED" of="$tmp" bs=1M iflag=skip_bytes,count_bytes \
        skip="$off" count="$(stat -c%s "$src")" status=none
    cmp "$tmp" "$src" || die "the merged image does not carry $(basename "$src") at offset $off"
    rm -f "$tmp"
}
check_region 8192 "$BOOTLOADER"
check_region 32768 "$PTABLE"
check_region 65536 "$APP"
printf '  ok  merged.bin carries all three regions unchanged\n'

# An independent parse of our own output. esptool reading what espflash wrote is
# a cheap second opinion, and it is the reference implementation of the format.
# Ratified Q27: if the two ever disagree about what an image should be, esptool
# becomes the normative producer and espflash stays the flashing tool.
"$ESPTOOL" image-info --version 2 "$APP" > /dev/null 2>&1 \
    || "$ESPTOOL" image_info --version 2 "$APP" > /dev/null \
    || die "esptool refuses to parse the app image this build produced"
printf '  ok  esptool parses the app image\n'

# ---------------------------------------------------------------------------
# Step 7: the leak check.
#
# The mechanical form of REPRODUCIBLE.md items 1 to 6: if any of these strings
# survives into the image, a path from this machine is inside a released binary
# and the next builder's image will differ from it.
step "checking the image for host paths"
if strings -a "$APP" | grep -Ei '/mnt/src|/root/|\.cargo/registry|\.espressif|rustlib|[A-Za-z]:\\\\' | head -n 20 | grep -q .; then
    strings -a "$APP" | grep -Ei '/mnt/src|/root/|\.cargo/registry|\.espressif|rustlib|[A-Za-z]:\\\\' | head -n 20 >&2
    die "the app image contains host paths; trim-paths or the -ffile-prefix-map set is not doing its job"
fi
printf '  ok  no host path in the app image\n'
RUSTC_PREFIX=$(strings -a "$APP" | grep -oE '/rustc/[0-9a-f]{40}' | sort -u | head -n 1 || true)
if [ -n "$RUSTC_PREFIX" ]; then
    EXPECT_HASH=$(lock_get rustc_commit_hash)
    [ "$RUSTC_PREFIX" = "/rustc/$EXPECT_HASH" ] || die "the image carries $RUSTC_PREFIX but the lock pins /rustc/$EXPECT_HASH"
    printf '  ok  standard library paths remap to %s\n' "$RUSTC_PREFIX"
fi

# ---------------------------------------------------------------------------
# Step 8: the manifest, the source and component archives, BUILDINFO, sums.

step "writing the verification manifest"
python3 "$MANIFEST_TOOL" emit \
    --version "$VERSION" --board "$BOARD" \
    --app "$APP" --bootloader "$BOOTLOADER" --partition-table "$PTABLE" \
    --partitions-csv "$SRC/firmware/partitions.csv" \
    --expect-idf "$(lock_get idf_version)" \
    --out "$OUT/$(name VERIFY.json)"

step "archiving the source and the managed components"
SRC_TAR="$OUT/notyas-$VERSION-src.tar.gz"
if [ "$TREE_CLEAN" -eq 1 ]; then
    # gzip -n: no timestamp and no original filename in the gzip header, so the
    # archive is a function of the commit and nothing else.
    git -C "$SRC_MOUNT" archive --format=tar --prefix="notyas-$VERSION/" HEAD | gzip -n -9 > "$SRC_TAR.new"
    if [ -f "$SRC_TAR" ] && ! cmp -s "$SRC_TAR" "$SRC_TAR.new"; then
        die "$SRC_TAR already exists with different bytes; the two board builds disagree about the source"
    fi
    mv "$SRC_TAR.new" "$SRC_TAR"
else
    rm -f "$SRC_TAR"
    printf '  skipped (dirty tree): a source archive of an uncommitted tree describes nothing\n'
fi

COMPONENTS_DIR=$(find "$TARGET" -type d -name managed_components -print | sort | head -n 1 || true)
COMP_TAR="$OUT/notyas-$VERSION-components.tar.gz"
if [ -n "$COMPONENTS_DIR" ]; then
    tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
        -C "$(dirname "$COMPONENTS_DIR")" -cf - managed_components | gzip -n -9 > "$COMP_TAR.new"
    if [ -f "$COMP_TAR" ] && ! cmp -s "$COMP_TAR" "$COMP_TAR.new"; then
        die "$COMP_TAR already exists with different bytes; two board builds resolved different components"
    fi
    mv "$COMP_TAR.new" "$COMP_TAR"
else
    printf '  no managed_components directory found - recording that rather than inventing an archive\n'
fi

step "writing BUILDINFO"
BINDINGS=$(find "$TARGET" -path '*esp-idf-sys*' -name bindings.rs -print | sort | head -n 1 || true)
hash_of() { [ -f "$1" ] && sha256sum "$1" | cut -d' ' -f1 || echo "absent"; }
{
    printf 'notyas BUILDINFO\n'
    printf 'version = %s\n' "$VERSION"
    printf 'board = %s\n' "$BOARD"
    printf 'cargo_feature = %s\n' "$FEATURE"
    printf 'git_commit = %s\n' "$GIT_COMMIT"
    printf 'git_describe = %s\n' "$GIT_DESCRIBE"
    printf 'tree_clean = %s\n' "$TREE_CLEAN"
    printf 'source_date_epoch = %s\n' "$SOURCE_DATE_EPOCH"
    printf 'release_build = %s\n' "$([ "$BOOTSTRAP" -eq 0 ] && [ "$TREE_CLEAN" -eq 1 ] && echo yes || echo no)"
    printf '\n[toolchain, as observed in the image]\n'
    printf '%s' "$OBSERVED"
    printf '\n[inputs]\n'
    printf 'cargo_lock_sha256 = %s\n' "$(hash_of "$SRC/Cargo.lock")"
    printf 'components_lock_sha256 = %s\n' "$(hash_of "$SRC/firmware/components_esp32p4.lock")"
    printf 'partitions_csv_sha256 = %s\n' "$(hash_of "$SRC/firmware/partitions.csv")"
    printf 'sdkconfig_base_sha256 = %s\n' "$(hash_of "$SRC/firmware/sdkconfig.base.defaults")"
    printf 'sdkconfig_board_sha256 = %s\n' "$(hash_of "$SRC/firmware/boards/$BOARD/sdkconfig.defaults")"
    printf 'sdkconfig_merged_sha256 = %s\n' "$(hash_of "$SDKCONFIG")"
    printf 'version_defaults_sha256 = %s\n' "$(hash_of "$VERSION_DEFAULTS")"
    printf 'bindings_rs_sha256 = %s\n' "$(hash_of "$BINDINGS")"
    printf '\n[environment]\n'
    # The environment is part of the comparison: two builders diffing BUILDINFO
    # before diffing binaries usually find the cause in one line. Nothing that
    # varies between two correct builds is recorded here - build duration goes to
    # the log, because BUILDINFO is a published artifact and must reproduce too.
    env | grep -E '^(TZ|LC_ALL|LANG|MCU|CARGO_|ESP_IDF_|CC_|AR_|CFLAGS_|LIBCLANG_PATH|SOURCE_DATE_EPOCH|IDF_PATH|IDF_TOOLS_PATH)' \
        | sed "s|$SRC|/src|g; s|$TARGET|/build-dir|g" | sort
} > "$OUT/$(name BUILDINFO.txt)"
printf '  wrote %s\n' "$(name BUILDINFO.txt)"

# One SHA256SUMS.txt over everything present, regenerated from the directory
# rather than from a list. A list would let a published artifact quietly escape
# the hash file, which is the exact hole m12 exists to close; a directory scan
# cannot.
step "hashing every artifact"
( cd "$OUT" && find . -maxdepth 1 -type f ! -name 'SHA256SUMS.txt*' -printf '%P\n' \
    | LC_ALL=C sort | xargs sha256sum > SHA256SUMS.txt )
cat "$OUT/SHA256SUMS.txt"

if [ "$BOOTSTRAP" -eq 1 ]; then
    printf '\nBOOTSTRAP RUN. Paste these into %s and commit before producing a release:\n' "$LOCK"
    printf '%s' "$OBSERVED"
fi

step "done: $BOARD"
