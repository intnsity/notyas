#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# check-repro-pins.sh - the reproducible-build pins agree with each other.
#
# The reproducibility claim is a set of exact versions written down in several
# files that must say the same thing: firmware/rust-toolchain.toml pins the
# nightly a developer gets, tools/repro/Dockerfile pins the one the release
# container installs, and tools/repro/toolchain.lock is what the build asserts
# before it compiles. Nothing stops those three drifting apart, and if they do,
# the failure surfaces as a mismatched release hash weeks later rather than as a
# red build now.
#
# This gate is deliberately cheap: no Docker, no ESP-IDF, no nightly toolchain,
# so it runs on every push beside the other host checks rather than only on
# tags. It cannot prove the build reproduces - only two container builds can do
# that (tools/repro/check-repro.sh) - it proves that the pins the claim rests on
# are consistent and that the manifest tool still passes its own tests.
#
# Usage:  tools/ci/check-repro-pins.sh

set -euo pipefail

cd "$(dirname "$0")/../.."

LOCK=tools/repro/toolchain.lock
DOCKERFILE=tools/repro/Dockerfile
BUILD=tools/repro/build.sh
WORKFLOW=.github/workflows/repro.yml
VERIFYING=docs/VERIFYING.md
RECIPE=docs/plan-0.2.0/REPRODUCIBLE.md

FAILURES=0
CHECKS=0

ok()   { CHECKS=$((CHECKS + 1)); printf '  ok    %s\n' "$*"; }
bad()  { CHECKS=$((CHECKS + 1)); FAILURES=$((FAILURES + 1)); printf '  FAIL  %s\n' "$*"; }

want() {
    # want <label> <expected> <actual>
    if [ "$2" = "$3" ]; then
        ok "$1 = $3"
    else
        bad "$1: expected '$2', found '$3'"
    fi
}

lock_get() {
    awk -F' *= *' -v k="$1" '$1 == k { print $2; exit }' "$LOCK"
}

for f in "$LOCK" "$DOCKERFILE" "$BUILD" "$WORKFLOW" "$RECIPE"; do
    [ -f "$f" ] || { printf 'check-repro-pins: %s is missing\n' "$f" >&2; exit 1; }
done

printf 'toolchain pins\n'

# 1. The nightly a developer builds with, the nightly the container installs and
#    the nightly the build asserts are one nightly.
CHANNEL_REPO=$(awk -F'"' '/^channel *=/ { print $2 }' firmware/rust-toolchain.toml)
CHANNEL_LOCK=$(lock_get rustc_channel)
CHANNEL_DOCKER=$(grep -oE 'default-toolchain [a-z0-9.-]+' "$DOCKERFILE" | awk '{ print $2 }')
want "rust channel (rust-toolchain.toml vs lock)" "$CHANNEL_REPO" "$CHANNEL_LOCK"
want "rust channel (Dockerfile vs lock)" "$CHANNEL_LOCK" "$CHANNEL_DOCKER"

# 2. rust-src is what makes -Zbuild-std work at all, and a nightly installed
#    without it fails deep in the build with an unhelpful message.
if grep -q 'rust-src' firmware/rust-toolchain.toml && grep -q 'component rust-src' "$DOCKERFILE"; then
    ok "rust-src is requested in both rust-toolchain.toml and the Dockerfile"
else
    bad "rust-src must be requested in both rust-toolchain.toml and the Dockerfile"
fi

# 3. The container image: tag and digest both, because a tag is mutable and a
#    digest is the actual pin.
IMAGE_LOCK=$(lock_get image_ref)
DIGEST_LOCK=$(lock_get image_digest)
FROM_LINE=$(grep -m1 '^FROM ' "$DOCKERFILE" | awk '{ print $2 }')
want "container image" "$IMAGE_LOCK" "${FROM_LINE%%@*}"
want "container digest" "$DIGEST_LOCK" "${FROM_LINE##*@}"

# 4. Host tools that sit in the artifact path.
want "espflash pin" "$(lock_get espflash_version)" \
     "$(grep -oE 'cargo install espflash --version =[0-9.]+' "$DOCKERFILE" | grep -oE '[0-9.]+$')"
want "ldproxy pin" "$(lock_get ldproxy_version)" \
     "$(grep -oE 'cargo install ldproxy +--version =[0-9.]+' "$DOCKERFILE" | grep -oE '[0-9.]+$')"

# 5. The ESP-IDF version is a hard pin for a reason recorded in
#    firmware/.cargo/config.toml: v5.5.5 breaks esp-idf-hal 0.46.2.
IDF_REPO=$(awk -F'"' '/^ESP_IDF_VERSION/ { print $2 }' firmware/.cargo/config.toml)
want "ESP-IDF version (.cargo/config.toml vs lock)" "$IDF_REPO" "$(lock_get idf_version)"
want "ESP-IDF version (image tag vs lock)" "$(lock_get idf_version)" "${IMAGE_LOCK##*:}"

printf '\nimage configuration\n'

# 6. Without this option the image carries a build timestamp and cannot
#    reproduce at all. The manifest tool refuses such an image, but that is a
#    failure at the end of a 40-minute build; this is the same fact in a second.
if grep -qx 'CONFIG_APP_REPRODUCIBLE_BUILD=y' firmware/sdkconfig.base.defaults; then
    ok "CONFIG_APP_REPRODUCIBLE_BUILD=y is in sdkconfig.base.defaults"
else
    bad "firmware/sdkconfig.base.defaults must set CONFIG_APP_REPRODUCIBLE_BUILD=y"
fi

printf '\nboard vocabulary\n'

# 7. One board vocabulary. build.sh owns it; every consumer reads it from there,
#    and every slug in it must be a board that actually exists.
BOARDS=$(bash "$BUILD" --list-boards)
for board in $BOARDS; do
    overlay="firmware/boards/$board/sdkconfig.defaults"
    if [ -f "$overlay" ]; then
        ok "board $board has $overlay"
    else
        bad "board $board has no $overlay"
    fi
    if grep -q "^board-$board = \[" firmware/Cargo.toml || grep -q "^board-$board *=" firmware/Cargo.toml; then
        ok "board $board has a cargo feature board-$board"
    else
        bad "board $board has no cargo feature board-$board in firmware/Cargo.toml"
    fi
    # The item-23 trap, made static: build.sh asserts a flash-size symbol per
    # board after the build, and that symbol has to be the one the board's own
    # overlay sets, or the assertion asserts nothing.
    symbol=$(awk -F'|' -v s="$board" '$1 == s { print $4 }' <<< "$(sed -n '/^BOARDS="/,/^"$/p' "$BUILD" | sed '/^BOARDS="/d; /^"$/d')")
    if [ -n "$symbol" ] && grep -qx "$symbol=y" "$overlay"; then
        ok "board $board flash size: $symbol matches its overlay"
    else
        bad "board $board: build.sh expects '$symbol' which its overlay does not set"
    fi
done

# 8. The CI matrix is the same list. An artifact built by a matrix that has
#    drifted from the board table is a published artifact nobody reproduces.
MATRIX=$(grep -oE '^ +board: \[.*\]' "$WORKFLOW" | sed 's/.*\[//; s/\]//; s/,/ /g' | xargs || true)
want "CI matrix boards" "$(echo "$BOARDS" | xargs)" "$MATRIX"

printf '\nrelease identity\n'

# 9. One fingerprint, spelled the same way everywhere. A short key id is never
#    printed, and a fingerprint that differs by a digit between two documents is
#    the kind of thing a reader reasonably treats as an attack.
FPR_RECIPE=$(grep -oE '([0-9A-F]{4} ){9}[0-9A-F]{4}' "$RECIPE" | head -n 1 | tr -d ' ')
if [ -f "$VERIFYING" ]; then
    FPR_VERIFYING=$(grep -oE '([0-9A-F]{4} ){9}[0-9A-F]{4}' "$VERIFYING" | head -n 1 | tr -d ' ')
    want "release key fingerprint" "$FPR_RECIPE" "$FPR_VERIFYING"
    if grep -qE '0x[0-9A-Fa-f]{8,16}\b' "$VERIFYING"; then
        bad "$VERIFYING prints a short key id; only the full 40-hex fingerprint may appear"
    else
        ok "$VERIFYING prints no short key id"
    fi
else
    bad "$VERIFYING is missing - the verifier-facing document is a release deliverable"
fi

printf '\nscripts\n'

# 10. Syntax, then the manifest tool's own tests. The selftest is the real gate
#     here: it exercises the image parser, the digest construction and every
#     refusal, and it needs nothing installed.
for script in "$BUILD" tools/repro/check-repro.sh tools/ci/check-repro-pins.sh; do
    if bash -n "$script"; then ok "$script parses"; else bad "$script does not parse"; fi
done
# python3 is the name everywhere this runs in CI and in the container. On the
# Windows bench it can be an App Execution Alias that resolves to a store stub,
# so fall back to `python` rather than reporting a tool failure as a pin failure.
PYTHON=python3
if ! "$PYTHON" -c 'import sys' > /dev/null 2>&1; then PYTHON=python; fi
if "$PYTHON" tools/repro/verify-manifest.py selftest > /dev/null; then
    ok "verify-manifest.py selftest"
else
    bad "verify-manifest.py selftest failed - run it directly for the detail"
fi

printf '\n'
if [ "$FAILURES" -gt 0 ]; then
    printf 'check-repro-pins: FAILED - %d of %d checks\n' "$FAILURES" "$CHECKS"
    exit 1
fi
printf 'check-repro-pins: OK - %d checks\n' "$CHECKS"
