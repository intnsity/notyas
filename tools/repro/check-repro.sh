#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# notyas - prove the release build reproduces, by building it twice.
#
# A single build proves nothing. This is the reprotest idea narrowed to our
# recipe: run the container build twice while VARYING everything the recipe
# claims is irrelevant and HOLDING FIXED everything it pins, then compare every
# byte of every artifact.
#
#   varied:      the host checkout path, the host user's umask, the container
#                hostname, the wall clock (the second build runs later), the
#                available CPU count, and a deliberately hostile environment
#                (TZ, LC_ALL, SOURCE_DATE_EPOCH, RUSTFLAGS) handed to the second
#                run to prove build.sh's clean-environment step actually drops it
#   held fixed:  the image digest, toolchain.lock, the in-container paths, the
#                sdkconfig pair, Cargo.lock and components_esp32p4.lock
#
# The in-container uid is deliberately NOT varied: the image pins it, the source
# is taken with `git archive` rather than copied from the mount, and a build that
# depended on the host user's id would be a bug in the recipe rather than a
# property worth exercising.
#
# Usage, from the repository root:
#   tools/repro/check-repro.sh                 # every release board
#   tools/repro/check-repro.sh waveshare-4b    # one board
#   tools/repro/check-repro.sh --keep          # leave both output trees behind
#
# Exit status is the gate: 0 only when every artifact of every board is
# byte-identical between the two builds.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO=$PWD
IMAGE=${NOTYAS_REPRO_IMAGE:-notyas-repro}
OUT_ROOT=$REPO/out/check-repro
KEEP=0
BOARDS=()

for arg in "$@"; do
    case "$arg" in
        --keep) KEEP=1 ;;
        --*) printf 'check-repro.sh: unknown option %s\n' "$arg" >&2; exit 2 ;;
        *) BOARDS+=("$arg") ;;
    esac
done

die() { printf 'check-repro: %s\n' "$*" >&2; exit 1; }

command -v docker > /dev/null || die "docker is not on PATH; the container build is the normative one"
PYTHON=python3
"$PYTHON" -c 'import sys' > /dev/null 2>&1 || PYTHON=python
git diff-index --quiet HEAD -- || die "the working tree has uncommitted changes; a dirty build cannot be compared against anything"

# The board vocabulary has one definition, in build.sh, so a board added there
# is compared here without a second edit.
if [ "${#BOARDS[@]}" -eq 0 ]; then
    mapfile -t BOARDS < <(bash tools/repro/build.sh --list-boards)
fi
printf 'boards: %s\n' "${BOARDS[*]}"

printf '\n=== building the image\n'
docker build -t "$IMAGE" -f tools/repro/Dockerfile .

# The second build runs from a different host path, which is the single most
# common way a build leaks its environment. A local clone gives a different
# path holding the same commit.
CLONE=$(mktemp -d)
trap 'if [ "$KEEP" -eq 0 ]; then rm -rf "$CLONE"; fi' EXIT
git clone --quiet --no-hardlinks "$REPO" "$CLONE/notyas-second-checkout"
CLONE_REPO="$CLONE/notyas-second-checkout"
git -C "$CLONE_REPO" checkout --quiet "$(git rev-parse HEAD)"

rm -rf "$OUT_ROOT"
mkdir -p "$OUT_ROOT/a" "$OUT_ROOT/b"

run_build() {
    # $1 = source repo, $2 = out dir, $3 = board, $4 = "a" or "b"
    local src="$1" out="$2" board="$3" which="$4"
    mkdir -p "$out"
    if [ "$which" = "a" ]; then
        ( umask 022
          docker run --rm --hostname notyas-a \
              -v "$src":/mnt/src:ro -v "$out":/out \
              "$IMAGE" "$board" )
    else
        # Hostile environment on purpose: if any of these reaches the compiler,
        # build.sh's `env -i` step is not doing its job and the artifacts will
        # differ. They are supposed to be dropped before anything is built.
        ( umask 077
          docker run --rm --hostname notyas-b --cpus 2 \
              -e TZ=Pacific/Kiritimati -e LC_ALL=en_US.UTF-8 \
              -e SOURCE_DATE_EPOCH=1 -e RUSTFLAGS=-Cdebuginfo=2 \
              -e CARGO_INCREMENTAL=1 \
              -v "$src":/mnt/src:ro -v "$out":/out \
              "$IMAGE" "$board" )
    fi
}

for board in "${BOARDS[@]}"; do
    printf '\n=== build A: %s (from %s)\n' "$board" "$REPO"
    run_build "$REPO" "$OUT_ROOT/a/$board" "$board" a
done

for board in "${BOARDS[@]}"; do
    printf '\n=== build B: %s (from %s, hostile environment)\n' "$board" "$CLONE_REPO"
    run_build "$CLONE_REPO" "$OUT_ROOT/b/$board" "$board" b
done

printf '\n=== comparing\n'
DIFFS=0
for board in "${BOARDS[@]}"; do
    a="$OUT_ROOT/a/$board"
    b="$OUT_ROOT/b/$board"

    # Compare the SET of files first, not a list written here. A published
    # artifact that escaped the rebuild matrix is precisely the hole this
    # milestone exists to close, and a directory comparison cannot have one.
    ( cd "$a" && find . -maxdepth 1 -type f -printf '%P\n' | LC_ALL=C sort ) > "$OUT_ROOT/a-$board.list"
    ( cd "$b" && find . -maxdepth 1 -type f -printf '%P\n' | LC_ALL=C sort ) > "$OUT_ROOT/b-$board.list"
    if ! diff -u "$OUT_ROOT/a-$board.list" "$OUT_ROOT/b-$board.list"; then
        printf 'DIFFER  %s: the two builds produced different FILE SETS\n' "$board"
        DIFFS=$((DIFFS + 1))
        continue
    fi

    while read -r f; do
        if cmp -s "$a/$f" "$b/$f"; then
            printf '  ok      %s/%s\n' "$board" "$f"
        else
            printf '  DIFFER  %s/%s\n' "$board" "$f"
            cmp -l "$a/$f" "$b/$f" | head -n 5 || true
            printf '          %s bytes differ\n' "$(cmp -l "$a/$f" "$b/$f" | wc -l)"
            DIFFS=$((DIFFS + 1))
        fi
    done < "$OUT_ROOT/a-$board.list"

    # The manifest must also describe the artifacts it shipped with, in both
    # trees. A manifest that reproduces but does not match is worse than one
    # that does neither, because it looks like a pass.
    for tree in "$a" "$b"; do
        manifest=$(find "$tree" -maxdepth 1 -name '*-VERIFY.json' -print | head -n 1)
        [ -n "$manifest" ] || die "no VERIFY.json in $tree"
        "$PYTHON" tools/repro/verify-manifest.py check --manifest "$manifest" --dir "$tree" > /dev/null \
            || die "the manifest in $tree does not match the artifacts beside it"
    done
    printf '  ok      %s/VERIFY.json matches its artifacts in both trees\n' "$board"
done

printf '\n'
if [ "$DIFFS" -gt 0 ]; then
    printf 'check-repro: FAILED - %d artifact(s) differ between the two builds.\n' "$DIFFS"
    printf 'Triage, outside-in (REPRODUCIBLE.md 4.4):\n'
    printf '  1. diff -u %s/a/<board>/*BUILDINFO.txt %s/b/<board>/*BUILDINFO.txt\n' "$OUT_ROOT" "$OUT_ROOT"
    printf '  2. diff -u %s/a/<board>/*sdkconfig.txt %s/b/<board>/*sdkconfig.txt\n' "$OUT_ROOT" "$OUT_ROOT"
    printf '  3. cmp -l on the app image; a handful of bytes near 0x20..0x90 is the\n'
    printf '     app descriptor, scattered bytes are codegen or a layout shift.\n'
    printf '  4. strings -a on both ELFs, sorted and diffed: an absolute path in the\n'
    printf '     diff names its own cause.\n'
    printf 'A persistent diff with none of REPRODUCIBLE.md 4.4 step 6 in play is a bug in\n'
    printf 'the recipe. File it; do not add it to a list of known harmless differences.\n'
    exit 1
fi

printf 'check-repro: OK - every artifact of every board is byte-identical across two\n'
printf 'builds from different paths, at different times, in different environments.\n'
if [ "$KEEP" -eq 1 ]; then
    printf 'Output kept in %s and the second checkout in %s\n' "$OUT_ROOT" "$CLONE_REPO"
fi
