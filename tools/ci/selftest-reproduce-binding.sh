#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# selftest-reproduce-binding.sh - prove the release path refuses to sign bytes no rebuild made.
#
# WHAT IT IS FOR
#
# tools/repro/check-repro.sh answers one question: does this recipe reproduce. It builds
# twice, into out/check-repro/a and out/check-repro/b, and compares those two trees
# against each other. It has never heard of out/release/<version>/artifacts, which is the
# directory the sign stage signs and the publish stage hands over.
#
# Until 0.2.0 the reproduce stage ran that script, read nothing it left behind, and
# stamped a pass. The only comparison ever made against the artifact directory was the
# optional second-machine attestation, so on the --no-second-machine path the gate that
# the whole ordering rests on, "reproduction before signature", was satisfied by a build
# nobody had tied to the release. An artifact rewritten between 'build' and 'sign', with
# SHA256SUMS.txt regenerated from the directory the way tools/repro/build.sh writes it,
# passed every later check: they all ask whether the list and the directory agree with
# each other, and they did.
#
# tools/release.sh now compares the rebuild to the hash list about to be signed, in both
# directions, and records the reduced list's digest in the reproduce stamp so 'sign' and
# 'publish' can re-ask it about the directory as it stands at that moment. This fixture is
# the proof that both of those can say no. It plants the rewrite from the finding, the
# file that rides along unbuilt, the artifact that never made it out of the container, the
# stale rebuild tree, and the stamp from an older release.sh, and asserts each one is
# refused. It also asserts the accept path still accepts, including the case where the two
# hash lists name the same bytes by different paths, because a check that refuses
# everything protects nothing and would be found on release day.
#
# WHAT IT DOES NOT CLAIM
#
# That a stamp cannot be forged. Anything that can write out/ can rewrite the stamp beside
# the artifacts, and can edit these scripts besides. The hazard this closes is the
# accidental rewrite and the stale directory, which is what the finding described.
#
# It never touches out/. Every case runs against directories made by mktemp, with
# ARTIFACTS and STAMPS overridden inside a subshell, so a real release in progress on this
# machine is neither read nor written.

set -euo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$REPO"

# The functions under test, loaded from the file that ships them. Sourcing rather than
# copying: a self-test that reimplements the check proves something about the copy.
# shellcheck source=../release.sh
. "$REPO/tools/release.sh"

FIX=$(mktemp -d)
trap 'rm -rf "$FIX"' EXIT

ART="$FIX/artifacts"
REBUILT="$FIX/rebuilt"
STAMPDIR="$FIX/stamps"
BOARDS="waveshare-4b esp32-p4-nano"

# Exactly the expression tools/repro/build.sh uses to write a hash list: a scan of the
# directory, not a list of names. Regenerating it here is what makes the tamper cases
# realistic. Anything that rewrites an artifact and re-runs a build writes this file too,
# which is why the checks that compare the list to the directory cannot see the rewrite.
write_sums() {
    ( cd "$1" && find . -maxdepth 1 -type f ! -name 'SHA256SUMS.txt*' -printf '%P\n' \
        | LC_ALL=C sort | xargs -r sha256sum > SHA256SUMS.txt )
}

# One board's container output: the two per-board files, plus the two archives every
# board build writes under the same name, which is why the comparison has to tolerate a
# basename appearing in more than one rebuilt tree.
plant_board() {
    local dir=$1 board=$2
    mkdir -p "$dir"
    printf 'app image for %s\n' "$board" > "$dir/notyas-0.0.0-$board-app.bin"
    printf 'manifest for %s\n'  "$board" > "$dir/notyas-0.0.0-$board-VERIFY.json"
    printf 'source archive\n'            > "$dir/notyas-0.0.0-src.tar.gz"
    printf 'components archive\n'        > "$dir/notyas-0.0.0-components.tar.gz"
    write_sums "$dir"
}

# The world as it stands when the reproduce stage runs and everything is honest: the
# artifact directory is the union of the boards' outputs, and the rebuild tree holds one
# directory per board.
plant_world() {
    local board
    rm -rf "$ART" "$REBUILT" "$STAMPDIR"
    mkdir -p "$ART" "$STAMPDIR"
    for board in $BOARDS; do
        plant_board "$REBUILT/$board" "$board"
        cp "$REBUILT/$board"/* "$ART/"
    done
    rm -f "$ART/SHA256SUMS.txt"
    write_sums "$ART"
}

plant_stamp() {
    { printf 'stage = reproduce\n'
      printf 'commit = %s\n' "$HEAD_COMMIT"
      printf 'double_build = passed\n'
      if [ "${1:-}" != "no-digest" ]; then
          printf 'reproduced_artifacts_sha256 = %s\n' "$(artifact_pairs_digest "$ART/SHA256SUMS.txt")"
      fi
    } > "$STAMPDIR/reproduce"
}

FAIL=0
CASES=0

# want=accept|refuse. Every case runs in a subshell with the artifact directory and the
# stamp directory pointed at the fixture, so the functions are the ones release.sh will
# run and nothing in out/ is touched.
case_is() {
    local want=$1 desc=$2; shift 2
    local rc=0 out
    CASES=$((CASES + 1))
    out=$(mktemp)
    ( ARTIFACTS=$ART; STAMPS=$STAMPDIR; "$@" ) > "$out" 2>&1 || rc=$?
    if { [ "$want" = accept ] && [ "$rc" -eq 0 ]; } || { [ "$want" = refuse ] && [ "$rc" -ne 0 ]; }; then
        printf '  ok    %s\n' "$desc"
    else
        printf '  FAIL  %s (wanted %s, exit %d)\n' "$desc" "$want" "$rc"
        sed 's/^/          /' "$out"
        FAIL=$((FAIL + 1))
    fi
    rm -f "$out"
}

# shellcheck disable=SC2086  # the board list is a list, and is ours
covers() { reproduction_covers_artifacts "$REBUILT" "$ART/SHA256SUMS.txt" $BOARDS; }
still()  { artifacts_match_reproduce_stamp "$1"; }

# Asked before the cases rather than discovered inside them. A case that expects a refusal
# and gets "command not found" has the exit status it wanted and none of the evidence: it
# would report green against a release script that ties nothing to anything, which is the
# state this fixture exists to detect.
for fn in reproduction_covers_artifacts artifact_pairs_digest artifacts_match_reproduce_stamp; do
    declare -F "$fn" > /dev/null || {
        printf 'selftest-reproduce-binding: tools/release.sh defines no %s.\n' "$fn" >&2
        printf 'The reproduce stage then compares the double build against nothing but itself,\n' >&2
        printf 'and the bytes that get signed are tied to no rebuild at all.\n' >&2
        exit 1
    }
done

printf 'selftest-reproduce-binding: fixtures in %s\n\n' "$FIX"

# --- the reproduce stage's own comparison

plant_world
case_is accept "an artifact directory that is exactly what the rebuild produced" covers

# The finding, exactly as it was reported: one artifact rewritten after the build, and the
# hash list regenerated from the directory so that every list-versus-directory check still
# passes.
plant_world
printf 'app image for waveshare-4b, rewritten\n' > "$ART/notyas-0.0.0-waveshare-4b-app.bin"
write_sums "$ART"
case_is refuse "an artifact rewritten after the build, with SHA256SUMS.txt regenerated" covers

plant_world
printf 'nobody built this\n' > "$ART/notyas-0.0.0-extra.bin"
write_sums "$ART"
case_is refuse "a file in the signed list that no rebuild produced" covers

plant_world
rm -f "$ART/notyas-0.0.0-esp32-p4-nano-app.bin"
write_sums "$ART"
case_is refuse "a rebuilt artifact the signed list does not carry" covers

plant_world
rm -rf "${REBUILT:?}/esp32-p4-nano"
case_is refuse "a rebuild tree that is missing a release board" covers

plant_world
rm -rf "${REBUILT:?}"/*
case_is refuse "a rebuild tree with nothing in it" covers

# The shared archives are written by every board build under one name. Two boards that
# disagree about their bytes is its own fault and gets its own answer.
plant_world
printf 'a different source archive\n' > "$REBUILT/esp32-p4-nano/notyas-0.0.0-src.tar.gz"
case_is refuse "two boards rebuilds disagreeing about a shared archive" covers

# The accept path that a careless reduction breaks: the container lists what it built
# under /out, a verifier lists it in the directory they downloaded it to. The path a
# builder happened to use is not a difference in the bytes, and a comparison that treats
# it as one refuses every honest release.
plant_world
sed -i 's|  |  /out/|' "$ART/SHA256SUMS.txt"
case_is accept "the same bytes named by different paths in the two lists" covers

# --- the re-assertion 'sign' and 'publish' make against the stamp

plant_world
plant_stamp
case_is accept "an artifact directory still holding what the reproduce stage tied" still sign

# The window the finding names: everything above passed, the stamp stands, and the bytes
# changed afterwards. This is the case the reproduce-time comparison alone cannot see.
plant_world
plant_stamp
printf 'app image for waveshare-4b, rewritten after the stamp\n' > "$ART/notyas-0.0.0-waveshare-4b-app.bin"
write_sums "$ART"
case_is refuse "an artifact rewritten between reproduce and sign" still sign
case_is refuse "the same rewrite, asked again at the push" still publish

plant_world
plant_stamp
printf 'nobody built this either\n' > "$ART/notyas-0.0.0-extra.bin"
write_sums "$ART"
case_is refuse "a file that appeared in the directory after the stamp" still sign

plant_world
plant_stamp no-digest
case_is refuse "a reproduce stamp from before the double build was tied to the artifacts" still sign

printf '\n'
if [ "$FAIL" -ne 0 ]; then
    printf 'selftest-reproduce-binding: %d of %d cases FAILED. The release path would sign bytes\n' "$FAIL" "$CASES" >&2
    printf 'that no rebuild produced, which is the finding this exists to close.\n' >&2
    exit 1
fi
printf 'selftest-reproduce-binding: %d cases. The bytes that get signed are bytes the double\n' "$CASES"
printf 'build produced, and are still those bytes at the signature and at the push.\n'
