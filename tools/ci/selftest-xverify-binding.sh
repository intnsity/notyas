#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# selftest-xverify-binding.sh - prove that a cross-check verdict nobody witnessed is refused.
#
# WHAT IT IS FOR
#
# out/xverify/attestation.json is the only durable evidence the third-party cross-check
# leaves behind, and a JSON file says nothing about when it was written or by whom. A file
# containing
#
#     { "status": "verified" }
#
# dropped into out/xverify used to survive the whole of tools/release.sh untouched: the
# 'gates' stage asks tools/ci/check-xverify.sh --probe first, --probe writes nothing by
# design, and nothing downstream ever read the file. Yesterday's honest verdict, a copy
# from a different tree and a forgery typed by hand were all indistinguishable from a live
# cross-check - to the release script, and to anybody who found the file beside a release.
#
# check-xverify.sh now writes a binding next to the attestation, at the end of a run it
# watched happen, naming the run id its caller generated, the digest of the sources the
# cross-check exercised, and the digest of the attestation's own bytes. --assert-fresh
# answers the question the release path actually needs: did the run I mean write this.
#
# This fixture is the proof that the answer can be no. It plants the file from the finding
# and every near miss around it - a binding for another run, a binding whose attestation
# was edited afterwards, a binding made against other sources - and asserts each one is
# refused with the exit code that says why. It also asserts the accept path still accepts,
# because a check that refuses everything protects nothing and would be found only on
# release day.
#
# One thing it does not claim: that a binding cannot be forged. Anything that can write
# to out/ can write both files, and can edit these scripts besides. The hazard this closes
# is the stale file and the one planted in advance, which is what was found in the release
# path.
#
# It never touches out/xverify: every case runs against --attestation-file in a directory
# made by mktemp, so a real verdict on this machine is neither read nor overwritten.

set -euo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$REPO"

CHECK="tools/ci/check-xverify.sh"
FIX=$(mktemp -d)
ATT="$FIX/attestation.json"
BIND="$ATT.run"
trap 'rm -rf "$FIX"' EXIT

TREE=$(bash "$CHECK" --tree-digest)
[ -n "$TREE" ] || { printf 'selftest-xverify-binding: could not digest the cross-checked sources\n' >&2; exit 1; }

FAIL=0
CASES=0

# The exit code is the whole interface here, so the cases assert on it rather than on
# prose: 0 this run verified, 1 this run ran and did not verify, 4 nothing claims
# anything, 5 something claims something and this run did not write it.
case_is() {
    local want=$1 desc=$2 run_id=$3
    local rc=0 out
    CASES=$((CASES + 1))
    out=$(mktemp)
    bash "$CHECK" --assert-fresh "$run_id" --attestation-file "$ATT" > "$out" 2>&1 || rc=$?
    if [ "$rc" -eq "$want" ]; then
        printf '  ok    %s (exit %d)\n' "$desc" "$rc"
    else
        printf '  FAIL  %s (wanted exit %d, got %d)\n' "$desc" "$want" "$rc"
        sed 's/^/          /' "$out"
        FAIL=$((FAIL + 1))
    fi
    rm -f "$out"
}

# A verdict in the shape both writers produce, claiming the strongest thing it can claim.
plant_attestation() {
    cat > "$ATT" <<'ATTEOF'
{
  "status": "passed",
  "verified": true,
  "conclusion": "VERIFIED - 21 cases, 0 failures, against Bitcoin Core and embit",
  "cases_verified": 21,
  "cases_expected": 21,
  "when": "2026-08-18T00:00:00Z",
  "written_by": "tools/xverify/xverify.py",
  "tree_digest": "0000000000000000000000000000000000000000000000000000000000000000"
}
ATTEOF
}

# A binding of the shape check-xverify.sh writes. The fields are public and computable,
# which is the honest limit recorded in the header above; what a planted file cannot have
# is the run id a release run made up seconds ago.
plant_binding() {
    local run_id=$1 tree=$2 att_digest=$3
    {
        printf 'run_id = %s\n' "$run_id"
        printf 'tree_digest = %s\n' "$tree"
        printf 'tree_dirs = crates/notyas-core/src crates/notyas-wallet/src tools/xverify\n'
        printf 'attestation_sha256 = %s\n' "$att_digest"
        printf 'status = passed\n'
        printf 'when = 2026-08-18T00:00:00Z\n'
    } > "$BIND"
}

digest_of() { sha256sum < "$1" | cut -d' ' -f1; }

printf 'selftest-xverify-binding: fixtures in %s\n' "$FIX"
printf 'selftest-xverify-binding: sources digest %s\n\n' "$TREE"

rm -f "$ATT" "$BIND"
case_is 4 "no attestation at all is a gap, not a pass" run-aaaaaaaa

# The finding, exactly as it was reported.
printf '{ "status": "verified" }\n' > "$ATT"
case_is 5 "the planted {\"status\": \"verified\"} from the report" run-aaaaaaaa

plant_attestation
case_is 5 "a full, plausible, passing attestation with nothing vouching for it" run-aaaaaaaa

plant_binding run-bbbbbbbb "$TREE" "$(digest_of "$ATT")"
case_is 5 "a binding that names a different run" run-aaaaaaaa

plant_binding run-aaaaaaaa "0000000000000000000000000000000000000000000000000000000000000000" "$(digest_of "$ATT")"
case_is 5 "a binding made against sources that are not the ones here now" run-aaaaaaaa

plant_binding run-aaaaaaaa "$TREE" "$(digest_of "$ATT")"
printf '\n' >> "$ATT"
case_is 5 "an attestation rewritten after its binding was made" run-aaaaaaaa

plant_attestation
plant_binding run-aaaaaaaa "$TREE" "$(digest_of "$ATT")"
rm -f "$ATT"
case_is 5 "a binding whose attestation has been taken away" run-aaaaaaaa

# The accept path, and the path where the named run really did run and really did fail.
plant_attestation
plant_binding run-aaaaaaaa "$TREE" "$(digest_of "$ATT")"
case_is 0 "a verdict bound to the run that is being asked about" run-aaaaaaaa

sed -i 's/"status": "passed"/"status": "skipped"/; s/"verified": true/"verified": false/' "$ATT"
plant_binding run-aaaaaaaa "$TREE" "$(digest_of "$ATT")"
case_is 1 "the named run wrote it and it did not verify" run-aaaaaaaa

printf '\n'
if [ "$FAIL" -ne 0 ]; then
    printf 'selftest-xverify-binding: %d of %d cases FAILED. A cross-check verdict this release\n' "$FAIL" "$CASES" >&2
    printf 'run did not produce can be read as if it had, which is the finding this exists to close.\n' >&2
    exit 1
fi
printf 'selftest-xverify-binding: %d cases. An attestation counts only when the run being asked\n' "$CASES"
printf 'about wrote it, against the sources that are here now, and has not been touched since.\n'
