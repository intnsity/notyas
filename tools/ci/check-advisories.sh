#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# check-advisories.sh - the dependency graph, against the RustSec advisory database.
#
# Until 0.2.0 nothing in this repository asked whether any crate it depends on was known
# to be broken. tools/build-graph-check.sh answers "is a forbidden crate present",
# tools/ci/check-supply-chain.sh answers "did every crate come from where the lock says",
# and both are checks against a list written HERE. Neither can learn anything new. A
# memory-safety advisory published tomorrow against argon2, chacha20poly1305, sha2,
# subtle, zeroize, bitcoin or secp256k1 - the crates that hold, stretch and sign with the
# seed - would have changed nothing about what those gates print, and would have reached
# a user as a firmware release rather than as a red build.
#
# This gate is the one check in the tree whose answer comes from outside the tree, which
# is the whole point of it and also its one operational cost: it needs network access to
# fetch the advisory database and the crates.io index. It does NOT run offline and does
# not fall back to a cached answer of unknown age - if the database cannot be fetched
# this gate FAILS. A gate that passes when it cannot see its input is worse than no gate,
# because from then on the green tick is what people trust instead of looking.
#
# Policy lives in tools/ci/deny.toml, next to this file, with a reason recorded against
# every accepted finding.
#
# Usage:  tools/ci/check-advisories.sh
#
# Exit 0 = no advisory outside the triaged list, 1 = a finding, a missing tool, or a
# database that could not be read.

set -euo pipefail

cd "$(dirname "$0")/../.."

CONFIG=tools/ci/deny.toml

# The oldest cargo-deny whose configuration schema matches deny.toml. This is a
# correctness check, not a preference: cargo-deny WARNS about configuration keys it does
# not understand and then carries on, so an older binary would read a file whose
# `unmaintained` and `ignore`-with-reason forms it does not support, skip those rules and
# report a pass. That is the precise failure this gate exists to refuse, so the version
# is asserted before the check runs rather than hoped for.
MIN_MAJOR=0
MIN_MINOR=20

if [ ! -f "$CONFIG" ]; then
    echo "check-advisories: ${CONFIG} is missing - the policy IS the gate, so this is a"
    echo "                  failure and not a reason to run with cargo-deny's defaults"
    exit 1
fi

if ! command -v cargo-deny >/dev/null 2>&1 && ! cargo deny --version >/dev/null 2>&1; then
    cat <<'EOF'
check-advisories: cargo-deny not found.

This gate cannot be skipped: a dependency graph nobody has checked against the advisory
database is not a checked graph, whatever the rest of CI says. Install it and re-run:

  cargo install --locked cargo-deny

The version CI pins is in .github/workflows/ci.yml.
EOF
    exit 1
fi

VERSION=$(cargo deny --version 2>/dev/null | awk '{print $NF}')
MAJOR=${VERSION%%.*}
REST=${VERSION#*.}
MINOR=${REST%%.*}

case "$MAJOR$MINOR" in
    *[!0-9]*|"")
        echo "check-advisories: cannot parse a version out of 'cargo deny --version' (${VERSION})"
        exit 1
        ;;
esac

if [ "$MAJOR" -lt "$MIN_MAJOR" ] ||
   { [ "$MAJOR" -eq "$MIN_MAJOR" ] && [ "$MINOR" -lt "$MIN_MINOR" ]; }; then
    echo "check-advisories: cargo-deny ${VERSION} is older than ${MIN_MAJOR}.${MIN_MINOR},"
    echo "                  which is the oldest version that understands ${CONFIG}."
    echo "                  It would ignore rules it cannot parse and report a pass."
    echo "                  Upgrade:  cargo install --locked cargo-deny"
    exit 1
fi

echo "cargo-deny ${VERSION}, policy ${CONFIG}"

# Resolve the workspace first, and separately. cargo-deny exits 1 both when it finds an
# advisory and when it cannot build the graph to look at, and those two mean opposite
# things to whoever reads the log: one is "a dependency is known-broken", the other is
# "this gate learned nothing". Asking cargo directly, first, is what lets the failure
# below name which happened instead of guessing. (Observed on 2026-08-18: a workspace
# member whose manifest listed no target made every cargo command in the tree fail, and
# an advisory gate that reported it as a finding would have sent someone hunting a
# vulnerability that did not exist.)
#
# Full resolution, not --no-deps: a stale Cargo.lock is the other way this can fail
# without any advisory being involved, and it should be named here rather than left to
# be read out of cargo-deny's own --locked complaint.
if ! META=$(cargo metadata --locked --format-version 1 2>&1 >/dev/null); then
    echo
    echo "check-advisories: the workspace does not resolve, so NOTHING was checked."
    printf '%s\n' "$META" | sed 's/^/  /'
    echo
    echo "Fix the manifest or the lockfile and re-run. This is not an advisory finding;"
    echo "it is this gate refusing to report a pass it did not earn."
    exit 1
fi

echo "fetching the RustSec advisory database (this gate needs network access)"
echo

# --locked: the committed Cargo.lock is the graph that was audited and hardware
# verified, and it is the graph the advisory answer has to be about. Without it a
# resolution drift would be checked instead, and the report would describe a set of
# versions that no release ever contained.
#
# `check advisories` only. Scope and the reasoning behind it are in deny.toml.
if ! cargo deny --locked --config "$CONFIG" check advisories; then
    echo
    cat <<'EOF'
check-advisories: FAILED

cargo-deny returned an error. The workspace resolved (that was checked above), so this
is either an advisory against a crate in the graph or a database that could not be
fetched - the output above says which, and both are release blockers.

If it is an advisory, in order of preference:

  1. Update the crate, re-run the affected package's tests, and re-run
     tools/build-graph-check.sh - a version bump can change the dependency graph.
  2. If the crate is not reachable from any package that links into the device image,
     prove that with:
         cargo tree --locked -p notyas-firmware --edges normal --target all
     and add an ignore entry to tools/ci/deny.toml stating the advisory id, that
     evidence, and what would make the entry invalid again.
  3. If neither holds, this is a release blocker. It is the case this gate was built
     for.

Do not silence it by widening the policy.
EOF
    exit 1
fi

echo
echo "check-advisories: OK - no advisory outside the triaged list in ${CONFIG}"
exit 0
