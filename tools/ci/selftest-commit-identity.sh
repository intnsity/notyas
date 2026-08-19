#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# selftest-commit-identity.sh - proof that check-commit-messages.sh fails when it should.
#
# check-commit-messages.sh is the gate that stops a repeat of the incident that
# cost this project its repository. Until this file existed, every run of it in
# this tree had passed, and a gate that has only ever passed is indistinguishable
# from a gate that cannot fail. The history it guards is clean, so the real
# repository can never supply the negative evidence: the only way to see the gate
# say no is to build a repository it must say no to.
#
# That is what this script does. It constructs throwaway git repositories under
# the system temp directory, commits into them with identities and messages the
# policy forbids, runs the REAL gate against each, and asserts the verdict. The
# owner's repository is never committed to and never read except to copy the one
# file under test.
#
# WHY THE GATE IS COPIED RATHER THAN CALLED IN PLACE. check-commit-messages.sh
# begins with `cd "$(dirname "$0")/../.."`, so it always inspects the repository
# it is stored in - which is the right behaviour for a gate and the reason it
# cannot simply be pointed at a fixture. Placing the file inside the fixture is
# therefore the only way to aim it, and copying the real file rather than
# reimplementing its logic is what makes this a test of the gate instead of a
# test of a paraphrase of it. The copy is compared against the original, so a
# truncated or rewritten copy cannot quietly become the thing under test.
#
# WHY THE FIXTURES ARE HERMETIC. GIT_CONFIG_GLOBAL and GIT_CONFIG_SYSTEM are
# pointed at /dev/null for every git invocation here. A developer's own global
# configuration - a signing key, a commit template, a pre-commit hook, an
# autocrlf setting - would otherwise decide whether a fixture commit can be
# created at all, and a self-test that goes red because of the machine it runs on
# is a self-test people learn to skip.
#
# WHY EVERY CASE ASSERTS OUTPUT AND NOT ONLY AN EXIT CODE. Exit 1 is also what
# the gate returns when it cannot resolve the range it was handed. A case that
# checked the code alone would go green against a gate that had stopped checking
# identities entirely and was merely failing to start, which is precisely the
# "passes for the wrong reason" defect this file exists to rule out. So each
# expected failure names the line the gate must print, and additionally asserts
# that the gate did not simply fail to run.
#
# WHY THE POLICY LISTS ARE READ OUT OF THE GATE. The forbidden tokens and the
# allowed identities are parsed from check-commit-messages.sh rather than copied
# here. A token added to the gate is then covered by this test without anyone
# remembering to, and - the half that matters more - every entry of the allowed
# list is exercised, so an identity that has silently stopped working cannot sit
# in that array looking like policy while being dead code. A parse that yields
# nothing stops the run: a self-test that quietly tests zero cases is the same
# defect one level up.
#
# WHY THE TOKENS ARE HEX IN THE GATE AND DECODED HERE. The same rule forbids
# those strings anywhere in the tree. A self-test that spelled them out would
# violate the policy it proves, so the fixture messages are built by decoding the
# gate's own hex.
#
# Usage:  tools/ci/selftest-commit-identity.sh [--keep]
#           --keep   leave the fixture repositories behind for inspection
#
# Exit 0 = the gate behaves as specified on every case, 1 = it does not.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT=$(pwd)
GATE="$REPO_ROOT/tools/ci/check-commit-messages.sh"

KEEP=0
case "${1:-}" in
    --keep) KEEP=1 ;;
    "") ;;
    *) printf 'selftest-commit-identity: unknown argument %s\n' "$1" >&2; exit 1 ;;
esac

if [ ! -f "$GATE" ]; then
    printf 'selftest-commit-identity: %s is not in this tree - nothing to test.\n' "$GATE" >&2
    exit 1
fi

# Hermetic fixtures. Exported once: every git call below, including the ones the
# gate itself makes inside a fixture, must see only that fixture's own config.
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_SYSTEM=/dev/null

# mktemp honours TMPDIR, which is where this belongs: the fixture is a git
# repository being written to, and the one place it must never be built is
# anywhere under the repository whose history the gate protects. Checked rather
# than trusted, because TMPDIR is an environment variable like any other.
WORK=$(mktemp -d)
case "$WORK" in
    "$REPO_ROOT"*)
        printf 'selftest-commit-identity: refusing to build fixtures inside the repository (%s)\n' "$WORK" >&2
        exit 1 ;;
esac

cleanup() {
    if [ "$KEEP" -eq 1 ]; then
        printf '\nfixtures kept at %s\n' "$WORK"
        return 0
    fi
    # Git marks loose objects read-only and MSYS rm honours that, so make the
    # tree writable first: cleanup must not be the thing that fails on Windows.
    chmod -R u+w "$WORK" 2>/dev/null || true
    rm -rf "$WORK" 2>/dev/null || true
}
trap cleanup EXIT

PASSES=0
FAILURES=0
pass() { PASSES=$((PASSES + 1)); printf '  ok    %s\n' "$1"; }
fail() { FAILURES=$((FAILURES + 1)); printf '  FAIL  %s\n' "$1"; }
note() { printf '        %s\n' "$1"; }

# --- the policy, read from the gate ------------------------------------------
#
# Both arrays are declared as NAME=( one quoted entry per line ) closed by a bare
# ")". Extracting between those two anchors is enough for that shape, and an
# empty result is treated as a broken parser rather than as an empty policy.
array_from_gate() {
    sed -n "/^$1=(/,/^)/p" "$GATE" | sed -n 's/^[[:space:]]*"\(.*\)"[[:space:]]*$/\1/p'
}

TOKEN_HEXES=()
while IFS= read -r line; do TOKEN_HEXES+=("$line"); done < <(array_from_gate TOKENS)
ALLOWED=()
while IFS= read -r line; do ALLOWED+=("$line"); done < <(array_from_gate ALLOWED_IDENTITIES)

if [ "${#TOKEN_HEXES[@]}" -eq 0 ] || [ "${#ALLOWED[@]}" -eq 0 ]; then
    printf 'selftest-commit-identity: could not read TOKENS/ALLOWED_IDENTITIES out of the gate.\n' >&2
    printf '  Their declarations changed shape. Fix the parser above - do not delete the case.\n' >&2
    exit 1
fi

unhex() { printf '%b' "$(printf %s "$1" | sed 's/../\\x&/g')"; }

TOKENS=()
for h in "${TOKEN_HEXES[@]}"; do TOKENS+=("$(unhex "$h")"); done

# The owner's canonical identity, taken from the head of the gate's own allowed
# list so that this file holds no second copy of it to drift out of step.
OWNER="${ALLOWED[0]}"

# The identities the gate must reject. The first is an ordinary foreign
# committer - what a rebase on somebody else's machine produces. The second is
# built from one of the gate's own forbidden tokens, which makes it the exact
# shape of identity that cost this project its repository, and keeps the string
# itself out of this file.
FOREIGN="release-bot <bot@example.invalid>"
TOOL_IDENTITY="${TOKENS[1]} <noreply@example.invalid>"

id_name()  { printf '%s' "${1%% <*}"; }
id_email() { local e="${1#*<}"; printf '%s' "${e%>}"; }

# --- fixture construction ----------------------------------------------------
#
# One repository per case rather than one repository with a branch per case: a
# fresh repository cannot inherit a previous case's objects, refs or config, and
# git init costs milliseconds. Empty commits throughout - the gate reads message
# and identity, never a tree.
# Sets D rather than printing it, because a helper called as $(new_repo) advances
# its case counter inside a subshell: every case would then be handed the same
# directory and the whole suite would pool its commits into one history, where a
# violation planted by one case is found by all the others and every count
# assertion is off. That is a self-test failing open, which is the defect this
# file exists to rule out - so the counter stays in the caller's shell.
D=""
CASE_N=0
new_repo() {
    CASE_N=$((CASE_N + 1))
    D="$WORK/case$CASE_N"
    mkdir -p "$D/tools/ci"
    cp "$GATE" "$D/tools/ci/check-commit-messages.sh"
    if ! cmp -s "$GATE" "$D/tools/ci/check-commit-messages.sh"; then
        printf 'selftest-commit-identity: the copied gate differs from the original.\n' >&2
        exit 1
    fi
    git -C "$D" init -q -b main
    git -C "$D" config commit.gpgsign false
    git -C "$D" config core.autocrlf false
    git -C "$D" config user.name "$(id_name "$OWNER")"
    git -C "$D" config user.email "$(id_email "$OWNER")"
}

# commit <dir> <author-identity> <committer-identity> <message>
commit() {
    local dir=$1 author=$2 committer=$3 message=$4
    GIT_AUTHOR_NAME="$(id_name "$author")" \
    GIT_AUTHOR_EMAIL="$(id_email "$author")" \
    GIT_COMMITTER_NAME="$(id_name "$committer")" \
    GIT_COMMITTER_EMAIL="$(id_email "$committer")" \
        git -C "$dir" commit -q --allow-empty -m "$message"
}

# --- the assertion -----------------------------------------------------------
#
# expect <description> <dir> <range> <want-exit> [marker...]
#
# A marker is a fixed string the gate's output must contain. For an expected
# failure the markers are what distinguish "the gate rejected this commit" from
# "the gate could not start", which is why an expected failure always carries at
# least one.
expect() {
    local what=$1 dir=$2 range=$3 want=$4; shift 4
    local out code m
    set +e
    if [ -z "$range" ]; then
        out=$(cd "$dir" && bash tools/ci/check-commit-messages.sh 2>&1)
    else
        out=$(cd "$dir" && bash tools/ci/check-commit-messages.sh "$range" 2>&1)
    fi
    code=$?
    set -e

    if [ "$code" -ne "$want" ]; then
        fail "$what"
        note "expected exit $want, got $code. The gate said:"
        printf '%s\n' "$out" | sed 's/^/          | /'
        return 0
    fi

    # "cannot resolve range" means the gate never inspected a commit, so for every
    # case except the one that is ABOUT that message it is a pass for the wrong
    # reason. Naming it as a marker is how that one case opts out.
    local about_range=0
    for m in "$@"; do
        [ "$m" = "cannot resolve range" ] && about_range=1
    done
    if [ "$want" -ne 0 ] && [ "$about_range" -eq 0 ] && printf '%s' "$out" | grep -qF 'cannot resolve range'; then
        fail "$what"
        note "exit $code, but the gate never ran - it could not resolve the range."
        note "accepting this would leave the self-test green against a gate that had"
        note "stopped checking identities altogether."
        printf '%s\n' "$out" | sed 's/^/          | /'
        return 0
    fi

    for m in "$@"; do
        if ! printf '%s' "$out" | grep -qF -- "$m"; then
            fail "$what"
            note "exit $code was right, but the output does not contain:"
            note "  \"$m\""
            note "so the gate did not fail for the reason under test."
            printf '%s\n' "$out" | sed 's/^/          | /'
            return 0
        fi
    done
    pass "$what"
}

printf '\n=== the commit identity gate, put in front of commits it must reject ===\n\n'
note "gate:      tools/ci/check-commit-messages.sh"
note "fixtures:  $WORK"
note "policy:    ${#ALLOWED[@]} allowed identities, ${#TOKENS[@]} forbidden tokens, read from the gate"
printf '\n'

# --- 1. the gate says yes to what it must ------------------------------------
#
# A gate that rejects everything is as worthless as one that accepts everything,
# because the first thing a noisy gate earns is a --no-verify. Every entry of the
# allowed list is exercised here for that reason and for one more: an identity
# that had quietly stopped being accepted would otherwise sit in that array
# looking like policy while being dead code.
for who in "${ALLOWED[@]}"; do
    new_repo
    commit "$D" "$who" "$who" "gates: an ordinary commit"
    expect "allowed identity is accepted: $who" "$D" HEAD 0 "check-commit-messages: OK"
done

new_repo
commit "$D" "$OWNER" "$OWNER" "gates: first"
commit "$D" "$OWNER" "$OWNER" "gates: second"
commit "$D" "$OWNER" "$OWNER" "gates: third"
expect "a clean history of three commits passes" "$D" HEAD 0 \
    "3 commit(s)" "no forbidden token, no foreign identity"

# The default range, exercised because CI's fallback branch - a new branch, or a
# force-push, where the before-image is not in the clone - depends on it.
new_repo
commit "$D" "$OWNER" "$OWNER" "gates: no range argument"
expect "no range argument defaults to the whole history" "$D" "" 0 "check-commit-messages: OK"

# --- 2. a foreign AUTHOR ------------------------------------------------------
#
# The case the identity check was added for. GitHub builds its contributor list
# from this field, so a clean message here buys nothing at all.
new_repo
commit "$D" "$FOREIGN" "$OWNER" "gates: a perfectly clean message"
expect "foreign AUTHOR is rejected (committer allowed, message clean)" "$D" HEAD 1 \
    "COMMIT IDENTITY POLICY VIOLATION" "author:    $FOREIGN"

# --- 3. a foreign COMMITTER ---------------------------------------------------
#
# The half that is easy to leave out, and the half a rebase or a cherry-pick on
# somebody else's machine produces without anyone typing an author flag.
new_repo
commit "$D" "$OWNER" "$FOREIGN" "gates: a perfectly clean message"
expect "foreign COMMITTER is rejected (author allowed, message clean)" "$D" HEAD 1 \
    "COMMIT IDENTITY POLICY VIOLATION" "committer:    $FOREIGN"

# --- 4. the identity that actually caused the incident ------------------------
new_repo
commit "$D" "$TOOL_IDENTITY" "$OWNER" "gates: a perfectly clean message"
expect "a tool identity in the author field is rejected" "$D" HEAD 1 \
    "COMMIT IDENTITY POLICY VIOLATION" "author:    $TOOL_IDENTITY"

new_repo
commit "$D" "$OWNER" "$TOOL_IDENTITY" "gates: a perfectly clean message"
expect "a tool identity in the committer field is rejected" "$D" HEAD 1 \
    "COMMIT IDENTITY POLICY VIOLATION" "committer:    $TOOL_IDENTITY"

# --- 5. every forbidden token, in the message, with clean identities ----------
#
# Driven off the gate's own list so that a fourth token cannot be added to it
# without this file proving that the addition works.
for t in "${TOKENS[@]}"; do
    new_repo
    commit "$D" "$OWNER" "$OWNER" "gates: a change

$t: somebody <somebody@example.invalid>"
    expect "forbidden token in the message is rejected: $t" "$D" HEAD 1 \
        "COMMIT MESSAGE POLICY VIOLATION" "token:   $t"
done

# The gate matches case-insensitively. Asserted rather than assumed: tooling and
# editors write these trailers in more than one casing, and a case-sensitive
# match would let the lower-cased spelling straight through.
lower=$(printf '%s' "${TOKENS[0]}" | tr 'A-Z' 'a-z')
new_repo
commit "$D" "$OWNER" "$OWNER" "gates: a change

$lower: somebody <somebody@example.invalid>"
expect "the token is caught in lower case too" "$D" HEAD 1 \
    "COMMIT MESSAGE POLICY VIOLATION"

# --- 6. near misses -----------------------------------------------------------
#
# The allowed list is matched whole. These cases are what stops it decaying into
# a match on the display name, which anybody can set to anything.
owner_name=$(id_name "$OWNER")
owner_email=$(id_email "$OWNER")

new_repo
commit "$D" "$owner_name <at@example.invalid>" "$OWNER" "gates: right name, wrong address"
expect "the owner's name with a foreign email is rejected" "$D" HEAD 1 \
    "COMMIT IDENTITY POLICY VIOLATION" "author:    $owner_name <at@example.invalid>"

new_repo
commit "$D" "somebody-else <$owner_email>" "$OWNER" "gates: right address, wrong name"
expect "the owner's email under another name is rejected" "$D" HEAD 1 \
    "COMMIT IDENTITY POLICY VIOLATION" "author:    somebody-else <$owner_email>"

# Documents the gate as it is: the comparison is exact, so a capitalised spelling
# of the owner's own name fails. That is the safe direction to err in, and
# writing it down here is what stops it being discovered during a release.
new_repo
commit "$D" "$(printf '%s' "$owner_name" | tr 'a-z' 'A-Z') <$owner_email>" "$OWNER" "gates: capitalised"
expect "the identity match is exact, so a re-cased name is rejected" "$D" HEAD 1 \
    "COMMIT IDENTITY POLICY VIOLATION"

# --- 7. it is every commit in the range, not the tip --------------------------
#
# The property the whole gate rests on: a bad commit cannot be corrected by a
# good one on top of it, so checking only the tip would be checking nothing.
new_repo
commit "$D" "$OWNER" "$OWNER" "gates: clean base"
commit "$D" "$FOREIGN" "$OWNER" "gates: the bad one, buried"
commit "$D" "$OWNER" "$OWNER" "gates: clean tip"
commit "$D" "$OWNER" "$OWNER" "gates: another clean tip"
expect "a foreign author three commits down is still caught" "$D" HEAD 1 \
    "COMMIT IDENTITY POLICY VIOLATION" "author:    $FOREIGN"

# Range scoping, which is what CI passes on a push. Same repository: the bad
# commit is outside base..HEAD and the gate is silent about it by design. Pinned
# here because it is the gate's one blind spot, and the reason CI falls back to
# the whole history whenever the before-image is not in the clone.
expect "a range that excludes the bad commit passes (documented scoping)" "$D" "HEAD~2..HEAD" 0 \
    "2 commit(s)"
expect "a range that includes it does not" "$D" "HEAD~3..HEAD" 1 \
    "COMMIT IDENTITY POLICY VIOLATION"

# --- 8. both roles, and message and identity together -------------------------
new_repo
commit "$D" "$FOREIGN" "$TOOL_IDENTITY" "gates: everything at once

${TOKENS[0]}: somebody <somebody@example.invalid>"
expect "author, committer and message violations are all reported" "$D" HEAD 1 \
    "author:    $FOREIGN" "committer:    $TOOL_IDENTITY" "COMMIT MESSAGE POLICY VIOLATION" \
    "3 violation(s) in 1 commit(s)"

# --- 9. the gate refuses to pass when it cannot run ---------------------------
#
# The failure mode this whole file is about, turned on the gate itself: handed a
# range that does not exist it must exit non-zero, not shrug and report clean.
new_repo
commit "$D" "$OWNER" "$OWNER" "gates: only commit"
expect "an unresolvable range is an error, never a pass" "$D" "no-such-ref..HEAD" 1 \
    "cannot resolve range"

printf '\n'
if [ "$FAILURES" -gt 0 ]; then
    printf 'selftest-commit-identity: FAILED - %d of %d cases.\n' "$FAILURES" "$((PASSES + FAILURES))"
    printf 'tools/ci/check-commit-messages.sh does not enforce the authorship policy as\n'
    printf 'specified. Until this passes, treat that gate as absent.\n'
    exit 1
fi
printf 'selftest-commit-identity: OK - %d cases, the gate accepts and rejects as specified.\n' "$PASSES"
exit 0
