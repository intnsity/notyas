#!/usr/bin/env bash
# check-xverify.sh - run the third-party cross-check, and make its absence unmistakable.
#
# tools/xverify/ puts Bitcoin Core and embit on the other side of everything this tree
# derives and signs. This script is the part that has to answer the harder question:
# what happens on a machine where the oracles are not installed.
#
# WHY THE DEFAULT REQUIRES THE CHECK
#
# An exit code is an assertion, and it is the only part of a gate that callers actually
# read. `if bash tools/ci/check-xverify.sh; then` is a sentence whose subject is "the
# cross-check" and whose verb is "passed". Until 0.2.0 this script answered 0 when it had
# verified nothing, which made that sentence unfalsifiable: 0 meant either "Core and embit
# agreed with all 21 cases" or "no oracle was reachable and nothing at all happened", and
# no caller could tell which. A banner does not repair that. Banners go to a terminal
# nobody is watching, scroll past in a CI log, and are invisible to `if`. The record in
# out/xverify/attestation.json was honest, but a file only helps a reader who already
# suspects the answer, and the whole failure mode here is a reader who does not.
#
# So the default is inverted: an unreachable oracle is a FAILURE (exit 3), and a caller
# who wants a green anyway has to say so on the command line. The old default was chosen
# to protect a developer whose machine has no bitcoind, and that cost is real, but it is
# paid by the one person who can fix it in a minute and who is standing right there
# reading the message. The old default's cost was paid by everyone downstream who read a
# green exit code as evidence, and they never found out.
#
# The opt-out is a FLAG and deliberately not an environment variable. An environment
# variable gets exported in a shell profile once and then silently suppresses the gate on
# that machine forever, which is the same vacuous pass wearing a different hat. A flag has
# to be typed into the command line that runs the gate, where it is visible in the CI
# config, in the release script and in the shell history of whoever chose it.
#
# MODES
#
#   (none)          Run it. A missing oracle is a failure. This is what CI, the release
#                   driver and any new caller get without reading this file.
#   --allow-absent  A missing oracle exits 0. For a developer's inner loop and for a
#                   machine that genuinely cannot host a Bitcoin node. It still prints the
#                   banner, still says NOT VERIFIED as its last line, and still writes an
#                   attestation whose status is "skipped" and whose "verified" field is
#                   false. Nothing about the run pretends the check happened.
#   --require       Accepted, and now a no-op: it is the default. Kept because
#                   .github/workflows/ci.yml and tools/release.sh already pass it.
#   --probe         Silent. Exit 0 if the oracles are here, 3 if not. Writes nothing, so a
#                   caller can choose its own words about an absence.
#   --run-id ID     Bind the attestation this run writes to ID. See BINDING below.
#   --assert-fresh ID
#                   Run nothing. Answer one question about the attestation already on
#                   disk: was it written by the run bearing ID, against this tree. Worth
#                   only as much as ID is unavailable to whoever could have written the
#                   files: see BINDING below before believing a pass.
#   --attestation-file PATH
#                   Read and write the attestation at PATH instead of
#                   out/xverify/attestation.json. For self-tests, which must not clobber
#                   a real verdict.
#   --tree-digest   Print the digest of the sources a cross-check is evidence about, and
#                   exit. It is what a binding records, and the answer to "why did my
#                   attestation stop counting" when the answer is "the code moved".
#
# BINDING: WHY A FILE ON DISK PROVES NOTHING BY ITSELF
#
# The attestation is the only durable evidence a cross-check leaves behind, and JSON on
# disk says nothing about when it was written or by whom. A file containing
# {"status": "verified"} planted in out/xverify used to survive the entire release path
# untouched: tools/release.sh asks --probe first, --probe writes nothing by design, and
# nothing downstream ever read the file. A stale verdict from last week and a forged one
# typed by hand were both indistinguishable from a live cross-check, to a script and to
# a person.
#
# So a run that is given --run-id writes a second file beside the attestation,
# <attestation>.run, containing three things: the run id its caller generated, a digest
# of the sources the cross-check is evidence about, and a digest of the attestation's own
# bytes. It is written at the END of a run this script witnessed, and it is deleted at the
# start of one and by the abort trap, so it never outlives the verdict it describes.
# --assert-fresh then answers "did the run I am thinking of write this", which is the
# question the release path actually needs; tools/release.sh generates a fresh unguessable
# id per release run and asks it again at the push.
#
# The limit, stated plainly: anything that can write to out/ at the moment of the check
# can write the binding too - and can edit this script. What the binding closes is the
# leftover and the forgery-in-advance, which is what was found.
#
# The second limit, which matters as much and is easier to miss: --assert-fresh is only
# as strong as the id the caller passes is out of reach of whoever could have written
# these files. A caller that generates the id and asks about it within the same run
# learns something, because the id was on no disk when the binding had to be written.
# A caller that reads the id back out of a file the same adversary can write learns only
# that the files agree with each other - tools/release.sh read it that way out of
# out/release/<version>/stamps/gates at the push, and a verdict typed by hand with a
# matching binding beside it exited 0. That caller now re-runs the cross-check with a
# fresh id whenever the oracles are present, and says so out loud when they are not.
#
# EXIT CODES
#
#   0  the cross-check ran and every case agreed with both oracles
#      (or it could not run and --allow-absent said that was acceptable)
#      (or, under --assert-fresh, the named run wrote this attestation and it verified)
#   1  the cross-check ran and at least one case disagreed
#      (or, under --assert-fresh, the named run wrote this attestation and it did not verify)
#   2  usage error
#   3  the cross-check did not run: a prerequisite is missing
#   4  --assert-fresh only: there is no attestation at all
#   5  --assert-fresh only: an attestation exists that the named run did not write
#
# 3 is distinct from 1 on purpose. "We could not check" and "we checked and it was wrong"
# call for different actions, and both are non-zero because neither is a pass. 4 and 5 are
# distinct for the same reason: an absent verdict is a gap, and a verdict of unknown
# origin sitting where this release's verdict belongs is a finding.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO=$(pwd)
ATTESTATION="$REPO/out/xverify/attestation.json"

# The pinned oracle, repeated here as well as in tools/xverify/README.md so the message a
# stuck operator reads names the exact version and digest to fetch. The authority for
# these digests is the signed SHA256SUMS published alongside the release by the Bitcoin
# Core builders, not this file; .github/workflows/ci.yml is where the linux one is
# actually enforced at download time.
CORE_VERSION=29.4
CORE_SHA256_LINUX=e15bff6f6d21a315c4af25d2e8ae933a22bd51e924e0e90ab0474e1e11516331
CORE_SHA256_WIN64=31e03b841bf2bbe711cf0179d3466678989fcbd46e5ef9bef957a20fa32e0e42

usage() {
    cat <<'USAGE'
check-xverify.sh - cross-check this tree against Bitcoin Core and embit.

  bash tools/ci/check-xverify.sh                 run it; a missing oracle is a failure
  bash tools/ci/check-xverify.sh --allow-absent  a missing oracle exits 0, loudly
  bash tools/ci/check-xverify.sh --probe         silent; 0 if the oracles are here, 3 if not
  bash tools/ci/check-xverify.sh --require       accepted, and a no-op: it is the default
  bash tools/ci/check-xverify.sh --run-id ID     bind the attestation this run writes to ID
  bash tools/ci/check-xverify.sh --assert-fresh ID
                                                 run nothing; was the attestation on disk
                                                 written by run ID against this tree
  bash tools/ci/check-xverify.sh --attestation-file PATH   use PATH, not out/xverify/
  bash tools/ci/check-xverify.sh --tree-digest   print the digest a binding records, and exit

Exit codes: 0 verified, 1 a case disagreed, 2 usage, 3 did not run,
            4 no attestation (--assert-fresh), 5 an attestation this run did not write.
Prerequisites and how to install them: tools/xverify/README.md
USAGE
}

MODE=verify
ALLOW_ABSENT=0
RUN_ID=""
WANT_RUN_ID=""

# An id is a name, not a message: it lands in a key = value file and is compared as a
# whole word, so it is restricted to characters that cannot smuggle a newline or a space
# into either side of that comparison.
check_run_id() {
    case "$1" in
        "") printf 'check-xverify: %s needs a run id\n' "$2" >&2; exit 2 ;;
        *[!A-Za-z0-9_-]*) printf 'check-xverify: %s: a run id may only contain A-Z a-z 0-9 _ -\n' "$2" >&2; exit 2 ;;
    esac
}

while [ $# -gt 0 ]; do
    case "$1" in
        --allow-absent) ALLOW_ABSENT=1; shift ;;
        --require) shift ;;  # the default since 0.2.0; accepted so existing callers keep working
        --probe) MODE=probe; shift ;;
        --run-id) RUN_ID=${2:-}; check_run_id "$RUN_ID" --run-id; shift 2 ;;
        --assert-fresh) MODE=assert; WANT_RUN_ID=${2:-}; check_run_id "$WANT_RUN_ID" --assert-fresh; shift 2 ;;
        --attestation-file) ATTESTATION=${2:-}; [ -n "$ATTESTATION" ] || { printf 'check-xverify: --attestation-file needs a path\n' >&2; exit 2; }; shift 2 ;;
        --tree-digest) MODE=tree-digest; shift ;;
        -h|--help) usage; exit 0 ;;
        *)
            printf 'check-xverify: unknown argument %s\n\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

# The binding lives beside the attestation it describes, named after it, for the same
# reason SHA256SUMS.txt.asc is: two files that only mean anything together should be
# impossible to move apart by accident.
BINDING="$ATTESTATION.run"

say() { [ "$MODE" = probe ] || printf '%s\n' "$*"; }

# --- the attestation ---------------------------------------------------------------
#
# One writer, so every status this script can produce carries the same fields and a
# reader never has to know which path wrote the file. Two of those fields exist purely to
# be unmistakable to a machine: "verified" is a bare boolean, and "tree_digest" is null
# unless a tree was really checked. A consumer that reads either one cannot accidentally
# read a skip as a pass; a consumer that reads only "status" sees a word that is not
# "passed". tools/xverify/xverify.py writes the same shape for the runs that get further
# than this script does.

json_escape() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }

# Read out of the harness rather than written down here, so the two can never disagree
# about how many cases exist. EXPECTED in xverify.py is the single definition. A tree with
# no harness in it reports 0, which is the truth about such a tree.
HARNESS="$REPO/tools/xverify/xverify.py"
if [ -f "$HARNESS" ]; then
    CASES_EXPECTED=$(sed -n '/^EXPECTED = \[/,/^\]/p' "$HARNESS" | grep -c '^    "' || true)
else
    CASES_EXPECTED=0
fi

# write_attestation <status> <verified> <conclusion> <exit_code> [missing...]
write_attestation() {
    local status=$1 verified=$2 conclusion=$3 code=$4
    shift 4
    local mode=default
    [ "$ALLOW_ABSENT" = 1 ] && mode=allow-absent
    mkdir -p "$(dirname "$ATTESTATION")"
    {
        printf '{\n'
        printf '  "status": "%s",\n' "$status"
        printf '  "verified": %s,\n' "$verified"
        printf '  "conclusion": "%s",\n' "$(json_escape "$conclusion")"
        printf '  "cases_verified": 0,\n'
        printf '  "cases_expected": %s,\n' "$CASES_EXPECTED"
        printf '  "harness_exit_code": %s,\n' "$code"
        printf '  "mode": "%s",\n' "$mode"
        printf '  "when": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf '  "written_by": "tools/ci/check-xverify.sh",\n'
        printf '  "tree_digest": null,\n'
        printf '  "attests_to": null,\n'
        printf '  "missing": ['
        local first=1 reason
        for reason in "$@"; do
            [ "$first" = 1 ] || printf ','
            printf '\n    "%s"' "$(json_escape "$reason")"
            first=0
        done
        [ "$first" = 1 ] || printf '\n  '
        printf ']\n}\n'
    } > "$ATTESTATION"
}

# --- the binding -----------------------------------------------------------------------
#
# The sources this cross-check is evidence ABOUT. The same three directories
# tools/xverify/xverify.py names in its own "attests_to" field, and for its reason: a
# cross-check is only evidence about the code it exercised. notyas-core and notyas-wallet
# decide what gets derived and signed; the harness decides what gets asked. Digesting the
# whole tree instead would invalidate every attestation whenever a document was edited,
# and an attestation that goes stale for no reason is one nobody reads.
XVERIFY_TREE_DIRS="crates/notyas-core/src crates/notyas-wallet/src tools/xverify"

# Paths are part of the digest, so a renamed or deleted file changes it as surely as an
# edited one. Build outputs are not: target/ and __pycache__ hold things a compiler
# writes, and an attestation that expired the moment somebody ran cargo would teach
# people to ignore it.
xverify_tree_digest() {
    local files
    files=$(cd "$REPO" && find $XVERIFY_TREE_DIRS -type f \
        \( -name '*.rs' -o -name '*.py' -o -name '*.toml' \) \
        ! -path '*/target/*' ! -path '*/__pycache__/*' -print 2>/dev/null | LC_ALL=C sort)
    if [ -z "$files" ]; then
        printf 'check-xverify: no cross-checked sources found under %s\n' "$XVERIFY_TREE_DIRS" >&2
        return 1
    fi
    (cd "$REPO" && printf '%s\n' "$files" | tr '\n' '\0' | xargs -0 sha256sum) \
        | sha256sum | cut -d' ' -f1
}

file_digest() { sha256sum < "$1" | cut -d' ' -f1; }

# Deliberately dumb readers. The attestation has two writers - this script and
# xverify.py - and both emit one field per line, so a line-oriented read of the two
# fields that carry the verdict cannot be wrong about a shape it does not parse.
attestation_says()     { sed -n 's/.*"'"$1"'": *"\([^"]*\)".*/\1/p' "$ATTESTATION" | head -1; }
attestation_verified() { grep -Eq '"verified"[[:space:]]*:[[:space:]]*true' "$ATTESTATION"; }
binding_says()         { sed -n 's/^'"$1"' = //p' "$BINDING" | head -1; }

# Written only at the end of a run this script watched happen, and only when a caller
# named that run.
write_binding() {
    local digest
    digest=$(xverify_tree_digest) || return 1
    mkdir -p "$(dirname "$BINDING")"
    {
        printf '# Binding for %s, written by tools/ci/check-xverify.sh at the end of a\n' "$(basename "$ATTESTATION")"
        printf '# run it witnessed. The attestation beside this file is a JSON document of\n'
        printf '# unknown origin without it: see BINDING in that script.\n'
        printf 'run_id = %s\n' "$RUN_ID"
        printf 'tree_digest = %s\n' "$digest"
        printf 'tree_dirs = %s\n' "$XVERIFY_TREE_DIRS"
        printf 'attestation_sha256 = %s\n' "$(file_digest "$ATTESTATION")"
        printf 'status = %s\n' "$(attestation_says status)"
        printf 'when = %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } > "$BINDING"
}

stated() { if [ -n "$1" ]; then printf '%s' "$1"; else printf '(no such field)'; fi; }

refuse_stale() {
    local why=$1
    printf '\n' >&2
    printf 'check-xverify: the attestation at %s cannot be believed: %s\n' "$ATTESTATION" "$why" >&2
    # Printed rather than summarised: what the file claims is what the operator has to
    # judge, and a field it does not carry at all is itself a finding - both writers in
    # this tree emit every one of them.
    printf 'check-xverify: it claims status "%s", verified %s, written %s by %s\n' \
        "$(stated "$(attestation_says status)")" \
        "$(if attestation_verified; then printf true; else printf false; fi)" \
        "$(stated "$(attestation_says when)")" "$(stated "$(attestation_says written_by)")" >&2
    printf 'check-xverify: a cross-check verdict is evidence about ONE run against ONE tree.\n' >&2
    printf 'check-xverify: this one is not this run'"'"'s. Read it, then remove it:\n' >&2
    printf 'check-xverify:   rm -f "%s" "%s"\n' "$ATTESTATION" "$BINDING" >&2
    exit 5
}

# Runs nothing, checks the file. The three comparisons are one question asked three ways,
# and all three have to hold: the binding names the run the caller means, the sources it
# was made against are the sources here now, and the attestation has not been rewritten
# since the binding was made.
assert_fresh() {
    local want=$1 digest
    if [ ! -f "$ATTESTATION" ]; then
        if [ -f "$BINDING" ]; then
            printf 'check-xverify: %s binds an attestation that is not there. Remove it: rm -f "%s"\n' \
                "$BINDING" "$BINDING" >&2
            exit 5
        fi
        printf 'check-xverify: no attestation at %s; nothing claims a cross-check happened\n' "$ATTESTATION"
        exit 4
    fi
    [ -f "$BINDING" ] || refuse_stale "there is no binding beside it, so nothing says which run wrote it"

    [ "$(binding_says run_id)" = "$want" ] \
        || refuse_stale "its binding names run $(binding_says run_id), and the caller asked about run $want"

    digest=$(xverify_tree_digest) || exit 5
    [ "$(binding_says tree_digest)" = "$digest" ] \
        || refuse_stale "the cross-checked sources have changed since it was written (binding $(binding_says tree_digest), tree now $digest)"

    [ "$(binding_says attestation_sha256)" = "$(file_digest "$ATTESTATION")" ] \
        || refuse_stale "the attestation has been rewritten since its binding was made"

    if attestation_verified && [ "$(attestation_says status)" = passed ]; then
        printf 'check-xverify: run %s wrote %s against this tree, and it VERIFIED\n' "$want" "$ATTESTATION"
        exit 0
    fi
    printf 'check-xverify: run %s wrote this attestation and it did NOT verify: status "%s"\n' \
        "$want" "$(attestation_says status)" >&2
    printf 'check-xverify: %s\n' "$(attestation_says conclusion)" >&2
    exit 1
}

if [ "$MODE" = tree-digest ]; then
    xverify_tree_digest
    exit 0
fi

if [ "$MODE" = assert ]; then
    assert_fresh "$WANT_RUN_ID"
fi

# A run that dies without saying anything - a killed terminal, a cargo build that blew up -
# must not leave the previous run's verdict standing as if it were this run's. The
# in-progress record is written before the first thing that can fail, and this trap turns
# it into a recorded abort. The status guard means a path that already wrote its own
# verdict keeps it. The binding goes unconditionally: a verdict nobody finished is not one
# any run gets to vouch for.
on_exit() {
    local code=$?
    [ "$MODE" = verify ] || return 0
    if [ "$code" -ne 0 ]; then
        rm -f "$BINDING"
        if [ -f "$ATTESTATION" ] && grep -q '"status": "running"' "$ATTESTATION"; then
            write_attestation aborted false \
                "NOT VERIFIED - the cross-check started and did not finish" "$code" \
                "the harness exited with code $code before it could report"
        fi
    fi
}
trap on_exit EXIT

banner() {
    printf '\n' >&2
    printf '%s\n' "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" >&2
    printf '%s\n' "!! THE THIRD-PARTY CROSS-CHECK DID NOT RUN" >&2
    printf '%s\n' "!!" >&2
    printf '%s\n' "!! Nothing signed by this tree has been checked against an implementation" >&2
    printf '%s\n' "!! outside it. Missing, precisely:" >&2
    printf '%s\n' "!!" >&2
    local line
    for line in "$@"; do
        printf '!!   - %s\n' "$line" >&2
    done
    printf '%s\n' "!!" >&2
    printf '!! Install: Bitcoin Core %s and embit. Exact versions, digests and the\n' "$CORE_VERSION" >&2
    printf '%s\n' "!! Windows notes are in tools/xverify/README.md, section 'Installing the" >&2
    printf '%s\n' "!! oracles'. Recorded as skipped in out/xverify/attestation.json." >&2
    printf '%s\n' "!!" >&2
    printf '%s\n' "!! If this machine genuinely cannot run a Bitcoin node, pass --allow-absent" >&2
    printf '%s\n' "!! to say so explicitly. It exits 0 and records the same refusal." >&2
    printf '%s\n' "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" >&2
}

# Reported all at once, not one per run: a gate that names one missing tool, then another
# on the next run, then a third, is a gate people route around.
absent() {
    if [ "$MODE" = probe ]; then exit 3; fi
    banner "$@"
    # Whatever was here described some other run. A skip vouches for nothing.
    rm -f "$BINDING"
    if [ "$ALLOW_ABSENT" = 1 ]; then
        write_attestation skipped false \
            "NOT VERIFIED - the cross-check could not run, and --allow-absent accepted that" 0 "$@"
        printf 'check-xverify: NOT VERIFIED - nothing was cross-checked (--allow-absent, exit 0)\n'
        exit 0
    fi
    write_attestation skipped false \
        "NOT VERIFIED - the cross-check could not run" 3 "$@"
    printf 'check-xverify: NOT VERIFIED - nothing was cross-checked (exit 3)\n' >&2
    printf 'check-xverify: pass --allow-absent only if this machine truly cannot host the oracles.\n' >&2
    exit 3
}

# --- find the oracles, and say exactly which piece is missing ------------------------
#
# Nothing here searches a filesystem: a gate that went hunting for a bitcoind would be
# slow when it worked and unbounded when it did not. Either a variable or PATH names it.

MISSING=()
note_missing() { MISSING+=("$1"); }

# An explicitly named tool that is not there is a different mistake from one that was
# never named - a typo in a variable, usually - and it deserves its own sentence.
resolve_named() {
    local var_name=$1 var_value=$2 tool=$3
    if [ -n "$var_value" ]; then
        if [ -x "$var_value" ] || command -v "$var_value" > /dev/null 2>&1; then
            printf '%s' "$var_value"
        else
            note_missing "$var_name names '$var_value', which is not an executable file"
        fi
        return
    fi
    command -v "$tool" 2> /dev/null || true
}

BITCOIND=$(resolve_named NOTYAS_XVERIFY_BITCOIND "${NOTYAS_XVERIFY_BITCOIND:-}" bitcoind)
BITCOIN_CLI=$(resolve_named NOTYAS_XVERIFY_BITCOIN_CLI "${NOTYAS_XVERIFY_BITCOIN_CLI:-}" bitcoin-cli)

[ -n "$BITCOIND" ] || note_missing \
    "bitcoind: not on PATH and NOTYAS_XVERIFY_BITCOIND is unset. Need Bitcoin Core $CORE_VERSION (linux-x86_64 tarball sha256 $CORE_SHA256_LINUX, win64 zip sha256 $CORE_SHA256_WIN64)"
[ -n "$BITCOIN_CLI" ] || note_missing \
    "bitcoin-cli: not on PATH and NOTYAS_XVERIFY_BITCOIN_CLI is unset. It ships in the same Bitcoin Core $CORE_VERSION archive as bitcoind"

# The interpreter question and the embit question are one question, because a python that
# cannot import embit is as useless here as no python at all. The three ways it goes wrong
# are told apart by name, because they have three different fixes and a message that
# merges them sends people to the wrong one. On Windows the first is the usual case:
# `python3` on PATH is the Microsoft Store app-execution alias, which is not an
# interpreter - it prints an advertisement to stderr and exits 49.
#
# The two diagnoses are kept apart and the first working interpreter wins, because they
# are not equally useful. "Install embit into THIS interpreter" is a command the operator
# can paste; "that name is a stub" only tells them where not to look. Reporting whichever
# candidate happened to be tried last would bury the actionable one.
PYTHON=""
PY_NO_EMBIT=""
PY_UNRUNNABLE=""
for candidate in "${NOTYAS_XVERIFY_PYTHON:-}" python3 python py; do
    [ -n "$candidate" ] || continue
    command -v "$candidate" > /dev/null 2>&1 || continue
    resolved=$(command -v "$candidate")
    if ! version=$("$candidate" -c 'import sys; print(sys.version.split()[0])' 2>/dev/null); then
        [ -n "$PY_UNRUNNABLE" ] && continue
        case "$resolved" in
            *WindowsApps*) PY_UNRUNNABLE="'$candidate' resolves to the Microsoft Store stub at $resolved, which is not an interpreter (it exits 49 without running anything)" ;;
            *) PY_UNRUNNABLE="'$candidate' ($resolved) is on PATH but could not run a one-line program" ;;
        esac
        continue
    fi
    if "$candidate" -c 'import embit' > /dev/null 2>&1; then
        PYTHON=$candidate
        break
    fi
    [ -n "$PY_NO_EMBIT" ] || PY_NO_EMBIT="$resolved is Python $version but cannot import embit. Install it into that exact interpreter: \"$resolved\" -m pip install embit"
done
[ -n "$PYTHON" ] || note_missing \
    "python with embit: ${PY_NO_EMBIT:-${PY_UNRUNNABLE:-no python3, python or py on PATH at all}}. Set NOTYAS_XVERIFY_PYTHON to an interpreter that can import embit"

command -v cargo > /dev/null 2>&1 || note_missing \
    "cargo: not on PATH, so the notyas side of the cross-check cannot be built (rustup.rs)"

# The harness is not a prerequisite anyone installs, but a tree without it produces a
# green from every other check in this script, and that is the one absence nobody would
# think to look for.
[ -f "$HARNESS" ] || note_missing \
    "tools/xverify/xverify.py is not in this tree, so there is no cross-check to run"

if [ ${#MISSING[@]} -gt 0 ]; then
    absent "${MISSING[@]}"
fi

if [ "$MODE" = probe ]; then exit 0; fi

# The pinned version is what the 21 cases were written against. A different major version
# is recorded rather than refused: it is a fact about the run, not a reason to withhold
# evidence that Core disagreed with something.
CORE_BANNER=$("$BITCOIND" -version 2>/dev/null | head -1 || true)
case "$CORE_BANNER" in
    *"version v$CORE_VERSION"*) ;;
    *) printf 'check-xverify: note - %s, not the pinned Bitcoin Core %s. The attestation records what ran.\n' \
           "${CORE_BANNER:-bitcoind did not report a version}" "$CORE_VERSION" >&2 ;;
esac

# From here a real run is under way, so the previous run's verdict stops being the
# standing answer immediately rather than when this one finishes - and neither does the
# binding that vouched for it.
rm -f "$BINDING"
write_attestation running false "NOT VERIFIED - a cross-check is in progress" 3 \
    "this run has not reported yet"

# --- build the device side ----------------------------------------------------------
#
# Debug, not release: this binary derives a few keys and signs a few inputs, and a release
# build would cost more in compile time than it saves. --locked so the graph that runs is
# the graph that was resolved.

say "check-xverify: building the device side"
# From inside the crate directory, not with --manifest-path from the root: cargo reads
# .cargo/config.toml relative to the CWD, so a build launched from the repository root
# would silently take the WORKSPACE's target directory and ignore the one this crate pins
# for itself. Same reason for asking cargo where the artifacts went from in there.
(cd tools/xverify && cargo build --locked)
TARGET_DIR=$(cd tools/xverify && cargo metadata --format-version 1 --no-deps \
    | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p' | sed 's/\\\\/\//g')

# The .exe is tested first and explicitly. On MSYS, `test -x foo` succeeds for a file
# actually named foo.exe, so a path that looks fine to this shell can be a path the
# harness cannot open.
DEVICE="$TARGET_DIR/debug/xverify-device.exe"
[ -f "$DEVICE" ] || DEVICE="$TARGET_DIR/debug/xverify-device"
[ -f "$DEVICE" ] || absent "xverify-device: cargo build reported success but no binary is in $TARGET_DIR/debug"

# --- run -----------------------------------------------------------------------------

say "check-xverify: running the cross-check"
set +e
"$PYTHON" tools/xverify/xverify.py \
    --bitcoind "$BITCOIND" \
    --bitcoin-cli "$BITCOIN_CLI" \
    --device "$DEVICE" \
    --attestation "$ATTESTATION"
STATUS=$?
set -e

# The harness has written its verdict. Vouch for it - or, when no caller named this run,
# make sure nothing else is vouching for it either.
rm -f "$BINDING"
if [ -n "$RUN_ID" ] && [ -f "$ATTESTATION" ]; then
    write_binding
fi

case "$STATUS" in
    0) say "check-xverify: VERIFIED - all $CASES_EXPECTED cases agreed with Bitcoin Core and embit" ;;
    3)
        # The harness got further than this script did and found the gap itself: embit
        # importable but broken, a node that would not start. It has already written its
        # own skip attestation, which is richer than anything this script could write
        # about a failure it did not witness, so that record stands. Only the policy is
        # applied here.
        if [ "$ALLOW_ABSENT" = 1 ]; then
            printf 'check-xverify: NOT VERIFIED - the harness could not reach its oracles (--allow-absent, exit 0)\n'
            STATUS=0
        else
            printf 'check-xverify: NOT VERIFIED - the harness could not reach its oracles (exit 3)\n' >&2
            printf 'check-xverify: see the banner above and out/xverify/attestation.json\n' >&2
        fi
        ;;
    1) printf 'check-xverify: FAIL - a case disagreed. See out/xverify/attestation.json\n' >&2 ;;
    *) printf 'check-xverify: FAIL - the harness exited %d. See out/xverify/attestation.json\n' "$STATUS" >&2 ;;
esac

exit "$STATUS"
