#!/usr/bin/env bash
# check-ratified.sh - assert the tree against the ratified answers.
#
# WHY THIS EXISTS. On 2026-08-19 a build reached the owner's hands in which
# crates/notyas-ui carried PIN_MIN = 6 and gated the Unlock button on it, while the
# ratified answer (Q4) put the PIN floor at 4 and the store formatted at 4. A device
# holding the owner's own 4-digit PIN could not be unlocked through the touchscreen at
# all. Every test in the tree passed, because every test agreed with the code. The defect
# was not a bug in a function - it was CODE THAT CONTRADICTED A RATIFIED DECISION, and
# nothing in the repository compared the two. This script is that comparison.
#
# WHAT IT IS AND IS NOT. It is not a linter and not a test. Each assertion below names one
# owner decision, quotes it, and checks the one property of the tree that decision makes
# mechanically checkable. A failure here means the tree and the ratified answer disagree;
# the tree is wrong until the owner says otherwise, and a deliberate change of mind is
# made by editing docs/archive/plan-0.2.0/OPEN-QUESTIONS.md (or PIN-MODES.md) FIRST and this file
# second. That is the reason every assertion quotes its decision inline: a future reader
# staring at a red gate has to be able to tell a regression from a decision that moved,
# without reading 168 KB of question register.
#
# THE RULE THIS GATE IS BUILT ON, taken from check-xverify.sh and check-release-symbols.sh:
# a gate that silently skips is worse than no gate, because the suite goes green and
# everyone believes it ran. So there is no skip path anywhere in this file. An assertion
# that cannot find the anchor it reads - a renamed constant, a moved block, a deleted file -
# reports that it COULD NOT EVALUATE and the script exits 2. Absence of evidence is
# reported as absence of evidence, never as a pass.
#
# TEETH. A detector that matches nothing is indistinguishable from a clean tree, and half
# these assertions currently pass. So every pattern-based detector is run against fixtures
# first: tools/ci/fixtures/ratified/*.bad must be caught, *.good must not be. A detector
# that fails its own fixture exits 2 before the real scan runs at all.
#
# USAGE
#   bash tools/ci/check-ratified.sh              run the self-test, then every assertion
#   bash tools/ci/check-ratified.sh --list       print the assertions and their decisions
#   bash tools/ci/check-ratified.sh --self-test  run only the fixture self-test
#
# EXIT CODES (distinct on purpose, the way check-xverify.sh separates "did not run" from
# "ran and failed"):
#   0  every assertion evaluated and held
#   1  the tree contradicts a ratified answer
#   2  the gate could not evaluate an assertion, or a detector failed its own fixture
#
# It scans TRACKED and untracked-but-not-ignored files, for the reason check-dashes.sh
# gives: a gate exists to catch a violation before it lands, and a new file is exactly
# where one lands.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO=$PWD

# This file and its fixtures quote the very strings they hunt for, so they are excluded
# from every scan. check-dashes.sh and tools/release.sh solve the same problem by
# assembling their search strings from parts; an explicit exclusion is clearer here,
# because the fixtures must contain the violations verbatim to be worth anything.
SELF=tools/ci/check-ratified.sh
FIXTURES=tools/ci/fixtures/ratified

# ---------------------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------------------

N_PASS=0
N_FAIL=0
N_BROKEN=0
CURRENT_ID=""

# Announce an assertion. Every one names the question it enforces and quotes the decision,
# so a red line in a CI log is readable without the register open beside it.
assertion() {
    CURRENT_ID=$1
    printf '\n[%s] %s\n' "$1" "$2"
    printf '      %s: "%s"\n' "$3" "$4"
}

pass() {
    N_PASS=$((N_PASS + 1))
    printf '  ok    %s\n' "$*"
}

# A violation: the tree contradicts the decision. Always carries the exact fix, because
# this gate is run by lanes that are fenced out of the source it reads.
violation() {
    N_FAIL=$((N_FAIL + 1))
    printf '  FAIL  %s\n' "$1"
    shift
    local line
    for line in "$@"; do printf '        %s\n' "$line"; done
}

# The gate could not evaluate. Never a pass, never a skip, and a different exit code from
# a violation so a caller can tell "the tree is wrong" from "this script is stale".
unevaluable() {
    N_BROKEN=$((N_BROKEN + 1))
    printf '  BROKEN  %s could not be evaluated: %s\n' "$CURRENT_ID" "$1"
    shift
    local line
    for line in "$@"; do printf '          %s\n' "$line"; done
    printf '          A gate that cannot evaluate an assertion states so and fails. Fix the\n'
    printf '          anchor this assertion reads, or move the assertion with the code.\n'
}

# ---------------------------------------------------------------------------------------
# Exemptions
# ---------------------------------------------------------------------------------------
#
# Some files must quote a superseded answer to do their job: the question register records
# what was replaced, and the review that FOUND a contradiction quotes the wrong literal
# verbatim. Those are exempted by name, with the reason, per assertion.
#
# An exemption that matches nothing is itself a defect and fails the gate. That is what
# stops this table from becoming the place violations go to be forgotten: an exemption
# only survives while the thing it excuses is still there.

EXEMPT_SPEC="\
Q4-DOCS|docs/archive/plan-0.2.0/OPEN-QUESTIONS.md|the decision register itself. Q4 records the superseded 6-character proposal and Q62 records the rejected 10-digit option (a); a register that could not quote the answer it replaced would stop being a record.
Q4-DOCS|docs/archive/plan-0.2.0/UX-REVISION.md|entry D1 is the review that found this exact contradiction and quotes the wrong literal to name it. Deleting the quote would delete the finding.
"

# Which exemptions fired, recorded in a FILE rather than a variable. exempt_filter runs
# inside a pipeline, and a pipeline stage is a subshell whose variable assignments die with
# it - so a variable here would leave every exemption looking stale and the gate would
# report a failure of its own making.
EXEMPT_USED=$(mktemp)
trap 'rm -f "$EXEMPT_USED"' EXIT

# Read "file:line:text" on stdin, drop lines from files exempted for ASSERTION, and record
# which exemptions actually fired.
exempt_filter() {
    local id=$1 line file spec_id spec_file hit
    while IFS= read -r line; do
        file=${line%%:*}
        hit=no
        while IFS='|' read -r spec_id spec_file _; do
            [ -n "$spec_id" ] || continue
            if [ "$spec_id" = "$id" ] && [ "$spec_file" = "$file" ]; then
                hit=yes
                printf '%s@%s\n' "$spec_id" "$spec_file" >> "$EXEMPT_USED"
            fi
        done <<< "$EXEMPT_SPEC"
        [ "$hit" = yes ] || printf '%s\n' "$line"
    done
}

check_exemptions_are_live() {
    assertion "EXEMPT" "Every exemption in this gate still excuses something real." \
        "gate design" "an exemption that matches nothing is where a violation goes to be forgotten"
    local spec_id spec_file reason
    while IFS='|' read -r spec_id spec_file reason; do
        [ -n "$spec_id" ] || continue
        if grep -qxF "$spec_id@$spec_file" "$EXEMPT_USED" 2>/dev/null; then
            pass "$spec_id exempts $spec_file, and it is still needed"
        else
            violation "$spec_id exempts $spec_file, which no longer matches anything" \
                "reason on file: $reason" \
                "Remove the exemption. It now hides nothing, so the next violation in" \
                "that file would pass unseen."
        fi
    done <<< "$EXEMPT_SPEC"
}

# ---------------------------------------------------------------------------------------
# File sets
# ---------------------------------------------------------------------------------------

# Tracked plus untracked-but-not-ignored, minus this gate and its fixtures.
tree_files() {
    { git ls-files; git ls-files --others --exclude-standard; } \
        | grep -v "^$SELF$" \
        | grep -v "^$FIXTURES/" \
        | sort -u
}

# The product code of a Rust file: everything above the first `#[cfg(test)]`, with
# whole-line comments dropped.
#
# Both halves are load-bearing. A test module legitimately names the wrong literal - the
# regression test for the PIN floor asserts the widest string the clamp admits, which is
# "at least 64 characters" - and a comment legitimately names the row it removed
# (screens/lock.rs says so about the capacity line). Neither is what ships to the panel.
# By house convention the test module is the last item in the file, so the first
# `#[cfg(test)]` is the boundary; a file with no test module is scanned whole.
product_lines() {
    awk '/^[[:space:]]*#\[cfg\(test\)\]/ { exit } /^[[:space:]]*\/\// { next } { print FILENAME ":" NR ":" $0 }' "$1"
}

# ---------------------------------------------------------------------------------------
# Detectors
#
# Each takes files as arguments and prints "file:line:text" for every hit. They are
# separate functions rather than inline greps for one reason: the fixture self-test runs
# these same functions against known-bad and known-good files, so what the assertions use
# is what was proved to have teeth.
# ---------------------------------------------------------------------------------------

# The shape of a stated PIN length, in any of the four forms the tree and its
# specifications actually use. Shared by the two detectors below.
PIN_LENGTH_RE="at least [0-9]+ (character|digit)|after [0-9]+ (digit|character)|[Bb]elow [0-9]+ character|(minimum [0-9]+[^\"]*alphanumeric|alphanumeric[^\"]*minimum [0-9]+)"

# Q37, in CODE. A PIN length written as a literal at all, whatever its value.
#
# The value is not the test here and must not be: "Available after 4 digits." is right
# today and drifts silently the day the constant beside it moves, which is the same defect
# as PIN_MIN = 6 caught one step earlier. The format-string form carries no digit and
# never matches, which is exactly the distinction the decision draws.
det_pin_length_literal() {
    local f
    for f in "$@"; do
        [ -f "$f" ] || continue
        product_lines "$f" | grep -E "$PIN_LENGTH_RE" || true
    done
}

# Q4, in DOCUMENTS. A stated floor whose number is not the ratified 4.
#
# Looser than the code rule on purpose: a document stating the floor is documentation, not
# copy on a panel, and the register and the specifications have to be able to say what the
# floor IS. What they may not do is say it is something else, which is how UX-SCREENS came
# to specify the literal that shipped.
det_pin_floor_wrong() {
    local f
    for f in "$@"; do
        [ -f "$f" ] || continue
        awk '{ print FILENAME ":" NR ":" $0 }' "$f" \
             | grep -E "$PIN_LENGTH_RE" \
             | awk -F: '{ n = ""; if (match($0, /at least [0-9]+/)) n = substr($0, RSTART + 9, RLENGTH - 9);
                          else if (match($0, /after [0-9]+/)) n = substr($0, RSTART + 6, RLENGTH - 6);
                          else if (match($0, /[Bb]elow [0-9]+/)) n = substr($0, RSTART + 6, RLENGTH - 6);
                          else if (match($0, /minimum [0-9]+/)) n = substr($0, RSTART + 8, RLENGTH - 8);
                          if (n + 0 != 4) print }' \
             | grep -v "no maximum below 64 characters" || true
    done
}

# Q2(a), as the owner extended it on 2026-08-19. A pre-PIN surface stating how many
# wallets the device holds, or could hold. String literals in product code only: the
# comment recording the row's removal is not a claim to a coercer.
det_capacity_claim() {
    local f
    for f in "$@"; do
        [ -f "$f" ] || continue
        product_lines "$f" \
            | grep -E '"[^"]*(holds up to|[0-9]+ of [0-9]+ (slot|wallet)|of \{WALLET_SLOTS\}|slots used|capacity)[^"]*"' || true
    done
}

# Q45. A call that programs an eFuse.
det_efuse_burn() {
    local f
    for f in "$@"; do
        [ -f "$f" ] || continue
        grep -nE "burn_hmac_up_key|burn_key|esp_efuse_write_key" "$f" \
            | grep -vE "^[0-9]+:[[:space:]]*(//|///|//!)" \
            | sed "s|^|$f:|" || true
    done
}

# The release identity, stated as the retired RSA-3072 key rather than the rsa4096 one.
det_release_identity() {
    local f
    for f in "$@"; do
        [ -f "$f" ] || continue
        grep -nE "OpenPGP RSA-3072|releases? (are|is) signed[^|]*RSA-3072|release (signing )?key[^|]*RSA-3072" "$f" \
            | sed "s|^|$f:|" || true
    done
}

# Q62. A floor that withholds the wipe-off setting from a short PIN.
det_wipe_disable_floor() {
    local f
    for f in "$@"; do
        [ -f "$f" ] || continue
        product_lines "$f" \
            | grep -E "(WIPE_DISABLE_MIN_PIN|disable_wipe_min_pin_len)[^,;]*(=|:)[[:space:]]*Some\(" || true
    done
}

# Q63. Secure boot or flash encryption switched on in a build configuration.
det_secure_boot_enabled() {
    local f
    for f in "$@"; do
        [ -f "$f" ] || continue
        grep -nE "^CONFIG_(SECURE_BOOT|SECURE_BOOT_V2_ENABLED|SECURE_FLASH_ENC_ENABLED|SECURE_BOOT_INSECURE)=y" "$f" \
            | sed "s|^|$f:|" || true
    done
}

# ---------------------------------------------------------------------------------------
# Fixture self-test
# ---------------------------------------------------------------------------------------

self_test() {
    printf '\n=== self-test: every detector against its fixtures ===\n'
    local broken=0 name det bad good hits

    for pair in \
        "pin-length-literal|det_pin_length_literal" \
        "pin-floor-wrong|det_pin_floor_wrong" \
        "capacity-claim|det_capacity_claim" \
        "efuse-burn|det_efuse_burn" \
        "release-identity|det_release_identity" \
        "wipe-disable-floor|det_wipe_disable_floor" \
        "secure-boot|det_secure_boot_enabled"
    do
        name=${pair%%|*}
        det=${pair##*|}
        bad=$(ls "$FIXTURES/$name".bad.* 2>/dev/null | head -1 || true)
        good=$(ls "$FIXTURES/$name".good.* 2>/dev/null | head -1 || true)

        if [ -z "$bad" ] || [ -z "$good" ]; then
            printf '  BROKEN  %s: fixtures missing (%s/%s.bad.* and .good.*)\n' "$name" "$FIXTURES" "$name"
            printf '          A detector with no fixture is a detector nobody has proved fires.\n'
            broken=1
            continue
        fi

        hits=$("$det" "$bad")
        if [ -z "$hits" ]; then
            printf '  BROKEN  %s did not catch %s\n' "$det" "$bad"
            printf '          The detector is dead. Until it is fixed, a clean run of this gate\n'
            printf '          means nothing for this assertion.\n'
            broken=1
        else
            printf '  ok    %s catches %s\n' "$det" "$(basename "$bad")"
        fi

        hits=$("$det" "$good")
        if [ -n "$hits" ]; then
            printf '  BROKEN  %s fires on the sanctioned form in %s:\n' "$det" "$good"
            printf '%s\n' "$hits" | sed 's/^/            /'
            printf '          A detector that flags the correct code teaches people to ignore it.\n'
            broken=1
        else
            printf '  ok    %s is quiet on %s\n' "$det" "$(basename "$good")"
        fi
    done

    return $broken
}

# ---------------------------------------------------------------------------------------
# Anchored value reads
#
# These read a specific constant out of a specific file. Every one of them can fail to
# find its anchor, and every one of them says so rather than defaulting.
#
# Each ends in `|| true`, and that is not sloppiness. This script runs under `set -e` with
# `pipefail`, so a grep that matches nothing inside a command substitution aborts the whole
# run - silently, mid-assertion, with a zero-length report and an exit code a caller could
# read as anything. That failure mode is precisely the one the design forbids: a missing
# anchor must arrive as "COULD NOT EVALUATE", loudly, and the emptiness of these reads is
# what the assertions test for.
# ---------------------------------------------------------------------------------------

# The right-hand side of `const NAME: TYPE = VALUE;` in a file.
const_value() {
    grep -hE "^[[:space:]]*(pub |pub\(crate\) )?const $2:" "$1" 2>/dev/null \
        | head -1 \
        | sed -E 's/.*=[[:space:]]*([^;]+);.*/\1/' \
        | sed 's/[[:space:]]*$//' \
        || true
}

# One field of `Config::NOTYAS_RELEASE`, the configuration the release firmware mounts
# with. The block is bounded by its own opening line and the `};` that closes it.
release_cfg() {
    awk '/pub const NOTYAS_RELEASE: Config = Config \{/, /^[[:space:]]*\};/' \
        crates/notyas-wallet/src/config.rs 2>/dev/null \
        | grep -E "^[[:space:]]*$1:" \
        | head -1 \
        | sed -E "s/^[[:space:]]*$1:[[:space:]]*//; s/,[[:space:]]*$//" \
        || true
}

# ---------------------------------------------------------------------------------------
# The assertions
# ---------------------------------------------------------------------------------------

Q4_STORE_FLOOR=""

a_q4_store_floor() {
    assertion "Q4-STORE" "The store formats at the ratified PIN floor." \
        "Q4" "minimum 4 characters, full alphanumeric supported and actively nudged, no maximum below 64 characters"

    local v
    v=$(release_cfg min_pin_len)
    if [ -z "$v" ]; then
        unevaluable "Config::NOTYAS_RELEASE has no min_pin_len field this script can read" \
            "expected it in crates/notyas-wallet/src/config.rs inside the NOTYAS_RELEASE block."
        return
    fi
    Q4_STORE_FLOOR=$v
    if [ "$v" = 4 ]; then
        pass "Config::NOTYAS_RELEASE formats at min_pin_len = 4"
    else
        violation "Config::NOTYAS_RELEASE formats at min_pin_len = $v, and the ratified floor is 4" \
            "Fix: crates/notyas-wallet/src/config.rs, NOTYAS_RELEASE.format_policy.min_pin_len = 4"
    fi
}

a_q4_ui_floor() {
    assertion "Q4-UI" "No constant in the UI imposes a PIN floor above the store's." \
        "Q4 + PIN-MODES.md" "the 4-digit floor applies in every state; a UI floor above the store is a provisioned device nobody can unlock"

    local floor v
    floor=${Q4_STORE_FLOOR:-4}
    v=$(const_value crates/notyas-ui/src/lib.rs PIN_MIN_DEFAULT)
    if [ -z "$v" ]; then
        unevaluable "crates/notyas-ui/src/lib.rs declares no PIN_MIN_DEFAULT" \
            "The UI's fallback floor was renamed or removed. This is the constant that" \
            "carried the defect (it was PIN_MIN = 6); it must stay named and readable."
        return
    fi
    if [ "$v" -le "$floor" ] 2>/dev/null; then
        pass "PIN_MIN_DEFAULT = $v, at or below the store floor of $floor"
    else
        violation "PIN_MIN_DEFAULT = $v sits ABOVE the store floor of $floor" \
            "This is the 2026-08-19 defect exactly: a device formatted at $floor could type" \
            "its whole PIN and never enable Unlock." \
            "Fix: crates/notyas-ui/src/lib.rs, PIN_MIN_DEFAULT = $floor"
    fi

    # Any OTHER constant in the crate that names itself a PIN minimum. Named separately
    # because the defect arrived under a name nobody had listed anywhere: PIN_MIN.
    local hits
    hits=$(grep -rnE "^[[:space:]]*(pub |pub\(crate\) )?const [A-Z_]*(PIN_MIN|MIN_PIN)[A-Z_]*:[[:space:]]*(u8|usize)[[:space:]]*=[[:space:]]*[0-9]+;" \
        crates/notyas-ui/src 2>/dev/null | grep -v "PIN_MIN_DEFAULT" || true)
    if [ -z "$hits" ]; then
        pass "no second PIN-minimum constant exists in crates/notyas-ui"
    else
        printf '%s\n' "$hits" | sed 's/^/        /'
        violation "a second PIN-minimum constant exists" \
            "The floor has exactly one owner, LockInfo::min_pin_len, read from the store." \
            "PIN_MIN was that second owner, and it is what shipped." \
            "Fix: delete the constant and read the runtime value."
    fi
}

a_q4_submit_guard() {
    assertion "Q4-GUARD" "The Unlock guard reads a runtime value, not a literal." \
        "Q37" "every number on a PIN screen is a format string over runtime policy, never a literal"

    local f=crates/notyas-ui/src/screens/pin.rs
    if [ ! -f "$f" ]; then
        unevaluable "$f is missing" "The PIN screen moved. Point this assertion at it."
        return
    fi

    local guard
    guard=$(grep -nE "RegionId::PinSubmit if " "$f" | head -1 || true)
    if [ -z "$guard" ]; then
        unevaluable "no guarded RegionId::PinSubmit arm in $f" \
            "Either the submit arm lost its guard - in which case a too-short PIN is now" \
            "submitted and the store refuses it after the user finished typing - or the" \
            "screen was restructured. Both need a human, not a default."
        return
    fi
    if printf '%s' "$guard" | grep -qE "pin_floor\(|min_pin_len"; then
        pass "the submit guard reads the device floor: ${guard#*:}"
    else
        violation "the submit guard does not read the device floor: $guard" \
            "Fix: guard on pin_floor(env.lock), which is usize::from(lock.min_pin_len)."
    fi

    # The paint and the guard must read the SAME value. A button drawn from one number and
    # gated on another lies in whichever direction they differ.
    if grep -qE "let floor = pin_floor\(ctx.lock\)" "$f" && grep -qE "if n >= floor" "$f"; then
        pass "the Unlock button is painted from the same floor the guard uses"
    else
        violation "the Unlock button's enabled state is not painted from pin_floor(ctx.lock)" \
            "Fix: draw the button kind from the same floor value the activate() guard reads."
    fi

    local hits
    hits=$(product_lines "$f" | grep -E "entry\.len\(\)[[:space:]]*[<>]=?[[:space:]]*[0-9]+" || true)
    if [ -z "$hits" ]; then
        pass "no integer-literal comparison against the PIN entry length"
    else
        printf '%s\n' "$hits" | sed 's/^/        /'
        violation "the PIN entry length is compared against an integer literal" \
            "Fix: compare against pin_floor(lock) or PIN_MAX, never a number."
    fi
}

a_q4_copy() {
    assertion "Q4-COPY" "No surface states a PIN length as a literal other than 4." \
        "Q4 + Q37" "the floor is 4 characters, and every number on a PIN screen is a format string over runtime policy"

    local hits
    hits=$(det_pin_length_literal $(tree_files | grep -E "^(crates|firmware)/.*\.rs$"))
    if [ -z "$hits" ]; then
        pass "no PIN-length literal in any crate's product code"
    else
        printf '%s\n' "$hits" | sed 's/^/        /'
        violation "a PIN length is stated as a literal in code" \
            "A number in copy that no code enforces is how S-04 came to say 6 while the" \
            "store accepted 4. The value being right today is not the point: the constant" \
            "beside it can move and the sentence will not." \
            "Fix: format the sentence over the value that governs it." \
            "For the words hint that is PIN_WORDS_AT: format!(\"Available after {PIN_WORDS_AT} digits.\")"
    fi

    hits=$(det_pin_floor_wrong $(tree_files | grep -E "\.md$") | exempt_filter Q4-DOCS)
    if [ -z "$hits" ]; then
        pass "no document states a PIN floor other than 4"
    else
        printf '%s\n' "$hits" | sed 's/^/        /'
        violation "a document states a PIN floor the owner did not ratify" \
            "These are the specifications the next implementer will build from, and they" \
            "still describe the defect that reached hardware." \
            "Fix: change the number to 4, or to the runtime form the screen actually uses."
    fi
}

a_q5_wipe_default() {
    assertion "Q5-N" "The wipe threshold default and range are the ratified ones." \
        "Q5" "Default N = 15, range 3..=25 inclusive (the 2026-08-17 ratification proposed 10; the owner set 15)"

    local w ui_default ui_min ui_max
    w=$(release_cfg wipe_after)
    if [ -z "$w" ]; then
        unevaluable "Config::NOTYAS_RELEASE has no wipe_after field this script can read"
        return
    fi
    if [ "$w" = 15 ]; then
        pass "Config::NOTYAS_RELEASE formats at wipe_after = 15"
    else
        violation "Config::NOTYAS_RELEASE formats at wipe_after = $w, and the ratified default is 15" \
            "Fix: crates/notyas-wallet/src/config.rs, NOTYAS_RELEASE.format_policy.wipe_after = 15"
    fi

    ui_default=$(const_value crates/notyas-ui/src/lib.rs WIPE_AFTER_DEFAULT)
    if [ -z "$ui_default" ]; then
        unevaluable "crates/notyas-ui/src/lib.rs declares no WIPE_AFTER_DEFAULT" \
            "The value the policy editor restores when the wipe is turned back on must be" \
            "readable, because it has to equal the store's format-time default."
        return
    fi
    if [ "$ui_default" = 15 ]; then
        pass "the UI restores the wipe at WIPE_AFTER_DEFAULT = 15"
    else
        violation "WIPE_AFTER_DEFAULT = $ui_default in crates/notyas-ui, and the ratified default is 15" \
            "The two crates disagree: the store formats at $w and the policy editor restores" \
            "at $ui_default, so an owner who turns the wipe off and back on lands on a" \
            "threshold nobody chose." \
            "Fix: crates/notyas-ui/src/lib.rs, WIPE_AFTER_DEFAULT = 15"
    fi

    ui_min=$(const_value crates/notyas-ui/src/lib.rs WIPE_AFTER_MIN)
    ui_max=$(const_value crates/notyas-ui/src/lib.rs WIPE_AFTER_MAX)
    if [ -z "$ui_min" ] || [ -z "$ui_max" ]; then
        unevaluable "crates/notyas-ui/src/lib.rs does not declare both WIPE_AFTER_MIN and WIPE_AFTER_MAX"
        return
    fi
    if [ "$ui_min" = 3 ] && [ "$ui_max" = 25 ]; then
        pass "the policy editor offers 3..=25, the frozen format range"
    else
        violation "the policy editor offers $ui_min..=$ui_max, and the frozen range is 3..=25" \
            "25 is not a preference: ESP-SEAL.md sizes the attempt ledger's tail reserve to" \
            "exactly 25, so raising it is a format migration." \
            "Fix: crates/notyas-ui/src/lib.rs, WIPE_AFTER_MIN = 3 and WIPE_AFTER_MAX = 25"
    fi
}

a_q62_no_disable_floor() {
    assertion "Q62" "Any PIN may disable the wipe; no length precondition exists." \
        "Q62(b)" "any PIN may disable wipe, with the arithmetic stated plainly at the moment of the change - THE OWNER'S ANSWER"

    local v hits
    v=$(const_value crates/notyas-ui/src/lib.rs WIPE_DISABLE_MIN_PIN)
    if [ -z "$v" ]; then
        unevaluable "crates/notyas-ui/src/lib.rs declares no WIPE_DISABLE_MIN_PIN" \
            "The answer is held as a constant on purpose, so revisiting it is one edit."
        return
    fi
    if [ "$v" = "None" ]; then
        pass "WIPE_DISABLE_MIN_PIN = None: the device states the trade rather than withholding the setting"
    else
        violation "WIPE_DISABLE_MIN_PIN = $v withholds the wipe-off setting from a short PIN" \
            "The owner was shown the arithmetic (4 digits with wipe off is an afternoon)" \
            "and reconfirmed (b) unchanged." \
            "Fix: crates/notyas-ui/src/lib.rs, WIPE_DISABLE_MIN_PIN = None"
    fi

    hits=$(det_wipe_disable_floor crates/notyas-wallet/src/config.rs crates/notyas-ui/src/lib.rs)
    if [ -z "$hits" ]; then
        pass "no disable-wipe floor is configured in the release config either"
    else
        printf '%s\n' "$hits" | sed 's/^/        /'
        violation "a disable-wipe floor is configured" \
            "Fix: disable_wipe_min_pin_len: None in Config::NOTYAS_RELEASE."
    fi

    # The warning has to be computed from the PIN in force, which is only possible if the
    # screen reads it. Structural, and the honest limit of what a shell script can assert:
    # that the screen reaches the runtime value at all.
    if grep -q "lock.pin" crates/notyas-ui/src/screens/policy.rs 2>/dev/null; then
        pass "the wipe-policy screen computes its warning from the PIN in force (lock.pin)"
    else
        violation "crates/notyas-ui/src/screens/policy.rs never reads lock.pin" \
            "Q62 makes the disclosure an acceptance criterion: the warning states the" \
            "keyspace and search time for the user's ACTUAL PIN length, never a generic" \
            "sentence." \
            "Fix: compute the arithmetic from LockInfo::pin (PinShape) and unlock_ms."
    fi
}

a_q2a_prepin() {
    assertion "Q2a" "No pre-PIN surface states the wallet count, and none states capacity." \
        "Q2(a), extended by the owner 2026-08-19" "pre-PIN and on the Verify screen the storage rows read present or blank and nothing else; no pre-PIN surface states capacity either"

    # The screens a locked device can put on the panel. Named explicitly rather than
    # discovered, so a NEW pre-PIN screen has to be added here by hand - which is the
    # moment somebody has to think about what it says to a coercer.
    local prepin="crates/notyas-ui/src/screens/lock.rs crates/notyas-ui/src/screens/door.rs crates/notyas-ui/src/screens/pin.rs crates/notyas-ui/src/screens/verify.rs"
    local f missing=""
    for f in $prepin; do [ -f "$f" ] || missing="$missing $f"; done
    if [ -n "$missing" ]; then
        unevaluable "pre-PIN screens missing:$missing" \
            "The list of surfaces a locked device can show is the whole assertion. Update it."
        return
    fi

    local hits
    hits=$(det_capacity_claim $prepin)
    if [ -z "$hits" ]; then
        pass "no capacity or count claim in the copy of any pre-PIN screen"
    else
        printf '%s\n' "$hits" | sed 's/^/        /'
        violation "a pre-PIN surface states capacity or a count" \
            "A coercer holding a locked device must learn nothing about what is on it." \
            "Fix: state present/blank, and nothing else."
    fi

    hits=$(for f in $prepin; do product_lines "$f" | grep -E "WALLET_SLOTS" || true; done)
    if [ -z "$hits" ]; then
        pass "no pre-PIN screen so much as reads WALLET_SLOTS in product code"
    else
        printf '%s\n' "$hits" | sed 's/^/        /'
        violation "a pre-PIN screen reads WALLET_SLOTS" \
            "Fix: the static maximum belongs to the post-unlock wallet list only."
    fi

    # Structural half: a locked device must hold no wallet list to render.
    if awk '/pub fn lock\(&mut self\)/, /^    \}/' crates/notyas-ui/src/ui.rs | grep -q "self.wallets.clear()"; then
        pass "Ui::lock() clears the wallet list, so a locked device holds no count to leak"
    else
        violation "Ui::lock() does not clear the wallet list" \
            "A locked device still holding a renderable list is exactly the pre-PIN count" \
            "Q2(a) forbids." \
            "Fix: self.wallets.clear() in Ui::lock()."
    fi

    # The firmware's Storage row, which is the one place the word is produced.
    local words
    words=$(awk '/storage: match store.map/, /^[[:space:]]*\},/' firmware/src/verify.rs 2>/dev/null \
        | grep -oE '(String::from|format!)\("[^"]+' | sed -E 's/.*\("//' | awk '{ print $1 }' | sort -u || true)
    if [ -z "$words" ]; then
        unevaluable "could not read the Storage row's vocabulary from firmware/src/verify.rs" \
            "The row that must read present/blank moved or changed shape."
        return
    fi
    local bad=""
    for w in $words; do
        case "$w" in
            present|blank|not|unreadable) : ;;
            *) bad="$bad $w" ;;
        esac
    done
    if [ -z "$bad" ]; then
        pass "the firmware Storage row says only: $(printf '%s ' $words)"
    else
        violation "the firmware Storage row can say:$bad" \
            "Fix: present / blank / not provisioned / unreadable, never a count."
    fi
}

a_r20_words() {
    assertion "R20" "No screen implies anti-phishing words exist on an unprovisioned device." \
        "R20 / Q21" "the words exist only after the eFuse key is provisioned, so a blank stateless device has none"

    local f=crates/notyas-ui/src/ui.rs
    if ! awk '/pub fn lock\(&mut self\)/, /^    \}/' "$f" | grep -q "has_pin()"; then
        unevaluable "Ui::lock() does not test has_pin()" \
            "R20 is enforced structurally: the screens that would show the words cannot be" \
            "reached at all on a device that has none. If that moved, name where it moved to."
        return
    fi
    if awk '/pub fn lock\(&mut self\)/, /^    \}/' "$f" | grep -qE "if ![[:alnum:]_.]*status.has_pin\(\)[[:space:]]*\{"; then
        pass "Ui::lock() refuses a device with no PIN, so the lock and PIN screens are unreachable"
    else
        violation "Ui::lock() no longer refuses when no PIN is set" \
            "Fix: return false before entering State::Lock when !self.lock.status.has_pin()."
    fi

    local arms
    arms=$(awk '/pub fn has_pin\(self\)/, /^    \}/' crates/notyas-ui/src/lib.rs | grep -oE "StoreStatus::[A-Za-z]+" | sort -u | tr '\n' ' ' || true)
    if [ -z "$arms" ]; then
        unevaluable "StoreStatus::has_pin() could not be read from crates/notyas-ui/src/lib.rs"
        return
    fi
    if [ "$(printf '%s' "$arms" | tr -s ' ')" = "StoreStatus::Locked StoreStatus::Unlocked " ]; then
        pass "has_pin() is true only for Locked and Unlocked"
    else
        violation "has_pin() covers: $arms" \
            "NotProvisioned, Blank and Unreadable have no device key and therefore no words." \
            "Fix: matches!(self, StoreStatus::Locked | StoreStatus::Unlocked)"
    fi
}

a_q45_no_burn() {
    assertion "Q45" "Release firmware contains no eFuse-burn code." \
        "Q45" "factory provisioning; release firmware contains no eFuse-burn code at all"

    # Every file in the device image that names a burn API. The set is asserted, not
    # merely filtered: a NEW call site is a decision, and it stops this gate until a human
    # states which feature gates it.
    local sites expected="firmware/src/hmac_check.rs"
    sites=$(det_efuse_burn $(tree_files | grep -E "^firmware/src/.*\.rs$") | cut -d: -f1 | sort -u | tr '\n' ' ' || true)
    sites=$(printf '%s' "$sites" | sed 's/[[:space:]]*$//')
    if [ "$sites" != "$expected" ]; then
        violation "the set of eFuse-burn call sites in firmware/ is: ${sites:-none}" \
            "This assertion knows about exactly one, $expected, and it is compiled only by" \
            "--features hmac-virtual-check against virtual fuses." \
            "If a new one is legitimate, gate it behind a non-default feature and add it" \
            "here with the reason. Do not widen the pattern."
    else
        pass "the only eFuse-burn call site in firmware/ is $expected"
    fi

    # ... and it is not in a default build.
    local decl
    decl=$(grep -B2 "^mod hmac_check;" firmware/src/main.rs 2>/dev/null | grep -oE '#\[cfg\(feature = "[a-z-]+"\)\]' || true)
    if [ -z "$decl" ]; then
        unevaluable "firmware/src/main.rs does not declare mod hmac_check behind a cfg(feature)" \
            "The module carrying the burn call must be invisible to a default build."
        return
    fi
    pass "mod hmac_check is compiled only under $decl"

    local def
    def=$(grep -E "^default = " firmware/Cargo.toml | head -1 || true)
    if [ -z "$def" ]; then
        unevaluable "firmware/Cargo.toml declares no default feature set"
        return
    fi
    if [ "$def" = "default = []" ]; then
        pass "firmware/Cargo.toml: $def"
    else
        violation "firmware/Cargo.toml: $def" \
            "Fix: default = [], and let the board feature be named on the command line."
    fi

    def=$(grep -A2 "^\[features\]" crates/esp-idf-hmac/Cargo.toml | grep -E "^default = " | head -1 || true)
    if [ "$def" = "default = []" ]; then
        pass "esp-idf-hmac's provisioning helpers are off by default ($def)"
    else
        violation "esp-idf-hmac's default features are: ${def:-unreadable}" \
            "Fix: default = [], with provisioning an opt-in feature."
    fi

    local outside
    outside=$(det_efuse_burn $(tree_files | grep -E "^crates/.*\.rs$" | grep -v "^crates/esp-idf-hmac/") | head -5)
    if [ -z "$outside" ]; then
        pass "no crate outside esp-idf-hmac calls an eFuse write API"
    else
        printf '%s\n' "$outside" | sed 's/^/        /'
        violation "an eFuse write API is called outside esp-idf-hmac" \
            "Fix: the burn ladder has one home, behind one feature."
    fi
}

a_q63_no_secure_boot() {
    assertion "Q63" "0.2.0 burns only HMAC_UP: no secure boot, no flash encryption." \
        "Q63(a)" "no SECURE-BOOT-related eFuse - no secure-boot digest, no anti-rollback, no flash-encryption key; the HMAC_UP provisioning of Q45 is the one burn 0.2.0 performs"

    local files hits
    files=$(tree_files | grep -E "sdkconfig.*defaults$" || true)
    if [ -z "$files" ]; then
        unevaluable "no sdkconfig defaults file found" \
            "The build configuration is where secure boot would be switched on. If the" \
            "layout changed, point this assertion at the new one."
        return
    fi
    hits=$(det_secure_boot_enabled $files)
    if [ -z "$hits" ]; then
        pass "no sdkconfig enables secure boot or flash encryption ($(printf '%s' "$files" | wc -l | tr -d ' ') files checked)"
    else
        printf '%s\n' "$hits" | sed 's/^/        /'
        violation "a build configuration enables secure boot or flash encryption" \
            "Q32 deferred Secure Boot v2 out of 0.2.0 and Q63 confirmed it." \
            "Fix: remove the option, or take the decision to the owner first."
    fi
}

a_release_identity() {
    assertion "KEY" "The release identity is the rsa4096 fingerprint, not the retired rsa3072 one." \
        "owner decision" "GPG rsa4096 intnsity, A1E9 53B2 5C6A 623B 77A1 D522 3AC4 BBCF E51A B37D"

    local fpr=A1E953B25C6A623B77A1D5223AC4BBCFE51AB37D
    local pretty declared
    pretty=$(printf '%s' "$fpr" | sed 's/..../& /g; s/ $//')

    declared=$(grep -E "^RELEASE_KEY_FPR=" tools/release.sh 2>/dev/null | head -1 | cut -d= -f2 || true)
    if [ -z "$declared" ]; then
        unevaluable "tools/release.sh declares no RELEASE_KEY_FPR" \
            "The release driver's idea of the signing identity is the thing being checked."
        return
    fi
    if [ "$declared" = "$fpr" ]; then
        pass "tools/release.sh signs with $pretty"
    else
        violation "tools/release.sh signs with $declared" \
            "Fix: RELEASE_KEY_FPR=$fpr"
    fi

    # Every document the release driver requires to name it. Read from release.sh rather
    # than duplicated, so the two lists cannot drift.
    local docs d
    docs=$(grep -E "^KEY_DOCS=" tools/release.sh | head -1 | sed 's/^KEY_DOCS="//; s/"$//' || true)
    if [ -z "$docs" ]; then
        unevaluable "tools/release.sh declares no KEY_DOCS"
        return
    fi
    for d in $docs; do
        if [ ! -f "$d" ]; then
            violation "$d does not exist, and tools/release.sh requires it to name the key" \
                "Fix: create it, or drop it from KEY_DOCS."
        elif grep -qF "$pretty" "$d" || grep -qF "$fpr" "$d"; then
            pass "$d names the release key"
        else
            violation "$d does not name the release key" \
                "tools/release.sh preflight requires it, so the release is blocked today." \
                "Fix: state the fingerprint in $d: $pretty"
        fi
    done

    local hits
    hits=$(det_release_identity $(tree_files | grep -E "\.(md|sh|ps1)$"))
    if [ -z "$hits" ]; then
        pass "no document calls the release identity an RSA-3072 key"
    else
        printf '%s\n' "$hits" | sed 's/^/        /'
        violation "a document states the release identity is RSA-3072" \
            "That key was retired on 2026-08-19 (SECUREBOOT.md section 4) and the release" \
            "identity is the rsa4096 one. A verifier sent to the wrong key cannot check the" \
            "release at all." \
            "Fix: RSA-4096, and check the surrounding sentence: the same paragraph calls the" \
            "fingerprint 'not the desktop BigDice key', which is the same key."
    fi
}

# ---------------------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------------------

list_assertions() {
    cat <<'EOF'
check-ratified.sh asserts the tree against these owner decisions:

  Q4-STORE  the store formats at a 4-character PIN floor
  Q4-UI     no UI constant imposes a floor above the store's
  Q4-GUARD  the Unlock guard and the Unlock button read the same runtime floor
  Q4-COPY   no code or document states a PIN length as a literal other than 4
  Q5-N      wipe threshold default 15, range 3..=25, in both crates
  Q62       any PIN may disable the wipe; the warning is computed from the PIN in force
  Q2a       no pre-PIN surface states a wallet count or a capacity
  R20       Ui::lock() refuses a device with no PIN, so no screen implies device words
  Q45       release firmware contains no reachable eFuse-burn code
  Q63       no build configuration enables secure boot or flash encryption
  KEY       the release identity is the rsa4096 fingerprint

Not asserted here because another gate owns it:
  invariant 3 (no RNG, transitively)   tools/build-graph-check.sh
  HIL console absent from the image    tools/ci/check-release-symbols.sh
EOF
}

case "${1:-}" in
    -h|--help) sed -n '2,45p' "$0"; exit 0 ;;
    --list) list_assertions; exit 0 ;;
    --self-test)
        if self_test; then
            printf '\ncheck-ratified: self-test OK\n'
            exit 0
        fi
        printf '\ncheck-ratified: SELF-TEST FAILED - the gate cannot be trusted\n' >&2
        exit 2
        ;;
    "") : ;;
    *) printf 'check-ratified: unknown argument %s\n' "$1" >&2; exit 2 ;;
esac

printf '=== check-ratified: the tree against the ratified answers ===\n'
printf 'Register: docs/archive/plan-0.2.0/OPEN-QUESTIONS.md and docs/archive/plan-0.2.0/PIN-MODES.md\n'

if ! self_test; then
    printf '\ncheck-ratified: BROKEN - a detector failed its own fixture.\n' >&2
    printf 'No assertion below would mean anything, so none were run.\n' >&2
    exit 2
fi

a_q4_store_floor
a_q4_ui_floor
a_q4_submit_guard
a_q4_copy
a_q5_wipe_default
a_q62_no_disable_floor
a_q2a_prepin
a_r20_words
a_q45_no_burn
a_q63_no_secure_boot
a_release_identity
check_exemptions_are_live

printf '\n=== summary ===\n'
printf '  %s assertion(s) held\n' "$N_PASS"
printf '  %s violation(s)\n' "$N_FAIL"
printf '  %s assertion(s) could not be evaluated\n' "$N_BROKEN"

if [ "$N_BROKEN" -gt 0 ]; then
    printf '\ncheck-ratified: BROKEN - %s assertion(s) could not be evaluated.\n' "$N_BROKEN" >&2
    printf 'That is a failure, not a skip: an assertion nobody can evaluate is a decision\n' >&2
    printf 'nobody is checking. Fix the anchor or move the assertion with the code.\n' >&2
    exit 2
fi

if [ "$N_FAIL" -gt 0 ]; then
    printf '\ncheck-ratified: FAILED - %s violation(s) of a ratified answer.\n' "$N_FAIL" >&2
    printf 'Each one is a defect until the owner says otherwise. To change a decision,\n' >&2
    printf 'edit docs/archive/plan-0.2.0/OPEN-QUESTIONS.md first and this gate second.\n' >&2
    exit 1
fi

printf '\ncheck-ratified: OK - the tree agrees with every ratified answer it can be checked against\n'
exit 0
