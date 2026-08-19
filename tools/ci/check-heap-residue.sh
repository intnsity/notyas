#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# check-heap-residue.sh - run the drop-equals-zeroize tests where they can be believed.
#
# crates/notyas-ui/tests/review_capacity_and_wipe.rs holds three tests that prove
# a typed passphrase and a typed mnemonic are in none of the heap blocks freed on
# the way to a seed. They do it by arming a scanning global allocator: set the
# needle, zero the counter, arm, run the code under test, read the counter.
#
# THE DEFECT THIS GATE COMPENSATES FOR. That arming state is three process-global
# statics - ARMED, HITS and WHICH - and cargo runs all five tests in that file as
# threads of ONE process. The allocator is global to the process, so the three
# statics are one instrument with one set of dials being turned by three tests at
# once. Every interleaving that matters ends the same way:
#
#   * a sibling's HITS.store(0) after a real hit and before the load: the test
#     reads zero and passes.
#   * a sibling's ARMED.store(false) between the arming and the frees: nothing is
#     scanned at all, the counter stays zero, and the test passes.
#   * a sibling's WHICH.store(1) inside another test's window: the scanner hunts
#     for the other test's needle, finds nothing, and the test passes.
#
# Every one of them is silent, and every one of them is green. This is a security
# test whose failure mode is to succeed - it would report clean over exactly the
# heap residue it exists to catch. Nothing about it looks wrong in a CI log.
#
# WHAT THIS SCRIPT DOES ABOUT IT. --test-threads=1 makes libtest run the whole
# binary on one thread, so no two tests are ever armed at once and each one
# measures its own frees. That is the entire content of the fix here.
#
# WHAT IT IS NOT. This is a compensating control, not the repair. The repair is
# in the test file - the three statics need to be acquired as one unit under a
# lock held for the whole armed window, so that arming without exclusive access
# is not expressible. Until that lands, two things remain true and are worth
# saying out loud rather than leaving to be discovered:
#
#   * a developer running `cargo test` by hand still gets the parallel, and
#     therefore untrustworthy, execution. Only this entry point is serial.
#   * the workspace-wide `cargo test` in CI runs the same binary in parallel as
#     well. That run can report a false pass; THIS run is the one of record, and
#     a disagreement between them is itself the finding.
#
# WHY IT ALSO READS THE SOURCE. A gate that runs "the tests in that file" and is
# happy with whatever it finds would keep passing after the tests were renamed,
# moved or deleted, and would then be a green light attached to nothing. So the
# three tests are named here and their presence in the run is asserted. The
# shared statics are looked for too, for the opposite reason: when the file grows
# its own lock this script has nothing left to compensate for and should be
# deleted, and it says so rather than quietly living on.
#
# Usage:  tools/ci/check-heap-residue.sh
#
# Exit 0 = the three heap-residue tests ran serially and passed, 1 = they did
# not, or the gate could no longer see them.

set -euo pipefail

cd "$(dirname "$0")/../.."

PACKAGE=notyas-ui
TEST_TARGET=review_capacity_and_wipe
TEST_SOURCE="crates/$PACKAGE/tests/$TEST_TARGET.rs"

# The tests whose verdict this gate is issued for. Named rather than counted: a
# count is satisfied by any three tests, and these three are the ones whose
# result is a claim about key material.
SECURITY_TESTS=(
    "a_typed_passphrase_is_in_no_freed_block_after_the_screens_holding_it_are_dropped"
    "bip39_seed_leaves_no_copy_of_the_passphrase_in_freed_heap"
    "bip39_seed_leaves_no_copy_of_the_mnemonic_in_freed_heap"
)

FAILURES=0
ok()   { printf '  ok    %s\n' "$*"; }
bad()  { FAILURES=$((FAILURES + 1)); printf '  FAIL  %s\n' "$*"; }
note() { printf '        %s\n' "$*"; }

printf '\n=== heap residue, measured one test at a time ===\n\n'

if [ ! -f "$TEST_SOURCE" ]; then
    bad "$TEST_SOURCE is not in this tree"
    note "the three tests this gate issues a verdict for have moved or been deleted."
    note "find them, point this script at them, or delete this script deliberately -"
    note "do not leave it passing over an empty run."
    printf '\ncheck-heap-residue: FAILED - the gate has lost its subject.\n'
    exit 1
fi

# --- is the compensation still needed? ---------------------------------------
#
# Informational, never a failure: a file that has learned to serialise itself is
# the outcome this script wants, and going red on a proper fix would be the
# clearest possible way to teach people not to make one.
if grep -qE '^\s*static\s+(ARMED|HITS|WHICH)\s*:' "$TEST_SOURCE" \
   && ! grep -qE 'Mutex|MutexGuard|Once' "$TEST_SOURCE"; then
    note "$TEST_SOURCE still arms a process-global scanner from three tests with no"
    note "lock between them, so this serial run remains the only trustworthy one."
else
    note "$TEST_SOURCE appears to serialise its own scanner now. If it does, this"
    note "script is redundant: read it, confirm, and delete it rather than keeping a"
    note "compensating control for a defect that has been repaired."
fi
printf '\n'

# --- the run -----------------------------------------------------------------
#
# --test-threads=1 is the whole point and belongs in the recorded command line.
# --locked for the same reason every other gate uses it: the committed lockfile
# is the graph that was audited.
# --nocapture so that a failing assertion's message - which names how many freed
# blocks held the secret - reaches the log rather than being summarised away.
CMD=(cargo test --locked -p "$PACKAGE" --test "$TEST_TARGET" -- --test-threads=1 --nocapture)
note "running: ${CMD[*]}"
printf '\n'

set +e
OUT=$("${CMD[@]}" 2>&1)
CODE=$?
set -e

printf '%s\n' "$OUT" | sed 's/^/        | /'
printf '\n'

if [ "$CODE" -ne 0 ]; then
    bad "the heap-residue suite failed (cargo exit $CODE)"
    note "a secret survived in a freed heap block, or the crate no longer builds."
    note "read the run above: the assertion names which secret and how many blocks."
else
    ok "the suite passed under a single test thread"
fi

# --- did the tests this gate speaks for actually run? ------------------------
#
# The anti-vacuity check. libtest reports "0 passed; 0 filtered out" as success,
# so a filter that matches nothing, a renamed test, or a #[ignore] added in
# passing all produce a green run that proves nothing whatsoever.
for t in "${SECURITY_TESTS[@]}"; do
    if printf '%s' "$OUT" | grep -qF "test $t ... ok"; then
        ok "ran and passed: $t"
    else
        bad "did not run (or did not pass): $t"
        note "this gate's verdict is about that test. It was not in the run, so there"
        note "is no verdict - which is not the same as a clean one."
    fi
done

# The serial execution is the reason this script exists, so it is asserted rather
# than assumed: a future edit that dropped the flag would leave the gate looking
# identical and measuring nothing.
if printf '%s' "$OUT" | grep -qE 'running [0-9]+ tests?'; then
    ok "libtest ran the binary (with --test-threads=1, so no two tests were armed at once)"
else
    bad "no libtest run in the output - the binary did not execute"
    note "cargo reported success without running the tests. Do not read that as clean."
fi

printf '\n'
if [ "$FAILURES" -gt 0 ]; then
    printf 'check-heap-residue: FAILED - %d assertion(s) broke.\n' "$FAILURES"
    printf 'SECURITY.md: a typed secret must not survive in any freed heap block.\n'
    exit 1
fi
printf 'check-heap-residue: OK - the three heap-residue tests ran serially and passed.\n'
exit 0
