#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# check-hil-fence.sh - firmware/build.rs's two refusals, EXECUTED rather than assumed.
#
# firmware/build.rs is the first of the three layers that keep the HIL console out of a
# shipped image (firmware/Cargo.toml, feature `hil-console`), and it is the only one that
# stops the artefact EXISTING: it panics when `hil-console` or `unsafe-emulated-key` is
# enabled in an image that is not bench-shaped. The console it fences off can format the
# store, seal records, erase both partitions, dump raw flash and - since 0.2.0 - SIGN a
# transaction, all from the UART with no PIN.
#
# That build script only runs inside a full ESP-IDF firmware build, and no automated
# process in this repository performs one (.github/workflows/ci.yml says why, and says
# what that leaves unverified). So until this gate existed, the fence that matters most
# was the one thing here that had never been run by anything but a person's own laptop -
# and it is a fence that has already been repaired twice, in opposite directions, each
# time because one build-system property was standing in for "what came out of rustc".
# A third such mistake would be discovered by a customer holding a device that answers
# `sign` over a serial port.
#
# WHAT IS ASSERTED
#
# build.rs decides "product image" as a CONJUNCTION over four cargo variables
# (CARGO_CFG_DEBUG_ASSERTIONS, PROFILE, OPT_LEVEL, DEBUG): a bench image must look like
# one in every respect, and any product-shaped answer refuses the build. Its own comment
# carries the profile table that conjunction was measured against, including the two
# escapes that defeated the previous one-bit fences - `hardened` (release-rooted with
# debug assertions turned back on) and `slimdev` (dev-rooted, built at the product's
# optimization level with its debuginfo thrown away). This gate runs that table. A
# measurement written in a comment ages; the same measurement run on every push does not.
#
# It also asserts the cfg the script hands to layer 2. src/hil.rs refuses to compile
# unless `notyas_bench_image` is set, so a build.rs that emitted it unconditionally would
# silently disarm that layer as well: the refusals would still fire here and the second
# fence would be gone. That is exactly the kind of failure a gate has to be told to look
# for, so it is checked in both directions.
#
# HOW IT RUNS THE REAL FENCE WITHOUT ESP-IDF
#
# A cargo build script is an ordinary host program. Its inputs are environment variables
# cargo sets, and this one touches exactly one thing outside std: the final
# embuild::espidf::sysenv::output() call, after both refusals. So we compile
# firmware/build.rs with rustc against a one-line stub crate that provides that call and
# prints a marker, then run the result under the environments cargo would produce. The
# code under test is the real file, byte for byte, not a copy and not a re-implementation.
#
# Two consequences worth stating, both deliberate:
#
#   * If firmware/build.rs grows a second embuild API, the stub stops compiling and this
#     gate FAILS. That is the correct direction: extending the stub is a one-line edit,
#     and a gate that quietly stopped compiling its subject would be the exact failure
#     this file exists to prevent.
#   * A refusal is confirmed by its MESSAGE, not merely by a non-zero exit. Any program
#     can exit non-zero. A gate that accepts "it failed somehow" as proof that a specific
#     fence fired cannot tell a working fence from a typo in this script.
#
# What this does NOT prove: that firmware/src compiles, that the compile_error! in
# src/hil.rs (layer 2) holds, or anything at all about a linked image (layer 3 is
# tools/ci/check-release-symbols.sh, which needs a real ELF).
#
# Usage:  tools/ci/check-hil-fence.sh
#
# Exit 0 = every case behaved, 1 = a fence did not.

set -euo pipefail

cd "$(dirname "$0")/../.."

BUILD_RS=firmware/build.rs

FAILURES=0
CHECKS=0
ok()   { CHECKS=$((CHECKS + 1)); printf '  ok    %s\n' "$*"; }
bad()  { CHECKS=$((CHECKS + 1)); FAILURES=$((FAILURES + 1)); printf '  FAIL  %s\n' "$*"; }
note() { printf '        %s\n' "$*"; }

if ! command -v rustc >/dev/null 2>&1; then
    echo "check-hil-fence: rustc not found - this gate cannot run, and a security gate"
    echo "                 that skips silently is worse than no gate at all"
    exit 1
fi

if [ ! -f "$BUILD_RS" ]; then
    echo "check-hil-fence: ${BUILD_RS} does not exist - the fence this gate tests is gone"
    exit 1
fi

WORK=$(mktemp -d)
# Cleans up on the error exits too, which under `set -e` are most of them.
trap 'rm -rf "$WORK"' EXIT

# The marker proves the probe reached the LAST statement of build.rs. Without it, a
# refusal that had been rewritten to return early would read as a pass.
MARKER="notyas-fence-probe: reached the end of build.rs"

# The verdict build.rs hands to layer 2. Emitted only for a bench image.
BENCH_CFG="cargo::rustc-cfg=notyas_bench_image"

{
    echo '// Stub for the single embuild call firmware/build.rs makes.'
    echo '// Written by tools/ci/check-hil-fence.sh; see that file for why.'
    echo 'pub mod espidf {'
    echo '    pub mod sysenv {'
    echo '        pub fn output() {'
    echo "            println!(\"${MARKER}\");"
    echo '        }'
    echo '    }'
    echo '}'
} > "$WORK/embuild_stub.rs"

echo "compiling ${BUILD_RS} against a stub embuild"

if ! OUT=$(rustc --edition 2021 --crate-name embuild --crate-type rlib \
            "$WORK/embuild_stub.rs" -o "$WORK/libembuild.rlib" 2>&1); then
    bad "the stub embuild crate does not compile"
    printf '%s\n' "$OUT" | sed 's/^/        /'
    echo
    echo "check-hil-fence: FAILED - ${FAILURES} of ${CHECKS} checks"
    exit 1
fi

# -C debuginfo=0: nothing here is debugged, and it keeps the temp directory small.
if ! OUT=$(rustc --edition 2021 -C debuginfo=0 --extern "embuild=$WORK/libembuild.rlib" \
            "$BUILD_RS" -o "$WORK/fence-probe" 2>&1); then
    bad "${BUILD_RS} does not compile against the stub"
    printf '%s\n' "$OUT" | sed 's/^/        /'
    note "If build.rs now calls an embuild API beyond espidf::sysenv::output(),"
    note "add it to the stub in this script. Do NOT delete this gate to go green."
    echo
    echo "check-hil-fence: FAILED - ${FAILURES} of ${CHECKS} checks"
    exit 1
fi
ok "build.rs compiles; its only external call is embuild::espidf::sysenv::output()"
echo

PROBE="$WORK/fence-probe"
PROBE_OUT=""
PROBE_RC=0

# The profile table from build.rs's own comment, as environments cargo would export.
# Measured there on cargo 1.96.0; run here so the measurement cannot go stale.
#
# A variable that is simply absent from one of these strings is absent from the probe's
# environment, which is what cargo does and what the fence reads as product-shaped.
# CARGO_CFG_DEBUG_ASSERTIONS carries an EMPTY value when set: cargo exports a boolean cfg
# by presence, so "= nothing" is how "on" looks.
P_DEV="CARGO_CFG_DEBUG_ASSERTIONS= PROFILE=debug OPT_LEVEL=z DEBUG=true"
P_RELEASE="PROFILE=release OPT_LEVEL=s DEBUG=false"
P_HARDENED="CARGO_CFG_DEBUG_ASSERTIONS= PROFILE=release OPT_LEVEL=s DEBUG=false"
P_HARDENED_MAX="CARGO_CFG_DEBUG_ASSERTIONS= PROFILE=release OPT_LEVEL=1 DEBUG=true"
P_SHIPDEV="PROFILE=debug OPT_LEVEL=3 DEBUG=false"
P_SLIMDEV="CARGO_CFG_DEBUG_ASSERTIONS= PROFILE=debug OPT_LEVEL=s DEBUG=false"

# run_probe <env assignments...>
#
# Every variable the fence reads is cleared first, so this gate cannot be influenced by
# the environment it happens to be invoked from - a parent `cargo` process exports
# CARGO_CFG_DEBUG_ASSERTIONS, PROFILE, OPT_LEVEL and DEBUG of its own, and a gate that
# inherited them would be testing its own invocation rather than the fence.
run_probe() {
    set +e
    PROBE_OUT=$(env -u CARGO_CFG_DEBUG_ASSERTIONS -u PROFILE -u OPT_LEVEL -u DEBUG \
                    -u CARGO_FEATURE_HIL_CONSOLE -u CARGO_FEATURE_UNSAFE_EMULATED_KEY \
                    "$@" "$PROBE" 2>&1)
    PROBE_RC=$?
    set -e
}

# expect_refusal <label> <substring the message must contain> <env assignments...>
expect_refusal() {
    label=$1; needle=$2; shift 2
    run_probe "$@"
    if [ "$PROBE_RC" -eq 0 ]; then
        bad "$label - the build was ALLOWED"
        note "exit 0, output: ${PROBE_OUT}"
    elif ! printf '%s\n' "$PROBE_OUT" | grep -qF "$needle"; then
        bad "$label - it failed, but not with the expected refusal"
        note "wanted a message containing: ${needle}"
        printf '%s\n' "$PROBE_OUT" | sed 's/^/        /'
    else
        ok "$label"
    fi
}

# expect_allowed <label> <bench|product> <env assignments...>
#
# The second argument is the verdict layer 2 must be handed: a bench image gets the
# notyas_bench_image cfg, a product image must not, and getting that backwards would
# disarm src/hil.rs's compile_error! without any refusal here changing.
expect_allowed() {
    label=$1; verdict=$2; shift 2
    run_probe "$@"
    if [ "$PROBE_RC" -ne 0 ]; then
        bad "$label - the build was REFUSED (exit ${PROBE_RC})"
        printf '%s\n' "$PROBE_OUT" | sed 's/^/        /'
        return
    fi
    if ! printf '%s\n' "$PROBE_OUT" | grep -qF "$MARKER"; then
        bad "$label - exited 0 without reaching the end of build.rs"
        note "the marker is missing, so the script returned early rather than passing"
        printf '%s\n' "$PROBE_OUT" | sed 's/^/        /'
        return
    fi
    if printf '%s\n' "$PROBE_OUT" | grep -qxF "$BENCH_CFG"; then
        got=bench
    else
        got=product
    fi
    if [ "$got" != "$verdict" ]; then
        bad "$label - built, but layer 2 was told this is a ${got} image"
        note "src/hil.rs compiles only with notyas_bench_image set; expected ${verdict}"
        printf '%s\n' "$PROBE_OUT" | sed 's/^/        /'
        return
    fi
    ok "$label"
}

# Refusal messages are matched on the stable half of the sentence - the feature name and
# the fact that it is enabled. The prose around it has been rewritten twice while the
# rule stayed the same, and a gate that pins the wording turns every clarification into
# a failure.
HIL_REFUSED='feature `hil-console` is enabled'
KEY_REFUSED='feature `unsafe-emulated-key` is enabled'

echo "hil-console, across the profile table in build.rs"
expect_allowed "dev is bench-shaped: the console is allowed" \
               bench $P_DEV CARGO_FEATURE_HIL_CONSOLE=1
expect_refusal "release is refused" "$HIL_REFUSED" \
               $P_RELEASE CARGO_FEATURE_HIL_CONSOLE=1
# The two escapes that defeated the previous one-property fences. If either of these
# starts passing, the conjunction has been narrowed back to a single bit.
expect_refusal "hardened (release-rooted, debug assertions back on) is refused" \
               "$HIL_REFUSED" $P_HARDENED CARGO_FEATURE_HIL_CONSOLE=1
expect_refusal "hardened-max (every exported bench bit back on) is refused" \
               "$HIL_REFUSED" $P_HARDENED_MAX CARGO_FEATURE_HIL_CONSOLE=1
expect_refusal "shipdev (dev-rooted, product-shaped) is refused" \
               "$HIL_REFUSED" $P_SHIPDEV CARGO_FEATURE_HIL_CONSOLE=1
expect_refusal "slimdev (dev-rooted, product optimization, no debuginfo) is refused" \
               "$HIL_REFUSED" $P_SLIMDEV CARGO_FEATURE_HIL_CONSOLE=1
# An empty environment is what a future cargo that stopped exporting these would produce,
# and the fence has to read that as a product image rather than as no answer.
expect_refusal "an environment that reports nothing at all is refused" \
               "$HIL_REFUSED" NOTYAS_FENCE_PROBE=1 CARGO_FEATURE_HIL_CONSOLE=1
echo

echo "unsafe-emulated-key (ESP-SEAL.md 6.4 fence 2)"
expect_allowed "dev is bench-shaped: the emulated key is allowed" \
               bench $P_DEV CARGO_FEATURE_UNSAFE_EMULATED_KEY=1
expect_refusal "release is refused" "$KEY_REFUSED" \
               $P_RELEASE CARGO_FEATURE_UNSAFE_EMULATED_KEY=1
expect_refusal "hardened is refused" "$KEY_REFUSED" \
               $P_HARDENED CARGO_FEATURE_UNSAFE_EMULATED_KEY=1
# Both features at once. The emulated-key refusal is written first, so this asserts that
# reaching one fence does not depend on the other being off.
expect_refusal "both features at once are refused" "$KEY_REFUSED" \
               $P_RELEASE CARGO_FEATURE_HIL_CONSOLE=1 CARGO_FEATURE_UNSAFE_EMULATED_KEY=1
echo

# The other direction. A fence that refused everything would pass every refusal check
# above, break the product build outright, and make m4a's power-cut evidence impossible
# to produce. The product image is the artefact that ships, so it is tested first.
echo "no optional feature: every profile still builds"
expect_allowed "release builds and is judged a product image" product $P_RELEASE
expect_allowed "dev builds and is judged a bench image" bench $P_DEV
expect_allowed "hardened builds and is judged a product image" product $P_HARDENED
expect_allowed "slimdev builds and is judged a product image" product $P_SLIMDEV
echo

if [ "$FAILURES" -gt 0 ]; then
    echo "check-hil-fence: FAILED - ${FAILURES} of ${CHECKS} checks"
    echo
    echo "firmware/build.rs is ESP-SEAL.md 6.4 fence 2 and MILESTONES.md m4a's Q41 gate."
    echo "If the fence was deliberately reworded, update the expectations in this script"
    echo "and say so. Do not release until the refusals behave as written."
    exit 1
fi

echo "check-hil-fence: OK - ${CHECKS} checks; both refusals fire across the whole profile"
echo "                 table, neither over-fires, and layer 2's cfg matches the verdict"
exit 0
