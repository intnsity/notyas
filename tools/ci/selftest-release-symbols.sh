#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# selftest-release-symbols.sh - proof that check-release-symbols.sh fails when it should.
#
# check-release-symbols.sh is the only evidence behind Q41: that a shipped notyas
# image does not contain the HIL test console, which since 0.2.0 can sign a
# transaction on command from a serial port with no PIN. Every run of it in this
# tree has passed, because every image built here has been console-free - and a
# gate that has only ever passed is indistinguishable from a gate that cannot
# fail. The one artefact that would make it print a finding is the one artefact
# nobody wants lying around.
#
# So this script builds that artefact. It synthesises small RISC-V ELFs carrying
# exactly the symbols and string literals the gate hunts for, runs the REAL gate
# against each, and asserts the verdict - including the verdicts that matter most
# and are hardest to believe without seeing them: that a STRIPPED image is a
# failure rather than a pass, and that the console's own words are still found in
# a file with no symbol table at all.
#
# WHY SYNTHETIC ELFs RATHER THAN A REAL BENCH BUILD. A console-bearing firmware
# takes ESP-IDF, a nightly toolchain and several minutes, and firmware/build.rs
# refuses to produce one in a release profile at all - which is the point of that
# fence. A gate self-test that could only run after defeating another gate would
# never be run. These fixtures are compiled in about a second by the toolchain
# the gate already requires, and they exercise the gate's decision path, which is
# the part under test: the gate reads names and bytes out of an ELF, and it
# cannot tell where the ELF came from.
#
# WHAT THAT DOES NOT COVER, stated rather than left to be assumed: these fixtures
# cannot prove that a real `--features hil-console` build emits the symbol names
# spelled below. That claim lives in the gate's own comments, and it was measured
# against a bench image. What this file proves is the other half, and the half
# that had never been demonstrated - that GIVEN those names, the gate finds them,
# refuses stripped input, refuses unrecognisable input, and refuses to run
# without its tools.
#
# WHY THE NEEDLES ARE READ OUT OF THE GATE. HIL_MODULE, HIL_UART and HIL_STRINGS
# are parsed from check-release-symbols.sh rather than copied here, so a needle
# that is changed there is still the needle proved here. A parse that yields
# nothing stops the run: a self-test that quietly tests zero cases is the defect
# it exists to rule out, one level up.
#
# Usage:  tools/ci/selftest-release-symbols.sh [--keep]
#           --keep   leave the fixture ELFs behind for inspection
#
# There is no --skip. If the RISC-V toolchain is absent this script FAILS, for
# the same reason the gate does: converting "could not check" into "clean" is the
# one output neither file may ever produce.
#
# Exit 0 = the gate behaves as specified on every case, 1 = it does not.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT=$(pwd)
GATE="$REPO_ROOT/tools/ci/check-release-symbols.sh"

KEEP=0
case "${1:-}" in
    --keep) KEEP=1 ;;
    "") ;;
    *) printf 'selftest-release-symbols: unknown argument %s\n' "$1" >&2; exit 1 ;;
esac

if [ ! -f "$GATE" ]; then
    printf 'selftest-release-symbols: %s is not in this tree - nothing to test.\n' "$GATE" >&2
    exit 1
fi

WORK=$(mktemp -d)
case "$WORK" in
    "$REPO_ROOT"*)
        printf 'selftest-release-symbols: refusing to build fixtures inside the repository (%s)\n' "$WORK" >&2
        exit 1 ;;
esac
cleanup() {
    if [ "$KEEP" -eq 1 ]; then printf '\nfixtures kept at %s\n' "$WORK"; return 0; fi
    chmod -R u+w "$WORK" 2>/dev/null || true
    rm -rf "$WORK" 2>/dev/null || true
}
trap cleanup EXIT

PASSES=0
FAILURES=0
pass() { PASSES=$((PASSES + 1)); printf '  ok    %s\n' "$1"; }
fail() { FAILURES=$((FAILURES + 1)); printf '  FAIL  %s\n' "$1"; }
note() { printf '        %s\n' "$1"; }

# --- the toolchain -----------------------------------------------------------
#
# Same search the gate makes, for the same reason: PATH first, then where the
# espressif installer puts the toolchain. gcc and strip are needed on top of the
# gate's nm because this file has to CREATE the evidence, not only read it.
find_tool() {
    local base=$1 c
    if command -v "$base" >/dev/null 2>&1; then command -v "$base"; return 0; fi
    for c in "$HOME"/.espressif/tools/riscv32-esp-elf/*/riscv32-esp-elf/bin/"$base" \
             "$HOME"/.espressif/tools/riscv32-esp-elf/*/riscv32-esp-elf/bin/"$base".exe; do
        if [ -x "$c" ]; then printf '%s' "$c"; return 0; fi
    done
    return 1
}

GCC=$(find_tool riscv32-esp-elf-gcc || true)
STRIP=$(find_tool riscv32-esp-elf-strip || true)
NM=$(find_tool riscv32-esp-elf-nm || true)
if [ -z "$GCC" ] || [ -z "$STRIP" ] || [ -z "$NM" ]; then
    printf 'selftest-release-symbols: the RISC-V toolchain is not on this machine.\n' >&2
    printf '  needed: riscv32-esp-elf-gcc, -strip, -nm (they ship together with ESP-IDF).\n' >&2
    printf '  This is a FAILURE and not a skip: the gate under test cannot run here\n' >&2
    printf '  either, so a green result would be a claim nobody checked.\n' >&2
    exit 1
fi

# --- the needles, read from the gate -----------------------------------------
HIL_MODULE=$(sed -n "s/^HIL_MODULE='\(.*\)'.*/\1/p" "$GATE")
HIL_UART_RE=$(sed -n "s/^HIL_UART='\(.*\)'.*/\1/p" "$GATE")
HIL_SOURCE=$(sed -n "s/^HIL_SOURCE='\(.*\)'.*/\1/p" "$GATE")
# HIL_STRINGS is a multi-line single-quoted assignment: take the lines between
# the opening quote and the line that closes it, then shave both quotes off.
HIL_STRINGS=$(sed -n "/^HIL_STRINGS='/,/'\$/p" "$GATE" \
    | sed "1s/^HIL_STRINGS='//" | sed "\$s/'\$//")
# The alternation is a regex only because the gate matches whole symbol names
# with it. Stripped of its anchors it is the list of C entry points to fabricate.
UART_NAMES=$(printf '%s' "$HIL_UART_RE" | tr -d '^()$' | tr '|' ' ')

if [ -z "$HIL_MODULE" ] || [ -z "$HIL_STRINGS" ] || [ -z "$UART_NAMES" ] || [ -z "$HIL_SOURCE" ]; then
    printf 'selftest-release-symbols: could not read the needles out of the gate.\n' >&2
    printf '  HIL_MODULE/HIL_UART/HIL_STRINGS/HIL_SOURCE changed shape. Fix the parser\n' >&2
    printf '  above - do not delete the cases.\n' >&2
    exit 1
fi

# --- fixture ELFs -------------------------------------------------------------
#
# An object file rather than a linked executable: the gate reads magic bytes,
# symbol names and raw bytes, all of which an ET_REL file has, and building one
# needs no linker script and no runtime. A non-static global cannot be discarded
# by the compiler, which is what guarantees the literals actually reach .rodata.
c_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

# emit_c <file> <with-hil-symbols:0|1> <with-uart:0|1> <with-words:0|1> <with-anchor:0|1>
emit_c() {
    local out=$1 hil=$2 uart=$3 words=$4 anchor=$5 i=0 s n
    : > "$out"
    if [ "$anchor" -eq 1 ]; then
        printf 'void nyt_anchor(void) asm("_ZN15notyas_firmware4main17hfeedfacefeedface0E");\nvoid nyt_anchor(void) {}\n' >> "$out"
    else
        printf 'void unrelated_entry(void) {}\n' >> "$out"
    fi
    if [ "$hil" -eq 1 ]; then
        # Both of rustc's manglings, because the gate claims one fixed substring
        # covers both and that claim is worth an assertion rather than a comment.
        printf 'void hil_legacy(void) asm("_ZN%s8dispatch17hfeedfacefeedface1E");\nvoid hil_legacy(void) {}\n' "$HIL_MODULE" >> "$out"
        printf 'void hil_v0(void) asm("_RNvNtCsfeedface_%s8dispatch");\nvoid hil_v0(void) {}\n' "$HIL_MODULE" >> "$out"
    fi
    if [ "$uart" -eq 1 ]; then
        for n in $UART_NAMES; do
            printf 'void %s(void) {}\n' "$n" >> "$out"
        done
    fi
    if [ "$words" -eq 1 ]; then
        while IFS= read -r s; do
            [ -n "$s" ] || continue
            printf 'const char *const nyt_word_%d = "%s";\n' "$i" "$(c_escape "$s")" >> "$out"
            i=$((i + 1))
        done <<EOF
$HIL_STRINGS
EOF
    fi
}

# fixture <name> <hil> <uart> <words> <anchor>  -> sets ELF
ELF=""
fixture() {
    local name=$1
    ELF="$WORK/$name.elf"
    emit_c "$WORK/$name.c" "$2" "$3" "$4" "$5"
    "$GCC" -c -O0 -o "$ELF" "$WORK/$name.c"
}

# --- the assertion -----------------------------------------------------------
#
# expect <description> <want-exit> <marker...> -- <gate argument...>
#
# Markers are fixed strings the gate's output must contain. They are what
# separates "the gate found the console" from "the gate fell over", which is the
# whole reason this file exists.
expect() {
    local what=$1 want=$2; shift 2
    local markers=() args=() out code m
    while [ $# -gt 0 ] && [ "$1" != "--" ]; do markers+=("$1"); shift; done
    shift || true
    args=("$@")

    set +e
    out=$(cd "$REPO_ROOT" && bash tools/ci/check-release-symbols.sh "${args[@]}" 2>&1)
    code=$?
    set -e

    if [ "$code" -ne "$want" ]; then
        fail "$what"
        note "expected exit $want, got $code. The gate said:"
        printf '%s\n' "$out" | sed 's/^/          | /'
        return 0
    fi
    for m in "${markers[@]}"; do
        if ! printf '%s' "$out" | grep -qF -- "$m"; then
            fail "$what"
            note "exit $code was right, but the output does not contain:"
            note "  \"$m\""
            note "so the gate did not reach its verdict for the reason under test."
            printf '%s\n' "$out" | sed 's/^/          | /'
            return 0
        fi
    done
    pass "$what"
}

printf '\n=== the Q41 symbol gate, put in front of images it must reject ===\n\n'
note "gate:      tools/ci/check-release-symbols.sh"
note "fixtures:  $WORK"
note "needles:   module \"$HIL_MODULE\", C entry points [$UART_NAMES],"
note "           $(printf '%s' "$HIL_STRINGS" | grep -c .) .rodata literals - all read from the gate"
printf '\n'

# --- 1. a clean image passes --------------------------------------------------
#
# First, because a gate that rejects everything is one nobody runs. This fixture
# is what every release artefact so far has looked like to the gate: recognisable
# as notyas firmware, and carrying none of the three console signatures.
fixture clean 0 0 0 1
expect "a console-free image is accepted" 0 \
    "recognised as a notyas firmware image" \
    "no notyas_firmware::hil symbol" \
    "nothing can read the port" \
    "no console string literal in .rodata" \
    -- --image "$ELF"

# --- 2. the console's Rust symbols --------------------------------------------
#
# The finding the gate exists to make. Both manglings are in this fixture, so a
# pass here also settles the gate's claim that one fixed substring covers legacy
# and v0 alike.
fixture console-symbols 1 0 0 1
expect "a linked HIL console is rejected on its Rust symbols" 1 \
    "THE HIL TEST CONSOLE IS LINKED INTO THIS IMAGE" \
    "2 symbol(s) of notyas_firmware::hil" \
    "not a release candidate" \
    -- --image "$ELF"

# --- 3. the console's RX path in C --------------------------------------------
#
# The tier that survives a rename. An image with no Rust symbol named hil, but
# with the UART entry points nothing else in the firmware calls, is still a
# finding - and this case is what proves that tier is wired rather than written.
fixture console-uart 0 1 0 1
expect "the console's UART RX path alone is enough to reject an image" 1 \
    "the console's UART RX path is linked into this image" \
    -- --image "$ELF"

# --- 4. the console's own words -----------------------------------------------
#
# The tier that survives inlining, LTO and strip, because it is data rather than
# code. No hil symbol and no UART call in this fixture: the literals carry it.
fixture console-words 0 0 1 1
expect "the console's string literals alone are enough to reject an image" 1 \
    "THE HIL TEST CONSOLE'S OWN WORDS ARE IN THIS IMAGE" \
    "answers format, seal, wipe, dump and psbtsign on UART0 with no PIN" \
    -- --image "$ELF"

# --- 5. strip is not a way past this gate -------------------------------------
#
# The case that has to be right. `strip = "symbols"` is one line of TOML, it is
# something hardening guides recommend, and it removes every symbol the two
# tiers above read. A gate that answered "no console symbols found" to a file
# with no symbols would be worse than absent: it would print a clean verdict on
# the most dangerous artefact this project can produce.
fixture stripped-clean 0 0 0 1
cp "$ELF" "$WORK/stripped-clean-s.elf"
"$STRIP" "$WORK/stripped-clean-s.elf"
expect "a STRIPPED image is refused rather than cleared" 1 \
    "STRIPPED - the symbol table is gone" \
    "the absence of a" \
    "A release artefact is never stripped" \
    -- --image "$WORK/stripped-clean-s.elf"

fixture stripped-console 1 1 1 1
cp "$ELF" "$WORK/stripped-console-s.elf"
"$STRIP" "$WORK/stripped-console-s.elf"
expect "a STRIPPED console-bearing image is still caught, by its words" 1 \
    "STRIPPED - the symbol table is gone" \
    "THE HIL TEST CONSOLE'S OWN WORDS ARE IN THIS IMAGE" \
    -- --image "$WORK/stripped-console-s.elf"

# Belt and braces on the wording of the stripped-but-clean verdict: it must not
# read as a pass anywhere in the output. This is asserted separately because it
# is the sentence a reader skims, and a future edit that softened it would
# quietly turn "unknown" back into "clean".
expect "a stripped clean image is never described as clean" 1 \
    "which is NOT a clean" \
    "A string probe can find a console; it can never rule one out" \
    -- --image "$WORK/stripped-clean-s.elf"

# --- 6. an image the gate cannot recognise ------------------------------------
#
# Absence of the console proves nothing about a file that is not this firmware.
# A bootloader, a partition table or somebody else's binary would all show zero
# console symbols, and reporting that as clean is a vacuous pass.
fixture foreign 0 0 0 0
expect "an ELF that is not notyas firmware cannot be cleared" 1 \
    "no notyas-firmware Rust symbols in this file" \
    "cannot say anything about an image it cannot recognise" \
    -- --image "$ELF"

printf 'not an ELF, just some bytes\n' > "$WORK/notanelf.bin"
expect "a non-ELF input is refused, not shrugged at" 1 \
    "not an ELF - this gate's subject is the linked image" \
    -- --image "$WORK/notanelf.bin"

expect "an image path that does not exist is a failure" 1 \
    "no such file" \
    -- --image "$WORK/there-is-no-such-image.elf"

# --- 7. the anti-rot check on the .rodata probe -------------------------------
#
# A literal the console no longer prints is a search that can only ever succeed
# at finding nothing, and finding nothing is this gate's pass verdict. The gate
# re-derives its literals from the console's source on every run for that reason.
# Proving it needs a tree where the source has moved on, which is what this
# fixture root is: a copy of the gate, and a stub console missing one of them.
STALE="$WORK/stale-root"
mkdir -p "$STALE/tools/ci" "$STALE/$(dirname "$HIL_SOURCE")"
cp "$GATE" "$STALE/tools/ci/check-release-symbols.sh"
{
    printf '// fixture: a console whose help text has been rewritten.\n'
    printf '%s\n' "$HIL_STRINGS" | sed -n '2,$p'
} > "$STALE/$HIL_SOURCE"
fixture for-stale 0 0 0 1
set +e
stale_out=$(cd "$STALE" && bash tools/ci/check-release-symbols.sh --image "$ELF" 2>&1)
stale_code=$?
set -e
if [ "$stale_code" -eq 1 ] \
   && printf '%s' "$stale_out" | grep -qF 'the .rodata probe is out of date' \
   && printf '%s' "$stale_out" | grep -qF 'a probe for a string nothing emits always passes'; then
    pass "a literal the console no longer prints fails the gate instead of rotting"
else
    fail "a literal the console no longer prints fails the gate instead of rotting"
    note "expected exit 1 and the out-of-date message, got exit $stale_code:"
    printf '%s\n' "$stale_out" | sed 's/^/          | /'
fi

# --- 8. the gate refuses to pass when it cannot run ---------------------------
#
# Its tools are part of its subject. With nm unreachable there is no view of the
# artefact at all, and the only honest verdict is failure. Forced by pointing
# HOME at an empty directory and cutting the toolchain out of PATH - the two
# places the gate looks. PATH keeps the system bin directory: the gate needs
# grep, sed, awk, od and head to reach the point where it reports a missing nm,
# and a shell with no PATH at all would fail before the gate ever started, which
# would be this case passing for the wrong reason.
fixture for-notools 0 0 0 1
mkdir -p "$WORK/empty-home"
SYSBIN=$(dirname "$(command -v grep)")
BASH_BIN=$(command -v bash)
set +e
notools_out=$(cd "$REPO_ROOT" && env -i \
    PATH="$SYSBIN" HOME="$WORK/empty-home" \
    "$BASH_BIN" tools/ci/check-release-symbols.sh --image "$ELF" 2>&1)
notools_code=$?
set -e
if [ "$notools_code" -eq 1 ] && printf '%s' "$notools_out" | grep -qF 'this gate cannot run'; then
    pass "with no nm on the machine the gate fails rather than reporting clean"
elif [ -x "$SYSBIN/riscv32-esp-elf-nm" ] || [ -x "$SYSBIN/riscv32-esp-elf-nm.exe" ]; then
    fail "with no nm on the machine the gate fails rather than reporting clean"
    note "this case could not be set up: the toolchain is installed in $SYSBIN,"
    note "so nm cannot be taken away without taking grep and sed with it."
else
    fail "with no nm on the machine the gate fails rather than reporting clean"
    note "expected exit 1 and 'this gate cannot run', got exit $notools_code:"
    printf '%s\n' "$notools_out" | sed 's/^/          | /'
fi

# --- 9. no image at all -------------------------------------------------------
#
# The vacuous pass in its purest form. Run from a tree with no board map and no
# built artefact, with the target-directory overrides cleared, the gate must say
# Q41 is unproven and exit non-zero.
NOIMG="$WORK/noimage-root"
mkdir -p "$NOIMG/tools/ci"
cp "$GATE" "$NOIMG/tools/ci/check-release-symbols.sh"
set +e
noimg_out=$(cd "$NOIMG" && env -u NOTYAS_TARGET_DIR -u CARGO_TARGET_DIR \
    bash tools/ci/check-release-symbols.sh 2>&1)
noimg_code=$?
set -e
if [ "$noimg_code" -eq 1 ] \
   && printf '%s' "$noimg_out" | grep -qF 'no built firmware ELF found' \
   && printf '%s' "$noimg_out" | grep -qF 'Do not read this as clean'; then
    pass "with no image to read the gate fails and says Q41 is unproven"
else
    fail "with no image to read the gate fails and says Q41 is unproven"
    note "expected exit 1 and 'no built firmware ELF found', got exit $noimg_code."
    note "If the gate found an image, it came from the root it hard-codes for a bare"
    note "cargo build. That root holding a firmware image is the only way this case"
    note "can report a false alarm, and it is worth knowing about either way."
    printf '%s\n' "$noimg_out" | sed 's/^/          | /'
fi

printf '\n'
if [ "$FAILURES" -gt 0 ]; then
    printf 'selftest-release-symbols: FAILED - %d of %d cases.\n' "$FAILURES" "$((PASSES + FAILURES))"
    printf 'tools/ci/check-release-symbols.sh does not enforce Q41 as specified. Until\n'
    printf 'this passes, the claim that a shipped image contains no test console has no\n'
    printf 'evidence behind it.\n'
    exit 1
fi
printf 'selftest-release-symbols: OK - %d cases, the gate clears and rejects as specified.\n' "$PASSES"
exit 0
