#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# check-release-symbols.sh - MILESTONES.md m4a Q41, asserted against the artefact.
#
# The claim is that a shipped notyas image does not contain the hardware-in-the-
# loop console. Two things already assert it, and neither is evidence:
#
#   - firmware/build.rs refuses `hil-console` in an image built without debug
#     assertions. That stops the artefact existing, which is the strongest thing
#     a build can do - and it is still a statement about a build we ran, not a
#     finding about a file somebody downloaded.
#   - firmware/src/hil.rs carries the same rule as a compile_error!, so it holds
#     even if the build script is skipped or stubbed. Same class: a promise.
#
# This gate reads the linked ELF. It is the only one of the three whose subject
# is the thing that ships, and it is the only one a stranger could re-run against
# a release binary without trusting a word of our build invocation. That is why
# firmware/Cargo.toml names it beside the feature it guards.
#
# WHY IT CARRIES THE WEIGHT. Fences have been written inside the build three
# times and broken three times with real cargo: keyed on PROFILE, a dev-rooted
# custom profile escaped; keyed on debug-assertions, a release-rooted profile
# with assertions turned back on escaped, and turning them on is something
# hardening guides recommend; keyed on a four-variable conjunction, a dev-rooted
# profile with opt-level z, fat LTO and `strip = "symbols"` escaped, built with
# this repository's own tools/build.ps1. The lesson is structural rather than a
# missing variable: a build script sees the profile REQUESTED, and lto, strip and
# RUSTFLAGS overrides never reach it. This script sees the file EMITTED, which is
# the only view that cannot be talked out of the answer.
#
# The console is not just a store editor any more. Since 0.2.0 it can SIGN, so an
# image containing it is a signer that signs on command from a serial port with
# no PIN - the worst defect this project could produce.
#
# WHAT THIS PROVES, AND WHAT IT DOES NOT. nm sees symbols. A hit is proof the
# console's code is in the image. A clean run is proof that no symbol of it
# survived the link, which is not the same as proof that no instruction of it
# did: a function that was fully inlined into a caller leaves no symbol behind.
# That is why the assertions below are of three different kinds - a Rust module
# path, which is what the console's own code is named by; the two ESP-IDF C entry
# points its RX path cannot exist without, which are not inlined across the FFI
# boundary and are discarded by --gc-sections when nothing calls them; and its
# own string literals, which are data rather than code and so survive inlining,
# LTO and strip alike. It is also why this gate does not retire build.rs's
# refusal.
#
# WHO RUNS THIS. tools/release.sh, in its `build` stage, once per board, against
# the ELF that stage has just produced - that wiring is what makes this file a
# gate rather than a tool nobody remembered to run. It is also meant to be run by
# hand on a bench, and by a stranger against a downloaded release ELF.
#
# Usage:
#   tools/ci/check-release-symbols.sh                    # every image found
#   tools/ci/check-release-symbols.sh --image PATH       # that one image, repeatable
#   tools/ci/check-release-symbols.sh --target-dir DIR   # also look under DIR, repeatable
#
# There is deliberately no --skip and no source-only mode. A gate that passes
# when it cannot see its input is worse than no gate: it converts "unknown" into
# "clean" in the one report a release reads. No image, no nm, an input that is
# not an ELF, and an ELF whose symbols have been stripped away are all failures
# here.
#
# Exit 0 = clean, 1 = violation or the gate could not run.

set -euo pipefail

cd "$(dirname "$0")/../.."

FAILURES=0
CHECKS=0
ok()   { CHECKS=$((CHECKS + 1)); printf '  ok    %s\n' "$*"; }
bad()  { CHECKS=$((CHECKS + 1)); FAILURES=$((FAILURES + 1)); printf '  FAIL  %s\n' "$*"; }
note() { printf '        %s\n' "$*"; }

IMAGES=""
EXTRA_DIRS=""
while [ $# -gt 0 ]; do
    case "$1" in
        --image) IMAGES="$IMAGES $2"; shift 2 ;;
        --target-dir) EXTRA_DIRS="$EXTRA_DIRS $2"; shift 2 ;;
        *) printf 'check-release-symbols: unknown argument %s\n' "$1" >&2; exit 1 ;;
    esac
done

# --- the symbols that mean the console is in the image ------------------------
#
# 1. The Rust module path. Both of rustc's manglings spell a path component as
#    its byte length followed by its name, and both put the defining crate in the
#    same string: legacy emits _ZN15notyas_firmware3hil8dispatch17h<hash>E and v0
#    emits _RNvNtCs<hash>_15notyas_firmware3hil8dispatch. So one fixed substring
#    covers both, and it is anchored to this crate rather than to the word "hil".
#    That anchoring is not decoration. A bare grep for "hil" matches nine symbols
#    in a console-free image today, every one of them from the mangled name of
#    core's BTreeNode::correct_all_childrens_parent_links - c-HIL-drens. An
#    unanchored pattern would cry wolf from the first run and the gate would be
#    switched off within a week (check-airgap.sh learned the same lesson about
#    bindgen's radio structs).
#
#    Matched with grep -F: the string carries no metacharacters and a fixed
#    search cannot be broken by a future component name that does.
HIL_MODULE='15notyas_firmware3hil'
#
# 2. The console's RX path in C. src/hil.rs is the ONLY caller of either of these
#    in the whole firmware tree, and neither survives --gc-sections unless
#    something calls it: uart_driver_install is absent from a console-free image
#    even though the IDF's own esp_vfs_uart symbols are present, which is what
#    makes it a signal rather than a coincidence. This assertion is here because
#    it is immune to the failure mode the first one has - a C symbol crossed by
#    FFI is not inlined away - and because it would still fire if the console
#    were rewritten under another module name.
#
#    If a future non-console feature legitimately installs a UART driver, this
#    gate must be edited and the edit explained. That is the correct outcome: it
#    makes a real change to what the serial port can do loud instead of silent.
HIL_UART='^(uart_driver_install|uart_read_bytes)$'
#
# 3. The console's own words, in .rodata. Both assertions above name a symbol,
#    and a symbol is precisely what `strip` removes. These are the console's
#    string literals: data the program needs at run time, which no strip, no
#    inlining and no LTO can take out of an image that still prints them. They
#    are what lets this gate say something true about a stripped file instead of
#    shrugging at it, and a second opinion on an unstripped one.
#
#    Measured on the waveshare-4b pair built today, before and after
#    riscv32-esp-elf-strip: every literal below occurs in the console-bearing
#    image, stripped and unstripped alike, and none of them occurs in the
#    console-free release image.
#
#    One literal from each of the three things the console is - the banner it
#    announces itself with, the help table that names the destructive commands,
#    and the reply prefix of `psbtsign`, the command that makes an image carrying
#    it a signer anyone with a cable can drive. A hit on ANY of them is a
#    finding; they are not required to agree.
HIL_STRINGS='hil: TEST CONSOLE ACTIVE on UART
erase BOTH partitions (store returns to blank)
HIL|psbtsign|'
#
# A literal probe rots silently: rewrite the help text and the search goes on
# succeeding forever against a string nothing prints any more. So the literals
# are re-derived from the console's own source on every run, and a stale one is
# a failure here - the same rule as the note above about uart_driver_install.
HIL_SOURCE='firmware/src/hil.rs'
#
# NOT checked here, on purpose: the `measure` and `hmac-virtual-check` features.
# Both also build images that are not products, and both deserve a gate - but Q41
# is about the console, and a gate that fails on artefacts nobody claimed were
# releases is a gate people learn to ignore. Adding either is one entry beside
# HIL_MODULE (15notyas_firmware7measure, 15notyas_firmware10hmac_check) plus the
# discovery rule that says which images are release candidates.

# --- the ELFs ----------------------------------------------------------------
#
# A bench image is EXPECTED to fail this gate: it was built with the console in
# it deliberately. That is a true finding, not a false alarm - the gate's subject
# is "may this be shipped", and the answer for a bench image is no. Scope a run
# with --image when you want the verdict on one artefact.
#
# WHICH DIRECTORIES, AND WHY NOT A LIST OF PROFILE NAMES. This loop used to walk
# `debug` and `release` under one hard-coded triple. Cargo does not put a custom
# profile's output in either: `--profile hardened` lands in
# <target>/<triple>/hardened/, measured directly on cargo 1.96.0. A console-
# bearing image built that way sat beside a scanned one and this gate printed
# "OK - N assertions hold" and exited 0, because the only directories it ever
# opened were the two it was told to expect. A gate whose subject is "the thing
# that ships" cannot hold a list of the shapes a shipping thing is allowed to
# have: that is the same class of mistake as keying a fence on a profile NAME,
# one layer along, and it produces the one output this gate must never produce -
# silence read as clean.
#
# So the profile directory is enumerated, never named. Every immediate child of
# every target-triple directory is a candidate, and an image is whatever answers
# to the binary's name; a directory that holds no image contributes nothing.
# <target>/<profile>/ is globbed too, which is where an image built for the host
# triple would land - not a shape this firmware can be built in today, and listed
# because the point of this loop is to stop asserting which shapes exist.
#
# WHICH ROOTS, AND WHY NOT A COPY OF THE BOARD MAP. The same mistake one layer
# further out. The roots used to be a transcription of tools/build.ps1's board
# map, so an image built with NOTYAS_TARGET_DIR - which that script documents as
# a supported override, and which its own warning about sdkconfig-bearing target
# directories tells the operator to use - was invisible to this gate. The
# transcription is gone: the board roots are read out of build.ps1 itself, so a
# board added there is scanned here without anyone remembering to, and the
# override is honoured from the environment and from --target-dir.
#
# The roots that were searched are printed. A gate that looked somewhere other
# than where the operator thinks is how "found nothing" gets read as "there is
# nothing to find", and saying out loud where it looked is the only defence.
ROOTS=""
NO_BOARD_MAP=0
add_root() {
    # NOTYAS_TARGET_DIR arrives spelled the way Windows spells it (C:\nb\nyt-hx).
    # A backslash inside a glob pattern escapes the character after it, so the
    # pattern C:\nb\nyt-hx/*/* searches for a directory literally called "Cnyt-hx"
    # and silently matches nothing - which is the exact failure this section
    # exists to end. Forward slashes work in every shell that can run this
    # script, MSYS bash included, so normalise on the way in and never carry the
    # other spelling further.
    local d=${1//\\//}
    while [ "$d" != "${d%/}" ]; do d=${d%/}; done
    [ -n "$d" ] || return 0
    case " $ROOTS " in *" $d "*) return 0 ;; esac
    ROOTS="$ROOTS $d"
}

if [ -z "$IMAGES" ]; then
    # The board map, read from the script that owns it rather than copied.
    if [ -f tools/build.ps1 ]; then
        while IFS= read -r d; do add_root "$d"; done <<EOF
$(sed -n 's/.*TargetDir *= *"\([^"]*\)".*/\1/p' tools/build.ps1)
EOF
    else
        # Held rather than printed: nothing has announced what this run is doing
        # yet, and a warning above the heading reads like a warning about the
        # shell rather than about the search.
        NO_BOARD_MAP=1
    fi
    # Where a bare `cargo build` lands, which build.ps1 has no row for. It is
    # here because an image nobody went through build.ps1 to produce is exactly
    # the one nobody remembers the feature flags of.
    add_root /c/nyt
    # The documented override, and cargo's own. Both are read rather than
    # assumed: the operator who set one is the operator whose image this gate
    # most needs to see.
    add_root "${NOTYAS_TARGET_DIR:-}"
    add_root "${CARGO_TARGET_DIR:-}"
    for d in $EXTRA_DIRS; do add_root "$d"; done

    for d in $ROOTS; do
        # An unmatched glob stays literal here (no nullglob), so the -f test is
        # what rejects a target directory that does not exist. `if` rather than
        # `[ -f x ] && ...`: under `set -e` the && form makes the loop's exit
        # status depend on whether the LAST candidate happened to exist.
        for e in "$d"/*/*/notyas-firmware "$d"/*/notyas-firmware; do
            if [ -f "$e" ]; then IMAGES="$IMAGES $e"; fi
        done
    done
    # And the artefacts themselves, when a release build has run here: the files
    # that would actually be uploaded, named as tools/repro/build.sh names them.
    # tools/release.sh passes them explicitly; this is what makes a bare run
    # afterwards report on them too.
    for e in out/release/*/artifacts/*.elf; do
        if [ -f "$e" ]; then IMAGES="$IMAGES $e"; fi
    done
fi

printf '\n=== the linked image ===\n\n'

if [ "$NO_BOARD_MAP" -eq 1 ]; then
    note "tools/build.ps1 is not in this tree, so the per-board target directories"
    note "could not be read from it. Name them with --target-dir DIR."
fi
if [ -n "$ROOTS" ]; then
    note "roots searched:$ROOTS"
    note "an image built anywhere else is invisible here: pass --image or --target-dir."
    printf '\n'
fi

# --- the .rodata probe, and the check that it is still real -------------------
#
# Run once, before any image: a literal the console no longer prints is a search
# that can only ever succeed at finding nothing, and finding nothing is this
# gate's pass verdict. Failing here, with a message naming the literal that
# moved, is far better than reporting clean images forever.
literals_are_current() {
    local missing=0 n=0 s
    if [ ! -f "$HIL_SOURCE" ]; then
        note "$HIL_SOURCE is not in this tree, so the .rodata literals could not be"
        note "re-derived from the console's own source. They are still searched for."
        return 0
    fi
    while IFS= read -r s; do
        [ -n "$s" ] || continue
        n=$((n + 1))
        if ! grep -qF -- "$s" "$HIL_SOURCE"; then
            bad "the .rodata probe is out of date: $HIL_SOURCE no longer contains"
            note "  \"$s\""
            note "the console was edited and this gate was not. Re-derive the literal from"
            note "the code that prints it: a probe for a string nothing emits always passes."
            missing=$((missing + 1))
        fi
    done <<EOF
$HIL_STRINGS
EOF
    [ "$missing" -gt 0 ] || ok "the $n .rodata literals are still printed by $HIL_SOURCE"
}

# The probe itself. grep over the raw file rather than `strings`: one less tool
# to find on a bench, and -a makes grep read a binary as text so that -c counts
# rather than reporting "binary file matches". -F because the literals carry | and
# ( ), and LC_ALL=C because these are bytes rather than text in anybody's locale.
#
# $2 says what an absence is worth here. In a linked image with a symbol table
# the symbols are the authority and this is a second opinion, so a clean probe is
# an assertion. In a stripped file there is no authority at all: absence of a
# string is absence of evidence, it is NOT a clean verdict, and it is recorded as
# a note precisely so that it can never be counted as one.
probe_rodata() {
    local image=$1 mode=$2 hits="" s n
    while IFS= read -r s; do
        [ -n "$s" ] || continue
        n=$(LC_ALL=C grep -acF -- "$s" "$image" || true)
        if [ "$n" -gt 0 ]; then
            hits="${hits}\"${s}\" x${n}
"
        fi
    done <<EOF
$HIL_STRINGS
EOF
    if [ -n "$hits" ]; then
        bad "  THE HIL TEST CONSOLE'S OWN WORDS ARE IN THIS IMAGE:"
        printf '%s' "$hits" | sed 's/^/            /'
        note "these are string literals from $HIL_SOURCE, and nothing in a build"
        note "removes them from an image that still prints them."
        note "This image answers format, seal, wipe, dump and psbtsign on UART0 with no PIN."
        return 0
    fi
    if [ "$mode" = "stripped" ]; then
        note "  no console string literal in .rodata either - which is NOT a clean"
        note "  verdict. A string probe can find a console; it can never rule one out."
        note "  The tier that rules one out is the symbol table, and this file has none."
    else
        ok "  no console string literal in .rodata"
    fi
}

if [ -z "$IMAGES" ]; then
    bad "no built firmware ELF found - this gate could not run"
    note "build one (tools/build.ps1 -Board <name>) or pass --image PATH."
    note "if it was built under NOTYAS_TARGET_DIR, set that variable here too, or"
    note "name the directory with --target-dir DIR."
    note "Q41 is UNPROVEN until this gate reads a real image. Do not read this as clean."
else
    # Same search as check-airgap.sh: PATH first, then the ESP-IDF toolchain the
    # espressif installer puts under the user's home.
    NM=""
    for c in riscv32-esp-elf-nm; do
        command -v "$c" >/dev/null 2>&1 && NM="$c"
    done
    if [ -z "$NM" ]; then
        for c in "$HOME"/.espressif/tools/riscv32-esp-elf/*/riscv32-esp-elf/bin/riscv32-esp-elf-nm \
                 "$HOME"/.espressif/tools/riscv32-esp-elf/*/riscv32-esp-elf/bin/riscv32-esp-elf-nm.exe; do
            [ -x "$c" ] && NM="$c" && break
        done
    fi
    if [ -z "$NM" ]; then
        bad "riscv32-esp-elf-nm not found - this gate cannot run"
        note "it ships with the ESP-IDF toolchain (~/.espressif/tools/riscv32-esp-elf/)."
    else
        literals_are_current

        for elf in $IMAGES; do
            printf '%s\n' "$elf"
            if [ ! -f "$elf" ]; then
                bad "  no such file"
                continue
            fi
            # --defined-only: an undefined reference is not code in the image.
            # Absolute (type A) symbols come from esp32p4.rom*.ld and are the mask
            # ROM's, not this artefact's. Both rules copied from check-airgap.sh so
            # the two gates are reading the same view of the same file.
            syms=$("$NM" --defined-only "$elf" 2>/dev/null | awk '$2 != "A" { print $3 }' || true)

            if [ -z "$syms" ]; then
                # Two very different files arrive here, and they used to be
                # reported as one: "not a readable ELF". That was wrong about the
                # dangerous one. A stripped image IS readable - nm reads it
                # perfectly and answers "no symbols" - and a stripped
                # console-bearing image is a signer on a serial port that the old
                # message described as unreadable rubbish. Four bytes settle which
                # of the two this file is.
                #
                # `head -c 4 | od` rather than file(1), which is not installed on
                # the Windows bench this is most often run from.
                if [ "$(head -c 4 "$elf" 2>/dev/null | od -An -tx1 | tr -d ' \n')" != "7f454c46" ]; then
                    bad "  not an ELF - this gate's subject is the linked image"
                    note "an app.bin, a merged.bin or a partition table is not that subject:"
                    note "pass the .elf that tools/repro/build.sh publishes beside them."
                else
                    # POLICY, and deliberately absolute. A notyas release artefact
                    # is not stripped: tools/repro/build.sh publishes the UNSTRIPPED
                    # release ELF on purpose, so that two builders who disagree can
                    # triage the difference (REPRODUCIBLE.md 4.4 step 5). A file
                    # with no symbol table is therefore either not ours or not the
                    # file we published, and in both cases the honest verdict is
                    # "cannot be verified", never "clean".
                    #
                    # This is the case that has to be right, because it is the one
                    # an attacker and a well-meaning hardening guide both reach
                    # for. `strip = "symbols"` is one line of TOML; it cleared the
                    # four-property build.rs fence with the console compiled in,
                    # and it removes every symbol the two tiers above read. Failing
                    # here, and probing .rodata anyway, is what stops "stripped"
                    # from being the way past the only gate that reads the artefact.
                    bad "  STRIPPED - the symbol table is gone, so this file cannot be cleared"
                    note "nm reads this ELF fine; there are no symbols in it to read. That is"
                    note "not the same as unreadable, and it is not a pass: the absence of a"
                    note "symbol in a file with no symbols means nothing at all."
                    note "A release artefact is never stripped - tools/repro/build.sh publishes"
                    note "the unstripped ELF (REPRODUCIBLE.md 4.4 step 5). Verify that file."
                fi
                # Both branches still get the probe: it is the one tier that works
                # on a file with no symbols, and a hit here is a finding every bit
                # as strong as a symbol.
                probe_rodata "$elf" stripped
                continue
            fi

            # The anchor, and the reason this gate cannot pass vacuously. Absence
            # of the console proves nothing unless the file is a notyas firmware
            # whose Rust symbols are still in it. A bootloader, a partition table
            # or somebody's unrelated binary would all show zero console symbols
            # and mean nothing at all. A fully stripped file never reaches here;
            # one stripped of debug info only keeps .symtab, arrives here, and is
            # verifiable.
            # grep -c rather than grep -q: pipefail is on and grep -q exits at the
            # first match, SIGPIPEing the producer and reporting 141 - the same
            # trap check-airgap.sh documents on its positive assertion.
            anchor=$(printf '%s\n' "$syms" | grep -cF '15notyas_firmware' || true)
            if [ "$anchor" -eq 0 ]; then
                bad "  no notyas-firmware Rust symbols in this file"
                note "this gate cannot say anything about an image it cannot recognise."
                probe_rodata "$elf" stripped
                continue
            fi
            ok "  recognised as a notyas firmware image ($anchor Rust symbols from this crate)"

            hil_hits=$(printf '%s\n' "$syms" | grep -F "$HIL_MODULE" || true)
            if [ -n "$hil_hits" ]; then
                bad "  THE HIL TEST CONSOLE IS LINKED INTO THIS IMAGE:"
                printf '%s\n' "$hil_hits" | head -20 | sed 's/^/            /'
                hil_count=$(printf '%s\n' "$hil_hits" | wc -l | tr -d ' ')
                note "$hil_count symbol(s) of notyas_firmware::hil."
                note "This image answers format, seal, wipe, dump and psbtsign on UART0 with no PIN."
                note "It was built with --features hil-console. It is not a release candidate."
            else
                ok "  no notyas_firmware::hil symbol"
            fi

            uart_hits=$(printf '%s\n' "$syms" | grep -E "$HIL_UART" || true)
            if [ -n "$uart_hits" ]; then
                bad "  the console's UART RX path is linked into this image:"
                printf '%s\n' "$uart_hits" | sed 's/^/            /'
                note "src/hil.rs is the only caller of these in the firmware tree."
                note "If that changed, this gate is out of date - fix it here and say why."
            else
                ok "  no uart_driver_install / uart_read_bytes (nothing can read the port)"
            fi

            probe_rodata "$elf" linked
        done
    fi
fi

printf '\n'
if [ "$FAILURES" -gt 0 ]; then
    printf 'check-release-symbols: FAILED - %d of %d assertions broke.\n' "$FAILURES" "$CHECKS"
    printf 'MILESTONES.md m4a Q41: a shipped image must not contain the test console.\n'
    printf 'Do not ship, sign or publish an image that failed this gate.\n'
    exit 1
fi
printf 'check-release-symbols: OK - %d assertions hold.\n' "$CHECKS"
exit 0
