#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# check-airgap.sh - SECURITY.md invariant 1, asserted mechanically.
#
# The product claim is that the radio is DEAD, not that it is documented as
# dead. tools/build-graph-check.sh already covers the Cargo half of that claim
# (no networking crate in the dependency graph). It cannot see the other three
# halves, and they are the ones an attacker cares about:
#
#   - the ESP-IDF component list, which is resolved by CMake and never appears
#     in any Cargo.lock, so a radio stack can enter the image without touching
#     a single file this repository greps today;
#   - the LINKED IMAGE, which is the only artefact that can be said to contain
#     or not contain a radio. A component on the link line whose members are all
#     discarded by --gc-sections is not in the image, and a component absent
#     from the manifest but pulled transitively is;
#   - the kill GPIO, whose whole value is that it is driven low FIRST and never
#     touched again. A pin driven low in app_main and then handed to a driver
#     later is a radio that comes back, and nothing in the tree notices.
#
# So this gate has two tiers. The source tier is cheap and runs anywhere. The
# image tier needs a built ELF and is the only tier that proves anything about
# what actually ships; it is therefore NOT optional by default - a security gate
# that skips silently is worse than no gate at all, the same rule
# build-graph-check.sh applies to a missing cargo.
#
# Usage:
#   tools/ci/check-airgap.sh                     # source tier + every image found
#   tools/ci/check-airgap.sh --image PATH/ELF    # source tier + that one image
#   tools/ci/check-airgap.sh --source-only       # source tier ONLY, and say so loudly
#
# Exit 0 = clean, 1 = violation.

set -euo pipefail

cd "$(dirname "$0")/../.."

FW=firmware
BOARDDIR=$FW/src/board

FAILURES=0
CHECKS=0
ok()   { CHECKS=$((CHECKS + 1)); printf '  ok    %s\n' "$*"; }
bad()  { CHECKS=$((CHECKS + 1)); FAILURES=$((FAILURES + 1)); printf '  FAIL  %s\n' "$*"; }
note() { printf '        %s\n' "$*"; }

SOURCE_ONLY=0
IMAGES=""
while [ $# -gt 0 ]; do
    case "$1" in
        --source-only) SOURCE_ONLY=1; shift ;;
        --image)       IMAGES="$IMAGES $2"; shift 2 ;;
        *) printf 'check-airgap: unknown argument %s\n' "$1" >&2; exit 1 ;;
    esac
done

# --- C6 SDIO host pins, per board family -------------------------------------
#
# docs/BOARDS.md "Peripheral map" is the source of truth for these; they are
# repeated here because a check that reads its expectations out of the document
# it is checking proves nothing. Format: <module-stem>:<space separated GPIOs>.
# A board module that NAMES one of its own SDIO pins has configured it, which is
# the third lockdown layer breaking.
SDIO_PINS="
waveshare_4b:14 15 16 17 18 19
waveshare_common:14 15 16 17 18 19
waveshare_5:14 15 16 17 18 19
waveshare_7b:14 15 16 17 18 19
waveshare_7x:14 15 16 17 18 19
waveshare_8x:14 15 16 17 18 19
waveshare_101x:14 15 16 17 18 19
elecrow_5:49 50 51 52 53 54
elecrow_dsi:14 15 18 19
"

printf '\n=== tier 1: source ===\n\n'

# 1. Every board module that exports a radio kill line declares the GPIO as a
#    compile-time constant. A runtime-computed kill pin would be a pin nobody
#    can audit from the source.
printf 'kill line declared\n'
for f in "$BOARDDIR"/*.rs; do
    stem=$(basename "$f" .rs)
    grep -q 'RADIO_KILL_GPIO *: *i32 *= *[0-9]' "$f" || continue
    kill_gpio=$(sed -n 's/.*RADIO_KILL_GPIO *: *i32 *= *\([0-9]*\).*/\1/p' "$f" | head -1)
    ok "$stem declares RADIO_KILL_GPIO = $kill_gpio"
done

# 2. radio_lockdown() drives that line LOW as its first statement. One level of
#    indirection is resolved (the Waveshare scaffolds share
#    waveshare_common::radio_lockdown_gpio54), because forbidding a shared
#    helper would only push people to copy-paste the thing that matters.
printf '\nkill line driven low FIRST inside radio_lockdown()\n'
first_stmt() {
    # first_stmt <file> <fn-name> -> first non-blank, non-comment line of the body.
    awk -v fn="$2" '
        $0 ~ ("fn " fn "\\(") { inbody = 1; next }
        inbody {
            line = $0
            sub(/^[ \t]+/, "", line)
            if (line == "" || line ~ /^\/\//) next
            print line
            exit
        }' "$1"
}
WANT_FIRST='claim_output(RADIO_KILL_GPIO, 0);'
for f in "$BOARDDIR"/*.rs; do
    stem=$(basename "$f" .rs)
    grep -q 'pub fn radio_lockdown' "$f" || continue
    stmt=$(first_stmt "$f" radio_lockdown)
    if [ "$stmt" = "$WANT_FIRST" ]; then
        ok "$stem::radio_lockdown drives RADIO_KILL_GPIO low first"
        continue
    fi
    case "$stmt" in
        *'();')
            # Delegated. Resolve the helper under src/board/ and demand the same
            # first statement of it.
            helper=$(printf '%s' "$stmt" | sed 's/();$//; s/.*:://')
            hfile=$(grep -l "fn $helper(" "$BOARDDIR"/*.rs 2>/dev/null | head -1)
            if [ -z "$hfile" ]; then
                bad "$stem::radio_lockdown delegates to '$helper', which does not exist under $BOARDDIR"
            else
                hstmt=$(first_stmt "$hfile" "$helper")
                if [ "$hstmt" = "$WANT_FIRST" ]; then
                    ok "$stem::radio_lockdown -> $(basename "$hfile" .rs)::$helper drives RADIO_KILL_GPIO low first"
                else
                    bad "$stem::radio_lockdown -> $helper does not drive the kill line first (found: $hstmt)"
                fi
            fi
            ;;
        *)
            bad "$stem::radio_lockdown does not drive the kill line first (found: ${stmt:-empty body})"
            note "the first statement of radio_lockdown must be: $WANT_FIRST"
            ;;
    esac
done

# 3. The kill GPIO is never reused. claim_output() is the only thing in this
#    tree that takes a pin, and a second constant carrying the kill pin's number
#    is how that pin quietly becomes a backlight - after which a driver owns it
#    and the radio's hold is whatever that driver leaves behind.
printf '\nkill GPIO is not reused by any other pin in its own module\n'
for f in "$BOARDDIR"/*.rs; do
    stem=$(basename "$f" .rs)
    grep -q 'RADIO_KILL_GPIO *: *i32 *= *[0-9]' "$f" || continue
    kill_gpio=$(sed -n 's/.*RADIO_KILL_GPIO *: *i32 *= *\([0-9]*\).*/\1/p' "$f" | head -1)
    clash=$(grep -n ": *i32 *= *${kill_gpio} *;" "$f" | grep -v RADIO_KILL_GPIO || true)
    arrayclash=$(grep -nE "\[i32; *[0-9]+\] *= *\[.*(\[|, *)${kill_gpio}(,|\])" "$f" || true)
    if [ -n "$clash$arrayclash" ]; then
        bad "$stem reuses GPIO$kill_gpio, its own radio kill line, as another pin"
        printf '%s\n' "$clash$arrayclash" | sed 's/^/          /'
    else
        ok "$stem: GPIO$kill_gpio appears only as RADIO_KILL_GPIO"
    fi
done

# 4. The C6 SDIO host pins are never named. Naming one is not proof it is
#    configured, but every way this firmware configures a pin goes through a
#    named constant, so "never named" is a sound over-approximation and it is
#    the one a reviewer can check by eye.
printf '\nC6 SDIO host pins never named in the owning board module\n'
printf '%s\n' "$SDIO_PINS" | grep . | while IFS=: read -r stem pins; do
    f="$BOARDDIR/$stem.rs"
    if [ ! -f "$f" ]; then
        printf '  FAIL  %s.rs is missing - the SDIO pin table in this script is stale\n' "$stem"
        continue
    fi
    hits=""
    for p in $pins; do
        h=$(grep -n ": *i32 *= *${p} *;" "$f" || true)
        a=$(grep -nE "\[i32; *[0-9]+\] *= *\[.*(\[|, *)${p}(,|\])" "$f" || true)
        [ -n "$h$a" ] && hits="$hits GPIO$p"
    done
    if [ -n "$hits" ]; then
        printf '  FAIL  %s names its own C6 SDIO host pin(s):%s\n' "$stem" "$hits"
    else
        printf '  ok    %s: none of GPIO{%s} is named\n' "$stem" "$(printf '%s' "$pins" | tr ' ' ',')"
    fi
done > "${TMPDIR:-/tmp}/airgap-sdio.$$"
cat "${TMPDIR:-/tmp}/airgap-sdio.$$"
SDIO_FAILS=$(grep -c '^  FAIL' "${TMPDIR:-/tmp}/airgap-sdio.$$" || true)
SDIO_OKS=$(grep -c '^  ok' "${TMPDIR:-/tmp}/airgap-sdio.$$" || true)
rm -f "${TMPDIR:-/tmp}/airgap-sdio.$$"
CHECKS=$((CHECKS + SDIO_FAILS + SDIO_OKS))
FAILURES=$((FAILURES + SDIO_FAILS))

# 5. app_main calls radio_lockdown BEFORE it touches storage, the self-test or
#    any peripheral. The boot order is the invariant; a mount or a panel
#    bring-up that runs first widens the window the Elecrow already has.
printf '\nradio_lockdown is the first board/hardware call in app_main\n'
MAIN=$FW/src/main.rs
lock_line=$(grep -n 'board::radio_lockdown()' "$MAIN" | head -1 | cut -d: -f1)
if [ -z "$lock_line" ]; then
    bad "main.rs never calls board::radio_lockdown()"
else
    earlier=$(awk -v n="$lock_line" 'NR < n && /board::(display_init|touch_init|backlight_set)|Store::mount|selftest::run|attach_scratch/ { printf "line %d: %s\n", NR, $0 }' "$MAIN" | sed 's/^[ \t]*//')
    if [ -n "$earlier" ]; then
        bad "main.rs does hardware or storage work before the lockdown at line $lock_line:"
        printf '%s\n' "$earlier" | sed 's/^/          /'
    else
        ok "board::radio_lockdown() at main.rs:$lock_line precedes storage, self-test and every peripheral"
    fi
fi

# 6. No radio component can enter through the ESP-IDF side. Two doors: the
#    extra_components table in firmware/Cargo.toml (what we ask for) and the
#    resolved component lock (what we got, including transitive pulls).
printf '\nno radio component in the ESP-IDF build\n'
RADIO_COMPONENTS='esp_wifi|esp-wifi|esp_hosted|esp-hosted|ieee802154|openthread|esp_now|espnow|bluedroid|nimble|esp_zigbee|esp_thread|esp_coex|wpa_supplicant|wifi_provisioning|esp_rainmaker'
for f in "$FW/Cargo.toml" "$FW/components_esp32p4.lock"; do
    if [ ! -f "$f" ]; then
        bad "$f is missing"
        continue
    fi
    hits=$(grep -nEi "$RADIO_COMPONENTS" "$f" || true)
    if [ -n "$hits" ]; then
        bad "$f names a radio component:"
        printf '%s\n' "$hits" | sed 's/^/          /'
    else
        ok "$(basename "$f"): no radio component named"
    fi
done

# 7. No sdkconfig defaults file in the repo turns a radio on. This covers the
#    board overlays too, which is where a per-board option would hide.
printf '\nno sdkconfig defaults file enables a radio\n'
RADIO_CONFIG='^CONFIG_(BT_ENABLED|BT_BLUEDROID_ENABLED|BT_NIMBLE_ENABLED|BLE_[A-Z_]*ENABLED|ESP_WIFI_ENABLED|ESP_WIFI_REMOTE_ENABLED|IEEE802154_ENABLED|OPENTHREAD_ENABLED|ESP_HOSTED[A-Z_]*)=y'
for f in "$FW"/sdkconfig*.defaults "$FW"/boards/*/sdkconfig.defaults; do
    [ -f "$f" ] || continue
    hits=$(grep -nE "$RADIO_CONFIG" "$f" || true)
    if [ -n "$hits" ]; then
        bad "$f enables a radio option:"
        printf '%s\n' "$hits" | sed 's/^/          /'
    else
        ok "$(printf '%s' "$f" | sed "s|^$FW/||"): clean"
    fi
done

# --- tier 2: the linked image ------------------------------------------------

printf '\n=== tier 2: the linked image ===\n\n'

if [ "$SOURCE_ONLY" -eq 1 ]; then
    printf '  SKIPPED by --source-only.\n'
    printf '  The source tier proves the tree ASKS for no radio. It cannot prove the\n'
    printf '  IMAGE contains none: the ESP-IDF link line carries libesp_wifi.a, liblwip.a\n'
    printf '  and libesp_netif.a on every build, and whether any of their members survive\n'
    printf '  --gc-sections is a property of the ELF alone. Run without --source-only\n'
    printf '  against a real build before believing invariant 1 of a release.\n'
else
    if [ -z "$IMAGES" ]; then
        # Per-board target dirs, from tools/build.ps1's board map.
        for d in /c/nyt-ws /c/nyt-w5 /c/nyt-w7b /c/nyt-w7x /c/nyt-w8x /c/nyt-w101x \
                 /c/nyt-e5 /c/nyt-e7 /c/nyt-e9 /c/nyt-e101; do
            for p in debug release; do
                e="$d/riscv32imafc-esp-espidf/$p/notyas-firmware"
                [ -f "$e" ] && IMAGES="$IMAGES $e"
            done
        done
    fi

    if [ -z "$IMAGES" ]; then
        bad "no built firmware ELF found - the image tier could not run"
        note "build one (tools/build.ps1 -Board <name>) or pass --image PATH."
        note "Pass --source-only ONLY when you accept that invariant 1 is unproven."
    else
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
            bad "riscv32-esp-elf-nm not found - the image tier cannot run"
            note "it ships with the ESP-IDF toolchain (~/.espressif/tools/riscv32-esp-elf/)."
        else
            # Symbols that mean a radio, a network stack, a debug server or a USB
            # data path is IN the image. Anchored at the start of the symbol name
            # on purpose: esp-idf-sys's bindgen emits Default impls for radio
            # STRUCTS (esp_now_peer_info, esp_netif_dns_info_t, esp_mqtt_*) whose
            # mangled Rust names contain these words in the middle. Those are
            # struct-zeroing code with no peripheral behind them; an unanchored
            # pattern would flag them forever and the gate would be switched off
            # within a week.
            BANNED='^(esp_wifi|wifi_|esp_now|espnow|ieee802154|esp_ieee802154|esp_bt_|bluedroid|btdm_|r_ble|ble_hs|nimble|esp_openthread|esp_zb)'
            BANNED="$BANNED|^(lwip_|tcpip_|esp_netif|netif_|dhcps_|dhcp_|sntp_|esp_eth_|emac_)"
            BANNED="$BANNED|^(esp_hosted|hosted_|slave_bt|sdio_slave)"
            BANNED="$BANNED|^(sdmmc_host|sdmmc_card|sdspi_host)"
            BANNED="$BANNED|^(tusb_|tud_|tinyusb|usb_host_)"
            BANNED="$BANNED|^(esp_gdbstub|esp_apptrace)"
            # USB paths that would make the port a data port. usb_serial_jtag_* is
            # NOT banned: it is the IDF secondary console, which is output only
            # (components/esp_vfs_console/vfs_console.c - console_write forwards to
            # the secondary, every other call goes to the primary). It is asserted
            # positively below so a change to it is loud rather than silent.
            USB_DATA='^(cdc_acm_[a-z]|msc_|tud_msc|tud_hid|tud_cdc|hid_dev_|esp_hidd|esp_hidh)'

            for elf in $IMAGES; do
                printf '%s\n' "$elf"
                # --defined-only: an undefined reference is not code in the image.
                # Absolute (type A) symbols are ROM addresses supplied by
                # esp32p4.rom*.ld - the mask ROM's own USB CDC-ACM stack among
                # them - and are not part of this artefact either.
                syms=$("$NM" --defined-only "$elf" 2>/dev/null | awk '$2 != "A" { print $3 }')
                if [ -z "$syms" ]; then
                    bad "  could not read symbols from $elf"
                    continue
                fi
                radio_hits=$(printf '%s\n' "$syms" | grep -E "$BANNED" || true)
                if [ -n "$radio_hits" ]; then
                    bad "  radio / network / debug-server code IS LINKED INTO THIS IMAGE:"
                    printf '%s\n' "$radio_hits" | head -20 | sed 's/^/            /'
                else
                    ok "  no radio, network, esp-hosted, SDIO-host or gdbstub symbol"
                fi
                usb_hits=$(printf '%s\n' "$syms" | grep -E "$USB_DATA" || true)
                if [ -n "$usb_hits" ]; then
                    bad "  a USB DATA path is linked into this image:"
                    printf '%s\n' "$usb_hits" | head -20 | sed 's/^/            /'
                else
                    ok "  no CDC-ACM, MSC, HID or TinyUSB device path"
                fi
                # Positive assertion. The USB-Serial-JTAG console driver IS in the
                # image by IDF default (CONFIG_ESP_CONSOLE_SECONDARY_USB_SERIAL_JTAG).
                # Stating it here means the day it changes - in either direction -
                # somebody has to come and edit this line and say why.
                # grep -c, not grep -q: `set -o pipefail` is on, and `grep -q`
                # exits at the first match, which SIGPIPEs the printf feeding it
                # and makes the whole pipeline report 141. A positive assertion
                # that silently inverts is the worst bug a gate can have.
                usj=$(printf '%s\n' "$syms" | grep -c '^usb_serial_jtag_write$' || true)
                if [ "$usj" -gt 0 ]; then
                    ok "  USB-Serial-JTAG present as the IDF secondary console (output only)"
                    note "the boot log therefore leaves the device on the USB port"
                else
                    ok "  USB-Serial-JTAG console absent from this image"
                fi
            done
        fi
    fi
fi

printf '\n'
if [ "$FAILURES" -gt 0 ]; then
    printf 'check-airgap: FAILED - %d of %d assertions broke.\n' "$FAILURES" "$CHECKS"
    printf 'SECURITY.md invariant 1 ("No radio") is the product. Do not merge past this.\n'
    exit 1
fi
printf 'check-airgap: OK - %d assertions hold.\n' "$CHECKS"
exit 0
