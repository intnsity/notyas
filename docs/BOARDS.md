# notyas - Multi-board design

Status: design, 2026-08-17. Governs how the firmware supports more than one physical
board. SECURITY.md remains normative for the invariants; this file defines how each
board satisfies them. Board fact sheets: docs/HARDWARE.md (Waveshare 4B),
docs/research/elecrow-board.md (Elecrow CrowPanel Advanced 5inch).

## Supported boards

| Feature name | Board | Display | Flash | Radio kill |
|---|---|---|---|---|
| `board-waveshare-4b` | Waveshare ESP32-P4-WiFi6-Touch-LCD-4B | 720x720 MIPI-DSI (ST7703) | 32 MB | GPIO54 low -> C6 EN |
| `board-elecrow-5` | Elecrow CrowPanel Advanced 5inch ESP32-P4 | 800x480 parallel RGB565 | 16 MB | GPIO20 low -> C6 EN |

Both are ESP32-P4NRW32 (32 MB PSRAM), rev v1.3 dev silicon, GT911 touch, and carry an
ESP32-C6 whose only control line is its EN pin from a P4 GPIO. The Elecrow board's size
variant is not yet physically confirmed (see TODO list at the end): the 7/9/10.1 inch
siblings share the electronics but use 1024x600 MIPI-DSI panels, which would be a
different board feature, not a variant of this one.

## Board selection: one cargo feature, no runtime detection

Exactly one `board-*` cargo feature must be enabled. The firmware crate declares no
default board; `firmware/src/board/mod.rs` enforces the invariant at compile time:

```rust
// board/mod.rs (sketch)
#[cfg(not(any(feature = "board-waveshare-4b", feature = "board-elecrow-5")))]
compile_error!("select exactly one board: --features board-waveshare-4b | board-elecrow-5");

#[cfg(all(feature = "board-waveshare-4b", feature = "board-elecrow-5"))]
compile_error!("board features are mutually exclusive; enable exactly one");

#[cfg(feature = "board-waveshare-4b")] mod waveshare_4b;
#[cfg(feature = "board-waveshare-4b")] pub use waveshare_4b::*;

#[cfg(feature = "board-elecrow-5")] mod elecrow_5;
#[cfg(feature = "board-elecrow-5")] pub use elecrow_5::*;
```

**SECURITY RATIONALE - the build IS the board.** There is no runtime board detection,
no probing of I2C addresses, flash IDs, or strap pins to "adapt" to whatever hardware
the image lands on. An airgapped signer must be a fixed, auditable configuration: a
firmware that probes-and-adapts has code paths that were never exercised on the
hardware it ships on, a larger attack surface (every probe is a parser of untrusted
hardware responses), and a verification story that depends on which branch ran. Static
dispatch also means the radio-kill GPIO is a compile-time constant that cannot be
redirected by any runtime state. A build for the wrong board fails visibly (wrong
display bus, wrong pins) rather than degrading silently. Reproducible-build artifacts
and release manifests are therefore **per board**: `notyas-0.1.0-waveshare-4b.bin`,
`notyas-0.1.0-elecrow-5.bin`, each with its own SHA256 in the signed manifest.

## The board module surface

Each board is one file, `firmware/src/board/<name>.rs`, exporting the same flat surface
of consts and free functions - no trait objects, no dyn dispatch, no board struct. The
rest of the firmware writes `board::DISPLAY_WIDTH`, `board::radio_lockdown()`, etc.;
conformance is enforced by the call sites (a missing item is a compile error in every
build of that board).

```rust
// Surface every board module must export (sketch, names normative):

pub const BOARD_NAME: &str;            // shown on the Verify screen
pub const DISPLAY_WIDTH: u32;          // physical panel resolution
pub const DISPLAY_HEIGHT: u32;
pub const FLASH_SIZE_MB: u32;          // 32 (waveshare) / 16 (elecrow)

// Radio kill - the airgap invariant, per board:
pub const RADIO_KILL_GPIO: i32;        // 54 (waveshare) / 20 (elecrow)
pub const RADIO_KILL_DOC: &str;        // human-readable mechanism description,
                                       // displayed verbatim on the Verify screen
pub fn radio_lockdown();               // drive the kill line low, first call in
                                       // app_main; also asserts any board-specific
                                       // "radio periphery never initialized" state

// Display + touch bring-up (all board-specific quirks live behind these):
pub fn display_init() -> Display;      // LDO acquires, panel init, framebuffer;
                                       // returns the embedded-graphics DrawTarget
pub fn backlight_set(percent: u8);     // LEDC PWM (waveshare) / STC8 I2C (elecrow)
pub fn touch_init() -> Touch;          // GT911 with per-board SDA/SCL/RST/INT wiring

// Pin consts used by the above (per board; examples):
//   waveshare_4b: LCD_RESET=27, BL_EN=33, BL_PWM=26, TOUCH_SDA=7, TOUCH_SCL=8,
//                 TOUCH_RST=23, TOUCH_INT=NC (polled)
//   elecrow_5:    RGB pin map (DE=2, PCLK=3, HSYNC=40, VSYNC=41, DATA0..15),
//                 TOUCH_SDA=45, TOUCH_SCL=46, TOUCH_RST=36 (BOOT strap - never
//                 drive low around reset), TOUCH_INT=42, STC8_ADDR=0x2F
```

What is deliberately NOT in the surface: anything cryptographic (notyas-core never
sees a board), the UI (draws on the returned DrawTarget), microSD (0.2.x will add
`sd_init()` when PSBT lands - note the Elecrow slot is 1-bit-only SDMMC, the Waveshare
4-bit; the surface fn hides that), audio and camera (never used).

## What varies vs what is invariant

Invariant across boards (the point of the design):

- **notyas-core** - no_std, no I/O, no board knowledge. Byte-identical output on every
  board is invariant 4 of SECURITY.md; the boot self-test vectors run identically.
- **UI screens and flow** - draw on an `embedded-graphics` DrawTarget of whatever
  resolution the board reports. See layout section below.
- **Security invariants 1-6** (SECURITY.md) - each board must satisfy all of them;
  only the *mechanism* of invariant 1 (no radio) is board-specific.
- **Chip-revision pin** - both dev units are rev v1.3; `ESP32P4_SELECTS_REV_LESS_V3`
  stays in the shared sdkconfig base.

Varies per board, confined to `board/<name>.rs` + the board sdkconfig overlay:

| Concern | Waveshare 4B | Elecrow 5inch |
|---|---|---|
| Display bus | 2-lane MIPI-DSI, ST7703 init via `esp_lcd_st7703` | 16-bit parallel RGB565, `esp_lcd_new_rgb_panel()`, no panel init |
| Display LDO dance | ch3 2500 mV (DPHY) + ch4 3300 mV | ch4 3300 mV (I2C/SDIO bank); ch3 only needed for camera - skip |
| Backlight | GPIO33 enable + GPIO26 LEDC PWM | I2C write to STC8 (0x2F reg 0x20) |
| Touch wiring | SDA 7 / SCL 8, RST 23, INT unrouted (poll) | SDA 45 / SCL 46, RST 36 (strap!), INT 42 |
| Radio kill | GPIO54 -> C6 EN | GPIO20 -> C6 EN (10K pullup: C6 defaults ON) |
| C6 SDIO pins (never configured) | 18/19/14-17 | 53/54/49-52 |
| Flash | 32 MB | 16 MB |
| Extra co-processor | none | STC8H1K17 I2C slave (backlight, battery) |
| UART0 bridge / flashing | CH343, COM3 | CH340K, COM6 |

## UI layout across resolutions

The current screens were designed against 720x720 (square). The Elecrow panel is
800x480 (5:3 landscape). The rule: **screens never hardcode pixels; they lay out on a
grid derived from the display dimensions.** Simplest sound mechanism:

- A `Layout` struct computed once at startup from `board::DISPLAY_WIDTH/HEIGHT`:
  content margin, card width, row height, keypad cell size, font scale - all derived
  as fractions of the short edge, clamped to minimum touch-target size (>= 9 mm
  equivalent; on these panels >= 60 px) and to the glyph atlas sizes we ship.
- Screens consume `Layout` fields, not literals. A screen is a vertical stack of
  full-width cards (the Butter Paper idiom already in use); vertical overflow scrolls
  or paginates identically on both boards.
- QR display computes its module size as `min(width, height) / modules`, integer-only
  scaling, centered - resolution-independent by construction.
- The dice keypad and mnemonic word grid get their column count from the aspect
  ratio (square: 3-4 columns; 800x480 landscape: keypad right, entry list left is the
  natural split) - but as a derived arrangement inside the one keypad widget, not a
  per-board screen. If a satisfying layout cannot be derived for a widget, the
  fallback is a `Layout`-selected variant keyed on aspect class (square vs landscape),
  still board-agnostic.
- No scaling of rendered output, ever: 1 framebuffer pixel = 1 panel pixel. Fonts are
  pre-rasterized atlases; `Layout` picks among the shipped sizes.

This keeps the UI code single-source and testable on host (render into an image buffer
at each board's resolution; golden-image tests per resolution).

## sdkconfig: base + per-board overlay

esp-idf-sys honors `ESP_IDF_SDKCONFIG_DEFAULTS` as a semicolon-separated list applied
in order (later files win). Split the current single file:

```
firmware/
  sdkconfig.base.defaults              # shared: rev pin (SELECTS_REV_LESS_V3,
                                       # REV_MIN_100), log level, FreeRTOS tick,
                                       # main stack, SPIRAM 200M + XIP + L2 cache,
                                       # I2C legacy-conflict skip, reproducible-build
  boards/
    waveshare-4b/sdkconfig.defaults    # CONFIG_ESPTOOLPY_FLASHSIZE_32MB=y
    elecrow-5/sdkconfig.defaults       # CONFIG_ESPTOOLPY_FLASHSIZE_16MB=y
                                       # (+ any RGB-peripheral options if needed)
```

Build sets `ESP_IDF_SDKCONFIG_DEFAULTS = "<abs>/sdkconfig.base.defaults;<abs>/boards/<board>/sdkconfig.defaults"`.
The existing `firmware/sdkconfig.defaults` becomes the base file plus the Waveshare
overlay; nothing in the base may name a GPIO or a flash size.

**Stale-artifact hazard:** the IDF build dir bakes in the merged sdkconfig; switching
boards inside one CARGO_TARGET_DIR risks flashing a stale bootloader for the wrong
flash size (flash.ps1's existing warning, squared). Therefore the target dir is
per-board: `C:\nyt-ws` and `C:\nyt-e5` (short, per the path-length constraint in
build.ps1). Switching boards never requires a clean.

## The airgap invariant, per board (normative)

Every board module MUST document its radio kill mechanism in `RADIO_KILL_DOC`, and
this section is the source of truth. A board whose radio cannot be held dead by
hardware from the P4 does not silently ship: it gets a **WARNING** subsection here and
in its fact sheet, and a documented software-only lockdown fallback (all radio-facing
GPIOs latched to inert states + build-graph exclusion), clearly labeled as the weaker
guarantee on the Verify screen.

### board-waveshare-4b

- Kill: **GPIO54 -> C6 CHIP_PU (EN)**, driven low first thing in app_main, never
  released. Hardware-held reset; no esp_hosted/esp_wifi_remote in the build; SDIO
  host never configured on GPIO14-19. (SECURITY.md invariant 1, unchanged.)
- Power-on window: TODO-verify-schematic - whether C6 EN carries a pullup (i.e.
  whether the C6 boots during the interval between power-on and app_main). The
  schematic shows R34 0R from GPIO54 but the default EN level before the P4 drives it
  is not established in our notes. Document the answer in RADIO_KILL_DOC.

### board-elecrow-5

- Kill: **GPIO20 -> C6 CHIP_PU (EN)** through R95 0R, driven low first thing in
  app_main, never released. Verified against schematic AND factory sdkconfig
  (`CONFIG_ESP_HOSTED_SDIO_GPIO_RESET_SLAVE=20`). SDIO host never configured on
  GPIO49-54. Same three-layer story as the Waveshare board.
- **Known power-on window (verified):** C6 EN has a 10K pullup (R77) to an always-on
  3V3 rail - the C6 boots its esp-hosted slave firmware at every power-up and runs
  until app_main drives GPIO20 low (order: hundreds of ms, incl. bootloader). The
  slave firmware idles waiting for an SDIO host and joins no network on its own, and
  the P4 side has no driver to talk to it - but the window exists and is documented,
  not hidden. Mitigation candidates for release units on this board: none in firmware
  (ROM+bootloader run before us); hardware option is removing R77/R95 or the C6
  module outright (document as the recommended prep for a production Elecrow unit).
- **Wireless module socket (physical requirement):** the board has a socket (J9/J11)
  for LoRa/nRF24/Zigbee modules. Airgap on this board additionally requires the
  socket to be EMPTY. Firmware never initializes the socket SPI/UART pins (GPIO26,
  29-32, 47, 48); the build-graph check extends to any driver for these radios; the
  fact sheet and Verify screen text state the socket-must-be-empty requirement.
  Firmware cannot detect an installed module reliably (and per the no-probing rule,
  does not try) - this is a documented physical precondition, like "keep the device
  in your possession".
- **STC8 co-MCU (accepted risk, to be added to SECURITY.md when this board lands):**
  backlight control requires talking I2C to an STC8H1K17 running unpublished Elecrow
  firmware. It has no radio and no bus-master role, but it sits on the touch I2C bus
  and its firmware is unverifiable. We send it exactly one register write (backlight
  duty) and read nothing security-relevant from it.

## Flash size and partition table

Waveshare has 32 MB flash, Elecrow 16 MB. Decision: **one shared partition table,
sized within 16 MB, used by both boards.** notyas is stateless - no NVS, no OTA in
0.1.0, no data partition - so the table is minimal (bootloader, partition table,
single factory app partition of ~4 MB, generous). Identical layout on both boards
means the app image offset, size accounting, and the Verify screen's running-app
SHA256 procedure are board-independent; the extra 16 MB on the Waveshare board is
simply unused. Only `CONFIG_ESPTOOLPY_FLASHSIZE_*` differs (bootloader flash-size
header field), which the per-board sdkconfig overlay owns. If 0.2.x ever wants an
OTA/anti-rollback scheme it must still fit 16 MB, keeping the smallest board the
binding constraint by policy.

## Build and flash tooling (sketch - scripts not yet edited)

`tools/build.ps1` gains a `-Board` parameter (mandatory once a second board module
exists; until then defaults to `waveshare-4b`):

```powershell
param([ValidateSet("waveshare-4b", "elecrow-5")] [string]$Board = "waveshare-4b")

$boardMap = @{
    "waveshare-4b" = @{ Feature = "board-waveshare-4b"; TargetDir = "C:\nyt-ws" }
    "elecrow-5"    = @{ Feature = "board-elecrow-5";    TargetDir = "C:\nyt-e5" }
}
$b = $boardMap[$Board]
$env:CARGO_TARGET_DIR = if ($env:NOTYAS_TARGET_DIR) { $env:NOTYAS_TARGET_DIR } else { $b.TargetDir }
$env:ESP_IDF_SDKCONFIG_DEFAULTS =
    "$firmwareDir\sdkconfig.base.defaults;$firmwareDir\boards\$Board\sdkconfig.defaults"
cargo build --no-default-features --features $b.Feature @args
```

`tools/flash.ps1` gains the same `-Board` parameter driving: the per-board target dir
(same map), `--flash-size` (32mb / 16mb), and the default `-Port` (COM3 = Waveshare
CH343; COM6 = Elecrow CH340K - port letters drift, still overridable). The existing
newest-bootloader-under-esp-idf-sys search is unchanged and now runs inside the
per-board target dir, which removes the wrong-board-bootloader hazard by construction.

Release packaging (tools, later): build both boards, emit
`notyas-<ver>-<board>.bin` + per-board SHA256 lines into one signed SHA256SUMS.txt.

## Open TODOs (need the schematic or the physical board)

1. **TODO-verify-board: Elecrow size variant.** Serial probe cannot distinguish
   5/7/9/10.1 inch (identical electronics). Confirm 5inch by panel dimensions or
   rear silkscreen before implementing `board-elecrow-5`; if it is a 7/9/10.1 the
   display section of this design changes (1024x600 MIPI-DSI, different feature).
2. **TODO-verify-schematic: Waveshare C6 EN default state** (pullup or floating) -
   determines whether the Waveshare board has the same power-on radio window the
   Elecrow board verifiably has. Re-read the 4B schematic around U1 EN / R34.
3. **TODO-verify-board: Elecrow GT911 address** (0x5D vs 0x14 as powered up) and
   touch behavior with RST on the GPIO36 boot strap - confirm probing order works
   and that leaving RST untouched after boot is safe.
4. **TODO-verify-board: Elecrow panel timings** - factory uses pclk 25 MHz, Arduino
   lessons 18 MHz; pick per observed tearing/stability with our double-FB setup.
   The panel's integrated driver IC is undocumented; treat timings as empirical.
5. **TODO-verify-board: STC8 protocol** - confirm backlight write (0x2F/0x20) against
   the physical board; Elecrow's C and MicroPython sources are the only references.
6. **TODO-verify-schematic: Elecrow LDO4/R109 mismatch** - schematic marks the LDO4
   route NC yet factory firmware acquires it and the I2C bank works; keep the acquire
   and verify I2C function on the physical board without relying on the schematic.
