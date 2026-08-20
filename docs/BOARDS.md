# notyas - Multi-board design

Status: implemented 2026-08-17 (originally authored as a design the same day; deltas
between design and implementation are marked "implementation note" inline). Governs how
the firmware supports more than one physical board. SECURITY.md remains normative for
the invariants; this file defines how each board satisfies them. Board fact sheets:
docs/HARDWARE.md (Waveshare 4B), docs/research/elecrow-board.md (Elecrow CrowPanel
Advanced family).

## Supported boards and status

| Feature name | Board | Display | Flash | Radio kill | Status |
|---|---|---|---|---|---|
| `board-waveshare-4b` | Waveshare ESP32-P4-WiFi6-Touch-LCD-4B | 720x720 MIPI-DSI (ST7703) | 32 MB | GPIO54 low -> C6 EN | **VERIFIED** on hardware (COM3 dev unit) |
| `board-elecrow-5` | Elecrow CrowPanel Advanced 5inch ESP32-P4 | 800x480 parallel RGB565 | 16 MB | GPIO20 low -> C6 EN | **VERIFIED** on hardware (COM6 dev unit) |
| `board-elecrow-7` | Elecrow CrowPanel Advanced 7inch ESP32-P4 | 1024x600 MIPI-DSI (EK79007) | 16 MB | GPIO32 low -> C6 EN | **UNTESTED scaffold** - compiles, never ran |
| `board-elecrow-9` | Elecrow CrowPanel Advanced 9inch ESP32-P4 | 1024x600 MIPI-DSI (EK79007) | 16 MB | GPIO32 low -> C6 EN | **UNTESTED scaffold** - compiles, never ran |
| `board-elecrow-101` | Elecrow CrowPanel Advanced 10.1inch ESP32-P4 | 1024x600 MIPI-DSI (EK79007) | 16 MB | GPIO32 low -> C6 EN | **UNTESTED scaffold** - compiles, never ran |
| `board-waveshare-5` | Waveshare ESP32-P4-WIFI6-Touch-LCD-5 | 720x1280 MIPI-DSI (HX8394) | 32 MB | GPIO54 low -> C6 EN | **UNTESTED scaffold + PORTRAIT LAYOUT UNVERIFIED** - compiles, never ran |
| `board-waveshare-7b` | Waveshare ESP32-P4-WIFI6-Touch-LCD-7B | 1024x600 MIPI-DSI (EK79007) | 32 MB | GPIO54 low -> C6 EN | **UNTESTED scaffold** - compiles, never ran |
| `board-waveshare-7x` | Waveshare ESP32-P4-WIFI6-Touch-LCD-7 ("X") | 720x1280 MIPI-DSI (ILI9881C) | 32 MB | GPIO54 low -> C6 EN | **UNTESTED scaffold + PORTRAIT LAYOUT UNVERIFIED** - compiles, never ran |
| `board-waveshare-8x` | Waveshare ESP32-P4-WIFI6-Touch-LCD-8 ("X") | 800x1280 MIPI-DSI (JD9365) | 32 MB | GPIO54 low -> C6 EN | **UNTESTED scaffold + PORTRAIT LAYOUT UNVERIFIED** - compiles, never ran |
| `board-waveshare-101x` | Waveshare ESP32-P4-WIFI6-Touch-LCD-10.1 ("X") | 800x1280 MIPI-DSI (JD9365) | 32 MB | GPIO54 low -> C6 EN | **UNTESTED scaffold + PORTRAIT LAYOUT UNVERIFIED** - compiles, never ran |

"UNTESTED scaffold" is a hard status: every constant traces to a published vendor
source (Elecrow: factory firmware + that board's own V1.0 Eagle schematic; Waveshare:
docs/research/waveshare-family.md - schematics - plus the vendor's BSP monorepo at a
pinned commit), the module carries an UNTESTED banner, the firmware logs `UNTESTED
BOARD CONFIG` at boot, and build.ps1 warns. No verification claim of any kind until a
physical unit runs it. "PORTRAIT LAYOUT UNVERIFIED" is the additional caveat for the
720x1280 / 800x1280 panels: the UI derives its layout from DISPLAY_WIDTH/HEIGHT but
has only ever been rendered at 720x720 (square) and 800x480 (landscape); these boards
log a dedicated boot warning for it.

All boards are ESP32-P4NRW32 (32 MB PSRAM), GT911 touch, and carry an ESP32-C6 whose
only control line is its EN pin from a P4 GPIO; both bench units are rev v1.3 dev
silicon. Correction to the original design text: the 7/9/10.1 inch siblings do NOT
"share the electronics" with the 5inch - they are a different layout (C6 EN on GPIO32
not 20, 1-bit SDIO on GPIO14/15/18/19 not 4-bit on 49-54, direct LEDC backlight on
GPIO31 instead of the STC8 path, touch RST on GPIO40 not the GPIO36 strap). See
docs/research/elecrow-board.md section 7.

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
//                 TOUCH_SDA=45, TOUCH_SCL=46, TOUCH_RST=36 (BOOT strap - the
//                 driver's runtime reset pulse is safe and factory-proven; the
//                 strap is only sampled at P4 reset, and the driver leaves the
//                 pin high), TOUCH_INT=42, STC8_ADDR=0x2F
//   elecrow_dsi (7/9/10.1): EK79007 DSI 1024x600, BL_PWM=31 (direct LEDC),
//                 TOUCH_SDA=45, TOUCH_SCL=46, TOUCH_RST=40, TOUCH_INT=42
```

Implementation notes (2026-08-17): `UNTESTED: bool` was added to the surface
(main logs `UNTESTED BOARD CONFIG` for scaffold boards); the surface functions
panic internally on esp_err failures (visible abort over limping); the three
DSI siblings share `board/elecrow_dsi.rs` with per-board `BOARD_NAME` wrappers,
since all three were independently verified identical in every checked item
(research doc section 7).

What is deliberately NOT in the surface: anything cryptographic (notyas-core never
sees a board), the UI (draws on the returned DrawTarget), microSD (0.2.x will add
`sd_init()` when PSBT lands - note the Elecrow slot is 1-bit-only SDMMC, the Waveshare
4-bit; the surface fn hides that), audio and camera (never used).

## Physical access to the microSD slot is a per-board release constraint

Recorded 2026-08-19, because it decides whether a given unit can be USED, not merely
whether it works.

0.2.0 ships SD-only: the camera moved to 0.3.0 (CAMERA.md, decided by the project owner),
so **the microSD slot is the only way a PSBT enters the device**. A slot the owner cannot
reach is therefore not an inconvenience, it is a unit that cannot sign.

- **Waveshare 4B:** the OEM white chassis exposes **two USB-C ports and nothing else**. The
  microSD slot sits behind the backing plate and is unreachable as shipped. Using this
  board for signing requires removing that plate and fitting a replacement that opens the
  slot. `3dp/ESP32-P4-WIFI6-Touch-LCD-4B-2D.zip` holds the vendor 2D drawing set, which is
  the input for that plate. **The printed desk stand in this repo does not solve it
  either**: `3dp/Makerworld-Screen-Stand-4inch+P4+Desk+Stand.3mf` has been printed and
  also leaves the slot unreachable, so the repo currently ships an enclosure asset that is
  incompatible with the only ingress path 0.2.0 has. A custom back plate is required, and
  until one exists this board cannot receive a PSBT in any enclosure we ship or reference.
- **Elecrow CrowPanel 5inch:** accessibility not yet recorded here. Establish it and write
  the answer down rather than leaving it to be rediscovered.

**This constraint runs opposite to the security ranking, and that is the point of writing
it down.** On the airgap the Waveshare is the better board: its C6 EN line has no pullup,
so the radio is held down from power-on. The Elecrow's C6 EN carries a 10K pullup (R77), so
its radio co-processor boots and its stock esp-hosted firmware starts Wi-Fi STA and the BT
controller at every power-up, for the whole window until app_main drives GPIO20 low. The
Waveshare is also the 4-bit SD host, and the only board with a Pi-compatible CSI connector
for 0.3.0's camera.

So the board that is right on every other axis is the one whose only 0.2.0 ingress path is
behind a plate. An enclosure change is what reconciles them, and it should be treated as
part of making this board usable rather than as an accessory.

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

Implementation note (2026-08-17): the full `Layout` struct lands with the real
screens (notyas-ui workstream). The m2 demo shell already follows the rule - a
`ShellLayout` in firmware main.rs derives the card and status-line geometry from
`board::DISPLAY_WIDTH/HEIGHT` as fractions; no screen code hardcodes pixels.

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

Implemented as designed (all five boards have overlays; the elecrow-5 RGB path
needed no extra kconfig options). One addition: `.cargo/config.toml` keeps
`ESP_IDF_SDKCONFIG_DEFAULTS` pointing at the base+waveshare pair (relative,
resolved against the pinned CARGO_WORKSPACE_DIR) so a bare `cargo build` cannot
silently fall back to stock IDF defaults (the rev-v3.x boot-loop trap); building
any non-Waveshare board therefore REQUIRES build.ps1 (firmware/README.md
pitfall 8).

**Stale-artifact hazard:** the IDF build dir bakes in the merged sdkconfig; switching
boards inside one CARGO_TARGET_DIR risks flashing a stale bootloader for the wrong
flash size (flash.ps1's existing warning, squared). Therefore the target dir is
per-board: `C:\nb\ws` and `C:\nb\e5` (short, per the path-length constraint in
build.ps1). Switching boards never requires a clean.

## The airgap invariant, per board (normative)

Every board module MUST document its radio kill mechanism in `RADIO_KILL_DOC`, and
this section is the source of truth. A board whose radio cannot be held dead by
hardware from the P4 does not silently ship: it gets a **WARNING** subsection here and
in its fact sheet, and a documented software-only lockdown fallback (all radio-facing
GPIOs latched to inert states + build-graph exclusion), clearly labeled as the weaker
guarantee on the Verify screen.

**Board choice is part of this invariant, because the boards differ before our code
runs.** Every Waveshare board module below carries a C6-MINI module whose EN has NO
pullup, so its radio is held down from power-on and no window exists. Every Elecrow board
module below pulls C6 EN up, so its C6 boots the factory esp-hosted slave firmware at
every power-up and runs a full WiFi and BT stack until app_main drives the kill line low
(see board-elecrow-5 for what that firmware actually does during the window - it is not
idle). **Of the boards this firmware supports, a Waveshare one is therefore the
airgap-preferred hardware.** The firmware states which case the running board is in at
every boot: info "C6 held down from power-on" on Waveshare, a warn-level power-on window
notice on Elecrow.

**The rule is the C6 part, not the vendor, and it is worth stating that way so nobody
generalizes it wrongly.** A C6-MINI module carries no EN pullup; a bare ESP32-C6FH8 die
does. Two Waveshare P4 boards use the bare chip and therefore DO boot their radio at every
power-on - the Touch-LCD-3.5 (R25) and the WIFI6-DEV-KIT (R78), both in the kill-pin table
in docs/research/waveshare-family.md. Neither has a board module here, and this is part of
why. "Waveshare" is not the guarantee; "C6-MINI module, EN unpulled, schematic-verified in
this file" is.

### board-waveshare-4b

- Kill: **GPIO54 -> C6 CHIP_PU (EN)**, driven low first thing in app_main, never
  released. Hardware-held reset; no esp_hosted/esp_wifi_remote in the build; SDIO
  host never configured on GPIO14-19. (SECURITY.md invariant 1, unchanged.)
- **No power-on window (schematic-verified 2026-08-17):** the 4B schematic's C6 sheet
  shows CHIP_PU carrying only a 1 uF cap (C10) to GND - NO pullup; the nearby 10K
  (R11) is on C6 IO2, not EN, and the ESP32-C6 has no internal EN pullup. The radio is
  therefore held down from power-on and could only ever run if the P4 drove GPIO54
  high, which this firmware never does. Strictly better than the Elecrow boards' verified
  power-on window, during which a full WiFi and BT stack runs on the C6 (board-elecrow-5),
  and the reason a Waveshare unit is the airgap-preferred choice. Source:
  docs/research/waveshare-family.md (the no-pullup EN circuit is common to every
  Waveshare P4 board carrying a C6 module).
  RADIO_KILL_DOC states it; the boot log says "held down from power-on".

### board-elecrow-5

- Kill: **GPIO20 -> C6 CHIP_PU (EN)** through R95 0R, driven low first thing in
  app_main, never released. Verified against schematic AND factory sdkconfig
  (`CONFIG_ESP_HOSTED_SDIO_GPIO_RESET_SLAVE=20`). SDIO host never configured on
  GPIO49-54. Same three-layer story as the Waveshare board.
- **Known power-on window (verified) - and the C6 is NOT idle during it:** C6 EN has a
  10K pullup (R77) to an always-on 3V3 rail, so the C6 boots its factory esp-hosted
  `network_adapter` slave firmware at every power-up and runs until app_main drives
  GPIO20 low (order: hundreds of ms, incl. ROM and bootloader). That firmware's init
  path is unconditional, not a wait for an SDIO host: `esp_hosted_coprocessor.c` calls
  `connect_sta()` inside a `#if 1`, which runs `esp_hosted_wifi_init`,
  `esp_wifi_set_mode(WIFI_MODE_STA)` and `esp_wifi_start()`, and `slave_bt.c` calls
  `esp_bt_controller_init` and `esp_bt_controller_enable` under `CONFIG_BT_ENABLED`.
  **So a WiFi MAC and a BT controller are live inside the case for the whole window at
  every power-on, and a C6 whose NVS holds credentials will attempt to associate.**
  Nothing of the user's can leave: the P4 side has no driver for the SDIO link, and no
  secret exists on the P4 that early in the boot. The exposure is RF presence and MAC
  identifiability, not user data - documented, not hidden. Mitigation candidates for
  release units on this board: **none in firmware** (ROM + bootloader run before us, so
  no build option or boot ordering closes it); the hardware options are removing R77 so
  EN is no longer pulled high - the P4 still holds the line low through R95 - or
  removing the C6 module outright. R77 removal is the recommended prep for a production
  Elecrow unit. **Do not remove R95 alone:** that cuts the kill line while leaving the
  pullup, turning a hundreds-of-ms window into the whole session.
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

### board-elecrow-7 / board-elecrow-9 / board-elecrow-101 (UNTESTED scaffolds)

- Kill: **GPIO32 -> C6 CHIP_PU (EN)**, driven low first thing in app_main, never
  released. Verified against each board's own V1.0 Eagle schematic (net `C6_EN`:
  `U7.GPIO32 -> IC1.EN`, 10K pullup R77) AND each board's factory sdkconfig
  (`CONFIG_ESP_HOSTED_SDIO_GPIO_RESET_SLAVE=32`). Same power-on window as the
  5inch, with the same live WiFi and BT stack running during it (pullup to an
  always-on rail); same warning logged at boot; same R77-removal mitigation. SDIO host
  never configured on GPIO14/15/18/19 (1-bit slot on these boards).
- **UNTESTED**: source-verified only - no such hardware has ever run this
  firmware. The modules carry the banner, the boot log says `UNTESTED BOARD
  CONFIG`, and build.ps1 warns. A physical unit must reproduce the elecrow-5
  verification protocol (lockdown line first, panel, touch, 30 s stable)
  before the status table row can say verified.
- Whether these boards have a wireless-module socket like the 5inch has not
  been surveyed; assume the socket-must-be-empty requirement until the fact
  sheet covers them.

### board-waveshare-5 / -7b / -7x / -8x / -101x (UNTESTED scaffolds)

- Kill: **GPIO54 -> C6 CHIP_PU (EN)**, driven low first thing in app_main, never
  released - the family-invariant circuit, schematic-verified per board in
  docs/research/waveshare-family.md (5: R34; 7B: R33; X series: R54; all 0R).
  Like the 4B and unlike every Elecrow board, C6 EN carries **no pullup** (module
  C6 with 1 uF to GND only), so the radio is held down from power-on - no boot
  window exists. SDIO host never configured on GPIO14-19. The 7B schematic marks
  its C6 block "optional"; a C6-unpopulated factory variant would only improve
  the airgap.
- **UNTESTED**: source-verified only (family schematic survey + the Waveshare BSP
  monorepo @ be0e5e4, re-fetched 2026-08-17 for DPI timings, backlight polarity,
  and panel init tables) - no such hardware has ever run this firmware. The
  modules carry the banner, the boot log says `UNTESTED BOARD CONFIG`, and
  build.ps1 warns. A physical unit must reproduce the 4B verification protocol
  before a status row can say verified.
- **PORTRAIT LAYOUT UNVERIFIED** (5 / 7x / 8x / 101x): first portrait panels in
  the roster (720x1280, 800x1280). The Layout mechanism is resolution-agnostic by
  design, but no portrait rendering has ever been looked at; these boards log an
  extra `PORTRAIT LAYOUT UNVERIFIED` warning at boot and keep the caveat in the
  status table until a portrait unit is verified end to end. (The 7B is 1024x600
  landscape - same aspect class as the verified Elecrow 5inch - so it carries
  only the plain UNTESTED status.)

## Flash size and partition table

Waveshare has 32 MB flash, Elecrow 16 MB. Decision: **one shared partition table,
sized within 16 MB, used by both boards.** Identical layout on both boards means
the app image offset, size accounting, and the Verify screen's running-app SHA256
procedure are board-independent; the extra 16 MB on the Waveshare board is simply
unused. Only `CONFIG_ESPTOOLPY_FLASHSIZE_*` differs (bootloader flash-size header
field), which the per-board sdkconfig overlay owns. If 0.2.x ever wants an
OTA/anti-rollback scheme it must still fit 16 MB, keeping the smallest board the
binding constraint by policy.

The table as 0.2.0 ships it (`firmware/partitions.csv`, handed to espflash
verbatim by `tools/flash.ps1`, so it is repo-pinned rather than an IDF build
artifact). Still no NVS, no otadata, no phy_init, no coredump and no emul_efuse:

| Name | Type | Subtype | Offset | Size | End | Flags |
| --- | --- | --- | --- | --- | --- | --- |
| `factory` | app | factory | `0x10000` | 4 MiB | `0x410000` | |
| `wallets` | data | undefined | `0x410000` | 256 KiB | `0x450000` | `encrypted` |
| `counters` | data | undefined | `0x450000` | 16 KiB | `0x454000` | |
| *(gap)* | | | `0x454000` | 48 KiB | `0x460000` | deliberate, see below |
| `settings` | data | undefined | `0x460000` | 64 KiB | `0x470000` | |

Everything below `0x10000` is silicon-fixed: key manager `0x0-0x2000`,
bootloader `0x2000-0x8000`, partition table `0x8000-0x9000`, gap to `0x10000`.

Free tail after the table: **11.56 MB** of the 16 MB Elecrow-5 and **27.56 MB**
of the 32 MB Waveshare-4b. The 16 MB budget is the only designable one.

`settings` (added in 0.2.0) is the one region that is not the sealing engine's:
two A/B slots of one sector each holding the public values the device must read
BEFORE a PIN - the device name the lock screen draws and the network choice -
plus a 14-sector reserve for a format revision that must not need a table change.
It carries no `encrypted` flag because it must be readable before any key exists.
Its charter and its exclusion list are in `crates/notyas-wallet/src/settings.rs`;
the one-line rule is that a value may live there only if "an attacker sets this to
any value of their choosing" is an acceptable outcome, which is why the wipe
policy, the boot counter, attempts-left and anything about wallet occupancy are
excluded from it by name.

The 48 KiB gap before it is deliberate, and it is the migration story rather than
waste: it leaves the next free offset at the 64 KiB-aligned `0x470000`, which is
where 0.3.0's anti-rollback set (`otadata` + a second app slot - app partitions
must be 64 KiB-aligned, SECUREBOOT.md section 8) can be appended without moving
anything that has shipped. Every addition appends at the aligned tail; no shipped
offset is ever re-derived, so the Verify running-partition procedure and every
superblock-recorded geometry stay valid across the change.

## Build and flash tooling (implemented in tools/build.ps1 + tools/flash.ps1)

`tools/build.ps1` gains a `-Board` parameter (mandatory once a second board module
exists; until then defaults to `waveshare-4b`):

```powershell
param([ValidateSet("waveshare-4b", "elecrow-5")] [string]$Board = "waveshare-4b")

$boardMap = @{
    "waveshare-4b" = @{ Feature = "board-waveshare-4b"; TargetDir = "C:\nb\ws" }
    "elecrow-5"    = @{ Feature = "board-elecrow-5";    TargetDir = "C:\nb\e5" }
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

Implemented as designed, extended to the full roster in build.ps1 (scaffold
target dirs C:\nb\e7 / C:\nb\e9 / C:\nb\e101 / C:\nb\w5 / C:\nb\w7b /
C:\nb\w7x / C:\nb\w8x / C:\nb\w101; scaffolds get a build.ps1 UNTESTED
warning - plus a PORTRAIT warning where it applies). flash.ps1 knows the Elecrow
scaffolds (no default flash port - `-Port` must be passed explicitly) but not
yet the Waveshare ones: extending it is deliberately deferred until a physical
Waveshare scaffold unit exists to flash.

Release packaging (tools, later): build both boards, emit
`notyas-<ver>-<board>.bin` + per-board SHA256 lines into one signed SHA256SUMS.txt.

## TODOs (resolutions 2026-08-17, from the physical elecrow-5 bring-up)

1. **RESOLVED - Elecrow size variant is the 5inch.** User-confirmed panel size,
   then verified live: 800x480 RGB timings drive the panel and GT911 reports at
   the expected wiring. (The 7/9/10.1 turned out NOT to share the electronics -
   see the correction at the top and research doc section 7.)
2. **RESOLVED (2026-08-17) - Waveshare C6 EN has NO pullup: radio off from
   power-on.** The 4B schematic C6 sheet, re-read for the family survey
   (docs/research/waveshare-family.md), shows CHIP_PU with only C10 1 uF to GND;
   the 10K (R11) is on C6 IO2. No power-on window exists on this board - the
   Elecrow-style window is a bare-C6FH8-chip design trait (Waveshare 3.5 /
   WIFI6-DEV-KIT), not a 4B one. See "The airgap invariant, per board".
3. **RESOLVED - Elecrow GT911 address.** The factory sequence is used: the
   esp_lcd_touch_gt911 driver owns RST (GPIO36) and INT (GPIO42) and straps INT
   low during the reset pulse, making the address deterministically 0x5D
   (observed on hardware; 0x14 fallback kept like Elecrow's own lessons).
   Driving the GPIO36 strap at runtime is factory-proven safe: the strap is only
   sampled at P4 reset and the driver leaves the pin high afterwards, so warm
   resets strap correctly. The Waveshare pitfall-7 race cannot occur (INT is
   driven, not floating).
4. **RESOLVED - Elecrow panel timings.** Factory pclk 25 MHz (HPW4/HBP8/HFP8,
   VPW4/VBP16/VFP16) ran stable over repeated 34 s monitored boots with the
   single-framebuffer no-copy path; no driver errors, no underruns logged.
   Visual tearing assessment on real screen flows stays open until animated
   screens exist - if it appears, the Arduino lessons' 18 MHz is the known-good
   fallback.
5. **RESOLVED - STC8 protocol.** Backlight write addr 0x2F reg 0x20 duty 0-100
   ACKs and controls the panel; blanked at display init, 80% after first frame.
   Backlight does NOT work without talking to the STC8 (the MT9201 EN sits on
   an STC8 pin with a pulldown - there is no P4-only path), so the single
   register write stays, as the accepted-risk note above describes.
6. **RESOLVED - Elecrow LDO4/R109 mismatch.** LDO channel 4 acquired at
   3300 mV as the factory firmware does; the GPIO45-54 I2C bank demonstrably
   works (STC8 and GT911 both respond). The schematic's NC marking on R109 does
   not reflect the assembled board; the acquire stays.
