# Research: Waveshare ESP32-P4 board family with displays (2026-08-17)

Agent-produced survey of every Waveshare board built on the ESP32-P4 that has (or
drives) a touchscreen, to plan multi-board support per docs/BOARDS.md. Rigor target is
docs/research/hardware.md (the 4B fact sheet): every radio-kill claim below is either
schematic-verified (schematic PDF downloaded and the C6 section read directly) or
marked UNVERIFIED.

Primary sources:
- Schematics from files.waveshare.com (per board, URLs inline below).
- BSP monorepo github.com/waveshareteam/Waveshare-ESP32-components @ be0e5e4
  (pin defines, panel drivers, touch drivers, IDF requirements read from source).
- Wiki mirror docs.waveshare.com (waveshare.com/wiki 403s plain fetchers).

## 0. Family-wide invariants (all schematic-verified unless noted)

The whole family is one hardware design language. Across every board below:

- SoC: ESP32-P4NRW32 bare chip (32 MB in-package PSRAM) + external QSPI NOR flash
  (exceptions on flash size noted per board). Module-DEV-KIT uses a castellated
  "ESP32-P4_Module" instead (internals unpublished).
- Radio: ESP32-C6 companion as an esp-hosted SDIO slave. On every board where the C6
  wiring is visible, the SAME circuit appears:
  - P4 GPIO54 -> 0R resistor -> C6 CHIP_PU (EN). **GPIO54 is the airgap kill pin
    family-wide.**
  - P4 GPIO6 -> 0R -> C6 IO2 (aux/bootstrap line, 10K pullup to 3V3).
  - SDIO: CLK = GPIO18, CMD = GPIO19, D0-D3 = GPIO14-17 (51K pullups). Same map as
    the 4B and Espressif's Function-EV board.
  - 4-pin C6 UART flashing header/pads (C6 U0TXD/U0RXD/IO9/GND).
- **C6 EN default state - the power-on-window question (resolves BOARDS.md TODO 2):**
  two sub-designs exist:
  - Boards with a C6 **module** (ESP32-C6-MINI-1-N4 or -1U-H8): CHIP_PU carries only
    a 1 uF cap to GND, **no pullup** (the nearby 10K goes to C6 IO2, not EN). The
    ESP32-C6 has no internal EN pullup, so **the radio is held down from power-on**
    until the P4 actively drives GPIO54 high - which our firmware never does. This is
    the 4B, 3.4C/4C, 4.3, 5, 7B, 7/8/10.1 and NANO. Verified in each schematic's C6
    sheet. This is strictly better than the Elecrow board's verified power-on window.
  - Boards with a **bare ESP32-C6FH8 chip**: CHIP_PU has a **10K pullup to 3V3**
    (plus 1 uF), so the C6 boots its firmware at every power-up until app_main drives
    GPIO54 low - an Elecrow-style power-on window. This is the 3.5 and the
    WIFI6-DEV-KIT.
- Shared I2C bus: SDA = GPIO7, SCL = GPIO8 (touch + codec, 100/400 kHz).
- Audio: ES8311 codec (+ ES7210 4-ch echo-cancel ADC on the larger boards), PA enable
  GPIO53. Never used by notyas.
- USB-UART bridge: **CH343P on every board** (all schematics), with the classic
  two-transistor auto-download circuit; BOOT = GPIO35, RESET = ESP_EN.
- BSPs: components `waveshare/esp32_p4_wifi6_touch_lcd_{3_5,4b,5,7b,x,xc}` and
  `waveshare/esp32_p4_nano` in the monorepo; examples repo
  github.com/waveshareteam/ESP32-P4-Platform (board-check ... system-monitor, needs
  IDF release/v5.4+ and per-silicon-revision overlay configs, see
  ESP32P4_REVISION_CONFIG.md there).
- Silicon revision hazard (from hardware.md, applies family-wide): pre-v3.0 and v3.x
  P4 chips are not binary compatible. Newer SKUs/batches (esp. the 4.3 and 2026
  stock) may ship v3.x; check each physical unit before picking the sdkconfig
  revision pin. UNVERIFIED per board until a unit is probed.
- No IO expander on any Touch-LCD board (everything on direct P4 GPIOs). The NANO
  family drives display power/backlight through an MCU at I2C 0x45 that lives on the
  DSI display adapter, not on the board - see NANO section.

## 1. ESP32-P4-WIFI6-Touch-LCD-4B (ours) / ESP32-P4-86-Panel-ETH-2RO

Fully documented in docs/research/hardware.md and docs/HARDWARE.md; listed here for
family completeness.

- SKU 31416 (4B), 31570 (86-Panel-ETH-2RO). **Same PCB**; the 86-Panel adds a bottom
  board (IP101 Ethernet PHY, RS485, 2 relays, 6-30 V input) and drops the CSI
  connector's camera role. Wiki: waveshare.com/wiki/ESP32-P4-WIFI6-Touch-LCD-4B
  (redirects to the 86-Panel-ETH-2RO title).
- Display: 4 inch 720x720 IPS, ST7703, 2-lane MIPI-DSI DPI mode, component
  `waveshare/esp_lcd_st7703`. LCD RESET GPIO27; backlight AP3032 boost, EN GPIO33,
  LEDC PWM GPIO26.
- Touch: GT911, I2C 7/8, RST GPIO23, INT NOT routed (test point TP2; polled).
- Radio kill: GPIO54 -> R34 0R -> C6 CHIP_PU (ESP32-C6-MINI-1U-H8). **New finding
  from this survey (4B schematic C6 sheet re-read): CHIP_PU has NO pullup - only C10
  1 uF to GND; the 10K (R11) is on C6 IO2.** The 4B C6 does not boot at power-on;
  BOARDS.md TODO 2 can be closed with "held down from power-on".
- Flash 32 MB (GD25Q256-class), PSRAM 32 MB. CH343P. No IO expander.
- BSP `waveshare/esp32_p4_wifi6_touch_lcd_4b` 3.0.0, idf >= 5.5.
- Tier: A (already shipped as `board-waveshare-4b`). 86-Panel-ETH-2RO: the same
  firmware image runs unchanged (extras live on the bottom board and are never
  initialized); support = the 4B feature + a documented physical caveat (Ethernet
  jack, relays, RS485 present; wired ETH is not a radio, RMII never configured).

## 2. ESP32-P4-WIFI6-Touch-LCD-4C and 3.4C (round, "XC" pair)

- SKU 31522 (4C, 4 inch round 720x720), 31523 (3.4C, 3.4 inch round 800x800). Two
  products, **one PCB/wiki/BSP family "XC"** (one schematic covers both; only the
  panel differs). Wiki: waveshare.com/wiki/ESP32-P4-WIFI6-Touch-LCD-4C and -3.4C;
  docs.waveshare.com/ESP32-P4-WIFI6-Touch-LCD-XC.
  Schematic: files.waveshare.com/wiki/ESP32-P4-WIFI6-Touch-LCD-XC/ESP32-P4-WIFI6-Touch-LCD-XC-Schematic.pdf
- Display: round IPS, controller **JD9365**, 2-lane MIPI-DSI, 1500 Mbps/lane, driver
  `esp_lcd_jd9365` (`esp_lcd_new_panel_jd9365`); BSP resolutions 800x800 (3.4C) /
  720x720 (4C). LCD RESET GPIO27 (0R), backlight AP3032 with BL_EN GPIO33 (0R) +
  LEDC PWM GPIO26 (BSP `BSP_LCD_BACKLIGHT = 26`). Same DPHY LDO dance as the 4B
  (ch3 2500 mV).
- Touch: GT911 (`esp_lcd_touch_new_i2c_gt911`), I2C 7/8; schematic shows GPIO23 ->
  0R -> TP_RST and a TP_INT net ending at a test point; BSP sets RST and INT =
  GPIO_NUM_NC (polled), matching the 4B pattern.
- Radio: ESP32-C6-MINI-1-N4 (4 MB, PCB antenna). Kill = **GPIO54 -> R54 0R ->
  C6_CHIP_PU, schematic-verified; no EN pullup (C6 off at power-on)**. GPIO6 -> R52
  -> C6 IO2.
- P4NRW32, 32 MB flash (GD25Q256EYIGR), CH343P, no expander. Schematic contains an
  IP101 Ethernet PHY block; product page lists no Ethernet - population UNVERIFIED,
  not airgap-relevant (not a radio; RMII never configured).
- BSP `waveshare/esp32_p4_wifi6_touch_lcd_xc` 3.0.1, idf >= 5.5; demo zip
  ESP32-P4-WIFI6-Touch-LCD-XC-Demo.zip; ESP32-P4-Platform examples.
- Tier: **B** - electrically as well-documented as the 4B and the kill story is
  identical, but the **round panel** means every rectangular screen layout (cards,
  keypad, QR) needs a circular-safe-area variant. QR display on a circle wastes
  ~29% of the diameter; usable but needs real UI work.

## 3. ESP32-P4-WIFI6-Touch-LCD-4.3

- SKU 33874, 33875 (with OV5647 camera). New for 2026; wiki:
  docs.waveshare.com/ESP32-P4-WIFI6-Touch-LCD-4.3. Schematic:
  files.waveshare.com/wiki/ESP32-P4-WIFI6-Touch-LCD-4.3/ESP32-P4-WIFI6-Touch-LCD-4.3-schematic.pdf
- Display: 4.3 inch 480x800 IPS, 2-lane MIPI-DSI. **Panel controller IC not named**
  in schematic text or wiki; no board BSP exists yet in the waveshareteam monorepo
  (the NANO Kconfig's "4inch DSI LCD 480x800, rev 3.x only" entry suggests the same
  panel exists as a NANO kit). Backlight AP3032, BL_EN + LCD_BL_PWM GPIO26; LCD
  reset GPIO27 pattern present. UNVERIFIED: exact panel init table.
- Touch: capacitive on-panel; TP_RST = GPIO23, TP_INT net present. **Touch
  controller IC UNVERIFIED** (siblings use GT911; not confirmed here).
- Radio: ESP32-C6-MINI-1-N4. Kill = **GPIO54 -> R34 0R -> C6_CHIP_PU,
  schematic-verified; no EN pullup (C6 off at power-on)**. GPIO6 -> R33 -> C6 IO2.
- 32 MB flash (GD25Q256EYIGR), CH343P. "rev 3.x only" note on the matching NANO
  panel entry hints this board ships v3.x P4 silicon - would need the other
  revision overlay than our dev units. UNVERIFIED.
- Tier: **C for now** - kill pin verified, but the display+touch stack is
  undocumented (no BSP, no named panel/touch IC). Revisit when Waveshare publishes
  the BSP; likely promotes straight to A (portrait 480x800, rectangular).

## 4. ESP32-P4-WIFI6-Touch-LCD-5

- SKU not captured from the store page (page 403s fetchers; price ~$71-73). Wiki:
  docs.waveshare.com/ESP32-P4-WIFI6-Touch-LCD-5; product
  waveshare.com/esp32-p4-wifi6-touch-lcd-5.htm. Schematic:
  files.waveshare.com/wiki/ESP32-P4-WIFI6-Touch-LCD-5/ESP32-P4-WIFI6-Touch-LCD-5-Schematic.pdf
- Display: 5 inch 720x1280 IPS, controller **HX8394**, 2-lane MIPI-DSI at 700
  Mbps/lane, driver `waveshare/esp_lcd_hx8394` ^2.1.0. LCD RESET GPIO27, backlight
  LEDC PWM GPIO26.
- Touch: GT911, I2C 7/8, BSP RST/INT = NC (polled), addresses 0x5D/0x14 as usual.
- Radio: ESP32-C6-MINI-1-N4. Kill = **GPIO54 -> R34 0R -> C6_CHIP_PU,
  schematic-verified; no EN pullup (C6 off at power-on)**. GPIO6 -> R33 -> C6 IO2.
- P4NRW32, 32 MB flash (GD25Q256EYIGR), CH343P, ES8311+ES7210, no expander.
- BSP `waveshare/esp32_p4_wifi6_touch_lcd_5` 1.0.3, **idf >= 5.4** (only this and
  the 3.5 accept 5.4; BSP pins lvgl 9.5.0 - irrelevant to us).
- Tier: **A** - everything documented: panel driver component, GT911, verified kill
  pin, 32 MB flash, portrait 720x1280 rectangular panel (aspect class "portrait"
  for the Layout mechanism; taller than wide is new vs 720x720 but the BOARDS.md
  grid rule handles it).

## 5. ESP32-P4-WIFI6-Touch-LCD-7B

- SKU 32510, 32511 (with OV5647). Wiki: docs.waveshare.com/ESP32-P4-WIFI6-Touch-LCD-7B.
  Schematic: files.waveshare.com/wiki/ESP32-P4-WIFI6-Touch-LCD-7B/ESP32-P4-WIFI6-Touch-LCD-7B.pdf
- Display: 7 inch 1024x600 landscape IPS, controller **EK79007**, 2-lane MIPI-DSI at
  1000 Mbps/lane, driver `esp_lcd_ek79007` (^2.0.2). **LCD RESET = GPIO33, backlight
  = LEDC PWM GPIO32** (7B differs from siblings here). USB OTG on a Type-A jack;
  CAN/RS485/I2C headers; RTC battery holder.
- Touch: GT911, I2C 7/8, BSP RST/INT = NC (polled).
- Radio: ESP32-C6-MINI-1-N4. Kill = **GPIO54 -> R33 0R -> C6_CHIP_PU,
  schematic-verified; no EN pullup (C6 off at power-on)**. GPIO6 -> R31 -> C6 IO2.
  Note: the schematic's C6 block is annotated "optional" (Chinese) - a
  C6-unpopulated factory variant may exist; airgap only improves if so. UNVERIFIED
  which SKUs populate it (product name says WIFI6, assume populated).
- P4NRW32, 32 MB flash (GD25Q256EYIGR), CH343P, ES8311+ES7210. IP101 PHY block in
  schematic, Ethernet not on the product spec - population UNVERIFIED, not
  airgap-relevant.
- BSP `waveshare/esp32_p4_wifi6_touch_lcd_7b` 3.0.0, idf >= 5.5.
- Tier: **A** - fully documented, verified kill, 1024x600 landscape (same aspect
  class as the Elecrow 800x480, so the landscape Layout variant is exercised).

## 6. ESP32-P4-WIFI6-Touch-LCD-7 / -8 / -10.1 ("X" series)

- Three products, **one PCB/wiki/BSP family "X"** (one schematic; only panel
  differs): 7 inch (SKU 30738 / 33147), 8 inch (33673 / 33149), 10.1 inch
  (33672 / 33150) - each pair standard / camera bundle, exact pairing UNVERIFIED.
  Wiki: docs.waveshare.com/ESP32-P4-WIFI6-Touch-LCD-X; product
  waveshare.com/esp32-p4-wifi6-touch-lcd-7-8-10.1.htm ("HMI all-in-one"). Schematic:
  files.waveshare.com/wiki/ESP32-P4-WIFI6-Touch-LCD-X/ESP32-P4-WIFI6-Touch-LCD-X-Schematic.pdf
- Display: 2-lane MIPI-DSI portrait panels, 10-point touch, per size:
  - 7 inch: 720x1280, **ILI9881C**, 1000 Mbps/lane (`waveshare/esp_lcd_ili9881c`).
  - 8 inch: 800x1280, **JD9365**, 1500 Mbps/lane (`esp_lcd_jd9365`).
  - 10.1 inch: 800x1280, **JD9365**, 1500 Mbps/lane.
  LCD RESET GPIO27, backlight LEDC PWM GPIO26. Panel selected by Kconfig
  (`BSP_LCD_TYPE_*`) - for notyas each size is its own board feature (the build IS
  the board; no runtime probing).
- Touch: GT911, I2C 7/8, BSP RST/INT = NC (polled).
- Radio: ESP32-C6-MINI-**1U-H8** (8 MB, IPEX antenna - like the 4B). Kill =
  **GPIO54 -> R54 0R -> C6_CHIP_PU, schematic-verified; no EN pullup (C6 off at
  power-on)**. GPIO6 -> R52 -> C6 IO2.
- P4NRW32, 32 MB flash (GD25Q256EYIGR), CH343P, ES8311+ES7210, speaker.
- BSP `waveshare/esp32_p4_wifi6_touch_lcd_x` 2.0.2, idf >= 5.5.
- Tier: **A** (all three sizes) - fully documented, verified kill. 10.1 at 800x1280
  is the largest sensible signer display; note 1500 Mbps/lane DSI is the top of the
  P4's range (BSP-proven, fine).

## 7. ESP32-P4-WIFI6-Touch-LCD-3.5

- SKU 33360 / 33511. Wiki: docs.waveshare.com/ESP32-P4-WIFI6-Touch-LCD-3.5.
  Schematic (in the board's own GitHub repo, not files.waveshare.com):
  raw.githubusercontent.com/waveshareteam/ESP32-P4-WIFI6-Touch-LCD-3.5/main/schematic/ESP32-P4-WIFI6-Touch-LCD-3.5-schematic.pdf
- Display: 3.5 inch 320x480 IPS, **ST7796 over SPI** (the only non-DSI board):
  MOSI GPIO20, CLK GPIO21, CS GPIO23, DC GPIO26, RESET GPIO27; backlight LEDC PWM
  GPIO28. Driver `espressif/esp_lcd_st7796` ^1. No DSI, so no DPHY LDO ch3 dance.
- Touch: **FT6336** (FT5x06 family), driver `espressif/esp_lcd_touch_ft5x06`, I2C
  7/8, **RST GPIO29, INT GPIO50 - both routed** (only family member with INT).
- Radio: **bare ESP32-C6FH8 chip** (not a module), PCB antenna + IPEX option. Kill =
  **GPIO54 -> R54 0R -> CHIP_PU, schematic-verified** - BUT **CHIP_PU has a 10K
  pullup (R25) to 3V3: the C6 boots at every power-on** and runs until app_main
  drives GPIO54 low. Same weaker guarantee as board-elecrow-5 (documented power-on
  window; C6 slave firmware joins no network on its own). GPIO6 -> R52 -> C6 IO2;
  SDIO CLK 18 / CMD 19 / D0-D3 14-17 wired to the bare chip's fixed SDIO pins.
- P4NRW32, **16 MB flash** (XM25QH128) - fits the shared 16 MB partition table
  policy. CH343P, ES8311 (no ES7210).
- BSP `waveshare/esp32_p4_wifi6_touch_lcd_3_5` 2.0.0, idf >= 5.4; dedicated repo
  waveshareteam/ESP32-P4-WIFI6-Touch-LCD-3.5 (schematic + firmware + examples).
- Tier: **B** - everything documented (only board with routed touch INT), but:
  320x480 is cramped for QR + verification text (QR modules get small; usable,
  needs layout care), SPI display path is a new display_init flavor, and the
  power-on radio window must be documented on the Verify screen like the Elecrow.

## 8. ESP32-P4-NANO (+ DSI display kits) and ESP32-P4-WIFI6-DEV-KIT

ESP32-P4-NANO:
- SKU 29026 bare; kit bundles 29027-29031 (display/camera kits A-D). Wiki:
  docs.waveshare.com/ESP32-P4-NANO. Schematic:
  files.waveshare.com/wiki/ESP32-P4-NANO/ESP32-P4-NANO-schematic.pdf
- No onboard display: 15-pin RPi-style 2-lane DSI connector; BSP supports 16 panel
  Kconfig choices (2.8 inch 480x640 ... 10.1 inch 800x1280; JD9365 / ILI9881C /
  HX8394 / generic esp_lcd_dsi; several marked "ESP32-P4 rev 3.x only"). Touch
  GT911 (I2C 7/8, RST/INT NC) on the DSI-TOUCH displays.
- **Backlight/panel power goes through an MCU at I2C 0x45 on the display adapter**
  (register 0x86 / 0x96 / 0xab by panel generation; BSP writes duty bytes to it).
  This is the "expander at 0x45" from ESP32_Display_Panel issue 205 - it is on the
  display, not the NANO. Unpublished firmware in the touch path (same class of
  accepted risk as the Elecrow STC8, but here it also gates panel power).
- Radio: ESP32-C6-MINI-1-N4. Kill = **GPIO54 -> R54 0R -> C6_CHIP_PU,
  schematic-verified; no EN pullup (C6 off at power-on)**. GPIO6 -> R52 -> C6 IO2.
- P4NRW32, **16 MB flash** (GD25Q128ESIG), CH343P, IP101 Ethernet (PoE variant),
  ES8311. BSP `waveshare/esp32_p4_nano` 3.0.0, idf >= 5.5.
- Tier: **C** - kill pin verified, but it is not a sealed appliance: the display is
  a user-attachable kit (open configuration matrix contradicts "the build IS the
  board"), panel power and backlight depend on an unverifiable display-side MCU,
  and it brings Ethernet + a bare-headers form factor. If a fixed NANO+panel bundle
  is ever wanted, it would be `board-waveshare-nano-<kit>` with one pinned panel.

ESP32-P4-WIFI6-DEV-KIT:
- SKUs 32054-32057. Wiki: waveshare.com/wiki/ESP32-P4-WIFI6-DEV-KIT (schematic:
  files.waveshare.com/wiki/ESP32-P4-WIFI6-DEV-KIT/ESP32-P4-WIFI6-DEV-KIT-datasheet.pdf
  - despite the name this PDF is the schematic). NANO-adjacent dev board: 2x20
  headers, RJ45, 2-lane DSI connector, no onboard display.
- Radio: **bare ESP32-C6FH8** with **10K pullup (R76) on CHIP_PU** - boots at
  power-on; kill = GPIO54 -> R78 0R -> CHIP_PU, schematic-verified. 16 MB flash
  (W25Q128JVSIQ), CH343P.
- Tier: **C** - no onboard display + power-on radio window + headers form factor.

## 9. ESP32-P4-Module-DEV-KIT (A/B/C)

- Product waveshare.com/esp32-p4-module-dev-kit.htm; wiki
  docs.waveshare.com/ESP32-P4-Module-DEV-KIT. Variants: base, -A (no display),
  -B (7 inch DSI kit + camera), -C (10.1 inch DSI kit + camera). Carrier schematic:
  files.waveshare.com/wiki/ESP32-P4-Module-DEV-KIT/ESP32-P4-Module-DEV-KIT.pdf
- Built on a castellated **"ESP32-P4_Module"** that integrates the P4 AND the C6
  (module exposes C6_U0RXD/TXD, C6_IO4-IO15, LNA_OUT antenna feed). **No module
  schematic is published.**
- **RADIO KILL FLAG: the module does NOT expose the C6's CHIP_PU/EN** (the module's
  "CHIP_PU" pin is the P4's own EN, wired to the reset button), and P4 GPIO54 is
  routed to the 40-pin RPi header as a plain GPIO - so unlike every other family
  member it is NOT the C6 enable here. Unless the unpublished module internals
  strap C6 EN to a P4 GPIO (nothing suggests they do), **the P4 cannot hold the C6
  dead on this board.** UNVERIFIED internals; treat as radio-not-killable until a
  module schematic proves otherwise.
- Displays are the same RPi-style DSI kits as the NANO (third-party BSP
  cfscn/esp32_p4_module_dev_kit; FT3236/FT6X36 or GT911 touch depending on kit;
  brightness via the display-side 0x45 MCU). CH343P, RJ45 with PoE (HBJ-6117ANL).
- Tier: **C - cannot be supported.** No onboard display, open display matrix, and
  above all no verified hardware radio kill. This is the one family member where
  the airgap invariant (SECURITY.md invariant 1) cannot currently be satisfied by
  hardware; a software-only lockdown would be the weaker fallback and is not worth
  it for a headers-and-carrier dev kit.

## Kill-pin table (the airgap column)

| Board | C6 part | Kill pin (P4 -> C6 EN) | EN pullup / power-on state | Verified |
|---|---|---|---|---|
| Touch-LCD-4B / 86-Panel-ETH-2RO | C6-MINI-1U-H8 module | GPIO54 -> R34 0R | none, 1 uF cap - OFF at power-on | schematic |
| Touch-LCD-3.4C / 4C (XC) | C6-MINI-1-N4 module | GPIO54 -> R54 0R | none - OFF at power-on | schematic |
| Touch-LCD-4.3 | C6-MINI-1-N4 module | GPIO54 -> R34 0R | none - OFF at power-on | schematic |
| Touch-LCD-5 | C6-MINI-1-N4 module | GPIO54 -> R34 0R | none - OFF at power-on | schematic |
| Touch-LCD-7B | C6-MINI-1-N4 module | GPIO54 -> R33 0R | none - OFF at power-on | schematic |
| Touch-LCD-7 / 8 / 10.1 (X) | C6-MINI-1U-H8 module | GPIO54 -> R54 0R | none - OFF at power-on | schematic |
| Touch-LCD-3.5 | bare C6FH8 chip | GPIO54 -> R54 0R | **10K pullup - radio BOOTS at power-on** | schematic |
| ESP32-P4-NANO | C6-MINI-1-N4 module | GPIO54 -> R54 0R | none - OFF at power-on | schematic |
| WIFI6-DEV-KIT | bare C6FH8 chip | GPIO54 -> R78 0R | **10K pullup - radio BOOTS at power-on** | schematic |
| Module-DEV-KIT | inside ESP32-P4_Module | **NONE EXPOSED - GPIO54 is a header GPIO here** | unknown (module internals unpublished) | **UNVERIFIED - assume NOT killable** |

Boards that cannot (or should not) be supported, and why:
- **ESP32-P4-Module-DEV-KIT**: radio cannot be held dead from the P4 (C6 EN buried
  in an unpublished module); also no onboard display.
- **ESP32-P4-NANO / WIFI6-DEV-KIT**: no fixed display (open kit matrix breaks the
  one-build-one-board rule); WIFI6-DEV-KIT additionally has the power-on radio
  window and no display at all.
- **Touch-LCD-4.3**: supportable in principle (kill verified) but display/touch
  stack undocumented today - park until the BSP lands.

## Summary table and proposed board feature names

Naming per BOARDS.md convention (`board-waveshare-<suffix>`, dots become dashes):

| Feature name | Board | Display | Panel driver | Touch | Flash | Kill | Tier |
|---|---|---|---|---|---|---|---|
| `board-waveshare-4b` | Touch-LCD-4B / 86-Panel | 720x720 4in DSI | esp_lcd_st7703 | GT911 poll | 32 MB | GPIO54 | A (shipped) |
| `board-waveshare-5` | Touch-LCD-5 | 720x1280 5in DSI | esp_lcd_hx8394 | GT911 poll | 32 MB | GPIO54 | A |
| `board-waveshare-7b` | Touch-LCD-7B | 1024x600 7in DSI | esp_lcd_ek79007 | GT911 poll | 32 MB | GPIO54 | A |
| `board-waveshare-7` | Touch-LCD-7 (X) | 720x1280 7in DSI | esp_lcd_ili9881c | GT911 poll | 32 MB | GPIO54 | A |
| `board-waveshare-8` | Touch-LCD-8 (X) | 800x1280 8in DSI | esp_lcd_jd9365 | GT911 poll | 32 MB | GPIO54 | A |
| `board-waveshare-10-1` | Touch-LCD-10.1 (X) | 800x1280 10.1in DSI | esp_lcd_jd9365 | GT911 poll | 32 MB | GPIO54 | A |
| `board-waveshare-4c` | Touch-LCD-4C | 720x720 round DSI | esp_lcd_jd9365 | GT911 poll | 32 MB | GPIO54 | B (round UI) |
| `board-waveshare-3-4c` | Touch-LCD-3.4C | 800x800 round DSI | esp_lcd_jd9365 | GT911 poll | 32 MB | GPIO54 | B (round UI) |
| `board-waveshare-3-5` | Touch-LCD-3.5 | 320x480 3.5in SPI | esp_lcd_st7796 | FT6336 INT50 | 16 MB | GPIO54 (window!) | B (small; radio window) |
| `board-waveshare-4-3` | Touch-LCD-4.3 | 480x800 4.3in DSI | UNVERIFIED | UNVERIFIED | 32 MB | GPIO54 | C (undocumented, revisit) |
| (none) | ESP32-P4-NANO + kits | kit-dependent | various | GT911 | 16 MB | GPIO54 | C (open kit matrix) |
| (none) | WIFI6-DEV-KIT | none onboard | - | - | 16 MB | GPIO54 (window) | C (no display) |
| (none) | Module-DEV-KIT A/B/C | kit-dependent | various | FT3236/GT911 | module | **not killable (UNVERIFIED)** | C (no hw kill) |

sdkconfig notes per supported candidate: all tier A/B boards except 3.5 take
`CONFIG_ESPTOOLPY_FLASHSIZE_32MB`; 3.5 takes 16 MB (already the partition-table
policy ceiling). All keep the shared base config; silicon-revision pin must be
confirmed per physical unit before first flash (v3.x suspected on newest SKUs).
DSI boards need the LDO ch3 (2500 mV) + ch4 dance; the 3.5 (SPI) skips ch3.
