# Research: Elecrow CrowPanel Advanced 5inch ESP32-P4 hardware (2026-08-17)

Agent-produced report, verified against the official Eagle schematic (V1.0, read and
machine-parsed directly) and Elecrow's factory ESP-IDF source + sdkconfig. Facts that
could NOT be verified against schematic or factory source are marked **UNVERIFIED**
inline; everything else traces to those two ground truths.

**Identification status:** the unknown COM6 board matches the CrowPanel Advanced
(ESP32-P4) *family* exactly - CH340K bridge (VID 1A86 PID 7522, Elecrow wiki names the
CH340K for UART0), ESP32-P4 rev v1.3 dual core + LP core 400 MHz, 40 MHz crystal, 16 MB
flash. Waveshare P4 boards use CH343 (different PID) and Espressif's Function-EV board
has no CH340K, so those are excluded. **Size variant RESOLVED (2026-08-17): it is the
5inch.** User-confirmed panel size, then proven live: notyas `board-elecrow-5` drives
the panel with the 5inch 800x480 RGB config and the GT911/STC8 respond at the 5inch
wiring (see "Bring-up results" below). Correction to this report's original claim:
the 7/9/10.1 siblings do NOT share identical electronics - see section 7.

Probe cross-check on flash: schematic specifies Winbond W25Q128JVSIQ; the probed unit
reports GigaDevice c8/4018 = GD25Q128 - same 16 MB capacity, a production vendor swap.
**UNVERIFIED by Elecrow docs** (consistent with, but not documented).

**Naming note:** Elecrow spells it "Advanced" on the wiki and "Advance" in code/readme;
the GitHub repo name starts with a stray hyphen. Product page SKU family DHE04005D.
Naming trap: Elecrow's "CrowPanel Advance" (ESP32-S3, e.g. Advance 5.0/7.0 800x480) is
a different, older family than "CrowPanel Advanced" (ESP32-P4).
Sources:
https://www.elecrow.com/wiki/CrowPanel_Advanced_5inch_ESP32-P4_HMI_AI_Display_800x480_IPS_Touch_Screen_with_WiFi_6.html ,
https://www.elecrow.com/crowpanel-advanced-5inch-esp32-p4-hmi-ai-display-800x480-ips-touch-screen-with-wifi-6.html

Schematic (1-page PDF + Eagle .sch/.brd):
https://github.com/Elecrow-RD/-CrowPanel-Advanced-5inch-ESP32-P4-HMI-AI-Display-800x480-IPS-Touch-Screen/tree/master/Eagle_SCH%26PCB/1.0

## 1. Core hardware

- SoC: **ESP32-P4NRW32** bare chip (U7), 32 MB in-package PSRAM; QSPI 16 MB NOR flash
  (IC4). 40 MHz main crystal (Y2), 32.768 kHz RTC crystal (Y4) on GPIO0/1.
  (schematic; repo readme)
- LCD: 5.0" IPS, **800x480**, **16-bit parallel RGB565 (DE mode)** on the P4's RGB LCD
  peripheral - **NOT MIPI-DSI**. The DSI pins are unconnected. The panel is a dumb
  RGB-TTL glass on a 40-pin FPC (footprint "CROWPANEL_ADVICE_HMI-4.3 40PIN"); there is
  **no init sequence, no panel controller commands, no LCD reset** (`LCD_GPIO_RST =
  -1`). **UNVERIFIED: the glass's integrated driver IC** is not named anywhere in wiki,
  schematic, or code.
- Init source: plain ESP-IDF **`esp_lcd_new_rgb_panel()`** (`esp_lcd_panel_rgb.h`), no
  vendor esp_lcd component. Factory config: pclk **25 MHz** (Arduino lessons use
  18 MHz, ~42 Hz), HPW 4 / HBP 8 / HFP 8, VPW 4 / VBP 16 / VFP 16, `num_fbs = 2` in
  PSRAM, optional bounce buffer 20 lines. (factory `peripheral/bsp_display/`; Arduino
  `board_config.h`)
- RGB pin map (schematic + code agree): **DE = GPIO2, PCLK = GPIO3, HSYNC = GPIO40,
  VSYNC = GPIO41**; DATA0-4 (blue B3-B7) = GPIO8,7,6,5,4; DATA5-10 (green G2-G7) =
  GPIO14,13,12,11,10,9; DATA11-15 (red R3-R7) = GPIO19,18,17,16,15. Only 16 of the
  FPC's 24 data pads are wired (lower bits of each color grounded).
- Backlight: MT9201 boost LED driver (U6) -> panel LEDA/LEDK. **The P4 has no
  backlight pin.** Brightness = PWM from the **STC8 co-MCU** pin P1.1 into MT9201 EN
  (R72 0R, 10K pulldown). Set over I2C: **addr 0x2F, reg 0x20, duty 0-100**
  (`stc8_set_pwm_duty(STC8_PWM_LCD_BL_EN, n)`). A separate backlight-power P-FET (Q11
  AO3401, STC8 P3.7) is marked NC on the V1.0 schematic although the STC8 register
  (SET_GPIO idx 3) exists.
- Touch: **GT911** on a 6-pin FPC (FPC2: 1 = SCL, 2 = SDA, 3 = INT, 5 = 3V3, 6 = RST).
  I2C1 **SDA = GPIO45, SCL = GPIO46** (4.7K pullups; BSS138 pair level-shifts to a 3V3
  branch for external connectors). **INT = GPIO42** (direct, usable). **RST = GPIO36**
  via R111 0R - note GPIO36 is also the DOWNLOAD_BOOT strap (10K pullup R106; 27K
  pulldown R74 on the panel side). Alternate STC8-driven reset route (P1.2, R122) is
  NC. Address 0x5D or 0x14; driver `espressif/esp_lcd_touch_gt911`.
- STC8 co-MCU (the board's "IO expander"): **STC8H1K17-36I** (U14), I2C slave at
  **0x2F** on the GPIO45/46 bus. Register map (from `bsp_stc8h1kxx.h` and
  `Micropython/stc8h1kxx.py`): 0x00 battery info struct {adc_mV u32, bat_mV u32,
  level% u8, bat_state u8, led_state u8}; 0x10+n get GPIO in (0 = SPI/UART switch
  position); 0x18+n set GPIO out (0 = TP_RST [NC on V1.0], 1 = CSI_RST, 2 = AUDIO_SD
  amp enable, 3 = LCD_BL_POWER [NC]); 0x20 backlight PWM duty. STC8 NRST is tied to
  the P4 reset rail (R192 0R) so the RESET button resets both. STC8 programming pads
  J8 (pogo, STC8_TXD/RXD). The STC8 runs Elecrow factory firmware; source is not
  published - **the STC8 firmware itself is unverifiable**.
- Internal LDOs (factory `main.c` `Init()`): acquires **channel 3 at 2500 mV** (feeds
  VDD_MIPI_DPHY via R80 0R - needed for the MIPI-CSI camera, not the display) and
  **channel 4 at 3300 mV** before anything else. LDO2 -> VDDPST (pin 59) via R40 0R.
  Caution: the schematic marks R109 (LDO4 -> VDDPST_5, the GPIO45-54 bank rail that
  also carries the I2C pullups) as NC, yet firmware acquires LDO4 -
  schematic/firmware mismatch; keep the LDO4 acquire.

## 2. WiFi/BT: ESP32-C6 companion

- Module: **ESP32-C6-MINI-1-N4** (IC1, 4 MB flash, PCB antenna). SDIO slave running
  **esp-hosted**; ships pre-flashed (slave firmware `network_adapter.bin` V2.12.3,
  2026-04-08, shipped in the repo with flashing + OTA guides).
- SDIO wiring (schematic, confirmed bit-for-bit by factory sdkconfig
  `CONFIG_ESP_HOSTED_PRIV_SDIO_PIN_*_SLOT_1`); all six lines have 51K pullups to the
  C6 3V3:

| Signal | P4 GPIO | C6 pin |
|---|---|---|
| SDIO CMD | GPIO54 | IO18 |
| SDIO CLK | GPIO53 | IO19 |
| SDIO D0 | GPIO52 | IO20 |
| SDIO D1 | GPIO51 | IO21 |
| SDIO D2 | GPIO50 | IO22 |
| SDIO D3 | GPIO49 | IO23 |

- **Radio kill pin: P4 GPIO20 -> C6 EN (CHIP_PU) through R95 0R**, with a 10K pullup
  (R77) to the C6's 3V3, which itself comes from the always-on VDD_3V3 via R76 0R -
  **the C6 defaults ON at power-up and its power rail is not switchable**. Driving
  GPIO20 low holds the C6 dead (in reset) indefinitely from the P4 - this is the only
  control line, and it is exactly what esp-hosted uses
  (`CONFIG_ESP_HOSTED_SDIO_GPIO_RESET_SLAVE=20`, 4-bit, 40 MHz, slot 1). Note:
  espboards.dev claims "reset IO32" - that is wrong (IO32 is the wireless-socket RST);
  schematic and sdkconfig agree on GPIO20.
- C6 UART0 is broken out only to test pads (TXD0/RXD0/IO9-boot pads P25/P21/P36) -
  reflashing the C6 directly requires pad soldering; the supported path is OTA from
  the P4 (`host_performs_slave_ota.zip`, upgrade guide PDFs in `example/`).
- BT: factory sdkconfig enables Bluedroid-over-hosted (BLE 4.2 feature set). ESP-NOW
  does not work over esp-hosted (**source: Elecrow forum thread**, not schematic).

## 3. Other peripherals

- microSD (J5): **1-bit SDMMC only** - D0 = GPIO39, CLK = GPIO43, CMD = GPIO44 (each
  via 0R). DAT1/DAT2 have 10K pullups but no P4 connection; DAT3/CS is pulled up
  (SDCS/R29) and not routed to any GPIO, so neither 4-bit nor SPI mode is possible.
  No card-detect (CDN unconnected).
- USB: two Type-C. **J1 = "UART" port -> CH340K** (U1): CH340 TXD -> **GPIO38
  (U0RXD)**, RXD <- **GPIO37 (U0TXD)** via 0R; classic two-transistor auto-download
  (UMH3NTN, U8) drives CHIP_PU and GPIO35 from DTR/RTS. **J16 = P4 native USB 2.0 OTG
  HS** (package DP/DM pins via 22R). Both VBUS feed the board through Schottky diodes;
  a slide switch (SW1) gates the main 5V rail via an NCE20P45Q P-FET.
- Buttons: **RESET = K4** -> CHIP_PU (also resets the STC8); **BOOT = K3 -> GPIO35**
  (strap, 10K pullup).
- Battery: PH2.0 (J3), **TP4059** linear charger (~430 mA), NCE20P45Q power-path FET
  pair (battery FET gated off when 5V present). Battery ADC (100K/39K divider),
  charge-status inputs, and the red/green charge LED are all on the **STC8** - the P4
  reads battery state via I2C reg 0x00, never directly.
- Audio: **two NS4168 mono I2S class-D amps** (U3/U13 - stereo, speaker connectors J4
  left / J6 right). I2S out: **LRCK = GPIO21, SCLK = GPIO22, SDOUT = GPIO23**. Amp
  shutdown via STC8 (SET_GPIO idx 2). **PDM mic** (MMICT5838): CLK = GPIO24,
  DATA = GPIO25. No codec chip, no line-in.
- Camera: 24-pin FPC (FPC3), **2-lane MIPI-CSI**; sensor I2C is **I2C2: SDA = GPIO33,
  SCL = GPIO34** level-shifted to 1.8 V; CSI_RESET from STC8 P1.3; AVDD 2V8 /
  DOVDD 1V8 via ME6211 LDOs. Factory config targets SC2336.
- Wireless module socket (two 7-pin headers J9/J11, for Elecrow SX1262 / nRF24L01 /
  Zigbee modules): SPI **SCK = GPIO26**, and MISO/MOSI = **GPIO47/GPIO48 through an
  SGM3005 analog mux** that alternatively routes GPIO47/48 as **UART1 TXD/RXD** to the
  Crowtail UART connector J2. Selection = physical switch S1 (net SEL0, readable by
  STC8 GPIO_IN 0) - UART1 and the module SPI are mutually exclusive. Module control
  pins: **CS = GPIO30, IRQ/DIO1 = GPIO31, RST = GPIO32, BUSY/DIO2 = GPIO29** (nRF24:
  IRQ = 29, CE = 31, CS = 32). GPIO31/32 double as UART2 TXD/RXD on the socket.
  (schematic; Arduino `board_config.h`)
- UART3-IN (J10, XH2.54): **TXD = GPIO27, RXD = GPIO28** through BSS138 shifters,
  5 V-tolerant; the connector also accepts **5 V / 2 A power in**.
- Headers: Crowtail I2C (J13, 3V3-shifted I2C1), Crowtail UART1 (J2), 2x8 GPIO header
  J7 (5V, 3V3, GPIO26, 29, 30, 31, 32, 47, 48, GND).
- IO expander: **no PCA/TCA/CH422** - the STC8 at 0x2F fills that role (backlight,
  amp enable, CSI reset, battery telemetry).

## 4. Elecrow wiki, demos, factory code

- Wiki (courses: Arduino, SquareLine, ESPHome, ESP-IDF, MicroPython; CH341SER driver
  download):
  https://www.elecrow.com/wiki/CrowPanel_Advanced_5inch_ESP32-P4_HMI_AI_Display_800x480_IPS_Touch_Screen_with_WiFi_6.html
  ESPHome tutorial PDF:
  https://www.elecrow.com/download/product/DHE04005D/5inch_Advance-P4-ESPHome_Tutorial.pdf
- Repo:
  https://github.com/Elecrow-RD/-CrowPanel-Advanced-5inch-ESP32-P4-HMI-AI-Display-800x480-IPS-Touch-Screen
  Contains `Eagle_SCH&PCB/1.0` (sch/brd/PDF), `3D file/`, `factory_firmware/`,
  `factory_sourcecode/V1.0/ESP32-P4-Advance-5inch-lvgl/` (LVGL 8.3.11 + vendored
  esp_lvgl_port + `peripheral/bsp_*` components), `example/V1.0/` (Arduino lessons
  01-16 on the ESP32_Display_Panel Arduino stack, idf-code lessons, MicroPython incl.
  `stc8h1kxx.py`, ESPHome config, SquareLine, AI_Conversation = xiaozhi fork with
  `elecrow-p4-board` board type, C6 firmware bins + upgrade guides).
- Factory build: **ESP-IDF 5.4.2** (`CONFIG_IDF_INIT_VERSION`), deps only
  `espressif/esp_lcd_touch_gt911 ^1.1.3` (RGB panel driver is core IDF). sdkconfig:
  `SPIRAM_MODE_HEX` + `SPIRAM_SPEED_200M` (needs `IDF_EXPERIMENTAL_FEATURES=y`),
  flash QIO/80M/16MB, **`ESP32P4_REV_MIN_1`, REV_MAX_FULL=199** (rev family
  v0.1-v1.99 - the probed chip's v1.3 is in range), esp-hosted SDIO block as in
  section 2, BT Bluedroid.

## 5. Espressif esp-bsp support

- No entry in espressif/esp-bsp for any Elecrow board; nothing transfers from
  esp32_p4_function_ev_board (that is DSI). Needed components are just core `esp_lcd`
  RGB panel + `espressif/esp_lcd_touch_gt911`; everything board-specific (backlight,
  battery, amp) goes through the STC8 I2C protocol above, for which the only
  reference implementations are Elecrow's `bsp_stc8h1kxx` (C) and `stc8h1kxx.py`
  (MicroPython).

## 6. Errata and gotchas

1. **Black screen after successful flash = backlight never enabled.** The panel needs
   no init at all, but brightness requires the I2C write to STC8 0x2F/0x20. Factory
   order: LDO ch3 + ch4 acquire -> I2C init -> STC8 -> touch -> display ->
   `set_lcd_blight(100)`.
2. GPIO36 is both touch RST and the DOWNLOAD_BOOT strap (10K up / 27K down through
   the touch FPC). Do not drive it low around reset; conversely a held touch panel
   line can interfere with strapping.
3. Wiki's "Backlight: STC8(P3.7)" is misleading - P3.7 is the unfitted
   backlight-power FET; brightness is P1.1 PWM via I2C reg 0x20.
4. esp-hosted stability (**UNVERIFIED - community reports**): WiFi dropouts at the
   default 40 MHz SDIO; lowering to 10-20 MHz mitigates (also seen as watchdog
   reboots on the 7-inch sibling, esphome/esphome#14313). Irrelevant to notyas - we
   never build esp-hosted.
5. ESP-NOW is not supported over esp-hosted P4+C6 (**source: Elecrow forum**); BLE
   only via Bluedroid-over-hosted. Irrelevant to notyas.
6. P4 revision family: factory config targets v0.1-v1.99. Fine for this v1.3 unit,
   but IDF v5.5+ defaults target the v3.x family - a wrong-family image builds and
   does not boot; keep `ESP32P4_REV_MIN` pinned (same trap as the Waveshare board).
7. Third-party pinout pages are unreliable for this board: espboards.dev lists the C6
   reset as IO32 (wrong - GPIO20) and the wiki's own tables mix in ESP32-S3-series
   text. Schematic + factory sdkconfig are the ground truth used here.
8. Power budget: backlight boost + 3 W amps can exceed one USB port; symptoms are
   brownouts/black screen under load. Feed 5 V/2 A into UART3-IN (J10) or both USB
   ports.
9. pclk discrepancy: factory IDF uses 25 MHz, Arduino lessons 18 MHz (~42 Hz); the
   header comment still shows an 18 MHz calculation. Both work; expect tearing
   without the double-FB/bounce-buffer options already in the factory Kconfig.
10. UART1 vs wireless-module SPI are hardware-muxed (SGM3005 + switch S1); firmware
    can read the switch position via STC8 GPIO_IN 0 but cannot override it.

## 6b. Bring-up results (2026-08-17, notyas board-elecrow-5 on the physical board)

Everything below was observed live on the COM6 unit (rev v1.3), resolving this
report's open items; BOARDS.md's TODO list carries the same resolutions:

- `esp_lcd_new_rgb_panel` with the factory config (pclk 25 MHz, HPW4/HBP8/HFP8,
  VPW4/VBP16/VFP16, DE mode, pclk_active_neg + pclk_idle_high, 16-bit,
  dma_burst 64, fb in PSRAM) initializes cleanly and streams; single-FB
  no-copy draw_bitmap path works exactly like the DPI driver's.
- STC8 backlight protocol confirmed: I2C 0x2F reg 0x20 duty write ACKs and
  controls brightness (blank at init, 80% after first frame). There is no
  P4-only backlight path - the write is required (errata 1 stands).
- GT911: driver-managed reset (RST GPIO36, INT GPIO42) straps the address
  deterministically to **0x5D**; TouchPad_ID 0x39,0x31,0x31, config version
  0x99. Runtime drive of the GPIO36 strap is safe as predicted (factory
  behavior); pin left high after init.
- LDO4 (3300 mV) acquire works and the GPIO45-54 I2C bank is live despite the
  schematic's R109 NC marking (STC8 + GT911 both respond).
- Radio kill GPIO20 verified as the first app_main action over two monitored
  boots; 34 s stable each, zero errors, steady heap (32.5 MB free).

## 7. The 7 / 9 / 10.1 inch siblings (added 2026-08-17, multi-board work)

Contrary to the earlier "identical electronics" assumption, the 1024x600 DSI
siblings are a DIFFERENT electrical layout, not just a different panel. Facts
below were verified per board against its own V1.0 Eagle schematic
(machine-parsed) and its factory firmware
(`factory_sourcecode/V1.0/ESP32-P4-Adcance-brookesia_phone_inch{7,9,10_1}.zip`,
a modified `espressif__esp32_p4_function_ev_board` BSP 4.1.1 +
`sdkconfig.defaults`); all three boards are identical to each other in every
checked item:

- **C6 radio kill: P4 GPIO32 -> C6 EN** (schematic net `C6_EN`:
  `U7.GPIO32 -> IC1.EN`, 10K pullup R77 to the always-on C6 3V3 - same
  power-on-window story as the 5inch), factory
  `CONFIG_ESP_HOSTED_SDIO_GPIO_RESET_SLAVE=32`. So espboards.dev's "IO32"
  claim is right for THESE boards and wrong for the 5inch (GPIO20).
- **C6 SDIO (never configured by notyas): 1-bit** - CMD=19, CLK=18, D0=14,
  D1=15 (factory sdkconfig `ESP_HOSTED_PRIV_SDIO_PIN_*`).
- **Display: 1024x600 2-lane MIPI-DSI, EK79007** via
  `espressif/esp_lcd_ek79007` (^1). Factory DPI config (explicit values in
  `esp32_p4_function_ev_board.c`, `CONFIG_BSP_LCD_TYPE_1024_600` branch):
  DPI 51 MHz, lane bit rate 1000 Mbps, HBP 160 / HPW 70 / HFP 160,
  VBP 23 / VPW 10 / VFP 12, RGB565, `use_dma2d`, no LCD reset pin.
  LDO channel 3 at 2500 mV for the DSI PHY (`bsp_enable_dsi_phy_power`).
- **Backlight: direct LEDC PWM on P4 GPIO31** (30 kHz, 10-bit,
  non-inverted) - unlike the 5inch there is no STC8 in the backlight path
  (the STC8 is still present for battery/GPIO duties).
- **Touch: GT911 on I2C SDA=45/SCL=46 (same as 5inch), RST=GPIO40 (a plain
  GPIO here, NOT a strap), INT=GPIO42.** Factory uses the driver-managed
  reset with INT strapping, primary address 0x5D, backup 0x14.
- 16 MB flash, `ESP32P4_REV_MIN_1` / `REV_MAX_FULL=199` family pin, same as
  the 5inch factory config.

No physical 7/9/10.1 board exists on this bench: notyas carries these as
compile-checked UNTESTED scaffolds only (`board-elecrow-7/-9/-101`,
`firmware/src/board/elecrow_dsi.rs`); see docs/BOARDS.md status table.

Sources:
[wiki](https://www.elecrow.com/wiki/CrowPanel_Advanced_5inch_ESP32-P4_HMI_AI_Display_800x480_IPS_Touch_Screen_with_WiFi_6.html),
[GitHub repo](https://github.com/Elecrow-RD/-CrowPanel-Advanced-5inch-ESP32-P4-HMI-AI-Display-800x480-IPS-Touch-Screen),
[schematic folder](https://github.com/Elecrow-RD/-CrowPanel-Advanced-5inch-ESP32-P4-HMI-AI-Display-800x480-IPS-Touch-Screen/tree/master/Eagle_SCH%26PCB/1.0),
[espboards.dev page](https://www.espboards.dev/esp32/elecrow-crowpanel-advance-5-esp32-p4/),
[ESP-NOW forum thread](https://forum.elecrow.com/discussion/28266/esp-now-on-crowpanel-advanced-5inch-esp32-p4-hmi-ai-display-800x480-ips-touch-screen-with-wifi-6),
[esphome issue #14313](https://github.com/esphome/esphome/issues/14313),
[product page](https://www.elecrow.com/crowpanel-advanced-5inch-esp32-p4-hmi-ai-display-800x480-ips-touch-screen-with-wifi-6.html),
[ESPHome tutorial PDF](https://www.elecrow.com/download/product/DHE04005D/5inch_Advance-P4-ESPHome_Tutorial.pdf)
