# Research: Waveshare ESP32-P4-WiFi6-Touch-LCD-4B hardware (2026-08-17)

Agent-produced report, verified against the official schematic. Summary lives in
docs/HARDWARE.md; this is the full sourced version.

**Naming note:** The wiki URL `ESP32-P4-WIFI6-Touch-LCD-4B` redirects to the page titled
"ESP32-P4-86-Panel-ETH-2RO". Same PCB family: the **4B** (SKU 31416) has the MIPI-CSI
camera connector; the **86-Panel-ETH-2RO** (SKU 31570) adds a bottom board with Ethernet,
RS485 and 2 relays. The extra peripherals (IP101 PHY, RS485, relays) exist only on the
86-Panel variant.
Sources: https://www.waveshare.com/wiki/ESP32-P4-WIFI6-Touch-LCD-4B ,
https://docs.waveshare.com/ESP32-P4-WIFI6-Touch-LCD-4B ,
https://www.waveshare.com/esp32-p4-wifi6-touch-lcd-4b.htm

Schematic PDF (2 pages, read directly):
https://files.waveshare.com/wiki/ESP32-P4-WIFI6-Touch-LCD-4B/ESP32-P4-WIFI6-Touch-LCD-4B.pdf
ETH/relay base board (separate): 86_Panel_Bottom_Board.pdf at the same base URL.

## 1. Core hardware

- SoC: **ESP32-P4NRW32** bare chip (U8), not a module. 32 MB PSRAM stacked in-package;
  QSPI to external **32 MB NOR flash** (nets FLASH_CS/Q/WP/HD/CK/D, powered from P4
  internal LDO VO1 via R53 0R). (schematic; wiki)
- LCD: 4" IPS, **720x720**, controller **ST7703**, **2-lane MIPI-DSI**, video (DPI)
  mode. BSP runs it at 60 Hz, 480 Mbps/lane, RGB565 or RGB888. 30-pin FPC carries
  panel + touch; D2/D3 lane pads exist on the FPC but only 2 lanes are wired.
  (schematic; https://components.espressif.com/components/waveshare/esp_lcd_st7703 ;
  BSP display.h)
- LCD control: **RESET = GPIO27** (R60 0R), **TE** on FPC pin 7 (not routed to a GPIO).
- Backlight: AP3032KTR-G1 boost LED driver from 5 V. **Enable = GPIO33** (BL_EN, R32
  0R), **PWM dimming = GPIO26** (via R43 0R into the FB node through R42 10K). BSP does
  LEDC PWM on GPIO26 (`BSP_LCD_BACKLIGHT = GPIO26`).
- Touch: **GT911**, 5-point capacitive, I2C **SDA = GPIO7, SCL = GPIO8** (shared bus),
  **RST = GPIO23** (R37 0R). **INT is NOT connected to any GPIO** - test point TP2
  only. BSP sets `int_gpio_num = GPIO_NUM_NC` (polled). GT911 address is whichever the
  chip powers up with - driver tries default **0x5D**, backup **0x14**; without INT
  control the address cannot be forced.
  (schematic; BSP source; https://components.espressif.com/components/espressif/esp_lcd_touch_gt911)
- MIPI-DPHY power: P4 internal **LDO VO3 (channel 3) at 2500 mV** feeds VDD_MIPI_DPHY -
  BSP acquires it before DSI init. VO4 (channel 4) set to **3300 mV** for the GPIO39-48
  IO domain (TF card / UART bank). (schematic; BSP `bsp_enable_dsi_phy_power()` /
  `bsp_enable_ldo_vo4()`)

## 2. WiFi: ESP32-C6 companion

- Module: **ESP32-C6-MINI-1U-H8** (U1; 8 MB flash, IPEX antenna). **SDIO slave**
  running esp-hosted; P4 is SDIO host using `espressif/esp_hosted` +
  `espressif/esp_wifi_remote` (wiki WiFi demo adds exactly these two components).
- SDIO wiring (schematic, cross-checked against C6 fixed SDIO pins); all six lines have
  51K pullups to 3V3; same mapping as Espressif's ESP32-P4-Function-EV-Board:

| Signal | P4 GPIO | C6 pin |
|---|---|---|
| SDIO CLK | GPIO18 | IO19 |
| SDIO CMD | GPIO19 | IO18 |
| SDIO D0 | GPIO14 | IO20 |
| SDIO D1 | GPIO15 | IO21 |
| SDIO D2 | GPIO16 | IO22 |
| SDIO D3 | GPIO17 | IO23 |

- Reset/power-down: **P4 GPIO54 -> C6 CHIP_PU (EN)** through R34 0R. Driving GPIO54 low
  holds the C6 in reset (esp-hosted's default `slave_reset` pin). No separate power
  switch for the C6 - reset is the only control.
- Extra line: **P4 GPIO6 -> C6 IO2** through R33 0R (10K pullup) - C6 boot-strap/aux.
- C6 UART flashing: 4-pin 2.54 mm pads **P1: TX (C6 U0TXD), RX (C6 U0RXD), IO9 (C6 boot
  strap), GND** - "for flashing ESP32-C6 module firmware".
- Pre-flashed firmware: neither wiki nor product page explicitly says the C6 ships
  pre-flashed with esp-hosted slave firmware. The WiFi demo has no C6 flashing step,
  implying it ships working - treat "pre-flashed" as implied, not documented.
- Wiki discrepancy: docs page lists C6 connections as "GPIO6, GPIO14, GPIO16,
  GPIO18-GPIO20, GPIO22, GPIO54", contradicting the schematic (GPIO14-19 + 6 + 54).
  The schematic is unambiguous; trust it.

## 3. Other peripherals

- microSD (TF): 4-bit SDIO 3.0 on **SDMMC Slot 0 IOMUX pins: D0-D3 = GPIO39-42,
  CLK = GPIO43, CMD = GPIO44**. Card VDD gated by P-FET Q1 (AO3401) on **GPIO45** with
  10K gate pulldown, so power defaults ON (BSP never touches GPIO45). No card-detect /
  write-protect. BSP mounts `SDMMC_HOST_SLOT_0`, 4-bit, high-speed.
- Camera: 15-pin 1.0 mm FFC (J1), **2-lane MIPI-CSI** + shared I2C (GPIO7/8), for
  OV5647 or SC2336; 4B variant only. CSI_REXT/DSI_REXT terminated 4.02K 1%.
- USB: two Type-C. **H2 "USB" = P4 native USB 2.0 OTG HS** (direct to P4 DP/DM pins
  50/51). **H1 "USB UART" = CH343P bridge (U6)**: CH343 TXD -> **P4 GPIO38 (U0RXD)**,
  RXD <- **GPIO37 (U0TXD)**, classic two-transistor auto-download circuit (EMH4T2R,
  U7) driving ESP_EN and GPIO35 from DTR/RTS. P4's USB 1.1 FS PHY (GPIO24/25) broken
  out but disconnected by default (R106/R107 NC). Both ports can power the board.
- Buttons: **BOOT = Key2 -> GPIO35** to GND (boot-strap); **RESET = Key1 -> ESP_EN**,
  10K pullup to ESP_VBAT.
- PMIC/battery: **none.** 5 V USB -> MP1658/MP1605 bucks (3.3 V, 1.2 V core). RTC
  backup header H3 (MX1.25 2P) feeds P4 VBAT (pin 103) through a B5819WS Schottky from
  3V3 - trickle-charges, hence "rechargeable RTC batteries only".
- RTC: no external RTC chip; P4 internal RTC with 32.768 kHz crystal (Y2) on GPIO0/1.
- Audio: **ES8311** codec + **ES7210** 4-ch ADC + **NS4150B** 3 W class-D amp. I2S:
  DOUT = GPIO9, LCLK/WS = GPIO10, DSDIN = GPIO11, SCLK = GPIO12, MCLK = GPIO13;
  PA enable = GPIO53; config over shared I2C (GPIO7/8). Two SMD mics; ES7210 MIC3 wired
  to codec OUTP/OUTN as AEC echo-reference loopback. Speaker MX1.25 2P, 8 ohm 2 W.
  Audio 3V3 from RT9193-33 LDO.
- IO expander: **none on this board.** Everything is on direct P4 GPIOs. (Other
  Waveshare P4 boards, e.g. P4-NANO, use an expander at I2C 0x45 - do not copy that
  pattern to the 4B. See ESP32_Display_Panel issue #205.)
- 86-Panel-ETH-2RO extras (bottom board only): IP101 100M PHY, RMII on
  GPIO28-31/34/35/49-52; RS485 TXD = GPIO47, RXD = GPIO48; relays GPIO32/GPIO46.
- Expansion headers (silk): P3: 3V3, GPIO7, 8, 2, 3, 4, 5, T+, T-, R+, R-, 25, 24, GND;
  P2: 5V, GND, 37, 38, 20, 21, 22, 5V, 3V3, 32, 46, 47, 48, GND.

## 4. Waveshare wiki, demos, BSP

- Wiki: https://www.waveshare.com/wiki/ESP32-P4-WIFI6-Touch-LCD-4B (403s to plain
  fetchers; browser UA works) - mirrored at
  https://docs.waveshare.com/ESP32-P4-WIFI6-Touch-LCD-4B
- Demo bundle (~117 MB):
  https://files.waveshare.com/wiki/ESP32-P4-WIFI6-Touch-LCD-4B/ESP32-P4-WIFI6-Touch-LCD-4B.zip
  Demos: HelloWorld, I2C, SDMMC, WiFi station (esp_hosted), I2S audio, MIPI-DSI screen
  wake-up, RS485, relay, USB extended screen (Windows IDD driver), ESP-Phone
  (esp-brookesia).
- Wiki says ESP-IDF >= v5.3.1, some "Expert" demos need IDF master; ESP-IDF recommended
  over Arduino.
- BSP component: `waveshare/esp32_p4_wifi6_touch_lcd_4b` v3.0.0, source in
  waveshareteam/Waveshare-ESP32-components. Manifest requires **idf >= 5.5**; deps:
  `waveshare/esp_lcd_st7703 ^2.0.0`, `esp_lcd_touch_gt911 ^1`, `esp_codec_dev ~1.5`,
  `esp_lvgl_adapter ~0.6`, `lvgl >=8,<10`. (BSP 1.x supported IDF 5.3.)
- Examples: waveshareteam/ESP32-P4-Platform (00_board_check ... 19_system_monitor;
  "release/v5.4 or later"). Dedicated waveshareteam/ESP32-P4-WIFI6-Touch-LCD-4B repo is
  currently EMPTY (created 2026-08, no commits).

## 5. Espressif esp-bsp support

- No entry for this board in espressif/esp-bsp (only esp32_p4_function_ev_board and
  esp32_p4_eye). Function-EV BSP is the closest architectural relative (same P4 +
  C6-over-SDIO + GT911 + 2-lane DSI) but different panels (ILI9881C 1280x800 / EK79007
  1024x600) - its display init does not transfer.
- Matching components for the 4B: panel waveshare/esp_lcd_st7703
  (`esp_lcd_new_panel_st7703()`, `ST7703_720_720_PANEL_60HZ_DPI_CONFIG`), touch
  espressif/esp_lcd_touch_gt911, audio espressif/esp_codec_dev.

## 6. Errata and gotchas

1. Touch INT physically not connected - GT911 must be polled; INT-based address
   selection impossible.
2. **P4 silicon revision boundary:** pre-v3.0 and v3.x chips NOT binary compatible;
   wrong-family image builds fine but will not boot. IDF v5.5 defaults to rev >= 3.1.
   Waveshare ships overlay configs per family:
   https://github.com/waveshareteam/ESP32-P4-Platform/blob/main/docs/ESP32P4_REVISION_CONFIG.md
3. PSRAM config from Waveshare examples: CONFIG_SPIRAM=y, SPIRAM_SPEED_200M (requires
   IDF_EXPERIMENTAL_FEATURES=y), SPIRAM_XIP_FROM_PSRAM=y, L2 cache 256KB/128B. Their
   generic sdkconfigs say FLASHSIZE_16MB - this board is 32 MB, set
   ESPTOOLPY_FLASHSIZE_32MB.
4. DSI init requires the internal LDO dance (ch3 2500 mV for DPHY; ch4 3300 mV for
   TF/UART bank) - forgetting esp_ldo_acquire_channel is the classic black-screen
   failure.
5. esp-hosted host/slave version skew is the common WiFi failure mode on P4+C6 boards
   (irrelevant to us - we never build it).
6. BSP dependency pinning history: BSP once pinned esp_codec_dev 1.2.* breaking newer
   trees (Waveshare-ESP32-components issue #143, fixed at ~1.5); BSP majors track
   HW/IDF versions - check the BSP README table.
7. ESPHome: not usable out of the box for P4+C6 hosted WiFi (irrelevant to us).
