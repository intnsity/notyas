# Waveshare ESP32-P4-WiFi6-Touch-LCD-4B - fact sheet

Verified against the official schematic (files.waveshare.com/wiki/ESP32-P4-WIFI6-Touch-LCD-4B/
ESP32-P4-WIFI6-Touch-LCD-4B.pdf) and the Waveshare BSP source
(github.com/waveshareteam/Waveshare-ESP32-components, bsp/esp32_p4_wifi6_touch_lcd_4b).
Full sourced research report: docs/research/hardware.md.

## Core

| Item | Fact |
|---|---|
| SoC | ESP32-P4NRW32 bare chip, 32 MB in-package PSRAM, 32 MB external QSPI NOR flash |
| Dev unit silicon | rev **v1.3** (esptool). Pre-v3.0 family; NOT binary-compatible with v3.x builds |
| Display | 4" IPS 720x720, ST7703 controller, 2-lane MIPI-DSI, DPI video mode, 60 Hz |
| Touch | GT911, I2C addr 0x5D (fallback 0x14), 5-point capacitive |
| WiFi | ESP32-C6-MINI-1U-H8 as SDIO slave (esp-hosted protocol). We never build that stack |
| PMIC/battery | None. 5 V USB in; RTC backup header only. No secure element |

## GPIO map (from schematic; wiki table has errors, schematic wins)

| Function | GPIO |
|---|---|
| LCD reset | 27 |
| Backlight enable | 33 |
| Backlight PWM (LEDC) | 26 |
| Touch I2C SDA / SCL (shared bus: touch, camera, audio codecs) | 7 / 8 |
| Touch reset | 23 |
| Touch INT | **not connected** (test point only) - GT911 must be polled |
| microSD (SDMMC slot 0, 4-bit) D0-D3 / CLK / CMD | 39-42 / 43 / 44 |
| microSD power gate (P-FET, pulldown = default ON) | 45 |
| **ESP32-C6 enable (CHIP_PU)** - drive LOW to hold radio in reset | **54** |
| C6 SDIO CLK/CMD/D0-D3 (never configured by our firmware) | 18/19/14-17 |
| C6 aux (IO2 strap) | 6 |
| UART0 TX / RX (CH343 bridge, USB-C port "USB UART") | 37 / 38 |
| Native USB 2.0 OTG HS (USB-C port "USB") | dedicated pins |
| BOOT button / RESET button | 35 / EN |
| I2S (audio, unused in 0.1.0) DOUT/WS/DSDIN/SCLK/MCLK, PA enable | 9/10/11/12/13, 53 |
| 32.768 kHz RTC crystal | 0 / 1 |

## Power-rail requirements (the classic P4 black-screen traps)

- MIPI DPHY: internal LDO **channel 3 at 2500 mV** must be acquired
  (esp_ldo_acquire_channel) before DSI init, or init hangs.
- GPIO39-48 IO bank (SD card, UART): internal LDO **channel 4 at 3300 mV**.

## Software config (from Waveshare's working examples)

- ESP-IDF >= 5.5 for BSP v3.x; panel driver component `waveshare/esp_lcd_st7703`
  (`ST7703_720_720_PANEL_60HZ_DPI_CONFIG`), touch `espressif/esp_lcd_touch_gt911`.
- sdkconfig: `CONFIG_SPIRAM=y`, `SPIRAM_SPEED_200M` (needs
  `IDF_EXPERIMENTAL_FEATURES=y`), `SPIRAM_XIP_FROM_PSRAM=y`, L2 cache 256 KB/128 B,
  `ESPTOOLPY_FLASHSIZE_32MB` (Waveshare's own sdkconfigs wrongly say 16MB),
  chip-revision min pinned to the v1.x family (IDF 5.5 defaults to v3.1+).
- Flashing: espflash >= 4.5 over CH343 COM port (currently COM3) or native USB.

## Board quirks

- Touch is poll-only (INT unrouted); I2C address cannot be forced - probe 0x5D then 0x14.
- SD power (GPIO45) defaults on; BSP never touches it.
- C6 reset (GPIO54) is the only control over the radio chip - no power switch.
- 4-pin pads P1 (TX/RX/IO9/GND) exist for reflashing the C6; irrelevant to us.
