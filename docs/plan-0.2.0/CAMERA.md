# CAMERA.md - camera input paths for notyas 0.2.0

Status: proposal, pending user decision. Companion documents in this directory:
ARCHITECTURE.md, SECURITY.md, UX.md, MILESTONES.md, OPEN-QUESTIONS.md (parallel
workflow); PARITY.md marks camera-dependent Coldcard Q features (QR seed scan,
PSBT scan-in, Key Teleport receive) as class b once a camera path exists.

## 1. Recommendation (ranked)

1. **CSI + OV5647 (Pi-camera-class module) - recommended for 0.2.0 on the
   Waveshare 4B.**
   - Security: a CSI sensor is a dumb peripheral - no protocol stack faces the
     input (section 4). Matches the SeedSigner precedent.
   - Software: complete vendor stack exists today - esp_cam_sensor OV5647
     driver + esp_video V4L2-style capture + ISP; requires IDF >= 5.4 and the
     4B BSP already requires IDF >= 5.5, so the floor is met.
   - BOM/reach: $8-12 Raspberry Pi camera clones are globally available, and
     SeedSigner owners already have exactly this module.
   - On Elecrow CrowPanel boards the same firmware path works but the physical
     camera is Elecrow's own 24-pin SC2336 module (section 2.3) - camera
     support is documented per-board.
2. **No camera in 0.2.0 (SD-card PSBT only) - acceptable fallback.** Coldcard's
   microSD PSBT flow demonstrates this is a legitimate airgap on its own
   (https://coldcard.com/learn/hardware-wallets/what-is-a-psbt). Camera slips
   to 0.3.0 without weakening the security story; PARITY.md's class-c camera
   rows simply stay class-c one release longer.
3. **USB-UVC webcam - rejected for the signer.** It adds an untrusted-device
   parser to an airgapped device (section 4), requires external camera power on
   both supported boards (section 3), and contradicts the prior art the project
   cites. If ever offered, it must be a compile-time-off feature.

## 2. MIPI-CSI path: hardware findings

### 2.1 Waveshare 4B connector J1 is pin-for-pin Raspberry Pi camera compatible

Verified by positional text extraction from the official schematic
(https://files.waveshare.com/wiki/ESP32-P4-WIFI6-Touch-LCD-4B/ESP32-P4-WIFI6-Touch-LCD-4B.pdf,
page 1, connector J1, 15-pin 1.0 mm FFC):

| Pin | 4B net | Pi camera 15-pin standard |
|---|---|---|
| 1 | GND | GND |
| 2 | CSI_D0_N | CSI_D0_N |
| 3 | CSI_D0_P | CSI_D0_P |
| 4 | GND | GND |
| 5 | CSI_D1_N | CSI_D1_N |
| 6 | CSI_D1_P | CSI_D1_P |
| 7 | GND | GND |
| 8 | CSI_CLK_N | CSI_CK_N |
| 9 | CSI_CLK_P | CSI_CK_P |
| 10 | GND | GND |
| 11 | CSI_IO0, 10K pullup to ESP_3V3 (R47) | IO0 / CAM_GPIO (module enable/LED) |
| 12 | CSI_IO1, R48 not fitted (floating) | IO1 |
| 13 | ESP_I2C_SCL via R49 2.2K (shared GPIO8 bus) | I2C_SCL |
| 14 | ESP_I2C_SDA via R50 2.2K (shared GPIO7 bus) | I2C_SDA |
| 15 | ESP_3V3 (C50 10uF + C51 100nF decoupling) | VCC 3V3 |

This is the standard Raspberry Pi 15-pin CSI camera pinout (GND on 1/4/7/10,
two data lanes, clock lane, two GPIO, I2C, 3V3 on 15). Pi pinout references:
https://blog.arducam.com/raspberry-pi-camera-pinout/ ,
https://docs.zephyrproject.org/latest/build/dts/api/bindings/gpio/raspberrypi,csi-connector.html ,
https://www.petervis.com/Raspberry_PI/Raspberry_Pi_CSI/raspberry-pi-csi-interface-connector-pinout.html

Notes:
- Voltage matches: Pi cameras take 3V3 and regulate 2.8V/1.8V on-module.
- Pin 11 (module enable on Pi cam v1.x) is permanently pulled high on the 4B,
  so the camera is always enabled; pin 12 floats. A clone routing its enable to
  pin 12 would fail to wake (harmless - see abort criteria). Waveshare sells a
  Pi-style OV5647 camera working on this connector family and bundles it with
  the P4-NANO KIT-A (same SoC, same 15-pin CSI):
  https://www.waveshare.com/wiki/ESP32-P4-Nano-StartPage ,
  https://docs.waveshare.com/ESP32-P4-NANO
- The 4B wiki specifies the connector for OV5647 or SC2336
  (https://docs.waveshare.com/ESP32-P4-WIFI6-Touch-LCD-4B); no camera demo is
  published there yet.

### 2.2 The SeedSigner camera is electrically a Pi camera

SeedSigner's documented tested camera is the Aokin/AuviPal 5MP OV5647 module, a
Raspberry Pi Camera v1.3 clone with the standard 15-pin pinout and 3V3 supply
(https://seedsigner.com/hardware/ ,
https://www.amazon.com/Aokin-Raspberry-Camera-Module-OV5647/dp/B07RXKZ1KN).
It should plug into the 4B's J1 directly, and its sensor is the same OV5647 the
Espressif driver targets.

### 2.3 Elecrow CrowPanel Advanced: CSI exists but is not Pi-compatible

The 5inch exposes CSI on a 24-pin FPC (FPC3), sensor I2C on a dedicated
1.8V-shifted bus (GPIO33/34), CSI_RESET via the STC8 co-MCU, on-board 2V8/1V8
LDOs, factory-targeted at SC2336 (verified from the Eagle schematic; see
docs/research/elecrow-board.md and
https://github.com/Elecrow-RD/-CrowPanel-Advanced-5inch-ESP32-P4-HMI-AI-Display-800x480-IPS-Touch-Screen).
A Pi/SeedSigner camera cannot plug in; the camera for this board is Elecrow's
own 2MP SC2336 accessory
(https://www.cnx-software.com/2025/12/23/crowpanel-advanced-7inch-review-part-1-esp32-p4-hmi-ai-display-hands-on-with-lvgl-factory-firmware/).
Consequence: camera support is a per-board statement, not a project-wide one.

### 2.4 Software support today (ESP-IDF)

- `espressif/esp_cam_sensor` v2.4.0: MIPI drivers for OV5647 and SC2336 among
  30+ sensors. P4 supports MIPI-CSI/DVP/USB/SPI inputs; ISP max input
  1920x1080; CSI max 1.5 Gbps/lane.
  https://components.espressif.com/components/espressif/esp_cam_sensor ,
  https://github.com/espressif/esp-video-components/tree/master/esp_cam_sensor
- `espressif/esp_video` v2.2.0: V4L2-style capture framework for P4 (CSI + ISP);
  requires IDF >= 5.4; deps esp_cam_sensor 2.4.*, esp_ipa 2.2.* (AE/AWB).
  https://components.espressif.com/components/espressif/esp_video ,
  https://docs.espressif.com/projects/esp-video-components/en/latest/esp32p4/Get_Started/index.html
- ISP relevance for QR: the pipeline can emit YUV, and the Y plane is exactly
  the grayscale input a QR decoder wants - no software conversion pass.

## 3. USB-UVC path (evaluated, rejected)

Software exists: P4's USB 2.0 OTG HS host is supported, IDF ships a host UVC
example that runs on P4 (640x480@15 MJPEG,
https://github.com/espressif/esp-idf/blob/master/examples/peripherals/usb/host/uvc/README.md),
`espressif/usb_host_uvc` v2.5.1 supports P4
(https://components.espressif.com/components/espressif/usb_host_uvc), and the
hardware JPEG codec decodes 640x480 MJPEG at ~307 fps with direct grayscale
output
(https://docs.espressif.com/projects/esp-idf/en/latest/esp32p4/api-reference/peripherals/jpeg.html).

Hardware does not cooperate on powering the webcam:
- Waveshare 4B: both Type-C VBUS rails enter VCC_5V through AO3401 P-FETs
  (Q2/Q3) under an MMDT3906DW priority circuit - a power-input ORing
  arrangement. The schematic shows no path sourcing 5V out onto the native
  port's VBUS (verified by schematic parse).
- Elecrow 5inch: both VBUS pins feed the board through Schottky diodes -
  definitively no power out (Eagle schematic, docs/research/elecrow-board.md).
- Consequence: a UVC webcam on either board needs an externally powered hub or
  a modified Y-cable, which alone breaks BOM simplicity.

## 4. Security analysis: USB host vs CSI sensor

- A CSI camera is a dumb peripheral: a unidirectional D-PHY pixel stream plus
  an I2C register interface that the host initiates. There is no enumeration,
  no descriptor parsing, no protocol state machine driven by
  attacker-formattable data structures.
- USB host mode means running enumeration and descriptor parsing against
  whatever is plugged in. This class of code has a long defect record: USBFuzz
  (USENIX Security 2020) found 26 new bugs across the Linux, FreeBSD, macOS and
  Windows USB host stacks by emulating malicious devices; its framing applies
  directly - host stacks were "developed under a security model that implicitly
  trusts connected devices"
  (https://www.usenix.org/conference/usenixsecurity20/presentation/peng ,
  https://www.usenix.org/system/files/sec20-peng_0.pdf). An embedded host stack
  has seen far less audit attention than Linux's; enabling it converts the
  signer's only data port into a parser of untrusted input, and BadUSB-class
  device spoofing applies as soon as more than one class driver is present.
- Prior art aligns: Coldcard's air-gapped model exists so the signing flow
  never touches a USB data connection
  (https://coldcard.com/learn/hardware-wallets/air-gapped-signing ,
  https://coldcard.com/docs/paranoid/), and SeedSigner receives data only by
  camera, with no USB data path at all (https://github.com/SeedSigner/seedsigner).
- There is also a UX/trust consideration: inviting users to plug a webcam into
  the cold signer normalizes plugging things into it. The CSI ribbon affords no
  such mistake.

## 5. SeedSigner-camera replug experiment (procedure)

Goal: demonstrate a stock SeedSigner OV5647 module working on the Waveshare 4B
J1 connector. Expected risk: low - supplies match, module regulators are
on-board, enable pin is held high by R47.

1. Cable: use a standard 15-pin, 1.0 mm-pitch, straight 1:1 FFC (the camera's
   own cable, or e.g. https://www.dfrobot.com/product-2035.html). Pi Zero
   owners note: the Zero-end cable is 22-pin - do not use it; use the
   standard-Pi 15-pin cable.
2. Seat the cable at both ends with the board unpowered. Contacts must face the
   connector's contact side (flip-lock FFC; wrong-side insertion is a
   no-contact failure, not damaging). Match pin 1 = GND to the marked pin 1 on
   J1.
3. Checks before powering (board still unpowered):
   - Continuity: camera-module GND (any shield/GND pad) to 4B GND.
   - Continuity: camera 3V3 pad to the 4B 3V3 rail (pin-15 side of J1; the C50
     capacitor pads are a probe point).
   - These catch the only genuinely damaging mistake: an end-for-end cable
     flip, which maps pin 1 (GND) onto pin 15 (3V3) and shorts the rail. If
     either check fails, reseat or replace the cable; do not power on.
4. Power on and run the esp-video `capture_stream` example
   (https://github.com/espressif/esp-video-components) with the OV5647 sensor
   selected, before any notyas integration.
5. Abort criteria:
   - Any smell, heat, or the board browning out at power-on: power off
     immediately, re-run the continuity checks.
   - The sensor never ACKs at I2C address 0x36: expected failure mode if a
     specific clone routes its enable to pin 12 instead of pin 11. Harmless -
     no damage; record the clone as incompatible and try a different module.
   - Frames captured but garbage: check lane count/config in the example
     (OV5647 on 2 lanes), not a hardware fault.

## 6. Rust decode stack

- **QR detect/decode: `rqrr`** - pure Rust, quirc-algorithm-based, takes
  grayscale input from any source, MIT/Apache-2.0, maintained.
  https://github.com/WanzenBug/rqrr , https://crates.io/crates/rqrr
  Fallback if too slow: Espressif's `quirc` C component
  (https://components.espressif.com/components/espressif/quirc), at the cost of
  C in the trusted computing base. zbar (C, LGPL, heavier) is not recommended.
- **Animated UR (BCR-2020-005, crypto-psbt): `ur`** (dspicher/ur-rs) - UR +
  Luby-transform fountain encode/decode + bytewords, MIT, active.
  https://github.com/dspicher/ur-rs . `foundation-urtypes` adds a no_std UR
  type registry (https://docs.rs/foundation-urtypes/latest/foundation_urtypes/).
- **BBQr (Coldcard-family interop): `bbqr`** 0.6.0 (SatoshiPortal/bbqr-rust,
  MIT, split + join). Spec: https://bbqr.org/ ,
  https://github.com/coinkite/BBQr/blob/master/BBQr.md ; crate:
  https://lib.rs/crates/bbqr
- **SeedQR**: no Rust crate exists; proposed as a notyas ecosystem contribution
  - see PLATFORM.md.
- **CPU budget**: P4 is dual RISC-V at 400 MHz with ISP, PPA and hardware JPEG.
  Espressif's ESP32-S3 camera QR demo measures ~22 ms/frame scan overhead at
  240 MHz (https://github.com/espressif/qrcode-demo); quirc's own benchmark is
  ~50 ms for VGA extract+decode on a modern x86 core
  (https://dlbeer.co.nz/oss/quirc.html). With the ISP delivering Y-plane
  grayscale and the PPA downscaling for free, a 10+ fps scan loop at 640x480 is
  realistic - comfortably above the 5-10 fps practical frame rates of UR2/BBQr
  animated streams (SeedSigner ships usable animated-UR scanning on a 1 GHz
  single-core Pi Zero).

## 7. Scope: 0.2.0 vs later (proposal)

In 0.2.0 (if the CSI path is approved):
- CSI capture bring-up on the Waveshare 4B with OV5647 (esp_cam_sensor +
  esp_video), Y-plane grayscale into `rqrr`.
- Static QR scan-in: SeedQR/CompactSeedQR (crate per PLATFORM.md), plain-text
  seed words, descriptors, addresses (feeds PARITY.md rows: seed scan, verify
  address ownership input).
- Animated scan-in: BBQr and UR crypto-psbt for PSBT (unlocks the full
  scan-sign-display loop; PARITY.md "PSBT via QR" row moves from c to b).
- Per-board support statement: camera = Waveshare 4B + Pi-camera-class module;
  Elecrow = Elecrow SC2336 module, bring-up permitting.

Later (0.3.0+):
- Elecrow SC2336 validation if not done in 0.2.0.
- Key-Teleport-style device-to-device receive (needs protocol work beyond
  capture).
- Flashlight/illumination LED, autofocus-module evaluation, scanning-UX polish
  beyond the basic viewfinder (defer to this directory's UX.md where present).

Decision requested from the user: adopt path 1 (CSI camera in 0.2.0) or path 2
(SD-only 0.2.0, camera in 0.3.0). Path 3 (USB-UVC) is recommended for rejection
in either case.

Repo files consulted: docs/research/hardware.md, docs/research/elecrow-board.md.

Input to: MILESTONES.md reconciliation
