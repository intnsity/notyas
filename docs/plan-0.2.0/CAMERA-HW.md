# CAMERA-HW.md - camera hardware and software integration spec

Status: PLAN, wave-2. This document takes CAMERA.md's ranking as settled and turns
its recommendation - MIPI-CSI plus an OV5647 Pi-camera-class module on the Waveshare
4B - into something a person can build and a person can bench-validate. It does not
re-argue CSI versus USB-UVC; section 5 only adds the analysis that is specific to
turning the camera on.

Companion documents in this directory (owned by other agents; referenced, never
edited here): CAMERA.md (survey and ranking), ARCHITECTURE.md (crate layout,
signing pipeline, transport), SECURITY.md (0.2.0 invariants), UX.md and
UX-SCREENS.md (screen inventory and flows), PARITY.md (which Coldcard rows this
unlocks), PLATFORM.md (crate contributions), MILESTONES.md and OPEN-QUESTIONS.md
(reconciliation targets). Board facts: docs/HARDWARE.md,
docs/research/hardware.md, docs/research/elecrow-board.md, docs/BOARDS.md.

Convention: `OPEN:` marks a decision for the user (each carries a recommendation);
`DECISION:` marks a call made here, with the reasoning attached.

---

## 0. The shape of the thing

```
        OV5647 module (self-clocked, 3V3)
                |  2-lane MIPI D-PHY  +  SCCB (I2C, addr 0x36)
                v
  J1 15-pin FFC ---> P4 MIPI-CSI ---> ISP (Bayer RAW8 -> UYVY422) ---> PSRAM
                                                                         |
                                          PPA SRM (UYVY422 -> GRAY8, scale) <-+
                                                                         |
                                                     grayscale frame -----+
                                                                         |
                              firmware (std): rqrr detect + decode -> bytes
                                                                         |
                        notyas-wallet (no_std): transport ingress validator
                                    UR2 / BBQr / SeedQR / plain text
                                                                         |
                                            notyas-wallet policy engine (PSBT)
                                                                         |
                                                notyas-ui review + hold-to-sign
```

Everything left of "firmware (std)" is C in the trusted computing base and is
budgeted, gated and enumerated in section 2. Everything right of it is Rust, and
the payload is untrusted from the first byte (section 5).

---

## 1. Bench validation: the SeedSigner-camera replug

Written for one careful person, one board, one camera, an ohmmeter and a serial
console. Read the whole section before touching anything. Nothing in it requires
the notyas 0.2.0 firmware to exist.

### 1.1 The schematic facts this procedure rests on

Verified by positional text extraction from the official 4B schematic
(https://files.waveshare.com/wiki/ESP32-P4-WIFI6-Touch-LCD-4B/ESP32-P4-WIFI6-Touch-LCD-4B.pdf,
page 1, connector J1) on 2026-08-17, re-checked for this document:

| J1 pin | 4B net | Note |
|---|---|---|
| 1, 4, 7, 10 | GND | |
| 2, 3 | CSI_D0_N / CSI_D0_P | lane 0 |
| 5, 6 | CSI_D1_N / CSI_D1_P | lane 1 |
| 8, 9 | CSI_CLK_N / CSI_CLK_P | clock lane |
| 11 | CSI_IO0 | **R47 10K 1% pull-up to ESP_3V3** - module enable is held asserted, always |
| 12 | CSI_IO1 | R48 **NC** - the pin floats |
| 13 | ESP_I2C_SCL | **R49 2.2K to ESP_3V3** |
| 14 | ESP_I2C_SDA | **R50 2.2K to ESP_3V3** |
| 15 | ESP_3V3 | C50 10uF + C51 100nF local decoupling |

Correction to CAMERA.md's phrasing, which reads as if R49/R50 were series
elements in the I2C path: they sit in the same 3V3-referenced column as R47
(10K, unambiguously a pull-up to ESP_3V3) and R48 (NC), and a sweep of the whole
page finds **no other fitted pull-up on the ESP_I2C_SCL / ESP_I2C_SDA nets** -
the only other candidates, R70/R71 in the audio block, are marked NC. R49/R50
are therefore the shared bus's 2.2K pull-ups, drawn inside the camera block.
Two consequences that matter:

- The bus the GT911 uses today already has its pull-ups whether or not a camera
  is plugged in. Attaching the camera adds cable stub capacitance and the
  sensor's pin capacitance, nothing else. There is no reason to expect the touch
  controller to stop working, and if it does, capacitance is the suspect.
- 2.2K at 3V3 is a comfortable value; 400 kHz is not at risk, but see the
  100 kHz SCCB recommendation in 2.5 - it costs nothing and removes one variable
  from first bring-up.

Also relevant and already true in the 0.1.0 firmware:

- **LDO channel 3 at 2500 mV is already up.** `display_init()` on the 4B
  acquires it for the MIPI DSI D-PHY and never releases it
  (`firmware/src/display.rs::acquire_ldo`, `firmware/src/board/waveshare_4b.rs`).
  The CSI D-PHY sits on the same VDD_MIPI_DPHY rail and the esp_video CSI device
  would acquire the same channel 3 at the same 2500 mV
  (`esp_video/src/device/esp_video_csi_device.c`: `CSI_LDO_UNIT_ID 3`,
  `CSI_LDO_CFG_VOL_MV 2500`). IDF reference-counts fixed-voltage LDO channels, so
  a second acquire is legal
  (https://docs.espressif.com/projects/esp-idf/en/v5.5/esp32p4/api-reference/peripherals/ldo_regulator.html),
  but we will not depend on that - see 2.6.
- The 4B has no camera reset pin and no camera power-down pin routed. CSI_IO0 is
  pulled high permanently; CSI_IO1 floats. There is nothing to sequence.
- **There is no clock pin on this connector.** The module must generate its own
  XVCLK. This is the single biggest compatibility question and gets its own
  subsection (1.7).

### 1.2 Step 0 - identify the module before anything else

With the module unplugged, under good light and a loupe or a phone macro shot:

1. **Sensor marking.** Confirm the die/package marking reads OV5647. A module
   sold as "5MP Pi camera" that turns out to be an OV5640 (DVP-era) or an IMX219
   (Pi v2) will not work: esp_cam_sensor has an OV5647 MIPI driver and the P4
   has no IMX219 driver
   (https://components.espressif.com/components/espressif/esp_cam_sensor ; the
   "ESP32-P4 supports the original Pi Camera Module (OV5647) but not the newer
   Sony IMX-based variants" summary is corroborated at
   https://www.cnx-software.com/2026/05/04/esp32-p4-esp32-c5-board-features-raspberry-pi-compatible-mipi-connectors-for-official-displays-and-camera-modules/).
   SeedSigner's own documented module is the OV5647 Pi v1.3 clone
   (https://seedsigner.com/hardware/), so the expected answer is yes.
2. **Oscillator.** Find the crystal or oscillator can (a small 2- or 4-pad metal
   part near the sensor) and photograph the marking. Record it. If there is no
   oscillator at all on the module, **stop**: this connector supplies no clock
   and the sensor will never come out of reset. See 1.7 for what a 25 MHz versus
   24 MHz marking means.
3. **Connector count and pitch.** 15 positions, 1.0 mm pitch. A 22-pin cable (Pi
   Zero / CM4 style) does not belong anywhere in this experiment.
4. **Lens.** Pi v1.3 modules are fixed focus with a manually rotatable lens
   barrel, usually glued at roughly 1 m. QR scanning happens at 10-25 cm.
   Expect to break the glue and rotate the barrel later (section 4 notes why
   this is a UX parameter, not a defect).

### 1.3 Cable, orientation and the one damaging mistake

Use a straight 15-pin 1.0 mm 1:1 FFC - the camera's own cable is the right
cable. Do everything below with the board unpowered and the USB cable out.

- Both connectors are flip-lock FFC housings. **Look inside each housing** and
  find which face carries the gold fingers: that is the contact side, and the
  cable's bare conductors must face it. The blue stiffener faces the latch.
  Raspberry Pi's own convention for the module end is "silver contacts toward
  the lens side of the board"
  (https://www.raspberrypi.com/documentation/accessories/camera.html); the 4B
  end is a different board and must be read off the housing, not assumed.
- A wrong-side insert is a **no-contact** failure. Nothing is damaged, nothing
  gets hot, and no I2C device appears. It is annoying, not dangerous.
- The dangerous case is an **end-for-end reversal that maps J1 pin 1 (GND) onto
  the module's pin 15 (3V3)**, shorting the 3V3 rail through the cable or
  presenting 3V3 to a ground pin. Pin 1 on both housings is silkscreened or
  marked with a triangle; find it on both ends and confirm the same conductor
  reaches pin 1 at both ends before you close either latch.
- Never insert or remove the FFC with the board powered. Pull USB, wait for the
  backlight to die plus five seconds, then work.

### 1.4 Pre-power electrical checks

Cable seated in both housings, both latches closed, board unpowered, USB out.
An ordinary DMM is enough; a bench supply with a current limit is better.

| # | Measure | Probe points | Expect | If not |
|---|---|---|---|---|
| 1 | Continuity, ground | any module GND pad / connector shell to any 4B GND (a USB shell or a capacitor ground pad) | < 1 ohm | reseat; a failure here means wrong contact side or an unlatched housing |
| 2 | Continuity, supply | module 3V3 pad to the 4B 3V3 rail - **C50's positive pad at J1 is the intended probe point** | < 1 ohm | reseat; same causes |
| 3 | **Rail short** | 4B 3V3 to GND, with the camera attached | hundreds of ohms to tens of k, and clearly higher than 5 ohm; compare against the same measurement taken with the camera **unplugged** | **abort.** A reading near zero, or a large drop versus the unplugged baseline, is the end-for-end reversal or a damaged module. Do not apply power. |
| 4 | I2C sanity | J1 pin 13 and pin 14 each to the 3V3 rail | about 2.2K (R49/R50) | a dead short to 3V3 or to GND on either line means a bent cable or a folded conductor; reseat |
| 5 | Lane pairs not shorted | pin 2-3, 5-6, 8-9 each pair to each other and to GND | no continuity | reseat; a shorted differential pair is a crushed or misaligned cable |

Take check 3's baseline **first**, before the camera is ever plugged in, and
write both numbers down. It is the only measurement that distinguishes "this is
normal for this board" from "something is wrong".

Optional and worth it if a current-limited bench supply is available: power the
board through it at 5 V with the limit set to 1 A, note the idle current with no
camera, then with the camera. The OV5647 module adds on the order of a few tens
of mA on 3V3 while idle. A jump of hundreds of mA is a short.

### 1.5 First power-on

1. Power the board with the camera attached and **watch the first three
   seconds**: any smell, any warm spot on the module or on the 4B's 3V3 buck, or
   a board that browns out or reboot-loops means power off immediately and
   return to check 3.
2. The board should boot the existing 0.1.0 firmware exactly as before. **Touch
   must still work.** If the GT911 stops responding with the camera attached,
   the added bus capacitance is the suspect; re-test with the SCCB/touch bus at
   100 kHz before blaming the camera.
3. Nothing else should change. The camera is not initialized by 0.1.0 firmware;
   it is a powered, idle sensor sitting on an I2C address nobody is talking to.

### 1.6 Software confirmation, in three stages

Do not skip to stage 2. Each stage answers a different question and each has a
cheap failure.

**Stage L0 - the sensor answers, using notyas firmware and nothing else.**
The 0.1.0 firmware already owns an `i2c_master` bus on GPIO7/GPIO8 (created in
`touch_init`). A throwaway debug build adds one function next to the GT911
probe:

- `i2c_master_probe(bus, 0x36, 100)` must return `ESP_OK`. 0x36 is the OV5647's
  7-bit SCCB address, and it is what the Espressif driver registers
  (`esp_cam_sensor/sensors/ov5647/include/ov5647.h`: `OV5647_SCCB_ADDR 0x36`,
  `OV5647_PID 0x5647`). It matches the mainline Linux binding
  (`ov5647@36`, https://github.com/raspberrypi/linux, `ov5647.dtsi`).
- Then read the chip ID: write the 16-bit register address big-endian and read
  one byte, for `0x300A` and `0x300B`
  (`esp_cam_sensor/sensors/ov5647/private_include/ov5647_regs.h`:
  `OV5647_REG_SENSOR_ID_H 0x300a`, `OV5647_REG_SENSOR_ID_L 0x300b`). Expected:
  **0x56 and 0x47**. Anything else and you are not talking to an OV5647.
- Run this at 100 kHz for the camera device (per-device speed is a property of
  the I2C device handle, not the bus - see 2.5), leaving the GT911 at 400 kHz.

L0 passing proves: cable orientation correct, 3V3 present at the module, the
module self-clocks well enough to run its SCCB block, and the shared bus is
healthy with the camera on it. That is most of the risk retired for the cost of
twenty lines of debug code and zero new C components.

**Stage L1 - the vendor stack streams, in a separate project.**
Build Espressif's `capture_stream` example from esp-video-components
(https://github.com/espressif/esp-video-components), configured for the 4B:
`CAMERA_OV5647=y`, MIPI-CSI device on, DVP/SPI/UVC off, and the sensor's SCCB
pins set to GPIO7/GPIO8. Success is the example printing the detected sensor and
capturing frames without CSI errors. Keep this out of the notyas tree: it exists
to answer "does the hardware work with the vendor stack", and mixing it into the
signer's build defeats the point.

**Stage L2 - notyas integration.** Section 2 onward.

### 1.7 The 24 MHz versus 25 MHz question

This is the failure this experiment is most likely to hit, and it is worth
understanding before it happens.

- Every OV5647 mode in `esp_cam_sensor` is named and computed for a **24 MHz**
  input clock: `MIPI_2lane_24Minput_RAW8_800x640_50fps` and siblings, all with
  `.xclk = 24000000` and a hard-coded MIPI line rate
  (`ov5647.c`; `ov5647_settings.h`:
  `OV5647_IDI_CLOCK_RATE_800x640_50FPS = 100 MHz`, line rate = 4x that = 400
  Mbps per lane).
- The Raspberry Pi ecosystem runs the same sensor at **25 MHz**: the mainline
  Linux driver rejects anything else
  (`drivers/media/i2c/ov5647.c`: `if (xclk_freq != 25000000) ... "Unsupported
  clock frequency"`), and the Pi's device tree overlay sets the camera clock to
  25 MHz (`arch/arm/boot/dts/overlays/ov5647-overlay.dts`:
  `clock-frequency = <25000000>`).
- The 15-pin connector carries no clock, so the module supplies its own. A Pi
  v1.3 clone therefore very plausibly carries a 25 MHz part, which makes every
  derived rate 4.17% high: 800x640 becomes about 52 fps and the D-PHY lane rate
  about 417 Mbps against a receiver configured for 400 Mbps.

What that means in practice:

- 4% is inside the tolerance of most D-PHY receivers, so it may simply work. It
  may also show up as intermittent line errors, torn frames, or ISP error
  interrupt spam.
- The fix, if needed, is small and lives entirely in a format table: add a
  25 MHz variant of the 800x640 entry with `mipi_clk` scaled by 25/24 and the
  matching `isp_info` clock, as a local override of the sensor driver or as an
  upstream PR. It is not a hardware problem.
- **DECISION:** record the oscillator marking in the bench log at step 0 (1.2)
  and, if frames come out garbled, treat the clock mismatch as suspect number
  one before touching lane counts or Bayer order. A garbled-frame failure with a
  25 MHz module is an expected outcome of this experiment, not a defeat.
- **OPEN: buy one known-good reference module.** Waveshare bundles an OV5647
  camera with the P4-NANO kit against the same 15-pin CSI connector family
  (https://www.waveshare.com/wiki/ESP32-P4-Nano-StartPage), so that module is
  presumptively 24 MHz and Espressif-driver-clean. Recommendation: buy one
  (about 10 USD). Having a known-good module turns every future "is it the
  camera or the firmware" question into a two-minute swap, and it is the module
  the documentation should recommend to users who do not already own a
  SeedSigner.

### 1.8 Abort criteria, consolidated

Stop and power down immediately on:

- any heat, smell, or discoloration at the module or the 4B 3V3 regulator;
- brownout, reboot loop, or the board failing to enumerate its serial bridge;
- 3V3-to-GND resistance at or near zero with the camera attached (check 3);
- the board behaving differently in any way that was not present before the
  camera was plugged in.

Do **not** abort, and do keep going, on:

- no I2C ACK at 0x36. Harmless. Causes, in order of likelihood: wrong contact
  side at one end; a clone that routes its enable to pin 12 (which floats on
  this board - R48 NC) instead of pin 11 (held high by R47); not an OV5647.
- garbage or torn frames with a healthy I2C ID read. That is a configuration
  question - clock (1.7), lane count, or Bayer order - not a hardware fault.
- touch getting flaky. Drop the bus to 100 kHz and re-test before concluding
  anything.

Record every outcome, including the "worked first time" case, in
docs/research/ so the next person does not repeat the measurements.

---

## 2. The ESP-IDF software stack

### 2.1 Components, versions, and the dependencies we do not want

Registry state verified 2026-08-17 through the component API:

| Component | Latest | What we take | Note |
|---|---|---|---|
| `espressif/esp_video` | **2.3.0** (2026-06-30) | the V4L2-style capture framework, CSI device, ISP device | requires **idf >= 5.4**; we are on 5.5 |
| `espressif/esp_cam_sensor` | 2.4.0 (2026-08-14) | OV5647 MIPI driver | **esp_video 2.3.0 pins `esp_cam_sensor 2.3.*`**, so adding esp_video gets 2.3.0, not 2.4.0 |
| `espressif/esp_ipa` | 2.2.0 | AE/AWB algorithms behind the ISP pipeline controller | pulled by esp_video 2.3.0 as `2.2.*`, P4 only |
| `espressif/esp_h264` | 1.3.0 | **nothing** | pulled unconditionally on P4 |
| `espressif/usb_host_uvc` | 2.5.* | **nothing** | pulled on P4/S3/S31 |
| `espressif/cmake_utilities` | 0.* | build glue | already in our lock file |

Correction to CAMERA.md 2.4, which pairs esp_video 2.2.0 with esp_cam_sensor
2.4.0: the manifest does not allow that pairing. **DECISION:** pin
`espressif/esp_video` at `=2.3.0` and let the manifest resolve
`esp_cam_sensor 2.3.0` and `esp_ipa 2.2.0`; record all three hashes in
`firmware/components_esp32p4.lock` exactly as the display components are
recorded today. Never float a `^` on the camera stack - it is the one part of
the image that parses attacker-adjacent data.

Three dependency-graph problems, each with a fix:

1. **`usb_host_uvc` is a hard dependency of `esp_video` on the P4** (rule:
   `target in [esp32p4, esp32s3, esp32s31]`, no Kconfig condition on the
   dependency itself). This is precisely the USB host stack CAMERA.md section 4
   rejected. The device shim is not compiled -
   `CONFIG_ESP_VIDEO_ENABLE_USB_UVC_VIDEO_DEVICE` defaults **n** and gates
   `src/device/esp_video_usb_uvc_device.c` in esp_video's CMakeLists - but the
   component itself would be downloaded into the tree and compiled.
   **DECISION:** ship a **local stub component** at
   `firmware/components/usb_host_uvc/` containing an empty
   `idf_component_register()` and a one-paragraph README explaining why. A
   component in the project's `components/` directory has the highest priority
   in the IDF build system and overrides a managed component of the same name
   (https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-guides/build-system.html,
   https://docs.espressif.com/projects/idf-component-manager/en/latest/reference/manifest_file.html).
   The USB host stack then never enters the source tree, never compiles, and
   cannot be enabled by a stray Kconfig edit. Same treatment for `esp_h264`
   (`CONFIG_ESP_VIDEO_ENABLE_H264_VIDEO_DEVICE` defaults n; we encode no video).
2. **`esp_video` declares `REQUIRES lwip`** (`esp_video/CMakeLists.txt`:
   `set(requires "esp_driver_cam" "esp_cam_sensor" "lwip")`). A TCP/IP stack in
   an airgapped signer's requirement graph is exactly the thing SECURITY.md
   invariant 1's build-graph check exists to catch. It is almost certainly a
   header-path dependency (`sys/ioctl.h`, which V4L2's ioctl surface needs) and
   not a functional one, and unreferenced archive members do not link - but
   "almost certainly" is not a claim we make. **DECISION:** the m-camera build
   gate is a **link-map assertion**: the produced `.map` must contain no lwip
   object (no `sockets.o`, `tcp*.o`, `ip4*.o`, `netif*.o`, `dhcp*.o`) and no
   `usb_host`/`uvc_host` symbol. The check is a script in `tools/`, runs in CI
   next to the existing build-graph check, and its output goes on the release
   manifest. If lwip objects do link, the camera does not ship until we know
   exactly which symbol pulled them in.
3. **esp-idf-sys metadata cannot be feature-gated** - already documented in
   `firmware/Cargo.toml`: "every board build compiles all components and carries
   all bindings". So adding esp_video puts its C sources into every board's
   build, including boards with no camera connector. Handled in section 6.

### 2.2 sdkconfig

New lines, split the way BOARDS.md already splits them. Base file (nothing
board-specific, nothing naming a GPIO):

```
# --- Camera (0.2.0) ----------------------------------------------------------
# CSI is the only capture path. Everything else esp_video can build is off,
# and the two components behind the off switches are stubbed out of the tree
# entirely (firmware/components/usb_host_uvc, .../esp_h264) - see CAMERA-HW.md.
CONFIG_ESP_VIDEO_ENABLE_MIPI_CSI_VIDEO_DEVICE=y     # default y; stated, not inherited
CONFIG_ESP_VIDEO_ENABLE_DVP_VIDEO_DEVICE=n          # DEFAULTS TO y - must be turned off
CONFIG_ESP_VIDEO_ENABLE_SPI_VIDEO_DEVICE=n
CONFIG_ESP_VIDEO_ENABLE_USB_UVC_VIDEO_DEVICE=n
CONFIG_ESP_VIDEO_ENABLE_HW_H264_VIDEO_DEVICE=n
CONFIG_ESP_VIDEO_ENABLE_HW_JPEG_ENC_VIDEO_DEVICE=n
CONFIG_ESP_VIDEO_ENABLE_HW_JPEG_DEC_VIDEO_DEVICE=n
CONFIG_ESP_VIDEO_ENABLE_ISP_VIDEO_DEVICE=y
# Auto-exposure. DEFAULTS TO n; without it a scan works only in one light level.
CONFIG_ESP_VIDEO_ENABLE_ISP_PIPELINE_CONTROLLER=y
CONFIG_ISP_PIPELINE_CONTROLLER_TASK_STACK_USE_PSRAM=y
CONFIG_ESP_VIDEO_CHECK_PARAMETERS=y                 # keep the C-side arg checks

# Sensor: OV5647 only, one mode only.
CONFIG_CAMERA_OV5647=y
CONFIG_CAMERA_OV5647_MIPI_RAW8_800X640_50FPS=y
CONFIG_CAMERA_OV5647_MIPI_DEFAULT_FMT_RAW8_800X640_50FPS=y
CONFIG_CAMERA_OV5647_MIPI_RAW8_800X800_50FPS=n      # DEFAULTS TO y
CONFIG_CAMERA_OV5647_MIPI_RAW8_800X1280_50FPS=n
CONFIG_CAMERA_OV5647_MIPI_RAW10_1920X1080_30FPS=n
CONFIG_CAMERA_OV5647_MIPI_RAW10_1280X960_BINNING_45FPS=n
CONFIG_CAMERA_OV5647_CSI_LINESYNC_ENABLE=y
# No VCM on a Pi v1.3 module, and pin 11 is strapped high by R47 on this board.
CONFIG_CAMERA_OV5647_ENABLE_MOTOR_BY_GPIO0=n
CONFIG_CAMERA_OV5647_AUTO_DETECT_MIPI_INTERFACE_SENSOR=y
```

Two of these override an Espressif default in the direction that shrinks the
image (`DVP=y` and the 800x800 mode `=y` are both upstream defaults). Any future
component bump must re-check the defaults, because a silently re-enabled DVP
device is a silently larger attack surface.

Two options deliberately left alone:
`CONFIG_ESP_VIDEO_DISABLE_MIPI_CSI_DRIVER_BACKUP_BUFFER` stays at its default y
(the driver reserves one of our queued buffers instead of allocating its own,
which is why the buffer count must be > 1), and
`CONFIG_ESP_VIDEO_DISABLE_ISP_ERROR_INTERRUPT` stays **off** - ISP error
interrupts are how a marginal D-PHY link (see 1.7) announces itself, and
silencing them during bring-up would hide exactly the evidence we need.

### 2.3 Sensor mode and ISP pipeline: chosen for decode, not for pixels

**DECISION: 800x640, RAW8, 50 fps** (`CAMERA_OV5647_MIPI_RAW8_800X640_50FPS`),
ISP output **UYVY422**.

Why not more resolution:

- QR decoding needs modules, not megapixels. A version-13 code (69x69 modules)
  filling 80% of the 640-pixel axis gives 512/69 = 7.4 pixels per module;
  version 20 (97x97) gives 5.3. quirc-class decoders work reliably from about 3.
  1920x1080 buys nothing a decoder can use and costs 3.2x the bandwidth, 3.2x
  the memory, and 3.2x the CPU per frame.
- Latency is the actual user-facing metric. Animated UR2/BBQr streams display at
  5-10 fps; a decoder that takes 200 ms per frame misses half the parts and the
  fountain has to loop. Small frames are what makes the loop close.
- 800x640 is the smallest mode the Espressif driver ships for this sensor and is
  4:5-ish, close to the 720x720 panel's aspect, which keeps the preview honest.
- The 1920x1080 and 1280x960 modes are RAW10, which changes the ISP input
  format for no decode benefit. The ISP's documented input ceiling is 1920x1080
  anyway (CAMERA.md 2.4).

Why UYVY422 out of the ISP:

- The ISP's non-bypass output set is exactly RAW8, RGB565, RGB888, YUV420 and
  UYVY (`esp_video/src/device/esp_video_csi_format.c`, `isp_output_formats[]`).
  `V4L2_PIX_FMT_GREY` appears in the CSI format tables but only as a
  sensor-native/bypass format - the ISP cannot emit it from a Bayer input, so
  "ask the ISP for grayscale" is not available.
- UYVY has an unambiguous, documented byte layout - `COLOR_PIXEL_UYVY422`:
  "(lowest byte) U0-Y0-V0-Y1 (highest byte)"
  (esp-idf `components/hal/include/hal/color_types.h`) - so the luma plane is
  every odd byte, no guessing. The IDF ISP documentation does **not** state
  whether its YUV420 output is planar or semi-planar, which makes YUV420 a
  buffer-layout question we would have to settle on the bench for no gain.
- UYVY is a first-class **PPA SRM input**, and GRAY8 is a first-class PPA SRM
  **output** (`components/hal/include/hal/ppa_types.h`:
  `PPA_SRM_COLOR_MODE_YUV422_UYVY`, `PPA_SRM_COLOR_MODE_GRAY8`; the
  RGB888-to-GRAY8 weights are configurable via `ppa_set_rgb2gray_formula()`).
  That is the whole grayscale-conversion-and-downscale stage done in hardware -
  see 3.3.

Fallbacks, in order, if UYVY-in/GRAY8-out does not behave:
(a) UYVY plus a software odd-byte gather (one pass, ~1 MB read / 0.5 MB write);
(b) RGB565 out of the ISP plus PPA RGB565-to-GRAY8;
(c) RAW8 ISP bypass, treating the Bayer mosaic as luma - legitimate for a
black-and-white target, and a 2x2 quad average both removes the colour-filter
modulation and halves the resolution in one step. Keep (c) documented: it is the
lowest-bandwidth path in the whole design (512 KB/frame, no ISP) and may end up
the right answer if bandwidth turns out to be the binding constraint.

Auto-exposure is not optional. A QR target is high-contrast, and a signer gets
used under a desk lamp, in daylight, and in a dim room in the same week. The ISP
pipeline controller plus esp_ipa provides AE/AWB from ISP statistics; we enable
it, and we accept the "isp_task" it creates (stack in PSRAM). AWB is irrelevant
to a grayscale consumer but harmless; the preview looks better for it.

### 2.4 Buffers, placement and the memory budget

esp_video allocates CSI capture buffers with
`MALLOC_CAP_8BIT | MALLOC_CAP_SPIRAM | MALLOC_CAP_CACHE_ALIGNED` when SPIRAM is
enabled (`esp_video_csi_device.c`, `CSI_MEM_CAPS`), which is where we want them.
`CONFIG_CACHE_L2_CACHE_LINE_128B=y` is already in
`firmware/sdkconfig.base.defaults`, so any buffer we allocate ourselves for a
DMA or PPA destination must be 128-byte aligned.

**DECISION: 3 buffers, `V4L2_MEMORY_MMAP`.** Espressif's `capture_stream`
example uses 2 (`BUFFER_COUNT 2`); with the driver's backup buffer disabled the
driver holds one of them, so 2 leaves the application exactly one, and a
decode that runs longer than a frame period stalls capture. Three gives
one filling, one queued, one under decode. `MMAP` because the driver's own
allocation already has the right caps and alignment; `USERPTR` (64-byte
alignment, our allocation) stays available if we later need the frames somewhere
specific.

Memory, Waveshare 4B, 720x720 panel, camera session active:

| Allocation | Bytes | Note |
|---|---|---|
| DPI driver framebuffer (PSRAM) | 1,036,800 | 720x720x2, exists today |
| notyas back buffer (PSRAM) | 1,036,800 | 720x720x2, exists today |
| V4L2 capture buffers, 3 x UYVY 800x640 | 3,072,000 | session-lifetime |
| PPA GRAY8 output, 2 x 800x640 | 1,024,000 | double-buffered, session-lifetime |
| rqrr working image, 800x640 | 512,000 | **per frame, allocated by rqrr** (3.4) |
| Preview RGB565 400x320 | 256,000 | session-lifetime |
| UR fountain decoder (boxed) | ~430,000 | bounded by const generics (3.5) |
| **Session total** | **~7.37 MB** | of 32 MB PSRAM |
| Non-session steady state | 2,073,600 | unchanged from 0.1.0 |

Everything except the two existing framebuffers is allocated when a scan session
starts and freed when it ends. A device that never scans pays nothing, which
also means a camera-related allocation failure can never brick the signing flow.

Internal SRAM (768 KB total on the P4, plus 32 KB LP SRAM and 8 KB scratchpad -
https://documentation.espressif.com/esp32-p4_datasheet_en.html) carries only
driver structures, DMA descriptors and task stacks. Two stack notes, both
learned the hard way in 0.1.0 (the base sdkconfig comment about the 8 KB main
stack and the mid-selftest stack-protection faults): the decode task gets its
own generous stack, and its high-water mark is measured and logged, not
guessed - see 3.6.

**PSRAM bandwidth is the real budget, not capacity.** Steady state during a
scan, at 720x720/60 Hz panel and 800x640/50 fps capture:

| Consumer | MB/s | Note |
|---|---|---|
| DSI scan-out (read) | 62.2 | continuous, unavoidable while the panel is on |
| CSI+ISP capture (write) | 51.2 | continuous while streaming, see below |
| PPA gray + preview at 10 fps | ~28 | 1.5 MB and 1.3 MB moved per frame |
| rqrr passes at 10 fps | ~20 | copy-in plus threshold and detect passes |
| **Total** | **~160** | must be measured against the real ceiling |

Espressif is explicit that PPA throughput "highly relies on the PSRAM bandwidth"
and degrades when several peripherals hit PSRAM at once
(https://docs.espressif.com/projects/esp-idf/en/v5.5/esp32p4/api-reference/peripherals/ppa.html).
Honest statement of the mechanism: **the CSI writes every frame the sensor
produces for as long as the stream is on**, regardless of how many we consume -
holding buffers back does not reduce write traffic, because the driver keeps a
reception buffer. The levers are therefore (1) the sensor mode, (2) stream
on/off, (3) the ISP output format (YUV420 would be 38.4 MB/s instead of 51.2,
RAW8 bypass 25.6), and (4) how often we run the PPA and the decoder. The
mitigation ladder in 3.6 is ordered by those levers.

### 2.5 Coexisting with the GT911 on the shared I2C bus

Today `touch_init()` creates the `i2c_master` bus on GPIO7/GPIO8 inside itself
and drops the handle (`firmware/src/board/waveshare_4b.rs`). Camera init needs
that same bus.

**DECISION: the board module owns the bus.** Add to the board surface described
in BOARDS.md:

```rust
/// The shared I2C master bus (touch, camera SCCB, and the audio codecs we
/// never talk to). Created once, on first call; never deleted.
pub fn shared_i2c_bus() -> sys::i2c_master_bus_handle_t;
```

`touch_init()` takes it instead of creating it; camera init passes it to
esp_video. This is a small refactor of existing, hardware-verified code and it
removes a hidden singleton, so it lands early (m-camera-1) rather than beside
the camera work.

Handing esp_video an existing bus is a supported, first-class path:

```rust
let sccb = esp_video_init_sccb_config_t {
    init_sccb: false,                    // we own the bus
    __bindgen_anon_1: { i2c_handle },    // board::shared_i2c_bus()
    freq: 100_000,                       // SCCB device speed, see below
};
let csi = esp_video_init_csi_config_t {
    sccb_config: sccb,
    reset_pin: -1,                       // not routed on the 4B
    pwdn_pin: -1,                        // not routed on the 4B
    dont_init_ldo: true,                 // display_init() already holds ch3 (2.6)
};
```

(`esp_video/include/esp_video_init.h`: "false: SCCB I2C is initialized and
esp_video_init function can use i2c_handle directly".)

Why the speed is not a conflict: esp_video turns `sccb_config.freq` into the
**per-device** `scl_speed_hz` of a new I2C device on the bus
(`esp_video_init.c`: `sccb_i2c_config.scl_speed_hz = sccb_config->freq`). The
IDF `i2c_master` driver clocks each device at its own rate on a shared bus, so
the camera can run at 100 kHz while the GT911 keeps its 400 kHz. **DECISION:**
start the camera at 100 kHz. It costs about 3 ms of extra time across the whole
OV5647 register table, once, at session start, and it removes bus timing from
the list of things that can be wrong during bring-up. Raise it to 400 kHz only
if a measurement says it matters.

Address map on this bus, for the record: GT911 at 0x5D (0x14 fallback), OV5647
at 0x36, ES8311 at 0x18 and ES7210 at 0x40-0x43 (present on the board, never
initialized by notyas). No collisions.

Ordering and arbitration:

- Boot order is unchanged: radio lockdown, LDOs, display, `shared_i2c_bus()`,
  GT911 reset and probe. **The camera is not initialized at boot.**
- `esp_video_init()` runs when the user opens a scan screen and
  `esp_video_deinit()` runs when the session ends. The GT911's one-shot reset
  pulse therefore never overlaps an SCCB transaction, because it happened
  hundreds of milliseconds before any camera code existed.
- The IDF `i2c_master` driver serializes transactions per bus, so touch polling
  (every UI tick) and the SCCB burst at session start interleave safely. The
  cost is that a touch poll can block behind an SCCB write; at 100 kHz the
  longest single SCCB transaction is well under a millisecond.

### 2.6 LDO channel 3 and the DSI display

Both the DSI D-PHY and the CSI D-PHY sit on VDD_MIPI_DPHY, fed by internal LDO
channel 3 at 2500 mV. `display_init()` acquires it and never releases it; the
esp_video CSI device would acquire the same channel at the same voltage.

**DECISION: `dont_init_ldo = true` on the Waveshare 4B**, with the invariant
stated in the board module: *the camera requires the display to be up, because
the display owns the D-PHY rail for the whole power cycle*. IDF's
reference-counted fixed channels would also make `false` work, but depending on
refcount semantics for a power rail is a subtler contract than "one owner, taken
at boot, never released", which is what `display.rs` already documents. It also
makes the flag a per-board constant with an obvious value on boards whose
display is not DSI: an Elecrow 5inch (parallel RGB, ch3 unused by the display -
BOARDS.md) would need `dont_init_ldo = false`, exactly as Elecrow's own factory
firmware acquires ch3 for its camera.

### 2.7 Bindings

One more `extra_components` entry in `firmware/Cargo.toml`, in the established
style:

```toml
[[package.metadata.esp-idf-sys.extra_components]]
remote_component = { name = "espressif/esp_video", version = "=2.3.0" }
bindings_header = "bindings/camera.h"
```

with `firmware/bindings/camera.h` including `esp_video_init.h`,
`linux/videodev2.h`, `esp_cam_sensor.h` and `driver/ppa.h`. Note that V4L2 is
used through `open`/`ioctl`/`mmap` on `/dev/video0`, which the esp_video VFS
layer registers - so the Rust side is `libc`-shaped, not a rich binding surface.
The `esp_video_init_*` config structs and the `V4L2_*` constants are what
bindgen has to produce; the ioctl calls themselves are three `unsafe` lines in
one module.

---

## 3. The Rust layer

### 3.1 Crate boundary

The governing constraint is one this document did not get to choose: **rqrr
requires std.** `src/lib.rs` uses `std::error::Error` and `std::io::Write`, and
there is no `no_std` feature (rqrr 0.10.1,
https://github.com/WanzenBug/rqrr/blob/master/Cargo.toml). It therefore cannot
live in `notyas-core` or `notyas-wallet`, both of which are `#![no_std]` by
charter (ARCHITECTURE.md 1).

That is a feature, not an obstacle, because it forces the boundary to be in the
right place:

```
firmware/src/camera/          std, esp-idf. Owns: esp_video lifecycle, V4L2
                              ioctls, PPA client, the decode task, rqrr.
                              Produces: Vec<u8> payloads and nothing else.
                              Knows nothing about bitcoin.

notyas-wallet::transport      no_std + alloc. Owns: the ingress validator
  (new module, existing crate) (section 5.2), UR2 fountain assembly, BBQr
                              join, SeedQR decode, transport autodetect.
                              Consumes: &[u8] payloads. Produces: a completed
                              message plus progress facts. Host-testable and
                              host-fuzzable with no camera and no IDF.

notyas-ui                     no_std. Owns: the scan screen state machine.
                              Consumes: the progress facts (section 4).
```

The camera module is a **deep module with a small interface** in the
Philosophy-of-Software-Design sense: a substantial implementation (three C
components, a hardware pipeline, a task) behind roughly this surface:

```rust
pub struct ScanSession { /* owns everything: video fd, buffers, PPA, task */ }

pub enum ScanEvent {
    Payload(Vec<u8>),           // one QR decoded, raw bytes, unvalidated
    Preview(PreviewFrame),      // downscaled RGB565, for the viewfinder
    NoCamera,                   // probe failed; session never started
    Fault(CameraFault),         // hardware or driver error, plain-word mapped
}

impl ScanSession {
    pub fn start() -> Result<Self, CameraFault>;
    pub fn poll(&mut self) -> Option<ScanEvent>;   // non-blocking, main loop
    pub fn stats(&self) -> ScanStats;              // fps, frames seen, decodes
}
impl Drop for ScanSession { /* STREAMOFF, deinit, free, sensor idle */ }
```

`Drop` doing the teardown is deliberate: "the camera is off unless a session
object is alive" then holds by construction, including on the error and panic
paths, which is the property section 5.7 wants to be able to state.

### 3.2 The frame path

```
V4L2 VIDIOC_DQBUF  -> UYVY422 800x640 in PSRAM (driver buffer)
   |
   +-- PPA SRM: UYVY422 in -> GRAY8 out, scale 1.0 (or 0.5)   [hardware]
   |      -> gray buffer, 128-byte aligned PSRAM, double-buffered
   |
   +-- PPA SRM: UYVY422 in -> RGB565 out, scale 0.5           [hardware, preview]
   |      -> preview buffer, handed to the UI as-is
   |
 VIDIOC_QBUF (buffer returned to the driver immediately after both PPA passes)
   |
 rqrr::PreparedImage::prepare_from_greyscale(w, h, |x, y| gray[y*w + x])
   -> detect_grids() -> grid.decode_to(&mut Vec<u8>)
   -> ScanEvent::Payload(bytes)
```

The driver buffer is requeued as soon as the PPA passes complete, so the decode
never holds capture memory hostage.

### 3.3 The PPA assist, precisely

`ppa_do_scale_rotate_mirror()` with `in.srm_cm = PPA_SRM_COLOR_MODE_YUV422_UYVY`
and `out.srm_cm = PPA_SRM_COLOR_MODE_GRAY8` is the entire
colour-conversion-plus-downscale stage. Facts and caveats:

- Scaling precision is a step of 1/16, and transaction time is proportional to
  the data moved, not to picture size
  (https://docs.espressif.com/projects/esp-idf/en/v5.5/esp32p4/api-reference/peripherals/ppa.html).
  So 1.0 and 0.5 are both exactly representable and 0.5 costs a quarter of the
  writes.
- Output buffers in PSRAM must be aligned to the L1 **and** L2 cache line size
  (the header says so explicitly); with `CACHE_L2_CACHE_LINE_128B=y` that means
  `heap_caps_aligned_alloc(128, ..., MALLOC_CAP_SPIRAM | MALLOC_CAP_CACHE_ALIGNED)`.
- The gray weights are global state (`ppa_set_rgb2gray_formula`, weights summing
  to 256). Set them once at session start; BT.601 luma (77/150/29) is the
  sensible default, and for a black-and-white target any sane weighting works.
- **Must be verified on hardware**: that the PPA accepts a YUV-space input with
  a GRAY8 output in one transaction. The type table permits it and nothing in
  the docs forbids it, but this is an internal-datapath question and the fallback
  ladder in 2.3 exists for the case where it does not.
- Use `PPA_TRANS_MODE_NON_BLOCKING` with the completion callback feeding the
  decode task, so the PPA overlaps the previous frame's decode.

### 3.4 rqrr specifics

Version 0.10.1, license `(MIT OR Apache-2.0) AND ISC` (the ISC part is the quirc
lineage) - all compatible with our GPL-3.0-or-later firmware. Dependencies are
`g2p` and `lru`, both small. Four things the integration has to know:

1. **It allocates one `w*h` byte buffer per prepared image and there is no way
   to reuse one.** `prepare_from_greyscale` builds a `Vec` and boxes it
   (`src/prepare.rs`); the `ImageBuffer` trait that would let us supply our own
   buffer exists but is not re-exported from the crate root (`mod prepare;` is
   private in `src/lib.rs`), so the only alternative constructor is the one
   behind the `img` feature, which drags in the `image` crate. At 800x640 that
   is a 512,000-byte PSRAM allocation and free per decoded frame. Measurable,
   probably fine, and worth an upstream PR - exporting `ImageBuffer` plus a
   `prepare_in(buffer)` constructor is a small, obviously-useful change and fits
   PLATFORM.md's "upstream the quirk, do not fork" pattern.
2. **Decode to bytes, not to `String`.** `Grid::decode()` does
   `String::from_utf8(out)?` internally; `Grid::decode_to<W: Write>(writer)`
   gives the raw decoded bytes with the same metadata. Use `decode_to` into a
   `Vec<u8>`. Its documented warning - "this may lead to half decoded content to
   be written to the writer" - means the payload buffer is only meaningful when
   the call returns `Ok`, which the ingress validator enforces anyway.
3. **Build with `default-features = false`.** The default `img` feature pulls
   the `image` crate for no benefit here.
4. **`f64` in the geometry.** rqrr's perspective mapping uses `f64`
   (`SkewedGridLocation`, `grid_size as f64`). Our target is
   `riscv32imafc-esp-espidf` - the `F` extension is single precision; **there is
   no `D` extension on the P4**, so every `f64` operation is soft-float. This is
   per-sampled-module work, so it scales with QR version squared. It is very
   likely fine and it is exactly the kind of thing that must be measured rather
   than assumed (3.6). If it dominates, the fix is an upstream `f32` geometry
   option, not a fork.

Fallback if rqrr cannot hit the budget: Espressif's `quirc` component
(https://components.espressif.com/components/espressif/quirc), at the cost of
adding C to the trusted computing base on the payload path - which is a real
cost here, because this is the one code path that parses attacker-controlled
data before any of our own validation runs. Recorded as the fallback, not the
plan. zbar is not considered.

### 3.5 Transport decoders

Per ARCHITECTURE.md 1, which already picked these for the outbound direction; the
inbound direction uses the same crates:

- **UR2 / `ur:crypto-psbt` - `foundation-ur` 0.4.0 (MIT), `default-features =
  false`** (`std` is a default feature). Use **`HeaplessDecoder`**, not the
  allocating `Decoder`:
  `HeaplessDecoder<MAX_MESSAGE_LEN, MAX_MIXED_PARTS, MAX_FRAGMENT_LEN,
  MAX_SEQUENCE_COUNT, QUEUE_SIZE, MAX_UR_TYPE>`. Every bound is a const
  generic, so the worst case is a compile-time number rather than a runtime
  allocation an attacker chooses. Approximate footprint:
  `MAX_MESSAGE_LEN + (QUEUE_SIZE + MAX_MIXED_PARTS) * (MAX_FRAGMENT_LEN +
  8*MAX_SEQUENCE_COUNT)`. Worked example with MAX_MESSAGE_LEN 128 KiB,
  MAX_FRAGMENT_LEN 512, MAX_SEQUENCE_COUNT 512, QUEUE_SIZE 32, MAX_MIXED_PARTS
  32: about 128 KiB + 64 * 4.5 KiB = ~420 KiB. That does not go on a stack: the
  decoder is boxed into PSRAM at session start, and a `const _: () =
  assert!(size_of::<UrDecoder>() < LIMIT);` pins it so a later constant bump
  cannot silently blow the budget. Constants get their final values in
  m-camera-4, driven by the largest PSBT we commit to accepting.
- **BBQr - `bbqr` 0.6.0 (MIT)**, std-oriented, which is fine on the firmware
  side of the boundary. Coldcard-family interop (https://bbqr.org/).
- **SeedQR / CompactSeedQR - no Rust crate exists.** PLATFORM.md item 3 proposes
  writing one; this is its first consumer. Small surface (11-bit index packing),
  validated against SeedSigner's published vectors
  (https://github.com/SeedSigner/seedsigner/blob/dev/docs/seed_qr/README.md).
- **Plain text** - BIP39 words, a descriptor, an address, an xpub. No framing.

Autodetect order is prefix-driven and total: `ur:` prefix -> UR; `B$` header ->
BBQr; all-digits and length in {48, 96, 132, 156, 192, 264} -> SeedQR; otherwise
plain text subject to the charset rule in 5.4. Anything unmatched is rejected
with a screen, never guessed at.

### 3.6 CPU budget: what is known, what is arithmetic, and what must be measured

**Known, from other people's hardware:**

- Espressif's ESP32-S3 QR demo measures roughly 22 ms per frame of scan overhead
  at 240 MHz (https://github.com/espressif/qrcode-demo).
- quirc's own benchmark is about 50 ms for VGA extract-plus-decode on a modern
  x86 core (https://dlbeer.co.nz/oss/quirc.html).
- SeedSigner ships usable animated-UR scanning on a 1 GHz single-core Pi Zero
  (https://github.com/SeedSigner/seedsigner).

**Arithmetic that follows from this design:** the P4 is dual-core RISC-V at
400 MHz; the grayscale conversion and downscale cost zero CPU (PPA); the
capture costs zero CPU (CSI+ISP DMA). What remains on the CPU is rqrr's copy-in,
adaptive threshold, capstone detection, grid fitting and Reed-Solomon decode over
a 512,000-pixel image, plus soft-float geometry. Pinning the decode task to core
1 leaves core 0 for the UI, touch and the display flush.

**None of that is a measurement of this system, and the document does not
pretend otherwise.** The numbers that must be produced, on the bench, before any
scanning UX is designed around them:

| Measurement | How | Gate |
|---|---|---|
| PPA UYVY->GRAY8 time, 800x640 at scale 1.0 and 0.5 | `esp_timer` around a blocking transaction, 100 iterations | informational; feeds the choice of scale |
| rqrr `prepare_from_greyscale` alone | same, on a fixed test image in PSRAM | informational; isolates the forced allocation and the copy |
| rqrr `detect_grids` with no code present | worst case is an empty scene, which is the common case | must not dominate; this runs on every frame |
| rqrr full decode, QR versions 5 / 13 / 20 | printed targets at a fixed distance | end-to-end budget input |
| Decode-task stack high-water mark | `uxTaskGetStackHighWaterMark` after 1000 frames | must leave >= 50% headroom (0.1.0's stack-fault history) |
| PSRAM bandwidth headroom | frame rate achieved with the panel live versus with the backlight off and no flush | tells us whether 2.4's ~160 MB/s estimate is near the ceiling |
| **End-to-end**: decode attempts per second with the panel live and a preview running | count `ScanEvent`s over 60 s | **>= 8 attempts/s. This is the gate.** |

Mitigation ladder if the end-to-end gate fails, in order (each step is cheap and
reversible, and each is a lever identified in 2.4):

1. PPA scale 0.5 - decode at 400x320 (128 KB working image, quarter the CPU).
   Costs QR version headroom; re-run the version-20 target to see what is lost.
2. Preview at 5 fps instead of matching the decode rate, or derive the preview
   from the gray buffer instead of a second PPA pass.
3. ISP output YUV420 (38.4 MB/s instead of 51.2) once its layout is confirmed on
   the bench, or RAW8 bypass (25.6 MB/s, and 2.3's option (c)).
4. Swap rqrr for the `quirc` C component, accepting the TCB cost.

If step 4 is reached, that is a finding worth writing up, not a quiet
substitution: it would mean the pure-Rust QR decoding story on this class of
hardware needs work, which is a PLATFORM.md-shaped contribution.

---

## 4. The scanning UX contract

This section specifies what the camera subsystem owes the UI and what the UI
owes the camera subsystem. It deliberately specifies no screens: the screen
inventory, layout and wording live in **UX-SCREENS.md**, and UX.md's ten
commandments govern both.

### 4.1 What the UI gets

`ScanSession::poll()` returns at most one event per call and never blocks, so it
drops into the existing input-driven main loop (extended with the tick that
ARCHITECTURE.md 6 already adds for hold-to-confirm and animated QR).

```rust
pub struct ScanStats {
    pub frames_captured: u32,      // since session start
    pub decode_attempts: u32,      // frames actually run through rqrr
    pub decodes_ok: u32,           // QRs read (including duplicates)
    pub fps_decode: u8,            // rolling, 2 s window
    pub exposure_ok: bool,         // ISP AE has converged
}

pub enum Progress {
    Idle,                                   // nothing recognized yet
    Single,                                 // a static QR - one frame is the whole payload
    Fountain { seen: u16, total: u16, percent: u8, transport: Transport },
}
```

- **Live preview: yes, and it is not decoration.** A user aiming a fixed-focus
  camera at a phone screen needs to see framing, distance and glare. Without a
  viewfinder, a failed scan is unattributable. The preview is a downscaled
  RGB565 frame the UI blits into a region it chooses; the camera subsystem does
  not draw.
- **Frame-rate feedback: as a health line, not a number to admire.** The UI
  shows a plain-word status derived from `ScanStats` - "hold steadier",
  "too dark", "move closer" - not "9.4 fps". `exposure_ok == false` for more
  than about two seconds is the "too dark / too bright" case; `decodes_ok == 0`
  with good exposure for more than about five seconds is the "move closer or
  further" case. UX.md commandment 10 applies to scanning failures exactly as it
  applies to refusals.
- **Fountain progress: `seen of total`, plus a percentage.** For UR2 the part
  header carries `seqNum-seqLen` in plain text (`ur:crypto-psbt/12-40/...`), so
  the camera subsystem counts distinct simple-part indexes itself rather than
  relying on the decoder. That is not laziness: `foundation-ur`'s
  `BaseDecoder` exposes only `is_complete()` and
  `estimated_percent_complete()`, the underlying received-index set is private,
  and the percentage formula multiplies raw progress by 1.2 and caps at 0.99
  (`ur/src/fountain/decoder.rs`), so it deliberately over-reports. **DECISION:**
  display our own `seen / total` as the primary indicator and use
  `estimated_percent_complete()` only as the bar fill, with the honest note that
  fountain decoding can complete before `seen == total` (that is what a fountain
  code is for) and can also need more than `total` frames when parts are missed.
  A progress indicator that can go from "38 of 40" to done in one frame is
  correct behavior and the UI copy should not imply otherwise.
- **Transport identity is shown.** "Reading an animated PSBT (UR)" versus
  "Reading a BBQr" versus "Reading a SeedQR" tells the user immediately if they
  are pointing the camera at the wrong thing.

### 4.2 Session lifecycle

| Transition | Trigger | Behavior |
|---|---|---|
| start | user opens a scan screen (an explicit action, never automatic) | probe 0x36; `esp_video_init`; allocate; STREAMON; preview begins within ~500 ms or the screen says why |
| abort | Cancel, back gesture, or hardware button | `Drop` runs: STREAMOFF, deinit, buffers freed, partial fountain state zeroized |
| timeout, inactivity | no successful decode for **60 s** | session ends with a plain-word screen offering retry or the SD path |
| timeout, stall | a fountain started but no **new** part for **30 s** | session ends; partial payload discarded, not held |
| completion | validator reports a complete message | STREAMOFF immediately, then hand off; the camera is off during review and signing |
| lock | auto-lock timer, or any navigation away | session ends first, then the lock proceeds |
| fault | driver or hardware error | session ends; the message names the stage (probe / init / stream / decode), never an `esp_err` hex code on the primary line |

Two rules that are security posture as much as UX:

- **The camera streams only while a scan screen is on top.** Not during review,
  not during signing, not on the wallet home, never in the background. This is
  enforced by ownership (3.1), not by discipline.
- **No auto-start.** A signer that turns its camera on by itself is a signer
  whose users cannot tell when it is watching. Every session is a deliberate
  user action, and the SD path (ARCHITECTURE.md 5.4) remains available for
  everything the camera can do, so nobody is forced through it.

### 4.3 Coordination points with UX-SCREENS.md

The camera subsystem needs exactly these five things from the screen layer, and
nothing about their arrangement is decided here:

1. A viewfinder region: any rectangle; the subsystem scales the preview to fit
   whatever it is told, at integer PPA scale steps.
2. A status line fed from `ScanStats` in plain words.
3. A progress element fed from `Progress` that can render both the `seen/total`
   pair and a bar.
4. A cancel affordance reachable at all times, per UX.md commandment 7.
5. A failure surface, sharing the refusal-screen treatment UX.md commandment 10
   already mandates, with an explicit "use the SD card instead" exit -
   commandment 9's SD-when-QR-fails, in the inbound direction.

Also worth naming for UX-SCREENS.md: the physical ergonomics. A Pi v1.3 module
is **fixed focus**, typically glued near 1 m, and needs its barrel rotated for
10-25 cm work (1.2). Whatever enclosure or mounting the project recommends,
first-run documentation has to tell the user to focus the lens, and the scan
screen is where they will discover they have not.

---

## 5. Security analysis: a camera is an input channel

Everything before this section is about making a camera work. This section is
about what it lets an attacker do once it does.

### 5.1 What actually changes

Before the camera, notyas ingested attacker-influenced bytes through exactly one
door: a PSBT or descriptor file on an SD card, which a person deliberately
copied, from a device they chose, at a moment they chose. SECURITY.md's threat
model already covers "a malicious or compromised coordinator feeding hostile
PSBTs, descriptors, or file content".

The camera changes three properties of that door, and only three:

1. **Remote-ish reach.** A hostile payload no longer needs the user to handle
   media. Anyone who can put pixels in front of the lens - a webpage, a screen
   over the user's shoulder, a printed page in a "scan to verify" phishing kit -
   can feed the parser. The attacker still needs the user to open the scan
   screen and point the device, which is a meaningful barrier, and it is why 4.2
   forbids auto-start.
2. **Volume and rate.** An animated QR is a stream. A fountain-coded stream is
   an *unbounded* stream by design. A file has an end; a camera feed does not.
   Every buffer on the ingest path therefore has to be bounded by construction
   rather than by the size of the input.
3. **A new C pipeline in the TCB** - esp_video, esp_cam_sensor, esp_ipa, the
   ISP and CSI drivers. This one is not payload-driven (see 5.6), which is what
   makes it acceptable.

What does **not** change: the policy engine is still the trust boundary
(SECURITY.md invariant 7), the review UI is still the thing the user must read,
and a PSBT that arrives by camera is subject to exactly the same ten checks as
one that arrives by SD (ARCHITECTURE.md 5.3). The camera is a transport. It gets
no privileges.

### 5.2 The ingress validator

**DECISION: nothing decoded from a QR reaches a transport decoder, let alone a
PSBT parser, without passing a validator that lives in `notyas-wallet`, is
`no_std`, allocates nothing unbounded, and is fuzzed on the host.**

The validator's job is to reject before allocating. Its rules:

- **Total payload cap.** A hard ceiling on the assembled message, shared with
  the SD path's existing cap (ARCHITECTURE.md 5.4) so there is one number, not
  two. The cap is a `const` in `notyas-wallet` and the UR decoder's
  `MAX_MESSAGE_LEN` is derived from it, not chosen separately.
- **Per-frame cap.** A single QR cannot exceed the largest payload a
  version-40 code can carry; anything claiming more is a lie about its own
  framing.
- **Header consistency across a session.** The first accepted part fixes the UR
  type, the sequence length, the message length and the checksum. Every
  subsequent part must match all four or is dropped silently (not fatally - a
  stray QR in frame should not kill a scan).
- **Declared-count bounds.** `seqLen` must be within `[1, MAX_SEQUENCE_COUNT]`
  and `seqNum` within `[1, 2 * seqLen]` before the part is handed to the
  fountain decoder. This is the single most important rule; 5.3 explains why.
- **Charset.** UR and BBQr payloads are restricted alphabets (bytewords /
  base32). Anything with a byte outside the transport's alphabet is rejected at
  the frame level, which incidentally makes the `decode_to` byte path safe to
  treat as text where the transport says it is text.
- **No transport switching mid-session.** A session that started reading UR
  finishes reading UR or ends.

Every rule above is a pure function of bytes, so it is a fuzz target with no
hardware in the loop: `cargo fuzz` over arbitrary byte strings, asserting no
panic, no allocation above the cap, and termination. That harness is the
deliverable, not the intention.

### 5.3 Three specific findings in the fountain decoder

Read while specifying this document, in `foundation-rs` `ur/src/fountain/`
(main branch, 2026-08-17). All three are reachable from a **single crafted QR
frame** if parts are passed through unvalidated, which is the concrete reason
5.2's validator exists rather than being a good-practice gesture.

1. **Unchecked multiplication sized by attacker input.** `BaseDecoder::receive`
   computes `let message_len = part.data.len() * usize::try_from(part.sequence_count).unwrap();`
   on the first part of a session. `sequence_count` is a `u32` straight off the
   wire; `usize` is 32 bits on `riscv32imafc`. With overflow checks off (release
   profile), a fragment of 100 bytes and a declared count of 0x0400_0000 wraps
   instead of producing 6.7e9, so the decoder proceeds with a nonsense message
   length. Bounding `sequence_count` before the call removes the input range
   that can wrap.
2. **`expect()` on a capacity failure.** `FragmentChooser::choose_fragments`
   does `set.insert(...).expect("Not enough capacity to store single index")`.
   On the heapless types this is a **panic**, and a panic in this firmware is an
   abort. A remote-ish, unauthenticated, one-frame reboot is a denial of
   service, and on a signer mid-flow it is worse than a reboot - it is a lost
   session at an unpredictable moment.
3. **Work proportional to a declared count.** The same function does
   `self.indexes.reserve(sequence_count)` and `extend(0..sequence_count)` for any
   part with `sequence > sequence_count`. The cost is linear in a number the
   attacker writes on the QR, which is a CPU-exhaustion lever independent of how
   much data was actually transmitted.

Response, in order of who owns it:

- **Ours, and blocking:** the validator (5.2) enforces the bounds before any
  part reaches the decoder, and the `HeaplessDecoder` const generics make the
  worst case a number we chose at compile time.
- **Upstream, and offered:** report all three to Foundation Devices with a patch
  - checked multiplication, `Result` instead of `expect`, and an explicit
  `sequence_count` bound. `foundation-ur` is MIT and actively maintained, and
  every hardware wallet using it has the same exposure. This is a real
  contribution and PLATFORM.md's section 6 licensing discussion already applies.
- **Recorded as an accepted risk if upstream declines:** we still depend on the
  crate; our validator is then load-bearing rather than defense in depth, and
  SECURITY.md should say so in those words.

### 5.4 PSBT and payload handling

Nothing here is new policy - it is the existing policy, restated for a channel
that can deliver it faster:

- The assembled message goes to the same parser and the same policy engine as an
  SD-borne one. `rust-bitcoin`'s PSBT parser is memory-safe Rust and is the only
  thing that interprets the bytes; the ten checks of ARCHITECTURE.md 5.3 are the
  trust boundary either way.
- **Size caps are the DoS answer**, not parsing cleverness: one cap on the
  assembled message, one on the per-frame payload, one on the number of inputs
  and outputs the review UI will render (which the policy engine already needs
  for the batch-transaction fatigue rule in UX.md screen 10).
- **Refusals are screens, not aborts.** Every rejection reason - too large,
  inconsistent parts, unknown transport, not a PSBT, PSBT v2 - has a plain-word
  screen with a corpus-driven test asserting the exact rendered text, exactly as
  UX.md section 4 already requires for policy-engine refusals.
- **A camera cannot approve anything.** No scanned payload may set a flag, skip
  a review page, shorten a hold, or change any setting. The only thing a scan
  can produce is a candidate document for a human to review. Worth stating
  because it is the invariant a "scan this QR to configure your device" phishing
  attack would need to break.

### 5.5 Why a CSI sensor is still the smaller surface

CAMERA.md section 4 makes the argument; the implementation confirms its
premises, and one of them needs a caveat.

Confirmed: the sensor is a dumb peripheral. The host initiates every SCCB
transaction; the sensor answers with register values the driver compares against
a constant (`dev->id.pid != OV5647_PID`) and otherwise ignores. The pixel path
is a unidirectional D-PHY stream into a fixed-size DMA buffer whose size the
host set. There is no enumeration, no descriptor parsing, no attacker-supplied
data structure, and nothing the camera can say that changes what code runs. That
is categorically different from a USB host stack running enumeration and
descriptor parsing against whatever is plugged in - the class of code USBFuzz
found 26 new bugs in across four mature operating systems
(https://www.usenix.org/conference/usenixsecurity20/presentation/peng).

The caveat that CAMERA.md does not state: **choosing CSI still adds C to the
TCB** - esp_video, esp_cam_sensor, esp_ipa, plus the IDF CSI/ISP/PPA drivers.
The honest formulation is not "CSI adds no attack surface" but "CSI adds C that
is not driven by attacker-controlled data, whereas USB host adds C whose entire
job is parsing attacker-controlled data". The first is a quality-of-driver risk
that a fault in the field turns into a crash; the second is an exploitation
surface. That distinction is the whole argument, and it survives.

### 5.6 The new C, enumerated

Because SECURITY.md's "known accepted risks" section will need this list:

| Added | Driven by attacker data? | Notes |
|---|---|---|
| esp_video core (buffer, ioctl, mman, vfs) | no | our own ioctls, our own sizes |
| esp_video CSI device + ISP device | no | fixed geometry set by us before STREAMON |
| esp_cam_sensor OV5647 driver | no | register tables plus an ID compare |
| esp_ipa (AE/AWB) | **indirectly** | consumes ISP statistics, which are a function of the scene, i.e. of pixels an attacker can control. Worst realistic case is bad exposure. Its per-sensor tuning file is a **build-time** JSON compiled in, not runtime input. |
| IDF ISP / CSI / PPA drivers | no | geometry from us; DMA into buffers we sized |
| `usb_host_uvc` | n/a | **stubbed out of the tree** (2.1) |
| `esp_h264` | n/a | **stubbed out of the tree** (2.1) |
| lwip | n/a | required by esp_video's CMake; **must not appear in the link map** (2.1) |

The image-analysis code that *is* driven by attacker pixels - thresholding,
capstone detection, grid fitting, Reed-Solomon - is Rust (rqrr). That is the
right side of the boundary for the one component whose input an attacker fully
controls, and it is the main reason the fallback to the C `quirc` component in
3.6 is a fallback and not the default.

### 5.7 Physical and privacy properties

- **The camera is off unless a session object is alive** (3.1, 4.2), which is
  enforced by `Drop` rather than by remembering to call a teardown function.
- **No frame is ever stored.** Not to flash, not to SD, not to a log. Buffers are
  freed at session end. This is a property to state on the scan screen, because
  users of a device with a camera reasonably want to know.
- **No LED to be honest with.** The 4B routes no camera activity LED; CSI_IO0 is
  strapped high and CSI_IO1 floats. The on-screen preview is therefore the
  indicator: if the viewfinder is not showing, the camera is not streaming. That
  is a weaker guarantee than a hardwired LED and it should be stated as such
  rather than dressed up.
- **A camera can be pointed at the user.** Anyone building an enclosure should
  put the lens on the back, opposite the screen. Not a firmware property; worth
  writing down anyway.
- **Optical side channel, both directions.** A camera-equipped signer sits in a
  room; so does its screen. Nothing about adding a camera makes shoulder-surfing
  of the screen worse, and the camera cannot exfiltrate because there is nowhere
  to exfiltrate to - but the sentence "this device has a camera and no radio"
  needs to appear next to the sentence "this device has no radio" wherever the
  latter appears, or the second one starts doing work it should not.

### 5.8 Residual risks, stated plainly

1. **rqrr is a QR decoder written to be correct, not to be hostile-input
   hardened.** It is memory-safe Rust, so the realistic worst case is a panic or
   a wrong decode rather than code execution - but a panic is an abort on this
   firmware. Mitigation: run decode in its own task, treat a decode fault as a
   session fault rather than a device fault, and fuzz rqrr on the host with
   arbitrary images as part of the corpus work MILESTONES.md already schedules.
   A wrong decode is caught downstream: a corrupted PSBT fails to parse, and one
   that parses is still reviewed field by field by a human.
2. **`foundation-ur`'s three findings (5.3)** are ours to contain until upstream
   fixes them.
3. **The ISP and CSI drivers are young.** esp_video reached 2.x in 2026 and its
   dependency set changes between minor versions. Pinned versions and a lock
   file bound the risk; a component bump is a review event, not a routine
   update.
4. **A camera makes phishing flows possible that did not exist before.** "Scan
   this QR to verify your device" is a natural-looking instruction. The
   structural answer is 5.4's last bullet - a scan can only ever produce a
   document for review - plus the anti-phishing words and the Verify screen that
   SECURITY.md already mandates.
5. **We cannot prove the sensor is a sensor.** A hostile module could be
   anything with the right pinout. So could a hostile SD card. This is the
   supply-chain tier SECURITY.md already places out of scope, and it is one more
   reason to recommend one known-good module (1.7) rather than "any Pi camera".

---

## 6. Scope: 0.2.0 versus 0.3.0, and the one-board problem

### 6.1 The problem

The Elecrow CrowPanel Advanced 5inch has a MIPI-CSI camera path, but it is not
the same path: a **24-pin** FPC (FPC3), sensor I2C on a separate 1.8 V-shifted
bus (GPIO33/GPIO34, not the GPIO45/GPIO46 touch bus), CSI_RESET driven by the
STC8 co-MCU, on-board 2V8/1V8 LDOs, and a factory target of SC2336 rather than
OV5647 (docs/research/elecrow-board.md section 3, verified against the Eagle
schematic). A Pi/SeedSigner camera cannot plug into it. The Elecrow camera is
Elecrow's own SC2336 accessory, which nobody on this bench owns.

So the feature works on one of two hardware-verified boards. BOARDS.md's
governing rule is that the build IS the board and that per-board differences are
confined to `board/<name>.rs` plus an sdkconfig overlay - it has no precedent
for a feature that only one board can have.

### 6.2 Recommendation

**OPEN: what is the per-board policy for camera support in 0.2.0?**

Recommendation, in three parts:

1. **Camera is a build variant, not a runtime capability.** Add a cargo feature
   `camera` that is only valid together with a board feature whose module
   declares camera hardware; a mismatch is a `compile_error!` in
   `board/mod.rs`, exactly like the existing exactly-one-board check. This keeps
   "the build IS the board" literally true and produces a distinct, separately
   hashed artifact: `notyas-0.2.0-waveshare-4b-camera.bin` alongside
   `notyas-0.2.0-waveshare-4b.bin`. Two artifacts for one board is the honest
   representation of two hardware configurations.
   - Consequence to accept: esp-idf-sys metadata cannot be feature-gated
     (`firmware/Cargo.toml` says so), so the esp_video C sources are present in
     every build's component tree. The per-board sdkconfig overlay turns them
     off for non-camera boards and the link-map gate (2.1) proves nothing camera
     related is in the image. This is verification rather than absence, and the
     release notes should say which it is.
2. **Support statement is per board and per variant, in the BOARDS.md table**,
   with the same discipline as UNTESTED scaffolds: camera = Waveshare 4B plus an
   OV5647 Pi-camera-class module, hardware-verified or not shipped. The Elecrow
   5inch row says "camera: not supported (24-pin SC2336 path, no hardware on
   bench)" and stays that way until someone owns the module.
3. **Parity language follows the artifact.** PARITY.md's camera-dependent rows
   (seed QR scan, PSBT scan-in, Key Teleport receive, verify-address input)
   become class b **on the camera variant** and stay class c on the base unit.
   No row is allowed to claim a capability the base artifact does not have.

**OPEN: does 0.2.0 ship camera support at all, or does it slip to 0.3.0?**
CAMERA.md put the CSI-versus-SD-only question to the user and it is still open.
Recommendation: **land it in 0.2.0, but sequence it last and let it slip
without blocking the release.** Reasoning:

- The 0.2.0 bar is storage, signing, multisig and Coldcard parity. Camera
  scanning is the largest single parity gap (PARITY.md's "QR scanner module"
  row), but every camera row has a working SD equivalent, so nothing in 0.2.0 is
  *blocked* on it.
- The riskiest part of the camera work is the part that costs almost nothing:
  the replug experiment in section 1. Doing it early gives a hardware answer for
  a couple of hours of bench time, and the answer changes the plan.
- Ordering that respects both: `m-camera-1` (shared I2C bus refactor plus the L0
  I2C ID probe) is cheap and independent, so it lands with the early
  infrastructure work. `m-camera-2` through `m-camera-5` sit at the end of the
  0.2.0 milestone list, behind signing and multisig, each individually
  droppable.

### 6.3 Milestone hooks for MILESTONES.md

Named here so the reconciliation agent can place them; the numbering is
indicative, not a claim on the milestone sequence.

| Id | Content | Gate |
|---|---|---|
| m-camera-0 | Bench: the replug experiment, section 1, stages L0 and L1 | I2C ID reads 0x5647; vendor example streams. Result written to docs/research/ either way |
| m-camera-1 | `board::shared_i2c_bus()` refactor; touch takes the bus instead of creating it | touch still works on both verified boards, unchanged behavior |
| m-camera-2 | esp_video pinned and integrated; stub components; link-map gate; one frame captured by notyas firmware | map contains no lwip, no usb_host; a UYVY frame reaches PSRAM |
| m-camera-3 | PPA UYVY->GRAY8, rqrr, static QR decode end to end; the measurement table in 3.6 | >= 8 decode attempts/s with the panel live |
| m-camera-4 | Ingress validator in notyas-wallet plus its fuzz harness; UR2 and BBQr assembly; const bounds pinned | fuzzer clean; the 5.3 cases are regression tests |
| m-camera-5 | Scan session plumbed into the UI per section 4 and UX-SCREENS.md; SeedQR | animated PSBT scanned, reviewed, signed, emitted |

### 6.4 Smaller opens

- **OPEN: does the camera variant accept SeedQR (a private-key input path)?**
  Recommendation: yes, but gated behind the same friction as manual mnemonic
  entry, and never as a default-visible action on the scan screen. Scanning a
  seed is genuinely useful (it is what SeedSigner users have) and the risk is
  the same risk as typing one in, with the addition that a camera pointed at a
  paper backup is a camera pointed at a paper backup. 0.1.0's structural rule -
  no private value ever leaves the device - is about output and is untouched by
  an input path.
- **OPEN: default preview on or off?** Recommendation: on. It costs one PPA
  pass, it is the only camera-activity indicator this hardware has (5.7), and a
  scan without a viewfinder is unattributable when it fails.
- **OPEN: buy a Waveshare OV5647 reference module** (1.7). Recommendation: yes,
  about 10 USD, before m-camera-0 if lead time allows.

---

## 7. Sources

Repo files consulted: `docs/research/hardware.md`,
`docs/research/elecrow-board.md`, `docs/BOARDS.md`, `docs/ARCHITECTURE.md`,
`docs/plan-0.2.0/{CAMERA,ARCHITECTURE,SECURITY,UX,PARITY,PLATFORM}.md`,
`firmware/Cargo.toml`, `firmware/sdkconfig.base.defaults`,
`firmware/src/display.rs`, `firmware/src/board/waveshare_4b.rs`,
`firmware/src/board/waveshare_common.rs`.

Schematic: https://files.waveshare.com/wiki/ESP32-P4-WIFI6-Touch-LCD-4B/ESP32-P4-WIFI6-Touch-LCD-4B.pdf
(page 1, connector J1 and R47-R50; re-extracted 2026-08-17 for this document).

Espressif components and drivers:
https://components.espressif.com/components/espressif/esp_video ,
https://components.espressif.com/components/espressif/esp_cam_sensor ,
https://github.com/espressif/esp-video-components (esp_video `CMakeLists.txt`,
`Kconfig`, `src/esp_video_init.c`, `src/device/esp_video_csi_device.c`,
`src/device/esp_video_csi_format.c`, `src/esp_video_buffer.c`,
`examples/capture_stream`; esp_cam_sensor `sensors/ov5647/*`),
https://components.espressif.com/components/espressif/quirc

ESP-IDF v5.5 (ESP32-P4):
https://docs.espressif.com/projects/esp-idf/en/v5.5/esp32p4/api-reference/peripherals/ppa.html ,
https://docs.espressif.com/projects/esp-idf/en/v5.5/esp32p4/api-reference/peripherals/isp.html ,
https://docs.espressif.com/projects/esp-idf/en/v5.5/esp32p4/api-reference/peripherals/ldo_regulator.html ,
`components/hal/include/hal/color_types.h`,
`components/hal/include/hal/ppa_types.h`,
`components/esp_driver_ppa/include/driver/ppa.h` ,
https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-guides/build-system.html ,
https://docs.espressif.com/projects/idf-component-manager/en/latest/reference/manifest_file.html ,
https://documentation.espressif.com/esp32-p4_datasheet_en.html

OV5647 and the Raspberry Pi camera:
https://github.com/torvalds/linux/blob/master/drivers/media/i2c/ov5647.c
(25 MHz xclk requirement),
https://github.com/raspberrypi/linux `arch/arm/boot/dts/overlays/ov5647-overlay.dts`
and `ov5647.dtsi` (`ov5647@36`, `clock-frequency = <25000000>`),
https://cdn.sparkfun.com/datasheets/Dev/RaspberryPi/ov5647_full.pdf ,
https://www.raspberrypi.com/documentation/accessories/camera.html ,
https://blog.arducam.com/raspberry-pi-camera-pinout/ ,
https://www.cnx-software.com/2026/05/04/esp32-p4-esp32-c5-board-features-raspberry-pi-compatible-mipi-connectors-for-official-displays-and-camera-modules/ ,
https://www.waveshare.com/wiki/ESP32-P4-Nano-StartPage

Rust crates:
https://github.com/WanzenBug/rqrr (0.10.1; `Cargo.toml`, `src/lib.rs`,
`src/prepare.rs`), https://crates.io/crates/rqrr ,
https://github.com/Foundation-Devices/foundation-rs (`ur/src/ur/decoder.rs`,
`ur/src/fountain/decoder.rs`, `ur/src/fountain/chooser.rs`,
`ur/src/fountain/part.rs`), https://crates.io/crates/foundation-ur ,
https://crates.io/crates/bbqr , https://bbqr.org/ ,
https://github.com/SeedSigner/seedsigner/blob/dev/docs/seed_qr/README.md

Prior art and security:
https://seedsigner.com/hardware/ , https://github.com/SeedSigner/seedsigner ,
https://www.usenix.org/conference/usenixsecurity20/presentation/peng (USBFuzz),
https://github.com/espressif/qrcode-demo , https://dlbeer.co.nz/oss/quirc.html ,
https://developer.blockchaincommons.com/ur/psbts/

Input to: MILESTONES.md and OPEN-QUESTIONS.md reconciliation; BOARDS.md status
table (camera row); PARITY.md camera-dependent rows; SECURITY.md "known accepted
risks"; UX-SCREENS.md scan screens.
