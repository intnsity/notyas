# notyas Flash Tool

A simple Windows GUI tool to verify and flash notyas ESP32-P4 hardware wallet
releases. Part of the [notyas](https://github.com/intnsity/notyas) project.

## What it does

1. **Verifies** your downloaded release files are authentic (GPG signature +
   SHA256 hashes)
2. **Flashes** them to your ESP32-P4 board over USB

## Prerequisites

The tool checks for these at startup and tells you if they're missing:

- **GnuPG** (gpg.exe) for signature verification
  - Install from https://gpg4win.org/download.html
- **Python + esptool** for flashing
  - Install Python from https://python.org (check "Add to PATH")
  - Then run: `pip install esptool`

## Building

```
cd flashtool
cargo build --release
```

The binary is at `target/release/notyas-flashtool.exe`.

## Using

1. Download the release files from the GitHub release page
2. Run the flash tool
3. Click **Start**
4. Select your release folder and verify the signature and hashes
5. Plug in your ESP32-P4 via USB-C
6. Select the merged.bin for your board
7. Click **Flash**
8. Wait for the flash to complete, then unplug and reconnect

## License

GPL-3.0-or-later. See the project root `COPYING` file.
