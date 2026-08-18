# build.ps1 - build the notyas firmware for one board.
#
# Usage: .\build.ps1 [-Board waveshare-4b|waveshare-5|waveshare-7b|waveshare-7x|
#                            waveshare-8x|waveshare-101x|elecrow-5|elecrow-7|
#                            elecrow-9|elecrow-101]
#                    [extra cargo build args, e.g. --release]
#
# The build IS the board (docs/BOARDS.md): -Board selects the cargo feature,
# the sdkconfig overlay pair, and a PER-BOARD target dir. Per-board target
# dirs exist because the IDF build dir bakes in the merged sdkconfig -
# switching boards inside one target dir risks flashing a stale bootloader
# built for the wrong flash size. With one dir per board, switching never
# requires a clean.
#
# Sources live on the NAS share; build artifacts MUST go to a local disk
# (UNC paths + the heavy IDF/CMake build do not mix). The esp-idf-sys build
# additionally hard-fails when the target path is long (Windows path-length
# limits in the CMake/ninja IDF build), so the defaults are very short
# (C:\nyt-ws etc). Override by setting NOTYAS_TARGET_DIR before calling -
# keep it SHORT (the build errors out with "Too long output directory"
# otherwise), and keep it per-board yourself.

param(
    [ValidateSet("waveshare-4b", "waveshare-5", "waveshare-7b", "waveshare-7x",
                 "waveshare-8x", "waveshare-101x",
                 "elecrow-5", "elecrow-7", "elecrow-9", "elecrow-101")]
    [string]$Board = "waveshare-4b",
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$CargoArgs
)

$ErrorActionPreference = "Stop"

$boardMap = @{
    "waveshare-4b"   = @{ Feature = "board-waveshare-4b";   TargetDir = "C:\nyt-ws";    Untested = $false }
    "waveshare-5"    = @{ Feature = "board-waveshare-5";    TargetDir = "C:\nyt-w5";    Untested = $true; Portrait = $true }
    "waveshare-7b"   = @{ Feature = "board-waveshare-7b";   TargetDir = "C:\nyt-w7b";   Untested = $true }
    "waveshare-7x"   = @{ Feature = "board-waveshare-7x";   TargetDir = "C:\nyt-w7x";   Untested = $true; Portrait = $true }
    "waveshare-8x"   = @{ Feature = "board-waveshare-8x";   TargetDir = "C:\nyt-w8x";   Untested = $true; Portrait = $true }
    "waveshare-101x" = @{ Feature = "board-waveshare-101x"; TargetDir = "C:\nyt-w101x"; Untested = $true; Portrait = $true }
    "elecrow-5"      = @{ Feature = "board-elecrow-5";      TargetDir = "C:\nyt-e5";    Untested = $false }
    "elecrow-7"      = @{ Feature = "board-elecrow-7";      TargetDir = "C:\nyt-e7";    Untested = $true }
    "elecrow-9"      = @{ Feature = "board-elecrow-9";      TargetDir = "C:\nyt-e9";    Untested = $true }
    "elecrow-101"    = @{ Feature = "board-elecrow-101";    TargetDir = "C:\nyt-e101";  Untested = $true }
}
$b = $boardMap[$Board]

if ($b.Untested) {
    Write-Warning ("Board '$Board' is an UNTESTED scaffold: config comes from the vendor's " +
        "published sources and schematics but has never run on hardware here. " +
        "Do not trust the image beyond compile-checking. (docs/BOARDS.md status table)")
}
if ($b.Portrait) {
    Write-Warning ("Board '$Board' has a PORTRAIT panel: the UI layout is derived from the " +
        "board resolution but has only been verified at 720x720 and 800x480 landscape - " +
        "PORTRAIT LAYOUT UNVERIFIED. (docs/BOARDS.md status table)")
}

$firmwareDir = Join-Path (Split-Path -Parent $PSScriptRoot) "firmware"
if (-not (Test-Path (Join-Path $firmwareDir "Cargo.toml"))) {
    Write-Error ("Firmware directory not reachable: $firmwareDir`n" +
        "If the repository lives on a network share, that share may be offline. " +
        "Restore it, then retry.")
    exit 1
}

if ($env:NOTYAS_TARGET_DIR) {
    $env:CARGO_TARGET_DIR = $env:NOTYAS_TARGET_DIR
} else {
    $env:CARGO_TARGET_DIR = $b.TargetDir
}
Write-Host "Board            = $Board (feature $($b.Feature))"
Write-Host "CARGO_TARGET_DIR = $env:CARGO_TARGET_DIR"

# Per-board sdkconfig pair: shared base + board overlay (later file wins).
# Passed as absolute paths so there is no ambiguity about what the IDF build
# consumed (pitfall: with a wrong/missing defaults path esp-idf-sys silently
# builds stock defaults and the image boot-loops on rev v1.3 silicon).
$env:ESP_IDF_SDKCONFIG_DEFAULTS =
    (Join-Path $firmwareDir "sdkconfig.base.defaults") + ";" +
    (Join-Path $firmwareDir "boards\$Board\sdkconfig.defaults")
Write-Host "ESP_IDF_SDKCONFIG_DEFAULTS = $env:ESP_IDF_SDKCONFIG_DEFAULTS"

# bindgen (esp-idf-sys) needs a native libclang.dll. The esp-clang tool that
# embuild installs into ~\.espressif does NOT ship one on Windows, so we use
# the one from the 'libclang' pip wheel: python -m pip install --user libclang
if (-not $env:LIBCLANG_PATH) {
    $wheelDir = Join-Path $env:APPDATA "Python\Python312\site-packages\clang\native"
    if (Test-Path (Join-Path $wheelDir "libclang.dll")) {
        $env:LIBCLANG_PATH = $wheelDir
    } else {
        Write-Error ("libclang.dll not found. Install it with " +
            "'python -m pip install --user libclang' or set LIBCLANG_PATH " +
            "to a directory containing libclang.dll.")
        exit 1
    }
}
Write-Host "LIBCLANG_PATH = $env:LIBCLANG_PATH"

# secp256k1-sys (via notyas-core -> bitcoin) compiles its C library for the espidf
# target with cc-rs, which cannot find the ESP toolchain on its own (esp-idf-sys
# exports it only inside its own build script, and secp256k1-sys does not depend on
# it). Point cc-rs at the embuild-installed RISC-V GCC explicitly. The CFLAGS pin the
# P4's hard-float ABI (ilp32f): cc-rs's own guess links soft-float objects that the
# linker rejects against the IDF build.
if (-not $env:CC_riscv32imafc_esp_espidf) {
    $gcc = Get-ChildItem "$env:USERPROFILE\.espressif\tools\riscv32-esp-elf" -Recurse `
        -Filter "riscv32-esp-elf-gcc.exe" -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending | Select-Object -First 1
    if ($gcc) {
        $env:CC_riscv32imafc_esp_espidf = $gcc.FullName
        $env:AR_riscv32imafc_esp_espidf = Join-Path $gcc.DirectoryName "riscv32-esp-elf-ar.exe"
        # -fno-pic: cc-rs defaults to PIC objects, which the static IDF link script
        # rejects ("discarded output section: .got.plt" at final link).
        $env:CFLAGS_riscv32imafc_esp_espidf = "-march=rv32imafc_zicsr_zifencei -mabi=ilp32f -fno-pic"
    } else {
        Write-Warning ("riscv32-esp-elf-gcc not found under ~\.espressif\tools - the " +
            "secp256k1 C build will fail. A first build installs the toolchain via " +
            "esp-idf-sys; re-run this script afterwards.")
    }
}
Write-Host "CC_riscv32imafc_esp_espidf = $env:CC_riscv32imafc_esp_espidf"

Push-Location $firmwareDir
try {
    # cargo logs progress to stderr; under EAP=Stop a stream-redirecting caller
    # would turn that into a terminating NativeCommandError. Judge by exit code.
    $ErrorActionPreference = "Continue"
    cargo build --features $b.Feature @CargoArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Error "cargo build failed with exit code $LASTEXITCODE"
        exit $LASTEXITCODE
    }
} finally {
    Pop-Location
}
