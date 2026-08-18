# build.ps1 - build the notyas firmware for one board.
#
# Usage: .\build.ps1 [-Board waveshare-4b|elecrow-5|elecrow-7|elecrow-9|elecrow-101]
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
    [ValidateSet("waveshare-4b", "elecrow-5", "elecrow-7", "elecrow-9", "elecrow-101")]
    [string]$Board = "waveshare-4b",
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$CargoArgs
)

$ErrorActionPreference = "Stop"

$boardMap = @{
    "waveshare-4b" = @{ Feature = "board-waveshare-4b"; TargetDir = "C:\nyt-ws";  Untested = $false }
    "elecrow-5"    = @{ Feature = "board-elecrow-5";    TargetDir = "C:\nyt-e5";  Untested = $false }
    "elecrow-7"    = @{ Feature = "board-elecrow-7";    TargetDir = "C:\nyt-e7";  Untested = $true }
    "elecrow-9"    = @{ Feature = "board-elecrow-9";    TargetDir = "C:\nyt-e9";  Untested = $true }
    "elecrow-101"  = @{ Feature = "board-elecrow-101";  TargetDir = "C:\nyt-e101"; Untested = $true }
}
$b = $boardMap[$Board]

if ($b.Untested) {
    Write-Warning ("Board '$Board' is an UNTESTED scaffold: config comes from Elecrow's " +
        "published sources and schematics but has never run on hardware here. " +
        "Do not trust the image beyond compile-checking. (docs/BOARDS.md status table)")
}

$firmwareDir = Join-Path (Split-Path -Parent $PSScriptRoot) "firmware"
if (-not (Test-Path (Join-Path $firmwareDir "Cargo.toml"))) {
    Write-Error ("Firmware directory not reachable: $firmwareDir`n" +
        "The NAS share (\\172.16.0.9\bear) may be offline. Fix the share, then retry.")
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
