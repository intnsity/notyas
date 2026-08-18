# flash.ps1 - flash the notyas firmware to a board over serial.
#
# Usage: .\flash.ps1 [-Board waveshare-4b|elecrow-5|elecrow-7|elecrow-9|elecrow-101]
#                    [-Port COMx] [-Profile debug|release] [-Monitor]
#
# -Board selects the per-board target dir (same map as build.ps1), the
# --flash-size for the image header, and the default -Port (port letters
# drift; override with -Port when they do). Build first: build.ps1 -Board <b>.
#
# Flashes the app ELF together with the bootloader and partition table that
# the esp-idf-sys build produced. Do NOT let espflash substitute its bundled
# bootloader: our dev silicon is rev v1.3 (pre-v3.0 family) and only a
# bootloader built with CONFIG_ESP32P4_SELECTS_REV_LESS_V3 boots on it.
# Respects NOTYAS_TARGET_DIR like build.ps1.

param(
    [ValidateSet("waveshare-4b", "elecrow-5", "elecrow-7", "elecrow-9", "elecrow-101")]
    [string]$Board = "waveshare-4b",
    [string]$Port = "",
    [string]$Profile = "debug",
    [switch]$Monitor
)

$ErrorActionPreference = "Stop"

$boardMap = @{
    # Default ports: COM3 = Waveshare (CH343), COM6 = Elecrow 5inch (CH340K).
    # The DSI scaffolds have no hardware here - no default port on purpose.
    "waveshare-4b" = @{ TargetDir = "C:\nyt-ws";   FlashSize = "32mb"; Port = "COM3" }
    "elecrow-5"    = @{ TargetDir = "C:\nyt-e5";   FlashSize = "16mb"; Port = "COM6" }
    "elecrow-7"    = @{ TargetDir = "C:\nyt-e7";   FlashSize = "16mb"; Port = "" }
    "elecrow-9"    = @{ TargetDir = "C:\nyt-e9";   FlashSize = "16mb"; Port = "" }
    "elecrow-101"  = @{ TargetDir = "C:\nyt-e101"; FlashSize = "16mb"; Port = "" }
}
$b = $boardMap[$Board]

if (-not $Port) { $Port = $b.Port }
if (-not $Port) {
    Write-Error ("No default port for board '$Board' (UNTESTED scaffold, no hardware " +
        "on this bench) - pass -Port COMx explicitly.")
    exit 1
}

$firmwareDir = Join-Path (Split-Path -Parent $PSScriptRoot) "firmware"
if (-not (Test-Path (Join-Path $firmwareDir "Cargo.toml"))) {
    Write-Error ("Firmware directory not reachable: $firmwareDir`n" +
        "The NAS share (\\172.16.0.9\bear) may be offline. Fix the share, then retry.")
    exit 1
}

if ($env:NOTYAS_TARGET_DIR) {
    $targetDir = $env:NOTYAS_TARGET_DIR
} else {
    $targetDir = $b.TargetDir
}

$outDir = Join-Path $targetDir "riscv32imafc-esp-espidf\$Profile"
$elf = Join-Path $outDir "notyas-firmware"
if (-not (Test-Path $elf)) {
    Write-Error "App ELF not found: $elf`nRun tools\build.ps1 -Board $Board first (same NOTYAS_TARGET_DIR)."
    exit 1
}

# Take the newest bootloader/partition-table under the esp-idf-sys out dirs.
# Do NOT use the convenience copies at <profile>\build\bootloader.bin - embuild
# does not always refresh them after a sdkconfig change, and flashing a stale
# (wrong-revision-family) bootloader bricks the boot with an illegal
# instruction at its entry point. The per-board target dir guarantees the
# newest one here was built for THIS board's sdkconfig.
$buildDir = Join-Path $outDir "build"
$bootloader = Get-ChildItem -Path $buildDir -Recurse -Filter "bootloader.bin" |
    Where-Object { $_.FullName -match "esp-idf-sys" } |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
$partTable = Get-ChildItem -Path $buildDir -Recurse -Filter "partition-table.bin" |
    Where-Object { $_.FullName -match "esp-idf-sys" } |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $bootloader -or -not $partTable) {
    Write-Error "bootloader.bin / partition-table.bin not found under $buildDir - rebuild first."
    exit 1
}

$flashArgs = @(
    "flash", $elf,
    "--port", $Port, "--baud", "921600",
    "--bootloader", $bootloader.FullName,
    "--partition-table", $partTable.FullName,
    "--flash-size", $b.FlashSize
)
if ($Monitor) { $flashArgs += "--monitor" }

Write-Host "espflash $($flashArgs -join ' ')"
# espflash logs to stderr; under EAP=Stop a stream-redirecting caller would
# turn that into a terminating NativeCommandError. Judge by exit code.
$ErrorActionPreference = "Continue"
espflash @flashArgs
if ($LASTEXITCODE -ne 0) {
    Write-Error "espflash failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}
