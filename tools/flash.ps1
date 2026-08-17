# flash.ps1 - flash the BigDice32 firmware to the board over serial.
#
# Flashes the app ELF together with the bootloader and partition table that
# the esp-idf-sys build produced. Do NOT let espflash substitute its bundled
# bootloader: our dev silicon is rev v1.3 (pre-v3.0 family) and only a
# bootloader built with CONFIG_ESP32P4_SELECTS_REV_LESS_V3 boots on it.
#
# Usage: .\flash.ps1 [-Port COM3] [-Profile debug|release] [-Monitor]
# Respects BIGDICE32_TARGET_DIR like build.ps1. Build first (build.ps1).

param(
    [string]$Port = "COM3",
    [string]$Profile = "debug",
    [switch]$Monitor
)

$ErrorActionPreference = "Stop"

$firmwareDir = Join-Path (Split-Path -Parent $PSScriptRoot) "firmware"
if (-not (Test-Path (Join-Path $firmwareDir "Cargo.toml"))) {
    Write-Error ("Firmware directory not reachable: $firmwareDir`n" +
        "The NAS share (\\172.16.0.9\bear) may be offline. Fix the share, then retry.")
    exit 1
}

if ($env:BIGDICE32_TARGET_DIR) {
    $targetDir = $env:BIGDICE32_TARGET_DIR
} else {
    $targetDir = "C:\bd32t"
}

$outDir = Join-Path $targetDir "riscv32imafc-esp-espidf\$Profile"
$elf = Join-Path $outDir "bigdice32-firmware"
if (-not (Test-Path $elf)) {
    Write-Error "App ELF not found: $elf`nRun tools\build.ps1 first (same BIGDICE32_TARGET_DIR)."
    exit 1
}

# Take the newest bootloader/partition-table under the esp-idf-sys out dirs.
# Do NOT use the convenience copies at <profile>\build\bootloader.bin - embuild
# does not always refresh them after a sdkconfig change, and flashing a stale
# (wrong-revision-family) bootloader bricks the boot with an illegal
# instruction at its entry point.
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
    "--flash-size", "32mb"
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
