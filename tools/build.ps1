# build.ps1 - build the BigDice32 firmware.
#
# Sources live on the NAS share; build artifacts MUST go to a local disk
# (UNC paths + the heavy IDF/CMake build do not mix). The esp-idf-sys build
# additionally hard-fails when the target path is long (Windows path-length
# limits in the CMake/ninja IDF build), so the default is the very short
# C:\bd32t. Override by setting BIGDICE32_TARGET_DIR before calling - keep
# it SHORT (the build errors out with "Too long output directory" otherwise).
#
# Usage: .\build.ps1 [extra cargo build args, e.g. --release]

$ErrorActionPreference = "Stop"

$firmwareDir = Join-Path (Split-Path -Parent $PSScriptRoot) "firmware"
if (-not (Test-Path (Join-Path $firmwareDir "Cargo.toml"))) {
    Write-Error ("Firmware directory not reachable: $firmwareDir`n" +
        "The NAS share (\\172.16.0.9\bear) may be offline. Fix the share, then retry.")
    exit 1
}

if ($env:BIGDICE32_TARGET_DIR) {
    $env:CARGO_TARGET_DIR = $env:BIGDICE32_TARGET_DIR
} else {
    $env:CARGO_TARGET_DIR = "C:\bd32t"
}
Write-Host "CARGO_TARGET_DIR = $env:CARGO_TARGET_DIR"

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
    cargo build @args
    if ($LASTEXITCODE -ne 0) {
        Write-Error "cargo build failed with exit code $LASTEXITCODE"
        exit $LASTEXITCODE
    }
} finally {
    Pop-Location
}
