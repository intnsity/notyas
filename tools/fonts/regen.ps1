# regen.ps1 - regenerate crates/notyas-fonts/src/gen from the committed upstream TTFs.
#
# Reproducible by construction: atlasgen writes no timestamps and iterates only fixed
# ordered lists, so two runs from the same TTFs produce byte-identical output. Proof:
# run this twice and `git diff --stat` (or hash the gen dir) between runs.
$ErrorActionPreference = 'Stop'

# ProviderPath, not Path: on a UNC share Resolve-Path returns a provider-qualified
# string ("Microsoft.PowerShell.Core\FileSystem::\\...") that cargo cannot open.
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).ProviderPath

# Never build onto the NAS share: sources live on UNC, artifacts go to local disk
# (same rule as tools/build.ps1).
if (-not $env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR = 'C:\nyt-fonts\target' }

cargo run --release --locked --manifest-path (Join-Path $root 'tools\fonts\atlasgen\Cargo.toml')
if ($LASTEXITCODE -ne 0) { throw "atlasgen failed with exit code $LASTEXITCODE" }
