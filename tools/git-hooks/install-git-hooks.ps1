<#
.SYNOPSIS
    Copy the tracked git hooks in this directory into .git\hooks, where git
    actually runs them.

.DESCRIPTION
    .git\hooks is not version controlled, so the tracked source of truth for
    every hook lives here instead, one file per hook name (post-commit,
    pre-push, ...). This installer copies whatever hook files it finds next
    to it into .git\hooks, unconditionally overwriting what is there. That
    makes adding a new hook later just "drop the file here and re-run this
    script" - nothing about this installer needs to change to pick it up.

    Run:      tools\git-hooks\install-git-hooks.ps1
    No admin needed - this only copies files inside the repo's own .git
    directory, the same privilege level as an ordinary git operation.

    Re-run any time a file under tools\git-hooks changes, and once after
    cloning the repository fresh anywhere - a git pull updates the tracked
    copy but never touches the live hook in .git\hooks.
#>
[CmdletBinding()]
param(
    [string] $RepoRoot
)

$ErrorActionPreference = 'Stop'

$here = $PSScriptRoot
if (-not $here) { $here = Split-Path -Parent $PSCommandPath }

if (-not $RepoRoot) {
    $RepoRoot = (& git -C $here rev-parse --show-toplevel 2>$null)
    if (-not $RepoRoot) {
        # Fall back to the fixed layout (tools\git-hooks is always two levels
        # under the repo root) so this still works if git itself is missing
        # from PATH, which is unlikely but cheap to guard.
        $RepoRoot = Split-Path -Parent (Split-Path -Parent $here)
    }
}
$RepoRoot = $RepoRoot -replace '/', '\'

$hooksDst = Join-Path $RepoRoot '.git\hooks'
if (-not (Test-Path -LiteralPath (Join-Path $RepoRoot '.git'))) {
    throw "not a git repository: $RepoRoot"
}
if (-not (Test-Path -LiteralPath $hooksDst)) {
    throw ".git\hooks not found at $hooksDst - is $RepoRoot really the repo root?"
}

$installerName = Split-Path -Leaf $PSCommandPath
$sources = Get-ChildItem -LiteralPath $here -File | Where-Object { $_.Name -ne $installerName }

if ($sources.Count -eq 0) {
    Write-Output "No hook files found in $here (besides this installer) - nothing to install."
    exit 1
}

Write-Output "Installing git hooks from $here"
Write-Output "                     into $hooksDst"
Write-Output ''
foreach ($f in $sources) {
    Copy-Item -LiteralPath $f.FullName -Destination (Join-Path $hooksDst $f.Name) -Force
    Write-Output "  $($f.Name)"
}
Write-Output ''
Write-Output 'Installed. .git\hooks is local-only: re-run this installer whenever the'
Write-Output 'tracked copies under tools\git-hooks change.'
exit 0
