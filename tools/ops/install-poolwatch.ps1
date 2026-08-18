# Register poolwatch.ps1 as a scheduled task running every 15 minutes.
# Run from an elevated prompt. Creating the event source needs admin once;
# after that the task itself runs as SYSTEM.
$ErrorActionPreference = 'Stop'
$script = Join-Path $PSScriptRoot 'poolwatch.ps1'
if (-not (Test-Path $script)) { throw "not found: $script" }

$action  = New-ScheduledTaskAction -Execute 'powershell.exe' `
             -Argument "-NonInteractive -NoProfile -ExecutionPolicy Bypass -File `"$script`""
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
             -RepetitionInterval (New-TimeSpan -Minutes 15)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName 'PoolWatch' -Action $action -Trigger $trigger `
    -Principal $principal -Description 'Kernel pool and System-handle leak watchdog' -Force
Write-Output "registered. Alerts land in Application log, source PoolWatch, event 9001."
