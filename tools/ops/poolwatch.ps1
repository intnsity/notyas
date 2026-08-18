# Kernel pool / handle watchdog.
#
# Why this exists: on 2026-08-18 a kernel-mode handle leak consumed 78 GB of
# paged plus nonpaged pool on a 95 GB machine and drove the System process to
# 16.7 M handles, 66 k short of the 16,777,216 per-process architectural cap.
# Explorer, dwm and SearchHost then died with "could not allocate additional
# memory". None of that is visible in Task Manager - no user process owns pool -
# and Windows logs no event for it. The failure was initially misread as a
# bluescreen and misattributed to a compiler.
#
# The thresholds are deliberately four orders of magnitude below the observed
# figures so this trips hours into a leak rather than days into one. A healthy
# System process holds handles in the low thousands.
$ErrorActionPreference = 'Stop'

$sysH  = (Get-Process -Id 4).HandleCount
$pp    = (Get-Counter '\Memory\Pool Paged Bytes').CounterSamples[0].CookedValue
$np    = (Get-Counter '\Memory\Pool Nonpaged Bytes').CounterSamples[0].CookedValue
$avail = (Get-Counter '\Memory\Available MBytes').CounterSamples[0].CookedValue

$alert = ($sysH -gt 200000) -or (($pp + $np) -gt 6GB) -or ($avail -lt 8192)

$msg = "SystemHandles={0:N0} Paged={1:N2}GB NonPaged={2:N2}GB Avail={3:N1}GB" -f `
       $sysH, ($pp/1GB), ($np/1GB), ($avail/1024)

if ($alert) {
    # The event-log write is best effort. Registering a source needs admin, and
    # this script is useful unelevated too - the scheduled task installed by
    # install-poolwatch.ps1 runs as SYSTEM and gets the log; a developer running
    # it by hand still gets the numbers on stdout and a non-zero exit.
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists('PoolWatch')) {
            New-EventLog -LogName Application -Source 'PoolWatch' -ErrorAction Stop
        }
        Write-EventLog -LogName Application -Source 'PoolWatch' -EventId 9001 `
            -EntryType Warning -Message "KERNEL POOL ALERT $msg" -ErrorAction Stop
    } catch {
        Write-Output "(event log unavailable without admin: $($_.Exception.GetType().Name))"
    }
    Write-Output "ALERT $msg"
    exit 1
}
Write-Output "ok $msg"
