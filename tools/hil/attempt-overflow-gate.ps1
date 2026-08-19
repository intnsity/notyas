# m4a: a device with the wipe DISABLED survives 128+ consecutive failed attempts.
#
# The exit gate's second Q5 addition, in its own words: "a device with wipe DISABLED
# survives 128+ consecutive failed attempts without overflowing the attempt log or losing
# the accumulated count (the `failures_base` rotation path)".
#
# WHY THIS IS NOT A MODE OF power-cut-gate.ps1. Nothing is cut here. The gate is a soak:
# type the wrong PIN until the 128-cell attempt log fills, and watch what the count does
# at the boundary. The operator is not needed at all once it starts, which is the point -
# it is the one outstanding hardware gate that costs bench time only in minutes, not in
# attention. Sharing a file with the cut harness would mean sharing a loop shaped around a
# power cut that never happens.
#
# WHAT IS ACTUALLY BEING WATCHED. `failures = failures_base + len(attempt_entry) -
# len(attempt_success)` (ledger.rs). The entry log has 128 cells. With the wipe enabled a
# streak can never reach that, because the wipe fires first; with it disabled nothing
# bounds the streak, so the log fills and `Vault::unlock` rotates the ledger BEFORE
# programming the cell, carrying the running count into `failures_base`. The failure this
# gate exists to catch is that carry going missing: the count would silently return to
# zero at attempt 129 and every subsequent guess would be free. So the evidence is one
# column - the failure count after each attempt - and the property is that it goes up by
# exactly one, every time, across the boundary.
#
# THE PRECONDITION IS ENFORCED, NOT ASSUMED. On a wipe-ENABLED board this script would
# destroy every record on the fifteenth attempt. It reads the policy first and refuses to
# send a single wrong PIN unless the device reports `wipe_after=0`. Board B is the only
# eFuse-provisioned unit and its store is where the storage evidence comes from.
#
# It records. It does not print PASS.
[CmdletBinding()]
param(
    [string] $Port     = 'COM6',
    [int]    $Baud     = 115200,
    [string] $Pin      = '1234',
    # Must parse as a PIN and must be wrong. A value the console rejects as malformed
    # never reaches the counter, and the run would soak an error path instead of the log.
    [string] $BadPin   = '9999',
    # 128 cells plus a margin either side of the boundary. The gate says 128+, and a run
    # that stopped at exactly 128 would leave the rotation itself unobserved.
    [int]    $Attempts = 136,
    # Power cycle after this many attempts to evidence the other half of the exit gate -
    # "the decrement survives a reboot" - inside the same run. 0 skips it. The operator is
    # prompted once, and the count is compared across the reboot.
    [int]    $RebootAt = 0,
    [string] $OutDir   = 'C:\nb\hil',
    [switch] $DryRun
)

$ErrorActionPreference = 'Stop'

if ($OutDir -match '^(\\\\|//)') { throw "OutDir must be a local path, not a UNC path: $OutDir" }

$stamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
$runDir = Join-Path $OutDir "overflow-$stamp"
if (-not $DryRun) {
    if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
    New-Item -ItemType Directory -Path $runDir -Force | Out-Null
}
$transcript = Join-Path $runDir 'console.log'
$recordCsv  = Join-Path $runDir 'attempts.csv'
$recordJson = Join-Path $runDir 'attempts.json'

function Write-Log {
    param([string] $Text)
    $line = '{0} {1}' -f (Get-Date -Format 'HH:mm:ss.fff'), $Text
    Add-Content -Path $transcript -Value $line -Encoding utf8
    Write-Output $line
}

function Test-PortPresent {
    param([string] $Name)
    return ([System.IO.Ports.SerialPort]::GetPortNames() -contains $Name)
}

function Wait-PortBack {
    param([string] $Name, [int] $TimeoutMs)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.ElapsedMilliseconds -lt $TimeoutMs) {
        if (Test-PortPresent $Name) { Start-Sleep -Milliseconds 1500; return $true }
        Start-Sleep -Milliseconds 50
    }
    return $false
}

function Open-Board {
    # `Tries`, not `Attempts`: in this script an attempt is a wrong PIN, and one word for
    # two counters in the same file is how a reader misjudges what a number bounds.
    param([string] $Name, [int] $Rate, [int] $Tries = 12)
    # Same retry as the cut harness, for the same measured reason: a board that has just
    # been re-powered can enumerate twice, and a handle opened against the first
    # enumeration opens cleanly and then dies on its first write.
    for ($a = 1; $a -le $Tries; $a++) {
        try {
            $sp = New-Object System.IO.Ports.SerialPort $Name, $Rate, 'None', 8, 'One'
            $sp.ReadTimeout = 250
            $sp.WriteTimeout = 2000
            $sp.NewLine = "`n"
            # DTR/RTS drive EN and GPIO0 on these bridges; both stay deasserted or opening
            # the port resets the board, which would clear the very streak being measured.
            $sp.DtrEnable = $false
            $sp.RtsEnable = $false
            $sp.Open()
            $sp.DiscardInBuffer()
            $null = $sp.BytesToRead
            return $sp
        } catch {
            if ($sp) { try { $sp.Dispose() } catch { } }
            if ($a -eq $Tries) { throw }
            Start-Sleep -Milliseconds 500
        }
    }
}

function Read-Until {
    param([System.IO.Ports.SerialPort] $Sp, [int] $TimeoutMs, [string] $StopOn, [ref] $Lines)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.ElapsedMilliseconds -lt $TimeoutMs) {
        $l = $null
        try { $l = $Sp.ReadLine() }
        catch [System.TimeoutException] { continue }
        catch { return 'port_lost' }
        if ($null -eq $l) { continue }
        $l = $l.TrimEnd("`r")
        if ($l.Length -gt 0) {
            $Lines.Value += $l
            Add-Content -Path $transcript -Value ('    < ' + $l) -Encoding utf8
        }
        if ($StopOn -and $l -match $StopOn) { return 'matched' }
    }
    return 'timeout'
}

function Send-Cmd {
    param([System.IO.Ports.SerialPort] $Sp, [string] $Cmd)
    Add-Content -Path $transcript -Value ('    > ' + $Cmd) -Encoding utf8
    $Sp.WriteLine($Cmd)
}

function ConvertFrom-HilLine {
    param([string] $Line)
    $h = @{}
    foreach ($f in ($Line -split '\|')) {
        $f = $f.Trim()
        if ($f -match '^([A-Za-z_][A-Za-z0-9_]*)=(.*)$') { $h[$matches[1]] = $matches[2] }
    }
    return $h
}

function Get-Field {
    param($Table, [string] $Key)
    if ($Table -and $Table.ContainsKey($Key)) { return $Table[$Key] }
    return ''
}

function Get-Status {
    param([System.IO.Ports.SerialPort] $Sp)
    $lines = @()
    Send-Cmd $Sp 'status'
    $null = Read-Until -Sp $Sp -TimeoutMs 4000 -StopOn 'HIL\|status\|' -Lines ([ref]$lines)
    $st = $lines | Where-Object { $_ -match 'HIL\|status\|' } | Select-Object -Last 1
    if ($st) { return (ConvertFrom-HilLine $st) }
    return $null
}

function Invoke-Unlock {
    param([System.IO.Ports.SerialPort] $Sp, [string] $Pin, [int] $TimeoutMs = 20000)
    $lines = @()
    Send-Cmd $Sp "unlock $Pin"
    $null = Read-Until -Sp $Sp -TimeoutMs $TimeoutMs -StopOn 'HIL\|unlock\|' -Lines ([ref]$lines)
    $line = $lines | Where-Object { $_ -match 'HIL\|unlock\|' } | Select-Object -Last 1
    $h = $null
    if ($line) { $h = ConvertFrom-HilLine $line }
    return @{
        answered = [bool]$line
        ok       = ((Get-Field $h 'ok') -eq 'true')
        ms       = (Get-Field $h 'ms')
        failures = (Get-Field $h 'failures_after')
        left     = (Get-Field $h 'attempts_left')
        err      = (Get-Field $h 'err')
    }
}

if ($DryRun) {
    Write-Output 'DRY RUN - nothing is sent to the board.'
    Write-Output "  port      : $Port at $Baud"
    Write-Output "  attempts  : $Attempts wrong PINs ($BadPin), about $([math]::Round($Attempts * 2.0 / 60.0, 1)) minutes at 1.9 s of stretch each"
    if ($RebootAt -gt 0) {
        Write-Output "  reboot    : after attempt $RebootAt, prompted once"
    } else {
        Write-Output '  reboot    : none (-RebootAt N adds one, which evidences the reboot half of the gate)'
    }
    Write-Output "  evidence  : $runDir"
    Write-Output ''
    Write-Output 'In order:'
    $steps = @(
        'open the port, wait for the boot banner, read status'
        'REFUSE unless the device reports wipe_after=0 (on a wipe-enabled board this run destroys every record at the threshold, so the precondition is a gate and not a note)'
        'scan, recorded as the ledger occupancy before the streak'
        "unlock $BadPin, $Attempts times, recording failures and attempts_left after each"
    )
    if ($RebootAt -gt 0) {
        $steps += "at attempt $RebootAt, ask for a power cycle and compare the count across it"
    }
    $steps += 'scan again, then unlock with the CORRECT PIN and confirm the count clears'
    for ($i = 0; $i -lt $steps.Count; $i++) {
        Write-Output ('  {0,2}. {1}' -f ($i + 1), $steps[$i])
    }
    Write-Output ''
    Write-Output 'What is being watched, one column: the failure count must rise by exactly one per'
    Write-Output 'attempt, including across the 128-cell boundary where the ledger rotates and the'
    Write-Output 'count moves into failures_base. A count that returns to zero there would make'
    Write-Output 'every guess after it free.'
    Write-Output ''
    Write-Output 'THIS GATE IS NOT DRIVABLE ON THE CURRENT FIRMWARE.'
    Write-Output ''
    Write-Output 'It needs the device to be in the wipe-disabled state, and nothing on the device can'
    Write-Output 'put it there: Vault::set_policy is the only route, firmware/src/store/mod.rs'
    Write-Output 'publishes no path to it, firmware/src/main.rs refuses UiRequest::SetWipePolicy'
    Write-Output 'saying so, and firmware/src/hil.rs has no setpolicy command. The precondition check'
    Write-Output 'in step 2 will refuse on any board built from this tree. The console contract that'
    Write-Output 'unblocks it is the same one power-cut-gate.ps1 -Mode policy needs:'
    Write-Output ''
    Write-Output '  setpolicy <wipe_after|off> <min_pin_len> <pin>'
    Write-Output '      -> HIL|setpolicy|ok=true|wipe_after=N|min_pin_len=N|policy_gen=N'
    return
}

Write-Log "run $stamp port=$Port attempts=$Attempts bad_pin=$BadPin"
Write-Log "evidence: $runDir"

if (-not (Test-PortPresent $Port)) {
    Write-Log "waiting for $Port - connect the board"
    if (-not (Wait-PortBack $Port 300000)) { throw "port $Port never appeared" }
}

$records = @()
$sp = Open-Board $Port $Baud
try {
    $boot = @()
    $null = Read-Until -Sp $sp -TimeoutMs 12000 -StopOn 'HIL\|(status|boot)' -Lines ([ref]$boot)
    $before = Get-Status $sp
    if ($null -eq $before) { throw 'no status line: cannot read the policy, so the precondition cannot be checked' }

    # --- The precondition. This is the most important check in the file. ---
    $wipeAfter = Get-Field $before 'wipe_after'
    if ($wipeAfter -ne '0') {
        Write-Log "REFUSED: the device reports wipe_after=$wipeAfter, so the wipe is ENABLED."
        Write-Log "This run types $Attempts wrong PINs. On this device the wipe would fire at attempt"
        Write-Log "$wipeAfter and destroy every record. Nothing has been sent."
        Write-Log ''
        Write-Log 'The gate needs a wipe-DISABLED device, and no path on the current firmware can'
        Write-Log 'produce one: Vault::set_policy is the only route to it and neither the UI nor the'
        Write-Log 'HIL console publishes one. See tools/hil/RUNBOOK.md, "What is blocked and why".'
        $blocked = Join-Path $runDir 'BLOCKED.txt'
        @(
            "refused: wipe_after=$wipeAfter, the wipe is enabled",
            '',
            'This gate requires wipe_after=0. Nothing was sent to the device.',
            '',
            'Blocked on a firmware surface, not on the bench: the store publishes no route to',
            'Vault::set_policy, so the device cannot be put into the wipe-disabled state at all.',
            'Required console command:',
            '',
            '  setpolicy <wipe_after|off> <min_pin_len> <pin>',
            '      -> HIL|setpolicy|ok=true|wipe_after=N|min_pin_len=N|policy_gen=N'
        ) | Set-Content -Path $blocked -Encoding utf8
        Write-Output ''
        Write-Output "Recorded as a gap, not a run: $blocked"
        return
    }

    $scanBefore = @()
    Send-Cmd $sp 'scan'
    $null = Read-Until -Sp $sp -TimeoutMs 20000 -StopOn 'HIL\|scan\|region=Ledger' -Lines ([ref]$scanBefore)

    $baseFailures = Get-Field $before 'failures'
    Write-Log "starting at failures=$baseFailures epoch=$(Get-Field $before 'epoch') next_seq=$(Get-Field $before 'next_seq')"

    for ($i = 1; $i -le $Attempts; $i++) {
        $u = Invoke-Unlock -Sp $sp -Pin $BadPin
        $st = Get-Status $sp
        $flags = @()
        if ($u.ok) { $flags += 'wrong_pin_opened_the_device' }
        if (-not $u.answered) { $flags += 'no_answer_from_console' }

        $f = Get-Field $st 'failures'
        $expected = ''
        if ($baseFailures -match '^\d+$') { $expected = [int]$baseFailures + $i }
        # Both sides are compared as strings first. An empty column is missing data, and
        # coercing it to a number to find that out is how a check turns into an exception.
        if ($f -match '^\d+$' -and "$expected" -match '^\d+$') {
            if ([int]$f -ne [int]$expected) { $flags += "count_off_by:$([int]$f - [int]$expected)" }
        }
        if ((Get-Field $st 'wipe_after') -ne '0') { $flags += 'wipe_reenabled_mid_run' }
        if ((Get-Field $st 'epoch') -ne (Get-Field $before 'epoch')) { $flags += 'epoch_changed' }

        $records += [pscustomobject]([ordered]@{
            attempt       = $i
            failures      = $f
            expected      = $expected
            attempts_left = (Get-Field $st 'attempts_left')
            epoch         = (Get-Field $st 'epoch')
            next_seq      = (Get-Field $st 'next_seq')
            boot_count    = (Get-Field $st 'boot_count')
            unlock_ms     = $u.ms
            err           = $u.err
            flags         = ($flags -join ';')
        })
        $records | Export-Csv -Path $recordCsv -NoTypeInformation -Encoding utf8
        $records | ConvertTo-Json -Depth 4 | Set-Content -Path $recordJson -Encoding utf8

        if ($flags.Count -gt 0) { Write-Log "attempt $i : failures=$f  FLAGS: $($flags -join '; ')" }
        elseif ($i % 8 -eq 0)   { Write-Log "attempt $i : failures=$f" }

        # A wrong PIN that opened the device ends the run immediately. Continuing would
        # produce 130 more rows of a store whose authentication has already failed.
        if ($u.ok) {
            Write-Log 'STOP: the WRONG PIN opened the device. Nothing after this point is worth measuring.'
            break
        }

        if ($RebootAt -gt 0 -and $i -eq $RebootAt) {
            Write-Log ''
            [Console]::Beep(1200, 250)
            Write-Log ">>> POWER CYCLE THE BOARD NOW (attempt $i of $Attempts) <<<"
            Write-Log "the count must read $f again when it comes back"
            try { if ($sp.IsOpen) { $sp.Close() } } catch { }
            try { $sp.Dispose() } catch { }
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            while ((Test-PortPresent $Port) -and $sw.ElapsedMilliseconds -lt 300000) { Start-Sleep -Milliseconds 100 }
            if (-not (Wait-PortBack $Port 300000)) { throw "port $Port never came back after the power cycle" }
            $sp = Open-Board $Port $Baud
            $b2 = @()
            $null = Read-Until -Sp $sp -TimeoutMs 15000 -StopOn 'HIL\|(status|boot)' -Lines ([ref]$b2)
            $stReboot = Get-Status $sp
            $fReboot = Get-Field $stReboot 'failures'
            $rflags = @()
            if ($fReboot -ne $f) { $rflags += "count_changed_across_reboot:$f->$fReboot" }
            $records += [pscustomobject]([ordered]@{
                attempt       = $i
                failures      = $fReboot
                expected      = $f
                attempts_left = (Get-Field $stReboot 'attempts_left')
                epoch         = (Get-Field $stReboot 'epoch')
                next_seq      = (Get-Field $stReboot 'next_seq')
                boot_count    = (Get-Field $stReboot 'boot_count')
                unlock_ms     = ''
                err           = 'reboot-checkpoint'
                flags         = ($rflags -join ';')
            })
            $records | Export-Csv -Path $recordCsv -NoTypeInformation -Encoding utf8
            Write-Log "after the power cycle: failures=$fReboot (was $f)"
        }
    }

    $scanAfter = @()
    Send-Cmd $sp 'scan'
    $null = Read-Until -Sp $sp -TimeoutMs 20000 -StopOn 'HIL\|scan\|region=Ledger' -Lines ([ref]$scanAfter)

    # The counter must clear on a success. Without this the run evidences only that the
    # count went up, which is half the property: a store that could never be unlocked
    # again would satisfy the other half perfectly.
    $good = Invoke-Unlock -Sp $sp -Pin $Pin
    $stEnd = Get-Status $sp
    Write-Log "correct PIN after the streak: ok=$($good.ok) failures=$(Get-Field $stEnd 'failures')"
} finally {
    try { if ($sp.IsOpen) { $sp.Close() } } catch { }
    try { $sp.Dispose() } catch { }
}

# --- What was observed. Not a verdict. ---
$rows = @($records | Where-Object { $_.err -ne 'reboot-checkpoint' })
$counted = @($rows | Where-Object { $_.failures -match '^\d+$' -and $_.expected -match '^\d+$' })
$off = @($counted | Where-Object { [int]$_.failures -ne [int]$_.expected })
$maxFailures = 0
foreach ($r in $counted) { if ([int]$r.failures -gt $maxFailures) { $maxFailures = [int]$r.failures } }

Write-Output ''
Write-Output "m4a wipe-disabled attempt overflow - $runDir"
Write-Output ('=' * 72)
Write-Output ''
Write-Output "Wrong attempts made   : $($rows.Count)"
Write-Output "Highest count reached : $maxFailures"
if ($counted.Count -eq 0) {
    Write-Output 'Count continuity      : NOT CHECKED - no attempt carried a readable count.'
    Write-Output '                        This is not a pass. Nothing about the rotation was measured.'
} elseif ($off.Count -eq 0) {
    Write-Output "Count continuity      : rose by exactly one across all $($counted.Count) attempts,"
    if ($maxFailures -gt 128) {
        Write-Output '                        including past the 128-cell boundary, so failures_base'
        Write-Output '                        carried the accumulated count through the rotation.'
    } else {
        Write-Output "                        but the highest count reached was $maxFailures. The 128-cell"
        Write-Output '                        boundary was NOT crossed, so the rotation path is unmeasured.'
    }
} else {
    Write-Output "Count continuity      : BROKEN at attempt(s) $(($off | ForEach-Object { $_.attempt }) -join ', ')."
    Write-Output '                        A count that does not rise by one is a free guess. Blocking.'
}
$flagged = @($records | Where-Object { $_.flags -ne '' })
Write-Output "Rows carrying flags   : $($flagged.Count)"
foreach ($r in $flagged) { Write-Output ("  attempt {0}: {1}" -f $r.attempt, $r.flags) }
Write-Output ''
Write-Output "Evidence: $recordCsv"
Write-Output "Console : $transcript"
Write-Output ''
Write-Output 'Read this against the m4a exit gate. This script does not declare it passed.'
