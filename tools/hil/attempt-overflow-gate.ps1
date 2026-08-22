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
    [string] $OutDir   = 'C:\notyas-build\hil',
    [switch] $DryRun,
    # Preflight. Reads the board's command surface and stops there: no wrong PIN, no
    # policy read that changes anything, no run-shaped directory left behind.
    [switch] $Probe
)

$ErrorActionPreference = 'Stop'

# Exit codes, shared with power-cut-gate.ps1 so a wrapper can read either the same way.
# The rule behind them: no path out of this script is allowed to end without a verdict on
# stdout and a matching code. A gate that returns quietly having done nothing is worse than
# one that crashes, because a crash gets investigated (2026-08-19, an evening).
$EXIT_OK               = 0   # the soak ran and recorded attempts
$EXIT_HARNESS          = 1   # bad arguments, or an unhandled harness error
$EXIT_PORT_ABSENT      = 2   # the port never enumerated
$EXIT_SILENT           = 3   # the port opened and nothing at all came back
$EXIT_NO_CONSOLE       = 4   # the board talks, but carries no HIL console
$EXIT_MISSING_COMMANDS = 5   # the console is there and lacks what this gate drives
$EXIT_REFUSED          = 6   # a precondition or a blocking finding ended it
$EXIT_NO_EVIDENCE      = 7   # it ended having measured nothing

# The console commands this gate drives. Read from `help` before a single wrong PIN is
# typed, because a console that swallows `unlock` would produce 136 rows of nothing and
# look exactly like a soak.
$NEEDS = @('unlock','status','scan')

trap {
    Write-Output ''
    Write-Output ('=' * 72)
    Write-Output 'THE GATE DID NOT COMPLETE - unhandled harness error.'
    Write-Output ''
    Write-Output "  $($_.Exception.Message)"
    Write-Output "  at line $($_.InvocationInfo.ScriptLineNumber): $(($_.InvocationInfo.Line).Trim())"
    Write-Output ''
    Write-Output ('=' * 72)
    Write-Output ''
    Write-Output 'VERDICT: NOT RUN (harness_error), exit 1'
    exit 1
}

$BOARD_BY_PORT = @{
    'COM6' = @{ Board = 'elecrow-5';    Features = 'hil-console' }
    'COM3' = @{ Board = 'waveshare-4b'; Features = 'hil-console,unsafe-emulated-key' }
}

function Get-BoardForPort {
    param([string] $Name)
    if ($BOARD_BY_PORT.ContainsKey($Name)) { return $BOARD_BY_PORT[$Name] }
    return @{ Board = 'elecrow-5'; Features = 'hil-console'; Guessed = $true }
}

if ($OutDir -match '^(\\\\|//)') { throw "OutDir must be a local path, not a UNC path: $OutDir" }

$stamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
$runDir = Join-Path $OutDir "overflow-$stamp"
# A probe creates a log FILE and never a run-shaped directory: an `overflow-*` directory
# with no attempts.csv in it is the shape this bench has already learned to misread.
if (-not $DryRun) {
    if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
    if (-not $Probe) { New-Item -ItemType Directory -Path $runDir -Force | Out-Null }
}
$transcript = Join-Path $runDir 'console.log'
$recordCsv  = Join-Path $runDir 'attempts.csv'
$recordJson = Join-Path $runDir 'attempts.json'
if ($Probe) { $transcript = Join-Path $OutDir "probe-overflow-$stamp.log" }

function Write-Log {
    param([string] $Text)
    $line = '{0} {1}' -f (Get-Date -Format 'HH:mm:ss.fff'), $Text
    Add-Content -Path $transcript -Value $line -Encoding utf8
    Write-Output $line
}

# Write-Log for use inside a function that returns a value: Write-Output would append the
# message to that function's return value and every property read off it afterwards would
# quietly be reading a log line.
function Write-Note {
    param([string] $Text)
    $line = '{0} {1}' -f (Get-Date -Format 'HH:mm:ss.fff'), $Text
    try { Add-Content -Path $transcript -Value $line -Encoding utf8 } catch { }
    Write-Host $line
}

function Write-Loud {
    param([string[]] $Lines)
    $bar = '=' * 72
    foreach ($l in (@('', $bar) + $Lines + @($bar, ''))) {
        Write-Output $l
        try { Add-Content -Path $transcript -Value $l -Encoding utf8 } catch { }
    }
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

# -------------------------------------------------------------------------------------
# The capability probe, and the four ways a board can fail to be drivable
# -------------------------------------------------------------------------------------
#
# Four rather than one because they need four different actions from the person at the
# bench, and a single "cannot talk to the board" sends them checking the cable when the
# answer is a rebuild:
#
#   port_absent      - nothing enumerates. Cable, power, or the wrong COM name.
#   silent           - the port opens and NOTHING arrives, not even a log line. Wrong baud,
#                      EN held low, or the ROM bootloader after a failed flash.
#   no_console       - the board talks and `help` produced no HIL line. The image was built
#                      without the hil-console feature.
#   missing_commands - the console answered and lacks what this gate drives.
#
# This gate used to have no probe at all. On a console-less image its first `status` came
# back empty and it threw "no status line: cannot read the policy" - non-zero and loud, but
# pointing at the policy when the fault was the image, which is a different evening's work.
function Get-HelpTable {
    param([System.IO.Ports.SerialPort] $Sp)
    $lines = @()
    Send-Cmd $Sp 'help'
    $null = Read-Until -Sp $Sp -TimeoutMs 6000 -StopOn $null -Lines ([ref]$lines)
    $cmds = @()
    foreach ($l in $lines) {
        if ($l -match 'HIL\|help\|\s*([a-z][a-z0-9_]*)') { $cmds += $matches[1] }
    }
    return @{ Commands = @($cmds | Sort-Object -Unique); Lines = @($lines) }
}

function Get-ConsoleReadiness {
    param([string] $Name, [int] $Rate, [string[]] $Needs)

    $r = @{ Verdict = 'ok'; Have = @(); Missing = @(); Lines = 0; Hil = 0; Tail = @(); Error = '' }

    if (-not (Test-PortPresent $Name)) {
        Write-Note "waiting up to 60 s for $Name - connect the board"
        if (-not (Wait-PortBack $Name 60000)) { $r.Verdict = 'port_absent'; return $r }
    }
    $sp = $null
    try { $sp = Open-Board $Name $Rate }
    catch { $r.Verdict = 'port_absent'; $r.Error = $_.Exception.Message; return $r }
    try {
        $boot = @()
        $null = Read-Until -Sp $sp -TimeoutMs 12000 -StopOn 'HIL\|(status|boot)' -Lines ([ref]$boot)
        $help = Get-HelpTable $sp
        $all  = @($boot) + @($help.Lines)
        $r.Lines = $all.Count
        $r.Hil   = @($all | Where-Object { $_ -match 'HIL\|' }).Count
        $r.Tail  = @($all | Select-Object -Last 3)
        $r.Have  = @($help.Commands)
    } finally {
        try { if ($sp.IsOpen) { $sp.Close() } } catch { }
        try { $sp.Dispose() } catch { }
    }

    if ($r.Lines -eq 0)      { $r.Verdict = 'silent';     return $r }
    if ($r.Have.Count -eq 0) { $r.Verdict = 'no_console'; return $r }
    $r.Missing = @($Needs | Where-Object { $r.Have -notcontains $_ })
    if ($r.Missing.Count -gt 0) { $r.Verdict = 'missing_commands' }
    return $r
}

# A run that did nothing must not leave a directory that looks like a run. The transcript
# is kept - it is the proof of what the board said, which is what turns "the gate did not
# run" into "the gate did not run BECAUSE ..." - so the directory moves out of the
# overflow-* namespace instead of being deleted, and is stamped with a file whose name is
# the whole story.
function Move-EvidenceAside {
    param([string] $Dir, [string] $Code, [string[]] $Why)
    if ($DryRun -or $Probe) { return $null }
    if (-not (Test-Path $Dir)) { return $null }
    $note = @("NOT A RUN - $Code", '') + $Why + @(
        '',
        'No wrong PIN was typed and nothing that changes the device was sent. There is no',
        'attempts.csv in this directory and there must never be one: this is the record of a',
        'gate that refused to start, kept so the console transcript can be read, and it is',
        'not evidence for any exit criterion.'
    )
    try { $note | Set-Content -Path (Join-Path $Dir 'NOT-A-RUN.txt') -Encoding utf8 } catch { }
    # A name collision must not put the directory back in the overflow-* namespace, which
    # is what giving up here would do. Uniquify instead; only a directory something else
    # has open reaches the fallback below.
    $parent = Split-Path -Parent $Dir
    $base   = 'aborted-' + (Split-Path -Leaf $Dir)
    try {
        $leaf = $base
        $n = 1
        while (Test-Path (Join-Path $parent $leaf)) { $leaf = "$base-$n"; $n++ }
        Rename-Item -Path $Dir -NewName $leaf -ErrorAction Stop
        return (Join-Path $parent $leaf)
    } catch {
        Write-Note "WARNING: could not rename $Dir out of the overflow-* namespace ($($_.Exception.Message))."
        Write-Note '         It carries NOT-A-RUN.txt instead. Do not read it as a run.'
        return $Dir
    }
}

function Stop-Run {
    param([string] $Code, [int] $ExitCode, [string[]] $Lines)
    Write-Loud $Lines
    $moved = Move-EvidenceAside -Dir $runDir -Code $Code -Why $Lines
    if ($moved) {
        Write-Output 'The evidence directory was not left looking like a run. It is now:'
        Write-Output "  $moved"
        Write-Output ''
    }
    Write-Output "VERDICT: NOT RUN ($Code), exit $ExitCode"
    exit $ExitCode
}

function Stop-OnReadiness {
    param($R)
    $b     = Get-BoardForPort $Port
    $build = ".\tools\build.ps1 -Board $($b.Board) --features $($b.Features)"
    $flash = ".\tools\flash.ps1 -Board $($b.Board) -Port $Port"
    $guess = @()
    if ($b.ContainsKey('Guessed')) {
        $guess = @('', "($Port is not one of the two known bench ports, so the board flag above is",
                       ' this file''s default rather than a fact. Check it before you flash.)')
    }

    switch ($R.Verdict) {
        'port_absent' {
            $present = @([System.IO.Ports.SerialPort]::GetPortNames() | Sort-Object)
            $list = 'none at all'
            if ($present.Count -gt 0) { $list = ($present -join ', ') }
            $why = @()
            if ($R.Error) { $why = @("The open failed with: $($R.Error)", '') }
            Stop-Run -Code 'port_absent' -ExitCode $EXIT_PORT_ABSENT -Lines (@(
                "CANNOT DRIVE THE BOARD: $Port is not usable.",
                '',
                "What was missing  : the serial port $Port, after waiting 60 s for it.",
                "Ports present now : $list") + $why + @(
                'Most likely cause : the USB cable is out, the board has no power, or this is',
                '                    the wrong port name for it. If the name is in the list',
                '                    above, something else already has it open.',
                '',
                'Fix: connect the board, close anything holding the port, then re-run:',
                "     .\tools\hil\attempt-overflow-gate.ps1 -Port <name from the list> -Probe"
            ))
        }
        'silent' {
            Stop-Run -Code 'silent' -ExitCode $EXIT_SILENT -Lines (@(
                "CANNOT DRIVE THE BOARD: $Port opened and the board said nothing at all.",
                '',
                '  What was missing  : every line. No boot banner, no IDF log, no console',
                "                      output - zero bytes in 18 s at $Baud baud.",
                '  Most likely cause : the baud rate is wrong (the firmware logs at 115200),',
                '                      the board is held in reset, or it is sitting in the ROM',
                '                      bootloader after a flash that did not finish.',
                '',
                'Fix, in this order:',
                '  1. press reset on the board and re-run the probe;',
                "  2. confirm -Baud is 115200 (this run used $Baud);",
                '  3. if it is stuck in the bootloader, reflash it:',
                "       $build",
                "       $flash") + $guess
            )
        }
        'no_console' {
            $tail = @()
            foreach ($l in $R.Tail) { $tail += "                      $l" }
            $cause = @(
                '  Most likely cause : the flashed image was built WITHOUT the hil-console',
                '                      feature. A product image has no console at all, so',
                '                      every command this gate sends is swallowed and every',
                '                      answer it waits for never arrives.')
            if ($R.Hil -gt 0) {
                $cause = @(
                    "  Most likely cause : the image DOES carry a console - $($R.Hil) HIL lines came",
                    '                      back - but its help table did not parse. That is a',
                    '                      console defect in firmware/src/hil.rs, not a missing',
                    '                      feature, and this gate will not type wrong PINs at a',
                    '                      command surface it could not read.')
            }
            Stop-Run -Code 'no_console' -ExitCode $EXIT_NO_CONSOLE -Lines (@(
                "CANNOT DRIVE THE BOARD: $Port answers, and there is no HIL console on it.",
                '',
                '  What was missing  : the help table. The command help produced no HIL|help|',
                "                      line. The board is alive - $($R.Lines) lines arrived - and",
                '                      none of them came from a console. The last of them:') + $tail + @(
                '') + $cause + @(
                '',
                'Fix - rebuild with the feature and reflash, then probe again:',
                "    $build",
                "    $flash",
                "    .\tools\hil\attempt-overflow-gate.ps1 -Port $Port -Probe") + $guess
            )
        }
        'missing_commands' {
            Stop-Run -Code 'missing_commands' -ExitCode $EXIT_MISSING_COMMANDS -Lines @(
                'CANNOT DRIVE THE BOARD: the console is there and does not carry what this gate drives.',
                '',
                "  Missing commands  : $($R.Missing -join ', ')",
                "  This gate needs   : $($NEEDS -join ', ')",
                "  The device has    : $($R.Have -join ' ')",
                '',
                '  Most likely cause : a firmware gap rather than a bench problem. If this',
                '                      board was flashed from an older tree, reflash it:',
                "                        $build",
                "                        $flash",
                '                      If the commands are absent from firmware/src/hil.rs',
                '                      altogether, the gate is blocked on firmware and no',
                '                      amount of bench time closes it.'
            )
        }
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
    Write-Output ''
    Write-Output 'VERDICT: DRY RUN, nothing was sent, exit 0'
    exit $EXIT_OK
}

Write-Log "run $stamp port=$Port attempts=$Attempts bad_pin=$BadPin"
if ($Probe) {
    Write-Log 'PROBE ONLY - reads the board, types no PIN, sends nothing that changes it'
    Write-Log "probe log: $transcript"
} else {
    Write-Log "evidence: $runDir"
}

# --- The capability probe, before a single wrong PIN. ---
$ready = Get-ConsoleReadiness -Name $Port -Rate $Baud -Needs $NEEDS
if ($ready.Verdict -ne 'ok') { Stop-OnReadiness $ready }
Write-Log "device exposes $($ready.Have.Count) console commands; all $($NEEDS.Count) this gate needs are present"

if ($Probe) {
    Write-Loud @(
        "READY: $Port can be driven for the attempt-overflow gate.",
        '',
        "  Console commands present : $($ready.Have.Count)",
        "  This gate needs          : $($NEEDS -join ', ')",
        '  All present.',
        '',
        'This says the console can be driven. It does NOT say the gate can run: that also',
        'needs wipe_after=0, which the run itself checks and refuses without. Nothing that',
        'changes the device was sent, and no evidence directory was created.'
    )
    Write-Output "Probe log: $transcript"
    Write-Output ''
    Write-Output 'VERDICT: READY, exit 0'
    exit $EXIT_OK
}

$records = @()
# Why the soak ended, when it did not end by finishing its attempts. The summary at the
# bottom has to be able to say "this stopped at attempt 40 of 136" rather than printing a
# tidy table that reads like a completed run.
$stopReason = ''
$sp = Open-Board $Port $Baud
try {
    $boot = @()
    $null = Read-Until -Sp $sp -TimeoutMs 12000 -StopOn 'HIL\|(status|boot)' -Lines ([ref]$boot)
    $before = Get-Status $sp
    if ($null -eq $before) {
        # The probe already proved `status` exists on this image, so an unparseable status
        # line here is a genuine anomaly rather than the wrong firmware. Say which, or the
        # operator reflashes a board that did not need it.
        Stop-Run -Code 'no_status_line' -ExitCode $EXIT_REFUSED -Lines @(
            "REFUSED: $Port has a working console and would not answer status.",
            '',
            '  What was missing  : the HIL|status| line, within 4 s of asking.',
            '  Most likely cause : the console is present - the probe read its help table a',
            '                      moment ago - so this is the store failing to report, not a',
            '                      missing feature. A board mid-boot, or a store that cannot',
            '                      mount, both look like this.',
            '',
            'The policy cannot be read, so the precondition below cannot be checked, so this',
            'gate must not type its first wrong PIN. Read console.log, then re-probe:',
            '',
            "    .\tools\hil\attempt-overflow-gate.ps1 -Port $Port -Probe"
        )
    }

    # --- The precondition. This is the most important check in the file. ---
    $wipeAfter = Get-Field $before 'wipe_after'
    if ($wipeAfter -ne '0') {
        Stop-Run -Code 'wipe_enabled' -ExitCode $EXIT_REFUSED -Lines @(
            "REFUSED: the device reports wipe_after=$wipeAfter, so the wipe is ENABLED.",
            '',
            "  What was missing  : the wipe-DISABLED precondition. This gate types $Attempts wrong",
            "                      PINs; on this device the wipe fires at attempt $wipeAfter and",
            '                      destroys every record. Not one PIN was sent.',
            '  Most likely cause : nothing on the current firmware can reach the wipe-disabled',
            '                      state. Vault::set_policy is the only route to it,',
            '                      firmware/src/store/mod.rs publishes none, firmware/src/main.rs',
            '                      refuses UiRequest::SetWipePolicy and says why, and',
            '                      firmware/src/hil.rs has no setpolicy command.',
            '',
            'Fix - this one is firmware, not bench time. The console command that unblocks it:',
            '',
            '    setpolicy <wipe_after|off> <min_pin_len> <pin>',
            '        -> HIL|setpolicy|ok=true|wipe_after=N|min_pin_len=N|policy_gen=N',
            '',
            'See tools/hil/RUNBOOK.md, "What is blocked, and why". Until it lands, what covers',
            'this property is the host fuzzer Op::RotationOnFailure, which is a different claim',
            'from hardware and must be written as one.'
        )
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
            $stopReason = "the wrong PIN opened the device at attempt $i - authentication failed, so every row after it would describe a store that is already broken"
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

# --- How the soak ended. Three outcomes, three exit codes, none of them silence. ---
#
# This block used to be absent: the table above printed and the script exited zero, whether
# it had measured 136 attempts or none. "Count continuity: NOT CHECKED - this is not a pass"
# followed by exit 0 is a sentence that says one thing to a reader and the opposite to
# anything that reads the exit code, and only one of those two gets read at 2am.
if ($stopReason) {
    Write-Loud @(
        'THE SOAK DID NOT FINISH.',
        '',
        "  $stopReason",
        '',
        "  Attempts requested : $Attempts",
        "  Attempts made      : $($rows.Count)",
        '',
        'The rows already written are real. The gate is not closed by them: it asks for 128+',
        'consecutive failures, and this run did not get there.'
    )
    Write-Output "VERDICT: STOPPED EARLY after $($rows.Count) of $Attempts attempt(s), exit $EXIT_REFUSED"
    exit $EXIT_REFUSED
}

if ($counted.Count -eq 0) {
    Write-Loud @(
        'THE SOAK MEASURED NOTHING.',
        '',
        "  Attempts made   : $($rows.Count)",
        '  With a readable count on both sides : 0',
        '',
        'Nothing here evidences the rotation path, and the one column this gate exists to',
        'watch was never read. Not a pass, not a finding - read console.log, then re-probe:',
        '',
        "    .\tools\hil\attempt-overflow-gate.ps1 -Port $Port -Probe"
    )
    Write-Output "VERDICT: NO EVIDENCE, exit $EXIT_NO_EVIDENCE"
    exit $EXIT_NO_EVIDENCE
}

if ($off.Count -gt 0) {
    Write-Output ''
    Write-Output "VERDICT: BLOCKING FINDING - the count did not rise by one on attempt(s) $(($off | ForEach-Object { $_.attempt }) -join ', '), exit $EXIT_REFUSED"
    exit $EXIT_REFUSED
}

Write-Output ''
if ($maxFailures -le 128) {
    Write-Output "VERDICT: INCOMPLETE - $($counted.Count) attempt(s) all continuous, but the highest count"
    Write-Output "         reached was $maxFailures and the 128-cell boundary was never crossed, so the"
    Write-Output "         rotation path this gate exists to measure is unmeasured. exit $EXIT_NO_EVIDENCE"
    exit $EXIT_NO_EVIDENCE
}
Write-Output "VERDICT: MEASURED - $($counted.Count) attempt(s), continuous past the 128-cell boundary, exit $EXIT_OK"
Write-Output '         This is the observation, not a verdict on the gate. A human reads it against m4a.'
exit $EXIT_OK
