# The 0.2.0 release bar, driven over the HIL console and recorded.
#
# MILESTONES.md section 9 clause 2 is the only clause that can fail the release on its own:
#
#   "A working wallet does the whole loop on real hardware, which is the actual bar the
#    re-scope was aimed at: create or import a seed, save it under a PIN, power cycle,
#    unlock, register a 2-of-3 P2WSH multisig, verify the first receive address against
#    another signer, load a PSBT from SD, review it, sign it, and hand the result to a
#    coordinator that accepts it. If that loop has a gap, the release is not done
#    regardless of what else is green."
#
# Every other gate is a property of a part. This one is the product working, so it is worth
# a harness rather than a checklist somebody ticks.
#
# WHAT THIS DOES THAT A CHECKLIST DOES NOT. It asks the device what it can do before it
# starts, by parsing `help`, and reports which steps of the loop are not yet drivable at
# all. Run today, that is the answer: it names the missing firmware surface. Run after the
# signing integration lands, the same script closes the gate. The report is the same shape
# either way, so the two are comparable.
#
# It records. It does not declare the release done - the operator reads the transcript
# against the clause above. A harness that prints PASS is a harness that gets believed when
# it should not be.
[CmdletBinding()]
param(
    [string] $Port   = 'COM6',
    [int]    $Baud   = 115200,
    [string] $Pin    = '1234',
    [int]    $Slot   = 1,
    [string] $OutDir = 'C:\nb\hil',
    # A 2-of-3 P2WSH sortedmulti descriptor. Supplied rather than generated: the point of
    # step 5 is that THIS device agrees with cosigners it did not create, so a descriptor
    # the device produced itself would prove nothing.
    [string] $Descriptor = '',
    # A PSBT in hex that spends from the registered wallet. Same reasoning: it must come
    # from a coordinator, not from here.
    [string] $PsbtHex = '',
    [switch] $DryRun
)

$ErrorActionPreference = 'Stop'

# Exit codes, shared with the other HIL gates so a wrapper can read them the same way.
# Nothing here ends without a verdict on stdout and a matching code: this script's whole
# product is a statement about what the device can do, and a statement that exits zero
# while saying THE LOOP IS NOT YET DRIVABLE is two contradictory answers to one question.
$EXIT_OK           = 0  # every step is drivable
$EXIT_HARNESS      = 1  # bad arguments, or an unhandled harness error
$EXIT_PORT_ABSENT  = 2  # the port never enumerated
$EXIT_SILENT       = 3  # the port opened and nothing at all came back
$EXIT_NO_CONSOLE   = 4  # the board talks, but carries no HIL console
$EXIT_NOT_DRIVABLE = 5  # the console is there and the loop has gaps in it

trap {
    Write-Output ''
    Write-Output ('=' * 72)
    Write-Output 'THE LOOP CHECK DID NOT COMPLETE - unhandled harness error.'
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

if ($OutDir -match '^(\\\\|//)') { throw "OutDir must be local, not a UNC path: $OutDir" }
$stamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
$runDir = Join-Path $OutDir "e2e-$stamp"
# A dry run creates nothing. It used to create the directory before it checked -DryRun,
# which left an empty e2e-* behind that looked like a run of the release loop and was not.
if (-not $DryRun) {
    if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
    New-Item -ItemType Directory -Path $runDir -Force | Out-Null
}
$transcript = Join-Path $runDir 'console.log'
$reportPath = Join-Path $runDir 'loop-report.txt'
$jsonPath   = Join-Path $runDir 'loop-report.json'

# The loop, in the order the milestone states it. Each step names the HIL command it needs,
# or $null where the step is physical and the operator performs it.
$STEPS = @(
    @{ n = 1;  name = 'create or import a seed';                 cmd = 'format';       physical = $false }
    @{ n = 2;  name = 'save it under a PIN';                     cmd = 'seal';         physical = $false }
    @{ n = 3;  name = 'power cycle';                             cmd = $null;          physical = $true  }
    @{ n = 4;  name = 'unlock';                                  cmd = 'unlock';       physical = $false }
    @{ n = 5;  name = 'register a 2-of-3 P2WSH multisig';        cmd = 'register';     physical = $false }
    @{ n = 6;  name = 'verify the first receive address';        cmd = 'address';      physical = $false }
    @{ n = 7;  name = 'load a PSBT';                             cmd = 'psbtload';     physical = $false }
    @{ n = 8;  name = 'review it';                               cmd = 'psbtinspect';  physical = $false }
    @{ n = 9;  name = 'sign it';                                 cmd = 'psbtsign';     physical = $false }
    @{ n = 10; name = 'a coordinator accepts the result';        cmd = $null;          physical = $true  }
)

function Write-Log {
    param([string] $Text)
    $line = '{0} {1}' -f (Get-Date -Format 'HH:mm:ss.fff'), $Text
    Add-Content -Path $transcript -Value $line -Encoding utf8
    Write-Output $line
}

# For use inside a value-returning function, where Write-Output would append the message
# to the return value and every property read off it afterwards would read a log line.
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

# A check that could not reach the device must not leave an e2e-* directory: that name is
# the record of a release-loop run, and one containing nothing but a boot log has already
# been mistaken for a result once on this bench. The transcript is kept - it is the proof
# of what the board actually said - under a name that cannot be misread.
function Move-EvidenceAside {
    param([string] $Dir, [string] $Code, [string[]] $Why)
    if ($DryRun) { return $null }
    if (-not (Test-Path $Dir)) { return $null }
    $note = @("NOT A RUN - $Code", '') + $Why + @(
        '',
        'The device was never reached, so nothing in this directory says anything about',
        'MILESTONES section 9 clause 2. There is no loop-report.txt here and there must',
        'never be one.'
    )
    try { $note | Set-Content -Path (Join-Path $Dir 'NOT-A-RUN.txt') -Encoding utf8 } catch { }
    $parent = Split-Path -Parent $Dir
    $base   = 'aborted-' + (Split-Path -Leaf $Dir)
    try {
        $leaf = $base
        $n = 1
        while (Test-Path (Join-Path $parent $leaf)) { $leaf = "$base-$n"; $n++ }
        Rename-Item -Path $Dir -NewName $leaf -ErrorAction Stop
        return (Join-Path $parent $leaf)
    } catch {
        Write-Note "WARNING: could not rename $Dir out of the e2e-* namespace ($($_.Exception.Message))."
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

function Test-PortPresent { param([string] $Name)
    return ([System.IO.Ports.SerialPort]::GetPortNames() -contains $Name)
}

function Open-Board {
    param([string] $Name, [int] $Rate, [int] $Attempts = 12)
    # Retrying, for the same reason the power-cut harness retries: a board that was just
    # re-powered can enumerate more than once while USB settles, and a handle opened
    # against the first enumeration dies on its first write.
    for ($a = 1; $a -le $Attempts; $a++) {
        try {
            $sp = New-Object System.IO.Ports.SerialPort $Name, $Rate, 'None', 8, 'One'
            $sp.ReadTimeout = 400; $sp.WriteTimeout = 2000; $sp.NewLine = "`n"
            # DTR/RTS drive EN and GPIO0; both stay deasserted or opening the port resets
            # the board, which would silently restart the very state we are testing.
            $sp.DtrEnable = $false; $sp.RtsEnable = $false
            $sp.Open(); $sp.DiscardInBuffer(); $null = $sp.BytesToRead
            return $sp
        } catch {
            if ($sp) { try { $sp.Dispose() } catch { } }
            if ($a -eq $Attempts) { throw }
            Start-Sleep -Milliseconds 500
        }
    }
}

function Invoke-Hil {
    param([System.IO.Ports.SerialPort] $Sp, [string] $Cmd, [int] $TimeoutMs = 12000, [string] $StopOn = $null)
    Add-Content -Path $transcript -Value ('    > ' + $Cmd) -Encoding utf8
    $Sp.WriteLine($Cmd)
    $lines = @()
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.ElapsedMilliseconds -lt $TimeoutMs) {
        try { $l = $Sp.ReadLine() } catch [System.TimeoutException] { continue } catch { break }
        if (-not $l) { continue }
        $l = $l.TrimEnd("`r")
        $lines += $l
        Add-Content -Path $transcript -Value ('    < ' + $l) -Encoding utf8
        if ($StopOn -and $l -match $StopOn) { break }
    }
    return $lines
}

if ($DryRun) {
    Write-Output 'DRY RUN - nothing is sent to the board.'
    Write-Output "  port     : $Port at $Baud"
    Write-Output "  evidence : $runDir"
    Write-Output ''
    Write-Output 'The loop, per MILESTONES section 9 clause 2:'
    foreach ($s in $STEPS) {
        $how = if ($s.physical) { 'operator' } else { "HIL '$($s.cmd)'" }
        Write-Output ("  {0,2}. {1,-42} {2}" -f $s.n, $s.name, $how)
    }
    Write-Output ''
    Write-Output 'Supply -Descriptor and -PsbtHex from a COORDINATOR, not from this device.'
    Write-Output 'Steps 5 and 7 prove agreement with software that did not create them, so'
    Write-Output 'self-generated inputs would prove nothing.'
    Write-Output ''
    Write-Output 'VERDICT: DRY RUN, nothing was sent, exit 0'
    exit $EXIT_OK
}

Write-Log "run $stamp port=$Port"
Write-Log "evidence: $runDir"
Write-Log 'THE BAR: MILESTONES section 9 clause 2. This records; it does not declare done.'

$board = Get-BoardForPort $Port
$build = ".\tools\build.ps1 -Board $($board.Board) --features $($board.Features)"
$flash = ".\tools\flash.ps1 -Board $($board.Board) -Port $Port"
$guess = @()
if ($board.ContainsKey('Guessed')) {
    $guess = @('', "($Port is not one of the two known bench ports, so the board flag above is",
                   ' this file''s default rather than a fact. Check it before you flash.)')
}

if (-not (Test-PortPresent $Port)) {
    $present = @([System.IO.Ports.SerialPort]::GetPortNames() | Sort-Object)
    $list = 'none at all'
    if ($present.Count -gt 0) { $list = ($present -join ', ') }
    Stop-Run -Code 'port_absent' -ExitCode $EXIT_PORT_ABSENT -Lines @(
        "CANNOT REACH THE BOARD: $Port is not there.",
        '',
        "What was missing  : the serial port $Port.",
        "Ports present now : $list",
        'Most likely cause : the USB cable is out, the board has no power, or this is the',
        '                    wrong port name for it.',
        '',
        'Fix: connect the board and re-run with -Port <a name from the list above>.'
    )
}
$sp = $null
try { $sp = Open-Board $Port $Baud }
catch {
    Stop-Run -Code 'port_absent' -ExitCode $EXIT_PORT_ABSENT -Lines @(
        "CANNOT REACH THE BOARD: $Port enumerated and would not open.",
        '',
        "What was missing  : a handle on $Port. The open failed with:",
        "                      $($_.Exception.Message)",
        'Most likely cause : something else already has the port open - a serial monitor,',
        '                    or another HIL gate still running.',
        '',
        'Fix: close whatever holds the port, then re-run.'
    )
}

# --- Capability probe. This is what makes the script useful before the loop is complete. ---
#
# It also has to tell three different silences apart, because they are three different
# actions for the person reading the report. A board that answers nothing, a board with no
# console on it, and a board whose console simply does not carry `psbtsign` yet all used to
# produce the same output here - "NOT DRIVABLE" against every step, exit 0 - and only the
# third of those is a statement about the firmware's progress. The first two are a bench
# mistake being written into the release record as a milestone gap.
Write-Log '=== probing the device command surface ==='
$boot = @()
try {
    $boot = Invoke-Hil -Sp $sp -Cmd 'help' -TimeoutMs 6000
} finally {
    try { if ($sp.IsOpen) { $sp.Close() } } catch { }
    try { $sp.Dispose() } catch { }
}
$help = @($boot)
$hilLines = @($help | Where-Object { $_ -match 'HIL\|' }).Count

$available = @()
foreach ($l in $help) {
    # Anchored on the FIRST token after `HIL|help|`, which is the command. Splitting the
    # whole line and keeping every lower-case word collected the descriptions too, so a
    # step whose command name happened to appear in some other command's help text - and
    # `read` does, in "read a payload slot back" - was reported drivable when it was not.
    if ($l -match 'HIL\|help\|\s*([a-z][a-z0-9_]*)') { $available += $matches[1] }
}
$available = @($available | Sort-Object -Unique)
Write-Log ("device reports " + $available.Count + " commands: " + ($available -join ' '))

if ($help.Count -eq 0) {
    Stop-Run -Code 'silent' -ExitCode $EXIT_SILENT -Lines (@(
        "CANNOT REACH THE BOARD: $Port opened and the board said nothing at all.",
        '',
        '  What was missing  : every line. Not one byte arrived in 6 s at ' + $Baud + ' baud.',
        '  Most likely cause : the baud rate is wrong (the firmware logs at 115200), the',
        '                      board is held in reset, or it is sitting in the ROM bootloader',
        '                      after a flash that did not finish.',
        '',
        'Fix: press reset and re-run. If it is stuck in the bootloader, reflash it:',
        "    $build",
        "    $flash") + $guess
    )
}
if ($available.Count -eq 0) {
    $tail = @()
    foreach ($l in (@($help) | Select-Object -Last 3)) { $tail += "                      $l" }
    $cause = @(
        '  Most likely cause : the flashed image was built WITHOUT the hil-console feature.',
        '                      A product image has no console, so this check cannot ask the',
        '                      device anything and MUST NOT report the loop as undrivable -',
        '                      that would write a bench mistake into the release record as a',
        '                      firmware gap.')
    if ($hilLines -gt 0) {
        $cause = @(
            "  Most likely cause : the image DOES carry a console - $hilLines HIL lines came back -",
            '                      but its help table did not parse. A console defect in',
            '                      firmware/src/hil.rs rather than a missing feature.')
    }
    Stop-Run -Code 'no_console' -ExitCode $EXIT_NO_CONSOLE -Lines (@(
        "CANNOT REACH THE BOARD: $Port answers, and there is no HIL console on it.",
        '',
        '  What was missing  : the help table. The command help produced no HIL|help| line.',
        "                      The board is alive - $($help.Count) lines arrived - and none of them",
        '                      came from a console. The last of them:') + $tail + @(
        '') + $cause + @(
        '',
        'Fix - rebuild with the feature and reflash, then re-run:',
        "    $build",
        "    $flash") + $guess
    )
}

$results = @()
$missing = @()
foreach ($s in $STEPS) {
    $state = 'operator-step'
    if ($s.cmd) {
        if ($available -contains $s.cmd) { $state = 'drivable' }
        else { $state = 'NOT DRIVABLE - firmware does not expose it'; $missing += $s.cmd }
    }
    $results += [pscustomobject]@{ step = $s.n; name = $s.name; command = $s.cmd; state = $state }
}

# The port was closed by the probe's finally, above: nothing after it talks to the board.

# --- Report ---
$lines = @()
$lines += ''
$lines += 'notyas 0.2.0 - end-to-end release loop'
$lines += ('=' * 72)
$lines += ''
$lines += 'MILESTONES.md section 9 clause 2 is the bar. Every step below must work on real'
$lines += 'hardware before 0.2.0 is done, and no other green gate substitutes for it.'
$lines += ''
foreach ($r in $results) {
    $lines += ("  {0,2}. {1,-42} {2}" -f $r.step, $r.name, $r.state)
}
$lines += ''
if ($missing.Count -gt 0) {
    $lines += 'THE LOOP IS NOT YET DRIVABLE.'
    $lines += ''
    $lines += ('Missing firmware commands: ' + ($missing -join ', '))
    $lines += ''
    $lines += 'This is a firmware integration gap, not a missing feature: the PSBT engine'
    $lines += '(crates/notyas-core/src/psbt/) and multisig registration'
    $lines += '(crates/notyas-core/src/multisig.rs) are complete and host-proven. They are'
    $lines += 'simply not wired into the device yet, so the device cannot sign. Until they'
    $lines += 'are, clause 2 cannot be attempted, and the release cannot be called done.'
} else {
    $lines += 'Every step is drivable. Run the loop with -Descriptor and -PsbtHex supplied'
    $lines += 'from a coordinator, capture the transcript, and read it against clause 2.'
}
$lines += ''
$lines += "Evidence: $transcript"
$lines += ''

$lines | Set-Content -Path $reportPath -Encoding utf8
$results | ConvertTo-Json -Depth 4 | Set-Content -Path $jsonPath -Encoding utf8
$lines | ForEach-Object { Write-Output $_ }

# The report is a real answer either way, and the exit code has to agree with it. A run
# that printed THE LOOP IS NOT YET DRIVABLE and exited zero told a human one thing and any
# wrapper the opposite, and the wrapper is what gets believed when nobody is reading.
if ($missing.Count -gt 0) {
    Write-Output "VERDICT: NOT DRIVABLE - $($missing.Count) of the $(@($STEPS | Where-Object { $_.cmd }).Count) driven steps have no console command ($($missing -join ', ')), exit $EXIT_NOT_DRIVABLE"
    Write-Output '         The device WAS reached and answered; this is a firmware gap, not a bench'
    Write-Output '         problem, and it is the honest state of MILESTONES section 9 clause 2.'
    exit $EXIT_NOT_DRIVABLE
}
Write-Output "VERDICT: EVERY STEP DRIVABLE, exit $EXIT_OK"
Write-Output '         That is not the same as the loop having been run. Supply -Descriptor and'
Write-Output '         -PsbtHex from a coordinator and read the transcript against clause 2.'
exit $EXIT_OK
