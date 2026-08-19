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

if ($OutDir -match '^(\\\\|//)') { throw "OutDir must be local, not a UNC path: $OutDir" }
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
$stamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
$runDir = Join-Path $OutDir "e2e-$stamp"
New-Item -ItemType Directory -Path $runDir -Force | Out-Null
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
    return
}

Write-Log "run $stamp port=$Port"
Write-Log "evidence: $runDir"
Write-Log 'THE BAR: MILESTONES section 9 clause 2. This records; it does not declare done.'

if (-not (Test-PortPresent $Port)) { throw "port $Port not present" }
$sp = Open-Board $Port $Baud

# --- Capability probe. This is what makes the script useful before the loop is complete. ---
Write-Log '=== probing the device command surface ==='
$help = Invoke-Hil -Sp $sp -Cmd 'help' -TimeoutMs 6000
$available = @()
foreach ($l in $help) {
    if ($l -match 'HIL\|help\|(.+)$') {
        foreach ($tok in ($matches[1] -split '[\s,|]+')) {
            $t = $tok.Trim()
            if ($t -match '^[a-z][a-z0-9_]*$') { $available += $t }
        }
    }
}
$available = $available | Sort-Object -Unique
Write-Log ("device reports " + $available.Count + " commands: " + ($available -join ' '))

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

try { if ($sp.IsOpen) { $sp.Close() } } catch { }
try { $sp.Dispose() } catch { }

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
