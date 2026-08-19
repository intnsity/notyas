# m4a power-cut gate: drive the HIL console, detect the cut, read the ledger back.
#
# Q43's USB-controlled relay is deferred to 0.3.0, so the cuts are made by hand at the
# connector. That is weaker than a relay in exactly one way and the milestone note must
# say so: the timing is not repeatable to the millisecond, so the window is SAMPLED
# rather than swept. Everything except the physical pull is automated here, because the
# gate is only evidence if the operator knows which step was in flight when the power
# went and can read the state back afterwards.
#
# The cut needs no operator confirmation. Pulling the connector de-enumerates the CH340K,
# so the port vanishing IS the cut and the port returning IS the reseat. Both are
# timestamped against the last `about_to_` line the board emitted, which is what ties a
# cut to a specific in-flight operation.
#
# This script records. It does not decide the gate passed: it flags anomalies and writes
# a per-cut record, and a human reads the summary against the milestone's exit criteria.
# A harness that prints PASS is a harness that gets trusted when it should not be.
#
# WHAT A MODE IS, AND WHY EACH ONE RECORDS DIFFERENT FIELDS
#
# The four operations this gate covers fail in four different ways, so the columns that
# would prove them right are not the same columns. A harness that recorded `next_seq` for
# all of them would produce a green run that proves nothing about three of them, which is
# the failure this file is shaped to avoid. Each mode therefore declares its own evidence:
#
#   seal    - the ledger must not lose a committed record. Evidence: next_seq never goes
#             backwards, the epoch never moves, the store remounts.
#   pin     - change-PIN moves a whole identity's records. Evidence: after the cut EXACTLY
#             ONE of the two PINs opens the device, and the payload digest under it is the
#             one from before the cut. Both PINs are tried after every cut; a device that
#             answered to both, or to neither, is the finding.
#   attempt - the wrong-PIN counter must not lose a count. Evidence: the failure count
#             before and after, plus whether the attempt had COMPLETED when the power
#             went. A completed attempt whose count vanished is an uncounted guess, which
#             is the attack the counter exists to stop.
#   policy  - SET-POLICY has seven steps (vault.rs Y1-Y7) and the effective policy after a
#             cut must never be weaker than both the old and the new value. Evidence: the
#             step that was in flight, and the wipe threshold and policy generation on
#             both sides of the cut.
#
# THE ATTEMPT WINDOW IS NOT WHAT IT LOOKS LIKE, and the mode says so in its own output.
# `Vault::unlock` spends about 1.9 s in Argon2id (U2/U3) BEFORE it programs the attempt
# cell (U4), deliberately: an attacker who cuts power during the stretch has paid the cost
# and learned nothing. So the counted region is microseconds wide at the end of a two
# second operation, and a hand-timed pull essentially never lands inside it. What this
# mode can honestly evidence on hardware is that the count survives a cut ANYWHERE in the
# unlock and never goes backwards; the exhaustive sweep of the U4 boundary is the host
# fuzzer, `cargo test -p notyas-wallet --release -- --ignored` (tests/powerloss.rs). The
# summary states which of the two a run measured rather than letting a reader assume.
[CmdletBinding()]
param(
    [string] $Port        = 'COM6',
    [int]    $Baud        = 115200,
    # seal    - cut during record seal (soak)
    # pin     - cut during change-PIN (pinsoak), the operation with the most steps
    # attempt - cut mid-decrement of the attempt counter (wrong-PIN unlock)
    # policy  - cut during SET-POLICY, at one of its seven steps
    [ValidateSet('seal','pin','attempt','policy')]
    [string] $Mode        = 'seal',
    # 0 means "the mode's own default", which is 20 everywhere except policy: that gate
    # wants a cut at each of SEVEN steps, so its default is three passes over the set.
    [int]    $Cuts        = 0,
    # The sample window. Each cut picks a delay uniformly inside it, so repeated runs
    # scatter across the window instead of hitting the same instant every time. Left
    # unset, each mode supplies a window sized to the operation it interrupts.
    [int]    $DelayMinMs  = -1,
    [int]    $DelayMaxMs  = -1,
    [string] $Pin         = '1234',
    [string] $PinB        = '5678',
    # The wrong PIN for `attempt`. It must be a PIN the store will REFUSE, and it must
    # still parse: a value the console rejects as malformed never reaches the counter, and
    # the cut would then interrupt nothing.
    [string] $BadPin      = '9999',
    # The two thresholds `policy` alternates between. Both must be inside WIPE_AFTER_MIN
    # to WIPE_AFTER_MAX (3..25), or `off`; the firmware refuses anything else, which would
    # leave the cut interrupting an error path instead of a commit.
    [string] $WipeAfterA  = '15',
    [string] $WipeAfterB  = '5',
    # Ratified Q4: the floor is 4 CHARACTERS, and this harness never raises it.
    [int]    $MinPinLen   = 4,
    [int]    $Slot        = 1,
    # The workload must outlast any human pause. Measured on this board: roughly 10
    # seals per second, so the old fixed 2000 ran dry after about 200 seconds and a
    # slow pull then cut into an idle console, interrupting nothing. 100000 cannot be
    # reached before the operator pulls, and the soak is abandoned by the cut anyway.
    [int]    $SoakCount   = 100000,
    # How close to the wipe threshold the run is allowed to get before it stops. The
    # modes that type a wrong PIN spend real attempts on a REAL provisioned board, and a
    # harness that walked board B into wipe-on-N would destroy the one device the storage
    # evidence comes from. Two attempts per cut, plus one for the operator to make a
    # mistake with.
    [int]    $WipeMargin  = 3,
    [string] $OutDir      = 'C:\nb\hil',
    [switch] $DryRun
)

$ErrorActionPreference = 'Stop'

# Artifacts never land on the share. The tree is canonical there; evidence is local.
if ($OutDir -match '^(\\\\|//)') { throw "OutDir must be a local path, not a UNC path: $OutDir" }

$stamp      = Get-Date -Format 'yyyyMMdd-HHmmss'
$runDir     = Join-Path $OutDir "powercut-$Mode-$stamp"
# A dry run creates nothing. summarize-cuts.ps1 defaults to the NEWEST powercut-* directory
# under the evidence root, so an empty directory left behind by a dry run becomes the
# default target of the next summary and answers a real question with "no cuts.csv".
if (-not $DryRun) {
    if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
    New-Item -ItemType Directory -Path $runDir -Force | Out-Null
}
$transcript = Join-Path $runDir 'console.log'
$recordCsv  = Join-Path $runDir 'cuts.csv'
$recordJson = Join-Path $runDir 'cuts.json'

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

function Wait-PortGone {
    param([string] $Name, [int] $TimeoutMs)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.ElapsedMilliseconds -lt $TimeoutMs) {
        if (-not (Test-PortPresent $Name)) { return $true }
        Start-Sleep -Milliseconds 50
    }
    return $false
}

function Wait-PortBack {
    param([string] $Name, [int] $TimeoutMs)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.ElapsedMilliseconds -lt $TimeoutMs) {
        if (Test-PortPresent $Name) {
            # The driver enumerates slightly before the port will accept an open, and
            # a freshly re-powered board may enumerate twice. Open-Board retries on top
            # of this, but settling here avoids burning those retries every cut.
            Start-Sleep -Milliseconds 1500
            return $true
        }
        Start-Sleep -Milliseconds 50
    }
    return $false
}

function Open-Board {
    param([string] $Name, [int] $Rate, [int] $Attempts = 12)
    # Retrying, because a board that was just re-powered can enumerate more than once
    # while USB settles. The first enumeration is often torn down again microseconds
    # later, and a handle opened against it dies with "the port is closed" on the next
    # write - which aborted a 20-cut run at cut 3 on 2026-08-18 with the operator
    # standing at the bench. Opening is cheap; being wrong about it is not.
    for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
        try {
            $sp = New-Object System.IO.Ports.SerialPort $Name, $Rate, 'None', 8, 'One'
            $sp.ReadTimeout  = 250
            $sp.WriteTimeout = 2000
            $sp.NewLine      = "`n"
            $sp.DtrEnable    = $false
            $sp.RtsEnable    = $false
            $sp.Open()
            # Prove the handle is live before handing it back: a port that enumerated
            # and vanished again still opens, and only fails on first use.
            $sp.DiscardInBuffer()
            $null = $sp.BytesToRead
            return $sp
        } catch {
            if ($sp) { try { $sp.Dispose() } catch { } }
            if ($attempt -eq $Attempts) { throw }
            Start-Sleep -Milliseconds 500
        }
    }
}

function Open-BoardLegacy {
    param([string] $Name, [int] $Rate)
    $sp = New-Object System.IO.Ports.SerialPort $Name, $Rate, 'None', 8, 'One'
    $sp.ReadTimeout  = 250
    $sp.WriteTimeout = 2000
    $sp.NewLine      = "`n"
    # DTR/RTS drive EN and GPIO0 on these bridges. Both must stay deasserted, or opening
    # the port resets the board - which would look exactly like the cut we are timing.
    $sp.DtrEnable    = $false
    $sp.RtsEnable    = $false
    $sp.Open()
    $sp.DiscardInBuffer()
    return $sp
}

# Reads lines until the deadline, or until $StopOn matches. Returns why it stopped.
# Never throws on a vanished port: that IS the cut, and the caller decides what it means.
function Read-Until {
    param(
        [System.IO.Ports.SerialPort] $Sp,
        [int] $TimeoutMs,
        [string] $StopOn,
        [ref] $Lines
    )
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.ElapsedMilliseconds -lt $TimeoutMs) {
        $l = $null
        try {
            $l = $Sp.ReadLine()
        } catch [System.TimeoutException] {
            continue
        } catch {
            return 'port_lost'
        }
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

# Pulls key=value pairs out of a HIL line into a hashtable.
function ConvertFrom-HilLine {
    param([string] $Line)
    $h = @{}
    foreach ($f in ($Line -split '\|')) {
        $f = $f.Trim()
        if ($f -match '^([A-Za-z_][A-Za-z0-9_]*)=(.*)$') { $h[$matches[1]] = $matches[2] }
    }
    return $h
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

function Get-Field {
    param($Table, [string] $Key)
    if ($Table -and $Table.ContainsKey($Key)) { return $Table[$Key] }
    return ''
}

# `attempts_left` is a Rust `Option<u32>` printed with `{:?}`, so it reads `Some(14)` or
# `None`. `None` is not missing data - it is the wipe being DISABLED, which is a different
# fact from a field the parser failed to find, and the two must not collapse into ''.
function Get-Attempts {
    param($Table)
    $raw = Get-Field $Table 'attempts_left'
    if ($raw -match 'Some\((\d+)\)') { return $matches[1] }
    if ($raw -match 'None') { return 'none' }
    return ''
}

# The commands this device actually exposes, read from `help` rather than assumed.
# A mode that needs a command the firmware does not have must say so and stop; running it
# anyway produces a transcript of the console rejecting every line, which reads like a
# device finding and is not one.
function Get-HelpCommands {
    param([System.IO.Ports.SerialPort] $Sp)
    $lines = @()
    Send-Cmd $Sp 'help'
    $null = Read-Until -Sp $Sp -TimeoutMs 6000 -StopOn $null -Lines ([ref]$lines)
    $cmds = @()
    foreach ($l in $lines) {
        if ($l -match 'HIL\|help\|\s*([a-z][a-z0-9_]*)') { $cmds += $matches[1] }
    }
    return @($cmds | Sort-Object -Unique)
}

# One unlock attempt, reported as a fact rather than a verdict: the console answers
# `ok=true|ms=N` or `ok=false|err=...`, and both arms carry `failures_after`.
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
        err      = (Get-Field $h 'err')
    }
}

function Invoke-Lock {
    param([System.IO.Ports.SerialPort] $Sp)
    $lines = @()
    Send-Cmd $Sp 'lock'
    $null = Read-Until -Sp $Sp -TimeoutMs 4000 -StopOn 'HIL\|lock\|' -Lines ([ref]$lines)
}

# The payload digest is what makes "no record was lost" a measurement instead of an
# assertion. `read` prints the length and the SHA-256 of the body on both arms, and a
# change-PIN that lost a record or re-sealed it wrongly moves one of them.
function Get-Payload {
    param([System.IO.Ports.SerialPort] $Sp, [int] $Slot)
    $lines = @()
    Send-Cmd $Sp "read $Slot"
    $null = Read-Until -Sp $Sp -TimeoutMs 8000 -StopOn 'HIL\|read\|' -Lines ([ref]$lines)
    $line = $lines | Where-Object { $_ -match 'HIL\|read\|' } | Select-Object -Last 1
    $h = $null
    if ($line) { $h = ConvertFrom-HilLine $line }
    return @{
        ok     = ((Get-Field $h 'ok') -eq 'true')
        len    = (Get-Field $h 'len')
        sha256 = (Get-Field $h 'sha256')
        err    = (Get-Field $h 'err')
    }
}

# Reads the console continuously until the port disappears, so the recorded in-flight
# line is the LAST one the board emitted before the cut - not the last one before the
# prompt. A manual cut lands seconds after the beep, and the board keeps working in
# between; recording the prompt-time index would attribute the cut to the wrong step,
# which is the one fact this gate exists to establish.
#
# $Completed is set when the console printed the line that ENDS the operation being cut.
# For `attempt` that single bit decides what the cut proves: an unlock that had already
# answered was not interrupted, and its count must still be there afterwards.
function Watch-UntilCut {
    param(
        [System.IO.Ports.SerialPort] $Sp,
        [string] $Name,
        [int] $TimeoutMs,
        [string] $InflightPattern,
        [string] $CompletePattern,
        [ref] $LastInflight,
        [ref] $LastLine,
        [ref] $Completed
    )
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $lastCheck = 0
    while ($sw.ElapsedMilliseconds -lt $TimeoutMs) {
        try {
            $l = $Sp.ReadLine()
            if ($l) {
                $l = $l.TrimEnd("`r")
                Add-Content -Path $transcript -Value ('    < ' + $l) -Encoding utf8
                $LastLine.Value = $l
                if ($InflightPattern -and $l -match $InflightPattern) { $LastInflight.Value = $l }
                if ($CompletePattern -and $l -match $CompletePattern) { $Completed.Value = $true }
            }
        } catch [System.TimeoutException] {
        } catch {
            return $true
        }
        # Port presence is the authoritative cut signal; the read above may simply be idle.
        if (($sw.ElapsedMilliseconds - $lastCheck) -ge 200) {
            $lastCheck = $sw.ElapsedMilliseconds
            if (-not (Test-PortPresent $Name)) { return $true }
        }
    }
    return $false
}

# -------------------------------------------------------------------------------------
# The modes
# -------------------------------------------------------------------------------------
#
# One table entry per mode, holding everything that differs between them: the console
# commands it requires, the window it samples, the pattern that marks an operation in
# flight, and the extra evidence columns. Everything else - open, boot, baseline, cut,
# reseat, readback, record - is one code path shared by all four, because that path is
# the part that has been proven on hardware and it must not fork per mode.
$MODES = @{
    'seal' = @{
        Needs     = @('soak','unlock','status','scan')
        Cuts      = 20
        DelayMin  = 40
        DelayMax  = 900
        BeepFirst = $false
        Inflight  = 'about_to_seal'
        Complete  = $null
        Columns   = @()
        Summary   = 'cut during a record seal; the ledger must lose nothing'
        Contract  = @()
    }
    'pin' = @{
        Needs     = @('pinsoak','changepin','unlock','lock','read','status','scan')
        Cuts      = 20
        # Each change-PIN re-stretches the new PIN (about 1.9 s) and re-seals every
        # record, so one iteration is seconds long. A window of a few hundred ms would put
        # every cut inside change i=0; six seconds spreads them across changes, and across
        # the steps inside one.
        DelayMin  = 40
        DelayMax  = 6000
        BeepFirst = $false
        Inflight  = 'about_to_change'
        Complete  = $null
        Columns   = @('pin_before','pin_a_opens','pin_b_opens','pin_after',
                      'payload_ok_before','payload_len_before','payload_sha_before',
                      'payload_ok_after','payload_len_after','payload_sha_after')
        Summary   = 'cut during change-PIN; exactly one PIN must open the device afterwards'
        Contract  = @()
    }
    'attempt' = @{
        Needs     = @('unlock','lock','status','scan')
        Cuts      = 20
        # Beep FIRST for this mode. The operation is a single two-second unlock, not a
        # stream, so a beep sent partway through it leaves no time to pull before it ends.
        # The delay here is the pause between the beep and the command, which puts the
        # operator's reaction time inside the unlock rather than after it.
        DelayMin  = 0
        DelayMax  = 700
        BeepFirst = $true
        Inflight  = 'HIL\|unlock\|'
        Complete  = 'HIL\|unlock\|'
        Columns   = @('bad_pin','stretch_ms','unlock_completed_before_cut','cut_phase',
                      'attempts_left_before','attempts_left_after','failures_after_clear')
        Summary   = 'cut during a wrong-PIN unlock; the count must survive and never go backwards'
        Contract  = @()
    }
    'policy' = @{
        Needs     = @('policysoak','setpolicy','unlock','lock','status','scan')
        # Seven steps, three passes. The gate wants a cut at EACH of Y1-Y7, the step is
        # observed rather than chosen, so the run is sized to give the sample a chance and
        # the summary reports which steps were actually hit. Coverage, not a count, closes
        # this one.
        Cuts      = 21
        DelayMin  = 40
        DelayMax  = 4000
        BeepFirst = $false
        Inflight  = 'about_to_step'
        Complete  = $null
        Columns   = @('step_at_cut','wipe_after_target','wipe_after_before','wipe_after_after',
                      'policy_gen_before','policy_gen_after','min_pin_len_requested','min_pin_len_after')
        Summary   = 'cut inside SET-POLICY; the effective policy must never be weaker than both values'
        # The two console commands this mode drives AND THIS FIRMWARE DOES NOT HAVE. They
        # are stated here, in the harness that needs them, so the contract is one artifact
        # rather than a paragraph in a document nobody has open while writing the firmware.
        Contract  = @(
            'setpolicy <wipe_after|off> <min_pin_len> <pin>',
            '    -> HIL|setpolicy|ok=true|wipe_after=N|min_pin_len=N|policy_gen=N',
            '       Vault::set_policy takes the PIN, because the policy is authenticated',
            '       inside the AEAD and the commit is a re-seal. The console must pass one',
            '       through; firmware/src/store/mod.rs publishes no route to it today.',
            '',
            'policysoak <wipe_a> <wipe_b> <min_pin_len> <pin> <n>',
            '    -> HIL|policysoak|about_to_step|i=N|step=Y1..Y7|wipe_after=N',
            '       one line BEFORE each of the seven steps, exactly as `soak` announces',
            '       each seal. Without the announcement a cut cannot be attributed to a',
            '       step, and "a cut at each of its seven steps" stays unevidenced.',
            '',
            'status: add min_pin_len to the existing line.',
            '       The status line carries wipe_after and policy_gen but not the floor, so',
            '       the half of SET-POLICY that moves the floor cannot be read back at all',
            '       today. The column min_pin_len_after stays empty until it can be.'
        )
    }
}

$spec = $MODES[$Mode]
if ($Cuts -le 0)       { $Cuts       = $spec.Cuts }
if ($DelayMinMs -lt 0) { $DelayMinMs = $spec.DelayMin }
if ($DelayMaxMs -lt 0) { $DelayMaxMs = $spec.DelayMax }
if ($DelayMaxMs -lt $DelayMinMs) { throw "DelayMaxMs ($DelayMaxMs) is below DelayMinMs ($DelayMinMs)" }

# Every row of a run carries the same columns, including the rows written when the harness
# itself failed. Export-Csv takes its header from the FIRST object it is given, so a
# harness-error row of a different shape silently truncates the columns of every row after
# it - the evidence would go missing exactly where something had already gone wrong.
function New-CutRecord {
    param([int] $Cut)
    $r = [ordered]@{
        cut              = $Cut
        mode             = $Mode
        delay_ms         = 0
        cut_detected     = $false
        cut_at_ms        = 0
        last_inflight    = ''
        mount_before     = ''
        mount_after      = ''
        epoch_before     = ''
        epoch_after      = ''
        next_seq_before  = ''
        next_seq_after   = ''
        failures_before  = ''
        failures_after   = ''
        boot_count_after = ''
    }
    foreach ($c in $spec.Columns) { $r[$c] = '' }
    $r['flags'] = ''
    return $r
}

# "The effective policy is never weaker than both the old and the new value" (MILESTONES
# m4a), as arithmetic. WEAKER means a HIGHER threshold - more guesses before the wipe - and
# `off` is weakest of all, because no number of guesses ever triggers it. So the effective
# value after a cut is acceptable when it is one of the two the change was moving between,
# and unacceptable when it is a third value or is weaker than the weaker of the two.
#
# A function, because this is the one piece of judgement in the file that is not a
# comparison of two numbers for equality, and a rule stated in prose beside a `-gt` is a
# rule nobody can test. `$Targets` are the requested values, `off` normalised to 0.
function Get-PolicyStrengthFlags {
    param([string] $Effective, [string[]] $Targets)
    $flags = @()
    if ($Effective -notmatch '^\d+$') { return $flags }
    $norm = @()
    foreach ($t in $Targets) {
        if ($t -match '^(off|0)$') { $norm += '0' } else { $norm += $t }
    }
    if ($norm -notcontains $Effective) { $flags += "policy_value_unexpected:$Effective" }
    # If either side asked for the wipe off, then off is not weaker than both - it IS one
    # of them, and a cut landing on it is the change committing rather than tearing.
    $anyOff = $false
    $weakest = 0
    foreach ($t in $norm) {
        if ([int]$t -eq 0) { $anyOff = $true }
        elseif ([int]$t -gt $weakest) { $weakest = [int]$t }
    }
    if (-not $anyOff) {
        if ([int]$Effective -eq 0) { $flags += 'policy_weaker_than_both:wipe_disabled' }
        elseif ([int]$Effective -gt $weakest) { $flags += "policy_weaker_than_both:$Effective" }
    }
    return $flags
}

# The wipe threshold is real on board B, and this harness types wrong PINs at it. Stopping
# short is not caution for its own sake: wipe-on-N destroys every record, board B is the
# only eFuse-provisioned unit, and a run that wiped it would cost the storage evidence for
# the whole milestone with no way to get it back.
function Test-WipeMargin {
    param($Status, [int] $Margin)
    $w = Get-Field $Status 'wipe_after'
    $f = Get-Field $Status 'failures'
    if ($w -eq '' -or $f -eq '') { return $null }   # unknown: neither safe nor unsafe
    if ([int]$w -eq 0) { return $true }             # wipe disabled: no threshold to hit
    return (([int]$f + $Margin) -lt [int]$w)
}

if ($DryRun) {
    Write-Output 'DRY RUN - nothing is sent to the board.'
    Write-Output "  port         : $Port at $Baud"
    Write-Output "  mode         : $Mode - $($spec.Summary)"
    Write-Output "  cuts         : $Cuts"
    Write-Output "  delay window : $DelayMinMs..$DelayMaxMs ms"
    Write-Output "  needs        : $($spec.Needs -join ' ')"
    Write-Output "  evidence     : $runDir"
    Write-Output ''
    Write-Output 'Per cut, in order:'
    # Built as a list and numbered at print time. A hand-numbered sequence with the
    # mode-specific entries switched in and out grows a hole where the omitted step was,
    # and an operator following a list that skips 8 reasonably wonders what they missed.
    $steps = @(
        'wait for the port, open it, wait for the boot banner, record the mount verdict'
        'status -> baseline (epoch, next_seq, failures, boot_count, policy)'
        'stop the run if the failure count is within the wipe margin'
    )
    switch ($Mode) {
        'seal' {
            $steps += "unlock, then soak $Slot $SoakCount"
            $steps += 'after the scripted delay, beep and print PULL POWER NOW'
        }
        'pin' {
            $steps += "unlock with the PIN known to be current, read slot $Slot for its digest"
            $steps += "pinsoak $Pin $PinB $SoakCount, then after the delay beep and print PULL POWER NOW"
        }
        'attempt' {
            $steps += 'unlock with the CORRECT PIN to measure the stretch and clear the counter, then lock'
            $steps += "beep FIRST, pause the scripted delay, then send unlock $BadPin (the counted region is at the END of a two second unlock, so the beep leads)"
        }
        'policy' {
            $steps += "unlock, then policysoak $WipeAfterA $WipeAfterB $MinPinLen <pin> $SoakCount"
            $steps += 'after the scripted delay, beep and print PULL POWER NOW'
        }
    }
    $steps += 'the port vanishing is the cut, timestamped against the last in-flight line'
    $steps += 'the port returning is the reseat; reopen, wait for boot, status + scan'
    if ($Mode -eq 'pin') {
        $steps += "try PIN $Pin, then PIN $PinB, recording which opens; re-read slot $Slot under whichever opened and compare the digest"
    }
    if ($Mode -eq 'attempt') {
        $steps += 'status for the count, then a correct unlock to clear it, then status again'
    }
    $steps += 'append the record and flag anomalies'
    for ($i = 0; $i -lt $steps.Count; $i++) {
        Write-Output ('  {0,2}. {1}' -f ($i + 1), $steps[$i])
    }
    Write-Output ''
    Write-Output 'Evidence columns for this mode, beyond the common set:'
    if ($spec.Columns.Count -eq 0) {
        Write-Output '  (none - the common columns are the whole evidence for seal)'
    } else {
        foreach ($c in $spec.Columns) { Write-Output "  $c" }
    }
    Write-Output ''
    Write-Output 'You pull and reseat the connector. Everything else is automatic.'
    if ($spec.Contract.Count -gt 0) {
        Write-Output ''
        Write-Output 'BUT THIS MODE IS NOT DRIVABLE ON THE CURRENT FIRMWARE.'
        Write-Output ''
        Write-Output 'It needs console commands that firmware/src/hil.rs does not have. The store'
        Write-Output 'publishes no route to Vault::set_policy at all - firmware/src/main.rs refuses'
        Write-Output 'UiRequest::SetWipePolicy for exactly that reason - so the policy cannot be'
        Write-Output 'committed from the device by any path today. What is required, and what the'
        Write-Output 'harness checks by reading help before the first cut:'
        Write-Output ''
        foreach ($l in $spec.Contract) {
            if ($l -eq '') { Write-Output '' } else { Write-Output "  $l" }
        }
    }
    return
}

Write-Log "run $stamp mode=$Mode cuts=$Cuts port=$Port window=$DelayMinMs..$DelayMaxMs ms"
Write-Log "evidence: $runDir"

$records = @()
$rand    = New-Object System.Random
# `pin` mode moves the device between two PINs, so which one is current is state the
# harness has to carry. Getting it wrong is not a cosmetic error: the next cut's unlock
# would fail, the workload would never start, the cut would interrupt nothing, and the
# wasted attempts would walk a provisioned board toward its wipe threshold.
$currentPin = $Pin
$stopRun    = $false

# --- Capability probe, before anything is cut. ---
# Refusing here costs the operator one power-on. Discovering it at cut 1 costs them a pull,
# a reseat, and a transcript that has to be thrown away.
if (-not (Test-PortPresent $Port)) {
    Write-Log "waiting for $Port - connect the board"
    if (-not (Wait-PortBack $Port 300000)) { throw "port $Port never appeared" }
}
$have   = @()
$absent = @()
$probe  = Open-Board $Port $Baud
try {
    $boot0 = @()
    $null = Read-Until -Sp $probe -TimeoutMs 12000 -StopOn 'HIL\|(status|boot)' -Lines ([ref]$boot0)
    $have = Get-HelpCommands $probe
    Write-Log "device exposes $($have.Count) console commands"
    $absent = @($spec.Needs | Where-Object { $have -notcontains $_ })
} finally {
    try { if ($probe.IsOpen) { $probe.Close() } } catch { }
    try { $probe.Dispose() } catch { }
}

if ($have.Count -eq 0) {
    Write-Log 'WARN: help returned nothing parseable, so the capability probe is inconclusive.'
    Write-Log 'Continuing: an unreadable help table is a console defect, not a missing command.'
} elseif ($absent.Count -gt 0) {
    $blocked = Join-Path $runDir 'BLOCKED.txt'
    $msg = @()
    $msg += "mode '$Mode' cannot run on this firmware"
    $msg += ''
    $msg += "Missing console commands: $($absent -join ', ')"
    $msg += ''
    $msg += 'The device answered help with: ' + ($have -join ' ')
    $msg += ''
    if ($spec.Contract.Count -gt 0) {
        $msg += 'The contract this mode drives, which the firmware must provide:'
        $msg += ''
        foreach ($l in $spec.Contract) {
            if ($l -eq '') { $msg += '' } else { $msg += "  $l" }
        }
        $msg += ''
    }
    $msg += 'Nothing was cut and nothing was written to the device. No evidence was produced,'
    $msg += 'and none should be claimed: this is a firmware gap, not a test result.'
    $msg | Set-Content -Path $blocked -Encoding utf8
    $msg | ForEach-Object { Write-Log $_ }
    Write-Output ''
    Write-Output "Recorded as a gap, not a run: $blocked"
    return
}

for ($cut = 1; $cut -le $Cuts; $cut++) {
    if ($stopRun) { break }
    Write-Log "=== cut $cut of $Cuts ==="

    # One bad cut must not cost the other nineteen. A serial port that dies mid-cycle,
    # a board that boots slowly, a reseat that bounces - each is a transient the operator
    # can simply repeat, and aborting the run makes them repeat all of it. A failed cut
    # is recorded as a flagged row and the run moves on, which is also the honest
    # accounting: the row exists, it says what went wrong, and it is not counted as a
    # pass. Learned the hard way on 2026-08-18, at cut 3 of 20.
    try {

    if (-not (Test-PortPresent $Port)) {
        Write-Log "waiting for $Port - reseat the connector"
        if (-not (Wait-PortBack $Port 300000)) { throw "port $Port never came back" }
    }

    $rec       = New-CutRecord $cut
    $gone      = $false
    $cutAt     = 0
    $delay     = 0
    $lastIdx   = ''
    $completed = $false
    $before    = $null
    $skip      = $false

    $sp = Open-Board $Port $Baud
    try {
        $boot = @()
        $null = Read-Until -Sp $sp -TimeoutMs 12000 -StopOn 'HIL\|(status|boot)' -Lines ([ref]$boot)
        $rec.mount_before = "$($boot | Where-Object { $_ -match 'mount|provenance|state=' } | Select-Object -Last 1)"

        $before = Get-Status $sp
        if ($null -eq $before) { Write-Log 'WARN: no status line before the cut' }
        $rec.epoch_before    = Get-Field $before 'epoch'
        $rec.next_seq_before = Get-Field $before 'next_seq'
        $rec.failures_before = Get-Field $before 'failures'

        $margin = Test-WipeMargin $before $WipeMargin
        if ($margin -eq $false) {
            Write-Log "STOP: failures=$(Get-Field $before 'failures') is within $WipeMargin of wipe_after=$(Get-Field $before 'wipe_after')."
            Write-Log 'Refusing to continue. Unlock the board with the correct PIN to clear the counter,'
            Write-Log 'then start a new run. This harness does not walk a provisioned board into a wipe.'
            $rec.flags = 'stopped_near_wipe_threshold'
            $stopRun = $true
            $skip = $true
        } elseif ($null -eq $margin) {
            Write-Log 'WARN: wipe_after/failures unreadable, so the wipe margin is unchecked this cut'
        }

        if (-not $skip) {
            $delay = $rand.Next($DelayMinMs, $DelayMaxMs + 1)
            $rec.delay_ms = $delay

            switch ($Mode) {
                'seal' {
                    $null = Invoke-Unlock -Sp $sp -Pin $Pin
                    Send-Cmd $sp "soak $Slot $SoakCount"
                }
                'pin' {
                    # Which PIN is current is carried between cuts, but a run resumed after
                    # an abort starts without that knowledge. Trying the other one costs a
                    # single attempt, and is the difference between a real workload and a
                    # cut that interrupts an idle console.
                    $u = Invoke-Unlock -Sp $sp -Pin $currentPin
                    if (-not $u.ok) {
                        $other = $Pin
                        if ($currentPin -eq $Pin) { $other = $PinB }
                        Write-Log "PIN $currentPin did not open the device; trying $other"
                        $u = Invoke-Unlock -Sp $sp -Pin $other
                        if ($u.ok) { $currentPin = $other }
                    }
                    $rec.pin_before = $currentPin
                    if (-not $u.ok) { throw "neither PIN opened the device before cut $cut" }
                    $p = Get-Payload -Sp $sp -Slot $Slot
                    $rec.payload_ok_before  = $p.ok
                    $rec.payload_len_before = $p.len
                    $rec.payload_sha_before = $p.sha256
                    if (-not $p.ok) {
                        Write-Log "WARN: slot $Slot did not read before the cut ($($p.err)); the record-survival check has no baseline this cut"
                    }
                    Send-Cmd $sp "pinsoak $Pin $PinB $SoakCount"
                }
                'attempt' {
                    # The correct unlock first: it clears the counter to a known 0 AND
                    # measures this board's real stretch cost, which is what the cut is
                    # timed against afterwards. A constant from MEASUREMENTS.md would be a
                    # different board on a different day.
                    $good = Invoke-Unlock -Sp $sp -Pin $Pin
                    if (-not $good.ok) { throw "the correct PIN did not open the device before cut $cut" }
                    $rec.stretch_ms = $good.ms
                    Invoke-Lock $sp
                    $b2 = Get-Status $sp
                    if ($b2) {
                        $before = $b2
                        $rec.epoch_before    = Get-Field $before 'epoch'
                        $rec.next_seq_before = Get-Field $before 'next_seq'
                        $rec.failures_before = Get-Field $before 'failures'
                    }
                    $rec.attempts_left_before = Get-Attempts $before
                    $rec.bad_pin = $BadPin
                    [Console]::Beep(1200, 250)
                    Write-Log ">>> PULL POWER NOW  (cut $cut of $Cuts; the wrong unlock starts in $delay ms and runs about $($rec.stretch_ms) ms) <<<"
                    Start-Sleep -Milliseconds $delay
                    Send-Cmd $sp "unlock $BadPin"
                }
                'policy' {
                    $null = Invoke-Unlock -Sp $sp -Pin $Pin
                    $rec.wipe_after_before     = Get-Field $before 'wipe_after'
                    $rec.policy_gen_before     = Get-Field $before 'policy_gen'
                    $rec.min_pin_len_requested = $MinPinLen
                    $rec.wipe_after_target     = "$WipeAfterA/$WipeAfterB"
                    Send-Cmd $sp "policysoak $WipeAfterA $WipeAfterB $MinPinLen $Pin $SoakCount"
                }
            }

            $workload = [System.Diagnostics.Stopwatch]::StartNew()

            if (-not $spec.BeepFirst) {
                # Read the in-flight announcements until the delay expires, so the last one
                # seen is the operation the cut lands on.
                $inflight = @()
                $null = Read-Until -Sp $sp -TimeoutMs $delay -StopOn $null -Lines ([ref]$inflight)
                $lastIdx = "$($inflight | Where-Object { $_ -match $spec.Inflight } | Select-Object -Last 1)"
                [Console]::Beep(1200, 250)
                Write-Log ">>> PULL POWER NOW  (cut $cut of $Cuts, $delay ms into the workload) <<<"
            }

            $lastLine = ''
            $gone = Watch-UntilCut -Sp $sp -Name $Port -TimeoutMs 600000 `
                        -InflightPattern $spec.Inflight -CompletePattern $spec.Complete `
                        -LastInflight ([ref]$lastIdx) -LastLine ([ref]$lastLine) `
                        -Completed ([ref]$completed)
            $cutAt = $workload.ElapsedMilliseconds
            if (-not $gone) {
                Write-Log 'WARN: port never vanished - the cut was not detected. Recording as MISSED.'
            } else {
                Write-Log "cut detected at +$cutAt ms (last in-flight: $lastIdx)"
            }
        }
    } finally {
        try { if ($sp.IsOpen) { $sp.Close() } } catch { }
        try { $sp.Dispose() } catch { }
    }

    if ($skip) {
        $records += [pscustomobject]$rec
        $records | Export-Csv -Path $recordCsv -NoTypeInformation -Encoding utf8
        $records | ConvertTo-Json -Depth 4 | Set-Content -Path $recordJson -Encoding utf8
        break
    }

    $rec.cut_detected  = $gone
    $rec.cut_at_ms     = $cutAt
    $rec.last_inflight = $lastIdx

    if ($Mode -eq 'attempt') {
        $rec.unlock_completed_before_cut = $completed
        # Which side of the counted region the cut fell on. `Vault::unlock` programs the
        # attempt cell only AFTER the Argon2id stretch, so a cut earlier than the measured
        # stretch cannot have decremented anything, and a cut later than it should have.
        # Stated as an observation with the two numbers behind it, because the
        # classification is an inference from timings and not something the device said.
        if ($completed) {
            $rec.cut_phase = 'after_the_attempt_completed'
        } elseif ($rec.stretch_ms -match '^\d+$' -and $cutAt -gt 0) {
            if ($cutAt -lt ([int]$rec.stretch_ms)) { $rec.cut_phase = 'uncounted_stretch' }
            else { $rec.cut_phase = 'at_or_after_the_counted_region' }
        } else {
            $rec.cut_phase = 'unknown'
        }
    }

    if ($Mode -eq 'policy' -and $lastIdx -match 'step=(Y\d)') { $rec.step_at_cut = $matches[1] }

    if ($gone) {
        Write-Log 'reseat the connector'
        if (-not (Wait-PortBack $Port 300000)) { throw "port $Port never came back after cut $cut" }
    }

    # Post-cut readback. This is the whole point of the exercise, so it retries rather
    # than surrendering the cut. A board that has just been re-powered can drop and
    # re-enumerate its USB bridge AFTER a handle was successfully opened against it -
    # the open succeeds, the first write throws "the port is closed". Proving the
    # handle live at open time is not enough; only reopening on failure is.
    $after = $null
    $readbackAttempts = 3
    for ($rb = 1; $rb -le $readbackAttempts; $rb++) {
      $sp2 = $null
      try {
        $sp2 = Open-Board $Port $Baud
        $boot2 = @()
        $null = Read-Until -Sp $sp2 -TimeoutMs 15000 -StopOn 'HIL\|(status|boot)' -Lines ([ref]$boot2)
        $rec.mount_after = "$($boot2 | Where-Object { $_ -match 'mount|provenance|state=' } | Select-Object -Last 1)"
        $after = Get-Status $sp2

        # --- The mode-specific readback: the fields that make this cut evidence. ---
        if ($Mode -eq 'pin') {
            # Both PINs, every time, in a fixed order. Asking only about the one expected
            # to work cannot see the failure that matters most - a cut leaving BOTH PINs
            # valid, which is two live sealing keys for one store. `lock` before each, so
            # each attempt is a genuine unlock from a locked device.
            Invoke-Lock $sp2
            $ua = Invoke-Unlock -Sp $sp2 -Pin $Pin
            Invoke-Lock $sp2
            $ub = Invoke-Unlock -Sp $sp2 -Pin $PinB
            Invoke-Lock $sp2
            $rec.pin_a_opens = $ua.ok
            $rec.pin_b_opens = $ub.ok
            $opener = ''
            if ($ua.ok) { $opener = $Pin }
            if ($ub.ok) { $opener = $PinB }
            if ($ua.ok -and $ub.ok) { $opener = 'BOTH' }
            if (-not $ua.ok -and -not $ub.ok) { $opener = 'NEITHER' }
            $rec.pin_after = $opener
            if ($ua.ok -or $ub.ok) {
                $use = $Pin
                if ($ub.ok) { $use = $PinB }
                $u2 = Invoke-Unlock -Sp $sp2 -Pin $use
                if ($u2.ok) {
                    $currentPin = $use
                    $p2 = Get-Payload -Sp $sp2 -Slot $Slot
                    $rec.payload_ok_after  = $p2.ok
                    $rec.payload_len_after = $p2.len
                    $rec.payload_sha_after = $p2.sha256
                }
            }
            $after = Get-Status $sp2
        }
        if ($Mode -eq 'attempt') {
            $rec.attempts_left_after = Get-Attempts $after
            # The count is read BEFORE it is cleared, then a correct unlock clears it, so
            # the next cut starts from a known 0 and the run cannot drift into the wipe.
            $clear = Invoke-Unlock -Sp $sp2 -Pin $Pin
            if ($clear.ok) { $rec.failures_after_clear = $clear.failures }
            else { Write-Log "WARN: the correct PIN did not open the device after cut $cut ($($clear.err))" }
        }

        $scan = @()
        Send-Cmd $sp2 'scan'
        $null = Read-Until -Sp $sp2 -TimeoutMs 20000 -StopOn 'HIL\|scan\|region=Ledger' -Lines ([ref]$scan)
        break
      } catch {
        Write-Log "readback attempt $rb of $readbackAttempts failed: $($_.Exception.Message)"
        if ($rb -eq $readbackAttempts) { throw }
        Start-Sleep -Milliseconds 2500
      } finally {
        if ($sp2) {
            try { if ($sp2.IsOpen) { $sp2.Close() } } catch { }
            try { $sp2.Dispose() } catch { }
        }
      }
    }

    $rec.epoch_after      = Get-Field $after 'epoch'
    $rec.next_seq_after   = Get-Field $after 'next_seq'
    $rec.failures_after   = Get-Field $after 'failures'
    $rec.boot_count_after = Get-Field $after 'boot_count'
    if ($Mode -eq 'policy') {
        $rec.wipe_after_after  = Get-Field $after 'wipe_after'
        $rec.policy_gen_after  = Get-Field $after 'policy_gen'
        $rec.min_pin_len_after = Get-Field $after 'min_pin_len'
    }

    # Anomaly flags. These are observations, not a verdict.
    $flags = @()
    if (-not $gone)       { $flags += 'cut_not_detected' }
    if ($null -eq $after) { $flags += 'no_status_after_cut' }
    if ($before -and $after) {
        $eb = Get-Field $before 'epoch'
        $ea = Get-Field $after  'epoch'
        if ($eb -ne '' -and $ea -ne '' -and $eb -ne $ea) { $flags += "epoch_changed:$eb->$ea" }
        $fb = Get-Field $before 'failures'
        $fa = Get-Field $after  'failures'
        if ($fb -ne '' -and $fa -ne '' -and ([int]$fa) -lt ([int]$fb)) { $flags += 'failures_went_backwards' }
        $sa = Get-Field $after 'state'
        if ($sa -ne '' -and $sa -notmatch 'Provisioned|Formatted') { $flags += "state_after=$sa" }
    }

    switch ($Mode) {
        'pin' {
            if ($rec.pin_after -eq 'BOTH') {
                $flags += 'both_pins_open'
            } elseif ($rec.pin_after -eq 'NEITHER') {
                $flags += 'no_pin_opens'
            }
            if ($rec.payload_sha_before -ne '' -and $rec.payload_sha_after -ne '' -and
                $rec.payload_sha_before -ne $rec.payload_sha_after) {
                $flags += 'payload_digest_changed'
            }
            if ($rec.payload_ok_before -eq $true -and $rec.payload_ok_after -ne $true) {
                $flags += 'record_unreadable_after_cut'
            }
            if ($rec.pin_after -eq 'NEITHER') {
                Write-Log 'STOP: neither PIN opened the device. That is a blocking finding AND it'
                Write-Log 'ends the run: every further cut would spend attempts against the wipe'
                Write-Log 'threshold with no way to clear them. Leave the board as it is and read'
                Write-Log 'the transcript before touching it again.'
                $stopRun = $true
            }
        }
        'attempt' {
            $fb = $rec.failures_before
            $fa = $rec.failures_after
            if ($fb -match '^\d+$' -and $fa -match '^\d+$') {
                if ([int]$fa -gt ([int]$fb + 1)) { $flags += 'failures_counted_more_than_once' }
                # The sharp one. If the console had already answered the unlock when the
                # power went, the attempt cell was programmed before that answer - so a
                # count that did not move is a verification the device performed and did
                # not charge for, which is precisely what the counter exists to prevent.
                if ($rec.unlock_completed_before_cut -eq $true -and [int]$fa -eq [int]$fb) {
                    $flags += 'completed_attempt_not_counted'
                }
            }
            if ($rec.failures_after_clear -match '^\d+$' -and [int]$rec.failures_after_clear -ne 0) {
                $flags += "success_did_not_clear:$($rec.failures_after_clear)"
            }
        }
        'policy' {
            $flags += Get-PolicyStrengthFlags -Effective $rec.wipe_after_after `
                          -Targets @($WipeAfterA, $WipeAfterB)
            $pb = $rec.policy_gen_before
            $pa = $rec.policy_gen_after
            if ($pb -match '^\d+$' -and $pa -match '^\d+$' -and [int]$pa -lt [int]$pb) {
                $flags += 'policy_gen_regressed'
            }
            if ($rec.step_at_cut -eq '') { $flags += 'no_step_in_flight' }
        }
    }

    $rec.flags = ($flags -join ';')
    $records += [pscustomobject]$rec

    # Written after every cut, so an interrupted run still leaves usable evidence.
    $records | Export-Csv -Path $recordCsv -NoTypeInformation -Encoding utf8
    $records | ConvertTo-Json -Depth 4 | Set-Content -Path $recordJson -Encoding utf8

    if ($flags.Count -gt 0) { Write-Log "FLAGS: $($flags -join '; ')" } else { Write-Log 'no anomalies flagged' }

    } catch {
        $err = $_.Exception.Message
        Write-Log "CUT $cut FAILED (harness error, not a device finding): $err"
        Write-Log 'recording it as a flagged row and continuing to the next cut'
        $bad = New-CutRecord $cut
        $bad.flags = "harness-error: $err"
        $records += [pscustomobject]$bad
        $records | Export-Csv -Path $recordCsv -NoTypeInformation -Encoding utf8
        $records | ConvertTo-Json -Depth 4 | Set-Content -Path $recordJson -Encoding utf8
        # Give USB time to settle before the next cycle tries to open the port again.
        Start-Sleep -Milliseconds 2000
    }
}

Write-Log "=== run complete: $($records.Count) rows recorded, evidence in $runDir ==="
Write-Output ''
Write-Output "Records : $recordCsv"
Write-Output "Console : $transcript"
Write-Output ''
Write-Output 'This harness does not declare the gate passed. Read cuts.csv against the m4a exit'
Write-Output 'criteria in docs/plan-0.2.0/MILESTONES.md, and record in the milestone note that the'
Write-Output 'window was SAMPLED by hand rather than swept, which is the one way this is weaker'
Write-Output 'than the relay rig deferred to 0.3.0.'
Write-Output ''
Write-Output 'Next: powershell -NoProfile -ExecutionPolicy Bypass -File tools\hil\summarize-cuts.ps1'
