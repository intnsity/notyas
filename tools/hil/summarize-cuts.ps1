# Turn a power-cut run's cuts.csv into the paragraph the milestone note needs.
#
# The harness deliberately refuses to declare the gate passed, because a tool that
# prints PASS is a tool that gets trusted when it should not be. This script does the
# next thing down: it states what was actually observed, per the m4a exit criteria, and
# leaves the verdict to a human. Everything it prints is derived from the CSV; nothing
# is asserted that the run did not measure.
#
# It also states the weakness in the same breath as the result, because the milestone
# requires that: Q43's USB-controlled relay moved to 0.3.0, so the timing window here is
# SAMPLED by hand rather than swept, and a reader who sees only the pass rate would
# reasonably assume otherwise.
#
# EACH MODE IS READ AGAINST ITS OWN CRITERIA. The common section below - remount, epoch,
# ledger monotonicity - is true of every mode and is where the `seal` gate lives. It is
# not the evidence for the other three. A `pin` run whose epoch never moved has said
# nothing about whether exactly one PIN still opens the device, and printing only the
# common section for it would read like a pass. So each mode adds a section that reports
# the columns its own gate is written in, and says NOT CHECKED wherever the data is
# absent rather than letting silence read as a pass.
[CmdletBinding()]
param(
    # Defaults to the newest run under the evidence root.
    [string] $RunDir,
    [string] $EvidenceRoot = 'C:\nb\hil'
)

$ErrorActionPreference = 'Stop'

if (-not $RunDir) {
    if (-not (Test-Path $EvidenceRoot)) { throw "no evidence root at $EvidenceRoot" }
    # The newest run that actually recorded something. A run aborted before its first cut
    # leaves an empty directory behind, and answering "summarise the last run" with a
    # complaint about that directory sends the operator hunting for a path when the run
    # they meant is sitting one entry further down.
    $newest = Get-ChildItem $EvidenceRoot -Directory -Filter 'powercut-*' |
              Sort-Object LastWriteTime -Descending |
              Where-Object {
                  (Test-Path (Join-Path $_.FullName 'cuts.csv')) -or
                  (Test-Path (Join-Path $_.FullName 'BLOCKED.txt'))
              } | Select-Object -First 1
    if (-not $newest) { throw "no powercut-* run under $EvidenceRoot has a cuts.csv or a BLOCKED.txt" }
    $RunDir = $newest.FullName
}

$blocked = Join-Path $RunDir 'BLOCKED.txt'
if (Test-Path $blocked) {
    # A blocked run is not an empty run, and it must not be summarised as one. The harness
    # writes this file when the firmware does not expose what the mode drives; the gate is
    # outstanding for a reason that has nothing to do with the bench.
    Write-Output ''
    Write-Output "This run was BLOCKED before anything was cut - $RunDir"
    Write-Output ('=' * 72)
    Write-Output ''
    Get-Content $blocked | ForEach-Object { Write-Output $_ }
    Write-Output ''
    return
}

$csv = Join-Path $RunDir 'cuts.csv'
if (-not (Test-Path $csv)) { throw "no cuts.csv in $RunDir" }
$rows = @(Import-Csv $csv)
if ($rows.Count -eq 0) { throw "cuts.csv is empty" }

$mode = $rows[0].mode
$total = $rows.Count
$detected = @($rows | Where-Object { $_.cut_detected -eq 'True' }).Count
$flagged = @($rows | Where-Object { $_.flags -ne '' }).Count

# The in-flight line is the evidence that a cut landed inside a live operation rather
# than between operations. A cut with no in-flight line interrupted nothing and proves
# nothing, so it is counted separately rather than folded into the pass rate.
$withInflight = @($rows | Where-Object { $_.last_inflight -match 'about_to_|HIL\|unlock\|' }).Count

$indices = @()
foreach ($r in $rows) {
    if ($r.last_inflight -match 'i=(\d+)') { $indices += [int]$matches[1] }
}

$epochChanges = @($rows | Where-Object { $_.epoch_before -ne '' -and $_.epoch_after -ne '' -and $_.epoch_before -ne $_.epoch_after })
$seqRegressions = @($rows | Where-Object {
    $_.next_seq_before -ne '' -and $_.next_seq_after -ne '' -and ([long]$_.next_seq_after) -lt ([long]$_.next_seq_before)
})
$noStatus = @($rows | Where-Object { $_.mount_after -eq '' })

# Padded rather than hand-spaced, so a label of a different length cannot shift the
# column and make one line of an otherwise aligned block look like a different report.
$inflightLabel = 'Landed inside a seal'
if ($mode -eq 'pin')     { $inflightLabel = 'Landed in a PIN change' }
if ($mode -eq 'attempt') { $inflightLabel = 'Landed in an unlock' }
if ($mode -eq 'policy')  { $inflightLabel = 'Landed in SET-POLICY' }
$inflightLabel = $inflightLabel.PadRight(21)

Write-Output ''
Write-Output "m4a power-cut gate, mode '$mode' - $RunDir"
Write-Output ('=' * 72)
Write-Output ''
Write-Output "Cuts requested        : $total"
Write-Output "Cuts detected         : $detected"
Write-Output "$inflightLabel : $withInflight   (a cut with no in-flight line interrupted nothing)"
if ($indices.Count -gt 0) {
    $mn = ($indices | Measure-Object -Minimum).Minimum
    $mx = ($indices | Measure-Object -Maximum).Maximum
    $distinct = ($indices | Sort-Object -Unique).Count
    Write-Output "In-flight index range : $mn to $mx across $distinct distinct values"
}
Write-Output "Rows carrying flags   : $flagged"
Write-Output ''
Write-Output 'Against the m4a exit criteria:'
Write-Output ''

if ($noStatus.Count -eq 0) {
    Write-Output "  Remount after cut   : all $detected cuts remounted and answered status."
} else {
    Write-Output "  Remount after cut   : $($noStatus.Count) cut(s) produced NO status after the cut - cuts $(($noStatus | ForEach-Object { $_.cut }) -join ', ')"
}

$epochComparable = @($rows | Where-Object { $_.epoch_before -ne '' -and $_.epoch_after -ne '' })
if ($epochComparable.Count -eq 0) {
    Write-Output '  Epoch stability     : NOT CHECKED - no row carried both epoch values.'
} elseif ($epochChanges.Count -eq 0) {
    Write-Output "  Epoch stability     : no epoch change across $($epochComparable.Count) comparable cut(s). No cut triggered a wipe."
} else {
    Write-Output "  Epoch stability     : EPOCH CHANGED on cut(s) $(($epochChanges | ForEach-Object { $_.cut }) -join ', ') - a cut caused a wipe or an epoch bump. Investigate before claiming the gate."
}

# A check with no data is not a passing check. The first run of this gate recorded
# empty next_seq columns because the console status line wraps and the field parser
# missed it, and a naive "no regressions found" then reads as evidence of a property
# nobody measured. Say which it was.
$seqComparable = @($rows | Where-Object { $_.next_seq_before -ne '' -and $_.next_seq_after -ne '' })
if ($seqComparable.Count -eq 0) {
    Write-Output '  Ledger monotonicity : NOT CHECKED - no row carried both next_seq values.'
    Write-Output '                        This is not a pass. The sequence property is unverified.'
} elseif ($seqRegressions.Count -eq 0) {
    Write-Output "  Ledger monotonicity : next_seq never went backwards across $($seqComparable.Count) comparable cut(s). No committed record was lost."
} else {
    Write-Output "  Ledger monotonicity : next_seq REGRESSED on cut(s) $(($seqRegressions | ForEach-Object { $_.cut }) -join ', ') - records were lost. This is a blocking finding."
}

$bootCounts = @($rows | Where-Object { $_.boot_count_after -match '\d' })
if ($bootCounts.Count -gt 0) {
    $first = $bootCounts[0].boot_count_after
    $last = $bootCounts[-1].boot_count_after
    Write-Output "  Boot counter        : $first -> $last across the run, surviving every cut."
}

# -------------------------------------------------------------------------------------
# The mode's own gate
# -------------------------------------------------------------------------------------

if ($mode -eq 'pin') {
    Write-Output ''
    Write-Output 'The change-PIN gate, which is what this mode exists to answer:'
    Write-Output ''
    $probed = @($rows | Where-Object { $_.pin_after -ne '' })
    if ($probed.Count -eq 0) {
        Write-Output '  Which PIN opens     : NOT CHECKED - no row recorded a post-cut PIN probe.'
        Write-Output '                        This is not a pass. The whole gate is unverified.'
    } else {
        $both = @($probed | Where-Object { $_.pin_after -eq 'BOTH' })
        $none = @($probed | Where-Object { $_.pin_after -eq 'NEITHER' })
        $one  = @($probed | Where-Object { $_.pin_after -ne 'BOTH' -and $_.pin_after -ne 'NEITHER' })
        if ($both.Count -eq 0 -and $none.Count -eq 0) {
            Write-Output "  Which PIN opens     : exactly one PIN opened the device after each of $($one.Count) probed cut(s)."
            $byPin = $one | Group-Object pin_after | ForEach-Object { "$($_.Name) x$($_.Count)" }
            Write-Output "                        distribution: $($byPin -join ', ')"
        }
        if ($both.Count -gt 0) {
            Write-Output "  Which PIN opens     : BOTH PINs opened the device after cut(s) $(($both | ForEach-Object { $_.cut }) -join ', ')."
            Write-Output '                        Two live sealing keys for one store. Blocking.'
        }
        if ($none.Count -gt 0) {
            Write-Output "  Which PIN opens     : NEITHER PIN opened the device after cut(s) $(($none | ForEach-Object { $_.cut }) -join ', ')."
            Write-Output '                        The store is unreachable with either PIN. Blocking.'
        }
    }
    $digest = @($rows | Where-Object { $_.payload_sha_before -ne '' -and $_.payload_sha_after -ne '' })
    $moved  = @($digest | Where-Object { $_.payload_sha_before -ne $_.payload_sha_after })
    if ($digest.Count -eq 0) {
        Write-Output '  Record survival     : NOT CHECKED - no row carried a payload digest on both sides.'
        Write-Output '                        "no record may be lost" is unverified by this run.'
    } elseif ($moved.Count -eq 0) {
        Write-Output "  Record survival     : the slot's SHA-256 was identical before and after across"
        Write-Output "                        $($digest.Count) cut(s). The record was re-sealed under the surviving"
        Write-Output '                        PIN with its bytes unchanged.'
    } else {
        Write-Output "  Record survival     : the payload digest CHANGED on cut(s) $(($moved | ForEach-Object { $_.cut }) -join ', ')."
        Write-Output '                        A record was lost or altered by the cut. Blocking.'
    }
    $unread = @($rows | Where-Object { $_.payload_ok_before -eq 'True' -and $_.payload_ok_after -ne 'True' })
    if ($unread.Count -gt 0) {
        Write-Output "  Readback            : the slot read before the cut and NOT after, on cut(s) $(($unread | ForEach-Object { $_.cut }) -join ', ')."
    }
    Write-Output ''
    Write-Output '  Note: the stale-ciphertext half of the same exit-gate clause - "a PIN change'
    Write-Output '  leaves no stale old-PIN ciphertext" - is proven from the raw flash, not from'
    Write-Output '  this table. Each cut ran `scan`; read the retired side of the re-sealed slot in'
    Write-Output '  console.log and confirm it counts zero non-0xff bytes.'
}

if ($mode -eq 'attempt') {
    Write-Output ''
    Write-Output 'The attempt-counter gate, which is what this mode exists to answer:'
    Write-Output ''
    $counted = @($rows | Where-Object { $_.failures_before -match '^\d+$' -and $_.failures_after -match '^\d+$' })
    if ($counted.Count -eq 0) {
        Write-Output '  Count continuity    : NOT CHECKED - no row carried the count on both sides.'
        Write-Output '                        This is not a pass. The decrement property is unverified.'
    } else {
        $lost   = @($counted | Where-Object { [int]$_.failures_after -lt [int]$_.failures_before })
        $double = @($counted | Where-Object { [int]$_.failures_after -gt ([int]$_.failures_before + 1) })
        $kept   = @($counted | Where-Object { [int]$_.failures_after -eq ([int]$_.failures_before + 1) })
        $held   = @($counted | Where-Object { [int]$_.failures_after -eq [int]$_.failures_before })
        Write-Output "  Count continuity    : across $($counted.Count) comparable cut(s), the count rose by one on"
        Write-Output "                        $($kept.Count) and stayed put on $($held.Count)."
        if ($lost.Count -gt 0) {
            Write-Output "                        WENT BACKWARDS on cut(s) $(($lost | ForEach-Object { $_.cut }) -join ', '). Blocking:"
            Write-Output '                        a lost count is a free guess for whoever pulled the power.'
        }
        if ($double.Count -gt 0) {
            Write-Output "                        COUNTED MORE THAN ONCE on cut(s) $(($double | ForEach-Object { $_.cut }) -join ', ')."
        }
        if ($lost.Count -eq 0 -and $double.Count -eq 0) {
            Write-Output '                        No count was lost and none was charged twice.'
        }
    }
    # The sharp check. A cut that arrived after the console had already answered did not
    # interrupt the attempt at all, so its count is not allowed to be missing.
    $completed = @($rows | Where-Object { $_.unlock_completed_before_cut -eq 'True' -and $_.failures_before -match '^\d+$' -and $_.failures_after -match '^\d+$' })
    $uncharged = @($completed | Where-Object { [int]$_.failures_after -eq [int]$_.failures_before })
    if ($completed.Count -eq 0) {
        Write-Output '  Completed attempts  : none of the cuts arrived after the unlock had answered,'
        Write-Output '                        so this check had no cases to judge.'
    } elseif ($uncharged.Count -eq 0) {
        Write-Output "  Completed attempts  : $($completed.Count) cut(s) arrived after the unlock had answered, and"
        Write-Output '                        every one of them still carried its count afterwards.'
    } else {
        Write-Output "  Completed attempts  : cut(s) $(($uncharged | ForEach-Object { $_.cut }) -join ', ') completed the unlock and lost the count."
        Write-Output '                        That is an uncounted verification. Blocking.'
    }
    $cleared = @($rows | Where-Object { $_.failures_after_clear -match '^\d+$' })
    $notCleared = @($cleared | Where-Object { [int]$_.failures_after_clear -ne 0 })
    if ($cleared.Count -gt 0) {
        if ($notCleared.Count -eq 0) {
            Write-Output "  Success clears      : the correct PIN reset the count to 0 after all $($cleared.Count) cut(s)."
        } else {
            Write-Output "  Success clears      : the count did NOT reset on cut(s) $(($notCleared | ForEach-Object { $_.cut }) -join ', ')."
        }
    }
    $phases = @($rows | Where-Object { $_.cut_phase -ne '' }) | Group-Object cut_phase |
              ForEach-Object { "$($_.Name) x$($_.Count)" }
    if ($phases) {
        Write-Output "  Where the cuts fell : $($phases -join ', ')"
    }
    Write-Output ''
    Write-Output '  WHAT THIS MODE DOES NOT PROVE, and the reason it cannot. Vault::unlock spends'
    Write-Output '  about 1.9 s in Argon2id before it programs the attempt cell - deliberately, so a'
    Write-Output '  cut during the stretch buys no uncounted verification. The counted region is'
    Write-Output '  therefore microseconds wide at the very end of a two second operation, and a'
    Write-Output '  hand-timed pull will almost never land inside it: a `cut_phase` column full of'
    Write-Output '  uncounted_stretch is the expected result, not a weak run. The exhaustive sweep of'
    Write-Output '  that boundary is the host fuzzer, notyas-wallet tests/powerloss.rs, at Op::UnlockBad'
    Write-Output '  and Op::UnlockToWipe:  cargo test -p notyas-wallet --release -- --ignored'
    Write-Output '  What the hardware adds is that the same property holds over the real esp_partition'
    Write-Output '  driver and the real HMAC key, which no host test can claim.'
}

if ($mode -eq 'policy') {
    Write-Output ''
    Write-Output 'The SET-POLICY gate, which is what this mode exists to answer:'
    Write-Output ''
    # The gate asks for a cut at EACH of the seven steps. The step is observed rather than
    # chosen, so coverage is the number that closes it - a count of cuts says nothing about
    # which steps were exercised.
    $steps = @('Y1','Y2','Y3','Y4','Y5','Y6','Y7')
    $seen = @{}
    foreach ($r in $rows) { if ($r.step_at_cut -match '^Y\d$') { $seen[$r.step_at_cut] = [int]$seen[$r.step_at_cut] + 1 } }
    $missing = @($steps | Where-Object { -not $seen.ContainsKey($_) })
    $line = ($steps | ForEach-Object { if ($seen.ContainsKey($_)) { "$_ x$($seen[$_])" } else { "$_ -" } }) -join '  '
    Write-Output "  Step coverage       : $line"
    if ($missing.Count -eq 0) {
        Write-Output '                        every one of the seven steps took at least one cut.'
    } else {
        Write-Output "                        NOT COVERED: $($missing -join ', '). The exit gate asks for a cut"
        Write-Output '                        at each of the seven steps, so it is not closed yet. Run more'
        Write-Output '                        cuts, or widen the delay window to reach the later steps.'
    }
    $weaker = @($rows | Where-Object { $_.flags -match 'policy_weaker_than_both' })
    $odd    = @($rows | Where-Object { $_.flags -match 'policy_value_unexpected' })
    $effective = @($rows | Where-Object { $_.wipe_after_after -match '^\d+$' })
    if ($effective.Count -eq 0) {
        Write-Output '  Effective policy    : NOT CHECKED - no row read a wipe threshold after the cut.'
    } elseif ($weaker.Count -eq 0 -and $odd.Count -eq 0) {
        $vals = ($effective | Group-Object wipe_after_after | ForEach-Object { "$($_.Name) x$($_.Count)" }) -join ', '
        Write-Output "  Effective policy    : after every cut the threshold was one of the two values in"
        Write-Output "                        play ($vals), never weaker than both."
    } else {
        if ($weaker.Count -gt 0) {
            Write-Output "  Effective policy    : WEAKER THAN BOTH values on cut(s) $(($weaker | ForEach-Object { $_.cut }) -join ', '). Blocking."
        }
        if ($odd.Count -gt 0) {
            Write-Output "  Effective policy    : a value neither side asked for on cut(s) $(($odd | ForEach-Object { $_.cut }) -join ', ')."
        }
    }
    $genRows = @($rows | Where-Object { $_.policy_gen_before -match '^\d+$' -and $_.policy_gen_after -match '^\d+$' })
    $genBack = @($genRows | Where-Object { [int]$_.policy_gen_after -lt [int]$_.policy_gen_before })
    if ($genRows.Count -eq 0) {
        Write-Output '  Policy generation   : NOT CHECKED - no row carried policy_gen on both sides.'
    } elseif ($genBack.Count -eq 0) {
        Write-Output "  Policy generation   : never went backwards across $($genRows.Count) comparable cut(s)."
    } else {
        Write-Output "  Policy generation   : REGRESSED on cut(s) $(($genBack | ForEach-Object { $_.cut }) -join ', '). Blocking."
    }
    $floor = @($rows | Where-Object { $_.min_pin_len_after -match '^\d+$' })
    if ($floor.Count -eq 0) {
        Write-Output '  PIN floor           : NOT CHECKED - the console status line does not report'
        Write-Output '                        min_pin_len, so the half of SET-POLICY that moves the floor'
        Write-Output '                        cannot be read back. Ratified Q4 puts the floor at 4'
        Write-Output '                        characters and the UI must never enforce more than the'
        Write-Output '                        store does, which makes this worth reporting rather than'
        Write-Output '                        dropping.'
    }
}

Write-Output ''
Write-Output 'Stated weakness, which belongs in the milestone note verbatim:'
Write-Output ''
Write-Output '  The cut window was SAMPLED, not swept. Q43''s USB-controlled relay is deferred'
Write-Output '  to 0.3.0, so cuts were made by hand at the connector. The harness selects when'
Write-Output '  to ASK for a cut, but the operator''s pull lands some seconds later, so the'
Write-Output '  in-flight index at cut time is observed rather than chosen. Coverage of the'
Write-Output '  commit window is therefore a sample whose distribution nobody controlled, and'
Write-Output '  a rare torn-write window could sit entirely between the sampled points.'
Write-Output ''
Write-Output "Evidence: $csv"
Write-Output ''

if ($flagged -gt 0) {
    Write-Output 'Flagged rows:'
    $rows | Where-Object { $_.flags -ne '' } | ForEach-Object {
        Write-Output ("  cut {0}: {1}" -f $_.cut, $_.flags)
    }
    Write-Output ''
}
