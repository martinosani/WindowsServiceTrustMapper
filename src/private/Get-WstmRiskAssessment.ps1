function Get-WstmRiskAssessment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Findings
    )

    $weights = Get-WstmRuleWeights

    # Normalize to array even when a single object is returned
    $f = @($Findings)

    if ($f.Count -eq 0) {
        return [pscustomobject]@{
            RiskScore = 0
            RiskLevel = 'None'
        }
    }

    # Baseline per-severity weights (used when rule not in weights table)
    $severityWeights = @{
        'High'   = 40
        'Medium' = 20
        'Low'    = 10
        'Info'   = 0
    }

    $score = 0

    foreach ($item in $f) {
        if (-not $item) { continue }

        $rule = $item.Rule
        $sev  = $item.Severity

        if ($rule -and $weights.ContainsKey($rule)) {
            $score += [int]$weights[$rule]
            continue
        }

        if ($sev -and $severityWeights.ContainsKey($sev)) {
            $score += [int]$severityWeights[$sev]
        }
        else {
            # Unknown severity -> minimal conservative score
            $score += 5
        }
    }

    # Cap to keep the scale readable
    if ($score -gt 100) { $score = 100 }

    # Convert score to a stable level
    $level = 'None'
    if ($f | Where-Object { $_.Severity -eq 'High' }   | Select-Object -First 1) { $level = 'High' }
    elseif ($f | Where-Object { $_.Severity -eq 'Medium' } | Select-Object -First 1) { $level = 'Medium' }
    elseif ($f | Where-Object { $_.Severity -eq 'Low' } | Select-Object -First 1) { $level = 'Low' }
    elseif ($f | Where-Object { $_.Severity -eq 'Info' } | Select-Object -First 1) { $level = 'Info' }

    # Optional escalation: if any 'High' severity finding exists, force High level
    if ($f | Where-Object { $_.Severity -eq 'High' } | Select-Object -First 1) {
        $level = 'High'
        if ($score -lt 70) { $score = 70 }
    }

    return [pscustomobject]@{
        RiskScore = $score
        RiskLevel = $level
    }
}
