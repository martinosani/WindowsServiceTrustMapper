function Convert-WstmFindingsToSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Findings
    )

    $f = @($Findings)
    if ($f.Count -eq 0) { return '' }

    ($f | ForEach-Object { "$($_.Rule):$($_.Severity)" }) -join '; '
}
