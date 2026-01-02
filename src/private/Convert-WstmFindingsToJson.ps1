function Convert-WstmFindingsToJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Findings
    )

    $f = @($Findings)
    if ($f.Count -eq 0) { return '[]' }

    $f | ConvertTo-Json -Depth 6 -Compress
}
