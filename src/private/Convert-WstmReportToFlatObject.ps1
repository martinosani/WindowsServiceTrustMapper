function Convert-WstmReportToFlatObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject]$InputObject
    )

    process {
        $findings = @($InputObject.Findings)

        $summary = Convert-WstmFindingsToSummary -Findings $findings
        $json    = Convert-WstmFindingsToJson    -Findings $findings

        [PSCustomObject]@{
            ServiceName     = $InputObject.ServiceName
            DisplayName     = $InputObject.DisplayName
            StartName       = $InputObject.StartName
            StartMode       = $InputObject.StartMode
            State           = $InputObject.State
            PathName        = $InputObject.PathName

            ExePathRaw      = $InputObject.ExePathRaw
            ArgsRaw         = $InputObject.ArgsRaw
            ParseMethod     = $InputObject.ParseMethod
            Confidence      = $InputObject.Confidence
            IsQuoted        = $InputObject.IsQuoted
            IsMalformed     = $InputObject.IsMalformed
            HasSpaces       = $InputObject.HasSpaces

            FindingCount    = $findings.Count
            FindingsSummary = $summary
            FindingsJson    = $json

            RiskScore       = $InputObject.RiskScore
            RiskLevel       = $InputObject.RiskLevel
        }
    }
}
