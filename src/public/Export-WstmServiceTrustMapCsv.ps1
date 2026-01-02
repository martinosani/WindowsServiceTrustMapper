function Export-WstmServiceTrustMapCsv {
    <#
    .SYNOPSIS
    Exports WindowsServiceTrustMapper results to CSV.

    .DESCRIPTION
    Exports a flattened CSV report of service trust mapping results.
    Findings are serialized into FindingsSummary and FindingsJson columns.

    .PARAMETER Path
    Output CSV path.

    .PARAMETER InputObject
    Optional pipeline input from Get-WstmServiceTrustMap.

    .PARAMETER Force
    Overwrite output file if it exists.

    .EXAMPLE
    Export-WstmServiceTrustMapCsv -Path .\wstm-report.csv -Force

    .EXAMPLE
    Get-WstmServiceTrustMap | Export-WstmServiceTrustMapCsv -Path .\wstm-report.csv -Force
    #>
    [CmdletBinding(DefaultParameterSetName='Run')]
    param(
        [Parameter(Mandatory, Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(ParameterSetName='Pipe', ValueFromPipeline)]
        [PSCustomObject]$InputObject,

        [switch]$Force
    )

    begin {
        $items = New-Object System.Collections.Generic.List[object]

        if ((Test-Path -LiteralPath $Path) -and (-not $Force)) {
            throw "File already exists: $Path. Use -Force to overwrite."
        }
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'Pipe') {
            $items.Add($InputObject)
        }
    }

    end {
        $data = if ($PSCmdlet.ParameterSetName -eq 'Pipe') {
            $items
        } else {
            Get-WstmServiceTrustMap -ErrorAction Stop
        }

        $flat = $data | Convert-WstmReportToFlatObject

        $flat | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding utf8 -Force:$Force

        Get-Item -LiteralPath $Path
    }
}
