function Test-ServicePathTrust {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$ParsedPath,

        # Optional: include informational findings
        [switch]$IncludeInfo
    )

    $findings = @()

    function New-Finding {
        param(
            [Parameter(Mandatory)][string]$Rule,
            [Parameter(Mandatory)][ValidateSet('Info','Low','Medium','High')][string]$Severity,
            [Parameter(Mandatory)][string]$Evidence,
            [Parameter()][ValidateSet('Parsing','Execution','TrustBoundary')][string]$Category = 'TrustBoundary',
            [Parameter()][string]$Recommendation = $null
        )
        [PSCustomObject]@{
            Rule           = $Rule
            Severity       = $Severity
            Category       = $Category
            Evidence       = $Evidence
            Recommendation = $Recommendation
        }
    }

    # Rule 1: Missing or empty ImagePath
    if ($ParsedPath.ParseMethod -eq 'Empty' -or [string]::IsNullOrWhiteSpace($ParsedPath.OriginalPathName)) {
        $findings += New-Finding `
            -Rule 'MissingImagePath' `
            -Severity 'Low' `
            -Category 'Parsing' `
            -Evidence 'Service ImagePath is empty or null' `
            -Recommendation 'Verify service configuration and registry ImagePath value.'
        return $findings
    }

    # Rule 2: Malformed quoted path
    if ($ParsedPath.IsMalformed -or $ParsedPath.ParseMethod -eq 'MalformedQuoted') {
        $findings += New-Finding `
            -Rule 'MalformedQuotedPath' `
            -Severity 'Low' `
            -Category 'Parsing' `
            -Evidence "Malformed quoting in ImagePath: $($ParsedPath.OriginalPathName)" `
            -Recommendation 'Fix quoting in ImagePath to avoid ambiguous CreateProcess parsing.'
    }

    # Rule 3: Unquoted service path with spaces (classic unquoted service path condition)
    if (-not $ParsedPath.IsQuoted -and $ParsedPath.HasSpaces -and $ParsedPath.ExePathRaw) {
        $findings += New-Finding `
            -Rule 'UnquotedPathPotential' `
            -Severity 'Medium' `
            -Category 'TrustBoundary' `
            -Evidence "Unquoted executable path contains spaces: $($ParsedPath.ExePathRaw)" `
            -Recommendation 'Quote the executable path in ImagePath and verify no writable locations exist in the path chain.'
    }

    # Rule 4: Interpreter/service launcher detection
    # Note: raw compare is fine here; real resolution comes later with Resolve-ExecutablePath
    $exeLower = ($ParsedPath.ExePathRaw -as [string]).ToLowerInvariant()
    $interpreters = @(
        '\cmd.exe', '\powershell.exe', '\pwsh.exe', '\wscript.exe', '\cscript.exe',
        '\mshta.exe', '\rundll32.exe'
    )
    if ($exeLower) {
        foreach ($i in $interpreters) {
            if ($exeLower.EndsWith($i)) {
                $findings += New-Finding `
                    -Rule 'ServiceRunsViaInterpreter' `
                    -Severity 'Medium' `
                    -Category 'Execution' `
                    -Evidence "Service executable appears to be an interpreter/launcher: $($ParsedPath.ExePathRaw)" `
                    -Recommendation 'Inspect arguments target (script/DLL/command), resolve target path, and verify ACLs and trust boundary.'
                break
            }
        }
    }

    # Rule 5: Suspicious argument patterns (cheap pivots)
    if ($ParsedPath.ArgsRaw) {
        $arguments = $ParsedPath.ArgsRaw

        if ($arguments -match '(?i)\bhttps?://') {
            $findings += New-Finding -Rule 'NetworkLocationInArgs' -Severity 'Low' -Category 'Execution' `
                -Evidence "Arguments contain URL: $arguments" `
                -Recommendation 'Verify the service does not fetch/execute code from remote locations.'
        }

        if ($arguments -match '\\\\[^\\]+\\[^\\]+') {
            $findings += New-Finding -Rule 'UNCPathInArgs' -Severity 'Low' -Category 'Execution' `
                -Evidence "Arguments contain UNC path: $arguments" `
                -Recommendation 'Verify the UNC target is controlled and that SMB integrity/authn expectations are met.'
        }

        if ($arguments -match '(?i)\b-encodedcommand\b') {
            $findings += New-Finding -Rule 'EncodedCommandInArgs' -Severity 'Medium' -Category 'Execution' `
                -Evidence "Arguments contain PowerShell encoded command flag: $arguments" `
                -Recommendation 'Review service command line intent; encoded commands are high-risk and often abused.'
        }
    }

    # Rule 6: Low-confidence parsing (info-only by default, to reduce noise)
    if ($ParsedPath.Confidence -eq 'Low' -and $IncludeInfo) {
        $findings += New-Finding `
            -Rule 'LowParsingConfidence' `
            -Severity 'Info' `
            -Category 'Parsing' `
            -Evidence "Parsing method '$($ParsedPath.ParseMethod)' indicates ambiguity" `
            -Recommendation 'Resolve executable path on disk and confirm actual binary launched.'
    }

    return $findings
}
