function Test-ServicePathTrust {
    <#
    .SYNOPSIS
    Evaluates a parsed Windows service ImagePath for common trust-boundary and execution risk signals.

    .DESCRIPTION
    Test-ServicePathTrust analyzes the output of Resolve-ServicePathName (a structured representation of a service ImagePath)
    and returns a list of security findings. The function focuses on identifying conditions that commonly lead to service
    misconfigurations, ambiguous CreateProcess parsing, and execution pivots useful for service attack-surface triage.

    It does not access the filesystem or validate ACLs. Instead, it applies lightweight, high-signal rules based on the parsed
    command line such as:
    - Missing or empty ImagePath values
    - Malformed quoting (broken quotes)
    - Unquoted executable paths containing spaces (classic unquoted service path condition)
    - Services launched via interpreters/launchers (cmd/powershell/wscript/rundll32, etc.)
    - Suspicious argument patterns (URLs, UNC paths, PowerShell encoded commands)
    Optionally, it can emit informational findings for low-confidence parsing to support deeper investigation.

    .OUTPUTS
    System.Management.Automation.PSCustomObject[]

    Each finding object contains:
    - Rule (string)
    - Severity (Info|Low|Medium|High)
    - Category (Parsing|Execution|TrustBoundary)
    - Evidence (string)
    - Recommendation (string)

    .EXAMPLE
    # Assess a single service ImagePath and show findings
    $parsed = Resolve-ServicePathName -ServicePathName 'C:\Program Files\Acme Agent\agent.exe -service'
    $findings = Test-ServicePathTrust -ParsedPath $parsed
    $findings | Format-Table -AutoSize

    .EXAMPLE
    # Include informational findings (e.g., low parsing confidence) for triage
    $parsed = Resolve-ServicePathName -ServicePathName '"C:\Program Files\Acme Agent\agent.exe -service'
    Test-ServicePathTrust -ParsedPath $parsed -IncludeInfo

    .EXAMPLE
    # Typical pipeline usage inside a service enumeration loop
    Get-CimInstance Win32_Service | ForEach-Object {
        $p = Resolve-ServicePathName -ServicePathName $_.PathName
        [pscustomobject]@{
            Name     = $_.Name
            PathName = $_.PathName
            Findings = @(Test-ServicePathTrust -ParsedPath $p)
        }
    } | Where-Object { $_.Findings.Count -gt 0 }
    #>
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
    $runsViaInterpreter = $false
    $exeLower = ($ParsedPath.ExePathRaw -as [string]).ToLowerInvariant()
    $interpreters = @(
        '\cmd.exe', '\powershell.exe', '\pwsh.exe', '\wscript.exe', '\cscript.exe',
        '\mshta.exe', '\rundll32.exe'
    )
    
    if ($exeLower) {
        foreach ($i in $interpreters) {
            if ($exeLower.EndsWith($i)) {
                $runsViaInterpreter = $true
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
    $hasEncodedCommand = $false
    $hasUrl = $false
    $hasUnc = $false
    if ($ParsedPath.ArgsRaw) {
        $arguments = $ParsedPath.ArgsRaw

        if ($arguments -match '(?i)\bhttps?://') {
            $hasUrl = $true
            $findings += New-Finding -Rule 'NetworkLocationInArgs' -Severity 'Low' -Category 'Execution' `
                -Evidence "Arguments contain URL: $arguments" `
                -Recommendation 'Verify the service does not fetch/execute code from remote locations.'
        }

        if ($arguments -match '\\\\[^\\]+\\[^\\]+') {
            $hasUnc = $true
            $findings += New-Finding -Rule 'UNCPathInArgs' -Severity 'Low' -Category 'Execution' `
                -Evidence "Arguments contain UNC path: $arguments" `
                -Recommendation 'Verify the UNC target is controlled and that SMB integrity/authn expectations are met.'
        }

        if ($arguments -match '(?i)\b-encodedcommand\b') {
            $hasEncodedCommand = $true
            $findings += New-Finding -Rule 'EncodedCommandInArgs' -Severity 'Medium' -Category 'Execution' `
                -Evidence "Arguments contain PowerShell encoded command flag: $arguments" `
                -Recommendation 'Review service command line intent; encoded commands are high-risk and often abused.'
        }
    }

    # Rule 5b: High-signal combo - Interpreter + EncodedCommand
    if ($runsViaInterpreter -and $hasEncodedCommand) {
        $findings += New-Finding `
            -Rule 'InterpreterEncodedCommandCombo' `
            -Severity 'High' `
            -Category 'Execution' `
            -Evidence "Service runs via interpreter and uses encoded command. Exe='$($ParsedPath.ExePathRaw)' Args='$($ParsedPath.ArgsRaw)'" `
            -Recommendation 'Treat as high-risk: confirm legitimacy/owner, verify binary & arguments origin, check service ACLs and persistence indicators.'
    }

    # Optional: another strong combo
    if ($runsViaInterpreter -and ($hasUrl -or $hasUnc)) {
        $findings += New-Finding `
            -Rule 'InterpreterRemoteTargetCombo' `
            -Severity 'High' `
            -Category 'Execution' `
            -Evidence "Service runs via interpreter and references remote content (URL/UNC). Exe='$($ParsedPath.ExePathRaw)' Args='$($ParsedPath.ArgsRaw)'" `
            -Recommendation 'Treat as high-risk: validate remote target trust, ensure no user-writable path involvement, and review change history.'
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
