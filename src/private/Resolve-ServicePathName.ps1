
function Resolve-ServicePathName {
    <#
    .SYNOPSIS
        Resolves and analyzes a Windows service ImagePath string into structured components.
    .DESCRIPTION
        Resolve-ServicePathName takes the raw ImagePath string of a Windows service and
        interprets it to extract the executable path and arguments while preserving
        ambiguity and parsing confidence.

        The function does NOT assume the path is safe or unambiguous. Instead, it applies
        multiple parsing strategies (quoted, unquoted, fallback) and reports:
        - how the path was interpreted
        - whether quoting is correct or malformed
        - whether spaces introduce ambiguity
        - how confident the parsing result is

        This function is designed for security analysis and trust boundary mapping,
        not for command execution or normalization.
    .PARAMETER ServicePathName
        The full path name of the Windows service, including the executable and any arguments.
    .OUTPUTS
        System.Management.Automation.PSCustomObject

        The returned object contains the following properties:

        - OriginalPathName : Original ImagePath string as stored in the service
        - ExePathRaw       : Parsed executable path (may be ambiguous)
        - ArgsRaw          : Parsed arguments (if determinable)
        - IsQuoted         : Indicates whether the path starts with a quote
        - IsMalformed      : Indicates malformed or broken quoting
        - HasSpaces        : Indicates whether the executable path contains spaces
        - Confidence       : Parsing confidence level (High, Medium, Low)
        - ParseMethod      : Parsing strategy used (Quoted, UnquotedExt, FallbackExt, FallbackRaw, MalformedQuoted)
    .EXAMPLE
        Resolve-ServicePathName -ServicePathName '"C:\Program Files\App\service.exe" -k start'

        Returns a high-confidence result indicating a correctly quoted executable path
        with associated arguments.

    .EXAMPLE
        Resolve-ServicePathName -ServicePathName 'C:\Program Files\App\service.exe -k start'

        Returns a medium-confidence result indicating an unquoted executable path with
        spaces, which may represent a potential unquoted service path condition.

    .EXAMPLE
        Resolve-ServicePathName -ServicePathName '"C:\Program Files\App\service.exe -k start'

        Returns a low-confidence result indicating malformed quoting, preserving ambiguity
        for further security analysis.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$ServicePathName
    )

    $result = [PSCustomObject]@{
        OriginalPathName = $ServicePathName
        ExePathRaw       = $null
        ArgsRaw          = $null
        IsQuoted         = $false
        IsMalformed      = $false
        HasSpaces        = $false
        Confidence       = 'Unknown'
        ParseMethod      = 'Unknown'
    }

    if ([string]::IsNullOrWhiteSpace($ServicePathName)) {
        $result.Confidence = 'Low'
        $result.ParseMethod = 'Empty'
        return $result
    }

    $pn = $ServicePathName.Trim()

    # Case 1: quoted executable
    if ($pn.StartsWith('"')) {
        if ($pn -match '^"([^"]+)"\s*(.*)$') {
            $result.ExePathRaw  = $Matches[1]
            $result.ArgsRaw     = $Matches[2]
            $result.IsQuoted    = $true
            $result.IsMalformed = $false
            $result.HasSpaces   = $result.ExePathRaw -match '\s'
            $result.Confidence  = 'High'
            $result.ParseMethod = 'Quoted'
        }
        else {
            # Malformed quoted string, take whole as exe path
            $result.ExePathRaw  = $pn.Trim('"')
            $result.ArgsRaw     = $null
            $result.IsQuoted    = $true
            $reuslt.IsMalformed = $true
            $result.HasSpaces   = $result.ExePathRaw -match '\s'
            $result.Confidence  = 'Low'
            $result.ParseMethod = 'MalformedQuoted'
        }
        return $result
    }

    # Case 2: unquoted, try to match executable extension
    if ($pn -match '(?i)^(.+?\.(exe|com|bat|cmd))\s*(.*)$') {
        $result.ExePathRaw = $Matches[1]
        $result.ArgsRaw    = $Matches[3]
        $result.IsQuoted  = $false
        $result.HasSpaces = $result.ExePathRaw -match '\s'
        $result.ParseMethod = 'UnquotedExt'
        if (-not $result.HasSpaces) {
            $result.Confidence = 'High'
        }
        else {
            $result.Confidence = 'Medium'
        }
        return $result
    }

    # Case 3: fallback split
    # Try to locate a plausible executable token anyway
    if ($pn -match '(.+?\.(exe|com|bat|cmd))') {
        $exeCandidate = $Matches[1]

        # Extract arguments by removing the exe candidate
        $argsCandidate = $pn.Substring($exeCandidate.Length).Trim()

        $result.ExePathRaw = $exeCandidate
        $result.ArgsRaw    = if ($argsCandidate) { $argsCandidate } else { $null }
        $result.HasSpaces  = $exeCandidate -match '\s'
        $result.IsQuoted   = $false
        $result.Confidence = 'Low'
        $result.ParseMethod = 'FallbackExt'
    }
    else {
        # Absolute last-resort fallback
        $result.ExePathRaw = $pn
        $result.ArgsRaw    = $null
        $result.HasSpaces  = $pn -match '\s'
        $result.IsQuoted   = $false
        $result.Confidence = 'Low'
        $result.ParseMethod = 'FallbackRaw'
    }

    return $result
}