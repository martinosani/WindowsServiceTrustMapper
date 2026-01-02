function Get-WstmRuleWeights {
    [CmdletBinding()]
    param()

    # Rule-specific weights (override defaults by rule name)
    @{
        'UnquotedPathPotential'     = 30
        'ServiceRunsViaInterpreter' = 20
        'EncodedCommandInArgs'      = 20
        'UNCPathInArgs'             = 10
        'NetworkLocationInArgs'     = 10
        'MalformedQuotedPath'       = 5
        'MissingImagePath'          = 5
        'LowParsingConfidence'      = 0  # Info-only by default
    }
}
