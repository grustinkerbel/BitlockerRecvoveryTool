@{
    RootModule            = 'BitlockerRecoveryTools.psm1'
    ModuleVersion         = '2.0.0'
    GUID                  = 'c32b2fde-9cbf-4633-8cbc-b37bdd1d88bd'
    Author                = 'Bill Galway'
    CompanyName           = ''
    Copyright             = '(c) Bill Galway. All rights reserved.'
    Description           = 'Audits BitLocker status and recovery key escrow across Active Directory computers using parallel processing, with optional remediation (enable BitLocker, back up missing recovery keys to AD, remove duplicate protectors). Run Get-Help Invoke-BitlockerTool -Full to get started.'
    PowerShellVersion     = '7.0'
    CompatiblePSEditions  = @('Core')

    # ActiveDirectory is imported by Invoke-BitlockerTool when it runs, so it is not listed
    # as a required module here. That keeps Import-Module and Get-Help working on machines
    # without RSAT installed.
    RequiredModules       = @()

    FunctionsToExport     = @(
        'Invoke-BitlockerTool'
        'Invoke-BitlockerEndpoint'
        'Get-ADBitLockerKeyMap'
        'Get-BitLockerStatus'
        'Export-ResultsSafe'
        'Write-Log'
    )
    CmdletsToExport       = @()
    VariablesToExport     = @()
    AliasesToExport       = @()

    PrivateData = @{
        PSData = @{
            Tags       = @('BitLocker', 'ActiveDirectory', 'RecoveryKey', 'Audit', 'Compliance', 'Parallel')
            ReleaseNotes = 'v2.0: single bulk AD query, one PSSession per endpoint, post-pass escrow verification, batched logging, correctness fixes.'
        }
    }
}
