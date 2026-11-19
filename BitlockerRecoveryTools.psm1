#Requires -Version 7.0
# ----------------------------
# Module state
# ----------------------------
$script:LogPath = Join-Path (Get-Location).Path 'BitlockerTools.log'

# ----------------------------
# Logging helpers
# ----------------------------
function Format-LogLine {
    param(
        [string]$Message,
        [string]$Level = 'INFO',
        [string]$ComputerName
    )
    $time = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    if ($ComputerName) { "[$time][$Level][$ComputerName] $Message" }
    else               { "[$time][$Level] $Message" }
}

# Main-thread only: writes a batch of lines to console and log file in one file operation.
function Write-LogLines {
    param([string[]]$Lines)
    if (-not $Lines -or $Lines.Count -eq 0) { return }
    foreach ($l in $Lines) { Write-Host $l }
    try   { Add-Content -Path $script:LogPath -Value $Lines -Encoding UTF8 -ErrorAction Stop }
    catch { Write-Warning "Could not write log file '$($script:LogPath)': $($_.Exception.Message)" }
}

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = 'INFO',
        [string]$ComputerName
    )
    Write-LogLines @(Format-LogLine -Message $Message -Level $Level -ComputerName $ComputerName)
}

# ----------------------------
# Small helpers
# ----------------------------
function ConvertTo-GuidKey {
    param([string]$Id)
    if (-not $Id) { return $null }
    $Id.Trim().Trim('{}').ToLowerInvariant()
}

function New-BitLockerResult {
    param([string]$ComputerName)
    [PSCustomObject]@{
        Timestamp             = Get-Date
        Computer              = $ComputerName
        Online                = $false
        WinRM                 = $false
        Reported              = $false
        Volume                = 'C:'
        Protected             = $null
        Percent               = $null
        MachineKeyCount       = $null
        ADKeyCount            = $null
        ADVerified            = $false
        ADRecoveryKeyID       = @()
        ADRecoveryKeyPassword = @()
        LocalKeySource        = $null
        RecoveryKeyID         = @()
        RecoveryPassword      = @()
        TPMPresent            = $false
        TPMReady              = $false
        CanEnableBitLocker    = $false
        ActivatedBitlocker    = $false
        Error                 = $null
        BackupAttempted       = $false
        # internal bookkeeping (stripped before returning to the pipeline)
        BackupFailed          = 0
        PendingVerifyIds      = @()
        Log                   = @()
    }
}

# ----------------------------
# AD: one bulk query -> hashtable[ComputerName] = List of { ID; Created; Password }
# ----------------------------
function Get-ADBitLockerKeyMap {
    [CmdletBinding()]
    param(
        [switch]$IncludePassword,
        [string]$SearchBase,
        [string]$Server
    )

    $props = @('whenCreated')
    if ($IncludePassword) { $props += 'msFVE-RecoveryPassword' }

    $splat = @{
        LDAPFilter     = '(objectClass=msFVE-RecoveryInformation)'
        Properties     = $props
        ResultPageSize = 1000
        ErrorAction    = 'Stop'
    }
    if ($SearchBase) { $splat.SearchBase = $SearchBase }
    if ($Server)     { $splat.Server     = $Server }

    $map = @{}   # case-insensitive keys
    foreach ($o in Get-ADObject @splat) {
        # DN: CN=<timestamp>{<protector GUID>},CN=<COMPUTER>,OU=...
        if ($o.DistinguishedName -notmatch '^CN=[^,]*\{(?<guid>[0-9A-Fa-f-]{36})\},CN=(?<name>(?:\\,|[^,])+),') {
            continue
        }
        $name = $Matches['name']
        if (-not $map.ContainsKey($name)) {
            $map[$name] = [System.Collections.Generic.List[object]]::new()
        }
        $map[$name].Add([PSCustomObject]@{
            ID       = $Matches['guid'].ToLowerInvariant()
            Created  = $o.whenCreated
            Password = if ($IncludePassword) { [string]$o.'msFVE-RecoveryPassword' } else { $null }
        })
    }
    $map
}

function Get-KeyIdsFromMap {
    param($Map, [string]$Computer)
    if ($Map -and $Map.ContainsKey($Computer)) { @($Map[$Computer] | ForEach-Object { $_.ID }) } else { @() }
}

# ----------------------------
# Remote: one round trip for everything we need to read
# ----------------------------
function Get-BitLockerSnapshot {
    param(
        [Parameter(Mandatory)]$Session,
        [switch]$IncludePassword
    )

    Invoke-Command -Session $Session -ErrorAction Stop -ArgumentList $IncludePassword.IsPresent -ScriptBlock {
        param($withPassword)

        $out = [PSCustomObject]@{
            Protected    = $null
            Percent      = $null
            VolumeStatus = $null
            Protectors   = @()
            TpmPresent   = $false
            TpmReady     = $false
            Error        = $null
        }

        try {
            $v = Get-BitLockerVolume -MountPoint 'C:' -ErrorAction Stop | Select-Object -First 1
            if (-not $v) { $out.Error = 'BitLocker volume not found.'; return $out }

            $out.Protected    = [string]$v.ProtectionStatus
            $out.Percent      = $v.EncryptionPercentage
            $out.VolumeStatus = [string]$v.VolumeStatus
            $out.Protectors   = @(
                $v.KeyProtector |
                    Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } |
                    ForEach-Object {
                        [PSCustomObject]@{
                            Id       = [string]$_.KeyProtectorId
                            Password = if ($withPassword) { [string]$_.RecoveryPassword } else { $null }
                        }
                    }
            )
        }
        catch {
            $out.Error = $_.Exception.Message
            return $out
        }

        try {
            $t = Get-Tpm -ErrorAction Stop
            $out.TpmPresent = [bool]$t.TpmPresent
            $out.TpmReady   = [bool]$t.TpmReady
        }
        catch { }   # no TPM / TPM cmdlets unavailable

        $out
    }
}

# Standalone convenience wrapper (opens and closes its own session)
function Get-BitLockerStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [switch]$IncludePassword
    )
    $session = New-PSSession -ComputerName $ComputerName -ErrorAction Stop
    try   { Get-BitLockerSnapshot -Session $session -IncludePassword:$IncludePassword }
    finally { Remove-PSSession $session -ErrorAction SilentlyContinue }
}

# ----------------------------
# Per-endpoint worker. Runs inside parallel runspaces; pure function of its inputs:
# no AD calls, no shared state, returns a result object carrying its own log lines.
# ----------------------------
function Invoke-BitlockerEndpoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [object[]]$ADKeys = @(),
        [switch]$IncludeRecoveryKey,
        [switch]$AutoEnableBitLocker,
        [switch]$CleanupProtectors,
        [switch]$DryRun,
        [switch]$SkipPing,
        [int]$OpenTimeoutSec = 10,
        [int]$OperationTimeoutSec = 60
    )

    $log = [System.Collections.Generic.List[string]]::new()
    $r   = New-BitLockerResult -ComputerName $ComputerName
    $session = $null

    try {
        # ---- AD data (already in memory) ----
        $ADKeys = @($ADKeys | Where-Object { $_ })
        $adIds  = @($ADKeys | ForEach-Object { $_.ID })
        $adSet  = [System.Collections.Generic.HashSet[string]]::new([string[]]$adIds, [StringComparer]::OrdinalIgnoreCase)
        $r.ADKeyCount      = $adIds.Count
        $r.ADRecoveryKeyID = $adIds
        if ($IncludeRecoveryKey) {
            $r.ADRecoveryKeyPassword = @($ADKeys | ForEach-Object { $_.Password } | Where-Object { $_ })
        }

        # ---- Connectivity ----
        if (-not $SkipPing) {
            $r.Online = [bool](Test-Connection -TargetName $ComputerName -Count 1 -TimeoutSeconds 1 -Quiet -ErrorAction SilentlyContinue)
            if (-not $r.Online) { throw 'Offline: ping failed' }
        }

        $so = New-PSSessionOption -OpenTimeout ($OpenTimeoutSec * 1000) `
                                  -OperationTimeout ($OperationTimeoutSec * 1000) -NoMachineProfile
        try   { $session = New-PSSession -ComputerName $ComputerName -SessionOption $so -ErrorAction Stop }
        catch { throw "WinRM unavailable: $($_.Exception.Message)" }
        $r.WinRM = $true
        if ($SkipPing) { $r.Online = $true }

        # ---- Snapshot ----
        $snap = Get-BitLockerSnapshot -Session $session -IncludePassword:$IncludeRecoveryKey
        if ($snap.Error) { throw $snap.Error }

        $localProt = @($snap.Protectors)
        $r.Protected      = $snap.Protected
        $r.Percent        = $snap.Percent
        $r.TPMPresent     = [bool]$snap.TpmPresent
        $r.TPMReady       = [bool]$snap.TpmReady
        $r.MachineKeyCount = $localProt.Count
        $r.LocalKeySource = 'BitLockerVolume'
        $r.CanEnableBitLocker = (
            $snap.Protected -eq 'Off' -and
            $snap.TpmPresent -and
            $snap.TpmReady -and
            $localProt.Count -eq 0
        )

        # ---- Optional auto-enable ----
        if ($AutoEnableBitLocker -and $r.CanEnableBitLocker) {
            if ($DryRun) {
                $log.Add((Format-LogLine 'WhatIf: would enable BitLocker' 'INFO' $ComputerName))
            }
            else {
                $log.Add((Format-LogLine 'Enabling BitLocker' 'INFO' $ComputerName))
                Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock {
                    Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 `
                                     -RecoveryPasswordProtector -Confirm:$false -ErrorAction Stop | Out-Null
                }
                $r.ActivatedBitlocker = $true

                # Re-read state over the same session (replaces the old fixed sleep)
                $snap = Get-BitLockerSnapshot -Session $session -IncludePassword:$IncludeRecoveryKey
                if ($snap.Error) { throw "Post-enable snapshot failed: $($snap.Error)" }
                $localProt         = @($snap.Protectors)
                $r.Protected       = $snap.Protected
                $r.Percent         = $snap.Percent
                $r.MachineKeyCount = $localProt.Count
            }
        }

        # ---- Optional cleanup: keep ONE protector that is already escrowed ----
        $removedIds = [System.Collections.Generic.List[string]]::new()
        if ($CleanupProtectors -and $localProt.Count -gt 1) {
            $escrowed = @($localProt | Where-Object { $adSet.Contains((ConvertTo-GuidKey $_.Id)) })

            if ($escrowed.Count -eq 0) {
                $log.Add((Format-LogLine 'Cleanup skipped: no local protector is escrowed in AD yet (keys will be backed up; cleanup next run)' 'WARN' $ComputerName))
            }
            else {
                $createdById = @{}
                foreach ($k in $ADKeys) { $createdById[$k.ID] = $k.Created }
                $keep = $escrowed |
                    Sort-Object { $createdById[(ConvertTo-GuidKey $_.Id)] } -Descending |
                    Select-Object -First 1

                $log.Add((Format-LogLine "Keeping protector $(ConvertTo-GuidKey $keep.Id)" 'INFO' $ComputerName))

                foreach ($p in ($localProt | Where-Object { $_.Id -ne $keep.Id })) {
                    if ($DryRun) {
                        $log.Add((Format-LogLine "WhatIf: would remove protector $(ConvertTo-GuidKey $p.Id)" 'INFO' $ComputerName))
                        $removedIds.Add($p.Id)
                        continue
                    }
                    try {
                        Invoke-Command -Session $session -ErrorAction Stop -ArgumentList $p.Id -ScriptBlock {
                            param($id)
                            Remove-BitLockerKeyProtector -MountPoint 'C:' -KeyProtectorId $id -ErrorAction Stop | Out-Null
                        }
                        $removedIds.Add($p.Id)
                        $log.Add((Format-LogLine "Removed protector $(ConvertTo-GuidKey $p.Id)" 'INFO' $ComputerName))
                    }
                    catch {
                        $log.Add((Format-LogLine "Failed to remove protector $(ConvertTo-GuidKey $p.Id): $($_.Exception.Message)" 'ERROR' $ComputerName))
                    }
                }
            }
        }
        $remaining = @($localProt | Where-Object { $removedIds -notcontains $_.Id })

        # ---- Back up anything not yet escrowed ----
        $missing = @($remaining | Where-Object { -not $adSet.Contains((ConvertTo-GuidKey $_.Id)) })
        $pending = [System.Collections.Generic.List[string]]::new()

        foreach ($p in $missing) {
            $key = ConvertTo-GuidKey $p.Id
            if ($DryRun) {
                $log.Add((Format-LogLine "WhatIf: would back up recovery key $key" 'INFO' $ComputerName))
                continue
            }
            try {
                Invoke-Command -Session $session -ErrorAction Stop -ArgumentList $p.Id -ScriptBlock {
                    param($id)
                    Backup-BitLockerKeyProtector -MountPoint 'C:' -KeyProtectorId $id -ErrorAction Stop | Out-Null
                }
                $r.BackupAttempted = $true
                $pending.Add($key)
                $log.Add((Format-LogLine "Backed up recovery key $key (verification pending)" 'INFO' $ComputerName))
            }
            catch {
                $r.BackupFailed++
                $r.Error = "Backup failed for ${key}: $($_.Exception.Message)"
                $log.Add((Format-LogLine $r.Error 'ERROR' $ComputerName))
            }
        }

        # ---- Final state ----
        $r.Reported         = $true
        $r.PendingVerifyIds = $pending.ToArray()
        $r.RecoveryKeyID    = @($remaining | ForEach-Object { ConvertTo-GuidKey $_.Id })
        if ($IncludeRecoveryKey) {
            $r.RecoveryPassword = @($remaining | ForEach-Object { $_.Password } | Where-Object { $_ })
        }
        # Verified only when there is something to verify and everything is already in AD.
        # Keys we just backed up are verified in the post-pass.
        $r.ADVerified = ($remaining.Count -gt 0 -and $missing.Count -eq 0)
    }
    catch {
        $r.Error = $_.Exception.Message
        $level = if ($r.Online) { 'ERROR' } else { 'WARN' }
        $log.Add((Format-LogLine $r.Error $level $ComputerName))
    }
    finally {
        if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
    }

    $r.Log = $log.ToArray()
    $r
}

# ----------------------------
# CSV export helper
# ----------------------------
function Export-ResultsSafe {
    param(
        [Parameter(Mandatory)][array]$Results,
        [Parameter(Mandatory)][string]$Path,
        [ValidateSet('Append','Overwrite')][string]$Mode = 'Append'
    )

    $join = {
        param($Value)
        if ($null -eq $Value) { '' }
        elseif ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) { @($Value) -join ',' }
        else { $Value }
    }

    $Cleaned = $Results | ForEach-Object {
        [PSCustomObject]@{
            Timestamp             = $_.Timestamp
            Computer              = $_.Computer
            Online                = $_.Online
            WinRM                 = $_.WinRM
            Reported              = $_.Reported
            Volume                = $_.Volume
            Protected             = $_.Protected
            Percent               = $_.Percent
            ADRecoveryKeyID       = & $join $_.ADRecoveryKeyID
            ADRecoveryKeyPassword = & $join $_.ADRecoveryKeyPassword
            LocalKeySource        = & $join $_.LocalKeySource
            RecoveryKey           = & $join $_.RecoveryKeyID
            RecoveryPassword      = & $join $_.RecoveryPassword
            MachineKeyCount       = $_.MachineKeyCount
            ADKeyCount            = $_.ADKeyCount
            ADVerified            = $_.ADVerified
            TPMPresent            = $_.TPMPresent
            TPMReady              = $_.TPMReady
            CanEnableBitLocker    = $_.CanEnableBitLocker
            ActivatedBitlocker    = $_.ActivatedBitlocker
            Error                 = $_.Error
        }
    }

    $exportParams = @{ Path = $Path; NoTypeInformation = $true }
    if ($Mode -eq 'Append' -and (Test-Path $Path)) { $exportParams.Append = $true }
    $Cleaned | Export-Csv @exportParams
}

# ----------------------------
# Main entry point
# ----------------------------

<#
.SYNOPSIS
Generates a BitLocker status and recovery key compliance report for Active Directory computers
using parallel processing.

.DESCRIPTION
Invoke-BitlockerTool collects, per computer:

  * Connectivity (ping + one WinRM session)
  * BitLocker protection state and encryption percentage
  * TPM presence and readiness
  * Recovery key escrow status in Active Directory

Optional remediation:

  * Enable BitLocker on eligible devices (-AutoEnableBitLocker)
  * Back up missing recovery keys to AD (always attempted unless -ADOnly / -WhatIf)
  * Remove duplicate recovery password protectors (-CleanupProtectors)
  * AD-only audit, no endpoint contact (-ADOnly)

PERFORMANCE DESIGN
  * AD is queried ONCE up front (all msFVE-RecoveryInformation objects) and held in a
    hashtable keyed by computer name. Runspaces only do in-memory lookups.
  * Recovery objects are matched to local protectors by protector GUID (parsed from the
    object's DN), so passwords are only fetched when -IncludeRecoveryKey is used.
  * Each endpoint gets ONE PSSession, reused for the snapshot and every remediation step.
  * Escrow verification is a single post-pass AD query, not a per-computer sleep.
  * Log lines are collected per computer and written by the main thread (no mutex).

-WhatIf / -Confirm are evaluated ONCE for the whole batch. If the batch is declined (or
-WhatIf is used) the run continues in report-only mode: nothing is changed on endpoints,
and the NotContacted / ComputerList housekeeping files are not rewritten.

.PARAMETER Filter
Active Directory filter string (Get-ADComputer -Filter syntax, NOT LDAP). Default: *

.PARAMETER SearchBase
Optional OU distinguished name. Limits both the computer query and the recovery-key query.
Recommended when you only care about part of the domain.

.PARAMETER Server
Optional domain controller to use for all AD queries. Using one DC avoids replication
surprises during post-pass verification.

.PARAMETER ComputerList
Text file with one computer name per line. Lines beginning with # are ignored.
Successfully reported computers are commented out afterwards (queue behaviour).

.PARAMETER OutputPath
CSV report path. Default: .\BitLocker_Report.csv

.PARAMETER Mode
Append or Overwrite the CSV. Default: Append.
NOTE: the CSV gained an Error column versus v1.0. Use -Overwrite once when upgrading.

.PARAMETER ThrottleLimit
Maximum parallel runspaces. Default: 50 (work is network-bound).

.PARAMETER IncludeRecoveryKey
Include recovery passwords in the output. WARNING: exported in plaintext.

.PARAMETER ADOnly
AD-only audit of recovery key presence. No endpoint contact.

.PARAMETER AutoEnableBitLocker
Enable BitLocker where: protection is Off, TPM present and ready, and no recovery
password protector exists yet.

.PARAMETER CleanupProtectors
Remove duplicate recovery password protectors, keeping ONE that is already escrowed in AD
(the one whose AD object is newest). If no protector is escrowed yet, cleanup is skipped for
that machine and the missing keys are backed up instead; cleanup happens on the next run.

.PARAMETER ContactedOnly
Export only devices that answered ping.

.PARAMETER SkipPing
Skip the ICMP check and go straight to WinRM (for networks that block ICMP).

.PARAMETER VerifyDelaySeconds
Seconds to wait before each escrow verification pass (max 3 passes). Default: 5.

.PARAMETER LogPath
Log file path. Default: .\BitlockerTools.log (resolved to an absolute path).

.EXAMPLE
Invoke-BitlockerTool -Filter "Name -like 'LT-*'" -SearchBase "OU=Laptops,DC=corp,DC=local"

.EXAMPLE
Invoke-BitlockerTool -ADOnly -IncludeRecoveryKey

.EXAMPLE
Invoke-BitlockerTool -AutoEnableBitLocker -CleanupProtectors -Mode Overwrite -WhatIf

.EXAMPLE
Invoke-BitlockerTool -ComputerList .\queue.txt -OutputPath C:\Reports\BitLocker.csv

Processes only the computers in queue.txt. Computers that report successfully are commented
out with a leading # so the next run retries only the remainder.

.EXAMPLE
Invoke-BitlockerTool -Filter "OperatingSystem -notlike '*Server*'" -SearchBase "OU=Workstations,DC=corp,DC=local" -Server dc01.corp.local -Mode Overwrite

Audits workstations in one OU, sends every AD query to a single domain controller (avoids
replication lag during escrow verification), and replaces any existing report.

.EXAMPLE
Invoke-BitlockerTool -SkipPing -ThrottleLimit 100

Skips the ICMP check for networks that block ping and raises the parallel limit. Useful when
most targets are online and the run is network-bound.

.EXAMPLE
Invoke-BitlockerTool -ContactedOnly -OutputPath .\Online_Only.csv

Exports only computers that answered ping. Offline computers are still appended to
NotContacted_Computers.txt next to the CSV.

.EXAMPLE
$results = Invoke-BitlockerTool -ADOnly
$results | Where-Object { $_.ADKeyCount -eq 0 } | Select-Object Computer

Lists computers that have no recovery key in AD, without contacting any endpoint.

.EXAMPLE
$results = Invoke-BitlockerTool -Filter "Name -like 'LT-*'" -WhatIf
$results | Where-Object { -not $_.ADVerified } | Select-Object Computer, Protected, Error

Report-only run: contacts endpoints but changes nothing. Shows laptops whose keys are not
confirmed in AD and why.

.EXAMPLE
Invoke-BitlockerTool -ComputerList .\NotContacted_Computers.txt -Mode Append

Retries computers that were unreachable on an earlier run.

.EXAMPLE
Invoke-BitlockerTool -Filter "Name -like 'LT-*'" -AutoEnableBitLocker -Confirm:$false -LogPath C:\Logs\BitLocker.log

Enables BitLocker on eligible laptops (TPM present and ready, no recovery protector) and
backs up their keys to AD without prompting. Writes the log to a custom path.

.EXAMPLE
Invoke-BitlockerTool -CleanupProtectors -IncludeRecoveryKey -OutputPath C:\Secure\BitLocker_Keys.csv

Removes duplicate recovery protectors and includes recovery passwords in the output. The CSV
contains plaintext passwords, so store it in a protected location.

.NOTES
Author: Bill Galway
Module: BitLockerTools
Version: 2.0

Requires: ActiveDirectory module (main session only), BitLocker cmdlets on targets,
WinRM on targets, PowerShell 7+.
#>

function Invoke-BitlockerTool {
    [CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'AD')]
    param(
        [Parameter(ParameterSetName = 'AD')]
        [string]$Filter = '*',

        [Parameter(ParameterSetName = 'File')]
        [string]$ComputerList,

        [string]$SearchBase,
        [string]$Server,
        [string]$OutputPath = '.\BitLocker_Report.csv',

        [ValidateSet('Append','Overwrite')]
        [string]$Mode = 'Append',

        [ValidateRange(1,256)]
        [int]$ThrottleLimit = 50,

        [int]$VerifyDelaySeconds = 5,
        [string]$LogPath = '.\BitlockerTools.log',

        [switch]$ContactedOnly,
        [switch]$IncludeRecoveryKey,
        [switch]$ADOnly,
        [switch]$AutoEnableBitLocker,
        [switch]$CleanupProtectors,
        [switch]$SkipPing
    )

    # Resolve paths against the PowerShell location (runspaces / .NET may use another cwd)
    $resolve    = { param($p) $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($p) }
    $OutputPath = & $resolve $OutputPath
    $script:LogPath = & $resolve $LogPath
    if ($ComputerList) { $ComputerList = & $resolve $ComputerList }

    $outDir = Split-Path -Parent $OutputPath
    if (-not (Test-Path $outDir)) { New-Item -Path $outDir -ItemType Directory -Force | Out-Null }

    Import-Module ActiveDirectory -ErrorAction Stop

    # --------------------------------------------------
    # Computer list
    # --------------------------------------------------
    if ($PSCmdlet.ParameterSetName -eq 'File') {
        $Computers = @(Get-Content -Path $ComputerList |
                       ForEach-Object { $_.Trim() } |
                       Where-Object { $_ -and -not $_.StartsWith('#') })
    }
    else {
        $adc = @{ Filter = $Filter; ErrorAction = 'Stop' }
        if ($SearchBase) { $adc.SearchBase = $SearchBase }
        if ($Server)     { $adc.Server     = $Server }
        $Computers = @(Get-ADComputer @adc | Select-Object -ExpandProperty Name)
    }
    $Computers = @($Computers | Sort-Object -Unique)

    if ($Computers.Count -eq 0) {
        Write-Log 'No computers found to process.'
        return
    }

    # --------------------------------------------------
    # One bulk AD query
    # --------------------------------------------------
    Write-Log "Loading BitLocker recovery objects from AD..."
    $mapParams = @{ IncludePassword = $IncludeRecoveryKey }
    if ($SearchBase) { $mapParams.SearchBase = $SearchBase }
    if ($Server)     { $mapParams.Server     = $Server }
    $KeyMap = Get-ADBitLockerKeyMap @mapParams
    Write-Log "Loaded recovery keys for $($KeyMap.Count) computers."

    # --------------------------------------------------
    # AD-only: plain loop, no remoting, no parallelism needed
    # --------------------------------------------------
    if ($ADOnly) {
        $Results = foreach ($c in $Computers) {
            $keys = if ($KeyMap.ContainsKey($c)) { @($KeyMap[$c]) } else { @() }
            $r = New-BitLockerResult -ComputerName $c
            $r.Online     = $null
            $r.WinRM      = $null
            $r.ADKeyCount = $keys.Count
            $r.ADVerified = ($keys.Count -gt 0)      # in AD-only mode: "a key exists in AD"
            $r.ADRecoveryKeyID = @($keys | ForEach-Object { $_.ID })
            if ($IncludeRecoveryKey) {
                $r.ADRecoveryKeyPassword = @($keys | ForEach-Object { $_.Password } | Where-Object { $_ })
            }
            $r
        }
        $Results = @($Results)
        Export-ResultsSafe -Results $Results -Path $OutputPath -Mode $Mode
        Write-Log "AD-only audit complete: $($Results.Count) computers, $(@($Results | Where-Object { $_.ADKeyCount -eq 0 }).Count) with no key in AD."
        return ($Results | Select-Object -Property * -ExcludeProperty Log, PendingVerifyIds, BackupFailed)
    }

    # --------------------------------------------------
    # Batch-level -WhatIf / -Confirm
    # --------------------------------------------------
    $actions = @('back up missing recovery keys to AD')
    if ($AutoEnableBitLocker) { $actions += 'enable BitLocker on eligible devices' }
    if ($CleanupProtectors)   { $actions += 'remove duplicate recovery password protectors' }
    $DryRun = -not $PSCmdlet.ShouldProcess("$($Computers.Count) computer(s)", ($actions -join '; '))
    if ($DryRun) { Write-Log 'Report-only mode: no changes will be made on endpoints.' -Level 'WARN' }

    # --------------------------------------------------
    # Parallel endpoint processing
    # --------------------------------------------------
    $ModulePath = $MyInvocation.MyCommand.Module.Path
    if (-not $ModulePath) { $ModulePath = $PSCommandPath }

    $Options = @{
        IncludeRecoveryKey  = [bool]$IncludeRecoveryKey
        AutoEnableBitLocker = [bool]$AutoEnableBitLocker
        CleanupProtectors   = [bool]$CleanupProtectors
        DryRun              = [bool]$DryRun
        SkipPing            = [bool]$SkipPing
    }

    Write-Log "Starting parallel BitLocker processing for $($Computers.Count) computers (throttle $ThrottleLimit)."

    $total     = $Computers.Count
    $processed = 0

    $Results = @(
        $Computers | ForEach-Object -Parallel {
            Import-Module $using:ModulePath          # no -Force: once per runspace, not per computer
            $keys   = $using:KeyMap                  # shared, read-only
            $opts   = $using:Options
            $name   = $_
            $adKeys = if ($keys.ContainsKey($name)) { @($keys[$name]) } else { @() }
            Invoke-BitlockerEndpoint -ComputerName $name -ADKeys $adKeys @opts
        } -ThrottleLimit $ThrottleLimit |
        ForEach-Object {
            # Streams as each computer completes: live progress + batched logging on main thread
            $processed++
            Write-LogLines $_.Log
            Write-Progress -Activity 'BitLocker scan' -Status "$processed / $total" -PercentComplete ([int](100 * $processed / $total))
            $_
        }
    )
    Write-Progress -Activity 'BitLocker scan' -Completed

    # --------------------------------------------------
    # Post-pass: verify escrow with ONE bulk query (replaces per-computer sleeps)
    # --------------------------------------------------
    if (-not $DryRun) {
        $unverified = @($Results | Where-Object { $_.PendingVerifyIds.Count -gt 0 })

        for ($attempt = 1; $attempt -le 3 -and $unverified.Count -gt 0; $attempt++) {
            Write-Log "Verifying escrow for $($unverified.Count) computer(s) (pass $attempt/3)..."
            Start-Sleep -Seconds $VerifyDelaySeconds

            $VerifyMap = Get-ADBitLockerKeyMap @mapParams
            $stillPending = [System.Collections.Generic.List[object]]::new()

            foreach ($r in $unverified) {
                $adIds   = Get-KeyIdsFromMap -Map $VerifyMap -Computer $r.Computer
                $notYet  = @($r.PendingVerifyIds | Where-Object { $adIds -notcontains $_ })

                if ($notYet.Count -eq 0) {
                    $r.ADVerified       = ($r.BackupFailed -eq 0)
                    $r.ADKeyCount       = $adIds.Count
                    $r.ADRecoveryKeyID  = $adIds
                    if ($IncludeRecoveryKey -and $VerifyMap.ContainsKey($r.Computer)) {
                        $r.ADRecoveryKeyPassword = @($VerifyMap[$r.Computer] | ForEach-Object { $_.Password } | Where-Object { $_ })
                    }
                    $r.PendingVerifyIds = @()
                }
                else {
                    $stillPending.Add($r)
                }
            }
            $unverified = @($stillPending)
        }

        foreach ($r in $unverified) {
            $r.ADVerified = $false
            $msg = 'Backup issued but key not visible in AD after verification passes'
            $r.Error = if ($r.Error) { "$($r.Error); $msg" } else { $msg }
            Write-Log $msg -Level 'WARN' -ComputerName $r.Computer
        }
    }

    # --------------------------------------------------
    # Housekeeping: unreachable list (HashSet lookups, not -notcontains)
    # --------------------------------------------------
    $NotContactedPath = Join-Path $outDir 'NotContacted_Computers.txt'
    $existingLines    = if (Test-Path $NotContactedPath) { @(Get-Content $NotContactedPath) } else { @() }
    $existing = [System.Collections.Generic.HashSet[string]]::new([string[]]$existingLines, [StringComparer]::OrdinalIgnoreCase)

    $newUnreachable = @($Results |
        Where-Object { $_.Online -eq $false } |
        ForEach-Object { $_.Computer } |
        Where-Object { $_ -and -not $existing.Contains($_) } |
        Sort-Object -Unique)

    if ($newUnreachable.Count -gt 0) {
        Add-Content -Path $NotContactedPath -Value $newUnreachable -Encoding UTF8
        Write-Log "Added $($newUnreachable.Count) new unreachable computers to $NotContactedPath."
    }
    else {
        Write-Log 'No new unreachable computers to add.'
    }

    # --------------------------------------------------
    # Housekeeping: comment out computers that reported successfully (queue behaviour)
    # --------------------------------------------------
    if ($PSCmdlet.ParameterSetName -eq 'File' -and -not $DryRun) {
        $reported = [System.Collections.Generic.HashSet[string]]::new(
            [string[]]@($Results | Where-Object { $_.Reported } | ForEach-Object { $_.Computer }),
            [StringComparer]::OrdinalIgnoreCase)

        if ($reported.Count -gt 0) {
            $updated = foreach ($line in (Get-Content -Path $ComputerList)) {
                $t = $line.Trim()
                if ($t -and -not $t.StartsWith('#') -and $reported.Contains($t)) { "#$t" } else { $line }
            }
            $updated | Set-Content -Path $ComputerList -Encoding UTF8
            Write-Log "Commented out $($reported.Count) successfully processed computers in $ComputerList."
        }
        else {
            Write-Log 'No successfully processed computers to comment out.'
        }
    }

    # --------------------------------------------------
    # Export + return
    # --------------------------------------------------
    $ExportResults = if ($ContactedOnly) { @($Results | Where-Object { $_.Online -eq $true }) } else { $Results }

    if ($ExportResults.Count -gt 0) {
        Export-ResultsSafe -Results $ExportResults -Path $OutputPath -Mode $Mode
    }

    Write-Log ("Done. Computers: {0} | Reported: {1} | Offline: {2} | ADVerified: {3} | Errors: {4}" -f
        $Results.Count,
        @($Results | Where-Object { $_.Reported }).Count,
        @($Results | Where-Object { $_.Online -eq $false }).Count,
        @($Results | Where-Object { $_.ADVerified }).Count,
        @($Results | Where-Object { $_.Error }).Count)

    $ExportResults | Select-Object -Property * -ExcludeProperty Log, PendingVerifyIds, BackupFailed
}

Export-ModuleMember -Function `
    Invoke-BitlockerTool, `
    Invoke-BitlockerEndpoint, `
    Get-ADBitLockerKeyMap, `
    Get-BitLockerStatus, `
    Export-ResultsSafe, `
    Write-Log
