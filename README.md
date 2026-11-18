# BitlockerRecoveryTools

A PowerShell module that audits BitLocker status and recovery key escrow across Active Directory computers, and can optionally remediate problems (enable BitLocker, back up missing recovery keys, remove duplicate protectors). Results are returned to the pipeline and exported to CSV.

**Version:** 2.0 | **Author:** Bill Galway

## Requirements

| Requirement | Notes |
|---|---|
| PowerShell 7+ | Uses `ForEach-Object -Parallel`. Windows PowerShell 5.1 is not supported. |
| `ActiveDirectory` module (RSAT) | Needed only in the session you run the tool from, not on targets. |
| WinRM enabled on targets | One PSSession is opened per computer. |
| BitLocker cmdlets on targets | `Get-BitLockerVolume`, `Backup-BitLockerKeyProtector`, etc. |
| AD read access to recovery objects | To read `msFVE-RecoveryPassword` (for `-IncludeRecoveryKey`) you need the delegated permission on that attribute. |
| Rights to remote into targets | Needed for remote enable, backup and cleanup. |

Only the `C:` volume is inspected.

## Installation

Copy the module folder somewhere on your module path, or import it by path:

```powershell
Import-Module C:\path\to\BitlockerRecoveryTools\BitlockerRecoveryTools.psm1
```

The module locates its own path to load itself into parallel runspaces, so it no longer needs to live at a hardcoded location.

## Quick start

```powershell
# Report on all laptops in one OU
Invoke-BitlockerTool -Filter "Name -like 'LT-*'" -SearchBase "OU=Laptops,DC=corp,DC=local"

# AD-only audit: no endpoint contact, finishes in seconds
Invoke-BitlockerTool -ADOnly

# Process a queue file (successfully reported machines are commented out afterwards)
Invoke-BitlockerTool -ComputerList .\queue.txt

# See what remediation would do, without changing anything
Invoke-BitlockerTool -AutoEnableBitLocker -CleanupProtectors -WhatIf

# Full remediation, overwrite the report, include keys, no prompt
Invoke-BitlockerTool -Filter "Name -like 'LT-*'" -AutoEnableBitLocker -CleanupProtectors `
    -IncludeRecoveryKey -Mode Overwrite -Confirm:$false
```

## Parameters

| Parameter | Description |
|---|---|
| `-Filter` | `Get-ADComputer -Filter` syntax (not LDAP). Default `*`. |
| `-ComputerList` | Text file, one name per line. Lines starting with `#` are ignored. Mutually exclusive with `-Filter`. |
| `-SearchBase` | OU distinguished name. Limits both the computer query and the recovery-key query. Recommended when you only need part of the domain. |
| `-Server` | Domain controller to use for all AD queries. Using one DC avoids replication surprises during verification. |
| `-OutputPath` | CSV path. Default `.\BitLocker_Report.csv`. |
| `-Mode` | `Append` (default) or `Overwrite`. |
| `-ThrottleLimit` | Max parallel runspaces. Default 50. |
| `-IncludeRecoveryKey` | Include recovery passwords in output. **They are exported in plaintext.** |
| `-ADOnly` | Audit recovery key presence in AD only. No endpoint contact. |
| `-AutoEnableBitLocker` | Enable BitLocker where protection is Off, TPM is present and ready, and no recovery password protector exists. |
| `-CleanupProtectors` | Remove duplicate recovery password protectors (see below). |
| `-ContactedOnly` | Export only computers that answered ping. |
| `-SkipPing` | Skip ICMP and go straight to WinRM, for networks that block ping. |
| `-VerifyDelaySeconds` | Wait before each escrow verification pass (up to 3 passes). Default 5. |
| `-LogPath` | Log file. Default `.\BitlockerTools.log`. |
| `-WhatIf` / `-Confirm` | See "Safety model". |

## How it works

1. **Build the computer list** from AD or a file.
2. **Load AD once.** A single query retrieves every `msFVE-RecoveryInformation` object and builds a hashtable keyed by computer name. Each entry holds the protector GUID (parsed from the object's DN), creation time, and (only with `-IncludeRecoveryKey`) the password.
3. **Process endpoints in parallel.** Each runspace runs `Invoke-BitlockerEndpoint`, which does one ping, opens one PSSession, takes a single snapshot (protection state, encryption %, recovery protectors, TPM), and reuses the session for any remediation. Escrow is checked by comparing local protector GUIDs against the in-memory AD data, so workers make no AD calls.
4. **Verify escrow in one post-pass.** If any keys were backed up, one bulk AD query (up to 3 passes) confirms they arrived. `ADVerified` is set from that data.
5. **Housekeeping and export.** Newly unreachable computers are appended to `NotContacted_Computers.txt` next to the CSV, queue files are updated, and the CSV is written.

### Remediation order per computer

1. Enable BitLocker (if `-AutoEnableBitLocker` and eligible), then re-read state over the same session.
2. Cleanup (if `-CleanupProtectors` and more than one recovery password protector exists).
3. Back up any remaining protector that is not yet in AD.

### Cleanup rules

Cleanup keeps **one** protector that is already escrowed in AD (the one whose AD object is newest) and removes the rest. If none of a machine's protectors is escrowed yet, cleanup is skipped for that machine and its keys are backed up instead; the next run cleans up. A protector that is the only copy of the key is never removed.

> Windows does not expose a creation time on `KeyProtector` objects, so "newest" is determined from AD, not from the endpoint.

## Safety model

- `-WhatIf` and `-Confirm` are evaluated **once for the whole batch**, not per computer.
- If the batch is declined or `-WhatIf` is used, the run continues in **report-only mode**: nothing is changed on endpoints, and the NotContacted and queue files are not rewritten.
- `-Confirm` prompts only when passed explicitly (the cmdlet uses the default confirm impact).
- Backing up missing keys to AD is always part of a normal run. Use `-WhatIf` or `-ADOnly` for a purely read-only pass.
- `-IncludeRecoveryKey` places plaintext recovery passwords in the CSV and in memory. Protect the output file accordingly.

## Output

Objects are returned to the pipeline and exported to CSV with these columns:

`Timestamp, Computer, Online, WinRM, Reported, Volume, Protected, Percent, ADRecoveryKeyID, ADRecoveryKeyPassword, LocalKeySource, RecoveryKey, RecoveryPassword, MachineKeyCount, ADKeyCount, ADVerified, TPMPresent, TPMReady, CanEnableBitLocker, ActivatedBitlocker, Error`

Notes on specific columns:

- **Online / WinRM:** `Online` is the ping result (or true if `-SkipPing` and the session opened). `WinRM` is whether a session was established. Both are blank in `-ADOnly` mode.
- **Reported:** true when a full snapshot was obtained.
- **ADVerified:** true when every recovery protector on the machine is present in AD. In `-ADOnly` mode it means "at least one key exists in AD".
- **ADRecoveryKeyID / RecoveryKey:** protector GUIDs, comma-joined when there are several.
- **Error:** the failure reason (offline, WinRM unavailable, backup failed, key not visible in AD after verification).

## Queue file behavior

With `-ComputerList`, computers that **reported successfully** are commented out with a leading `#`, so re-running the same file only retries the rest. Machines that were online but failed (for example, WinRM errors) stay in the queue.

## Public functions

| Function | Purpose |
|---|---|
| `Invoke-BitlockerTool` | Main entry point. |
| `Invoke-BitlockerEndpoint` | Per-computer worker. Called inside parallel runspaces; also usable on its own. |
| `Get-ADBitLockerKeyMap` | One bulk AD query returning the computer-to-keys hashtable. |
| `Get-BitLockerStatus` | Opens a session and returns a BitLocker/TPM snapshot for one computer. |
| `Export-ResultsSafe` | CSV export helper (flattens arrays, supports append). |
| `Write-Log` | Console and file logging. |

## Upgrading from v1.0

- The CSV gained an `Error` column. Run once with `-Mode Overwrite`, or move the old report aside.
- These exports were removed; their logic now lives in `Invoke-BitlockerEndpoint`: `Test-ComputerConnectivity`, `Get-CVolumeRecoveryKeyCount`, `Enable-BitLockerRemote`, `Remove-ExtraBitLockerProtectors`, `Backup-BitLocker`, `Get-ADBitLockerRecoveryKeys`. Update any outside scripts that call them.
- `-ThrottleLimit` now defaults to 50 (was 20).
- Queue files are updated only for computers that reported, not merely those that answered ping.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `Offline: ping failed` for machines you know are up | ICMP is blocked. Use `-SkipPing`. |
| `WinRM unavailable` | WinRM not enabled, firewall, or no rights on the target. |
| Passwords are empty with `-IncludeRecoveryKey` | Your account lacks read permission on `msFVE-RecoveryPassword`. |
| `Backup issued but key not visible in AD` | Replication lag between DCs. Pass `-Server` so every query hits one DC, or increase `-VerifyDelaySeconds`. |
| CSV append fails or columns misalign | Existing file was written by v1.0. Use `-Mode Overwrite`. |
| Cleanup did nothing on a machine | No protector was escrowed yet. Keys were backed up; run again to clean up. |

## Known limitations

- Only the `C:` volume is handled.
- Computer names are used as hashtable keys, so duplicate computer CNs in different OUs would collide (rare).
- `Enable-BitLocker` is called with `-RecoveryPasswordProtector` only. Validate on a test machine before broad use of `-AutoEnableBitLocker`; some environments also need `-TpmProtector`.
- The domain-wide key query returns all recovery objects. Use `-SearchBase` to scope it on very large directories.
