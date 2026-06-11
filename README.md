# ADUserAudit

ADUserAudit is a practical, read-only Active Directory audit script for internal IT teams and sysadmins.
It checks common account hygiene issues and gives you results both on-screen and in CSV format for follow-up.

## What It Does

- Finds stale accounts with no logon in a configurable number of days
- Finds disabled users that are still assigned to AD groups
- Reports accounts with expired passwords or passwords nearing expiry (configurable threshold)
- Shows last logon timestamp per user
- Outputs console-readable tables and a single exportable CSV

## Who It Is For

- Internal IT operations teams
- Active Directory administrators
- Sysadmins doing recurring access hygiene checks

## Prerequisites

- Windows host with RSAT installed
- PowerShell ActiveDirectory module available
- Read permissions in Active Directory for user, group membership, and policy data

## Script

- `ADUserAudit.ps1`

No third-party modules or dependencies are required.

## Usage

Run with defaults:

```powershell
.\ADUserAudit.ps1
```

Run with custom stale threshold and near-expiry window:

```powershell
.\ADUserAudit.ps1 -StaleDays 120 -PasswordExpiryDays 21
```

Run scoped to a specific OU:

```powershell
.\ADUserAudit.ps1 -SearchBase "OU=Users,DC=corp,DC=example,DC=com"
```

Set a custom CSV output path:

```powershell
.\ADUserAudit.ps1 -CsvPath "C:\Reports\ADUserAudit_Weekly.csv"
```

## Parameters

- `-StaleDays` (default: `90`): account considered stale if last logon is older than this
- `-PasswordExpiryDays` (default: `14`): include users expiring within this window
- `-SearchBase` (default: empty): optional OU/container distinguished name to scope the query
- `-CsvPath` (default: timestamped file in current folder): output path for CSV report

## Sample Output

Console sections:

```text
=== Stale Accounts (>90 days) ===
SamAccountName Name          Enabled LastLogonDate         DaysSinceLastLogon Details
-------------- ----          ------- -------------         ------------------ -------
jdoe           John Doe      True    1/12/2026 9:11:22 AM 150                No logon in more than 90 days
svc_backup     Backup Service False                        	                 No lastLogonTimestamp value found

=== Disabled Users Still in Groups ===
SamAccountName Name          GroupCount Groups
-------------- ----          ---------- ------
old.user       Old User      2          HR-Shared; Legacy-App-Users

=== Password Expired or Near Expiry (<= 14 days) ===
SamAccountName Name          Status     PasswordExpiryDate    DaysToExpiry
-------------- ----          ------     ------------------    ------------
asmith         Alice Smith   NearExpiry 6/18/2026 10:00:00 AM 7
bking          Bob King      Expired    6/01/2026 8:00:00 AM -10

=== Last Logon Timestamp Per User ===
SamAccountName Name          Enabled LastLogonDate
-------------- ----          ------- -------------
jdoe           John Doe      True    1/12/2026 9:11:22 AM
old.user       Old User      False   10/03/2025 2:44:51 PM
```

CSV export message:

```text
CSV exported: .\ADUserAudit_20260611_081530.csv
Audit complete. Total rows exported: 425
No changes were made to Active Directory.
```

## Read-Only Safety Note

This tool is read-only. It does not enable, disable, move, modify, or delete any Active Directory object.
It only queries AD and writes output to the console and a CSV file.

## Error Handling

The script handles these common failure scenarios gracefully:

- ActiveDirectory module not installed or unavailable
- Insufficient directory permissions
- Invalid or inaccessible `-SearchBase` OU scope
- CSV export write failures

Each failure path returns actionable error or warning messages so you can correct environment or permission issues quickly.

## CI Workflow

GitHub Actions workflow: `.github/workflows/powershell-ci.yml`

On push and pull request, it runs on a Windows runner and:

- Installs `PSScriptAnalyzer`
- Lints `ADUserAudit.ps1`
- Runs a script parse check to catch syntax errors early

## License

MIT. See the `LICENSE` file.
