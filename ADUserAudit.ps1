<#
.SYNOPSIS
Read-only Active Directory user audit script for stale accounts, disabled users in groups,
password expiry checks, and last logon reporting.

.DESCRIPTION
This script is designed for IT operations teams to quickly identify common AD hygiene issues.
It only reads from Active Directory and does not make any changes.
#>

[CmdletBinding()]
param(
    # Users with no logon newer than this many days are reported as stale.
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 3650)]
    [int]$StaleDays = 90,

    # Users whose passwords expire within this many days are reported as near expiry.
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 365)]
    [int]$PasswordExpiryDays = 14,

    # Optional OU or container DN to limit scope. Leave empty for full domain.
    [Parameter(Mandatory = $false)]
    [string]$SearchBase = "",

    # Output CSV path. Defaults to timestamped filename in current folder.
    [Parameter(Mandatory = $false)]
    [string]$CsvPath = ".\ADUserAudit_{0}.csv" -f (Get-Date -Format "yyyyMMdd_HHmmss")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-ActiveDirectoryModule {
    <#
    .SYNOPSIS
    Ensures the ActiveDirectory module is available and loaded.
    #>
    try {
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            throw "The ActiveDirectory module is not installed. Install RSAT AD tools and try again."
        }

        Import-Module ActiveDirectory -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Error "ActiveDirectory module check failed: $($_.Exception.Message)"
        return $false
    }

    return $true
}

function Convert-LastLogonTimestamp {
    <#
    .SYNOPSIS
    Converts AD lastLogonTimestamp (FileTime) to local DateTime.
    #>
    param(
        [Parameter(Mandatory = $false)]
        [Nullable[long]]$LastLogonTimestamp
    )

    if (-not $LastLogonTimestamp -or $LastLogonTimestamp -le 0) {
        return $null
    }

    try {
        return [DateTime]::FromFileTimeUtc([int64]$LastLogonTimestamp).ToLocalTime()
    }
    catch {
        return $null
    }
}

function Get-DomainPasswordPolicy {
    <#
    .SYNOPSIS
    Retrieves default domain password policy for expiry calculations.
    #>
    try {
        return Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
    }
    catch {
        Write-Warning "Could not read domain password policy. Password expiry checks may be incomplete. $($_.Exception.Message)"
        return $null
    }
}

function Get-ScopedAdUsers {
    <#
    .SYNOPSIS
    Reads user objects and required properties from AD.
    #>
    param(
        [Parameter(Mandatory = $false)]
        [string]$ScopeSearchBase
    )

    $properties = @(
        'SamAccountName',
        'Name',
        'Enabled',
        'DistinguishedName',
        'lastLogonTimestamp',
        'PasswordLastSet',
        'PasswordNeverExpires',
        'PasswordExpired',
        'whenCreated'
    )

    $queryParams = @{
        Filter     = '*'
        Properties = $properties
        ErrorAction = 'Stop'
    }

    if (-not [string]::IsNullOrWhiteSpace($ScopeSearchBase)) {
        $queryParams['SearchBase'] = $ScopeSearchBase
    }

    try {
        return Get-ADUser @queryParams
    }
    catch {
        throw "Failed to query AD users. Check OU scope and read permissions. $($_.Exception.Message)"
    }
}

function Invoke-StaleAccountAudit {
    <#
    .SYNOPSIS
    Finds user accounts that have not logged on within the configured threshold.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Users,

        [Parameter(Mandatory = $true)]
        [int]$ThresholdDays
    )

    $cutoffDate = (Get-Date).AddDays(-$ThresholdDays)
    $results = foreach ($user in $Users) {
        $lastLogonDate = Convert-LastLogonTimestamp -LastLogonTimestamp $user.lastLogonTimestamp

        if (-not $lastLogonDate -or $lastLogonDate -lt $cutoffDate) {
            [PSCustomObject]@{
                AuditType         = 'StaleAccount'
                SamAccountName    = $user.SamAccountName
                Name              = $user.Name
                Enabled           = $user.Enabled
                DistinguishedName = $user.DistinguishedName
                LastLogonDate     = $lastLogonDate
                DaysSinceLastLogon = if ($lastLogonDate) { [int]((Get-Date) - $lastLogonDate).TotalDays } else { $null }
                Details           = if ($lastLogonDate) { "No logon in more than $ThresholdDays days" } else { 'No lastLogonTimestamp value found' }
            }
        }
    }

    return @($results)
}

function Invoke-DisabledUsersWithGroupAudit {
    <#
    .SYNOPSIS
    Finds disabled accounts that still have direct AD group memberships.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Users
    )

    $disabledUsers = $Users | Where-Object { $_.Enabled -eq $false }
    $results = New-Object System.Collections.Generic.List[object]

    foreach ($user in $disabledUsers) {
        try {
            $groups = Get-ADPrincipalGroupMembership -Identity $user.DistinguishedName -ErrorAction Stop |
                Where-Object { $_.Name -ne 'Domain Users' }

            if ($groups) {
                $groupNames = $groups.Name | Sort-Object
                $lastLogonDate = Convert-LastLogonTimestamp -LastLogonTimestamp $user.lastLogonTimestamp

                $results.Add([PSCustomObject]@{
                    AuditType         = 'DisabledUserInGroups'
                    SamAccountName    = $user.SamAccountName
                    Name              = $user.Name
                    Enabled           = $user.Enabled
                    DistinguishedName = $user.DistinguishedName
                    LastLogonDate     = $lastLogonDate
                    GroupCount        = $groupNames.Count
                    Groups            = ($groupNames -join '; ')
                    Details           = 'Disabled account still has direct group memberships'
                })
            }
        }
        catch {
            Write-Warning "Could not read group memberships for $($user.SamAccountName): $($_.Exception.Message)"
        }
    }

    return @($results)
}

function Invoke-PasswordExpiryAudit {
    <#
    .SYNOPSIS
    Finds expired and near-expiry passwords based on domain policy and threshold.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Users,

        [Parameter(Mandatory = $false)]
        [object]$PasswordPolicy,

        [Parameter(Mandatory = $true)]
        [int]$NearExpiryDays
    )

    if (-not $PasswordPolicy -or -not $PasswordPolicy.MaxPasswordAge -or $PasswordPolicy.MaxPasswordAge.Ticks -eq 0) {
        Write-Warning 'Password policy is missing or does not enforce expiry. Skipping password expiry audit.'
        return @()
    }

    $maxPasswordAge = $PasswordPolicy.MaxPasswordAge
    $now = Get-Date

    $results = foreach ($user in $Users) {
        if ($user.PasswordNeverExpires -or -not $user.PasswordLastSet) {
            continue
        }

        $expiryDate = $user.PasswordLastSet + $maxPasswordAge
        $daysToExpiry = [int][Math]::Floor(($expiryDate - $now).TotalDays)

        if ($user.PasswordExpired -or $daysToExpiry -le 0 -or $daysToExpiry -le $NearExpiryDays) {
            $status = if ($user.PasswordExpired -or $daysToExpiry -le 0) { 'Expired' } else { 'NearExpiry' }
            $lastLogonDate = Convert-LastLogonTimestamp -LastLogonTimestamp $user.lastLogonTimestamp

            [PSCustomObject]@{
                AuditType          = 'PasswordExpiry'
                Status             = $status
                SamAccountName     = $user.SamAccountName
                Name               = $user.Name
                Enabled            = $user.Enabled
                DistinguishedName  = $user.DistinguishedName
                PasswordLastSet    = $user.PasswordLastSet
                PasswordExpiryDate = $expiryDate
                DaysToExpiry       = $daysToExpiry
                LastLogonDate      = $lastLogonDate
                Details            = if ($status -eq 'Expired') { 'Password is expired' } else { "Password expires within $NearExpiryDays days" }
            }
        }
    }

    return @($results)
}

function Invoke-LastLogonAudit {
    <#
    .SYNOPSIS
    Generates a per-user last logon timestamp report.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Users
    )

    $results = foreach ($user in $Users) {
        $lastLogonDate = Convert-LastLogonTimestamp -LastLogonTimestamp $user.lastLogonTimestamp

        [PSCustomObject]@{
            AuditType          = 'LastLogon'
            SamAccountName     = $user.SamAccountName
            Name               = $user.Name
            Enabled            = $user.Enabled
            DistinguishedName  = $user.DistinguishedName
            LastLogonDate      = $lastLogonDate
            LastLogonAvailable = [bool]$lastLogonDate
            Details            = if ($lastLogonDate) { 'Last logon timestamp available' } else { 'No lastLogonTimestamp value found' }
        }
    }

    return @($results)
}

function Write-AuditSection {
    <#
    .SYNOPSIS
    Writes audit results to console as readable tables.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $true)]
        [object[]]$Rows,

        [Parameter(Mandatory = $true)]
        [string[]]$Columns
    )

    Write-Host "`n=== $Title ===" -ForegroundColor Cyan

    if (-not $Rows -or $Rows.Count -eq 0) {
        Write-Host 'No results.' -ForegroundColor Green
        return
    }

    $Rows | Select-Object $Columns | Format-Table -AutoSize
}

function Export-AuditCsv {
    <#
    .SYNOPSIS
    Exports all audit rows to a single CSV for downstream reporting.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Rows,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {
        $Rows | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
        Write-Host "`nCSV exported: $Path" -ForegroundColor Yellow
    }
    catch {
        Write-Warning "Failed to export CSV to $Path. $($_.Exception.Message)"
    }
}

function Start-ADUserAudit {
    <#
    .SYNOPSIS
    Main entry point that orchestrates all audits and output.
    #>

    if (-not (Test-ActiveDirectoryModule)) {
        return
    }

    Write-Host 'Starting AD user audit (read-only)...' -ForegroundColor Yellow

    try {
        $users = Get-ScopedAdUsers -ScopeSearchBase $SearchBase
    }
    catch {
        Write-Error $_.Exception.Message
        return
    }

    if (-not $users -or $users.Count -eq 0) {
        Write-Warning 'No users found for the provided scope. Nothing to audit.'
        return
    }

    $passwordPolicy = Get-DomainPasswordPolicy

    $staleResults = Invoke-StaleAccountAudit -Users $users -ThresholdDays $StaleDays
    $disabledInGroupsResults = Invoke-DisabledUsersWithGroupAudit -Users $users
    $passwordResults = Invoke-PasswordExpiryAudit -Users $users -PasswordPolicy $passwordPolicy -NearExpiryDays $PasswordExpiryDays
    $lastLogonResults = Invoke-LastLogonAudit -Users $users

    Write-AuditSection -Title "Stale Accounts (>$StaleDays days)" -Rows $staleResults -Columns @(
        'SamAccountName',
        'Name',
        'Enabled',
        'LastLogonDate',
        'DaysSinceLastLogon',
        'Details'
    )

    Write-AuditSection -Title 'Disabled Users Still in Groups' -Rows $disabledInGroupsResults -Columns @(
        'SamAccountName',
        'Name',
        'GroupCount',
        'Groups'
    )

    Write-AuditSection -Title "Password Expired or Near Expiry (<= $PasswordExpiryDays days)" -Rows $passwordResults -Columns @(
        'SamAccountName',
        'Name',
        'Status',
        'PasswordExpiryDate',
        'DaysToExpiry'
    )

    Write-AuditSection -Title 'Last Logon Timestamp Per User' -Rows $lastLogonResults -Columns @(
        'SamAccountName',
        'Name',
        'Enabled',
        'LastLogonDate'
    )

    $allResults = @($staleResults + $disabledInGroupsResults + $passwordResults + $lastLogonResults)
    Export-AuditCsv -Rows $allResults -Path $CsvPath

    Write-Host "`nAudit complete. Total rows exported: $($allResults.Count)" -ForegroundColor Green
    Write-Host 'No changes were made to Active Directory.' -ForegroundColor Green
}

Start-ADUserAudit
