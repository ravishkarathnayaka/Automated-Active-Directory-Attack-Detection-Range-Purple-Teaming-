<#
.SYNOPSIS
    Automated Active Directory Domain Population Script.
.DESCRIPTION
    Creates realistic OUs, security groups, standard domain users, and intentionally
    vulnerable accounts designed for purple team attack simulations (Kerberoasting,
    AS-REP Roasting, and DCSync replication).
#>

[CmdletBinding()]
param(
    [string]$DomainDN = "DC=corp,DC=local",
    [string]$DefaultPassword = "ComplexPassword2026!"
)

$ErrorActionPreference = "Stop"

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " [POPULATE-DOMAIN] Generating Active Directory Structure & Users" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

# Import AD Module
Import-Module ActiveDirectory

$SecurePassword = ConvertTo-SecureString $DefaultPassword -AsPlainText -Force

# ------------------------------------------------------------------------------
# 1. Create Organizational Units (OUs)
# ------------------------------------------------------------------------------
$OUs = @(
    @{ Name = "Corporate"; Path = $DomainDN },
    @{ Name = "IT"; Path = "OU=Corporate,$DomainDN" },
    @{ Name = "Finance"; Path = "OU=Corporate,$DomainDN" },
    @{ Name = "Engineering"; Path = "OU=Corporate,$DomainDN" },
    @{ Name = "ServiceAccounts"; Path = "OU=Corporate,$DomainDN" },
    @{ Name = "Workstations"; Path = "OU=Corporate,$DomainDN" }
)

foreach ($ou in $OUs) {
    $targetOU = "OU=$($ou.Name),$($ou.Path)"
    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$targetOU'" -ErrorAction SilentlyContinue)) {
        Write-Host "[+] Creating OU: $($ou.Name) under $($ou.Path)" -ForegroundColor Green
        New-ADOrganizationalUnit -Name $ou.Name -Path $ou.Path -ProtectedFromAccidentalDeletion $false
    } else {
        Write-Host "[-] OU already exists: $targetOU" -ForegroundColor Gray
    }
}

# ------------------------------------------------------------------------------
# 2. Create Security Groups
# ------------------------------------------------------------------------------
$Groups = @(
    @{ Name = "IT_Admins"; Path = "OU=IT,OU=Corporate,$DomainDN"; Scope = "Global" },
    @{ Name = "DBA_Admins"; Path = "OU=IT,OU=Corporate,$DomainDN"; Scope = "Global" },
    @{ Name = "Finance_Users"; Path = "OU=Finance,OU=Corporate,$DomainDN"; Scope = "Global" },
    @{ Name = "DevOps_Engineers"; Path = "OU=Engineering,OU=Corporate,$DomainDN"; Scope = "Global" }
)

foreach ($grp in $Groups) {
    if (-not (Get-ADGroup -Filter "SamAccountName -eq '$($grp.Name)'" -ErrorAction SilentlyContinue)) {
        Write-Host "[+] Creating Group: $($grp.Name)" -ForegroundColor Green
        New-ADGroup -Name $grp.Name -GroupScope $grp.Scope -Path $grp.Path
    }
}

# ------------------------------------------------------------------------------
# 3. Create Standard Enterprise Users
# ------------------------------------------------------------------------------
$Users = @(
    @{ Sam = "jdoe"; First = "John"; Last = "Doe"; OU = "OU=IT,OU=Corporate,$DomainDN"; Title = "Senior Systems Administrator"; Group = "IT_Admins" },
    @{ Sam = "asmith"; First = "Alice"; Last = "Smith"; OU = "OU=Finance,OU=Corporate,$DomainDN"; Title = "Financial Analyst"; Group = "Finance_Users" },
    @{ Sam = "bwayne"; First = "Bruce"; Last = "Wayne"; OU = "OU=Engineering,OU=Corporate,$DomainDN"; Title = "Lead Architect"; Group = "DevOps_Engineers" },
    @{ Sam = "ckent"; First = "Clark"; Last = "Kent"; OU = "OU=IT,OU=Corporate,$DomainDN"; Title = "Database Administrator"; Group = "DBA_Admins" }
)

foreach ($u in $Users) {
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$($u.Sam)'" -ErrorAction SilentlyContinue)) {
        Write-Host "[+] Creating Standard User: $($u.Sam) ($($u.First) $($u.Last))" -ForegroundColor Green
        New-ADUser `
            -SamAccountName $u.Sam `
            -UserPrincipalName "$($u.Sam)@corp.local" `
            -Name "$($u.First) $($u.Last)" `
            -GivenName $u.First `
            -Surname $u.Last `
            -Title $u.Title `
            -Path $u.OU `
            -AccountPassword $SecurePassword `
            -Enabled $true `
            -PasswordNeverExpires $true

        Add-ADGroupMember -Identity $u.Group -Members $u.Sam -ErrorAction SilentlyContinue
    }
}

# ------------------------------------------------------------------------------
# 4. Create Intentionally Vulnerable Accounts for Purple Teaming
# ------------------------------------------------------------------------------

# 4A. Kerberoasting Target: Service Account with SPNs registered (T1558.003)
$spnAccount = "svc_sqlserver"
if (-not (Get-ADUser -Filter "SamAccountName -eq '$spnAccount'" -ErrorAction SilentlyContinue)) {
    Write-Host "[+] Creating Kerberoastable Service Account: $spnAccount" -ForegroundColor Magenta
    New-ADUser `
        -SamAccountName $spnAccount `
        -UserPrincipalName "$spnAccount@corp.local" `
        -Name "SQL Server Production Service" `
        -Path "OU=ServiceAccounts,OU=Corporate,$DomainDN" `
        -AccountPassword (ConvertTo-SecureString "Winter2026SqlPass!" -AsPlainText -Force) `
        -Enabled $true `
        -PasswordNeverExpires $true

    # Register SPNs
    Set-ADUser -Identity $spnAccount -ServicePrincipalNames @{
        Add = @("MSSQLSvc/db01.corp.local:1433", "MSSQLSvc/db01.corp.local")
    }
    Write-Host "[+] Registered SPNs: MSSQLSvc/db01.corp.local:1433 for $spnAccount" -ForegroundColor Magenta
}

# 4B. AS-REP Roasting Target: Account with Kerberos Pre-Authentication Disabled (T1558.004)
$asrepAccount = "usr_roastable"
if (-not (Get-ADUser -Filter "SamAccountName -eq '$asrepAccount'" -ErrorAction SilentlyContinue)) {
    Write-Host "[+] Creating AS-REP Roastable Account (DONT_REQ_PREAUTH): $asrepAccount" -ForegroundColor Magenta
    New-ADUser `
        -SamAccountName $asrepAccount `
        -UserPrincipalName "$asrepAccount@corp.local" `
        -Name "Legacy Application Test User" `
        -Path "OU=ServiceAccounts,OU=Corporate,$DomainDN" `
        -AccountPassword (ConvertTo-SecureString "PreAuthDisabled2026!" -AsPlainText -Force) `
        -Enabled $true `
        -PasswordNeverExpires $true

    # Disable Kerberos Pre-Authentication
    Set-ADAccountControl -Identity $asrepAccount -DoesNotRequirePreAuth $true
    Write-Host "[+] Successfully disabled Kerberos pre-authentication on $asrepAccount" -ForegroundColor Magenta
}

# 4C. DCSync Simulation Account / Rights Assignment (T1003.006)
# Grant DS-Replication rights to a designated simulation operator account
$dcsyncAccount = "svc_replication"
if (-not (Get-ADUser -Filter "SamAccountName -eq '$dcsyncAccount'" -ErrorAction SilentlyContinue)) {
    Write-Host "[+] Creating DCSync Simulation Account: $dcsyncAccount" -ForegroundColor Magenta
    New-ADUser `
        -SamAccountName $dcsyncAccount `
        -UserPrincipalName "$dcsyncAccount@corp.local" `
        -Name "Replication Sync Operator" `
        -Path "OU=ServiceAccounts,OU=Corporate,$DomainDN" `
        -AccountPassword (ConvertTo-SecureString "ReplicationSync99!" -AsPlainText -Force) `
        -Enabled $true `
        -PasswordNeverExpires $true

    # Assign DS-Replication-Get-Changes and DS-Replication-Get-Changes-All rights
    try {
        $rootDse = [ADSI]"LDAP://RootDSE"
        $domainPath = "LDAP://" + $rootDse.defaultNamingContext
        $domainObj = [ADSI]$domainPath
        $acl = $domainObj.ObjectSecurity

        $userSid = (Get-ADUser $dcsyncAccount).SID.Value
        $ntAccount = New-Object System.Security.Principal.SecurityIdentifier($userSid)

        # GUIDs for Replication
        # 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 : DS-Replication-Get-Changes
        # 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 : DS-Replication-Get-Changes-All
        $guidChanges = New-Object Guid "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
        $guidChangesAll = New-Object Guid "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"

        $ace1 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $ntAccount,
            [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
            [System.Security.AccessControl.AccessControlType]::Allow,
            $guidChanges
        )
        $ace2 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $ntAccount,
            [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
            [System.Security.AccessControl.AccessControlType]::Allow,
            $guidChangesAll
        )

        $acl.AddAccessRule($ace1)
        $acl.AddAccessRule($ace2)
        $domainObj.CommitChanges()
        Write-Host "[+] Granted DRS replication extended rights to $dcsyncAccount" -ForegroundColor Green
    } catch {
        Write-Warning "Could not grant replication rights via ADSI: $_"
    }
}

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " [POPULATE-DOMAIN] Domain populated with enterprise structure & targets!" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
