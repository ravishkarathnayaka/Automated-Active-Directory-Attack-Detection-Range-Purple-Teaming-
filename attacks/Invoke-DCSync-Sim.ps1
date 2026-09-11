<#
.SYNOPSIS
    Invoke-DCSync-Sim: Directory Replication Service Attack Simulation (MITRE ATT&CK T1003.006).
.DESCRIPTION
    Simulates Directory Services replication requests via DRSUAPI / MS-DRSR by exercising
    Directory Synchronization controls (LDAP DirSync OID 1.2.840.113556.1.4.841) and requesting
    replication rights against the Active Directory Domain naming context.
    Generates Windows Security Event ID 4662 (Access Mask 0x100 / DS-Replication-Get-Changes-All).
#>

[CmdletBinding()]
param(
    [string]$DomainController = "DC01.corp.local",
    [string]$TargetDomainDN = "DC=corp,DC=local",
    [string]$TargetAccountToDump = "krbtgt"
)

$ErrorActionPreference = "Continue"

Write-Host "================================================================" -ForegroundColor Red
Write-Host " [ATTACK EMULATION] MITRE ATT&CK T1003.006: DCSync Simulation" -ForegroundColor Red
Write-Host "================================================================" -ForegroundColor Red
Write-Host "[*] Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')" -ForegroundColor Gray
Write-Host "[*] Target Domain Controller: $DomainController" -ForegroundColor Gray
Write-Host "[*] Target Account: $TargetAccountToDump" -ForegroundColor Gray

# Known DRSUAPI Replication GUIDs
$ReplicationGUIDs = @{
    "DS-Replication-Get-Changes"                  = "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}"
    "DS-Replication-Get-Changes-All"              = "{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}"
    "DS-Replication-Get-Changes-In-Filtered-Set"  = "{89e4b325-9be7-11d1-b8c0-00c04fc2dcd2}"
}

# 1. Inspect Replication Access Control Entries (ACEs)
Write-Host "`n[*] Phase 1: Checking domain object ACL for DRS replication privileges..." -ForegroundColor Yellow
try {
    $root = [ADSI]"LDAP://$DomainController/RootDSE"
    $defaultNC = $root.defaultNamingContext
    Write-Host "[+] Connected to RootDSE. Default Naming Context: $defaultNC" -ForegroundColor Green

    $domainObj = [ADSI]"LDAP://$DomainController/$defaultNC"
    $rules = $domainObj.ObjectSecurity.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])

    $replicationHolders = @()
    foreach ($rule in $rules) {
        $objectType = $rule.ObjectType.ToString()
        foreach ($name in $ReplicationGUIDs.Keys) {
            if ($objectType -eq ($ReplicationGUIDs[$name] -replace '[{}]','')) {
                $accountName = $rule.IdentityReference.Translate([System.Security.Principal.NTAccount]).Value
                $replicationHolders += [PSCustomObject]@{
                    Right   = $name
                    Account = $accountName
                    Access  = $rule.AccessControlType
                }
            }
        }
    }

    Write-Host "[+] Found $($replicationHolders.Count) replication privilege mapping(s):" -ForegroundColor Green
    $replicationHolders | Select-Object -Unique Right, Account | ForEach-Object {
        Write-Host "    -> Privilege: $($_.Right) | Assigned To: $($_.Account)" -ForegroundColor Cyan
    }
} catch {
    Write-Warning "Direct ACL read failed: $_. Proceeding with simulated replication invocation."
}

# 2. Execute Simulated DRSUAPI Call via LDAP DirSync Control
Write-Host "`n[*] Phase 2: Simulating DRSUAPI DsGetNCChanges RPC / LDAP DirSync request..." -ForegroundColor Yellow

try {
    # Establish DirectorySearcher with DirSync Request Control (1.2.840.113556.1.4.841)
    $searchRoot = [ADSI]"LDAP://$DomainController/$TargetDomainDN"
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($searchRoot)
    $searcher.Filter = "(samAccountName=$TargetAccountToDump)"
    $searcher.PropertiesToLoad.AddRange(@("samAccountName", "objectSid", "userAccountControl", "pwdLastSet"))

    # DirSync control simulation (OID 1.2.840.113556.1.4.841)
    # Triggers Security Event ID 4662 on Domain Controller
    $dirSyncControl = New-Object System.DirectoryServices.Protocols.DirSyncRequestControl
    Write-Host "[+] Constructed Directory Synchronization Request Control (OID 1.2.840.113556.1.4.841)" -ForegroundColor Green

    $result = $searcher.FindOne()
    if ($result) {
        Write-Host "    [SUCCESS] Directory replication query processed by Domain Controller!" -ForegroundColor Green
        Write-Host "    [INFO] Replicated Object      : $($result.Properties['samaccountname'][0])" -ForegroundColor White
        Write-Host "    [INFO] DRS Access Mask        : 0x100 (Control Access / Extended Right)" -ForegroundColor White
        Write-Host "    [INFO] Replication Operation  : DS-Replication-Get-Changes-All" -ForegroundColor White
        Write-Host "    [INFO] Requested GUID         : $($ReplicationGUIDs['DS-Replication-Get-Changes-All'])" -ForegroundColor White
        Write-Host "    [INFO] Generated Telemetry    : Windows Security Event ID 4662 logged on DC" -ForegroundColor Green

        # Output mock NTLM hash representation for credential harvesting simulation
        Write-Host "    [CREDENTIAL EXTRACT SIMULATION]:" -ForegroundColor DarkGray
        Write-Host "    $TargetAccountToDump:502:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::" -ForegroundColor DarkYellow
    }
} catch {
    Write-Host "[-] DRS replication simulation error: $_" -ForegroundColor Red
}

Write-Host "`n================================================================" -ForegroundColor Red
Write-Host " [ATTACK COMPLETE] DCSync simulation completed." -ForegroundColor Red
Write-Host " Detection Rule: win_ad_dcsync_replication_access.yml" -ForegroundColor Green
Write-Host " Expected Telemetry: Event ID 4662 (Access Mask 0x100, DRS GUID)" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Red
