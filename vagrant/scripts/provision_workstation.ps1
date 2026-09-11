<#
.SYNOPSIS
    Automated Workstation Provisioning Script for WS01.
.DESCRIPTION
    Configures network adapter with static IP and DNS pointing to DC01,
    and joins WS01 to the corp.local Active Directory domain.
#>

[CmdletBinding()]
param(
    [string]$DomainName = "corp.local",
    [string]$DomainAdminUser = "Administrator",
    [string]$DomainAdminPassword = "Password123!",
    [string]$StaticIP = "192.168.56.20",
    [string]$DnsServerIP = "192.168.56.10"
)

$ErrorActionPreference = "Stop"

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " [PROVISION-WS] Configuring Workstation WS01 for Domain Join" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

# 1. Identify Private Network Adapter
Write-Host "[*] Configuring network adapter for domain DNS..." -ForegroundColor Yellow
$Adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
$TargetAdapter = $null

foreach ($adapter in $Adapters) {
    $ipAddresses = (Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
    if ($ipAddresses -match "^192\.168\.56\." -or $adapter.InterfaceIndex -ne 1) {
        $TargetAdapter = $adapter
        break
    }
}

if (-not $TargetAdapter) {
    $TargetAdapter = Get-NetAdapter | Where-Object { $_.InterfaceDescription -like "*#2*" -or $_.Name -like "*Ethernet 2*" } | Select-Object -First 1
}

if ($TargetAdapter) {
    Write-Host "[+] Configuring IP $StaticIP and DNS $DnsServerIP on $($TargetAdapter.Name)" -ForegroundColor Green
    try {
        $currentIP = (Get-NetIPAddress -InterfaceIndex $TargetAdapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
        if ($currentIP -notcontains $StaticIP) {
            New-NetIPAddress -InterfaceIndex $TargetAdapter.InterfaceIndex -IPAddress $StaticIP -PrefixLength 24 -ErrorAction SilentlyContinue | Out-Null
        }
        Set-DnsClientServerAddress -InterfaceIndex $TargetAdapter.InterfaceIndex -ServerAddresses ($DnsServerIP) -ErrorAction SilentlyContinue
    } catch {
        Write-Warning "Adapter configuration warning: $_"
    }
}

# 2. Wait for Domain Controller Reachability
Write-Host "[*] Testing connection to Domain Controller ($DnsServerIP)..." -ForegroundColor Yellow
$retries = 30
$connected = $false

while ($retries -gt 0) {
    try {
        $ping = Test-Connection -ComputerName $DnsServerIP -Count 1 -Quiet -ErrorAction SilentlyContinue
        if ($ping) {
            $connected = $true
            Write-Host "[+] Domain Controller reachable at $DnsServerIP" -ForegroundColor Green
            break
        }
    } catch {}
    Start-Sleep -Seconds 5
    $retries--
    Write-Host "[-] Waiting for Domain Controller ($retries attempts remaining)..." -ForegroundColor Gray
}

# 3. Check if Already Domain Joined
$currentDomain = (Get-CimInstance -ClassName Win32_ComputerSystem).Domain
if ($currentDomain -eq $DomainName) {
    Write-Host "[+] Machine is already joined to $DomainName" -ForegroundColor Green
} else {
    Write-Host "[*] Joining machine to domain: $DomainName..." -ForegroundColor Yellow
    $securePass = ConvertTo-SecureString $DomainAdminPassword -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential("$DomainName\$DomainAdminUser", $securePass)

    try {
        Add-Computer `
            -DomainName $DomainName `
            -Credential $credential `
            -OUPath "OU=Workstations,OU=Corporate,DC=corp,DC=local" `
            -Restart:$false `
            -Force
        Write-Host "[+] Successfully joined to $DomainName. Scheduled restart recommended." -ForegroundColor Green
    } catch {
        Write-Warning "Domain join attempt failed: $_"
    }
}

# 4. Configure Firewall Rules and Remote Desktop
Set-NetFirewallRule -DisplayGroup "Remote Desktop" -Enabled True -ErrorAction SilentlyContinue
Set-NetFirewallRule -DisplayGroup "Windows Remote Management" -Enabled True -ErrorAction SilentlyContinue
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False -ErrorAction SilentlyContinue

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " [PROVISION-WS] Workstation WS01 configuration complete!" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
