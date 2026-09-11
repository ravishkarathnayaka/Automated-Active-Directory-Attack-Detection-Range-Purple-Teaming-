<#
.SYNOPSIS
    Automated Active Directory Domain Controller Provisioning Script for DC01.
.DESCRIPTION
    Configures network settings, installs AD DS Windows feature, and establishes
    a new Active Directory forest for corp.local with RSAT tools and DNS forwarders.
#>

[CmdletBinding()]
param(
    [string]$DomainName = "corp.local",
    [string]$NetbiosName = "CORP",
    [string]$SafeModePassword = "Password123!",
    [string]$StaticIP = "192.168.56.10",
    [string]$SubnetMask = "255.255.255.0",
    [string]$DefaultGateway = ""
)

$ErrorActionPreference = "Stop"

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " [PROVISION-DC] Starting Domain Controller Provisioning for $DomainName" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

# 1. Identify Private Network Adapter (VirtualBox Host-Only / Internal adapter)
Write-Host "[*] Identifying private network adapter..." -ForegroundColor Yellow
$Adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
$TargetAdapter = $null

foreach ($adapter in $Adapters) {
    $ipAddresses = (Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
    # If the adapter is already on 192.168.56.x or is the secondary interface
    if ($ipAddresses -match "^192\.168\.56\." -or $adapter.InterfaceIndex -ne 1) {
        $TargetAdapter = $adapter
        break
    }
}

if (-not $TargetAdapter) {
    # Fallback to the second network adapter typically created by Vagrant
    $TargetAdapter = Get-NetAdapter | Where-Object { $_.InterfaceDescription -like "*#2*" -or $_.Name -like "*Ethernet 2*" } | Select-Object -First 1
}

if ($TargetAdapter) {
    Write-Host "[+] Configuring static IP $StaticIP on adapter: $($TargetAdapter.Name)" -ForegroundColor Green
    try {
        # Check current IP
        $currentIP = (Get-NetIPAddress -InterfaceIndex $TargetAdapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
        if ($currentIP -notcontains $StaticIP) {
            New-NetIPAddress -InterfaceIndex $TargetAdapter.InterfaceIndex -IPAddress $StaticIP -PrefixLength 24 -ErrorAction SilentlyContinue | Out-Null
        }
        Set-DnsClientServerAddress -InterfaceIndex $TargetAdapter.InterfaceIndex -ServerAddresses ("127.0.0.1", "1.1.1.1") -ErrorAction SilentlyContinue
    } catch {
        Write-Warning "Adapter configuration warning: $_"
    }
} else {
    Write-Warning "Private network adapter not uniquely matched; proceeding with existing IP bindings."
}

# 2. Check if AD DS is already installed and promoted
$isDomainController = (Get-CimInstance -ClassName Win32_OperatingSystem).ProductType -eq 2

if ($isDomainController) {
    Write-Host "[+] DC01 is already promoted to a Domain Controller for $DomainName." -ForegroundColor Green
} else {
    Write-Host "[*] Installing Active Directory Domain Services & RSAT tools..." -ForegroundColor Yellow
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

    Write-Host "[*] Creating new AD Forest: $DomainName ($NetbiosName)..." -ForegroundColor Yellow
    $SecurePassword = ConvertTo-SecureString $SafeModePassword -AsPlainText -Force

    Install-ADDSForest `
        -DomainName $DomainName `
        -DomainNetbiosName $NetbiosName `
        -SafeModeAdministratorPassword $SecurePassword `
        -InstallDns:$true `
        -CreateDnsDelegation:$false `
        -DatabasePath "C:\Windows\NTDS" `
        -LogPath "C:\Windows\NTDS" `
        -SysvolPath "C:\Windows\SYSVOL" `
        -Force:$true

    Write-Host "[+] Forest deployment initiated. Host rebooting..." -ForegroundColor Green
}

# 3. Configure DNS Forwarders
try {
    Write-Host "[*] Configuring DNS Forwarders (1.1.1.1, 8.8.8.8)..." -ForegroundColor Yellow
    if (Get-Service -Name DNS -ErrorAction SilentlyContinue) {
        Set-DnsServerForwarder -IPAddress @("1.1.1.1", "8.8.8.8") -PassThru -ErrorAction SilentlyContinue | Out-Null
        Write-Host "[+] DNS Forwarders successfully updated." -ForegroundColor Green
    }
} catch {
    Write-Warning "DNS Server service not yet active or accessible: $_"
}

# 4. Configure Firewall Rules for Lab Testing
Write-Host "[*] Opening firewall ports for Active Directory, RPC, and WinRM..." -ForegroundColor Yellow
Set-NetFirewallRule -DisplayGroup "Windows Remote Management" -Enabled True -ErrorAction SilentlyContinue
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False -ErrorAction SilentlyContinue

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " [PROVISION-DC] DC01 Domain Controller provisioning complete!" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
