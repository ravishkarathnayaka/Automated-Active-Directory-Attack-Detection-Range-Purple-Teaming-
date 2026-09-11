<#
.SYNOPSIS
    Automated Telemetry Installation and Configuration Script.
.DESCRIPTION
    Installs Sysmon, applies Advanced Windows Audit Policies, enables PowerShell
    Script Block & Process Command Line auditing, and configures Winlogbeat log forwarding.
#>

[CmdletBinding()]
param(
    [string]$SysmonConfigPath = "C:\vagrant\telemetry\sysmonconfig.xml",
    [string]$AuditPolBatchPath = "C:\vagrant\telemetry\auditpol_commands.bat",
    [string]$WinlogbeatConfigPath = "C:\vagrant\telemetry\winlogbeat.yml",
    [string]$ToolsDir = "C:\Tools"
)

$ErrorActionPreference = "Continue"

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " [INSTALL-TELEMETRY] Deploying Sysmon, Audit Policies & Winlogbeat" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

# Ensure Tools directory exists
if (-not (Test-Path $ToolsDir)) {
    New-Item -ItemType Directory -Path $ToolsDir -Force | Out-Null
}

# ------------------------------------------------------------------------------
# 1. Apply Advanced Windows Audit Policies via Batch Script
# ------------------------------------------------------------------------------
Write-Host "[*] Applying Advanced Windows Audit Policies..." -ForegroundColor Yellow
if (Test-Path $AuditPolBatchPath) {
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$AuditPolBatchPath`"" -Wait -NoNewWindow
    Write-Host "[+] Audit policies applied successfully." -ForegroundColor Green
} else {
    Write-Warning "Audit policy batch script not found at $AuditPolBatchPath"
}

# ------------------------------------------------------------------------------
# 2. Enable Detailed Command Line Logging (Event ID 4688) & PowerShell Logging
# ------------------------------------------------------------------------------
Write-Host "[*] Enabling Process Creation Command Line Auditing in Registry..." -ForegroundColor Yellow
$regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
Set-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord -Force
Write-Host "[+] ProcessCreationIncludeCmdLine_Enabled set to 1" -ForegroundColor Green

Write-Host "[*] Enabling PowerShell Script Block & Module Logging..." -ForegroundColor Yellow
$psAuditPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (-not (Test-Path $psAuditPath)) {
    New-Item -Path $psAuditPath -Force | Out-Null
}
Set-ItemProperty -Path $psAuditPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force

$psModulePath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
if (-not (Test-Path $psModulePath)) {
    New-Item -Path $psModulePath -Force | Out-Null
}
Set-ItemProperty -Path $psModulePath -Name "EnableModuleLogging" -Value 1 -Type DWord -Force

# ------------------------------------------------------------------------------
# 3. Install Microsoft Sysmon with Modular Configuration
# ------------------------------------------------------------------------------
Write-Host "[*] Installing Microsoft Sysmon..." -ForegroundColor Yellow
$sysmonExe = Join-Path $ToolsDir "Sysmon64.exe"

# If Sysmon64.exe is not present, download it
if (-not (Test-Path $sysmonExe)) {
    Write-Host "[-] Sysmon not found locally. Downloading Sysmon from Microsoft Sysinternals..." -ForegroundColor Yellow
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $zipPath = Join-Path $ToolsDir "Sysmon.zip"
    try {
        Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile $zipPath -UseBasicParsing
        Expand-Archive -Path $zipPath -DestinationPath $ToolsDir -Force
        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Warning "Could not download Sysmon from internet: $_"
    }
}

if (Test-Path $sysmonExe) {
    if (Test-Path $SysmonConfigPath) {
        Write-Host "[+] Installing Sysmon with config: $SysmonConfigPath" -ForegroundColor Green
        Start-Process -FilePath $sysmonExe -ArgumentList "-accepteula -i `"$SysmonConfigPath`"" -Wait -NoNewWindow
    } else {
        Write-Host "[+] Installing Sysmon with default configuration" -ForegroundColor Green
        Start-Process -FilePath $sysmonExe -ArgumentList "-accepteula -i" -Wait -NoNewWindow
    }
} else {
    Write-Warning "Sysmon executable could not be resolved. Skipping Sysmon service installation."
}

# ------------------------------------------------------------------------------
# 4. Install and Configure Winlogbeat
# ------------------------------------------------------------------------------
Write-Host "[*] Setting up Winlogbeat for event forwarding..." -ForegroundColor Yellow
$winlogbeatDir = Join-Path $ToolsDir "winlogbeat"

if (-not (Test-Path $winlogbeatDir)) {
    $winlogbeatZip = Join-Path $ToolsDir "winlogbeat.zip"
    $winlogbeatUrl = "https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-8.11.3-windows-x86_64.zip"
    try {
        Write-Host "[-] Downloading Winlogbeat 8.11.3..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri $winlogbeatUrl -OutFile $winlogbeatZip -UseBasicParsing
        Expand-Archive -Path $winlogbeatZip -DestinationPath $ToolsDir -Force
        $extractedDir = Get-ChildItem -Path $ToolsDir -Directory -Filter "winlogbeat-*" | Select-Object -First 1
        if ($extractedDir) {
            Rename-Item -Path $extractedDir.FullName -NewName "winlogbeat"
        }
        Remove-Item $winlogbeatZip -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Warning "Could not download Winlogbeat: $_"
    }
}

if (Test-Path $winlogbeatDir) {
    if (Test-Path $WinlogbeatConfigPath) {
        Copy-Item -Path $WinlogbeatConfigPath -Destination (Join-Path $winlogbeatDir "winlogbeat.yml") -Force
        Write-Host "[+] Configured winlogbeat.yml" -ForegroundColor Green
    }
    
    # Register Winlogbeat service if script exists
    $installServiceScript = Join-Path $winlogbeatDir "install-service-winlogbeat.ps1"
    if (Test-Path $installServiceScript) {
        & powershell.exe -ExecutionPolicy Bypass -File $installServiceScript
        Start-Service -Name "winlogbeat" -ErrorAction SilentlyContinue
        Write-Host "[+] Winlogbeat service registered and started." -ForegroundColor Green
    }
}

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " [INSTALL-TELEMETRY] Telemetry and auditing setup completed!" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
