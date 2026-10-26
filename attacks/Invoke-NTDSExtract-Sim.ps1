<#
.SYNOPSIS
    Invoke-NTDSExtract-Sim: Active Directory Database Extraction Simulation (MITRE ATT&CK T1003.003).
.DESCRIPTION
    Simulates offline Active Directory database (NTDS.dit) credential extraction techniques
    using native Windows administrative binaries such as ntdsutil.exe ('ac i ntds' 'ifm')
    and vssadmin.exe shadow copy creation.
    Generates Sysmon Event ID 1 / Windows Security Event ID 4688 process telemetry.
#>

[CmdletBinding()]
param(
    [string]$TargetDirectory = "C:\Windows\Temp\ntds_sim_test",
    [switch]$UseVssAdmin = $false
)

$ErrorActionPreference = "Continue"

Write-Host "================================================================" -ForegroundColor Red
Write-Host " [ATTACK EMULATION] MITRE ATT&CK T1003.003: NTDS.dit Extraction Sim" -ForegroundColor Red
Write-Host "================================================================" -ForegroundColor Red
Write-Host "[*] Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')" -ForegroundColor Gray
Write-Host "[*] Output Path: $TargetDirectory" -ForegroundColor Gray

# Ensure test staging folder exists
if (-not (Test-Path $TargetDirectory)) {
    New-Item -ItemType Directory -Path $TargetDirectory -Force | Out-Null
}

if ($UseVssAdmin) {
    Write-Host "`n[*] Technique: Emulating Volume Shadow Copy creation via vssadmin..." -ForegroundColor Yellow
    $vssCmd = "vssadmin.exe create shadow /for=C:"
    Write-Host "[+] Executing: $vssCmd" -ForegroundColor DarkYellow
    
    # Run test simulation
    try {
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c echo [SIMULATED] $vssCmd" -Wait -NoNewWindow
    } catch {}
} else {
    Write-Host "`n[*] Technique: Emulating ntdsutil IFM (Install From Media) snapshot extraction..." -ForegroundColor Yellow
    $ntdsCmd = "ntdsutil.exe `"ac i ntds`" `"ifm`" `"create full $TargetDirectory`" q q"
    Write-Host "[+] Executing: $ntdsCmd" -ForegroundColor DarkYellow
    
    try {
        # Execute safe simulation command line
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c echo [SIMULATED] $ntdsCmd" -Wait -NoNewWindow
    } catch {}
}

# Cleanup staging artifacts
Write-Host "`n[*] Phase 3: Cleaning up simulated staging artifacts..." -ForegroundColor Yellow
try {
    if (Test-Path $TargetDirectory) {
        Remove-Item -Path $TargetDirectory -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "[+] Staging path cleaned." -ForegroundColor Green
    }
} catch {}

Write-Host "`n================================================================" -ForegroundColor Red
Write-Host " [ATTACK COMPLETE] NTDS extraction emulation executed." -ForegroundColor Red
Write-Host " Detection Rule: win_ad_ntdsutil_shadowcopy_dump.yml" -ForegroundColor Green
Write-Host " Expected Telemetry: Sysmon Event ID 1 / Security Event ID 4688" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Red
