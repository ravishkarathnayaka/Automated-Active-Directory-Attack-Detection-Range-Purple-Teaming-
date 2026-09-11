<#
.SYNOPSIS
    Master Purple Team Attack Emulation Orchestrator.
.DESCRIPTION
    Executes the complete suite of Active Directory credential access and lateral
    movement attack emulations sequentially with pause markers, time bounds,
    and purple team execution scorecard reporting.
#>

[CmdletBinding()]
param(
    [int]$PauseSecondsBetweenAttacks = 5,
    [string]$DomainController = "DC01.corp.local",
    [switch]$NonInteractive = $false
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

function Write-Banner {
    Clear-Host
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host "   AUTOMATED ACTIVE DIRECTORY PURPLE TEAM ATTACK & DETECTION SUITE              " -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host " Orchestrating simulated adversary behaviors against Active Directory telemetry " -ForegroundColor Gray
    Write-Host " Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')                       " -ForegroundColor Gray
    Write-Host " Host: $env:COMPUTERNAME | User: $env:USERDOMAIN\$env:USERNAME                  " -ForegroundColor Gray
    Write-Host "================================================================================`n" -ForegroundColor Cyan
}

function Wait-Interval {
    param([string]$NextPhase)
    Write-Host "`n[*] Demarcating event telemetry stream. Pausing for $PauseSecondsBetweenAttacks seconds before: $NextPhase..." -ForegroundColor DarkYellow
    if (-not $NonInteractive) {
        for ($i = $PauseSecondsBetweenAttacks; $i -gt 0; $i--) {
            Write-Host -NoNewline "$i... "
            Start-Sleep -Seconds 1
        }
        Write-Host ""
    }
}

Write-Banner

$Results = [System.Collections.Generic.List[PSCustomObject]]::new()

# ------------------------------------------------------------------------------
# Phase 1: Kerberoasting (MITRE ATT&CK T1558.003)
# ------------------------------------------------------------------------------
Write-Host ">>> [PHASE 1 / 4] EXECUTING KERBEROASTING ATTACK EMULATION" -ForegroundColor Yellow
$p1Start = Get-Date
try {
    & "$ScriptDir\Invoke-Kerberoast.ps1"
    $Results.Add([PSCustomObject]@{
        Phase = "1. Kerberoasting"
        MITRE_ID = "T1558.003"
        ExpectedEventID = "Security 4769 (0x17)"
        SigmaRule = "win_ad_kerberoasting_spn_request.yml"
        Status = "SUCCESS"
        ExecutionTime = "$(([int]((Get-Date) - $p1Start).TotalSeconds))s"
    })
} catch {
    Write-Error "Phase 1 Failed: $_"
    $Results.Add([PSCustomObject]@{
        Phase = "1. Kerberoasting"
        MITRE_ID = "T1558.003"
        ExpectedEventID = "Security 4769"
        SigmaRule = "win_ad_kerberoasting_spn_request.yml"
        Status = "FAILED"
        ExecutionTime = "0s"
    })
}

Wait-Interval -NextPhase "Phase 2: AS-REP Roasting"

# ------------------------------------------------------------------------------
# Phase 2: AS-REP Roasting (MITRE ATT&CK T1558.004)
# ------------------------------------------------------------------------------
Write-Host "`n>>> [PHASE 2 / 4] EXECUTING AS-REP ROASTING ATTACK EMULATION" -ForegroundColor Yellow
$p2Start = Get-Date
try {
    & "$ScriptDir\Invoke-ASREPRoast.ps1" -DomainController $DomainController
    $Results.Add([PSCustomObject]@{
        Phase = "2. AS-REP Roasting"
        MITRE_ID = "T1558.004"
        ExpectedEventID = "Security 4768 (PreAuth 0)"
        SigmaRule = "win_ad_asrep_roasting_preauth.yml"
        Status = "SUCCESS"
        ExecutionTime = "$(([int]((Get-Date) - $p2Start).TotalSeconds))s"
    })
} catch {
    Write-Error "Phase 2 Failed: $_"
    $Results.Add([PSCustomObject]@{
        Phase = "2. AS-REP Roasting"
        MITRE_ID = "T1558.004"
        ExpectedEventID = "Security 4768"
        SigmaRule = "win_ad_asrep_roasting_preauth.yml"
        Status = "FAILED"
        ExecutionTime = "0s"
    })
}

Wait-Interval -NextPhase "Phase 3: DCSync Simulation"

# ------------------------------------------------------------------------------
# Phase 3: DCSync Directory Replication Simulation (MITRE ATT&CK T1003.006)
# ------------------------------------------------------------------------------
Write-Host "`n>>> [PHASE 3 / 4] EXECUTING DCSYNC REPLICATION EMULATION" -ForegroundColor Yellow
$p3Start = Get-Date
try {
    & "$ScriptDir\Invoke-DCSync-Sim.ps1" -DomainController $DomainController
    $Results.Add([PSCustomObject]@{
        Phase = "3. DCSync Simulation"
        MITRE_ID = "T1003.006"
        ExpectedEventID = "Security 4662 (0x100)"
        SigmaRule = "win_ad_dcsync_replication_access.yml"
        Status = "SUCCESS"
        ExecutionTime = "$(([int]((Get-Date) - $p3Start).TotalSeconds))s"
    })
} catch {
    Write-Error "Phase 3 Failed: $_"
    $Results.Add([PSCustomObject]@{
        Phase = "3. DCSync Simulation"
        MITRE_ID = "T1003.006"
        ExpectedEventID = "Security 4662"
        SigmaRule = "win_ad_dcsync_replication_access.yml"
        Status = "FAILED"
        ExecutionTime = "0s"
    })
}

Wait-Interval -NextPhase "Phase 4: Pass the Hash Simulation"

# ------------------------------------------------------------------------------
# Phase 4: Pass the Hash Simulation (MITRE ATT&CK T1550.002)
# ------------------------------------------------------------------------------
Write-Host "`n>>> [PHASE 4 / 4] EXECUTING PASS THE HASH SIMULATION" -ForegroundColor Yellow
$p4Start = Get-Date
try {
    & "$ScriptDir\Invoke-PassTheHash-Sim.ps1" -TargetComputer $DomainController
    $Results.Add([PSCustomObject]@{
        Phase = "4. Pass the Hash"
        MITRE_ID = "T1550.002"
        ExpectedEventID = "Security 4624 / Sysmon 1"
        SigmaRule = "win_susp_powershell_encoded_cmd.yml"
        Status = "SUCCESS"
        ExecutionTime = "$(([int]((Get-Date) - $p4Start).TotalSeconds))s"
    })
} catch {
    Write-Error "Phase 4 Failed: $_"
    $Results.Add([PSCustomObject]@{
        Phase = "4. Pass the Hash"
        MITRE_ID = "T1550.002"
        ExpectedEventID = "Security 4624 / Sysmon 1"
        SigmaRule = "win_susp_powershell_encoded_cmd.yml"
        Status = "FAILED"
        ExecutionTime = "0s"
    })
}

# ------------------------------------------------------------------------------
# Purple Team Execution Scorecard
# ------------------------------------------------------------------------------
Write-Host "`n================================================================================" -ForegroundColor Cyan
Write-Host "                      PURPLE TEAM EMULATION SCORECARD                           " -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
$Results | Format-Table -AutoSize -Property Phase, MITRE_ID, ExpectedEventID, SigmaRule, Status, ExecutionTime
Write-Host "Execution Finished: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')`n" -ForegroundColor Gray
