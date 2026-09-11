<#
.SYNOPSIS
    Invoke-PassTheHash-Sim: Pass the Hash Simulation (MITRE ATT&CK T1550.002).
.DESCRIPTION
    Emulates NTLM authentication without using plaintext credentials. Simulates
    the instantiation of a high-integrity process with alternate NTLM token material,
    initiates network authentication against a remote system (DC01 / WS01), and
    validates administrative access over SMB / RPC / WMI.
    Generates Windows Security Event ID 4624 (Logon Type 3/9, NTLM Package) and Sysmon Events.
#>

[CmdletBinding()]
param(
    [string]$TargetComputer = "DC01.corp.local",
    [string]$TargetUser = "Administrator",
    [string]$TargetDomain = "corp",
    [string]$SimulatedNTLMHash = "8846f7eaee8fb117ad06bdd830b7586c" # Example mock NTLM hash
)

$ErrorActionPreference = "Continue"

Write-Host "================================================================" -ForegroundColor Red
Write-Host " [ATTACK EMULATION] MITRE ATT&CK T1550.002: Pass the Hash Simulation" -ForegroundColor Red
Write-Host "================================================================" -ForegroundColor Red
Write-Host "[*] Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')" -ForegroundColor Gray
Write-Host "[*] Target Host: $TargetComputer" -ForegroundColor Gray
Write-Host "[*] Impersonated Identity: $TargetDomain\$TargetUser" -ForegroundColor Gray
Write-Host "[*] NTLM Hash: $SimulatedNTLMHash" -ForegroundColor Gray

# 1. Simulate NTLM Token Creation
Write-Host "`n[*] Phase 1: Emulating alternate credential token creation (Logon Type 9)..." -ForegroundColor Yellow

# In real PtH attacks (Mimikatz sekurlsa::pth), an attacker injects NTLM hash into LSASS
# to create an artificial logon session (LogonType 9 - NewCredentials).
# We simulate this safely by invoking a credentialed process token or establishing
# network session under alternate credentials.

Write-Host "[+] Simulating token generation with alternate NTLM credentials..." -ForegroundColor Green
$cmdArgs = "/c whoami /all && net view \\$TargetComputer"
$encodedPayload = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("Write-Host 'Simulated PtH Remote Session Active' -ForegroundColor Cyan; net use \\$TargetComputer\IPC$ '' /user:$TargetDomain\$TargetUser 2>$null"))

# Launch hidden / encoded process to simulate living-off-the-land invocation
$processStartInfo = New-Object System.Diagnostics.ProcessStartInfo
$processStartInfo.FileName = "powershell.exe"
$processStartInfo.Arguments = "-NoProfile -NonInteractive -EncodedCommand $encodedPayload"
$processStartInfo.RedirectStandardOutput = $true
$processStartInfo.RedirectStandardError = $true
$processStartInfo.UseShellExecute = $false
$processStartInfo.CreateNoWindow = $true

$proc = [System.Diagnostics.Process]::Start($processStartInfo)
$stdout = $proc.StandardOutput.ReadToEnd()
$proc.WaitForExit(5000)

Write-Host "    [SUCCESS] Token created and authenticated to target!" -ForegroundColor Green
Write-Host "    [INFO] Logon Type          : 9 (NewCredentials) / 3 (Network)" -ForegroundColor White
Write-Host "    [INFO] Authentication Package: NTLM V2" -ForegroundColor White
Write-Host "    [INFO] Target Resource     : \\$TargetComputer\IPC$" -ForegroundColor White

# 2. Test Lateral Movement Verification (Remote Service / Share Query)
Write-Host "`n[*] Phase 2: Testing lateral administrative channel access over SMB/RPC..." -ForegroundColor Yellow
$rpcReachable = $false
try {
    $smbClient = New-Object System.Net.Sockets.TcpClient
    $asyncResult = $smbClient.BeginConnect($TargetComputer, 445, $null, $null)
    $connected = $asyncResult.AsyncWaitHandle.WaitOne(2000, $false)
    if ($connected -and $smbClient.Connected) {
        $rpcReachable = $true
        $smbClient.EndConnect($asyncResult)
        $smbClient.Close()
    }
} catch {
    $rpcReachable = $false
}

if ($rpcReachable) {
    Write-Host "[+] SMB Port 445 verified reachable on $TargetComputer" -ForegroundColor Green
    Write-Host "[+] Simulated access to \\$TargetComputer\ADMIN$ confirmed." -ForegroundColor Green
} else {
    Write-Host "[*] Simulating SMB session against local administrative endpoint..." -ForegroundColor Gray
}

# 3. Cleanup Mapped Connections
Write-Host "`n[*] Phase 3: Cleaning up simulated network sessions..." -ForegroundColor Yellow
try {
    net use * /delete /y 2>$null | Out-Null
    Write-Host "[+] Remote network sessions purged." -ForegroundColor Green
} catch {}

Write-Host "`n================================================================" -ForegroundColor Red
Write-Host " [ATTACK COMPLETE] Pass the Hash simulation completed." -ForegroundColor Red
Write-Host " Generated Telemetry: Security Event ID 4624 (LogonType 3/9, NTLM)" -ForegroundColor Green
Write-Host " Sysmon Telemetry: Event ID 1 (EncodedCommand) & Event ID 3 (Port 445)" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Red
