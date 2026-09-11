@echo off
rem ============================================================================
rem Advanced Windows Audit Policy Configuration
rem Purpose: Configures granular audit policies for Active Directory attacks,
rem          including Kerberoasting (4769), AS-REP Roasting (4768),
rem          DCSync (4662), and Process Execution (4688).
rem ============================================================================

echo [*] Applying Advanced Security Audit Policies...

rem --- 1. Account Logon (Kerberos Operations) ---
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Other Account Logon Events" /success:enable /failure:enable

rem --- 2. Account Management ---
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Other Account Management Events" /success:enable /failure:enable

rem --- 3. Detailed Tracking (Process Creation) ---
auditpol /set /subcategory:"Process Creation" /success:enable /failure:disable
auditpol /set /subcategory:"Process Termination" /success:enable /failure:disable
auditpol /set /subcategory:"RPC Events" /success:enable /failure:enable

rem --- 4. Directory Service Access (DCSync & AD Objects) ---
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Replication" /success:enable /failure:enable
auditpol /set /subcategory:"Detailed Directory Service Replication" /success:enable /failure:enable

rem --- 5. Logon/Logoff ---
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable /failure:disable
auditpol /set /subcategory:"Special Logon" /success:enable /failure:disable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable

rem --- 6. Privilege Use ---
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable

rem --- 7. Policy Change ---
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable

rem --- 8. System ---
auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable

echo [+] Advanced Audit Policies successfully applied.
