# Threat Hunt Report — Virtual Machine Compromise: *“Hide Your RDP”*

**Incident Date:** 14 September 2025  
**Analyst:** Steven Noel Cruz  
**Compromised Host:** `slflarewinsysmo`  
**Compromised Account:** `slflare`  

---

## 🚀 Executive Summary
On 14 September 2025, suspicious RDP login activity was observed on a cloud-hosted Windows VM. Following a brute-force campaign, the adversary gained RDP access with the `slflare` account. They staged and executed a malicious binary (`msupdate.exe`), created persistence with a scheduled task, modified Microsoft Defender exclusions, performed host discovery, archived data into `backup_sync.zip`, and attempted to exfiltrate it via `curl` to external infrastructure (`185.92.220.87:8081`).  

This attack demonstrates a full intrusion lifecycle: **Initial Access → Execution → Persistence → Defense Evasion → Discovery → Collection → C2 → Exfiltration.**

---

## 📅 Timeline of Events

| Time (UTC+09:00)       | Stage                   | Event / Artifact                                                                                  |
|-------------------------|-------------------------|--------------------------------------------------------------------------------------------------|
| Sep 16, 2025 06:40:57   | Initial Access          | Successful RDP login from attacker IP `159.26.106.84` to account `slflare`                       |
| Sep 16, 2025 06:43:46   | Initial Access          | `RemoteInteractive` logon confirms RDP session established                                       |
| Sep 16, 2025 07:38:01   | Execution               | File `msupdate.exe` created in `C:\Users\Public\` by PowerShell                                  |
| Sep 16, 2025 07:38:40   | Execution               | `msupdate.exe` launched with `-ExecutionPolicy Bypass -File update_check.ps1`                    |
| Sep 16, 2025 07:39:45   | Persistence             | Scheduled Task `MicrosoftUpdateSync` created in TaskCache registry                               |
| Sep 16, 2025 07:39:48   | Defense Evasion         | Defender exclusion added for `C:\Windows\Temp`                                                   |
| Sep 16, 2025 07:40:28   | Discovery               | Discovery command executed: `"cmd.exe" /c systeminfo`                                            |
| Sep 16, 2025 07:41:30   | Collection / Staging    | Archive file `backup_sync.zip` created by `slflare`                                              |
| Sep 16, 2025 07:42:17   | Command & Control       | Outbound connection attempt to C2 `185.92.220.87` on port 80                                     |
| Sep 16, 2025 07:43:42   | Exfiltration            | `curl` used to POST `backup_sync.zip` to `http://185.92.220.87:8081/upload`                      |

---

## 🎯 Flag-by-Flag Findings

### 🚩 Flag 1 — Attacker IP Address
- **Objective:** Identify the external IP that successfully logged in via RDP after repeated failures.  
- **Finding:** Attacker IP `159.26.106.84`.  
- **Evidence:** `DeviceLogonEvents` rows at 06:30, 07:45, and success at 06:40:57.  
- **Query Used:**
```kql
DeviceLogonEvents
| where DeviceName contains "flare"
| where ActionType == "LogonAttempted"
| where RemoteIP != "-"
| summarize FailedAttempts = count() by RemoteIP,AccountName,DeviceName, bin(Timestamp, 15m)
| order by FailedAttempts desc
```
- **Why this matters:** Multiple failed attempts followed by a success confirms brute-force/spray attack.  
- **Flag Answer:**

<img width="865" height="208" alt="Screenshot 2025-09-22 202507" src="https://github.com/user-attachments/assets/20f21577-9105-45dc-83a5-0cea6c853a08" />

```
159.26.106.84
```

---

### 🚩 Flag 2 — Compromised Account
- **Objective:** Identify which account was compromised.  
- **Finding:** Account `slflare`.  
- **Evidence:** `DeviceLogonEvents` rows showing `LogonSuccess` at 06:40:57 (Network) and 06:43:46 (RemoteInteractive).  
- **Query Used:**
```kql
DeviceLogonEvents
| where Timestamp between (datetime(2025-09-13) .. datetime(2025-09-16T23:59:59Z))
| where DeviceName contains "slflarewinsysmo"
| where AccountName == "slflare"
| where RemoteIP == "159.26.106.84"
| where ActionType == "LogonSuccess"
| project Timestamp, AccountName, RemoteIP, DeviceName, LogonType, ActionType
| order by Timestamp asc
```
- **Why this matters:** Confirms the adversary gained access with `slflare`, pivot point for all subsequent activity.  
- **Flag Answer:**

<img width="1053" height="207" alt="Screenshot 2025-09-22 202959" src="https://github.com/user-attachments/assets/a0ba289e-b29d-4f3b-aec4-678a8fea6a4b" />


```
slflare
```

---

### 🚩 Flag 3 — Executed Binary
- **Objective:** Identify the binary executed after login.  
- **Finding:** `msupdate.exe` created in `C:\Users\Public\`.  
- **Evidence:** File creation at 07:38:01 by `powershell.exe`.  
- **Query Used:**
```kql
DeviceFileEvents
| where DeviceName contains "slflarewinsysmo"
| where Timestamp between (datetime(2025-09-15) .. datetime(2025-09-18))
| where InitiatingProcessFileName contains "powershell"
| where FileName endswith ".exe"
| where FolderPath has_any ("\\Users\\Public", "\\Users\\", "\\Downloads", "\\Temp")
| where RequestAccountName contains "slflare"
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName, ActionType, RequestAccountName
```
- **Why this matters:** Suspicious binary staged by attacker.  
- **Flag Answer:**

<img width="456" height="212" alt="Screenshot 2025-09-22 212246" src="https://github.com/user-attachments/assets/3cbeff1f-b154-4316-ac75-42a245d07a44" />


```
msupdate.exe
```

---

### 🚩 Flag 4 — Command Line Used
- **Objective:** Identify the command line used to execute the binary.  
- **Finding:**
```
"msupdate.exe" -ExecutionPolicy Bypass -File C:\Users\Public\update_check.ps1
```
- **Evidence:** Process creation at 07:38:40.  
- **Query Used:**
```kql
DeviceProcessEvents
| where DeviceName contains "slflarewinsysmo"
| where Timestamp between (datetime(2025-09-15) .. datetime(2025-09-18))
| where FileName == "msupdate.exe"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, FileName, FolderPath, ActionType
```
- **Why this matters:** Execution policy bypass indicates attacker intent to evade PowerShell restrictions.  
- **Flag Answer:**

<img width="763" height="236" alt="Screenshot 2025-09-22 212842" src="https://github.com/user-attachments/assets/7f2ff07f-9d04-43c5-abd7-8a578fffaf6a" />


```
"msupdate.exe" -ExecutionPolicy Bypass -File C:\Users\Public\update_check.ps1
```

---

### 🚩 Flag 5 — Persistence Mechanism
- **Objective:** Identify the persistence mechanism.  
- **Finding:** Scheduled task `MicrosoftUpdateSync`.  
- **Evidence:** Registry key created under TaskCache at 07:39:45.  
- **Query Used:**
```kql
DeviceRegistryEvents
| where Timestamp between (datetime(2025-09-16T18:40:57Z) .. datetime(2025-09-18))
| where DeviceName contains "slflarewinsysmo"
| where RegistryKey has "Schedule"
| where ActionType contains "RegistryKeyCreated"
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RegistryKey
```
- **Why this matters:** Scheduled tasks provide reliable persistence under SYSTEM context.  
- **Flag Answer:**

<img width="1441" height="635" alt="Screenshot 2025-09-22 214637" src="https://github.com/user-attachments/assets/90642385-877d-4d74-81c1-0cd1bfc71b1a" />


```
MicrosoftUpdateSync
```

---

### 🚩 Flag 6 — Defender Setting Modified
- **Objective:** Identify the Defender exclusion added.  
- **Finding:** `C:\Windows\Temp`.  
- **Evidence:** RegistryValueSet at 07:39:48 under Defender exclusions.  
- **Query Used:**
```kql
DeviceRegistryEvents
| where DeviceName contains "slflarewinsysmo"
| where RegistryKey contains "Windows Defender" and RegistryKey contains "Exclusions"
| where ActionType == "RegistryValueSet"
| project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName
```
- **Why this matters:**
Adding C:\Windows\Temp to Defender exclusions prevents Defender from scanning that folder, allowing staged payloads or exfil archives placed there (e.g., backup_sync.zip) to go unchecked.

This is a deliberate defense-evasion step (MITRE T1562.001) that increases attacker dwell time and reduces likelihood of detection during staging/exfiltration.

Because the change is made in the registry, it may persist across reboots and survive simple remediation unless explicitly removed.
- **Flag Answer:**

<img width="802" height="170" alt="Screenshot 2025-09-22 214954" src="https://github.com/user-attachments/assets/141586e9-a5cc-4125-b095-089791424ea2" />


```
C:\Windows\Temp
```

---

### 🚩 Flag 7 — Discovery Command
- **Objective:** Identify the discovery command executed.  
- **Finding:** `"cmd.exe" /c systeminfo`  
- **Evidence:** Process creation at 07:40:28.  
- **Query Used:**
```kql
DeviceProcessEvents
| where DeviceName contains "slflarewinsysmo"
| where ProcessCommandLine contains "systeminfo"
| project Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine
```
- **Why this matters:** 
systeminfo returns host OS, patch level, and other system metadata — standard reconnaissance to tailor follow-up actions (privilege escalation, persistence placement, targeted exfil paths).

Because it’s executed immediately after RDP access/payload execution, it anchors the attacker’s early discovery phase (MITRE T1082 — System Information Discovery).

This command helps explain later choices (where to stage data, whether to attempt credential theft, etc.).
- **Flag Answer:**

<img width="420" height="174" alt="Screenshot 2025-09-22 215157" src="https://github.com/user-attachments/assets/3335ea6a-1d46-45c1-964b-a70c6877cf82" />


```
"cmd.exe" /c systeminfo
```

---

### 🚩 Flag 8 — Archive File Created
- **Objective:** Identify the archive staged for exfiltration.  
- **Finding:** `backup_sync.zip`.  
- **Evidence:** File creation at 07:41:30.  
- **Query Used:**
```kql
DeviceFileEvents
| where DeviceName contains "slflarewinsysmo"
| where InitiatingProcessAccountName contains "slflare"
| where FileName contains "zip"
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, FileName
```
- **Why this matters:**
The presence of backup_sync.zip in user-space and created by the compromised account immediately after discovery/persistence strongly indicates the attacker collected and packaged data for exfiltration (MITRE T1560.001 — Local Archiving).

The archive filename and timing allow us to correlate subsequent network activity (beacon/C2 and exfil attempts) to confirm when data staging completed and when exfil likely began.  
- **Flag Answer:**

<img width="896" height="94" alt="Screenshot 2025-09-22 215423" src="https://github.com/user-attachments/assets/c500a234-a81a-4fb4-b9ca-5353228bb2a1" />


```
backup_sync.zip
```

---

### 🚩 Flag 9 — C2 Destination
- **Objective:** Identify the attacker’s C2 destination.  
- **Finding:** `185.92.220.87` (port 80).  
- **Evidence:** Connection attempt at 07:42:17 from PowerShell.  
- **Query Used:**
```kql
DeviceNetworkEvents
| where DeviceName contains "slflarewinsysmo"
| where InitiatingProcessFileName contains "powershell"
| where RemotePort between (80 .. 443)
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort
```
- **Why this matters:**
The outbound attempt from the compromised host to 185.92.220.87 (port 80) coincides with the timeline after the payload executed and archive staging — strongly indicating C2 beaconing or ingress-tool transfer (MITRE T1071.001 / T1105).
- **Flag Answer:**

<img width="434" height="206" alt="Screenshot 2025-09-22 220008" src="https://github.com/user-attachments/assets/1d618919-5311-415c-876e-e0a63d55f09c" />


```
185.92.220.87
```

---

### 🚩 Flag 10 — Exfiltration Attempt
- **Objective:** Identify the exfil IP and port.  
- **Finding:** `185.92.220.87:8081`  
- **Evidence:** Curl POST request at 07:43:42 uploading `backup_sync.zip`.  
- **Query Used:**
```kql
DeviceNetworkEvents
| where DeviceName contains "slflarewinsysmo"
| where InitiatingProcessAccountName contains "slflare"
| where InitiatingProcessCommandLine contains "backup_sync.zip"
| where RemoteIP == "185.92.220.87"
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteIP, RemotePort, InitiatingProcessCommandLine
```
- **Why this matters:**
The attacker explicitly used curl to POST the staged archive backup_sync.zip to their C2 server.

The choice of port 8081 (a non-standard web port) shows an attempt to evade basic monitoring while still blending in as “web traffic.”

This is a textbook case of T1048.003 — Exfiltration Over Unencrypted Protocol, where sensitive data is sent to an attacker-controlled endpoint without encryption.

Strong correlation with Flags 8 (archive staging) and 9 (C2 IP) confirms consolidated infrastructure and full kill-chain progression.
- **Flag Answer:**

<img width="965" height="209" alt="Screenshot 2025-09-22 220311" src="https://github.com/user-attachments/assets/1833ec13-baed-4be0-a8bb-a9fc262d5569" />


```
185.92.220.87:8081
```

---

## 🛡️ After Action Recommendations

**Containment & Eradication**  
- Isolate host `slflarewinsysmo`.  
- Terminate malicious tasks (`MicrosoftUpdateSync`) and binaries (`msupdate.exe`).  
- Remove Defender exclusion for `C:\Windows\Temp`.  
- Rotate passwords and enforce MFA for `slflare`.  
- Reimage if persistence/credential theft suspected.  

**Detection & Monitoring**  
- Alert on Defender exclusion changes.  
- Monitor for scheduled task creation with unusual names.  
- Detect brute-force RDP attempts.  
- Alert on `curl` or PowerShell uploads to external IPs.  

**Prevention & Hardening**  
- Require MFA on RDP.  
- Block direct RDP from internet (VPN/jump host only).  
- Deploy rules to detect PowerShell `ExecutionPolicy Bypass`.  

---
