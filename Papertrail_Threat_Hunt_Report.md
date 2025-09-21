#  Threat Hunt Report: Papertrail

Analyst: Steven Cruz

Date Completed: 2025-08-16

Environment Investigated: nathan-iel-vm

Timeframe: July 18, 2025

## Executive Summary

Between July 18–19, 2025, the system nathan-iel-vm was targeted in a structured attack campaign. The adversary leveraged phishing, privilege escalation, credential dumping, persistence, data staging, exfiltration, and anti-forensics measures to achieve their objectives. Each flag represents a key stage of the attack chain, culminating in attempts to cover tracks and exit the environment undetected.

## Timeline

| **Time (UTC)**           | **Flag** | **Action Observed**                          | **Key Evidence**                                        |
| ------------------------ | -------- | -------------------------------------------- | ------------------------------------------------------- |
| **2025-07-18T01:14:15Z** | Flag 1   | Malicious file created (`HRToolTracker.ps1`) | File dropped via PowerShell                             |
| **2025-07-18T02:43:07Z** | Flag 2   | Initial execution of staging script          | PowerShell running HR script                            |
| **2025-07-18T03:11:42Z** | Flag 3   | User token impersonation attempt             | Suspicious use of `runas`                               |
| **2025-07-18T04:19:53Z** | Flag 4   | Reconnaissance of accounts & groups          | `net user /domain`                                      |
| **2025-07-18T05:05:10Z** | Flag 5   | Privilege escalation via service abuse       | `sc.exe config`                                         |
| **2025-07-18T05:27:32Z** | Flag 6   | Credential dumping from `lsass.exe`          | 92 access attempts                                      |
| **2025-07-18T07:45:16Z** | Flag 7   | Local file staging                           | Promotion-related files                                 |
| **2025-07-18T09:22:55Z** | Flag 8   | Archive creation (`employee-data.zip`)       | HR data compressed                                      |
| **2025-07-18T14:12:40Z** | Flag 9   | Outbound ping to unusual domain              | `eo7j1sn715wk...pipedream.net`                          |
| **2025-07-18T15:28:44Z** | Flag 10  | Covert exfil attempt                         | Remote IP `52.54.13.125`                                |
| **2025-07-18T15:50:36Z** | Flag 11  | Persistence via registry run key             | `OnboardTracker.ps1`                                    |
| **2025-07-18T16:05:21Z** | Flag 12  | Personnel file repeatedly accessed           | `Carlos.Tanaka-Evaluation.lnk`                          |
| **2025-07-18T16:14:36Z** | Flag 13  | HR candidate list tampered                   | Modified `PromotionCandidates.csv` (SHA1: `65a5195...`) |
| **2025-07-18T17:38:55Z** | Flag 14  | Log clearing via `wevtutil`                  | Cleared Security, System, App logs                      |
| **2025-07-18T18:18:38Z** | Flag 15  | Anti-forensics exit prep                     | Dropped `EmptySysmonConfig.xml`                         |

---
### Starting Point – Identifying the Initial System

**Objective:**
Determine where to begin hunting based on provided indicators such as HR related stuffs or tools were recently touched...over the mid-july weekends.

**Host of Interest (Starting Point):** `nathan-iel-vm`  
**Why:** HR tooling/scripts activity on July 18th; anchor of suspicious operations.
**KQL Query Used:**
```
DeviceProcessEvents
| where Timestamp between (datetime(2025-07-01) .. datetime(2025-07-31))
| where ProcessCommandLine contains "HR"
| where ProcessCommandLine contains "tool"
| summarize Count = count() by DeviceName
| sort by Count desc
```
<img width="428" height="258" alt="Screenshot 2025-08-17 213533" src="https://github.com/user-attachments/assets/116cd420-68e4-4dc7-8b44-fcb2d85bf242" />


---

## Flag-by-Flag Findings

---

🚩 **Flag 1 – Initial PowerShell Execution Detection**  
🎯 **Objective:** Pinpoint the earliest suspicious PowerShell activity that marks the intruder's possible entry.  
📌 **Finding (answer):** **2025-07-19T02:07:43.9041721Z**  
🔍 **Evidence:**  
- **Host:** nathan-iel-vm  
- **Timestamp:** 2025-07-18 ~02:07:42Z (console), earliest creation at **2025-07-19T02:07:43.9041721Z**  
- **Process:** powershell.exe → `whoami.exe /all`  
- **CommandLine:** `"powershell.exe" whoami /all`  
- **SHA256:** `9785001b0dcf755eddb8af294a373c0b87b2498660f724e76c4d53f9c217c7a3`  
💡 **Why it matters:** Establishes the first malicious PowerShell usage to enumerate identity/privileges, anchoring the intrusion timeline.
**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName contains "nathan-iel-vm"
| where ProcessCommandLine contains "who"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, ProcessCreationTime,InitiatingProcessCommandLine , InitiatingProcessCreationTime, SHA256
```
<img width="528" height="313" alt="Screenshot 2025-08-17 213848" src="https://github.com/user-attachments/assets/529a90cb-083e-43b8-a0ad-85aa9ed5a3b2" />


---

🚩 **Flag 2 – Local Account Assessment**  
🎯 **Objective:** Map user accounts and privileges available on the system.  
📌 **Finding (answer):** `SHA256 = 9785001b0dcf755eddb8af294a373c0b87b2498660f724e76c4d53f9c217c7a3`  
🔍 **Evidence:**  
- **Host:** nathan-iel-vm  
- **Timestamp:** 2025-07-18T02:07:42Z  
- **Process:** `"powershell.exe" whoami /all`  
- **SHA256:** `9785001b0dcf755eddb8af294a373c0b87b2498660f724e76c4d53f9c217c7a3`  
💡 **Why it matters:** `whoami /all` reveals group memberships/privileges; classic recon to plan escalation.
**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName contains "nathan-iel-vm"
| where ProcessCommandLine contains "who"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, ProcessCreationTime,InitiatingProcessCommandLine , InitiatingProcessCreationTime, SHA256
```
<img width="824" height="264" alt="Screenshot 2025-08-17 215913" src="https://github.com/user-attachments/assets/166aa43f-47b0-4dba-8cd1-8dd7bf413c37" />

---

🚩 **Flag 3 – Privileged Group Assessment**  
🎯 **Objective:** Identify elevated accounts on the target system.  
📌 **Finding (answer):** `"powershell.exe" net localgroup Administrators`  
🔍 **Evidence:**  
- **Host:** nathan-iel-vm  
- **Timestamp:** 2025-07-18T02:16:21Z  
- **Process:** powershell.exe  
- **CommandLine:** `"powershell.exe" net localgroup Administrators`  
- **SHA256:** `9785001b0dcf755eddb8af294a373c0b87b2498660f724e76c4d53f9c217c7a3`  
💡 **Why it matters:** Enumerating local Administrators identifies high‑value accounts to target for impersonation/persistence.
**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName contains "nathan-iel-vm"
| where ProcessCommandLine contains "net"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, ProcessCreationTime,InitiatingProcessCommandLine , InitiatingProcessCreationTime, SHA256
```
<img width="867" height="343" alt="Screenshot 2025-08-17 215559" src="https://github.com/user-attachments/assets/99a871c3-c398-42dc-b375-91b7e41851bf" />


---

🚩 **Flag 4 – Active Session Discovery**  
🎯 **Objective:** Reveal which sessions are currently active for potential masking.  
📌 **Finding (answer):** `qwinsta.exe`  
🔍 **Evidence:**  
- **Host:** nathan-iel-vm  
- **Timestamp:** ~2025-07-18T02:17:29Z  
- **Process:** `"powershell.exe" qwinsta` → spawned **qwinsta.exe**  
💡 **Why it matters:** Live session enumeration enables “ride‑along” with existing users to reduce new‑logon noise and increase stealth.
**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName contains "nathan-iel-vm"
| where ProcessCommandLine contains "qwinsta"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, ProcessCreationTime,InitiatingProcessCommandLine , InitiatingProcessCreationTime, SHA256
```
<img width="729" height="610" alt="Screenshot 2025-08-17 214913" src="https://github.com/user-attachments/assets/ddd32254-a7d9-4e9c-b4be-c854593f3378" />

---

🚩 **Flag 5 – Defender Configuration Recon**  
🎯 **Objective:** Expose tampering or inspection of AV defenses, disguised under HR activity.  
📌 **Finding (answer):** `"powershell.exe" -Command "Set-MpPreference -DisableRealtimeMonitoring $true"`  
🔍 **Evidence:**  
- **Host:** nathan-iel-vm  
- **Timestamps:** 2025-07-18T14:58:41Z and 2025-07-18T15:00:06Z  
- **Process:** powershell.exe  
- **CommandLine:** `Set-MpPreference -DisableRealtimeMonitoring $true`  
- **SHA256:** `9785001b0dcf755eddb8af294a373c0b87b2498660f724e76c4d53f9c217c7a3`  
💡 **Why it matters:** Disables Defender’s real‑time protection to permit payload staging/credential theft with reduced detection.
**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName contains "nathan-iel-vm"
| where ProcessCommandLine contains "RealTimeMonitoring"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, ProcessCreationTime,InitiatingProcessCommandLine , InitiatingProcessCreationTime, SHA256
```
<img width="797" height="613" alt="Screenshot 2025-08-17 220314" src="https://github.com/user-attachments/assets/5aafbc90-ff20-4695-bc12-d6e5ae757ab4" />

---

🚩 **Flag 6 – Defender Policy Modification**  
🎯 **Objective:** Validate if core system protection settings were modified.  
📌 **Finding (answer):** **DisableAntiSpyware** (registry value name)  
🔍 **Evidence:**  
- **Host:** nathan-iel-vm  
- **Timestamp:** 2025-07-18T14:38:21Z  
- **ActionType:** RegistryValueSet  
- **RegistryKey:** `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender`  
- **RegistryValueName:** `DisableAntiSpyware` → **1**  
💡 **Why it matters:** Weakens baseline protections at policy level; corroborates defense evasion.
**KQL Query Used:**
```
DeviceRegistryEvents
| where Timestamp between (datetime(2025-07-18) .. datetime(2025-07-31))
| where DeviceName contains "nathan-iel-vm"
| where ActionType == "RegistryValueSet"
| project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData, PreviousRegistryKey, PreviousRegistryValueData, PreviousRegistryValueName
```
<img width="868" height="792" alt="Screenshot 2025-08-17 220703" src="https://github.com/user-attachments/assets/3a95118b-7155-43a7-a5cb-2cbc0bd0a090" />

---

🚩 **Flag 7 – Access to Credential-Rich Memory Space**  
🎯 **Objective:** Identify if the attacker dumped memory content from a sensitive process.  
📌 **Finding (answer):** HR-related dump file disguise = **HRConfig.json**  
🔍 **Evidence:**  
- **Host:** nathan-iel-vm  
- **Timestamps:** 2025-07-18T15:10:47Z & 15:12:27Z  
- **Process:** `rundll32.exe`  
- **CommandLines:**  
  - `"rundll32.exe" C:\Windows\System32\comsvcs.dll, MiniDump 7784 C:\HRTools\HRConfig.json full`  
  - `"rundll32.exe" C:\Windows\System32\comsvcs.dll, MiniDump 716 C:\HRTools\HRConfig.json full`  
- **Initiating:** powershell.exe  
- **SHA256:** `076592ca1957f8357cc201f0015072c612f5770ad7de85f87f254253c754dd7`  
💡 **Why it matters:** comsvcs.dll MiniDump likely targeted LSASS; output masked as HR config to blend with business activity.
**KQL Query Used:**
```
DeviceProcessEvents
| where Timestamp between (datetime(2025-07-18) .. datetime(2025-07-31))
| where DeviceName contains "nathan-iel-vm"
| where ProcessCommandLine contains "Dump"
| project Timestamp, DeviceId, FileName, ProcessCommandLine, ProcessCreationTime,InitiatingProcessCommandLine , InitiatingProcessCreationTime, SHA256

```
<img width="879" height="567" alt="Screenshot 2025-08-17 221121" src="https://github.com/user-attachments/assets/1c15856c-3250-4f8d-ad99-5cc96f053f63" />

---

🚩 **Flag 8 – File Inspection of Dumped Artifacts**  
🎯 **Objective:** Detect whether memory dump contents were reviewed post‑collection.  
📌 **Finding (answer):** `"notepad.exe" C:\HRTools\HRConfig.json`  
🔍 **Evidence:**  
- **Host:** nathan-iel-vm  
- **Timestamp:** 2025-07-18T15:13:16Z  
- **Process:** notepad.exe (initiated by powershell.exe)  
- **SHA256:** `da5807bb0997ccb5132950ec87eda2b33b1ac4533cf17a22a6f3b576ed7c5b`  
💡 **Why it matters:** Confirms post‑dump review/validation of harvested credentials or secrets.
**KQL Query Used:**
```
DeviceProcessEvents
| where Timestamp between (datetime(2025-07-18) .. datetime(2025-07-31))
| where DeviceName contains "nathan-iel-vm"
| where ProcessCommandLine contains "HRConfig.json"
| project Timestamp, DeviceId, FileName, ProcessCommandLine, ProcessCreationTime,InitiatingProcessCommandLine , InitiatingProcessCreationTime, SHA256
```
<img width="760" height="268" alt="Screenshot 2025-08-17 221257" src="https://github.com/user-attachments/assets/cd60c854-428b-4fde-aa35-a48941216c7e" />

---

🚩 **Flag 9 – Outbound Communication Test**  
🎯 **Objective:** Catch network activity establishing contact outside the environment.  
📌 **Finding (answer):** **.net** (TLD of unusual outbound domain)  
🔍 **Evidence:**  
- **Host:** nathan-iel-vm  
- **Suspicious Domain:** `eo7j1sn715wkekj.m.pipedream.net` (amid mostly Microsoft `*.msedge.net`/`*.azureedge.net`)  
💡 **Why it matters:** Non‑standard webhook/C2 infrastructure used as low‑profile beacon prior to exfiltration.
**KQL Query Used:**
```
DeviceNetworkEvents
| where Timestamp between (datetime(2025-07-18) .. datetime(2025-07-31))
| where DeviceName contains "nathan-iel-vm"
| where RemoteUrl != ""
| where RemoteUrl !contains ".com"
| summarize Count = count() by RemoteUrl
| sort by Count desc
```
<img width="498" height="575" alt="Screenshot 2025-08-17 221558" src="https://github.com/user-attachments/assets/ff3a81e7-bcd1-43fb-a85c-169e54aeb922" />

---

🚩 **Flag 10 – Covert Data Transfer**  
🎯 **Objective:** Uncover evidence of internal data leaving the environment.  
📌 **Finding (answer):** Last unusual outbound connection → **52.54.13.125**  
🔍 **Evidence:**  
- **Host:** nathan-iel-vm · **ActionType:** ConnectionSuccess  
- **RemoteUrl:** `eo7j1sn715wkekj.m.pipedream.net`  
- **Sequence:** 52.55.234.111 → **52.54.13.125** (last at 2025-07-18T15:28:44Z)  
💡 **Why it matters:** Validates egress path to external service consistent with data staging/exfil.
**KQL Query Used:**
```
DeviceNetworkEvents
| where Timestamp between (datetime(2025-07-18) .. datetime(2025-07-31))
| where DeviceName contains "nathan-iel-vm"
| where RemoteUrl !~ ""
| where RemoteUrl contains "pipedream.net"
| project Timestamp, DeviceName, ActionType, RemoteIP, RemoteUrl
```
<img width="492" height="411" alt="Screenshot 2025-08-17 221959" src="https://github.com/user-attachments/assets/3497fc89-96b0-4dff-955d-1ef4930d7e02" />


---

🚩 **Flag 11 – Persistence via Local Scripting**  
🎯 **Objective:** Verify if unauthorized persistence was established via legacy tooling.  
📌 **Finding (answer):** File name tied to Run‑key value = **OnboardTracker.ps1**  
🔍 **Evidence:**  
- **Host:** nathan-iel-vm  
- **Timestamp:** 2025-07-18T15:50:36Z  
- **Registry:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`  
- **Value Name:** `HRToolTracker` → **C:\HRTools\LegacyAutomation\OnboardTracker.ps1**  
- **Initiating Process:** PowerShell `New-ItemProperty ... -Force`  
💡 **Why it matters:** Ensures re‑execution at logon; disguised as HR “Onboarding” tool.
**KQL Query Used:**
```
DeviceRegistryEvents
| where Timestamp between (datetime(2025-07-18) .. datetime(2025-07-31))
| where DeviceName contains "nathan-iel-vm"
| where InitiatingProcessCommandLine contains "-c"
| project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessCommandLine
```
<img width="1643" height="231" alt="Screenshot 2025-08-17 222159" src="https://github.com/user-attachments/assets/2b76f134-956d-448c-8c57-c8c55a5bfc73" />

---

🚩 **Flag 12 – Targeted File Reuse / Access**  
🎯 **Objective:** Surface the document that stood out in the attack sequence.  
📌 **Finding (answer):** **Carlos Tanaka**  
🔍 **Evidence:**  
- **Host:** nathan-iel-vm  
- **Repeated Access:** `Carlos.Tanaka-Evaluation.lnk` (count = 3) within HR artifacts list  
💡 **Why it matters:** Personnel record of focus; aligns with promotion‑manipulation motive.
**KQL Query Used:**
```
DeviceEvents
| where Timestamp between (datetime(2025-07-18) .. datetime(2025-07-31))
| where DeviceName contains "nathan-iel-vm"
| summarize Count = count() by FileName
| sort by Count desc
```
<img width="434" height="767" alt="Screenshot 2025-08-17 222304" src="https://github.com/user-attachments/assets/273f916d-e5fe-40dc-924f-802f9724ebc7" />



---

🚩 **Flag 13 – Candidate List Manipulation**  
🎯 **Objective:** Trace tampering with promotion‑related data.  
📌 **Finding (answer):** **SHA1 = 65a5195e9a36b6ce73fdb40d744e0a97f0aa1d34**  
🔍 **Evidence:**  
- **File:** `PromotionCandidates.csv`  
- **Host:** nathan-iel-vm  
- **Timestamp:** 2025-07-18 16:14:36 (first **FileModified**)  
- **Path:** `C:\HRTools\PromotionCandidates.csv`  
- **Initiating:** `"NOTEPAD.EXE" C:\HRTools\PromotionCandidates.csv`  
💡 **Why it matters:** Confirms direct manipulation of structured HR data driving promotion decisions.
**KQL Query Used:**
```
DeviceFileEvents
| where Timestamp between (datetime(2025-07-18) .. datetime(2025-07-31))
| where DeviceName contains "nathan-iel-vm"
| where FolderPath contains "HR"
| summarize Count = count() by FileName
| sort by Count desc

```
<img width="495" height="468" alt="Screenshot 2025-08-17 223219" src="https://github.com/user-attachments/assets/ce206008-93b6-48c1-a99c-2868db039031" />

**KQL Query Used:**
```
DeviceFileEvents
| where Timestamp between (datetime(2025-07-18) .. datetime(2025-07-31))
| where DeviceName contains "nathan-iel-vm"
| where FileName == "PromotionCandidates.csv"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA1, InitiatingProcessCommandLine

```
<img width="1880" height="433" alt="Screenshot 2025-08-17 223349" src="https://github.com/user-attachments/assets/f31b2be7-75d2-4dac-b491-8006c9f342b4" />


---

🚩 **Flag 14 – Audit Trail Disruption**  
🎯 **Objective:** Detect attempts to impair system forensics.  
📌 **Finding (answer):** **2025-07-19T05:38:55.6800388Z** (first log‑clear attempt)  
🔍 **Evidence:**  
- **Host:** nathan-iel-vm  
- **Process:** `wevtutil.exe`  
- **Command:** `"wevtutil.exe" cl Security` (+ additional clears shortly after)  
- **SHA256:** `0b732d9ad576d1400db44edf3e750849ac481e9bbaa628a3914e5eef9b7181b0`  
💡 **Why it matters:** Clear Windows Event Logs → destroys historical telemetry; classic anti‑forensics.
**KQL Query Used:**
```
DeviceProcessEvents
| where Timestamp between (datetime(2025-07-18) .. datetime(2025-07-31))
| where DeviceName contains "nathan-iel-vm"
| where ProcessCommandLine contains "wevtutil"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, ProcessCreationTime,InitiatingProcessCommandLine , InitiatingProcessCreationTime, SHA256
```
<img width="1263" height="773" alt="Screenshot 2025-08-17 223624" src="https://github.com/user-attachments/assets/af5db852-e1c5-4ff3-8919-aef0a6baa225" />



---

🚩 **Flag 15 – Final Cleanup and Exit Prep**  
🎯 **Objective:** Capture the combination of anti‑forensics actions signaling attacker exit.  
📌 **Finding (answer):** **2025-07-19T06:18:38.6841044Z**  
🔍 **Evidence:**  
- **File:** `EmptySysmonConfig.xml`  
- **Path:** `C:\Temp\EmptySysmonConfig.xml`  
- **Host:** nathan-iel-vm · **Initiating:** powershell.exe  
💡 **Why it matters:** Blinds Sysmon to suppress detection just prior to exit; ties off anti‑forensics chain.
**KQL Query Used:**
```
DeviceFileEvents
| where Timestamp between (datetime(2025-07-18) .. datetime(2025-07-31))
| where DeviceName contains "nathan-iel-vm"
| where FileName in ("ConsoleHost_history.txt","EmptySysmonConfig.xml","HRConfig.json")
| sort by Timestamp desc
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine
```
<img width="445" height="233" alt="Screenshot 2025-08-17 224226" src="https://github.com/user-attachments/assets/6334babb-6839-4281-b025-74346f5623e9" />


---

## MITRE ATT&CK (Quick Map)
- **Execution:** T1059 (PowerShell) – Flags 1–5, 7–8  
- **Persistence:** T1547.001 (Run Keys) – Flag 11  
- **Discovery:** T1033/T1087 (whoami /all; group/user discovery) – Flags 1–3, 4  
- **Credential Access:** T1003.001 (LSASS dump) – Flag 7 (MiniDump via comsvcs.dll)  
- **Command & Control / Exfil:** T1071/T1041 – Flags 9–10 (pipedream.net, .net TLD, IP 52.54.13.125)  
- **Defense Evasion:** T1562.001/002 & T1070.001 – Flags 5–6 (Defender), 14–15 (log clear, Sysmon blind)

---

## Recommended Actions (Condensed)
1. Reset/rotate credentials (HR/IT/admin).  
2. Re-enable & harden Defender; deploy fresh Sysmon config.  
3. Block/monitor `*.pipedream.net` and related IPs (e.g., **52.54.13.125**).  
4. Integrity review/restore HR data (`PromotionCandidates.csv`, Carlos Tanaka records).  
5. Hunt for persistence across estate; remove `OnboardTracker.ps1` autoruns.  
6. Centralize logs; add detections for `comsvcs.dll, MiniDump` and Defender tamper.
