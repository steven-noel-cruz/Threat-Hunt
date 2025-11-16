# Introduction

Between **October 1–15, 2025**, anomalous activity was identified across several user endpoints within the organization. Multiple machines were observed executing files directly from the **Downloads** directory—a behavior that does not align with normal operational patterns. Several of these files shared similar naming conventions incorporating keywords such as **“support,” “help,” “tool,”** and **“desk,”** suggesting a coordinated theme or intentional staging rather than accidental execution.

Among the systems reviewed, **gab-intern-vm** displayed the earliest and most significant indicators of compromise. This machine became the focal point of the investigation based on:

- The earliest recorded execution of suspicious tooling  
- Repeated untrusted process activity originating from user-controlled paths  
- Correlation to initial threat intelligence indicating intern-operated machines were affected  

This report reconstructs the intrusion sequence, correlates observed behaviors with MITRE ATT&CK techniques, and evaluates whether these actions represent benign activity, misconfiguration, or malicious intent.

---

# Scenario Overview

What initially appeared to be a normal remote support session gradually revealed a pattern of actions inconsistent with legitimate troubleshooting. Instead of performing targeted remediation or diagnostics, the actor engaged in a series of operations typically observed during early-stage reconnaissance and host assessment.

During the investigation window, the actor’s activity included:

1. Executing support-themed scripts directly from the Downloads directory  
2. Gathering host and user context, including session enumeration  
3. Inspecting privilege levels and account configuration  
4. Probing transient data sources such as the clipboard  
5. Mapping available storage surfaces  
6. Verifying outbound connectivity for potential data exfiltration  
7. Creating ZIP-based staging artifacts in public directories  
8. Establishing persistence through scheduled tasks and autorun registry entries  
9. Planting narrative files designed to justify or obscure prior actions  

Artifacts such as **DefenderTamperArtifact.lnk** and **SupportChat_log.lnk** suggest an intentional effort to fabricate a plausible explanation for the observed behaviors, masking malicious operations under the guise of “remote assistance.”

The observed pattern aligns with an adversary leveraging support-themed nomenclature to reduce suspicion, while conducting reconnaissance, staging data, and establishing multiple forms of persistence to maintain long-term access.

---

# Full Timeline

| Time (UTC) | Flag | Stage | Event / Artifact |
|------------|-------|--------|------------------|
| 12:22 | **Flag 1** | Starting Point | Most suspicious machine identified → `gab-intern-vm` |
| 12:34 | **Flag 2** | Defense Deception | Tamper decoy artifact created → `DefenderTamperArtifact.lnk` |
| 12:22 | **Flag 1/Entry Context** | Initial Execution | `SupportTool.ps1` launched from Downloads (`-ExecutionPolicy`) |
| 12:50 | **Flag 3** | Data Probe | Clipboard accessed via PowerShell (`Get-Clipboard`) |
| 12:51 | **Flag 4 & Flag 7** | Session Recon | `qwinsta` executed to enumerate active sessions |
| 12:52 | **Flag 9** | Privilege Recon | `whoami /groups` executed |
| 12:53 | **Flag 5** | Storage Mapping | `wmic logicaldisk get name,freespace,size` |
| 12:55 | **Flag 6 & Flag 10** | Egress Check | First outbound connection → `www.msftconnecttest.com` |
| 12:56 | **Flag 8** | Runtime Inventory | `tasklist.exe` executed |
| 12:58 | **Flag 11** | Staging | `C:\Users\Public\ReconArtifacts.zip` created |
| 12:59 | **Flag 12** | Exfil Attempt | Outbound connection attempted → `100.29.147.161` |
| 13:01 | **Flag 13** | Persistence | Scheduled task created → `SupportToolUpdater` |
| 13:01–13:02 | **Flag 14** | Fallback Persistence | Autorun entry created → `RemoteAssistUpdater` |
| 13:02 | **Flag 15** | Misdirection | Narrative artifact created → `SupportChat_log.lnk` |

---

# Flag-by-Flag Findings

## Flag 0 – Starting Point Identification

### Objective
Determine which machine should be the primary focus of the threat hunt based on early indicators, file naming patterns, and activity observed in the first half of October. The goal is to identify the endpoint most likely associated with the initial execution of suspicious support-themed tooling.

### Finding
The earliest and most relevant suspicious activity was traced to **gab-intern-vm**, which showed:
- Execution of support-themed tooling from the **Downloads** directory  
- Early-October activity matching the intel provided  
- File naming patterns (“support,” “tool”) consistent with other affected hosts  
- The presence of artifacts linked to subsequent stages of the intrusion  

### Evidence
Within the date window of October 1–15, 2025, only **gab-intern-vm** recorded:
- A `SupportTool.ps1` file in the Downloads folder  
- Multiple process executions originating from this file  
- Matches to keyword indicators: *support*, *tool*, *help*, *desk*  

<img width="605" height="146" alt="Screenshot 2025-11-16 090251" src="https://github.com/user-attachments/assets/dafd4bac-bfff-4102-8011-e9ce68f942e1" />


The distribution of hosts in the dataset indicated this system was the earliest and most consistently associated with suspicious file execution.

### Query Used
```
let T0 = datetime(2025-10-01);
let T1 = datetime(2025-10-15);
DeviceFileEvents
| where TimeGenerated between (T0 .. T1)
| where FileName contains "support"
  and FileName contains "tool"
  and FolderPath contains "Download"
| summarize Hosts = make_set(DeviceName), Count = dcount(DeviceName)
    by FileName, SHA256, FileSize
| sort by Count desc
```
### Why This Matters
Identifying the correct starting point is critical in a threat hunt.
It establishes:
- The earliest confirmed execution of malicious tooling
- The logical origin of the intrusion timeline
- The baseline from which all subsequent activity can be reconstructed
Choosing the wrong starting system leads to incomplete or misleading analysis, so Flag 1 acts as the anchor for the full investigation.

### Flag Answer
``` gab-intern-vm ```

---
## Flag 1 – Earliest Anomalous Execution (Execution Policy Parameter)

### Objective
Identify the earliest unusual execution event that could represent the initial entry point of the intrusion. The focus is on detecting atypical script execution behavior originating from untrusted paths, particularly the user’s Downloads directory.

### Finding
The earliest suspicious execution occurred when the user on **gab-intern-vm** launched `SupportTool.ps1` using PowerShell with the **`-ExecutionPolicy`** parameter.  
This parameter was the **first CLI switch** observed in the malicious command line.

### Evidence
- The script `SupportTool.ps1` was executed directly from the **Downloads** directory.  
- The command line included the parameter:  
- This is consistent with attempts to run unsigned or untrusted scripts without policy restrictions.
- The timestamp places this as the first anomalous execution within the investigation window.

<img width="772" height="138" alt="Screenshot 2025-11-16 090638" src="https://github.com/user-attachments/assets/79879602-da87-4cf2-be00-dc49ef8e58db" />


### Query Used
```
let T0 = datetime(2025-10-01);
let T1 = datetime(2025-10-15);
DeviceProcessEvents
| where DeviceName == @"gab-intern-vm"
| where ProcessCommandLine contains "SupportTool.ps1"
| where TimeGenerated between (T0 .. T1)
| extend FirstSwitch = extract(@"[\/\-]([A-Za-z0-9_\-]+)", 1, ProcessCommandLine)
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, FirstSwitch
| order by TimeGenerated asc
```

### Why This Matters

Execution policy bypasses are common in:

- Initial access

- Script-based payload delivery

- Living-off-the-land tradecraft

- Reducing PowerShell’s built-in security friction

- Identifying the first CLI parameter used allows analysts to:

- Anchor the attack timeline

- Validate the method of execution

- Confirm that the script was intentionally allowed to circumvent security controls

This flag represents the initial foothold in the attack sequence.

``` -ExecutionPolicy ```

---

## Flag 2 – Defense Disabling (Simulated Tamper Indicator)

### Objective
Identify any artifacts or events that suggest the actor attempted to imply, simulate, or stage security posture changes—specifically actions that appear to disable or tamper with security controls without actually modifying them.

### Finding
A suspicious shortcut file named **DefenderTamperArtifact.lnk** was discovered on **gab-intern-vm**.  
This file was **manually accessed via Explorer.exe**, indicating that the actor intentionally opened it.  
No real Defender configuration changes occurred; the file served as a planted decoy.

### Evidence
- `DefenderTamperArtifact.lnk` was created and accessed during the intrusion window.  
- The shortcut’s naming convention implies Defender tamper actions, but:
  - No changes were logged in Defender configuration or registry keys.
  - No corresponding tampering commands (e.g., `Set-MpPreference`) were executed.
- Access via **Explorer.exe** supports that the file was intentionally opened, likely to reinforce the deception narrative.

<img width="585" height="442" alt="Screenshot 2025-11-16 091038" src="https://github.com/user-attachments/assets/92120389-5588-4db0-af84-3f2579179b9d" />


### Query Used
```
let T0 = datetime(2025-10-01);
let T1 = datetime(2025-10-30);
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (T0 .. T1)
| project TimeGenerated, FileName, InitiatingProcessCommandLine
| where InitiatingProcessCommandLine == "Explorer.EXE"
```

### Why This Matters

Staged artifacts like fake tamper files are common in intrusion playbooks designed to:
- Distract analysts
- Inflate the perceived scope of compromise
- Justify other suspicious activity as “troubleshooting”
- Create a false trail that implies IT or support involvement
Recognizing planted artifacts helps distinguish actual tampering from intentional misdirection, improving investigative accuracy.

### Flag Answer
``` DefenderTamperArtifact.lnk ```

---

## Flag 4 – Quick Data Probe (Clipboard Access)

### Objective
Identify short-lived actions that attempt to gather easily accessible, high-value data such as clipboard contents. These probes often occur early in an intrusion as attackers look for credentials, tokens, or other sensitive information requiring minimal effort to obtain.

### Finding
The actor executed a PowerShell command designed to silently read the clipboard. This was a brief, opportunistic action consistent with early-stage reconnaissance and “quick win” data collection.

### Evidence
The following command was executed on **gab-intern-vm**:

<img width="758" height="257" alt="Screenshot 2025-11-16 091417" src="https://github.com/user-attachments/assets/54f5b26b-941f-4509-b404-7a2f406cdbb7" />


- The command suppresses errors and returns no output, indicating covert intent.
- The use of `-NoProfile` and `-Sta` reduces detection opportunities.
- Clipboard access is a known tradecraft method for capturing credentials copied during authentication.

### Query Used
```
let T0 = datetime(2025-10-01);
let T1 = datetime(2025-10-15);
DeviceProcessEvents
| where DeviceName == @"gab-intern-vm"
| where TimeGenerated between (T0 .. T1)
| order by TimeGenerated asc
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| where ProcessCommandLine contains "clip"
```
### Why This Matters

Clipboard data frequently contains:

- Passwords

- MFA codes

- SSO tokens

- PII and sensitive business data

Attackers routinely check the clipboard early because:

- It is low-effort

- It avoids writing files

- It requires no elevated privileges

- It can reveal immediate value without deeper exploration

Detecting clipboard access helps identify early insight-gathering behaviors that precede more intrusive operations.

### Flag Answer

``` powershell.exe -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }" ```
