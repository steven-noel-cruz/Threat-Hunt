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

<img width="605" height="146" alt="Screenshot 2025-11-16 090251" src="https://github.com/user-attachments/assets/dafd4bac-bfff-4102-8011-e9ce68f942e1" />

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
### Flag Answer
<img width="772" height="138" alt="Screenshot 2025-11-16 090638" src="https://github.com/user-attachments/assets/79879602-da87-4cf2-be00-dc49ef8e58db" />

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
<img width="585" height="442" alt="Screenshot 2025-11-16 091038" src="https://github.com/user-attachments/assets/92120389-5588-4db0-af84-3f2579179b9d" />

``` DefenderTamperArtifact.lnk ```

---

## Flag 4 – Quick Data Probe (Clipboard Access)

### Objective
Identify short-lived actions that attempt to gather easily accessible, high-value data such as clipboard contents. These probes often occur early in an intrusion as attackers look for credentials, tokens, or other sensitive information requiring minimal effort to obtain.

### Finding
The actor executed a PowerShell command designed to silently read the clipboard. This was a brief, opportunistic action consistent with early-stage reconnaissance and “quick win” data collection.

### Evidence
The following command was executed on **gab-intern-vm**:

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
<img width="758" height="257" alt="Screenshot 2025-11-16 091417" src="https://github.com/user-attachments/assets/54f5b26b-941f-4509-b404-7a2f406cdbb7" />

``` powershell.exe -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }" ```

---

## Flag 5 – Host Context Recon (Session Enumeration)

### Objective
Identify reconnaissance activity that gathers basic host and user context—specifically attempts to determine which sessions are active on the system. Attackers often use session enumeration to assess whether a user is present, whether the machine is safe to operate on, and whether privilege escalation opportunities are tied to active sessions.

### Finding
The actor executed **qwinsta**, a command used to list active terminal sessions. This provided the attacker with details about logged-in accounts, session states, and potential interactive users.

The **last** recon attempt occurred at:

**2025-10-09T12:51:44.3425653Z**

### Evidence
- `qwinsta.exe` was executed from **gab-intern-vm** within the intrusion window.
- This command enumerates:
  - Session IDs  
  - Username  
  - Session state (active/disconnected)  
  - Session type (console/RDP)  
- Execution aligned directly after clipboard probing and before privilege enumeration, matching a typical recon flow.

### Query Used
```
let T0 = datetime(2025-10-01);
let T1 = datetime(2025-10-30);
DeviceProcessEvents
| where DeviceName == @"gab-intern-vm"
| where TimeGenerated between (T0 .. T1)
| where ProcessCommandLine contains "qwi"
| order by TimeGenerated asc
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessCommandLine
```
### Why This Matters

Session enumeration is a reliable early indicator of malicious reconnaissance. It supports attacker objectives such as:

- Identifying if the user is currently active

- Determining the safety window for further operations

- Confirming remote session availability

- Planning persistence or lateral movement steps based on active user context

When combined with clipboard probing and privilege checks, this forms a complete reconnaissance triad.

Flag Answer
<img width="456" height="110" alt="Screenshot 2025-11-16 091741" src="https://github.com/user-attachments/assets/1724fb41-9ca7-41d2-aa30-875d23659b1c" />

``` 2025-10-09T12:51:44.3425653Z ```

---

## Flag 6 – Storage Surface Mapping (Logical Disk Enumeration)

### Objective
Detect reconnaissance activity that enumerates local storage devices, available free space, and mounted volumes. Attackers perform this step to understand where data can be stored, staged, or exfiltrated from.

### Finding
The actor executed a WMIC command to enumerate logical disks and their free space. This represents a deliberate check of storage surfaces, often performed before staging artifacts or preparing exfiltration bundles.

The second command tied to this activity was:

**`"cmd.exe" /c wmic logicaldisk get name,freespace,size"`**

### Evidence
- Command enumerated all logical drives (C:, D:, network shares, removable media).
- Output reveals available free space, which attackers use to determine:
  - Where to write temp files
  - Where to place ZIP archives
  - Whether the disk has enough room for staged artifacts
- This action occurred shortly before ZIP bundle creation (`ReconArtifacts.zip`).

### Query Used
```
DeviceProcessEvents
| where ProcessCommandLine contains "wmic"
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-30))
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessCommandLine, AccountName
| order by TimeGenerated asc
```

### Why This Matters

Storage enumeration is a common discovery technique used to:

- Identify writable locations (Public folders, user profiles)

- Select staging directories for exfiltration

- Assess constraints for large file creation or compression tasks

This behavior strongly aligns with pre-exfiltration reconnaissance and is commonly observed in hands-on intrusion workflows.

### Flag Answer
<img width="592" height="313" alt="Screenshot 2025-11-16 092123" src="https://github.com/user-attachments/assets/95985208-1cc7-41fd-8b52-cfbc739e6d3a" />

``` "cmd.exe" /c wmic logicaldisk get name,freespace,size" ```

---

## Flag 7 – Connectivity & Name Resolution Check

### Objective
Identify activity that verifies the system’s ability to resolve domain names and communicate with external hosts. Attackers commonly perform lightweight connectivity tests before attempting data exfiltration or command-and-control communication.

### Finding
Outbound network activity originated from a process whose parent was **RuntimeBroker.exe**, indicating that the execution chain leveraged a user-context process often associated with application mediation. The initiating parent process identified was:

**RuntimeBroker.exe**

### Evidence
- Outbound requests to HTTP port 80 were observed.
- Requests included known connectivity test domains (`msftconnecttest.com`), indicating resolution and egress validation.
- The parent process recorded for the suspicious PowerShell-driven outbound check was `RuntimeBroker.exe`.
- This aligns with the actor testing network availability before staging and exfiltration.

### Query Used
```
let T0 = datetime(2025-10-01);
let T1 = datetime(2025-10-15);
DeviceNetworkEvents
| where DeviceName =~ "gab-intern-vm" 
| where TimeGenerated between (T0 .. T1)
| where RemotePort == "80"
| where RemoteUrl != ""
| where InitiatingProcessAccountName == "g4bri3lintern"
| project TimeGenerated, RemotePort, RemoteUrl, DeviceName, 
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName
```

### Why This Matters

Connectivity checks commonly precede:

-Exfiltration attempts

-Command-and-control communication

-Remote payload staging

-Beaconing behavior

The use of RuntimeBroker.exe in the parent chain helps attackers blend into legitimate application workflows and reduces detection visibility.

### Flag Answer
<img width="556" height="443" alt="Screenshot 2025-11-16 094448" src="https://github.com/user-attachments/assets/54f8383c-b822-4cf6-895a-f6a34df755c7" />


``` RuntimeBroker.exe ```

---

## Flag 8 – Interactive Session Discovery (Initiating Process Unique ID)

### Objective
Identify activity used to determine whether interactive or active user sessions are present on the system. Attackers perform this check to understand whether the endpoint is currently in use, which influences timing and stealth for subsequent actions.

### Finding
Session enumeration commands such as `query user`, `query session`, `qwinsta`, and `quser` were executed on **gab-intern-vm**.  
The **unique ID of the initiating process chain** responsible for this activity was:

**2533274790397065**

### Evidence
- Multiple session discovery commands were observed within the intrusion window.
- These commands list current sessions, their states (Active/Disc), and session types.
- The process chain for these recon commands led back to a single initiating process, uniquely identified by the `InitiatingProcessUniqueId` field.
- This recon activity occurred shortly before privilege enumeration and storage mapping, matching known attacker workflow patterns.

### Query Used
```
let T0 = datetime(2025-10-09);
let T1 = datetime(2025-10-15);
let needles = dynamic(["query user","quser","query session","qwinsta","session","whoami /all","tasklist"]);
DeviceProcessEvents
| where DeviceName =~ "gab-intern-vm"
| where TimeGenerated between (T0 .. T1)
| where ProcessCommandLine has_any (needles)
| project
    TimeGenerated,
    DeviceName,
    ProcessCommandLine,
    InitiatingProcessUniqueId,
    InitiatingProcessCommandLine,
    InitiatingProcessFileName
| order by TimeGenerated asc
```
### Why This Matters

Session enumeration is a high-value signal of interactive intrusion because it enables attackers to:

-Detect whether a human is currently active on the device

-Avoid performing noisy actions during active usage

-Determine whether elevated sessions are present

-Tailor persistence mechanisms to the user’s login patterns

Tracking the initiating process ID helps correlate this behavior to later persistence and data staging events.

### Flag Answer
<img width="1204" height="341" alt="Screenshot 2025-11-16 095223" src="https://github.com/user-attachments/assets/b2a327f2-6c34-45ab-91dd-1ef2fd010eca" />

```2533274790397065```

---
## Flag 9 – Runtime Application Inventory (Process Enumeration)

### Objective
Identify activity that enumerates running processes or services on the host. Attackers commonly perform this step to understand what security tools are active, what applications are running, and whether any obstacles exist for further operations.

### Finding
The actor executed **`tasklist.exe`**, a Windows-native utility used to enumerate all running processes. This activity occurred after privilege and session reconnaissance, consistent with an attacker building situational awareness on the host.

The process that best demonstrated runtime process enumeration was:

**tasklist.exe**

### Evidence
- `tasklist.exe` was observed on **gab-intern-vm** during the intrusion window.
- This command provides a full list of running processes, their PIDs, memory usage, and service associations.
- The command execution closely followed session and privilege enumeration, further validating an intentional reconnaissance phase.

### Query Used
```kql
let T0 = datetime(2025-10-09);
let T1 = datetime(2025-10-15);
let needles = dynamic(["query user","quser","query session","qwinsta","session","whoami /all","tasklist"]);
DeviceProcessEvents
| where DeviceName =~ "gab-intern-vm"
| where TimeGenerated between (T0 .. T1)
| where ProcessCommandLine has_any (needles)
| project TimeGenerated, DeviceName, ProcessCommandLine,
          InitiatingProcessUniqueId, InitiatingProcessCommandLine,
          InitiatingProcessFileName, ProcessVersionInfoFileDescription
| order by TimeGenerated asc
```
### Why This Matters

Process enumeration is commonly used to:

-Identify active security tools

-Detect monitoring agents

-Confirm whether defensive processes can be bypassed

-Map high-value processes related to credentials or sensitive data

-Prepare for persistence, injection, or exploitation

In this scenario, the process inventory aligns with the actor’s methodical reconnaissance flow.

### Flag Answer

<img width="588" height="258" alt="image" src="https://github.com/user-attachments/assets/45e46f46-377f-49e6-92a7-e0a1dd328454" />

``` tasklist.exe ```

---

## Flag 10 – Privilege Surface Check (User & Group Enumeration)

### Objective
Identify attempts to enumerate the current user’s privilege level, group membership, and available security tokens. Attackers routinely perform this step early in an intrusion to determine whether privilege escalation is necessary.

### Finding
The actor executed the Windows-native command:

``` whoami /groups ```


This command reveals all security groups associated with the current account and is commonly used to assess available privileges.  
The **first** privilege enumeration event occurred at:

**2025-10-09T12:52:14.3135459Z**

### Evidence
- `whoami /groups` was executed shortly after session enumeration (`qwinsta`).
- This positions the activity directly within the reconnaissance phase of the intrusion.
- The command provided the actor with insight into privilege level, token groups, and potential escalation paths.
- The timestamp represents the earliest privilege-mapping activity on the host.

### Query Used
```kql
let T0 = datetime(2025-10-09);
let T1 = datetime(2025-10-15);
DeviceProcessEvents
| where DeviceName =~ "gab-intern-vm"
| where TimeGenerated between (T0 .. T1)
| where ProcessCommandLine has_any ("whoami /all","whoami /groups","whoami /priv","whoami")
| project TimeGenerated, FileName, ProcessId, ProcessCommandLine,
          InitiatingProcessFileName, ReportId
| order by TimeGenerated asc
| take 1
```
### Why This Matters

Privilege enumeration is a strong indicator of malicious intent because it:

Helps attackers determine what access they currently have

Identifies token privileges (SeDebugPrivilege, SeBackupPrivilege, etc.)

Reveals whether the user belongs to administrative or delegated groups

Guides next steps such as persistence, credential access, or lateral movement

The timing of this event—immediately after session recon—aligns with typical attacker workflow.

### Flag Answer

<img width="451" height="162" alt="Screenshot 2025-11-16 100320" src="https://github.com/user-attachments/assets/9cf77afc-4d56-4211-8a42-d2af538de273" />


``` 2025-10-09T12:52:14.3135459Z ```

---







