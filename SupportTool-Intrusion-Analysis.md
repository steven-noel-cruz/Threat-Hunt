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

- Helps attackers determine what access they currently have

- Identifies token privileges (SeDebugPrivilege, SeBackupPrivilege, etc.)

- Reveals whether the user belongs to administrative or delegated groups

- Guides next steps such as persistence, credential access, or lateral movement

The timing of this event—immediately after session recon—aligns with typical attacker workflow.

### Flag Answer

<img width="451" height="162" alt="Screenshot 2025-11-16 100320" src="https://github.com/user-attachments/assets/9cf77afc-4d56-4211-8a42-d2af538de273" />


``` 2025-10-09T12:52:14.3135459Z ```

---

## Flag 11 – Proof of Access & Egress Validation (First Outbound Destination)

### Objective
Identify network activity that demonstrates both the ability to reach external destinations and the intent to validate outbound communication pathways. Attackers frequently perform lightweight outbound checks before attempting exfiltration or command-and-control communication.

### Finding
The first outbound network destination contacted during the intrusion window was:

**www.msftconnecttest.com**

This domain is commonly used by Windows to validate internet connectivity, making it an ideal covert method for attackers to blend egress checks with benign-looking traffic.

### Evidence
- Outbound HTTP traffic to `www.msftconnecttest.com` was observed immediately after reconnaissance and system mapping.
- The activity originated from user-context PowerShell execution.
- No other suspicious outbound connections preceded this one.
- The timing aligns with typical pre-exfiltration validation behavior.

### Query Used
```
DeviceNetworkEvents
| where DeviceName =~ "gab-intern-vm"
| where InitiatingProcessCommandLine !contains "exfiltrate"
| where InitiatingProcessCommandLine !contains "portscan"
| where InitiatingProcessCommandLine !contains "crypt"
| where InitiatingProcessCommandLine !contains "eicar"
| where TimeGenerated between (datetime(2025-10-09) .. datetime(2025-10-10))
| where InitiatingProcessFileName in~ ("powershell.exe","cmd.exe")
| project TimeGenerated, RemoteUrl, RemoteIP, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

### Why This Matters

Outbound connectivity checks:

- Confirm the host can reach the internet

- Validate whether HTTP/HTTPS egress is permitted

- Allow attackers to test resolution and routing without raising suspicion

- Precede exfiltration attempts and C2 beacons

- Help the attacker map which ports, domains, and protocols are allowed out of the network

Using a legitimate Windows connectivity-test domain helps attackers avoid triggering alerts.

### Flag Answer

<img width="942" height="286" alt="Screenshot 2025-11-16 100522" src="https://github.com/user-attachments/assets/1e2b365f-2c4a-4150-bd15-725b20f45910" />


``` www.msftconnecttest.com ```

---

## Flag 12 – Artifact Staging (Recon Data Bundled)

### Objective
Identify actions that consolidate reconnaissance outputs or collected artifacts into a single location or compressed package. This typically occurs immediately before an exfiltration attempt.

### Finding
The actor created a ZIP archive named **ReconArtifacts.zip** in the **Public** user directory.  
This file represents the staging of collected data in preparation for transfer.

The full path of the staged artifact was:

**C:\Users\Public\ReconArtifacts.zip**

### Evidence
- A `.zip` file was created within the intrusion window.
- The archive was written to a globally accessible directory (`C:\Users\Public`), suggesting the attacker wanted:
  - predictable write access  
  - broad permissions  
  - a location unlikely to be monitored by the user  
- This activity directly preceded an attempted outbound connection to an external IP address.

### Query Used
```
DeviceFileEvents
| where DeviceName =~ "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-09) .. datetime(2025-10-10))
| where FileName contains "zip"
| where InitiatingProcessAccountDomain == "gab-intern-vm"
| project TimeGenerated, DeviceName, ActionType, InitiatingProcessAccountName, FileName, FolderPath
```
### Why This Matters

Staging is a critical indicator of malicious behavior because it:

- Shows clear preparation for data exfiltration

- Represents deliberate collection and packaging of reconnaissance data

- Often serves as the final step before an upload attempt

- Provides strong evidence of intent even if the exfiltration fails

ZIP-based staging is a common tradecraft technique for both threat actors and red teams.

### Flag Answer

<img width="1523" height="187" alt="Screenshot 2025-11-16 100825" src="https://github.com/user-attachments/assets/f8d29e43-0b9d-4a18-a1bc-369fe742d328" />


```C:\Users\Public\ReconArtifacts.zip```

---

## Flag 13 – Outbound Transfer Attempt (Simulated Exfiltration)

### Objective
Identify any network activity indicating an attempt to move staged data off the host. Even if the upload fails, outbound transfer attempts demonstrate malicious intent and confirm that the actor is testing or actively using egress channels.

### Finding
The actor attempted an outbound connection to the external IP:

**100.29.147.161**

This connection occurred shortly after the creation of the `ReconArtifacts.zip` staging file, indicating a simulated or attempted exfiltration step.

### Evidence
- Network telemetry shows an outbound HTTP request from **gab-intern-vm** to `100.29.147.161`.
- The initiating process was a PowerShell execution under the user `g4bri3lintern`.
- No successful file upload was confirmed, but the attempt itself demonstrates intent to exfiltrate.
- The timing aligns directly after the ZIP bundling activity, forming a complete exfil attempt chain.

### Query Used
```
DeviceNetworkEvents
| where DeviceName =~ "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-09) .. datetime(2025-10-10))
| where InitiatingProcessCommandLine == "\"powershell.exe\" "
| where InitiatingProcessAccountName == "g4bri3lintern"
| project TimeGenerated, DeviceName, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessCommandLine
```

### Why This Matters

Outbound transfer attempts are critical indicators because they:

- Reveal the adversary’s intention to remove data from the environment

- Validate the attacker’s reconnaissance and staging phases

- Identify which external services or IPs are being used as exfil endpoints

- Provide valuable indicators for network containment and monitoring

- Demonstrate the ability to perform outbound communication despite security controls

Even a failed exfil attempt confirms the actor reached the final stages of a typical intrusion workflow.

### Flag Answer

<img width="1203" height="132" alt="Screenshot 2025-11-16 102855" src="https://github.com/user-attachments/assets/23c3c927-f934-43e0-87a8-3451a0e70005" />


``` 100.29.147.161 ``` 

---

## Flag 14 – Scheduled Re-Execution Persistence (Scheduled Task Creation)

### Objective
Identify mechanisms that ensure the attacker’s tooling will automatically run again after a reboot or user sign-in. Scheduled tasks are a common persistence method because they do not require elevated privileges if created under a user context.

### Finding
The actor created a scheduled task named:

**SupportToolUpdater**

This task is configured to trigger at logon, ensuring the malicious support-themed tooling re-executes automatically on each user session.

### Evidence
- `schtasks.exe` was executed with the `/Create` parameter.
- The task name clearly follows the attacker’s “support” narrative theme.
- This persistence mechanism was set shortly after reconnaissance and artifact staging.
- The timing of this event indicates deliberate preparation for long-term access.

Example matching activity:

``` "schtasks.exe" /Create /SC ONLOGON /TN SupportToolUpdater /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\Users\g4bri3lintern\Downloads\SupportTool.ps1"" /RL LIMITED /F  ```


### Query Used
```
DeviceProcessEvents
| where DeviceName =~ "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-09) .. datetime(2025-10-15))
| where ProcessCommandLine contains "Create"
| where FileName contains "schtasks"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
```
### Why This Matters

Scheduled task persistence is widely used by attackers because it:

- Survives reboots and logouts

- Executes under the user context, reducing detection

- Mimics legitimate administrative behavior

- Requires no advanced evasion techniques

- Fits into support-themed deception (naming looks “helpdesk-like”)

The name SupportToolUpdater reinforces the attacker’s narrative and blends malicious persistence into what appears to be routine support maintenance.

### Flag Answer

<img width="931" height="143" alt="Screenshot 2025-11-16 103130" src="https://github.com/user-attachments/assets/ca5471f8-39e5-45e2-a8f5-8cb0f264ca1d" />


``` SupportToolUpdater ```

---

## Flag 15 – Autorun Fallback Persistence (Registry-Based Startup Entry)

### Objective
Identify lightweight persistence mechanisms created under the user context, specifically autorun entries in the registry or startup directory. These serve as backup mechanisms designed to execute malicious tooling even if primary persistence methods are removed.

### Finding
A user-scope autorun registry value named:

**RemoteAssistUpdater**

was identified as the fallback persistence mechanism.  
Although the relevant telemetry had rolled out of retention, the CTF administrator confirmed that this was the intended registry value captured during the scenario.

### Evidence
- No autorun registry events were present in current telemetry due to log retention limits.
- Behavior aligns with the attack pattern:
  - Support-themed naming convention  
  - Tied directly to execution of SupportTool.ps1  
  - Established shortly after scheduled task creation  
- Registry autoruns are commonly used for:
  - User-context persistence  
  - Low-privilege persistence  
  - Backup execution of tooling if scheduled tasks fail  
  - Blending into IT-support workflows  

### Query Used
_The expected table returned no results due to data retention expiration, as acknowledged in scenario instructions._

If logs were present, the hunt would rely on:

```kql
DeviceRegistryEvents
| where DeviceName == "gab-intern-vm"
| where RegistryKey contains "Run"
| where RegistryValueName contains "Assist" or RegistryValueName contains "Support"
```

### Why This Matters

Registry autoruns are highly reliable and stealthy persistence mechanisms because:

- They do not require administrative rights

- They execute at each user logon

- They integrate into legitimate Windows behavior

- They avoid creating obvious scheduled tasks

- They are rarely monitored in non-hardened environments

In this intrusion, RemoteAssistUpdater mirrors the support-themed deception used throughout the attack chain, reinforcing the actor’s attempt to disguise persistence as legitimate remote support activity.

### Flag Answer

``` RemoteAssistUpdater ```

---

## Flag 16 – Planted Narrative / Cover Artifact

### Objective
Identify any artifacts deliberately created to justify, disguise, or mislead investigators regarding the nature of the suspicious activity. These “narrative” files are often designed to mimic legitimate IT support artifacts.

### Finding
A shortcut file named:

**SupportChat_log.lnk**

was discovered and accessed on **gab-intern-vm**.  
The file’s presence and naming strongly suggest a staged attempt to fabricate a narrative of a legitimate support session, aligning with the attacker’s support-themed deception.

### Evidence
- `SupportChat_log.lnk` was created under the **Recent** directory: `C:\Users\g4bri3lintern\AppData\Roaming\Microsoft\Windows\Recent\`
- The shortcut was opened via `Explorer.exe`, indicating intentional viewing.
- The timing of the artifact correlates directly with:
- Reconnaissance  
- Data staging  
- Persistence creation  
- The name “SupportChat_log” implies a support transcript or troubleshooting log, meant to obscure malicious intent.

### Query Used
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-10-09) .. datetime(2025-10-10))
| where DeviceName =~ "gab-intern-vm"
| where InitiatingProcessAccountName == "g4bri3lintern"
| where InitiatingProcessFileName contains "explorer"
| project TimeGenerated, ActionType, DeviceName, FileName,
        InitiatingProcessFileName, FolderPath
```

### Why This Matters

Planted artifacts are a hallmark of attackers attempting to blend into legitimate workflows. This technique:

- Establishes a false explanation for observed activity

- Reduces suspicion for high-risk commands executed earlier

- Suggests a support-related context to justify reconnaissance and persistence

- Can mislead inexperienced analysts or automated triage systems

- Aligns with long-term persistence by normalizing suspicious actions

The use of a fake “support chat log” directly reinforces the actor’s overarching theme of impersonating remote assistance.

### Flag Answer

<img width="910" height="850" alt="Screenshot 2025-11-16 104957" src="https://github.com/user-attachments/assets/9a73805b-9f64-4fd4-9855-c17a2e089431" />


``` SupportChat_log.lnk ```

---

# MITRE ATT&CK Mapping

The following table maps the observed behaviors during the SupportTool intrusion to relevant MITRE ATT&CK techniques. Techniques were selected based on confirmed telemetry, tool usage, and the attacker’s workflow across execution, discovery, persistence, and exfiltration phases.

| Flag | Tactic | Technique | ID | Description |
|------|--------|-----------|----|-------------|
| 1 | Recon | Initial Target Identification | N/A | Identification of the starting point for threat analysis (not a MITRE technique). |
| 2 | Execution | Command and Scripting Interpreter: PowerShell | **T1059.001** | Execution of `SupportTool.ps1` with `-ExecutionPolicy` bypass. |
| 3 | Defense Evasion | Masquerading | **T1036** | Use of `DefenderTamperArtifact.lnk` to imply security tampering. |
| 4 | Credential Access | Clipboard Data | **T1115** | PowerShell command executed to retrieve clipboard contents. |
| 5 | Discovery | System Owner/User Discovery | **T1087** | Session enumeration (`qwinsta`) to identify active users. |
| 6 | Discovery | File and Directory Discovery | **T1083** | Disk enumeration using `wmic logicaldisk` to map storage surfaces. |
| 7 | Discovery | System Network Configuration Discovery | **T1016** | Outbound connectivity tests to validate external network access. |
| 7 | Command & Control | Application Layer Protocol | **T1071.001** | HTTP(S)-based outbound communication blending with legitimate traffic. |
| 8 | Discovery | Process Discovery | **T1057** | Runtime process listing using `tasklist.exe`. |
| 9 | Discovery | Permission Groups Discovery | **T1069** | `whoami /groups` used to enumerate privilege levels. |
| 10 | Discovery | System Network Connections Discovery | **T1049** | Outbound checks to `www.msftconnecttest.com`. |
| 10 | C2 / Exfil Prep | Exfiltration Over Unencrypted/Encrypted Channel | **T1041 / T1048** | Validation of outbound channels prior to exfiltration attempt. |
| 11 | Collection | Data Staged | **T1074** | Creation of `ReconArtifacts.zip` in `C:\Users\Public`. |
| 12 | Exfiltration | Exfiltration Over Web Services | **T1567.002** | Attempted outbound transfer to `100.29.147.161`. |
| 13 | Persistence | Scheduled Task | **T1053.005** | Task created (`SupportToolUpdater`) for logon persistence. |
| 14 | Persistence | Registry Run Keys/Startup Folder | **T1547.001** | Autorun entry created (`RemoteAssistUpdater`). |
| 15 | Defense Evasion | Misdirection / User Impersonation | **T1036.004** | Use of fake “SupportChat_log.lnk” to justify earlier activity. |

---

# MITRE Summary by Tactic

### **Execution**
- `T1059.001` – PowerShell execution via custom support script.

### **Privilege & Session Discovery**
- `T1087`, `T1069`, `T1049`, `T1016` – User, group, session, and network configuration discovery.

### **Defense Evasion**
- `T1036` / `T1036.004` – Decoy artifacts and support-themed misdirection.

### **Credential Access**
- `T1115` – Clipboard content probing.

### **Discovery**
- `T1083`, `T1057` – Storage and process enumeration.
- `T1016` – Network configuration validation.

### **Collection**
- `T1074` – Data staged in ZIP format.

### **Exfiltration**
- `T1567.002`, `T1041`, `T1048` – Outbound channel testing and simulated exfiltration.

### **Persistence**
- `T1053.005` – Scheduled task persistence.
- `T1547.001` – Autorun registry persistence.

---

# MITRE ATT&CK Narrative

The activity observed on **gab-intern-vm** aligns closely with multiple stages of the MITRE ATT&CK framework, particularly within the Execution, Discovery, Persistence, Defense Evasion, and Exfiltration tactics. The following narrative outlines how the attacker’s actions map to ATT&CK techniques and how those behaviors fit into a coherent intrusion chain.

The intrusion began with the execution of a support-themed PowerShell script (`SupportTool.ps1`) delivered and run from the **Downloads** directory. This behavior corresponds to **T1059.001 – PowerShell**, as the actor used command-line parameters (`-ExecutionPolicy Bypass`) to override built-in protections and execute untrusted code.

Immediately following initial execution, the actor conducted a series of **Discovery** activities. This included:

- **Clipboard probing** (`Get-Clipboard`) aligning with **T1115 – Clipboard Data**  
- **Session enumeration** using `qwinsta` and `quser`, aligning with **T1087 / T1033 – Account & System Owner/User Discovery**
- **Privilege inspection** using `whoami /groups`, mapping to **T1069 – Permission Groups Discovery**
- **Storage enumeration** using `wmic logicaldisk`, mapping to **T1083 – File and Directory Discovery**
- **Process enumeration** with `tasklist.exe`, matching **T1057 – Process Discovery**

These actions formed a structured recon phase intended to determine the system’s state, privileges, available data sources, and running defenses.

In parallel, the actor validated outbound connectivity using requests to **`www.msftconnecttest.com`**, blending real-world egress tests into routine system traffic. This activity maps to **T1046 – Network Service Scanning** and **T1016 – System Network Configuration Discovery**, supporting later exfiltration attempts.

The attacker then prepared for data removal through **staging**, compressing reconnaissance artifacts into `ReconArtifacts.zip` under the **Public** directory. This behavior aligns with **T1074 – Data Staged**, indicating intent to consolidate materials for transfer. This was followed by a simulated outbound transfer attempt to external IP **100.29.147.161**, mapping to **T1041 – Exfiltration Over C2 Channel** or **T1567.002 – Exfiltration to Cloud Storage** depending on the categorization used.

Persistence mechanisms were established through a scheduled task named **SupportToolUpdater**, mapping to **T1053.005 – Scheduled Task**, and a backup autorun entry **RemoteAssistUpdater**, mapping to **T1547.001 – Registry Run Keys / Startup Folder**. These dual persistence mechanisms ensured the malicious tooling would continue to run even after reboot or user logon.

Finally, the attacker deployed deceptive artifacts—**DefenderTamperArtifact.lnk** and **SupportChat_log.lnk**—designed to establish a false narrative of remote support assistance. This activity aligns with **T1036 – Masquerading**, as the attacker used naming and placement strategies to disguise malicious intent and mislead analysts.

Overall, the sequence of observed behaviors reflects a deliberate, methodical intrusion workflow involving initial execution, layered reconnaissance, persistence establishment, data staging, exfiltration validation, and deception—each mapping cleanly to well-defined MITRE ATT&CK techniques.

---

# After-Action Recommendations

The investigation into the support-themed intrusion on **gab-intern-vm** revealed several gaps in monitoring, configuration, and user security posture that enabled the attacker to execute reconnaissance, stage artifacts, and establish persistence. The following recommendations outline actionable steps to reduce the likelihood of similar incidents and strengthen endpoint resilience.

---

## 1. Enhance PowerShell Logging and Restrict Execution Policies

### Recommendation
Enable advanced PowerShell logging and prevent unverified scripts from running by default.

### Actions
- Enforce `AllSigned` or `RemoteSigned` execution policies via GPO.
- Enable:
  - Module Logging  
  - Script Block Logging  
  - PowerShell Transcription  
- Forward PowerShell logs to SIEM for real-time alerting.

### Rationale
The attacker used PowerShell with `-ExecutionPolicy` to bypass restrictions. Improved logging and enforcement would allow earlier detection and prevention of unauthorized script execution.

---

## 2. Harden User Download Folders and Block Script Execution

### Recommendation
Prevent execution of scripts directly from user-controlled directories such as `Downloads`.

### Actions
- Enforce WDAC (Windows Defender Application Control) or AppLocker policies:
  - Block `.ps1`, `.bat`, `.cmd` outside approved paths.
- Implement Protected Folders for high-risk directories.

### Rationale
The initial intrusion originated from a script executed directly from the Downloads folder. Blocking execution reduces common user-error attack paths.

---

## 3. Improve Endpoint Protection Configuration and Detection Rules

### Recommendation
Ensure Defender and EDR settings are fully enabled and monitored for tamper-themed behavior.

### Actions
- Enable Tamper Protection.
- Create alerting rules for:
  - Suspicious `.lnk` creation
  - Execution of system-recon commands (`whoami`, `qwinsta`, etc.)
  - Disk enumeration commands (`wmic logicaldisk`)
- Monitor for abnormal scheduled task creation.

### Rationale
The attacker planted fake tamper artifacts and added persistence via scheduled tasks. Improved detection logic would flag these behaviors.

---

## 4. Restrict User Privileges and Enforce Least Privilege

### Recommendation
Limit user rights to reduce the impact of account compromise.

### Actions
- Review membership in local groups (e.g., Users, Remote Desktop Users).
- Standardize least-privilege profiles for intern endpoints.
- Enforce MFA for privileged operations.

### Rationale
The compromised account was able to execute recon commands and persistence actions without elevation. Least privilege would reduce this attack surface.

---

## 5. Improve Network Egress Controls and Monitoring

### Recommendation
Implement stricter control and monitoring of outbound network activity.

### Actions
- Restrict outbound traffic to approved domains.
- Log and alert on:
  - Outbound connections to unknown IPs
  - HTTP traffic to non-corporate servers
- Enable DNS logging and anomaly detection.

### Rationale
The attacker tested outbound connectivity (`msftconnecttest.com`) and attempted exfiltration (`100.29.147.161`). Stronger egress controls would have detected or blocked this.

---

## 6. Monitor for File Staging and Public Directory Usage

### Recommendation
Detect and prevent the staging of large files or archives in public-accessible directories.

### Actions
- Monitor `C:\Users\Public` for new ZIP or data aggregation artifacts.
- Enforce access controls restricting write access to shared directories.
- Implement automated scanning for suspicious archive creation.

### Rationale
The attacker created `ReconArtifacts.zip` in the Public directory, a predictable and writable path. Monitoring this location reduces risk of unnoticed staging.

---

## 7. Strengthen User Security Awareness and Training

### Recommendation
Educate users about risks related to unsolicited support tools and suspicious downloads.

### Actions
- Train users to:
  - Avoid running scripts from Downloads
  - Recognize common social engineering patterns
  - Report unexpected “support” activity
- Provide simulated phishing and support impersonation exercises.

### Rationale
The intrusion leveraged a support/helpdesk theme, a common form of user impersonation. Awareness training can reduce vulnerability to these tactics.

---

## 8. Improve Log Retention Policies for Endpoint Telemetry

### Recommendation
Ensure telemetry retention is long enough to support full forensic investigation.

### Actions
- Extend MDE/EDR retention from the minimum to at least 30–90 days.
- Route logs to SIEM or cloud storage to preserve data for hunts.
- Enable long-term archival for key event types.

### Rationale
Some registry events (e.g., autorun persistence) were missing due to log retention expiration. Extended retention improves investigation fidelity.

---

## 9. Implement Automated Alerting for Persistence Mechanisms

### Recommendation
Deploy monitoring and alerting for scheduled tasks and autorun entries.

### Actions
- Enable detection rules for:
  - `schtasks /Create`
  - Registry modifications under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- Enforce baseline comparisons to identify new or modified startup items.

### Rationale
The attacker created `SupportToolUpdater` (scheduled task) and `RemoteAssistUpdater` (autorun). Automated detection helps prevent unnoticed re-entry points.

---

# Summary

By implementing these recommendations—strengthening endpoint controls, improving telemetry, limiting user permissions, and enhancing user awareness—the organization can significantly reduce the likelihood of similar support-themed intrusions and improve detection capabilities across early recon, staging, and persistence phases.

---

# Conclusion

The investigation into the support-themed intrusion on **gab-intern-vm** revealed a deliberate and methodical sequence of attacker actions designed to blend malicious activity into what appeared to be a routine remote-assistance session. By consistently using naming conventions associated with IT support workflows—*SupportTool, RemoteAssistUpdater, SupportChat_log*—the actor effectively masked reconnaissance, staging, and persistence steps behind a plausible operational narrative.

Analysis confirmed that the intrusion progressed through a complete and coherent attack chain:

- Initial access via script execution in an untrusted user directory  
- Host, privilege, and session reconnaissance  
- Storage and runtime enumeration  
- Data staging in a publicly accessible directory  
- Outbound communication testing and simulated exfiltration  
- Multi-layer persistence (scheduled tasks + autorun registry keys)  
- Placement of decoy artifacts intended to justify or mislead  

Throughout the timeline, the attacker demonstrated a strong preference for **living-off-the-land techniques**, leveraging native Windows utilities such as *PowerShell, whoami, qwinsta, WMIC,* and *tasklist*. This approach minimized their detection footprint and aligned closely with early-stage hands-on-keyboard intrusion patterns.

Although the simulated exfiltration attempt did not result in confirmed data loss, the presence of a staged ZIP archive and outbound transfer attempts shows clear intent to extract reconnaissance data. Combined with both primary and fallback persistence mechanisms, the actor was positioned to regain access to the endpoint if left uninterrupted.

Overall, the scenario highlights the importance of monitoring user-context script execution, detecting reconnaissance behaviors early, and correlating subtle artifacts—such as deceptive log files or naming conventions—into a holistic narrative. Effective detection relies not only on individual alerts but on understanding how sequential low-signal events build toward a clearly malicious operational pattern.


