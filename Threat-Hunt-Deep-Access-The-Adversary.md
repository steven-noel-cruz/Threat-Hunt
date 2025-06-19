# 📚 Table of Contents

- [🕵️‍♂️ Threat Hunt: "Deep Access – The Adversary"](##-🕵️‍♂️-threat-hunt-deep-access-–-the-adversary)
- [🧰 Platforms and Tools](#-platforms-and-tools)
- [🔍 Summary of Findings (Flags)](#-summary-of-findings-flags)
  - [🏁 Flag 0: Starting Point – Entry Device Identification](#-flag-0-starting-point--entry-device-identification)
  - [🕵️‍♂️ Flag 1: Initial PowerShell Execution Detection](#-flag-1-initial-powershell-execution-detection)
  - [🌐 Flag 2: Suspicious Outbound Signal](#-flag-2-suspicious-outbound-signal)
  - [🛠️ Flag 3: Registry-Based Autorun Setup](#-flag-3-registry-based-autorun-setup)
  - [🗓️ Flag 4: Scheduled Task Persistence](#-flag-4-scheduled-task-persistence)
  - [🧪 Flag 5: Obfuscated PowerShell Execution](#-flag-5-obfuscated-powershell-execution)
  - [🕳️ Flag 6: Evasion via Legacy Scripting](#-flag-6-evasion-via-legacy-scripting)
  - [🔄 Flag 7: Remote Movement Discovery](#-flag-7-remote-movement-discovery)
  - [🧩 Flag 8: Entry Indicators on Second Host](#-flag-8-entry-indicators-on-second-host)
  - [🧩 Flag 8.1: Persistence Registration on Entry](#-flag-81-persistence-registration-on-entry)
  - [🛰️ Flag 9: External Communication Re-established](#-flag-9-external-communication-re-established)
  - [🛠️ Flag 10: Stealth Mechanism Registration](#-flag-10-stealth-mechanism-registration)
  - [🔐 Flag 11: Suspicious Data Access Simulation](#-flag-11-suspicious-data-access-simulation)
  - [🌐 Flag 12: Unusual Outbound Transfer](#-flag-12-unusual-outbound-transfer)
  - [📄 Flag 13: Sensitive Asset Interaction](#-flag-13-sensitive-asset-interaction)
  - [📦 Flag 14: Tool Packaging Activity](#-flag-14-tool-packaging-activity)
  - [📁 Flag 15: Deployment Artifact Planted](#-flag-15-deployment-artifact-planted)
  - [⏰ Flag 16: Persistence Trigger Finalized](#-flag-16-persistence-trigger-finalized)
- [🎯 MITRE ATT&CK Technique Mapping](#-mitre-attck-technique-mapping)
- [💠 Diamond Model of Intrusion Analysis](#-diamond-model-of-intrusion-analysis)
- [🧾 Conclusion](#-conclusion)
- [🎓 Lessons Learned](#-lessons-learned)
- [🛠️ Recommendations for Remediation](#-recommendations-for-remediation)

---

# 🕵️‍♂️ Threat Hunt: *"Deep Access – The Adversary"*

> *"Not all breaches sound alarms. Some whisper their presence, slipping through telemetry and leaving behind only the faintest trace. Our job: amplify the signal."*

In June 2025, a coordinated threat hunt was conducted across simulated enterprise environments to investigate stealthy adversarial behaviors that mimic advanced persistent threat (APT) tactics. The scenario focused on tracking malicious actions across two virtual machines, designed to replicate real-world intrusion patterns: covert PowerShell usage, registry manipulation, scheduled task abuse, and lateral movement, all executed without triggering traditional alerts.

The adversary’s playbook was methodical: from initial PowerShell-based execution on a short-lived system to persistence via registry keys and scheduled tasks, culminating in credential dumping, internal reconnaissance, and data staging for exfiltration. Each technique was a breadcrumb and our task was to follow them all.

This report includes:

- 📅 Timeline reconstruction of adversarial activity across **`acolyte756`** and **`victor-disa-vm`**
- 📜 Detailed queries using Microsoft 365 Defender Advanced Hunting (KQL)
- 🧠 MITRE ATT&CK mapping to understand TTP alignment
- 💠 Diamond Model analysis for adversary profiling
- 🧪 Evidence-based summaries supporting each flag and behavior discovered


---

## 🧰 Platforms and Tools

**Analysis Environment:**
- Microsoft Defender for Endpoint
- Log Analytics Workspace

**Techniques Used:**
- Kusto Query Language (KQL)
- Behavioral analysis of endpoint logs (DeviceProcessEvents, DeviceNetworkEvents, DeviceRegistryEvents)

---

## 🔍 Summary of Findings (Flags)

| Flag | Objective Description | Finding |
|------|------------------------|---------|
| 1 | Initial infection vector (low event volume device) | `acolyte756` was the first targeted machine |
| 2 | First suspicious PowerShell activity | Timestamp: `2025-05-24T00:02:00Z` |
| 3 | Unusual outbound communication | RemoteURL: `eoqsu1hq6e9ulga.m.pipedream.net` |
| 4 | Scheduled task creation | TaskName: `SimC2Task` created via `schtasks.exe` |
| 5 | Registry persistence | Registry Key: `HKLM\...\TaskCache\Tree\SimC2Task` |
| 6 | Encoded PowerShell | `powershell.exe -EncodedCommand ...` |
| 7 | PowerShell downgrade attempt | `powershell.exe -Version 2 -ExecutionPolicy Bypass` |
| 8 | Lateral movement | Next device: `victor-disa-vm` |
| 9 | Lateral artifact | File: `savepoint_sync.ps1` |
| 10 | Persistence on second machine | Registry value referencing: `savepoint_sync.ps1` |
| 11 | C2 from second machine | RemoteURL: `eo1v1texxlrdq3v.m.pipedream.net` |
| 12 | WMI-based execution | Script: `beacon_sync_job_flag2.ps1` |
| 13 | Credential theft attempt | File: `mimidump_sim.txt` |
| 14 | Document exfil target | File: `RolloutPlan_v8_477.docx` |
| 15 | Staging payloads | Archive: `spicycore_loader_flag8.zip` |
| 16 | Task execution | Task created via `schtasks.exe` on `victor` |

---
### 🏁 Flag 0: Starting Point – Entry Device Identification

**Objective:**  
Determine the initial point of compromise by identifying newly created virtual machines that were only active for a short period before deletion. These devices will have minimal process logs, making them ideal starting points for a threat hunt.

**Flag Value:**  
`acolyte756`

**Detection Strategy:**  
We queried the number of recorded process events per device over a focused timeframe. Devices with unusually low process counts are indicative of ephemeral activity, potentially short-lived staging environments for adversary operations.

**KQL Query:**
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-05-23T00:00:00Z)..datetime(2025-05-25T23:59:59Z))
| summarize ProcessCount = count() by DeviceName
| order by ProcessCount asc
```

**Evidence:**

![Screenshot 2025-06-08 153355](https://github.com/user-attachments/assets/97e6a20f-f466-48a3-a8a2-a3f94b432cd7)

![Screenshot 2025-06-08 153412](https://github.com/user-attachments/assets/95cdad85-736a-4b37-87e9-74c522f36b90)



**Why This Matters:**
The device acolyte756 stood out with significantly fewer logged processes and a first and last seen time of May 24, 2025 6:35:57 PM to May 24, 2025 11:38:08 PM, aligning with the behavior of a temporary virtual machine likely used as an initial beachhead.


### 🕵️‍♂️ Flag 1: Initial PowerShell Execution Detection

**Objective:**  
Pinpoint the earliest suspicious PowerShell activity that marks the intruder's possible entry.

**Flag Value:**  
`2025-05-25T09:14:02.3908261Z`

**What to Hunt:**  
Initial signs of PowerShell usage that deviate from normal operational behavior. This could include execution via encoded commands, suspicious paths, or unusual launch methods.

**Detection Strategy:**  
We filtered PowerShell executions on the entry device `acolyte756` and sorted the events chronologically to locate the earliest instance.

**KQL Query:**
```kql
DeviceProcessEvents
| where DeviceName contains "acolyte756"
| where FileName contains "powershell"
| project Timestamp,DeviceName,FileName,ProcessCommandLine
| order by Timestamp asc
```
**Evidence:**

![Screenshot 2025-06-08 153905](https://github.com/user-attachments/assets/ccfc6bb9-b1c6-492a-aac8-9a9adbbe670c)

**Why This Matters:**
This timestamp (2025-05-25T09:14:02.3908261Z) marks the initial use of PowerShell. This invocation runs PowerShell silently, without logo or profile loading, which is often used to minimize visibility during malicious scripting. A key indicator of suspicious scripting activity that may have kicked off the broader intrusion sequence.

### 🌐 Flag 2: Suspicious Outbound Signal

**Objective:**  
Confirm an unusual outbound communication attempt from a potentially compromised host.

**Flag Value:**  
`eoqsu1hq6e9ulga.m.pipedream.net`

**What to Hunt:**  
Look for external network connections from the host `acolyte756` to public or unrecognized domains — particularly those that may be command-and-control (C2) endpoints.

**Detection Strategy:**  
We filtered network activity on `acolyte756` within the relevant time window, then isolated remote connections made by LOLBins or scripting engines (PowerShell, CMD, WScript, etc.) to suspicious external destinations.

**KQL Query:**
```kql
DeviceNetworkEvents
| where DeviceName contains "acolyte756"
| where Timestamp between (datetime(2025-05-23T00:00:00Z)..datetime(2025-05-25T23:59:59Z))
| where RemoteUrl != "" or RemoteIPType == "Public"
| where InitiatingProcessFileName has_any ("powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe")
| project RemoteIP, RemoteUrl, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId, Timestamp
| order by Timestamp asc
```
**Evidence:**

![Screenshot 2025-06-08 154641](https://github.com/user-attachments/assets/6251de70-2972-49a7-8910-355b9d00d23a)

**Why This Matters:**
The domain eoqsu1hq6e9ulga.m.pipedream.net was contacted via PowerShell from a system with no business context for such communication. This domain resembles a known technique for simulating beaconing or acting as a placeholder for dynamic C2 infrastructure. The metaphor “hollow tube” in the hint refers to a beaconing channel without obvious data flow.

### 🛠️ Flag 3: Registry-Based Autorun Setup

**Objective:**  
Detect whether the adversary used registry-based mechanisms to gain persistence.

**Flag Value:**  
`C2.ps1`

**What to Hunt:**  
Search for newly created or modified registry values in autorun paths that execute suspicious files or scripts, especially PowerShell scripts in public directories.

**Detection Strategy:**  
We reviewed `DeviceRegistryEvents` for the device `acolyte756`, focusing on changes to the well-known autorun key path: HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run

There, we identified the file `C2.ps1` being referenced via PowerShell in the registry value, a clear sign of persistence.

**KQL Query:**
```kql
DeviceRegistryEvents
| where DeviceName contains "acolyte756"
| where RegistryKey startswith @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\"
| order by Timestamp asc
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessCommandLine
```
**Evidence:**

![Screenshot 2025-06-08 155119](https://github.com/user-attachments/assets/5a27ba1d-515b-457d-892f-3b8e6c7ba545)


**Why This Matters:**
The script C2.ps1 was set to auto-run via both registry and scheduled task creation. This double persistence strategy enhances stealth and guarantees execution upon user logon or system reboot.

### 🗓️ Flag 4: Scheduled Task Persistence

**Objective:**  
Investigate the presence of alternate autorun methods used by the intruder.

**Flag Value:**  
`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\SimC2Task`

**What to Hunt:**  
Verify if scheduled tasks were created in the system that could enable persistence, especially those tied to attacker-controlled scripts or binaries.

**Detection Strategy:**  
We queried registry key creation activity on `acolyte756`, specifically targeting the Windows Task Scheduler’s internal registry structure. The presence of a task entry within the `TaskCache\Tree\` hierarchy indicates a newly registered task.

**KQL Query:**
```kql
DeviceRegistryEvents
| where DeviceName contains "acolyte756"
| where RegistryKey startswith @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
| order by Timestamp asc
```
**Evidence:**

![Screenshot 2025-06-08 155816](https://github.com/user-attachments/assets/94f48987-1c85-486c-8be0-aec64ccd3a08)


**Why This Matters:**
The use of a scheduled task (SimC2Task) alongside registry persistence provides redundancy, increasing the malware's chance of executing reliably while remaining under the radar.

### 🧪 Flag 5: Obfuscated PowerShell Execution

**Objective:**  
Uncover signs of script concealment or encoding in command-line activity.

**Flag Value:**  
```powershell
"powershell.exe" -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFMAaQBtAHUAbABhAHQAZQBkACAAbwBiAGYAdQBzAGMAYQB0AGUAZAAgAGUAeABlAGMAdQB0AGkAbwBuACIA
```
**What to Hunt:**
PowerShell commands that use the -EncodedCommand flag to hide the actual script. These often indicate attempts to evade detection or static analysis.

**Detection Strategy:**
We filtered process execution events on acolyte756 for any command lines containing -EncodedCommand, then decoded the base64 payload. The output string matched the known simulation flag:
Write-Output "Simulated obfuscated execution"

**KQL Query:**
```kql
DeviceProcessEvents
| where DeviceName contains "acolyte756"
| where ProcessCommandLine contains "-EncodedCommand"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessCommandLine, AccountName
```
**Evidence:**

![Screenshot 2025-06-08 160338](https://github.com/user-attachments/assets/8098c1db-4ddc-48c3-b2f8-9188f89a4db3)

**Why This Matters:**
Encoding commands hides them from basic logging and detection tools. The presence of base64-encoded PowerShell suggests the adversary attempted to conceal their actions during execution, even in a simulated scenario.

### 🕳️ Flag 6: Evasion via Legacy Scripting

**Objective:**  
Detect usage of outdated script configurations likely intended to bypass modern controls.

**Flag Value:**  
```powershell
"powershell.exe" -Version 2 -NoProfile -ExecutionPolicy Bypass -NoExit
```

**What to Hunt:**
Look for PowerShell executions using the -Version 2 flag, which attempts to downgrade to PowerShell v2 — a legacy version lacking many modern logging and security protections.

**Detection Strategy:**
We queried DeviceProcessEvents for executions of powershell.exe and filtered on command lines specifying older versions (particularly v2). The following legacy call was discovered on acolyte756:
Timestamp: 2025-05-24T21:14:05Z
Device: acolyte756
Command: "powershell.exe" -Version 2 -NoProfile -ExecutionPolicy Bypass -NoExit

**KQL Query:**
```kql
DeviceProcessEvents
| where DeviceName contains "acolyte756"
| where FileName contains "powershell"
| where ProcessCommandLine contains "version"
| project Timestamp,DeviceName,FileName,ProcessCommandLine
| order by Timestamp asc
```
**Evidence:**

![Screenshot 2025-06-08 161137](https://github.com/user-attachments/assets/7b0abdc1-04cf-4074-ab30-c9807175e360)

**Why This Matters:**
Downgrading to PowerShell v2 is a known tactic to bypass script block logging and modern AMSI-based (Antimalware Scan Interface) protections. This enables stealthy script execution without full telemetry capture.

### 🔄 Flag 7: Remote Movement Discovery

**Objective:**  
Reveal the intruder's next target beyond the initial breach point.

**Flag Value:**  
`victor-disa-vm`

**What to Hunt:**  
Trace outbound process activity from the initially compromised host (`acolyte756`) that mentions or interacts with other device names or IPs — especially through tools like `schtasks.exe`, `PsExec`, `WinRM`, or custom PowerShell remoting commands.

**Detection Strategy:**  
We analyzed process creation events from `acolyte756` for signs of outbound task creation or command execution. A `schtasks.exe` command was found, attempting to push a scheduled task to another device named `victor-disa-vm` using administrative credentials.

**Evidence:**

![Screenshot 2025-06-08 161739](https://github.com/user-attachments/assets/2aeb795f-51b8-438d-9ef5-79b6e48dc4e3)

**KQL Query:**
```kql
DeviceProcessEvents
| where DeviceName contains "acolyte756"
| where FileName in~ ("schtasks.exe", "powershell.exe")
| where ProcessCommandLine has_any ("/create", "Register-ScheduledTask")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp asc
```

**Why This Matters:**
Lateral movement is a crucial stage of adversary operations. Detecting outbound interactions with other internal hosts helps identify spread potential, persistence expansion, or pivoting behavior that might otherwise be missed.


### 🧩 Flag 8: Entry Indicators on Second Host

**Objective:**  
Identify the subtle digital footprints left during a pivot.

**Flag Value:**  
`savepoint_sync.lnk`

**What to Hunt:**  
Search for suspicious file creations on the second machine, especially `.lnk` (shortcut) files with names related to *sync*, *stage*, or *checkpoint*. These filenames often mark the drop-point for follow-on access or automation triggers.

**Detection Summary:**  
On the secondary system `victor-disa-vm`, a `.lnk` file named `savepoint_sync.lnk` was created in the user's recent folder. This artifact strongly suggests the system was accessed with intent to stage or sync malicious tools post-lateral movement.

**Evidence:**

![Screenshot 2025-06-08 162345](https://github.com/user-attachments/assets/c25daadc-a23b-4dcf-92e1-84e4a20c1201)

**KQL Query Used:**
```kql
DeviceFileEvents
| where DeviceName contains "victor-disa-vm"
| where FileName contains "point" or FileName contains "stage" or FileName contains "sync"
```

**Why This Matters:**
Even minor artifacts like .lnk files in user profile directories can signify pivot points or attacker-created shortcuts for automated execution. In this case, savepoint_sync.lnk likely points to either a payload or a post-access script and provides a trace of lateral movement confirmation.



### 🧩 Flag 8.1: Persistence Registration on Entry

**Objective:**  
Detect attempts to embed control mechanisms within system configuration.

**Flag Value:**  
`powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Users\Public\savepoint_sync.ps1"`

**What to Hunt:**  
Registry entries under autorun paths (`Run`, `TaskCache`, etc.) that reference `.ps1`, `.exe`, or `.lnk` files located in `C:\Users\Public`, `%APPDATA%`, or other shared directories, especially those not previously observed on the system.

**Detection Summary:**  
A registry value was identified on the `victor-disa-vm` host that executes a PowerShell script located at `C:\Users\Public\savepoint_sync.ps1`. This aligns with the previously observed lateral entry (`savepoint_sync.lnk`) and confirms persistence registration shortly after file drop.

**KQL Query Used:**
```kql
DeviceRegistryEvents
| where DeviceName contains "victor-disa"
| where RegistryKey has_any (
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Policies",
    "TaskCache",
    "Shell", 
    "Windows\\CurrentVersion\\Explorer"
)
| where RegistryValueData has_any ("powershell", ".ps1", "cmd.exe", ".lnk", "AppData", "Public")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessCommandLine
| order by Timestamp asc
```

**Evidence:**

![Screenshot 2025-06-08 163204](https://github.com/user-attachments/assets/d35367a9-013e-4f86-874c-50932c288b6c)

**Why This Matters:**
Registry-based persistence remains a common and effective technique for attackers to maintain access without needing login sessions. This PowerShell invocation matches known malicious patterns and directly ties back to the previously discovered .lnk artifact further confirming system compromise and attacker foothold.

### 🛰️ Flag 9 – External Communication Re-established

**Objective:**  
Verify if outbound signals continued from the newly touched system.

**Flag Value:**  
`eo1v1texxlrdq3v.m.pipedream.net`

**What to Hunt:**  
Look for external connection attempts from `victor-disa-vm` targeting suspicious or unfamiliar destinations, particularly those outside the organization's expected network communication patterns.

**Detection Summary:**  
After lateral movement onto `victor-disa-vm`, the system initiated outbound connections to the command-and-control (C2) domain `eo1v1texxlrdq3v.m.pipedream.net`, indicating continued adversary control and beaconing behavior from the secondary compromised machine.

**Evidence:**

![Screenshot 2025-06-08 163751](https://github.com/user-attachments/assets/1a31b522-e65d-4a3a-a715-653280326abb)


**KQL Query Used:**
```kql
DeviceNetworkEvents
| where DeviceName contains "victor-disa-vm"
| where RemoteUrl contains "pipedream.net"
| order by Timestamp asc
```

**Why This Matters:**
Beaconing behavior to pipedream.net domains mimics common techniques used for callback and remote control. The use of HTTPS (port 443) helps evade traditional inspection. The shift from successful to failed connections over time may suggest containment or infrastructure takedown.

### 🛠️ Flag 10 – Stealth Mechanism Registration

**Objective:**  
Uncover non-traditional persistence mechanisms leveraging system instrumentation.

**Flag Value:**  
`2025-05-26T02:48:07.2900744Z`

**What to Hunt:**  
Execution patterns or command traces that silently embed PowerShell scripts via background system monitors such as **Windows Management Instrumentation (WMI)**.

**Thought:**  
Sophisticated adversaries sometimes bypass scheduled tasks and registry autoruns by leveraging WMI for stealthy persistence. These mechanisms can persist across reboots and evade standard detection if not explicitly hunted.

**Evidence:**

![Screenshot 2025-06-08 164759](https://github.com/user-attachments/assets/70b5940f-c7fd-4a57-b1cf-27d8acaf1cd1)

**KQL Query Used:**
```kql
DeviceProcessEvents
| where DeviceName contains "victor"
| where ProcessCommandLine contains "beacon"
| project Timestamp, DeviceName, ProcessCommandLine
```
**Why This Matters:**
This method shows adversaries employing stealthier techniques to maintain access by attaching script execution to system-level event triggers — without relying on login sessions or scheduled tasks. The use of beacon_sync.ps1 indicates an intent to persist in a covert manner consistent with WMI Event Subscription Abuse.


### 🔐 Flag 11 – Suspicious Data Access Simulation

**Objective:**  
Detect test-like access patterns mimicking sensitive credential theft.

**Flag Value:**  
`mimidump_sim.txt`

**What to Hunt:**  
References or interactions with files suggestive of password dumps or memory scraping artifacts often related to tools like Mimikatz.

**Thought:**  
Even simulated credential access leaves behavioral traces. Attackers often imitate legitimate tool usage for testing, staging, or distraction. Identifying these events is critical to spotting early access attempts or red-team-like simulations.

**Evidence:**

![Screenshot 2025-06-08 165422](https://github.com/user-attachments/assets/4843c996-2c75-431f-877f-b5bd2b4f56cc)


**KQL Query Used:**
```kql
DeviceProcessEvents
| where DeviceName contains "victor"
| where ProcessCommandLine contains "mimi"
| project Timestamp, DeviceName, ProcessCommandLine
```

**Why This Matters:**
Simulated or test artifacts like mimidump_sim.txt mimic the behavior of credential harvesting tools. Monitoring and correlating access to files with terms like "dump" or "password" is essential to catching credential theft behaviors early, even during trial runs.

### 🌐 Flag 12 – Unusual Outbound Transfer

**Objective:**  
Investigate signs of potential data transfer to untrusted locations.

**Flag Value:**  
`9785001b0dcf755eddb8af294a373c0b87b2498660f724e76c4d53f9c217c7a3`

**What to Hunt:**  
External destinations indicative of third-party file storage or sharing services, especially those used for stealthy beaconing or data exfiltration.

**Thought:**  
Outbound communications to unknown or disallowed external destinations can signal staged data exfiltration. Correlating process hashes with network activity can expose covert C2 channels or file transfers.

**Evidence:**

![Screenshot 2025-06-08 170042](https://github.com/user-attachments/assets/2479efdf-5396-494a-b712-63e39584ac02)

![Screenshot 2025-06-08 170830](https://github.com/user-attachments/assets/2ce19734-4b9b-454a-b47e-0ae77cba0e4e)

**KQL Querys Used:**
```kql
DeviceProcessEvents
| where DeviceName contains "victor"
| where ProcessCommandLine contains "mimi"
| project Timestamp, DeviceName, ProcessCommandLine, SHA256

DeviceNetworkEvents
| where DeviceName contains "victor"
| where InitiatingProcessSHA256 contains "9785001b0dcf755eddb8af294a373c0b87b2498660f724e76c4d53f9c217c7a3"
| project Timestamp, DeviceName,RemoteUrl, InitiatingProcessCommandLine, InitiatingProcessSHA256, InitiatingProcessFileName
```
**Why This Matters:**
This SHA256 hash identifies a PowerShell process on victor-disa-vm reaching out to drive.google.com, an uncommon and unauthorized outbound interaction that may indicate file drop-off or command-retrieval behavior. Catching these "low-and-slow" leaks is vital for preventing stealthy data exfiltration.

### 📄 Flag 13 – Sensitive Asset Interaction

**Objective:**  
Reveal whether any internal document of significance was involved.

**Flag Value:**  
`RolloutPlan_v8_477.docx`

**What to Hunt:**  
Access logs involving time-sensitive or project-critical files, particularly documents named or stored according to organizational project schedules or release cycles (e.g., folders labeled by year-month).

**Evidence:**

![image](https://github.com/user-attachments/assets/c3c2106d-ae21-4b6c-907b-d4a2a6a43a3c)

![Screenshot 2025-06-19 182954](https://github.com/user-attachments/assets/5020dfb3-5ca9-404d-85b1-bf8914c8cfbd)



**KQL Query Used:**
```kql
DeviceProcessEvents
| where DeviceName contains "victor"
| where ProcessCommandLine contains ".docx"
| project Timestamp, ActionType, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine, ProcessCommandLine
| order by Timestamp asc
```

**Why This Matters:**
The document was accessed through a standard process chain (userinit.exe → explorer.exe → wordpad.exe), confirming that a logged-in user (or impersonated session) interacted with a strategically sensitive file. The filename and folder structure (2025-12) suggest it contains future operational planning, making it a high-value target. Whether accessed manually or by an adversary operating under a hijacked session, this confirms interest in forward-looking leadership material—potentially useful for espionage, extortion, or disruption.

### 📦 Flag 14 – Tool Packaging Activity

**Objective:**  
Spot behaviors related to preparing code or scripts for movement.

**Flag Value:**  
`"powershell.exe" -NoProfile -ExecutionPolicy Bypass -Command Compress-Archive -Path "C:\Users\Public\dropzone_spicy" -DestinationPath "C:\Users\Public\spicycore_loader_flag8.zip" -Force`

**What to Hunt:**  
Compression or packaging of local assets in non-administrative directories, especially targeting `Public`, `Temp`, or `AppData` paths.

**Thought:**  
Before exfiltration, staging occurs. Files don’t always move immediately — attackers often prep archives for batch transfer. Monitoring compression commands and abnormal zip activity is essential for catching this staging phase.

**Evidence:**  

![Screenshot 2025-06-08 171925](https://github.com/user-attachments/assets/28cd665a-6147-4f9c-bf66-7ed29ee918ff)


**KQL Query Used:**
```kql
DeviceProcessEvents
| where DeviceName contains "victor"
| where ProcessCommandLine contains "compress"
| project Timestamp, DeviceName, FileName, ProcessCommandLine
```
**Why This Matters:**
The command shows the adversary using PowerShell's built-in Compress-Archive cmdlet to package a malicious directory (dropzone_spicy) into a zip archive named spicycore_loader_flag8.zip. This tactic is consistent with preparation for data exfiltration and is a clear signal of adversarial staging behavior.

### 📁 Flag 15 – Deployment Artifact Planted

**Objective:**  
Verify whether staged payloads were saved to disk.

**Flag Value:**  
`spicycore_loader_flag8.zip`

**What to Hunt:**  
Unusual compressed file drops (`.zip`, `.7z`, `.rar`) especially in shared, public, or non-admin folders like `C:\Users\Public`, `C:\ProgramData`, or `C:\Temp`.

**Evidence:**  

![Screenshot 2025-06-08 172605](https://github.com/user-attachments/assets/87eab110-3db0-445b-8e67-7c8dfd26b443)

**KQL Query Used:**
```kql
DeviceFileEvents
| where DeviceName contains "victor"
| where FileName contains "spicycore_loader_flag8"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessCommandLine
```
**Why This Matters:**
The .zip archive spicycore_loader_flag8.zip appeared in C:\Users\Public, a known staging location for unprivileged execution or lateral movement. While the archive wasn’t yet executed, its existence marks the adversary’s intent to persist or exfiltrate. Identifying these signs early can prevent the next phase of compromise.

### ⏰ Flag 16 – Persistence Trigger Finalized

**Objective:**  
Identify automation set to invoke recently dropped content.

**Flag Value:**  
`2025-05-26T07:01:01.6652736Z`

**What to Hunt:**  
Scheduled task creation events (`schtasks.exe`, `Register-ScheduledTask`, etc.) that reference suspicious or non-standard script names, especially in public or user-writable directories.

**Evidence:**  

![Screenshot 2025-06-08 172954](https://github.com/user-attachments/assets/5819ff03-2ba4-4bd8-bd2b-58f30f3d4474)

**KQL Query Used:**
```kql
DeviceProcessEvents
| where DeviceName contains "victor"
| where FileName == "schtasks.exe"
| project Timestamp, DeviceName, FileName, ProcessCommandLine
| order by Timestamp desc
```
**Why This Matters:**
The command line confirms the adversary created a task named SpicyPayloadSync that executes the script spicy_exec_flag10.ps1. Scheduled to run at logon with highest privileges, this action secures continued access. By observing this timestamped event, defenders can pinpoint the exact moment persistent automation was finalized.


---

## 🎯 MITRE ATT&CK Technique Mapping

| Flag | MITRE Technique                    | ID                                                          | Description                                                             |
| ---- | ---------------------------------- | ----------------------------------------------------------- | ----------------------------------------------------------------------- |
| 1    | PowerShell                         | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Initial use of PowerShell for script execution.                         |
| 2    | Application Layer Protocol         | [T1071](https://attack.mitre.org/techniques/T1071/)         | Beaconing via HTTPS to external infrastructure (`pipedream.net`).       |
| 3    | Registry Run Keys/Startup Folder   | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Persistence via `HKCU\...\Run` registry key with `C2.ps1`.              |
| 4    | Scheduled Task/Job                 | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Alternate persistence through scheduled task `SimC2Task`.               |
| 5    | Obfuscated Files or Information    | [T1027](https://attack.mitre.org/techniques/T1027/)         | Execution of base64-encoded PowerShell command.                         |
| 6    | Indicator Removal on Host          | [T1070](https://attack.mitre.org/techniques/T1070/)         | PowerShell v2 downgrade to bypass AMSI/logging.                         |
| 7    | Remote Services: Scheduled Task    | [T1021.003](https://attack.mitre.org/techniques/T1021/003/) | Lateral movement using `schtasks.exe` targeting `victor-disa-vm`.       |
| 8    | Lateral Tool Transfer              | [T1570](https://attack.mitre.org/techniques/T1570/)         | Use of `.lnk` files like `savepoint_sync.lnk` to stage/pivot.           |
| 8.1  | Registry Modification              | [T1112](https://attack.mitre.org/techniques/T1112/)         | `savepoint_sync.ps1` registered for autorun.                            |
| 9    | Application Layer Protocol         | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | New beaconing to `eo1v1texxlrdq3v.m.pipedream.net`.                     |
| 10   | WMI Event Subscription             | [T1546.003](https://attack.mitre.org/techniques/T1546/003/) | Stealth persistence via WMI script `beacon_sync_job_flag2.ps1`.         |
| 11   | Credential Dumping Simulation      | [T1003](https://attack.mitre.org/techniques/T1003/)         | Mimic of credential access via `mimidump_sim.txt`.                      |
| 12   | Data Staged: Local                 | [T1074.001](https://attack.mitre.org/techniques/T1074/001/) | Powershell process connects to `drive.google.com`.                      |
| 13   | Data from Information Repositories | [T1213](https://attack.mitre.org/techniques/T1213/)         | Access of sensitive doc `RolloutPlan_v8_477.docx`.                      |
| 14   | Archive Collected Data             | [T1560.001](https://attack.mitre.org/techniques/T1560/001/) | Use of `Compress-Archive` to prepare ZIP payload.                       |
| 15   | Ingress Tool Transfer              | [T1105](https://attack.mitre.org/techniques/T1105/)         | Staging of `spicycore_loader_flag8.zip`.                                |
| 16   | Scheduled Task/Job                 | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Final scheduled task `SpicyPayloadSync` set to trigger script on logon. |


---

## 💠 Diamond Model of Intrusion Analysis
The Diamond Model breaks down an intrusion event into four core features: Adversary, Infrastructure, Capability, and Victim. This framework helps correlate activities and identify attacker patterns at a high level.

```
+-----------------+       +------------------+
|                 |<----->|                  |
|    Adversary    |       |  Infrastructure  |
| Phantom Group   |       | pipedream.net,   |
| (Possible        |       | drive.google.com |
| Mercenary Unit) |       | beacon_sync.ps1  |
+-----------------+       +------------------+
        ^                          |
        |                          v
+-----------------+       +------------------+
|     Victim      |<----->|    Capability    |
| acolyte756,     |       | PowerShell, WMI, |
| victor-disa-vm  |       | Registry, LNK,   |
| User: acolight  |       | Scheduled Tasks  |
+-----------------+       +------------------+
```

# 🔍 Breakdown of Each Node

**🕵️ Adversary**

***Name/Attribution:*** 

- Likely APT-aligned threat actor or red-team emulation of a mercenary group.

***Evidence:***

- Coordinated multi-host campaign

- Use of stealthy persistence and living-off-the-land binaries (LOLBins)

- Mimicked data theft via Mimikatz-style dump simulation

**🌐 Infrastructure**

***C2 Endpoints:***

- eoqsu1hq6e9ulga.m.pipedream.net

- eo1v1texxlrdq3v.m.pipedream.net

***Staging & Exfil:***

- drive.google.com

***Execution Artifacts:***

- beacon_sync_job_flag2.ps1

- spicycore_loader_flag8.zip

***Scheduled Tasks:***

- SimC2Task
  
- SpicyPayloadSync

**🛠️ Capability**

***Tactics and Tools:***

- PowerShell for execution, obfuscation, and persistence

- Registry run keys for autorun

- WMI event binding for stealth persistence

- Credential mimicry via mimidump_sim.txt

- Use of Compress-Archive to package payloads

- Scheduled task automation for triggering attacks

***Command Examples:***

```powershell
powershell.exe -EncodedCommand [...]
powershell.exe -ExecutionPolicy Bypass -File "C:\Users\Public\beacon_sync.ps1"
```

**🎯 Victim**

***Devices Affected:***

- acolyte756 (initial access point)

- victor-disa-vm (pivoted target)

***User Accounts:***

- acolight

- V1cth0r

***Targeted Assets:***

- RolloutPlan_v8_477.docx (critical year-end document)

***Shared paths:***
- C:\Users\Public\
- AppData\Roaming
- Startup

---
## 🧾 Conclusion

The June 2025 Cyber Threat Hunt: Deep Access – The Adversary revealed a sophisticated, stealth-oriented attack chain spanning multiple hosts, leveraging native system tools, obfuscation, and layered persistence. Starting from an ephemeral host (acolyte756), the adversary executed obfuscated PowerShell scripts and established outbound communication to obscure external C2 domains such as pipedream.net.

Key persistence methods included both registry autorun entries and scheduled tasks, with additional stealth mechanisms like WMI event consumer binding uncovered later in the campaign. The actor successfully laterally moved to victor-disa-vm, where payloads were staged, compressed, and poised for execution or exfiltration, all without triggering conventional alerting.

The adversary demonstrated a clear interest in credential harvesting simulations (mimidump_sim.txt) and sensitive internal documentation (RolloutPlan_v8_477.docx), suggesting intent beyond simple access — possibly toward data theft or corporate disruption.

This hunt underscores the importance of:

- Baseline monitoring of PowerShell and LOLBin activity

- Regular auditing of scheduled tasks and WMI filters

- Enhanced detection for encoded commands, legacy execution flags, and out-of-band communication

- Inter-host telemetry correlation to track subtle lateral movement paths

---

## 🎓 Lessons Learned

***Attackers Prioritize Stealth over Speed***
- The adversary’s reliance on PowerShell, obfuscation, and system-native utilities (e.g., schtasks.exe, svchost.exe) shows a strong preference for blending into legitimate activity to prolong access.

***Persistence Techniques Were Layered and Diverse***
- Both registry keys and scheduled tasks were used in tandem, followed by a WMI-based fallback — illustrating the adversary’s resilience planning and defense evasion mindset.

***Command-and-Control Infrastructure Evaded Traditional Detection***
- By using public platforms like pipedream.net and redirecting to domains mimicking automation tools, the adversary circumvented conventional network blocklists.

***Credential Theft Was Simulated Using Realistic Artifacts***
- Deployment of mimidump_sim.txt and access patterns matching credential scraping reflect red-team-level staging or reconnaissance tests for future privilege escalation.

***Lateral Movement Occurred Without Credential Changes***
- Remote task creation (schtasks.exe /Create /S ...) indicated successful reuse of stolen or pre-existing credentials without triggering identity-based anomaly alerts.

---

## 🛠️ Recommendations for Remediation

- Implement Script Block Logging & Deep PowerShell Auditing

- Enable enhanced PowerShell logging via Group Policy and forward logs to centralized SIEM.

- Flag obfuscated scripts, encoded commands, and version downgrades (e.g., -Version 2) for alerting.

- Audit and Harden Task Scheduler and WMI Interfaces

- Monitor schtasks.exe and Register-ScheduledTask invocations, especially those triggered remotely or referencing external script paths.

- Periodically review WMI filters, consumers, and bindings using tools like WMIEvtxParser or Sysinternals WMI Explorer.

- Restrict Outbound Traffic to Known Good Destinations

- Use firewall egress filtering and DNS allowlists to prevent beaconing to obscure or dynamic endpoints like *.pipedream.net.

- Apply Lateral Movement Detection Rules

- Monitor for remote task creation, especially from non-admin hosts to critical systems (e.g., schtasks /S or WinRM usage).

- Correlate logon events with unexpected file access or script drops.

- Secure and Monitor Shared Directories

- Disable public folder sharing where unnecessary.

- Monitor C:\Users\Public, AppData, and Temp directories for archive drops or .ps1 scripts.

- Enhance User Credential Protection

- Enforce strong password policies and MFA for all privileged accounts.

- Apply LSASS protection (Credential Guard) to reduce memory scraping risks.

- Run Regular Threat Hunts Using MITRE ATT&CK Mapping

- This scenario mapped to over a dozen ATT&CK techniques, build detections and analytics to continuously validate defenses against these behaviors.
