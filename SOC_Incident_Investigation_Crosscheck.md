# SOC Incident Investigation – Crosscheck

**Scenario:** Crosscheck – Year-End Compensation & Performance Review Access  
**Methodology:** KQL-only Threat Hunting (Microsoft Defender for Endpoint)

---

## Executive Summary

Routine monitoring during year-end compensation and performance review operations identified activity that initially appeared consistent with legitimate administrative workflows. Deeper correlation across endpoint telemetry revealed a multi-stage activity chain involving scripted execution, reconnaissance, sensitive data access, data staging, persistence, outbound connectivity testing, and anti-forensic behavior.

This report documents the investigation **flag by flag**, including the **exact KQL pivots** used to validate each finding.

---

## Environment Scope

**Endpoints**
- sys1-dept (initial access)
- main1-srvr (secondary scope)

**Observed User / Session Contexts**
- 5y51-d3p7  
- YE-HELPDESKTECH  
- YE-HRPLANNER  
- YE-FINANCEREVIE  

---

## Flag 1 – Initial Endpoint Association

**Finding:** The earliest activity tied to the account `5y51-d3p7` identifies the initial endpoint.

**Result:** sys1-dept

```kql
DeviceProcessEvents
| where AccountName == "5y51-d3p7"
| summarize FirstSeen=min(TimeGenerated) by DeviceName
| order by FirstSeen asc
```

---

## Flag 2 – Remote Session Source Attribution

**Finding:** Remote session metadata reveals the originating IP.

**Result:** 192.168.0.110

```kql
DeviceProcessEvents
| where DeviceName == "sys1-dept"
| where InitiatingProcessRemoteSessionIP != ""
| summarize FirstSeen=min(TimeGenerated) by InitiatingProcessRemoteSessionIP
| order by FirstSeen asc
```

---

## Flag 3 – Support Script Execution

**Finding:** PowerShell executed a support-themed script from a user directory.

**Command**
```text
powershell.exe -ExecutionPolicy Bypass -File C:\Users\5y51-D3p7\Downloads\PayrollSupportTool.ps1
```

```kql
DeviceProcessEvents
| where DeviceName == "sys1-dept"
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has "PayrollSupportTool.ps1"
| project TimeGenerated, AccountName, ProcessCommandLine
| order by TimeGenerated asc
```

---

## Flag 4 – System Reconnaissance

**Finding:** Identity enumeration using built-in tooling.

**Command**
```text
whoami.exe /all
```

```kql
DeviceProcessEvents
| where DeviceName == "sys1-dept"
| where ProcessCommandLine has "whoami"
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated asc
```

---

## Flag 5 – Sensitive Bonus File Exposure

**Finding:** Discovery and access of draft bonus data.

**File:** BonusMatrix_Draft_v3.xlsx

```kql
DeviceFileEvents
| where DeviceName == "sys1-dept"
| where FileName == "BonusMatrix_Draft_v3.xlsx"
| project TimeGenerated, ActionType, FolderPath
| order by TimeGenerated asc
```

---

## Flag 6 – Data Staging Activity

**Finding:** Sensitive content staged into an archive.

**InitiatingProcessUniqueId:** 2533274790396713

```kql
DeviceFileEvents
| where DeviceName == "sys1-dept"
| where ActionType == "FileCreated"
| where FileName endswith ".zip"
| project TimeGenerated, FileName, FolderPath, InitiatingProcessUniqueId
| order by TimeGenerated asc
```

---

## Flag 7 – Outbound Connectivity Test

**Finding:** PowerShell-driven outbound connectivity tested prior to transfer.

**Timestamp:** 2025-12-03T06:27:31.1857946Z

```kql
DeviceNetworkEvents
| where DeviceName == "sys1-dept"
| where InitiatingProcessCommandLine has "powershell"
| project TimeGenerated, RemoteIP, RemoteUrl
| order by TimeGenerated asc
```

---

## Flag 8 – Registry-Based Persistence

**Finding:** Persistence established via HKCU Run key.

```kql
DeviceRegistryEvents
| where DeviceName == "sys1-dept"
| where RegistryKey has @"\Microsoft\Windows\CurrentVersion\Run"
| project TimeGenerated, RegistryKey, RegistryValueName, RegistryValueData
| order by TimeGenerated asc
```

---

## Flag 9 – Scheduled Task Persistence

**Finding:** Scheduled task created for recurring execution.

**Task Name:** BonusReviewAssist

```kql
DeviceProcessEvents
| where DeviceName == "sys1-dept"
| where ProcessCommandLine has "schtasks"
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated asc
```

---

## Flag 10 – Secondary Scorecard Access

**Finding:** Different remote session accessed scorecard artifacts.

**User:** YE-HELPDESKTECH

```kql
DeviceFileEvents
| where DeviceName == "sys1-dept"
| where FileName has "Scorecard"
| project TimeGenerated, InitiatingProcessAccountName
| order by TimeGenerated asc
```

---

## Flag 11 – Bonus Access by New Context

**Finding:** Higher-level department context interacted with bonus data.

**Context:** YE-HRPLANNER

```kql
DeviceFileEvents
| where DeviceName == "sys1-dept"
| where FileName has "Bonus"
| project TimeGenerated, InitiatingProcessAccountName
| order by TimeGenerated asc
```

---

## Flag 12 – Performance Review Access

**Timestamp:** 2025-12-03T07:25:15.6288106Z

```kql
DeviceProcessEvents
| where DeviceName == "sys1-dept"
| where ProcessCommandLine has "review"
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated asc
```

---

## Flag 13 – Approved Bonus Artifact Access

**Timestamp:** 2025-12-03T07:25:39.1653621Z

```kql
DeviceEvents
| where DeviceName == "sys1-dept"
| where ActionType has "Sensitive"
| project TimeGenerated, ActionType
| order by TimeGenerated asc
```

---

## Flag 14 – Candidate Archive Location

**Path**
```text
C:\Users\5y51-D3p7\Documents\Q4Candidate_Pack.zip
```

```kql
DeviceFileEvents
| where FileName == "Q4Candidate_Pack.zip"
| project TimeGenerated, FolderPath
```

---

## Flag 15 – Outbound Transfer Attempt

**Timestamp:** 2025-12-03T07:26:28.5959592Z

```kql
DeviceNetworkEvents
| where DeviceName == "sys1-dept"
| where TimeGenerated >= todatetime("2025-12-03T07:26:03.9765516Z")
| project TimeGenerated, RemoteIP, RemoteUrl
| order by TimeGenerated asc
```

---

## Flag 16 – Log Clearing Attempt

**Command**
```text
wevtutil.exe cl Microsoft-Windows-PowerShell/Operational
```

```kql
DeviceProcessEvents
| where DeviceName == "sys1-dept"
| where FileName =~ "wevtutil.exe"
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated asc
```

---

## Flag 17 – Second Endpoint Scope

**Device:** main1-srvr

```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("bonus","review","scorecard")
| summarize FirstSeen=min(TimeGenerated) by DeviceName
| order by FirstSeen asc
```

---

## Flag 18 – Approved Bonus Access on Second Endpoint

**Timestamp:** 2025-12-04T03:11:58.6027696Z

```kql
DeviceProcessEvents
| where DeviceName == "main1-srvr"
| where ProcessCommandLine has "Bonus"
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated asc
```

---

## Flag 19 – Scorecard Access on Second Endpoint

**Remote Context:** YE-FINANCEREVIE

```kql
DeviceFileEvents
| where DeviceName == "main1-srvr"
| where FileName has "Scorecard"
| project TimeGenerated, InitiatingProcessAccountName
| order by TimeGenerated asc
```

---

## Flag 20 – Staging Directory on Second Endpoint

```kql
DeviceFileEvents
| where DeviceName == "main1-srvr"
| where FolderPath has @"\InternalReferences\ArchiveBundles\"
| project TimeGenerated, FileName, FolderPath
| order by TimeGenerated asc
```

---

## Flag 21 – Staging Timestamp (Second Endpoint)

**Timestamp:** 2025-12-04T03:15:29.2597235Z

```kql
DeviceFileEvents
| where DeviceName == "main1-srvr"
| where FolderPath has "ArchiveBundles"
| order by TimeGenerated asc
```

---

## Flag 22 – Final Outbound Connection

**Remote IP:** 54.83.21.156

```kql
DeviceNetworkEvents
| where DeviceName == "main1-srvr"
| project TimeGenerated, RemoteIP, RemoteUrl
| order by TimeGenerated asc
```

---

## Credits

Thanks to **Josh Madakor** and **Joshua Balondo** for the scenario design and cyber range environment.

---

## Disclaimer

This report is based on a controlled cyber range scenario. All systems, users, files, and IP addresses are simulated.
