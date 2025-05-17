# Threat Hunt Report: The Great Admin Heist Investigation

**Participant:** Steven Cruz
**Date:** May 2025

## Platforms and Languages Leveraged

**Platforms:**

* Microsoft Defender for Endpoint (MDE)
* Log Analytics Workspace
* Windows 10-based corporate workstation (`anthony-001`)

**Languages/Tools:**

* Kusto Query Language (KQL) for querying device events, registry modifications, and persistence artifacts
* Native Windows utilities: `powershell.exe`, `cmd.exe`, `schtasks.exe`, `csc.exe`

---

## Scenario

At Acme Corp, the privileged IT admin **Bubba Rockerfeatherman III** unknowingly became the target of a sophisticated APT group called **The Phantom Hackers**. These attackers leveraged phishing and stealthy execution tactics, including masquerading malware, Windows LOLBins, and multiple persistence techniques, to breach the system and maintain long-term access.

---

## Key Observations

* **Initial Vector:** A fake antivirus binary named `BitSentinelCore.exe` was dropped into `C:\ProgramData\`.
* **Dropper Used:** Legitimate Microsoft-signed binary `csc.exe` (C# compiler) was abused to compile and drop the malware.
* **Execution:** The malware was executed via PowerShell on **2025-05-07T02:00:36.794406Z**, marking the root of the malicious chain.
* **Keylogger:** A deceptive shortcut `systemreport.lnk` was dropped in the AppData folder to enable keystroke capture on logon.
* **Registry Persistence:** Auto-run registry key was created at:
  `HKEY_CURRENT_USER\S-1-5-21-2009930472-1356288797-1940124928-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
* **Scheduled Task:** Named `UpdateHealthTelemetry`, this ensured long-term execution of the malware.
* **Process Chain:** `BitSentinelCore.exe -> cmd.exe -> schtasks.exe`

---

## Timeline & Queries Used

### Initial Malware Execution:
The investigation began by analyzing DeviceLogonEvents on the target system anthony-001 to determine if a breach had occurred following brute force behavior.
The logs revealed repeated authentication attempts from IP 102.88.21.215—an address geolocated in Nigeria—which was ultimately unsuccessful. 
However, shortly afterward, a successful logon was observed from IP 49.147.196.23 (based in the Philippines) under a device name referencing Bubba, the privileged IT admin.
```kql
DeviceLogonEvents
| where DeviceName contains "anthony-001"
```
![image](https://github.com/user-attachments/assets/e54fd2ae-9dc5-4fee-a3e7-4075c6f62295)

📌 *Timestamp:* `2025-05-07T02:00:36.794406Z`

### File Write via Legitimate LOLBin:

Pivoting to file creation events, I filtered for files created outside normal patterns on this device.
This revealed the drop of BitSentinelCore.exe—a fake antivirus program masquerading as a legitimate security tool. 
Using the parent process ID, I traced its origin to csc.exe, Microsoft's legitimate C# compiler, which was exploited to compile and place the malware on disk


```kql
DeviceFileEvents
| where FileName == "BitSentinelCore"
```
![image](https://github.com/user-attachments/assets/ce2d22b5-022c-4f55-94ec-09a890fb579c)

📌 *Dropper Used:* `csc.exe`

### Execution Path:
To validate execution, I examined the initiating process and found the command line and path traced back to explorer.exe.
This strongly indicated that Bubba himself manually executed the malware.
```kql
DeviceProcessEvents
| where FileName == "BitSentinelCore.exe" or InitiatingProcessFileName == "BitSentinelCore.exe"
```
![image](https://github.com/user-attachments/assets/cb242707-d915-4c3a-9b28-c0b633651ff7)


### Keylogger Artifact:
Following execution, a suspicious file named systemreport.lnk appeared in the AppData folder.
Its creation shortly after malware execution suggested keylogging or surveillance functionality—particularly because this was the only occurrence of that file on the system, and its timing implied intentional deployment for data collection.

```kql
DeviceFileEvents
| where DeviceName contains "anthony-001"
| where InitiatingProcessRemoteSessionDeviceName contains "bubba"
| where Timestamp >= datetime("2025-05-07T02:00:36.794406Z")
```
![image](https://github.com/user-attachments/assets/7b3740ff-14cf-457b-a440-56bb2fb7bb0d)

📌 *Artifact:* `systemreport.lnk`

### Registry Persistence:
Continuing, I reviewed registry modifications. A persistence key was identified in: HKEY_CURRENT_USER\S-1-5-21-2009930472-1356288797-1940124928-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
This entry was configured to launch BitSecSvc (an alias of the malware) on boot, establishing persistence across reboots.
```kql
DeviceRegistryEvents
| where RegistryKey contains "Run"
| where RegistryValueData has "BitSentinelCore"
```
![image](https://github.com/user-attachments/assets/3a05e25f-e17e-4d55-9082-b603d88490ce)

📌 *Key:* `HKCU\...\Run`

### Scheduled Task Creation:
Additional persistence was confirmed through scheduled task creation. 
The most notable task was titled UpdateHealthTelemetry, a deceptively benign name likely designed to blend in with legitimate Windows health-related processes.
This ensured long-term malware execution during system uptime.
```kql
DeviceProcessEvents
| where DeviceName contains "anthony"
| where ProcessCommandLine has "BitSentinelCore"
```
![image](https://github.com/user-attachments/assets/fcbbbd34-6a90-4b43-82ee-a0b8d0c652cc)

📌 *Task Name:* `UpdateHealthTelemetry`

### Process Chain:
Pulling together the execution chain, we confirmed the sequence:
```text
BitSentinelCore.exe -> cmd.exe -> schtasks.exe
```

---

## Summary of Findings

| Flag | Description                   | Answer/Value                                     |
| ---- | ----------------------------- | ------------------------------------------------ |
| 1    | Fake AV binary                | `BitSentinelCore.exe`                            |
| 2    | Dropper used to write malware | `csc.exe`                                        |
| 3    | Initial execution method      | `BitSentinelCore.exe`                            |
| 4    | Keylogger file dropped        | `systemreport.lnk`                               |
| 5    | Registry persistence path     | `HKEY_CURRENT_USER\...\Run`                      |
| 6    | Scheduled task name           | `UpdateHealthTelemetry`                          |
| 7    | Process chain                 | `BitSentinelCore.exe -> cmd.exe -> schtasks.exe` |
| 8    | Root cause timestamp          | `2025-05-07T02:00:36.794406Z`                    |

---

## Response Actions

* **Immediate Block:** Hashes and process signatures of `BitSentinelCore.exe` added to threat blocklists
* **Persistence Removal:** Startup `.lnk` file, registry key, and scheduled task manually removed
* **Telemetry Expansion:** Queries extended to check lateral movement beyond `anthony-001`
* **Awareness:** Flag shared with Blue Team and Detection Engineering for rule creation

---

## Diamond Model of Intrusion Analysis

| Feature            | Description                                                                                                                                                      |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Adversary**      | APT group **The Phantom Hackers** — actors targeting privileged accounts through phishing and stealth persistence                                                |
| **Capability**     | Malware disguised as a fake antivirus (`BitSentinelCore.exe`), leveraging LOLBins like `csc.exe`, keylogging, registry persistence, and scheduled tasks          |
| **Infrastructure** | Remote IPs from Nigeria (`102.88.21.215`) and the Philippines (`49.147.196.23`), custom malware staging in `ProgramData`, scheduled task `UpdateHealthTelemetry` |
| **Victim**         | Bubba Rockerfeatherman III — privileged IT admin at Acme Corp on workstation `anthony-001`                                                                       |

                   +-----------------------+
                   |     Infrastructure    |
                   |  (IPs, LOLBins, STs)  |
                   +-----------+-----------+
                               |
                               v
+----------------+     +------+-------+     +------------------+
|   Adversary    |<--->|   Capability  |<--->|      Victim      |
| Phantom Hackers|     | Fake AV, Key  |     |  Bubba @ anthony |
|                |     | logger, Tasks |     |    -001          |
+----------------+     +---------------+     +------------------+



---

## Lessons Learned

* Malware impersonating legitimate tools can easily evade static detection without behavioral telemetry.
* Scheduled tasks with realistic system names (`UpdateHealthTelemetry`) can persist undetected.
* LOLBins like `csc.exe` can be abused to compile and deploy malware post-download.
* Registry and Startup folders remain prime persistence targets.

---

**Report Completed By:** Steven Cruz
**Status:** ✅ All 8 flags investigated and confirmed
