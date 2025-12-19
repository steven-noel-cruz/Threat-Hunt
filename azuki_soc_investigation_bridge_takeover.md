# SOC Incident Investigation – Azuki Import/Export Compromise

**Analyst:** Steven Cruz  
**Source:** Cyber Range SOC Challenge  
**System:** azuki-adminpc

---

## Executive Summary
Bridge Takeover documents a multi-stage intrusion against Azuki Import/Export (梓貿易株式会社) in which a threat actor escalated from an existing foothold into administrative control, established redundant persistence, and exfiltrated sensitive business and credential data using legitimate tooling and trusted infrastructure.

Five days after an earlier file server breach, the attacker re-entered the environment and pivoted laterally from a previously compromised system into the CEO’s administrative workstation. Leveraging valid credentials and native Windows utilities, the actor deployed a command-and-control implant, created and elevated a backdoor administrator account, and conducted extensive discovery to identify high-value data sources.

Sensitive information—including financial records, browser credentials, and password manager data—was staged locally, archived, and exfiltrated via legitimate cloud file-hosting services over HTTPS. The attacker’s tradecraft emphasized stealth over exploitation, abusing trust relationships, administrative tooling, and common services to blend into normal enterprise activity.

This investigation was conducted entirely through Microsoft Defender for Endpoint (MDE) telemetry, without endpoint access or file inspection, demonstrating how a full attack narrative can be reconstructed through systematic hunting, correlation, and MITRE ATT&CK–aligned analysis.

## Key Outcomes

- Confirmed lateral movement using valid credentials into an executive system
- Identified multiple persistence mechanisms, including a C2 implant and backdoor admin account
- Quantified data collection and exfiltration scope
- Mapped attacker behavior across the full kill chain
- Produced IR-ready evidence suitable for remediation, detection engineering, and reporting

---

## Environment Overview

This investigation was conducted within a simulated enterprise environment representing Azuki Import/Export (梓貿易株式会社). The environment consists of Windows-based endpoints monitored exclusively through Microsoft Defender for Endpoint (MDE), with all findings derived from endpoint telemetry.

### Monitoring & Data Sources

The following data sources were available for analysis:

* Microsoft Defender for Endpoint (MDE)
    - Advanced Hunting (KQL)
    - Endpoint telemetry including:
      - Process execution events
      - Logon activity
      - File creation and modification
      - Network connections
      - System and security events


No additional log sources (e.g., firewall logs, proxy logs, or packet captures) were available.

### Investigation Constraints

This threat hunt was intentionally limited to reflect realistic SOC conditions:

- No direct endpoint access
-  No PowerShell or command-line execution
-   No file content inspection
-    No memory or disk forensics
-    No packet capture or network tap data

All conclusions were drawn solely from telemetry and metadata, requiring behavioral analysis and correlation rather than artifact inspection.

### Analysis Approach Implications

Due to these constraints:
- Every indicator had to be observable in logs
- Command intent was inferred from:
    - Process command-line arguments
    - Execution context
    - Timing and sequence
- Attack progression was reconstructed by correlating:
    - Logon events
    - Process execution chains
    - File system activity
    - Network communications

If an action was not reflected in Defender telemetry, it was treated as out of scope for the investigation.

### Why This Matters

These constraints closely mirror real-world SOC investigations, where analysts often:

- Lack direct system access
- Must make decisions based on incomplete data
- Rely on telemetry correlation rather than artifacts

Successfully reconstructing the full attack lifecycle under these conditions demonstrates practical threat hunting and incident response capability, not just theoretical knowledge.

---

## Incident Scope & Objectives

Bridge Takeover represents the third phase in the Azuki Breach Saga, following the events documented in Port of Entry and Cargo Hold. While earlier investigations focused on initial access and server-side compromise, this phase examines the attacker’s escalation into trusted administrative systems and their transition from access to control.

### Incident Scope

The scope of this investigation includes:

* Activity occurring five days after the initial file server breach
* Lateral movement from a previously compromised system into an executive administrative workstation
* Post-compromise actions including:
    - Payload execution
    - Persistence establishment
    - Environment discovery
    - Data collection and staging
    - Data exfiltration
    - Credential harvesting

The investigation intentionally excludes speculation about initial access techniques, as those were addressed in earlier phases of the series.

### Investigation Objectives

This hunt was designed to answer the following key questions:

1. How did the attacker pivot into a high-value administrative system?

    - Identify the source system, account, and target device involved in lateral movement.

2. What persistence mechanisms were established to maintain access?

    - Determine whether access survived credential resets or implant removal.

3. What discovery actions were performed to understand the environment?

    - Identify commands and tooling used to enumerate users, trusts, networks, and data locations.

4. What data was collected and how was it staged?

    - Locate staging directories and quantify the scope of collected data.

5. How was data exfiltrated from the environment?

    - Identify services, destinations, and volumes involved in exfiltration.

6. What credentials were ultimately compromised?

    - Determine whether browser credentials and password manager secrets were accessed.
  
### Why This Phase Matters

This phase marks a strategic shift in the attacker’s behavior:

- From opportunistic access → deliberate control
- From single-system compromise → enterprise-level impact
- From simple persistence → redundant, layered access mechanisms

Understanding this transition is critical for defenders, as it reflects the point where an intrusion becomes a business-impacting incident rather than a contained security event.

--- 

## Investigation Methodology

This investigation followed **a structured, kill-chain–driven threat hunting methodology**, aligned with SOC and DFIR best practices. Rather than searching for isolated indicators, analysis focused on behavioral progression, correlation, and validation across multiple telemetry sources.

### Analytical Framework

The investigation was guided by two primary frameworks:

- **Cyber Kill Chain**
    - Used to understand attacker progression from lateral movement through exfiltration and credential access.

- **MITRE ATT&CK Framework**
    - Used to map observed behaviors to known adversary techniques and ensure comprehensive coverage across tactics.

Each finding was mapped to a specific **ATT&CK tactic and technique**, reinforcing both analytical rigor and reporting clarity.

### Hunting Strategy

Analysis was conducted using a **pivot-based approach**, starting from the scenario’s defined entry point and expanding outward only when supported by evidence.

The general workflow followed this pattern:

1. **Start with Identity and Access**
   - Analyze logon activity to identify lateral movement
   - Confirm source systems, target systems, and accounts involved

2. **Pivot to Execution**
   - Identify process executions tied to the compromised session
   - Examine command-line arguments for intent and obfuscation

3. **Validate Persistence**
   - Look for mechanisms that would survive reboot or account reset
   - Identify redundancy in attacker access paths

4. **Expand into Discovery**
   - Enumerate commands used to understand the environment
   - Identify what the attacker was searching for and why

5. **Confirm Collection and Exfiltration**
   - Track file creation, staging, archiving, and upload activity
   - Quantify the scope of data impacted

6. **Assess Credential Impact**
   - Identify credential harvesting techniques
   - Determine downstream risk to additional systems
  
### Evidence Correlation
No single data point was accepted in isolation. Findings were validated by correlating:

- **Logon events** → user context and trust abuse  
- **Process execution** → attacker intent and tooling  
- **File events** → data staging and collection  
- **Network events** → infrastructure use and exfiltration  

This approach reduced false assumptions and ensured that each conclusion was supported by **multiple, independent telemetry sources**.


### Documentation Discipline
Throughout the investigation:

- Queries were named descriptively and saved
- Key timestamps were noted for timeline reconstruction
- Commands were captured verbatim for IR reporting
- Indicators of compromise were documented for remediation

The result is an investigation that is **reproducible**, **defensible**, and suitable for both operational response and post-incident reporting.

---

##  Attack Chain Overview

This section provides a high-level view of the attacker’s progression during the **Bridge Takeover** incident. Rather than focusing on individual commands or indicators, it illustrates **how discrete actions combined into a cohesive intrusion**, moving from access to impact.

The attacker leveraged **existing trust, native tooling, and legitimate services** to avoid detection, prioritizing stealth and reliability over noisy exploitation.

### Kill Chain Progression (Summary)

1. **Lateral Movement**  
   Pivoted from a previously compromised system into an executive administrative workstation using valid credentials.

2. **Execution**  
   Downloaded and extracted malicious tooling using native command-line utilities and rotated external infrastructure.

3. **Persistence**  
   Established redundant access through a C2 implant, named pipe communication, and a backdoor administrator account.

4. **Discovery**  
   Enumerated sessions, domain trusts, network connections, and credential storage locations to identify high-value targets.

5. **Collection**  
   Staged sensitive business and credential data in a hidden system directory and prepared it for exfiltration.

6. **Exfiltration**  
   Uploaded archived data to anonymous cloud file-sharing services over HTTPS.

7. **Credential Access**  
   Extracted browser credentials and password manager secrets, enabling long-term compromise beyond the initial environment.


###  Kill Chain Diagram

``` mermaid
flowchart LR
    A[Existing Foothold<br/>from prior breach] --> B[Lateral Movement<br/>Valid Accounts]
    B --> C[Execution<br/>Payload Download & Extraction]
    C --> D[Persistence<br/>C2 + Backdoor Account]
    D --> E[Discovery<br/>Sessions, Trusts, Network, Files]
    E --> F[Collection<br/>Data Staging & Archiving]
    F --> G[Exfiltration<br/>Cloud File Uploads]
    G --> H[Credential Access<br/>Browser & Password Manager]

```

### Key Observations

- No exploits were required — the attack relied entirely on **trust abuse and legitimate tooling**
- Each stage **enabled the next**, demonstrating deliberate planning
- The attack only became clearly malicious **late in the chain**, after persistence and discovery were complete

This progression highlights why early detection of **credential misuse, encoded commands, and anomalous administrative behavior** is critical to preventing business-impacting incidents.

---

##  Detailed Findings — Flag-by-Flag Analysis

The following sections document the investigation findings **in the order they were uncovered**, corresponding directly to each flag in the *Bridge Takeover* challenge.

Each flag represents a **discrete investigative milestone** commonly included in real-world incident response and threat intelligence reports. Rather than treating these as isolated answers, the analysis emphasizes:

- **What evidence was identified**
- **How it was discovered**
- **Why it mattered to the overall incident**

All findings are supported by **Microsoft Defender for Endpoint telemetry**, with commands, indicators, and behaviors mapped to **MITRE ATT&CK techniques** where applicable.

> **Note:** While flags are presented individually, they should be interpreted as part of a continuous attack narrative. Many findings build upon previous discoveries, reinforcing the importance of correlation over isolated indicators.

###  Structure of Each Flag Section

Each flag analysis follows a consistent structure:

- **Objective** — What the flag was designed to identify  
- **Evidence Observed** — Key telemetry or artifacts used  
- **Analysis** — How the evidence was interpreted  
- **MITRE ATT&CK Mapping** — Relevant tactics and techniques  

This approach mirrors professional SOC and DFIR reporting standards, ensuring the investigation is **reproducible, defensible, and operationally useful**.

---

### Flag 1: Lateral Movement — Source System

**Objective**  
Identify the originating system used by the attacker to pivot laterally into the administrative environment.

**Evidence Observed**  
Analysis of **RemoteInteractive** logon events across Azuki systems revealed repeated remote sessions originating from a single internal IP address.

**KQL Used (MDE Advanced Hunting):**
```kql
DeviceLogonEvents
| where DeviceName == "azuki-adminpc"
| where RemoteIP != "" and RemoteDeviceName startswith "azuki"
| project Timestamp, DeviceName, ActionType, LogonType, AccountName, RemoteDeviceName, RemoteIP
| sort by Timestamp desc
```

**Key observations:** 
- Logon type: RemoteInteractive
- Source IP address: 10.1.0.204
- Consistent activity across administrative targets

**Analysis**
The source IP address `10.1.0.204` was consistently associated with RemoteInteractive logons into higher-value systems. Correlation with prior investigation context confirmed that this IP belonged to `azuki-sl`, a system compromised during an earlier phase of the Azuki Breach Saga.

This indicates the attacker **reused an existing foothold** rather than exploiting a new vulnerability, leveraging trusted access paths to move laterally within the environment.

Identifying the source system was critical for:
- Establishing the attack progression
- Confirming scope overlap with earlier breaches
- Guiding subsequent pivots into credential usage and target identification


**MITRE ATT&CK Mapping**
- Tactic: Lateral Movement
- Technique: T1078 — Valid Accounts

**Evidence**
<img width="1104" height="555" alt="image" src="https://github.com/user-attachments/assets/07917867-e406-4d35-8db5-689c3b224046" />

*With the source system identified, the investigation pivoted to determining which credentials were used to facilitate lateral movement.*

--- 

###  Flag 2: Lateral Movement — Compromised Credentials

**Objective**  
Identify the account used by the attacker to authenticate during lateral movement. Determining the compromised credentials helps define the blast radius and informs credential reset and containment actions.

**Evidence Observed**  
RemoteInteractive logon events showed repeated use of a single user account across multiple Azuki systems during lateral movement.

**KQL Used (MDE Advanced Hunting):**
```kql
DeviceLogonEvents
| where DeviceName == "azuki-adminpc"
| where RemoteIP != "" and RemoteDeviceName startswith "azuki"
| project Timestamp, DeviceName, ActionType, LogonType, AccountName, RemoteDeviceName, RemoteIP
| sort by Timestamp desc
```
**Key observations:**
- Account used: `yuki.tanaka`
- Logon type: `RemoteInteractive`
- Repeated authentication to administrative systems

**Analysis**  
The account `yuki.tanaka` was consistently associated with RemoteInteractive logons originating from the previously identified source system. This account had been compromised during an earlier phase of the incident and was reused for lateral movement, allowing the attacker to pivot without triggering exploit-based detections.

The reuse of valid credentials indicates:
- Trust abuse rather than vulnerability exploitation
- Increased risk of undetected movement
- Potential exposure of additional systems accessible by this account

**MITRE ATT&CK Mapping**
- **Tactic:** Lateral Movement  
- **Technique:** T1078 — Valid Accounts

**Evidence Screenshot (Placeholder)**
<img width="1104" height="555" alt="image" src="https://github.com/user-attachments/assets/07917867-e406-4d35-8db5-689c3b224046" />

*With the compromised credentials identified, the investigation next focused on determining the specific system that was targeted during lateral movement.*

---

###  Flag 3: Lateral Movement — Target Device

**Objective**  
Identify the high-value system targeted during lateral movement. Determining the destination device clarifies what level of access the attacker achieved and what data was placed at risk.

**Evidence Observed**  
RemoteInteractive logon events originating from the previously identified source IP were correlated to specific destination devices within the Azuki environment.

**KQL Used (MDE Advanced Hunting):**  
```
DeviceLogonEvents
| where DeviceName == "azuki-adminpc"
| where RemoteIP != "" and RemoteDeviceName startswith "azuki"
| project Timestamp, DeviceName, ActionType, LogonType, AccountName, RemoteDeviceName, RemoteIP
| sort by Timestamp desc 
```
**Key observations:**
- Target device: `azuki-adminpc`
- Logon type: `RemoteInteractive`
- Access originated from the compromised source system
- Device naming convention indicates an administrative or executive workstation

**Analysis**  
The device `azuki-adminpc` was identified as the primary destination for lateral movement activity originating from the compromised source system. The naming convention and access pattern strongly suggest this system belonged to an administrative or executive user, making it a high-value target.

Successful access to this device represented a significant escalation in attacker capability. By pivoting into an administrative workstation, the attacker gained visibility into sensitive business data and the ability to perform privileged actions without immediately raising suspicion.

This finding confirms that the attacker’s objective extended beyond persistence and into **control of trusted systems** within the organization.

**MITRE ATT&CK Mapping**
- **Tactic:** Lateral Movement  
- **Technique:** T1078 — Valid Accounts

**Evidence Screenshot (Placeholder)**  
<img width="1104" height="555" alt="image" src="https://github.com/user-attachments/assets/07917867-e406-4d35-8db5-689c3b224046" />

---

###  Flag 4: Execution — Payload Hosting Service

**Objective**  
Identify the external file hosting service used by the attacker to stage and deliver malicious payloads. Documenting attacker infrastructure enables blocking, threat intelligence enrichment, and detection tuning.

**Evidence Observed**  
Network telemetry revealed outbound connections from the compromised administrative system to an external file hosting service during the malware download phase.

**KQL Used (MDE Advanced Hunting):** 
```  
DeviceNetworkEvents
| where DeviceName == "azuki-adminpc"
| where InitiatingProcessRemoteSessionIP == "10.1.0.204"
| where InitiatingProcessCommandLine contains "curl.exe" or InitiatingProcessCommandLine contains "powershell"
| where RemoteUrl != ""
| sort by Timestamp desc 
```
**Key observations:**
- External hosting domain identified: `litter.catbox.moe`
- Connections occurred during the execution phase
- Hosting service differed from infrastructure used in earlier hunts
- Domain is consistent with short-lived, anonymous file hosting

**Analysis**  
The domain `litter.catbox.moe` was identified as the payload hosting service used to stage malicious archives. This service is commonly abused for temporary file storage and allows attackers to rapidly rotate infrastructure, reducing the effectiveness of static domain blocklists.

The use of a new hosting service compared to previous phases of the Azuki Breach Saga indicates deliberate **infrastructure rotation**, a technique used to evade detection and attribution while maintaining operational continuity.

Identifying the payload hosting service provides defenders with an actionable indicator for:
- Network-level blocking
- Retrospective threat hunting
- Detection engineering improvements

**MITRE ATT&CK Mapping**
- **Tactic:** Execution  
- **Technique:** T1608.001 — Stage Capabilities: Upload Malware

**Evidence Screenshot (Placeholder)**  
<img width="1565" height="137" alt="image" src="https://github.com/user-attachments/assets/e595bc5d-5bbd-42a6-9cf0-641ecf0cc9e7" />

---

###  Flag 5: Execution — Malware Download Command

**Objective**  
Identify the exact command used to download the malicious archive. Capturing the full command line provides insight into attacker tradecraft and supports command-line–based detections.

**Evidence Observed**  
Process execution telemetry on the compromised administrative system showed use of a native command-line utility to retrieve a remote file masquerading as a legitimate Windows update.

**KQL Used (MDE Advanced Hunting):**  
```  
DeviceNetworkEvents
| where DeviceName == "azuki-adminpc"
| where InitiatingProcessRemoteSessionIP == "10.1.0.204"
| where InitiatingProcessCommandLine contains "curl.exe" or InitiatingProcessCommandLine contains "powershell"
| where RemoteUrl != ""
| sort by Timestamp desc 
```

**Key observations:**
- Utility used: `curl.exe`
- Download destination: `C:\Windows\Temp\cache\KB5044273-x64.7z`
- Filename mimics a legitimate Windows security update
- Payload retrieved from previously identified hosting infrastructure

**Analysis**  
The attacker used `curl.exe`, a legitimate Windows utility, to download a malicious archive directly to a system cache directory. The archive filename was crafted to resemble a Windows knowledge base update, a common masquerading technique intended to reduce suspicion during casual inspection.

Using native tooling for payload retrieval allowed the attacker to blend malicious activity with routine administrative behavior, bypassing simple allowlisting controls and reducing the likelihood of immediate detection.

This command represents the transition from access to **active execution**, marking a critical escalation in the intrusion.

**MITRE ATT&CK Mapping**
- **Tactic:** Execution  
- **Technique:** T1105 — Ingress Tool Transfer

**Evidence Screenshot (Placeholder)**  
<img width="1565" height="137" alt="image" src="https://github.com/user-attachments/assets/e595bc5d-5bbd-42a6-9cf0-641ecf0cc9e7" />

---

###  Flag 6: Execution — Archive Extraction Command

**Objective**  
Identify the command used to extract the downloaded password-protected archive. Understanding archive extraction behavior helps reveal how attackers bypass content inspection and application control mechanisms.

**Evidence Observed**  
Process execution telemetry showed the use of a legitimate compression utility to extract the contents of the previously downloaded archive into the same cache directory.

**KQL Used (MDE Advanced Hunting):**  
```
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where FileName contains "7z"
| project Timestamp,DeviceName, FileName, ProcessCommandLine  
| sort by Timestamp desc 
```
**Key observations:**
- Compression utility used: `7z.exe`
- Archive extracted: `KB5044273-x64.7z`
- Archive was password-protected
- Extraction output directory matched the download cache path
- Extraction occurred shortly after archive download

**Analysis**  
The attacker used `7z.exe`, a commonly trusted compression utility, to extract a password-protected archive containing malicious tooling. Password protection prevents basic security controls from inspecting archive contents prior to extraction, allowing malicious files to evade detection until executed.

By extracting the archive into the same cache directory used for staging, the attacker maintained a consistent workflow and reduced the likelihood of drawing attention through unusual file paths or behavior.

This step completed the delivery phase and enabled subsequent execution of attacker-controlled payloads.

**MITRE ATT&CK Mapping**
- **Tactic:** Execution  
- **Technique:** T1140 — Deobfuscate/Decode Files

**Evidence Screenshot (Placeholder)**  
<img width="1081" height="133" alt="image" src="https://github.com/user-attachments/assets/84c17ed6-6c74-4049-b51c-6e8b274be8b7" />

---

###  Flag 7: Persistence — C2 Implant

**Objective**  
Identify the command-and-control implant deployed by the attacker to maintain persistent access to the compromised system. Implant identification is critical for scoping compromise and ensuring complete remediation.

**Evidence Observed**  
File creation telemetry revealed the appearance of a new executable in the cache directory immediately following archive extraction.

**KQL Used (MDE Advanced Hunting):**  
```
DeviceFileEvents
| where DeviceName == "azuki-adminpc"
| where InitiatingProcessCommandLine contains @"KB5044273-x64.7z"
| project Timestamp,DeviceName, FileName, FolderPath, InitiatingProcessCommandLine
| sort by Timestamp desc
```

**Key observations:**
- Newly created executable: `meterpreter.exe`
- File created shortly after archive extraction
- File location aligned with previously used staging directory
- Filename references known offensive security tooling

**Analysis**  
The executable `meterpreter.exe` was identified as the attacker’s command-and-control implant. Meterpreter is a well-known post-exploitation framework commonly used to establish interactive remote access to compromised systems.

Placing the implant within an existing cache directory allowed the attacker to blend malicious artifacts with previously staged files, reducing the likelihood of detection through anomalous directory creation or path usage.

The deployment of a dedicated C2 implant marked a shift from initial execution to **persistent control**, enabling the attacker to execute commands, deploy additional tooling, and maintain long-term access.

**MITRE ATT&CK Mapping**
- **Tactic:** Persistence  
- **Technique:** T1059 — Command and Scripting Interpreter

**Evidence Screenshot (Placeholder)**  
<img width="1370" height="151" alt="image" src="https://github.com/user-attachments/assets/094b9341-6e33-4918-8e79-6692a78ceb7b" />

---










