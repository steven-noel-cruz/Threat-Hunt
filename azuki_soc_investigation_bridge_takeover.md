# ++SOC Incident Investigation – Azuki Import/Export Compromise++

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

**Evidence Screenshot**
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

**Evidence Screenshot**
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

**Evidence Screenshot**  
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

**Evidence Screenshot**  
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

**Evidence Screenshot**  
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

**Evidence Screenshot**  
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

**Evidence Screenshot**  
<img width="1370" height="151" alt="image" src="https://github.com/user-attachments/assets/094b9341-6e33-4918-8e79-6692a78ceb7b" />

---

###  Flag 8: Persistence — Named Pipe

**Objective**  
Identify the named pipe created by the command-and-control implant for inter-process communication. Named pipes are commonly used by C2 frameworks to relay commands while blending into normal Windows behavior.

**Evidence Observed**  
System event telemetry showed the creation of a named pipe shortly after execution of the C2 implant.

**KQL Used (MDE Advanced Hunting):**
```
DeviceEvents
| where DeviceName == "azuki-adminpc"
| where ActionType == @"NamedPipeEvent"
| where InitiatingProcessFolderPath contains "meterpreter"
| project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, AdditionalFields
```
**Key observations:**
- Named pipe created: `\Device\NamedPipe\msf-pipe-5902`
- Pipe creation occurred shortly after `meterpreter.exe` execution
- Naming pattern is consistent with Metasploit-based tooling

**Analysis**  
The named pipe `\Device\NamedPipe\msf-pipe-5902` was created by the C2 implant to facilitate internal command-and-control communication. Metasploit and Meterpreter commonly use named pipes with predictable naming conventions, which can serve as strong behavioral indicators when correlated with suspicious process execution.

Because named pipes are also used legitimately by Windows and third-party applications, detection typically relies on **contextual correlation** rather than pipe creation alone. In this case, the timing and association with a known C2 implant strongly indicate malicious use.

Identifying the named pipe provides a valuable artifact for:
- Endpoint detection tuning
- Retrospective hunting
- Incident scoping

**MITRE ATT&CK Mapping**
- **Tactic:** Command and Control  
- **Technique:** T1090.001 — Internal Proxy

**Evidence Screenshot**  
<img width="1365" height="354" alt="image" src="https://github.com/user-attachments/assets/dc1cf421-7892-47d5-a846-c37041011ff5" />

---

###  Flag 9: Credential Access — Decoded Account Creation

**Objective**  
Identify the malicious command hidden within an encoded PowerShell execution. Decoding obfuscated commands reveals attacker intent that is not immediately visible through basic log inspection.

**Evidence Observed**  
Process execution telemetry revealed PowerShell commands executed with Base64-encoded input, a common technique used to evade basic string-based detections.

**KQL Used (MDE Advanced Hunting):**  
```
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where ProcessCommandLine contains "enc"
| where InitiatingProcessAccountName != @"system"
| where FileName contains "powershell"
| extend Enc = extract(@"-EncodedCommand\s+([A-Za-z0-9+/=]+)", 1, ProcessCommandLine)
| extend Decoded = base64_decode_tostring(Enc)
| project Timestamp, DeviceName, ProcessCommandLine, Decoded 
```
**Key observations:**
- PowerShell executed with encoded input
- Encoded payload concealed account creation activity
- Execution occurred after C2 implant deployment

**Analysis**  
Decoding the Base64-encoded PowerShell payload revealed the following command:

`net user yuki.tanaka2 B@ckd00r2024! /add`

This command created a new local user account with a strong, attacker-controlled password. The use of Base64 encoding obscured the command’s intent in raw telemetry, allowing the activity to blend into normal administrative PowerShell usage.

Creating a new account provided the attacker with an **alternative access mechanism** independent of the original compromised credentials, increasing resilience against containment actions such as password resets.

**MITRE ATT&CK Mapping**
- **Tactic:** Credential Access  
- **Technique:** T1027 — Obfuscated Files or Information

**Evidence Screenshot**  
<img width="1260" height="115" alt="image" src="https://github.com/user-attachments/assets/6e8d04d8-5ca1-4e32-91ed-3d3dd78a48ea" />

---

###  Flag 10: Persistence — Backdoor Account

**Objective**  
Identify the backdoor account created by the attacker to maintain alternate access if primary credentials or implants were discovered and removed.

**Evidence Observed**  
Decoded command output from the previous flag revealed the creation of a new local user account designed to blend in with existing legitimate accounts.

**KQL Used (MDE Advanced Hunting):**  
```
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where ProcessCommandLine contains "enc"
| where InitiatingProcessAccountName != @"system"
| where FileName contains "powershell"
| extend Enc = extract(@"-EncodedCommand\s+([A-Za-z0-9+/=]+)", 1, ProcessCommandLine)
| extend Decoded = base64_decode_tostring(Enc)
| project Timestamp, DeviceName, ProcessCommandLine, Decoded 
```
**Key observations:**
- Newly created account: `yuki.tanaka2`
- Account naming closely mirrors an existing legitimate user
- Account creation followed shortly after C2 implant deployment

**Analysis**  
The account `yuki.tanaka2` was identified as a backdoor account created by the attacker. By closely mimicking the name of an existing user, the attacker reduced the likelihood of immediate detection during routine account reviews.

Backdoor accounts provide attackers with a **durable persistence mechanism**, allowing re-entry even if implants are removed or original credentials are reset. This technique is especially effective in environments with limited account auditing or alerting on local user creation.

The presence of this account significantly increased the attacker’s ability to maintain long-term access to the compromised system.

**MITRE ATT&CK Mapping**
- **Tactic:** Persistence  
- **Technique:** T1136.001 — Create Account: Local Account

**Evidence Screenshot**  
<img width="1260" height="115" alt="image" src="https://github.com/user-attachments/assets/6e8d04d8-5ca1-4e32-91ed-3d3dd78a48ea" />

---

###  Flag 11: Persistence — Decoded Privilege Escalation Command

**Objective**  
Identify the command used to elevate the privileges of the backdoor account. Privilege escalation of attacker-created accounts enables full administrative control and long-term persistence.

**Evidence Observed**  
Additional Base64-encoded PowerShell executions were identified following the creation of the backdoor account. These executions obscured the intent of privilege modification actions.

**KQL Used (MDE Advanced Hunting):**  
```
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where ProcessCommandLine contains "enc"
| where InitiatingProcessAccountName != @"system"
| where FileName contains "powershell"
| extend Enc = extract(@"-EncodedCommand\s+([A-Za-z0-9+/=]+)", 1, ProcessCommandLine)
| extend Decoded = base64_decode_tostring(Enc)
| project Timestamp, DeviceName, ProcessCommandLine, Decoded 
```  

**Key observations:**
- PowerShell executed with encoded input
- Encoded payload modified local group membership
- Activity occurred shortly after backdoor account creation

**Analysis**  
Decoding the Base64-encoded PowerShell command revealed the following action:

`net localgroup Administrators yuki.tanaka2 /add`

This command added the attacker-created backdoor account to the local **Administrators** group, granting full administrative privileges. Elevating the account in this manner ensured that the attacker could perform privileged actions without relying on the original compromised credentials.

This step completed a layered persistence strategy:
- C2 implant for interactive access
- Backdoor account for redundancy
- Administrative privileges for unrestricted control

**MITRE ATT&CK Mapping**
- **Tactic:** Persistence  
- **Technique:** T1078.003 — Valid Accounts: Local Accounts

**Evidence Screenshot**  
<img width="1396" height="138" alt="image" src="https://github.com/user-attachments/assets/b35bb587-c766-41b0-a1bb-5d5e4c733bd1" />

---

###  Flag 12: Discovery — Session Enumeration

**Objective**  
Identify the command used by the attacker to enumerate active Remote Desktop sessions. Session enumeration allows attackers to identify logged-in users, high-value targets, and opportunities to avoid detection.

**Evidence Observed**  
Process execution telemetry showed execution of a native Windows command commonly used to list active terminal service sessions.

**KQL Used (MDE Advanced Hunting):**  
```
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"  
| where ProcessCommandLine has_any ("qwinsta","query user")  
| project Timestamp, DeviceName,AccountName, ProcessCommandLine
```
**Key observations:**
- Session enumeration command executed: `qwinsta`
- Command executed in an administrative context
- Activity occurred after persistence was established

**Analysis**  
The attacker executed the `qwinsta` command to enumerate active Remote Desktop sessions on the compromised system. This command provides visibility into logged-on users and active sessions, enabling the attacker to identify high-value accounts or determine whether an administrator was currently active.

Session enumeration is often performed after persistence is secured, allowing the attacker to operate more confidently while minimizing the risk of detection.

This behavior demonstrates a methodical approach to situational awareness prior to further discovery and data access.

**MITRE ATT&CK Mapping**
- **Tactic:** Discovery  
- **Technique:** T1033 — System Owner/User Discovery

**Evidence Screenshot**  
<img width="363" height="123" alt="image" src="https://github.com/user-attachments/assets/4d73783e-8665-4435-94a1-6cb8134d0365" />

---

###  Flag 13: Discovery — Domain Trust Enumeration

**Objective**  
Identify how the attacker enumerated domain trust relationships. Understanding trust relationships helps attackers identify additional lateral movement paths and high-value targets across connected environments.

**Evidence Observed**  
Process execution telemetry showed execution of a native Windows command used to query domain trust information with parameters that expose all trust relationships.

**KQL Used (MDE Advanced Hunting):**  
```
DeviceProcessEvents  
| where DeviceName == "azuki-adminpc"  
| where InitiatingProcessAccountName == @"yuki.tanaka"
| where ProcessCommandLine contains "trust"  
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine  
```
**Key observations:**
- Command executed: `"nltest.exe" /domain_trusts /all_trusts`
- Output enumerates direct and transitive domain trusts
- Activity occurred during the broader discovery phase

**Analysis**  
The attacker executed `nltest /domain_trusts /all_trusts` to enumerate trust relationships within the domain. This command provides visibility into how authentication and authorization flow between domains, revealing potential paths for lateral movement beyond the initially compromised environment.

By enumerating all trust types, including transitive trusts, the attacker demonstrated intent to understand the broader organizational landscape rather than limiting activity to a single domain.

This behavior aligns with deliberate reconnaissance aimed at identifying expansion opportunities and assessing the full potential impact of the compromise.

**MITRE ATT&CK Mapping**
- **Tactic:** Discovery  
- **Technique:** T1482 — Domain Trust Discovery

**Evidence Screenshot**  
<img width="436" height="340" alt="image" src="https://github.com/user-attachments/assets/f881e608-3bfa-4824-8a8c-2ea594e44e6c" />

---

###  Flag 14: Discovery — Network Connection Enumeration

**Objective**  
Identify the command used by the attacker to enumerate active network connections and associated processes. Network connection enumeration helps attackers understand active sessions, listening services, and potential lateral movement opportunities.

**Evidence Observed**  
Process execution telemetry showed execution of a native Windows utility commonly used to list active network connections along with the owning process identifiers.

**KQL Used (MDE Advanced Hunting):**  
```
DeviceProcessEvents
| where Timestamp between (
    datetime(2025-11-24T00:00:00.7943081Z)
    ..
    datetime(2025-11-26T00:00:00.7943081Z)
)
| where DeviceName == "azuki-adminpc"  
| where ProcessCommandLine contains "kdbx"  
| where InitiatingProcessAccountName == @"yuki.tanaka"
| project Timestamp, DeviceName, AccountName, FileName,ProcessVersionInfoFileDescription, ProcessCommandLine
| order by Timestamp desc 
```

**Key observations:**
- Command executed: `netstat -ano`
- Output includes active connections, listening ports, and process IDs
- Activity occurred during the discovery phase following session and trust enumeration

**Analysis**  
The attacker executed `netstat -ano` to enumerate active network connections and identify which processes owned each connection. Including the `-o` flag provided process identifiers, enabling the attacker to correlate network activity with specific applications or services.

This information can be used to identify:
- Active management sessions
- Internally exposed services
- Processes suitable for monitoring, hijacking, or further investigation

Network enumeration at this stage reflects a methodical effort to build situational awareness before proceeding to data discovery and collection.

**MITRE ATT&CK Mapping**
- **Tactic:** Discovery  
- **Technique:** T1049 — System Network Connections Discovery

**Evidence Screenshot**  
<img width="376" height="149" alt="Screenshot 2025-12-19 163759" src="https://github.com/user-attachments/assets/508c311a-48e4-417d-9d0f-58c03e639e60" />


---

###  Flag 15: Discovery — Password Database Search

**Objective**  
Identify how the attacker searched for password management databases within user directories. Password databases represent high-value targets because they may contain credentials for multiple systems.

**Evidence Observed**  
Process execution telemetry showed recursive file enumeration targeting password database file extensions within user profile directories.

**KQL Used (MDE Advanced Hunting):**  
```
| where Timestamp between (
    datetime(2025-11-24T00:00:00.7943081Z)
    ..
    datetime(2025-11-26T00:00:00.7943081Z)
)
| where DeviceName == "azuki-adminpc"  
| where ProcessCommandLine contains "kdbx"  
| where InitiatingProcessAccountName == @"yuki.tanaka"
| project Timestamp, DeviceName, AccountName, FileName,ProcessVersionInfoFileDescription, ProcessCommandLine
| order by Timestamp desc 
```
**Key observations:**
- Recursive search of user directories
- Targeted KeePass database files (`.kdbx`)
- Enumeration focused on credential storage locations

**Analysis**  
The attacker used a recursive file search to locate KeePass password database files within user directories. KeePass databases are commonly used to store large numbers of credentials, making them a priority target during post-compromise discovery.

By searching specifically for `.kdbx` files, the attacker demonstrated awareness of common enterprise password management practices and intentionally focused on files likely to yield high-impact credential access.

This activity represents a transition from environmental discovery to **credential-focused reconnaissance**, directly setting the stage for subsequent credential theft.

**MITRE ATT&CK Mapping**
- **Tactic:** Discovery  
- **Technique:** T1552.001 — Credentials in Files

**Evidence Screenshot**  
<img width="1391" height="158" alt="Screenshot 2025-12-19 164441" src="https://github.com/user-attachments/assets/40c63662-27a0-4884-a092-21a2d2007d26" />

---

###  Flag 16: Discovery — Plaintext Credential File

**Objective**  
Identify a plaintext credential file accessed by the attacker. Plaintext password files represent critical security failures and often provide immediate access to additional systems.

**Evidence Observed**  
Process execution telemetry showed an interactive application being used to open a plaintext password file during a remote session originating from the previously compromised system.

**KQL Used (MDE Advanced Hunting):**  
DeviceProcessEvents  
| where DeviceName == "azuki-adminpc"  
| where InitiatingProcessRemoteSessionIP == "10.1.0.204"  
| where ProcessCommandLine has "OLD-Passwords.txt"  
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine  
| order by Timestamp desc  

**Key observations:**
- Application used: `notepad.exe`
- File accessed: `OLD-Passwords.txt`
- File location: User Desktop directory
- Action performed during a RemoteInteractive session
- Activity attributed to compromised account `yuki.tanaka`

**Analysis**  
The attacker explicitly opened the file `OLD-Passwords.txt` using `notepad.exe`, demonstrating **intentional interaction** with a plaintext credential file rather than incidental access or automated scanning. This action occurred within a remote session originating from the previously compromised source system, firmly tying the activity to lateral movement behavior.

Plaintext password files commonly contain reused, legacy, or high-privilege credentials. By directly opening this file, the attacker bypassed more complex credential theft techniques and gained immediate access to sensitive authentication material.

This behavior significantly increased the potential impact of the compromise and highlights the ongoing risk posed by insecure credential storage practices.

**MITRE ATT&CK Mapping**
- **Tactic:** Discovery  
- **Technique:** T1552.001 — Credentials in Files

**Evidence Screenshot**  
<img width="582" height="188" alt="image" src="https://github.com/user-attachments/assets/09edfa20-a39d-4ac3-ad91-869b3a705561" />

---

###  Flag 17: Collection — Data Staging Directory

**Objective**  
Identify the directory used by the attacker to stage collected data prior to archiving and exfiltration. Staging directories provide critical insight into attacker workflow and data handling.

**Evidence Observed**  
After identifying attacker interaction with sensitive data in the user’s Documents directory, the investigation pivoted to identifying **where that data was being aggregated**. File system and process telemetry revealed repeated references to a single directory within a legitimate-looking Windows system path.

**KQL Used (MDE Advanced Hunting):**  
```
DeviceProcessEvents  
| where DeviceName == "azuki-adminpc"  
| where InitiatingProcessRemoteSessionIP == "10.1.0.204"  
| where InitiatingProcessAccountName == "yuki.tanaka"  
| where ProcessCommandLine has @"C:\Users\yuki.tanaka\Documents\"  
| where FileName in ("Robocopy.exe","xcopy.exe","cmd.exe","powershell.exe")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessRemoteSessionIP, FileName, ProcessCommandLine  
| order by Timestamp desc  
```
**Key observations:**
- Staging directory identified: `C:\ProgramData\Microsoft\Crypto\staging`
- Directory path closely resembles legitimate Windows cryptographic service locations
- Directory repeatedly referenced as the destination for copied user data
- Activity occurred during an active RemoteInteractive session

**Analysis**  
The directory `C:\ProgramData\Microsoft\Crypto\staging` was identified as the attacker’s centralized data staging location. By selecting a path that mimics legitimate Windows cryptographic service directories, the attacker reduced the likelihood of detection during routine inspection or automated monitoring.

This directory served as the aggregation point for sensitive data copied from the user’s Documents directory, confirming its role as a preparatory step prior to archiving and exfiltration. Identifying this staging location was critical for scoping the volume of collected data and correlating subsequent archive creation and outbound transfer activity.

**MITRE ATT&CK Mapping**
- **Tactic:** Collection  
- **Technique:** T1074.001 — Data Staged: Local Data Staging

**Evidence Screenshot**  
<img width="1623" height="165" alt="image" src="https://github.com/user-attachments/assets/b7a782c0-6aa2-404f-bc4e-ccf200825576" />

---

###  Flag 18: Collection — Automated Data Collection Command

**Objective**  
Identify the command used by the attacker to automate bulk collection of sensitive data. Automated collection enables efficient harvesting of large data sets while minimizing manual interaction.

**Evidence Observed**  
After identifying the attacker’s data staging directory, the investigation focused on determining **how data was moved into that location**. Process execution telemetry referencing the user’s Documents directory revealed repeated bulk copy operations.

**KQL Used (MDE Advanced Hunting):**  
```
DeviceProcessEvents  
| where DeviceName == "azuki-adminpc"  
| where InitiatingProcessRemoteSessionIP == "10.1.0.204"  
| where InitiatingProcessAccountName == "yuki.tanaka"  
| where ProcessCommandLine has @"C:\Users\yuki.tanaka\Documents\"  
| where FileName == "Robocopy.exe"  
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine  
| order by Timestamp desc  
```
**Key observations:**
- Repeated execution of `Robocopy.exe`
- Bulk copying of multiple business-related directories
- Source directories included Banking, Tax-Records, QuickBooks, and Contracts
- Destination paths consistently pointed to `C:\ProgramData\Microsoft\Crypto\staging\`
- Commands executed during an active RemoteInteractive session

**Analysis**  
The attacker used `Robocopy.exe` to perform automated, recursive copying of sensitive user data into the staging directory. The command was executed multiple times to target specific business-related folders, indicating a structured approach to data collection rather than opportunistic access.

The use of reliability-focused flags (`/E`, `/R:1`, `/W:1`, `/NP`) suggests the attacker intended to ensure complete data transfer while minimizing noise and retry delays. Leveraging a native Windows utility allowed the activity to blend with legitimate administrative behavior.

This step confirms the attacker’s transition from discovery into **systematic data collection**, preparing the environment for subsequent archiving and exfiltration.

**MITRE ATT&CK Mapping**
- **Tactic:** Collection  
- **Technique:** T1119 — Automated Collection

**Evidence Screenshot**  
<img width="1623" height="165" alt="image" src="https://github.com/user-attachments/assets/b7a782c0-6aa2-404f-bc4e-ccf200825576" />

--

### 🚩 Flag 19: Collection — Exfiltration Volume

**Objective**  
Quantify the number of archives prepared for exfiltration. Measuring archive volume helps determine the scope of data theft and supports impact assessment.

**Evidence Observed**  
After identifying automated data collection into the staging directory, the investigation pivoted to identifying **archive creation activity** within that location. File telemetry revealed multiple compressed files created in preparation for outbound transfer.

**KQL Used (MDE Advanced Hunting):**  
```
DeviceFileEvents  
| where DeviceName == "azuki-adminpc"  
| where FolderPath startswith @"C:\ProgramData\Microsoft\Crypto\staging"  
| where FileName has_any (".7z",".zip",".tar",".gz")  
| project Timestamp, DeviceName, FileName, FolderPath
```
**Key observations:**
- Total archives created: **8**
- Archives created within the staging directory
- Compression occurred after automated data collection completed
- Archive filenames were unique, indicating segmented data packaging

**Analysis**  
Eight distinct archives were created within the staging directory, indicating the attacker segmented collected data into multiple packages prior to exfiltration. Segmenting archives can improve transfer reliability, reduce the risk of total data loss during interrupted uploads, and allow selective re-exfiltration if needed.

The timing of archive creation, following structured data collection and staging, confirms a deliberate workflow consistent with mature data theft operations.

Quantifying archive volume provides defenders with a measurable indicator of impact and helps prioritize response actions related to data exposure and notification requirements.

**MITRE ATT&CK Mapping**
- **Tactic:** Collection  
- **Technique:** T1560.001 — Archive Collected Data

**Evidence Screenshot**  
<img width="1096" height="277" alt="image" src="https://github.com/user-attachments/assets/199d9073-301b-490c-9db5-6bd5b5500382" />

---

###  Flag 20: Credential Access — Credential Theft Tool Download

**Objective**  
Identify the command used by the attacker to download a credential theft tool. Downloading specialized tooling indicates a shift toward harvesting credentials beyond those already discovered on disk.

**Evidence Observed**  
Process execution telemetry revealed additional outbound file download activity after data collection and archiving were completed. The attacker reused previously established external hosting infrastructure to retrieve credential theft tooling.

**KQL Used (MDE Advanced Hunting):**  
```
DeviceProcessEvents  
| where DeviceName == "azuki-adminpc"  
| where InitiatingProcessRemoteSessionIP == "10.1.0.204"  
| where FileName == "curl.exe"  
| where ProcessCommandLine has "catbox"  
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine  
| order by Timestamp desc  
```
**Key observations:**
- Download utility used: `curl.exe`
- Archive downloaded: `m-temp.7z`
- Hosting service reused: `litter.catbox.moe`
- Download occurred after data staging and archive creation

**Analysis**  
The attacker used `curl.exe`, a legitimate Windows command-line utility, to download an additional archive containing credential theft tooling. By reusing the same external hosting service observed earlier in the execution phase, the attacker demonstrated infrastructure reuse to maintain operational efficiency.

The decision to download credential theft tooling after completing data collection suggests the attacker sought to **expand long-term access** by harvesting additional credentials, rather than relying solely on previously discovered plaintext files or password databases.

This activity marks a transition from data-focused objectives to **credential-centric post-exploitation**, increasing the potential downstream impact of the intrusion.

**MITRE ATT&CK Mapping**
- **Tactic:** Credential Access  
- **Technique:** T1105 — Ingress Tool Transfer

**Evidence Screenshot**  
<img width="558" height="144" alt="image" src="https://github.com/user-attachments/assets/4bc8689c-00df-4409-bf67-1510cb738f2b" />

---

### Flag 21: Credential Access — Browser Credential Theft

**Objective**  
Identify the command used by the attacker to extract saved browser credentials. Browser credential stores are high-value targets because they often contain reusable passwords for internal and external services.

**Evidence Observed**  
Following the download of credential theft tooling, process execution telemetry showed execution of the tool with module-specific parameters targeting browser credential storage.

**KQL Used (MDE Advanced Hunting):** 
```
DeviceProcessEvents  
| where DeviceName == "azuki-adminpc"  
| where InitiatingProcessRemoteSessionIP == "10.1.0.204"  
| where FileName in ("m.exe","mimikatz.exe")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine  
| order by Timestamp desc  
```
**Key observations:**
- Credential theft tool executed: `m.exe`
- DPAPI module targeted Chrome credential storage
- Input file referenced Chrome `Login Data` database
- Execution occurred after credential theft tooling was downloaded

**Analysis**  
The attacker executed the credential theft tool with the `dpapi::chrome` module to extract saved Google Chrome credentials from the local user profile. This technique leverages Windows DPAPI to decrypt stored browser credentials without interacting with LSASS, reducing the likelihood of triggering memory-dump–focused detections.

Targeting browser credential stores allowed the attacker to harvest credentials for web applications, cloud services, and internal portals, significantly expanding the potential impact of the compromise.

This behavior demonstrates a deliberate focus on **credential longevity**, enabling access persistence beyond the compromised host itself.

**MITRE ATT&CK Mapping**
- **Tactic:** Credential Access  
- **Technique:** T1555.003 — Credentials from Web Browsers

**Evidence Screenshot (Placeholder)**  
<img width="931" height="157" alt="image" src="https://github.com/user-attachments/assets/927c31be-66e1-4d19-b5d9-cae1be012466" />

---

### Flag 22: Exfiltration — Data Upload Command

**Objective**  
Identify the command used to exfiltrate collected data from the environment. Understanding the exact exfiltration mechanism enables defenders to detect, block, and investigate similar activity.

**Evidence Observed**  
After archive creation and credential harvesting, network-aware process execution telemetry revealed outbound HTTP POST requests consistent with file upload activity.

**KQL Used (MDE Advanced Hunting):**  
DeviceProcessEvents  
| where DeviceName == "azuki-adminpc"  
| where InitiatingProcessRemoteSessionIP == "10.1.0.204"  
| where FileName == "curl.exe"  
| where ProcessCommandLine has_any ("-X POST","-F")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine  
| order by Timestamp desc  

**Key observations:**
- HTTP client used: `curl.exe`
- Exfiltration method: HTTP POST with form-based file upload
- Archive uploaded: `credentials.tar.gz`
- Upload destination was an external file hosting service

**Analysis**  
The attacker used `curl.exe` to perform an HTTP POST request containing a form-based file upload. This technique allows large files to be transferred reliably while blending with legitimate web traffic.

By leveraging HTTPS-based uploads to a legitimate file hosting service, the attacker avoided the need for custom C2 infrastructure and reduced the likelihood of detection by perimeter security controls.

This activity marks the transition from internal data handling to **active data exfiltration**, representing a critical point of business impact.

**MITRE ATT&CK Mapping**
- **Tactic:** Exfiltration  
- **Technique:** T1567 — Exfiltration Over Web Service

**Evidence Screenshot**  
<img width="1220" height="258" alt="image" src="https://github.com/user-attachments/assets/ec7426cb-fb90-427a-8f8a-15dd1b46d86e" />

---

###  Flag 23: Exfiltration — Cloud Storage Service

**Objective**  
Identify the cloud storage service used by the attacker to receive exfiltrated data. Knowing the service enables defenders to apply domain-based blocking and enrich threat intelligence.

**Evidence Observed**  
Review of the data upload command identified an external cloud storage service being used as the destination for the exfiltrated archive.

**KQL Used (MDE Advanced Hunting):**  
```
DeviceNetworkEvents  
| where DeviceName == "azuki-adminpc"  
| where InitiatingProcessRemoteSessionIP == "10.1.0.204"  
| where RemoteUrl has "gofile"  
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteUrl, RemoteIP  
| order by Timestamp desc  
```
**Key observations:**
- Cloud storage service identified: `gofile.io`
- Service supports anonymous, temporary file hosting
- Commonly abused for malware distribution and data exfiltration
- Activity aligned with previously observed upload commands

**Analysis**  
The domain `gofile.io` was identified as the cloud storage service used to receive exfiltrated data. This service provides anonymous file uploads and temporary storage links, making it attractive for attackers seeking to minimize attribution and persistence of stolen data.

Using a legitimate cloud storage provider allowed the attacker to blend exfiltration traffic with normal web activity, complicating detection and response efforts.

Identifying the exfiltration service provides defenders with a clear opportunity for domain-based blocking, retrospective traffic analysis, and threat intelligence correlation.

**MITRE ATT&CK Mapping**
- **Tactic:** Exfiltration  
- **Technique:** T1567.002 — Exfiltration to Cloud Storage

**Evidence Screenshot**  
<img width="314" height="146" alt="image" src="https://github.com/user-attachments/assets/3ff8b963-420d-418c-b796-edf695f9dcce" />

---

###  Flag 24: Exfiltration — Destination Server IP

**Objective**  
Identify the IP address of the server receiving exfiltrated data. IP-level indicators enable network-layer blocking and support threat intelligence correlation when domain-based controls are bypassed.

**Evidence Observed**  
Network telemetry correlated outbound connections to the previously identified cloud storage service with a specific remote IP address during the data upload window.

**KQL Used (MDE Advanced Hunting):**  
```
DeviceNetworkEvents  
| where DeviceName == "azuki-adminpc"  
| where InitiatingProcessRemoteSessionIP == "10.1.0.204"  
| where RemoteUrl has "gofile"  
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteUrl, RemoteIP  
| order by Timestamp desc  
```
**Key observations:**
- Exfiltration server IP identified: `45.112.123.227`
- IP associated with the cloud storage service backend
- Connections occurred during active data upload activity
- IP-level indicator remained consistent across sessions

**Analysis**  
The IP address `45.112.123.227` was identified as the backend server receiving exfiltrated data. While the attacker leveraged a legitimate cloud storage domain, resolving and capturing the destination IP provides defenders with an additional enforcement point beyond domain-based controls.

IP-level indicators are particularly valuable in environments where DNS-based blocking is unavailable, delayed, or circumvented. This finding enables defenders to perform retrospective traffic analysis and implement temporary containment measures during active response.

**MITRE ATT&CK Mapping**
- **Tactic:** Exfiltration  
- **Technique:** T1041 — Exfiltration Over C2 Channel

**Evidence Screenshot**  
<img width="314" height="146" alt="image" src="https://github.com/user-attachments/assets/3ff8b963-420d-418c-b796-edf695f9dcce" />

---

###  Flag 25: Credential Access — Master Password Extraction

**Objective**  
Identify the final credential artifact recovered by the attacker that enabled access to an encrypted password database. Master passwords represent a critical escalation point, as they unlock multiple stored credentials at once.

**Evidence Observed**  
File system telemetry revealed access to a plaintext file containing a password associated with a previously identified password management database.

**KQL Used (MDE Advanced Hunting):**  
```
DeviceFileEvents  
| where DeviceName == "azuki-adminpc"  
| where FileName has "KeePass"  
| where FileName contains "txt" 
| project Timestamp, DeviceName, ActionType, FileName, FolderPath  
| order by Timestamp desc  
```
**Key observations:**
- Credential file identified: `KeePass-Master-Password.txt`
- File name explicitly references a password manager master password
- File accessed after browser credential theft activity
- File presence correlates with previously discovered `.kdbx` databases

**Analysis**  
The file `KeePass-Master-Password.txt` was identified as containing the master password for a KeePass credential database previously discovered during the investigation. Possession of this password allowed the attacker to decrypt the entire password database, granting access to all credentials stored within it.

This represents the **highest-impact credential access event** in the intrusion. Unlike individual browser passwords, a KeePass master password can unlock credentials for numerous internal systems, external services, and privileged accounts.

The recovery of this artifact confirms that the attacker achieved comprehensive credential compromise, extending the potential impact of the incident well beyond the initially compromised host.

**MITRE ATT&CK Mapping**
- **Tactic:** Credential Access  
- **Technique:** T1555.005 — Credentials from Password Stores

**Evidence Screenshot**  
<img width="614" height="146" alt="image" src="https://github.com/user-attachments/assets/f9272777-4699-4639-9e7b-c315f535f043" />

---

## 🧾 Final Impact Summary

The **Bridge Takeover** incident resulted in a comprehensive compromise of both **data confidentiality** and **credential security** within the Azuki Import/Export environment. By leveraging valid credentials, native tooling, and trusted cloud services, the attacker progressed from lateral movement to full administrative control without relying on exploit-based techniques.

### Confirmed Impacts

- **Administrative System Compromise**
  - Successful lateral movement into `azuki-adminpc`, a high-value administrative workstation
  - Establishment of multiple persistence mechanisms, including a C2 implant and backdoor administrator account

- **Sensitive Data Exposure**
  - Structured collection of business-critical data from user Documents directories
  - Financial records, tax data, contracts, and accounting files staged and archived
  - Creation of **eight distinct archives** prepared for exfiltration

- **Credential Compromise**
  - Discovery and access of plaintext password files
  - Theft of saved browser credentials via DPAPI decryption
  - Recovery of a KeePass **master password**, enabling decryption of an entire credential database

- **Data Exfiltration**
  - Successful exfiltration of staged archives using HTTPS-based uploads
  - Abuse of legitimate cloud storage infrastructure (`gofile.io`)
  - Identification of the backend exfiltration server IP (`45.112.123.227`)

### Overall Assessment

The attacker achieved:
- Long-term access persistence
- Broad credential exposure
- Verified data theft with potential regulatory and business impact

This incident represents a **high-severity compromise**, transitioning from endpoint intrusion to **enterprise-wide risk**, primarily due to credential reuse, plaintext password storage, and limited detection of trusted-tool abuse.

---

##  Detection & Mitigation Recommendations

The following recommendations are derived directly from observed attacker behavior and are intended to reduce the likelihood and impact of similar intrusions.

###  Credential Hygiene & Access Controls
- Enforce **unique, complex passwords** and prohibit plaintext credential storage
- Audit and remove legacy files containing passwords (`*.txt`, notes, documents)
- Implement **credential vaulting** with enforced access controls
- Require **multi-factor authentication (MFA)** for all administrative and remote access accounts

###  Account & Privilege Monitoring
- Alert on **local account creation** and **local Administrators group changes**
- Regularly review local accounts for naming patterns that mimic legitimate users
- Implement just-in-time (JIT) administration where possible

###  Endpoint Detection Improvements
- Monitor for **encoded PowerShell executions** (`-enc`, `-EncodedCommand`)
- Detect execution of credential theft tooling (e.g., Mimikatz modules, DPAPI abuse)
- Correlate **named pipe creation** with suspicious process execution
- Alert on abuse of LOLBins such as `curl.exe`, `robocopy.exe`, and `7z.exe` outside normal administrative workflows

###  Data Protection & Monitoring
- Monitor access to high-value directories such as `Documents`, `Desktop`, and shared drives
- Detect bulk file copy operations into unusual system directories
- Alert on archive creation activity in non-standard locations

###  Network & Exfiltration Controls
- Implement egress filtering for known file-sharing services
- Monitor outbound HTTPS POST requests with file upload patterns
- Track destination IPs associated with cloud storage providers during active incidents
- Perform retrospective network analysis following credential theft events

###  Threat Hunting & Preparedness
- Conduct routine threat hunts focused on:
  - Valid account abuse
  - Administrative session anomalies
  - Credential access patterns
- Maintain playbooks for post-compromise credential rotation
- Periodically validate detection coverage against MITRE ATT&CK techniques observed in this incident

---

*Together, these measures address both the technical and procedural gaps exploited during the Bridge Takeover incident, reducing attacker dwell time and limiting business impact in future events.*

---

## 🧭 MITRE ATT&CK Heatmap Summary

The following heatmap summarizes the attacker techniques observed throughout the **Bridge Takeover** incident, mapped across the MITRE ATT&CK framework. This visualization highlights the attacker’s heavy reliance on **valid credentials**, **living-off-the-land tooling**, and **credential-centric post-exploitation** rather than exploit-based intrusion.

### ATT&CK Technique Coverage Overview

| Tactic | Technique ID | Technique Name | Observed |
|------|-------------|---------------|----------|
| Initial Access | T1078 | Valid Accounts | 🔴 |
| Execution | T1059 | Command and Scripting Interpreter | 🔴 |
| Execution | T1105 | Ingress Tool Transfer | 🔴 |
| Persistence | T1136.001 | Create Account: Local Account | 🔴 |
| Persistence | T1078.003 | Valid Accounts: Local Accounts | 🔴 |
| Privilege Escalation | T1078 | Valid Accounts | 🔴 |
| Defense Evasion | T1027 | Obfuscated Files or Information | 🔴 |
| Discovery | T1033 | System Owner/User Discovery | 🟠 |
| Discovery | T1049 | System Network Connections Discovery | 🟠 |
| Discovery | T1482 | Domain Trust Discovery | 🟠 |
| Collection | T1074.001 | Data Staged: Local Data Staging | 🔴 |
| Collection | T1119 | Automated Collection | 🔴 |
| Collection | T1560.001 | Archive Collected Data | 🔴 |
| Credential Access | T1552.001 | Credentials in Files | 🔴 |
| Credential Access | T1555.003 | Credentials from Web Browsers | 🔴 |
| Credential Access | T1555.005 | Credentials from Password Stores | 🔴 |
| Exfiltration | T1567 | Exfiltration Over Web Service | 🔴 |
| Exfiltration | T1567.002 | Exfiltration to Cloud Storage | 🔴 |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | 🟠 |

### Heatmap Interpretation

- 🔴 **High Confidence / Directly Observed**  
  Technique was explicitly identified through telemetry and validated with supporting evidence.

- 🟠 **Moderate Confidence / Supporting Activity**  
  Technique inferred through correlated behavior and supporting command execution.

### Key Observations

- The intrusion heavily favored **credential abuse** over exploit development, indicating either prior access to valid credentials or a focus on stealth.
- **Persistence and credential access** techniques were layered to ensure long-term access even if individual mechanisms were removed.
- The attacker demonstrated a **mature collection and exfiltration workflow**, including staging, archiving, and segmented uploads.
- Use of **legitimate tools and services** (PowerShell, robocopy, curl, cloud storage providers) allowed activity to blend into normal enterprise behavior.

### Defensive Implications

This heatmap reinforces the importance of:
- Monitoring **valid account usage patterns**
- Detecting **encoded command execution**
- Auditing **credential storage practices**
- Tracking **data movement from high-value directories**
- Applying layered detection across the full kill chain rather than focusing solely on initial access

---

*This MITRE ATT&CK heatmap provides a concise, evidence-backed overview of attacker behavior and serves as a reference point for improving detection coverage and response readiness.*

