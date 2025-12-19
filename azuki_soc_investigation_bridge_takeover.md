# SOC Incident Investigation – Azuki Import/Export Compromise

**Analyst:** Steven Cruz  
**Source:** Cyber Range SOC Challenge  
**System:** azuki-fileserver01

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
    A[Existing Foothold<br/>(from prior breach)]
    --> B[Lateral Movement<br/>Valid Accounts]
    B --> C[Execution<br/>Payload Download & Extraction]
    C --> D[Persistence<br/>C2 + Backdoor Account]
    D --> E[Discovery<br/>Sessions, Trusts, Network, Files]
    E --> F[Collection<br/>Data Staging & Archiving]
    F --> G[Exfiltration<br/>Cloud File Uploads]
    G --> H[Credential Access<br/>Browser & Password Manager]
    style B fill:#ffcccc
    style D fill:#ffd9b3
    style F fill:#fff2cc
    style G fill:#d9ead3
```

### Key Observations

- No exploits were required — the attack relied entirely on **trust abuse and legitimate tooling**
- Each stage **enabled the next**, demonstrating deliberate planning
- The attack only became clearly malicious **late in the chain**, after persistence and discovery were complete

This progression highlights why early detection of **credential misuse, encoded commands, and anomalous administrative behavior** is critical to preventing business-impacting incidents.

---

## 
