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
