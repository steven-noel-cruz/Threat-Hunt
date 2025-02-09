# Threat Hunt Report: Operation Jackal Spear

## Platforms and Languages Leveraged
- **Windows 10 Virtual Machines** (Microsoft Azure)
- **EDR Platform**: Microsoft Defender for Endpoint
- **Kusto Query Language (KQL)**

## Scenario
A newly discovered Advanced Persistent Threat (APT) group known as **"Jackal Spear"** has emerged, originating from South Africa and sometimes operating out of Egypt. Their spear-phishing and credential stuffing attacks target large corporations, aiming to compromise the accounts of executives. Once they obtain access, the group creates a secondary account on the system, mirroring the original user’s identity, and uses it to steal sensitive data while remaining undetected.

This report outlines the investigation and threat-hunting steps taken to identify the compromised system and provide indicators of compromise (IoCs) related to this attack.

---

## Steps Taken

### 1. Identifying the Compromised Device

To start the investigation, I searched the **`DeviceProcessEvents`** table for evidence of suspicious user account creation. I was looking for any indication that the attacker created a new local user on a system. The query revealed that on the device `corpnet-1-ny`, a new local user named `chadwick.s` was created using a PowerShell command. This account is likely used for persistent access after the initial compromise.

**Query Used**:
```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("New-LocalUser")
| project DeviceName, AccountName, ProcessCommandLine
```
![image](https://github.com/user-attachments/assets/5317dd5d-450e-4ab0-9d31-87f4a7c78330)


### 2. Investigating Login Attempts

Next, I examined the DeviceLogonEvents table to determine the method and timing of the compromise. The attacker attempted to log into the compromised machine (corpnet-1-ny) 14 times unsuccessfully before finally succeeding. This was followed shortly by the creation of the chadwick.s account. This series of failed and successful login attempts is consistent with a credential-stuffing attack.

**Query Used**:
```kql
DeviceLogonEvents
| where Timestamp > ago(7d)
| where DeviceName == "corpnet-1-ny"
| project Timestamp, AccountName, ActionType, LogonType, DeviceName, RemoteIP
| order by Timestamp asc
```
![image](https://github.com/user-attachments/assets/6dd0c466-3b90-444c-90aa-60d03223c3af)


### 3. Analyzing File Events
To understand the extent of the data compromise, I searched the DeviceFileEvents table for actions initiated by the attacker under the new user account chadwick.s. I discovered that the attacker accessed and likely stole a sensitive file named CRISPR-X__Next-Generation_Gene_Editing_for_Artificial_Evolution.pdf alognside other files in a zip file named gene_editing_papers, a high-value target that could indicate a larger espionage operation targeting proprietary research.

**Query Used**:
```kql
DeviceFileEvents
| where DeviceName == "corpnet-1-ny"
| where InitiatingProcessAccountName == "chadwick.s"
| where FileName has_any ("zip")
| project
    TimeGenerated,
    DeviceName,
    InitiatingProcessAccountName,
    FileName,
    InitiatingProcessCommandLine
```
![image](https://github.com/user-attachments/assets/d58c6f50-5d26-4b31-9b65-1ebf7e177a57)


### Summary of Findings
-Compromised Device: corpnet-1-ny

-Attacker's Public IP Address: 102.37.140.95

-Number of Failed Login Attempts: 14

-Account Created by the Attacker: chadwick.s

-Stolen Files: a gene_editing_papers.zip "CRISPR-X__Next-Generation_Gene_Editing_for_Artificial_Evolution.pdf" "Genetic_Drift_in_Hyper-Evolving_Species__A_Case_Study.pdf" "Mutagenic_Pathways_and_Cellular_Adaptation.pdf" "Mutational_Therapy__Theoretical_Applications_in_Human_Enhancement.pdf" "Spontaneous_Mutations_in_Simulated Microbial Ecosystems"

### Response Taken
Upon identifying the compromised device and account, I took steps to isolate corpnet-1-ny from the network to prevent further data exfiltration. The chadwick.s account was flagged for further investigation, and incident response teams were alerted to the presence of stolen research files. Additionally, the system logs were preserved for forensic analysis and evidence gathering.
