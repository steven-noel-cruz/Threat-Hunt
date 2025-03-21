# Threat Hunt Report: Operation Jackal Spear

## Platforms and Languages Leveraged
- **Windows 10 Virtual Machines** (Microsoft Azure)
- **EDR Platform**: Microsoft Defender for Endpoint
- **Kusto Query Language (KQL)**

## Scenario
Your SOC team received an urgent email from Microsoft Azure Safeguards Team
regarding potential misuse of Azure resources. Microsoft flagged your subscription for
external reports of brute-force attacks originating from one of your IP addresses. Your
organization's reputation—and your Azure subscription—is at stake.
Your SOC Manager urgently tasks you with investigating this alert. You must determine if
there's truth to these allegations and, if so, uncover how deep the compromise goes. 

---

## Steps Taken

### 1. . Validate the Allegation:

To start the investigation, I searched the **AzureNetworkAnalytics_CL** and **`DeviceLogonEvents`** table to verify ownership of the reported IP and confirm the brute force attack pattern from our environment. Our first query shows the name, MAC, Private and Public IP, aswell as the subnetwork which displays the cyber-range, our organization, confirming that the IP does infact belong to us.

**Query Used**:
```kql
AzureNetworkAnalytics_CL
| where PublicIPAddresses_s == "20.81.228.191"
| project TimeGenerated, Name_s,MACAddress_s, PrivateIPAddresses_s, PublicIPAddresses_s, Subnetwork_s
```
![image](https://github.com/user-attachments/assets/9564a07f-8f8b-4eee-97da-339979188f94)


The second query shows that the Public IP address reported, has indeed shown patterns of brute-force attacks on the device "xxlinuxprofixxx" with 100 failed login attempts over 2 minutes using the root account. With this, we can validate the allegation.

**Query Used**:
```kql
let failure_threshold = 10;
let time_window = 720h;
let trigger_window = 60s;
DeviceLogonEvents
| where (RemoteIP contains "20.81.228.191" or RemoteIP contains "10.0.0.217")  // Filter for your compromised device IPs
| where ActionType == "LogonFailed"
| where Timestamp > ago(time_window)
| summarize FailedLogonCount = count()by bin(Timestamp, trigger_window), DeviceName,DeviceId, RemoteIP, AccountName
| where FailedLogonCount >= failure_threshold
| extend ReportId = strcat("LogonFailureAlert_", DeviceName, "_", format_datetime(Timestamp, 'yyyyMMdd_HHmmss')) // Dynamic ReportId
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/8e4478ec-f656-410e-ae6a-2dfcebb9be7a)


### 2. Trace the Origin of Malicious Activity: 

Next, I examined the DeviceInfo table to identify the compromised host, "sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net", which is a linux platform. 

**Query Used**:
```kql
DeviceInfo
| where PublicIP == "20.81.228.191"
| project Timestamp,DeviceName, PublicIP, OSPlatform
```
![image](https://github.com/user-attachments/assets/9c3f2854-d717-47ca-a492-cce775273da1)

Now that we have the host, we will use the device process table to find the entry point of any malicious behavior.

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
