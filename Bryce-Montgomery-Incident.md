**Threat Hunt Report: Bryce Montgomery Investigation**

---

### **Platforms and Languages Leveraged**
- **Platforms**:
  - Microsoft Sentinel (Log Analytics Workspace)
  - Windows-based corporate workstations (corporate and shared environments)
  - Shared guest workstations on campus
  
- **Languages/Tools**:
  - **Kusto Query Language (KQL)** for querying device events, process logs, and file activities.
  - **Steganography tools**: *Steghide.exe* for embedding data into images.
  - **7z.exe** for compressing and packaging files into an archive for potential exfiltration.

---

### **Scenario**
The VP of Risk requested an investigation after suspecting that Bryce Montgomery, a company executive, may have been involved in the unauthorized access and exfiltration of sensitive corporate intellectual property. The investigation needed to focus on Mr. Montgomery’s computer and potential misuse of shared workstations.

Key points:
- **User**: Bryce Montgomery (username: *bmontgomery*).
- **Workstation**: Corporate workstation (*corp-ny-it-0334*), but additional guest workstations were suspected.
- **Concern**: Data exfiltration through steganography and compression of files for unauthorized transmission out of the corporate network.
  
Executives like Bryce have **full administrative privileges** on their machines, and some were exempted from the **Data Loss Prevention (DLP)** policy, which could make tracing Bryce's activities difficult.

---

### **Steps Taken**

1. **Initial Investigation on Bryce Montgomery's Workstation**:
   - A KQL query was executed on the workstation `corp-ny-it-0334` to identify files interacted with by Bryce.
   - Tracked **FileName** and **FilePath** for any critical corporate documents (such as “Q1-2025-ResearchAndDevelopment.pdf”) and identified the file *thumbprint* (hash) `b3302e58be7eb604fda65d1d04a5e18325c66792`.
**Query Used**:
```kql
DeviceFileEvents
| where DeviceName == "corp-ny-it-0334"
| where InitiatingProcessAccountName == "bmontgomery"
| order by TimeGenerated desc 
| project TimeGenerated ,DeviceName, InitiatingProcessAccountName, FileName, SHA1
```
![image](https://github.com/user-attachments/assets/8a2c9918-6c46-4ae7-bca4-a418a5a27d53)


2. **Cross-Reference on Shared Workstations**:
   - Investigated shared workstations that Mr. Montgomery might have accessed under generic or guest profiles.
   - The **DeviceFileEvents** table was queried to compare file interactions and identify other workstations used by Mr. Montgomery.
   - DeviceName **"lobby-fl2-ae5fc"** was flagged for matching files found on Bryce's workstation, confirming his use of a guest workstation.
 **Query Used**:
```kql
DeviceFileEvents
| where PreviousFileName contains "Q3-2025-AnimalTrials-SiberianTigers" or PreviousFileName contains "Q2-2025-HumanTrials" or PreviousFileName contains "Q1-2025-ResearchAndDevelopment"
| order by TimeGenerated desc 
| project TimeGenerated ,DeviceName, InitiatingProcessAccountName, PreviousFileName, FileName
```
![image](https://github.com/user-attachments/assets/ec998431-f79c-4ce7-b6e2-73fbcce41beb)

3. **Identifying Steganography Use**:
   - After querying **DeviceProcessEvents** for process interactions involving corporate files, it was discovered that **Steghide.exe** was used to embed corporate documents into personal image files on the shared workstation.
   - Images involved: `suzie-and-bob.bmp`, `bryce-and-kid.bmp`, and `bryce-fishing.bmp`.
   - The **ProcessCommandLine** and **ProcessName** indicated the use of *steghide.exe*.
 **Query Used**:
```kql
DeviceProcessEvents
| where DeviceName == "lobby-fl2-ae5fc"
| where ProcessCommandLine contains "bryce-homework-fall-2024.pdf" or ProcessCommandLine contains "Amazon-Order-123456789-Invoice.pdf" or ProcessCommandLine contains "temp___2bbf98cf.pdf"
| order by TimeGenerated desc 
| project TimeGenerated ,DeviceName, AccountName, ProcessCommandLine
```
![image](https://github.com/user-attachments/assets/85b67407-0150-4fb7-a012-562d4a7e5f2b)

4. **Investigating Compression and Transfer**:
   - Further KQL queries showed the **7z.exe** process interacting with these same stego images, confirming they were being compressed into a zip file (`marketing_misc.zip`).
   - The zip file ended up on the **F:\** drive of the lobby workstation, further pointing to suspicious data packaging for exfiltration.

5. **Identifying the Culprit**:
   - The final piece of evidence came from a **damning KQL record** that directly tied Bryce Montgomery to these actions.
   - Timestamp **2025-02-05T08:57:32.2582822Z** revealed that Bryce, under a generic profile, initiated the data manipulation and zipping processes.
  
---

### **Summary of Findings**
The investigation revealed that Bryce Montgomery, using both his own corporate workstation and a shared guest workstation, attempted to exfiltrate sensitive company data through the following steps:

1. **Unauthorized Access**: Bryce accessed and manipulated sensitive files (related to corporate research) without authorization.
2. **Steganography**: He used *steghide.exe* to embed corporate documents into seemingly innocuous personal images of himself and his family.
3. **Data Packaging**: He compressed the stego images into a zip file using *7z.exe* and saved it to the F:\ drive of a guest workstation, presumably for transfer outside the network.
4. **Cross-Workstation Activity**: Evidence showed that Bryce likely used shared workstations to hide his tracks, taking advantage of generic user profiles to mask his identity.
  
---

### **Response Taken**
1. **Immediate User Suspension**:
   - Bryce Montgomery's access to the corporate network and all systems was immediately suspended pending further legal and HR investigation.
  
2. **Incident Escalation**:
   - The Security Operations team escalated the incident to the VP of Risk and Corporate Legal departments, triggering a formal investigation into potential data theft and corporate espionage.
  
3. **Forensic Image and Collection**:
   - Forensic imaging of Bryce's workstation and the shared workstations involved was initiated. All activity logs, steganography tools, and data zipping processes were secured for further analysis.
  
4. **Review of DLP Policies**:
   - The Security team recommended reviewing the **DLP exemption** policy for executives, given that this exemption created a blind spot in monitoring potentially malicious activities.
  
5. **Data Integrity Review**:
   - An internal audit was initiated to determine whether any of the data embedded in the images had been compromised or transmitted outside the company.

6. **Awareness Training**:
   - A company-wide security awareness campaign was started, highlighting the dangers of insider threats, steganography, and the importance of following data protection policies.

This report will be kept as part of the formal record for this case. The Security Operations and Risk Departments will continue monitoring the situation and ensure all legal actions are taken.

--- 

**End of Report**
