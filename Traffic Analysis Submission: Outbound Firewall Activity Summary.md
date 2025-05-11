# 🔍 Traffic Analysis Submission: Outbound Firewall Activity Summary

### 📡 Platforms and Tools Leveraged
**Platform**:  
- Microsoft Sentinel (Log Analytics Workspace – `LAW-Cyber-Range`)  
- Azure NSG Flow Logs (`AzureNetworkAnalytics_CL` table)

**Tools / Languages**:  
- Kusto Query Language (KQL)

---

### 📝 Request Origin
**Log Request By**: Josh Madakor  
**Purpose**: Provide a quick summary of **outbound traffic** (allowed/blocked) by **Cyber Range firewall** (NSG), grouped by **destination port** over the **last 30 days**.

---

### 📌 Query Executed

```kql
AzureNetworkAnalytics_CL
| where TimeGenerated >= ago(30d)
| where FlowDirection_s == "O"
| extend FlowStatusStr = tostring(FlowStatus_s)
| summarize 
    TotalConnections = count(),
    AllowedConnections = countif(FlowStatusStr == "A"),
    DeniedConnections = countif(FlowStatusStr == "D")
  by DestPort_d
| sort by TotalConnections desc
```

## 📊 Summary of Findings (Last 30 Days)

| Port         | Total Connections | Allowed Connections | Denied Connections | Notes                                           |
|--------------|-------------------|----------------------|---------------------|--------------------------------------------------|
| **22**       | 1,963,259         | 1,356                | **1,961,903**        | SSH traffic mostly denied – strict control       |
| **443**      | 311,385           | 311,385              | 0                   | HTTPS fully allowed – normal web activity        |
| **80**       | 27,510            | 27,510               | 0                   | HTTP fully allowed                               |
| **135/139/445** | ~5,500         | ~4,000               | ~1,500              | Legacy protocols partially blocked (SMB/RPC)     |
| **3389**     | 1,801             | 1,317                | 484                 | RDP outbound partially blocked                   |
| **2222**     | 72                | 0                    | 72                  | Fully denied – likely custom/alt SSH             |
| **3306/995/143** | 1,500+ each   | All allowed          | 0                   | MySQL and secure mail protocols active           |
| **9000–9090**| 25–50 each        | All allowed          | 0                   | Custom apps/services present                     |

## 📌 Observations

- 🔒 **Port 22 (SSH)** had over **1.96 million outbound attempts**, with **only 0.07% allowed**, showing **very strict egress filtering** to prevent remote access or tunneling.
- 🌐 **Web traffic** on **port 443 (HTTPS)** and **port 80 (HTTP)** was **fully allowed**, supporting expected browsing and API activity.
- 🧨 **Legacy ports** like **135, 139, and 445** (used by SMB and RPC) showed **partial denials**, aligning with best practices to reduce lateral movement risk.
- 🖥️ **Port 3389 (RDP)** had nearly **500 denied connections**, indicating controlled outbound remote desktop access.
- 🚫 **Port 2222** (commonly used for alternate SSH services) was **fully blocked**, suggesting it's either unauthorized or not configured in NSG rules.
- 🛠️ Several ports in the **9000–9090 range** were active (e.g., 9000, 9090, 9300), which may represent **custom applications, internal services, or testing tools** used in the Cyber Range.


## 📎 Recommendation Highlights

- 🔍 **Investigate source VMs** responsible for large volumes of denied traffic on sensitive ports (e.g., SSH, RDP, SMB) to determine if the behavior is legitimate or indicative of scanning/misuse.
- 🔒 **Review and validate custom port activity** (e.g., ports 9000–9090, 3306, 2222) to ensure those services are authorized and properly secured.
- ⚙️ **Adjust NSG/firewall rules** as needed to tighten outbound access where services are unused or misconfigured.
- 📈 **Monitor high-volume denied traffic (like on port 22)** for brute-force attempts, misconfigured agents, or potential command-and-control behavior.
- 🧪 Consider building **alerts** or **dashboards** to continuously track denied vs allowed traffic by port, and identify sudden spikes in activity.


✅ Submitted for internship credit
🧠 Responded by: Steven Cruz
📅 Date: May 11, 2025
