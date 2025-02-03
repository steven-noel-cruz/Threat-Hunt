<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/steven-noel-cruz/Threat_Hunt_Event_-TOR-Usage-.md/blob/main/Threat_Hunt_Event-TOR-Usage.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "windows-user" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-02-02T23:36:18.157`. These events began at `2025-02-02T23:11:29.052`.

**Query used to locate events:**

```kql
let target_machine = "windows-10-mde-";
DeviceFileEvents
| where FileName has_any ("tor")
| where DeviceName == target_machine
| order by TimeGenerated asc  
| project TimeGenerated, DeviceName, ActionType, FileName, InitiatingProcessCommandLine
```
![image](https://github.com/user-attachments/assets/38dbb7a3-e3bc-4661-affe-ab1280769838)


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2025-02-02T23:24:53.827`, an employee on the "windows-10-mde-" device ran the file `tor-browser-windows-x86_64-portable-14.0.1.exe` from their Downloads folder, using a command that triggered a silent installation.  In addition to this, we see usage of firefox indicating that the tor browser was accessed and utilized, as well as the creation of a shopping list from tor usage.


**Query used to locate event:**

```kql

let target_machine = "windows-10-mde-";
DeviceProcessEvents
| where DeviceName == target_machine
| where ProcessCommandLine contains "tor"
| where InitiatingProcessAccountName == "windows-user"
| order by TimeGenerated desc 
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine
```
![image](https://github.com/user-attachments/assets/79c5825a-a541-4189-929c-e09ff8536abf)
![image](https://github.com/user-attachments/assets/c56f2222-79b4-4790-8d4c-c6c4fc58bd07)
![image](https://github.com/user-attachments/assets/5ac3e44b-b6f5-4752-a7b7-a58daf35d32c)

---

### 3. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2024-11-08T22:18:01.1246358Z`, an employee on the "threat-hunt-lab" device successfully established a connection to the remote IP address `176.198.159.33` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
let target_machine = "windows-10-mde-";
DeviceNetworkEvents
| where DeviceName == target_machine
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150)
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by TimeGenerated desc
```
![image](https://github.com/user-attachments/assets/1fb73422-b972-48ef-965a-38921d8b1372)



---

## Chronological Event Timeline 

### 1. File Download - TOR Installer
- **Timestamp:** 2025-02-02T23:24:29Z
- **Event:** The user "windows-user" downloaded a file named tor-browser-windows-x86_64-portable-14.0.4.exe to the Downloads folder.
- **Action:** File download detected.
- **File Path:** C:\Users\windows-user\Downloads\tor-browser-windows-x86_64-portable-14.0.4.exe
### 2. Process Execution - TOR Browser Installation
- **Timestamp:** 2025-02-02T23:24:46Z
- **Event:** The user "windows-user" executed the file tor-browser-windows-x86_64-portable-14.0.4.exe in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** tor-browser-windows-x86_64-portable-14.0.4.exe /S
- **File Path:** C:\Users\windows-user\Downloads\tor-browser-windows-x86_64-portable-14.0.4.exe
### 3. Process Execution - TOR Browser Launch
- **Timestamp:** 2025-02-02T23:25:46Z
- **Event:** User "windows-user" opened the TOR browser. Processes associated with TOR browser, such as firefox.exe and tor.exe, were created, indicating successful browser launch.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** C:\Users\windows-user\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe
### 4. Network Connection - TOR Network
- **Timestamp:** 2025-02-02T23:26:00Z
- **Event:** A network connection to IP 176.198.159.33 on port 9001 was established by the user "windows-user," confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** tor.exe
- **File Path:** C:\Users\windows-user\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe
### 5. Additional Network Connections - TOR Browser Activity
- **Timestamps:**
  - 2025-02-02T23:26:08Z - Connected to 194.164.169.85 on port 443.
  - 2025-02-02T23:26:16Z - Local connection to 127.0.0.1 on port 9150.
- **Event**: Additional TOR network connections were established, indicating ongoing TOR browser activity by the user "windows-user."
- **Action:** Multiple successful connections detected.
### 6. File Creation - TOR Shopping List
- **Timestamp:** 2025-02-02T23:36:35Z
- **Event:** The user "windows-user" created a file named tor-shopping-list.txt on the desktop, potentially documenting their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** C:\Users\windows-user\Desktop\tor-shopping-list.txt


---

## Summary

The user "windows-user" on the "windows-10-mde-" device initiated and completed the silent installation of the TOR browser. The user launched the browser, established connections within the TOR network, and created a file named tor-shopping-list.txt. These events indicate that the user actively used the TOR browser for anonymous browsing, with potential documentation in the form of the created file.

---

## Response Taken

TOR usage was confirmed on endpoint windows-10-mde-. The device was isolated and the user's direct manager was notified.

---
