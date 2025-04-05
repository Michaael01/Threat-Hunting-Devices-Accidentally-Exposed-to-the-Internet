# Threat-Hunting-Devices-Accidentally-Exposed-to-the-Internet
## 1. Preparation
 During routine maintenance, the security team is tasked with investigating any VMs in the shared services cluster (handling DNS, Domain Services, DHCP, etc.) that have mistakenly been exposed to the public internet. The goal is to identify any misconfigured VMs and check for potential brute-force login attempts/successes from external sources using Microsoft Defender (EDR)
 
 I developed an hypothesis based on threat intelligence and security gaps (e.g., “Could there be lateral movement in the network?”). Therefore, I simulated a vitual machine that is opened to public internet for more than 24hours
During the time the devices were unknowingly exposed to the internet, it’s possible that someone could have actually brute-force logged into some of them since some of the older devices do not have account lockout configured for excessive failed login attempts. 

## 2. In this step, I will check for relevant tables that contains recent logs

Went to Advance hunting in edr and type in the query below. The query will scanned the selected device machine, confirmed the internet facing and listed the output in order of timestamp in descending order.
The findings shows that the tosinvm-ranger1 has been internet facing for several days. 
## KQL Queries

| Metric                                       | Query                                                                                                                                            |
|----------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| Initial logs                              | DeviceInfo<br>\| where DeviceName == "tosinvm-ranger1"<br>\| where IsInternetFacing == true<br>\| order by Timestamp desc                                                                  |
                                                                                                              
The command shows the last internet facing time to be Apr 5, 2025 5:53:18 AM as shown in the picture below:
![image](https://github.com/user-attachments/assets/2f7ff6f7-3f78-4f5c-81af-a0bd023d7e39)

I went further to find out the numbers of login attempts to the virtual machine with the KQL query below . 
| Metric                                       | Query                                                                                                                                            |
|----------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| login Attempts                             | DeviceLogonEvents<br>\| where DeviceName == "tosinvm-ranger1"

This shows that there are 263 login attempts to the virtual machine.

![image](https://github.com/user-attachments/assets/9d4a5e99-0128-45ed-8186-067f322b5678)

## 3. Data Analysis

The goal here is to analys the data to test my hzpothesis. I looked for indicators of compromise (IOC) using various tools and techniques. The questions for the hypothesis is that: 
- Is there any evidence of brute force success (many failed logins followed by a success?) on your VM or ANY VMs in the environment?
- If so, what else happened on that machine around the same time? Were any bad actors able to log in?
  
3.1 I started the analysis by checking various ip addresses and attempted numbers of failed logins bruteforcing to my virtual machine. The results interestingly as shown below that several bd actors made login attempts.
The query used to determine this event is:

| Metric                                       | Query                                                                                                                                            |
|----------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| IOC                             | DeviceLogonEvents<br>\| where DeviceName == "tosinvm-ranger1"<br>\| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")<br>\| where ActionType == "LogonFailed"<br>\| where isnotempty(RemoteIP)<br>\| summarize Attempts = count() by ActionType, RemoteIP, DeviceName<br>\| order by Attempts


![image](https://github.com/user-attachments/assets/277eec0f-a814-4f82-bf15-dd530e647185)

3.2 From the output of the previous command, copied top five(5) ip addresses and pasted the ip addresses in the query below to know if any of the ip address was able to login successfully in to the virtual machine at all.
This did not show any result which means that the bad actors with top 5 login attempts have not been able to successfully break into the vm.

| Metric                                       | Query                                                                                                                                            |
|----------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| IOC                             | let RemoteIPsInQuestion = dynamic(["58.69.74.34","182.78.20.172", "92.53.90.104", "188.124.36.148", "5.182.5.119"]); DeviceLogonEvents<br>\| where DeviceName == "tosinvm-ranger1"<br>\| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")<br>\| where ActionType == "LogonSuccess"<br>\| where RemoteIP has_any(RemoteIPsInQuestion)

The query does not show any result

![image](https://github.com/user-attachments/assets/110a6d87-b3fc-4feb-9f26-e3bdcf2b0dc3)

3.3 I ran the query below to detect the numbers of successful logins. This returned that there was 8 items successful logins and shows the only successful login is from the "labuser" itself which it Oluwatosin in the last 24 hours

| Metric                                       | Query                                                                                                                                            |
|----------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| IOC                             | DeviceLogonEvents<br>\| where DeviceName == "tosinvm-ranger1"<br>\| where LogonType == "Network"<br>\| where ActionType == "LogonSuccess"

![image](https://github.com/user-attachments/assets/b2add1cc-1c94-4e4d-8a2e-da80ef8a385a)

3.4 With focus on Network, checked if there is a failed login from labuser in the last 24 hours. This returned yero which means that brute force did not occur from labuser
| Metric                                       | Query                                                                                                                                            |
|----------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| IOC                             | DeviceLogonEvents<br>\| where DeviceName == "tosinvm-ranger1"<br>\| where LogonType == "Network"<br>\| where ActionType == "Logonfailed"<br>\| where AccountName == "labuser"<br>\| summarize count()

![image](https://github.com/user-attachments/assets/846ab71f-a1f1-4dea-8d1e-90e81225343e)


3.5 checked all of the login ip addresses of the labuser to see if any of them were unusual or from an unexpected location. All ip were normal though the device was exposed to the internet, clear brute force attempt took place but there is no clear evidence of a successful brute force or unauthorized access from the legitimate account labuser.

| Metric                                       | Query                                                                                                                                            |
|----------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| IOC                             | DeviceLogonEvents<br>\| where DeviceName == "tosinvm-ranger1"<br>\| where LogonType == "Network"<br>\| where ActionType == "LogonSuccess"<br>\| where AccountName == "labuser"<br>\| summarize count()<br>\| summarize Attempts = count() by ActionType, RemoteIP, DeviceName

![image](https://github.com/user-attachments/assets/c0a5c46f-bc87-49b6-b25b-bbc8346bcf06)


# 4. Investigation

The goal is to Investigate any suspicious findings. I therefore digged deeper into detected threats, determine their scope, and escalate if necessary. I researched for TTPs within the MITRE ATT&CK Framework.
TTPs stands for Tactics, Techniques, and Procedures. It's a term commonly used in cybersecurity and military contexts to describe how adversaries carry out attacks or operations. Here’s a breakdown:
- Tactics: The overall strategy or goal of an attack, like the objective an attacker is trying to achieve.
- Techniques: The general methods or approaches used to achieve the tactic, such as phishing, exploitation of a vulnerability, or social engineering.
- Procedures: The specific, detailed steps or actions taken to execute a technique. For example, how exactly the attacker executes the phishing attack, including the use of specific tools, delivery methods, or times for the attack.

In cybersecurity, understanding an adversary's TTPs is important because it helps defenders anticipate and recognize attacks, develop better defenses, and improve threat detection. It’s also used in the MITRE ATT&CK framework, which categorizes common TTPs used by threat actors.


## 4.1  TTPs Corresponding to Findings:
- **T1071.001** - Application Layer Protocol: Web Protocols (likely used for remote access attempts)
- **T1078** - Valid Accounts (attempts to use valid credentials for unauthorized access)
- **T1110.001** - Brute Force: Password Guessing (failed login attempts indicating brute force attempts)
- **T1021.001** - Remote Services: Remote Desktop Protocol (RDP) (login attempts via remote protocols like RDP)
- **T1040** - Network Sniffing (IP addresses used for login attempts)
- **T1086** - PowerShell (used for querying and managing device logs)
- **T1203** - Exploitation for Client Execution (could be inferred due to internet-facing nature and login attempts)

# 5. Response

The goal here is to mitigate any confirmed threats based on my findings by containing, removing, and recovering from the threats.
- Created new inbound security rule to Tosinvm-Ranger1 to allow only specific endpoint (no public internet access)
- Implemented account lockout policy
- Implemented MFA threshold
