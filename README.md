# Threat-Hunting-Devices-Accidentally-Exposed-to-the-Internet
## 1. Preparation
 During routine maintenance, the security team is tasked with investigating any VMs in the shared services cluster (handling DNS, Domain Services, DHCP, etc.) that have mistakenly been exposed to the public internet. The goal is to identify any misconfigured VMs and check for potential brute-force login attempts/successes from external sources using Microsoft Defender (EDR)
 
 I developed an hypothesis based on threat intelligence and security gaps (e.g., “Could there be lateral movement in the network?”). Therefore, I simulated a vitual machine that is opened to public internet for more than 24hours
During the time the devices were unknowingly exposed to the internet, it’s possible that someone could have actually brute-force logged into some of them since some of the older devices do not have account lockout configured for excessive failed login attempts. 

# 2. In this step, I will check for relevant tables that contains recent logs

Went to Advance hunting in edr and type in the query below. The query will scanned the selected device machine, confirmed the internet facing and listed the output in order of timestamp in descending order.
The findings shows that the tosinvm-ranger1 has been internet facing for several days. 
DeviceInfo
| where DeviceName == "tosinvm-ranger1"
| where IsInternetFacing == true
| order by Timestamp desc

The command shows the last internet facing time to be Apr 5, 2025 5:53:18 AM as shown in the picture
