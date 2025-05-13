# Threat-Hunting-Scenario-Devices-Accidentally-Exposed-to-the-Internet

During routine maintenance, the security team is tasked with investigating any VMs in the shared services cluster (handling DNS, Domain Services, DHCP, etc.) that have mistakenly been exposed to the public internet. The goal is to identify any misconfigured VMs and check for potential brute-force login attempts/successes from external sources.
While the devices were unknowingly exposed to the internet, it’s possible someone could have actually brute-force logged into some of them since some of the older devices do not have account lockout configured for excessive failed login attempts.

---

## 🔍 Investigation Summary

### ✅ Confirmed Internet Exposure
```kql
DeviceInfo
| where DeviceName == "windows-target-1"
| where IsInternetFacing == "1"
| order by Timestamp desc
```
Finding:
The most recent internet-facing result was on:
2025-05-13T16:51:42.9217096Z

<img width="1414" alt="image" src="https://github.com/user-attachments/assets/f0b09231-0193-4ce5-8413-70af9db46869">


### 🚨 Brute-Force Attempt Analysis
Failed Logon Attempts by Remote IP
```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts
```
Finding:
Several external IPs were identified attempting failed logons.

<img width="1414" alt="image" src="https://github.com/user-attachments/assets/543563f0-d018-4dc6-8115-a10683390299">


Top 10 IPs investigated:
[
  "88.214.50.13", "194.165.16.43", "185.39.19.56", "78.188.114.168", 
  "103.143.143.215", "52.162.240.156", "102.88.21.219", 
  "192.82.65.200", "119.73.154.210", "190.57.75.42"
]

Successful Logon Attempts from Suspicious IPs

```kql
let RemoteIPsInQuestion = dynamic(["88.214.50.13", "194.165.16.43", "185.39.19.56", "78.188.114.168", "103.143.143.215", "52.162.240.156", "102.88.21.219", "192.82.65.200", "119.73.154.210", "190.57.75.42"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```
Finding:
No results were found. These IPs did not successfully log in.

<img width="1414" alt="image" src="https://github.com/user-attachments/assets/40116e45-31ea-46a7-8cbe-eba6b280ffb7">


Legitimate Logon Activity
```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
```
Finding:
The only successful login attempts in the past 30 days were for legitimate accounts josh and josh1. (The other logins shown are Microsoft services)

<img width="1414" alt="image" src="https://github.com/user-attachments/assets/389be551-919d-4f18-aa33-f0b5a27b52d7">


Failed Attempts on Legitimate Accounts
```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where AccountName has_any("josh", "josh1")
```
Finding:
No failed attempts against josh or josh1, which would typically occur in a brute-force attack.

<img width="1414" alt="image" src="https://github.com/user-attachments/assets/3f70c3d0-7ce4-43a6-9754-8f2993d6c1c3">


Origin of Successful Logins
```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| summarize LoginCount = count() by DeviceName, ActionType, RemoteIP, AccountName
```
Finding:
All successful logins for the legitimate users originated from known and expected IP addresses/regions.

<img width="1414" alt="image" src="https://github.com/user-attachments/assets/5ae15941-5a3b-495a-8c16-d8615c20825a">


## 📌 Conclusion

While the device windows-target-1 was briefly exposed to the internet and did receive brute-force login attempts from various external IP addresses, there is no evidence of successful unauthorized access.
No logon attempts from the suspicious IPs were successful, and only known user accounts (josh, josh1) were observed logging in during the review period.

## 🎯 MITRE ATT&CK Mapping
| Tactic            | Technique ID | Technique Name                    |
| ----------------- | ------------ | --------------------------------- |
| Initial Access    | T1190        | Exploit Public-Facing Application |
| Credential Access | T1110        | Brute Force                       |
| Persistence       | T1078        | Valid Accounts                    |

## 🛡️ Response Actions Taken

- Enabled Multi-Factor Authentication (MFA) for all user accounts

- Tightened Network Security Group (NSG) rules:

  - Explicitly allowed only known IPs for RDP

  - Blocked all other external RDP access

- Implemented Account Lockout Policy using Group Policy
  
  - Lock account after defined number of failed attempts
---
📇 Analyst Contact  
Name: Britt Parks  
Contact: [linkedin.com/in/brittaparks](https://linkedin.com/in/brittaparks)  
Date: May 13, 2025
