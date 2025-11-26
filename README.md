🛡️ Volt Typhoon APT Investigation (Blue Team / Splunk)
📌 Summary

This project is a full-scale investigation of the Volt Typhoon APT intrusion inside an enterprise environment using Splunk. The goal was to analyze logs, trace attacker activity, identify persistence, credential theft, lateral movement, and reconstruct the entire attack chain.

🧠 Investigation Overview

Objective: Identify malicious activity performed by Volt Typhoon using Splunk endpoint & authentication logs.
Tools Used: Splunk, Sysmon, PowerShell logs, Windows Event Logs, CyberChef, MITRE ATT&CK
Data Analyzed: Authentication logs, Sysmon events, script execution, file modifications, registry events, network connections.

🔍 What I Did

Tracked account takeover via password reset of dean-admin

Identified malicious admin account voltyp-admin

Analyzed drive enumeration commands

Detected NTDS.dit extraction using ntdsutil.exe

Identified web shell creation in C:\Windows\Temp

Tracked lateral movement to server-02

Observed C2 proxy setup using netsh

Detected event log clearing using wevtutil cl

🚨 Key Findings

Account takeover & rogue admin account creation

NTDS.dit credential extraction

Base64 web shell persistence

Lateral movement & file transfers

Financial data exfiltration attempts

C2 communications to 172.31.45.200:443

Event logs cleared to evade detection

| Tactic           | Technique              | ID        |
| ---------------- | ---------------------- | --------- |
| Initial Access   | Valid Accounts         | T1078     |
| Cred Access      | OS Credential Dumping  | T1003     |
| Persistence      | Web Shell              | T1505.003 |
| Defense Evasion  | Clear Logs             | T1070     |
| Lateral Movement | Remote Services        | T1021     |
| C2               | Exfiltration via Proxy | T1090     |


| Type              | Value            |
| ----------------- | ---------------- |
| Malicious Account | voltyp-admin     |
| C2 IP             | 172.31.45[.]200  |
| Web Shell Path    | C:\Windows\Temp\ |

Screenshots located in writeup pdf

🎯 What I Learned

How attackers establish persistence & C2 channels

How to analyze account takeover events

How to detect credential dumping (NTDS.dit)

How to correlate Sysmon + Windows logs in Splunk

How to reconstruct a full APT intrusion timeline

🏁 Conclusion

This investigation confirmed a full Volt Typhoon intrusion involving credential theft, persistence, lateral movement, C2 communication, and log tampering. The results demonstrate the complete SOC workflow from alert validation to attack reconstruction.
