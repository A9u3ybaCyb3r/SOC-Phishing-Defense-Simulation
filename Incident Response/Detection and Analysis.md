# Detection and Analysis


## Monitoring Phase

During this phase, we actively monitor security alerts and events using Splunk to identify potential threats. In this scenario, we observed triggered alerts for a **reverse TCP connection** in Splunk.

- Go to **Activity > Triggered Alerts** and we will see the alerts that were triggered in Splunk.

![image](https://github.com/user-attachments/assets/734071cd-58ae-4f34-a1bf-eea2784b1bce)

## Detection Phase

In this phase, we analyze alerts and detections using **Endpoint Detection and Response (EDR)** tools, like as **LimaCharlie**, and continue to investigate in Splunk. The detections observed include:

![image](https://github.com/user-attachments/assets/11edcdac-e209-4410-ae46-528d4f72a980)

- **Executable Drop in Download Directory**: This was triggered by a D&R created during the preparation phase. The malicious file **SecurityUpdate.exe** and its file hash were detected.
  ![image](https://github.com/user-attachments/assets/1261b8d1-594b-433c-8512-b57febe4ac19)
  - The YARA scan detected that it was a **Meterpreter Reverse TCP Payload**.
  ![image](https://github.com/user-attachments/assets/95934230-55ef-484c-a815-8c4264bb7764)

- **Execution from Download Directory**: Another detection based on a D&R rule.
- **Direct Autorun Key Modification**: Indicating a registry modification used to create a backdoor.
- **New User Creation**: The attacker created a new user.
- **Windows System and Security Logs Deletion**: Logs were cleared to hide malicious activity.

Splunk logs further provide details on the attack, such as the **attacker's IP (10.19.19.134)** and port (**4444**) used for C2 communication.

### Indicators of Compromise (IOCs) Identified:

1. Malicious file hash.
2. Modified registry key.
3. Unauthorized user account creation.
4. System log deletion.
5. Use of non-standard port 4444 for C2 communication.
6. Phishing email with a shortened URL (e.g., greet-link).

## Analysis

### Phishing Analysis

- Downloading and analyzing phishing emails.
- Unshortening malicious URLs to trace attacker infrastructure.
- Inspecting email headers and attachments for malware.

### Network and Log Analysis

- **Wireshark** will be used to analyze network packets for signs of C2 communication.
- Examining **Splunk** logs for:
  - Sysmon log anomalies.
  - Windows event logs (e.g., event ID 1102 for audit log clearance).
  - IDS logs for unauthorized HTTP traffic on port 8088.
- **EDR file hash analysis** using VirusTotal to verify malware presence.

### Forensic Analysis

- Extracting compromised machine artifacts using **GKAPE**.
- **Analyzing Windows Security Account Manager (SAM)** database for deleted user accounts.
- Recovering deleted files using **FTK Manager**.

### Identified Tactics, Techniques, and Procedures (TTPs)

1. T1589: Gathering victim identity information. 
2. T1204.002: User execution of malicious files.
3. T1566: Phishing attacks.
4. T1665: Hiding Infrastructure
5. T1204: User Execution
6. T1203: Exploitation for Client Execution
7. T1547.001: Registry Run Keys/Startup Folder
8. T1571: Non-Standard Port
9. T1041: Exfiltration over C2 channel.
10. T1222: File and Directory Permissions Modification
11. T1136: Create Account
12. T1098: Account Manipulation
13. T1070: Indicator Removal on Host

