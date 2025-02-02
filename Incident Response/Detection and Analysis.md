# Detection and Analysis

## Monitoring

### Objective:
Monitor network activity and detect potential security threats.

### Action:

- Access Splunk to monitor for alerts.

- Observe alerts related to reverse TCP connection.

### Result:

- [Insert Screenshot: Splunk alert showing reverse TCP connection]

## Detection

### Objective:
Identify suspicious activities using Endpoint Detection and Response (EDR) and Splunk.

### Action:

- Use Lima Charmin EDR to check detections.

- Review Splunk for triggered detections.

### Result:

- [Insert Screenshot: EDR detections for reverse TCP connection]

- Detections observed:

  - Executable dropped in the Downloads directory.

  - Autorun key modification for backdoor persistence.

  - New user account creation.

  - Clearing of Windows system and security logs.

- [Insert Screenshot: EDR detection of executable drop]

### Network Analysis:

- Snort logs in Splunk provide further insights, including attacker IP (192.168.1.5) and port (4444).

- [Insert Screenshot: Snort logs showing attacker IP and port]

## Indicators of Compromise (IOCs)

### Objective:
Identify key signs of compromise to aid analysis and response.

### IOCs Identified:

1. File hash of the malicious payload.

2. Modified registry key.

3. Creation of a new user account.

4. Deletion of log files.

5. Non-standard port usage (port 4444).

6. Shortened URLs with read-only access.

- [Insert Screenshot: List of IOCs from Splunk and EDR]

# Analysis 

## Phishing Analysis

### Objective:
Analyze the phishing email used for initial compromise.

### Action:

- Use Phish Tool to analyze the phishing email.

- Identify sender, receiver, return path, and download link.

### Result:

- [Insert Screenshot: Extracted phishing email details]

- Unshorten the URL to reveal attacker’s IP and payload location.

- [Insert Screenshot: Unshortened phishing URL details]

## Network Analysis

### Objective:
Analyze network traffic to identify malicious communication.

### Action:

- Use Wireshark to inspect captured packets.

- Filter for port 4444 and analyze ASCII and hex dump data.

### Result:

- [Insert Screenshot: Wireshark analysis of C2 communication]

- Identify payload strings and execution attempts.

- [Insert Screenshot: Malicious payload details in Wireshark]

## System & Security Log Analysis

### Objective:
Analyze system logs for suspicious activities.

### Action:

- Search for new user creation logs in Sysmon.

- Analyze Windows Security logs for event code 1102 (log clearing).

- Conduct IDS analysis for port 8088 to detect non-standard HTTP traffic.

- Identify executable transfers over non-standard ports.

### Result:

- [Insert Screenshot: Sysmon logs showing new user creation]

- [Insert Screenshot: Windows security logs showing log clearing]

- [Insert Screenshot: IDS detection of non-standard HTTP traffic]

- [Insert Screenshot: IDS alert for executable transfer]

## Endpoint & Malware Analysis

### Objective:
Verify and analyze malicious files using VirusTotal.

### Action:

- Copy file hash from EDR and check in VirusTotal.

### Result:

- [Insert Screenshot: VirusTotal results for malicious file]

- Confirm that "notmalicious.exe" is flagged as malware by 61/73 vendors.

- Identify C2 communication details.

- [Insert Screenshot: C2 connection details from VirusTotal]

## Forensic Analysis

### Objective:
Recover deleted artifacts and investigate system compromise.

### Action:

- Use GKEG to extract compromised machine’s disk for triage.

- Load security account manager (SAM) hive to recover deleted user accounts.

- Load end-user hive to find backdoor evidence.

- Extract artifacts before eradication.

### Result:

- [Insert Screenshot: SAM database showing deleted user recovery]

- [Insert Screenshot: Registry Explorer showing backdoor evidence]

## Data Recovery

### Objective:
Recover deleted files for further investigation.

### Action:

- Use FTK Manager to restore deleted .txt files.

- Recover "important_doc.txt" from the secret folder.

### Result:

- [Insert Screenshot: FTK Manager showing recovered file]

## Identified TTPs

### Objective:
Recognize attacker behavior through tactics, techniques, and procedures (TTPs).

### TTPs Identified:

1. Gather Victim Identity Information.

2. User Execution Malicious File.

3. Phishing.

4. Hide Infrastructure.

5. Exploitation for Client Execution.

6. Registry Run Keys/Startup Folder.

7. Non-Standard Ports.

8. Exfiltration Over C2 Channel.

9. File Directory Permissions Modification.

10. Create Account.

11. Account Manipulation.

12. Indicator Removal Controls.

