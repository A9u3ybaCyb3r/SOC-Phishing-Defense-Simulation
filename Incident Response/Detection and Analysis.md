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

  - Another exe file was downloaded.
  
    ![image](https://github.com/user-attachments/assets/36f82cf5-5be3-4152-9845-55af3c2aa8cc)

  
- **Execution from Download Directory**: Another detection based on a D&R rule.
  ![image](https://github.com/user-attachments/assets/a46a48a0-8cf0-4ae2-9b2e-a0ace0eb7208)
  - YARA Scan detected that it was **LaZagne**
    ![image](https://github.com/user-attachments/assets/154cb1ff-7554-4c2d-a626-9659ce370be2)

- **Direct Autorun Key Modification**: Indicating a registry modification used to create a backdoor.
  ![image](https://github.com/user-attachments/assets/37479115-e504-4cf2-ba0a-cce3f0447e41)

- **New User Creation**: The attacker created a new user.
  ![image](https://github.com/user-attachments/assets/088390e6-ff33-4377-aec6-fa6bd921e46c)

- **Dumping Credentials**: Sensitive hives were dumped via Reg.exe.
  ![image](https://github.com/user-attachments/assets/769d3607-8ed1-42e0-a3cd-5016fb332912)

- **Windows System and Security Logs Deletion**: Logs were cleared to hide malicious activity.
  ![image](https://github.com/user-attachments/assets/a0c302a5-b9b9-4950-99a1-94cbb4c2a6bf)

Splunk logs further provide details on the attack, such as the **attacker's IP (10.19.19.134)** and port (**4444**) used for C2 communication.

![image](https://github.com/user-attachments/assets/2a1352e1-bd76-4604-b239-d52a5332ea1c)

### Indicators of Compromise (IOCs) Identified:

1. Malicious file hash.
2. Modified registry key.
3. Unauthorized user account creation.
4. System log deletion.
5. Use of non-standard port 4444 for C2 communication.
6. Phishing email with a shortened URL (e.g., Bitly link).

## Analysis

### Phishing Analysis

- Download the .eml file if you have not done it

![image](https://github.com/user-attachments/assets/e5bccb96-c184-4ccd-93b5-b33e36a95a45)

- Go to [Phishtool](https://app.phishtool.com/submit) and choose the .eml file that you downloaded.

![image](https://github.com/user-attachments/assets/58e68194-17dd-4b90-9c08-3201577ca87c)

![image](https://github.com/user-attachments/assets/c2421f9d-4912-4c29-bf1b-c9aeb34928db)

- Unshortening malicious URLs to trace attacker infrastructure.
  - Copy the shortened link and paste it in [URL Expander Tool](https://www.bing.com/ck/a?!&&p=e4c94fa102759f71528b69a24210c528e8d83d620f0ef91e8e8458218145bd2dJmltdHM9MTc0MDM1NTIwMA&ptn=3&ver=2&hsh=4&fclid=05217751-e29b-69ad-1992-62d9e33c683b&psq=link+unshortener&u=a1aHR0cHM6Ly90Lmx5L3Rvb2xzL2xpbmstZXhwYW5kZXI&ntb=1)

![image](https://github.com/user-attachments/assets/ea5d590b-19c9-41a4-8042-c040a7effe6d)

![image](https://github.com/user-attachments/assets/5434000a-eb4a-4b27-90d0-d19f1897e95c)

- We can see here the IP address of the attacker, the port that was used to host the payload, and the file path.

### Network and Log Analysis

- **Wireshark** will be used to analyze network packets for signs of C2 communication.

![image](https://github.com/user-attachments/assets/5fbba53a-4afb-4bf4-8ffb-b4f28d29ec9d)

![image](https://github.com/user-attachments/assets/3c0d8179-9b8f-40ac-b366-54c1385b873c)

![image](https://github.com/user-attachments/assets/cf2e6f50-1237-4edb-b518-b76852b83055)

- Examining **Splunk** logs for:
  - Sysmon log anomalies.

     ![image](https://github.com/user-attachments/assets/e2ef3580-64fb-41a9-9803-52f88836a197)
    
    ![image](https://github.com/user-attachments/assets/796c83cf-317b-4a99-bf9e-ef00641ea50b)
    
    ![image](https://github.com/user-attachments/assets/a6555bac-f584-4a3e-88d1-60ae1c655dea)
      
      - Here we can see the user that was created and when was deleted. 

  - Windows event logs (e.g., event ID 1102 for audit log clearance).

     ![image](https://github.com/user-attachments/assets/3c69c8a5-e321-4ddb-8d2d-7dc2f03676d9)

  - IDS logs for unauthorized HTTP traffic on port 8080.

     ![image](https://github.com/user-attachments/assets/27411d9c-d223-4fc4-9f81-8d0ea0d61af9)

- **EDR file hash analysis** using [VirusTotal](https://www.virustotal.com/gui/home/search) to verify malware presence.

![image](https://github.com/user-attachments/assets/05716a9c-d470-44bf-aaba-efd0ed9c709a)

![image](https://github.com/user-attachments/assets/7be8304d-7135-41d2-a9ff-c915ca6be8db)

   - Here we can confirm that the Security Update is indeed a malicious file.
- If we go to behavior we can see the IP address of your attacker machine and the port that was used for C2 Communications

  ![image](https://github.com/user-attachments/assets/6462020d-5a5f-4193-a443-e13bde1ef5c5)

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

