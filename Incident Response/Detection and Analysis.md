# 🔍 Detection and Analysis

## 🛁 Monitoring Phase

During this phase, we actively monitor security alerts and events using Splunk to identify potential threats. In this scenario, we observed triggered alerts for a **reverse TCP connection** in Splunk.

* Go to **Activity > Triggered Alerts** to view active alerts in Splunk.

![image](https://github.com/user-attachments/assets/734071cd-58ae-4f34-a1bf-eea2784b1bce)

---

## 🚨 Detection Phase

In this phase, we analyze alerts and detections using **Endpoint Detection and Response (EDR)** tools, such as **LimaCharlie**, and continue to investigate within Splunk. Detections included:

* **Executable Drop in Download Directory**: Triggered by a D\&R rule. The malicious file **SecurityUpdate.exe** and its hash were detected.

  * The YARA scan identified it as a **Meterpreter Reverse TCP Payload**.
  * Additional suspicious executable files were also detected.

![image](https://github.com/user-attachments/assets/1261b8d1-594b-433c-8512-b57febe4ac19)

![image](https://github.com/user-attachments/assets/95934230-55ef-484c-a815-8c4264bb7764)

![image](https://github.com/user-attachments/assets/36f82cf5-5be3-4152-9845-55af3c2aa8cc)

* **Execution from Download Directory**: Another detection by D\&R.

  * The YARA scan confirmed it was **LaZagne**.

![image](https://github.com/user-attachments/assets/a46a48a0-8cf0-4ae2-9b2e-a0ace0eb7208)
![image](https://github.com/user-attachments/assets/154cb1ff-7554-4c2d-a626-9659ce370be2)

* **Direct Autorun Key Modification**: Indicates a registry modification used to create a backdoor.

![image](https://github.com/user-attachments/assets/37479115-e504-4cf2-ba0a-cce3f0447e41)

* **New User Creation**: Indicates privilege escalation or lateral movement.

![image](https://github.com/user-attachments/assets/088390e6-ff33-4377-aec6-fa6bd921e46c)

* **Dumping Credentials**: Registry hives dumped using Reg.exe.

![image](https://github.com/user-attachments/assets/769d3607-8ed1-42e0-a3cd-5016fb332912)

* **Windows Log Deletion**: System and security logs were cleared.

![image](https://github.com/user-attachments/assets/a0c302a5-b9b9-4950-99a1-94cbb4c2a6bf)

Splunk logs revealed additional context including the **attacker's IP (10.19.19.134)** and port (**4444**) used for C2.

![image](https://github.com/user-attachments/assets/2a1352e1-bd76-4604-b239-d52a5332ea1c)

---

## 🧪 Phishing Analysis

* Download the `.eml` file of the phishing email.
* Submit it to [PhishTool](https://app.phishtool.com/submit).

![image](https://github.com/user-attachments/assets/e5bccb96-c184-4ccd-93b5-b33e36a95a45)
![image](https://github.com/user-attachments/assets/58e68194-17dd-4b90-9c08-3201577ca87c)

* Expand malicious URLs using a [URL Expander Tool](https://t.ly/tools/link-expander).

![image](https://github.com/user-attachments/assets/ea5d590b-19c9-41a4-8042-c040a7effe6d)

---

## 🌐 Network and Log Analysis

* Analyze packets in **Wireshark** for C2 indicators.

![image](https://github.com/user-attachments/assets/5fbba53a-4afb-4bf4-8ffb-b4f28d29ec9d)

* Look for `port 4444` and click `Follow > TCP Stream`
  ![image](https://github.com/user-attachments/assets/3c0d8179-9b8f-40ac-b366-54c1385b873c)

![image](https://github.com/user-attachments/assets/cf2e6f50-1237-4edb-b518-b76852b83055)
* In this case, Snort did not detect the file download due to configuration issues, but other tools like YARA and LimaCharlie successfully identified the download activity.
* The misconfiguration was intentional. In the Post-Incident Activity, you will find the explanation.

* Search **Splunk logs** for:

  * Sysmon anomalies (user creation/deletion, autorun keys).
![image](https://github.com/user-attachments/assets/e2ef3580-64fb-41a9-9803-52f88836a197)
    
    ![image](https://github.com/user-attachments/assets/796c83cf-317b-4a99-bf9e-ef00641ea50b)
    
    ![image](https://github.com/user-attachments/assets/a6555bac-f584-4a3e-88d1-60ae1c655dea)
	
  * Windows Event ID `1102` for log clearance.
  ![image](https://github.com/user-attachments/assets/3c69c8a5-e321-4ddb-8d2d-7dc2f03676d9)

   * Unauthorized HTTP traffic on port `8080`.
   ![image](https://github.com/user-attachments/assets/27411d9c-d223-4fc4-9f81-8d0ea0d61af9)

* Use [VirusTotal](https://www.virustotal.com/gui/home/search) to verify malicious file hashes.
* Take the file hash from **LimaCharlie EDR**

![image](https://github.com/user-attachments/assets/05716a9c-d470-44bf-aaba-efd0ed9c709a)

![image](https://github.com/user-attachments/assets/7be8304d-7135-41d2-a9ff-c915ca6be8db)

![image](https://github.com/user-attachments/assets/6462020d-5a5f-4193-a443-e13bde1ef5c5)

---

## 🧬 Forensic Analysis

* Use **GKAPE** to extract evidence and artifacts from the compromised system.

![image](https://github.com/user-attachments/assets/3b62b0b3-84f1-4975-ad2a-54b14534b816)

![image](https://github.com/user-attachments/assets/95458ed6-d63e-4259-95ab-651144e17ced)

![image](https://github.com/user-attachments/assets/a22bb3ff-2ea2-448e-8f32-33303488eb82)

![image](https://github.com/user-attachments/assets/8118de5d-dc0f-45ab-b798-cb5560859d3d)
* Open extracted registry hives using **Registry Explorer** to:

 ![image](https://github.com/user-attachments/assets/eeee63e1-d314-448d-b43f-011cb23c4bd9)

  * Confirm deleted accounts in SAM.
![image](https://github.com/user-attachments/assets/4842e184-5831-4924-bf34-ebb97a038f23)

![image](https://github.com/user-attachments/assets/e20438e7-735a-4526-98ea-4014c340fd1d)

![image](https://github.com/user-attachments/assets/b62ad4de-d665-432c-b3a6-e966a45245bd)

  * Identify persistence mechanisms via autorun keys in `NTUSER.DAT`.

![image](https://github.com/user-attachments/assets/0f596ff0-0508-40ae-a722-fb9b798a8f55)

* Recover deleted files using **FTK Imager**:

  * Add evidence > Physical drive
  * Export files with red X to a recovery directory.

![image](https://github.com/user-attachments/assets/559d53ef-89a0-4173-ad8d-8143897bb085)

![image](https://github.com/user-attachments/assets/05e8e80d-3c32-483f-ade0-0e329ec90f97)

![image](https://github.com/user-attachments/assets/8709630a-3061-4275-9cd7-65b7c6da0e1a)
  
![image](https://github.com/user-attachments/assets/02c75315-a868-451b-89b3-e82549c20edf)

![image](https://github.com/user-attachments/assets/10183fa7-fc84-4249-af00-5ffe9c4cb5dc)
  
---

## 🧠 Indicators of Compromise (IOCs)

| **Indicator**             | **Description**                           |
| ------------------------- | ----------------------------------------- |
| Malicious file hash       | Meterpreter payload: `SecurityUpdate.exe` |
| Registry key modification | Autorun key added for persistence         |
| Unauthorized user account | Attacker-created admin account            |
| System log deletion       | Audit logs wiped via `event ID 1102`      |
| Port 4444                 | Used for reverse TCP C2 channel           |
| Bitly link in email       | Embedded in phishing lure to victim       |

---

## 🎯 Identified MITRE ATT\&CK TTPs

| **TTP ID** | **Technique Name**                          | **Tactic Category**  |
| ---------- | ------------------------------------------- | -------------------- |
| T1589      | Gather Victim Identity Information          | Reconnaissance       |
| T1566      | Phishing                                    | Initial Access       |
| T1204      | User Execution                              | Execution            |
| T1204.002  | User Execution: Malicious File              | Execution            |
| T1203      | Exploitation for Client Execution           | Execution            |
| T1665      | Hiding Infrastructure                       | Defense Evasion      |
| T1547.001  | Registry Run Keys / Startup Folder          | Persistence          |
| T1571      | Non-Standard Port                           | Command and Control  |
| T1041      | Exfiltration Over C2 Channel                | Exfiltration         |
| T1222      | File and Directory Permissions Modification | Defense Evasion      |
| T1136      | Create Account                              | Persistence          |
| T1098      | Account Manipulation                        | Privilege Escalation |
| T1070      | Indicator Removal on Host                   | Defense Evasion      |
