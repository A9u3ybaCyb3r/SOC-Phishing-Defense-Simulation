# SOC Phishing Defense Simulation

## 📚 Table of Contents
- [Objective](#objective)
- [NIST Incident Response Plan](#defense-scenario)
- [Cyber Kill Chain Scenario](#attack-scenario)
- [Skills Learned](#skills-learned)
- [Disclaimer](#disclaimer)

## Objective:

This project simulates a phishing attack in a controlled lab and demonstrates the full incident response lifecycle preparation, detection, analysis, and mitigation using tools like Splunk, Snort, Sysmon, and LimaCharlie. It follows both the **NIST Incident Response Plan** and **Cyber Kill Chain** to build hands-on experience in detecting threats, analyzing attacker behavior, and identifying Indicators of Compromise (IOCs).

---

# 🧩 Overview of the Project

## Defense Scenario

This project is structured around the **NIST Incident Response Lifecycle**, providing a hands-on simulation of how security teams prepare for, detect, contain, and recover from cyberattacks. Each phase includes specific tools, configurations, and techniques to demonstrate professional blue team operations.

---

### 🛡️ 1. **Preparation Phase**

> *Goal: Build resilience before an incident occurs.*

In this phase, the environment is configured for maximum visibility and alerting:

* **Snort IDS** rules are written to detect suspicious traffic (e.g., reverse TCP shells, HTTP anomalies).
* **LimaCharlie EDR** is deployed to monitor endpoint activity and trigger YARA-based detections.
* **Sysmon** is configured to capture low-level Windows event logs.
* **Splunk SIEM** is set up to ingest, correlate, and alert on Snort, Sysmon, and LimaCharlie logs.
* **Forensic tools** like FTK Imager, Registry Explorer, and KAPE are prepared for post-breach analysis.
* **User awareness training and phishing detection preparation** are implied by the simulated threat.

---

### 💥 2. **Detection and Analysis Phase**

> *Goal: Identify, validate, and analyze the incident as early as possible.*

After the phishing attack is triggered, this phase focuses on **identifying and understanding the threat**:

* **Snort** triggers alerts on known attack patterns (e.g., port 4444 reverse shell).
* **Splunk dashboards** visualize and correlate incoming Snort, Sysmon, and EDR logs.
* **LimaCharlie** detects process anomalies and file creation events via YARA rules.
* Analysts **map attacker behavior** using the MITRE ATT\&CK Framework and **validate IOCs** such as file names, IP addresses, and system modifications.

---

### 🚨 3. **Containment, Eradication, and Recovery Phase**

> *Goal: Minimize damage, remove the threat, and restore systems to normal.*

Once detection confirms the compromise:

* **Containment** steps include tagging compromised systems with LimaCharlie and disabling reverse shell activity.
* **Eradication** involves removing the malware and terminating unauthorized accounts or processes.
* **Recovery** includes restoring system integrity and re-enabling services after forensic validation.

Logging and forensic evidence are preserved for future analysis or reporting.

---

### 📘 4. **Post-Incident Activity Phase**

> *Goal: Learn from the incident and strengthen defenses.*

After resolving the attack:

* The team reviews logs, alerts, and actions taken to evaluate effectiveness.
* Lessons learned are documented, including:

  * Which alerts triggered early enough?
  * Were any gaps found in detection logic?
  * How did the environment respond under simulated stress?

This feedback loop leads to updated Snort/YARA rules, improved automation, and better training for future incidents.

---

## Attack Scenario 

This simulation models a realistic phishing-based compromise on a standalone **Windows 10** machine. The attack follows the **Cyber Kill Chain** framework, progressing through all key adversarial phases:

---

### 🛰️ 1. **Reconnaissance**

The attacker gathers intelligence on the target organization through publicly available information (OSINT), identifying an employee and crafting a believable phishing lure.

---

### ✉️ 2. **Weaponization**

A **malicious payload** is created using **Metasploit**, embedded in an executable file named to appear as a critical software update (e.g., `UrgentUpdate.exe`). The payload is configured to open a **reverse TCP shell** on port `4444`.

---

### 📤 3. **Delivery**

The payload is delivered to the victim via **phishing email**, masquerading as an urgent internal IT update. The email contains social engineering tactics to trick the user into downloading and executing the file.

---

### 💥 4. **Exploitation**

Upon execution, the payload **exploits user trust**, not a system vulnerability. The reverse shell initiates a connection back to the attacker, establishing remote control of the system.

---

### 📡 5. **Installation**

A **Meterpreter session** is established. The attacker uploads tools, installs persistence mechanisms, and **creates a new administrative user account** to maintain long-term access.

---

### 🕹️ 6. **Command and Control (C2)**

The attacker communicates with the compromised system via the **reverse TCP shell**, using encrypted Metasploit traffic to avoid detection. Commands are executed to further explore the host and maintain stealth.

---

### 📦 7. **Actions on Objectives**

The attacker achieves their primary goals:

* **Data exfiltration** of sensitive documents.
* **Log tampering and clearing** to cover tracks and evade detection.

---

## Skills Learned:

| Skill               | Tool/Technique                      |
| ------------------- | ----------------------------------- |
| Intrusion Detection | Snort IDS                           |
| Endpoint Monitoring | LimaCharlie EDR                     |
| Log Analysis        | Splunk SIEM                         |
| Threat Simulation   | Metasploit (Meterpreter)            |
| Attack Analysis     | MITRE ATT\&CK, Cyber Kill Chain     |
| Incident Response   | NIST Incident Response Plan         |
| Forensics           | KAPE, FTK Imager, Registry Explorer |


## Disclaimer

This project is intended solely for educational and research purposes in a controlled lab environment. All simulations, tools, and techniques demonstrated are designed to enhance knowledge in cybersecurity defense and incident response. **Do not deploy or execute any offensive security techniques or tools against systems you do not have explicit permission to test.**

Unauthorized access, testing, or modification of networks or systems is illegal and unethical. The project creator is not responsible for any misuse of the provided information or tools. Please adhere to legal and ethical guidelines when practicing cybersecurity skills.


