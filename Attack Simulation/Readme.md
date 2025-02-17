# Cyber Kill Chain

Developed by Lockheed Martin, it is a conceptual framework that describes the stages of a cyberattack. Originating from military concepts, the model parallels physical attack planning and execution, providing organizations with a systematic approach to understanding, detecting, and defending against cyber threats. We will use this framework for our attack simulation. 

## [Reconnaissance](https://github.com/A9u3ybaCyb3r/SOC-Phishing-Defense-Simulation/blob/main/Attack%20Simulation/Reconnaissance.md) 

- The attacker gathers information about the victim from their **Facebook** profile.
- The victim’s **email address** is obtained.
- The attacker plans a **spear-phishing** attack targeting the victim.

## [Weaponization](https://github.com/A9u3ybaCyb3r/SOC-Phishing-Defense-Simulation/blob/main/Attack%20Simulation/Weaponization.md)

- The attacker uses **MSF Venom** (part of the Metasploit framework) to create a **malicious payload**.
- The payload is a PP32 executable file named `SecurityUpdate.exe`.
- The payload is designed to establish a **reverse TCP connection** to the attacker's machine.

## [Delivery Phase](https://github.com/A9u3ybaCyb3r/SOC-Phishing-Defense-Simulation/blob/main/Attack%20Simulation/Delivery%20Phase.md)

- The attacker **hosts the payload** using **Python's HTTP** server, making it available for download.
- A **phishing email** is sent to the victim via **Temp Mail** (you can use any email for this test), masquerading as a **tech support email**.
- Sends a spoofed phishing email with a disguised **shortened URL** linking to the payload using **Emkei's Fake Mailer**.
- The email subject creates a **sense of urgency**:
  - **Subject**: "`Critical Update: Immediate Action Required`"

## [Exploitation Phase](https://github.com/A9u3ybaCyb3r/SOC-Phishing-Defense-Simulation/blob/main/Attack%20Simulation/Exploitation%20Phase.md)

- The victim **receives the phishing email**, clicks the link, and **downloads the malicious executable**.
- The victim runs `SecurityUpdate.exe` via the **command prompt** as an **administrator**. 
- The payload **executes**, triggering a **reverse TCP connection** to the attacker's machine.
- The attacker has now compromised the Windows machine.

## [Installation Phase](https://github.com/A9u3ybaCyb3r/SOC-Phishing-Defense-Simulation/blob/main/Attack%20Simulation/Installation%20Phase.md)

- The attacker **modifies the Windows registry** to create **persistence**.
- A backdoor named `update.exe` is added to **autoruns**, ensuring the attacker maintains access even after the system reboots.
- The name is to  help the backdoor blend in with legitimate software.
- Attackers rely on a system's sheer volume of files to obscure their malicious presence.

## [Command and Control Phase](https://github.com/A9u3ybaCyb3r/SOC-Phishing-Defense-Simulation/blob/main/Attack%20Simulation/Command%20and%20Control%20Phase.md)

- The attacker **sends commands** (e.g., `cd`, `ls`) to **navigate the compromised system**.
- The attacker **searches for sensitive information**, including folders, user accounts, and stored data.

## [Actions on Objectives Phase](https://github.com/A9u3ybaCyb3r/SOC-Phishing-Defense-Simulation/blob/main/Attack%20Simulation/Actions%20on%20Objectives.md)

- The attacker **creates a new user** named `guest` with password `password123`.
- **Data exfiltration**:
  - The attacker navigates to `secret_folder`.
  - A file named `important_doc.txt` is downloaded to the attacker's machine.
- **Data destruction**:
  - The attacker deletes `important_doc.txt` from the victim’s machine.
- **Covering tracks**:
  - The attacker **removes the created user** (`guest`).
  - The attacker **clears Windows system and security logs** to eliminate traces of the attack.

---

## Tools Utilized

### Metasploit

Metasploit is a penetration testing framework used for finding, exploiting, and validating vulnerabilities in systems. It provides a suite of tools for ethical hackers, security researchers, and red teamers to conduct security assessments and exploit known vulnerabilities in networks, applications, and operating systems.

### Emkei's Fake Mailer

Emkei's Fake Mailer is an online tool that allows users to send spoofed emails by forging the "From" address and other email headers. It is typically used to simulate email communications from any sender address, making it appear as though the email originates from a legitimate source.


### LaZagne

LaZagne is an open-source tool for retrieving stored passwords from various system applications. It automates extracting credentials from commonly used software and is widely employed in penetration testing and red team engagements.

### Temp Mail

Disposable email - is a free email service that allows you to receive email at a temporary address that self-destructed after a certain time elapses. 
