# Cyber Kill Chain

Developed by Lockheed Martin, it is a conceptual framework that describes the stages of a cyberattack. Originating from military concepts, the model parallels physical attack planning and execution, providing organizations with a systematic approach to understanding, detecting, and defending against cyber threats. We will use this framework for our attack simulation. 

## [Reconnaissance](https://github.com/A9u3ybaCyb3r/Cyber_Defense_Lab/blob/main/Attack%20Simulation/Reconnaissance.md) 

- The attacker gathers information about the victim from their **Facebook** profile.
- The victim’s **email address** is obtained.
- The attacker plans a **spear-phishing** attack targeting the victim.

## [Weaponization](https://github.com/A9u3ybaCyb3r/Cyber_Defense_Lab/blob/main/Attack%20Simulation/Weaponization.md)

- The attacker uses **MSF Venom** (part of the Metasploit framework) to create a **malicious payload**.
- The payload is a PP32 executable file named `SecurityUpdate.exe`.
- The payload is designed to establish a **reverse TCP connection** to the attacker's machine.

## [Delivery Phase](https://github.com/A9u3ybaCyb3r/Cyber_Defense_Lab/blob/main/Attack%20Simulation/Delivery%20Phase.md)

- The attacker **hosts the payload** using **Python's HTTP** server, making it available for download.
- A **phishing email** is sent to the victim via **Temp Mail** (you can use any email for this test), masquerading as a **tech support email**.
- Sends a spoofed phishing email with a disguised **shortened URL** linking to the payload using **Emkei's Fake Mailer**.
- The email subject creates a **sense of urgency**:
  - **Subject**: "`Critical Update: Immediate Action Required`"

## [Exploitation Phase](https://github.com/A9u3ybaCyb3r/Cyber_Defense_Lab/blob/main/Attack%20Simulation/Exploitation%20Phase.md)

- Victim downloads and executes `SecurityUpdate.exe` as an administrator.
- A reverse TCP connection is established on port **4444** using a **Meterpreter session**.

## [Installation Phase](https://github.com/A9u3ybaCyb3r/Cyber_Defense_Lab/blob/main/Attack%20Simulation/Installation%20Phase.md)

- The attacker modifies the **Windows Registry** to create a backdoor for persistence.

## [Command and Control Phase](https://github.com/A9u3ybaCyb3r/Cyber_Defense_Lab/blob/main/Attack%20Simulation/Command%20and%20Control%20Phase.md)

- **Establish Persistent Access**: Maintain a reliable communication channel to the compromised systems.
Issue Commands: Execute malicious instructions, such as collecting data, escalating privileges, or disabling defenses.
- **Exfiltrate Data**: Send sensitive information back to the attacker's infrastructure.
- **Enable Further Actions**: This option supports subsequent stages of the attack, such as lateral movement or data destruction.

## [Actions on Objectives Phase](https://github.com/A9u3ybaCyb3r/Cyber_Defense_Lab/blob/main/Attack%20Simulation/Actions%20on%20Objectives.md)

In this final phase of the Cyber Kill Chain, the attacker:
- **Data Exfiltration**: Steal sensitive information such as intellectual property, credentials, or personal data.
- **Lateral Movement and Persistence**: Can expand access to other systems to maintain long-term control.
- Deletes the exfiltrated file and clears system logs to erase evidence.

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
