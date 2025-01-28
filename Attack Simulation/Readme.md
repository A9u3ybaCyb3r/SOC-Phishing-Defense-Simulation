# Cyber Kill Chain

Developed by Lockheed Martin, it is a conceptual framework that describes the stages of a cyberattack. Originating from military concepts, the model parallels physical attack planning and execution, providing organizations with a systematic approach to understanding, detecting, and defending against cyber threats. We are going to use this framework for our attack simulation. 

## Reconnaissance and Weaponization
- The attacker (**Kali VM**) gathers a victim’s email from LinkedIn.
- Creates a malicious payload (`payload.exe`) using DSViper to bypass Windows Defender.
- Hosts the payload on port **8000** using Python HTTP server.

## Delivery Phase
- Sends a spoofed phishing email with a disguised **shortened URL** linking to the payload using Emkei's Fake Mailer.
- Subject: "*Critical Update: Immediate Action Required.*"

## Exploitation Phase
- Victim downloads and executes `payload.exe`.
- A reverse TCP connection is established on port **4444** using a **Meterpreter session**.

## Installation Phase
- The attacker modifies the **Windows Registry** to create a backdoor for persistence.

## Command and Control Phase
- **Establish Persistent Access**: Maintain a reliable communication channel to the compromised systems.
- **Issue Commands**: Execute malicious instructions, such as collecting data, escalating privileges, or disabling defenses.
- **Exfiltrate Data**: Send sensitive information back to the attacker's infrastructure.
- **Enable Further Actions**: Support subsequent stages of the attack, such as lateral movement or data destruction.

## Actions on Objectives Phase
In this final phase of the Cyber Kill Chain, the attacker:
- **Data Exfiltration**: Steal sensitive information such as intellectual property, credentials, or personal data.
- **Lateral Movement and Persistence**: Can expand access to other systems to maintain long-term control.
- Deletes the exfiltrated file and clears system logs to erase evidence.

---

## Tools Utilized

### DS Viper

DS Viper is a powerful tool designed to bypass Windows Defender's security mechanisms, enabling seamless execution of payloads on Windows systems without triggering security alerts. It utilizes a combination of advanced techniques to manipulate and disguise payloads, providing cybersecurity professionals, red teamers, and penetration testers with a robust solution for achieving undetected access.

### Emkei's Fake Mailer

Emkei's Fake Mailer is an online tool that allows users to send spoofed emails by forging the "From" address and other email headers. It is typically used to simulate email communications from any sender address, making it appear as though the email originates from a legitimate source.
