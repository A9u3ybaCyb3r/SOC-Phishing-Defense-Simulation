# Cyber Kill Chain

Developed by Lockheed Martin, it is a conceptual framework that describes the stages of a cyberattack. Originating from military concepts, the model parallels physical attack planning and execution, providing organizations with a systematic approach to understanding, detecting, and defending against cyber threats. We are going to use this framework for our attack simulation. 

## Reconnaissance and Weaponization
- The attacker (Ubuntu VM) gathers a victim’s email from LinkedIn.
- Creates a malicious payload (`payload.exe`) using MSFVenom.
- Hosts the payload on port **8000** using Python HTTP server.

## Delivery Phase
- Sends a phishing email with a disguised **shortened URL** linking to the payload.
- Subject: "*Critical Update: Immediate Action Required.*"

## Exploitation Phase
- Victim downloads and executes `payload.exe`.
- A reverse TCP connection is established on port **4444** using **Metasploit**.

## Installation Phase
- The attacker modifies the **Windows Registry** to create a backdoor for persistence.

## Command and Control Phase
- The attacker executes commands remotely, exploring the compromised system and preparing for data exfiltration.

## Actions on Objectives Phase
In this final phase of the Cyber Kill Chain, the attacker:
- **Escalates privileges** to domain admin using credential dumping.
- Adds a new user: `EvilUser` to the domain.
- **Exfiltrates sensitive data** (e.g., `passwords.txt`, `secrets.txt`).
- Deletes the exfiltrated file and clears system logs to erase evidence.

---

## Actions on the Domain
