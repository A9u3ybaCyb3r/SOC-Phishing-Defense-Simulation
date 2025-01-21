# Cyber Kill Chain

Developed by Lockheed Martin, it is a conceptual framework that describes the stages of a cyberattack. Originating from military concepts, the model parallels physical attack planning and execution, providing organizations with a systematic approach to understanding, detecting, and defending against cyber threats. We are going to use this framework for our attack simulation. 

## Reconnaissance and Weaponization
- The attacker (Kali VM) gathers a victim’s email from LinkedIn.
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
- The attacker executes commands remotely, escalates privileges, disables Windows Defender to execute Mimikatz, explores the compromised system, and prepares for data exfiltration.

## Actions on Objectives Phase
In this final phase of the Cyber Kill Chain, the attacker:
- **Escalates Privileges** to have full control of the machine.  
-  **Disables Windows Defender** to dump all of the credentials using Mimikatz.
- Adds a new user: `EvilUser` to the computer.
- **Exfiltrates sensitive data** (e.g., `passwords.txt`, `secrets.txt`).
- Deletes the exfiltrated file and clears system logs to erase evidence.

---

# Step by Step to Full Compromise

## Reconnaissance and Weaponization

- We are going to assume that we already have the target's email.
- Create an email:
  ```
  Social Media Policy Update
  Subject: Mandatory: Review and Acknowledge Updated Social Media Policy
  Email Body:
  "Hi [Name],
  We’ve updated our company’s social media policy. Please download and review the attached document, then confirm your acknowledgment by replying to this email.

  [Download Policy Document]

  Compliance is required by [specific date].

  Best regards,
  [Fake HR Department]"

  Attachment: Social_Media_Policy.docx (macro-enabled Word document).
  ```
- Create the payload using DS Viper
- Host the payload on Python HTTP server 
  

## Delivery Phase

## Exploitation Phase

## Exploitation Phase

## Installation Phase

## Command and Control Phase

---

## Tools Utilized

### DS Viper

DS Viper is a powerful tool designed to bypass Windows Defender's security mechanisms, enabling seamless execution of payloads on Windows systems without triggering security alerts. It utilizes a combination of advanced techniques to manipulate and disguise payloads, providing cybersecurity professionals, red teamers, and penetration testers with a robust solution for achieving undetected access.

### Emkei's Fake Mailer

Emkei's Fake Mailer is an online tool that allows users to send spoofed emails by forging the "From" address and other email headers. It is typically used to simulate email communications from any sender address, making it appear as though the email originates from a legitimate source.
