# Cyber Kill Chain

The Cyber Kill Chain, developed by Lockheed Martin, is a seven-stage framework originally inspired by military operations. It outlines the lifecycle of a cyberattack from initial reconnaissance to data exfiltration or system damage allowing defenders to identify, disrupt, and mitigate intrusions at each step. This guide applies the model in a realistic attack simulation to demonstrate how adversaries operate and how defenders can respond.

## [Reconnaissance](https://github.com/A9u3ybaCyb3r/SOC-Phishing-Defense-Simulation/blob/main/Attack%20Simulation/Reconnaissance.md)

* The attacker gathers intelligence from the victim’s **Facebook** profile.
* The attacker obtains the victim’s **email address**.
* The attacker plans a **spear-phishing** campaign specifically targeting the victim.

## [Weaponization](https://github.com/A9u3ybaCyb3r/SOC-Phishing-Defense-Simulation/blob/main/Attack%20Simulation/Weaponization.md)

* The attacker uses **MSFVenom**, a Metasploit payload generator, to craft a **malicious executable**.
* The payload is named `SecurityUpdate.exe` and designed to appear legitimate.
* The executable is configured to initiate a **reverse TCP connection** back to the attacker’s machine.

## [Delivery Phase](https://github.com/A9u3ybaCyb3r/SOC-Phishing-Defense-Simulation/blob/main/Attack%20Simulation/Delivery%20Phase.md)

* The attacker hosts the payload using a **Python HTTP server**.
* The attacker sends a **phishing email** to the victim via **Temp Mail**, posing as **tech support**.
* The email contains a disguised **shortened URL** generated using **Emkei's Fake Mailer**.
* The email subject line is designed to induce urgency:

  * **Subject**: "`Critical Update: Immediate Action Required`"

## [Exploitation Phase](https://github.com/A9u3ybaCyb3r/SOC-Phishing-Defense-Simulation/blob/main/Attack%20Simulation/Exploitation%20Phase.md)

* The victim receives the phishing email and clicks on the malicious link.
* The victim downloads and runs `SecurityUpdate.exe` as an administrator via the **command prompt**.
* The payload executes, establishing a **reverse TCP session** with the attacker’s system.
* The attacker now has remote access to the victim's Windows machine.

## [Installation Phase](https://github.com/A9u3ybaCyb3r/SOC-Phishing-Defense-Simulation/blob/main/Attack%20Simulation/Installation%20Phase.md)

* The attacker modifies the Windows **Registry** to achieve **persistence**.
* A backdoor named `update.exe` is added to the system’s **autorun** entries.
* The attacker names the backdoor `update.exe` to mimic legitimate system files and avoid detection.
* The attacker relies on the sheer number of legitimate files in the system to hide malicious ones.

## [Command and Control Phase](https://github.com/A9u3ybaCyb3r/SOC-Phishing-Defense-Simulation/blob/main/Attack%20Simulation/Command%20and%20Control%20Phase.md)

* The attacker sends shell commands such as `cd` and `ls` to navigate the compromised system.
* The attacker searches for sensitive data including user credentials, documents, and folders.

## [Actions on Objectives Phase](https://github.com/A9u3ybaCyb3r/SOC-Phishing-Defense-Simulation/blob/main/Attack%20Simulation/Actions%20on%20Objectives.md)

* The attacker creates a new user account named `guest` with the password `password123`.
* The attacker accesses a directory named `secret_folder` and downloads `important_doc.txt`.
* The attacker deletes `important_doc.txt` from the victim’s machine to cover their tracks.
* The attacker removes the created `guest` user account.
* The attacker clears the Windows **system and security logs** to erase evidence of the breach.

---

## 🛠️ Tools Utilized

| Tool                  | Purpose                                                                 |
|-----------------------|-------------------------------------------------------------------------|
| **Metasploit**        | To create and deliver the payload (`msfvenom`) and handle the exploit. |
| **Emkei’s Fake Mailer** | To send spoofed phishing emails with fake sender addresses.           |
| **LaZagne**           | To extract stored passwords post-exploitation.                          |
| **Temp Mail**         | To receive phishing emails without exposing real inboxes.              |

This simulation demonstrates how a single phishing email can lead to a full system compromise. By analyzing each phase of the Cyber Kill Chain, defenders can better detect, disrupt, and mitigate attacks before damage is done.
