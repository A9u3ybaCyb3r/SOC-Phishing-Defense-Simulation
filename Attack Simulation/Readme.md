# Cyber Kill Chain

Developed by Lockheed Martin, it is a conceptual framework that describes the stages of a cyberattack. Originating from military concepts, the model parallels physical attack planning and execution, providing organizations with a systematic approach to understanding, detecting, and defending against cyber threats. We are going to use this framework for our attack simulation. 


## Reconnaissance and Weaponization
The attacker gathers the victim's email address from their LinkedIn profile, setting the stage for a spear phishing attack. A malicious payload is created using MSF Venom, which is a PE32 executable file. The payload is hosted using Python on port 8000.

## Delivery Phase
The payload is sent via a phishing email using Gmail, with a subject line designed to create a sense of urgency: "Immediate Action Required - Download Critical Application Update." A shortened URL is used to disguise the actual link.

## Exploitation Phase
The attacker sets up a listener on port 4444 using MSF console. The victim receives the phishing email, downloads the executable, and runs it, establishing a reverse TCP connection to the attacker's machine.

## Installation Phase
After compromising the Windows VM, the attacker modifies the Windows registry to create a backdoor, allowing future access without needing to run the payload again.

## Command and Control Phase
The attacker sends commands to the compromised machine to view sensitive information and prepares for data exfiltration.

## Actions on Objectives Phase
In this final phase of the Cyber Kill Chain, the attacker:
- Adds a new user named "EvilUser."
- Exfiltrates data from the compromised machine.
- Deletes the data from the compromised machine.
- Removes the created user and clears system and security logs to erase traces of the attack.

