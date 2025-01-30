# Reconnaissance

### Objective: Gather information about the target.

### Action:

1. Use OSINT (Open-Source Intelligence) techniques to gather information about the target.

2. Assume we found the target's email address on Facebook by analyzing their public profile, posts, or comments.

3. Additional information may include their job role, interests, or connections, which can be used to craft a convincing phishing email.

### Since this is a simulation we are going to assume that we have gathered all of this information to craft the payload and the malicious email.

### Also, we are going to use [Temp Mail](https://temp-mail.org/en) to create a temporary email. This is going to be the victim's email that is going to receive the malicious email.

![image](https://github.com/user-attachments/assets/fccedbae-e5a8-41f0-8e4c-1f4377fb39e9)

# Weaponization

### Objective: Create a malicious payload and delivery mechanism.

### Action:

1. Use DSViper (a tool for creating payloads) to generate a malicious executable that can execute a Meterpreter shell (a Metasploit payload for remote control). The payload is used to bypass Windows Defender

2. Host the payload in a python HTTP server.

