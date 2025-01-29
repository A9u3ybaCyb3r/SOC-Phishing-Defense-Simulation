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

2. Create a spoofed email using [Emkei's Fake Mailer](https://emkei.cz/) (a tool for sending emails with a forged sender address).

![image](https://github.com/user-attachments/assets/48236a67-3e18-43c9-b808-2f1b0ffcca06)

3. Craft the email to appear legitimate, using the information gathered during reconnaissance (e.g., impersonating a service the target uses).

```
Subject: Urgent: Critical Security Update Required

Body:
Dear Bob,
We have identified a critical vulnerability in your system that requires immediate attention. This vulnerability could expose sensitive company data and compromise your account.

To resolve this issue, please download and install the Critical Security Update Tool by clicking the link below:

Download Security Update Tool [Link]

Instructions:

1. Click the link above to download the tool.
2. Run the tool and follow the on-screen instructions.
3. Restart your computer to complete the update.
4. This update is mandatory and must be completed by January 30, 2025, to avoid service interruptions. Failure to comply may result in account suspension.

If you have any questions, please contact the IT Help Desk at helpdesk@borikenshield.com or call 1-800-123-4567.

Thank you for your prompt attention to this matter.

Best regards,
IT Support Team
Boriken Shield
```

