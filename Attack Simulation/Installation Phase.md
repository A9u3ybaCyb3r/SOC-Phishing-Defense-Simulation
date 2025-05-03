# 🧬 Phase 5: Installation

## 🎯 Objective

Establish persistence on the victim’s machine to maintain access across system reboots.

---

## 🛠️ Step 1: Create a Persistent Backdoor

The attacker modifies **Windows registry settings** to run the malicious payload automatically at login:

* The executable `SecurityUpdate.exe` is disguised as a system update.
* A **registry autorun entry** is created under the current user hive.
* The value is labeled `update.exe` to blend in with legitimate Windows processes.

---

## 💻 Registry Command

Run the following command from a Meterpreter session or remote shell to register the backdoor:

```cmd
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "update.exe" /t REG_SZ /d "C:\Users\Bob\Downloads\SecurityUpdate.exe" /f
```

📌 **Command Breakdown**

| Part                             | Purpose                                                       |
| -------------------------------- | ------------------------------------------------------------- |
| `HKCU\...\Run`                   | Registry key for user-level startup programs                  |
| `/v "update.exe"`                | Name of the registry value (disguised as legitimate)          |
| `/t REG_SZ`                      | Declares the data type as a string                            |
| `/d "C:\...\SecurityUpdate.exe"` | Path to the payload that will run at login                    |
| `/f`                             | Forces the registry modification without confirmation prompts |

![Registry screenshot](https://github.com/user-attachments/assets/73d813bc-eccb-4d4b-b376-1bb7e980b069)

---

## 🔁 Step 2: Validate Persistence

* The attacker **reboots the victim’s machine**.
* Upon startup, the backdoor (`SecurityUpdate.exe`) is executed automatically.
* The attacker successfully regains remote access via the previously established reverse shell.

---

## 🧩 Summary

✅ **Persistence Achieved**:
The backdoor now runs every time the user logs in, ensuring long-term control.

🛡️ **Real-World Implication**:
Such persistence techniques are commonly used in real-world intrusions to maintain access while the attacker continues data exfiltration or lateral movement undetected.

