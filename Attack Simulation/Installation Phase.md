# Phase 5: Installation

## 🌟 Objective:
Establish persistence on the victim’s system to ensure continued access.

### Steps:
#### Creating a Backdoor for Persistence:
- The attacker modifies **Windows registry settings** to create a persistent backdoor.
- The **update.exe** is added to **autoruns**, allowing the attacker to regain access every time the system reboots.
    - The name is to help the backdoor blend in with legitimate software.

### Adding the Backdoor to the Registry

Run the following command to add an entry to the registry. This will configure Windows to run the malicious **SecurityUpdate.exe** file on startup:

```
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "update.exe" /t REG_SZ /d "C:\Users\Bob\Downloads\SecurityUpdate.exe" /f
```

Here's what this command does:

- `"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"` – This is the registry key where Windows stores the applications that should run automatically when a user logs in.
- `/v "update.exe"` – This specifies the name of the registry value. In this case, it's called "update.exe".
- `/t REG_SZ` – Specifies that the value will be a string (the path to the executable).
- `/d "C:\Users\Bob\Downloads\SecurityUpdate.exe"` – The path to the malicious executable that will be run at startup.
- `/f` – Forces the update without asking for confirmation.

![image](https://github.com/user-attachments/assets/73d813bc-eccb-4d4b-b376-1bb7e980b069)

#### Ensuring Long-Term Access:
- The attacker verifies that the backdoor works by restarting the victim’s machine and checking if access is maintained.

#### Persistence Ensured

- By adding the backdoor to the registry, Windows will automatically execute the malicious payload (**SecurityUpdate.exe**) located at the specified path every time the victim logs in.

- This ensures that the attacker maintains persistent access to the system, even if the victim reboots or logs off.

- Outcome: The backdoor allows the attacker to maintain access to the system without the victim having to manually run the malicious file again.

