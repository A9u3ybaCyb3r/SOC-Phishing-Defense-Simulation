# Installation

## Objective:
Establish a foothold in the target system to maintain persistent access, even after the victim logs out or restarts.

## Action:
To maintain access to the system, we can install a backdoor by modifying the Windows registry. This ensures that the malicious payload will be executed automatically every time the victim logs in.

1. Adding the Backdoor to the Registry

    Run the following command to add an entry to the registry. This will configure Windows to run the malicious **SecurityUpdate.exe** file on startup:

```
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Backdoor" /t REG_SZ /d "C:\Users\Bob\Downloads\SecurityUpdate.exe" /f
```

Here's what this command does:

- `"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"` – This is the registry key where Windows stores the applications that should run automatically when a user logs in.
- `/v "Backdoor"` – This specifies the name of the registry value. In this case, it's called "Backdoor".
- `/t REG_SZ` – Specifies that the value will be a string (the path to the executable).
- `/d "C:\Users\Bob\Downloads\SecurityUpdate.exe"` – The path to the malicious executable that will be run at startup.
- `/f` – Forces the update without asking for confirmation.

![image](https://github.com/user-attachments/assets/5cc9b67d-0148-4f63-9a99-89d2c3dd7bbe)

2. Persistence Ensured

    By adding the backdoor to the registry, every time the victim logs in, Windows will automatically execute the malicious payload (**SecurityUpdate.exe**) located at the specified path.

    This ensures that the attacker maintains persistent access to the system, even if the victim reboots or logs off.

- **Outcome**: The backdoor allows the attacker to maintain access to the system without needing the victim to manually run the malicious file again.

