# 🕹️ Phase 6: Command and Control (C2)

## 🎯 Objective

Leverage the established Meterpreter session to interact with the compromised system and identify valuable data.

---

## 🔧 Step 1: Interact with the Victim's Machine

Once the payload executes and the reverse connection is established, the attacker gains an interactive **Meterpreter shell** via **Metasploit**.

### 🔹 Basic Command Execution

The attacker uses commands like:

```bash
cd
ls
```

These allow the attacker to:

* Change directories (`cd`)
* List files and folders (`ls`)

![C2 image](https://github.com/user-attachments/assets/6501381c-59d7-44cf-8487-6442cea0bb95)

---

## 🔍 Step 2: Explore the File System

With shell access, the attacker begins enumerating directories to find sensitive data.

### Activities:

* Browse user directories (e.g., `C:\Users\Bob\Documents`)
* Enumerate desktop files, downloads, and shared folders
* Look for keywords like `confidential`, `finance`, or `passwords`

### Example Discovery:

* A suspicious folder named **`secret_folder`** is found.
* Its presence suggests the potential for **high-value data**.

---

## 🧩 Summary

✅ **C2 Achieved**:
The attacker successfully controls the target system in real-time.

📂 **Initial Exploration Complete**:
Key directories are mapped and potential targets (like `secret_folder`) are identified for exfiltration in the next phase.
