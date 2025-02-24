# Phase 7: Actions on Objectives

## 🌟 Objective:
Exfiltrate data, manipulate the system, and cover tracks to avoid detection.

### Steps:
#### Creating a New User:
- The attacker creates a new user named `guest` with password `password123` using:
  ```bash
  net user guesstt Password123 /add
  ```
  ![image](https://github.com/user-attachments/assets/0538c131-2050-4555-a199-2b8de4241b1d)

- This allows the attacker to **re-enter the system at will**.

#### Credential Dumping

![image](https://github.com/user-attachments/assets/6e1b11bc-9012-4690-a653-5c1de564996f)

![image](https://github.com/user-attachments/assets/0fe4970b-416e-4db5-80a4-c2c0b23cd581)

#### Exfiltrating Data:
- The attacker downloads a file named **`important_doc.txt`** from the `secret_folder` to their own machine.
- The file likely contains sensitive information.

![image](https://github.com/user-attachments/assets/168246a7-23c9-49d4-8473-06ecee780829)

![image](https://github.com/user-attachments/assets/c03f2349-81ea-4b59-a1ab-5b1e5a179f31)

![image](https://github.com/user-attachments/assets/e48caaaf-4265-494b-91bd-e619d47f4879)

#### Deleting Evidence on the Victim’s Machine:
- The attacker deletes `important_doc.txt` from the victim’s machine:
  ```bash
  del "C:\Users\Bob\secret_folder\important_doc.txt"
  ```

![image](https://github.com/user-attachments/assets/a484140e-fe48-401a-a666-82071249971c)

#### Removing Traces of the Attack:
- The attacker removes the created user:
  ```bash
  net user guest /delete
  ```
  ![image](https://github.com/user-attachments/assets/98f4e8c7-524f-49e7-b0e4-c56519bec77f)

- The attacker clears Windows system and security logs to hide their actions:
  ```bash
  wevtutil cl System
  wevtutil cl Security
  ```
  ![image](https://github.com/user-attachments/assets/ad49d2f7-0b58-45ee-9a25-22358ce5d544)

- This prevents forensic investigators from detecting the attack.

# Now we are done with the Attack Phase. Now we jump into the Incident Response Phase
