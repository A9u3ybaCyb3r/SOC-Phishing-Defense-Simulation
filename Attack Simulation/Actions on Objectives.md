# Phase 7: Actions on Objectives

## 🌟 Objective:

Exfiltrate sensitive data, establish fallback access, and erase evidence to avoid detection.

### Steps:

#### Creating a New User Account

* The attacker creates a user named `guest` with password `Password123` to establish fallback access:

  ```bash
  net user guest Password123 /add
  ```

  ![image](https://github.com/user-attachments/assets/0538c131-2050-4555-a199-2b8de4241b1d)

* This ensures the attacker can re-enter the system even if the current session is terminated.

---

#### Dumping Credentials

* The attacker uses tools like **LaZagne** to extract saved credentials from the system.
* Recovered passwords may be used to escalate privileges or access external accounts.

![image](https://github.com/user-attachments/assets/6e1b11bc-9012-4690-a653-5c1de564996f)
![image](https://github.com/user-attachments/assets/0fe4970b-416e-4db5-80a4-c2c0b23cd581)

---

#### Exfiltrating Data

* The attacker locates a folder named `secret_folder` and downloads `important_doc.txt`:

  ![image](https://github.com/user-attachments/assets/168246a7-23c9-49d4-8473-06ecee780829)
  ![image](https://github.com/user-attachments/assets/c03f2349-81ea-4b59-a1ab-5b1e5a179f31)
  ![image](https://github.com/user-attachments/assets/e48caaaf-4265-494b-91bd-e619d47f4879)

* The stolen file likely contains confidential or valuable information.

---

#### Deleting Local Evidence

* The attacker deletes the `Secret Storage.txt` file to remove traces of data access:

  ```bash
  del "Secret Storage.txt"
  ```

  ![image](https://github.com/user-attachments/assets/3643df55-9185-4242-aea6-fcc154eba029)

---

#### Covering Tracks

* The attacker removes the newly created user account:

  ```bash
  net user guest /delete
  ```

  ![image](https://github.com/user-attachments/assets/98f4e8c7-524f-49e7-b0e4-c56519bec77f)

* The attacker clears the **System** and **Security** logs using `wevtutil` to wipe forensic evidence:

  ```bash
  wevtutil cl System
  wevtutil cl Security
  ```

  ![image](https://github.com/user-attachments/assets/ad49d2f7-0b58-45ee-9a25-22358ce5d544)

* This hinders incident responders from reconstructing the attack timeline.

---

## ✅ Attack Phase Complete

The attacker has successfully compromised the system, extracted sensitive data, and covered their tracks.

➡️ Proceed to the [Incident Response Phase](https://github.com/A9u3ybaCyb3r/Cyber_Defense_Lab/blob/main/Incident%20Response/Preparation.md) to begin detection, containment, and recovery.
