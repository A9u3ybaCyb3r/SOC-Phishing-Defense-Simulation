# 🚨 Containment, Eradication, and Recovery

## 🔒 Containment

* **Isolate compromised systems** from the network.

  * In **LimaCharlie**, isolate the system to cut off attacker communication:

    ![LimaCharlie Isolation Step 1](https://github.com/user-attachments/assets/6b172adb-25a7-461f-a0fd-2b7031f4a12a)
    ![LimaCharlie Isolation Step 2](https://github.com/user-attachments/assets/41eeb892-65e0-41da-aedf-efdc759e5bed)
    ![LimaCharlie Isolation Step 3](https://github.com/user-attachments/assets/9e14af56-6174-4cb7-835e-5fe46e74b787)
    ![LimaCharlie Isolation Step 4](https://github.com/user-attachments/assets/480df2dc-8138-4cea-a46b-37113e642285)

* **Disable persistence mechanisms** such as registry-based backdoors.

  * Use **Autoruns** from Sysinternals Suite to inspect startup items.

    ![Autoruns Detection](https://github.com/user-attachments/assets/a2dabb4c-b2b4-4e61-8a5f-29f4886bc63d)

  * Uncheck and then delete suspicious entries to disable attacker persistence:

    ![Autoruns Deletion](https://github.com/user-attachments/assets/bd976e57-4edd-4eda-9b58-22d0bb4df0e7)

---

## 🔍 Eradication

* **Use EDR tools to delete malware** (e.g., `SecurityUpdate.exe`).

  * In **LimaCharlie**, navigate to the file system and delete the malware:

    ![Deleting Malware in LimaCharlie](https://github.com/user-attachments/assets/44ded4ce-19f3-4cad-91da-03d3184d672c)

  * You may optionally download the malware for sandbox analysis, but deletion is advised in recovery.

* **Blacklist attacker's IP address** using Windows Firewall:

  * Run the following commands in **Command Prompt as Administrator**:

    ```bash
    netsh advfirewall firewall add rule name="Blacklisted IP" dir=in action=block remoteip=10.19.19.134
    netsh advfirewall firewall add rule name="Blacklisted IP" dir=out action=block remoteip=10.19.19.134
    ```

    ![Firewall Rule Block](https://github.com/user-attachments/assets/12f064ca-60fc-47c0-9134-82520ba65657)

---

## 🔧 Recovery

* **Restore compromised systems** from a known clean snapshot.

* **Validate integrity** before reconnecting to the network.

* **Conduct a post-remediation review** to verify that:

  * All IOCs are removed
  * No persistence remains
  * Logs confirm cleanup success

* If using a virtualization platform, such as VirtualBox, choose to restore from a saved state:

  ![VirtualBox Restore Option](https://github.com/user-attachments/assets/2c765d11-2348-4304-a13a-b78b6e2276fd)

* Alternatively, **power off the virtual machine** and restore snapshot from the VirtualBox manager:

  ![VirtualBox Shutdown](https://github.com/user-attachments/assets/30a50276-fe25-42a1-83c0-b04072bd2a62)
  ![VirtualBox Snapshot Recovery](https://github.com/user-attachments/assets/5c4348dd-d18c-4fac-9e6b-c78b8b15f677)
