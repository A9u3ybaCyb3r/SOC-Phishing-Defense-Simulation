# Containment, Eradication, and Recovery

## Containment

- **Isolate compromised systems** from the network.
  - On **LimaCharlie** you can isolate the system from the network
  
  ![image](https://github.com/user-attachments/assets/6b172adb-25a7-461f-a0fd-2b7031f4a12a)

  ![image](https://github.com/user-attachments/assets/41eeb892-65e0-41da-aedf-efdc759e5bed)

  ![image](https://github.com/user-attachments/assets/9e14af56-6174-4cb7-835e-5fe46e74b787)

  ![image](https://github.com/user-attachments/assets/480df2dc-8138-4cea-a46b-37113e642285)

- **Disable persistence mechanisms** (e.g., backdoors in the registry using Autoruns).
  - Here we are using a tool called Autorun from the sysinternals. We can also see the backdoor that the attacker created.
  
  ![image](https://github.com/user-attachments/assets/a2dabb4c-b2b4-4e61-8a5f-29f4886bc63d)

  - Uncheck the box to disable the backdoor that the attacker created and then proceed to delete it.
  
  ![image](https://github.com/user-attachments/assets/bd976e57-4edd-4eda-9b58-22d0bb4df0e7)


## Eradication

- **Use EDR solutions** to delete malware (e.g., SecurityUpdate.exe).
  - On **LimaCharlie** go to the file system and delete the malware.

    ![image](https://github.com/user-attachments/assets/44ded4ce-19f3-4cad-91da-03d3184d672c)

  - For further analysis, you can also download the malware but in this case we will delete it.
    
- **Blacklist the attacker's IP address** via Windows Firewall.
  - Open CMD (as Administrator) and write these commands:
```
netsh advfirewall firewall add rule name="Blacklisted IP" dir=in action=block remoteip=10.19.19.134

netsh advfirewall firewall add rule name="Blacklisted IP" dir=out action=block remoteip=10.19.19.134
```

![image](https://github.com/user-attachments/assets/12f064ca-60fc-47c0-9134-82520ba65657)

## Recovery

- Restore the compromised system from a clean snapshot.
- Verify system integrity before reconnecting to the network.
- Conduct a final review to ensure all traces of compromise are removed.

You can use this option when closing the machine to restore it. 

![image](https://github.com/user-attachments/assets/2c765d11-2348-4304-a13a-b78b6e2276fd)

The other option is to turn off the machine and do this in Virtualbox.

![image](https://github.com/user-attachments/assets/30a50276-fe25-42a1-83c0-b04072bd2a62)

![image](https://github.com/user-attachments/assets/5c4348dd-d18c-4fac-9e6b-c78b8b15f677)

