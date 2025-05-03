# 🛡️ Preparation Phase

## 🎯 Objectives

* ✅ Establish and maintain an incident response policy and plan
* 🧠 Train personnel and run awareness programs
* 🧪 Develop & test incident handling procedures
* 🛠️ Set up monitoring systems, forensic tools, and detection software

📘 *This preparation phase aligns with the NIST SP 800-61 Computer Security Incident Handling Guide and SANS Incident Response methodology.*

---

## 📚 Table of Contents

1. [Writing Snort Rules](#writing-snort-rules)
    - [Sending Snort Logs to Splunk](#sending-snort-logs-to-splunk)
2. [Creating a Real-Time Alert for Reverse TCP in Splunk](#creating-a-real-time-alert-for-reverse-tcp-in-splunk)
3. [Writing YARA Rules](#writing-yara-rules)
4. [LimaCharlie Detection and Response Rules](#LimaCharlie-Detection-and-Response-Rules)
5. [Setting Up Microsoft Sysmon for Splunk](#setting-up-microsoft-sysmon-for-splunk)

---

## 🔍 Writing Snort Rules

Configured Snort rules using [Snort Rule Generator](https://anir0y.in/snort2-rulgen/) to detect suspicious behavior in our lab:

Setting Up Snort Environment
- Configuration File: Use `sudo subl` to edit the `local.rules` file in the Snort directory.
- Go to the **Snort Rules** Directory: 
```bash
  cd /etc/snort/rules/
```

- Use **Sublime Text** to edit the rules.
```bash
  sudo subl local.rules
```

### 🚨 Lab Rules

* **Rule 1: Reverse TCP Detection**

  * Detects reverse shell connections over TCP port 4444 (commonly used by Metasploit payloads).
```snort
alert tcp any 4444 -> 10.19.19.6 any (msg:"Reverse TCP on Port 4444"; sid:1000002; rev:1;)
```

* **Rule 2: HTTP on Non-Standard Ports (8001–9000)**

  * Monitors web traffic on ports frequently used by C2 channels or misconfigured applications.
  * *Note: Splunk is hosted on port 8000 in this setup.*
```snort
alert tcp any 8001:9000 -> 10.19.19.6 any (msg:"HTTP Traffic on Non-Standard Port Detected"; sid:1000003; rev:1;)
```

* **Rule 3: HTTP on Port 80**

  * Baseline detection of standard HTTP communication.
```snort
alert tcp any 80 -> 10.19.19.6 any (msg:"HTTP Traffic Detected"; sid:1000004; rev:1;)
```

Example of ICMP Ping Rule:

```snort
alert icmp any any -> 8.8.8.8 any (msg:"ICMP Ping Detected"; sid:1000001; rev:1;)
```

Test with:

```bash
ping 8.8.8.8
```

### Test **Snort Rules**
- Run Snort in Console Mode:

```bash
sudo snort -A console -q -c /etc/snort/snort.conf -i [your interface]
```

- Use the `-A` console option to display alerts in real-time.
- `-q` to suppress unnecessary output.
Generate traffic for each rule, if you see the alerts then it is working.

Then set the rules to generate logs and monitor the network:

![image](https://github.com/user-attachments/assets/ea7f41e3-c75b-4aab-8353-1169b3500c44)

```bash
sudo snort -A fast -l /var/log/snort -i [your interface] -c /etc/snort/snort.conf  -q
```

---

## ## 📤 Sending Snort Logs to Splunk

This guide focuses on configuring Snort to send logs to Splunk, assuming both are already installed on the same system.

---

## 1. Configure Snort Logging
1. Ensure Snort logs are saved in a directory accessible by Splunk:
   - Default directory: `/var/log/snort/`

2. Confirm the log format is compatible with Splunk (e.g., plain text or syslog format).

## 2. Set Up Splunk to Monitor Snort Logs

1. **Access Splunk Web Interface:**
   Open a browser and navigate to `http://localhost:8000`.

2. **Install Snort Alert for Splunk App:**
- Go to `Apps > Find More Apps`
- On the search bar, search for **Snort** and install the app.

![image](https://github.com/user-attachments/assets/a1daa98d-aaaf-46e8-868b-dc67100f1aaf)

- Provide the credentials of your **Splunk.com**(the creds that you used to download **Splunk**) and install the app. 

3. **Create a Data Input:**
   - Go to `Settings > Data Inputs > Files & Directories`.
   - Add a new data input pointing to `/var/log/snort/alert`.
   - If the `alert` file is missing, run the following command to generate log entries:
   ```bash
   sudo snort -q -l /var/log/snort -A fast -i enp0s3 -c /etc/snort/snort.conf
   ```
   - In another terminal, perform a simple ping test:
   ```bash
   ping 8.8.8.8
   ```
   - The generated alerts should be logged in `/var/log/snort/alert`. To verify, open the file with a text editor or cat:
   ```bash
   cat /var/log/snort/alert
   ``` 


4. **Set Source Type:**
   - Choose `Select > Network & Security > snort` as the source type.
   - Also, you can create a custom source type if you need it.

   ![image](https://github.com/user-attachments/assets/0c10dd92-7bd4-454c-aee0-03730b2770fa)

   ![image](https://github.com/user-attachments/assets/a66b01cd-07a4-4703-9007-4b76f1a515b4)

   ![image](https://github.com/user-attachments/assets/d9fad025-ff17-439a-8e23-085fa04c534d)

   - Click on **Save as** and you will see how it automatically did this for us.


6. **App Context**
   - Choose `Snort Alert for Splunk (snortalert)`.

7.  **Assign an Index:**
   - Specify an index (e.g., `ids`).

![image](https://github.com/user-attachments/assets/0dfcd718-ab6b-4ace-86df-c4ca865d5df8)

![image](https://github.com/user-attachments/assets/bb71756b-799e-4065-b5b3-cd765c36c513)

## 3. Verify Logs in Splunk

1. Trigger Snort alerts by simulating network activity (e.g., pinging):
   ```bash
   sudo snort -q -l /var/log/snort/ -i [your interface] -A full -c /etc/snort/snort.conf
   ```

2. Check Splunk for indexed logs:
   - Go to `Search > Data Summary`.
   - Confirm logs are indexed under `ids`.

3. Run a search query to view logs:
   ```spl
   index=ids
   ```

## 4. Optional: Field Extraction and Parsing

1. Use Splunk's field extraction feature to parse Snort logs into structured fields:
   - Timestamp
   - Source IP
   - Destination IP
   - Alert message

2. Use regex to extract fields if needed manually.


By following these steps, Snort logs will be sent to Splunk for efficient analysis and monitoring.

---

# Creating a Real-Time Alert for Reverse TCP in Splunk

## Step 1: Search for Critical Events
To detect reverse TCP connections in Splunk, use the following search query to find Snort alerts indicating a potential compromise:

```spl
index=* eventtype="snort-alert" name="Reverse TCP*"
```
![image](https://github.com/user-attachments/assets/63971e29-f381-49ed-84cb-8afa23e5ec89)

### Verification
- Modify the query by adjusting the wildcard (*) placement on "Reverse" to test if results remain consistent.
- If no logs are generated, simulate an attack using a Meterpreter reverse shell on port 4444 to verify the detection.

## Step 2: Save the Search as an Alert
- Click **Save As → Alert**.
- Configure the alert settings:
- **Name**: Reverse TCP
- **Alert Type**: Real-Time
- **Trigger Condition**: Trigger per result (fires when an event is detected).

### Actions:
- Add to **Triggered Alerts**.
- Set **Severity** to **Critical**.
   - (Optional) Configure notifications via email, Slack, or other integrations.

![image](https://github.com/user-attachments/assets/a6b1dc69-03bb-4505-91a8-a822c26bd07b)

## Step 3: Simulate and Test the Alert
- Simulate an Attack:
  - Use **Metasploit** to set up a listener and establish a **Meterpreter** reverse shell.
  - Ensure **Snort** is actively monitoring traffic.
- Verify Alert Triggering:
  - Check the Triggered Alerts section in Splunk to confirm detection.

---

# Writing YARA Rules

## YARA Rule for LaZagne.exe

```yara
rule LaZagne
{
    meta:
        id = "67890"
        hash = "467e49f1f795c1b08245ae621c59cdf06df630fc1631dc0059da9a032858a486" 
        version = "1.0"
        date = "2025-02-09"
        author = "BVega"
        description = "Identifies LaZagne, credentials recovery project."
        reference = "https://github.com/AlessandroZ/LaZagne"


    strings:
        $ = "[!] Specify a directory, not a file !" ascii wide
        $ = "lazagne.config" ascii wide
        $ = "lazagne.softwares" ascii wide
        $ = "blazagne.exe.manifest" ascii wide
        $ = "slaZagne" ascii wide fullword

    condition:
        any of them
}
```

### Rule Highlights:
1. Metadata (**meta**):
- Provides a description, author, and reference for documentation.
2. Strings (**strings**):
- The rule uses a combination of generic and specific strings to detect LaZagne:
  - **$name**: Matches the term "lazagne" in a case-insensitive manner (**nocase**).
  - **$url**: Detects the GitHub repository URL, useful for identifying files referencing the tool.
  - **$string1**, **$string2**, **$string3**: Detects descriptive strings commonly associated with LaZagne's functionality, such as:
    - **"Retrieve credentials from browsers"**
    - **"Dumping saved passwords"**
    - **"Extracting credentials from system"**
3. Condition (**condition**):
- Triggers if any of the defined strings are found in the scanned file.
4. Case-Insensitive Matching:
- Strings like **$name** and **$url** are marked with **nocase** to detect variations in capitalization.

## YARA Rule for LaZagne-process

```yara
rule laZagne_strings 
{
    meta:
      author = "BVega"
      description = "Detects LaZagne post-exploitation tool based on key strings"
  
    strings:
      $l1 = "LaZagne" ascii nocase
      $l2 = "GetPasswords" ascii nocase
  
    condition:
      any of them
}
```

### Explanation:

- **Meta**: Provides context and attribution.
- **Strings**:
  - `$l1` looks for the string "`LaZagne`" (case-insensitive).
  - `$l2` looks for the string "`GetPasswords`".
- **Condition**:
  - **any of them** means that any of $l1 or $l2 must be found in the scanned file or memory region for the rule to trigger.

## Yara Rule Meterpreter Reverse TCP Payload

```yara
rule Meterpreter_Reverse_TCP
{
    meta:
        author = "BVega"
        description = "Detects Windows x64 Meterpreter Reverse TCP payload"
        date = "2025-02-22"
    
    strings:
        // PE Header check (Windows EXE)
        $mz = { 4D 5A }  // MZ Header
        $pe = { 50 45 00 00 } // PE Header

        // Common Meterpreter shellcode patterns
        $meterpreter_1 = { FC 48 83 E4 F0 E8 CC 00 00 00 41 51 41 50 52 48 31 D2 65 48 8B 52 60 } 
        $meterpreter_2 = { 6A 02 5F 6A 01 5E 6A 06 5A 48 89 E1 49 89 C8 49 89 D1 4D 31 C9 4D 31 C0 }
        $meterpreter_3 = { 48 8B 05 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? FF 15 ?? ?? ?? ?? }
        
        // Windows API functions commonly used by Meterpreter
        $exit_process = "ExitProcess" ascii
        $virtual_alloc = "VirtualAlloc" ascii
        $kernel32 = "KERNEL32.dll" ascii

        // DOS Stub string in PE files
        $dos_stub = "This program cannot be run in DOS mode" ascii

    condition:
        // Ensure it's a PE file
        uint16(0) == 0x5A4D and 

        // Match any of the core Meterpreter shellcode patterns
        (any of ($meterpreter*) or

        // Match Meterpreter's API calls and DOS stub
        all of ($exit_process, $virtual_alloc, $kernel32) or

        // Ensure it’s an EXE with expected PE format
        ($mz and $pe and $dos_stub))
}
```
### Explanation:

- **Meta**:
  - Provides context about the rule, including the author, description, and creation date.
  - Describes the purpose of detecting **Windows x64 Meterpreter Reverse TCP payloads**.

- **Strings**:
  - `$mz` looks for the "**MZ**" (`4D 5A`) header, which identifies Windows executable files.
  - `$pe` looks for the "**PE**" (`50 45 00 00`) header, confirming that the file is a **Portable Executable** (**PE**).
  - `$meterpreter_1` detects a **common Meterpreter shellcode** pattern used for memory allocation and execution.
  - `$meterpreter_2` identifies the **reverse TCP socket setup**, which Meterpreter uses to establish a connection.
  - `$meterpreter_3` looks for **networking-related API** calls, crucial for initiating a reverse connection.
  - `$exit_process` detects the "**ExitProcess**" function, which Meterpreter calls when terminating.
  - `$virtual_alloc` identifies "**VirtualAlloc**", which allocates memory for shellcode execution.
  - `$kernel32` checks for "**KERNEL32.dll**", a Windows API library required for process execution.
  - `$dos_stub` looks for the standard "**This program cannot be run in DOS mode**" message, which appears in Windows PE files.

- **Condition**:
  - Ensures the file starts with **MZ** (`0x5A4D`), confirming it’s a Windows executable.
  - The rule triggers if:
    - Any of the `$meterpreter_*` patterns are found OR
    - The file contains all three API function calls (`$exit_process`, `$virtual_alloc`, `$kernel32`) OR
    - The file contains both `$mz` and `$pe` headers along with the DOS stub.

This ensures accurate detection of **Meterpreter reverse TCP** payloads while avoiding false positives.

---

# LimaCharlie Detection and Response Rules

## Setting Up Generic YARA Detection D&R Rules in LimaCharlie

### Overview
This guide describes the steps required to create two generic D&R rules in LimaCharlie. These rules are designed to:

- Rule 1 – YARA Detection: Detect and alert when a YARA detection occurs that does not include a PROCESS object.
- Rule 2 – YARA Detection in Memory: Detect and alert when a YARA detection occurs that involves a PROCESS object.

### Step 1: Create the “YARA Detection” Rule
This rule is designed to catch YARA detections that do not involve a PROCESS object (typically on-disk detections).

1. **Navigate to D&R Rules**
- Log in to your LimaCharlie dashboard.
- In the left-hand menu, go to “**Automation**” > “**D&R Rules**”.
2. **Create a New Rule**
- Click the “**New Rule**” button to start a new rule.
3. **Configure the Detection Block**
In the rule’s **Detect** block, paste the following YAML:
```yaml
event: YARA_DETECTION
op: and
rules:
  - not: true
    op: exists
    path: event/PROCESS/*
  - op: exists
    path: event/RULE_NAME
```
### Explanation:

- **event: YARA_DETECTION**
Specifies that the rule will only evaluate events labeled as `YARA_DETECTION`.

- **First sub-rule**:
Uses `not: true` with the operator `exists` on the path `event/PROCESS/*`. This means the rule will only match if the event does not have any PROCESS-related data.

- **Second sub-rule**:
Uses `op: exists` to ensure that the event includes a `RULE_NAME` attribute.

4. **Configure the Response Block**
In the rule’s Respond block, paste the following YAML:

```yaml
- action: report
  name: YARA Detection {{ .event.RULE_NAME }}
- action: add tag
  tag: yara_detection
  ttl: 80000
```
### Explanation:

- **Report Action**:
Generates a detection report. The detection name dynamically incorporates the YARA rule name from the event.

- **Add Tag Action**:
Tags the sensor with `yara_detection` for later filtering or automated actions, with a Time-To-Live (TTL) of 80,000 seconds.

5. **Save the Rule**
- Title the rule as “**YARA Detection**”.
- Click “**Save**” to deploy the rule.

### Step 2: Create the “YARA Detection in Memory” Rule
This rule is targeted at YARA detections that involve a PROCESS object, indicating an in-memory detection.

1. **Navigate to D&R Rules**
- From the “**Automation**” > “**D&R Rules**” section, click “**New Rule**” to create another rule.
2. **Configure the Detection Block**
In the **Detect** block, paste the following YAML:
```yaml
event: YARA_DETECTION
op: and
rules:
  - op: exists
    path: event/RULE_NAME
  - op: exists
    path: event/PROCESS/*
```
### Explanation:
- **event: YARA_DETECTION**
Ensures the rule processes only YARA detection events.
- **First sub-rule**:
Confirms that the event includes a `RULE_NAME` field.
- **Second sub-rule**:
Confirms that the event has a PROCESS object by checking for any data under `event/PROCESS/*`.

3. **Configure the Response Block**
In the Respond block, paste the following YAML:

```yaml
- action: report
  name: YARA Detection in Memory {{ .event.RULE_NAME }}
- action: add tag
  tag: yara_detection_memory
  ttl: 80000
```

### Explanation:
- **Report Action**:
Reports the detection and dynamically includes the YARA rule name.
- **Add Tag Action**:
Tags the sensor with `yara_detection_memory` for easier filtering and automated responses.
4. **Save the Rule**
- Title the rule as “**YARA Detection in Memory**”.
- Click “Save” to deploy the rule.

# Automate YARA Scanning

## Overview
This documentation explains how to set up two D&R rules in LimaCharlie that will:

- Rule 1: **YARA Scan Downloaded EXE**
Detect new `.exe` files appearing in any user’s Downloads folder and trigger a YARA scan against the file (using the LaZagne YARA signature).
- Rule 2: **YARA Scan Process Launched from Downloads**
Detect processes launched from a user’s Downloads directory and trigger an in-memory YARA scan on the running process (using a LaZagne-specific YARA rule for running processes).

## Part 1: Automatically YARA Scan Downloaded EXE Files
This rule detects when a new EXE file appears in a user’s Downloads folder (i.e. a NEW_DOCUMENT event) and triggers a YARA scan using the LaZagne signature.

### Step 1.1: Create the Rule
1. **Navigate to D&R Rules**:
- In the LimaCharlie dashboard, go to “**Automation**” > “**D&R Rules**”.
2. **Create a New Rule**:
- Click on the “New Rule” button.

### Step 1.2: Configure the Detect Block
In the **Detect** block, paste the following YAML:
```yaml
event: NEW_DOCUMENT
op: and
rules:
  - op: starts with
    path: event/FILE_PATH
    value: C:\Users\
  - op: contains
    path: event/FILE_PATH
    value: \Downloads\
  - op: ends with
    path: event/FILE_PATH
    value: .exe
```
### Explanation:
- Event Type: The rule only applies to `NEW_DOCUMENT` events.
- File Path Conditions:
  - **Starts with**: Ensures the file is under a user directory (e.g., `C:\Users\`).
  - **Contains**: Checks that the file path includes `\Downloads\`.
  - **Ends with**: Confirms the file is an `.exe` file.

### Step 1.3: Configure the Respond Block
In the `Respond` block, paste the following YAML:
```yaml
- action: report
  name: EXE dropped in Downloads directory
- action: task
  command: >-
    yara_scan hive://yara/lazagne -f "{{ .event.FILE_PATH }}"
  investigation: Yara Scan Exe
  suppression:
    is_global: false
    keys:
      - '{{ .event.FILE_PATH }}'
      - Yara Scan Exe
    max_count: 1
    period: 1m
```

### Explanation:
- **Report Action**: Generates an alert named “EXE dropped in Downloads directory (LaZagne).”
- **Task Action**:
  - Initiates a sensor command to perform a YARA scan.
  - Uses the LaZagne YARA rule (`hive://yara/lazagne`) to scan the file specified by the `FILE_PATH` field.
  - The **suppression** settings ensure that duplicate scans are prevented for the same file within one minute.

### Now do the same but with winPEAS YARA rule

### Step 1.4: Save the Rule
- Title the rule as “**YARA Scan Downloaded EXE**”.
- Click “**Save**” to deploy the rule.

## Part 2: Automatically YARA Scan Processes Launched from Downloads
This rule detects when a process is started from a user’s Downloads folder (i.e. a NEW_PROCESS event) and triggers an in-memory YARA scan using a LaZagne-specific signature.

### Step 2.1: Create the Rule
1. **Navigate to D&R Rules**:
- In the LimaCharlie dashboard, under “**Automation**” > “**D&R Rules**”, click on “**New Rule**”.

### Step 2.2: Configure the Detect Block
In the **Detect** block, paste the following YAML:
```yaml
event: NEW_PROCESS
op: and
rules:
  - op: starts with
    path: event/FILE_PATH
    value: C:\Users\
  - op: contains
    path: event/FILE_PATH
    value: \Downloads\
```

### Explanation:
- **Event Type**: The rule applies to `NEW_PROCESS` events.
- **File Path Conditions**:
Checks that the process’s file path starts with C:\Users\ and includes \Downloads\, indicating it was launched from the Downloads directory.

### Step 2.3: Configure the Respond Block
In the **Respond** block, paste the following YAML:
```yaml
- action: report
  name: Execution from Downloads directory
- action: task
  command: yara_scan hive://yara/lazagne-process --pid "{{ .event.PROCESS_ID }}"
  investigation: Yara Scan Process
  suppression:
    is_global: false
    keys:
      - '{{ .event.PROCESS_ID }}'
      - Yara Scan Process
    max_count: 1
    period: 1m
```
### Explanation:
- **Report Action**: Generates an alert named “Execution from Downloads directory.”
- **Task Action**:
  - Initiates a YARA scan on the running process using its `PROCESS_ID`.
  - Uses the LaZagne-specific YARA rule for processes (`hive://yara/lazagne-process`).
  - The suppression settings prevent duplicate scans for the same process within one minute.

### Step 2.4: Save the Rule
- Title the rule as “**YARA Scan Process Launched from Downloads (LaZagne)**”.
- Click “**Save**” to deploy the rule.

### Now do the same but with winPEAS process YARA rule

## Part 3: Triggering and Testing the Rules

### Testing the Downloaded EXE Rule
1. **Simulate EXE Movement**:
- Open an Administrative PowerShell prompt.
- Move your LaZagne payload from the Downloads folder to Documents:
```powershell
Move-Item -Path C:\Users\User\Downloads\LaZagne.exe -Destination C:\Users\User\Documents\LaZagne.exe
```
Then, move it back to the Downloads folder to generate a `NEW_DOCUMENT` event:
```powershell
Move-Item -Path C:\Users\User\Documents\LaZagne.exe -Destination C:\Users\User\Downloads\LaZagne.exe
```
2. **Verify Detections**:
- Go to your Detections tab in LimaCharlie.
- You should see an alert titled “EXE dropped in Downloads directory” followed by a YARA detection report once the scan completes.
- If no detection appears, check the Timeline for a `NEW_DOCUMENT` event showing the file movement.

### Testing the Process Rule
1. **Terminate Existing Instances**:
- Open an Administrative PowerShell prompt.
- Stop any running instances of LaZagne.exe (replace `LaZagne` with the payload name without the `.exe` extension):
```powershell
Get-Process LaZagne | Stop-Process
```
- (Ignore errors if no instance is running.)
2. **Launch the Payload**:
- Execute LaZagne.exe from the Downloads folder:
```powershell
C:\Users\User\Downloads\LaZagne.exe
```
3. **Verify Detections**:
- Check your **Detections** tab.
- You should see an alert titled “Execution from Downloads directory” followed by an in-memory YARA detection once the process scan is completed.

---

# Setting Up Microsoft Sysmon for Splunk

This detailed guide provides step-by-step instructions for configuring the Splunk Universal Forwarder to send logs to a Splunk server, setting up the necessary configurations, and verifying data ingestion.

## 1. Inputs.conf Configuration

- **File Location:**
  - `C:\Program Files\Splunk Universal Forwarder\etc\system\default\inputs.conf`

- **Important:** Do not edit the default `inputs.conf`. Instead, create a new one under:
  - `C:\Program Files\Splunk Universal Forwarder\etc\system\local\inputs.conf`

- **Steps:**
  1. Open Notepad as Administrator.
  2. Create a new file with the name `inputs.conf`.
  3. Copy the desired configuration into this file, specifying the logs to forward (e.g., security, application, system, Sysmon).
  4. Save the file as `inputs.conf` in the `local` directory.

- **Configuration:**
  
  ```
  [WinEventLog://Application]

  index = endpoint

  disabled = false

  [WinEventLog://Security]

  index = endpoint

  disabled = false

  [WinEventLog://System]

  index = endpoint

  disabled = false

  [WinEventLog://Microsoft-Windows-Sysmon/Operational]

  index = endpoint

  disabled = false

  renderXml = true

  source = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  ```

- Reference: [Active Directory Project GitHub](https://github.com/MyDFIR/Active-Directory-Project)

## 2. Restart Splunk Forwarder Service

1. Navigate to **Services** in Windows.
2. Locate **Splunk Forwarder Service**.
3. Update the **Log On As** account:
   - Change from `NT Service\SplunkForwarder` to **Local System Account**.
4. Restart the service to apply changes.

## 3. Splunk Server Configuration

1. **Create Index:**
   - Log in to the Splunk web portal.
   - Go to **Settings > Indexes**.
   - Create a new index named `endpoint`.

2. **Enable Receiving:**
   - Go to **Settings > Forwarding and Receiving**.
   - Under **Receive Data**, configure a new receiving port (e.g., `9997`).

## 4. Verify Data Ingestion

1. Go to **Apps > Search & Reporting**.
2. Search for:
   ```spl
   index=endpoint
   ```
3. Verify:
   - Event count.
   - Host details (e.g., Bob-PC).
   - Sources and sourcetypes (e.g., security, application, system, Sysmon).

## Key Notes

- Restart the Splunk Forwarder service after every `inputs.conf` update.
- Ensure the Splunk server has the same index (`Endpoint`) as specified in `inputs.conf`.
- Use the default port (`9997`) for data forwarding.

By following these steps, you can successfully configure and verify the Splunk Universal Forwarder to send logs to your Splunk server.

---

# Downloading Forensic Tools on the Machine

## Installation and Setup
- Downloading FTK Imager:
To download the latest version, visit [Exterro's FTK Product Downloads](https://www.exterro.com/ftk-product-downloads/). The website may require basic information and CAPTCHA verification.

### Installation Steps:
1. Run the installer and follow the wizard.
2. Accept the license agreement.
3. Choose the default installation location or specify a custom path.
4. Finish the installation process.
5. Organizing Forensic Tools:
- Create a dedicated folder, such as `Forensic Tools`, on the forensic workstation desktop to store FTK Imager and other utilities.

## Registry Explorer
- Purpose: Analyze registry hives for evidence.
- Download: [Eric Zimmerman's Tools](https://ericzimmerman.github.io)
- Requirements: Install the [.NET Desktop Runtime](https://dotnet.microsoft.com/en-us/download/dotnet).

### Steps to Use:
1. Download and extract Registry Explorer.
2. Install .NET Runtime if prompted.
3. Open registry hives for analysis.

## KAPE (Kroll Artifact Parser and Extractor)
- Purpose: Rapid triage and extraction of artifacts from live systems.
- Download:
  - Primary: [KAPE](https://s3.amazonaws.com/cyb-us-prd-kape/kape.zip)
  - Alternate: [Kroll's KAPE Page](https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape)

### Steps to Use:
1. Download and extract KAPE.
2. Configure targets and modules for specific artifact extraction.
3. Run KAPE on live systems for rapid data collection.

---

## 🔚 Next Step: [➡️ Attack Simulation Phase](https://github.com/A9u3ybaCyb3r/Cyber_Defense_Lab/tree/main/Attack%20Simulation)
