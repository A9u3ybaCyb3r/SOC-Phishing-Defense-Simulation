# Preparation Phase

### Objectives
- Establish and maintain an incident response policy and plan.
- Train personnel and conduct awareness programs.
- Develop and test incident handling procedures.
- Set up necessary tools and resources, such as monitoring systems and forensic software.

---

In the preparation phase, several key configurations are made:
- **Snort Rules**: Configured to detect potential threats, including:
  - Rule 1: Detects a reverse TCP connection on port 4444 to the Windows VM.
  - Rule 2: Monitors HTTP traffic on non-standard ports (8000 to 9000).
  - Rule 3: Checks for executable files in HTTP traffic looking for MZ headers.
  - Rule 4: Monitors standard HTTP traffic on port 80.
- **Lima Charlie**: It is integrated with a Windows workstation for advanced threat detection and response capabilities.
  - **YARA Rules**: Rules are written to detect executable files in the downloads directory.
- **Splunk Configuration**: Alerts are set up to detect reverse TCP connections.
  - Both **Snort Logs** and **Sysmon Logs** are going to be sent to **Splunk** for centralised monitoring and analysis.
- **Forensic Tools**: Tools like Kape, Registry Explorer, and FTK Imager are downloaded for forensic analysis.

---

# Create a Real-Time Alert for reverse TCP on Splunk
1. **Search for Critical Events**
- Use Splunk to search for Event ID 1102, which indicates the clearing of security logs:

  ```spl
  index=* sourcetype="WinEventLog:Security" EventCode=1102
	
- To verify the search logic, modify the query to test using a different event code, such as 4624 (logon events).
2. **Save Search as an Alert**
- Click **Save As** and select **Alert**.
- Configure alert settings:
	- **Name**: Security Event Log Cleared.
	- **Real-Time Alert**: Trigger per result as soon as the event is detected.
	- **Actions**: Add to **Triggered Alerts** and configure alert severity (e.g., medium).
	- Optionally, set up notifications via email, Slack, or other integrations.
3. **Simulate and Test the Alert**
- Clear the security log on the monitored Windows system to generate an Event ID 1102.
- Confirm the alert triggers and appears in the **Triggered Alerts** section of Splunk.

---

# Writing Snort Rules

We will use [Snort Rule Generator](https://anir0y.in/snort2-rulgen/) to make our rules.

1. Setting Up Snort Environment
- Configuration File: Use `sudo subl` to edit the `local.rules` file in the Snort directory.
- Go to the **Snort Rules** Directory: 
```
  cd /etc/snort/rules/
```

- Use **Sublime Text** to edit the rules.
```
  sudo subl local.rules
```

2. Create a rule for testing pings.

```snort
alert icmp any any -> 8.8.8.8 any (msg:"ICMP Ping Detected"; sid:1000001; rev:1;)
```

- **Action**: alert
- **Protocol**: ICMP
- **Source**: Any IP and port.
- **Direction**: From source to destination.
- **Destination**: IP 8.8.8.8, any port.
- **Options**:
  - **Message**: "ICMP Ping Detected"
  - **SID**: 1000001
  - **Revision**: 1

3. Test **Snort Rules**
- Run Snort in Console Mode:

```
sudo snort -A console -q -c /etc/snort/snort.conf -i [your interface]
```

- Use the `-A` console option to display alerts in real-time.
- `-q` to suppress unnecessary output.


- Generating Traffic for Testing:
  - Ping `8.8.8.8` to trigger the ICMP rule and observe alerts in the console.
  - Ping a different IP (e.g., `8.8.4.4`) to confirm no alerts are generated for non-matching traffic.



4. Then we are going to create our rules for the lab.

- **Rule 1** 
```snort
alert tcp any any -> any 4444 ( msg:"Reverse TCP connection detected";  sid:1000002; rev:1; )
```
### What This Rule Detects
The rule looks for TCP traffic originating from any port on any IP and destined for any IP address on port 4444.
Port `4444` is often associated with reverse shells, such as those created by Metasploit or other penetration testing tools, where an attacker gains control of a compromised system.

### Example Scenario
An attacker compromises a machine and sets up a reverse shell listener on port `4444`.
The compromised machine with the IP of `10.19.19.133` initiates a connection to the attacker's machine.
This rule detects the traffic and generates an alert with the message:
`"Reverse TCP connection detected"`.

- **Rule 2**
```
alert tcp any 8000:9000 -> any any (msg:"HTTP Traffic on common Non-Standard Port Detected"; sid:1000003; rev:3;)
```
### What This Rule Detects
This rule detects **TCP traffic originating from ports 8000 to 9000**.
These ports are often used for HTTP traffic on non-standard ports, such as web applications, proxy servers, or custom services.
By monitoring this range, the rule identifies potentially suspicious or misconfigured web servers or malicious activities like command-and-control (C2) traffic disguised as HTTP.

### Example Scenario
A web server runs on port `8080` instead of the standard HTTP port (`80`).
A user or attacker accesses the server, generating traffic from port `8080`.
The rule detects this traffic and generates an alert with the message:
`"HTTP Traffic on common Non-Standard Port Detected"`.


- **Rule 3** 
```
alert tcp any 8000:9000 -> any any (msg:"HTTP on Non-Standard Port Payload contains executable"; file_data; content:"|4D 5A|"; sid:1000004; rev:4;)
```
### What This Rule Detects
This rule identifies HTTP traffic on non-standard ports (8000 to 9000) where the payload contains a Windows executable file (indicated by the `4D 5A` magic bytes). This could be an attempt to:
- Transfer a malicious executable (e.g., malware, trojans) over HTTP.
- Deliver a payload for an exploit or compromise.

### Example Scenario
- A web server is running on port `8080` and serves a malicious `.exe` file.
- A client downloads the file, generating HTTP traffic containing the executable in its payload.
- The rule inspects the HTTP payload and detects the `4D 5A` magic bytes.
- Snort generates an alert with the message:
`"HTTP on Non-Standard Port Payload contains executable"`.

- **Rule 4** 
```
alert tcp any any <> any 80 (msg:"HTTP Traffic Detected"; sid:1000005; rev:5;)
```
### What This Rule Detects
- The rule detects **any TCP traffic involving port 80**, which is the standard port for HTTP.
- It does not analyze the payload or check for specific HTTP characteristics.
- The rule is generic and will trigger on any bidirectional traffic involving port 80.

### Example Scenario
- A client sends an HTTP request to a web server on port `80`.
- The web server responds with an HTTP response.
- This bidirectional traffic matches the rule, and Snort generates an alert with the message:
`"HTTP Traffic Detected"`.

## Activating Snort for Intrusion Detection and Prevention

### Configure Network Interfaces
Before starting Snort, shut down your **Ubuntu machine** and adjust its network settings:

1. Open the **VM Network Settings**.
2. Add a **second network interface**.
3. Set the new interface to the same **NAT Network** used in your lab.

![image](https://github.com/user-attachments/assets/51594814-03e1-468b-84b0-974c10721e87)

### Start Snort in Inline Mode 

Once your Ubuntu machine is back online, use the following command to activate Snort:
```
sudo snort -q -A console -i enp0s3:enp0s8 -c /etc/snort/snort.conf --daq afpacket -Q
```

### Command Breakdown:
- `-q` → Quiet mode (suppresses banner output).
- `-A console` → Displays alerts in the console.
- `-i enp0s3:enp0s8` → Specifies two interfaces for inline mode.
- `-c /etc/snort/snort.conf` → Loads the Snort configuration file.
- `--daq afpacket` → Uses the AFPacket DAQ module for packet handling.
- `-Q` → Enables inline mode for active intrusion prevention.

### Verify Snort is Running

To check if Snort is actively monitoring traffic, run:

```
sudo snort -T -c /etc/snort/snort.conf
```
If everything is set up correctly, Snort will initialize and start capturing network traffic.

# Sending Snort Logs to Splunk

This guide focuses on configuring Snort to send logs to Splunk, assuming both are already installed on the same system.

---

## 1. Configure Snort Logging
1. Ensure Snort logs are saved in a directory accessible by Splunk:
   - Default directory: `/var/log/snort/`

2. Confirm the log format is compatible with Splunk (e.g., plain text or syslog format).

---

## 2. Set Up Splunk to Monitor Snort Logs

1. **Access Splunk Web Interface:**
   Open a browser and navigate to `http://localhost:8000`.

2. **Create a Data Input:**
   - Go to `Settings > Data Inputs > Files & Directories`.
   - Add a new data input pointing to `/var/log/snort/`.

3. **Set Source Type:**
   - Choose `Network & Security > snort` as the source type.
   - Also, you can create a custom source type if you need it.

4. **Assign an Index:**
   - Specify an index (e.g., `snort_logs`).

![image](https://github.com/user-attachments/assets/059bc6cb-5bc7-488f-9c57-3936519b2c17)

---

## 3. Verify Logs in Splunk

1. Trigger Snort alerts by simulating network activity (e.g., pinging or scanning):
   ```bash
   sudo snort -q -l /var/log/snort/ -i [your interface] -A full -c /etc/snort/snort.conf
   ```

2. Check Splunk for indexed logs:
   - Go to `Search > Data Summary`.
   - Confirm logs are indexed under `snort_logs`.

3. Run a search query to view logs:
   ```spl
   index=snort_logs
   ```

---

## 4. Optional: Field Extraction and Parsing

1. Use Splunk's field extraction feature to parse Snort logs into structured fields:
   - Timestamp
   - Source IP
   - Destination IP
   - Alert message

2. Use regex to extract fields if needed manually.

---

By following these steps, Snort logs will be sent to Splunk for efficient analysis and monitoring.


---

# Writing Yara Rules

## YARA Rule for mimikatz

```yara
rule Detect_mimikatz {
     meta:
       description = "Detects Mimikatz executable"
       author = "Bryan"
        reference = "https://blog.gentlekiwi.com/Mimikatz"
        date = "2024-08-24"
  
    strings:
        $mz_magic = { 4D 5A } // 'MZ' header (magic bytes)
  
  condition:
       $mz_magic at 0 // 'MZ' must be at the beginning of the file
}
```

### Rule Highlights:
1. Metadata (**meta**):
- Provides a description, author, and reference for documentation.
2. Strings (**strings**):
- Includes the tool's name and URL.
- Adds specific commands or phrases commonly associated with Mimikatz, such as:
  - **$mz_header** (identifies a Windows PE file).
  - **$url** (URL of the creator).
3. Condition (**condition**):
- Triggers if any of the defined strings are found in the scanned file.

## YARA Rule for LaZagne.exe

```yara
rule Detect_lazagne {
    meta:
        description = "Detects LaZagne executable"
        author = "Bryan"
        date = "2025-01-17"
        reference = "https://github.com/AlessandroZ/LaZagne"

    strings:
        $name = "lazagne" nocase
        $url = "https://github.com/AlessandroZ/LaZagne" nocase
        $string1 = "Retrieve credentials from browsers"
        $string2 = "Dumping saved passwords"
        $string3 = "Extracting credentials from system"

    condition:
        any of ($name, $url, $string1, $string2, $string3)
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

## YARA Rule for Winpeas

```yara
rule Detect_winpeas {
    meta:
        description = "Detects winpeas executable or script"
        author = "Bryan"
        date = "2025-01-17"
        reference = "https://github.com/carlospolop/PEASS-ng"

    strings:
        $name = "winpeas" nocase
        $url = "https://github.com/carlospolop/PEASS-ng" nocase
        $string1 = "Checking Windows enumeration"
        $string2 = "Find interesting files"
        $string3 = "Checking for installed programs"

    condition:
        any of ($name, $url, $string1, $string2, $string3)
}
```

### Rule Highlights:
1. Metadata (**meta**):
- Provides a description, author, and reference for documentation.
2. Strings (**strings**):
- Combines tool-specific and functional strings for reliable detection:
  - **$name**: Matches the term "winpeas" in a case-insensitive manner (**nocase**).
  - **$url**: Detects references to the GitHub repository for PEASS-ng.
  - **$string1**, **$string2**, **$string3**: Captures descriptive strings commonly associated with WinPEAS functionality:
    - **"Checking Windows enumeration"**
    - **"Find interesting files"**
    - **"Checking for installed programs"**
3. Condition (**condition**):
- Triggers if any of the defined strings are found in the scanned file.
4. Case-Insensitive Matching:
- Strings like **$name** and **$url** are marked with **nocase** to detect variations in capitalization.

---

# LimaCharlie Detection & Response Rules with Yara

## Examples: [Detection & Response Rules Examples](https://docs.limacharlie.io/v2/docs/detection-and-response-examples)

## Step 1: Automate YARA Scans for Downloaded EXEs

### Rule: Automatically Scan Downloaded EXEs
1. Create a rule titled YARA Scan Downloaded EXE.

2. Add the following Detect block:


```
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


3. Add the following Respond block:


```
- action: report
  name: EXE dropped in Downloads directory
- action: task
  command: >-
    yara_scan hive://yara/lazagne hive://yara/winpeas
    hive://yara/mimikatz -f "{{ .event.FILE_PATH }}"
  investigation: Yara Scan Exe
  suppression:
    is_global: false
    keys:
      - '{{ .event.FILE_PATH }}'
      - Yara Scan Exe
    max_count: 1
    period: 1m
```



## Step 2: Automate YARA Scans for Processes Launched from Downloads

### Rule: Automatically Scan Launched Processes
1. Create a rule titled YARA Scan Process Launched from Downloads.

2. Add the following Detect block:


```
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


3. Add the following Respond block:

```
- action: report
  name: Execution from Downloads directory
- action: task
  command: >-
    yara_scan hive://yara/lazagne hive://yara/winpeas
    hive://yara/mimikatz -f "{{ .event.FILE_PATH }}"
  investigation: Yara Scan Process
  suppression:
    is_global: false
    keys:
      - '{{ .event.PROCESS_ID }}'
      - Yara Scan Process
    max_count: 1
    period: 1m
```



## Step 3: Test the Rules

### Simulate Download and Execution
1. Place the Mimikatz executable (mimikatz.exe) in the C:\Users\User\Downloads folder.

2. Move it to another location and back to trigger the NEW_DOCUMENT event using PowerShell or moving it manually:
- For example:
```
Move-Item -Path C:\Users\User\Downloads\mimikatz.exe -Destination C:\Users\User\Documents\mimikatz.exe
Move-Item -Path C:\Users\User\Documents\mimikatz.exe -Destination C:\Users\User\Downloads\mimikatz.exe
```


3. Launch the Mimikatz executable to trigger the NEW_PROCESS event:
- For example:
```
C:\Users\User\Downloads\mimikatz.exe
```


4. Verify detections in the Detections tab.

This approach ensures that the file and process activities involving Mimikatz are monitored and flagged automatically. Based on your specific use case, you can further refine the YARA rule or detection logic.

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
   ```
   index=Endpoint
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

### Now that we are done with the lab and preparing our defenses we are going to jump to the [Attack Simulation](https://github.com/A9u3ybaCyb3r/Cyber_Defense_Lab/tree/main/Attack%20Simulation).
