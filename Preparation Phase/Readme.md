# Preparation Phase

In the preparation phase, several key configurations are made:
- **Snort Rules**: Configured to detect potential threats, including:
  - Rule 1: Detects a reverse TCP connection on port 4444 to the Windows VM.
  - Rule 2: Monitors HTTP traffic on non-standard ports (8000 to 9000).
  - Rule 3: Checks for executable files in HTTP traffic looking for MZ headers.
  - Rule 4: Monitors standard HTTP traffic on port 80.
- **Lima Charlie**: It is integrated with a Windows workstation for advanced threat detection and response capabilities.
  - **YARA Rules**: Rules are written to detect executable files in the downloads directory.
- **Splunk Configuration**: Alerts are set up for detecting reverse TCP connections.
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

First, we are going to create a rule for testing pings.

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

Then we are going to create our rules for the lab.

```snort
alert tcp any 4444 -> 10.19.19.132 any (msg:"Reverse TCP connection detected"; sid:1000002; rev:2;)

alert tcp any 8000:9000 -> any any (msg:"HTTP Traffic on common Non-Standard Port Detected"; sid:1000003; rev:3;)

alert tcp any 8000:9000 -> any any (msg:"HTTP on Non-Standard Port Payload contains executable"; file_data; content:"|4D 5A|"; sid:1000004; rev:4;)

alert tcp any any <> any 80 (msg:"HTTP Traffic Detected"; sid:1000005; rev:5;)
```


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
rule MAL_Mimikatz_Win_exe_2024_08_24 {
  meta:
    description = "Detects Mimikatz executable"
    author = "Bryan"
    reference = "https://blog.gentlekiwi.com/Mimikatz"
    date = "2024-08-24"
  
  strings:
    $mz_header = "This program cannot be run in DOS mode"
    $url = "blog.gentlekiwi.com/Mimikatz"
  
  condition:
    $mz_header and $url
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

Examples: https://docs.limacharlie.io/v2/docs/detection-and-response-examples



---

# Downloading Forensic Tools on the Machine

## Installation and Setup
- Downloading FTK Imager:
Visit [Exterro's FTK Product Downloads](https://www.exterro.com/ftk-product-downloads/) to download the latest version. The website may require basic information and CAPTCHA verification.

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
