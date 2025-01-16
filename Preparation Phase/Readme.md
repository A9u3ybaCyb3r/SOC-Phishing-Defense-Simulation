# Preparation Phase

In the preparation phase, several key configurations are made:
- Snort Rules: Configured to detect potential threats, including:
  - Rule 1: Detects a reverse TCP connection on port 4444 to the Windows VM.
  - Rule 2: Monitors HTTP traffic on non-standard ports (8000 to 9000).
  - Rule 3: Checks for executable files in HTTP traffic looking for MZ headers.
  - Rule 4: Monitors standard HTTP traffic on port 80.
- Lima Charlie: Integrated with the Windows workstations and server VMs for advanced threat detection and response capabilities.
- YARA Rules: Rules are written to detect executable files in the downloads directory.
- Splunk Configuration: Alerts are set up for detecting reverse TCP connections.
- Forensic Tools: Tools like Kape, Registry Explorer, and FTK Imager are downloaded for forensic analysis.

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

The rule that we are going to write is going to be named exe for executables related to Mimikatz.


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

# Importing Yara Rules Logs into Splunk

## 1. Set Up Yara to Generate Logs
Configure Yara to log its findings to a specific directory:
```bash
yara -r /path/to/rules.yar /path/to/scan/ > /var/log/yara/yara.log
```

## 2. Install Splunk Universal Forwarder
Download and install the Splunk Universal Forwarder from [Splunk Universal Forwarder](https://www.splunk.com/en_us/download/universal-forwarder.html) if you have not done it.

## 3. Add Yara Log Directory to Splunk Forwarder
Use the Splunk Universal Forwarder to monitor the Yara log directory:
```bash
sudo ./splunk add monitor /var/log/yara
```

## 4. Configure Splunk Inputs
Edit the `inputs.conf` file to ensure the Yara logs are being indexed correctly:
```bash
sudo vim /opt/splunkforwarder/etc/system/local/inputs.conf
```
Add or modify the following lines:
```ini
[monitor:///var/log/yara]
index = main
sourcetype = yara_logs
```

## 5. Restart Splunk Forwarder
Restart the Splunk Universal Forwarder to apply the changes:
```bash
sudo ./splunk restart
```

## 6. Verify Logs in Splunk
Log in to the Splunk Web interface (`http://[your-IP]:8000`).
- Go to `Search` > `Data Summary` and check if the Yara logs are appearing under the specified index and sourcetype.

## 7. Create Dashboards or Alerts (Optional)
Once the Yara logs are in Splunk, you can create dashboards or alerts to visualize and respond to any threats detected by Yara.

---

# Integrate Sysmon to Splunk

## Setting Up Microsoft Sysmon for Splunk

## 1. Configure Sysmon to Collect Data
- Sysmon logs events in `Applications and Services Logs/Microsoft/Windows/Sysmon/Operational` or on a WEC server if using Windows Event Collection (WEC).
- **Prepare your Sysmon configuration file**:
  - Start with the `SwiftOnSecurity/sysmon-config` template.
  - Customize filtering rules to match your organization's needs.
  - Avoid using Sysmon without a custom config to prevent unnecessary event logs or limited event monitoring.

**Resources for Configuration**:
- Microsoft Sysmon documentation
- TrustedSec Sysmon Community Guide
- Olaf Hartong's sysmon-modular
- SwiftOnSecurity sysmon-config

## 2. Install the Splunk Add-on for Sysmon
1. **Download the Add-On**:
   - From [Splunkbase](https://splunkbase.splunk.com/app/5709/) or via the Splunk Web app browser.
2. **Decide Where to Install**:
   - Use the deployment tables for guidance.
3. **Follow Any Prerequisites**:
   - Check if there are specific steps required before installation.
4. **Complete Installation**:
   - Refer to the installation walkthroughs for specific deployment setups (single-instance, distributed, or Splunk Cloud).

## 3. Distributed Deployments
- **Install the Add-On on Various Components**:
  - **Search Heads**: Required for Sysmon knowledge management.
  - **Indexers**: Required.
  - **Forwarders** (Heavy/Universal): Install on monitored Windows endpoints or WEC for data collection.
  - **Splunk Cloud**: Compatible via Self Service App Install (SSAI).

**Compatibility Table**:
- Supported on Search Head Clusters, Indexer Clusters, and Deployment Servers.

## 4. Configure Inputs for the Splunk Add-on
- **Default Inputs**:
  - `WinEventLog://Microsoft-Windows-Sysmon/Operational` (enabled by default).
  - `WinEventLog://WEC-Sysmon` (needs to be enabled for WEC architecture).

**Steps for WEC Installation**:
1. Go to `Settings > Data Inputs > Remote event log collections`.
2. Enable 'WEC-Sysmon' log collection.
3. Ensure Sysmon events are collected in `WEC-Sysmon` log or modify `inputs.conf`.
4. If forwarding from WEC to its Sysmon channel, disable `WinEventLog://Microsoft-Windows-Sysmon/Operational` to prevent duplicate logs.


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
◇ Purpose: Rapid triage and extraction of artifacts from live systems.
◇ Download:
  ▪ Primary: [KAPE](https://s3.amazonaws.com/cyb-us-prd-kape/kape.zip)
  ▪ Alternate: [Kroll's KAPE Page](https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape)

### Steps to Use:
1. Download and extract KAPE.
2. Configure targets and modules for specific artifact extraction.
3. Run KAPE on live systems for rapid data collection.
