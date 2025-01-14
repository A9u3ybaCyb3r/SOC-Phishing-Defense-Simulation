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

We are going to use [Snort Rule Generator](https://anir0y.in/snort2-rulgen/) to make our rules.

First we are going to create a rule for testing pings.

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
alert tcp any 4444 -> 10.19.19.132 any (msg:"Reverse TCP connection detected"; sid:1000002; rev:2;)

alert tcp any 8000:9000 -> any any (msg:"HTTP Traffic on common Non-Standard Port Detected"; sid:1000003; rev:3;)

alert tcp any 8000:9000 -> any any (msg:"HTTP on Non-Standard Port Payload contains executable"; file_data; content:"|4D 5A|"; sid:1000004; rev:4;)

alert tcp any any <> any 80 (msg:"HTTP Traffic Detected"; sid:1000005; rev:5;)


## Integrate Snort logs to Splunk
### Adding Snort to Splunk
1. Install Snort App for Splunk:
- Navigate to **Apps** **>** **Find more Apps**.
- Search for ‘**Snort**’ and install the **"Snort Alert for Splunk"** app.
- After installation, you should see Snort listed on the left side of the Splunk interface.

2. Install Splunk’s Universal Forwarder:
- Download the 64-bit **.deb** package from Splunk Universal Forwarder.
- After installation, add your Splunk server for log forwarding:

	```bash
	sudo ./splunk add forward-server 45.56.114.54:9997

3. Configure Outputs:
- Navigate to the configuration directory:

	```bash
	cd /opt/splunkforwarder/etc/system/local


 - Open and verify `outputs.conf`:

	```bash
	sudo vim outputs.conf

- Ensure the correct IP address for your Splunk server is set.


Testing Snort
1. Run a Test with Snort:
- Use the following command to run Snort and check logs:

	```bash
	sudo snort -q -l /var/log/snort/ -i enp0s3 -A full -c /etc/snort/snort.conf


- The command options are:
	- `-q`: Quiet mode.
	- `-l`: Log directory.
	- `-i`: Network interface.
	- `-A`: Alert mode.
	- `-c`: Rules file.


2. Verify Logs:
- Check the logs in `/var/log/snort` to see pings from the attacker's PC.


### Adding Snort Logs to Splunk
1. Monitor Snort Alert Logs:
- Add the Snort alert log to the Splunk forwarder:

	```bash
	sudo ./splunk add monitor /var/log/snort/alert

2. Configure Inputs:
- Navigate to the `inputs.conf` file in the search app directory:

	```bash
	/opt/splunkforwarder/etc/apps/search


- Edit `inputs.conf` as needed (ensure you have root access).

3. Restart Splunk:
- Switch back to your user and restart Splunk:

	```bash
	sudo ./splunk restart

4. Verify Data in Splunk:
- Go to `http://[your-IP]:8000`, and click on **Search** > **Data Summary**.
- Confirm that your host and sources are correctly added.

### Final Snort Check
- Ensure Snort is running by executing:

	```bash
	sudo snort -q -l /var/log/snort -i enp0s3 -A full -c /etc/snort/snort.conf

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

# Integrate Sysmon, Windows System, and Security logs to Splunk


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
