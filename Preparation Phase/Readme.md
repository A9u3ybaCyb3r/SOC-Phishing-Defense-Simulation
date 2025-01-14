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



# Integrate Yara logs to Splunk

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
