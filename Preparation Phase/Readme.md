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
