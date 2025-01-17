# Lab Setup

## Table of Contents
1. [Planning Phase](#planning-phase)
2. [Create a new NAT Network](#create-a-new-nat-network)
3. [Setting up Ubuntu Desktop](#setting-up-ubuntu-desktop)
4. [Installing Splunk on Ubuntu](#installing-splunk-on-ubuntu)
5. [Installing Snort](#installing-snort)
6. [Setting up Kali Linux](#setting-up-kali-linux)
7. [Setting up a Small Active Directory](#setting-up-a-small-active-directory)
8. [Installing Splunk Forwarder](#installing-splunk-forwarder)
9. [Installing LimaCharlie](#installing-limacharlie)
	- [Deploying Endpoint Agents](#deploying-endpoint-agents) 
10. [Installing Yara on Windows](#installing-yara-on-windows)

---

## Planning Phase

First, we build the network architecture for the lab environment using [Draw.io](https://www.drawio.com/). This includes creating a detailed network diagram outlining the Active Directory Security Lab's structure, components, and connections. The diagram helps visualize how different elements interact, ensuring a well-organized setup for testing and security exercises.

- [Network Diagram](https://github.com/A9u3ybaCyb3r/Adaptive-Threat-Detection-and-Incident-Response-Lab/blob/main/Lab%20Setup%20Guide/ATDIR%20Lab%20Network%20Diagram.drawio.pdf)


## Creating a New NAT Network in VirtualBox

1. Open VirtualBox and go to **File > Tools > Network Manager**.

   ![image](https://github.com/user-attachments/assets/ec55021a-a04e-43d4-9d00-97e9e2fb3717)

2. In the **Network Manager**, select the **NAT Network** tab and click **Create** to create a new network.

   ![image](https://github.com/user-attachments/assets/440ede8a-f2be-4438-9d5c-3e2f7cfc3101)

3. Configure the network by setting your preferred **name** and **IP address range**.

   ![image](https://github.com/user-attachments/assets/8565b6fa-bb0b-498b-8d4c-ee3aded21032)

---

## Setting up Ubuntu Desktop

### Download the ISO File

[Download Ubuntu Desktop ISO](https://ubuntu.com/download/desktop)

### Create the Ubuntu Machine

1. Create a virtual machine.

   ![image](https://github.com/user-attachments/assets/c1fb78f6-e41d-4b8a-aa85-61003cec5ece)

2. Increase the RAM.

   ![image](https://github.com/user-attachments/assets/3e96eb97-22e1-4768-b1f6-fc5cfccd9123)

3. Increase the storage.

   ![image](https://github.com/user-attachments/assets/8cc68869-cbdf-46cb-a230-f04a27029d6d)

4. Set your network to **NAT Network**, and choose the name of the network that you created, then click **OK**.

   ![image](https://github.com/user-attachments/assets/1c22e291-17bb-4247-985f-dc98c2fdad6e)

### Installing Ubuntu Desktop

1. Hit **Start** to turn on the machine.

   ![image](https://github.com/user-attachments/assets/69a5dbdf-5af8-4cba-ae86-e9661c273662)

2. Hit **ENTER** on **Try or Install Ubuntu**.

   ![image](https://github.com/user-attachments/assets/f0762659-8f0e-4380-bfad-4236a95fd5d1)

3. Choose your **Language**.

   ![image](https://github.com/user-attachments/assets/3d4084f9-e655-49f1-b5bc-88bba873c63b)

4. Hit **Next**.

   ![image](https://github.com/user-attachments/assets/0b8d9dda-803a-42d5-9531-5ea8e2fb0daa)

5. Choose your **Keyboard Language**.

   ![image](https://github.com/user-attachments/assets/59893904-4886-4970-b923-acd221d8890e)

6. Hit **Next**.

   ![image](https://github.com/user-attachments/assets/caea4edb-8adf-4cf0-8697-d8f9512bb152)

7. Install Ubuntu and hit **Next**.

   ![image](https://github.com/user-attachments/assets/7d4266ef-95f3-44ca-8472-b6d3b428af81)

8. Hit **Next**.

   ![image](https://github.com/user-attachments/assets/9e9c120b-7281-4462-bb23-91e506f42a28)

9. Hit **Next**.

   ![image](https://github.com/user-attachments/assets/b2e84545-b8e0-4563-a535-957a6c96c79c)

10. Hit **Next**.

    ![image](https://github.com/user-attachments/assets/f99918f9-f678-4618-874f-59644379867e)

11. Hit **Next**.

    ![image](https://github.com/user-attachments/assets/fa2b1daa-5c6b-4678-b779-b58ea683562a)

12. Create your account.

    ![image](https://github.com/user-attachments/assets/dbb70d73-3c75-44a6-b3e4-03c6a8ed068c)

13. Choose your time zone.

    ![image](https://github.com/user-attachments/assets/7164ebbb-1967-46ce-8016-0b580ddba58d)

14. Hit **Install** and wait for the installation to complete.

    ![image](https://github.com/user-attachments/assets/0387d603-cf67-4d5f-b093-c8c7c23fe0ad)

15. Hit **Restart** and log in to the machine with your profile.

    ![image](https://github.com/user-attachments/assets/b7d28532-c722-4c24-9c90-ed6efcfde3b1)

16. Update system packages using the command: 

    ```bash
    sudo apt update
    ```

    ![image](https://github.com/user-attachments/assets/b3777a70-67a7-4879-89ee-5448b82363dc)

17. Install required packages using the command:

    ```bash
    sudo apt install bzip2 tar gcc make perl git
    ```

    ![image](https://github.com/user-attachments/assets/f0fd8c7d-550a-4b56-b014-7a4386c0818c)

18. Install the generic kernel headers using the command:

    ```bash
    sudo apt install linux-headers-generic
    ```

    ![image](https://github.com/user-attachments/assets/2e92508d-8e3d-4ef7-9fd5-b59693e8c0e6)

19. Install the system-specific kernel headers using the command:

    ```bash
    sudo apt install linux-headers-$(uname -r)
    ```

    ![image](https://github.com/user-attachments/assets/2b93e0dd-f7f9-4f0d-b6b2-804ad9003573)

20. Install Guest Additions on the machine.

    ![image](https://github.com/user-attachments/assets/5ef60e06-c2e3-4a0b-a5d2-88db608a929c)

21. Open a terminal on the disk that was just added.

    ![image](https://github.com/user-attachments/assets/967d8a4b-7973-4216-bd24-9a3072fb3311)

22. Run the VirtualBox additions.

    ![image](https://github.com/user-attachments/assets/7a3d48c2-1009-4457-bf5b-aaad289761d6)

### Setting an IP Address to the Machine

1. Open a terminal and run the command: 

    ```bash
    ip a

You can view the current IP of the machine.

![image](https://github.com/user-attachments/assets/9a659493-91b2-40b3-8e72-201f6522a7af)

2. Go to the network settings of the machine.

   ![image](https://github.com/user-attachments/assets/2d9b0143-1c74-4a98-9465-5e42a2791d5b)

3. Click on the settings.

   ![image](https://github.com/user-attachments/assets/95176f40-0f24-480e-946a-b61ba95e36d6)

4. Go to **IPv4** and configure the IP, subnet, and gateway. Then hit **Apply**.

   ![image](https://github.com/user-attachments/assets/1c3aa72a-e5ad-4703-bbe8-12dbbf82a2ba)

5. Confirm the IP address using the command:

   ```bash
   ip a

![image](https://github.com/user-attachments/assets/b56054d4-b4ae-430e-8cf0-5d13052231f4)

---

## Installing Splunk on Ubuntu

### Download Splunk Enterprise

1. Go to [Splunk's download page](https://www.splunk.com/en_us/download.html).
2. Log in and download the Splunk Enterprise version.

   ![image](https://github.com/user-attachments/assets/3bfd482a-7018-4085-8285-9fddaa2efa7f)

3. Grab the Linux `.tgz` version of Splunk.

   ![image](https://github.com/user-attachments/assets/213e9d53-a073-46fa-a903-2673b09b2b03)

### Install Splunk on Ubuntu

1. Open a terminal and navigate to the Downloads folder. Run the following command to extract the Splunk archive:

   ```bash
   sudo tar xvzf splunk-file.tgz -C /opt

![image](https://github.com/user-attachments/assets/1647559c-cd30-4931-a285-bd8185e2b0ca)

2. Change to the Splunk directory:

   ```bash
   cd /opt/splunk/bin

![image](https://github.com/user-attachments/assets/5267939f-0a7b-4e22-a306-8b1d6978ad63)

![image](https://github.com/user-attachments/assets/0dd806ab-e1bd-4de4-bb6c-3e98f04d04d4)

3. Start Splunk and accept the license:

   ```bash
   sudo ./splunk start --accept-license

![image](https://github.com/user-attachments/assets/ecbe0a05-e233-4292-9725-a63e8a3dc700)

4. You will be prompted to create a username and password for Splunk.

![image](https://github.com/user-attachments/assets/3b6cec53-95f2-4b7b-b963-87c7d916b1a3)

### Access the Splunk Web Interface

1. Open a web browser and navigate to one of the following URLs to access the Splunk web interface:

- `http://localhost:8000`
- `http://<your-ubuntu-ip>:8000` (if accessing from another machine)

![image](https://github.com/user-attachments/assets/9a7ac6a4-87eb-44d3-826e-69d271bda6bd)

2. To access the web interface from another machine, use the IP address of your Ubuntu server.

![image](https://github.com/user-attachments/assets/b7600173-eff5-4b40-bbf9-588d53e2a6b9)

3. Log in using the credentials you created during installation.

![image](https://github.com/user-attachments/assets/37b467ee-f995-458c-bbb4-b520bd39fe61)

![image](https://github.com/user-attachments/assets/c376e027-79b0-4898-9cca-f6362db9f9f4)

4. After logging in, you should see the Splunk dashboard.

![image](https://github.com/user-attachments/assets/9ca05a5d-2008-4f18-8289-9f4516b20888)

5. To have Splunk start automatically when the machine boots, run:

   ```bash
   sudo ./splunk enable boot-start

![image](https://github.com/user-attachments/assets/2e1ced1f-1e41-4a01-8d79-dc6b6865dec6)

### Managing Splunk on Your Lab Machine

1. To stop the Splunk service, use:

   ```bash
   sudo /opt/splunk/bin/splunk stop

2. To disable Splunk from starting automatically at boot:

   ```bash
   sudo systemctl disable splunk

3. If needed, you can re-enable it later with:

   ```bash
   sudo systemctl enable splunk

---

## Installing Snort

1. Open a terminal and run:

	```bash
	sudo apt install snort

- Enter your password if prompted.

- During installation, Snort will ask for the local network address range. You can find this information using:

	```bash
	ifconfig

- Note your IP address and subnet mask. For example, if your IP is `192.168.1.4` and subnet mask is `255.255.255.0`, the network range is `192.168.1.0/24`.

2. Verify the installed version:

	```bash
	snort --version

3. Directory and Files Overview

- Configuration File: Located at `/etc/snort/snort.conf`. This file controls Snort's settings, including network variables and rules.

- Rules Directory: `/etc/snort/rules/` contains predefined rule files for detecting malicious activity.

4. Before making changes:

	```bash
	sudo cp /etc/snort/snort.conf /etc/snort/snort.conf.bak

### Editing Configuration

1. Open the configuration file:

	```bash
	sudo nano /etc/snort/snort.conf

2. Set Network Variables:

- `HOME_NET`: Defines the monitored subnet. For example:

	```bash
	var HOME_NET 192.168.1.0/24

- `EXTERNAL_NET`: Defines the external network. Use:

	```bash
	var EXTERNAL_NET any

- Rule Configuration: Locate the rules section and ensure it points to your rule files:

	```bash
	include $RULE_PATH/local.rules
	include $RULE_PATH/backdoor.rules

### Testing Configuration:

1. Validate configuration changes using:

	```bash
	sudo snort -T -c /etc/snort/snort.conf

- A successful test ensures that changes don't introduce errors.

2. Practical Usage:

- Sniffer Mode:

	```bash
	sudo snort -i <interface>

3. Displays captured packet headers.

- Packet Logger Mode: Stores packets in files for analysis.

- IDS/IPS Mode: Implements rule-based monitoring and prevention.

---

## Setting up Kali Linux

### Downloading Kali Linux Virtual Machine Image

1. Go to [Kali's official download page](https://kali.org/get-kali/).
2. Click on **Virtual Machines** and download the 64-bit version for VirtualBox.

   ![image](https://github.com/user-attachments/assets/ae2d558e-57a4-4d1a-8576-5ad25de659ec)
   
   ![image](https://github.com/user-attachments/assets/6430026d-9ca1-46db-9dd6-98e6d758617c)

### Importing Kali Linux into VirtualBox

1. After downloading, extract the `.ova` file.
2. Open VirtualBox, click **Add**, and select the `.vbox` extension file from the extracted contents.

   ![image](https://github.com/user-attachments/assets/37ef160d-c250-4151-80df-bdfb038f063c)
   
   ![image](https://github.com/user-attachments/assets/5cf67d2e-ebd6-4c6e-ab83-f49f87a27b82)

### Configuring Network Settings

1. Right-click on the Kali Linux machine in VirtualBox, then select **Settings > Network**.

   ![image](https://github.com/user-attachments/assets/465b1135-d2b9-4e79-aa75-f6eb9f315ed1)

2. Change the network adapter to the **NAT Network** that you created.

   ![image](https://github.com/user-attachments/assets/13a03bdb-84e5-4cad-bac3-aa89af5adb77)

### Adjusting System Resources

1. To allocate more RAM, go to **Settings > System > Motherboard**. Increase the RAM based on your system’s resources (e.g., 8GB for resource-intensive tools).

   ![image](https://github.com/user-attachments/assets/9cf482b6-64c7-48be-8248-fe25ad5868eb)

### Starting Kali Linux

1. Click **OK** to save the settings, then start the machine.
2. Login using the default credentials: `kali` for both the username and password.

   ![image](https://github.com/user-attachments/assets/919a0fe4-12fe-4847-acad-0180f51a77b8)

---

## Setting up a Small Active Directory

### Download the ISO

### Step 1: Visit Microsoft Evaluation Center
1. Go to Google and search for "Microsoft Evaluation Center."
   - Official link: [Microsoft Evaluation Center](https://www.microsoft.com/en-us/evalcenter)
2. Open the official Microsoft Evaluation Center page from the search results.

### Step 2: Browse Available Software
- The Evaluation Center offers trial versions of Windows, Windows Server, SQL Server, and more.
- For this lab, download **Windows 10 Enterprise** and **Windows Server 2022**.

### Step 3: Download Windows 10 Enterprise
1. Select **Windows 10 Enterprise** from the list.
2. Choose the **64-bit ISO** version for your region (e.g., United States).
3. Fill out the registration form (generic information is acceptable).
4. Click **Download Now** to start the download.

### Step 4: Download Windows Server 2022:
   1. Similarly, select **Windows Server 2022** and open the download page.
   2. Choose the **64-bit ISO** version.
   3. Complete the registration form, then click **Download Now** to begin.

### Step 5: Notes
- Note that these downloads are large.
- After 90 days, the OS may prompt for activation or start shutting down if inactive. Reboot as needed for testing.

---

## Steps for Domain Controller Setup

### 1. Create a New Virtual Machine
1. In VMware or VirtualBox, select **Create a New Virtual Machine**.
2. Choose the **Typical setup** option.
3. Browse for the Windows Server 2022 ISO file and select it.

### 2. Operating System Selection
- If **Windows Server 2022** isn’t listed, select **Windows Server 2016**. This won’t affect your setup.

### 3. Configure Disk Space
- Allocate at least **60 GB** of disk space.
- Select the option to **Split virtual disk into multiple files**.

### 4. Adjust Virtual Machine Settings
- Open **Edit Virtual Machine Settings**.
- Set memory to **4–8 GB** (8 GB recommended if available).
- Remove any floppy disk device if listed.

### 5. Power On and Install Windows Server
1. Power on the virtual machine.
2. Press any key to boot from the ISO.
3. Follow the installation prompts:
   - Select language and region (default options are fine).
   - Choose **Standard Evaluation Desktop Experience**.
   - Accept license terms.
   - Perform a **Custom installation** on Drive 0 (unallocated space).

### 6. Complete Initial Setup
- After installation, Windows will reboot.
- Set an administrator password (e.g., `P@$$w0rd!`).

### 7. Install VMware Tools (Optional)
1. In VMware, go to **VM > Install VMware Tools**.
2. Run the `setup64` file from the D drive.
3. Select the **Complete installation** option and reboot if prompted.

### 8. Rename the Computer
1. Go to **Start** > Search for **View your PC name**.
2. Click **Rename this PC** and name your domain controller (e.g., `Jarvis-DC`).
3. Restart the virtual machine.

### 9. Promote to Domain Controller
1. Open **Server Manager**.
2. Select **Manage > Add Roles and Features**.
3. In the wizard:
   - Choose **Role-based or feature-based installation**.
   - Select the server and add **Active Directory Domain Services (AD DS)**.
4. After installation, click **Promote this server to a domain controller**.
5. Select **Add a new forest** and enter a root domain name (e.g., `StarkTech.local`).
6. Set the Forest and Domain functional levels to 2016.
7. Set a Directory Services Restore Mode (DSRM) password.
8. Accept default NetBIOS and path settings.
9. Complete the installation and let the server reboot.

### 10. Install Active Directory Certificate Services (AD CS)
1. Add **Active Directory Certificate Services** via **Add Roles and Features**.
2. Install **Certification Authority** as an Enterprise and Root CA.
3. Create a new private key and set the validity period (e.g., 99 years).
4. Restart the server after configuration.

## Steps for Windows 10 Client Setup

### 1. Create New Virtual Machines
1. In VMware or VirtualBox, select **Create a New Virtual Machine**.
2. Use the Windows 10 ISO file.
3. Skip the product key and select **Windows 10 Enterprise** as the version.

### 2. Configure Virtual Machine Hardware
- Allocate **60 GB** of disk space.
- Remove the floppy disk drive.
- Set memory to **4–8 GB**.
- Use **NAT** for the network adapter.

### 3. Install Windows 10
1. Power on the VM and press a key to boot from the ISO.
2. Complete the setup:
   - Select language, region, and keyboard layout.
   - Perform a **Custom Install**.
   - Partition the drive and proceed.

### 4. Configure User Accounts
- For **IronMan**:
  - Username: `Tony`
  - Password: `Password1`
- Set security questions with generic answers (e.g., "Bob").

### 5. Finalize Setup
- Install VMware Tools for each VM.
- Rename the machines:
  - `IronMan` for Tony.
- Restart the machines.

## Setting Up Users, Groups, and Policies

### 1. Create Organizational Units (OUs)
1. Open **Active Directory Users and Computers**.
2. Right-click the domain root and create OUs for **Users** and **Groups**.

### 2. Create User Accounts
- **SQL Service Account**:
  - Username: `SQLService`
  - Password: `MyPassword123#`
- **Standard Users**:
  - Tony Stark: `tstark` / `Password1`

### 3. Configure SMB File Share
1. In **Server Manager**, go to **File and Storage Services > Shares**.
2. Create an SMB share named `Projects`.
3. Share path: `\\Jarvis-DC\Projects`.

### 4. Set up a Service Principal Name (SPN)
1. Open Command Prompt as Administrator.
2. Use the following command to set up an SPN:
   ```cmd
     setspn -a Jarvis-DC/SQLService.StarkTech.local:60111 StarkTech\SQLService
   ```
3. Verify the SPN by querying with:
 ```cmd
     setspn -T StarkTech.local -Q */*
   ```

### 5: Set a Static IP Address (Optional)
 1. Go to Network & Internet Settings > Change adapter options.
 2. Open Properties for the network adapter, and configure IPv4 settings:
    - IP Address: 10.19.19.250 (Static IP Address)
    - Subnet Mask: 255.255.255.0
    - Default Gateway: 10.19.19.2 (NAT Network Gateway)


## Joining Windows 10 Client to the Domain

1. Boot up the Domain Controller.
2. On the Windows 10 machine:
   - Configure Network Settings on Each Machine
     1. Open **Network and Sharing Center**:
     2. Go to **Change Adapter Settings**.
     3. Right-click on **Ethernet0** and choose **Properties**.
     4. Select **Internet Protocol Version 4 (TCP/IPv4)**, then **Properties**.
     5. Use the domain controller’s IP as the **DNS** server (e.g., 10.19.19.250).
     6. Save the settings.
   - Go to **Settings > Accounts > Access work or school**.
   - Select **Connect** and choose **Join this device to a local Active Directory domain**.
   - Enter the domain name (e.g., `StarkTech.local`).
   - Provide domain admin credentials.
4. Restart the machines to complete the domain join.

### Configure Local Users and Groups on Each Client Machine

1. Enable and Set Password for the Local Administrator Account:
-  Go to **Computer Management > Local Users and Groups > Users**.
-  Double-click on **Administrator**, set the password (**Password1!**) and enable the account.

2. Add Domain Users as Local Administrators:
- Go to **Computer Management > Local Users and Groups > Groups > Administrators**.
- Add **tstark** (**Tony Stark**) as a local administrator on **IronMan**.

### Enable Network Discovery
 - On each client, go to **Network & Sharing Center > Change advanced sharing settings**:
   - Turn **ON** **Network discovery and File and printer sharing**.
 

### Map the Shared Drive (Projects) on IronMan
 - Open File Explorer:
   - Go to **This PC > Map Network Drive**.
 
 - Set Drive Mapping:
   - Choose a drive letter (e.g., Z:).
   - Enter the path \\Jarvis-DC\Projects.
   - Select **Connect using different credentials**.
   - Use the Administrator account and password for authentication.
 
### Verify Access to Shared Drive
 ◇ Ensure the HackMe shared drive is accessible on IronMan.
---

With this setup, you have a functional domain controller and Windows 10 clients ready for further testing or configurations.

---

### Installing Splunk Forwarder

### Deployment Steps
1. **Configuring the Splunk Indexer to Receive Data**

	- Navigate to **Settings > Data > Forwarding and Receiving** in Splunk.

	- Under **Configure Receiving Data**, click **Add New** and specify the port for listening (default: 9997).

	- Save the configuration to prepare the indexer for receiving forwarded events.

2. **Installing the Splunk Universal Forwarder**
	- Download the Universal Forwarder on the Windows 11 machine from Splunk's official site: https://www.splunk.com/en_us/download/universal-forwarder.html
	- During installation:
		- Select **Security** and **System Logs** to forward.
		- Specify the Splunk server's IP address and port (default: 8089 for management and 9997 for telemetry).
		- Complete the installation.
4. **Configuring Firewall Rules**
	- Allow Splunk's necessary ports (8089 and 9997) in **Windows Defender Firewall** for both inbound and outbound rules.
	- Create rules under **Advanced Settings**:
		- **Inbound Rule**: Allow TCP ports 8089 and 9997.
		- **Outbound Rule**: Allow TCP ports 8089 and 9997.
		- Name the rules "Splunk Forwarder."
5. **Verifying Data Transmission**
	- In Splunk, go to **Apps > Search & Reporting**.
	- Click **Data Summary** and verify the host and event logs appear.
	- Run a basic query to confirm events are being indexed:

	```spl
	index=* | stats count by host, sourcetype


---

## Installing LimaCharlie

1. Create an Account:

- Visit LimaCharlie.io and sign up using an email or other authentication methods.

- Verify your email to proceed.

2. Set Up an Organization:

- Enter your organization’s name.

- Select a data residency region for storage compliance (e.g., Canada).

- Enable demo configuration for a pre-populated environment or choose a pre-made template (e.g., incident response).

   - In our case, we are going to leave the demo configuration with no pre-configurations

### Deploying Endpoint Agents

1. Define Logical Groupings with Installation Keys

- Navigate to the Installation Keys section in the LimaCharlie dashboard.

- Create installation keys based on endpoint categories. Examples:
   
   - Windows Lab Workstations: For Windows systems used in lab environments.
   
   - Linux Servers: For production or lab Linux servers.
   
   - Critical Infrastructure: For endpoints requiring log forwarding instead of direct agents.

- Use descriptive tags (e.g., ```workstations```, ```windows```, ```servers```) to simplify management and filtering.

2. Prepare Sensor Binaries

- Download the appropriate agent binary from the Sensor Download section. Ensure compatibility with the endpoint’s architecture and OS:
   
   - For Windows, download the ```Windows 64-bit``` executable.
   
   - For other systems (Linux, macOS, etc.), select the corresponding binary.

- Organize binaries for automated deployment to endpoints.

3. Centralized Deployment

- Integrate agent installation into endpoint provisioning pipelines:
   
   - Embed the sensor in baseline installation images for new endpoints.
   
   - Use configuration management tools (e.g., Ansible, SCCM) to push the agent to existing endpoints.

- Ensure administrative privileges on target endpoints for successful agent installation.

4. Agent Installation

- Deploy the agent using the installation key to link it with the corresponding logical group:

  1. Open a terminal or PowerShell as an administrator on the endpoint.

  2. Execute the downloaded agent binary with the -i option followed by the installation key:

      ```cmd
      ./sensor_binary_name.exe -i <installation_key>
			
   - Confirm successful installation by verifying the agent appears under the Sensors List in the LimaCharlie dashboard.

5. Validate Deployment

- Check the Sensors List to ensure endpoints are properly registered.

- Verify telemetry data collection and connectivity.

- Perform a functional test using built-in commands like ```netstat``` via the Console feature to confirm operational status.

6. Post-Deployment Configuration

- Utilize the metadata provided in the dashboard to configure policies and detection rules for each endpoint group.

- Use the Autoruns feature to inspect and address persistence mechanisms on deployed endpoints.

- Leverage the Console for remote command execution and endpoint management.

---

## Installing Yara on Windows

1. Download Yara:
- Visit the [Yara GitHub Releases page](https://github.com/VirusTotal/yara/releases/tag/v4.5.2) and download the latest Windows binaries.

2. Extract and Install:
- Extract the downloaded archive to a directory of your choice.
- Optionally, add the Yara executable to your system's PATH for easier access:
- Search for "Environment Variables" in the Windows search bar.
- Click "Environment Variables," then edit the "Path" variable under "System variables."
- Add the directory where you extracted Yara.

---
### Now that we are done with the Lab Setup let's go to the [Preparation Phase](https://github.com/A9u3ybaCyb3r/Adaptive-Threat-Detection-and-Incident-Response-Lab/tree/main/Preparation%20Phase) to configure alerts and integrate logs to Splunk.



