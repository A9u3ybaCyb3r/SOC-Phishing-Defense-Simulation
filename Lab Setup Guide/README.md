# Lab Setup

This guide walks through the complete setup of a blue team cybersecurity lab environment using VirtualBox, Splunk, Snort, Sysmon, LimaCharlie, and more all within isolated VMs. Perfect for hands-on SOC simulation and incident response training.

## 📚 Quick Table of Contents

* [Planning Phase (Draw.io)](#planning-phase)
* [Installing VirtualBox](#installing-virtualbox)
* [Creating a NAT Network](#creating-a-new-nat-network-in-virtualbox)
* [Ubuntu Setup + Splunk](#setting-up-ubuntu-desktop)
* [Installing Snort](#installing-snort)
* [Installing Wireshark](#wireshark-installation)
* [Kali Linux Setup](#setting-up-kali-linux)
* [Windows 10 + Splunk Forwarder](#installing-windows-10)
* [LimaCharlie Deployment](#installing-limacharlie)
* [Installing Sysmon](#installing-sysmon)
* [Lab Setup Complete!](#lab-setup-complete!)

---

## Planning Phase

First, we build the network architecture for the lab environment using [Draw.io](https://www.drawio.com/). This includes creating a detailed network diagram outlining the lab's structure, components, and connections. The diagram helps visualize how different elements interact, ensuring a well-organized setup for testing and security exercises.

- [Network Diagram](https://github.com/A9u3ybaCyb3r/Cyber_Defense_Lab/blob/main/Lab%20Setup%20Guide/CyberDefense-Lab%20Network%20Diagram.drawio.pdf)

---

<details>
	
## Downloading Virtualbox

## **1. Open Internet Browser**
- Launch your preferred **web browser**.

### **Search for VirtualBox**
- You can either do a web search for **"VirtualBox download"** or directly navigate to the official website: [VirtualBox.org](https://www.virtualbox.org/).

### **Access the Download Page**
- Click on the **Download VirtualBox** link on the website.

![image](https://github.com/user-attachments/assets/8d970060-385f-471c-8010-5f4307e6e151)

### **Select the Appropriate Host Package**
- Identify your operating system (**Windows, macOS, or Linux**) and click on the corresponding download link.
- Example: Click on **Windows Host** if you are using Windows.


## **2. Download the Installer**
- The download will begin. Once it's completed, locate the installer file in your **Downloads folder**.

![image](https://github.com/user-attachments/assets/abd99c34-e215-452c-8981-d4ecf657202b)

### **Run the Installer**
- **Double-click** the installer file to run it.
- When prompted by the **User Account Control (UAC)**, click **Yes**.


## **3. Install Microsoft Visual C++ (if necessary)**
If you encounter an error indicating that **Microsoft Visual C++ 2019** is required, follow these steps:
- Search for **Microsoft Visual C++ 2019 Redistributable**.
- Go to the **official Microsoft link** and download the latest version (**click on x64 for a 64-bit system**).
- After downloading, **run the Visual C++ installer**.

![image](https://github.com/user-attachments/assets/fea04302-ed87-4364-849e-a5b0aa25cc9a)

![image](https://github.com/user-attachments/assets/f321cf6c-f4d2-4bec-88a2-14b90ad01672)

![image](https://github.com/user-attachments/assets/ee7bca59-73be-4c31-8b22-2c623bce0b07)

![image](https://github.com/user-attachments/assets/1f609d4c-5c34-42cf-ae48-5c60991a84dc)

![image](https://github.com/user-attachments/assets/da2bcb42-225f-4a37-ad5e-0147cb2f3938)


## **4. Re-run the VirtualBox Installer**
- Once **Visual C++ is installed**, double-click on the **VirtualBox installer** again to continue the installation.

![image](https://github.com/user-attachments/assets/ecf37b22-9eb4-404e-aeba-a414ab68f0a8)

### **Follow Installation Prompts**
- Accept the **default settings** throughout the installation process.
- When prompted about your **network interface**, acknowledge that it will temporarily reset.


## **5. Complete the Installation**
- Click on **Install** to start the installation.
- Once the installation is finished, click on **Finish** to exit the installer.

### **Launch VirtualBox**
- Upon finishing the installation, the **Oracle VM VirtualBox Manager** should open automatically.
- If it doesn't, you can find it in your **Start Menu**.

### **Start Building Virtual Machines**
- You are now ready to **create and manage virtual machines** using VirtualBox.

---

## Creating a New NAT Network in VirtualBox

1. Open VirtualBox and go to **File > Tools > Network Manager**.

   ![image](https://github.com/user-attachments/assets/ec55021a-a04e-43d4-9d00-97e9e2fb3717)

2. In the **Network Manager**, select the **NAT Network** tab and click **Create** to create a new network.

   ![image](https://github.com/user-attachments/assets/440ede8a-f2be-4438-9d5c-3e2f7cfc3101)

3. Configure the network by setting your preferred **name** and **IP address range**.

  ![image](https://github.com/user-attachments/assets/114eb586-d303-496f-ae88-78afd80ee9e3)

</details>

---

<details>
	
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
	```
	   
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
	```
	  
![image](https://github.com/user-attachments/assets/b56054d4-b4ae-430e-8cf0-5d13052231f4)

</details>
	
---

<details>
	
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
	```
	  
![image](https://github.com/user-attachments/assets/1647559c-cd30-4931-a285-bd8185e2b0ca)

2. Change to the Splunk directory:

   ```bash
   cd /opt/splunk/bin
	```
	  
![image](https://github.com/user-attachments/assets/5267939f-0a7b-4e22-a306-8b1d6978ad63)

![image](https://github.com/user-attachments/assets/0dd806ab-e1bd-4de4-bb6c-3e98f04d04d4)

3. Start Splunk and accept the license:

   ```bash
   sudo ./splunk start --accept-license
	```
	  
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
	```
	  
![image](https://github.com/user-attachments/assets/2e1ced1f-1e41-4a01-8d79-dc6b6865dec6)

### Managing Splunk on Your Lab Machine

1. To stop the Splunk service, use:

   ```bash
   sudo /opt/splunk/bin/splunk stop
	```
2. To disable Splunk from starting automatically at boot:

   ```bash
   sudo systemctl disable splunk
	```
3. If needed, you can re-enable it later with:

   ```bash
   sudo systemctl enable splunk
	```

</details>
	
---

<details>
	
## Installing Snort

1. Open a terminal and run:

	```bash
	sudo apt install snort
	```
- Enter your password if prompted.

- During installation, Snort will ask for the local network address range. You can find this information using:

	```bash
	ip a
	```

- Note your IP address and subnet mask. For example, if your IP is `192.168.1.4` and subnet mask is `255.255.255.0`, the network range is `192.168.1.0/24`.

2. Verify the installed version:

	```bash
	snort --version
	```
3. Directory and Files Overview

- Configuration File: Located at `/etc/snort/snort.conf`. This file controls Snort's settings, including network variables and rules.

- Rules Directory: `/etc/snort/rules/` contains predefined rule files for detecting malicious activity.

4. Before making changes:

	```bash
	sudo cp /etc/snort/snort.conf /etc/snort/snort.conf.bak
	```

### Editing Configuration

1. Open the configuration file:

	```bash
	sudo nano /etc/snort/snort.conf
	```
	
2. Set Network Variables:

- `HOME_NET`: Defines the monitored subnet. For example:

	```bash
	var HOME_NET 192.168.1.0/24
	```
	
- `EXTERNAL_NET`: Defines the external network. Use:

	```bash
	var EXTERNAL_NET any
	```
	
- Rule Configuration: Locate the rules section and ensure it points to your rule files:

	```bash
	include $RULE_PATH/local.rules
	```
	
![image](https://github.com/user-attachments/assets/ede4059d-18bf-4fef-b37e-c2ad1e11d8f3)

- **Comment out** (`#`) all of the rules except local rules. Since we are writing custom rules, we do not want the default rules to get in the way.


### Testing Configuration:

1. Validate configuration changes using:

	```bash
	sudo snort -T -c /etc/snort/snort.conf
	```
	
![image](https://github.com/user-attachments/assets/aadf9cf5-13b0-421d-8a76-f3f557726a6c)

- A successful test ensures that changes don't introduce errors.
- If we scroll up we can see that there are no rules

![image](https://github.com/user-attachments/assets/2ae21d69-fbae-45f8-9c88-26e1af79b3e8)


2. Practical Usage:

- Sniffer Mode:

	```bash
	sudo snort -i <interface>
	```
	
3. Displays captured packet headers.

- Packet Logger Mode: Stores packets in files for analysis.

- IDS/IPS Mode: Implements rule-based monitoring and prevention.

</details>
	
---

<details>
	
# Wireshark Installation

## Purpose

Wireshark is used for in-depth network traffic analysis and supports both live packet capture and offline analysis. Common use cases include:

- Analyzing suspicious PCAP files.

- Performing live incident response by capturing packets directly from compromised devices.

## Ubuntu Installation

1. Default Installation:
```
sudo apt install wireshark
```
- During installation, you will be prompted to configure whether non-root users can capture packets. Selecting "**No**" requires running Wireshark with `sudo`.

2. Latest Version Installation:

To install the latest stable version, add the official Wireshark PPA:
```
sudo add-apt-repository ppa:wireshark-dev/stable
sudo apt update
sudo apt install wireshark
```
Now you have Wireshark ready for network analysis. 

</details>

---

<details>
	
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

</details>
	
---

<details>
	
## Installing Windows 10

### **1. Download the Windows 10 ISO**
- Visit the [Windows Evaluation Center](https://www.microsoft.com/en-us/evalcenter/).
- Choose the **64-bit edition** and **English** as the language.
- Download the ISO file (approximately **5 GB** in size). This may take a while depending on your internet speed.

### **2. Create a New Virtual Machine in VirtualBox**
- Open **VirtualBox** and click **New** to create a new virtual machine (VM).
- Name the VM (e.g., `Bob-PC`).
- Set the **machine folder** to the folder where you stored your ISO file.
- Select the **ISO image** for the installation (the Windows 10 ISO you downloaded).
- Ensure **Skip Unattended Installation** is checked and click **Next**.

### **3. Configure VM Settings**
- **Memory:** Allocate RAM for the VM. It’s recommended to use **6–8 GB** of RAM if your physical machine supports it.
- **Virtual Hard Disk:** Create a new **dynamically allocated hard disk** with a default size of **50 GB** (this can be adjusted later).
- Review your settings and click **Finish**.

## **4. Start the VM**
- Click **Start** to boot up the VM. The system will load the Windows installation process.

## **5. Install Windows 10**
- **Language and Region:** Select your preferred language, time, and keyboard layout, then click **Next**.
- **Install Now:** Click **Install Now** to begin the installation process.
- **License Agreement:** Accept the Windows license terms.
- **Custom Installation:** Choose the **Custom installation** option to perform a clean install.
- **Drive Allocation:** Click **New** to create a partition on the virtual hard disk and click **Apply**. This will automatically create additional partitions necessary for the installation.
- Click **Next** to begin the installation. The process may take some time.

## **6. Complete the Initial Setup**
After the installation, Windows will prompt for some initial configuration:
- **Keyboard Layout:** Confirm the layout and click **Next**.
- **Sign-in:** Choose **Domain Join** and set up a local account (e.g., `Username: Bob, Password: Password1`).
- **Security Questions:** Provide answers to security questions (e.g., first pet, childhood nickname, birthplace).
- **Privacy Settings:** Disable unwanted privacy features like tracking and telemetry.
- **Cortana:** Choose **Not Now** when prompted about Cortana.

## **8. Enhance VM Usability**
- **Install Guest Additions:**
  - In the **VirtualBox menu**, go to **Devices > Insert Guest Additions CD Image**.
  - Open **This PC** and double-click the **VirtualBoxGuest Editions drive**.
  - Run the installer (`VBoxWindowsAdditions-x86_64.exe`) and follow the on-screen instructions.
  - After installation, reboot the VM.

## **9. Optimize VM Display**
- Once the system restarts, go to the **View** tab in VirtualBox and select **Full Screen Mode** for a better display experience.

## **10. Enable Shared Clipboard**
- In VirtualBox, go to **Devices > Shared Clipboard** and set it to **Bi-directional**.
- This allows you to **copy and paste** between the host and the VM.

## **11. Create a Secrets folder**
- Create a new folder on the Desktop and name it `Secrets`.
- Go to `Secrets` folder and create a new text document named `Secret Storage`
	- (Optional) open it with **Notepad** and write something inside the txt file and save it.
   
## **12. Take a Snapshot**
- To save the current state of your VM, go to **Machine > Take Snapshot** in VirtualBox.
- Name the snapshot (e.g., `Base-Install`) to preserve the clean installation state.

## **13. Ready for Use**
- Your **Windows 10 VM is now ready** for use.
- You can proceed with any additional configuration or software installation as needed.

---

### Installing Splunk Forwarder

### Deployment Steps
1. **Configuring the Splunk Indexer to Receive Data**

	- Navigate to **Settings > Data > Forwarding and Receiving** in Splunk.

	- Under **Configure Receiving Data**, click **Add New** and specify the port for listening (default: 9997).

	- Save the configuration to prepare the indexer for receiving forwarded events.

2. **Installing the Splunk Universal Forwarder**
	- Download the Universal Forwarder on the Windows 10 machine from Splunk's official site: https://www.splunk.com/en_us/download/universal-forwarder.html
	- During installation:
		- Accept the **Terms and Conditions** then choose **Next**.
  		- Use the same **username** and **password** that you used to create Splunk earlier.
    		- Skip the **Deployment Server**.
		- Specify the Splunk server's IP address and port (default: 9997 for telemetry) on the **Receiving Indexer**.
		- Complete the installation.
3. **Configuring Firewall Rules**
	- Allow Splunk's necessary ports (8089 and 9997) in **Windows Defender Firewall** for both inbound and outbound rules.
	- Create rules under **Advanced Settings**:
		- **Inbound Rule**: Allow TCP ports 8089 and 9997.
		- **Outbound Rule**: Allow TCP ports 8089 and 9997.
  		- **Allow the connection** on both of the rules.
    		- Use all of the profiles.
		- Name the rules "Splunk Forwarder."
4. **Verifying Data Transmission**
	- In Splunk, go to **Apps > Search & Reporting**.
	- Click **Data Summary** and verify the host and event logs appear.
	- Run a basic query to confirm events are being indexed:
	
	```spl
	index=* | stats count by host, sourcetype
	```

</details>
	
---

<details>
	
## Installing LimaCharlie

1. Create an Account:

- Visit LimaCharlie.io and sign up using an email or other authentication methods.

- Verify your email to proceed.

2. Set Up an Organization:

- Enter your organization’s name.

- Select a data residency region for storage compliance (e.g., Canada).

- Enable demo configuration for a pre-populated environment or choose a pre-made template (e.g., **Incident Response**).

![image](https://github.com/user-attachments/assets/cd238046-bd85-4cc5-b01c-67476542c7fb)


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
		```	

   - Confirm successful installation by verifying the agent appears under the Sensors List in the LimaCharlie dashboard.

5. Validate Deployment

- Check the Sensors List to ensure endpoints are properly registered.

- Verify telemetry data collection and connectivity.

- Perform a functional test using built-in commands like ```netstat``` via the Console feature to confirm operational status.

6. Post-Deployment Configuration

- Utilize the metadata provided in the dashboard to configure policies and detection rules for each endpoint group.

- Use the Autoruns feature to inspect and address persistence mechanisms on deployed endpoints.

- Leverage the Console for remote command execution and endpoint management.

</details>
	
---

<details>
	
## Installing Sysmon

### 1. Download Sysmon
Sysmon is available from the Microsoft Sysinternals website:
[https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

### 2. Obtain Configuration Files
Use community-supported configurations as a baseline for setup:

- [**SwiftOnSecurity's Sysmon Configuration**](https://github.com/SwiftOnSecurity/sysmon-config): A high-quality default configuration.

- [**Olaf Hartong's Sysmon Modular**](https://github.com/olafhartong/sysmon-modular): A modular and customizable approach.
  - **We will choose this one to send the logs to Splunk**.
  - Download the **sysmonconfig.xml** file

### 3. Install Sysmon

1. Extract the Sysmon executable from the downloaded package.
2. Run the installer with administrative privileges in PowerShell using a configuration file:

   ```powershell
   sysmon64.exe -i <config-file-path> -accepteula
   ```

   Replace `<config-file-path>` with the path to your chosen configuration file.

### 4. Verify Installation

1. **Check Running Services**:
   ```powershell
   net start
   ```

   Ensure the Sysmon service is listed as running.

2. **Confirm Sysmon Logs**:
   Open the Event Viewer and navigate to **Applications and Service Logs > Microsoft > Windows > Sysmon > Operational**
   - Verify that Sysmon is logging events as expected.

</details>
	
---

## ✅ Lab Setup Complete!  

➡️ Continue to [Preparation Phase »](https://github.com/A9u3ybaCyb3r/SOC-Phishing-Defense-Simulation/blob/main/Incident%20Response/Preparation.md)




