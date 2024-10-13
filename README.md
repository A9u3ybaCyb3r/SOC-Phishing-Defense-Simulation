# Active Directory Security Lab

## Objective

This lab aims to develop a comprehensive understanding of Active Directory security and threat detection. To achieve this, the lab will focus on several key areas: gaining hands-on experience with Splunk as an SIEM tool, utilizing Kali Linux for penetration testing and simulating real-world attack scenarios, leveraging LimaCharlie for endpoint detection and response (EDR), and developing skills in identifying and responding to common Active Directory security threats. 

### Skills Learned

- Virtualization: Installing and configuring VMware software, creating and managing virtual machines (VMs), allocating resources to VMs, and installing guest operating systems.
- Active Directory Fundamentals: Gain a solid understanding of how domain environments function within Active Directory.
- SIEM Implementation: Learn to set up and utilize Splunk as a Security Information and Event Management (SIEM) tool for collecting and analyzing security data.
- Log Management: Master ingesting security events into an SIEM system for efficient analysis.
- Threat Detection Techniques: Develop skills in identifying and responding to common Active Directory security threats, enhancing your ability to protect domain environments.
- Attack Simulation and Mitigation: Learn how to simulate common attacks on Active Directory environments and implement defense strategies using real-time telemetry and alerts from LimaCharlie and Splunk.
- Incident Response: Learn to respond to security incidents, identify attack vectors, and use SIEM/EDR data to quickly mitigate threats.
Endpoint Detection and Response (EDR): Develop expertise in using LimaCharlie to detect, monitor, and respond to endpoint security threats in real time.
- Network Traffic Analysis: Understand how to analyze network traffic and detect suspicious behavior or patterns that could indicate a security breach.

### Tools Used

- Virtualbox: A virtualization software platform used to create and manage virtual machines.
- Ubuntu Desktop: A free and open-source operating system based on the Linux kernel. It provides a user-friendly interface and a wide range of applications for personal and professional use.
- Active Directory: A Microsoft directory service that manages user accounts, computers, and other network resources.
- Splunk: A powerful SIEM platform for collecting, analyzing, and acting on machine data.
- Kali Linux: A popular penetration testing distribution containing a wide range of tools for vulnerability assessment and ethical hacking.
- Lima Charlie: A comprehensive security operations platform offering real-time telemetry, endpoint detection and response (EDR), and security monitoring capabilities.

## Lab Setup

### Network Diagram

[Network Diagram](https://github.com/A9u3ybaCyb3r/Active-Directory-Security-Lab/blob/main/NetworkDiagram-AD-Security-Lab.drawio.pdf)

### Links of iso files to download

Microsoft 2022 Server and Windows 10
- [Microsoft 2022 Server](https://info.microsoft.com/ww-landing-windows-server-2022.html)
- [Windows 10](https://info.microsoft.com/ww-landing-windows-10-enterprise.html)

**Fill out the form to get the iso files**

Kali Linux 
- [Kali](https://www.kali.org/get-kali/#kali-installer-images)

Ubuntu Desktop
- [Ubuntu](https://ubuntu.com/download/desktop)

## Create a new NAT Network

On Virtualbox go to File > Tools > Network Manager

![image](https://github.com/user-attachments/assets/ec55021a-a04e-43d4-9d00-97e9e2fb3717)

Go to NAT Network tab and hit Create to create a new network

![image](https://github.com/user-attachments/assets/440ede8a-f2be-4438-9d5c-3e2f7cfc3101)

Set up your name and IP address range

![image](https://github.com/user-attachments/assets/8565b6fa-bb0b-498b-8d4c-ee3aded21032)


## Setting up Ubuntu Desktop

### Create the Ubuntu Machine

Create a virtual machine

![image](https://github.com/user-attachments/assets/c1fb78f6-e41d-4b8a-aa85-61003cec5ece)

Increase the RAM

![image](https://github.com/user-attachments/assets/3e96eb97-22e1-4768-b1f6-fc5cfccd9123)

Increase the storage

![image](https://github.com/user-attachments/assets/8cc68869-cbdf-46cb-a230-f04a27029d6d)

Set your network to NAT Network and the name of the network that you created then hit OK

![image](https://github.com/user-attachments/assets/1c22e291-17bb-4247-985f-dc98c2fdad6e)


### Installing Ubuntu Desktop

Hit Start, to turn on the machine

![image](https://github.com/user-attachments/assets/69a5dbdf-5af8-4cba-ae86-e9661c273662)

Hit ENTER on Try or Install Ubuntu 

![image](https://github.com/user-attachments/assets/f0762659-8f0e-4380-bfad-4236a95fd5d1)

Choose your Language

![image](https://github.com/user-attachments/assets/3d4084f9-e655-49f1-b5bc-88bba873c63b)

Hit Next

![image](https://github.com/user-attachments/assets/0b8d9dda-803a-42d5-9531-5ea8e2fb0daa)

Choose your Keyboard Language

![image](https://github.com/user-attachments/assets/59893904-4886-4970-b923-acd221d8890e)

Hit Next

![image](https://github.com/user-attachments/assets/caea4edb-8adf-4cf0-8697-d8f9512bb152)

Install Ubuntu and hit Next

![image](https://github.com/user-attachments/assets/7d4266ef-95f3-44ca-8472-b6d3b428af81)

Hit Next

![image](https://github.com/user-attachments/assets/9e9c120b-7281-4462-bb23-91e506f42a28)

Hit Next

![image](https://github.com/user-attachments/assets/b2e84545-b8e0-4563-a535-957a6c96c79c)

Hit Next

![image](https://github.com/user-attachments/assets/f99918f9-f678-4618-874f-59644379867e)

Hit Next

![image](https://github.com/user-attachments/assets/fa2b1daa-5c6b-4678-b779-b58ea683562a)

Create your account

![image](https://github.com/user-attachments/assets/dbb70d73-3c75-44a6-b3e4-03c6a8ed068c)

Choose your time-zone

![image](https://github.com/user-attachments/assets/7164ebbb-1967-46ce-8016-0b580ddba58d)

Hit Install and wait for the installation to be completed

![image](https://github.com/user-attachments/assets/0387d603-cf67-4d5f-b093-c8c7c23fe0ad)

Hit Restart and then log in to the machine with your profile

![image](https://github.com/user-attachments/assets/b7d28532-c722-4c24-9c90-ed6efcfde3b1)

Update system packages, command: **sudo apt update**

![image](https://github.com/user-attachments/assets/b3777a70-67a7-4879-89ee-5448b82363dc)

Install required packages, command: **sudo apt install bzip2 tar gcc make perl git**

![image](https://github.com/user-attachments/assets/f0fd8c7d-550a-4b56-b014-7a4386c0818c)

Install the generic kernel headers, command: **sudo apt install linux-headers-generic**

![image](https://github.com/user-attachments/assets/2e92508d-8e3d-4ef7-9fd5-b59693e8c0e6)

Install our system-specific kernel headers, command: **sudo apt install linux-headers-$(uname -r)**

![image](https://github.com/user-attachments/assets/2b93e0dd-f7f9-4f0d-b6b2-804ad9003573)

Now install Guest additions on the machine

![image](https://github.com/user-attachments/assets/5ef60e06-c2e3-4a0b-a5d2-88db608a929c)

Open a terminal on the disk that was just added

![image](https://github.com/user-attachments/assets/967d8a4b-7973-4216-bd24-9a3072fb3311)

Run the VirtualBox additions

![image](https://github.com/user-attachments/assets/7a3d48c2-1009-4457-bf5b-aaad289761d6)

### Setting an IP to the machine

Open a terminal and write the command: **ip a**  you can see the IP that we have 

![image](https://github.com/user-attachments/assets/9a659493-91b2-40b3-8e72-201f6522a7af)

Go to the network settings of the machine

![image](https://github.com/user-attachments/assets/2d9b0143-1c74-4a98-9465-5e42a2791d5b)

Click on the settings

![image](https://github.com/user-attachments/assets/95176f40-0f24-480e-946a-b61ba95e36d6)

Go to IPv4 and fill in the contents with the IP that you want for your machine and subnet and gateway then hit Apply

![image](https://github.com/user-attachments/assets/1c3aa72a-e5ad-4703-bbe8-12dbbf82a2ba)

Confirm the IP with the command: **ip a**

![image](https://github.com/user-attachments/assets/b56054d4-b4ae-430e-8cf0-5d13052231f4)

### Installing Splunk on Ubuntu

Go to https://www.splunk.com/en_us/download.html log in and grab the Splunk Enterprise

![image](https://github.com/user-attachments/assets/3bfd482a-7018-4085-8285-9fddaa2efa7f)

Grab the Linux .tgz version of Splunk

![image](https://github.com/user-attachments/assets/213e9d53-a073-46fa-a903-2673b09b2b03)

Go to Downloads in the terminal and then run the command: **sudo tar xvzf (splunk file) -C /opt**

![image](https://github.com/user-attachments/assets/1647559c-cd30-4931-a285-bd8185e2b0ca)

After the download is done run this command: **cd /opt** and go to the /splunk/bin directory

![image](https://github.com/user-attachments/assets/5267939f-0a7b-4e22-a306-8b1d6978ad63)

![image](https://github.com/user-attachments/assets/0dd806ab-e1bd-4de4-bb6c-3e98f04d04d4)

Run Splunk with the command: **sudo ./splunk start --accept-license**

![image](https://github.com/user-attachments/assets/ecbe0a05-e233-4292-9725-a63e8a3dc700)

Create a username and password to use Splunk

![image](https://github.com/user-attachments/assets/3b6cec53-95f2-4b7b-b963-87c7d916b1a3)

Now we can go to the web server using one of these two links

![image](https://github.com/user-attachments/assets/9a7ac6a4-87eb-44d3-826e-69d271bda6bd)

If you want to access the web server with another machine use the IP address of Ubuntu

![image](https://github.com/user-attachments/assets/b7600173-eff5-4b40-bbf9-588d53e2a6b9)

Accessing the Splunk web server using another machine

![image](https://github.com/user-attachments/assets/37b467ee-f995-458c-bbb4-b520bd39fe61)

Use the credentials that you created earlier when installing Splunk to get access

![image](https://github.com/user-attachments/assets/c376e027-79b0-4898-9cca-f6362db9f9f4)

Now you are inside the Splunk web server

![image](https://github.com/user-attachments/assets/9ca05a5d-2008-4f18-8289-9f4516b20888)

You can also make Splunk start every time you turn on the machine with this command: **sudo ./splunk enable boot-start**

![image](https://github.com/user-attachments/assets/2e1ced1f-1e41-4a01-8d79-dc6b6865dec6)

## Building an Active Directory 

### Building Windows 2022 Server

Create a new machine

![image](https://github.com/user-attachments/assets/39d5f1c7-099b-4d70-9008-bf46342ae038)

Increase RAM

![image](https://github.com/user-attachments/assets/265e3851-dd5a-4432-8335-a10a0df949a4)

Increase the storage

![image](https://github.com/user-attachments/assets/c470a06a-986b-42c5-a4b7-28b4285d9b59)

Go to machine settings > System and uncheck the Floppy disk

![image](https://github.com/user-attachments/assets/b3347046-4cb9-484b-9333-5426fc4bd02e)

Go to Network and then choose NAT Network and the network that you created 

![image](https://github.com/user-attachments/assets/0e6decf0-cffe-4f67-a9b1-86cd671989da)

Turn on the machine and choose the Language and the keyboard language

![image](https://github.com/user-attachments/assets/36f48e3a-92d9-454f-b833-e349a657d813)

Hit Install now

![image](https://github.com/user-attachments/assets/cec36e91-e472-4d5e-984a-736a73f755f4)

Choose Windows 2022 Standard Evaluation (Desktop Experience)

![image](https://github.com/user-attachments/assets/ea7c6b0e-17a8-4b6a-a05f-cabe999d46c9)

Choose Custom

![image](https://github.com/user-attachments/assets/1cedd3ae-ee85-4363-b4f7-5ba27806438c)

Choose New and Apply and then hit OK. Hit Next and wait for the Installation to finish

![image](https://github.com/user-attachments/assets/a2dfa82b-9e67-4ad6-9bfd-d63955d9d438)

Create a password for your Administrator

![image](https://github.com/user-attachments/assets/6a3a7dbd-00ff-4d99-ac8b-40694925721d)

Log in and now you have built the machine

### Building the Windows 10 Machine

Create the machine

![image](https://github.com/user-attachments/assets/6ffad3c7-8d69-4829-896b-63e042afadc8)

Increase the RAM

![image](https://github.com/user-attachments/assets/df174513-71f3-44f4-afa9-b081a0831325)

Increase the storage

![image](https://github.com/user-attachments/assets/8cab0a3c-1604-45c9-a5e5-869544fb9153)

Go to machine settings > System and uncheck the Floppy disk

![image](https://github.com/user-attachments/assets/b3347046-4cb9-484b-9333-5426fc4bd02e)

Go to Network and then choose NAT Network and the network that you created 

![image](https://github.com/user-attachments/assets/0e6decf0-cffe-4f67-a9b1-86cd671989da)

Turn on the machine and choose the language and keyboard language

![image](https://github.com/user-attachments/assets/7d6bf863-59b8-4201-aa1c-775094ae506a)

Install now

![image](https://github.com/user-attachments/assets/27daa2c2-e2db-4d93-8dc6-df946b1e5c2e)

Choose Custom

![image](https://github.com/user-attachments/assets/1cedd3ae-ee85-4363-b4f7-5ba27806438c)

Choose New and Apply and then hit OK. Hit Next and wait for the Installation to finish

![image](https://github.com/user-attachments/assets/a2dfa82b-9e67-4ad6-9bfd-d63955d9d438)

Choose the language

![image](https://github.com/user-attachments/assets/5bb249ee-05b8-4ba2-b3ba-d5ff16113294)

Choose the keyboard language

![image](https://github.com/user-attachments/assets/0a3afc45-1131-4509-ad7e-0c6a7353fcaf)

Choose Domain Join Instead

![image](https://github.com/user-attachments/assets/de35fcfd-313c-4c19-921a-95bcc3dcad67)

Create a user

![image](https://github.com/user-attachments/assets/25192082-c4b0-48bc-a3f3-95d1eec498f3)

Set a password

![image](https://github.com/user-attachments/assets/c5377e43-c2db-42f4-a756-7d5b64c13a07)

Then answer the security questions, turn off everything, and lastly log into the machine

Repeat this step for the third machine

### Creating the Active Directory Domain

There are two ways to do this:

- Use this tool: https://github.com/Dewalt-arch/pimpmyadlab
  
- Do it manually following this video: https://youtu.be/VXxH4n684HE?si=gIwdJf221BlEpB2c

I will use the tool, go to the link https://github.com/Dewalt-arch/pimpmyadlab and follow the instructions

![image](https://github.com/user-attachments/assets/2ce769e4-304e-4e13-a7c0-b91d38f72a92)

![image](https://github.com/user-attachments/assets/857e8820-495d-445a-b9a4-804015b97e94)

After following the instructions log in with the credentials of the domain users and now you have built an Active Directory

## Installing Splunk  Universal Forwarder and Sysmon on the environment

On the three machines on the domain, we will install Splunk Universal Forwarder and Sysmon these are the links:

- Splunk Universal Forwarder: https://www.splunk.com/en_us/download/universal-forwarder.html

- Sysmon: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
  
### Installing Splunk Universal Forwarder

Download the 64-bit

![image](https://github.com/user-attachments/assets/af4584b6-2239-4361-8b04-d5c8e7286882)

Double-click on the file that you downloaded and check the box to agree with the License

![image](https://github.com/user-attachments/assets/912406a7-910c-46af-bf4c-7ec4dc5fb9e4)

For the username use admin and check the box to generate a random password

![image](https://github.com/user-attachments/assets/4b9c8c1d-6bf2-408a-923e-d71e4e998b5e)

Leave it like this because we do not have a deployment server

![image](https://github.com/user-attachments/assets/8b718979-7dde-4ee5-9914-a27cc1d51d9f)

The IP is going to be the Splunk machine that we just created

![image](https://github.com/user-attachments/assets/183fd850-f06c-4223-8532-bbdf2666c4c9)

Hit Install and wait for the installation to be done, then hit Finish

![image](https://github.com/user-attachments/assets/38bccafe-86b4-49a0-b07f-0bf59bdc6ea2)


### Installing Sysmon

Download Sysmon

![image](https://github.com/user-attachments/assets/f89e1eda-bd12-4a9a-916c-c6c41f8ab10e)

We also are going to use sysmon olaf config

![image](https://github.com/user-attachments/assets/7f5457e4-4ddd-4437-ab15-d86e7ce720a8)

We want this file

![image](https://github.com/user-attachments/assets/73407917-6b03-4c9f-8b5e-1646c85f7fec)

Click on Raw and Save as 

![image](https://github.com/user-attachments/assets/9b6b605c-3912-45f8-9fd9-abf09b99c643)

![image](https://github.com/user-attachments/assets/42d351e6-f7ce-411c-8bd6-470f56ae03dc)

![image](https://github.com/user-attachments/assets/5c8729e8-f735-411f-939d-fc5352796b94)

Extract the zip file 

![image](https://github.com/user-attachments/assets/d6ed30e4-4ae5-4560-b3bf-9c84008687c3)

Copy the path, open a Windows Powershell, and Run as an administrator

![image](https://github.com/user-attachments/assets/29b557f6-189c-46e0-a38e-914d775f5fda)

![image](https://github.com/user-attachments/assets/8b18a2a5-1a0b-483c-b3f2-d67590cfc069)

Change directory and run this command: **.\Sysmon64.exe -i ..\sysmonconfig.xml**

![image](https://github.com/user-attachments/assets/0bce0ef7-8f4f-4bd6-a7c7-5170763d42ef)

Hit Agree and it will start the installation

![image](https://github.com/user-attachments/assets/78ddda26-b3ea-4f94-af74-0c68d41f4910)

### Configuring the Splunk Universal Forwarder 

We need to instruct Splunk on what we want to be sent to the Splunk Server, so we need the inputs.conf

![image](https://github.com/user-attachments/assets/890f4719-c0f7-4ccc-8c88-9f7ce1284999)

Copy the file

![image](https://github.com/user-attachments/assets/4a496772-8c80-4444-ab40-7958a30e2ad4)

Then we go to the local file 

![image](https://github.com/user-attachments/assets/8ee079ed-3a6c-4218-8c32-ee5b2d915f00)

![image](https://github.com/user-attachments/assets/efe4a1b0-85ec-4947-8d8b-f25df4370b7f)

Then we open Notepad as administrator

![image](https://github.com/user-attachments/assets/8dc3129a-1b94-4846-8993-0e70ad250313)

Use this link: https://github.com/MyDFIR/Active-Directory-Project/blob/main/README.md to copy and paste the configuration that you need

![image](https://github.com/user-attachments/assets/39b1f1b5-a514-4fdd-8c87-5c2d1134d5b3)

This is so that all of the events including the Sysmon, can be forwarded to Splunk

Save the file in the local file of the Splunk Universal Forwarder

![image](https://github.com/user-attachments/assets/bada5383-6112-4eb3-92ae-78014c506a55)

Now we need to restart the Splunk Universal Forwarder and you need to do it every time you update the inputs.conf file

Go to Services and Run as administrator

![image](https://github.com/user-attachments/assets/6b89fe22-cd67-4746-87c5-c5d6ecba6895)

Look for Splunk Forwarder, make sure that it is logged on as a Local System, and then Restart the service

![image](https://github.com/user-attachments/assets/91e1a112-473a-4fe4-8177-2148d23093aa)

If it is not logged on as a Local System, double-click on it, go to Log On, and make sure that it is a Local System account

![image](https://github.com/user-attachments/assets/655c996f-b37b-44b3-86fa-b738c3792846)

Also, verify that Sysmon is running and it is logged on as a Local System

![image](https://github.com/user-attachments/assets/eae0a486-6c63-40a2-a3e4-05747f059d80)

Then we go into our Splunk web, log in, and go to Settings and Indexes

![image](https://github.com/user-attachments/assets/38a76459-6cc4-42f8-9f65-99e22a46b4c1)

Create a New Index

![image](https://github.com/user-attachments/assets/e5178808-a0d8-4221-99db-5058f41ec504)

Name it endpoint and save it

![image](https://github.com/user-attachments/assets/4324d381-fbd8-4118-afdc-9d1e2bcad5df)

Now we go to Settings and Forwarding and receiving

![image](https://github.com/user-attachments/assets/cb986d88-d0b2-44c3-90a8-81ca6f8d116e)

Go to Configure receiving

![image](https://github.com/user-attachments/assets/694b4939-d900-4d9a-a1cf-0bf41d410420)

Click on New Receiving Port

![image](https://github.com/user-attachments/assets/90bc70ab-f8c8-47d6-a949-62fdd816dcb8)

Write the receiving port 

![image](https://github.com/user-attachments/assets/9d531f94-78e1-4d75-a97c-d319896771b7)

Now we are done, do this process for the other machines and you will receive events that occur on those machines

To see the events go to APP > Search and Reporting 

![image](https://github.com/user-attachments/assets/9b22cdba-82a1-422b-a879-ea47ed65aefe)

Write index="endpoint" and hit search and you will see the machines and the events

![image](https://github.com/user-attachments/assets/afe24dbf-06fc-4321-b169-474fa3299991)


## Setting up Kali Linux

 Go to https://kali.org/get-kali/

   - Click on the image that says Virtual Machines and download the 64-bit version of Virtualbox.

      ![image](https://github.com/user-attachments/assets/ae2d558e-57a4-4d1a-8576-5ad25de659ec)
     
     ![image](https://github.com/user-attachments/assets/6430026d-9ca1-46db-9dd6-98e6d758617c)

 After downloading the file, extract it and hit the Add button on Virtualbox. 

![image](https://github.com/user-attachments/assets/37ef160d-c250-4151-80df-bdfb038f063c)

Then choose the .vbox extension file.

![image-38](https://github.com/user-attachments/assets/5cf67d2e-ebd6-4c6e-ab83-f49f87a27b82)

 Right-click the machine and choose the Network settings.

![cd25168f5bf7404cb6e4d5a8b84ca441](https://github.com/user-attachments/assets/465b1135-d2b9-4e79-aa75-f6eb9f315ed1)

Change the network settings to the NAT Network that you created

![image](https://github.com/user-attachments/assets/13a03bdb-84e5-4cad-bac3-aa89af5adb77)

Then increase your RAM depending on how much you need. Mine is 8GB RAM because of the tools that I use. You can do it on the machine settings. 

![image](https://github.com/user-attachments/assets/9cf482b6-64c7-48be-8248-fe25ad5868eb)

 Click OK and now you can start the machine. Use the default credentials of *kali:kali*.

![image](https://github.com/user-attachments/assets/919a0fe4-12fe-4847-acad-0180f51a77b8)

 To create a static IP, right-click on the Network Connection and hit Edit Connections

![image](https://github.com/user-attachments/assets/6760384a-e918-4589-8e5a-a73f0f78d0e8)

Double-click on the profile

![image](https://github.com/user-attachments/assets/02818c7a-224e-43a3-a4ce-247bb8e8076f)




