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



#### Installing Splunk on Ubuntu

## Building an Active Directory 

#### Installing Splunk Forwarder and Sysmon on the environment

## Setting up Kali Linux
