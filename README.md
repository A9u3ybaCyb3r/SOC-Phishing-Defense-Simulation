# SOC Phishing Defense Simulation

## Objective:

The project aims to simulate a phishing attack in a controlled lab environment and demonstrate the full incident response lifecycle, from attack preparation and execution to threat detection, analysis, and mitigation, using tools like Splunk, Snort, Sysmon, and LimaCharlie. It follows the NIST Incident Response Plan and Cyber Kill Chain framework to provide hands-on experience in detecting, analyzing, and responding to cyber threats while identifying key Indicators of Compromise (IOCs) and improving security measures.

## Overview

The project follows the NIST Incident Response Plan for blue teaming and the Cyber Kill Chain for red teaming. The workflow consists of several phases:
1. **Preparation Phase**: Setting up defenses.
2. **Attacking Phase**: Simulating a cyber attack.
3. **Detection, Analysis, and Response Phases**: Handling the incident.
4. **Post-Incident Activities**: Discussing lessons learned and improvements.

## Attack Scenario

On a standalone Windows 10 machine, an attacker sends a phishing email containing a malicious payload disguised as a critical software update. The victim downloads and executes the payload, establishing a reverse TCP connection to the attacker’s machine using Metasploit. The attacker escalates privileges, creates a new user account, and compromises the machine, gaining admin access. Sensitive data is exfiltrated from the machine, and the attacker clears logs to erase traces of the attack.

## Skills Learned:

- **Intrusion Detection:** Configuring Snort IDS to identify and alert on network-based threats.
- **Endpoint Threat Monitoring and Response:** Using LimaCharlie EDR to detect and contain endpoint threats in real-time.
- **Security Information and Event Management (SIEM):** Setting up and managing Splunk SIEM for log analysis, alert configuration, and network anomaly tracking.
- **Incident Response:** Applying the NIST Incident Response Plan framework to handle each phase of cyber incidents, from detection through to remediation.
- **Threat Analysis:** Leveraging the MITRE ATT&CK Framework and Cyber Kill Chain to analyze attacker tactics, techniques, and procedures (TTPs).
- **Threat Simulation:** Creating realistic attack simulations, including phishing campaigns, reverse TCP sessions, and persistence tactics, for testing detection and response capabilities.
- **Blue Team Operations:** Building defensive security skills and applying them to monitor, detect, and respond to threats.
- **Network Traffic Analysis:** Gaining insights into network behavior, identifying suspicious patterns, and filtering malicious traffic.


## Tools Used in the Lab

This lab leverages various industry-standard tools and frameworks for comprehensive threat detection and incident response:

1. **Snort IDS** - Network intrusion detection system for real-time monitoring and alerting on suspicious network traffic.

2. **LimaCharlie EDR** - Endpoint Detection and Response platform providing continuous endpoint monitoring, threat detection, and response.

3. **Sysmon** -  Windows system service and device driver that monitors and logs critical system activity to the Windows Event Log

4. **Splunk SIEM** - Security Information and Event Management system for log analysis, alerting, and security incident management.

5. **Cyber Kill Chain** - A model that breaks down each phase of an attack, assisting in identifying and mitigating threats at various stages.

6. **Meterpreter** - A Metasploit payload used to simulate attacks, such as reverse shells, persistence tactics, and lateral movement.

7. **NIST Incident Response Plan** - Structured framework for managing each phase of incident response, from preparation to recovery.

Each tool is integral to achieving a practical and robust cybersecurity defense and incident response setup.

## Disclaimer

This project is intended solely for educational and research purposes in a controlled lab environment. All simulations, tools, and techniques demonstrated are designed to enhance knowledge in cybersecurity defense and incident response. **Do not deploy or execute any offensive security techniques or tools against systems you do not have explicit permission to test.**

Unauthorized access, testing, or modification of networks or systems is illegal and unethical. The project creator is not responsible for any misuse of the provided information or tools. Please adhere to legal and ethical guidelines when practicing cybersecurity skills.


