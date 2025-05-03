# 🛡️ Incident Response Phase

## 🎯 Objective:

Apply the **NIST Incident Response Framework** to detect, contain, eradicate, and recover from the simulated phishing attack — ensuring both system restoration and organizational resilience.

---

## 🔍 Overview: NIST Incident Response Framework

The **NIST Cybersecurity Framework** provides a standardized approach to incident handling through four critical stages:
**Preparation**, **Detection & Analysis**, **Containment, Eradication & Recovery**, and **Post-Incident Activity**.
It is designed to help organizations minimize damage, reduce recovery time, and strengthen defenses against future attacks.

---

## 📁 [Preparation](https://github.com/A9u3ybaCyb3r/Cyber_Defense_Lab/blob/main/Incident%20Response/Preparation.md)

Establish a strong foundation to proactively detect and respond to incidents.

### Key Activities:

* 🔧 **Deploy Monitoring Tools**: Set up SIEM (**Splunk**), IDS (**Snort**), and EDR (**LimaCharlie**) for threat visibility.
* 📏 **Define Detection Rules**: Create **URL-based**, **IOC-based**, and **behavior-based** detection mechanisms.
* 📊 **Baseline System Behavior**: Identify normal activity across the network and endpoints to detect anomalies.
* 🧑‍🏫 **Train SOC Analysts**: Conduct tabletop exercises and response simulations to build team readiness.

---

## 🧠 [Detection & Analysis](https://github.com/A9u3ybaCyb3r/Cyber_Defense_Lab/blob/main/Incident%20Response/Detection%20and%20Analysis.md)

Monitor the environment and investigate suspicious behavior to confirm and understand the incident.

### Key Activities:

* 📡 **Monitor Alerts and Logs**: Use Splunk and LimaCharlie to monitor host and network data in real time.
* 🚨 **Identify True Positives**: Validate alerts using correlation rules, threat intel, and log analysis.
* 🔬 **Analyze Scope & Impact**: Determine which systems are affected, what was compromised, and how deep the intrusion goes.
* 📝 **Document Findings**: Maintain detailed notes for containment and reporting purposes.

---

## 🔧 [Containment, Eradication & Recovery](https://github.com/A9u3ybaCyb3r/Cyber_Defense_Lab/blob/main/Incident%20Response/Containment%2C%20Eradication%2C%20and%20Recovery.md)

Act swiftly to isolate threats, remove malicious components, and restore safe operations.

### Key Activities:

* 🛑 **Containment**: Disconnect or quarantine compromised hosts to limit attacker movement.
* 🧹 **Eradication**: Remove malware (e.g., `update.exe`), delete malicious registry keys, and close exploited vulnerabilities.
* 💾 **Recovery**: Reimage affected machines or restore from known-good snapshots. Confirm that systems are clean and operational before reconnecting.

---

## 🔁 [Post-Incident Activity](https://github.com/A9u3ybaCyb3r/Cyber_Defense_Lab/blob/main/Incident%20Response/Post-Incident%20Activity.md)

Reflect, report, and reinforce the organization’s defenses.

### Key Activities:

* 📋 **Conduct a Post-Mortem**: Review the incident timeline, actions taken, and lessons learned.
* 🛠️ **Update Playbooks**: Revise detection rules, policies, and response workflows to address identified gaps.
* 👥 **Share Findings**: Inform stakeholders and teammates to improve awareness and coordination.
* 🧩 **Build Resilience**: Incorporate changes into training and architecture to prevent recurrence.

---

✅ **Incident Response Complete**
The organization has successfully detected, contained, and recovered from the attack — turning an intrusion into an opportunity for improvement.
