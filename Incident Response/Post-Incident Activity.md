# 📄 Post-Incident Activity

## 📚 Lessons Learned & Improvement

* **Monitoring effectiveness**: Evaluate whether detection tools, such as Splunk, Sysmon, YARA, Snort, or LimaCharlie, successfully identify the threat across all phases.
  In this case, Snort failed to detect the `.exe` download where the malicious file was hosted on a **Kali Linux machine**, despite all systems being on the same network.
  
* **Detection gaps**: The root cause of this failure was not due to a faulty rule set or misconfiguration, but a **lack of traffic visibility**. Snort can only inspect traffic that traverses the interface it monitors. Since traffic between the victim and the Kali server never passed through Ubuntu's Snort interface, the activity was invisible to Snort. This was confirmed by reproducing the test in a controlled NAT network and observing that detection occurred only when the traffic hit the monitored interface directly.
  * In other words, recreating the attack but using Metasploit on the Ubuntu machine, and the Ubuntu machine is acting as the attacker.

* **Response speed**: Evaluate how quickly the team identified the visibility issue and adjusted their detection scope accordingly. Detection through other tools (e.g., endpoint logs or proxy logs) may have partially mitigated this blind spot, but reliance on a single sensor (Snort) left a significant gap.

These insights must inform architectural adjustments, not just rule tuning. Ensure all critical paths are monitored, especially in segmented or virtualized environments. Use the findings to guide detection engineering and infrastructure review.

---

## 📃 Final Documentation

* Create a detailed **Incident Report** that documents:

  * Initial infection vector (e.g., phishing email)
  * Timeline of attacker activity and detection
  * Containment and eradication steps
  * Tools and techniques used for analysis and recovery
  * IOCs and TTPs observed
  * Root cause analysis of **Snort detection failure due to network visibility limitation**

* Conduct a **post-mortem meeting** with the team to:

  * Identify what went well
  * Pinpoint areas for improvement
  * Document and address monitoring blind spots
  * Update the Incident Response Plan (IRP)

---

## 🔹 Conclusion

Following the **NIST Incident Response Framework** ensures a structured and proactive approach to handling cybersecurity incidents. This incident revealed that **detection tool placement** is just as critical as the tool configuration itself. Even well-configured sensors like Snort can fail if they lack visibility into key traffic flows.

By conducting thorough post-incident analysis and adjusting both detection rules and infrastructure design, organizations can:

* Increase detection accuracy
* Eliminate visibility gaps
* Improve response time
* Enhance resilience against future threats

Every incident is an opportunity to harden defenses and elevate the organization’s cybersecurity posture.

