# Phase 3: Delivery

## 🌟 Objective:
Deliver the malicious payload to the victim in a way that convinces them to execute it.

### Steps:
#### Hosting the Payload:
- The attacker hosts the payload using Python’s built-in HTTP server:
  ```bash
  python3 -m http.server 8080
  ```
- This makes the payload accessible for download via HTTP on port **8088**.

![image](https://github.com/user-attachments/assets/cdbda6d0-356f-41c7-9682-c0025751f498)

### Command Explanation:

```
python3 -m http.server 8080
```

1. `python3` – Runs Python version 3.
2. `-m http.server` – Uses Python’s built-in web server module to start a temporary HTTP server.
3. `8080` – Specifies that the server should run on port 8080 (you can change this to any available port).

### Output of the Command:

  - `"Serving HTTP on 0.0.0.0 port 8080"` – The server is now running and accessible from any computer on the network.
  - `"http://0.0.0.0:8080/"` – You (or others on the network) can access it by typing `http://your-ip:8080/` in a web browser.

### What This Means:

  - If you run this command in a folder, Python will share all the files in that folder over HTTP.
  - You can download files from this machine by visiting `http://your-ip:8080/` in a browser or using `wget` or `curl`.
  - Useful for quick file sharing or setting up a local web server for testing.

#### Creating the Phishing Email:
- The attacker crafts a convincing email pretending to be from tech support.
- Use [Emkei's Fake Mailer](https://emkei.cz/) a tool that allows you to send emails with a forged sender address. This helps craft a **legitimate-looking email** for the target.

![image](https://github.com/user-attachments/assets/48236a67-3e18-43c9-b808-2f1b0ffcca06)

- The subject line is designed to create urgency:
  - `Urgent: Critical Security Update Required`
```
Subject: Urgent: Critical Security Update Required

Body:
Dear Bob,
We have identified a critical vulnerability in your system that requires immediate attention. This vulnerability could expose sensitive company data and compromise your account.

To resolve this issue, please download and install the Critical Security Update Tool by clicking the link below:

Download Security Update Tool [Link]

Instructions:

1. Click the link above to download the tool.
2. Run the tool (as administrator) and follow the on-screen instructions.
3. This update is mandatory to avoid service interruptions. Failure to comply may result in account suspension.

If you have any questions, please contact the IT Help Desk at helpdesk@borikenshield.com or call 1-800-123-4567.

Thank you for your prompt attention to this matter.

Best regards,
IT Support Team
Boriken Shield
```

![image](https://github.com/user-attachments/assets/7e074809-53fc-4daa-8e22-b54f818eaab5)

- The body of the email contains a shortened URL (via a URL shortening service) to hide the actual HTTP link to the payload.
    - Use **URL Shortening** via [Bitly](https://app.bitly.com/Bp21hrdeijm/links) to obscure the destination and make the link appear more legitimate.
    - **Steps to Create a Shortened URL**:
        - Please make sure your **Python HTTP Server** is running (as the previous step) and open **Firefox**.
        - Visit `http://{your local machine IP}:8080` to access the payload.
        - **Right-click** the payload and select **Copy Link**.
       
       ![image](https://github.com/user-attachments/assets/d470cdad-11f7-4623-9dd9-d482a6285304)
       
        -  Paste the link in the **Destination bar** and click **Create your link**.

       ![image](https://github.com/user-attachments/assets/63d48125-d3a0-4f9b-8952-70138169650f)

        - The result will be a **shortened URL** that hides the true destination.

        ![image](https://github.com/user-attachments/assets/42efe46a-856d-444a-a338-bf924b03de9b)

#### Sending the Phishing Email:
- The attacker sends the email to the victim using **Temp Mail**, making it appear more legitimate.

### Click on the Source icon to download the .eml file on your victim machine.

![image](https://github.com/user-attachments/assets/c145f18d-6821-4f98-a388-adcaac20a233)
