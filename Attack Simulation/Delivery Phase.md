# Phase 3: Delivery

## 🌟 Objective:
Deliver the malicious payload to the victim in a way that convinces them to execute it.

### Steps:
#### Hosting the Payload:
- The attacker hosts the payload using Python’s built-in HTTP server:
  ```bash
  python3 -m http.server 8088
  ```
- This makes the payload accessible for download via HTTP on port **8088**.

![image](https://github.com/user-attachments/assets/1c66b5c9-4f4c-4285-8f5a-d86b5a14c244)

### Command Explanation:

```
python3 -m http.server 8000
```

1. `python3` – Runs Python version 3.
2. `-m http.server` – Uses Python’s built-in web server module to start a temporary HTTP server.
3. `8000` – Specifies that the server should run on port 8000 (you can change this to any available port).

### Output of the Command:

  - `"Serving HTTP on 0.0.0.0 port 8000"` – The server is now running and accessible from any computer on the network.
  - `"http://0.0.0.0:8000/"` – You (or others on the network) can access it by typing http://your-ip:8000/ in a web browser.

### What This Means:

  - If you run this command in a folder, Python will share all the files in that folder over HTTP.
  - You can download files from this machine by visiting `http://your-ip:8000/` in a browser or using `wget` or `curl`.
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
2. Run the tool and follow the on-screen instructions.
3. Restart your computer to complete the update.
4. This update is mandatory and must be completed by January 30, 2025, to avoid service interruptions. Failure to comply may result in account suspension.

If you have any questions, please contact the IT Help Desk at helpdesk@borikenshield.com or call 1-800-123-4567.

Thank you for your prompt attention to this matter.

Best regards,
IT Support Team
Boriken Shield
```

![image](https://github.com/user-attachments/assets/41995845-6222-411f-9c5d-cceff97325a0)

- The body of the email contains a shortened URL (via a URL shortening service) to hide the actual HTTP link to the payload.
    - Use **URL Shortening** via [Bitly](https://app.bitly.com/Bp21hrdeijm/links) to obscure the destination and make the link appear more legitimate.
    - **Steps to Create a Shortened URL**:
        - Ensure your **Python HTTP Server** is running (as per the previous step) and open **Firefox**.
        - Visit `http://{your local machine IP}:8000` to access the payload.
        - **Right-click** the payload and select **Copy Link**.
       
        ![image](https://github.com/user-attachments/assets/f006f266-2f33-4bad-a03c-d92c6434114d)
       
        -  Paste the link in the **Destination bar** and click **Create your link**.

        ![image](https://github.com/user-attachments/assets/609b9635-e0ae-4093-892a-cbc903c350ab)

        - The result will be a **shortened URL** that hides the true destination.

        ![image](https://github.com/user-attachments/assets/5336073a-5b71-46d0-88e1-5feb09225061)

#### Sending the Phishing Email:
- The attacker sends the email using **Temp Mail** to the victim, making it appear more legitimate.

### Open both Emkei's Fake Mailer and Temp Mail on your Ubuntu machine. Then, send an email to the temporary mail you receive to download the *.eml* file for a phishing analysis. This is because we are using temporary emails.

### Click on the Source icon to download the .eml file

![image](https://github.com/user-attachments/assets/c145f18d-6821-4f98-a388-adcaac20a233)
