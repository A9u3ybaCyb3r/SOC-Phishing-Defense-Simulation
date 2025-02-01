# Delivery

### Objective: Deliver the weaponized payload to the target.

### Action:

1. Create a spoofed email using [Emkei's Fake Mailer](https://emkei.cz/) (a tool for sending emails with a forged sender address).

![image](https://github.com/user-attachments/assets/48236a67-3e18-43c9-b808-2f1b0ffcca06)

2. The email includes a link to a malicious website hosting the payload.
- We will do **URL Shortening** using [Bitly](https://app.bitly.com/Bp21hrdeijm/links) to obscure the true destinations.
- To do this we need to have our **Python HTTP Server** running, open **Firefox**, and then visit `http://{your local machine ip}:8000`.
- Look for the payload that you created, **Right-click**, and hit **Copy link**.
![image](https://github.com/user-attachments/assets/f006f266-2f33-4bad-a03c-d92c6434114d)

- Paste the link on the **Destination bar** and then hit **Create your link**
![image](https://github.com/user-attachments/assets/609b9635-e0ae-4093-892a-cbc903c350ab)

- This is the result.
![image](https://github.com/user-attachments/assets/5336073a-5b71-46d0-88e1-5feb09225061)


3. Use social engineering techniques to convince the target to open the attachment or click the link (e.g., "Urgent: Please review the attached document").

4. Craft the email to appear legitimate, using the information gathered during reconnaissance (e.g., impersonating a service the target uses).

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

5. Send the spoofed email to the target's email address.

### Open both Emkei's Fake Mailer and Temp Mail on your Ubuntu machine. Then, send an email to the temporary mail you receive to download the *.eml* file for a phishing analysis. This is because we are using temporary emails.
