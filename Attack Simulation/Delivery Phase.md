# Delivery

## Objective:
Deliver the weaponized payload to the target via social engineering and email.

## Action:
1. Create a Spoofed Email Using [Emkei's Fake Mailer](https://emkei.cz/)

    Use **Emkei's Fake Mailer**, a tool that allows you to send emails with a forged sender address. This helps craft a **legitimate-looking email** for the target.

![image](https://github.com/user-attachments/assets/48236a67-3e18-43c9-b808-2f1b0ffcca06)

2. Include a Link to the Malicious Website

   The email will contain a link that points to a **malicious website** where the payload is hosted.

    - Use **URL Shortening** via [Bitly](https://app.bitly.com/Bp21hrdeijm/links) to obscure the destination and make the link appear more legitimate.

### Steps to Create a Shortened URL:

- Ensure your **Python HTTP Server** is running (as per the previous step) and open **Firefox**.
- Visit `http://{your local machine IP}:8000` to access the payload.
- **Right-click** the payload and select **Copy Link**.

![image](https://github.com/user-attachments/assets/f006f266-2f33-4bad-a03c-d92c6434114d)

- Paste the link in the **Destination bar** and click **Create your link**.

![image](https://github.com/user-attachments/assets/609b9635-e0ae-4093-892a-cbc903c350ab)

- The result will be a **shortened URL** that hides the true destination.

![image](https://github.com/user-attachments/assets/5336073a-5b71-46d0-88e1-5feb09225061)

3. Use Social Engineering to Convince the Target

    Craft a message that convinces the target to open the attachment or click the link. For example, use a sense of urgency with a message like:

    - “**Urgent: Please review the attached document** ”

4. Craft the Email to Appear Legitimate
Based on the information gathered during reconnaissance, craft the email to appear **trustworthy**. For instance, impersonate a service or entity the target uses. Here’s a sample email template:

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

5. Send the Spoofed Email to the Target’s Address
After crafting the email with the **malicious link** and **social engineering message**, send the email to the victim's email address, ensuring it appears legitimate and trustworthy.



### Open both Emkei's Fake Mailer and Temp Mail on your Ubuntu machine. Then, send an email to the temporary mail you receive to download the *.eml* file for a phishing analysis. This is because we are using temporary emails.

### Click on the Source icon to download the .eml file

![image](https://github.com/user-attachments/assets/c145f18d-6821-4f98-a388-adcaac20a233)
