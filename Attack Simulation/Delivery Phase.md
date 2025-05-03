# 📬 Delivery Phase

## 🎯 Objective

Deliver the malicious payload in a convincing, socially engineered email that persuades the victim to execute the file.

---

### 📡 Hosting the Payload

The attacker uses Python’s built-in web server to make the payload downloadable over HTTP:

```bash
python3 -m http.server 8080
```

📘 **Command Breakdown**

| Command Part     | Description                     |
| ---------------- | ------------------------------- |
| `python3`        | Launches Python version 3       |
| `-m http.server` | Starts a basic HTTP file server |
| `8080`           | Specifies the listening port    |

🔍 This shares all files in the current directory at:
`http://<attacker-ip>:8080/`

![HTTP server running](https://github.com/user-attachments/assets/cdbda6d0-356f-41c7-9682-c0025751f498)

---

### ✉️ Crafting the Phishing Email

The attacker uses [**Emkei's Fake Mailer**](https://emkei.cz/) to spoof a tech support email and embed a **shortened URL** linking to the payload.

📌 **Email Subject**:
`Urgent: Critical Security Update Required`

📨 **Email Body Preview**:

> Dear Bob,
>
> We have identified a critical vulnerability in your system that requires immediate attention. Please download and install the Critical Security Update Tool using the link below:
>
> 🔗 **[Download Security Update Tool](http://short.url/hide-payload-link)**
>
> Failure to comply may result in service disruptions.
>
> — *IT Support Team, Boriken Shield*

📷 Email Interface (Emkei’s Mailer):

![image](https://github.com/user-attachments/assets/48236a67-3e18-43c9-b808-2f1b0ffcca06)

📷 Final Email Preview:

![image](https://github.com/user-attachments/assets/d335d713-0573-42f7-94d8-37f7041a89f1)

![image](https://github.com/user-attachments/assets/7e074809-53fc-4daa-8e22-b54f818eaab5)

---

### 🔗 Creating a Shortened URL

To mask the true destination of the payload, the attacker uses [**Bitly**](https://bitly.com):

1. Ensure the Python HTTP server is running.
2. Right-click your payload in the browser and choose **Copy Link**.

   ![copy link](https://github.com/user-attachments/assets/d470cdad-11f7-4623-9dd9-d482a6285304)

3. Paste the link into Bitly and click **Create Link**.

   ![bitly](https://github.com/user-attachments/assets/63d48125-d3a0-4f9b-8952-70138169650f)

4. Use the generated **shortened link** in your phishing email.

    ![shortened url](https://github.com/user-attachments/assets/42efe46a-856d-444a-a338-bf924b03de9b)

---

### 📤 Sending the Email

The attacker sends the phishing message using **Temp Mail**, completing the delivery step without exposing a real identity.

📥 Once sent, you can download and inspect the `.eml` message on the victim’s machine:

![download .eml](https://github.com/user-attachments/assets/c145f18d-6821-4f98-a388-adcaac20a233)
