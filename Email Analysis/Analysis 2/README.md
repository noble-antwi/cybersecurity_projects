
# Security Event Report: Potential Phishing Attempt  

**Prepared by:** Noble Antwi (SOC Analyst, Global Logistics )
**Incident Reported by:** Emily Nguyen (Marketing Team Member)  
**Incident Type:** Potential Phishing Email  

---

## Incident Overview  

On May 12, 2024, Emily Nguyen, a marketing team member at Global Logistics, reported a suspicious email. The email claimed that a password change request had been initiated for her inactive Dropbox account and included a link to reset her password. Concerned about its authenticity, Emily forwarded the email to the security team for analysis. This report outlines the investigation conducted to determine the legitimacy of the email.  

---

## Investigation Details  

### **1. Full Date and Time of Email Delivery**  

---

**1. Full Date and Time of Email Delivery**  
The exact date and time when the email was delivered were extracted using two different methods to ensure accuracy:  

- **Method 1: Didier Stevens’ `eioc.py` script**  
  Didier Stevens’ Python script, `eioc.py`, was used to extract key metadata from the email file (`challenge2.eml`). This tool is commonly used for email analysis, providing a detailed breakdown of email headers, including delivery timestamps.  

  - **Command Executed:**  
  
    ``` bash

    python3 Tools/eioc.py Challenges/challenge2.eml
    ```  

  - **Output:**  
    The script output revealed the delivery timestamp as:  
    **Sun, 12 May 2024 04:10:52 +0000**  

    ![Didier Stevens Script](<File/Images/01 Runnins Python SCript.png>)  

  This output confirms that the email was received on May 12, 2024, at 4:10:52 AM UTC.  

- **Method 2: Online Tool - MXToolbox**  
  To cross-verify the timestamp, the email was analyzed using [MXToolbox](https://mxtoolbox.com). This tool allows for a detailed inspection of email headers, including delivery timing.  

  - **Output from MXToolbox:**  
    ![MXToolbox Output](image.png)  

  - **Explanation of Findings:**  
    MXToolbox corroborated the findings from `eioc.py`, confirming the delivery timestamp. The inclusion of multiple verification methods ensures the timestamp’s accuracy and reliability.  

---

Here is the expanded and professional version of each section:

---

### **2. Email Subject**  

The subject line of an email is a critical indicator of its purpose and intent. In this case, the subject line was determined by analyzing the email header through two methods:  

1. **Using Didier Stevens’ `eioc.py` Script:**  
   The `eioc.py` script parses email metadata and displays essential information such as the subject line. Upon running the script on the provided email file (`challenge2.eml`), the output clearly displayed the subject as:  
   **`Reset your Dropbox password`**  

2. **Manual Header Analysis via Text Editors:**  
   By opening the email file in a text editor such as Sublime Text and searching for the "Subject" field in the header section, the subject was confirmed to be:  
   **`Reset your Dropbox password`**  

This consistency between automated tools and manual analysis ensures the subject line's accuracy. It provides insights into the purpose of the email, indicating a password reset request for a Dropbox account.

---

### **3. Email Recipient**  

Identifying the intended recipient of the email is crucial to understanding its relevance and authenticity.  

1. **Using the `eioc.py` Script:**  
   The script's output included the "To" field from the email header, which identified the recipient as:  
   **`emily.nguyen@glbllogistics.co`**  

2. **Manual Inspection of the Header:**  
   Opening the email file in a text editor revealed the "To" field in the email header:  
   ```
   To: emily.nguyen@glbllogistics.co
   ```  

3. **Verification Using MXToolbox:**  
   MXToolbox further validated the recipient's email address by parsing the header details.  

This confirms that the email was directed specifically to Emily Nguyen, which aligns with the report from the marketing team member.

---

### **4. Sender’s Display Name**  

The sender's display name provides an immediate impression of the email's source. In this case, the email claimed to be from "Dropbox."  

1. **Header Analysis via the `eioc.py` Script:**  
   The `eioc.py` script extracted the "From" field from the email header, which displayed the sender’s display name as:  
   **Dropbox**  

2. **Manual Inspection of the Email Header:**  
   Reviewing the header in a text editor revealed the "From" field:  
   ```
   From: Dropbox <no-reply@dropbox.com>
   ```  

The use of a recognizable name like "Dropbox" is a tactic often employed in phishing attempts to gain the recipient's trust. This finding was critical to determining the email's authenticity.

---

### **5. Return Path (Bounce Email Address)**  

The Return-Path field in the email header indicates the address where undeliverable messages are returned. This information can help verify the legitimacy of the email's origin.  

1. **Extracted via Didier Stevens’ `eioc.py` Script:**  
   The script output included the Return-Path field, displaying:  
   **`0101018f6aff12b2-5bcaa145-861b-45da-a06e-b5c1ee3ca941-000000@email.dropbox.com`**  

2. **Manual Verification in the Header:**  
   Searching for the "Return-Path" field in the header using a text editor confirmed the value:  
   ```
   Return-Path: <0101018f6aff12b2-5bcaa145-861b-45da-a06e-b5c1ee3ca941-000000@email.dropbox.com>
   ```  

3. **Analysis and Correlation:**  
   The Return-Path address uses a domain consistent with Dropbox's email services, which strengthens the case for the email being legitimate.  

![Return Path](image-1.png)  

---

### **6. Resolved Hostname of Sender’s IP Address**  

The sender's IP address is a key factor in tracing the email’s origin. The resolved hostname provides further context about the infrastructure used to send the email.  

1. **Extracted IP Address:**  
   From the email header, the originating IP address was identified as:  
   **`54.240.60.143`**  

2. **DNS Lookup for Hostname Resolution:**  
   Using a DNS lookup tool, the sender's IP address was resolved to the hostname:  
   **`a60-143.smtp-out.us-west-2.amazonses.com`**  

3. **Verification through Didier Stevens’ Script:**  
   The script's output included the IP address, which matched the manual findings.  

4. **Analysis of Hostname:**  
   The hostname indicates that the email was routed through Amazon Simple Email Service (SES) servers located in the US-West-2 region. Amazon SES is a widely used, legitimate email-sending service, commonly used by businesses like Dropbox to manage email communications.  

By correlating the IP address, hostname, and email content, the likelihood of this email being from a legitimate source increased significantly.

---
Here’s the expanded version of the remaining sections of your analysis:

---

### **7. Autonomous System Number (ASN)**  

The Autonomous System Number (ASN) is a unique identifier assigned to an autonomous system, representing the network that owns the IP address in question. Determining the ASN provides insights into the network infrastructure used to send the email.  

1. **IP Address Identification:**  
   From the email header analysis, the sender's IP address was extracted as:  
   **`54.240.60.143`**

2. **WHOIS Lookup for ASN Identification:**  
   A WHOIS query was conducted to determine the ASN associated with this IP address:  

   ``` bash
   whois 54.240.60.143
   ```  

   The results revealed that the IP address belongs to:  
   **ASN:** `AS16509`  

3. **Analysis of ASN:**  
   The ASN `AS16509` is registered to Amazon Web Services (AWS), indicating that the email originated from an Amazon SES (Simple Email Service) server. This finding aligns with the legitimate infrastructure often used by Dropbox for sending emails.  

   ![ASN Result](image-2.png)  

---

### **8. SPF Check Result**  

The Sender Policy Framework (SPF) check is a mechanism to validate the authenticity of an email’s origin. This involves verifying whether the sending IP address is authorized to send emails for the domain in question.  

1. **SPF Check Conducted via MXToolbox:**  
   The email header was analyzed using MXToolbox to perform an SPF check. The tool validated that the sending IP address was authorized, returning the result:  
   **SPF Check Result:** `Pass`  

2. **Significance of the SPF Check:**  
   A "Pass" result indicates that the email passed SPF validation, supporting the legitimacy of the sender’s domain and infrastructure. This finding is consistent with Dropbox's use of Amazon SES.  

   ![SPF Check](image-8.png)  

---

### **9. Sender’s Full SPF Record**  

The SPF record for the sender's domain provides a list of IP addresses and mechanisms authorized to send emails on behalf of the domain. This is critical for preventing email spoofing.  

1. **DNS Lookup for SPF Record:**  
   A DNS lookup was performed to retrieve the SPF record for the sender's domain (`amazonses.com`).  
   Command used:  

   ``` bash
   nslookup -type=TXT amazonses.com
   ```  

   The output revealed the SPF record as:  
   **`v=spf1 include:amazonses.com ~all`**  

   ![DNS Lookup](image-9.png)  

2. **Cross-Verification via MXToolbox:**  
   MXToolbox confirmed the SPF record through its SPF lookup functionality.  

   ![SPF Online Method](image-10.png)  

3. **Significance of Findings:**  
   The SPF record specifies that only Amazon SES servers are authorized to send emails for this domain. This strengthens the case for the email’s legitimacy.  

---

### **10. Email’s Message ID**  

The Message ID is a unique identifier assigned to each email by the originating server. It helps track the email's origin and verify its authenticity.  

1. **Message ID Extraction Using Didier Stevens’ Script:**  
   The `eioc.py` script output revealed the Message ID as:  
   **`<0101018f6aff12b2-5bcaa145-861b-45da-a06e-b5c1ee3ca941-000000@us-west-2.amazonses.com>`**  

2. **Manual Verification:**  
   A review of the email header in a text editor confirmed the same Message ID.  

   ![Message ID](image-3.png)  

3. **Analysis:**  
   The Message ID structure and domain align with Amazon SES’s email-sending standards, further validating the email's authenticity.  

---

### **11. Encoding Type**  

The encoding type defines how the email body content is represented for transmission. Identifying the encoding type helps ensure the content has not been tampered with.  

1. **Identified via Email Header Analysis:**  
   Using a text editor, the "Content-Transfer-Encoding" field in the email header was reviewed. It specified:  
   **Encoding Type:** `quoted-printable`  

2. **Definition of Quoted-Printable Encoding:**  
   This encoding method is commonly used for email content, enabling non-ASCII characters to be encoded in a way that remains compatible with most email systems.  

   ![Encoding Type](image-4.png)  

3. **Significance of Findings:**  
   The use of a standard encoding method like quoted-printable supports the legitimacy of the email's formatting and transmission.  

---

### **12. First URL Extracted (Defanged Format)**  

URLs in phishing emails often lead to malicious websites. Extracting and analyzing these URLs helps identify potential threats.  

1. **URL Extraction Using Didier Stevens’ Script:**  
   The script identified several URLs in the email. The first URL extracted, in defanged format, was:  
   **`hxxps[://]www[.]dropbox[.]com/l/AADiZXaA7dm2EyafvAILlHJAzwU3D55FQwg/forgot_finish`**  

   ![Extracted URLs](image-5.png)  

2. **Alternative Extraction via CyberChef:**  
   Using CyberChef, the URLs were extracted, defanged, and cross-verified. The results matched those obtained from Didier Stevens’ script.  

   ![CyberChef URL Extraction](image-6.png)  

3. **Analysis of Base Domain:**  
   The base domain (`www.dropbox.com`) was verified as legitimate using Cisco Talos.  

---

### **13. Domain Reputation**  

The reputation of the domain sending the email or hosting links is a strong indicator of the email’s legitimacy.  

1. **Domain Verification via Cisco Talos:**  
   The base domain (`https://www.dropbox.com`) was analyzed using Cisco Talos’ reputation service. The domain was classified as:  
   **Reputation:** Favorable  

   ![Domain Reputation](image-7.png)  

2. **Significance of Findings:**  
   A favorable reputation for the domain suggests it is legitimate and unlikely to be associated with malicious activity.  

---

## Conclusion  

Following a comprehensive analysis of the email headers, SPF records, Message ID, and domain reputation, it was concluded that the email is **legitimate**. Emily Nguyen can safely interact with the email and proceed with the password reset if required.  

--- 