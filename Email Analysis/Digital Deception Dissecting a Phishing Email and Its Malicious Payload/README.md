# Digital Deception: Dissecting a Phishing Email and Its Malicious Payload

In this project, I analyze a phishing email targeting a marketing team member at Global Logistics. The email, which was flagged by the company's email gateway, contained a malicious attachment designed to compromise the recipient’s system. Using various analysis tools, I dissect the email’s header, identify the malicious attachment, and delve into the VBA macro that triggered a Trojan downloader.

Key findings from the investigation:
- **Email Header Analysis**: Identified the sender’s domain and extracted key metadata.
- **Attachment Analysis**: Extracted and analyzed a malicious `.docm` file with a trojan downloader.
- **VBA Macro Behavior**: Detailed the malicious script responsible for downloading and executing malware.

For a step-by-step breakdown of the tools, methods, and findings, along with supporting evidence such as logs and screenshots, check out the full write-up on [Medium](https://medium.com/@noble-antwi/digital-deception-dissecting-a-phishing-email-and-its-malicious-payload-e1eb61985a0a).

---

## Key Tools Used:
- Didier Stevens' Toolkit
- VirusTotal
- oledump.py
- Python scripts for email and attachment analysis

## Recommendations:
- Quarantine suspicious emails.
- Notify recipients of phishing attempts.
- Block malicious sender domains.
- Conduct phishing awareness training across the organization.

Explore the full project and learn more about this real-world cybersecurity threat detection scenario!
