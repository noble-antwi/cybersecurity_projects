# Advanced Techniques in Email Header Analysis for Phishing Detection

This project presents a comprehensive investigation into a reported phishing attempt within Global Logistics. A suspicious email, allegedly from Dropbox, was analyzed to determine its legitimacy. The analysis encompassed:

- **Email Header Examination**: Utilized tools like Didier Stevens’ `eioc.py` script and MXToolbox to extract and verify metadata, including delivery timestamps, sender information, and recipient details.

- **Sender Authentication**: Assessed the sender's display name, return path, and originating IP address to evaluate authenticity.

- **Domain and IP Analysis**: Performed DNS lookups and examined the Autonomous System Number (ASN) to trace the email's origin and verify its legitimacy.

- **SPF Record Evaluation**: Checked the Sender Policy Framework (SPF) records to confirm the email was sent from an authorized server.

- **URL Inspection**: Analyzed embedded links in defanged format to assess potential threats.

The investigation concluded that the email was legitimate, allowing the recipient to proceed with the password reset safely.

For a detailed analysis, read the full report on Medium: [Advanced Techniques in Email Header Analysis for Phishing Detection](https://medium.com/@noble-antwi/advanced-techniques-in-email-header-analysis-for-phishing-detection-c5567f1caa00)
