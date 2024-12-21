# TCM SOC 101 Study Journey

This will be a place where i document my study of SOC 101 from TCM Security. I will try as much as mpossible to document anything of value on this page.

## LAB Setup

I install Windows 10 and Ubuntu Virtula machine on VMware Hypervisor

![Ubuntu Installed](files/images/001UbuntuSetup.png)
Ubuntu Installation

![Windows 10 Installation](files/images/002Win10Done.png)

### Configuring Windows

In order to ensure windows security does not block some of the attacks I will be runnong, I have to turn it off and also the regsitry key by sunig the commans below:

1. Disable real-time protection

     ```powershell

        Set-MpPreference -DisableRealtimeMonitoring $true
     ```

2. Disable the scanning of network files

```powershell
Set-MpPreference -DisableScanningNetworkFiles $true
```

3. Disable the blocking of files at first sight

```powershell
Set-MpPreference -DisableBlockAtFirstSeen $true
```

4. Disable Windows Defender AntiSpyware

```powershell
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
```

I ensured both the Ubuntu and Windows are sitting on the same network in VMware.

### Clone the course repository

```bash
git clone <https://github.com/MalwareCube/SOC101.git>
```

Next, extract each of the course ZIP files onto the desktop using the password below:

ZIP file password
nucleus-faucet-rockslide

## SOC Model

1. Internal SOC
2. Managed SOC : Third party provider of security opeartions
3. Hybrid: combines both internal and managed soc.

### SOC Roles

1. SOC Analyst: Frontline roles
   1. Tier I: Entry level
   2. Tier II (Incident Responder): INvestigating and remediating an escalted incident
   3. Tier 3 (Threat Hunters)
   4. SOC Team Lead
2. Specialsied roles
   1. Incidence Responder
   2. Threat Hunters: They are proactive. Developing custom alert and detection rules.
   3. Threat Intelligence Analyst
   4. Security Engineer
   5. Vulnerability Management.
   6. Forensics Analyst
   7. Malware analysts
3. Management Roles
   1. SOC Manager: Day to day operation of SOC team, including budgeting etc
   2. Director of Security.
   3. CISO

## Incident and Event Management

The goal is to accuratly collect records with regards to security incidents

### Incident management

 1. Incident identification
 2. Incident calssification
 3. Incident investigation
 4. Incident containment
 5. Incident eradication
 6. Incident recovery

## SOC Metrics

1. Mean Time to Detection (MTTD): Average time it takes SOC to detect
2. Mean Time to Resolution (MTTR)
3. Mean Time to Attend and Analyse (MTTA&A)
4. Incidence Detection Rate: Higher rate, means higher visibility.
5. False Positive Rates: Calculated in percentages.
6. False Negative Rates: Fewer rates are good.

## SOC Tools

1. Security Information and Event Managment System(SIEM): Aggregate logs accross the enterprise
   1. Log management
   2. real-time monitoring
   3. alerting and notification
   4. reporting
   5. visualisation
   6. threat intelligence incoportation
2. Security Orhestration, Automation, and Response (SOAR).
3. Incidence Managment Tools
   1. Ticketing management system
   2. alert management
   3. workflow automation
   4. collaboration
4. Network Security Moniroting(NSM)
   1. Packet capture and analysis
   2. Network Trafic Analysis
   3. Intrusion Detection
5. Endpoint Detection and Response (EDR)
   1. DentinelOne
   2. Crowdstrike
   3. User entitry behaviour and analytics (UEBA)
6. IDS /IPS
7. Firewall
   1. pfsense, paloalto, cloudflare,juniper,
   2. NextGen Firewall
   3. web application firewall
8. Threat Intelligence Platforms
   1. Maltego,
   2. data aggregation and enrichment
   3. indicator of compromise
   4. analysis nad prioritixation
9. Forensics Analsis Tool
10. Malware Analysis Tool
    1. Hybrid analysis, cuckoo, chidra, any run

## Common Threats and Attacks

1. Social engineering
   1. expoiting humansa
   2. spoofing
   3. phishing
      1. spear phishing
      2. whaling : targets high profile individuals
      3. vishing (Voice phishing)
      4. smishing (sms phishing
      5. Quishing ())
2. Worm: Self replicating without
   1. stuxnet, blaster
3. Spyware /Adware
4. Ransomware
5. Botnet: set of compromised devices called zombies.
6. Fileless malwate: Executes in memory, living of the land
   1. uses stuffs like WMI, powershell, and code injection.
7. Idenity and account compromise
   1. an individual gaines access account they are not supposed to.
8. Insider Threat.
9. Denial of Service
10. Data Breaches

## Phishing

Exploiting the weakest link in the security of an organization. Phishing mails may show

1. Authority
2. Trust
3. Intimidation
4. Social Proof: validate legitimate throuh consensus.
5. Urgency  
6. Scarcity
7. Farmiliarity.

## EMAILS

This is control by the protocol SMTP(Simple Main Transfer Protocl) using port 25 or 465 and 587 if it is secured. Handles the outgoing message from client to the recipient.
![Email Protocols View](image.png)
![alt text](image-1.png)

### SMTP

Used to send outgoing mail. Port 24 (or 465, 587)

### POP3  (Post Office Protocol version 3)

Protocol used by mail client to download email from mail server and then deletes them. Use Port 110 port ( or 995 )

### IMAP (Internet Message Access Protocl)

It is also another email retrival protocol but in this case it does not delete the mail after client accessese it unlike POP3.Emails stores on the mail server. wokrs on port 143 (993 for secure)

### Email Headers

Contains information about email content, origin and how it should be handled.

### Mail Transfer Agent (MTA)

Helps to move the email from multiple servers till it reaches the end-users mail server

### Mail User Agent

Actual software used to compose email like gmail, yahoo, outlook etc

### Mail Delivery Agent

More like the last agent to hold the email for the receiver to retrive it.

## Types of Phishing

1. Information gathering attacks.
2. Credential Harvesting.
3. Malware delivery
4. Spear phishing: target a specific group
5. whaling: high profile individual
6. Vishing: Voice phishing
7. smishing: SMS
8. Quishing: exploitaion of QR Codes

### Phishing Attack Tecqnieue

1. Pretexting
   1. Fabricates story to deceive a victim
   2. Manipulation under false orete
2. SPoofing and Impersonation
   1. Email Addres Spoofing
   2. Domain Spoofing
3. URL Manipulation
   1. URL Shortening
   2. subdomain spoofing
4. homograph: same or similar words but with different meaning,. A homoglyth site can generate the similiar link
5. typosquatting . Registering similar domain names to the original(DNS twist can be used to identify typosquatting)
6. Encoding: Obfuscate and evade detection.Can be used in Base64, URL encoding, HTML encoding
7. Attachement
   1. Abuse of legitimate services like google drive, dropbox. using trusted reputations to send malware. You can use the Phishtank to analyse suspicious URLS
8. Pharming: Two steps technique
   1. Directst to a malicois site
   2. alware bases pharming
   3. DNS server poisoning

#### Phishing Analysis Methodology

1. Initial Triage
   1. quickly assess and prioritise
2. Header and Sender Examiniation
3. Content Examination
   1. look for socail enfineering red flags
   2. analyze email content
4. Web and URL examiniation
5. Attachment examination
6. Contextual Examiniation
   1. look for paterns and assess scope
   2. consider broder context
7. Defense measures
   1. take reactive defense actions (if needed)
   2. take proactive defense actions
8. Documentationa dn reporting.

### Email Headers.

1. Date: SPecifies the date the message was composed or sent
2. From: Sender details: this can be spoofed.
3. Subject:
4. Message ID: Unique ID generated by the first MTA. Under no circumstance should this be duplicated. Containes 2 parts. Part before the @ is a unique field whilst the part after the @ indicates the host IP or the domain from which the email originated from.![Message ID](image-2.png)
5. To: Indicates the recipient Email Address
6. Reply to: Indicates the email address to whcih the replies go to in the even the user want to send a reply.
7. Return Path: also known as the envelope, or bounce address: This indicates where failed email address shpuld be sent i.e if there is a failure in sending a mail then it should be sent to the specified email address.
8. X-headerer IP ot X-origninating IP: INdicates the IP of the email provider it coming from.If this is not present then you can check the received hearders section
9. Received: There are mutiple of them which ondicates hte ralye of MTA hwich is the number of email servers that the email traverse.The received orderes are in reverese chronilogial order.

Parsin =g email headers can also be done in an easy way by using the platform <https://mha.azurewebsites.net/> and <https://mxtoolbox.com/EmailHeaders.aspx>

## SKILLS

1. Email Analysis.
2. Phishing Analysis
