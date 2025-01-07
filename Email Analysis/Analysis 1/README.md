# Instructions:
You are a SOC Analyst at Mighty Solutions, Inc. An account executive, Dana Derringer, noticed a warning email in her inbox claiming her online access has been disabled. However, she noticed this was odd as she is still able to access her online business platforms and inbox. She decided to forward the email in question to the security team's phishing mailbox for review.

Using what you've learned within this domain, perform a detailed email analysis on the challenge1.eml file to answer the report questions below.

Challenge File:
01_Phishing_Analysis/Challenges/challenge1.eml

## Based on the contents of the email header, what is the full date and time of the email delivery ?

Using Didier Stevens set of tools, I used his pythin script of `eioc.py` which was able to generate key information from the Email header. Among the infomaiotn is ther Full Delivery Date and time of ``Tue, 31 Oct 2023 10:10:04 -0900`

![Delivery Date and TIme](image.png)

## What is the subject of the email?

From the scame script, the subject line was identified to be `Your account has been flagged for unusual activity`

## Who was the email sent to?


From the script, the email was sent to `dderringer@mighty-solutions.net`

## Based on the sender's display name, who does the email claim to be from?

Fromt the script ooutput, the email claimed to have originated from  `Outlook Support Team `

## What is the sender's email address?

This information was also obtained from the email script output as 
`social201511138@social.helwan.edu.eg`

## What email address is used for receiving bounced emails?

The bounced mails in email header is reffered to as the Return Path which was identified throught the script output as `social201511138@social.helwan.edu.eg`

## What is the IP address of the sender's email server?

Again from the  script output, the senders email address has been identified as `40.107.22.60`

## What is the resolved hostname of the sender's IP address?

Using the `nslookup 40.107.22.60`
The resolved IP address was identified as `mail-am6eur05on2060.outbound.protection.outlook.com`
![nslookup](image-1.png)

## What corporation owns the sender's IP address?

In order to ascertain this i made use of `whois 40.107.22.60` which provided the answer to be `Microsoft Corporation`
![Microsoft Corporation](image-2.png)

## What was the result of the SPF check?

Using the email header parser platform of https://mha.azurewebsites.net/, the SPF check was identified to be `Pass`
![SPF Check](image-3.png)

## What is the full SPF record of the sender's domain?

The SPF record of the senders domain was obtain after running the command
``` bash
nslookup -type=txt helwan.edu.eg
```
This produced the valued of v=spf1 include:spf.protection.outlook.com -all`

![SPF Record](image-4.png)

## What is email's Message ID?

The identified message ID from the initial python script runned from Didier steven has been identified as:
`<JMrByPl2c3HBo8SctKnJ5C5Gp64sPSSWk76p4sjQ@s6>`

## What type of encoding was used to transfer the email body content?

From the email header viewed in Sublime text editor, the identified Encoding is` base 64`
![Encoding](image-5.png)

## In defanged format, what is the second URL extracted from the email?
 
The solution to this has been obtained from the script run in step one  as `hxxps[://]0[.]232[.]205[.]92[.]host[.]secureserver[.]net/lclbluewin08812/`. Didier Stevens tools was able to extract the URL in a Defang format
![Defang Format](image-6.png)

However, I also used Cyberchef as a second method where i first decode the message from base 64, then fetch URLs from it and then defanged it with the various modules in Cyberhsef as displayed below:

![Cyberchef](image-7.png)

## Perform a VirusTotal scan on the URL. What verdict did Fortinet assign to it?

Performing this action on the URL in a fang format revealed that the URL is a Phishing URL 
![Virus TOtal Scan](image-8.png)

## [Yes or No] - After your analysis, is this email genuine?

After this thourough analysis, I can confidently say the email is not genuine and has the intension of Phishing. 