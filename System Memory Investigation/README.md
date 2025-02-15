# Computer Forensics Project: System Memory Investigation

## **Lab Context and Materials**

This project is part of my MSc Program in Cyber Forensics, conducted as a lab exercise. The investigation follows the guidelines and instructions provided in the official lab manual. You can access the relevant documents here:


- [Lab Guide (PDF](Files/Document/Conducting_Forensic_Investigations_on_System_Memory_4e.pdf)

- [Solution Report (PDF)](Files/Document/Conducting_Forensic_Investigations_on_System_Memory_4e_-_noble_antwi.pdf)

This write-up expands on the steps, findings, and insights derived from the lab activities, presenting a structured forensic investigation of system memory.

---

## **Project Overview**

This document details the methodology, tools, findings, and analysis conducted during a forensic investigation of system memory. The project showcases a structured approach to extracting, analyzing, and interpreting volatile memory to identify potential threats and anomalies.

---

## **1. Introduction**

### **1.1 Background**

Memory forensics involves analyzing volatile data stored in a system’s RAM to uncover critical insights into the system’s activities. Unlike non-volatile storage, volatile memory is erased when the system powers down, making real-time capture crucial for investigations.

### **1.2 Objectives**

The primary objectives of this investigation were:

- Capture and analyze system memory using industry-standard tools.
- Identify and document malicious activities.
- Enhance investigative skills relevant to real-world scenarios.

---

## **2. Methodology**

### **2.1 Tools and Software Used**

- **DumpIt**: A lightweight tool designed for capturing raw memory dumps. It offers ease of use and quick deployment, making it suitable for immediate capture scenarios.

- **FTK Imager**: A robust forensic imaging tool that not only captures memory but also enables previewing and verifying data. Chosen for its advanced capabilities and integration with other forensic tools.

- **Paraben's E3**: An all-in-one forensic analysis tool that supports memory dump parsing alongside other digital evidence. Its graphical interface simplifies the analysis process for investigators.

- **Volatility Framework**: A command-line-based, open-source tool specialized in memory forensics. It provides comprehensive analysis capabilities, including process trees, network connections, and malware detection.

- **DensityScout**: A specialized utility for analyzing file densities to detect signs of malware. Its ability to flag packed or encrypted files makes it invaluable for identifying potentially malicious executables.

- **Google Search and File.net**: Used for researching the legitimacy of processes and files identified during analysis, providing context and confirmation for findings.

### **2.2 Process Flow**

1. **Capture System Memory**:
   - DumpIt and FTK Imager were utilized to capture memory snapshots.
2. **Analyze Memory Dumps**:
   - Tools like Paraben’s E3 and Volatility were employed to extract process trees, identify hidden processes, and track network connections.
3. **Validate Findings**:
   - DensityScout and additional internet research verified the legitimacy and risk level of flagged files and processes.

---

## **3. Findings and Analysis**

### **3.1 Hands-On Demonstration**

#### **3.1.1 Key Processes Identified**

- **conhost.exe**: A legitimate process that manages command-line interfaces in Windows. It showed no signs of malicious activity and was verified to be safe.

- **hooker.exe**: Flagged as malicious due to several behavioral and contextual indicators. Hooker.exe demonstrated the following suspicious traits:
  - **Keylogging Capabilities**: Hooker.exe was identified as software capable of recording user keyboard inputs, a hallmark of spyware and data theft malware.
  - **Registry Modifications**: It was found to modify persistence-related registry keys, including:
    - **HKCU\Software\Microsoft\Windows\CurrentVersion\Run**: To ensure execution at login.
    - **HKLM\System\CurrentControlSet\Services**: Suggesting attempts to masquerade as a legitimate service.
  - **File Access Patterns**: The executable interacted with sensitive directories, including:
    - **AppData\Roaming\Logs.txt**: Indicative of logging captured inputs.
    - **System32\hooker-3.4.dll**: Suggesting attempts to integrate or manipulate system-level processes.
  - **Location in Downloads Folder**: Malware often resides in user-accessible locations such as Downloads due to accidental execution by users.

The above traits collectively indicated a high probability of malicious intent, highlighting the executable’s role in unauthorized data collection and system compromise.

#### **3.1.2 Memory Capture with DumpIt**

DumpIt was used successfully to capture volatile memory. The raw dump contained evidence of running processes, loaded drivers, and system configurations that were critical for subsequent analysis.

#### **3.1.3 Memory Analysis Using Paraben’s E3**

Using Paraben’s E3, the following observations were made:

- **Registry Analysis**: Hooker.exe was found to modify several Windows Registry keys:
  - **HKCU\Software\Microsoft\Windows\CurrentVersion\Run**: This registry key is commonly used for persistence, allowing hooker.exe to execute automatically at user login.
  - **HKLM\System\CurrentControlSet\Services**: Indicated attempts to create or modify a system service to disguise its operations.
  These modifications confirm that hooker.exe was designed to embed itself deeply into the system for sustained malicious activity.

- **File Access**: Hooker.exe accessed multiple sensitive files, including:
  - **C:\Users\[Username]\AppData\Roaming\Logs.txt**: Indicative of keylogging or data exfiltration activities.
  - **C:\Windows\System32\hooker-3.4.dll**: Demonstrated integration with system processes to enable covert operations. 
  The presence of these files in conjunction with hooker.exe reinforces its malicious intent and highlights its capabilities for data theft and persistence.

- **Process Timing**: Analysis of process start times indicated anomalies. Hooker.exe initiated operations shortly after login, leveraging user activity to blend into typical system usage patterns. This strategic timing minimized the likelihood of early detection by monitoring tools.

### **3.2 Advanced Analysis**

#### **3.2.1 Volatility Framework**

- **Process Relationships**: Using the `pstree` module, a detailed map of parent-child relationships was constructed:
  - **explorer.exe** was identified as the parent process for several suspicious activities, including **hooker.exe**. This suggests manual or interactive execution, possibly by the user unknowingly launching malware.
  - Other processes, such as **cmd.exe** and **rvlkl.exe**, were traced back to explorer.exe as well, indicating potential malware-laden tasks triggered post-login.
- **Suspicious Grouping**:
  - The proximity of suspicious processes like **hooker.exe**, **rvlkl.exe**, and **DumpIt.exe** in the process tree raised concerns about coordinated malicious activity.
  - For example, **hooker.exe** exhibited behaviors consistent with persistence mechanisms, while **rvlkl.exe** operated as a keylogger, capturing user data covertly.
- **Execution Timing**: By correlating timestamps, it was evident that these processes were launched in quick succession, which is a common tactic in malware campaigns to overwhelm detection mechanisms.
- **Hidden Processes**: No hidden processes were detected during the `psxview` analysis, indicating the malware relied on standard visibility rather than stealth.

#### **3.2.2 Network Analysis**

- **Ephemeral Ports**: Port 56610, observed in the memory dump, was confirmed as a temporary port for client-server communication and showed no signs of malicious activity.
- **Network Connections**: Neither hooker.exe nor rvlkl.exe exhibited any active or historical network connections during the analysis, indicating that their malicious activities were confined to local operations.

#### **3.2.3 Malware Detection Using DensityScout**

DensityScout revealed the following:

- Hooker.exe exhibited a moderately suspicious density score, consistent with packed or obfuscated files commonly used in malware.
- Rvlkl.exe, identified as Revealer Keylogger, showed similar density characteristics but was also recognized as legitimate software under certain contexts. However, its unauthorized presence raised security concerns.

### **3.3 Challenge and Analysis**

#### **3.3.1 Malicious Connections**

Analysis identified three processes connected to a suspicious IP address (205.134.253.10) on port 4444:

- **QaNoQBC.exe**: Flagged for its elevated privileges and active connection to the remote IP.
- **fixtureComputer.exe**: Demonstrated a parent-child relationship with QaNoQBC.exe.
- **dllhost.exe**: Often a legitimate process, but in this instance, flagged for suspicious activity due to its network connection.

Research on port 4444 revealed its common use in:

- **Metasploit Framework**: A penetration testing tool often exploited by attackers for reverse shells.
- **Netcat**: A network utility sometimes used maliciously.
- **Malware Backdoors**: Many malware strains use port 4444 for command-and-control communications.

#### **3.3.2 Privilege Escalation**

Investigation of privilege escalation revealed:

- **tior.exe**: A known User Account Control (UAC) bypass tool, was detected in memory. It injected code into svchost.exe, a legitimate Windows process, to evade detection.
- **QaNoQBC.exe**: Elevated its privileges immediately after tior.exe’s execution, confirming a successful exploitation sequence.

---

## **4. Conclusion**

The investigation successfully identified and analyzed malicious activities within the captured memory dumps. The findings highlight the critical role of memory forensics in identifying hidden threats and safeguarding system integrity.

### **4.1 Key Takeaways**

- Volatile memory is a treasure trove of forensic evidence, crucial for modern investigations.
- Tools like Volatility and DensityScout provide unparalleled insights into system behavior.
- Real-world scenarios demand both technical expertise and investigative intuition.

### **4.2 Recommendations**

- Regular training on memory forensics tools and techniques.
- Implementation of robust monitoring systems to detect anomalies in real time.
- Proactive research on emerging threats and malware techniques.

---
