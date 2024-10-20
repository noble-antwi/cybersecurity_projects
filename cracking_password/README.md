Here's a structured introduction and explanation for your GitHub project based on cracking password hashes:

---

## **Cracking NTLM Hashes - Project Overview**

**Project Description:**

This project focuses on understanding and cracking NTLM (NT LAN Manager) password hashes. NTLM is a suite of Microsoft security protocols intended to provide authentication, integrity, and confidentiality to users. Although widely used in the past, NTLM hashes are considered weak by modern security standards due to vulnerabilities in their cryptographic design. This project aims to showcase the process of cracking NTLM password hashes using various tools, turning a practical assignment into a hands-on learning experience in cybersecurity.

**Objective:**

- Crack the given NTLM password hashes.
- Understand and explain how the hash cracking process works.
- Provide detailed explanations, screenshots, and methodologies used.

---

## **Password Hashes Explanation:**

In many operating systems, password hashes are stored instead of plain-text passwords for security reasons. A hash is a one-way cryptographic function that turns any input (like a password) into a fixed-size string of characters, which is the hash.

Here, we have the following hash dump:

```python
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e02bc503339d51f71d913c245d35b50b:::

vagrant:1000:aad3b435b51404eeaad3b435b51404ee:e02bc503339d51f71d913c245d35b50b:::

sshd:1001:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

c_three_pio:1008:aad3b435b51404eeaad3b435b51404ee:0fd2eb40c4aa690171ba066c037397ee:::

boba_fett:1014:aad3b435b51404eeaad3b435b51404ee:d60f9a4859da4feadaf160e97d200dc9:::

```

### **Components Breakdown:**

Each line in this format represents a user and their password hash:

```
<username>:<UID>:<LM hash>:<NTLM hash>:::
```

1. **Username**: The account name of the user (e.g., `Administrator`, `vagrant`).
2. **UID**: The User Identifier (UID) is a unique number assigned to each user in the system (e.g., `500`, `1000`).
3. **LM Hash**: A legacy password hashing format. In many modern systems, it's no longer used and filled with placeholders (`aad3b435b51404eeaad3b435b51404ee`).
4. **NTLM Hash**: The more modern and commonly used hash format. This is the hash we aim to crack to reveal the actual password.

### **NTLM Hashes & Security:**

NTLM hashes are vulnerable to brute-force attacks and rainbow table lookups due to the absence of modern protections like salting (adding random data to the password before hashing). Hash cracking tools can exploit this vulnerability by using computational power to reverse the hash into its original password.

**Example Breakdown:**

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e02bc503339d51f71d913c245d35b50b:::
```

- **Username**: `Administrator`
- **UID**: `500`
- **LM Hash**: `aad3b435b51404eeaad3b435b51404ee` (no LM hash stored, placeholder)
- **NTLM Hash**: `e02bc503339d51f71d913c245d35b50b` (this is the hash we need to crack)

The same pattern follows for other users like `vagrant`, `sshd`, `c_three_pio`, and `boba_fett`.

### **Tools Used in This Project:**

- **Hashcat**: A fast and efficient password cracking tool used to crack NTLM hashes.
- **John the Ripper**: Another popular password cracking tool.
- **RockYou.txt**: A commonly used wordlist in password cracking.

Through this project, we will leverage these tools and techniques to crack the hashes and identify the plaintext passwords.

## Cracking NTLM Passwords Using Hashcat

### Creating the Hash File

To begin, I created a text file to store the NTLM hashes I intended to crack. This involved using the **nano** text editor, which is a widely used command-line text editor in Linux environments. The following steps outline this process:
Firslty, i created a directory in my home directory and names at as projects and created another sub directory calling it passwordcracking both using the ```mkdir``` command and then navigated to it using the ```cd``` command.

 I then executed the following command to create a new text file named `ntlmhash.txt`:

   ```bash
   nano ntlmhash.txt
   ```

Inside the nano editor, I entered the NTLM hashes provided for cracking:

   ```bash
   e02bc503339d51f71d913c245d35b50b
   31d6cfe0d16ae931b73c59d7e0c089c0
   0fd2eb40c4aa690171ba066c037397ee
   d60f9a4859da4feadaf160e97d200dc9
   e02bc503339d51f71d913c245d35b50b
   ```

 After inputting the hashes, I saved the file by pressing `CTRL + O` followed by `Enter` and exited the editor with `CTRL + X`. This step resulted in a successfully created hash file. The content can be seen below
 ![NTLM Has File](files/images/004DisplayingtheContentwithcat.png)

To effectively crack the hashes, a robust wordlist is necessary. Kali Linux includes the well-known wordlist `rockyou.txt`, but it is stored in a compressed format. I changed my directory to where the `rockyou.txt.gz` file is located with the command:

   ```bash
   cd /usr/share/wordlists/
   ```

 To decompress the file, I utilized the `gunzip` command:

   ```bash
   sudo gunzip rockyou.txt.gz
   ```

To ensure that the file was unzipped successfully, I listed the files in the directory:

   ```bash
   ls /usr/share/wordlists/
   ```

This command confirmed the presence of `rockyou.txt`, indicating that the unzipping process was successful.

With the NTLM hash file and the wordlist ready, I proceeded to use **Hashcat** in straight mode (also known as dictionary mode). Sitting the directory i created the NTLM Hashes,  I executed Hashcat with the following command:

   ```bash
   hashcat -m 1000 -a 0 -o crackedpassword.txt ntlmhash.txt /usr/share/wordlists/rockyou.txt
   ```

   In this command:

- `hashcat`: Calls the Hashcat tool.
- `-m 1000`: Specifies the hash type as NTLM.
- `-a 0`: Indicates the use of straight mode with the wordlist.
- `-o crackedpassword.txt`: Specifies that the output (cracked passwords) should be saved in a file named `crackedpassword.txt`.
- `ntlmhash.txt`: This is the input file containing the NTLM hashes.
- `/usr/share/wordlists/rockyou.txt`: This is the wordlist that I unzipped earlier.
-

![Failed Attack](files/images/005FirstAttackFailed.png)

From the above, you woould realize the attack failed due to lack of RAM hence i wll increase my RAM from the current 2GB to 14.9GB or more as shonw below
![Changed RAM](files/images/006ChangedRAM.png)

 Throughout the execution, I monitored the terminal output, observing Hashcat as it systematically attempted to crack each hash by checking against the wordlist.
 ![Running Process](files/images/007ReRunofCommand.png)
 From the output above, ```Recovered........: 3/4 (75.00%) Digests (total), 3/4 (75.00%)``` Hashcat successfully cracked 3 out of 4(5) hashes, meaning it recovered 75% of the hashes.
After the process completed, I viewed the results by displaying the contents of `crackedpassword.txt`:

   ```bash
   cat crackedpassword.txt
   nano crackedpassword.txt
   ```

| NTLM Hash                                | Plaintext  |
|------------------------------------------|------------|
| 31d6cfe0d16ae931b73c59d7e0c089c0       |     |
| e02bc503339d51f71d913c245d35b50b       | vagrant    |
| 0fd2eb40c4aa690171ba066c037397ee       | pr0t0c0l   |

This indicates that 31d6cfe0d16ae931b73c59d7e0c089c0  has an empty space as its password or say no password set whilst e02bc503339d51f71d913c245d35b50b  is vagrant and 0fd2eb40c4aa690171ba066c037397ee is pr0t0c0l.  In order to very all of this i used the website of ```cyberchef``` to cross check the hashes of all of them with the url [Cyberchef](https://gchq.github.io/CyberChef/#recipe=NT_Hash())

**Empty Space**

![Empty](files/images/010EMpty.png)

**Vagrant**

   ![Vagrant](files/images/011Vagrant.png)

  **pr0t0c0l**
  ![Protocol](files/images/012Protocol.png)

The password for the hash ```d60f9a4859da4feadaf160e97d200dc9``` however is missing and cpuld not be fpund hence I need to explore other ways to obtain it.

## **Step 4: Using Hashcat in Brute-Force Mode (`-a 3`)**

After successfully cracking some hashes, I decided to further explore Hashcat's capabilities by utilizing brute-force mode (mask attack mode, `-a 3`). This mode generates and tests all possible combinations of characters according to specified criteria. Here’s how I implemented this:

1. **Run Hashcat in Brute-Force Mode**: I executed the following command for a brute-force attack:

   ```bash
   hashcat -m 1000 -a 3 -o crackedpassword.txt ntlmhash.txt ?l?l?l?l?l?l?l?l
   ```

   In this command:
   - `?l`: Represents a lowercase letter.
   - The mask `?l?l?l?l?l?l?l?l` indicates that Hashcat should attempt all combinations of 8 lowercase letters.

2. **Monitor Progress**: As the brute-force attack commenced, I observed that this method was considerably more time-consuming compared to the straight mode, given the sheer number of possible combinations.

---

## **Conclusion**

This project provided a comprehensive exploration of using Hashcat to crack NTLM password hashes. By creating a hash file, utilizing a well-known wordlist, and experimenting with both straight and brute-force attack modes, I gained valuable insights into password security and hash cracking methodologies.

Understanding how hashes work and the importance of strong passwords is critical in the field of cybersecurity. I hope this documentation serves as a useful guide for anyone interested in learning about password cracking techniques and the tools available for such tasks.

Feel free to reach out if you have any questions or would like to discuss further!

---

This professional write-up effectively communicates the steps and methodologies you employed while maintaining clarity and a formal tone. If you need any further modifications or additions, feel free to ask!
