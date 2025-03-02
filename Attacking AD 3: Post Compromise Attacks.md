Setup win2022 server: 192.168.64.138  
Setup Peterparker: \192.168.64.140  
Setup Frankcastle: 192.168.64.139  
Kali: \192.168.64.129/24  

## 🚩 'Pass Attacks' - Pass the Password / Pass the Hash.  

### Pass the Password  
With a SAM dump and cracked hash, we have the ability to push the credentials around with every device that has the ability to recieve and accept the login attempt.  

crackmapexec SMB Password abuse: 

    crackmapexec smb 192.168.64.0/24 -u fcastle -d MARVEL.local -p Password1

![image](https://github.com/user-attachments/assets/025b48ea-6702-4094-ae25-c54168fb1607)
We can see that the username and password has been passed around the network and was successful only on Spiderman and Thepunisher devices. Although there was a succesful authentication on Hyrda-DC, fcastle is not a local admin on that device therefore there is no login. 

---

## 🚩 Pass the Hash  
With a SAM dump containing local Admin credentials (likely gathered during the initial attack stage), we can also pass a local admin account credentials with hash around the network and observe what devices will accept these credentials.

crackmapexec SMB Hash abuse:

    crackmapexec smb 192.168.64.0/24 -u administrator -H aad3b435b51404eeaad3b435b51404ee:fbdcd5041c96ddbd82224270b57f11fc --local-auth

![image](https://github.com/user-attachments/assets/13e70253-c999-4110-baf0-1cab4d1841f4)  
Local admin account succesful for Spiderman and Thepunisher  

adding the below flags behind --local-auth:   
--sam {dumps all local SAM files found}  
--shares {dumps all local SAM files found}  
--lsa {local security authority}  

crackmapexec smb -L will list out all the modules we can use with SMB
