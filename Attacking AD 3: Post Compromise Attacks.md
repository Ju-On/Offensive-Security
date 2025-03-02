Setup win2022 server: 192.168.64.138  
Setup Peterparker: \192.168.64.140  
Setup Frankcastle: 192.168.64.139  
Kali: \192.168.64.129/24  

## 🚩 'Pass Attacks' - Pass the Password / Pass the Hash.  

### Pass the Password  
With a SAM dump and cracked hash, we have the ability to push the credentials around with every device that has the ability to recieve and accept the login attempt.  

crackmapexec: 

    crackmapexec smb 192.168.64.0/24 -u fcastle -d MARVEL.local -p Password1

![image](https://github.com/user-attachments/assets/025b48ea-6702-4094-ae25-c54168fb1607)
We can see that the username and password has been passed around the network and was successful only on Spiderman and Thepunisher devices. Although there was a succesful authentication on Hyrda-DC, fcastle is not a local admin in that device therefore no login. 


### Pass the Hash  
With a SAM dump containing local Admin credentials, we can also pass an admin account credentials with the hash around the network and observe what devices will accept these credentials.
