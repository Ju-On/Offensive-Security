Setup win2022 server: 192.168.64.138  
Setup Peterparker: \192.168.64.140  
Setup Frankcastle: 192.168.64.139  
Kali: \192.168.64.129/24  

Now that we have compromised an account or have gotten user credentials, further **enumeration** will be conducted with these elevated access.

## 🚩 Domain enumeration with ldapdomaindump  

If an IPv6 attack was conducted with mitm6 with the combination of ntlmrelayx, there is a possibility a dump was succesfully taken from the lootme -l switch.  

However if not, and the network does not have IPv6 DHCP enabled but we have user credentials from the **initial attack vectors** we can still query the LDAP to fetch us a LDAP domain dump.

    ldapdomaindump ldaps://192.168.64.138 -u 'MARVEL\fcastle' -p Password1

![image](https://github.com/user-attachments/assets/8e4726f9-f194-41f6-b462-0f3a7380eb3b)

## 🚩 Domain enumeration with Bloodhound


