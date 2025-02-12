Setup win2022 server  
Setup Peterparker account  
Setup Frankcastle account  
Kali: 192.168.64.129/24

## LLMNR Poisoning
Link Local Multicast resolution  

Requirements: LLMNR attack can be performed if the LLMNR/NBT-NS is enabled and the attacker machine is in the same network as the target.
LLMNR attacks use the Responder tool which captures credentials that are broadcasted over the network when a user seek connection to a another service / resource that does not exists or is poorly configured. Through these vulnerabilities, Responder spoofs the request and responds by stating they know the service or resource. Requesting the victims NTLM hash.  

![image](https://github.com/user-attachments/assets/fc6902c4-acf7-4787-b2c8-607a7cd2900b)  

Commonly used tooling for LLMNR Poisoning attacks:  
Responder, Impacket, MITM6

### Capturing Hashes with Responder

Kali responder IP: 192.168.64.129/24
sudo responder -I eth0 -dwPv

![image](https://github.com/user-attachments/assets/8de5ddb4-8956-4b4b-98f6-c2df1cb6ac99)  

Ensure details such as nic, responder ip, is all correct. Once responder is on the network and listening for traffic, an example of captured NTLMv2 hashes can be seen like this:

![image](https://github.com/user-attachments/assets/f4e41ca4-5d90-4b66-b181-399742def06f)

### Cracking NTLM hashes  

root@kali:/home/kali# hashcat -m 5600 ntlm.txt /usr/share/wordlists/rockyou.txt --force

![image](https://github.com/user-attachments/assets/7d5a47ce-1ef8-4cb6-9e7d-b8785a930da5)

Hash cracked.

## LLMNR Poisoning Mitigation
