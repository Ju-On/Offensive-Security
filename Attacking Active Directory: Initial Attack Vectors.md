Setup win2022 server  
Setup Peterparker account  
Setup Frankcastle account  

## LLMNR Poisoning
Link Local Multicast resolution  

Requirements: LLMNR attack can be performed if the LLMNR/NBT-NS is enabled and the attacker machine is in the same network as the target.
LLMNR attacks use the Responder tool which captures credentials that are broadcasted over the network when a user seek connection to a another service / resource that does not exists or is poorly configured. Through these vulnerabilities, Responder spoofs the request and responds by stating they know the service or resource. Requesting the victims NTLM hash.  

![image](https://github.com/user-attachments/assets/fc6902c4-acf7-4787-b2c8-607a7cd2900b)

Commonly used tooling for LLMNR Poisoning attacks:  
Responder, Impacket, MITM6

### Capturing Hashes with Responder
