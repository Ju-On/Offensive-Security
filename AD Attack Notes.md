# Active Directory 101 - Reconnaissance to Exploitation

## Table of content:  

**Basic Concepts**  

**AD Pentesting Methodology**  
  Step 1: Getting Initial Access 🚪  
  Step 2: Enumerating AD 🔍  
  Step 3: Moving Laterally and Exploiting ⬅️➡️  
  Step 4: Persisting in AD 🔗

Active Directory is a directory service created by MS for Windows Domain networks. Included in most Windows Server Operating systems and can even operate in some non-Window based OS.

-------

## Key Concept

**Domain Servces:** AD DS stores directory data, manages communication between users and domains. These include user logon processes, authentication and directory searchers.

**Objects and Attributes:** Everything in AD is considered an object, each object represents a single entity. This can be a user, printer or group. Each object has attributes which are the associations attached to it.

**Organisational Units:** OUs are containers within a domain, OUs can contain users, groups, computers and other OUs. They help create a hierarchical structure within a domain and facilitate the delegation of administrative control.

**Groups:** Groups are a collection of objects, these can include users, computers and other groups. Groups help manage permissions and access to other resources in a simplified way.

**Trusts:** Trusts are established between domains to allow users in one domain to access resources in another. 

**Group Policy:** Group Policy provides centralized management and configuration of operating systems, applications, and users’ settings in an Active Directory environment.

**NTLM:**  (New Technology LAN Manager)hashes are cryptographic representations of user passwords used for authentication in Windows environments. used for network authentication and remote access, especially in legacy systems or as a fallback for Kerberos.

**NetNTLM authentication:** NetNTLM works using a challenge-response mechanism.

-------

## AD Pentesting Methodology

**Obtaining initiall credentials**

🔴 **LLMNR Attack:** 

Link Local Multicast Resolution previously called NBT-NS is a network protocol that is still in use for Windows environments for name    resolution. Operating on port 137 it is used as a fallback mechanism when DNS is not available or fails to resolve names.

The requirements to perform this attack requires LLMNR/NBT-NS protocol enabled and the attacker has to be on the samee network as the target.

In order to perform this attack you need to use the Responder tool which is used to capture credentials and other sensitive information. It works by responding to certain network protocol requests, such as LLMNR/NBT-NS, and MDNS, which are typically broadcasted by devices on a local network. From the attacker machine run the below command and wait for traffic to be captured by Responder:

    sudo responder -I eth0 -dwPV
    #d:enable answer for DHCP broadcast
    #w:Start the WPAD rogue proxy server
    #P: force the NTLM authentication for the the proxy  

You will then get username ad hash as shown below :

  ![image](https://github.com/user-attachments/assets/aa31c708-a469-4ac7-a851-b9a8fde40a81)

Once the NTLM hashes are acquired, you can now use multiple ways to crack the hash.

    hashcat -m 5600 llmnr_hash.txt /usr/share/wordlists/rockyou.txt 

🔴**SMBRelay Attack:**

A type of network attack where authentication requests and responses are intercepted between client and a server.  
It can act as a secondary attempt fall back when hash cracking has failed, as the intercepted hash can be directly relayed to authenticate with a server, removing the requirement for hash cracking.

Requirements:

* SMB signing is disabled or not enforced.

* The relayed user credentials have administrative privileges on the target machine.

* The attacker’s machine must be on the same network as the victim’s machine.

To perform this, the attacker must identify the list of machines that meet the requirements above and have it saved in a file e.g victims.txt.

Using Responder, disable SMB and HTTP in the configs file.

    sudo responder -I eth0 -dwPv

launch “Impacket-ntlmrelayx.py,” which will take the hashes captured by Responder and relay them to the list of victims specified in the victims.txt file:

    impacket-ntlmrelayx -tf victims.txt -smb2support

When network traffic is generated, we will get hashes corresponding to the victims where the relay process has succeeded:

![image](https://github.com/user-attachments/assets/092903a7-6f48-4b9e-a9b0-ca82570b4759)

🔴 **IPV6 DNS Takeover ATTACK**  






  
------- 
**Reference:**  
<https://medium.com/@RootRouteway/hacking-active-directory-from-reconnaissance-to-exploitation-part-1-0ec218c4d533>  

<https://medium.com/@RootRouteway/hacking-active-directory-from-reconnaissance-to-exploitation-part-2-f2630b836e73>
