# Active Directory 101 - Reconnaissance to Exploitation

## Table of content:  

**Basic Concepts**  

**AD Pentesting Methodology**  
  Step 1: Getting Initial Access 🚪  
  Step 2: Enumerating AD 🔍  
  Step 3: Moving Laterally and Exploiting ⬅️➡️  
  Step 4: Persisting in AD 🔗

Active Directory is a directory service created by MS for Windows Domain networks. Included in most Windows Server Operating systems and can even operate in some non-Window based OS.

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

**LLMNR Attack:** Link Local Multicast Resolution previously called NBT-NS 

Reference <https://medium.com/@RootRouteway/hacking-active-directory-from-reconnaissance-to-exploitation-part-1-0ec218c4d533>
