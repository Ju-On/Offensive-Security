# Windows compatiable | Analysis tools | Web Analysis tools | Web reference with source | Debian changes

***********************

File Graber <Initialise and set newly created files, folders and droppers during dynamic analysis>

Apache OpenOffice <View hidden XLS files without needing Excel Licensing work https://openoffice.org>

Fiddler <Analyse dynamic network traffic> 

Process Hacker <Analyse processees during dynamic mode>

QR Code Scanner <https://qrcodescan.in/>

Burp Suite web and trafflic analysis tooling. Prior to any traffic captures, specific configurations is required in order for Burpe to efficiently capture any data for analysis. <https://thecybersecguru.com/tutorials/intercepting-web-traffic-with-burp-suite/>

***********************

Exploit database designed for Pentesting use cases and vulnerability researchers <Exploit-db.com>
It is CVE compliant archive of publicly available exploits.

NVD database of known exploits with ratings and links to advisories / githubs. <https://nvd.nist.gov/vuln/detail/CVE-2021-28169>

Global Malware Hunting <https://app.any.run/>

Virus Total <https://www.virustotal.com>

URL Void <URL reputation https://www.urlvoid.com/>

abuseipdb cursory checker of IPs and websites <https://www.abuseipdb.com>

CentraOps online toolset for network troubleshooting and reconnaissance, including WHOIS lookups, DNS queries, and traceroute. <https://centralops.net/co/)> 

MalwareBazaar <Malware sample repository https://bazaar.abuse.ch/>

***********************

Proxylife <https://twitter.com/search?q=xxe%20file&src=typed_query>

***********************

pdfstreamdumper to view hex and run scripts

***********************

Peekyou.com <Why do people use PeekYou?
PeekYou is a data broker website that advertises itself as a search engine for people, allowing users to look up anyone they want. The website functions by indexing individuals 
through easily accessible background information and combines it with active social media accounts.>

dehashed.com 

Pisieve to output and exfiltrate .dll packages specfically usefull to pull Qakbot C2s (Static C2s) - to view live without using PiSieve use
view memory > https > condition 7 and filter. Typcially viewable in the spawned wegmr.exe maybe also [regsvr32.exe / calc.exe]?

***********************

## Post Compromise Enumeration   

LinPEAS

WinPEAS

PSPY

Msfvenom Payload generator and packer.

python -m SimpleHTTPServer automatic http hosting of the current directory via port 8000.

Certutil basic CLI commandlet to grab files. <https://www.ired.team/offensive-security/defense-evasion/downloading-file-with-certutil>

***********************  

## Post Compromise Privilige Escalation   

**Linux/Unix Privilege Escalation**
GTFOBins <https://gtfobins.github.io/>

***********************

## Active Directory  

Responder - LLMNR Poisoning attacks / Capturing Hashes.  

Relayx  

Impacket a collection of Python scripts and libraries used for network protocol manipulation, exploitation, and lateral movement. Widely used to interact with Windows systems over SMB, WMI, RPC, LDAP, and other protocols.

MITM6 for IPv6 environments    

Metasploit Auxilliary modules  

## AD Post Compromise Enumeration

Bloodhound

PlumHound - Post domain enumeration tool <https://github.com/PlumHound/PlumHound/blob/master/README.md#installation-requirements>

## AD Post Compromise Attacks 

Secretsdump

Crackmapexec  

Mimikatz.exe  

***********************
## Venv  
(Virtual Environment) is a built-in Python module that creates an isolated environment for installing independant Python packages.
* Keeps dependencies separate from the system Python (prevents breaking system tools).
* Allows different Python projects to have different package versions.
* Prevents conflicts between system packages (apt) and user-installed packages (pip).
* Now required in Kali Linux due to PEP 668 (restricts global pip installs).

Step 1: Create a Virtual Environment  
    
    python3 -m venv venv
Step 2: Activate the Virtual Environment  
    
    source venv/bin/activate
Step 3: Install Packages Inside the Virtual Environment  
    
    pip install -r requirements.txt
Step 4: Deactivate the Virtual Environment  
   
    deactivate
Step 5: Reactivate the Virtual Environment (Later Use and in the same terminal as it was activated)  
    
    source venv/bin/activate

---

## Shell generator

Shell generator for different OS platforms - <https://www.revshells.com/>
