# Linux | Active Directory | Analysis tools | Web Analysis tools | Web reference with source | Debian changes

## General file resources

python3 -c 'for i in range (1,2001): print(i)' > range.txt | create a range txt file from 1-2000

---

## General Analysis
File Graber <Initialise and set newly created files, folders and droppers during dynamic analysis>

Apache OpenOffice <View hidden XLS files without needing Excel Licensing work https://openoffice.org>

Fiddler <Analyse dynamic network traffic> 

Process Hacker <Analyse processees during dynamic mode>

QR Code Scanner <https://qrcodescan.in/>

Burp Suite web and trafflic analysis tooling. Prior to any traffic captures, specific configurations is required in order for Burpe to efficiently capture any data for analysis. <https://thecybersecguru.com/tutorials/intercepting-web-traffic-with-burp-suite/>

---

## Web Enumeration
Gobuster - great for directory busting

assetfinder <github.com/tomnomnom/assetfinder@latest>

ffuf - directory and subdomain busting

dnsrecon -r - good for enumerating an IP address for it's PTR records to see reverse mappings of IPs to domains.

subfinder -d - good for subdomain hunting

---

## Web App Attacks  
Alex Olsen Collection of Web Attacks - <https://appsecexplained.gitbook.io/appsecexplained>

---

## Vulnerabilities
Exploit database designed for Pentesting use cases and vulnerability researchers <Exploit-db.com>
It is CVE compliant archive of publicly available exploits

NVD database of known exploits with ratings and links to advisories / githubs. <https://nvd.nist.gov/vuln/detail/CVE-2021-28169>

--- 
## Analysis
Global Malware Hunting <https://app.any.run/>

Virus Total <https://www.virustotal.com>  

URL Void <URL reputation https://www.urlvoid.com/>  

abuseipdb cursory checker of IPs and websites <https://www.abuseipdb.com>  

CentraOps online toolset for network troubleshooting and reconnaissance, including WHOIS lookups, DNS queries, and traceroute. <https://centralops.net/co/)>  

MalwareBazaar <Malware sample repository https://bazaar.abuse.ch/>  

Proxylife <https://twitter.com/search?q=xxe%20file&src=typed_query>  

pdfstreamdumper to view hex and run scripts  

---

## OSINT
Peekyou.com <Why do people use PeekYou?
PeekYou is a data broker website that advertises itself as a search engine for people, allowing users to look up anyone they want. The website functions by indexing individuals 
through easily accessible background information and combines it with active social media accounts.>

dehashed.com 

Pisieve to output and exfiltrate .dll packages specfically usefull to pull Qakbot C2s (Static C2s) - to view live without using PiSieve use view memory > https > condition 7 and filter. Typcially viewable in the spawned wegmr.exe maybe also [regsvr32.exe / calc.exe]?

phonebook.cz

hunter.io

hunch.ly

---

## Linux Post Compromise Enumeration   
LinPEAS

PSPY

Msfvenom Payload generator and packer.

Msfconsole multi handler 'use explot/multi/handler' 

[python2] python -m SimpleHTTPServer - automatic http hosting of the current directory via port 8000.

[python3] python3 - python3 -m http.server 8080

python -m pyftpdlib - automatic hosting of the current dirrectory via port 2121.

Certutil basic CLI commandlet to grab files. <https://www.ired.team/offensive-security/defense-evasion/downloading-file-with-certutil>

---  

## Linux Post Compromise Privilige Escalation   
**Linux/Unix Privilege Escalation**
GTFOBins <https://gtfobins.github.io/>

---

## Windows Initial Compromise Active Directory  
nmap --script=smb2-security-mode.nse -p445 10.0.0.0/24 -Pn / other modes can be used for other forms of vuln / service type scanning 

Responder - LLMNR Poisoning attacks / Capturing Hashes.  

Relayx - Tool used with Responder to act as a man in the middle, capturing hashes from sender to service (relay) 

Impacket a collection of Python scripts and libraries used for network protocol manipulation, exploitation, and lateral movement. Widely used to interact with Windows systems over SMB, WMI, RPC, LDAP, and other protocols.

MITM6 for IPv6 environments    

Metasploit Auxilliary modules  

## Windows Post Compromise Enumeration  

UAC Bypass Techniques: <https://github.com/hfiref0x/uacme>  

ldapdomaindump - identify high-priv accounts (such as Domain Admins), weak settings, service accounts, or vulnerable trust relationships. Only applicable when IPv6 is turned, can also act as an alternative if mitm6 fails to dump information due to no IPv6 DHCP or misconfig. ldapdomain dump can be used to attempt a dump using both IPv6 and IPv4.

Bloodhound

PlumHound - Post domain enumeration tool <https://github.com/PlumHound/PlumHound/blob/master/README.md#installation-requirements>

PingCastle

Executables:  
* WinPEAS <https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS>  
* Seatbelt.exe <https://github.com/GhostPack/Seatbelt>  
* Watson.exe <https://github.com/rasta-mouse/Watson>  
* SharpUp.exe <https://github.com/GhostPack/SharpUp>  

PowerShell:  
* Sherlock.ps1 <https://github.com/rasta-mouse/Sherlock>  
* PowerUp.ps1 <https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc>  
* jaws-enum.ps1 <https://github.com/411Hall/JAWS>  

Other:  
* (ran on attacker by providing sysinfo of target) windows-exploit-suggester.py <https://github.com/AonCyberLabs/Windows-Exploit-Suggester>  
* (Metasploit) Exploit Suggester <https://blog.rapid7.com/2015/08/11/metasploit-local-exploit-suggester-do-less-get-more/>  

## Windows AD Post Compromise Attacks 
Secretsdump - use different modules such as smb, ldap etc  

Crackmapexec - use for pass attacks / handy to enumerate entire networks with credentials / hashes found and identify the type of services it is running. Crackmapexec also has a range of other functionalities not only just domain enumeration. <https://github.com/byt3bl33d3r/CrackMapExec/tree/master>  

impacket-GetUsersSPNs - use for kerberoasting attacks, where we attain a TGS from the DC, crack the krbtgt hash and use the Service Principle name with the password to access to the service account.  

Psexec  

Mimikatz.exe <https://github.com/gentilkiwi/mimikatz>  

---

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

Reverse shell cheat sheet - <https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md>  
