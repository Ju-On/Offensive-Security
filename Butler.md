# Butler

Target: 192.168.64.136

# Nmap enumeration nmap -sV -A -T4 -p- 192.168.64.136
    Nmap scan report for 192.168.64.136                                                        
    Host is up (0.0015s latency).                                                              
    Not shown: 65523 closed ports                                                              
    PORT      STATE SERVICE       VERSION                                                      
    135/tcp   open  msrpc         Microsoft Windows RPC                                        
    139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn                                
    445/tcp   open  microsoft-ds?                                                              
    5040/tcp  open  unknown                                                                    
    7680/tcp  open  tcpwrapped                                                                 
    8080/tcp  open  http          Jetty 9.4.41.v20210516                                       
    | http-robots.txt: 1 disallowed entry                                                      
    |_/
    |_http-server-header: Jetty(9.4.41.v20210516)
    |_http-title: Site doesn't have a title (text/html;charset=utf-8).
    49664/tcp open  msrpc         Microsoft Windows RPC
    49665/tcp open  msrpc         Microsoft Windows RPC
    49666/tcp open  msrpc         Microsoft Windows RPC
    49667/tcp open  msrpc         Microsoft Windows RPC
    49668/tcp open  msrpc         Microsoft Windows RPC
    49669/tcp open  msrpc         Microsoft Windows RPC
    MAC Address: 00:0C:29:E5:A3:B4 (VMware)
    No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
    TCP/IP fingerprint:
    OS:SCAN(V=7.80%E=4%D=12/21%OT=135%CT=1%CU=31450%PV=Y%DS=1%DC=D%G=Y%M=000C29
    OS:%TM=6766C917%P=x86_64-pc-linux-gnu)SEQ(SP=10A%GCD=1%ISR=10A%TI=I%CI=I%II
    OS:=I%SS=S%TS=U)OPS(O1=M5B4NW8NNS%O2=M5B4NW8NNS%O3=M5B4NW8%O4=M5B4NW8NNS%O5
    OS:=M5B4NW8NNS%O6=M5B4NNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF
    OS:70)ECN(R=Y%DF=Y%T=80%W=FFFF%O=M5B4NW8NNS%CC=N%Q=)T1(R=Y%DF=Y%T=80%S=O%A=
    OS:S+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y
    OS:%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD
    OS:=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0
    OS:%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1
    OS:(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI
    OS:=N%T=80%CD=Z)
    
    Network Distance: 1 hop
    Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
    
    Host script results:
    |_clock-skew: 18h59m59s
    |_nbstat: NetBIOS name: BUTLER, NetBIOS user: <unknown>, NetBIOS MAC: 00:0c:29:e5:a3:b4 (VMware)
    | smb2-security-mode: 
    |   2.02: 
    |_    Message signing enabled but not required
    | smb2-time: 
    |   date: 2024-12-22T08:56:24
    |_  start_date: N/A
    
    TRACEROUTE
    HOP RTT     ADDRESS
    1   1.48 ms 192.168.64.136
    
    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 544.32 seconds

## Nmap scan 1 results:
    135/tcp   open  msrpc         Microsoft Windows RPC                                        
    139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn                                
    445/tcp   open  microsoft-ds?                                                              
    5040/tcp  open  unknown                                                                    
    7680/tcp  open  tcpwrapped                                                                 
    8080/tcp  open  http          Jetty 9.4.41.v20210516                                       
    | http-robots.txt: 1 disallowed entry                                                      
    |_/
    |_http-server-header: Jetty(9.4.41.v20210516)
    
## Port 8080 
![image](https://github.com/user-attachments/assets/3c70c2f7-dcf9-4851-a86a-2736dcfa0199)

![image](https://github.com/user-attachments/assets/52a631a1-0dfe-4082-a915-dea8619810d1)

## Scan using nmap --script vuln 192.168.64.136
    Nmap done: 1 IP address (1 host up) scanned in 20.42 seconds
    root@kali:/home/kali# nmap --script vuln 192.168.64.136
    Starting Nmap 7.80 ( https://nmap.org ) at 2024-12-21 10:03 EST
    Pre-scan script results:
    | broadcast-avahi-dos: 
    |   Discovered hosts:
    |     224.0.0.251
    |   After NULL UDP avahi packet DoS (CVE-2011-1002).
    |_  Hosts are all up (not vulnerable).
    Nmap scan report for 192.168.64.136
    Host is up (0.00033s latency).
    Not shown: 996 closed ports
    PORT     STATE SERVICE
    135/tcp  open  msrpc
    |_clamav-exec: ERROR: Script execution failed (use -d to debug)
    139/tcp  open  netbios-ssn
    |_clamav-exec: ERROR: Script execution failed (use -d to debug)
    445/tcp  open  microsoft-ds
    |_clamav-exec: ERROR: Script execution failed (use -d to debug)
    8080/tcp open  http-proxy
    |_clamav-exec: ERROR: Script execution failed (use -d to debug)
    | http-enum: 
    |_  /robots.txt: Robots file
    MAC Address: 00:0C:29:E5:A3:B4 (VMware)
    
    Host script results:
    |_samba-vuln-cve-2012-1182: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
    |_smb-vuln-ms10-054: false
    |_smb-vuln-ms10-061: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
    
    Nmap done: 1 IP address (1 host up) scanned in 57.23 seconds

## Jetty9 looks to be interesting given there is an active Jenkins website om 8080
Through Googling, we have disocvered a Medium potential vulnerability that may provide some information disclosure.

### Jetty 9.4.41.v20210516 / Debian: CVE-2021-28169: jetty9 -- security update
    NVD: https://nvd.nist.gov/vuln/detail/CVE-2021-28169
    Rapid7: https://www.rapid7.com/db/vulnerabilities/debian-cve-2021-28169/

Exploit: /concat?/%2557EB-INF/web.xml

After some attempts of the above exploit and further research, no vulnerabilities can be found associated with the Jetty 9.4.41 version yet.

## Tried to connect to the SMB port with no access.
        root@kali:/home/kali# smbclient -L //192.168.64.136 -p 445
        Enter WORKGROUP\root's password: 
        session setup failed: NT_STATUS_ACCESS_DENIED
        root@kali:/home/kali# 

