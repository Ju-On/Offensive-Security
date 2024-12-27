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

**CVE-2023-26049** Cookie Parser may leak information. 'There is a vulnerability in Eclipse Jetty that could allow a remote authenticated attacker to obtain sensitive information on the system.'  We are no an authenticated attacker.

**CVE-2021-34429** 'The vulnerability allows a remote attacker to gain unauthorized access to otherwise restricted functionality.
tried installing docker compose to see if i can download and replicate the Jetty infra. No success in downloading Docker Compose at all.

## GoBuster for website enumeration.
    gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --no-error -u http://192.168.64.136:8080/ --exclude-length 620 -v | grep "Status: 200"    

    root@kali:/home/kali# gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --no-error -u http://192.168.64.136:8080/ --exclude-length 620 -v | grep "Status: 200"
    Found: /login                (Status: 200) [Size: 2028]
    Found: /oops                 (Status: 200) [Size: 6503]

    Explanation:
    --no-error: Suppresses error messages.
    --exclude-length 620: Excludes responses with a length of 620 (likely irrelevant results).
    -v: Enables verbose mode to show more detailed output.
    | grep "Status: 200": Filters the output to show only positive hits where the status code is 200.

## Wfuzz for website enumeration.
    wfuzz -c -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --hc 404 http://192.168.64.136:8080/FUZZ

    Explanation:
    -c:
    
    Enables colored output for better visibility.
    -z file,<path_to_wordlist>:
    
    Specifies the input method (a file-based wordlist in this case).
    Replace <path_to_wordlist> with the location of your wordlist (e.g., /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt). --hc 404:
    
    Excludes responses with an HTTP status code of 404 (Not Found) to reduce noise.
    http://192.168.64.136:8080/FUZZ:

    Seems like Wfuzz does not like the target machine. 
    
    root@kali:/home/kali# wfuzz -c -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --hc 404 http://192.168.64.136:8080/FUZZ
    
    Warning: Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
    
    ********************************************************
    * Wfuzz 2.4 - The Web Fuzzer                           *
    ********************************************************
    
    Target: http://192.168.64.136:8080/FUZZ
    Total requests: 220560
    
    ===================================================================
    ID           Response   Lines    Word     Chars       Payload                           
    ===================================================================
    
    Fatal exception: Pycurl error 7: Failed to connect to 192.168.64.136 port 8080: Connection refused

## Try found out more details on 192.168.64.136:8080 | curl -I http://192.168.64.136:8080
    root@kali:/home/kali# curl -i http://192.168.64.136:8080
    HTTP/1.1 403 Forbidden
    Date: Mon, 23 Dec 2024 14:18:13 GMT
    X-Content-Type-Options: nosniff
    Set-Cookie: JSESSIONID.6dd96482=node016xz31g05zqmvnn516yomsoak2.node0; Path=/; HttpOnly
    Expires: Thu, 01 Jan 1970 00:00:00 GMT
    Content-Type: text/html;charset=utf-8
    X-Hudson: 1.395
    X-Jenkins: 2.289.3
    X-Jenkins-Session: 19bdc77b
    Content-Length: 548
    Server: Jetty(9.4.41.v20210516)
    
    <html><head><meta http-equiv='refresh' content='1;url=/login?from=%2F'/><script>window.location.replace('/login?from=%2F');</script></head><body style='background-color:white; color:white;'>
    
    
    Authentication required
    <!--
    -->

</body></html>

## List of Jenkin vulnerabilities:
    https://www.cvedetails.com/vulnerability-list/vendor_id-15865/product_id-34004/version_id-1127237/Jenkins-Jenkins-2.289.3.html?page=2&order=1

**CVE-2024-43044** High The exploit will use the vulnerability to read files to forge a remember-me cookie for an admin account and gain access to Jenkins scripting engine. 

**CVE-2024-43044** Checker Python script. https://github.com/HwMex0/CVE-2024-43044?tab=readme-ov-file
Downloaded the custom script to identify if the current Jenkins version is vulnerable to CVE-2024-43044
    
    root@kali:/home/kali# python3 CVE-2024-43044.py http://192.168.64.136:8080
    [+] http://192.168.64.136:8080 (Jenkins Version: 2.289.3) is potentially vulnerable.
    root@kali:/home/kali# 

**POC:** https://github.com/convisolabs/CVE-2024-43044-jenkins

To firstly exploit Jenkins in this case we need to figure the 'Agent Node' if it is allowed on the endpoint without authentication.

Common Jenkins Endpoints to Test:

    Script Console:
    curl -i http://192.168.64.136:8080/computer/

    Manage Jenkins:
    curl -i http://192.168.64.136:8080/manage

    Jenkins API:
    curl -i http://192.168.64.136:8080/api/json

Test for Anonymous Access:

    Node Listings:
    curl -i http://192.168.64.136:8080/computer/

None of these command lines worked, making this slightly more diffuclt. In this instance, we could take it a step further and exploit another vulnerability against Jenkins or Jetty and attempt for it to disclose the Agent Header information to potential get one step further into exploiting CVE-2024-43044. In a real life scenario, this would probably be attempted but at this point it is clear for this box alone. It is beyond the scope and the design intentions.

## Furhter enumeration using Nikto web vulnerability scanner | nikto -h http://192.168.64.136:8080
    root@kali:/home/kali# nikto -h http://192.168.64.136:8080
    - Nikto v2.1.6
    ---------------------------------------------------------------------------
    + Target IP:          192.168.64.136
    + Target Hostname:    192.168.64.136
    + Target Port:        8080
    + Start Time:         2024-12-24 01:36:01 (GMT-5)
    ---------------------------------------------------------------------------
    + Server: Jetty(9.4.41.v20210516)
    + The anti-clickjacking X-Frame-Options header is not present.
    + The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
    + Uncommon header 'x-jenkins' found, with contents: 2.289.3
    + Uncommon header 'x-jenkins-session' found, with contents: d22a90da
    + Uncommon header 'x-hudson' found, with contents: 1.395
    + All CGI directories 'found', use '-C none' to test none
    + Uncommon header 'x-hudson-theme' found, with contents: default
    + Uncommon header 'x-instance-identity' found, with contents: MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw43hS+kkhDV0LAwc2YVGFglH5IN1zZfBknSOOnM8uzQe2KSrC0PdLp+bTTNiK80Ill04oLGN5LBVAxwJ0koN0X2FPwGLqM6lJQlw9sESCUK0r6SfyTJJMZbsMaUKgwSFePnEbbheH4tPmNxGtI71812KggjsT22Oi5jKHv3rt2OM3dTa4Ma6jwLwke1Iz/rIYmRuW2pUanPVvyg7V2ZiWfqkMkWWs0WN9Y1MnGfyDrIGMYlDIFDZ1w2J25tBTzCR/tWMXOzyZh34hsbZX8a1bzFa7q+DsfL0D/hdDIG6pOuBO8JhffUsKe7qr4Xp2HQ1z/3AQLo4xYq8ojWOq7xX6wIDAQAB
    + Uncommon header 'cross-origin-opener-policy' found, with contents: same-origin
    + 26546 requests: 0 error(s) and 8 item(s) reported on remote host
    + End Time:           2024-12-24 01:36:57 (GMT-5) (56 seconds)
    ---------------------------------------------------------------------------
    + 1 host(s) tested

      *********************************************************************

Besides finding the public key usd in the x-instance-identity, no other direct findings can be found here. The base64 public key is normal information that is typically left disclosed and does not normally provide any direct attack opportunities.

## Look to try exploiting the website directly next

![image](https://github.com/user-attachments/assets/8a6b42d3-5e28-4166-8d58-a408a55639ca)

First attempt at traffic interception with proxy.

![image](https://github.com/user-attachments/assets/b03352d6-ed03-4cc8-a539-756a0923df46)

## Tried to modify the session cookie with the one found in previous curl -I and Repat it back towards 192.168.64.136:8080 login page findings with no success.

![image](https://github.com/user-attachments/assets/990194ae-931a-4621-b04a-0266003dca65) 

![image](https://github.com/user-attachments/assets/ab057963-51ff-4ed0-8eed-2b74114819fb)

Change test1 with username and test1 to password. Attack type: Cluster bomb to make attempts against username and password spraying.

![image](https://github.com/user-attachments/assets/d2c5bb79-1aea-47ce-b79a-a222cfc3422b)

Payload Sets 1 (username)

![image](https://github.com/user-attachments/assets/842c60fd-806b-419d-a293-6fc669d1ebbe)

Payload sets 2 (password)

## Changed burpe Payload Sets 1 and 2 to Smalllist.txt


Try to perform password spraying against target on 8080 with a common list of user names and passwords next in Burpe Suite.

## Tried to connect to the SMB port with no access.
    root@kali:/home/kali# smbclient -L //192.168.64.136 -p 445
    Enter WORKGROUP\root's password: 
    session setup failed: NT_STATUS_ACCESS_DENIED
    root@kali:/home/kali# 

