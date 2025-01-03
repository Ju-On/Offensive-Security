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

gobuster dir -w /usr/share/wordlists/rockyou.txt --no-error -u http://192.168.64.137/ -v | grep "Status: 200" 
[image]
rockyou.txt
