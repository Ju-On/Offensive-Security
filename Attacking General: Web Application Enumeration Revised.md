## Web Applicaiton Enumeration - Revisited
This revisted section will primiarly focus on tools written in GoLang. Providing other enumeration methodes as relying on a single tool can either not work in instances or miss important sub-domains.

#### 🔴 Assetfinder
A more modern directory busting tool. Requires GoLang to be installed on machine and downnloaded from git 

directory busting use:

    root@kali:go install github.com/tomnomnom/assetfinder@latest

    root@kali:assetfinder tesla.com 
    or
    root@kali:assetfinder tesla.com --subs-only

custom bash script to parse only the subdomains related to the target:  
chmod +x when created. This script parses out only domains related to the target in the newly **created recon dir as assets.txt**

    #!/bin/bash
    
    url="$1"
    
    if [ ! -d "$url" ]; then
        mkdir $url
    fi
    
    if [ ! -d "$url/recon" ]; then
        mkdir $url/recon
    fi
    
    echo "[+] Harvesting subdomains with assetfinder..."
    assetfinder $url >> $url/recon/assets.txt
    cat $url/recon/assets.txt | grep $1 >> $url/recon/final.txt
    rm $url/recon/assets.txt

#### 🔴 Amass by OWASP
Owasp open soruce tool designed to gather subdomain information and other DNS-related data, which can be crucial for network mapping, vulnerability identification, and attack surface analysis. amass should alreayd be installed on Kali by default, if not install to machine with the following:

    root@kali:go install -v github.com/owasp-amass/amass/v4/...@master

    root@kali:amass enum -d tesla.com

Adding Amass into the above existing parser

    echo "[+] Harvesting subdomains with Amass..."
    amass enum -d $url >> $url/recon/f.txt
    sort -u $url/recon/f.txt >> $url/recon/final.txt
    rm $url/recon/f.txt


