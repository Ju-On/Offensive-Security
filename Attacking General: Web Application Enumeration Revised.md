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

assetfinder script with amass commented out:
![image](https://github.com/user-attachments/assets/302fe96d-6599-4663-8040-565d4dc11103)

---

#### 🔴 Httprobe - Finding live domains  
More modern GoLang tool to test list of domains and probe for working HTTP and HTTPS servers. <https://github.com/tomnomnom/httprobe?tab=readme-ov-file#prefer-https> 

To install and run:  

    root@kali:go install github.com/tomnomnom/httprobe@latest
    or
    root@kali:apt install httprobe

once installed httprobe can run on the command line with an exising list of domains to present the subdomains that are live:  

    root@kali:/home/kali/fire/tesla.com/recon# cat final.txt | httprobe
    https://dal11-gpgw1.tesla.com
    https://ams13-gpgw1.tesla.com
    https://hnd13-gpgw1.tesla.com
    https://lax32-gpgw1.tesla.com
    https://iad05-gpgw1.tesla.com
    http://itanswers.tesla.com

to surpress non responsive default ports such as 80 / 443 use the '| httprobe -s -p https:443' -p is to specify what to scan, here i have specified https:443 again after excluding 80 with -s, and return successful HTTP or HTTPS responses.  

    root@kali:/home/kali/fire/tesla.com/recon# cat final.txt | httprobe -s -p https:443
    https://ams13-gpgw1.tesla.com:443
    https://hnd13-gpgw1.tesla.com:443
    https://lax32-gpgw1.tesla.com:443
    https://iad05-gpgw1.tesla.com:443
    https://sin05-gpgw1.tesla.com:443
    http://engage.tesla.com:443
    http://trumpstesla.com:443
    
to remove https:// and :443 add '| sed 's/https\?:\/\///' | sed 's/:443//'  

    root@kali:/home/kali/fire/tesla.com/recon# cat final.txt | httprobe -s -p https:443 | sed 's/https\?:\/\///' | sed 's/:443//'
    dal11-gpgw1.tesla.com
    ams13-gpgw1.tesla.com
    hnd13-gpgw1.tesla.com
    lax32-gpgw1.tesla.com
    iad05-gpgw1.tesla.com

**🔵 Note**: when conducting any engagement, it's best to check all ports of the domains found, unless we need to specifically narrow it down. For example above we are only looking for any domains responsive to only https:443. Therefore we should list out all live domains, clean the results and feed it through a nmap scanner.  

Example for more general scan for all default ports wiht removal of http/s:

    root@kali:/home/kali/fire/tesla.com/recon# cat final.txt | httprobe | sed 's/https\?:\/\///'

Combining the resppnsive (http:443) probe to our script:  

    echo "[+] Probing for alive domains..."
    cat $url/recon/final.txt | sort -u | httprobe -s -p https:443 | sed 's/https\?:\/\///' | sed 's/:443//' >> $url/recon/alive.txt

![image](https://github.com/user-attachments/assets/f9d893fb-40ff-47fc-bad3-b0bcc9b6aab2)

Now this script will execute domain enumeration either through assetfinder or amass and output into the 'final.txt'.  
The domains in 'final.txt' will be httpprobed with the current condition to only look for responsive http:443 domains, with http/s, :443 and duplicates removed and placed into 'alive.txt' for further use. 
    

    
