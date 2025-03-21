## Web Applicaiton Enumeration - Revisisted
This revisted section will primiarly focus on tools written in GoLang.

#### Assetfinder
A more modern directory busting tool. Requires GoLang to be installed on machine and downnloaded from git 

directory busting use:

    go install github.com/tomnomnom/assetfinder@latest

    assetfinder tesla.com 
    or
    assetfinder tesla.com --subs-only

custom bash script to parse only the subdomains related to the target:

    #!/bin/bash
    
    $url="example.com"
    
    if [ ! -d "$url" ]; then
        mkdir $url
    fi
    
    if [ ! -d "$url/recon" ]; then
        mkdir $url/recon
    fi
    
    echo "Harvesting subdomains with assetfinder"
    assetfinder $url >> $url/recon/assets.txt
    cat $url/recon/assets.txt | grep $1 >> $url/recon/final.txt
    rm $url/recon/assets.txt
