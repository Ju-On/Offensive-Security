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

