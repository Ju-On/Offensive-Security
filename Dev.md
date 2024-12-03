# Dev

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

Findings: 
22/tcp    open  ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp    open  http     Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Bolt - Installation error
111/tcp   open  rpcbind  2-4 (RPC #100000)
2049/tcp  open  nfs_acl  3 (RPC #100227)
8080/tcp  open  http     Apache httpd 2.4.38 ((Debian))
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
