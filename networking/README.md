## Networking

**Tools**
- [Echo Mirage](https://resources.infosecinstitute.com/topic/echo-mirage-walkthrough/)
- [Wireshark](https://www.wireshark.org/)
- [PCredz](https://github.com/lgandx/PCredz)
- [Impacket](https://github.com/SecureAuthCorp/impacket)
  - `impacket-mssqlclient <user>:<password>@<IP> -windows-auth`
  - `impacket-psexec -hashes 00000000000000000000000000000000:<NTLM> <USERNAME>@<IP>`
  - `impacket-psexec <USERNAME>:<PASSWORD>@<IP>`
- [putty](https://www.putty.org/)
- [MobaXterm](https://mobaxterm.mobatek.net/)
- [proxychains](https://github.com/haad/proxychains)
- [Samba suite](https://www.samba.org/)
- [Enum](https://packetstormsecurity.com/search/?q=win32+enum&s=files)
- [Winfo](https://packetstormsecurity.com/search/?q=winfo&s=files)
- [enum4linux](https://www.kali.org/tools/enum4linux/)
- [macchanger](https://github.com/acrogenesis/macchanger)

#### Checking the routing table
```
ip route        on Linux box
route print     on Windows
netstat -r      on Mac OSX
```

#### Discover the MAC address
```
ip addr         on Linux
ipconfig /all   on Windows
ifconfig        on MacOS
```

#### Change MAC addess
- [How to change or spoof the MAC address in Windows (7 ways)](https://www.digitalcitizen.life/change-mac-address-windows/)
- [How to Change Your MAC Address on Linux](https://www.makeuseof.com/how-to-change-mac-address-on-linux/)
  - [macchanger](https://github.com/acrogenesis/macchanger)

#### Check listening ports and the current TCP connections
```
netstat -ano    on Windows
netstat -tunp   on Linux

on MacOS
--------
netstat -p tcp -p udp
lsof -n -i4TCP -i4UDP
```

#### Add new routes
```
ip route add <net_address_in_cdr> via <interface_gateway>                             on Linux
route add <net_address_in_cdr> mask <net_address_mask_in_cdr> <interface_gateway>     on Windows
nmap -sn <net_address_in_cdr>                                                         Check hosts alive, adding -A you gather more info for a target
```

#### Null session
```
Windows
-------
nbtstat /?                               help command
nbtstat -A <Target-IP>                   display information about a target
NET VIEW <Target-IP>                     enumerate the shares of a target
NET USE \\<Target-IP>\IPC$ '' /u:''      connect to a window share; connect to 'IPC$' share by using empty username and password

Linux
-----
nmblookup -A <Target-IP>                 same as nbtstat for Linux; display information about a target
smbclient -L //<Target-IP> -N            access Windows shares
smbclient //<Target-IP>/IPC$ -N          connect to a window share; connect to 'IPC$' share by using empty username and password

Enum
----
enum -s <Target-IP>                      enumerate the shares of a machine
enum -U <Target-IP>                      enumerate the users of a machine
enum -P <Target-IP>                      check the password policy of a machine

Winfo
-----
winfo <Target-IP> -n                     use winfo with null session

```

#### Enumeration
```
ip addr                                                                             query available network interfaces
ip route                                                                            enumerate network routes
for i in $(seq 1 254); do nc -zv -w 1 <octet>.<octet>.<octet>.$i <port>; done       bash loop with Netcat to sweep for port <PORT> in a subnet
```

#### Target analysis
- `tracert <target>` shows details about the path that a packet takes from the device sender to the target destination specified
- `for ip in $(echo '<IP>'); do ping -c 5 $ip; traceroute $ip; echo '\nnslookup'; nslookup $ip; done`

#### Check ARP cache
```
ip neighbour    on Linux
apr -a          on Windows
arp             on *nix OS
```

#### ARP Poisoning

1. The goal is to (1) trick the victim to save in the ARP Cache my MAC address (the attacker) associated it with the router IP and (2) the router to send the traffic back to you, this to perform a MITM
2. First, enable the Linux Kernel IP Forwarding to transform a Linux Box into a router `echo 1 > /proc/sys/net/ipv4/ip_forward`
3. Run arpspoof `arpspoof -i <interface> -t <target> -r <host>`
   - Check also [Ettercap](ettercap-project.org)

An example
1. `echo 1 > /proc/sys/net/ipv4/ip_forward`
2. `arpspoof -i eth0 -t 192.168.4.11 -r 192.168.4.16`


#### Well-known Ports

| Service       | Port          |
| ---           | ---           |
| SMTP          | 25            |
| SSH           | 22            |
| POP3          | 110           |
| IMAP          | 143           |
| HTTP          | 80            |
| HTTPS         | 443           |
| NETBIOS       | 137, 138, 139 |
| SFTP          | 115           |
| Telnet        | 23            |
| FTP           | 21            |
| RDP           | 3389          |
| MySQL         | 3306          |
| MS SQL Server | 1433          |
| Confluence    | 8090          |

#### Common Port Vulnerabilities

See : ["Open Port Vulnerabilities List by Dirk Schrader"](https://blog.netwrix.com/2022/08/04/open-port-vulnerabilities-list/)

| Ports | Vulnerabilities |
| ---  | --- |
| 20, 21 (FTP) | - Brute-forcing <br/>- Anonymous authentication (`anonymous` as username and password) <br/>- Cross-site scripting <br/>- Directory traversal attacks |
| 22 (SSH) | - leaked SSH keys <br/>- Brute-forcing |
| 23 (Telnet) | - Brute-forcing <br/>- Spoofing <br/>-Credential sniffing |
| 25 (SMTP) | - Spoofing <br/>- Spamming |
| 53 (DNS) | - DDoS |
| 137, 139 (NetBIOS over TCP) 445 (SMB) | - [EternalBlue](https://www.cisecurity.org/wp-content/uploads/2019/01/Security-Primer-EternalBlue.pdf) <br/>- Capturing NTLM hashes <br/>- Brute-force |
| 80, 443, 8080 and 8443 (HTTP and HTTPS) | - Cross-site Scripting (XSS) <br/>- SQL injections <br/>- Cross-Site Request Forgeries (CSRF) <br/>- DDoS |
| 1433,1434 and 3306 (SQL Server and MySQL) | - Default configurations <br/>- DDoS |
| 3389 (Remote Desktop) | - [BlueKeep](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2019-0708) <br/>- Leaked or weak user authentication |
| 8090 (Confluence) | [CVE-2022-26134](#cve-2022-26134) |
