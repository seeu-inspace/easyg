## Active Information Gathering

### <ins>DNS Enumeration</ins>

**host command**
```
host www.targetcorp.com                         Find the A host record
host -t mx www.targetcorp.com                   Find the MX record
host -t txt www.targetcorp.com                  Find the TXT record
host -l <domain name> <dns server address>      Perform a DNS zone transfer; -l: list zone
```

**Brute force forward DNS name lookups** using a list like `possible_subs.txt` containing common hostnames (see [SecLists](https://github.com/danielmiessler/SecLists)):
```
for ip in $(cat possible_subs.txt); do host $ip.megacorpone.com; done
```

**Brute force reverse DNS names**
```
for ip in $(seq 50 100); do host 38.100.193.$ip; done | grep -v "not found"
```

**Tools**
- DNSRecon
  ```
  dnsrecon -d zonetransfer.com -t axfr                      Perform a zone transfer; -t: specify the type of enumeration to perform
  dnsrecon -d zonetransfer.com -D ~/list.txt -t brt         Brute forcing hostnames
  ```
- DNSenum
  ```
  dnsenum zonetransfer.me                                   Perform a zone transfer
  ```
- [Wappalyzer](https://www.wappalyzer.com/)
- [WhatWeb](https://github.com/urbanadventurer/WhatWeb)
- [BuiltWith](https://builtwith.com/)


### <ins>Port Scanning</ins>

#### **Netcat**
```
nc -nvv -w 1 -z <IP> <PORT-RANGE>                        Use netcat to perform a TCP port scan
nc -nv -u -z -w 1 <IP> <PORT-RANGE>                      Use netcat to perform an UDP port scan
```

#### **Nmap**

```
nmap <IP>                                                            Simple nmap scan
nmap -p 1-65535 <IP>                                                 Scan all the ports
nmap -sS <IP>                                                        Stealth / SYN Scanning (will not appear in any application logs)
nmap -sT <IP>                                                        TCP connect scan
nmap -sU <IP>                                                        UDP scan
nmap -sS -sU <IP>                                                    Perform a combined UDP and SYN scan
nmap -sn <IP>                                                        Perform a network sweep
nmap -p 1-65535 -sV -T4 -Pn -n -vv -iL target.txt -oX out.xml        Discover everything including running services using a list of targets
nmap -sn <net_address_in_cdr>                                        Check hosts alive, adding -A you gather more info for a target
nmap -sT -A <IP-range>                                               Banner grabbing and/or service enumeration
nmap -sT -A --top-ports=20 <IP-range> -oG top-port-sweep.txt         Perform a top twenty port scan, save the output in greppable format
nmap -O <IP>                                                         OS fingerprinting
nmap -sV -sT -A <IP>                                                 Banner Grabbing, Service Enumeration

Find live hosts
---------------
nmap -v -sn <IP-range> -oG ping-sweep.txt
grep Up ping-sweep.txt | cut -d " " -f 2

Find web servers using port 80
------------------------------
nmap -p 80 <IP-range> -oG web-sweep.txt
grep open web-sweep.txt | cut -d " " -f 2

Nmap Scripting Engine (NSE)
---------------------------
nmap --script-help dns-zone-transfer                                  View information about a script, in this case "dns-zone-transfer"
nmap <IP> --script=smb-os-discovery                                   OS fingerprinting (SMB services)
nmap --script=dns-zone-transfer -p 53 ns2.zonetransfer.com            Perform a DNS zone transfer
nmap --script http-headers <IP>                                       OS fingerprinting (HTTP supported headers)
nmap --script http-title <IP>

Other usages
------------
nmap -vvv -A --reason --script="+(safe or default) and not broadcat -p - <IP>"

```

#### **Masscan**

```
masscan -p80 10.0.0.0/8                                               Look for all web servers using port 80 within a class A subnet
masscan -p80 10.11.1.0/24 --rate=1000 -e tap0 --router-ip 10.11.0.1   --rate specify the desired rate of packet transmission
                                                                      -e specify the raw network interface to use
                                                                      --router-ip specify the IP address for the appropriate gateway
```

#### Other tools

- [httprobe](https://github.com/tomnomnom/httprobe) designed to find web servers
  - `type subs.txt | httprobe -p http:81 -p http:3000 -p https:3000 -p http:3001 -p https:3001 -p http:8000 -p http:8080 -p https:8443 -c 150 > out.txt`
- [naabu](https://github.com/projectdiscovery/naabu) a fast port scanner
  - A simple usage using a list of subdomains: `naabu -v -list subs.txt -stats -o out.txt`
  - Discover everything faster, excluding some ports maybe already checked: `naabu -l 1.txt -v -p - -exclude-ports 80,443,81,3000,3001,8000,8080,8443 -c 1000 -rate 7000 -stats -o 1_o.txt`
- **Powershell**
  - SMB port scanning `Test-NetConnection -Port 445 <IP>`
  - `1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("<IP>", $_)) "TCP port $_ is open"} 2>$null`
- [nmapAutomator](https://github.com/21y4d/nmapAutomator)

### <ins>SMB Enumeration</ins>

**Resources**
- [smbclient](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html)
- [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec)
  - `crackmapexec smb <IP> -u usernames.txt -p passwords.txt --continue-on-success`
  - `crackmapexec smb <IP> -u <user> -p <password> --shares`
- ["A Little Guide to SMB Enumeration"](https://www.hackingarticles.in/a-little-guide-to-smb-enumeration/)

**Enumerate SMB Shares**
```
smbclient
---------
smbclient -L <IP>                                                     see which shares are available
smbclient //<IP>/<share>                                              connect to the SMB share
smbclient -p <port> -L //<IP>/ -U <username> --password=<password>    connect to the SMB share
get <file>                                                            get files

net
---
net view \\<IP> /All                                                  see which shares are available
net use \\<IP>\<share>                                                connect to the SMB share
copy \\<IP>\<share>\<file>                                            get files

more enumeration
----------------
sudo nmap -vvv -p 137 -sU --script=nbstat.nse 192.168.190.140
nmap -vvv -p 139,445 --script=smb* 192.168.228.63
crackmapexec smb 192.168.157.31 -u 'guest' -p ''
crackmapexec smb 192.168.228.63 -u '' -p '' --shares
- see anon logins
- use flags --shares and --rid-brute
smbclient \\\\\192.168.228.63\\
smbclient -U 'Guest' -L \\\\\192.168.134.126\\
smbclient --no-pass -L //192.168.203.172
enum4linux -a -u "CRAFT2\\thecybergeek" -p "winniethepooh" 192.168.203.188
```

**Connect to a share**
```
smbclient //192.168.134.126/print$
smbclient \\\\\192.168.212.172\\Shenzi
smbclient //192.168.203.172/DocumentsShare -U CRAFT2/thecybergeek
mount -t cifs -o rw,username=guest,password= '//10.10.10.103/Department Shares' /mnt
```

**Use nmap to scan for the NetBIOS service**<br/>
`nmap -v -p 139,445 -oG smb.txt 10.11.1.1-254`

**Use nbtscan to collect additional NetBIOS information**<br/>
`sudo nbtscan -r 10.11.1.0/24`

**Find various nmap SMB NSE scripts**<br/>
`ls -1 /usr/share/nmap/scripts/smb*`<br/>
Example: `nmap -v -p 139, 445 --script=smb-os-discovery <IP>`

**Determining whether a host is vulnerable to the MS08_067 vulnerability**
- `nmap -v -p 139,445 --script=smb-vuln-ms08-067 --script-args=unsafe=1 <IP>`
  - Note: the script parameter `unsafe=1`, the scripts that will run are almost guaranteed to crash a vulnerable system

**EternalBlue**
- https://redteamzone.com/EternalBlue/
- `nmap -Pn -p445 --open --max-hostgroup 3 --script smb-vuln-ms17-010 192.168.1.17`
- `sudo impacket-smbserver -smb2support share /home/kali/Documents/windows-attack/nc/`
First option
- `python 42315 10.10.10.4`
  - exploit: https://www.exploit-db.com/exploits/42315
Second option
- With AutoBlue-MS17-010
  1. `cd shellcode` > `./shell_prep.sh`
  2. run a listener
  3. `python eternalblue_exploit7.py 10.10.14.10 shellcode/sc_x64.bin`
Third option
- with metasploit
  - `use windows/smb/ms17_010_psexec`

**General notes**
- Remember that you can transfer files to the share with `copy <file> \\<IP>\share`
  - Also when using `sudo impacket-smbserver -smb2support share .`
- check if this smb hosts files of the web service, it might be possible to upload a shell
- maybe it's possible to do phishing
- nmap -Pn -p 139,445 --open --max-hostgroup 3 --script=smb-vuln* 10.10.10.4

### <ins>NFS Enumeration</ins>

**Find and identify hosts that have portmapper/rpcbind running using nmap**<br/>
`nmap -v -p 111 10.11.1.1-254`

**Query rpcbind in order to get registered services**<br/>
`nmap -sV -p 111 --script=rpcinfo 10.11.1.1-254`

**Nmap NFS NSE Scripts**<br/>
`ls -1 /usr/share/nmap/scripts/nfs*`<br/>
Run all these scripts with `nmap -p 111 --script nfs* <IP>`

**Example of entire /home directory shared**
```
Mount the directory and access the NFS share
--------------------------------------------
mkdir home
sudo mount -o nolock <IP>:/home ~/home/
cd home/ && ls

Add a local user
----------------
sudo adduser pwn                                         Add the new user "pwn"
sudo sed -i -e 's/1001/1014/g' /etc/passwd               Change the sed of the "pwn" user
cat /etc/passwd | grep pwn                               Verify that the changes have been made
```


### <ins>SMTP Enumeration</ins>

**Interesting commands**
- `VRFY` request asks the server to verify an email address
- `EXPN` asks the server for the membership of a mailing list
- Use telnet to connect to the target to gather information
  - `telnet <IP> 25`
- Port scanning with Powershell
  - `Test-NetConnection -Port 25 <IP>`

**Use nc to validate SMTP users**<br/>
`nc -nv <IP> 25`

**Use nmap for SMTP enumeration**<br/>
`nmap -p 25 --script=smtp-enum-users <IP>`

### <ins>SNMP Enumeration</ins>

**Use nmap to perform a SNMP scan**<br/>
`sudo nmap -sU --open -p 161 <IP-range> -oG open-snmp.txt`

**Use onesixtyone to brute force community strings**
1. Build a text file containing community strings
   ```
   echo public > community
   echo private >> community
   echo manager >> community
   ```
2. Build a text file containing IP addresses to scan<br/>
   `for ip in $(seq 1 254); do echo 192.168.45.$ip; done > ips`
3. Use [onesixtyone](https://github.com/trailofbits/onesixtyone)<br/>
   `onesixtyone -c community -i ips`

Note: Provided we at least know the SNMP read-only community string (in most cases is "public")<br/>
**Use snmpwalk to enumerate**<br/>
- The entire MIB tree: `snmpwalk -c public -v1 -t 10 <IP>`
  - `-c`: specify the community string
  - `-v`: specify the SNMP version number
  - `-t 10` to increase the timeout period to 10 seconds
-  Windows users: `snmpwalk -c public -v1 <IP> 1.3.6.1.4.1.77.1.2.25`
- Windows processes: `snmpwalk -c public -v1 <IP> 1.3.6.1.2.1.25.4.2.1.2`
- Installed software: `snmpwalk -c public -v1 <IP> 1.3.6.1.2.1.25.6.3.1.2`


### <ins>HTTP / HTTPS enumeration</ins>

- [httprobe](https://github.com/tomnomnom/httprobe)
  - example: `cat subdomains.txt | httprobe -p http:81 -p http:3000 -p https:3000 -p http:3001 -p https:3001 -p http:8000 -p http:8080 -p https:8443 -c 150 > output.txt`
- [naabu](https://github.com/projectdiscovery/naabu) + [httprobe](https://github.com/tomnomnom/httprobe), to find hidden web ports
  - example
    ``` 
    naabu -v -list subdomains.txt  -exclude-ports 80,443,81,3000,3001,8000,8080,8443 -c 1000 -rate 7000 -stats -o naabu.txt
    cat naabu.txt | httprobe > results.txt
    ```

### <ins>SSH enumeration</ins>

- Port `22`, connect with
  - `ssh <ip>`, `ssh <ip> -oKexAlgorithms=+<option>`, ``ssh <ip> -oKexAlgorithms=+<option>` -c <cipher>`
  - [PuTTY](https://www.putty.org/)
- Search for a banner, to get more info
