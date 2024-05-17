# Check-lists*

*Note: Check-lists and cheat-sheets :)

## Index

- [General checklists](#general-checklists)
- [Toolset](#toolset)
- [Testing layers](#testing-layers)
- [Penetration Testing cycle](#penetration-testing-cycle)
  - [0. Defining the Scope](#0-defining-the-scope)
  - [1. Information gathering](#1-information-gathering)
  - [2. Service enumeration](#2-service-enumeration)
  - [3. Cicle](#3-cicle)
  - [4. House keeping](#4-house-keeping)
  - [5. Results](#5-results)
- [Penetration Testing process](#penetration-testing-process)
  - [1. Public Network Enumeration](#1-public-network-enumeration)
  - [2. Attack a Public Machine](#2-attack-a-public-machine)
  - [3. Internal Network Access](#3-internal-network-access)
  - [4. Internal Network Enumeration](#4-internal-network-enumeration)
  - [5. Domain Controller Access](#5-domain-controller-access)
- [Bug Bounty Hunting](#bug-bounty-hunting)
  - [Top vulnerabilities to always look for](#top-vulnerabilities-to-always-look-for)
  - [Multiple targets](#multiple-targets)
  - [Single target](#single-target)


## General checklists

- [SMB-Checklist](https://github.com/pentesterzone/pentest-checklists/blob/master/Services/SMB-Checklist.md)
- [Win32 Offensive Cheatsheet](https://github.com/matthieu-hackwitharts/Win32_Offensive_Cheatsheet)
- [Regexp Security Cheatsheet](https://github.com/attackercan/regexp-security-cheatsheet)
- [Cheat-Sheet - Active-Directory](https://github.com/drak3hft7/Cheat-Sheet---Active-Directory)
- [Security Testing of Thick Client Application](https://medium.com/@david.valles/security-testing-of-thick-client-application-15612f326cac)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [OSSTMM](https://isecom.org/research.html)
- [MindMaps](https://github.com/imran-parray/Mind-Maps)

## Toolset
- [ ] [EasyG](../scripts/) and all the connected tools
- [ ] [Burp Suite](#burp-suite) and all the extensions
- [ ] [Kali Linux](https://www.kali.org/) + [install.sh](https://github.com/seeu-inspace/install.sh) since it has everything you need 

## Testing layers

See [The Bug Hunter's Methodology v4.0 - Recon Edition by @jhaddix #NahamCon2020!](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [ ] Integrations
- [ ] Application Libraries (usually JavaScript)
- [ ] Application: Custom Code or COTS
- [ ] Application Framework
- [ ] Web Hosting Software (Default creds, Web server misconfigurations, web exploits)
- [ ] Open Ports and Services (Default creds on services, service level exploits)

## Penetration Testing cycle

### 0. Defining the Scope

### 1. Information gathering
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

### 2. Service enumeration
- [Active Information Gathering](#active-information-gathering)
- Finding subdomains
  - [Google Fu](#google-dorking)
  - [EasyG](#easyg)
- Fingerprinting
  - [nmap](#nmap), [Wappalyzer](https://www.wappalyzer.com/), [WhatWeb](https://github.com/urbanadventurer/WhatWeb), [BuiltWith](https://builtwith.com/)
- [Content Discovery](#content-discovery)
- [Vulnerability Scanning](#vulnerability-scanning)

### 3. Cicle
- Penetration
  - Initial Foothold
  - Privilege Escalation
  - Lateral Movement
- Maintaining access (Trojans)

### 4. House keeping
- Cleaning up rootkits
- Covering tracks
- See: [Post Exploitation - The Penetration Testing Execution Standard](http://www.pentest-standard.org/index.php/Post_Exploitation)

### 5. Results
- Reporting / Analysis
- Lessons Learned / Remediation


## Penetration Testing process

- Setup the environment
  - Create a dedicated folder
  - Create files like `creds.txt` and `computers.txt`
  - Notes every service found, domain, host etc.
- Check that the targets are valid and owned by client

### 1. Public Network Enumeration

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

### 2. Attack a Public Machine

1. Exploit the machine
   - Example: exploit a Directory Traversal in a Web Application to gain `/etc/passwd` or SSH private keys, like `id_rsa` or `id_ecdsa`
2. Use what you found to access the machine
   - Example: crack the password of `id_rsa` with `ssh2john id_rsa > ssh.hash` and `john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash`, then gain access with `ssh -i id_rsa <username>@<IP>`
3. Elevate your privileges
   - Run `PowerUp.ps1` `Invoke-AllChecks` in Windows
   - Run [Privesc](https://github.com/enjoiz/Privesc)
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

### 3. Internal Network Access

- Password attack: test the credentials found to gain more accesses
  - use `crackmapexec` or similar
- Explore the services found
  - Example: enumerate SMB shares with `crackmapexec smb <IP> -u <user> -p <password> --shares`
- Client-side attacks
  - Perform a Phishing attack
  - If you have more information, you could leverage Microsoft Office or Windows Library Files

### 4. Internal Network Enumeration

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

### 5. Domain Controller Access

- Elevate your privileges to `NT AUTHORITY\SYSTEM`
- Lateral Movement
  - Leverage the privileges to get access to the other machines
  - Use `Golden Ticket` and `Rubeus.exe`
- Obtain `ntds.dit`, located at `%SystemRoot%\NTDS`


## Bug Bounty Hunting

### Top vulnerabilities to always look for
- [ ] XSS
- [ ] CSRF
- [ ] Authorization issues
- [ ] IDOR

### Multiple targets
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
- [ ] If IPs are in scope: `cat ip.txt | dnsx -ptr -resp-only`

### Single target
- [ ] Recon
  + Explore the app, test every functionality (eventually, search for documentation)
  + Crawl with Burp Suite
  + Collect endpoints with [BurpJSLinkFinder](https://github.com/InitRoot/BurpJSLinkFinder)
  + [Content Discovery](../web-vulnerabilities/#content-discovery), use tools, [Google Dorking](../web-vulnerabilities/#google-dorking) and [GitHub Dorking](../web-vulnerabilities/#github-dorking)
  + Check the [Testing layers](../web-vulnerabilities/#testing-layers)
  + See the technologies, [search for CVEs](https://exploits.shodan.io/welcome)
- [ ] Look for PII Disclosure
  - If you find documents redacted
    - Try to copy and paste the obscured text
    - Try to convert the PDF, for example with pdftotext
- [ ] Parameters
  - Look for reflections
  - Use [ParamSpider](https://github.com/devanshbatham/ParamSpider)
    - [rXSS](../web-vulnerabilities/#cross-site-scripting-xss)
  - Redirection
    - Check for [Open Redirects](../web-vulnerabilities#open-redirection)
- [ ] Authentication
  - See [Authentication vulnerabilities](../web-vulnerabilities/#authentication-vulnerabilities)
  - Account Section
    - Profile
      - Stored or Blind [XSS](../web-vulnerabilities/#cross-site-scripting-xss)
    - App Custom Fields
    - Integrations
      - [SSRF](../web-vulnerabilities/#server-side-request-forgery-ssrf), [XSS](../web-vulnerabilities/#cross-site-scripting-xss)
  - [HTTP Request Smuggling](../web-vulnerabilities#http-request-smuggling) in login panels
  - [CSRF](../web-vulnerabilities#cross-site-request-forgery-csrf) for every auth user action
  - Password Reset Broken Logic / Poisoning
- [ ] [Upload Functions](../web-vulnerabilities/#file-upload-vulnerabilities)
- [ ] Email functions, check if you can send emails from the target
  - [ ] Spoofing
  - [ ] HTML Injection
  - [ ] [XSS](../web-vulnerabilities/#cross-site-scripting-xss)
- [ ] Feedback functions
  - Look for [Blind XSS](../web-vulnerabilities/#cross-site-scripting-xss)
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
- [ ] [Look at the index of this repo](../#index) and see if you've missed anything interesting
