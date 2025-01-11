# Check-lists*

*Note: Check-lists and cheat-sheets :)

## Index

- [General checklists](#general-checklists)
- [Toolset](#toolset)
- [Testing layers](#testing-layers)
- [Recon](#recon)
- [Penetration Testing cycle](#penetration-testing-cycle)
- [Bug Bounty Hunting](#bug-bounty-hunting)
  - [Top vulnerabilities to always look for](#top-vulnerabilities-to-always-look-for)
  - [Multiple targets](#multiple-targets)
  - [Single target](#single-target)
  - [E-commerce](#e-commerce)

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

## Recon
- [ ] Identify technologies
	- [ ] Look for response headers, use `curl -I www.domain.com`
	- [ ] Use WappaLyzer, WhatWeb, BuilWith
		- Check for CVEs
	- [ ] Portscanning: use nmap, also for possible hidden web ports
		- SMB: `nmap -vvv -p 139,445 --script=smb*`
  	- [ ] Check errors / cause an error
  	      - Search for possible disclosures in the responses
  	      - Try to cause an error with a wrong / non-existent HTTP method
  	- [ ] Search for `.js` files, they may reveal infos about libraries and / or plugin used
- [ ] Check available HTTP methods
	- Use `OPTIONS` and `HEAD`
	- Pay attention if dangerous methods are enabled, like `PUT`, `DELETE`, `CONNECT` and `TRACE`
	- HTTP verb tampering
- [ ] Test for SSL
	- [ ] Check ciphers
		- [testssl.sh](https://testssl.sh/)
		- `nmap -sV --script ssl-enum-ciphers -p 443`
		- [SSL Server Test (Powered by Qualys SSL Labs)](https://www.ssllabs.com/ssltest/)
	- [ ] Check if HTST is set
		- `Strict-Transport-Security`
		- [sslstrip](https://github.com/moxie0/sslstrip)
- [ ] Metafiles Leakage
	- Look for infos in `robots.txt`, `.svn`, `.DS_STORE`, `README.md`, `.env`
- [ ] Enumerate inputs and functionalities
	- Be sure to have noted every possible input, especially the riskier ones
- [ ] Look at the source code
	- Search for interesting content, like comments
- [ ] Directory Research
	- Check for possible backup files `.old`, log files, and other files like `.php` or `.asp`, even for source disclosure
	- Search for possible hidden / supposed-to-be protected paths
	- Use various lists
		- [SecLists](https://github.com/danielmiessler/SecLists), [FuzzDB](https://github.com/fuzzdb-project/fuzzdb), [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
		- Custom: [cewl](https://github.com/digininja/CeWL)
- [ ] Dorking
	- Google, GitHub, Shodan


## Penetration Testing cycle

1. Defining the Scope
	- Check if the target is valid
	- Setup the environment
2. Information gathering
	- Passive Information Gathering (OSINT)
	- Active Information Gathering
3. Service enumeration
4. Cicle
	- Penetration
  	- Initial Foothold
  	- Privilege Escalation
  	- Lateral Movement
	- Maintaining access (Trojans)
5. House keeping
	- Cleaning up rootkits
	- Covering tracks
	- See: [Post Exploitation - The Penetration Testing Execution Standard](http://www.pentest-standard.org/index.php/Post_Exploitation)
6. Results
	- Reporting / Analysis
	- Lessons Learned / Remediation


## Bug Bounty Hunting

### Top vulnerabilities to always look for
- [ ] XSS
- [ ] CSRF
- [ ] Authorization issues
- [ ] IDOR

### Multiple targets
- [ ] If every asset is in scope
	- Apex enumeration
		- [bgp.he.net](https://bgp.he.net/)
  		- [asrank.caida.org](https://asrank.caida.org/)
  		- [check_mdi.py](https://github.com/expl0itabl3/check_mdi/blob/main/check_mdi.py)
    			- `./check_mdi.py -d <domain>`
    		- [whois.arin.net](https://whois.arin.net/ui/query.do)
    		- [asnmap](https://github.com/projectdiscovery/asnmap)
      		- For ASNs
        		- `amass intel -asn 13374,14618`
          		- `whois -h whois.radb.net  -- '-i origin AS714' | grep -Eo "([0-9.]+){4}/[0-9]+" | uniq`
  - [Crunchbase](https://www.crunchbase.com/)
  - [OCCRP Aleph](https://aleph.occrp.org/)
  - [duckduckgo/tracker-radar/entities](https://github.com/duckduckgo/tracker-radar/tree/main/entities)
- [ ] If IPs are in scope
	- `cat ip.txt | dnsx -ptr -resp-only`
 	- [Reversino](https://github.com/drak3hft7/Reversino)
- [ ] Run EasyG assetenum
- [ ] Select the interesting targets
  - Take screenshots
  - Pass the subdomains to Burp Suite
  - Open them in Firefox
  - Grab the HTTP titles
    `cat out.txt | httpx -title`
- [ ] Check for mobile/desktop applications
  - If there are any other non-web application, use [Apkleak](https://github.com/dwisiswant0/apkleaks) and [Source2Url](https://github.com/danielmiessler/Source2URL/blob/master/Source2URL) (even if OoS) to grap endpoints

### Single target
- [ ] Recon
  + Explore the app, test every functionality, search also for documentation
  + Crawl with Burp Suite
  + Run EasyG's crawl option
  + If you have accounts, run `katana -u "https://www.redacted.com" -jc -jsl -hl -kf -aff -d 3 -p 25 -c 25 -fs fqdn -H cookie.txt -proxy http://127.0.0.1:8080`
  + Collect endpoints with [BurpJSLinkFinder](https://github.com/InitRoot/BurpJSLinkFinder)
  + [Google Dorking](../web-vulnerabilities/#google-dorking) and [GitHub Dorking](../web-vulnerabilities/#github-dorking), check also [Content Discovery](../content-discovery)
  + See the technologies, [search for CVEs](https://exploits.shodan.io/welcome)
  + [Check the checklist](#recon)
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
- [ ] Cheack / search for [upload functions](../web-vulnerabilities/#file-upload-vulnerabilities)
- [ ] Email functions, check if you can send emails from the target
  - [ ] Spoofing
  - [ ] HTML Injection
  - [ ] [XSS](../web-vulnerabilities/#cross-site-scripting-xss)
- [ ] Feedback functions
  - Look for [Blind XSS](../web-vulnerabilities/#cross-site-scripting-xss)
- [ ] Broken Access Control, Vertical / Horizontal Privilege escalation
  - Check for APIs
  - Check for IDORs
  - If you have multiple accounts with different privileges, check on every level, try to automate with [Autorize](https://portswigger.net/bappstore/f9bbac8c4acf4aefa4d7dc92a991af2f)
  - Use HTTP Verb tampering for bypasses
  - Keep an eye on [internal path traversals](https://x.com/yeswehack/status/1859884798162211250)
- [ ] Errors
  - Try to get a positive response, try HTTP verb tampering & co.
- Extra
  - [ ] [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/index.html), check also
    - [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
    - [OWASP Web Application Penetration Checklist](https://wiki.owasp.org/index.php/Testing_Checklist)
  - [ ] [Look at the index of this repo](../#index) and see if you've missed anything interesting

### E-commerce
- [ ] IDORs
	- [ ] Order status
	- [ ] Order history
	- [ ] PDF generation / download
	- [ ] Account details
- [ ] Payment bypasses, see "[Payment Bypass Guide for Bug Bounty | 69 case studies](https://medium.com/@illoyscizceneghposter/payment-bypass-guide-for-bug-bounty-69-case-studies-15379b4f76fa)"
	- [ ] Tampering values like quantities, prices or coupons
 	- [ ] Coupon Generation
  	- [ ] Numerical Error
  	- [ ] IDOR
  	- [ ] Race Conditions
