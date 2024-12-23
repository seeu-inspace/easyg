# Content Discovery

## Index

- [Notes](#notes)
- [Google Dorking](#google-dorking)
- [GitHub Dorking](#github-dorking)
- [Shodan Dorking](#shodan-dorking)

## Notes

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
  - `dirsearch -e * -x 429,406,404,403,401,400 -l file.txt --no-color --full-url -t 5`
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
- Greps for the output files
  - `grep -E '\.(asp|aspx|jsp|jspx|do|action|php|php3|form|html|xhtml|phtml|cfm|fcc|xsp|swf|nsf|cgi|axd|jsf|esp)(\?|$)'`
  - `grep -vE '\.(js|jsx|svg|png|pngx|gif|gifx|ico|jpg|jpgx|jpeg|bpm|mp3|mp4|ttf|woff|ttf2|woff2|eot|eot2|swf2|css|pdf|webp|tif|xlsx|xls|map|jfif|jpg-large|xml)'`

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

## Google Dorking
- `ext:` search for: asp, aspx, jsp, jspx, do, action, php, php3, form, html, xhtml, phtml, cfm, fcc, xsp, swf, nsf, cgi, axd, jsf
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
- [Attacking organizations with big scopes: from zero to hero](https://www.youtube.com/watch?v=vFk0XtHfuSg)
  - `site: *<yahoo>*`
  - `site:atlassian>*`
  - `site:*<atlassian.*>*`
  - `site:*yahoo.*`
  - Bing `ip:127.0.0.1`
    - Sometimes the DNS name will not resolve. In this case, send IP (as Target) + Domain name (as Host header) returned by bing
  - Bing `domain:yahoo.com inbody:login`

Collection
```
(ext:asp OR ext:aspx OR ext:jsp OR ext:jspx OR ext:do OR ext:action OR ext:php OR ext:php3 OR ext:form OR ext:html OR ext:xhtml OR ext:phtml OR ext:cfm OR ext:fcc OR ext:xsp OR ext:swf OR ext:nsf OR ext:cgi OR ext:axd OR ext:jsf OR ext:esp)
(inurl:user/register OR inurl:admin OR inurl:panel OR intext:login OR intext:username OR intext:password)
(intext:"submit" OR intext:"upload" OR intext:"carga" OR intext:"hochladen" OR intext:"télécharger")
site:target.com intext:"Warning: mysql_num_rows()"
site:http://s3.amazonaws.com "target.com"
site:http://blob.core.windows.net "target.com"
site:http://googleapis.com "target.com"
site:http://drive.google.com "target.com"
```

## GitHub Dorking
- sensitive words: `password, api_key, access_key, dbpassword, dbuser, pwd, pwds, aws_access, key, token, credentials, pass, pwd, passwd, private, preprod, appsecret`
- languages: `json, bash, shell, java etc.`, example `HEROKU_API_KEY language:json`
- extensions: `extensions: bat, config, ini, env etc.`
- filename: `netrpc, .git-credentials, .history, .htpasswd, bash_history`, example `filename:users`
- [Other dorks](https://github.com/techgaun/github-dorks#list-of-dorks)


## Shodan Dorking
- `hostname:targetcorp.com` Search for TargetCorp’s domain
- `hostname:targetcorp.com port:'22'` Search for TargetCorp’s domain running SSH
- `http.favicon.hash:`, see [Finding a P1 in one minute with Shodan.io (RCE)](https://medium.com/@sw33tlie/finding-a-p1-in-one-minute-with-shodan-io-rce-735e08123f52)
