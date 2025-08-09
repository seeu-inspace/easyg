# Linux

Note: a lot of these commands are from [RTFM: Red Team Field Manual](https://www.goodreads.com/en/book/show/21419959) by Ben Clark and from [PEN-200: Penetration Testing with Kali Linux](https://www.offsec.com/courses/pen-200/) by Offensive Security.

## Index

- [Linux Services and Networking](#linux-services-and-networking)
- [Linux User Management](#linux-user-management)
- [Linux File Commands](#linux-file-commands)
- [Misc Commands](#misc-commands)
- [Linux environment variables](#linux-environment-variables)
- [Linux File System Permissions](#linux-file-system-permissions)
- [Linux Directories](#linux-directories)
- [Linux Interesting Files / Directories](#linux-interesting-files-directories)
- [Examples](#examples)

## Linux Services and Networking
```shell
netstat -tulpn                                           Show Linux network ports with process ID’s (PIDs)
watch ss -stplu                                          Watch TCP, UDP open ports in real time with socket summary
lsof -i                                                  Show established connections
macchanger -m MACADDR INTR                               Change MAC address on KALI Linux
ifconfig eth0 192.168.2.1/24                             Set IP address in Linux
ifconfig eth0:1 192.168.2.3/24                           Add IP address to existing network interface in Linux
ifconfig eth0 hw ether MACADDR                           Change MAC address in Linux using ifconfig
ifconfig eth0 mtu 1500                                   Change MTU size Linux using ifconfig, change 1500 to your desired MTU
dig -x 192.168.1.1                                       Dig reverse lookup on an IP address
host 192.168.1.1                                         Reverse lookup on an IP address, in case dig is not installed
dig @192.168.2.2 domain.com -t AXFR                      Perform a DNS zone transfer using dig
host -l domain.com nameserver                            Perform a DNS zone transfer using host
nbtstat -A x.x.x.x                                       Get hostname for IP address
ip addr add 192.168.2.22/24 dev eth0                     Adds a hidden IP address to Linux, does not show up when performing an ifconfig
tcpkill -9 host google.com                               Blocks access to google.com from the host machine
echo \"1\" > /proc/sys/net/ipv4/ip_forward               Enables IP forwarding, turns Linux box into a router – handy for routing traffic through a box
echo \"8.8.8.8\" > /etc/resolv.conf                      Use Google DNS
sudo systemctl start ssh                                 Start the SSH service in Kali
sudo ss -antlp | grep sshd                               Confirm that SSH has been started and is running
sudo systemctl enable ssh                                Configure SSH to start at boot time
sudo systemctl start apache2                             Start the apache service in Kali
sudo ss -antlp | grep apache                             Confirm that apache has been started and is running
sudo systemctl enable apache2                            Enable apache to start at boot time
systemctl list-unit-files                                Display all available services
ps -fe                                                   Common ps syntax to list all the processes currently running; f: display full format listing (UID, PID, PPID, etc.), e: select all processes, C: select by command name
sudo tail -f /var/log/apache2/access.log                 Monitor the Apache log file using tail command
```

## Linux User Management
```shell
whoami                                                   Shows currently logged in user on Linux
id                                                       Shows currently logged in user and groups for the user
last                                                     Shows last logged in users
mount                                                    Show mounted drives
df -h                                                    Shows disk usage in human readable output
echo \"user:passwd\" | chpasswd                          Reset password in one line
getent passwd                                            List users on Linux
strings /usr/local/bin/blah                              Shows contents of none text files, e.g. whats in a binary
uname -ar                                                Shows running kernel version
history                                                  Show bash history, commands the user has entered previously
```

## Linux File Commands
```shell
df -h blah                                               Display size of file / dir Linux
diff file1 file2                                         Compare / Show differences between two files on Linux
md5sum file                                              Generate MD5SUM Linux
md5sum -c blah.iso.md5                                   Check file against MD5SUM on Linux, assuming both file and .md5 are in the same dir
file blah                                                Find out the type of file on Linux, also displays if file is 32 or 64 bit
dos2unix                                                 Convert Windows line endings to Unix / Linux
base64 < input-file > output-file                        Base64 encodes input file and outputs a Base64 encoded file called output-file
base64 -d < input-file > output-file                     Base64 decodes input file and outputs a Base64 decoded file called output-file
touch -r ref-file new-file                               Creates a new file using the timestamp data from the reference file, drop the -r to simply create a file
rm -rf                                                   Remove files and directories without prompting for confirmation
mkdir -p pt/{recon,exploit,report}                       This command will create a directory pt and inside of it the directories recon, exploit and report
ls /etc/apache2/wwwold/*.conf                            Display files with certain criteria
ls -a                                                    -a option is used to display all files
ls -1                                                    Display each file in a single line
ls -l                                                    Shows detailed information about the files and directories in a directory
ls -la /usr/bin | grep zip                               Search for any file(s) in /usr/bin containing "zip"
pwd                                                      Print the current directory
cd ~                                                     Return to the home/user directory
echo "test1" > test.txt                                  Saves "test1" in the new file "test.txt"
echo "test2" >> test.txt                                 Add in a new line "test2" in the file "test.txt"
echo "hack::the::world" | awk -F "::" '{print $1, $3}'   Extr fields from a stream using a multi-character separator in awk
comm scan-a.txt scan-b.txt                               Compare files
diff -c scan-a.txt scan-b.txt                            Compare files, context format
diff -u scan-a.txt scan-b.txt                            Compare files, unified format
vimdiff scan-a.txt scan-b.txt                            Compare files using vim
```

## Misc Commands
```shell
init 6                                                   Reboot Linux from the command line
gcc -o output.c input.c                                  Compile C code
gcc -m32 -o output.c input.c                             Cross compile C code, compile 32 bit binary on 64 bit Linux
unset HISTORYFILE                                        Disable bash history logging
kill -9 $$                                               Kill current session
chown user:group blah                                    Change owner of file or dir
chown -R user:group blah                                 Change owner of file or dir and all underlying files / dirs – recersive chown
chmod 600 file                                           Change file / dir permissions, see [Linux File System Permissons](#linux-file-system-permissions) for details
ssh user@X.X.X.X | cat /dev/null > ~/.bash_history       Clear bash history
man -k '^passwd$'                                        See the documentation of a command. Use the flag -k for keyword research
man 5 passwd                                             See the page 5 of the documentation
apropos descr                                            See wich description from docs matches the input for apropos
locate sbd.exe                                           Locate "sbd.exe"
sudo find / -name sbd*                                   Perform recursive search starting from root file system directory and look for files that starts with "sbd"
which sbd                                                Search in $PATH "sbd"
apt-cache search pure-ftpd                               Search for the pure-ftpd application
apt show resource-agents                                 Examine information related to the resource-agents package
sudo apt install pure-ftpd                               apt install the pure-ftpd application
sudo apt remove --purge pure-ftpd                        apt remove –purge to completely remove the pure-ftpd application
sudo dpkg -i man-db_2.7.0.2-5_amd64.deb                  dpkg -i to install the man-db application
echo "I need to try hard" | sed 's/hard/harder/'         Replac a word in the output stream
echo "Hack.The.World."| cut -f 3 -d "."                  Extract fields from the echo command output using cut
cut -d ":" -f 1 /etc/passwd                              Extract usernames from /etc/passwd using cut
wc -m < test.txt                                         Feed the wc command with the < operator
cat test.txt | wc -m                                     Pip the output of the cat command into wc
wget -O report_w.pdf https://of.io/report.pdf            Download a file through wget
curl -o report_c.pdf https://of.io/report.pdf            Download a file with curl
axel -a -n 20 -o report_a.pdf https://of.io/report.pdf   Download a file with axel; -n: number of multiple connections to use, -a: more concise progress indicator, -o specify a different file name for the downloaded file
alias lsa='ls -la'                                       Create an alias "lsa" to execute the command "ls -la"
alias mkdir='ping -c 1 localhost'                        Creat an alias that overrides the mkdir command
unalias mkdir                                            Unsett an alias
cat ~/.bashrc                                            Examin the ".bashrc" default file, the system-wide file for Bash settings located at "/etc/bash.bashrc"
chmod +x                                                 Make a file executable
xfreerdp /u:<user> /p:<password> /cert:ignore /v:<ip>    Connect with RDP
rdesktop -u <user> -p <password> <ip>                    Connect with RDP
```

## Linux environment variables
```shell
export vartest=8.8.8.8                                   Declare an environment variable
env                                                      See all declared environment variables
$$                                                       Env var; Display the ID of the current shell instance
$PATH                                                    Env var; List of directories for the shell to locate executable files
PATH=$PATH:/my/new-path                                  Add a new PATH, handy for local FS manipulation
$USER                                                    Env var; Current user
$PWD                                                     Env var; Current directory path
$HOME                                                    Env var; Home directory path
HISTCONTROL                                              Env var; Defines whether or not to remove duplicate commands
export HISTCONTROL=ignoredups                            Remove duplicates from our bash history
export HISTIGNORE="&:ls:[bf]g:exit:history"              Filter basic, common commands
export HISTTIMEFORMAT='%F %T '                           Include the date/time in our bash history
```

## Linux File System Permissions
```shell
777 rwxrwxrwx                                            No restriction, global WRX any user can do anything
755 rwxr-xr-x                                            Owner has full access, others can read and execute the file
700 rwx------                                            Owner has full access, no one else has access
666 rw-rw-rw-                                            All users can read and write but not execute
644 rw-r--r--                                            Owner can read and write, everyone else can read
600 rw-------                                            Owner can read and write, everyone else has no access
```

## Linux Directories
```shell
/                                                        / also know as “slash” or the root
/bin                                                     Common programs, shared by the system, the system administrator and the users
/boot                                                    Boot files, boot loader (grub), kernels, vmlinuz
/dev                                                     Contains references to system devices, files with special properties
/etc                                                     Important system config files
/home                                                    Home directories for system users
/lib                                                     Library files, includes files for all kinds of programs needed by the system and the users
/lost+found                                              Files that were saved during failures are here
/mnt                                                     Standard mount point for external file systems
/media                                                   Mount point for external file systems (on some distros)
/net                                                     Standard mount point for entire remote file systems – nfs
/opt                                                     Typically contains extra and third party software
/proc                                                    A virtual file system containing information about system resources
/root                                                    root users home dir
/sbin                                                    Programs for use by the system and the system administrator
/tmp                                                     Temporary space for use by the system, cleaned upon reboot
/usr                                                     Programs, libraries, documentation etc. for all user-related programs
/var                                                     Storage for all variable files and temporary files created by users, such as log files, mail queue, print spooler, Web servers, Databases etc
```

## Linux Interesting Files / Directories
```shell
/etc/passwd                                              Contains local Linux users
/etc/shadow                                              Contains local account password hashes
/etc/group                                               Contains local account groups
/etc/init.d/                                             Contains service init script – worth a look to see whats installed
/etc/hostname                                            System hostname
/etc/network/interfaces                                  Network interfaces
/etc/resolv.conf                                         System DNS servers
/etc/profile                                             System environment variables
~/.ssh/                                                  SSH keys
~/.bash_history                                          Users bash history log
/var/log/                                                Linux system log files are typically stored here
/var/adm/                                                UNIX system log files are typically stored here
/var/log/apache2/access.log                              Apache access log file typical path
/var/log/httpd/access.log                                Apache access log file typical path
/etc/fstab                                               File system mounts
```

## More commands
```shell
# to add routes to .ovpn
cat list.txt | while read domain; do ip=$(dig +short "$domain" | grep -E '^[0-9.]+$* | head -n 1); if [-n "$ip" ]; then echo "route $ip 255.255.255.255 #$domain"; fi; done
```

## Examples

- Search the /etc/passwd file for users with a shell set to /bin/false and prints the username and home directory of each user found:
`cat /etc/passwd | awk -F: '{if ($7 == "/bin/false") print "The user " $1 " home directory is " $6}'`
- Inspect Apache logs
  1. Get IPs in access.log, count the frequency and sort them: `cat access.log | cut -d " " -f 1 | sort | uniq -c | sort -urn`
  2. From the log file, pick one IP:  `cat access.log | grep '108.38.224.98' | cut -d "\"" -f 2 | uniq -c`
  3. Further inspect user's behavior: `cat access.log | grep '108.38.224.98' | grep '/admin ' | sort -u`
- [Mounting a Shared Folder on a Linux Computer](https://docs.qnap.com/operating-system/qts/4.5.x/en-us/GUID-445D5C06-7E5A-4232-AC76-CDAF48EDB655.html)
  - `mount <NAS Ethernet Interface IP>:/share/<Shared Folder Name> <Directory to Mount>`
