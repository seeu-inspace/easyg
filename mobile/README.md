# Mobile

## Index

- [Structure](#structure)
- [Resources](#resources)
- [Tools](#tools)
  - [ADB](#adb)
  - [Frida](#frida)
  - [Objection](#objection)
  - [Apktool](#apktool)
- [Missing Certificate and Public Key Pinning](#missing-certificate-and-public-key-pinning)
- [Cordova attacks](#cordova-attacks)
- [Hardcoded strings](#hardcoded-strings)

## Structure

**FlappyBird_structure.apk**<br/>
├── **AndroidManifest.xml** meta-information about the app<br/>
├── **META-INF/** a manifest of metadata information<br/>
├── **classes.dex** contains the Java libraries that the application uses<br/>
├── **lib/** compiled native libraries used by the app<br/>
├── **res/** It can store resource files such as pictures, XML files, etc.<br/>
├── **assets/** application assets<br/>
└── **resources.arsc** contains compiled resources in a binary format


**AndroidManifest.xml** What can you see?
- Permissions
  - Documentation: https://developer.android.com/reference/android/Manifest.permission
  - About the Android Manifest.xml: https://developer.android.com/guide/topics/manifest/manifest-intro
- Activities
  - UI elements or different screens accessed by the users. Some functionalities need to be protected, like account details, money transfer screens etc.
  - If you see `exported=”True”` it means it can be accessed outside the application. To access:
    - `adb shell`
    - `am start b3nac.injuredandroid/.b25lActivity`
- Also…
  - Check if you can find API Keys
  - See if the backup option is present. If it is, it means that the application might store data as a backup when it’s running or it’s closed

## Troubleshooting

If you find the emulator online but you can't close it
```Shell
adb devices
netstat -tulpn|grep 5554 # if you have emulator-5554
sudo kill -9 22240       # the rightmost numeric value you find
```
- See also: [Android Stop Emulator from Command Line - Stack Overflow](https://stackoverflow.com/questions/20155376/android-stop-emulator-from-command-line)

Some misc commands
```Shell
openssl x509 -inform der -in test.der -pubkey -noout | openssl rsa -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64 # to get the sha256 hash of the certificate
```

In case you need to reinstall the certificate in the smartphone
- From Burp: proxy configured with bind to any port that you want, bind to address set to "All interfaces"
- From the device
  1. Set VPN configuration in Wi-Fi with the machine's IP and the listener port set before
  2. Go to `brup/` with your browser and download the certificate
  3. Rename it with `.crt` extension
  4. Go to "Install a certificate" from your device settings and install the downloaded certificate
  5. Reboot (Note: you need Magisk + [MagiskTrustUserCerts](https://github.com/NVISOsecurity/MagiskTrustUserCerts))
  6. Now check if the requests go through

## Resources

- [Mobile Application Penetration Testing Cheat Sheet](https://github.com/tanprathan/MobileApp-Pentest-Cheatsheet)
- [Mobile Hacking Cheatsheet](https://github.com/randorisec/MobileHackingCheatSheet)
- [OWASP Mobile Application Security](https://mas.owasp.org/)
- [OWASP MASTG](https://mobile-security.gitbook.io/mobile-security-testing-guide/android-testing-guide/0x05a-platform-overview)
- [Docs about security from Android](https://source.android.com/docs/security/overview/app-security?hl=it)

**Data storage** search for PII unencrypted in
- [ ] Phone system logs
- [ ] Webkit cache
- [ ] Dbs, plists, etc.
- [ ] Hardcoded in the binary

**Download APKs**
- [m.apkpure.com](https://m.apkpure.com/it/)
- [apps.evozi.com](https://apps.evozi.com/apk-downloader/)
- [apk-dl.com](http://apk-dl.com/) 

**Emulators**
- [Noxplayer](https://www.bignox.com/)
- [Genymotion](https://www.genymotion.com/) an android emulator
- [Android Studio](https://developer.android.com/studio) Android application development, useful also for the emulator
  - Note: to start only the emulator, use commands such as
    ```cmd
    cd C:\Users\Riccardo\AppData\Local\Android\Sdk\emulator
    emulator -avd Pixel_4_XL_API_30
    ```

## Tools
- [HTTP Toolkit](https://httptoolkit.tech/) to see requests on a non-rooted or emulated device
- [Java Decompiler](https://java-decompiler.github.io/)
- [dex2jar](https://github.com/pxb1988/dex2jar) decompile an .apk into .jar
- [jadx-gui](https://github.com/skylot/jadx/releases) another tool for producing Java source code from Android Dex and Apk files
- [APK-MITM](https://github.com/shroudedcode/apk-mitm) removes certificate pinning
- [Apkleak](https://github.com/dwisiswant0/apkleaks) to get endpoints from an apk


### ADB
- [adb](https://developer.android.com/studio/command-line/adb)

```Shell
# How to start adb
adb kill-server
lsof -i :5037
adb -a nodaemon server -P 5038

# To connect to the Windows machine
adb -H <IP_of_windows> -P <port> shell

# If you are running an emulator from Android Studio, open the terminal from there and just run
adb shell

adb shell "su -c /data/local/tmp/frida-server &"               # to run frida-server on the telephone
adb devices                                                    # to see which devices are connected
adb -s <DEVICE> shell "su -c /data/local/tmp/frida-server &"   # when you have multiple devices
adb install myapp.apk                                          # install an apk with adb
adb logcat --pid=<PID>                                         # to view an app's logs
adb shell getprop ro.product.cpu.abilist                       # to detect the architecture
adb pull </data/app/base64/base.apk> <application_output.apk>  # extract an apk from a device

pm list packages                                               # to see every package install
pm list packages | grep <name_to_search_for>                   # for a specific package
pm path <name_of_package>                                      # see the path where the application is installed

find unpacked/smali -type f                                    # searches for files in the unpacked/smali directory.
```

### Frida
- [Frida](https://github.com/frida/frida)
- See: [Using Frida on Android without root](https://koz.io/using-frida-on-android-without-root/) and [codeshare.frida.re](https://codeshare.frida.re/)

```Shell
# Commands
frida-ps -Uia
frida -f com.topjohnwu.magisk -U
frida -f com.anu.developers3k.rootchecker -U -l scrpt.js # run an application with a frida script
```

### Objection

- [objection - Runtime Mobile Exploration](https://github.com/sensepost/objection)

```Shell
objection -g com.anu.developers3k.rootchecker explore
objection -g "Advanced Root Checker" explore
objection patchapk -s myapp.apk                                                                                 # patch an apk. If needed, specify: -d -a arm64
objection patchapk -s myapp.apk -l bypass.js -d -c gadget-config                                                # use a frida script with the patch
objection -g com.anu.developers3k.rootchecker explore -s "android hooking watch class c4.k0 --dump-args --dump-backtrace --dump-return"

## From objection
ios hooking watch method "-[MPProfileManager deviceIsJailBroken]" --dump-args --dump-backtrace --dump-return    # hooking objection, syntax
android sslpinning disable
android hooking search classes pinn
android hooking watch class com.android.okhttp.CertificatePinner --dump-args --dump-backtrace --dump-return
android heap search instances nome_oggetto                                                                      # get instance
android heap print fields/methods hashcode                                                                      # get fields/methods

# Get fields of an object
var fieldsArr = map.class.getFields();
for(var f in fieldsArr) { console.log(fieldsArr[f]); }
```

### Apktool

- [Apktool](https://apktool.org/)

Decompile with `apktool d app.apk`
- Use `-r` to not decompile the resources, useful for very large applications

You can find more elements than when using `jadx-gui`
- `~/Documents/AppName-1.9.0-release/AppName-1.9.0-release/assets`
- `~/Documents/AppName-1.9.0-release/AppName-1.9.0-release/` depending on the application, you can find some source code here
- `~/Documents/AppName-1.9.0-release/AppName-1.9.0-release/lib` important for when you recompile the application. Also, worth look into it as some devs might store some API keys here
    - use `strings [libapp.so](http://libapp.so)` to see if there is any human redeable strings in these files
- `~/Documents/AppName-1.9.0-release/AppName-1.9.0-release/res/values/strings.xml` here you can find some interesting strings
- `~/Documents/AppName-1.9.0-release/AppName-1.9.0-release/smali` where the actual source code is stored. This files are not humanly redeable, so you shoudl use `jadx-gui`




## Missing Certificate and Public Key Pinning

Absence or improper implementation of certificate and public key pinning in a mobile app. This allows an attacker to potentially intercept communication by presenting fraudulent or unauthorized certificates, undermining the security of the system and enabling man-in-the-middle attacks.

## Cordova attacks

- Check for HTML injections
- Search for XSS
  - With this type of attack, it's possible to achieve an RCE. Check [this](https://www.joshmorony.com/why-xss-attacks-are-more-dangerous-for-capacitor-cordova-apps/) and [this](https://research.securitum.com/security-problems-of-apache-cordova-steal-the-entire-contents-of-the-phone_s-memory-card-with-one-xss/)


## Hardcoded strings

- Often, they can be found in resources/strings.xml
- They can also be found in activity source code
- Threat vectors
    - URLs exposed (http/https)
    - Credentials
    - API keys
    - Firebase URLs (firebase.io)

Some obfuscation:
- `R.string.cmVzb3VyY2VzX3lv`
    - `R.string` means that you can find the string in Resources
    - If you are using `jadx-gui`, go to `resources.arsc` > `res` > `values` > `strings.xml`
- Check for `Base64.decode` for possible secrets
