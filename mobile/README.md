# Mobile

## Index

- [Structure](#structure)
- [Resources](#resources)
- [Tools](#tools)
  - [Frida](#frida)
  - [Apktool](#apktool)
- [Missing Certificate and Public Key Pinning](#missing-certificate-and-public-key-pinning)
- [Cordova attacks](#cordova-attacks)

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

# To see every package install
pm list packages

# For a specific package
pm list packages | grep <name_to_search_for>

# See the path where the application is installed
pm path <name_of_package>

# Extract the apk from a device
adb pull </data/app/base64/base.apk> <application_output.apk>
```

### Frida
- [Frida](https://github.com/frida/frida)
- See: [Using Frida on Android without root](https://koz.io/using-frida-on-android-without-root/) and [codeshare.frida.re](https://codeshare.frida.re/)

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
