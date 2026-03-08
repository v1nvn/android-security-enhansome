# android-security-awesome ![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)

[![Link Liveness Checker](https://github.com/ashishb/android-security-awesome/actions/workflows/validate-links.yml/badge.svg)](https://github.com/ashishb/android-security-awesome/actions/workflows/validate-links.yml) ⭐ 9,257 | 🐛 3 | 🌐 Shell | 📅 2026-03-01

[![Lint Shell scripts](https://github.com/ashishb/android-security-awesome/actions/workflows/lint-shell-script.yaml/badge.svg)](https://github.com/ashishb/android-security-awesome/actions/workflows/lint-shell-script.yaml) ⭐ 9,257 | 🐛 3 | 🌐 Shell | 📅 2026-03-01
[![Lint Markdown](https://github.com/ashishb/android-security-awesome/actions/workflows/lint-markdown.yaml/badge.svg)](https://github.com/ashishb/android-security-awesome/actions/workflows/lint-markdown.yaml) ⭐ 9,257 | 🐛 3 | 🌐 Shell | 📅 2026-03-01
[![Lint YAML](https://github.com/ashishb/android-security-awesome/actions/workflows/lint-yaml.yaml/badge.svg)](https://github.com/ashishb/android-security-awesome/actions/workflows/lint-yaml.yaml) ⭐ 9,257 | 🐛 3 | 🌐 Shell | 📅 2026-03-01
[![Lint GitHub Actions](https://github.com/ashishb/android-security-awesome/actions/workflows/lint-github-actions.yaml/badge.svg)](https://github.com/ashishb/android-security-awesome/actions/workflows/lint-github-actions.yaml) ⭐ 9,257 | 🐛 3 | 🌐 Shell | 📅 2026-03-01
![GitHub contributors](https://img.shields.io/github/contributors/ashishb/android-security-awesome)

A collection of Android security-related resources.

1. [Tools](#tools)
2. [Academic/Research/Publications/Books](#academic)
3. [Exploits/Vulnerabilities/Bugs](#exploits)

## Tools

### Online Analyzers

1. [AndroTotal](http://andrototal.org/)
2. [Appknox](https://www.appknox.com/) - not free
3. [Virustotal](https://www.virustotal.com/) - max 128MB
4. [Fraunhofer App-ray](http://app-ray.co/) - not free
5. [NowSecure Lab Automated](https://www.nowsecure.com/blog/2016/09/19/announcing-nowsecure-lab-automated/) - Enterprise tool for mobile app security testing both Android and iOS mobile apps. Lab Automated features dynamic and static analysis on real devices in the cloud to return results in minutes. Not free
6. [App Detonator](https://appdetonator.run/) - Detonate APK binary to provide source code level details, including app author, signature, build, and manifest information. 3 Analysis/day free quota.
7. [Pithus](https://beta.pithus.org/) - Open-Source APK analyzer. Still in Beta and limited to static analysis for the moment. It is possible to hunt malware with Yara rules. More [here](https://beta.pithus.org/about/).
8. [Oversecured](https://oversecured.com/) - Enterprise vulnerability scanner for Android and iOS apps; it offers app owners and developers the ability to secure each new version of a mobile app by integrating Oversecured into the development process. Not free.
9. [AppSweep by Guardsquare](https://appsweep.guardsquare.com/) - Free, fast Android application security testing for developers
10. [Koodous](https://koodous.com) - Performs static/dynamic malware analysis over a vast repository of Android samples and checks them against public and private Yara rules.
11. [Immuniweb](https://www.immuniweb.com/mobile/). Does an "OWASP Mobile Top 10 Test", "Mobile App Privacy Check", and an application permissions test. The free tier is 4 tests per day, including report after registration
12. [ANY.RUN](https://app.any.run/) - An interactive cloud-based malware analysis platform with support for Android application analysis. Limited free plan available.
13. ~~[BitBaan](https://malab.bitbaan.com/)~~
14. ~~[AVC UnDroid](http://undroid.av-comparatives.info/)~~
15. ~~[AMAaaS](https://amaaas.com) - Free Android Malware Analysis Service. A bare-metal service features static and dynamic analysis for Android applications. A product of [MalwarePot](https://malwarepot.com/index.php/AMAaaS)~~.
16. ~~[AppCritique](https://appcritique.boozallen.com) - Upload your Android APKs and receive comprehensive free security assessments~~
17. ~~[NVISO ApkScan](https://apkscan.nviso.be/) - sunsetting on Oct 31, 2019~~
18. ~~[Mobile Malware Sandbox](http://www.mobilemalware.com.br/analysis/index_en.php)~~
19. ~~[IBM Security AppScan Mobile Analyzer](https://appscan.bluemix.net/mobileAnalyzer) - not free~~
20. ~~[Visual Threat](https://www.visualthreat.com/) - no longer an Android app analyzer~~
21. ~~[Tracedroid](http://tracedroid.few.vu.nl/)~~
22. ~~[habo](https://habo.qq.com/) - 10/day~~
23. ~~[CopperDroid](http://copperdroid.isg.rhul.ac.uk/copperdroid/)~~
24. ~~[SandDroid](http://sanddroid.xjtu.edu.cn/)~~
25. ~~[Stowaway](http://www.android-permissions.org/)~~
26. ~~[Anubis](http://anubis.iseclab.org/)~~
27. ~~[Mobile app insight](http://www.mobile-app-insight.org)~~
28. ~~[Mobile-Sandbox](http://mobile-sandbox.com)~~
29. ~~[Ijiami](http://safe.ijiami.cn/)~~
30. ~~[Comdroid](http://www.comdroid.org/)~~
31. ~~[Android Sandbox](http://www.androidsandbox.net/)~~
32. ~~[Foresafe](http://www.foresafe.com/scan)~~
33. ~~[Dexter](https://dexter.dexlabs.org/)~~
34. ~~[MobiSec Eacus](http://www.mobiseclab.org/eacus.jsp)~~
35. ~~[Fireeye](https://fireeye.ijinshan.com/)- max 60MB 15/day~~
36. ~~[approver](https://approver.talos-sec.com/) - Approver  is a fully automated security analysis and risk assessment platform for Android and iOS apps. Not free.~~

### Static Analysis Tools

1. [ClassyShark](https://github.com/google/android-classyshark) ⚠️ Archived - A Standalone binary inspection tool that can browse any Android executable and show important info.
2. [Detekt](https://github.com/detekt/detekt) ⭐ 6,855 | 🐛 233 | 🌐 Kotlin | 📅 2026-03-07 - Static code analysis for Kotlin
3. [APKLeaks](https://github.com/dwisiswant0/apkleaks) ⭐ 5,986 | 🐛 25 | 🌐 Python | 📅 2025-08-20 - Scanning APK file for URIs, endpoints & secrets.
4. [Quark-Engine](https://github.com/quark-engine/quark-engine) ⭐ 1,645 | 🐛 77 | 🌐 Python | 📅 2026-03-07 - An Obfuscation-Neglect Android Malware Scoring System
5. [ApkAnalyser](https://github.com/sonyxperiadev/ApkAnalyser) ⭐ 1,046 | 🐛 6 | 🌐 Java | 📅 2023-07-13
6. [StaCoAn](https://github.com/vincentcox/StaCoAn) ⭐ 868 | 🐛 11 | 🌐 JavaScript | 📅 2021-04-27 - Cross-platform tool that aids developers, bug-bounty hunters, and ethical hackers in performing static code analysis on mobile applications. This tool was created with a big focus on usability and graphical guidance in the user interface.
7. [APKInspector](https://github.com/honeynet/apkinspector/) ⭐ 853 | 🐛 15 | 🌐 Java | 📅 2013-02-25
8. [Androwarn](https://github.com/maaaaz/androwarn/) ⭐ 523 | 🐛 22 | 🌐 HTML | 📅 2020-01-21 - detect and warn the user about potential malicious behaviors developed by an Android application.
9. [SUPER](https://github.com/SUPERAndroidAnalyzer/super) ⚠️ Archived - Secure, Unified, Powerful, and Extensible Rust Android Analyzer
10. [JAADAS](https://github.com/flankerhqd/JAADAS) ⚠️ Archived - Joint intraprocedural and interprocedural program analysis tool to find vulnerabilities in Android apps, built on Soot and Scala
11. [SmaliSCA](https://github.com/dorneanu/smalisca) ⚠️ Archived - Smali Static Code Analysis
12. [One Step Decompiler](https://github.com/b-mueller/apkx) ⭐ 289 | 🐛 4 | 🌐 Python | 📅 2021-01-19 - Android APK Decompilation for the Lazy
13. [Mobile Audit](https://github.com/mpast/mobileAudit) ⭐ 224 | 🐛 1 | 🌐 HTML | 📅 2026-03-04 - Web application for performing Static Analysis and detecting malware in Android APKs.
14. [RiskInDroid](https://github.com/ClaudiuGeorgiu/RiskInDroid) ⭐ 162 | 🐛 0 | 🌐 Python | 📅 2026-03-02 - A tool for calculating the risk of Android apps based on their permissions, with an online demo available.
15. [Madrolyzer](https://github.com/maldroid/maldrolyzer) ⭐ 112 | 🐛 5 | 🌐 Python | 📅 2015-05-07 - extracts actionable data like C\&C, phone number etc.
16. [CFGScanDroid](https://github.com/douggard/CFGScanDroid) ⭐ 63 | 🐛 4 | 🌐 Java | 📅 2015-05-26 - Scans and compares the CFG against the CFG of malicious applications
17. [ConDroid](https://github.com/JulianSchuette/ConDroid) ⭐ 56 | 🐛 4 | 🌐 Java | 📅 2016-03-08 - Performs a combination of symbolic + concrete execution of the app
18. [DroidRA](https://github.com/serval-snt-uni-lu/DroidRA) ⭐ 52 | 🐛 4 | 🌐 Java | 📅 2020-02-14
19. [APKdevastate](https://github.com/rafigk2v9c/APKdevastate/) ⭐ 35 | 🐛 0 | 🌐 C# | 📅 2026-03-06 - Advanced analysis software for APK payloads created by RATs.
20. [Droid Intent Data Flow Analysis for Information Leakage](https://insights.sei.cmu.edu/library/didfail/)
21. [DroidLegacy](https://bitbucket.org/srl/droidlegacy)
22. [FlowDroid](https://blogs.uni-paderborn.de/sse/tools/flowdroid/)
23. [Android Decompiler](https://www.pnfsoftware.com/) – not free
24. [PSCout](https://security.csl.toronto.edu/pscout/) - A tool that extracts the permission specification from the Android OS source code using static analysis
25. [Amandroid](http://amandroid.sireum.org/)
26. ~~[Smali CFG generator](https://github.com/EugenioDelfa/Smali-CFGs)~~
27. ~~[Several tools from PSU](http://siis.cse.psu.edu/tools.html)~~
28. ~~[SPARTA](https://www.cs.washington.edu/sparta) - verifies (proves) that an app satisfies an information-flow security policy; built on the [Checker Framework](https://types.cs.washington.edu/checker-framework/)~~

### App Vulnerability Scanners

1. [QARK](https://github.com/linkedin/qark/) ⭐ 3,355 | 🐛 79 | 🌐 Python | 📅 2024-01-16 - QARK by LinkedIn is for app developers to scan apps for security issues
2. [Nogotofail](https://github.com/google/nogotofail) ⚠️ Archived
3. [AndroBugs](https://github.com/AndroBugs/AndroBugs_Framework) ⚠️ Archived
4. ~~[Devknox](https://devknox.io/) - IDE plugin to build secure Android apps. Not maintained anymore.~~

### Dynamic Analysis Tools

1. [Mobile-Security-Framework MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) ⭐ 20,526 | 🐛 24 | 🌐 JavaScript | 📅 2026-03-04 - Mobile Security Framework is an intelligent, all-in-one open-source mobile application (Android/iOS) automated pen-testing framework capable of performing static, dynamic analysis, and web API testing.
2. [Drozer](https://github.com/mwrlabs/drozer) ⭐ 4,463 | 🐛 10 | 🌐 Python | 📅 2026-01-29
3. [Runtime Mobile Security (RMS)](https://github.com/m0bilesecurity/RMS-Runtime-Mobile-Security) ⭐ 2,979 | 🐛 7 | 🌐 JavaScript | 📅 2026-02-28 - is a powerful web interface that helps you to manipulate Android and iOS Apps at Runtime
4. [Inspeckage](https://github.com/ac-pm/Inspeckage) ⭐ 2,959 | 🐛 98 | 🌐 Java | 📅 2020-09-22 - Android Package Inspector - dynamic analysis with API hooks, start unexported activities, and more. (Xposed Module)
5. [Brida](https://github.com/federicodotta/Brida) ⭐ 1,852 | 🐛 11 | 🌐 Java | 📅 2025-10-30 - Burp Suite extension that, working as a bridge between Burp and Frida, lets you use and manipulate the applications' own methods while tampering with the traffic exchanged between the applications and their back-end services/servers.
6. [Andriller](https://github.com/den4uk/andriller) ⭐ 1,529 | 🐛 11 | 🌐 Python | 📅 2022-06-27 - software utility with a collection of forensic tools for smartphones. It performs read-only, forensically sound, non-destructive acquisition from Android devices.
7. [House](https://github.com/nccgroup/house) ⭐ 1,458 | 🐛 16 | 🌐 JavaScript | 📅 2021-06-03- House: A runtime mobile application analysis toolkit with a Web GUI, powered by Frida, written in Python.
8. [Androl4b](https://github.com/sh4hin/Androl4b) ⭐ 1,156 | 🐛 5 | 📅 2023-05-31- A Virtual Machine For Assessing Android applications, Reverse Engineering and Malware Analysis
9. [adbsploit](https://github.com/mesquidar/adbsploit) ⚠️ Archived - tools for exploiting device via ADB
10. [DECAF](https://github.com/sycurelab/DECAF) ⭐ 838 | 🐛 37 | 🌐 C | 📅 2024-11-19 - Dynamic Executable Code Analysis Framework based on QEMU (DroidScope is now an extension to DECAF)
11. [Droidbox](https://github.com/pjlantz/droidbox) ⭐ 796 | 🐛 32 | 🌐 Python | 📅 2023-06-22
12. [MARA](https://github.com/xtiankisutsa/MARA_Framework) ⭐ 670 | 🐛 3 | 🌐 Python | 📅 2019-07-26 - Mobile Application Reverse Engineering and Analysis Framework
13. [CuckooDroid](https://github.com/idanr1986/cuckoo-droid) ⭐ 604 | 🐛 71 | 🌐 Python | 📅 2020-11-07 - Android extension for Cuckoo sandbox
14. [friTap](https://github.com/fkie-cad/friTap) ⭐ 470 | 🐛 7 | 🌐 JavaScript | 📅 2026-03-06- Intercept SSL/TLS connections with Frida; Allows TLS key extraction and decryption of TLS payload as PCAP on Android in real-time.
15. [Android Hooker](https://github.com/AndroidHooker/hooker) ⚠️ Archived - Dynamic Java code instrumentation (requires the Substrate Framework)
16. [AndroPyTool](https://github.com/alexMyG/AndroPyTool) ⭐ 379 | 🐛 26 | 🌐 Python | 📅 2022-12-07 - a tool for extracting static and dynamic features from Android APKs. It combines different well-known Android app analysis tools such as DroidBox, FlowDroid, Strace, AndroGuard, and VirusTotal analysis.
17. [Android Malware Sandbox](https://github.com/Areizen/Android-Malware-Sandbox) ⭐ 302 | 🐛 7 | 🌐 JavaScript | 📅 2025-02-06
18. [Android Linux Kernel modules](https://github.com/strazzere/android-lkms) ⭐ 220 | 🐛 0 | 🌐 C | 📅 2014-09-11
19. [ProbeDroid](https://github.com/ZSShen/ProbeDroid) ⭐ 203 | 🐛 3 | 🌐 C++ | 📅 2018-12-16 - Dynamic Java code instrumentation
20. [Android\_application\_analyzer](https://github.com/NotSoSecure/android_application_analyzer) ⭐ 171 | 🐛 3 | 🌐 Python | 📅 2025-10-03 - The tool is used to analyze the content of the Android application in local storage.
21. [HacknDroid](https://github.com/RaffaDNDM/HacknDroid) ⭐ 132 | 🐛 0 | 🌐 Python | 📅 2025-12-07 - A tool designed to automate various Mobile Application Penetration Testing (MAPT) tasks and facilitate interaction with Android devices.
22. [Vezir Project](https://github.com/oguzhantopgul/Vezir-Project) ⭐ 115 | 🐛 3 | 📅 2016-04-25 - Virtual Machine for Mobile Application Pentesting and Mobile Malware Analysis
23. [PAPIMonitor](https://github.com/Dado1513/PAPIMonitor) ⭐ 87 | 🐛 3 | 🌐 JavaScript | 📅 2024-07-04 – PAPIMonitor (Python API Monitor for Android apps) is a Python tool based on Frida for monitoring user-select APIs during the app execution.
24. [Mem](https://github.com/MobileForensicsResearch/mem) ⭐ 70 | 🐛 0 | 🌐 C | 📅 2015-06-12 - Memory analysis of Android (root required)
25. [MPT](https://github.com/ByteSnipers/mobile-pentest-toolkit) ⭐ 55 | 🐛 0 | 🌐 Python | 📅 2025-10-30 - MPT (Mobile Pentest Toolkit) is a must-have solution for your Android penetration testing workflows. This tool allows you to automate security tasks.
26. [AuditdAndroid](https://github.com/nwhusted/AuditdAndroid) ⭐ 47 | 🐛 2 | 🌐 C | 📅 2013-05-09 – Android port of auditd, not under active development anymore
27. [Aurasium](https://github.com/xurubin/aurasium) ⭐ 39 | 🐛 0 | 🌐 Python | 📅 2015-01-18 – Practical security policy enforcement for Android apps via bytecode rewriting and in-place reference monitoring.
28. [DroidAnalytics](https://github.com/zhengmin1989/DroidAnalytics) ⭐ 30 | 🐛 0 | 🌐 Python | 📅 2015-05-13 - incomplete
29. [StaDynA](https://github.com/zyrikby/StaDynA) ⭐ 25 | 🐛 0 | 📅 2023-04-01 - a system supporting security app analysis in the presence of dynamic code update features (dynamic class loading and reflection). This tool combines static and dynamic analysis of Android applications in order to reveal the hidden/updated behavior and extend static analysis results with this information.
30. [Android DBI frameowork](http://www.mulliner.org/blog/blosxom.cgi/security/androiddbiv02.html)
31. [Xposed](https://forum.xda-developers.com/xposed/xposed-installer-versions-changelog-t2714053) - equivalent of doing Stub-based code injection but without any modifications to the binary
32. [Crowdroid](http://www.ida.liu.se/labs/rtslab/publications/2011/spsm11-burguera.pdf) – unable to find the actual tool
33. [Android Security Evaluation Framework](https://code.google.com/p/asef/) - not under active development anymore
34. [Taintdroid](http://appanalysis.org) - requires AOSP compilation
35. [ARTist](https://artist.cispa.saarland) - a flexible open-source instrumentation and hybrid analysis framework for Android apps and Android's Java middleware. It is based on the Android Runtime's (ART) compiler and modifies code during on-device compilation.
36. [Decompiler.com](https://www.decompiler.com/) - Online APK and Java decompiler
37. ~~[AppUse](https://appsec-labs.com/AppUse/) – custom build for penetration testing~~
38. ~~[Appie](https://manifestsecurity.com/appie/) - Appie is a software package that has been pre-configured to function as an Android Pentesting Environment. It is completely portable and can be carried on a USB stick or smartphone. This is a one-stop answer for all the tools needed in Android Application Security Assessment and an awesome alternative to existing virtual machines.~~
39. ~~[Android Tamer](https://androidtamer.com/) - Virtual / Live Platform for Android Security Professionals~~
40. ~~[Android Malware Analysis Toolkit](http://www.mobilemalware.com.br/amat/download.html) - (Linux distro) Earlier, it used to be an [online analyzer](http://dunkelheit.com.br/amat/analysis/index_en.php)~~
41. ~~[Android Reverse Engineering](https://redmine.honeynet.org/projects/are/wiki) – ARE (android reverse engineering) is not under active development anymore~~
42. ~~[ViaLab Community Edition](https://www.nowsecure.com/blog/2014/09/09/introducing-vialab-community-edition/)~~
43. ~~[Mercury](https://labs.mwrinfosecurity.com/tools/2012/03/16/mercury/)~~
44. ~~[Cobradroid](https://thecobraden.com/projects/cobradroid/) – custom image for malware analysis~~

### Reverse Engineering

1. [Jadx](https://github.com/skylot/jadx) ⭐ 47,540 | 🐛 419 | 🌐 Java | 📅 2026-03-07
2. [Radare2](https://github.com/radare/radare2) ⭐ 23,207 | 🐛 839 | 🌐 C | 📅 2026-03-07
3. [Bytecode viewer](https://github.com/Konloch/bytecode-viewer) ⭐ 15,432 | 🐛 100 | 🌐 Java | 📅 2026-01-07
4. [JD-GUI](https://github.com/java-decompiler/jd-gui) ⭐ 15,033 | 🐛 245 | 🌐 Java | 📅 2024-07-08 - Java decompiler
5. [Dex2Jar](https://github.com/pxb1988/dex2jar) ⭐ 13,080 | 🐛 379 | 🌐 Java | 📅 2024-07-21 - dex to jar converter
6. [MVT (Mobile Verification Toolkit)](https://github.com/mvt-project/mvt) ⭐ 12,197 | 🐛 64 | 🌐 Python | 📅 2026-03-05 - a collection of utilities to simplify and automate the process of gathering forensic traces helpful to identify a potential compromise of Android and iOS devices
7. [Smali/Baksmali](https://github.com/JesusFreke/smali) ⭐ 6,605 | 🐛 144 | 🌐 Java | 📅 2024-01-17 – apk decompilation
8. [Androguard](https://github.com/androguard/androguard) ⭐ 5,980 | 🐛 44 | 🌐 Python | 📅 2026-01-12 – powerful, integrates well with other tools
9. [PhoneSpolit-Pro](https://github.com/AzeemIdrisi/PhoneSploit-Pro) ⭐ 5,652 | 🐛 12 | 🌐 Python | 📅 2024-04-19 - An all-in-one hacking tool to remotely exploit Android devices using ADB and Metasploit Framework to get a Meterpreter session.
10. [apk-mitm](https://github.com/shroudedcode/apk-mitm) ⭐ 4,933 | 🐛 76 | 🌐 TypeScript | 📅 2024-07-24 - A CLI application that prepares Android APK files for HTTPS inspection
11. [Simplify Android deobfuscator](https://github.com/CalebFenton/simplify) ⭐ 4,632 | 🐛 32 | 🌐 Java | 📅 2022-04-30
12. [FernFlower](https://github.com/fesh0r/fernflower) ⭐ 4,181 | 🐛 0 | 🌐 Java | 📅 2026-03-05 - Java decompiler
13. [APKLab](https://github.com/APKLab/APKLab) ⭐ 3,743 | 🐛 23 | 🌐 TypeScript | 📅 2025-11-11 - plugin for VS code to analyze APKs
14. [Enjarify](https://github.com/google/enjarify) ⚠️ Archived - dex to jar converter from Google
15. [Krakatau](https://github.com/Storyyeller/Krakatau) ⭐ 2,183 | 🐛 25 | 🌐 Rust | 📅 2025-06-02 - Java decompiler
16. [Dwarf](https://github.com/iGio90/Dwarf) ⭐ 1,313 | 🐛 5 | 🌐 Python | 📅 2024-05-16 - GUI for reverse engineering
17. [Obfuscapk](https://github.com/ClaudiuGeorgiu/Obfuscapk) ⚠️ Archived — Obfuscapk is a modular Python tool for obfuscating Android apps without requiring their source code.
18. [Andromeda](https://github.com/secrary/Andromeda) ⭐ 710 | 🐛 0 | 🌐 C++ | 📅 2020-03-14 - Another basic command-line reverse engineering tool
19. [AndBug](https://github.com/swdunlop/AndBug) ⭐ 603 | 🐛 16 | 🌐 Python | 📅 2016-07-30
20. [Introspy](https://github.com/iSECPartners/Introspy-Android) ⭐ 485 | 🐛 11 | 🌐 Java | 📅 2014-01-13
21. [Android Framework for Exploitation](https://github.com/appknox/AFE) ⭐ 198 | 🐛 16 | 🌐 Python | 📅 2015-09-27
22. [Frida](https://www.frida.re/) - inject JavaScript to explore applications and a [GUI tool](https://github.com/antojoseph/diff-gui) ⭐ 182 | 🐛 2 | 🌐 JavaScript | 📅 2016-11-03 for it
23. [Redexer](https://github.com/plum-umd/redexer) ⭐ 173 | 🐛 7 | 🌐 Smali | 📅 2021-05-20 – apk manipulation
24. [Android OpenDebug](https://github.com/iSECPartners/Android-OpenDebug) ⭐ 135 | 🐛 0 | 🌐 Java | 📅 2013-12-14 – make any application on the device debuggable (using Cydia Substrate).
25. [Noia](https://github.com/0x742/noia) ⭐ 123 | 🐛 3 | 🌐 JavaScript | 📅 2020-11-27 - Simple Android application sandbox file browser tool
26. [Fino](https://github.com/sysdream/fino) ⭐ 110 | 🐛 1 | 🌐 Java | 📅 2014-10-25
27. [odex-patcher](https://github.com/giacomoferretti/odex-patcher) ⭐ 102 | 🐛 10 | 🌐 Kotlin | 📅 2024-01-13 - Run arbitrary code by patching OAT files
28. [Bypass signature and permission checks for IPCs](https://github.com/iSECPartners/Android-KillPermAndSigChecks) ⭐ 85 | 🐛 1 | 🌐 Java | 📅 2013-12-19
29. [Dexmod](https://github.com/google/dexmod) ⚠️ Archived - a tool to exemplify patching Dalvik bytecode in a DEX (Dalvik Executable) file and assist in the static analysis of Android applications.
30. [emacs syntax coloring for smali files](https://github.com/strazzere/Emacs-Smali) ⭐ 36 | 🐛 0 | 🌐 Smali | 📅 2026-03-02
31. [ARMANDroid](https://github.com/Mobile-IoT-Security-Lab/ARMANDroid) ⭐ 15 | 🐛 1 | 🌐 Dockerfile | 📅 2020-12-18 - ARMAND (Anti-Repackaging through Multi-pattern, Anti-tampering based on Native Detection) is a novel anti-tampering protection scheme that embeds logic bombs and AT detection nodes directly in the apk file without needing their source code.
32. [vim syntax coloring for smali files](http://codetastrophe.com/smali.vim)
33. [Apktool](https://ibotpeaches.github.io/Apktool/) – really useful for compilation/decompilation (uses smali)
34. [Dedexer](https://sourceforge.net/projects/dedexer/)
35. [Indroid](https://bitbucket.org/aseemjakhar/indroid) – thread injection kit
36. [Jad](https://varaneckas.com/jad/) - Java decompiler
37. [CFR](http://www.benf.org/other/cfr/) - Java decompiler
38. ~~[IntentSniffer](https://www.nccgroup.com/us/our-research/intent-sniffer/)~~
39. ~~[Procyon](https://bitbucket.org/mstrobel/procyon/wiki/Java%20Decompiler) - Java decompiler~~
40. ~~[Smali viewer](http://blog.avlyun.com/wp-content/uploads/2014/04/SmaliViewer.zip)~~
41. ~~[ZjDroid](https://github.com/BaiduSecurityLabs/ZjDroid)~~, ~~[fork/mirror](https://github.com/yangbean9/ZjDroid)~~
42. ~~[Dare](http://siis.cse.psu.edu/dare/index.html) – .dex to .class converter~~

### Fuzz Testing

1. [Honggfuzz](https://github.com/google/honggfuzz) ⭐ 3,311 | 🐛 30 | 🌐 C | 📅 2026-01-06
2. [Media Fuzzing Framework for Android](https://github.com/fuzzing/MFFA) ⭐ 333 | 🐛 0 | 🌐 Python | 📅 2016-04-01
3. [QuarksLab's Android Fuzzing](https://github.com/quarkslab/android-fuzzing) ⭐ 137 | 🐛 1 | 🌐 C | 📅 2023-05-01
4. [Radamsa Fuzzer](https://github.com/anestisb/radamsa-android) ⭐ 68 | 🐛 0 | 🌐 C | 📅 2019-12-24
5. [An Android port of the Melkor ELF fuzzer](https://github.com/anestisb/melkor-android) ⭐ 63 | 🐛 0 | 🌐 C | 📅 2014-08-21
6. [AndroFuzz](https://github.com/jonmetz/AndroFuzz) ⭐ 39 | 🐛 1 | 🌐 Python | 📅 2014-09-04
7. ~~[IntentFuzzer](https://www.nccgroup.trust/us/about-us/resources/intent-fuzzer/)~~

### App Repackaging Detectors

1. [FSquaDRA](https://github.com/zyrikby/FSquaDRA) ⭐ 74 | 🐛 0 | 🌐 Java | 📅 2023-04-01 - a tool for detecting repackaged Android applications based on app resources hash comparison.

### Market Crawlers

1. [PlaystoreDownloader](https://github.com/ClaudiuGeorgiu/PlaystoreDownloader) ⚠️ Archived - PlaystoreDownloader is a tool for downloading Android applications directly from the Google Play Store. After an initial (one-time) configuration, applications can be downloaded by specifying their package name.
2. [Google Play crawler (Python)](https://github.com/egirault/googleplay-api) ⚠️ Archived
3. [Google Play crawler (Java)](https://github.com/Akdeniz/google-play-crawler) ⚠️ Archived
4. [Google Play crawler (Node)](https://github.com/dweinstein/node-google-play) ⚠️ Archived - get app details and download apps from the official Google Play Store.
5. [Aptoide downloader (Node)](https://github.com/dweinstein/node-aptoide) ⭐ 27 | 🐛 2 | 🌐 JavaScript | 📅 2015-07-31 - download apps from Aptoide third-party Android market
6. [Appland downloader (Node)](https://github.com/dweinstein/node-appland) ⭐ 19 | 🐛 0 | 🌐 JavaScript | 📅 2015-07-30 - download apps from Appland third-party Android market
7. [APK Downloader](https://apkcombo.com/apk-downloader/) Online Service to download APK from the Play Store for a specific Android Device Configuration
8. ~~[Apkpure](https://apkpure.com/) - Online apk downloader. Also, it provides its own app for downloading.~~

### Misc Tools

1. [mitmproxy](https://github.com/mitmproxy/mitmproxy) ⭐ 42,559 | 🐛 427 | 🌐 Python | 📅 2026-03-06
2. [AppMon](https://github.com/dpnishant/appmon) ⭐ 1,611 | 🐛 38 | 🌐 JavaScript | 📅 2023-05-01- AppMon is an automated framework for monitoring and tampering with system API calls of native macOS, iOS, and Android apps. It is based on Frida.
3. [Android Vulnerability Test Suite](https://github.com/AndroidVTS/android-vts) ⭐ 1,027 | 🐛 24 | 🌐 Java | 📅 2019-08-02 - android-vts scans a device for set of vulnerabilities
4. [sundaysec/Android-Exploits](https://github.com/sundaysec/Android-Exploits) ⭐ 968 | 🐛 4 | 🌐 HTML | 📅 2019-10-08 - A collection of android Exploits and Hacks
5. [Internal Blue](https://github.com/seemoo-lab/internalblue) ⭐ 764 | 🐛 20 | 🌐 Python | 📅 2024-08-21 - Bluetooth experimentation framework based on the Reverse Engineering of Broadcom Bluetooth Controllers
6. [Firmware Extractor](https://github.com/AndroidDumps/Firmware_extractor) ⭐ 346 | 🐛 5 | 🌐 Python | 📅 2025-03-09 - Extract given archive to images
7. [adb autocomplete](https://github.com/mbrubeck/android-completion) ⭐ 262 | 🐛 5 | 🌐 Shell | 📅 2025-11-22
8. [Android Mobile Device Hardening](https://github.com/SecTheTech/AMDH) ⭐ 216 | 🐛 0 | 🌐 Python | 📅 2023-02-26 - AMDH scans and hardens the device's settings and lists harmful installed Apps based on permissions.
9. [ARMv7 payload that provides arbitrary code execution on MediaTek bootloaders](https://github.com/R0rt1z2/kaeru) ⭐ 191 | 🐛 7 | 🌐 C | 📅 2026-03-04
10. [DroidGround](https://github.com/SECFORCE/droidground) ⭐ 111 | 🐛 0 | 🌐 TypeScript | 📅 2026-03-05 - A flexible playground for Android CTF challenges
11. [dockerfile/androguard](https://github.com/dweinstein/dockerfile-androguard) ⭐ 45 | 🐛 1 | 📅 2019-10-29
12. [NullKia](https://github.com/bad-antics/nullkia) ⭐ 12 | 🐛 3 | 🌐 Go | 📅 2026-02-27 - Comprehensive mobile security framework supporting 18 manufacturers with baseband exploitation, cellular security, TEE/TrustZone research, and BootROM extraction tools.
13. [smalihook](http://androidcracking.blogspot.com/2011/03/original-smalihook-java-source.html)
14. [AXMLPrinter2](http://code.google.com/p/android4me/downloads/detail?name=AXMLPrinter2.jar) - to convert binary XML files to human-readable XML files
15. ~~[Android Device Security Database](https://www.android-device-security.org/client/datatable) - Database of security features of Android devices~~
16. ~~[Opcodes table for quick reference](http://ww38.xchg.info/corkami/opcodes_tables.pdf)~~
17. ~~[APK-Downloader](http://codekiem.com/2012/02/24/apk-downloader/)~~ - seems dead now
18. ~~[Dalvik opcodes](http://pallergabor.uw.hu/androidblog/dalvik_opcodes.html)~~

### Vulnerable Applications for practice

1. [Android InsecureBank](https://github.com/dineshshetty/Android-InsecureBankv2) ⭐ 1,411 | 🐛 16 | 🌐 Java | 📅 2024-04-17
2. [Damn Insecure Vulnerable Application (DIVA)](https://github.com/payatu/diva-android) ⭐ 1,088 | 🐛 13 | 🌐 Java | 📅 2023-05-19
3. [Oversecured Vulnerable Android App (OVAA)](https://github.com/oversecured/ovaa) ⭐ 732 | 🐛 1 | 🌐 Java | 📅 2024-07-18
4. [GoatDroid](https://github.com/jackMannino/OWASP-GoatDroid-Project) ⚠️ Archived
5. [Insecureshop](https://github.com/optiv/insecureshop) ⚠️ Archived
6. [Vuldroid](https://github.com/jaiswalakshansh/Vuldroid) ⭐ 66 | 🐛 1 | 🌐 Java | 📅 2021-09-18
7. [ExploitMe Android Labs](http://securitycompass.github.io/AndroidLabs/setup.html)

## Academic/Research/Publications/Books

### Research Papers

1. [Exploit Database](https://www.exploit-db.com/papers/)
2. [Android security-related presentations](https://github.com/jacobsoo/AndroidSlides) ⭐ 175 | 🐛 0 | 📅 2021-08-16
3. [A good collection of static analysis papers](https://tthtlc.wordpress.com/2011/09/01/static-analysis-of-android-applications/)

### Books

1. [SEI CERT Android Secure Coding Standard](https://wiki.sei.cmu.edu/confluence/display/android/Android+Secure+Coding+Standard)

### Others

1. [OWASP Mobile Security Testing Guide Manual](https://github.com/OWASP/owasp-mstg) ⭐ 12,755 | 🐛 249 | 🌐 Python | 📅 2026-03-07
2. [Mobile App Pentest Cheat Sheet](https://github.com/tanprathan/MobileApp-Pentest-Cheatsheet) ⭐ 5,157 | 🐛 18 | 📅 2024-02-08
3. [doridori/Android-Security-Reference](https://github.com/doridori/Android-Security-Reference) ⭐ 981 | 🐛 5 | 📅 2025-03-24
4. [android app security checklist](https://github.com/b-mueller/android_app_security_checklist) ⭐ 890 | 🐛 6 | 📅 2022-08-27
5. [Android Reverse Engineering 101 by Daniele Altomare (Web Archive link)](https://web.archive.org/web/20180721134044/http://www.fasteque.com:80/android-reverse-engineering-101-part-1/)
6. ~~[Mobile Security Reading Room](https://mobile-security.zeef.com) - A reading room that contains well-categorized technical reading material about mobile penetration testing, mobile malware, mobile forensics, and all kinds of mobile security-related topics~~

## Exploits/Vulnerabilities/Bugs

### List

1. [Android Security Bulletins](https://source.android.com/security/bulletin/)
2. [Android's reported security vulnerabilities](https://www.cvedetails.com/vulnerability-list/vendor_id-1224/product_id-19997/Google-Android.html)
3. [OWASP Mobile Top 10 2016](https://www.owasp.org/index.php/Mobile_Top_10_2016-Top_10)
4. [Exploit Database](https://www.exploit-db.com/search/?action=search\&q=android) - click search
5. [Vulnerability Google Doc](https://docs.google.com/spreadsheet/pub?key=0Am5hHW4ATym7dGhFU1A4X2lqbUJtRm1QSWNRc3E0UlE\&single=true\&gid=0\&output=html)
6. [Google Android Security Team’s Classifications for Potentially Harmful Applications (Malware)](https://source.android.com/security/reports/Google_Android_Security_PHA_classifications.pdf)
7. ~~[Android Devices Security Patch Status](https://kb.androidtamer.com/Device_Security_Patch_tracker/)~~

### Malware

1. [androguard - Database Android Malware wiki](https://code.google.com/p/androguard/wiki/DatabaseAndroidMalwares)
2. [Android Malware Github repo](https://github.com/ashishb/android-malware) ⭐ 1,193 | 🐛 0 | 🌐 Shell | 📅 2025-12-31
3. [Android Malware Genome Project](http://www.malgenomeproject.org/) - contains 1260 malware samples categorized into 49 different malware families, free for research purposes.
4. [Contagio Mobile Malware Mini Dump](http://contagiominidump.blogspot.com)
5. [Drebin](https://www.sec.tu-bs.de/~danarp/drebin/)
6. [Hudson Rock](https://www.hudsonrock.com/threat-intelligence-cybercrime-tools) - A Free cybercrime intelligence toolset that can indicate if a specific APK package was compromised in an Infostealer malware attack.
7. [Kharon Malware Dataset](http://kharon.gforge.inria.fr/dataset/) - 7 malware which have been reverse-engineered and documented
8. [Android Adware and General Malware Dataset](https://www.unb.ca/cic/datasets/android-adware.html)
9. [AndroZoo](https://androzoo.uni.lu/) - AndroZoo is a growing Android application collection from several sources, including the official Google Play app market.
10. ~~[Android PRAGuard Dataset](http://pralab.diee.unica.it/en/AndroidPRAGuardDataset) - The dataset contains 10479 samples, obtained by obfuscating the MalGenome and the Contagio Minidump datasets with seven different obfuscation techniques.~~
11. ~~[Admire](http://admire.necst.it/)~~

### Bounty Programs

1. [Android Security Reward Program](https://www.google.com/about/appsecurity/android-rewards/)

### How to report Security issues

1. [Android - reporting security issues](https://source.android.com/security/overview/updates-resources.html#report-issues)
2. [Android Reports and Resources](https://github.com/B3nac/Android-Reports-and-Resources) ⭐ 1,671 | 🐛 0 | 📅 2025-09-10 - List of Android Hackerone disclosed reports and other resources

## Contributing

Your contributions are always welcome!

## 📖 Citation

```bibtex
@misc{
  author = {Ashish Bhatia - ashishb.net},
  title = {The most comprehensive collection of Android Security related resources},
  year = {2025},
  publisher = {GitHub},
  journal = {GitHub repository},
  howpublished = {\url{https://github.com/ashishb/android-security-awesome}}
}
```

This repository has been cited in [10+ papers](https://scholar.google.com/scholar?q=github.com%2Fashishb%2Fandroid-security-awesome)
