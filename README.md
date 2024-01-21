# Tools Hub

Collection of useful cyber security tools (WIP).

It will be extended, and individual summaries of the tools and one-pagers will be added.

| Tool | Category | Type | Description | Reference |
| ---- | ---- | ---- | ---- | ---- |
| hashID | Password Cracking | Offensive | hashID is a Python tool for identifying over 220 unique hash types using regular expressions. | https://github.com/psypanda/hashID |
| hashcat | Password Cracking | Offensive | Hashcat is an advanced password recovery tool supporting a large number of hash types and attack modes. | https://hashcat.net/hashcat/ |
| Elastic Stack | Security Monitoring | Neutral | Elastic Stack is a set of open source tools for searching, analyzing, and visualizing data in real time. | https://www.elastic.co/elastic-stack |
| MITRE ATT&CK | Security Framework | Neutral | MITRE ATT&CK is a knowledge base of adversary tactics and techniques based on real-world observations. | https://attack.mitre.org/ |
| Event Viewer | Event Logging | Defensive | Event Viewer is a component of Microsoft's Windows NT line of operating systems that lets administrators and users view the event logs on a local or remote machine. | https://en.wikipedia.org/wiki/Event_Viewer |
| Sysmon | System Monitoring | Defensive | System Monitor (Sysmon) is a Windows system service for monitoring and logging system activity to the event log. | https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon |
| Process Hacker | System Management | Neutral | Process Hacker is a multi-purpose tool that helps with monitoring system resources, debugging software, and detecting malware. | https://processhacker.sourceforge.io/ |
| mimikatz | Security Tool | Offensive | Mimikatz is a tool that extracts plaintext passwords, hashes, PIN codes, and kerberos tickets from memory. | https://github.com/gentilkiwi/mimikatz |
| Logman | Logging Utility | Neutral | Logman is a utility for managing Event Tracing for Windows (ETW) and Event Tracing Sessions. | https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/logman |
| Performance Monitor | Performance Monitoring | Neutral | Performance Monitor is a Windows tool for analyzing system and application performance. | https://techcommunity.microsoft.com/t5/ask-the-performance-team/windows-performance-monitor-overview/ba-p/375481 |
| EtwExplorer | Event Tracing | Neutral | EtwExplorer is a GUI tool for viewing ETW Provider metadata and exploring events. | https://github.com/zodiacon/EtwExplorer |
| SilkETW & SilkService | Event Tracing | Neutral | SilkETW & SilkService are C# wrappers for ETW, simplifying the interface for research and introspection. | https://github.com/mandiant/SilkETW |
| Seatbelt | Security Assessment | Neutral | Seatbelt conducts security-oriented host-survey checks from both offensive and defensive perspectives. | https://github.com/GhostPack/Seatbelt |
| Get-WinEvent | Event Logging | Neutral | The `Get-WinEvent` cmdlet is a PowerShell tool for querying Windows Event logs. | https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.3 |
| Splunk | Data Analysis | Neutral | Splunk is a software platform for searching, monitoring, and analyzing machine-generated big data. | https://www.splunk.com/ |
| Active Directory (AD) | Network Management | Neutral | Active Directory is a directory service developed by Microsoft for Windows domain networks. | https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview |
| Rebeus | Security Tool | Offensive | Rubeus is a toolset for raw Kerberos interaction and abuses, adapted from Benjamin Delpy's Kekeo project. | https://github.com/GhostPack/Rubeus |
| PowerSploit | PowerShell Modules | Offensive | PowerSploit is a collection of PowerShell modules for penetration testing. | https://github.com/PowerShellMafia/PowerSploit |
| impacket | Network Protocols | Offensive | Impacket is a collection of Python classes for working with network protocols. | https://github.com/fortra/impacket/tree/master |
| Coercer | Security Tool | Offensive | Coercer is a Python script for coercing a Windows server to authenticate on an arbitrary machine. | https://github.com/p0dalirius/Coercer |
| BloodHound | Network Analysis | Neutral | BloodHound uses graph theory to reveal hidden relationships in Active Directory or Azure environments. | https://github.com/BloodHoundAD/BloodHound |
| Certify | Security Tool | Offensive | Certify is a tool to enumerate and abuse misconfigurations in Active Directory Certificate Services. | https://github.com/GhostPack/Certify |
| tcpdump | Network Analysis | Neutral | tcpdump is a command-line utility for capturing and interpreting network traffic. | https://www.tcpdump.org/ |
| Tshark | Network Analysis | Neutral | TShark is a network packet analyzer, the command-line variant of Wireshark. | https://www.wireshark.org/docs/man-pages/tshark.html |
| Wireshark | Network Analysis | Neutral | Wireshark is a graphical network traffic analyzer for in-depth inspection of network environments. | https://www.wireshark.org/ |
| NGrep | Network Analysis | Neutral | NGrep is a pattern-matching tool for network traffic packets, using regex expressions and BPF syntax. | https://github.com/jpr5/ngrep |
| tcpick | Network Analysis | Neutral | tcpick is a command-line packet sniffer specializing in tracking and reassembling TCP streams. | https://sourceforge.net/projects/tcpick/ |
| Network Taps | Network Monitoring | Neutral | Network Taps are devices for copying network traffic for analysis, either in-line or out of band. | https://www.gigamon.com/<br>https://www.niagaranetworks.com/products/network-tap |
| Networking Span Ports | Network Monitoring | Neutral | Span Ports are used to copy frames from networking devices during processing for collection and logging. | https://en.wikipedia.org/wiki/Port_mirroring |
| Suricata | Intrusion Detection | Defensive | Suricata is a potent tool for Network Intrusion Detection, Intrusion Prevention, and Network Security Monitoring. | https://suricata.io/ |
| Snort | Intrusion Detection | Defensive | Snort is a network inspection tool that can read and analyze network traffic for malicious activity. | https://docs.snort.org/start/inspection |
| Zeek | Network Analysis | Defensive | Zeek is an open-source network traffic analyzer used for scrutinizing network traffic for suspicious or malicious activity. | https://zeek.org/ |
| Velociraptor | Incident Response | Defensive | Velociraptor is a tool for host-based incident response and digital forensics, employing Velocidex Query Language (VQL) for data collection and manipulation. | https://github.com/Velocidex/velociraptor |
| KAPE (Kroll Artifact Parser and Extractor) | Digital Forensics | Defensive | KAPE is a triage tool for collecting and parsing artifacts quickly and effectively, focusing on targeted collection. | https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape |
| pestudio | Malware Analysis | Defensive | pestudio is used to analyze executable files for initial malware assessment, identifying artifacts that are not easily visible. | https://www.winitor.com/ |
| CFF Explorer | File Analysis | Neutral | CFF Explorer includes a PE editor for viewing and editing raw data in executable files, supporting PE32/64 and .NET structures. | https://ntcore.com/?page_id=388 |
| Strings | String Analysis | Neutral | Strings is a utility for scanning files for UNICODE and ASCII strings, particularly useful in NT and Win2K systems. | https://learn.microsoft.com/en-us/sysinternals/downloads/strings |
| ssdeep | Malware Analysis | Defensive | ssdeep computes context triggered piecewise hashes (CTPH) for identifying similarities in files. | https://ssdeep-project.github.io/ssdeep/index.html |
| FLOSS | Malware Analysis | Defensive | FLOSS supports analysts in extracting hidden strings from malware samples, particularly useful for obfuscated strings. | https://www.mandiant.com/resources/blog/floss-version-2 |
| UPX | Executable Packing | Neutral | UPX is a free, secure, portable executable packer for several executable formats. | https://upx.github.io/ |
| Noriben | Malware Analysis | Defensive | Noriben is a Python-based script that automates the collection and analysis of malware indicators with Sysinternals Procmon. | https://github.com/Rurik/Noriben |
| IDA Pro | Disassembly | Neutral | IDA Pro is a disassembler for generating assembly language source code from machine-executable code. | https://hex-rays.com/ida-pro/ |
| x64dbg | Debugging | Neutral | x64dbg is an open-source debugger for Windows, suitable for x64/x32. | https://x64dbg.com/ |
| YARA | Malware Classification | Neutral | YARA is a tool for creating rules to identify and classify malware samples based on textual or binary patterns. | https://virustotal.github.io/yara/ |
| yarGen | Rule Generation | Neutral | yarGen creates yara rules from strings found in malware files, excluding strings also present in goodware files. | https://github.com/Neo23x0/yarGen |
| JavaScript Minifier | Code Minification | Neutral | An online tool for minimizing and compressing JavaScript code. | https://www.toptal.com/developers/javascript-minifier |
| Javascript Obfuscator | Code Obfuscation | Neutral | An online tool that obfuscates JavaScript code to protect it from theft or reuse. | https://beautifytools.com/javascript-obfuscator.php |
| jsconsole | Code Analysis | Neutral | An online JavaScript console for code testing and debugging. | https://jsconsole.com/ |
| JavaScript Obfuscator Tool | Code Obfuscation | Neutral | A web UI for obfuscating JavaScript code, supporting ES2022, making the code harder to copy or steal. | https://obfuscator.io/ |
| Prettier | Code Beautification | Neutral | An online tool for formatting and beautifying code, making it more readable. | https://prettier.io/playground/ |
| js-beautify | Code Beautification | Neutral | An online tool for beautifying JavaScript code to improve readability. | https://beautifier.io/ |
| UnPakcer | Code Analysis | Neutral | An online tool for unpacking and analyzing packed JavaScript code. | https://matthewfl.com/unPacker.html |
| Sigma | Signature Format | Neutral | Sigma is a generic signature format for describing relevant log events in log files. | https://github.com/SigmaHQ/sigma |
| UnpacMe | Malware Unpacking | Defensive | UNPACME is an automated service for unpacking malware and extracting payloads. | https://www.unpac.me/#/ |
| Zircolite | Log Analysis | Defensive | Zircolite is a Python tool for using SIGMA rules on various log formats including EVTX, Auditd logs, and Sysmon for Linux. | https://github.com/wagga40/Zircolite |
| Chainsaw | Log Analysis | Neutral | Chainsaw offers a fast method for searching through Windows forensic artifacts like Event Logs and MFT files for keywords, and identifies threats using built-in Sigma detection rules or custom Chainsaw rules. | https://github.com/WithSecureLabs/chainsaw |
| SRUM | System Monitoring | Neutral | System Resource Utilization Monitor (SRUM) is a Windows feature tracking application usage, network utilization, and energy state, crucial for modern forensic analysis. | https://www.magnetforensics.com/blog/srum-forensic-analysis-of-windows-system-resource-utilization-monitor/ |
| FTK Imager | Forensic Imaging | Defensive | FTK Imager is a digital forensic imaging tool, enabling users to acquire digital evidence with integrity, supporting various image formats. | https://www.exterro.com/ftk-imager |
| Arsenal Image Mounter | Forensic Imaging | Defensive | Arsenal Image Mounter assists in mounting disk images as complete disks, making it easier to conduct digital forensic examinations. | https://arsenalrecon.com/downloads |
| WinPmem | Memory Analysis | Defensive | WinPmem has been a key open-source memory acquisition tool for Windows, essential for detailed forensic analysis. | https://github.com/Velocidex/WinPmem |
| Volatility | Memory Analysis | Defensive | Volatility is an advanced memory forensics framework, essential for analyzing memory dumps and uncovering hidden aspects of OS internals and suspect activities. | https://www.volatilityfoundation.org/releases<br>https://volatility3.readthedocs.io/en/latest/index.html |
| Autopsy | Digital Forensics | Defensive | Autopsy is an open-source end-to-end digital forensics platform, known for its thorough and efficient hard drive investigations. | https://www.autopsy.com/ |
| Zimmerman Tools | Forensic Analysis | Defensive | Zimmerman Tools, including MFTEcmd, Registry Explorer, and others, are crucial for extracting information from various digital artifacts in forensic investigations. | https://ericzimmerman.github.io/#!index.md |
| Active@ Disk Editor | Data Analysis | Neutral | Active@ Disk Editor is a tool for viewing and editing raw data on disks, including physical sectors, partitions, and files, vital for forensic analysis. | https://www.disk-editor.org/index.html |
| RegRipper | Registry Analysis | Neutral | RegRipper is an advanced tool for extracting and analyzing information from the Windows registry, crucial for digital forensic investigations. | https://github.com/keydet89/RegRipper3.0 |
| Spray | Security Tool | Offensive | Spray is an Active Directory password spraying tool, designed for identifying weak credentials in a network. | https://github.com/Greenwolf/Spray |
| psexec | Remote Administration | Offensive | PsExec is a lightweight tool for remote system management, allowing execution of processes on remote systems, often used for both administrative and offensive purposes. | https://learn.microsoft.com/en-us/sysinternals/downloads/psexec |

