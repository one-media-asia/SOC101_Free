# Prerequisites and Course Resources

- Course repository: [https://github.com/MalwareCube/SOC101_Free](https://github.com/MalwareCube/SOC101_Free)
- SOC Bookmarks file: [https://github.com/MalwareCube/SOC101_Free/blob/main/resources/bookmarks/soc_bookmarks.html](https://github.com/MalwareCube/SOC101_Free/blob/main/resources/bookmarks/soc_bookmarks.html)
- Import a bookmarks file (_Chrome_): [https://support.google.com/chrome/answer/96816?hl=en](https://support.google.com/chrome/answer/96816?hl=en)
- Import a bookmarks file (_Firefox_): [https://support.mozilla.org/en-US/kb/import-bookmarks-html-file](https://support.mozilla.org/en-US/kb/import-bookmarks-html-file)
- Import a bookmarks file (_Edge_): [https://consumer.huawei.com/en/support/content/en-us15879281/](https://consumer.huawei.com/en/support/content/en-us15879281)
- Import a bookmarks file (_Safari_): [https://support.apple.com/en-ca/guide/safari/ibrw1015/mac](https://support.apple.com/en-ca/guide/safari/ibrw1015/mac)
# Installing Oracle VM VirtualBox

- [https://www.virtualbox.org/wiki/Downloads](https://www.virtualbox.org/wiki/Downloads)  
- Install VirtualBox on Mac: [https://cs.hofstra.edu/docs/pages/guides/vbox_mac.html](https://cs.hofstra.edu/docs/pages/guides/vbox_mac.html)  
- Install VirtualBox on Linux: [https://phoenixnap.com/kb/install-virtualbox-on-ubuntu](https://phoenixnap.com/kb/install-virtualbox-on-ubuntu)
- [https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist?view=msvc-170)
# Installing Windows

- [https://www.microsoft.com/en-us/evalcenter/download-windows-10-enterprise](https://www.microsoft.com/en-us/evalcenter/download-windows-10-enterprise)
# Configuring Windows

- [https://git-scm.com/](https://git-scm.com/)
- [https://github.com/MalwareCube/SOC101_Free](https://github.com/MalwareCube/SOC101_Free)
### **Disable real-time protection**

`Set-MpPreference -DisableRealtimeMonitoring $true`
### **Disable the scanning of network files**

`Set-MpPreference -DisableScanningNetworkFiles $true`
### **Disable the blocking of files at first sight**

`Set-MpPreference -DisableBlockAtFirstSeen $true`
### **Disable Windows Defender AntiSpyware**

`reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f`  
### **Clone the course repository**

`git clone https://github.com/MalwareCube/SOC101_Free.git`
# Installing Ubuntu

- Latest Ubuntu desktop download: [https://ubuntu.com/download/desktop](https://ubuntu.com/download/desktop)
- Past Ubuntu releases: [https://releases.ubuntu.com/](https://releases.ubuntu.com/)
### **Update system packages**

`sudo apt update`
### **Install required packages**

`sudo apt install bzip2 tar gcc make perl git`
### **Install the generic kernel headers**

`sudo apt install linux-headers-generic`
### **Install our system-specific kernel headers**

`sudo apt install linux-headers-$(uname -r)`
# Configuring Ubuntu

- [https://github.com/MalwareCube/SOC101_Free](https://github.com/MalwareCube/SOC101_Free)
### **Make sure Git is installed**

`sudo apt install git`
### **Clone the course repository**

`git clone https://github.com/MalwareCube/SOC101_Free.git`

### **Make the install script executable**

`chmod +x ./install.sh`
### **Run the install script**

`./install.sh`
# Common Threats and Attacks

- [https://crowdstrike.com/adversaries/](https://crowdstrike.com/adversaries)
- [https://mandiant.com/resources/insights/apt-groups](https://mandiant.com/resources/insights/apt-groups)
- [https://attack.mitre.org/groups/](https://attack.mitre.org/groups)
# Introduction to Phishing

- [https://abnormalsecurity.com/blog/colonial-pipeline-attack-phishing-email-likely-the-culprit](https://abnormalsecurity.com/blog/colonial-pipeline-attack-phishing-email-likely-the-culprit)
- [https://www.secureworld.io/industry-news/hedge-fund-closes-after-bec-cyber-attac](https://www.secureworld.io/industry-news/hedge-fund-closes-after-bec-cyber-attac)
- [https://krebsonsecurity.com/2015/08/tech-firm-ubiquiti-suffers-46m-cyberheist/](https://krebsonsecurity.com/2015/08/tech-firm-ubiquiti-suffers-46m-cyberheist)
- [https://en.wikipedia.org/wiki/2015_Ukraine_power_grid_hack](https://en.wikipedia.org/wiki/2015_Ukraine_power_grid_hack)
# Phishing Analysis Configuration

- [https://www.sublimetext.com/](https://www.sublimetext.com/)
- Sublime Text installation commands: [https://www.sublimetext.com/docs/linux_repositories.html](https://www.sublimetext.com/docs/linux_repositories.html)
# Phishing Attack Techniques

- [https://bitly.com](https://bitly.com/)
- [https://unshorten.it](https://unshorten.it/)
- [https://www.irongeek.com/homoglyph-attack-generator.php](https://www.irongeek.com/homoglyph-attack-generator.php)
- [https://github.com/elceef/dnstwist](https://github.com/elceef/dnstwist)
- [https://dnstwist.it/](https://dnstwist.it/)
- [https://dnstwister.report/](https://dnstwister.report/)
- [https://phishtank.org/](https://phishtank.org/)
# Email Header and Sender Analysis

- [https://packagecontrol.io/packages/Email%20Header](https://packagecontrol.io/packages/Email%20Header)
- [https://github.com/13Cubed/EmailHeader](https://github.com/13Cubed/EmailHeader)
- [https://www.iana.org/assignments/message-headers/message-headers.xhtml](https://www.iana.org/assignments/message-headers/message-headers.xhtml)
- [https://whois.domaintools.com/](https://whois.domaintools.com/)
- [https://mha.azurewebsites.net/](https://mha.azurewebsites.net/)
- [https://github.com/microsoft/MHA](https://github.com/microsoft/MHA)
- [https://mxtoolbox.com/EmailHeaders.aspx](https://mxtoolbox.com/EmailHeaders.aspx)
# Email Content Analysis

- [https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef)
# Email URL Analysis

- [https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef)
- [https://github.com/MalwareCube/Email-IOC-Extractor](https://github.com/MalwareCube/Email-IOC-Extractor)
- [https://phishtank.org/](https://phishtank.org/)
- [https://www.url2png.com/](https://www.url2png.com/)
- [https://urlscan.io/](https://urlscan.io/)
- [https://www.virustotal.com/gui/home/upload](https://www.virustotal.com/gui/home/upload)
- [https://www.urlvoid.com/](https://www.urlvoid.com/)
- [https://www.wannabrowser.net/](https://www.wannabrowser.net/)
- [https://unshorten.it/](https://unshorten.it/)
- [https://urlhaus.abuse.ch/](https://urlhaus.abuse.ch/)
- [https://transparencyreport.google.com/safe-browsing/search](https://transparencyreport.google.com/safe-browsing/search)
- [https://www.joesandbox.com/](https://www.joesandbox.com/)
# Email Attachment Analysis

- [https://github.com/DidierStevens/DidierStevensSuite/blob/master/emldump.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/emldump.py)
- [https://github.com/MalwareCube/Email-IOC-Extractor](https://github.com/MalwareCube/Email-IOC-Extractor)
- [https://www.virustotal.com/gui/home/upload](https://www.virustotal.com/gui/home/upload)
- [https://talosintelligence.com/](https://talosintelligence.com/)
# Dynamic Attachment Analysis and Sandboxing
- [https://hybrid-analysis.com/](https://hybrid-analysis.com/)
- [https://cloud.google.com/blog/topics/threat-intelligence/cve-2017-0199-hta-handler](https://cloud.google.com/blog/topics/threat-intelligence/cve-2017-0199-hta-handler)
- [https://medium.com/@asmcybersecurity/diving-deeper-into-the-microsoft-office-cve-2017-0199-vulnerability-11bd3e725ab7](https://medium.com/@asmcybersecurity/diving-deeper-into-the-microsoft-office-cve-2017-0199-vulnerability-11bd3e725ab7)
- [https://joesandbox.com](https://joesandbox.com/)
- [https://app.any.run](https://app.any.run/)
# Static MalDoc Analysis

- [https://github.com/DidierStevens/DidierStevensSuite/blob/master/oledump.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/oledump.py)
# Static PDF Analysis

- [https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py)
- [https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdfid.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdfid.py)
# Automated Email Analysis

- [https://www.phishtool.com/](https://www.phishtool.com/)
# Reactive Phishing Defense

- [https://learn.microsoft.com/en-us/exchange/monitoring/trace-an-email-message/message-trace-modern-eac](https://learn.microsoft.com/en-us/exchange/monitoring/trace-an-email-message/message-trace-modern-eac)
- [https://learn.microsoft.com/en-us/purview/ediscovery-content-search-overview](https://learn.microsoft.com/en-us/purview/ediscovery-content-search-overview)
- [https://learn.microsoft.com/en-us/purview/ediscovery-content-search](https://learn.microsoft.com/en-us/purview/ediscovery-content-search)
# Additional Practice

- [https://github.com/rf-peixoto/phishing_pot/](https://github.com/rf-peixoto/phishing_pot)
- [https://phishtank.org/](https://phishtank.org/)
- [https://bazaar.abuse.ch/](https://bazaar.abuse.ch/)
# Introduction to Wireshark

- [https://wireshark.org](https://wireshark.org/)
### **Wireshark Latest Installation (Ubuntu)**

This adds the official Wireshark stable version PPA to the system's package sources. 

```
sudo add-apt-repository ppa:wireshark-dev/stable
sudo apt update
sudo apt install wireshark
```

# Wireshark: Capture and Display Filters

- [https://wiki.wireshark.org/CaptureFilters](https://wiki.wireshark.org/CaptureFilters)
- [https://www.wireshark.org/docs/wsug_html_chunked/ChCapCaptureFilterSection](https://www.wireshark.org/docs/wsug_html_chunked/ChCapCaptureFilterSection)
- [https://wiki.wireshark.org/DisplayFilters](https://wiki.wireshark.org/DisplayFilters)
- [https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html)
# Wireshark: Analyzing Network Traffic

- [https://www.malware-traffic-analysis.net/](https://www.malware-traffic-analysis.net/)
- [https://unit42.paloaltonetworks.com/feb-wireshark-quiz-answers/](https://unit42.paloaltonetworks.com/feb-wireshark-quiz-answers)
- [https://attack.mitre.org/software/S0650/](https://attack.mitre.org/software/S0650)
# Introduction to Snort

- [https://snort.org/](https://snort.org/)

**Note:** If you are attempting to change the `HOME_NET` variable and receive an error when validating the configuration file, such as:

`ERROR: /etc/snort/snort.conf Variable name should contain minimum 1 alphabetic character.`

Instead of taking out `HOME_NET`, keep that variable name in, and replace the `any` keyword with your network range. For example:

`ipvar HOME_NET 10.0.2.0/24`

However, you don't need to change this variable at all if you don't want to. Leaving it default works for our purposes.

# Snort: Reading and Writing Rules

- [https://snort.org/downloads#rule-downloads](https://snort.org/downloads#rule-downloads)
- [https://github.com/chrisjd20/Snorpy](https://github.com/chrisjd20/Snorpy)
- [http://snorpy.cyb3rs3c.net/](http://snorpy.cyb3rs3c.net/) (Alternative URL: [https://anir0y.in/snort2-rulgen/](https://anir0y.in/snort2-rulgen))

# Snort: Intrusion Detection and Prevention

- [http://snorpy.cyb3rs3c.net/](http://snorpy.cyb3rs3c.net/) (Alternative URL: [https://anir0y.in/snort2-rulgen/](https://anir0y.in/snort2-rulgen))

# Additional Practice

- [https://www.malware-traffic-analysis.net/](https://www.malware-traffic-analysis.net/)
- [https://chrissanders.org/packet-captures/](https://chrissanders.org/packet-captures/)
- [https://github.com/chrissanders/packets](https://github.com/chrissanders/packets)
- [https://wiki.wireshark.org/SampleCaptures](https://wiki.wireshark.org/SampleCaptures)
- [https://www.netresec.com/?page=PcapFiles](https://www.netresec.com/?page=PcapFiles)
- [https://github.com/zeek/zeek/tree/master/testing/btest/Traces](https://github.com/zeek/zeek/tree/master/testing/btest/Traces)
- ﻿[https://docs.securityonion.net/en/2.4/pcaps.html](https://docs.securityonion.net/en/2.4/pcaps.html)

# Creating Our Malware

- [https://docs.rapid7.com/metasploit/installing-the-metasploit-framework/](https://docs.rapid7.com/metasploit/installing-the-metasploit-framework)
- [https://github.com/rapid7/metasploit-omnibus](https://github.com/rapid7/metasploit-omnibus)

# Next Steps

This is only the tip of the iceberg! Check out https://academy.tcm-sec.com/p/security-operations-soc-101 for the full course, where we deep dive into:

- Security Operations Fundamentals
- Phishing Analysis
- Network Security Monitoring
- Network Traffic Analysis
- Endpoint Security Monitoring
- Endpoint Detection and Response
- Log Analysis and Management
- Security Information and Event Management (SIEM)
- Threat Intelligence
- Digital Forensics
- Incident Response
