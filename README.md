# Awesome Malware Analysis [![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)

A curated list of awesome malware analysis tools and resources. Inspired by
[awesome-python](https://github.com/vinta/awesome-python) and
[awesome-php](https://github.com/ziadoz/awesome-php).

[![Drop ICE](drop.png)](https://twitter.com/githubbers/status/1182017616740663296)

- [Malware Collection](#malware-collection)
    - [Anonymizers](#anonymizers)
    - [Honeypots](#honeypots)
    - [Malware Corpora](#malware-corpora)
- [Open Source Threat Intelligence](#open-source-threat-intelligence)
    - [Tools](#tools)
    - [Other Resources](#other-resources)
- [Detection and Classification](#detection-and-classification)
- [Online Scanners and Sandboxes](#online-scanners-and-sandboxes)
- [Domain Analysis](#domain-analysis)
- [Browser Malware](#browser-malware)
- [Documents and Shellcode](#documents-and-shellcode)
- [File Carving](#file-carving)
- [Deobfuscation](#deobfuscation)
- [Debugging and Reverse Engineering](#debugging-and-reverse-engineering)
- [Network](#network)
- [Memory Forensics](#memory-forensics)
- [Windows Artifacts](#windows-artifacts)
- [Storage and Workflow](#storage-and-workflow)
- [Miscellaneous](#miscellaneous)
- [Resources](#resources)
    - [Books](#books)
    - [Other](#other)
- [Related Awesome Lists](#related-awesome-lists)
- [Contributing](#contributing)
- [Thanks](#thanks)

View Chinese translation: [恶意软件分析大合集.md](恶意软件分析大合集.md).

---

## Malware Collection

### Anonymizers

*Web traffic anonymizers for analysts.*

* [Anonymouse.org](http://anonymouse.org/) - A free, web based anonymizer.
* [OpenVPN](https://openvpn.net/) - VPN software and hosting solutions.
* [Privoxy](http://www.privoxy.org/) - An open source proxy server with some
  privacy features.
* [Tor](https://www.torproject.org/) - The Onion Router, for browsing the web
  without leaving traces of the client IP.

### Honeypots

*Trap and collect your own samples.*

* [Conpot](https://github.com/mushorg/conpot) - ICS/SCADA honeypot.
* [Cowrie](https://github.com/micheloosterhof/cowrie) - SSH honeypot, based
  on Kippo.
* [DemoHunter](https://github.com/RevengeComing/DemonHunter) - Low interaction Distributed Honeypots.
* [Dionaea](https://github.com/DinoTools/dionaea) - Honeypot designed to trap malware.
* [Glastopf](https://github.com/mushorg/glastopf) - Web application honeypot.
* [Honeyd](http://www.honeyd.org/) - Create a virtual honeynet.
* [HoneyDrive](http://bruteforcelab.com/honeydrive) - Honeypot bundle Linux distro.
* [Honeytrap](https://github.com/honeytrap/honeytrap) - Opensource system for running, monitoring and managing honeypots.
* [MHN](https://github.com/pwnlandia/mhn) - MHN is a centralized server for management and data collection of honeypots. MHN allows you to deploy sensors quickly and to collect data immediately, viewable from a neat web interface.
* [Mnemosyne](https://github.com/johnnykv/mnemosyne) - A normalizer for
  honeypot data; supports Dionaea.
* [Thug](https://github.com/buffer/thug) - Low interaction honeyclient, for
  investigating malicious websites.


### Malware Corpora

*Malware samples collected for analysis.*

* [Clean MX](http://support.clean-mx.de/clean-mx/viruses.php) - Realtime
  database of malware and malicious domains.
* [Contagio](http://contagiodump.blogspot.com/) - A collection of recent
  malware samples and analyses.
* [Exploit Database](https://www.exploit-db.com/) - Exploit and shellcode
  samples.
* [Infosec - CERT-PA](https://infosec.cert-pa.it/analyze/submission.html) - Malware samples collection and analysis.
* [InQuest Labs](https://labs.inquest.net) - Evergrowing searchable corpus of malicious Microsoft documents.
* [Javascript Mallware Collection](https://github.com/HynekPetrak/javascript-malware-collection) - Collection of almost 40.000 javascript malware samples
* [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/) - A resource providing
  rapid identification and actionable context for malware investigations.
* [Malshare](https://malshare.com) - Large repository of malware actively
  scrapped from malicious sites.
* [Open Malware Project](http://openmalware.org/) - Sample information and
  downloads. Formerly Offensive Computing.
* [Ragpicker](https://github.com/robbyFux/Ragpicker) - Plugin based malware
  crawler with pre-analysis and reporting functionalities
* [theZoo](https://github.com/ytisf/theZoo) - Live malware samples for
  analysts.
* [Tracker h3x](http://tracker.h3x.eu/) - Agregator for malware corpus tracker
  and malicious download sites.
* [vduddu malware repo](https://github.com/vduddu/Malware) - Collection of
  various malware files and source code.
* [VirusBay](https://beta.virusbay.io/) - Community-Based malware repository and social network.
* [ViruSign](http://www.virussign.com/) - Malware database that detected by
  many anti malware programs except ClamAV.
* [VirusShare](https://virusshare.com/) - Malware repository, registration
  required.
* [VX Vault](http://vxvault.net) - Active collection of malware samples.
* [Zeltser's Sources](https://zeltser.com/malware-sample-sources/) - A list
  of malware sample sources put together by Lenny Zeltser.
* [Zeus Source Code](https://github.com/Visgean/Zeus) - Source for the Zeus
  trojan leaked in 2011.

## Open Source Threat Intelligence

### Tools

*Harvest and analyze IOCs.*

* [AbuseHelper](https://github.com/abusesa/abusehelper) - An open-source
  framework for receiving and redistributing abuse feeds and threat intel.
* [AlienVault Open Threat Exchange](https://otx.alienvault.com/) - Share and
  collaborate in developing Threat Intelligence.
* [Combine](https://github.com/mlsecproject/combine) - Tool to gather Threat
  Intelligence indicators from publicly available sources.
* [Fileintel](https://github.com/keithjjones/fileintel) - Pull intelligence per file hash.
* [Hostintel](https://github.com/keithjjones/hostintel) - Pull intelligence per host.
* [IntelMQ](https://www.enisa.europa.eu/topics/csirt-cert-services/community-projects/incident-handling-automation) -
  A tool for CERTs for processing incident data using a message queue.
* [IOC Editor](https://www.fireeye.com/services/freeware/ioc-editor.html) -
  A free editor for XML IOC files.
* [iocextract](https://github.com/InQuest/python-iocextract) - Advanced Indicator
  of Compromise (IOC) extractor, Python library and command-line tool.
* [ioc_writer](https://github.com/mandiant/ioc_writer) - Python library for
  working with OpenIOC objects, from Mandiant.
* [MalPipe](https://github.com/silascutler/MalPipe) - Malware/IOC ingestion and
  processing engine, that enriches collected data.
* [Massive Octo Spice](https://github.com/csirtgadgets/massive-octo-spice) -
  Previously known as CIF (Collective Intelligence Framework). Aggregates IOCs
  from various lists. Curated by the
  [CSIRT Gadgets Foundation](http://csirtgadgets.org/collective-intelligence-framework).
* [MISP](https://github.com/MISP/MISP) - Malware Information Sharing
  Platform curated by [The MISP Project](http://www.misp-project.org/).
* [Pulsedive](https://pulsedive.com) - Free, community-driven threat intelligence platform collecting IOCs from open-source feeds.
* [PyIOCe](https://github.com/pidydx/PyIOCe) - A Python OpenIOC editor.
* [RiskIQ](https://community.riskiq.com/) - Research, connect, tag and
  share IPs and domains. (Was PassiveTotal.)
* [threataggregator](https://github.com/jpsenior/threataggregator) -
  Aggregates security threats from a number of sources, including some of
  those listed below in [other resources](#other-resources).
* [ThreatConnect](https://threatconnect.com/free/) - TC Open allows you to see and
  share open source threat data, with support and validation from our free community.
* [ThreatCrowd](https://www.threatcrowd.org/) - A search engine for threats,
  with graphical visualization.
* [ThreatIngestor](https://github.com/InQuest/ThreatIngestor/) - Build
  automated threat intel pipelines sourcing from Twitter, RSS, GitHub, and
  more.
* [ThreatTracker](https://github.com/michael-yip/ThreatTracker) - A Python
  script to monitor and generate alerts based on IOCs indexed by a set of
  Google Custom Search Engines.
* [TIQ-test](https://github.com/mlsecproject/tiq-test) - Data visualization
  and statistical analysis of Threat Intelligence feeds.

### Other Resources

*Threat intelligence and IOC resources.*

* [Autoshun](https://www.autoshun.org/) ([list](https://www.autoshun.org/files/shunlist.csv)) -
  Snort plugin and blocklist.
* [Bambenek Consulting Feeds](http://osint.bambenekconsulting.com/feeds/) -
  OSINT feeds based on malicious DGA algorithms.
* [Fidelis Barncat](https://www.fidelissecurity.com/resources/fidelis-barncat) -
  Extensive malware config database (must request access).
* [CI Army](http://cinsscore.com/) ([list](http://cinsscore.com/list/ci-badguys.txt)) -
  Network security blocklists.
* [Critical Stack- Free Intel Market](https://intel.criticalstack.com) - Free
  intel aggregator with deduplication featuring 90+ feeds and over 1.2M indicators.
* [Cybercrime tracker](http://cybercrime-tracker.net/) - Multiple botnet active tracker.
* [FireEye IOCs](https://github.com/fireeye/iocs) - Indicators of Compromise
  shared publicly by FireEye.
* [FireHOL IP Lists](https://iplists.firehol.org/) - Analytics for 350+ IP lists
  with a focus on attacks, malware and abuse. Evolution, Changes History,
  Country Maps, Age of IPs listed, Retention Policy, Overlaps.
* [HoneyDB](https://riskdiscovery.com/honeydb) - Community driven honeypot sensor data collection and aggregation.
* [hpfeeds](https://github.com/rep/hpfeeds) - Honeypot feed protocol.
* [Infosec - CERT-PA lists](https://infosec.cert-pa.it/analyze/statistics.html) ([IPs](https://infosec.cert-pa.it/analyze/listip.txt) - [Domains](https://infosec.cert-pa.it/analyze/listdomains.txt) - [URLs](https://infosec.cert-pa.it/analyze/listurls.txt)) - Blocklist service.
* [InQuest REPdb](https://labs.inquest.net/repdb) - Continuous aggregation of IOCs from a variety of open reputation sources.
* [InQuest IOCdb](https://labs.inquest.net/iocdb) - Continuous aggregation of IOCs from a variety of blogs, Github repos, and Twitter.
* [Internet Storm Center (DShield)](https://isc.sans.edu/) - Diary and
  searchable incident database, with a web [API](https://dshield.org/api/).
  ([unofficial Python library](https://github.com/rshipp/python-dshield)).
* [malc0de](http://malc0de.com/database/) - Searchable incident database.
* [Malware Domain List](http://www.malwaredomainlist.com/) - Search and share
  malicious URLs.
* [MetaDefender Threat Intelligence Feed](https://www.opswat.com/developers/threat-intelligence-feed) -
  List of the most looked up file hashes from MetaDefender Cloud.
* [OpenIOC](https://www.fireeye.com/services/freeware.html) - Framework for sharing threat intelligence.
* [Proofpoint Threat Intelligence](https://www.proofpoint.com/us/products/et-intelligence) -
  Rulesets and more. (Formerly Emerging Threats.)
* [Ransomware overview](https://docs.google.com/spreadsheets/d/1TWS238xacAto-fLKh1n5uTsdijWdCEsGIM0Y0Hvmc5g/pubhtml) -
  A list of ransomware overview with details, detection and prevention.
* [STIX - Structured Threat Information eXpression](http://stixproject.github.io) -
  Standardized language to represent and share cyber threat information.
  Related efforts from [MITRE](https://www.mitre.org/):
  - [CAPEC - Common Attack Pattern Enumeration and Classification](http://capec.mitre.org/)
  - [CybOX - Cyber Observables eXpression](http://cyboxproject.github.io)
  - [MAEC - Malware Attribute Enumeration and Characterization](http://maec.mitre.org/)
  - [TAXII - Trusted Automated eXchange of Indicator Information](http://taxiiproject.github.io)
* [SystemLookup](https://www.systemlookup.com/) - SystemLookup hosts a collection of lists that provide information on
  the components of legitimate and potentially unwanted programs.
* [ThreatMiner](https://www.threatminer.org/) - Data mining portal for threat
  intelligence, with search.
* [threatRECON](https://threatrecon.co/) - Search for indicators, up to 1000
  free per month.
* [Yara rules](https://github.com/Yara-Rules/rules) - Yara rules repository.
* [YETI](https://github.com/yeti-platform/yeti) - Yeti is a platform meant to organize observables, indicators of compromise, TTPs, and knowledge on threats in a single, unified repository.
* [ZeuS Tracker](https://zeustracker.abuse.ch/blocklist.php) - ZeuS
  blocklists.

## Detection and Classification

*Antivirus and other malware identification tools*

* [AnalyzePE](https://github.com/hiddenillusion/AnalyzePE) - Wrapper for a
  variety of tools for reporting on Windows PE files.
* [Assemblyline](https://bitbucket.org/cse-assemblyline/assemblyline) - A scalable
  distributed file analysis framework.
* [BinaryAlert](https://github.com/airbnb/binaryalert) - An open source, serverless
  AWS pipeline that scans and alerts on uploaded files based on a set of
  YARA rules.
* [chkrootkit](http://www.chkrootkit.org/) - Local Linux rootkit detection.
* [ClamAV](http://www.clamav.net/) - Open source antivirus engine.
* [Detect It Easy(DiE)](https://github.com/horsicq/Detect-It-Easy) - A program for
  determining types of files.
* [Exeinfo PE](http://exeinfo.pe.hu/) - Packer, compressor detector, unpack
  info, internal exe tools.
* [ExifTool](https://sno.phy.queensu.ca/~phil/exiftool/) - Read, write and
  edit file metadata.
* [File Scanning Framework](https://github.com/EmersonElectricCo/fsf) -
  Modular, recursive file scanning solution.
* [Generic File Parser](https://github.com/uppusaikiran/generic-parser) - A Single Library Parser to extract meta information,static analysis and detect macros within the files.
* [hashdeep](https://github.com/jessek/hashdeep) - Compute digest hashes with
  a variety of algorithms.
* [HashCheck](https://github.com/gurnec/HashCheck) - Windows shell extension
  to compute hashes with a variety of algorithms.
* [Loki](https://github.com/Neo23x0/Loki) - Host based scanner for IOCs.
* [Malfunction](https://github.com/Dynetics/Malfunction) - Catalog and
  compare malware at a function level.
* [Manalyze](https://github.com/JusticeRage/Manalyze) - Static analyzer for PE
executables.
* [MASTIFF](https://github.com/KoreLogicSecurity/mastiff) - Static analysis
  framework.
* [MultiScanner](https://github.com/mitre/multiscanner) - Modular file
  scanning/analysis framework
* [Nauz File Detector(NFD)](https://github.com/horsicq/Nauz-File-Detector) - Linker/Compiler/Tool detector  for Windows, Linux and MacOS.
* [nsrllookup](https://github.com/rjhansen/nsrllookup) - A tool for looking
  up hashes in NIST's National Software Reference Library database.
* [packerid](http://handlers.sans.org/jclausing/packerid.py) - A cross-platform
  Python alternative to PEiD.
* [PE-bear](https://hshrzd.wordpress.com/pe-bear/) - Reversing tool for PE
  files.
* [PEframe](https://github.com/guelfoweb/peframe) - PEframe is an open source tool to perform static analysis on Portable Executable malware and malicious MS Office documents.
* [PEV](http://pev.sourceforge.net/) - A multiplatform toolkit to work with PE
  files, providing feature-rich tools for proper analysis of suspicious binaries.
* [PortEx](https://github.com/katjahahn/PortEx) - Java library to analyse PE files with a special focus on malware analysis and PE malformation robustness.
* [Quark-Engine](https://github.com/quark-engine/quark-engine) - An Obfuscation-Neglect Android Malware Scoring System
* [Rootkit Hunter](http://rkhunter.sourceforge.net/) - Detect Linux rootkits.
* [ssdeep](https://ssdeep-project.github.io/ssdeep/) - Compute fuzzy hashes.
* [totalhash.py](https://gist.github.com/gleblanc1783/3c8e6b379fa9d646d401b96ab5c7877f) -
  Python script for easy searching of the [TotalHash.cymru.com](https://totalhash.cymru.com/)
  database.
* [TrID](http://mark0.net/soft-trid-e.html) - File identifier.
* [YARA](https://plusvic.github.io/yara/) - Pattern matching tool for
  analysts.
* [Yara rules generator](https://github.com/Neo23x0/yarGen) - Generate
  yara rules based on a set of malware samples. Also contains a good
  strings DB to avoid false positives.
* [Yara Finder](https://github.com/uppusaikiran/yara-finder) - A simple tool to yara match the file against various yara rules to find the indicators of suspicion.


## Online Scanners and Sandboxes

*Web-based multi-AV scanners, and malware sandboxes for automated analysis.*

* [anlyz.io](https://sandbox.anlyz.io/) - Online sandbox.
* [any.run](https://app.any.run/) - Online interactive sandbox.
* [AndroTotal](https://andrototal.org/) - Free online analysis of APKs
  against multiple mobile antivirus apps.
* [AVCaesar](https://avcaesar.malware.lu/) - Malware.lu online scanner and
  malware repository.
* [BoomBox](https://github.com/nbeede/BoomBox) - Automatic deployment of Cuckoo
  Sandbox malware lab using Packer and Vagrant.
* [Cryptam](http://www.cryptam.com/) - Analyze suspicious office documents.
* [Cuckoo Sandbox](https://cuckoosandbox.org/) - Open source, self hosted
  sandbox and automated analysis system.
* [cuckoo-modified](https://github.com/brad-accuvant/cuckoo-modified) - Modified
  version of Cuckoo Sandbox released under the GPL. Not merged upstream due to
  legal concerns by the author.
* [cuckoo-modified-api](https://github.com/keithjjones/cuckoo-modified-api) - A
  Python API used to control a cuckoo-modified sandbox.
* [DeepViz](https://www.deepviz.com/) - Multi-format file analyzer with
  machine-learning classification.
* [detux](https://github.com/detuxsandbox/detux/) - A sandbox developed to do
  traffic analysis of Linux malwares and capturing IOCs.
* [DRAKVUF](https://github.com/tklengyel/drakvuf) - Dynamic malware analysis
  system.
* [firmware.re](http://firmware.re/) - Unpacks, scans and analyzes almost any
  firmware package.
* [HaboMalHunter](https://github.com/Tencent/HaboMalHunter) - An Automated Malware
  Analysis Tool for Linux ELF Files.
* [Hybrid Analysis](https://www.hybrid-analysis.com/) - Online malware
  analysis tool, powered by VxSandbox.
* [Intezer](https://analyze.intezer.com) - Detect, analyze, and categorize malware by
  identifying code reuse and code similarities.
* [IRMA](http://irma.quarkslab.com/) - An asynchronous and customizable
  analysis platform for suspicious files.
* [Joe Sandbox](https://www.joesecurity.org) - Deep malware analysis with Joe Sandbox.
* [Jotti](https://virusscan.jotti.org/en) - Free online multi-AV scanner.
* [Limon](https://github.com/monnappa22/Limon) - Sandbox for Analyzing Linux Malware.
* [Malheur](https://github.com/rieck/malheur) - Automatic sandboxed analysis
  of malware behavior.
* [malice.io](https://github.com/maliceio/malice) - Massively scalable malware analysis framework.
* [malsub](https://github.com/diogo-fernan/malsub) - A Python RESTful API framework for
  online malware and URL analysis services.
* [Malware config](https://malwareconfig.com/) - Extract, decode and display online
  the configuration settings from common malwares.
* [MalwareAnalyser.io](https://malwareanalyser.io/) - Online malware anomaly-based static analyser with heuristic detection engine powered by data mining and machine learning.
* [Malwr](https://malwr.com/) - Free analysis with an online Cuckoo Sandbox
  instance.
* [MetaDefender Cloud](https://metadefender.opswat.com/ ) - Scan a file, hash, IP, URL or
  domain address for malware for free.
* [NetworkTotal](https://www.networktotal.com/index.html) - A service that analyzes
  pcap files and facilitates the quick detection of viruses, worms, trojans, and all
  kinds of malware using Suricata configured with EmergingThreats Pro.
* [Noriben](https://github.com/Rurik/Noriben) - Uses Sysinternals Procmon to
  collect information about malware in a sandboxed environment.
* [PacketTotal](https://packettotal.com/) - PacketTotal is an online engine for analyzing .pcap files, and visualizing the network traffic within.
* [PDF Examiner](http://www.pdfexaminer.com/) - Analyse suspicious PDF files.
* [ProcDot](http://www.procdot.com) - A graphical malware analysis tool kit.
* [Recomposer](https://github.com/secretsquirrel/recomposer) - A helper
  script for safely uploading binaries to sandbox sites.
* [sandboxapi](https://github.com/InQuest/python-sandboxapi) - Python library for
  building integrations with several open source and commercial malware sandboxes.
* [SEE](https://github.com/F-Secure/see) - Sandboxed Execution Environment (SEE)
  is a framework for building test automation in secured Environments.
* [SEKOIA Dropper Analysis](https://malware.sekoia.fr/) - Online dropper analysis (Js, VBScript, Microsoft Office, PDF).
* [VirusTotal](https://www.virustotal.com/) - Free online analysis of malware
  samples and URLs
* [Visualize_Logs](https://github.com/keithjjones/visualize_logs) - Open source
  visualization library and command line tools for logs.  (Cuckoo, Procmon, more
  to come...)
* [Zeltser's List](https://zeltser.com/automated-malware-analysis/) - Free
  automated sandboxes and services, compiled by Lenny Zeltser.

## Domain Analysis

*Inspect domains and IP addresses.*

* [AbuseIPDB](https://www.abuseipdb.com/) - AbuseIPDB is a project dedicated
  to helping combat the spread of hackers, spammers, and abusive activity on the internet.
* [badips.com](https://www.badips.com/) - Community based IP blacklist service.
* [boomerang](https://github.com/EmersonElectricCo/boomerang) - A tool designed
  for consistent and safe capture of off network web resources.
* [Cymon](https://cymon.io/) - Threat intelligence tracker, with IP/domain/hash
  search.
* [Desenmascara.me](http://desenmascara.me) - One click tool to retrieve as
  much metadata as possible for a website and to assess its good standing.
* [Dig](https://networking.ringofsaturn.com/) - Free online dig and other
  network tools.
* [dnstwist](https://github.com/elceef/dnstwist) - Domain name permutation
  engine for detecting typo squatting, phishing and corporate espionage.
* [IPinfo](https://github.com/hiddenillusion/IPinfo) - Gather information
  about an IP or domain by searching online resources.
* [Machinae](https://github.com/hurricanelabs/machinae) - OSINT tool for
  gathering information about URLs, IPs, or hashes. Similar to Automator.
* [mailchecker](https://github.com/FGRibreau/mailchecker) - Cross-language
  temporary email detection library.
* [MaltegoVT](https://github.com/michael-yip/MaltegoVT) - Maltego transform
  for the VirusTotal API. Allows domain/IP research, and searching for file
  hashes and scan reports.
* [Multi rbl](http://multirbl.valli.org/) - Multiple DNS blacklist and forward
  confirmed reverse DNS lookup over more than 300 RBLs.
* [NormShield Services](https://services.normshield.com/) - Free API Services
  for detecting possible phishing domains, blacklisted ip addresses and breached
  accounts.
* [PhishStats](https://phishstats.info/) - Phishing Statistics with search for
  IP, domain and website title
* [Spyse](https://spyse.com/) - subdomains, whois, realted domains, DNS, hosts AS, SSL/TLS info,  
* [SecurityTrails](https://securitytrails.com/) - Historical and current WHOIS,
  historical and current DNS records, similar domains, certificate information
  and other domain and IP related API and tools.
* [SpamCop](https://www.spamcop.net/bl.shtml) - IP based spam block list.
* [SpamHaus](https://www.spamhaus.org/lookup/) - Block list based on
  domains and IPs.
* [Sucuri SiteCheck](https://sitecheck.sucuri.net/) - Free Website Malware
  and Security Scanner.
* [Talos Intelligence](https://talosintelligence.com/) - Search for IP, domain
  or network owner. (Previously SenderBase.)
* [TekDefense Automater](http://www.tekdefense.com/automater/) - OSINT tool
  for gathering information about URLs, IPs, or hashes.
* [URLhaus](https://urlhaus.abuse.ch/) - A project from abuse.ch with the goal
  of sharing malicious URLs that are being used for malware distribution.
* [URLQuery](http://urlquery.net/) - Free URL Scanner.
* [urlscan.io](https://urlscan.io/) - Free URL Scanner & domain information.
* [Whois](https://whois.domaintools.com/) - DomainTools free online whois
  search.
* [Zeltser's List](https://zeltser.com/lookup-malicious-websites/) - Free
  online tools for researching malicious websites, compiled by Lenny Zeltser.
* [ZScalar Zulu](https://zulu.zscaler.com/#) - Zulu URL Risk Analyzer.

## Browser Malware

*Analyze malicious URLs. See also the [domain analysis](#domain-analysis) and
[documents and shellcode](#documents-and-shellcode) sections.*

* [Firebug](https://getfirebug.com/) - Firefox extension for web development.
* [Java Decompiler](http://jd.benow.ca/) - Decompile and inspect Java apps.
* [Java IDX Parser](https://github.com/Rurik/Java_IDX_Parser/) - Parses Java
  IDX cache files.
* [JSDetox](http://www.relentless-coding.com/projects/jsdetox/) - JavaScript
  malware analysis tool.
* [jsunpack-n](https://github.com/urule99/jsunpack-n) - A javascript
  unpacker that emulates browser functionality.
* [Krakatau](https://github.com/Storyyeller/Krakatau) - Java decompiler,
  assembler, and disassembler.
* [Malzilla](http://malzilla.sourceforge.net/) - Analyze malicious web pages.
* [RABCDAsm](https://github.com/CyberShadow/RABCDAsm) - A "Robust
  ActionScript Bytecode Disassembler."
* [SWF Investigator](https://labs.adobe.com/technologies/swfinvestigator/) -
  Static and dynamic analysis of SWF applications.
* [swftools](http://www.swftools.org/) - Tools for working with Adobe Flash
  files.
* [xxxswf](http://hooked-on-mnemonics.blogspot.com/2011/12/xxxswfpy.html) - A
  Python script for analyzing Flash files.

## Documents and Shellcode

*Analyze malicious JS and shellcode from PDFs and Office documents. See also
the [browser malware](#browser-malware) section.*

* [AnalyzePDF](https://github.com/hiddenillusion/AnalyzePDF) - A tool for
  analyzing PDFs and attempting to determine whether they are malicious.
* [box-js](https://github.com/CapacitorSet/box-js) - A tool for studying JavaScript
  malware, featuring JScript/WScript support and ActiveX emulation.
* [diStorm](http://www.ragestorm.net/distorm/) - Disassembler for analyzing
  malicious shellcode.
* [InQuest Deep File Inspection](https://labs.inquest.net/dfi) - Upload common malware lures for Deep File Inspection and heuristical analysis.
* [JS Beautifier](http://jsbeautifier.org/) - JavaScript unpacking and deobfuscation.
* [libemu](http://libemu.carnivore.it/) - Library and tools for x86 shellcode
  emulation.
* [malpdfobj](https://github.com/9b/malpdfobj) - Deconstruct malicious PDFs
  into a JSON representation.
* [OfficeMalScanner](http://www.reconstructer.org/code.html) - Scan for
  malicious traces in MS Office documents.
* [olevba](http://www.decalage.info/python/olevba) - A script for parsing OLE
  and OpenXML documents and extracting useful information.
* [Origami PDF](https://code.google.com/archive/p/origami-pdf) - A tool for
  analyzing malicious PDFs, and more.
* [PDF Tools](https://blog.didierstevens.com/programs/pdf-tools/) - pdfid,
  pdf-parser, and more from Didier Stevens.
* [PDF X-Ray Lite](https://github.com/9b/pdfxray_lite) - A PDF analysis tool,
  the backend-free version of PDF X-RAY.
* [peepdf](http://eternal-todo.com/tools/peepdf-pdf-analysis-tool) - Python
  tool for exploring possibly malicious PDFs.
* [QuickSand](https://www.quicksand.io/) - QuickSand is a compact C framework
  to analyze suspected malware documents to identify exploits in streams of different
  encodings and to locate and extract embedded executables.
* [Spidermonkey](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/SpiderMonkey) -
  Mozilla's JavaScript engine, for debugging malicious JS.

## File Carving

*For extracting files from inside disk and memory images.*

* [bulk_extractor](https://github.com/simsong/bulk_extractor) - Fast file
  carving tool.
* [EVTXtract](https://github.com/williballenthin/EVTXtract) - Carve Windows
  Event Log files from raw binary data.
* [Foremost](http://foremost.sourceforge.net/) - File carving tool designed
  by the US Air Force.
* [hachoir3](https://github.com/vstinner/hachoir3) - Hachoir is a Python library
  to view and edit a binary stream field by field.
* [Scalpel](https://github.com/sleuthkit/scalpel) - Another data carving
  tool.
* [SFlock](https://github.com/jbremer/sflock) - Nested archive
  extraction/unpacking (used in Cuckoo Sandbox).

## Deobfuscation

*Reverse XOR and other code obfuscation methods.*

* [Balbuzard](https://bitbucket.org/decalage/balbuzard/wiki/Home) - A malware
  analysis tool for reversing obfuscation (XOR, ROL, etc) and more.
* [de4dot](https://github.com/0xd4d/de4dot) - .NET deobfuscator and
  unpacker.
* [ex_pe_xor](http://hooked-on-mnemonics.blogspot.com/2014/04/expexorpy.html)
  & [iheartxor](http://hooked-on-mnemonics.blogspot.com/p/iheartxor.html) -
  Two tools from Alexander Hanel for working with single-byte XOR encoded
  files.
* [FLOSS](https://github.com/fireeye/flare-floss) - The FireEye Labs Obfuscated
  String Solver uses advanced static analysis techniques to automatically
  deobfuscate strings from malware binaries.
* [NoMoreXOR](https://github.com/hiddenillusion/NoMoreXOR) - Guess a 256 byte
  XOR key using frequency analysis.
* [PackerAttacker](https://github.com/BromiumLabs/PackerAttacker) - A generic
  hidden code extractor for Windows malware.
* [un{i}packer](https://github.com/unipacker/unipacker) - Automatic and
  platform-independent unpacker for Windows binaries based on emulation.
* [unpacker](https://github.com/malwaremusings/unpacker/) - Automated malware
  unpacker for Windows malware based on WinAppDbg.
* [unxor](https://github.com/tomchop/unxor/) - Guess XOR keys using
  known-plaintext attacks.
* [VirtualDeobfuscator](https://github.com/jnraber/VirtualDeobfuscator) -
  Reverse engineering tool for virtualization wrappers.
* [XORBruteForcer](http://eternal-todo.com/var/scripts/xorbruteforcer) -
  A Python script for brute forcing single-byte XOR keys.
* [XORSearch & XORStrings](https://blog.didierstevens.com/programs/xorsearch/) -
  A couple programs from Didier Stevens for finding XORed data.
* [xortool](https://github.com/hellman/xortool) - Guess XOR key length, as
  well as the key itself.

## Debugging and Reverse Engineering

*Disassemblers, debuggers, and other static and dynamic analysis tools.*

* [angr](https://github.com/angr/angr) - Platform-agnostic binary analysis
  framework developed at UCSB's Seclab.
* [bamfdetect](https://github.com/bwall/bamfdetect) - Identifies and extracts
  information from bots and other malware.
* [BAP](https://github.com/BinaryAnalysisPlatform/bap) - Multiplatform and
  open source (MIT) binary analysis framework developed at CMU's Cylab.
* [BARF](https://github.com/programa-stic/barf-project) - Multiplatform, open
  source Binary Analysis and Reverse engineering Framework.
* [binnavi](https://github.com/google/binnavi) - Binary analysis IDE for
  reverse engineering based on graph visualization.
* [Binary ninja](https://binary.ninja/) - A reversing engineering platform
  that is an alternative to IDA.
* [Binwalk](https://github.com/devttys0/binwalk) - Firmware analysis tool.
* [Capstone](https://github.com/aquynh/capstone) - Disassembly framework for
  binary analysis and reversing, with support for many architectures and
  bindings in several languages.
* [codebro](https://github.com/hugsy/codebro) - Web based code browser using
  clang to provide basic code analysis.
* [Cutter](https://github.com/radareorg/cutter) - GUI for Radare2.
* [DECAF (Dynamic Executable Code Analysis Framework)](https://github.com/sycurelab/DECAF)
  - A binary analysis platform based   on QEMU. DroidScope is now an extension to DECAF.
* [dnSpy](https://github.com/0xd4d/dnSpy) - .NET assembly editor, decompiler
  and debugger.
* [dotPeek](https://www.jetbrains.com/decompiler/) - Free .NET Decompiler and
  Assembly Browser.
* [Evan's Debugger (EDB)](http://codef00.com/projects#debugger) - A
  modular debugger with a Qt GUI.
* [Fibratus](https://github.com/rabbitstack/fibratus) - Tool for exploration
  and tracing of the Windows kernel.
* [FPort](https://www.mcafee.com/us/downloads/free-tools/fport.aspx) - Reports
  open TCP/IP and UDP ports in a live system and maps them to the owning application.
* [GDB](http://www.sourceware.org/gdb/) - The GNU debugger.
* [GEF](https://github.com/hugsy/gef) - GDB Enhanced Features, for exploiters
  and reverse engineers.
* [Ghidra](https://github.com/NationalSecurityAgency/ghidra) - A software reverse engineering (SRE) framework created and       maintained by the National Security Agency Research Directorate.
* [hackers-grep](https://github.com/codypierce/hackers-grep) - A utility to
  search for strings in PE executables including imports, exports, and debug
  symbols.
* [Hopper](https://www.hopperapp.com/) - The macOS and Linux Disassembler.
* [IDA Pro](https://www.hex-rays.com/products/ida/index.shtml) - Windows
  disassembler and debugger, with a free evaluation version.
* [IDR](https://github.com/crypto2011/IDR) - Interactive Delphi Reconstructor
  is a decompiler of Delphi executable files and dynamic libraries.
* [Immunity Debugger](http://debugger.immunityinc.com/) - Debugger for
  malware analysis and more, with a Python API.
* [ILSpy](http://ilspy.net/) - ILSpy is the open-source .NET assembly browser and decompiler.
* [Kaitai Struct](http://kaitai.io/) - DSL for file formats / network protocols /
  data structures reverse engineering and dissection, with code generation
  for C++, C#, Java, JavaScript, Perl, PHP, Python, Ruby.
* [LIEF](https://lief.quarkslab.com/) - LIEF provides a cross-platform library
  to parse, modify and abstract ELF, PE and MachO formats.
* [ltrace](http://ltrace.org/) - Dynamic analysis for Linux executables.
* [mac-a-mal](https://github.com/phdphuc/mac-a-mal) - An automated framework
  for mac malware hunting.
* [objdump](https://en.wikipedia.org/wiki/Objdump) - Part of GNU binutils,
  for static analysis of Linux binaries.
* [OllyDbg](http://www.ollydbg.de/) - An assembly-level debugger for Windows
  executables.
* [PANDA](https://github.com/moyix/panda) - Platform for Architecture-Neutral
  Dynamic Analysis.
* [PEDA](https://github.com/longld/peda) - Python Exploit Development
  Assistance for GDB, an enhanced display with added commands.
* [pestudio](https://winitor.com/) - Perform static analysis of Windows
  executables.
* [Pharos](https://github.com/cmu-sei/pharos) - The Pharos binary analysis framework
  can be used to perform automated static analysis of binaries.
* [plasma](https://github.com/plasma-disassembler/plasma) - Interactive
  disassembler for x86/ARM/MIPS.
* [PPEE (puppy)](https://www.mzrst.com/) - A Professional PE file Explorer for
  reversers, malware researchers and those who want to statically inspect PE
  files in more detail.
* [Process Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/process-explorer) -
  Advanced task manager for Windows.
* [Process Hacker](http://processhacker.sourceforge.net/) - Tool that monitors
  system resources.
* [Process Monitor](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) -
  Advanced monitoring tool for Windows programs.
* [PSTools](https://docs.microsoft.com/en-us/sysinternals/downloads/pstools) - Windows
  command-line tools that help manage and investigate live systems.
* [Pyew](https://github.com/joxeankoret/pyew) - Python tool for malware
  analysis.
* [PyREBox](https://github.com/Cisco-Talos/pyrebox) - Python scriptable reverse
  engineering sandbox by the Talos team at Cisco.
* [QKD](https://github.com/ispras/qemu/releases/) - QEMU with embedded WinDbg
  server for stealth debugging.
* [Radare2](http://www.radare.org/r/) - Reverse engineering framework, with
  debugger support.
* [RegShot](https://sourceforge.net/projects/regshot/) - Registry compare utility
  that compares snapshots.
* [RetDec](https://retdec.com/) - Retargetable machine-code decompiler with an
  [online decompilation service](https://retdec.com/decompilation/) and
  [API](https://retdec.com/api/) that you can use in your tools.
* [ROPMEMU](https://github.com/Cisco-Talos/ROPMEMU) - A framework to analyze, dissect
  and decompile complex code-reuse attacks.
* [SMRT](https://github.com/pidydx/SMRT) - Sublime Malware Research Tool, a
  plugin for Sublime 3 to aid with malware analyis.
* [strace](https://sourceforge.net/projects/strace/) - Dynamic analysis for
  Linux executables.
* [StringSifter](https://github.com/fireeye/stringsifter) - A machine learning tool 
  that automatically ranks strings based on their relevance for malware analysis.
* [Triton](https://triton.quarkslab.com/) - A dynamic binary analysis (DBA) framework.
* [Udis86](https://github.com/vmt/udis86) - Disassembler library and tool
  for x86 and x86_64.
* [Vivisect](https://github.com/vivisect/vivisect) - Python tool for
  malware analysis.
* [WinDbg](https://developer.microsoft.com/en-us/windows/hardware/download-windbg) - multipurpose debugger for the Microsoft Windows computer operating system, used to debug user mode applications, device drivers, and the kernel-mode memory dumps.
* [X64dbg](https://github.com/x64dbg/) - An open-source x64/x32 debugger for windows.

## Network

*Analyze network interactions.*

* [Bro](https://www.bro.org) - Protocol analyzer that operates at incredible
  scale; both file and network protocols.
* [BroYara](https://github.com/hempnall/broyara) - Use Yara rules from Bro.
* [CapTipper](https://github.com/omriher/CapTipper) -  Malicious HTTP traffic
  explorer.
* [chopshop](https://github.com/MITRECND/chopshop) - Protocol analysis and
  decoding framework.
* [CloudShark](https://www.cloudshark.org) - Web-based tool for packet analysis
  and malware traffic detection.
* [FakeNet-NG](https://github.com/fireeye/flare-fakenet-ng) - Next generation
  dynamic network analysis tool.
* [Fiddler](https://www.telerik.com/fiddler) - Intercepting web proxy designed
  for "web debugging."
* [Hale](https://github.com/pjlantz/Hale) - Botnet C&C monitor.
* [Haka](http://www.haka-security.org/) - An open source security oriented
  language for describing protocols and applying security policies on (live)
  captured traffic.
* [HTTPReplay](https://github.com/jbremer/httpreplay) - Library for parsing
  and reading out PCAP files, including TLS streams using TLS Master Secrets
  (used in Cuckoo Sandbox).
* [INetSim](http://www.inetsim.org/) - Network service emulation, useful when
  building a malware lab.
* [Laika BOSS](https://github.com/lmco/laikaboss) - Laika BOSS is a file-centric
  malware analysis and intrusion detection system.
* [Malcolm](https://github.com/idaholab/Malcolm) - Malcolm is a powerful, easily
  deployable network traffic analysis tool suite for full packet capture artifacts
  (PCAP files) and Zeek logs.
* [Malcom](https://github.com/tomchop/malcom) - Malware Communications
  Analyzer.
* [Maltrail](https://github.com/stamparm/maltrail) - A malicious traffic
  detection system, utilizing publicly available (black)lists containing
  malicious and/or generally suspicious trails and featuring an reporting
  and analysis interface.
* [mitmproxy](https://mitmproxy.org/) - Intercept network traffic on the fly.
* [Moloch](https://github.com/aol/moloch) - IPv4 traffic capturing, indexing
  and database system.
* [NetworkMiner](http://www.netresec.com/?page=NetworkMiner) - Network
  forensic analysis tool, with a free version.
* [ngrep](https://github.com/jpr5/ngrep) - Search through network traffic
  like grep.
* [PcapViz](https://github.com/mateuszk87/PcapViz) - Network topology and
  traffic visualizer.
* [Python ICAP Yara](https://github.com/RamadhanAmizudin/python-icap-yara) - An
  ICAP Server with yara scanner for URL or content.
* [Squidmagic](https://github.com/ch3k1/squidmagic) - squidmagic is a tool
  designed to analyze a web-based network traffic to detect central command
  and control (C&C) servers and malicious sites, using Squid proxy server and
  Spamhaus.
* [Tcpdump](http://www.tcpdump.org/) - Collect network traffic.
* [tcpick](http://tcpick.sourceforge.net/) - Trach and reassemble TCP streams
  from network traffic.
* [tcpxtract](http://tcpxtract.sourceforge.net/) - Extract files from network
  traffic.
* [Wireshark](https://www.wireshark.org/) - The network traffic analysis
  tool.

## Memory Forensics

*Tools for dissecting malware in memory images or running systems.*

* [BlackLight](https://www.blackbagtech.com/blacklight.html) - Windows/MacOS
  forensics client supporting hiberfil, pagefile, raw memory analysis.
* [DAMM](https://github.com/504ensicsLabs/DAMM) - Differential Analysis of
  Malware in Memory, built on Volatility.
* [evolve](https://github.com/JamesHabben/evolve) - Web interface for the
  Volatility Memory Forensics Framework.
* [FindAES](https://sourceforge.net/projects/findaes/) - Find AES
  encryption keys in memory.
* [inVtero.net](https://github.com/ShaneK2/inVtero.net) - High speed memory
  analysis framework developed in .NET supports all Windows x64, includes
  code integrity and write support.
* [Muninn](https://github.com/ytisf/muninn) - A script to automate portions
  of analysis using Volatility, and create a readable report.
* [Rekall](http://www.rekall-forensic.com/) - Memory analysis framework,
  forked from Volatility in 2013.
* [TotalRecall](https://github.com/sketchymoose/TotalRecall) - Script based
  on Volatility for automating various malware analysis tasks.
* [VolDiff](https://github.com/aim4r/VolDiff) - Run Volatility on memory
  images before and after malware execution, and report changes.
* [Volatility](https://github.com/volatilityfoundation/volatility) - Advanced
  memory forensics framework.
* [VolUtility](https://github.com/kevthehermit/VolUtility) - Web Interface for
  Volatility Memory Analysis framework.
* [WDBGARK](https://github.com/swwwolf/wdbgark) -
  WinDBG Anti-RootKit Extension.
* [WinDbg](https://developer.microsoft.com/en-us/windows/hardware/windows-driver-kit) -
  Live memory inspection and kernel debugging for Windows systems.

## Windows Artifacts

* [AChoir](https://github.com/OMENScan/AChoir) - A live incident response
  script for gathering Windows artifacts.
* [python-evt](https://github.com/williballenthin/python-evt) - Python
  library for parsing Windows Event Logs.
* [python-registry](http://www.williballenthin.com/registry/) - Python
  library for parsing registry files.
* [RegRipper](http://brettshavers.cc/index.php/brettsblog/tags/tag/regripper/)
  ([GitHub](https://github.com/keydet89/RegRipper2.8)) -
  Plugin-based registry analysis tool.

## Storage and Workflow

* [Aleph](https://github.com/merces/aleph) - Open Source Malware Analysis
  Pipeline System.
* [CRITs](https://crits.github.io/) - Collaborative Research Into Threats, a
  malware and threat repository.
* [FAME](https://certsocietegenerale.github.io/fame/) - A malware analysis
  framework featuring a pipeline that can be extended with custom modules,
  which can be chained and interact with each other to perform end-to-end
  analysis.
* [Malwarehouse](https://github.com/sroberts/malwarehouse) - Store, tag, and
  search malware.
* [Polichombr](https://github.com/ANSSI-FR/polichombr) - A malware analysis
  platform designed to help analysts to reverse malwares collaboratively.
* [stoQ](http://stoq.punchcyber.com) - Distributed content analysis
  framework with extensive plugin support, from input to output, and everything
  in between.
* [Viper](http://viper.li/) - A binary management and analysis framework for
  analysts and researchers.

## Miscellaneous

* [al-khaser](https://github.com/LordNoteworthy/al-khaser) - A PoC malware
  with good intentions that aimes to stress anti-malware systems.
* [CryptoKnight](https://github.com/AbertayMachineLearningGroup/CryptoKnight) - Automated cryptographic algorithm reverse engineering and classification framework.
* [DC3-MWCP](https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP) -
  The Defense Cyber Crime Center's Malware Configuration Parser framework.
* [FLARE VM](https://github.com/fireeye/flare-vm) - A fully customizable,
  Windows-based, security distribution for malware analysis.
* [MalSploitBase](https://github.com/misterch0c/malSploitBase) - A database
  containing exploits used by malware.
* [Malware Museum](https://archive.org/details/malwaremuseum) - Collection of
  malware programs that were distributed in the 1980s and 1990s.
* [Malware Organiser](https://github.com/uppusaikiran/malware-organiser) - A simple tool to organise large malicious/benign files into a organised Structure.
* [Pafish](https://github.com/a0rtega/pafish) - Paranoid Fish, a demonstration
  tool that employs several techniques to detect sandboxes and analysis
  environments in the same way as malware families do.
* [REMnux](https://remnux.org/) - Linux distribution and docker images for
  malware reverse engineering and analysis.
* [Santoku Linux](https://santoku-linux.com/) - Linux distribution for mobile
  forensics, malware analysis, and security.

# Resources

## Books

*Essential malware analysis reading material.*

* [Learning Malware Analysis](https://www.packtpub.com/networking-and-servers/learning-malware-analysis) - Learning Malware Analysis: Explore the concepts, tools, and techniques to analuze and investigate Windows malware
* [Malware Analyst's Cookbook and DVD](https://amzn.com/dp/0470613033) -
  Tools and Techniques for Fighting Malicious Code.
* [Mastering Malware Analysis](https://www.packtpub.com/networking-and-servers/mastering-malware-analysis) - Mastering Malware Analysis: The complete malware analyst's guide to combating malicious software, APT, cybercime, and IoT attacks
* [Mastering Reverse Engineering](https://www.packtpub.com/networking-and-servers/mastering-reverse-engineering) - Mastering Reverse Engineering: Re-engineer your ethical hacking skills
* [Practical Malware Analysis](https://amzn.com/dp/1593272901) - The Hands-On
  Guide to Dissecting Malicious Software.
* [Practical Reverse Engineering](https://www.amzn.com/dp/1118787315/) -
  Intermediate Reverse Engineering.
* [Real Digital Forensics](https://www.amzn.com/dp/0321240693) - Computer
  Security and Incident Response.
* [Rootkits and Bootkits](https://www.amazon.com/dp/1593277164) - Rootkits and Bootkits: Reversing Modern Malware and Next Generation Threats
* [The Art of Memory Forensics](https://amzn.com/dp/1118825098) - Detecting
  Malware and Threats in Windows, Linux, and Mac Memory.
* [The IDA Pro Book](https://amzn.com/dp/1593272898) - The Unofficial Guide
  to the World's Most Popular Disassembler.
* [The Rootkit Arsenal](https://amzn.com/dp/144962636X) - The Rootkit Arsenal:
  Escape and Evasion in the Dark Corners of the System

## Other

* [APT Notes](https://github.com/aptnotes/data) - A collection of papers
  and notes related to Advanced Persistent Threats.
* [Ember](https://github.com/endgameinc/ember) - Endgame Malware BEnchmark for Research,
  a repository that makes it easy to (re)create a machine learning model that can be used
  to predict a score for a PE file based on static analysis.
* [File Formats posters](https://github.com/corkami/pics) - Nice visualization
  of commonly used file format (including PE & ELF).
* [Honeynet Project](http://honeynet.org/) - Honeypot tools, papers, and
  other resources.
* [Kernel Mode](http://www.kernelmode.info/forum/) - An active community
  devoted to malware analysis and kernel development.
* [Malicious Software](https://zeltser.com/malicious-software/) - Malware
  blog and resources by Lenny Zeltser.
* [Malware Analysis Search](https://cse.google.com/cse/home?cx=011750002002865445766%3Apc60zx1rliu) -
  Custom Google search engine from [Corey Harrell](journeyintoir.blogspot.com/).
* [Malware Analysis Tutorials](http://fumalwareanalysis.blogspot.nl/p/malware-analysis-tutorials-reverse.html) -
  The Malware Analysis Tutorials by Dr. Xiang Fu, a great resource for learning
  practical malware analysis.
* [Malware Analysis, Threat Intelligence and Reverse Engineering](https://www.slideshare.net/bartblaze/malware-analysis-threat-intelligence-and-reverse-engineering) -
  Presentation introducing the concepts of malware analysis, threat intelligence
  and reverse engineering. Experience or prior knowledge is not required. Labs
  link in description.
* [Malware Persistence](https://github.com/Karneades/malware-persistence) - Collection 
  of various information focused on malware persistence: detection (techniques), 
  response, pitfalls and the log collection (tools).
* [Malware Samples and Traffic](http://malware-traffic-analysis.net/) - This
  blog focuses on network traffic related to malware infections.
* [Malware Search+++](https://addons.mozilla.org/fr/firefox/addon/malware-search-plusplusplus/) Firefox extension allows
  you to easily search some of the most popular malware databases
* [Practical Malware Analysis Starter Kit](https://bluesoul.me/practical-malware-analysis-starter-kit/) -
  This package contains most of the software referenced in the Practical Malware
  Analysis book.
* [RPISEC Malware Analysis](https://github.com/RPISEC/Malware) - These are the
  course materials used in the Malware Analysis course at at Rensselaer Polytechnic
  Institute during Fall 2015.
* [WindowsIR: Malware](http://windowsir.blogspot.com/p/malware.html) - Harlan
  Carvey's page on Malware.
* [Windows Registry specification](https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md) -
  Windows registry file format specification.
* [/r/csirt_tools](https://www.reddit.com/r/csirt_tools/) - Subreddit for CSIRT
  tools and resources, with a
  [malware analysis](https://www.reddit.com/r/csirt_tools/search?q=flair%3A%22Malware%20analysis%22&sort=new&restrict_sr=on) flair.
* [/r/Malware](https://www.reddit.com/r/Malware) - The malware subreddit.
* [/r/ReverseEngineering](https://www.reddit.com/r/ReverseEngineering) -
  Reverse engineering subreddit, not limited to just malware.



# Related Awesome Lists

* [Android Security](https://github.com/ashishb/android-security-awesome)
* [AppSec](https://github.com/paragonie/awesome-appsec)
* [CTFs](https://github.com/apsdehal/awesome-ctf)
* [Forensics](https://github.com/Cugu/awesome-forensics)
* ["Hacking"](https://github.com/carpedm20/awesome-hacking)
* [Honeypots](https://github.com/paralax/awesome-honeypots)
* [Industrial Control System Security](https://github.com/hslatman/awesome-industrial-control-system-security)
* [Incident-Response](https://github.com/meirwah/awesome-incident-response)
* [Infosec](https://github.com/onlurking/awesome-infosec)
* [PCAP Tools](https://github.com/caesar0301/awesome-pcaptools)
* [Pentesting](https://github.com/enaqx/awesome-pentest)
* [Security](https://github.com/sbilly/awesome-security)
* [Threat Intelligence](https://github.com/hslatman/awesome-threat-intelligence)
* [YARA](https://github.com/InQuest/awesome-yara)

# [Contributing](CONTRIBUTING.md)

Pull requests and issues with suggestions are welcome! Please read the
[CONTRIBUTING](CONTRIBUTING.md) guidelines before submitting a PR.

# Thanks

This list was made possible by:

* Lenny Zeltser and other contributors for developing REMnux, where I
  found many of the tools in this list;
* Michail Hale Ligh, Steven Adair, Blake Hartstein, and Mather Richard for
  writing the *Malware Analyst's Cookbook*, which was a big inspiration for
  creating the list;
* And everyone else who has sent pull requests or suggested links to add here!

Thanks!
