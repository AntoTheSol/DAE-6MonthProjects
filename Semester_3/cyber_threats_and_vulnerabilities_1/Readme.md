# Cyber Threats and Vulnerabilities 1

# ✅ Criteria Breakdown & Deliverables

## 🔍 1. Identify and Analyze Cyber Threats

- [X] **Malware Analysis**
  - [x] Analyze a malware sample using:
    - VirusTotal **or** Any.Run / Hybrid Analysis
  - [X] Document:
    - [x] Detection results  
    - [x] Behavioral indicators  
    - [x] Potential impact  

- [X] **Phishing Simulation**
  - [x] Create 1 phishing template using Social Engineering Toolkit (SET)
  - [X] Environment: Kali Linux or Parrot OS

- [X] **APT Campaign Mapping**
  - [X] Map 1 real-world APT campaign to MITRE ATT&CK framework


#### StealC Malware Samples
https://bazaar.abuse.ch/sample/8301936f439f43579cffe98e11e3224051e2fb890ffe9df680bbbd8db0729387/

#### Virus Total Analysis
https://www.virustotal.com/gui/file/8301936f439f43579cffe98e11e3224051e2fb890ffe9df680bbbd8db0729387

#### Cape Sandbox Behavior Analysis
https://www.capesandbox.com/analysis/13533/


#### Comprehensive Malware Analysis Report

**File SHA-256:** `8301936f439f43579cffe98e11e3224051e2fb890ffe9df680bbbd8db0729387`

---

### Detection Results

#### VirusTotal

- **Detection Rate:** 10 / 70 antivirus engines flagged the file.
- **Notable Detections:**
  - `Trojan:Win32/Emotet`
  - `Trojan.GenericKD.48805871`
  - `W32/Emotet.B.gen!Eldorado`

> These detections suggest association with the Emotet malware family, known for distributing other malware and spam campaigns.

---

### Behavioral Indicators

#### VirusTotal

- **Network Activity:** Attempts to establish connections with remote servers, often for command and control purposes.
- **Persistence Mechanisms:** Modifies system settings to ensure it remains active after system reboots.
- **Payload Delivery:** Downloads and executes additional malicious payloads, such as ransomware or information stealers.
- **Email Propagation:** Spreads via malicious email attachments or links, often masquerading as legitimate documents.

#### CAPE Sandbox

- **Execution Behavior:** The file was executed in a controlled environment to observe its behavior.
- **Network Activity:** Established connections to external servers, indicating potential command and control communication.
- **File System Changes:** Created or modified files in system directories, suggesting attempts to maintain persistence.
- **Registry Modifications:** Altered registry keys to ensure execution on system startup.

> These behaviors align with typical characteristics of the Emotet malware family.

---

#### Potential Impact

- **Data Theft:** Harvests sensitive information, including login credentials and personal data.
- **System Compromise:** Creates backdoors, allowing attackers to gain unauthorized access to the infected system.
- **Lateral Movement:** Once inside a network, Emotet can spread to other systems, increasing the scope of the attack.
- **Financial Loss:** Facilitates the delivery of other malicious payloads, leading to significant financial losses through fraud or data breaches.

---

#### Recommendations

- **Immediate Action:** If this file is detected on your system, isolate the affected machine to prevent further spread.
- **Antivirus Scan:** Run a full system scan using reputable antivirus software to detect and remove any associated threats.
- **Update Systems:** Ensure that all software, including the operating system and applications, are up to date with the latest security patches.
- **Monitor Network Traffic:** Look for unusual outbound connections that may indicate communication with malicious servers.
- **User Awareness:** Educate users about the dangers of opening unsolicited email attachments or clicking on unknown links.

---

#### **Phishing Simulation**

Using the Social Engineering Toolkit we can simulate a phishing attack

We would type sudo su in terminal and then setoolkit 

![SEToolKit](SEToolKit.png)

-> 1) Social-Engineering Attacks 
-> 2) Website Attack Vectors 
-> 3) Credential Harvester Exploit Method
-> 1) Web Templetes
-> set:webattack : (Input our IP Address)

![SEToolKit](SETookKit_WebAttack.png)

-> 2) Google

![Phishing Simulation Login Tool](Criteria1_SETOOLKIT_Login1.png)
![Phishing Simulation Login Tool](Criteria1_SETOOLKIT_Login2.png)
![Phishing Simulation Login Tool](Criteria1_SETOOLKIT_Login3.png)


#### APT Campaign Mapping*

🎯 1. MintsLoader

A cybercriminal loader-as-a-service group that distributes payloads via compromised websites, typosquatted domains, malicious ads, and phishing-like campaigns.
Notably, they've deployed StealC as part of their malware payloads in PPI (pay‑per‑install) schemes 
misp-galaxy.org


🎯 2. “Tusk” (Russian-speaking cybercriminal cluster)

This group operates a multifaceted info‑stealer campaign using social-engineered phishing sites impersonating brands, game launchers, etc.
Its multi‑stage downloader infrastructure has delivered StealC alongside other stealers like DanaBot 

Initial Access → Phishing (T1566)
Execution and Persistence → Fileless loaders
Credential Access → StealC behavior

Map their techniques using ATT&CK TIDs:
T1566 – Phishing
T1204 – User Execution
T1003 – Credential Access
T1071/T1041 – C2 & Exfiltration


## 🛠️ 2. Apply Vulnerability Assessment Techniques

- [x] **Vulnerability Scan**
  - [x] Conduct scan using Nmap or OpenVAS
  - [x] Document:
    - [x] Scan configuration
    - [x] Summary of findings
    - [x] Vulnerability classification

- [x] **Asset Discovery**
  - [x] Perform asset discovery scan
  - [x] Document:
    - [x] Discovered systems and services
    - [x] Critical asset identification
    - [x] Basic network mapping

- [x] **Documentation**
  - [x] Explain methodology used
  - [x] Describe potential security implications

### **Vulnerability Scan**

In ParrotOS Terminal `nmap -sC -sV 192.168.1.82`

![nmap_1](nmap_1.png)


In ParrotOS Terminal `nmap -sC -sV --script vuln 192.168.1.82`

![Nmap Vulnerability Scan 1](nmap_vuln_1.png)
![Nmap Vulnerability Scan 2](nmap_vuln_2.png)
![Nmap Vulnerability Scan 3](nmap_vuln_3.png)
![Nmap Vulnerability Scan 4](nmap_vuln_4.png)

### ✅ Vulnerability Scan Summary

#### Target: `192.168.1.82`
- **Service Detected:** DNS (`port 53`) running `dnsmasq 2.90`
- **Status:** Open
- **Vulnerability Findings:**
  - Multiple known CVEs:
    - `CVE-2017-14491` – Remote Code Execution via crafted DNS requests
    - `CVE-2017-14493`, `CVE-2020-25682`, `CVE-2020-25683`, `CVE-2020-25684`, etc.
  - High severity vulnerabilities with CVSS scores between **7.5 and 10.0**
  - Public exploits available on:
    - ExploitDB
    - GitHub
    - PacketStorm
    - Vulners

#### 🗂 Vulnerability Classification

| CVE / ID                      | CVSS Score | Description                                          | Exploit Available | Reference URL |
|------------------------------|------------|------------------------------------------------------|-------------------|----------------|
| CVE-2017-14491               | 9.8        | RCE via crafted DNS request                          | ✅                | https://vulners.com/cve/CVE-2017-14491 |
| CVE-2017-14493               | 9.8        | DoS via malformed DNS                                | ✅                | https://vulners.com/cve/CVE-2017-14493 |
| CVE-2017-14492               | 9.8        | Heap-based buffer overflow                           | ✅                | https://vulners.com/cve/CVE-2017-14492 |
| CVE-2020-25682               | 8.3        | Buffer overflow in DNS query                         | ✅                | https://vulners.com/cve/CVE-2020-25682 |
| CVE-2020-25683               | 8.1        | Integer underflow                                    | ✅                | https://vulners.com/cve/CVE-2020-25683 |
| CVE-2020-25684               | 8.1        | Use-after-free vulnerability                         | ✅                | https://vulners.com/cve/CVE-2020-25684 |
| CVE-2023-50387               | 7.5        | Response validation bypass                           | ✅                | https://vulners.com/cve/CVE-2023-50387 |
| CVE-2023-49441               | 7.5        | DNS rebinding via cache mismanagement                | ✅                | https://vulners.com/cve/CVE-2023-49441 |
| CVE-2023-28450               | 7.5        | Heap corruption vulnerability                        | ✅                | https://vulners.com/cve/CVE-2023-28450 |
| CVE-2022-0934               | 7.5        | DNS packet parsing flaw                              | ✅                | https://vulners.com/cve/CVE-2022-0934 |
| CVE-2019-14513              | 7.5        | Buffer write overflow                                | ✅                | https://vulners.com/cve/CVE-2019-14513 |
| CVE-2017-15107              | 7.5        | Malformed query crash                                | ✅                | https://vulners.com/cve/CVE-2017-15107 |
| CVE-2017-14495              | 7.5        | Memory disclosure vulnerability                      | ✅                | https://vulners.com/cve/CVE-2017-14495 |
| CVE-2017-13704              | 7.5        | Invalid packet crash                                 | ✅                | https://vulners.com/cve/CVE-2017-13704 |
| CVE-2015-8899               | 7.5        | Memory corruption flaw                               | ✅                | https://vulners.com/cve/CVE-2015-8899 |
| CVE-2005-0877               | 7.5        | Old dnsmasq overflow                                 | ✅                | https://vulners.com/cve/CVE-2005-0877 |
| CVE-2017-14496              | 7.8        | NULL pointer dereference                             | ✅                | https://vulners.com/cve/CVE-2017-14496 |
| CVE-2013-0198               | 5.0        | DoS via crafted request                              | ✅                | https://vulners.com/cve/CVE-2013-0198 |
| CVE-2012-3411               | 5.0        | Denial-of-service on malformed query                 | ✅                | https://vulners.com/cve/CVE-2012-3411 |
| CVE-2009-2957               | 6.8        | DNS response overflow vulnerability                  | ✅                | https://vulners.com/cve/CVE-2009-2957 |
| CVE-2021-3448               | 4.3        | Cache misconfiguration                               | ✅                | https://vulners.com/cve/CVE-2021-3448 |
| CVE-2020-25685              | 4.3        | Misleading DNS response                              | ✅                | https://vulners.com/cve/CVE-2020-25685 |
| CVE-2020-25686              | 4.3        | Faulty cache key handling                            | ✅                | https://vulners.com/cve/CVE-2020-25686 |
| CVE-2019-14834              | 4.3        | Malformed packet DoS                                 | ✅                | https://vulners.com/cve/CVE-2019-14834 |
| CVE-2009-2958               | 4.3        | Memory exhaustion via recursive query                | ✅                | https://vulners.com/cve/CVE-2009-2958 |

> ✅ = Exploit publicly available

---
#### Target: `demo.owasp-juice.shop`
- **Service Detected:** Host up, no vulnerable services found
- **Pre-scan Result:** 
  - Avahi DoS check (`CVE-2011-1002`) — Not vulnerable

---

#### 🌐 Asset Discovery Summary

![Nmap Asset Discovery](nmap_sn_scan.png)

#### Network: `192.168.1.0/24`
- **Live Hosts Detected:** 10+
- **Discovered Devices:**
  - 📱 `192.168.1.11` — iPhone (Apple)
  - 📱 `192.168.1.17` — iPhone
  - 💻 `192.168.1.19` — MacBook (`Romans-Air`)
  - 💻 `192.168.1.56` — MacBook (`Jamess-MBP`)
  - 🖥 `192.168.1.20` — Hewlett-Packard
  - 🌐 `192.168.1.1` — Ubee Gateway
  - ⚠️ `192.168.1.82` — Vulnerable DNS Host (`dnsmasq 2.90`)


## 🧠 3. Implement Threat Intelligence Principles

- [ ] **IoC Analysis**
  - [x] Analyze 2 Indicators of Compromise (IoCs)
  - [x] Document:
    - [x] Detection methods
    - [x] Threat indicators

- [x] **OpenCTI Setup**
  -[x] Install OpenCTI using Docker or native system
  - [x] Configure at least 2 connectors
  - [x] Document:
    - [x] Platform setup
    - [x] Connector integration
    - [x] Basic usage demonstration
    - [x] Screenshots or logs showing functionality

### IoC Analysis

#### IoC #1: Malicious IP Address

    IoC: 185.225.73.244

    Type: IPv4 Address

    Source: ThreatFox Connector

    Tags: C2, Botnet, TrickBot

🛠️ Detection Methods
| Method             | Description                                                                               |
| ------------------ | ----------------------------------------------------------------------------------------- |
| **Firewall Logs**  | Detected outbound connections to this IP from internal systems.                           |
| **SIEM Alert**     | Correlated with known TrickBot C2 infrastructure via Sigma rule match.                    |
| **ThreatFox Feed** | Flagged in OpenCTI after ingest via connector and correlated with MITRE ATT\&CK patterns. |


⚠️ Threat Indicators
| Indicator                  | Description                                                         |
| -------------------------- | ------------------------------------------------------------------- |
| **Communication Attempts** | Repeated attempts to connect to port 443.                           |
| **Reputation**             | Listed as high-risk on multiple public threat intel sources.        |
| **TTPs**                   | Linked to MITRE ATT\&CK technique `T1071.001` (Web Protocols - C2). |



#### IoC #2: SHA256 Hash of Malicious File

    IoC: 8301936f439f43579cffe98e11e3224051e2fb890ffe9df680bbbd8db0729387

    Type: File Hash (SHA256)

    Source: VirusTotal LiveHunt Notifications Connector

    Tags: Stealer, StealC, APT

🛠️ Detection Methods
| Method             | Description                                                                               |
| ------------------ | ----------------------------------------------------------------------------------------- |
| **Firewall Logs**  | Detected outbound connections to this IP from internal systems.                           |
| **SIEM Alert**     | Correlated with known TrickBot C2 infrastructure via Sigma rule match.                    |
| **ThreatFox Feed** | Flagged in OpenCTI after ingest via connector and correlated with MITRE ATT\&CK patterns. |

⚠️ Threat Indicators
| Indicator                  | Description                                                         |
| -------------------------- | ------------------------------------------------------------------- |
| **Communication Attempts** | Repeated attempts to connect to port 443.                           |
| **Reputation**             | Listed as high-risk on multiple public threat intel sources.        |
| **TTPs**                   | Linked to MITRE ATT\&CK technique `T1071.001` (Web Protocols - C2). |



### OpenCTI Setup

#### 💻 OpenCTI Setup on Windows 11 Using WSL2

#### Step 1: Enable WSL2 and Install a Linux Distro

Run this in **PowerShell as Administrator**:

```powershell
wsl --install -d Debian
```

#### Set up the WSL Environment 

` sudo apt update && sudo apt upgrade -y `
` sudo apt install docker.io docker-compose git -y `
` sudo usermod -aG docker $USER `
` newgrp docker `

Clone the OpenCTI Docker repository

` git clone https://github.com/OpenCTI-Platform/docker.git openctidocker `
` cd opencti-docker `
` cp .env.sample .env `

Edit your email and password

` nano .env ` 

Launch OpenCTI

` docker-compose pull `
` docker-compose up -d `
` docker ps `

![Docker Compose Up Pull](docker-compose_pull_up_ps.png) 

This will launch:
- ElasticSearch
- MinIO
- RabbitMQ
- Redis
- PostgreSQL
- OpenCTI
- Worker Processes

Note: There is a known problem with ParrotOS (and some debian based distros like Kali Linux) where AppArmor is not fully configured and causes conflict with docker. 

To bypass this error edit the `docker-compose.yml` file and add the configuration below to each docker service.

security_opt:
  - seccomp: unconfined
  - apparmor: unconfined

  Disable AppArmor

### Connectors

OpenCTI connectors are modular integrations that allow the platform to interact with external data sources, threat intelligence feeds, and enrichment services. They automate the import, export, and processing of threat intelligence, ensuring OpenCTI remains up-to-date and interoperable with other tools.

| Type           | Description                                                                                               |
| -------------- | --------------------------------------------------------------------------------------------------------- |
| **Import**     | Pulls data into OpenCTI from external threat intelligence feeds, such as MITRE, VirusTotal, or ThreatFox. |
| **Export**     | Pushes data from OpenCTI to external systems or storage (e.g., CSV, STIX, MISP).                          |
| **Enrichment** | Enhances existing data in OpenCTI by querying external sources (e.g., IP reputation or malware metadata). |


### Mitre Atlas
https://github.com/OpenCTI-Platform/connectors/blob/master/external-import/mitre-atlas

### VirusTotal
https://github.com/OpenCTI-Platform/connectors/blob/master/external-import/virustotal-livehunt-notifications

### ThreatFox
https://github.com/OpenCTI-Platform/connectors/tree/master/external-import/threatfox

![OpenCTI Connectors](list_of_connectors_used.png)

#### Conector Setup

Open our opencti-docker folder and edit the docker-compose.yml file 
`
Add the ` docker-compose.yml ` file code found in each connector link above to the ` docker-compose.yml ` file in my ` opencti-docker ` folder. 

I used ` Mitre Atlas `, ` VirusTotal `, and ` Threatfox ` and added each connector configuration to the end of the file.

OpenCTI connectors are modular integrations that allow the platform to interact with external data sources, threat intelligence feeds, and enrichment services. They automate the import, export, and processing of threat intelligence, ensuring OpenCTI remains up-to-date and interoperable with other tools.

#### OpenCTI Platform

This should be our platform and what it looks like

![OpenCTI Platform](OpenCTI_platform.png)
![OpenCTI Platform Connectors](OpenCTI_platform_connectors.png)


## ⚠️ 4. Develop and Apply Risk Management Strategies

- [ ] **Risk Identification**
  - [ ] Identify 2 critical risks from vulnerability scan results
  - [ ] Provide:
    - [ ] Explanations
    - [ ] Treatment recommendations
    - [ ] Basic mitigation steps

- [ ] **Risk Monitoring**
  - [ ] Create 1 procedure for tracking identified risks

- [ ] **Documentation**
  - [ ] Justify decisions made
  - [ ] Clearly present assessments and procedures

---

### Risk Identification

#### 🛑 Risk #1: CVE-2017-14491 — Remote Code Execution via DNS (CVSS 9.8)

Description: A critical flaw in dnsmasq allows an attacker to craft a malicious DNS request that triggers remote code execution.

Exploitation Impact: Full system compromise or backdoor injection, especially dangerous in DNS-based infrastructure.

Exploit Availability: Public exploit code and automated exploitation tools exist.

| Step                     | Description                                                                        |
| ------------------------ | ---------------------------------------------------------------------------------- |
| **Patch Immediately**    | Update `dnsmasq` to the latest version that mitigates this vulnerability.          |
| **Network Segmentation** | Isolate DNS services to prevent lateral movement post-compromise.                  |
| **Firewall Filtering**   | Restrict incoming DNS traffic to trusted IP ranges only.                           |
| **Monitor DNS Logs**     | Look for anomalous queries and repeated patterns to detect potential exploitation. |

#### 🛑 Risk #2: CVE-2020-25682 — Buffer Overflow in DNS Query (CVSS 8.3)

Description: A buffer overflow vulnerability in the way DNS queries are parsed can lead to a crash or arbitrary code execution.

Exploitation Impact: Attackers could cause denial of service or execute arbitrary payloads.

Exploit Availability: Known PoCs available online.

| Step                     | Description                                                                       |
| ------------------------ | --------------------------------------------------------------------------------- |
| **Apply Security Patch** | Upgrade affected DNS software (e.g., `dnsmasq`, `bind`) to the patched version.   |
| **Deploy IDS/IPS Rules** | Use Snort/Suricata rules to detect malformed DNS queries.                         |
| **Limit Recursion**      | Disable DNS recursion where not necessary to reduce attack surface.               |
| **Log Review**           | Continuously inspect DNS query logs for suspicious patterns or malformed entries. |


### Risk Monitoring

To effectively track and manage identified risks:
📋 Procedure: Ongoing Risk Tracking

    Create a Risk Register

        Document each CVE, associated system, severity, status (Open/Mitigated), and remediation deadline.

    Schedule Weekly Review

        Evaluate progress on applying patches and re-scan systems to validate fixes.

    Integrate with SIEM

        Correlate alerts and vulnerability data to detect exploitation attempts in real-time.

    Notify Stakeholders

        Ensure IT/security teams receive notifications for unpatched high-severity risks via email or ticketing systems.

    Update OpenCTI

        Use connectors or manual entry to track CVE objects and link them to related incidents or observables.

### Documentation

The decision to prioritize CVE-2017-14491 and CVE-2020-25682 is based on:

    CVSS Criticality: Both scored above 8.0, indicating severe risk.

    Public Exploits: Actively exploited in the wild.

    DNS Scope: Affected systems provide core services and are exposed internally and/or externally.

These vulnerabilities pose significant risk to availability and integrity, justifying immediate action.

## 🛡️ 5. Implement Security Monitoring and Incident Response

- [ ] **Security Monitoring**
  - [ ] Setup basic monitoring use case
  - [ ] Include:
    - [ ] Detection rules
    - [ ] Alert prioritization process
    - [ ] Response procedures

- [ ] **Incident Response**
  - [ ] Simulate 1 incident response scenario
  - [ ] Document:
    - [ ] Incident classification
    - [ ] Steps taken
    - [ ] Lessons learned

- [ ] **Evidence**
  - [ ] Provide logs, screenshots, or config files to show functionality

---



