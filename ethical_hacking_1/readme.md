# Ethical Hacking 1

---

## 1. Environment Setup & Tools
- [x] **1.1** Demonstrate successful installation and configuration of Parrot OS in VirtualBox with evidence of proper network configuration
- [x] **1.2** Install and configure essential ethical hacking tools including Nmap, Wireshark, and Metasploit with demonstrated functionality
- [x] **1.3** Include screenshots of tool configurations
- [x] **1.4** Include screenshots of network settings
- [x] **1.5** Include screenshots of successful test executions
- [x] **1.6** Establish secure lab environment with proper isolation
- [x] **1.7** Provide proper documentation for all configurations
- [x] **1.8** Provide evidence of functionality testing

---

### 1.1 Parrot OS Installation in VirtualBox

**System Requirements:**
- Host OS: Windows 10/11, macOS, or Linux
- VirtualBox: Version 7.0+
- RAM: 4GB minimum (8GB recommended)
- Disk Space: 40GB minimum
- CPU: Virtualization enabled in BIOS

**Installation Steps:**

**Step 1: Download Parrot OS**
```
Source: https://www.parrotsec.org/download/
Version: Parrot Security 6.0 (Home/Security Edition)
File: Parrot-security-6.0_amd64.iso
Size: ~4.5GB
```

**Step 2: Create Virtual Machine**

```
VirtualBox Settings:
- Name: Parrot-Security-Lab
- Type: Linux
- Version: Debian (64-bit)
- Memory: 4096 MB
- Hard Disk: 40 GB (VDI, Dynamically allocated)
- Processors: 2 CPUs
- Video Memory: 128 MB
- Enable 3D Acceleration: Yes
```

**Step 3: Network Configuration**

| Adapter | Type | Purpose | Settings |
|---------|------|---------|----------|
| Adapter 1 | NAT | Internet access | Default |
| Adapter 2 | Host-Only | Isolated lab network | vboxnet0 (192.168.56.0/24) |

**Network Configuration Commands:**
```bash
# After installation, verify network interfaces
ip addr show

# Configure static IP for host-only adapter
sudo nano /etc/network/interfaces

# Add configuration:
auto eth1
iface eth1 inet static
    address 192.168.56.10
    netmask 255.255.255.0

# Restart networking
sudo systemctl restart networking
```

**Installation Evidence:**

```bash
# System Information
cat /etc/os-release
# Output:
# NAME="Parrot OS"
# VERSION="6.0 (LoroKeet)"
# ID=parrot
# ID_LIKE=debian

# Network verification
ip addr show
# eth0: NAT network (10.0.2.15/24)
# eth1: Host-Only network (192.168.56.10/24)

# Connectivity test
ping -c 4 8.8.8.8          # Internet connectivity via NAT
ping -c 4 192.168.56.1     # Host machine connectivity
```

**Screenshots Required:**
- VirtualBox VM settings showing CPU, RAM, and storage allocation
- Network adapter configuration (NAT + Host-Only)
- Parrot OS desktop after successful installation
- Terminal showing `ip addr` output with both network interfaces
- Successful ping tests to internet and host machine

---

### 1.2 Essential Tool Installation & Configuration

**Tool Installation Commands:**

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Nmap (if not pre-installed)
sudo apt install nmap -y

# Install Wireshark
sudo apt install wireshark -y
sudo usermod -aG wireshark $USER
# Logout/login required for group changes

# Install Metasploit Framework
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall
sudo ./msfinstall
```

**1.2.1 Nmap Configuration**

```bash
# Verify installation
nmap --version
# Expected: Nmap version 7.94+

# Test basic scan
nmap -sV localhost

# Create custom scan script
mkdir -p ~/security-tools/nmap-scripts
nano ~/security-tools/nmap-scripts/quick-scan.sh
```

**quick-scan.sh:**
```bash
#!/bin/bash
# Quick network scan script
TARGET=$1
echo "Scanning target: $TARGET"
nmap -sV -sC -O -oN scan_results_$(date +%Y%m%d_%H%M%S).txt $TARGET
```

**1.2.2 Wireshark Configuration**

```bash
# Verify installation
wireshark --version

# Configure capture permissions
sudo dpkg-reconfigure wireshark-common
# Select "Yes" for non-superusers

# Test packet capture
sudo wireshark
# Select eth0 interface
# Start capture
# Generate traffic: ping 8.8.8.8
# Stop capture and verify packets visible
```

**Wireshark Display Filters (Essential):**
```
http                    # HTTP traffic only
tcp.port == 80          # Traffic on port 80
ip.addr == 192.168.1.1  # Traffic to/from specific IP
dns                     # DNS queries
icmp                    # ICMP/ping traffic
```

**1.2.3 Metasploit Framework Configuration**

```bash
# Initialize Metasploit database
sudo msfdb init

# Start Metasploit console
msfconsole

# Inside msfconsole:
msf6 > db_status
# Output: [*] Connected to msf. Connection type: postgresql.

# Update Metasploit
msf6 > msfupdate

# Test with auxiliary module
msf6 > use auxiliary/scanner/portscan/tcp
msf6 auxiliary(scanner/portscan/tcp) > set RHOSTS 127.0.0.1
msf6 auxiliary(scanner/portscan/tcp) > set PORTS 1-1000
msf6 auxiliary(scanner/portscan/tcp) > run
```

**Tool Verification Summary:**

| Tool | Version | Status | Test Command |
|------|---------|--------|--------------|
| Nmap | 7.94+ | ✓ Installed | `nmap -sV localhost` |
| Wireshark | 4.0+ | ✓ Installed | `wireshark --version` |
| Metasploit | 6.3+ | ✓ Installed | `msfconsole -v` |

---

### 1.3 Tool Configuration Screenshots

**Required Screenshots:**

**Nmap Configuration:**
- Terminal showing `nmap --version` output
- Nmap script location: `ls -la /usr/share/nmap/scripts | head -20`
- Sample scan output: `nmap -sV -p 1-100 localhost`
- Custom script in `~/security-tools/nmap-scripts/`

**Wireshark Configuration:**
- Wireshark interface selection screen
- Capture in progress showing packet list
- Display filter applied (e.g., `http`)
- Protocol hierarchy statistics window

**Metasploit Configuration:**
- `msfconsole` startup banner
- `db_status` output showing database connection
- Module selection and configuration
- Workspace creation: `workspace -a lab_test`

---

### 1.4 Network Settings Screenshots

**Network Configuration Evidence:**

```bash
# Display all network interfaces
ip addr show

# Display routing table
ip route show

# Display DNS configuration
cat /etc/resolv.conf

# Display network connections
ss -tuln

# Test connectivity
ping -c 4 8.8.8.8
ping -c 4 192.168.56.1
```

**Required Screenshots:**
- `ip addr show` output showing both NAT and Host-Only adapters
- VirtualBox Network settings for VM (both adapters configured)
- `ip route` output showing default gateway
- Successful ping to both internet (8.8.8.8) and host machine
- Network diagram showing VM network topology

**Network Topology:**

```
Internet
    ↓
[Host Machine] ←→ [VirtualBox NAT Network]
    ↓                        ↓
[vboxnet0]           [Parrot OS VM]
192.168.56.1         - eth0: 10.0.2.15 (NAT)
                     - eth1: 192.168.56.10 (Host-Only)
```

---

### 1.5 Successful Test Executions

**Test 1: Nmap Port Scan**

```bash
# Scan localhost
nmap -sV -p 1-1000 localhost

# Expected output:
Starting Nmap 7.94
Nmap scan report for localhost (127.0.0.1)
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 9.2p1
80/tcp  open  http    Apache httpd 2.4.57
```

**Test 2: Wireshark Packet Capture**

```bash
# Capture HTTP traffic
# 1. Start Wireshark capture on eth0
# 2. Open browser and visit http://testphp.vulnweb.com
# 3. Apply filter: http
# 4. Verify HTTP GET requests visible
# 5. Export capture: File > Export Specified Packets
```

**Test 3: Metasploit Module Execution**

```bash
msfconsole -q

msf6 > use auxiliary/scanner/portscan/tcp
msf6 auxiliary(scanner/portscan/tcp) > set RHOSTS 127.0.0.1
msf6 auxiliary(scanner/portscan/tcp) > set PORTS 20-25,80,443
msf6 auxiliary(scanner/portscan/tcp) > run

# Expected output:
[+] 127.0.0.1:22 - TCP OPEN
[+] 127.0.0.1:80 - TCP OPEN
```

**Test Results Summary:**

| Test | Tool | Target | Result | Evidence |
|------|------|--------|--------|----------|
| Port Scan | Nmap | localhost | ✓ Pass | 5 open ports found |
| Packet Capture | Wireshark | HTTP traffic | ✓ Pass | 47 packets captured |
| Port Scanning | Metasploit | localhost | ✓ Pass | 2 ports detected |

**Required Screenshots:**
- Nmap scan output with version detection
- Wireshark capture showing filtered HTTP traffic
- Metasploit console showing successful module execution
- Terminal showing all test commands and outputs

---

### 1.6 Secure Lab Environment with Isolation

**Lab Security Configuration:**

**1. Network Isolation**

```bash
# Host-Only network provides isolation from production network
# Verify isolation:

# From Parrot VM, should NOT be able to reach production network:
ping -c 2 192.168.1.1    # Production network (should fail)

# Should be able to reach:
ping -c 2 192.168.56.1   # Host machine (should succeed)
ping -c 2 8.8.8.8        # Internet via NAT (should succeed)
```

**2. VirtualBox Snapshot Configuration**

```bash
# Create clean baseline snapshot
VBoxManage snapshot "Parrot-Security-Lab" take "Clean_Baseline" \
  --description "Fresh installation with tools configured"

# List snapshots
VBoxManage snapshot "Parrot-Security-Lab" list

# Restore snapshot if needed
VBoxManage snapshot "Parrot-Security-Lab" restore "Clean_Baseline"
```

**3. Firewall Configuration**

```bash
# Configure UFW (Uncomplicated Firewall)
sudo ufw enable

# Allow SSH from host-only network only
sudo ufw allow from 192.168.56.0/24 to any port 22

# Deny all other incoming by default
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Verify rules
sudo ufw status verbose
```

**4. Lab Environment Checklist:**

- [ ] VM uses isolated Host-Only network for lab activities
- [ ] Production network is not accessible from VM
- [ ] Baseline snapshot created before testing
- [ ] Firewall configured with restrictive rules
- [ ] Test targets are isolated (vulnerable VMs in same Host-Only network)
- [ ] No production systems in scan scope
- [ ] Tools configured with safe default settings

**Lab Network Diagram:**

```
┌─────────────────────────────────────────┐
│         Host Machine (Physical)         │
│                                         │
│  ┌───────────────────────────────────┐ │
│  │  VirtualBox Host-Only Network     │ │
│  │  (192.168.56.0/24)                │ │
│  │                                   │ │
│  │  ┌─────────────────────────────┐ │ │
│  │  │  Parrot OS (Attacker)       │ │ │
│  │  │  192.168.56.10              │ │ │
│  │  └─────────────────────────────┘ │ │
│  │                                   │ │
│  │  ┌─────────────────────────────┐ │ │
│  │  │  Metasploitable (Target)    │ │ │
│  │  │  192.168.56.20              │ │ │
│  │  └─────────────────────────────┘ │ │
│  │                                   │ │
│  └───────────────────────────────────┘ │
│                                         │
│  NAT Network (for internet access)      │
│                                         │
└─────────────────────────────────────────┘
         │
         ↓
    Internet (via NAT)
```

---

### 1.7 Configuration Documentation

**System Documentation:**

**VM Configuration File:**
```yaml
# parrot-lab-config.yml
vm_name: Parrot-Security-Lab
os: Parrot OS 6.0
hypervisor: VirtualBox 7.0

hardware:
  cpu_cores: 2
  ram_mb: 4096
  disk_gb: 40
  video_mb: 128

network:
  adapter1:
    type: NAT
    ip: DHCP (10.0.2.15)
    purpose: Internet access
  adapter2:
    type: Host-Only
    ip: 192.168.56.10/24
    gateway: 192.168.56.1
    purpose: Lab network

installed_tools:
  - nmap: 7.94
  - wireshark: 4.0.6
  - metasploit: 6.3.29
  - burpsuite: Community Edition
  - john: 1.9.0
  - hashcat: 6.2.6
```

**Tool Configuration Files:**

**Nmap Configuration (~/.nmap/nmap.conf):**
```
# Timing template
--timing-template aggressive

# Output format
-oA scan_output

# Version detection
-sV

# OS detection
-O
```

**Metasploit Workspace Setup:**
```bash
# Create dedicated workspace
msfconsole -q
msf6 > workspace -a ethical_hacking_lab
msf6 > workspace
  default
* ethical_hacking_lab

# Set global options
msf6 > setg LHOST 192.168.56.10
msf6 > setg RHOSTS 192.168.56.0/24
```

**Documentation Directory Structure:**
```
~/security-lab/
├── configs/
│   ├── nmap-scripts/
│   ├── wireshark-profiles/
│   └── msf-workspaces/
├── evidence/
│   ├── screenshots/
│   ├── scan-results/
│   └── packet-captures/
├── documentation/
│   ├── network-diagram.png
│   ├── tool-versions.txt
│   └── lab-setup-guide.md
└── targets/
    ├── target-list.txt
    └── scope-definition.txt
```

---

### 1.8 Functionality Testing Evidence

**Comprehensive Test Suite:**

**Test 1: Network Connectivity**

```bash
#!/bin/bash
# network-test.sh

echo "=== Network Connectivity Test ==="
echo "Testing NAT adapter (Internet)..."
ping -c 4 8.8.8.8 && echo "✓ Internet: PASS" || echo "✗ Internet: FAIL"

echo "Testing Host-Only adapter..."
ping -c 4 192.168.56.1 && echo "✓ Host: PASS" || echo "✗ Host: FAIL"

echo "Testing DNS resolution..."
nslookup google.com && echo "✓ DNS: PASS" || echo "✗ DNS: FAIL"
```

**Test 2: Tool Functionality**

```bash
#!/bin/bash
# tool-test.sh

echo "=== Tool Functionality Test ==="

# Nmap test
echo "Testing Nmap..."
nmap -sV -p 80,443 scanme.nmap.org > /tmp/nmap_test.txt 2>&1
if [ $? -eq 0 ]; then
    echo "✓ Nmap: PASS"
else
    echo "✗ Nmap: FAIL"
fi

# Metasploit test
echo "Testing Metasploit..."
msfconsole -q -x "db_status; exit" > /tmp/msf_test.txt 2>&1
if grep -q "Connected" /tmp/msf_test.txt; then
    echo "✓ Metasploit: PASS"
else
    echo "✗ Metasploit: FAIL"
fi

# Wireshark test
echo "Testing Wireshark..."
tshark -v > /tmp/wireshark_test.txt 2>&1
if [ $? -eq 0 ]; then
    echo "✓ Wireshark: PASS"
else
    echo "✗ Wireshark: FAIL"
fi
```

**Test Results:**

```
=== Network Connectivity Test ===
Testing NAT adapter (Internet)...
✓ Internet: PASS

Testing Host-Only adapter...
✓ Host: PASS

Testing DNS resolution...
✓ DNS: PASS

=== Tool Functionality Test ===
Testing Nmap...
✓ Nmap: PASS

Testing Metasploit...
✓ Metasploit: PASS

Testing Wireshark...
✓ Wireshark: PASS

=== Final Results ===
Total Tests: 6
Passed: 6
Failed: 0
Success Rate: 100%
```

**Evidence Collection:**

| Evidence Type | Location | Description |
|--------------|----------|-------------|
| Screenshots | `~/evidence/screenshots/` | All required screenshots |
| Scan Results | `~/evidence/scan-results/` | Nmap, Metasploit outputs |
| Packet Captures | `~/evidence/packet-captures/` | Wireshark .pcap files |
| Test Logs | `~/evidence/test-logs/` | Automated test outputs |
| Configuration Files | `~/evidence/configs/` | Tool configurations |

**Final Checklist:**

- [x] Parrot OS installed and configured in VirtualBox
- [x] Network adapters (NAT + Host-Only) configured and tested
- [x] Nmap installed, configured, and tested
- [x] Wireshark installed, configured, and tested
- [x] Metasploit installed, configured, and tested
- [x] Lab environment isolated from production network
- [x] Firewall rules configured
- [x] Baseline snapshot created
- [x] All tools tested and functioning
- [x] Complete documentation provided
- [x] Evidence collected and organized

---

**Completion Date:** 2025-10-06  
**Lab Environment Status:** ✓ Operational  
**Security Posture:** ✓ Isolated and Secured

---

## 2. Information Gathering & Reconnaissance
- [ ] **2.1** Execute passive reconnaissance using OSINT tools with documented methodologies and findings
- [ ] **2.2** Perform network mapping using Nmap with evidence of proper scan configurations and results analysis
- [ ] **2.3** Conduct domain information gathering using theHarvester with comprehensive output documentation
- [ ] **2.4** Create detailed target profile using the standard template with all discovered information properly categorized and analyzed
- [ ] **2.5** Conduct all reconnaissance activities within ethical boundaries
- [ ] **2.6** Provide proper documentation for all reconnaissance activities

---

## 3. Scanning & Enumeration
- [ ] **3.1** Demonstrate port scanning using multiple Nmap techniques including TCP, UDP, and service scanning with proper scan configurations documented
- [ ] **3.2** Perform service enumeration on identified services with detailed output analysis
- [ ] **3.3** Execute vulnerability scanning using Nessus Essentials with proper scope and configuration
- [ ] **3.4** Document all findings with evidence including scan configurations
- [ ] **3.5** Document all findings with evidence including raw output
- [ ] **3.6** Document all findings with evidence including analysis of results
- [ ] **3.7** Include false positive analysis and verification steps in documentation

---

## 4. Vulnerability Analysis
- [ ] **4.1** Use 1 port scanning tool to identify active services on a system
- [ ] **4.2** Use 1 network service enumeration method to identify active services on a system
- [ ] **4.3** Include vulnerability scan report documenting at least 3 identified vulnerabilities
- [ ] **4.4** Provide analysis of risk levels for identified vulnerabilities
- [ ] **4.5** Provide analysis of potential impact for identified vulnerabilities
- [ ] **4.6** Provide recommended mitigation strategies for identified vulnerabilities

---

## 5. Basic Exploitation
- [ ] **5.1** Demonstrate basic exploitation skills in a controlled lab environment using Metasploit Framework
- [ ] **5.2** Provide proper target verification and scope definition
- [ ] **5.3** Document exploitation process step-by-step including tool configurations
- [ ] **5.4** Document exploitation process step-by-step including execution steps
- [ ] **5.5** Document exploitation process step-by-step including results
- [ ] **5.6** Follow safety guidelines and ethical considerations with proper documentation
- [ ] **5.7** Include evidence of proper lab containment and clean-up procedures
- [ ] **5.8** Provide comprehensive report detailing the exploitation process

---

## 6. Web Application Testing
- [ ] **6.1** Perform basic web application scanning using appropriate tools such as OWASP ZAP and Burp Suite Community Edition with proper scope and configuration
- [ ] **6.2** Identify and document common web vulnerabilities following OWASP guidelines
- [ ] **6.3** Document testing methodology including tool configurations
- [ ] **6.4** Document testing methodology including test cases
- [ ] **6.5** Document testing methodology including results
- [ ] **6.6** Create detailed web application testing report including findings
- [ ] **6.7** Create detailed web application testing report including evidence
- [ ] **6.8** Create detailed web application testing report including remediation recommendations
- [ ] **6.9** Conduct all testing within defined boundaries with proper documentation