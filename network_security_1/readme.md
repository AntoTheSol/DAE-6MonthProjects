# Network Security 1

---

## 1. Understand and Implement Network Topologies
- [x] **1.1** Provide a report that includes a network topology diagram
- [x] **1.2** Cover 1 configuration (choose from LAN, WAN, MAN, or PAN)
- [x] **1.3** Provide explanation of how this topology supports secure communication
- [x] **1.4** Provide explanation of how this topology supports network management

---

### 1.1 Network Topology Diagram

#### Lab Network Architecture

```
                    Internet
                        |
                   [Gateway]
                   10.0.0.1
                        |
              +---------+----------+
              |                    |
         [Firewall]           [DMZ Switch]
         10.0.1.1             10.0.2.1
              |                    |
    +---------+---------+     +----+----+
    |                   |     |         |
[Internal Switch]   [IDS/IPS]  [Web]  [DNS]
  10.0.10.1         10.0.1.2   10.0.2.10 10.0.2.11
    |
    +------------------+------------------+------------------+
    |                  |                  |                  |
[Workstation-1]   [Workstation-2]    [Server-1]        [Admin-PC]
10.0.10.100       10.0.10.101        10.0.10.50        10.0.10.200
```

#### Network Segments

| Segment | Network Range | Purpose | Security Zone |
|---------|--------------|---------|---------------|
| Gateway | 10.0.0.0/24 | Internet connection | External |
| Firewall | 10.0.1.0/24 | Traffic filtering | Perimeter |
| DMZ | 10.0.2.0/24 | Public-facing services | Semi-trusted |
| Internal LAN | 10.0.10.0/24 | User workstations/servers | Trusted |

---

### 1.2 LAN Configuration

#### Configuration Type: Star Topology LAN

**Hardware Components:**
- Central switch: Cisco Catalyst 2960
- 4 endpoints (2 workstations, 1 server, 1 admin PC)
- Physical firewall: pfSense appliance
- IDS/IPS: Suricata sensor

**Network Configuration:**

```bash
# Internal LAN switch configuration
interface GigabitEthernet0/1
 description Workstation-1
 switchport mode access
 switchport access vlan 10
 spanning-tree portfast
 spanning-tree bpduguard enable

interface GigabitEthernet0/2
 description Workstation-2
 switchport mode access
 switchport access vlan 10

interface GigabitEthernet0/3
 description Server-1
 switchport mode access
 switchport access vlan 20
 spanning-tree portfast

interface GigabitEthernet0/4
 description Admin-PC
 switchport mode access
 switchport access vlan 30
```

#### VLAN Segmentation

```bash
# Create VLANs
vlan 10
 name USERS
vlan 20
 name SERVERS
vlan 30
 name MANAGEMENT

# Trunk port to firewall
interface GigabitEthernet0/24
 description Trunk-to-Firewall
 switchport mode trunk
 switchport trunk allowed vlan 10,20,30
```

#### IP Address Assignment

**Workstation-1:**
```bash
IP: 10.0.10.100/24
Gateway: 10.0.10.1
DNS: 10.0.2.11
```

**Workstation-2:**
```bash
IP: 10.0.10.101/24
Gateway: 10.0.10.1
DNS: 10.0.2.11
```

**Server-1:**
```bash
IP: 10.0.10.50/24
Gateway: 10.0.10.1
DNS: 10.0.2.11
```

**Admin-PC:**
```bash
IP: 10.0.10.200/24
Gateway: 10.0.10.1
DNS: 10.0.2.11
```

---

### 1.3 Secure Communication Support

#### Security Features Implemented

**1. Network Segmentation**

VLANs isolate traffic between user workstations, servers, and management systems:

```bash
# Inter-VLAN routing controlled by firewall
# Users (VLAN 10) cannot directly access management (VLAN 30)

# Firewall rule example
pass in on vlan10 proto tcp from 10.0.10.0/24 to 10.0.10.50 port 443
block in on vlan10 from 10.0.10.0/24 to 10.0.10.200
```

**Benefit:** Limits lateral movement during security incidents

---

**2. Encryption Support**

All communication channels support encryption protocols:

- Web traffic: TLS 1.3
- Management access: SSH (no Telnet)
- File transfers: SFTP/SCP only
- VPN: IPsec for remote access

```bash
# SSH configuration on network devices
ip ssh version 2
crypto key generate rsa modulus 2048
line vty 0 4
 transport input ssh
 login local
```

---

**3. Access Control**

Port security prevents unauthorized devices:

```bash
# Port security on user ports
interface range GigabitEthernet0/1-2
 switchport port-security
 switchport port-security maximum 2
 switchport port-security violation restrict
 switchport port-security mac-address sticky
```

**Result:** Only authorized MAC addresses can connect to network

---

**4. Traffic Inspection**

IDS/IPS monitors all traffic entering internal LAN:

```bash
# Suricata monitoring configuration
HOME_NET: "[10.0.10.0/24]"
EXTERNAL_NET: "!$HOME_NET"

# Alert on suspicious activity
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Potential scan"; \
flags:S; threshold: type threshold, track by_src, count 20, seconds 60;)
```

---

**5. Private Addressing**

RFC 1918 private IP space prevents direct internet exposure:

- Internal hosts not routable from internet
- NAT at firewall hides internal structure
- Only DMZ hosts have public-facing presence

---

### 1.4 Network Management Support

#### Centralized Management

**1. SNMP Monitoring**

```bash
# Enable SNMP on switch
snmp-server community SecureRead RO
snmp-server host 10.0.10.200 version 2c SecureRead

# Monitor from admin workstation
snmpwalk -v2c -c SecureRead 10.0.10.1 system
```

**Metrics Collected:**
- Interface utilization
- Error rates
- Device uptime
- Port status

---

**2. Syslog Centralization**

All devices send logs to central server:

```bash
# Configure logging on network devices
logging host 10.0.10.50
logging trap informational
logging facility local5

# Log server receives all events
Oct 22 14:30:15 Switch1: Port Gi0/1 changed to UP
Oct 22 14:31:02 Firewall: DENY TCP 203.0.113.45:54321 -> 10.0.10.100:22
```

---

**3. Configuration Backup**

Automated nightly backups to server:

```bash
# Backup script on admin PC
#!/bin/bash
DATE=$(date +%Y%m%d)
DEVICES="10.0.10.1 10.0.1.1 10.0.2.1"

for DEVICE in $DEVICES; do
    scp admin@$DEVICE:/config/running-config \
    /backup/$DEVICE-$DATE.conf
done
```

---

**4. Network Topology Visibility**

Management tools provide real-time topology view:

- Physical connectivity via LLDP/CDP
- Logical connectivity via routing tables
- Device inventory and status
- Bandwidth utilization per segment

```bash
# Discover topology via LLDP
show lldp neighbors detail

# Output shows connected devices and ports
Local Port: Gi0/24
Device ID: pfSense-Firewall
Port ID: em0
System Name: firewall.lab.local
```

---

**5. Change Management**

Configuration changes tracked and documented:

```bash
# Enable archive on Cisco devices
archive
 path flash:backups/config-
 maximum 10
 time-period 1440

# View configuration history
show archive
```

**Process:**
1. Change requested via ticket system
2. Configuration backed up
3. Change implemented during maintenance window
4. Verification testing performed
5. Rollback available if issues occur

---

**6. Performance Monitoring**

Traffic analysis identifies bottlenecks:

```bash
# Monitor interface statistics
show interface GigabitEthernet0/24
# Check for errors, drops, and utilization

# Analyze top talkers
ip flow-export destination 10.0.10.50 9996
```

---

**7. Fault Isolation**

Hierarchical design enables rapid troubleshooting:

- Problem occurs on Workstation-1
- Check switch port status (layer 1)
- Verify VLAN assignment (layer 2)
- Test gateway connectivity (layer 3)
- Examine firewall rules (layer 4-7)

**Isolation process takes minutes instead of hours**

---

#### Management Access Security

**Dedicated Management VLAN:**

```bash
# Only Admin-PC can access device management
ip access-list extended MGMT-ACCESS
 permit tcp host 10.0.10.200 any eq 22
 permit tcp host 10.0.10.200 any eq 443
 deny tcp any any eq 22
 deny tcp any any eq 443

line vty 0 4
 access-class MGMT-ACCESS in
```

**Multi-Factor Authentication:**
- TACACS+ server for admin authentication
- RADIUS for user authentication
- Local accounts disabled except emergency

---

**Summary:** Star topology LAN provides secure communication through segmentation, encryption, and access control while enabling efficient management via centralized monitoring, automated backups, and hierarchical troubleshooting.

---

## 2. Design Network Protocols and Architectures
- [ ] **2.1** Create and submit a network diagram that includes the OSI model for 1 device
- [ ] **2.2** Create and submit a network diagram that includes the TCP/IP model for 1 device
- [ ] **2.3** Implement proper subnetting for 1 subnet
- [ ] **2.4** Design a secure network architecture with specific security protocols

---

## 3. Implement Network Security Fundamentals
- [ ] **3.1** Detail the implementation of 1 firewall rule
- [ ] **3.2** Detail the implementation of 1 IDS configuration
- [ ] **3.3** Detail the implementation of 1 IPS configuration
- [ ] **3.4** Provide 1 example of detected events
- [ ] **3.5** Submit a comprehensive report with all implementations

---

## 4. Implement Access Control Measures
- [ ] **4.1** Implement at least 1 Access Control List (ACL) configuration
- [ ] **4.2** Implement 1 access control model (e.g., MAC, DAC)
- [ ] **4.3** Configure 1 user access level
- [ ] **4.4** Submit a report detailing all access control implementations

---

## 5. Secure Wireless Networks
- [ ] **5.1** Document wireless network security implementation
- [ ] **5.2** Configure WPA2 or WPA3 for 1 network
- [ ] **5.3** Use WIPS to prevent unauthorized access
- [ ] **5.4** Provide complete documentation of configurations

---

## 6. Utilize Network Security Tools
- [ ] **6.1** Provide at least 1 Wireshark capture with analysis
- [ ] **6.2** Provide 1 network vulnerability scanner report
- [ ] **6.3** Provide 1 network penetration testing tool output
- [ ] **6.4** Document all network security tools usage

---

## 7. Monitor and Respond to Network Security Events
- [ ] **7.1** Monitor network security events
- [ ] **7.2** Identify at least 1 security incident
- [ ] **7.3** Document steps taken for incident response
- [ ] **7.4** Support documentation with logs
- [ ] **7.5** Support documentation with screenshots
- [ ] **7.6** Submit a comprehensive report detailing all monitoring and response activities