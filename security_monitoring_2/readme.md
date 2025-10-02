# Security Monitoring 2

---

## 1. Advanced Monitoring Design
- [x] **1.1** Document a comprehensive design for complex event processing in an enterprise environment.  
- [x] **1.2** Define and justify event stream sources.  
- [x] **1.3** Select and justify processing engine(s).  
- [x] **1.4** Define and justify action framework components.  
- [x] **1.5** Install and configure **Zeek** or **Suricata** or **Wazuh** with:  
    - [x] **1.5a** Screenshots of setup  
    - [x] **1.5b** Evidence of basic functionality  
- [x] **1.6** Demonstrate understanding of advanced correlation methods with examples:  
    - [x] **1.6a** Pattern-based  
    - [x] **1.6b** Statistical  
    - [x] **1.6c** Contextual  
- [x] **1.7** Explain integration of machine learning and behavior analysis with:  
    - [x] **1.7a** Specific enterprise use cases  
    - [x] **1.7b** Implementation considerations  

---

### 1.1 Document a comprehensive design for complex event processing in an enterprise environment

**Enterprise SOC Architecture Design Using Wazuh, MISP, and OpenCTI**

The enterprise SOC is built around a centralized Wazuh SIEM platform integrated with MISP for threat intelligence sharing and OpenCTI for threat intelligence management, with Zeek providing deep network visibility.

**Core Architecture Components:**

```mermaid
graph TB
    subgraph "Data Collection Layer"
        A[Endpoints with Wazuh Agents] --> G[Wazuh Manager]
        B[Network Traffic] --> C[Zeek IDS]
        D[Firewalls/Routers] --> G
        E[Cloud Services] --> G
        C --> G
    end
    
    subgraph "Processing & Intelligence Layer"
        G --> H[Wazuh Indexer]
        H --> I[Wazuh Dashboard]
        G --> J[MISP Platform]
        J --> K[OpenCTI Platform]
        K --> G
    end
    
    subgraph "Analysis & Response Layer"
        I --> L[SOC Analysts]
        L --> M[Alert Investigation]
        M --> N[Incident Response]
        N --> O[Threat Hunting]
    end
    
    subgraph "Intelligence Sharing"
        J --> P[External MISP Feeds]
        K --> Q[STIX/TAXII Feeds]
        P --> K
        Q --> J
    end
```

**Wazuh-Centric Design Principles:**
- **Unified Agent Management**: Single agent deployment across Windows, Linux, macOS endpoints
- **Real-time Event Processing**: Sub-second alerting through Wazuh's event engine
- **Rule-based Detection**: Custom Wazuh rules integrated with MISP IOCs
- **Threat Intelligence Integration**: Automated IOC matching via MISP-Wazuh connector
- **Scalable Architecture**: Clustered Wazuh managers for high availability

**Enterprise Requirements Addressed:**
- **Multi-tenant SOC**: Separate indices per business unit in Wazuh
- **Compliance**: Built-in PCI DSS, NIST, and CIS compliance dashboards
- **Threat Intelligence**: Automated IOC ingestion from MISP communities
- **Investigation Workflow**: Integrated case management in Wazuh dashboard

---

### 1.2 Define and justify event stream sources

**Primary Event Stream Sources for Wazuh Integration:**

| Source Category | Specific Sources | Wazuh Integration Method | Justification | Expected Volume |
|----------------|------------------|-------------------------|---------------|-----------------|
| **Endpoint Security** | Windows Event Logs, Linux syslogs, macOS logs | Wazuh Agent | Critical for detecting malware, lateral movement | 200K events/sec |
| **Network Traffic** | Zeek logs, Firewall logs, DNS logs | Log forwarding to Wazuh | Network-based attack detection | 150K events/sec |
| **Threat Intelligence** | MISP IOCs, OpenCTI indicators | MISP-Wazuh integration | IOC matching and attribution | 50K IOCs/day |
| **Cloud Infrastructure** | AWS CloudTrail, Azure logs, GCP audit logs | Wazuh AWS/Azure modules | Cloud security monitoring | 100K events/sec |
| **Web Applications** | Apache/Nginx logs, Application logs | Wazuh file monitoring | Web attack detection | 75K events/sec |
| **Authentication** | AD logs, LDAP, SSO providers | Wazuh agent + custom rules | Identity-based threats | 50K events/sec |

**Wazuh Agent Configuration Example:**

```xml
<ossec_config>
  <!-- Windows Event Log Collection -->
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
  
  <!-- Linux System Logs -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>
  
  <!-- Apache Access Logs -->
  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/apache2/access.log</location>
  </localfile>
  
  <!-- File Integrity Monitoring -->
  <syscheck>
    <directories check_all="yes" realtime="yes">/etc</directories>
    <directories check_all="yes" realtime="yes">/bin,/sbin</directories>
  </syscheck>
</ossec_config>
```

**Justification for Wazuh-Centric Approach:**
- **Unified Collection**: Single agent reduces endpoint overhead compared to multiple tools
- **Real-time Processing**: Wazuh's event engine processes events as they're generated
- **Built-in Correlation**: Native rule engine eliminates need for external correlation tools
- **Threat Intelligence Integration**: Direct MISP integration for IOC enrichment

---

### 1.3 Select and justify processing engine(s)

**Selected Processing Engine Stack: Wazuh + MISP + OpenCTI**

**Primary Engine: Wazuh SIEM Platform**

```xml
<!-- Wazuh Manager Configuration (ossec.conf) -->
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
    <email_notification>yes</email_notification>
    <smtp_server>smtp.company.com</smtp_server>
    <email_from>wazuh@company.com</email_from>
  </global>
  
  <!-- High-performance settings -->
  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
  </remote>
  
  <!-- Clustering for HA -->
  <cluster>
    <name>wazuh_cluster</name>
    <node_name>master-node</node_name>
    <node_type>master</node_type>
    <key>c98b62a9b6169ac5f67dae55ae4a9088</key>
    <port>1516</port>
    <bind_addr>0.0.0.0</bind_addr>
    <nodes>
        <node>192.168.1.100</node>
        <node>192.168.1.101</node>
    </nodes>
    <hidden>no</hidden>
    <disabled>no</disabled>
  </cluster>
</ossec_config>
```

**Threat Intelligence Engine: MISP Integration**

```python
# MISP-Wazuh Integration Script
import requests
import json
from pymisp import PyMISP

class MISPWazuhConnector:
    def __init__(self, misp_url, misp_key, wazuh_api_url, wazuh_token):
        self.misp = PyMISP(misp_url, misp_key, ssl=False)
        self.wazuh_api = wazuh_api_url
        self.wazuh_token = wazuh_token
        
    def sync_iocs_to_wazuh(self):
        # Get IOCs from MISP
        events = self.misp.search(controller='events', return_format='json')
        
        ioc_rules = []
        for event in events:
            for attribute in event.get('Attribute', []):
                if attribute['type'] == 'ip-dst':
                    rule = self.create_wazuh_rule(attribute)
                    ioc_rules.append(rule)
        
        # Push rules to Wazuh
        self.update_wazuh_rules(ioc_rules)
    
    def create_wazuh_rule(self, attribute):
        return f"""
        <rule id="{100000 + attribute['id']}" level="10">
            <if_sid>1002</if_sid>
            <dstip>{attribute['value']}</dstip>
            <description>MISP IOC Match: {attribute['comment']}</description>
            <group>misp_ioc,malicious_ip</group>
        </rule>
        """
```

**Processing Engine Justification:**

**Wazuh Advantages:**
- **Native Rule Engine**: Built-in complex event processing without external tools
- **Horizontal Scaling**: Cluster mode supports thousands of agents
- **Real-time Processing**: Event processing in under 100ms
- **Integration Ready**: RESTful API for MISP/OpenCTI integration
- **Cost Effective**: Open-source with enterprise features

**MISP Integration Benefits:**
- **Community Intelligence**: Access to shared threat indicators
- **Attribution**: Link events to known threat actors via MISP galaxies
- **Automated Updates**: IOCs automatically sync to Wazuh rules
- **Collaboration**: Share internal IOCs with partner organizations

**OpenCTI Benefits:**
- **STIX/TAXII Compliance**: Industry-standard threat intelligence formats
- **Knowledge Graphs**: Visual representation of threat relationships
- **Multi-source Feeds**: Aggregates intelligence from multiple sources

---

### 1.4 Define and justify action framework components

**Wazuh-Based Action Framework Architecture:**

```xml
<!-- Wazuh Active Response Configuration -->
<ossec_config>
  <command>
    <name>block-malicious-ip</name>
    <executable>firewall-drop.sh</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>
  
  <command>
    <name>isolate-endpoint</name>
    <executable>endpoint-isolate.py</executable>
    <expect>hostname</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>
  
  <command>
    <name>misp-sighting</name>
    <executable>misp-create-sighting.py</executable>
    <expect>ioc</expect>
  </command>
  
  <active-response>
    <disabled>no</disabled>
    <command>block-malicious-ip</command>
    <location>local</location>
    <rules_id>100001,100002</rules_id>
    <timeout>600</timeout>
  </active-response>
</ossec_config>
```

**Action Framework Components:**

| Component | Function | Technology | Integration Method |
|-----------|----------|------------|-------------------|
| **Wazuh Active Response** | Automated blocking and isolation | Shell scripts, Python | Native Wazuh feature |
| **MISP Sighting Creation** | IOC validation and tracking | Python PyMISP library | Custom integration script |
| **Endpoint Isolation** | Network quarantine of infected hosts | Wazuh agent commands | Active response script |
| **Ticket Creation** | ITSM integration for manual review | REST API calls | Custom Python script |
| **Threat Hunting Triggers** | Automated query generation | Wazuh API | Custom dashboard widgets |
| **Email Notifications** | SOC analyst alerting | SMTP integration | Native Wazuh feature |

**Example Active Response Scripts:**

```bash
#!/bin/bash
# firewall-drop.sh - Block malicious IP via iptables
ACTION=$1
USER=$2
IP=$3

if [ "$ACTION" = "add" ]; then
    iptables -I INPUT -s $IP -j DROP
    echo "Blocked IP: $IP"
elif [ "$ACTION" = "delete" ]; then
    iptables -D INPUT -s $IP -j DROP
    echo "Unblocked IP: $IP"
fi
```

```python
#!/usr/bin/env python3
# misp-create-sighting.py - Create MISP sighting from Wazuh alert
import sys
import json
from pymisp import PyMISP

def create_sighting(ioc_value, event_data):
    misp = PyMISP('https://misp.company.com', 'your-api-key', ssl=False)
    
    sighting_data = {
        'value': ioc_value,
        'source': 'Wazuh SIEM',
        'type': '0',  # Sighting
        'timestamp': event_data.get('timestamp'),
        'org_name': 'SOC Team'
    }
    
    result = misp.add_sighting(sighting_data)
    print(f"MISP sighting created: {result}")

if __name__ == "__main__":
    ioc = sys.argv[1]
    event_json = sys.argv[2]
    event_data = json.loads(event_json)
    create_sighting(ioc, event_data)
```

**Response Action Categories:**

**Immediate Actions (0-5 seconds):**
- IP blocking via iptables/firewall rules
- DNS sinkholing for malicious domains
- MISP sighting creation for IOC validation

**Short-term Actions (5-60 seconds):**
- Endpoint isolation via Wazuh agent
- Process termination on infected hosts
- Additional log collection and forensics

**Long-term Actions (1-5 minutes):**
- ITSM ticket creation for investigation
- Threat hunting query generation
- Intelligence sharing with MISP community

---

### 1.5 Install and configure Zeek with screenshots and functionality evidence

**1.5a Screenshots of Setup**

**Zeek Installation Process (Your Environment):**

Based on your installation commands:

```bash
sudo apt update
sudo apt install flex bison build-essential

# LibMMDB (MaxMind GeoIP database support) - Very useful for network analysis
sudo apt install libmaxminddb-dev

# LibKrb5 (Kerberos authentication analysis):
sudo apt install cmake make gcc g++ flex bison libpcap-dev libssl-dev python3-dev swig zlib1g-dev

# GoldLinker - Faster linking during compilation, but not essential
sudo apt install binutils-gold

# Node.js - Only needed if you want Node.js bindings for Zeek
sudo apt install nodejs npm libnode-dev

# Install ZeroMQ
sudo apt install libzmq3-dev

# C++ Bindings that Zeek uses
sudo apt install libczmq-dev

make distclean
./configure

```

![Zeek Configure](img/zeek_configure1_1.png)
*Zeek configuration process beginning - dependency check phase*

![Zeek Configure](img/zeek_configure1_2.png)
*Zeek configuration completion after 20-30 minutes*

**Post-Configuration Build Process:**

```bash
# Compile Zeek (this will take 30-60 minutes)
make -j$(nproc)

# Install Zeek
sudo make install

# Add Zeek to PATH
echo 'export PATH=/usr/local/zeek/bin:$PATH' >> ~/.bashrc
source ~/.bashrc
```

**Zeek Configuration for Wazuh Integration:**

```bash
# Configure Zeek networks
sudo nano /usr/local/zeek/etc/networks.cfg
```

```ini
# networks.cfg
192.168.1.0/24    Private
10.0.0.0/8        Private
172.16.0.0/12     Private
```

```bash
# Configure Zeek node
sudo nano /usr/local/zeek/etc/node.cfg
```

```ini
[zeek]
type=standalone
host=localhost
interface=eth0
```

**1.5b Evidence of Basic Functionality**

**Starting Zeek and Wazuh Integration:**

```bash
# Start Zeek
sudo zeekctl deploy

# Check Zeek status
sudo zeekctl status
```

![Zeek_Status_Running](img/zeek_zeekctl_deploy_status.png)
*Zeek successfully deployed and running*

**Zeek Log Integration with Wazuh:**

```xml
<!-- Wazuh ossec.conf - Zeek log integration -->
<localfile>
  <log_format>json</log_format>
  <location>/usr/local/zeek/logs/current/conn.log</location>
</localfile>

<localfile>
  <log_format>json</log_format>
  <location>/usr/local/zeek/logs/current/http.log</location>
</localfile>

<localfile>
  <log_format>json</log_format>
  <location>/usr/local/zeek/logs/current/dns.log</location>
</localfile>

<localfile>
  <log_format>json</log_format>
  <location>/usr/local/zeek/logs/current/ssl.log</location>
</localfile>
```

**Zeek Detection Example - HTTP Traffic:**

```bash
# Monitor HTTP logs in real-time
tail -f /usr/local/zeek/logs/current/http.log
```

Sample HTTP detection in Wazuh:
```json
{
  "timestamp": "2024-08-28T14:30:15.123Z",
  "agent": {"name": "zeek-sensor-01"},
  "rule": {"id": 200001, "level": 7, "description": "Zeek: Suspicious HTTP User-Agent"},
  "data": {
    "srcip": "192.168.1.100",
    "dstip": "203.0.113.50",
    "user_agent": "sqlmap/1.6.12",
    "uri": "/admin/login.php",
    "method": "POST"
  }
}
```

![Zeek_HTTP_Detection_Wazuh](img/Zeek_HTTP_Detection_Wazuh.png)
*Wazuh dashboard showing Zeek HTTP detection*

**Custom Zeek Scripts for Enhanced Detection:**

```zeek
# /usr/local/zeek/share/zeek/site/custom-detection.zeek
@load base/protocols/http
@load base/protocols/dns

# Detect SQL injection attempts
event http_request(c: connection, method: string, original_URI: string, 
                  unescaped_URI: string, version: string) {
    if (/select|union|insert|update|delete|drop|create|alter/i in unescaped_URI) {
        NOTICE([$note=HTTP::SQL_Injection_Attack,
                $conn=c,
                $msg=fmt("Potential SQL injection from %s to %s%s", 
                        c$id$orig_h, c$http$host, original_URI),
                $identifier=cat(c$id$orig_h, c$http$host, original_URI)]);
    }
}

# Detect DNS tunneling
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
    if (|query| > 50) {  # Unusually long DNS query
        NOTICE([$note=DNS::Suspicious_Query_Length,
                $conn=c,
                $msg=fmt("Suspicious long DNS query: %s", query),
                $identifier=cat(c$id$orig_h, query)]);
    }
}
```

**Zeek-Wazuh Integration Results:**

![Zeek_DNS_Tunneling_Alert](img/Zeek_DNS_Tunneling_Alert.png)
*Wazuh alert triggered by Zeek DNS tunneling detection*

---

### 1.6 Demonstrate understanding of advanced correlation methods with examples

**1.6a Pattern-based Correlation in Wazuh**

Pattern-based correlation uses Wazuh's built-in rule engine to detect multi-stage attacks by correlating events across time windows.

**Example: Credential Stuffing → Lateral Movement Pattern**

```xml
<!-- Wazuh rules for pattern detection -->
<group name="attack_patterns">

  <!-- Stage 1: Multiple failed logins -->
  <rule id="200100" level="5">
    <if_sid>5760</if_sid>
    <same_source_ip />
    <description>SSH: Multiple failed logins from same IP</description>
    <options>no_email_alert</options>
  </rule>

  <!-- Stage 2: Successful login after failures -->
  <rule id="200101" level="8">
    <if_sid>5715</if_sid>
    <same_source_ip />
    <if_matched_sid>200100</if_matched_sid>
    <timeframe>300</timeframe>
    <description>SSH: Successful login after multiple failures - Possible brute force</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>

  <!-- Stage 3: Lateral movement via SMB -->
  <rule id="200102" level="10">
    <if_sid>18152</if_sid>
    <same_user />
    <if_matched_sid>200101</if_matched_sid>
    <timeframe>600</timeframe>
    <description>Lateral movement detected: SMB access after successful brute force</description>
    <mitre>
      <id>T1021.002</id>
    </mitre>
  </rule>

</group>
```

**MISP Integration for Pattern Attribution:**

```python
# Enhanced pattern detection with MISP attribution
class AttackPatternAnalyzer:
    def __init__(self, misp_client):
        self.misp = misp_client
        self.patterns = {
            'apt29_pattern': {
                'stages': ['credential_access', 'lateral_movement', 'data_exfiltration'],
                'misp_galaxy': 'mitre-intrusion-set="APT29"'
            }
        }
    
    def analyze_pattern_with_attribution(self, wazuh_alert):
        # Extract IOCs from alert
        src_ip = wazuh_alert.get('data', {}).get('srcip')
        
        # Query MISP for attribution
        misp_results = self.misp.search(controller='attributes', 
                                      value=src_ip, 
                                      return_format='json')
        
        if misp_results:
            for event in misp_results:
                if 'APT29' in str(event.get('Galaxy', [])):
                    return {
                        'attribution': 'APT29',
                        'confidence': 'high',
                        'misp_event_id': event['id']
                    }
        
        return {'attribution': 'unknown', 'confidence': 'low'}
```

**1.6b Statistical Correlation using Wazuh Analytics**

Statistical correlation identifies anomalies by comparing current behavior against historical baselines stored in Wazuh.

**Example: Login Time Anomaly Detection**

```xml
<!-- Wazuh rule for statistical anomaly -->
<rule id="200200" level="7">
  <if_sid>5715</if_sid>
  <time>22:00-06:00</time>
  <description>Unusual login time detected - Outside business hours</description>
  <group>anomaly,after_hours</group>
</rule>

<!-- Volume-based anomaly -->
<rule id="200201" level="8">
  <if_sid>1002</if_sid>
  <same_source_ip />
  <frequency>50</frequency>
  <timeframe>60</timeframe>
  <description>High connection volume anomaly - Possible DDoS or scanning</description>
  <group>anomaly,high_volume</group>
</rule>
```

**Python Script for Advanced Statistical Analysis:**

```python
#!/usr/bin/env python3
# wazuh-behavioral-analytics.py
import requests
import numpy as np
from scipy import stats
import json

class WazuhBehavioralAnalytics:
    def __init__(self, wazuh_api_url, auth_token):
        self.api_url = wazuh_api_url
        self.headers = {'Authorization': f'Bearer {auth_token}'}
        
    def get_user_login_baseline(self, username, days=30):
        # Query Wazuh API for historical login data
        query = {
            'query': f'data.dstuser:{username} AND rule.id:5715',
            'date_range': f'{days}d'
        }
        
        response = requests.get(f'{self.api_url}/search',
                              headers=self.headers,
                              params=query)
        
        login_hours = []
        for hit in response.json().get('data', {}).get('hits', []):
            timestamp = hit['_source']['timestamp']
            hour = int(timestamp.split('T')[1].split(':')[0])
            login_hours.append(hour)
        
        return {
            'mean_hour': np.mean(login_hours),
            'std_hour': np.std(login_hours),
            'login_count': len(login_hours)
        }
    
    def detect_time_anomaly(self, username, current_hour):
        baseline = self.get_user_login_baseline(username)
        
        # Calculate z-score
        z_score = abs((current_hour - baseline['mean_hour']) / baseline['std_hour'])
        
        if z_score > 2.5:  # 2.5 standard deviations
            return {
                'anomaly': True,
                'severity': 'high' if z_score > 3 else 'medium',
                'z_score': z_score,
                'baseline_hours': f"{baseline['mean_hour']:.1f} ± {baseline['std_hour']:.1f}"
            }
        
        return {'anomaly': False, 'z_score': z_score}

# Integration with Wazuh Custom Rule
analytics = WazuhBehavioralAnalytics('https://wazuh-api:55000', 'your-token')
result = analytics.detect_time_anomaly('jsmith', 23)  # 11 PM login

if result['anomaly']:
    print(f"ANOMALY DETECTED: User jsmith login at unusual time (z-score: {result['z_score']:.2f})")
```

**1.6c Contextual Correlation with MISP and Asset Data**

Contextual correlation enriches Wazuh alerts with business context from MISP threat intelligence and internal asset databases.

**Example: Context-Aware Risk Scoring**

```python
class ContextualAlertEnricher:
    def __init__(self, misp_client, asset_db):
        self.misp = misp_client
        self.asset_db = asset_db
        
    def enrich_wazuh_alert(self, alert):
        enriched_alert = alert.copy()
        
        # Add asset context
        asset_info = self.get_asset_context(alert.get('agent', {}).get('name'))
        enriched_alert['asset_context'] = asset_info
        
        # Add threat intelligence
        threat_context = self.get_threat_context(alert.get('data', {}))
        enriched_alert['threat_context'] = threat_context
        
        # Calculate contextual risk score
        risk_score = self.calculate_contextual_risk(asset_info, threat_context, alert)
        enriched_alert['contextual_risk_score'] = risk_score
        
        return enriched_alert
    
    def get_asset_context(self, hostname):
        # Query internal asset database
        return {
            'criticality': 'High',  # Financial server
            'compliance_scope': ['PCI-DSS', 'SOX'],
            'business_owner': 'Finance Department',
            'data_classification': 'Confidential'
        }
    
    def get_threat_context(self, alert_data):
        src_ip = alert_data.get('srcip')
        if not src_ip:
            return {}
        
        # Query MISP for threat intelligence
        misp_results = self.misp.search(controller='attributes',
                                      value=src_ip,
                                      return_format='json')
        
        if misp_results:
            return {
                'threat_actor': 'FIN7',
                'campaign': 'Carbanak',
                'first_seen': '2024-07-15',
                'threat_types': ['Banking Trojan', 'Point of Sale'],
                'confidence': 85
            }
        
        return {'reputation': 'unknown'}
    
    def calculate_contextual_risk(self, asset_info, threat_context, alert):
        base_score = alert.get('rule', {}).get('level', 5)
        
        # Asset criticality multiplier
        if asset_info.get('criticality') == 'High':
            base_score *= 1.5
        
        # Threat actor multiplier
        if threat_context.get('threat_actor') == 'FIN7':
            base_score *= 2.0  # Known financial threat actor
        
        # Compliance scope multiplier
        if 'PCI-DSS' in asset_info.get('compliance_scope', []):
            base_score *= 1.3
        
        return min(base_score, 10.0)  # Cap at 10
```

**Wazuh Dashboard Integration:**

```json
{
  "alert_id": "1630089234.123456",
  "rule": {"id": 200101, "level": 8, "description": "SSH brute force detected"},
  "asset_context": {
    "criticality": "High",
    "compliance_scope": ["PCI-DSS"],
    "business_owner": "Finance Department"
  },
  "threat_context": {
    "threat_actor": "FIN7",
    "misp_event_id": "12345",
    "confidence": 85
  },
  "contextual_risk_score": 9.2,
  "recommended_actions": [
    "Immediate isolation",
    "Executive notification",
    "Forensic imaging"
  ]
}
```

---

### 1.7 Explain integration of machine learning and behavior analysis

**1.7a Specific Enterprise Use Cases**

**Use Case 1: User and Entity Behavior Analytics (UEBA) with Wazuh**

```python
# UEBA implementation using Wazuh data
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

class WazuhUEBA:
    def __init__(self, wazuh_api):
        self.wazuh_api = wazuh_api
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        
    def extract_user_features(self, username, timeframe='7d'):
        """Extract behavioral features from Wazuh logs"""
        # Query Wazuh for user activity
        query = f'data.dstuser:{username}'
        logs = self.wazuh_api.search(query=query, timeframe=timeframe)
        
        features = {
            'login_count': 0,
            'unique_hosts_accessed': set(),
            'after_hours_activity': 0,
            'failed_login_attempts': 0,
            'privilege_escalation_count': 0,
            'data_transfer_volume': 0,
            'unique_applications': set(),
            'geographic_variance': 0
        }
        
        for log in logs:
            # Extract features from each log entry
            rule_id = log.get('rule', {}).get('id')
            timestamp = log.get('timestamp')
            
            if rule_id == 5715:  # Successful login
                features['login_count'] += 1
                features['unique_hosts_accessed'].add(log.get('agent', {}).get('name'))
                
                # Check if after hours (6 PM - 6 AM)
                hour = int(timestamp.split('T')[1].split(':')[0])
                if hour >= 18 or hour <= 6:
                    features['after_hours_activity'] += 1
                    
            elif rule_id == 5760:  # Failed login
                features['failed_login_attempts'] += 1
                
            elif rule_id in [4950, 4951]:  # Sudo usage
                features['privilege_escalation_count'] += 1
        
        # Convert sets to counts
        features['unique_hosts_accessed'] = len(features['unique_hosts_accessed'])
        features['unique_applications'] = len(features['unique_applications'])
        
        return features
    
    def train_baseline(self, users_list):
        """Train UEBA model on normal user behavior"""
        training_data = []
        
        for user in users_list:
            features = self.extract_user_features(user)
            feature_vector = [
                features['login_count'],
                features['unique_hosts_accessed'],
                features['after_hours_activity'],
                features['failed_login_attempts'],
                features['privilege_escalation_count'],
                features['data_transfer_volume'],
                features['unique_applications']
            ]
            training_data.append(feature_vector)
        
        # Normalize and train
        training_data_scaled = self.scaler.fit_transform(training_data)
        self.model.fit(training_data_scaled)
        
    def detect_anomaly(self, username):
        """Detect anomalous user behavior"""
        features = self.extract_user_features(username)
        feature_vector = [[
            features['login_count'],
            features['unique_hosts_accessed'],
            features['after_hours_activity'],
            features['failed_login_attempts'],
            features['privilege_escalation_count'],
            features['data_transfer_volume'],
            features['unique_applications']
        ]]
        
        feature_vector_scaled = self.scaler.transform(feature_vector)
        
        # Get anomaly score and prediction
        anomaly_score = self.model.decision_function(feature_vector_scaled)[0]
        is_anomaly = self.model.predict(feature_vector_scaled)[0] == -1
        
        return {
            'user': username,
            'is_anomaly': is_anomaly,
            'anomaly_score': anomaly_score,
            'risk_level': self.calculate_risk_level(anomaly_score),
            'behavioral_features': features
        }
    
    def calculate_risk_level(self, score):
        if score < -0.6:
            return 'Critical'
        elif score < -0.3:
            return 'High'
        elif score < 0:
            return 'Medium'
        else:
            return 'Low'

# Integration with Wazuh custom rules
ueba = WazuhUEBA(wazuh_api_client)
result = ueba.detect_anomaly('suspicious_user')

if result['is_anomaly']:
    # Trigger Wazuh alert
    wazuh_alert = {
        'rule_id': 200300,
        'level': 9,
        'description': f"UEBA: Anomalous behavior detected for user {result['user']}",
        'risk_level': result['risk_level'],
        'anomaly_score': result['anomaly_score']
    }
```

**Use Case 2: Network Traffic Anomaly Detection with Zeek + Wazuh**

```python
# Network anomaly detection using Zeek logs in Wazuh
class NetworkAnomalyDetector:
    def __init__(self):
        self.connection_baselines = {}
        
    def analyze_zeek_conn_logs(self, timeframe='24h'):
        """Analyze Zeek connection logs for anomalies"""
        # Query Wazuh for Zeek connection logs
        query = 'location:"/usr/local/zeek/logs/current/conn.log"'
        logs = wazuh_api.search(query=query, timeframe=timeframe)
        
        anomalies = []
        
        for log in logs:
            conn_data = log.get('data', {})
            
            # Extract connection features
            features = {
                'duration': float(conn_data.get('duration', 0)),
                'orig_bytes': int(conn_data.get('orig_bytes', 0)),
                'resp_bytes': int(conn_data.get('resp_bytes', 0)),
                'orig_pkts': int(conn_data.get('orig_pkts', 0)),
                'resp_pkts': int(conn_data.get('resp_pkts', 0))
            }
            
            # Detect long-duration connections (potential C2)
            if features['duration'] > 3600 and features['orig_bytes'] < 1000:
                anomalies.append({
                    'type': 'potential_c2_beacon',
                    'severity': 'high',
                    'evidence': f"Long duration ({features['duration']}s), low volume connection",
                    'src_ip': conn_data.get('id.orig_h'),
                    'dst_ip': conn_data.get('id.resp_h')
                })
            
            # Detect data exfiltration patterns
            if features['orig_bytes'] > 100000000:  # >100MB upload
                anomalies.append({
                    'type': 'potential_data_exfiltration',
                    'severity': 'critical',
                    'evidence': f"Large data upload: {features['orig_bytes']} bytes",
                    'src_ip': conn_data.get('id.orig_h'),
                    'dst_ip': conn_data.get('id.resp_h')
                })
        
        return anomalies

# MISP Integration for IOC Enrichment
def enrich_with_misp_iocs(anomalies, misp_client):
    """Enrich detected anomalies with MISP threat intelligence"""
    for anomaly in anomalies:
        dst_ip = anomaly.get('dst_ip')
        
        # Check if destination IP is in MISP
        misp_results = misp_client.search(controller='attributes',
                                        value=dst_ip,
                                        return_format='json')
        
        if misp_results:
            anomaly['misp_context'] = {
                'known_malicious': True,
                'threat_types': ['C2', 'Malware'],
                'first_seen': '2024-08-15',
                'confidence': 90
            }
            anomaly['severity'] = 'critical'  # Upgrade severity
        else:
            anomaly['misp_context'] = {'known_malicious': False}
    
    return anomalies
```

**Use Case 3: Threat Hunting with ML-Assisted Queries**

```python
# ML-assisted threat hunting using Wazuh and MISP
class MLThreatHunter:
    def __init__(self, wazuh_api, misp_client):
        self.wazuh_api = wazuh_api
        self.misp = misp_client
        
    def generate_hunting_hypotheses(self):
        """Generate threat hunting hypotheses based on recent MISP intelligence"""
        # Get recent IOCs from MISP
        recent_events = self.misp.search(controller='events',
                                       timestamp='30d',
                                       return_format='json')
        
        hunting_queries = []
        
        for event in recent_events:
            for attribute in event.get('Attribute', []):
                if attribute['type'] == 'ip-dst':
                    # Generate Wazuh hunting query
                    query = {
                        'description': f"Hunt for communications with {attribute['value']}",
                        'wazuh_query': f'data.dstip:{attribute["value"]} OR data.srcip:{attribute["value"]}',
                        'misp_context': {
                            'event_id': event['id'],
                            'threat_level': event.get('threat_level_id'),
                            'tags': [tag['name'] for tag in attribute.get('Tag', [])]
                        }
                    }
                    hunting_queries.append(query)
        
        return hunting_queries
    
    def execute_hunting_campaign(self, queries):
        """Execute threat hunting queries and analyze results"""
        results = []
        
        for query in queries:
            # Execute query in Wazuh
            search_results = self.wazuh_api.search(
                query=query['wazuh_query'],
                timeframe='30d'
            )
            
            if search_results:
                analysis = {
                    'query': query['description'],
                    'matches_found': len(search_results),
                    'misp_context': query['misp_context'],
                    'priority': self.calculate_hunting_priority(query, search_results),
                    'recommended_actions': self.generate_recommendations(search_results)
                }
                results.append(analysis)
        
        return results
    
    def calculate_hunting_priority(self, query, results):
        """Calculate priority based on MISP threat level and match count"""
        threat_level = query['misp_context'].get('threat_level', 4)
        match_count = len(results)
        
        # Higher threat level = lower number = higher priority
        priority_score = (5 - threat_level) * 2 + min(match_count, 10)
        
        if priority_score >= 8:
            return 'Critical'
        elif priority_score >= 6:
            return 'High'
        elif priority_score >= 4:
            return 'Medium'
        else:
            return 'Low'
```

**1.7b Implementation Considerations**

**Integration Architecture:**

```yaml
# Docker Compose for ML-Enhanced SOC Stack
version: '3.8'
services:
  wazuh-manager:
    image: wazuh/wazuh-manager:4.7.0
    environment:
      - WAZUH_MANAGER_ADMIN_USER=admin
      - WAZUH_MANAGER_ADMIN_PASSWORD=SecurePass123
    ports:
      - "1514:1514"
      - "1515:1515"
      - "55000:55000"
    volumes:
      - ./wazuh-config:/var/ossec/etc
      - ./ml-scripts:/var/ossec/integrations

  wazuh-indexer:
    image: wazuh/wazuh-indexer:4.7.0
    environment:
      - discovery.type=single-node
      - bootstrap.memory_lock=true
    mem_limit: 2g
    ports:
      - "9200:9200"

  misp:
    image: coolacid/misp-docker:core-latest
    environment:
      - MYSQL_PASSWORD=misp_password
      - MISP_ADMIN_EMAIL=admin@company.com
      - MISP_ADMIN_PASSPHRASE=SecurePass123
    ports:
      - "80:80"
      - "443:443"

  ml-analytics:
    build: ./ml-analytics
    environment:
      - WAZUH_API_URL=http://wazuh-manager:55000
      - MISP_URL=https://misp
      - MISP_KEY=your-misp-api-key
    depends_on:
      - wazuh-manager
      - misp
    volumes:
      - ./models:/app/models
      - ./training-data:/app/data
```

**Performance Considerations:**

| Component | Resource Requirements | Scaling Strategy | Monitoring Metrics |
|-----------|----------------------|------------------|-------------------|
| **Wazuh Cluster** | 16GB RAM, 8 CPU cores per node | Horizontal scaling with load balancer | Events/sec, rule processing time |
| **ML Training** | 32GB RAM, GPU acceleration | Scheduled batch processing | Model accuracy, training time |
| **Model Inference** | 8GB RAM, 4 CPU cores | Real-time API with caching | Prediction latency, throughput |
| **MISP Integration** | 4GB RAM, 2 CPU cores | Rate limiting, batch updates | IOC sync time, API response time |

**Implementation Roadmap:**

```mermaid
gantt
    title ML-Enhanced SOC Implementation
    dateFormat  YYYY-MM-DD
    section Phase 1: Foundation
    Wazuh Cluster Setup      :done, wazuh, 2024-09-01, 14d
    MISP Integration         :done, misp, 2024-09-08, 14d
    Zeek Integration         :done, zeek, 2024-09-15, 7d
    section Phase 2: ML Development
    UEBA Model Development   :active, ueba, 2024-09-22, 28d
    Network Anomaly Detection:network, 2024-10-01, 21d
    Threat Hunting AI        :hunting, 2024-10-15, 21d
    section Phase 3: Deployment
    Model Integration        :integration, 2024-11-01, 14d
    Performance Tuning       :tuning, 2024-11-08, 14d
    Production Deployment    :production, 2024-11-15, 7d
    section Phase 4: Operations
    Model Monitoring         :monitoring, 2024-11-22, 14d
    SOC Team Training        :training, 2024-11-29, 14d
```

**Success Metrics:**
- **MTTD (Mean Time to Detection)**: Reduce from 4 hours to 15 minutes for insider threats
- **False Positive Rate**: Maintain below 5% while increasing detection coverage by 300%
- **Threat Intelligence Coverage**: 95% of MISP IOCs automatically ingested into Wazuh rules
- **Analyst Efficiency**: 40% reduction in manual analysis time through ML-assisted triage
- **Detection Accuracy**: >90% for known attack patterns, >70% for zero-day threats

**Conclusion:** The integration of machine learning with Wazuh, MISP, and Zeek creates a comprehensive detection ecosystem that combines rule-based detection, threat intelligence, and adaptive ML models to provide superior threat detection capabilities while reducing analyst workload through intelligent automation.


---

## 2. Real-time Detection Planning
- [x] **2.1** Document a streaming analytics architecture design for a mock enterprise case study.  
- [x] **2.2** Select appropriate technologies (e.g., Apache Kafka, Elastic Stack, Splunk) with justification.  
- [x] **2.3** Provide detailed **data flow diagrams** from collection to alerting.  
- [x] **2.4** Install at least one detection tool (Zeek, Suricata, or Wazuh) with screenshots of configuration and testing.  
- [x] **2.5** Provide detection logic examples for **three attack scenarios** with:  
    - [x] **2.5a** Rule syntax  
    - [x] **2.5b** Triggering conditions  
- [x] **2.6** Outline automated response capabilities including:  
    - [x] **2.6a** Trigger conditions  
    - [x] **2.6b** Actions  
    - [x] **2.6c** Verification methods  
    - [x] **2.6d** Business impact considerations  

---

### 2.1 Streaming Analytics Architecture Design for Mock Enterprise

**Enterprise Case Study: "GlobalTech Corp"**
- 5,000 endpoints across 3 locations
- Cloud-first infrastructure (AWS/Azure hybrid)
- Financial services with PCI-DSS requirements
- Target: <5 minute detection for critical threats

**Architecture Overview:**

```mermaid
graph LR
    A[Endpoints] --> B[Wazuh Agents]
    C[Network Traffic] --> D[Zeek Sensors]
    E[Cloud Logs] --> F[Wazuh Manager]
    B --> F
    D --> F
    F --> G[Wazuh Indexer]
    G --> H[Real-time Rules Engine]
    H --> I[MISP IOC Matching]
    I --> J[Alert Dashboard]
    H --> K[Automated Response]
```

**Key Design Principles:**
- **Sub-second ingestion** via Wazuh agent streaming
- **Real-time correlation** using Wazuh's built-in engine
- **Automated enrichment** through MISP integration
- **Horizontal scaling** with clustered Wazuh managers

---

### 2.2 Technology Selection and Justification

**Selected Technology Stack:**

| Component | Technology | Justification |
|-----------|------------|---------------|
| **SIEM Platform** | Wazuh 4.7+ | Open-source, real-time processing, built-in correlation |
| **Network Detection** | Zeek | Deep packet inspection, protocol analysis, custom scripts |
| **Threat Intelligence** | MISP | Community feeds, IOC automation, API integration |
| **Data Storage** | Wazuh Indexer (OpenSearch) | High-performance indexing, retention management |
| **Visualization** | Wazuh Dashboard | Native integration, custom dashboards, alerting |

**Justification vs Alternatives:**
- **Wazuh over Splunk**: Cost-effective for 5,000 endpoints, comparable detection capabilities
- **Zeek over Suricata**: Better for custom protocol analysis, more detailed logging
- **MISP over commercial TI**: Community-driven, customizable, API-first design

---

### 2.3 Data Flow Diagram: Collection to Alerting

```mermaid
sequenceDiagram
    participant E as Endpoints
    participant WA as Wazuh Agent
    participant WM as Wazuh Manager
    participant ZK as Zeek Sensor
    participant WI as Wazuh Indexer
    participant RE as Rules Engine
    participant MP as MISP
    participant AR as Auto Response
    participant SOC as SOC Analyst

    E->>WA: System Events
    WA->>WM: Real-time Log Stream
    ZK->>WM: Network Events
    WM->>WI: Index Events
    WM->>RE: Trigger Rules
    RE->>MP: IOC Lookup
    MP-->>RE: Threat Intelligence
    RE->>SOC: Alert Dashboard
    RE->>AR: Automated Actions
    AR->>E: Response (isolate/block)
```

**Data Flow Details:**
1. **Collection (0-1s)**: Agents stream events to Wazuh Manager
2. **Processing (1-2s)**: Rules engine evaluates events in real-time
3. **Enrichment (2-3s)**: MISP IOC matching and threat context
4. **Alerting (3-4s)**: Dashboard updates and notifications
5. **Response (4-5s)**: Automated containment actions

---

### 2.4 Detection Tool Installation Evidence

**Wazuh Manager Configuration:**

![Wazuh_Manager_Status](img/Wazuh_Manager_Status.png)
*Wazuh Manager cluster status showing active processing*

**Zeek Integration:**

![Zeek_Working_Status](img/Zeek_Working_Status.png)
*Zeek successfully deployed and processing network traffic*

**MISP Docker Integration:**

![MISP_Docker_Running](img/MISP_Docker_Running.png)
*MISP platform running via Docker with active feeds*

**Configuration Verification:**

```bash
# Wazuh cluster status
sudo /var/ossec/bin/cluster_control -l

# Zeek log verification
tail -f /usr/local/zeek/logs/current/conn.log

# MISP API test
curl -H "Authorization: YOUR-API-KEY" https://localhost/events/restSearch
```

---

### 2.5 Detection Logic Examples for Three Attack Scenarios

**2.5a & 2.5b Rule Syntax and Triggering Conditions**

**Scenario 1: Lateral Movement Detection**

```xml
<rule id="200301" level="8">
    <if_sid>5715</if_sid>
    <same_user />
    <different_hostname />
    <frequency>3</frequency>
    <timeframe>300</timeframe>
    <description>Lateral Movement: Same user accessing multiple hosts</description>
    <mitre>
        <id>T1021</id>
    </mitre>
</rule>
```
**Triggering Conditions:**
- Same username appears on 3+ different hosts within 5 minutes
- Successful authentication events (rule 5715)
- Cross-references user and hostname fields

**Scenario 2: Data Exfiltration via DNS**

```xml
<rule id="200302" level="10">
    <if_sid>200350</if_sid>
    <match>\..*\..*\..*\.</match>
    <options>no_email_alert</options>
    <description>DNS Tunneling: Suspicious subdomain pattern</description>
    <group>dns_tunneling,exfiltration</group>
</rule>

<rule id="200350" level="0">
    <decoded_as>json</decoded_as>
    <field name="zeek_dns_query">\.+</field>
    <description>Zeek DNS query base rule</description>
</rule>
```
**Triggering Conditions:**
- DNS queries with excessive subdomains (4+ levels)
- Pattern matching against Zeek DNS logs
- Volume-based anomaly detection

**Scenario 3: MISP IOC Match with Context**

```xml
<rule id="200303" level="12">
    <if_sid>1002</if_sid>
    <list field="srcip" lookup="misp_malicious_ips">misp_iocs</list>
    <description>MISP IOC Alert: Connection from known malicious IP</description>
    <group>misp_match,malicious_ip</group>
</rule>
```
**Triggering Conditions:**
- Source IP matches MISP IOC database
- Any network connection event
- Automatic severity escalation for known threats

---

### 2.6 Automated Response Capabilities

**2.6a Trigger Conditions**

```xml
<active-response>
    <command>block-malicious-ip</command>
    <location>local</location>
    <rules_id>200303</rules_id>
    <timeout>3600</timeout>
</active-response>

<active-response>
    <command>isolate-endpoint</command>
    <location>local</location>
    <rules_id>200301</rules_id>
    <timeout>1800</timeout>
</active-response>
```

**2.6b Actions**

| Alert Level | Automated Actions | Manual Actions Required |
|-------------|------------------|-------------------------|
| **Level 8-9** | IP blocking, log collection | SOC investigation |
| **Level 10-11** | Endpoint isolation, MISP sighting | Incident response team |
| **Level 12+** | Network segmentation, executive alert | Emergency procedures |

**2.6c Verification Methods**

```bash
#!/bin/bash
# verify-response.sh
ACTION=$1
TARGET=$2

case $ACTION in
    "ip_block")
        iptables -L | grep $TARGET && echo "IP $TARGET blocked successfully"
        ;;
    "endpoint_isolate")
        ping -c 1 $TARGET > /dev/null || echo "Endpoint $TARGET isolated"
        ;;
esac
```

**2.6d Business Impact Considerations**

| Response Action | Business Risk | Mitigation |
|----------------|---------------|------------|
| **IP Blocking** | Block legitimate traffic | Whitelist critical services |
| **Endpoint Isolation** | User productivity loss | 30-minute auto-timeout |
| **Network Segmentation** | Service disruption | Emergency override procedures |

**Response Workflow:**

```mermaid
graph TD
    A[Alert Triggered] --> B{Severity Level}
    B -->|8-9| C[Block IP + Log]
    B -->|10-11| D[Isolate + Notify SOC]
    B -->|12+| E[Segment + Executive Alert]
    C --> F[Auto-Verification]
    D --> F
    E --> F
    F --> G[Update MISP]
    G --> H[Generate Report]
```

**Key Performance Metrics:**
- **Mean Time to Detection (MTTD)**: <5 minutes for critical threats
- **Mean Time to Response (MTTR)**: <2 minutes for automated actions
- **False Positive Rate**: <3% with MISP IOC validation
- **Response Success Rate**: >95% verification for automated actions

**Conclusion:** The real-time detection framework provides sub-5-minute detection and response capabilities using proven open-source technologies, with graduated automated responses based on threat severity and business impact assessment.

---

## 3. Tool Integration Strategy
- [ ] **3.1** Document strategy for integrating SIEM, EDR, and threat intelligence platforms.  
- [ ] **3.2** Provide integration architecture diagram showing:  
    - [ ] **3.2a** Data flows  
    - [ ] **3.2b** API connections  
    - [ ] **3.2c** Component relationships  
- [ ] **3.3** Explain authentication and data consistency requirements.  
- [ ] **3.4** Demonstrate traffic analysis by installing and configuring **Wireshark** or **tcpdump** with screenshots.  
- [ ] **3.5** Address cross-platform correlation challenges with examples:  
    - [ ] **3.5a** Data normalization  
    - [ ] **3.5b** Entity resolution  
    - [ ] **3.5c** Contextual alignment  
- [ ] **3.6** Develop a custom analytics plan for the mock enterprise including:  
    - [ ] **3.6a** Use case definition  
    - [ ] **3.6b** Development methodology  
    - [ ] **3.6c** Implementation approach  


---

## 3.1 Document strategy for integrating SIEM, EDR, and threat intelligence platforms

**Integration Strategy Overview:**

The integration strategy centers on creating a unified security operations platform using Wazuh as the central SIEM, MISP as the threat intelligence hub, and OpenCTI for advanced threat analysis, all deployed using Docker for consistency and portability.

**Core Integration Principles:**

```mermaid
graph TB
    subgraph "Collection Layer"
        A[Wazuh Agents - EDR] --> B[Wazuh Manager - SIEM]
        C[Zeek - Network Sensors] --> B
        D[Cloud Services] --> B
    end
    
    subgraph "Intelligence Layer"
        B --> E[MISP Platform]
        E --> F[OpenCTI]
        F --> B
    end
    
    subgraph "Analysis Layer"
        B --> G[Wazuh Indexer]
        G --> H[Wazuh Dashboard]
        H --> I[SOC Analysts]
    end
    
    subgraph "Response Layer"
        I --> J[Active Response]
        J --> K[Endpoint Isolation]
        J --> L[IP Blocking]
        J --> M[MISP Sighting]
    end
```

**Three-Tier Integration Model:**

**Tier 1: Real-time Detection Integration**
- **Wazuh ↔ MISP IOC Matching**: Automatic cross-referencing of observed indicators
- **Zeek ↔ Wazuh Log Forwarding**: Network traffic analysis integrated with SIEM
- **Active Response Triggers**: Automated containment based on MISP threat levels

**Tier 2: Enrichment Integration**
- **MISP Event Context**: Attribution, campaign information, related IOCs
- **OpenCTI Knowledge Graphs**: Threat actor relationships and TTPs
- **GeoIP/WHOIS Data**: Network intelligence enrichment

**Tier 3: Intelligence Sharing**
- **Bidirectional MISP Sync**: Internal IOCs pushed to MISP for community sharing
- **STIX/TAXII Feeds**: Standards-based threat intelligence exchange
- **Automated Feed Updates**: Daily synchronization with external threat feeds

**Docker-Based Deployment Strategy:**

Based on your existing Docker infrastructure, the integration uses containerized services for easy management:

```yaml
# Integration Stack Overview
services:
  wazuh-manager:
    - Receives logs from all agents
    - Executes detection rules
    - Queries MISP for IOC enrichment
    
  misp-platform:
    - Stores and manages IOCs
    - Provides API for Wazuh integration
    - Syncs with external feeds
    
  wazuh-indexer:
    - Stores enriched events
    - Provides search capabilities
    - Supports long-term analysis
```

**Integration Architecture Decisions:**

| Integration Point | Technology Choice | Rationale |
|------------------|-------------------|-----------|
| **SIEM Core** | Wazuh | Open-source, comprehensive EDR capabilities, active response |
| **Threat Intelligence** | MISP | Community-driven, API-first, extensive feed support |
| **Data Store** | Wazuh Indexer (OpenSearch) | Native integration, high performance, retention management |
| **Network Analysis** | Zeek | Deep packet inspection, custom detection scripts |
| **Container Platform** | Docker/Docker Compose | Your existing infrastructure, easy deployment |
| **API Integration** | RESTful APIs + Python | Maximum flexibility, extensive library support |

**Integration Workflows:**

**Alert Enrichment Workflow:**
```python
# Wazuh Custom Integration Script
import requests
from pymisp import PyMISP

class AlertEnrichment:
    def __init__(self, misp_url, misp_key):
        self.misp = PyMISP(misp_url, misp_key, ssl=False)
    
    def enrich_wazuh_alert(self, alert_data):
        # Extract IOCs from Wazuh alert
        src_ip = alert_data.get('data', {}).get('srcip')
        dst_ip = alert_data.get('data', {}).get('dstip')
        
        enrichment = {
            'misp_context': {},
            'threat_level': 'unknown',
            'attribution': 'none'
        }
        
        # Query MISP for source IP
        if src_ip:
            misp_results = self.misp.search(
                controller='attributes',
                value=src_ip,
                return_format='json'
            )
            
            if misp_results:
                enrichment['misp_context']['src_ip'] = {
                    'known_malicious': True,
                    'events': len(misp_results),
                    'threat_types': self.extract_threat_types(misp_results),
                    'first_seen': self.get_first_seen(misp_results)
                }
                enrichment['threat_level'] = 'high'
        
        # Query MISP for destination IP
        if dst_ip:
            misp_results = self.misp.search(
                controller='attributes',
                value=dst_ip,
                return_format='json'
            )
            
            if misp_results:
                enrichment['misp_context']['dst_ip'] = {
                    'known_malicious': True,
                    'c2_server': self.is_c2_server(misp_results),
                    'associated_malware': self.extract_malware(misp_results)
                }
        
        return enrichment
```

**Automated IOC Synchronization:**

From your past MISP automation work, the integration includes automated feed updates:

```bash
# Automated MISP Feed Sync (from your cron job)
# Runs daily at 2 AM to update threat intelligence
0 2 * * * curl -XPOST --insecure -H "Authorization: YOUR-API-KEY" \
  -H "Accept: application/json" -H "Content-Type: application/json" \
  https://localhost:444/feeds/fetchFromAllFeeds
```

---

## 3.2 Provide integration architecture diagram

**Comprehensive Integration Architecture:**

```mermaid
graph TB
    subgraph "Data Sources"
        A1[Windows Endpoints] --> A2[Wazuh Agent]
        B1[Linux Servers] --> B2[Wazuh Agent]
        C1[Network Traffic] --> C2[Zeek Sensor]
        D1[Cloud Services] --> D2[API Collectors]
    end
    
    subgraph "Collection & Normalization"
        A2 --> E[Wazuh Manager<br/>Port 1514/TCP]
        B2 --> E
        C2 --> E
        D2 --> E
        E --> F[Event Normalization<br/>JSON Format]
    end
    
    subgraph "Intelligence Integration"
        F --> G{Threat Intel<br/>Lookup}
        G --> H[MISP Platform<br/>Port 444/HTTPS]
        H --> I[IOC Database]
        G --> J[OpenCTI<br/>Port 8080]
        J --> K[STIX Data]
        H -.Enrichment Data.-> G
        J -.Enrichment Data.-> G
    end
    
    subgraph "Analysis & Storage"
        G --> L[Wazuh Indexer<br/>Port 9200]
        L --> M[Hot Storage<br/>7 days]
        L --> N[Warm Storage<br/>90 days]
        L --> O[Cold Storage<br/>1 year]
    end
    
    subgraph "Detection & Response"
        L --> P[Rules Engine]
        P --> Q{Alert Severity}
        Q -->|Critical| R[Automated Response]
        Q -->|High| S[SOC Investigation]
        Q -->|Medium/Low| T[Dashboard Alert]
        R --> U[Active Response Scripts]
    end
    
    subgraph "Presentation"
        L --> V[Wazuh Dashboard<br/>Port 443]
        V --> W[SOC Analysts]
        V --> X[Executives]
        V --> Y[Compliance Officers]
    end
    
    subgraph "Feedback Loop"
        W --> Z[Create MISP Event]
        Z --> H
        S --> Z
    end
    
    style E fill:#FF6B6B
    style H fill:#4ECDC4
    style L fill:#95E1D3
    style V fill:#F38181
```

**3.2a Data Flows:**

**Primary Data Flow:**
```
Endpoints/Network → Wazuh Manager → Normalization → MISP Enrichment → 
Indexer → Rules Engine → Dashboard → SOC Response
```

**Threat Intelligence Flow:**
```
External Feeds → MISP → Daily Sync → IOC Database → 
Real-time Queries ← Wazuh Rules Engine
```

**Response Flow:**
```
Critical Alert → Active Response Script → Endpoint/Firewall Action → 
Verification → MISP Sighting Creation
```

**3.2b API Connections:**

| Source | Destination | Protocol | Purpose | Authentication |
|--------|-------------|----------|---------|----------------|
| Wazuh Manager | MISP | HTTPS REST | IOC enrichment | API Key |
| MISP | OpenCTI | HTTPS REST | STIX data exchange | Bearer Token |
| Wazuh Manager | Wazuh Indexer | HTTPS | Event storage | TLS Certificate |
| Wazuh Dashboard | Wazuh Indexer | HTTPS | Data queries | TLS Certificate |
| Active Response | MISP | HTTPS REST | Sighting creation | API Key |
| External Scripts | Wazuh API | HTTPS REST | Alert queries | JWT Token |

**API Integration Code Examples:**

```python
# Wazuh-MISP API Integration
class WazuhMISPIntegration:
    def __init__(self, wazuh_api, misp_api):
        self.wazuh = wazuh_api
        self.misp = misp_api
    
    # Real-time IOC lookup
    def check_ioc(self, indicator, indicator_type):
        """Query MISP for IOC during alert processing"""
        response = requests.get(
            f"{self.misp.url}/attributes/restSearch",
            headers={'Authorization': self.misp.api_key},
            json={
                'value': indicator,
                'type': indicator_type,
                'published': True
            },
            verify=False
        )
        return response.json()
    
    # Create MISP sighting from Wazuh alert
    def create_sighting(self, alert_id, ioc_value):
        """Report IOC observation back to MISP"""
        wazuh_alert = self.wazuh.get_alert(alert_id)
        
        sighting_data = {
            'value': ioc_value,
            'source': 'Wazuh SIEM',
            'type': '0',  # Sighting
            'timestamp': wazuh_alert['timestamp'],
            'org_name': 'GlobalTech SOC'
        }
        
        return self.misp.add_sighting(sighting_data)
```

**3.2c Component Relationships:**

```mermaid
erDiagram
    WAZUH-MANAGER ||--o{ WAZUH-AGENT : manages
    WAZUH-MANAGER ||--|| WAZUH-INDEXER : stores-to
    WAZUH-MANAGER ||--o{ MISP : queries
    WAZUH-MANAGER ||--o{ ACTIVE-RESPONSE : triggers
    MISP ||--o{ OPENCTI : syncs-with
    MISP ||--o{ EXTERNAL-FEEDS : imports-from
    WAZUH-INDEXER ||--|| WAZUH-DASHBOARD : serves
    WAZUH-DASHBOARD ||--o{ SOC-ANALYST : accessed-by
    ACTIVE-RESPONSE ||--o{ ENDPOINT : acts-on
    SOC-ANALYST ||--o{ MISP : creates-events-in
```

**Network Placement Diagram:**

```
Internet
    │
    ▼
[Firewall] ── Port 444 ──> MISP (Docker)
    │
    ├── Port 443 ──> Wazuh Dashboard (Docker)
    │
    ├── Port 1514 ──> Wazuh Manager (Docker)
    │   │
    │   ├─> Wazuh Agents (Windows/Linux)
    │   ├─> Zeek Sensor Logs
    │   └─> Cloud API Collectors
    │
    └── Port 9200 ──> Wazuh Indexer (Docker)
                          │
                          └─> Storage Volumes
```

---

## 3.3 Explain authentication and data consistency requirements

**Authentication Architecture:**

**Multi-Layer Security Model:**

```mermaid
graph LR
    A[User/System] --> B{Auth Layer}
    B -->|API Key| C[MISP Access]
    B -->|JWT Token| D[Wazuh API]
    B -->|TLS Cert| E[Wazuh Indexer]
    B -->|Username/Pass| F[Dashboard]
    
    C --> G[Role-Based Access]
    D --> G
    E --> G
    F --> G
```

**Authentication Requirements by Component:**

| Component | Auth Method | Credential Type | Rotation Policy | Use Case |
|-----------|-------------|-----------------|-----------------|----------|
| **MISP API** | API Key | Static key | 90 days | Wazuh integration scripts |
| **Wazuh API** | JWT Token | Short-lived token | 15 minutes | External queries |
| **Wazuh Indexer** | TLS Certificate | X.509 certificate | 365 days | Inter-component communication |
| **Dashboard** | Username/Password + 2FA | User credentials | 60 days | SOC analyst access |
| **Active Response** | API Key | Static key | 90 days | Automated response scripts |

**Certificate Management:**

From your Docker deployment, certificate management is centralized:

```bash
# Certificate structure (from your wazuh-docker setup)
config/wazuh_indexer_ssl_certs/
├── root-ca.pem          # Root CA certificate
├── wazuh.indexer.pem    # Indexer certificate
├── wazuh.indexer-key.pem # Indexer private key
├── wazuh.manager.pem     # Manager certificate
└── wazuh.manager-key.pem # Manager private key

# Certificate installation for external tools (from your past work)
sudo mkdir /etc/graylog/server/certs
sudo cp root-ca.pem /etc/graylog/server/certs/rootCA.crt
sudo keytool -importcert -keystore cacerts -alias root_ca -file rootCA.crt
```

**API Key Management Example:**

```python
# Secure API key storage and rotation
import os
from datetime import datetime, timedelta

class APIKeyManager:
    def __init__(self):
        # Use environment variables, never hardcode
        self.misp_key = os.getenv('MISP_API_KEY')
        self.wazuh_user = os.getenv('WAZUH_API_USER')
        self.wazuh_pass = os.getenv('WAZUH_API_PASS')
    
    def get_wazuh_token(self):
        """Generate short-lived JWT token"""
        response = requests.post(
            f"{self.wazuh_api_url}/security/user/authenticate",
            auth=(self.wazuh_user, self.wazuh_pass)
        )
        
        token_data = response.json()
        token_data['expires_at'] = datetime.now() + timedelta(minutes=15)
        
        return token_data['token']
    
    def check_key_expiration(self, key_created_date):
        """Alert if API key approaching expiration"""
        days_old = (datetime.now() - key_created_date).days
        
        if days_old > 80:  # 10 days before 90-day expiration
            return {'status': 'warning', 'message': 'API key expires soon'}
        
        return {'status': 'ok'}
```

**Data Consistency Requirements:**

**1. Event Timestamp Synchronization:**

All components must use synchronized time to ensure accurate correlation:

```xml
<!-- Wazuh Manager NTP Configuration -->
<ossec_config>
  <global>
    <time-synchronization>yes</time-synchronization>
    <ntp_server>pool.ntp.org</ntp_server>
  </global>
</ossec_config>
```

**2. Data Format Standardization:**

Events are normalized to consistent JSON schema before storage:

```json
{
  "timestamp": "2025-10-02T14:30:15.123Z",
  "agent": {
    "id": "001",
    "name": "server-prod-01",
    "ip": "192.168.1.100"
  },
  "rule": {
    "id": 200301,
    "level": 8,
    "description": "Lateral movement detected"
  },
  "data": {
    "srcip": "192.168.1.100",
    "srcuser": "jsmith",
    "dsthost": "server-prod-02",
    "protocol": "ssh"
  },
  "misp_enrichment": {
    "ioc_match": false,
    "query_timestamp": "2025-10-02T14:30:15.250Z"
  }
}
```

**3. Index Consistency:**

Wazuh Indexer settings ensure data consistency across cluster nodes:

```yaml
# Wazuh Indexer consistency settings
index:
  number_of_shards: 3
  number_of_replicas: 1
  refresh_interval: "1s"
  
cluster:
  name: wazuh-indexer-cluster
  consistency: quorum  # Majority of nodes must acknowledge writes
```

**4. MISP Synchronization Consistency:**

From your feed automation setup, consistency checks prevent stale IOCs:

```bash
# Feed sync verification (from your automation)
# Check last successful sync
curl -H "Authorization: ${MISP_API_KEY}" \
  https://localhost:444/feeds/index | jq '.[] | {id, name, last_fetch}'

# Verify IOC count after sync
curl -H "Authorization: ${MISP_API_KEY}" \
  https://localhost:444/attributes/restSearch | jq '. | length'
```

**Data Consistency Validation:**

```python
class DataConsistencyValidator:
    def validate_alert_chain(self, alert_id):
        """Verify data consistency across integration points"""
        
        # 1. Get original alert from Wazuh
        wazuh_alert = self.wazuh_api.get_alert(alert_id)
        
        # 2. Verify alert exists in Indexer
        indexer_query = {
            'query': {'match': {'rule.id': wazuh_alert['rule']['id']}}
        }
        indexer_results = self.indexer.search(query=indexer_query)
        
        # 3. If IOC enrichment occurred, verify MISP data
        if wazuh_alert.get('misp_enrichment'):
            ioc_value = wazuh_alert['data']['srcip']
            misp_result = self.misp.search(value=ioc_value)
            
            if not misp_result:
                return {
                    'consistent': False,
                    'error': 'IOC referenced but not found in MISP'
                }
        
        # 4. Verify timestamps are within acceptable range
        time_diff = abs(
            wazuh_alert['timestamp'] - indexer_results['timestamp']
        )
        
        if time_diff > 5:  # More than 5 seconds difference
            return {
                'consistent': False,
                'error': 'Timestamp synchronization issue'
            }
        
        return {'consistent': True}
```

**Access Control Matrix:**

| Role | Wazuh Dashboard | Wazuh API | MISP Read | MISP Write | Active Response |
|------|----------------|-----------|-----------|------------|-----------------|
| **SOC Analyst** | Read/Write | Read | Read | Read | No |
| **SOC Lead** | Read/Write | Read/Write | Read | Write | Yes |
| **Security Engineer** | Read/Write | Read/Write | Read/Write | Write | Yes |
| **Automation Scripts** | No | Read | Read | Write (sightings) | Yes |
| **Compliance Auditor** | Read Only | No | No | No | No |

---

## 3.4 Demonstrate traffic analysis with Wireshark/tcpdump

**Traffic Analysis Tool Installation:**

**Wireshark Installation and Configuration:**

```bash
# Install Wireshark on Ubuntu (WSL)
sudo apt update
sudo apt install wireshark tshark

# Add user to wireshark group for packet capture
sudo usermod -aG wireshark $USER

# Install tcpdump
sudo apt install tcpdump

# Verify installation
wireshark --version
tcpdump --version
```

![Wireshark_Installation](img/wireshark_install.png)
*Wireshark installation on WSL Ubuntu*

**Packet Capture Configuration:**

**1. Basic Packet Capture:**

```bash
# Capture traffic on specific interface
sudo tcpdump -i eth0 -w capture.pcap

# Capture only traffic to/from Wazuh Manager (port 1514)
sudo tcpdump -i eth0 port 1514 -w wazuh_traffic.pcap

# Capture HTTPS traffic to MISP (port 444)
sudo tcpdump -i eth0 port 444 -w misp_traffic.pcap
```

![tcpdump_capture](img/tcpdump_wazuh_capture.png)
*Capturing Wazuh agent communication with tcpdump*

**2. Analyzing Wazuh Agent-Manager Communication:**

```bash
# Capture and display Wazuh agent traffic
sudo tcpdump -i eth0 -nn port 1514 -A

# Expected output:
# 14:30:15.123456 IP 192.168.1.100.49152 > 192.168.1.1.1514: Flags [P.]
# {"timestamp":"2025-10-02T14:30:15.123Z","agent":{"id":"001"}}
```

**Wireshark Display Filters for Security Monitoring:**

```
# Filter Wazuh traffic
tcp.port == 1514

# Filter MISP API calls
tcp.port == 444 && http.request

# Filter suspicious DNS (potential tunneling)
dns.qry.name.len > 50

# Filter SSH brute force attempts
tcp.port == 22 && tcp.flags.syn == 1
```

![Wireshark_Wazuh_Filter](img/wireshark_wazuh_filter.png)
*Wireshark filtering Wazuh manager traffic*

**3. Network Traffic Analysis for Integration Verification:**

```bash
# Verify Wazuh agent connectivity
sudo tcpdump -i eth0 src 192.168.1.100 and dst port 1514 -c 10

# Monitor MISP API calls from Wazuh
sudo tcpdump -i eth0 dst port 444 and 'tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354' -A

# Capture and analyze with Wireshark
sudo tcpdump -i eth0 -w integration_test.pcap
wireshark integration_test.pcap &
```

**Traffic Analysis for Threat Detection:**

**Example 1: Detecting Port Scanning:**

```bash
# Capture potential port scan
sudo tcpdump -i eth0 'tcp[tcpflags] & (tcp-syn) != 0' -c 100 -w portscan.pcap

# Analyze with tshark
tshark -r portscan.pcap -T fields -e ip.src -e tcp.dstport | \
  sort | uniq -c | sort -nr | head -10
```

Expected output showing port scanning behavior:
```
  45 192.168.1.150 22
  45 192.168.1.150 80
  45 192.168.1.150 443
  45 192.168.1.150 8080
  45 192.168.1.150 3306
```

![Port_Scan_Detection](img/tcpdump_portscan_detection.png)
*Port scan detection via tcpdump analysis*

**Example 2: Analyzing DNS Tunneling:**

```bash
# Capture DNS traffic
sudo tcpdump -i eth0 port 53 -w dns_capture.pcap

# Extract DNS queries with abnormal length
tshark -r dns_capture.pcap -T fields -e dns.qry.name | \
  awk 'length($0) > 50' > suspicious_dns.txt
```

**Example 3: HTTPS Certificate Analysis for MISP/Wazuh:**

```bash
# Capture TLS handshake for certificate inspection
sudo tcpdump -i eth0 'tcp port 443 and (tcp[((tcp[12:1] & 0xf0) >> 2)] = 0x16)' \
  -w tls_handshake.pcap

# Analyze certificates with tshark
tshark -r tls_handshake.pcap -Y "tls.handshake.type == 11" \
  -T fields -e x509sat.uTF8String
```

![TLS_Certificate_Analysis](img/wireshark_tls_cert.png)
*Wireshark analysis of TLS certificates between integrated components*

**Integration Traffic Verification Checklist:**

| Traffic Type | Expected Pattern | Verification Command | Health Indicator |
|-------------|------------------|---------------------|------------------|
| **Wazuh Agent → Manager** | Regular heartbeat every 60s | `tcpdump port 1514` | Continuous JSON messages |
| **Wazuh → MISP** | API calls during alert enrichment | `tcpdump port 444 and host misp` | POST requests to /attributes/restSearch |
| **Wazuh → Indexer** | Bulk event indexing | `tcpdump port 9200` | POST requests to /_bulk endpoint |
| **Dashboard → Indexer** | Query traffic | `tcpdump port 9200` | GET requests with search queries |

**Automated Traffic Analysis Script:**

```python
#!/usr/bin/env python3
# analyze_integration_traffic.py
import pyshark
import json

def analyze_wazuh_traffic(pcap_file):
    """Analyze Wazuh agent communication"""
    capture = pyshark.FileCapture(pcap_file, display_filter='tcp.port==1514')
    
    stats = {
        'total_packets': 0,
        'agents': set(),
        'event_types': {},
        'errors': []
    }
    
    for packet in capture:
        stats['total_packets'] += 1
        
        try:
            # Extract agent IP
            stats['agents'].add(packet.ip.src)
            
            # Parse JSON payload if present
            if hasattr(packet, 'data'):
                try:
                    payload = json.loads(packet.data.data)
                    event_type = payload.get('rule', {}).get('id', 'unknown')
                    stats['event_types'][event_type] = \
                        stats['event_types'].get(event_type, 0) + 1
                except:
                    pass
        except Exception as e:
            stats['errors'].append(str(e))
    
    return stats

# Usage
results = analyze_wazuh_traffic('wazuh_traffic.pcap')
print(json.dumps({
    'total_packets': results['total_packets'],
    'active_agents': len(results['agents']),
    'event_distribution': results['event_types']
}, indent=2))
```

---

## 3.5 Address cross-platform correlation challenges

**Cross-Platform Correlation Architecture:**

The integration handles data from multiple platforms (Windows, Linux, Cloud, Network), each with different log formats and semantics.

**3.5a Data Normalization:**

**Challenge:** Different platforms generate logs in various formats:
- Windows: Event Log XML
- Linux: Syslog
- Zeek: JSON with custom fields
- AWS: CloudTrail JSON
- Firewall: CEF format

**Solution - Unified Wazuh Event Schema:**

```python
# Data normalization engine
class EventNormalizer:
    def normalize_event(self, raw_event, source_type):
        """Normalize different log formats to unified schema"""
        
        normalized = {
            'timestamp': None,
            'source': {'type': source_type, 'host': None},
            'user': {'name': None, 'id': None},
            'process': {'name': None, 'pid': None},
            'network': {'srcip': None, 'dstip': None, 'protocol': None},
            'file': {'path': None, 'hash': None},
            'action': None,
            'result': None
        }
        
        if source_type == 'windows_eventlog':
            normalized.update(self._normalize_windows(raw_event))
        elif source_type == 'linux_syslog':
            normalized.update(self._normalize_linux(raw_event))
        elif source_type == 'zeek_conn':
            normalized.update(self._normalize_zeek(raw_event))
        elif source_type == 'aws_cloudtrail':
            normalized.update(self._normalize_aws(raw_event))
        
        return normalized
    
    def _normalize_windows(self, event):
        """Extract fields from Windows Event Log"""
        return {
            'timestamp': event['System']['TimeCreated']['@SystemTime'],
            'source': {
                'type': 'windows',
                'host': event['System']['Computer']
            },
            'user': {
                'name': event['EventData']['TargetUserName'],
                'id': event['EventData']['TargetUserSid']
            },
            'action': event['System']['EventID'],
            'result': 'success' if event['System']['EventID'] == '4624' else 'failure'
        }
    
    def _normalize_linux(self, event):
        """Extract fields from Linux syslog"""
        return {
            'timestamp': event['timestamp'],
            'source': {
                'type': 'linux',
                'host': event['hostname']
            },
            'user': {
                'name': event.get('user'),
                'id': event.get('uid')
            },
            'process': {
                'name': event.get('program'),
                'pid': event.get('pid')
            }
        }
    
    def _normalize_zeek(self, event):
        """Extract fields from Zeek connection logs"""
        return {
            'timestamp': event['ts'],
            'source': {
                'type': 'network',
                'host': event.get('id.orig_h')
            },
            'network': {
                'srcip': event['id.orig_h'],
                'dstip': event['id.resp_h'],
                'srcport': event['id.orig_p'],
                'dstport': event['id.resp_p'],
                'protocol': event['proto']
            },
            'action': 'connection',
            'result': event.get('conn_state')
        }
```

**Wazuh Decoder Configuration for Normalization:**

```xml
<!-- Custom decoder for non-standard logs -->
<decoder name="custom-app-json">
  <program_name>custom-app</program_name>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>

<decoder name="custom-app-json">
  <parent>custom-app-json</parent>
  <json_decoder>user.name</json_decoder>
  <field name="srcuser">$.user.name</field>
</decoder>

<decoder name="custom-app-json">
  <parent>custom-app-json</parent>
  <json_decoder>network.srcip</json_decoder>
  <field name="srcip">$.network.srcip</field>
</decoder>
```

**3.5b Entity Resolution:**

**Challenge:** Same entity appears differently across platforms:
- User: `DOMAIN\jsmith`, `jsmith@company.com`, `jsmith`, UID `1001`
- Host: `SERVER01`, `server01.company.com`, `192.168.1.100`
- Process: `C:\Windows\System32\cmd.exe`, `cmd.exe`, PID `1234`

**Solution - Entity Resolution Service:**

```python
class EntityResolver:
    def __init__(self, entity_db):
        self.entity_db = entity_db  # Central entity database
    
    def resolve_user(self, raw_username, source_type):
        """Resolve user identity across platforms"""
        
        # Normalize username format
        username = self._normalize_username(raw_username, source_type)
        
        # Query entity database
        canonical_user = self.entity_db.query({
            'type': 'user',
            'aliases': username
        })
        
        if canonical_user:
            return {
                'canonical_id': canonical_user['id'],
                'canonical_name': canonical_user['preferred_name'],
                'email': canonical_user['email'],
                'department': canonical_user['department'],
                'risk_score': canonical_user['risk_score']
            }
        
        # Create new entity if not found
        return self._create_new_user_entity(username)
    
    def _normalize_username(self, username, source_type):
        """Normalize username based on source"""
        if source_type == 'windows':
            # DOMAIN\username -> username
            return username.split('\\')[-1].lower()
        elif source_type == 'linux':
            # Already lowercase, return as-is
            return username.lower()
        elif source_type == 'email':
            # user@domain.com -> user
            return username.split('@')[0].lower()
        return username.lower()
    
    def resolve_host(self, raw_hostname, ip_address=None):
        """Resolve host identity"""
        
        # Try DNS resolution
        if ip_address:
            resolved_hostname = self._reverse_dns_lookup(ip_address)
        else:
            resolved_hostname = raw_hostname
        
        # Normalize hostname
        canonical_hostname = resolved_hostname.split('.')[0].upper()
        
        # Query asset database
        asset = self.entity_db.query({
            'type': 'host',
            'hostname': canonical_hostname,
            'ip': ip_address
        })
        
        if asset:
            return {
                'canonical_id': asset['id'],
                'hostname': asset['hostname'],
                'ip_addresses': asset['ip_addresses'],
                'asset_type': asset['type'],
                'criticality': asset['criticality'],
                'owner': asset['owner']
            }
        
        return {'canonical_id': None, 'hostname': canonical_hostname}
```

**Entity Resolution Example in Wazuh:**

```xml
<!-- Wazuh rule using entity resolution -->
<rule id="200400" level="8">
  <if_sid>5715</if_sid>
  <field name="normalized_user">jsmith</field>
  <same_normalized_user />
  <different_hostname />
  <frequency>3</frequency>
  <timeframe>300</timeframe>
  <description>User $(normalized_user) accessing multiple hosts - potential lateral movement</description>
  <mitre>
    <id>T1021</id>
  </mitre>
</rule>
```

**3.5c Contextual Alignment:**

**Challenge:** Understanding context requires knowledge of:
- Business operations (normal vs abnormal)
- Asset importance (critical server vs test system)
- User behavior (admin vs standard user)
- Threat landscape (current campaigns, TTPs)

**Solution - Multi-Layer Context Engine:**

```python
class ContextEngine:
    def __init__(self, asset_db, misp_client, behavioral_baselines):
        self.asset_db = asset_db
        self.misp = misp_client
        self.baselines = behavioral_baselines
    
    def build_alert_context(self, alert):
        """Enrich alert with comprehensive context"""
        
        context = {
            'asset_context': {},
            'user_context': {},
            'threat_context': {},
            'behavioral_context': {},
            'business_context': {}
        }
        
        # Asset context
        if alert.get('agent'):
            asset = self.asset_db.get_asset(alert['agent']['name'])
            context['asset_context'] = {
                'criticality': asset['criticality'],  # Critical/High/Medium/Low
                'asset_type': asset['type'],  # Server/Workstation/Network Device
                'business_function': asset['business_function'],
                'compliance_scope': asset['compliance_scope'],  # PCI-DSS, HIPAA, etc.
                'data_classification': asset['data_classification']
            }
        
        # User context
        if alert.get('data', {}).get('srcuser'):
            user = self.entity_db.get_user(alert['data']['srcuser'])
            context['user_context'] = {
                'department': user['department'],
                'is_privileged': user['is_admin'],
                'risk_score': user['risk_score'],  # Based on past behavior
                'normal_work_hours': user['work_schedule']
            }
        
        # Threat intelligence context
        if alert.get('data', {}).get('srcip'):
            misp_results = self.misp.search(value=alert['data']['srcip'])
            if misp_results:
                context['threat_context'] = {
                    'known_malicious': True,
                    'threat_types': self._extract_threat_types(misp_results),
                    'associated_campaigns': self._extract_campaigns(misp_results),
                    'attribution': self._extract_attribution(misp_results),
                    'first_seen': self._get_first_seen(misp_results),
                    'confidence': self._calculate_confidence(misp_results)
                }
        
        # Behavioral context
        baseline = self.baselines.get_user_baseline(alert['data'].get('srcuser'))
        context['behavioral_context'] = {
            'deviation_score': self._calculate_deviation(alert, baseline),
            'is_anomalous_time': self._check_time_anomaly(alert, baseline),
            'is_anomalous_volume': self._check_volume_anomaly(alert, baseline),
            'similar_past_events': baseline.get('similar_events', 0)
        }
        
        # Business context
        context['business_context'] = {
            'is_business_hours': self._is_business_hours(alert['timestamp']),
            'is_holiday': self._is_holiday(alert['timestamp']),
            'is_maintenance_window': self._is_maintenance_window(
                alert['agent']['name'],
                alert['timestamp']
            )
        }
        
        return context
    
    def calculate_contextual_risk(self, alert, context):
        """Calculate risk score based on all context"""
        
        base_risk = alert['rule']['level']
        
        # Asset criticality multiplier
        criticality_multiplier = {
            'Critical': 2.0,
            'High': 1.5,
            'Medium': 1.0,
            'Low': 0.7
        }
        base_risk *= criticality_multiplier.get(
            context['asset_context'].get('criticality', 'Medium')
        )
        
        # Threat intelligence multiplier
        if context['threat_context'].get('known_malicious'):
            base_risk *= 1.8
        
        # Behavioral anomaly multiplier
        if context['behavioral_context'].get('deviation_score', 0) > 0.7:
            base_risk *= 1.5
        
        # Business context adjustment
        if not context['business_context']['is_business_hours']:
            base_risk *= 1.3  # After-hours activity is more suspicious
        
        if context['business_context']['is_maintenance_window']:
            base_risk *= 0.5  # Maintenance window reduces suspicion
        
        return min(base_risk, 10.0)  # Cap at 10
```

**Contextual Correlation Example:**

```mermaid
graph TD
    A[Raw Alert: SSH Login] --> B{Context Engine}
    B --> C[Asset DB: Server Criticality = High]
    B --> D[User DB: After-hours = Anomalous]
    B --> E[MISP: Source IP = Known Scanner]
    B --> F[Baseline: First time from this IP]
    
    C --> G[Context Enrichment]
    D --> G
    E --> G
    F --> G
    
    G --> H[Risk Score: 9.5/10]
    H --> I[High Priority Alert]
    I --> J[Automated Response]
    I --> K[SOC Investigation]
```

**Implementation in Wazuh Rules:**

```xml
<!-- Rule leveraging contextual data -->
<rule id="200500" level="5">
  <if_sid>5715</if_sid>
  <description>SSH login detected</description>
  <group>authentication</group>
</rule>

<!-- Contextual escalation based on asset criticality -->
<rule id="200501" level="8">
  <if_sid>200500</if_sid>
  <field name="asset_criticality">Critical|High</field>
  <description>SSH login to critical asset</description>
</rule>

<!-- Further escalation based on MISP IOC match -->
<rule id="200502" level="12">
  <if_sid>200501</if_sid>
  <list field="srcip" lookup="misp_malicious_ips">misp_iocs</list>
  <description>Critical: SSH login to critical asset from known malicious IP</description>
  <group>misp_match,lateral_movement</group>
</rule>
```

**Cross-Platform Correlation Dashboard:**

```json
{
  "correlation_summary": {
    "alert_id": "2025-10-02-12345",
    "correlation_chain": [
      {
        "platform": "Windows",
        "event": "Multiple failed logins",
        "timestamp": "2025-10-02T14:28:00Z"
      },
      {
        "platform": "Linux",
        "event": "Successful SSH login",
        "timestamp": "2025-10-02T14:30:15Z",
        "correlation": "Same username after Windows failures"
      },
      {
        "platform": "Zeek",
        "event": "SMB traffic to file server",
        "timestamp": "2025-10-02T14:31:45Z",
        "correlation": "Same source IP as SSH login"
      }
    ],
    "entity_resolution": {
      "canonical_user": "jsmith",
      "aliases": ["DOMAIN\\jsmith", "jsmith@company.com", "jsmith"],
      "resolved_host": "SERVER01",
      "host_aliases": ["server01", "192.168.1.100"]
    },
    "threat_intelligence": {
      "misp_match": true,
      "campaign": "APT29 Lateral Movement",
      "confidence": 85
    },
    "contextual_risk": 9.2,
    "recommended_action": "Immediate isolation and investigation"
  }
}
```

---

## 3.6 Develop custom analytics plan for mock enterprise

**Custom Analytics Framework for GlobalTech Corp:**

**3.6a Use Case Definition:**

| Use Case ID | Name | Business Driver | Security Objective | Data Sources |
|------------|------|-----------------|-------------------|--------------|
| **UC-001** | Insider Threat Detection | Protect intellectual property | Detect anomalous data access | Windows Event Logs, File Servers, DLP |
| **UC-002** | Lateral Movement Detection | Prevent ransomware spread | Identify privilege escalation patterns | AD logs, SMB traffic, Wazuh agents |
| **UC-003** | Cloud Account Compromise | Secure cloud infrastructure | Detect suspicious cloud API usage | AWS CloudTrail, Azure Activity Logs |
| **UC-004** | Data Exfiltration | Compliance (PCI-DSS) | Identify large data transfers | Network traffic (Zeek), Proxy logs |
| **UC-005** | Supply Chain Attack | Third-party risk management | Monitor vendor access patterns | VPN logs, Application logs |

**Detailed Use Case: Insider Threat Detection (UC-001)**

```python
class InsiderThreatAnalytics:
    """
    Detect anomalous data access patterns indicative of insider threats
    """
    
    def __init__(self, wazuh_api, misp_client):
        self.wazuh = wazuh_api
        self.misp = misp_client
        self.risk_factors = []
    
    def analyze_user_file_access(self, username, timeframe='7d'):
        """Detect unusual file access patterns"""
        
        # Collect file access events
        query = f'data.dstuser:{username} AND rule.id:(550|553|554)'
        events = self.wazuh.search(query=query, timeframe=timeframe)
        
        # Extract features
        features = {
            'unique_files_accessed': set(),
            'sensitive_files': [],
            'access_times': [],
            'access_volumes': [],
            'file_types': {}
        }
        
        for event in events:
            file_path = event['data'].get('file_path')
            timestamp = event['timestamp']
            
            features['unique_files_accessed'].add(file_path)
            features['access_times'].append(timestamp)
            
            # Check if sensitive file
            if self._is_sensitive_file(file_path):
                features['sensitive_files'].append(file_path)
            
            # Track file types
            file_ext = file_path.split('.')[-1]
            features['file_types'][file_ext] = \
                features['file_types'].get(file_ext, 0) + 1
        
        # Calculate risk indicators
        risk_score = 0
        
        # Risk Factor 1: High volume of unique files
        if len(features['unique_files_accessed']) > 100:
            risk_score += 3
            self.risk_factors.append('High volume of unique file access')
        
        # Risk Factor 2: Sensitive file access
        if len(features['sensitive_files']) > 5:
            risk_score += 5
            self.risk_factors.append('Multiple sensitive file access')
        
        # Risk Factor 3: After-hours access
        after_hours_count = sum(
            1 for t in features['access_times']
            if self._is_after_hours(t)
        )
        if after_hours_count > 20:
            risk_score += 4
            self.risk_factors.append('Significant after-hours activity')
        
        # Risk Factor 4: Unusual file types
        if 'zip' in features['file_types'] or 'rar' in features['file_types']:
            risk_score += 3
            self.risk_factors.append('Compression file creation')
        
        return {
            'user': username,
            'risk_score': risk_score,
            'risk_level': self._categorize_risk(risk_score),
            'risk_factors': self.risk_factors,
            'features': {
                'unique_files': len(features['unique_files_accessed']),
                'sensitive_files': len(features['sensitive_files']),
                'after_hours_events': after_hours_count
            }
        }
    
    def _is_sensitive_file(self, file_path):
        """Determine if file contains sensitive data"""
        sensitive_patterns = [
            '/finance/', '/hr/', '/payroll/',
            'confidential', 'secret', 'customer_data'
        ]
        return any(pattern in file_path.lower() 
                  for pattern in sensitive_patterns)
    
    def _categorize_risk(self, score):
        if score >= 10:
            return 'Critical'
        elif score >= 7:
            return 'High'
        elif score >= 4:
            return 'Medium'
        return 'Low'
```

**3.6b Development Methodology:**

**Phase 1: Requirements Gathering (Weeks 1-2)**

```yaml
activities:
  - stakeholder_interviews:
      participants:
        - CISO
        - SOC Manager
        - Compliance Officer
        - Business Unit Leads
      outcomes:
        - Priority use cases identified
        - Success criteria defined
        - Resource requirements estimated
        
  - data_source_assessment:
      inventory:
        - Existing log sources
        - Coverage gaps
        - Data quality issues
      outputs:
        - Data source matrix
        - Integration requirements
        - Retention policies
```

**Phase 2: Analytics Development (Weeks 3-8)**

```python
# Development workflow for each use case

class AnalyticsDevelopmentWorkflow:
    def __init__(self, use_case):
        self.use_case = use_case
        self.stages = []
    
    def stage1_hypothesis_definition(self):
        """Define detection hypothesis"""
        hypothesis = {
            'threat_scenario': self.use_case.description,
            'indicators': [],  # Observable behaviors
            'thresholds': {},  # Statistical thresholds
            'false_positive_factors': []  # Known FP sources
        }
        
        # Example for lateral movement:
        if self.use_case.id == 'UC-002':
            hypothesis['indicators'] = [
                'Same user authenticating to multiple hosts',
                'Privilege escalation after initial access',
                'SMB traffic to file shares'
            ]
            hypothesis['thresholds'] = {
                'unique_hosts': 3,
                'timeframe': 300,  # 5 minutes
                'privilege_actions': 1
            }
        
        return hypothesis
    
    def stage2_data_collection(self):
        """Collect historical data for testing"""
        data_sources = {
            'wazuh_events': self._collect_wazuh_events(),
            'zeek_logs': self._collect_zeek_logs(),
            'labeled_incidents': self._collect_past_incidents()
        }
        return data_sources
    
    def stage3_algorithm_development(self, data):
        """Develop detection algorithm"""
        # Implement detection logic
        detector = LateralMovementDetector()
        
        # Train on historical data
        detector.train(data['labeled_incidents'])
        
        # Validate accuracy
        accuracy = detector.validate(data['wazuh_events'])
        
        return detector, accuracy
    
    def stage4_tuning(self, detector, validation_data):
        """Tune thresholds to minimize false positives"""
        best_params = self._grid_search_thresholds(
            detector,
            validation_data,
            target_fpr=0.05  # 5% false positive rate
        )
        
        detector.update_params(best_params)
        return detector
    
    def stage5_integration(self, detector):
        """Integrate with Wazuh"""
        # Generate Wazuh rules
        wazuh_rules = detector.to_wazuh_rules()
        
        # Deploy to test environment
        self._deploy_to_test(wazuh_rules)
        
        # Monitor for 2 weeks
        performance = self._monitor_performance(days=14)
        
        return performance
```

**Phase 3: Testing & Validation (Weeks 9-10)**

```python
class AnalyticsValidator:
    def validate_use_case(self, use_case, detector):
        """Comprehensive validation framework"""
        
        validation_results = {
            'accuracy_metrics': {},
            'performance_metrics': {},
            'operational_metrics': {}
        }
        
        # 1. Accuracy Testing
        test_data = self._prepare_test_dataset()
        validation_results['accuracy_metrics'] = {
            'true_positive_rate': detector.calculate_tpr(test_data),
            'false_positive_rate': detector.calculate_fpr(test_data),
            'precision': detector.calculate_precision(test_data),
            'recall': detector.calculate_recall(test_data),
            'f1_score': detector.calculate_f1(test_data)
        }
        
        # 2. Performance Testing
        validation_results['performance_metrics'] = {
            'avg_detection_time': self._measure_detection_time(detector),
            'max_processing_latency': self._measure_latency(detector),
            'resource_usage': self._measure_resources(detector)
        }
        
        # 3. Operational Testing
        validation_results['operational_metrics'] = {
            'alert_volume': self._measure_alert_volume(detector, days=7),
            'analyst_feedback': self._collect_analyst_feedback(),
            'integration_stability': self._test_integration_stability()
        }
        
        # Determine if use case passes validation
        validation_results['passed'] = self._evaluate_criteria(
            validation_results
        )
        
        return validation_results
    
    def _evaluate_criteria(self, results):
        """Check against success criteria"""
        criteria = {
            'min_precision': 0.80,  # 80% of alerts must be true positives
            'max_fpr': 0.05,  # Less than 5% false positive rate
            'max_detection_time': 300,  # Under 5 minutes
            'max_alert_volume': 50  # Under 50 alerts per day per use case
        }
        
        return (
            results['accuracy_metrics']['precision'] >= criteria['min_precision'] and
            results['accuracy_metrics']['false_positive_rate'] <= criteria['max_fpr'] and
            results['performance_metrics']['avg_detection_time'] <= criteria['max_detection_time'] and
            results['operational_metrics']['alert_volume'] <= criteria['max_alert_volume']
        )
```

**3.6c Implementation Approach:**

**Implementation Architecture:**

```mermaid
graph TB
    subgraph "Development Environment"
        A[Analytics Workstation] --> B[Test Wazuh Instance]
        A --> C[Sample Data Lake]
        B --> D[Test MISP Instance]
    end
    
    subgraph "Staging Environment"
        E[Staging Wazuh Cluster] --> F[Subset of Production Data]
        E --> G[Staging MISP]
        F --> H[Validation Dashboard]
    end
    
    subgraph "Production Environment"
        I[Production Wazuh Cluster] --> J[Full Production Data]
        I --> K[Production MISP]
        J --> L[SOC Dashboard]
        L --> M[Alert Queue]
    end
    
    B -->|Validated Rules| E
    E -->|Approved Rules| I
```

**Deployment Pipeline:**

```yaml
# CI/CD pipeline for analytics deployment
analytics_pipeline:
  stage_1_development:
    - write_detection_logic
    - unit_tests
    - code_review
    
  stage_2_validation:
    - deploy_to_test_environment
    - run_automated_tests:
        - accuracy_tests
        - performance_tests
        - integration_tests
    - manual_validation:
        - soc_analyst_review
        - false_positive_analysis
    
  stage_3_staging:
    - deploy_to_staging:
        duration: 2_weeks
        monitoring: continuous
    - collect_metrics:
        - alert_volume
        - detection_rate
        - false_positive_rate
    - stakeholder_approval_required: true
    
  stage_4_production:
    - phased_rollout:
        phase_1: 
          duration: 1_week
          coverage: 20%
        phase_2:
          duration: 1_week
          coverage: 50%
        phase_3:
          duration: 1_week
          coverage: 100%
    - monitoring:
        - real_time_performance
        - analyst_feedback
        - incident_correlation
    
  stage_5_optimization:
    - continuous_tuning
    - quarterly_review
    - annual_revalidation
```

**Implementation Code Example:**

```python
# Deployment automation script
class AnalyticsDeployment:
    def __init__(self, environment):
        self.environment = environment
        self.wazuh_api = self._init_wazuh_api(environment)
    
    def deploy_use_case(self, use_case, detector):
        """Deploy analytics use case to Wazuh"""
        
        # 1. Generate Wazuh rules
        rules = detector.generate_wazuh_rules()
        
        # 2. Backup existing rules
        self._backup_current_rules()
        
        # 3. Deploy new rules
        try:
            for rule in rules:
                self.wazuh_api.add_rule(rule)
            
            # 4. Restart Wazuh manager
            self.wazuh_api.restart_manager()
            
            # 5. Verify deployment
            self._verify_rules_active(rules)
            
            # 6. Configure alerting
            self._configure_alert_routing(use_case)
            
            # 7. Update documentation
            self._update_runbook(use_case, rules)
            
            return {
                'status': 'success',
                'rules_deployed': len(rules),
                'environment': self.environment
            }
            
        except Exception as e:
            # Rollback on error
            self._rollback_deployment()
            return {
                'status': 'failed',
                'error': str(e)
            }
    
    def _configure_alert_routing(self, use_case):
        """Configure how alerts are routed to SOC"""
        routing_config = {
            'use_case_id': use_case.id,
            'severity_routing': {
                'Critical': ['soc_l3_team', 'siem_alerts_critical'],
                'High': ['soc_l2_team', 'siem_alerts_high'],
                'Medium': ['soc_l1_team', 'siem_alerts_medium'],
                'Low': ['automated_triage']
            },
            'notification_channels': {
                'email': use_case.notification_emails,
                'slack': use_case.slack_channel,
                'pagerduty': use_case.oncall_rotation
            }
        }
        
        self.wazuh_api.configure_routing(routing_config)
```

**Success Metrics & KPIs:**

| Metric | Target | Measurement Method | Review Frequency |
|--------|--------|-------------------|------------------|
| **Detection Accuracy** | >90% TPR, <5% FPR | Weekly validation against known incidents | Weekly |
| **Mean Time to Detect** | <5 minutes for critical threats | Automated timestamp analysis | Daily |
| **Alert Quality** | >80% actionable alerts | SOC analyst feedback | Weekly |
| **Coverage** | >95% of attack techniques | MITRE ATT&CK mapping | Monthly |
| **Analyst Efficiency** | <15 min average investigation time | SIEM metrics | Weekly |
| **False Positive Trend** | Decreasing month-over-month | Alert disposition tracking | Monthly |

**Operational Runbook:**

```markdown
# Analytics Use Case Runbook: UC-002 Lateral Movement Detection

## Overview
- **Use Case ID:** UC-002
- **Analyst Team:** SOC L2
- **Severity:** High
- **MITRE ATT&CK:** T1021

## Alert Response Procedure

1. **Initial Triage (0-5 minutes)**
   - Review alert details in Wazuh dashboard
   - Check MISP for IOC matches
   - Verify user identity and asset criticality

2. **Investigation (5-15 minutes)**
   - Query additional logs for user activity
   - Check for privilege escalation events
   - Review network traffic to/from affected hosts
   - Consult behavioral baseline for anomalies

3. **Containment (15-30 minutes)**
   - If malicious: Isolate affected endpoints
   - Disable compromised user account
   - Block malicious IPs in firewall
   - Notify incident response team

4. **Documentation**
   - Update MISP with new IOCs
   - Create incident ticket
   - Document timeline of events
```

---

**Implementation Timeline:**

```gantt
title Custom Analytics Implementation
dateFormat YYYY-MM-DD
section Planning
Requirements Gathering    :done, req, 2025-10-01, 14d
Use Case Prioritization   :done, prio, after req, 7d
section Development
UC-001 Development        :active, uc1, 2025-10-22, 21d
UC-002 Development        :uc2, after uc1, 21d
UC-003 Development        :uc3, after uc2, 21d
section Testing
UC-001 Validation         :test1, after uc1, 14d
UC-002 Validation         :test2, after uc2, 14d
UC-003 Validation         :test3, after uc3, 14d
section Deployment
Staging Deployment        :stage, after test1, 14d
Production Rollout        :prod, after stage, 21d
section Operations
Continuous Monitoring     :monitor, after prod, 30d
Optimization & Tuning     :opt, after prod, 90d
```

---

## 4. Enterprise Architecture Design
- [ ] **4.1** Create a detailed enterprise monitoring architecture design for a mock global organization.  
- [ ] **4.2** Apply appropriate architecture patterns:  
    - [ ] **4.2a** Hierarchical  
    - [ ] **4.2b** Hub-and-spoke  
    - [ ] **4.2c** Microservices  
- [ ] **4.3** Define component placement, communication flows, and scalability considerations.  
- [ ] **4.4** Provide comprehensive **architecture diagrams** with network placement, data flows, and component relationships.  
- [ ] **4.5** Outline health monitoring approach:  
    - [ ] **4.5a** Monitoring points  
    - [ ] **4.5b** Metrics  
    - [ ] **4.5c** Alerting thresholds  
- [ ] **4.6** Develop a capacity planning model including:  
    - [ ] **4.6a** Current state assessment  
    - [ ] **4.6b** Growth forecasting  
    - [ ] **4.6c** Expansion scenarios  

---

## 5. Detection Strategy Development
- [ ] **5.1** Develop a behavioral analysis strategy for the mock enterprise.  
- [ ] **5.2** Include approaches for:  
    - [ ] **5.2a** User Behavior Analytics (UBA)  
    - [ ] **5.2b** Network Behavior Analytics (NBA)  
- [ ] **5.3** Outline baselining methodology:  
    - [ ] **5.3a** Data collection requirements  
    - [ ] **5.3b** Business cycle considerations  
    - [ ] **5.3c** Seasonal variation handling  
- [ ] **5.4** Install and configure basic log analysis tools (Elastic Stack or Splunk) with screenshots of dashboard creation.  
- [ ] **5.5** Create detection use cases for **three threat scenarios** including:  
    - [ ] **5.5a** Required data sources  
    - [ ] **5.5b** Detection logic  
    - [ ] **5.5c** Expected outputs  
- [ ] **5.6** Address false positive management with:  
    - [ ] **5.6a** Tuning methodology  
    - [ ] **5.6b** Effectiveness metrics  

---

## 6. Operational Framework Design
- [ ] **6.1** Document comprehensive operational procedures for security monitoring.  
- [ ] **6.2** Create SOPs for:  
    - [ ] **6.2a** System maintenance  
    - [ ] **6.2b** Incident response  
    - [ ] **6.2c** Detection tuning  
    - [ ] **6.2d** Health monitoring  
- [ ] **6.3** Define roles and responsibilities with workflow diagrams.  
- [ ] **6.4** Create a governance framework covering:  
    - [ ] **6.4a** Access management  
    - [ ] **6.4b** Automation limitations  
    - [ ] **6.4c** Data handling  
    - [ ] **6.4d** Compliance requirements  
- [ ] **6.5** Define performance measurement approach including:  
    - [ ] **6.5a** Metrics  
    - [ ] **6.5b** Benchmarking methodology  
    - [ ] **6.5c** Reporting templates  
- [ ] **6.6** Outline ITSM integration with:  
    - [ ] **6.6a** Change management procedures  
    - [ ] **6.6b** Incident workflows  
    - [ ] **6.6c** Escalation paths  
- [ ] **6.7** Develop an implementation roadmap including:  
    - [ ] **6.7a** Phased approach  
    - [ ] **6.7b** Milestone definitions  
    - [ ] **6.7c** Validation testing methodology  
