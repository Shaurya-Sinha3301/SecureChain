# OpenCTI Usefulness Demonstration Scripts

These scripts demonstrate the real-world value and practical applications of OpenCTI for threat intelligence operations.

## 📁 Available Scripts

### 1. Comprehensive Demo (`opencti_usefulness_demo.py`)
**Purpose:** Full-featured demonstration showing OpenCTI's complete threat intelligence lifecycle

**Features:**
- Creates realistic threat landscape with actors, malware, indicators, and incidents
- Establishes relationships between threat entities
- Demonstrates threat hunting capabilities
- Generates comprehensive threat intelligence reports
- Shows search and discovery features
- Includes cleanup functionality

**Usage:**
```bash
# Run complete demonstration
python opencti_usefulness_demo.py --token "YOUR_TOKEN"

# Save results and skip cleanup
python opencti_usefulness_demo.py --token "YOUR_TOKEN" --no-cleanup --output demo_results.json

# Custom URL
python opencti_usefulness_demo.py --url "http://localhost:8080" --token "YOUR_TOKEN"
```

### 2. Practical Use Cases Demo (`opencti_practical_demo.py`)
**Purpose:** Focused on day-to-day security operations scenarios

**Features:**
- IOC reputation checking
- Bulk threat analysis
- Incident response enrichment
- Threat hunting workflows
- Business value demonstration

**Usage:**
```bash
# Run practical scenarios
python opencti_practical_demo.py --token "YOUR_TOKEN"

# Save results
python opencti_practical_demo.py --token "YOUR_TOKEN" --output practical_results.json
```

## 🎯 Demonstration Scenarios

### Comprehensive Demo Scenarios

#### 1. **Building Threat Landscape**
- Creates threat actors (APT29, Lazarus Group)
- Adds malware families (Emotet, Cobalt Strike)
- Establishes indicators of compromise
- Creates security incidents

#### 2. **Establishing Relationships**
- Links threat actors to their tools
- Connects malware to indicators
- Associates incidents with threat actors
- Maps attack patterns

#### 3. **Threat Hunting Simulation**
- Searches for specific IOCs
- Identifies related threats
- Provides actionable recommendations
- Demonstrates investigation workflow

#### 4. **Intelligence Reporting**
- Generates comprehensive threat reports
- Analyzes threat landscape density
- Provides coverage metrics
- Summarizes threat posture

#### 5. **Search and Discovery**
- Demonstrates search capabilities
- Shows pattern matching
- Tests query performance
- Validates data retrieval

### Practical Demo Scenarios

#### 1. **IOC Reputation Check**
```python
# Example: Check if an IP is malicious
result = demo.check_ioc_reputation("192.168.1.100", "ip")
```

#### 2. **Bulk IOC Analysis**
```python
# Example: Analyze multiple IOCs at once
iocs = [
    {"value": "evil-domain.com", "type": "domain"},
    {"value": "malicious-hash", "type": "hash"}
]
results = demo.bulk_ioc_check(iocs)
```

#### 3. **Incident Enrichment**
```python
# Example: Enrich incident with threat intelligence
incident_iocs = ["suspicious-ip", "malware-hash", "c2-domain"]
enrichment = demo.simulate_incident_enrichment(incident_iocs)
```

#### 4. **Threat Hunting Workflow**
```python
# Example: Complete hunting session
hunting_results = demo.demonstrate_threat_hunting_workflow()
```

## 🚀 Quick Start

### Prerequisites
1. OpenCTI running on localhost:8080 (or your configured URL)
2. Valid API token
3. Python 3.7+ with requests library

### Get Your Token
```bash
# From your environment file
cat SecureChain/docker/.env | grep OPENCTI_ADMIN_TOKEN
```

### Run Comprehensive Demo
```bash
python SecureChain/opencti_usefulness_demo.py --token "3b2641f7-3232-418c-8365-5454b3953143"
```

### Run Practical Demo
```bash
python SecureChain/opencti_practical_demo.py --token "3b2641f7-3232-418c-8365-5454b3953143"
```

## 📊 Expected Output Examples

### Comprehensive Demo Output
```
🚀 OPENCTI USEFULNESS DEMONSTRATION
================================================================================
📋 SCENARIO 1: BUILDING THREAT LANDSCAPE
--------------------------------------------------
🎭 Creating threat actor: APT29 (Cozy Bear)
✅ Created threat actor: APT29 (Cozy Bear) (ID: abc123...)
🦠 Creating malware: Emotet
✅ Created malware: Emotet (ID: def456...)
🎯 Creating indicator: [ipv4-addr:value = '192.168.1.100']
✅ Created indicator: [ipv4-addr:value = '192.168.1.100'] (ID: ghi789...)

📋 SCENARIO 2: ESTABLISHING THREAT RELATIONSHIPS
--------------------------------------------------
🔗 Creating relationship: uses
✅ Created relationship: uses (ID: jkl012...)

📋 SCENARIO 3: THREAT HUNTING SIMULATION
--------------------------------------------------
🎯 THREAT HUNTING DEMONSTRATION
Hunting for IOC: 192.168.1.100
============================================================
🚨 ALERT: Found 1 matching indicators!
📍 Indicator Details:
   Pattern: [ipv4-addr:value = '192.168.1.100']
   Type: malicious-activity
   Confidence: 80%
   Description: Command and control server for APT29 operations
🔗 Related Threat:
   Type: ThreatActor
   Name: APT29 (Cozy Bear)
   Relationship: indicates

💡 RECOMMENDATIONS:
   1. Block the identified IOC in security controls
   2. Search logs for historical presence of this IOC
   3. Investigate related threat actors and malware families
   4. Update threat hunting rules with new patterns
   5. Share intelligence with security team and partners
```

### Practical Demo Output
```
📋 SCENARIO 1: IOC REPUTATION CHECK
----------------------------------------
🔍 Checking reputation for ip: 192.168.1.100
🚨 MALICIOUS IOC DETECTED!
   Confidence: 85%
   Threat Types: malicious-activity
   Description: Known C2 server
   Associated Threats:
     - ThreatActor: APT29 (indicates)

📋 SCENARIO 2: BULK IOC ANALYSIS
----------------------------------------
🔍 BULK IOC REPUTATION CHECK
Checking 5 indicators...
==================================================
📊 BULK CHECK SUMMARY:
   Total IOCs Checked: 5
   Malicious IOCs Found: 2
   Clean IOCs: 3
   Threat Detection Rate: 40.0%
```

## 💡 Business Value Demonstrated

### Security Operations Benefits
- **Faster Threat Detection**: Automated IOC reputation checking
- **Enhanced Incident Response**: Rich context for security incidents
- **Proactive Threat Hunting**: Intelligence-driven hunting workflows
- **Reduced False Positives**: High-confidence threat attribution
- **Improved Decision Making**: Data-driven security operations

### Threat Intelligence Benefits
- **Centralized Intelligence**: Single source of truth for threat data
- **Relationship Mapping**: Understanding threat actor TTPs
- **Historical Analysis**: Tracking threat evolution over time
- **Collaborative Intelligence**: Sharing insights across teams
- **Automated Enrichment**: Context-aware threat analysis

### Operational Efficiency
- **Time Savings**: Automated threat analysis and reporting
- **Consistency**: Standardized threat intelligence processes
- **Scalability**: Handle large volumes of threat data
- **Integration**: API-driven integration with security tools
- **Reporting**: Executive and technical threat reports

## 🔧 Customization Options

### Adding Custom IOCs
```python
# Modify the scripts to test your own IOCs
custom_iocs = [
    {"value": "your-suspicious-ip", "type": "ip"},
    {"value": "your-domain.com", "type": "domain"},
    {"value": "your-file-hash", "type": "hash"}
]
```

### Custom Threat Scenarios
```python
# Create your own threat actors and malware
custom_actor = demo.create_threat_actor(
    "Your Threat Group", 
    "Description of the threat group"
)
```

### Integration Examples
```python
# Example: Integrate with SIEM
def check_siem_alerts():
    alerts = get_siem_alerts()  # Your SIEM integration
    for alert in alerts:
        reputation = demo.check_ioc_reputation(alert['ioc'], alert['type'])
        if reputation['is_malicious']:
            escalate_alert(alert, reputation)
```

## 🛠️ Troubleshooting

### Common Issues
1. **Authentication Errors**: Verify your API token is correct
2. **Connection Issues**: Ensure OpenCTI is running and accessible
3. **Permission Errors**: Check token has required permissions
4. **Data Creation Failures**: Verify GraphQL schema compatibility

### Debug Mode
Add debug output to scripts:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Manual Cleanup
If demo data isn't cleaned up automatically:
```bash
# Access OpenCTI web interface
# Go to Data → Entities
# Filter by creation date and delete demo entities
```

## 📈 Performance Metrics

The demonstrations track various metrics:
- **Entity Creation Speed**: Time to create threat entities
- **Query Performance**: Response times for searches
- **Relationship Mapping**: Time to establish connections
- **Bulk Analysis**: Throughput for multiple IOCs
- **Report Generation**: Time to compile intelligence reports

## 🔄 Continuous Improvement

### Extending the Demos
1. Add more threat actor profiles
2. Include additional malware families
3. Expand IOC types (URLs, email addresses, etc.)
4. Add MITRE ATT&CK framework integration
5. Include threat feed integration examples

### Real-World Integration
1. Connect to your SIEM platform
2. Integrate with threat feeds
3. Add automated reporting
4. Include incident response workflows
5. Build custom dashboards

## 📚 Additional Resources

- [OpenCTI Documentation](https://docs.opencti.io/)
- [STIX 2.1 Specification](https://docs.oasis-open.org/cti/stix/v2.1/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Threat Intelligence Best Practices](https://www.sans.org/white-papers/threat-intelligence/)

---

These demonstration scripts showcase OpenCTI's capabilities in real-world security scenarios, helping you understand the practical value of threat intelligence platforms in modern cybersecurity operations.