
# SecureChain Test Environment

This test environment provides realistic vulnerability scenarios for testing the complete SecureChain pipeline.

## Test Data Files

### 1. realistic_scan_data.json
- Comprehensive network scan results
- Multiple hosts with various vulnerabilities
- Realistic service versions and configurations

### 2. opencti_sample_data.json
- Sample threat intelligence data
- CVE mappings to threat actors
- MITRE ATT&CK technique associations

### 3. attack_scenarios.json
- Realistic attack scenarios
- Multi-step attack chains
- MITRE ATT&CK technique mappings

### 4. normalized_findings.json
- Normalized vulnerability findings
- Ready for ingestion into SecureChain backend
- Includes asset classification and risk scoring

## Test Targets

### Web Server (192.168.1.100)
- **Vulnerabilities**: CVE-2021-44228 (Log4j), CVE-2021-41773 (Apache)
- **Services**: HTTP (80), HTTPS (443), SSH (22)
- **Risk Level**: Critical

### Database Server (192.168.1.200)
- **Vulnerabilities**: CVE-2020-14867 (MySQL)
- **Services**: MySQL (3306), SSH (22)
- **Risk Level**: High

### Jump Server (192.168.1.150)
- **Vulnerabilities**: CVE-2018-15473 (SSH)
- **Services**: SSH (22)
- **Risk Level**: Medium

### File Server (192.168.1.180)
- **Vulnerabilities**: CVE-2011-2523 (vsftpd), CVE-2017-0144 (EternalBlue)
- **Services**: FTP (21), SMB (445)
- **Risk Level**: Critical

### Admin Workstation (192.168.1.50)
- **Vulnerabilities**: CVE-2019-0708 (BlueKeep)
- **Services**: RDP (3389)
- **Risk Level**: Critical

## Attack Scenarios

### 1. Web-to-Database Lateral Movement
1. Exploit Log4j vulnerability in web server
2. Perform network discovery
3. Lateral movement to database server via SSH
4. Privilege escalation using MySQL vulnerability
5. Data exfiltration

### 2. RDP Admin Compromise
1. Exploit BlueKeep RDP vulnerability
2. Establish persistence
3. Credential dumping
4. Domain enumeration

### 3. FTP-to-SMB Worm Propagation
1. Exploit vsftpd backdoor
2. Network scanning for SMB services
3. EternalBlue exploitation
4. Self-replication

## Usage Instructions

### 1. AI Vulnerability Scanner Test
```bash
python AI-Vuln-Scanner/vulnscanner.py -t scanme.nmap.org -p 1 -o json
```

### 2. Attack Graph Generation Test
```bash
python attackGraph/attack_graph_generator.py
```

### 3. Backend Integration Test
```bash
python backend/test_backend_with_data.py
```

### 4. Comprehensive Pipeline Test
```bash
python comprehensive_pipeline_test.py
```

### 5. Chatbot Testing
```bash
python test_chatbot_vulnerabilities.py
```

## Expected Results

- **AI Scanner**: Should identify vulnerabilities and generate analysis
- **OpenCTI**: Should enrich findings with threat intelligence
- **Attack Graph**: Should generate visual attack paths
- **Backend**: Should store and retrieve findings
- **Chatbot**: Should answer vulnerability-related questions

## Troubleshooting

### Common Issues
1. **Scanner fails**: Check target accessibility and permissions
2. **OpenCTI connection**: Verify OpenCTI is running and accessible
3. **Database errors**: Check PostgreSQL and Neo4j connections
4. **Chatbot unresponsive**: Verify chatbot service is running

### Log Files
- `pipeline_test.log`: Comprehensive test execution log
- `chatbot_test_results.json`: Detailed chatbot test results
- `attack_graph_test.json`: Attack graph analysis results

## Security Note

This test environment contains intentionally vulnerable configurations.
**DO NOT** deploy in production environments.
Use only for testing and educational purposes.
