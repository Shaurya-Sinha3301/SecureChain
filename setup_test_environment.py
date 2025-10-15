#!/usr/bin/env python3
"""
Setup Test Environment for SecureChain Pipeline Testing
Creates realistic test scenarios with vulnerable services
"""

import os
import json
import subprocess
import logging
import time
from pathlib import Path
from typing import Dict, List, Any

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TestEnvironmentSetup:
    """Setup realistic test environment for vulnerability testing"""
    
    def __init__(self):
        self.test_data_dir = Path("test_data")
        self.test_data_dir.mkdir(exist_ok=True)
        
    def create_realistic_scan_data(self) -> Dict[str, Any]:
        """Create realistic vulnerability scan data for testing"""
        
        # Simulate a comprehensive network scan with various vulnerabilities
        scan_data = {
            "scan_metadata": {
                "scan_id": "test_scan_001",
                "timestamp": "2024-01-15T10:30:00Z",
                "scanner": "nmap",
                "target_range": "192.168.1.0/24",
                "scan_type": "comprehensive"
            },
            "hosts": {
                "192.168.1.100": {
                    "hostname": [{"name": "web-server-dmz.company.local"}],
                    "status": "up",
                    "ports": [
                        {
                            "portid": "80",
                            "protocol": "tcp",
                            "state": "open",
                            "service": {
                                "name": "http",
                                "product": "Apache httpd",
                                "version": "2.4.41",
                                "extrainfo": "(Ubuntu)"
                            },
                            "vulnerabilities": [
                                {
                                    "cve": "CVE-2021-44228",
                                    "cvss": 9.8,
                                    "severity": "Critical",
                                    "description": "Log4j Remote Code Execution",
                                    "evidence": "Log4j library detected in web application logs"
                                }
                            ]
                        },
                        {
                            "portid": "443",
                            "protocol": "tcp", 
                            "state": "open",
                            "service": {
                                "name": "https",
                                "product": "Apache httpd",
                                "version": "2.4.41"
                            },
                            "vulnerabilities": [
                                {
                                    "cve": "CVE-2021-41773",
                                    "cvss": 7.5,
                                    "severity": "High",
                                    "description": "Apache HTTP Server Path Traversal",
                                    "evidence": "Vulnerable Apache version detected"
                                }
                            ]
                        },
                        {
                            "portid": "22",
                            "protocol": "tcp",
                            "state": "open",
                            "service": {
                                "name": "ssh",
                                "product": "OpenSSH",
                                "version": "7.4"
                            },
                            "vulnerabilities": [
                                {
                                    "cve": "CVE-2018-15473",
                                    "cvss": 5.3,
                                    "severity": "Medium",
                                    "description": "SSH User Enumeration",
                                    "evidence": "SSH version vulnerable to user enumeration"
                                }
                            ]
                        }
                    ]
                },
                "192.168.1.200": {
                    "hostname": [{"name": "db-server-internal.company.local"}],
                    "status": "up",
                    "ports": [
                        {
                            "portid": "3306",
                            "protocol": "tcp",
                            "state": "open",
                            "service": {
                                "name": "mysql",
                                "product": "MySQL",
                                "version": "5.7.30"
                            },
                            "vulnerabilities": [
                                {
                                    "cve": "CVE-2020-14867",
                                    "cvss": 7.5,
                                    "severity": "High",
                                    "description": "MySQL Privilege Escalation",
                                    "evidence": "MySQL version with privilege escalation vulnerability"
                                }
                            ]
                        },
                        {
                            "portid": "22",
                            "protocol": "tcp",
                            "state": "open",
                            "service": {
                                "name": "ssh",
                                "product": "OpenSSH",
                                "version": "8.0"
                            }
                        }
                    ]
                },
                "192.168.1.150": {
                    "hostname": [{"name": "jump-server.company.local"}],
                    "status": "up",
                    "ports": [
                        {
                            "portid": "22",
                            "protocol": "tcp",
                            "state": "open",
                            "service": {
                                "name": "ssh",
                                "product": "OpenSSH",
                                "version": "7.4"
                            },
                            "vulnerabilities": [
                                {
                                    "cve": "CVE-2018-15473",
                                    "cvss": 5.3,
                                    "severity": "Medium",
                                    "description": "SSH User Enumeration",
                                    "evidence": "SSH version vulnerable to user enumeration"
                                }
                            ]
                        }
                    ]
                },
                "192.168.1.180": {
                    "hostname": [{"name": "file-server.company.local"}],
                    "status": "up",
                    "ports": [
                        {
                            "portid": "21",
                            "protocol": "tcp",
                            "state": "open",
                            "service": {
                                "name": "ftp",
                                "product": "vsftpd",
                                "version": "2.3.4"
                            },
                            "vulnerabilities": [
                                {
                                    "cve": "CVE-2011-2523",
                                    "cvss": 10.0,
                                    "severity": "Critical",
                                    "description": "vsftpd Backdoor Command Execution",
                                    "evidence": "Backdoored version of vsftpd detected"
                                }
                            ]
                        },
                        {
                            "portid": "445",
                            "protocol": "tcp",
                            "state": "open",
                            "service": {
                                "name": "microsoft-ds",
                                "product": "Microsoft Windows SMB"
                            },
                            "vulnerabilities": [
                                {
                                    "cve": "CVE-2017-0144",
                                    "cvss": 8.1,
                                    "severity": "High",
                                    "description": "EternalBlue SMB Vulnerability",
                                    "evidence": "SMB service vulnerable to EternalBlue exploit"
                                }
                            ]
                        }
                    ]
                },
                "192.168.1.50": {
                    "hostname": [{"name": "admin-workstation.company.local"}],
                    "status": "up",
                    "ports": [
                        {
                            "portid": "3389",
                            "protocol": "tcp",
                            "state": "open",
                            "service": {
                                "name": "ms-wbt-server",
                                "product": "Microsoft Terminal Services"
                            },
                            "vulnerabilities": [
                                {
                                    "cve": "CVE-2019-0708",
                                    "cvss": 9.8,
                                    "severity": "Critical",
                                    "description": "BlueKeep RDP Vulnerability",
                                    "evidence": "RDP service vulnerable to BlueKeep exploit"
                                }
                            ]
                        }
                    ]
                }
            }
        }
        
        return scan_data
    
    def create_opencti_sample_data(self) -> Dict[str, Any]:
        """Create sample OpenCTI threat intelligence data"""
        
        opencti_data = {
            "vulnerabilities": [
                {
                    "id": "vulnerability--log4j-rce",
                    "name": "CVE-2021-44228",
                    "description": "Apache Log4j2 Remote Code Execution Vulnerability",
                    "cvss_score": 9.8,
                    "threat_actors": [
                        {
                            "name": "APT29",
                            "confidence": 85
                        },
                        {
                            "name": "Lazarus Group", 
                            "confidence": 70
                        }
                    ],
                    "attack_patterns": [
                        {
                            "mitre_id": "T1190",
                            "name": "Exploit Public-Facing Application",
                            "confidence": 95
                        }
                    ],
                    "exploits": [
                        {
                            "name": "Log4Shell Exploit Kit",
                            "availability": "public",
                            "complexity": "low"
                        }
                    ],
                    "indicators": [
                        {
                            "type": "network-traffic",
                            "pattern": "${jndi:ldap://",
                            "confidence": 90
                        }
                    ]
                },
                {
                    "id": "vulnerability--bluekeep-rdp",
                    "name": "CVE-2019-0708",
                    "description": "BlueKeep RDP Remote Code Execution",
                    "cvss_score": 9.8,
                    "threat_actors": [
                        {
                            "name": "APT41",
                            "confidence": 75
                        }
                    ],
                    "attack_patterns": [
                        {
                            "mitre_id": "T1021.001",
                            "name": "Remote Services: Remote Desktop Protocol",
                            "confidence": 90
                        }
                    ],
                    "exploits": [
                        {
                            "name": "BlueKeep Scanner",
                            "availability": "public",
                            "complexity": "medium"
                        }
                    ]
                },
                {
                    "id": "vulnerability--eternalblue-smb",
                    "name": "CVE-2017-0144",
                    "description": "EternalBlue SMB Remote Code Execution",
                    "cvss_score": 8.1,
                    "threat_actors": [
                        {
                            "name": "WannaCry",
                            "confidence": 95
                        },
                        {
                            "name": "NotPetya",
                            "confidence": 90
                        }
                    ],
                    "attack_patterns": [
                        {
                            "mitre_id": "T1021.002",
                            "name": "Remote Services: SMB/Windows Admin Shares",
                            "confidence": 95
                        }
                    ]
                }
            ],
            "malware": [
                {
                    "id": "malware--log4j-miner",
                    "name": "Log4j Cryptocurrency Miner",
                    "description": "Cryptocurrency mining malware exploiting Log4j vulnerability",
                    "associated_cves": ["CVE-2021-44228"]
                },
                {
                    "id": "malware--bluekeep-backdoor",
                    "name": "BlueKeep Backdoor",
                    "description": "Backdoor malware using BlueKeep RDP vulnerability",
                    "associated_cves": ["CVE-2019-0708"]
                }
            ]
        }
        
        return opencti_data
    
    def create_attack_scenarios(self) -> List[Dict[str, Any]]:
        """Create realistic attack scenarios for testing"""
        
        scenarios = [
            {
                "scenario_id": "web_to_db_lateral_movement",
                "name": "Web Server to Database Lateral Movement",
                "description": "Attacker exploits web server vulnerability to gain access to internal database",
                "attack_chain": [
                    {
                        "step": 1,
                        "action": "Initial Access",
                        "target": "192.168.1.100",
                        "technique": "T1190",
                        "vulnerability": "CVE-2021-44228",
                        "description": "Exploit Log4j vulnerability in web application"
                    },
                    {
                        "step": 2,
                        "action": "Discovery",
                        "target": "192.168.1.100",
                        "technique": "T1018",
                        "description": "Network discovery to identify internal systems"
                    },
                    {
                        "step": 3,
                        "action": "Lateral Movement",
                        "target": "192.168.1.200",
                        "technique": "T1021.004",
                        "description": "SSH to database server using compromised credentials"
                    },
                    {
                        "step": 4,
                        "action": "Privilege Escalation",
                        "target": "192.168.1.200",
                        "technique": "T1068",
                        "vulnerability": "CVE-2020-14867",
                        "description": "Exploit MySQL privilege escalation vulnerability"
                    },
                    {
                        "step": 5,
                        "action": "Data Exfiltration",
                        "target": "192.168.1.200",
                        "technique": "T1041",
                        "description": "Exfiltrate sensitive database contents"
                    }
                ],
                "impact": "High",
                "likelihood": "High",
                "risk_score": 9.2
            },
            {
                "scenario_id": "rdp_admin_compromise",
                "name": "RDP Admin Workstation Compromise",
                "description": "Direct compromise of admin workstation via BlueKeep vulnerability",
                "attack_chain": [
                    {
                        "step": 1,
                        "action": "Initial Access",
                        "target": "192.168.1.50",
                        "technique": "T1021.001",
                        "vulnerability": "CVE-2019-0708",
                        "description": "Exploit BlueKeep RDP vulnerability"
                    },
                    {
                        "step": 2,
                        "action": "Persistence",
                        "target": "192.168.1.50",
                        "technique": "T1547.001",
                        "description": "Create registry run key for persistence"
                    },
                    {
                        "step": 3,
                        "action": "Credential Access",
                        "target": "192.168.1.50",
                        "technique": "T1003.001",
                        "description": "Dump LSASS memory for credentials"
                    },
                    {
                        "step": 4,
                        "action": "Domain Enumeration",
                        "target": "192.168.1.50",
                        "technique": "T1087.002",
                        "description": "Enumerate domain users and groups"
                    }
                ],
                "impact": "Critical",
                "likelihood": "Medium",
                "risk_score": 8.5
            },
            {
                "scenario_id": "ftp_smb_worm_propagation",
                "name": "FTP to SMB Worm Propagation",
                "description": "Worm-like propagation from FTP backdoor to SMB vulnerability",
                "attack_chain": [
                    {
                        "step": 1,
                        "action": "Initial Access",
                        "target": "192.168.1.180",
                        "technique": "T1190",
                        "vulnerability": "CVE-2011-2523",
                        "description": "Exploit vsftpd backdoor"
                    },
                    {
                        "step": 2,
                        "action": "Network Scanning",
                        "target": "192.168.1.0/24",
                        "technique": "T1046",
                        "description": "Scan network for SMB services"
                    },
                    {
                        "step": 3,
                        "action": "Lateral Movement",
                        "target": "192.168.1.180",
                        "technique": "T1021.002",
                        "vulnerability": "CVE-2017-0144",
                        "description": "Exploit EternalBlue SMB vulnerability"
                    },
                    {
                        "step": 4,
                        "action": "Propagation",
                        "target": "Multiple",
                        "technique": "T1570",
                        "description": "Self-replicate to other vulnerable systems"
                    }
                ],
                "impact": "High",
                "likelihood": "Medium",
                "risk_score": 7.8
            }
        ]
        
        return scenarios
    
    def setup_test_files(self):
        """Create all test data files"""
        logger.info("Setting up test environment files...")
        
        # Create scan data
        scan_data = self.create_realistic_scan_data()
        with open(self.test_data_dir / "realistic_scan_data.json", "w") as f:
            json.dump(scan_data, f, indent=2)
        
        # Create OpenCTI data
        opencti_data = self.create_opencti_sample_data()
        with open(self.test_data_dir / "opencti_sample_data.json", "w") as f:
            json.dump(opencti_data, f, indent=2)
        
        # Create attack scenarios
        scenarios = self.create_attack_scenarios()
        with open(self.test_data_dir / "attack_scenarios.json", "w") as f:
            json.dump(scenarios, f, indent=2)
        
        # Create normalized findings for attack graph
        normalized_findings = self._create_normalized_findings(scan_data)
        with open(self.test_data_dir / "normalized_findings.json", "w") as f:
            json.dump(normalized_findings, f, indent=2)
        
        logger.info(f"Test files created in {self.test_data_dir}")
    
    def _create_normalized_findings(self, scan_data: Dict) -> List[Dict]:
        """Convert scan data to normalized findings format"""
        findings = []
        
        for ip, host_data in scan_data["hosts"].items():
            hostname = host_data["hostname"][0]["name"] if host_data.get("hostname") else ip
            
            for port_data in host_data.get("ports", []):
                service = port_data["service"]
                
                # Create finding for each vulnerability
                for vuln in port_data.get("vulnerabilities", []):
                    finding = {
                        "finding_id": f"vuln_{ip}_{port_data['portid']}_{vuln['cve'].replace('-', '_')}",
                        "host": hostname,
                        "ip": ip,
                        "service": service["name"],
                        "port": int(port_data["portid"]),
                        "version": f"{service.get('product', '')} {service.get('version', '')}".strip(),
                        "cve": vuln["cve"],
                        "cvss": vuln["cvss"],
                        "severity": vuln["severity"],
                        "evidence": vuln["evidence"],
                        "scan_tool": "nmap",
                        "asset_type": self._determine_asset_type(service["name"], hostname),
                        "network_zone": self._determine_network_zone(ip),
                        "criticality": self._calculate_criticality(vuln["cvss"], service["name"]),
                        "exploitability": self._calculate_exploitability(vuln["cve"])
                    }
                    findings.append(finding)
                
                # Create finding for open service even without specific vulnerability
                if not port_data.get("vulnerabilities"):
                    finding = {
                        "finding_id": f"service_{ip}_{port_data['portid']}_{service['name']}",
                        "host": hostname,
                        "ip": ip,
                        "service": service["name"],
                        "port": int(port_data["portid"]),
                        "version": f"{service.get('product', '')} {service.get('version', '')}".strip(),
                        "cve": None,
                        "cvss": 0.0,
                        "severity": "Info",
                        "evidence": f"Open {service['name']} service detected",
                        "scan_tool": "nmap",
                        "asset_type": self._determine_asset_type(service["name"], hostname),
                        "network_zone": self._determine_network_zone(ip),
                        "criticality": 3,
                        "exploitability": 0.1
                    }
                    findings.append(finding)
        
        return findings
    
    def _determine_asset_type(self, service: str, hostname: str) -> str:
        """Determine asset type based on service and hostname"""
        if "web" in hostname.lower() or service in ["http", "https"]:
            return "web_server"
        elif "db" in hostname.lower() or service in ["mysql", "postgresql", "mssql"]:
            return "database_server"
        elif "jump" in hostname.lower() or service == "ssh":
            return "jump_server"
        elif "file" in hostname.lower() or service in ["ftp", "smb"]:
            return "file_server"
        elif "admin" in hostname.lower() or service == "rdp":
            return "workstation"
        else:
            return "server"
    
    def _determine_network_zone(self, ip: str) -> str:
        """Determine network zone based on IP address"""
        if ip.startswith("192.168.1.1"):  # 100-199 range
            return "dmz"
        elif ip.startswith("192.168.1.2"):  # 200-299 range
            return "internal"
        elif ip.startswith("192.168.1.5"):  # 50-99 range
            return "admin"
        else:
            return "unknown"
    
    def _calculate_criticality(self, cvss: float, service: str) -> int:
        """Calculate asset criticality based on CVSS and service type"""
        base_criticality = {
            "mysql": 10,
            "postgresql": 10,
            "http": 8,
            "https": 8,
            "rdp": 9,
            "ssh": 7,
            "ftp": 5,
            "smb": 6
        }.get(service, 5)
        
        # Adjust based on CVSS
        if cvss >= 9.0:
            return min(10, base_criticality + 2)
        elif cvss >= 7.0:
            return min(10, base_criticality + 1)
        else:
            return base_criticality
    
    def _calculate_exploitability(self, cve: str) -> float:
        """Calculate exploitability score based on CVE"""
        # Known high-exploitability CVEs
        high_exploitability = {
            "CVE-2021-44228": 0.95,  # Log4j
            "CVE-2019-0708": 0.85,   # BlueKeep
            "CVE-2017-0144": 0.90,   # EternalBlue
            "CVE-2011-2523": 1.0     # vsftpd backdoor
        }
        
        return high_exploitability.get(cve, 0.5)
    
    def create_docker_compose_test_env(self):
        """Create Docker Compose file for test environment"""
        
        docker_compose = {
            "version": "3.8",
            "services": {
                "vulnerable-web": {
                    "image": "vulnerables/web-dvwa",
                    "ports": ["8080:80"],
                    "environment": {
                        "MYSQL_DATABASE": "dvwa",
                        "MYSQL_USER": "dvwa",
                        "MYSQL_PASSWORD": "password"
                    }
                },
                "vulnerable-ftp": {
                    "image": "metasploitable/vsftpd",
                    "ports": ["2121:21"]
                },
                "vulnerable-ssh": {
                    "image": "vulnerables/ssh-audit-test",
                    "ports": ["2222:22"]
                },
                "mysql-db": {
                    "image": "mysql:5.7.30",
                    "ports": ["3306:3306"],
                    "environment": {
                        "MYSQL_ROOT_PASSWORD": "password",
                        "MYSQL_DATABASE": "testdb"
                    }
                }
            }
        }
        
        with open("docker-compose.test.yml", "w") as f:
            import yaml
            yaml.dump(docker_compose, f, default_flow_style=False)
        
        logger.info("Docker Compose test environment created: docker-compose.test.yml")
    
    def generate_test_documentation(self):
        """Generate documentation for the test environment"""
        
        documentation = """
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
"""
        
        with open("TEST_ENVIRONMENT_README.md", "w") as f:
            f.write(documentation)
        
        logger.info("Test environment documentation created: TEST_ENVIRONMENT_README.md")

def main():
    """Main function"""
    print("🛠️  SecureChain Test Environment Setup")
    print("="*50)
    print("Setting up realistic test environment for vulnerability testing...")
    
    setup = TestEnvironmentSetup()
    
    try:
        # Create test files
        setup.setup_test_files()
        
        # Create Docker Compose test environment
        setup.create_docker_compose_test_env()
        
        # Generate documentation
        setup.generate_test_documentation()
        
        print("\n✅ Test environment setup completed!")
        print("\nGenerated Files:")
        print("  📁 test_data/")
        print("    ├── realistic_scan_data.json")
        print("    ├── opencti_sample_data.json")
        print("    ├── attack_scenarios.json")
        print("    └── normalized_findings.json")
        print("  🐳 docker-compose.test.yml")
        print("  📖 TEST_ENVIRONMENT_README.md")
        
        print("\nNext Steps:")
        print("1. Review TEST_ENVIRONMENT_README.md for usage instructions")
        print("2. Run comprehensive_pipeline_test.py for full testing")
        print("3. Use docker-compose.test.yml for containerized vulnerable services")
        
        return True
        
    except Exception as e:
        logger.error(f"Setup failed: {str(e)}")
        print(f"\n❌ Setup failed: {str(e)}")
        return False

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)