"""
Finding Normalizer
Converts raw scan results into normalized vulnerability findings
"""

import re
import json
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)

class FindingNormalizer:
    """Normalize vulnerability findings from different scan tools"""
    
    def __init__(self):
        self.cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}')
        self.ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        self.port_pattern = re.compile(r'(\d+)/(tcp|udp)')
    
    def normalize_nmap_findings(self, nmap_results: Dict[str, Any], scan_tool: str = "nmap") -> List[Dict[str, Any]]:
        """Normalize nmap scan results into structured findings"""
        findings = []
        
        for host_ip, host_data in nmap_results.items():
            if host_ip in ['runtime', 'stats', 'task_results']:
                continue
                
            hostname = host_data.get('hostname', [{}])[0].get('name', host_ip) if host_data.get('hostname') else host_ip
            
            # Process open ports
            ports = host_data.get('ports', [])
            for port_info in ports:
                if port_info.get('state') == 'open':
                    finding = self._create_port_finding(
                        host=hostname,
                        ip=host_ip,
                        port_info=port_info,
                        scan_tool=scan_tool
                    )
                    findings.append(finding)
            
            # Process OS detection if available
            if 'osmatch' in host_data:
                os_findings = self._create_os_findings(
                    host=hostname,
                    ip=host_ip,
                    os_data=host_data['osmatch'],
                    scan_tool=scan_tool
                )
                findings.extend(os_findings)
        
        logger.info(f"Normalized {len(findings)} findings from nmap results")
        return findings
    
    def _create_port_finding(self, host: str, ip: str, port_info: Dict[str, Any], scan_tool: str) -> Dict[str, Any]:
        """Create a finding for an open port"""
        port = port_info.get('portid')
        protocol = port_info.get('protocol', 'tcp')
        service_info = port_info.get('service', {})
        service_name = service_info.get('name', 'unknown')
        version = service_info.get('version', '')
        product = service_info.get('product', '')
        
        # Combine product and version for full version string
        full_version = f"{product} {version}".strip() if product and version else (product or version or '')
        
        # Determine severity based on service and port
        severity = self._assess_port_severity(port, service_name, full_version)
        
        # Create evidence string
        evidence = f"Open {protocol.upper()} port {port} running {service_name}"
        if full_version:
            evidence += f" ({full_version})"
        
        finding = {
            'finding_id': str(uuid.uuid4()),
            'host': host,
            'ip': ip,
            'service': service_name,
            'port': int(port) if port else None,
            'version': full_version,
            'cve': None,  # Will be enriched later
            'cvss': None,  # Will be enriched later
            'evidence': evidence,
            'scan_tool': scan_tool,
            'severity': severity,
            'scan_timestamp': datetime.utcnow()
        }
        
        return finding
    
    def _create_os_findings(self, host: str, ip: str, os_data: List[Dict], scan_tool: str) -> List[Dict[str, Any]]:
        """Create findings for OS detection"""
        findings = []
        
        for os_match in os_data:
            if os_match.get('accuracy', 0) > 80:  # Only high-confidence matches
                os_name = os_match.get('name', 'Unknown OS')
                accuracy = os_match.get('accuracy', 0)
                
                finding = {
                    'finding_id': str(uuid.uuid4()),
                    'host': host,
                    'ip': ip,
                    'service': 'operating_system',
                    'port': None,
                    'version': os_name,
                    'cve': None,
                    'cvss': None,
                    'evidence': f"OS fingerprinting detected: {os_name} (accuracy: {accuracy}%)",
                    'scan_tool': scan_tool,
                    'severity': 'Info',
                    'scan_timestamp': datetime.utcnow()
                }
                findings.append(finding)
        
        return findings
    
    def _assess_port_severity(self, port: int, service: str, version: str) -> str:
        """Assess severity based on port, service, and version"""
        port = int(port) if port else 0
        
        # Critical services/ports
        critical_services = ['telnet', 'ftp', 'rsh', 'rlogin']
        critical_ports = [23, 21, 514, 513]
        
        # High-risk services/ports
        high_risk_services = ['ssh', 'rdp', 'vnc', 'mysql', 'postgresql', 'mongodb']
        high_risk_ports = [22, 3389, 5900, 3306, 5432, 27017]
        
        # Medium-risk services/ports
        medium_risk_services = ['http', 'https', 'smtp', 'pop3', 'imap']
        medium_risk_ports = [80, 443, 25, 110, 143]
        
        if service.lower() in critical_services or port in critical_ports:
            return 'Critical'
        elif service.lower() in high_risk_services or port in high_risk_ports:
            return 'High'
        elif service.lower() in medium_risk_services or port in medium_risk_ports:
            return 'Medium'
        else:
            return 'Low'
    
    def normalize_nikto_findings(self, nikto_results: str, target_host: str, scan_tool: str = "nikto") -> List[Dict[str, Any]]:
        """Normalize Nikto scan results"""
        findings = []
        
        # Parse Nikto output (assuming text format)
        lines = nikto_results.split('\n')
        ip_match = self.ip_pattern.search(target_host)
        ip = ip_match.group() if ip_match else target_host
        
        for line in lines:
            if '+ ' in line and ('OSVDB' in line or 'CVE' in line or 'vulnerability' in line.lower()):
                finding = self._parse_nikto_line(line, target_host, ip, scan_tool)
                if finding:
                    findings.append(finding)
        
        logger.info(f"Normalized {len(findings)} findings from Nikto results")
        return findings
    
    def _parse_nikto_line(self, line: str, host: str, ip: str, scan_tool: str) -> Optional[Dict[str, Any]]:
        """Parse a single Nikto finding line"""
        # Extract CVE if present
        cve_match = self.cve_pattern.search(line)
        cve = cve_match.group() if cve_match else None
        
        # Extract port if present
        port_match = self.port_pattern.search(line)
        port = int(port_match.group(1)) if port_match else 80  # Default to HTTP
        
        # Determine severity based on keywords
        severity = 'Medium'  # Default for web vulnerabilities
        if any(keyword in line.lower() for keyword in ['critical', 'high', 'severe']):
            severity = 'High'
        elif any(keyword in line.lower() for keyword in ['info', 'low']):
            severity = 'Low'
        
        finding = {
            'finding_id': str(uuid.uuid4()),
            'host': host,
            'ip': ip,
            'service': 'http',
            'port': port,
            'version': None,
            'cve': cve,
            'cvss': None,  # Will be enriched later
            'evidence': line.strip(),
            'scan_tool': scan_tool,
            'severity': severity,
            'scan_timestamp': datetime.utcnow()
        }
        
        return finding
    
    def normalize_custom_findings(self, findings_data: List[Dict[str, Any]], scan_tool: str) -> List[Dict[str, Any]]:
        """Normalize custom finding format"""
        normalized_findings = []
        
        for finding_data in findings_data:
            # Ensure required fields
            finding = {
                'finding_id': finding_data.get('finding_id', str(uuid.uuid4())),
                'host': finding_data.get('host', ''),
                'ip': finding_data.get('ip', ''),
                'service': finding_data.get('service', ''),
                'port': finding_data.get('port'),
                'version': finding_data.get('version', ''),
                'cve': finding_data.get('cve'),
                'cvss': finding_data.get('cvss'),
                'evidence': finding_data.get('evidence', ''),
                'scan_tool': scan_tool,
                'severity': finding_data.get('severity', 'Medium'),
                'scan_timestamp': datetime.utcnow()
            }
            
            normalized_findings.append(finding)
        
        logger.info(f"Normalized {len(normalized_findings)} custom findings")
        return normalized_findings
    
    def extract_cves_from_text(self, text: str) -> List[str]:
        """Extract CVE identifiers from text"""
        return self.cve_pattern.findall(text)
    
    def validate_finding(self, finding: Dict[str, Any]) -> bool:
        """Validate that a finding has required fields"""
        required_fields = ['host', 'ip', 'scan_tool']
        return all(field in finding and finding[field] for field in required_fields)