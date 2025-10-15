"""
OpenCTI Enrichment Service
Enriches vulnerability findings with threat intelligence from OpenCTI
"""

import requests
import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class OpenCTIEnricher:
    """Enrich findings with OpenCTI threat intelligence"""
    
    def __init__(self, opencti_url: str, opencti_token: str):
        self.base_url = opencti_url.rstrip('/')
        self.token = opencti_token
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {opencti_token}',
            'Content-Type': 'application/json'
        })
    
    def execute_query(self, query: str, variables: Dict = None) -> Dict[str, Any]:
        """Execute GraphQL query against OpenCTI"""
        payload = {'query': query}
        if variables:
            payload['variables'] = variables
            
        try:
            response = self.session.post(f"{self.base_url}/graphql", json=payload, timeout=30)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"OpenCTI query failed: {e}")
            return {'errors': [{'message': str(e)}]}
    
    def enrich_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich a single finding with OpenCTI data"""
        enrichment_data = {}
        
        # Enrich CVE if present
        if finding.get('cve'):
            cve_data = self.get_cve_intelligence(finding['cve'])
            enrichment_data.update(cve_data)
        
        # Enrich IP address
        if finding.get('ip'):
            ip_data = self.get_ip_intelligence(finding['ip'])
            enrichment_data.update(ip_data)
        
        # Enrich service/software
        if finding.get('service') and finding.get('version'):
            software_data = self.get_software_intelligence(finding['service'], finding['version'])
            enrichment_data.update(software_data)
        
        # Get related attack patterns
        attack_patterns = self.get_attack_patterns_for_finding(finding)
        if attack_patterns:
            enrichment_data['opencti_attack_patterns'] = attack_patterns
        
        logger.info(f"Enriched finding {finding.get('finding_id')} with OpenCTI data")
        return enrichment_data
    
    def get_cve_intelligence(self, cve_id: str) -> Dict[str, Any]:
        """Get CVE intelligence from OpenCTI"""
        query = """
        query GetCVE($cve_id: String!) {
            vulnerabilities(filters: [{key: "name", values: [$cve_id]}]) {
                edges {
                    node {
                        id
                        name
                        description
                        x_opencti_cvss_base_score
                        x_opencti_cvss_base_severity
                        stixCoreRelationships {
                            edges {
                                node {
                                    relationship_type
                                    from {
                                        ... on StixCoreObject {
                                            id
                                            entity_type
                                            ... on Malware { name }
                                            ... on ThreatActorGroup { name }
                                            ... on AttackPattern { 
                                                name 
                                                x_mitre_id
                                            }
                                        }
                                    }
                                    to {
                                        ... on StixCoreObject {
                                            id
                                            entity_type
                                            ... on Malware { name }
                                            ... on ThreatActorGroup { name }
                                            ... on AttackPattern { 
                                                name 
                                                x_mitre_id
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        """
        
        result = self.execute_query(query, {'cve_id': cve_id})
        
        if 'data' in result and result['data']['vulnerabilities']['edges']:
            vuln_data = result['data']['vulnerabilities']['edges'][0]['node']
            
            # Extract related entities
            malware_ids = []
            threat_actors = []
            attack_patterns = []
            
            for rel in vuln_data.get('stixCoreRelationships', {}).get('edges', []):
                rel_node = rel['node']
                from_entity = rel_node.get('from', {})
                to_entity = rel_node.get('to', {})
                
                for entity in [from_entity, to_entity]:
                    if entity.get('entity_type') == 'Malware':
                        malware_ids.append(entity['id'])
                    elif entity.get('entity_type') == 'Threat-Actor-Group':
                        threat_actors.append({
                            'id': entity['id'],
                            'name': entity.get('name')
                        })
                    elif entity.get('entity_type') == 'Attack-Pattern':
                        attack_patterns.append({
                            'id': entity['id'],
                            'name': entity.get('name'),
                            'mitre_id': entity.get('x_mitre_id')
                        })
            
            return {
                'opencti_vulnerability_id': vuln_data['id'],
                'cvss': vuln_data.get('x_opencti_cvss_base_score'),
                'opencti_malware_ids': malware_ids,
                'threat_actor_groups': threat_actors,
                'opencti_attack_patterns': attack_patterns,
                'exploit_available': len(malware_ids) > 0  # If malware is associated, likely exploited
            }
        
        return {}
    
    def get_ip_intelligence(self, ip_address: str) -> Dict[str, Any]:
        """Get IP address intelligence from OpenCTI"""
        query = """
        query GetIPIntel($ip: String!) {
            indicators(filters: [{key: "pattern", values: [$pattern]}]) {
                edges {
                    node {
                        id
                        name
                        pattern
                        indicator_types
                        confidence
                        stixCoreRelationships {
                            edges {
                                node {
                                    relationship_type
                                    from {
                                        ... on StixCoreObject {
                                            id
                                            entity_type
                                            ... on Malware { name }
                                            ... on ThreatActorGroup { name }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        """
        
        pattern = f"[ipv4-addr:value = '{ip_address}']"
        result = self.execute_query(query, {'pattern': pattern})
        
        if 'data' in result and result['data']['indicators']['edges']:
            indicator_data = result['data']['indicators']['edges'][0]['node']
            
            # Extract related threat actors and malware
            related_entities = []
            for rel in indicator_data.get('stixCoreRelationships', {}).get('edges', []):
                from_entity = rel['node'].get('from', {})
                if from_entity.get('entity_type') in ['Malware', 'Threat-Actor-Group']:
                    related_entities.append({
                        'type': from_entity['entity_type'],
                        'name': from_entity.get('name'),
                        'id': from_entity['id']
                    })
            
            return {
                'opencti_indicator_id': indicator_data['id'],
                'threat_actor_groups': [e for e in related_entities if e['type'] == 'Threat-Actor-Group'],
                'opencti_malware_ids': [e['id'] for e in related_entities if e['type'] == 'Malware']
            }
        
        return {}
    
    def get_software_intelligence(self, service: str, version: str) -> Dict[str, Any]:
        """Get software/service intelligence from OpenCTI"""
        # Search for software vulnerabilities
        query = """
        query GetSoftwareVulns($software: String!) {
            vulnerabilities(search: $software, first: 10) {
                edges {
                    node {
                        id
                        name
                        description
                        x_opencti_cvss_base_score
                        stixCoreRelationships {
                            edges {
                                node {
                                    relationship_type
                                    from {
                                        ... on AttackPattern { 
                                            name 
                                            x_mitre_id
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        """
        
        search_term = f"{service} {version}".strip()
        result = self.execute_query(query, {'software': search_term})
        
        if 'data' in result and result['data']['vulnerabilities']['edges']:
            # Get attack patterns from related vulnerabilities
            attack_patterns = []
            for vuln in result['data']['vulnerabilities']['edges']:
                for rel in vuln['node'].get('stixCoreRelationships', {}).get('edges', []):
                    from_entity = rel['node'].get('from', {})
                    if from_entity and 'x_mitre_id' in from_entity:
                        attack_patterns.append({
                            'name': from_entity.get('name'),
                            'mitre_id': from_entity.get('x_mitre_id')
                        })
            
            return {
                'opencti_attack_patterns': attack_patterns
            }
        
        return {}
    
    def get_attack_patterns_for_finding(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get relevant MITRE ATT&CK patterns for a finding"""
        attack_patterns = []
        
        # Map common services to attack patterns
        service_to_attack_patterns = {
            'ssh': ['T1021.004'],  # Remote Services: SSH
            'rdp': ['T1021.001'],  # Remote Services: Remote Desktop Protocol
            'http': ['T1190'],     # Exploit Public-Facing Application
            'https': ['T1190'],    # Exploit Public-Facing Application
            'ftp': ['T1021.002'],  # Remote Services: SMB/Windows Admin Shares
            'telnet': ['T1021'],   # Remote Services
            'smtp': ['T1566'],     # Phishing
            'mysql': ['T1190'],    # Exploit Public-Facing Application
            'postgresql': ['T1190'] # Exploit Public-Facing Application
        }
        
        service = finding.get('service', '').lower()
        if service in service_to_attack_patterns:
            for technique_id in service_to_attack_patterns[service]:
                attack_patterns.append({
                    'mitre_id': technique_id,
                    'name': f"Attack pattern for {service}",
                    'confidence': 80
                })
        
        return attack_patterns
    
    def get_exploit_availability(self, cve_id: str) -> bool:
        """Check if exploits are available for a CVE"""
        query = """
        query CheckExploits($cve_id: String!) {
            malwares(search: $cve_id, first: 5) {
                edges {
                    node {
                        id
                        name
                    }
                }
            }
        }
        """
        
        result = self.execute_query(query, {'cve_id': cve_id})
        
        if 'data' in result and result['data']['malwares']['edges']:
            return len(result['data']['malwares']['edges']) > 0
        
        return False
    
    def batch_enrich_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enrich multiple findings in batch"""
        enriched_findings = []
        
        for finding in findings:
            try:
                enrichment_data = self.enrich_finding(finding)
                finding.update(enrichment_data)
                enriched_findings.append(finding)
            except Exception as e:
                logger.error(f"Failed to enrich finding {finding.get('finding_id')}: {e}")
                enriched_findings.append(finding)  # Add without enrichment
        
        logger.info(f"Enriched {len(enriched_findings)} findings with OpenCTI data")
        return enriched_findings