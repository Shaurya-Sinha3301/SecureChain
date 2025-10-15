"""
Vulnerability Finding Ingestion Service
Handles the complete workflow: normalization -> enrichment -> storage -> attack graph
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
import asyncio
import json

from services.finding_normalizer import FindingNormalizer
from services.opencti_enricher import OpenCTIEnricher
from services.database_manager import DatabaseManager

logger = logging.getLogger(__name__)

class IngestionService:
    """Main service for ingesting and processing vulnerability findings"""
    
    def __init__(self, 
                 db_manager: DatabaseManager,
                 opencti_enricher: Optional[OpenCTIEnricher] = None):
        self.db_manager = db_manager
        self.normalizer = FindingNormalizer()
        self.opencti_enricher = opencti_enricher
        
    def process_scan_results(self, 
                           scan_results: Dict[str, Any], 
                           scan_tool: str,
                           target: str) -> Dict[str, Any]:
        """
        Complete workflow: normalize -> enrich -> store -> create attack graph
        """
        logger.info(f"Starting ingestion workflow for {scan_tool} scan of {target}")
        
        try:
            # Step 1: Normalize findings
            normalized_findings = self._normalize_findings(scan_results, scan_tool)
            logger.info(f"Normalized {len(normalized_findings)} findings")
            
            # Step 2: Enrich with OpenCTI (if available)
            if self.opencti_enricher:
                enriched_findings = self._enrich_findings(normalized_findings)
                logger.info(f"Enriched findings with OpenCTI data")
            else:
                enriched_findings = normalized_findings
                logger.warning("OpenCTI enricher not available, skipping enrichment")
            
            # Step 3: Store findings in PostgreSQL
            stored_findings = self._store_findings(enriched_findings)
            logger.info(f"Stored {len(stored_findings)} findings in database")
            
            # Step 4: Create attack graph nodes in Neo4j
            self._create_attack_graph_data(stored_findings)
            logger.info("Created attack graph data in Neo4j")
            
            # Step 5: Generate attack paths
            self._generate_attack_paths(stored_findings)
            logger.info("Generated attack paths")
            
            return {
                'success': True,
                'findings_processed': len(stored_findings),
                'findings': [f.get('finding_id') for f in stored_findings],
                'timestamp': datetime.utcnow().isoformat(),
                'scan_tool': scan_tool,
                'target': target
            }
            
        except Exception as e:
            logger.error(f"Ingestion workflow failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat(),
                'scan_tool': scan_tool,
                'target': target
            }
    
    def _normalize_findings(self, scan_results: Dict[str, Any], scan_tool: str) -> List[Dict[str, Any]]:
        """Normalize scan results based on tool type"""
        if scan_tool.lower() == 'nmap':
            return self.normalizer.normalize_nmap_findings(scan_results, scan_tool)
        elif scan_tool.lower() == 'nikto':
            # Assume scan_results contains the raw output
            target = list(scan_results.keys())[0] if scan_results else 'unknown'
            output = scan_results.get(target, '')
            return self.normalizer.normalize_nikto_findings(output, target, scan_tool)
        else:
            # Generic normalization for custom formats
            findings_list = scan_results.get('findings', [])
            return self.normalizer.normalize_custom_findings(findings_list, scan_tool)
    
    def _enrich_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enrich findings with OpenCTI threat intelligence"""
        if not self.opencti_enricher:
            return findings
        
        return self.opencti_enricher.batch_enrich_findings(findings)
    
    def _store_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Store findings in PostgreSQL database"""
        stored_findings = []
        
        for finding in findings:
            try:
                # Validate finding before storing
                if self.normalizer.validate_finding(finding):
                    finding_id = self.db_manager.store_finding(finding)
                    finding['finding_id'] = finding_id
                    stored_findings.append(finding)
                else:
                    logger.warning(f"Invalid finding skipped: {finding}")
            except Exception as e:
                logger.error(f"Failed to store finding: {e}")
        
        return stored_findings
    
    def _create_attack_graph_data(self, findings: List[Dict[str, Any]]):
        """Create nodes and relationships in Neo4j for attack graph"""
        try:
            self.db_manager.create_attack_graph_nodes(findings)
        except Exception as e:
            logger.error(f"Failed to create attack graph nodes: {e}")
    
    def _generate_attack_paths(self, findings: List[Dict[str, Any]]):
        """Generate attack paths based on MITRE ATT&CK patterns"""
        attack_paths = []
        
        # Group findings by host
        host_findings = {}
        for finding in findings:
            host = finding.get('ip', finding.get('host'))
            if host not in host_findings:
                host_findings[host] = []
            host_findings[host].append(finding)
        
        # Generate paths within each host
        for host, host_findings_list in host_findings.items():
            paths = self._generate_host_attack_paths(host_findings_list)
            attack_paths.extend(paths)
        
        # Generate paths between hosts
        inter_host_paths = self._generate_inter_host_paths(findings)
        attack_paths.extend(inter_host_paths)
        
        # Store attack paths in Neo4j
        if attack_paths:
            try:
                self.db_manager.create_attack_paths(attack_paths)
            except Exception as e:
                logger.error(f"Failed to create attack paths: {e}")
    
    def _generate_host_attack_paths(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate attack paths within a single host"""
        paths = []
        
        # Sort findings by severity and port number for logical progression
        sorted_findings = sorted(findings, key=lambda x: (
            {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}.get(x.get('severity', 'Low'), 3),
            x.get('port', 0)
        ))
        
        # Create paths from lower-privilege to higher-privilege services
        for i in range(len(sorted_findings) - 1):
            source_finding = sorted_findings[i]
            target_finding = sorted_findings[i + 1]
            
            # Determine attack technique based on services
            technique = self._determine_attack_technique(source_finding, target_finding)
            
            if technique:
                path = {
                    'source_finding': source_finding['finding_id'],
                    'target_finding': target_finding['finding_id'],
                    'technique': technique,
                    'weight': self._calculate_path_weight(source_finding, target_finding)
                }
                paths.append(path)
        
        return paths
    
    def _generate_inter_host_paths(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate attack paths between different hosts"""
        paths = []
        
        # Group by host
        hosts = {}
        for finding in findings:
            host = finding.get('ip', finding.get('host'))
            if host not in hosts:
                hosts[host] = []
            hosts[host].append(finding)
        
        # Create lateral movement paths
        host_list = list(hosts.keys())
        for i in range(len(host_list)):
            for j in range(i + 1, len(host_list)):
                source_host = host_list[i]
                target_host = host_list[j]
                
                # Find best source and target findings for lateral movement
                source_findings = hosts[source_host]
                target_findings = hosts[target_host]
                
                # Prefer SSH, RDP, or other remote access services
                source_finding = self._find_lateral_movement_source(source_findings)
                target_finding = self._find_lateral_movement_target(target_findings)
                
                if source_finding and target_finding:
                    path = {
                        'source_finding': source_finding['finding_id'],
                        'target_finding': target_finding['finding_id'],
                        'technique': 'T1021',  # Remote Services
                        'weight': 2.0  # Higher weight for lateral movement
                    }
                    paths.append(path)
        
        return paths
    
    def _determine_attack_technique(self, source: Dict[str, Any], target: Dict[str, Any]) -> Optional[str]:
        """Determine MITRE ATT&CK technique for attack path"""
        source_service = source.get('service', '').lower()
        target_service = target.get('service', '').lower()
        
        # Service-specific attack techniques
        technique_map = {
            ('http', 'ssh'): 'T1190',      # Exploit Public-Facing Application -> Remote Services
            ('ftp', 'ssh'): 'T1021.002',   # Remote Services progression
            ('telnet', 'ssh'): 'T1021',    # Remote Services
            ('ssh', 'mysql'): 'T1078',     # Valid Accounts
            ('http', 'mysql'): 'T1190',    # Exploit Public-Facing Application
        }
        
        return technique_map.get((source_service, target_service), 'T1068')  # Default: Exploitation for Privilege Escalation
    
    def _calculate_path_weight(self, source: Dict[str, Any], target: Dict[str, Any]) -> float:
        """Calculate weight for attack path based on difficulty/likelihood"""
        base_weight = 1.0
        
        # Adjust based on severity
        severity_weights = {'Critical': 0.5, 'High': 0.7, 'Medium': 1.0, 'Low': 1.5}
        source_weight = severity_weights.get(source.get('severity', 'Medium'), 1.0)
        target_weight = severity_weights.get(target.get('severity', 'Medium'), 1.0)
        
        # Adjust based on CVE availability
        if source.get('cve') or target.get('cve'):
            base_weight *= 0.8  # Easier with known CVE
        
        # Adjust based on exploit availability
        if source.get('exploit_available') or target.get('exploit_available'):
            base_weight *= 0.6  # Much easier with available exploits
        
        return base_weight * (source_weight + target_weight) / 2
    
    def _find_lateral_movement_source(self, findings: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Find best finding for lateral movement source"""
        # Prefer compromised remote access services
        preferred_services = ['ssh', 'rdp', 'telnet', 'ftp']
        
        for service in preferred_services:
            for finding in findings:
                if finding.get('service', '').lower() == service:
                    return finding
        
        # Fallback to any finding
        return findings[0] if findings else None
    
    def _find_lateral_movement_target(self, findings: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Find best finding for lateral movement target"""
        # Prefer high-value targets
        high_value_services = ['mysql', 'postgresql', 'mongodb', 'rdp', 'ssh']
        
        for service in high_value_services:
            for finding in findings:
                if finding.get('service', '').lower() == service:
                    return finding
        
        # Fallback to any finding
        return findings[0] if findings else None
    
    async def process_scan_results_async(self, 
                                       scan_results: Dict[str, Any], 
                                       scan_tool: str,
                                       target: str) -> Dict[str, Any]:
        """Async version of process_scan_results"""
        return await asyncio.get_event_loop().run_in_executor(
            None, self.process_scan_results, scan_results, scan_tool, target
        )
    
    def get_ingestion_stats(self) -> Dict[str, Any]:
        """Get ingestion service statistics"""
        try:
            findings = self.db_manager.get_findings(limit=1000)
            
            stats = {
                'total_findings': len(findings),
                'findings_by_severity': {},
                'findings_by_tool': {},
                'findings_by_status': {},
                'enriched_findings': 0,
                'findings_with_cve': 0,
                'findings_with_exploits': 0
            }
            
            for finding in findings:
                # Count by severity
                severity = finding.get('severity', 'Unknown')
                stats['findings_by_severity'][severity] = stats['findings_by_severity'].get(severity, 0) + 1
                
                # Count by tool
                tool = finding.get('scan_tool', 'Unknown')
                stats['findings_by_tool'][tool] = stats['findings_by_tool'].get(tool, 0) + 1
                
                # Count by status
                status = finding.get('status', 'Unknown')
                stats['findings_by_status'][status] = stats['findings_by_status'].get(status, 0) + 1
                
                # Count enriched findings
                if finding.get('opencti_indicator_id') or finding.get('opencti_vulnerability_id'):
                    stats['enriched_findings'] += 1
                
                # Count CVE findings
                if finding.get('cve'):
                    stats['findings_with_cve'] += 1
                
                # Count exploit availability
                if finding.get('exploit_available'):
                    stats['findings_with_exploits'] += 1
            
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get ingestion stats: {e}")
            return {'error': str(e)}