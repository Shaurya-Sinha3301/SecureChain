"""
Database Manager for PostgreSQL and Neo4j
Handles connections and operations for both databases
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models.database_models import Base, VulnerabilityFinding, ScanSession, AttackPath
import logging
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)

class DatabaseManager:
    """Manage PostgreSQL and Neo4j connections"""
    
    def __init__(self, postgres_url: str, neo4j_uri: str = None, neo4j_user: str = None, neo4j_password: str = None):
        # PostgreSQL setup
        self.postgres_engine = create_engine(postgres_url)
        Base.metadata.create_all(self.postgres_engine)
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.postgres_engine)
        
        # Neo4j setup
        self.neo4j_uri = neo4j_uri
        self.neo4j_user = neo4j_user
        self.neo4j_password = neo4j_password
        self.neo4j_driver = None
        
        if neo4j_uri and neo4j_user and neo4j_password:
            try:
                from neo4j import GraphDatabase
                self.neo4j_driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
                logger.info("Neo4j connection established")
            except ImportError:
                logger.warning("Neo4j driver not installed. Install with: pip install neo4j")
            except Exception as e:
                logger.error(f"Failed to connect to Neo4j: {e}")
    
    def get_postgres_session(self):
        """Get PostgreSQL session"""
        return self.SessionLocal()
    
    def get_neo4j_session(self):
        """Get Neo4j session"""
        if self.neo4j_driver:
            return self.neo4j_driver.session()
        return None
    
    def store_finding(self, finding_data: Dict[str, Any]) -> str:
        """Store vulnerability finding in PostgreSQL"""
        session = self.get_postgres_session()
        try:
            finding = VulnerabilityFinding(**finding_data)
            session.add(finding)
            session.commit()
            logger.info(f"Stored finding: {finding.finding_id}")
            return finding.finding_id
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to store finding: {e}")
            raise
        finally:
            session.close()
    
    def get_findings(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """Retrieve vulnerability findings"""
        session = self.get_postgres_session()
        try:
            findings = session.query(VulnerabilityFinding).offset(offset).limit(limit).all()
            return [finding.to_dict() for finding in findings]
        finally:
            session.close()
    
    def update_finding_opencti_data(self, finding_id: str, opencti_data: Dict[str, Any]):
        """Update finding with OpenCTI enrichment data"""
        session = self.get_postgres_session()
        try:
            finding = session.query(VulnerabilityFinding).filter(
                VulnerabilityFinding.finding_id == finding_id
            ).first()
            
            if finding:
                for key, value in opencti_data.items():
                    if hasattr(finding, key):
                        setattr(finding, key, value)
                session.commit()
                logger.info(f"Updated finding {finding_id} with OpenCTI data")
            else:
                logger.warning(f"Finding {finding_id} not found for OpenCTI update")
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to update finding with OpenCTI data: {e}")
            raise
        finally:
            session.close()
    
    def create_attack_graph_nodes(self, findings: List[Dict[str, Any]]):
        """Create meaningful attack graph with enriched data and relationships"""
        if not self.neo4j_driver:
            logger.warning("Neo4j not available for attack graph creation")
            return
        
        neo4j_session = self.get_neo4j_session()
        try:
            # Calculate host risk scores and create enriched host nodes
            unique_hosts = {}
            for finding in findings:
                ip = finding.get('ip')
                host = finding.get('host', ip)
                if ip not in unique_hosts:
                    unique_hosts[ip] = {
                        'hostname': host,
                        'vulnerabilities': [],
                        'risk_score': 0.0
                    }
                unique_hosts[ip]['vulnerabilities'].append(finding)
                cvss = finding.get('cvss', 0) or 0
                unique_hosts[ip]['risk_score'] += float(cvss)
            
            # Create host nodes with risk assessment
            for ip, host_data in unique_hosts.items():
                avg_risk = host_data['risk_score'] / len(host_data['vulnerabilities']) if host_data['vulnerabilities'] else 0
                criticality = "CRITICAL" if avg_risk >= 7.0 else "HIGH" if avg_risk >= 4.0 else "MEDIUM"
                
                query = """
                MERGE (h:Host {
                    ip: $ip, 
                    hostname: $hostname,
                    vulnerability_count: $vuln_count,
                    risk_score: $risk_score,
                    criticality: $criticality
                })
                """
                neo4j_session.run(query, 
                    ip=ip, 
                    hostname=host_data['hostname'],
                    vuln_count=len(host_data['vulnerabilities']),
                    risk_score=round(avg_risk, 2),
                    criticality=criticality
                )
            
            # Create enriched vulnerability nodes
            for finding in findings:
                exploitable = (
                    finding.get('exploit_available', False) or
                    bool(finding.get('opencti_malware_ids')) or
                    (finding.get('cvss', 0) or 0) >= 7.0
                )
                
                attack_patterns = finding.get('opencti_attack_patterns', [])
                techniques = [ap.get('mitre_id') for ap in attack_patterns if ap.get('mitre_id')]
                
                query = """
                MERGE (v:Vulnerability {
                    finding_id: $finding_id,
                    cve: $cve,
                    service: $service,
                    port: $port,
                    cvss: $cvss,
                    severity: $severity,
                    exploitable: $exploitable,
                    mitre_techniques: $techniques,
                    description: $evidence
                })
                """
                neo4j_session.run(query,
                    finding_id=finding.get('finding_id'),
                    cve=finding.get('cve'),
                    service=finding.get('service'),
                    port=finding.get('port'),
                    cvss=finding.get('cvss'),
                    severity=finding.get('severity'),
                    exploitable=exploitable,
                    techniques=techniques,
                    evidence=finding.get('evidence', '')
                )
                
                # Create host-vulnerability relationships with risk contribution
                query = """
                MATCH (v:Vulnerability {finding_id: $finding_id})
                MATCH (h:Host {ip: $ip})
                MERGE (h)-[:HAS_VULNERABILITY {
                    discovered_at: datetime(),
                    risk_contribution: $risk_contribution
                }]->(v)
                """
                risk_contribution = (finding.get('cvss', 0) or 0) / 10.0
                neo4j_session.run(query, 
                    finding_id=finding.get('finding_id'),
                    ip=finding.get('ip'),
                    risk_contribution=risk_contribution
                )
            
            # Create attack paths between vulnerabilities on same host
            for ip, host_data in unique_hosts.items():
                vulns = host_data['vulnerabilities']
                if len(vulns) > 1:
                    # Sort by exploitability and CVSS
                    sorted_vulns = sorted(vulns, 
                        key=lambda x: (x.get('cvss', 0) or 0, x.get('exploit_available', False)), 
                        reverse=True
                    )
                    
                    # Create logical attack paths
                    for i, vuln1 in enumerate(sorted_vulns):
                        for vuln2 in sorted_vulns[i+1:]:
                            if self._should_create_attack_path(vuln1, vuln2):
                                query = """
                                MATCH (v1:Vulnerability {finding_id: $finding_id1})
                                MATCH (v2:Vulnerability {finding_id: $finding_id2})
                                MERGE (v1)-[:LEADS_TO {
                                    attack_vector: $vector,
                                    likelihood: $likelihood,
                                    technique: $technique
                                }]->(v2)
                                """
                                vector = f"{vuln1.get('service', 'unknown')} -> {vuln2.get('service', 'unknown')}"
                                likelihood = 0.8 if vuln1.get('exploit_available') else 0.6
                                technique = self._get_attack_technique(vuln1, vuln2)
                                
                                neo4j_session.run(query,
                                    finding_id1=vuln1.get('finding_id'),
                                    finding_id2=vuln2.get('finding_id'),
                                    vector=vector,
                                    likelihood=likelihood,
                                    technique=technique
                                )
            
            logger.info(f"Created enriched attack graph with {len(findings)} vulnerabilities across {len(unique_hosts)} hosts")
            
        except Exception as e:
            logger.error(f"Failed to create attack graph nodes: {e}")
            raise
        finally:
            neo4j_session.close()
    
    def _should_create_attack_path(self, vuln1, vuln2):
        """Determine if there's a logical attack path between vulnerabilities"""
        # Web services can lead to SSH/internal services
        if vuln1.get('service') in ['http', 'https'] and vuln2.get('service') in ['ssh', 'telnet']:
            return True
        
        # High CVSS vulnerabilities can lead to lower ones
        cvss1 = vuln1.get('cvss', 0) or 0
        cvss2 = vuln2.get('cvss', 0) or 0
        if cvss1 > cvss2 and cvss1 >= 6.0:
            return True
        
        # Exploitable vulnerabilities can lead to others
        if vuln1.get('exploit_available') and not vuln2.get('exploit_available'):
            return True
        
        return False
    
    def _get_attack_technique(self, vuln1, vuln2):
        """Get MITRE ATT&CK technique for attack path"""
        service_techniques = {
            'http': 'T1190',
            'https': 'T1190',
            'ssh': 'T1021.004',
            'rdp': 'T1021.001',
            'ftp': 'T1021.002'
        }
        
        return service_techniques.get(vuln1.get('service', ''), 'T1190')
    
    def create_attack_paths(self, attack_patterns: List[Dict[str, Any]]):
        """Create attack paths in Neo4j based on MITRE ATT&CK patterns"""
        if not self.neo4j_driver:
            logger.warning("Neo4j not available for attack path creation")
            return
        
        neo4j_session = self.get_neo4j_session()
        try:
            for pattern in attack_patterns:
                query = """
                MATCH (v1:Vulnerability {finding_id: $source_finding})
                MATCH (v2:Vulnerability {finding_id: $target_finding})
                MERGE (v1)-[:ATTACK_PATH {
                    technique: $technique,
                    weight: $weight
                }]->(v2)
                """
                neo4j_session.run(query, **pattern)
            
            logger.info(f"Created {len(attack_patterns)} attack paths")
            
        except Exception as e:
            logger.error(f"Failed to create attack paths: {e}")
            raise
        finally:
            neo4j_session.close()
    
    def get_attack_graph(self) -> Dict[str, Any]:
        """Retrieve attack graph data from Neo4j"""
        if not self.neo4j_driver:
            return {"nodes": [], "edges": []}
        
        neo4j_session = self.get_neo4j_session()
        try:
            # Get nodes
            nodes_query = """
            MATCH (n)
            RETURN n, labels(n) as labels
            """
            nodes_result = neo4j_session.run(nodes_query)
            nodes = []
            for record in nodes_result:
                node = dict(record['n'])
                node['labels'] = record['labels']
                nodes.append(node)
            
            # Get relationships
            edges_query = """
            MATCH (a)-[r]->(b)
            RETURN a.finding_id as source, b.finding_id as target, 
                   type(r) as relationship, properties(r) as props
            """
            edges_result = neo4j_session.run(edges_query)
            edges = []
            for record in edges_result:
                edge = {
                    'source': record['source'],
                    'target': record['target'],
                    'relationship': record['relationship'],
                    'properties': dict(record['props'])
                }
                edges.append(edge)
            
            return {"nodes": nodes, "edges": edges}
            
        except Exception as e:
            logger.error(f"Failed to retrieve attack graph: {e}")
            return {"nodes": [], "edges": []}
        finally:
            neo4j_session.close()
    
    def close(self):
        """Close database connections"""
        if self.neo4j_driver:
            self.neo4j_driver.close()
            logger.info("Neo4j connection closed")