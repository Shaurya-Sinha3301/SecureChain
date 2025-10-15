"""
Database Models for SecureChain
PostgreSQL models for vulnerability findings and Neo4j integration
"""

from sqlalchemy import create_engine, Column, String, Integer, Float, DateTime, Text, Boolean, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import uuid

Base = declarative_base()

class VulnerabilityFinding(Base):
    """PostgreSQL model for normalized vulnerability findings"""
    __tablename__ = 'vulnerability_findings'
    
    finding_id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    host = Column(String, nullable=False)
    ip = Column(String, nullable=False)
    service = Column(String)
    port = Column(Integer)
    version = Column(String)
    cve = Column(String)
    cvss = Column(Float)
    evidence = Column(Text)
    scan_tool = Column(String, nullable=False)
    
    # OpenCTI enrichment fields
    opencti_indicator_id = Column(String)
    opencti_vulnerability_id = Column(String)
    opencti_malware_ids = Column(JSON)  # List of malware IDs
    opencti_attack_patterns = Column(JSON)  # ATT&CK mappings
    exploit_available = Column(Boolean, default=False)
    threat_actor_groups = Column(JSON)  # Associated threat actors
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    scan_timestamp = Column(DateTime)
    severity = Column(String)  # Critical, High, Medium, Low
    status = Column(String, default='open')  # open, investigating, resolved
    
    def to_dict(self):
        """Convert to dictionary for API responses"""
        return {
            'finding_id': self.finding_id,
            'host': self.host,
            'ip': self.ip,
            'service': self.service,
            'port': self.port,
            'version': self.version,
            'cve': self.cve,
            'cvss': self.cvss,
            'evidence': self.evidence,
            'scan_tool': self.scan_tool,
            'opencti_indicator_id': self.opencti_indicator_id,
            'opencti_vulnerability_id': self.opencti_vulnerability_id,
            'opencti_malware_ids': self.opencti_malware_ids,
            'opencti_attack_patterns': self.opencti_attack_patterns,
            'exploit_available': self.exploit_available,
            'threat_actor_groups': self.threat_actor_groups,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'scan_timestamp': self.scan_timestamp.isoformat() if self.scan_timestamp else None,
            'severity': self.severity,
            'status': self.status
        }

class ScanSession(Base):
    """Track scan sessions for grouping findings"""
    __tablename__ = 'scan_sessions'
    
    session_id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    target = Column(String, nullable=False)
    scan_type = Column(String, nullable=False)
    scan_tool = Column(String, nullable=False)
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime)
    status = Column(String, default='running')  # running, completed, failed
    findings_count = Column(Integer, default=0)

class AttackPath(Base):
    """Store attack paths for Neo4j integration"""
    __tablename__ = 'attack_paths'
    
    path_id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    source_finding_id = Column(String, nullable=False)
    target_finding_id = Column(String, nullable=False)
    attack_technique = Column(String)  # MITRE ATT&CK technique
    path_weight = Column(Float, default=1.0)  # Risk weight
    created_at = Column(DateTime, default=datetime.utcnow)