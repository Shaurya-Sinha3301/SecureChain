// Neo4j initialization script for SecureChain
// This script creates constraints, indexes, and initial schema

// Create constraints for unique identifiers
CREATE CONSTRAINT vulnerability_finding_id IF NOT EXISTS
FOR (v:Vulnerability) REQUIRE v.finding_id IS UNIQUE;

CREATE CONSTRAINT host_ip IF NOT EXISTS
FOR (h:Host) REQUIRE h.ip IS UNIQUE;

CREATE CONSTRAINT service_id IF NOT EXISTS
FOR (s:Service) REQUIRE s.id IS UNIQUE;

CREATE CONSTRAINT attack_pattern_id IF NOT EXISTS
FOR (a:AttackPattern) REQUIRE a.mitre_id IS UNIQUE;

CREATE CONSTRAINT malware_id IF NOT EXISTS
FOR (m:Malware) REQUIRE m.opencti_id IS UNIQUE;

CREATE CONSTRAINT threat_actor_id IF NOT EXISTS
FOR (t:ThreatActor) REQUIRE t.opencti_id IS UNIQUE;

// Create indexes for performance
CREATE INDEX vulnerability_severity IF NOT EXISTS
FOR (v:Vulnerability) ON (v.severity);

CREATE INDEX vulnerability_cvss IF NOT EXISTS
FOR (v:Vulnerability) ON (v.cvss);

CREATE INDEX vulnerability_cve IF NOT EXISTS
FOR (v:Vulnerability) ON (v.cve);

CREATE INDEX vulnerability_service IF NOT EXISTS
FOR (v:Vulnerability) ON (v.service);

CREATE INDEX vulnerability_port IF NOT EXISTS
FOR (v:Vulnerability) ON (v.port);

CREATE INDEX host_hostname IF NOT EXISTS
FOR (h:Host) ON (h.hostname);

CREATE INDEX service_name IF NOT EXISTS
FOR (s:Service) ON (s.name);

CREATE INDEX attack_pattern_name IF NOT EXISTS
FOR (a:AttackPattern) ON (a.name);

// Create composite indexes for common queries
CREATE INDEX vulnerability_host_service IF NOT EXISTS
FOR (v:Vulnerability) ON (v.host, v.service);

CREATE INDEX vulnerability_severity_cvss IF NOT EXISTS
FOR (v:Vulnerability) ON (v.severity, v.cvss);

// Print success message
CALL apoc.log.info("SecureChain Neo4j constraints and indexes created successfully!");

// Create sample data structure (will be populated by application)
// This creates the basic schema structure

// Create sample vulnerability node
MERGE (v:Vulnerability {
    finding_id: "sample-vuln-001",
    host: "test.local",
    ip: "192.168.1.100",
    service: "ssh",
    port: 22,
    version: "OpenSSH 8.9p1",
    cve: "CVE-2023-1234",
    cvss: 7.5,
    evidence: "Sample vulnerability for schema creation",
    scan_tool: "nmap",
    severity: "High",
    created_at: datetime(),
    exploit_available: true
});

// Create sample host node
MERGE (h:Host {
    ip: "192.168.1.100",
    hostname: "test.local",
    os: "Ubuntu 20.04",
    created_at: datetime()
});

// Create sample service node
MERGE (s:Service {
    id: "ssh-192.168.1.100-22",
    name: "ssh",
    port: 22,
    version: "OpenSSH 8.9p1",
    protocol: "tcp",
    created_at: datetime()
});

// Create sample attack pattern node
MERGE (a:AttackPattern {
    mitre_id: "T1021.004",
    name: "Remote Services: SSH",
    description: "Adversaries may use Valid Accounts to log into remote machines using Secure Shell (SSH).",
    tactic: "Lateral Movement",
    created_at: datetime()
});

// Create sample malware node
MERGE (m:Malware {
    opencti_id: "malware-sample-001",
    name: "Sample Malware",
    family: "Backdoor",
    description: "Sample malware for schema creation",
    created_at: datetime()
});

// Create sample threat actor node
MERGE (t:ThreatActor {
    opencti_id: "threat-actor-sample-001",
    name: "Sample APT Group",
    description: "Sample threat actor for schema creation",
    sophistication: "expert",
    created_at: datetime()
});

// Create relationships
MATCH (v:Vulnerability {finding_id: "sample-vuln-001"})
MATCH (h:Host {ip: "192.168.1.100"})
MERGE (v)-[:AFFECTS]->(h);

MATCH (v:Vulnerability {finding_id: "sample-vuln-001"})
MATCH (s:Service {id: "ssh-192.168.1.100-22"})
MERGE (v)-[:TARGETS]->(s);

MATCH (s:Service {id: "ssh-192.168.1.100-22"})
MATCH (h:Host {ip: "192.168.1.100"})
MERGE (s)-[:RUNS_ON]->(h);

MATCH (v:Vulnerability {finding_id: "sample-vuln-001"})
MATCH (a:AttackPattern {mitre_id: "T1021.004"})
MERGE (v)-[:ENABLES {confidence: 85}]->(a);

MATCH (v:Vulnerability {finding_id: "sample-vuln-001"})
MATCH (m:Malware {opencti_id: "malware-sample-001"})
MERGE (v)-[:EXPLOITED_BY {confidence: 70}]->(m);

MATCH (m:Malware {opencti_id: "malware-sample-001"})
MATCH (t:ThreatActor {opencti_id: "threat-actor-sample-001"})
MERGE (m)-[:USED_BY]->(t);

MATCH (a:AttackPattern {mitre_id: "T1021.004"})
MATCH (t:ThreatActor {opencti_id: "threat-actor-sample-001"})
MERGE (t)-[:USES]->(a);

// Create attack path relationships between vulnerabilities
// This will be expanded when more vulnerabilities are added
MATCH (v1:Vulnerability {finding_id: "sample-vuln-001"})
WITH v1
// Create a self-referencing attack path for demonstration
MERGE (v1)-[:ATTACK_PATH {
    technique: "T1021.004",
    weight: 0.8,
    description: "SSH lateral movement",
    created_at: datetime()
}]->(v1);

// Print schema information
CALL db.schema.visualization();

CALL apoc.log.info("SecureChain Neo4j schema created successfully!");
CALL apoc.log.info("Sample nodes and relationships created for testing");
CALL apoc.log.info("Ready for vulnerability data ingestion");

// Show created nodes count
MATCH (n) 
RETURN labels(n) as NodeType, count(n) as Count
ORDER BY NodeType;