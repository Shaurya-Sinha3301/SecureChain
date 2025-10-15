# SecureChain Data Flow Architecture

## 🔄 Complete Data Flow Overview

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                           SECURECHAIN DATA FLOW ARCHITECTURE                        │
└─────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│                 │    │                  │    │                 │    │                 │
│  AI-Vuln-       │───▶│  Integration     │───▶│  Ingestion      │───▶│  Finding        │
│  Scanner        │    │  Client          │    │  API            │    │  Normalizer     │
│                 │    │                  │    │                 │    │                 │
│ • Nmap Results  │    │ • HTTP POST      │    │ • FastAPI       │    │ • Structure     │
│ • Nikto Results │    │ • JSON Payload   │    │ • Validation    │    │ • Validate      │
│ • Custom Scans  │    │ • Error Handling │    │ • Async Support │    │ • Extract CVEs  │
└─────────────────┘    └──────────────────┘    └─────────────────┘    └─────────────────┘
                                                        │                        │
                                                        ▼                        ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│                 │    │                  │    │                 │    │                 │
│  Neo4j          │◀───│  Attack Graph    │◀───│  PostgreSQL     │◀───│  OpenCTI        │
│  Database       │    │  Generator       │    │  Database       │    │  Enricher       │
│                 │    │                  │    │                 │    │                 │
│ • Nodes         │    │ • MITRE ATT&CK   │    │ • Findings      │    │ • CVE Intel     │
│ • Relationships │    │ • Attack Paths   │    │ • Metadata      │    │ • Threat Actors │
│ • Graph Queries │    │ • Risk Scoring   │    │ • OpenCTI IDs   │    │ • Exploits      │
└─────────────────┘    └──────────────────┘    └─────────────────┘    └─────────────────┘
```

## 📊 Detailed Data Flow Steps

### Step 1: Scan Execution
```
AI-Vuln-Scanner (vulnscanner.py)
├── Executes nmap scan
├── Performs AI analysis
├── Generates vulnerability report
└── Calls integration_client.py
```

### Step 2: Data Integration
```
Integration Client (integration_client.py)
├── Receives raw scan results
├── Formats for API consumption
├── Sends HTTP POST to backend
└── Handles response/errors
```

### Step 3: API Ingestion
```
Ingestion API (ingestion_endpoints.py)
├── Validates incoming data
├── Triggers ingestion workflow
├── Returns processing status
└── Supports async/sync modes
```

### Step 4: Finding Normalization
```
Finding Normalizer (finding_normalizer.py)
├── Converts raw scan data to structured findings
├── Extracts: finding_id, host, ip, service, port, version, cve, cvss, evidence, scan_tool
├── Assesses severity levels
└── Validates required fields
```

### Step 5: OpenCTI Enrichment
```
OpenCTI Enricher (opencti_enricher.py)
├── Queries OpenCTI for CVE intelligence
├── Retrieves threat actor associations
├── Maps MITRE ATT&CK techniques
├── Checks exploit availability
└── Adds OpenCTI object IDs
```

### Step 6: PostgreSQL Storage
```
Database Manager (database_manager.py)
├── Stores normalized findings
├── Includes OpenCTI enrichment data
├── Maintains finding relationships
└── Supports CRUD operations
```

### Step 7: Neo4j Attack Graph
```
Attack Graph Generator (ingestion_service.py)
├── Creates vulnerability nodes
├── Creates host nodes
├── Establishes relationships
├── Generates attack paths
└── Applies MITRE ATT&CK mapping
```

## 🗃️ Data Structures

### Raw Scan Input
```json
{
  "192.168.1.100": {
    "hostname": [{"name": "target.local"}],
    "ports": [
      {
        "portid": "22",
        "protocol": "tcp",
        "state": "open",
        "service": {
          "name": "ssh",
          "product": "OpenSSH",
          "version": "8.9p1"
        }
      }
    ]
  }
}
```

### Normalized Finding
```json
{
  "finding_id": "uuid-123",
  "host": "target.local",
  "ip": "192.168.1.100",
  "service": "ssh",
  "port": 22,
  "version": "OpenSSH 8.9p1",
  "cve": "CVE-2023-1234",
  "cvss": 7.5,
  "evidence": "Open TCP port 22 running ssh (OpenSSH 8.9p1)",
  "scan_tool": "nmap",
  "severity": "High",
  "scan_timestamp": "2024-01-01T12:00:00Z"
}
```

### OpenCTI Enriched Finding
```json
{
  "finding_id": "uuid-123",
  "host": "target.local",
  "ip": "192.168.1.100",
  "service": "ssh",
  "port": 22,
  "version": "OpenSSH 8.9p1",
  "cve": "CVE-2023-1234",
  "cvss": 7.5,
  "evidence": "Open TCP port 22 running ssh (OpenSSH 8.9p1)",
  "scan_tool": "nmap",
  "severity": "High",
  "opencti_indicator_id": "indicator-uuid-456",
  "opencti_vulnerability_id": "vuln-uuid-789",
  "opencti_malware_ids": ["malware-uuid-101"],
  "opencti_attack_patterns": [
    {
      "name": "Remote Services: SSH",
      "mitre_id": "T1021.004",
      "confidence": 85
    }
  ],
  "exploit_available": true,
  "threat_actor_groups": [
    {
      "id": "actor-uuid-202",
      "name": "APT29"
    }
  ]
}
```

### Neo4j Graph Structure
```cypher
// Vulnerability Node
CREATE (v:Vulnerability {
  finding_id: "uuid-123",
  host: "target.local",
  ip: "192.168.1.100",
  service: "ssh",
  port: 22,
  cve: "CVE-2023-1234",
  cvss: 7.5,
  severity: "High"
})

// Host Node
CREATE (h:Host {
  ip: "192.168.1.100",
  hostname: "target.local"
})

// Relationship
CREATE (v)-[:AFFECTS]->(h)

// Attack Path
CREATE (v1)-[:ATTACK_PATH {
  technique: "T1021.004",
  weight: 0.8
}]->(v2)
```

## 🔄 Data Transformation Pipeline

### 1. Raw → Normalized
```
Nmap Output:
{
  "192.168.1.100": {
    "ports": [{"portid": "22", "state": "open", "service": {"name": "ssh"}}]
  }
}

↓ Finding Normalizer ↓

Normalized Finding:
{
  "finding_id": "generated-uuid",
  "host": "192.168.1.100",
  "ip": "192.168.1.100",
  "service": "ssh",
  "port": 22,
  "scan_tool": "nmap"
}
```

### 2. Normalized → Enriched
```
Normalized Finding:
{
  "cve": "CVE-2023-1234",
  "service": "ssh"
}

↓ OpenCTI Enricher ↓

Enriched Finding:
{
  "cve": "CVE-2023-1234",
  "service": "ssh",
  "opencti_vulnerability_id": "vuln-123",
  "exploit_available": true,
  "opencti_attack_patterns": [{"mitre_id": "T1021.004"}]
}
```

### 3. Enriched → Stored
```
Enriched Finding → PostgreSQL Table:
vulnerability_findings {
  finding_id: "uuid-123",
  host: "target.local",
  cve: "CVE-2023-1234",
  opencti_vulnerability_id: "vuln-123",
  created_at: "2024-01-01T12:00:00Z"
}
```

### 4. Stored → Graph
```
PostgreSQL Finding → Neo4j Nodes:
(:Vulnerability {finding_id: "uuid-123"})
(:Host {ip: "192.168.1.100"})
(:Vulnerability)-[:AFFECTS]->(:Host)
```

## 🌊 Data Flow Sequence

```
1. User runs: python vulnscanner.py -t 192.168.1.100
2. Scanner executes nmap scan
3. AI analyzes results
4. integration_client.py sends to backend API
5. API validates and triggers ingestion workflow
6. Finding normalizer structures the data
7. OpenCTI enricher adds threat intelligence
8. PostgreSQL stores enriched findings
9. Neo4j creates attack graph nodes/relationships
10. User can query findings via API
11. Attack graph available for visualization
```

## 📈 Data Volume Expectations

### Per Scan Session
- **Input**: 1 nmap scan result (1-50 open ports)
- **Normalized**: 1-50 findings
- **Enriched**: 1-50 findings + OpenCTI data
- **Stored**: 1-50 PostgreSQL records
- **Graph**: 1-50 Neo4j nodes + relationships

### Database Growth
- **PostgreSQL**: ~1KB per finding
- **Neo4j**: ~500 bytes per node + relationships
- **OpenCTI**: Shared threat intelligence (no duplication)

## 🔍 Query Capabilities

### PostgreSQL Queries
```sql
-- Get all high severity findings
SELECT * FROM vulnerability_findings WHERE severity = 'High';

-- Get findings with exploits available
SELECT * FROM vulnerability_findings WHERE exploit_available = true;

-- Get findings by scan tool
SELECT * FROM vulnerability_findings WHERE scan_tool = 'nmap';
```

### Neo4j Queries
```cypher
// Find attack paths
MATCH (v1:Vulnerability)-[:ATTACK_PATH]->(v2:Vulnerability)
RETURN v1, v2;

// Find vulnerabilities affecting specific host
MATCH (v:Vulnerability)-[:AFFECTS]->(h:Host {ip: "192.168.1.100"})
RETURN v;

// Find shortest attack path
MATCH path = shortestPath((v1:Vulnerability)-[*]-(v2:Vulnerability))
RETURN path;
```

### API Queries
```bash
# Get all findings
curl "http://localhost:8001/api/v1/ingestion/findings"

# Filter by severity
curl "http://localhost:8001/api/v1/ingestion/findings?severity=High"

# Get attack graph
curl "http://localhost:8001/api/v1/ingestion/attack-graph"
```

## 🎯 Key Benefits of This Architecture

1. **Separation of Concerns**: Each component has a specific responsibility
2. **Scalability**: Can handle multiple scan tools and large datasets
3. **Enrichment**: Adds valuable threat intelligence context
4. **Flexibility**: Supports various output formats and integrations
5. **Visualization Ready**: Neo4j enables attack graph visualization
6. **API-First**: Everything accessible via REST API
7. **Extensible**: Easy to add new scan tools or enrichment sources

This architecture provides a complete pipeline from raw vulnerability scans to actionable threat intelligence with attack graph visualization capabilities.