# SecureChain Backend - Integrated Vulnerability Management

A comprehensive vulnerability management backend with normalization, OpenCTI enrichment, PostgreSQL storage, and Neo4j attack graph generation.

## Features

- **Finding Normalization**: Convert raw scan results from various tools into structured findings
- **OpenCTI Integration**: Enrich findings with threat intelligence, CVE data, and MITRE ATT&CK mappings
- **PostgreSQL Storage**: Store normalized and enriched findings with full metadata
- **Neo4j Attack Graphs**: Generate attack paths and visualizations based on findings
- **RESTful API**: Complete API for ingestion, retrieval, and management
- **Background Processing**: Async processing for large scan results

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Scan Tools    │───▶│   Normalization  │───▶│   OpenCTI       │
│  (Nmap, Nikto)  │    │    Service       │    │  Enrichment     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │                        │
                                ▼                        ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│     Neo4j       │◀───│   PostgreSQL     │◀───│   Ingestion     │
│ Attack Graphs   │    │   Findings DB    │    │    Service      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## Quick Start

### 1. Environment Setup

```bash
# Copy environment template
cp .env.example .env

# Edit configuration
nano .env
```

### 2. Database Setup (Docker)

```bash
# Start all services
docker-compose up -d

# Check service status
docker-compose ps
```

### 3. Manual Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Start PostgreSQL
sudo systemctl start postgresql

# Start Neo4j
sudo systemctl start neo4j

# Start Redis
sudo systemctl start redis
```

### 4. Run the Backend

```bash
# Development mode
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Production mode
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
```

## API Endpoints

### Ingestion

- `POST /api/v1/ingestion/scan-results` - Ingest scan results (async)
- `POST /api/v1/ingestion/scan-results/sync` - Ingest scan results (sync)

### Findings Management

- `GET /api/v1/ingestion/findings` - List findings with filters
- `GET /api/v1/ingestion/findings/{id}` - Get specific finding
- `PUT /api/v1/ingestion/findings/{id}/status` - Update finding status
- `POST /api/v1/ingestion/findings/{id}/enrich` - Re-enrich finding
- `DELETE /api/v1/ingestion/findings/{id}` - Delete finding

### Attack Graph

- `GET /api/v1/ingestion/attack-graph` - Get attack graph data

### Statistics

- `GET /api/v1/ingestion/stats` - Get ingestion statistics

## Usage Examples

### 1. Ingest Nmap Results

```python
import requests
import json

# Nmap scan results
nmap_results = {
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
            },
            {
                "portid": "80",
                "protocol": "tcp", 
                "state": "open",
                "service": {
                    "name": "http",
                    "product": "Apache",
                    "version": "2.4.41"
                }
            }
        ]
    }
}

# Send to ingestion API
response = requests.post(
    "http://localhost:8000/api/v1/ingestion/scan-results",
    json={
        "scan_results": nmap_results,
        "scan_tool": "nmap",
        "target": "192.168.1.100"
    }
)

print(response.json())
```

### 2. Query Findings

```python
# Get all findings
response = requests.get("http://localhost:8000/api/v1/ingestion/findings")
findings = response.json()

# Filter by severity
response = requests.get(
    "http://localhost:8000/api/v1/ingestion/findings?severity=High&limit=50"
)
high_severity = response.json()

# Get specific finding
finding_id = findings[0]["finding_id"]
response = requests.get(f"http://localhost:8000/api/v1/ingestion/findings/{finding_id}")
finding_detail = response.json()
```

### 3. Get Attack Graph

```python
# Retrieve attack graph data
response = requests.get("http://localhost:8000/api/v1/ingestion/attack-graph")
graph_data = response.json()

nodes = graph_data["nodes"]
edges = graph_data["edges"]

# Process for visualization
for node in nodes:
    print(f"Node: {node}")

for edge in edges:
    print(f"Attack Path: {edge['source']} -> {edge['target']} ({edge['relationship']})")
```

## Integration with AI-Vuln-Scanner

To integrate with the existing AI-Vuln-Scanner, modify the scanner to send results to the ingestion API:

```python
# Add to vulnscanner.py after analysis
def send_to_ingestion_service(analyze, target, scan_tool="nmap"):
    """Send scan results to SecureChain backend"""
    import requests
    
    try:
        response = requests.post(
            "http://localhost:8000/api/v1/ingestion/scan-results",
            json={
                "scan_results": analyze,
                "scan_tool": scan_tool,
                "target": target
            },
            timeout=60
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Ingested {result['findings_processed']} findings")
            return result
        else:
            print(f"❌ Ingestion failed: {response.text}")
            
    except Exception as e:
        print(f"❌ Failed to send to ingestion service: {e}")
    
    return None

# Add after vulnerability analysis
ingestion_result = send_to_ingestion_service(analyze, target, "nmap")
```

## Database Schema

### PostgreSQL Tables

#### vulnerability_findings
- `finding_id` (UUID, Primary Key)
- `host` (String)
- `ip` (String) 
- `service` (String)
- `port` (Integer)
- `version` (String)
- `cve` (String)
- `cvss` (Float)
- `evidence` (Text)
- `scan_tool` (String)
- `severity` (String)
- `status` (String)
- `created_at` (DateTime)
- `updated_at` (DateTime)
- OpenCTI enrichment fields...

### Neo4j Graph Schema

#### Nodes
- `Vulnerability`: Individual findings
- `Host`: Target systems
- `Service`: Running services

#### Relationships
- `AFFECTS`: Vulnerability affects Host
- `RUNS_ON`: Service runs on Host
- `ATTACK_PATH`: Attack progression between vulnerabilities

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `POSTGRES_URL` | PostgreSQL connection string | `postgresql://user:pass@localhost:5432/db` |
| `NEO4J_URI` | Neo4j connection URI | `bolt://localhost:7687` |
| `NEO4J_USER` | Neo4j username | `neo4j` |
| `NEO4J_PASSWORD` | Neo4j password | `password` |
| `OPENCTI_URL` | OpenCTI platform URL | `http://localhost:8080` |
| `OPENCTI_TOKEN` | OpenCTI API token | Required for enrichment |

### OpenCTI Setup

1. Deploy OpenCTI using the provided docker-compose
2. Access web interface at http://localhost:8080
3. Generate API token in Settings > API Access
4. Configure token in environment variables

## Development

### Running Tests

```bash
# Install test dependencies
pip install pytest pytest-asyncio httpx

# Run tests
pytest tests/

# Run with coverage
pytest --cov=. tests/
```

### Code Quality

```bash
# Format code
black .

# Lint code
flake8 .

# Type checking
mypy .
```

## Monitoring and Logging

### Health Checks

```bash
# Check overall health
curl http://localhost:8000/health

# Check configuration
curl http://localhost:8000/api/v1/config

# Get statistics
curl http://localhost:8000/api/v1/ingestion/stats
```

### Logs

Logs are structured and include:
- Request/response details
- Database operations
- OpenCTI enrichment status
- Attack graph generation
- Error tracking

## Troubleshooting

### Common Issues

1. **Database Connection Failed**
   - Check PostgreSQL/Neo4j are running
   - Verify connection strings in .env
   - Check firewall settings

2. **OpenCTI Enrichment Not Working**
   - Verify OpenCTI URL and token
   - Check OpenCTI platform status
   - Review API token permissions

3. **Attack Graph Empty**
   - Ensure Neo4j is running
   - Check Neo4j authentication
   - Verify findings have been processed

### Debug Mode

```bash
# Enable debug logging
export LOG_LEVEL=DEBUG

# Run with detailed output
uvicorn main:app --reload --log-level debug
```

## Contributing

1. Fork the repository
2. Create feature branch
3. Add tests for new functionality
4. Ensure code quality checks pass
5. Submit pull request

## License

MIT License - see LICENSE file for details.