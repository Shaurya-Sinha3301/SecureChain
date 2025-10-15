#!/usr/bin/env python3
"""
Debug why OpenCTI enrichment and Neo4j aren't providing value
"""

import os
import sys
from dotenv import load_dotenv

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

load_dotenv()

def test_opencti_enricher():
    """Test OpenCTI enricher directly"""
    print("🔍 Testing OpenCTI Enricher...")
    
    try:
        from services.opencti_enricher import OpenCTIEnricher
        
        opencti_url = os.getenv('OPENCTI_URL', 'http://localhost:8080')
        opencti_token = os.getenv('OPENCTI_TOKEN', '3b2641f7-3232-418c-8365-5454b3953143')
        
        print(f"OpenCTI URL: {opencti_url}")
        print(f"OpenCTI Token: {opencti_token[:20]}...")
        
        enricher = OpenCTIEnricher(opencti_url, opencti_token)
        
        # Test with a real CVE finding
        test_finding = {
            'finding_id': 'test-123',
            'host': 'web-server.local',
            'ip': '192.168.1.200',
            'service': 'http',
            'port': 80,
            'version': 'Apache 2.4.49',
            'cve': 'CVE-2021-41773',
            'cvss': 7.5,
            'evidence': 'Apache HTTP Server 2.4.49 - Path Traversal vulnerability detected',
            'severity': 'High'
        }
        
        print(f"\nTesting enrichment for: {test_finding['cve']}")
        enrichment_data = enricher.enrich_finding(test_finding)
        
        print("Enrichment Results:")
        for key, value in enrichment_data.items():
            print(f"  {key}: {value}")
        
        if enrichment_data:
            print("✅ OpenCTI enrichment is working!")
            return True
        else:
            print("❌ OpenCTI enrichment returned no data")
            return False
            
    except Exception as e:
        print(f"❌ OpenCTI enricher test failed: {e}")
        return False

def test_neo4j_attack_graph():
    """Test Neo4j attack graph functionality"""
    print("\n🔍 Testing Neo4j Attack Graph...")
    
    try:
        from services.database_manager import DatabaseManager
        
        postgres_url = os.getenv('POSTGRES_URL', 'postgresql://securechain:shivam2469@localhost:5432/securechain')
        neo4j_uri = os.getenv('NEO4J_URI', 'bolt://localhost:7687')
        neo4j_user = os.getenv('NEO4J_USER', 'neo4j')
        neo4j_password = os.getenv('NEO4J_PASSWORD', 'neo4j_password')
        
        db_manager = DatabaseManager(
            postgres_url=postgres_url,
            neo4j_uri=neo4j_uri,
            neo4j_user=neo4j_user,
            neo4j_password=neo4j_password
        )
        
        # Test creating meaningful attack graph data
        test_findings = [
            {
                'finding_id': 'test-web-1',
                'host': 'web-server.local',
                'ip': '192.168.1.200',
                'service': 'http',
                'port': 80,
                'cve': 'CVE-2021-41773',
                'severity': 'High',
                'cvss': 7.5
            },
            {
                'finding_id': 'test-ssh-1',
                'host': 'web-server.local',
                'ip': '192.168.1.200',
                'service': 'ssh',
                'port': 22,
                'cve': 'CVE-2018-15473',
                'severity': 'Medium',
                'cvss': 5.3
            }
        ]
        
        print("Creating attack graph nodes...")
        
        # Create nodes with proper types and relationships
        session = db_manager.get_neo4j_session()
        if session:
            # Clear existing test data
            session.run("MATCH (n:Host {ip: '192.168.1.200'}) DETACH DELETE n")
            session.run("MATCH (n:Vulnerability) WHERE n.cve IN ['CVE-2021-41773', 'CVE-2018-15473'] DETACH DELETE n")
            
            # Create host node
            session.run("""
                CREATE (h:Host {
                    ip: '192.168.1.200',
                    hostname: 'web-server.local',
                    risk_score: 8.5
                })
            """)
            
            # Create vulnerability nodes with proper relationships
            for finding in test_findings:
                session.run("""
                    MATCH (h:Host {ip: $ip})
                    CREATE (v:Vulnerability {
                        cve: $cve,
                        service: $service,
                        port: $port,
                        severity: $severity,
                        cvss: $cvss,
                        exploitable: true
                    })
                    CREATE (h)-[:HAS_VULNERABILITY]->(v)
                    CREATE (v)-[:ENABLES_ACCESS {technique: $technique}]->(h)
                """, {
                    'ip': finding['ip'],
                    'cve': finding['cve'],
                    'service': finding['service'],
                    'port': finding['port'],
                    'severity': finding['severity'],
                    'cvss': finding['cvss'],
                    'technique': 'T1190' if finding['service'] == 'http' else 'T1021.004'
                })
            
            # Create attack path
            session.run("""
                MATCH (h:Host {ip: '192.168.1.200'})
                MATCH (v1:Vulnerability {cve: 'CVE-2021-41773'})
                MATCH (v2:Vulnerability {cve: 'CVE-2018-15473'})
                CREATE (v1)-[:LEADS_TO {attack_path: 'Web exploit -> SSH access', risk: 9.0}]->(v2)
            """)
            
            # Query the attack graph
            result = session.run("""
                MATCH (h:Host)-[r1:HAS_VULNERABILITY]->(v:Vulnerability)
                OPTIONAL MATCH (v)-[r2:ENABLES_ACCESS]->(target)
                OPTIONAL MATCH (v)-[r3:LEADS_TO]->(next_vuln)
                RETURN h.hostname as host, h.ip as ip, h.risk_score as risk,
                       v.cve as cve, v.service as service, v.cvss as cvss,
                       r2.technique as technique, r3.attack_path as attack_path
            """)
            
            print("Attack Graph Results:")
            attack_data = []
            for record in result:
                attack_data.append(dict(record))
                print(f"  Host: {record['host']} ({record['ip']}) - Risk: {record['risk']}")
                print(f"    Vuln: {record['cve']} on {record['service']} (CVSS: {record['cvss']})")
                if record['technique']:
                    print(f"    MITRE Technique: {record['technique']}")
                if record['attack_path']:
                    print(f"    Attack Path: {record['attack_path']}")
                print()
            
            session.close()
            
            if attack_data:
                print("✅ Neo4j attack graph is working with meaningful data!")
                return True
            else:
                print("❌ Neo4j attack graph has no meaningful data")
                return False
        else:
            print("❌ Neo4j session not available")
            return False
            
    except Exception as e:
        print(f"❌ Neo4j attack graph test failed: {e}")
        return False

def test_ingestion_service_integration():
    """Test if the ingestion service is properly using enrichment"""
    print("\n🔍 Testing Ingestion Service Integration...")
    
    try:
        from services.database_manager import DatabaseManager
        from services.opencti_enricher import OpenCTIEnricher
        from services.ingestion_service import IngestionService
        
        # Initialize services
        postgres_url = os.getenv('POSTGRES_URL', 'postgresql://securechain:shivam2469@localhost:5432/securechain')
        neo4j_uri = os.getenv('NEO4J_URI', 'bolt://localhost:7687')
        neo4j_user = os.getenv('NEO4J_USER', 'neo4j')
        neo4j_password = os.getenv('NEO4J_PASSWORD', 'neo4j_password')
        
        db_manager = DatabaseManager(
            postgres_url=postgres_url,
            neo4j_uri=neo4j_uri,
            neo4j_user=neo4j_user,
            neo4j_password=neo4j_password
        )
        
        opencti_url = os.getenv('OPENCTI_URL', 'http://localhost:8080')
        opencti_token = os.getenv('OPENCTI_TOKEN', '3b2641f7-3232-418c-8365-5454b3953143')
        
        opencti_enricher = OpenCTIEnricher(opencti_url, opencti_token)
        
        ingestion_service = IngestionService(
            db_manager=db_manager,
            opencti_enricher=opencti_enricher
        )
        
        print(f"Ingestion service has OpenCTI enricher: {ingestion_service.opencti_enricher is not None}")
        
        # Test with real vulnerability data
        scan_results = {
            "findings": [
                {
                    "host": "test-server.local",
                    "ip": "192.168.1.250",
                    "service": "http",
                    "port": 80,
                    "version": "Apache 2.4.49",
                    "cve": "CVE-2021-41773",
                    "cvss": 7.5,
                    "evidence": "Apache path traversal vulnerability",
                    "severity": "High"
                }
            ]
        }
        
        print("Processing scan results with enrichment...")
        result = ingestion_service.process_scan_results(
            scan_results=scan_results,
            scan_tool="test",
            target="192.168.1.250"
        )
        
        print(f"Processing result: {result}")
        
        if result['success']:
            print("✅ Ingestion service integration working!")
            return True
        else:
            print(f"❌ Ingestion service failed: {result.get('error')}")
            return False
            
    except Exception as e:
        print(f"❌ Ingestion service integration test failed: {e}")
        return False

def main():
    print("🚀 Debugging OpenCTI and Neo4j Integration")
    print("=" * 50)
    
    # Test OpenCTI enricher
    opencti_ok = test_opencti_enricher()
    
    # Test Neo4j attack graph
    neo4j_ok = test_neo4j_attack_graph()
    
    # Test ingestion service integration
    integration_ok = test_ingestion_service_integration()
    
    print("=" * 50)
    print("📊 Debug Results:")
    print(f"   OpenCTI Enrichment: {'✅' if opencti_ok else '❌'}")
    print(f"   Neo4j Attack Graph: {'✅' if neo4j_ok else '❌'}")
    print(f"   Integration: {'✅' if integration_ok else '❌'}")
    
    if opencti_ok and neo4j_ok and integration_ok:
        print("\n🎉 All integrations should now provide real value!")
    else:
        print("\n⚠️  Some integrations need fixes to provide value.")

if __name__ == "__main__":
    main()