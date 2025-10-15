#!/usr/bin/env python3
"""
Test database connections for SecureChain
Tests both PostgreSQL and Neo4j connectivity
"""

import os
import sys
import psycopg2
from neo4j import GraphDatabase
import requests
from datetime import datetime

def test_postgresql():
    """Test PostgreSQL connection"""
    print("🐘 Testing PostgreSQL connection...")
    
    try:
        # Connection parameters
        conn_params = {
            'host': '127.0.0.1',
            'port': 5432,
            'database': 'securechain',
            'user': 'securechain',
            'password': 'shivam2469'
        }
        
        # Connect to PostgreSQL
        conn = psycopg2.connect(**conn_params)
        cursor = conn.cursor()
        
        # Test basic query
        cursor.execute("SELECT version();")
        version = cursor.fetchone()[0]
        print(f"   ✅ Connected to PostgreSQL: {version}")
        
        # Test SecureChain tables
        cursor.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public' 
            AND table_name IN ('vulnerability_findings', 'scan_sessions', 'attack_paths')
        """)
        tables = cursor.fetchall()
        
        if len(tables) == 3:
            print("   ✅ All SecureChain tables exist")
        else:
            print(f"   ⚠️ Only {len(tables)}/3 SecureChain tables found")
            for table in tables:
                print(f"      - {table[0]}")
        
        # Test sample data
        cursor.execute("SELECT COUNT(*) FROM vulnerability_findings;")
        count = cursor.fetchone()[0]
        print(f"   📊 Vulnerability findings count: {count}")
        
        # Test indexes
        cursor.execute("""
            SELECT indexname 
            FROM pg_indexes 
            WHERE tablename = 'vulnerability_findings'
        """)
        indexes = cursor.fetchall()
        print(f"   📇 Indexes on vulnerability_findings: {len(indexes)}")
        
        cursor.close()
        conn.close()
        
        return True
        
    except psycopg2.Error as e:
        print(f"   ❌ PostgreSQL connection failed: {e}")
        return False
    except Exception as e:
        print(f"   ❌ Unexpected error: {e}")
        return False

def test_neo4j():
    """Test Neo4j connection"""
    print("\n🔗 Testing Neo4j connection...")
    
    try:
        # Connection parameters
        uri = "bolt://localhost:7687"
        username = "neo4j"
        password = "neo4j_password"
        
        # Connect to Neo4j
        driver = GraphDatabase.driver(uri, auth=(username, password))
        
        with driver.session() as session:
            # Test basic query
            result = session.run("CALL dbms.components() YIELD name, versions, edition")
            components = result.single()
            print(f"   ✅ Connected to Neo4j: {components['name']} {components['versions'][0]} ({components['edition']})")
            
            # Test constraints
            result = session.run("SHOW CONSTRAINTS")
            constraints = list(result)
            print(f"   🔒 Constraints: {len(constraints)}")
            
            # Test indexes
            result = session.run("SHOW INDEXES")
            indexes = list(result)
            print(f"   📇 Indexes: {len(indexes)}")
            
            # Test sample data
            result = session.run("MATCH (n) RETURN labels(n) as labels, count(n) as count")
            nodes = list(result)
            
            if nodes:
                print("   📊 Node counts by label:")
                for record in nodes:
                    labels = record['labels']
                    count = record['count']
                    print(f"      - {':'.join(labels)}: {count}")
            else:
                print("   📊 No nodes found in database")
            
            # Test relationships
            result = session.run("MATCH ()-[r]->() RETURN type(r) as type, count(r) as count")
            relationships = list(result)
            
            if relationships:
                print("   🔗 Relationship counts by type:")
                for record in relationships:
                    rel_type = record['type']
                    count = record['count']
                    print(f"      - {rel_type}: {count}")
            else:
                print("   🔗 No relationships found in database")
        
        driver.close()
        return True
        
    except Exception as e:
        print(f"   ❌ Neo4j connection failed: {e}")
        return False

def test_neo4j_http():
    """Test Neo4j HTTP interface"""
    print("\n🌐 Testing Neo4j HTTP interface...")
    
    try:
        # Test Neo4j Browser
        response = requests.get("http://localhost:7474", timeout=5)
        if response.status_code == 200:
            print("   ✅ Neo4j Browser accessible at http://localhost:7474")
        else:
            print(f"   ❌ Neo4j Browser returned status {response.status_code}")
            return False
        
        # Test REST API
        import base64
        auth_string = base64.b64encode(b"neo4j:neo4j_password").decode('ascii')
        headers = {
            'Authorization': f'Basic {auth_string}',
            'Content-Type': 'application/json'
        }
        
        data = {
            "statements": [
                {
                    "statement": "RETURN 'Hello Neo4j!' as message"
                }
            ]
        }
        
        response = requests.post(
            "http://localhost:7474/db/data/transaction/commit",
            json=data,
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            if result.get('errors'):
                print(f"   ❌ Neo4j REST API returned errors: {result['errors']}")
                return False
            else:
                print("   ✅ Neo4j REST API is working")
                return True
        else:
            print(f"   ❌ Neo4j REST API returned status {response.status_code}")
            return False
            
    except requests.RequestException as e:
        print(f"   ❌ Neo4j HTTP test failed: {e}")
        return False
    except Exception as e:
        print(f"   ❌ Unexpected error: {e}")
        return False

def test_integration():
    """Test integration between databases"""
    print("\n🔄 Testing database integration...")
    
    try:
        # Test PostgreSQL -> Neo4j data flow simulation
        conn = psycopg2.connect(
            host='127.0.0.1',
            port=5432,
            database='securechain',
            user='securechain',
            password='shivam2469'
        )
        cursor = conn.cursor()
        
        # Get a sample finding from PostgreSQL
        cursor.execute("""
            SELECT finding_id, host, ip, service, port, severity 
            FROM vulnerability_findings 
            LIMIT 1
        """)
        finding = cursor.fetchone()
        
        if finding:
            finding_id, host, ip, service, port, severity = finding
            print(f"   📊 Sample finding from PostgreSQL: {finding_id}")
            
            # Check if corresponding node exists in Neo4j
            driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "neo4j_password"))
            with driver.session() as session:
                result = session.run(
                    "MATCH (v:Vulnerability {finding_id: $finding_id}) RETURN v",
                    finding_id=finding_id
                )
                neo4j_node = result.single()
                
                if neo4j_node:
                    print("   ✅ Corresponding node found in Neo4j")
                else:
                    print("   ⚠️ No corresponding node found in Neo4j (this is expected if data hasn't been synced)")
            
            driver.close()
        else:
            print("   ⚠️ No sample data found in PostgreSQL")
        
        cursor.close()
        conn.close()
        
        return True
        
    except Exception as e:
        print(f"   ❌ Integration test failed: {e}")
        return False

def main():
    """Main test function"""
    print("🧪 SecureChain Database Connection Tests")
    print("=" * 50)
    print(f"Test started at: {datetime.now()}")
    
    # Test results
    results = {
        'postgresql': False,
        'neo4j': False,
        'neo4j_http': False,
        'integration': False
    }
    
    # Run tests
    results['postgresql'] = test_postgresql()
    results['neo4j'] = test_neo4j()
    results['neo4j_http'] = test_neo4j_http()
    results['integration'] = test_integration()
    
    # Summary
    print("\n" + "=" * 50)
    print("📋 Test Summary:")
    
    passed = sum(results.values())
    total = len(results)
    
    for test_name, passed_test in results.items():
        status = "✅ PASS" if passed_test else "❌ FAIL"
        print(f"   {test_name.replace('_', ' ').title()}: {status}")
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All database tests passed! SecureChain is ready to use.")
        return 0
    else:
        print("⚠️ Some tests failed. Please check the database setup.")
        return 1

if __name__ == "__main__":
    # Check if required packages are installed
    try:
        import psycopg2
        import neo4j
        import requests
    except ImportError as e:
        print(f"❌ Missing required package: {e}")
        print("Please install with: pip install psycopg2-binary neo4j requests")
        sys.exit(1)
    
    sys.exit(main())