#!/usr/bin/env python3
"""
Test Neo4j connection for SecureChain
"""

from neo4j import GraphDatabase
import sys

def test_neo4j_connection():
    """Test Neo4j connection"""
    try:
        print("🔧 Testing Neo4j connection...")
        
        # Connect to Neo4j
        driver = GraphDatabase.driver(
            "bolt://localhost:7687",
            auth=("neo4j", "neo4j_password")
        )
        
        # Test connection with a simple query
        with driver.session() as session:
            result = session.run("RETURN 'Hello, Neo4j!' as message")
            message = result.single()["message"]
            print(f"✅ Connected successfully!")
            print(f"📝 Response: {message}")
            
            # Check APOC availability
            try:
                result = session.run("RETURN apoc.version() as version")
                version = result.single()["version"]
                print(f"🔌 APOC Plugin version: {version}")
            except Exception as e:
                print(f"⚠️  APOC Plugin not available: {e}")
            
            # Show database info
            result = session.run("CALL db.info()")
            info = result.single()
            print(f"🗄️  Database: {info.get('name', 'neo4j')}")
        
        driver.close()
        return True
        
    except Exception as e:
        print(f"❌ Neo4j connection failed: {e}")
        return False

if __name__ == "__main__":
    success = test_neo4j_connection()
    sys.exit(0 if success else 1)