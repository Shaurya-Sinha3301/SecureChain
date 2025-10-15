#!/usr/bin/env python3
"""
Test script to verify backend can start properly
"""

import sys
import os

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    """Test if all imports work correctly"""
    try:
        print("🔧 Testing backend imports...")
        
        # Test service imports
        from services.database_manager import DatabaseManager
        print("✅ DatabaseManager imported successfully")
        
        from services.opencti_enricher import OpenCTIEnricher
        print("✅ OpenCTIEnricher imported successfully")
        
        from services.ingestion_service import IngestionService
        print("✅ IngestionService imported successfully")
        
        # Test API imports
        from api.ingestion_endpoints import router
        print("✅ API router imported successfully")
        
        # Test main app import
        from main import app
        print("✅ FastAPI app imported successfully")
        
        print("🎉 All imports successful!")
        return True
        
    except Exception as e:
        print(f"❌ Import failed: {e}")
        return False

def test_database_connection():
    """Test database connections"""
    try:
        print("\n🔧 Testing database connections...")
        
        from services.database_manager import DatabaseManager
        
        # Test with environment variables
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
        
        # Test PostgreSQL
        from sqlalchemy import text
        session = db_manager.get_postgres_session()
        session.execute(text("SELECT 1"))
        session.close()
        print("✅ PostgreSQL connection successful")
        
        # Test Neo4j
        neo4j_session = db_manager.get_neo4j_session()
        if neo4j_session:
            neo4j_session.run("RETURN 1")
            neo4j_session.close()
            print("✅ Neo4j connection successful")
        
        db_manager.close()
        print("🎉 All database connections successful!")
        return True
        
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        return False

if __name__ == "__main__":
    print("🚀 Testing SecureChain Backend...")
    
    # Load environment variables
    from dotenv import load_dotenv
    load_dotenv()
    
    success = True
    
    # Test imports
    if not test_imports():
        success = False
    
    # Test database connections
    if not test_database_connection():
        success = False
    
    if success:
        print("\n🎉 Backend is ready to start!")
        print("Run: python main.py or uvicorn main:app --reload")
    else:
        print("\n❌ Backend has issues that need to be resolved")
    
    sys.exit(0 if success else 1)