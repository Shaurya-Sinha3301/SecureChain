#!/usr/bin/env python3
"""
Database initialization script for SecureChain
Runs the PostgreSQL initialization SQL script
"""

import psycopg2
import sys
import os

def init_database():
    """Initialize the PostgreSQL database with schema"""
    try:
        print("🔧 Initializing SecureChain PostgreSQL database...")
        
        # Connect to PostgreSQL
        conn = psycopg2.connect(
            host='127.0.0.1',
            port=5432,
            database='securechain',
            user='securechain',
            password='shivam2469'
        )
        
        # Enable autocommit for DDL operations
        conn.autocommit = True
        cursor = conn.cursor()
        
        # Read and execute the initialization script
        script_path = os.path.join(os.path.dirname(__file__), 
                                 'database-setup', 'postgres-init', '01-create-database.sql')
        
        if not os.path.exists(script_path):
            print(f"❌ SQL script not found at: {script_path}")
            return False
            
        with open(script_path, 'r') as f:
            sql_script = f.read()
        
        print("📝 Executing database initialization script...")
        cursor.execute(sql_script)
        
        # Test the setup
        cursor.execute("SELECT COUNT(*) FROM vulnerability_findings;")
        count = cursor.fetchone()[0]
        print(f"✅ Database initialized successfully!")
        print(f"📊 Sample vulnerability findings: {count}")
        
        # Show tables
        cursor.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public' 
            ORDER BY table_name;
        """)
        tables = cursor.fetchall()
        print(f"📋 Created tables: {', '.join([t[0] for t in tables])}")
        
        cursor.close()
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Database initialization failed: {e}")
        return False

if __name__ == "__main__":
    success = init_database()
    sys.exit(0 if success else 1)