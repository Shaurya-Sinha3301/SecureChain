#!/usr/bin/env python3
import psycopg2
import sys

def test_connection():
    try:
        print("Testing PostgreSQL connection...")
        conn = psycopg2.connect(
            host='127.0.0.1',
            port=5432,
            database='securechain',
            user='securechain',
            password='shivam2469'
        )
        
        cursor = conn.cursor()
        cursor.execute("SELECT version();")
        version = cursor.fetchone()[0]
        print(f"✅ Connected successfully!")
        print(f"PostgreSQL version: {version}")
        
        cursor.execute("SELECT COUNT(*) FROM vulnerability_findings;")
        count = cursor.fetchone()[0]
        print(f"Vulnerability findings count: {count}")
        
        cursor.close()
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        return False

if __name__ == "__main__":
    success = test_connection()
    sys.exit(0 if success else 1)