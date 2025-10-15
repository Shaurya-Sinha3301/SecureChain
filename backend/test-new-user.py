#!/usr/bin/env python3
import psycopg2

try:
    print("Testing with testuser...")
    conn = psycopg2.connect(
        host='127.0.0.1',
        port=5432,
        database='securechain',
        user='testuser',
        password='shivam2469'
    )
    
    cursor = conn.cursor()
    cursor.execute("SELECT current_user, version();")
    result = cursor.fetchone()
    print(f"✅ Connected as: {result[0]}")
    print(f"PostgreSQL version: {result[1]}")
    
    cursor.close()
    conn.close()
    print("✅ Test successful!")
    
except Exception as e:
    print(f"❌ Test failed: {e}")