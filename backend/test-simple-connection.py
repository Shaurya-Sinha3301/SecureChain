#!/usr/bin/env python3
import psycopg2
import os

# Try different connection methods
connection_strings = [
    "postgresql://securechain:shivam2469@127.0.0.1:5432/securechain",
    "postgresql://securechain:shivam2469@localhost:5432/securechain",
    "host=127.0.0.1 port=5432 dbname=securechain user=securechain password=shivam2469",
    "host=localhost port=5432 dbname=securechain user=securechain password=shivam2469"
]

for i, conn_str in enumerate(connection_strings, 1):
    try:
        print(f"Test {i}: {conn_str.replace('shivam2469', '***')}")
        if conn_str.startswith("postgresql://"):
            conn = psycopg2.connect(conn_str)
        else:
            conn = psycopg2.connect(conn_str)
        
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        result = cursor.fetchone()
        print(f"✅ Success! Result: {result}")
        cursor.close()
        conn.close()
        break
    except Exception as e:
        print(f"❌ Failed: {e}")
        print()

print("\nTesting environment variables...")
os.environ['PGPASSWORD'] = 'shivam2469'
try:
    conn = psycopg2.connect(
        host='127.0.0.1',
        port='5432',
        database='securechain',
        user='securechain'
    )
    cursor = conn.cursor()
    cursor.execute("SELECT 'Environment variable auth works!' as result")
    result = cursor.fetchone()
    print(f"✅ Environment variable method: {result[0]}")
    cursor.close()
    conn.close()
except Exception as e:
    print(f"❌ Environment variable method failed: {e}")