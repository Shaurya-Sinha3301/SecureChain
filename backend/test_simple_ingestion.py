#!/usr/bin/env python3
"""
Simple ingestion test to debug the data format issues
"""

import requests
import json

def test_simple_ingestion():
    """Test with minimal data to see what's happening"""
    
    # Simple test data that matches expected format
    test_data = {
        "scan_tool": "nuclei",
        "target": "192.168.1.100",
        "scan_results": {
            "findings": [
                {
                    "host": "192.168.1.100",
                    "ip": "192.168.1.100",
                    "service": "http",
                    "port": 80,
                    "version": "Apache 2.4.41",
                    "evidence": "HTTP service detected",
                    "severity": "Medium"
                }
            ]
        }
    }
    
    try:
        print("🔧 Testing simple ingestion...")
        response = requests.post(
            "http://localhost:8000/api/v1/ingestion/scan-results/sync",
            json=test_data,
            timeout=10
        )
        
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text}")
        
        if response.status_code == 200:
            data = response.json()
            print("✅ Success!")
            print(f"Findings processed: {data.get('findings_processed', 0)}")
        else:
            print("❌ Failed")
            
    except Exception as e:
        print(f"❌ Error: {e}")

def test_findings_retrieval():
    """Test retrieving findings"""
    try:
        print("\n🔧 Testing findings retrieval...")
        response = requests.get(
            "http://localhost:8000/api/v1/ingestion/findings?limit=5",
            timeout=10
        )
        
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text}")
        
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    test_simple_ingestion()
    test_findings_retrieval()