#!/usr/bin/env python3
"""
Test OpenCTI connection with the backend
"""

import requests
import json
import os
from dotenv import load_dotenv

load_dotenv()

def test_opencti_direct():
    """Test OpenCTI connection directly"""
    print("🔧 Testing OpenCTI direct connection...")
    
    token = os.getenv('OPENCTI_TOKEN', '3b2641f7-3232-418c-8365-5454b3953143')
    
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    
    query = {
        "query": """
        query {
            me {
                id
                name
                user_email
            }
        }
        """
    }
    
    try:
        response = requests.post(
            "http://localhost:8080/graphql",
            json=query,
            headers=headers,
            timeout=10
        )
        
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text}")
        
        if response.status_code == 200:
            data = response.json()
            if 'data' in data and data['data']['me']:
                print("✅ OpenCTI authentication successful!")
                user = data['data']['me']
                print(f"   User: {user.get('name', 'N/A')} ({user.get('user_email', 'N/A')})")
                return True
            else:
                print("⚠️  OpenCTI responded but user is null")
                return False
        else:
            print("❌ OpenCTI connection failed")
            return False
            
    except Exception as e:
        print(f"❌ OpenCTI connection error: {e}")
        return False

def test_opencti_indicators():
    """Test querying OpenCTI indicators"""
    print("\n🔧 Testing OpenCTI indicators query...")
    
    token = os.getenv('OPENCTI_TOKEN', '3b2641f7-3232-418c-8365-5454b3953143')
    
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    
    query = {
        "query": """
        query {
            indicators(first: 3) {
                edges {
                    node {
                        id
                        pattern
                        indicator_types
                        created
                    }
                }
            }
        }
        """
    }
    
    try:
        response = requests.post(
            "http://localhost:8080/graphql",
            json=query,
            headers=headers,
            timeout=10
        )
        
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            if 'data' in data:
                indicators = data['data']['indicators']['edges']
                print(f"✅ Found {len(indicators)} indicators")
                for i, indicator in enumerate(indicators):
                    node = indicator['node']
                    print(f"   {i+1}. {node['pattern']} ({', '.join(node['indicator_types'])})")
                return True
            else:
                print("⚠️  No data in response")
                return False
        else:
            print(f"❌ Query failed: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Query error: {e}")
        return False

def test_backend_opencti_health():
    """Test backend's OpenCTI health check"""
    print("\n🔧 Testing backend OpenCTI health...")
    
    try:
        response = requests.get("http://localhost:8000/health", timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            opencti_status = data['services'].get('opencti', 'unknown')
            print(f"Backend OpenCTI status: {opencti_status}")
            
            if opencti_status == 'healthy':
                print("✅ Backend reports OpenCTI as healthy")
                return True
            else:
                print(f"⚠️  Backend reports OpenCTI as: {opencti_status}")
                return False
        else:
            print("❌ Backend health check failed")
            return False
            
    except Exception as e:
        print(f"❌ Backend health check error: {e}")
        return False

if __name__ == "__main__":
    print("🚀 OpenCTI Connection Test")
    print("=" * 40)
    
    # Test direct connection
    direct_ok = test_opencti_direct()
    
    # Test indicators query
    indicators_ok = test_opencti_indicators()
    
    # Test backend health
    backend_ok = test_backend_opencti_health()
    
    print("\n" + "=" * 40)
    print("📊 Summary:")
    print(f"   Direct OpenCTI: {'✅' if direct_ok else '❌'}")
    print(f"   Indicators Query: {'✅' if indicators_ok else '❌'}")
    print(f"   Backend Health: {'✅' if backend_ok else '❌'}")
    
    if direct_ok and indicators_ok:
        print("\n🎉 OpenCTI is working! The backend should be able to enrich findings.")
    else:
        print("\n⚠️  OpenCTI has some issues, but the backend will work without enrichment.")