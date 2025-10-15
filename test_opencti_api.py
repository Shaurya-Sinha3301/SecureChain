#!/usr/bin/env python3
"""
OpenCTI API Testing Script
Tests the OpenCTI API running on localhost:8000
Requires API token for authentication
"""

import requests
import json
import sys
import argparse
from typing import Dict, Any, Optional

class OpenCTIAPITester:
    def __init__(self, base_url: str = "http://localhost:8000", token: str = None):
        self.base_url = base_url.rstrip('/')
        self.token = token
        self.session = requests.Session()
        
        if self.token:
            self.session.headers.update({
                'Authorization': f'Bearer {self.token}',
                'Content-Type': 'application/json'
            })
    
    def test_health_check(self, health_key: str = None) -> Dict[str, Any]:
        """Test the health endpoint"""
        print("🔍 Testing Health Check...")
        
        url = f"{self.base_url}/health"
        if health_key:
            url += f"?health_access_key={health_key}"
        
        try:
            response = self.session.get(url, timeout=10)
            result = {
                'endpoint': 'Health Check',
                'status_code': response.status_code,
                'success': response.status_code == 200,
                'response': response.text
            }
            
            if result['success']:
                print("✅ Health check passed")
            else:
                print(f"❌ Health check failed: {response.status_code}")
                
            return result
            
        except requests.exceptions.RequestException as e:
            print(f"❌ Health check failed: {str(e)}")
            return {
                'endpoint': 'Health Check',
                'success': False,
                'error': str(e)
            }
    
    def test_graphql_introspection(self) -> Dict[str, Any]:
        """Test GraphQL introspection query"""
        print("🔍 Testing GraphQL Introspection...")
        
        query = {
            "query": """
            query IntrospectionQuery {
                __schema {
                    queryType { name }
                    mutationType { name }
                    subscriptionType { name }
                }
            }
            """
        }
        
        try:
            response = self.session.post(
                f"{self.base_url}/graphql",
                json=query,
                timeout=10
            )
            
            result = {
                'endpoint': 'GraphQL Introspection',
                'status_code': response.status_code,
                'success': response.status_code == 200,
                'response': response.json() if response.status_code == 200 else response.text
            }
            
            if result['success']:
                print("✅ GraphQL introspection successful")
            else:
                print(f"❌ GraphQL introspection failed: {response.status_code}")
                
            return result
            
        except requests.exceptions.RequestException as e:
            print(f"❌ GraphQL introspection failed: {str(e)}")
            return {
                'endpoint': 'GraphQL Introspection',
                'success': False,
                'error': str(e)
            }
    
    def test_me_query(self) -> Dict[str, Any]:
        """Test the 'me' query to verify authentication"""
        print("🔍 Testing Authentication (me query)...")
        
        query = {
            "query": """
            query {
                me {
                    id
                    name
                    user_email
                    roles {
                        name
                    }
                }
            }
            """
        }
        
        try:
            response = self.session.post(
                f"{self.base_url}/graphql",
                json=query,
                timeout=10
            )
            
            result = {
                'endpoint': 'Authentication Test',
                'status_code': response.status_code,
                'success': response.status_code == 200,
                'response': response.json() if response.status_code == 200 else response.text
            }
            
            if result['success'] and 'data' in result['response'] and result['response']['data']['me']:
                print("✅ Authentication successful")
                user_info = result['response']['data']['me']
                print(f"   User: {user_info.get('name', 'N/A')} ({user_info.get('user_email', 'N/A')})")
            else:
                print(f"❌ Authentication failed: {response.status_code}")
                
            return result
            
        except requests.exceptions.RequestException as e:
            print(f"❌ Authentication test failed: {str(e)}")
            return {
                'endpoint': 'Authentication Test',
                'success': False,
                'error': str(e)
            }
    
    def test_indicators_query(self) -> Dict[str, Any]:
        """Test querying indicators"""
        print("🔍 Testing Indicators Query...")
        
        query = {
            "query": """
            query {
                indicators(first: 5) {
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
            response = self.session.post(
                f"{self.base_url}/graphql",
                json=query,
                timeout=10
            )
            
            result = {
                'endpoint': 'Indicators Query',
                'status_code': response.status_code,
                'success': response.status_code == 200,
                'response': response.json() if response.status_code == 200 else response.text
            }
            
            if result['success']:
                indicators_count = len(result['response'].get('data', {}).get('indicators', {}).get('edges', []))
                print(f"✅ Indicators query successful - Found {indicators_count} indicators")
            else:
                print(f"❌ Indicators query failed: {response.status_code}")
                
            return result
            
        except requests.exceptions.RequestException as e:
            print(f"❌ Indicators query failed: {str(e)}")
            return {
                'endpoint': 'Indicators Query',
                'success': False,
                'error': str(e)
            }
    
    def test_malware_query(self) -> Dict[str, Any]:
        """Test querying malware"""
        print("🔍 Testing Malware Query...")
        
        query = {
            "query": """
            query {
                malwares(first: 5) {
                    edges {
                        node {
                            id
                            name
                            malware_types
                            created
                        }
                    }
                }
            }
            """
        }
        
        try:
            response = self.session.post(
                f"{self.base_url}/graphql",
                json=query,
                timeout=10
            )
            
            result = {
                'endpoint': 'Malware Query',
                'status_code': response.status_code,
                'success': response.status_code == 200,
                'response': response.json() if response.status_code == 200 else response.text
            }
            
            if result['success']:
                malware_count = len(result['response'].get('data', {}).get('malwares', {}).get('edges', []))
                print(f"✅ Malware query successful - Found {malware_count} malware entries")
            else:
                print(f"❌ Malware query failed: {response.status_code}")
                
            return result
            
        except requests.exceptions.RequestException as e:
            print(f"❌ Malware query failed: {str(e)}")
            return {
                'endpoint': 'Malware Query',
                'success': False,
                'error': str(e)
            }
    
    def run_all_tests(self, health_key: str = None) -> Dict[str, Any]:
        """Run all API tests"""
        print("🚀 Starting OpenCTI API Tests")
        print("=" * 50)
        
        results = {}
        
        # Test health check
        results['health'] = self.test_health_check(health_key)
        print()
        
        # Test GraphQL introspection
        results['introspection'] = self.test_graphql_introspection()
        print()
        
        # Test authentication (only if token provided)
        if self.token:
            results['authentication'] = self.test_me_query()
            print()
            
            # Test data queries (only if authenticated)
            results['indicators'] = self.test_indicators_query()
            print()
            
            results['malware'] = self.test_malware_query()
            print()
        else:
            print("⚠️  Skipping authenticated tests - no token provided")
            print()
        
        # Summary
        print("=" * 50)
        print("📊 Test Summary:")
        
        total_tests = len(results)
        successful_tests = sum(1 for result in results.values() if result.get('success', False))
        
        for test_name, result in results.items():
            status = "✅ PASS" if result.get('success', False) else "❌ FAIL"
            print(f"   {test_name.capitalize()}: {status}")
        
        print(f"\nOverall: {successful_tests}/{total_tests} tests passed")
        
        return results

def main():
    parser = argparse.ArgumentParser(description='Test OpenCTI API')
    parser.add_argument('--url', default='http://localhost:8000', 
                       help='OpenCTI base URL (default: http://localhost:8000)')
    parser.add_argument('--token', required=False,
                       help='OpenCTI API token for authentication')
    parser.add_argument('--health-key', required=False,
                       help='Health check access key')
    parser.add_argument('--output', required=False,
                       help='Output file for detailed results (JSON format)')
    
    args = parser.parse_args()
    
    if not args.token:
        print("⚠️  Warning: No API token provided. Only basic tests will run.")
        print("   Use --token YOUR_TOKEN for full testing")
        print()
    
    # Create tester instance
    tester = OpenCTIAPITester(base_url=args.url, token=args.token)
    
    # Run tests
    results = tester.run_all_tests(health_key=args.health_key)
    
    # Save detailed results if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n💾 Detailed results saved to: {args.output}")

if __name__ == "__main__":
    main()