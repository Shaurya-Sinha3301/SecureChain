#!/usr/bin/env python3
"""
Comprehensive Backend Test with Sample Data
Tests the complete vulnerability ingestion pipeline
"""

import requests
import json
import sys
import time
from datetime import datetime
from typing import Dict, Any, List

class BackendTester:
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json'
        })
    
    def test_health(self) -> Dict[str, Any]:
        """Test backend health"""
        print("🔍 Testing Backend Health...")
        
        try:
            response = self.session.get(f"{self.base_url}/health", timeout=10)
            result = {
                'endpoint': 'Health Check',
                'status_code': response.status_code,
                'success': response.status_code == 200,
                'response': response.json() if response.status_code == 200 else response.text
            }
            
            if result['success']:
                health_data = result['response']
                print(f"✅ Backend is {health_data['status']}")
                print("   Service Status:")
                for service, status in health_data['services'].items():
                    status_icon = "✅" if status == "healthy" else "⚠️" if "not_configured" in str(status) else "❌"
                    print(f"     {service}: {status_icon} {status}")
            else:
                print(f"❌ Health check failed: {response.status_code}")
                
            return result
            
        except Exception as e:
            print(f"❌ Health check failed: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def test_root_endpoint(self) -> Dict[str, Any]:
        """Test root endpoint"""
        print("\n🔍 Testing Root Endpoint...")
        
        try:
            response = self.session.get(f"{self.base_url}/", timeout=10)
            result = {
                'endpoint': 'Root',
                'status_code': response.status_code,
                'success': response.status_code == 200,
                'response': response.json() if response.status_code == 200 else response.text
            }
            
            if result['success']:
                data = result['response']
                print(f"✅ API: {data['message']}")
                print(f"   Version: {data['version']}")
                print(f"   Status: {data['status']}")
                print(f"   Features: {len(data['features'])} available")
            else:
                print(f"❌ Root endpoint failed: {response.status_code}")
                
            return result
            
        except Exception as e:
            print(f"❌ Root endpoint failed: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def create_sample_nmap_data(self) -> Dict[str, Any]:
        """Create sample Nmap scan data"""
        return {
            "scan_tool": "nmap",
            "target": "192.168.1.0/24",
            "scan_results": {
                "tool": "nmap",
                "version": "7.94",
                "scan_type": "tcp_syn",
                "target": "192.168.1.0/24",
                "timestamp": datetime.utcnow().isoformat(),
                "hosts": [
                    {
                        "ip": "192.168.1.100",
                        "hostname": "web-server.local",
                        "status": "up",
                        "ports": [
                            {
                                "port": 22,
                                "protocol": "tcp",
                                "state": "open",
                                "service": "ssh",
                                "version": "OpenSSH 8.9p1 Ubuntu 3ubuntu0.4",
                                "cpe": "cpe:/a:openbsd:openssh:8.9p1"
                            },
                            {
                                "port": 80,
                                "protocol": "tcp",
                                "state": "open",
                                "service": "http",
                                "version": "Apache httpd 2.4.41",
                                "cpe": "cpe:/a:apache:http_server:2.4.41"
                            },
                            {
                                "port": 443,
                                "protocol": "tcp",
                                "state": "open",
                                "service": "https",
                                "version": "Apache httpd 2.4.41 (SSL)",
                                "cpe": "cpe:/a:apache:http_server:2.4.41"
                            }
                        ]
                    },
                    {
                        "ip": "192.168.1.101",
                        "hostname": "db-server.local",
                        "status": "up",
                        "ports": [
                            {
                                "port": 22,
                                "protocol": "tcp",
                                "state": "open",
                                "service": "ssh",
                                "version": "OpenSSH 7.4",
                                "cpe": "cpe:/a:openbsd:openssh:7.4"
                            },
                            {
                                "port": 3306,
                                "protocol": "tcp",
                                "state": "open",
                                "service": "mysql",
                                "version": "MySQL 5.7.40",
                                "cpe": "cpe:/a:mysql:mysql:5.7.40"
                            }
                        ]
                    }
                ]
            }
        }
    
    def create_sample_nuclei_data(self) -> Dict[str, Any]:
        """Create sample Nuclei scan data"""
        return {
            "scan_tool": "nuclei",
            "target": "192.168.1.100",
            "scan_results": {
                "tool": "nuclei",
                "version": "3.1.0",
                "scan_type": "vulnerability",
                "target": "192.168.1.100",
                "timestamp": datetime.utcnow().isoformat(),
                "findings": [
                    {
                        "template_id": "apache-version-detect",
                        "info": {
                            "name": "Apache Version Detection",
                            "severity": "info",
                            "description": "Apache HTTP Server version detection",
                            "tags": ["tech", "apache", "version"]
                        },
                        "matched_at": "http://192.168.1.100",
                        "extracted_results": ["Apache/2.4.41"],
                        "curl_command": "curl -X 'GET' -H 'Accept: */*' -H 'Accept-Language: en' -H 'User-Agent: Mozilla/5.0' 'http://192.168.1.100'",
                        "type": "http"
                    },
                    {
                        "template_id": "CVE-2021-41773",
                        "info": {
                            "name": "Apache HTTP Server 2.4.49 - Path Traversal",
                            "severity": "high",
                            "description": "Apache HTTP Server 2.4.49 is susceptible to a path traversal attack",
                            "reference": ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41773"],
                            "tags": ["cve", "apache", "lfi", "traversal"],
                            "classification": {
                                "cvss_metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                "cvss_score": 7.5,
                                "cve_id": "CVE-2021-41773"
                            }
                        },
                        "matched_at": "http://192.168.1.100/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
                        "extracted_results": ["root:x:0:0:root:/root:/bin/bash"],
                        "curl_command": "curl -X 'GET' 'http://192.168.1.100/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'",
                        "type": "http"
                    }
                ]
            }
        }
    
    def test_ingestion_endpoint(self, scan_data: Dict[str, Any], scan_type: str) -> Dict[str, Any]:
        """Test vulnerability ingestion endpoint"""
        print(f"\n🔍 Testing {scan_type} Ingestion...")
        
        try:
            response = self.session.post(
                f"{self.base_url}/api/v1/ingestion/scan-results/sync",
                json=scan_data,
                timeout=30
            )
            
            result = {
                'endpoint': f'{scan_type} Ingestion',
                'status_code': response.status_code,
                'success': response.status_code in [200, 201],
                'response': response.json() if response.status_code in [200, 201] else response.text
            }
            
            if result['success']:
                data = result['response']
                print(f"✅ {scan_type} ingestion successful")
                print(f"   Session ID: {data.get('session_id', 'N/A')}")
                print(f"   Findings processed: {data.get('findings_processed', 0)}")
                print(f"   Processing time: {data.get('processing_time_seconds', 0):.2f}s")
                if data.get('enrichment_summary'):
                    enrichment = data['enrichment_summary']
                    print(f"   OpenCTI enrichment: {enrichment.get('enriched_findings', 0)} findings enriched")
            else:
                print(f"❌ {scan_type} ingestion failed: {response.status_code}")
                print(f"   Error: {result['response']}")
                
            return result
            
        except Exception as e:
            print(f"❌ {scan_type} ingestion failed: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def test_findings_retrieval(self) -> Dict[str, Any]:
        """Test findings retrieval endpoint"""
        print("\n🔍 Testing Findings Retrieval...")
        
        try:
            response = self.session.get(
                f"{self.base_url}/api/v1/ingestion/findings?limit=10",
                timeout=10
            )
            
            result = {
                'endpoint': 'Findings Retrieval',
                'status_code': response.status_code,
                'success': response.status_code == 200,
                'response': response.json() if response.status_code == 200 else response.text
            }
            
            if result['success']:
                data = result['response']
                findings = data.get('findings', [])
                print(f"✅ Retrieved {len(findings)} findings")
                
                # Show summary of findings
                if findings:
                    print("   Sample findings:")
                    for i, finding in enumerate(findings[:3]):
                        print(f"     {i+1}. {finding.get('host', 'N/A')}:{finding.get('port', 'N/A')} - {finding.get('service', 'N/A')} ({finding.get('severity', 'N/A')})")
                        if finding.get('cve'):
                            print(f"        CVE: {finding['cve']} (CVSS: {finding.get('cvss', 'N/A')})")
                        if finding.get('opencti_vulnerability_id'):
                            print(f"        OpenCTI enriched: ✅")
            else:
                print(f"❌ Findings retrieval failed: {response.status_code}")
                
            return result
            
        except Exception as e:
            print(f"❌ Findings retrieval failed: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def test_attack_graph_generation(self) -> Dict[str, Any]:
        """Test attack graph generation"""
        print("\n🔍 Testing Attack Graph Generation...")
        
        try:
            response = self.session.get(
                f"{self.base_url}/api/v1/ingestion/attack-graph",
                timeout=30
            )
            
            result = {
                'endpoint': 'Attack Graph Generation',
                'status_code': response.status_code,
                'success': response.status_code in [200, 201],
                'response': response.json() if response.status_code in [200, 201] else response.text
            }
            
            if result['success']:
                data = result['response']
                print(f"✅ Attack graph generated")
                print(f"   Nodes: {data.get('nodes_created', 0)}")
                print(f"   Relationships: {data.get('relationships_created', 0)}")
                print(f"   Attack paths: {data.get('attack_paths_found', 0)}")
            else:
                print(f"❌ Attack graph generation failed: {response.status_code}")
                
            return result
            
        except Exception as e:
            print(f"❌ Attack graph generation failed: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def run_comprehensive_test(self) -> Dict[str, Any]:
        """Run comprehensive backend test"""
        print("🚀 Starting Comprehensive Backend Test")
        print("=" * 60)
        
        results = {}
        
        # Test basic endpoints
        results['health'] = self.test_health()
        results['root'] = self.test_root_endpoint()
        
        # Test data ingestion
        nmap_data = self.create_sample_nmap_data()
        results['nmap_ingestion'] = self.test_ingestion_endpoint(nmap_data, "Nmap")
        
        nuclei_data = self.create_sample_nuclei_data()
        results['nuclei_ingestion'] = self.test_ingestion_endpoint(nuclei_data, "Nuclei")
        
        # Wait a moment for processing
        print("\n⏳ Waiting for data processing...")
        time.sleep(3)
        
        # Test data retrieval
        results['findings_retrieval'] = self.test_findings_retrieval()
        
        # Test attack graph generation
        results['attack_graph'] = self.test_attack_graph_generation()
        
        # Summary
        print("\n" + "=" * 60)
        print("📊 Test Summary:")
        
        total_tests = len(results)
        successful_tests = sum(1 for result in results.values() if result.get('success', False))
        
        for test_name, result in results.items():
            status = "✅ PASS" if result.get('success', False) else "❌ FAIL"
            print(f"   {test_name.replace('_', ' ').title()}: {status}")
        
        print(f"\nOverall: {successful_tests}/{total_tests} tests passed")
        
        if successful_tests == total_tests:
            print("🎉 All tests passed! Backend is fully functional.")
        elif successful_tests >= total_tests * 0.8:
            print("✅ Most tests passed! Backend is mostly functional.")
        else:
            print("⚠️  Several tests failed. Backend needs attention.")
        
        return results

def main():
    print("🔧 SecureChain Backend Comprehensive Test")
    print("Testing complete vulnerability management pipeline")
    print()
    
    # Wait for backend to be ready
    print("⏳ Waiting for backend to be ready...")
    time.sleep(2)
    
    # Create tester instance
    tester = BackendTester()
    
    # Run comprehensive test
    results = tester.run_comprehensive_test()
    
    # Save results
    with open('backend_test_results.json', 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"\n💾 Detailed results saved to: backend_test_results.json")

if __name__ == "__main__":
    main()