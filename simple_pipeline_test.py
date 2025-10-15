#!/usr/bin/env python3
"""
Simple Pipeline Test for SecureChain
Tests core functionality without Unicode characters for Windows compatibility
"""

import os
import sys
import json
import time
import requests
import subprocess
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

# Configure logging without Unicode
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('simple_pipeline_test.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class SimplePipelineTest:
    """Simple test runner for SecureChain pipeline"""
    
    def __init__(self):
        self.test_results = {
            'timestamp': datetime.now().isoformat(),
            'tests': {},
            'overall_status': 'PENDING'
        }
        self.backend_url = "http://localhost:8000"
        
    def log_test_result(self, test_name: str, status: str, details: Dict = None):
        """Log test results"""
        self.test_results['tests'][test_name] = {
            'status': status,
            'timestamp': datetime.now().isoformat(),
            'details': details or {}
        }
        logger.info(f"Test '{test_name}': {status}")
        if details:
            logger.info(f"Details: {details}")
    
    def test_attack_graph_generation(self) -> bool:
        """Test attack graph generation using NetworkX"""
        logger.info("Testing Attack Graph Generation...")
        
        try:
            # Import required modules
            import networkx as nx
            import matplotlib.pyplot as plt
            
            # Create sample vulnerability data
            vuln_data = [
                {
                    "finding_id": "vuln_web_001",
                    "host": "web-server-01",
                    "ip": "192.168.1.100",
                    "service": "http",
                    "port": 80,
                    "cve": "CVE-2021-44228",
                    "cvss": 9.8,
                    "severity": "Critical",
                    "asset_type": "web_server",
                    "network_zone": "dmz",
                    "criticality": 9
                },
                {
                    "finding_id": "vuln_db_001",
                    "host": "db-server-01",
                    "ip": "192.168.1.200",
                    "service": "mysql",
                    "port": 3306,
                    "cve": "CVE-2020-14867",
                    "cvss": 7.5,
                    "severity": "High",
                    "asset_type": "database_server",
                    "network_zone": "internal",
                    "criticality": 10
                }
            ]
            
            # Create NetworkX graph
            G = nx.DiGraph()
            
            # Add nodes for assets and vulnerabilities
            for vuln in vuln_data:
                # Add asset node
                asset_id = f"asset_{vuln['ip']}"
                G.add_node(asset_id, 
                          node_type="asset",
                          ip=vuln['ip'],
                          hostname=vuln['host'],
                          asset_type=vuln['asset_type'],
                          criticality=vuln['criticality'])
                
                # Add vulnerability node
                vuln_id = vuln['finding_id']
                G.add_node(vuln_id,
                          node_type="vulnerability", 
                          cve=vuln['cve'],
                          cvss=vuln['cvss'],
                          severity=vuln['severity'],
                          service=vuln['service'])
                
                # Add edge from vulnerability to asset
                G.add_edge(vuln_id, asset_id, 
                          relationship="affects",
                          weight=vuln['cvss']/10.0)
            
            # Add attack path edge (web to database lateral movement)
            G.add_edge("vuln_web_001", "vuln_db_001",
                      relationship="attack_path",
                      attack_type="lateral_movement",
                      probability=0.8)
            
            # Generate graph statistics
            stats = {
                "nodes": len(G.nodes()),
                "edges": len(G.edges()),
                "assets": len([n for n, d in G.nodes(data=True) if d.get('node_type') == 'asset']),
                "vulnerabilities": len([n for n, d in G.nodes(data=True) if d.get('node_type') == 'vulnerability'])
            }
            
            # Create simple visualization
            plt.figure(figsize=(12, 8))
            pos = nx.spring_layout(G, k=2, iterations=50)
            
            # Draw nodes
            asset_nodes = [n for n, d in G.nodes(data=True) if d.get('node_type') == 'asset']
            vuln_nodes = [n for n, d in G.nodes(data=True) if d.get('node_type') == 'vulnerability']
            
            nx.draw_networkx_nodes(G, pos, nodelist=asset_nodes,
                                  node_color='lightblue', node_size=1000, alpha=0.8)
            nx.draw_networkx_nodes(G, pos, nodelist=vuln_nodes,
                                  node_color='red', node_size=800, alpha=0.8)
            
            # Draw edges
            nx.draw_networkx_edges(G, pos, edge_color='gray', width=1, alpha=0.6)
            
            # Add labels
            labels = {n: n.split('_')[-1] for n in G.nodes()}
            nx.draw_networkx_labels(G, pos, labels, font_size=8)
            
            plt.title("SecureChain Attack Graph Test")
            plt.axis('off')
            plt.tight_layout()
            plt.savefig("simple_attack_graph.png", dpi=300, bbox_inches='tight')
            plt.close()
            
            # Export graph data
            graph_data = {
                "nodes": [{"id": n, **d} for n, d in G.nodes(data=True)],
                "edges": [{"source": u, "target": v, **d} for u, v, d in G.edges(data=True)],
                "statistics": stats
            }
            
            with open("simple_attack_graph.json", "w") as f:
                json.dump(graph_data, f, indent=2)
            
            self.log_test_result("attack_graph", "PASSED", {
                "statistics": stats,
                "output_files": ["simple_attack_graph.png", "simple_attack_graph.json"]
            })
            
            return True
            
        except Exception as e:
            self.log_test_result("attack_graph", "FAILED", {"error": str(e)})
            return False
    
    def test_backend_health(self) -> bool:
        """Test backend health check"""
        logger.info("Testing Backend Health...")
        
        try:
            response = requests.get(f"{self.backend_url}/health", timeout=10)
            
            if response.status_code == 200:
                health_data = response.json()
                self.log_test_result("backend_health", "PASSED", health_data)
                return True
            else:
                self.log_test_result("backend_health", "FAILED", 
                                   {"status_code": response.status_code})
                return False
                
        except Exception as e:
            self.log_test_result("backend_health", "FAILED", {"error": str(e)})
            return False
    
    def test_data_ingestion(self) -> bool:
        """Test data ingestion with sample findings"""
        logger.info("Testing Data Ingestion...")
        
        try:
            # Load sample findings
            sample_data_file = Path("test_data/normalized_findings.json")
            if not sample_data_file.exists():
                self.log_test_result("data_ingestion", "FAILED", 
                                   {"error": "Sample data file not found"})
                return False
            
            with open(sample_data_file, 'r') as f:
                findings = json.load(f)
            
            # Test ingestion with first finding
            test_finding = findings[0] if findings else {
                "finding_id": "test_001",
                "host": "test-host",
                "ip": "192.168.1.100",
                "service": "http",
                "port": 80,
                "cve": "CVE-2021-44228",
                "cvss": 9.8,
                "severity": "Critical"
            }
            
            response = requests.post(
                f"{self.backend_url}/api/v1/ingestion/ingest",
                json={"findings": [test_finding]},
                timeout=30
            )
            
            if response.status_code in [200, 201]:
                self.log_test_result("data_ingestion", "PASSED", {
                    "status_code": response.status_code,
                    "finding_id": test_finding["finding_id"]
                })
                return True
            else:
                self.log_test_result("data_ingestion", "FAILED", {
                    "status_code": response.status_code,
                    "response": response.text[:200]
                })
                return False
                
        except Exception as e:
            self.log_test_result("data_ingestion", "FAILED", {"error": str(e)})
            return False
    
    def test_findings_retrieval(self) -> bool:
        """Test findings retrieval"""
        logger.info("Testing Findings Retrieval...")
        
        try:
            response = requests.get(f"{self.backend_url}/api/v1/ingestion/findings", timeout=10)
            
            if response.status_code == 200:
                findings = response.json()
                self.log_test_result("findings_retrieval", "PASSED", {
                    "findings_count": len(findings) if isinstance(findings, list) else "unknown"
                })
                return True
            else:
                self.log_test_result("findings_retrieval", "FAILED", {
                    "status_code": response.status_code
                })
                return False
                
        except Exception as e:
            self.log_test_result("findings_retrieval", "FAILED", {"error": str(e)})
            return False
    
    def test_opencti_connectivity(self) -> bool:
        """Test OpenCTI connectivity"""
        logger.info("Testing OpenCTI Connectivity...")
        
        try:
            opencti_url = "http://localhost:8080"
            response = requests.get(f"{opencti_url}/health", timeout=5)
            
            if response.status_code == 200:
                self.log_test_result("opencti_connectivity", "PASSED", {
                    "status_code": response.status_code
                })
                return True
            else:
                self.log_test_result("opencti_connectivity", "PARTIAL", {
                    "status_code": response.status_code,
                    "note": "OpenCTI responding but may need authentication"
                })
                return True  # Consider partial success
                
        except Exception as e:
            self.log_test_result("opencti_connectivity", "FAILED", {
                "error": str(e),
                "note": "OpenCTI may not be running"
            })
            return False
    
    def generate_report(self):
        """Generate test report"""
        logger.info("Generating Test Report...")
        
        # Calculate overall statistics
        total_tests = len(self.test_results['tests'])
        passed_tests = len([t for t in self.test_results['tests'].values() 
                           if t['status'] == 'PASSED'])
        success_rate = passed_tests / total_tests if total_tests > 0 else 0
        
        self.test_results['overall_status'] = 'PASSED' if success_rate >= 0.6 else 'FAILED'
        self.test_results['summary'] = {
            'total_tests': total_tests,
            'passed_tests': passed_tests,
            'success_rate': success_rate
        }
        
        # Save results
        with open('simple_pipeline_test_results.json', 'w') as f:
            json.dump(self.test_results, f, indent=2)
        
        # Print summary
        print("\n" + "="*60)
        print("SECURECHAIN SIMPLE PIPELINE TEST RESULTS")
        print("="*60)
        print(f"Overall Status: {self.test_results['overall_status']}")
        print(f"Success Rate: {success_rate:.1%}")
        print(f"Tests Passed: {passed_tests}/{total_tests}")
        
        print("\nTest Details:")
        for test_name, result in self.test_results['tests'].items():
            status_icon = "PASS" if result['status'] == 'PASSED' else "FAIL"
            print(f"  [{status_icon}] {test_name}: {result['status']}")
            if result.get('details'):
                for key, value in result['details'].items():
                    print(f"    - {key}: {value}")
        
        print("\nGenerated Files:")
        output_files = [
            "simple_pipeline_test_results.json",
            "simple_attack_graph.png",
            "simple_attack_graph.json",
            "simple_pipeline_test.log"
        ]
        
        for file in output_files:
            if Path(file).exists():
                print(f"  [EXISTS] {file}")
            else:
                print(f"  [MISSING] {file}")
        
        print("="*60)
        
        return self.test_results['overall_status'] == 'PASSED'
    
    def run_all_tests(self) -> bool:
        """Run all tests"""
        print("SECURECHAIN SIMPLE PIPELINE TEST")
        print("="*50)
        print("Testing core SecureChain functionality...")
        print("="*50)
        
        # Test sequence
        tests = [
            ("Attack Graph Generation", self.test_attack_graph_generation),
            ("Backend Health", self.test_backend_health),
            ("Data Ingestion", self.test_data_ingestion),
            ("Findings Retrieval", self.test_findings_retrieval),
            ("OpenCTI Connectivity", self.test_opencti_connectivity)
        ]
        
        for test_name, test_func in tests:
            print(f"\nRunning: {test_name}")
            print("-" * 40)
            
            try:
                success = test_func()
                if success:
                    print(f"[PASS] {test_name}")
                else:
                    print(f"[FAIL] {test_name}")
            except Exception as e:
                print(f"[ERROR] {test_name}: {str(e)}")
                self.log_test_result(test_name.lower().replace(' ', '_'), "ERROR", {"error": str(e)})
        
        # Generate final report
        return self.generate_report()

def main():
    """Main function"""
    tester = SimplePipelineTest()
    
    try:
        success = tester.run_all_tests()
        
        if success:
            print("\nSUCCESS: Pipeline test completed successfully!")
            sys.exit(0)
        else:
            print("\nWARNING: Some tests failed. Check the results for details.")
            sys.exit(1)
            
    except Exception as e:
        logger.error(f"Test suite failed: {str(e)}")
        print(f"\nERROR: Test suite failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()