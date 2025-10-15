#!/usr/bin/env python3
"""
Comprehensive SecureChain Pipeline Test
Tests the complete pipeline with real threat scenarios:
1. AI Vulnerability Scanner
2. OpenCTI Integration
3. Attack Graph Generation with NetworkX
4. Chatbot Query Testing

This script simulates real-world attack scenarios and validates each component.
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
import networkx as nx
import matplotlib.pyplot as plt
import pandas as pd
from typing import Dict, List, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('pipeline_test.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ComprehensivePipelineTest:
    """Comprehensive test suite for the entire SecureChain pipeline"""
    
    def __init__(self):
        self.test_results = {
            'timestamp': datetime.now().isoformat(),
            'tests': {},
            'overall_status': 'PENDING'
        }
        self.backend_url = "http://localhost:8000"
        self.opencti_url = "http://localhost:8080"
        self.test_targets = [
            "scanme.nmap.org",  # Official nmap test target
            "testphp.vulnweb.com",  # Vulnerable web app for testing
            "demo.testfire.net"  # IBM's vulnerable banking app
        ]
        
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
    
    def test_ai_vulnerability_scanner(self) -> bool:
        """Test AI Vulnerability Scanner with real targets"""
        logger.info("🔍 Testing AI Vulnerability Scanner...")
        
        try:
            # Test with a safe, public target
            target = "scanme.nmap.org"
            scanner_path = Path("AI-Vuln-Scanner/vulnscanner.py")
            
            if not scanner_path.exists():
                self.log_test_result("ai_scanner", "FAILED", 
                                   {"error": "Scanner script not found"})
                return False
            
            # Run vulnerability scan
            cmd = [
                sys.executable, str(scanner_path),
                "-t", target,
                "-p", "1",  # Fast scan profile
                "-o", "json"
            ]
            
            logger.info(f"Running command: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                # Look for output files
                output_files = list(Path(".").glob(f"{target}-*.json"))
                if output_files:
                    with open(output_files[0], 'r') as f:
                        scan_data = json.load(f)
                    
                    self.log_test_result("ai_scanner", "PASSED", {
                        "target": target,
                        "output_file": str(output_files[0]),
                        "findings_count": len(scan_data.get('vulnerability_analysis', '').split('\n'))
                    })
                    return True
                else:
                    self.log_test_result("ai_scanner", "FAILED", 
                                       {"error": "No output files generated"})
                    return False
            else:
                self.log_test_result("ai_scanner", "FAILED", {
                    "error": result.stderr,
                    "stdout": result.stdout
                })
                return False
                
        except Exception as e:
            self.log_test_result("ai_scanner", "FAILED", {"error": str(e)})
            return False
    
    def test_opencti_integration(self) -> bool:
        """Test OpenCTI integration and threat intelligence enrichment"""
        logger.info("🧠 Testing OpenCTI Integration...")
        
        try:
            # Test OpenCTI API connectivity
            health_url = f"{self.opencti_url}/health"
            response = requests.get(health_url, timeout=10)
            
            if response.status_code != 200:
                self.log_test_result("opencti_health", "FAILED", 
                                   {"status_code": response.status_code})
                return False
            
            # Test GraphQL endpoint
            graphql_url = f"{self.opencti_url}/graphql"
            query = {
                "query": "{ __schema { types { name } } }"
            }
            
            response = requests.post(graphql_url, json=query, timeout=10)
            if response.status_code == 200:
                self.log_test_result("opencti_graphql", "PASSED", 
                                   {"response_size": len(response.text)})
            else:
                self.log_test_result("opencti_graphql", "FAILED", 
                                   {"status_code": response.status_code})
                return False
            
            # Test threat intelligence queries
            threat_query = {
                "query": """
                query {
                    vulnerabilities(first: 5) {
                        edges {
                            node {
                                id
                                name
                                description
                            }
                        }
                    }
                }
                """
            }
            
            response = requests.post(graphql_url, json=threat_query, timeout=10)
            if response.status_code == 200:
                data = response.json()
                vuln_count = len(data.get('data', {}).get('vulnerabilities', {}).get('edges', []))
                self.log_test_result("opencti_vulnerabilities", "PASSED", 
                                   {"vulnerability_count": vuln_count})
                return True
            else:
                self.log_test_result("opencti_vulnerabilities", "FAILED", 
                                   {"status_code": response.status_code})
                return False
                
        except Exception as e:
            self.log_test_result("opencti_integration", "FAILED", {"error": str(e)})
            return False
    
    def create_sample_vulnerability_data(self) -> List[Dict]:
        """Create realistic vulnerability data for testing"""
        return [
            {
                "finding_id": "vuln_001",
                "host": "web-server-01",
                "ip": "192.168.1.100",
                "service": "http",
                "port": 80,
                "version": "Apache 2.4.41",
                "cve": "CVE-2021-44228",  # Log4j vulnerability
                "cvss": 9.8,
                "severity": "Critical",
                "evidence": "Log4j library detected in web application",
                "scan_tool": "nmap",
                "asset_type": "web_server",
                "criticality": 9
            },
            {
                "finding_id": "vuln_002", 
                "host": "db-server-01",
                "ip": "192.168.1.200",
                "service": "mysql",
                "port": 3306,
                "version": "MySQL 5.7.30",
                "cve": "CVE-2020-14867",
                "cvss": 7.5,
                "severity": "High",
                "evidence": "MySQL server with known vulnerability",
                "scan_tool": "nmap",
                "asset_type": "database_server",
                "criticality": 8
            },
            {
                "finding_id": "vuln_003",
                "host": "ssh-server-01", 
                "ip": "192.168.1.150",
                "service": "ssh",
                "port": 22,
                "version": "OpenSSH 7.4",
                "cve": "CVE-2018-15473",
                "cvss": 5.3,
                "severity": "Medium",
                "evidence": "SSH server with user enumeration vulnerability",
                "scan_tool": "nmap",
                "asset_type": "linux_server",
                "criticality": 6
            },
            {
                "finding_id": "vuln_004",
                "host": "ftp-server-01",
                "ip": "192.168.1.180",
                "service": "ftp",
                "port": 21,
                "version": "vsftpd 2.3.4",
                "cve": "CVE-2011-2523",
                "cvss": 10.0,
                "severity": "Critical", 
                "evidence": "FTP server with backdoor vulnerability",
                "scan_tool": "nmap",
                "asset_type": "file_server",
                "criticality": 7
            }
        ]
    
    def test_attack_graph_generation(self) -> bool:
        """Test attack graph generation using NetworkX"""
        logger.info("🕸️ Testing Attack Graph Generation...")
        
        try:
            # Create sample vulnerability data
            vuln_data = self.create_sample_vulnerability_data()
            
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
                          service=vuln['service'],
                          port=vuln['port'])
                
                # Add edge from vulnerability to asset
                G.add_edge(vuln_id, asset_id, 
                          relationship="affects",
                          weight=vuln['cvss']/10.0)
            
            # Add attack path edges based on network topology and vulnerability chains
            self._add_attack_paths(G, vuln_data)
            
            # Generate graph statistics
            stats = {
                "nodes": len(G.nodes()),
                "edges": len(G.edges()),
                "assets": len([n for n, d in G.nodes(data=True) if d.get('node_type') == 'asset']),
                "vulnerabilities": len([n for n, d in G.nodes(data=True) if d.get('node_type') == 'vulnerability']),
                "critical_vulns": len([n for n, d in G.nodes(data=True) 
                                     if d.get('node_type') == 'vulnerability' and d.get('severity') == 'Critical'])
            }
            
            # Find attack paths
            attack_paths = self._find_attack_paths(G)
            
            # Visualize the graph
            self._visualize_attack_graph(G, "attack_graph_test.png")
            
            # Export graph data
            graph_data = {
                "nodes": [{"id": n, **d} for n, d in G.nodes(data=True)],
                "edges": [{"source": u, "target": v, **d} for u, v, d in G.edges(data=True)],
                "statistics": stats,
                "attack_paths": attack_paths
            }
            
            with open("attack_graph_test.json", "w") as f:
                json.dump(graph_data, f, indent=2)
            
            self.log_test_result("attack_graph", "PASSED", {
                "statistics": stats,
                "attack_paths_found": len(attack_paths),
                "output_files": ["attack_graph_test.png", "attack_graph_test.json"]
            })
            
            return True
            
        except Exception as e:
            self.log_test_result("attack_graph", "FAILED", {"error": str(e)})
            return False
    
    def _add_attack_paths(self, G: nx.DiGraph, vuln_data: List[Dict]):
        """Add realistic attack paths to the graph"""
        # Example attack chains:
        # 1. Web server (Log4j) -> Database server (lateral movement)
        # 2. SSH server -> Web server (privilege escalation)
        # 3. FTP server -> SSH server (network pivot)
        
        attack_chains = [
            ("vuln_001", "vuln_002", "lateral_movement", 0.8),  # Web to DB
            ("vuln_003", "vuln_001", "privilege_escalation", 0.6),  # SSH to Web
            ("vuln_004", "vuln_003", "network_pivot", 0.9),  # FTP to SSH
            ("vuln_002", "asset_192.168.1.200", "data_exfiltration", 0.7)  # DB access
        ]
        
        for source, target, attack_type, probability in attack_chains:
            if G.has_node(source) and G.has_node(target):
                G.add_edge(source, target,
                          relationship="attack_path",
                          attack_type=attack_type,
                          probability=probability,
                          weight=probability)
    
    def _find_attack_paths(self, G: nx.DiGraph) -> List[Dict]:
        """Find potential attack paths in the graph"""
        attack_paths = []
        
        # Find entry points (externally accessible services)
        entry_points = [n for n, d in G.nodes(data=True) 
                       if d.get('node_type') == 'vulnerability' and 
                       d.get('service') in ['http', 'ftp', 'ssh']]
        
        # Find high-value targets (critical assets)
        targets = [n for n, d in G.nodes(data=True)
                  if d.get('node_type') == 'asset' and 
                  d.get('asset_type') in ['database_server', 'web_server']]
        
        # Calculate shortest paths
        for entry in entry_points:
            for target in targets:
                try:
                    if nx.has_path(G, entry, target):
                        path = nx.shortest_path(G, entry, target)
                        path_length = len(path) - 1
                        
                        # Calculate path risk score
                        risk_score = 0
                        for i in range(len(path) - 1):
                            edge_data = G.get_edge_data(path[i], path[i+1])
                            if edge_data:
                                risk_score += edge_data.get('weight', 0.5)
                        
                        attack_paths.append({
                            "entry_point": entry,
                            "target": target,
                            "path": path,
                            "length": path_length,
                            "risk_score": risk_score / path_length if path_length > 0 else 0
                        })
                except nx.NetworkXNoPath:
                    continue
        
        # Sort by risk score
        attack_paths.sort(key=lambda x: x['risk_score'], reverse=True)
        return attack_paths[:10]  # Top 10 paths
    
    def _visualize_attack_graph(self, G: nx.DiGraph, filename: str):
        """Create a visualization of the attack graph"""
        plt.figure(figsize=(15, 10))
        
        # Create layout
        pos = nx.spring_layout(G, k=3, iterations=50)
        
        # Separate nodes by type
        asset_nodes = [n for n, d in G.nodes(data=True) if d.get('node_type') == 'asset']
        vuln_nodes = [n for n, d in G.nodes(data=True) if d.get('node_type') == 'vulnerability']
        
        # Draw asset nodes (blue)
        nx.draw_networkx_nodes(G, pos, nodelist=asset_nodes, 
                              node_color='lightblue', node_size=1000, alpha=0.8)
        
        # Draw vulnerability nodes (red for critical, orange for high, yellow for medium)
        critical_vulns = [n for n in vuln_nodes 
                         if G.nodes[n].get('severity') == 'Critical']
        high_vulns = [n for n in vuln_nodes 
                     if G.nodes[n].get('severity') == 'High']
        medium_vulns = [n for n in vuln_nodes 
                       if G.nodes[n].get('severity') == 'Medium']
        
        nx.draw_networkx_nodes(G, pos, nodelist=critical_vulns,
                              node_color='red', node_size=800, alpha=0.8)
        nx.draw_networkx_nodes(G, pos, nodelist=high_vulns,
                              node_color='orange', node_size=600, alpha=0.8)
        nx.draw_networkx_nodes(G, pos, nodelist=medium_vulns,
                              node_color='yellow', node_size=400, alpha=0.8)
        
        # Draw edges
        attack_edges = [(u, v) for u, v, d in G.edges(data=True) 
                       if d.get('relationship') == 'attack_path']
        affect_edges = [(u, v) for u, v, d in G.edges(data=True) 
                       if d.get('relationship') == 'affects']
        
        nx.draw_networkx_edges(G, pos, edgelist=attack_edges,
                              edge_color='red', width=2, alpha=0.7, 
                              arrowsize=20, arrowstyle='->')
        nx.draw_networkx_edges(G, pos, edgelist=affect_edges,
                              edge_color='gray', width=1, alpha=0.5,
                              arrowsize=15, arrowstyle='->')
        
        # Add labels
        labels = {}
        for n, d in G.nodes(data=True):
            if d.get('node_type') == 'asset':
                labels[n] = d.get('hostname', n)
            else:
                labels[n] = d.get('cve', n)
        
        nx.draw_networkx_labels(G, pos, labels, font_size=8)
        
        plt.title("SecureChain Attack Graph Visualization", size=16)
        plt.legend(['Assets', 'Critical Vulns', 'High Vulns', 'Medium Vulns'], 
                  loc='upper right')
        plt.axis('off')
        plt.tight_layout()
        plt.savefig(filename, dpi=300, bbox_inches='tight')
        plt.close()
        
        logger.info(f"Attack graph visualization saved to {filename}")
    
    def test_backend_integration(self) -> bool:
        """Test backend API integration"""
        logger.info("🔗 Testing Backend Integration...")
        
        try:
            # Test health endpoint
            response = requests.get(f"{self.backend_url}/health", timeout=10)
            if response.status_code != 200:
                self.log_test_result("backend_health", "FAILED", 
                                   {"status_code": response.status_code})
                return False
            
            health_data = response.json()
            self.log_test_result("backend_health", "PASSED", health_data)
            
            # Test ingestion endpoint with sample data
            sample_findings = self.create_sample_vulnerability_data()
            
            for finding in sample_findings:
                response = requests.post(
                    f"{self.backend_url}/api/v1/ingestion/ingest",
                    json={"findings": [finding]},
                    timeout=30
                )
                
                if response.status_code not in [200, 201]:
                    self.log_test_result("backend_ingestion", "FAILED", {
                        "status_code": response.status_code,
                        "finding_id": finding['finding_id']
                    })
                    return False
            
            # Test findings retrieval
            response = requests.get(f"{self.backend_url}/api/v1/ingestion/findings", timeout=10)
            if response.status_code == 200:
                findings = response.json()
                self.log_test_result("backend_retrieval", "PASSED", {
                    "findings_count": len(findings)
                })
            else:
                self.log_test_result("backend_retrieval", "FAILED", {
                    "status_code": response.status_code
                })
                return False
            
            return True
            
        except Exception as e:
            self.log_test_result("backend_integration", "FAILED", {"error": str(e)})
            return False
    
    def test_chatbot_queries(self) -> bool:
        """Test chatbot functionality with vulnerability queries"""
        logger.info("🤖 Testing Chatbot Queries...")
        
        try:
            # Test various vulnerability-related queries
            test_queries = [
                "What are the critical vulnerabilities in our network?",
                "Show me all CVE-2021-44228 findings",
                "Which assets are most at risk?",
                "What attack paths exist from external services?",
                "How can we remediate the Log4j vulnerability?"
            ]
            
            chatbot_url = f"{self.backend_url}/api/v1/chat"
            successful_queries = 0
            
            for query in test_queries:
                try:
                    response = requests.post(
                        chatbot_url,
                        json={"message": query},
                        timeout=30
                    )
                    
                    if response.status_code == 200:
                        result = response.json()
                        if result.get('response'):
                            successful_queries += 1
                            logger.info(f"Query successful: {query[:50]}...")
                        else:
                            logger.warning(f"Empty response for: {query[:50]}...")
                    else:
                        logger.warning(f"Failed query: {query[:50]}... (Status: {response.status_code})")
                        
                except Exception as e:
                    logger.warning(f"Query error: {query[:50]}... - {str(e)}")
            
            success_rate = successful_queries / len(test_queries)
            
            if success_rate >= 0.6:  # 60% success rate threshold
                self.log_test_result("chatbot_queries", "PASSED", {
                    "successful_queries": successful_queries,
                    "total_queries": len(test_queries),
                    "success_rate": success_rate
                })
                return True
            else:
                self.log_test_result("chatbot_queries", "FAILED", {
                    "successful_queries": successful_queries,
                    "total_queries": len(test_queries),
                    "success_rate": success_rate
                })
                return False
                
        except Exception as e:
            self.log_test_result("chatbot_queries", "FAILED", {"error": str(e)})
            return False
    
    def generate_comprehensive_report(self):
        """Generate a comprehensive test report"""
        logger.info("📊 Generating Comprehensive Test Report...")
        
        # Calculate overall success rate
        total_tests = len(self.test_results['tests'])
        passed_tests = len([t for t in self.test_results['tests'].values() 
                           if t['status'] == 'PASSED'])
        success_rate = passed_tests / total_tests if total_tests > 0 else 0
        
        self.test_results['overall_status'] = 'PASSED' if success_rate >= 0.8 else 'FAILED'
        self.test_results['summary'] = {
            'total_tests': total_tests,
            'passed_tests': passed_tests,
            'failed_tests': total_tests - passed_tests,
            'success_rate': success_rate
        }
        
        # Save detailed results
        with open('comprehensive_test_results.json', 'w') as f:
            json.dump(self.test_results, f, indent=2)
        
        # Generate HTML report
        self._generate_html_report()
        
        # Print summary
        print("\n" + "="*80)
        print("🛡️  SECURECHAIN COMPREHENSIVE PIPELINE TEST RESULTS")
        print("="*80)
        print(f"Overall Status: {self.test_results['overall_status']}")
        print(f"Success Rate: {success_rate:.1%}")
        print(f"Tests Passed: {passed_tests}/{total_tests}")
        print("\nTest Details:")
        
        for test_name, result in self.test_results['tests'].items():
            status_icon = "✅" if result['status'] == 'PASSED' else "❌"
            print(f"  {status_icon} {test_name}: {result['status']}")
            if result.get('details'):
                for key, value in result['details'].items():
                    print(f"    - {key}: {value}")
        
        print("\nGenerated Files:")
        output_files = [
            "comprehensive_test_results.json",
            "pipeline_test_report.html", 
            "attack_graph_test.png",
            "attack_graph_test.json",
            "pipeline_test.log"
        ]
        
        for file in output_files:
            if Path(file).exists():
                print(f"  ✅ {file}")
            else:
                print(f"  ❌ {file}")
        
        print("="*80)
        
        return self.test_results['overall_status'] == 'PASSED'
    
    def _generate_html_report(self):
        """Generate an HTML test report"""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>SecureChain Pipeline Test Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
                .summary {{ background: #ecf0f1; padding: 15px; margin: 20px 0; border-radius: 5px; }}
                .test-result {{ margin: 10px 0; padding: 10px; border-radius: 5px; }}
                .passed {{ background: #d5f4e6; border-left: 5px solid #27ae60; }}
                .failed {{ background: #fadbd8; border-left: 5px solid #e74c3c; }}
                .details {{ margin-left: 20px; font-size: 0.9em; color: #666; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🛡️ SecureChain Comprehensive Pipeline Test Report</h1>
                <p>Generated: {self.test_results['timestamp']}</p>
            </div>
            
            <div class="summary">
                <h2>Summary</h2>
                <p><strong>Overall Status:</strong> {self.test_results['overall_status']}</p>
                <p><strong>Success Rate:</strong> {self.test_results['summary']['success_rate']:.1%}</p>
                <p><strong>Tests Passed:</strong> {self.test_results['summary']['passed_tests']}/{self.test_results['summary']['total_tests']}</p>
            </div>
            
            <h2>Test Results</h2>
        """
        
        for test_name, result in self.test_results['tests'].items():
            css_class = "passed" if result['status'] == 'PASSED' else "failed"
            html_content += f"""
            <div class="test-result {css_class}">
                <h3>{test_name}: {result['status']}</h3>
                <p><em>Timestamp: {result['timestamp']}</em></p>
            """
            
            if result.get('details'):
                html_content += "<div class='details'><strong>Details:</strong><ul>"
                for key, value in result['details'].items():
                    html_content += f"<li><strong>{key}:</strong> {value}</li>"
                html_content += "</ul></div>"
            
            html_content += "</div>"
        
        html_content += """
        </body>
        </html>
        """
        
        with open('pipeline_test_report.html', 'w') as f:
            f.write(html_content)
    
    def run_comprehensive_test(self):
        """Run the complete test suite"""
        logger.info("🚀 Starting Comprehensive SecureChain Pipeline Test...")
        
        # Test sequence
        tests = [
            ("AI Vulnerability Scanner", self.test_ai_vulnerability_scanner),
            ("OpenCTI Integration", self.test_opencti_integration),
            ("Attack Graph Generation", self.test_attack_graph_generation),
            ("Backend Integration", self.test_backend_integration),
            ("Chatbot Queries", self.test_chatbot_queries)
        ]
        
        for test_name, test_func in tests:
            logger.info(f"\n{'='*60}")
            logger.info(f"Running: {test_name}")
            logger.info(f"{'='*60}")
            
            try:
                success = test_func()
                if not success:
                    logger.warning(f"Test '{test_name}' failed, continuing with remaining tests...")
            except Exception as e:
                logger.error(f"Test '{test_name}' encountered an error: {e}")
                self.log_test_result(test_name.lower().replace(' ', '_'), "ERROR", {"error": str(e)})
        
        # Generate final report
        return self.generate_comprehensive_report()

def main():
    """Main function"""
    print("🛡️  SecureChain Comprehensive Pipeline Test")
    print("="*80)
    print("This test will validate the entire SecureChain pipeline:")
    print("1. AI Vulnerability Scanner with real targets")
    print("2. OpenCTI threat intelligence integration")
    print("3. Attack graph generation using NetworkX")
    print("4. Backend API integration")
    print("5. Chatbot vulnerability query testing")
    print("="*80)
    
    # Confirm test execution
    response = input("\nProceed with comprehensive testing? (y/N): ").strip().lower()
    if response != 'y':
        print("Test cancelled.")
        return
    
    # Run tests
    tester = ComprehensivePipelineTest()
    success = tester.run_comprehensive_test()
    
    if success:
        print("\n🎉 All tests completed successfully!")
        sys.exit(0)
    else:
        print("\n⚠️  Some tests failed. Check the report for details.")
        sys.exit(1)

if __name__ == "__main__":
    main()