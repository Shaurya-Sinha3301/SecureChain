#!/usr/bin/env python3
"""
Advanced Attack Graph Generator using NetworkX
Creates sophisticated attack graphs with MITRE ATT&CK mapping and risk analysis
"""

import json
import networkx as nx
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Any
from pathlib import Path
import logging
from datetime import datetime
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AttackGraphGenerator:
    """Advanced attack graph generator with NetworkX"""
    
    def __init__(self):
        self.graph = nx.DiGraph()
        self.mitre_mapping = self._load_mitre_mapping()
        self.risk_weights = {
            'Critical': 1.0,
            'High': 0.8,
            'Medium': 0.6,
            'Low': 0.3
        }
        
    def _load_mitre_mapping(self) -> Dict:
        """Load MITRE ATT&CK technique mappings"""
        return {
            'ssh': {'technique': 'T1021.004', 'name': 'Remote Services: SSH'},
            'http': {'technique': 'T1190', 'name': 'Exploit Public-Facing Application'},
            'https': {'technique': 'T1190', 'name': 'Exploit Public-Facing Application'},
            'ftp': {'technique': 'T1021.002', 'name': 'Remote Services: SMB/Windows Admin Shares'},
            'mysql': {'technique': 'T1505.003', 'name': 'Server Software Component: Web Shell'},
            'rdp': {'technique': 'T1021.001', 'name': 'Remote Services: Remote Desktop Protocol'},
            'smb': {'technique': 'T1021.002', 'name': 'Remote Services: SMB/Windows Admin Shares'}
        }
    
    def load_vulnerability_data(self, data_source: str) -> List[Dict]:
        """Load vulnerability data from various sources"""
        if isinstance(data_source, str) and Path(data_source).exists():
            with open(data_source, 'r') as f:
                return json.load(f)
        elif isinstance(data_source, list):
            return data_source
        else:
            # Generate sample data for testing
            return self._generate_sample_data()
    
    def _generate_sample_data(self) -> List[Dict]:
        """Generate realistic sample vulnerability data"""
        return [
            {
                "finding_id": "vuln_web_001",
                "host": "web-dmz-01",
                "ip": "10.0.1.100",
                "service": "http",
                "port": 80,
                "version": "Apache 2.4.41",
                "cve": "CVE-2021-44228",
                "cvss": 9.8,
                "severity": "Critical",
                "evidence": "Log4j RCE vulnerability in web application",
                "asset_type": "web_server",
                "network_zone": "dmz",
                "criticality": 9,
                "exploitability": 0.95
            },
            {
                "finding_id": "vuln_db_001",
                "host": "db-internal-01",
                "ip": "10.0.2.200",
                "service": "mysql",
                "port": 3306,
                "version": "MySQL 5.7.30",
                "cve": "CVE-2020-14867",
                "cvss": 7.5,
                "severity": "High",
                "evidence": "MySQL privilege escalation vulnerability",
                "asset_type": "database_server",
                "network_zone": "internal",
                "criticality": 10,
                "exploitability": 0.7
            },
            {
                "finding_id": "vuln_ssh_001",
                "host": "jump-server-01",
                "ip": "10.0.1.150",
                "service": "ssh",
                "port": 22,
                "version": "OpenSSH 7.4",
                "cve": "CVE-2018-15473",
                "cvss": 5.3,
                "severity": "Medium",
                "evidence": "SSH user enumeration vulnerability",
                "asset_type": "jump_server",
                "network_zone": "dmz",
                "criticality": 7,
                "exploitability": 0.4
            },
            {
                "finding_id": "vuln_ftp_001",
                "host": "file-server-01",
                "ip": "10.0.2.180",
                "service": "ftp",
                "port": 21,
                "version": "vsftpd 2.3.4",
                "cve": "CVE-2011-2523",
                "cvss": 10.0,
                "severity": "Critical",
                "evidence": "FTP backdoor vulnerability",
                "asset_type": "file_server",
                "network_zone": "internal",
                "criticality": 6,
                "exploitability": 1.0
            },
            {
                "finding_id": "vuln_rdp_001",
                "host": "admin-workstation-01",
                "ip": "10.0.3.50",
                "service": "rdp",
                "port": 3389,
                "version": "Windows RDP",
                "cve": "CVE-2019-0708",
                "cvss": 9.8,
                "severity": "Critical",
                "evidence": "BlueKeep RDP vulnerability",
                "asset_type": "workstation",
                "network_zone": "admin",
                "criticality": 8,
                "exploitability": 0.8
            }
        ]
    
    def build_attack_graph(self, vulnerability_data: List[Dict]) -> nx.DiGraph:
        """Build comprehensive attack graph from vulnerability data"""
        logger.info(f"Building attack graph from {len(vulnerability_data)} vulnerabilities")
        
        # Clear existing graph
        self.graph.clear()
        
        # Add nodes for assets and vulnerabilities
        for vuln in vulnerability_data:
            self._add_asset_node(vuln)
            self._add_vulnerability_node(vuln)
            self._add_vulnerability_to_asset_edge(vuln)
        
        # Add network topology edges
        self._add_network_topology_edges(vulnerability_data)
        
        # Add attack path edges
        self._add_attack_path_edges(vulnerability_data)
        
        # Add MITRE ATT&CK mappings
        self._add_mitre_mappings()
        
        logger.info(f"Attack graph built: {len(self.graph.nodes())} nodes, {len(self.graph.edges())} edges")
        return self.graph
    
    def _add_asset_node(self, vuln: Dict):
        """Add asset node to graph"""
        asset_id = f"asset_{vuln['ip']}"
        
        if not self.graph.has_node(asset_id):
            self.graph.add_node(asset_id,
                              node_type="asset",
                              ip=vuln['ip'],
                              hostname=vuln['host'],
                              asset_type=vuln['asset_type'],
                              network_zone=vuln.get('network_zone', 'unknown'),
                              criticality=vuln.get('criticality', 5),
                              compromised=False)
    
    def _add_vulnerability_node(self, vuln: Dict):
        """Add vulnerability node to graph"""
        vuln_id = vuln['finding_id']
        
        self.graph.add_node(vuln_id,
                          node_type="vulnerability",
                          cve=vuln['cve'],
                          cvss=vuln['cvss'],
                          severity=vuln['severity'],
                          service=vuln['service'],
                          port=vuln['port'],
                          version=vuln.get('version', ''),
                          exploitability=vuln.get('exploitability', 0.5),
                          evidence=vuln.get('evidence', ''))
    
    def _add_vulnerability_to_asset_edge(self, vuln: Dict):
        """Add edge from vulnerability to asset"""
        vuln_id = vuln['finding_id']
        asset_id = f"asset_{vuln['ip']}"
        
        self.graph.add_edge(vuln_id, asset_id,
                          relationship="affects",
                          weight=self.risk_weights.get(vuln['severity'], 0.5))
    
    def _add_network_topology_edges(self, vulnerability_data: List[Dict]):
        """Add network topology edges based on network zones"""
        # Group assets by network zone
        zones = {}
        for vuln in vulnerability_data:
            zone = vuln.get('network_zone', 'unknown')
            asset_id = f"asset_{vuln['ip']}"
            if zone not in zones:
                zones[zone] = []
            if asset_id not in zones[zone]:
                zones[zone].append(asset_id)
        
        # Add connectivity within zones and between zones
        zone_connectivity = {
            ('dmz', 'internal'): 0.8,
            ('internal', 'admin'): 0.6,
            ('dmz', 'admin'): 0.3
        }
        
        for (zone1, zone2), connectivity in zone_connectivity.items():
            if zone1 in zones and zone2 in zones:
                for asset1 in zones[zone1]:
                    for asset2 in zones[zone2]:
                        self.graph.add_edge(asset1, asset2,
                                          relationship="network_access",
                                          weight=connectivity,
                                          zone_transition=f"{zone1}_to_{zone2}")
    
    def _add_attack_path_edges(self, vulnerability_data: List[Dict]):
        """Add realistic attack path edges"""
        # Define attack patterns
        attack_patterns = [
            # Web server compromise -> lateral movement
            {
                'source_service': 'http',
                'target_services': ['mysql', 'ssh', 'ftp'],
                'attack_type': 'lateral_movement',
                'probability': 0.7
            },
            # SSH compromise -> privilege escalation
            {
                'source_service': 'ssh',
                'target_services': ['http', 'mysql'],
                'attack_type': 'privilege_escalation',
                'probability': 0.6
            },
            # Database access -> data exfiltration
            {
                'source_service': 'mysql',
                'target_services': ['ftp', 'rdp'],
                'attack_type': 'data_exfiltration',
                'probability': 0.8
            },
            # RDP compromise -> admin access
            {
                'source_service': 'rdp',
                'target_services': ['mysql', 'ssh', 'http'],
                'attack_type': 'admin_access',
                'probability': 0.9
            }
        ]
        
        # Apply attack patterns
        for pattern in attack_patterns:
            source_vulns = [v for v in vulnerability_data 
                           if v['service'] == pattern['source_service']]
            target_vulns = [v for v in vulnerability_data 
                           if v['service'] in pattern['target_services']]
            
            for source_vuln in source_vulns:
                for target_vuln in target_vulns:
                    if source_vuln['finding_id'] != target_vuln['finding_id']:
                        # Check network reachability
                        if self._is_network_reachable(source_vuln, target_vuln):
                            self.graph.add_edge(
                                source_vuln['finding_id'],
                                target_vuln['finding_id'],
                                relationship="attack_path",
                                attack_type=pattern['attack_type'],
                                probability=pattern['probability'],
                                weight=pattern['probability']
                            )
    
    def _is_network_reachable(self, source_vuln: Dict, target_vuln: Dict) -> bool:
        """Check if target is reachable from source based on network zones"""
        source_zone = source_vuln.get('network_zone', 'unknown')
        target_zone = target_vuln.get('network_zone', 'unknown')
        
        # Define reachability matrix
        reachability = {
            ('dmz', 'dmz'): True,
            ('dmz', 'internal'): True,
            ('dmz', 'admin'): False,
            ('internal', 'internal'): True,
            ('internal', 'admin'): True,
            ('internal', 'dmz'): False,
            ('admin', 'admin'): True,
            ('admin', 'internal'): True,
            ('admin', 'dmz'): False
        }
        
        return reachability.get((source_zone, target_zone), False)
    
    def _add_mitre_mappings(self):
        """Add MITRE ATT&CK technique mappings to vulnerability nodes"""
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get('node_type') == 'vulnerability':
                service = node_data.get('service', '')
                if service in self.mitre_mapping:
                    mitre_info = self.mitre_mapping[service]
                    self.graph.nodes[node_id]['mitre_technique'] = mitre_info['technique']
                    self.graph.nodes[node_id]['mitre_name'] = mitre_info['name']
    
    def find_attack_paths(self, max_length: int = 5, top_k: int = 10) -> List[Dict]:
        """Find top attack paths in the graph"""
        logger.info("Finding attack paths...")
        
        # Identify entry points (externally accessible vulnerabilities)
        entry_points = []
        for node_id, node_data in self.graph.nodes(data=True):
            if (node_data.get('node_type') == 'vulnerability' and
                node_data.get('service') in ['http', 'https', 'ftp', 'ssh']):
                entry_points.append(node_id)
        
        # Identify high-value targets (critical assets)
        targets = []
        for node_id, node_data in self.graph.nodes(data=True):
            if (node_data.get('node_type') == 'asset' and
                node_data.get('criticality', 0) >= 8):
                targets.append(node_id)
        
        attack_paths = []
        
        # Find paths from each entry point to each target
        for entry in entry_points:
            for target in targets:
                try:
                    if nx.has_path(self.graph, entry, target):
                        # Find all simple paths up to max_length
                        paths = list(nx.all_simple_paths(
                            self.graph, entry, target, cutoff=max_length))
                        
                        for path in paths:
                            if len(path) <= max_length:
                                risk_score = self._calculate_path_risk(path)
                                attack_paths.append({
                                    'entry_point': entry,
                                    'target': target,
                                    'path': path,
                                    'length': len(path) - 1,
                                    'risk_score': risk_score,
                                    'path_description': self._describe_path(path)
                                })
                except nx.NetworkXNoPath:
                    continue
        
        # Sort by risk score and return top k
        attack_paths.sort(key=lambda x: x['risk_score'], reverse=True)
        return attack_paths[:top_k]
    
    def _calculate_path_risk(self, path: List[str]) -> float:
        """Calculate risk score for an attack path"""
        total_risk = 0.0
        path_length = len(path) - 1
        
        for i in range(len(path) - 1):
            edge_data = self.graph.get_edge_data(path[i], path[i+1])
            if edge_data:
                weight = edge_data.get('weight', 0.5)
                total_risk += weight
        
        # Normalize by path length and apply exploitability factors
        if path_length > 0:
            avg_risk = total_risk / path_length
            
            # Apply exploitability bonus for vulnerability nodes
            exploitability_bonus = 0
            vuln_count = 0
            for node in path:
                node_data = self.graph.nodes.get(node, {})
                if node_data.get('node_type') == 'vulnerability':
                    exploitability_bonus += node_data.get('exploitability', 0.5)
                    vuln_count += 1
            
            if vuln_count > 0:
                avg_exploitability = exploitability_bonus / vuln_count
                return avg_risk * avg_exploitability
        
        return total_risk
    
    def _describe_path(self, path: List[str]) -> str:
        """Generate human-readable description of attack path"""
        descriptions = []
        
        for i, node in enumerate(path):
            node_data = self.graph.nodes.get(node, {})
            
            if node_data.get('node_type') == 'vulnerability':
                service = node_data.get('service', 'unknown')
                cve = node_data.get('cve', 'unknown')
                descriptions.append(f"Exploit {service} ({cve})")
            elif node_data.get('node_type') == 'asset':
                hostname = node_data.get('hostname', 'unknown')
                asset_type = node_data.get('asset_type', 'unknown')
                descriptions.append(f"Compromise {hostname} ({asset_type})")
        
        return " → ".join(descriptions)
    
    def visualize_attack_graph(self, output_file: str = "attack_graph.png", 
                             layout: str = "spring", figsize: Tuple[int, int] = (20, 15)):
        """Create advanced visualization of the attack graph"""
        logger.info(f"Creating attack graph visualization: {output_file}")
        
        plt.figure(figsize=figsize)
        
        # Choose layout algorithm
        if layout == "spring":
            pos = nx.spring_layout(self.graph, k=3, iterations=50, seed=42)
        elif layout == "circular":
            pos = nx.circular_layout(self.graph)
        elif layout == "hierarchical":
            pos = nx.nx_agraph.graphviz_layout(self.graph, prog='dot')
        else:
            pos = nx.spring_layout(self.graph)
        
        # Separate nodes by type and properties
        asset_nodes = []
        vuln_nodes_critical = []
        vuln_nodes_high = []
        vuln_nodes_medium = []
        vuln_nodes_low = []
        
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get('node_type') == 'asset':
                asset_nodes.append(node_id)
            elif node_data.get('node_type') == 'vulnerability':
                severity = node_data.get('severity', 'Low')
                if severity == 'Critical':
                    vuln_nodes_critical.append(node_id)
                elif severity == 'High':
                    vuln_nodes_high.append(node_id)
                elif severity == 'Medium':
                    vuln_nodes_medium.append(node_id)
                else:
                    vuln_nodes_low.append(node_id)
        
        # Draw nodes with different colors and sizes
        nx.draw_networkx_nodes(self.graph, pos, nodelist=asset_nodes,
                              node_color='lightblue', node_size=1500, 
                              alpha=0.8, node_shape='s')
        
        nx.draw_networkx_nodes(self.graph, pos, nodelist=vuln_nodes_critical,
                              node_color='darkred', node_size=1000, alpha=0.9)
        
        nx.draw_networkx_nodes(self.graph, pos, nodelist=vuln_nodes_high,
                              node_color='red', node_size=800, alpha=0.8)
        
        nx.draw_networkx_nodes(self.graph, pos, nodelist=vuln_nodes_medium,
                              node_color='orange', node_size=600, alpha=0.7)
        
        nx.draw_networkx_nodes(self.graph, pos, nodelist=vuln_nodes_low,
                              node_color='yellow', node_size=400, alpha=0.6)
        
        # Draw edges with different styles
        attack_edges = [(u, v) for u, v, d in self.graph.edges(data=True)
                       if d.get('relationship') == 'attack_path']
        affect_edges = [(u, v) for u, v, d in self.graph.edges(data=True)
                       if d.get('relationship') == 'affects']
        network_edges = [(u, v) for u, v, d in self.graph.edges(data=True)
                        if d.get('relationship') == 'network_access']
        
        nx.draw_networkx_edges(self.graph, pos, edgelist=attack_edges,
                              edge_color='red', width=3, alpha=0.8,
                              arrowsize=20, arrowstyle='->')
        
        nx.draw_networkx_edges(self.graph, pos, edgelist=affect_edges,
                              edge_color='gray', width=1, alpha=0.5,
                              arrowsize=15, arrowstyle='->')
        
        nx.draw_networkx_edges(self.graph, pos, edgelist=network_edges,
                              edge_color='blue', width=1, alpha=0.3,
                              arrowsize=10, arrowstyle='->', style='dashed')
        
        # Add labels
        labels = {}
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get('node_type') == 'asset':
                labels[node_id] = node_data.get('hostname', node_id)
            else:
                cve = node_data.get('cve', node_id)
                service = node_data.get('service', '')
                labels[node_id] = f"{cve}\n({service})"
        
        nx.draw_networkx_labels(self.graph, pos, labels, font_size=8, font_weight='bold')
        
        # Create legend
        legend_elements = [
            mpatches.Rectangle((0, 0), 1, 1, facecolor='lightblue', label='Assets'),
            mpatches.Circle((0, 0), 1, facecolor='darkred', label='Critical Vulns'),
            mpatches.Circle((0, 0), 1, facecolor='red', label='High Vulns'),
            mpatches.Circle((0, 0), 1, facecolor='orange', label='Medium Vulns'),
            mpatches.Circle((0, 0), 1, facecolor='yellow', label='Low Vulns'),
            plt.Line2D([0], [0], color='red', linewidth=3, label='Attack Paths'),
            plt.Line2D([0], [0], color='gray', linewidth=1, label='Affects'),
            plt.Line2D([0], [0], color='blue', linewidth=1, linestyle='--', label='Network Access')
        ]
        
        plt.legend(handles=legend_elements, loc='upper left', bbox_to_anchor=(1, 1))
        
        plt.title("SecureChain Attack Graph Analysis", size=20, fontweight='bold')
        plt.axis('off')
        plt.tight_layout()
        plt.savefig(output_file, dpi=300, bbox_inches='tight', facecolor='white')
        plt.close()
        
        logger.info(f"Attack graph visualization saved to {output_file}")
    
    def create_interactive_visualization(self, output_file: str = "attack_graph_interactive.html"):
        """Create interactive Plotly visualization"""
        logger.info(f"Creating interactive visualization: {output_file}")
        
        # Get node positions
        pos = nx.spring_layout(self.graph, k=3, iterations=50, seed=42)
        
        # Prepare node data
        node_x = []
        node_y = []
        node_text = []
        node_color = []
        node_size = []
        
        for node_id, node_data in self.graph.nodes(data=True):
            x, y = pos[node_id]
            node_x.append(x)
            node_y.append(y)
            
            if node_data.get('node_type') == 'asset':
                hostname = node_data.get('hostname', node_id)
                asset_type = node_data.get('asset_type', 'unknown')
                criticality = node_data.get('criticality', 0)
                node_text.append(f"Asset: {hostname}<br>Type: {asset_type}<br>Criticality: {criticality}")
                node_color.append('lightblue')
                node_size.append(30)
            else:
                cve = node_data.get('cve', node_id)
                service = node_data.get('service', 'unknown')
                severity = node_data.get('severity', 'Low')
                cvss = node_data.get('cvss', 0)
                node_text.append(f"Vulnerability: {cve}<br>Service: {service}<br>Severity: {severity}<br>CVSS: {cvss}")
                
                if severity == 'Critical':
                    node_color.append('darkred')
                    node_size.append(25)
                elif severity == 'High':
                    node_color.append('red')
                    node_size.append(20)
                elif severity == 'Medium':
                    node_color.append('orange')
                    node_size.append(15)
                else:
                    node_color.append('yellow')
                    node_size.append(10)
        
        # Prepare edge data
        edge_x = []
        edge_y = []
        edge_info = []
        
        for edge in self.graph.edges(data=True):
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])
            
            relationship = edge[2].get('relationship', 'unknown')
            edge_info.append(f"{edge[0]} → {edge[1]}<br>Relationship: {relationship}")
        
        # Create Plotly figure
        fig = go.Figure()
        
        # Add edges
        fig.add_trace(go.Scatter(x=edge_x, y=edge_y,
                                line=dict(width=1, color='gray'),
                                hoverinfo='none',
                                mode='lines',
                                name='Relationships'))
        
        # Add nodes
        fig.add_trace(go.Scatter(x=node_x, y=node_y,
                                mode='markers+text',
                                marker=dict(size=node_size,
                                           color=node_color,
                                           line=dict(width=2, color='black')),
                                text=[node_id.split('_')[-1] for node_id in self.graph.nodes()],
                                textposition="middle center",
                                hovertext=node_text,
                                hoverinfo='text',
                                name='Nodes'))
        
        fig.update_layout(title="Interactive SecureChain Attack Graph",
                         showlegend=False,
                         hovermode='closest',
                         margin=dict(b=20,l=5,r=5,t=40),
                         annotations=[ dict(
                             text="Hover over nodes for details",
                             showarrow=False,
                             xref="paper", yref="paper",
                             x=0.005, y=-0.002,
                             xanchor='left', yanchor='bottom',
                             font=dict(color="gray", size=12)
                         )],
                         xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                         yaxis=dict(showgrid=False, zeroline=False, showticklabels=False))
        
        fig.write_html(output_file)
        logger.info(f"Interactive visualization saved to {output_file}")
    
    def export_attack_paths_csv(self, attack_paths: List[Dict], output_file: str = "attack_paths.csv"):
        """Export attack paths to CSV for analysis"""
        logger.info(f"Exporting attack paths to {output_file}")
        
        df_data = []
        for i, path_info in enumerate(attack_paths):
            df_data.append({
                'path_id': i + 1,
                'entry_point': path_info['entry_point'],
                'target': path_info['target'],
                'path_length': path_info['length'],
                'risk_score': path_info['risk_score'],
                'path_description': path_info['path_description'],
                'full_path': ' → '.join(path_info['path'])
            })
        
        df = pd.DataFrame(df_data)
        df.to_csv(output_file, index=False)
        logger.info(f"Attack paths exported to {output_file}")
    
    def generate_risk_report(self, attack_paths: List[Dict]) -> Dict:
        """Generate comprehensive risk assessment report"""
        logger.info("Generating risk assessment report")
        
        # Calculate statistics
        total_paths = len(attack_paths)
        if total_paths == 0:
            return {"error": "No attack paths found"}
        
        avg_path_length = np.mean([p['length'] for p in attack_paths])
        max_risk_score = max([p['risk_score'] for p in attack_paths])
        avg_risk_score = np.mean([p['risk_score'] for p in attack_paths])
        
        # Identify most common entry points and targets
        entry_points = [p['entry_point'] for p in attack_paths]
        targets = [p['target'] for p in attack_paths]
        
        from collections import Counter
        common_entries = Counter(entry_points).most_common(5)
        common_targets = Counter(targets).most_common(5)
        
        # Vulnerability severity distribution
        vuln_severities = []
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get('node_type') == 'vulnerability':
                vuln_severities.append(node_data.get('severity', 'Low'))
        
        severity_dist = Counter(vuln_severities)
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_attack_paths': total_paths,
                'average_path_length': round(avg_path_length, 2),
                'maximum_risk_score': round(max_risk_score, 4),
                'average_risk_score': round(avg_risk_score, 4),
                'total_assets': len([n for n, d in self.graph.nodes(data=True) 
                                   if d.get('node_type') == 'asset']),
                'total_vulnerabilities': len([n for n, d in self.graph.nodes(data=True) 
                                            if d.get('node_type') == 'vulnerability'])
            },
            'top_entry_points': [{'node': ep, 'count': count} for ep, count in common_entries],
            'top_targets': [{'node': target, 'count': count} for target, count in common_targets],
            'vulnerability_distribution': dict(severity_dist),
            'top_attack_paths': attack_paths[:5],
            'recommendations': self._generate_recommendations(attack_paths)
        }
        
        return report
    
    def _generate_recommendations(self, attack_paths: List[Dict]) -> List[str]:
        """Generate security recommendations based on attack paths"""
        recommendations = []
        
        if not attack_paths:
            return ["No attack paths found - system appears secure"]
        
        # Analyze common vulnerabilities
        vuln_services = []
        for path in attack_paths:
            for node in path['path']:
                node_data = self.graph.nodes.get(node, {})
                if node_data.get('node_type') == 'vulnerability':
                    vuln_services.append(node_data.get('service', ''))
        
        from collections import Counter
        common_services = Counter(vuln_services).most_common(3)
        
        for service, count in common_services:
            if service == 'http':
                recommendations.append(f"Secure web applications - {count} HTTP vulnerabilities found")
            elif service == 'ssh':
                recommendations.append(f"Harden SSH configuration - {count} SSH vulnerabilities found")
            elif service == 'mysql':
                recommendations.append(f"Update database security - {count} MySQL vulnerabilities found")
            elif service == 'ftp':
                recommendations.append(f"Consider disabling FTP or use SFTP - {count} FTP vulnerabilities found")
            elif service == 'rdp':
                recommendations.append(f"Secure RDP access - {count} RDP vulnerabilities found")
        
        # General recommendations
        if len(attack_paths) > 10:
            recommendations.append("High number of attack paths detected - implement network segmentation")
        
        max_risk = max([p['risk_score'] for p in attack_paths])
        if max_risk > 0.8:
            recommendations.append("Critical risk paths identified - prioritize immediate patching")
        
        return recommendations

def load_scan(filename: str) -> List[Dict]:
    """Load scan data from file"""
    if Path(filename).exists():
        with open(filename, 'r') as f:
            return json.load(f)
    else:
        # Return sample data if file doesn't exist
        generator = AttackGraphGenerator()
        return generator._generate_sample_data()

def build_graph(records: List[Dict]) -> nx.DiGraph:
    """Build attack graph from records"""
    generator = AttackGraphGenerator()
    return generator.build_attack_graph(records)

def compute_attack_paths(graph: nx.DiGraph, entry_points: List[str] = None, 
                        targets: List[str] = None, max_depth: int = 5, top_k: int = 10) -> List[Dict]:
    """Compute attack paths in the graph"""
    generator = AttackGraphGenerator()
    generator.graph = graph
    return generator.find_attack_paths(max_depth, top_k)

def main():
    """Main function for standalone execution"""
    print("🕸️  Advanced Attack Graph Generator")
    print("="*50)
    
    # Initialize generator
    generator = AttackGraphGenerator()
    
    # Load or generate data
    vuln_data = generator._generate_sample_data()
    print(f"Loaded {len(vuln_data)} vulnerability records")
    
    # Build attack graph
    graph = generator.build_attack_graph(vuln_data)
    print(f"Built attack graph: {len(graph.nodes())} nodes, {len(graph.edges())} edges")
    
    # Find attack paths
    attack_paths = generator.find_attack_paths()
    print(f"Found {len(attack_paths)} attack paths")
    
    # Generate visualizations
    generator.visualize_attack_graph("advanced_attack_graph.png")
    generator.create_interactive_visualization("advanced_attack_graph.html")
    
    # Export data
    generator.export_attack_paths_csv(attack_paths, "advanced_attack_paths.csv")
    
    # Generate risk report
    risk_report = generator.generate_risk_report(attack_paths)
    with open("risk_assessment_report.json", "w") as f:
        json.dump(risk_report, f, indent=2)
    
    print("\n📊 Generated Files:")
    print("  ✅ advanced_attack_graph.png - Static visualization")
    print("  ✅ advanced_attack_graph.html - Interactive visualization")
    print("  ✅ advanced_attack_paths.csv - Attack path analysis")
    print("  ✅ risk_assessment_report.json - Risk assessment report")
    
    print(f"\n🎯 Risk Summary:")
    print(f"  - Total attack paths: {risk_report['summary']['total_attack_paths']}")
    print(f"  - Average path length: {risk_report['summary']['average_path_length']}")
    print(f"  - Maximum risk score: {risk_report['summary']['maximum_risk_score']}")
    
    if risk_report.get('recommendations'):
        print(f"\n💡 Top Recommendations:")
        for i, rec in enumerate(risk_report['recommendations'][:3], 1):
            print(f"  {i}. {rec}")

if __name__ == "__main__":
    main()