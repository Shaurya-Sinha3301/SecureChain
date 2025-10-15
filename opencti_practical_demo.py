#!/usr/bin/env python3
"""
OpenCTI Practical Use Cases Demo
Demonstrates real-world threat intelligence scenarios
"""

import requests
import json
import hashlib
import ipaddress
from datetime import datetime
from typing import Dict, List, Any

class OpenCTIPracticalDemo:
    def __init__(self, base_url: str, token: str):
        self.base_url = base_url.rstrip('/')
        self.token = token
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        })
    
    def execute_query(self, query: str, variables: Dict = None) -> Dict[str, Any]:
        """Execute GraphQL query"""
        payload = {'query': query}
        if variables:
            payload['variables'] = variables
            
        try:
            response = self.session.post(f"{self.base_url}/graphql", json=payload, timeout=30)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {'errors': [{'message': str(e)}]}
    
    def check_ioc_reputation(self, ioc: str, ioc_type: str) -> Dict[str, Any]:
        """Check if an IOC exists in the threat intelligence database"""
        print(f"🔍 Checking reputation for {ioc_type}: {ioc}")
        
        # Create STIX pattern based on IOC type
        if ioc_type == "ip":
            pattern = f"[ipv4-addr:value = '{ioc}']"
        elif ioc_type == "domain":
            pattern = f"[domain-name:value = '{ioc}']"
        elif ioc_type == "hash":
            pattern = f"[file:hashes.MD5 = '{ioc}']"
        else:
            pattern = ioc
        
        query = """
        query SearchIndicators($search: String) {
            indicators(search: $search, first: 10) {
                edges {
                    node {
                        id
                        pattern
                        indicator_types
                        description
                        confidence
                        created
                        labels {
                            edges {
                                node {
                                    value
                                }
                            }
                        }
                        stixCoreRelationships {
                            edges {
                                node {
                                    relationship_type
                                    to {
                                        ... on StixCoreObject {
                                            entity_type
                                            ... on ThreatActor { name }
                                            ... on Malware { name }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        """
        
        result = self.execute_query(query, {"search": ioc})
        
        reputation = {
            'ioc': ioc,
            'type': ioc_type,
            'is_malicious': False,
            'confidence': 0,
            'threat_types': [],
            'associated_threats': [],
            'description': '',
            'first_seen': None
        }
        
        if 'data' in result and result['data']['indicators']['edges']:
            indicators = result['data']['indicators']['edges']
            
            for edge in indicators:
                indicator = edge['node']
                if ioc.lower() in indicator['pattern'].lower():
                    reputation['is_malicious'] = True
                    reputation['confidence'] = max(reputation['confidence'], indicator['confidence'])
                    reputation['threat_types'].extend(indicator['indicator_types'])
                    reputation['description'] = indicator.get('description', '')
                    reputation['first_seen'] = indicator['created']
                    
                    # Get associated threats
                    for rel_edge in indicator['stixCoreRelationships']['edges']:
                        rel = rel_edge['node']
                        threat_entity = rel['to']
                        reputation['associated_threats'].append({
                            'type': threat_entity['entity_type'],
                            'name': threat_entity.get('name', 'Unknown'),
                            'relationship': rel['relationship_type']
                        })
        
        # Print results
        if reputation['is_malicious']:
            print(f"🚨 MALICIOUS IOC DETECTED!")
            print(f"   Confidence: {reputation['confidence']}%")
            print(f"   Threat Types: {', '.join(set(reputation['threat_types']))}")
            print(f"   Description: {reputation['description']}")
            if reputation['associated_threats']:
                print(f"   Associated Threats:")
                for threat in reputation['associated_threats']:
                    print(f"     - {threat['type']}: {threat['name']} ({threat['relationship']})")
        else:
            print(f"✅ IOC appears clean - no threats found")
        
        return reputation
    
    def bulk_ioc_check(self, iocs: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        """Check multiple IOCs for threats"""
        print(f"\n🔍 BULK IOC REPUTATION CHECK")
        print(f"Checking {len(iocs)} indicators...")
        print("=" * 50)
        
        results = []
        malicious_count = 0
        
        for ioc_data in iocs:
            result = self.check_ioc_reputation(ioc_data['value'], ioc_data['type'])
            results.append(result)
            
            if result['is_malicious']:
                malicious_count += 1
            
            print()  # Add spacing between checks
        
        print(f"📊 BULK CHECK SUMMARY:")
        print(f"   Total IOCs Checked: {len(iocs)}")
        print(f"   Malicious IOCs Found: {malicious_count}")
        print(f"   Clean IOCs: {len(iocs) - malicious_count}")
        print(f"   Threat Detection Rate: {(malicious_count/len(iocs)*100):.1f}%")
        
        return results
    
    def simulate_incident_enrichment(self, incident_iocs: List[str]) -> Dict[str, Any]:
        """Simulate enriching an incident with threat intelligence"""
        print(f"\n🚨 INCIDENT ENRICHMENT SIMULATION")
        print("=" * 50)
        print("Scenario: Security team detected suspicious network activity")
        print("IOCs extracted from logs and forensic analysis")
        print()
        
        enrichment_data = {
            'incident_id': f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            'iocs_analyzed': len(incident_iocs),
            'threat_actors': set(),
            'malware_families': set(),
            'attack_patterns': set(),
            'confidence_scores': [],
            'recommendations': []
        }
        
        for ioc in incident_iocs:
            # Determine IOC type
            ioc_type = self.determine_ioc_type(ioc)
            result = self.check_ioc_reputation(ioc, ioc_type)
            
            if result['is_malicious']:
                enrichment_data['confidence_scores'].append(result['confidence'])
                
                for threat in result['associated_threats']:
                    if threat['type'] == 'ThreatActor':
                        enrichment_data['threat_actors'].add(threat['name'])
                    elif threat['type'] == 'Malware':
                        enrichment_data['malware_families'].add(threat['name'])
                    elif threat['type'] == 'AttackPattern':
                        enrichment_data['attack_patterns'].add(threat['name'])
        
        # Generate recommendations
        if enrichment_data['threat_actors']:
            enrichment_data['recommendations'].append("Review threat actor TTPs and update defenses")
        if enrichment_data['malware_families']:
            enrichment_data['recommendations'].append("Deploy malware-specific detection rules")
        if enrichment_data['confidence_scores']:
            avg_confidence = sum(enrichment_data['confidence_scores']) / len(enrichment_data['confidence_scores'])
            if avg_confidence > 80:
                enrichment_data['recommendations'].append("HIGH CONFIDENCE - Immediate containment recommended")
            elif avg_confidence > 60:
                enrichment_data['recommendations'].append("MEDIUM CONFIDENCE - Enhanced monitoring recommended")
        
        # Print enrichment results
        print(f"📋 INCIDENT ENRICHMENT RESULTS:")
        print(f"   Incident ID: {enrichment_data['incident_id']}")
        print(f"   IOCs Analyzed: {enrichment_data['iocs_analyzed']}")
        
        if enrichment_data['threat_actors']:
            print(f"   Threat Actors: {', '.join(enrichment_data['threat_actors'])}")
        if enrichment_data['malware_families']:
            print(f"   Malware Families: {', '.join(enrichment_data['malware_families'])}")
        if enrichment_data['confidence_scores']:
            avg_conf = sum(enrichment_data['confidence_scores']) / len(enrichment_data['confidence_scores'])
            print(f"   Average Confidence: {avg_conf:.1f}%")
        
        print(f"\n💡 RECOMMENDATIONS:")
        for i, rec in enumerate(enrichment_data['recommendations'], 1):
            print(f"   {i}. {rec}")
        
        return enrichment_data
    
    def determine_ioc_type(self, ioc: str) -> str:
        """Determine the type of IOC"""
        try:
            ipaddress.ip_address(ioc)
            return "ip"
        except:
            pass
        
        if len(ioc) == 32 and all(c in '0123456789abcdef' for c in ioc.lower()):
            return "hash"
        elif len(ioc) == 40 and all(c in '0123456789abcdef' for c in ioc.lower()):
            return "hash"
        elif len(ioc) == 64 and all(c in '0123456789abcdef' for c in ioc.lower()):
            return "hash"
        elif '.' in ioc and not ioc.replace('.', '').isdigit():
            return "domain"
        else:
            return "unknown"
    
    def demonstrate_threat_hunting_workflow(self) -> Dict[str, Any]:
        """Demonstrate a complete threat hunting workflow"""
        print(f"\n🎯 THREAT HUNTING WORKFLOW DEMONSTRATION")
        print("=" * 60)
        print("Scenario: Proactive threat hunting based on new intelligence")
        print()
        
        # Sample IOCs that might be found during hunting
        hunting_iocs = [
            {"value": "192.168.1.100", "type": "ip", "source": "Network logs"},
            {"value": "evil-domain.com", "type": "domain", "source": "DNS logs"},
            {"value": "d41d8cd98f00b204e9800998ecf8427e", "type": "hash", "source": "File analysis"},
            {"value": "suspicious-site.net", "type": "domain", "source": "Web proxy logs"},
            {"value": "10.0.0.50", "type": "ip", "source": "Firewall logs"}
        ]
        
        workflow_results = {
            'hunting_session_id': f"HUNT-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            'iocs_investigated': len(hunting_iocs),
            'threats_identified': 0,
            'false_positives': 0,
            'hunting_effectiveness': 0,
            'next_actions': []
        }
        
        print(f"🔍 HUNTING SESSION: {workflow_results['hunting_session_id']}")
        print(f"Investigating {len(hunting_iocs)} IOCs from various sources...")
        print()
        
        for ioc_data in hunting_iocs:
            print(f"📍 Investigating {ioc_data['type'].upper()}: {ioc_data['value']}")
            print(f"   Source: {ioc_data['source']}")
            
            result = self.check_ioc_reputation(ioc_data['value'], ioc_data['type'])
            
            if result['is_malicious']:
                workflow_results['threats_identified'] += 1
                workflow_results['next_actions'].append(f"Block {ioc_data['value']} in security controls")
            else:
                workflow_results['false_positives'] += 1
            
            print()
        
        # Calculate hunting effectiveness
        if workflow_results['iocs_investigated'] > 0:
            workflow_results['hunting_effectiveness'] = (
                workflow_results['threats_identified'] / workflow_results['iocs_investigated'] * 100
            )
        
        # Add general next actions
        if workflow_results['threats_identified'] > 0:
            workflow_results['next_actions'].extend([
                "Update threat hunting rules with new patterns",
                "Share intelligence with security team",
                "Review historical logs for IOC presence",
                "Update incident response playbooks"
            ])
        
        print(f"📊 HUNTING SESSION RESULTS:")
        print(f"   Session ID: {workflow_results['hunting_session_id']}")
        print(f"   IOCs Investigated: {workflow_results['iocs_investigated']}")
        print(f"   Threats Identified: {workflow_results['threats_identified']}")
        print(f"   False Positives: {workflow_results['false_positives']}")
        print(f"   Hunting Effectiveness: {workflow_results['hunting_effectiveness']:.1f}%")
        
        print(f"\n🎯 NEXT ACTIONS:")
        for i, action in enumerate(workflow_results['next_actions'], 1):
            print(f"   {i}. {action}")
        
        return workflow_results
    
    def run_practical_scenarios(self) -> Dict[str, Any]:
        """Run all practical demonstration scenarios"""
        print("🚀 OPENCTI PRACTICAL USE CASES DEMONSTRATION")
        print("=" * 80)
        print("Demonstrating real-world threat intelligence scenarios")
        print("that security teams encounter daily.")
        print("=" * 80)
        
        demo_results = {
            'start_time': datetime.utcnow().isoformat(),
            'scenarios': {}
        }
        
        # Scenario 1: Single IOC reputation check
        print(f"\n📋 SCENARIO 1: IOC REPUTATION CHECK")
        print("-" * 40)
        suspicious_ip = "192.168.1.100"
        reputation_result = self.check_ioc_reputation(suspicious_ip, "ip")
        demo_results['scenarios']['ioc_reputation'] = reputation_result
        
        # Scenario 2: Bulk IOC analysis
        print(f"\n📋 SCENARIO 2: BULK IOC ANALYSIS")
        print("-" * 40)
        bulk_iocs = [
            {"value": "192.168.1.100", "type": "ip"},
            {"value": "evil-domain.com", "type": "domain"},
            {"value": "d41d8cd98f00b204e9800998ecf8427e", "type": "hash"},
            {"value": "google.com", "type": "domain"},  # Should be clean
            {"value": "8.8.8.8", "type": "ip"}  # Should be clean
        ]
        bulk_results = self.bulk_ioc_check(bulk_iocs)
        demo_results['scenarios']['bulk_analysis'] = bulk_results
        
        # Scenario 3: Incident enrichment
        print(f"\n📋 SCENARIO 3: INCIDENT ENRICHMENT")
        print("-" * 40)
        incident_iocs = ["192.168.1.100", "evil-domain.com", "suspicious-file.exe"]
        enrichment_result = self.simulate_incident_enrichment(incident_iocs)
        demo_results['scenarios']['incident_enrichment'] = enrichment_result
        
        # Scenario 4: Threat hunting workflow
        print(f"\n📋 SCENARIO 4: THREAT HUNTING WORKFLOW")
        print("-" * 40)
        hunting_result = self.demonstrate_threat_hunting_workflow()
        demo_results['scenarios']['threat_hunting'] = hunting_result
        
        demo_results['end_time'] = datetime.utcnow().isoformat()
        
        # Final summary
        print(f"\n🎉 PRACTICAL DEMONSTRATION COMPLETE!")
        print("=" * 60)
        print("✅ OpenCTI Use Cases Demonstrated:")
        print("   • IOC Reputation Checking")
        print("   • Bulk Threat Analysis")
        print("   • Incident Response Enrichment")
        print("   • Proactive Threat Hunting")
        print("   • Intelligence-Driven Security Operations")
        
        print(f"\n💡 Business Value Delivered:")
        print("   • Faster threat detection and response")
        print("   • Reduced false positives in security alerts")
        print("   • Enhanced incident investigation capabilities")
        print("   • Proactive threat hunting effectiveness")
        print("   • Improved security team decision making")
        
        return demo_results

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='OpenCTI Practical Use Cases Demo')
    parser.add_argument('--url', default='http://localhost:8080',
                       help='OpenCTI base URL')
    parser.add_argument('--token', required=True,
                       help='OpenCTI API token')
    parser.add_argument('--output',
                       help='Save results to JSON file')
    
    args = parser.parse_args()
    
    # Create demo instance
    demo = OpenCTIPracticalDemo(base_url=args.url, token=args.token)
    
    # Run practical scenarios
    results = demo.run_practical_scenarios()
    
    # Save results if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n💾 Results saved to: {args.output}")

if __name__ == "__main__":
    main()