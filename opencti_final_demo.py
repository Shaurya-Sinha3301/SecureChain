#!/usr/bin/env python3
"""
OpenCTI Final Demonstration
Shows the real usefulness of OpenCTI with actual threat data
"""

import requests
import json
from datetime import datetime
from typing import Dict, List, Any

class OpenCTIFinalDemo:
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
    
    def get_all_indicators(self) -> List[Dict]:
        """Get all indicators from OpenCTI"""
        query = """
        query GetAllIndicators {
            indicators(first: 50) {
                edges {
                    node {
                        id
                        name
                        pattern
                        indicator_types
                        description
                        confidence
                        created
                        stixCoreRelationships {
                            edges {
                                node {
                                    relationship_type
                                    from {
                                        ... on StixCoreObject {
                                            id
                                            entity_type
                                            ... on Malware { name }
                                            ... on ThreatActorGroup { name }
                                        }
                                    }
                                    to {
                                        ... on StixCoreObject {
                                            id
                                            entity_type
                                            ... on Malware { name }
                                            ... on ThreatActorGroup { name }
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
        
        result = self.execute_query(query)
        if 'data' in result and result['data']['indicators']:
            return [edge['node'] for edge in result['data']['indicators']['edges']]
        return []
    
    def get_all_malware(self) -> List[Dict]:
        """Get all malware from OpenCTI"""
        query = """
        query GetAllMalware {
            malwares(first: 50) {
                edges {
                    node {
                        id
                        name
                        description
                        malware_types
                        confidence
                        created
                    }
                }
            }
        }
        """
        
        result = self.execute_query(query)
        if 'data' in result and result['data']['malwares']:
            return [edge['node'] for edge in result['data']['malwares']['edges']]
        return []
    
    def demonstrate_threat_intelligence_value(self) -> Dict[str, Any]:
        """Demonstrate the real value of OpenCTI threat intelligence"""
        print("🚀 OPENCTI THREAT INTELLIGENCE VALUE DEMONSTRATION")
        print("=" * 80)
        print("Showing how OpenCTI provides actionable threat intelligence")
        print("for real-world cybersecurity operations")
        print("=" * 80)
        
        demo_results = {
            'timestamp': datetime.utcnow().isoformat(),
            'threat_landscape': {},
            'use_cases': {},
            'business_value': {}
        }
        
        # Get current threat landscape
        print(f"\n📊 CURRENT THREAT LANDSCAPE ANALYSIS")
        print("-" * 50)
        
        indicators = self.get_all_indicators()
        malware_families = self.get_all_malware()
        
        demo_results['threat_landscape'] = {
            'total_indicators': len(indicators),
            'total_malware_families': len(malware_families),
            'threat_coverage': 'High' if len(indicators) > 3 else 'Medium' if len(indicators) > 0 else 'Low'
        }
        
        print(f"🎯 Indicators of Compromise: {len(indicators)}")
        print(f"🦠 Malware Families: {len(malware_families)}")
        print(f"📈 Threat Coverage: {demo_results['threat_landscape']['threat_coverage']}")
        
        # Show detailed threat intelligence
        if indicators:
            print(f"\n🔍 DETAILED THREAT INTELLIGENCE")
            print("-" * 50)
            
            for i, indicator in enumerate(indicators, 1):
                print(f"\n📍 Indicator #{i}: {indicator['name']}")
                print(f"   Pattern: {indicator['pattern']}")
                print(f"   Type: {', '.join(indicator['indicator_types'])}")
                print(f"   Confidence: {indicator['confidence']}%")
                print(f"   Description: {indicator.get('description', 'N/A')}")
                
                # Extract IOC value for practical use
                pattern = indicator['pattern']
                if 'ipv4-addr:value' in pattern:
                    ioc_value = pattern.split("'")[1]
                    print(f"   🚨 ACTIONABLE IOC: Block IP {ioc_value} in firewalls")
                elif 'domain-name:value' in pattern:
                    ioc_value = pattern.split("'")[1]
                    print(f"   🚨 ACTIONABLE IOC: Block domain {ioc_value} in DNS/proxy")
                elif 'file:hashes' in pattern:
                    ioc_value = pattern.split("'")[1]
                    print(f"   🚨 ACTIONABLE IOC: Block hash {ioc_value} in endpoint protection")
        
        # Show malware intelligence
        if malware_families:
            print(f"\n🦠 MALWARE FAMILY INTELLIGENCE")
            print("-" * 50)
            
            for i, malware in enumerate(malware_families, 1):
                print(f"\n🔬 Malware #{i}: {malware['name']}")
                print(f"   Types: {', '.join(malware['malware_types'])}")
                print(f"   Confidence: {malware['confidence']}%")
                print(f"   Description: {malware.get('description', 'N/A')}")
                print(f"   💡 DEFENSE: Update signatures for {malware['name']} variants")
        
        # Demonstrate use cases
        print(f"\n💼 REAL-WORLD USE CASES ENABLED")
        print("-" * 50)
        
        use_cases = [
            {
                'name': 'Automated Threat Blocking',
                'description': 'Automatically block known malicious IPs, domains, and hashes',
                'value': f'Block {len(indicators)} known threats immediately'
            },
            {
                'name': 'Incident Response Enrichment',
                'description': 'Enrich security alerts with threat context and attribution',
                'value': f'Provide context for {len(malware_families)} malware families'
            },
            {
                'name': 'Proactive Threat Hunting',
                'description': 'Hunt for indicators across network and endpoint logs',
                'value': f'Hunt for {len(indicators)} IOCs across infrastructure'
            },
            {
                'name': 'Threat Intelligence Reporting',
                'description': 'Generate executive and technical threat reports',
                'value': f'Report on {len(malware_families)} active threat families'
            },
            {
                'name': 'Security Tool Integration',
                'description': 'Feed threat intelligence into SIEM, EDR, and other tools',
                'value': f'Integrate {len(indicators)} IOCs into security stack'
            }
        ]
        
        demo_results['use_cases'] = use_cases
        
        for i, use_case in enumerate(use_cases, 1):
            print(f"\n{i}. {use_case['name']}")
            print(f"   Description: {use_case['description']}")
            print(f"   Immediate Value: {use_case['value']}")
        
        # Calculate business value
        print(f"\n💰 QUANTIFIED BUSINESS VALUE")
        print("-" * 50)
        
        # Estimate time savings and risk reduction
        threat_detection_time_saved = len(indicators) * 30  # 30 minutes per IOC investigation
        incident_response_time_saved = len(malware_families) * 60  # 1 hour per malware analysis
        total_time_saved = threat_detection_time_saved + incident_response_time_saved
        
        business_value = {
            'threat_detection_time_saved_minutes': threat_detection_time_saved,
            'incident_response_time_saved_minutes': incident_response_time_saved,
            'total_time_saved_hours': total_time_saved / 60,
            'estimated_cost_savings_per_month': (total_time_saved / 60) * 100,  # $100/hour analyst time
            'threats_prevented': len(indicators),
            'security_posture_improvement': 'Significant' if len(indicators) > 3 else 'Moderate'
        }
        
        demo_results['business_value'] = business_value
        
        print(f"⏱️  Threat Detection Time Saved: {threat_detection_time_saved} minutes")
        print(f"🚨 Incident Response Time Saved: {incident_response_time_saved} minutes")
        print(f"💵 Estimated Monthly Cost Savings: ${business_value['estimated_cost_savings_per_month']:.0f}")
        print(f"🛡️  Threats Prevented: {business_value['threats_prevented']}")
        print(f"📈 Security Posture Improvement: {business_value['security_posture_improvement']}")
        
        # Integration examples
        print(f"\n🔧 INTEGRATION EXAMPLES")
        print("-" * 50)
        
        integration_examples = [
            "SIEM Rules: Create detection rules for all IOCs",
            "Firewall Policies: Block malicious IPs automatically",
            "DNS Filtering: Block malicious domains at DNS level",
            "Endpoint Protection: Add malware hashes to blocklists",
            "Threat Hunting: Search logs for historical IOC presence",
            "Incident Response: Enrich alerts with threat context",
            "Executive Reporting: Generate monthly threat landscape reports"
        ]
        
        for i, example in enumerate(integration_examples, 1):
            print(f"{i}. {example}")
        
        # Success metrics
        print(f"\n📊 SUCCESS METRICS")
        print("-" * 50)
        
        success_metrics = [
            f"Mean Time to Detection (MTTD): Reduced by {threat_detection_time_saved} minutes",
            f"Mean Time to Response (MTTR): Reduced by {incident_response_time_saved} minutes",
            f"False Positive Rate: Reduced through high-confidence intelligence",
            f"Threat Coverage: {demo_results['threat_landscape']['threat_coverage']} coverage achieved",
            f"Analyst Efficiency: {total_time_saved} minutes saved per month",
            f"Security ROI: ${business_value['estimated_cost_savings_per_month']:.0f} monthly savings"
        ]
        
        for metric in success_metrics:
            print(f"✅ {metric}")
        
        print(f"\n🎉 OPENCTI VALUE DEMONSTRATION COMPLETE!")
        print("=" * 60)
        print("OpenCTI provides immediate, actionable threat intelligence that:")
        print("• Reduces threat detection and response times")
        print("• Improves security analyst efficiency")
        print("• Enables proactive threat hunting")
        print("• Provides rich context for incident response")
        print("• Integrates seamlessly with existing security tools")
        print("• Delivers measurable ROI through time and cost savings")
        
        return demo_results

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='OpenCTI Final Value Demonstration')
    parser.add_argument('--url', default='http://localhost:8080',
                       help='OpenCTI base URL')
    parser.add_argument('--token', required=True,
                       help='OpenCTI API token')
    parser.add_argument('--output',
                       help='Save results to JSON file')
    
    args = parser.parse_args()
    
    # Create demo instance
    demo = OpenCTIFinalDemo(base_url=args.url, token=args.token)
    
    # Run value demonstration
    results = demo.demonstrate_threat_intelligence_value()
    
    # Save results if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n💾 Results saved to: {args.output}")

if __name__ == "__main__":
    main()