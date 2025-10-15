#!/usr/bin/env python3
"""
OpenCTI Usefulness Demonstration Script
Tests real-world threat intelligence capabilities of OpenCTI
"""

import requests
import json
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import argparse

class OpenCTIDemo:
    def __init__(self, base_url: str, token: str):
        self.base_url = base_url.rstrip('/')
        self.token = token
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        })
        
        # Store created entities for cleanup
        self.created_entities = []
        
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
            print(f"❌ Query failed: {str(e)}")
            return {'errors': [{'message': str(e)}]}
    
    def create_threat_actor(self, name: str, description: str) -> Optional[str]:
        """Create a threat actor"""
        print(f"🎭 Creating threat actor: {name}")
        
        query = """
        mutation ThreatActorGroupAdd($input: ThreatActorGroupAddInput!) {
            threatActorGroupAdd(input: $input) {
                id
                name
                description
            }
        }
        """
        
        variables = {
            "input": {
                "name": name,
                "description": description,
                "threat_actor_group_types": ["hacker"],
                "confidence": 85
            }
        }
        
        result = self.execute_query(query, variables)
        if 'data' in result and result['data']['threatActorGroupAdd']:
            actor_id = result['data']['threatActorGroupAdd']['id']
            self.created_entities.append(('ThreatActorGroup', actor_id))
            print(f"✅ Created threat actor: {name} (ID: {actor_id})")
            return actor_id
        else:
            print(f"❌ Failed to create threat actor: {result.get('errors', 'Unknown error')}")
            return None
    
    def create_malware(self, name: str, description: str) -> Optional[str]:
        """Create malware"""
        print(f"🦠 Creating malware: {name}")
        
        query = """
        mutation MalwareAdd($input: MalwareAddInput!) {
            malwareAdd(input: $input) {
                id
                name
                description
            }
        }
        """
        
        variables = {
            "input": {
                "name": name,
                "description": description,
                "malware_types": ["trojan"],
                "is_family": True,
                "confidence": 90
            }
        }
        
        result = self.execute_query(query, variables)
        if 'data' in result and result['data']['malwareAdd']:
            malware_id = result['data']['malwareAdd']['id']
            self.created_entities.append(('Malware', malware_id))
            print(f"✅ Created malware: {name} (ID: {malware_id})")
            return malware_id
        else:
            print(f"❌ Failed to create malware: {result.get('errors', 'Unknown error')}")
            return None
    
    def create_indicator(self, pattern: str, indicator_type: str, description: str) -> Optional[str]:
        """Create an indicator"""
        print(f"🎯 Creating indicator: {pattern}")
        
        query = """
        mutation IndicatorAdd($input: IndicatorAddInput!) {
            indicatorAdd(input: $input) {
                id
                pattern
                indicator_types
            }
        }
        """
        
        variables = {
            "input": {
                "name": f"IOC-{pattern[:20]}",
                "pattern": pattern,
                "pattern_type": "stix",
                "indicator_types": [indicator_type],
                "description": description,
                "confidence": 80,
                "valid_from": datetime.utcnow().isoformat() + "Z",
                "valid_until": (datetime.utcnow() + timedelta(days=365)).isoformat() + "Z"
            }
        }
        
        result = self.execute_query(query, variables)
        if 'data' in result and result['data']['indicatorAdd']:
            indicator_id = result['data']['indicatorAdd']['id']
            self.created_entities.append(('Indicator', indicator_id))
            print(f"✅ Created indicator: {pattern} (ID: {indicator_id})")
            return indicator_id
        else:
            print(f"❌ Failed to create indicator: {result.get('errors', 'Unknown error')}")
            return None
    
    def create_relationship(self, from_id: str, to_id: str, relationship_type: str) -> Optional[str]:
        """Create a relationship between entities"""
        print(f"🔗 Creating relationship: {relationship_type}")
        
        query = """
        mutation StixCoreRelationshipAdd($input: StixCoreRelationshipAddInput!) {
            stixCoreRelationshipAdd(input: $input) {
                id
                relationship_type
            }
        }
        """
        
        variables = {
            "input": {
                "fromId": from_id,
                "toId": to_id,
                "relationship_type": relationship_type,
                "confidence": 75,
                "start_time": datetime.utcnow().isoformat() + "Z"
            }
        }
        
        result = self.execute_query(query, variables)
        if 'data' in result and result['data']['stixCoreRelationshipAdd']:
            rel_id = result['data']['stixCoreRelationshipAdd']['id']
            self.created_entities.append(('StixCoreRelationship', rel_id))
            print(f"✅ Created relationship: {relationship_type} (ID: {rel_id})")
            return rel_id
        else:
            print(f"❌ Failed to create relationship: {result.get('errors', 'Unknown error')}")
            return None
    
    def create_incident(self, name: str, description: str) -> Optional[str]:
        """Create an incident"""
        print(f"🚨 Creating incident: {name}")
        
        query = """
        mutation IncidentAdd($input: IncidentAddInput!) {
            incidentAdd(input: $input) {
                id
                name
                description
            }
        }
        """
        
        variables = {
            "input": {
                "name": name,
                "description": description,
                "confidence": 85,
                "first_seen": datetime.utcnow().isoformat() + "Z"
            }
        }
        
        result = self.execute_query(query, variables)
        if 'data' in result and result['data']['incidentAdd']:
            incident_id = result['data']['incidentAdd']['id']
            self.created_entities.append(('Incident', incident_id))
            print(f"✅ Created incident: {name} (ID: {incident_id})")
            return incident_id
        else:
            print(f"❌ Failed to create incident: {result.get('errors', 'Unknown error')}")
            return None
    
    def search_indicators_by_pattern(self, search_term: str) -> List[Dict]:
        """Search for indicators containing a pattern"""
        print(f"🔍 Searching indicators for: {search_term}")
        
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
                    }
                }
            }
        }
        """
        
        variables = {"search": search_term}
        result = self.execute_query(query, variables)
        
        if 'data' in result and result['data']['indicators']:
            indicators = [edge['node'] for edge in result['data']['indicators']['edges']]
            print(f"✅ Found {len(indicators)} indicators matching '{search_term}'")
            return indicators
        else:
            print(f"❌ Search failed: {result.get('errors', 'No results')}")
            return []
    
    def get_entity_relationships(self, entity_id: str) -> List[Dict]:
        """Get all relationships for an entity"""
        print(f"🔗 Getting relationships for entity: {entity_id}")
        
        query = """
        query GetRelationships($id: String!) {
            stixCoreObject(id: $id) {
                ... on StixCoreObject {
                    stixCoreRelationships {
                        edges {
                            node {
                                id
                                relationship_type
                                from {
                                    ... on StixCoreObject {
                                        id
                                        entity_type
                                        ... on ThreatActor { name }
                                        ... on Malware { name }
                                        ... on Indicator { pattern }
                                    }
                                }
                                to {
                                    ... on StixCoreObject {
                                        id
                                        entity_type
                                        ... on ThreatActor { name }
                                        ... on Malware { name }
                                        ... on Indicator { pattern }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        """
        
        variables = {"id": entity_id}
        result = self.execute_query(query, variables)
        
        if 'data' in result and result['data']['stixCoreObject']:
            relationships = result['data']['stixCoreObject']['stixCoreRelationships']['edges']
            print(f"✅ Found {len(relationships)} relationships")
            return [edge['node'] for edge in relationships]
        else:
            print(f"❌ Failed to get relationships: {result.get('errors', 'Unknown error')}")
            return []
    
    def demonstrate_threat_hunting(self, ioc: str) -> Dict[str, Any]:
        """Demonstrate threat hunting capabilities"""
        print(f"\n🎯 THREAT HUNTING DEMONSTRATION")
        print(f"Hunting for IOC: {ioc}")
        print("=" * 60)
        
        # Search for the IOC
        indicators = self.search_indicators_by_pattern(ioc)
        
        hunting_results = {
            'ioc_searched': ioc,
            'indicators_found': len(indicators),
            'related_threats': [],
            'recommendations': []
        }
        
        if indicators:
            print(f"\n🚨 ALERT: Found {len(indicators)} matching indicators!")
            
            for indicator in indicators:
                print(f"\n📍 Indicator Details:")
                print(f"   Pattern: {indicator['pattern']}")
                print(f"   Type: {', '.join(indicator['indicator_types'])}")
                print(f"   Confidence: {indicator['confidence']}%")
                print(f"   Description: {indicator.get('description', 'N/A')}")
                
                # Get relationships for this indicator
                relationships = self.get_entity_relationships(indicator['id'])
                
                for rel in relationships:
                    threat_info = {
                        'relationship_type': rel['relationship_type'],
                        'related_entity': None
                    }
                    
                    # Determine which entity is the threat
                    if rel['from']['id'] != indicator['id']:
                        related_entity = rel['from']
                    else:
                        related_entity = rel['to']
                    
                    threat_info['related_entity'] = {
                        'type': related_entity['entity_type'],
                        'id': related_entity['id'],
                        'name': related_entity.get('name', related_entity.get('pattern', 'Unknown'))
                    }
                    
                    hunting_results['related_threats'].append(threat_info)
                    
                    print(f"\n🔗 Related Threat:")
                    print(f"   Type: {related_entity['entity_type']}")
                    print(f"   Name: {related_entity.get('name', related_entity.get('pattern', 'Unknown'))}")
                    print(f"   Relationship: {rel['relationship_type']}")
            
            # Generate recommendations
            hunting_results['recommendations'] = [
                "Block the identified IOC in security controls",
                "Search logs for historical presence of this IOC",
                "Investigate related threat actors and malware families",
                "Update threat hunting rules with new patterns",
                "Share intelligence with security team and partners"
            ]
            
            print(f"\n💡 RECOMMENDATIONS:")
            for i, rec in enumerate(hunting_results['recommendations'], 1):
                print(f"   {i}. {rec}")
        
        else:
            print(f"✅ No threats found for IOC: {ioc}")
            hunting_results['recommendations'] = [
                "IOC appears clean - continue monitoring",
                "Consider adding to watchlist for future reference"
            ]
        
        return hunting_results
    
    def generate_threat_report(self) -> Dict[str, Any]:
        """Generate a comprehensive threat intelligence report"""
        print(f"\n📊 GENERATING THREAT INTELLIGENCE REPORT")
        print("=" * 60)
        
        # Get all entities
        queries = {
            'threat_actors': """
                query { threatActorGroups(first: 50) { edges { node { id name description threat_actor_group_types } } } }
            """,
            'malware': """
                query { malwares(first: 50) { edges { node { id name description malware_types } } } }
            """,
            'indicators': """
                query { indicators(first: 50) { edges { node { id pattern indicator_types confidence } } } }
            """,
            'incidents': """
                query { incidents(first: 50) { edges { node { id name description first_seen } } } }
            """
        }
        
        report = {
            'generated_at': datetime.utcnow().isoformat(),
            'summary': {},
            'entities': {},
            'threat_landscape': {}
        }
        
        for entity_type, query in queries.items():
            result = self.execute_query(query)
            query_key = 'threatActorGroups' if entity_type == 'threat_actors' else entity_type
            if 'data' in result and result['data'][query_key]:
                entities = [edge['node'] for edge in result['data'][query_key]['edges']]
                report['entities'][entity_type] = entities
                report['summary'][entity_type] = len(entities)
                print(f"📈 {entity_type.replace('_', ' ').title()}: {len(entities)}")
        
        # Analyze threat landscape
        total_threats = sum(report['summary'].values())
        report['threat_landscape'] = {
            'total_entities': total_threats,
            'threat_density': 'High' if total_threats > 20 else 'Medium' if total_threats > 5 else 'Low',
            'coverage_areas': list(report['summary'].keys())
        }
        
        print(f"\n🎯 THREAT LANDSCAPE ANALYSIS:")
        print(f"   Total Entities: {report['threat_landscape']['total_entities']}")
        print(f"   Threat Density: {report['threat_landscape']['threat_density']}")
        print(f"   Coverage Areas: {', '.join(report['threat_landscape']['coverage_areas'])}")
        
        return report
    
    def cleanup_demo_data(self):
        """Clean up created demo data"""
        print(f"\n🧹 CLEANING UP DEMO DATA")
        print("=" * 40)
        
        # Reverse order to handle dependencies
        for entity_type, entity_id in reversed(self.created_entities):
            print(f"🗑️  Deleting {entity_type}: {entity_id}")
            
            # Generic delete mutation
            delete_name = entity_type.lower()
            if entity_type == 'ThreatActorGroup':
                delete_name = 'threatActorGroup'
            elif entity_type == 'StixCoreRelationship':
                delete_name = 'stixCoreRelationship'
            
            query = f"""
            mutation Delete{entity_type}($id: ID!) {{
                {delete_name}Delete(id: $id)
            }}
            """
            
            variables = {"id": entity_id}
            result = self.execute_query(query, variables)
            
            if 'errors' not in result:
                print(f"✅ Deleted {entity_type}: {entity_id}")
            else:
                print(f"⚠️  Could not delete {entity_type}: {entity_id}")
        
        self.created_entities.clear()
    
    def run_comprehensive_demo(self, cleanup: bool = True) -> Dict[str, Any]:
        """Run the complete OpenCTI usefulness demonstration"""
        print("🚀 OPENCTI USEFULNESS DEMONSTRATION")
        print("=" * 80)
        print("This demo will showcase OpenCTI's threat intelligence capabilities")
        print("by creating sample data and demonstrating real-world scenarios.")
        print("=" * 80)
        
        demo_results = {
            'start_time': datetime.utcnow().isoformat(),
            'scenarios': {},
            'entities_created': 0,
            'relationships_created': 0
        }
        
        try:
            # Scenario 1: Create threat landscape
            print(f"\n📋 SCENARIO 1: BUILDING THREAT LANDSCAPE")
            print("-" * 50)
            
            # Create threat actors
            apt29_id = self.create_threat_actor(
                "APT29 (Cozy Bear)", 
                "Russian state-sponsored threat group known for sophisticated attacks"
            )
            
            lazarus_id = self.create_threat_actor(
                "Lazarus Group", 
                "North Korean state-sponsored group known for financial crimes and espionage"
            )
            
            # Create malware families
            emotet_id = self.create_malware(
                "Emotet", 
                "Banking trojan and malware-as-a-service platform"
            )
            
            cobalt_strike_id = self.create_malware(
                "Cobalt Strike", 
                "Commercial penetration testing tool often abused by threat actors"
            )
            
            # Create indicators
            malicious_ip = self.create_indicator(
                "[ipv4-addr:value = '192.168.1.100']",
                "malicious-activity",
                "Command and control server for APT29 operations"
            )
            
            malicious_domain = self.create_indicator(
                "[domain-name:value = 'evil-c2.example.com']",
                "malicious-activity", 
                "Domain used for malware communication"
            )
            
            malicious_hash = self.create_indicator(
                "[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']",
                "malicious-activity",
                "Hash of Emotet payload"
            )
            
            # Create incident
            incident_id = self.create_incident(
                "Corporate Network Breach - Q4 2024",
                "Sophisticated attack targeting financial data using APT29 TTPs"
            )
            
            demo_results['entities_created'] = len(self.created_entities)
            
            # Scenario 2: Create relationships
            print(f"\n📋 SCENARIO 2: ESTABLISHING THREAT RELATIONSHIPS")
            print("-" * 50)
            
            relationships_created = 0
            
            if apt29_id and cobalt_strike_id:
                self.create_relationship(apt29_id, cobalt_strike_id, "uses")
                relationships_created += 1
            
            if lazarus_id and emotet_id:
                self.create_relationship(lazarus_id, emotet_id, "uses")
                relationships_created += 1
            
            if apt29_id and malicious_ip:
                self.create_relationship(apt29_id, malicious_ip, "indicates")
                relationships_created += 1
            
            if emotet_id and malicious_hash:
                self.create_relationship(emotet_id, malicious_hash, "indicates")
                relationships_created += 1
            
            if incident_id and apt29_id:
                self.create_relationship(incident_id, apt29_id, "attributed-to")
                relationships_created += 1
            
            demo_results['relationships_created'] = relationships_created
            
            # Scenario 3: Threat hunting simulation
            print(f"\n📋 SCENARIO 3: THREAT HUNTING SIMULATION")
            print("-" * 50)
            
            hunting_results = self.demonstrate_threat_hunting("192.168.1.100")
            demo_results['scenarios']['threat_hunting'] = hunting_results
            
            # Scenario 4: Intelligence reporting
            print(f"\n📋 SCENARIO 4: THREAT INTELLIGENCE REPORTING")
            print("-" * 50)
            
            threat_report = self.generate_threat_report()
            demo_results['scenarios']['threat_report'] = threat_report
            
            # Scenario 5: Demonstrate search capabilities
            print(f"\n📋 SCENARIO 5: SEARCH AND DISCOVERY")
            print("-" * 50)
            
            search_results = self.search_indicators_by_pattern("evil-c2")
            demo_results['scenarios']['search_demo'] = {
                'search_term': 'evil-c2',
                'results_found': len(search_results)
            }
            
            demo_results['end_time'] = datetime.utcnow().isoformat()
            demo_results['success'] = True
            
            # Final summary
            print(f"\n🎉 DEMONSTRATION COMPLETE!")
            print("=" * 50)
            print(f"✅ Entities Created: {demo_results['entities_created']}")
            print(f"✅ Relationships Created: {demo_results['relationships_created']}")
            print(f"✅ Scenarios Demonstrated: {len(demo_results['scenarios'])}")
            print("\n💡 OpenCTI Capabilities Demonstrated:")
            print("   • Threat Actor Management")
            print("   • Malware Family Tracking") 
            print("   • Indicator of Compromise (IOC) Management")
            print("   • Incident Response Integration")
            print("   • Relationship Mapping")
            print("   • Threat Hunting")
            print("   • Intelligence Reporting")
            print("   • Search and Discovery")
            
        except Exception as e:
            print(f"❌ Demo failed: {str(e)}")
            demo_results['success'] = False
            demo_results['error'] = str(e)
        
        finally:
            if cleanup:
                self.cleanup_demo_data()
        
        return demo_results

def main():
    parser = argparse.ArgumentParser(description='Demonstrate OpenCTI usefulness')
    parser.add_argument('--url', default='http://localhost:8080',
                       help='OpenCTI base URL')
    parser.add_argument('--token', required=True,
                       help='OpenCTI API token')
    parser.add_argument('--no-cleanup', action='store_true',
                       help='Skip cleanup of demo data')
    parser.add_argument('--output', 
                       help='Save demo results to JSON file')
    
    args = parser.parse_args()
    
    # Create demo instance
    demo = OpenCTIDemo(base_url=args.url, token=args.token)
    
    # Run demonstration
    results = demo.run_comprehensive_demo(cleanup=not args.no_cleanup)
    
    # Save results if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n💾 Demo results saved to: {args.output}")
    
    return 0 if results.get('success', False) else 1

if __name__ == "__main__":
    exit(main())