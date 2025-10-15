#!/usr/bin/env python3
"""
OpenCTI Sample Data Creator
Creates realistic threat intelligence data to demonstrate OpenCTI's capabilities
"""

import requests
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

class OpenCTISampleDataCreator:
    def __init__(self, base_url: str, token: str):
        self.base_url = base_url.rstrip('/')
        self.token = token
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        })
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
            return {'errors': [{'message': str(e)}]}
    
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
    
    def create_indicator(self, name: str, pattern: str, indicator_type: str, description: str) -> Optional[str]:
        """Create an indicator"""
        print(f"🎯 Creating indicator: {name}")
        
        query = """
        mutation IndicatorAdd($input: IndicatorAddInput!) {
            indicatorAdd(input: $input) {
                id
                name
                pattern
                indicator_types
            }
        }
        """
        
        variables = {
            "input": {
                "name": name,
                "pattern": pattern,
                "pattern_type": "stix",
                "indicator_types": [indicator_type],
                "description": description,
                "confidence": 85,
                "valid_from": datetime.utcnow().isoformat() + "Z",
                "valid_until": (datetime.utcnow() + timedelta(days=365)).isoformat() + "Z"
            }
        }
        
        result = self.execute_query(query, variables)
        if 'data' in result and result['data']['indicatorAdd']:
            indicator_id = result['data']['indicatorAdd']['id']
            self.created_entities.append(('Indicator', indicator_id))
            print(f"✅ Created indicator: {name} (ID: {indicator_id})")
            return indicator_id
        else:
            print(f"❌ Failed to create indicator: {result.get('errors', 'Unknown error')}")
            return None
    
    def create_threat_actor_group(self, name: str, description: str) -> Optional[str]:
        """Create a threat actor group"""
        print(f"🎭 Creating threat actor group: {name}")
        
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
            print(f"✅ Created threat actor group: {name} (ID: {actor_id})")
            return actor_id
        else:
            print(f"❌ Failed to create threat actor group: {result.get('errors', 'Unknown error')}")
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
    
    def create_sample_threat_landscape(self) -> Dict[str, Any]:
        """Create a comprehensive sample threat landscape"""
        print("🚀 CREATING SAMPLE THREAT LANDSCAPE")
        print("=" * 60)
        
        results = {
            'created_entities': 0,
            'created_relationships': 0,
            'threat_actors': [],
            'malware_families': [],
            'indicators': [],
            'relationships': []
        }
        
        # Create threat actors
        apt29_id = self.create_threat_actor_group(
            "APT29 (Cozy Bear)",
            "Russian state-sponsored threat group known for sophisticated attacks targeting government and private sector organizations"
        )
        if apt29_id:
            results['threat_actors'].append(apt29_id)
        
        lazarus_id = self.create_threat_actor_group(
            "Lazarus Group", 
            "North Korean state-sponsored group known for financial crimes, cryptocurrency theft, and espionage operations"
        )
        if lazarus_id:
            results['threat_actors'].append(lazarus_id)
        
        # Create malware families
        emotet_id = self.create_malware(
            "Emotet",
            "Banking trojan and malware-as-a-service platform used for credential theft and lateral movement"
        )
        if emotet_id:
            results['malware_families'].append(emotet_id)
        
        cobalt_strike_id = self.create_malware(
            "Cobalt Strike",
            "Commercial penetration testing tool frequently abused by threat actors for post-exploitation activities"
        )
        if cobalt_strike_id:
            results['malware_families'].append(cobalt_strike_id)
        
        trickbot_id = self.create_malware(
            "TrickBot",
            "Modular banking trojan used for credential harvesting and as a delivery mechanism for other malware"
        )
        if trickbot_id:
            results['malware_families'].append(trickbot_id)
        
        # Create indicators of compromise
        indicators_data = [
            {
                "name": "Malicious IP - APT29 C2",
                "pattern": "[ipv4-addr:value = '192.168.1.100']",
                "type": "malicious-activity",
                "description": "Command and control server associated with APT29 operations"
            },
            {
                "name": "Suspicious Domain - Emotet C2",
                "pattern": "[domain-name:value = 'evil-c2.example.com']",
                "type": "malicious-activity",
                "description": "Domain used by Emotet for command and control communications"
            },
            {
                "name": "Malicious Hash - TrickBot Payload",
                "pattern": "[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']",
                "type": "malicious-activity",
                "description": "MD5 hash of TrickBot banking trojan payload"
            },
            {
                "name": "Phishing Domain - Lazarus Campaign",
                "pattern": "[domain-name:value = 'fake-bank-login.net']",
                "type": "malicious-activity",
                "description": "Phishing domain used in Lazarus Group financial targeting campaign"
            },
            {
                "name": "Cobalt Strike Beacon",
                "pattern": "[network-traffic:dst_ref.value = '10.0.0.50' AND network-traffic:dst_port = 443]",
                "type": "malicious-activity",
                "description": "Network traffic pattern indicating Cobalt Strike beacon communication"
            }
        ]
        
        created_indicators = []
        for indicator_data in indicators_data:
            indicator_id = self.create_indicator(
                indicator_data["name"],
                indicator_data["pattern"],
                indicator_data["type"],
                indicator_data["description"]
            )
            if indicator_id:
                created_indicators.append(indicator_id)
                results['indicators'].append(indicator_id)
        
        # Create relationships
        relationships_to_create = [
            (apt29_id, cobalt_strike_id, "uses", "APT29 uses Cobalt Strike"),
            (lazarus_id, emotet_id, "uses", "Lazarus Group uses Emotet"),
            (emotet_id, created_indicators[1] if len(created_indicators) > 1 else None, "indicates", "Emotet indicates C2 domain"),
            (trickbot_id, created_indicators[2] if len(created_indicators) > 2 else None, "indicates", "TrickBot indicates malicious hash"),
            (apt29_id, created_indicators[0] if len(created_indicators) > 0 else None, "indicates", "APT29 indicates C2 IP"),
            (lazarus_id, created_indicators[3] if len(created_indicators) > 3 else None, "indicates", "Lazarus indicates phishing domain"),
            (cobalt_strike_id, created_indicators[4] if len(created_indicators) > 4 else None, "indicates", "Cobalt Strike indicates beacon traffic")
        ]
        
        for from_id, to_id, rel_type, description in relationships_to_create:
            if from_id and to_id:
                rel_id = self.create_relationship(from_id, to_id, rel_type)
                if rel_id:
                    results['relationships'].append(rel_id)
        
        results['created_entities'] = len(self.created_entities)
        results['created_relationships'] = len([e for e in self.created_entities if e[0] == 'StixCoreRelationship'])
        
        print(f"\n🎉 SAMPLE THREAT LANDSCAPE CREATED!")
        print("=" * 50)
        print(f"✅ Threat Actor Groups: {len(results['threat_actors'])}")
        print(f"✅ Malware Families: {len(results['malware_families'])}")
        print(f"✅ Indicators of Compromise: {len(results['indicators'])}")
        print(f"✅ Relationships: {len(results['relationships'])}")
        print(f"✅ Total Entities: {results['created_entities']}")
        
        print(f"\n💡 Now you can run the practical demo to see OpenCTI's usefulness!")
        print("   python opencti_practical_demo.py --token YOUR_TOKEN")
        
        return results

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Create sample threat intelligence data in OpenCTI')
    parser.add_argument('--url', default='http://localhost:8080',
                       help='OpenCTI base URL')
    parser.add_argument('--token', required=True,
                       help='OpenCTI API token')
    parser.add_argument('--output',
                       help='Save creation results to JSON file')
    
    args = parser.parse_args()
    
    # Create sample data creator
    creator = OpenCTISampleDataCreator(base_url=args.url, token=args.token)
    
    # Create sample threat landscape
    results = creator.create_sample_threat_landscape()
    
    # Save results if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n💾 Creation results saved to: {args.output}")

if __name__ == "__main__":
    main()