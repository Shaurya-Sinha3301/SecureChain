#!/usr/bin/env python3
"""
Test script for the attack graph generator.
"""

import json
import os
from attack_graph_generator import load_scan, build_graph, compute_attack_paths

def test_attack_graph():
    """Test the attack graph functionality."""
    print("🔍 Testing Attack Graph Generator")
    print("=" * 40)
    
    # Test 1: Load sample data
    print("1. Loading sample scan data...")
    try:
        records = load_scan("sample_scan.json")
        print(f"✅ Loaded {len(records)} scan records")
    except Exception as e:
        print(f"❌ Failed to load data: {e}")
        return False
    
    # Test 2: Build graph
    print("\n2. Building attack graph...")
    try:
        G = build_graph(records)
        print(f"✅ Graph built: {len(G.nodes())} nodes, {len(G.edges())} edges")
        
        # Show node types
        assets = [n for n, d in G.nodes(data=True) if d.get("node_type") == "asset"]
        vulns = [n for n, d in G.nodes(data=True) if d.get("node_type") == "vuln"]
        print(f"   - Assets: {len(assets)}")
        print(f"   - Vulnerabilities: {len(vulns)}")
        
    except Exception as e:
        print(f"❌ Failed to build graph: {e}")
        return False
    
    # Test 3: Identify entry points and targets
    print("\n3. Identifying entry points and targets...")
    
    # Entry points (internet gateways or web servers)
    entry_points = [n for n, d in G.nodes(data=True) if d.get("node_type") == "asset" and
                    (d.get("asset_type") == "internet_gateway" or "web_server" in (d.get("asset_type") or ""))]
    
    # Targets (database servers or high criticality assets)
    targets = [n for n, d in G.nodes(data=True) if d.get("node_type") == "asset" and 
               "db_server" in (d.get("asset_type") or "")]
    
    if not entry_points:
        # Fallback: any asset with external IP or web service
        entry_points = [n for n, d in G.nodes(data=True) if d.get("node_type") == "asset" and
                       (not d.get("ip", "").startswith("10.") or "web" in (d.get("asset_type") or ""))]
    
    if not targets:
        # Fallback: highest criticality assets
        assets_by_crit = [(n, d.get("criticality", 5)) for n, d in G.nodes(data=True) 
                         if d.get("node_type") == "asset"]
        assets_by_crit.sort(key=lambda x: -x[1])
        targets = [assets_by_crit[0][0]] if assets_by_crit else []
    
    print(f"   - Entry points: {entry_points}")
    print(f"   - Targets: {targets}")
    
    # Test 4: Compute attack paths
    print("\n4. Computing attack paths...")
    try:
        paths = compute_attack_paths(G, entry_points, targets, max_depth=4, top_k=5)
        print(f"✅ Found {len(paths)} attack paths")
        
        if paths:
            print("\n   Top attack paths:")
            for i, path in enumerate(paths[:3], 1):
                path_str = " -> ".join(path["path"])
                print(f"   {i}. {path_str} (score: {path['score']:.3f})")
        else:
            print("   ⚠️  No attack paths found")
            
    except Exception as e:
        print(f"❌ Failed to compute paths: {e}")
        return False
    
    # Test 5: Check generated files
    print("\n5. Checking generated files...")
    expected_files = [
        "attack_graph_beautiful.html",
        "attack_graph_beautiful.svg", 
        "attack_graph_beautiful.png",
        "attack_graph.json",
        "top_attack_paths.csv"
    ]
    
    for file in expected_files:
        if os.path.exists(file):
            size = os.path.getsize(file)
            print(f"   ✅ {file} ({size} bytes)")
        else:
            print(f"   ❌ {file} missing")
    
    print(f"\n🎉 Attack graph generator test completed!")
    return True

def show_sample_data():
    """Show sample data structure."""
    print("\n📊 Sample Data Structure:")
    print("=" * 30)
    
    try:
        records = load_scan("sample_scan.json")
        if records:
            sample = records[0]
            print("Sample record fields:")
            for key, value in sample.items():
                print(f"  - {key}: {value}")
    except Exception as e:
        print(f"Error loading sample data: {e}")

if __name__ == "__main__":
    test_attack_graph()
    show_sample_data()