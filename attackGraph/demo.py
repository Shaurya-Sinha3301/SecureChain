#!/usr/bin/env python3
"""
Demo script for the Attack Graph Generator.
Shows key functionality and outputs.
"""

import os
import json
from attack_graph_generator import load_scan, build_graph, compute_attack_paths

def demo_attack_graph():
    """Demonstrate attack graph functionality."""
    print("🛡️  Attack Graph Generator Demo")
    print("=" * 50)
    
    # Load and analyze sample data
    print("📊 Loading sample vulnerability data...")
    records = load_scan("sample_scan.json")
    print(f"   Loaded {len(records)} vulnerability records")
    
    # Show sample assets
    assets = set(r["asset_id"] for r in records)
    print(f"   Assets discovered: {len(assets)}")
    for asset in sorted(assets):
        asset_data = next(r for r in records if r["asset_id"] == asset)
        print(f"   - {asset} ({asset_data['asset_type']}) - {asset_data['ip']}")
    
    print("\n🕸️  Building attack graph...")
    G = build_graph(records)
    print(f"   Graph: {len(G.nodes())} nodes, {len(G.edges())} edges")
    
    # Identify critical components
    entry_points = [n for n, d in G.nodes(data=True) if d.get("node_type") == "asset" and
                    (d.get("asset_type") == "internet_gateway" or "web_server" in (d.get("asset_type") or ""))]
    if not entry_points:
        # Fallback: any asset with external IP or web service
        entry_points = [n for n, d in G.nodes(data=True) if d.get("node_type") == "asset" and
                       (not d.get("ip", "").startswith("10.") or "web" in (d.get("asset_type") or ""))]
    
    targets = [n for n, d in G.nodes(data=True) if d.get("node_type") == "asset" and 
               "db_server" in (d.get("asset_type") or "")]
    if not targets:
        # Fallback: highest criticality assets
        assets_by_crit = [(n, d.get("criticality", 5)) for n, d in G.nodes(data=True) 
                         if d.get("node_type") == "asset"]
        assets_by_crit.sort(key=lambda x: -x[1])
        targets = [assets_by_crit[0][0]] if assets_by_crit else []
    
    print(f"   Entry points: {entry_points}")
    print(f"   High-value targets: {targets}")
    
    print("\n🎯 Computing attack paths...")
    paths = compute_attack_paths(G, entry_points, targets, max_depth=4, top_k=5)
    print(f"   Found {len(paths)} potential attack paths")
    
    if paths:
        print("\n   🔥 Top Attack Paths:")
        for i, path in enumerate(paths, 1):
            path_str = " → ".join(path["path"])
            print(f"   {i}. {path_str}")
            print(f"      Risk Score: {path['score']:.4f} | Length: {path['len']} hops")
    
    print("\n📁 Generated Files:")
    output_files = [
        ("attack_graph_beautiful.html", "Interactive visualization"),
        ("attack_graph_beautiful.svg", "Static vector image"),
        ("attack_graph_beautiful.png", "Static raster image"),
        ("top_attack_paths.csv", "Attack path analysis"),
        ("attack_graph.json", "Raw graph data")
    ]
    
    for filename, description in output_files:
        if os.path.exists(filename):
            size = os.path.getsize(filename)
            print(f"   ✅ {filename} - {description} ({size:,} bytes)")
        else:
            print(f"   ❌ {filename} - Missing")
    
    print("\n🎨 Visualization Features:")
    print("   - Interactive HTML with hover tooltips")
    print("   - Color-coded nodes (red=exploitable, green=secure)")
    print("   - Edge thickness represents vulnerability severity")
    print("   - Physics-based layout for optimal viewing")
    
    print("\n📈 Analysis Insights:")
    if paths:
        shortest_path = min(paths, key=lambda x: x['len'])
        highest_risk = max(paths, key=lambda x: x['score'])
        
        print(f"   - Shortest attack path: {shortest_path['len']} hops")
        print(f"   - Highest risk path score: {highest_risk['score']:.4f}")
        print(f"   - Most common entry point: {entry_points[0] if entry_points else 'None'}")
        print(f"   - Primary target: {targets[0] if targets else 'None'}")
    
    print("\n🔧 Next Steps:")
    print("   1. Open attack_graph_beautiful.html in your browser")
    print("   2. Review top_attack_paths.csv for detailed analysis")
    print("   3. Use attack_graph.json for custom integrations")
    print("   4. Share static images for reports and presentations")
    
    print(f"\n✨ Demo completed! Attack graph analysis ready.")

if __name__ == "__main__":
    demo_attack_graph()