#!/usr/bin/env python3
"""
Demo: Complete SecureChain Workflow
Demonstrates the full pipeline from website input to chatbot interaction
"""

import os
import sys
import json
import time
import subprocess
from pathlib import Path

def print_banner():
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    SECURECHAIN COMPLETE WORKFLOW DEMO                       ║
║                                                                              ║
║  Input: Website URL → Vulnerability Scan → Attack Graph → Chatbot Q&A       ║
║                                                                              ║
║  🔍 AI Vulnerability Scanner    🕸️ Attack Graph Generation                   ║
║  🧠 OpenCTI Threat Intelligence  🤖 Interactive Chatbot                     ║
║  📊 Risk Assessment Reports     🛡️ Remediation Guidance                     ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """)

def demo_website_analysis():
    """Demonstrate complete website analysis"""
    
    print_banner()
    
    # Demo targets (safe, public testing sites)
    demo_targets = [
        "testphp.vulnweb.com",
        "demo.testfire.net", 
        "scanme.nmap.org"
    ]
    
    print("🎯 Available Demo Targets:")
    for i, target in enumerate(demo_targets, 1):
        print(f"  {i}. {target}")
    
    print("\n📝 Or enter your own target website")
    
    # Get user choice
    choice = input("\nSelect target (1-3) or enter custom URL: ").strip()
    
    if choice in ['1', '2', '3']:
        target = demo_targets[int(choice) - 1]
    elif choice:
        target = choice
    else:
        target = demo_targets[0]  # Default
    
    print(f"\n🎯 Selected Target: {target}")
    print("="*80)
    
    # Step 1: Run complete analysis
    print("🚀 STEP 1: Running Complete Vulnerability Analysis...")
    print("-" * 60)
    
    try:
        result = subprocess.run([
            sys.executable, "complete_website_analysis.py", target
        ], capture_output=True, text=True, timeout=120)
        
        if result.returncode == 0:
            print("✅ Analysis completed successfully!")
            
            # Extract analysis ID from output
            analysis_id = None
            for line in result.stdout.split('\n'):
                if 'Analysis ID:' in line:
                    analysis_id = line.split('Analysis ID:')[1].strip()
                    break
            
            if not analysis_id:
                # Find the most recent analysis files
                analysis_files = list(Path(".").glob("analysis_*_final_report.json"))
                if analysis_files:
                    latest_file = sorted(analysis_files)[-1]
                    analysis_id = latest_file.stem.replace('_final_report', '')
            
            if analysis_id:
                print(f"📊 Analysis ID: {analysis_id}")
                return analysis_id
            else:
                print("⚠️ Could not determine analysis ID")
                return None
        else:
            print(f"❌ Analysis failed: {result.stderr}")
            return None
            
    except subprocess.TimeoutExpired:
        print("⏰ Analysis timed out")
        return None
    except Exception as e:
        print(f"❌ Error running analysis: {e}")
        return None

def demo_results_review(analysis_id):
    """Demonstrate results review"""
    
    print(f"\n🔍 STEP 2: Reviewing Analysis Results...")
    print("-" * 60)
    
    # Check generated files
    expected_files = [
        f"{analysis_id}_final_report.json",
        f"{analysis_id}_attack_graph.png",
        f"{analysis_id}_interactive_report.html",
        f"{analysis_id}_chatbot_kb.json"
    ]
    
    print("📁 Generated Files:")
    for file in expected_files:
        if Path(file).exists():
            size = Path(file).stat().st_size
            print(f"  ✅ {file} ({size:,} bytes)")
        else:
            print(f"  ❌ {file} (missing)")
    
    # Load and display summary
    report_file = f"{analysis_id}_final_report.json"
    if Path(report_file).exists():
        with open(report_file, 'r') as f:
            report = json.load(f)
        
        summary = report['analysis_summary']
        print(f"\n📊 Analysis Summary:")
        print(f"  🎯 Target: {summary['target']}")
        print(f"  🔍 Total Vulnerabilities: {summary['total_findings']}")
        print(f"  📈 Severity Breakdown:")
        
        for severity, count in summary['severity_breakdown'].items():
            if count > 0:
                emoji = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢'}[severity]
                print(f"    {emoji} {severity}: {count}")
        
        # Show top recommendations
        recommendations = report.get('recommendations', [])
        if recommendations:
            print(f"\n💡 Top Recommendations:")
            for i, rec in enumerate(recommendations[:3], 1):
                print(f"  {i}. {rec}")
    
    return True

def demo_chatbot_interaction(analysis_id):
    """Demonstrate chatbot interaction"""
    
    print(f"\n🤖 STEP 3: Interactive Chatbot Demo...")
    print("-" * 60)
    
    kb_file = f"{analysis_id}_chatbot_kb.json"
    if not Path(kb_file).exists():
        print(f"❌ Knowledge base file not found: {kb_file}")
        return False
    
    # Load chatbot responses
    responses_file = f"{analysis_id}_chatbot_responses.json"
    if Path(responses_file).exists():
        with open(responses_file, 'r') as f:
            sample_responses = json.load(f)
        
        print("🎭 Sample Chatbot Interactions:")
        print("=" * 60)
        
        for question, answer in sample_responses.items():
            print(f"\n👤 User: {question}")
            print(f"🤖 Bot: {answer}")
            print("-" * 40)
    
    # Offer interactive session
    print(f"\n🎮 Interactive Session Available!")
    print(f"To start chatbot: python interactive_vulnerability_chatbot.py {kb_file}")
    
    start_interactive = input("\nStart interactive chatbot now? (y/N): ").strip().lower()
    
    if start_interactive == 'y':
        print("\n🚀 Starting Interactive Chatbot...")
        print("(Type 'quit' to exit the chatbot and return to demo)")
        print("=" * 60)
        
        try:
            subprocess.run([
                sys.executable, "interactive_vulnerability_chatbot.py", kb_file
            ], timeout=300)
        except subprocess.TimeoutExpired:
            print("\n⏰ Chatbot session timed out")
        except KeyboardInterrupt:
            print("\n⏹️ Chatbot session interrupted")
        except Exception as e:
            print(f"\n❌ Error starting chatbot: {e}")
    
    return True

def demo_attack_graph_visualization(analysis_id):
    """Demonstrate attack graph visualization"""
    
    print(f"\n🕸️ STEP 4: Attack Graph Visualization...")
    print("-" * 60)
    
    # Check for attack graph files
    graph_files = [
        f"{analysis_id}_attack_graph.png",
        f"{analysis_id}_attack_graph.json",
        f"{analysis_id}_interactive_report.html"
    ]
    
    print("🎨 Visualization Files:")
    for file in graph_files:
        if Path(file).exists():
            print(f"  ✅ {file}")
        else:
            print(f"  ❌ {file}")
    
    # Load attack graph data
    graph_file = f"{analysis_id}_attack_graph.json"
    if Path(graph_file).exists():
        with open(graph_file, 'r') as f:
            graph_data = json.load(f)
        
        print(f"\n📊 Attack Graph Statistics:")
        print(f"  🔗 Nodes: {len(graph_data.get('nodes', []))}")
        print(f"  ➡️ Edges: {len(graph_data.get('edges', []))}")
        print(f"  🎯 Attack Paths: {len(graph_data.get('attack_paths', []))}")
        
        # Show top attack paths
        attack_paths = graph_data.get('attack_paths', [])
        if attack_paths:
            print(f"\n🔥 Top Attack Paths:")
            for i, path in enumerate(attack_paths[:3], 1):
                risk_score = path.get('risk_score', 0)
                description = path.get('description', 'No description')
                print(f"  {i}. Risk: {risk_score:.2f} - {description}")
    
    # Show how to view visualizations
    html_file = f"{analysis_id}_interactive_report.html"
    if Path(html_file).exists():
        print(f"\n🌐 Interactive Report: {html_file}")
        print("   Open this file in your web browser to view the interactive report")
    
    png_file = f"{analysis_id}_attack_graph.png"
    if Path(png_file).exists():
        print(f"🖼️ Static Graph: {png_file}")
        print("   Open this image file to view the attack graph visualization")
    
    return True

def main():
    """Main demo function"""
    
    print("🎬 Starting SecureChain Complete Workflow Demo...")
    
    # Step 1: Website Analysis
    analysis_id = demo_website_analysis()
    if not analysis_id:
        print("❌ Demo failed at analysis step")
        return False
    
    # Step 2: Results Review
    if not demo_results_review(analysis_id):
        print("❌ Demo failed at results review step")
        return False
    
    # Step 3: Attack Graph Visualization
    if not demo_attack_graph_visualization(analysis_id):
        print("❌ Demo failed at visualization step")
        return False
    
    # Step 4: Chatbot Interaction
    if not demo_chatbot_interaction(analysis_id):
        print("❌ Demo failed at chatbot step")
        return False
    
    # Final Summary
    print(f"\n🎉 DEMO COMPLETE!")
    print("=" * 80)
    print(f"✅ Successfully demonstrated complete SecureChain workflow")
    print(f"📊 Analysis ID: {analysis_id}")
    print(f"🎯 All components working: Scan → Graph → Chatbot")
    
    print(f"\n📁 Generated Files for {analysis_id}:")
    all_files = [
        f"{analysis_id}_final_report.json",
        f"{analysis_id}_scan_results.json", 
        f"{analysis_id}_attack_graph.json",
        f"{analysis_id}_attack_graph.png",
        f"{analysis_id}_interactive_report.html",
        f"{analysis_id}_chatbot_kb.json",
        f"{analysis_id}_chatbot_responses.json"
    ]
    
    for file in all_files:
        if Path(file).exists():
            print(f"  ✅ {file}")
    
    print(f"\n🚀 Next Steps:")
    print(f"1. Open {analysis_id}_interactive_report.html in browser")
    print(f"2. View {analysis_id}_attack_graph.png for network visualization")
    print(f"3. Run: python interactive_vulnerability_chatbot.py {analysis_id}_chatbot_kb.json")
    print(f"4. Review {analysis_id}_final_report.json for complete analysis")
    
    print("=" * 80)
    return True

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n⏹️ Demo interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Demo failed with error: {e}")
        sys.exit(1)