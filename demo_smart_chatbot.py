#!/usr/bin/env python3
"""
Demo: Smart Vulnerability Chatbot
Demonstrates the improved natural language processing capabilities
"""

import sys
from pathlib import Path
from smart_vulnerability_chatbot import SmartVulnerabilityChatbot

def demo_chatbot_responses():
    """Demonstrate various chatbot responses"""
    
    # Find knowledge base file
    kb_files = list(Path(".").glob("*_chatbot_kb.json"))
    if not kb_files:
        print("❌ No knowledge base file found. Run complete_website_analysis.py first.")
        return False
    
    kb_file = str(sorted(kb_files)[-1])
    print(f"📚 Using knowledge base: {kb_file}")
    
    # Initialize chatbot
    chatbot = SmartVulnerabilityChatbot(kb_file)
    
    # Demo queries with natural language
    demo_queries = [
        "Hello, what did you find?",
        "What are the most dangerous vulnerabilities?",
        "Tell me about the Log4j vulnerability",
        "How can attackers exploit my website?",
        "What should I fix first?",
        "How do I patch the critical issues?",
        "What's my overall risk level?",
        "Explain CVSS scores to me"
    ]
    
    print("\n" + "="*80)
    print("🎭 SMART CHATBOT DEMO - NATURAL LANGUAGE RESPONSES")
    print("="*80)
    
    for i, query in enumerate(demo_queries, 1):
        print(f"\n{'='*60}")
        print(f"Demo Query {i}: {query}")
        print(f"{'='*60}")
        
        response = chatbot.process_query(query)
        print(f"\n🤖 SecureChain AI:\n{response}")
        
        input("\nPress Enter to continue to next demo...")
    
    print(f"\n{'='*80}")
    print("🎉 Demo completed! The chatbot shows much more natural responses.")
    print("✅ Key improvements:")
    print("  - Natural language understanding")
    print("  - Context-aware responses")
    print("  - Conversational tone")
    print("  - Specific vulnerability guidance")
    print("  - No more rigid if/else patterns")
    print("="*80)
    
    return True

def main():
    """Main function"""
    print("🎬 SecureChain Smart Chatbot Demo")
    print("="*50)
    print("This demo shows the improved natural language capabilities")
    print("of the SecureChain vulnerability chatbot.")
    print("="*50)
    
    try:
        success = demo_chatbot_responses()
        if success:
            print("\n🎉 Demo completed successfully!")
        else:
            print("\n❌ Demo failed - missing knowledge base")
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")

if __name__ == "__main__":
    main()