#!/usr/bin/env python3
"""
Local LLM-Powered Vulnerability Chatbot
Uses local language models (Ollama, Hugging Face) for private, intelligent responses
"""

import json
import sys
import os
import requests
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class LocalLLMChatbot:
    """Local LLM-powered vulnerability chatbot"""
    
    def __init__(self, knowledge_base_file: str):
        self.knowledge_base = self._load_knowledge_base(knowledge_base_file)
        self.conversation_history = []
        self.context_window = []
        
        # Local LLM configurations
        self.ollama_url = os.getenv('OLLAMA_URL', 'http://localhost:11434')
        self.hf_model = os.getenv('HF_MODEL', 'microsoft/DialoGPT-medium')
        
        # Choose available local LLM
        self.llm_provider = self._detect_local_llm()
        
        # Create system prompt
        self.system_prompt = self._create_system_prompt()
        
    def _load_knowledge_base(self, kb_file: str) -> Dict:
        """Load knowledge base from JSON file"""
        try:
            with open(kb_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.error(f"Knowledge base file not found: {kb_file}")
            return self._create_default_kb()
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON in knowledge base file: {kb_file}")
            return self._create_default_kb()
    
    def _create_default_kb(self) -> Dict:
        """Create default knowledge base"""
        return {
            'target_info': {'website': 'example.com', 'total_vulnerabilities': 0},
            'vulnerabilities': {},
            'recommendations': [],
            'severity_summary': {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        }
    
    def _detect_local_llm(self) -> str:
        """Detect available local LLM providers"""
        # Check Ollama
        try:
            response = requests.get(f"{self.ollama_url}/api/tags", timeout=5)
            if response.status_code == 200:
                models = response.json().get('models', [])
                if models:
                    logger.info(f"Ollama detected with {len(models)} models")
                    return 'ollama'
        except:
            pass
        
        # Check Hugging Face Transformers
        try:
            import transformers
            logger.info("Hugging Face Transformers available")
            return 'huggingface'
        except ImportError:
            pass
        
        # Fallback to enhanced rule-based
        logger.warning("No local LLM detected. Using enhanced rule-based responses.")
        return 'enhanced_rules'
    
    def _create_system_prompt(self) -> str:
        """Create system prompt with vulnerability context"""
        target_info = self.knowledge_base.get('target_info', {})
        vulnerabilities = self.knowledge_base.get('vulnerabilities', {})
        severity_summary = self.knowledge_base.get('severity_summary', {})
        
        vuln_details = ""
        for vuln_id, vuln_data in vulnerabilities.items():
            vuln_details += f"- {vuln_id}: {vuln_data.get('severity')} ({vuln_data.get('cvss')} CVSS)\n"
        
        return f"""You are SecureChain AI, an expert cybersecurity consultant. You've analyzed {target_info.get('website', 'a website')} and found {target_info.get('total_vulnerabilities', 0)} vulnerabilities.

FINDINGS:
{vuln_details}

SEVERITY BREAKDOWN:
Critical: {severity_summary.get('Critical', 0)}, High: {severity_summary.get('High', 0)}, Medium: {severity_summary.get('Medium', 0)}

Provide expert, conversational advice about these specific vulnerabilities. Be practical, specific, and helpful."""
    
    def _call_ollama(self, user_message: str) -> str:
        """Call local Ollama model"""
        try:
            # Get available models
            models_response = requests.get(f"{self.ollama_url}/api/tags", timeout=5)
            if models_response.status_code != 200:
                return self._enhanced_rule_response(user_message)
            
            models = models_response.json().get('models', [])
            if not models:
                return self._enhanced_rule_response(user_message)
            
            # Use first available model (prefer llama2, mistral, or codellama)
            model_name = None
            preferred_models = ['llama2', 'mistral', 'codellama', 'llama3']
            
            for preferred in preferred_models:
                for model in models:
                    if preferred in model['name'].lower():
                        model_name = model['name']
                        break
                if model_name:
                    break
            
            if not model_name:
                model_name = models[0]['name']  # Use first available
            
            # Prepare conversation context
            conversation = self.system_prompt + "\n\nConversation:\n"
            for msg in self.context_window[-4:]:
                role = "Human" if msg["role"] == "user" else "Assistant"
                conversation += f"{role}: {msg['content']}\n"
            conversation += f"Human: {user_message}\nAssistant:"
            
            # Call Ollama API
            data = {
                "model": model_name,
                "prompt": conversation,
                "stream": False,
                "options": {
                    "temperature": 0.7,
                    "top_p": 0.9,
                    "max_tokens": 500
                }
            }
            
            response = requests.post(
                f"{self.ollama_url}/api/generate",
                json=data,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                return result.get('response', '').strip()
            else:
                logger.error(f"Ollama API error: {response.status_code}")
                return self._enhanced_rule_response(user_message)
                
        except Exception as e:
            logger.error(f"Ollama error: {e}")
            return self._enhanced_rule_response(user_message)
    
    def _call_huggingface(self, user_message: str) -> str:
        """Call Hugging Face local model"""
        try:
            from transformers import pipeline, AutoTokenizer, AutoModelForCausalLM
            
            # Use a lightweight conversational model
            model_name = "microsoft/DialoGPT-small"  # Smaller, faster model
            
            # Initialize model (cache for reuse)
            if not hasattr(self, '_hf_generator'):
                logger.info(f"Loading Hugging Face model: {model_name}")
                self._hf_generator = pipeline(
                    "text-generation",
                    model=model_name,
                    tokenizer=model_name,
                    device=-1,  # CPU
                    max_length=512,
                    do_sample=True,
                    temperature=0.7,
                    pad_token_id=50256
                )
            
            # Prepare context-aware prompt
            context = f"SecureChain AI analyzing {self.knowledge_base['target_info'].get('website', 'website')}:\n"
            context += f"Found {self.knowledge_base['target_info'].get('total_vulnerabilities', 0)} vulnerabilities.\n"
            context += f"User: {user_message}\nSecureChain AI:"
            
            # Generate response
            result = self._hf_generator(
                context,
                max_length=len(context.split()) + 100,
                num_return_sequences=1,
                temperature=0.7,
                do_sample=True
            )
            
            # Extract generated text
            generated = result[0]['generated_text']
            response = generated[len(context):].strip()
            
            # Clean up response
            if '\n' in response:
                response = response.split('\n')[0]
            
            return response if response else self._enhanced_rule_response(user_message)
            
        except Exception as e:
            logger.error(f"Hugging Face error: {e}")
            return self._enhanced_rule_response(user_message)
    
    def _enhanced_rule_response(self, user_message: str) -> str:
        """Enhanced rule-based responses with natural language patterns"""
        user_lower = user_message.lower()
        target_info = self.knowledge_base.get('target_info', {})
        vulnerabilities = self.knowledge_base.get('vulnerabilities', {})
        severity_summary = self.knowledge_base.get('severity_summary', {})
        
        # Natural language patterns for different intents
        greeting_patterns = ['hello', 'hi', 'hey', 'start', 'help']
        critical_patterns = ['critical', 'urgent', 'severe', 'dangerous', 'worst']
        fix_patterns = ['fix', 'remediate', 'patch', 'solve', 'repair', 'update']
        attack_patterns = ['attack', 'exploit', 'hack', 'breach', 'compromise']
        priority_patterns = ['priority', 'first', 'order', 'important', 'urgent']
        
        # Intent detection with natural responses
        if any(pattern in user_lower for pattern in greeting_patterns):
            return self._natural_greeting_response()
        elif any(pattern in user_lower for pattern in critical_patterns):
            return self._natural_critical_response()
        elif any(pattern in user_lower for pattern in fix_patterns):
            return self._natural_remediation_response(user_message)
        elif any(pattern in user_lower for pattern in attack_patterns):
            return self._natural_attack_response()
        elif any(pattern in user_lower for pattern in priority_patterns):
            return self._natural_priority_response()
        elif 'log4j' in user_lower or 'cve-2021-44228' in user_lower:
            return self._natural_log4j_response()
        else:
            return self._natural_general_response(user_message)
    
    def _natural_greeting_response(self) -> str:
        """Natural greeting response"""
        target = self.knowledge_base['target_info'].get('website', 'your website')
        total_vulns = self.knowledge_base['target_info'].get('total_vulnerabilities', 0)
        critical_count = self.knowledge_base['severity_summary'].get('Critical', 0)
        
        if critical_count > 0:
            urgency = f"I found {critical_count} critical vulnerabilities that need immediate attention! 🚨"
        elif total_vulns > 0:
            urgency = f"I discovered {total_vulns} security issues that we should address."
        else:
            urgency = "The security analysis looks good overall."
        
        return f"""Hey there! I'm SecureChain AI, your personal cybersecurity consultant. 

I've just finished analyzing **{target}** and here's what I found: {urgency}

I'm here to help you understand these vulnerabilities and guide you through fixing them step by step. Think of me as your security expert who speaks plain English, not tech jargon.

What would you like to know? You can ask me things like:
• "What's the most dangerous vulnerability?"
• "How do I fix the critical issues?"
• "What would happen if someone exploited these?"

Just ask me anything - I'm here to help! 😊"""
    
    def _natural_critical_response(self) -> str:
        """Natural response about critical vulnerabilities"""
        critical_vulns = {k: v for k, v in self.knowledge_base['vulnerabilities'].items() 
                         if v.get('severity') == 'Critical'}
        
        if not critical_vulns:
            return """Great news! 🎉 I didn't find any critical vulnerabilities in your analysis. 

That means there are no "drop everything and fix this now" type of security issues. You're in a much better position than many websites I analyze.

However, you might still have some high or medium severity issues that are worth addressing. Want me to walk you through those?"""
        
        responses = [
            "Alright, let's talk about the elephant in the room - your critical vulnerabilities. 😬",
            "I need to be straight with you about these critical security issues I found.",
            "Here's what's keeping me up at night about your website's security:"
        ]
        
        import random
        response = random.choice(responses) + "\n\n"
        
        for vuln_id, vuln_data in critical_vulns.items():
            service = vuln_data.get('service', 'Unknown service')
            cvss = vuln_data.get('cvss', 'Unknown')
            description = vuln_data.get('description', 'No description available')
            
            response += f"🔴 **{vuln_id}** (CVSS: {cvss}/10)\n"
            response += f"   This affects your {service} and here's why it's scary: {description}\n"
            response += f"   Translation: An attacker could potentially take complete control of your system.\n\n"
        
        response += "I know this sounds alarming, but the good news is that these are fixable! Want me to walk you through exactly how to secure these vulnerabilities?"
        
        return response
    
    def _natural_remediation_response(self, user_message: str) -> str:
        """Natural remediation guidance"""
        user_lower = user_message.lower()
        
        # Check if asking about specific vulnerability
        if 'log4j' in user_lower:
            return self._natural_log4j_response()
        
        # General remediation advice
        severity_summary = self.knowledge_base['severity_summary']
        target = self.knowledge_base['target_info'].get('website', 'your website')
        
        response = f"Absolutely! Let's get {target} secured. Here's your personalized action plan:\n\n"
        
        if severity_summary.get('Critical', 0) > 0:
            response += f"🚨 **STOP EVERYTHING AND DO THIS FIRST** ({severity_summary['Critical']} critical issues)\n"
            response += "These vulnerabilities are like leaving your front door wide open. Attackers are probably already scanning for these.\n"
            response += "Timeline: Fix these TODAY. Seriously, not tomorrow.\n\n"
        
        if severity_summary.get('High', 0) > 0:
            response += f"🟠 **HIGH PRIORITY** ({severity_summary['High']} high-severity issues)\n"
            response += "These are significant security gaps that skilled attackers could exploit.\n"
            response += "Timeline: Fix within the next week.\n\n"
        
        if severity_summary.get('Medium', 0) > 0:
            response += f"🟡 **MEDIUM PRIORITY** ({severity_summary['Medium']} medium-severity issues)\n"
            response += "These won't cause immediate disasters, but they're still security weaknesses.\n"
            response += "Timeline: Address within the next month.\n\n"
        
        response += "Want me to dive deeper into any specific vulnerability? Just ask me about it and I'll give you step-by-step instructions!"
        
        return response
    
    def _natural_attack_response(self) -> str:
        """Natural response about attack scenarios"""
        target = self.knowledge_base['target_info'].get('website', 'your website')
        critical_count = self.knowledge_base['severity_summary'].get('Critical', 0)
        
        if critical_count > 0:
            threat_level = "very real and immediate"
            scenario = "Here's what keeps me worried about your current security posture"
        else:
            threat_level = "moderate but manageable"
            scenario = "While you're not in immediate danger, here's what could happen"
        
        return f"""Let me paint you a picture of what an attacker might do to {target}. The threat level is {threat_level}.

{scenario}:

**🎯 The Attack Scenario:**

1. **Reconnaissance** - Attackers scan your website (just like I did) and find the same vulnerabilities
2. **Initial Access** - They exploit your web application vulnerabilities to get a foothold
3. **Escalation** - Using critical vulnerabilities (especially Log4j if present), they gain deeper system access
4. **Persistence** - They install backdoors to maintain access even if you patch some issues
5. **Data Theft** - They steal customer data, business secrets, or install ransomware

**🛡️ The Reality Check:**
- Your vulnerabilities are publicly known (CVE database)
- Automated tools scan for these 24/7
- It's not "if" but "when" if you don't patch

**💡 The Good News:**
Most attacks are opportunistic. Fix the critical and high-severity issues, and attackers will move on to easier targets.

Want me to help you prioritize which vulnerabilities to fix first to break these attack chains?"""
    
    def _natural_priority_response(self) -> str:
        """Natural prioritization guidance"""
        severity_summary = self.knowledge_base['severity_summary']
        
        return f"""Great question! Let me break down your security priorities like a triage nurse in an ER:

**🚨 CODE RED (Fix Immediately):** {severity_summary.get('Critical', 0)} critical vulnerabilities
Think of these as "patient is bleeding out" level urgency. These could lead to complete system compromise.
*Drop everything and fix these first.*

**🟠 URGENT (Fix This Week):** {severity_summary.get('High', 0)} high-severity issues  
These are like "broken bones" - serious problems that won't kill you immediately but need prompt attention.
*Schedule dedicated time this week.*

**🟡 IMPORTANT (Fix This Month):** {severity_summary.get('Medium', 0)} medium-severity issues
Think "sprained ankle" - you can walk, but you're vulnerable and it'll get worse if ignored.
*Add to your monthly maintenance schedule.*

**🟢 ROUTINE (Fix When Convenient):** {severity_summary.get('Low', 0)} low-severity issues
These are like "minor cuts" - good to address but won't cause major problems.
*Include in regular updates.*

**💡 Pro Tip:** Focus on internet-facing services first. A critical vulnerability on your internal network is less urgent than a medium vulnerability on your public website.

Which priority level would you like me to dive deeper into?"""
    
    def _natural_log4j_response(self) -> str:
        """Natural Log4j vulnerability explanation"""
        if 'CVE-2021-44228' in self.knowledge_base['vulnerabilities']:
            found_status = "I found this vulnerability in your system! 😰"
            urgency = "This is a five-alarm fire situation."
        else:
            found_status = "Good news - I didn't detect this in your current analysis."
            urgency = "But let me explain why everyone's talking about it."
        
        return f"""Ah, Log4j - the vulnerability that made cybersecurity professionals lose sleep worldwide! {found_status}

**What is Log4j?**
It's a Java logging library that's everywhere - like finding out your favorite coffee shop uses the same supplier as half the city. It's in web applications, enterprise software, even some IoT devices.

**Why is CVE-2021-44228 so scary?**
- Attackers can execute ANY code they want on your server
- It's ridiculously easy to exploit (just send a malicious string)
- It affects millions of applications worldwide
- It's been actively exploited since December 2021

**{urgency}**

**If you have Log4j vulnerability, here's your emergency action plan:**

1. **🔄 Update immediately** to Log4j version 2.17.0 or later
2. **🛡️ Emergency workaround** (if you can't update right now):
   ```bash
   # Remove the vulnerable class
   zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class
   ```
3. **⚙️ Set system property:** `-Dlog4j2.formatMsgNoLookups=true`
4. **🔍 Monitor your logs** for exploitation attempts (look for jndi patterns)

This isn't something you can put off. Attackers have automated tools scanning for this 24/7.

Need help with the technical steps? I can walk you through it!"""
    
    def _natural_general_response(self, user_message: str) -> str:
        """Natural general response"""
        target = self.knowledge_base['target_info'].get('website', 'your website')
        total_vulns = self.knowledge_base['target_info'].get('total_vulnerabilities', 0)
        
        return f"""I'm here to help you understand and secure {target}! 

From my analysis, I found {total_vulns} security issues that we should discuss. I can help you with:

🔍 **Understanding vulnerabilities** - "What does CVE-2021-44228 mean?"
🛠️ **Step-by-step fixes** - "How do I patch the Log4j vulnerability?"
🎯 **Risk prioritization** - "What should I fix first?"
🕸️ **Attack scenarios** - "How could someone exploit this?"
📊 **Security strategy** - "How do I prevent this in the future?"

I try to explain things in plain English, not tech jargon. Think of me as your friendly neighborhood security expert who actually wants to help, not just scare you with technical terms.

What specific aspect of your security would you like to explore? Just ask me naturally - I'm pretty good at understanding what you're looking for! 😊"""
    
    def process_query(self, user_message: str) -> str:
        """Process user query using local LLM or enhanced rules"""
        
        # Add to conversation history
        self.conversation_history.append({
            'timestamp': datetime.now().isoformat(),
            'user_message': user_message,
            'llm_provider': self.llm_provider
        })
        
        # Add to context window
        self.context_window.append({"role": "user", "content": user_message})
        
        # Get response based on available LLM
        if self.llm_provider == 'ollama':
            response = self._call_ollama(user_message)
        elif self.llm_provider == 'huggingface':
            response = self._call_huggingface(user_message)
        else:
            response = self._enhanced_rule_response(user_message)
        
        # Add response to context
        self.context_window.append({"role": "assistant", "content": response})
        
        # Keep context manageable
        if len(self.context_window) > 8:
            self.context_window = self.context_window[-8:]
        
        return response
    
    def start_interactive_session(self):
        """Start interactive session"""
        print("="*80)
        print("🤖 SECURECHAIN LOCAL AI - PRIVATE VULNERABILITY CONSULTANT")
        print("="*80)
        
        # Show LLM provider status
        provider_info = {
            'ollama': '🦙 Ollama (Local LLM)',
            'huggingface': '🤗 Hugging Face Transformers',
            'enhanced_rules': '🧠 Enhanced Rule-Based (No LLM required)'
        }
        
        print(f"🔧 AI Provider: {provider_info.get(self.llm_provider, 'Unknown')}")
        print("🔒 Privacy: All processing happens locally on your machine")
        
        print("\n" + self.process_query("hello"))
        print("\nType 'quit' or 'exit' to end the session.")
        print("="*80)
        
        while True:
            try:
                user_input = input("\n💬 You: ").strip()
                
                if user_input.lower() in ['quit', 'exit', 'bye']:
                    print("\n👋 Thanks for using SecureChain Local AI! Stay secure!")
                    break
                
                if not user_input:
                    print("Please enter a question or type 'quit' to exit.")
                    continue
                
                print("\n🤖 SecureChain AI: ", end="")
                
                # Show processing indicator for LLM responses
                if self.llm_provider in ['ollama', 'huggingface']:
                    print("(processing locally...)", end="", flush=True)
                    print("\r🤖 SecureChain AI: ", end="")
                
                response = self.process_query(user_input)
                print(response)
                
            except KeyboardInterrupt:
                print("\n\n👋 Session ended. Stay secure!")
                break
            except Exception as e:
                logger.error(f"Error: {e}")
                print(f"\n❌ I encountered an error. Please try again.")

def main():
    """Main function"""
    print("🚀 Starting SecureChain Local AI Vulnerability Chatbot...")
    
    # Check for local LLM availability
    print("\n🔍 Checking for local AI capabilities...")
    
    # Check Ollama
    try:
        response = requests.get("http://localhost:11434/api/tags", timeout=2)
        if response.status_code == 200:
            models = response.json().get('models', [])
            print(f"✅ Ollama detected with {len(models)} models")
        else:
            print("⚠️  Ollama not available")
    except:
        print("⚠️  Ollama not available (install from https://ollama.ai)")
    
    # Check Hugging Face
    try:
        import transformers
        print("✅ Hugging Face Transformers available")
    except ImportError:
        print("⚠️  Hugging Face Transformers not available (pip install transformers)")
    
    print("✅ Enhanced rule-based responses always available")
    
    # Get knowledge base file
    if len(sys.argv) > 1:
        kb_file = sys.argv[1]
    else:
        kb_files = list(Path(".").glob("*_chatbot_kb.json"))
        if kb_files:
            kb_file = str(sorted(kb_files)[-1])
            print(f"\n📚 Using knowledge base: {kb_file}")
        else:
            print("\n❌ No knowledge base file found.")
            print("   Run: python complete_website_analysis.py <website> first")
            sys.exit(1)
    
    try:
        chatbot = LocalLLMChatbot(kb_file)
        chatbot.start_interactive_session()
    except Exception as e:
        logger.error(f"Error starting chatbot: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()