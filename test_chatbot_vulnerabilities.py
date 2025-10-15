#!/usr/bin/env python3
"""
Chatbot Vulnerability Query Testing Script
Tests the chatbot's ability to answer security-related questions
"""

import requests
import json
import time
import logging
from typing import List, Dict, Any
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ChatbotVulnerabilityTester:
    """Test chatbot responses to vulnerability-related queries"""
    
    def __init__(self, chatbot_url: str = "http://localhost:3001"):
        self.chatbot_url = chatbot_url
        self.test_results = []
        
    def test_vulnerability_queries(self) -> Dict[str, Any]:
        """Test various vulnerability-related queries"""
        
        test_queries = [
            {
                "category": "Critical Vulnerabilities",
                "query": "What are the critical vulnerabilities in our network?",
                "expected_keywords": ["critical", "vulnerability", "CVE", "CVSS", "high risk"]
            },
            {
                "category": "CVE Lookup",
                "query": "Tell me about CVE-2021-44228 (Log4j vulnerability)",
                "expected_keywords": ["log4j", "remote code execution", "java", "apache", "critical"]
            },
            {
                "category": "Asset Risk Assessment",
                "query": "Which assets are most at risk in our environment?",
                "expected_keywords": ["asset", "risk", "vulnerability", "critical", "exposure"]
            },
            {
                "category": "Attack Paths",
                "query": "What attack paths exist from external services to our database?",
                "expected_keywords": ["attack path", "lateral movement", "database", "external", "compromise"]
            },
            {
                "category": "Remediation Guidance",
                "query": "How can we remediate the SSH vulnerabilities found in our scan?",
                "expected_keywords": ["ssh", "remediation", "patch", "update", "configuration"]
            },
            {
                "category": "MITRE ATT&CK",
                "query": "What MITRE ATT&CK techniques are associated with our vulnerabilities?",
                "expected_keywords": ["mitre", "att&ck", "technique", "tactic", "T1021"]
            },
            {
                "category": "Network Segmentation",
                "query": "How does network segmentation help reduce our attack surface?",
                "expected_keywords": ["network segmentation", "attack surface", "isolation", "firewall"]
            },
            {
                "category": "Vulnerability Prioritization",
                "query": "How should we prioritize vulnerability remediation?",
                "expected_keywords": ["prioritize", "cvss", "exploitability", "business impact", "critical"]
            },
            {
                "category": "Threat Intelligence",
                "query": "Are there any active threats targeting our identified vulnerabilities?",
                "expected_keywords": ["threat", "exploit", "active", "in the wild", "threat actor"]
            },
            {
                "category": "Compliance Impact",
                "query": "How do these vulnerabilities affect our compliance posture?",
                "expected_keywords": ["compliance", "regulation", "standard", "audit", "requirement"]
            }
        ]
        
        results = {
            "timestamp": datetime.now().isoformat(),
            "total_queries": len(test_queries),
            "successful_queries": 0,
            "failed_queries": 0,
            "query_results": [],
            "overall_score": 0.0
        }
        
        for i, test_case in enumerate(test_queries, 1):
            logger.info(f"Testing query {i}/{len(test_queries)}: {test_case['category']}")
            
            try:
                # Send query to chatbot
                response = self._send_query(test_case["query"])
                
                if response:
                    # Analyze response quality
                    analysis = self._analyze_response(response, test_case["expected_keywords"])
                    
                    query_result = {
                        "query_id": i,
                        "category": test_case["category"],
                        "query": test_case["query"],
                        "response": response,
                        "analysis": analysis,
                        "status": "SUCCESS" if analysis["relevance_score"] >= 0.3 else "POOR_QUALITY",
                        "timestamp": datetime.now().isoformat()
                    }
                    
                    if analysis["relevance_score"] >= 0.3:
                        results["successful_queries"] += 1
                    else:
                        results["failed_queries"] += 1
                        
                else:
                    query_result = {
                        "query_id": i,
                        "category": test_case["category"],
                        "query": test_case["query"],
                        "response": None,
                        "analysis": {"error": "No response received"},
                        "status": "FAILED",
                        "timestamp": datetime.now().isoformat()
                    }
                    results["failed_queries"] += 1
                
                results["query_results"].append(query_result)
                
                # Brief pause between queries
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"Error testing query {i}: {str(e)}")
                query_result = {
                    "query_id": i,
                    "category": test_case["category"],
                    "query": test_case["query"],
                    "response": None,
                    "analysis": {"error": str(e)},
                    "status": "ERROR",
                    "timestamp": datetime.now().isoformat()
                }
                results["query_results"].append(query_result)
                results["failed_queries"] += 1
        
        # Calculate overall score
        if results["total_queries"] > 0:
            results["overall_score"] = results["successful_queries"] / results["total_queries"]
        
        return results
    
    def _send_query(self, query: str) -> str:
        """Send query to chatbot and return response"""
        try:
            # Try different possible endpoints
            endpoints = [
                f"{self.chatbot_url}/api/chat",
                f"{self.chatbot_url}/chat",
                f"{self.chatbot_url}/api/v1/chat"
            ]
            
            for endpoint in endpoints:
                try:
                    response = requests.post(
                        endpoint,
                        json={"message": query, "user_id": "test_user"},
                        timeout=30,
                        headers={"Content-Type": "application/json"}
                    )
                    
                    if response.status_code == 200:
                        data = response.json()
                        return data.get("response", data.get("message", ""))
                    
                except requests.exceptions.RequestException:
                    continue
            
            # If all endpoints fail, try a simple GET with query parameter
            try:
                response = requests.get(
                    f"{self.chatbot_url}/chat",
                    params={"q": query},
                    timeout=30
                )
                if response.status_code == 200:
                    return response.text
            except:
                pass
                
            return None
            
        except Exception as e:
            logger.error(f"Error sending query: {str(e)}")
            return None
    
    def _analyze_response(self, response: str, expected_keywords: List[str]) -> Dict[str, Any]:
        """Analyze the quality and relevance of the chatbot response"""
        if not response:
            return {
                "relevance_score": 0.0,
                "keyword_matches": 0,
                "response_length": 0,
                "quality_indicators": []
            }
        
        response_lower = response.lower()
        
        # Check for keyword matches
        keyword_matches = 0
        matched_keywords = []
        for keyword in expected_keywords:
            if keyword.lower() in response_lower:
                keyword_matches += 1
                matched_keywords.append(keyword)
        
        # Calculate relevance score
        relevance_score = keyword_matches / len(expected_keywords) if expected_keywords else 0
        
        # Check for quality indicators
        quality_indicators = []
        
        # Length check
        if len(response) > 100:
            quality_indicators.append("adequate_length")
        
        # Technical terms
        technical_terms = ["vulnerability", "cve", "cvss", "exploit", "patch", "security", 
                          "risk", "threat", "attack", "remediation", "mitigation"]
        tech_term_count = sum(1 for term in technical_terms if term in response_lower)
        if tech_term_count >= 3:
            quality_indicators.append("technical_content")
        
        # Actionable advice
        actionable_words = ["should", "recommend", "update", "patch", "configure", 
                           "implement", "disable", "enable", "monitor"]
        if any(word in response_lower for word in actionable_words):
            quality_indicators.append("actionable_advice")
        
        # Specific references
        if any(ref in response_lower for ref in ["cve-", "mitre", "owasp", "nist"]):
            quality_indicators.append("specific_references")
        
        # Structure indicators
        if any(indicator in response for indicator in ["1.", "2.", "•", "-", "Step"]):
            quality_indicators.append("structured_response")
        
        return {
            "relevance_score": relevance_score,
            "keyword_matches": keyword_matches,
            "matched_keywords": matched_keywords,
            "response_length": len(response),
            "quality_indicators": quality_indicators,
            "technical_term_count": tech_term_count
        }
    
    def test_contextual_queries(self) -> Dict[str, Any]:
        """Test contextual follow-up queries"""
        
        contextual_tests = [
            {
                "initial_query": "What vulnerabilities were found in our last scan?",
                "follow_up": "Which of these are being actively exploited?",
                "context_type": "threat_intelligence"
            },
            {
                "initial_query": "Show me critical vulnerabilities in web servers",
                "follow_up": "What's the remediation timeline for these?",
                "context_type": "remediation_planning"
            },
            {
                "initial_query": "What attack paths exist in our network?",
                "follow_up": "How can we break these attack chains?",
                "context_type": "defensive_strategy"
            }
        ]
        
        results = {
            "timestamp": datetime.now().isoformat(),
            "contextual_tests": [],
            "context_retention_score": 0.0
        }
        
        successful_contexts = 0
        
        for test in contextual_tests:
            logger.info(f"Testing contextual query: {test['context_type']}")
            
            try:
                # Send initial query
                initial_response = self._send_query(test["initial_query"])
                time.sleep(2)
                
                # Send follow-up query
                followup_response = self._send_query(test["follow_up"])
                
                # Analyze context retention
                context_retained = self._analyze_context_retention(
                    initial_response, followup_response, test["context_type"]
                )
                
                test_result = {
                    "context_type": test["context_type"],
                    "initial_query": test["initial_query"],
                    "follow_up": test["follow_up"],
                    "initial_response": initial_response,
                    "followup_response": followup_response,
                    "context_retained": context_retained,
                    "status": "SUCCESS" if context_retained else "FAILED"
                }
                
                if context_retained:
                    successful_contexts += 1
                
                results["contextual_tests"].append(test_result)
                
            except Exception as e:
                logger.error(f"Error in contextual test: {str(e)}")
                results["contextual_tests"].append({
                    "context_type": test["context_type"],
                    "error": str(e),
                    "status": "ERROR"
                })
        
        if len(contextual_tests) > 0:
            results["context_retention_score"] = successful_contexts / len(contextual_tests)
        
        return results
    
    def _analyze_context_retention(self, initial_response: str, followup_response: str, 
                                 context_type: str) -> bool:
        """Analyze if the chatbot retained context between queries"""
        if not initial_response or not followup_response:
            return False
        
        # Check if follow-up response references the initial context
        initial_keywords = self._extract_key_terms(initial_response)
        followup_lower = followup_response.lower()
        
        # Look for references to previous context
        context_indicators = [
            "these vulnerabilities", "those issues", "the mentioned", 
            "previously identified", "from the scan", "these findings"
        ]
        
        has_context_reference = any(indicator in followup_lower for indicator in context_indicators)
        
        # Check for keyword overlap
        keyword_overlap = sum(1 for keyword in initial_keywords 
                            if keyword in followup_lower) >= 2
        
        return has_context_reference or keyword_overlap
    
    def _extract_key_terms(self, text: str) -> List[str]:
        """Extract key technical terms from text"""
        if not text:
            return []
        
        key_terms = []
        text_lower = text.lower()
        
        # Common vulnerability terms
        vuln_terms = ["vulnerability", "cve", "exploit", "patch", "critical", 
                     "high", "medium", "low", "cvss", "risk"]
        
        for term in vuln_terms:
            if term in text_lower:
                key_terms.append(term)
        
        return key_terms
    
    def generate_test_report(self, basic_results: Dict, contextual_results: Dict) -> Dict:
        """Generate comprehensive test report"""
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "test_summary": {
                "basic_query_success_rate": basic_results["overall_score"],
                "contextual_success_rate": contextual_results["context_retention_score"],
                "total_queries_tested": basic_results["total_queries"],
                "successful_basic_queries": basic_results["successful_queries"],
                "failed_basic_queries": basic_results["failed_queries"]
            },
            "detailed_results": {
                "basic_queries": basic_results,
                "contextual_queries": contextual_results
            },
            "performance_analysis": self._analyze_performance(basic_results),
            "recommendations": self._generate_recommendations(basic_results, contextual_results)
        }
        
        return report
    
    def _analyze_performance(self, results: Dict) -> Dict:
        """Analyze chatbot performance across different categories"""
        
        category_performance = {}
        
        for query_result in results["query_results"]:
            category = query_result["category"]
            if category not in category_performance:
                category_performance[category] = {
                    "total": 0,
                    "successful": 0,
                    "avg_relevance": 0.0,
                    "avg_quality_indicators": 0
                }
            
            category_performance[category]["total"] += 1
            
            if query_result["status"] == "SUCCESS":
                category_performance[category]["successful"] += 1
            
            if "analysis" in query_result and "relevance_score" in query_result["analysis"]:
                category_performance[category]["avg_relevance"] += query_result["analysis"]["relevance_score"]
            
            if "analysis" in query_result and "quality_indicators" in query_result["analysis"]:
                category_performance[category]["avg_quality_indicators"] += len(query_result["analysis"]["quality_indicators"])
        
        # Calculate averages
        for category in category_performance:
            total = category_performance[category]["total"]
            if total > 0:
                category_performance[category]["success_rate"] = category_performance[category]["successful"] / total
                category_performance[category]["avg_relevance"] /= total
                category_performance[category]["avg_quality_indicators"] /= total
        
        return {
            "category_breakdown": category_performance,
            "strongest_categories": sorted(category_performance.items(), 
                                         key=lambda x: x[1]["success_rate"], reverse=True)[:3],
            "weakest_categories": sorted(category_performance.items(), 
                                       key=lambda x: x[1]["success_rate"])[:3]
        }
    
    def _generate_recommendations(self, basic_results: Dict, contextual_results: Dict) -> List[str]:
        """Generate recommendations for improving chatbot performance"""
        
        recommendations = []
        
        overall_score = basic_results["overall_score"]
        context_score = contextual_results["context_retention_score"]
        
        if overall_score < 0.7:
            recommendations.append("Overall query success rate is below 70% - consider improving knowledge base")
        
        if context_score < 0.5:
            recommendations.append("Context retention is poor - implement conversation memory")
        
        # Analyze failed queries
        failed_categories = []
        for query_result in basic_results["query_results"]:
            if query_result["status"] != "SUCCESS":
                failed_categories.append(query_result["category"])
        
        from collections import Counter
        common_failures = Counter(failed_categories).most_common(3)
        
        for category, count in common_failures:
            recommendations.append(f"Improve responses for {category} queries - {count} failures detected")
        
        # Technical recommendations
        if overall_score >= 0.8:
            recommendations.append("Good performance - consider adding more advanced security topics")
        
        return recommendations
    
    def run_comprehensive_test(self) -> Dict:
        """Run comprehensive chatbot testing"""
        
        logger.info("🤖 Starting Comprehensive Chatbot Vulnerability Testing")
        logger.info("="*60)
        
        # Test basic vulnerability queries
        logger.info("Testing basic vulnerability queries...")
        basic_results = self.test_vulnerability_queries()
        
        # Test contextual queries
        logger.info("Testing contextual query handling...")
        contextual_results = self.test_contextual_queries()
        
        # Generate comprehensive report
        report = self.generate_test_report(basic_results, contextual_results)
        
        # Save results
        with open("chatbot_test_results.json", "w") as f:
            json.dump(report, f, indent=2)
        
        # Print summary
        self._print_test_summary(report)
        
        return report
    
    def _print_test_summary(self, report: Dict):
        """Print test summary to console"""
        
        print("\n" + "="*60)
        print("🤖 CHATBOT VULNERABILITY TESTING RESULTS")
        print("="*60)
        
        summary = report["test_summary"]
        print(f"Basic Query Success Rate: {summary['basic_query_success_rate']:.1%}")
        print(f"Contextual Success Rate: {summary['contextual_success_rate']:.1%}")
        print(f"Total Queries Tested: {summary['total_queries_tested']}")
        print(f"Successful Queries: {summary['successful_basic_queries']}")
        print(f"Failed Queries: {summary['failed_basic_queries']}")
        
        print("\n📊 Category Performance:")
        performance = report["performance_analysis"]
        for category, stats in performance["category_breakdown"].items():
            print(f"  {category}: {stats['success_rate']:.1%} success rate")
        
        print("\n💡 Recommendations:")
        for i, rec in enumerate(report["recommendations"], 1):
            print(f"  {i}. {rec}")
        
        print("\n📁 Generated Files:")
        print("  ✅ chatbot_test_results.json - Detailed test results")
        
        print("="*60)

def main():
    """Main function"""
    
    print("🤖 SecureChain Chatbot Vulnerability Testing")
    print("="*50)
    print("This script tests the chatbot's ability to answer security questions")
    print("="*50)
    
    # Get chatbot URL
    chatbot_url = input("Enter chatbot URL (default: http://localhost:3001): ").strip()
    if not chatbot_url:
        chatbot_url = "http://localhost:3001"
    
    # Initialize tester
    tester = ChatbotVulnerabilityTester(chatbot_url)
    
    # Run tests
    try:
        results = tester.run_comprehensive_test()
        
        overall_success = (results["test_summary"]["basic_query_success_rate"] >= 0.7 and
                          results["test_summary"]["contextual_success_rate"] >= 0.5)
        
        if overall_success:
            print("\n🎉 Chatbot testing completed successfully!")
            return 0
        else:
            print("\n⚠️ Chatbot testing revealed areas for improvement.")
            return 1
            
    except Exception as e:
        logger.error(f"Testing failed: {str(e)}")
        print(f"\n❌ Testing failed: {str(e)}")
        return 1

if __name__ == "__main__":
    exit(main())