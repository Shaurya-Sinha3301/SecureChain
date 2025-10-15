import { useState } from 'react';
import { BookOpen, Search, Terminal, Shield, ScanSearch, GitBranch, MessageSquare } from 'lucide-react';
import { GlassmorphicLayout } from '../components/GlassmorphicLayout';
import { GlassmorphicNav } from '../components/GlassmorphicNav';
import { GlassmorphicCard, GlassmorphicCardHeader, GlassmorphicCardContent } from '../components/GlassmorphicCard';
import { Input } from '../components/ui/input';
import { Badge } from '../components/ui/badge';
import { motion } from 'motion/react';

export function DocsPage() {
  const [searchQuery, setSearchQuery] = useState('');
  const [activeSection, setActiveSection] = useState('getting-started');

  const sections = [
    { id: 'getting-started', title: 'Getting Started', icon: BookOpen },
    { id: 'scanning', title: 'Vulnerability Scanning', icon: ScanSearch },
    { id: 'attack-paths', title: 'Attack Path Visualization', icon: GitBranch },
    { id: 'ai-assistant', title: 'AI Assistant', icon: MessageSquare },
    { id: 'threat-intel', title: 'Threat Intelligence', icon: Shield },
    { id: 'api', title: 'API Reference', icon: Terminal },
  ];

  return (
    <GlassmorphicLayout>
      <GlassmorphicNav />
      
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <motion.div 
          className="mb-8"
          initial={{ y: 20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ duration: 0.6 }}
        >
          <h1 className="text-3xl mb-2 text-white">Documentation</h1>
          <p className="text-white/60">Learn how to use CyberGuard AI platform</p>
        </motion.div>

        {/* Search */}
        <div className="mb-6">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-white/40" />
            <Input
              placeholder="Search documentation..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-10 bg-white/5 border-white/10 text-white placeholder:text-white/40"
            />
          </div>
        </div>

        <div className="grid lg:grid-cols-4 gap-6">
          {/* Sidebar */}
          <div className="lg:col-span-1">
            <GlassmorphicCard>
              <GlassmorphicCardContent className="pt-6">
                <div className="space-y-2">
                  {sections.map((section) => {
                    const Icon = section.icon;
                    return (
                      <motion.button
                        key={section.id}
                        onClick={() => setActiveSection(section.id)}
                        className={`w-full text-left px-3 py-2 rounded-xl flex items-center gap-3 transition-colors ${
                          activeSection === section.id
                            ? 'bg-emerald-500/20 text-white border border-emerald-500/30'
                            : 'hover:bg-white/10 text-white/80 border border-transparent'
                        }`}
                        whileHover={{ scale: 1.02 }}
                        whileTap={{ scale: 0.98 }}
                      >
                        <Icon className="h-4 w-4 flex-shrink-0" />
                        <span className="text-sm">{section.title}</span>
                      </motion.button>
                    );
                  })}
                </div>
              </GlassmorphicCardContent>
            </GlassmorphicCard>
          </div>

          {/* Content */}
          <div className="lg:col-span-3">
            <GlassmorphicCard>
              <GlassmorphicCardContent className="pt-6">
                <div className="prose prose-invert max-w-none">
                  {activeSection === 'getting-started' && (
                    <div className="space-y-6">
                      <div>
                        <h2 className="text-2xl mb-4 text-white">Getting Started with CyberGuard AI</h2>
                        <p className="text-white/70 mb-4">
                          CyberGuard AI is a comprehensive cybersecurity platform that combines vulnerability scanning,
                          attack-path visualization, and AI-powered security analysis.
                        </p>
                      </div>

                      <div>
                        <h3 className="text-xl mb-3 text-white">Quick Start Guide</h3>
                        <ol className="list-decimal list-inside space-y-2 text-white/70">
                          <li>Configure your API keys in Settings</li>
                          <li>Navigate to the Scan page</li>
                          <li>Enter your target domain or IP address</li>
                          <li>Select scanning tools and intensity level</li>
                          <li>Click "Start Scan" to begin vulnerability assessment</li>
                          <li>Review results in the Dashboard and Reports</li>
                        </ol>
                      </div>

                      <div>
                        <h3 className="text-xl mb-3 text-white">System Requirements</h3>
                        <ul className="list-disc list-inside space-y-1 text-white/70">
                          <li>Python 3.8 or higher</li>
                          <li>Node.js 16.x or higher</li>
                          <li>8GB RAM minimum (16GB recommended)</li>
                          <li>100GB available storage</li>
                          <li>Network access to target systems</li>
                        </ul>
                      </div>
                    </div>
                  )}

                  {activeSection === 'scanning' && (
                    <div className="space-y-6">
                      <div>
                        <h2 className="text-2xl mb-4 text-white">Vulnerability Scanning</h2>
                        <p className="text-white/70 mb-4">
                          CyberGuard AI integrates multiple industry-standard scanning tools to provide comprehensive
                          vulnerability assessment.
                        </p>
                      </div>

                      <div>
                        <h3 className="text-xl mb-3 text-white">Available Scanning Tools</h3>
                        
                        <div className="space-y-4">
                          <div className="bg-white/5 rounded-xl p-4 border border-white/10">
                            <h4 className="text-lg text-white mb-2">Nmap</h4>
                            <p className="text-sm text-white/60 mb-2">
                              Network discovery and port scanning tool for identifying open ports and services.
                            </p>
                            <Badge className="bg-blue-500/20 text-blue-300 border-blue-500/30">Network Layer</Badge>
                          </div>

                          <div className="bg-white/5 rounded-xl p-4 border border-white/10">
                            <h4 className="text-lg text-white mb-2">OpenVAS</h4>
                            <p className="text-sm text-white/60 mb-2">
                              Comprehensive vulnerability scanner with extensive CVE database.
                            </p>
                            <Badge className="bg-purple-500/20 text-purple-300 border-purple-500/30">Full Stack</Badge>
                          </div>

                          <div className="bg-white/5 rounded-xl p-4 border border-white/10">
                            <h4 className="text-lg text-white mb-2">Nikto</h4>
                            <p className="text-sm text-white/60 mb-2">
                              Web server scanner for detecting misconfigurations and vulnerabilities.
                            </p>
                            <Badge className="bg-gray-500/20 text-gray-300 border-gray-500/30">Web Applications</Badge>
                          </div>

                          <div className="bg-white/5 rounded-xl p-4 border border-white/10">
                            <h4 className="text-lg text-white mb-2">Nuclei</h4>
                            <p className="text-sm text-white/60 mb-2">
                              Template-based vulnerability scanner for fast, customizable scanning.
                            </p>
                            <Badge className="bg-orange-500/20 text-orange-300 border-orange-500/30">Template-Based</Badge>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  {activeSection === 'attack-paths' && (
                    <div className="space-y-6">
                      <div>
                        <h2 className="text-2xl mb-4 text-white">Attack Path Visualization</h2>
                        <p className="text-white/70 mb-4">
                          Visualize how attackers could chain vulnerabilities to compromise your systems.
                        </p>
                      </div>

                      <div>
                        <h3 className="text-xl mb-3 text-white">Understanding Attack Graphs</h3>
                        <ul className="list-disc list-inside space-y-2 text-white/70">
                          <li><span className="text-white">Entry Points:</span> External access points (web servers, exposed services)</li>
                          <li><span className="text-white">Vulnerabilities:</span> Exploitable weaknesses (CVEs) discovered during scans</li>
                          <li><span className="text-white">Assets:</span> Systems and resources that can be compromised</li>
                          <li><span className="text-white">Impact:</span> Potential outcomes (data breach, system compromise)</li>
                        </ul>
                      </div>

                      <div className="bg-blue-500/10 border border-blue-500/20 rounded-xl p-4">
                        <h4 className="text-blue-300 mb-2">Pro Tip</h4>
                        <p className="text-sm text-blue-200">
                          Click on any node in the graph to view detailed CVE information, exploit steps,
                          and recommended remediation actions.
                        </p>
                      </div>
                    </div>
                  )}

                  {activeSection === 'ai-assistant' && (
                    <div className="space-y-6">
                      <div>
                        <h2 className="text-2xl mb-4 text-white">AI-Powered Security Assistant</h2>
                        <p className="text-white/70 mb-4">
                          Query your vulnerability data using natural language with our RAG-based chatbot.
                        </p>
                      </div>

                      <div>
                        <h3 className="text-xl mb-3 text-white">Sample Queries</h3>
                        <div className="space-y-2">
                          <div className="bg-white/5 rounded-xl p-4 border border-white/10">
                            <p className="text-sm font-mono text-emerald-400">"What are the critical vulnerabilities in the latest scan?"</p>
                          </div>
                          <div className="bg-white/5 rounded-xl p-4 border border-white/10">
                            <p className="text-sm font-mono text-emerald-400">"Explain the exploit steps for CVE-2024-1234"</p>
                          </div>
                          <div className="bg-white/5 rounded-xl p-4 border border-white/10">
                            <p className="text-sm font-mono text-emerald-400">"Show me all SQL injection vulnerabilities"</p>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  {activeSection === 'threat-intel' && (
                    <div className="space-y-6">
                      <div>
                        <h2 className="text-2xl mb-4 text-white">Threat Intelligence Integration</h2>
                        <p className="text-white/70 mb-4">
                          Automatically enrich vulnerability data with threat intelligence from multiple sources.
                        </p>
                      </div>

                      <div>
                        <h3 className="text-xl mb-3 text-white">Data Sources</h3>
                        <div className="space-y-3">
                          <div>
                            <h4 className="text-white mb-1">National Vulnerability Database (NVD)</h4>
                            <p className="text-sm text-white/60">
                              Official CVE database with CVSS scores, descriptions, and references
                            </p>
                          </div>
                          <div>
                            <h4 className="text-white mb-1">ExploitDB</h4>
                            <p className="text-sm text-white/60">
                              Public exploit database with proof-of-concept code and exploit steps
                            </p>
                          </div>
                          <div>
                            <h4 className="text-white mb-1">Rapid7</h4>
                            <p className="text-sm text-white/60">
                              Threat intelligence and vulnerability research
                            </p>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  {activeSection === 'api' && (
                    <div className="space-y-6">
                      <div>
                        <h2 className="text-2xl mb-4 text-white">API Reference</h2>
                        <p className="text-white/70 mb-4">
                          Integrate CyberGuard AI into your security workflows using our REST API.
                        </p>
                      </div>

                      <div>
                        <h3 className="text-xl mb-3 text-white">Authentication</h3>
                        <div className="bg-black/40 text-gray-100 rounded-lg p-4 font-mono text-sm mb-3 border border-white/10">
                          <div>curl -X POST https://api.cyberguard.ai/auth/login \</div>
                          <div className="ml-4">-H &quot;Content-Type: application/json&quot; \</div>
                          <div className="ml-4">-d &apos;&#123;&quot;username&quot;:&quot;admin&quot;,&quot;password&quot;:&quot;****&quot;&#125;&apos;</div>
                        </div>
                      </div>

                      <div>
                        <h3 className="text-xl mb-3 text-white">Start a Scan</h3>
                        <div className="bg-black/40 text-gray-100 rounded-lg p-4 font-mono text-sm mb-3 border border-white/10">
                          <div>POST /api/v1/scans</div>
                          <div className="text-gray-400 mt-2">&#123;</div>
                          <div className="ml-4 text-gray-400">&quot;target&quot;: &quot;example.com&quot;,</div>
                          <div className="ml-4 text-gray-400">&quot;tools&quot;: [&quot;nmap&quot;, &quot;openvas&quot;],</div>
                          <div className="ml-4 text-gray-400">&quot;intensity&quot;: &quot;medium&quot;</div>
                          <div className="text-gray-400">&#125;</div>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </GlassmorphicCardContent>
            </GlassmorphicCard>
          </div>
        </div>
      </div>
    </GlassmorphicLayout>
  );
}
