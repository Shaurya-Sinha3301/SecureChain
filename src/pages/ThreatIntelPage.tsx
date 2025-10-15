import { useState } from 'react';
import { Database, Search, ExternalLink, TrendingUp, AlertTriangle, Calendar, Code } from 'lucide-react';
import { GlassmorphicLayout } from '../components/GlassmorphicLayout';
import { GlassmorphicNav } from '../components/GlassmorphicNav';
import { GlassmorphicCard, GlassmorphicCardHeader, GlassmorphicCardContent } from '../components/GlassmorphicCard';
import { Input } from '../components/ui/input';
import { Badge } from '../components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs';
import { mockThreatIntel } from '../utils/mockData';
import { motion } from 'motion/react';

export function ThreatIntelPage() {
  const [searchQuery, setSearchQuery] = useState('');
  const [activeTab, setActiveTab] = useState('enriched');

  const recentCVEs = [
    { cveId: 'CVE-2025-0001', severity: 'critical', published: '2025-01-10', description: 'Remote code execution in popular framework' },
    { cveId: 'CVE-2025-0002', severity: 'high', published: '2025-01-09', description: 'Authentication bypass vulnerability' },
    { cveId: 'CVE-2025-0003', severity: 'critical', published: '2025-01-08', description: 'SQL injection in database driver' },
    { cveId: 'CVE-2025-0004', severity: 'medium', published: '2025-01-07', description: 'Cross-site scripting vulnerability' },
  ];

  const exploitActivity = [
    { cveId: 'CVE-2024-1234', exploits: 15, lastSeen: '2 hours ago', trending: true },
    { cveId: 'CVE-2024-5678', exploits: 8, lastSeen: '1 day ago', trending: false },
    { cveId: 'CVE-2024-9101', exploits: 3, lastSeen: '3 days ago', trending: false },
  ];

  const getSeverityColor = (severity: string) => {
    const colors: Record<string, string> = {
      critical: 'bg-red-600',
      high: 'bg-orange-600',
      medium: 'bg-yellow-600',
      low: 'bg-blue-600',
    };
    return colors[severity] || 'bg-gray-600';
  };

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
          <h1 className="text-3xl mb-2 text-white">Threat Intelligence</h1>
          <p className="text-white/60">Real-time CVE updates and exploit intelligence</p>
        </motion.div>

        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
          <GlassmorphicCard>
            <GlassmorphicCardContent className="pt-6">
              <div className="text-2xl mb-1 text-white">1,234</div>
              <div className="text-sm text-white/60">Total CVEs Tracked</div>
            </GlassmorphicCardContent>
          </GlassmorphicCard>
          <GlassmorphicCard>
            <GlassmorphicCardContent className="pt-6">
              <div className="text-2xl mb-1 text-red-400">45</div>
              <div className="text-sm text-white/60">Active Exploits</div>
            </GlassmorphicCardContent>
          </GlassmorphicCard>
          <GlassmorphicCard>
            <GlassmorphicCardContent className="pt-6">
              <div className="text-2xl mb-1 text-orange-400">156</div>
              <div className="text-sm text-white/60">PoCs Available</div>
            </GlassmorphicCardContent>
          </GlassmorphicCard>
          <GlassmorphicCard>
            <GlassmorphicCardContent className="pt-6">
              <div className="text-2xl mb-1 text-blue-400">8</div>
              <div className="text-sm text-white/60">New Today</div>
            </GlassmorphicCardContent>
          </GlassmorphicCard>
        </div>

        {/* Search */}
        <GlassmorphicCard className="mb-8">
          <GlassmorphicCardContent className="pt-6">
            <div className="flex gap-4">
              <div className="flex-1 relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-white/40" />
                <Input
                  placeholder="Search CVE ID, vulnerability name, or description..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-10 bg-white/5 border-white/10 text-white placeholder:text-white/40"
                />
              </div>
              <motion.button 
                className="px-6 py-2 bg-emerald-500/20 backdrop-blur-xl rounded-full border border-emerald-500/30 text-white hover:bg-emerald-500/30 transition-all shadow-lg"
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
              >
                Search
              </motion.button>
            </div>
          </GlassmorphicCardContent>
        </GlassmorphicCard>

        {/* Main Content */}
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="mb-6 bg-white/5 border border-white/10">
            <TabsTrigger value="enriched" className="data-[state=active]:bg-white/10">Enriched Data</TabsTrigger>
            <TabsTrigger value="recent" className="data-[state=active]:bg-white/10">Recent CVEs</TabsTrigger>
            <TabsTrigger value="exploits" className="data-[state=active]:bg-white/10">Exploit Activity</TabsTrigger>
            <TabsTrigger value="patterns" className="data-[state=active]:bg-white/10">Attack Patterns</TabsTrigger>
          </TabsList>

          <TabsContent value="enriched">
            <div className="grid lg:grid-cols-2 gap-6">
              {mockThreatIntel.map((item, index) => (
                <GlassmorphicCard key={index}>
                  <GlassmorphicCardHeader>
                    <div className="flex items-start justify-between">
                      <div>
                        <h3 className="text-xl text-white">{item.cveId}</h3>
                        <p className="text-sm text-white/60">Published: {item.publicationDate}</p>
                      </div>
                      {item.activeExploits && (
                        <Badge className="bg-red-600 text-white border-0">Active Exploits</Badge>
                      )}
                    </div>
                  </GlassmorphicCardHeader>
                  <GlassmorphicCardContent className="space-y-4">
                    <div>
                      <div className="text-sm text-white/60 mb-2">Exploit Information</div>
                      <div className="flex items-center gap-4 text-sm text-white/80">
                        <span>Published: {item.exploitPublished}</span>
                        <span>•</span>
                        <span>Count: {item.exploitCount}</span>
                      </div>
                    </div>

                    <div>
                      <div className="text-sm text-white/60 mb-2">Attack Patterns</div>
                      <div className="flex flex-wrap gap-2">
                        {item.attackPatterns.map((pattern, idx) => (
                          <Badge key={idx} className="bg-white/10 text-white border-white/20">{pattern}</Badge>
                        ))}
                      </div>
                    </div>

                    <div>
                      <div className="text-sm text-white/60 mb-2">Indicators of Compromise (IoCs)</div>
                      <div className="bg-black/20 rounded-lg p-3 space-y-1 border border-white/5">
                        {item.iocs.map((ioc, idx) => (
                          <div key={idx} className="font-mono text-sm text-emerald-400">{ioc}</div>
                        ))}
                      </div>
                    </div>

                    <div className="flex gap-2 pt-2">
                      <motion.button 
                        className="px-4 py-2 bg-white/5 backdrop-blur-xl rounded-full border border-white/10 text-white hover:bg-white/10 transition-all text-sm flex items-center gap-2"
                        whileHover={{ scale: 1.05 }}
                        whileTap={{ scale: 0.95 }}
                      >
                        <ExternalLink className="h-3 w-3" />
                        NVD Details
                      </motion.button>
                      <motion.button 
                        className="px-4 py-2 bg-white/5 backdrop-blur-xl rounded-full border border-white/10 text-white hover:bg-white/10 transition-all text-sm flex items-center gap-2"
                        whileHover={{ scale: 1.05 }}
                        whileTap={{ scale: 0.95 }}
                      >
                        <Code className="h-3 w-3" />
                        View PoCs
                      </motion.button>
                    </div>
                  </GlassmorphicCardContent>
                </GlassmorphicCard>
              ))}
            </div>
          </TabsContent>

          <TabsContent value="recent">
            <GlassmorphicCard>
              <GlassmorphicCardHeader>
                <div className="flex items-center gap-2">
                  <Calendar className="h-5 w-5 text-white" />
                  <h2 className="text-xl text-white">Recent CVE Disclosures</h2>
                </div>
              </GlassmorphicCardHeader>
              <GlassmorphicCardContent>
                <div className="space-y-4">
                  {recentCVEs.map((cve) => (
                    <div key={cve.cveId} className="bg-white/5 rounded-2xl p-4 border border-white/10">
                      <div className="flex items-start justify-between mb-2">
                        <div>
                          <div className="flex items-center gap-2 mb-2">
                            <h3 className="text-white">{cve.cveId}</h3>
                            <Badge className={`${getSeverityColor(cve.severity)} text-white border-0`}>
                              {cve.severity.toUpperCase()}
                            </Badge>
                          </div>
                          <p className="text-sm text-white/60">{cve.description}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-4 text-sm text-white/50">
                        <span>Published: {cve.published}</span>
                        <motion.button 
                          className="text-emerald-400 hover:text-emerald-300 transition-colors"
                          whileHover={{ x: 5 }}
                        >
                          View Details →
                        </motion.button>
                      </div>
                    </div>
                  ))}
                </div>
              </GlassmorphicCardContent>
            </GlassmorphicCard>
          </TabsContent>

          <TabsContent value="exploits">
            <GlassmorphicCard>
              <GlassmorphicCardHeader>
                <div className="flex items-center gap-2">
                  <TrendingUp className="h-5 w-5 text-white" />
                  <h2 className="text-xl text-white">Active Exploit Activity</h2>
                </div>
              </GlassmorphicCardHeader>
              <GlassmorphicCardContent>
                <div className="space-y-4">
                  {exploitActivity.map((item) => (
                    <div key={item.cveId} className="flex items-center justify-between p-4 bg-white/5 rounded-2xl border border-white/10">
                      <div className="flex items-center gap-4">
                        {item.trending && (
                          <TrendingUp className="h-5 w-5 text-red-400" />
                        )}
                        <div>
                          <div className="text-white">{item.cveId}</div>
                          <div className="text-sm text-white/60">Last seen: {item.lastSeen}</div>
                        </div>
                      </div>
                      <div className="text-right">
                        <div className="text-2xl text-red-400">{item.exploits}</div>
                        <div className="text-sm text-white/60">active exploits</div>
                      </div>
                    </div>
                  ))}
                </div>
              </GlassmorphicCardContent>
            </GlassmorphicCard>
          </TabsContent>

          <TabsContent value="patterns">
            <div className="grid lg:grid-cols-2 gap-6">
              <GlassmorphicCard>
                <GlassmorphicCardHeader>
                  <h2 className="text-xl text-white">Common Attack Patterns</h2>
                </GlassmorphicCardHeader>
                <GlassmorphicCardContent>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between p-3 bg-white/5 rounded-xl border border-white/10">
                      <span className="text-white/80">Remote Code Execution</span>
                      <Badge className="bg-white/10 text-white border-white/20">45 CVEs</Badge>
                    </div>
                    <div className="flex items-center justify-between p-3 bg-white/5 rounded-xl border border-white/10">
                      <span className="text-white/80">SQL Injection</span>
                      <Badge className="bg-white/10 text-white border-white/20">32 CVEs</Badge>
                    </div>
                    <div className="flex items-center justify-between p-3 bg-white/5 rounded-xl border border-white/10">
                      <span className="text-white/80">Privilege Escalation</span>
                      <Badge className="bg-white/10 text-white border-white/20">28 CVEs</Badge>
                    </div>
                    <div className="flex items-center justify-between p-3 bg-white/5 rounded-xl border border-white/10">
                      <span className="text-white/80">Authentication Bypass</span>
                      <Badge className="bg-white/10 text-white border-white/20">21 CVEs</Badge>
                    </div>
                  </div>
                </GlassmorphicCardContent>
              </GlassmorphicCard>

              <GlassmorphicCard>
                <GlassmorphicCardHeader>
                  <h2 className="text-xl text-white">Affected Technologies</h2>
                </GlassmorphicCardHeader>
                <GlassmorphicCardContent>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between p-3 bg-white/5 rounded-xl border border-white/10">
                      <span className="text-white/80">Web Servers</span>
                      <Badge className="bg-white/10 text-white border-white/20">67 CVEs</Badge>
                    </div>
                    <div className="flex items-center justify-between p-3 bg-white/5 rounded-xl border border-white/10">
                      <span className="text-white/80">Database Systems</span>
                      <Badge className="bg-white/10 text-white border-white/20">43 CVEs</Badge>
                    </div>
                    <div className="flex items-center justify-between p-3 bg-white/5 rounded-xl border border-white/10">
                      <span className="text-white/80">Network Devices</span>
                      <Badge className="bg-white/10 text-white border-white/20">38 CVEs</Badge>
                    </div>
                    <div className="flex items-center justify-between p-3 bg-white/5 rounded-xl border border-white/10">
                      <span className="text-white/80">Operating Systems</span>
                      <Badge className="bg-white/10 text-white border-white/20">29 CVEs</Badge>
                    </div>
                  </div>
                </GlassmorphicCardContent>
              </GlassmorphicCard>
            </div>
          </TabsContent>
        </Tabs>
      </div>
    </GlassmorphicLayout>
  );
}
