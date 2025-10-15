import { useState } from 'react';
import { Save, Key, Database, Bell, Shield, Trash2 } from 'lucide-react';
import { GlassmorphicLayout } from '../components/GlassmorphicLayout';
import { GlassmorphicNav } from '../components/GlassmorphicNav';
import { GlassmorphicCard, GlassmorphicCardHeader, GlassmorphicCardContent } from '../components/GlassmorphicCard';
import { Input } from '../components/ui/input';
import { Label } from '../components/ui/label';
import { Switch } from '../components/ui/switch';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs';
import { toast } from 'sonner';
import { motion } from 'motion/react';

export function SettingsPage() {
  const [apiKeys, setApiKeys] = useState({
    nvd: 'nvd_api_key_**********************',
    exploitdb: 'exploit_db_key_****************',
    shodan: 'shodan_key_********************',
    rapid7: '',
  });

  const [notifications, setNotifications] = useState({
    scanComplete: true,
    criticalVuln: true,
    newCVE: false,
    weeklyReport: true,
  });

  const [ragSettings, setRagSettings] = useState({
    modelPath: '/models/llama-2-7b-chat',
    indexPath: '/data/vulnerability-index',
    maxTokens: 2048,
    temperature: 0.7,
    cacheEnabled: true,
  });

  const handleSaveApiKeys = () => {
    toast.success('API keys saved successfully');
  };

  const handleSaveNotifications = () => {
    toast.success('Notification settings saved');
  };

  const handleSaveRAGSettings = () => {
    toast.success('RAG model settings updated');
  };

  const handleClearCache = () => {
    toast.success('Cache cleared successfully');
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
          <h1 className="text-3xl mb-2 text-white">Settings</h1>
          <p className="text-white/60">Manage your platform configuration and preferences</p>
        </motion.div>

        <Tabs defaultValue="api" className="space-y-6">
          <TabsList className="bg-white/5 border border-white/10">
            <TabsTrigger value="api" className="data-[state=active]:bg-white/10 gap-2">
              <Key className="h-4 w-4" />
              API Keys
            </TabsTrigger>
            <TabsTrigger value="rag" className="data-[state=active]:bg-white/10 gap-2">
              <Database className="h-4 w-4" />
              RAG Model
            </TabsTrigger>
            <TabsTrigger value="notifications" className="data-[state=active]:bg-white/10 gap-2">
              <Bell className="h-4 w-4" />
              Notifications
            </TabsTrigger>
          </TabsList>

          {/* API Keys Tab */}
          <TabsContent value="api">
            <GlassmorphicCard>
              <GlassmorphicCardHeader>
                <h2 className="text-xl text-white">API Key Management</h2>
                <p className="text-sm text-white/60">Configure API keys for external threat intelligence sources</p>
              </GlassmorphicCardHeader>
              <GlassmorphicCardContent className="space-y-6">
                <div className="space-y-4">
                  <div>
                    <Label htmlFor="nvd-key" className="text-white/80">NVD API Key</Label>
                    <Input
                      id="nvd-key"
                      type="password"
                      value={apiKeys.nvd}
                      onChange={(e) => setApiKeys({ ...apiKeys, nvd: e.target.value })}
                      placeholder="Enter NVD API key"
                      className="bg-white/5 border-white/10 text-white placeholder:text-white/40"
                    />
                    <p className="text-sm text-white/40 mt-1">
                      Get your API key from NVD Developer Portal
                    </p>
                  </div>

                  <div>
                    <Label htmlFor="exploitdb-key" className="text-white/80">ExploitDB API Key</Label>
                    <Input
                      id="exploitdb-key"
                      type="password"
                      value={apiKeys.exploitdb}
                      onChange={(e) => setApiKeys({ ...apiKeys, exploitdb: e.target.value })}
                      placeholder="Enter ExploitDB API key"
                      className="bg-white/5 border-white/10 text-white placeholder:text-white/40"
                    />
                  </div>

                  <div>
                    <Label htmlFor="shodan-key" className="text-white/80">Shodan API Key</Label>
                    <Input
                      id="shodan-key"
                      type="password"
                      value={apiKeys.shodan}
                      onChange={(e) => setApiKeys({ ...apiKeys, shodan: e.target.value })}
                      placeholder="Enter Shodan API key"
                      className="bg-white/5 border-white/10 text-white placeholder:text-white/40"
                    />
                  </div>

                  <div>
                    <Label htmlFor="rapid7-key" className="text-white/80">Rapid7 API Key (Optional)</Label>
                    <Input
                      id="rapid7-key"
                      type="password"
                      value={apiKeys.rapid7}
                      onChange={(e) => setApiKeys({ ...apiKeys, rapid7: e.target.value })}
                      placeholder="Enter Rapid7 API key"
                      className="bg-white/5 border-white/10 text-white placeholder:text-white/40"
                    />
                  </div>
                </div>

                <div className="border-t border-white/10 pt-4" />

                <div className="flex justify-end">
                  <motion.button 
                    onClick={handleSaveApiKeys} 
                    className="px-6 py-3 bg-emerald-500/20 backdrop-blur-xl rounded-full border border-emerald-500/30 text-white hover:bg-emerald-500/30 transition-all shadow-lg flex items-center gap-2"
                    whileHover={{ scale: 1.05 }}
                    whileTap={{ scale: 0.95 }}
                  >
                    <Save className="h-4 w-4" />
                    Save API Keys
                  </motion.button>
                </div>
              </GlassmorphicCardContent>
            </GlassmorphicCard>
          </TabsContent>

          {/* RAG Model Tab */}
          <TabsContent value="rag">
            <GlassmorphicCard>
              <GlassmorphicCardHeader>
                <h2 className="text-xl text-white">RAG Model Configuration</h2>
                <p className="text-sm text-white/60">Configure the Retrieval-Augmented Generation model settings</p>
              </GlassmorphicCardHeader>
              <GlassmorphicCardContent className="space-y-6">
                <div className="space-y-4">
                  <div>
                    <Label htmlFor="model-path" className="text-white/80">Model Path</Label>
                    <Input
                      id="model-path"
                      value={ragSettings.modelPath}
                      onChange={(e) => setRagSettings({ ...ragSettings, modelPath: e.target.value })}
                      placeholder="/path/to/model"
                      className="bg-white/5 border-white/10 text-white placeholder:text-white/40"
                    />
                  </div>

                  <div>
                    <Label htmlFor="index-path" className="text-white/80">Vector Index Path</Label>
                    <Input
                      id="index-path"
                      value={ragSettings.indexPath}
                      onChange={(e) => setRagSettings({ ...ragSettings, indexPath: e.target.value })}
                      placeholder="/path/to/index"
                      className="bg-white/5 border-white/10 text-white placeholder:text-white/40"
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <Label htmlFor="max-tokens" className="text-white/80">Max Tokens</Label>
                      <Input
                        id="max-tokens"
                        type="number"
                        value={ragSettings.maxTokens}
                        onChange={(e) => setRagSettings({ ...ragSettings, maxTokens: parseInt(e.target.value) })}
                        className="bg-white/5 border-white/10 text-white"
                      />
                    </div>

                    <div>
                      <Label htmlFor="temperature" className="text-white/80">Temperature</Label>
                      <Input
                        id="temperature"
                        type="number"
                        step="0.1"
                        min="0"
                        max="1"
                        value={ragSettings.temperature}
                        onChange={(e) => setRagSettings({ ...ragSettings, temperature: parseFloat(e.target.value) })}
                        className="bg-white/5 border-white/10 text-white"
                      />
                    </div>
                  </div>

                  <div className="flex items-center justify-between py-3 px-4 bg-white/5 rounded-xl border border-white/10">
                    <div>
                      <Label htmlFor="cache-enabled" className="text-white/80">Enable Response Caching</Label>
                      <p className="text-sm text-white/40">Cache responses for faster retrieval</p>
                    </div>
                    <Switch
                      id="cache-enabled"
                      checked={ragSettings.cacheEnabled}
                      onCheckedChange={(checked) => setRagSettings({ ...ragSettings, cacheEnabled: checked })}
                    />
                  </div>
                </div>

                <div className="border-t border-white/10 pt-4" />

                <div className="flex justify-between">
                  <motion.button 
                    onClick={handleClearCache}
                    className="px-6 py-3 bg-red-500/20 backdrop-blur-xl rounded-full border border-red-500/30 text-white hover:bg-red-500/30 transition-all shadow-lg flex items-center gap-2"
                    whileHover={{ scale: 1.05 }}
                    whileTap={{ scale: 0.95 }}
                  >
                    <Trash2 className="h-4 w-4" />
                    Clear Cache
                  </motion.button>
                  <motion.button 
                    onClick={handleSaveRAGSettings}
                    className="px-6 py-3 bg-emerald-500/20 backdrop-blur-xl rounded-full border border-emerald-500/30 text-white hover:bg-emerald-500/30 transition-all shadow-lg flex items-center gap-2"
                    whileHover={{ scale: 1.05 }}
                    whileTap={{ scale: 0.95 }}
                  >
                    <Save className="h-4 w-4" />
                    Save Settings
                  </motion.button>
                </div>
              </GlassmorphicCardContent>
            </GlassmorphicCard>

            {/* Model Performance Metrics */}
            <GlassmorphicCard className="mt-6">
              <GlassmorphicCardHeader>
                <h2 className="text-xl text-white">Model Performance Metrics</h2>
              </GlassmorphicCardHeader>
              <GlassmorphicCardContent>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div>
                    <div className="text-sm text-white/60">Accuracy</div>
                    <div className="text-2xl text-white">94.2%</div>
                  </div>
                  <div>
                    <div className="text-sm text-white/60">F1 Score</div>
                    <div className="text-2xl text-white">0.89</div>
                  </div>
                  <div>
                    <div className="text-sm text-white/60">Avg Response Time</div>
                    <div className="text-2xl text-white">1.2s</div>
                  </div>
                  <div>
                    <div className="text-sm text-white/60">Cache Hit Rate</div>
                    <div className="text-2xl text-white">67%</div>
                  </div>
                </div>
              </GlassmorphicCardContent>
            </GlassmorphicCard>
          </TabsContent>

          {/* Notifications Tab */}
          <TabsContent value="notifications">
            <GlassmorphicCard>
              <GlassmorphicCardHeader>
                <h2 className="text-xl text-white">Notification Preferences</h2>
                <p className="text-sm text-white/60">Choose what notifications you want to receive</p>
              </GlassmorphicCardHeader>
              <GlassmorphicCardContent className="space-y-6">
                <div className="space-y-4">
                  <div className="flex items-center justify-between py-3 px-4 bg-white/5 rounded-xl border border-white/10">
                    <div>
                      <Label htmlFor="scan-complete" className="text-white/80">Scan Completion</Label>
                      <p className="text-sm text-white/40">Notify when scans complete</p>
                    </div>
                    <Switch
                      id="scan-complete"
                      checked={notifications.scanComplete}
                      onCheckedChange={(checked) => setNotifications({ ...notifications, scanComplete: checked })}
                    />
                  </div>

                  <div className="flex items-center justify-between py-3 px-4 bg-white/5 rounded-xl border border-white/10">
                    <div>
                      <Label htmlFor="critical-vuln" className="text-white/80">Critical Vulnerabilities</Label>
                      <p className="text-sm text-white/40">Alert on critical vulnerability detection</p>
                    </div>
                    <Switch
                      id="critical-vuln"
                      checked={notifications.criticalVuln}
                      onCheckedChange={(checked) => setNotifications({ ...notifications, criticalVuln: checked })}
                    />
                  </div>

                  <div className="flex items-center justify-between py-3 px-4 bg-white/5 rounded-xl border border-white/10">
                    <div>
                      <Label htmlFor="new-cve" className="text-white/80">New CVE Updates</Label>
                      <p className="text-sm text-white/40">Notify about new CVEs affecting your assets</p>
                    </div>
                    <Switch
                      id="new-cve"
                      checked={notifications.newCVE}
                      onCheckedChange={(checked) => setNotifications({ ...notifications, newCVE: checked })}
                    />
                  </div>

                  <div className="flex items-center justify-between py-3 px-4 bg-white/5 rounded-xl border border-white/10">
                    <div>
                      <Label htmlFor="weekly-report" className="text-white/80">Weekly Reports</Label>
                      <p className="text-sm text-white/40">Receive weekly security summary</p>
                    </div>
                    <Switch
                      id="weekly-report"
                      checked={notifications.weeklyReport}
                      onCheckedChange={(checked) => setNotifications({ ...notifications, weeklyReport: checked })}
                    />
                  </div>
                </div>

                <div className="border-t border-white/10 pt-4" />

                <div className="flex justify-end">
                  <motion.button 
                    onClick={handleSaveNotifications}
                    className="px-6 py-3 bg-emerald-500/20 backdrop-blur-xl rounded-full border border-emerald-500/30 text-white hover:bg-emerald-500/30 transition-all shadow-lg flex items-center gap-2"
                    whileHover={{ scale: 1.05 }}
                    whileTap={{ scale: 0.95 }}
                  >
                    <Save className="h-4 w-4" />
                    Save Preferences
                  </motion.button>
                </div>
              </GlassmorphicCardContent>
            </GlassmorphicCard>
          </TabsContent>
        </Tabs>
      </div>
    </GlassmorphicLayout>
  );
}
