import { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Play, Square, RotateCcw, Terminal, AlertCircle, CheckCircle2, Loader2 } from 'lucide-react';
import { GlassmorphicLayout } from '../components/GlassmorphicLayout';
import { GlassmorphicNav } from '../components/GlassmorphicNav';
import { GlassmorphicCard, GlassmorphicCardHeader, GlassmorphicCardContent } from '../components/GlassmorphicCard';
import { Input } from '../components/ui/input';
import { Label } from '../components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select';
import { Checkbox } from '../components/ui/checkbox';
import { Progress } from '../components/ui/progress';
import { Badge } from '../components/ui/badge';
import { motion } from 'motion/react';

export function ScanningPage() {
  const { scanId } = useParams();
  const navigate = useNavigate();
  const [isScanning, setIsScanning] = useState(!!scanId);
  const [target, setTarget] = useState('example.com');
  const [intensity, setIntensity] = useState('medium');
  const [progress, setProgress] = useState(scanId ? 67 : 0);
  const [selectedTools, setSelectedTools] = useState(['nmap', 'openvas']);

  const tools = [
    { id: 'nmap', name: 'Nmap', description: 'Network discovery and port scanning' },
    { id: 'openvas', name: 'OpenVAS', description: 'Comprehensive vulnerability scanning' },
    { id: 'nikto', name: 'Nikto', description: 'Web server scanner' },
    { id: 'nuclei', name: 'Nuclei', description: 'Template-based vulnerability scanning' },
    { id: 'nessus', name: 'Nessus', description: 'Professional vulnerability assessment' },
  ];

  const [logs, setLogs] = useState([
    { time: '10:30:15', level: 'info', message: 'Initializing Nmap scan for target: example.com' },
    { time: '10:30:16', level: 'info', message: 'Port scan started - scanning 1000 most common ports' },
    { time: '10:30:45', level: 'success', message: 'Found 8 open ports: 22, 80, 443, 3306, 8080, 8443, 9000, 27017' },
    { time: '10:31:00', level: 'info', message: 'Starting service detection on open ports' },
    { time: '10:31:30', level: 'success', message: 'Service detection complete' },
    { time: '10:31:31', level: 'info', message: 'Initializing OpenVAS vulnerability scan' },
    { time: '10:32:00', level: 'warning', message: 'Detected outdated Apache version 2.4.41' },
    { time: '10:32:15', level: 'error', message: 'Critical vulnerability found: CVE-2024-1234 (CVSS 9.8)' },
    { time: '10:32:45', level: 'warning', message: 'SQL injection point detected on port 3306' },
    { time: '10:33:00', level: 'info', message: 'Scanning progress: 67% complete' },
  ]);

  const [stats, setStats] = useState({
    portsScanned: 1000,
    openPorts: 8,
    servicesDetected: 8,
    vulnerabilitiesFound: 8,
    critical: 1,
    high: 3,
    medium: 4,
    low: 0,
  });

  const handleStartScan = () => {
    if (!target) return;
    setIsScanning(true);
    setProgress(0);
    const interval = setInterval(() => {
      setProgress(prev => {
        if (prev >= 100) {
          clearInterval(interval);
          return 100;
        }
        return prev + 5;
      });
    }, 500);
  };

  const handleStopScan = () => {
    setIsScanning(false);
  };

  const handleViewReport = () => {
    navigate(`/report/${scanId || 'scan-001'}`);
  };

  const toggleTool = (toolId: string) => {
    setSelectedTools(prev =>
      prev.includes(toolId)
        ? prev.filter(t => t !== toolId)
        : [...prev, toolId]
    );
  };

  const getLogIcon = (level: string) => {
    switch (level) {
      case 'error':
        return <AlertCircle className="h-4 w-4 text-white" />;
      case 'warning':
        return <AlertCircle className="h-4 w-4 text-white" />;
      case 'success':
        return <CheckCircle2 className="h-4 w-4 text-white" />;
      default:
        return <Terminal className="h-4 w-4 text-white" />;
    }
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
          <h1 className="text-3xl mb-2 text-white">Vulnerability Scanner</h1>
          <p className="text-white/60">Configure and execute security scans</p>
        </motion.div>

        <div className="grid lg:grid-cols-3 gap-6">
          {/* Configuration Panel */}
          <div className="lg:col-span-1 space-y-6">
            <GlassmorphicCard>
              <GlassmorphicCardHeader>
                <h2 className="text-xl text-white">Scan Configuration</h2>
              </GlassmorphicCardHeader>
              <GlassmorphicCardContent className="space-y-4">
                <div>
                  <Label htmlFor="target" className="text-white/80">Target Domain/IP</Label>
                  <Input
                    id="target"
                    placeholder="example.com or 192.168.1.1"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    disabled={isScanning}
                    className="bg-white/5 border-white/10 text-white placeholder:text-white/40"
                  />
                </div>

                <div>
                  <Label htmlFor="intensity" className="text-white/80">Scan Intensity</Label>
                  <Select value={intensity} onValueChange={setIntensity} disabled={isScanning}>
                    <SelectTrigger id="intensity" className="bg-white/5 border-white/10 text-white">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="light">Light (Fast)</SelectItem>
                      <SelectItem value="medium">Medium (Balanced)</SelectItem>
                      <SelectItem value="aggressive">Aggressive (Thorough)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div>
                  <Label className="mb-3 block text-white/80">Scanning Tools</Label>
                  <div className="space-y-3">
                    {tools.map(tool => (
                      <div key={tool.id} className="flex items-start gap-3">
                        <Checkbox
                          id={tool.id}
                          checked={selectedTools.includes(tool.id)}
                          onCheckedChange={() => toggleTool(tool.id)}
                          disabled={isScanning}
                          className="border-white/20"
                        />
                        <div className="flex-1">
                          <label htmlFor={tool.id} className="text-sm text-white cursor-pointer">
                            {tool.name}
                          </label>
                          <p className="text-xs text-white/50">{tool.description}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="pt-4 space-y-2">
                  {!isScanning ? (
                    <motion.button 
                      className="w-full px-6 py-3 bg-white backdrop-blur-xl rounded-full border border-white text-black hover:bg-gray-100 transition-all shadow-lg flex items-center justify-center gap-2 font-satoshi font-bold"
                      onClick={handleStartScan}
                      disabled={selectedTools.length === 0 || !target}
                      whileHover={{ scale: 1.02 }}
                      whileTap={{ scale: 0.98 }}
                    >
                      <Play className="h-4 w-4" />
                      Start Scan
                    </motion.button>
                  ) : (
                    <>
                      <motion.button 
                        className="w-full px-6 py-3 bg-white backdrop-blur-xl rounded-full border border-white text-black hover:bg-gray-100 transition-all shadow-lg flex items-center justify-center gap-2 font-satoshi font-bold"
                        onClick={handleStopScan}
                        whileHover={{ scale: 1.02 }}
                        whileTap={{ scale: 0.98 }}
                      >
                        <Square className="h-4 w-4" />
                        Stop Scan
                      </motion.button>
                      {progress === 100 && (
                        <motion.button 
                          className="w-full px-6 py-3 bg-white/10 backdrop-blur-xl rounded-full border border-white/20 text-white hover:bg-white/20 transition-all shadow-lg"
                          onClick={handleViewReport}
                          whileHover={{ scale: 1.02 }}
                          whileTap={{ scale: 0.98 }}
                        >
                          View Full Report
                        </motion.button>
                      )}
                    </>
                  )}
                  <motion.button 
                    className="w-full px-6 py-3 bg-white/5 backdrop-blur-xl rounded-full border border-white/10 text-white hover:bg-white/10 transition-all shadow-lg flex items-center justify-center gap-2"
                    disabled={isScanning}
                    whileHover={{ scale: 1.02 }}
                    whileTap={{ scale: 0.98 }}
                  >
                    <RotateCcw className="h-4 w-4" />
                    Reset
                  </motion.button>
                </div>
              </GlassmorphicCardContent>
            </GlassmorphicCard>

            {/* Status Cards */}
            <GlassmorphicCard>
              <GlassmorphicCardHeader>
                <h2 className="text-xl text-white">Scan Statistics</h2>
              </GlassmorphicCardHeader>
              <GlassmorphicCardContent className="space-y-3">
                <div className="flex justify-between">
                  <span className="text-sm text-white/60">Ports Scanned</span>
                  <span className="font-medium text-white">{stats.portsScanned}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-sm text-white/60">Open Ports</span>
                  <span className="font-medium text-white">{stats.openPorts}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-sm text-white/60">Services Detected</span>
                  <span className="font-medium text-white">{stats.servicesDetected}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-sm text-white/60">Vulnerabilities</span>
                  <span className="font-medium text-white">{stats.vulnerabilitiesFound}</span>
                </div>
                <div className="pt-3 border-t border-white/10">
                  <div className="flex items-center gap-2 flex-wrap">
                    <Badge className="bg-white text-black font-satoshi font-bold">Critical: {stats.critical}</Badge>
                    <Badge className="bg-white text-black font-satoshi font-bold">High: {stats.high}</Badge>
                    <Badge className="bg-white text-black font-satoshi font-bold">Medium: {stats.medium}</Badge>
                    <Badge className="bg-white text-black font-satoshi font-bold">Low: {stats.low}</Badge>
                  </div>
                </div>
              </GlassmorphicCardContent>
            </GlassmorphicCard>
          </div>

          {/* Live Console & Progress */}
          <div className="lg:col-span-2 space-y-6">
            {/* Progress Card */}
            {isScanning && (
              <GlassmorphicCard>
                <GlassmorphicCardHeader>
                  <div className="flex items-center justify-between">
                    <h2 className="text-xl text-white">Scan Progress</h2>
                    {progress < 100 && <Loader2 className="h-5 w-5 animate-spin text-white" />}
                  </div>
                </GlassmorphicCardHeader>
                <GlassmorphicCardContent>
                  <div className="space-y-2">
                    <div className="flex justify-between text-sm text-white/80">
                      <span>Overall Progress</span>
                      <span>{progress}%</span>
                    </div>
                    <Progress value={progress} className="bg-white/10" />
                    <div className="text-sm text-white/60">
                      {progress < 100 ? 'Scanning in progress...' : 'Scan completed successfully'}
                    </div>
                  </div>
                </GlassmorphicCardContent>
              </GlassmorphicCard>
            )}

            {/* Live Console */}
            <GlassmorphicCard className="flex-1">
              <GlassmorphicCardHeader>
                <div className="flex items-center gap-2">
                  <Terminal className="h-5 w-5 text-white" />
                  <h2 className="text-xl text-white">Live Scan Console</h2>
                </div>
              </GlassmorphicCardHeader>
              <GlassmorphicCardContent>
                <div className="h-96 bg-black/40 backdrop-blur-sm rounded-lg p-4 font-mono text-sm overflow-auto border border-white/5">
                  {logs.map((log, index) => (
                    <div key={index} className="flex items-start gap-3 mb-2 text-gray-300">
                      <span className="text-gray-500 text-xs">{log.time}</span>
                      {getLogIcon(log.level)}
                      <span className={
                        'text-white font-satoshi font-bold'
                      }>
                        {log.message}
                      </span>
                    </div>
                  ))}
                  {isScanning && progress < 100 && (
                    <div className="flex items-center gap-2 text-white animate-pulse font-satoshi font-bold">
                      <Loader2 className="h-4 w-4 animate-spin" />
                      <span>Scanning...</span>
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
