import { useState, useEffect, useRef } from 'react';
import { useParams, Link } from 'react-router-dom';
import { GitBranch, ZoomIn, ZoomOut, FileText } from 'lucide-react';
import { GlassmorphicLayout } from '../components/GlassmorphicLayout';
import { GlassmorphicNav } from '../components/GlassmorphicNav';
import { GlassmorphicCard, GlassmorphicCardHeader, GlassmorphicCardContent } from '../components/GlassmorphicCard';
import { Badge } from '../components/ui/badge';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select';
import { Switch } from '../components/ui/switch';
import { Label } from '../components/ui/label';
import { motion } from 'motion/react';

interface Node {
  id: string;
  label: string;
  severity: string;
  cveId: string;
  type: 'entry' | 'vulnerability' | 'asset' | 'impact';
  cvssScore?: number;
  description: string;
}

interface Edge {
  from: string;
  to: string;
  label: string;
}

export function AttackPathPage() {
  const { scanId } = useParams();
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [severityFilter, setSeverityFilter] = useState('all');
  const [simulationMode, setSimulationMode] = useState(false);
  const [selectedNode, setSelectedNode] = useState<Node | null>(null);
  const [zoom, setZoom] = useState(1);

  const nodes: Node[] = [
    { id: 'entry', label: 'Internet', type: 'entry', severity: 'info', cveId: '', description: 'External entry point' },
    { id: 'web', label: 'Web Server\nPort 80/443', type: 'asset', severity: 'info', cveId: '', description: 'Apache HTTP Server' },
    { id: 'vuln1', label: 'CVE-2024-1234', type: 'vulnerability', severity: 'critical', cveId: 'CVE-2024-1234', cvssScore: 9.8, description: 'Remote Code Execution' },
    { id: 'vuln2', label: 'CVE-2024-5678', type: 'vulnerability', severity: 'high', cveId: 'CVE-2024-5678', cvssScore: 8.1, description: 'SQL Injection' },
    { id: 'db', label: 'Database\nPort 3306', type: 'asset', severity: 'info', cveId: '', description: 'MySQL Database' },
    { id: 'vuln3', label: 'CVE-2024-9101', type: 'vulnerability', severity: 'medium', cveId: 'CVE-2024-9101', cvssScore: 6.5, description: 'XSS Vulnerability' },
    { id: 'internal', label: 'Internal Network', type: 'asset', severity: 'info', cveId: '', description: 'Internal systems' },
    { id: 'impact', label: 'Data Breach', type: 'impact', severity: 'critical', cveId: '', description: 'Potential data exfiltration' },
  ];

  const edges: Edge[] = [
    { from: 'entry', to: 'web', label: 'HTTP Request' },
    { from: 'web', to: 'vuln1', label: 'Exploit RCE' },
    { from: 'web', to: 'vuln3', label: 'Inject XSS' },
    { from: 'vuln1', to: 'internal', label: 'Shell Access' },
    { from: 'web', to: 'db', label: 'DB Connection' },
    { from: 'db', to: 'vuln2', label: 'Exploit SQLi' },
    { from: 'vuln2', to: 'impact', label: 'Extract Data' },
    { from: 'internal', to: 'impact', label: 'Lateral Movement' },
  ];

  useEffect(() => {
    drawGraph();
  }, [zoom, severityFilter, simulationMode]);

  const drawGraph = () => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    canvas.width = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    const nodePositions: Record<string, { x: number; y: number }> = {};
    const layers = [
      ['entry'],
      ['web'],
      ['vuln1', 'vuln3'],
      ['db', 'internal'],
      ['vuln2'],
      ['impact'],
    ];

    layers.forEach((layer, layerIdx) => {
      const y = 100 + layerIdx * 120;
      const layerWidth = canvas.width - 200;
      const spacing = layerWidth / (layer.length + 1);
      
      layer.forEach((nodeId, idx) => {
        nodePositions[nodeId] = {
          x: 100 + spacing * (idx + 1),
          y: y * zoom,
        };
      });
    });

    // Draw edges
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.2)';
    ctx.lineWidth = 2;
    edges.forEach(edge => {
      const from = nodePositions[edge.from];
      const to = nodePositions[edge.to];
      if (!from || !to) return;

      ctx.beginPath();
      ctx.moveTo(from.x, from.y);
      ctx.lineTo(to.x, to.y);
      ctx.stroke();

      const angle = Math.atan2(to.y - from.y, to.x - from.x);
      const arrowSize = 10;
      ctx.beginPath();
      ctx.moveTo(to.x, to.y);
      ctx.lineTo(
        to.x - arrowSize * Math.cos(angle - Math.PI / 6),
        to.y - arrowSize * Math.sin(angle - Math.PI / 6)
      );
      ctx.lineTo(
        to.x - arrowSize * Math.cos(angle + Math.PI / 6),
        to.y - arrowSize * Math.sin(angle + Math.PI / 6)
      );
      ctx.closePath();
      ctx.fillStyle = 'rgba(255, 255, 255, 0.2)';
      ctx.fill();
    });

    // Draw nodes
    nodes.forEach(node => {
      if (severityFilter !== 'all' && node.severity !== severityFilter && node.type === 'vulnerability') {
        return;
      }

      const pos = nodePositions[node.id];
      if (!pos) return;

      let fillColor = '#3b82f6';
      if (node.type === 'vulnerability') {
        if (node.severity === 'critical') fillColor = '#dc2626';
        else if (node.severity === 'high') fillColor = '#ea580c';
        else if (node.severity === 'medium') fillColor = '#ca8a04';
        else fillColor = '#2563eb';
      } else if (node.type === 'entry') {
        fillColor = '#64748b';
      } else if (node.type === 'impact') {
        fillColor = '#dc2626';
      }

      ctx.beginPath();
      ctx.arc(pos.x, pos.y, 30, 0, 2 * Math.PI);
      ctx.fillStyle = fillColor;
      ctx.fill();
      ctx.strokeStyle = '#ffffff';
      ctx.lineWidth = 3;
      ctx.stroke();

      if (simulationMode) {
        ctx.shadowColor = fillColor;
        ctx.shadowBlur = 20;
      }

      ctx.fillStyle = '#ffffff';
      ctx.font = '12px sans-serif';
      ctx.textAlign = 'center';
      const lines = node.label.split('\n');
      lines.forEach((line, idx) => {
        ctx.fillText(line, pos.x, pos.y + 50 + idx * 15);
      });
    });
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
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl mb-2 text-white">Attack Path Visualization</h1>
              <p className="text-white/60">Scan ID: {scanId} • Interactive exploit chain analysis</p>
            </div>
            <Link to={`/report/${scanId}`}>
              <motion.button 
                className="px-4 py-2 bg-white/5 backdrop-blur-xl rounded-full border border-white/10 text-white hover:bg-white/10 transition-all shadow-lg flex items-center gap-2"
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
              >
                <FileText className="h-4 w-4" />
                View Full Report
              </motion.button>
            </Link>
          </div>
        </motion.div>

        <div className="grid lg:grid-cols-4 gap-6">
          {/* Controls Panel */}
          <div className="lg:col-span-1 space-y-4">
            <GlassmorphicCard>
              <GlassmorphicCardHeader>
                <h2 className="text-xl text-white">Controls</h2>
              </GlassmorphicCardHeader>
              <GlassmorphicCardContent className="space-y-4">
                <div>
                  <Label className="text-white/80">Severity Filter</Label>
                  <Select value={severityFilter} onValueChange={setSeverityFilter}>
                    <SelectTrigger className="bg-white/5 border-white/10 text-white">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All Severities</SelectItem>
                      <SelectItem value="critical">Critical</SelectItem>
                      <SelectItem value="high">High</SelectItem>
                      <SelectItem value="medium">Medium</SelectItem>
                      <SelectItem value="low">Low</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="flex items-center justify-between">
                  <Label htmlFor="simulation" className="text-white/80">Simulation Mode</Label>
                  <Switch
                    id="simulation"
                    checked={simulationMode}
                    onCheckedChange={setSimulationMode}
                  />
                </div>

                <div className="pt-4 border-t border-white/10">
                  <Label className="mb-2 block text-white/80">Zoom</Label>
                  <div className="flex items-center gap-2">
                    <motion.button
                      className="px-3 py-2 bg-white/5 backdrop-blur-xl rounded-full border border-white/10 text-white hover:bg-white/10 transition-all"
                      onClick={() => setZoom(Math.max(0.5, zoom - 0.1))}
                      whileHover={{ scale: 1.05 }}
                      whileTap={{ scale: 0.95 }}
                    >
                      <ZoomOut className="h-4 w-4" />
                    </motion.button>
                    <span className="text-sm flex-1 text-center text-white">{Math.round(zoom * 100)}%</span>
                    <motion.button
                      className="px-3 py-2 bg-white/5 backdrop-blur-xl rounded-full border border-white/10 text-white hover:bg-white/10 transition-all"
                      onClick={() => setZoom(Math.min(2, zoom + 0.1))}
                      whileHover={{ scale: 1.05 }}
                      whileTap={{ scale: 0.95 }}
                    >
                      <ZoomIn className="h-4 w-4" />
                    </motion.button>
                  </div>
                </div>
              </GlassmorphicCardContent>
            </GlassmorphicCard>

            <GlassmorphicCard>
              <GlassmorphicCardHeader>
                <h2 className="text-xl text-white">Legend</h2>
              </GlassmorphicCardHeader>
              <GlassmorphicCardContent className="space-y-2">
                <div className="flex items-center gap-2">
                  <div className="w-4 h-4 rounded-full bg-red-600"></div>
                  <span className="text-sm text-white/80">Critical Vulnerability</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-4 h-4 rounded-full bg-orange-600"></div>
                  <span className="text-sm text-white/80">High Vulnerability</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-4 h-4 rounded-full bg-yellow-600"></div>
                  <span className="text-sm text-white/80">Medium Vulnerability</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-4 h-4 rounded-full bg-blue-600"></div>
                  <span className="text-sm text-white/80">Asset/System</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-4 h-4 rounded-full bg-gray-600"></div>
                  <span className="text-sm text-white/80">Entry Point</span>
                </div>
              </GlassmorphicCardContent>
            </GlassmorphicCard>

            {selectedNode && (
              <GlassmorphicCard>
                <GlassmorphicCardHeader>
                  <h2 className="text-xl text-white">Selected Node</h2>
                </GlassmorphicCardHeader>
                <GlassmorphicCardContent className="space-y-2">
                  <div>
                    <div className="text-sm text-white/60">Node Type</div>
                    <div className="text-white capitalize">{selectedNode.type}</div>
                  </div>
                  {selectedNode.cveId && (
                    <div>
                      <div className="text-sm text-white/60">CVE ID</div>
                      <Badge className="bg-white/10 text-white border-white/20">{selectedNode.cveId}</Badge>
                    </div>
                  )}
                  {selectedNode.cvssScore && (
                    <div>
                      <div className="text-sm text-white/60">CVSS Score</div>
                      <div className="text-white">{selectedNode.cvssScore}</div>
                    </div>
                  )}
                  <div>
                    <div className="text-sm text-white/60">Description</div>
                    <div className="text-sm text-white/80">{selectedNode.description}</div>
                  </div>
                </GlassmorphicCardContent>
              </GlassmorphicCard>
            )}
          </div>

          {/* Graph Visualization */}
          <div className="lg:col-span-3">
            <GlassmorphicCard className="h-[800px]">
              <GlassmorphicCardHeader>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <GitBranch className="h-5 w-5 text-white" />
                    <h2 className="text-xl text-white">Attack Chain Graph</h2>
                  </div>
                </div>
              </GlassmorphicCardHeader>
              <GlassmorphicCardContent className="h-full p-0">
                <canvas
                  ref={canvasRef}
                  onClick={(e) => {
                    const clickedNode = nodes[Math.floor(Math.random() * nodes.length)];
                    setSelectedNode(clickedNode);
                  }}
                  className="w-full h-full cursor-pointer rounded-b-3xl"
                  style={{ height: 'calc(100% - 80px)' }}
                />
              </GlassmorphicCardContent>
            </GlassmorphicCard>
          </div>
        </div>
      </div>
    </GlassmorphicLayout>
  );
}
