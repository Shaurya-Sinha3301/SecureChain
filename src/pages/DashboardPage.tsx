import { Link } from "react-router-dom";
import { useState } from "react";
import {
  ScanSearch,
  Calendar,
  Clock,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Filter,
  Download,
} from "lucide-react";
import { GlassmorphicNav } from "../components/GlassmorphicNav";
import {
  GlassmorphicCard,
  GlassmorphicCardHeader,
  GlassmorphicCardContent,
} from "../components/GlassmorphicCard";
import { Badge } from "../components/ui/badge";
import { Progress } from "../components/ui/progress";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "../components/ui/select";
import { mockScans } from "../utils/mockData";
import { motion } from "motion/react";
import PrismaticBurst from "../components/PrismaticBurst";

export function DashboardPage() {
  const [filterStatus, setFilterStatus] = useState<string>("all");
  const [filterType, setFilterType] = useState<string>("all");

  const filteredScans = mockScans.filter((scan) => {
    if (filterStatus !== "all" && scan.status !== filterStatus) return false;
    if (filterType !== "all" && scan.type !== filterType) return false;
    return true;
  });

  const totalScans = mockScans.length;
  const runningScans = mockScans.filter((s) => s.status === "running").length;
  const completedScans = mockScans.filter(
    (s) => s.status === "completed"
  ).length;
  const totalVulns = mockScans.reduce(
    (sum, s) => sum + s.vulnerabilitiesFound,
    0
  );
  const criticalVulns = mockScans.reduce((sum, s) => sum + s.criticalCount, 0);

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "completed":
        return <CheckCircle className="h-4 w-4 text-gray-400" />;
      case "running":
        return <Clock className="h-4 w-4 text-white animate-spin" />;
      case "failed":
        return <XCircle className="h-4 w-4 text-white" />;
      case "scheduled":
        return <Calendar className="h-4 w-4 text-white" />;
      default:
        return null;
    }
  };

  const getSeverityBadge = (severity: string, count: number) => {
    return (
      <Badge className="bg-white text-black font-satoshi font-bold">
        {count}
      </Badge>
    );
  };

  return (
    <div className="min-h-screen relative bg-black">
      <PrismaticBurst
        intensity={1.8}
        speed={0.4}
        animationType="rotate3d"
        colors={["#FFFFFF", "#D1D5DB", "#9CA3AF", "#6B7280", "#374151"]}
        distort={3}
        mixBlendMode="screen"
      />
      <div className="relative z-10">
        <GlassmorphicNav />

        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          {/* Header */}
          <motion.div
            className="mb-8"
            initial={{ y: 20, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            transition={{ duration: 0.6 }}
          >
            <h1 className="text-3xl mb-2 text-white">Security Dashboard</h1>
            <p className="text-white/60">
              Monitor and manage your security scans
            </p>
          </motion.div>

          {/* Stats Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4 mb-8">
            <GlassmorphicCard>
              <GlassmorphicCardContent className="pt-6">
                <div className="text-2xl mb-1 text-white">{totalScans}</div>
                <div className="text-sm text-white/60">Total Scans</div>
              </GlassmorphicCardContent>
            </GlassmorphicCard>
            <GlassmorphicCard>
              <GlassmorphicCardContent className="pt-6">
                <div className="text-2xl mb-1 text-white font-satoshi font-bold">
                  {runningScans}
                </div>
                <div className="text-sm text-white/60">Running</div>
              </GlassmorphicCardContent>
            </GlassmorphicCard>
            <GlassmorphicCard>
              <GlassmorphicCardContent className="pt-6">
                <div className="text-2xl mb-1 text-gray-400">
                  {completedScans}
                </div>
                <div className="text-sm text-white/60">Completed</div>
              </GlassmorphicCardContent>
            </GlassmorphicCard>
            <GlassmorphicCard>
              <GlassmorphicCardContent className="pt-6">
                <div className="text-2xl mb-1 text-white">{totalVulns}</div>
                <div className="text-sm text-white/60">
                  Total Vulnerabilities
                </div>
              </GlassmorphicCardContent>
            </GlassmorphicCard>
            <GlassmorphicCard>
              <GlassmorphicCardContent className="pt-6">
                <div className="text-2xl mb-1 text-white font-satoshi font-bold">
                  {criticalVulns}
                </div>
                <div className="text-sm text-white/60">Critical Issues</div>
              </GlassmorphicCardContent>
            </GlassmorphicCard>
          </div>

          {/* Actions */}
          <div className="flex gap-4 mb-6">
            <Link to="/scan">
              <motion.button
                className="px-6 py-3 bg-white/20 backdrop-blur-xl rounded-full border border-white/30 text-white hover:bg-white/30 transition-all shadow-lg flex items-center gap-2"
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
              >
                <ScanSearch className="h-4 w-4" />
                New Active Scan
              </motion.button>
            </Link>
            <Link to="/scan?type=passive">
              <motion.button
                className="px-6 py-3 bg-white/5 backdrop-blur-xl rounded-full border border-white/10 text-white hover:bg-white/10 transition-all shadow-lg flex items-center gap-2"
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
              >
                <ScanSearch className="h-4 w-4" />
                New Passive Scan
              </motion.button>
            </Link>
            <motion.button
              className="px-6 py-3 bg-white/5 backdrop-blur-xl rounded-full border border-white/10 text-white hover:bg-white/10 transition-all shadow-lg flex items-center gap-2"
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
            >
              <Calendar className="h-4 w-4" />
              Schedule Scan
            </motion.button>
          </div>

          {/* Filters */}
          <GlassmorphicCard className="mb-6">
            <GlassmorphicCardContent className="pt-6">
              <div className="flex items-center gap-4">
                <Filter className="h-4 w-4 text-white/60" />
                <Select value={filterStatus} onValueChange={setFilterStatus}>
                  <SelectTrigger className="w-40 bg-white/5 border-white/10 text-white">
                    <SelectValue placeholder="Status" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Status</SelectItem>
                    <SelectItem value="running">Running</SelectItem>
                    <SelectItem value="completed">Completed</SelectItem>
                    <SelectItem value="scheduled">Scheduled</SelectItem>
                    <SelectItem value="failed">Failed</SelectItem>
                  </SelectContent>
                </Select>

                <Select value={filterType} onValueChange={setFilterType}>
                  <SelectTrigger className="w-40 bg-white/5 border-white/10 text-white">
                    <SelectValue placeholder="Type" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Types</SelectItem>
                    <SelectItem value="active">Active</SelectItem>
                    <SelectItem value="passive">Passive</SelectItem>
                  </SelectContent>
                </Select>

                <div className="ml-auto">
                  <motion.button
                    className="px-4 py-2 bg-white/5 backdrop-blur-xl rounded-full border border-white/10 text-white hover:bg-white/10 transition-all shadow-lg flex items-center gap-2 text-sm"
                    whileHover={{ scale: 1.05 }}
                    whileTap={{ scale: 0.95 }}
                  >
                    <Download className="h-4 w-4" />
                    Export All
                  </motion.button>
                </div>
              </div>
            </GlassmorphicCardContent>
          </GlassmorphicCard>

          {/* Scans List */}
          <div className="space-y-4">
            {filteredScans.map((scan) => (
              <GlassmorphicCard key={scan.id}>
                <GlassmorphicCardHeader>
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        {getStatusIcon(scan.status)}
                        <h3 className="text-lg text-white">{scan.target}</h3>
                        <Badge
                          variant="outline"
                          className="border-white/20 text-white"
                        >
                          {scan.type}
                        </Badge>
                        <Badge
                          variant={
                            scan.status === "completed"
                              ? "default"
                              : "secondary"
                          }
                        >
                          {scan.status}
                        </Badge>
                      </div>
                      <div className="flex items-center gap-4 text-sm text-white/60">
                        <span>Tools: {scan.tools.join(", ")}</span>
                        <span>•</span>
                        <span>
                          Started: {new Date(scan.startTime).toLocaleString()}
                        </span>
                        {scan.endTime && (
                          <>
                            <span>•</span>
                            <span>
                              Completed:{" "}
                              {new Date(scan.endTime).toLocaleString()}
                            </span>
                          </>
                        )}
                      </div>
                    </div>
                  </div>
                </GlassmorphicCardHeader>
                <GlassmorphicCardContent>
                  {scan.status === "running" && (
                    <div className="mb-4">
                      <div className="flex justify-between text-sm mb-2 text-white/80">
                        <span>Progress</span>
                        <span>{scan.progress}%</span>
                      </div>
                      <Progress value={scan.progress} className="bg-white/10" />
                    </div>
                  )}

                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4">
                      <div className="flex items-center gap-2">
                        <AlertTriangle className="h-4 w-4 text-white/60" />
                        <span className="text-sm text-white/80">
                          {scan.vulnerabilitiesFound} vulnerabilities
                        </span>
                      </div>
                      <div className="flex items-center gap-2">
                        {getSeverityBadge("critical", scan.criticalCount)}
                        {getSeverityBadge("high", scan.highCount)}
                        {getSeverityBadge("medium", scan.mediumCount)}
                        {getSeverityBadge("low", scan.lowCount)}
                      </div>
                    </div>

                    <div className="flex gap-2">
                      {scan.status === "completed" && (
                        <>
                          <Link to={`/report/${scan.id}`}>
                            <motion.button
                              className="px-4 py-2 bg-white/5 backdrop-blur-xl rounded-full border border-white/10 text-white hover:bg-white/10 transition-all text-sm"
                              whileHover={{ scale: 1.05 }}
                              whileTap={{ scale: 0.95 }}
                            >
                              View Report
                            </motion.button>
                          </Link>
                          <Link to={`/attack-path/${scan.id}`}>
                            <motion.button
                              className="px-4 py-2 bg-white/5 backdrop-blur-xl rounded-full border border-white/10 text-white hover:bg-white/10 transition-all text-sm"
                              whileHover={{ scale: 1.05 }}
                              whileTap={{ scale: 0.95 }}
                            >
                              Attack Paths
                            </motion.button>
                          </Link>
                        </>
                      )}
                      {scan.status === "running" && (
                        <>
                          <Link to={`/scan/${scan.id}`}>
                            <motion.button
                              className="px-4 py-2 bg-white/20 backdrop-blur-xl rounded-full border border-white/30 text-white hover:bg-white/30 transition-all text-sm"
                              whileHover={{ scale: 1.05 }}
                              whileTap={{ scale: 0.95 }}
                            >
                              View Progress
                            </motion.button>
                          </Link>
                          <motion.button
                            className="px-4 py-2 bg-white/5 backdrop-blur-xl rounded-full border border-white/10 text-white hover:bg-white/10 transition-all text-sm"
                            whileHover={{ scale: 1.05 }}
                            whileTap={{ scale: 0.95 }}
                          >
                            Stop
                          </motion.button>
                        </>
                      )}
                      {scan.status === "scheduled" && (
                        <motion.button
                          className="px-4 py-2 bg-white/5 backdrop-blur-xl rounded-full border border-white/10 text-white hover:bg-white/10 transition-all text-sm"
                          whileHover={{ scale: 1.05 }}
                          whileTap={{ scale: 0.95 }}
                        >
                          Edit Schedule
                        </motion.button>
                      )}
                    </div>
                  </div>
                </GlassmorphicCardContent>
              </GlassmorphicCard>
            ))}
          </div>

          {filteredScans.length === 0 && (
            <GlassmorphicCard>
              <GlassmorphicCardContent className="py-12 text-center">
                <ScanSearch className="h-12 w-12 text-white/40 mx-auto mb-4" />
                <p className="text-white/60">
                  No scans found with current filters
                </p>
              </GlassmorphicCardContent>
            </GlassmorphicCard>
          )}
        </div>
      </div>
    </div>
  );
}
