import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { Toaster } from 'sonner';

// Pages
import { LandingPage } from './pages/LandingPage';
import { DashboardPage } from './pages/DashboardPage';
import { ScanningPage } from './pages/ScanningPage';
import { VulnerabilityReportPage } from './pages/VulnerabilityReportPage';
import { AttackPathPage } from './pages/AttackPathPage';
import { ThreatIntelPage } from './pages/ThreatIntelPage';
import { ChatbotPage } from './pages/ChatbotPage';
import { SettingsPage } from './pages/SettingsPage';
import { DocsPage } from './pages/DocsPage';

export default function App() {
  return (
    <Router>
      <div className="min-h-screen bg-gray-50">
        <Routes>
          {/* Landing Page */}
          <Route path="/" element={<LandingPage />} />
          
          {/* Main Application Routes */}
          <Route path="/dashboard" element={<DashboardPage />} />
          
          {/* Scanning Routes */}
          <Route path="/scan" element={<ScanningPage />} />
          <Route path="/scan/:scanId" element={<ScanningPage />} />
          
          {/* Vulnerability Report */}
          <Route path="/report/:scanId" element={<VulnerabilityReportPage />} />
          
          {/* Attack Path Visualization */}
          <Route path="/attack-path/:scanId" element={<AttackPathPage />} />
          
          {/* Threat Intelligence */}
          <Route path="/threat-intel" element={<ThreatIntelPage />} />
          
          {/* AI Assistant / Chatbot */}
          <Route path="/assistant" element={<ChatbotPage />} />
          
          {/* Settings */}
          <Route path="/settings" element={<SettingsPage />} />
          
          {/* Documentation */}
          <Route path="/docs" element={<DocsPage />} />
          
          {/* Fallback - redirect to dashboard */}
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
        
        {/* Toast Notifications */}
        <Toaster position="top-right" />
      </div>
    </Router>
  );
}