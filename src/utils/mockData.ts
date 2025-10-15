export interface Vulnerability {
  id: string;
  cveId: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  cvssScore: number;
  title: string;
  description: string;
  affectedComponent: string;
  exploitAvailable: boolean;
  exploitSteps?: string[];
  references: string[];
  remediation: string;
  port?: number;
  service?: string;
}

export interface Scan {
  id: string;
  target: string;
  type: 'active' | 'passive';
  tools: string[];
  status: 'running' | 'completed' | 'failed' | 'scheduled';
  progress: number;
  startTime: string;
  endTime?: string;
  vulnerabilitiesFound: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
}

export const mockScans: Scan[] = [
  {
    id: 'scan-001',
    target: 'example.com',
    type: 'active',
    tools: ['Nmap', 'OpenVAS', 'Nikto'],
    status: 'completed',
    progress: 100,
    startTime: '2025-01-10T10:00:00Z',
    endTime: '2025-01-10T10:45:00Z',
    vulnerabilitiesFound: 23,
    criticalCount: 3,
    highCount: 7,
    mediumCount: 10,
    lowCount: 3,
  },
  {
    id: 'scan-002',
    target: '192.168.1.100',
    type: 'active',
    tools: ['Nmap', 'Nuclei'],
    status: 'running',
    progress: 67,
    startTime: '2025-01-11T14:30:00Z',
    vulnerabilitiesFound: 8,
    criticalCount: 1,
    highCount: 3,
    mediumCount: 4,
    lowCount: 0,
  },
  {
    id: 'scan-003',
    target: 'testapp.io',
    type: 'passive',
    tools: ['Shodan', 'Recon'],
    status: 'scheduled',
    progress: 0,
    startTime: '2025-01-12T09:00:00Z',
    vulnerabilitiesFound: 0,
    criticalCount: 0,
    highCount: 0,
    mediumCount: 0,
    lowCount: 0,
  },
];

export const mockVulnerabilities: Vulnerability[] = [
  {
    id: 'vuln-001',
    cveId: 'CVE-2024-1234',
    severity: 'critical',
    cvssScore: 9.8,
    title: 'Remote Code Execution in Apache Web Server',
    description: 'A critical vulnerability allows remote attackers to execute arbitrary code through specially crafted HTTP requests.',
    affectedComponent: 'Apache HTTP Server 2.4.x',
    exploitAvailable: true,
    exploitSteps: [
      'Identify vulnerable Apache version',
      'Craft malicious HTTP request with payload',
      'Send request to target server',
      'Gain shell access'
    ],
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2024-1234',
      'https://www.exploit-db.com/exploits/51234'
    ],
    remediation: 'Update Apache HTTP Server to version 2.4.58 or later',
    port: 80,
    service: 'HTTP',
  },
  {
    id: 'vuln-002',
    cveId: 'CVE-2024-5678',
    severity: 'high',
    cvssScore: 8.1,
    title: 'SQL Injection in MySQL Database',
    description: 'SQL injection vulnerability in authentication module allows unauthorized database access.',
    affectedComponent: 'MySQL 8.0.x',
    exploitAvailable: true,
    exploitSteps: [
      'Identify vulnerable endpoint',
      'Test with SQL injection payloads',
      'Extract database credentials',
      'Access sensitive data'
    ],
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2024-5678'
    ],
    remediation: 'Implement parameterized queries and update MySQL to 8.0.35',
    port: 3306,
    service: 'MySQL',
  },
  {
    id: 'vuln-003',
    cveId: 'CVE-2024-9101',
    severity: 'medium',
    cvssScore: 6.5,
    title: 'Cross-Site Scripting (XSS) in Web Application',
    description: 'Reflected XSS vulnerability allows attackers to inject malicious scripts.',
    affectedComponent: 'Web Application Frontend',
    exploitAvailable: false,
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2024-9101'
    ],
    remediation: 'Implement input sanitization and Content Security Policy',
    port: 443,
    service: 'HTTPS',
  },
];

export const mockThreatIntel = [
  {
    cveId: 'CVE-2024-1234',
    publicationDate: '2024-01-15',
    exploitPublished: '2024-01-20',
    exploitCount: 3,
    activeExploits: true,
    attackPatterns: ['Remote Code Execution', 'Web Server Attack'],
    iocs: ['malicious-payload.sh', '192.168.1.50'],
  },
  {
    cveId: 'CVE-2024-5678',
    publicationDate: '2024-02-10',
    exploitPublished: '2024-02-15',
    exploitCount: 2,
    activeExploits: true,
    attackPatterns: ['SQL Injection', 'Database Compromise'],
    iocs: ['sqli-payload.txt'],
  },
];

export const mockChatHistory = [
  {
    id: 'msg-1',
    role: 'user' as const,
    content: 'What are the critical vulnerabilities found in the last scan?',
    timestamp: '2025-01-11T15:00:00Z',
  },
  {
    id: 'msg-2',
    role: 'assistant' as const,
    content: 'Based on the latest scan of example.com, 3 critical vulnerabilities were found:\n\n1. CVE-2024-1234: Remote Code Execution in Apache Web Server (CVSS 9.8)\n2. CVE-2024-3456: Authentication Bypass (CVSS 9.1)\n3. CVE-2024-7890: Privilege Escalation (CVSS 9.0)\n\nWould you like details on any specific vulnerability?',
    timestamp: '2025-01-11T15:00:05Z',
  },
];
