-- PostgreSQL initialization script for SecureChain
-- This script creates the database, user, and initial schema

-- Create database (if running as postgres user)
-- CREATE DATABASE securechain;

-- Create user and grant privileges
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'securechain') THEN
        CREATE USER securechain WITH PASSWORD 'password';
    END IF;
END
$$;

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE securechain TO securechain;
GRANT ALL ON SCHEMA public TO securechain;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO securechain;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO securechain;

-- Set default privileges for future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO securechain;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO securechain;

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create custom types
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'severity_level') THEN
        CREATE TYPE severity_level AS ENUM ('Critical', 'High', 'Medium', 'Low', 'Info');
    END IF;
END
$$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'finding_status') THEN
        CREATE TYPE finding_status AS ENUM ('open', 'investigating', 'resolved', 'false_positive');
    END IF;
END
$$;

-- Create vulnerability_findings table
CREATE TABLE IF NOT EXISTS vulnerability_findings (
    finding_id VARCHAR(255) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    host VARCHAR(255) NOT NULL,
    ip INET NOT NULL,
    service VARCHAR(100),
    port INTEGER CHECK (port >= 0 AND port <= 65535),
    version TEXT,
    cve VARCHAR(20),
    cvss DECIMAL(3,1) CHECK (cvss >= 0.0 AND cvss <= 10.0),
    evidence TEXT,
    scan_tool VARCHAR(50) NOT NULL,
    
    -- OpenCTI enrichment fields
    opencti_indicator_id VARCHAR(255),
    opencti_vulnerability_id VARCHAR(255),
    opencti_malware_ids JSONB,
    opencti_attack_patterns JSONB,
    exploit_available BOOLEAN DEFAULT FALSE,
    threat_actor_groups JSONB,
    
    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    scan_timestamp TIMESTAMP WITH TIME ZONE,
    severity severity_level DEFAULT 'Medium',
    status finding_status DEFAULT 'open',
    
    -- Indexes for common queries
    CONSTRAINT valid_cve CHECK (cve IS NULL OR cve ~ '^CVE-\d{4}-\d{4,7}$')
);

-- Create scan_sessions table
CREATE TABLE IF NOT EXISTS scan_sessions (
    session_id VARCHAR(255) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    target VARCHAR(255) NOT NULL,
    scan_type VARCHAR(50) NOT NULL,
    scan_tool VARCHAR(50) NOT NULL,
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(20) DEFAULT 'running' CHECK (status IN ('running', 'completed', 'failed')),
    findings_count INTEGER DEFAULT 0,
    metadata JSONB
);

-- Create attack_paths table
CREATE TABLE IF NOT EXISTS attack_paths (
    path_id VARCHAR(255) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    source_finding_id VARCHAR(255) NOT NULL,
    target_finding_id VARCHAR(255) NOT NULL,
    attack_technique VARCHAR(20), -- MITRE ATT&CK technique ID
    path_weight DECIMAL(5,2) DEFAULT 1.0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (source_finding_id) REFERENCES vulnerability_findings(finding_id) ON DELETE CASCADE,
    FOREIGN KEY (target_finding_id) REFERENCES vulnerability_findings(finding_id) ON DELETE CASCADE
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_findings_ip ON vulnerability_findings(ip);
CREATE INDEX IF NOT EXISTS idx_findings_host ON vulnerability_findings(host);
CREATE INDEX IF NOT EXISTS idx_findings_service ON vulnerability_findings(service);
CREATE INDEX IF NOT EXISTS idx_findings_port ON vulnerability_findings(port);
CREATE INDEX IF NOT EXISTS idx_findings_cve ON vulnerability_findings(cve);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON vulnerability_findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON vulnerability_findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_scan_tool ON vulnerability_findings(scan_tool);
CREATE INDEX IF NOT EXISTS idx_findings_created_at ON vulnerability_findings(created_at);
CREATE INDEX IF NOT EXISTS idx_findings_opencti_vuln ON vulnerability_findings(opencti_vulnerability_id);

-- GIN indexes for JSONB fields
CREATE INDEX IF NOT EXISTS idx_findings_attack_patterns ON vulnerability_findings USING GIN (opencti_attack_patterns);
CREATE INDEX IF NOT EXISTS idx_findings_malware_ids ON vulnerability_findings USING GIN (opencti_malware_ids);
CREATE INDEX IF NOT EXISTS idx_findings_threat_actors ON vulnerability_findings USING GIN (threat_actor_groups);

-- Indexes for scan_sessions
CREATE INDEX IF NOT EXISTS idx_sessions_target ON scan_sessions(target);
CREATE INDEX IF NOT EXISTS idx_sessions_scan_tool ON scan_sessions(scan_tool);
CREATE INDEX IF NOT EXISTS idx_sessions_started_at ON scan_sessions(started_at);

-- Indexes for attack_paths
CREATE INDEX IF NOT EXISTS idx_paths_source ON attack_paths(source_finding_id);
CREATE INDEX IF NOT EXISTS idx_paths_target ON attack_paths(target_finding_id);
CREATE INDEX IF NOT EXISTS idx_paths_technique ON attack_paths(attack_technique);

-- Create function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create trigger for updated_at
DROP TRIGGER IF EXISTS update_vulnerability_findings_updated_at ON vulnerability_findings;
CREATE TRIGGER update_vulnerability_findings_updated_at
    BEFORE UPDATE ON vulnerability_findings
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Create views for common queries
CREATE OR REPLACE VIEW high_severity_findings AS
SELECT * FROM vulnerability_findings 
WHERE severity IN ('Critical', 'High')
ORDER BY created_at DESC;

CREATE OR REPLACE VIEW exploitable_findings AS
SELECT * FROM vulnerability_findings 
WHERE exploit_available = TRUE
ORDER BY cvss DESC NULLS LAST, created_at DESC;

CREATE OR REPLACE VIEW recent_findings AS
SELECT * FROM vulnerability_findings 
WHERE created_at >= CURRENT_TIMESTAMP - INTERVAL '7 days'
ORDER BY created_at DESC;

-- Insert sample data for testing (optional)
-- This will be populated by the application, but useful for initial testing
INSERT INTO vulnerability_findings (
    host, ip, service, port, version, evidence, scan_tool, severity
) VALUES 
    ('test.local', '192.168.1.100', 'ssh', 22, 'OpenSSH 8.9p1', 'Open SSH service detected', 'nmap', 'Medium'),
    ('web.local', '192.168.1.101', 'http', 80, 'Apache 2.4.41', 'Web server detected', 'nmap', 'Low'),
    ('db.local', '192.168.1.102', 'mysql', 3306, 'MySQL 8.0.28', 'Database server detected', 'nmap', 'High')
ON CONFLICT (finding_id) DO NOTHING;

-- Grant permissions on all created objects
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO securechain;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO securechain;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO securechain;

-- Print success message
DO $$
BEGIN
    RAISE NOTICE 'SecureChain PostgreSQL database initialized successfully!';
    RAISE NOTICE 'Database: securechain';
    RAISE NOTICE 'User: securechain';
    RAISE NOTICE 'Tables created: vulnerability_findings, scan_sessions, attack_paths';
    RAISE NOTICE 'Views created: high_severity_findings, exploitable_findings, recent_findings';
END
$$;