-- ==============================================================================
-- RAM ANTIVIRUS - ENTERPRISE MULTI-TENANT CLOUD SECURITY DATABASE SCHEMA
-- PostgreSQL (Compatible with Supabase, Render PostgreSQL, AWS RDS, Neon)
-- ==============================================================================

-- Enable UUID extension if available
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. ORGANIZATIONS (TENANTS)
CREATE TABLE IF NOT EXISTS organizations (
    org_id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    external_id VARCHAR(64) UNIQUE NOT NULL,
    industry VARCHAR(128) DEFAULT 'Technology',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 2. USERS & RBAC
CREATE TABLE IF NOT EXISTS users (
    user_id VARCHAR(64) PRIMARY KEY,
    org_id VARCHAR(64) REFERENCES organizations(org_id) ON DELETE CASCADE,
    username VARCHAR(128) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(32) NOT NULL DEFAULT 'viewer',
    full_name VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT TRUE
);
CREATE INDEX IF NOT EXISTS idx_users_org ON users(org_id);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- 3. TENANT CLOUD CONNECTIONS (AWS CREDENTIALS & AUDIT STATUS)
CREATE TABLE IF NOT EXISTS tenant_cloud_connections (
    id SERIAL PRIMARY KEY,
    org_id VARCHAR(64) NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    provider VARCHAR(32) NOT NULL DEFAULT 'aws',
    account_id VARCHAR(32),
    auth_mode VARCHAR(64) DEFAULT 'direct_keys',
    region VARCHAR(64) DEFAULT 'ap-southeast-2',
    access_key_id VARCHAR(128),
    secret_access_key VARCHAR(255),
    role_arn VARCHAR(255),
    external_id VARCHAR(128),
    status VARCHAR(32) DEFAULT 'NOT_CONNECTED',
    latency_ms REAL DEFAULT 0.0,
    connected_at TIMESTAMPTZ,
    last_scanned_at TIMESTAMPTZ,
    CONSTRAINT uq_tenant_provider UNIQUE (org_id, provider)
);
CREATE INDEX IF NOT EXISTS idx_tenant_conn_org ON tenant_cloud_connections(org_id);

-- 4. SECURITY FINDINGS (CSPM, CIEM, ANOMALIES)
CREATE TABLE IF NOT EXISTS findings (
    finding_id VARCHAR(128) PRIMARY KEY,
    org_id VARCHAR(64) REFERENCES organizations(org_id) ON DELETE CASCADE,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    attack_category VARCHAR(128) NOT NULL,
    category_index INTEGER,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(32) NOT NULL,
    confidence REAL DEFAULT 0.9,
    detection_method VARCHAR(64) DEFAULT 'live_audit',
    status VARCHAR(32) DEFAULT 'open',
    affected_resource VARCHAR(255),
    affected_principal VARCHAR(255),
    playbook_id VARCHAR(64),
    data_source VARCHAR(64) DEFAULT 'LIVE_AWS',
    evidence_json TEXT,
    verification_status VARCHAR(32) DEFAULT 'verified'
);
CREATE INDEX IF NOT EXISTS idx_findings_org ON findings(org_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);

-- 5. CORRELATED INCIDENTS
CREATE TABLE IF NOT EXISTS incidents (
    incident_id VARCHAR(128) PRIMARY KEY,
    org_id VARCHAR(64) REFERENCES organizations(org_id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(32) NOT NULL,
    status VARCHAR(32) DEFAULT 'open',
    lead_attack_category VARCHAR(128),
    entity_key VARCHAR(255),
    finding_ids_json TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ,
    resolved_at TIMESTAMPTZ,
    resolution_notes TEXT,
    start_time TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    duration_seconds INTEGER DEFAULT 0,
    finding_count INTEGER DEFAULT 0,
    principals_json TEXT,
    source_ips_json TEXT,
    resources_json TEXT,
    attack_categories_json TEXT,
    attack_stages_json TEXT,
    correlation_score REAL DEFAULT 0.0,
    correlation_reasons_json TEXT,
    primary_playbook_id VARCHAR(64)
);
CREATE INDEX IF NOT EXISTS idx_incidents_org ON incidents(org_id);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);

-- 6. CLOUD ASSETS
CREATE TABLE IF NOT EXISTS cloud_assets (
    asset_id VARCHAR(128) PRIMARY KEY,
    org_id VARCHAR(64) REFERENCES organizations(org_id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    asset_type VARCHAR(64) NOT NULL,
    provider VARCHAR(32) NOT NULL DEFAULT 'aws',
    region VARCHAR(64) NOT NULL DEFAULT 'ap-southeast-2',
    account_id VARCHAR(32),
    status VARCHAR(32) DEFAULT 'active',
    risk_score REAL DEFAULT 0.0,
    connector_status VARCHAR(32) DEFAULT 'connected',
    tags_json TEXT,
    discovered_at TIMESTAMPTZ,
    last_scanned_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_assets_org ON cloud_assets(org_id);

-- 7. VULNERABILITIES (CVEs)
CREATE TABLE IF NOT EXISTS vulnerabilities (
    vuln_id VARCHAR(128) PRIMARY KEY,
    org_id VARCHAR(64) REFERENCES organizations(org_id) ON DELETE CASCADE,
    cve_id VARCHAR(64) NOT NULL,
    title VARCHAR(255) NOT NULL,
    package_name VARCHAR(128) NOT NULL,
    installed_version VARCHAR(64) NOT NULL,
    fixed_version VARCHAR(64) NOT NULL,
    severity VARCHAR(32) NOT NULL,
    cvss_score REAL NOT NULL,
    affected_asset_id VARCHAR(128) NOT NULL,
    status VARCHAR(32) DEFAULT 'open',
    discovered_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_vulns_org ON vulnerabilities(org_id);

-- 8. COMPOSITE RISK SCORE HISTORY
CREATE TABLE IF NOT EXISTS risk_history (
    id SERIAL PRIMARY KEY,
    org_id VARCHAR(64) REFERENCES organizations(org_id) ON DELETE CASCADE,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    unified_score REAL,
    incident_score REAL DEFAULT 0.0,
    ml_score REAL,
    cspm_score REAL,
    ciem_score REAL,
    level VARCHAR(32)
);
CREATE INDEX IF NOT EXISTS idx_risk_org ON risk_history(org_id);

-- 9. REMEDIATION PLAYBOOK EXECUTION AUDIT LOG
CREATE TABLE IF NOT EXISTS remediation_history (
    execution_id VARCHAR(64) PRIMARY KEY,
    org_id VARCHAR(64) REFERENCES organizations(org_id) ON DELETE CASCADE,
    playbook_id VARCHAR(64) NOT NULL,
    target_fid VARCHAR(128),
    is_dry_run BOOLEAN DEFAULT TRUE,
    pre_remediation_state VARCHAR(64) DEFAULT 'open',
    post_remediation_state VARCHAR(64) DEFAULT 'contained',
    timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    rolled_back BOOLEAN DEFAULT FALSE,
    rolled_back_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_remediation_org ON remediation_history(org_id);

-- 10. SYSTEM AUDIT & ALERT LOGS
CREATE TABLE IF NOT EXISTS alert_log (
    id SERIAL PRIMARY KEY,
    org_id VARCHAR(64),
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    alert_type VARCHAR(64),
    severity VARCHAR(32),
    message TEXT,
    email_sent BOOLEAN DEFAULT FALSE,
    recipient VARCHAR(255)
);

-- SEED BASELINE MASTER ACCOUNTS:
-- Master Admin (Password: admin123)
-- Demo Analyst (Password: demo123)
INSERT INTO organizations (org_id, name, external_id, industry)
VALUES 
    ('org_master_admin', 'RAM Antivirus Platform', 'RAM-MASTER-000001', 'Cybersecurity'),
    ('org_demo', 'Acme Demo Corp', 'RAM-ACMEDEMO-000002', 'Cloud Infrastructure')
ON CONFLICT (org_id) DO NOTHING;

INSERT INTO users (user_id, org_id, username, email, password_hash, role, full_name)
VALUES
    ('usr_master_admin_01', 'org_master_admin', 'admin', 'admin@ramantivirus.com', '$2b$12$4O6cO9l63O5lV0vU8pI4y.1aA31w/x9q8m.XvN6Z8PZ5aA7b9dFe6', 'admin', 'RAM Antivirus Admin'),
    ('usr_demo_analyst_01', 'org_demo', 'demo', 'demo@ramantivirus.com', '$2b$12$vybibq/62NOPennwAlR/AeAZZuPOl1HRUJnqCWSDy0eH6V94hNrTe', 'analyst', 'Demo Analyst')
ON CONFLICT (username) DO NOTHING;
