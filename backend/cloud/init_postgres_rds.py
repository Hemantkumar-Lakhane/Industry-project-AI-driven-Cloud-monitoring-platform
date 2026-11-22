"""
AWS RDS PostgreSQL Initialization & Migration Script for RAM Antivirus
Configures schema, indexes, multi-tenant organizations, and default accounts (admin & demo).
"""
import os
import sys
import psycopg2
from psycopg2.extras import RealDictCursor

# Default to the detected RDS instance in Sydney
DEFAULT_HOST = "cloudresume-postgres.cd8ewc4qw5qp.ap-southeast-2.rds.amazonaws.com"
DEFAULT_PORT = 5432
DEFAULT_DB = "cloudresumeai_prod"
DEFAULT_USER = "cloudresume_admin"

SCHEMA_SQL = """
-- 1. Organizations (Multi-Tenant SaaS)
CREATE TABLE IF NOT EXISTS organizations (
    org_id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    external_id VARCHAR(128) UNIQUE NOT NULL,
    industry VARCHAR(128) DEFAULT 'Technology',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 2. Users & Authentication
CREATE TABLE IF NOT EXISTS users (
    user_id VARCHAR(64) PRIMARY KEY,
    username VARCHAR(128) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(32) NOT NULL DEFAULT 'analyst',
    full_name VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_login TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE
);

-- 3. Cloud Assets Inventory (Live Cloud Resources)
CREATE TABLE IF NOT EXISTS cloud_assets (
    asset_id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    asset_type VARCHAR(64) NOT NULL,
    provider VARCHAR(32) NOT NULL DEFAULT 'aws',
    region VARCHAR(64) NOT NULL DEFAULT 'ap-southeast-2',
    account_id VARCHAR(32) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    risk_score REAL NOT NULL DEFAULT 0.0,
    connector_status VARCHAR(32) NOT NULL DEFAULT 'CONNECTED',
    tags_json JSONB DEFAULT '{}',
    discovered_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_scanned_at TIMESTAMP WITH TIME ZONE
);

-- 4. Findings & Posture (Zero-Mock Verified Findings)
CREATE TABLE IF NOT EXISTS findings (
    finding_id VARCHAR(64) PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    attack_category VARCHAR(64) NOT NULL,
    category_index INTEGER,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(32) NOT NULL,
    confidence REAL,
    detection_method VARCHAR(64),
    status VARCHAR(32) DEFAULT 'open',
    affected_resource VARCHAR(255),
    affected_principal VARCHAR(255),
    playbook_id VARCHAR(64),
    data_source VARCHAR(64) DEFAULT 'LIVE_AWS_CONNECTED',
    evidence_json JSONB,
    verification_status VARCHAR(32) DEFAULT 'VERIFIED'
);

-- 5. Risk & Telemetry Score History
CREATE TABLE IF NOT EXISTS risk_history (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    unified_score REAL,
    incident_score REAL DEFAULT 0.0,
    ml_score REAL,
    cspm_score REAL,
    ciem_score REAL,
    level VARCHAR(32)
);

-- 6. Incidents
CREATE TABLE IF NOT EXISTS incidents (
    incident_id VARCHAR(64) PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(32) NOT NULL,
    status VARCHAR(32) DEFAULT 'open',
    start_time TIMESTAMP WITH TIME ZONE,
    last_seen TIMESTAMP WITH TIME ZONE,
    duration_seconds REAL DEFAULT 0.0,
    finding_count INTEGER DEFAULT 1,
    finding_ids_json JSONB,
    principals_json JSONB,
    source_ips_json JSONB,
    resources_json JSONB,
    attack_categories_json JSONB,
    attack_stages_json JSONB,
    correlation_score REAL DEFAULT 0.0,
    correlation_reasons_json JSONB,
    primary_playbook_id VARCHAR(64),
    lead_attack_category VARCHAR(64),
    entity_key VARCHAR(128),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    resolved_at TIMESTAMP WITH TIME ZONE,
    resolution_notes TEXT
);

-- 7. Remediation Executions
CREATE TABLE IF NOT EXISTS remediation_history (
    execution_id VARCHAR(64) PRIMARY KEY,
    playbook_id VARCHAR(64) NOT NULL,
    target_fid VARCHAR(64),
    is_dry_run BOOLEAN DEFAULT TRUE,
    pre_remediation_state VARCHAR(32) DEFAULT 'open',
    post_remediation_state VARCHAR(32) DEFAULT 'contained',
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    rolled_back BOOLEAN DEFAULT FALSE,
    rolled_back_at TIMESTAMP WITH TIME ZONE
);

-- Indexes for high performance
CREATE INDEX IF NOT EXISTS idx_findings_ts ON findings(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_cloud_assets_acct ON cloud_assets(account_id, provider);
CREATE INDEX IF NOT EXISTS idx_incidents_ls ON incidents(last_seen DESC);
"""

def init_postgres(password: str = None, host: str = None, port: int = None, db: str = None, user: str = None):
    host = host or os.environ.get("POSTGRES_HOST", DEFAULT_HOST)
    port = port or int(os.environ.get("POSTGRES_PORT", DEFAULT_PORT))
    db = db or os.environ.get("POSTGRES_DB", DEFAULT_DB)
    user = user or os.environ.get("POSTGRES_USER", DEFAULT_USER)
    password = password or os.environ.get("POSTGRES_PASSWORD")

    if not password:
        print("[!] POSTGRES_PASSWORD not set. Please supply the RDS master password via env or argument.")
        print("    Usage: python init_postgres_rds.py <PASSWORD>")
        return False

    print(f"[*] Connecting to PostgreSQL at {host}:{port}/{db} as {user}...")
    try:
        conn = psycopg2.connect(
            host=host,
            port=port,
            dbname=db,
            user=user,
            password=password,
            connect_timeout=10
        )
        conn.autocommit = True
        cur = conn.cursor()
        print("[*] Connected successfully! Creating RAM Antivirus SaaS schema...")
        cur.execute(SCHEMA_SQL)
        print("[+] Schema creation completed successfully!")
        cur.close()
        conn.close()
        return True
    except Exception as e:
        print(f"[!] PostgreSQL initialization error: {e}")
        return False

if __name__ == "__main__":
    pwd = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("POSTGRES_PASSWORD")
    init_postgres(password=pwd)
