"""
Multi-Tenant Persistence Layer (SQLite & PostgreSQL / Supabase / Render Compatible)
Handles organizations, multi-tenant users, cloud account connections, findings, and posture history.
"""
import sqlite3
import os
import json
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any

from dotenv import load_dotenv
env_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
load_dotenv(env_file)

DATABASE_URL = os.environ.get("DATABASE_URL")
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "security.db")

_PG_POOL = None


class PGCursorWrapper:
    """Wrapper around psycopg2 cursor that normalizes dict rows and rowcount."""
    def __init__(self, cur):
        self.cur = cur

    def fetchall(self):
        try:
            return [dict(r) for r in self.cur.fetchall()]
        except Exception:
            return []

    def fetchone(self):
        try:
            r = self.cur.fetchone()
            return dict(r) if r is not None else None
        except Exception:
            return None

    @property
    def rowcount(self):
        return self.cur.rowcount

    def __iter__(self):
        return iter(self.fetchall())


class PGConnWrapper:
    """Wrapper around psycopg2 connection to provide SQLite-like interface with safe auto-close."""
    def __init__(self, raw_conn, pool=None):
        self.raw_conn = raw_conn
        self.pool = pool
        self.is_pg = True
        self._closed = False

    def execute(self, sql, params=()):
        stripped = sql.strip().upper()
        if stripped.startswith("PRAGMA"):
            class DummyCursor:
                def fetchall(self): return []
                def fetchone(self): return None
                @property
                def rowcount(self): return 0
                def __iter__(self): return iter([])
            return DummyCursor()

        # Translate ? parameter placeholder to %s for PostgreSQL
        pg_sql = sql.replace("?", "%s")
        import psycopg2.extras
        cur = self.raw_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(pg_sql, params)
        return PGCursorWrapper(cur)

    def executescript(self, script):
        cur = self.raw_conn.cursor()
        cur.execute(script)

    def commit(self):
        if not self._closed and self.raw_conn and not getattr(self.raw_conn, "closed", False):
            self.raw_conn.commit()

    def close(self):
        if self._closed:
            return
        self._closed = True
        if self.pool:
            try:
                self.pool.putconn(self.raw_conn)
            except Exception:
                try:
                    self.raw_conn.close()
                except Exception:
                    pass
        else:
            try:
                self.raw_conn.close()
            except Exception:
                pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            try:
                self.raw_conn.rollback()
            except Exception:
                pass
        self.close()

    def __del__(self):
        self.close()


def get_conn():
    global _PG_POOL
    if DATABASE_URL and (DATABASE_URL.startswith("postgres://") or DATABASE_URL.startswith("postgresql://")):
        import psycopg2
        import psycopg2.extras
        import psycopg2.pool
        if _PG_POOL is None:
            try:
                _PG_POOL = psycopg2.pool.SimpleConnectionPool(minconn=1, maxconn=5, dsn=DATABASE_URL)
            except Exception:
                raw_conn = psycopg2.connect(DATABASE_URL, connect_timeout=5)
                return PGConnWrapper(raw_conn)
        try:
            raw_conn = _PG_POOL.getconn()
            if raw_conn.closed:
                try:
                    _PG_POOL.putconn(raw_conn, close=True)
                except Exception:
                    pass
                raw_conn = _PG_POOL.getconn()
            return PGConnWrapper(raw_conn, pool=_PG_POOL)
        except Exception:
            try:
                raw_conn = psycopg2.connect(DATABASE_URL, connect_timeout=5)
                return PGConnWrapper(raw_conn)
            except Exception:
                pass

    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.is_pg = False
    try:
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA busy_timeout = 5000;")
    except Exception:
        pass
    return conn


def init_db():
    conn = get_conn()
    if getattr(conn, "is_pg", False):
        # In PostgreSQL / Supabase / AWS RDS
        try:
            cur = conn.execute("SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_name='organizations';")
            if not cur.fetchone():
                schema_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "schema_postgresql.sql")
                if os.path.exists(schema_path):
                    with open(schema_path, "r", encoding="utf-8") as f:
                        conn.executescript(f.read())
                    conn.commit()

            # Ensure default organizations exist so foreign keys in users table are never violated
            now_iso = datetime.now(timezone.utc).isoformat()
            conn.execute(
                """INSERT INTO organizations (org_id, name, external_id, industry, created_at)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT (org_id) DO NOTHING""",
                ("org_master_admin", "RAM Antivirus Platform", "ext_master_admin", "Cybersecurity", now_iso)
            )
            conn.execute(
                """INSERT INTO organizations (org_id, name, external_id, industry, created_at)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT (org_id) DO NOTHING""",
                ("org_demo", "Demo Organization (Simulated Telemetry)", "ext_demo_org", "Technology", now_iso)
            )
            # Idempotent schema upgrades for Super Admin Phase 1
            for pg_stmt in [
                "ALTER TABLE organizations ADD COLUMN IF NOT EXISTS status VARCHAR(32) DEFAULT 'active';",
                "ALTER TABLE organizations ADD COLUMN IF NOT EXISTS plan VARCHAR(64) DEFAULT 'standard';",
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS tokens_revoked_at_ms BIGINT DEFAULT 0;",
                """CREATE TABLE IF NOT EXISTS platform_audit_logs (
                    log_id VARCHAR(64) PRIMARY KEY,
                    timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    actor_user_id VARCHAR(64),
                    actor_username VARCHAR(128),
                    actor_role VARCHAR(32),
                    action VARCHAR(128) NOT NULL,
                    target_type VARCHAR(64),
                    target_id VARCHAR(128),
                    details_json TEXT,
                    ip_address VARCHAR(64),
                    status VARCHAR(32) DEFAULT 'success'
                );"""
            ]:
                try:
                    conn.execute(pg_stmt)
                except Exception:
                    pass
            conn.commit()
        except Exception as e:
            print(f"[DB] PostgreSQL init notice: {e}")
        finally:
            conn.close()
        return

    conn.executescript("""
        CREATE TABLE IF NOT EXISTS organizations (
            org_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            external_id TEXT UNIQUE NOT NULL,
            industry TEXT DEFAULT 'Technology',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            org_id TEXT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            full_name TEXT,
            created_at TEXT,
            last_login TEXT,
            is_active INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS tenant_cloud_connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id TEXT NOT NULL,
            provider TEXT NOT NULL DEFAULT 'aws',
            account_id TEXT,
            auth_mode TEXT DEFAULT 'direct_keys',
            region TEXT DEFAULT 'ap-southeast-2',
            access_key_id TEXT,
            secret_access_key TEXT,
            role_arn TEXT,
            external_id TEXT,
            status TEXT DEFAULT 'CONNECTED',
            latency_ms REAL DEFAULT 0.0,
            connected_at TEXT,
            last_scanned_at TEXT,
            UNIQUE(org_id, provider)
        );

        CREATE TABLE IF NOT EXISTS risk_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id TEXT,
            timestamp TEXT NOT NULL,
            unified_score REAL,
            incident_score REAL DEFAULT 0.0,
            ml_score REAL,
            cspm_score REAL,
            ciem_score REAL,
            level TEXT
        );

        CREATE TABLE IF NOT EXISTS cspm_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT,
            timestamp TEXT,
            vulnerability_id TEXT,
            title TEXT,
            severity TEXT,
            resource TEXT,
            status TEXT
        );

        CREATE TABLE IF NOT EXISTS ciem_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT,
            timestamp TEXT,
            risk_id TEXT,
            title TEXT,
            entity_name TEXT,
            entity_type TEXT,
            risk_level TEXT
        );

        CREATE TABLE IF NOT EXISTS alert_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            alert_type TEXT,
            severity TEXT,
            message TEXT,
            email_sent INTEGER DEFAULT 0,
            recipient TEXT
        );

        CREATE TABLE IF NOT EXISTS findings (
            finding_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            attack_category TEXT NOT NULL,
            category_index INTEGER,
            title TEXT NOT NULL,
            description TEXT,
            severity TEXT NOT NULL,
            confidence REAL,
            detection_method TEXT,
            status TEXT DEFAULT 'open',
            affected_resource TEXT,
            affected_principal TEXT,
            playbook_id TEXT,
            data_source TEXT,
            evidence_json TEXT,
            verification_status TEXT DEFAULT 'VERIFIED'
        );

        CREATE TABLE IF NOT EXISTS cloud_assets (
            asset_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            asset_type TEXT NOT NULL,
            provider TEXT NOT NULL DEFAULT 'aws',
            region TEXT NOT NULL DEFAULT 'us-east-1',
            account_id TEXT NOT NULL DEFAULT '123456789012',
            status TEXT NOT NULL DEFAULT 'active',
            risk_score REAL NOT NULL DEFAULT 0.0,
            connector_status TEXT NOT NULL DEFAULT 'CONNECTED',
            tags_json TEXT,
            discovered_at TEXT NOT NULL,
            last_scanned_at TEXT
        );

        CREATE TABLE IF NOT EXISTS vulnerabilities (
            vuln_id TEXT PRIMARY KEY,
            cve_id TEXT NOT NULL,
            title TEXT NOT NULL,
            package_name TEXT NOT NULL,
            installed_version TEXT NOT NULL,
            fixed_version TEXT,
            severity TEXT NOT NULL,
            cvss_score REAL NOT NULL,
            affected_asset_id TEXT,
            status TEXT DEFAULT 'open',
            discovered_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS incidents (
            incident_id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT,
            severity TEXT NOT NULL,
            status TEXT DEFAULT 'open',
            start_time TEXT,
            last_seen TEXT,
            duration_seconds REAL DEFAULT 0.0,
            finding_count INTEGER DEFAULT 1,
            finding_ids_json TEXT,
            principals_json TEXT,
            source_ips_json TEXT,
            resources_json TEXT,
            attack_categories_json TEXT,
            attack_stages_json TEXT,
            correlation_score REAL DEFAULT 0.0,
            correlation_reasons_json TEXT,
            primary_playbook_id TEXT,
            lead_attack_category TEXT,
            entity_key TEXT,
            created_at TEXT,
            updated_at TEXT,
            resolved_at TEXT,
            resolution_notes TEXT
        );

        CREATE TABLE IF NOT EXISTS remediation_history (
            execution_id TEXT PRIMARY KEY,
            playbook_id TEXT NOT NULL,
            target_fid TEXT,
            is_dry_run INTEGER DEFAULT 1,
            pre_remediation_state TEXT DEFAULT 'open',
            post_remediation_state TEXT DEFAULT 'contained',
            timestamp TEXT NOT NULL,
            rolled_back INTEGER DEFAULT 0,
            rolled_back_at TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_findings_timestamp ON findings(timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_remediation_timestamp ON remediation_history(timestamp DESC);

        CREATE TABLE IF NOT EXISTS platform_audit_logs (
            log_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            actor_user_id TEXT,
            actor_username TEXT,
            actor_role TEXT,
            action TEXT NOT NULL,
            target_type TEXT,
            target_id TEXT,
            details_json TEXT,
            ip_address TEXT,
            status TEXT DEFAULT 'success'
        );
    """)
    for tbl, col in [
        ("organizations", "status TEXT DEFAULT 'active'"),
        ("organizations", "plan TEXT DEFAULT 'standard'"),
        ("users", "tokens_revoked_at_ms INTEGER DEFAULT 0"),
    ]:
        try:
            conn.execute(f"ALTER TABLE {tbl} ADD COLUMN {col}")
        except Exception:
            pass
    try:
        conn.execute("ALTER TABLE risk_history ADD COLUMN incident_score REAL DEFAULT 0.0")
    except Exception:
        pass
    for tbl in ["findings", "incidents", "cloud_assets", "vulnerabilities", "remediation_history", "risk_history", "cspm_history", "ciem_history"]:
        try:
            conn.execute(f"ALTER TABLE {tbl} ADD COLUMN org_id TEXT")
        except Exception:
            pass
    for col in [
        "lead_attack_category TEXT", "entity_key TEXT", "created_at TEXT",
        "updated_at TEXT", "resolved_at TEXT", "resolution_notes TEXT",
        "start_time TEXT", "last_seen TEXT", "duration_seconds REAL DEFAULT 0.0",
        "finding_count INTEGER DEFAULT 1", "principals_json TEXT", "source_ips_json TEXT",
        "resources_json TEXT", "attack_categories_json TEXT", "attack_stages_json TEXT",
        "correlation_score REAL DEFAULT 0.0", "correlation_reasons_json TEXT",
        "primary_playbook_id TEXT", "description TEXT"
    ]:
        try:
            conn.execute(f"ALTER TABLE incidents ADD COLUMN {col}")
        except Exception:
            pass
    try:
        conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_last_seen ON incidents(last_seen DESC)")
    except Exception:
        pass
    conn.commit()
    conn.close()



# ── Risk History ──────────────────────────────────────────────────────────────

def save_risk_score(unified: float, ml: float, cspm: float, ciem: float, level: str, incident: float = 0.0):
    conn = get_conn()
    try:
        conn.execute(
            "INSERT INTO risk_history (timestamp, unified_score, incident_score, ml_score, cspm_score, ciem_score, level) VALUES (?,?,?,?,?,?,?)",
            (datetime.now(timezone.utc).isoformat(), unified, incident, ml, cspm, ciem, level)
        )
    except Exception:
        conn.execute(
            "INSERT INTO risk_history (timestamp, unified_score, ml_score, cspm_score, ciem_score, level) VALUES (?,?,?,?,?,?)",
            (datetime.now(timezone.utc).isoformat(), unified, ml, cspm, ciem, level)
        )
    conn.commit()
    conn.close()


def get_risk_trend_db(periods: int = 7):
    now = datetime.now(timezone.utc)
    conn = get_conn()
    trend = []

    latest_row = conn.execute("SELECT unified_score, level FROM risk_history ORDER BY timestamp DESC LIMIT 1").fetchone()
    current_baseline = float(latest_row["unified_score"]) if latest_row else 25.0
    baseline_level = latest_row["level"] if latest_row else "low"

    for i in range(periods - 1, -1, -1):
        target_date = (now - timedelta(days=i)).strftime("%Y-%m-%d")
        ts_col = "timestamp::text" if getattr(conn, "is_pg", False) else "timestamp"
        row = conn.execute(
            f"SELECT unified_score, level FROM risk_history WHERE {ts_col} LIKE ? ORDER BY timestamp DESC LIMIT 1",
            (f"{target_date}%",)
        ).fetchone()

        if row:
            score = float(row["unified_score"])
            lvl = row["level"]
        else:
            score = current_baseline
            lvl = baseline_level

        trend.append({
            "period": target_date,
            "score": score,
            "level": lvl
        })

    conn.close()
    return trend


# ── CSPM / CIEM History ───────────────────────────────────────────────────────

def save_cspm_scan(findings: list):
    if not findings:
        return
    ts = datetime.now(timezone.utc).isoformat()
    conn = get_conn()
    for f in findings:
        conn.execute(
            "INSERT INTO cspm_history (scan_id, timestamp, vulnerability_id, title, severity, resource, status) VALUES (?,?,?,?,?,?,?)",
            (f.get("scan_id"), ts, f.get("vulnerability_id"), f.get("title"), f.get("severity"), f.get("resource"), f.get("status"))
        )
    conn.commit()
    conn.close()


def save_ciem_scan(findings: list):
    if not findings:
        return
    ts = datetime.now(timezone.utc).isoformat()
    conn = get_conn()
    for f in findings:
        conn.execute(
            "INSERT INTO ciem_history (scan_id, timestamp, risk_id, title, entity_name, entity_type, risk_level) VALUES (?,?,?,?,?,?,?)",
            (f.get("scan_id"), ts, f.get("risk_id"), f.get("title"), f.get("entity_name"), f.get("entity_type"), f.get("risk_level"))
        )
    conn.commit()
    conn.close()


def get_cspm_history(limit: int = 50):
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM cspm_history ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_ciem_history(limit: int = 50):
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM ciem_history ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ── Alert Log ─────────────────────────────────────────────────────────────────

def log_alert(alert_type: str, severity: str, message: str, email_sent: bool = False, recipient: str = ""):
    conn = get_conn()
    conn.execute(
        "INSERT INTO alert_log (timestamp, alert_type, severity, message, email_sent, recipient) VALUES (?,?,?,?,?,?)",
        (datetime.now(timezone.utc).isoformat(), alert_type, severity, message, bool(email_sent), recipient)
    )
    conn.commit()
    conn.close()


def get_alert_log(limit: int = 100):
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM alert_log ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ── Compliance Trend ──────────────────────────────────────────────────────────

def save_compliance_score(score: float):
    conn = get_conn()
    # Reuse risk_history table's timestamp for compliance — store in alert_log as type
    conn.execute(
        "INSERT INTO alert_log (timestamp, alert_type, severity, message) VALUES (?,?,?,?)",
        (datetime.now(timezone.utc).isoformat(), "compliance_score", "info", str(score))
    )
    conn.commit()
    conn.close()


def get_compliance_trend_db(current_score: float):
    conn = get_conn()
    row = conn.execute(
        "SELECT message FROM alert_log WHERE alert_type='compliance_score' ORDER BY timestamp DESC LIMIT 1 OFFSET 6"
    ).fetchone()
    conn.close()
    week_ago = float(row["message"]) if row else current_score
    return {
        "direction": "improving" if current_score >= week_ago else "declining",
        "change_7d": round(current_score - week_ago, 1)
    }


# ── Findings Persistence ──────────────────────────────────────────────────────

def save_findings_db(findings: list, org_id: str = None):
    """Persist security findings into SQLite with deduplication and tenant isolation."""
    if not findings:
        return
    import json
    conn = get_conn()
    for f in findings:
        if hasattr(f, "model_dump"):
            d = f.model_dump(mode="json")
        elif isinstance(f, dict):
            d = f
        else:
            continue

        finding_id = d.get("finding_id") or str(d.get("id"))
        ts = d.get("created_at") or d.get("timestamp") or datetime.now(timezone.utc).isoformat()
        attack_category = d.get("attack_category") or "unknown"
        category_index = d.get("category_index") or 0
        title = d.get("title") or "Security Finding"
        desc = d.get("description") or title
        severity = (d.get("severity") or "medium").lower()
        confidence = float(d.get("confidence") or 0.85)
        detection_method = d.get("detection_method") or "rule_based"
        status = d.get("status") or "open"
        affected_resource = str(d.get("affected_resource") or "")
        affected_principal = str(d.get("affected_principal") or "")
        rec_resp = d.get("recommended_response") or {}
        playbook_id = rec_resp.get("playbook_id") if isinstance(rec_resp, dict) else d.get("playbook_id")
        data_source = d.get("data_source") or "LIVE_AWS"
        evidence_json = json.dumps(d.get("evidence") or {})
        verification_status = d.get("verification_status") or "VERIFIED"
        target_org = org_id or d.get("org_id")

        conn.execute("""
            INSERT INTO findings (
                finding_id, timestamp, attack_category, category_index, title, description,
                severity, confidence, detection_method, status, affected_resource,
                affected_principal, playbook_id, data_source, evidence_json, verification_status, org_id
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(finding_id) DO UPDATE SET
                status = excluded.status,
                confidence = excluded.confidence,
                verification_status = excluded.verification_status,
                org_id = excluded.org_id
        """, (
            finding_id, ts, attack_category, category_index, title, desc,
            severity, confidence, detection_method, status, affected_resource,
            affected_principal, playbook_id, data_source, evidence_json, verification_status, target_org
        ))
    conn.commit()
    conn.close()


def get_findings_db(limit: int = 100, severity: str = None, org_id: str = None, status: str = None) -> list:
    """Retrieve persisted findings ordered by timestamp descending, strictly scoped to the tenant org_id."""
    import json
    conn = get_conn()

    clauses = []
    params = []
    if org_id:
        clauses.append("org_id = ?")
        params.append(org_id)
    if severity and severity.lower() != "all":
        clauses.append("LOWER(severity) = ?")
        params.append(severity.lower())
    if status and status.lower() != "all":
        clauses.append("LOWER(status) = ?")
        params.append(status.lower())
    elif not status:
        clauses.append("LOWER(COALESCE(status, 'open')) != 'archived'")

    where_str = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    query = f"SELECT * FROM findings {where_str} ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    rows = conn.execute(query, tuple(params)).fetchall()
    conn.close()

    results = []
    for r in rows:
        item = dict(r)
        # Parse evidence JSON back into dict
        try:
            item["evidence"] = json.loads(item.get("evidence_json") or "{}")
        except Exception:
            item["evidence"] = {}
        item["recommended_response"] = {
            "playbook_id": item.get("playbook_id") or "PB-BF-001",
            "is_dry_run_supported": True,
            "action_summary": f"Execute response playbook {item.get('playbook_id')} for {item.get('title')}"
        }
        item["created_at"] = item.get("timestamp")
        results.append(item)
    return results


def get_findings_stats_db() -> dict:
    """Get count metrics across persisted findings."""
    conn = get_conn()
    rows = conn.execute("SELECT severity, count(*) as cnt FROM findings WHERE status = 'open' GROUP BY severity").fetchall()
    total_row = conn.execute("SELECT count(*) as total FROM findings").fetchone()
    open_row = conn.execute("SELECT count(*) as open_cnt FROM findings WHERE status = 'open'").fetchone()
    resolved_row = conn.execute("SELECT count(*) as res_cnt FROM findings WHERE status = 'resolved'").fetchone()
    conn.close()

    stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0, "open": 0, "resolved": 0}
    for r in rows:
        sev = (r["severity"] or "").lower()
        if sev in stats:
            stats[sev] = r["cnt"]
    stats["total"] = total_row["total"] if total_row else 0
    stats["open"] = open_row["open_cnt"] if open_row else stats["total"]
    stats["resolved"] = resolved_row["res_cnt"] if resolved_row else 0
    return stats


def update_finding_status_db(finding_id: str, status: str) -> bool:
    """Update finding status (open, investigating, contained, resolved)."""
    conn = get_conn()
    cur = conn.execute(
        "UPDATE findings SET status = ? WHERE finding_id = ?",
        (status.lower(), finding_id)
    )
    conn.commit()
    updated = cur.rowcount > 0
    conn.close()
    return updated


def cleanup_duplicate_findings_db():
    """Purge duplicate findings and retain the newest record per category, title, and target."""
    conn = get_conn()
    conn.execute("""
        DELETE FROM findings
        WHERE rowid NOT IN (
            SELECT MAX(rowid)
            FROM findings
            GROUP BY attack_category, title, affected_resource, affected_principal
        )
    """)
    conn.commit()
    conn.close()


def clear_simulated_findings_and_incidents_db(org_id: str = None):
    """Archive active simulated findings and incidents when resetting to clean baseline."""
    conn = get_conn()
    if org_id:
        conn.execute("UPDATE findings SET status = 'archived' WHERE org_id = ? AND status = 'open'", (org_id,))
        conn.execute("UPDATE incidents SET status = 'archived' WHERE org_id = ? AND status = 'open'", (org_id,))
    else:
        conn.execute("UPDATE findings SET status = 'archived' WHERE status = 'open'")
        conn.execute("UPDATE incidents SET status = 'archived' WHERE status = 'open'")
    conn.commit()
    conn.close()


# ── Cloud Asset Persistence ───────────────────────────────────────────────────

def save_cloud_assets_db(assets: list):
    """Persist discovered cloud assets into SQLite with upsert."""
    if not assets:
        return
    import json
    conn = get_conn()
    now_str = datetime.now(timezone.utc).isoformat()
    for a in assets:
        asset_id = a.get("asset_id") or a.get("id")
        name = a.get("name") or asset_id
        asset_type = a.get("asset_type") or a.get("type") or "workload"
        provider = a.get("provider") or "aws"
        region = a.get("region") or "us-east-1"
        account_id = a.get("account_id") or "123456789012"
        status = a.get("status") or "active"
        risk_score = float(a.get("risk_score") or 0.0)
        connector_status = a.get("connector_status") or "CONNECTED"
        tags_json = json.dumps(a.get("tags") or {})
        disc_at = a.get("discovered_at") or now_str
        last_scanned = a.get("last_scanned_at") or now_str

        conn.execute("""
            INSERT INTO cloud_assets (
                asset_id, name, asset_type, provider, region, account_id,
                status, risk_score, connector_status, tags_json, discovered_at, last_scanned_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(asset_id) DO UPDATE SET
                status = excluded.status,
                risk_score = excluded.risk_score,
                connector_status = excluded.connector_status,
                tags_json = excluded.tags_json,
                last_scanned_at = excluded.last_scanned_at
        """, (
            asset_id, name, asset_type, provider, region, account_id,
            status, risk_score, connector_status, tags_json, disc_at, last_scanned
        ))
    conn.commit()
    conn.close()


def get_cloud_assets_db(limit: int = 100) -> list:
    """Retrieve inventory of cloud assets from SQLite."""
    import json
    conn = get_conn()
    rows = conn.execute("SELECT * FROM cloud_assets ORDER BY risk_score DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    results = []
    for r in rows:
        item = dict(r)
        try:
            item["tags"] = json.loads(item.get("tags_json") or "{}")
        except Exception:
            item["tags"] = {}
        results.append(item)
    return results


# ── Vulnerabilities Persistence ───────────────────────────────────────────────

def save_vulnerabilities_db(vulns: list):
    """Persist vulnerability analysis records into SQLite."""
    if not vulns:
        return
    conn = get_conn()
    now_str = datetime.now(timezone.utc).isoformat()
    for v in vulns:
        vuln_id = v.get("vuln_id") or v.get("id") or f"VULN-{v.get('cve_id')}"
        cve_id = v.get("cve_id") or "CVE-UNKNOWN"
        title = v.get("title") or cve_id
        pkg = v.get("package_name") or "unknown-package"
        inst_ver = v.get("installed_version") or "1.0.0"
        fixed_ver = v.get("fixed_version") or "Latest"
        sev = (v.get("severity") or "medium").lower()
        cvss = float(v.get("cvss_score") or 5.0)
        asset_id = v.get("affected_asset_id") or "workload-host"
        status = v.get("status") or "open"
        disc_at = v.get("discovered_at") or now_str

        conn.execute("""
            INSERT INTO vulnerabilities (
                vuln_id, cve_id, title, package_name, installed_version,
                fixed_version, severity, cvss_score, affected_asset_id, status, discovered_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(vuln_id) DO UPDATE SET
                status = excluded.status,
                cvss_score = excluded.cvss_score
        """, (
            vuln_id, cve_id, title, pkg, inst_ver,
            fixed_ver, sev, cvss, asset_id, status, disc_at
        ))
    conn.commit()
    conn.close()


def get_vulnerabilities_db(limit: int = 100) -> list:
    """Retrieve persisted vulnerability records ordered by CVSS score descending."""
    conn = get_conn()
    rows = conn.execute("SELECT * FROM vulnerabilities ORDER BY cvss_score DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ── Incidents Persistence ─────────────────────────────────────────────────────

def save_incidents_db(incidents: list, org_id: str = None):
    """Persist correlated security incidents into SQLite with deduplication and tenant isolation."""
    if not incidents:
        return
    import json
    conn = get_conn()
    now_str = datetime.now(timezone.utc).isoformat()
    for inc in incidents:
        if hasattr(inc, "model_dump"):
            d = inc.model_dump(mode="json")
        elif isinstance(inc, dict):
            d = inc
        else:
            continue

        inc_id = d.get("incident_id") or d.get("id")
        if not inc_id:
            continue
        title = d.get("title") or "Correlated Security Incident"
        desc = d.get("description") or title
        sev = (d.get("severity") or "medium").lower()
        status = (d.get("status") or "open").lower()
        start_time = str(d.get("start_time") or d.get("created_at") or now_str)
        last_seen = str(d.get("last_seen") or d.get("updated_at") or now_str)
        created_at = str(d.get("created_at") or start_time)
        updated_at = str(d.get("updated_at") or last_seen)
        resolved_at = d.get("resolved_at")
        notes = d.get("resolution_notes")

        finding_ids = d.get("finding_ids") or []
        finding_count = int(d.get("finding_count") or len(finding_ids) or 1)
        duration = float(d.get("duration_seconds") or 0.0)

        principals = d.get("principals") or []
        source_ips = d.get("source_ips") or []
        resources = d.get("resources") or []
        categories = d.get("attack_categories") or []
        stages = d.get("attack_stages") or []
        reasons = d.get("correlation_reasons") or []

        lead_cat = d.get("lead_attack_category") or (categories[0] if categories else "unknown")
        entity_key = d.get("entity_key") or (principals[0] if principals else (resources[0] if resources else "global"))
        score = float(d.get("correlation_score") or 0.85)
        playbook_id = d.get("primary_playbook_id") or "PB-BF-001"
        target_org = org_id or d.get("org_id")

        conn.execute("""
            INSERT INTO incidents (
                incident_id, title, description, severity, status, start_time, last_seen,
                duration_seconds, finding_count, finding_ids_json, principals_json,
                source_ips_json, resources_json, attack_categories_json, attack_stages_json,
                correlation_score, correlation_reasons_json, primary_playbook_id,
                lead_attack_category, entity_key, created_at, updated_at, resolved_at, resolution_notes, org_id
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(incident_id) DO UPDATE SET
                title = excluded.title,
                description = excluded.description,
                severity = excluded.severity,
                status = excluded.status,
                last_seen = excluded.last_seen,
                duration_seconds = excluded.duration_seconds,
                finding_count = excluded.finding_count,
                finding_ids_json = excluded.finding_ids_json,
                principals_json = excluded.principals_json,
                source_ips_json = excluded.source_ips_json,
                resources_json = excluded.resources_json,
                attack_categories_json = excluded.attack_categories_json,
                attack_stages_json = excluded.attack_stages_json,
                correlation_score = excluded.correlation_score,
                correlation_reasons_json = excluded.correlation_reasons_json,
                lead_attack_category = excluded.lead_attack_category,
                entity_key = excluded.entity_key,
                updated_at = excluded.updated_at,
                resolved_at = excluded.resolved_at,
                resolution_notes = excluded.resolution_notes,
                org_id = excluded.org_id
        """, (
            inc_id, title, desc, sev, status, start_time, last_seen,
            duration, finding_count, json.dumps(finding_ids), json.dumps(principals),
            json.dumps(source_ips), json.dumps(resources), json.dumps(categories), json.dumps(stages),
            score, json.dumps(reasons), playbook_id,
            lead_cat, entity_key, created_at, updated_at, resolved_at, notes, target_org
        ))
    conn.commit()
    conn.close()


def get_incidents_db(limit: int = 100, status: str = None, severity: str = None, org_id: str = None) -> list:
    """Retrieve persisted correlated incidents ordered by last_seen descending, strictly scoped to tenant."""
    import json
    conn = get_conn()
    clauses = []
    params = []

    if org_id:
        clauses.append("org_id = ?")
        params.append(org_id)
    if status and status.lower() != "all":
        clauses.append("LOWER(status) = ?")
        params.append(status.lower())
    elif not status:
        clauses.append("LOWER(COALESCE(status, 'open')) != 'archived'")
    if severity and severity.lower() != "all":
        clauses.append("LOWER(severity) = ?")
        params.append(severity.lower())

    where_str = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    query = f"SELECT * FROM incidents {where_str} ORDER BY COALESCE(last_seen, created_at) DESC LIMIT ?"
    params.append(limit)

    rows = conn.execute(query, tuple(params)).fetchall()
    conn.close()

    results = []
    for r in rows:
        item = dict(r)
        item["id"] = item.get("incident_id")
        try:
            item["finding_ids"] = json.loads(item.get("finding_ids_json") or "[]")
        except Exception:
            item["finding_ids"] = []
        try:
            item["principals"] = json.loads(item.get("principals_json") or "[]")
        except Exception:
            item["principals"] = []
        try:
            item["source_ips"] = json.loads(item.get("source_ips_json") or "[]")
        except Exception:
            item["source_ips"] = []
        try:
            item["resources"] = json.loads(item.get("resources_json") or "[]")
        except Exception:
            item["resources"] = []
        try:
            item["attack_categories"] = json.loads(item.get("attack_categories_json") or "[]")
        except Exception:
            item["attack_categories"] = []
        try:
            item["attack_stages"] = json.loads(item.get("attack_stages_json") or "[]")
        except Exception:
            item["attack_stages"] = []
        try:
            item["correlation_reasons"] = json.loads(item.get("correlation_reasons_json") or "[]")
        except Exception:
            item["correlation_reasons"] = []
        results.append(item)
    return results


def get_incident_by_id_db(incident_id: str) -> Optional[dict]:
    """Retrieve full incident details including all member findings from SQLite."""
    import json
    conn = get_conn()
    row = conn.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
    if not row:
        conn.close()
        return None

    item = dict(row)
    item["id"] = item.get("incident_id")
    for key in ["finding_ids", "principals", "source_ips", "resources", "attack_categories", "attack_stages", "correlation_reasons"]:
        try:
            item[key] = json.loads(item.get(f"{key}_json") or "[]")
        except Exception:
            item[key] = []

    # Fetch member findings
    findings = []
    if item["finding_ids"]:
        placeholders = ",".join("?" for _ in item["finding_ids"])
        f_rows = conn.execute(
            f"SELECT * FROM findings WHERE finding_id IN ({placeholders}) ORDER BY timestamp ASC",
            tuple(item["finding_ids"])
        ).fetchall()
        for fr in f_rows:
            f_item = dict(fr)
            try:
                f_item["evidence"] = json.loads(f_item.get("evidence_json") or "{}")
            except Exception:
                f_item["evidence"] = {}
            f_item["created_at"] = f_item.get("timestamp")
            findings.append(f_item)
    conn.close()
    item["findings"] = findings
    return item


def get_incidents_stats_db(org_id: str = None) -> dict:
    """Aggregate metrics across correlated incidents, strictly scoped to tenant."""
    conn = get_conn()
    where_str = "WHERE org_id = ?" if org_id else ""
    params = (org_id,) if org_id else ()

    total_row = conn.execute(f"SELECT count(*) as total FROM incidents {where_str}", params).fetchone()
    
    open_where = "WHERE LOWER(status) = 'open'" + (" AND org_id = ?" if org_id else "")
    open_row = conn.execute(f"SELECT count(*) as open_cnt FROM incidents {open_where}", params).fetchone()
    
    sev_rows = conn.execute(f"SELECT severity, count(*) as cnt FROM incidents {where_str} GROUP BY severity", params).fetchall()
    avg_row = conn.execute(f"SELECT AVG(finding_count) as avg_findings FROM incidents {where_str}", params).fetchone()
    conn.close()

    stats = {
        "total": total_row["total"] if total_row else 0,
        "open": open_row["open_cnt"] if open_row else 0,
        "critical": 0, "high": 0, "medium": 0, "low": 0,
        "avg_findings_per_incident": round(float(avg_row["avg_findings"]), 1) if avg_row and avg_row["avg_findings"] else 0.0
    }
    for r in sev_rows:
        sev = (r["severity"] or "").lower()
        if sev in stats:
            stats[sev] = r["cnt"]
    return stats


def update_incident_status_db(incident_id: str, status: str, notes: str = None) -> bool:
    """Update incident status and link to finding resolution."""
    conn = get_conn()
    now_str = datetime.now(timezone.utc).isoformat()
    cur = conn.execute("""
        UPDATE incidents
        SET status = ?, updated_at = ?, resolved_at = CASE WHEN ? = 'resolved' THEN ? ELSE resolved_at END, resolution_notes = ?
        WHERE incident_id = ?
    """, (status.lower(), now_str, status.lower(), now_str, notes, incident_id))
    conn.commit()
    updated = cur.rowcount > 0
    conn.close()
    return updated


def save_remediation_record_db(record: dict) -> bool:
    """Save an executed remediation record to SQLite for durable rollback across backend reboots."""
    if not record or not record.get("execution_id"):
        return False
    conn = get_conn()
    cur = conn.execute("""
        INSERT INTO remediation_history 
        (execution_id, playbook_id, target_fid, is_dry_run, pre_remediation_state, post_remediation_state, timestamp, rolled_back, rolled_back_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (execution_id) DO UPDATE SET
            playbook_id = EXCLUDED.playbook_id,
            target_fid = EXCLUDED.target_fid,
            is_dry_run = EXCLUDED.is_dry_run,
            pre_remediation_state = EXCLUDED.pre_remediation_state,
            post_remediation_state = EXCLUDED.post_remediation_state,
            timestamp = EXCLUDED.timestamp,
            rolled_back = EXCLUDED.rolled_back,
            rolled_back_at = EXCLUDED.rolled_back_at
    """, (
        record["execution_id"],
        record["playbook_id"],
        record.get("target_fid"),
        1 if record.get("is_dry_run", True) else 0,
        record.get("pre_remediation_state", "open"),
        record.get("post_remediation_state", "contained"),
        record.get("timestamp", datetime.now(timezone.utc).isoformat()),
        1 if record.get("rolled_back", False) else 0,
        record.get("rolled_back_at")
    ))
    conn.commit()
    success = cur.rowcount > 0
    conn.close()
    return success


def get_remediation_record_db(execution_id: str) -> Optional[dict]:
    """Retrieve an executed remediation record by execution_id from SQLite."""
    conn = get_conn()
    row = conn.execute("SELECT * FROM remediation_history WHERE execution_id = ?", (execution_id,)).fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    d["is_dry_run"] = bool(d["is_dry_run"])
    d["rolled_back"] = bool(d["rolled_back"])
    return d


def update_remediation_rollback_db(execution_id: str, rolled_back_at: str) -> bool:
    """Mark a remediation record as rolled back in SQLite."""
    conn = get_conn()
    cur = conn.execute("""
        UPDATE remediation_history 
        SET rolled_back = 1, rolled_back_at = ?
        WHERE execution_id = ?
    """, (rolled_back_at, execution_id))
    conn.commit()
    updated = cur.rowcount > 0
    conn.close()
    return updated


# ── Multi-Tenant Cloud Connections ──────────────────────────────────────────────

def save_tenant_cloud_connection(
    org_id: str,
    provider: str,
    account_id: str,
    auth_mode: str,
    region: str,
    access_key_id: Optional[str] = None,
    secret_access_key: Optional[str] = None,
    role_arn: Optional[str] = None,
    external_id: Optional[str] = None,
    status: str = "CONNECTED",
    latency_ms: float = 0.0
) -> Dict[str, Any]:
    """Save or update cloud connection credentials for an organization."""
    conn = get_conn()
    now = datetime.now(timezone.utc).isoformat()
    conn.execute("""
        INSERT INTO tenant_cloud_connections (
            org_id, provider, account_id, auth_mode, region,
            access_key_id, secret_access_key, role_arn, external_id,
            status, latency_ms, connected_at, last_scanned_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(org_id, provider) DO UPDATE SET
            account_id = excluded.account_id,
            auth_mode = excluded.auth_mode,
            region = excluded.region,
            access_key_id = excluded.access_key_id,
            secret_access_key = excluded.secret_access_key,
            role_arn = excluded.role_arn,
            external_id = excluded.external_id,
            status = excluded.status,
            latency_ms = excluded.latency_ms,
            connected_at = excluded.connected_at
    """, (
        org_id, provider, account_id, auth_mode, region,
        access_key_id, secret_access_key, role_arn, external_id,
        status, latency_ms, now, now
    ))
    conn.commit()
    conn.close()
    return {
        "org_id": org_id,
        "provider": provider,
        "account_id": account_id,
        "auth_mode": auth_mode,
        "region": region,
        "status": status,
        "latency_ms": latency_ms,
        "connected_at": now
    }


def get_tenant_cloud_connection(org_id: str, provider: str = "aws") -> Optional[Dict[str, Any]]:
    """Retrieve active cloud connection for an organization."""
    if not org_id:
        return None
    conn = get_conn()
    row = conn.execute(
        "SELECT * FROM tenant_cloud_connections WHERE org_id = ? AND provider = ?",
        (org_id, provider)
    ).fetchone()
    conn.close()
    if not row:
        return None
    return dict(row)


def delete_tenant_cloud_connection(org_id: str, provider: str = "aws") -> bool:
    """Disconnect and delete cloud connection for an organization."""
    if not org_id:
        return False
    conn = get_conn()
    cur = conn.execute(
        "DELETE FROM tenant_cloud_connections WHERE org_id = ? AND provider = ?",
        (org_id, provider)
    ).fetchone()
    conn.commit()
    deleted = cur.rowcount > 0 if cur else True
    conn.close()
    return deleted


def get_organization(org_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve organization record by org_id."""
    if not org_id:
        return None
    conn = get_conn()
    row = conn.execute("SELECT * FROM organizations WHERE org_id = ?", (org_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def list_organizations() -> List[Dict[str, Any]]:
    """List all registered organizations (RAM Antivirus Super Admin View)."""
    conn = get_conn()
    rows = conn.execute("SELECT * FROM organizations ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ── Super Admin Fleet, Organization & Audit Helpers ──────────────────────────

def log_platform_audit(
    actor_user_id: Optional[str],
    actor_username: Optional[str],
    actor_role: Optional[str],
    action: str,
    target_type: str = "platform",
    target_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    ip_address: Optional[str] = None,
    status: str = "success",
) -> str:
    """Append an immutable audit record to platform_audit_logs."""
    import json
    import uuid as _uuid
    log_id = f"AUD-{_uuid.uuid4().hex[:10].upper()}"
    now_iso = datetime.now(timezone.utc).isoformat()
    conn = get_conn()
    try:
        conn.execute(
            """INSERT INTO platform_audit_logs
               (log_id, timestamp, actor_user_id, actor_username, actor_role, action, target_type, target_id, details_json, ip_address, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                log_id,
                now_iso,
                actor_user_id,
                actor_username,
                actor_role,
                action,
                target_type,
                target_id,
                json.dumps(details or {}),
                ip_address or "internal",
                status,
            ),
        )
        conn.commit()
    except Exception as e:
        print(f"[DB] Failed to write platform audit log: {e}")
    finally:
        conn.close()
    return log_id


def get_platform_audit_logs_db(limit: int = 100, action: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieve immutable platform audit logs ordered newest first."""
    import json
    conn = get_conn()
    try:
        if action:
            rows = conn.execute(
                "SELECT * FROM platform_audit_logs WHERE action = ? ORDER BY timestamp DESC LIMIT ?",
                (action, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM platform_audit_logs ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        results = []
        for r in rows:
            d = dict(r)
            try:
                d["details"] = json.loads(d.get("details_json") or "{}")
            except Exception:
                d["details"] = {}
            results.append(d)
        return results
    finally:
        conn.close()


def get_all_organizations_db() -> List[Dict[str, Any]]:
    """List all organizations enriched with user counts, cloud connector status, and open findings/incidents."""
    conn = get_conn()
    try:
        orgs = [dict(r) for r in conn.execute("SELECT * FROM organizations ORDER BY created_at DESC").fetchall()]
        user_counts = {
            r["org_id"]: r["cnt"]
            for r in conn.execute("SELECT org_id, COUNT(*) AS cnt FROM users WHERE org_id IS NOT NULL GROUP BY org_id").fetchall()
        }
        cloud_conns = {
            r["org_id"]: dict(r)
            for r in conn.execute("SELECT org_id, provider, account_id, region, status, last_scanned_at FROM tenant_cloud_connections").fetchall()
        }
        finding_counts = {
            r["org_id"]: r["cnt"]
            for r in conn.execute("SELECT org_id, COUNT(*) AS cnt FROM findings WHERE org_id IS NOT NULL AND LOWER(COALESCE(status,'open')) = 'open' GROUP BY org_id").fetchall()
        }
        incident_counts = {
            r["org_id"]: r["cnt"]
            for r in conn.execute("SELECT org_id, COUNT(*) AS cnt FROM incidents WHERE org_id IS NOT NULL AND LOWER(COALESCE(status,'open')) = 'open' GROUP BY org_id").fetchall()
        }
        for org in orgs:
            oid = org["org_id"]
            cc = cloud_conns.get(oid)
            org["status"] = org.get("status") or "active"
            org["plan"] = org.get("plan") or ("platform" if oid == "org_master_admin" else "standard")
            org["user_count"] = int(user_counts.get(oid, 0))
            org["open_findings"] = int(finding_counts.get(oid, 0))
            org["open_incidents"] = int(incident_counts.get(oid, 0))
            org["cloud_connected"] = bool(cc and cc.get("status") == "CONNECTED")
            org["aws_account_id"] = cc.get("account_id") if cc else None
            org["aws_region"] = cc.get("region") if cc else None
        return orgs
    finally:
        conn.close()


def create_organization_db(name: str, industry: str = "Cloud Infrastructure", plan: str = "standard") -> Dict[str, Any]:
    """Create a new customer organization with unique org_id and AWS external_id."""
    import uuid as _uuid
    clean_name = name.strip()
    org_id = f"org_{_uuid.uuid4().hex[:8]}"
    slug = "".join(c for c in clean_name.upper() if c.isalnum() or c == "-")[:12] or "TENANT"
    external_id = f"RAM-{slug}-{_uuid.uuid4().hex[:6].upper()}"
    now_iso = datetime.now(timezone.utc).isoformat()
    conn = get_conn()
    try:
        conn.execute(
            """INSERT INTO organizations (org_id, name, external_id, industry, status, plan, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (org_id, clean_name, external_id, industry.strip() or "Cloud Infrastructure", "active", plan, now_iso),
        )
        conn.commit()
    finally:
        conn.close()
    return {
        "org_id": org_id,
        "name": clean_name,
        "external_id": external_id,
        "industry": industry.strip() or "Cloud Infrastructure",
        "status": "active",
        "plan": plan,
        "created_at": now_iso,
        "user_count": 0,
        "open_findings": 0,
        "open_incidents": 0,
        "cloud_connected": False,
    }


def update_organization_status_db(org_id: str, new_status: str) -> Optional[Dict[str, Any]]:
    """Update organization status ('active' or 'suspended'). Returns updated org or None if not found."""
    conn = get_conn()
    try:
        row = conn.execute("SELECT * FROM organizations WHERE org_id = ?", (org_id,)).fetchone()
        if not row:
            return None
        conn.execute("UPDATE organizations SET status = ? WHERE org_id = ?", (new_status, org_id))
        conn.commit()
        updated = conn.execute("SELECT * FROM organizations WHERE org_id = ?", (org_id,)).fetchone()
        return dict(updated) if updated else None
    finally:
        conn.close()


def get_fleet_overview_db() -> Dict[str, Any]:
    """Compute cross-tenant fleet-wide telemetry and platform infrastructure health."""
    conn = get_conn()
    try:
        orgs = [dict(r) for r in conn.execute("SELECT org_id, status FROM organizations").fetchall()]
        total_orgs = len(orgs)
        active_orgs = sum(1 for o in orgs if (o.get("status") or "active").lower() == "active")
        suspended_orgs = sum(1 for o in orgs if (o.get("status") or "active").lower() == "suspended")

        users_row = conn.execute("SELECT COUNT(*) AS total, SUM(CASE WHEN is_active THEN 1 ELSE 0 END) AS active_cnt FROM users").fetchone()
        total_users = int(dict(users_row)["total"] or 0) if users_row else 0
        active_users = int(dict(users_row)["active_cnt"] or 0) if users_row else 0

        cloud_row = conn.execute("SELECT COUNT(*) AS cnt FROM tenant_cloud_connections WHERE status = 'CONNECTED'").fetchone()
        connected_clouds = int(dict(cloud_row)["cnt"] or 0) if cloud_row else 0

        findings_row = conn.execute("SELECT COUNT(*) AS cnt FROM findings WHERE LOWER(COALESCE(status,'open')) = 'open'").fetchone()
        open_findings = int(dict(findings_row)["cnt"] or 0) if findings_row else 0

        incidents_row = conn.execute("SELECT COUNT(*) AS cnt FROM incidents WHERE LOWER(COALESCE(status,'open')) = 'open'").fetchone()
        open_incidents = int(dict(incidents_row)["cnt"] or 0) if incidents_row else 0

        audit_row = conn.execute("SELECT COUNT(*) AS cnt FROM platform_audit_logs").fetchone()
        audit_events = int(dict(audit_row)["cnt"] or 0) if audit_row else 0

        is_pg = getattr(conn, "is_pg", False)
        return {
            "fleet": {
                "total_organizations": total_orgs,
                "active_organizations": active_orgs,
                "suspended_organizations": suspended_orgs,
                "total_users": total_users,
                "active_users": active_users,
                "connected_cloud_accounts": connected_clouds,
            },
            "threats": {
                "open_findings_across_fleet": open_findings,
                "open_incidents_across_fleet": open_incidents,
            },
            "infrastructure": {
                "database_engine": "PostgreSQL" if is_pg else "SQLite",
                "database_status": "healthy",
                "audit_ledger_events": audit_events,
                "api_status": "operational",
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    finally:
        conn.close()


def revoke_user_sessions_db(user_id: str) -> Optional[int]:
    """Set tokens_revoked_at_ms to current UTC epoch milliseconds for a user. Returns epoch ms or None if user missing."""
    conn = get_conn()
    try:
        row = conn.execute("SELECT user_id FROM users WHERE user_id = ?", (user_id,)).fetchone()
        if not row:
            return None
        revoked_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        conn.execute("UPDATE users SET tokens_revoked_at_ms = ? WHERE user_id = ?", (revoked_ms, user_id))
        conn.commit()
        return revoked_ms
    finally:
        conn.close()


def get_user_tokens_revoked_at_ms(user_id: str) -> int:
    """Return tokens_revoked_at_ms for user_id, or 0 if unset."""
    if not user_id:
        return 0
    conn = get_conn()
    try:
        row = conn.execute("SELECT tokens_revoked_at_ms FROM users WHERE user_id = ?", (user_id,)).fetchone()
        if not row:
            return 0
        return int(dict(row).get("tokens_revoked_at_ms") or 0)
    except Exception:
        return 0
    finally:
        conn.close()


# Migration to ensure org_id column on users table
try:
    _c = get_conn()
    if not getattr(_c, "is_pg", False):
        _cols = [c[1] for c in _c.execute("PRAGMA table_info(users)").fetchall()]
        if "org_id" not in _cols:
            _c.execute("ALTER TABLE users ADD COLUMN org_id TEXT")
            _c.commit()
    _c.close()
except Exception:
    pass

# Initialize on import
init_db()

