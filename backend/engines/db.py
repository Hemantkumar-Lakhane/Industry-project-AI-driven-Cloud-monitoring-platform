"""
SQLite Persistence Layer
Handles users, risk history, scan history, compliance history, and alerts.
"""
import sqlite3
import os
import json
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "security.db")


def get_conn():
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA busy_timeout = 5000;")
    except Exception:
        pass
    return conn


def init_db():
    conn = get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            full_name TEXT,
            created_at TEXT,
            last_login TEXT,
            is_active INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS risk_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
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
    """)
    try:
        conn.execute("ALTER TABLE risk_history ADD COLUMN incident_score REAL DEFAULT 0.0")
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
    conn = get_conn()
    rows = conn.execute(
        "SELECT timestamp, unified_score, level FROM risk_history ORDER BY timestamp DESC LIMIT ?", (periods,)
    ).fetchall()
    conn.close()
    trend = [{"period": r["timestamp"][:10], "score": r["unified_score"], "level": r["level"]} for r in reversed(rows)]
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
        (datetime.now(timezone.utc).isoformat(), alert_type, severity, message, int(email_sent), recipient)
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

def save_findings_db(findings: list):
    """Persist security findings into SQLite with deduplication."""
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
        data_source = d.get("data_source") or "SIMULATED"
        evidence_json = json.dumps(d.get("evidence") or {})
        verification_status = d.get("verification_status") or "VERIFIED"

        conn.execute("""
            INSERT INTO findings (
                finding_id, timestamp, attack_category, category_index, title, description,
                severity, confidence, detection_method, status, affected_resource,
                affected_principal, playbook_id, data_source, evidence_json, verification_status
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(finding_id) DO UPDATE SET
                status = excluded.status,
                confidence = excluded.confidence,
                verification_status = excluded.verification_status
        """, (
            finding_id, ts, attack_category, category_index, title, desc,
            severity, confidence, detection_method, status, affected_resource,
            affected_principal, playbook_id, data_source, evidence_json, verification_status
        ))
    conn.commit()
    conn.close()


def get_findings_db(limit: int = 100, severity: str = None) -> list:
    """Retrieve persisted findings ordered by timestamp descending."""
    import json
    conn = get_conn()
    if severity and severity.lower() != "all":
        rows = conn.execute(
            "SELECT * FROM findings WHERE LOWER(severity) = ? ORDER BY timestamp DESC LIMIT ?",
            (severity.lower(), limit)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM findings ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
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
    rows = conn.execute("SELECT severity, count(*) as cnt FROM findings GROUP BY severity").fetchall()
    total_row = conn.execute("SELECT count(*) as total FROM findings").fetchone()
    open_row = conn.execute("SELECT count(*) as open_cnt FROM findings WHERE status = 'open'").fetchone()
    conn.close()

    stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0, "open": 0}
    for r in rows:
        sev = (r["severity"] or "").lower()
        if sev in stats:
            stats[sev] = r["cnt"]
    stats["total"] = total_row["total"] if total_row else 0
    stats["open"] = open_row["open_cnt"] if open_row else stats["total"]
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


def clear_simulated_findings_and_incidents_db():
    """Archive active simulated findings and incidents when resetting to clean baseline."""
    conn = get_conn()
    conn.execute("UPDATE findings SET status = 'archived' WHERE data_source = 'SIMULATED' AND status = 'open'")
    conn.execute("UPDATE incidents SET status = 'archived' WHERE status = 'open' AND (incident_id LIKE 'INC-SIM-%' OR title LIKE '%Simulat%' OR lead_attack_category IN ('brute_force', 'account_takeover', 'iam_privilege_escalation', 'data_exfiltration', 'cryptomining', 'ddos', 'malware_ransomware', 'defense_tampering'))")
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

def save_incidents_db(incidents: list):
    """Persist correlated security incidents into SQLite with deduplication."""
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

        conn.execute("""
            INSERT INTO incidents (
                incident_id, title, description, severity, status, start_time, last_seen,
                duration_seconds, finding_count, finding_ids_json, principals_json,
                source_ips_json, resources_json, attack_categories_json, attack_stages_json,
                correlation_score, correlation_reasons_json, primary_playbook_id,
                lead_attack_category, entity_key, created_at, updated_at, resolved_at, resolution_notes
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
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
                resolution_notes = excluded.resolution_notes
        """, (
            inc_id, title, desc, sev, status, start_time, last_seen,
            duration, finding_count, json.dumps(finding_ids), json.dumps(principals),
            json.dumps(source_ips), json.dumps(resources), json.dumps(categories), json.dumps(stages),
            score, json.dumps(reasons), playbook_id,
            lead_cat, entity_key, created_at, updated_at, resolved_at, notes
        ))
    conn.commit()
    conn.close()


def get_incidents_db(limit: int = 100, status: str = None, severity: str = None) -> list:
    """Retrieve persisted correlated incidents ordered by last_seen descending."""
    import json
    conn = get_conn()
    clauses = []
    params = []

    if status and status.lower() != "all":
        clauses.append("LOWER(status) = ?")
        params.append(status.lower())
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


def get_incidents_stats_db() -> dict:
    """Aggregate metrics across correlated incidents."""
    conn = get_conn()
    total_row = conn.execute("SELECT count(*) as total FROM incidents").fetchone()
    open_row = conn.execute("SELECT count(*) as open_cnt FROM incidents WHERE LOWER(status) = 'open'").fetchone()
    sev_rows = conn.execute("SELECT severity, count(*) as cnt FROM incidents GROUP BY severity").fetchall()
    avg_row = conn.execute("SELECT AVG(finding_count) as avg_findings FROM incidents").fetchone()
    conn.close()

    stats = {
        "total": total_row["total"] if total_row else 0,
        "open": open_row["open_cnt"] if open_row else 0,
        "critical": 0, "high": 0, "medium": 0, "low": 0,
        "avg_findings_per_incident": round(float(avg_row["avg_findings"]), 1) if avg_row and avg_row["avg_findings"] else 1.0
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
        INSERT OR REPLACE INTO remediation_history 
        (execution_id, playbook_id, target_fid, is_dry_run, pre_remediation_state, post_remediation_state, timestamp, rolled_back, rolled_back_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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


# Initialize on import
init_db()

