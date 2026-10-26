"""
SQLite Persistence Layer
Handles users, risk history, scan history, compliance history, and alerts.
"""
import sqlite3
import os
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "security.db")


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
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
    """)
    conn.commit()
    conn.close()


# ── Risk History ──────────────────────────────────────────────────────────────

def save_risk_score(unified: float, ml: float, cspm: float, ciem: float, level: str):
    conn = get_conn()
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


# Initialize on import
init_db()
