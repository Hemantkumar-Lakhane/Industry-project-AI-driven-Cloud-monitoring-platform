"""
Wazuh Log File Reader
Reads real Wazuh alert logs from disk (JSON format).
Falls back to simulator if log file not found.

Wazuh default alert log path:
  Linux:   /var/ossec/logs/alerts/alerts.json
  Windows: C:\\Program Files (x86)\\ossec-agent\\logs\\alerts.json

Set env var WAZUH_LOG_PATH to override.
"""
import os
import json
import uuid
from datetime import datetime, timezone
from typing import List, Dict

def get_wazuh_log_path() -> str:
    env_path = os.environ.get("WAZUH_LOG_PATH")
    if env_path:
        env_path = env_path.strip()
        if os.path.exists(env_path):
            return env_path

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates = [
        os.path.join(base_dir, "data", "alerts.json"),
        os.path.join(os.getcwd(), "backend", "data", "alerts.json"),
        os.path.join(os.getcwd(), "data", "alerts.json"),
        "/var/ossec/logs/alerts/alerts.json",
        r"C:\Program Files (x86)\ossec-agent\logs\alerts.json"
    ]
    if env_path:
        candidates.insert(0, os.path.join(base_dir, env_path))
        candidates.insert(0, os.path.join(os.getcwd(), env_path))

    for p in candidates:
        if os.path.exists(p) and os.path.getsize(p) > 0:
            return p

    # Auto-seed baseline alerts.json if missing so Wazuh is always available
    default_log = os.path.join(base_dir, "data", "alerts.json")
    try:
        os.makedirs(os.path.dirname(default_log), exist_ok=True)
        from simulator.log_generator import generate_batch, append_to_log
        append_to_log(generate_batch())
        if os.path.exists(default_log):
            return default_log
    except Exception:
        pass

    return env_path or "/var/ossec/logs/alerts/alerts.json"

WAZUH_LOG_PATH = get_wazuh_log_path()

# Wazuh rule ID → attack type mapping
RULE_ATTACK_MAP = {
    # Brute force
    5710: "brute_force", 5712: "brute_force", 40111: "brute_force", 40112: "brute_force",
    # Privilege escalation
    5402: "privilege_escalation", 5403: "privilege_escalation", 8502: "privilege_escalation", 8504: "privilege_escalation",
    # Data exfiltration
    31100: "data_exfiltration", 31101: "data_exfiltration", 31102: "data_exfiltration",
    # Lateral movement
    5510: "lateral_movement", 5511: "lateral_movement", 18100: "lateral_movement",
    # Port scan
    40101: "port_scan", 40102: "port_scan", 40103: "port_scan",
    # Crypto mining
    87100: "crypto_mining", 87101: "crypto_mining",
    # Ransomware
    60100: "ransomware_precursor", 60101: "ransomware_precursor",
    # Credential stuffing
    5716: "credential_stuffing", 5717: "credential_stuffing",
}

RULE_DESCRIPTIONS = {
    5710: "Multiple failed SSH/login attempts",
    5712: "Brute force attack detected",
    5402: "Privilege escalation attempt",
    5403: "User attached admin policy to self",
    31101: "Large data transfer to external IP",
    5510: "Unusual AssumeRole chain detected",
    40101: "Port scan from external IP",
    87100: "Crypto mining process detected",
    60100: "Ransomware precursor activity",
    5716: "Credential stuffing pattern detected",
}


def _parse_wazuh_alert(raw: dict) -> Dict:
    """Convert a raw Wazuh JSON alert into our standard event format."""
    rule = raw.get("rule", {})
    rule_id = int(rule.get("id", 0))
    level = int(rule.get("level", 1))
    agent = raw.get("agent", {})
    data = raw.get("data", {})
    src_ip = (
        data.get("srcip") or
        raw.get("location", "").split("->")[0].strip() or
        "unknown"
    )

    severity = "low"
    if level >= 12: severity = "critical"
    elif level >= 8: severity = "high"
    elif level >= 4: severity = "medium"

    attack_type = RULE_ATTACK_MAP.get(rule_id)
    event_type = "attack" if attack_type else "normal"

    return {
        "id": raw.get("id", str(uuid.uuid4())),
        "timestamp": raw.get("timestamp", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")),
        "source": "wazuh",
        "rule_id": rule_id,
        "rule_description": rule.get("description", RULE_DESCRIPTIONS.get(rule_id, "Security event")),
        "level": level,
        "severity": severity,
        "event_type": event_type,
        "attack_type": attack_type,
        "user": data.get("dstuser") or data.get("srcuser") or agent.get("name", "unknown"),
        "src_ip": src_ip,
        "dst_ip": data.get("dstip", "unknown"),
        "service": data.get("program_name", "unknown"),
        "region": "on-premise",
        "action": rule.get("description", "unknown"),
        "status": "detected",
        "bytes_transferred": int(data.get("size", 0)),
        "failed_attempts": int(data.get("failed_attempts", 0)),
        "description": rule.get("description", ""),
        "anomaly_score": min(1.0, round(level / 15, 4)),
        "agent_name": agent.get("name", "unknown"),
        "agent_id": agent.get("id", "000"),
    }


def read_wazuh_logs(max_events: int = 200) -> List[Dict]:
    """
    Read real Wazuh alert logs from disk.
    Returns list of parsed events or empty list if file not found.
    """
    path = get_wazuh_log_path()
    if not os.path.exists(path):
        return []

    events = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        # Wazuh writes one JSON object per line - read up to max_events
        slice_lines = reversed(lines[-max_events * 2:]) if max_events else reversed(lines)
        for line in slice_lines:
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
                events.append(_parse_wazuh_alert(raw))
                if max_events and len(events) >= max_events:
                    break
            except json.JSONDecodeError:
                continue

    except Exception as e:
        print(f"[Wazuh Reader] Error reading {path}: {e}")
        return []

    return events


def is_wazuh_available() -> bool:
    """Check if real Wazuh log file exists."""
    return os.path.exists(get_wazuh_log_path())


def get_wazuh_status() -> Dict:
    path = get_wazuh_log_path()
    available = os.path.exists(path)
    return {
        "available": available,
        "log_path": path,
        "mode": "real" if available else "simulated",
        "message": f"Reading from {path}" if available else "Wazuh log not found — using simulator"
    }
