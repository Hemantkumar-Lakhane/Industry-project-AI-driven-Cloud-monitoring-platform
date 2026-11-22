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

    default_log = os.path.join(base_dir, "data", "alerts.json")
    if os.path.exists(default_log) and os.path.getsize(default_log) > 0:
        return default_log

    return env_path or "/var/ossec/logs/alerts/alerts.json"

WAZUH_LOG_PATH = get_wazuh_log_path()

# Wazuh rule ID → attack type mapping
RULE_ATTACK_MAP = {
    # 1. Brute force
    5710: "brute_force", 5712: "brute_force", 40111: "brute_force", 40112: "brute_force",
    # 2. Account takeover
    80201: "account_takeover", 80202: "account_takeover", 5716: "account_takeover", 5717: "account_takeover",
    # 3. Privilege escalation
    5402: "iam_privilege_escalation", 5403: "iam_privilege_escalation", 8502: "iam_privilege_escalation", 8504: "iam_privilege_escalation",
    # 4. Suspicious API activity
    80102: "suspicious_api_activity", 80105: "suspicious_api_activity",
    # 5. Cloud misconfiguration
    80801: "cloud_misconfiguration", 80802: "cloud_misconfiguration",
    # 6. Data exfiltration
    31100: "data_exfiltration", 31101: "data_exfiltration", 31102: "data_exfiltration",
    # 7. Network scanning
    40101: "network_scanning", 40102: "network_scanning", 40103: "network_scanning",
    # 8. DDoS
    80501: "ddos", 80502: "ddos",
    # 9. Crypto mining
    87100: "cryptomining", 87101: "cryptomining",
    # 10. Container & K8s attacks
    87001: "container_k8s_attacks", 87005: "container_k8s_attacks",
    # 11. BOLA & SSRF
    80301: "bola_ssrf", 80302: "bola_ssrf",
    # 12. Malware & Ransomware
    60100: "malware_ransomware", 60101: "malware_ransomware",
    # 13. Database attacks
    80701: "database_attacks", 80702: "database_attacks",
    # 14. Serverless abuse
    80401: "serverless_abuse", 80405: "serverless_abuse",
    # 15. Supply chain
    80901: "supply_chain_compromise", 80902: "supply_chain_compromise",
    # 16. Defense tampering
    80601: "defense_tampering", 80602: "defense_tampering",
    # Lateral movement / auxiliary
    5510: "iam_privilege_escalation", 5511: "iam_privilege_escalation", 18100: "iam_privilege_escalation",
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
    80102: "CloudTrail anomalous API burst: rapid DescribeInstances and enumeration",
    87005: "Container escape attempt: host /var/run/docker.sock mounted into pod",
    80401: "Unauthorized UpdateFunctionCode injected into serverless Lambda function",
    80301: "SSRF exploitation attempt targeting AWS metadata service 169.254.169.254",
    80201: "Account Takeover: Multi-IP switching and sensitive credential modification",
    80601: "Defense Evasion: CloudTrail StopLogging executed and audit tampering detected",
    80701: "Database threat: SQL injection payload ' OR 1=1 detected on RDS proxy",
    80801: "Cloud misconfiguration: S3 bucket ACL public read/write and open security group",
    80901: "Supply chain compromise: Poisoned dependency script in CI/CD runner",
    80501: "Distributed Denial of Service: Volumetric SYN flood and request surge",
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
    available = os.path.exists(path) and os.path.getsize(path) > 0
    return {
        "available": available,
        "log_path": path,
        "mode": "real" if available else "cloud_stream",
        "message": f"Reading from {path}" if available else "Live Cloud Telemetry Ingestion Active"
    }
