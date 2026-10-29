"""
Incident Correlation Engine for RAM Antivirus
================================================
Deterministic, evidence-based correlation layer that groups related security
findings into higher-level SecurityIncidents.

Pipeline:
  Telemetry -> Normalization -> Detectors -> Findings -> Correlation Engine -> Incidents

Correlation Signals:
  1. Temporal Proximity (configurable sliding window, default 900s / 15 min)
  2. Principal / Identity Matching (same user or service account)
  3. Source IP Matching (combined with entity, resource, or attack progression)
  4. Resource Matching (same cloud ARN, host, database, or storage bucket)
  5. MITRE Kill-Chain Stage Progression (Initial Access -> Privilege Escalation -> Exfiltration)
"""
import os
import re
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Union, Set, Tuple
from collections import defaultdict

from schemas.finding import SecurityFinding
from schemas.incident import SecurityIncident

# Configurable temporal window for incident correlation (defaults to 15 minutes / 900 seconds)
DEFAULT_CORRELATION_WINDOW_SECONDS: int = int(os.environ.get("CORRELATION_WINDOW_SECONDS", 900))
DEFAULT_WINDOW_SECONDS: int = DEFAULT_CORRELATION_WINDOW_SECONDS

# MITRE Attack Stage Mapping for the 16 Canonical Categories
CATEGORY_STAGE_MAP: Dict[str, str] = {
    "brute_force": "Initial Access & Credential Abuse",
    "account_takeover": "Credential Access & Persistence",
    "bola_ssrf": "Initial Access & API Exploitation",
    "network_scanning": "Reconnaissance & Network Discovery",
    "suspicious_api_activity": "Reconnaissance & Cloud Enumeration",
    "iam_privilege_escalation": "Privilege Escalation & IAM Manipulation",
    "container_k8s_attacks": "Execution & Container Privilege Abuse",
    "serverless_abuse": "Execution & Serverless Abuse",
    "supply_chain_compromise": "Initial Access & Supply Chain Compromise",
    "defense_tampering": "Defense Evasion & Logging Impairment",
    "cloud_misconfiguration": "Defense Evasion & Posture Drift",
    "data_exfiltration": "Exfiltration Over Web/Cloud Storage",
    "database_attacks": "Data Exfiltration & Database Compromise",
    "cryptomining": "Resource Hijacking & Impact",
    "malware_ransomware": "Impact & Data Encryption",
    "ddos": "Impact & Denial of Service",
}

# Canonical kill-chain tiers for progressive attack stages
STAGE_TIERS: Dict[str, int] = {
    # Tier 1: Reconnaissance
    "network_scanning": 1,
    "suspicious_api_activity": 1,
    # Tier 2: Initial Access & Credential Abuse
    "brute_force": 2,
    "account_takeover": 2,
    "bola_ssrf": 2,
    "supply_chain_compromise": 2,
    # Tier 3: Execution & Posture Drift
    "container_k8s_attacks": 3,
    "serverless_abuse": 3,
    "cloud_misconfiguration": 3,
    # Tier 4: Privilege Escalation & Defense Evasion
    "iam_privilege_escalation": 4,
    "defense_tampering": 4,
    # Tier 5: Exfiltration & Impact
    "data_exfiltration": 5,
    "database_attacks": 5,
    "cryptomining": 5,
    "malware_ransomware": 5,
    "ddos": 5,
}

# Explicit within-tier kill-chain progression sequences
VALID_STAGE_TRANSITIONS: Set[Tuple[str, str]] = {
    ("brute_force", "account_takeover"),
    ("account_takeover", "brute_force"),
    ("bola_ssrf", "account_takeover"),
    ("account_takeover", "bola_ssrf"),
    ("iam_privilege_escalation", "defense_tampering"),
    ("defense_tampering", "iam_privilege_escalation"),
    ("data_exfiltration", "malware_ransomware"),
    ("malware_ransomware", "data_exfiltration"),
    ("database_attacks", "data_exfiltration"),
    ("data_exfiltration", "database_attacks"),
}

# Multi-tenant / shared infrastructure service hubs that must NOT bridge disparate users/IPs
COMMON_SERVICE_HUBS: Set[str] = {
    "apache2", "nginx", "httpd", "web-server", "auth-portal", "login-portal",
    "gateway", "api-gateway", "proxy", "load-balancer", "ingress"
}


def is_meaningful_stage_progression(cat_a: str, cat_b: str) -> Tuple[bool, str]:
    """
    Deterministically evaluates whether two categories form a meaningful MITRE ATT&CK kill-chain progression.
    Returns (has_progression, reason_detail).
    """
    if cat_a == cat_b or not cat_a or not cat_b:
        return False, ""

    tier_a = STAGE_TIERS.get(cat_a, 0)
    tier_b = STAGE_TIERS.get(cat_b, 0)

    # 1. Progression across distinct tiers (e.g. Initial Access -> PrivEsc -> Exfiltration)
    if tier_a > 0 and tier_b > 0 and tier_a != tier_b:
        min_tier, max_tier = min(tier_a, tier_b), max(tier_a, tier_b)
        return True, f"Tier {min_tier} -> Tier {max_tier} progression"

    # 2. Known within-tier progression pairs (e.g. brute_force -> account_takeover)
    if (cat_a, cat_b) in VALID_STAGE_TRANSITIONS:
        return True, f"Direct kill-chain transition '{cat_a}' <-> '{cat_b}'"

    return False, ""


SEVERITY_RANK: Dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0
}

# Generic values to filter out from entity correlation
GENERIC_PRINCIPALS: Set[str] = {
    "", "unknown", "unknown-principal", "unknown-user", "anonymous", "none", "null"
}

GENERIC_IPS: Set[str] = {
    "", "0.0.0.0", "127.0.0.1", "::1", "unknown", "none", "null", "external-endpoint"
}

GENERIC_RESOURCES: Set[str] = {
    "", "unknown", "cloud-resource", "cloud-workload", "cloud-workload-general",
    "detected-via-log", "cloud-audit-trail", "s3:detected-via-log",
    "security-group:detected-via-log", "none", "null"
}

IP_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")


def generate_incident_id(finding_ids: List[str]) -> str:
    """
    Generate an idempotent, deterministic incident ID from a cluster of finding IDs.
    Running correlation on the identical set of findings will always produce the exact same ID.
    """
    if not finding_ids:
        return "INC-UNKNOWN"
    sorted_ids = sorted(list(set(finding_ids)))
    seed_str = ":".join(sorted_ids)
    h = hashlib.sha256(seed_str.encode("utf-8")).hexdigest()[:8].upper()
    return f"INC-{h}"


def _parse_timestamp(val: Any) -> datetime:
    """Convert string or datetime to UTC datetime."""
    if isinstance(val, datetime):
        return val if val.tzinfo else val.replace(tzinfo=timezone.utc)
    if isinstance(val, str):
        try:
            clean_str = val.replace("Z", "+00:00")
            parsed = datetime.fromisoformat(clean_str)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except Exception:
            return datetime.now(timezone.utc)
    return datetime.now(timezone.utc)


def _extract_principal(finding_dict: Dict[str, Any]) -> Optional[str]:
    """Extract and normalize principal identity from finding data."""
    raw_p = finding_dict.get("affected_principal")
    if isinstance(raw_p, dict):
        raw_p = raw_p.get("identity")
    if not raw_p:
        evidence = finding_dict.get("evidence") or {}
        telemetry = evidence.get("telemetry_fields") or {}
        p_val = telemetry.get("principal") or telemetry.get("user")
        if isinstance(p_val, dict):
            raw_p = p_val.get("identity")
        elif isinstance(p_val, str):
            raw_p = p_val

    if raw_p:
        cleaned = str(raw_p).strip().lower()
        if cleaned not in GENERIC_PRINCIPALS:
            return cleaned
    return None


def _extract_source_ip(finding_dict: Dict[str, Any]) -> Optional[str]:
    """Extract and normalize source IP address from finding telemetry or facts."""
    evidence = finding_dict.get("evidence") or {}
    telemetry = evidence.get("telemetry_fields") or {}
    raw_ip = telemetry.get("source_ip") or telemetry.get("initial_ip") or telemetry.get("src_ip")

    if not raw_ip:
        # Check observed facts for IP patterns
        facts = evidence.get("observed_facts") or []
        for fact in facts:
            match = IP_REGEX.search(str(fact))
            if match:
                raw_ip = match.group(0)
                break

    if not raw_ip:
        res = str(finding_dict.get("affected_resource") or "")
        match = IP_REGEX.search(res)
        if match:
            raw_ip = match.group(0)

    if raw_ip:
        cleaned = str(raw_ip).strip()
        if cleaned not in GENERIC_IPS and not cleaned.startswith("127."):
            return cleaned
    return None


def _extract_resource(finding_dict: Dict[str, Any]) -> Optional[str]:
    """Extract and normalize cloud resource identifier from finding."""
    raw_res = finding_dict.get("affected_resource")
    if not raw_res:
        evidence = finding_dict.get("evidence") or {}
        telemetry = evidence.get("telemetry_fields") or {}
        raw_res = telemetry.get("resource") or telemetry.get("bucket") or telemetry.get("target")

    if raw_res:
        cleaned = str(raw_res).strip().lower()
        # Strip common prefixes for canonical matching (e.g. "s3:my-bucket" -> "my-bucket")
        for prefix in ("s3:", "arn:aws:s3:::", "compute:", "host:", "iam:", "audit:", "storage:"):
            if cleaned.startswith(prefix):
                cleaned = cleaned[len(prefix):]
                break
        if cleaned not in GENERIC_RESOURCES and len(cleaned) > 2:
            return cleaned
    return None


class UnionFind:
    """Disjoint Set data structure for graph connected component clustering."""

    def __init__(self, elements: List[int]):
        self.parent = {e: e for e in elements}

    def find(self, item: int) -> int:
        if self.parent[item] != item:
            self.parent[item] = self.find(self.parent[item])
        return self.parent[item]

    def union(self, set1: int, set2: int) -> None:
        root1 = self.find(set1)
        root2 = self.find(set2)
        if root1 != root2:
            self.parent[root2] = root1


def evaluate_finding_pair_correlation(
    item_a: Dict[str, Any],
    item_b: Dict[str, Any],
    window_seconds: int = DEFAULT_CORRELATION_WINDOW_SECONDS
) -> Tuple[bool, List[str]]:
    """
    Deterministically evaluates whether two findings belong to the same incident.
    Returns (is_correlated, list_of_reasons).
    """
    ts_a = item_a["_parsed_ts"]
    ts_b = item_b["_parsed_ts"]
    delta_sec = abs((ts_a - ts_b).total_seconds())

    # Temporal boundary check
    if delta_sec > window_seconds:
        return False, []

    reasons: List[str] = []

    p_a, p_b = item_a["_principal"], item_b["_principal"]
    ip_a, ip_b = item_a["_source_ip"], item_b["_source_ip"]
    res_a, res_b = item_a["_resource"], item_b["_resource"]
    cat_a, cat_b = item_a["_category"], item_b["_category"]
    stage_a, stage_b = item_a["_stage"], item_b["_stage"]

    same_principal = bool(p_a and p_b and p_a == p_b)
    same_ip = bool(ip_a and ip_b and ip_a == ip_b)
    same_resource = bool(res_a and res_b and res_a == res_b)

    both_principals_distinct = bool(p_a and p_b and p_a.lower() != p_b.lower())
    both_ips_distinct = bool(ip_a and ip_b and ip_a != ip_b)
    both_resources_distinct = bool(res_a and res_b and res_a.lower() != res_b.lower())
    is_hub_resource = bool((res_a and res_a in COMMON_SERVICE_HUBS) or (res_b and res_b in COMMON_SERVICE_HUBS))

    has_progression, prog_reason = is_meaningful_stage_progression(cat_a, cat_b)

    # ── Signal 1: Same Principal Identity (Requiring Corroborating Evidence) ───
    # Per Step 2: Same principal within 15 minutes is NOT sufficient by itself.
    # It must be corroborated by: same IP, same resource, or meaningful stage progression.
    # If both IPs are explicitly distinct AND both resources are distinct, disparate sessions do not group.
    if same_principal:
        if same_ip and same_resource:
            reasons.append(f"Identical principal '{p_a}' operating from source IP '{ip_a}' targeting resource '{res_a}'")
        elif same_ip:
            reasons.append(f"Identical principal '{p_a}' operating from source IP '{ip_a}'")
        elif same_resource:
            reasons.append(f"Identical principal '{p_a}' targeting resource '{res_a}'")
        elif has_progression and not (both_ips_distinct and both_resources_distinct):
            reasons.append(f"Kill-chain progression by principal '{p_a}': '{stage_a}' -> '{stage_b}' ({prog_reason})")

    # ── Signal 2: Same Source IP (Combined Context) ───────────────────────────
    # Per Step 5: If both identities are distinct (e.g. User A vs User B), do not group.
    elif same_ip:
        if not both_principals_distinct:
            if same_resource:
                reasons.append(f"Coordinated adversary activity from source IP '{ip_a}' targeting resource '{res_a}'")
            elif has_progression and delta_sec <= 600:
                reasons.append(f"Multi-stage attack sequence originating from IP '{ip_a}': '{stage_a}' -> '{stage_b}' ({prog_reason})")

    # ── Signal 3: Same Specific Cloud Resource (Dedicated Target Only) ────────
    # Per Step 3: Common service hubs (apache2, portal) must NOT bridge disparate users/IPs.
    elif same_resource:
        if not both_principals_distinct and not both_ips_distinct and not is_hub_resource:
            # Dedicated workload multi-vector attack without conflicting identities or IPs
            if cat_a != cat_b and delta_sec <= 180:
                reasons.append(f"Multi-vector threat activity targeting dedicated resource '{res_a}' within {int(delta_sec)}s")

    is_correlated = len(reasons) > 0
    return is_correlated, reasons


KILL_CHAIN_PHASES: Dict[str, str] = {
    "network_scanning": "Reconnaissance",
    "cloud_misconfiguration": "Reconnaissance",
    "brute_force": "Initial Access",
    "bola_ssrf": "Initial Access",
    "supply_chain": "Initial Access",
    "iam_privilege_escalation": "Privilege Escalation",
    "account_takeover": "Privilege Escalation",
    "defense_tampering": "Defense Evasion",
    "suspicious_api_activity": "Defense Evasion",
    "container_k8s_attacks": "Execution",
    "serverless_abuse": "Execution",
    "malware_ransomware": "Execution",
    "data_exfiltration": "Exfiltration",
    "database_attacks": "Collection",
    "cryptomining": "Impact",
    "ddos": "Impact"
}





def correlate_findings(
    findings: List[Any],
    window_seconds: float = DEFAULT_WINDOW_SECONDS
) -> List[SecurityIncident]:
    """
    Correlate atomic findings into higher-level SecurityIncidents.
    Uses sliding-time-window graph clustering with hub protection and corroborated same-principal grouping.
    """
    if not findings:
        return []

    # 1. Normalize finding representations and extract correlation keys
    normalized_items: List[Dict[str, Any]] = []
    for idx, f in enumerate(findings):
        d = f.model_dump(mode="json") if hasattr(f, "model_dump") else dict(f)
        cat = str(d.get("attack_category") or "unknown").lower()

        normalized_items.append({
            "_index": idx,
            "_raw": d,
            "finding_id": str(d.get("finding_id") or f"FIND-{idx:04d}"),
            "title": str(d.get("title") or "Security Finding"),
            "severity": str(d.get("severity") or "medium").lower(),
            "status": str(d.get("status") or "open").lower(),
            "_parsed_ts": _parse_timestamp(d.get("created_at") or d.get("timestamp")),
            "_principal": _extract_principal(d),
            "_source_ip": _extract_source_ip(d),
            "_resource": _extract_resource(d),
            "_category": cat,
            "_stage": CATEGORY_STAGE_MAP.get(cat, "Threat Activity"),
            "playbook_id": d.get("recommended_response", {}).get("playbook_id") if isinstance(d.get("recommended_response"), dict) else d.get("playbook_id"),
        })

    # Sort chronologically by timestamp
    normalized_items.sort(key=lambda x: x["_parsed_ts"])

    n = len(normalized_items)
    uf = UnionFind(list(range(n)))
    edge_reasons: Dict[Tuple[int, int], List[str]] = {}

    # 2. Pairwise evaluation with sliding window
    for i in range(n):
        for j in range(i + 1, n):
            # Because items are sorted by timestamp, if delta exceeds window we can break the inner loop early
            delta = (normalized_items[j]["_parsed_ts"] - normalized_items[i]["_parsed_ts"]).total_seconds()
            if delta > window_seconds:
                break

            correlated, reasons = evaluate_finding_pair_correlation(
                normalized_items[i],
                normalized_items[j],
                window_seconds=window_seconds
            )
            if correlated:
                uf.union(i, j)
                edge_reasons[(min(i, j), max(i, j))] = reasons

    # 3. Group items into clusters by connected component root
    clusters: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    for idx in range(n):
        root = uf.find(idx)
        clusters[root].append(normalized_items[idx])

    # 4. Construct SecurityIncident for each cluster
    incidents: List[SecurityIncident] = []

    for root, cluster_items in clusters.items():
        finding_ids = [item["finding_id"] for item in cluster_items]
        incident_id = generate_incident_id(finding_ids)

        # Collect entities and metadata
        principals = sorted(list(set(item["_principal"] for item in cluster_items if item["_principal"])))
        source_ips = sorted(list(set(item["_source_ip"] for item in cluster_items if item["_source_ip"])))
        resources = sorted(list(set(item["_resource"] for item in cluster_items if item["_resource"])))
        categories = sorted(list(set(item["_category"] for item in cluster_items if item["_category"])))
        stages = []
        for item in cluster_items:
            st = item["_stage"]
            if st not in stages:
                stages.append(st)

        # Timestamps
        start_time = cluster_items[0]["_parsed_ts"]
        last_seen = cluster_items[-1]["_parsed_ts"]
        duration_sec = max(0.0, (last_seen - start_time).total_seconds())

        # Determine overall severity (maximum of member findings)
        highest_sev = max(cluster_items, key=lambda x: SEVERITY_RANK.get(x["severity"], 0))["severity"]

        # Status: open if any is open; resolved only if all resolved
        all_resolved = all(item["status"] in ("resolved", "contained", "false_positive") for item in cluster_items)
        incident_status = "resolved" if all_resolved else "open"

        # Collect correlation reasons across edges in this cluster
        reasons_set: Set[str] = set()
        cluster_indices = [item["_index"] for item in cluster_items]
        for (i, j), r_list in edge_reasons.items():
            if normalized_items[i]["_index"] in cluster_indices and normalized_items[j]["_index"] in cluster_indices:
                reasons_set.update(r_list)

        correlation_reasons = sorted(list(reasons_set))
        if not correlation_reasons:
            if len(cluster_items) == 1:
                item0 = cluster_items[0]
                cat0 = (item0.get("attack_category") or "Threat").replace("_", " ").title()
                princ0 = item0.get("affected_principal") or (principals[0] if principals else "Host Principal")
                res0 = item0.get("affected_resource") or (resources[0] if resources else "Cloud Resource")
                ip0 = item0.get("source_ip") or (source_ips[0] if source_ips else "Remote Ingress")
                correlation_reasons = [
                    f"Direct telemetry signal: {cat0} activity targeting '{res0}' via principal '{princ0}' from IP '{ip0}'."
                ]
            else:
                correlation_reasons = ["Correlated by multi-signal entity and temporal alignment."]

        # Calculate deterministic correlation score
        if len(cluster_items) == 1:
            correlation_score = 0.85
        else:
            score = 0.70
            if len(principals) == 1:
                score += 0.12
            if len(source_ips) == 1:
                score += 0.08
            if len(resources) == 1:
                score += 0.05
            if len(stages) >= 2:
                score += 0.10
            if duration_sec <= 300:
                score += 0.05
            correlation_score = min(0.99, round(score, 2))

        # Playbook recommendation
        primary_playbook = next((item["playbook_id"] for item in cluster_items if item.get("playbook_id")), "PB-BF-001")

        # Generate human-readable campaign title and narrative
        primary_entity = principals[0] if principals else (source_ips[0] if source_ips else (resources[0] if resources else "Workload"))
        if len(cluster_items) > 1:
            if len(stages) >= 2:
                title = f"Multi-Stage Campaign: {' -> '.join(stages[:2])} ({primary_entity})"
            else:
                stage_name = stages[0] if stages else "Coordinated Threat"
                title = f"Coordinated Incident: {len(cluster_items)} Findings in {stage_name} ({primary_entity})"
            desc = (
                f"Correlated security incident comprising {len(cluster_items)} findings over {duration_sec:.1f}s. "
                f"Identities involved: {', '.join(principals) if principals else 'N/A'}. "
                f"Source IPs: {', '.join(source_ips) if source_ips else 'N/A'}. "
                f"Affected resources: {', '.join(resources) if resources else 'N/A'}."
            )
        else:
            title = cluster_items[0]["title"]
            desc = f"Isolated security finding: {cluster_items[0]['title']} ({cluster_items[0]['finding_id']})."

        incident = SecurityIncident(
            incident_id=incident_id,
            title=title,
            description=desc,
            severity=highest_sev,
            status=incident_status,
            start_time=start_time,
            last_seen=last_seen,
            duration_seconds=round(duration_sec, 1),
            finding_count=len(cluster_items),
            finding_ids=finding_ids,
            principals=principals,
            source_ips=source_ips,
            resources=resources,
            attack_categories=categories,
            attack_stages=stages,
            correlation_score=correlation_score,
            correlation_reasons=correlation_reasons,
            primary_playbook_id=primary_playbook,
            findings=[item["_raw"] for item in cluster_items]
        )
        incidents.append(incident)

    # Sort incidents: most recent last_seen first
    incidents.sort(key=lambda inc: inc.last_seen, reverse=True)
    return incidents

def get_correlated_incidents() -> Dict[str, Any]:
    """Retrieve all current incidents, running correlation over persisted findings if empty."""
    from engines.db import get_incidents_db, get_findings_db, save_incidents_db
    persisted = get_incidents_db(limit=100)
    if not persisted:
        findings = get_findings_db(limit=300)
        if findings:
            inc_objs = correlate_findings(findings)
            persisted = [inc.model_dump(mode="json") if hasattr(inc, "model_dump") else inc for inc in inc_objs]
            save_incidents_db(persisted)

    total = len(persisted)
    open_count = sum(1 for inc in persisted if (inc.get("status") or "").lower() == "open")
    contained_count = sum(1 for inc in persisted if (inc.get("status") or "").lower() == "contained")
    resolved_count = sum(1 for inc in persisted if (inc.get("status") or "").lower() == "resolved")
    crit_count = sum(1 for inc in persisted if (inc.get("severity") or "").lower() == "critical")
    high_count = sum(1 for inc in persisted if (inc.get("severity") or "").lower() == "high")

    return {
        "status": "success",
        "total_incidents": total,
        "open_incidents": open_count,
        "contained_incidents": contained_count,
        "resolved_incidents": resolved_count,
        "critical_incidents": crit_count,
        "high_incidents": high_count,
        "incidents": persisted
    }
