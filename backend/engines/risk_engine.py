"""
Unified Incident-Aware Risk Scoring Engine
==========================================
Combines outputs from Task-1 Correlated Incidents, Specialist ML Anomaly Detection,
Cloud Security Posture Management (CSPM), and Cloud Infrastructure Entitlement
Management (CIEM) into a single, four-pillar, explainable risk score.

Mathematical Architecture:
--------------------------
Unified Risk = 0.35 * Incident_Risk + 0.25 * ML_Risk + 0.20 * CSPM_Risk + 0.20 * CIEM_Risk

Pillar 1: Incident Risk (35% weight)
  Evaluates coordinated multi-stage threat campaigns derived by Task-1 correlation.
  - Base Severity Weights: Critical=35, High=20, Medium=10, Low=5
  - Diminishing Finding Volume: M_findings = 1.0 + 0.35 * ln(1 + max(0, N_findings - 1)) [capped at 3.0]
  - MITRE Attack Progression: 1 stage = 1.0x, 2 stages = 1.3x, 3+ stages = 1.7x
  - Entity Blast Radius: M_blast = 1.0 + 0.1 * ln(1 + N_resources + N_principals) [capped at 1.5]
  - Temporal Recency Decay: M_temporal = exp(-0.02 * age_hours) [floor at 0.10]
  - Incident Status Sensitivity: Open/Investigating = 1.0x, Resolved/Closed = 0.15x
  - Multi-Incident Aggregation: Primary incident sets baseline S_(1); secondary add 0.15 * S_(i)

Pillar 2: ML/AI Flow Anomaly Detection (25% weight)
  Evaluates 9-dimensional network and operational flow probabilities across PyOD models.

Pillar 3: CSPM Cloud Posture (20% weight)
  Evaluates cloud configuration exposures and security group misconfigurations.

Pillar 4: CIEM Identity Entitlements (20% weight)
  Evaluates excessive permissions, privilege escalation paths, and risky IAM principals.
"""
import math
import uuid
import bisect
from typing import List, Dict, Optional, Any, Tuple
from datetime import datetime, timezone
from engines.db import save_risk_score, get_risk_trend_db

# ── Severity Scoring Constants ────────────────────────────────────────────────
INCIDENT_SEVERITY_WEIGHTS = {
    "critical": 35.0,
    "high": 20.0,
    "medium": 10.0,
    "low": 5.0,
}

SEVERITY_SCORES = {
    "critical": 100, "high": 75, "medium": 50, "low": 25,
    "Critical": 100, "High": 75, "Medium": 50, "Low": 25,
}


def _risk_level(score: float) -> str:
    """Map numeric score (0-100) to standard severity classification."""
    if score >= 76.0:
        return "critical"
    elif score >= 51.0:
        return "high"
    elif score >= 26.0:
        return "medium"
    else:
        return "low"


def _risk_color(level: str) -> str:
    """Map severity tier to design-token color hex."""
    return {
        "critical": "#ef4444",
        "high": "#f97316",
        "medium": "#eab308",
        "low": "#10b981"
    }.get(level, "#8b949e")


def _parse_timestamp(ts_val: Any) -> Optional[datetime]:
    """Parse ISO8601 or datetime object into UTC-aware datetime."""
    if not ts_val:
        return None
    if isinstance(ts_val, datetime):
        return ts_val if ts_val.tzinfo else ts_val.replace(tzinfo=timezone.utc)
    try:
        s = str(ts_val).replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


# ── Kill-Chain Stage Progression Logic ────────────────────────────────────────

MITRE_STAGE_ORDER: Dict[str, int] = {
    # 0: Reconnaissance
    "reconnaissance": 0,
    "reconnaissance & network discovery": 0,
    "reconnaissance & cloud enumeration": 0,
    "network_scanning": 0,
    "suspicious_api_activity": 0,
    "port_scan": 0,

    # 1: Initial Access & Credential Abuse
    "initial access": 1,
    "initial access & credential abuse": 1,
    "initial access & api exploitation": 1,
    "initial access & supply chain compromise": 1,
    "credential access & persistence": 1,
    "credential access": 1,
    "brute_force": 1,
    "account_takeover": 1,
    "bola_ssrf": 1,
    "supply_chain_compromise": 1,

    # 2: Privilege Escalation & Execution
    "privilege escalation": 2,
    "privilege escalation & iam manipulation": 2,
    "execution & container privilege abuse": 2,
    "execution & serverless abuse": 2,
    "execution": 2,
    "iam_privilege_escalation": 2,
    "container_k8s_attacks": 2,
    "serverless_abuse": 2,

    # 3: Defense Evasion & Posture Drift
    "defense evasion": 3,
    "defense evasion & logging impairment": 3,
    "defense evasion & posture drift": 3,
    "defense_tampering": 3,
    "cloud_misconfiguration": 3,

    # 4: Exfiltration & Database Compromise
    "exfiltration": 4,
    "exfiltration over web/cloud storage": 4,
    "data exfiltration & database compromise": 4,
    "data_exfiltration": 4,
    "database_attacks": 4,

    # 5: Impact & Resource Hijacking
    "impact": 5,
    "resource hijacking & impact": 5,
    "impact & data encryption": 5,
    "impact & denial of service": 5,
    "cryptomining": 5,
    "malware_ransomware": 5,
    "ddos": 5,
}


def map_stage_to_index(stage_or_cat: Any) -> Optional[int]:
    """Map MITRE stage name or category slug to its canonical kill-chain index (0 to 5)."""
    if not stage_or_cat:
        return None
    s = str(stage_or_cat).strip().lower()
    if s in MITRE_STAGE_ORDER:
        return MITRE_STAGE_ORDER[s]
    # Keyword fallback
    if any(k in s for k in ("recon", "scan", "enum")):
        return 0
    if any(k in s for k in ("initial", "access", "brute", "credential", "takeover")):
        return 1
    if any(k in s for k in ("privilege", "escalat", "iam", "container", "serverless", "execution")):
        return 2
    if any(k in s for k in ("evasion", "tamper", "misconfig")):
        return 3
    if any(k in s for k in ("exfil", "database", "egress")):
        return 4
    if any(k in s for k in ("impact", "ransom", "cryptomin", "ddos", "encrypt", "hijack")):
        return 5
    return None


def calculate_kill_chain_progression(incident_data: Dict[str, Any]) -> Tuple[float, Dict[str, Any]]:
    """
    Determine whether observed attack stages demonstrate chronological kill-chain progression.

    Evaluation Process:
      1. Chronologically sort findings by timestamp.
      2. Map each finding to its MITRE stage index (0 to 5).
      3. Collapse consecutive duplicate findings in the same stage.
      4. Compute the Longest Strictly Increasing Subsequence (LIS) representing forward progression.
      5. Measure the forward transition consistency ratio R_fwd = N_fwd / N_trans.
      6. Return a bounded multiplier in [1.0, 1.70] with detailed breakdown.
    """
    findings = incident_data.get("findings") or []
    finding_tuples = []

    for f in findings:
        if not isinstance(f, dict):
            continue
        ts = _parse_timestamp(f.get("timestamp") or f.get("last_seen") or f.get("start_time"))
        idx = map_stage_to_index(f.get("attack_stage"))
        if idx is None:
            idx = map_stage_to_index(f.get("attack_category"))
        if idx is None:
            idx = map_stage_to_index(f.get("title"))
        if idx is not None:
            finding_tuples.append((ts, idx))

    if finding_tuples:
        # Sort chronologically by finding timestamp
        finding_tuples.sort(key=lambda x: (x[0] is None, x[0] if x[0] else datetime.min.replace(tzinfo=timezone.utc)))
        raw_indices = [idx for _, idx in finding_tuples]
    else:
        # Fallback to attack_stages or attack_categories order if findings list is omitted
        raw_stages = incident_data.get("attack_stages") or incident_data.get("attack_categories") or []
        raw_indices = [map_stage_to_index(s) for s in raw_stages if map_stage_to_index(s) is not None]

    # Collapse consecutive duplicate stages
    collapsed = []
    for s in raw_indices:
        if not collapsed or s != collapsed[-1]:
            collapsed.append(s)

    k = len(collapsed)
    if k <= 1:
        return 1.0, {
            "stage_indices": collapsed,
            "progression_type": "single_stage",
            "forward_stages": k,
            "r_fwd": 0.0,
            "multiplier": 1.0
        }

    # Analyze transitions
    n_trans = k - 1
    n_fwd = sum(1 for i in range(n_trans) if collapsed[i + 1] > collapsed[i])
    r_fwd = n_fwd / n_trans if n_trans > 0 else 0.0

    if n_fwd == 0:
        # Entirely reversed / retrograde sequence -> zero progression bonus
        return 1.0, {
            "stage_indices": collapsed,
            "progression_type": "reversed_or_retrograde",
            "forward_stages": 1,
            "r_fwd": 0.0,
            "multiplier": 1.0
        }

    # Find longest strictly increasing subsequence (LIS)
    lis_tails = []
    for x in collapsed:
        pos = bisect.bisect_left(lis_tails, x)
        if pos < len(lis_tails):
            lis_tails[pos] = x
        else:
            lis_tails.append(x)
    lis_len = len(lis_tails)

    # Determine base progression potential
    if lis_len >= 3:
        p_base = 1.70
        prog_type = "full_kill_chain" if lis_len >= 4 else "three_stage_progression"
    elif lis_len == 2:
        # Check if step is contiguous (e.g. Initial Access -> PrivEsc) vs partial jump (e.g. Initial Access -> Exfil)
        is_contiguous = (lis_tails[1] - lis_tails[0] == 1)
        p_base = 1.30 if is_contiguous else 1.20
        prog_type = "two_stage_contiguous" if is_contiguous else "two_stage_partial"
    else:
        p_base = 1.0
        prog_type = "limited_progression"

    # Scale base progression by forward consistency ratio
    multiplier = min(1.70, round(1.0 + (p_base - 1.0) * r_fwd, 3))

    return multiplier, {
        "stage_indices": collapsed,
        "lis_stages": lis_tails,
        "lis_len": lis_len,
        "progression_type": prog_type,
        "r_fwd": round(r_fwd, 3),
        "multiplier": multiplier
    }


# ── Pillar 1: Incident Risk Calculation ───────────────────────────────────────

def calculate_incident_risk(
    incidents: Optional[List[Dict]],
    current_time: Optional[datetime] = None
) -> Dict[str, Any]:
    """
    Calculate a bounded 0-100 Incident Risk score based on Task-1 correlated incidents.

    Mathematical Formulation per Incident:
      S_inc = min(100.0, W_sev * M_findings * M_progression * M_blast * M_temporal * M_status)

    Where:
      - W_sev: Base severity weight (Critical=35, High=20, Medium=10, Low=5)
      - M_findings = min(3.0, 1.0 + 0.35 * ln(1 + max(0, N_findings - 1)))
      - M_progression: Chronological kill-chain multiplier [1.0x to 1.70x]
      - M_blast = min(1.5, 1.0 + 0.1 * ln(1 + N_resources + N_principals))
      - M_temporal = max(0.10, exp(-0.02 * age_hours))
      - M_status = 1.0 (open/investigating) or 0.15 (resolved/closed)

    Multi-Incident Aggregation:
      I_risk = min(100.0, S_(1) + 0.15 * sum_{i=2}^k S_(i))
    """
    if not incidents:
        return {
            "score": 0.0,
            "level": "low",
            "color": _risk_color("low"),
            "details": {
                "total_incidents": 0,
                "active_incidents": 0,
                "max_individual_score": 0.0,
                "severity_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "stage_diversity": 0
            },
            "actionable_drivers": []
        }

    now = current_time or datetime.now(timezone.utc)
    scored_incidents = []
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    unique_stages_all = set()
    active_count = 0

    for inc in incidents:
        # Handle dict or Pydantic model representation
        if hasattr(inc, "model_dump"):
            d = inc.model_dump(mode="json")
        elif isinstance(inc, dict):
            d = inc
        else:
            continue

        sev = (d.get("severity") or "medium").lower()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
        base_sev = INCIDENT_SEVERITY_WEIGHTS.get(sev, 10.0)

        # 1. Finding Volume Multiplier (diminishing sublinear return)
        findings = d.get("finding_ids") or []
        n_findings = max(int(d.get("finding_count") or len(findings)), 1)
        m_findings = min(3.0, 1.0 + 0.35 * math.log(1.0 + max(0, n_findings - 1)))

        # 2. Chronological Attack Progression Multiplier
        raw_stages = [s for s in (d.get("attack_stages") or []) if s]
        unique_stages = sorted(list(set(raw_stages)))
        unique_stages_all.update(unique_stages)
        m_progression, prog_details = calculate_kill_chain_progression(d)

        # 3. Blast Radius Multiplier (distinct resources + principals)
        resources = set(d.get("resources") or [])
        principals = set(d.get("principals") or [])
        total_entities = len(resources) + len(principals)
        m_blast = min(1.5, 1.0 + 0.1 * math.log(1.0 + total_entities))

        # 4. Temporal Decay Multiplier (exponential decay with half-life ~35 hours)
        last_seen_dt = _parse_timestamp(d.get("last_seen") or d.get("start_time"))
        if last_seen_dt:
            delta_sec = max(0.0, (now - last_seen_dt).total_seconds())
            age_hours = delta_sec / 3600.0
            # lambda = 0.02 -> recent attacks maintain ~1.0; 24h old ~0.62; floor at 0.10
            m_temporal = max(0.10, math.exp(-0.02 * age_hours))
        else:
            m_temporal = 1.0

        # 5. Incident Status Multiplier
        status = (d.get("status") or "open").lower()
        if status in ("resolved", "closed"):
            m_status = 0.15
        else:
            m_status = 1.0
            active_count += 1

        # Calculate Individual Incident Score
        raw_score = base_sev * m_findings * m_progression * m_blast * m_temporal * m_status
        inc_score = min(100.0, round(raw_score, 1))

        primary_res = list(resources)[0] if resources else (d.get("affected_resource") or "cloud-workload")
        primary_user = list(principals)[0] if principals else (d.get("affected_principal") or "unknown-user")

        scored_incidents.append({
            "incident_id": d.get("incident_id") or f"INC-{str(uuid.uuid4())[:8].upper()}",
            "title": d.get("title") or "Correlated Security Incident",
            "severity": sev,
            "status": status,
            "finding_count": n_findings,
            "stages": unique_stages,
            "progression_details": prog_details,
            "resource": primary_res,
            "principal": primary_user,
            "score": inc_score,
            "multipliers": {
                "base_severity": base_sev,
                "findings": round(m_findings, 3),
                "progression": m_progression,
                "blast_radius": round(m_blast, 3),
                "temporal": round(m_temporal, 3),
                "status": m_status
            },
            "raw": d
        })

    # Sort descending by individual incident score
    scored_incidents.sort(key=lambda x: x["score"], reverse=True)

    # Multi-Incident Aggregation: Primary sets baseline; secondary add diminished marginal risk
    if scored_incidents:
        primary_score = scored_incidents[0]["score"]
        secondary_sum = sum(x["score"] for x in scored_incidents[1:])
        composite_score = min(100.0, round(primary_score + 0.15 * secondary_sum, 1))
    else:
        primary_score = 0.0
        composite_score = 0.0

    # Build Top Actionable Risk Drivers (Top 3 incidents)
    actionable_drivers = []
    for item in scored_incidents[:3]:
        actionable_drivers.append({
            "id": item["incident_id"],
            "title": item["title"],
            "resource": f"{item['resource']} ↗",
            "source": f"Incident · {item['status'].upper()}",
            "severity": item["severity"],
            "stages": item["stages"],
            "finding_count": item["finding_count"],
            "risk_score": item["score"],
            "nextStep": "Investigate campaign →"
        })

    level = _risk_level(composite_score)
    return {
        "score": composite_score,
        "level": level,
        "color": _risk_color(level),
        "details": {
            "total_incidents": len(scored_incidents),
            "active_incidents": active_count,
            "max_individual_score": primary_score,
            "severity_breakdown": sev_counts,
            "stage_diversity": len(unique_stages_all)
        },
        "actionable_drivers": actionable_drivers
    }


# ── Pillar 2: ML Anomaly Detection Risk ────────────────────────────────────────

def calculate_ml_risk(analyzed_events: List[Dict]) -> Dict:
    """Evaluate operational network and host flow anomaly probabilities across PyOD specialist models."""
    if not analyzed_events:
        return {"score": 0.0, "level": "low", "color": _risk_color("low"), "details": {}}
    total = len(analyzed_events)
    anomalies = [e for e in analyzed_events if e.get("is_anomaly")]
    anomaly_ratio = len(anomalies) / total if total > 0 else 0.0
    avg_score = sum(e.get("ml_anomaly_score", 0.0) for e in anomalies) / len(anomalies) if anomalies else 0.0
    critical_count = sum(1 for e in analyzed_events if e.get("ml_severity") == "Critical")
    high_count = sum(1 for e in analyzed_events if e.get("ml_severity") == "High")
    critical_density = (critical_count + high_count * 0.5) / total if total > 0 else 0.0
    risk_score = min(100.0, round(anomaly_ratio * 40.0 + avg_score * 35.0 + critical_density * 25.0, 1))
    level = _risk_level(risk_score)
    return {
        "score": risk_score,
        "level": level,
        "color": _risk_color(level),
        "details": {
            "total_events": total,
            "anomalies_detected": len(anomalies),
            "anomaly_ratio": round(anomaly_ratio * 100, 1),
            "avg_anomaly_score": round(avg_score, 4),
            "critical_threats": critical_count,
            "high_threats": high_count
        }
    }


# ── Pillar 3: CSPM Cloud Posture Risk ─────────────────────────────────────────

def calculate_cspm_risk(cspm_findings: List[Dict]) -> Dict:
    """Evaluate cloud infrastructure misconfigurations and exposure findings."""
    if not cspm_findings:
        return {"score": 0.0, "level": "low", "color": _risk_color("low"), "details": {}}
    sc = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in cspm_findings:
        s = f.get("severity", "low").lower()
        sc[s] = sc.get(s, 0) + 1
    raw = sc["critical"] * 25.0 + sc["high"] * 15.0 + sc["medium"] * 8.0 + sc["low"] * 3.0
    risk_score = min(100.0, round(raw, 1))
    level = _risk_level(risk_score)
    return {
        "score": risk_score,
        "level": level,
        "color": _risk_color(level),
        "details": {
            "total_findings": len(cspm_findings),
            "severity_breakdown": sc,
            "open_critical": sc["critical"],
            "open_high": sc["high"]
        }
    }


# ── Pillar 4: CIEM Identity & Entitlement Risk ─────────────────────────────────

def calculate_ciem_risk(ciem_findings: List[Dict]) -> Dict:
    """Evaluate IAM permissions, privilege escalation paths, and identity anomalies."""
    if not ciem_findings:
        return {"score": 0.0, "level": "low", "color": _risk_color("low"), "details": {}}
    rc = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    et = {"human": 0, "machine": 0, "role": 0}
    for f in ciem_findings:
        r = f.get("risk_level", "low").lower()
        rc[r] = rc.get(r, 0) + 1
        t = f.get("entity_type", "unknown")
        et[t] = et.get(t, 0) + 1
    raw = rc["critical"] * 30.0 + rc["high"] * 20.0 + rc["medium"] * 10.0 + rc["low"] * 5.0
    risk_score = min(100.0, round(raw, 1))
    level = _risk_level(risk_score)
    return {
        "score": risk_score,
        "level": level,
        "color": _risk_color(level),
        "details": {
            "total_risky_entities": len(ciem_findings),
            "risk_breakdown": rc,
            "entity_types_affected": et
        }
    }


# ── Unified Four-Pillar Composite Risk Engine ─────────────────────────────────

def calculate_unified_risk(
    analyzed_events: List[Dict],
    cspm_findings: List[Dict],
    ciem_findings: List[Dict],
    incidents: Optional[List[Dict]] = None,
    weights: Optional[Dict[str, float]] = None
) -> Dict[str, Any]:
    """
    Calculate Unified Risk score across four calibrated pillars:
      1. Incident Risk (35%) — Correlated multi-stage attack campaigns (Task 1)
      2. ML/AI Detection (25%) — PyOD operational flow anomaly probabilities
      3. CSPM Posture (20%) — Cloud security posture misconfigurations
      4. CIEM Identity (20%) — IAM entitlement and privilege exposures

    Unified Risk = 0.35 * Incident + 0.25 * ML + 0.20 * CSPM + 0.20 * CIEM
    """
    if weights is None:
        weights = {"incident": 0.35, "ml": 0.25, "cspm": 0.20, "ciem": 0.20}

    incident_risk = calculate_incident_risk(incidents or [])
    ml_risk = calculate_ml_risk(analyzed_events)
    cspm_risk = calculate_cspm_risk(cspm_findings)
    ciem_risk = calculate_ciem_risk(ciem_findings)

    w_inc = weights.get("incident", 0.35)
    w_ml = weights.get("ml", 0.25)
    w_cspm = weights.get("cspm", 0.20)
    w_ciem = weights.get("ciem", 0.20)

    unified_score = round(
        incident_risk["score"] * w_inc +
        ml_risk["score"] * w_ml +
        cspm_risk["score"] * w_cspm +
        ciem_risk["score"] * w_ciem,
        1
    )
    unified_score = min(100.0, max(0.0, unified_score))
    unified_level = _risk_level(unified_score)

    # Context-aware recommendations
    recs = []
    if incident_risk["score"] >= 45.0:
        recs.append({
            "priority": "critical" if incident_risk["score"] >= 75.0 else "high",
            "category": "Incident Correlation",
            "recommendation": f"Active threat campaign detected (Risk {incident_risk['score']}). Review attack progression.",
            "action": "Isolate compromised assets and terminate adversary sessions"
        })
    if ml_risk["score"] > 60.0:
        recs.append({
            "priority": "critical" if ml_risk["score"] > 80.0 else "high",
            "category": "ML/AI Detection",
            "recommendation": f"High anomaly rate. Review {ml_risk['details'].get('critical_threats', 0)} critical flow threats.",
            "action": "Trigger auto-remediation network playbooks"
        })
    if cspm_risk["score"] > 40.0:
        recs.append({
            "priority": "critical" if cspm_risk["score"] > 70.0 else "high",
            "category": "Cloud Posture",
            "recommendation": f"{cspm_risk['details'].get('open_critical', 0)} critical cloud misconfigurations.",
            "action": "Run CSPM auto-fix pipeline"
        })
    if ciem_risk["score"] > 40.0:
        recs.append({
            "priority": "critical" if ciem_risk["score"] > 70.0 else "high",
            "category": "Identity & Access",
            "recommendation": f"{ciem_risk['details'].get('total_risky_entities', 0)} risky IAM identities detected.",
            "action": "Revoke excessive IAM permissions"
        })
    if not recs:
        recs.append({
            "priority": "low",
            "category": "General",
            "recommendation": "All risk indicators within acceptable security thresholds.",
            "action": "Maintain active monitoring baseline"
        })

    # Threshold-triggered operational actions
    actions = {
        "escalate_to_soc": unified_score >= 80.0 or incident_risk["score"] >= 75.0,
        "auto_remediate": unified_score >= 70.0 or incident_risk["score"] >= 70.0,
        "isolate_incident_principals": incident_risk["score"] >= 60.0,
        "block_suspicious_ips": ml_risk["score"] >= 75.0 or incident_risk["score"] >= 70.0,
        "disable_risky_users": ciem_risk["score"] >= 80.0,
        "fix_configurations": cspm_risk["score"] >= 60.0,
        "generate_incident_report": unified_score >= 50.0 or incident_risk["score"] >= 45.0,
    }
    triggered = [k for k, v in actions.items() if v]

    # Actionable risk drivers: primary source is real correlated incidents
    actionable_drivers = incident_risk.get("actionable_drivers") or []
    if not actionable_drivers:
        # Fallback to posture / identity drivers if no incidents are active
        for f in (cspm_findings or [])[:2]:
            actionable_drivers.append({
                "id": f.get("vulnerability_id") or "CSPM-001",
                "title": f.get("title") or "Cloud Misconfiguration",
                "resource": f"{f.get('resource', 'cloud-resource')} ↗",
                "source": "Config · IMPORTED",
                "severity": f.get("severity", "medium"),
                "stages": ["Defense Evasion"],
                "finding_count": 1,
                "risk_score": 25.0 if f.get("severity") == "critical" else 15.0,
                "nextStep": "Review exposure →"
            })
        for f in (ciem_findings or [])[:1]:
            actionable_drivers.append({
                "id": f.get("risk_id") or "CIEM-001",
                "title": f.get("title") or "Excessive Permissions",
                "resource": f"{f.get('entity_name', 'operator')} ↗",
                "source": "IAM · IMPORTED",
                "severity": f.get("risk_level", "medium"),
                "stages": ["Privilege Escalation"],
                "finding_count": 1,
                "risk_score": 30.0 if f.get("risk_level") == "critical" else 20.0,
                "nextStep": "Review identity →"
            })

    return {
        "risk_id": f"RISK-{str(uuid.uuid4())[:8].upper()}",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "unified_risk_score": unified_score,
        "unified_risk_level": unified_level,
        "unified_risk_color": _risk_color(unified_level),
        "weights": weights,
        "components": {
            "incident_correlation": incident_risk,
            "ml_anomaly_detection": ml_risk,
            "cspm_posture": cspm_risk,
            "ciem_identity": ciem_risk
        },
        "risk_breakdown_chart": [
            {"name": "Incident Correlation", "score": incident_risk["score"], "weight": w_inc, "color": "#f43f5e"},
            {"name": "ML/AI Detection", "score": ml_risk["score"], "weight": w_ml, "color": "#8b5cf6"},
            {"name": "CSPM Posture", "score": cspm_risk["score"], "weight": w_cspm, "color": "#3b82f6"},
            {"name": "CIEM Identity", "score": ciem_risk["score"], "weight": w_ciem, "color": "#06b6d4"},
        ],
        "actionable_drivers": actionable_drivers,
        "recommendations": sorted(recs, key=lambda r: {"critical": 0, "high": 1, "medium": 2, "low": 3}[r["priority"]]),
        "threshold_actions": {
            "actions": actions,
            "triggered_count": len(triggered),
            "triggered_actions": triggered,
            "severity": unified_level
        },
    }


# ── Deterministic Risk Trend (Zero Fake Random Numbers) ─────────────────────────

def get_risk_trend(current_score: float, periods: int = 7) -> List[Dict]:
    """
    Derive risk trend strictly from recorded database history.
    Never generates fabricated random noise.
    """
    trend = get_risk_trend_db(periods)
    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    if not trend:
        # Return only Today's verified score if no history exists yet
        return [{"period": "Today", "score": current_score, "level": _risk_level(current_score)}]

    # If the last recorded period is not today, append today
    if trend[-1].get("period") != today_str and trend[-1].get("period") != "Today":
        trend.append({"period": "Today", "score": current_score, "level": _risk_level(current_score)})
    else:
        trend[-1]["period"] = "Today"
        trend[-1]["score"] = current_score
        trend[-1]["level"] = _risk_level(current_score)

    return trend
