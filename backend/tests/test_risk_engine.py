"""
Unit & Integration Test Suite for Incident-Aware Unified Risk Engine (Task 2)
=============================================================================
Verifies:
  - Test A: Empty incidents -> Incident Risk = 0
  - Test B: One low-severity single-stage incident -> Non-zero Incident Risk
  - Test C: Repeated findings in same incident -> Sub-linear / bounded increase
  - Test D: Single-stage vs multi-stage incident -> Multi-stage risk > single-stage risk
  - Test E: Two-stage vs three-stage attack -> Three-stage risk > two-stage risk
  - Test F: Blast radius expansion -> Bounded increase with resource count
  - Test G: Temporal decay -> Recent active incident scores higher than old inactive incident
  - Test H: Incident status -> Resolved incident contributes significantly reduced risk
  - Test I: Double-counting prevention -> Sublinear response to duplicated findings
  - Test J: Four-pillar unified formula -> 0.35 Incident + 0.25 ML + 0.20 CSPM + 0.20 CIEM
  - Test K: Kill-chain progression -> Full kill-chain produces materially higher risk than single probe
  - Test L: Deterministic trend generation -> Zero random numbers, returns clean historical series
  - Test M: Actionable drivers generation -> Real incident IDs and MITRE stages exposed for UI
"""
import sys
import os
import math
from datetime import datetime, timezone, timedelta
import pytest

# Ensure backend directory is in path
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from engines.risk_engine import (
    calculate_incident_risk,
    calculate_unified_risk,
    calculate_ml_risk,
    calculate_cspm_risk,
    calculate_ciem_risk,
    get_risk_trend,
    _risk_level,
    _risk_color
)


def _create_mock_incident(
    incident_id: str = "INC-TEST-001",
    title: str = None,
    severity: str = "high",
    finding_count: int = 1,
    stages: list = None,
    resources: list = None,
    principals: list = None,
    status: str = "open",
    last_seen: datetime = None
) -> dict:
    """Helper to create standardized mock incident payloads matching Task-1 schema."""
    ts = last_seen or datetime.now(timezone.utc)
    return {
        "incident_id": incident_id,
        "title": title or f"Test Incident {incident_id}",
        "severity": severity,
        "status": status,
        "finding_count": finding_count,
        "finding_ids": [f"FND-{i:03d}" for i in range(finding_count)],
        "attack_stages": stages or ["Initial Access & Credential Abuse"],
        "attack_categories": ["brute_force"],
        "resources": resources or ["web-server-01"],
        "principals": principals or ["admin"],
        "source_ips": ["198.51.100.1"],
        "start_time": (ts - timedelta(minutes=10)).isoformat(),
        "last_seen": ts.isoformat(),
        "duration_seconds": 600.0,
        "correlation_score": 0.95
    }


def test_a_no_incidents():
    """Test A: Empty incident list produces exactly zero Incident Risk."""
    res = calculate_incident_risk([])
    assert res["score"] == 0.0
    assert res["level"] == "low"
    assert res["details"]["total_incidents"] == 0
    assert res["actionable_drivers"] == []


def test_b_low_severity_single_stage():
    """Test B: One low-severity single-stage incident produces a valid, non-zero bounded score."""
    inc = _create_mock_incident(severity="low", finding_count=1, stages=["Initial Access"])
    res = calculate_incident_risk([inc])
    assert res["score"] > 0.0
    assert res["score"] <= 25.0  # Low severity should produce low score
    assert res["level"] == "low"
    assert len(res["actionable_drivers"]) == 1
    assert res["actionable_drivers"][0]["id"] == inc["incident_id"]


def test_c_diminishing_returns_finding_count():
    """Test C: Repeated findings in the same incident exhibit sub-linear growth, not linear multiplication."""
    now = datetime.now(timezone.utc)
    inc_1 = _create_mock_incident(severity="high", finding_count=1, last_seen=now)
    inc_5 = _create_mock_incident(severity="high", finding_count=5, last_seen=now)
    inc_50 = _create_mock_incident(severity="high", finding_count=50, last_seen=now)
    inc_100 = _create_mock_incident(severity="high", finding_count=100, last_seen=now)

    s1 = calculate_incident_risk([inc_1])["score"]
    s5 = calculate_incident_risk([inc_5])["score"]
    s50 = calculate_incident_risk([inc_50])["score"]
    s100 = calculate_incident_risk([inc_100])["score"]

    # 1 -> 5 findings increases meaningfully
    assert s5 > s1
    # 5 findings is NOT 5x the score of 1 finding
    assert s5 < s1 * 3.0
    # 50 -> 100 findings does NOT double the score (diminishing return)
    assert s100 > s50
    assert s100 < s50 * 1.5


def test_d_single_stage_vs_multi_stage():
    """Test D: Multi-stage incident produces higher risk than single-stage incident with equal finding count."""
    now = datetime.now(timezone.utc)
    inc_single = _create_mock_incident(
        severity="high",
        finding_count=4,
        stages=["Initial Access & Credential Abuse"],
        last_seen=now
    )
    inc_multi = _create_mock_incident(
        severity="high",
        finding_count=4,
        stages=["Initial Access & Credential Abuse", "Privilege Escalation & IAM Manipulation"],
        last_seen=now
    )

    s_single = calculate_incident_risk([inc_single])["score"]
    s_multi = calculate_incident_risk([inc_multi])["score"]

    assert s_multi > s_single
    # Verify progression ratio is approximately 1.3x
    ratio = s_multi / s_single
    assert 1.25 <= ratio <= 1.35


def test_e_two_stage_vs_three_stage():
    """Test E: Three-stage attack chain produces higher risk than two-stage attack chain."""
    now = datetime.now(timezone.utc)
    inc_2_stage = _create_mock_incident(
        severity="high",
        finding_count=6,
        stages=["Credential Access", "Privilege Escalation"],
        last_seen=now
    )
    inc_3_stage = _create_mock_incident(
        severity="high",
        finding_count=6,
        stages=["Credential Access", "Privilege Escalation", "Exfiltration"],
        last_seen=now
    )

    s2 = calculate_incident_risk([inc_2_stage])["score"]
    s3 = calculate_incident_risk([inc_3_stage])["score"]

    assert s3 > s2
    # 1.7x vs 1.3x progression multiplier
    assert s3 / s2 >= 1.25


def test_f_blast_radius_bounded_increase():
    """Test F: Compounding blast radius (multiple affected resources) increases risk with sub-linear ceiling."""
    now = datetime.now(timezone.utc)
    inc_small = _create_mock_incident(resources=["app-01"], principals=["alice"], last_seen=now)
    inc_medium = _create_mock_incident(resources=[f"app-{i}" for i in range(5)], principals=["alice"], last_seen=now)
    inc_large = _create_mock_incident(resources=[f"app-{i}" for i in range(25)], principals=["alice", "bob", "carol"], last_seen=now)

    s_small = calculate_incident_risk([inc_small])["score"]
    s_medium = calculate_incident_risk([inc_medium])["score"]
    s_large = calculate_incident_risk([inc_large])["score"]

    assert s_medium > s_small
    assert s_large > s_medium
    # 25 resources must NOT produce 25x the risk
    assert s_large < s_small * 2.0


def test_g_temporal_decay():
    """Test G: Recent active incident contributes more risk than old historical incident."""
    now = datetime.now(timezone.utc)
    inc_recent = _create_mock_incident(last_seen=now - timedelta(minutes=5))
    inc_12h = _create_mock_incident(last_seen=now - timedelta(hours=12))
    inc_48h = _create_mock_incident(last_seen=now - timedelta(hours=48))

    s_recent = calculate_incident_risk([inc_recent], current_time=now)["score"]
    s_12h = calculate_incident_risk([inc_12h], current_time=now)["score"]
    s_48h = calculate_incident_risk([inc_48h], current_time=now)["score"]

    assert s_recent > s_12h
    assert s_12h > s_48h
    # Old incident decays but stays bounded by floor
    assert s_48h >= s_recent * 0.10


def test_h_resolved_incident_reduced_risk():
    """Test H: Resolved incident has reduced active contribution compared to open incident."""
    now = datetime.now(timezone.utc)
    inc_open = _create_mock_incident(status="open", last_seen=now)
    inc_resolved = _create_mock_incident(status="resolved", last_seen=now)

    s_open = calculate_incident_risk([inc_open], current_time=now)["score"]
    s_resolved = calculate_incident_risk([inc_resolved], current_time=now)["score"]

    assert s_open > s_resolved
    # Resolved multiplier is 0.15x
    assert round(s_resolved / s_open, 2) == 0.15


def test_i_double_counting_prevention():
    """Test I: Duplicating findings within an incident does not produce linear proportional score explosion."""
    now = datetime.now(timezone.utc)
    inc_10 = _create_mock_incident(severity="high", finding_count=10, last_seen=now)
    inc_40 = _create_mock_incident(severity="high", finding_count=40, last_seen=now)

    s10 = calculate_incident_risk([inc_10])["score"]
    s40 = calculate_incident_risk([inc_40])["score"]

    # 4x findings should NOT produce 4x risk
    assert s40 < s10 * 2.0


def test_j_four_pillar_unified_formula():
    """Test J: Unified risk formula calculates exactly 0.35 Incident + 0.25 ML + 0.20 CSPM + 0.20 CIEM."""
    # Construct exact component inputs
    inc = _create_mock_incident(severity="critical", finding_count=1, stages=["Stage1"])
    inc_risk = calculate_incident_risk([inc])

    # Controlled mock findings
    analyzed_events = [{"is_anomaly": True, "ml_anomaly_score": 0.8, "ml_severity": "High"}]
    cspm_findings = [{"severity": "high"}]  # 1 high -> 15.0
    ciem_findings = [{"risk_level": "medium", "entity_type": "human"}]  # 1 med -> 10.0

    unified = calculate_unified_risk(
        analyzed_events=analyzed_events,
        cspm_findings=cspm_findings,
        ciem_findings=ciem_findings,
        incidents=[inc]
    )

    expected_score = round(
        inc_risk["score"] * 0.35 +
        unified["components"]["ml_anomaly_detection"]["score"] * 0.25 +
        15.0 * 0.20 +
        10.0 * 0.20,
        1
    )
    assert unified["unified_risk_score"] == expected_score
    assert len(unified["risk_breakdown_chart"]) == 4
    assert unified["weights"]["incident"] == 0.35
    assert unified["weights"]["ml"] == 0.25
    assert unified["weights"]["cspm"] == 0.20
    assert unified["weights"]["ciem"] == 0.20


def test_k_kill_chain_progression_vs_isolated_probe():
    """Test K: A full 4-stage kill-chain produces materially higher risk than an isolated probe."""
    now = datetime.now(timezone.utc)
    isolated_probe = _create_mock_incident(
        severity="high",
        finding_count=1,
        stages=["Credential Access"],
        last_seen=now
    )
    full_kill_chain = _create_mock_incident(
        severity="critical",
        finding_count=12,
        stages=["Credential Access", "Privilege Escalation", "Exfiltration", "Impact"],
        resources=["s3-bucket-data", "db-prod-01"],
        principals=["attacker-root"],
        last_seen=now
    )

    s_isolated = calculate_incident_risk([isolated_probe], current_time=now)["score"]
    s_campaign = calculate_incident_risk([full_kill_chain], current_time=now)["score"]

    assert s_campaign > s_isolated * 2.5
    assert s_campaign >= 75.0  # Full kill-chain reaches Critical severity tier


def test_l_deterministic_trend():
    """Test L: get_risk_trend returns deterministic data points with zero random fluctuations."""
    t1 = get_risk_trend(65.4, periods=7)
    t2 = get_risk_trend(65.4, periods=7)

    # Must be 100% deterministic (identical scores and periods)
    assert t1 == t2
    assert t1[-1]["period"] == "Today"
    assert t1[-1]["score"] == 65.4
    assert t1[-1]["level"] == "high"


def test_m_actionable_drivers_real_evidence():
    """Test M: Actionable drivers expose real incident ID, stages, and affected resources."""
    now = datetime.now(timezone.utc)
    inc = _create_mock_incident(
        incident_id="INC-CAMPAIGN-42",
        title="Multi-Vector S3 Exfiltration",
        severity="critical",
        finding_count=8,
        stages=["Exfiltration Over Web/Cloud Storage"],
        resources=["s3://prod-records"],
        last_seen=now
    )

    res = calculate_incident_risk([inc])
    drivers = res["actionable_drivers"]

    assert len(drivers) == 1
    d = drivers[0]
    assert d["id"] == "INC-CAMPAIGN-42"
    assert d["title"] == "Multi-Vector S3 Exfiltration"
    assert "s3://prod-records" in d["resource"]
    assert d["severity"] == "critical"
    assert d["stages"] == ["Exfiltration Over Web/Cloud Storage"]
    assert d["risk_score"] > 0.0


def test_n_baseline_simulation_isolation():
    """Test N: Reset to baseline isolates simulation buffer and prevents disk log clobbering."""
    from simulator.session_manager import session_manager
    session = session_manager.reset_to_baseline(n_normal=60)
    assert len(session.events) == 60
    assert len(session.findings) == 0
    assert len(session.incidents) == 0

    # Subsequent retrieval must NOT clobber the simulated session with disk logs
    s2 = session_manager.get_session()
    assert len(s2.events) == 60
    assert len(s2.findings) == 0
    assert len(s2.incidents) == 0

    risk = calculate_incident_risk(s2.incidents)
    assert risk["score"] == 0.0
    assert risk["level"] == "low"


def test_o_chronological_progression_contract():
    """Test O: Contract verification that forward kill-chain progression strictly outranks reversed sequences."""
    now = datetime.now(timezone.utc)
    fwd_stages = ["Initial Access & Credential Abuse", "Privilege Escalation & IAM Manipulation", "Exfiltration Over Web/Cloud Storage"]
    rev_stages = ["Exfiltration Over Web/Cloud Storage", "Privilege Escalation & IAM Manipulation", "Initial Access & Credential Abuse"]

    inc_fwd = _create_mock_incident(severity="critical", finding_count=3, stages=fwd_stages, last_seen=now)
    inc_rev = _create_mock_incident(severity="critical", finding_count=3, stages=rev_stages, last_seen=now)

    res_fwd = calculate_incident_risk([inc_fwd])
    res_rev = calculate_incident_risk([inc_rev])
    s_fwd = res_fwd["score"]
    s_rev = res_rev["score"]

    # Forward kill-chain progression receives 1.65x multiplier; reversed sequence receives 1.0x (zero bonus)
    assert s_fwd > s_rev
    assert s_fwd >= s_rev * 1.5
    assert res_fwd["details"]["total_incidents"] == 1
    assert res_rev["details"]["total_incidents"] == 1


def test_p_risk_ordering_sanity():
    """Test P: Validate that full multi-stage campaigns strictly outrank isolated attacks and baseline noise."""
    now = datetime.now(timezone.utc)
    inc_baseline = []
    inc_brute_force = [_create_mock_incident(severity="high", finding_count=1, stages=["Initial Access & Credential Abuse"], last_seen=now)]
    inc_priv_esc = [_create_mock_incident(severity="critical", finding_count=6, stages=["Privilege Escalation & IAM Manipulation", "Defense Evasion & Logging Impairment"], last_seen=now)]
    inc_campaign = [_create_mock_incident(severity="critical", finding_count=7, stages=["Privilege Escalation & IAM Manipulation", "Exfiltration Over Web/Cloud Storage", "Impact & Data Encryption"], last_seen=now)]

    score_base = calculate_incident_risk(inc_baseline)["score"]
    score_bf = calculate_incident_risk(inc_brute_force)["score"]
    score_pe = calculate_incident_risk(inc_priv_esc)["score"]
    score_camp = calculate_incident_risk(inc_campaign)["score"]

    assert score_base == 0.0
    assert score_bf < score_pe
    assert score_pe < score_camp

