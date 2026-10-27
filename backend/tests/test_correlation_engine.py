"""
Unit & Integration Tests for Deterministic Incident Correlation Engine
======================================================================
Verifies:
1. Test 1 — Same attack chain (1 incident, N findings)
2. Test 2 — Same IP but unrelated context (separate incidents)
3. Test 3 — Different users/entities (separate incidents)
4. Test 4 — Temporal boundary (within window vs outside window)
5. Test 5 — Multi-stage attack progression (1 incident)
6. Test 6 — Unrelated simultaneous events (multiple incidents)
7. Test 7 — Idempotency (repeated correlation produces identical incident IDs)
8. Test 8 — Existing findings preservation (original findings intact and unmutated)
"""
import sys
import os
import copy
from datetime import datetime, timezone, timedelta
import pytest

# Ensure backend and pylibs in path
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from schemas.finding import SecurityFinding, FindingEvidence, RecommendedResponse
from schemas.incident import SecurityIncident
from engines.correlation_engine import (
    correlate_findings,
    evaluate_finding_pair_correlation,
    generate_incident_id,
    DEFAULT_CORRELATION_WINDOW_SECONDS
)


def _make_finding(
    finding_id: str,
    category: str,
    principal: str,
    resource: str,
    source_ip: str,
    timestamp: datetime,
    severity: str = "high",
    title: str = None
) -> SecurityFinding:
    """Helper to construct clean, deterministic SecurityFinding objects."""
    evidence = FindingEvidence(
        observed_facts=[f"Detected {category} on {resource}"],
        triggering_event_ids=[f"EVT-{finding_id}"],
        telemetry_fields={"source_ip": source_ip, "principal": principal, "resource": resource}
    )
    response = RecommendedResponse(
        action="Isolate host and revoke session",
        playbook_id="PB-BF-001" if "brute" in category else "PB-IAM-001"
    )
    return SecurityFinding(
        finding_id=finding_id,
        attack_category=category,
        category_index=1,
        title=title or f"Finding {category} on {resource}",
        severity=severity,
        confidence=0.92,
        affected_resource=resource,
        affected_principal=principal,
        evidence=evidence,
        recommended_response=response,
        created_at=timestamp
    )


# ══════════════════════════════════════════════════════════════════════════════
# Test 1 — Same attack chain
# ══════════════════════════════════════════════════════════════════════════════
def test_same_attack_chain_correlates_to_one_incident():
    """
    Several findings with:
    - same principal ('attacker_compromised')
    - same source IP ('198.51.100.25')
    - nearby timestamps (within 5 minutes)
    - related attack stages (Credential Access -> Privilege Escalation)
    Expected: Exactly 1 incident containing all N findings.
    """
    base_time = datetime(2026, 10, 27, 10, 0, 0, tzinfo=timezone.utc)
    findings = [
        _make_finding("F-101", "brute_force", "attacker_compromised", "auth-service", "198.51.100.25", base_time),
        _make_finding("F-102", "account_takeover", "attacker_compromised", "auth-service", "198.51.100.25", base_time + timedelta(seconds=60)),
        _make_finding("F-103", "iam_privilege_escalation", "attacker_compromised", "iam::role/Admin", "198.51.100.25", base_time + timedelta(seconds=180)),
    ]

    incidents = correlate_findings(findings, window_seconds=900)

    assert len(incidents) == 1, f"Expected 1 correlated incident, got {len(incidents)}"
    inc = incidents[0]
    assert inc.finding_count == 3
    assert set(inc.finding_ids) == {"F-101", "F-102", "F-103"}
    assert "attacker_compromised" in inc.principals
    assert "198.51.100.25" in inc.source_ips
    assert inc.correlation_score >= 0.85
    assert len(inc.correlation_reasons) > 0


# ══════════════════════════════════════════════════════════════════════════════
# Test 2 — Same IP but unrelated context
# ══════════════════════════════════════════════════════════════════════════════
def test_same_ip_unrelated_context_separate_incidents():
    """
    Same IP (e.g. shared NAT gateway or VPN), but:
    - different principals
    - completely different unrelated resources
    - far apart in time or separate contexts without corroborating signals
    Expected: Separate incidents (avoid false grouping on IP alone).
    """
    base_time = datetime(2026, 10, 27, 10, 0, 0, tzinfo=timezone.utc)
    shared_ip = "203.0.113.50"

    finding_a = _make_finding("F-NAT-1", "cloud_misconfiguration", "alice@corp.io", "s3-public-bucket", shared_ip, base_time)
    # Finding B occurs with a completely different user and resource
    finding_b = _make_finding("F-NAT-2", "serverless_abuse", "lambda-runner@cloud", "lambda-fn-processor", shared_ip, base_time + timedelta(seconds=600))

    incidents = correlate_findings([finding_a, finding_b], window_seconds=900)

    # Because principals and resources differ completely, same IP alone must NOT force correlation
    assert len(incidents) == 2, f"Expected 2 separate incidents to avoid false grouping on IP, got {len(incidents)}"
    inc_ids_a = [i.finding_ids for i in incidents]
    assert ["F-NAT-1"] in inc_ids_a
    assert ["F-NAT-2"] in inc_ids_a


# ══════════════════════════════════════════════════════════════════════════════
# Test 3 — Different users/entities
# ══════════════════════════════════════════════════════════════════════════════
def test_different_users_entities_separate_incidents():
    """
    Different identities, different source IPs, and unrelated resources.
    Expected: Separate incidents.
    """
    base_time = datetime(2026, 10, 27, 10, 0, 0, tzinfo=timezone.utc)
    finding_1 = _make_finding("F-USR-1", "brute_force", "bob@corp.io", "vpc-east-app", "192.0.2.10", base_time)
    finding_2 = _make_finding("F-USR-2", "cryptomining", "charlie@corp.io", "ec2-worker-99", "198.51.100.99", base_time + timedelta(seconds=120))

    incidents = correlate_findings([finding_1, finding_2], window_seconds=900)

    assert len(incidents) == 2, f"Expected 2 separate incidents, got {len(incidents)}"


# ══════════════════════════════════════════════════════════════════════════════
# Test 4 — Temporal boundary
# ══════════════════════════════════════════════════════════════════════════════
def test_temporal_boundary_inside_and_outside_window():
    """
    Findings just inside the correlation window (e.g. 14 min apart, window=15 min) should correlate.
    Findings outside the window (e.g. 20 min apart) should NOT correlate.
    """
    window = 900  # 15 minutes
    t0 = datetime(2026, 10, 27, 10, 0, 0, tzinfo=timezone.utc)
    t_inside = t0 + timedelta(seconds=840)   # 14 min (inside)
    t_outside = t0 + timedelta(seconds=1200) # 20 min (outside)

    # Pair A: inside window
    f_anchor = _make_finding("F-T0", "brute_force", "dev-user", "auth-portal", "198.51.100.1", t0)
    f_inside = _make_finding("F-TIN", "account_takeover", "dev-user", "auth-portal", "198.51.100.1", t_inside)

    incidents_inside = correlate_findings([f_anchor, f_inside], window_seconds=window)
    assert len(incidents_inside) == 1, "Findings within 14 min should correlate inside 15 min window"

    # Pair B: outside window
    f_outside = _make_finding("F-TOUT", "account_takeover", "dev-user", "auth-portal", "198.51.100.1", t_outside)
    incidents_outside = correlate_findings([f_anchor, f_outside], window_seconds=window)
    assert len(incidents_outside) == 2, "Findings 20 min apart should NOT correlate in 15 min window"


# ══════════════════════════════════════════════════════════════════════════════
# Test 5 — Multi-stage attack progression
# ══════════════════════════════════════════════════════════════════════════════
def test_multi_stage_attack_progression():
    """
    Adversary execution chain:
    Brute Force -> Successful Login/Account Takeover -> IAM Privilege Escalation -> Data Exfiltration.
    Expected: Exactly 1 unified correlated attack campaign.
    """
    t0 = datetime(2026, 10, 27, 11, 0, 0, tzinfo=timezone.utc)
    findings = [
        _make_finding("F-STG-1", "brute_force", "compromised_service_account", "portal-login", "198.51.100.77", t0),
        _make_finding("F-STG-2", "account_takeover", "compromised_service_account", "portal-login", "198.51.100.77", t0 + timedelta(seconds=45)),
        _make_finding("F-STG-3", "iam_privilege_escalation", "compromised_service_account", "iam::role/BillingAdmin", "198.51.100.77", t0 + timedelta(seconds=120)),
        _make_finding("F-STG-4", "data_exfiltration", "compromised_service_account", "s3::corporate-financials", "198.51.100.77", t0 + timedelta(seconds=240), severity="critical"),
    ]

    incidents = correlate_findings(findings, window_seconds=900)

    assert len(incidents) == 1, f"Expected 1 multi-stage campaign incident, got {len(incidents)}"
    inc = incidents[0]
    assert inc.finding_count == 4
    assert len(inc.attack_stages) >= 3
    assert inc.duration_seconds == 240.0
    assert inc.severity == "critical"
    assert "compromised_service_account" in inc.principals
    assert "198.51.100.77" in inc.source_ips


# ══════════════════════════════════════════════════════════════════════════════
# Test 6 — Unrelated simultaneous events
# ══════════════════════════════════════════════════════════════════════════════
def test_unrelated_simultaneous_events_remain_separate():
    """
    Multiple unrelated users and resources generating findings at the exact same second.
    Expected: Each distinct identity/target forms its own incident.
    """
    exact_time = datetime(2026, 10, 27, 12, 0, 0, tzinfo=timezone.utc)
    findings = [
        _make_finding("F-SIM-1", "cloud_misconfiguration", "user_alpha", "s3-bucket-alpha", "10.0.1.1", exact_time),
        _make_finding("F-SIM-2", "cryptomining", "user_beta", "ec2-instance-beta", "10.0.2.2", exact_time),
        _make_finding("F-SIM-3", "database_attacks", "user_gamma", "rds-cluster-gamma", "10.0.3.3", exact_time),
    ]

    incidents = correlate_findings(findings, window_seconds=900)

    assert len(incidents) == 3, f"Expected 3 separate incidents, got {len(incidents)}"
    found_ids = {tuple(i.finding_ids) for i in incidents}
    assert found_ids == {("F-SIM-1",), ("F-SIM-2",), ("F-SIM-3",)}


# ══════════════════════════════════════════════════════════════════════════════
# Test 7 — Idempotency of incident correlation
# ══════════════════════════════════════════════════════════════════════════════
def test_correlation_is_idempotent():
    """
    Running correlation repeatedly on the exact same findings produces:
    - the exact same number of incidents
    - the exact same incident IDs
    - identical correlation scores
    """
    base_time = datetime(2026, 10, 27, 10, 0, 0, tzinfo=timezone.utc)
    findings = [
        _make_finding("F-IDM-1", "brute_force", "admin", "login-portal", "1.2.3.4", base_time),
        _make_finding("F-IDM-2", "iam_privilege_escalation", "admin", "role-admin", "1.2.3.4", base_time + timedelta(seconds=30)),
    ]

    run1 = correlate_findings(findings, window_seconds=900)
    run2 = correlate_findings(findings, window_seconds=900)

    assert len(run1) == len(run2) == 1
    assert run1[0].incident_id == run2[0].incident_id
    assert run1[0].correlation_score == run2[0].correlation_score
    assert run1[0].finding_ids == run2[0].finding_ids
    assert run1[0].title == run2[0].title


# ══════════════════════════════════════════════════════════════════════════════
# Test 8 — Existing findings preservation
# ══════════════════════════════════════════════════════════════════════════════
def test_findings_preservation_not_mutated_or_deleted():
    """
    Verify that correlation leaves original finding objects completely intact:
    - fields are unchanged
    - finding count in and out are conserved
    - member findings inside the incident match the input findings
    """
    base_time = datetime(2026, 10, 27, 10, 0, 0, tzinfo=timezone.utc)
    original_findings = [
        _make_finding("F-PRS-1", "brute_force", "victim_user", "res-1", "10.0.0.1", base_time),
        _make_finding("F-PRS-2", "account_takeover", "victim_user", "res-1", "10.0.0.1", base_time + timedelta(seconds=40)),
    ]
    # Deep copy for strict comparison
    baseline_copy = copy.deepcopy(original_findings)

    incidents = correlate_findings(original_findings, window_seconds=900)

    # 1. Original input list was not mutated or lost
    assert len(original_findings) == 2
    for orig, base in zip(original_findings, baseline_copy):
        assert orig.finding_id == base.finding_id
        assert orig.title == base.title
        assert orig.severity == base.severity
        assert orig.attack_category == base.attack_category
        assert orig.created_at == base.created_at

    # 2. Member findings inside the generated incident match originals
    inc = incidents[0]
    assert len(inc.findings) == 2
    inc_f_ids = [f["finding_id"] if isinstance(f, dict) else f.finding_id for f in inc.findings]
    assert inc_f_ids == ["F-PRS-1", "F-PRS-2"]


# ══════════════════════════════════════════════════════════════════════════════
# Test 9 (Step 7) — Hub-Node Transitive Bridge Prevention (Alice/Bob on apache2)
# ══════════════════════════════════════════════════════════════════════════════
def test_hub_node_apache2_does_not_bridge_unrelated_users():
    """
    Exact failure found during verification:
      Finding A: Alice -> apache2 (privilege escalation, IP 10.0.1.1)
      Finding B: Bob   -> apache2 (data exfiltration, IP 10.0.1.2)
      Finding C: Bob   -> S3      (data exfiltration, IP 10.0.1.2)

    Expected:
      NOT ONE MEGA INCIDENT!
      Alice@apache2 must NOT be merged with Bob's attack chain!
      Alice forms 1 separate incident.
      Bob's findings (sharing principal and IP) form Bob's 2-finding incident.
    """
    t0 = datetime(2026, 10, 27, 10, 0, 0, tzinfo=timezone.utc)
    f_alice = _make_finding("F-ALICE", "iam_privilege_escalation", "alice", "apache2", "10.0.1.1", t0)
    f_bob_apache = _make_finding("F-BOB-1", "data_exfiltration", "bob", "apache2", "10.0.1.2", t0 + timedelta(seconds=60))
    f_bob_s3 = _make_finding("F-BOB-2", "data_exfiltration", "bob", "s3::finance-docs", "10.0.1.2", t0 + timedelta(seconds=120))

    incidents = correlate_findings([f_alice, f_bob_apache, f_bob_s3], window_seconds=900)

    assert len(incidents) == 2, f"Expected exactly 2 separate incidents, got {len(incidents)}"

    # Find the incident containing Alice
    alice_incs = [i for i in incidents if "F-ALICE" in i.finding_ids]
    assert len(alice_incs) == 1
    assert alice_incs[0].finding_count == 1
    assert "bob" not in alice_incs[0].principals
    assert "s3::finance-docs" not in alice_incs[0].resources

    # Find the incident containing Bob's activities
    bob_incs = [i for i in incidents if "F-BOB-1" in i.finding_ids]
    assert len(bob_incs) == 1
    assert bob_incs[0].finding_count == 2
    assert set(bob_incs[0].finding_ids) == {"F-BOB-1", "F-BOB-2"}
    assert "alice" not in bob_incs[0].principals


# ══════════════════════════════════════════════════════════════════════════════
# Test 10 (Step 8) — Same Principal Over-Grouping Prevention (root on S3, EC2, RDS)
# ══════════════════════════════════════════════════════════════════════════════
def test_same_principal_without_corroborating_signals_not_grouped():
    """
    Exact scenario:
      10:00 | principal = root | resource = S3  | attack = data_exfiltration
      10:02 | principal = root | resource = EC2 | attack = cloud_misconfiguration
      10:04 | principal = root | resource = RDS | attack = database_attacks

    Without same IP, same resource, or kill-chain progression across tiers:
    Expected: NOT automatically one incident. Must remain 3 separate incidents.
    """
    t0 = datetime(2026, 10, 27, 10, 0, 0, tzinfo=timezone.utc)
    # Different IPs and disjoint resources with unrelated activities
    f1 = _make_finding("F-ROOT-1", "data_exfiltration", "root", "s3::assets", "192.0.2.1", t0)
    f2 = _make_finding("F-ROOT-2", "cloud_misconfiguration", "root", "compute::ec2-prod", "198.51.100.2", t0 + timedelta(seconds=120))
    f3 = _make_finding("F-ROOT-3", "database_attacks", "root", "database::rds-main", "203.0.113.3", t0 + timedelta(seconds=240))

    incidents = correlate_findings([f1, f2, f3], window_seconds=900)

    assert len(incidents) == 3, f"Expected 3 separate incidents for root on disjoint resources/IPs, got {len(incidents)}"


# ══════════════════════════════════════════════════════════════════════════════
# Test 11 (Step 9) — Genuine Attack Chain Supported by Entity Context
# ══════════════════════════════════════════════════════════════════════════════
def test_genuine_attack_chain_correlates_to_one_incident():
    """
    Multi-stage adversary campaign with matching context:
      Brute Force (Initial Access)
      -> Successful Login / Account Takeover (Credential Access)
      -> IAM Privilege Escalation (Privilege Escalation)
      -> Data Exfiltration (Impact / Exfiltration)
    All by same attacker identity and originating IP.
    Expected: Exactly ONE unified incident.
    """
    t0 = datetime(2026, 10, 27, 11, 0, 0, tzinfo=timezone.utc)
    findings = [
        _make_finding("F-CHAIN-1", "brute_force", "adv_operator", "auth-portal", "198.51.100.99", t0),
        _make_finding("F-CHAIN-2", "account_takeover", "adv_operator", "auth-portal", "198.51.100.99", t0 + timedelta(seconds=30)),
        _make_finding("F-CHAIN-3", "iam_privilege_escalation", "adv_operator", "iam::role/SecurityAdmin", "198.51.100.99", t0 + timedelta(seconds=90)),
        _make_finding("F-CHAIN-4", "data_exfiltration", "adv_operator", "s3::corporate-vault", "198.51.100.99", t0 + timedelta(seconds=180), severity="critical"),
    ]

    incidents = correlate_findings(findings, window_seconds=900)

    assert len(incidents) == 1, f"Expected 1 multi-stage campaign incident, got {len(incidents)}"
    inc = incidents[0]
    assert inc.finding_count == 4
    assert len(inc.attack_stages) >= 3
    assert inc.severity == "critical"
    assert "adv_operator" in inc.principals
    assert "198.51.100.99" in inc.source_ips


# ══════════════════════════════════════════════════════════════════════════════
# Test 12 (Step 10) — Unrelated Users on Disjoint Resources
# ══════════════════════════════════════════════════════════════════════════════
def test_unrelated_users_disjoint_resources_remain_separate():
    """
    Alice -> S3 (IP 10.0.1.10)
    Bob   -> EC2 (IP 10.0.2.20)
    Charlie -> RDS (IP 10.0.3.30)
    Occurring within the same 15-minute window.
    Expected: Exactly 3 separate incidents.
    """
    t0 = datetime(2026, 10, 27, 10, 0, 0, tzinfo=timezone.utc)
    findings = [
        _make_finding("F-DISJ-1", "data_exfiltration", "alice", "s3::public-docs", "10.0.1.10", t0),
        _make_finding("F-DISJ-2", "cryptomining", "bob", "compute::worker-node", "10.0.2.20", t0 + timedelta(seconds=60)),
        _make_finding("F-DISJ-3", "database_attacks", "charlie", "rds::user-db", "10.0.3.30", t0 + timedelta(seconds=120)),
    ]

    incidents = correlate_findings(findings, window_seconds=900)

    assert len(incidents) == 3, f"Expected 3 separate incidents, got {len(incidents)}"


# ══════════════════════════════════════════════════════════════════════════════
# Test 13 (Step 11) — Legitimate Shared Resource Multi-Vector Attack
# ══════════════════════════════════════════════════════════════════════════════
def test_legitimate_multi_vector_resource_attack_correlates():
    """
    Multiple findings legitimately targeting the same dedicated resource
    from the same attacker source IP:
      Finding 1: BOLA/SSRF exploit targeting api-gateway-prod from 198.51.100.55
      Finding 2: Data Exfiltration from api-gateway-prod from 198.51.100.55
    Expected: Exactly ONE correlated incident.
    """
    t0 = datetime(2026, 10, 27, 10, 0, 0, tzinfo=timezone.utc)
    f1 = _make_finding("F-RES-1", "bola_ssrf", None, "api-gateway-prod", "198.51.100.55", t0)
    f2 = _make_finding("F-RES-2", "data_exfiltration", None, "api-gateway-prod", "198.51.100.55", t0 + timedelta(seconds=90), severity="critical")

    incidents = correlate_findings([f1, f2], window_seconds=900)

    assert len(incidents) == 1, f"Expected 1 correlated incident for targeted attack on api-gateway-prod, got {len(incidents)}"
    assert incidents[0].finding_count == 2
    assert "api-gateway-prod" in incidents[0].resources
    assert "198.51.100.55" in incidents[0].source_ips

