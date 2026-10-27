"""
Chronological Kill-Chain Progression Test Suite (Task 2.1)
==========================================================
Verifies that the incident risk engine evaluates true chronological kill-chain
attack-path progression, distinguishing forward progression from reversed,
duplicate, non-monotonic, and isolated attack patterns.
"""
import pytest
from datetime import datetime, timezone, timedelta
from engines.risk_engine import (
    calculate_kill_chain_progression,
    calculate_incident_risk,
    map_stage_to_index
)


def _make_finding(stage: str, category: str, ts_offset_min: int, finding_id: str = "FIND-01") -> dict:
    """Helper to create a finding with an explicit UTC timestamp and stage."""
    base_time = datetime(2026, 10, 27, 10, 0, 0, tzinfo=timezone.utc)
    ts = (base_time + timedelta(minutes=ts_offset_min)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "finding_id": finding_id,
        "title": f"Security Finding in {stage}",
        "timestamp": ts,
        "attack_stage": stage,
        "attack_category": category,
        "severity": "high",
        "affected_resource": "cloud-host-01"
    }


def test_a_single_stage():
    """Test A: Single stage (Initial Access) produces baseline 1.0x progression multiplier."""
    inc = {
        "incident_id": "INC-TEST-A",
        "severity": "high",
        "attack_stages": ["Initial Access & Credential Abuse"],
        "findings": [_make_finding("Initial Access & Credential Abuse", "brute_force", 0)]
    }
    mult, details = calculate_kill_chain_progression(inc)
    assert mult == 1.0
    assert details["progression_type"] == "single_stage"
    assert details["forward_stages"] == 1


def test_b_valid_two_stage_progression():
    """Test B: Valid 2-stage progression (Initial Access -> Privilege Escalation) receives moderate 1.30x multiplier."""
    inc = {
        "incident_id": "INC-TEST-B",
        "severity": "critical",
        "attack_stages": ["Initial Access & Credential Abuse", "Privilege Escalation & IAM Manipulation"],
        "findings": [
            _make_finding("Initial Access & Credential Abuse", "brute_force", 0, "F1"),
            _make_finding("Privilege Escalation & IAM Manipulation", "iam_privilege_escalation", 5, "F2"),
        ]
    }
    mult, details = calculate_kill_chain_progression(inc)
    assert mult == 1.30
    assert details["progression_type"] == "two_stage_contiguous"
    assert details["lis_len"] == 2
    assert details["r_fwd"] == 1.0


def test_c_valid_three_stage_progression():
    """Test C: Valid 3-stage progression (Initial Access -> Privilege Escalation -> Exfiltration) receives strong multiplier."""
    inc = {
        "incident_id": "INC-TEST-C",
        "severity": "critical",
        "attack_stages": ["Initial Access & Credential Abuse", "Privilege Escalation & IAM Manipulation", "Exfiltration Over Web/Cloud Storage"],
        "findings": [
            _make_finding("Initial Access & Credential Abuse", "brute_force", 0, "F1"),
            _make_finding("Privilege Escalation & IAM Manipulation", "iam_privilege_escalation", 5, "F2"),
            _make_finding("Exfiltration Over Web/Cloud Storage", "data_exfiltration", 10, "F3"),
        ]
    }
    mult, details = calculate_kill_chain_progression(inc)
    assert mult >= 1.60
    assert details["progression_type"] == "three_stage_progression"
    assert details["lis_len"] == 3
    assert details["r_fwd"] == 1.0


def test_d_full_progression():
    """Test D: Full 5-stage progression receives maximum bounded progression multiplier (1.70x)."""
    inc = {
        "incident_id": "INC-TEST-D",
        "severity": "critical",
        "attack_stages": [
            "Initial Access & Credential Abuse",
            "Privilege Escalation & IAM Manipulation",
            "Defense Evasion & Logging Impairment",
            "Exfiltration Over Web/Cloud Storage",
            "Impact & Data Encryption"
        ],
        "findings": [
            _make_finding("Initial Access & Credential Abuse", "brute_force", 0, "F1"),
            _make_finding("Privilege Escalation & IAM Manipulation", "iam_privilege_escalation", 5, "F2"),
            _make_finding("Defense Evasion & Logging Impairment", "defense_tampering", 10, "F3"),
            _make_finding("Exfiltration Over Web/Cloud Storage", "data_exfiltration", 15, "F4"),
            _make_finding("Impact & Data Encryption", "malware_ransomware", 20, "F5"),
        ]
    }
    mult, details = calculate_kill_chain_progression(inc)
    assert mult == 1.70
    assert details["progression_type"] == "full_kill_chain"
    assert details["lis_len"] == 5
    assert details["r_fwd"] == 1.0


def test_e_reversed_sequence():
    """Test E: Reversed sequence (Impact -> Exfiltration -> PrivEsc -> Initial Access) receives NO progression bonus (1.0x)."""
    inc_fwd = {
        "incident_id": "INC-FWD",
        "severity": "critical",
        "findings": [
            _make_finding("Initial Access & Credential Abuse", "brute_force", 0, "F1"),
            _make_finding("Privilege Escalation & IAM Manipulation", "iam_privilege_escalation", 5, "F2"),
            _make_finding("Exfiltration Over Web/Cloud Storage", "data_exfiltration", 10, "F3"),
            _make_finding("Impact & Data Encryption", "malware_ransomware", 15, "F4"),
        ]
    }
    inc_rev = {
        "incident_id": "INC-REV",
        "severity": "critical",
        "findings": [
            _make_finding("Impact & Data Encryption", "malware_ransomware", 0, "F4"),
            _make_finding("Exfiltration Over Web/Cloud Storage", "data_exfiltration", 5, "F3"),
            _make_finding("Privilege Escalation & IAM Manipulation", "iam_privilege_escalation", 10, "F2"),
            _make_finding("Initial Access & Credential Abuse", "brute_force", 15, "F1"),
        ]
    }

    mult_fwd, details_fwd = calculate_kill_chain_progression(inc_fwd)
    mult_rev, details_rev = calculate_kill_chain_progression(inc_rev)

    assert mult_fwd == 1.70
    assert mult_rev == 1.0
    assert details_rev["progression_type"] == "reversed_or_retrograde"
    assert details_rev["r_fwd"] == 0.0

    score_fwd = calculate_incident_risk([inc_fwd])["score"]
    score_rev = calculate_incident_risk([inc_rev])["score"]
    assert score_fwd > score_rev
    assert score_fwd >= score_rev * 1.5


def test_f_duplicate_stage():
    """Test F: Duplicate findings in the same stage (Initial Access x 3) collapse to single-stage 1.0x."""
    inc = {
        "incident_id": "INC-TEST-F",
        "severity": "high",
        "attack_stages": ["Initial Access & Credential Abuse", "Initial Access & Credential Abuse", "Initial Access & Credential Abuse"],
        "findings": [
            _make_finding("Initial Access & Credential Abuse", "brute_force", 0, "F1"),
            _make_finding("Initial Access & Credential Abuse", "brute_force", 1, "F2"),
            _make_finding("Initial Access & Credential Abuse", "brute_force", 2, "F3"),
        ]
    }
    mult, details = calculate_kill_chain_progression(inc)
    assert mult == 1.0
    assert details["progression_type"] == "single_stage"
    assert len(details["stage_indices"]) == 1


def test_g_partial_progression_jump():
    """Test G: Partial progression with gap (Initial Access -> Exfiltration) receives lower score than contiguous progression."""
    inc_contiguous = {
        "incident_id": "INC-CONTIG",
        "severity": "high",
        "attack_stages": ["Initial Access & Credential Abuse", "Privilege Escalation & IAM Manipulation"],
        "findings": [
            _make_finding("Initial Access & Credential Abuse", "brute_force", 0, "F1"),
            _make_finding("Privilege Escalation & IAM Manipulation", "iam_privilege_escalation", 5, "F2"),
        ]
    }
    inc_gapped = {
        "incident_id": "INC-GAPPED",
        "severity": "high",
        "attack_stages": ["Initial Access & Credential Abuse", "Exfiltration Over Web/Cloud Storage"],
        "findings": [
            _make_finding("Initial Access & Credential Abuse", "brute_force", 0, "F1"),
            _make_finding("Exfiltration Over Web/Cloud Storage", "data_exfiltration", 5, "F3"),
        ]
    }

    mult_contig, _ = calculate_kill_chain_progression(inc_contiguous)
    mult_gapped, details_gapped = calculate_kill_chain_progression(inc_gapped)

    assert mult_contig == 1.30
    assert mult_gapped == 1.20
    assert mult_gapped < mult_contig
    assert details_gapped["progression_type"] == "two_stage_partial"


def test_h_same_stage_repeated_findings_different_timestamps():
    """Test H: Multiple repeated findings in the same stage over an extended time interval remain single-stage."""
    findings = [_make_finding("Initial Access & Credential Abuse", "brute_force", i * 10, f"BF-{i}") for i in range(10)]
    inc = {
        "incident_id": "INC-TEST-H",
        "severity": "high",
        "findings": findings
    }
    mult, details = calculate_kill_chain_progression(inc)
    assert mult == 1.0
    assert details["progression_type"] == "single_stage"
    assert details["stage_indices"] == [1]


def test_i_non_monotonic_stage_sequence():
    """Test I: Non-monotonic / out-of-order sequence (Exfil -> Initial Access -> PrivEsc) receives discounted progression."""
    inc_non_monotonic = {
        "incident_id": "INC-TEST-I",
        "severity": "critical",
        "attack_stages": ["Exfiltration Over Web/Cloud Storage", "Initial Access & Credential Abuse", "Privilege Escalation & IAM Manipulation"],
        "findings": [
            _make_finding("Exfiltration Over Web/Cloud Storage", "data_exfiltration", 0, "F1"),
            _make_finding("Initial Access & Credential Abuse", "brute_force", 5, "F2"),
            _make_finding("Privilege Escalation & IAM Manipulation", "iam_privilege_escalation", 10, "F3"),
        ]
    }
    mult, details = calculate_kill_chain_progression(inc_non_monotonic)

    # 1 backward transition (4 -> 1), 1 forward transition (1 -> 2) -> r_fwd = 0.5
    # LIS is [1, 2] (len 2 contiguous, p_base = 1.30) -> 1.0 + (1.30 - 1.0) * 0.5 = 1.15
    assert mult == 1.15
    assert details["r_fwd"] == 0.5
    assert details["lis_len"] == 2
    assert mult < 1.30  # Strictly less than pure forward 2-stage


def test_j_real_task1_correlated_multi_stage_campaign():
    """Test J: Verify real Task-1 correlated multi-stage incident produces strong progression evidence."""
    from engines.correlation_engine import correlate_findings

    now = datetime(2026, 10, 27, 12, 0, 0, tzinfo=timezone.utc)
    findings = [
        {
            "finding_id": "FIND-J-01",
            "title": "SSH Brute Force",
            "timestamp": (now + timedelta(minutes=0)).isoformat(),
            "attack_category": "brute_force",
            "attack_stage": "Initial Access & Credential Abuse",
            "severity": "high",
            "affected_resource": "ssh-auth",
            "evidence": {"telemetry_fields": {"user": "attacker-joe", "source_ip": "198.51.100.42"}}
        },
        {
            "finding_id": "FIND-J-02",
            "title": "IAM Backdoor Policy",
            "timestamp": (now + timedelta(minutes=4)).isoformat(),
            "attack_category": "iam_privilege_escalation",
            "attack_stage": "Privilege Escalation & IAM Manipulation",
            "severity": "critical",
            "affected_resource": "iam-role-admin",
            "evidence": {"telemetry_fields": {"user": "attacker-joe", "source_ip": "198.51.100.42"}}
        },
        {
            "finding_id": "FIND-J-03",
            "title": "S3 High-Volume Exfiltration",
            "timestamp": (now + timedelta(minutes=8)).isoformat(),
            "attack_category": "data_exfiltration",
            "attack_stage": "Exfiltration Over Web/Cloud Storage",
            "severity": "critical",
            "affected_resource": "s3-customer-bucket",
            "evidence": {"telemetry_fields": {"user": "attacker-joe", "source_ip": "198.51.100.42"}}
        }
    ]

    incidents = correlate_findings(findings)
    assert len(incidents) == 1
    inc = incidents[0].model_dump(mode="json")

    mult, details = calculate_kill_chain_progression(inc)
    assert mult >= 1.60
    assert details["lis_len"] == 3
    assert details["r_fwd"] == 1.0

    risk_res = calculate_incident_risk([inc])
    assert risk_res["score"] >= 75.0
    assert risk_res["level"] == "critical"
