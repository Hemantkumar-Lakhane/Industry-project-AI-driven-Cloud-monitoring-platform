"""
Comprehensive Unit & Integration Tests for Attack Category 1: Brute-Force Detector
==================================================================================
Covers:
- Five or more failures within 60 seconds (positive finding)
- Fewer than five failures (no false positive)
- Failures spread outside 60s window (no alert)
- Separate target identities and source IPs (no cross-contamination)
- Benign successful logins (no false positive)
- Breach detection: burst followed by successful login elevates to CRITICAL
- Missing/malformed fields, dirty timestamps, null users
- Duplicate events and out-of-order chronological arrival
- 60-second window exact boundary conditions
- Finding schema and evidence correctness
- DetectorRegistry registration and FastAPI endpoint integration
- ML inference protection against 9D feature mismatch

NOTE: All test fixtures below are synthetic, labeled simulation fixtures.
"""
import sys
import os
import pytest
from datetime import datetime, timezone, timedelta
import numpy as np

# Ensure backend directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient
from main import app
from schemas.event import NormalizedEvent, normalize_event
from schemas.finding import SecurityFinding
from engines.base_detector import detector_registry
from engines.detectors.brute_force import (
    BruteForceDetector,
    brute_force_detector,
    _is_auth_failure,
    _is_auth_success
)
from engines.ml_engine import (
    score_flow_features,
    _scale_for,
    get_model_info,
    FEATURES
)

client = TestClient(app)


# ══════════════════════════════════════════════════════════════════════════════
# Helper to build simulated test events
# ══════════════════════════════════════════════════════════════════════════════

def _make_failure_event(
    event_id: str,
    seconds_offset: float,
    user: str = "alice",
    src_ip: str = "192.0.2.1",
    rule_id: int = 5710,
    base_time: datetime = None
) -> NormalizedEvent:
    """Creates a simulated authentication failure event at a specific time offset."""
    if base_time is None:
        base_time = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)
    ts = base_time + timedelta(seconds=seconds_offset)
    return normalize_event({
        "id": event_id,
        "timestamp": ts.isoformat(),
        "source": "synthetic_test",
        "rule_id": rule_id,
        "user": user,
        "src_ip": src_ip,
        "action": "ConsoleLogin",
        "status": "failure",
        "service": "iam",
        "failed_attempts": 1,
        "description": f"[Simulated Test] Failed login attempt for {user}"
    })


def _make_success_event(
    event_id: str,
    seconds_offset: float,
    user: str = "alice",
    src_ip: str = "192.0.2.1",
    base_time: datetime = None
) -> NormalizedEvent:
    """Creates a simulated benign successful login event."""
    if base_time is None:
        base_time = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)
    ts = base_time + timedelta(seconds=seconds_offset)
    return normalize_event({
        "id": event_id,
        "timestamp": ts.isoformat(),
        "source": "synthetic_test",
        "rule_id": 5715,
        "user": user,
        "src_ip": src_ip,
        "action": "ConsoleLogin",
        "status": "success",
        "service": "iam",
        "failed_attempts": 0,
        "description": f"[Simulated Test] Successful login for {user}"
    })


# ══════════════════════════════════════════════════════════════════════════════
# 1. Core Detection Tests (Positive, Negative, Boundary)
# ══════════════════════════════════════════════════════════════════════════════

def test_brute_force_five_failures_within_window():
    """Verify that 5 failed attempts in 30 seconds triggers a HIGH severity finding."""
    detector = BruteForceDetector(failure_threshold=5, window_seconds=60.0)
    events = [
        _make_failure_event(f"SIM-BF-{i}", seconds_offset=i * 6.0, user="target_user", src_ip="198.51.100.10")
        for i in range(5)
    ]
    findings = detector.detect(events)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.attack_category == "brute_force"
    assert finding.category_index == 1
    assert finding.severity == "high"
    assert finding.affected_principal == "target_user"
    assert finding.recommended_response.playbook_id == "PB-BF-001"
    assert finding.recommended_response.is_dry_run_supported is True
    assert len(finding.evidence.triggering_event_ids) == 5
    assert "5 consecutive authentication failures" in finding.evidence.observed_facts[0]


def test_brute_force_fewer_than_threshold_no_alert():
    """Verify that fewer than 5 failures (e.g. 4) produces zero findings."""
    detector = BruteForceDetector(failure_threshold=5, window_seconds=60.0)
    events = [
        _make_failure_event(f"SIM-BF-{i}", seconds_offset=i * 5.0, user="target_user")
        for i in range(4)
    ]
    findings = detector.detect(events)
    assert len(findings) == 0


def test_brute_force_spread_outside_window_no_alert():
    """Verify that 5 failures spaced 30 seconds apart (spanning 120s) do not trigger a 60s window."""
    detector = BruteForceDetector(failure_threshold=5, window_seconds=60.0)
    events = [
        _make_failure_event(f"SIM-BF-{i}", seconds_offset=i * 30.0, user="target_user")
        for i in range(5)  # offsets: 0, 30, 60, 90, 120 -> max in any 60s is 3
    ]
    findings = detector.detect(events)
    assert len(findings) == 0


def test_brute_force_boundary_conditions():
    """Verify boundary conditions: 5 events at offsets 0, 10, 20, 30, 59.9s (trigger) vs 60.1s (no trigger)."""
    detector = BruteForceDetector(failure_threshold=5, window_seconds=60.0)

    # Within boundary: offsets [0, 10, 20, 30, 59.9] -> span 59.9s <= 60s
    in_boundary = [
        _make_failure_event(f"SIM-IN-{i}", seconds_offset=[0, 10, 20, 30, 59.9][i])
        for i in range(5)
    ]
    assert len(detector.detect(in_boundary)) == 1

    # Outside boundary: offsets [0, 10, 20, 30, 60.5] -> span 60.5s > 60s
    out_boundary = [
        _make_failure_event(f"SIM-OUT-{i}", seconds_offset=[0, 10, 20, 30, 60.5][i])
        for i in range(5)
    ]
    assert len(detector.detect(out_boundary)) == 0


def test_brute_force_different_users_not_combined():
    """Verify that failures targeting different usernames are not aggregated together."""
    detector = BruteForceDetector(failure_threshold=5, window_seconds=60.0)
    events = [
        _make_failure_event("SIM-U1-1", 1.0, user="user_one"),
        _make_failure_event("SIM-U1-2", 2.0, user="user_one"),
        _make_failure_event("SIM-U1-3", 3.0, user="user_one"),
        _make_failure_event("SIM-U2-1", 4.0, user="user_two"),
        _make_failure_event("SIM-U2-2", 5.0, user="user_two"),
        _make_failure_event("SIM-U2-3", 6.0, user="user_two"),
    ]
    # Total 6 events, but user_one has 3 and user_two has 3 -> both below threshold of 5
    findings = detector.detect(events)
    assert len(findings) == 0


def test_brute_force_different_source_ips_not_combined():
    """Verify that failures from different source IPs targeting the same user are not combined if partitioned."""
    detector = BruteForceDetector(failure_threshold=5, window_seconds=60.0)
    events = [
        _make_failure_event("SIM-IP1-1", 1.0, user="shared_user", src_ip="192.0.2.1"),
        _make_failure_event("SIM-IP1-2", 2.0, user="shared_user", src_ip="192.0.2.1"),
        _make_failure_event("SIM-IP2-1", 3.0, user="shared_user", src_ip="198.51.100.5"),
        _make_failure_event("SIM-IP2-2", 4.0, user="shared_user", src_ip="198.51.100.5"),
        _make_failure_event("SIM-IP2-3", 5.0, user="shared_user", src_ip="198.51.100.5"),
    ]
    # Total 5 events, but IP1 has 2 and IP2 has 3 -> both below threshold of 5
    findings = detector.detect(events)
    assert len(findings) == 0


# ══════════════════════════════════════════════════════════════════════════════
# 2. Breach Detection (Burst + Immediate Success)
# ══════════════════════════════════════════════════════════════════════════════

def test_brute_force_breach_detection_escalates_to_critical():
    """Verify that a successful login immediately following 5 failures elevates severity to CRITICAL."""
    detector = BruteForceDetector(failure_threshold=5, window_seconds=60.0)
    events = [
        _make_failure_event(f"SIM-BF-{i}", seconds_offset=i * 5.0, user="admin_user", src_ip="203.0.113.42")
        for i in range(5)
    ]
    # Add successful login at t = 28s (immediately following failures at 0, 5, 10, 15, 20s)
    events.append(_make_success_event("SIM-BF-SUCCESS", seconds_offset=28.0, user="admin_user", src_ip="203.0.113.42"))

    findings = detector.detect(events)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "critical"
    assert f.confidence == 0.95
    assert "BREACH" in f.title.upper()
    assert any("BREACH INDICATOR" in fact for fact in f.evidence.observed_facts)
    assert f.evidence.telemetry_fields["breach_confirmed"] is True


def test_benign_successful_logins_never_trigger():
    """Verify that purely successful logins never produce brute force findings."""
    detector = BruteForceDetector(failure_threshold=5, window_seconds=60.0)
    events = [
        _make_success_event(f"SIM-OK-{i}", seconds_offset=i * 2.0, user="alice")
        for i in range(20)
    ]
    findings = detector.detect(events)
    assert len(findings) == 0


# ══════════════════════════════════════════════════════════════════════════════
# 3. Robustness: Out-of-Order, Duplicates, Malformed Data
# ══════════════════════════════════════════════════════════════════════════════

def test_out_of_order_and_duplicate_events_handled():
    """Verify that duplicate event IDs are deduplicated and out-of-order events are sorted chronologically."""
    detector = BruteForceDetector(failure_threshold=5, window_seconds=60.0)
    events = [
        _make_failure_event("SIM-1", seconds_offset=40.0),
        _make_failure_event("SIM-2", seconds_offset=10.0),
        _make_failure_event("SIM-1", seconds_offset=40.0),  # Duplicate SIM-1
        _make_failure_event("SIM-3", seconds_offset=20.0),
        _make_failure_event("SIM-4", seconds_offset=5.0),
        _make_failure_event("SIM-5", seconds_offset=30.0),
    ]
    findings = detector.detect(events)
    assert len(findings) == 1
    # Triggering IDs should contain exactly 5 unique events
    assert len(set(findings[0].evidence.triggering_event_ids)) == 5


def test_missing_or_malformed_fields_gracefully_handled():
    """Verify detector handles null identities, missing timestamps, and non-auth events without crashing."""
    detector = BruteForceDetector(failure_threshold=5, window_seconds=60.0)
    dirty_events = [
        {"id": "ERR-1", "user": None, "src_ip": None, "timestamp": "invalid-time"},
        {"id": "ERR-2", "action": "GetObject", "service": "s3", "status": "success"},
        {"id": "ERR-3", "action": "DescribeInstances", "service": "ec2", "status": "failure"},  # non-auth failure
        None,
        "string-instead-of-dict",
    ]
    findings = detector.detect(dirty_events)
    assert len(findings) == 0  # no crash, zero false positives


# ══════════════════════════════════════════════════════════════════════════════
# 4. Detector Registry and API Integration
# ══════════════════════════════════════════════════════════════════════════════

def test_detector_registered_in_global_registry():
    """Verify brute_force_detector is registered and listed in detector_registry."""
    detector = detector_registry.get("brute_force")
    assert detector is not None
    assert detector.category == "brute_force"
    assert detector.category_index == 1


def test_api_list_detectors():
    """Verify GET /api/detection/detectors returns registered detectors."""
    response = client.get("/api/detection/detectors")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert any(d["category"] == "brute_force" for d in data["data"])


def test_api_detection_findings_endpoint():
    """Verify GET /api/detection/findings executes detection pipeline."""
    response = client.get("/api/detection/findings?normal=20&attacks=5")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "data" in data
    assert isinstance(data["data"], list)


def test_api_detection_evaluate_custom_batch():
    """Verify POST /api/detection/evaluate processes custom telemetry batch."""
    events = [
        {
            "id": f"TEST-API-BF-{i}",
            "timestamp": f"2026-10-25T12:00:{i * 5:02d}Z",
            "source": "synthetic_test",
            "rule_id": 5710,
            "user": "victim_service_account",
            "src_ip": "198.51.100.99",
            "action": "ConsoleLogin",
            "status": "failure",
            "service": "iam",
            "failed_attempts": 1
        }
        for i in range(6)
    ]
    response = client.post("/api/detection/evaluate", json={"events": events})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert len(data["data"]) >= 1
    finding = data["data"][0]
    assert finding["attack_category"] == "brute_force"
    assert finding["affected_principal"] == "victim_service_account"
    assert finding["recommended_response"]["playbook_id"] == "PB-BF-001"


# ══════════════════════════════════════════════════════════════════════════════
# 5. ML Inference Protection & Feature Dimension Guards
# ══════════════════════════════════════════════════════════════════════════════

def test_score_flow_features_returns_not_configured_for_9d():
    """
    Verify that passing 9-dimensional flow features returns an explicit
    'NOT CONFIGURED' status rather than crashing or using incompatible legacy models.
    """
    X_9d = np.ones((10, 9), dtype=np.float64)
    res = score_flow_features(X_9d)
    assert res["status"] == "NOT CONFIGURED"
    assert res["compatible"] is False
    assert res["feature_dim"] == 9


def test_ml_scale_for_rejects_incompatible_dimensions():
    """Verify that _scale_for strictly rejects 9D input and raises ValueError."""
    X_incompatible = np.ones((5, 9), dtype=np.float64)
    with pytest.raises(ValueError, match="Incompatible feature dimension"):
        _scale_for("iforest", X_incompatible)


def test_get_model_info_reports_feature_metadata():
    """Verify get_model_info reports legacy 3D schema and compatibility status."""
    info = get_model_info()
    if info.get("pretrained"):
        assert info["feature_dimension"] == 3
        assert info["compatible_with_9d_extractor"] is False
