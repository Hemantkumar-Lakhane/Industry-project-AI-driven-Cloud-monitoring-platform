"""
Unit Tests for RAM Antivirus Backend Foundation
================================================
Covers:
1. Event Schema validation (NormalizedEvent) and robust normalization
2. Finding Schema validation (SecurityFinding, FindingEvidence, RecommendedResponse)
3. Leakage-free 9-dimensional operational flow feature extraction
4. BaseDetector and DetectorRegistry contracts
"""
import sys
import os
import pytest
import numpy as np
from datetime import datetime, timezone

# Add backend directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from schemas.event import (
    NormalizedEvent,
    PrincipalInfo,
    NetworkInfo,
    EventProvenance,
    normalize_event,
)
from schemas.finding import (
    SecurityFinding,
    FindingEvidence,
    RecommendedResponse,
)
from engines.feature_extractor import (
    FEATURE_NAMES,
    FEATURE_DIM,
    extract_features,
    extract_feature_matrix,
    validate_feature_vector,
)
from engines.base_detector import (
    BaseDetector,
    DetectorRegistry,
    TAXONOMY_16,
)


# ══════════════════════════════════════════════════════════════════════════════
# 1. NormalizedEvent Schema Tests
# ══════════════════════════════════════════════════════════════════════════════

def test_normalized_event_defaults():
    """Verify default initialization produces a valid event with UUID and UTC timestamp."""
    event = NormalizedEvent()
    assert event.event_id.startswith("EVT-")
    assert isinstance(event.timestamp, datetime)
    assert event.timestamp.tzinfo is not None
    assert event.severity == "low"
    assert event.status == "unknown"


def test_normalized_event_timestamp_parsing():
    """Verify timestamp parsing handles ISO strings with Z, +00:00, or invalid formats."""
    e1 = NormalizedEvent(timestamp="2026-10-25T01:00:00Z")
    assert e1.timestamp.year == 2026
    assert e1.timestamp.tzinfo is not None

    e2 = NormalizedEvent(timestamp="invalid-timestamp-string")
    assert isinstance(e2.timestamp, datetime)


def test_normalize_event_from_legacy_wazuh_dict():
    """Verify normalize_event handles legacy simulator dictionaries."""
    raw = {
        "id": "SIM-BF-101",
        "timestamp": "2026-10-25T01:30:00Z",
        "source": "wazuh",
        "rule_id": 5710,
        "level": 10,
        "severity": "HIGH",
        "user": "svc-backup",
        "src_ip": "185.220.101.5",
        "dst_ip": "10.0.0.10",
        "bytes_transferred": 2048,
        "failed_attempts": 12,
        "description": "Multiple failed SSH logins",
    }
    event = normalize_event(raw)
    assert event.event_id == "SIM-BF-101"
    assert event.principal.identity == "svc-backup"
    assert event.principal.principal_type == "machine"  # contains 'svc'
    assert event.network.src_ip == "185.220.101.5"
    assert event.severity == "high"
    assert event.src_bytes == 2048
    assert event.failed_attempts == 12
    assert event.provenance.ingest_mode == "simulated"


def test_normalize_event_from_dirty_input():
    """Verify normalize_event survives nulls, negative bytes, and malformed rates."""
    dirty = {
        "id": None,
        "timestamp": None,
        "src_bytes": -500,
        "serror_rate": 2.5,  # out of [0, 1] bounds -> clamped
        "diff_srv_rate": "invalid-float",  # fallback to default
    }
    event = normalize_event(dirty)
    assert event.event_id.startswith("EVT-")
    assert event.src_bytes == 0  # clamped non-negative
    assert event.serror_rate == 1.0  # clamped to 1.0
    assert event.diff_srv_rate == 0.0  # fallback default


# ══════════════════════════════════════════════════════════════════════════════
# 2. SecurityFinding Schema Tests
# ══════════════════════════════════════════════════════════════════════════════

def test_security_finding_valid_creation():
    """Verify SecurityFinding instantiation and evidence structuring."""
    evidence = FindingEvidence(
        triggering_event_ids=["EVT-001"],
        observed_facts=["42 failed logins within 60s from Tor exit node"],
        inferred_hypothesis="Automated credential stuffing tool",
        missing_evidence="Host authentication logs on target server",
        telemetry_fields={"failed_count": 42, "ip": "185.220.101.5"}
    )
    finding = SecurityFinding(
        attack_category="brute_force",
        category_index=1,
        title="Brute Force Authentication Burst",
        severity="critical",
        confidence=0.95,
        detection_method="hybrid",
        affected_resource="arn:aws:iam::123456789012:user/svc-deploy",
        evidence=evidence
    )
    assert finding.finding_id.startswith("FIND-")
    assert finding.severity == "critical"
    assert finding.confidence == 0.95
    assert len(finding.evidence.observed_facts) == 1
    assert finding.recommended_response.is_dry_run_supported is True


def test_security_finding_confidence_clamping():
    """Verify confidence values are clamped to [0.0, 1.0]."""
    f1 = SecurityFinding(attack_category="brute_force", title="Test", confidence=1.5)
    assert f1.confidence == 1.0
    f2 = SecurityFinding(attack_category="brute_force", title="Test", confidence=-0.5)
    assert f2.confidence == 0.0


# ══════════════════════════════════════════════════════════════════════════════
# 3. Leakage-Free 9-Dimensional Feature Extractor Tests
# ══════════════════════════════════════════════════════════════════════════════

def test_feature_names_match_ieee_paper():
    """Verify exact 9 feature names and ordering specified in the IEEE paper."""
    expected = [
        "duration", "src_bytes", "dst_bytes", "count",
        "srv_count", "serror_rate", "rerror_rate",
        "same_srv_rate", "diff_srv_rate"
    ]
    assert FEATURE_NAMES == expected
    assert FEATURE_DIM == 9


def test_extract_features_from_normalized_event():
    """Verify feature vector extraction from a NormalizedEvent."""
    event = NormalizedEvent(
        duration=2.5,
        src_bytes=1024,
        dst_bytes=4096,
        count=15,
        srv_count=8,
        serror_rate=0.2,
        rerror_rate=0.05,
        same_srv_rate=0.85,
        diff_srv_rate=0.15,
    )
    vec = extract_features(event)
    assert isinstance(vec, np.ndarray)
    assert vec.shape == (9,)
    assert vec.dtype == np.float64
    assert vec[0] == 2.5
    assert vec[1] == 1024.0
    assert vec[2] == 4096.0
    assert vec[3] == 15.0
    assert vec[4] == 8.0
    assert vec[5] == 0.2
    assert vec[6] == 0.05
    assert vec[7] == 0.85
    assert vec[8] == 0.15
    assert validate_feature_vector(vec) is True


def test_extract_features_no_target_leakage():
    """
    Verify that post-event label 'level' or ground-truth classifications
    are strictly excluded from the extracted feature vector.
    """
    leaked_dict = {
        "level": 14,              # Leaked ordinal label from legacy pipeline
        "attack_type": "dos",     # Ground truth label
        "duration": 0.0,
        "bytes_transferred": 500,
        "failed_attempts": 10,
    }
    vec = extract_features(leaked_dict)
    assert vec.shape == (9,)
    # Index 0 is duration, Index 1 is src_bytes (derived from bytes_transferred)
    assert vec[0] == 0.0
    assert vec[1] == 500.0
    # No feature in vec contains 14 (the leaked level)
    assert 14.0 not in vec


def test_extract_feature_matrix_batch():
    """Verify batch extraction produces (N, 9) matrix and handles empty list."""
    empty_mat = extract_feature_matrix([])
    assert empty_mat.shape == (0, 9)

    events = [NormalizedEvent(src_bytes=i * 100) for i in range(5)]
    mat = extract_feature_matrix(events)
    assert mat.shape == (5, 9)
    assert list(mat[:, 1]) == [0.0, 100.0, 200.0, 300.0, 400.0]


def test_validate_feature_vector_edge_cases():
    """Verify validate_feature_vector rejects NaNs, wrong shapes, and negative values."""
    assert validate_feature_vector(np.array([1, 2, 3])) is False  # wrong length
    assert validate_feature_vector(np.array([0, 0, 0, 1, 1, np.nan, 0, 1, 0])) is False  # NaN
    assert validate_feature_vector(np.array([-1, 0, 0, 1, 1, 0, 0, 1, 0])) is False  # negative duration
    assert validate_feature_vector(np.array([0, 0, 0, 1, 1, 1.5, 0, 1, 0])) is False  # rate > 1.0


# ══════════════════════════════════════════════════════════════════════════════
# 4. BaseDetector & DetectorRegistry Contract Tests
# ══════════════════════════════════════════════════════════════════════════════

class MockBruteForceDetector(BaseDetector):
    """Simple mock detector testing interface compliance."""

    def __init__(self):
        super().__init__(
            category="brute_force",
            category_index=1,
            name="Mock Brute Force Detector",
            description="Detects consecutive authentication failures"
        )

    def detect(self, events):
        norm_events = self._ensure_normalized(events)
        findings = []
        for e in norm_events:
            if e.failed_attempts >= 5:
                finding = self.create_finding(
                    title=f"Authentication burst: {e.failed_attempts} failed logins",
                    severity="high",
                    confidence=0.9,
                    detection_method="rule_based",
                    triggering_events=[e],
                    observed_facts=[f"{e.failed_attempts} failed login attempts from {e.network.src_ip}"],
                    inferred_hypothesis="Credential brute-force attack",
                    affected_resource=e.principal.identity,
                    affected_principal=e.principal.identity
                )
                findings.append(finding)
        return findings


def test_base_detector_contract():
    """Verify concrete detector executes detect() and returns standard SecurityFinding."""
    detector = MockBruteForceDetector()
    events = [
        {"failed_attempts": 2, "user": "alice", "src_ip": "10.0.0.1"},
        {"failed_attempts": 10, "user": "admin", "src_ip": "185.220.101.5"},
    ]
    findings = detector.detect(events)
    assert len(findings) == 1
    f = findings[0]
    assert isinstance(f, SecurityFinding)
    assert f.attack_category == "brute_force"
    assert f.category_index == 1
    assert f.severity == "high"
    assert f.confidence == 0.9
    assert f.affected_principal == "admin"
    assert f.recommended_response.playbook_id == "PB-BF-001"
    assert f.recommended_response.is_dry_run_supported is True


def test_detector_registry():
    """Verify registry registers, lists, and runs detectors."""
    registry = DetectorRegistry()
    detector = MockBruteForceDetector()
    registry.register(detector)

    assert registry.get("brute_force") is detector
    assert registry.get("non_existent") is None

    listing = registry.list_all()
    assert len(listing) == 1
    assert listing[0]["category"] == "brute_force"

    # Run all
    events = [NormalizedEvent(failed_attempts=8, principal=PrincipalInfo(identity="root"))]
    findings = registry.run_all(events)
    assert len(findings) == 1
    assert findings[0].affected_principal == "root"


def test_taxonomy_16_completeness():
    """Verify that all 16 categories are defined in the canonical taxonomy."""
    assert len(TAXONOMY_16) == 16
    assert all(i in TAXONOMY_16 for i in range(1, 17))
    assert TAXONOMY_16[1]["slug"] == "brute_force"
    assert TAXONOMY_16[3]["slug"] == "iam_privilege_escalation"
    assert TAXONOMY_16[16]["slug"] == "defense_tampering"
