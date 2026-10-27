"""
Unit Tests for ML Engine Cloud-Native Telemetry Integration (HMT-02)
=====================================================================
Verifies:
1. Dual-scoring architecture: network flow specialist models + cloud behavioral analyzer
2. Calibration of combined anomaly scores into percentile tiers
3. Explainability annotations (cloud_features, model_scores, detected_by)
4. Robustness against missing fields and dimension boundaries
"""
import pytest
import numpy as np
from engines.ml_engine import (
    analyze_events,
    get_model_info,
    _compute_cloud_behavioral_score,
    _severity,
)
from engines.feature_extractor import CLOUD_FEATURE_NAMES, CLOUD_FEATURE_DIM


def test_compute_cloud_behavioral_score_bounds():
    """Verify cloud behavioral score evaluates cleanly within [0.0, 1.0]."""
    # Benign zero vector
    vec_benign = np.array([0.0, 0.0, 0.0, 0.0, 0.0, 0.25, 0.0, 1.0], dtype=np.float64)
    s_benign = _compute_cloud_behavioral_score(vec_benign)
    assert 0.0 <= s_benign <= 0.2

    # Malicious vector with high-risk action, auth anomaly, high severity
    vec_mal = np.array([1000.0, 5.0, 1.0, 1.0, 1.0, 1.0, 1.0, 15.0], dtype=np.float64)
    s_mal = _compute_cloud_behavioral_score(vec_mal)
    assert s_mal >= 0.85

    # Invalid input handling
    assert _compute_cloud_behavioral_score(np.zeros(3)) == 0.0
    assert _compute_cloud_behavioral_score(None) == 0.0


def test_severity_tier_calibration():
    """Verify calibrated score thresholds conform to percentile tiers."""
    assert _severity(0.95) == "Critical"
    assert _severity(0.86) == "Critical"
    assert _severity(0.85) == "High"
    assert _severity(0.75) == "High"
    assert _severity(0.70) == "Medium"
    assert _severity(0.50) == "Medium"
    assert _severity(0.45) == "Low"
    assert _severity(0.10) == "Low"


def test_analyze_events_annotates_dual_scores_and_cloud_features():
    """Verify analyze_events incorporates both flow and cloud telemetry."""
    events = [
        {
            "id": "EVT-NORM-001",
            "timestamp": "2026-10-27T10:00:00Z",
            "source": "cloudtrail",
            "action": "DescribeInstances",
            "status": "success",
            "severity": "low",
            "src_ip": "10.0.0.5",
            "user": "developer-read",
            "failed_attempts": 0,
            "bytes_transferred": 500,
        },
        {
            "id": "EVT-ATTACK-001",
            "timestamp": "2026-10-27T10:01:00Z",
            "source": "cloudtrail",
            "action": "iam:CreateAccessKey",
            "status": "failure",
            "severity": "critical",
            "src_ip": "198.51.100.42",
            "user": "compromised_admin",
            "failed_attempts": 10,
            "bytes_transferred": 15000000,  # 15MB exfiltration
        }
    ]

    analyzed = analyze_events(events)
    assert len(analyzed) == 2

    # Normal event check
    norm = analyzed[0]
    assert "calibrated_score" in norm
    assert "flow_anomaly_score" in norm
    assert "cloud_anomaly_score" in norm
    assert "cloud_features" in norm
    assert len(norm["cloud_features"]) == CLOUD_FEATURE_DIM
    assert norm["is_anomaly"] is False
    assert norm["ml_severity"] == "Low"

    # Attack event check
    att = analyzed[1]
    assert att["cloud_anomaly_score"] >= 0.85
    assert att["calibrated_score"] >= 0.85
    assert att["is_anomaly"] is True
    assert att["ml_severity"] == "Critical"
    assert att["detected_by"] == "Cloud Behavioral Analyzer"
    assert "Cloud Behavioral Analyzer" in att["model_scores"]


def test_get_model_info_includes_cloud_schema():
    """Verify get_model_info reports both flow 9D and cloud 8D schemas."""
    info = get_model_info()
    assert info.get("pretrained") is True
    assert info["feature_dimension"] == 9
    assert info["cloud_feature_dimension"] == 8
    assert info["cloud_feature_schema"] == "cloud_native_8d"
    assert len(info["cloud_features"]) == 8
