import pytest
import numpy as np
import sys
import os

backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from engines.feature_extractor import (
    CLOUD_FEATURE_NAMES,
    CLOUD_FEATURE_DIM,
    extract_cloud_features,
    extract_cloud_feature_matrix,
    validate_cloud_feature_vector
)
from schemas.event import NormalizedEvent, PrincipalInfo, NetworkInfo

def test_cloud_feature_schema_definition():
    """Verify cloud feature schema contains exactly 8 verified dimensions."""
    assert CLOUD_FEATURE_DIM == 8
    assert len(CLOUD_FEATURE_NAMES) == 8
    expected = [
        "payload_bytes",
        "failed_auth_count",
        "high_risk_action_flag",
        "auth_anomaly_flag",
        "distinct_targets_count",
        "rule_severity_norm",
        "error_status_flag",
        "burst_velocity"
    ]
    assert CLOUD_FEATURE_NAMES == expected

def test_extract_cloud_features_normal_event():
    """Verify benign event yields expected low-risk normalized features."""
    event = NormalizedEvent(
        action="s3:GetObject",
        status="success",
        src_bytes=1024,
        dst_bytes=2048,
        failed_attempts=0,
        severity="low",
        count=1,
        srv_count=1,
        target_resource="arn:aws:s3:::company-reports/public.pdf"
    )
    vec = extract_cloud_features(event)
    assert vec.shape == (8,)
    assert validate_cloud_feature_vector(vec) is True
    # payload_bytes = 1024 + 2048 = 3072.0
    assert vec[0] == 3072.0
    # failed_auth_count = 0.0
    assert vec[1] == 0.0
    # high_risk_action_flag = 0.0
    assert vec[2] == 0.0
    # auth_anomaly_flag = 0.0
    assert vec[3] == 0.0
    # distinct_targets_count = 1.0
    assert vec[4] == 1.0
    # rule_severity_norm = 0.25 (low)
    assert vec[5] == 0.25
    # error_status_flag = 0.0
    assert vec[6] == 0.0
    # burst_velocity = 1.0
    assert vec[7] == 1.0

def test_extract_cloud_features_malicious_event():
    """Verify adversary event yields expected high-risk normalized features."""
    event = NormalizedEvent(
        action="iam:AttachRolePolicy",
        status="failed",
        src_bytes=512,
        dst_bytes=128,
        failed_attempts=5,
        severity="critical",
        count=15,
        srv_count=12,
        target_resource="arn:aws:iam::123456789012:role/AdminRole"
    )
    vec = extract_cloud_features(event)
    assert vec.shape == (8,)
    assert validate_cloud_feature_vector(vec) is True
    # payload_bytes = 512 + 128 = 640.0
    assert vec[0] == 640.0
    # failed_auth_count = 5.0
    assert vec[1] == 5.0
    # high_risk_action_flag = 1.0 (AttachRolePolicy)
    assert vec[2] == 1.0
    # auth_anomaly_flag = 1.0 (failed)
    assert vec[3] == 1.0
    # distinct_targets_count = 1.0
    assert vec[4] == 1.0
    # rule_severity_norm = 1.0 (critical)
    assert vec[5] == 1.0
    # error_status_flag = 1.0 (failed)
    assert vec[6] == 1.0
    # burst_velocity = 15.0
    assert vec[7] == 15.0

def test_extract_cloud_feature_matrix():
    """Verify batch extraction preserves dimensions and ordering."""
    events = [
        {"action": "s3:GetObject", "status": "success", "bytes_transferred": 100},
        {"action": "iam:DeleteBucket", "status": "failed", "failed_attempts": 3, "severity": "high"}
    ]
    matrix = extract_cloud_feature_matrix(events)
    assert matrix.shape == (2, 8)
    assert validate_cloud_feature_vector(matrix[0]) is True
    assert validate_cloud_feature_vector(matrix[1]) is True
    assert matrix[0, 2] == 0.0  # s3:GetObject is not high risk
    assert matrix[1, 2] == 1.0  # DeleteBucket is high risk
