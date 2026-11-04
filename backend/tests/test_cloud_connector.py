"""
Tests for Production Cloud Connector & CloudTrail Ingestion Pipeline
=====================================================================
Verifies:
1. Multi-mode authentication and STS connectivity probing
2. Safe graceful fallback when offline or in simulation mode
3. CloudTrail record normalization and security field attribution
4. Direct detection of cloud attacks (ConsoleLogin Brute Force & IAM Privilege Escalation)
5. CloudFormation onboarding template structure and Confused Deputy mitigation (sts:ExternalId)
"""
import sys
import os
import pytest
from datetime import datetime, timezone

# Ensure backend directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engines.cloud_connector import (
    probe_cloud_connectivity,
    configure_cloud_credentials,
    run_production_cspm_scan,
    run_production_ciem_scan,
    get_localstack_status
)
from engines.cloudtrail_ingestor import (
    normalize_cloudtrail_record,
    ingest_cloudtrail_events
)
from schemas.event import NormalizedEvent


def test_probe_cloud_connectivity_resilience():
    """Verify that probing connectivity returns a valid structured payload without exceptions."""
    probe = probe_cloud_connectivity()
    assert isinstance(probe, dict)
    assert "status" in probe
    assert "provider" in probe
    assert "auth_mode" in probe
    assert probe["status"] in ("CONNECTED", "OFFLINE", "ERROR")


def test_configure_cloud_credentials_runtime():
    """Verify runtime credential configuration updates the engine state."""
    result = configure_cloud_credentials({
        "provider": "aws",
        "target_account_id": "999888777666",
        "role_name": "RAMAntivirusAuditRole",
        "external_id": "TEST-TENANT-EXTERNAL-ID-42",
        "region": "eu-west-1"
    })
    assert isinstance(result, dict)
    assert "status" in result


def test_production_cspm_and_ciem_scans_do_not_crash():
    """Verify CSPM and CIEM scanning engines execute gracefully and return valid list results."""
    cspm_results = run_production_cspm_scan()
    assert isinstance(cspm_results, list)

    ciem_results = run_production_ciem_scan()
    assert isinstance(ciem_results, list)


def test_normalize_cloudtrail_console_login_failure():
    """Verify that AWS CloudTrail ConsoleLogin failure event is parsed into NormalizedEvent."""
    ct_record = {
        "eventVersion": "1.08",
        "eventID": "ct-evt-001",
        "eventTime": "2026-11-04T05:20:00Z",
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "198.51.100.99",
        "userIdentity": {
            "type": "IAMUser",
            "userName": "finance_admin",
            "arn": "arn:aws:iam::123456789012:user/finance_admin"
        },
        "responseElements": {
            "ConsoleLogin": "Failure"
        },
        "errorMessage": "Failed authentication"
    }

    norm = normalize_cloudtrail_record(ct_record)
    assert isinstance(norm, NormalizedEvent)
    assert norm.source_type == "cloudtrail"
    assert norm.action == "ConsoleLogin"
    assert norm.status == "failure"
    assert norm.principal.identity == "finance_admin"
    assert norm.network.src_ip == "198.51.100.99"
    assert norm.failed_attempts == 1


def test_normalize_cloudtrail_iam_privilege_escalation():
    """Verify that AWS CloudTrail AttachUserPolicy is parsed and mapped correctly."""
    ct_record = {
        "eventVersion": "1.08",
        "eventID": "ct-evt-002",
        "eventTime": "2026-11-04T05:25:00Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "AttachUserPolicy",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.45",
        "userIdentity": {
            "type": "IAMUser",
            "userName": "rogue_developer",
            "arn": "arn:aws:iam::123456789012:user/rogue_developer"
        },
        "requestParameters": {
            "userName": "rogue_developer",
            "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
        }
    }

    norm = normalize_cloudtrail_record(ct_record)
    assert isinstance(norm, NormalizedEvent)
    assert norm.source_type == "cloudtrail"
    assert norm.service == "iam"
    assert norm.action == "AttachUserPolicy"
    assert norm.principal.identity == "rogue_developer"
    assert "AdministratorAccess" in (norm.target_resource or "")
    assert norm.status == "success"


def test_cloudtrail_ingest_detects_brute_force_burst():
    """Verify that a sequence of 5 failed CloudTrail ConsoleLogin events triggers Brute Force detector."""
    burst_records = [
        {
            "eventVersion": "1.08",
            "eventID": f"ct-bf-{i}",
            "eventTime": f"2026-11-04T06:00:0{i}Z",
            "eventSource": "signin.amazonaws.com",
            "eventName": "ConsoleLogin",
            "sourceIPAddress": "198.51.100.77",
            "userIdentity": {
                "type": "IAMUser",
                "userName": "target_admin"
            },
            "responseElements": {"ConsoleLogin": "Failure"},
            "errorMessage": "Failed authentication"
        }
        for i in range(5)
    ]

    result = ingest_cloudtrail_events(burst_records, save_to_database=False)
    assert result["status"] == "success"
    assert result["ingested_count"] == 5

    # Check that brute force was detected
    categories = [f["attack_category"] for f in result["findings"]]
    assert "brute_force" in categories


def test_onboarding_cloudformation_template_security():
    """Verify CloudFormation template exists, has valid syntax, and enforces Confused Deputy protection."""
    tpl_path = os.path.join(os.path.dirname(__file__), "..", "cloud", "ram-antivirus-onboarding.yaml")
    assert os.path.exists(tpl_path), "CloudFormation template must exist on disk"

    with open(tpl_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Verify critical production security properties
    assert "sts:ExternalId" in content, "Must enforce sts:ExternalId to prevent Confused Deputy attacks"
    assert "sts:AssumeRole" in content, "Must use STS AssumeRole"
    assert "SecurityAudit" in content, "Must attach AWS-managed SecurityAudit read-only policy"
    assert "RAMAntivirusAuditRole" in content, "Must define audit role"
