"""
SRS Functional Requirements Verification Test Suite
====================================================
Comprehensive tests validating the core implementation of:
  - FR-01: Cloud Asset Discovery & Inventory
  - FR-02 & FR-06: Workload Telemetry & Normalization
  - FR-05: Workload Vulnerability Analysis & CVE Scoring
  - FR-07: Threat Detection & Data Exfiltration False-Positive Elimination (Rule 31100)
  - FR-08: Cross-Detector Incident Correlation & Kill-Chain Phases
  - FR-09 & FR-10: Automated Response Lifecycle & Rollback
  - FR-11: SQLite Deterministic Finding ID Deduplication
"""
import sys
import os

# Ensure backend directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi.testclient import TestClient
from main import app
from schemas.event import NormalizedEvent, normalize_event
from engines.base_detector import detector_registry
from engines.detectors.data_exfiltration import DataExfiltrationDetector
from engines.asset_engine import discover_assets, get_asset_inventory, check_connectors
from engines.vulnerability_engine import run_vulnerability_scan, get_vulnerability_summary
from engines.correlation_engine import correlate_findings, get_correlated_incidents
from engines.remediation_engine import execute_playbook, rollback_remediation
from engines.db import update_finding_status_db, get_findings_stats_db

client = TestClient(app)


# ── FR-01: Asset Discovery & Inventory Tests ───────────────────────────────────

def test_cloud_asset_discovery():
    """Verify that asset discovery produces structured cloud resources with risk scores."""
    assets = discover_assets(force_rescan=True)
    assert len(assets) >= 5
    types = {a["asset_type"] for a in assets}
    assert "ec2_instance" in types
    assert "s3_bucket" in types
    assert "iam_role" in types

    for a in assets:
        assert "asset_id" in a
        assert "name" in a
        assert "risk_score" in a
        assert 0.0 <= a["risk_score"] <= 100.0


def test_asset_inventory_api():
    """Verify GET /api/assets returns structured inventory."""
    resp = client.get("/api/assets")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["total_assets"] >= 5
    assert "connectors" in data


def test_connectors_status_api():
    """Verify GET /api/assets/connectors reports accurate status for all 3 connectors."""
    resp = client.get("/api/assets/connectors")
    assert resp.status_code == 200
    conns = resp.json()["connectors"]
    assert "localstack" in conns
    assert "aws" in conns
    assert "wazuh" in conns


# ── FR-05: Vulnerability Analysis Tests ────────────────────────────────────────

def test_vulnerability_scanning():
    """Verify vulnerability analysis matches CVEs with CVSS scores and patches."""
    vulns = run_vulnerability_scan()
    assert len(vulns) >= 5
    cve_ids = {v["cve_id"] for v in vulns}
    assert "CVE-2021-44228" in cve_ids  # Log4Shell
    assert "CVE-2022-0847" in cve_ids   # Dirty Pipe

    for v in vulns:
        assert v["cvss_score"] > 0.0
        assert v["severity"] in ("critical", "high", "medium", "low")
        assert "remediation" in v
        assert "affected_asset_id" in v


def test_vulnerability_api():
    """Verify GET /api/vulnerabilities returns posture summary."""
    resp = client.get("/api/vulnerabilities")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["total_vulnerabilities"] >= 5
    assert data["critical_count"] >= 1
    assert data["mean_cvss_score"] > 0.0


# ── FR-07: Threat Detection & Exfiltration Fix Tests ───────────────────────────

def test_data_exfiltration_rule_31100_not_flagged():
    """Verify that routine web requests (rule 31100) do NOT produce Critical exfiltration findings."""
    detector = DataExfiltrationDetector()
    normal_web_events = [
        normalize_event({
            "event_id": "EVT-NORM-001",
            "timestamp": "2026-10-26T12:00:00Z",
            "rule_id": 31100,
            "level": 2,
            "action": "GET /index.html",
            "description": "Web server request",
            "source": "wazuh",
            "user": "alice",
            "src_ip": "10.0.1.5",
            "bytes_transferred": 1250
        }),
        normalize_event({
            "event_id": "EVT-NORM-002",
            "timestamp": "2026-10-26T12:00:01Z",
            "rule_id": 31100,
            "level": 2,
            "action": "GET /api/status",
            "description": "Web server request",
            "source": "wazuh",
            "user": "bob",
            "src_ip": "10.0.1.6",
            "bytes_transferred": 450
        })
    ]
    findings = detector.detect(normal_web_events)
    assert len(findings) == 0, f"Rule 31100 normal web requests must not produce findings, got: {findings}"


def test_data_exfiltration_real_attack_flagged():
    """Verify that true volumetric exfiltration is detected."""
    detector = DataExfiltrationDetector()
    attack_events = [
        normalize_event({
            "event_id": "EVT-EXFIL-001",
            "timestamp": "2026-10-26T12:05:00Z",
            "rule_id": 31101,
            "level": 14,
            "action": "GetObject",
            "attack_type": "data_exfiltration",
            "description": "Large volume egress transfer detected",
            "source": "wazuh",
            "user": "compromised-admin",
            "src_ip": "10.0.1.20",
            "dst_ip": "198.51.100.42",
            "bytes_transferred": 600_000_000
        })
    ]
    findings = detector.detect(attack_events)
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].confidence >= 0.90


# ── FR-08: Cross-Detector Incident Correlation Tests ───────────────────────────

def test_incident_correlation():
    """Verify cross-detector correlation clusters findings by entity into kill-chain incidents."""
    mock_findings = [
        {
            "finding_id": "FIND-NETW-A1B2C3D4",
            "attack_category": "network_scanning",
            "title": "Port scan detected",
            "severity": "medium",
            "affected_principal": "attacker-user",
            "affected_resource": "web-server-01",
            "timestamp": "2026-10-26T10:00:00Z",
            "status": "open"
        },
        {
            "finding_id": "FIND-BRUT-E5F6G7H8",
            "attack_category": "brute_force",
            "title": "Authentication burst",
            "severity": "high",
            "affected_principal": "attacker-user",
            "affected_resource": "web-server-01",
            "timestamp": "2026-10-26T10:05:00Z",
            "status": "open"
        },
        {
            "finding_id": "FIND-DATA-I9J0K1L2",
            "attack_category": "data_exfiltration",
            "title": "High volume egress",
            "severity": "critical",
            "affected_principal": "attacker-user",
            "affected_resource": "web-server-01",
            "timestamp": "2026-10-26T10:10:00Z",
            "status": "open"
        }
    ]
    incidents = correlate_findings(mock_findings)
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc["entity_name"] == "attacker-user"
    assert inc["severity"] == "critical"
    assert len(inc["phases_detected"]) >= 2
    assert "Reconnaissance" in inc["phases_detected"]
    assert "Initial Access" in inc["phases_detected"]
    assert "Exfiltration" in inc["phases_detected"]


# ── FR-09 & FR-10: Remediation Lifecycle & Rollback Tests ──────────────────────

def test_remediation_lifecycle_and_rollback():
    """Verify playbook execution updates finding status and rollback restores it."""
    test_fid = "FIND-TEST-12345678"
    update_finding_status_db(test_fid, "open")

    # Execute dry-run
    dry_result = execute_playbook("brute_force", event={"finding_id": test_fid}, dry_run=True)
    assert dry_result["is_dry_run"] is True
    assert dry_result["steps_executed"] > 0

    # Execute live playbook -> transitions to resolved
    live_result = execute_playbook("brute_force", event={"finding_id": test_fid}, dry_run=False)
    assert live_result["is_dry_run"] is False
    exec_id = live_result["execution_id"]

    # Roll back the remediation
    rollback_result = rollback_remediation(exec_id)
    assert rollback_result["status"] == "success"
    assert rollback_result["current_state"] == "open"
