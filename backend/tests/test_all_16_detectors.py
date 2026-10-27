"""
Comprehensive Test Suite for All 16 Modular Attack Detectors
============================================================
Verifies benign activity, attack activity, boundary conditions, false-positive rejection,
and schema adherence for each of the 16 cloud attack categories in TAXONOMY_16.
"""
import sys
import os
import pytest
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any

# Ensure backend directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from schemas.event import NormalizedEvent, normalize_event
from schemas.finding import SecurityFinding
from engines.base_detector import detector_registry, TAXONOMY_16
import engines.detectors  # Ensure all 16 detectors are registered


def _make_event(
    event_type: str = "normal",
    action: str = "GetObject",
    status: str = "success",
    service: str = "s3",
    user_id: str = "alice",
    src_ip: str = "10.0.0.1",
    dst_ip: str = "10.0.0.2",
    bytes_transferred: int = 1000,
    seconds_offset: int = 0,
    attack_type: str = None,
    description: str = "Normal cloud activity",
    rule_id: int = 1001,
    target_resource: str = None,
    raw_data: Dict[str, Any] = None,
    serror_rate: float = 0.0,
    rerror_rate: float = 0.0,
    diff_srv_rate: float = 0.0,
    count: int = 1,
) -> NormalizedEvent:
    base_time = datetime(2026, 10, 26, 12, 0, 0, tzinfo=timezone.utc)
    ts = base_time + timedelta(seconds=seconds_offset)
    payload = {
        "id": f"EVT-{seconds_offset:04d}",
        "timestamp": ts,
        "event_type": event_type,
        "action": action,
        "status": status,
        "service": service,
        "user": user_id,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "target_resource": target_resource,
        "resource": target_resource,
        "bytes_transferred": bytes_transferred,
        "attack_type": attack_type,
        "description": description,
        "rule_id": rule_id,
        "serror_rate": serror_rate,
        "rerror_rate": rerror_rate,
        "diff_srv_rate": diff_srv_rate,
        "count": count,
    }
    if raw_data:
        payload.update(raw_data)
    return normalize_event(payload)


# ══════════════════════════════════════════════════════════════════════════════
# 1. Global Registry Completeness
# ══════════════════════════════════════════════════════════════════════════════

def test_registry_contains_all_16_taxonomy_categories():
    """Verify that all 16 categories from TAXONOMY_16 have a registered detector."""
    registered = detector_registry.list_all()
    registered_slugs = {d["category"] for d in registered}
    expected_slugs = {v["slug"] for v in TAXONOMY_16.values()}

    assert len(registered_slugs) >= 16
    assert expected_slugs.issubset(registered_slugs)


# ══════════════════════════════════════════════════════════════════════════════
# 2. Category 1: Brute-Force & Credential Abuse
# ══════════════════════════════════════════════════════════════════════════════

def test_detector_c1_brute_force():
    d = detector_registry.get("brute_force")
    assert d is not None

    # Benign: single failure
    benign = [_make_event(action="ConsoleLogin", status="failure", seconds_offset=0)]
    assert len(d.detect(benign)) == 0

    # Attack: 5 failures in 10s
    attack = [
        _make_event(action="ConsoleLogin", status="failure", seconds_offset=i * 2)
        for i in range(5)
    ]
    findings = d.detect(attack)
    assert len(findings) == 1
    assert findings[0].attack_category == "brute_force"
    assert findings[0].severity == "high"


# ══════════════════════════════════════════════════════════════════════════════
# 3. Category 2: Account Takeover (ATO)
# ══════════════════════════════════════════════════════════════════════════════

def test_detector_c2_account_takeover():
    d = detector_registry.get("account_takeover")
    assert d is not None

    # Benign: single user from consistent internal IP
    benign = [
        _make_event(action="ConsoleLogin", status="success", user_id="bob", src_ip="198.51.100.1", seconds_offset=0),
        _make_event(action="GetObject", status="success", user_id="bob", src_ip="198.51.100.1", seconds_offset=10),
    ]
    assert len(d.detect(benign)) == 0

    # Attack: Login from IP A, then immediate ChangePassword from IP B within 30s
    attack = [
        _make_event(action="ConsoleLogin", status="success", user_id="bob", src_ip="198.51.100.1", seconds_offset=0),
        _make_event(action="ChangePassword", status="success", user_id="bob", src_ip="203.0.113.5", seconds_offset=30),
    ]
    findings = d.detect(attack)
    assert len(findings) == 1
    assert findings[0].attack_category == "account_takeover"
    assert findings[0].severity == "critical"
    assert "Sensitive Modification" in findings[0].title


# ══════════════════════════════════════════════════════════════════════════════
# 4. Category 3: IAM Privilege Escalation
# ══════════════════════════════════════════════════════════════════════════════

def test_detector_c3_iam_privilege_escalation():
    d = detector_registry.get("iam_privilege_escalation")
    assert d is not None

    # Benign: read-only IAM describe
    benign = [_make_event(action="GetRole", status="success", service="iam", user_id="charlie")]
    assert len(d.detect(benign)) == 0

    # Attack: AttachUserPolicy with AdministratorAccess
    attack = [
        _make_event(
            action="AttachUserPolicy",
            status="success",
            service="iam",
            user_id="charlie",
            raw_data={"requestParameters": {"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess", "userName": "charlie"}}
        )
    ]
    findings = d.detect(attack)
    assert len(findings) == 1
    assert findings[0].attack_category == "iam_privilege_escalation"
    assert findings[0].severity == "critical"


# ══════════════════════════════════════════════════════════════════════════════
# 5. Category 4: Suspicious API Activity
# ══════════════════════════════════════════════════════════════════════════════

def test_detector_c4_suspicious_api_activity():
    d = detector_registry.get("suspicious_api_activity")
    assert d is not None

    # Benign: 3 normal Describe calls (sub-threshold)
    benign = [_make_event(action="DescribeInstances", seconds_offset=i * 2) for i in range(3)]
    assert len(d.detect(benign)) == 0

    # Attack: Burst of 12 Describe/List calls within 20s
    attack = [_make_event(action="DescribeSecurityGroups", seconds_offset=i) for i in range(12)]
    findings = d.detect(attack)
    assert len(findings) == 1
    assert findings[0].attack_category == "suspicious_api_activity"
    assert findings[0].severity == "high"


# ══════════════════════════════════════════════════════════════════════════════
# 6. Category 5: Cloud Misconfiguration Drift
# ══════════════════════════════════════════════════════════════════════════════

def test_detector_c5_cloud_misconfiguration():
    d = detector_registry.get("cloud_misconfiguration")
    assert d is not None

    # Benign: standard tag modification
    benign = [_make_event(action="CreateTags", service="ec2")]
    assert len(d.detect(benign)) == 0

    # Attack: S3 PutBucketAcl with public-read
    attack = [
        _make_event(
            action="PutBucketAcl",
            service="s3",
            description="Public S3 bucket access granted",
            raw_data={"requestParameters": {"bucketName": "finance-vault", "acl": "public-read"}}
        )
    ]
    findings = d.detect(attack)
    assert len(findings) == 1
    assert findings[0].attack_category == "cloud_misconfiguration"
    assert findings[0].severity == "critical"


# ══════════════════════════════════════════════════════════════════════════════
# 7. Category 6: Data Exfiltration
# ══════════════════════════════════════════════════════════════════════════════

def test_detector_c6_data_exfiltration():
    d = detector_registry.get("data_exfiltration")
    assert d is not None

    # Benign: 50 KB normal download
    benign = [_make_event(action="GetObject", bytes_transferred=50_000)]
    assert len(d.detect(benign)) == 0

    # Attack: 600 MB single external egress
    attack = [
        _make_event(
            action="GetObject",
            bytes_transferred=600_000_000,
            dst_ip="203.0.113.88",
            description="Large volume data transfer to external IP"
        )
    ]
    findings = d.detect(attack)
    assert len(findings) == 1
    assert findings[0].attack_category == "data_exfiltration"
    assert findings[0].severity == "critical"


# ══════════════════════════════════════════════════════════════════════════════
# 8. Category 7: Network Scanning & Reconnaissance
# ══════════════════════════════════════════════════════════════════════════════

def test_detector_c7_network_scanning():
    d = detector_registry.get("network_scanning")
    assert d is not None

    # Benign: standard same-service flow traffic
    benign = [_make_event(diff_srv_rate=0.05, count=2)]
    assert len(d.detect(benign)) == 0

    # Attack: High diff_srv_rate flow sweep or Wazuh scan alert
    attack = [
        _make_event(
            action="NetworkScan",
            src_ip="198.51.100.99",
            rule_id=40101,
            description="Port scan detected from external IP"
        )
    ]
    findings = d.detect(attack)
    assert len(findings) == 1
    assert findings[0].attack_category == "network_scanning"
    assert findings[0].severity in ("high", "medium")


# ══════════════════════════════════════════════════════════════════════════════
# 9. Category 8: Distributed Denial of Service (DDoS)
# ══════════════════════════════════════════════════════════════════════════════

def test_detector_c8_ddos():
    d = detector_registry.get("ddos")
    assert d is not None

    # Benign: low connection count
    benign = [_make_event(count=5, serror_rate=0.0)]
    assert len(d.detect(benign)) == 0

    # Attack: SYN flood (high serror_rate and connection count)
    attack = [_make_event(count=50, serror_rate=0.88, dst_ip="10.0.0.80")]
    findings = d.detect(attack)
    assert len(findings) == 1
    assert findings[0].attack_category == "ddos"
    assert findings[0].severity == "critical"


# ══════════════════════════════════════════════════════════════════════════════
# 10. Category 9: Cryptomining Workloads
# ══════════════════════════════════════════════════════════════════════════════

def test_detector_c9_cryptomining():
    d = detector_registry.get("cryptomining")
    assert d is not None

    # Benign: standard python process
    benign = [_make_event(description="python app.py running normally")]
    assert len(d.detect(benign)) == 0

    # Attack: xmrig binary execution targeting stratum pool
    attack = [
        _make_event(
            action="ProcessSpawn",
            description="xmrig miner executed with pool stratum+tcp://xmr.pool.com",
            raw_data={"port": 3333}
        )
    ]
    findings = d.detect(attack)
    assert len(findings) == 1
    assert findings[0].attack_category == "cryptomining"
    assert findings[0].severity == "critical"


# ══════════════════════════════════════════════════════════════════════════════
# 11. Category 10: Container & Kubernetes Attacks
# ══════════════════════════════════════════════════════════════════════════════

def test_detector_c10_container_k8s():
    d = detector_registry.get("container_k8s_attacks")
    assert d is not None

    # Benign: standard container get pods
    benign = [_make_event(action="GetPods", service="k8s")]
    assert len(d.detect(benign)) == 0

    # Attack: hostPath mount to docker.sock
    attack = [
        _make_event(
            action="CreatePod",
            description="Pod created with hostPath mount /var/run/docker.sock and privileged securityContext",
            target_resource="prod-backend-pod"
        )
    ]
    findings = d.detect(attack)
    assert len(findings) == 1
    assert findings[0].attack_category == "container_k8s_attacks"
    assert findings[0].severity == "critical"


# ══════════════════════════════════════════════════════════════════════════════
# 12. Category 11: Application BOLA & SSRF
# ══════════════════════════════════════════════════════════════════════════════

def test_detector_c11_bola_ssrf():
    d = detector_registry.get("bola_ssrf")
    assert d is not None

    # Benign: normal web request
    benign = [_make_event(dst_ip="10.0.0.15", action="HTTP_GET")]
    assert len(d.detect(benign)) == 0

    # Attack: Probing 169.254.169.254 instance metadata
    attack = [
        _make_event(
            dst_ip="169.254.169.254",
            action="HTTP_GET",
            description="Request to AWS IMDS metadata service 169.254.169.254"
        )
    ]
    findings = d.detect(attack)
    assert len(findings) == 1
    assert findings[0].attack_category == "bola_ssrf"
    assert findings[0].severity == "critical"


# ══════════════════════════════════════════════════════════════════════════════
# 13. Category 12: Malware & Ransomware Precursor
# ══════════════════════════════════════════════════════════════════════════════

def test_detector_c12_malware_ransomware():
    d = detector_registry.get("malware_ransomware")
    assert d is not None

    # Benign: file backup creation
    benign = [_make_event(action="BackupCreate", description="Created scheduled backup")]
    assert len(d.detect(benign)) == 0

    # Attack: vssadmin delete shadows command execution
    attack = [
        _make_event(
            action="CommandExecute",
            description="vssadmin delete shadows /all /quiet executed on host"
        )
    ]
    findings = d.detect(attack)
    assert len(findings) == 1
    assert findings[0].attack_category == "malware_ransomware"
    assert findings[0].severity == "critical"


# ══════════════════════════════════════════════════════════════════════════════
# 14. Category 13: Database Threat Activity
# ══════════════════════════════════════════════════════════════════════════════

def test_detector_c13_database_attacks():
    d = detector_registry.get("database_attacks")
    assert d is not None

    # Benign: parameterized SELECT query
    benign = [_make_event(action="Query", description="SELECT * FROM users WHERE id = ?")]
    assert len(d.detect(benign)) == 0

    # Attack: SQLi UNION SELECT payload
    attack = [
        _make_event(
            action="Query",
            description="UNION SELECT username, password FROM users -- SQL injection"
        )
    ]
    findings = d.detect(attack)
    assert len(findings) == 1
    assert findings[0].attack_category == "database_attacks"
    assert findings[0].severity in ("critical", "high")


# ══════════════════════════════════════════════════════════════════════════════
# 15. Category 14: Serverless Function Abuse
# ══════════════════════════════════════════════════════════════════════════════

def test_detector_c14_serverless_abuse():
    d = detector_registry.get("serverless_abuse")
    assert d is not None

    # Benign: Invoke function
    benign = [_make_event(action="Invoke", service="lambda")]
    assert len(d.detect(benign)) == 0

    # Attack: UpdateFunctionCode direct runtime code tampering
    attack = [
        _make_event(
            action="UpdateFunctionCode",
            service="lambda",
            target_resource="billing-processor",
            description="Direct runtime code package updated outside deployment pipeline"
        )
    ]
    findings = d.detect(attack)
    assert len(findings) == 1
    assert findings[0].attack_category == "serverless_abuse"
    assert findings[0].severity == "critical"


# ══════════════════════════════════════════════════════════════════════════════
# 16. Category 15: Supply-Chain Compromise
# ══════════════════════════════════════════════════════════════════════════════

def test_detector_c15_supply_chain():
    d = detector_registry.get("supply_chain_compromise")
    assert d is not None

    # Benign: GetDownloadUrlForLayer
    benign = [_make_event(action="GetDownloadUrlForLayer", service="ecr")]
    assert len(d.detect(benign)) == 0

    # Attack: Container image tag mutation / overwrite
    attack = [
        _make_event(
            action="PutImage",
            service="ecr",
            target_resource="prod-api-server",
            description="Existing production image tag overwrite detected (tag mutation)"
        )
    ]
    findings = d.detect(attack)
    assert len(findings) == 1
    assert findings[0].attack_category == "supply_chain_compromise"
    assert findings[0].severity == "critical"


# ══════════════════════════════════════════════════════════════════════════════
# 17. Category 16: Audit Defense & Logging Tampering
# ══════════════════════════════════════════════════════════════════════════════

def test_detector_c16_defense_tampering():
    d = detector_registry.get("defense_tampering")
    assert d is not None

    # Benign: DescribeTrails
    benign = [_make_event(action="DescribeTrails", service="cloudtrail")]
    assert len(d.detect(benign)) == 0

    # Attack: StopLogging on primary security audit trail
    attack = [
        _make_event(
            action="StopLogging",
            service="cloudtrail",
            target_resource="security-hub-trail",
            description="Primary organization audit trail logging stopped"
        )
    ]
    findings = d.detect(attack)
    assert len(findings) == 1
    assert findings[0].attack_category == "defense_tampering"
    assert findings[0].severity == "critical"
    assert findings[0].confidence >= 0.95


# ══════════════════════════════════════════════════════════════════════════════
# 18. Multi-Detector Execution and Idempotency
# ══════════════════════════════════════════════════════════════════════════════

def test_detector_registry_run_all_idempotency():
    """Verify that scanning a mixed batch produces consistent results without state leaks."""
    batch = [
        _make_event(action="DescribeInstances", seconds_offset=0),
        _make_event(action="StopLogging", service="cloudtrail", seconds_offset=1),
        _make_event(action="PutBucketAcl", description="public-read s3 bucket", seconds_offset=2),
    ]

    findings_run_1 = detector_registry.run_all(batch)
    findings_run_2 = detector_registry.run_all(batch)

    assert len(findings_run_1) == 2
    assert len(findings_run_2) == 2

    cats_1 = {f.attack_category for f in findings_run_1}
    cats_2 = {f.attack_category for f in findings_run_2}
    assert cats_1 == {"defense_tampering", "cloud_misconfiguration"}
    assert cats_1 == cats_2
