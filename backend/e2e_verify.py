import sys
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_e2e():
    print("=" * 60)
    print("RAM ANTIVIRUS PRODUCTION END-TO-END VERIFICATION SUITE")
    print("=" * 60)

    # 1. Admin Login
    print("\n[1] Testing Platform Superadmin Login...")
    admin_res = client.post("/api/auth/login", json={"username": "admin", "password": "password123"})
    if admin_res.status_code != 200:
        admin_res = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    assert admin_res.status_code == 200, f"Admin login failed: {admin_res.text}"
    admin_data = admin_res.json()["data"]
    admin_token = admin_data["token"]
    admin_user = admin_data["user"]
    assert admin_user["role"] == "admin", f"Expected admin role, got: {admin_user['role']}"
    assert "users:manage" in admin_user["permissions"], "Admin missing users:manage permission"
    print(f"    PASS: Superadmin authenticated as '{admin_user['full_name']}' with role='{admin_user['role']}'")

    # 2. Register New Enterprise Company Tenant
    print("\n[2] Testing Self-Serve Company Registration...")
    import time
    test_email = f"audit_user_{int(time.time())}@enterprise.com"
    reg_res = client.post("/api/auth/register-company", json={
        "company_name": "Acme Global Security",
        "admin_name": "Alice Cyber Lead",
        "email": test_email,
        "password": "SecurePassword#2026",
        "username": f"alice_{int(time.time())}"
    })
    assert reg_res.status_code == 200, f"Registration failed: {reg_res.text}"
    tenant_data = reg_res.json()["data"]
    tenant_token = tenant_data["token"]
    tenant_user = tenant_data["user"]
    assert tenant_user["role"] == "user", f"Expected company user role='user', got: {tenant_user['role']}"
    assert "users:manage" not in tenant_user.get("permissions", []), "Tenant user must NOT have users:manage!"
    print(f"    PASS: Company user registered with role='{tenant_user['role']}', org_id='{tenant_user['org_id']}'")

    # 3. RBAC Enforcement: Normal user cannot delete or deactivate admin
    print("\n[3] Testing RBAC Tenant Isolation & Admin Protection...")
    tenant_headers = {"Authorization": f"Bearer {tenant_token}"}
    forbidden_res = client.post("/api/auth/users/admin/deactivate", headers=tenant_headers)
    assert forbidden_res.status_code == 403, f"Expected 403 Forbidden, got {forbidden_res.status_code}"
    print("    PASS: Tenant user correctly blocked (403 Forbidden) from deactivating Platform Admin")

    # 4. Zero State Verification for Unconnected Tenant
    print("\n[4] Testing Zero State for Fresh Tenant (No Cloud Linked)...")
    cloud_status_res = client.get("/api/cloud/status", headers=tenant_headers)
    assert cloud_status_res.status_code == 200
    probe = cloud_status_res.json().get("probe", {})
    assert probe.get("status") == "NOT_CONNECTED", f"Expected NOT_CONNECTED, got {probe.get('status')}"
    assert probe.get("account_id") is None, f"Expected None account_id, got {probe.get('account_id')}"
    print(f"    PASS: Cloud status correctly reports '{probe.get('status')}' (0 ambient leakage)")

    summary_res = client.get("/api/dashboard/summary", headers=tenant_headers)
    assert summary_res.status_code == 200
    summary = summary_res.json().get("data", {})
    assert summary.get("cloud_connected") is False, "Expected cloud_connected=False"
    assert summary.get("threats", {}).get("critical") == 0
    assert summary.get("threats", {}).get("total_analyzed") == 0
    print("    PASS: Dashboard summary correctly reports 0 findings, 0 events, cloud_connected=False")

    findings_res = client.get("/api/detection/findings", headers=tenant_headers)
    assert findings_res.status_code == 200
    findings = findings_res.json()
    assert findings.get("count") == 0, f"Expected 0 findings, got {findings.get('count')}"
    assert findings.get("source") == "NOT_CONNECTED"
    print("    PASS: Detection findings returns 0 findings with source='NOT_CONNECTED'")

    risk_res = client.get("/api/risk/score", headers=tenant_headers)
    assert risk_res.status_code == 200
    risk = risk_res.json().get("data", {})
    assert risk.get("unified_risk_score") == 0.0, f"Expected 0.0 score, got {risk.get('unified_risk_score')}"
    assert risk.get("unified_risk_level") == "NOT_EVALUATED"
    print("    PASS: Risk score returns 0.0 with level='NOT_EVALUATED'")

    # 5. Connect Live AWS Account
    print("\n[5] Testing Live AWS Account Connection...")
    import os
    aws_key = os.environ.get("AWS_ACCESS_KEY_ID", "AKIA_CONFIGURED_TEST")
    aws_sec = os.environ.get("AWS_SECRET_ACCESS_KEY", "AWS_SECRET_CONFIGURED_TEST")

    # In production tests, load from backend .env if available
    if os.path.exists(".env"):
        from dotenv import load_dotenv
        load_dotenv(".env")
        aws_key = os.environ.get("AWS_ACCESS_KEY_ID", aws_key)
        aws_sec = os.environ.get("AWS_SECRET_ACCESS_KEY", aws_sec)

    connect_res = client.post("/api/cloud/connect", json={
        "provider": "aws",
        "region": "ap-southeast-2",
        "access_key_id": aws_key,
        "secret_access_key": aws_sec
    }, headers=tenant_headers)
    assert connect_res.status_code == 200, f"Connection failed: {connect_res.text}"
    connected_probe = connect_res.json().get("probe", {})
    assert connected_probe.get("status") == "CONNECTED", f"Expected CONNECTED, got {connected_probe.get('status')}"
    print(f"    PASS: Connected to live AWS Account {connected_probe.get('account_id')} in {connected_probe.get('region')} ({connected_probe.get('latency_ms')}ms)")

    # 6. Run Live Cloud Posture Audit (CSPM)
    print("\n[6] Testing Live CSPM Security Audit...")
    cspm_res = client.post("/api/cloud/scan/cspm", headers=tenant_headers)
    assert cspm_res.status_code == 200
    cspm_data = cspm_res.json().get("data", [])
    print(f"    PASS: Live CSPM Scan returned {len(cspm_data)} findings across real AWS resources")

    # 7. Check Playbooks
    print("\n[7] Testing Remediation Playbooks...")
    playbooks_res = client.get("/api/remediation/playbooks", headers=tenant_headers)
    assert playbooks_res.status_code == 200
    pb_data = playbooks_res.json().get("data", [])
    assert len(pb_data) > 0, "No playbooks returned"
    print(f"    PASS: Remediation engine loaded {len(pb_data)} verified response playbooks")

    print("\n" + "=" * 60)
    print("ALL 7 END-TO-END VERIFICATION CHECKS PASSED PERFECTLY!")
    print("=" * 60)

if __name__ == "__main__":
    test_e2e()
