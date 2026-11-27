import os
import sys
import uuid
import pytest
from fastapi.testclient import TestClient

backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from main import app
from engines.auth_engine import ROLE_PERMISSIONS, login_user, register_user

client = TestClient(app)

REQUIRED_SUPER_ADMIN_PERMS = {
    "platform:manage",
    "tenants:read",
    "tenants:write",
    "tenants:suspend",
    "fleet:telemetry",
    "audit:read",
}


def _super_admin_headers():
    pw = os.environ.get("SUPER_ADMIN_PASSWORD", "SuperAdmin!2026#")
    res = login_user("superadmin", pw)
    assert res["success"] is True, f"superadmin login failed: {res}"
    return {"Authorization": f"Bearer {res['token']}"}, res


def test_super_admin_role_permissions_defined():
    assert "super_admin" in ROLE_PERMISSIONS
    perms = set(ROLE_PERMISSIONS["super_admin"]["permissions"])
    assert REQUIRED_SUPER_ADMIN_PERMS.issubset(perms)

    # Tenant admin must NOT possess super_admin exclusive permissions
    admin_perms = set(ROLE_PERMISSIONS["admin"]["permissions"])
    assert REQUIRED_SUPER_ADMIN_PERMS.isdisjoint(admin_perms)


def test_admin_endpoints_reject_anonymous_and_non_super_admin():
    endpoints = [
        ("GET", "/api/admin/fleet/overview", None),
        ("GET", "/api/admin/organizations", None),
        ("POST", "/api/admin/organizations", {"name": "Blocked Corp"}),
        ("PUT", "/api/admin/organizations/org_demo/status", {"status": "suspended"}),
        ("GET", "/api/admin/users", None),
        ("POST", "/api/admin/users/usr_demo_analyst_01/terminate-sessions", None),
        ("GET", "/api/admin/audit-logs", None),
    ]

    # 1. Anonymous -> 401
    for method, path, body in endpoints:
        res = client.request(method, path, json=body) if body is not None else client.request(method, path)
        assert res.status_code == 401, f"Anon {method} {path} returned {res.status_code}"

    # 2. Tenant Admin & Viewer -> 403
    for uname, pw in [("admin", "admin123"), ("viewer1", "viewer123")]:
        tok = login_user(uname, pw)["token"]
        headers = {"Authorization": f"Bearer {tok}"}
        for method, path, body in endpoints:
            res = client.request(method, path, json=body, headers=headers) if body is not None else client.request(method, path, headers=headers)
            assert res.status_code == 403, f"{uname} {method} {path} returned {res.status_code}"


def test_super_admin_fleet_overview_and_org_lifecycle():
    headers, login_res = _super_admin_headers()
    assert login_res["user"]["role"] == "super_admin"
    assert login_res["user"]["org_id"] == "org_master_admin"

    # 1. Fleet Overview
    res_fleet = client.get("/api/admin/fleet/overview", headers=headers)
    assert res_fleet.status_code == 200
    fleet_data = res_fleet.json()["data"]
    assert "fleet" in fleet_data
    assert "threats" in fleet_data
    assert "infrastructure" in fleet_data
    assert fleet_data["fleet"]["total_organizations"] >= 2

    # 2. Create Organization
    org_name = f"Test Enterprise {uuid.uuid4().hex[:6]}"
    res_create = client.post(
        "/api/admin/organizations",
        json={"name": org_name, "industry": "FinTech", "plan": "enterprise"},
        headers=headers,
    )
    assert res_create.status_code == 200
    created_org = res_create.json()["data"]
    org_id = created_org["org_id"]
    assert created_org["name"] == org_name
    assert created_org["status"] == "active"
    assert created_org["plan"] == "enterprise"

    # 3. List Organizations includes the new org
    res_list = client.get("/api/admin/organizations", headers=headers)
    assert res_list.status_code == 200
    org_ids = [o["org_id"] for o in res_list.json()["data"]]
    assert org_id in org_ids

    # 4. Provision a user inside the new org and verify suspension blocks login
    uname = f"tenant_usr_{uuid.uuid4().hex[:6]}"
    reg = register_user(uname, "StrongPass!99", f"{uname}@example.com", role="user", full_name="Tenant User", org_id=org_id)
    assert reg["success"] is True
    user_id = reg["user"]["user_id"]

    # Master org cannot be suspended
    res_master = client.put("/api/admin/organizations/org_master_admin/status", json={"status": "suspended"}, headers=headers)
    assert res_master.status_code == 400

    # Suspend new org
    res_susp = client.put(f"/api/admin/organizations/{org_id}/status", json={"status": "suspended"}, headers=headers)
    assert res_susp.status_code == 200
    assert res_susp.json()["data"]["status"] == "suspended"

    blocked_login = login_user(uname, "StrongPass!99")
    assert blocked_login["success"] is False
    assert "suspended" in blocked_login["error"].lower()

    # Reactivate new org
    res_react = client.put(f"/api/admin/organizations/{org_id}/status", json={"status": "active"}, headers=headers)
    assert res_react.status_code == 200
    assert res_react.json()["data"]["status"] == "active"

    ok_login = login_user(uname, "StrongPass!99")
    assert ok_login["success"] is True
    old_token = ok_login["token"]

    # 5. Global User Directory search & filter
    res_users = client.get(f"/api/admin/users?org_id={org_id}&search={uname}", headers=headers)
    assert res_users.status_code == 200
    found_users = res_users.json()["data"]
    assert len(found_users) == 1
    assert found_users[0]["user_id"] == user_id

    # 6. Terminate User Sessions & verify old JWT is invalidated
    res_before = client.get("/api/incidents", headers={"Authorization": f"Bearer {old_token}"})
    assert res_before.status_code == 200

    res_term = client.post(f"/api/admin/users/{user_id}/terminate-sessions", headers=headers)
    assert res_term.status_code == 200
    assert res_term.json()["data"]["user_id"] == user_id

    res_after = client.get("/api/incidents", headers={"Authorization": f"Bearer {old_token}"})
    assert res_after.status_code == 403
    assert "revoked" in res_after.json()["detail"].lower()

    # 7. Audit Logs recorded all actions
    res_audit = client.get("/api/admin/audit-logs?limit=25", headers=headers)
    assert res_audit.status_code == 200
    actions = {item["action"] for item in res_audit.json()["data"]}
    assert "TENANT_CREATED" in actions
    assert "TENANT_SUSPENDED" in actions
    assert "TENANT_REACTIVATED" in actions
    assert "USER_SESSIONS_REVOKED" in actions
    assert "FLEET_TELEMETRY_VIEWED" in actions

    # Cleanup synthetic test org & user so live DB stays clean
    from engines.db import get_conn
    conn = get_conn()
    try:
        conn.execute("DELETE FROM users WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM organizations WHERE org_id = ?", (org_id,))
        conn.commit()
    finally:
        conn.close()
