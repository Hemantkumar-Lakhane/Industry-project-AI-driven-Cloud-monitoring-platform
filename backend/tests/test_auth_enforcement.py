import pytest
from fastapi.testclient import TestClient
import sys
import os

# Ensure backend directory is in sys.path
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from main import app
from engines.auth_engine import login_user

client = TestClient(app)

def test_public_routes_accessible_without_token():
    """Verify public endpoints remain open for probes, health, and login."""
    res_root = client.get("/")
    assert res_root.status_code == 200
    assert res_root.json()["service"] == "RAM Antivirus Cloud Security API"

    res_health = client.get("/healthz")
    assert res_health.status_code == 200
    assert res_health.json()["status"] == "ok"

    res_docs = client.get("/docs")
    assert res_docs.status_code == 200

    res_login = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    assert res_login.status_code == 200
    assert res_login.json()["data"]["success"] is True

def test_registration_requires_admin_authorization():
    """Verify registration cannot be executed by anonymous users or lower-privilege roles."""
    import uuid
    unique_user = f"user_{uuid.uuid4().hex[:8]}"
    new_user_payload = {
        "username": unique_user,
        "password": "Password123!",
        "email": f"{unique_user}@test.com",
        "role": "analyst",
        "full_name": "Test User"
    }

    # 1. Anonymous request should be rejected with 401
    res_anon = client.post("/api/auth/register", json=new_user_payload)
    assert res_anon.status_code == 401

    # 2. Viewer request should be rejected with 403 (insufficient permissions)
    viewer_login = login_user("viewer1", "viewer123")
    viewer_token = viewer_login["token"]
    res_viewer = client.post(
        "/api/auth/register",
        json=new_user_payload,
        headers={"Authorization": f"Bearer {viewer_token}"}
    )
    assert res_viewer.status_code == 403

    # 3. Admin request should be accepted
    admin_login = login_user("admin", "admin123")
    admin_token = admin_login["token"]
    res_admin = client.post(
        "/api/auth/register",
        json=new_user_payload,
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert res_admin.status_code == 200
    assert res_admin.json()["data"]["success"] is True

def test_remediation_dry_run_requires_authentication():
    """Verify remediation dry-run endpoints require valid permissions."""
    # Anonymous request -> 401
    res_anon = client.post("/api/remediation/dry-run/brute_force")
    assert res_anon.status_code == 401

    # Admin request -> 200
    admin_login = login_user("admin", "admin123")
    admin_token = admin_login["token"]
    res_auth = client.post(
        "/api/remediation/dry-run/brute_force",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert res_auth.status_code == 200
    assert res_auth.json()["status"] == "success"

def test_remediation_execution_requires_remediation_execute_permission():
    """Verify execution of remediation is blocked for viewer and analyst roles."""
    viewer_login = login_user("viewer1", "viewer123")
    viewer_token = viewer_login["token"]
    res_viewer = client.post(
        "/api/remediation/execute/brute_force",
        headers={"Authorization": f"Bearer {viewer_token}"}
    )
    assert res_viewer.status_code == 403

    # Admin has remediation:execute
    admin_login = login_user("admin", "admin123")
    admin_token = admin_login["token"]
    res_admin = client.post(
        "/api/remediation/execute/brute_force",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert res_admin.status_code == 200
