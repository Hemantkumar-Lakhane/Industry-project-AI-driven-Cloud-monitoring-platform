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

def test_sensitive_endpoints_require_authentication():
    """Verify sensitive read and write endpoints reject unauthenticated access with 401."""
    unauthenticated_endpoints = [
        ("GET", "/api/incidents"),
        ("GET", "/api/cspm/scan"),
        ("GET", "/api/ciem/scan"),
        ("GET", "/api/detection/findings"),
        ("POST", "/api/assets/scan"),
        ("POST", "/api/simulate/attack"),
        ("POST", "/api/cloud/connect"),
    ]
    for method, path in unauthenticated_endpoints:
        if method == "GET":
            res = client.get(path)
        else:
            res = client.post(path, json={})
        assert res.status_code == 401, f"{method} {path} returned {res.status_code}, expected 401"

def test_role_based_access_on_mutating_actions():
    """Verify viewer role cannot trigger asset discovery or attack simulations."""
    viewer_res = login_user("viewer1", "viewer123")
    viewer_token = viewer_res["token"]
    viewer_headers = {"Authorization": f"Bearer {viewer_token}"}

    admin_res = login_user("admin", "admin123")
    admin_token = admin_res["token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # Viewer should be rejected with 403
    res_asset_viewer = client.post("/api/assets/scan", headers=viewer_headers)
    assert res_asset_viewer.status_code == 403

    res_sim_viewer = client.post("/api/simulate/attack?scenario=brute_force", headers=viewer_headers)
    assert res_sim_viewer.status_code == 403

    # Admin should succeed with 200
    res_asset_admin = client.post("/api/assets/scan", headers=admin_headers)
    assert res_asset_admin.status_code == 200

    res_sim_admin = client.post("/api/simulate/attack?scenario=brute_force", headers=admin_headers)
    assert res_sim_admin.status_code == 200

def test_jwt_secret_required_in_production():
    """Verify RuntimeError is raised when JWT_SECRET is unset in production environment."""
    import subprocess
    cmd = [
        sys.executable, "-c",
        f"import os, sys; sys.path.insert(0, r'{backend_dir}'); os.environ['ENV'] = 'production'; os.environ.pop('JWT_SECRET', None); from engines.auth_engine import JWT_SECRET"
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=backend_dir)
    assert proc.returncode != 0
    assert "RuntimeError" in proc.stderr
    assert "JWT_SECRET environment variable is missing" in proc.stderr


def test_login_endpoint_rate_limiting():
    """Verify rapid failed login requests exceed threshold and return HTTP 429."""
    try:
        responses = [
            client.post("/api/auth/login", json={"username": "probe_user", "password": "wrong_password"})
            for _ in range(8)
        ]
        status_codes = [r.status_code for r in responses]
        assert 429 in status_codes
        assert status_codes[-1] == 429
    finally:
        if hasattr(app.state, "limiter"):
            app.state.limiter.reset()

