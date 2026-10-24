"""
Tests for Swagger UI (/docs) and OpenAPI Specification (/openapi.json).
Verifies that all platform endpoints, descriptions, request/response schemas,
and security configurations are correctly exposed in the generated API documentation.
"""
import sys
import os

# Ensure backend directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_swagger_docs_html():
    """Verify GET /docs returns HTTP 200 with HTML Swagger UI."""
    response = client.get("/docs")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "swagger-ui" in response.text.lower()


def test_openapi_json_schema():
    """Verify GET /openapi.json returns HTTP 200 with valid OpenAPI 3.x specification."""
    response = client.get("/openapi.json")
    assert response.status_code == 200
    assert "application/json" in response.headers["content-type"]
    schema = response.json()
    assert "openapi" in schema
    assert schema["info"]["title"] == "Advanced Cloud Security API"
    assert "paths" in schema
    assert len(schema["paths"]) >= 39


def test_openapi_tags_metadata():
    """Verify openapi_tags grouping metadata exists with descriptions."""
    schema = client.get("/openapi.json").json()
    tags = {t["name"]: t["description"] for t in schema.get("tags", [])}
    expected_tags = [
        "General",
        "Health & System Status",
        "Authentication & Access Control",
        "Security Posture (CSPM & CIEM)",
        "ML Detection & Analytics",
        "Unified Risk Analysis",
        "Attack Simulation",
        "Remediation & Playbooks",
        "Compliance Management",
        "Audit History & Data Export",
        "Threat Alerts & Notifications",
    ]
    for tag in expected_tags:
        assert tag in tags, f"Expected tag '{tag}' missing from OpenAPI metadata"
        assert len(tags[tag]) > 10, f"Tag '{tag}' should have a detailed description"


def test_security_schemes_configured():
    """Verify HTTPBearer security scheme is defined in components."""
    schema = client.get("/openapi.json").json()
    components = schema.get("components", {})
    security_schemes = components.get("securitySchemes", {})
    assert "HTTPBearer" in security_schemes
    assert security_schemes["HTTPBearer"]["type"] == "http"
    assert security_schemes["HTTPBearer"]["scheme"] == "bearer"


def test_protected_endpoints_have_security_scheme():
    """Verify endpoints requiring authentication specify HTTPBearer security."""
    schema = client.get("/openapi.json").json()
    paths = schema["paths"]

    protected_routes = [
        ("/api/auth/me", "get"),
        ("/api/auth/users", "get"),
        ("/api/auth/users/{username}/deactivate", "post"),
        ("/api/auth/users/{username}/reactivate", "post"),
        ("/api/alerts/test", "post"),
    ]

    for path, method in protected_routes:
        assert path in paths, f"Path {path} missing from OpenAPI schema"
        operation = paths[path].get(method, {})
        assert "security" in operation, f"Operation {method.upper()} {path} missing security block"
        sec_names = [list(s.keys())[0] for s in operation["security"]]
        assert "HTTPBearer" in sec_names, f"Operation {method.upper()} {path} must declare HTTPBearer security"


def test_all_endpoints_have_summary_and_description():
    """Verify every registered HTTP operation has non-empty summary and description."""
    schema = client.get("/openapi.json").json()
    paths = schema["paths"]

    for path, path_item in paths.items():
        for method, operation in path_item.items():
            if method.lower() in ["get", "post", "put", "delete", "patch"]:
                summary = operation.get("summary")
                description = operation.get("description")
                assert summary, f"Operation {method.upper()} {path} has missing or empty summary"
                assert description, f"Operation {method.upper()} {path} has missing or empty description"
                assert len(description) >= 20, f"Operation {method.upper()} {path} description too short"


def test_request_models_in_components():
    """Verify Pydantic request models are documented in components schemas."""
    schema = client.get("/openapi.json").json()
    schemas = schema.get("components", {}).get("schemas", {})
    assert "RegisterRequest" in schemas
    assert "LoginRequest" in schemas

    reg_props = schemas["RegisterRequest"]["properties"]
    assert "description" in reg_props["username"]
    assert "description" in reg_props["password"]
    assert "description" in reg_props["email"]
    assert "description" in reg_props["role"]

    login_props = schemas["LoginRequest"]["properties"]
    assert "description" in login_props["username"]
    assert "description" in login_props["password"]


def test_public_endpoints_status_and_contracts():
    """Verify key public endpoints return 200 and expected contracts."""
    endpoints = [
        "/api/auth/roles",
        "/api/status",
        "/api/compliance/frameworks",
        "/api/simulation/scenarios",
        "/api/remediation/playbooks",
        "/api/history/cspm",
        "/api/history/ciem",
        "/api/history/alerts",
        "/api/ml/model-info",
    ]
    for ep in endpoints:
        resp = client.get(ep)
        assert resp.status_code == 200, f"Endpoint {ep} returned {resp.status_code}"
        assert resp.json().get("status") == "success", f"Endpoint {ep} response missing status: success"


def test_auth_protection_and_token_flow():
    """Verify protected endpoints reject unauthenticated calls and accept valid JWT token."""
    # 1. Unauthenticated requests must fail with 401
    assert client.get("/api/auth/me").status_code == 401
    assert client.get("/api/auth/users").status_code == 401
    assert client.post("/api/auth/users/nobody/deactivate").status_code == 401
    assert client.post("/api/alerts/test").status_code == 401

    # 2. Login as admin
    login_resp = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    assert login_resp.status_code == 200
    token = login_resp.json()["data"]["token"]
    assert token

    # 3. Authenticated requests with Bearer token must succeed
    headers = {"Authorization": f"Bearer {token}"}
    me_resp = client.get("/api/auth/me", headers=headers)
    assert me_resp.status_code == 200
    assert me_resp.json()["data"]["username"] == "admin"
    assert me_resp.json()["data"]["role"] == "admin"

    users_resp = client.get("/api/auth/users", headers=headers)
    assert users_resp.status_code == 200
    assert isinstance(users_resp.json()["data"], list)

