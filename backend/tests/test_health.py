"""
Tests for the /healthz health check and / root service endpoints.
"""
import sys
import os

# Ensure backend directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_root_endpoint_status_code_and_payload():
    """Verify GET / returns HTTP 200 with service identification and status."""
    response = client.get("/")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    data = response.json()
    assert data["service"] == "RAM Antivirus Cloud Security API"
    assert data["status"] == "running"


def test_healthz_status_code_and_payload():
    """Verify GET /healthz returns HTTP 200 with {'status': 'ok'}."""
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_healthz_response_headers():
    """Verify GET /healthz returns application/json content type."""
    response = client.get("/healthz")
    assert response.headers["content-type"] == "application/json"


def test_cors_allows_localhost():
    """Verify CORS allows localhost:5173."""
    response = client.options(
        "/healthz",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.headers.get("access-control-allow-origin") == "http://localhost:5173"


def test_cors_allows_vercel_domain():
    """Verify CORS allows Vercel production/preview domain via regex."""
    response = client.options(
        "/healthz",
        headers={
            "Origin": "https://ram-antivirus-platform.vercel.app",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.headers.get("access-control-allow-origin") == "https://ram-antivirus-platform.vercel.app"


def test_cors_rejects_untrusted_origin():
    """Verify CORS rejects unauthorized arbitrary origins."""
    response = client.options(
        "/healthz",
        headers={
            "Origin": "https://malicious-site.example.com",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert "access-control-allow-origin" not in response.headers
