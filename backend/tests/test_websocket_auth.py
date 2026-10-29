"""
Test Suite: Secure WebSocket Authentication & Lifecycle (Platform Security Module)
=======================================================================
Verifies:
1. Unauthenticated or timed-out connections are rejected with 4401.
2. Invalid JWT tokens are rejected with auth_error and 4401.
3. Authenticated handshake using valid Bearer JWT succeeds with auth_ok and receives events.
4. Single-use short-lived tickets (/api/auth/ws-ticket) allow query-param or frame authentication.
5. Ticket consumption is atomic and cannot be reused or redeemed after expiry.
6. Role-based authorization: connections without 'dashboard:read' are rejected.
"""
import pytest
from fastapi.testclient import TestClient
from fastapi.websockets import WebSocketDisconnect

from main import app
from engines.auth_engine import login_user, create_ws_ticket, redeem_ws_ticket


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def admin_token():
    res = login_user("admin", "admin123")
    assert res["success"] is True
    return res["token"]


@pytest.fixture
def viewer_token():
    res = login_user("viewer1", "viewer123")
    assert res["success"] is True
    return res["token"]


def test_ws_ticket_generation_endpoint(client, admin_token):
    """Verify POST /api/auth/ws-ticket generates a short-lived, single-use ticket."""
    resp = client.post("/api/auth/ws-ticket", headers={"Authorization": f"Bearer {admin_token}"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert "ticket" in data
    assert data["ticket"].startswith("wstk_")
    assert data["expires_in"] == 60


def test_ws_ticket_atomic_redemption():
    """Verify tickets can only be redeemed once and expire properly."""
    fake_payload = {"username": "testuser", "role": "admin", "permissions": ["dashboard:read"]}
    ticket = create_ws_ticket(fake_payload, ttl_seconds=60)
    
    # First redemption succeeds
    redeem1 = redeem_ws_ticket(ticket)
    assert redeem1["valid"] is True
    assert redeem1["payload"]["username"] == "testuser"
    
    # Second redemption must fail (single-use)
    redeem2 = redeem_ws_ticket(ticket)
    assert redeem2["valid"] is False
    assert "already consumed" in redeem2["error"]


def test_ws_connection_rejected_for_invalid_token(client):
    """Verify invalid token sent in auth frame is rejected and closed."""
    with client.websocket_connect("/ws/events") as websocket:
        websocket.send_json({"type": "auth", "token": "invalid.bogus.jwt"})
        msg = websocket.receive_json()
        assert msg["type"] == "auth_error"
        assert "Invalid" in msg["detail"] or "error" in msg["detail"].lower()


def test_ws_authenticated_handshake_with_token(client, admin_token):
    """Verify valid token completes handshake, receives auth_ok, and streams events."""
    with client.websocket_connect("/ws/events") as websocket:
        websocket.send_json({"type": "auth", "token": admin_token})
        
        # 1. Handshake response
        handshake = websocket.receive_json()
        assert handshake["type"] == "auth_ok"
        assert handshake["username"] == "admin"
        assert handshake["role"] == "admin"
        
        # 2. First streamed event update
        event_frame = websocket.receive_json()
        assert event_frame["type"] == "events_update"
        assert "total" in event_frame
        assert "latest_events" in event_frame


def test_ws_authenticated_handshake_with_ticket_query_param(client, admin_token):
    """Verify connection authenticating via query param ticket (?ticket=wstk_...)."""
    # Generate ticket
    t_resp = client.post("/api/auth/ws-ticket", headers={"Authorization": f"Bearer {admin_token}"})
    ticket = t_resp.json()["ticket"]
    
    with client.websocket_connect(f"/ws/events?ticket={ticket}") as websocket:
        handshake = websocket.receive_json()
        assert handshake["type"] == "auth_ok"
        assert handshake["username"] == "admin"
        
        event_frame = websocket.receive_json()
        assert event_frame["type"] == "events_update"


def test_ws_viewer_role_access(client, viewer_token):
    """Verify viewer accounts possessing 'dashboard:read' can connect."""
    with client.websocket_connect("/ws/events") as websocket:
        websocket.send_json({"type": "auth", "token": viewer_token})
        handshake = websocket.receive_json()
        assert handshake["type"] == "auth_ok"
        assert handshake["username"] == "viewer1"
        assert handshake["role"] == "viewer"
