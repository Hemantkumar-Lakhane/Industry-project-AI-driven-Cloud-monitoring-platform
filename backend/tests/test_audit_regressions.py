"""
Regression Test Suite for Audit Fixes
======================================
Verifies:
1. GET /api/risk/score is strictly read-only and does not mutate or insert rows into risk_history.
2. Clean baseline reset produces 0 incidents, an injected attack produces incidents,
   subsequent reset clears back to 0 incidents, and new attack produces only fresh incidents.
"""
import pytest
from fastapi.testclient import TestClient
from main import app
from engines.db import get_conn
from engines.auth_engine import login_user


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def admin_headers():
    res = login_user("admin", "admin123")
    token = res.get("token")
    return {"Authorization": f"Bearer {token}"}


def test_get_risk_score_is_read_only(client, admin_headers):
    """Verify GET /api/risk/score does not mutate the database by inserting risk_history records."""
    conn = get_conn()
    initial_count = conn.execute("SELECT COUNT(*) as cnt FROM risk_history").fetchone()["cnt"]
    conn.close()

    # Repeatedly poll the risk score endpoint 5 times
    for _ in range(5):
        r = client.get("/api/risk/score")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "success"
        assert "unified_risk_score" in data["data"]

    # Verify count in risk_history has not grown
    conn = get_conn()
    final_count = conn.execute("SELECT COUNT(*) as cnt FROM risk_history").fetchone()["cnt"]
    conn.close()

    assert final_count == initial_count, f"GET /api/risk/score mutated risk_history: initial={initial_count}, final={final_count}"


def test_simulation_reset_clean_state_cycle(client, admin_headers):
    """
    Verify complete simulation reset lifecycle:
    1. baseline -> 0 incidents
    2. attack simulation -> incidents appear
    3. reset -> 0 incidents again
    4. new attack -> only new incidents appear
    """
    # 1. Reset to baseline
    r_reset1 = client.post("/api/simulation/reset", headers=admin_headers)
    assert r_reset1.status_code == 200

    r_inc1 = client.get("/api/incidents")
    assert r_inc1.status_code == 200
    assert r_inc1.json().get("count") == 0
    assert len(r_inc1.json().get("data", [])) == 0

    r_stats1 = client.get("/api/incidents/stats")
    assert r_stats1.status_code == 200
    assert r_stats1.json()["data"]["total_incidents"] == 0

    # 2. Attack simulation
    r_sim1 = client.post("/api/simulation/run/brute_force?intensity=high", headers=admin_headers)
    assert r_sim1.status_code == 200

    r_inc2 = client.get("/api/incidents")
    assert r_inc2.status_code == 200
    assert r_inc2.json().get("count") >= 1
    assert len(r_inc2.json().get("data", [])) >= 1

    r_stats2 = client.get("/api/incidents/stats")
    assert r_stats2.json()["data"]["total_incidents"] >= 1

    # 3. Reset again -> 0 incidents
    r_reset2 = client.post("/api/simulation/reset", headers=admin_headers)
    assert r_reset2.status_code == 200

    r_inc3 = client.get("/api/incidents")
    assert r_inc3.status_code == 200
    assert r_inc3.json().get("count") == 0
    assert len(r_inc3.json().get("data", [])) == 0

    # 4. New attack -> fresh incidents
    r_sim2 = client.post("/api/simulation/run/data_exfiltration?intensity=high", headers=admin_headers)
    assert r_sim2.status_code == 200

    r_inc4 = client.get("/api/incidents")
    assert r_inc4.status_code == 200
    assert r_inc4.json().get("count") >= 1
    all_categories = [cat for inc in r_inc4.json().get("data", []) for cat in inc.get("attack_categories", [])]
    assert len(all_categories) >= 1
