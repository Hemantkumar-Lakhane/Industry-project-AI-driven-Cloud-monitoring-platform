import sys
import os

# Ensure backend, pylibs, and workspace root are in sys.path
_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT_DIR = os.path.dirname(_CURRENT_DIR)
_PYLIBS_DIR = os.path.join(_ROOT_DIR, "pylibs")

for _d in (_PYLIBS_DIR, _CURRENT_DIR, _ROOT_DIR):
    if os.path.exists(_d) and _d not in sys.path:
        sys.path.insert(0, _d)

from fastapi import FastAPI, Header, HTTPException, Request, Depends, Path, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, StreamingResponse, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.websockets import WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field, ConfigDict
import uvicorn
from typing import Optional, List, Dict, Any
import asyncio
import json
import csv
import io
import traceback

from simulator.wazuh_simulator import simulate_session
from simulator.wazuh_reader import read_wazuh_logs, get_wazuh_status, is_wazuh_available
from simulator.attack_simulator import run_attack_simulation, run_full_simulation, SCENARIOS, get_scenario_catalog, simulate_brute_force
from engines.cspm_engine import run_cspm_scan
from engines.ciem_engine import run_ciem_scan
from engines.ml_engine import analyze_events, compare_models, get_model_info, get_benchmark_results
from engines.remediation_engine import (
    execute_playbook, correct_configuration, revoke_entity_access,
    get_all_playbooks, auto_remediate_threats, rollback_remediation
)
from engines.compliance_engine import (
    map_findings_to_compliance, get_compliance_dashboard,
    generate_compliance_report, COMPLIANCE_FRAMEWORKS
)
from engines.auth_engine import (
    register_user, login_user, verify_token, check_permission,
    get_all_users, deactivate_user, reactivate_user, get_role_info, ROLE_PERMISSIONS
)
from engines.risk_engine import calculate_unified_risk, get_risk_trend
from engines.localstack_engine import (
    run_cspm_scan_localstack, run_ciem_scan_localstack,
    get_localstack_status, is_localstack_running
)
from engines.db import (
    save_risk_score, get_cspm_history, get_ciem_history,
    save_cspm_scan, save_ciem_scan, get_alert_log,
    save_compliance_score, get_compliance_trend_db,
    save_findings_db, get_findings_db, get_findings_stats_db,
    save_incidents_db, get_incidents_db, get_incident_by_id_db, get_incidents_stats_db,
    update_finding_status_db, update_incident_status_db,
    get_cloud_assets_db, get_vulnerabilities_db
)
from engines.asset_engine import discover_assets, get_asset_inventory, check_connectors
from engines.vulnerability_engine import run_vulnerability_scan, get_vulnerability_summary
from engines.correlation_engine import correlate_findings, get_correlated_incidents
from engines.alert_engine import send_alert_email
from schemas.event import NormalizedEvent, normalize_event
from schemas.finding import SecurityFinding
from schemas.incident import SecurityIncident
from engines.base_detector import detector_registry
from engines.detectors.brute_force import brute_force_detector
from simulator.session_manager import session_manager

# ── OpenAPI Tags & Metadata ───────────────────────────────────────────────────

tags_metadata = [
    {
        "name": "General",
        "description": "Platform service identity, root routing, and core metadata."
    },
    {
        "name": "Health & System Status",
        "description": "Liveness and readiness probes for container deployment verification and operational mode status of integrated subsystems (Wazuh SIEM, LocalStack AWS emulation, SQLite database)."
    },
    {
        "name": "Authentication & Access Control",
        "description": "User registration, JWT Bearer token generation, session verification, and Role-Based Access Control (RBAC) user administration."
    },
    {
        "name": "Security Posture (CSPM & CIEM)",
        "description": "Cloud Security Posture Management (CSPM) configuration audits, Cloud Infrastructure Entitlement Management (CIEM) identity risk analysis, and high-level posture dashboard metrics."
    },
    {
        "name": "ML Detection & Analytics",
        "description": "PyOD machine learning anomaly detection ensemble (Isolation Forest, KNN, HBOS), multi-model benchmarking, and model architecture metadata."
    },
    {
        "name": "Unified Risk Analysis",
        "description": "Enterprise composite risk scoring engine synthesizing telemetry anomaly metrics (35%), CSPM posture findings (35%), and CIEM identity risks (30%) with trend history."
    },
    {
        "name": "Attack Simulation",
        "description": "Adversary emulation engine executing MITRE ATT&CK scenarios (brute force, data exfiltration, privilege escalation, abnormal access) to empirically benchmark detection rates."
    },
    {
        "name": "Remediation & Playbooks",
        "description": "Automated incident response playbooks, configuration auto-correction, least-privilege entitlement revocations, and end-to-end response pipelines."
    },
    {
        "name": "Compliance Management",
        "description": "Regulatory compliance tracking, control mapping, posture scoring, and audit reports across ISO 27001, SOC 2, and GDPR."
    },
    {
        "name": "Audit History & Data Export",
        "description": "Historical audit logs for posture scans, entitlement evaluations, and downloadable CSV exports for security analysts and forensic auditing."
    },
    {
        "name": "Threat Alerts & Notifications",
        "description": "Incident alerting pipelines, email notification testing, and historical alert dispatch logs."
    },
    {
        "name": "Incident Correlation & Investigation",
        "description": "Multi-signal deterministic correlation layer grouping related atomic findings into higher-level attack campaigns."
    },
    {
        "name": "Real-Time Streaming",
        "description": "WebSocket live stream delivering continuous security telemetry, anomaly metrics, and critical alert updates."
    }
]


app = FastAPI(
    title="Advanced Cloud Security API",
    version="1.0.0",
    description="""
# RAM Antivirus - AI-Driven Cloud Security & Workload Monitoring Platform API

Welcome to the interactive Swagger API documentation for the **RAM Antivirus Cloud Security Platform**.
This platform delivers automated cloud security monitoring, combining machine learning anomaly detection,
Cloud Security Posture Management (CSPM), Cloud Infrastructure Entitlement Management (CIEM),
multi-framework compliance reporting, unified risk calculation, and automated incident remediation playbooks.

---

### 🔐 Authentication & Role-Based Access Control (RBAC)

Certain administrative and privileged endpoints require JWT Bearer authentication:
- **Obtain a Token:** Call `POST /api/auth/login` with your credentials (e.g., `admin` / `admin123`).
- **Authorize in Swagger:** Click the **Authorize** 🔓 button at the top right of this documentation and paste your token in the **Value** box.
- **Role Hierarchy:**
  - **`admin`**: Full access to all endpoints, user management, alert dispatch, and remediation playbooks.
  - **`analyst`**: Access to dashboards, telemetry analysis, ML benchmarking, compliance, attack simulation, and risk scoring.
  - **`viewer`**: Read-only access to posture, compliance, and event dashboards.

---

### ☁️ Integration Modes & Fallbacks
- **Wazuh SIEM:** Analyzes alerts from `/var/ossec/logs/alerts/alerts.json` when present. If unavailable, seamlessly falls back to high-fidelity synthetic telemetry simulation.
- **LocalStack AWS:** When running locally (`http://localhost:4566`), scans emulated S3 and IAM resources via `boto3`. When offline, derives findings from audit event logs.
""",
    openapi_tags=tags_metadata
)

# Global Bearer security definition for Swagger UI
bearer_scheme = HTTPBearer(
    auto_error=False,
    description="JWT Bearer access token. Obtain from `/api/auth/login`. Enter token in the Authorize dialog."
)


# ── General & Health Endpoints ─────────────────────────────────────────────────

@app.get(
    "/",
    tags=["General"],
    summary="Service Identification & Status",
    description="Root identification endpoint for the RAM Antivirus Cloud Security Platform API. Returns service identification and operational status.",
    response_description="Platform service name and running state confirmation.",
    responses={
        200: {
            "description": "API service operational confirmation",
            "content": {
                "application/json": {
                    "example": {
                        "service": "RAM Antivirus Cloud Security API",
                        "status": "running"
                    }
                }
            }
        }
    }
)
def root():
    """Service identification endpoint."""
    return {
        "service": "RAM Antivirus Cloud Security API",
        "status": "running"
    }


@app.get(
    "/healthz",
    tags=["Health & System Status"],
    summary="Container Health Check Probe",
    description="Lightweight health check endpoint designed for container orchestrator liveness/readiness probes, uptime monitors, and cloud deployment health verification.",
    response_description="Health status confirmation object.",
    responses={
        200: {
            "description": "Backend service is healthy and operational",
            "content": {
                "application/json": {
                    "example": {"status": "ok"}
                }
            }
        }
    }
)
def health_check():
    """Lightweight health check endpoint for container probes and Render deployments."""
    return {"status": "ok"}


ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "https://zrtjg51w-5173.inc1.devtunnels.ms",
]

extra_origins = os.environ.get("FRONTEND_URL") or os.environ.get("CORS_ORIGINS", "")
if extra_origins:
    for origin in extra_origins.split(","):
        cleaned = origin.strip().rstrip("/")
        if cleaned and cleaned not in ALLOWED_ORIGINS:
            ALLOWED_ORIGINS.append(cleaned)

CORS_ORIGIN_REGEX = os.environ.get(
    "CORS_ORIGIN_REGEX",
    r"^https://.*(\.devtunnels\.ms|\.vercel\.app)$"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=CORS_ORIGIN_REGEX,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Return JSON for unexpected backend failures so the frontend sees the real error."""
    traceback.print_exc()
    return JSONResponse(
        status_code=500,
        content={
            "status": "error",
            "detail": str(exc) or exc.__class__.__name__,
            "path": str(request.url.path),
        },
    )


# ── Pydantic Request Models ───────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "username": "analyst_jane",
                "password": "SecurePass123!",
                "email": "analyst_jane@ramantivirus.com",
                "role": "analyst",
                "full_name": "Jane Doe"
            }
        }
    )

    username: str = Field(
        ...,
        min_length=3,
        description="Unique username for the new account (minimum 3 characters)",
        examples=["analyst_jane"]
    )
    password: str = Field(
        ...,
        min_length=6,
        description="User password (minimum 6 characters)",
        examples=["SecurePass123!"]
    )
    email: str = Field(
        ...,
        description="Corporate or user email address (must be unique)",
        examples=["analyst_jane@ramantivirus.com"]
    )
    role: str = Field(
        "viewer",
        description="Role-based access level. Accepted values: `admin`, `analyst`, or `viewer` (default: `viewer`)",
        examples=["analyst"]
    )
    full_name: str = Field(
        "",
        description="Optional full legal or display name of the user",
        examples=["Jane Doe"]
    )


class LoginRequest(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "username": "admin",
                "password": "admin123"
            }
        }
    )

    username: str = Field(
        ...,
        description="Registered account username",
        examples=["admin"]
    )
    password: str = Field(
        ...,
        description="Account password",
        examples=["admin123"]
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_token(
    authorization: Optional[str] = None,
    credentials: Optional[HTTPAuthorizationCredentials] = None
) -> Optional[str]:
    if credentials and credentials.credentials:
        return credentials.credentials
    if authorization:
        return authorization.replace("Bearer ", "").strip()
    return None

def _get_current_user(
    authorization: Optional[str] = None,
    credentials: Optional[HTTPAuthorizationCredentials] = None
):
    token = _extract_token(authorization, credentials)
    if not token:
        return None
    try:
        result = verify_token(token)
        if result.get("valid"):
            return result.get("payload")
    except Exception:
        pass
    return None

def _require_permission(
    authorization: Optional[str] = None,
    permission: str = "",
    credentials: Optional[HTTPAuthorizationCredentials] = None
):
    token = _extract_token(authorization, credentials)
    if not token:
        raise HTTPException(status_code=401, detail="Authorization header required")
    result = check_permission(token, permission)
    if not result.get("authorized"):
        raise HTTPException(status_code=403, detail=result.get("error", "Forbidden"))
    return result.get("user")

def _get_events(normal: int = 80, attacks: int = 15):
    """
    Returns events from the unified active session buffer.
    Ensures Overview, Findings, and Attack Simulation observe identical event batches.
    """
    session = session_manager.get_session()
    if session and session.events:
        return session.events
    if is_wazuh_available():
        events = read_wazuh_logs(max_events=normal + attacks)
        if events:
            return events
    return simulate_session(n_normal=normal, n_attacks=attacks)

def _get_cspm(events: list = None):
    """Derive CSPM findings from active session or log events."""
    if is_localstack_running():
        results = run_cspm_scan_localstack()
        if results:
            save_cspm_scan(results)
            return results
    session = session_manager.get_session()
    if not events and session and session.cspm_results:
        return session.cspm_results
    results = run_cspm_scan(events or (session.events if session else []))
    save_cspm_scan(results)
    return results

def _get_ciem(events: list = None):
    """Derive CIEM findings from active session or log events."""
    if is_localstack_running():
        results = run_ciem_scan_localstack()
        if results:
            save_ciem_scan(results)
            return results
    session = session_manager.get_session()
    if not events and session and session.ciem_results:
        return session.ciem_results
    results = run_ciem_scan(events or (session.events if session else []))
    save_ciem_scan(results)
    return results


# ══════════════════════════════════════════════════════════════════════════════
# 1 — AUTHENTICATION & ACCESS CONTROL
# ══════════════════════════════════════════════════════════════════════════════

@app.post(
    "/api/auth/register",
    tags=["Authentication & Access Control"],
    summary="Register New User Account",
    description="""
Register a new user account with role-based access control (RBAC).

### Capabilities by Role:
- **`admin`**: Full system control, user management, playbook execution, alert testing.
- **`analyst`**: Telemetry analysis, ML benchmarking, attack simulation, compliance reporting, risk calculation.
- **`viewer`**: Read-only dashboard visibility for posture, compliance, and event logs.

### Constraints:
- Username must be unique and at least 3 characters.
- Password must be at least 6 characters.
- Email must be valid and not previously registered.
- Passwords are salted and securely hashed using SHA-256 before storage in SQLite.
""",
    response_description="User account creation confirmation and profile details (passwords omitted).",
    responses={
        200: {
            "description": "User successfully registered",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "data": {
                            "success": True,
                            "user": {
                                "user_id": "8f3e2b1a-9c4d-4e5f-b6a7-0d1e2f3a4b5c",
                                "username": "analyst_jane",
                                "email": "analyst_jane@ramantivirus.com",
                                "role": "analyst",
                                "full_name": "Jane Doe",
                                "permissions": [
                                    "dashboard:read", "events:read", "cspm:read", "ciem:read",
                                    "ml:read", "ml:execute", "remediation:read",
                                    "compliance:read", "compliance:generate",
                                    "simulation:read", "simulation:execute", "risk:read"
                                ],
                                "created_at": "2026-03-15T10:00:00Z"
                            }
                        }
                    }
                }
            }
        },
        400: {
            "description": "Validation failure (username/password too short, user exists, email duplicate, invalid role)",
            "content": {
                "application/json": {
                    "example": {"detail": "Username 'analyst_jane' already exists"}
                }
            }
        }
    }
)
def api_register(req: RegisterRequest):
    result = register_user(req.username, req.password, req.email, req.role, req.full_name)
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["error"])
    return {"status": "success", "data": result}


@app.post(
    "/api/auth/login",
    tags=["Authentication & Access Control"],
    summary="Authenticate User & Issue JWT Token",
    description="""
Authenticate user credentials and receive a signed JSON Web Token (JWT) Bearer access token valid for 24 hours.

### Usage in Swagger UI:
1. Call this endpoint with valid credentials (`admin` / `admin123` or `analyst1` / `analyst123`).
2. Copy the `token` string from the response.
3. Click the **Authorize** 🔓 button at the top right of the Swagger UI.
4. Paste the token into the **Value** field and click **Authorize**.
""",
    response_description="JWT access token, token type, expiry duration (in seconds), and authenticated user details.",
    responses={
        200: {
            "description": "Authentication successful, token issued",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "data": {
                            "success": True,
                            "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                            "token_type": "Bearer",
                            "expires_in": 86400,
                            "user": {
                                "user_id": "8f3e2b1a-9c4d-4e5f-b6a7-0d1e2f3a4b5c",
                                "username": "admin",
                                "email": "admin@ramantivirus.com",
                                "role": "admin",
                                "full_name": "System Administrator",
                                "permissions": [
                                    "dashboard:read", "events:read", "cspm:read", "ciem:read",
                                    "ml:read", "ml:execute", "remediation:read", "remediation:execute",
                                    "compliance:read", "compliance:generate", "compliance:export",
                                    "simulation:read", "simulation:execute",
                                    "users:read", "users:manage", "risk:read", "risk:configure"
                                ]
                            }
                        }
                    }
                }
            }
        },
        401: {
            "description": "Authentication failed (invalid username/password or deactivated account)",
            "content": {
                "application/json": {
                    "example": {"detail": "Invalid username or password"}
                }
            }
        }
    }
)
def api_login(req: LoginRequest):
    result = login_user(req.username, req.password)
    if not result["success"]:
        raise HTTPException(status_code=401, detail=result["error"])
    return {"status": "success", "data": result}


@app.get(
    "/api/auth/me",
    tags=["Authentication & Access Control"],
    summary="Get Current User Profile & Permissions",
    description="""
Retrieve account details, active role, and permission grants for the currently authenticated user session.

**Authentication Required:** Bearer token must be provided via the `Authorization` header (`Bearer <token>`) or the Swagger UI Authorize button.
""",
    response_description="Authenticated user token payload with user ID, username, role, and permission scopes.",
    dependencies=[Depends(bearer_scheme)],
    responses={
        200: {
            "description": "User profile successfully retrieved",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "data": {
                            "user_id": "8f3e2b1a-9c4d-4e5f-b6a7-0d1e2f3a4b5c",
                            "username": "admin",
                            "role": "admin",
                            "permissions": ["dashboard:read", "events:read", "users:read", "users:manage"],
                            "iat": 1700000000,
                            "exp": 1700086400,
                            "iss": "ram-antivirus-cloud-security"
                        }
                    }
                }
            }
        },
        401: {
            "description": "Missing, invalid, or expired Bearer token",
            "content": {
                "application/json": {
                    "example": {"detail": "Invalid or missing token"}
                }
            }
        }
    }
)
def api_get_me(
    authorization: Optional[str] = Header(None, description="Bearer token in format: `Bearer <jwt_token>`"),
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)
):
    user = _get_current_user(authorization, credentials)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or missing token")
    return {"status": "success", "data": user}


@app.get(
    "/api/auth/roles",
    tags=["Authentication & Access Control"],
    summary="List RBAC Roles & Permission Scopes",
    description="Retrieve the complete Role-Based Access Control (RBAC) permission matrix defining capabilities and descriptions for `admin`, `analyst`, and `viewer` roles.",
    response_description="Dictionary mapping each system role to its description and granted permissions list.",
    responses={
        200: {
            "description": "RBAC role definitions retrieved successfully",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "data": {
                            "admin": {
                                "description": "Full access — all endpoints, remediation, user management",
                                "permissions": ["dashboard:read", "events:read", "cspm:read", "ciem:read", "users:read", "users:manage"]
                            },
                            "analyst": {
                                "description": "View + alerts + compliance + ML analysis",
                                "permissions": ["dashboard:read", "events:read", "cspm:read", "ciem:read", "ml:read", "ml:execute"]
                            },
                            "viewer": {
                                "description": "Read-only dashboard access",
                                "permissions": ["dashboard:read", "events:read", "cspm:read", "ciem:read"]
                            }
                        }
                    }
                }
            }
        }
    }
)
def api_get_roles():
    return {"status": "success", "data": get_role_info()}


@app.get(
    "/api/auth/users",
    tags=["Authentication & Access Control"],
    summary="List All Registered Users (Admin)",
    description="""
Retrieve all registered user accounts with roles, activation status, creation timestamps, and last login dates.

**Permissions Required:** `users:read` (`admin` role).
""",
    response_description="Array of user accounts (password hashes are securely omitted).",
    dependencies=[Depends(bearer_scheme)],
    responses={
        200: {
            "description": "User accounts directory retrieved successfully",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "data": [
                            {
                                "user_id": "8f3e2b1a-9c4d-4e5f-b6a7-0d1e2f3a4b5c",
                                "username": "admin",
                                "email": "admin@ramantivirus.com",
                                "role": "admin",
                                "full_name": "System Administrator",
                                "created_at": "2026-01-01T00:00:00Z",
                                "last_login": "2026-03-15T09:30:00Z",
                                "is_active": True
                            },
                            {
                                "user_id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
                                "username": "analyst1",
                                "email": "analyst@ramantivirus.com",
                                "role": "analyst",
                                "full_name": "Security Analyst",
                                "created_at": "2026-01-01T00:00:00Z",
                                "last_login": "2026-03-15T08:15:00Z",
                                "is_active": True
                            }
                        ]
                    }
                }
            }
        },
        401: {"description": "Missing or invalid authorization token", "content": {"application/json": {"example": {"detail": "Authorization header required"}}}},
        403: {"description": "Forbidden (insufficient permissions, requires admin role)", "content": {"application/json": {"example": {"detail": "Insufficient permissions. Required: 'users:read'. Your role: 'analyst'"}}}}
    }
)
def api_list_users(
    authorization: Optional[str] = Header(None, description="Admin Bearer token (`Bearer <jwt_token>`)"),
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)
):
    _require_permission(authorization, "users:read", credentials)
    return {"status": "success", "data": get_all_users()}


@app.post(
    "/api/auth/users/{username}/deactivate",
    tags=["Authentication & Access Control"],
    summary="Deactivate User Account (Admin)",
    description="""
Deactivate a registered user account to prevent future logins. Existing sessions will expire upon token expiration.

**Permissions Required:** `users:manage` (`admin` role).
""",
    response_description="Deactivation confirmation message.",
    dependencies=[Depends(bearer_scheme)],
    responses={
        200: {
            "description": "User successfully deactivated",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "data": {"success": True, "message": "User 'analyst1' deactivated"}
                    }
                }
            }
        },
        401: {"description": "Missing or invalid authorization token", "content": {"application/json": {"example": {"detail": "Authorization header required"}}}},
        403: {"description": "Forbidden (requires admin role with users:manage)", "content": {"application/json": {"example": {"detail": "Insufficient permissions. Required: 'users:manage'"}}}},
        404: {"description": "User not found", "content": {"application/json": {"example": {"detail": "User 'unknown_user' not found"}}}}
    }
)
def api_deactivate_user(
    username: str = Path(..., description="Username of the user account to deactivate", openapi_examples={"default": {"value": "analyst1"}}),
    authorization: Optional[str] = Header(None, description="Admin Bearer token"),
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)
):
    _require_permission(authorization, "users:manage", credentials)
    result = deactivate_user(username)
    if not result["success"]:
        raise HTTPException(status_code=404, detail=result["error"])
    return {"status": "success", "data": result}


@app.post(
    "/api/auth/users/{username}/reactivate",
    tags=["Authentication & Access Control"],
    summary="Reactivate User Account (Admin)",
    description="""
Reactivate a previously deactivated user account, restoring login access.

**Permissions Required:** `users:manage` (`admin` role).
""",
    response_description="Reactivation confirmation message.",
    dependencies=[Depends(bearer_scheme)],
    responses={
        200: {
            "description": "User successfully reactivated",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "data": {"success": True, "message": "User 'analyst1' reactivated"}
                    }
                }
            }
        },
        401: {"description": "Missing or invalid authorization token", "content": {"application/json": {"example": {"detail": "Authorization header required"}}}},
        403: {"description": "Forbidden (requires admin role with users:manage)", "content": {"application/json": {"example": {"detail": "Insufficient permissions. Required: 'users:manage'"}}}},
        404: {"description": "User not found", "content": {"application/json": {"example": {"detail": "User 'unknown_user' not found"}}}}
    }
)
def api_reactivate_user(
    username: str = Path(..., description="Username of the user account to reactivate", openapi_examples={"default": {"value": "analyst1"}}),
    authorization: Optional[str] = Header(None, description="Admin Bearer token"),
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)
):
    _require_permission(authorization, "users:manage", credentials)
    result = reactivate_user(username)
    if not result["success"]:
        raise HTTPException(status_code=404, detail=result["error"])
    return {"status": "success", "data": result}


# ══════════════════════════════════════════════════════════════════════════════
# 2 — SECURITY POSTURE & SCANS (CSPM & CIEM)
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/events", include_in_schema=False)
@app.get(
    "/api/simulate/events",
    tags=["ML Detection & Analytics"],
    summary="Fetch & Analyze Security Events with ML",
    description="""
Retrieve cloud security events and process them through the multi-model PyOD machine learning anomaly detection pipeline.

### Operational Data Source:
- **Live Wazuh SIEM:** If a real Wazuh alert file exists at `WAZUH_LOG_PATH` (`/var/ossec/logs/alerts/alerts.json` or local path), real alerts are read and analyzed.
- **Simulation Fallback:** If Wazuh logs are unavailable, synthetic high-fidelity cloud events are generated using the parameters provided.

### ML Scoring:
Each event is evaluated by Isolation Forest, KNN, and HBOS models to assign an anomaly score (0.0 to 1.0), binary anomaly flag (`is_anomaly`), and severity rating (`Critical`, `High`, `Medium`, `Low`).
""",
    response_description="Array of analyzed security telemetry events with machine learning anomaly scores and classifications.",
    responses={
        200: {
            "description": "Events retrieved and analyzed successfully",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "count": 175,
                        "source": "simulated",
                        "data": [
                            {
                                "id": "EVT-8F3E2B1A",
                                "timestamp": "2026-03-15T10:14:22Z",
                                "source": "wazuh",
                                "rule_id": 5712,
                                "level": 12,
                                "severity": "critical",
                                "event_type": "attack",
                                "attack_type": "brute_force",
                                "user": "admin",
                                "src_ip": "192.168.1.105",
                                "service": "iam",
                                "region": "us-east-1",
                                "bytes_transferred": 0,
                                "failed_attempts": 25,
                                "ml_anomaly_score": 0.884,
                                "is_anomaly": True,
                                "ml_severity": "Critical",
                                "detected_by": "iforest"
                            }
                        ]
                    }
                }
            }
        }
    }
)
def get_simulated_events(
    hours: int = Query(24, ge=1, le=168, description="Time window in hours for event generation", openapi_examples={"default": {"value": 24}}),
    normal: int = Query(150, ge=1, le=1000, description="Number of baseline normal events to generate", openapi_examples={"default": {"value": 150}}),
    attacks: int = Query(25, ge=0, le=500, description="Number of simulated threat/attack events to inject", openapi_examples={"default": {"value": 25}}),
    search: Optional[str] = Query(None, description="Search filter for user, IP, action, or description"),
    severity: Optional[str] = Query(None, description="Filter by event severity (all, critical, high, medium, low)"),
    limit: int = Query(200, ge=1, le=1000, description="Maximum number of events to return")
):
    session = session_manager.get_session()
    if session and session.analyzed_events:
        all_events = session.analyzed_events
        source_mode = session.data_source
    else:
        raw_events = _get_events(normal, attacks)
        all_events = analyze_events(raw_events)
        source_mode = get_wazuh_status()["mode"]

    # Apply search filter
    filtered = all_events
    if search:
        s_lower = search.lower()
        filtered = [
            e for e in filtered
            if s_lower in str(e.get("user", "")).lower()
            or s_lower in str(e.get("src_ip", "")).lower()
            or s_lower in str(e.get("action", "")).lower()
            or s_lower in str(e.get("description", "")).lower()
            or s_lower in str(e.get("service", "")).lower()
            or s_lower in str(e.get("id", "")).lower()
        ]

    # Apply severity filter
    if severity and severity.lower() != "all":
        sev_target = severity.lower()
        filtered = [
            e for e in filtered
            if (e.get("severity") or e.get("ml_severity") or "").lower() == sev_target
        ]

    paginated = filtered[:limit]
    return {
        "status": "success",
        "total": len(all_events),
        "count": len(paginated),
        "data": paginated,
        "source": source_mode
    }


@app.get(
    "/api/cspm/scan",
    tags=["Security Posture (CSPM & CIEM)"],
    summary="Execute Cloud Security Posture Management Scan",
    description="""
Execute a CSPM scan across cloud resource configurations to identify security misconfigurations and compliance violations.

### Operational Modes:
- **LocalStack AWS:** When LocalStack is running on `http://localhost:4566`, queries emulated AWS resources (S3 bucket public access blocks, Security Group ingress rules, IAM policies) using `boto3`.
- **Telemetry-Derived / Simulated:** If LocalStack is unavailable, derives misconfigurations from audit event telemetry.

All scan findings are automatically logged into the SQLite posture scan history table.
""",
    response_description="Array of CSPM configuration findings with severity, affected resources, and remediation instructions.",
    responses={
        200: {
            "description": "CSPM scan executed and findings persisted",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "count": 3,
                        "source": "simulated",
                        "data": [
                            {
                                "scan_id": "CSPM-9B1A4C2E",
                                "vulnerability_id": "CSPM-S3-001",
                                "title": "S3 Bucket Publicly Accessible",
                                "severity": "critical",
                                "resource": "arn:aws:s3:::customer-data-backup",
                                "description": "Large-volume transfer to an external IP indicates a publicly accessible S3 bucket was exploited.",
                                "remediation": "Enable S3 Block Public Access on all buckets. Review bucket policies and ACLs.",
                                "status": "open"
                            }
                        ]
                    }
                }
            }
        }
    }
)
def get_cspm_results():
    events = _get_events(80, 20)
    results = _get_cspm(events)
    return {
        "status": "success",
        "count": len(results),
        "data": results,
        "source": get_localstack_status()["mode"]
    }


@app.get(
    "/api/ciem/scan",
    tags=["Security Posture (CSPM & CIEM)"],
    summary="Execute Cloud Infrastructure Entitlement Scan",
    description="""
Execute a CIEM scan to detect excessive entitlements, inactive IAM roles, privilege escalation paths, wildcard policies, and identity risks across human and machine identities.

### Operational Modes:
- **LocalStack AWS IAM:** When LocalStack is running on `http://localhost:4566`, inspects emulated IAM users, groups, and roles for wildcard permissions (`Action: *`, `Resource: *`).
- **Telemetry-Derived / Simulated:** Derives identity risks from recent event logs and attack patterns.

Findings are persisted to the SQLite entitlement scan history table.
""",
    response_description="Array of CIEM identity findings with entity name, entity type, assessed risk level, and remediation guidance.",
    responses={
        200: {
            "description": "CIEM scan completed successfully",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "count": 2,
                        "source": "simulated",
                        "data": [
                            {
                                "scan_id": "CIEM-4D2E8F1A",
                                "risk_id": "CIEM-001",
                                "title": "Over-privileged Identity",
                                "entity_name": "developer-service-role",
                                "entity_type": "machine",
                                "risk_level": "high",
                                "description": "Identity performed actions beyond expected scope indicating AdministratorAccess or wildcard policy.",
                                "remediation": "Generate a least-privilege policy using IAM Access Analyzer. Remove unused permissions."
                            }
                        ]
                    }
                }
            }
        }
    }
)
def get_ciem_results():
    events = _get_events(80, 20)
    results = _get_ciem(events)
    return {
        "status": "success",
        "count": len(results),
        "data": results,
        "source": get_localstack_status()["mode"]
    }


@app.get(
    "/api/dashboard/summary",
    tags=["Security Posture (CSPM & CIEM)"],
    summary="Get Executive Dashboard Summary",
    description="Retrieve consolidated executive overview metrics aggregating critical/high threat counts from PyOD ML analysis, open CSPM misconfigurations, open CIEM identity risks, and the 5 most recent critical security alerts.",
    response_description="Executive summary metrics object.",
    responses={
        200: {
            "description": "Dashboard summary metrics retrieved successfully",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "data": {
                            "threats": {
                                "critical": 3,
                                "high": 7,
                                "total_analyzed": 115
                            },
                            "posture": {
                                "cspm_open_issues": 4,
                                "ciem_open_risks": 2
                            },
                            "recent_critical_alerts": [
                                {
                                    "id": "EVT-CRIT-001",
                                    "timestamp": "2026-03-15T10:12:00Z",
                                    "attack_type": "brute_force",
                                    "user": "admin",
                                    "ml_anomaly_score": 0.942,
                                    "ml_severity": "Critical",
                                    "description": "Brute force attack detected on privileged account"
                                }
                            ]
                        }
                    }
                }
            }
        }
    }
)
def get_dashboard_summary():
    session = session_manager.get_session()
    summary = session.to_summary()

    # Enrich with live asset inventory and correlated incidents
    try:
        inv = get_asset_inventory()
        inc = get_correlated_incidents()
        vulns = get_vulnerability_summary()
        summary["assets"] = {
            "total_assets": inv.get("total_assets", 8),
            "critical_risk_assets": inv.get("critical_risk_assets", 0),
            "connectors": inv.get("connectors", {})
        }
        summary["incidents"] = {
            "total_incidents": inc.get("total_incidents", 0),
            "open_incidents": inc.get("open_incidents", 0),
            "contained_incidents": inc.get("contained_incidents", 0),
            "resolved_incidents": inc.get("resolved_incidents", 0)
        }
        summary["vulnerabilities"] = {
            "total": vulns.get("total_vulnerabilities", 0),
            "critical": vulns.get("critical_count", 0),
            "high": vulns.get("high_count", 0)
        }
    except Exception:
        pass

    return {
        "status": "success",
        "data": summary
    }


@app.get(
    "/api/simulate/attack",
    tags=["ML Detection & Analytics"],
    summary="Simulate Targeted Attack & Evaluate ML Score",
    description="""
Inject a targeted cyberattack scenario into benign background noise to evaluate the PyOD anomaly detection engine under realistic conditions.

### Supported Attack Types:
- **`brute_force`**: Generates high-volume failed authentication attempts against privileged accounts.
- **`data_exfiltration`**: Simulates massive outbound bytes transfer from cloud storage to external destinations.
""",
    response_description="Targeted event ML evaluation results and full event dataset.",
    responses={
        200: {
            "description": "Targeted attack simulated and evaluated successfully",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "pyod_analysis": {
                            "score": 0.923,
                            "is_anomaly": True,
                            "severity": "Critical"
                        },
                        "all_data": [
                            {
                                "id": "TARGETED-ATTACK-002",
                                "attack_type": "brute_force",
                                "ml_anomaly_score": 0.923,
                                "is_anomaly": True,
                                "ml_severity": "Critical"
                            }
                        ]
                    }
                }
            }
        }
    }
)
def trigger_targeted_attack(
    type: str = Query("brute_force", description="Targeted attack type: 'brute_force' or 'data_exfiltration'", openapi_examples={"default": {"value": "brute_force"}})
):
    noise = simulate_session(n_normal=50, n_attacks=0, time_window_hours=1)
    if type == "data_exfiltration":
        attack = {
            "id": "TARGETED-ATTACK-001", "timestamp": noise[0]["timestamp"], "source": "wazuh",
            "rule_id": 31101, "level": 15, "severity": "critical", "event_type": "attack",
            "attack_type": "data_exfiltration", "user": "malicious-actor", "src_ip": "1.2.3.4",
            "dst_ip": "99.88.77.66", "service": "s3", "region": "us-east-1", "action": "ExfiltrateData",
            "status": "success", "bytes_transferred": 10_000_000_000, "failed_attempts": 0,
            "description": "TARGETED TEST: Massive data transfer detected"
        }
    else:
        attack = {
            "id": "TARGETED-ATTACK-002", "timestamp": noise[0]["timestamp"], "source": "wazuh",
            "rule_id": 5712, "level": 12, "severity": "critical", "event_type": "attack",
            "attack_type": "brute_force", "user": "admin", "src_ip": "103.21.244.1",
            "dst_ip": "10.0.0.5", "service": "iam", "region": "us-east-1", "action": "ConsoleLogin",
            "status": "failure", "bytes_transferred": 0, "failed_attempts": 500,
            "description": "TARGETED TEST: Massive brute force detected"
        }
    events = [attack] + noise
    analyzed = analyze_events(events)
    target_result = next(e for e in analyzed if e["id"].startswith("TARGETED-ATTACK"))
    return {
        "status": "success",
        "pyod_analysis": {
            "score": target_result.get("ml_anomaly_score", 0.0),
            "is_anomaly": target_result.get("is_anomaly", False),
            "severity": target_result.get("ml_severity", "Low")
        },
        "all_data": analyzed
    }


# ══════════════════════════════════════════════════════════════════════════════
# 3 — MACHINE LEARNING ENSEMBLE
# ══════════════════════════════════════════════════════════════════════════════

@app.get(
    "/api/ml/compare",
    tags=["ML Detection & Analytics"],
    summary="Benchmark Multi-Model ML Ensemble",
    description="""
Compare performance metrics across the platform's multi-model anomaly detection ensemble on a generated event dataset:
- **Isolation Forest (iforest):** Trained on NSL-KDD dataset; specializes in brute force, privilege escalation, and port scans.
- **K-Nearest Neighbors (knn):** Trained on CICIDS-2017 dataset; specializes in DDoS, web attacks, botnets, and lateral movement.
- **Histogram-based Outlier Score (hbos):** Trained on UNSW-NB15 dataset; specializes in malware, reconnaissance, and backdoors.

Returns per-model detection counts, individual anomaly scores, execution latency, and specialist strengths.
""",
    response_description="Multi-model benchmark evaluation comparison matrix.",
    responses={
        200: {
            "description": "ML models compared successfully",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "data": {
                            "models": {
                                "iforest": {"display_name": "Isolation Forest (NSL-KDD)", "anomalies_detected": 18, "avg_score": 0.742},
                                "knn": {"display_name": "KNN (CICIDS-2017)", "anomalies_detected": 15, "avg_score": 0.688},
                                "hbos": {"display_name": "HBOS (UNSW-NB15)", "anomalies_detected": 20, "avg_score": 0.812}
                            },
                            "total_events": 120,
                            "ensemble_agreement": 82.5
                        }
                    }
                }
            }
        }
    }
)
def ml_model_comparison(
    normal: int = Query(100, ge=1, le=1000, description="Number of baseline normal events for comparison", openapi_examples={"default": {"value": 100}}),
    attacks: int = Query(20, ge=1, le=500, description="Number of attack events for comparison", openapi_examples={"default": {"value": 20}})
):
    events = simulate_session(n_normal=normal, n_attacks=attacks)
    return {"status": "success", "data": compare_models(events)}


@app.get(
    "/api/ml/model-info",
    tags=["ML Detection & Analytics"],
    summary="Get ML Model Metadata & Training Specs",
    description="Retrieve architecture metadata, training datasets, benchmark F1 scores, specialized attack types, contamination rates, and feature scalers for the loaded pre-trained PyOD machine learning models.",
    response_description="Metadata details for Isolation Forest, KNN, and HBOS models.",
    responses={
        200: {
            "description": "Model metadata retrieved successfully",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "data": {
                            "models_loaded": ["iforest", "knn", "hbos"],
                            "training_meta": {
                                "iforest": {
                                    "dataset": "NSL-KDD",
                                    "f1_score": 0.620,
                                    "specialises": ["brute_force", "privilege_escalation", "port_scan"]
                                },
                                "knn": {
                                    "dataset": "CICIDS-2017",
                                    "f1_score": 0.2416,
                                    "specialises": ["ddos", "web_attacks", "botnet", "lateral_movement"]
                                },
                                "hbos": {
                                    "dataset": "UNSW-NB15",
                                    "f1_score": 1.0,
                                    "specialises": ["malware", "reconnaissance", "backdoor"]
                                }
                            }
                        }
                    }
                }
            }
        }
    }
)
def ml_model_info():
    """Return metadata about the loaded pre-trained models."""
    return {"status": "success", "data": get_model_info()}


@app.get(
    "/api/ml/benchmark",
    tags=["ML Detection & Analytics"],
    summary="Get Multi-Algorithm Benchmark Results",
    description="Retrieve empirical evaluation metrics across all 7 benchmarked candidate algorithms on the NSL-KDD held-out test set (N=22,544)."
)
def ml_benchmark_results():
    """Return empirical evaluation metrics across all 7 benchmarked candidate algorithms."""
    return {"status": "success", "data": get_benchmark_results()}


class EvaluateEventsRequest(BaseModel):
    events: List[Dict[str, Any]] = Field(
        ...,
        description="Array of raw or normalized security telemetry events to evaluate"
    )


class UpdateFindingStatusRequest(BaseModel):
    status: str = Field(..., description="Target status: open, investigating, contained, resolved")


class UpdateIncidentStatusRequest(BaseModel):
    status: str = Field(..., description="Target status: open, investigating, contained, resolved")
    notes: Optional[str] = Field(None, description="Optional resolution or analyst notes")


@app.get(
    "/api/detection/detectors",
    tags=["ML Detection & Analytics"],
    summary="List Registered Attack Category Detectors",
    description="Retrieve all modular attack category detectors registered in the platform, including taxonomy index, supported telemetry sources, and active status.",
    response_description="Array of registered detector descriptors.",
    responses={
        200: {
            "description": "Registered attack detectors retrieved successfully",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "count": 1,
                        "data": [
                            {
                                "category": "brute_force",
                                "category_index": 1,
                                "name": "Brute-Force & Credential Abuse Detector",
                                "description": "Detects rapid consecutive authentication failures targeting an identity within a sliding time window.",
                                "supported_sources": ["wazuh", "cloudtrail", "host_audit", "synthetic"],
                                "enabled": True
                            }
                        ]
                    }
                }
            }
        }
    }
)
def list_attack_detectors():
    return {
        "status": "success",
        "count": len(detector_registry.list_all()),
        "data": detector_registry.list_all()
    }


@app.get(
    "/api/detection/findings",
    tags=["ML Detection & Analytics"],
    summary="Run Attack Detectors on Telemetry Stream",
    description="Fetch current security telemetry events from Wazuh or live buffer, normalize them, run all registered attack detectors (including Brute-Force Category 1), and return structured SecurityFinding objects.",
    response_description="Array of security findings with observed facts, inferred hypotheses, and response playbooks.",
    responses={
        200: {
            "description": "Detection executed and findings generated",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "count": 1,
                        "data": [],
                        "source": "simulated"
                    }
                }
            }
        }
    }
)
def get_detected_findings(
    normal: Optional[int] = Query(None, ge=1, le=500, description="Baseline normal events count"),
    attacks: Optional[int] = Query(None, ge=0, le=200, description="Injected attack events count")
):
    session = session_manager.get_session()
    # If the caller explicitly requested a specific attack count > 0, inject brute force scenario
    if attacks is not None and attacks > 0:
        session_manager.inject_scenario("brute_force", "high")
        session = session_manager.get_session()

    if session and session.findings is not None:
        findings_data = session.findings
    else:
        persisted = get_findings_db(limit=200)
        if persisted:
            findings_data = persisted
        else:
            raw_events = session.events if session and session.events else _get_events(normal or 50, attacks or 0)
            norm_events = [normalize_event(e) for e in raw_events]
            eval_findings = detector_registry.run_all(norm_events)
            findings_data = [f.model_dump(mode="json") for f in eval_findings]
            for f in findings_data:
                f["data_source"] = session.data_source if session else "SIMULATED"
            try:
                save_findings_db(findings_data)
            except Exception:
                pass
        if session:
            session.findings = findings_data

    return {
        "status": "success",
        "count": len(findings_data),
        "data": findings_data,
        "source": session.data_source if session else get_wazuh_status()["mode"]
    }


@app.post(
    "/api/detection/evaluate",
    tags=["ML Detection & Analytics"],
    summary="Evaluate Event Batch with Attack Detectors",
    description="Submit an arbitrary batch of telemetry events to normalize and evaluate against all registered attack category detectors.",
    response_description="Array of security findings with evidence and response playbooks.",
    responses={
        200: {
            "description": "Custom event batch evaluated successfully",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "count": 1,
                        "data": []
                    }
                }
            }
        }
    }
)
def evaluate_custom_events(payload: EvaluateEventsRequest):
    norm_events = [normalize_event(e) for e in payload.events]
    findings = detector_registry.run_all(norm_events)
    return {
        "status": "success",
        "count": len(findings),
        "data": [f.model_dump(mode="json") for f in findings]
    }


# ── Finding Status Lifecycle ──────────────────────────────────────────────────

@app.patch(
    "/api/findings/{finding_id}/status",
    tags=["Threat Detection & Findings"],
    summary="Update Security Finding Status",
    description="Update the lifecycle status of a specific security finding (open, investigating, contained, resolved)."
)
def update_finding_status(
    finding_id: str = Path(..., description="The unique finding ID"),
    payload: UpdateFindingStatusRequest = None
):
    valid_statuses = {"open", "investigating", "contained", "resolved"}
    if not payload or payload.status.lower() not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of {valid_statuses}")

    updated = update_finding_status_db(finding_id, payload.status.lower())

    # Also update in active session if present
    session = session_manager.get_session()
    if session and session.findings:
        for f in session.findings:
            if f.get("finding_id") == finding_id:
                f["status"] = payload.status.lower()
                break

    return {
        "status": "success",
        "finding_id": finding_id,
        "new_status": payload.status.lower(),
        "updated_in_db": updated
    }


# ── Incident Correlation & Investigation ──────────────────────────────────────

@app.get(
    "/api/incidents",
    tags=["Incident Correlation & Management"],
    summary="Get Correlated Security Incidents",
    description="""
Retrieve deterministic, multi-signal security incidents correlated from atomic findings.
Groups related findings sharing identical principal identity, source IP, or cloud resource within a sliding temporal window (default 15 minutes / 900 seconds).
""",
    response_description="Array of correlated security incidents with member finding summaries and correlation evidence.",
    responses={
        200: {
            "description": "Correlated security incidents retrieved successfully",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "count": 2,
                        "total": 2,
                        "data": []
                    }
                }
            }
        }
    }
)
def get_correlated_incidents(
    status: Optional[str] = Query(None, description="Filter by incident status: 'open', 'resolved', 'investigating'"),
    severity: Optional[str] = Query(None, description="Filter by severity: 'critical', 'high', 'medium', 'low'"),
    limit: int = Query(100, ge=1, le=500, description="Max incidents to return")
):
    session = session_manager.get_session()
    incidents = []
    if session and session.incidents:
        incidents = session.incidents
    else:
        persisted = get_incidents_db(limit=limit, status=status, severity=severity)
        if persisted:
            incidents = persisted
        else:
            current_findings = session.findings if session and session.findings else get_findings_db(limit=200)
            if current_findings:
                corr_incidents = correlate_findings(current_findings)
                incidents = [inc.model_dump(mode="json") if hasattr(inc, "model_dump") else inc for inc in corr_incidents]
                if session:
                    session.incidents = incidents
                try:
                    save_incidents_db(incidents)
                except Exception:
                    pass

    filtered = incidents
    if status and status.lower() != "all":
        filtered = [inc for inc in filtered if (inc.get("status") or "").lower() == status.lower()]
    if severity and severity.lower() != "all":
        filtered = [inc for inc in filtered if (inc.get("severity") or "").lower() == severity.lower()]

    open_cnt = sum(1 for inc in incidents if (inc.get("status") or "").lower() == "open")
    contained_cnt = sum(1 for inc in incidents if (inc.get("status") or "").lower() == "contained")
    resolved_cnt = sum(1 for inc in incidents if (inc.get("status") or "").lower() == "resolved")
    crit_cnt = sum(1 for inc in incidents if (inc.get("severity") or "").lower() == "critical")
    high_cnt = sum(1 for inc in incidents if (inc.get("severity") or "").lower() == "high")

    return {
        "status": "success",
        "count": len(filtered[:limit]),
        "total": len(incidents),
        "total_incidents": len(incidents),
        "open_incidents": open_cnt,
        "contained_incidents": contained_cnt,
        "resolved_incidents": resolved_cnt,
        "critical_incidents": crit_cnt,
        "high_incidents": high_cnt,
        "data": filtered[:limit],
        "incidents": filtered[:limit]
    }


@app.post(
    "/api/incidents/correlate",
    tags=["Incident Correlation & Management"],
    summary="Trigger Cross-Detector Incident Correlation",
    description="Re-run correlation engine across current findings to synthesize updated incidents."
)
def trigger_incident_correlation():
    session = session_manager.get_session()
    current_findings = session.findings if session and session.findings else get_findings_db(limit=500)
    corr_incidents = correlate_findings(current_findings)
    incidents_data = [inc.model_dump(mode="json") if hasattr(inc, "model_dump") else inc for inc in corr_incidents]
    if session:
        session.incidents = incidents_data
    try:
        save_incidents_db(incidents_data)
    except Exception:
        pass
    return {
        "status": "success",
        "incidents_created": len(incidents_data),
        "data": incidents_data,
        "incidents": incidents_data
    }


@app.patch(
    "/api/incidents/{incident_id}/status",
    tags=["Incident Correlation & Management"],
    summary="Update Incident Status",
    description="Update incident lifecycle status (open, investigating, contained, resolved)."
)
def update_incident_status(
    incident_id: str = Path(..., description="The unique incident ID"),
    payload: UpdateIncidentStatusRequest = None
):
    valid_statuses = {"open", "investigating", "contained", "resolved"}
    if not payload or payload.status.lower() not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of {valid_statuses}")

    updated = update_incident_status_db(incident_id, payload.status.lower(), payload.notes)
    session = session_manager.get_session()
    if session and session.incidents:
        for inc in session.incidents:
            if inc.get("incident_id") == incident_id or inc.get("id") == incident_id:
                inc["status"] = payload.status.lower()
                if payload.notes:
                    inc["resolution_notes"] = payload.notes
                break
    return {
        "status": "success",
        "incident_id": incident_id,
        "new_status": payload.status.lower(),
        "updated": updated
    }


@app.get(
    "/api/incidents/stats",
    tags=["Incident Correlation & Investigation"],
    summary="Get Incident Correlation Metrics",
    description="Retrieve aggregate metrics across correlated incidents, including total incidents, open count, severity breakdown, and average findings per incident.",
    response_description="Incident correlation statistics object.",
)
def get_incident_stats():
    session = session_manager.get_session()
    incidents = session.incidents if session and session.incidents else get_incidents_db(limit=200)

    total = len(incidents)
    open_cnt = sum(1 for inc in incidents if (inc.get("status") or "").lower() == "open")
    critical = sum(1 for inc in incidents if (inc.get("severity") or "").lower() == "critical")
    high = sum(1 for inc in incidents if (inc.get("severity") or "").lower() == "high")
    medium = sum(1 for inc in incidents if (inc.get("severity") or "").lower() == "medium")
    low = sum(1 for inc in incidents if (inc.get("severity") or "").lower() == "low")
    avg_findings = round(sum(inc.get("finding_count", 1) for inc in incidents) / total, 1) if total > 0 else 1.0

    return {
        "status": "success",
        "data": {
            "total_incidents": total,
            "open_incidents": open_cnt,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "avg_findings_per_incident": avg_findings
        }
    }


@app.get(
    "/api/incidents/{incident_id}",
    tags=["Incident Correlation & Investigation"],
    summary="Get Specific Incident Details with Member Findings",
    description="Retrieve full forensic details for a correlated incident, including all individual security findings attached to it.",
    response_description="Detailed incident record with full member findings array.",
    responses={
        200: {
            "description": "Incident details retrieved successfully"
        },
        404: {
            "description": "Incident not found"
        }
    }
)
def get_incident_detail(
    incident_id: str = Path(..., description="Unique deterministic incident identifier (e.g. 'INC-A1B2C3D4')")
):
    session = session_manager.get_session()
    incident = None
    if session and session.incidents:
        incident = next((inc for inc in session.incidents if inc.get("incident_id") == incident_id or inc.get("id") == incident_id), None)

    if not incident:
        incident = get_incident_by_id_db(incident_id)

    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")

    return {
        "status": "success",
        "data": incident
    }


# ── Cloud Asset Discovery & Inventory (SRS FR-01) ─────────────────────────────

@app.get(
    "/api/assets",
    tags=["Cloud Asset Discovery & Inventory"],
    summary="Get Cloud Asset Inventory",
    description="Retrieve inventory of discovered cloud accounts, workloads, object storage, and security resources."
)
def get_assets_list():
    return get_asset_inventory()


@app.get(
    "/api/assets/inventory",
    tags=["Cloud Asset Discovery & Inventory"],
    summary="Get Detailed Cloud Asset Inventory",
    description="Retrieve full cloud asset inventory with risk scores, finding counts, and connector metadata."
)
def get_assets_inventory_detail():
    return get_asset_inventory()


@app.post(
    "/api/assets/scan",
    tags=["Cloud Asset Discovery & Inventory"],
    summary="Run Cloud Asset Discovery Scan",
    description="Trigger an active cloud resource discovery scan across connected providers."
)
def run_asset_discovery_scan():
    discovered = discover_assets(force_rescan=True)
    return {
        "status": "success",
        "count": len(discovered),
        "data": discovered
    }


@app.get(
    "/api/assets/connectors",
    tags=["Cloud Asset Discovery & Inventory"],
    summary="Check Cloud Connector Status",
    description="Check connectivity status for LocalStack, AWS, and Wazuh workload connectors."
)
def get_connectors_status():
    return {
        "status": "success",
        "connectors": check_connectors()
    }


# ── Workload Vulnerability Analysis (SRS FR-05) ───────────────────────────────

@app.get(
    "/api/vulnerabilities",
    tags=["Vulnerability Analysis"],
    summary="Get Workload Vulnerability Findings",
    description="Retrieve prioritized workload software vulnerabilities with CVSS scores and remediation patches."
)
def get_vulnerabilities_list():
    return get_vulnerability_summary()


@app.post(
    "/api/vulnerabilities/scan",
    tags=["Vulnerability Analysis"],
    summary="Execute Workload Vulnerability Scan",
    description="Execute vulnerability analysis against discovered workload assets."
)
def run_vulnerabilities_scan():
    findings = run_vulnerability_scan()
    return {
        "status": "success",
        "count": len(findings),
        "data": findings
    }


# ── Remediation Rollback (SRS FR-10) ──────────────────────────────────────────

@app.post(
    "/api/remediation/rollback/{execution_id}",
    tags=["Remediation & Playbooks"],
    summary="Rollback Executed Remediation Action",
    description="Roll back an automated remediation action and restore the targeted entity to its previous security state (SRS FR-10)."
)
def rollback_executed_remediation(execution_id: str = Path(..., description="Remediation execution ID")):
    result = rollback_remediation(execution_id)
    if result.get("status") == "error":
        raise HTTPException(status_code=404, detail=result["message"])
    return result


# ══════════════════════════════════════════════════════════════════════════════
# 4 — REMEDIATION & PLAYBOOKS
# ══════════════════════════════════════════════════════════════════════════════

@app.get(
    "/api/remediation/playbooks",
    tags=["Remediation & Playbooks"],
    summary="List Automated Remediation Playbooks",
    description="Retrieve the catalog of all automated security remediation playbooks configured in the platform, including execution steps, severity triggers, estimated execution durations, and rollback availability.",
    response_description="Playbook catalog definitions array.",
    responses={
        200: {
            "description": "Remediation playbooks retrieved successfully",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "count": 4,
                        "data": {
                            "brute_force": {
                                "playbook_id": "PB-BF-001",
                                "name": "Brute Force Response",
                                "description": "Automated response to detected brute force attacks",
                                "severity_trigger": "high",
                                "steps": [
                                    {"order": 1, "action": "block_ip", "automated": True},
                                    {"order": 2, "action": "lock_account", "automated": True}
                                ],
                                "rollback_available": True
                            }
                        }
                    }
                }
            }
        }
    }
)
def list_playbooks():
    return {"status": "success", "count": len(get_all_playbooks()), "data": get_all_playbooks()}


@app.post(
    "/api/remediation/dry-run/{attack_type}",
    tags=["Remediation & Playbooks"],
    summary="Execute Dry-Run of Remediation Playbook",
    description="Safely evaluate a remediation playbook in non-destructive dry-run mode. Validates execution steps without mutating cloud resources or issuing external alerts.",
    response_description="Dry-run execution outcome and step-by-step verification.",
    responses={
        200: {
            "description": "Playbook dry-run completed successfully",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "data": {
                            "execution_id": "EXEC-8F3E2B1A",
                            "playbook_id": "PB-BF-001",
                            "is_dry_run": True,
                            "overall_status": "completed"
                        }
                    }
                }
            }
        }
    }
)
def dry_run_remediation(
    attack_type: str = Path(..., description="Attack category playbook to dry-run", openapi_examples={"default": {"value": "brute_force"}})
):
    result = execute_playbook(attack_type, dry_run=True)
    return {"status": "success", "data": result}


@app.post(
    "/api/remediation/execute/{attack_type}",
    tags=["Remediation & Playbooks"],
    summary="Execute Incident Remediation Playbook",
    description="""
Trigger and execute an automated remediation playbook for a designated attack type (e.g., `brute_force`, `data_exfiltration`, `privilege_escalation`).
Supports safe dry-run execution (default) to avoid destructive cloud mutations unless live execution is explicitly instructed.
""",
    response_description="Playbook execution result record detailing actions executed, status, and outcome.",
    responses={
        200: {
            "description": "Playbook executed successfully",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "data": {
                            "execution_id": "REM-EXEC-8F3E2B1A",
                            "playbook_id": "PB-BF-001",
                            "attack_type": "brute_force",
                            "status": "completed",
                            "steps_executed": [
                                {"action": "block_ip", "status": "success", "detail": "Blocked source IP 192.168.1.105"},
                                {"action": "lock_account", "status": "success", "detail": "Account locked for 30 minutes"}
                            ],
                            "executed_at": "2026-03-15T10:15:30Z"
                        }
                    }
                }
            }
        }
    }
)
def execute_remediation(
    attack_type: str = Path(..., description="Attack category to remediate (e.g., 'brute_force', 'data_exfiltration', 'privilege_escalation')", openapi_examples={"default": {"value": "brute_force"}}),
    dry_run: bool = Query(True, description="When true (default), executes in dry-run mode without mutating live cloud resources")
):
    result = execute_playbook(attack_type, dry_run=dry_run)
    return {"status": "success", "data": result}


@app.post(
    "/api/remediation/auto",
    tags=["Remediation & Playbooks"],
    summary="Trigger Autonomous Threat Remediation",
    description="Scan recent events with the PyOD machine learning engine and autonomously trigger remediation playbooks for all detected anomalies rated Critical or High severity.",
    response_description="Autonomous remediation summary detailing triggered playbooks and mitigated threats.",
    responses={
        200: {
            "description": "Autonomous remediation executed successfully",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "data": {
                            "remediations_triggered": 3,
                            "summary": {
                                "fully_completed": 3,
                                "partial": 0,
                                "failed": 0
                            },
                            "remediations": [
                                {
                                    "threat_id": "EVT-8F3E2B1A",
                                    "playbook_id": "PB-BF-001",
                                    "status": "completed"
                                }
                            ]
                        }
                    }
                }
            }
        }
    }
)
def auto_remediate():
    events = _get_events(100, 20)
    analyzed = analyze_events(events)
    return {"status": "success", "data": auto_remediate_threats(analyzed)}


@app.post(
    "/api/remediation/config-fix/{vulnerability_id}",
    tags=["Remediation & Playbooks"],
    summary="Auto-Correct CSPM Misconfiguration",
    description="Apply an automated remediation fix for a specific CSPM vulnerability finding (e.g., `CSPM-S3-001` to enable S3 Block Public Access, `CSPM-EC2-002` to close unrestricted SSH port 22, `CSPM-IAM-003` to enforce MFA on privileged accounts).",
    response_description="Configuration fix execution record with previous and updated configuration states.",
    responses={
        200: {
            "description": "Configuration corrected successfully",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "data": {
                            "remediation_id": "CFG-FIX-4C2E8F1A",
                            "vulnerability_id": "CSPM-S3-001",
                            "status": "applied",
                            "resource": "arn:aws:s3:::customer-data-backup",
                            "action_taken": "Applied S3 Block Public Access settings",
                            "verified": True
                        }
                    }
                }
            }
        }
    }
)
def fix_configuration(
    vulnerability_id: str = Path(..., description="Vulnerability finding ID to fix (e.g., 'CSPM-S3-001', 'CSPM-EC2-002', 'CSPM-IAM-003')", openapi_examples={"default": {"value": "CSPM-S3-001"}})
):
    return {"status": "success", "data": correct_configuration(vulnerability_id)}


@app.post(
    "/api/remediation/revoke-access",
    tags=["Remediation & Playbooks"],
    summary="Revoke High-Risk Entity Access",
    description="Revoke cloud identity access and entitlements for a risky human user account or machine service principal identified during CIEM analysis.",
    response_description="Access revocation execution details.",
    responses={
        200: {
            "description": "Access revoked successfully",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "data": {
                            "revocation_id": "REV-8F3E2B1A",
                            "entity_name": "developer-service-role",
                            "entity_type": "machine",
                            "risk_level": "high",
                            "actions_taken": [
                                "Detached AdministratorAccess policy",
                                "Revoked active STS assume-role sessions",
                                "Applied DenyAll temporary policy"
                            ],
                            "status": "completed"
                        }
                    }
                }
            }
        }
    }
)
def revoke_access(
    entity_name: str = Query(..., description="Identity name or IAM role ARN to revoke", openapi_examples={"default": {"value": "developer-service-role"}}),
    entity_type: str = Query("human", description="Type of entity: 'human' or 'machine'", openapi_examples={"default": {"value": "machine"}}),
    risk_level: str = Query("high", description="Assessed risk level: 'critical', 'high', 'medium', or 'low'", openapi_examples={"default": {"value": "high"}})
):
    return {"status": "success", "data": revoke_entity_access(entity_name, entity_type, risk_level)}


@app.get(
    "/api/remediation/full-pipeline",
    tags=["Remediation & Playbooks"],
    summary="Execute End-to-End Remediation Pipeline",
    description="Execute the complete autonomous security response pipeline: generates and analyzes telemetry events, triggers playbooks for ML threats, applies configuration corrections for all CSPM findings, and executes access revocations for all CIEM risks.",
    response_description="Complete pipeline execution report covering ML threat mitigation, CSPM config fixes, and CIEM access revocations.",
    responses={
        200: {
            "description": "Full remediation pipeline executed successfully",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "data": {
                            "ml_analysis": {"total_events": 100, "anomalies_detected": 15},
                            "threat_remediation": {"remediations_triggered": 4, "summary": {"fully_completed": 4}},
                            "config_fixes": [{"vulnerability_id": "CSPM-S3-001", "status": "applied"}],
                            "access_revocations": [{"entity_name": "dormant-admin", "status": "completed"}]
                        }
                    }
                }
            }
        }
    }
)
def full_remediation_pipeline():
    events = _get_events(80, 20)
    analyzed = analyze_events(events)
    cspm_findings = _get_cspm(events)
    ciem_findings = _get_ciem(events)
    return {
        "status": "success",
        "data": {
            "ml_analysis": {"total_events": len(analyzed), "anomalies_detected": sum(1 for e in analyzed if e.get("is_anomaly"))},
            "threat_remediation": auto_remediate_threats(analyzed),
            "config_fixes": [correct_configuration(f["vulnerability_id"]) for f in cspm_findings],
            "access_revocations": [revoke_entity_access(f["entity_name"], f["entity_type"], f["risk_level"]) for f in ciem_findings],
        }
    }


# ══════════════════════════════════════════════════════════════════════════════
# 5 — COMPLIANCE MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════

@app.get(
    "/api/compliance/frameworks",
    tags=["Compliance Management"],
    summary="List Supported Compliance Frameworks",
    description="List all cybersecurity and regulatory compliance frameworks supported by the platform (ISO 27001, SOC 2, and GDPR) along with control counts, categories, and descriptions.",
    response_description="Dictionary of supported compliance framework metadata.",
    responses={
        200: {
            "description": "Compliance frameworks retrieved successfully",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "data": {
                            "ISO27001": {
                                "name": "ISO/IEC 27001:2022",
                                "description": "Information Security Management Systems (ISMS)",
                                "total_controls": 93
                            },
                            "SOC2": {
                                "name": "SOC 2 Type II",
                                "description": "Trust Services Criteria (AICPA)",
                                "total_controls": 64
                            },
                            "GDPR": {
                                "name": "General Data Protection Regulation",
                                "description": "EU Data Protection and Privacy Regulation",
                                "total_controls": 44
                            }
                        }
                    }
                }
            }
        }
    }
)
def list_frameworks():
    return {"status": "success", "data": COMPLIANCE_FRAMEWORKS}


@app.get(
    "/api/compliance/dashboard",
    tags=["Compliance Management"],
    summary="Get Compliance Posture Dashboard",
    description="""
Generate an aggregated compliance dashboard calculating compliance readiness scores (0-100%) and passing status across ISO 27001, SOC 2, and GDPR based on active CSPM configuration findings and CIEM identity risks.
Persists the calculated score in SQLite and returns historical compliance trend trajectory.
""",
    response_description="Dashboard data with overall score, per-framework scores, control passing percentages, and historical trend.",
    responses={
        200: {
            "description": "Compliance dashboard calculated successfully",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "data": {
                            "overall_score": 84.5,
                            "status": "compliant",
                            "trend": "+2.5%",
                            "frameworks": {
                                "ISO27001": {"score": 88.0, "status": "compliant", "controls_passed": 82, "controls_failed": 11},
                                "SOC2": {"score": 82.5, "status": "compliant", "controls_passed": 53, "controls_failed": 11},
                                "GDPR": {"score": 83.0, "status": "compliant", "controls_passed": 37, "controls_failed": 7}
                            }
                        }
                    }
                }
            }
        }
    }
)
def compliance_dashboard():
    events = _get_events(80, 15)
    cspm_findings = _get_cspm(events)
    ciem_findings = _get_ciem(events)
    dashboard = get_compliance_dashboard(cspm_findings, ciem_findings)
    dashboard["trend"] = get_compliance_trend_db(dashboard["overall_score"])
    save_compliance_score(dashboard["overall_score"])
    return {"status": "success", "data": dashboard}


@app.get(
    "/api/compliance/map",
    tags=["Compliance Management"],
    summary="Map Security Findings to Compliance Controls",
    description="Map current CSPM configuration vulnerabilities and CIEM identity risks directly to specific compliance controls and clauses within supported regulatory frameworks.",
    response_description="Mapped compliance controls with status (PASS, FAIL), severity, and associated findings.",
    responses={
        200: {
            "description": "Findings mapped to compliance controls successfully",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "data": {
                            "mapped_findings": [
                                {
                                    "finding_id": "CSPM-S3-001",
                                    "framework": "SOC2",
                                    "control": "CC6.1",
                                    "control_title": "Logical Access Controls",
                                    "status": "FAIL",
                                    "severity": "critical"
                                }
                            ]
                        }
                    }
                }
            }
        }
    }
)
def compliance_mapping(
    framework: Optional[str] = Query(None, description="Optional framework filter: 'ISO27001', 'SOC2', or 'GDPR' (default: all)", openapi_examples={"default": {"value": "SOC2"}})
):
    events = _get_events(80, 15)
    cspm_findings = _get_cspm(events)
    ciem_findings = _get_ciem(events)
    return {"status": "success", "data": map_findings_to_compliance(cspm_findings, ciem_findings, framework)}


@app.get(
    "/api/compliance/report",
    tags=["Compliance Management"],
    summary="Generate Full Compliance Audit Report",
    description="""
Generate an audit-ready compliance report evaluating the entire security posture across all frameworks, active findings, and remediation status.

### Export Formats:
- **`json`** (default): Returns structured JSON report with executive summaries and findings breakdown.
- **`csv`**: Returns a downloadable CSV file attachment (`compliance_report_<id>.csv`).
""",
    response_description="JSON compliance audit report or streaming CSV file attachment.",
    responses={
        200: {
            "description": "Compliance report generated successfully",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "data": {
                            "report_id": "RPT-COMP-8F3E2B1A",
                            "generated_at": "2026-03-15T10:20:00Z",
                            "executive_summary": "Overall compliance score is 84.5% across ISO 27001, SOC 2, and GDPR.",
                            "overall_score": 84.5,
                            "findings_summary": {"total": 5, "critical": 1, "high": 3, "medium": 1}
                        }
                    }
                },
                "text/csv": {
                    "schema": {"type": "string", "format": "binary"}
                }
            }
        }
    }
)
def get_compliance_report(
    format: str = Query("json", description="Report export format: 'json' (default) or 'csv'", openapi_examples={"default": {"value": "json"}})
):
    events = _get_events(80, 15)
    analyzed = analyze_events(events)
    cspm_findings = _get_cspm(events)
    ciem_findings = _get_ciem(events)
    remediation = auto_remediate_threats(analyzed)
    report = generate_compliance_report(cspm_findings, ciem_findings, analyzed, remediation_results=remediation, format=format)
    if format == "csv":
        return PlainTextResponse(
            content=report["csv_data"],
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=compliance_report_{report['report_id']}.csv"}
        )
    return {"status": "success", "data": report}


@app.get(
    "/api/compliance/report/executive",
    tags=["Compliance Management"],
    summary="Generate Executive Compliance Summary",
    description="Generate a high-level executive summary report of organizational compliance posture tailored for CISOs, compliance auditors, and executive leadership.",
    response_description="Executive compliance summary object.",
    responses={
        200: {
            "description": "Executive summary report generated successfully",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "data": {
                            "executive_summary": "Security posture indicates 84.5% compliance across evaluated standards.",
                            "compliance_scores": {
                                "ISO27001": {"score": 88.0, "status": "compliant"},
                                "SOC2": {"score": 82.5, "status": "compliant"},
                                "GDPR": {"score": 83.0, "status": "compliant"}
                            },
                            "overall_score": 84.5,
                            "trend": "+2.5%",
                            "generated_at": "2026-03-15T10:20:00Z"
                        }
                    }
                }
            }
        }
    }
)
def executive_summary():
    events = _get_events(80, 15)
    analyzed = analyze_events(events)
    cspm_findings = _get_cspm(events)
    ciem_findings = _get_ciem(events)
    remediation = auto_remediate_threats(analyzed)
    report = generate_compliance_report(cspm_findings, ciem_findings, analyzed, remediation_results=remediation)
    dashboard = get_compliance_dashboard(cspm_findings, ciem_findings)
    return {
        "status": "success",
        "data": {
            "executive_summary": report["executive_summary"],
            "compliance_scores": {fw: {"score": data["score"], "status": data["status"]} for fw, data in dashboard["frameworks"].items()},
            "overall_score": dashboard["overall_score"],
            "trend": dashboard["trend"],
            "generated_at": report["generated_at"]
        }
    }


# ══════════════════════════════════════════════════════════════════════════════
# 6 — UNIFIED RISK SCORING
# ══════════════════════════════════════════════════════════════════════════════

@app.get(
    "/api/risk/score",
    tags=["Unified Risk Analysis"],
    summary="Calculate Unified Enterprise Risk Score",
    description="""
Calculate a composite enterprise risk score (0-100 scale) synthesizing three foundational pillars:
- **Machine Learning Telemetry Anomaly Detection (35% weight):** Anomaly ratio, anomaly score intensity, and critical threat density.
- **CSPM Cloud Posture (35% weight):** Severity-weighted misconfiguration findings.
- **CIEM Identity & Entitlement (30% weight):** Excessive privileges, dormant accounts, and privilege escalation risks.

Saves the computed score into the SQLite risk history database and computes the real-time trend trajectory.
""",
    response_description="Unified risk score object with component breakdown and historical trend indicator.",
    responses={
        200: {
            "description": "Unified risk score calculated and persisted successfully",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "data": {
                            "unified_risk_score": 42.5,
                            "unified_risk_level": "medium",
                            "color": "#eab308",
                            "components": {
                                "ml_anomaly_detection": {"score": 38.0, "level": "medium"},
                                "cspm_posture": {"score": 45.0, "level": "medium"},
                                "ciem_identity": {"score": 46.0, "level": "medium"}
                            },
                            "trend": "-3.2%"
                        }
                    }
                }
            }
        }
    }
)
def get_risk_score():
    session = session_manager.get_session()
    if session and session.analyzed_events:
        analyzed = session.analyzed_events
        cspm_findings = session.cspm_results if session.cspm_results is not None else _get_cspm(session.events)
        ciem_findings = session.ciem_results if session.ciem_results is not None else _get_ciem(session.events)
        incidents = session.incidents if session.incidents is not None else get_incidents_db(limit=50)
    else:
        events = _get_events(80, 15)
        analyzed = analyze_events(events)
        cspm_findings = _get_cspm(events)
        ciem_findings = _get_ciem(events)
        incidents = get_incidents_db(limit=50)

    risk = calculate_unified_risk(analyzed, cspm_findings, ciem_findings, incidents=incidents)
    save_risk_score(
        risk["unified_risk_score"],
        risk["components"]["ml_anomaly_detection"]["score"],
        risk["components"]["cspm_posture"]["score"],
        risk["components"]["ciem_identity"]["score"],
        risk["unified_risk_level"],
        incident=risk["components"]["incident_correlation"]["score"]
    )
    risk["trend"] = get_risk_trend(risk["unified_risk_score"])
    return {"status": "success", "data": risk}


# ══════════════════════════════════════════════════════════════════════════════
# 7 — ATTACK SIMULATION
# ══════════════════════════════════════════════════════════════════════════════

@app.get(
    "/api/simulation/scenarios",
    tags=["Attack Simulation"],
    summary="List MITRE ATT&CK Simulation Scenarios",
    description="Retrieve the catalog of available attack simulation scenarios: `brute_force`, `privilege_escalation`, `data_exfiltration`, and `abnormal_access`.",
    response_description="Catalog of simulation scenarios.",
    responses={
        200: {
            "description": "Scenario catalog retrieved successfully",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "data": [
                            {
                                "id": "brute_force",
                                "title": "Brute Force",
                                "description": "Multiple failed login attempts followed by a successful breach.",
                                "supports_intensity": True,
                                "default_intensity": "high"
                            }
                        ]
                    }
                }
            }
        }
    }
)
def list_scenarios():
    return {"status": "success", "data": get_scenario_catalog()}


@app.post(
    "/api/simulation/run/{scenario}",
    tags=["Attack Simulation"],
    summary="Execute Single Attack Simulation Scenario",
    description="""
Execute a simulated cloud cyberattack scenario with configurable intensity.
Adversary events are blended into normal telemetry noise and passed through the PyOD machine learning anomaly detector to calculate the empirical detection rate.

### Supported Scenarios:
- `brute_force`
- `privilege_escalation`
- `data_exfiltration`
- `abnormal_access`

### Intensity Levels:
`low`, `medium`, `high`, `extreme` (default: `high`).
""",
    response_description="Simulation execution report with detection rate, anomaly count, and sample simulated events.",
    responses={
        200: {
            "description": "Attack simulation executed and evaluated successfully",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "data": {
                            "simulation": {
                                "scenario": "brute_force",
                                "intensity": "high",
                                "simulation_id": "SIM-BF-8F3E2B1A",
                                "generated_at": "2026-03-15T10:25:00Z"
                            },
                            "detection": {
                                "total_sim_events": 15,
                                "detected_as_anomaly": 14,
                                "detection_rate": 93.3,
                                "detection_success": True
                            },
                            "sample_sim_events": [
                                {
                                    "id": "SIM-BF-001",
                                    "attack_type": "brute_force",
                                    "user": "admin",
                                    "failed_attempts": 25
                                }
                            ]
                        }
                    }
                }
            }
        },
        400: {
            "description": "Unknown scenario requested",
            "content": {
                "application/json": {
                    "example": {"detail": "Unknown scenario 'unknown'. Valid: ['brute_force', 'privilege_escalation', 'data_exfiltration', 'abnormal_access']"}
                }
            }
        }
    }
)
def run_simulation(
    scenario: str = Path(..., description="Simulation scenario ID: 'brute_force', 'privilege_escalation', 'data_exfiltration', or 'abnormal_access'", openapi_examples={"default": {"value": "brute_force"}}),
    intensity: str = Query("high", description="Simulation intensity: 'low', 'medium', 'high', or 'extreme'", openapi_examples={"default": {"value": "high"}})
):
    if scenario not in SCENARIOS:
        raise HTTPException(status_code=400, detail=f"Unknown scenario '{scenario}'. Valid: {list(SCENARIOS.keys())}")
    result = session_manager.inject_scenario(scenario, intensity)
    return {
        "status": "success",
        "data": result
    }


@app.post(
    "/api/simulation/full",
    tags=["Attack Simulation"],
    summary="Execute Full Multi-Scenario Attack Suite",
    description="""
Execute a comprehensive multi-scenario attack simulation suite running all threat scenarios concurrently against the environment.
Measures overall ensemble detection rate, re-calculates unified risk score under attack conditions, and verifies automated incident remediation triggers.
""",
    response_description="Comprehensive evaluation report detailing all scenarios executed, detection rates, post-attack risk score, and auto-remediation execution metrics.",
    responses={
        200: {
            "description": "Full attack simulation suite executed successfully",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "data": {
                            "simulation_summary": {
                                "simulation_id": "FULL-SIM-8F3E2B1A",
                                "generated_at": "2026-03-15T10:30:00Z",
                                "intensity": "high",
                                "scenarios_run": 4,
                                "total_attack_events": 60,
                                "total_with_noise": 140
                            },
                            "detection": {
                                "detected_as_anomaly": 56,
                                "detection_rate": 93.3,
                                "detection_success": True
                            },
                            "risk_score": {
                                "unified": 78.5,
                                "level": "critical",
                                "components": {"ml_anomaly_detection": 82.0, "cspm_posture": 75.0, "ciem_identity": 78.0}
                            },
                            "auto_remediation": {
                                "triggered": 12,
                                "completed": 12
                            }
                        }
                    }
                }
            }
        }
    }
)
def run_full_attack_simulation(
    intensity: str = Query("high", description="Simulation intensity: 'low', 'medium', 'high', or 'extreme'", openapi_examples={"default": {"value": "high"}})
):
    full_sim = session_manager.inject_full_simulation(intensity)
    all_sim_events = [e for s in full_sim["scenarios"] for e in s["events"]]
    session = session_manager.get_session()
    all_events = session.events
    analyzed = session.analyzed_events
    sim_ids = {e["id"] for e in all_sim_events}
    detected = [e for e in analyzed if e["id"] in sim_ids and e.get("is_anomaly")]
    detection_rate = len(detected) / len(all_sim_events) * 100 if all_sim_events else 0
    cspm = session.cspm_results
    ciem = session.ciem_results
    incidents = session.incidents if session.incidents is not None else get_incidents_db(limit=50)
    risk = calculate_unified_risk(analyzed, cspm, ciem, incidents=incidents)
    remediation = auto_remediate_threats(analyzed)
    return {
        "status": "success",
        "data": {
            "simulation_summary": {
                "simulation_id": full_sim["simulation_id"],
                "generated_at": full_sim["timestamp"],
                "intensity": full_sim["intensity"],
                "scenarios_run": full_sim["scenarios_run"],
                "total_attack_events": len(all_sim_events),
                "total_with_noise": len(all_events)
            },
            "detection": {
                "detected_as_anomaly": len(detected),
                "detection_rate": round(detection_rate, 1),
                "detection_success": detection_rate > 50
            },
            "risk_score": {
                "unified": risk["unified_risk_score"],
                "level": risk["unified_risk_level"],
                "components": {k: v["score"] for k, v in risk["components"].items()}
            },
            "auto_remediation": {
                "triggered": remediation["remediations_triggered"],
                "completed": remediation["summary"]["fully_completed"]
            },
            "scenarios": [{k: v for k, v in s.items() if k != "events"} for s in full_sim["scenarios"]]
        }
    }


@app.post(
    "/api/simulation/reset",
    tags=["Attack Simulation"],
    summary="Reset Telemetry Session to Clean Baseline",
    description="Resets the shared active telemetry session buffer to clean baseline noise with zero injected attacks.",
    response_description="Confirmation of session reset.",
    responses={
        200: {
            "description": "Telemetry session reset to baseline successfully",
            "content": {
                "application/json": {
                    "example": {"status": "success", "message": "Telemetry session reset to baseline"}
                }
            }
        }
    }
)
def reset_simulation_session():
    session = session_manager.reset_to_baseline()
    return {
        "status": "success",
        "message": "Telemetry session reset to clean baseline",
        "session_id": session.session_id,
        "threats": session.to_summary()["threats"]
    }


# ══════════════════════════════════════════════════════════════════════════════
# 8 — AUDIT HISTORY & DATA EXPORT
# ══════════════════════════════════════════════════════════════════════════════

@app.get(
    "/api/history/cspm",
    tags=["Audit History & Data Export"],
    summary="Get CSPM Scan Audit History",
    description="Retrieve historical records of previous Cloud Security Posture Management (CSPM) scans stored in the SQLite database.",
    response_description="Array of past CSPM scan records.",
    responses={
        200: {
            "description": "CSPM history retrieved successfully",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "data": [
                            {
                                "id": 1,
                                "timestamp": "2026-03-15T09:00:00Z",
                                "findings_count": 3,
                                "critical_count": 1,
                                "high_count": 2
                            }
                        ]
                    }
                }
            }
        }
    }
)
def cspm_history():
    return {"status": "success", "data": get_cspm_history()}


@app.get(
    "/api/history/ciem",
    tags=["Audit History & Data Export"],
    summary="Get CIEM Scan Audit History",
    description="Retrieve historical records of previous Cloud Infrastructure Entitlement Management (CIEM) scans stored in the SQLite database.",
    response_description="Array of past CIEM scan records.",
    responses={
        200: {
            "description": "CIEM history retrieved successfully",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "data": [
                            {
                                "id": 1,
                                "timestamp": "2026-03-15T09:00:00Z",
                                "risks_count": 2,
                                "critical_count": 0,
                                "high_count": 2
                            }
                        ]
                    }
                }
            }
        }
    }
)
def ciem_history():
    return {"status": "success", "data": get_ciem_history()}


@app.get(
    "/api/history/alerts",
    tags=["Threat Alerts & Notifications"],
    summary="Get Alert Notification History",
    description="Retrieve the historical audit log of all security alert notifications dispatched by the platform (email, webhook, system events).",
    response_description="Array of alert records from SQLite database.",
    responses={
        200: {
            "description": "Alert history retrieved successfully",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "data": [
                            {
                                "id": 1,
                                "timestamp": "2026-03-15T10:15:00Z",
                                "subject": "Test Alert",
                                "recipient": "soc@ramantivirus.com",
                                "status": "sent"
                            }
                        ]
                    }
                }
            }
        }
    }
)
def alert_history():
    return {"status": "success", "data": get_alert_log()}


@app.get(
    "/api/export/events",
    tags=["Audit History & Data Export"],
    summary="Export Analyzed Events as CSV",
    description="Generate and stream a downloadable CSV file (`events_export.csv`) containing recent telemetry security events enriched with PyOD anomaly detection scores, ML severity classifications, and attack classifications.",
    response_description="Streaming CSV file download.",
    responses={
        200: {
            "description": "CSV export generated and streamed",
            "content": {
                "text/csv": {
                    "schema": {"type": "string", "format": "binary"}
                }
            }
        }
    }
)
def export_events():
    events = _get_events(100, 20)
    analyzed = analyze_events(events)
    output = io.StringIO()
    if analyzed:
        writer = csv.DictWriter(output, fieldnames=["id", "timestamp", "event_type", "attack_type", "user", "src_ip", "service", "level", "severity", "ml_anomaly_score", "is_anomaly", "ml_severity", "description"])
        writer.writeheader()
        for e in analyzed:
            writer.writerow({k: e.get(k, "") for k in writer.fieldnames})
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode()),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=events_export.csv"}
    )


@app.get(
    "/api/export/cspm",
    tags=["Audit History & Data Export"],
    summary="Export CSPM Findings as CSV",
    description="Generate and stream a downloadable CSV file (`cspm_export.csv`) of all current Cloud Security Posture Management (CSPM) misconfiguration findings.",
    response_description="Streaming CSV file download.",
    responses={
        200: {
            "description": "CSPM CSV export generated and streamed",
            "content": {
                "text/csv": {
                    "schema": {"type": "string", "format": "binary"}
                }
            }
        }
    }
)
def export_cspm():
    events = _get_events(80, 20)
    findings = _get_cspm(events)
    output = io.StringIO()
    if findings:
        writer = csv.DictWriter(output, fieldnames=["scan_id", "vulnerability_id", "title", "severity", "resource", "description", "remediation", "status"])
        writer.writeheader()
        for f in findings:
            writer.writerow({k: f.get(k, "") for k in writer.fieldnames})
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode()),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=cspm_export.csv"}
    )


@app.get(
    "/api/export/ciem",
    tags=["Audit History & Data Export"],
    summary="Export CIEM Entitlements as CSV",
    description="Generate and stream a downloadable CSV file (`ciem_export.csv`) of all current Cloud Infrastructure Entitlement Management (CIEM) identity risk findings.",
    response_description="Streaming CSV file download.",
    responses={
        200: {
            "description": "CIEM CSV export generated and streamed",
            "content": {
                "text/csv": {
                    "schema": {"type": "string", "format": "binary"}
                }
            }
        }
    }
)
def export_ciem():
    events = _get_events(80, 20)
    findings = _get_ciem(events)
    output = io.StringIO()
    if findings:
        writer = csv.DictWriter(output, fieldnames=["scan_id", "risk_id", "title", "entity_name", "entity_type", "risk_level", "description", "remediation"])
        writer.writeheader()
        for f in findings:
            writer.writerow({k: f.get(k, "") for k in writer.fieldnames})
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode()),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=ciem_export.csv"}
    )


# ══════════════════════════════════════════════════════════════════════════════
# 9 — SYSTEM STATUS & ALERTS
# ══════════════════════════════════════════════════════════════════════════════

@app.get(
    "/api/status",
    tags=["Health & System Status"],
    summary="Get Subsystem Integration Status",
    description="""
Check the connectivity and operational mode of all integrated platform subsystems:
- **Wazuh SIEM:** Reports whether real alert log `/var/ossec/logs/alerts/alerts.json` is active (`real`) or using synthetic simulation (`simulated`).
- **LocalStack AWS:** Reports whether local AWS emulator at `http://localhost:4566` is connected (`localstack`) or using fallback (`simulated`).
- **SQLite Database:** Reports SQLite database connectivity status (`connected`).
""",
    response_description="Integration subsystem status report.",
    responses={
        200: {
            "description": "Subsystem status retrieved successfully",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "data": {
                            "wazuh": {
                                "available": False,
                                "log_path": "/var/ossec/logs/alerts/alerts.json",
                                "mode": "simulated",
                                "message": "Wazuh log not found — using simulator"
                            },
                            "localstack": {
                                "available": False,
                                "endpoint": "http://localhost:4566",
                                "mode": "simulated",
                                "message": "LocalStack not running — using simulator"
                            },
                            "database": "connected"
                        }
                    }
                }
            }
        }
    }
)
def system_status():
    return {
        "status": "success",
        "data": {
            "wazuh": get_wazuh_status(),
            "localstack": get_localstack_status(),
            "database": "connected",
        }
    }


@app.post(
    "/api/alerts/test",
    tags=["Threat Alerts & Notifications"],
    summary="Send Test Threat Alert Email (Admin)",
    description="""
Trigger and dispatch a test security alert email to verify SMTP configuration and notification dispatch pipelines.

**Permissions Required:** `users:manage` (`admin` role).
""",
    response_description="Email notification dispatch result.",
    dependencies=[Depends(bearer_scheme)],
    responses={
        200: {
            "description": "Alert email dispatched successfully",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "data": {
                            "success": True,
                            "recipient": "soc-team@ramantivirus.com",
                            "message": "Alert sent successfully"
                        }
                    }
                }
            }
        },
        401: {"description": "Missing or invalid authorization token", "content": {"application/json": {"example": {"detail": "Authorization header required"}}}},
        403: {"description": "Forbidden (requires admin role with users:manage)", "content": {"application/json": {"example": {"detail": "Insufficient permissions. Required: 'users:manage'"}}}}
    }
)
def test_alert(
    authorization: Optional[str] = Header(None, description="Admin Bearer token"),
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)
):
    _require_permission(authorization, "users:manage", credentials)
    result = send_alert_email("Test Alert", "This is a test alert from Ram Antivirus Cloud Security Platform.")
    return {"status": "success", "data": result}


# ══════════════════════════════════════════════════════════════════════════════
# 10 — REAL-TIME WEBSOCKET STREAMING
# ══════════════════════════════════════════════════════════════════════════════

@app.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    """
    WebSocket endpoint — pushes new analyzed events every 10 seconds.
    Frontend connects once and receives live updates automatically.
    """
    await websocket.accept()
    try:
        while True:
            events = _get_events(30, 5)
            analyzed = analyze_events(events)
            anomalies = [e for e in analyzed if e.get("is_anomaly")]
            await websocket.send_text(json.dumps({
                "type": "events_update",
                "total": len(analyzed),
                "anomalies": len(anomalies),
                "critical": sum(1 for e in analyzed if e.get("ml_severity") == "Critical"),
                "latest_events": analyzed[:10]
            }))
            await asyncio.sleep(10)
    except WebSocketDisconnect:
        pass


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
