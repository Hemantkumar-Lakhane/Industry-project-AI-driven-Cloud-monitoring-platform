"""
JWT Authentication & Role-Based Access Control Engine — SQLite backed
"""
import jwt
import hashlib
import uuid
import os
import secrets
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional, List, Tuple, Any
try:
    import bcrypt
    _BCRYPT_AVAILABLE = True
except ImportError:
    bcrypt = None
    _BCRYPT_AVAILABLE = False
from engines.db import get_conn, init_db

ENV = os.environ.get("ENV", os.environ.get("APP_ENV", "")).lower()
JWT_SECRET = os.environ.get("JWT_SECRET")
if not JWT_SECRET:
    if ENV in ("production", "prod"):
        raise RuntimeError(
            "JWT_SECRET environment variable is missing in production environment. "
            "Configure a secure JWT_SECRET before starting the server."
        )
    JWT_SECRET = "ram-antivirus-cloud-security-super-secret-key-2026"
    print("[AUTH] Using development JWT_SECRET. Set JWT_SECRET in production.")

JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24


def _hash_password(password: str) -> str:
    """Hash password using bcrypt with a cryptographically secure per-user salt, falling back to PBKDF2 if bcrypt is not installed."""
    if _BCRYPT_AVAILABLE and bcrypt is not None:
        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    # Resilient standard-library fallback: PBKDF2-HMAC-SHA256 with per-user salt
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000)
    return f"$pbkdf2${salt}${dk.hex()}"


def _verify_password(password: str, stored_hash: str) -> bool:
    """
    Verify password with backward-compatible support for bcrypt, pbkdf2, and legacy static-salted SHA-256 hashes.
    """
    if not stored_hash:
        return False
    if stored_hash.startswith("$2b$") or stored_hash.startswith("$2a$"):
        if _BCRYPT_AVAILABLE and bcrypt is not None:
            try:
                return bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8"))
            except Exception:
                return False
        return False
    if stored_hash.startswith("$pbkdf2$"):
        try:
            parts = stored_hash.split("$")
            if len(parts) == 4:
                salt, expected_hex = parts[2], parts[3]
                dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000)
                return secrets.compare_digest(dk.hex(), expected_hex)
        except Exception:
            return False
    # Legacy SHA-256 backward compatibility
    legacy_hash = hashlib.sha256(f"ram-av-salt{password}".encode("utf-8")).hexdigest()
    return legacy_hash == stored_hash



def _row_to_user(row) -> Dict:
    if row is None:
        return None
    d = dict(row)
    return {
        "user_id": d.get("user_id"),
        "org_id": d.get("org_id"),
        "username": d.get("username"),
        "email": d.get("email"),
        "password_hash": d.get("password_hash"),
        "role": d.get("role"),
        "full_name": d.get("full_name"),
        "created_at": d.get("created_at"),
        "last_login": d.get("last_login"),
        "is_active": bool(d.get("is_active", 1))
    }


def _get_user(username: str) -> Optional[Dict]:
    conn = get_conn()
    row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    return _row_to_user(row)


def _save_user(user: Dict):
    conn = get_conn()
    conn.execute(
        """INSERT INTO users
           (user_id,org_id,username,email,password_hash,role,full_name,created_at,last_login,is_active)
           VALUES (?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT (user_id) DO UPDATE SET
               org_id = EXCLUDED.org_id,
               username = EXCLUDED.username,
               email = EXCLUDED.email,
               password_hash = EXCLUDED.password_hash,
               role = EXCLUDED.role,
               full_name = EXCLUDED.full_name,
               last_login = EXCLUDED.last_login,
               is_active = EXCLUDED.is_active""",
        (user["user_id"], user.get("org_id"), user["username"], user["email"], user["password_hash"],
         user["role"], user["full_name"], user["created_at"], user["last_login"], bool(user.get("is_active", True)))
    )
    conn.commit()
    conn.close()


# Seed default users if not present (Platform Superadmin & Demo User)
def _seed_defaults():
    _defaults = [
        {"username": "admin", "password": "admin123", "email": "admin@ramantivirus.com", "role": "admin", "full_name": "RAM Antivirus Admin", "org_id": "org_master_admin"},
        {"username": "demo",  "password": "demo123",  "email": "demo@ramantivirus.com",  "role": "analyst", "full_name": "Demo User", "org_id": "org_demo"},
    ]
    for u in _defaults:
        existing = _get_user(u["username"])
        if not existing:
            _save_user({
                "user_id": f"usr_{u['username']}_01", "org_id": u.get("org_id"), "username": u["username"], "email": u["email"],
                "password_hash": _hash_password(u["password"]), "role": u["role"],
                "full_name": u["full_name"], "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "last_login": None, "is_active": True
            })
        else:
            # Ensure valid password hash for defaults
            if not _verify_password(u["password"], existing["password_hash"]):
                existing["password_hash"] = _hash_password(u["password"])
                existing["full_name"] = u["full_name"]
                _save_user(existing)

_seed_defaults()


# ── Role Permissions ─────────────────────────────────────────────────────────
ROLE_PERMISSIONS = {
    "admin": {
        "description": "RAM Antivirus Platform Super Administrator — full access to all endpoints, platform oversight, and directory",
        "permissions": [
            "dashboard:read", "events:read", "cspm:read", "ciem:read",
            "ml:read", "ml:execute", "remediation:read", "remediation:execute",
            "compliance:read", "compliance:generate", "compliance:export",
            "simulation:read", "simulation:execute",
            "users:read", "users:manage",
            "risk:read", "risk:configure",
            "assets:read", "assets:write",
            "vulnerabilities:read", "vulnerabilities:write",
            "cloud:read", "cloud:configure", "cloud:scan", "telemetry:ingest",
            "findings:read", "incidents:read"
        ]
    },
    "user": {
        "description": "Standard company tenant user — full cloud connection, scanning, posture auditing, and remediation for their organization",
        "permissions": [
            "dashboard:read", "events:read", "cspm:read", "ciem:read",
            "ml:read", "ml:execute", "remediation:read", "remediation:execute",
            "compliance:read", "compliance:generate", "compliance:export",
            "risk:read", "risk:configure",
            "assets:read", "assets:write",
            "vulnerabilities:read", "vulnerabilities:write",
            "cloud:read", "cloud:configure", "cloud:scan", "telemetry:ingest",
            "findings:read", "incidents:read"
        ]
    },
    "analyst": {
        "description": "Read access with analytics, scans, and simulation execution",
        "permissions": [
            "dashboard:read", "events:read", "cspm:read", "ciem:read",
            "ml:read", "ml:execute", "remediation:read",
            "compliance:read", "compliance:generate",
            "simulation:read", "simulation:execute",
            "risk:read",
            "assets:read", "assets:write",
            "vulnerabilities:read",
            "cloud:read", "cloud:scan", "telemetry:ingest",
            "findings:read", "incidents:read"
        ]
    },
    "viewer": {
        "description": "Read-only access to dashboards and reports",
        "permissions": [
            "dashboard:read", "events:read", "cspm:read", "ciem:read",
            "ml:read", "compliance:read", "risk:read",
            "assets:read", "vulnerabilities:read",
            "cloud:read", "findings:read", "incidents:read"
        ]
    }
}


# ── Registration ─────────────────────────────────────────────────────────────
def register_user(username: str, password: str, email: str, role: str = "viewer", full_name: str = "", org_id: Optional[str] = None) -> Dict:
    """
    Register a new user with the given credentials and role.
    Returns user info (without password hash) or error.
    """
    # Validation
    if not username or len(username) < 3:
        return {"success": False, "error": "Username must be at least 3 characters"}
    
    if not password or len(password) < 6:
        return {"success": False, "error": "Password must be at least 6 characters"}
    
    if _get_user(username):
        return {"success": False, "error": f"Username '{username}' already exists"}

    if role not in ROLE_PERMISSIONS:
        return {"success": False, "error": f"Invalid role '{role}'. Must be: admin, analyst, or viewer"}

    conn = get_conn()
    existing_email = conn.execute("SELECT username FROM users WHERE email=?", (email,)).fetchone()
    conn.close()
    if existing_email:
        return {"success": False, "error": f"Email '{email}' already registered"}

    user_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Sanitize full_name - never allow password strings to become the display name
    safe_full_name = full_name.strip() if full_name else username
    if safe_full_name.lower() in ("password", "password123", password.lower(), ""):
        safe_full_name = f"{username.capitalize()} User"

    _save_user({
        "user_id": user_id, "org_id": org_id, "username": username, "email": email,
        "password_hash": _hash_password(password), "role": role,
        "full_name": safe_full_name, "created_at": now,
        "last_login": None, "is_active": True
    })
    
    return {
        "success": True,
        "user": {
            "user_id": user_id,
            "org_id": org_id,
            "username": username,
            "email": email,
            "role": role,
            "full_name": safe_full_name,
            "permissions": ROLE_PERMISSIONS[role]["permissions"],
            "created_at": now
        }
    }


def register_company(company_name: str, admin_name: str, email: str, password: str, username: str = None) -> Dict:
    """
    Self-serve registration for new enterprise company accounts.
    Creates an organization record, tenant ID, unique AWS External ID, and initial admin account.
    """
    if not company_name or len(company_name.strip()) < 2:
        return {"success": False, "error": "Company name must be at least 2 characters"}
    if not email or "@" not in email:
        return {"success": False, "error": "A valid business email is required"}
    if not password or len(password) < 6:
        return {"success": False, "error": "Password must be at least 6 characters"}

    user_name = (username or email.split("@")[0]).lower().replace(".", "_").replace("-", "_")
    base_user = user_name
    counter = 1
    while _get_user(user_name):
        user_name = f"{base_user}_{counter}"
        counter += 1

    org_id = f"org_{uuid.uuid4().hex[:8]}"
    clean_org_slug = "".join(c for c in company_name.upper() if c.isalnum() or c == "-")[:12] or "TENANT"
    external_id = f"RAM-{clean_org_slug}-{uuid.uuid4().hex[:6].upper()}"
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    conn = get_conn()
    try:
        conn.execute(
            "INSERT INTO organizations (org_id, name, external_id, industry, created_at) VALUES (?, ?, ?, ?, ?)",
            (org_id, company_name.strip(), external_id, "Cloud Infrastructure", now)
        )
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()

    # Sanitize admin name to prevent accidental password autofill leaks
    safe_admin_name = admin_name.strip() if admin_name else f"{company_name.strip()} Admin"
    if safe_admin_name.lower() in ("password", "password123", password.lower(), ""):
        safe_admin_name = f"{company_name.strip()} Admin"

    user_res = register_user(
        username=user_name,
        password=password,
        email=email.strip().lower(),
        role="user",
        full_name=safe_admin_name,
        org_id=org_id
    )
    if not user_res.get("success"):
        return user_res

    login_res = login_user(user_name, password)
    if not login_res.get("success"):
        return login_res

    login_res["organization"] = {
        "org_id": org_id,
        "company_name": company_name.strip(),
        "external_id": external_id
    }
    login_res["is_new_registration"] = True
    return login_res


# ── Login & Token Generation ─────────────────────────────────────────────────
def login_user(username: str, password: str) -> Dict:
    """
    Authenticate user and return a JWT token.
    """
    user = _get_user(username)

    if not user:
        return {"success": False, "error": "Invalid username or password"}

    if not user["is_active"]:
        return {"success": False, "error": "Account is deactivated. Contact administrator."}

    if not _verify_password(password, user["password_hash"]):
        return {"success": False, "error": "Invalid username or password"}

    # Transparently upgrade legacy SHA-256 hash to bcrypt upon successful authentication
    if not (user["password_hash"].startswith("$2b$") or user["password_hash"].startswith("$2a$")):
        user["password_hash"] = _hash_password(password)

    now = datetime.now(timezone.utc)
    user["last_login"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    _save_user(user)

    # Fetch organization details for multi-tenant isolation
    org_id = user.get("org_id")
    company_name = None
    external_id = None
    if org_id:
        conn = get_conn()
        org_row = conn.execute("SELECT name, external_id FROM organizations WHERE org_id = ?", (org_id,)).fetchone()
        conn.close()
        if org_row:
            company_name = org_row["name"]
            external_id = org_row["external_id"]
    elif user["username"] == "admin":
        company_name = "RAM Antivirus Platform"
        org_id = "org_system_master"

    role_label = "System Admin" if user["username"] == "admin" else ("Company Admin" if user["role"] == "admin" else "Security Analyst")
    
    # Generate JWT token
    payload = {
        "user_id": user["user_id"],
        "username": user["username"],
        "role": user["role"],
        "role_label": role_label,
        "org_id": org_id,
        "company_name": company_name,
        "permissions": ROLE_PERMISSIONS[user["role"]]["permissions"],
        "iat": now,
        "exp": now + timedelta(hours=JWT_EXPIRATION_HOURS),
        "iss": "ram-antivirus-cloud-security"
    }
    
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    
    return {
        "success": True,
        "token": token,
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": JWT_EXPIRATION_HOURS * 3600,
        "user": {
            "user_id": user["user_id"],
            "org_id": org_id,
            "company_name": company_name,
            "external_id": external_id,
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
            "role_label": role_label,
            "full_name": user["full_name"],
            "permissions": ROLE_PERMISSIONS[user["role"]]["permissions"]
        }
    }


def login_google_user(email: str, name: str, google_sub: str) -> Dict:
    """
    Authenticate or self-provision a user signing in with Google OAuth 2.0.
    Creates an organization and tenant user if first-time, or updates last login.
    Returns standard JWT token and user details.
    """
    clean_email = email.strip().lower()
    clean_name = name.strip() if name else clean_email.split("@")[0]

    conn = get_conn()
    user = conn.execute("SELECT * FROM users WHERE LOWER(email) = ?", (clean_email,)).fetchone()

    if not user:
        # Create organization for new user
        org_id = f"org_{uuid.uuid4().hex[:8]}"
        company_name = f"{clean_name.split()[0]}'s Cloud" if clean_name else "Cloud Workspace"
        clean_org_slug = "".join(c for c in company_name.upper() if c.isalnum() or c == "-")[:12] or "TENANT"
        external_id = f"RAM-{clean_org_slug}-{uuid.uuid4().hex[:6].upper()}"
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        try:
            conn.execute(
                "INSERT INTO organizations (org_id, name, external_id, industry, created_at) VALUES (?, ?, ?, ?, ?)",
                (org_id, company_name, external_id, "Cloud Infrastructure", now)
            )
            conn.commit()
        except Exception:
            pass

        user_id = str(uuid.uuid4())
        base_username = clean_email.split("@")[0].lower().replace(".", "_").replace("-", "_")
        user_name = base_username
        counter = 1
        while conn.execute("SELECT user_id FROM users WHERE username = ?", (user_name,)).fetchone():
            user_name = f"{base_username}_{counter}"
            counter += 1

        dummy_hash = _hash_password(f"google_{google_sub}_{uuid.uuid4().hex}")
        _save_user({
            "user_id": user_id,
            "org_id": org_id,
            "username": user_name,
            "email": clean_email,
            "password_hash": dummy_hash,
            "role": "user",
            "full_name": clean_name,
            "created_at": now,
            "last_login": now,
            "is_active": True
        })
        user = _get_user(user_name)
    else:
        # Update last login
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        user["last_login"] = now
        _save_user(user)

    conn.close()

    if not user:
        return {"success": False, "error": "Failed to retrieve or provision user"}

    if not user.get("is_active", True):
        return {"success": False, "error": "Account is deactivated. Contact administrator."}

    # Fetch org details
    org_id = user.get("org_id")
    company_name = None
    external_id = None
    if org_id:
        conn = get_conn()
        org_row = conn.execute("SELECT name, external_id FROM organizations WHERE org_id = ?", (org_id,)).fetchone()
        conn.close()
        if org_row:
            company_name = org_row["name"]
            external_id = org_row["external_id"]

    role = user.get("role", "user")
    role_label = "System Admin" if user["username"] == "admin" else ("Company Admin" if role == "admin" else "Security Analyst")
    now_dt = datetime.now(timezone.utc)

    payload = {
        "user_id": user["user_id"],
        "username": user["username"],
        "role": role,
        "role_label": role_label,
        "org_id": org_id,
        "company_name": company_name,
        "full_name": user.get("full_name") or clean_name,
        "email": user["email"],
        "permissions": ROLE_PERMISSIONS.get(role, {}).get("permissions", []),
        "iat": now_dt,
        "exp": now_dt + timedelta(hours=JWT_EXPIRATION_HOURS),
        "iss": "ram-antivirus-cloud-security"
    }

    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    return {
        "success": True,
        "token": token,
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": JWT_EXPIRATION_HOURS * 3600,
        "user": {
            "user_id": user["user_id"],
            "org_id": org_id,
            "company_name": company_name,
            "external_id": external_id,
            "username": user["username"],
            "email": user["email"],
            "role": role,
            "role_label": role_label,
            "full_name": user.get("full_name") or clean_name,
            "permissions": ROLE_PERMISSIONS.get(role, {}).get("permissions", [])
        }
    }


# ── Token Verification ───────────────────────────────────────────────────────
def verify_token(token: str) -> Dict:
    """
    Verify and decode a JWT token.
    Returns the decoded payload or error.
    """
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return {"valid": True, "payload": payload}
    except jwt.ExpiredSignatureError:
        return {"valid": False, "error": "Token has expired"}
    except jwt.InvalidTokenError as e:
        return {"valid": False, "error": f"Invalid token: {str(e)}"}


def check_permission(token: str, required_permission: str) -> Dict:
    """
    Verify token and check if the user has the required permission.
    """
    result = verify_token(token)
    
    if not result["valid"]:
        return {"authorized": False, "error": result["error"]}
    
    user_permissions = result["payload"].get("permissions", [])
    
    if required_permission in user_permissions:
        return {
            "authorized": True,
            "user": {
                "user_id": result["payload"]["user_id"],
                "username": result["payload"]["username"],
                "role": result["payload"]["role"],
                "org_id": result["payload"].get("org_id"),
                "company_name": result["payload"].get("company_name"),
                "full_name": result["payload"].get("full_name"),
                "permissions": user_permissions
            }
        }
    
    return {
        "authorized": False,
        "error": f"Insufficient permissions. Required: '{required_permission}'. Your role: '{result['payload']['role']}'"
    }


# ── WebSocket Single-Use Short-Lived Ticket Store ───────────────────────────
_WS_TICKETS: Dict[str, Tuple[datetime, Dict]] = {}

def create_ws_ticket(user_payload: Dict, ttl_seconds: int = 60) -> str:
    """
    Generate a cryptographically random, single-use, short-lived ticket
    for secure WebSocket authentication without passing long-lived credentials in URLs.
    """
    now = datetime.now(timezone.utc)
    # Prune expired tickets
    expired_keys = [k for k, (exp, _) in _WS_TICKETS.items() if exp < now]
    for k in expired_keys:
        _WS_TICKETS.pop(k, None)

    ticket = f"wstk_{secrets.token_urlsafe(32)}"
    expires_at = now + timedelta(seconds=ttl_seconds)
    _WS_TICKETS[ticket] = (expires_at, user_payload)
    return ticket


def redeem_ws_ticket(ticket: str) -> Dict[str, Any]:
    """
    Atomically redeem and delete a WebSocket ticket.
    Returns payload if valid and unexpired, else error.
    """
    if not ticket or ticket not in _WS_TICKETS:
        return {"valid": False, "error": "Invalid or already consumed WebSocket ticket"}

    expires_at, payload = _WS_TICKETS.pop(ticket)
    now = datetime.now(timezone.utc)
    if now > expires_at:
        return {"valid": False, "error": "WebSocket ticket has expired"}

    return {"valid": True, "payload": payload}


def validate_ws_auth(raw_auth: str) -> Dict[str, Any]:
    """
    Validates either a Bearer JWT token or a single-use short-lived WS ticket.
    Enforces expiration check, signature check, and 'dashboard:read' authorization.
    Returns dict with 'authorized': bool, 'user': dict, and 'error': str if any.
    """
    if not raw_auth:
        return {"authorized": False, "error": "Missing authentication credential"}

    # Case 1: WS Ticket (starts with wstk_)
    if raw_auth.startswith("wstk_"):
        redeem_res = redeem_ws_ticket(raw_auth)
        if not redeem_res["valid"]:
            return {"authorized": False, "error": redeem_res["error"]}
        payload = redeem_res["payload"]
    else:
        # Case 2: Bearer JWT
        token = raw_auth[7:].strip() if raw_auth.lower().startswith("bearer ") else raw_auth.strip()
        v_res = verify_token(token)
        if not v_res["valid"]:
            return {"authorized": False, "error": v_res["error"]}
        payload = v_res["payload"]

    # Check required permission for WebSocket streaming
    perms = payload.get("permissions", [])
    if "dashboard:read" not in perms and payload.get("role") != "admin":
        return {
            "authorized": False,
            "error": "Forbidden: user lacks 'dashboard:read' permission"
        }

    return {
        "authorized": True,
        "user": {
            "user_id": payload.get("user_id"),
            "username": payload.get("username"),
            "role": payload.get("role"),
            "permissions": perms
        }
    }


# ── User Management ──────────────────────────────────────────────────────────
def get_all_users() -> List[Dict]:
    conn = get_conn()
    rows = conn.execute("SELECT * FROM users").fetchall()
    conn.close()
    return [
        {"user_id": r["user_id"], "username": r["username"], "email": r["email"],
         "role": r["role"], "full_name": r["full_name"], "created_at": r["created_at"],
         "last_login": r["last_login"], "is_active": bool(r["is_active"])}
        for r in rows
    ]


def deactivate_user(username: str) -> Dict:
    if username.strip().lower() in ("admin", "ramantivirus admin"):
        return {"success": False, "error": "Cannot deactivate platform master admin account"}
    user = _get_user(username)
    if not user:
        return {"success": False, "error": f"User '{username}' not found"}
    user["is_active"] = False
    _save_user(user)
    return {"success": True, "message": f"User '{username}' deactivated"}


def reactivate_user(username: str) -> Dict:
    user = _get_user(username)
    if not user:
        return {"success": False, "error": f"User '{username}' not found"}
    user["is_active"] = True
    _save_user(user)
    return {"success": True, "message": f"User '{username}' reactivated"}


def get_role_info() -> Dict:
    """Return all role definitions and their permissions."""
    return ROLE_PERMISSIONS


if __name__ == "__main__":
    import json
    
    print("=== Register User ===")
    reg = register_user("testuser", "test123456", "test@example.com", "analyst", "Test User")
    print(json.dumps(reg, indent=2))
    
    print("\n=== Login ===")
    login = login_user("admin", "admin123")
    print(json.dumps(login, indent=2))
    
    print("\n=== Verify Token ===")
    if login["success"]:
        verify = verify_token(login["token"])
        print(json.dumps(verify, indent=2, default=str))
    
    print("\n=== Check Permission ===")
    if login["success"]:
        perm = check_permission(login["token"], "remediation:execute")
        print(json.dumps(perm, indent=2))
