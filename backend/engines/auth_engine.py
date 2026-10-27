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

JWT_SECRET = os.environ.get("JWT_SECRET")
if not JWT_SECRET:
    JWT_SECRET = "ram-antivirus-cloud-security-super-secret-key-2026"
    print("[AUTH] Operational Notice: Using development JWT_SECRET. In production, configure JWT_SECRET environment variable.")

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
    return {
        "user_id": row["user_id"], "username": row["username"], "email": row["email"],
        "password_hash": row["password_hash"], "role": row["role"], "full_name": row["full_name"],
        "created_at": row["created_at"], "last_login": row["last_login"],
        "is_active": bool(row["is_active"])
    }


def _get_user(username: str) -> Optional[Dict]:
    conn = get_conn()
    row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    return _row_to_user(row)


def _save_user(user: Dict):
    conn = get_conn()
    conn.execute(
        """INSERT OR REPLACE INTO users
           (user_id,username,email,password_hash,role,full_name,created_at,last_login,is_active)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (user["user_id"], user["username"], user["email"], user["password_hash"],
         user["role"], user["full_name"], user["created_at"], user["last_login"], int(user["is_active"]))
    )
    conn.commit()
    conn.close()


# Seed default users if not present
def _seed_defaults():
    _defaults = [
        {"username": "admin",    "password": "admin123",   "email": "admin@ramantivirus.com",   "role": "admin",   "full_name": "System Administrator"},
        {"username": "analyst1", "password": "analyst123", "email": "analyst@ramantivirus.com", "role": "analyst", "full_name": "Security Analyst"},
        {"username": "viewer1",  "password": "viewer123",  "email": "viewer@ramantivirus.com",  "role": "viewer",  "full_name": "Dashboard Viewer"},
    ]
    for u in _defaults:
        existing = _get_user(u["username"])
        if not existing:
            _save_user({
                "user_id": str(uuid.uuid4()), "username": u["username"], "email": u["email"],
                "password_hash": _hash_password(u["password"]), "role": u["role"],
                "full_name": u["full_name"], "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "last_login": None, "is_active": True
            })

_seed_defaults()


# ── Role Permissions ─────────────────────────────────────────────────────────
ROLE_PERMISSIONS = {
    "admin": {
        "description": "Full access — all endpoints, remediation, user management",
        "permissions": [
            "dashboard:read", "events:read", "cspm:read", "ciem:read",
            "ml:read", "ml:execute", "remediation:read", "remediation:execute",
            "compliance:read", "compliance:generate", "compliance:export",
            "simulation:read", "simulation:execute",
            "users:read", "users:manage",
            "risk:read", "risk:configure"
        ]
    },
    "analyst": {
        "description": "View + alerts + compliance + ML analysis",
        "permissions": [
            "dashboard:read", "events:read", "cspm:read", "ciem:read",
            "ml:read", "ml:execute", "remediation:read",
            "compliance:read", "compliance:generate",
            "simulation:read", "simulation:execute",
            "risk:read"
        ]
    },
    "viewer": {
        "description": "Read-only dashboard access",
        "permissions": [
            "dashboard:read", "events:read", "cspm:read", "ciem:read",
            "ml:read", "compliance:read", "risk:read"
        ]
    }
}


# ── Registration ─────────────────────────────────────────────────────────────
def register_user(username: str, password: str, email: str, role: str = "viewer", full_name: str = "") -> Dict:
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
    _save_user({
        "user_id": user_id, "username": username, "email": email,
        "password_hash": _hash_password(password), "role": role,
        "full_name": full_name or username, "created_at": now,
        "last_login": None, "is_active": True
    })
    
    return {
        "success": True,
        "user": {
            "user_id": user_id,
            "username": username,
            "email": email,
            "role": role,
            "full_name": full_name or username,
            "permissions": ROLE_PERMISSIONS[role]["permissions"],
            "created_at": now
        }
    }


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
    
    # Generate JWT token
    payload = {
        "user_id": user["user_id"],
        "username": user["username"],
        "role": user["role"],
        "permissions": ROLE_PERMISSIONS[user["role"]]["permissions"],
        "iat": now,
        "exp": now + timedelta(hours=JWT_EXPIRATION_HOURS),
        "iss": "ram-antivirus-cloud-security"
    }
    
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    
    return {
        "success": True,
        "token": token,
        "token_type": "Bearer",
        "expires_in": JWT_EXPIRATION_HOURS * 3600,
        "user": {
            "user_id": user["user_id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
            "full_name": user["full_name"],
            "permissions": ROLE_PERMISSIONS[user["role"]]["permissions"]
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
                "role": result["payload"]["role"]
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
