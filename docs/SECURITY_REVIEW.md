# RAM Antivirus — Security Review & Vulnerability Register

**Document ID:** `docs/SECURITY_REVIEW.md`  
**Review Date:** October 27, 2026  
**Auditor:** Engineering Audit Council (Security Lead)  
**Target Repository:** `Industry-project-AI-driven-Cloud-monitoring-platform-`  
**Active Branch:** `ui-design`  

---

## 1. Verified Security Defects

### SEC-01: Missing Authentication on Operational API Endpoints
* **Severity:** **CRITICAL** | **CVSS v3.1:** 8.8 (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L`)
* **Affected File:** [`backend/main.py`](file:///d:/ram_antivirus_official/Industry-project-AI-driven-Cloud-monitoring-platform-/backend/main.py)
* **Description:** Over 40 operational endpoints (e.g., `/api/remediation/*`, `/api/detection/*`, `/api/incidents/*`, `/api/simulation/*`, `/api/assets/*`) omit `Depends(bearer_scheme)`. Any client on the network can query security findings, trigger remediation playbooks, or launch simulation bursts without a valid JWT token.
* **Impact:** Complete authorization bypass for platform operations.
* **Remediation:** Apply `_require_permission` and `Depends(bearer_scheme)` across all operational routes. Public routes are restricted to `/`, `/healthz`, `/docs`, `/redoc`, `/openapi.json`, and `/api/auth/login`.

---

### SEC-02: Static-Salted Weak Password Hashing
* **Severity:** **HIGH** | **CVSS v3.1:** 7.5 (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)
* **Affected File:** [`backend/engines/auth_engine.py`](file:///d:/ram_antivirus_official/Industry-project-AI-driven-Cloud-monitoring-platform-/backend/engines/auth_engine.py)
* **Description:** Passwords are hashed using single-round SHA-256 with a shared, hardcoded static salt (`salt = "ram-av-salt"`).
* **Impact:** In the event of database exposure, password hashes can be rapidly reversed using GPU-accelerated pre-computed rainbow tables.
* **Remediation:** Upgrade to `bcrypt` with unique per-password cryptographic salts (`bcrypt.gensalt()`). Implement backward-compatible verification for existing hashes that upgrades accounts to bcrypt on successful login.

---

### SEC-03: Hardcoded Default JWT Secret Key
* **Severity:** **HIGH** | **CVSS v3.1:** 7.5 (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)
* **Affected File:** [`backend/engines/auth_engine.py`](file:///d:/ram_antivirus_official/Industry-project-AI-driven-Cloud-monitoring-platform-/backend/engines/auth_engine.py)
* **Description:** If the environment variable `JWT_SECRET` is unset, the system falls back to `"ram-antivirus-cloud-security-super-secret-key-2026"`.
* **Impact:** Attackers knowing the hardcoded default can forge valid JWT tokens for any user or role (including `admin`).
* **Remediation:** Enforce startup validation that warns or rejects default secrets in production mode.

---

### SEC-04: Unrestricted Public User Registration
* **Severity:** **MEDIUM** | **CVSS v3.1:** 5.3 (`AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`)
* **Affected File:** [`backend/main.py`](file:///d:/ram_antivirus_official/Industry-project-AI-driven-Cloud-monitoring-platform-/backend/main.py)
* **Description:** `POST /api/auth/register` allows unauthenticated clients to register accounts directly.
* **Impact:** Uncontrolled creation of accounts in enterprise deployments.
* **Remediation:** Restrict registration endpoint to authenticated administrators with `users:manage` permission.

---

## 2. Residual Risks & Operational Safeguards
1. **Local Demo Workflow:** Default credentials (`admin`/`admin123`, `analyst1`/`analyst123`, `viewer1`/`viewer123`) are provided for academic review and local evaluation. In enterprise production deployments, default accounts should be disabled or prompted for password reset on first login.
2. **Localhost CORS:** Development origins (`http://localhost:5173`) are permitted. Production deployments must restrict `ALLOWED_ORIGINS` to the verified corporate domain.
