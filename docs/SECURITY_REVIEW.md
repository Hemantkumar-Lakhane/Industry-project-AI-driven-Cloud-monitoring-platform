# RAM Antivirus — Security Review & Vulnerability Register

**Document ID:** `docs/SECURITY_REVIEW.md`  
**Review Date:** November 2026 (Updated Baseline)  
**Auditor:** Engineering Audit Council (Security Lead)  
**Target Repository:** `Industry-project-AI-driven-Cloud-monitoring-platform-`  
**Active Branch:** `main`  

---

## 1. Verified Security Defects & Resolution Status

### SEC-01: Missing Authentication on Operational API Endpoints
* **Severity:** **CRITICAL** | **CVSS v3.1:** 8.8 (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L`)
* **Status:** **RESOLVED & VERIFIED**
* **Affected File:** [`backend/main.py`](file:///d:/ram_antivirus_official/Industry-project-AI-driven-Cloud-monitoring-platform-/backend/main.py)
* **Description:** Over 40 operational endpoints (e.g., `/api/remediation/*`, `/api/detection/*`, `/api/incidents/*`, `/api/simulation/*`, `/api/assets/*`) previously omitted `Depends(bearer_scheme)`.
* **Resolution:** All 51 operational data-modifying (`POST`, `PUT`, `DELETE`) and sensitive telemetry read routes now enforce JWT Bearer validation with granular role permissions (`_require_permission`) and `Depends(bearer_scheme)`. Public access is strictly limited to `/`, `/healthz`, `/docs`, `/redoc`, `/openapi.json`, and `/api/auth/login`.
* **Code Evidence:** Verified in `backend/main.py` and automated test suite `tests/test_auth_enforcement.py`.

---

### SEC-02: Static-Salted Weak Password Hashing
* **Severity:** **HIGH** | **CVSS v3.1:** 7.5 (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)
* **Status:** **RESOLVED & VERIFIED**
* **Affected File:** [`backend/engines/auth_engine.py`](file:///d:/ram_antivirus_official/Industry-project-AI-driven-Cloud-monitoring-platform-/backend/engines/auth_engine.py)
* **Description:** Passwords were previously hashed using single-round SHA-256 with a static salt.
* **Resolution:** Upgraded to `bcrypt` with individual cryptographic salts (`bcrypt.gensalt(rounds=12)`). Implemented automatic zero-downtime hash upgrades upon successful user authentication.
* **Code Evidence:** Verified in `backend/engines/auth_engine.py` and `tests/test_auth_enforcement.py`.

---

### SEC-03: Hardcoded Default JWT Secret Key
* **Severity:** **HIGH** | **CVSS v3.1:** 7.5 (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)
* **Status:** **RESOLVED & VERIFIED**
* **Affected File:** [`backend/engines/auth_engine.py`](file:///d:/ram_antivirus_official/Industry-project-AI-driven-Cloud-monitoring-platform-/backend/engines/auth_engine.py)
* **Description:** When the environment variable `JWT_SECRET` was unset, the system fell back to a default key.
* **Resolution:** Added strict startup validation in `auth_engine.py`. In production deployments (`ENVIRONMENT=production` or `RENDER=true`), the backend throws a fatal `RuntimeError` on startup if `JWT_SECRET` is unset or matches the insecure fallback string.
* **Code Evidence:** Verified in `backend/engines/auth_engine.py:27-36` and test case `test_jwt_secret_required_in_production`.

---

### SEC-04: Unrestricted Public User Registration
* **Severity:** **MEDIUM** | **CVSS v3.1:** 5.3 (`AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`)
* **Status:** **RESOLVED & VERIFIED**
* **Affected File:** [`backend/main.py`](file:///d:/ram_antivirus_official/Industry-project-AI-driven-Cloud-monitoring-platform-/backend/main.py)
* **Description:** `POST /api/auth/register` previously allowed unauthenticated clients to register accounts directly.
* **Resolution:** Restricted user registration to authenticated administrators with the `users:manage` permission.
* **Code Evidence:** Verified in `backend/main.py` lines 360-390 and `tests/test_auth_enforcement.py`.

---

### SEC-05: Rate Limiting & DoS Protection (Brute Force / Abuse Mitigation)
* **Severity:** **MEDIUM** | **CVSS v3.1:** 5.3 (`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`)
* **Status:** **RESOLVED & VERIFIED**
* **Affected File:** [`backend/main.py`](file:///d:/ram_antivirus_official/Industry-project-AI-driven-Cloud-monitoring-platform-/backend/main.py)
* **Description:** Public and simulation endpoints had no rate limiting, allowing rapid credential spraying or excessive adversary simulation bursts.
* **Resolution:** Integrated SlowAPI with IP-based limits:
  - `POST /api/auth/login`: Maximum 5 attempts per minute per remote IP address.
  - `POST /api/simulate/attack`: Maximum 10 simulation invocations per minute per remote IP address.
  - Configured 429 Too Many Requests response handler with structured error detail.
* **Code Evidence:** Verified in `backend/main.py:28-31`, lines 395-405, and lines 1520-1535.

---

### SEC-06: Elimination of Non-Deterministic Remediation Simulation Fallbacks
* **Severity:** **LOW / INTEGRITY** | **CVSS v3.1:** 3.1 (`AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:L/A:N`)
* **Status:** **RESOLVED & VERIFIED**
* **Affected File:** [`backend/engines/remediation_engine.py`](file:///d:/ram_antivirus_official/Industry-project-AI-driven-Cloud-monitoring-platform-/backend/engines/remediation_engine.py)
* **Description:** Previous demo fallback code in `remediation_engine.py` simulated execution success using random probability (`success = random.random() < 0.90`).
* **Resolution:** Removed all random execution fallbacks. Playbook execution now performs deterministic validation against resource state and records durable execution and rollback entries in SQLite (`remediation_history`).
* **Code Evidence:** Verified in `backend/engines/remediation_engine.py`.

---

## 2. Residual Risks & Operational Safeguards

1. **Local Evaluation Credentials:** Pre-seeded demo credentials (`admin`/`admin123`, `analyst1`/`analyst123`, `viewer1`/`viewer123`) exist for local testing and QA review. For enterprise deployments, default passwords must be rotated upon initial deployment.
2. **CORS Restrictions:** Local origins (`http://localhost:5173`, `http://127.0.0.1:5173`) are enabled for development. Production deployments specify explicit origin domains through environment variables.
3. **Database Security:** SQLite file permissions on `backend/security.db` should be restricted to the daemon user in Linux server environments.
