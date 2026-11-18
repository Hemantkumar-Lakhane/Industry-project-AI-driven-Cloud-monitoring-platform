# RAM Antivirus — Architectural & Engineering Decisions (ADR)

**Document ID:** `docs/DECISIONS.md`  
**Date:** November 2026 (Updated Baseline)  

---

## ADR-001: Separation of Workstreams Between the 4 Engineering Members
* **Status:** Accepted
* **Context:** Simultaneous edits to `backend/main.py` and `feature_extractor.py` by multiple developers create high risk of Git merge conflicts and test regressions.
* **Decision:** Assign strict single ownership:
  - Member 1 / Member 4 owns API routing, authentication, authorization, cloud connector infrastructure, and remediation persistence.
  - Member 2 / Member 3 owns ML feature extraction, model inference calibration, detector tuning, compliance history, and UI components.
* **Consequences:** Changes to shared Pydantic schemas require mutual sign-off before implementation.

---

## ADR-002: Backward-Compatible Password Hash Upgrade to Bcrypt
* **Status:** Accepted
* **Context:** Existing database `security.db` contained user records hashed with legacy SHA-256 (`ram-av-salt{pwd}`). Upgrading password hashing must not break existing users or the demo workflow.
* **Decision:**
  - `auth_engine.py` inspects the stored hash format:
    - If it starts with `$2b$`, verify with `bcrypt.checkpw()`.
    - If it is a 64-character hex hash, verify using legacy SHA-256 and immediately upgrade to a bcrypt hash in SQLite upon successful verification.
  - New users and seeded demo accounts are hashed with `bcrypt.gensalt(rounds=12)`.
* **Consequences:** Eliminates static salt vulnerability while preserving zero-downtime login for all existing users.

---

## ADR-003: Coexistence of 9D Flow Schema and Cloud-Native Behavioral Schema
* **Status:** Accepted
* **Context:** The pre-trained PyOD models (`iforest`, `knn`, `hbos`) were trained on NSL-KDD using 9 numerical flow features (`duration`, `src_bytes`, `count`, etc.). Replacing them prematurely breaks benchmark comparisons.
* **Decision:**
  - Preserve `extract_features()` (9D flow schema) for NSL-KDD benchmark compatibility.
  - Introduce `extract_cloud_features()` in `feature_extractor.py` that extracts behavioral cloud telemetry attributes (payload bytes, failed logins, high-risk actions, burst velocity, error flags).
* **Consequences:** Enables clean, independent evaluation of cloud telemetry without breaking legacy benchmark tests.

---

## ADR-004: Strict JWT & RBAC Token Enforcement with SlowAPI Rate Limiting on Production Endpoints
* **Status:** Accepted
* **Context:** Over 40 operational endpoints allowed unauthenticated access to facilitate demo viewing without logging in, exposing sensitive telemetry and remediation execution to unauthorized callers.
* **Decision:**
  - Enforce `Depends(bearer_scheme)` and granular role-based authorization (`_require_permission`) on all data-modifying (`POST`, `PUT`, `DELETE`) and sensitive telemetry read routes (`/api/incidents`, `/api/cspm/scan`, `/api/ciem/scan`, `/api/assets/scan`, `/api/vulnerabilities/scan`).
  - Restrict public routes to `/`, `/healthz`, `/docs`, `/redoc`, `/openapi.json`, and `/api/auth/login`.
  - In production mode (`ENVIRONMENT=production` or `RENDER=true`), enforce startup validation requiring `JWT_SECRET` to be explicitly provided.
  - Integrate SlowAPI rate limiting on `/api/auth/login` (5 requests/minute/IP) and `/api/simulate/attack` (10 requests/minute/IP).
* **Consequences:** Secures the entire API surface against unauthorized access and brute-force credential stuffing.

---

## ADR-005: Deterministic Remediation Execution and Elimination of Random Simulation Fallbacks
* **Status:** Accepted
* **Context:** An offline demo fallback line in `remediation_engine.py` (`success = random.random() < 0.90`) simulated remediation success probabilistically when live cloud agent connectivity was absent.
* **Decision:**
  - Remove all probabilistic fallbacks.
  - Require deterministic validation against the target resource and state.
  - Record execution state and rollback checkpoints in SQLite (`remediation_history`), guaranteeing repeatable, audited remediation lifecycle operations.
* **Consequences:** Ensures consistent, verifiable behavior suitable for strict QA evaluation and production deployment.

---

## ADR-006: Dedicated Telemetry Signatures and Isolation of 16 MITRE ATT&CK Simulation Scenarios
* **Status:** Accepted
* **Context:** Telemetry injection for certain scenarios (such as Account Takeover `DET-ATO-07`) shared rule IDs or actions with other detectors (such as IAM Privilege Escalation `DET-PE-03`), causing cross-triggering and false baseline reports.
* **Decision:**
  - Assign dedicated, non-overlapping Wazuh rule IDs across all 16 attack categories (`80102`, `80201`, `80301`, `80401`, `80501`, `80601`, `80701`, `80801`, `80901`, etc.).
  - Model authentic attack behavior in `attack_simulator.py`:
    - Account Takeover: Legitimate internal corporate login (`10.0.0.x`) followed by external IP credential modification (`ChangePassword`, `CreateAccessKey`, `DeleteVirtualMFADevice`).
    - Suspicious API Activity: 12-call reconnaissance burst meeting `SuspiciousAPIActivityDetector` velocity thresholds.
  - Add canonical category slug resolution in `session_manager.py` so aliases map cleanly to their verified taxonomy findings.
* **Consequences:** 100% 1-to-1 fidelity between simulated attacks and their corresponding detector engines with zero cross-triggering.

---

## ADR-007: Continuous Asynchronous Telemetry Ingestion Loop in FastAPI Lifespan for Cloud Deployments
* **Status:** Accepted
* **Context:** In cloud deployments (e.g. Render/Vercel) without a persistent separate console running `log_generator.py`, the backend initialized once with a static baseline of 47 events and remained static.
* **Decision:**
  - In `backend/main.py`'s `lifespan` handler, launch an asynchronous background task `_background_telemetry_loop()` when not executing tests (`"pytest" not in sys.modules`).
  - Periodically (every 25 seconds), generate a fresh batch of Wazuh and CloudTrail telemetry events, append them to `alerts.json`, rotate logs at 3,000 entries, and call `session_manager.refresh_from_logs(500)`.
* **Consequences:** Deployed cloud instances continuously update their metrics, charts, and findings in real-time without requiring external daemon processes.
