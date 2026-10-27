# RAM Antivirus — Architectural & Engineering Decisions (ADR)

**Document ID:** `docs/DECISIONS.md`  
**Date:** October 27, 2026  

---

## ADR-001: Separation of Workstreams Between Tanmay and Hemant
* **Status:** Accepted
* **Context:** Simultaneous edits to `backend/main.py` and `feature_extractor.py` by two developers create high risk of Git merge conflicts and test regressions.
* **Decision:** Assign strict single ownership:
  - Tanmay owns API routing, authentication, authorization, cloud connector infrastructure, and remediation persistence.
  - Hemant owns ML feature extraction, model inference calibration, detector tuning, compliance history, and UI components.
* **Consequences:** Changes to shared Pydantic schemas require mutual sign-off before implementation.

---

## ADR-002: Backward-Compatible Password Hash Upgrade to Bcrypt
* **Status:** Accepted
* **Context:** Existing database `security.db` contains user records hashed with legacy SHA-256 (`ram-av-salt{pwd}`). Upgrading password hashing must not break existing users or the demo workflow.
* **Decision:**
  - `auth_engine.py` will inspect the stored hash format:
    - If it starts with `$2b$`, verify with `bcrypt.checkpw()`.
    - If it is a 64-character hex hash, verify using legacy SHA-256 and immediately upgrade to a bcrypt hash in SQLite upon successful verification.
  - New users and seeded demo accounts are hashed with `bcrypt.gensalt()`.
* **Consequences:** Eliminates static salt vulnerability while preserving zero-downtime login for all existing users.

---

## ADR-003: Coexistence of 9D Flow Schema and Cloud-Native Behavioral Schema
* **Status:** Accepted
* **Context:** The pre-trained PyOD models (`iforest`, `knn`, `hbos`) were trained on NSL-KDD using 9 numerical flow features (`duration`, `src_bytes`, `count`, etc.). Replacing them prematurely breaks benchmark comparisons.
* **Decision:**
  - Preserve `extract_features()` (9D flow schema) for NSL-KDD benchmark compatibility.
  - Introduce `extract_cloud_features()` in `feature_extractor.py` that extracts behavioral cloud telemetry attributes (payload bytes, failed logins, high-risk actions, burst velocity, error flags).
* **Consequences:** Enables clean, independent evaluation of cloud telemetry without breaking legacy benchmark tests.
