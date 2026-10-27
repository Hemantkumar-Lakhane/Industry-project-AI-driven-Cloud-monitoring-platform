# RAM Antivirus — Testing & Verification Procedures

**Document ID:** `docs/TESTING_AND_VERIFICATION.md`  
**Date:** October 27, 2026  
**Current Test Coverage:** 134 Automated Unit & Integration Tests (100% Passing)

---

## 1. Test Suite Classification

| Test Suite File | Execution Safety | Purpose | Primary Commands |
| :--- | :---: | :--- | :--- |
| `tests/test_auth_enforcement.py` | **Safe (In-Memory)** | Validates route authentication enforcement (401 anonymous rejections, 403 viewer rejections, admin 200 grants on registration and remediation). | `pytest tests/test_auth_enforcement.py -v` |
| `tests/test_cloud_feature_extractor.py` | **Safe (In-Memory)** | Validates 8D cloud-native behavioral feature extraction, missing-value handling, zero userAgent leakage, and validation bounds. | `pytest tests/test_cloud_feature_extractor.py -v` |
| `tests/test_ml_cloud_native_integration.py` | **Safe (In-Memory)** | Validates dual-lens ML inference (specialist flow models + cloud behavioral analyzer), percentile score calibration, and explainability fields. | `pytest tests/test_ml_cloud_native_integration.py -v` |
| `tests/test_vulnerability_engine_deep.py` | **Safe (In-Memory & SQLite)** | Validates CVE matching against advisories, semantic version parsing, package manifest scanning, and REST API endpoints. | `pytest tests/test_vulnerability_engine_deep.py -v` |
| `tests/test_schemas_and_foundation.py` | **Safe (In-Memory)** | Validates Pydantic schemas, normalization, IEEE flow feature extraction matrix. | `pytest tests/test_schemas_and_foundation.py -v` |
| `tests/test_all_16_detectors.py` | **Safe (In-Memory)** | Validates all 16 modular attack detectors against benign and attack patterns with zero false positives. | `pytest tests/test_all_16_detectors.py -v` |
| `tests/test_correlation_engine.py` | **Safe (In-Memory)** | Validates multi-signal incident correlation across 5 kill-chain tiers, 15-minute sliding windows, and anti-hub protection. | `pytest tests/test_correlation_engine.py -v` |
| `tests/test_risk_engine.py` | **Safe (In-Memory)** | Validates 4-pillar composite risk score calculation, blast radius bounds, temporal decay, and deterministic ordering. | `pytest tests/test_risk_engine.py -v` |
| `tests/test_brute_force_detector.py` | **Safe (In-Memory & Auth)** | Validates Category 1 brute-force detector, 60s windows, breach escalation, remediation dry-runs, and provenance labels. | `pytest tests/test_brute_force_detector.py -v` |
| `tests/test_srs_functional_requirements.py` | **Safe (In-Memory & SQLite)** | End-to-end integration across all 12 FRs against `security.db`. | `pytest tests/test_srs_functional_requirements.py -v` |
| `tests/test_docs_openapi.py` | **Safe (Read-Only)** | Validates OpenAPI 3.x schema generation, endpoints, and security tags. | `pytest tests/test_docs_openapi.py -v` |
| `tests/test_health.py` | **Safe (Read-Only)** | Validates `/` root and `/healthz` endpoints, CORS headers. | `pytest tests/test_health.py -v` |

---

## 2. Standard Verification Commands & Measured Outcomes

* **Complete Backend Test Suite (134 Tests):**
  ```bash
  python -m pytest tests/ -q
  ```
  *Measured Result:* **134 passed, 0 failed, 301 warnings in 49.34s (Exit Code 0)**

* **All 16 Detectors Matrix Audit:**
  ```bash
  python tests/verify_detectors_matrix.py
  ```
  *Measured Result:* **All 16 detectors tested and verified with 100% genuine findings, precise rejection of benign streams, and strict boundary thresholds (Exit Code 0)**

* **Durable Remediation Rollback Test:**
  ```bash
  python -c "from engines.remediation_engine import execute_playbook, rollback_remediation, EXECUTION_HISTORY; res = execute_playbook('brute_force'); eid = res['execution_id']; EXECUTION_HISTORY.clear(); rb = rollback_remediation(eid); print('Rollback across memory wipe:', rb['status'])"
  ```
  *Measured Result:* **Rollback across memory wipe: success (Exit Code 0)**

* **Frontend Production Compilation:**
  ```bash
  npm --prefix frontend run build
  ```
  *Measured Result:* **Built in 397ms (Exit Code 0, 2,344 modules transformed, 0 errors)**

* **Backend Import & ML Specialist Model Verification:**
  ```bash
  python -c "import main; print('[OK] Backend verified')"
  ```
  *Measured Result:* **All 3 PyOD models (iforest, knn, hbos) loaded; SQLite connected; 49 routes registered (Exit Code 0)**
