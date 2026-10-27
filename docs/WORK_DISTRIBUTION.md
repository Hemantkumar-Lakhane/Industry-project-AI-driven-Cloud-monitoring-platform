# RAM Antivirus — Authoritative Work Distribution & Implementation Plan

**Document ID:** `docs/WORK_DISTRIBUTION.md`  
**Current Milestone:** Milestone 2 (Platform Reliability, Detection Rebalance & ML Calibration)  
**Last Updated:** October 27, 2026  
**Engineering Team:**  
- **Developer 1 (Platform Security, Cloud Infrastructure & Detection Workstream A):** Tanmay  
- **Developer 2 (Intelligence Engine, ML, Analytics & Detection Workstream B):** Hemant  

---

## 1. Project Objective & Core Architecture Principles

1. **Strictly Non-Overlapping Ownership:** To prevent file collision and race conditions, each source file has exactly one primary owner. Cross-cutting integrations occur exclusively through stable, shared contracts (`schemas/event.py`, `schemas/finding.py`, and `schemas/incident.py`).
2. **Balanced Workload Allocation:** Both developers own end-to-end capabilities spanning frontend, backend, detection logic, and persistence.
3. **Evidence-Based Verification:** No task is marked complete without executable automated test evidence, exact exit codes, and verifiable outputs.
4. **Preservation of Demo Workflow:** Security enhancements and RBAC must never break the seamless local demo login flow (`admin` / `admin123`, `analyst1` / `analyst123`, `viewer1` / `viewer123`).

---

## 2. File Ownership Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                 DEVELOPER 1: TANMAY                         │
│                                                             │
│  Primary Module Ownership:                                  │
│    • backend/main.py (Route definitions & auth middleware)  │
│    • backend/engines/auth_engine.py                         │
│    • backend/engines/asset_engine.py                        │
│    • backend/engines/cspm_engine.py & ciem_engine.py        │
│    • backend/engines/localstack_engine.py                   │
│    • backend/engines/remediation_engine.py                  │
│    • backend/engines/db.py (Schema migrations)              │
│    • frontend/src/App.jsx (WebSocket & Axios interceptor)   │
│    • backend/engines/detectors/:                            │
│        - brute_force.py                                     │
│        - account_takeover.py                                │
│        - iam_privilege_escalation.py                        │
│        - cloud_misconfiguration.py                          │
│        - network_scanning.py                                │
│        - ddos.py                                            │
│        - defense_tampering.py                               │
│        - supply_chain.py                                    │
│    • backend/tests/test_auth_enforcement.py                 │
└─────────────────────────────────────────────────────────────┘
                               ▲
                               │ Shared Contract Boundary:
                               │ schemas/event.py, schemas/finding.py, schemas/incident.py
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                 DEVELOPER 2: HEMANT                         │
│                                                             │
│  Primary Module Ownership:                                  │
│    • backend/engines/feature_extractor.py                   │
│    • backend/engines/ml_engine.py                           │
│    • backend/engines/correlation_engine.py                  │
│    • backend/engines/risk_engine.py                         │
│    • backend/engines/vulnerability_engine.py                │
│    • backend/engines/compliance_engine.py                   │
│    • backend/engines/alert_engine.py                        │
│    • frontend/src/components/* (All UI tab views)           │
│    • backend/engines/detectors/:                            │
│        - suspicious_api_activity.py                         │
│        - data_exfiltration.py                               │
│        - cryptomining.py                                    │
│        - container_k8s.py                                   │
│        - bola_ssrf.py                                       │
│        - malware_ransomware.py                              │
│        - database_attacks.py                                │
│        - serverless_abuse.py                                │
│    • backend/tests/test_cloud_feature_extractor.py          │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. All 16 Modular Attack Detectors: Audit & Ownership Distribution

| Category Index & Name | Implementation File | Primary Detection Logic | Inputs & Dependencies | Existing Tests | Status / Limitations | Effort | Assigned Owner |
| :--- | :--- | :--- | :--- | :--- | :--- | :---: | :---: |
| **C1: Brute Force** | `detectors/brute_force.py` | Sliding-window threshold on consecutive auth failures (default $\ge 5$ failures within 120s). | `event.action`, `status="failure"`, `principal.identity`, `network.src_ip` | `test_all_16_detectors.py::test_detector_c1_brute_force` | **VERIFIED WORKING**; robust temporal bucket logic. | Low | **Tanmay** |
| **C2: Account Takeover (ATO)** | `detectors/account_takeover.py` | Identifies concurrent logins across disparate geographic/IP locations or login followed immediately by credential/MFA modification. | `event.action in ["ChangePassword", "DeactivateMFA"]`, `src_ip`, `principal.identity` | `test_all_16_detectors.py::test_detector_c2_account_takeover` | **VERIFIED WORKING**; verified fast IP flip detection. | Med | **Tanmay** |
| **C3: IAM Privilege Escalation** | `detectors/iam_privilege_escalation.py` | Detects high-privilege policy attachments (e.g. `AdministratorAccess`), user group escalations, and unauthorized role trust edits. | `action in ["AttachUserPolicy", "PutUserPolicy", "CreatePolicyVersion"]`, `service="iam"` | `test_all_16_detectors.py::test_detector_c3_iam_privilege_escalation` | **VERIFIED WORKING**; inspects policyArn and request parameters. | Med | **Tanmay** |
| **C4: Suspicious API Activity** | `detectors/suspicious_api_activity.py` | Detects volumetric reconnaissance bursts (bursts of `Describe*`, `List*`, `Get*` API calls exceeding sliding threshold). | `action`, `count`, `srv_count`, temporal window | `test_all_16_detectors.py::test_detector_c4_suspicious_api_activity` | **VERIFIED WORKING**; catches rapid enumeration bursts. | Med | **Hemant** |
| **C5: Cloud Misconfiguration** | `detectors/cloud_misconfiguration.py` | Detects risky configuration mutations in real-time (e.g. `PutBucketAcl` public-read, security group ingress `0.0.0.0/0` on port 22/3389). | `action in ["PutBucketAcl", "AuthorizeSecurityGroupIngress"]`, `service` | `test_all_16_detectors.py::test_detector_c5_cloud_misconfiguration` | **VERIFIED WORKING**; maps directly to CSPM remediation fixes. | Low | **Tanmay** |
| **C6: Data Exfiltration** | `detectors/data_exfiltration.py` | Detects anomalous outbound data transfers exceeding baseline volume thresholds ($>500\text{ MB}$) to non-internal IP destinations. | `dst_bytes`, `bytes_transferred`, `network.dst_ip`, `action="GetObject"` | `test_all_16_detectors.py::test_detector_c6_data_exfiltration` | **VERIFIED WORKING**; inspects egress volumes. | Med | **Hemant** |
| **C7: Network Scanning** | `detectors/network_scanning.py` | Detects horizontal port sweeps and multi-service probing based on elevated `diff_srv_rate` and port connection diversity. | `diff_srv_rate > 0.4`, `dst_port`, `count`, Wazuh rule IDs | `test_all_16_detectors.py::test_detector_c7_network_scanning` | **VERIFIED WORKING**; checks network flow headers. | Med | **Tanmay** |
| **C8: DDoS** | `detectors/ddos.py` | Detects volumetric connection floods and SYN floods characterized by elevated `count` and high `serror_rate` ($\ge 0.7$). | `count > 30`, `serror_rate > 0.6`, `action in ["SYN_FLOOD", "UDP_FLOOD"]` | `test_all_16_detectors.py::test_detector_c8_ddos` | **VERIFIED WORKING**; dual trigger on rule and flow headers. | Low | **Tanmay** |
| **C9: Cryptomining** | `detectors/cryptomining.py` | Detects execution of known mining binaries (`xmrig`, `minerd`) and outbound connections to stratum mining pools on ports 3333, 4444, 8333. | `description`, `action="ProcessSpawn"`, `raw_payload.port` | `test_all_16_detectors.py::test_detector_c9_cryptomining` | **VERIFIED WORKING**; string & port matching. | Low | **Hemant** |
| **C10: Container & K8s Attacks** | `detectors/container_k8s.py` | Detects container breakout indicators, privileged securityContext, and suspicious hostPath mounts (`/var/run/docker.sock`). | `action in ["CreatePod", "ExecPod"]`, `description`, `target_resource` | `test_all_16_detectors.py::test_detector_c10_container_k8s` | **VERIFIED WORKING**; inspects pod manifests. | Med | **Hemant** |
| **C11: Application BOLA & SSRF** | `detectors/bola_ssrf.py` | Detects server-side request forgery targeting internal metadata services (`169.254.169.254`) and parameter ID tampering. | `network.dst_ip == "169.254.169.254"`, `description`, `action="HTTP_GET"` | `test_all_16_detectors.py::test_detector_c11_bola_ssrf` | **VERIFIED WORKING**; catches cloud IMDS probes. | Med | **Hemant** |
| **C12: Malware & Ransomware** | `detectors/malware_ransomware.py` | Detects ransomware precursor activity, shadow copy deletion (`vssadmin delete shadows`), and mass file renaming. | `action="CommandExecute"`, `description`, Wazuh malware rule IDs | `test_all_16_detectors.py::test_detector_c12_malware_ransomware` | **VERIFIED WORKING**; detects evasion and shadow copy wiping. | Med | **Hemant** |
| **C13: Database Attacks** | `detectors/database_attacks.py` | Detects SQL injection payloads (`UNION SELECT`, `' OR 1=1`), bulk table dumping, and unauthorized schema drops. | `action="Query"`, `description`, `service in ["rds", "postgres", "mysql"]` | `test_all_16_detectors.py::test_detector_c13_database_attacks` | **VERIFIED WORKING**; regex pattern & SQL keyword parsing. | Med | **Hemant** |
| **C14: Serverless Abuse** | `detectors/serverless_abuse.py` | Detects unauthorized runtime package tampering (`UpdateFunctionCode`) outside CI/CD pipelines and concurrency exhaustion. | `service="lambda"`, `action in ["UpdateFunctionCode", "PutFunctionConcurrency"]` | `test_all_16_detectors.py::test_detector_c14_serverless_abuse` | **VERIFIED WORKING**; monitors serverless function modifications. | Med | **Hemant** |
| **C15: Supply Chain** | `detectors/supply_chain.py` | Detects container image tag overwrites in production repositories (`PutImage`) and dependency manifest hijacking. | `service="ecr"`, `action in ["PutImage", "UploadLayerPart"]`, `target_resource` | `test_all_16_detectors.py::test_detector_c15_supply_chain` | **VERIFIED WORKING**; flags tag mutation. | Med | **Tanmay** |
| **C16: Defense Tampering** | `detectors/defense_tampering.py` | Detects impairment of security telemetry and logging infrastructure (`StopLogging`, `DeleteTrail`, `DeleteFlowLogs`). | `service in ["cloudtrail", "guardduty", "waf"]`, `action in ["StopLogging", "DeleteTrail"]` | `test_all_16_detectors.py::test_detector_c16_defense_tampering` | **VERIFIED WORKING**; high confidence alert generation. | Low | **Tanmay** |

---

## 4. Workstream A — Tanmay (Developer 1)

### TNY-01: Authentication & Endpoint Access Control Enforcement
* **Status:** **VERIFIED COMPLETED**
* **Delivered:** Enforced `_require_permission` across sensitive backend routes in `backend/main.py`. Restricted `POST /api/auth/register` to authenticated administrators with `users:manage` permissions. Public routes preserved for health checks and Swagger UI.
* **Evidence:** `backend/tests/test_auth_enforcement.py` (4 passed, exit code 0).

### TNY-02: Cryptographic Password Hashing & JWT Hardening
* **Status:** **VERIFIED COMPLETED**
* **Delivered:** Upgraded `backend/engines/auth_engine.py` to use `bcrypt` (12 rounds) with individual salts. Added transparent upgrade for legacy SHA-256 hashes upon successful authentication. Seeded default demo accounts with valid bcrypt hashes. Connected Axios Bearer token interceptor in `frontend/src/App.jsx`.
* **Evidence:** Verified admin hash prefix `$2b$12$` and login success (exit code 0).

### TNY-03: Durable Remediation History & Rollback Persistence
* **Status:** **VERIFIED COMPLETED**
* **Delivered:** Created `remediation_history` SQLite table in `backend/engines/db.py`. Updated `backend/engines/remediation_engine.py` to persist all execution records and read from SQLite during rollback operations. Verified rollback succeeds across complete in-memory wipe.
* **Evidence:** Python test command executing memory wipe and durable rollback passed (exit code 0).

### TNY-04: Real Host & Local Workload Asset Discovery
* **Status:** In Progress
* **Files Owned:** `backend/engines/asset_engine.py`
* **Objective:** Discover actual local workload listening ports, system processes, and network interfaces when LocalStack or AWS live connectors are offline, replacing purely synthetic static catalogs.
* **Acceptance Criteria:** `discover_assets()` outputs real workload host processes and open ports with provenance marked as `LOCAL_WORKLOAD`.

### TNY-05: Real-Time WebSocket Streaming Client
* **Status:** Planned
* **Files Owned:** `frontend/src/App.jsx`
* **Objective:** Connect the React application root to `/ws/events` with reconnection backoff, event deduplication, and graceful fallback to HTTP polling.
* **Acceptance Criteria:** Telemetry and findings stream live without manual page refreshes.

### TNY-06: Infrastructure & Platform Security Regression
* **Status:** In Progress / Continuous
* **Files Owned:** `backend/tests/test_auth_enforcement.py`, infrastructure tests
* **Scope:** Maintain regression suite covering authentication, authorization, LocalStack, and remediation durability.

---

## 5. Workstream B — Hemant (Developer 2)

### HMT-01: Cloud-Native Feature Extraction Pipeline
* **Status:** **VERIFIED COMPLETED**
* **Delivered:** Implemented `extract_cloud_features()`, `extract_cloud_feature_matrix()`, and `validate_cloud_feature_vector()` in `backend/engines/feature_extractor.py`. Schema contains 8 non-leaking, non-constant behavioral audit telemetry dimensions with bounded missing-value handling.
* **Evidence:** `backend/tests/test_cloud_feature_extractor.py` (4 passed, exit code 0).

### HMT-02: ML Inference Scoring Calibration & Dual-Schema Compatibility
* **Status:** In Progress
* **Files Owned:** `backend/engines/ml_engine.py`
* **Objective:** Connect cloud-native feature extraction to inference, calibrate PyOD anomaly scores against empirical percentiles, and eliminate the arbitrary 0.5 threshold. Ensure clear separation between network-flow evaluation and cloud audit log evaluation.
* **Acceptance Criteria:** Scores produce an explainable distribution across Low, Medium, High, and Critical.

### HMT-03: Dynamic Compliance Trend History
* **Status:** **VERIFIED COMPLETED**
* **Delivered:** Connected `backend/engines/compliance_engine.py` to SQLite `save_compliance_score()` and `get_compliance_trend_db()`, replacing the artificial hardcoded baseline (`overall_score - 72.5`) with real historical snapshot deltas.
* **Evidence:** Python test verified `get_compliance_dashboard` calculates trend deltas from SQLite (exit code 0).

### HMT-04: Multi-Signal Incident Correlation & Risk Engine Verification
* **Status:** In Progress
* **Files Owned:** `backend/engines/correlation_engine.py`, `backend/engines/risk_engine.py`
* **Objective:** Verify temporal sliding-window grouping, MITRE stage transitions, and multi-factor composite risk scoring (35% ML + 35% CSPM + 30% CIEM). Ensure incident findings display complete forensic evidence.
* **Acceptance Criteria:** Correlation tests pass with zero synthetic leakage and correct incident synthesis.

### HMT-05: Workload Vulnerability Engine (CVE/CVSS) Verification
* **Status:** Planned
* **Files Owned:** `backend/engines/vulnerability_engine.py`
* **Objective:** Verify automated CVE matching against local requirements.txt and discovered workload binaries with CVSS v3.1 base scoring.
* **Acceptance Criteria:** Vulnerability scan returns verified CVE records persisted in SQLite `vulnerabilities` table.

### HMT-06: Frontend Forensic Drawers & Clean Metrics
* **Status:** Planned
* **Files Owned:** `frontend/src/components/*`
* **Objective:** Connect all dashboard tabs to live backend APIs, eliminating hardcoded educational strings and displaying real evidence in forensic drawers.
* **Acceptance Criteria:** Frontend builds cleanly; all data views display live API metrics.

### HMT-07: ML, Detection & Analytics Regression Suite
* **Status:** In Progress / Continuous
* **Files Owned:** `backend/tests/test_cloud_feature_extractor.py`, `backend/tests/test_all_16_detectors.py`
* **Scope:** Maintain regression suite covering ML feature extraction, detector accuracy, correlation, and compliance history.

---

## 6. SRS Functional Requirements Matrix (FR-01 to FR-12)

| Requirement | Description | Current Architecture Status | Evidence / Verification Method | Remaining Work | Assigned Owner |
| :--- | :--- | :---: | :--- | :--- | :---: |
| **FR-01** | Cloud Resource Discovery | **PARTIALLY IMPLEMENTED** | Discovers emulated S3/IAM when LocalStack runs; falls back to static catalog. | Add local workload process/port discovery in `asset_engine.py`. | **Tanmay** |
| **FR-02** | Workload Monitoring | **VERIFIED WORKING** | Reads Wazuh `/var/ossec/logs/alerts/alerts.json` with fallback to `wazuh_simulator.py`. | Maintain live Wazuh and synthetic buffer compatibility. | **Tanmay** |
| **FR-03** | IAM Assessment | **VERIFIED WORKING** | Scans excessive permissions, dormant keys, and root MFA in `ciem_engine.py`. | Add live LocalStack IAM policy evaluation. | **Tanmay** |
| **FR-04** | Misconfiguration Detection | **VERIFIED WORKING** | Scans public S3, open SG ports 22/3389, and RDS unencrypted in `cspm_engine.py`. | Integrate with detector C5 for real-time drift alerts. | **Tanmay** |
| **FR-05** | Vulnerability Analysis | **VERIFIED WORKING** | `vulnerability_engine.py` scans `requirements.txt` and packages against CVE database with CVSS v3.1 scoring. | Expose interactive scan trigger in UI dashboard. | **Hemant** |
| **FR-06** | Event Monitoring & Normalization | **VERIFIED WORKING** | `schemas/event.py` normalizes heterogeneous logs into validated Pydantic events. | Verified via `test_schemas_and_foundation.py`. | **Shared** |
| **FR-07** | Threat Detection | **VERIFIED WORKING** | All 16 modular attack detectors implemented in `engines/detectors/` and verified. | ML score calibration (HMT-02). | **Hemant & Tanmay** |
| **FR-08** | Correlation & Risk Scoring | **VERIFIED WORKING** | `correlation_engine.py` groups findings into incidents; `risk_engine.py` calculates composite 0-100 score. | Verify multi-stage MITRE kill-chain progression tests. | **Hemant** |
| **FR-09** | Automated Response | **VERIFIED WORKING** | `remediation_engine.py` executes step-by-step playbooks with safe dry-run mode. | Connect LocalStack Boto3 execution actions. | **Tanmay** |
| **FR-10** | Remediation & Rollback | **VERIFIED WORKING** | Rollback restores findings to `open`; now survives backend reboots via SQLite `remediation_history`. | Verified via memory-wipe execution test. | **Tanmay** |
| **FR-11** | Incident & Audit Logging | **VERIFIED WORKING** | Persists findings, incidents, and scan logs to SQLite WAL database (`security.db`). | All events persisted with UTC timestamps. | **Shared** |
| **FR-12** | Reporting & Visualization | **VERIFIED WORKING** | `compliance_engine.py` outputs JSON/CSV reports; trend deltas now computed from SQLite snapshots. | Update frontend drawers to render live evidence. | **Hemant** |
