# RAM Antivirus — Authoritative Work Distribution & Implementation Plan

**Document ID:** `docs/WORK_DISTRIBUTION.md`  
**Current Milestone:** Milestone 2 (Platform Reliability, Detection Rebalance & ML Calibration)  
**Last Updated:** October 27, 2026  
**Engineering Team (4 Members):**  
- **Member 1 (Workstream 1):** Identity & Access Attacks, Platform Security & Auth Engine  
- **Member 2 (Workstream 2):** Network Attacks, Feature Extraction & Machine Learning Pipeline  
- **Member 3 (Workstream 3):** API Attacks, Attack Simulation, Multi-Signal Incident Correlation & Risk Scoring  
- **Member 4 (Workstream 4):** Cloud Security Posture (CSPM), Vulnerability Management & Automated Remediation  

---

## 1. Project Objective & Core Architecture Principles

1. **Strictly Non-Overlapping Ownership:** To prevent file collision and race conditions, each source file has exactly one primary owner. Cross-cutting integrations occur exclusively through stable, shared contracts (`schemas/event.py`, `schemas/finding.py`, and `schemas/incident.py`).
2. **Balanced Workload Allocation:** All four team members own end-to-end capabilities spanning frontend views, backend modules, detection logic, and persistence.
3. **Evidence-Based Verification:** No task is marked complete without executable automated test evidence, exact exit codes, and verifiable outputs.
4. **Preservation of Demo Workflow:** Security enhancements and RBAC must never break the seamless local demo login flow (`admin` / `admin123`, `analyst1` / `analyst123`, `viewer1` / `viewer123`).

---

## 2. File Ownership Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                 MEMBER 1: IDENTITY & ACCESS                 │
│                                                             │
│  Primary Module Ownership:                                  │
│    • backend/main.py (Route definitions & auth middleware)  │
│    • backend/engines/auth_engine.py                         │
│    • backend/engines/ciem_engine.py                         │
│    • backend/engines/db.py (Schema migrations)              │
│    • frontend/src/App.jsx (WebSocket & Axios interceptor)   │
│    • backend/engines/detectors/:                            │
│        - brute_force.py (C1)                                │
│        - account_takeover.py (C2)                           │
│        - iam_privilege_escalation.py (C3)                   │
│        - defense_tampering.py (C16)                         │
│    • backend/tests/test_auth_enforcement.py                 │
└─────────────────────────────────────────────────────────────┘
                               ▲
                               │ Shared Contract Boundary:
                               │ schemas/event.py, schemas/finding.py, schemas/incident.py
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                 MEMBER 2: NETWORK ATTACKS & ML              │
│                                                             │
│  Primary Module Ownership:                                  │
│    • backend/engines/feature_extractor.py                   │
│    • backend/engines/ml_engine.py                           │
│    • backend/train_model.py                                 │
│    • backend/models/* (iforest, hbos, knn, scalers, meta)   │
│    • frontend/src/components/MLComparisonTab.jsx            │
│    • backend/engines/detectors/:                            │
│        - data_exfiltration.py (C6)                          │
│        - network_scanning.py (C7)                           │
│        - ddos.py (C8)                                       │
│        - cryptomining.py (C9)                               │
│    • backend/tests/test_cloud_feature_extractor.py          │
│    • backend/tests/test_ml_cloud_native_integration.py     │
└─────────────────────────────────────────────────────────────┘
                               ▲
                               │ Shared Contract Boundary:
                               │ schemas/event.py, schemas/finding.py, schemas/incident.py
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                 MEMBER 3: API, SIMULATION & RISK            │
│                                                             │
│  Primary Module Ownership:                                  │
│    • backend/engines/correlation_engine.py                  │
│    • backend/engines/risk_engine.py                         │
│    • backend/simulator/attack_simulator.py                  │
│    • backend/simulator/session_manager.py                   │
│    • frontend/src/components/AttackSimulationTab.jsx        │
│    • frontend/src/components/AlertsIncidentsTab.jsx         │
│    • backend/engines/detectors/:                            │
│        - suspicious_api_activity.py (C4)                    │
│        - bola_ssrf.py (C11)                                 │
│        - database_attacks.py (C13)                          │
│        - serverless_abuse.py (C14)                          │
│    • backend/tests/test_correlation_engine.py               │
└─────────────────────────────────────────────────────────────┘
                               ▲
                               │ Shared Contract Boundary:
                               │ schemas/event.py, schemas/finding.py, schemas/incident.py
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                 MEMBER 4: CLOUD, VULN & REMEDIATION         │
│                                                             │
│  Primary Module Ownership:                                  │
│    • backend/engines/cspm_engine.py                         │
│    • backend/engines/vulnerability_engine.py                │
│    • backend/engines/remediation_engine.py                  │
│    • backend/engines/compliance_engine.py                   │
│    • backend/engines/asset_engine.py                        │
│    • frontend/src/components/ComplianceTab.jsx              │
│    • frontend/src/components/RemediationTab.jsx             │
│    • backend/engines/detectors/:                            │
│        - cloud_misconfiguration.py (C5)                     │
│        - container_k8s.py (C10)                             │
│        - malware_ransomware.py (C12)                        │
│        - supply_chain.py (C15)                              │
│    • backend/tests/test_vulnerability_engine_deep.py        │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. All 16 Modular Attack Detectors: Audit & Ownership Distribution

| Category Index & Name | Implementation File | Primary Detection Logic | Inputs & Dependencies | Existing Tests | Status / Limitations | Effort | Assigned Owner |
| :--- | :--- | :--- | :--- | :--- | :--- | :---: | :---: |
| **C1: Brute Force** | `detectors/brute_force.py` | Sliding-window threshold on consecutive auth failures (default $\ge 5$ failures within 120s). | `event.action`, `status="failure"`, `principal.identity`, `network.src_ip` | `test_all_16_detectors.py::test_detector_c1_brute_force` | **VERIFIED WORKING**; robust temporal bucket logic. | Low | **Member 1** |
| **C2: Account Takeover (ATO)** | `detectors/account_takeover.py` | Identifies concurrent logins across disparate geographic/IP locations or login followed immediately by credential/MFA modification. | `event.action in ["ChangePassword", "DeactivateMFA"]`, `src_ip`, `principal.identity` | `test_all_16_detectors.py::test_detector_c2_account_takeover` | **VERIFIED WORKING**; verified fast IP flip detection. | Med | **Member 1** |
| **C3: IAM Privilege Escalation** | `detectors/iam_privilege_escalation.py` | Detects high-privilege policy attachments (e.g. `AdministratorAccess`), user group escalations, and unauthorized role trust edits. | `action in ["AttachUserPolicy", "PutUserPolicy", "CreatePolicyVersion"]`, `service="iam"` | `test_all_16_detectors.py::test_detector_c3_iam_privilege_escalation` | **VERIFIED WORKING**; inspects policyArn and request parameters. | Med | **Member 1** |
| **C4: Suspicious API Activity** | `detectors/suspicious_api_activity.py` | Detects volumetric reconnaissance bursts (bursts of `Describe*`, `List*`, `Get*` API calls exceeding sliding threshold). | `action`, `count`, `srv_count`, temporal window | `test_all_16_detectors.py::test_detector_c4_suspicious_api_activity` | **VERIFIED WORKING**; catches rapid enumeration bursts. | Med | **Member 3** |
| **C5: Cloud Misconfiguration** | `detectors/cloud_misconfiguration.py` | Detects risky configuration mutations in real-time (e.g. `PutBucketAcl` public-read, security group ingress `0.0.0.0/0` on port 22/3389). | `action in ["PutBucketAcl", "AuthorizeSecurityGroupIngress"]`, `service` | `test_all_16_detectors.py::test_detector_c5_cloud_misconfiguration` | **VERIFIED WORKING**; maps directly to CSPM remediation fixes. | Low | **Member 4** |
| **C6: Data Exfiltration** | `detectors/data_exfiltration.py` | Detects anomalous outbound data transfers exceeding baseline volume thresholds ($>500\text{ MB}$) to non-internal IP destinations. | `dst_bytes`, `bytes_transferred`, `network.dst_ip`, `action="GetObject"` | `test_all_16_detectors.py::test_detector_c6_data_exfiltration` | **VERIFIED WORKING**; inspects egress volumes. | Med | **Member 2** |
| **C7: Network Scanning** | `detectors/network_scanning.py` | Detects horizontal port sweeps and multi-service probing based on elevated `diff_srv_rate` and port connection diversity. | `diff_srv_rate > 0.4`, `dst_port`, `count`, Wazuh rule IDs | `test_all_16_detectors.py::test_detector_c7_network_scanning` | **VERIFIED WORKING**; checks network flow headers. | Med | **Member 2** |
| **C8: DDoS** | `detectors/ddos.py` | Detects volumetric connection floods and SYN floods characterized by elevated `count` and high `serror_rate` ($\ge 0.7$). | `count > 30`, `serror_rate > 0.6`, `action in ["SYN_FLOOD", "UDP_FLOOD"]` | `test_all_16_detectors.py::test_detector_c8_ddos` | **VERIFIED WORKING**; dual trigger on rule and flow headers. | Low | **Member 2** |
| **C9: Cryptomining** | `detectors/cryptomining.py` | Detects execution of known mining binaries (`xmrig`, `minerd`) and outbound connections to stratum mining pools on ports 3333, 4444, 8333. | `description`, `action="ProcessSpawn"`, `raw_payload.port` | `test_all_16_detectors.py::test_detector_c9_cryptomining` | **VERIFIED WORKING**; string & port matching. | Low | **Member 2** |
| **C10: Container & K8s Attacks** | `detectors/container_k8s.py` | Detects container breakout indicators, privileged securityContext, and suspicious hostPath mounts (`/var/run/docker.sock`). | `action in ["CreatePod", "ExecPod"]`, `description`, `target_resource` | `test_all_16_detectors.py::test_detector_c10_container_k8s` | **VERIFIED WORKING**; inspects pod manifests. | Med | **Member 4** |
| **C11: Application BOLA & SSRF** | `detectors/bola_ssrf.py` | Detects server-side request forgery targeting internal metadata services (`169.254.169.254`) and parameter ID tampering. | `network.dst_ip == "169.254.169.254"`, `description`, `action="HTTP_GET"` | `test_all_16_detectors.py::test_detector_c11_bola_ssrf` | **VERIFIED WORKING**; catches cloud IMDS probes. | Med | **Member 3** |
| **C12: Malware & Ransomware** | `detectors/malware_ransomware.py` | Detects ransomware precursor activity, shadow copy deletion (`vssadmin delete shadows`), and mass file renaming. | `action="CommandExecute"`, `description`, Wazuh malware rule IDs | `test_all_16_detectors.py::test_detector_c12_malware_ransomware` | **VERIFIED WORKING**; detects evasion and shadow copy wiping. | Med | **Member 4** |
| **C13: Database Attacks** | `detectors/database_attacks.py` | Detects SQL injection payloads (`UNION SELECT`, `' OR 1=1`), bulk table dumping, and unauthorized schema drops. | `action="Query"`, `description`, `service in ["rds", "postgres", "mysql"]` | `test_all_16_detectors.py::test_detector_c13_database_attacks` | **VERIFIED WORKING**; regex pattern & SQL keyword parsing. | Med | **Member 3** |
| **C14: Serverless Abuse** | `detectors/serverless_abuse.py` | Detects unauthorized runtime package tampering (`UpdateFunctionCode`) outside CI/CD pipelines and concurrency exhaustion. | `service="lambda"`, `action in ["UpdateFunctionCode", "PutFunctionConcurrency"]` | `test_all_16_detectors.py::test_detector_c14_serverless_abuse` | **VERIFIED WORKING**; monitors serverless function modifications. | Med | **Member 3** |
| **C15: Supply Chain** | `detectors/supply_chain.py` | Detects container image tag overwrites in production repositories (`PutImage`) and dependency manifest hijacking. | `service="ecr"`, `action in ["PutImage", "UploadLayerPart"]`, `target_resource` | `test_all_16_detectors.py::test_detector_c15_supply_chain` | **VERIFIED WORKING**; flags tag mutation. | Med | **Member 4** |
| **C16: Defense Tampering** | `detectors/defense_tampering.py` | Detects impairment of security telemetry and logging infrastructure (`StopLogging`, `DeleteTrail`, `DeleteFlowLogs`). | `service in ["cloudtrail", "guardduty", "waf"]`, `action in ["StopLogging", "DeleteTrail"]` | `test_all_16_detectors.py::test_detector_c16_defense_tampering` | **VERIFIED WORKING**; high confidence alert generation. | Low | **Member 1** |

---

## 4. Workstream 1 — Member 1 (Identity & Access Foundation)

### M1-01: Authentication & Endpoint Access Control Enforcement
* **Status:** **VERIFIED COMPLETED**
* **Delivered:** Enforced `_require_permission` across sensitive backend routes in `backend/main.py`. Restricted `POST /api/auth/register` to authenticated administrators with `users:manage` permissions. Public routes preserved for health checks and Swagger UI.
* **Evidence:** `backend/tests/test_auth_enforcement.py` (4 passed, exit code 0).

### M1-02: Cryptographic Password Hashing & JWT Hardening
* **Status:** **VERIFIED COMPLETED**
* **Delivered:** Upgraded `backend/engines/auth_engine.py` to use `bcrypt` (12 rounds) with individual salts. Added transparent upgrade for legacy SHA-256 hashes upon successful authentication. Seeded default demo accounts with valid bcrypt hashes. Connected Axios Bearer token interceptor in `frontend/src/App.jsx`.
* **Evidence:** Verified admin hash prefix `$2b$12$` and login success (exit code 0).

### M1-03: Cloud Infrastructure Entitlement Management (CIEM)
* **Status:** **VERIFIED COMPLETED**
* **Delivered:** Implemented IAM risk scoring, excessive permission scans, and dormant credential tracking in `backend/engines/ciem_engine.py`.
* **Evidence:** Passes CIEM validation routines and integration tests.

### M1-04: Identity Detectors (C1, C2, C3, C16)
* **Status:** **VERIFIED COMPLETED**
* **Delivered:** Completed sliding-window brute force detection, multi-region IP anomaly ATO detection, IAM privilege policy attachment detection, and security logging tamper detection.
* **Evidence:** `backend/tests/test_all_16_detectors.py` (C1, C2, C3, C16 passed).

---

## 5. Workstream 2 — Member 2 (Network Attacks & Machine Learning Pipeline)

### M2-01: 9-Dimensional Operational Flow Feature Extraction
* **Status:** **VERIFIED COMPLETED**
* **Delivered:** Implemented `extract_features()`, `extract_feature_matrix()`, and `validate_feature_vector()` in `backend/engines/feature_extractor.py`. Schema contains 9 non-leaking, RFC/IEEE-standard operational network flow dimensions (`duration`, `src_bytes`, `dst_bytes`, `count`, `srv_count`, `serror_rate`, `rerror_rate`, `same_srv_rate`, `diff_srv_rate`).
* **Evidence:** Unit tests verifying vector bounds and zero target leakage.

### M2-02: Cloud-Native Audit Telemetry Extraction (8D)
* **Status:** **VERIFIED COMPLETED**
* **Delivered:** Implemented `extract_cloud_features()`, `extract_cloud_feature_matrix()`, and `validate_cloud_feature_vector()` in `backend/engines/feature_extractor.py`. Provides 8 behavioral dimensions for cloud audit events without synthetic target leakage.
* **Evidence:** `backend/tests/test_cloud_feature_extractor.py` (4 passed, exit code 0).

### M2-03: Multi-Model Unsupervised Anomaly Detection (PyOD)
* **Status:** **VERIFIED COMPLETED**
* **Delivered:** Trained Isolation Forest ($F_1 = 78.74\%$), Histogram-Based Outlier Score ($F_1 = 69.47\%$), and k-Nearest Neighbors ($F_1 = 74.23\%$) on 125,973 NSL-KDD benchmark flow records, evaluated against held-out KDDTest+ ($N = 22,544$).
* **Evidence:** `backend/train_model.py` and `backend/models/training_meta.json`.

### M2-04: Real-Time ML Engine Dual-Lens Scoring
* **Status:** **VERIFIED COMPLETED**
* **Delivered:** Implemented `backend/engines/ml_engine.py` providing dual-lens threat scoring: $\text{Score} = \max(\text{Flow\_Score}, \text{Cloud\_Behavior\_Score})$ with standardized percentile severity mapping (Low, Medium, High, Critical).
* **Evidence:** `backend/tests/test_ml_cloud_native_integration.py` (4 passed, exit code 0).

### M2-05: Network Attack Detectors (C6, C7, C8, C9)
* **Status:** **VERIFIED COMPLETED**
* **Delivered:** Completed C6 Data Exfiltration ($>500\text{ MB}$ volume checks), C7 Network Scanning (`diff_srv_rate \ge 0.65`, port sweeps), C8 DDoS (`count \ge 150`, SYN flood `serror_rate \ge 0.75`), and C9 Cryptomining (Stratum mining ports 3333/4444/8333, `xmrig`/`minerd` process matches).
* **Evidence:** `backend/tests/test_all_16_detectors.py` (C6, C7, C8, C9 passed).

### M2-06: Model Comparison & Benchmark UI
* **Status:** **VERIFIED COMPLETED**
* **Delivered:** Connected `frontend/src/components/MLComparisonTab.jsx` to live `/ml/compare` and `/ml/info` endpoints, rendering Recharts bar charts and confusion matrix statistics.

---

## 6. Workstream 3 — Member 3 (API Attacks, Correlation & Risk Engine)

### M3-01: Multi-Signal Incident Correlation Engine
* **Status:** **VERIFIED COMPLETED**
* **Delivered:** Implemented `backend/engines/correlation_engine.py` with 900-second temporal sliding window, entity graph linking (`principal`, `source_ip`, `target_resource`), anti-bridging constraints, and MITRE ATT&CK kill-chain progression (Recon $\to$ Initial Access $\to$ Privilege Escalation $\to$ Defense Evasion $\to$ Exfiltration $\to$ Impact).
* **Evidence:** `backend/tests/test_correlation_engine.py` passes with zero synthetic leakage.

### M3-02: Unified Composite Risk Engine
* **Status:** **VERIFIED COMPLETED**
* **Delivered:** Implemented 4-pillar risk calculation in `backend/engines/risk_engine.py`:
  $$\text{Composite Risk} = 0.35 \times \text{Incident Risk} + 0.25 \times \text{ML Anomaly} + 0.20 \times \text{CSPM Risk} + 0.20 \times \text{CIEM Risk}$$
  Includes severity weighting, blast radius multipliers, and exponential temporal decay.
* **Evidence:** Verified 0-100 normalized risk score output.

### M3-03: Attack Simulator & Scenario Injection
* **Status:** **VERIFIED COMPLETED**
* **Delivered:** Implemented `backend/simulator/attack_simulator.py` and `backend/simulator/session_manager.py` capable of simulating multi-stage attack scenarios across all 16 threat categories.
* **Evidence:** Interactive simulation playback verified via `frontend/src/components/AttackSimulationTab.jsx`.

### M3-04: API & Workload Abuse Detectors (C4, C11, C13, C14)
* **Status:** **VERIFIED COMPLETED**
* **Delivered:** Implemented C4 Suspicious API Activity (enumeration bursts), C11 BOLA/SSRF (IMDS `169.254.169.254` probes), C13 Database Threats (SQLi patterns, mass dumps), and C14 Serverless Abuse (`UpdateFunctionCode`, concurrency exhaustion).
* **Evidence:** `backend/tests/test_all_16_detectors.py` (C4, C11, C13, C14 passed).

---

## 7. Workstream 4 — Member 4 (Cloud Posture, Vulnerability & Remediation)

### M4-01: Cloud Security Posture Management (CSPM)
* **Status:** **VERIFIED COMPLETED**
* **Delivered:** Implemented CIS AWS Foundations Benchmark checks in `backend/engines/cspm_engine.py` (public S3 buckets, open security group ingress ports 22/3389, unencrypted RDS instances).
* **Evidence:** Live posture scoring and check catalog verified.

### M4-02: Workload Vulnerability Engine (CVE/CVSS)
* **Status:** **VERIFIED COMPLETED**
* **Delivered:** Implemented `backend/engines/vulnerability_engine.py` with local curated CVE advisory database, semver parsing via `packaging.version`, and CVSS v3.1 severity scoring.
* **Evidence:** `backend/tests/test_vulnerability_engine_deep.py` passed with verified CVE matching.

### M4-03: Automated Remediation Engine with Durable Rollback
* **Status:** **VERIFIED COMPLETED**
* **Delivered:** Implemented playbook execution with safe dry-run mode, durable execution tracking in SQLite `remediation_history` table (`backend/engines/db.py`), and idempotent rollback surviving server reboots.
* **Evidence:** Python test verifying durable rollback across complete in-memory wipe passed.

### M4-04: Compliance Engine & Regulatory Mapping
* **Status:** **VERIFIED COMPLETED**
* **Delivered:** Implemented compliance mapping in `backend/engines/compliance_engine.py` across ISO 27001:2022, SOC 2 Type II, and GDPR, with historical snapshot trends persisted in SQLite.
* **Evidence:** Verified historical snapshot deltas in compliance dashboard.

### M4-05: Infrastructure Detectors (C5, C10, C12, C15)
* **Status:** **VERIFIED COMPLETED**
* **Delivered:** Implemented C5 Cloud Misconfiguration, C10 Container & Kubernetes Breakout (`/var/run/docker.sock`), C12 Malware/Ransomware precursor (`vssadmin delete shadows`), and C15 Supply Chain container image tag overwrite.
* **Evidence:** `backend/tests/test_all_16_detectors.py` (C5, C10, C12, C15 passed).

---

## 8. SRS Functional Requirements Matrix (FR-01 to FR-12)

| Requirement | Description | Current Architecture Status | Evidence / Verification Method | Remaining Work | Assigned Owner |
| :--- | :--- | :---: | :--- | :--- | :---: |
| **FR-01** | Cloud Resource Discovery | **PARTIALLY IMPLEMENTED** | Discovers emulated S3/IAM when LocalStack runs; falls back to static catalog. | Add local workload process/port discovery in `asset_engine.py`. | **Member 4** |
| **FR-02** | Workload Monitoring | **VERIFIED WORKING** | Reads Wazuh `/var/ossec/logs/alerts/alerts.json` with fallback to `wazuh_simulator.py`. | Maintain live Wazuh and synthetic buffer compatibility. | **Member 1** |
| **FR-03** | IAM Assessment | **VERIFIED WORKING** | Scans excessive permissions, dormant keys, and root MFA in `ciem_engine.py`. | Add live LocalStack IAM policy evaluation. | **Member 1** |
| **FR-04** | Misconfiguration Detection | **VERIFIED WORKING** | Scans public S3, open SG ports 22/3389, and RDS unencrypted in `cspm_engine.py`. | Integrate with detector C5 for real-time drift alerts. | **Member 4** |
| **FR-05** | Vulnerability Analysis | **VERIFIED WORKING** | `vulnerability_engine.py` scans `requirements.txt` and packages against CVE database with CVSS v3.1 scoring. | Expose interactive scan trigger in UI dashboard. | **Member 4** |
| **FR-06** | Event Monitoring & Normalization | **VERIFIED WORKING** | `schemas/event.py` normalizes heterogeneous logs into validated Pydantic events. | Verified via `test_schemas_and_foundation.py`. | **Shared** |
| **FR-07** | Threat Detection | **VERIFIED WORKING** | All 16 modular attack detectors implemented in `engines/detectors/` and verified. | ML score calibration. | **All Members** |
| **FR-08** | Correlation & Risk Scoring | **VERIFIED WORKING** | `correlation_engine.py` groups findings into incidents; `risk_engine.py` calculates composite 0-100 score. | Multi-stage MITRE kill-chain progression verified. | **Member 3** |
| **FR-09** | Automated Response | **VERIFIED WORKING** | `remediation_engine.py` executes step-by-step playbooks with safe dry-run mode. | Connect LocalStack Boto3 execution actions. | **Member 4** |
| **FR-10** | Remediation & Rollback | **VERIFIED WORKING** | Rollback restores findings to `open`; survives backend reboots via SQLite `remediation_history`. | Verified via memory-wipe execution test. | **Member 4** |
| **FR-11** | Incident & Audit Logging | **VERIFIED WORKING** | Persists findings, incidents, and scan logs to SQLite WAL database (`security.db`). | All events persisted with UTC timestamps. | **Shared** |
| **FR-12** | Reporting & Visualization | **VERIFIED WORKING** | `compliance_engine.py` outputs JSON/CSV reports; trend deltas computed from SQLite snapshots. | Render live evidence in frontend drawers. | **Member 4** |
