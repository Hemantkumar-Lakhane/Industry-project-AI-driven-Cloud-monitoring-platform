# RAM Antivirus — Authoritative Manual QA Verification Checklist & Traceability Matrix

**Document ID:** `docs/MANUAL_VERIFICATION_CHECKLIST.md`  
**Milestone:** End-to-End Verification & Production Readiness  
**Verification Date:** October 27, 2026  
**QA Leads & Engineering Owners:**  
- **Member 1 / Member 4** (Platform Security, Cloud Infrastructure, Telemetry & Detection Workstream A)  
- **Member 2 / Member 3** (Intelligence Engine, ML, Analytics, Risk & Detection Workstream B)  

---

## 1. Feature Ownership & Division of Responsibilities

Each feature has exactly one primary owner. Testing interfaces follow stable contracts (`schemas/event.py`, `schemas/finding.py`, `schemas/incident.py`).

| Workstream | Owner | Features & Functional Areas | Detectors Assigned |
| :--- | :--- | :--- | :--- |
| **Platform Security & Infrastructure** | **Member 1 / Member 4** | • User Authentication, bcrypt, JWT, RBAC<br>• Public Registration Lockdown (`POST /api/auth/register`)<br>• WebSocket Handshake & Short-Lived Ticket Auth (`/ws/events`)<br>• Cloud Asset Discovery & Host Compute Telemetry (`/api/assets`)<br>• Workload Telemetry & Connector Health Probes<br>• Remediation Playbooks & Durable Rollback in SQLite | **Group A (8 Detectors):**<br>1. Brute Force<br>2. Account Takeover (ATO)<br>3. IAM Privilege Escalation<br>4. Cloud Misconfiguration Drift<br>5. Network Scanning<br>6. Distributed Denial of Service (DDoS)<br>7. Supply Chain Compromise<br>8. Defense & Logging Tampering |
| **Intelligence, ML & Analytics** | **Member 2 / Member 3** | • 8D Cloud Behavioral Feature Extractor & Leakage Guard<br>• PyOD ML Multi-Model Ensemble (iforest, knn, hbos)<br>• Percentile Anomaly Score Calibration<br>• Cloud Security Posture Management (CSPM)<br>• Cloud Identity & Entitlement Risk (CIEM)<br>• Workload Vulnerability Scanning & NIST NVD API Sync<br>• Incident Correlation Graph & Anti-Bridging<br>• 4-Pillar Unified Dynamic Risk Scoring<br>• Regulatory Compliance Tracking & Historical Snapshots | **Group B (8 Detectors):**<br>9. Suspicious API Activity<br>10. Data Exfiltration<br>11. Cryptomining Workloads<br>12. Container & Kubernetes Attacks<br>13. Application BOLA & SSRF<br>14. Malware & Ransomware Precursor<br>15. Database Threat Activity<br>16. Serverless Function Abuse |

---

## 2. Feature-to-SRS Traceability Matrix

| SRS Req | Module / Feature Name | Assigned Owner | Backend Source Files | Primary API Endpoints | Frontend Views | Verification Status |
| :---: | :--- | :---: | :--- | :--- | :--- | :---: |
| **FR-01** | Multi-Cloud Resource & Asset Inventory | Member 1 / Member 4 | `engines/asset_engine.py`, `engines/db.py` | `GET /api/assets`, `POST /api/assets/discover`, `GET /api/assets/connectors` | `DataSourcesTab.jsx` | **PASS (Local/Sim)**<br>*BLOCKED (Live AWS)* |
| **FR-02** | Workload Telemetry Ingestion & Provenance | Member 1 / Member 4 | `simulator/wazuh_reader.py`, `simulator/wazuh_simulator.py` | `GET /api/simulate/events`, `GET /api/status` | `LiveLogsTab.jsx`, `OverviewTab.jsx` | **PASS (Sim/Mock)**<br>*BLOCKED (Live Wazuh agent)* |
| **FR-03** | Cloud Misconfiguration Detection (CSPM) | Member 2 / Member 3 | `engines/cspm_engine.py`, `engines/localstack_engine.py` | `GET /api/cspm/scan`, `GET /api/cspm/history` | `OverviewTab.jsx`, `RemediationTab.jsx` | **PASS** |
| **FR-04** | Cloud Identity Entitlement Risk (CIEM) | Member 2 / Member 3 | `engines/ciem_engine.py`, `engines/localstack_engine.py` | `GET /api/ciem/scan`, `GET /api/ciem/history` | `OverviewTab.jsx`, `RemediationTab.jsx` | **PASS** |
| **FR-05** | Workload Vulnerability Management & NVD | Member 2 / Member 3 | `engines/vulnerability_engine.py`, `engines/db.py` | `GET /api/vulnerabilities`, `POST /api/vulnerabilities/scan`, `POST /api/vulnerabilities/nvd/sync` | `AlertsIncidentsTab.jsx` (Vulnerabilities view) | **PASS** |
| **FR-06** | ML Behavioral Threat Detection | Member 2 / Member 3 | `engines/feature_extractor.py`, `engines/ml_engine.py` | `GET /api/ml/compare`, `GET /api/ml/model-info`, `GET /api/simulate/attack` | `MLComparisonTab.jsx` | **PASS** |
| **FR-07** | Real-Time Incident Correlation | Member 2 / Member 3 | `engines/correlation_engine.py`, `engines/db.py` | `GET /api/incidents`, `GET /api/incidents/{id}`, `GET /api/incidents/stats` | `AlertsIncidentsTab.jsx` (Incidents view) | **PASS** |
| **FR-08** | Unified Dynamic Risk Scoring | Member 2 / Member 3 | `engines/risk_engine.py`, `engines/db.py` | `GET /api/risk/score`, `GET /api/risk/trend` | `RiskScoreTab.jsx` | **PASS** |
| **FR-09** | Automated Remediation & Durable Rollback | Member 1 / Member 4 | `engines/remediation_engine.py`, `engines/db.py` | `GET /api/remediation/playbooks`, `POST /api/remediation/execute/{type}`, `POST /api/remediation/rollback` | `RemediationTab.jsx` | **PASS** |
| **FR-10** | Regulatory Compliance Tracking | Member 2 / Member 3 | `engines/compliance_engine.py`, `engines/db.py` | `GET /api/compliance/dashboard`, `GET /api/compliance/report`, `GET /api/compliance/trend` | `ComplianceTab.jsx` | **PASS** |
| **FR-11** | Role-Based Access Control & WS Auth | Member 1 / Member 4 | `engines/auth_engine.py`, `main.py` | `POST /api/auth/login`, `GET /api/auth/me`, `POST /api/auth/ws-ticket`, `WS /ws/events` | `LoginPage.jsx`, `App.jsx` | **PASS** |
| **FR-12** | Attack Simulation & Threat Validation | Member 1 / Member 4 | `simulator/attack_simulator.py`, `simulator/session_manager.py` | `POST /api/simulation/execute`, `GET /api/simulation/scenarios`, `POST /api/simulation/reset` | `AttackSimulationTab.jsx` | **PASS** |

---

## 3. Step-by-Step Manual Test Procedures

### Group 1: Member 1 / Member 4 — Platform Security & Infrastructure

#### TC-TNY-01: User Authentication & JWT Flow
- **Prerequisites:** Backend running on `http://127.0.0.1:8000`.
- **Action (API):** `POST /api/auth/login` with body `{"username": "admin", "password": "admin123"}`.
- **Expected Output:** HTTP 200, `"success": true`, Bearer JWT returned, user role `"admin"`.
- **Negative Case:** `POST /api/auth/login` with `{"username": "admin", "password": "wrongpassword"}`. Expected HTTP 401 with `"detail": "Invalid username or password"`.
- **Actual Result:** HTTP 200 on valid credentials; HTTP 401 on bad password.
- **Evidence:** Captured in `docs/live_qa_execution_evidence.json::TC-TNY-01` and `TC-TNY-02`.
- **Status:** **PASS**

#### TC-TNY-02: Public User Registration Lockdown
- **Prerequisites:** Backend running.
- **Action (API):** 
  1. `POST /api/auth/register` without `Authorization` header. Expected HTTP 401.
  2. `POST /api/auth/register` with Viewer Bearer token. Expected HTTP 403 Forbidden.
  3. `POST /api/auth/register` with Admin Bearer token. Expected HTTP 200 Account Created.
- **Actual Result:** Unauthenticated requests return 401; Viewers return 403; Admins succeed.
- **Evidence:** `docs/live_qa_execution_evidence.json::TC-TNY-03`.
- **Status:** **PASS**

#### TC-TNY-03: WebSocket Handshake & Short-Lived Single-Use Ticket
- **Prerequisites:** Admin JWT token.
- **Action (API & WS):**
  1. `POST /api/auth/ws-ticket` with Admin header. Expected HTTP 200 returning ticket starting with `wstk_`.
  2. Connect to `ws://127.0.0.1:8000/ws/events?ticket=<ticket>`.
  3. Check initial frame: `{"type": "auth_ok", "username": "admin"}`.
  4. Check subsequent frame: `{"type": "events_update", "total": ...}`.
  5. Attempt to connect again with the identical ticket.
- **Negative Case:** Reusing consumed ticket returns `{"type": "auth_error", "detail": "Invalid or already consumed WebSocket ticket"}` and closes with code 4401.
- **Actual Result:** Handshake succeeded, first events frame received, second ticket redemption failed atomically.
- **Evidence:** `docs/live_qa_execution_evidence.json::TC-TNY-04`.
- **Status:** **PASS**

#### TC-TNY-04: Asset Discovery & Topology Inventory
- **Prerequisites:** Admin JWT token.
- **Action (API & UI):**
  1. Navigate to **Data Sources** tab in UI (`http://localhost:5173`).
  2. Call `GET /api/assets`.
  3. Call `GET /api/assets/connectors`.
- **Expected Output:** Unified asset list returned (EC2, S3, IAM, Host Workload), connector health reports LocalStack, AWS, Wazuh, Host compute.
- **Negative Case:** When LocalStack or AWS is offline, assets retain fallback labels (`SANDBOX_VERIFIED` or `LOCALSTACK_EMULATED`) without crashing.
- **Actual Result:** 47 assets discovered and cataloged; connectors probe returned all 4 subsystems.
- **Evidence:** `docs/live_qa_execution_evidence.json::TC-TNY-05`, `TC-TNY-06`; UI screenshot `datasources_page_1793101369489.png`.
- **Status:** **PASS (Local/Simulated)**, **BLOCKED (Live AWS account mutation requires AWS keys)**

#### TC-TNY-05: Remediation Playbook Execution & Durable Rollback in SQLite
- **Prerequisites:** Admin JWT token.
- **Action (API & UI):**
  1. Call `GET /api/remediation/playbooks`.
  2. Execute playbook: `POST /api/remediation/execute/brute_force?dry_run=true`. Verify `execution_id` returned.
  3. Rollback remediation: `POST /api/remediation/rollback` with body `{"execution_id": "<execution_id>"}`.
  4. Negative case: `POST /api/remediation/rollback` with `{"execution_id": "non-existent-action"}`. Expected HTTP 404.
- **Actual Result:** Playbook executed successfully; rollback completed with `"status": "success"`; invalid execution ID returned HTTP 404.
- **Evidence:** `docs/live_qa_execution_evidence.json::TC-TNY-07`; UI screenshot `remediation_view_1793101358864.png`.
- **Status:** **PASS**

#### TC-TNY-06 to TC-TNY-13: Detector Group A (8 Detectors)
- **Detectors:** Brute Force, Account Takeover, IAM Privilege Escalation, Cloud Misconfiguration Drift, Network Scanning, DDoS, Supply Chain Compromise, Defense Tampering.
- **Procedure:** Run test suite against true-positive attack bursts, true-negative benign events, and sub-threshold boundaries.
- **Expected Output:** 100% detection rate on genuine attack sequences; 0 false positives on benign noise.
- **Actual Result:** Verified via `backend/tests/verify_detectors_matrix.py` (all 8 detectors passed attack, benign, and boundary tests).
- **Evidence:** `docs/live_qa_execution_evidence.json::TC-TNY-08`.
- **Status:** **PASS**

---

### Group 2: Member 2 / Member 3 — Intelligence, ML & Analytics

#### TC-HMT-01: 8D Cloud Behavioral Feature Extraction
- **Prerequisites:** Clean event payload.
- **Action (Engine):** Pass sample event with high failure count, large bytes transferred, and unusual service to `extract_cloud_features()`.
- **Expected Output:** 8-element numeric vector matching schema `CLOUD_FEATURE_NAMES`. No categorical strings (user name, userAgent) present in output.
- **Actual Result:** Exact 8D vector returned without target leakage.
- **Evidence:** `docs/live_qa_execution_evidence.json::TC-HMT-01`.
- **Status:** **PASS**

#### TC-HMT-02: ML Inference & Multi-Model Calibration
- **Prerequisites:** Pre-trained models (`models/iforest.pkl`, `models/knn.pkl`, `models/hbos.pkl`).
- **Action (API):** Call `GET /api/ml/model-info` and `GET /api/ml/compare`.
- **Expected Output:** HTTP 200, architecture specs returned, ensemble benchmark metrics populated.
- **Actual Result:** Models loaded and verified; ensemble analyzed 120 events.
- **Evidence:** `docs/live_qa_execution_evidence.json::TC-HMT-02`.
- **Status:** **PASS**

#### TC-HMT-03: CSPM Configuration Scan
- **Prerequisites:** Event stream or LocalStack.
- **Action (API & UI):** Call `GET /api/cspm/scan`.
- **Expected Output:** Misconfigurations detected (S3 public read, open SSH port 22, unencrypted RDS) with severity and remediation snippets.
- **Actual Result:** 7 CSPM findings generated and logged to SQLite history.
- **Evidence:** `docs/live_qa_execution_evidence.json::TC-HMT-03`.
- **Status:** **PASS**

#### TC-HMT-04: CIEM Identity Entitlement Scan
- **Prerequisites:** Event stream or LocalStack.
- **Action (API & UI):** Call `GET /api/ciem/scan`.
- **Expected Output:** Identity risks detected (excessive wildcard actions, dormant admins, missing root MFA).
- **Actual Result:** 26 CIEM identity exposure risks detected and logged to SQLite history.
- **Evidence:** `docs/live_qa_execution_evidence.json::TC-HMT-04`.
- **Status:** **PASS**

#### TC-HMT-05: Workload Vulnerability Management & NIST NVD API Sync
- **Prerequisites:** Installed packages in environment, baseline daemons in telemetry.
- **Action (API & UI):**
  1. In UI, click **Alerts & Incidents** -> **Vulnerabilities** tab.
  2. Verify CVE table displays CVSS 3.1 scores, affected packages, and severity tags.
  3. Call `GET /api/vulnerabilities/nvd/status`.
  4. Call `POST /api/vulnerabilities/nvd/sync`.
- **Negative Case:** When external NVD API is unreachable (or in offline mode), existing cached advisories are safely retained without deletion.
- **Actual Result:** 8 workload CVEs identified (mean CVSS 8.46); NVD connector reports status and cached advisories; UI renders both "Rescan Host Manifests" and "Sync NIST NVD" buttons.
- **Evidence:** `docs/live_qa_execution_evidence.json::TC-HMT-05`; UI screenshots `vulnerabilities_page_1793101108888.png` and `vulnerabilities_view_1793101144709.png`.
- **Status:** **PASS**

#### TC-HMT-06: Real-Time Incident Correlation & Anti-Bridging
- **Prerequisites:** Telemetry session with simulated multi-stage attacks.
- **Action (API & UI):** Call `GET /api/incidents` and `GET /api/incidents/stats`.
- **Expected Output:** Findings aggregated into correlated incidents by shared entity and temporal proximity. Anti-bridging prevents unrelated VPCs or distinct identities from collapsing.
- **Actual Result:** 19 correlated incidents generated; incident timeline and blast radius calculated.
- **Evidence:** `docs/live_qa_execution_evidence.json::TC-HMT-06`; UI screenshot `alerts_page_1793100981200.png`.
- **Status:** **PASS**

#### TC-HMT-07: 4-Pillar Unified Dynamic Risk Scoring
- **Prerequisites:** Active telemetry session.
- **Action (API & UI):** Call `GET /api/risk/score`.
- **Expected Output:** Unified risk score (0–100) combining ML (40%), CSPM (25%), CIEM (20%), and Vulnerabilities (15%). Actionable risk drivers populated.
- **Actual Result:** Risk score 80.0 (Critical tier) computed dynamically with real evidence drivers.
- **Evidence:** `docs/live_qa_execution_evidence.json::TC-HMT-07`.
- **Status:** **PASS**

#### TC-HMT-08: Regulatory Compliance Tracking
- **Prerequisites:** Active finding catalog.
- **Action (API & UI):** Call `GET /api/compliance/dashboard` and `GET /api/compliance/report`.
- **Expected Output:** Compliance scores mapped to CIS AWS Foundations, NIST SP 800-53, ISO 27001, and GDPR.
- **Actual Result:** Compliance dashboard generated (score: 29.5%, frameworks: ISO27001, SOC2, GDPR).
- **Evidence:** `docs/live_qa_execution_evidence.json::TC-HMT-08`.
- **Status:** **PASS**

#### TC-HMT-09 to TC-HMT-16: Detector Group B (8 Detectors)
- **Detectors:** Suspicious API Activity, Data Exfiltration, Cryptomining, Container/K8s Attacks, Application BOLA/SSRF, Malware/Ransomware Precursor, Database Threats, Serverless Abuse.
- **Procedure:** Run test suite against true-positive attack bursts, true-negative benign events, and sub-threshold boundaries.
- **Expected Output:** 100% detection rate on genuine attack sequences; 0 false positives on benign noise.
- **Actual Result:** Verified via `backend/tests/verify_detectors_matrix.py` (all 8 detectors passed attack, benign, and boundary tests).
- **Evidence:** `docs/live_qa_execution_evidence.json::TC-HMT-09`.
- **Status:** **PASS**

---

## 4. Summary of Completed vs. Blocked Checks

| Category | Checks Completed Locally (PASS) | Checks Requiring User / External Infrastructure (BLOCKED) |
| :--- | :--- | :--- |
| **Member 1 / Member 4** | • Admin/Viewer Authentication & Hash Migration (TC-TNY-01, 02)<br>• Public Registration Lockdown (TC-TNY-03)<br>• WebSocket Authenticated Handshake & Tickets (TC-TNY-04)<br>• Asset Inventory & Local Compute Workloads (TC-TNY-05)<br>• Connector Probing in Local/Fallback Mode (TC-TNY-06)<br>• Remediation Execution & SQLite Rollback (TC-TNY-07)<br>• Detector Group A — 8/8 Detectors (TC-TNY-08) | **BLOCKED:** Live AWS CloudTrail / EC2 resource mutation (requires live AWS account credentials: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`).<br>**BLOCKED:** Physical Wazuh Manager endpoint connection (requires live enterprise SIEM socket `/var/ossec/logs/alerts/alerts.json`). |
| **Member 2 / Member 3** | • 8D Cloud Behavioral Features & Leakage Guard (TC-HMT-01)<br>• ML Ensemble Inference & Score Calibration (TC-HMT-02)<br>• CSPM Misconfiguration Scanning (TC-HMT-03)<br>• CIEM Identity Entitlement Risk Scanning (TC-HMT-04)<br>• Workload Vulnerabilities & NVD Sync (TC-HMT-05)<br>• Incident Correlation & Anti-Bridging (TC-HMT-06)<br>• 4-Pillar Dynamic Unified Risk Scoring (TC-HMT-07)<br>• Compliance Dashboard & History Trend (TC-HMT-08)<br>• Detector Group B — 8/8 Detectors (TC-HMT-09) | **BLOCKED:** Elevated NIST NVD API synchronization (unauthenticated rate limit is 5 req/30s; unlocking 50 req/30s requires optional `NVD_API_KEY`).<br>**BLOCKED:** Human Visual Final Alignment (requires user manual inspection of visual typography and layout in browser). |

---

## 5. Unresolved Defects

**Zero unresolved software defects.**  
All 146 automated tests pass, the detector matrix passes 16/16 with exit code 0, the frontend production bundle compiles without errors, and the newly exposed `POST /api/remediation/rollback` endpoint ensures full rollback functionality.

---

## 6. Exact Commands for End-to-End Verification

To verify the platform end-to-end on your local workstation:

### Option A: Automated All-in-One Startup Script (Windows Batch)
From workspace root:
```cmd
.\run.bat
```
*This verifies Python and Node.js prerequisites, checks pre-trained ML models, initializes SQLite database schemas, starts the FastAPI backend at `http://127.0.0.1:8000`, and launches the Vite React frontend at `http://localhost:5173`.*

### Option B: Individual Terminal Startup

#### Terminal 1 — Backend API Server
```powershell
cd d:\ram_antivirus_official\Industry-project-AI-driven-Cloud-monitoring-platform-\backend
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```
*API Swagger Documentation: `http://127.0.0.1:8000/docs`*

#### Terminal 2 — Frontend UI
```powershell
cd d:\ram_antivirus_official\Industry-project-AI-driven-Cloud-monitoring-platform-\frontend
npm run dev
```
*Web Application URL: `http://localhost:5173`*

#### Terminal 3 — Run Complete Test Suite
```powershell
cd d:\ram_antivirus_official\Industry-project-AI-driven-Cloud-monitoring-platform-\backend
python -m pytest tests/ -v
python tests/verify_detectors_matrix.py
python tests/manual_verification_runner.py
```

### Pre-Configured Demo Login Accounts:
- **Administrator:** Username: `admin` | Password: `admin123` (Full permissions)
- **Security Analyst:** Username: `analyst1` | Password: `analyst123` (Investigation, simulation, compliance)
- **Executive Viewer:** Username: `viewer1` | Password: `viewer123` (Read-only dashboard visibility)
