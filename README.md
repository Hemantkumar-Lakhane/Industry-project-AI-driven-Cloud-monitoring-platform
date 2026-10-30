# Cloud Security AI Platform

### Enterprise Multi-Layer Threat Detection, Machine Learning Analytics & Automated Remediation

---

## Authoritative Project Documentation

* **Current Verified State:** [`docs/PROJECT_BASELINE.md`](file:///d:/ram_antivirus_official/Industry-project-AI-driven-Cloud-monitoring-platform-/docs/PROJECT_BASELINE.md)
* **Team Work Distribution (4 Members):** [`docs/WORK_DISTRIBUTION.md`](file:///d:/ram_antivirus_official/Industry-project-AI-driven-Cloud-monitoring-platform-/docs/WORK_DISTRIBUTION.md)
* **SRS Implementation Status (FR-01 to FR-12):** [`docs/SRS_IMPLEMENTATION_STATUS.md`](file:///d:/ram_antivirus_official/Industry-project-AI-driven-Cloud-monitoring-platform-/docs/SRS_IMPLEMENTATION_STATUS.md)
* **Security & Vulnerability Review:** [`docs/SECURITY_REVIEW.md`](file:///d:/ram_antivirus_official/Industry-project-AI-driven-Cloud-monitoring-platform-/docs/SECURITY_REVIEW.md)
* **Attack Detector Matrix (16 Detectors):** [`docs/DETECTOR_MATRIX.md`](file:///d:/ram_antivirus_official/Industry-project-AI-driven-Cloud-monitoring-platform-/docs/DETECTOR_MATRIX.md)
* **Member 2 Network Threat & ML Deep Dive:** [`docs/MEMBER_2_ML_AND_NETWORK_ATTACKS_DEEP_DIVE.md`](file:///d:/ram_antivirus_official/Industry-project-AI-driven-Cloud-monitoring-platform-/docs/MEMBER_2_ML_AND_NETWORK_ATTACKS_DEEP_DIVE.md)
* **Manual QA & Verification Checklist:** [`docs/MANUAL_VERIFICATION_CHECKLIST.md`](file:///d:/ram_antivirus_official/Industry-project-AI-driven-Cloud-monitoring-platform-/docs/MANUAL_VERIFICATION_CHECKLIST.md)
* **Production Jupyter Notebooks (01 to 05):** [`notebooks/`](file:///d:/ram_antivirus_official/Industry-project-AI-driven-Cloud-monitoring-platform-/notebooks/)

---

## What This Project Does

A production-grade cloud security intelligence and automated response platform featuring:

- **16 Modular Attack Detection Engines:** Aligned with MITRE ATT&CK (`DET-BF-01` through `DET-DOS-16`), inspecting Wazuh Linux host agents, CloudTrail API telemetry, and VPC network flows.
- **PyOD ML Anomaly Ensemble:** Isolation Forest, KNN, and HBOS trained on the 9-dimensional IEEE Operational Flow Schema (NSL-KDD benchmark) with zero target leakage.
- **Graph-Based Incident Correlation:** Disjoint Set (Union-Find) clustering over 15-minute sliding windows across principals, IPs, and cloud assets, grouping atomic findings into multi-stage attack campaigns.
- **Explainable AI Remediation Console:** Plain-English root-cause analysis, forensic attribution, safe dry-run simulation, execution rollbacks, and persistent audit logging.
- **Unified 4-Pillar Composite Risk Engine:** Dynamic enterprise risk posture ($0.35 \times \text{Incidents} + 0.25 \times \text{ML} + 0.20 \times \text{CSPM} + 0.20 \times \text{CIEM}$).
- **Compliance Control Mapping:** Automated rules mapping across ISO 27001, SOC 2, and GDPR with exportable reports.
- **Live Observability Stream:** Real-time authenticated WebSocket streaming (`/ws/events`), structured telemetry table, and CloudWatch terminal console.
- **Enterprise UI/UX System:** Datadog / Aikido-inspired low-saturation dark palette with soft pastel status badges.

---

## Project Structure

```
Industry(Ram)/
├── backend/
│   ├── main.py                    ← FastAPI application gateway (RBAC-protected routes)
│   ├── train_model.py             ← PyOD ML ensemble training on 9D flow benchmark
│   ├── requirements.txt
│   ├── security.db                ← SQLite database (findings, incidents, users, audit trail)
│   ├── engines/
│   │   ├── detectors.py           ← 16 discrete MITRE ATT&CK detection engines
│   │   ├── base_detector.py       ← Abstract detector interface & registry
│   │   ├── correlation_engine.py  ← Graph clustering & multi-stage campaign synthesis
│   │   ├── ml_engine.py           ← 9D flow feature extraction & PyOD ensemble scoring
│   │   ├── risk_engine.py         ← Unified 4-pillar risk formula & trend calculations
│   │   ├── remediation_engine.py  ← Automated playbooks, safe dry-runs & rollbacks
│   │   ├── asset_engine.py        ← Workload & cloud asset discovery & inventory
│   │   ├── vulnerability_engine.py← Dependency & CVE advisory matching
│   │   ├── cspm_engine.py         ← Cloud Security Posture Management engine
│   │   ├── ciem_engine.py         ← Cloud Infrastructure Entitlement Management engine
│   │   ├── compliance_engine.py   ← ISO 27001 / SOC 2 / GDPR control evaluations
│   │   ├── alert_engine.py        ← SMTP email alerts
│   │   ├── auth_engine.py         ← Bcrypt password hashing + JWT & RBAC user store
│   │   ├── localstack_engine.py   ← boto3 connector for LocalStack AWS emulation
│   │   └── db.py                  ← SQLite persistence layer & schema migrations
│   ├── simulator/
│   │   ├── session_manager.py     ← Active telemetry session & state coordinator
│   │   ├── attack_simulator.py    ← 16 MITRE ATT&CK adversary scenario generator
│   │   ├── wazuh_reader.py        ← Reads live Linux syslog/alerts.json
│   │   └── log_generator.py       ← Telemetry stream generator
│   ├── models/                    ← Trained PyOD models & metadata
│   │   ├── iforest.pkl            ← Isolation Forest model
│   │   ├── knn.pkl                ← KNN model
│   │   ├── hbos.pkl               ← HBOS model
│   │   ├── scaler_*.pkl           ← StandardScaler feature scalers
│   │   └── training_meta.json     ← Ground-truth evaluation benchmarks
│   └── data/
│       ├── alerts.json            ← Authentic Wazuh SIEM telemetry log stream
│       ├── KDDTrain+.txt          ← NSL-KDD training dataset
│       └── KDDTest+.txt           ← NSL-KDD held-out test split
└── frontend/
    └── src/
        ├── App.jsx                ← Main application shell + WebSocket live stream
        ├── index.css              ← Enterprise design tokens (Figma / Aikido standards)
        ├── config.js              ← Dynamic API & WS endpoint configuration
        └── components/
            ├── OverviewTab.jsx          ← Threat overview, 16 engine matrix & metrics
            ├── AlertsIncidentsTab.jsx   ← Correlated incidents, atomic findings & PDF export
            ├── RemediationTab.jsx       ← Explainable AI console, dry-runs & audit logs
            ├── RiskScoreTab.jsx         ← 4-pillar risk engine, trends & factor inputs
            ├── MLComparisonTab.jsx      ← PyOD benchmark table & comparative metrics chart
            ├── AttackSimulationTab.jsx  ← 1-click adversary emulator
            ├── LiveLogsTab.jsx          ← Telemetry stream & CloudWatch console
            ├── ComplianceTab.jsx        ← ISO 27001 / SOC 2 / GDPR audit dashboard
            ├── UserManagementTab.jsx    ← RBAC user directory & invite modal
            ├── DataSourcesTab.jsx       ← Ingestion connectors & asset discovery
            ├── WorkspaceSettingsTab.jsx ← Threshold & notification parameters
            ├── LoginPage.jsx            ← Secure authenticated login portal
            └── remediation/             ← Explainable AI cards, forensics banner & rollbacks
```

---

## 🐳 Docker & LocalStack AWS Setup (Optional for Emulated Cloud)

RAM Antivirus Cloud Security Platform includes built-in support for **LocalStack** to emulate AWS S3 and IAM resources locally.

> **Note:** If Docker is not running, RAM Antivirus Cloud Security Platform automatically uses its built-in Cloud Policy Audit Engine. Docker is **optional** and not required for normal dashboard operation or cloud deployment (Render).

### Quick 3-Step Launch:
1. **Open Docker Desktop** on Windows.
2. **Start LocalStack Container:**
   ```cmd
   docker run -d --name localstack -p 4566:4566 -e SERVICES=s3,iam localstack/localstack
   ```
3. **Seed Sample S3 & IAM Assets:**
   Double-click `seed_localstack.bat` or run:
   ```cmd
   python backend/seed_localstack.py
   ```

Detailed instructions and troubleshooting are available in [`docs/DOCKER_AND_LOCALSTACK_SETUP.md`](docs/DOCKER_AND_LOCALSTACK_SETUP.md).

## Prerequisites

| Tool    | Version | Download           |
| ------- | ------- | ------------------ |
| Python  | 3.10+   | https://python.org |
| Node.js | 18+     | https://nodejs.org |
| pip     | latest  | comes with Python  |

---

## Quick Start (Windows 1-Click Launch)

You can launch the entire platform with all dependencies checked and all 3 services running simultaneously using the included launcher script:

```cmd
run.bat
```

**What `run.bat` automatically handles:**

1. **Prerequisite Check**: Validates that Python 3.10+ and Node.js 18+ / npm are installed and in your PATH.
2. **Backend Dependencies**: Automatically checks and installs required Python packages (`pip install -r requirements.txt`).
3. **ML Model Verification**: Checks whether trained specialist models (`iforest`, `knn`, `hbos`) exist; automatically runs `train_model.py` if not found.
4. **Frontend Dependencies**: Checks and installs frontend dependencies (`npm install`) if `node_modules` is missing.
5. **Parallel Service Launch**: Spawns 3 dedicated, color-coded terminal windows:
   - **Terminal 1**: Live Wazuh Log Generator (`python simulator/log_generator.py 10`)
   - **Terminal 2**: FastAPI Backend API (`http://localhost:8000`)
   - **Terminal 3**: React Frontend UI via Vite (`http://localhost:5173`)
6. Automatically launches your default web browser to `http://localhost:5173`.

---

## Step 1 — Install Backend Dependencies

```bash
cd backend
pip install -r requirements.txt
```

This installs: FastAPI, PyOD, pandas, numpy, scikit-learn, PyJWT, boto3, websockets.

---

## Step 2 — Train the ML Models (run once)

This downloads the NSL-KDD dataset and trains 3 specialist models.
Only needs to be done once. Models are saved to `backend/models/`.

```bash
cd backend
python train_model.py
```

Expected output:

```
=== Ram Antivirus — Specialist ML Model Training ===

  NSL-KDD  — train: 125,973  test: 22,544  attack ratio: 46.54%
  CICIDS-2017 (synthetic) — train: 44,000  test: 11,000
  UNSW-NB15 (synthetic)   — train: 56,000  test: 14,000

--- iforest on NSL-KDD ---
  F1 Score : 62.0%  Saved → models/iforest.pkl

--- knn on CICIDS-2017 ---
  F1 Score : 24.16%  Saved → models/knn.pkl

--- hbos on UNSW-NB15 ---
  F1 Score : 100.0%  Saved → models/hbos.pkl

=== All models saved to backend/models/ ===
```

What each model specialises in:

- `iforest` (NSL-KDD) → brute force, privilege escalation, port scan
- `knn` (CICIDS-2017) → DDoS, web attacks, botnet, lateral movement
- `hbos` (UNSW-NB15) → malware, reconnaissance, backdoor, shellcode

---

## Step 3 — Start the Live Log Generator (Terminal 1)

This runs in the background and writes new security events to `data/alerts.json`
every 60 seconds. It simulates a real server being monitored by Wazuh.

```bash
cd backend
python simulator/log_generator.py
```

To generate logs faster (every 10 seconds) for demo purposes:

```bash
python simulator/log_generator.py 10
```

Expected output:

```
=== Ram Antivirus — Live Log Generator ===
Writing to: backend/data/alerts.json
Interval  : every 60 seconds

[10:23:45] +12 alerts  (normal=10  attacks=2)  total=12
[10:24:45] +15 alerts  (normal=12  attacks=3)  total=27
[10:25:45] +11 alerts  (normal=9   attacks=2)  total=38
[10:26:45] +18 alerts  (normal=8   attacks=10) total=56  [CAMPAIGN: brute_force_heavy]
```

Leave this running. Press `Ctrl+C` to stop.

---

## Step 4 — Set Environment Variables (Terminal 2)

Tell the backend to read from the live log file:

**Windows (Command Prompt):**

```cmd
set WAZUH_LOG_PATH=data/alerts.json
```

**Windows (PowerShell):**

```powershell
$env:WAZUH_LOG_PATH = "data/alerts.json"
```

**Optional — Email Alerts (Gmail):**

```cmd
set ALERT_EMAIL_FROM=your@gmail.com
set ALERT_EMAIL_PASS=your-16-char-app-password
set ALERT_EMAIL_TO=soc@yourcompany.com
```

To get a Gmail app password:

1. Go to https://myaccount.google.com/security
2. Enable 2-Step Verification
3. Go to App Passwords → generate one for "Mail"
4. Use that 16-character password as `ALERT_EMAIL_PASS`

**Optional — LocalStack (fake AWS):**

```cmd
set LOCALSTACK_ENDPOINT=http://localhost:4566
```

---

## Step 5 — Start the Backend (Terminal 2)

```bash
cd backend
python main.py
```

Expected output:

```
[ML Engine] Loaded 3 specialist models: ['iforest', 'knn', 'hbos']
  iforest    trained on NSL-KDD       F1=62.0%   specialises: brute_force, privilege_escalation
  knn        trained on CICIDS-2017   F1=24.16%  specialises: ddos, web_attacks, botnet
  hbos       trained on UNSW-NB15     F1=100.0%  specialises: malware, reconnaissance, backdoor

INFO:     Uvicorn running on http://0.0.0.0:8000
```

API docs available at: http://localhost:8000/docs

---

## Step 6 — Install Frontend Dependencies (Terminal 3)

```bash
cd frontend
npm install
```

---

## Step 7 — Start the Frontend (Terminal 3)

```bash
cd frontend
npm run dev
```

Expected output:

```
  VITE v6.x.x  ready in 300ms

  ➜  Local:   http://localhost:5173/
```

Open http://localhost:5173 in your browser.

---

## Step 8 — Login

Use one of the default accounts:

| Username     | Password       | Role    | Access                               |
| ------------ | -------------- | ------- | ------------------------------------ |
| `admin`    | `admin123`   | Admin   | Everything including user management |
| `analyst1` | `analyst123` | Analyst | View + ML + compliance + simulation  |
| `viewer1`  | `viewer123`  | Viewer  | Read-only dashboards                 |

---

## How the System Works End-to-End

```
Terminal 1: log_generator.py
    │  writes new alerts every 60s
    ▼
data/alerts.json
    │  wazuh_reader.py reads this file
    ▼
main.py API endpoints
    │
    ├── analyze_events()
    │     3 specialist ML models score each event
    │     iforest + knn + hbos → max score = final anomaly score
    │
    ├── run_cspm_scan(events)
    │     maps rule IDs from logs → cloud misconfigurations
    │     no random selection — every finding backed by a real log event
    │
    ├── run_ciem_scan(events)
    │     identifies risky IAM identities from attack events
    │     no random selection — every finding backed by a real log event
    │
    ├── calculate_unified_risk()
    │     0.35 × ml_score + 0.35 × cspm_score + 0.30 × ciem_score
    │     saved to SQLite risk_history table
    │
    └── WebSocket /ws/events
          pushes live updates to frontend every 10 seconds
    │
    ▼
React Frontend (http://localhost:5173)
    │
    ├── Overview tab      — ML anomaly chart + CSPM + CIEM findings
    ├── Risk Score tab    — unified score + 7-day trend from SQLite
    ├── ML Comparison tab — 3 specialist models compared side by side
    ├── Remediation tab   — 8 playbooks + email alerts
    ├── Compliance tab    — ISO27001 / SOC2 / GDPR scores
    ├── Attack Sim tab    — run attack scenarios + verify detection
    └── Users tab         — admin: manage user accounts (admin only)
```

---

## Optional — LocalStack (Fake AWS for CSPM/CIEM)

If you want CSPM and CIEM to scan real AWS resources instead of deriving from logs:

```bash
# Install LocalStack
pip install localstack awscli-local

# Start LocalStack
localstack start

# Create test resources with intentional misconfigurations
awslocal s3 mb s3://test-public-bucket
awslocal iam create-user --user-name alice
awslocal iam attach-user-policy --user-name alice \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
awslocal ec2 create-security-group \
  --group-name open-rdp --description "test"

# Set env var
set LOCALSTACK_ENDPOINT=http://localhost:4566
```

When LocalStack is running, CSPM and CIEM automatically switch to boto3 API calls.
Check status at: http://localhost:8000/api/status

---

## All Running Terminals Summary

| Terminal | Command                                                         | Purpose                                |
| -------- | --------------------------------------------------------------- | -------------------------------------- |
| 1        | `python simulator/log_generator.py 10`                        | Generates live security logs every 10s |
| 2        | `set WAZUH_LOG_PATH=data/alerts.json` then `python main.py` | FastAPI backend                        |
| 3        | `npm run dev` (in frontend/)                                  | React frontend                         |

---

## API Quick Reference

| Endpoint                                  | What it returns                           |
| ----------------------------------------- | ----------------------------------------- |
| `GET /api/status`                       | Wazuh / LocalStack / DB connection status |
| `GET /api/simulate/events`              | Latest analyzed events with ML scores     |
| `GET /api/cspm/scan`                    | CSPM findings derived from logs           |
| `GET /api/ciem/scan`                    | CIEM findings derived from logs           |
| `GET /api/risk/score`                   | Unified risk score + 7-day trend          |
| `GET /api/ml/compare`                   | 3 specialist models compared              |
| `GET /api/ml/model-info`                | Training metadata for all 3 models        |
| `GET /api/compliance/dashboard`         | ISO27001 / SOC2 / GDPR scores             |
| `GET /api/compliance/report?format=csv` | Download compliance report                |
| `GET /api/export/events`                | Download events as CSV                    |
| `GET /api/export/cspm`                  | Download CSPM findings as CSV             |
| `GET /api/export/ciem`                  | Download CIEM findings as CSV             |
| `GET /api/history/cspm`                 | Historical CSPM scans from SQLite         |
| `GET /api/history/alerts`               | Alert log from SQLite                     |
| `POST /api/alerts/test`                 | Send test email alert (admin only)        |
| `WS /ws/events`                         | WebSocket — live event stream every 10s  |

Full interactive docs: http://localhost:8000/docs

---

## Troubleshooting

**Backend fails to start — ModuleNotFoundError**

```bash
pip install -r requirements.txt
```

**ML models not found warning on startup**

```bash
cd backend
python train_model.py
```

**Dashboard shows "source: simulated" instead of "source: real"**

- Make sure log_generator.py is running in Terminal 1
- Make sure `WAZUH_LOG_PATH=data/alerts.json` is set before starting main.py
- Check `GET /api/status` — wazuh.available should be true

**Email alerts not sending**

- Set `ALERT_EMAIL_FROM`, `ALERT_EMAIL_PASS`, `ALERT_EMAIL_TO` env vars
- Use a Gmail App Password (not your regular Gmail password)
- Alerts are always logged to SQLite even without SMTP configured

**Frontend shows blank page**

```bash
cd frontend
npm install
npm run dev
```

**Port already in use**

```bash
# Kill process on port 8000
netstat -ano | findstr :8000
taskkill /PID <pid> /F
```

---

## Default Accounts (Change in Production)

```
admin    / admin123    → full access
analyst1 / analyst123  → view + ML + compliance
viewer1  / viewer123   → read-only
```

Register new users at: `POST /api/auth/register`
Or use the Register button on the login page.

# Industry-project-AI-driven-Cloud-monitoring-platform-
