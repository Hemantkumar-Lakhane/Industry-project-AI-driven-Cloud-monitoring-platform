# Ram Antivirus — Cloud Security AI Platform

### Setup & Run Guide

---

## What This Project Does

A full-stack cloud security platform that:

- Reads real or simulated Wazuh security logs every minute
- Runs 3 specialist ML models (trained on NSL-KDD, CICIDS-2017, UNSW-NB15) to detect anomalies
- Derives CSPM and CIEM findings directly from log events — no random selection
- Shows unified risk score, compliance status (ISO27001 / SOC2 / GDPR), and remediation playbooks
- Sends real email alerts when attacks are detected
- Persists all data in SQLite across restarts

---

## Project Structure

```
Industry(Ram)/
├── backend/
│   ├── main.py                    ← FastAPI server (all API endpoints)
│   ├── train_model.py             ← Train ML models on datasets (run once)
│   ├── requirements.txt
│   ├── security.db                ← SQLite database (auto-created)
│   ├── engines/
│   │   ├── ml_engine.py           ← PyOD anomaly detection (loads trained models)
│   │   ├── cspm_engine.py         ← Cloud misconfigs derived from logs
│   │   ├── ciem_engine.py         ← IAM risks derived from logs
│   │   ├── risk_engine.py         ← Unified risk score formula
│   │   ├── compliance_engine.py   ← ISO27001 / SOC2 / GDPR mapping
│   │   ├── remediation_engine.py  ← 8 automated playbooks
│   │   ├── alert_engine.py        ← Real SMTP email alerts
│   │   ├── auth_engine.py         ← JWT auth + RBAC (SQLite-backed)
│   │   ├── localstack_engine.py   ← boto3 against LocalStack (optional)
│   │   └── db.py                  ← SQLite persistence layer
│   ├── simulator/
│   │   ├── log_generator.py       ← Live log generator (writes every 60s)
│   │   ├── wazuh_reader.py        ← Reads alerts.json in Wazuh format
│   │   ├── wazuh_simulator.py     ← Fallback event generator
│   │   └── attack_simulator.py    ← Attack scenario generator
│   ├── models/                    ← Trained ML model files (auto-created)
│   │   ├── iforest.pkl            ← Isolation Forest (NSL-KDD)
│   │   ├── knn.pkl                ← KNN (CICIDS-2017)
│   │   ├── hbos.pkl               ← HBOS (UNSW-NB15)
│   │   ├── scaler_*.pkl           ← Feature scalers
│   │   └── training_meta.json     ← Training metadata
│   └── data/
│       ├── alerts.json            ← Live log file (written by log_generator.py)
│       ├── KDDTrain+.txt          ← NSL-KDD training data (auto-downloaded)
│       └── KDDTest+.txt           ← NSL-KDD test data (auto-downloaded)
└── frontend/
    └── src/
        ├── App.jsx                ← Main dashboard + WebSocket
        └── components/
            ├── LoginPage.jsx
            ├── AttackSimulationTab.jsx
            ├── RiskScoreTab.jsx
            ├── MLComparisonTab.jsx
            ├── UserManagementTab.jsx
            └── SharedComponents.jsx
```

---

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
