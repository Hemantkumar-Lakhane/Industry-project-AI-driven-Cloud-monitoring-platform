# 🐳 Docker & LocalStack AWS Setup Guide

This document provides simple, step-by-step instructions to run **Docker** and **LocalStack AWS Emulation** with the AegisCloud platform.

---

## 📌 1. Do You Need to Run Docker? (Important)

> **Short Answer: NO, it is completely OPTIONAL.**

AegisCloud is built with an **Intelligent Dual-Mode Architecture**:
* **Mode 1: Live Cloud Emulation (When Docker & LocalStack are ON):**  
  The backend directly connects to LocalStack on `http://localhost:4566` using `boto3` to audit real emulated AWS S3 buckets and IAM roles.
* **Mode 2: Cloud Policy Audit Engine (When Docker is OFF or on Render Cloud):**  
  The backend automatically switches to its built-in Cloud Policy Audit Engine (`mode: "cloud_policy_engine"`). CSPM posture checks, CIEM identity audits, multi-framework compliance (ISO 27001 / SOC 2 / GDPR), and Unified Risk Scoring continue to work **100% perfectly with zero configuration**.

---

## 🚀 2. Quick Setup (3 Simple Steps)

If you want to run live AWS emulation locally:

### Step 1: Open Docker Desktop
Ensure **Docker Desktop** is running on your Windows computer.
* Search for **Docker Desktop** in the Windows Start Menu and launch it.
* Wait until the bottom left icon turns green (`Engine running`).

### Step 2: Start LocalStack Container
Open **PowerShell** or **Command Prompt** and run:

```cmd
docker run -d --name localstack -p 4566:4566 -e SERVICES=s3,iam localstack/localstack
```

* `-d`: Runs the container in the background (detached).
* `--name localstack`: Assigns a clean name to the container.
* `-p 4566:4566`: Binds LocalStack's AWS gateway to port `4566`.
* `-e SERVICES=s3,iam`: Enables S3 and IAM cloud services.

### Step 3: Seed Sample Cloud Assets (1-Click)
In the project folder, double-click:
```cmd
seed_localstack.bat
```
*(Or run `python backend/seed_localstack.py`)*

This script automatically creates:
1. `s3://aegiscloud-compliant-storage`: Encrypted, compliant private storage.
2. `s3://aegiscloud-public-exfil-bucket`: Publicly accessible S3 bucket (triggers CSPM detection!).
3. IAM User `cloud-dev-user`: Least-privilege developer role.
4. IAM User `compromised-admin`: Wildcard `*` administrator policy without MFA (triggers CIEM detection!).

---

## 🔍 3. Verifying the Connection

Open your AegisCloud dashboard at `http://localhost:5173/` or query the backend health endpoint:

```cmd
curl http://localhost:8000/api/status
```

Response when LocalStack is running:
```json
{
  "status": "success",
  "data": {
    "wazuh": {
      "available": true,
      "mode": "real",
      "message": "Reading from .../data/alerts.json"
    },
    "localstack": {
      "available": true,
      "endpoint": "http://localhost:4566",
      "mode": "cloud_connector",
      "message": "Connected to LocalStack AWS at http://localhost:4566"
    },
    "database": "connected"
  }
}
```

---

## 🛠️ 4. Useful Docker Management Commands

| Action | Command |
| :--- | :--- |
| **Check LocalStack logs** | `docker logs -f localstack` |
| **Stop LocalStack** | `docker stop localstack` |
| **Restart LocalStack** | `docker start localstack` |
| **Remove Container** | `docker rm -f localstack` |
| **Check Port 4566** | `curl http://localhost:4566/_localstack/health` |

---

## ☁️ 5. Cloud Deployment (Render / AWS / GCP)

On cloud providers like **Render** where Docker-in-Docker is not supported on free tiers, AegisCloud seamlessly uses its native Cloud Policy Audit Engine. No Docker daemon is required on Render.

