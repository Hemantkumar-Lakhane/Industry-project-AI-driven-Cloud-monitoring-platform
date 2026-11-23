# RAM Antivirus — Cloud Security & Threat Verification Guide

This guide details how to verify end-to-end real-time threat detection, ML anomaly scoring, incident correlation, and autonomous playbook remediation against your connected cloud environment and live workloads.

---

## 1. Quick Start

### Prerequisites
- Python 3.10+ (Standard library only; zero mandatory third-party pip dependencies required for test execution)
- Connected AWS Cloud environment configured in **Cloud Connectors**

### Environment Configuration (`.env`)
Configuration is externalized to `.env` (gitignored to protect secrets). A template is provided in `.env.example`:
```ini
# Target Workload Under Audit
TARGET_APP_URL=https://main.dfikzx2dg0tka.amplifyapp.com
TARGET_BACKEND_URL=https://dcjovytpk37z6noqf7et5nt3uq0lnrvj.lambda-url.ap-southeast-2.on.aws
TARGET_USER_EMAIL=hemantkumar.lakhane23@vit.edu
TARGET_USER_PASSWORD=password123

# Connected Customer AWS Environment
AUDIT_ACCOUNT_ID=617711904818
AUDIT_REGION=ap-southeast-2
AUDIT_PRINCIPAL=ram-audit-user

# RAM Antivirus Platform Endpoints & Management Credentials
RAM_PLATFORM_URL=https://yjgrkgtghhynpb2kh3xtgjh7km0vdnsu.lambda-url.ap-southeast-2.on.aws
RAM_FRONTEND_URL=https://d3sa9ma9swl1ef.cloudfront.net
RAM_ADMIN_USER=admin
RAM_ADMIN_PASS=admin123
```

---

## 2. Interactive Verification Console

Launch the interactive terminal console from the project root:
```powershell
python scripts\threat_verification_console.py
```
Or directly via the detector verification engine:
```powershell
python scripts\verify_cloud_detection.py -i
```

### Menu Options
| Option | Attack Vector / Scenario | Target Detector | MITRE Technique |
| :--- | :--- | :--- | :--- |
| **[1]** | **Brute Force & Credential Stuffing** | `DET-BF-01` | **T1110.001** (Password Spraying) |
| **[2]** | **Credential Abuse & Account Takeover** | `DET-ATO-07` | **T1078.004** (Valid Cloud Accounts) |
| **[3]** | **Control-Plane Reconnaissance Burst** | `DET-API-09` | **T1046** (Network/API Discovery) |
| **[4]** | **IAM Privilege Escalation** | `DET-PE-03` | **T1098** (Account Manipulation) |
| **[5]** | **Full Verification Matrix** | All Detectors | Full Attack Lifecycle |
| **[6]** | **Live Incident & Findings Inspection** | Correlator | Real-time summary |
| **[7]** | **Open Cloud Dashboard** | Frontend Web | Direct browser launch |

---

## 3. Direct Command-Line Execution

To run automated tests or integrate into CI/CD pipelines:

### Single Attack Vectors
```powershell
# 1. Test High-Velocity Brute Force & Credential Stuffing
python scripts\verify_cloud_detection.py --vector brute_force

# 2. Test Account Takeover & Breached Auth Sequence
python scripts\verify_cloud_detection.py --vector credential_abuse

# 3. Test Cloud Control-Plane Reconnaissance Burst
python scripts\verify_cloud_detection.py --vector reconnaissance

# 4. Test Unauthorized IAM Privilege Escalation
python scripts\verify_cloud_detection.py --vector privilege_escalation
```

### Automated Multi-Vector Suite
```powershell
# Run the complete verification suite with automated PASS/FAIL reporting
python scripts\cloud_security_tests\run_all_security_tests.py
```

Or using Windows batch scripts:
```powershell
.\run_all_security_tests.bat
```

---

## 4. How Verification Works (Zero-Mock Architecture)

1. **Authentic IP Detection**:
   The script queries external resolvers (`api.ipify.org`, `icanhazip.com`) to determine your host's actual public egress IP.

2. **Live Target Workload Probing**:
   Dispatches genuine HTTP authentication requests against the live target endpoint (e.g. `https://main.dfikzx2dg0tka.amplifyapp.com` via its API Gateway/Lambda URL) to generate real application-layer telemetry.

3. **CloudTrail Audit Telemetry Ingestion**:
   Constructs structured CloudTrail and AWS audit records tagged with your authentic IP and account details, then transmits them to `/api/cloud/ingest/cloudtrail`.

4. **Multi-Signal Correlation Engine**:
   - The detector pipeline evaluates sliding windows and anomaly scoring.
   - Finds matching incident campaigns and creates findings in PostgreSQL (`FIND-BRUT-*`, `FIND-CIEM-*`, etc.).
   - Increments active counts in the **Threat Detection Engines** matrix on the **Overview** page.

---

## 5. Verifying Alerts & Remediation in the Web Console

1. Navigate to **RAM Antivirus Console**:
   👉 `https://d3sa9ma9swl1ef.cloudfront.net`

2. **Overview Page**:
   - In the **Threat Detection Engines** catalog, verify that the card matching your tested attack (e.g., *Brute Force & Credential Stuffing*) displays an active badge (e.g. `1 Active Alert`) rather than baseline clean.
   - Click **`Inspect →`** to view correlated details.

3. **Alerts & Incidents Page**:
   - View correlated campaigns under **Correlated Incidents** (e.g. `[INC-55904D29] Brute-Force Burst`).
   - Switch to **Atomic Findings** to inspect granular event telemetry, timestamps, source IPs, and MITRE tactics.
   - Use the category dropdown to filter across any of the 16 specialized threat categories.

4. **Remediation & Autonomous Containment**:
   - Click **Investigate & Remediate** on any active threat.
   - Inspect plain-English root cause analysis, affected resources, and verified MITRE ATT&CK mapping.
   - Execute dry-run rollback or real containment playbooks (`PB-BF-001`, `PB-CS-009`, `PB-NM-010`, etc.).
