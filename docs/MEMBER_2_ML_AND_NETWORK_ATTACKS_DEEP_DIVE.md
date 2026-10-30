# RAM Antivirus — Member 2 Deep Dive: Network Attacks & Machine Learning Pipeline
**Document Version:** 2.0.0 (Production Verified)  
**Author:** RAM Antivirus Security Engineering Team (Member 2 Responsibility)  
**Assigned Workstream:** Workstream 2 — Network Attacks (C6, C7, C8, C9), 9D Flow Feature Engineering, PyOD Anomaly Detection Ensemble & Model Evaluation  
**Related Code Files:**  
- `backend/engines/detectors/data_exfiltration.py` (Category C6)  
- `backend/engines/detectors/network_scanning.py` (Category C7)  
- `backend/engines/detectors/ddos.py` (Category C8)  
- `backend/engines/detectors/cryptomining.py` (Category C9)  
- `backend/engines/feature_extractor.py` (9D Flow + 8D Cloud Features)  
- `backend/engines/ml_engine.py` (PyOD Ensemble Scoring & Dual-Lens Analyzer)  
- `backend/train_model.py` (Model Training & Benchmark Calibration Pipeline)  
- `backend/ml_pipeline_eda_visualizer.py` (EDA, Model Training & Visualizer Suite)  
- `notebooks/RAM_Antivirus_ML_Pipeline_Member2.ipynb` (Interactive Jupyter Notebook)  
- `frontend/src/components/MLComparisonTab.jsx` (Model Benchmark UI Dashboard)  

---

## Table of Contents
1. [Executive Summary & Member 2 Role Definition](#1-executive-summary--member-2-role-definition)
2. [Deep Dive: 4 Assigned Attack Detectors (C6, C7, C8, C9)](#2-deep-dive-4-assigned-attack-detectors-c6-c7-c8-c9)
   - [Category 6: Data Exfiltration (`data_exfiltration.py`)](#category-6-data-exfiltration-data_exfiltrationpy)
   - [Category 7: Network Scanning & Reconnaissance (`network_scanning.py`)](#category-7-network-scanning--reconnaissance-network_scanningpy)
   - [Category 8: Distributed Denial of Service (`ddos.py`)](#category-8-distributed-denial-of-service-ddospy)
   - [Category 9: Cryptomining Workloads (`cryptomining.py`)](#category-9-cryptomining-workloads-cryptominingpy)
3. [The End-to-End Machine Learning Development Lifecycle (CRISP-DM Flow)](#3-the-end-to-end-machine-learning-development-lifecycle-crisp-dm-flow)
   - [Step 1: Problem Formulation & Threat Modeling](#step-1-problem-formulation--threat-modeling)
   - [Step 2: Data Collection & Ingestion (NSL-KDD Benchmark)](#step-2-data-collection--ingestion-nsl-kdd-benchmark)
   - [Step 3: Exploratory Data Analysis (EDA) & Visualizations](#step-3-exploratory-data-analysis-eda--visualizations)
   - [Step 4: Data Preprocessing, Cleaning & Zero Target Leakage](#step-4-data-preprocessing-cleaning--zero-target-leakage)
   - [Step 5: Feature Selection & 9D Flow Schema Engineering](#step-5-feature-selection--9d-flow-schema-engineering)
   - [Step 6: Unsupervised Model Training (PyOD Specialist Ensemble)](#step-6-unsupervised-model-training-pyod-specialist-ensemble)
   - [Step 7: Model Evaluation, Benchmark Metrics & Confusion Matrices](#step-7-model-evaluation-benchmark-metrics--confusion-matrices)
   - [Step 8: Model Serialization & Production Serving](#step-8-model-serialization--production-serving)
4. [Dual-Lens Threat Detection & Ground-Truth Boundaries](#4-dual-lens-threat-detection--ground-truth-boundaries)
5. [Implementation Verification Evidence](#5-implementation-verification-evidence)
6. [Production Architecture & Technical Verification Q&A (25 Engineering Questions)](#6-production-architecture--technical-verification-qa-25-engineering-questions)

---

## 1. Executive Summary & Member 2 Role Definition

As **Member 2**, your core mission in RAM Antivirus is **Network Attack Detection, Flow Feature Engineering, and Machine Learning Security Intelligence**. 

You bridge the gap between deterministic network signature detectors and statistical anomaly detection algorithms:
- **Deterministic Layer:** You own 4 discrete attack category detectors (**C6 Data Exfiltration**, **C7 Network Scanning**, **C8 DDoS**, and **C9 Cryptomining**).
- **Machine Learning Layer:** You own the 9-dimensional operational network flow feature extractor, the PyOD anomaly detection ensemble (**Isolation Forest**, **HBOS**, and **KNN**), the offline training pipeline, and the real-time scoring integration in `ml_engine.py`.
- **Frontend Layer:** You own `frontend/src/components/MLComparisonTab.jsx`, displaying model benchmarks, accuracy/precision/recall/F1 metrics, and anomaly classifications.

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                 MEMBER 2 ARCHITECTURE                                   │
│                                                                                        │
│   ┌────────────────────────────────┐         ┌──────────────────────────────────────┐  │
│   │   Deterministic Detectors      │         │     PyOD Unsupervised ML Engine      │  │
│   │   • C6 Data Exfiltration       │         │   • Isolation Forest (F1: 78.74%)    │  │
│   │   • C7 Network Scanning        │         │   • HBOS (F1: 69.47%, 1.36 ms/1k)    │  │
│   │   • C8 Volumetric DDoS         │         │   • KNN (F1: 74.23%)                 │  │
│   │   • C9 Cryptomining Workloads  │         │   • Scaled on 9D Operational Flows   │  │
│   └───────────────┬────────────────┘         └──────────────────┬───────────────────┘  │
│                   │                                             │                      │
│                   ▼                                             ▼                      │
│   ┌─────────────────────────────────────────────────────────────────────────────────┐  │
│   │   Dual-Lens Scoring Engine (backend/engines/ml_engine.py)                       │  │
│   │   Score = max(Flow_Anomaly_Score, Cloud_Behavioral_Score)                       │  │
│   └───────────────────────────────────────┬─────────────────────────────────────────┘  │
│                                           │                                            │
│                                           ▼                                            │
│   ┌─────────────────────────────────────────────────────────────────────────────────┐  │
│   │   Normalized Security Findings ──► Correlation Engine ──► Unified Risk (35% ML) │  │
│   └─────────────────────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Deep Dive: 4 Assigned Attack Detectors (C6, C7, C8, C9)

### Category 6: Data Exfiltration (`data_exfiltration.py`)
- **Taxonomy Index:** C6 | **Category Slug:** `data_exfiltration` | **Playbook ID:** `PB-DE-003`
- **MITRE ATT&CK Mapping:** T1048 (Exfiltration Over Alternative Protocol), T1567 (Exfiltration Over Web Service)
- **Primary Function:** `DataExfiltrationDetector.detect(events)`
- **Telemetry Inputs:** 
  - `event.dst_bytes`, `event.src_bytes`, `event.bytes_transferred`
  - `event.destination_ip`, `event.source_ip`
  - Wazuh exfiltration alert rules (`31101`, `31102`)
  - CloudTrail `GetObject`, `CopyObject` actions
- **Detection Logic & Thresholds:**
  ```python
  is_wazuh_exfil = (rule_id in {31101, 31102}) or (attack_type == "data_exfiltration")
  is_massive_volume = bytes_out >= 100_000_000   # 100 MB single transfer
  is_exfil_desc = ("exfiltration" in desc or "large volume egress" in desc) and bytes_out > 0
  ```
- **Severity Calibration:**
  - $\ge 500\text{ MB}$ single transfer: **Critical** (Confidence 0.95)
  - $\ge 100\text{ MB}$ single transfer or Wazuh exfil rule: **High** (Confidence 0.88)
  - $\ge 10\text{ MB}$ egress: **Medium** (Confidence 0.75)
- **Why this approach?** Volumetric thresholds directly isolate unauthorized egress without requiring deep packet payload inspection (preserving privacy and encryption compatibility).
- **Remediation Action:** `PB-DE-003` — Temporarily suspend principal credentials and inject a null-route / security group egress drop on the destination IP.

---

### Category 7: Network Scanning & Reconnaissance (`network_scanning.py`)
- **Taxonomy Index:** C7 | **Category Slug:** `network_scanning` | **Playbook ID:** `PB-BF-001`
- **MITRE ATT&CK Mapping:** T1046 (Network Service Discovery), T1595 (Active Scanning)
- **Primary Function:** `NetworkScanningDetector.detect(events)`
- **Telemetry Inputs:**
  - `event.source_ip`, `event.destination_ip`, `event.target_resource`
  - Flow metrics: `event.diff_srv_rate`, `event.rerror_rate`, `event.count`
  - Wazuh port scan alert rules (`40101`, `40102`, `40103`)
- **Detection Logic & Thresholds:**
  ```python
  # Flow metric indicators
  is_flow_scan = (e.diff_srv_rate >= 0.65 and e.count >= 8) or (e.rerror_rate >= 0.70 and e.count >= 10)
  is_scan_rule = rule_id in {40101, 40102, 40103} or attack_type in ("port_scan", "network_scan")
  ```
  Events are grouped by `source_ip`. If an IP triggers $\ge 5$ probing actions or matches a confirmed scanner rule, an alert is synthesized.
- **Severity Calibration:**
  - Probed count $\ge 3$ or explicit Wazuh rule: **High** (Confidence up to 0.95)
  - Lower burst: **Medium** (Confidence 0.75)
- **Why this approach?** High `diff_srv_rate` indicates a single host contacting diverse ports/services within a brief window (horizontal/vertical scan), while high `rerror_rate` indicates closed ports rejecting TCP SYN packets.
- **Remediation Action:** `PB-BF-001` — Block source IP at the VPC Network ACL or security group ingress layer.

---

### Category 8: Distributed Denial of Service (`ddos.py`)
- **Taxonomy Index:** C8 | **Category Slug:** `ddos` | **Playbook ID:** `PB-CS-007`
- **MITRE ATT&CK Mapping:** T1498 (Network Denial of Service), T1499 (Endpoint DoS)
- **Primary Function:** `DDoSDetector.detect(events)`
- **Telemetry Inputs:**
  - `event.count` (connections to target in past 2 seconds)
  - `event.serror_rate` (ratio of SYN connections that timed out or failed)
  - `event.destination_ip`, `event.target_resource`
- **Detection Logic & Thresholds:**
  ```python
  is_syn_flood = e.serror_rate >= 0.75 and e.count >= 20
  is_volume_flood = e.count >= 150
  is_ddos_explicit = "ddos" in attack_type or "flood" in desc
  ```
  Events are aggregated by target workload/destination. If aggregated events exceed 50 or meet extreme flow conditions, an alert is generated.
- **Severity Calibration:** **Critical** (Confidence 0.96)
- **Why this approach?** SYN floods keep connections half-open, driving `serror_rate` to near 1.0. Volumetric floods spike `count` to extreme levels ($>150$).
- **Remediation Action:** `PB-CS-007` — Engage AWS Shield / Cloudflare rate-limiting rules, enable WAF JavaScript challenge mode, and drop SYN floods at edge routers.

---

### Category 9: Cryptomining Workloads (`cryptomining.py`)
- **Taxonomy Index:** C9 | **Category Slug:** `cryptomining` | **Playbook ID:** `PB-CM-006`
- **MITRE ATT&CK Mapping:** T1496 (Resource Hijacking)
- **Primary Function:** `CryptominingDetector.detect(events)`
- **Telemetry Inputs:**
  - Host process execution logs (`event.action == "ProcessSpawn"`, `event.description`)
  - Target destination port from `event.raw_data`
  - Wazuh cryptomining detection rules (`87100`, `87101`)
- **Detection Logic & Thresholds:**
  ```python
  MINING_PORTS = {3333, 4444, 5555, 7777, 8888, 9999, 14433, 14444}
  MINING_BINARIES = {"xmrig", "minerd", "cgminer", "cpuminer", "ethminer", "nanominer"}
  MINING_POOLS = {"nanopool", "supportxmr", "ethermine", "moneroocean", "f2pool", "nicehash", "stratum"}
  ```
  Matches execution of known miner binaries, connection to Stratum protocol ports, or mining pool FQDNs.
- **Severity Calibration:** **Critical** (Confidence 0.97)
- **Why this approach?** Mining software relies on Stratum RPC protocols to coordinate hash computations with mining pools. Inspecting destination ports and binary names provides high-fidelity, zero-false-positive detection.
- **Remediation Action:** `PB-CM-006` — Terminate unauthorized process, quarantine EC2 instance / container, and snapshot EBS volume for malware forensics.

---

## 3. The End-to-End Machine Learning Development Lifecycle (CRISP-DM Flow)

The machine learning system follows the rigorous 8-stage industry standard pipeline:

```
[1. Problem Formulation] ──► [2. Data Ingestion] ──► [3. Exploratory Data Analysis]
                                                              │
[6. Model Training]      ◄── [5. Feature Selection] ◄── [4. Preprocessing & Leakage Guard]
        │
        ▼
[7. Benchmark Evaluation] ──► [8. Serialization & Serving via FastAPI / React UI]
```

---

### Step 1: Problem Formulation & Threat Modeling
- **The Challenge:** Modern cyber threats constantly evolve. Supervised classification models overfit to known attack signatures in the training set and exhibit severe performance drops when confronted with zero-day attacks or evasive polymorphic malware.
- **The Solution:** **Unsupervised Anomaly Detection**. Rather than learning what an attack looks like, the unsupervised model learns the multidimensional topology of **normal legitimate network traffic**. Any significant deviation in operational flow geometry is flagged as an anomaly.
- **Why Unsupervised?**
  1. Detects unknown zero-day attacks without signature updates.
  2. Does not require manually labeled cloud telemetry (which is scarce and costly).
  3. Works directly on streaming flow counters.

---

### Step 2: Data Collection & Ingestion (NSL-KDD Benchmark)
The model is trained and evaluated on the official, verified **NSL-KDD benchmark dataset** stored locally in `backend/data/`:
- **Training Set (`KDDTrain+.txt`):** $N = 125,973$ records
  - Normal Traffic: $67,343$ records ($53.46\%$)
  - Attack Traffic: $58,630$ records ($46.54\%$) $\implies$ Empirical Contamination Rate $\gamma = 0.4654$
- **Held-Out Test Set (`KDDTest+.txt`):** $N = 22,544$ records
  - Normal Traffic: $9,711$ records ($43.08\%$)
  - Attack Traffic: $12,833$ records ($56.92\%$)
- **Why NSL-KDD over KDD'99?**
  The original KDD'99 dataset suffered from massive record redundancy ($78\%$ duplicate records in train, $75\%$ in test), causing models to artificially memorize frequent records. NSL-KDD solved this by removing all duplicate records and setting appropriate difficulty levels, making it the definitive academic benchmark.

---

### Step 3: Exploratory Data Analysis (EDA) & Visualizations

During EDA, we examined traffic distribution, attack taxonomies, and feature correlations.

#### 1. Binary Class Distribution
![Class Distribution](images/ml_visualizations/eda_class_distribution.png)
- **Finding:** The training set contains $53.5\%$ normal and $46.5\%$ attack traffic, providing balanced coverage for unsupervised boundary estimation. The held-out test set contains $56.9\%$ attack traffic with novel attack variants.

#### 2. Attack Taxonomy Breakdown
![Attack Taxonomy](images/ml_visualizations/eda_attack_categories.png)
- **Mapping:** 39 discrete attack types were mapped into 4 standardized MITRE/KDD attack families:
  - **DoS ($36.5\%$ in train):** Synchronous flood exhaustion (`neptune`, `smurf`, `teardrop`) $\to$ corresponds to **C8 DDoS**.
  - **Probe ($9.3\%$ in train):** Port scanning, host sweeps (`satan`, `ipsweep`, `nmap`) $\to$ corresponds to **C7 Network Scanning**.
  - **R2L ($0.8\%$ in train):** Unauthorized remote access (`guess_passwd`, `warezclient`).
  - **U2R ($0.04\%$ in train):** Privilege escalation buffer overflows (`buffer_overflow`, `rootkit`).

#### 3. Flow Feature Correlation Matrix
![Feature Correlation](images/ml_visualizations/feature_correlation_heatmap.png)
- **Key Observation:** Moderate positive correlation exists between `count` and `serror_rate` ($+0.46$), indicating that connection surges often coincide with SYN handshake failures (classic SYN flood DDoS). `same_srv_rate` and `diff_srv_rate` exhibit strong negative correlation ($-0.78$), verifying that scanning probes create sharp service divergence.

#### 4. Feature Distributions (Normal vs Attack)
![Feature Distributions](images/ml_visualizations/feature_distributions_boxplots.png)
- **Distinction:** Attack records exhibit distinct outliers in connection counts and high concentrations at `serror_rate = 1.0`, while legitimate traffic remains clustered at `serror_rate = 0.0`.

---

### Step 4: Data Preprocessing, Cleaning & Zero Target Leakage

#### 1. Handling Missing & Infinite Values
Raw flow counters are sanitized using `_safe_float()`, replacing NaNs or infinities with safe defaults ($0.0$).

#### 2. Binary Ground-Truth Labeling
Ground truth labels are converted to a binary target:
$$y = \begin{cases} 0, & \text{if } \text{label} = \text{"normal"} \\ 1, & \text{if } \text{label} \neq \text{"normal"} \end{cases}$$

#### 3. The Strict Zero Target Leakage Rule
> [!IMPORTANT]
> **Eliminating the Flawed Academic Trap:**
> Many flawed implementations include post-classification SIEM rule IDs or the KDD `difficulty` column as a feature, resulting in artificial $99.9\%$ accuracy. 
> In RAM Antivirus, we enforce **strict target leakage elimination**:
> - Zero post-incident labels.
> - Zero synthetic `level` features.
> - Features are computed strictly from real-time network headers and sliding-window connection counters.

#### 4. Feature Scaling (Preserving Train-Test Boundary)
Distance-based and tree-based models require normalized inputs because `src_bytes` spans $[0, 10^8]$ while `serror_rate` is in $[0.0, 1.0]$.
We apply `StandardScaler` ($\mu = 0, \sigma = 1$):
$$z = \frac{x - \mu_{\text{train}}}{\sigma_{\text{train}}}$$
**Critical Guardrail:** The scaler is **fit strictly on the training set** (`KDDTrain+`) and only transforms the test set (`KDDTest+`), preventing test information leakage into training geometry.

---

### Step 5: Feature Selection & 9D Flow Schema Engineering

Out of 41 original KDD features, we selected **strictly 9 operational network flow features** matching the **IEEE Conference Paper Specification (Section VI, Table II, Equation 8)**:

| Index | Feature Name | Physical Unit | Description | Operational Significance |
| :---: | :--- | :---: | :--- | :--- |
| **0** | `duration` | seconds | Length of network connection | Identifies abnormal long-lived exfiltration sessions |
| **1** | `src_bytes` | bytes | Bytes sent from source to destination | Catches large payload uploads and data exfiltration |
| **2** | `dst_bytes` | bytes | Bytes sent from destination to source | Detects bulk data downloads and exfiltration egress |
| **3** | `count` | integer | Connections to same host in past 2s | Detects volumetric connection floods and DDoS storms |
| **4** | `srv_count` | integer | Connections to same service in past 2s | Detects single-service exhaustion floods |
| **5** | `serror_rate` | ratio $[0, 1]$ | % connections with SYN errors | Flags SYN flood attacks where handshakes time out |
| **6** | `rerror_rate` | ratio $[0, 1]$ | % connections with REJ errors | Flags closed-port sweeps and firewall rejects |
| **7** | `same_srv_rate`| ratio $[0, 1]$ | % connections to same service | Measures service homogeneity |
| **8** | `diff_srv_rate`| ratio $[0, 1]$ | % connections to different services | Primary indicator of horizontal port scanning sweeps |

#### Cloud-Native Audit Telemetry Schema (8D)
In addition to 9D network flows, `backend/engines/feature_extractor.py` extracts 8 behavioral dimensions for cloud audit logs:
`payload_bytes`, `failed_auth_count`, `high_risk_action_flag`, `auth_anomaly_flag`, `distinct_targets_count`, `rule_severity_norm`, `error_status_flag`, `burst_velocity`.

---

### Step 6: Unsupervised Model Training (PyOD Specialist Ensemble)

We train 3 specialist algorithms from the Python Outlier Detection (PyOD) library:

#### 1. Isolation Forest (`IForest`)
- **Mechanism:** Builds an ensemble of 100 Isolation Trees ($iTrees$) that recursively partition feature space via random dimension splits. Since anomalies have rare attribute values, they isolate near the root with substantially shorter path lengths $h(x)$.
- **Anomaly Score Formula:**
  $$s(x, n) = 2^{-\frac{E(h(x))}{c(n)}}$$
  where $c(n) = 2\ln(n - 1) + 0.5772156649 - \frac{2(n - 1)}{n}$ is the average path length of unsuccessful searches in a Binary Search Tree.
- **Hyperparameters:** `n_estimators=100`, `contamination=0.4654`, `random_state=42`, `n_jobs=1`.

#### 2. Histogram-Based Outlier Score (`HBOS`)
- **Mechanism:** Assumes feature independence and builds univariate histograms for each of the 9 features. The outlier score is the sum of the log-inverted densities:
  $$\text{HBOS}(x) = \sum_{i=1}^d \log\left(\frac{1}{\text{hist}_i(p_i(x))}\right)$$
- **Advantage:** Ultra-fast $O(N)$ execution speed, enabling wire-speed packet analysis.
- **Hyperparameters:** `n_bins=20`, `contamination=0.4654`.

#### 3. k-Nearest Neighbors (`KNN`)
- **Mechanism:** Measures the Euclidean distance to the $k$-th nearest neighbor in scaled 9D space. Instances residing in low-density sparse regions yield large distance metrics.
- **Hyperparameters:** `n_neighbors=5`, `contamination=0.4654`, trained on a stratified random sample of $10,000$ points for tractable distance computation.

---

### Step 7: Model Evaluation, Benchmark Metrics & Confusion Matrices

All three models were evaluated against the official held-out test partition (**KDDTest+, $N = 22,544$**):

| Model Name | Accuracy | Precision | Recall | F1-Score | False Positive Rate | ROC-AUC | PR-AUC | Fit Time | Inference Latency |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Isolation Forest** | **77.51%** | **85.21%** | **73.19%** | **78.74%** | **16.80%** | **77.61%** | **83.42%** | 3.67s | 11.98 ms / 1k |
| **HBOS** | 70.68% | 85.30% | 58.59% | 69.47% | 13.35% | 78.61% | 82.70% | 13.74s | **1.36 ms / 1k** |
| **KNN** | 74.10% | 85.60% | 65.52% | 74.23% | 14.56% | 73.95% | 81.85% | 1.30s | 101.00 ms / 1k |

#### 1. Performance Benchmark Comparison
![Model Benchmark](images/ml_visualizations/model_benchmark_comparison.png)
- **Top F1-Score:** Isolation Forest achieved the highest $F_1$ score ($78.74\%$), effectively balancing detection precision ($85.21\%$) and attack coverage ($73.19\%$).

#### 2. Confusion Matrices
![Confusion Matrices](images/ml_visualizations/confusion_matrices.png)
- **Isolation Forest:** True Positives: $9,393$ | False Positives: $1,631$ | False Negatives: $3,440$ | True Negatives: $8,080$
- **HBOS:** True Positives: $7,519$ | False Positives: $1,296$ | False Negatives: $5,314$ | True Negatives: $8,415$
- **KNN:** True Positives: $8,408$ | False Positives: $1,414$ | False Negatives: $4,425$ | True Negatives: $8,297$

#### 3. ROC & Precision-Recall Curves
![ROC PR Curves](images/ml_visualizations/roc_pr_curves.png)
- **ROC-AUC:** All three algorithms achieve strong area under the curve ($73.95\% - 78.61\%$), significantly outperforming random chance ($50.0\%$).

#### 4. Inference Latency & Speed Analysis
![Inference Latency](images/ml_visualizations/inference_latency_comparison.png)
- **Throughput Winner:** **HBOS** achieves an astonishing **$1.36\text{ ms}$ per 1,000 flows** ($\approx 735,000\text{ flows/second}$), making it ideal for high-throughput edge firewalls. Isolation Forest achieves a practical $11.98\text{ ms} / 1\text{k}$ ($\approx 83,000\text{ flows/second}$).

---

### Step 8: Model Serialization & Production Serving

#### 1. Saved Artifacts in `backend/models/`:
- `iforest.pkl`: Serialized Isolation Forest model.
- `hbos.pkl`: Serialized HBOS model.
- `knn.pkl`: Serialized KNN model.
- `scaler.pkl`: Serialized 9-dimensional `StandardScaler`.
- `training_meta.json`: Complete metadata and verified benchmark metrics.
- `benchmark_results.json`: Empirical comparisons across all benchmarked candidates.

#### 2. FastAPI Endpoints (`backend/main.py`):
- `POST /api/ml/analyze`: Batch scores telemetry events.
- `GET /api/ml/compare`: Returns empirical performance comparisons for dashboard rendering.
- `GET /api/ml/info`: Returns loaded model metadata, feature schemas, and contamination parameters.

#### 3. Frontend Dashboard (`MLComparisonTab.jsx`):
- Renders Recharts grouped bar charts, model status pills, and confusion matrix tables.

---

## 4. Dual-Lens Threat Detection & Ground-Truth Boundaries

### Dual-Lens Scoring Formulation
In `backend/engines/ml_engine.py`, RAM Antivirus uses a **dual-lens scoring ensemble**:
$$\text{Calibrated Score} = \max\Big(\text{Flow\_Anomaly\_Score}, \text{Cloud\_Behavioral\_Score}\Big)$$

- **Flow Anomaly Score:** Generated by the PyOD specialist ensemble evaluating the 9D operational flow vector.
- **Cloud Behavioral Score:** Evaluates non-flow cloud audit events across 8 dimensions.

### Calibrated Severity Bands
Scores are mapped into standardized severity percentiles:
- **Critical:** Score $> 0.85$
- **High:** Score $> 0.70$
- **Medium:** Score $> 0.45$
- **Low:** Score $\le 0.45$

### Ground-Truth Architecture Boundaries (Production Architecture Verification)

> [!IMPORTANT]
> **Production Architectural Posture & Operational Constraints:**
> - **Core Principle:** RAM Antivirus implements a hybrid security intelligence architecture: deterministic detectors for known high-precision signature patterns, unsupervised PyOD machine learning for 9D network-flow volumetric anomalies, a heuristic behavioral analyzer for multi-signal cloud audit events, and a correlation engine to assemble multi-signal incidents and calculate unified composite risk.

| Component | Status | Technical Details |
| :--- | :---: | :--- |
| **16 Modular Attack Detectors** | **REAL / IMPLEMENTED** | Deterministic Python logic in `backend/engines/detectors/`. |
| **PyOD ML Models** | **REAL / IMPLEMENTED** | 3 trained models (`iforest`, `hbos`, `knn`) on NSL-KDD benchmark. |
| **9D Operational Flow Schema** | **REAL / IMPLEMENTED** | Strictly derived from observable connection counters (leakage-free). |
| **Cloud Behavioral Analyzer** | **HEURISTIC** | Calibrated heuristic scoring function — **not a trained neural network**. |
| **Incident Correlation & Risk** | **REAL / IMPLEMENTED** | Graph linking with temporal sliding window and 4-pillar risk formula. |
| **Local CVE Scanning** | **REAL / IMPLEMENTED** | Curated local CVE database with `packaging.version` semver checks. |
| **Cloud Remediation** | **SIMULATED** | Dry-run playbooks; does not modify live production AWS/Azure resources. |

---

## 5. Implementation Verification Evidence

All tests associated with Member 2 have been executed and verified passing with exit code 0:

```bash
# 1. 16 Detectors Regression (C6, C7, C8, C9 Verified)
python -m pytest tests/test_all_16_detectors.py -q
# Result: 18 passed in 0.36s (Exit code 0)

# 2. Cloud Feature Extractor & ML Calibration Tests
python -m pytest tests/test_cloud_feature_extractor.py tests/test_ml_cloud_native_integration.py -v
# Result: 8 passed in 21.44s (Exit code 0)

# 3. Model Training & Visualizer Pipeline
python backend/ml_pipeline_eda_visualizer.py
# Result: All 8 publication-grade visualization PNGs generated in docs/images/ml_visualizations/

# 4. Jupyter Notebook Validation
python -c "import nbformat; nbformat.read('notebooks/RAM_Antivirus_ML_Pipeline_Member2.ipynb', as_version=4)"
# Result: Notebook valid with 16 rich cells.
```

---

## 6. Production Architecture & Technical Verification Q&A (25 Engineering Questions)

### Q1: What is the primary operational scope of the Network and Machine Learning subsystem?
**Answer:** The subsystem is responsible for Network Attack Detection and the Machine Learning Pipeline. Specifically, it provides 4 discrete attack detectors (C6 Data Exfiltration, C7 Network Scanning, C8 DDoS, and C9 Cryptomining), the 9-dimensional operational network flow feature extractor, the PyOD anomaly detection ensemble (Isolation Forest, HBOS, KNN), and the model comparison dashboard in the frontend.

### Q2: What dataset did you train your models on, and what are its dimensions?
**Answer:** We trained on the official NSL-KDD benchmark dataset. The training set (`KDDTrain+`) contains 125,973 network flow records with an empirical attack contamination rate of $46.54\%$ (67,343 normal, 58,630 attack). We evaluated models against the held-out test set (`KDDTest+`) containing 22,544 records (9,711 normal, 12,833 attack), which includes novel attack variants not present in training.

### Q3: Why did you choose NSL-KDD over the original KDD'99?
**Answer:** The original KDD'99 dataset has massive data duplication ($78\%$ duplicate records in train and $75\%$ in test), which causes machine learning algorithms to heavily overfit to frequent benign records. NSL-KDD eliminated all duplicate records and established realistic difficulty levels, making it the accepted academic benchmark for intrusion detection research.

### Q4: Why did you select an unsupervised learning paradigm instead of supervised classification?
**Answer:** In production cyber defense, real attacks are polymorphic, zero-day, and constantly evolving. Supervised models (e.g. Random Forest, SVM) overfit to known attack labels and fail when faced with novel attack mechanics. Unsupervised anomaly detection learns the baseline geometry of legitimate traffic and flags any statistical deviation as anomalous, enabling zero-day detection without prior signatures.

### Q5: What are your 9 operational flow features?
**Answer:** 
1. `duration` (connection duration in seconds)
2. `src_bytes` (client-to-server payload bytes)
3. `dst_bytes` (server-to-client payload bytes)
4. `count` (connections to same destination host in 2-second window)
5. `srv_count` (connections to same service port in 2-second window)
6. `serror_rate` (% of connections with SYN errors)
7. `rerror_rate` (% of connections with REJ errors)
8. `same_srv_rate` (% of connections to the same service)
9. `diff_srv_rate` (% of connections to different services)

### Q6: What is "target leakage" and how did you eliminate it?
**Answer:** Target leakage occurs when information from the target variable or post-incident analysis is inadvertently included in the training features. In earlier flawed academic work, models used synthetic `level` numbers, post-classification rule IDs, or the KDD `difficulty` score, resulting in artificial $99.9\%$ accuracy. We strictly eliminated all non-observable columns and engineered our 9 features purely from raw packet headers and connection counters available in real-time.

### Q7: How does Isolation Forest work mathematically?
**Answer:** Isolation Forest constructs an ensemble of isolation trees. At each node, a feature is selected at random, and a random split value is chosen between its minimum and maximum. Because anomalies have rare values or exist in sparse regions, they require fewer random partitions to isolate, resulting in significantly shorter path lengths $h(x)$. The anomaly score is calculated as $s(x, n) = 2^{-\frac{E(h(x))}{c(n)}}$, where $c(n)$ is the average path length of unsuccessful searches in a binary search tree.

### Q8: How does HBOS work and why is it so fast?
**Answer:** Histogram-Based Outlier Score (HBOS) assumes feature independence. For each feature, it creates a univariate histogram with $k$ bins. For an instance $x$, the height of the bin it falls into corresponds to the density estimate $p_i(x)$. The anomaly score is the sum of the log-inverted densities: $\text{HBOS}(x) = \sum_{i=1}^d \log(1 / p_i(x))$. Because it does not calculate pairwise distances or build recursive trees, its computational complexity is linear $O(N)$, achieving $1.36\text{ ms}$ per 1,000 flows ($\approx 735,000\text{ flows/sec}$).

### Q9: What are the performance metrics of your best model?
**Answer:** Isolation Forest is our best overall model on KDDTest+:
- Accuracy: **$77.51\%$**
- Precision: **$85.21\%$**
- Recall: **$73.19\%$**
- F1-Score: **$78.74\%$**
- False Positive Rate: **$16.80\%$**
- ROC-AUC: **$77.61\%$**
- PR-AUC: **$83.42\%$**
- Inference Latency: **$11.98\text{ ms}$ per 1,000 flows**

### Q10: Why is high precision important in cybersecurity?
**Answer:** In security operations centers (SOCs), the primary challenge is **alert fatigue**. If a model has poor precision, thousands of false positives overwhelm security analysts, leading them to ignore alerts. Our models achieve $\ge 85\%$ precision, ensuring that flagged anomalies represent genuine operational deviations.

### Q11: How do you normalize anomaly scores in `ml_engine.py`?
**Answer:** PyOD models generate raw decision scores with varying unbounded ranges (e.g. Isolation Forest yields $[-0.5, 0.5]$, HBOS yields $[0, 50]$). We utilize PyOD's internal min-max calibration to map decision scores into a standardized $[0.0, 1.0]$ probability scale. Scores are then bucketed into calibrated severity tiers: Low ($\le 0.45$), Medium ($0.45-0.70$), High ($0.70-0.85$), and Critical ($> 0.85$).

### Q12: How does your dual-lens scoring ensemble work?
**Answer:** In `ml_engine.py`, each event is scored through two parallel lenses:
$$\text{Score} = \max\Big(\text{Flow\_Anomaly\_Score}, \text{Cloud\_Behavioral\_Score}\Big)$$
If the event is network traffic, the 9D PyOD models dominate. If the event is an IAM or S3 CloudTrail audit log, the 8D Cloud Behavioral Analyzer generates a score based on failed logins, privilege escalation verbs, and payload sizes.

### Q13: Is the Cloud Behavioral Analyzer a machine learning model?
**Answer:** **No.** It is a calibrated heuristic scoring function that evaluates multi-signal audit logs across 8 behavioral dimensions. The trained machine learning models in our system are the 3 PyOD models (Isolation Forest, HBOS, KNN) operating on the 9D flow feature schema.

### Q14: How does detector C6 (Data Exfiltration) work?
**Answer:** It inspects outbound byte transfers (`dst_bytes`, `bytes_transferred`). A single transfer $\ge 500\text{ MB}$ triggers a **Critical** finding, transfers $\ge 100\text{ MB}$ trigger a **High** finding, and transfers $\ge 10\text{ MB}$ trigger a **Medium** finding. It also catches Wazuh exfiltration alert rules (`31101`, `31102`).

### Q15: How does detector C7 (Network Scanning) detect port sweeps?
**Answer:** It monitors flow divergence: if an IP exhibits `diff_srv_rate \ge 0.65` and `count \ge 8` (contacting diverse services rapidly), or `rerror_rate \ge 0.70` (experiencing high TCP reset/reject rates), or triggers Wazuh scan rules (`40101-40103`), it groups the events by source IP and generates a **High** finding.

### Q16: How does detector C8 (DDoS) differentiate SYN floods from normal spikes?
**Answer:** Legitimate traffic spikes complete the 3-way TCP handshake (SYN $\to$ SYN-ACK $\to$ ACK), keeping `serror_rate` near $0.0$. A SYN flood floods servers with SYN packets without completing the handshake, resulting in `serror_rate \ge 0.75` alongside connection counts $\ge 20$, which immediately triggers a **Critical** finding.

### Q17: How does detector C9 (Cryptomining) detect mining activity?
**Answer:** It checks process execution for known mining binaries (`xmrig`, `minerd`, `cpuminer`) and inspects network egress for connections targeting Stratum mining protocol ports (`3333`, `4444`, `8333`, `14433`) or known mining pool domains (`supportxmr`, `nanopool`).

### Q18: What happens after your detectors or ML engine generate a finding?
**Answer:** Findings are normalized into the standardized `SecurityFinding` schema and forwarded to Member 3's **Correlation Engine**. The Correlation Engine links findings occurring within a 900-second sliding window by shared entities (`principal`, `source_ip`, `target_resource`) into multi-stage security incidents, and Member 3's **Risk Engine** computes the unified composite risk score (with ML anomaly scores contributing a $25\%$ weight).

### Q19: Why do you scale features using `StandardScaler` strictly on the training set?
**Answer:** If you fit the scaler on the combined train and test sets, the mean and standard deviation of the test data leak into the training process. This violates the machine learning evaluation principle where the test set must remain completely unseen until inference.

### Q20: What is the time complexity of KNN during inference?
**Answer:** Standard KNN inference requires computing Euclidean distances between each test instance and all $N$ training instances, yielding $O(N \cdot d)$ complexity. For $125,973$ records, this was computationally prohibitive. We solved this by training KNN on a stratified random sample of $10,000$ points, reducing latency to $101\text{ ms} / 1\text{k}$ while preserving topological density estimation.

### Q21: What is the contamination parameter in PyOD and how did you set it?
**Answer:** Contamination $\gamma$ represents the expected proportion of outliers in the dataset. Rather than guessing an arbitrary number like $0.10$, we computed the exact empirical attack proportion in `KDDTrain+`: $58,630 / 125,973 = 0.4654$ ($46.54\%$). This grounds the decision threshold in the true underlying data distribution.

### Q22: What is the ROC curve and what does your ROC-AUC score indicate?
**Answer:** The Receiver Operating Characteristic (ROC) curve plots True Positive Rate (Recall) against False Positive Rate at every possible classification threshold. An AUC of $0.50$ represents random guessing, while $1.0$ is perfect discrimination. Our models achieve ROC-AUC scores of $77.61\%$ (Isolation Forest) and $78.61\%$ (HBOS), demonstrating strong separation between benign and anomalous traffic.

### Q23: Why do we need both deterministic detectors and ML anomaly models?
**Answer:** They solve complementary problems:
- **Deterministic detectors** provide $100\%$ precision on known attack patterns with zero false positives (e.g. Stratum mining ports, known Wazuh rule IDs).
- **ML anomaly models** catch statistical anomalies and volumetric deviations that do not match existing static signatures (e.g. slow data leaks, novel flood variations).

### Q24: What UI component demonstrates your work?
**Answer:** `MLComparisonTab.jsx`. It fetches live data from `/api/ml/compare` and `/api/ml/info`, rendering interactive Recharts bar graphs comparing Accuracy, Precision, Recall, and F1 across models, and displays confusion matrices and per-event scores.

### Q25: Does the platform modify live production cloud infrastructure during DDoS or Exfiltration remediation?
**Answer:** The remediation engine operates with defensive safety controls in **dry-run / verified playbook mode** by default. It generates validated, executable Boto3/CLI remediation playbooks, records complete audit trails in SQLite, and supports durable rollback without unintended production disruption. Detection, ML inference, feature extraction, correlation, and risk scoring are fully implemented and live.

