# RAM Antivirus Cloud Security Platform

# Person 1: Complete Machine Learning Dataset, Feature Engineering, and Model Analysis Report

**Document Author:** Person 1 (Lead: Machine Learning & Adaptive Threat Detection)**Target Repository:** `RAM Antivirus Cloud Security AI Platform`**Target File Path:** `docs/PERSON_1_DATASET_AND_FEATURE_ANALYSIS.md`**Status:** Complete Technical Analysis & Architectural Audit**Code & Data Snapshot Inspected:**

- `backend/train_model.py` (549 lines)
- `backend/engines/ml_engine.py` (322 lines)
- `backend/models/training_meta.json` (71 lines)
- `backend/data/KDDTrain+.txt` (125,973 rows, 43 columns, 19.2 MB)
- `backend/data/KDDTest+.txt` (22,544 rows, 43 columns, 3.46 MB)
- `backend/data/alerts.json` (5,001 simulated Wazuh log lines, 2.07 MB)
- `backend/models/` (`iforest.pkl`, `knn.pkl`, `hbos.pkl`, `scaler_iforest.pkl`, `scaler_knn.pkl`, `scaler_hbos.pkl`)
- `backend/simulator/` (`log_generator.py`, `wazuh_simulator.py`, `wazuh_reader.py`, `attack_simulator.py`)
- `backend/requirements.txt` (`pyod==1.1.3`, `scikit-learn==1.4.2`, `pandas==2.2.2`, `numpy==1.26.4`)

---

## Executive Summary for Person 1

As **Person 1 (Machine Learning and Adaptive Threat Detection)**, your responsibility is to understand, evaluate, and upgrade the anomaly detection engine that powers the RAM Antivirus Cloud Security Platform.

Before modifying code or attempting to retrain models, this document provides the **ground-truth analysis** of what is actually running in the backend today. Key findings that every engineer on this project must know:

1. **Ensemble Architecture**: The platform uses three specialized unsupervised anomaly detection algorithms from the `PyOD` library:
   - **Isolation Forest (`iforest`)**: Assigned to the **NSL-KDD** dataset.
   - **K-Nearest Neighbors (`knn`)**: Assigned to the **CICIDS-2017** dataset.
   - **Histogram-based Outlier Score (`hbos`)**: Assigned to the **UNSW-NB15** dataset.
2. **Real vs. Synthetic Datasets**:
   - Only **NSL-KDD** exists locally as real CSV data in `backend/data/` (`KDDTrain+.txt` and `KDDTest+.txt`).
   - Neither **CICIDS-2017** nor **UNSW-NB15** exists on disk. When `train_model.py` was originally executed, public GitHub raw download URLs failed, triggering the fallback generators `_synthetic_cicids()` and `_synthetic_unsw()`.
   - **Mathematical proof from `training_meta.json` confirms that the recorded KNN and HBOS models were trained on synthetic data**, not real university benchmark traffic.
3. **Severe Target-Label Leakage in Feature Engineering**:
   - All three models are trained on only 3 derived numerical features: `level`, `bytes_transferred`, and `failed_attempts`.
   - The `level` feature (supposed to represent Wazuh rule severity 1–15) was **synthesized by mapping ground-truth attack labels directly into numerical levels** (e.g. `normal` $\rightarrow$ 2, `dos` $\rightarrow$ 13, `privilege_escalation` $\rightarrow$ 14, or `level = is_anomaly ? 13 : 2`).
   - Consequently, **the models were given the evaluation answers as an input feature during training**, causing artificially inflated metrics (such as HBOS reporting 100% precision, 100% recall, and 100% F1).
4. **Live Inference Mismatch**:
   - In live production or testing, incoming cloud events derive `level` from **Wazuh SIEM rule severity** (from `alerts.json` or simulated sessions), not from network traffic.
   - The ML models are effectively learning to replicate Wazuh's static rule levels rather than discovering novel anomalies from traffic flow.

This document breaks down every detail with exact numbers, equations, code traces, and verification tables so you can proceed with confidence.

---

## 1. The Complete End-to-End ML Pipeline

The platform's machine learning lifecycle follows an 11-stage pipeline spanning training (`train_model.py`) and live inference (`engines/ml_engine.py`):

```
┌───────────────────────────────────────────────────────────────────────────────────┐
│                           OFFLINE TRAINING PIPELINE (train_model.py)              │
│                                                                                   │
│  [1. Raw Dataset] ──> [2. Loader & Fallback] ──> [3. Label Creation (is_anomaly)] │
│                                                                 │                 │
│  [5. Train/Test Split] <── [4. Feature Extraction & Engineering]                  │
│            │               (level, bytes_transferred, failed_attempts)            │
│            v                                                                      │
│  [6. Clipping & Scaling] ──> [7. Model Fitting (.fit)] ──> [8. Offline Evaluation]│
│  (p99 clip + MinMaxScaler)   (Unsupervised PyOD)           (predict_proba > 0.5)  │
│                                                                 │                 │
│                                                                 v                 │
│                                                     [9. Serialization]            │
│                                                     (.pkl models & scalers,       │
│                                                      training_meta.json)          │
└─────────────────────────────────────────────────────────────────┬─────────────────┘
                                                                  │
┌─────────────────────────────────────────────────────────────────▼─────────────────┐
│                            LIVE INFERENCE PIPELINE (ml_engine.py)                 │
│                                                                                   │
│  [Incoming Events] ──> [Feature Extraction] ──> [Per-Model Scaling] ──────────┐   │
│  (Wazuh / Simulator)   (level, bytes, fails)   (apply saved scaler & p99 clip)│   │
│                                                                               │   │
│  [Final Output] <── [Composite Severity] <── [Max-Score Ensemble] <──────────┘   │
│  (anomaly score,    (Critical/High/Med/Low)  max(iforest, knn, hbos)              │
│   flag, detected_by)                                                              │
└───────────────────────────────────────────────────────────────────────────────────┘
```

### Stage-by-Stage Explanation

1. **Raw Dataset Acquisition**:
   The script checks whether local dataset files exist in `backend/data/`. If missing, it attempts to stream them from public GitHub repositories (`urllib.request.urlretrieve`).
2. **Loading & Fallback**:
   If the network download succeeds, Pandas parses the raw CSV/TXT. If download fails or parsing encounters a schema error, execution jumps into dedicated synthetic fallback generators (`_synthetic_cicids()` or `_synthetic_unsw()`).
3. **Ground-Truth Label Creation**:
   The raw dataset label (e.g. `label`, `attack_cat`) is binarized into an integer column `is_anomaly`:
   $$
   \text{is\_anomaly} = \begin{cases} 0 & \text{if traffic is normal/benign} \\ 1 & \text{if traffic is an attack/anomaly} \end{cases}
   $$
4. **Feature Extraction & Engineering**:
   The raw columns (which vary from 43 to 79 columns depending on the dataset) are reduced to exactly three shared floating-point features:
   - `level`: Intended to represent security rule severity (integer 1 to 15).
   - `bytes_transferred`: Volume of communication in bytes.
   - `failed_attempts`: Count of authentication or connection errors.
5. **Train / Test Partitioning**:
   - NSL-KDD provides pre-split benchmark files (`KDDTrain+.txt` and `KDDTest+.txt`).
   - CICIDS-2017 and UNSW-NB15 use an 80/20 train/test split. For KNN, the dataset is subsampled to at most 30,000 training rows and 8,000 test rows to prevent $O(N^2)$ distance computation bottlenecks.
6. **Feature Clipping & MinMax Scaling**:
   - Outlier protection: The 99th percentile ($P_{99}$) of `bytes_transferred` is calculated **from the training set only**:
     $$
     \text{bytes}_{\text{clipped}} = \min(\text{bytes}, P_{99})
     $$
   - Both training and testing data are clipped using this training threshold.
   - `MinMaxScaler` is fitted on training features and transforms both sets into $[0, 1]$:
     $$
     X_{\text{scaled}} = \frac{X - X_{\min,\text{train}}}{X_{\max,\text{train}} - X_{\min,\text{train}}}
     $$
7. **Unsupervised Model Training**:
   The PyOD model instance is fitted **only on the scaled feature matrix $X_{\text{train,scaled}}$**. The target label `is_anomaly` is **never passed** to `.fit()`. However, the training label is used to set the model's `contamination` parameter:
   $$
   \text{contamination} = \text{clip}\left(\frac{1}{N_{\text{train}}}\sum_{i=1}^{N_{\text{train}}} y_{\text{train},i},\; 0.01,\; 0.49\right)
   $$
8. **Prediction & Offline Evaluation**:
   The fitted model evaluates test samples using `model.predict_proba(X_test)[:, 1]`. Samples with predicted anomaly probability $> 0.5$ are classified as anomalies. Predictions are compared with ground-truth test labels to compute Accuracy, Precision, Recall, F1-score, and the confusion matrix ($TP, FP, FN, TN$).
9. **Artifact Serialization**:
   Trained models and their corresponding scalers are dumped using `joblib` into `backend/models/`:
   `iforest.pkl`, `knn.pkl`, `hbos.pkl`, `scaler_iforest.pkl`, `scaler_knn.pkl`, `scaler_hbos.pkl`, and performance metrics are written to `training_meta.json`.
10. **Live Inference & Scoring**:
    When the backend API starts, `ml_engine.py` loads all three `.pkl` models, scalers, and metadata into RAM. Incoming event objects have their fields extracted, scaled with each model's specific scaler, and scored by all three models simultaneously.
11. **Ensemble Aggregation**:
    The platform applies a competitive maximum-score strategy:
    $$
    \text{Final Anomaly Score} = \max\left(S_{\text{iforest}}, S_{\text{knn}}, S_{\text{hbos}}\right)
    $$

    The model that produced the highest score is credited in `detected_by`.

---

## 2. Exhaustive Dataset Analysis

### Dataset Inventory Overview

| Dataset Attribute                       | Dataset 1: NSL-KDD                                         | Dataset 2: CICIDS-2017                                             | Dataset 3: UNSW-NB15                                                   |
| :-------------------------------------- | :--------------------------------------------------------- | :----------------------------------------------------------------- | :--------------------------------------------------------------------- |
| **Assigned Model**                | Isolation Forest (`iforest`)                             | K-Nearest Neighbors (`knn`)                                      | Histogram-based Outlier Score (`hbos`)                               |
| **Claimed Specialization**        | Brute force, Privilege Escalation, Port scan, R2L, U2R     | DDoS, Web attacks, Botnet, Infiltration, Lateral movement          | Malware, Reconnaissance, Backdoor, Shellcode, Worms                    |
| **Declared Source URL(s)**        | `KDDTrain+.txt` & `KDDTest+.txt` from defcom17/NSL_KDD | `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` from CIC repo | `UNSW_NB15_training-set.csv` & `testing-set.csv` from Abertay repo |
| **Local Path in Repo**            | `backend/data/KDDTrain+.txtbackend/data/KDDTest+.txt`    | `backend/data/cicids_ddos.csv`                                   | `backend/data/unsw_train.csvbackend/data/unsw_test.csv`              |
| **Physical File Exists in Repo?** | **YES (Verified)**                                   | **NO (Missing)**                                             | **NO (Missing)**                                                 |
| **Origin of Trained Artifacts**   | **Real NSL-KDD data on disk**                        | **Synthetic Fallback (`_synthetic_cicids`)**               | **Synthetic Fallback (`_synthetic_unsw`)**                     |
| **Raw Training Rows**             | 125,973                                                    | 40,000 (synthetic)                                                 | 50,000 (synthetic)                                                     |
| **Raw Testing Rows**              | 22,544                                                     | 15,000 (synthetic)                                                 | 20,000 (synthetic)                                                     |
| **Total Rows Used**               | 148,517                                                    | 55,000                                                             | 70,000                                                                 |
| **Raw Feature Columns**           | 41 traffic + 2 labels = 43                                 | 79 (real spec) / 4 (synthetic)                                     | 44 (real spec) / 4 (synthetic)                                         |
| **Target Label Column**           | `label` (col index 41)                                   | `Label` (real) / `is_anomaly` (synthetic)                      | `label` / `attack_cat` (real) / `is_anomaly` (synthetic)         |

---

### 2.1 Dataset 1: NSL-KDD (Isolation Forest Specialist)

#### Provenance and File Verification

- **Source**: University of New Brunswick (UNB) / Canadian Institute for Cybersecurity revision of KDD Cup 99.
- **Repository URLs**:
  - Training: `https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt`
  - Testing: `https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt`
- **File Verification**:
  - `backend/data/KDDTrain+.txt`: Exactly **125,973 lines**, 19,235,397 bytes.
  - `backend/data/KDDTest+.txt`: Exactly **22,544 lines**, 3,464,057 bytes.
  - Total records: **148,517**.
- **Data Quality**:
  - Missing values: **0** across all 43 columns.
  - Exact duplicate rows: **0** in training, **0** in testing.

#### Complete Raw Column Inventory (43 Columns)

```
Index  Column Name                   Data Type  Description
─────────────────────────────────────────────────────────────────────────────
0      duration                      int64      Length of connection in seconds
1      protocol_type                 object     Protocol (tcp, udp, icmp)
2      service                       object     Network service on destination (http, ftp, smtp, etc.)
3      flag                          object     Normal or error connection status flag (SF, S0, REJ, etc.)
4      src_bytes                     int64      Number of data bytes from source to destination
5      dst_bytes                     int64      Number of data bytes from destination to source
6      land                          int64      1 if connection is from/to same host/port; 0 otherwise
7      wrong_fragment                int64      Number of wrong fragments
8      urgent                        int64      Number of urgent packets
9      hot                           int64      Number of "hot" indicators (e.g. entering system directory)
10     num_failed_logins             int64      Number of failed login attempts
11     logged_in                     int64      1 if successfully logged in; 0 otherwise
12     num_compromised               int64      Number of compromised conditions
13     root_shell                    int64      1 if root shell is obtained; 0 otherwise
14     su_attempted                  int64      1 if "su root" command attempted; 0 otherwise
15     num_root                      int64      Number of "root" accesses
16     num_file_creations            int64      Number of file creation operations
17     num_shells                    int64      Number of shell prompts
18     num_access_files              int64      Number of operations on access control files
19     num_outbound_cmds             int64      Number of outbound commands in an ftp session
20     is_host_login                 int64      1 if the login belongs to the "hot" list
21     is_guest_login                int64      1 if the login is a "guest" account; 0 otherwise
22     count                         int64      Connections to the same destination host in past 2 seconds
23     srv_count                     int64      Connections to the same service in past 2 seconds
24     serror_rate                   float64    % of connections that have "SYN" errors
25     srv_serror_rate               float64    % of connections that have "SYN" errors to same service
26     rerror_rate                   float64    % of connections that have "REJ" errors
27     srv_rerror_rate               float64    % of connections that have "REJ" errors to same service
28     same_srv_rate                 float64    % of connections to the same service
29     diff_srv_rate                 float64    % of connections to different services
30     srv_diff_host_rate            float64    % of connections to different hosts to same service
31     dst_host_count                int64      Count of destination host connections
32     dst_host_srv_count            int64      Count of destination host connections to same service
33     dst_host_same_srv_rate        float64    % of connections to destination host to same service
34     dst_host_diff_srv_rate        float64    % of connections to destination host to different services
35     dst_host_same_src_port_rate   float64    % of connections to destination host from same source port
36     dst_host_srv_diff_host_rate   float64    % of connections to same service from different hosts
37     dst_host_serror_rate          float64    % of destination host connections with SYN errors
38     dst_host_srv_serror_rate      float64    % of destination host connections with SYN errors (service)
39     dst_host_rerror_rate          float64    % of destination host connections with REJ errors
40     dst_host_srv_rerror_rate      float64    % of destination host connections with REJ errors (service)
41     label                         object     Raw connection classification (normal or attack name)
42     difficulty                    int64      Evaluation difficulty level score (integer 0 to 21)
```

#### Class Distribution

- **Training Set (`KDDTrain+.txt`)**:
  - `normal`: **67,343 rows (53.46%)**
  - `attack` (all 22 attack types combined): **58,630 rows (46.54%)**
  - Training Contamination: $\frac{58,630}{125,973} \approx 0.465417$
  - Top attack classes in train: `neptune` (41,214), `satan` (3,633), `ipsweep` (3,599), `portsweep` (2,931), `smurf` (2,646), `nmap` (1,493), `back` (956), `teardrop` (892), `warezclient` (890), `pod` (201).
- **Test Set (`KDDTest+.txt`)**:
  - `normal`: **9,711 rows (43.08%)**
  - `attack` (all 37 attack types combined): **12,833 rows (56.92%)**
  - Test Contamination: $\frac{12,833}{22,544} \approx 0.569242$
  - Top attack classes in test: `neptune` (4,657), `guess_passwd` (1,231), `mscan` (996), `warezmaster` (944), `apache2` (737), `satan` (735), `processtable` (685), `smurf` (665), `back` (359), `snmpguess` (331).
  - *Key Observation:* The test set includes 17 novel zero-day attack types not present in the training data (e.g. `mscan`, `apache2`, `processtable`, `snmpguess`, `saint`, `mailbomb`, `httptunnel`).

#### Raw Representative Sample (5 Rows from `KDDTrain+.txt`)

|     Row     | duration | protocol | service | flag | src_bytes | dst_bytes | failed_logins | serror_rate | rerror_rate |    label    | difficulty |
| :---------: | :------: | :------: | :------: | :--: | :-------: | :-------: | :-----------: | :---------: | :---------: | :---------: | :--------: |
| **0** |    0    |   tcp   | ftp_data |  SF  |    491    |     0     |       0       |    0.00    |    0.00    | `normal` |     20     |
| **1** |    0    |   udp   |  other  |  SF  |    146    |     0     |       0       |    0.00    |    0.00    | `normal` |     15     |
| **2** |    0    |   tcp   | private |  S0  |     0     |     0     |       0       |    1.00    |    0.00    | `neptune` |     19     |
| **3** |    0    |   tcp   |   http   |  SF  |    232    |   8153   |       0       |    0.20    |    0.00    | `normal` |     21     |
| **4** |    0    |   tcp   |   http   |  SF  |    199    |    420    |       0       |    0.00    |    0.00    | `normal` |     21     |

---

### 2.2 Dataset 2: CICIDS-2017 (KNN Specialist)

#### Provenance and Real Specification

- **Intended Dataset**: Canadian Institute for Cybersecurity, University of New Brunswick (2017).
- **Intended Subset**: Friday Afternoon DDoS traffic (`Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`).
- **Declared URLs in `train_model.py`**:
  - Primary: `https://raw.githubusercontent.com/CanadianInstituteForCybersecurity/CIC-IDS-2017/master/GeneratedLabelledFlows/TrafficLabels/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`
  - Fallback Mirror: `https://raw.githubusercontent.com/wesleyit/ml_ids_cicids2017/main/data/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`
- **Current Status in Repository**: **FILE DOES NOT EXIST**. Neither `cicids_ddos.csv` nor any CICIDS directory exists in `backend/data/`.
- **Synthetic Fallback Triggered**: When `train_model.py` was executed, the download timed out or was rate-limited by GitHub, causing the script to call `_synthetic_cicids()`.

#### Synthetic Fallback Generator Specification (`_synthetic_cicids()`)

The training script generates synthetic data using the following exact rules:

- **Seed**: `np.random.seed(42)`
- **Normal Class Generation**:
  - Count: **40,000 records**
  - `level`: Discrete uniform integer in $[1, 4]$ (`np.random.randint(1, 5)`)
  - `bytes_transferred`: Exponential distribution with mean 5,000 bytes (`np.random.exponential(5000)`)
  - `failed_attempts`: Constant `0`
  - `is_anomaly`: Constant `0`
- **Attack Class Generation**:
  - Total count: **15,000 records**, divided into 3 equal partitions of 5,000 records:
    1. **DDoS Attack (5,000 rows)**:
       - `level`: Uniform integer in $[11, 13]$ (`np.random.randint(11, 14)`)
       - `bytes_transferred`: Uniform float in $[10{,}000{,}000,\; 500{,}000{,}000]$ (10 MB to 500 MB)
       - `failed_attempts`: Uniform integer in $[0, 2]$
       - `is_anomaly`: Constant `1`
    2. **Botnet Attack (5,000 rows)**:
       - `level`: Uniform integer in $[10, 12]$ (`np.random.randint(10, 13)`)
       - `bytes_transferred`: Uniform float in $[50{,}000,\; 2{,}000{,}000]$ (50 KB to 2 MB)
       - `failed_attempts`: Uniform integer in $[5, 29]$
       - `is_anomaly`: Constant `1`
    3. **Web Attack (5,000 rows)**:
       - `level`: Uniform integer in $[9, 12]$ (`np.random.randint(9, 13)`)
       - `bytes_transferred`: Uniform float in $[1{,}000,\; 50{,}000]$ (1 KB to 50 KB)
       - `failed_attempts`: Uniform integer in $[20, 199]$
       - `is_anomaly`: Constant `1`
- **Total Combined Synthetic Records**: **55,000 rows**.
- **Split & Subsampling**:
  - 80% train = 44,000 rows $\rightarrow$ Subsampled with `min(30000, len)` $\rightarrow$ **30,000 rows used for KNN training**.
  - 20% test = 11,000 rows $\rightarrow$ Subsampled with `min(8000, len)` $\rightarrow$ **8,000 rows used for KNN evaluation**.
- **Contamination**: 15,000 / 55,000 = 27.27% (subsample contamination in `training_meta.json`: **0.273033**).

#### Sample Synthetic CICIDS Rows (5 Rows)

| Synthetic Type           | level | bytes_transferred | failed_attempts | is_anomaly |
| :----------------------- | :---: | :---------------: | :-------------: | :--------: |
| **Normal Traffic** |   2   |     4,218.42     |        0        |     0     |
| **Normal Traffic** |   1   |     8,912.11     |        0        |     0     |
| **DDoS Attack**    |  13  |  312,481,992.50  |        1        |     1     |
| **Botnet Attack**  |  11  |    842,104.30    |       18       |     1     |
| **Web Attack**     |  10  |     14,290.00     |       85       |     1     |

---

### 2.3 Dataset 3: UNSW-NB15 (HBOS Specialist)

#### Provenance and Real Specification

- **Intended Dataset**: Cyber Range Lab of the Australian Centre for Cyber Security (ACCS), UNSW Canberra (2015).
- **Intended Files**: `UNSW_NB15_training-set.csv` (82,332 records) and `UNSW_NB15_testing-set.csv` (175,341 records).
- **Declared URLs in `train_model.py`**:
  - Train: `https://raw.githubusercontent.com/AbertayMachineLearningGroup/UNSW-NB15-PYTHON/master/UNSW_NB15_training-set.csv`
  - Test: `https://raw.githubusercontent.com/AbertayMachineLearningGroup/UNSW-NB15-PYTHON/master/UNSW_NB15_testing-set.csv`
- **Current Status in Repository**: **FILE DOES NOT EXIST**. Neither `unsw_train.csv` nor `unsw_test.csv` exists in `backend/data/`.
- **Synthetic Fallback Triggered**: Downloading failed during execution, triggering `_synthetic_unsw()`.

#### Synthetic Fallback Generator Specification (`_synthetic_unsw()`)

- **Seed**: `np.random.seed(123)` (with dataset shuffle using seed 42)
- **Normal Class Generation**:
  - Count: **50,000 records**
  - `level`: Discrete uniform integer in $[1, 3]$ (`np.random.randint(1, 4)`)
  - `bytes_transferred`: Exponential distribution with mean 3,000 bytes (`np.random.exponential(3000)`)
  - `failed_attempts`: Constant `0`
  - `is_anomaly`: Constant `0`
- **Attack Class Generation**:
  - Count: **20,000 records** (modeling malware, backdoors, shellcode, worms)
  - `level`: Discrete uniform integer in $[12, 15]$ (`np.random.randint(12, 16)`)
  - `bytes_transferred`: Exponential distribution with mean 8,000 bytes (`np.random.exponential(8000)`)
  - `failed_attempts`: Discrete uniform integer in $[5, 49]$ (`np.random.randint(5, 50)`)
  - `is_anomaly`: Constant `1`
- **Total Combined Synthetic Records**: **70,000 rows**.
- **Split**:
  - 80% train = **56,000 rows** (Exactly matches `train_samples: 56000` in `training_meta.json`).
  - 20% test = **14,000 rows** (Exactly matches $3896 + 10104 = 14000$ in `training_meta.json`).
- **Contamination**: 20,000 / 70,000 = 28.57% (sample contamination in `training_meta.json`: **0.287571**).

#### Sample Synthetic UNSW-NB15 Rows (5 Rows)

| Synthetic Type             | level | bytes_transferred | failed_attempts | is_anomaly |
| :------------------------- | :---: | :---------------: | :-------------: | :--------: |
| **Normal Traffic**   |   2   |     2,840.15     |        0        |     0     |
| **Normal Traffic**   |   1   |     1,120.40     |        0        |     0     |
| **Malware/Backdoor** |  14  |     9,812.20     |       24       |     1     |
| **Shellcode/Worm**   |  15  |     6,430.80     |       12       |     1     |
| **Reconnaissance**   |  13  |     11,204.50     |       38       |     1     |

---

## 3. Feature Mapping and Transformation Analysis

The platform forces every dataset—regardless of its native domain—into three common features: `FEATURES = ["level", "bytes_transferred", "failed_attempts"]`.

### Comprehensive Feature-Mapping Table

| Dataset                      | Raw Dataset Column(s)                                   | Derived Feature Name  | Transformation / Formula in Code                                                                                                     | Model Input? |              Target Label?              |                  Available in Real Live Inference?                  |
| :--------------------------- | :------------------------------------------------------ | :-------------------- | :----------------------------------------------------------------------------------------------------------------------------------- | :-----------: | :--------------------------------------: | :------------------------------------------------------------------: |
| **NSL-KDD**            | `label` $\rightarrow$ `cat`                       | `level`             | `cat = NSL_ATTACK_CATEGORY[label]level = NSL_LEVEL_MAP[cat]`(normal: 2, dos: 13, probe: 8, r2l: 10, u2r: 14)                       | **YES** |        NO (Derived from target!)        | **NO** (Live events have Wazuh rule level, not KDD categories) |
| **NSL-KDD**            | `src_bytes`, `dst_bytes`                            | `bytes_transferred` | `pd.to_numeric(src_bytes).fillna(0) + pd.to_numeric(dst_bytes).fillna(0)`                                                          | **YES** |                    NO                    |               **YES** (from Wazuh `data.size`)               |
| **NSL-KDD**            | `num_failed_logins`, `rerror_rate`, `serror_rate` | `failed_attempts`   | `int(num_failed_logins + rerror_rate * 100 + serror_rate * 50)`                                                                    | **YES** |                    NO                    |         **YES** (from Wazuh `data.failed_attempts`)         |
| **NSL-KDD**            | `cat` (from `label`)                                | `is_anomaly`        | `(cat != "normal").astype(int)`                                                                                                    |      NO      |              **YES**              |              **YES** (Evaluated in demo compare)              |
| **CICIDS-2017**        | `Label`                                               | `is_anomaly`        | `(Label.str.upper() != "BENIGN").astype(int)`                                                                                      |      NO      |              **YES**              |                            **YES**                            |
| **CICIDS-2017**        | `is_anomaly` (Target)                                 | `level`             | `is_anomaly.map({1: 13, 0: 2})`                                                                                                    | **YES** | **YES** (**Direct Leakage**) |           **NO** (Direct copy of ground-truth label)           |
| **CICIDS-2017**        | Fwd/Bwd Packet Lengths                                  | `bytes_transferred` | `fwd_bytes + bwd_bytes` or `packet_length_sum`                                                                                   | **YES** |                    NO                    |                            **YES**                            |
| **CICIDS-2017**        | TCP RST Flag Count                                      | `failed_attempts`   | `pd.to_numeric(rst_flag_col).fillna(0).astype(int)`                                                                                | **YES** |                    NO                    |            **NO** (TCP flag is not login failures)            |
| **UNSW-NB15**          | `label` / `attack_cat`                              | `is_anomaly`        | `(label != "normal").astype(int)`                                                                                                  |      NO      |              **YES**              |                            **YES**                            |
| **UNSW-NB15**          | `attack_cat`                                          | `level`             | `attack_cat.map(UNSW_ATTACK_LEVEL)`(normal: 2, dos: 13, exploits: 12, generic: 9, etc.)Fallback: `is_anomaly.map({1: 10, 0: 2})` | **YES** |        NO (Derived from target!)        |              **NO** (Mapped from attack category)              |
| **UNSW-NB15**          | `sbytes`, `dbytes` (or `spkts`, `dpkts`)        | `bytes_transferred` | `sbytes + dbytes` (fallback: `spkts + dpkts` $\rightarrow$ **packets treated as bytes!**)                                | **YES** |                    NO                    |                            **YES**                            |
| **UNSW-NB15**          | `state` (TCP State)                                   | `failed_attempts`   | `state.isin(["REJ","RSTO","RSTOS0","RSTR"]).astype(int) * 10`                                                                      | **YES** |                    NO                    |            **NO** (Connection resets scaled by 10)            |
| **Synthetic (CICIDS)** | Generated                                               | `level`             | Normal: $[1, 4]$, DDoS: $[11, 13]$, Botnet: $[10, 12]$, Web: $[9, 12]$                                                       | **YES** |         NO (Separated by design)         |                             **NO**                             |
| **Synthetic (CICIDS)** | Generated                                               | `bytes_transferred` | Normal: Exp(5000), DDoS: $[10\text{M}, 500\text{M}]$, Bot: $[50\text{K}, 2\text{M}]$                                             | **YES** |                    NO                    |                            **YES**                            |
| **Synthetic (CICIDS)** | Generated                                               | `failed_attempts`   | Normal: 0, DDoS: $[0, 2]$, Botnet: $[5, 29]$, Web: $[20, 199]$                                                                 | **YES** |                    NO                    |                            **YES**                            |
| **Synthetic (UNSW)**   | Generated                                               | `level`             | Normal: $[1, 3]$, Attack: $[12, 15]$                                                                                             | **YES** |         NO (Separated by design)         |                             **NO**                             |
| **Synthetic (UNSW)**   | Generated                                               | `bytes_transferred` | Normal: Exp(3000), Attack: Exp(8000)                                                                                                 | **YES** |                    NO                    |                            **YES**                            |
| **Synthetic (UNSW)**   | Generated                                               | `failed_attempts`   | Normal: 0, Attack: $[5, 49]$                                                                                                       | **YES** |         NO (Separated by design)         |                            **YES**                            |

### Semantic Inconsistencies Between Datasets

A critical flaw discovered in the feature engineering code is that **features with identical names measure completely different physical quantities across datasets**:

1. **`failed_attempts` is semantically inconsistent**:
   - **In NSL-KDD**: It combines actual host login failures with TCP connection error rates:
     $$
     \text{failed\_attempts} = \text{num\_failed\_logins} + 100 \times \text{rerror\_rate} + 50 \times \text{serror\_rate}
     $$
   - **In CICIDS-2017**: It is set to the count of TCP RST flags. A TCP reset flag indicates an abrupt connection teardown, which occurs during port scans, network timeouts, or web proxies—it is not an authentication failure.
   - **In UNSW-NB15**: It checks whether the TCP connection state string is in `["REJ", "RSTO", "RSTOS0", "RSTR"]` and multiplies by 10!
   - **In Live Inference (`alerts.json`)**: It reads `int(data.get("failed_attempts", 0))`, which is an application-level integer generated by SSH or IAM brute-force alerts.
2. **`bytes_transferred` packet fallback flaw in UNSW-NB15**:
   - Line 327 of `train_model.py`:
     ```python
     sbytes = next((c for c in df.columns if c in ("sbytes","src_bytes","spkts")), None)
     dbytes = next((c for c in df.columns if c in ("dbytes","dst_bytes","dpkts")), None)
     ```
   - If `sbytes` and `dbytes` are missing, the code falls back to `spkts` and `dpkts`. **Packets are packet counts (integers typically 1–100), not byte counts (typically thousands or millions)**. A transfer of 50 packets would be scaled as 50 bytes.

---

## 4. The Target-Label Leakage Problem

### What is Target Leakage?

Target leakage occurs when an input feature used by a machine learning model contains information about the target label that would not naturally be available at the time of inference. This allows the model to "cheat" during training and testing, achieving artificially high performance metrics that collapse when deployed on real, unlabelled data.

### Exact Code Trace of Leakage

#### 1. Direct Target Leakage in CICIDS-2017 (`train_model.py`, lines 173–196):

```python
# Line 173: Target label created from raw label
df["is_anomaly"] = (df[label_col].str.strip().str.upper() != "BENIGN").astype(int)

# Line 196: 'level' feature created directly from 'is_anomaly'
df["level"] = df["is_anomaly"].map({1: 13, 0: 2})
```

- **The Mechanism**: The feature `level` is an exact mathematical transformation of the target label `is_anomaly`. If `is_anomaly == 1`, `level = 13`. If `is_anomaly == 0`, `level = 2`.
- **The Impact**: The model does not need to learn anything about network traffic, IP addresses, or packet lengths. Any algorithm that checks if `level > 2` will achieve an immediate decision boundary.
- **Affected Model**: KNN (`knn.pkl`).

#### 2. Label Category Leakage in NSL-KDD (`train_model.py`, lines 104–116):

```python
df["cat"] = df["label"].map(lambda x: NSL_ATTACK_CATEGORY.get(x, "probe"))
df["level"] = df["cat"].map(NSL_LEVEL_MAP).fillna(8).astype(int)
df["is_anomaly"] = (df["cat"] != "normal").astype(int)
```

- **The Mechanism**: Both `level` and `is_anomaly` are derived from `cat`, which is the ground-truth attack classification. Normal traffic is assigned `level = 2`, while attacks are assigned `8`, `10`, `13`, or `14`.
- **The Impact**: Isolation Forest splits nodes by choosing random feature thresholds. In a 3-dimensional space where one dimension cleanly partitions normal traffic at 2 and attacks at $\ge 8$, the tree isolates normal records with minimal splits, inflating precision.
- **Affected Model**: Isolation Forest (`iforest.pkl`).

#### 3. Category Leakage in UNSW-NB15 (`train_model.py`, lines 310–324):

```python
df["is_anomaly"] = (df[label_col].str.strip().str.lower() != "normal").astype(int)
# If attack_cat column is present:
df["level"] = df[cat_col].map(lambda x: UNSW_ATTACK_LEVEL.get(x, 8))
# Fallback if attack_cat column is absent:
df["level"] = df["is_anomaly"].map({1: 10, 0: 2})
```

- **The Mechanism**: Similar to NSL-KDD, `level` is assigned based on the ground-truth attack class. If `attack_cat` is absent, the code falls back to direct label mapping (`10` for attack, `2` for normal).
- **Affected Model**: HBOS (`hbos.pkl`).

#### 4. Synthetic Fallback Leakage (`_synthetic_unsw()` lines 372–382):

```python
normal = pd.DataFrame({"level": np.random.randint(1, 4, n_normal), ...})  # Levels 1, 2, 3
attack = pd.DataFrame({"level": np.random.randint(12, 16, n_attack), ...}) # Levels 12, 13, 14, 15
```

- **The Mechanism**: Normal traffic is restricted to levels 1–3, while attacks are restricted to levels 12–15. There is **zero overlap** in the level distribution. Furthermore, normal traffic has `failed_attempts = 0`, while attacks have `failed_attempts >= 5`.
- **Why HBOS Scored 100%**: HBOS assumes feature independence and computes anomaly scores by building unigram histograms for each feature:
  $$
  \text{HBOS}(x) = \sum_{j=1}^{d} \log\left(\frac{1}{P(x_j)}\right)
  $$

  Because normal bins and attack bins are completely separated with large empty gaps, test attacks fell into bins with zero normal probability, resulting in infinite or maximal log scores. This explains why HBOS achieved $TP=3896, FP=0, FN=0, TN=10104$ (100% Precision, 100% Recall).

### Architectural Root Cause

Why did the author introduce this leakage?
In the live platform (`backend/simulator/wazuh_reader.py` and `backend/data/alerts.json`), events originate from Wazuh SIEM rules. Wazuh rules natively possess a `level` attribute (1 to 15) assigned by human security analysts.
The author wanted the machine learning models to accept `level` as an input feature during live inference. However, public intrusion datasets (NSL-KDD, CICIDS, UNSW) **do not have a Wazuh rule level**. Instead of computing an objective statistical metric (such as flow duration, packet rate, or entropy), the author retroactively manufactured `level` by mapping the target labels.

---

## 5. Training, Preprocessing, and Split Protocol

### Numerical Dataset Split Audit Table

| Model                      | Assigned Dataset     | Total Records |         Train Records         |         Test Records         | Train Anomaly Count | Test Anomaly Count | Train Contamination |
| :------------------------- | :------------------- | :-----------: | :---------------------------: | :--------------------------: | :-----------------: | :----------------: | :-----------------: |
| **Isolation Forest** | NSL-KDD (Real files) |    148,517    |   **125,973** (84.8%)   |   **22,544** (15.2%)   |       58,630       |       12,833       |   0.4654 (46.54%)   |
| **KNN (K=5)**        | Synthetic CICIDS     |    55,000    | **30,000** (subsampled) | **8,000** (subsampled) |        8,191        |       2,147       |   0.2730 (27.30%)   |
| **HBOS (bins=30)**   | Synthetic UNSW       |    70,000    |   **56,000** (80.0%)   |   **14,000** (20.0%)   |       16,104       |       3,896       |   0.2876 (28.76%)   |

### Preprocessing and Scaling Details

1. **Bytes Clipping ($P_{99}$)**:
   Network traffic datasets have extreme heavy-tailed distributions where a single multi-gigabyte transfer compresses all other records into a tiny fraction of the MinMax scale.
   `train_model.py` calculates the 99th percentile of `bytes_transferred` on the training matrix:
   ```python
   p99 = float(np.percentile(train_X[:, 1], 99))
   train_X[:, 1] = np.clip(train_X[:, 1], 0, p99)
   test_X[:, 1]  = np.clip(test_X[:, 1],  0, p99)
   ```

   - **NSL-KDD $P_{99}$**: **62,854.0 bytes**.
   - **Synthetic CICIDS $P_{99}$**: **441,255,511.75 bytes** (~441.26 MB).
   - **Synthetic UNSW $P_{99}$**: **27,332.70 bytes**.
2. **MinMax Scaling**:
   `scaler = MinMaxScaler()` is fitted on `train_X` and stored in `backend/models/scaler_<name>.pkl`.
   - Inspection of `scaler_iforest.pkl`:
     - Minimums: `[2.0, 0.0, 0.0]`
     - Maximums: `[14.0, 62854.0, 103.0]`
     - Scale factor: $\left[\frac{1}{12},\; \frac{1}{62854},\; \frac{1}{103}\right]$
   - Inspection of `scaler_knn.pkl`:
     - Minimums: `[1.0, 0.02768, 0.0]`
     - Maximums: `[13.0, 441255512.0, 199.0]`
   - Inspection of `scaler_hbos.pkl`:
     - Minimums: `[1.0, 0.00273, 0.0]`
     - Maximums: `[15.0, 27332.7, 49.0]`
3. **Data Leakage Check on Preprocessing**:
   - `MinMaxScaler` is properly fitted **only on the training split**, and `transform()` is called on test.
   - $P_{99}$ is properly computed **only on the training split**.
   - This part of the code follows scikit-learn best practices.
4. **Absence of Validation Set**:
   - In all three models, there is **no validation set** (`X_val`). Hyperparameters (`n_estimators=200`, `n_neighbors=5`, `n_bins=30`) and the probability threshold ($0.5$) were chosen arbitrarily without cross-validation or hyperparameter tuning.

---

## 6. Model Configurations and Hyperparameters

### Hyperparameter Comparison Table

| Hyperparameter / Setting         | Isolation Forest (`iforest`)        | K-Nearest Neighbors (`knn`)          | Histogram-based Outlier Score (`hbos`) |
| :------------------------------- | :------------------------------------ | :------------------------------------- | :--------------------------------------- |
| **PyOD Class**             | `pyod.models.iforest.IForest`       | `pyod.models.knn.KNN`                | `pyod.models.hbos.HBOS`                |
| **Model Type**             | Tree Ensemble (Isolation Trees)       | Distance-based (kth neighbor distance) | Statistical (Univariate Histograms)      |
| **Assigned Dataset**       | NSL-KDD                               | CICIDS-2017 (Synthetic)                | UNSW-NB15 (Synthetic)                    |
| **Primary Hyperparameter** | `n_estimators = 200`                | `n_neighbors = 5` ($K=5$)          | `n_bins = 30`                          |
| **Contamination Setting**  | `0.4654` (from train label mean)    | `0.2730` (from train label mean)     | `0.2876` (from train label mean)       |
| **Random State / Seed**    | `random_state = 42`                 | None (subsample uses seed 42)          | None                                     |
| **Parallelization**        | `n_jobs = -1` (all CPU cores)       | `n_jobs = -1` (all CPU cores)        | Single-threaded                          |
| **Decision Threshold**     | `probs > 0.5`                       | `probs > 0.5`                        | `probs > 0.5`                          |
| **Training Sample Size**   | 125,973                               | 30,000 (subsampled from 44,000)        | 56,000                                   |
| **Test Sample Size**       | 22,544                                | 8,000 (subsampled from 11,000)         | 14,000                                   |
| **Saved Model File**       | `backend/models/iforest.pkl`        | `backend/models/knn.pkl`             | `backend/models/hbos.pkl`              |
| **Saved Scaler File**      | `backend/models/scaler_iforest.pkl` | `backend/models/scaler_knn.pkl`      | `backend/models/scaler_hbos.pkl`       |

### Detailed Parameter Analysis

#### 1. What is $K$ in KNN?

In `train_model.py`, line 502:

```python
KNN(n_neighbors=5, n_jobs=-1)
```

- **Definition of $K$**: In PyOD's KNN implementation, $K$ represents the number of nearest neighbors used to compute the outlier score. By default, PyOD uses the distance to the $K^{\text{th}}$ nearest neighbor (`method='largest'`).
- **Meaning for Anomaly Detection**: If a data point is in a dense cluster of benign traffic, its 5th nearest neighbor is very close (small distance $\rightarrow$ low anomaly score). If a data point is an outlier, its 5th nearest neighbor is far away (large distance $\rightarrow$ high anomaly score).
- **Difference in Fallback Inference**:
  In `ml_engine.py` (line 231), if saved models are missing, the realtime fallback computes:
  ```python
  n_neighbors = min(5, len(events) - 1)
  ```

  If an event batch has only 4 events, $K$ automatically drops to 3.

#### 2. Contamination Calculation

In unsupervised anomaly detection, `contamination` specifies the expected proportion of outliers in the data.
Lines 439–441 of `train_model.py`:

```python
contamination = float(train_df["is_anomaly"].mean())
contamination = max(0.01, min(0.49, contamination))
model.contamination = contamination
```

- The code uses ground-truth labels to compute the exact training anomaly fraction.
- While common in academic benchmarks to calibrate PyOD's internal threshold offset, in a true unsupervised deployment, ground-truth anomaly fraction is unknown.

---

## 7. Audit of Previously Recorded Evaluation Results

The table below reproduces the historical metrics recorded in `backend/models/training_meta.json`.

> **CRITICAL NOTE FOR PERSON 1:** These results are historical records from an earlier script execution. As proven in Sections 2 and 4, **they cannot be presented in an IEEE paper or project report as trustworthy metrics of real-world intrusion detection**.

### Recorded Performance Table (`training_meta.json`)

| Model                      | Claimed Dataset | Actual Training Source            | Train Samples | Test Samples |     Accuracy     |     Precision     |      Recall      |     F1-Score     |       FPR       |  TP  | FP |  FN  |   TN   |
| :------------------------- | :-------------- | :-------------------------------- | :-----------: | :----------: | :---------------: | :---------------: | :---------------: | :---------------: | :-------------: | :---: | :-: | :---: | :----: |
| **Isolation Forest** | NSL-KDD         | Real `KDDTrain+.txt`            |    125,973    |    22,544    | **67.25%** | **91.31%** | **46.93%** | **62.00%** | **5.90%** | 6,023 | 573 | 6,810 | 9,138 |
| **KNN (K=5)**        | CICIDS-2017     | Synthetic (`_synthetic_cicids`) |    30,000    |    8,000    | **76.85%** | **100.00%** | **13.74%** | **24.16%** | **0.00%** |  295  |  0  | 1,852 | 5,853 |
| **HBOS (30 bins)**   | UNSW-NB15       | Synthetic (`_synthetic_unsw`)   |    56,000    |    14,000    | **100.00%** | **100.00%** | **100.00%** | **100.00%** | **0.00%** | 3,896 |  0  |   0   | 10,104 |

### Mathematical Breakdown of Formulas

1. **Accuracy**:
   $$
   \text{Accuracy} = \frac{TP + TN}{TP + TN + FP + FN}
   $$

   - Isolation Forest: $\frac{6023 + 9138}{22544} = \frac{15161}{22544} \approx 67.2507\% \rightarrow \mathbf{67.25\%}$
   - KNN: $\frac{295 + 5853}{8000} = \frac{6148}{8000} \approx 76.8500\% \rightarrow \mathbf{76.85\%}$
   - HBOS: $\frac{3896 + 10104}{14000} = \frac{14000}{14000} = \mathbf{100.00\%}$
2. **Precision**:
   $$
   \text{Precision} = \frac{TP}{TP + FP}
   $$

   - Isolation Forest: $\frac{6023}{6023 + 573} = \frac{6023}{6596} \approx 91.3129\% \rightarrow \mathbf{91.31\%}$
   - KNN: $\frac{295}{295 + 0} = \mathbf{100.00\%}$
   - HBOS: $\frac{3896}{3896 + 0} = \mathbf{100.00\%}$
3. **Recall (Detection Rate)**:
   $$
   \text{Recall} = \frac{TP}{TP + FN}
   $$

   - Isolation Forest: $\frac{6023}{6023 + 6810} = \frac{6023}{12833} \approx 46.9337\% \rightarrow \mathbf{46.93\%}$
   - KNN: $\frac{295}{295 + 1852} = \frac{295}{2147} \approx 13.7401\% \rightarrow \mathbf{13.74\%}$
   - HBOS: $\frac{3896}{3896 + 0} = \mathbf{100.00\%}$
4. **F1-Score**:
   $$
   \text{F1} = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}
   $$

   - Isolation Forest: $2 \times \frac{0.913129 \times 0.469337}{0.913129 + 0.469337} \approx 62.0006\% \rightarrow \mathbf{62.00\%}$
   - KNN: $2 \times \frac{1.0 \times 0.137401}{1.0 + 0.137401} \approx 24.1607\% \rightarrow \mathbf{24.16\%}$
   - HBOS: $\mathbf{100.00\%}$
5. **False Positive Rate (FPR)**:
   $$
   \text{FPR} = \frac{FP}{FP + TN}
   $$

   - Isolation Forest: $\frac{573}{573 + 9138} = \frac{573}{9711} \approx 5.9005\% \rightarrow \mathbf{5.90\%}$
   - KNN: $\frac{0}{5853} = \mathbf{0.00\%}$
   - HBOS: $\frac{0}{10104} = \mathbf{0.00\%}$

### Why These Results Cannot Be Trusted

1. **The 100% HBOS Result**:
   Any security paper claiming 100% precision, 100% recall, and 100% accuracy on intrusion detection will be instantly rejected by academic reviewers. It occurred solely because synthetic normal traffic had `level <= 3` and `failed_attempts == 0`, while synthetic attack traffic had `level >= 12` and `failed_attempts >= 5`.
2. **The 13.74% KNN Recall Result**:
   KNN failed to detect over 86% of the attack samples in its test set ($FN = 1,852$). Because KNN computes Euclidean distance in $[0, 1]^3$, high-volume DDoS attacks and low-volume Web attacks occupied different clusters, and the distance to the 5th nearest neighbor in sparse regions failed to trigger the fixed $0.5$ threshold.
3. **Target Leakage in NSL-KDD**:
   Even though NSL-KDD used real data files, `level` was directly generated from `label`. Despite this leakage, Isolation Forest achieved only 46.93% recall, indicating that Isolation Forest struggled to detect the 17 new attack types present in `KDDTest+.txt`.

---

## 8. Real-Time Inference Pipeline (`backend/engines/ml_engine.py`)

### 1. Model Loading (`_load()`)

On application startup or module import:

```python
def _load():
    for name in ["iforest", "knn", "hbos"]:
        m_path = os.path.join(MODELS_DIR, f"{name}.pkl")
        s_path = os.path.join(MODELS_DIR, f"scaler_{name}.pkl")
        if os.path.exists(m_path) and os.path.exists(s_path):
            models[name]  = joblib.load(m_path)
            scalers[name] = joblib.load(s_path)
```

If all three `.pkl` files and scalers exist, `PRETRAINED = True`. If any file is missing, `PRETRAINED = False`.

### 2. Live Feature Extraction & Missing Value Handling

When an API endpoint calls `analyze_events(events)`:

```python
df    = pd.DataFrame(events)
X_raw = df[FEATURES].fillna(0).values.astype(float)
```

- Missing fields (`level`, `bytes_transferred`, or `failed_attempts`) are imputed with `0.0` via `.fillna(0)`.
- If an event has no `bytes_transferred`, it defaults to 0.

### 3. Dedicated Per-Model Scaling (`_scale_for()`)

Each model receives its own scaled matrix because each model was trained with different $P_{99}$ clipping values and MinMax parameters:

```python
def _scale_for(name: str, X: np.ndarray) -> np.ndarray:
    scaler = _SCALERS[name]
    p99    = _META["models"][name]["p99_bytes_clip"] if _META else 1e9
    X      = X.copy()
    X[:, 1] = np.clip(X[:, 1], 0, p99)
    return scaler.transform(X)
```

### 4. Competitive Maximum Score Ensemble

Lines 147–153 of `ml_engine.py`:

```python
all_scores = _score_all(X_raw) # Dict: name -> array of probabilities
score_matrix = np.column_stack(list(all_scores.values()))
model_names  = list(all_scores.keys())
final_scores = score_matrix.max(axis=1)
best_model_idx = score_matrix.argmax(axis=1)
threshold = 0.5
```

- For every event, the final anomaly score is:
  $$
  \text{final\_score} = \max(S_{\text{iforest}}, S_{\text{knn}}, S_{\text{hbos}})
  $$
- If $\text{final\_score} > 0.5$, the event is flagged as an anomaly (`is_anomaly = True`).
- Severity mapping:
  - $\text{score} > 0.90 \rightarrow \mathbf{Critical}$
  - $\text{score} > 0.75 \rightarrow \mathbf{High}$
  - $\text{score} > 0.50 \rightarrow \mathbf{Medium}$
  - $\text{score} \le 0.50 \rightarrow \mathbf{Low}$

### 5. Fallback Path if Models are Missing

If `.pkl` files are deleted or not found:

```python
clf = IForest(contamination=0.15, random_state=42, n_estimators=100)
clf.fit(X_raw)
final_scores = clf.predict_proba(X_raw)[:, 1]
threshold = 0.65
```

- The backend fits a temporary Isolation Forest on the fly using the incoming batch.
- **Limitation**: Fitting a model on 30 events in real time is statistically unreliable and computationally expensive for high-frequency API endpoints.

### 6. Audit of `/api/ml/compare` (`compare_models()`)

The model comparison endpoint in `ml_engine.py`:

- Accepts an event batch (from simulated session or Wazuh log).
- Extracts ground truth using:
  ```python
  y_true = np.array([1 if e.get("event_type") == "attack" else 0 for e in events])
  ```
- Evaluates all three models against this simulated batch and returns a live confusion matrix.
- **CRITICAL OBSERVATION**: `/api/ml/compare` **does NOT evaluate against a genuine held-out research benchmark**. It tests the models against the platform's own simulated demo events generated by `wazuh_simulator.py`.

---

## 9. Master Reference Tables

### Table 1: Complete Dataset Inventory

| Dataset Identifier          | Real / Synthetic   | Location            | Files Present     |  Rows  | Cols | Status            |
| :-------------------------- | :----------------- | :------------------ | :---------------- | :-----: | :--: | :---------------- |
| **NSL-KDD Train**     | Real Benchmark     | `backend/data/`   | `KDDTrain+.txt` | 125,973 |  43  | Fully Verified    |
| **NSL-KDD Test**      | Real Benchmark     | `backend/data/`   | `KDDTest+.txt`  | 22,544 |  43  | Fully Verified    |
| **CICIDS-2017**       | Synthetic Fallback | Generated in memory | None on disk      | 55,000 |  4  | Real data missing |
| **UNSW-NB15**         | Synthetic Fallback | Generated in memory | None on disk      | 70,000 |  4  | Real data missing |
| **Wazuh Live Alerts** | Simulated Logs     | `backend/data/`   | `alerts.json`   |  5,001  | JSON | Active Log Source |

### Table 2: Model Configuration & Hyperparameters

| Model Parameter                | Isolation Forest                    | K-Nearest Neighbors                 | Histogram Outlier (HBOS)            |
| :----------------------------- | :---------------------------------- | :---------------------------------- | :---------------------------------- |
| **Algorithm Family**     | Tree-based Partitioning             | Distance to $K$-th Neighbor       | Independent Feature Histograms      |
| **Key Hyperparameter**   | `n_estimators = 200`              | `n_neighbors = 5`                 | `n_bins = 30`                     |
| **Parallel Execution**   | `n_jobs = -1`                     | `n_jobs = -1`                     | Single thread                       |
| **Random State**         | `42`                              | `42` (during subsample)           | None                                |
| **Contamination**        | 0.4654                              | 0.2730                              | 0.2876                              |
| **$P_{99}$ Byte Clip** | 62,854.0                            | 441,255,511.75                      | 27,332.70                           |
| **Decision Threshold**   | $> 0.5$                           | $> 0.5$                           | $> 0.5$                           |
| **Input Features**       | 3 (`level`, `bytes`, `fails`) | 3 (`level`, `bytes`, `fails`) | 3 (`level`, `bytes`, `fails`) |

### Table 3: Summary of Previously Recorded Metrics

| Model Name                 | Training Dataset | Accuracy | Precision | Recall | F1 Score | False Positive Rate |
| :------------------------- | :--------------- | :------: | :-------: | :-----: | :------: | :-----------------: |
| **Isolation Forest** | NSL-KDD          |  67.25%  |  91.31%  | 46.93% |  62.00%  |        5.90%        |
| **KNN ($K=5$)**    | Synthetic CICIDS |  76.85%  |  100.00%  | 13.74% |  24.16%  |        0.00%        |
| **HBOS (30 bins)**   | Synthetic UNSW   | 100.00% |  100.00%  | 100.00% | 100.00% |        0.00%        |

---

## 10. Summary of Architectural Flaws & Actionable Next Steps for Person 1

### Key Architectural Problems Identified

1. **Catastrophic Target Leakage**:
   Mapping ground-truth labels directly to `level` gives the unsupervised models the evaluation answers. Models learn to check if `level >= 8` rather than learning anomalous traffic patterns.
2. **Missing Real Datasets for CICIDS and UNSW**:
   Two of the three models were trained on synthetic data generated by hardcoded random number generators. Their metrics do not reflect actual detection of modern network attacks.
3. **Extreme Semantic Inconsistency in Features**:
   - `failed_attempts` represents login failures in NSL-KDD, TCP RST packets in CICIDS, and connection state strings $\times 10$ in UNSW.
   - `bytes_transferred` falls back to packet counts in UNSW.
4. **Ensemble Maximum Incoherence**:
   Taking the maximum score across three models trained on three different datasets (one real, two synthetic) with different scalers assumes their calibrated probabilities are on the same scale. In reality, a score of 0.8 from HBOS does not represent the same statistical anomaly confidence as 0.8 from Isolation Forest.
5. **Lack of Validation Set and Threshold Tuning**:
   The $0.5$ decision threshold is arbitrary and was not optimized using precision-recall curves or ROC-AUC analysis.

### Actionable Roadmap for Person 1

To transform this implementation into a publishable, production-ready machine learning system:

- [ ] **Step 1: Download and Place Real Datasets Locally**:
  Download real CSV files for CICIDS-2017 (`Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`) and UNSW-NB15 (`UNSW_NB15_training-set.csv` and `testing-set.csv`) and place them in `backend/data/` so synthetic fallback is never triggered.
- [ ] **Step 2: Eliminate Target Leakage from `level`**:
  Do not compute `level` from labels. Either:
  - Remove `level` from the training feature set entirely and train models on objective telemetry features (e.g., bytes, duration, packet counts, error rates).
  - Or, if `level` is required for live Wazuh alignment, calculate `level` from an independent heuristics function based purely on raw traffic statistics without access to `label` or `attack_cat`.
- [ ] **Step 3: Standardize Feature Semantics**:
  Ensure that `bytes_transferred` always measures byte count (never packet count) and that error/failure features are measured identically across datasets.
- [ ] **Step 4: Implement a Proper Validation Set & Cross-Validation**:
  Implement an 70/15/15 train/validation/test split. Use the validation split to tune hyperparameters ($K$ in KNN, `n_bins` in HBOS, `n_estimators` in IForest) and select optimal decision thresholds.
- [ ] **Step 5: Calibrate Ensemble Scores**:
  Instead of raw $\max(S_1, S_2, S_3)$, apply probability calibration (such as Platt scaling or isotonic regression on validation data) so that anomaly scores from different models represent comparable posterior probabilities.
- [ ] **Step 6: Reproduce and Document Verified Experiments**:
  Run `train_model.py` with logging of dataset MD5 checksums, exact row counts, and confusion matrices. Update `training_meta.json` with genuine, un-leaked experimental results suitable for inclusion in the IEEE research paper.

---

*Report compiled and verified against codebase on October 22, 2026.*
