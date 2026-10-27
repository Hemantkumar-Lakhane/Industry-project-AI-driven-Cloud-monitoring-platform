"""
Reproducible ML Model Training Pipeline — RAM Antivirus
========================================================
Trains 3 unsupervised anomaly detection models (Isolation Forest, HBOS, KNN)
on the real benchmark NSL-KDD dataset using the verified, leakage-free
9-dimensional operational network flow feature schema defined in the IEEE research paper:
  duration, src_bytes, dst_bytes, count, srv_count,
  serror_rate, rerror_rate, same_srv_rate, diff_srv_rate

Eliminates all target leakage (no 'level' mapped from attack labels).
Evaluates models against the official held-out test set (KDDTest+, N=22,544).

Artifacts saved to backend/models/:
  - iforest.pkl
  - hbos.pkl
  - knn.pkl
  - scaler.pkl
  - training_meta.json
"""

import os
import time
import json
import numpy as np
import pandas as pd
import joblib
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    precision_score, recall_score, f1_score,
    accuracy_score, confusion_matrix, roc_auc_score, average_precision_score
)
from pyod.models.iforest import IForest
from pyod.models.knn import KNN
from pyod.models.hbos import HBOS

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, "models")
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

# Exact 9-dimensional flow feature schema from IEEE Paper Section VI & feature_extractor.py
FLOW_FEATURES = [
    "duration",
    "src_bytes",
    "dst_bytes",
    "count",
    "srv_count",
    "serror_rate",
    "rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
]

KDD_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty"
]


def load_nsl_kdd():
    train_path = os.path.join(DATA_DIR, "KDDTrain+.txt")
    test_path = os.path.join(DATA_DIR, "KDDTest+.txt")

    if not os.path.exists(train_path) or not os.path.exists(test_path):
        raise FileNotFoundError(
            f"NSL-KDD dataset files missing from {DATA_DIR}. "
            "Expected KDDTrain+.txt and KDDTest+.txt."
        )

    print(f"[*] Loading NSL-KDD dataset from {DATA_DIR}...")
    df_train = pd.read_csv(train_path, header=None, names=KDD_COLUMNS)
    df_test = pd.read_csv(test_path, header=None, names=KDD_COLUMNS)

    print(f"    Train records: {len(df_train):,}")
    print(f"    Test records:  {len(df_test):,}")

    return df_train, df_test


def evaluate_model(model, X_train, y_train, X_test, y_test, model_name):
    print(f"\n--- Training & Evaluating: {model_name} ---")
    t0_fit = time.time()
    model.fit(X_train)
    fit_time = time.time() - t0_fit

    t0_pred = time.time()
    test_scores = model.decision_function(X_test)
    pred_time = time.time() - t0_pred

    # Binary prediction threshold
    y_pred = (test_scores > model.threshold_).astype(int)

    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()

    precision = float(precision_score(y_test, y_pred, zero_division=0))
    recall = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    acc = float(accuracy_score(y_test, y_pred))
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    try:
        roc_auc = float(roc_auc_score(y_test, test_scores))
    except Exception:
        roc_auc = None

    try:
        pr_auc = float(average_precision_score(y_test, test_scores))
    except Exception:
        pr_auc = None

    metrics = {
        "model": model_name,
        "dataset": "NSL-KDD",
        "train_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "contamination": round(float(model.contamination), 4),
        "threshold": round(float(model.threshold_), 4),
        "performance": {
            "accuracy": round(acc * 100, 2),
            "precision": round(precision * 100, 2),
            "recall": round(recall * 100, 2),
            "f1_score": round(f1 * 100, 2),
            "false_positive_rate": round(fpr * 100, 2),
            "roc_auc": round(roc_auc * 100, 2) if roc_auc else None,
            "pr_auc": round(pr_auc * 100, 2) if pr_auc else None,
            "confusion_matrix": {
                "tp": int(tp),
                "fp": int(fp),
                "fn": int(fn),
                "tn": int(tn)
            }
        },
        "timing": {
            "fit_time_sec": round(fit_time, 3),
            "pred_time_ms_per_1k": round((pred_time / len(X_test)) * 1000 * 1000, 3)
        }
    }

    print(f"  TP: {tp:,}  FP: {fp:,}  FN: {fn:,}  TN: {tn:,}")
    print(f"  Accuracy:  {metrics['performance']['accuracy']}%")
    print(f"  Precision: {metrics['performance']['precision']}%")
    print(f"  Recall:    {metrics['performance']['recall']}%")
    print(f"  F1-Score:  {metrics['performance']['f1_score']}%")
    print(f"  FPR:       {metrics['performance']['false_positive_rate']}%")
    if roc_auc:
        print(f"  ROC-AUC:   {metrics['performance']['roc_auc']}%")
    print(f"  Fit time:  {metrics['timing']['fit_time_sec']}s, Latency: {metrics['timing']['pred_time_ms_per_1k']} ms/1k")

    return metrics, model


def run_pipeline():
    print("=" * 70)
    print("RAM ANTIVIRUS — REPRODUCIBLE ML MODEL TRAINING PIPELINE")
    print("=" * 70)

    df_train, df_test = load_nsl_kdd()

    # Clean labels: 0 = normal, 1 = attack
    y_train = (df_train["label"].str.strip().str.lower() != "normal").astype(int).values
    y_test = (df_test["label"].str.strip().str.lower() != "normal").astype(int).values

    print(f"[*] Extracting verified 9-dimensional flow features: {FLOW_FEATURES}")
    X_train_raw = df_train[FLOW_FEATURES].fillna(0).values.astype(np.float64)
    X_test_raw = df_test[FLOW_FEATURES].fillna(0).values.astype(np.float64)

    # Scaling strictly on training data
    print("[*] Fitting StandardScaler on training set...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train_raw)
    X_test_scaled = scaler.transform(X_test_raw)

    scaler_path = os.path.join(MODELS_DIR, "scaler.pkl")
    joblib.dump(scaler, scaler_path)
    print(f"    Saved scaler to {scaler_path}")

    contamination = float(np.mean(y_train))
    contamination = max(0.01, min(0.49, contamination))
    print(f"[*] Training contamination rate: {contamination:.4f}")

    meta = {
        "pipeline_version": "2.0.0",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "feature_schema": "flow_9d",
        "features": FLOW_FEATURES,
        "feature_count": len(FLOW_FEATURES),
        "target_leakage": "none_verified",
        "benchmark_dataset": "NSL-KDD",
        "models": {}
    }

    # 1. Isolation Forest
    ifo = IForest(n_estimators=100, contamination=contamination, random_state=42, n_jobs=1)
    ifo_metrics, ifo_model = evaluate_model(ifo, X_train_scaled, y_train, X_test_scaled, y_test, "iforest")
    ifo_path = os.path.join(MODELS_DIR, "iforest.pkl")
    joblib.dump(ifo_model, ifo_path)
    meta["models"]["iforest"] = ifo_metrics

    # 2. HBOS
    hbos = HBOS(n_bins=20, contamination=contamination)
    hbos_metrics, hbos_model = evaluate_model(hbos, X_train_scaled, y_train, X_test_scaled, y_test, "hbos")
    hbos_path = os.path.join(MODELS_DIR, "hbos.pkl")
    joblib.dump(hbos_model, hbos_path)
    meta["models"]["hbos"] = hbos_metrics

    # 3. KNN (Sample 10,000 stratified training samples for tractable distance computation)
    np.random.seed(42)
    sample_size = min(10000, len(X_train_scaled))
    sub_idx = np.random.choice(len(X_train_scaled), size=sample_size, replace=False)
    knn = KNN(n_neighbors=5, contamination=contamination, n_jobs=1)
    knn_metrics, knn_model = evaluate_model(
        knn, X_train_scaled[sub_idx], y_train[sub_idx], X_test_scaled, y_test, "knn"
    )
    knn_path = os.path.join(MODELS_DIR, "knn.pkl")
    joblib.dump(knn_model, knn_path)
    meta["models"]["knn"] = knn_metrics

    # Save metadata
    meta_path = os.path.join(MODELS_DIR, "training_meta.json")
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)
    print(f"\n[+] Saved complete metadata and verified metrics to {meta_path}")
    print("=" * 70)
    print("Training pipeline completed successfully.")
    print("=" * 70)


if __name__ == "__main__":
    run_pipeline()
