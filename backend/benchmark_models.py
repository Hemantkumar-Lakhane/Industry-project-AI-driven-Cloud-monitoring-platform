"""
RAM Antivirus — Multi-Algorithm Benchmark Suite
=================================================
Benchmarks 7 candidate algorithms on the NSL-KDD benchmark dataset
using the verified 9-dimensional flow feature schema from IEEE paper Section VI:
  - Isolation Forest (Unsupervised tree-based)
  - HBOS (Unsupervised histogram density)
  - k-Nearest Neighbors (Unsupervised distance-based)
  - Local Outlier Factor (Unsupervised local density)
  - One-Class SVM (Unsupervised kernel boundary)
  - Random Forest Classifier (Supervised non-linear ensemble baseline)
  - Logistic Regression (Supervised linear baseline)

Outputs complete evaluation metrics, confusion matrices, timings,
and saves results to backend/models/benchmark_results.json.
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
from pyod.models.hbos import HBOS
from pyod.models.knn import KNN
from pyod.models.lof import LOF
from pyod.models.ocsvm import OCSVM
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, "models")
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(MODELS_DIR, exist_ok=True)

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


def load_dataset():
    train_path = os.path.join(DATA_DIR, "KDDTrain+.txt")
    test_path = os.path.join(DATA_DIR, "KDDTest+.txt")
    if not os.path.exists(train_path) or not os.path.exists(test_path):
        raise FileNotFoundError(f"Missing NSL-KDD dataset files in {DATA_DIR}")

    print(f"[*] Loading NSL-KDD dataset from {DATA_DIR}...")
    df_train = pd.read_csv(train_path, header=None, names=KDD_COLUMNS)
    df_test = pd.read_csv(test_path, header=None, names=KDD_COLUMNS)

    y_train = (df_train["label"].str.strip().str.lower() != "normal").astype(int).values
    y_test = (df_test["label"].str.strip().str.lower() != "normal").astype(int).values

    X_train_raw = df_train[FLOW_FEATURES].fillna(0).values.astype(np.float64)
    X_test_raw = df_test[FLOW_FEATURES].fillna(0).values.astype(np.float64)

    print(f"    Train records: {len(X_train_raw):,} | Test records: {len(X_test_raw):,}")
    print(f"    Features ({len(FLOW_FEATURES)}D): {FLOW_FEATURES}")

    # Standard scaling strictly on train
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train_raw)
    X_test_scaled = scaler.transform(X_test_raw)

    return X_train_scaled, y_train, X_test_scaled, y_test


def evaluate_candidate(name, model, X_train, y_train, X_test, y_test, is_supervised=False):
    print(f"\n[{name}] Training...")
    t0_fit = time.time()
    if is_supervised:
        model.fit(X_train, y_train)
    else:
        model.fit(X_train)
    fit_time = time.time() - t0_fit

    print(f"[{name}] Predicting on held-out test set (N={len(X_test):,})...")
    t0_pred = time.time()
    if is_supervised:
        test_scores = model.predict_proba(X_test)[:, 1]
        y_pred = (test_scores >= 0.5).astype(int)
    else:
        test_scores = model.decision_function(X_test)
        y_pred = (test_scores > model.threshold_).astype(int)
    pred_time = time.time() - t0_pred

    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    try:
        roc_auc = float(roc_auc_score(y_test, test_scores))
    except Exception:
        roc_auc = None

    try:
        pr_auc = float(average_precision_score(y_test, test_scores))
    except Exception:
        pr_auc = None

    latency_ms_per_1k = (pred_time / len(X_test)) * 1000 * 1000

    print(f"  Accuracy:  {acc * 100:.2f}% | Precision: {prec * 100:.2f}% | Recall: {rec * 100:.2f}%")
    print(f"  F1-Score:  {f1 * 100:.2f}% | FPR: {fpr * 100:.2f}% | ROC-AUC: {roc_auc * 100 if roc_auc else 0:.2f}%")
    print(f"  Fit time:  {fit_time:.3f}s | Latency: {latency_ms_per_1k:.3f} ms / 1k records")
    print(f"  Confusion Matrix: TP={tp:,}, FP={fp:,}, FN={fn:,}, TN={tn:,}")

    return {
        "model_name": name,
        "paradigm": "Supervised" if is_supervised else "Unsupervised Anomaly Detection",
        "train_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "accuracy": round(float(acc * 100), 2),
        "precision": round(float(prec * 100), 2),
        "recall": round(float(rec * 100), 2),
        "f1_score": round(float(f1 * 100), 2),
        "false_positive_rate": round(float(fpr * 100), 2),
        "roc_auc": round(float(roc_auc * 100), 2) if roc_auc else None,
        "pr_auc": round(float(pr_auc * 100), 2) if pr_auc else None,
        "confusion_matrix": {"tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn)},
        "timing": {
            "fit_time_seconds": round(float(fit_time), 3),
            "inference_latency_ms_per_1k": round(float(latency_ms_per_1k), 3)
        }
    }


def run_benchmark():
    print("=" * 80)
    print("RAM ANTIVIRUS — COMPREHENSIVE MULTI-ALGORITHM BENCHMARK")
    print("=" * 80)

    X_train, y_train, X_test, y_test = load_dataset()
    contamination = float(np.mean(y_train))
    contamination = max(0.01, min(0.49, contamination))
    print(f"[*] Base empirical contamination: {contamination:.4f}")

    # For quadratic distance models (KNN, LOF, OCSVM), extract a stratified representative subset
    np.random.seed(42)
    sample_size = 10000
    subset_idx = np.random.choice(len(X_train), size=sample_size, replace=False)
    X_train_sub = X_train[subset_idx]
    y_train_sub = y_train[subset_idx]

    benchmark_results = {}

    # 1. Isolation Forest (Unsupervised Tree)
    iforest = IForest(n_estimators=100, contamination=contamination, random_state=42, n_jobs=1)
    benchmark_results["Isolation Forest"] = evaluate_candidate(
        "Isolation Forest", iforest, X_train, y_train, X_test, y_test, is_supervised=False
    )

    # 2. Histogram-Based Outlier Score (HBOS, Linear time density)
    hbos = HBOS(n_bins=20, contamination=contamination)
    benchmark_results["HBOS"] = evaluate_candidate(
        "HBOS", hbos, X_train, y_train, X_test, y_test, is_supervised=False
    )

    # 3. k-Nearest Neighbors (KNN, Distance density)
    knn = KNN(n_neighbors=5, contamination=contamination, n_jobs=1)
    benchmark_results["KNN"] = evaluate_candidate(
        "KNN", knn, X_train_sub, y_train_sub, X_test, y_test, is_supervised=False
    )

    # 4. Local Outlier Factor (LOF with novelty detection)
    lof = LOF(n_neighbors=20, contamination=contamination, novelty=True, n_jobs=1)
    benchmark_results["Local Outlier Factor (LOF)"] = evaluate_candidate(
        "Local Outlier Factor (LOF)", lof, X_train_sub, y_train_sub, X_test, y_test, is_supervised=False
    )

    # 5. One-Class SVM (OCSVM with RBF kernel)
    ocsvm = OCSVM(kernel="rbf", gamma="scale", contamination=contamination)
    benchmark_results["One-Class SVM"] = evaluate_candidate(
        "One-Class SVM", ocsvm, X_train_sub, y_train_sub, X_test, y_test, is_supervised=False
    )

    # 6. Random Forest Classifier (Supervised Ensemble Baseline)
    rf = RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42, n_jobs=1)
    benchmark_results["Random Forest (Supervised)"] = evaluate_candidate(
        "Random Forest (Supervised)", rf, X_train, y_train, X_test, y_test, is_supervised=True
    )

    # 7. Logistic Regression (Supervised Linear Baseline)
    lr = LogisticRegression(max_iter=1000, random_state=42)
    benchmark_results["Logistic Regression (Supervised)"] = evaluate_candidate(
        "Logistic Regression (Supervised)", lr, X_train, y_train, X_test, y_test, is_supervised=True
    )
    # 8. Ensemble Evaluator (Isolation Forest + HBOS + KNN)
    print("\n--- Evaluating 3-Model Operational Ensemble ---")
    ifo_pred = (iforest.decision_function(X_test) > iforest.threshold_).astype(int)
    hbos_pred = (hbos.decision_function(X_test) > hbos.threshold_).astype(int)
    knn_pred = (knn.decision_function(X_test) > knn.threshold_).astype(int)
    vote_matrix = np.column_stack([ifo_pred, hbos_pred, knn_pred])

    # Ensemble: Majority Voting
    pred_maj = (np.sum(vote_matrix, axis=1) >= 2).astype(int)
    cm_maj = confusion_matrix(y_test, pred_maj)
    tn_m, fp_m, fn_m, tp_m = cm_maj.ravel()
    benchmark_results["Ensemble (Majority Voting)"] = {
        "model_name": "Ensemble (Majority Voting)",
        "paradigm": "Multi-Model Ensemble",
        "train_samples": 125973,
        "test_samples": len(X_test),
        "accuracy": round(float(accuracy_score(y_test, pred_maj) * 100), 2),
        "precision": round(float(precision_score(y_test, pred_maj, zero_division=0) * 100), 2),
        "recall": round(float(recall_score(y_test, pred_maj, zero_division=0) * 100), 2),
        "f1_score": round(float(f1_score(y_test, pred_maj, zero_division=0) * 100), 2),
        "false_positive_rate": round(float((fp_m / (fp_m + tn_m)) * 100), 2),
        "roc_auc": round(float(roc_auc_score(y_test, np.mean(vote_matrix, axis=1)) * 100), 2),
        "pr_auc": round(float(average_precision_score(y_test, np.mean(vote_matrix, axis=1)) * 100), 2),
        "confusion_matrix": {"tp": int(tp_m), "fp": int(fp_m), "fn": int(fn_m), "tn": int(tn_m)},
        "timing": {
            "fit_time_seconds": round(float(benchmark_results["Isolation Forest"]["timing"]["fit_time_seconds"] + benchmark_results["HBOS"]["timing"]["fit_time_seconds"] + benchmark_results["KNN"]["timing"]["fit_time_seconds"]), 3),
            "inference_latency_ms_per_1k": round(float(benchmark_results["Isolation Forest"]["timing"]["inference_latency_ms_per_1k"] + benchmark_results["HBOS"]["timing"]["inference_latency_ms_per_1k"] + benchmark_results["KNN"]["timing"]["inference_latency_ms_per_1k"]), 3)
        }
    }

    # Ensemble: Union / Max Recall (OR Logic)
    pred_any = (np.sum(vote_matrix, axis=1) >= 1).astype(int)
    cm_any = confusion_matrix(y_test, pred_any)
    tn_a, fp_a, fn_a, tp_a = cm_any.ravel()
    benchmark_results["Ensemble (Max Recall / OR)"] = {
        "model_name": "Ensemble (Max Recall / OR)",
        "paradigm": "Multi-Model Ensemble",
        "train_samples": 125973,
        "test_samples": len(X_test),
        "accuracy": round(float(accuracy_score(y_test, pred_any) * 100), 2),
        "precision": round(float(precision_score(y_test, pred_any, zero_division=0) * 100), 2),
        "recall": round(float(recall_score(y_test, pred_any, zero_division=0) * 100), 2),
        "f1_score": round(float(f1_score(y_test, pred_any, zero_division=0) * 100), 2),
        "false_positive_rate": round(float((fp_a / (fp_a + tn_a)) * 100), 2),
        "roc_auc": round(float(roc_auc_score(y_test, np.mean(vote_matrix, axis=1)) * 100), 2),
        "pr_auc": round(float(average_precision_score(y_test, np.mean(vote_matrix, axis=1)) * 100), 2),
        "confusion_matrix": {"tp": int(tp_a), "fp": int(fp_a), "fn": int(fn_a), "tn": int(tn_a)},
        "timing": {
            "fit_time_seconds": benchmark_results["Ensemble (Majority Voting)"]["timing"]["fit_time_seconds"],
            "inference_latency_ms_per_1k": benchmark_results["Ensemble (Majority Voting)"]["timing"]["inference_latency_ms_per_1k"]
        }
    }

    output_path = os.path.join(MODELS_DIR, "benchmark_results.json")
    with open(output_path, "w") as f:
        json.dump(benchmark_results, f, indent=2)

    print("\n" + "=" * 80)
    print(f"[+] Multi-algorithm & ensemble benchmark complete! Results saved to {output_path}")
    print("=" * 80)


if __name__ == "__main__":
    run_benchmark()
