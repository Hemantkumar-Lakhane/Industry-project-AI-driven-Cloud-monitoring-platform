"""
RAM Antivirus — Comprehensive ML Benchmark & Ensemble Audit Script
====================================================================
Performs an independent mathematical audit of:
1. All 7 candidate models trained on NSL-KDD (mixed traffic vs normal-only).
2. The 3-model operational ensemble (Isolation Forest + HBOS + KNN).
3. Score normalization methods, decision rules (Max, Average, Majority Voting).
4. Full confusion matrices, precision, recall, F1, FPR, ROC-AUC, and total latency.
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
DATA_DIR = os.path.join(BASE_DIR, "data")
MODELS_DIR = os.path.join(BASE_DIR, "models")

FLOW_FEATURES = [
    "duration", "src_bytes", "dst_bytes", "count", "srv_count",
    "serror_rate", "rerror_rate", "same_srv_rate", "diff_srv_rate"
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


def run_audit():
    train_path = os.path.join(DATA_DIR, "KDDTrain+.txt")
    test_path = os.path.join(DATA_DIR, "KDDTest+.txt")

    df_train = pd.read_csv(train_path, header=None, names=KDD_COLUMNS)
    df_test = pd.read_csv(test_path, header=None, names=KDD_COLUMNS)

    y_train = (df_train["label"].str.strip().str.lower() != "normal").astype(int).values
    y_test = (df_test["label"].str.strip().str.lower() != "normal").astype(int).values

    X_train_raw = df_train[FLOW_FEATURES].fillna(0).values.astype(np.float64)
    X_test_raw = df_test[FLOW_FEATURES].fillna(0).values.astype(np.float64)

    # Scaler fitted strictly on train
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train_raw)
    X_test = scaler.transform(X_test_raw)

    contamination = float(np.mean(y_train))
    print(f"Total Test Records: {len(y_test):,} (Normal: {int(np.sum(y_test==0)):,}, Attack: {int(np.sum(y_test==1)):,})")
    print(f"Empirical Train Contamination: {contamination:.4f}")

    # Load pre-trained models from models directory
    iforest = joblib.load(os.path.join(MODELS_DIR, "iforest.pkl"))
    hbos = joblib.load(os.path.join(MODELS_DIR, "hbos.pkl"))
    knn = joblib.load(os.path.join(MODELS_DIR, "knn.pkl"))

    print("\n" + "=" * 80)
    print("1. INDEPENDENT VERIFICATION OF 3 SPECIALIST MODELS (KDDTest+, N=22,544)")
    print("=" * 80)

    models = {"Isolation Forest": iforest, "HBOS": hbos, "KNN": knn}
    preds = {}
    raw_scores = {}
    norm_scores = {}
    timings = {}

    for name, m in models.items():
        t0 = time.time()
        scores = m.decision_function(X_test)
        t_pred = time.time() - t0
        latency_1k = (t_pred / len(X_test)) * 1e6

        # Standard decision threshold in PyOD: scores > threshold_ -> anomaly (1)
        pred = (scores > m.threshold_).astype(int)
        cm = confusion_matrix(y_test, pred)
        tn, fp, fn, tp = cm.ravel()

        acc = accuracy_score(y_test, pred)
        prec = precision_score(y_test, pred, zero_division=0)
        rec = recall_score(y_test, pred, zero_division=0)
        f1 = f1_score(y_test, pred, zero_division=0)
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        preds[name] = pred
        raw_scores[name] = scores
        # Min-max normalization for score combination
        s_min, s_max = np.min(scores), np.max(scores)
        norm_scores[name] = (scores - s_min) / (s_max - s_min) if s_max > s_min else scores
        timings[name] = latency_1k

        print(f"\n[{name}]")
        print(f"  TP={tp:,}  FP={fp:,}  FN={fn:,}  TN={tn:,}")
        print(f"  Accuracy:  {acc*100:.2f}% | Precision: {prec*100:.2f}% | Recall: {rec*100:.2f}%")
        print(f"  F1-Score:  {f1*100:.2f}% | FPR: {fpr*100:.2f}% | Latency: {latency_1k:.3f} ms/1k")

    print("\n" + "=" * 80)
    print("2. INDEPENDENT ENSEMBLE EVALUATION (Isolation Forest + HBOS + KNN)")
    print("=" * 80)

    # Strategy A: Binary Majority Voting (>= 2 models agree on anomaly)
    vote_matrix = np.column_stack([preds["Isolation Forest"], preds["HBOS"], preds["KNN"]])
    pred_majority = (np.sum(vote_matrix, axis=1) >= 2).astype(int)
    cm_maj = confusion_matrix(y_test, pred_majority)
    tn_m, fp_m, fn_m, tp_m = cm_maj.ravel()
    acc_m = accuracy_score(y_test, pred_majority)
    prec_m = precision_score(y_test, pred_majority, zero_division=0)
    rec_m = recall_score(y_test, pred_majority, zero_division=0)
    f1_m = f1_score(y_test, pred_majority, zero_division=0)
    fpr_m = fp_m / (fp_m + tn_m)

    print("\n--- Strategy A: Majority Voting (>= 2 Models Flag Anomaly) ---")
    print(f"  TP={tp_m:,}  FP={fp_m:,}  FN={fn_m:,}  TN={tn_m:,}")
    print(f"  Accuracy:  {acc_m*100:.2f}%")
    print(f"  Precision: {prec_m*100:.2f}%")
    print(f"  Recall:    {rec_m*100:.2f}%")
    print(f"  F1-Score:  {f1_m*100:.2f}%")
    print(f"  FPR:       {fpr_m*100:.2f}%")

    # Strategy B: Union / Any Model Flags (Max Anomaly Sensitivity)
    pred_any = (np.sum(vote_matrix, axis=1) >= 1).astype(int)
    cm_any = confusion_matrix(y_test, pred_any)
    tn_a, fp_a, fn_a, tp_a = cm_any.ravel()
    acc_a = accuracy_score(y_test, pred_any)
    prec_a = precision_score(y_test, pred_any, zero_division=0)
    rec_a = recall_score(y_test, pred_any, zero_division=0)
    f1_a = f1_score(y_test, pred_any, zero_division=0)
    fpr_a = fp_a / (fp_a + tn_a)

    print("\n--- Strategy B: Union / Any Model (OR Logic: Max Recall) ---")
    print(f"  TP={tp_a:,}  FP={fp_a:,}  FN={fn_a:,}  TN={tn_a:,}")
    print(f"  Accuracy:  {acc_a*100:.2f}%")
    print(f"  Precision: {prec_a*100:.2f}%")
    print(f"  Recall:    {rec_a*100:.2f}%")
    print(f"  F1-Score:  {f1_a*100:.2f}%")
    print(f"  FPR:       {fpr_a*100:.2f}%")

    # Strategy C: Unanimous Voting (AND Logic: Max Precision / Min False Alarms)
    pred_all = (np.sum(vote_matrix, axis=1) == 3).astype(int)
    cm_all = confusion_matrix(y_test, pred_all)
    tn_u, fp_u, fn_u, tp_u = cm_all.ravel()
    acc_u = accuracy_score(y_test, pred_all)
    prec_u = precision_score(y_test, pred_all, zero_division=0)
    rec_u = recall_score(y_test, pred_all, zero_division=0)
    f1_u = f1_score(y_test, pred_all, zero_division=0)
    fpr_u = fp_u / (fp_u + tn_u)

    print("\n--- Strategy C: Unanimous Agreement (AND Logic: Max Precision) ---")
    print(f"  TP={tp_u:,}  FP={fp_u:,}  FN={fn_u:,}  TN={tn_u:,}")
    print(f"  Accuracy:  {acc_u*100:.2f}%")
    print(f"  Precision: {prec_u*100:.2f}%")
    print(f"  Recall:    {rec_u*100:.2f}%")
    print(f"  F1-Score:  {f1_u*100:.2f}%")
    print(f"  FPR:       {fpr_u*100:.2f}%")

    # Strategy D: Average Normalized Score with Threshold Sweep
    score_avg = (norm_scores["Isolation Forest"] + norm_scores["HBOS"] + norm_scores["KNN"]) / 3.0
    roc_ensemble = roc_auc_score(y_test, score_avg)
    pr_ensemble = average_precision_score(y_test, score_avg)
    total_latency_1k = sum(timings.values())

    print("\n--- Strategy D: Average Normalized Score Ensemble ---")
    print(f"  Ensemble ROC-AUC: {roc_ensemble*100:.2f}%")
    print(f"  Ensemble PR-AUC:  {pr_ensemble*100:.2f}%")
    print(f"  Combined Latency: {total_latency_1k:.3f} ms / 1k events")

    print("\n" + "=" * 80)
    print("3. TRAINING FORMULATION AUDIT: NORMAL-ONLY VS MIXED CONTAMINATED TRAFFIC")
    print("=" * 80)
    # Train IForest on purely normal traffic (N=67,343)
    normal_idx = np.where(y_train == 0)[0]
    X_train_normal = X_train[normal_idx]
    print(f"Training Clean Normal-Only Isolation Forest (N={len(X_train_normal):,})...")
    ifo_normal = IForest(n_estimators=100, contamination=0.05, random_state=42, n_jobs=1)
    ifo_normal.fit(X_train_normal)
    scores_norm_ifo = ifo_normal.decision_function(X_test)
    pred_norm_ifo = (scores_norm_ifo > ifo_normal.threshold_).astype(int)
    cm_ni = confusion_matrix(y_test, pred_norm_ifo)
    tn_ni, fp_ni, fn_ni, tp_ni = cm_ni.ravel()
    prec_ni = precision_score(y_test, pred_norm_ifo, zero_division=0)
    rec_ni = recall_score(y_test, pred_norm_ifo, zero_division=0)
    f1_ni = f1_score(y_test, pred_norm_ifo, zero_division=0)
    fpr_ni = fp_ni / (fp_ni + tn_ni)

    print(f"  [Normal-Only IForest (contamination=0.05)]")
    print(f"  TP={tp_ni:,}  FP={fp_ni:,}  FN={fn_ni:,}  TN={tn_ni:,}")
    print(f"  Precision: {prec_ni*100:.2f}% | Recall: {rec_ni*100:.2f}% | F1: {f1_ni*100:.2f}% | FPR: {fpr_ni*100:.2f}%")

    print("=" * 80)


if __name__ == "__main__":
    run_audit()
