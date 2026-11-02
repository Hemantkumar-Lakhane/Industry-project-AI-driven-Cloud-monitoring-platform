"""
RAM Antivirus — Clean Timing Benchmark & KNN Full-Fit Evaluation
================================================================
Runs on idle machine, sequential execution, isolated process:
- Hardware: Intel 16-Core, 24GB RAM, Windows 11 64-bit, Python 3.11.8
- Measures:
  1. Complete 5-seed evaluation for KNN full-fit (N=53,874 normal records)
  2. Isolated single-process fit time and inference latency (ms / 1k records) for all models
"""
import os
import sys
import time
import json
import warnings
import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROJECT_ROOT = os.path.dirname(ROOT_DIR)
PYLIBS_DIR = os.path.join(PROJECT_ROOT, "pylibs")
if os.path.exists(PYLIBS_DIR) and PYLIBS_DIR not in sys.path:
    sys.path.insert(0, PYLIBS_DIR)

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    precision_score, recall_score, f1_score, accuracy_score,
    confusion_matrix, roc_auc_score, average_precision_score
)
from sklearn.neural_network import MLPRegressor
from pyod.models.iforest import IForest
from pyod.models.hbos import HBOS
from pyod.models.knn import KNN
from pyod.models.ocsvm import OCSVM
from pyod.models.lof import LOF

DATA_DIR = os.path.join(ROOT_DIR, "data")
RESULTS_DIR = os.path.join(ROOT_DIR, "experiments", "results")

FLOW_FEATURES = [
    "duration", "src_bytes", "dst_bytes", "count", "srv_count",
    "serror_rate", "rerror_rate", "same_srv_rate", "diff_srv_rate"
]
BYTE_COUNT_COLS = ["duration", "src_bytes", "dst_bytes", "count", "srv_count"]
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
SEEDS = [11, 23, 37, 51, 73]


def run_clean_evaluation():
    print("=" * 80, flush=True)
    print("RUNNING ISOLATED CLEAN TIMING & KNN FULL-FIT BENCHMARK", flush=True)
    print("=" * 80, flush=True)

    df_train = pd.read_csv(os.path.join(DATA_DIR, "KDDTrain+.txt"), header=None, names=KDD_COLUMNS)
    df_test = pd.read_csv(os.path.join(DATA_DIR, "KDDTest+.txt"), header=None, names=KDD_COLUMNS)

    y_test = (df_test["label"].str.strip().str.lower() != "normal").astype(int).values
    df_train_norm = df_train[df_train["label"].str.strip().str.lower() == "normal"].copy()

    knn_full_records = []
    timing_records = {
        "IForest": {"fit": [], "pred": []},
        "HBOS": {"fit": [], "pred": []},
        "KNN_10k": {"fit": [], "pred": []},
        "KNN_full": {"fit": [], "pred": []},
        "OCSVM_10k": {"fit": [], "pred": []},
        "LOF_10k": {"fit": [], "pred": []},
        "AutoEncoder": {"fit": [], "pred": []},
        "Proposed_Fusion": {"fit": [], "pred": []}
    }

    for seed in SEEDS:
        print(f"\n--- Seed {seed} ---", flush=True)
        train_norm, val_norm = train_test_split(df_train_norm, test_size=0.20, random_state=seed)

        X_fit = train_norm[FLOW_FEATURES].copy()
        X_val = val_norm[FLOW_FEATURES].copy()
        X_te = df_test[FLOW_FEATURES].copy()

        for c in BYTE_COUNT_COLS:
            X_fit[c] = np.log1p(X_fit[c].astype(float))
            X_val[c] = np.log1p(X_val[c].astype(float))
            X_te[c] = np.log1p(X_te[c].astype(float))

        scaler = StandardScaler()
        X_fit_sc = scaler.fit_transform(X_fit.values)
        X_val_sc = scaler.transform(X_val.values)
        X_te_sc = scaler.transform(X_te.values)

        np.random.seed(seed)
        sub_idx = np.random.choice(len(X_fit_sc), size=10000, replace=False)
        X_fit_sub = X_fit_sc[sub_idx]

        # 1. KNN Full Fit Evaluation
        t0_knn_f = time.perf_counter()
        knn_f = KNN(n_neighbors=5, n_jobs=1)
        knn_f.fit(X_fit_sc)
        fit_time_knn_f = time.perf_counter() - t0_knn_f

        val_sc_f = knn_f.decision_function(X_val_sc)
        th_f = float(np.percentile(val_sc_f, 95))

        t0_p_knn_f = time.perf_counter()
        te_sc_f = knn_f.decision_function(X_te_sc)
        pred_time_knn_f = time.perf_counter() - t0_p_knn_f
        lat_knn_f = (pred_time_knn_f / len(X_te_sc)) * 1e6

        yp_f = (te_sc_f > th_f).astype(int)
        cm_f = confusion_matrix(y_test, yp_f)
        tn, fp, fn, tp = cm_f.ravel()
        prec = precision_score(y_test, yp_f, zero_division=0)
        rec = recall_score(y_test, yp_f, zero_division=0)
        f1 = f1_score(y_test, yp_f, zero_division=0)
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        acc = accuracy_score(y_test, yp_f)
        roc = roc_auc_score(y_test, te_sc_f)
        pr = average_precision_score(y_test, te_sc_f)

        knn_full_records.append({
            "seed": seed, "model": "KNN (Full 53k Fit)",
            "precision": prec, "recall": rec, "f1_score": f1, "fpr": fpr,
            "accuracy": acc, "roc_auc": roc, "pr_auc": pr, "threshold_95": th_f,
            "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn),
            "fit_time_sec": fit_time_knn_f, "latency_ms_per_1k": lat_knn_f
        })
        print(f"  KNN Full Fit: F1={f1:.4f} | Prec={prec:.4f} | Rec={rec:.4f} | FPR={fpr:.4f} | Fit={fit_time_knn_f:.2f}s | Lat={lat_knn_f:.2f}ms", flush=True)

        timing_records["KNN_full"]["fit"].append(fit_time_knn_f)
        timing_records["KNN_full"]["pred"].append(lat_knn_f)

        # 2. Timing benchmark for other models
        # IForest
        t0 = time.perf_counter()
        ifo = IForest(n_estimators=100, random_state=seed, n_jobs=1).fit(X_fit_sc)
        timing_records["IForest"]["fit"].append(time.perf_counter() - t0)
        t0 = time.perf_counter()
        _ = ifo.decision_function(X_te_sc)
        timing_records["IForest"]["pred"].append(((time.perf_counter() - t0) / len(X_te_sc)) * 1e6)

        # HBOS
        t0 = time.perf_counter()
        hbos = HBOS(n_bins=20).fit(X_fit_sc)
        timing_records["HBOS"]["fit"].append(time.perf_counter() - t0)
        t0 = time.perf_counter()
        _ = hbos.decision_function(X_te_sc)
        timing_records["HBOS"]["pred"].append(((time.perf_counter() - t0) / len(X_te_sc)) * 1e6)

        # KNN 10k
        t0 = time.perf_counter()
        knn_10 = KNN(n_neighbors=5, n_jobs=1).fit(X_fit_sub)
        timing_records["KNN_10k"]["fit"].append(time.perf_counter() - t0)
        t0 = time.perf_counter()
        _ = knn_10.decision_function(X_te_sc)
        timing_records["KNN_10k"]["pred"].append(((time.perf_counter() - t0) / len(X_te_sc)) * 1e6)

        # AutoEncoder
        t0 = time.perf_counter()
        ae = MLPRegressor(hidden_layer_sizes=(6, 3, 6), max_iter=100, random_state=seed, early_stopping=True, validation_fraction=0.1, n_iter_no_change=8, batch_size=256).fit(X_fit_sc, X_fit_sc)
        timing_records["AutoEncoder"]["fit"].append(time.perf_counter() - t0)
        t0 = time.perf_counter()
        _ = np.mean(np.square(X_te_sc - ae.predict(X_te_sc)), axis=1)
        timing_records["AutoEncoder"]["pred"].append(((time.perf_counter() - t0) / len(X_te_sc)) * 1e6)

        # OCSVM (Seed 11 only for clean timing)
        if seed == 11:
            t0 = time.perf_counter()
            ocsvm = OCSVM(kernel="rbf", gamma="scale").fit(X_fit_sub)
            timing_records["OCSVM_10k"]["fit"].append(time.perf_counter() - t0)
            t0 = time.perf_counter()
            _ = ocsvm.decision_function(X_te_sc)
            timing_records["OCSVM_10k"]["pred"].append(((time.perf_counter() - t0) / len(X_te_sc)) * 1e6)

            t0 = time.perf_counter()
            lof = LOF(n_neighbors=20, novelty=True, n_jobs=1).fit(X_fit_sub)
            timing_records["LOF_10k"]["fit"].append(time.perf_counter() - t0)
            t0 = time.perf_counter()
            _ = lof.decision_function(X_te_sc)
            timing_records["LOF_10k"]["pred"].append(((time.perf_counter() - t0) / len(X_te_sc)) * 1e6)

    # Save KNN Full fit results
    df_knn_full = pd.DataFrame(knn_full_records)
    knn_full_csv = os.path.join(RESULTS_DIR, "e1_knn_full_fit_per_seed.csv")
    df_knn_full.to_csv(knn_full_csv, index=False)
    print(f"\n[+] Saved KNN Full-fit records to: {knn_full_csv}", flush=True)

    print("\n=== KNN FULL-FIT 5-SEED SUMMARY ===")
    for col in ["precision", "recall", "f1_score", "fpr", "roc_auc", "pr_auc", "fit_time_sec", "latency_ms_per_1k"]:
        print(f"  {col}: {df_knn_full[col].mean():.4f} +/- {df_knn_full[col].std():.4f}")

    print("\n=== ISOLATED CLEAN TIMING SUMMARY (Single Process) ===")
    for m, d in timing_records.items():
        fits = d["fit"]
        preds = d["pred"]
        if fits:
            print(f"  {m:<16}: Fit = {np.mean(fits):.3f}s (±{np.std(fits):.3f}s) | Latency = {np.mean(preds):.3f} ms/1k (±{np.std(preds):.3f} ms)")


if __name__ == "__main__":
    run_clean_evaluation()

