"""
Clean, Single-Process Isolated Timing Benchmark with Warm-up Exclusion
=====================================================================
Hardware: 13th Gen Intel(R) Core(TM) i5-13450HX (16 threads)
OS: Windows 11 64-bit, Python 3.11.8

Protocol:
- Single-process execution (n_jobs=1)
- Model fitted on normal KDDTrain+ data (80/20 split, seed 11)
- 1 dry warm-up call on 1,000 samples (EXCLUDED from timing)
- 3 repeated inference passes on full KDDTest+ (N = 22,544)
- Reports: Mean ± Std inference latency in milliseconds per 1,000 records (ms/1k)
- Reports: Measured fit time (seconds)
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
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
PROJECT_ROOT = os.path.dirname(ROOT_DIR)
PYLIBS_DIR = os.path.join(PROJECT_ROOT, "pylibs")
if os.path.exists(PYLIBS_DIR) and PYLIBS_DIR not in sys.path:
    sys.path.insert(0, PYLIBS_DIR)

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
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


def run_clean_timing_benchmark():
    print("=" * 80, flush=True)
    print("CLEAN TIMING BENCHMARK: ISOLATED PROCESS & WARM-UP EXCLUSION", flush=True)
    print("=" * 80, flush=True)
    print(f"Hardware: 13th Gen Intel(R) Core(TM) i5-13450HX (16 threads)", flush=True)
    print(f"Dataset: NSL-KDD (KDDTest+ N=22,544, 9 flow features)", flush=True)
    print(f"Timing protocol: 1 dry warm-up run (excluded), 3 timed inference iterations\n", flush=True)

    # Load data
    df_train = pd.read_csv(os.path.join(DATA_DIR, "KDDTrain+.txt"), header=None, names=KDD_COLUMNS)
    df_test = pd.read_csv(os.path.join(DATA_DIR, "KDDTest+.txt"), header=None, names=KDD_COLUMNS)

    df_train_norm = df_train[df_train["label"].str.strip().str.lower() == "normal"].copy()
    train_norm, _ = train_test_split(df_train_norm, test_size=0.20, random_state=11)

    X_fit = train_norm[FLOW_FEATURES].copy()
    X_te = df_test[FLOW_FEATURES].copy()

    for c in BYTE_COUNT_COLS:
        X_fit[c] = np.log1p(X_fit[c].astype(float))
        X_te[c] = np.log1p(X_te[c].astype(float))

    scaler = StandardScaler()
    X_fit_sc = scaler.fit_transform(X_fit.values)
    X_te_sc = scaler.transform(X_te.values)

    np.random.seed(11)
    sub_idx = np.random.choice(len(X_fit_sc), size=10000, replace=False)
    X_fit_sub = X_fit_sc[sub_idx]

    models = [
        ("IForest", lambda: IForest(n_estimators=100, random_state=11, n_jobs=1), X_fit_sc, False),
        ("HBOS", lambda: HBOS(n_bins=20), X_fit_sc, False),
        ("KNN (10k)", lambda: KNN(n_neighbors=5, n_jobs=1), X_fit_sub, False),
        ("KNN (Full 53k)", lambda: KNN(n_neighbors=5, n_jobs=1), X_fit_sc, False),
        ("OCSVM (10k)", lambda: OCSVM(kernel="rbf", gamma="scale"), X_fit_sub, False),
        ("LOF (10k)", lambda: LOF(n_neighbors=20, novelty=True, n_jobs=1), X_fit_sub, False),
        ("AutoEncoder (MLP)", lambda: MLPRegressor(
            hidden_layer_sizes=(6, 3, 6), max_iter=100, random_state=11,
            early_stopping=True, validation_fraction=0.1, n_iter_no_change=8, batch_size=256
        ), X_fit_sc, True)
    ]

    results = []
    fitted_models = {}

    for name, init_fn, fit_data, is_ae in models:
        print(f"[*] Benchmarking {name}...", flush=True)
        m = init_fn()

        t0_fit = time.perf_counter()
        if is_ae:
            m.fit(fit_data, fit_data)
        else:
            m.fit(fit_data)
        fit_time = time.perf_counter() - t0_fit
        fitted_models[name] = m
        print(f"    Fit Time: {fit_time:.3f}s", flush=True)

        # 1. Warm-up call (EXCLUDED)
        warmup_x = X_te_sc[:1000]
        if is_ae:
            _ = np.mean(np.square(warmup_x - m.predict(warmup_x)), axis=1)
        else:
            _ = m.decision_function(warmup_x)

        # 2. 3 Timed inference passes on full test set (N=22,544)
        latencies = []
        for it in range(3):
            t0 = time.perf_counter()
            if is_ae:
                _ = np.mean(np.square(X_te_sc - m.predict(X_te_sc)), axis=1)
            else:
                _ = m.decision_function(X_te_sc)
            elapsed = time.perf_counter() - t0
            lat = (elapsed / len(X_te_sc)) * 1e6  # ms per 1k records
            latencies.append(lat)

        mean_lat = float(np.mean(latencies))
        std_lat = float(np.std(latencies))
        print(f"    Inference Latency: {mean_lat:.3f} ms/1k (±{std_lat:.3f} ms/1k)", flush=True)

        results.append({
            "model": name,
            "fit_time_sec": round(fit_time, 4),
            "latency_ms_per_1k_mean": round(mean_lat, 4),
            "latency_ms_per_1k_std": round(std_lat, 4),
            "passes": 3,
            "test_samples": len(X_te_sc)
        })

    # Benchmark Proposed Model (Max-Score Fusion)
    print("\n[*] Benchmarking Proposed Model (Max-Score Fusion of IForest, HBOS, KNN-10k)...", flush=True)
    ifo_m = fitted_models["IForest"]
    hbos_m = fitted_models["HBOS"]
    knn_m = fitted_models["KNN (10k)"]

    def run_fusion(x):
        s1 = ifo_m.decision_function(x)
        s2 = hbos_m.decision_function(x)
        s3 = knn_m.decision_function(x)
        def nrm(s):
            return (s - np.min(s)) / (np.max(s) - np.min(s) + 1e-9)
        return np.maximum(np.maximum(nrm(s1), nrm(s2)), nrm(s3))

    # Warm-up (EXCLUDED)
    _ = run_fusion(X_te_sc[:1000])

    fus_latencies = []
    for _ in range(3):
        t0 = time.perf_counter()
        _ = run_fusion(X_te_sc)
        elapsed = time.perf_counter() - t0
        fus_latencies.append((elapsed / len(X_te_sc)) * 1e6)

    fus_mean_lat = float(np.mean(fus_latencies))
    fus_std_lat = float(np.std(fus_latencies))
    fus_fit = results[0]["fit_time_sec"] + results[1]["fit_time_sec"] + results[2]["fit_time_sec"]

    print(f"    Constituent Fit Time: {fus_fit:.3f}s", flush=True)
    print(f"    Fusion Inference Latency: {fus_mean_lat:.3f} ms/1k (±{fus_std_lat:.3f} ms/1k)", flush=True)

    results.append({
        "model": "Proposed Model (Max-Score Fusion)",
        "fit_time_sec": round(fus_fit, 4),
        "latency_ms_per_1k_mean": round(fus_mean_lat, 4),
        "latency_ms_per_1k_std": round(fus_std_lat, 4),
        "passes": 3,
        "test_samples": len(X_te_sc)
    })

    # Save to CSV and JSON
    df_res = pd.DataFrame(results)
    out_csv = os.path.join(RESULTS_DIR, "clean_timing_benchmark.csv")
    out_json = os.path.join(RESULTS_DIR, "clean_timing_benchmark.json")
    df_res.to_csv(out_csv, index=False)
    with open(out_json, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n[+] Saved clean timing benchmark to:\n  - {out_csv}\n  - {out_json}", flush=True)


if __name__ == "__main__":
    run_clean_timing_benchmark()
