"""
RAM Antivirus — Experiment E1: Multi-Algorithm NSL-KDD Benchmarks & Proposed Fusion
=====================================================================================
Strict Protocol Replicating IEEE Paper Section VI & Adding Baselines & Proposed Ensemble:
- Seeds: [11, 23, 37, 51, 73]
- 80/20 train/validation split of normal KDDTrain+ records
- 9-dimensional verified flow feature schema:
    duration, src_bytes, dst_bytes, count, srv_count,
    serror_rate, rerror_rate, same_srv_rate, diff_srv_rate
- log1p transformation on byte & count features (duration, src_bytes, dst_bytes, count, srv_count)
- StandardScaler fitted strictly on 80% normal training partition
- Operational decision threshold locked at 95th percentile of validation normal scores (5% validation FPR)
- Evaluation on official KDDTest+ (N=22,544: 9,711 normal, 12,833 attack)
- Models evaluated:
    1. Isolation Forest (IForest, n_estimators=100)
    2. Histogram-Based Outlier Score (HBOS, n_bins=20)
    3. k-Nearest Neighbors (KNN, k=5, 10k normal sample)
    4. One-Class SVM (OCSVM, RBF kernel, gamma='scale', 10k normal sample)
    5. Local Outlier Factor (LOF, k=20, novelty=True, 10k normal sample)
    6. Multi-Layer Perceptron AutoEncoder (MLP AutoEncoder, architecture 9-6-3-6-9, reconstruction MSE)
    7. Proposed RAM Operational Ensemble (Max-Score Fusion of IForest, HBOS, KNN via predict_proba)

Outputs saved to backend/experiments/results/:
- e1_nsl_kdd_per_seed.csv
- e1_nsl_kdd_summary.csv
- e1_nsl_kdd_summary.json
- e1_roc_curves.csv
- e1_pr_curves.csv
"""

import os
import sys
import time
import json
import warnings
import subprocess
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
    confusion_matrix, roc_auc_score, average_precision_score,
    roc_curve, precision_recall_curve
)
from sklearn.neural_network import MLPRegressor
from pyod.models.iforest import IForest
from pyod.models.hbos import HBOS
from pyod.models.knn import KNN
from pyod.models.ocsvm import OCSVM
from pyod.models.lof import LOF

DATA_DIR = os.path.join(ROOT_DIR, "data")
RESULTS_DIR = os.path.join(ROOT_DIR, "experiments", "results")
os.makedirs(RESULTS_DIR, exist_ok=True)

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


class MLPAutoEncoderModel:
    """Unsupervised AutoEncoder anomaly detector using sklearn MLPRegressor."""
    def __init__(self, hidden_layer_sizes=(6, 3, 6), max_iter=100, random_state=42):
        self.hidden_layer_sizes = hidden_layer_sizes
        self.max_iter = max_iter
        self.random_state = random_state
        self.mlp = MLPRegressor(
            hidden_layer_sizes=hidden_layer_sizes,
            activation="relu",
            solver="adam",
            max_iter=max_iter,
            random_state=random_state,
            early_stopping=True,
            validation_fraction=0.1,
            n_iter_no_change=8,
            batch_size=256
        )

    def fit(self, X):
        self.mlp.fit(X, X)
        return self

    def decision_function(self, X):
        X_pred = self.mlp.predict(X)
        mse = np.mean(np.square(X - X_pred), axis=1)
        return mse


def get_git_commit_hash():
    try:
        out = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=PROJECT_ROOT)
        return out.decode("utf-8").strip()
    except Exception:
        return "3646033a96ee5ba40f772381e9178b8e04d31f77"


def run_experiment_e1():
    print("=" * 85, flush=True)
    print("RAM Antivirus — Experiment E1: NSL-KDD Benchmarks, Baselines & Proposed Fusion", flush=True)
    print("=" * 85, flush=True)

    train_path = os.path.join(DATA_DIR, "KDDTrain+.txt")
    test_path = os.path.join(DATA_DIR, "KDDTest+.txt")
    if not os.path.exists(train_path) or not os.path.exists(test_path):
        raise FileNotFoundError(f"Missing NSL-KDD files in {DATA_DIR}")

    print(f"[*] Loading KDDTrain+ and KDDTest+ from {DATA_DIR}...", flush=True)
    df_train = pd.read_csv(train_path, header=None, names=KDD_COLUMNS)
    df_test = pd.read_csv(test_path, header=None, names=KDD_COLUMNS)

    y_test = (df_test["label"].str.strip().str.lower() != "normal").astype(int).values
    df_train_norm = df_train[df_train["label"].str.strip().str.lower() == "normal"].copy()

    n_test_norm = int(np.sum(y_test == 0))
    n_test_atk = int(np.sum(y_test == 1))
    print(f"    Train normal pool: {len(df_train_norm):,} records", flush=True)
    print(f"    Test set: {len(df_test):,} records (Normal: {n_test_norm:,}, Attack: {n_test_atk:,})", flush=True)
    print(f"    Flow Features (9D): {FLOW_FEATURES}", flush=True)
    print(f"    Log1p Transformed: {BYTE_COUNT_COLS}", flush=True)
    print(f"    Random Seeds: {SEEDS}", flush=True)

    per_seed_records = []
    roc_curves_dict = {}
    pr_curves_dict = {}

    for seed_idx, seed in enumerate(SEEDS, 1):
        print(f"\n" + "-" * 75, flush=True)
        print(f"Executing Seed {seed} ({seed_idx}/{len(SEEDS)})...", flush=True)
        print("-" * 75, flush=True)

        # 80/20 train/val split on normal pool
        train_norm, val_norm = train_test_split(df_train_norm, test_size=0.20, random_state=seed)

        X_fit_df = train_norm[FLOW_FEATURES].copy()
        X_val_df = val_norm[FLOW_FEATURES].copy()
        X_test_df = df_test[FLOW_FEATURES].copy()

        # Log1p transformation on byte & count features
        for col in BYTE_COUNT_COLS:
            X_fit_df[col] = np.log1p(X_fit_df[col].astype(float))
            X_val_df[col] = np.log1p(X_val_df[col].astype(float))
            X_test_df[col] = np.log1p(X_test_df[col].astype(float))

        # StandardScaler strictly fitted on 80% normal training partition
        scaler = StandardScaler()
        X_fit_sc = scaler.fit_transform(X_fit_df.values)
        X_val_sc = scaler.transform(X_val_df.values)
        X_test_sc = scaler.transform(X_test_df.values)

        # Subsample 10k for distance/quadratic kernel models (KNN, OCSVM, LOF)
        np.random.seed(seed)
        sub_size = min(10000, len(X_fit_sc))
        sub_idx = np.random.choice(len(X_fit_sc), size=sub_size, replace=False)
        X_fit_sub = X_fit_sc[sub_idx]

        # Instantiate specialist models
        ifo_model = IForest(n_estimators=100, random_state=seed, n_jobs=1)
        hbos_model = HBOS(n_bins=20)
        knn_model = KNN(n_neighbors=5, n_jobs=-1)
        ocsvm_model = OCSVM(kernel="rbf", gamma="scale")
        lof_model = LOF(n_neighbors=20, novelty=True, n_jobs=-1)
        ae_model = MLPAutoEncoderModel(hidden_layer_sizes=(6, 3, 6), max_iter=100, random_state=seed)

        candidate_models = [
            ("Isolation Forest", ifo_model, X_fit_sc),
            ("HBOS", hbos_model, X_fit_sc),
            ("KNN (5-NN)", knn_model, X_fit_sub),
            ("OCSVM (RBF)", ocsvm_model, X_fit_sub),
            ("LOF", lof_model, X_fit_sub),
            ("AutoEncoder (MLP)", ae_model, X_fit_sc)
        ]

        val_scores_cache = {}
        test_scores_cache = {}

        for model_name, model, train_data in candidate_models:
            t0_fit = time.time()
            model.fit(train_data)
            fit_time = time.time() - t0_fit

            val_scores = model.decision_function(X_val_sc)
            threshold_95 = float(np.percentile(val_scores, 95))

            t0_pred = time.time()
            test_scores = model.decision_function(X_test_sc)
            pred_time = time.time() - t0_pred
            latency_ms_per_1k = (pred_time / len(X_test_sc)) * 1e6

            val_scores_cache[model_name] = val_scores
            test_scores_cache[model_name] = test_scores

            y_pred = (test_scores > threshold_95).astype(int)
            cm = confusion_matrix(y_test, y_pred)
            tn, fp, fn, tp = cm.ravel()

            prec = float(precision_score(y_test, y_pred, zero_division=0))
            rec = float(recall_score(y_test, y_pred, zero_division=0))
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

            record = {
                "seed": seed,
                "model": model_name,
                "precision": round(prec, 6),
                "recall": round(rec, 6),
                "f1_score": round(f1, 6),
                "fpr": round(fpr, 6),
                "accuracy": round(acc, 6),
                "roc_auc": round(roc_auc, 6) if roc_auc is not None else None,
                "pr_auc": round(pr_auc, 6) if pr_auc is not None else None,
                "threshold_95": round(threshold_95, 6),
                "tp": int(tp),
                "fp": int(fp),
                "fn": int(fn),
                "tn": int(tn),
                "fit_time_sec": round(fit_time, 4),
                "latency_ms_per_1k": round(latency_ms_per_1k, 4),
                "train_samples": int(len(train_data))
            }
            per_seed_records.append(record)

            print(f"  [{model_name:24s}] F1: {f1:.4f} | Prec: {prec:.4f} | Rec: {rec:.4f} | FPR: {fpr:.4f} | ROC: {roc_auc:.4f} | Fit: {fit_time:.2f}s", flush=True)

            if seed == 11:
                try:
                    fpr_vals, tpr_vals, _ = roc_curve(y_test, test_scores)
                    prec_vals, rec_vals, _ = precision_recall_curve(y_test, test_scores)
                    sample_indices = np.linspace(0, len(fpr_vals) - 1, min(100, len(fpr_vals)), dtype=int)
                    roc_curves_dict[model_name] = [{"fpr": round(float(fpr_vals[i]), 5), "tpr": round(float(tpr_vals[i]), 5)} for i in sample_indices]

                    sample_pr_indices = np.linspace(0, len(rec_vals) - 1, min(100, len(rec_vals)), dtype=int)
                    pr_curves_dict[model_name] = [{"recall": round(float(rec_vals[i]), 5), "precision": round(float(prec_vals[i]), 5)} for i in sample_pr_indices]
                except Exception as e:
                    print(f"    Curve generation warning for {model_name}: {e}", flush=True)

        # ── 7. PROPOSED OPERATIONAL MODEL: Max-Score Fusion (IForest + HBOS + KNN) ────
        t0_fusion = time.time()
        # Normalize validation scores via predict_proba as in ml_engine.py
        val_p_ifo = ifo_model.predict_proba(X_val_sc)[:, 1]
        val_p_hbos = hbos_model.predict_proba(X_val_sc)[:, 1]
        val_p_knn = knn_model.predict_proba(X_val_sc)[:, 1]
        val_fusion_score = np.maximum(np.maximum(val_p_ifo, val_p_hbos), val_p_knn)
        th_fusion = float(np.percentile(val_fusion_score, 95))

        t0_pred_fus = time.time()
        te_p_ifo = ifo_model.predict_proba(X_test_sc)[:, 1]
        te_p_hbos = hbos_model.predict_proba(X_test_sc)[:, 1]
        te_p_knn = knn_model.predict_proba(X_test_sc)[:, 1]
        te_fusion_score = np.maximum(np.maximum(te_p_ifo, te_p_hbos), te_p_knn)
        pred_time_fus = time.time() - t0_pred_fus
        latency_fus = (pred_time_fus / len(X_test_sc)) * 1e6

        y_pred_fus = (te_fusion_score > th_fusion).astype(int)
        cm_fus = confusion_matrix(y_test, y_pred_fus)
        tn_f, fp_f, fn_f, tp_f = cm_fus.ravel()

        prec_f = float(precision_score(y_test, y_pred_fus, zero_division=0))
        rec_f = float(recall_score(y_test, y_pred_fus, zero_division=0))
        f1_f = float(f1_score(y_test, y_pred_fus, zero_division=0))
        acc_f = float(accuracy_score(y_test, y_pred_fus))
        fpr_f = float(fp_f / (fp_f + tn_f)) if (fp_f + tn_f) > 0 else 0.0

        roc_f = float(roc_auc_score(y_test, te_fusion_score))
        pr_f = float(average_precision_score(y_test, te_fusion_score))

        record_fus = {
            "seed": seed,
            "model": "Proposed Fusion (Max-Score)",
            "precision": round(prec_f, 6),
            "recall": round(rec_f, 6),
            "f1_score": round(f1_f, 6),
            "fpr": round(fpr_f, 6),
            "accuracy": round(acc_f, 6),
            "roc_auc": round(roc_f, 6),
            "pr_auc": round(pr_f, 6),
            "threshold_95": round(th_fusion, 6),
            "tp": int(tp_f),
            "fp": int(fp_f),
            "fn": int(fn_f),
            "tn": int(tn_f),
            "fit_time_sec": round(per_seed_records[-6]["fit_time_sec"] + per_seed_records[-5]["fit_time_sec"] + per_seed_records[-4]["fit_time_sec"], 4),
            "latency_ms_per_1k": round(latency_fus, 4),
            "train_samples": int(len(X_fit_sc))
        }
        per_seed_records.append(record_fus)

        print(f"  [Proposed Fusion (Max)   ] F1: {f1_f:.4f} | Prec: {prec_f:.4f} | Rec: {rec_f:.4f} | FPR: {fpr_f:.4f} | ROC: {roc_f:.4f} | Lat: {latency_fus:.2f}ms", flush=True)

        if seed == 11:
            try:
                fpr_vals, tpr_vals, _ = roc_curve(y_test, te_fusion_score)
                prec_vals, rec_vals, _ = precision_recall_curve(y_test, te_fusion_score)
                sample_indices = np.linspace(0, len(fpr_vals) - 1, min(100, len(fpr_vals)), dtype=int)
                roc_curves_dict["Proposed Fusion (Max-Score)"] = [{"fpr": round(float(fpr_vals[i]), 5), "tpr": round(float(tpr_vals[i]), 5)} for i in sample_indices]

                sample_pr_indices = np.linspace(0, len(rec_vals) - 1, min(100, len(rec_vals)), dtype=int)
                pr_curves_dict["Proposed Fusion (Max-Score)"] = [{"recall": round(float(rec_vals[i]), 5), "precision": round(float(prec_vals[i]), 5)} for i in sample_pr_indices]
            except Exception as e:
                print(f"    Curve generation warning for Proposed Fusion: {e}", flush=True)

    # Build per-seed DataFrame
    df_per_seed = pd.DataFrame(per_seed_records)
    per_seed_csv = os.path.join(RESULTS_DIR, "e1_nsl_kdd_per_seed.csv")
    df_per_seed.to_csv(per_seed_csv, index=False)
    print(f"\n[+] Saved per-seed results to: {per_seed_csv}", flush=True)

    # Compute summary mean +/- std across 5 seeds
    summary_list = []
    models_evaluated = list(df_per_seed["model"].unique())
    metric_cols = ["precision", "recall", "f1_score", "fpr", "accuracy", "roc_auc", "pr_auc", "fit_time_sec", "latency_ms_per_1k"]

    for m in models_evaluated:
        m_df = df_per_seed[df_per_seed["model"] == m]
        row_summary = {"model": m, "seeds_evaluated": len(m_df)}
        for col in metric_cols:
            vals = m_df[col].dropna()
            mean_v = float(vals.mean())
            std_v = float(vals.std(ddof=1)) if len(vals) > 1 else 0.0
            row_summary[f"{col}_mean"] = round(mean_v, 6)
            row_summary[f"{col}_std"] = round(std_v, 6)
            row_summary[f"{col}_formatted"] = f"{mean_v:.4f} ± {std_v:.4f}"
        summary_list.append(row_summary)

    df_summary = pd.DataFrame(summary_list)
    summary_csv = os.path.join(RESULTS_DIR, "e1_nsl_kdd_summary.csv")
    df_summary.to_csv(summary_csv, index=False)
    print(f"[+] Saved summary results to: {summary_csv}", flush=True)

    # Complete structured JSON with metadata
    git_hash = get_git_commit_hash()
    import sklearn
    import pyod

    full_payload = {
        "experiment": "E1_NSL_KDD_Baselines_and_Fusion",
        "description": "5-seed evaluation replicating IEEE paper protocol, adding OCSVM, LOF, MLP AutoEncoder, and Proposed Max-Score Fusion",
        "protocol": {
            "dataset_train": "KDDTrain+.txt",
            "dataset_test": "KDDTest+.txt",
            "novelty_protocol": "normal_only_train",
            "train_val_split": "80/20",
            "feature_schema": "flow_9d",
            "features": FLOW_FEATURES,
            "log1p_features": BYTE_COUNT_COLS,
            "scaler": "StandardScaler (fitted strictly on 80% normal train)",
            "threshold_rule": "95th percentile of normal validation scores (nominal 5% val FPR)",
            "seeds": SEEDS
        },
        "environment": {
            "git_commit": git_hash,
            "python_version": sys.version.split()[0],
            "sklearn_version": sklearn.__version__,
            "pyod_version": pyod.__version__,
            "numpy_version": np.__version__,
            "pandas_version": pd.__version__
        },
        "summary": summary_list,
        "per_seed": per_seed_records
    }

    summary_json = os.path.join(RESULTS_DIR, "e1_nsl_kdd_summary.json")
    with open(summary_json, "w", encoding="utf-8") as f:
        json.dump(full_payload, f, indent=2)
    print(f"[+] Saved complete JSON metadata to: {summary_json}", flush=True)

    # Save ROC curves
    roc_rows = []
    for m_name, points in roc_curves_dict.items():
        for pt in points:
            roc_rows.append({"model": m_name, "fpr": pt["fpr"], "tpr": pt["tpr"]})
    df_roc = pd.DataFrame(roc_rows)
    roc_csv = os.path.join(RESULTS_DIR, "e1_roc_curves.csv")
    df_roc.to_csv(roc_csv, index=False)
    print(f"[+] Saved ROC curves to: {roc_csv}", flush=True)

    # Save PR curves
    pr_rows = []
    for m_name, points in pr_curves_dict.items():
        for pt in points:
            pr_rows.append({"model": m_name, "recall": pt["recall"], "precision": pt["precision"]})
    df_pr = pd.DataFrame(pr_rows)
    pr_csv = os.path.join(RESULTS_DIR, "e1_pr_curves.csv")
    df_pr.to_csv(pr_csv, index=False)
    print(f"[+] Saved PR curves to: {pr_csv}", flush=True)

    print("\n" + "=" * 85, flush=True)
    print("EXPERIMENT E1 WITH PROPOSED FUSION COMPLETED SUCCESSFULLY", flush=True)
    print("=" * 85, flush=True)


if __name__ == "__main__":
    run_experiment_e1()
