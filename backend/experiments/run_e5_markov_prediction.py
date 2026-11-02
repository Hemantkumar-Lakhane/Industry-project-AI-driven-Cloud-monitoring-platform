"""
Experiment E5: Predictive Analytics for Kill-Chain Stage Progression
===================================================================
Evaluates Next-Stage Prediction on Real Ground-Truth Multi-Stage Incidents from security.db.

Protocol:
1. Stage Mapping to Canonical 6 Tiers (Recon=0, Access=1, PrivEsc=2, Evasion=3, Exfil=4, Impact=5)
2. Extract all multi-stage incidents (k >= 2) and collapse consecutive duplicate stages
3. Compare:
   - Baseline: Most-Frequent-Stage (MFS)
   - 1st-Order Markov Chain (with backoff to MFS for unseen states)
   - 2nd-Order Markov Chain (with backoff to 1st-order and MFS)
4. Evaluations:
   - Protocol 1: Full In-Sample Empirical Transition Matrix (N_trans = 223)
   - Protocol 2: Grouped 5-Fold Cross-Validation by Trajectory (Zero Trajectory Leakage)
   - Protocol 3: Leave-One-Trajectory-Out (LOTO) Cross-Validation (11 Trajectories)
"""
import os
import sys
import json
import sqlite3
import numpy as np
import pandas as pd
from collections import Counter, defaultdict
from typing import List, Tuple, Dict, Any

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
PROJECT_ROOT = os.path.dirname(ROOT_DIR)
RESULTS_DIR = os.path.join(ROOT_DIR, "experiments", "results")
DB_PATH = os.path.join(ROOT_DIR, "security.db")

# Import canonical mapping from risk_engine
from engines.risk_engine import map_stage_to_index, MITRE_STAGE_ORDER

STAGE_NAMES = {
    0: "Reconnaissance",
    1: "Initial Access",
    2: "Privilege Escalation",
    3: "Defense Evasion",
    4: "Exfiltration",
    5: "Impact"
}
SHORT_NAMES = {
    0: "Recon",
    1: "Access",
    2: "PrivEsc",
    3: "Evasion",
    4: "Exfil",
    5: "Impact"
}


class MostFrequentStageBaseline:
    def __init__(self):
        self.top1 = 0
        self.top2 = [0, 1]

    def fit(self, transitions: List[Dict]):
        targets = [t["target"] for t in transitions]
        counts = Counter(targets)
        common = counts.most_common(2)
        if common:
            self.top1 = common[0][0]
            self.top2 = [c[0] for c in common]
            if len(self.top2) < 2:
                self.top2.append((self.top1 + 1) % 6)

    def predict(self, current: int, history: Any = None) -> int:
        return self.top1

    def predict_top2(self, current: int, history: Any = None) -> List[int]:
        return self.top2


class FirstOrderMarkovChain:
    def __init__(self, laplace_alpha: float = 0.01):
        self.alpha = laplace_alpha
        self.trans_counts = np.zeros((6, 6), dtype=float)
        self.trans_probs = np.zeros((6, 6), dtype=float)
        self.global_mfs = MostFrequentStageBaseline()

    def fit(self, transitions: List[Dict]):
        self.global_mfs.fit(transitions)
        self.trans_counts = np.zeros((6, 6), dtype=float)
        for t in transitions:
            self.trans_counts[t["current"], t["target"]] += 1.0

        for i in range(6):
            row_sum = np.sum(self.trans_counts[i, :])
            if row_sum > 0:
                self.trans_probs[i, :] = (self.trans_counts[i, :] + self.alpha) / (row_sum + 6 * self.alpha)
            else:
                self.trans_probs[i, :] = 1.0 / 6.0

    def predict(self, current: int, history: Any = None) -> int:
        if np.sum(self.trans_counts[current, :]) > 0:
            return int(np.argmax(self.trans_probs[current, :]))
        return self.global_mfs.predict(current)

    def predict_top2(self, current: int, history: Any = None) -> List[int]:
        if np.sum(self.trans_counts[current, :]) > 0:
            order = np.argsort(self.trans_probs[current, :])[::-1]
            return [int(order[0]), int(order[1])]
        return self.global_mfs.predict_top2(current)


class SecondOrderMarkovChain:
    def __init__(self, laplace_alpha: float = 0.01):
        self.alpha = laplace_alpha
        self.trans_counts = defaultdict(lambda: np.zeros(6, dtype=float))
        self.first_order = FirstOrderMarkovChain(laplace_alpha=laplace_alpha)

    def fit(self, transitions: List[Dict]):
        self.first_order.fit(transitions)
        self.trans_counts = defaultdict(lambda: np.zeros(6, dtype=float))
        for t in transitions:
            prev = t["prev"]
            curr = t["current"]
            tgt = t["target"]
            if prev is not None:
                self.trans_counts[(prev, curr)][tgt] += 1.0

    def predict(self, current: int, prev: Any = None) -> int:
        if prev is not None and (prev, current) in self.trans_counts:
            counts = self.trans_counts[(prev, current)]
            if np.sum(counts) > 0:
                return int(np.argmax(counts))
        return self.first_order.predict(current)

    def predict_top2(self, current: int, prev: Any = None) -> List[int]:
        if prev is not None and (prev, current) in self.trans_counts:
            counts = self.trans_counts[(prev, current)]
            if np.sum(counts) > 0:
                order = np.argsort(counts)[::-1]
                return [int(order[0]), int(order[1])]
        return self.first_order.predict_top2(current)


def extract_incident_sequences(collapse_duplicates: bool = False):
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT incident_id, attack_stages_json FROM incidents").fetchall()
    conn.close()

    incidents_data = []
    for inc_id, stages_json in rows:
        stages = json.loads(stages_json) if stages_json else []
        raw_indices = [map_stage_to_index(s) for s in stages if map_stage_to_index(s) is not None]
        if collapse_duplicates:
            collapsed = []
            for s in raw_indices:
                if not collapsed or s != collapsed[-1]:
                    collapsed.append(s)
            target_indices = collapsed
        else:
            target_indices = raw_indices

        if len(target_indices) >= 2:
            incidents_data.append({
                "incident_id": inc_id,
                "stages": target_indices,
                "trajectory": tuple(target_indices)
            })

    return incidents_data


def generate_transition_instances(incidents: List[Dict]) -> List[Dict]:
    instances = []
    for inc in incidents:
        st = inc["stages"]
        traj = inc["trajectory"]
        inc_id = inc["incident_id"]
        for idx in range(len(st) - 1):
            prev = st[idx - 1] if idx > 0 else None
            curr = st[idx]
            tgt = st[idx + 1]
            instances.append({
                "incident_id": inc_id,
                "trajectory": traj,
                "step_index": idx,
                "prev": prev,
                "current": curr,
                "target": tgt
            })
    return instances


def evaluate_predictions(y_true: List[int], y_pred: List[int], y_top2: List[List[int]]) -> Dict[str, float]:
    y_true = np.array(y_true)
    y_pred = np.array(y_pred)
    acc = float(np.mean(y_true == y_pred))

    top2_correct = sum(1 for yt, preds in zip(y_true, y_top2) if yt in preds)
    top2_acc = float(top2_correct / len(y_true)) if len(y_true) > 0 else 0.0

    # Macro precision, recall, F1 across the 6 classes
    precisions = []
    recalls = []
    f1s = []
    for c in range(6):
        tp = int(np.sum((y_pred == c) & (y_true == c)))
        fp = int(np.sum((y_pred == c) & (y_true != c)))
        fn = int(np.sum((y_pred != c) & (y_true == c)))
        p = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        r = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f = (2 * p * r) / (p + r) if (p + r) > 0 else 0.0
        if (tp + fn) > 0:  # Class present in ground truth
            precisions.append(p)
            recalls.append(r)
            f1s.append(f)

    return {
        "accuracy": acc,
        "top2_accuracy": top2_acc,
        "macro_precision": float(np.mean(precisions)) if precisions else 0.0,
        "macro_recall": float(np.mean(recalls)) if recalls else 0.0,
        "macro_f1": float(np.mean(f1s)) if f1s else 0.0,
        "n_samples": len(y_true)
    }


def run_e5_experiment():
    print("=" * 80)
    print("EXPERIMENT E5: PREDICTIVE ANALYTICS FOR KILL-CHAIN PROGRESSION")
    print("=" * 80)

    incidents = extract_incident_sequences()
    all_transitions = generate_transition_instances(incidents)
    traj_counts = Counter(inc["trajectory"] for inc in incidents)
    unique_trajs = list(traj_counts.keys())

    print(f"Total Multi-Stage Incidents:  {len(incidents):,}")
    print(f"Unique Distinct Trajectories: {len(unique_trajs):,}")
    print(f"Total Transitions (N_trans):  {len(all_transitions):,}\n")

    # ──────────────────────────────────────────────────────────────────────────
    # 1. Full In-Sample Empirical Transition Matrix
    # ──────────────────────────────────────────────────────────────────────────
    print("--- PROTOCOL 1: FULL IN-SAMPLE EVALUATION & EMPIRICAL TRANSITION MATRIX ---")
    mfs = MostFrequentStageBaseline()
    m1 = FirstOrderMarkovChain()
    m2 = SecondOrderMarkovChain()

    mfs.fit(all_transitions)
    m1.fit(all_transitions)
    m2.fit(all_transitions)

    # Save Transition Matrix Counts & Probs
    df_counts = pd.DataFrame(m1.trans_counts, index=[STAGE_NAMES[i] for i in range(6)], columns=[STAGE_NAMES[j] for j in range(6)])
    counts_csv = os.path.join(RESULTS_DIR, "e5_transition_matrix_counts.csv")
    df_counts.to_csv(counts_csv)

    df_probs = pd.DataFrame(m1.trans_probs, index=[STAGE_NAMES[i] for i in range(6)], columns=[STAGE_NAMES[j] for j in range(6)])
    probs_csv = os.path.join(RESULTS_DIR, "e5_transition_matrix_probs.csv")
    df_probs.to_csv(probs_csv)
    print(f"[+] Saved Empirical Transition Matrices to:\n  - {counts_csv}\n  - {probs_csv}\n")

    print("Empirical Transition Counts (From -> To):")
    header = "From / To".ljust(22) + "".join(SHORT_NAMES[j].rjust(10) for j in range(6))
    print(header)
    for i in range(6):
        row = STAGE_NAMES[i].ljust(22)
        for j in range(6):
            row += f"{int(m1.trans_counts[i, j]):>10d}"
        print(row)

    # In-Sample Metrics
    y_true = [t["target"] for t in all_transitions]

    preds_mfs = [mfs.predict(t["current"], t["prev"]) for t in all_transitions]
    top2_mfs = [mfs.predict_top2(t["current"], t["prev"]) for t in all_transitions]
    met_mfs = evaluate_predictions(y_true, preds_mfs, top2_mfs)

    preds_m1 = [m1.predict(t["current"], t["prev"]) for t in all_transitions]
    top2_m1 = [m1.predict_top2(t["current"], t["prev"]) for t in all_transitions]
    met_m1 = evaluate_predictions(y_true, preds_m1, top2_m1)

    preds_m2 = [m2.predict(t["current"], t["prev"]) for t in all_transitions]
    top2_m2 = [m2.predict_top2(t["current"], t["prev"]) for t in all_transitions]
    met_m2 = evaluate_predictions(y_true, preds_m2, top2_m2)

    print("\nIn-Sample Performance (N = 223 transitions):")
    print(f"  Baseline (MFS):      Accuracy = {met_mfs['accuracy']:.4f} | Top-2 = {met_mfs['top2_accuracy']:.4f} | Macro-F1 = {met_mfs['macro_f1']:.4f}")
    print(f"  1st-Order Markov:    Accuracy = {met_m1['accuracy']:.4f} | Top-2 = {met_m1['top2_accuracy']:.4f} | Macro-F1 = {met_m1['macro_f1']:.4f}")
    print(f"  2nd-Order Markov:    Accuracy = {met_m2['accuracy']:.4f} | Top-2 = {met_m2['top2_accuracy']:.4f} | Macro-F1 = {met_m2['macro_f1']:.4f}")

    # ──────────────────────────────────────────────────────────────────────────
    # 2. Grouped 5-Fold Cross-Validation by Trajectory (Zero Trajectory Leakage)
    # ──────────────────────────────────────────────────────────────────────────
    print("\n--- PROTOCOL 2: GROUPED 5-FOLD CROSS-VALIDATION BY TRAJECTORY ---")
    np.random.seed(42)
    shuffled_trajs = list(unique_trajs)
    np.random.shuffle(shuffled_trajs)
    n_trajs = len(shuffled_trajs)
    k_folds = min(5, n_trajs)
    folds = [shuffled_trajs[i * n_trajs // k_folds : (i + 1) * n_trajs // k_folds] for i in range(k_folds)]

    cv_results = {"mfs": [], "m1": [], "m2": []}

    for fold_idx, test_trajs in enumerate(folds):
        test_traj_set = set(tuple(t) for t in test_trajs)
        train_trans = [t for t in all_transitions if t["trajectory"] not in test_traj_set]
        test_trans = [t for t in all_transitions if t["trajectory"] in test_traj_set]

        if not test_trans:
            continue

        y_test_fold = [t["target"] for t in test_trans]

        # Train models
        fold_mfs = MostFrequentStageBaseline()
        fold_mfs.fit(train_trans)
        fold_m1 = FirstOrderMarkovChain()
        fold_m1.fit(train_trans)
        fold_m2 = SecondOrderMarkovChain()
        fold_m2.fit(train_trans)

        p_mfs = [fold_mfs.predict(t["current"], t["prev"]) for t in test_trans]
        t2_mfs = [fold_mfs.predict_top2(t["current"], t["prev"]) for t in test_trans]
        cv_results["mfs"].append(evaluate_predictions(y_test_fold, p_mfs, t2_mfs))

        p_m1 = [fold_m1.predict(t["current"], t["prev"]) for t in test_trans]
        t2_m1 = [fold_m1.predict_top2(t["current"], t["prev"]) for t in test_trans]
        cv_results["m1"].append(evaluate_predictions(y_test_fold, p_m1, t2_m1))

        p_m2 = [fold_m2.predict(t["current"], t["prev"]) for t in test_trans]
        t2_m2 = [fold_m2.predict_top2(t["current"], t["prev"]) for t in test_trans]
        cv_results["m2"].append(evaluate_predictions(y_test_fold, p_m2, t2_m2))

    print(f"Grouped 5-Fold CV Results (Zero Trajectory Leakage Across Folds):")
    for model_key, name in [("mfs", "Baseline (MFS)"), ("m1", "1st-Order Markov"), ("m2", "2nd-Order Markov")]:
        accs = [r["accuracy"] for r in cv_results[model_key]]
        top2s = [r["top2_accuracy"] for r in cv_results[model_key]]
        f1s = [r["macro_f1"] for r in cv_results[model_key]]
        print(f"  {name:<18s}: Accuracy = {np.mean(accs):.4f} (±{np.std(accs):.4f}) | Top-2 = {np.mean(top2s):.4f} (±{np.std(top2s):.4f}) | Macro-F1 = {np.mean(f1s):.4f} (±{np.std(f1s):.4f})")

    # ──────────────────────────────────────────────────────────────────────────
    # 3. Leave-One-Trajectory-Out (LOTO) Cross-Validation (All 11 Trajectories)
    # ──────────────────────────────────────────────────────────────────────────
    print("\n--- PROTOCOL 3: LEAVE-ONE-TRAJECTORY-OUT (LOTO) AUDIT (11 TRAJECTORIES) ---")
    loto_records = []

    for traj_idx, held_out_traj in enumerate(unique_trajs):
        test_trans = [t for t in all_transitions if t["trajectory"] == held_out_traj]
        train_trans = [t for t in all_transitions if t["trajectory"] != held_out_traj]

        y_true_loto = [t["target"] for t in test_trans]

        loto_mfs = MostFrequentStageBaseline()
        loto_mfs.fit(train_trans)
        loto_m1 = FirstOrderMarkovChain()
        loto_m1.fit(train_trans)
        loto_m2 = SecondOrderMarkovChain()
        loto_m2.fit(train_trans)

        p_mfs = [loto_mfs.predict(t["current"], t["prev"]) for t in test_trans]
        t2_mfs = [loto_mfs.predict_top2(t["current"], t["prev"]) for t in test_trans]
        m_mfs = evaluate_predictions(y_true_loto, p_mfs, t2_mfs)

        p_m1 = [loto_m1.predict(t["current"], t["prev"]) for t in test_trans]
        t2_m1 = [loto_m1.predict_top2(t["current"], t["prev"]) for t in test_trans]
        m_m1 = evaluate_predictions(y_true_loto, p_m1, t2_m1)

        p_m2 = [loto_m2.predict(t["current"], t["prev"]) for t in test_trans]
        t2_m2 = [loto_m2.predict_top2(t["current"], t["prev"]) for t in test_trans]
        m_m2 = evaluate_predictions(y_true_loto, p_m2, t2_m2)

        traj_name = " -> ".join(SHORT_NAMES[s] for s in held_out_traj)
        n_inc = traj_counts[held_out_traj]
        n_tr = len(test_trans)

        # Check if transitions exist in train set
        train_pairs = set((t["current"], t["target"]) for t in train_trans)
        test_pairs = set((t["current"], t["target"]) for t in test_trans)
        novel_pairs = test_pairs - train_pairs

        loto_records.append({
            "trajectory_id": f"TRAJ-{traj_idx+1:02d}",
            "trajectory_name": traj_name,
            "incidents_count": n_inc,
            "transitions_count": n_tr,
            "novel_transitions": len(novel_pairs),
            "mfs_accuracy": m_mfs["accuracy"],
            "m1_accuracy": m_m1["accuracy"],
            "m1_top2": m_m1["top2_accuracy"],
            "m2_accuracy": m_m2["accuracy"],
            "m2_top2": m_m2["top2_accuracy"]
        })

    df_loto = pd.DataFrame(loto_records)
    loto_csv = os.path.join(RESULTS_DIR, "e5_loto_per_trajectory.csv")
    df_loto.to_csv(loto_csv, index=False)
    print(f"[+] Saved LOTO Per-Trajectory Results to: {loto_csv}\n")

    print(df_loto[["trajectory_id", "trajectory_name", "incidents_count", "m1_accuracy", "m1_top2", "m2_accuracy", "m2_top2"]].to_string(index=False))

    # Overall Summary Table
    summary_rows = [
        {
            "evaluation_protocol": "In-Sample (Full Dataset N=223)",
            "model": "Most-Frequent-Stage (MFS)",
            "accuracy": round(met_mfs["accuracy"], 4),
            "top2_accuracy": round(met_mfs["top2_accuracy"], 4),
            "macro_f1": round(met_mfs["macro_f1"], 4),
            "notes": "Unconditional prior baseline"
        },
        {
            "evaluation_protocol": "In-Sample (Full Dataset N=223)",
            "model": "1st-Order Markov Chain",
            "accuracy": round(met_m1["accuracy"], 4),
            "top2_accuracy": round(met_m1["top2_accuracy"], 4),
            "macro_f1": round(met_m1["macro_f1"], 4),
            "notes": "State-to-state conditional probability"
        },
        {
            "evaluation_protocol": "In-Sample (Full Dataset N=223)",
            "model": "2nd-Order Markov Chain",
            "accuracy": round(met_m2["accuracy"], 4),
            "top2_accuracy": round(met_m2["top2_accuracy"], 4),
            "macro_f1": round(met_m2["macro_f1"], 4),
            "notes": "Pair-to-state with 1st-order backoff"
        },
        {
            "evaluation_protocol": "Grouped 5-Fold CV (Zero Trajectory Leakage)",
            "model": "Most-Frequent-Stage (MFS)",
            "accuracy": round(float(np.mean([r["accuracy"] for r in cv_results["mfs"]])), 4),
            "top2_accuracy": round(float(np.mean([r["top2_accuracy"] for r in cv_results["mfs"]])), 4),
            "macro_f1": round(float(np.mean([r["macro_f1"] for r in cv_results["mfs"]])), 4),
            "notes": "Unseen trajectories"
        },
        {
            "evaluation_protocol": "Grouped 5-Fold CV (Zero Trajectory Leakage)",
            "model": "1st-Order Markov Chain",
            "accuracy": round(float(np.mean([r["accuracy"] for r in cv_results["m1"]])), 4),
            "top2_accuracy": round(float(np.mean([r["top2_accuracy"] for r in cv_results["m1"]])), 4),
            "macro_f1": round(float(np.mean([r["macro_f1"] for r in cv_results["m1"]])), 4),
            "notes": "Unseen trajectories"
        },
        {
            "evaluation_protocol": "Grouped 5-Fold CV (Zero Trajectory Leakage)",
            "model": "2nd-Order Markov Chain",
            "accuracy": round(float(np.mean([r["accuracy"] for r in cv_results["m2"]])), 4),
            "top2_accuracy": round(float(np.mean([r["top2_accuracy"] for r in cv_results["m2"]])), 4),
            "macro_f1": round(float(np.mean([r["macro_f1"] for r in cv_results["m2"]])), 4),
            "notes": "Unseen trajectories"
        },
        {
            "evaluation_protocol": "Leave-One-Trajectory-Out (LOTO Macro Mean)",
            "model": "Most-Frequent-Stage (MFS)",
            "accuracy": round(float(df_loto["mfs_accuracy"].mean()), 4),
            "top2_accuracy": round(float(df_loto["mfs_accuracy"].mean()), 4),  # baseline top1
            "macro_f1": 0.0,
            "notes": "Across all 11 trajectories"
        },
        {
            "evaluation_protocol": "Leave-One-Trajectory-Out (LOTO Macro Mean)",
            "model": "1st-Order Markov Chain",
            "accuracy": round(float(df_loto["m1_accuracy"].mean()), 4),
            "top2_accuracy": round(float(df_loto["m1_top2"].mean()), 4),
            "macro_f1": 0.0,
            "notes": "Across all 11 trajectories"
        },
        {
            "evaluation_protocol": "Leave-One-Trajectory-Out (LOTO Macro Mean)",
            "model": "2nd-Order Markov Chain",
            "accuracy": round(float(df_loto["m2_accuracy"].mean()), 4),
            "top2_accuracy": round(float(df_loto["m2_top2"].mean()), 4),
            "macro_f1": 0.0,
            "notes": "Across all 11 trajectories"
        }
    ]

    df_summary = pd.DataFrame(summary_rows)
    summary_csv = os.path.join(RESULTS_DIR, "e5_markov_evaluation_summary.csv")
    df_summary.to_csv(summary_csv, index=False)
    print(f"\n[+] Saved Complete E5 Summary Table to: {summary_csv}")


if __name__ == "__main__":
    run_e5_experiment()

