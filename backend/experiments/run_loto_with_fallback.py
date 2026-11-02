import os
import sys
import json
import sqlite3
import numpy as np
import pandas as pd
from collections import Counter, defaultdict

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(ROOT_DIR, "security.db")
RESULTS_DIR = os.path.join(ROOT_DIR, "experiments", "results")

if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
from engines.risk_engine import map_stage_to_index

SHORT_NAMES = {0: "Recon", 1: "Access", 2: "PrivEsc", 3: "Evasion", 4: "Exfil", 5: "Impact"}

conn = sqlite3.connect(DB_PATH)
rows = conn.execute("SELECT incident_id, attack_stages_json FROM incidents").fetchall()
conn.close()

incidents = []
for inc_id, s_json in rows:
    stages = json.loads(s_json) if s_json else []
    mapped = [map_stage_to_index(s) for s in stages if map_stage_to_index(s) is not None]
    if len(mapped) >= 2:
        incidents.append({
            "incident_id": inc_id,
            "stages": mapped,
            "trajectory": tuple(mapped)
        })

# Flatten transitions
all_trans = []
for inc in incidents:
    st = inc["stages"]
    traj = inc["trajectory"]
    for i in range(len(st) - 1):
        all_trans.append({
            "incident_id": inc["incident_id"],
            "trajectory": traj,
            "prev": st[i-1] if i > 0 else None,
            "curr": st[i],
            "tgt": st[i+1]
        })

N_total = len(all_trans)
print(f"Total transitions: {N_total}")

# Prior distribution over targets (unconditional stage prior)
prior_counter = Counter(t["tgt"] for t in all_trans)
prior_top1 = prior_counter.most_common(1)[0][0]
prior_top2 = [c[0] for c in prior_counter.most_common(2)]
print(f"Unconditional Stage Prior Top-1: {SHORT_NAMES[prior_top1]} ({prior_top1})")
print(f"Unconditional Stage Prior Top-2: {[SHORT_NAMES[s] for s in prior_top2]}")

# Distinct trajectories
traj_counts = Counter(inc["trajectory"] for inc in incidents)
unique_trajs = sorted(traj_counts.keys(), key=lambda x: traj_counts[x], reverse=True)

loto_results = []
pooled_correct_mfs = 0
pooled_correct_top2_mfs = 0
pooled_correct_m1 = 0
pooled_correct_top2_m1 = 0
pooled_correct_m2 = 0
pooled_correct_top2_m2 = 0

for traj_idx, held_out_traj in enumerate(unique_trajs):
    test_t = [t for t in all_trans if t["trajectory"] == held_out_traj]
    train_t = [t for t in all_trans if t["trajectory"] != held_out_traj]
    
    # Train stage prior on training set
    tr_prior = Counter(t["tgt"] for t in train_t)
    fallback_top1 = tr_prior.most_common(1)[0][0]
    fallback_top2 = [c[0] for c in tr_prior.most_common(2)]
    
    # Train 1st-order Markov
    tr_c1 = defaultdict(Counter)
    for t in train_t:
        tr_c1[t["curr"]][t["tgt"]] += 1
        
    # Train 2nd-order Markov
    tr_c2 = defaultdict(Counter)
    for t in train_t:
        if t["prev"] is not None:
            tr_c2[(t["prev"], t["curr"])][t["tgt"]] += 1
            
    # Evaluate test instances
    mfs_hits = 0
    mfs_hits_top2 = 0
    m1_hits = 0
    m1_hits_top2 = 0
    m2_hits = 0
    m2_hits_top2 = 0
    
    for t in test_t:
        curr = t["curr"]
        prev = t["prev"]
        tgt = t["tgt"]
        
        # MFS
        p_mfs = fallback_top1
        p_mfs_t2 = fallback_top2
        if tgt == p_mfs:
            mfs_hits += 1
        if tgt in p_mfs_t2:
            mfs_hits_top2 += 1
            
        # 1st-order with stage-prior fallback
        if curr in tr_c1 and len(tr_c1[curr]) > 0:
            top_c1 = tr_c1[curr].most_common(2)
            p_m1 = top_c1[0][0]
            p_m1_t2 = [c[0] for c in top_c1]
            if len(p_m1_t2) < 2:
                # Add stage prior fallback for 2nd slot
                for s in fallback_top2:
                    if s not in p_m1_t2:
                        p_m1_t2.append(s)
                        break
        else:
            p_m1 = fallback_top1
            p_m1_t2 = fallback_top2
            
        if tgt == p_m1:
            m1_hits += 1
        if tgt in p_m1_t2:
            m1_hits_top2 += 1
            
        # 2nd-order with 1st-order & stage-prior fallback
        if prev is not None and (prev, curr) in tr_c2 and len(tr_c2[(prev, curr)]) > 0:
            top_c2 = tr_c2[(prev, curr)].most_common(2)
            p_m2 = top_c2[0][0]
            p_m2_t2 = [c[0] for c in top_c2]
            if len(p_m2_t2) < 2:
                for s in p_m1_t2:
                    if s not in p_m2_t2:
                        p_m2_t2.append(s)
                        break
        else:
            # Backoff to 1st-order
            p_m2 = p_m1
            p_m2_t2 = p_m1_t2
            
        if tgt == p_m2:
            m2_hits += 1
        if tgt in p_m2_t2:
            m2_hits_top2 += 1
            
    n_tr = len(test_t)
    pooled_correct_mfs += mfs_hits
    pooled_correct_top2_mfs += mfs_hits_top2
    pooled_correct_m1 += m1_hits
    pooled_correct_top2_m1 += m1_hits_top2
    pooled_correct_m2 += m2_hits
    pooled_correct_top2_m2 += m2_hits_top2
    
    traj_name = " -> ".join(SHORT_NAMES[s] for s in held_out_traj)
    loto_results.append({
        "trajectory_id": f"TRAJ-{traj_idx+1:02d}",
        "trajectory_name": traj_name,
        "trajectory_tuple": str(held_out_traj),
        "incidents_count": traj_counts[held_out_traj],
        "transitions_count": n_tr,
        "mfs_accuracy": mfs_hits / n_tr,
        "mfs_top2": mfs_hits_top2 / n_tr,
        "m1_accuracy": m1_hits / n_tr,
        "m1_top2": m1_hits_top2 / n_tr,
        "m2_accuracy": m2_hits / n_tr,
        "m2_top2": m2_hits_top2 / n_tr,
        "correct_m1": m1_hits,
        "correct_top2_m1": m1_hits_top2
    })

print("\n=== POOLED LOTO RESULTS (N = 223 TRANSITIONS) ===")
print(f"MFS Baseline Pooled Accuracy: {pooled_correct_mfs} / {N_total} = {pooled_correct_mfs / N_total:.4f} ({pooled_correct_mfs / N_total * 100:.2f}%)")
print(f"MFS Baseline Pooled Top-2:    {pooled_correct_top2_mfs} / {N_total} = {pooled_correct_top2_mfs / N_total:.4f} ({pooled_correct_top2_mfs / N_total * 100:.2f}%)")
print(f"1st-Order Markov Pooled Acc:  {pooled_correct_m1} / {N_total} = {pooled_correct_m1 / N_total:.4f} ({pooled_correct_m1 / N_total * 100:.2f}%)")
print(f"1st-Order Markov Pooled Top-2:{pooled_correct_top2_m1} / {N_total} = {pooled_correct_top2_m1 / N_total:.4f} ({pooled_correct_top2_m1 / N_total * 100:.2f}%)")
print(f"2nd-Order Markov Pooled Acc:  {pooled_correct_m2} / {N_total} = {pooled_correct_m2 / N_total:.4f} ({pooled_correct_m2 / N_total * 100:.2f}%)")
print(f"2nd-Order Markov Pooled Top-2:{pooled_correct_top2_m2} / {N_total} = {pooled_correct_top2_m2 / N_total:.4f} ({pooled_correct_top2_m2 / N_total * 100:.2f}%)")

df_loto = pd.DataFrame(loto_results)
out_csv = os.path.join(RESULTS_DIR, "e5_loto_with_fallback.csv")
df_loto.to_csv(out_csv, index=False)
print(f"\n[+] Saved refined LOTO to: {out_csv}")
print(df_loto[["trajectory_id", "trajectory_name", "incidents_count", "transitions_count", "m1_accuracy", "m1_top2", "m2_accuracy", "m2_top2"]].to_string(index=False))

