import os
import sys
import json
import sqlite3
import numpy as np
import pandas as pd
from collections import Counter, defaultdict

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(ROOT_DIR, "security.db")
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
        incidents.append(mapped)

transitions = []
for seq in incidents:
    for i in range(len(seq) - 1):
        transitions.append((seq[i], seq[i+1]))

c1 = defaultdict(Counter)
for curr, tgt in transitions:
    c1[curr][tgt] += 1

print("=== BRANCH DISTRIBUTION FROM EACH STAGE ===")
majority_transitions = []
minority_transitions = []

for curr, tgts in sorted(c1.items()):
    total_out = sum(tgts.values())
    top_tgt, top_cnt = tgts.most_common(1)[0]
    print(f"\nStage {SHORT_NAMES[curr]} ({curr}) -> Total Outbound: {total_out}")
    for tgt, cnt in tgts.most_common():
        pct = (cnt / total_out) * 100
        is_maj = (tgt == top_tgt)
        label = "MAJORITY" if is_maj else "MINORITY"
        print(f"  -> {SHORT_NAMES[tgt]} ({tgt}): {cnt:3d} ({pct:5.1f}%) [{label}]")
        for _ in range(cnt):
            if is_maj:
                majority_transitions.append((curr, tgt))
            else:
                minority_transitions.append((curr, tgt))

print(f"\nTotal Majority Branch Transitions: {len(majority_transitions)} ({len(majority_transitions)/len(transitions)*100:.2f}%)")
print(f"Total Minority Branch Transitions: {len(minority_transitions)} ({len(minority_transitions)/len(transitions)*100:.2f}%)")
print(f"Total Transitions: {len(transitions)}")

print("\nBreakdown of the 10 Minority Branch Transitions:")
min_counter = Counter(minority_transitions)
for (curr, tgt), count in min_counter.items():
    print(f"  {SHORT_NAMES[curr]} ({curr}) -> {SHORT_NAMES[tgt]} ({tgt}): {count} occurrences")

# Evaluate deterministic Markov recall
maj_correct = len(majority_transitions) # 213/213
min_correct = 0 # 0/10

print(f"\nDeterministic Markov Recall on Majority Branches: {maj_correct}/{len(majority_transitions)} = 100.0%")
print(f"Deterministic Markov Recall on Minority Branches: {min_correct}/{len(minority_transitions)} = 0.0%")
print(f"Overall Accuracy: {(maj_correct + min_correct)}/{len(transitions)} = {(maj_correct + min_correct)/len(transitions)*100:.2f}%")

