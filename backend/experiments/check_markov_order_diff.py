import sqlite3
import os
import json
from collections import Counter, defaultdict

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(ROOT_DIR, "security.db")

import sys
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
from engines.risk_engine import map_stage_to_index

# Let's see: for every transition instance, what does 1st-order predict vs 2nd-order?
conn = sqlite3.connect(DB_PATH)
rows = conn.execute("SELECT incident_id, attack_stages_json FROM incidents").fetchall()
conn.close()

sequences = []
for inc_id, s_json in rows:
    stages = json.loads(s_json) if s_json else []
    mapped = [map_stage_to_index(s) for s in stages if map_stage_to_index(s) is not None]
    if len(mapped) >= 2:
        sequences.append(mapped)

# Build 1st-order counts and 2nd-order counts
c1 = defaultdict(Counter)
c2 = defaultdict(Counter)

for seq in sequences:
    for i in range(len(seq) - 1):
        prev = seq[i-1] if i > 0 else None
        curr = seq[i]
        tgt = seq[i+1]
        c1[curr][tgt] += 1
        if prev is not None:
            c2[(prev, curr)][tgt] += 1

print("=== FIRST ORDER PREDICTIONS ===")
for curr, tgts in sorted(c1.items()):
    best = tgts.most_common(1)[0]
    print(f"State {curr} -> Top transition: {best[0]} (count {best[1]}/{sum(tgts.values())}) | All: {dict(tgts)}")

print("\n=== SECOND ORDER PREDICTIONS ===")
differences = 0
for (prev, curr), tgts in sorted(c2.items()):
    best2 = tgts.most_common(1)[0]
    best1 = c1[curr].most_common(1)[0]
    is_diff = best2[0] != best1[0]
    if is_diff:
        differences += 1
    print(f"History ({prev}, {curr}) -> Top: {best2[0]} (count {best2[1]}/{sum(tgts.values())}) | 1st-order was: {best1[0]} | Diff: {is_diff}")

print(f"\nTotal contexts where 2nd order argmax differs from 1st order argmax: {differences}")

