import sqlite3
import os
import json
from collections import Counter, defaultdict

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(ROOT_DIR, "security.db")

import sys
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
from engines.risk_engine import map_stage_to_index, MITRE_STAGE_ORDER

STAGE_NAMES = {0: "Recon", 1: "Access", 2: "PrivEsc", 3: "Evasion", 4: "Exfil", 5: "Impact"}

conn = sqlite3.connect(DB_PATH)
rows = conn.execute("SELECT incident_id, attack_stages_json FROM incidents").fetchall()
conn.close()

print(f"Total rows in incidents: {len(rows)}")

# Let's inspect raw stages and mapped stages
trajectories_raw = Counter()
trajectories_mapped = Counter()
trajectories_collapsed = Counter()

raw_transitions = Counter()
collapsed_transitions = Counter()

sample_raw_per_traj = {}

for inc_id, s_json in rows:
    stages = json.loads(s_json) if s_json else []
    if len(stages) >= 2:
        raw_tuple = tuple(stages)
        trajectories_raw[raw_tuple] += 1
        
        mapped = [map_stage_to_index(s) for s in stages if map_stage_to_index(s) is not None]
        if len(mapped) >= 2:
            mapped_tuple = tuple(mapped)
            trajectories_mapped[mapped_tuple] += 1
            if mapped_tuple not in sample_raw_per_traj:
                sample_raw_per_traj[mapped_tuple] = (stages, mapped)
                
            for i in range(len(mapped) - 1):
                raw_transitions[(mapped[i], mapped[i+1])] += 1
                
            # Collapsed
            col = []
            for s in mapped:
                if not col or s != col[-1]:
                    col.append(s)
            if len(col) >= 2:
                col_tuple = tuple(col)
                trajectories_collapsed[col_tuple] += 1
                for i in range(len(col) - 1):
                    collapsed_transitions[(col[i], col[i+1])] += 1

print("\n=== RAW DISTINCT TRAJECTORIES (BEFORE MAPPING) ===")
print(f"Count of raw string trajectories: {len(trajectories_raw)}")
for traj, count in trajectories_raw.most_common(15):
    print(f"  {traj} : {count}")

print(f"\n=== MAPPED TRAJECTORIES (WITHOUT COLLAPSING DUPLICATES) ===")
print(f"Count of mapped trajectories: {len(trajectories_mapped)}")
print(f"Total incidents: {sum(trajectories_mapped.values())}")
print(f"Total transitions: {sum(raw_transitions.values())}")

for traj, count in trajectories_mapped.most_common(15):
    raw_sample = sample_raw_per_traj[traj][0]
    name_str = " -> ".join(STAGE_NAMES[s] for s in traj)
    print(f"  [{count:2d} incs] {name_str:<45s} | Raw: {raw_sample}")

print("\nTransition counts (Raw Mapped):")
for k, v in sorted(raw_transitions.items()):
    print(f"  {STAGE_NAMES[k[0]]} ({k[0]}) -> {STAGE_NAMES[k[1]]} ({k[1]}): {v}")

print(f"\n=== MAPPED TRAJECTORIES (WITH CONSECUTIVE DUPLICATES COLLAPSED) ===")
print(f"Count of collapsed trajectories: {len(trajectories_collapsed)}")
print(f"Total incidents: {sum(trajectories_collapsed.values())}")
print(f"Total transitions: {sum(collapsed_transitions.values())}")
for traj, count in trajectories_collapsed.most_common(15):
    name_str = " -> ".join(STAGE_NAMES[s] for s in traj)
    print(f"  [{count:2d} incs] {name_str:<45s}")

print("\nTransition counts (Collapsed):")
for k, v in sorted(collapsed_transitions.items()):
    print(f"  {STAGE_NAMES[k[0]]} ({k[0]}) -> {STAGE_NAMES[k[1]]} ({k[1]}): {v}")

