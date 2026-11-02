import sys
import os

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from simulator import attack_simulator

flow_keys = {"duration", "src_bytes", "dst_bytes", "bytes_transferred", "count", "srv_count", "serror_rate", "rerror_rate", "same_srv_rate", "diff_srv_rate"}

print(f"{'Scenario Name':<28s} | {'Evts':<5s} | {'Flow-Related Keys Present'} | {'Sample Values'}")
print("-" * 95)

for name, fn in attack_simulator.SCENARIOS.items():
    try:
        res = fn()
        evts = res.get("events", [])
        all_keys = set()
        for e in evts:
            all_keys.update(e.keys())
        present_flow = flow_keys.intersection(all_keys)
        samples = {}
        if evts:
            for k in sorted(list(present_flow)):
                samples[k] = evts[0].get(k)
        print(f"{name:<28s} | {len(evts):<5d} | {str(sorted(list(present_flow))):<25s} | {samples}")
    except Exception as e:
        print(f"{name:<28s} | ERR: {e}")
