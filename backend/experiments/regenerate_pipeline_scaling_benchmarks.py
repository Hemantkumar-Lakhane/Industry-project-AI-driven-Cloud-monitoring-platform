"""
Regenerate Pipeline & Correlation Scaling Benchmarks (Purely Programmatic)
========================================================================
Executes 3 iterations for N in [500, 1000, 2000, 5000] alerts from alerts.json.
Writes pipeline_correlation_scaling.csv and pipeline_correlation_scaling.json directly.
No manual edits.
"""
import os
import sys
import time
import json
import numpy as np
import pandas as pd

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from engines.correlation_engine import correlate_findings
from engines.risk_engine import calculate_unified_risk

RESULTS_DIR = os.path.join(ROOT_DIR, "experiments", "results")
ALERTS_PATH = os.path.join(ROOT_DIR, "data", "alerts.json")


def regenerate_scaling():
    print("=" * 80, flush=True)
    print("REGENERATING PIPELINE CORRELATION SCALING BENCHMARK (3 RUNS PER SLICE)", flush=True)
    print("=" * 80, flush=True)

    with open(ALERTS_PATH, "r", encoding="utf-8") as f:
        all_raw_alerts = [json.loads(line.strip()) for line in f if line.strip()]

    slice_sizes = [500, 1000, 2000, 5000]
    records = []

    for n in slice_sizes:
        print(f"\n[*] Benchmarking Slice N = {n:,} alerts (3 iterations)...", flush=True)
        raw_slice = all_raw_alerts[:n]

        norm_times = []
        corr_times = []
        risk_times = []
        total_times = []
        incidents_counts = []

        for it in range(3):
            # Normalization
            t0 = time.perf_counter()
            findings = []
            for idx, a in enumerate(raw_slice):
                rule = a.get("rule", {})
                cat = a.get("attack_category") or rule.get("category") or "suspicious_api_activity"
                ts = a.get("timestamp") or a.get("@timestamp") or "2026-10-26T12:00:00Z"
                res = a.get("affected_resource") or a.get("resource") or a.get("target") or "cloud-resource"
                p = a.get("affected_principal") or a.get("user") or a.get("principal") or "cloud-user"
                ip = a.get("source_ip") or a.get("src_ip") or "198.51.100.1"

                findings.append({
                    "finding_id": f"FIND-REGEN-{idx:05d}",
                    "title": a.get("title") or rule.get("description") or f"Finding {idx}",
                    "attack_category": str(cat).lower(),
                    "severity": str(a.get("severity") or rule.get("severity") or "medium").lower(),
                    "status": "open",
                    "timestamp": ts,
                    "created_at": ts,
                    "affected_resource": res,
                    "affected_principal": p,
                    "source_ip": ip,
                    "evidence": {
                        "observed_facts": [f"Source IP {ip}", f"Resource {res}"],
                        "telemetry_fields": {"principal": p, "source_ip": ip, "resource": res}
                    }
                })
            t_norm = time.perf_counter() - t0
            norm_times.append(t_norm)

            # Correlation
            t0 = time.perf_counter()
            incidents = correlate_findings(findings, window_seconds=900.0)
            t_corr = time.perf_counter() - t0
            corr_times.append(t_corr)

            # Risk Scoring
            t0 = time.perf_counter()
            _ = calculate_unified_risk(
                analyzed_events=[],
                cspm_findings=[],
                ciem_findings=[],
                incidents=incidents
            )
            t_risk = time.perf_counter() - t0
            risk_times.append(t_risk)

            t_total = t_norm + t_corr + t_risk
            total_times.append(t_total)
            incidents_counts.append(len(incidents))
            print(f"    Pass {it+1}/3: Norm={t_norm:.4f}s | Corr={t_corr:.2f}s | Risk={t_risk:.4f}s | Total={t_total:.2f}s", flush=True)

        mean_norm = float(np.mean(norm_times))
        std_norm = float(np.std(norm_times))
        mean_corr = float(np.mean(corr_times))
        std_corr = float(np.std(corr_times))
        mean_risk = float(np.mean(risk_times))
        std_risk = float(np.std(risk_times))
        mean_total = float(np.mean(total_times))
        std_total = float(np.std(total_times))
        corr_thru = float(n / mean_corr) if mean_corr > 0 else 0.0
        tot_thru = float(n / mean_total) if mean_total > 0 else 0.0

        records.append({
            "n_alerts": n,
            "runs": 3,
            "incidents_formed": int(incidents_counts[0]),
            "normalization_time_sec": round(mean_norm, 4),
            "normalization_std": round(std_norm, 4),
            "correlation_time_sec": round(mean_corr, 4),
            "correlation_std": round(std_corr, 4),
            "correlation_throughput_alerts_sec": round(corr_thru, 1),
            "risk_scoring_time_sec": round(mean_risk, 4),
            "risk_scoring_std": round(std_risk, 4),
            "total_pipeline_time_sec": round(mean_total, 4),
            "total_pipeline_std": round(std_total, 4),
            "total_throughput_alerts_sec": round(tot_thru, 1)
        })

    df = pd.DataFrame(records)
    out_csv = os.path.join(RESULTS_DIR, "pipeline_correlation_scaling.csv")
    out_json = os.path.join(RESULTS_DIR, "pipeline_correlation_scaling.json")

    df.to_csv(out_csv, index=False)
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2)

    print(f"\n[+] Successfully regenerated:\n  - {out_csv}\n  - {out_json}", flush=True)


if __name__ == "__main__":
    regenerate_scaling()

