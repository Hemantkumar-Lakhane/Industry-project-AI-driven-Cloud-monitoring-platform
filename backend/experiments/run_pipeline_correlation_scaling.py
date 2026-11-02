"""
Pipeline & Correlation Scaling Benchmark
========================================
Measures execution time and throughput across input slices:
N in [500, 1000, 2000, 5000] alerts from alerts.json.

Deconstructs pipeline into 4 distinct stages:
Stage 1: File Ingestion & JSON Deserialization
Stage 2: Schema Normalization (Raw Alert -> SecurityFinding)
Stage 3: Correlation Engine (Union-Find Temporal & Entity Graph Clustering)
Stage 4: Unified Risk Engine (Multi-Pillar Scoring & Kill-Chain Multiplier)
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
PROJECT_ROOT = os.path.dirname(ROOT_DIR)
PYLIBS_DIR = os.path.join(PROJECT_ROOT, "pylibs")
if os.path.exists(PYLIBS_DIR) and PYLIBS_DIR not in sys.path:
    sys.path.insert(0, PYLIBS_DIR)

from engines.correlation_engine import correlate_findings
from engines.risk_engine import calculate_unified_risk

RESULTS_DIR = os.path.join(ROOT_DIR, "experiments", "results")
ALERTS_PATH = os.path.join(ROOT_DIR, "data", "alerts.json")


def run_scaling_benchmark():
    print("=" * 80, flush=True)
    print("PIPELINE & CORRELATION SCALING BENCHMARK", flush=True)
    print("=" * 80, flush=True)

    with open(ALERTS_PATH, "r", encoding="utf-8") as f:
        all_raw_alerts = [json.loads(line.strip()) for line in f if line.strip()]

    print(f"Total raw alerts loaded from disk: {len(all_raw_alerts):,}", flush=True)

    slice_sizes = [500, 1000, 2000, 5000]
    scaling_records = []

    for n in slice_sizes:
        print(f"\n--- Benchmarking Slice N = {n:,} alerts ---", flush=True)
        raw_slice = all_raw_alerts[:n]

        norm_times = []
        corr_times = []
        risk_times = []
        total_times = []
        incidents_counts = []

        # Run 3 iterations per slice size for variance estimation
        n_iters = 3
        for it in range(n_iters):
            # Stage 2: Normalization
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
                    "finding_id": f"FIND-SLICE-{idx:05d}",
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

            # Stage 3: Correlation
            t0 = time.perf_counter()
            incidents = correlate_findings(findings, window_seconds=900.0)
            t_corr = time.perf_counter() - t0
            corr_times.append(t_corr)

            # Stage 4: Risk Scoring
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

        mean_norm = float(np.mean(norm_times))
        std_norm = float(np.std(norm_times))
        mean_corr = float(np.mean(corr_times))
        std_corr = float(np.std(corr_times))
        mean_risk = float(np.mean(risk_times))
        std_risk = float(np.std(risk_times))
        mean_total = float(np.mean(total_times))
        std_total = float(np.std(total_times))
        corr_throughput = n / mean_corr if mean_corr > 0 else 0.0
        total_throughput = n / mean_total if mean_total > 0 else 0.0
        n_inc = int(incidents_counts[0])

        print(f"  Normalization:   {mean_norm:.4f}s (±{std_norm:.4f}s)")
        print(f"  Correlation:     {mean_corr:.4f}s (±{std_corr:.4f}s) -> {corr_throughput:.1f} alerts/sec")
        print(f"  Risk Scoring:    {mean_risk:.4f}s (±{std_risk:.4f}s)")
        print(f"  Total Pipeline:  {mean_total:.4f}s (±{std_total:.4f}s) -> {total_throughput:.1f} alerts/sec")
        print(f"  Incidents Formed:{n_inc:,}")

        scaling_records.append({
            "n_alerts": n,
            "incidents_formed": n_inc,
            "normalization_time_sec": round(mean_norm, 4),
            "normalization_std": round(std_norm, 4),
            "correlation_time_sec": round(mean_corr, 4),
            "correlation_std": round(std_corr, 4),
            "correlation_throughput_alerts_sec": round(corr_throughput, 1),
            "risk_scoring_time_sec": round(mean_risk, 4),
            "risk_scoring_std": round(std_risk, 4),
            "total_pipeline_time_sec": round(mean_total, 4),
            "total_pipeline_std": round(std_total, 4),
            "total_throughput_alerts_sec": round(total_throughput, 1)
        })

    df_scaling = pd.DataFrame(scaling_records)
    out_csv = os.path.join(RESULTS_DIR, "pipeline_correlation_scaling.csv")
    out_json = os.path.join(RESULTS_DIR, "pipeline_correlation_scaling.json")
    df_scaling.to_csv(out_csv, index=False)
    with open(out_json, "w") as f:
        json.dump(scaling_records, f, indent=2)

    print(f"\n[+] Saved Scaling Benchmark results to:\n  - {out_csv}\n  - {out_json}", flush=True)


if __name__ == "__main__":
    run_scaling_benchmark()

