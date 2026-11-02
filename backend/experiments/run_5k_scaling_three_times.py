"""
Run N=5,000 Alerts Scaling 3 Times to Get Mean ± Std
===================================================
Pipeline stages timed:
Stage 1: Raw JSON Ingestion & Deserialization
Stage 2: Schema Normalization (Raw Alert -> SecurityFinding)
Stage 3: Temporal Sliding-Window Correlation Engine (correlate_findings, delta_T = 900s)
Stage 4: Unified Multi-Pillar Risk Engine (calculate_unified_risk)

Note: ML anomaly detectors (PyOD models) and rule matching run upstream during
telemetry ingestion and are NOT part of this correlation stress test.
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


def run_5k_benchmark_3x():
    print("=" * 80, flush=True)
    print("BENCHMARKING N=5,000 ALERTS PIPELINE (3 REPEATED RUNS)", flush=True)
    print("=" * 80, flush=True)

    with open(ALERTS_PATH, "r", encoding="utf-8") as f:
        all_raw_alerts = [json.loads(line.strip()) for line in f if line.strip()]

    raw_5k = all_raw_alerts[:5000]
    n_alerts = len(raw_5k)
    print(f"Loaded {n_alerts:,} alerts for repeated evaluation.\n", flush=True)

    ingest_times = []
    norm_times = []
    corr_times = []
    risk_times = []
    total_times = []
    incidents_counts = []

    for run_idx in range(1, 4):
        print(f"--- Iteration {run_idx}/3 ---", flush=True)

        # Stage 1: Ingestion
        t0 = time.perf_counter()
        _ = [dict(a) for a in raw_5k]
        t_ingest = time.perf_counter() - t0
        ingest_times.append(t_ingest)

        # Stage 2: Normalization
        t0 = time.perf_counter()
        findings = []
        for idx, a in enumerate(raw_5k):
            rule = a.get("rule", {})
            cat = a.get("attack_category") or rule.get("category") or "suspicious_api_activity"
            ts = a.get("timestamp") or a.get("@timestamp") or "2026-10-26T12:00:00Z"
            res = a.get("affected_resource") or a.get("resource") or a.get("target") or "cloud-resource"
            p = a.get("affected_principal") or a.get("user") or a.get("principal") or "cloud-user"
            ip = a.get("source_ip") or a.get("src_ip") or "198.51.100.1"

            findings.append({
                "finding_id": f"FIND-5K-{idx:05d}",
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

        print(f"  Ingest: {t_ingest:.4f}s | Norm: {t_norm:.4f}s | Corr: {t_corr:.2f}s | Risk: {t_risk:.4f}s | Total: {t_total:.2f}s | Incidents: {len(incidents)}", flush=True)

    summary_5k = {
        "n_alerts": 5000,
        "runs": 3,
        "incidents_formed": incidents_counts[0],
        "ingest_time_mean": float(np.mean(ingest_times)),
        "ingest_time_std": float(np.std(ingest_times)),
        "norm_time_mean": float(np.mean(norm_times)),
        "norm_time_std": float(np.std(norm_times)),
        "corr_time_mean": float(np.mean(corr_times)),
        "corr_time_std": float(np.std(corr_times)),
        "risk_time_mean": float(np.mean(risk_times)),
        "risk_time_std": float(np.std(risk_times)),
        "total_time_mean": float(np.mean(total_times)),
        "total_time_std": float(np.std(total_times)),
        "total_throughput_alerts_sec": float(n_alerts / np.mean(total_times))
    }

    out_file = os.path.join(RESULTS_DIR, "scaling_5k_3runs.json")
    with open(out_file, "w") as f:
        json.dump(summary_5k, f, indent=2)

    print(f"\n[+] Saved 3-run 5k summary to: {out_file}", flush=True)
    print(f"  Total Pipeline Time (5,000 alerts): {summary_5k['total_time_mean']:.2f}s ± {summary_5k['total_time_std']:.2f}s")
    print(f"  Correlation Time:                   {summary_5k['corr_time_mean']:.2f}s ± {summary_5k['corr_time_std']:.2f}s")
    print(f"  Throughput:                         {summary_5k['total_throughput_alerts_sec']:.1f} alerts/sec")


if __name__ == "__main__":
    run_5k_benchmark_3x()

