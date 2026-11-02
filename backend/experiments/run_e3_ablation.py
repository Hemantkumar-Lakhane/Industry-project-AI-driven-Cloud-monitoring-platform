"""
Experiment E3: Detection Ablation Benchmark (Rule-Only vs Model-Only vs Fusion)
=============================================================================
Evaluates detection performance on scripted attack scenarios and benign baselines
with strictly pre-defined ground truth labels.

Configurations:
1. Rule-Only: 16 signature-based MITRE ATT&CK detectors (detector_registry.run_all)
2. Model-Only: 9D PyOD ML specialist models + 8D Cloud Behavioral Analyzer (ml_engine.analyze_events)
3. Fusion: Dual-lens logical OR union (Rule Detection OR ML Anomaly Flag)

Metrics:
- TP, FP, TN, FN, Precision, Recall, F1 Score, Accuracy
- Time to First Alert (T_first, ms)
"""
import os
import sys
import time
import json
import uuid
import numpy as np
import pandas as pd
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Tuple

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

RESULTS_DIR = os.path.join(ROOT_DIR, "experiments", "results")

# Import all detectors to ensure automatic registration with detector_registry
from engines.base_detector import detector_registry
import engines.detectors
from engines.ml_engine import analyze_events

def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_e3_dataset() -> Tuple[List[Dict[str, Any]], List[int], List[str]]:
    """
    Generates a controlled, reproducible dataset of 200 events with known ground truth:
    - 100 Malicious events (Y = 1) across 8 distinct attack categories
    - 100 Benign events (Y = 0) representing typical cloud workflows
    """
    base_time = datetime(2026, 11, 2, 12, 0, 0, tzinfo=timezone.utc)
    events: List[Dict[str, Any]] = []
    ground_truth: List[int] = []
    scenario_names: List[str] = []

    def add_evt(evt: Dict[str, Any], is_malicious: bool, scenario: str):
        events.append(evt)
        ground_truth.append(1 if is_malicious else 0)
        scenario_names.append(scenario)

    curr_time = base_time

    # ──────────────────────────────────────────────────────────────────────────
    # PART 1: MALICIOUS SCENARIOS (100 Attack Events, Y = 1)
    # ──────────────────────────────────────────────────────────────────────────

    # Scenario 1: Brute Force & Credential Guessing (20 events)
    bf_ip = "198.51.100.42"
    for i in range(19):
        curr_time += timedelta(seconds=2)
        add_evt({
            "id": f"EVT-BF-FAIL-{i:03d}",
            "timestamp": _iso(curr_time),
            "source": "wazuh",
            "rule_id": 5710,
            "level": 10,
            "severity": "high",
            "event_type": "attack",
            "attack_type": "brute_force",
            "user": "admin",
            "src_ip": bf_ip,
            "dst_ip": "10.0.0.5",
            "service": "iam",
            "action": "ConsoleLogin",
            "status": "failure",
            "bytes_transferred": 0,
            "failed_attempts": i + 1,
            "description": f"Failed password attempt #{i+1} for admin from {bf_ip}"
        }, True, "brute_force")

    # Successful breach after burst
    curr_time += timedelta(seconds=1)
    add_evt({
        "id": "EVT-BF-SUCCESS-020",
        "timestamp": _iso(curr_time),
        "source": "wazuh",
        "rule_id": 5715,
        "level": 14,
        "severity": "critical",
        "event_type": "attack",
        "attack_type": "brute_force",
        "user": "admin",
        "src_ip": bf_ip,
        "dst_ip": "10.0.0.5",
        "service": "iam",
        "action": "ConsoleLogin",
        "status": "success",
        "bytes_transferred": 0,
        "failed_attempts": 20,
        "description": f"Successful login after 19 failed attempts from {bf_ip}"
    }, True, "brute_force")

    # Scenario 2: IAM Privilege Escalation (15 events)
    pe_user = "compromised-dev"
    pe_actions = [
        ("CreatePolicy", "AdministratorAccessPolicy", 5402),
        ("AttachUserPolicy", "AdministratorAccess", 5403),
        ("CreateAccessKey", "AKIAIOSFODNN7EXAMPLE", 5405),
        ("PutUserPolicy", "InlineAdminEscalation", 5402),
        ("UpdateAssumeRolePolicy", "sts:AssumeRole", 5404),
    ]
    for i in range(15):
        curr_time += timedelta(seconds=5)
        act, desc, r_id = pe_actions[i % len(pe_actions)]
        add_evt({
            "id": f"EVT-PE-{i:03d}",
            "timestamp": _iso(curr_time),
            "source": "cloudtrail",
            "rule_id": r_id,
            "level": 12,
            "severity": "critical",
            "event_type": "attack",
            "attack_type": "privilege_escalation",
            "user": pe_user,
            "src_ip": "10.0.1.55",
            "dst_ip": "10.0.0.1",
            "service": "iam",
            "action": act,
            "status": "success",
            "bytes_transferred": 0,
            "failed_attempts": 0,
            "description": f"{pe_user} executed unauthorized IAM escalation: {desc}"
        }, True, "privilege_escalation")

    # Scenario 3: Data Exfiltration (15 events)
    exfil_ip = "203.0.113.88"
    for i in range(15):
        curr_time += timedelta(seconds=10)
        chunk_bytes = int(150 * 1024 * 1024 + i * 20 * 1024 * 1024)  # 150MB to 430MB per chunk
        add_evt({
            "id": f"EVT-DE-{i:03d}",
            "timestamp": _iso(curr_time),
            "source": "cloudtrail",
            "rule_id": 80105,
            "level": 14,
            "severity": "critical",
            "event_type": "attack",
            "attack_type": "data_exfiltration",
            "user": "compromised-service-role",
            "src_ip": "10.0.2.10",
            "dst_ip": exfil_ip,
            "service": "s3",
            "action": "GetObject",
            "status": "success",
            "bytes_transferred": chunk_bytes,
            "failed_attempts": 0,
            "description": f"Bulk data transfer of {chunk_bytes//(1024*1024)}MB to external IP {exfil_ip}"
        }, True, "data_exfiltration")

    # Scenario 4: Reconnaissance & Network Port Scanning (15 events)
    scan_ip = "192.0.2.77"
    for i in range(15):
        curr_time += timedelta(seconds=1)
        port = 20 + i * 15
        add_evt({
            "id": f"EVT-SCAN-{i:03d}",
            "timestamp": _iso(curr_time),
            "source": "wazuh",
            "rule_id": 5712,
            "level": 8,
            "severity": "medium",
            "event_type": "attack",
            "attack_type": "network_scanning",
            "user": "unauthenticated",
            "src_ip": scan_ip,
            "dst_ip": "10.0.0.10",
            "service": "network",
            "action": "PortScan",
            "status": "denied",
            "bytes_transferred": 64,
            "failed_attempts": 0,
            "description": f"SYN probe targeting port {port} from scanning host {scan_ip}"
        }, True, "network_scanning")

    # Scenario 5: Defense & Audit Logging Tampering (10 events)
    dt_actions = ["StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors", "DeleteFlowLogs"]
    for i in range(10):
        curr_time += timedelta(seconds=8)
        act = dt_actions[i % len(dt_actions)]
        add_evt({
            "id": f"EVT-DT-{i:03d}",
            "timestamp": _iso(curr_time),
            "source": "cloudtrail",
            "rule_id": 80301,
            "level": 14,
            "severity": "critical",
            "event_type": "attack",
            "attack_type": "defense_tampering",
            "user": "rogue-admin",
            "src_ip": "198.51.100.99",
            "dst_ip": "10.0.0.1",
            "service": "cloudtrail",
            "action": act,
            "status": "success",
            "bytes_transferred": 0,
            "failed_attempts": 0,
            "description": f"Adversary executed audit tampering: {act}"
        }, True, "defense_tampering")

    # Scenario 6: Cryptomining & Host Resource Hijacking (10 events)
    for i in range(10):
        curr_time += timedelta(seconds=15)
        add_evt({
            "id": f"EVT-CM-{i:03d}",
            "timestamp": _iso(curr_time),
            "source": "wazuh",
            "rule_id": 80201,
            "level": 13,
            "severity": "critical",
            "event_type": "attack",
            "attack_type": "cryptomining",
            "user": "ec2-user",
            "src_ip": "10.0.5.21",
            "dst_ip": "185.220.101.5",
            "service": "compute",
            "action": "StratumMiningTraffic",
            "status": "success",
            "bytes_transferred": 8192,
            "failed_attempts": 0,
            "description": f"Outbound mining protocol traffic on port 3333 to mining pool"
        }, True, "cryptomining")

    # Scenario 7: DDoS & Connection Burst (10 events)
    for i in range(10):
        curr_time += timedelta(seconds=1)
        add_evt({
            "id": f"EVT-DDOS-{i:03d}",
            "timestamp": _iso(curr_time),
            "source": "wazuh",
            "rule_id": 80001,
            "level": 11,
            "severity": "high",
            "event_type": "attack",
            "attack_type": "ddos",
            "user": "anonymous",
            "src_ip": f"198.51.100.{100+i}",
            "dst_ip": "10.0.0.5",
            "service": "network",
            "action": "SYNFlood",
            "status": "denied",
            "bytes_transferred": 40960,
            "failed_attempts": 0,
            "description": f"High volume ingress SYN flood connection burst"
        }, True, "ddos")

    # Scenario 8: Account Takeover & Session Hijacking (5 events)
    for i in range(5):
        curr_time += timedelta(seconds=12)
        add_evt({
            "id": f"EVT-ATO-{i:03d}",
            "timestamp": _iso(curr_time),
            "source": "cloudtrail",
            "rule_id": 5716,
            "level": 13,
            "severity": "critical",
            "event_type": "attack",
            "attack_type": "account_takeover",
            "user": "executive-user",
            "src_ip": "45.33.32.156",
            "dst_ip": "10.0.0.1",
            "service": "iam",
            "action": "DeactivateMFADevice",
            "status": "success",
            "bytes_transferred": 0,
            "failed_attempts": 0,
            "description": f"Anomalous MFA deactivation from foreign geo-location IP"
        }, True, "account_takeover")

    # ──────────────────────────────────────────────────────────────────────────
    # PART 2: BENIGN SCENARIOS (100 Normal Baseline Events, Y = 0)
    # ──────────────────────────────────────────────────────────────────────────

    # Benign 1: Routine Developer S3 Operations (30 events)
    for i in range(30):
        curr_time += timedelta(seconds=20)
        file_bytes = int(45 * 1024 + (i * 12 * 1024))  # 45KB to 390KB
        add_evt({
            "id": f"EVT-NORM-S3-{i:03d}",
            "timestamp": _iso(curr_time),
            "source": "cloudtrail",
            "rule_id": 10001,
            "level": 3,
            "severity": "low",
            "event_type": "normal",
            "attack_type": "benign",
            "user": "alice-developer",
            "src_ip": "10.0.10.5",
            "dst_ip": "10.0.0.1",
            "service": "s3",
            "action": "GetObject" if i % 2 == 0 else "PutObject",
            "status": "success",
            "bytes_transferred": file_bytes,
            "failed_attempts": 0,
            "description": f"Standard CI/CD artifact read/write on internal build bucket"
        }, False, "benign_s3")

    # Benign 2: Routine Infrastructure & IAM Read Queries (25 events)
    iam_reads = ["GetUser", "GetRole", "ListBuckets", "DescribeInstances", "DescribeSecurityGroups"]
    for i in range(25):
        curr_time += timedelta(seconds=15)
        act = iam_reads[i % len(iam_reads)]
        add_evt({
            "id": f"EVT-NORM-IAM-{i:03d}",
            "timestamp": _iso(curr_time),
            "source": "cloudtrail",
            "rule_id": 10002,
            "level": 2,
            "severity": "low",
            "event_type": "normal",
            "attack_type": "benign",
            "user": "terraform-automation-role",
            "src_ip": "10.0.10.2",
            "dst_ip": "10.0.0.1",
            "service": "iam" if "User" in act or "Role" in act else "ec2",
            "action": act,
            "status": "success",
            "bytes_transferred": 1024,
            "failed_attempts": 0,
            "description": f"Automated infrastructure state sync read query: {act}"
        }, False, "benign_iam_read")

    # Benign 3: Standard Web Application Ingress Traffic (25 events)
    for i in range(25):
        curr_time += timedelta(seconds=5)
        add_evt({
            "id": f"EVT-NORM-WEB-{i:03d}",
            "timestamp": _iso(curr_time),
            "source": "wazuh",
            "rule_id": 10003,
            "level": 2,
            "severity": "low",
            "event_type": "normal",
            "attack_type": "benign",
            "user": "customer-session",
            "src_ip": f"198.51.100.{200 + (i % 20)}",
            "dst_ip": "10.0.0.100",
            "service": "httpd",
            "action": "HTTP_GET",
            "status": "success",
            "bytes_transferred": 2048 + (i * 256),
            "failed_attempts": 0,
            "description": f"Valid HTTP 200 GET request to public product catalog"
        }, False, "benign_web_traffic")

    # Benign 4: Internal System Health Checks & Telemetry (20 events)
    for i in range(20):
        curr_time += timedelta(seconds=30)
        add_evt({
            "id": f"EVT-NORM-SYS-{i:03d}",
            "timestamp": _iso(curr_time),
            "source": "wazuh",
            "rule_id": 10004,
            "level": 1,
            "severity": "low",
            "event_type": "normal",
            "attack_type": "benign",
            "user": "health-check-agent",
            "src_ip": "10.0.0.2",
            "dst_ip": "10.0.0.5",
            "service": "monitoring",
            "action": "HealthCheckProbe",
            "status": "success",
            "bytes_transferred": 128,
            "failed_attempts": 0,
            "description": f"Periodic synthetic availability ping (TCP/443 OK)"
        }, False, "benign_health_check")

    return events, ground_truth, scenario_names


def run_e3_ablation():
    print("=" * 80, flush=True)
    print("EXPERIMENT E3: ABLATION BENCHMARK (RULE-ONLY vs MODEL-ONLY vs FUSION)", flush=True)
    print("=" * 80, flush=True)

    events, y_true, scenarios = generate_e3_dataset()
    y_true = np.array(y_true)
    n_total = len(events)
    n_pos = int(np.sum(y_true == 1))
    n_neg = int(np.sum(y_true == 0))

    print(f"Total Evaluated Events: {n_total}")
    print(f"  Malicious Events (Ground Truth = 1): {n_pos} (across 8 attack scenarios)")
    print(f"  Benign Events    (Ground Truth = 0): {n_neg} (across 4 routine workflows)\n")

    # ──────────────────────────────────────────────────────────────────────────
    # CONFIGURATION 1: RULE-ONLY (16 Signature & Correlation Detectors)
    # ──────────────────────────────────────────────────────────────────────────
    print("[*] Running Configuration 1: Rule-Only (16 Detectors)...", flush=True)
    t0_rule = time.perf_counter()
    findings = detector_registry.run_all(events)
    rule_exec_time = time.perf_counter() - t0_rule

    # Extract all event IDs flagged by rules
    rule_flagged_ids = set()
    for f in findings:
        ev = f.evidence
        if isinstance(ev, dict):
            trig_ids = ev.get("triggering_event_ids") or []
        else:
            trig_ids = getattr(ev, "triggering_event_ids", []) or []
        for tid in trig_ids:
            rule_flagged_ids.add(str(tid))

    y_pred_rule = np.array([1 if e["id"] in rule_flagged_ids else 0 for e in events])

    # First detected attack event index
    first_detected_idx_rule = next((idx for idx, (yt, yp) in enumerate(zip(y_true, y_pred_rule)) if yt == 1 and yp == 1), None)
    
    # Strictly measured processing latency to first alert (ms) using time.perf_counter
    if first_detected_idx_rule is not None:
        t0_sub = time.perf_counter()
        _ = detector_registry.run_all(events[:first_detected_idx_rule + 1])
        t_first_rule_ms = (time.perf_counter() - t0_sub) * 1000.0
        
        # Scenario simulation time delta from first attack event (seconds)
        first_attack_ts = datetime.fromisoformat(events[0]["timestamp"].replace("Z", "+00:00"))
        first_alert_ts = datetime.fromisoformat(events[first_detected_idx_rule]["timestamp"].replace("Z", "+00:00"))
        sim_delta_rule_sec = (first_alert_ts - first_attack_ts).total_seconds()
    else:
        t_first_rule_ms = float("inf")
        sim_delta_rule_sec = float("inf")

    # ──────────────────────────────────────────────────────────────────────────
    # CONFIGURATION 2: MODEL-ONLY (9D Flow + 8D Cloud Behavioral Analyzer)
    # ──────────────────────────────────────────────────────────────────────────
    print("[*] Running Configuration 2: Model-Only (ML Operational Engines)...", flush=True)
    t0_ml = time.perf_counter()
    analyzed_events = analyze_events(events)
    ml_exec_time = time.perf_counter() - t0_ml

    # Event is flagged if is_anomaly is True or ml_anomaly_score >= 0.50
    y_pred_ml = np.array([
        1 if (ae.get("is_anomaly") or ae.get("ml_anomaly_score", 0.0) >= 0.50) else 0
        for ae in analyzed_events
    ])

    first_detected_idx_ml = next((idx for idx, (yt, yp) in enumerate(zip(y_true, y_pred_ml)) if yt == 1 and yp == 1), None)
    
    # Strictly measured processing latency to first alert (ms) using time.perf_counter
    if first_detected_idx_ml is not None:
        t0_sub = time.perf_counter()
        _ = analyze_events(events[:first_detected_idx_ml + 1])
        t_first_ml_ms = (time.perf_counter() - t0_sub) * 1000.0
        
        first_attack_ts = datetime.fromisoformat(events[0]["timestamp"].replace("Z", "+00:00"))
        first_alert_ts = datetime.fromisoformat(events[first_detected_idx_ml]["timestamp"].replace("Z", "+00:00"))
        sim_delta_ml_sec = (first_alert_ts - first_attack_ts).total_seconds()
    else:
        t_first_ml_ms = float("inf")
        sim_delta_ml_sec = float("inf")

    # ──────────────────────────────────────────────────────────────────────────
    # CONFIGURATION 3: FUSION (Dual-Lens Logical OR Union)
    # ──────────────────────────────────────────────────────────────────────────
    print("[*] Running Configuration 3: Fusion (Rule-Only OR Model-Only)...", flush=True)
    t0_fus = time.perf_counter()
    y_pred_fusion = np.bitwise_or(y_pred_rule, y_pred_ml)
    fus_exec_time = rule_exec_time + ml_exec_time

    first_detected_idx_fus = next((idx for idx, (yt, yp) in enumerate(zip(y_true, y_pred_fusion)) if yt == 1 and yp == 1), None)
    
    # Strictly measured processing latency to first alert (ms) using time.perf_counter
    if first_detected_idx_fus is not None:
        t0_sub = time.perf_counter()
        _ = detector_registry.run_all(events[:first_detected_idx_fus + 1])
        _ = analyze_events(events[:first_detected_idx_fus + 1])
        t_first_fus_ms = (time.perf_counter() - t0_sub) * 1000.0
        
        first_attack_ts = datetime.fromisoformat(events[0]["timestamp"].replace("Z", "+00:00"))
        first_alert_ts = datetime.fromisoformat(events[first_detected_idx_fus]["timestamp"].replace("Z", "+00:00"))
        sim_delta_fus_sec = (first_alert_ts - first_attack_ts).total_seconds()
    else:
        t_first_fus_ms = float("inf")
        sim_delta_fus_sec = float("inf")

    # ──────────────────────────────────────────────────────────────────────────
    # COMPUTE METRICS
    # ──────────────────────────────────────────────────────────────────────────
    configs = [
        ("Rule-Only", y_pred_rule, rule_exec_time, t_first_rule_ms, sim_delta_rule_sec, first_detected_idx_rule),
        ("Model-Only", y_pred_ml, ml_exec_time, t_first_ml_ms, sim_delta_ml_sec, first_detected_idx_ml),
        ("Fusion (Rules + ML)", y_pred_fusion, fus_exec_time, t_first_fus_ms, sim_delta_fus_sec, first_detected_idx_fus),
    ]

    summary_rows = []

    for name, yp, ex_t, t_first, sim_sec, det_idx in configs:
        tp = int(np.sum((y_true == 1) & (yp == 1)))
        fp = int(np.sum((y_true == 0) & (yp == 1)))
        fn = int(np.sum((y_true == 1) & (yp == 0)))
        tn = int(np.sum((y_true == 0) & (yp == 0)))

        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
        acc = (tp + tn) / n_total

        summary_rows.append({
            "configuration": name,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "accuracy": round(acc, 4),
            "execution_time_sec": round(ex_t, 4),
            "measured_latency_to_first_alert_ms": round(t_first, 2),
            "simulation_delay_to_first_alert_sec": round(sim_sec, 2),
            "first_alert_event_index": int(det_idx + 1) if det_idx is not None else -1
        })

    df_summary = pd.DataFrame(summary_rows)
    out_csv = os.path.join(RESULTS_DIR, "e3_ablation_summary.csv")
    out_json = os.path.join(RESULTS_DIR, "e3_ablation_summary.json")
    df_summary.to_csv(out_csv, index=False)
    with open(out_json, "w") as f:
        json.dump(summary_rows, f, indent=2)

    print("\n" + "=" * 80)
    print("EXPERIMENT E3 SUMMARY TABLE")
    print("=" * 80)
    print(df_summary[["configuration", "tp", "fp", "fn", "tn", "precision", "recall", "f1_score", "measured_latency_to_first_alert_ms", "simulation_delay_to_first_alert_sec"]].to_string(index=False))

    # Scenario-by-Scenario Breakdown
    scen_rows = []
    unique_scens = sorted(list(set(scenarios)))
    for sc in unique_scens:
        sc_mask = np.array([s == sc for s in scenarios])
        sc_yt = y_true[sc_mask]
        sc_rule = y_pred_rule[sc_mask]
        sc_ml = y_pred_ml[sc_mask]
        sc_fus = y_pred_fusion[sc_mask]

        is_attack = (sc_yt[0] == 1)
        scen_rows.append({
            "scenario": sc,
            "type": "Attack" if is_attack else "Benign",
            "total_events": int(np.sum(sc_mask)),
            "rule_detections": int(np.sum(sc_rule)),
            "model_detections": int(np.sum(sc_ml)),
            "fusion_detections": int(np.sum(sc_fus)),
        })

    df_scen = pd.DataFrame(scen_rows)
    scen_csv = os.path.join(RESULTS_DIR, "e3_scenarios_breakdown.csv")
    df_scen.to_csv(scen_csv, index=False)
    print(f"\n[+] Saved detailed breakdown to:\n  - {out_csv}\n  - {scen_csv}\n")
    print(df_scen.to_string(index=False))


if __name__ == "__main__":
    run_e3_ablation()

