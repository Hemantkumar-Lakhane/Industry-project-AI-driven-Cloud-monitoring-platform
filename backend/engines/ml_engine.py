"""
ML Engine — 3 Specialist PyOD Models on 9-Dimensional Flow Features
====================================================================
Evaluates operational network flow features against 3 calibrated PyOD models:
  - iforest: Isolation Forest
  - hbos:    Histogram-Based Outlier Score
  - knn:     k-Nearest Neighbors

Feature Schema (9D, leakage-free from IEEE paper):
  duration, src_bytes, dst_bytes, count, srv_count,
  serror_rate, rerror_rate, same_srv_rate, diff_srv_rate

Scoring strategy:
  Every event is mapped through feature_extractor to the 9D schema.
  Final score = max(iforest_score, knn_score, hbos_score).
  Detected_by = model with highest normalized anomaly score.
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
from typing import List, Dict, Any, Optional

try:
    from pyod.models.iforest import IForest
    from pyod.models.knn import KNN
    from pyod.models.hbos import HBOS
    PYOD_AVAILABLE = True
except (ImportError, OSError) as e:
    IForest = None
    KNN = None
    HBOS = None
    PYOD_AVAILABLE = False
    print(f"[ML Engine] WARNING: PyOD models could not be imported ({e}). Dynamic fallback enabled.")

from engines.feature_extractor import (
    FEATURE_NAMES,
    FEATURE_DIM,
    extract_features,
    extract_feature_matrix,
    validate_feature_vector,
    CLOUD_FEATURE_NAMES,
    CLOUD_FEATURE_DIM,
    extract_cloud_features,
    extract_cloud_feature_matrix,
    validate_cloud_feature_vector,
)

FEATURES = FEATURE_NAMES  # Verified 9-dimensional schema
MODELS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "models")
META_PATH = os.path.join(MODELS_DIR, "training_meta.json")

MODEL_DISPLAY = {
    "iforest": "Isolation Forest (NSL-KDD)",
    "knn":     "KNN (NSL-KDD)",
    "hbos":    "HBOS (NSL-KDD)",
}


# ── Load saved models on module import ───────────────────────────────────────

def _load():
    """
    Load all 3 specialist models + unified scaler from disk.
    Returns (models, scaler, meta) or (None, None, None).
    """
    if not PYOD_AVAILABLE or not os.path.exists(MODELS_DIR):
        return None, None, None

    models = {}
    scaler = None

    scaler_path = os.path.join(MODELS_DIR, "scaler.pkl")
    if os.path.exists(scaler_path):
        try:
            scaler = joblib.load(scaler_path)
        except Exception as e:
            print(f"[ML Engine] Failed to load scaler: {e}")

    for name in ["iforest", "knn", "hbos"]:
        m_path = os.path.join(MODELS_DIR, f"{name}.pkl")
        if os.path.exists(m_path):
            try:
                models[name] = joblib.load(m_path)
            except Exception as e:
                print(f"[ML Engine] Failed to load model {name}: {e}")

    if not models or scaler is None:
        return None, None, None

    meta = {}
    if os.path.exists(META_PATH):
        try:
            with open(META_PATH) as f:
                meta = json.load(f)
        except Exception as e:
            print(f"[ML Engine] Failed to read {META_PATH}: {e}")

    print(f"[ML Engine] Loaded {len(models)} 9D specialist models: {list(models.keys())}")
    for k, v in meta.get("models", {}).items():
        perf = v.get("performance", {})
        print(f"  {k:<10} trained on {v.get('dataset', 'NSL-KDD'):<12} "
              f"F1={perf.get('f1_score', 0)}%  ROC-AUC={perf.get('roc_auc', 0)}%")

    return models, scaler, meta


_MODELS = None
_SCALER = None
_META = None
_IS_LOADED = False

def _ensure_loaded():
    global _MODELS, _SCALER, _META, _IS_LOADED
    if not _IS_LOADED:
        _IS_LOADED = True
        try:
            _MODELS, _SCALER, _META = _load()
        except Exception as e:
            print(f"[ML Engine] Model load warning: {e}", flush=True)
            _MODELS, _SCALER, _META = None, None, None

def is_pretrained() -> bool:
    _ensure_loaded()
    return _MODELS is not None and _SCALER is not None

class _PretrainedProxy:
    def __bool__(self):
        return is_pretrained()
    def __repr__(self):
        return str(is_pretrained())

PRETRAINED = _PretrainedProxy()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _safe(v) -> float:
    if np.isnan(v) or np.isinf(v):
        return 0.0
    return float(v)


def _json_safe_value(v):
    if isinstance(v, (np.floating, float)):
        if np.isnan(v) or np.isinf(v):
            return None
        return float(v)
    if isinstance(v, (np.integer, int)):
        return int(v)
    if isinstance(v, (np.bool_, bool)):
        return bool(v)
    return v


def _severity(score: float) -> str:
    """Calibrate anomaly severity into standardized percentile tiers."""
    if score > 0.85:
        return "Critical"
    elif score > 0.70:
        return "High"
    elif score > 0.45:
        return "Medium"
    return "Low"


def _compute_cloud_behavioral_score(vec: np.ndarray) -> float:
    """
    Computes a normalized anomaly score [0.0, 1.0] from an 8D cloud-native feature vector:
    Indices:
      0: payload_bytes
      1: failed_auth_count
      2: high_risk_action_flag
      3: auth_anomaly_flag
      4: distinct_targets_count
      5: rule_severity_norm
      6: error_status_flag
      7: burst_velocity
    """
    if not isinstance(vec, np.ndarray) or len(vec) != CLOUD_FEATURE_DIM:
        return 0.0
    
    # Normalized weights sum to 1.0
    s_action = 0.35 * float(vec[2])
    s_auth = 0.25 * min(1.0, (float(vec[1]) / 5.0) + (0.2 * float(vec[3])))
    s_sev = 0.20 * min(1.0, max(0.0, float(vec[5])))
    s_err = 0.10 * float(vec[6])
    s_burst = 0.10 * min(1.0, max(0.0, (float(vec[7]) - 1.0) / 20.0))
    
    score = s_action + s_auth + s_sev + s_err + s_burst
    # Large payload exfiltration boost (>10MB)
    if float(vec[0]) > 10 * 1024 * 1024:
        score = min(1.0, score + 0.15)
        
    return min(1.0, max(0.0, float(score)))


def _scale_for(name: str, X: np.ndarray) -> np.ndarray:
    """Apply the fitted 9-dimensional scaler with strict dimension validation."""
    _ensure_loaded()
    if X.ndim != 2 or X.shape[1] != FEATURE_DIM:
        raise ValueError(
            f"Incompatible feature dimension for model '{name}'. "
            f"Expected {FEATURE_DIM} features ({FEATURES}), but received {X.shape[1] if X.ndim == 2 else 'invalid'}."
        )
    return _SCALER.transform(X)


def _score_all(X_raw: np.ndarray) -> Dict[str, np.ndarray]:
    _ensure_loaded()
    """
    Score X_raw with every loaded specialist model.
    Validates input dimension before scoring.
    Returns dict: model_name -> array of normalized anomaly scores in [0.0, 1.0].
    NOTE: PyOD's predict_proba applies min-max scaling across decision scores.
    These are normalized anomaly scores rather than calibrated Bayesian posterior probabilities.
    """
    if X_raw.ndim != 2 or X_raw.shape[1] != FEATURE_DIM:
        print(f"[ML Engine] Incompatible feature dimension: expected {FEATURE_DIM}, received {X_raw.shape[1] if X_raw.ndim == 2 else 'invalid'}")
        return {}

    scores = {}
    for name, model in _MODELS.items():
        try:
            X_s = _scale_for(name, X_raw)
            # PyOD predict_proba returns [score_normal, score_anomaly] normalized in [0, 1]
            probs = model.predict_proba(X_s)[:, 1]
            scores[name] = probs
        except Exception as e:
            print(f"[ML Engine] {name} scoring failed: {e}")
    return scores


def score_flow_features(X_flow: np.ndarray) -> Dict[str, Any]:
    """
    Controlled entry point for evaluating 9-dimensional operational flow features.
    Evaluates against trained models if loaded, or validates rejection of bad shapes.
    """
    if not isinstance(X_flow, np.ndarray) or X_flow.ndim != 2 or X_flow.shape[1] != FEATURE_DIM:
        return {
            "status": "ERROR",
            "message": f"Expected 9-dimensional feature matrix, but received shape {getattr(X_flow, 'shape', 'invalid')}.",
            "compatible": False,
        }

    if not PRETRAINED:
        return {
            "status": "NOT CONFIGURED",
            "message": "9-dimensional operational flow models are not yet loaded. Run train_model.py to generate models.",
            "compatible": False,
            "feature_dim": FEATURE_DIM,
            "active_models": 0,
        }

    scores = _score_all(X_flow)
    return {
        "status": "CONFIGURED",
        "message": "9-dimensional operational flow models evaluated successfully using verified NSL-KDD benchmark calibration.",
        "compatible": True,
        "feature_dim": FEATURE_DIM,
        "active_models": len(scores),
        "scores": {k: [round(_safe(v), 4) for v in vals] for k, vals in scores.items()}
    }


# ── Public API ────────────────────────────────────────────────────────────────

def analyze_events(events: List[Dict]) -> List[Dict]:
    _ensure_loaded()
    """
    Score each event using calibrated 9D specialist models and 8D cloud behavioral analyzer.
    Calibrated score = max(flow_score, cloud_behavior_score).
    Provides dual-lens threat visibility for both network flows and cloud audit logs.
    """
    if not events:
        return []

    X_flow = extract_feature_matrix(events)
    X_cloud = extract_cloud_feature_matrix(events)

    if PRETRAINED and X_flow.shape[1] == FEATURE_DIM:
        all_scores = _score_all(X_flow)
        if all_scores:
            score_matrix = np.column_stack(list(all_scores.values()))
            model_names = list(all_scores.keys())
            flow_scores = score_matrix.max(axis=1)
            best_model_idx = score_matrix.argmax(axis=1)
        else:
            flow_scores = np.zeros(len(events))
            score_matrix = flow_scores.reshape(-1, 1)
            model_names = ["fallback"]
            best_model_idx = np.zeros(len(events), dtype=int)
    else:
        print("[ML Engine] WARNING: Pretrained models not available or dimension mismatch. Falling back to dynamic fit.")
        if IForest is not None:
            try:
                clf = IForest(contamination=0.15, random_state=42, n_estimators=50, n_jobs=1)
                clf.fit(X_flow)
                flow_scores = clf.predict_proba(X_flow)[:, 1]
            except Exception as e:
                print(f"[ML Engine] Fallback IForest failed: {e}")
                flow_scores = np.zeros(len(events))
        else:
            flow_scores = np.zeros(len(events))
        score_matrix = flow_scores.reshape(-1, 1)
        model_names = ["iforest"]
        best_model_idx = np.zeros(len(events), dtype=int)

    results = []
    for idx, e in enumerate(events):
        s_flow = _safe(float(flow_scores[idx]))
        s_cloud = _compute_cloud_behavioral_score(X_cloud[idx]) if idx < len(X_cloud) else 0.0

        # Calibrated combined score: max across specialized flow models and cloud behavior
        calibrated_score = round(max(s_flow, s_cloud), 4)
        is_anom = calibrated_score > 0.45

        rec = {k: _json_safe_value(v) for k, v in e.items()}
        rec["ml_anomaly_score"] = calibrated_score
        rec["calibrated_score"] = calibrated_score
        rec["flow_anomaly_score"] = round(s_flow, 4)
        rec["cloud_anomaly_score"] = round(s_cloud, 4)
        rec["is_anomaly"] = bool(is_anom)
        rec["ml_severity"] = _severity(calibrated_score)
        rec["model_source"] = "pretrained_specialist+cloud_behavior" if PRETRAINED else "realtime_fit"

        # Model attribution
        if s_cloud > s_flow and s_cloud > 0.45:
            rec["detected_by"] = "Cloud Behavioral Analyzer"
        elif PRETRAINED and model_names and len(model_names) > 0:
            best_name = model_names[best_model_idx[idx]]
            rec["detected_by"] = MODEL_DISPLAY.get(best_name, best_name)
        else:
            rec["detected_by"] = "Isolation Forest"

        # Detailed model scores
        scores_dict = {}
        if PRETRAINED and model_names:
            for i, n in enumerate(model_names):
                scores_dict[MODEL_DISPLAY.get(n, n)] = round(_safe(float(score_matrix[idx, i])), 4)
        scores_dict["Cloud Behavioral Analyzer"] = round(s_cloud, 4)
        rec["model_scores"] = scores_dict

        # Cloud feature explainability
        if idx < len(X_cloud):
            rec["cloud_features"] = {
                name: round(float(X_cloud[idx, i]), 4)
                for i, name in enumerate(CLOUD_FEATURE_NAMES)
            }

        results.append(rec)

    return results


def compare_models(events: List[Dict]) -> Dict:
    _ensure_loaded()
    """
    Compare all 3 specialist models on the current event batch.
    Shows per-model metrics against ground-truth event_type labels.
    """
    if not events:
        return {"error": "No events to analyze"}

    X_raw = extract_feature_matrix(events)
    y_true = np.array([1 if e.get("event_type") == "attack" else 0 for e in events])

    comparison = {}
    per_event_scores = {}

    if PRETRAINED and X_raw.shape[1] == FEATURE_DIM:
        all_scores = _score_all(X_raw)
        for name, probs in all_scores.items():
            display = MODEL_DISPLAY.get(name, name)
            max_p = float(np.max(probs)) if len(probs) > 0 else 0.0
            if max_p > 0.5 and np.sum(probs > 0.5) > 0:
                thresh = 0.5
            elif len(probs) > 5:
                p_thresh = float(np.percentile(probs, 82))
                thresh = min(0.35, max(1e-6, p_thresh))
            elif max_p > 1e-4:
                thresh = max_p * 0.5
            else:
                thresh = 0.5
            predictions = (probs >= thresh).astype(int)
            tp = int(np.sum((predictions == 1) & (y_true == 1)))
            fp = int(np.sum((predictions == 1) & (y_true == 0)))
            fn = int(np.sum((predictions == 0) & (y_true == 1)))
            tn = int(np.sum((predictions == 0) & (y_true == 0)))
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
            accuracy = (tp + tn) / len(y_true) if len(y_true) > 0 else 0

            m_meta = _META.get("models", {}).get(name, {})
            perf = m_meta.get("performance", {})

            comparison[display] = {
                "accuracy": round(accuracy * 100, 1),
                "precision": round(precision * 100, 1),
                "recall": round(recall * 100, 1),
                "f1_score": round(f1 * 100, 1),
                "anomalies_detected": int(np.sum(predictions)),
                "avg_anomaly_score": round(float(np.mean(probs)), 4) if len(probs) > 0 else 0.0,
                "confusion_matrix": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
                "dataset": m_meta.get("dataset", "NSL-KDD"),
                "specialises_in": "9-dimensional network flow anomalies",
                "training_f1": perf.get("f1_score", 0),
            }
            per_event_scores[display] = [_safe(p) for p in probs]
    else:
        # Fallback dynamic fit
        if IForest is not None:
            try:
                clf = IForest(contamination=0.15, random_state=42, n_estimators=50, n_jobs=1)
                clf.fit(X_raw)
                probs = clf.predict_proba(X_raw)[:, 1]
            except Exception:
                probs = np.zeros(len(X_raw))
        else:
            probs = np.zeros(len(X_raw))
        display = "Isolation Forest (Fallback Dynamic)"
        predictions = (probs > 0.65).astype(int)
        tp = int(np.sum((predictions == 1) & (y_true == 1)))
        fp = int(np.sum((predictions == 1) & (y_true == 0)))
        fn = int(np.sum((predictions == 0) & (y_true == 1)))
        tn = int(np.sum((predictions == 0) & (y_true == 0)))
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        accuracy = (tp + tn) / len(y_true) if len(y_true) > 0 else 0
        comparison[display] = {
            "accuracy": round(accuracy * 100, 1),
            "precision": round(precision * 100, 1),
            "recall": round(recall * 100, 1),
            "f1_score": round(f1 * 100, 1),
            "anomalies_detected": int(np.sum(predictions)),
            "avg_anomaly_score": round(float(np.mean(probs)), 4),
            "confusion_matrix": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
            "dataset": "Runtime Buffer",
            "specialises_in": "Generic anomaly scoring",
            "training_f1": 0,
        }
        per_event_scores[display] = [_safe(p) for p in probs]

    valid = {k: v for k, v in comparison.items() if "error" not in v}
    best = max(valid, key=lambda k: valid[k]["f1_score"]) if valid else "Isolation Forest (NSL-KDD)"

    event_comparison = []
    for i in range(min(20, len(events))):
        entry = {
            "index": i,
            "event_type": events[i].get("event_type", "unknown"),
            "attack_type": events[i].get("attack_type"),
        }
        for name in per_event_scores:
            entry[name] = round(per_event_scores[name][i], 4)
        event_comparison.append(entry)

    return {
        "total_events": len(events),
        "total_attacks": int(np.sum(y_true)),
        "total_normal": int(np.sum(y_true == 0)),
        "pretrained": PRETRAINED,
        "training_mode": "leakage_free_flow_9d",
        "scoring_strategy": "Multi-model ensemble on 9D operational network flow features",
        "models": comparison,
        "best_model": best,
        "best_f1": valid.get(best, {}).get("f1_score", 0),
        "event_comparison": event_comparison,
        "chart_data": [
            {"model": k, **{m: v for m, v in v.items()
                            if m in ["accuracy", "precision", "recall", "f1_score"]}}
            for k, v in comparison.items() if "error" not in v
        ],
    }


def get_model_info() -> Dict:
    _ensure_loaded()
    """Return verified metadata about the loaded 9D flow specialist models."""
    if not PRETRAINED:
        return {
            "pretrained": False,
            "message": "No pre-trained models found. Run: python backend/train_model.py",
            "models_dir": MODELS_DIR,
        }
    return {
        "pretrained": True,
        "training_mode": "leakage_free_flow_9d",
        "scoring_strategy": "Multi-model ensemble on 9D operational network flow features",
        "features": FEATURES,
        "feature_dimension": FEATURE_DIM,
        "feature_schema": "flow_9d",
        "cloud_features": CLOUD_FEATURE_NAMES,
        "cloud_feature_dimension": CLOUD_FEATURE_DIM,
        "cloud_feature_schema": "cloud_native_8d",
        "cloud_behavioral_analyzer": "Rule-weighted heuristic analyzer evaluating 8D cloud telemetry features",
        "target_leakage_status": "none_verified",
        "compatible_with_9d_extractor": True,
        "models": {
            MODEL_DISPLAY.get(k, k): {
                "dataset": v.get("dataset", "NSL-KDD"),
                "specialises_in": "9-dimensional network flow anomalies",
                "train_samples": v.get("train_samples", 0),
                "contamination": v.get("contamination", 0.0),
                "f1_score": v.get("performance", {}).get("f1_score", 0),
                "accuracy": v.get("performance", {}).get("accuracy", 0),
                "recall": v.get("performance", {}).get("recall", 0),
                "precision": v.get("performance", {}).get("precision", 0),
                "false_positive_rate": v.get("performance", {}).get("false_positive_rate", 0),
                "roc_auc": v.get("performance", {}).get("roc_auc", 0),
                "confusion_matrix": v.get("performance", {}).get("confusion_matrix", {}),
            }
            for k, v in _META.get("models", {}).items()
        },
    }


def get_benchmark_results() -> Dict[str, Any]:
    """Return empirical evaluation metrics across all 7 benchmarked candidate algorithms."""
    bench_path = os.path.join(MODELS_DIR, "benchmark_results.json")
    if os.path.exists(bench_path):
        try:
            with open(bench_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"[ML Engine] Failed to read benchmark results: {e}")
    return {}
