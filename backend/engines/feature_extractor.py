"""
Operational Flow Feature Extractor for RAM Antivirus
=====================================================
Extracts a verified 9-dimensional flow feature schema strictly from operational
network headers and connection counters, completely eliminating the legacy
target leakage (where post-classification labels were mapped to an ordinal 'level' feature).

Specification Reference:
- IEEE Conference Paper: Section VI, Table II, Equation 8
- Approved Production Roadmap: Workstream B, Phase 4
"""
import numpy as np
from typing import Dict, Any, List, Union
from schemas.event import NormalizedEvent

# Exact 9-dimensional operational flow feature schema defined in the IEEE research paper
FEATURE_NAMES: List[str] = [
    "duration",       # Length of network connection (seconds)
    "src_bytes",      # Bytes sent from source to destination
    "dst_bytes",      # Bytes sent from destination to source
    "count",          # Connections to same host in past 2 seconds
    "srv_count",      # Connections to same service in past 2 seconds
    "serror_rate",    # Ratio of connections with SYN errors [0.0, 1.0]
    "rerror_rate",    # Ratio of connections with REJ errors [0.0, 1.0]
    "same_srv_rate",  # Ratio of connections to same service [0.0, 1.0]
    "diff_srv_rate",  # Ratio of connections to different services [0.0, 1.0]
]

FEATURE_DIM: int = len(FEATURE_NAMES)  # 9


FEATURE_METADATA: Dict[str, Dict[str, Any]] = {
    "duration": {
        "unit": "seconds",
        "type": "float",
        "description": "Connection duration in seconds",
        "leakage_free": True,
    },
    "src_bytes": {
        "unit": "bytes",
        "type": "integer",
        "description": "Payload bytes sent from source to destination",
        "leakage_free": True,
    },
    "dst_bytes": {
        "unit": "bytes",
        "type": "integer",
        "description": "Payload bytes sent from destination to source",
        "leakage_free": True,
    },
    "count": {
        "unit": "count",
        "type": "integer",
        "description": "Number of connections to same host in sliding window",
        "leakage_free": True,
    },
    "srv_count": {
        "unit": "count",
        "type": "integer",
        "description": "Number of connections to same service in sliding window",
        "leakage_free": True,
    },
    "serror_rate": {
        "unit": "ratio",
        "type": "float",
        "description": "Percentage of connections with SYN errors [0.0, 1.0]",
        "leakage_free": True,
    },
    "rerror_rate": {
        "unit": "ratio",
        "type": "float",
        "description": "Percentage of connections with REJ errors [0.0, 1.0]",
        "leakage_free": True,
    },
    "same_srv_rate": {
        "unit": "ratio",
        "type": "float",
        "description": "Percentage of connections to same service [0.0, 1.0]",
        "leakage_free": True,
    },
    "diff_srv_rate": {
        "unit": "ratio",
        "type": "float",
        "description": "Percentage of connections to different services [0.0, 1.0]",
        "leakage_free": True,
    },
}


def _safe_float(val: Any, default: float = 0.0, min_val: float = 0.0, max_val: float = float("inf")) -> float:
    """Safely cast input to float, handle NaN/Inf, and clamp to [min_val, max_val]."""
    if val is None:
        return default
    try:
        f = float(val)
        if np.isnan(f) or np.isinf(f):
            return default
        return max(min_val, min(max_val, f))
    except (ValueError, TypeError):
        return default


def extract_features(event: Union[NormalizedEvent, Dict[str, Any]]) -> np.ndarray:
    """
    Extracts the verified 9-dimensional operational feature vector from a single event.
    
    Returns:
        np.ndarray of shape (9,) with dtype float64.
        Guarantees exact ordering matching FEATURE_NAMES.
    """
    if isinstance(event, NormalizedEvent):
        raw = event
        src_b = float(raw.src_bytes)
        dst_b = float(raw.dst_bytes)
        dur = float(raw.duration)
        cnt = float(raw.count)
        srv_cnt = float(raw.srv_count)
        s_err = float(raw.serror_rate)
        r_err = float(raw.rerror_rate)
        same_srv = float(raw.same_srv_rate)
        diff_srv = float(raw.diff_srv_rate)
    elif isinstance(event, dict):
        raw = event
        dur = _safe_float(raw.get("duration"), 0.0, 0.0)
        src_b = _safe_float(raw.get("src_bytes") if raw.get("src_bytes") is not None else raw.get("bytes_transferred"), 0.0, 0.0)
        dst_b = _safe_float(raw.get("dst_bytes"), 0.0, 0.0)
        cnt = _safe_float(raw.get("count"), 1.0, 0.0)
        srv_cnt = _safe_float(raw.get("srv_count"), 1.0, 0.0)
        s_err = _safe_float(raw.get("serror_rate"), 0.0, 0.0, 1.0)
        r_err = _safe_float(raw.get("rerror_rate"), 0.0, 0.0, 1.0)
        same_srv = _safe_float(raw.get("same_srv_rate"), 1.0, 0.0, 1.0)
        diff_srv = _safe_float(raw.get("diff_srv_rate"), 0.0, 0.0, 1.0)
    else:
        # Fallback for unexpected types
        return np.array([0.0, 0.0, 0.0, 1.0, 1.0, 0.0, 0.0, 1.0, 0.0], dtype=np.float64)

    vector = np.array([
        dur,
        src_b,
        dst_b,
        cnt,
        srv_cnt,
        s_err,
        r_err,
        same_srv,
        diff_srv,
    ], dtype=np.float64)

    return vector


def extract_feature_matrix(events: List[Union[NormalizedEvent, Dict[str, Any]]]) -> np.ndarray:
    """
    Batch extracts the 9-dimensional operational feature matrix.
    
    Returns:
        np.ndarray of shape (N, 9) with dtype float64.
        Returns shape (0, 9) if events list is empty.
    """
    if not events:
        return np.empty((0, FEATURE_DIM), dtype=np.float64)

    matrix = np.zeros((len(events), FEATURE_DIM), dtype=np.float64)
    for idx, e in enumerate(events):
        matrix[idx] = extract_features(e)

    return matrix


def validate_feature_vector(vec: np.ndarray) -> bool:
    """
    Verifies that a feature vector conforms to:
    - Shape (9,)
    - No NaN or Inf values
    - Rates bounded between 0.0 and 1.0
    - Non-negative bytes and counts
    """
    if not isinstance(vec, np.ndarray) or vec.shape != (FEATURE_DIM,):
        return False
    if np.any(np.isnan(vec)) or np.any(np.isinf(vec)):
        return False
    # Check non-negativity
    if np.any(vec < 0.0):
        return False
    # Check rate bounds: serror_rate (idx 5), rerror_rate (idx 6), same_srv_rate (idx 7), diff_srv_rate (idx 8)
    for idx in (5, 6, 7, 8):
        if vec[idx] < 0.0 or vec[idx] > 1.0:
            return False
    return True
