"""
Brute-Force & Credential Abuse Detector (Attack Category 1)
============================================================
Detects high-velocity authentication failures and credential stuffing patterns
using a sliding-window correlation pipeline.

Taxonomy Index: 1
Category Slug:  brute_force
Playbook ID:    PB-BF-001

Detection Logic:
- Identifies authentication failure events via source-specific rule IDs,
  CloudTrail ConsoleLogin errors, and SSH/PAM auth failure actions.
- Groups events strictly by (target_identity, source_ip) tuples to prevent
  incorrectly merging unrelated users or unrelated attack sources.
- Evaluates a sliding temporal window (default: 60 seconds) to identify
  bursts of at least 5 failures.
- Checks if a successful authentication immediately succeeds the failure burst
  from the same source, elevating the finding from HIGH to CRITICAL.
"""
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Union, Tuple, Set
from collections import defaultdict

from schemas.event import NormalizedEvent, normalize_event
from schemas.finding import SecurityFinding
from engines.base_detector import BaseDetector, detector_registry

# Known telemetry indicators for authentication failures
AUTH_FAILURE_RULE_IDS: Set[int] = {
    5710,   # Wazuh: Multiple failed SSH/login attempts
    5712,   # Wazuh: Brute force attack detected
    5716,   # Wazuh: Credential stuffing pattern detected
    40111,  # Wazuh: Multiple failed authentication attempts
    40112,  # Wazuh: Excessive authentication failures
}

AUTH_FAILURE_ACTIONS: Set[str] = {
    "consolelogin",
    "login",
    "signin",
    "ssh_login",
    "ssh_failed_login",
    "authenticate",
    "user_auth",
    "pam_auth",
    "check_password",
    "failed_auth",
    "failed_login",
}

FAILURE_STATUSES: Set[str] = {
    "failure",
    "failed",
    "denied",
    "rejected",
    "error",
    "unauthorized",
}

AUTH_SERVICES: Set[str] = {
    "iam",
    "ssh",
    "sshd",
    "auth",
    "login",
    "console",
    "pam",
    "active_directory",
    "cognito",
    "okta",
}


def _is_auth_failure(event: NormalizedEvent) -> bool:
    """
    Strictly verifies whether a normalized event represents an authentication failure.
    Prevents misclassifying non-auth activities (e.g. S3 GetObject, EC2 DescribeInstances)
    or benign successful logins as failures.
    """
    # 1. Rule ID match
    if event.rule_id and event.rule_id in AUTH_FAILURE_RULE_IDS:
        return True

    action_clean = (event.action or "").strip().lower()
    status_clean = (event.status or "").strip().lower()
    service_clean = (event.service or "").strip().lower()

    # 2. AWS CloudTrail ConsoleLogin or Auth Actions
    if action_clean in AUTH_FAILURE_ACTIONS or any(k in action_clean for k in ("login", "signin", "authenticate")):
        if status_clean in FAILURE_STATUSES:
            return True

    # 3. Known auth service with failure status
    if service_clean in AUTH_SERVICES and status_clean in FAILURE_STATUSES:
        return True

    # 4. Failed attempts counter explicitly present on failure status
    if event.failed_attempts > 0 and status_clean in FAILURE_STATUSES:
        return True

    return False


def _is_auth_success(event: NormalizedEvent) -> bool:
    """Verifies whether an event represents a successful authentication."""
    action_clean = (event.action or "").strip().lower()
    status_clean = (event.status or "").strip().lower()
    service_clean = (event.service or "").strip().lower()

    if status_clean == "success" and event.failed_attempts == 0:
        if action_clean in AUTH_FAILURE_ACTIONS or any(k in action_clean for k in ("login", "signin", "authenticate")):
            return True
        if service_clean in AUTH_SERVICES and "login" in action_clean:
            return True
        if event.rule_id == 5715:  # Wazuh rule: Successful login
            return True

    return False


def _get_timestamp_sec(dt: datetime) -> float:
    """Convert datetime to UTC epoch seconds."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


class BruteForceDetector(BaseDetector):
    """
    Attack Category 1: Brute-Force & Credential Abuse.
    Implements a sliding-window failure counter with breach detection.
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        window_seconds: float = 60.0,
        enabled: bool = True
    ):
        super().__init__(
            category="brute_force",
            category_index=1,
            name="Brute-Force & Credential Abuse Detector",
            description="Detects rapid consecutive authentication failures targeting an identity within a sliding time window.",
            supported_sources=["wazuh", "cloudtrail", "host_audit", "synthetic"],
            enabled=enabled
        )
        self.failure_threshold = max(2, failure_threshold)
        self.window_seconds = max(5.0, window_seconds)

    def detect(self, events: List[Union[NormalizedEvent, Dict[str, Any]]]) -> List[SecurityFinding]:
        """
        Processes an event batch through the sliding-window brute force detector.
        """
        if not self.enabled or not events:
            return []

        norm_events = self._ensure_normalized(events)

        # 1. Deduplicate by event_id
        seen_ids: Set[str] = set()
        unique_events: List[NormalizedEvent] = []
        for e in norm_events:
            if e.event_id not in seen_ids:
                seen_ids.add(e.event_id)
                unique_events.append(e)

        # 2. Sort chronologically to safely handle out-of-order events
        unique_events.sort(key=lambda e: _get_timestamp_sec(e.timestamp))

        # 3. Partition events into buckets by (identity, src_ip)
        buckets: Dict[Tuple[str, str], List[NormalizedEvent]] = defaultdict(list)
        success_events: Dict[Tuple[str, str], List[NormalizedEvent]] = defaultdict(list)

        for e in unique_events:
            identity = (e.principal.identity or "unknown").strip()
            src_ip = (e.network.src_ip or "unknown").strip()
            key = (identity, src_ip)

            if _is_auth_failure(e):
                buckets[key].append(e)
            elif _is_auth_success(e):
                success_events[key].append(e)

        findings: List[SecurityFinding] = []

        # 4. Evaluate sliding window for each bucket
        for (identity, src_ip), failure_list in buckets.items():
            if len(failure_list) < self.failure_threshold:
                continue

            # Sliding window over the failure sequence
            i = 0
            while i < len(failure_list):
                window_start_time = _get_timestamp_sec(failure_list[i].timestamp)
                # Find all events in [window_start_time, window_start_time + window_seconds]
                window_events: List[NormalizedEvent] = []
                j = i
                while j < len(failure_list):
                    t_j = _get_timestamp_sec(failure_list[j].timestamp)
                    if t_j - window_start_time <= self.window_seconds:
                        window_events.append(failure_list[j])
                        j += 1
                    else:
                        break

                if len(window_events) >= self.failure_threshold:
                    # Calculate actual elapsed duration of the burst
                    t_first = _get_timestamp_sec(window_events[0].timestamp)
                    t_last = _get_timestamp_sec(window_events[-1].timestamp)
                    elapsed = max(0.1, t_last - t_first)

                    # Check for immediate breach (successful login after burst within window)
                    subsequent_successes = [
                        s for s in success_events.get((identity, src_ip), [])
                        if t_last <= _get_timestamp_sec(s.timestamp) <= (t_last + self.window_seconds)
                    ]
                    breach_occurred = len(subsequent_successes) > 0

                    # Calculate burst scoring (frequency rate, strictly documented as deterministic heuristic)
                    burst_rate = len(window_events) / elapsed  # attempts per second
                    burst_score = min(1.0, round(burst_rate / 2.0, 4))  # normalized heuristic: 2/s = 1.0

                    severity = "critical" if breach_occurred else "high"
                    confidence = 0.95 if breach_occurred else 0.88

                    title = (
                        f"Brute-Force Breach: {len(window_events)} failures followed by SUCCESSFUL LOGIN"
                        if breach_occurred
                        else f"Brute-Force Burst: {len(window_events)} authentication failures in {elapsed:.1f}s"
                    )

                    observed_facts = [
                        f"{len(window_events)} consecutive authentication failures observed for identity '{identity}'",
                        f"Source IP address: {src_ip}",
                        f"Elapsed window duration: {elapsed:.1f} seconds (burst rate: {burst_rate:.2f} attempts/sec)",
                    ]
                    if breach_occurred:
                        succ = subsequent_successes[0]
                        observed_facts.append(
                            f"BREACH INDICATOR: Successful login event '{succ.event_id}' observed at {succ.timestamp.isoformat()} after burst"
                        )

                    inferred_hypothesis = (
                        f"Adversary successfully guessed credentials for '{identity}' via high-rate password spray or brute force."
                        if breach_occurred
                        else f"Automated credential brute-force or dictionary attack targeting '{identity}'."
                    )

                    missing_evidence = (
                        "Target host access logs to determine if session was established, and secondary MFA challenge status."
                    )

                    telemetry_fields = {
                        "failure_count": len(window_events),
                        "elapsed_seconds": round(elapsed, 2),
                        "burst_rate_per_sec": round(burst_rate, 2),
                        "burst_score": burst_score,
                        "breach_confirmed": breach_occurred,
                        "target_identity": identity,
                        "source_ip": src_ip,
                        "first_failure_time": window_events[0].timestamp.isoformat(),
                        "last_failure_time": window_events[-1].timestamp.isoformat(),
                    }

                    triggering_list = list(window_events)
                    if breach_occurred:
                        triggering_list.extend(subsequent_successes)

                    finding = self.create_finding(
                        title=title,
                        severity=severity,
                        confidence=confidence,
                        detection_method="hybrid" if breach_occurred else "rule_based",
                        triggering_events=triggering_list,
                        observed_facts=observed_facts,
                        inferred_hypothesis=inferred_hypothesis,
                        missing_evidence=missing_evidence,
                        affected_resource=identity,
                        affected_principal=identity,
                        telemetry_fields=telemetry_fields,
                        action_summary=f"Temporarily lock account '{identity}' (dry-run) and evaluate source IP '{src_ip}' for blocking.",
                        playbook_id="PB-BF-001",
                        raw_scores={"burst_score": burst_score}
                    )
                    findings.append(finding)

                    # Advance window to next unprocessed event to avoid spamming findings
                    i = j
                else:
                    i += 1

        return findings


# Automatically register the detector with the global registry
brute_force_detector = BruteForceDetector()
detector_registry.register(brute_force_detector)
