"""
Suspicious API Activity Detector (Attack Category 4)
====================================================
Detects high-velocity reconnaissance enumeration bursts, anomalous automation user-agents,
and suspicious management API calls from external or untrusted entities.

Taxonomy Index: 4
Category Slug:  suspicious_api_activity
Playbook ID:    PB-MC-005
"""
from typing import Dict, Any, List, Optional, Union, Tuple, Set
from collections import defaultdict
from schemas.event import NormalizedEvent
from schemas.finding import SecurityFinding
from engines.base_detector import BaseDetector, detector_registry

RECON_ACTIONS_PREFIX = ("describe", "list", "get")
SUSPICIOUS_USER_AGENTS = ("python-requests", "curl", "bot", "go-http-client", "postman", "powershell")


class SuspiciousAPIActivityDetector(BaseDetector):
    """
    Evaluates cloud API events for:
    1. High-velocity reconnaissance bursts: >= 10 Describe*/List* calls within 60 seconds from same entity.
    2. Headless automation / script tooling user agents accessing sensitive management APIs.
    """

    def __init__(self, burst_threshold: int = 10, window_seconds: int = 60, enabled: bool = True):
        super().__init__(
            category="suspicious_api_activity",
            category_index=4,
            name="Suspicious API Activity Detector",
            description="Identifies automated reconnaissance bursts, excessive API velocity, and script-based management calls.",
            supported_sources=["cloudtrail", "wazuh"],
            enabled=enabled
        )
        self.burst_threshold = burst_threshold
        self.window_seconds = window_seconds

    def detect(self, events: List[Union[NormalizedEvent, Dict[str, Any]]]) -> List[SecurityFinding]:
        norm_events = self._ensure_normalized(events)
        findings: List[SecurityFinding] = []

        # Group by caller tuple (principal, source_ip)
        caller_timeline = defaultdict(list)
        for e in norm_events:
            principal = (e.user_id or "unknown").strip().lower()
            ip = e.source_ip or "0.0.0.0"
            caller_timeline[(principal, ip)].append(e)

        for (principal, ip), caller_events in caller_timeline.items():
            caller_events.sort(key=lambda x: x.timestamp)
            n = len(caller_events)

            i = 0
            while i < n:
                # Sliding window evaluation
                window_events = []
                anchor = caller_events[i]
                recon_count = 0
                suspicious_ua_events = []

                j = i
                while j < n:
                    cand = caller_events[j]
                    delta_t = (cand.timestamp - anchor.timestamp).total_seconds()
                    if delta_t < 0:
                        j += 1
                        continue
                    if delta_t > self.window_seconds:
                        break

                    window_events.append(cand)
                    act_lower = (cand.action or "").lower()
                    if any(act_lower.startswith(p) for p in RECON_ACTIONS_PREFIX) or cand.action == "SuspiciousAPICall":
                        recon_count += 1

                    raw_meta = cand.raw_data or {}
                    ua = str(raw_meta.get("userAgent", "")).lower()
                    if any(s in ua for s in SUSPICIOUS_USER_AGENTS):
                        suspicious_ua_events.append(cand)

                    j += 1

                if recon_count >= self.burst_threshold:
                    observed = [
                        f"Principal '{principal}' originating from IP '{ip}' generated {recon_count} reconnaissance calls within {self.window_seconds}s.",
                        f"Targeted services include: {', '.join(set(e.service for e in window_events if e.service))}."
                    ]
                    if suspicious_ua_events:
                        observed.append(f"Detected automated script user-agent: {suspicious_ua_events[0].raw_data.get('userAgent')}.")

                    finding = self.create_finding(
                        title=f"Suspicious API Reconnaissance Burst: {recon_count} calls in {self.window_seconds}s",
                        severity="high",
                        confidence=min(0.95, 0.70 + (recon_count - self.burst_threshold) * 0.02),
                        detection_method="hybrid",
                        triggering_events=window_events,
                        observed_facts=observed,
                        inferred_hypothesis=f"Threat actor executing automated discovery / environment enumeration across cloud infrastructure.",
                        affected_resource=f"api:cloudtrail",
                        affected_principal=principal,
                        telemetry_fields={"principal": principal, "source_ip": ip, "recon_count": recon_count},
                        action_summary=f"Apply temporary rate-limiting or policy throttling to principal '{principal}' and investigate source IP '{ip}'.",
                        playbook_id="PB-MC-005",
                        verification_status="VERIFIED"
                    )
                    findings.append(finding)
                    i = j
                elif len(suspicious_ua_events) >= 5:
                    finding = self.create_finding(
                        title=f"Anomalous Scripted API Access from Tooling User-Agent by '{principal}'",
                        severity="medium",
                        confidence=0.75,
                        detection_method="rule_based",
                        triggering_events=suspicious_ua_events,
                        observed_facts=[f"Detected {len(suspicious_ua_events)} calls using command-line/script user-agent."],
                        inferred_hypothesis="Automated scraper or unapproved script accessing sensitive cloud APIs.",
                        affected_resource="api:cloudtrail",
                        affected_principal=principal,
                        telemetry_fields={"principal": principal, "source_ip": ip, "call_count": len(suspicious_ua_events)},
                        action_summary=f"Review API credentials for '{principal}' and enforce MFA on console and CLI sessions.",
                        playbook_id="PB-MC-005",
                        verification_status="VERIFIED"
                    )
                    findings.append(finding)
                    i = j
                else:
                    i += 1

        return findings


suspicious_api_activity_detector = SuspiciousAPIActivityDetector()
detector_registry.register(suspicious_api_activity_detector)
