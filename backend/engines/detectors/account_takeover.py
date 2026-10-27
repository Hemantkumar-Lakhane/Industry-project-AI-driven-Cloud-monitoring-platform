"""
Account Takeover (ATO) Detector (Attack Category 2)
===================================================
Detects account compromise via rapid IP divergence, multi-geo access velocity,
and immediate sensitive credential modifications following authentication.

Taxonomy Index: 2
Category Slug:  account_takeover
Playbook ID:    PB-CS-007
"""
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Union, Tuple, Set
from collections import defaultdict

from schemas.event import NormalizedEvent
from schemas.finding import SecurityFinding
from engines.base_detector import BaseDetector, detector_registry

SENSITIVE_POST_AUTH_ACTIONS: Set[str] = {
    "changepassword",
    "updateloginprofile",
    "createaccesskey",
    "enablemfadevice",
    "deletemfadevice",
    "resyncmfadevice",
    "createloginprofile",
    "putuserpolicy",
}

AUTH_ACTIONS: Set[str] = {
    "consolelogin",
    "login",
    "signin",
    "ssh_login",
    "authenticate",
}


class AccountTakeoverDetector(BaseDetector):
    """
    Evaluates account takeover patterns:
    1. Multi-IP switching: Same user authenticating from distinct external IPs within a short window (< 120s).
    2. Sensitive post-auth actions: Password reset, MFA tampering, or access key generation immediately following IP transition.
    """

    def __init__(self, window_seconds: int = 120, enabled: bool = True):
        super().__init__(
            category="account_takeover",
            category_index=2,
            name="Account Takeover (ATO) Detector",
            description="Detects rapid IP shifting and immediate sensitive credential modifications post-authentication.",
            supported_sources=["wazuh", "cloudtrail", "host_audit"],
            enabled=enabled
        )
        self.window_seconds = window_seconds

    def detect(self, events: List[Union[NormalizedEvent, Dict[str, Any]]]) -> List[SecurityFinding]:
        norm_events = self._ensure_normalized(events)
        if not norm_events:
            return []

        # Group by principal identity
        user_timeline = defaultdict(list)
        for e in norm_events:
            identity = (e.user_id or "unknown").strip().lower()
            if identity and identity not in ("anonymous", "unknown", "root"):
                user_timeline[identity].append(e)

        findings: List[SecurityFinding] = []

        for user, user_events in user_timeline.items():
            user_events.sort(key=lambda x: x.timestamp)
            n = len(user_events)

            i = 0
            while i < n:
                anchor = user_events[i]
                action_lower = (anchor.action or "").lower()
                status_lower = (anchor.status or "").lower()
                is_auth = (action_lower in AUTH_ACTIONS or anchor.event_type == "authentication") and status_lower in ("success", "ok")

                if not is_auth:
                    i += 1
                    continue

                anchor_ip = anchor.source_ip
                if not anchor_ip or anchor_ip.startswith("127.") or anchor_ip == "::1":
                    i += 1
                    continue

                # Look forward within sliding window
                j = i + 1
                suspicious_actions = []
                divergent_ips = set()

                while j < n:
                    candidate = user_events[j]
                    delta_t = (candidate.timestamp - anchor.timestamp).total_seconds()
                    if delta_t < 0:
                        j += 1
                        continue
                    if delta_t > self.window_seconds:
                        break

                    cand_ip = candidate.source_ip
                    cand_act = (candidate.action or "").lower()

                    if cand_ip and cand_ip != anchor_ip and not cand_ip.startswith("127."):
                        divergent_ips.add(cand_ip)

                    if cand_act in SENSITIVE_POST_AUTH_ACTIONS:
                        suspicious_actions.append(candidate)

                    j += 1

                # Condition 1: Divergent IP followed by sensitive action (Critical ATO)
                # Condition 2: Multiple distinct external IPs within <= 120s (High ATO)
                if divergent_ips and suspicious_actions:
                    triggering = [anchor] + suspicious_actions
                    facts = [
                        f"User '{user}' successfully logged in from IP '{anchor_ip}'.",
                        f"Observed rapid IP transition to '{', '.join(divergent_ips)}' within {self.window_seconds}s.",
                        f"Sensitive post-auth actions executed: {', '.join(a.action for a in suspicious_actions)}."
                    ]
                    finding = self.create_finding(
                        title=f"Account Takeover Confirmed: Sensitive Modification Post IP Shift for '{user}'",
                        severity="critical",
                        confidence=0.96,
                        detection_method="hybrid",
                        triggering_events=triggering,
                        observed_facts=facts,
                        inferred_hypothesis=f"Attacker obtained credentials, authenticated from new IP, and immediately modified authentication factors for '{user}'.",
                        affected_resource=f"user:{user}",
                        affected_principal=user,
                        telemetry_fields={"initial_ip": anchor_ip, "divergent_ips": list(divergent_ips), "user": user},
                        action_summary=f"Revoke active sessions for '{user}', disable compromised access keys, and require out-of-band identity verification.",
                        playbook_id="PB-CS-007",
                        verification_status="VERIFIED"
                    )
                    findings.append(finding)
                    i = j
                elif len(divergent_ips) >= 1:
                    facts = [
                        f"User '{user}' authenticated from IP '{anchor_ip}'.",
                        f"Subsequent authentication or activity from divergent IP '{', '.join(divergent_ips)}' within {self.window_seconds}s."
                    ]
                    finding = self.create_finding(
                        title=f"Suspicious Concurrent Session / IP Shift for '{user}'",
                        severity="high",
                        confidence=0.82,
                        detection_method="rule_based",
                        triggering_events=[anchor],
                        observed_facts=facts,
                        inferred_hypothesis=f"Potential concurrent session hijacking or credential sharing across distinct network locations for '{user}'.",
                        affected_resource=f"user:{user}",
                        affected_principal=user,
                        telemetry_fields={"initial_ip": anchor_ip, "divergent_ips": list(divergent_ips), "user": user},
                        action_summary=f"Audit active sessions for user '{user}' and verify legitimacy of IP transitions.",
                        playbook_id="PB-CS-007",
                        verification_status="VERIFIED"
                    )
                    findings.append(finding)
                    i = j
                else:
                    i += 1

        return findings


account_takeover_detector = AccountTakeoverDetector()
detector_registry.register(account_takeover_detector)
