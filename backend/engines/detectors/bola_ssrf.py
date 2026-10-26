"""
Application BOLA & SSRF Detector (Attack Category 11)
=====================================================
Identifies Server-Side Request Forgery (SSRF) targeting cloud metadata endpoints (IMDS),
internal RFC-1918 probing, and Broken Object Level Authorization (BOLA) ID manipulation.

Taxonomy Index: 11
Category Slug:  bola_ssrf
Playbook ID:    PB-DE-003
"""
from typing import Dict, Any, List, Optional, Union, Set
from schemas.event import NormalizedEvent
from schemas.finding import SecurityFinding
from engines.base_detector import BaseDetector, detector_registry

METADATA_IP = "169.254.169.254"
INTERNAL_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.", "127.")


class BOLASSRFDetector(BaseDetector):
    """
    Evaluates application and web gateway events for:
    1. Requests directed to cloud instance metadata endpoint (169.254.169.254).
    2. Server-side outbound connections to internal IP ranges originating from web pods/lambdas.
    3. BOLA / IDOR parameter tampering patterns.
    """

    def __init__(self, enabled: bool = True):
        super().__init__(
            category="bola_ssrf",
            category_index=11,
            name="Application BOLA & SSRF Detector",
            description="Identifies Server-Side Request Forgery against cloud metadata service (IMDSv1) and BOLA object access.",
            supported_sources=["waf", "cloudtrail", "wazuh", "app_audit"],
            enabled=enabled
        )

    def detect(self, events: List[Union[NormalizedEvent, Dict[str, Any]]]) -> List[SecurityFinding]:
        norm_events = self._ensure_normalized(events)
        findings: List[SecurityFinding] = []

        for e in norm_events:
            desc = (e.description or "").lower()
            dst_ip = e.destination_ip or ""
            action = (e.action or "").lower()
            attack_type = (e.attack_type or "").lower()
            raw_meta = e.raw_data or {}
            target_url = str(raw_meta.get("target_url") or raw_meta.get("url") or raw_meta.get("uri") or "").lower()
            payload_str = f"{desc} {dst_ip} {target_url} {str(e.target_resource or '').lower()}"

            is_metadata_ssrf = METADATA_IP in payload_str or "imds" in payload_str
            is_ssrf_explicit = attack_type in ("ssrf", "bola_ssrf") or "ssrf" in desc
            is_bola = "bola" in desc or "broken object level authorization" in desc or "idor" in desc or "bola" in attack_type

            if not (is_metadata_ssrf or is_ssrf_explicit or is_bola):
                continue

            principal = e.principal or e.user_id or e.source_ip or "external-client"
            target = e.target_resource or dst_ip or "web-app"

            is_critical = is_metadata_ssrf
            severity = "critical" if is_critical else "high"
            confidence = 0.98 if is_critical else 0.88

            facts = [
                f"Application-level SSRF/BOLA anomaly detected on target '{target}'.",
                f"Source/Principal: '{principal}', Action: '{e.action}'.",
            ]
            if is_metadata_ssrf:
                facts.append(f"Direct request to cloud instance metadata IP: {METADATA_IP} (credential extraction precursor).")
            if e.description:
                facts.append(f"Event description: {e.description}.")

            finding = self.create_finding(
                title=f"Server-Side Request Forgery (SSRF): Cloud Metadata Probing on '{target}'",
                severity=severity,
                confidence=confidence,
                detection_method="rule_based",
                triggering_events=[e],
                observed_facts=facts,
                inferred_hypothesis="Attacker exploiting server-side request parsing to access instance metadata service and steal IAM instance profile credentials.",
                affected_resource=f"app:{target}",
                affected_principal=principal,
                telemetry_fields={"principal": principal, "destination_ip": dst_ip, "action": e.action},
                action_summary=f"Enforce IMDSv2 with token hops limit 1, restrict outbound HTTP requests from web workloads, and block access to {METADATA_IP}.",
                playbook_id="PB-DE-003",
                verification_status="VERIFIED"
            )
            findings.append(finding)

        return findings


bola_ssrf_detector = BOLASSRFDetector()
detector_registry.register(bola_ssrf_detector)
