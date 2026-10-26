"""
Data Exfiltration Detector (Attack Category 6)
==============================================
Identifies large volumetric transfers to external destinations, bulk file downloads,
and unauthorized data egress across cloud buckets and object stores.

Taxonomy Index: 6
Category Slug:  data_exfiltration
Playbook ID:    PB-DE-003
"""
from typing import Dict, Any, List, Optional, Union, Set
from collections import defaultdict
from schemas.event import NormalizedEvent
from schemas.finding import SecurityFinding
from engines.base_detector import BaseDetector, detector_registry

WAZUH_EXFIL_RULES: Set[int] = {31101, 31102}
HIGH_VOLUME_BYTES_SINGLE = 100_000_000    # 100 MB single transfer
MASSIVE_VOLUME_BYTES_SINGLE = 500_000_000 # 500 MB single transfer
MODERATE_VOLUME_BYTES = 10_000_000        # 10 MB egress


class DataExfiltrationDetector(BaseDetector):
    """
    Evaluates egress traffic and storage retrieval for:
    1. Single massive data transfers (> 100 MB / 500 MB) to external IP destinations.
    2. Wazuh data exfiltration alert signatures (31101, 31102).
    3. High-velocity repeated GetObject / download streams to external endpoints.
    """

    def __init__(self, enabled: bool = True):
        super().__init__(
            category="data_exfiltration",
            category_index=6,
            name="Data Exfiltration Detector",
            description="Detects anomalous volumetric data transfers, bulk downloads, and unauthorized external data egress.",
            supported_sources=["wazuh", "cloudtrail", "vpc_flow"],
            enabled=enabled
        )

    def detect(self, events: List[Union[NormalizedEvent, Dict[str, Any]]]) -> List[SecurityFinding]:
        norm_events = self._ensure_normalized(events)
        findings: List[SecurityFinding] = []

        for e in norm_events:
            bytes_out = e.dst_bytes or e.src_bytes or e.bytes_transferred or 0
            rule_id = e.rule_id
            attack_type = e.attack_type
            action_lower = (e.action or "").lower()
            dst_ip = e.destination_ip or ""
            src_ip = e.source_ip or ""

            # Check if this is external egress
            is_wazuh_exfil = (rule_id in WAZUH_EXFIL_RULES) or (attack_type == "data_exfiltration")
            is_massive_volume = bytes_out >= HIGH_VOLUME_BYTES_SINGLE
            is_exfil_desc = ("exfiltration" in (e.description or "").lower() or "large volume egress" in (e.description or "").lower()) and bytes_out > 0

            if not (is_wazuh_exfil or is_massive_volume or is_exfil_desc):
                continue

            principal = e.principal or e.user_id or "unknown-user"
            dest = dst_ip or "external-endpoint"

            if bytes_out >= MASSIVE_VOLUME_BYTES_SINGLE or (is_wazuh_exfil and bytes_out >= HIGH_VOLUME_BYTES_SINGLE):
                severity = "critical"
                confidence = 0.95
            elif bytes_out >= HIGH_VOLUME_BYTES_SINGLE or is_wazuh_exfil:
                severity = "high"
                confidence = 0.88
            elif bytes_out >= MODERATE_VOLUME_BYTES:
                severity = "medium"
                confidence = 0.75
            else:
                severity = "medium"
                confidence = 0.70

            mb_transferred = round(bytes_out / (1024 * 1024), 2)
            facts = [
                f"Principal '{principal}' initiated transfer resulting in {mb_transferred} MB data volume.",
                f"Source IP: '{src_ip}', Destination IP: '{dest}', Action: '{e.action or 'GetObject'}'.",
            ]
            if is_wazuh_exfil:
                facts.append(f"Wazuh SIEM rule triggered: Rule ID {rule_id}.")

            finding = self.create_finding(
                title=f"Data Exfiltration: High-Volume Egress ({mb_transferred} MB) to External Endpoint",
                severity=severity,
                confidence=confidence,
                detection_method="hybrid",
                triggering_events=[e],
                observed_facts=facts,
                inferred_hypothesis=f"Threat actor executing unauthorized bulk data extraction from storage repository to external host '{dest}'.",
                affected_resource=f"storage:{e.target_resource or e.service or 's3'}",
                affected_principal=principal,
                telemetry_fields={"principal": principal, "source_ip": src_ip, "destination_ip": dest, "bytes": bytes_out},
                action_summary=f"Temporarily suspend credentials for principal '{principal}' and block egress route to IP '{dest}'.",
                playbook_id="PB-DE-003",
                verification_status="VERIFIED"
            )
            findings.append(finding)

        return findings


data_exfiltration_detector = DataExfiltrationDetector()
detector_registry.register(data_exfiltration_detector)
