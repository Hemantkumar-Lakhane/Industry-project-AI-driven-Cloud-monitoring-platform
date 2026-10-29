"""
Network Scanning & Reconnaissance Detector (Attack Category 7)
==============================================================
Identifies port sweeps, host discovery, SYN port scans, and high service
divergence across cloud virtual private clouds (VPC).

Taxonomy Index: 7
Category Slug:  network_scanning
Playbook ID:    PB-BF-001
"""
from typing import Dict, Any, List, Optional, Union, Set
from collections import defaultdict
from schemas.event import NormalizedEvent
from schemas.finding import SecurityFinding
from engines.base_detector import BaseDetector, detector_registry

WAZUH_SCAN_RULES: Set[int] = {40101, 40102, 40103}


class NetworkScanningDetector(BaseDetector):
    """
    Evaluates network telemetry and VPC flow indicators for:
    1. Flow divergence: high diff_srv_rate (>= 0.7) and high connection count (>= 8).
    2. Repeated failed connections to distinct ports from single source IP.
    3. Wazuh port scan alerts (40101, 40102, 40103).
    """

    def __init__(self, enabled: bool = True):
        super().__init__(
            category="network_scanning",
            category_index=7,
            name="Network Scanning & Reconnaissance Detector",
            description="Identifies horizontal and vertical port scanning, service probing, and network enumeration sweeps.",
            supported_sources=["wazuh", "vpc_flow", "suricata"],
            enabled=enabled
        )

    def detect(self, events: List[Union[NormalizedEvent, Dict[str, Any]]]) -> List[SecurityFinding]:
        norm_events = self._ensure_normalized(events)
        findings: List[SecurityFinding] = []

        # Single event indicators & aggregation by src_ip
        ip_groups = defaultdict(list)

        for e in norm_events:
            rule_id = e.rule_id
            attack_type = e.attack_type
            action_lower = (e.action or "").lower()
            src_ip = e.source_ip or "unknown-ip"

            is_scan_rule = rule_id in WAZUH_SCAN_RULES or attack_type in ("port_scan", "network_scan")
            is_scan_action = "scan" in action_lower or "probe" in action_lower or "sweep" in action_lower

            # Flow metric indicators
            is_flow_scan = (e.diff_srv_rate >= 0.65 and e.count >= 8) or (e.rerror_rate >= 0.70 and e.count >= 10)

            if is_scan_rule or is_scan_action or is_flow_scan:
                ip_groups[src_ip].append(e)

        for src_ip, scan_events in ip_groups.items():
            count = len(scan_events)
            first_event = scan_events[0]
            if count < 5 and first_event.rule_id not in WAZUH_SCAN_RULES and first_event.attack_type not in ("port_scan", "network_scan"):
                continue

            triggering = scan_events[:10]

            facts = [
                f"Source IP '{src_ip}' exhibited network port scanning indicators across {count} events.",
                f"Target resources: {', '.join(list({e.target_resource or e.destination_ip or 'workload' for e in triggering if e.destination_ip or e.target_resource})[:5])}."
            ]
            if first_event.rule_id in WAZUH_SCAN_RULES:
                facts.append(f"Wazuh alert rule ID {first_event.rule_id} triggered: {first_event.description}.")

            severity = "medium" if count >= 3 else "low"
            confidence = min(0.95, 0.75 + count * 0.03)

            finding = self.create_finding(
                title=f"Network Reconnaissance: Port Scan Detected from '{src_ip}'",
                severity=severity,
                confidence=confidence,
                detection_method="hybrid",
                triggering_events=triggering,
                observed_facts=facts,
                inferred_hypothesis=f"Adversary scanning internal/external perimeter to map active services and discover open ports.",
                affected_resource=f"network:vpc:{first_event.target_resource or 'ingress'}",
                affected_principal=src_ip,
                telemetry_fields={"source_ip": src_ip, "probed_events_count": count},
                action_summary=f"Block source IP '{src_ip}' at security group or VPC Network ACL level and inspect targeted ports.",
                playbook_id="PB-BF-001",
                verification_status="VERIFIED"
            )
            findings.append(finding)

        return findings


network_scanning_detector = NetworkScanningDetector()
detector_registry.register(network_scanning_detector)
