"""
Cryptomining Workloads Detector (Attack Category 9)
===================================================
Identifies unauthorized cryptocurrency mining execution, Stratum protocol communication,
and connections to mining pool infrastructure.

Taxonomy Index: 9
Category Slug:  cryptomining
Playbook ID:    PB-CM-006
"""
from typing import Dict, Any, List, Optional, Union, Set
from schemas.event import NormalizedEvent
from schemas.finding import SecurityFinding
from engines.base_detector import BaseDetector, detector_registry

MINING_PORTS: Set[int] = {3333, 4444, 5555, 7777, 8888, 9999, 14433, 14444}
MINING_BINARIES: Set[str] = {"xmrig", "minerd", "cgminer", "cpuminer", "ethminer", "nanominer"}
MINING_POOLS: Set[str] = {"nanopool", "supportxmr", "ethermine", "moneroocean", "f2pool", "nicehash", "stratum"}
WAZUH_MINING_RULES: Set[int] = {87100, 87101}


class CryptominingDetector(BaseDetector):
    """
    Evaluates host process execution and network egress for:
    1. Known mining binaries (xmrig, minerd, cpuminer).
    2. Connections to Stratum protocol ports or known mining pool domains.
    3. Wazuh cryptomining detection rules (87100, 87101).
    """

    def __init__(self, enabled: bool = True):
        super().__init__(
            category="cryptomining",
            category_index=9,
            name="Cryptomining Workloads Detector",
            description="Identifies unauthorized cryptojacking activity, mining software execution, and mining pool communication.",
            supported_sources=["wazuh", "cloudtrail", "host_audit"],
            enabled=enabled
        )

    def detect(self, events: List[Union[NormalizedEvent, Dict[str, Any]]]) -> List[SecurityFinding]:
        norm_events = self._ensure_normalized(events)
        findings: List[SecurityFinding] = []

        for e in norm_events:
            desc = (e.description or "").lower()
            action = (e.action or "").lower()
            rule_id = e.rule_id
            attack_type = (e.attack_type or "").lower()
            raw_meta = e.raw_data or {}
            audit_str = f"{desc} {action} {str(raw_meta).lower()}"

            is_mining_explicit = attack_type in ("crypto_mining", "cryptomining") or rule_id in WAZUH_MINING_RULES
            is_mining_text = any(m in audit_str for m in MINING_BINARIES) or any(p in audit_str for p in MINING_POOLS) or "cryptomining" in audit_str or "crypto mining" in audit_str

            dest_port = raw_meta.get("dst_port") or raw_meta.get("port")
            is_mining_port = dest_port in MINING_PORTS

            if not (is_mining_explicit or is_mining_text or is_mining_port):
                continue

            principal = e.principal or e.user_id or "instance-worker"
            resource = e.target_resource or e.source_ip or "ec2-instance"

            facts = [
                f"Unauthorized cryptomining activity detected on host/workload '{resource}'.",
                f"Observed event details: Action='{e.action}', Description='{e.description}'.",
            ]
            if is_mining_port:
                facts.append(f"Network egress targeted known mining protocol port: {dest_port}.")

            finding = self.create_finding(
                title=f"Cryptojacking Activity: Mining Workload Detected on '{resource}'",
                severity="critical",
                confidence=0.97,
                detection_method="signature_and_behavioral",
                triggering_events=[e],
                observed_facts=facts,
                inferred_hypothesis=f"Host compromised by threat actor to execute cryptomining payloads and consume cloud compute resources.",
                affected_resource=f"compute:{resource}",
                affected_principal=principal,
                telemetry_fields={"resource": resource, "principal": principal, "port": dest_port},
                action_summary=f"Immediately terminate unauthorized mining process on '{resource}', isolate instance, and snapshot disks for forensics.",
                playbook_id="PB-CM-006",
                verification_status="VERIFIED"
            )
            findings.append(finding)

        return findings


cryptomining_detector = CryptominingDetector()
detector_registry.register(cryptomining_detector)
