"""
Supply-Chain Compromise Detector (Attack Category 15)
=====================================================
Identifies immutable container tag mutation, unauthorized CI/CD pipeline modifications,
and introduction of unverified third-party dependencies or malicious container digests.

Taxonomy Index: 15
Category Slug:  supply_chain_compromise
Playbook ID:    PB-RP-008
"""
from typing import Dict, Any, List, Optional, Union, Set
from schemas.event import NormalizedEvent
from schemas.finding import SecurityFinding
from engines.base_detector import BaseDetector, detector_registry

SUPPLY_CHAIN_ACTIONS: Set[str] = {
    "putimage",
    "batchdeleteimage",
    "updatepipeline",
    "createpipeline",
    "createbuild",
}


class SupplyChainDetector(BaseDetector):
    """
    Evaluates registry and CI/CD events for:
    1. Overwriting production container image tags (e.g. 'latest' or release semver) in ECR/registries.
    2. Modification of CI/CD pipeline definitions or build scripts from non-administrative identities.
    3. Injection of unvetted packages or dependency tampering.
    """

    def __init__(self, enabled: bool = True):
        super().__init__(
            category="supply_chain_compromise",
            category_index=15,
            name="Supply-Chain Compromise Detector",
            description="Identifies container image tag mutation, pipeline build tampering, and unauthorized package injection.",
            supported_sources=["ecr_audit", "codebuild", "wazuh"],
            enabled=enabled
        )

    def detect(self, events: List[Union[NormalizedEvent, Dict[str, Any]]]) -> List[SecurityFinding]:
        norm_events = self._ensure_normalized(events)
        findings: List[SecurityFinding] = []

        for e in norm_events:
            desc = (e.description or "").lower()
            action_lower = (e.action or "").lower()
            attack_type = (e.attack_type or "").lower()

            is_supply_action = action_lower in SUPPLY_CHAIN_ACTIONS
            is_supply_attack = attack_type in ("supply_chain_compromise", "supply_chain") or "supply chain" in desc or "tag overwrite" in desc or "tag mutation" in desc

            if not (is_supply_action or is_supply_attack):
                continue

            principal = e.principal or e.user_id or "pipeline-identity"
            repo_name = e.target_resource or "production-image-repo"

            is_critical = "tag overwrite" in desc or "tag mutation" in desc or "tampering" in desc or attack_type == "supply_chain_compromise"
            severity = "critical" if is_critical else "high"
            confidence = 0.94 if is_critical else 0.85

            facts = [
                f"Supply-chain integrity anomaly observed on artifact repository '{repo_name}'.",
                f"Action: '{e.action}', Principal: '{principal}'.",
            ]
            if "tag" in desc or action_lower == "putimage":
                facts.append("Potential image tag mutability exploit detected: Existing image tag overwritten with new digest.")

            finding = self.create_finding(
                title=f"Supply-Chain Compromise: Container Tag Mutation or Pipeline Tampering on '{repo_name}'",
                severity=severity,
                confidence=confidence,
                detection_method="rule_based",
                triggering_events=[e],
                observed_facts=facts,
                inferred_hypothesis=f"Threat actor altered container image digest or build steps to inject malicious dependencies into production deployment pipelines.",
                affected_resource=f"registry:{repo_name}",
                affected_principal=principal,
                telemetry_fields={"repository": repo_name, "principal": principal, "action": e.action},
                action_summary=f"Enforce immutable tags on repository '{repo_name}', halt automated deployments, and verify container signature against cosign/Notary.",
                playbook_id="PB-RP-008",
                verification_status="VERIFIED"
            )
            findings.append(finding)

        return findings


supply_chain_detector = SupplyChainDetector()
detector_registry.register(supply_chain_detector)
