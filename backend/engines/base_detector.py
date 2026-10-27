"""
Base Detector Architecture for RAM Antivirus
==============================================
Defines the abstract BaseDetector interface and DetectorRegistry supporting
all 16 cloud attack categories specified in the approved implementation roadmap.

Every detector consumes normalized events and produces standard SecurityFinding
objects with strict separation of observed evidence from analytical inference.
"""
from abc import ABC, abstractmethod
import uuid
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Union, Type

from schemas.event import NormalizedEvent, normalize_event
from schemas.finding import SecurityFinding, FindingEvidence, RecommendedResponse

# The canonical 16 attack categories from the approved RAM Antivirus roadmap
TAXONOMY_16: Dict[int, Dict[str, Any]] = {
    1: {"slug": "brute_force", "name": "Brute-Force & Credential Abuse", "default_playbook": "PB-BF-001"},
    2: {"slug": "account_takeover", "name": "Account Takeover (ATO)", "default_playbook": "PB-CS-007"},
    3: {"slug": "iam_privilege_escalation", "name": "IAM Privilege Escalation", "default_playbook": "PB-PE-002"},
    4: {"slug": "suspicious_api_activity", "name": "Suspicious API Activity", "default_playbook": "PB-MC-005"},
    5: {"slug": "cloud_misconfiguration", "name": "Cloud Misconfiguration Drift", "default_playbook": "PB-MC-005"},
    6: {"slug": "data_exfiltration", "name": "Data Exfiltration", "default_playbook": "PB-DE-003"},
    7: {"slug": "network_scanning", "name": "Network Scanning & Reconnaissance", "default_playbook": "PB-BF-001"},
    8: {"slug": "ddos", "name": "Distributed Denial of Service (DDoS)", "default_playbook": "PB-CS-007"},
    9: {"slug": "cryptomining", "name": "Cryptomining Workloads", "default_playbook": "PB-CM-006"},
    10: {"slug": "container_k8s_attacks", "name": "Container & Kubernetes Attacks", "default_playbook": "PB-RP-008"},
    11: {"slug": "bola_ssrf", "name": "Application BOLA & SSRF", "default_playbook": "PB-DE-003"},
    12: {"slug": "malware_ransomware", "name": "Malware & Ransomware Precursor", "default_playbook": "PB-RP-008"},
    13: {"slug": "database_attacks", "name": "Database Threat Activity", "default_playbook": "PB-DE-003"},
    14: {"slug": "serverless_abuse", "name": "Serverless Function Abuse", "default_playbook": "PB-MC-005"},
    15: {"slug": "supply_chain_compromise", "name": "Supply-Chain Compromise", "default_playbook": "PB-RP-008"},
    16: {"slug": "defense_tampering", "name": "Audit Defense & Logging Tampering", "default_playbook": "PB-PE-002"},
}


class BaseDetector(ABC):
    """
    Abstract base class for all 16 attack category detection modules.
    Ensures consistent finding schemas, evidence structuring, and safe responses.
    """

    def __init__(
        self,
        category: str,
        category_index: int,
        name: str,
        description: str,
        supported_sources: Optional[List[str]] = None,
        enabled: bool = True
    ):
        self.category = category
        self.category_index = category_index
        self.name = name
        self.description = description
        self.supported_sources = supported_sources or ["wazuh", "cloudtrail", "host_audit"]
        self.enabled = enabled

    @abstractmethod
    def detect(self, events: List[Union[NormalizedEvent, Dict[str, Any]]]) -> List[SecurityFinding]:
        """
        Analyze an event stream or batch and return all identified security findings.
        Must be implemented by every concrete detector.
        """
        pass

    def detect_single(self, event: Union[NormalizedEvent, Dict[str, Any]]) -> Optional[SecurityFinding]:
        """
        Convenience method to evaluate a single event.
        Default implementation wraps single event in a list and calls detect().
        """
        findings = self.detect([event])
        return findings[0] if findings else None

    def create_finding(
        self,
        title: str,
        severity: str,
        confidence: float,
        detection_method: str,
        triggering_events: List[NormalizedEvent],
        observed_facts: List[str],
        inferred_hypothesis: Optional[str] = None,
        missing_evidence: Optional[str] = None,
        affected_resource: Optional[str] = None,
        affected_principal: Optional[str] = None,
        telemetry_fields: Optional[Dict[str, Any]] = None,
        action_summary: Optional[str] = None,
        playbook_id: Optional[str] = None,
        raw_scores: Optional[Dict[str, float]] = None,
        data_source: str = "SIMULATED",
        verification_status: str = "VERIFIED",
    ) -> SecurityFinding:
        """
        Factory helper ensuring all findings adhere strictly to SecurityFinding schema
        with verified evidence provenance and default guarded dry-run response.
        """
        # Resolve default playbook from taxonomy if not specified
        if not playbook_id and self.category_index in TAXONOMY_16:
            playbook_id = TAXONOMY_16[self.category_index].get("default_playbook")

        if affected_principal is not None and not isinstance(affected_principal, str):
            affected_principal = getattr(affected_principal, "identity", str(affected_principal))
        if affected_resource is not None and not isinstance(affected_resource, str):
            affected_resource = str(affected_resource)

        event_ids = [e.event_id for e in triggering_events if isinstance(e, NormalizedEvent)]

        evidence = FindingEvidence(
            triggering_event_ids=event_ids,
            observed_facts=observed_facts,
            inferred_hypothesis=inferred_hypothesis,
            missing_evidence=missing_evidence,
            telemetry_fields=telemetry_fields or {}
        )

        response = RecommendedResponse(
            playbook_id=playbook_id,
            action_summary=action_summary or f"Investigate {self.name} finding for affected entity.",
            is_dry_run_supported=True,
            requires_admin_auth=True
        )

        # Deterministic finding ID enables deduplication across repeated evaluation scans
        id_seed = f"{self.category}:{affected_resource or 'none'}:{affected_principal or 'none'}:{title}"
        det_hash = hashlib.sha256(id_seed.encode("utf-8")).hexdigest()[:8].upper()

        return SecurityFinding(
            finding_id=f"FIND-{self.category.upper()[:4]}-{det_hash}",
            attack_category=self.category,
            category_index=self.category_index,
            title=title,
            description=f"[{self.name}] {title}",
            severity=severity,
            confidence=max(0.0, min(1.0, float(confidence))),
            detection_method=detection_method,
            status="open",
            affected_resource=affected_resource,
            affected_principal=affected_principal,
            evidence=evidence,
            recommended_response=response,
            data_source=data_source,
            verification_status=verification_status,
            raw_scores=raw_scores or {}
        )

    def _ensure_normalized(self, events: List[Union[NormalizedEvent, Dict[str, Any]]]) -> List[NormalizedEvent]:
        """Safely normalize all input events."""
        normalized = []
        for e in events:
            if isinstance(e, NormalizedEvent):
                normalized.append(e)
            elif isinstance(e, dict):
                normalized.append(normalize_event(e))
        return normalized


class DetectorRegistry:
    """
    Central registry for managing detector lifecycle and multi-module execution.
    """

    def __init__(self):
        self._detectors: Dict[str, BaseDetector] = {}

    def register(self, detector: BaseDetector) -> None:
        """Register a detector instance by its category slug."""
        self._detectors[detector.category] = detector

    def get(self, category: str) -> Optional[BaseDetector]:
        """Retrieve a registered detector by category."""
        return self._detectors.get(category)

    def list_all(self) -> List[Dict[str, Any]]:
        """List metadata for all registered detectors."""
        return [
            {
                "category": d.category,
                "category_index": d.category_index,
                "name": d.name,
                "description": d.description,
                "supported_sources": d.supported_sources,
                "enabled": d.enabled
            }
            for d in self._detectors.values()
        ]

    def run_all(self, events: List[Union[NormalizedEvent, Dict[str, Any]]]) -> List[SecurityFinding]:
        """Run all enabled detectors across an event batch."""
        all_findings = []
        for detector in self._detectors.values():
            if detector.enabled:
                findings = detector.detect(events)
                all_findings.extend(findings)
        return all_findings


# Global singleton registry instance
detector_registry = DetectorRegistry()
