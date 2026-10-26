"""
Audit Defense & Logging Tampering Detector (Attack Category 16)
==============================================================
Identifies termination of cloud logging (StopLogging, DeleteTrail), disabling
security sensors (GuardDuty, Wazuh agent), and host audit log file deletion.

Taxonomy Index: 16
Category Slug:  defense_tampering
Playbook ID:    PB-PE-002
"""
from typing import Dict, Any, List, Optional, Union, Set
from schemas.event import NormalizedEvent
from schemas.finding import SecurityFinding
from engines.base_detector import BaseDetector, detector_registry

TAMPER_ACTIONS: Set[str] = {
    "stoplogging",
    "deletetrail",
    "updatetrail",
    "deletedetector",
    "disassociatefrommasteraccount",
    "disableorganizationadminaccount",
    "deleteflowlogs",
    "deletealarms",
    "disablealarmactions",
}

TAMPER_COMMANDS = ("rm -rf /var/log", "auditctl -e 0", "wevtutil cl", "systemctl stop wazuh", "service ossec stop", "killall ossec")


class DefenseTamperingDetector(BaseDetector):
    """
    Evaluates cloud management plane and host telemetry for:
    1. CloudTrail termination: StopLogging, DeleteTrail, or disabling multi-region trails.
    2. GuardDuty / SecurityHub / VPC Flow Logs disruption or deletion.
    3. Host audit log destruction (clearing Windows Event Logs, killing Wazuh agent, rm /var/log).
    """

    def __init__(self, enabled: bool = True):
        super().__init__(
            category="defense_tampering",
            category_index=16,
            name="Audit Defense & Logging Tampering Detector",
            description="Identifies disabling of CloudTrail, disruption of security sensors, and host audit log clearing.",
            supported_sources=["cloudtrail", "wazuh", "host_audit"],
            enabled=enabled
        )

    def detect(self, events: List[Union[NormalizedEvent, Dict[str, Any]]]) -> List[SecurityFinding]:
        norm_events = self._ensure_normalized(events)
        findings: List[SecurityFinding] = []

        for e in norm_events:
            desc = (e.description or "").lower()
            action_lower = (e.action or "").lower()
            attack_type = (e.attack_type or "").lower()

            is_tamper_action = action_lower in TAMPER_ACTIONS
            is_tamper_cmd = any(cmd in desc for cmd in TAMPER_COMMANDS)
            is_tamper_explicit = attack_type in ("defense_tampering", "logging_tampering", "audit_tampering") or "defense tampering" in desc or "stoplogging" in desc or "deletetrail" in desc

            if not (is_tamper_action or is_tamper_cmd or is_tamper_explicit):
                continue

            principal = e.principal or e.user_id or "unauthorized-operator"
            trail_name = e.target_resource or "cloud-audit-trail"

            facts = [
                f"Audit logging / security defense tampering action observed: Action='{e.action}'.",
                f"Principal: '{principal}', Target: '{trail_name}'.",
            ]
            if action_lower in ("stoplogging", "deletetrail"):
                facts.append("Critical cloud defense evasion: Primary audit trail logging explicitly stopped or deleted.")
            if is_tamper_cmd:
                facts.append("Host sensor evasion: System commands detected attempting to silence audit agents or wipe /var/log.")

            finding = self.create_finding(
                title=f"Critical Defense Evasion: Audit Logging Disabled or Tampered on '{trail_name}'",
                severity="critical",
                confidence=0.99,
                detection_method="rule_based",
                triggering_events=[e],
                observed_facts=facts,
                inferred_hypothesis=f"Threat actor executing deliberate defense evasion / evidence destruction to blind Security Operations Center (SOC) monitoring.",
                affected_resource=f"audit:{trail_name}",
                affected_principal=principal,
                telemetry_fields={"trail": trail_name, "principal": principal, "action": e.action},
                action_summary=f"Immediately re-enable CloudTrail logging on '{trail_name}', quarantine principal '{principal}', and lock management plane sessions.",
                playbook_id="PB-PE-002",
                verification_status="VERIFIED"
            )
            findings.append(finding)

        return findings


defense_tampering_detector = DefenseTamperingDetector()
detector_registry.register(defense_tampering_detector)
