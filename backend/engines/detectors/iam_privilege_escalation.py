"""
IAM Privilege Escalation Detector (Attack Category 3)
======================================================
Identifies unauthorized privilege escalation vectors, administrative policy attachments,
and permissive wildcard role/policy modifications in cloud control planes.

Taxonomy Index: 3
Category Slug:  iam_privilege_escalation
Playbook ID:    PB-PE-002
"""
from typing import Dict, Any, List, Optional, Union, Set
from schemas.event import NormalizedEvent
from schemas.finding import SecurityFinding
from engines.base_detector import BaseDetector, detector_registry

ESCALATION_ACTIONS: Set[str] = {
    "attachuserpolicy",
    "attachrolepolicy",
    "attachgrouppolicy",
    "putuserpolicy",
    "putrolepolicy",
    "putgrouppolicy",
    "createpolicyversion",
    "setdefaultpolicyversion",
    "addusertogroup",
    "createloginprofile",
    "updateloginprofile",
    "updaterolesubject",
}

CRITICAL_POLICIES: Set[str] = {
    "administratoraccess",
    "poweruseraccess",
    "iamfullaccess",
    "securityaudit",
    "*",
}

CRITICAL_GROUPS: Set[str] = {
    "administrators",
    "admins",
    "devopsadmin",
    "cloudadmin",
}

WAZUH_PRIV_ESC_RULE_IDS: Set[int] = {5402, 5403, 8502, 8504}


class IAMPrivilegeEscalationDetector(BaseDetector):
    """
    Evaluates IAM and authorization streams for:
    1. Direct attachment of AdministratorAccess / full control policies to unprivileged entities.
    2. Adding users to administrative security groups.
    3. Creating new policy versions with wildcard statements.
    4. Wazuh privilege escalation alert signatures.
    """

    def __init__(self, enabled: bool = True):
        super().__init__(
            category="iam_privilege_escalation",
            category_index=3,
            name="IAM Privilege Escalation Detector",
            description="Detects unauthorized assignment of administrative privileges, excessive policy attachments, and role abuse.",
            supported_sources=["wazuh", "cloudtrail", "host_audit"],
            enabled=enabled
        )

    def detect(self, events: List[Union[NormalizedEvent, Dict[str, Any]]]) -> List[SecurityFinding]:
        norm_events = self._ensure_normalized(events)
        findings: List[SecurityFinding] = []

        for e in norm_events:
            action_lower = (e.action or "").lower()
            service_lower = (e.service or "").lower()
            rule_id = e.rule_id
            status_lower = (e.status or "").lower()

            is_escalation_action = action_lower in ESCALATION_ACTIONS
            is_wazuh_rule = rule_id in WAZUH_PRIV_ESC_RULE_IDS
            is_iam_attack = e.attack_type == "privilege_escalation"

            if not (is_escalation_action or is_wazuh_rule or is_iam_attack):
                continue

            # Check if this was a successful or attempted privilege grant
            raw_meta = e.raw_data or {}
            params = raw_meta.get("requestParameters", {}) or {}
            policy_arn = str(params.get("policyArn", "")).lower()
            policy_doc = str(params.get("policyDocument", "")).lower()
            group_name = str(params.get("groupName", "")).lower()
            desc = (e.description or "").lower()

            is_critical = False
            for p in CRITICAL_POLICIES:
                if p in policy_arn or p in policy_doc or p in desc:
                    is_critical = True
                    break

            for g in CRITICAL_GROUPS:
                if g in group_name:
                    is_critical = True
                    break

            # If Wazuh flagged it or attack_type was privilege_escalation, treat as confirmed
            if is_iam_attack or rule_id in (8502, 8504):
                is_critical = True

            principal = e.principal or e.user_id or "unknown-principal"
            target = params.get("userName") or params.get("roleName") or principal

            severity = "critical" if is_critical else "high"
            confidence = 0.95 if is_critical else 0.85

            facts = [
                f"Principal '{principal}' executed action '{e.action or 'PrivilegeEscalation'}' against target '{target}'.",
                f"Service context: '{e.service or 'IAM'}', Status: '{e.status}'.",
            ]
            if policy_arn:
                facts.append(f"Attached policy ARN: '{policy_arn}'.")
            if desc:
                facts.append(f"Event summary: {e.description}.")

            finding = self.create_finding(
                title=f"IAM Privilege Escalation: Excessive Access Granted via {e.action or 'IAM Policy'}",
                severity=severity,
                confidence=confidence,
                detection_method="rule_based",
                triggering_events=[e],
                observed_facts=facts,
                inferred_hypothesis=f"Principal '{principal}' performed an unauthorized privilege grant to acquire administrative control over cloud resources.",
                affected_resource=f"iam:{target}",
                affected_principal=principal,
                telemetry_fields={"principal": principal, "target": target, "action": e.action, "service": e.service},
                action_summary=f"Detach administrative policy from '{target}', quarantine principal '{principal}', and initiate credential rotation.",
                playbook_id="PB-PE-002",
                verification_status="VERIFIED"
            )
            findings.append(finding)

        return findings


iam_privilege_escalation_detector = IAMPrivilegeEscalationDetector()
detector_registry.register(iam_privilege_escalation_detector)
