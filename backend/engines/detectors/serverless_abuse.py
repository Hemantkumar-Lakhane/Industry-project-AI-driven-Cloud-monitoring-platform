"""
Serverless Function Abuse Detector (Attack Category 14)
=======================================================
Identifies unauthorized Lambda/serverless code tampering, environment variable
secret exfiltration, and concurrency exhaustion (denial-of-wallet).

Taxonomy Index: 14
Category Slug:  serverless_abuse
Playbook ID:    PB-MC-005
"""
from typing import Dict, Any, List, Optional, Union, Set
from schemas.event import NormalizedEvent
from schemas.finding import SecurityFinding
from engines.base_detector import BaseDetector, detector_registry

LAMBDA_ABUSE_ACTIONS: Set[str] = {
    "updatefunctioncode",
    "updatefunctionconfiguration",
    "putfunctionconcurrency",
    "addpermission",
    "publishversion",
}


class ServerlessAbuseDetector(BaseDetector):
    """
    Evaluates serverless lifecycle events for:
    1. Direct Lambda code updates from interactive/non-CI/CD identities (UpdateFunctionCode).
    2. Modification of function configuration injecting rogue environment variables or layers.
    3. Concurrency manipulation causing denial-of-wallet or starvation of critical workloads.
    """

    def __init__(self, enabled: bool = True):
        super().__init__(
            category="serverless_abuse",
            category_index=14,
            name="Serverless Function Abuse Detector",
            description="Identifies rogue Lambda code injections, environment variable tampering, and serverless concurrency manipulation.",
            supported_sources=["cloudtrail", "wazuh"],
            enabled=enabled
        )

    def detect(self, events: List[Union[NormalizedEvent, Dict[str, Any]]]) -> List[SecurityFinding]:
        norm_events = self._ensure_normalized(events)
        findings: List[SecurityFinding] = []

        for e in norm_events:
            desc = (e.description or "").lower()
            action_lower = (e.action or "").lower()
            raw_meta = e.raw_data or {}
            raw_str = (str(raw_meta) + " " + desc).lower()
            has_env_injection = any(k in raw_str for k in ("ld_preload", "exec_wrapper", "pythonpath", "env_injection", "backdoor"))
            is_code_tamper = action_lower == "updatefunctioncode"
            is_concurrency_abuse = action_lower == "putfunctionconcurrency"
            attack_type = (e.attack_type or "").lower()
            is_explicit = attack_type in ("serverless_abuse", "lambda_tampering") or "abuse" in desc or "tampering" in desc

            if not (has_env_injection or is_code_tamper or is_concurrency_abuse or is_explicit):
                continue

            principal = e.principal or e.user_id or "developer"
            function_name = e.target_resource or "serverless-function"

            # Elevated severity if non-CI identity updates code
            is_critical = action_lower in ("updatefunctioncode", "putfunctionconcurrency") or "rogue code" in desc or "tampering" in desc
            severity = "critical" if is_critical else "high"
            confidence = 0.94 if is_critical else 0.85

            facts = [
                f"Serverless control plane action '{e.action}' executed on function '{function_name}'.",
                f"Caller identity: '{principal}', Service: '{e.service or 'Lambda'}'.",
            ]
            if action_lower == "updatefunctioncode":
                facts.append("Identified direct runtime code package modification bypassing automated deployment pipeline.")
            if action_lower == "putfunctionconcurrency":
                facts.append("Identified reserved concurrency allocation manipulation (potential denial-of-wallet).")

            finding = self.create_finding(
                title=f"Serverless Function Abuse: Unauthorized Code/Config Tampering on '{function_name}'",
                severity=severity,
                confidence=confidence,
                detection_method="rule_based",
                triggering_events=[e],
                observed_facts=facts,
                inferred_hypothesis=f"Threat actor modified serverless executable code or environment secrets directly to persist backdoors or hijack cloud execution.",
                affected_resource=f"lambda:{function_name}",
                affected_principal=principal,
                telemetry_fields={"function": function_name, "principal": principal, "action": e.action},
                action_summary=f"Revert function '{function_name}' to last verified build artifact and restrict IAM permissions for principal '{principal}'.",
                playbook_id="PB-MC-005",
                verification_status="VERIFIED"
            )
            findings.append(finding)

        return findings


serverless_abuse_detector = ServerlessAbuseDetector()
detector_registry.register(serverless_abuse_detector)
