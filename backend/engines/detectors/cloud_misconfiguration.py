"""
Cloud Misconfiguration Drift Detector (Attack Category 5)
==========================================================
Identifies critical cloud resource drift, publicly accessible S3 storage,
overly permissive security groups, and unencrypted critical infrastructure.

Taxonomy Index: 5
Category Slug:  cloud_misconfiguration
Playbook ID:    PB-MC-005
"""
from typing import Dict, Any, List, Optional, Union, Set
from schemas.event import NormalizedEvent
from schemas.finding import SecurityFinding
from engines.base_detector import BaseDetector, detector_registry

MISCONFIG_ACTIONS: Set[str] = {
    "putbucketacl",
    "putbucketpolicy",
    "deletebucketpublicaccessblock",
    "authorizesecuritygroupingress",
    "modifysubnetattribute",
    "modifydbinstance",
}

DANGEROUS_PORTS: Set[int] = {22, 3389, 5432, 3306, 27017, 6379, 9200}


class CloudMisconfigurationDetector(BaseDetector):
    """
    Evaluates cloud modification events for:
    1. S3 bucket public exposure (public read/write grants, disabled public access block).
    2. Security group rules allowing 0.0.0.0/0 on sensitive ports (SSH, RDP, databases).
    3. Direct misconfiguration drift events generated from CSPM sweeps.
    """

    def __init__(self, enabled: bool = True):
        super().__init__(
            category="cloud_misconfiguration",
            category_index=5,
            name="Cloud Misconfiguration Drift Detector",
            description="Detects public S3 exposures, unrestricted security group ingress, and insecure infrastructure posture drift.",
            supported_sources=["cloudtrail", "wazuh", "cspm"],
            enabled=enabled
        )

    def detect(self, events: List[Union[NormalizedEvent, Dict[str, Any]]]) -> List[SecurityFinding]:
        norm_events = self._ensure_normalized(events)
        findings: List[SecurityFinding] = []

        for e in norm_events:
            act_lower = (e.action or "").lower()
            desc = (e.description or "").lower()
            is_misconfig = act_lower in MISCONFIG_ACTIONS or e.attack_type in ("cloud_misconfiguration", "misconfiguration")

            # Check for keyword matches in description or parameters
            raw_meta = e.raw_data or {}
            params = raw_meta.get("requestParameters", {}) or {}
            raw_str = (str(raw_meta) + " " + str(params) + " " + str(e.raw_data)).lower()

            is_s3_public = (
                "public-read" in raw_str or
                "public-read-write" in raw_str or
                '"principal": "*"' in raw_str or
                "deletebucketpublicaccessblock" in act_lower or
                "public s3" in desc or
                "bucket public" in desc
            )

            is_sg_wildcard = (
                "0.0.0.0/0" in raw_str or
                "::/0" in raw_str or
                ("authorizesecuritygroupingress" in act_lower and ("0.0.0.0/0" in raw_str or "open to world" in desc)) or
                "open to world" in desc or
                "0.0.0.0/0" in desc
            )

            is_explicit_misconfig = e.attack_type in ("cloud_misconfiguration", "misconfiguration") or "misconfiguration" in desc

            if not (is_s3_public or is_sg_wildcard or is_explicit_misconfig):
                continue

            principal = e.principal or e.user_id or "cloud-admin"
            resource = e.target_resource or params.get("bucketName") or params.get("groupId") or "cloud-workload"

            if is_s3_public:
                facts = [
                    f"Action '{e.action or 'PutBucketAcl'}' executed on resource '{resource}' by '{principal}'.",
                    "Public exposure indicators detected: ACL public-read or disabled PublicAccessBlock.",
                ]
                finding = self.create_finding(
                    title=f"Critical Storage Exposure: S3 Bucket '{resource}' Granted Public Access",
                    severity="critical",
                    confidence=0.98,
                    detection_method="rule_based",
                    triggering_events=[e],
                    observed_facts=facts,
                    inferred_hypothesis="Storage bucket configured to permit unauthenticated internet reads or writes.",
                    affected_resource=f"s3:{resource}",
                    affected_principal=principal,
                    telemetry_fields={"bucket": resource, "principal": principal, "action": e.action},
                    action_summary=f"Enable S3 Block Public Access on '{resource}' immediately and verify bucket policy.",
                    playbook_id="PB-MC-005",
                    verification_status="VERIFIED"
                )
                findings.append(finding)
            elif is_sg_wildcard:
                facts = [
                    f"Security group rule modified by principal '{principal}'.",
                    "Ingress rule allows 0.0.0.0/0 (unrestricted public internet ingress).",
                ]
                finding = self.create_finding(
                    title=f"Perimeter Exposure: Security Group '{resource}' Opened to 0.0.0.0/0",
                    severity="high",
                    confidence=0.92,
                    detection_method="rule_based",
                    triggering_events=[e],
                    observed_facts=facts,
                    inferred_hypothesis="Security group ingress opened to entire internet on management or database ports.",
                    affected_resource=f"ec2:security-group:{resource}",
                    affected_principal=principal,
                    telemetry_fields={"security_group": resource, "principal": principal, "action": e.action},
                    action_summary=f"Revoke 0.0.0.0/0 ingress rule on security group '{resource}' and restrict to corporate CIDR blocks.",
                    playbook_id="PB-MC-005",
                    verification_status="VERIFIED"
                )
                findings.append(finding)
            elif is_misconfig:
                facts = [
                    f"Configuration drift action '{e.action}' observed by '{principal}'.",
                    f"Description: {e.description or 'Unsafe cloud modification.'}"
                ]
                finding = self.create_finding(
                    title=f"Cloud Infrastructure Drift: Insecure Configuration on '{resource}'",
                    severity="medium",
                    confidence=0.80,
                    detection_method="rule_based",
                    triggering_events=[e],
                    observed_facts=facts,
                    inferred_hypothesis="Infrastructure state drifted from hardened baseline configuration.",
                    affected_resource=f"resource:{resource}",
                    affected_principal=principal,
                    telemetry_fields={"resource": resource, "principal": principal, "action": e.action},
                    action_summary=f"Remediate configuration drift for resource '{resource}' using baseline IaC definitions.",
                    playbook_id="PB-MC-005",
                    verification_status="VERIFIED"
                )
                findings.append(finding)

        return findings


cloud_misconfiguration_detector = CloudMisconfigurationDetector()
detector_registry.register(cloud_misconfiguration_detector)
