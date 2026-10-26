"""
Database Threat Activity Detector (Attack Category 13)
======================================================
Identifies SQL injection patterns, unauthorized database snapshot sharing,
unapproved database exports, and credential scraping against managed RDS / SQL workloads.

Taxonomy Index: 13
Category Slug:  database_attacks
Playbook ID:    PB-DE-003
"""
from typing import Dict, Any, List, Optional, Union, Set
from schemas.event import NormalizedEvent
from schemas.finding import SecurityFinding
from engines.base_detector import BaseDetector, detector_registry

SQLI_SIGNATURES = ("union select", "' or '1'='1", "information_schema", "; drop table", "xp_cmdshell", "waitfor delay", "' or 1=1")
DB_ACTIONS: Set[str] = {"modifydbsnapshotattribute", "sharedbsnapshot", "copydbsnapshot", "restoredbinstancefromdbsnapshot"}


class DatabaseAttacksDetector(BaseDetector):
    """
    Evaluates database audit and CloudTrail RDS logs for:
    1. SQL injection payloads in query fields or web inputs.
    2. Unauthorized public sharing of database snapshots (ValuesToAdd: all).
    3. Bulk unapproved database extraction or anomalous exports.
    """

    def __init__(self, enabled: bool = True):
        super().__init__(
            category="database_attacks",
            category_index=13,
            name="Database Threat Activity Detector",
            description="Identifies SQL injection exploits, unauthorized database snapshot exposure, and data dumping activity.",
            supported_sources=["rds_audit", "waf", "cloudtrail"],
            enabled=enabled
        )

    def detect(self, events: List[Union[NormalizedEvent, Dict[str, Any]]]) -> List[SecurityFinding]:
        norm_events = self._ensure_normalized(events)
        findings: List[SecurityFinding] = []

        for e in norm_events:
            desc = (e.description or "").lower()
            action = (e.action or "").lower()
            attack_type = (e.attack_type or "").lower()

            is_sqli = any(sig in desc for sig in SQLI_SIGNATURES) or "sql injection" in desc or "sqli" in attack_type
            is_snapshot_share = action in DB_ACTIONS or "sharedbsnapshot" in desc or "snapshot public" in desc or "snapshot share" in desc
            is_db_dump = "pg_dump" in desc or "mysqldump" in desc or "database exfiltration" in desc

            if not (is_sqli or is_snapshot_share or is_db_dump or attack_type == "database_attacks"):
                continue

            principal = e.principal or e.user_id or "db-user"
            target = e.target_resource or "rds-instance"

            is_critical = is_snapshot_share or "drop table" in desc
            severity = "critical" if is_critical else "high"
            confidence = 0.95 if is_critical else 0.88

            facts = [
                f"Database threat activity detected targeting resource '{target}'.",
                f"Principal: '{principal}', Action: '{e.action}'.",
            ]
            if is_snapshot_share:
                facts.append("Identified RDS snapshot modification granting unauthorized cross-account or public read access.")
            if is_sqli:
                facts.append("Identified SQL injection signature in query execution parameters.")

            finding = self.create_finding(
                title=f"Database Threat Detected: SQL Injection or Snapshot Exposure on '{target}'",
                severity=severity,
                confidence=confidence,
                detection_method="signature_and_behavioral",
                triggering_events=[e],
                observed_facts=facts,
                inferred_hypothesis=f"Threat actor targeting relational data layer via injection or snapshot theft to access confidential records.",
                affected_resource=f"rds:{target}",
                affected_principal=principal,
                telemetry_fields={"database": target, "principal": principal, "action": e.action},
                action_summary=f"Revoke snapshot sharing permissions for '{target}', enable WAF SQLi inspection rules, and rotate database master credentials.",
                playbook_id="PB-DE-003",
                verification_status="VERIFIED"
            )
            findings.append(finding)

        return findings


database_attacks_detector = DatabaseAttacksDetector()
detector_registry.register(database_attacks_detector)
